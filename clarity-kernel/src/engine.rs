// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! The engine ABI: the boundary between a Clarity execution engine (a
//! parser + analyzer + evaluator for one or more language versions) and the
//! host that embeds it.
//!
//! Data crosses this boundary only as kernel types: [`Value`]s in and out,
//! [`AssetMap`] and event batches for the host's post-condition checks, and
//! [`Diagnostic`]s for static rejection. An engine's internal representation
//! of contracts (interpreted AST, compiled Wasm, ...) never crosses.
//!
//! The ABI models the production transaction flow: contract deploys are
//! phased ([`Engine::analyze_contract`] → [`Engine::initialize_contract`] →
//! [`Engine::save_analysis`], the same order as Stacks smart-contract
//! transaction processing, with the host holding an [`AnalyzedContract`]
//! handle across the phases), hosts can reject otherwise-successful
//! interactions before commit via [`AbortCallback`] (post-conditions), all
//! interactions charge a per-transaction [`CostBudget`], and analysis and
//! execution are bounded by host-supplied [`ResourceBudget`]s. Contract
//! interfaces persist in the kernel-owned
//! [`StoredContractAnalysis`] format, so engines can read
//! each other's deployed contracts.
//!
//! Known evolution points, in dependency order:
//!
//! - **Epoch inversion**: [`TransactionContext`] still carries a
//!   `StacksEpochId`; it will become a kernel-owned ruleset identifier.

use std::any::{Any, TypeId};
use std::collections::HashMap;

use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_types::{ClarityVersion, Value};
use stacks_common::types::StacksEpochId;

use crate::analysis::StoredContractAnalysis;
use crate::assets::AssetMap;
use crate::costs::{CostTracker, CostTrackerHandle, CostTrackerMetrics, ExecutionCost};
use crate::database::ClarityDatabase;
use crate::diagnostic::Diagnostic;
use crate::errors::{StaticCheckError, VmExecutionError};
use crate::events::StacksTransactionEvent;
use crate::resource_limiter::{ResourceBudget, ResourceLimiter};
use crate::transaction::{CallStack, TransactionFrame};

/// An owned runtime component that may be temporarily lent across an engine
/// boundary. Dereferencing an empty slot is an ABI violation; dispatch code
/// uses [`Self::take`] and [`Self::restore`] to make suspension explicit.
pub struct RuntimeSlot<T> {
    value: Option<T>,
}

impl<T> RuntimeSlot<T> {
    pub fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    pub fn take(&mut self, name: &str) -> Result<T, EngineError> {
        self.value.take().ok_or_else(|| {
            EngineError::Internal(format!("Runtime {name} was taken and not restored"))
        })
    }

    pub fn restore(&mut self, value: T) {
        self.value = Some(value);
    }

    pub fn into_inner(self) -> Option<T> {
        self.value
    }
}

impl<T> std::ops::Deref for RuntimeSlot<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value
            .as_ref()
            .expect("BUG: accessed a suspended Clarity runtime slot")
    }
}

impl<T> std::ops::DerefMut for RuntimeSlot<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
            .as_mut()
            .expect("BUG: accessed a suspended Clarity runtime slot")
    }
}

/// A short-lived view of the shared state at a nested contract-call boundary.
///
/// The outer engine retains the slots themselves. The dispatch path
/// temporarily takes their contents, invokes the selected engine, and restores
/// them before returning to the suspended caller.
pub struct RuntimeContext<'runtime, 'db> {
    pub db: &'runtime mut RuntimeSlot<ClarityDatabase<'db>>,
    pub cost_tracker: &'runtime mut RuntimeSlot<CostTrackerHandle>,
    pub transaction_frame: &'runtime mut RuntimeSlot<TransactionFrame>,
    pub call_stack: &'runtime mut CallStack,
    pub execution_resource_limiter: ResourceLimiter,
    pub epoch: StacksEpochId,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl<'db> RuntimeContext<'_, 'db> {
    /// Suspend the outer engine and collect its shared state in the ordinary
    /// engine ABI context. Any partial failure restores already-taken slots.
    pub fn take_transaction_context(&mut self) -> Result<TransactionContext<'db>, EngineError> {
        let db = self.db.take("database")?;
        let tracker = match self.cost_tracker.take("cost tracker") {
            Ok(tracker) => tracker,
            Err(e) => {
                self.db.restore(db);
                return Err(e);
            }
        };
        let frame = match self.transaction_frame.take("transaction frame") {
            Ok(frame) => frame,
            Err(e) => {
                self.cost_tracker.restore(tracker);
                self.db.restore(db);
                return Err(e);
            }
        };
        let call_stack = std::mem::take(self.call_stack);

        Ok(TransactionContext::from_runtime(
            db,
            tracker,
            frame,
            call_stack,
            self.execution_resource_limiter,
            self.mainnet,
            self.chain_id,
            self.epoch,
        ))
    }

    /// Resume the suspended outer engine after a nested engine returns.
    pub fn restore_transaction_context(
        &mut self,
        ctx: TransactionContext<'db>,
    ) -> Result<(), EngineError> {
        let TransactionContext {
            db,
            cost_tracker,
            transaction_frame,
            call_stack,
            ..
        } = ctx;
        let missing_call_stack = call_stack.is_none();
        if let Some(db) = db {
            self.db.restore(db);
        }
        if let Some(tracker) = cost_tracker {
            self.cost_tracker.restore(tracker);
        }
        if let Some(frame) = transaction_frame {
            self.transaction_frame.restore(frame);
        }
        if let Some(call_stack) = call_stack {
            *self.call_stack = call_stack;
        }

        if self.db.value.is_none()
            || self.cost_tracker.value.is_none()
            || self.transaction_frame.value.is_none()
            || missing_call_stack
        {
            Err(EngineError::Internal(
                "Nested engine failed to restore shared runtime state".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// Post-execution decision hook: after an interaction executes successfully,
/// the host inspects the resulting asset movements (and may read chain
/// state) *before* the changes commit — this is how Stacks post-conditions
/// are enforced. Returning `Some(reason)` rolls the interaction back and
/// surfaces [`EngineError::AbortedByCallback`].
pub type AbortCallback<'x> = &'x mut dyn FnMut(&AssetMap, &mut ClarityDatabase) -> Option<String>;

/// The execution-cost budget for all engine interactions within one
/// [`TransactionContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostBudget {
    /// No cost enforcement, no cost metering. Suitable for tooling and
    /// read-only hosts; never for consensus.
    Free,
    /// Enforce this budget cumulatively across every interaction run in the
    /// context. Exceeding it fails the interaction with a cost error.
    Limited(ExecutionCost),
}

/// Errors crossing the engine ABI.
#[derive(Debug)]
pub enum EngineError {
    /// The source failed to parse. Carries only presentation data — lexer
    /// and parser error types are engine-internal.
    Parse {
        diagnostics: Vec<Diagnostic>,
        /// Whether block validation must reject the transaction instead of
        /// accepting it as a paid analysis failure.
        rejectable: bool,
    },
    /// Parsing or analysis exhausted the cumulative transaction cost budget.
    Cost(ExecutionCost, ExecutionCost),
    /// The contract failed static checks.
    Static(Box<StaticCheckError>),
    /// Runtime failure during evaluation.
    Execution(VmExecutionError),
    /// The interaction executed successfully, but the host's
    /// [`AbortCallback`] rejected it; all of its changes were rolled back.
    /// Carries what the execution produced so the host can build receipts.
    AbortedByCallback {
        /// The call's return value (`None` for contract deploys).
        output: Option<Box<Value>>,
        /// The asset movements the rolled-back execution would have made.
        assets: Box<AssetMap>,
        /// The events the rolled-back execution emitted.
        events: Vec<StacksTransactionEvent>,
        /// The host-provided reason for the abort.
        reason: String,
    },
    /// The engine or host violated the ABI contract (e.g. the transaction
    /// context's database was not available).
    Internal(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Parse { diagnostics, .. } => {
                write!(f, "Parse failure:")?;
                for d in diagnostics {
                    write!(f, " {d}")?;
                }
                Ok(())
            }
            EngineError::Cost(total, limit) => {
                write!(f, "Cost budget exceeded: total={total}, limit={limit}")
            }
            EngineError::Static(e) => write!(f, "Static check failure: {}", e.diagnostic),
            EngineError::Execution(e) => write!(f, "Execution failure: {e}"),
            EngineError::AbortedByCallback { reason, .. } => {
                write!(f, "Aborted by host callback: {reason}")
            }
            EngineError::Internal(s) => write!(f, "Internal engine error: {s}"),
        }
    }
}

impl From<VmExecutionError> for EngineError {
    fn from(err: VmExecutionError) -> Self {
        EngineError::Execution(err)
    }
}

impl From<StaticCheckError> for EngineError {
    fn from(err: StaticCheckError) -> Self {
        EngineError::Static(Box::new(err))
    }
}

/// The transaction-scoped state a host hands to an engine for one
/// interaction (deploy, call, or read-only evaluation).
///
/// The database is transferred by value because engines assemble their own
/// execution context around it (the legacy engine's `GlobalContext` owns its
/// `ClarityDatabase`); [`Self::take_db`] / [`Self::restore_db`] make that
/// hand-off explicit, and a well-behaved engine restores the database before
/// returning — including on error paths.
pub struct TransactionContext<'a> {
    db: Option<ClarityDatabase<'a>>,
    /// The one cumulative cost tracker shared by every engine participating
    /// in this transaction. It is type-erased so historical engine-specific
    /// schedules can remain outside the kernel.
    cost_tracker: Option<CostTrackerHandle>,
    /// Asset/event/read-only rollback frames shared by all participating
    /// engines.
    transaction_frame: Option<TransactionFrame>,
    /// Function and expression depth shared across engine call boundaries.
    call_stack: Option<CallStack>,
    dispatcher: Option<Box<dyn ContractDispatcher>>,
    execution_resource_limiter: ResourceLimiter,
    /// Transitional: epochs are a Stacks-host concept; this becomes a
    /// kernel-owned ruleset identifier at the epoch-inversion step.
    pub epoch: StacksEpochId,
    pub mainnet: bool,
    pub chain_id: u32,
    /// Cost budget for all interactions in this context. Defaults to
    /// [`CostBudget::Free`]; set with [`Self::with_budget`].
    pub budget: CostBudget,
    /// Engine-owned state persisted between interactions in this context,
    /// keyed by its concrete type. Multiple engines may park private state
    /// without overwriting one another. Opaque to the kernel and the host.
    ///
    /// Consensus-shared state must not live here; the cumulative tracker and
    /// live nested-call frame are explicit fields above.
    engine_states: HashMap<TypeId, Box<dyn Any>>,
}

impl<'a> TransactionContext<'a> {
    pub fn new(
        db: ClarityDatabase<'a>,
        mainnet: bool,
        chain_id: u32,
        epoch: StacksEpochId,
    ) -> Self {
        TransactionContext {
            db: Some(db),
            cost_tracker: None,
            transaction_frame: Some(TransactionFrame::new()),
            call_stack: Some(CallStack::new()),
            dispatcher: None,
            execution_resource_limiter: ResourceLimiter::unlimited(),
            epoch,
            mainnet,
            chain_id,
            budget: CostBudget::Free,
            engine_states: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn from_runtime(
        db: ClarityDatabase<'a>,
        cost_tracker: CostTrackerHandle,
        transaction_frame: TransactionFrame,
        call_stack: CallStack,
        execution_resource_limiter: ResourceLimiter,
        mainnet: bool,
        chain_id: u32,
        epoch: StacksEpochId,
    ) -> Self {
        Self {
            db: Some(db),
            cost_tracker: Some(cost_tracker),
            transaction_frame: Some(transaction_frame),
            call_stack: Some(call_stack),
            dispatcher: None,
            execution_resource_limiter,
            epoch,
            mainnet,
            chain_id,
            budget: CostBudget::Free,
            engine_states: HashMap::new(),
        }
    }

    pub fn execution_resource_limiter(&self) -> ResourceLimiter {
        self.execution_resource_limiter
    }

    /// Install the host-owned nested-call router for this interaction.
    pub fn install_dispatcher<D: ContractDispatcher + 'static>(&mut self, dispatcher: D) {
        self.dispatcher = Some(Box::new(dispatcher));
    }

    pub fn take_dispatcher(&mut self) -> Option<Box<dyn ContractDispatcher>> {
        self.dispatcher.take()
    }

    pub fn restore_dispatcher(&mut self, dispatcher: Box<dyn ContractDispatcher>) {
        self.dispatcher = Some(dispatcher);
    }

    /// Set the cost budget for this context. Must be set before the first
    /// engine interaction; engines may cache budget-derived state in the
    /// context after that.
    pub fn with_budget(mut self, budget: CostBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Install a concrete tracker as this transaction's shared cumulative
    /// meter. Hosts use this to lend their block-wide tracker to the engine
    /// ABI without exposing its concrete type to other engines.
    pub fn install_cost_tracker<T>(&mut self, tracker: T)
    where
        T: CostTracker + CostTrackerMetrics + 'static,
    {
        self.cost_tracker = Some(CostTrackerHandle::new(tracker));
    }

    /// Install an already-erased shared tracker.
    pub fn restore_cost_tracker(&mut self, tracker: CostTrackerHandle) {
        self.cost_tracker = Some(tracker);
    }

    /// Take the shared tracker for the duration of one engine interaction.
    /// Engines must restore it on every return path.
    pub fn take_cost_tracker(&mut self) -> Option<CostTrackerHandle> {
        self.cost_tracker.take()
    }

    /// Recover a concrete host tracker without losing an unexpected tracker
    /// type. A failed downcast leaves the shared handle installed.
    pub fn take_cost_tracker_as<T: 'static>(&mut self) -> Option<Box<T>> {
        let tracker = self.take_cost_tracker()?;
        match tracker.into_inner::<T>() {
            Ok(tracker) => Some(tracker),
            Err(tracker) => {
                self.restore_cost_tracker(tracker);
                None
            }
        }
    }

    pub fn take_transaction_frame(&mut self) -> Result<TransactionFrame, EngineError> {
        self.transaction_frame.take().ok_or_else(|| {
            EngineError::Internal("Transaction frame was taken and not restored".into())
        })
    }

    pub fn restore_transaction_frame(&mut self, frame: TransactionFrame) {
        self.transaction_frame = Some(frame);
    }

    pub fn take_call_stack(&mut self) -> Result<CallStack, EngineError> {
        self.call_stack.take().ok_or_else(|| {
            EngineError::Internal("Transaction call stack was taken and not restored".into())
        })
    }

    pub fn restore_call_stack(&mut self, call_stack: CallStack) {
        self.call_stack = Some(call_stack);
    }

    /// Take this engine-owned inter-interaction state, if present.
    pub fn take_engine_state<T: 'static>(&mut self) -> Option<Box<T>> {
        self.engine_states
            .remove(&TypeId::of::<T>())?
            .downcast::<T>()
            .ok()
    }

    /// Store engine-owned state to be retrieved by the same engine on its
    /// next interaction in this context. This replaces only that concrete
    /// state's previous value; other engines' state remains parked.
    pub fn set_engine_state<T: 'static>(&mut self, state: T) {
        self.engine_states
            .insert(TypeId::of::<T>(), Box::new(state));
    }

    /// Take ownership of the database for the duration of one engine
    /// interaction. Fails if a previous interaction did not restore it.
    pub fn take_db(&mut self) -> Result<ClarityDatabase<'a>, EngineError> {
        self.db.take().ok_or_else(|| {
            EngineError::Internal("Transaction context database was taken and not restored".into())
        })
    }

    /// Return the database after an engine interaction.
    pub fn restore_db(&mut self, db: ClarityDatabase<'a>) {
        self.db = Some(db);
    }

    /// Consume the context, recovering the database (if it was restored).
    pub fn into_db(self) -> Option<ClarityDatabase<'a>> {
        self.db
    }
}

/// A contract that has been parsed and statically checked, ready to be
/// initialized and persisted.
///
/// The host holds this between the deploy phases and hands it back — the
/// same shape as the Stacks transaction path, which already carries the
/// parsed contract from analysis through initialization to storage. The
/// engine's own representation (an AST, a compiled module, ...) rides along
/// opaquely in `engine_data`; the host sees only the kernel-format
/// [`interface`](Self::interface).
pub struct AnalyzedContract {
    source: String,
    /// The contract's stored-interface record, readable by any engine.
    interface: StoredContractAnalysis,
    engine_data: Box<dyn Any>,
}

impl AnalyzedContract {
    pub fn new<T: 'static>(
        source: String,
        interface: StoredContractAnalysis,
        engine_data: T,
    ) -> Self {
        AnalyzedContract {
            source,
            interface,
            engine_data: Box::new(engine_data),
        }
    }

    /// The identifier whose source and interface were analyzed.
    pub fn contract(&self) -> &QualifiedContractIdentifier {
        &self.interface.contract_identifier
    }

    /// The language version under which the source was analyzed.
    pub fn version(&self) -> ClarityVersion {
        self.interface.clarity_version
    }

    /// The exact source that produced this analysis.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The engine-neutral stored interface produced by analysis.
    pub fn interface(&self) -> &StoredContractAnalysis {
        &self.interface
    }

    /// Borrow the producing engine's private representation. Returns `None`
    /// if this handle came from a different engine.
    pub fn engine_data<T: 'static>(&self) -> Option<&T> {
        self.engine_data.downcast_ref::<T>()
    }

    /// Consume the handle and take the producing engine's private
    /// representation. Returns `None` (dropping the payload) if this handle
    /// came from a different engine.
    ///
    /// Used by engines offering hosts a way back to their own types — e.g.
    /// a host mid-migration that still threads an engine's AST directly.
    pub fn into_engine_data<T: 'static>(self) -> Option<Box<T>> {
        self.engine_data.downcast::<T>().ok()
    }
}

/// What a contract deployment produced, for the host's post-condition and
/// event processing.
#[derive(Debug)]
pub struct DeployOutcome {
    pub assets: AssetMap,
    pub events: Vec<StacksTransactionEvent>,
    /// Cumulative cost consumed in this [`TransactionContext`] so far
    /// (always zero under [`CostBudget::Free`]).
    pub cost: ExecutionCost,
}

/// What a contract call produced.
#[derive(Debug)]
pub struct ExecutionOutcome {
    pub value: Value,
    pub assets: AssetMap,
    pub events: Vec<StacksTransactionEvent>,
    /// Cumulative cost consumed in this [`TransactionContext`] so far
    /// (always zero under [`CostBudget::Free`]).
    pub cost: ExecutionCost,
}

/// A Clarity execution engine: parser, static checker, and evaluator for one
/// or more language versions, embeddable behind this trait by any host.
///
/// Engines are stateless between interactions — all persistent state lives
/// in the [`ClarityDatabase`] carried by the [`TransactionContext`], and all
/// per-transaction state is scoped to a single method call.
pub trait Engine {
    /// Stable, human-readable engine identifier (for logs and diagnostics).
    fn name(&self) -> &'static str;

    /// The language versions this engine can execute.
    fn supported_versions(&self) -> &'static [ClarityVersion];

    /// Parse and statically check a contract, without evaluating or
    /// persisting anything. The returned handle is passed back to
    /// [`Self::initialize_contract`] and [`Self::save_analysis`].
    ///
    /// `analysis_budget` bounds wall-clock and allocation for parsing plus
    /// analysis; hosts must pass [`ResourceBudget::unlimited`] on
    /// deterministic replay/commit paths so consensus stays deterministic.
    fn analyze_contract(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
        analysis_budget: &ResourceBudget,
    ) -> Result<AnalyzedContract, EngineError>;

    /// Evaluate an analyzed contract's top-level forms and persist the
    /// contract itself.
    ///
    /// If `abort` returns `Some(reason)` after successful evaluation, all
    /// changes roll back and [`EngineError::AbortedByCallback`] is returned.
    /// This does *not* persist the analysis — hosts call
    /// [`Self::save_analysis`] after a successful initialization, matching
    /// the Stacks deploy flow (a runtime failure in top-level code leaves
    /// the contract unmaterialized, so its interface must not be stored).
    fn initialize_contract(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
        sponsor: Option<PrincipalData>,
        abort: Option<AbortCallback>,
        execution_budget: &ResourceBudget,
    ) -> Result<DeployOutcome, EngineError>;

    /// Persist an analyzed contract's interface to the metadata store.
    fn save_analysis(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
    ) -> Result<(), EngineError>;

    /// Execute one public-function call on a deployed contract.
    ///
    /// If `abort` returns `Some(reason)` after successful execution, all
    /// changes roll back and [`EngineError::AbortedByCallback`] is returned
    /// (carrying the call's output, assets, and events for receipts).
    #[allow(clippy::too_many_arguments)]
    fn execute_call(
        &self,
        ctx: &mut TransactionContext,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
        abort: Option<AbortCallback>,
        execution_budget: &ResourceBudget,
    ) -> Result<ExecutionOutcome, EngineError>;

    /// Execute a call from another engine over an already-open transaction
    /// frame. Unlike [`Self::execute_call`], this does not create a top-level
    /// interaction boundary or run a host abort callback.
    #[allow(clippy::too_many_arguments)]
    fn execute_nested_call(
        &self,
        ctx: &mut TransactionContext,
        dispatcher: &mut dyn ContractDispatcher,
        sender: Option<PrincipalData>,
        caller: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
    ) -> Result<Value, EngineError>;

    /// Evaluate a read-only snippet in the context of a deployed contract.
    fn eval_read_only(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, EngineError>;

    /// Convenience: the full deploy pipeline — analyze, initialize, persist
    /// the analysis — with unlimited resource budgets and no abort hook.
    /// Hosts running real transactions drive the three phases themselves.
    fn deploy_contract(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
        sponsor: Option<PrincipalData>,
    ) -> Result<DeployOutcome, EngineError> {
        let analyzed =
            self.analyze_contract(ctx, contract, source, version, &ResourceBudget::unlimited())?;
        let outcome =
            self.initialize_contract(ctx, &analyzed, sponsor, None, &ResourceBudget::unlimited())?;
        self.save_analysis(ctx, &analyzed)?;
        Ok(outcome)
    }
}

/// Cross-engine contract-call routing: every hosted `contract-call?` re-enters
/// this selector, and the host chooses the callee's engine from its stored
/// language version while preserving the same shared transaction state.
///
pub trait ContractDispatcher {
    fn select_engine(
        &mut self,
        runtime: &mut RuntimeContext,
        contract: &QualifiedContractIdentifier,
    ) -> Result<&'static dyn Engine, EngineError>;
}
