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

//! The legacy engine: this crate's interpreter (Clarity 1 through
//! [`ClarityVersion::latest`]) wrapped behind the kernel's [`Engine`] ABI.
//!
//! The ABI mirrors the production transaction flow: [`Engine::analyze_contract`]
//! (parse + static checks, nothing persisted), [`Engine::initialize_contract`]
//! (evaluate top-level forms, host abort hook before commit), then
//! [`Engine::save_analysis`] — the same three phases, in the same order, as
//! the node's smart-contract transaction processing. Post-condition-style
//! aborts hold an outer rollback layer open across the interaction and roll
//! it back when the host's [`AbortCallback`] rejects the asset movements.
//!
//! `analyze_contract` hands back an [`AnalyzedContract`] that the host holds
//! across the phases (mirroring how the node's transaction path already
//! carries a parsed contract from analysis to storage); this engine's AST and
//! working analysis ride inside it opaquely.
//!
//! All phases charge the context's [`CostBudget`]. The cost tracker lives in
//! the context's engine-state slot between interactions, so one budget spans
//! a whole transaction; hosts that own a longer-lived tracker (a Stacks block
//! budget) install it with [`LegacyEngine::install_cost_tracker`].
//!
//! Caveats, tracked in the extraction plan:
//! - A [`CostBudget::Limited`] tracker resolves cost functions from the
//!   database at first use, exactly like the node does; on a fresh store
//!   this requires the stored Clarity epoch to be 4.0 or later (where cost
//!   functions are Rust-implemented boot defaults rather than deployed
//!   contracts).
//! - `contract-call?` between contracts stays inside this engine; routing
//!   through [`ContractDispatcher`] is the mixed-engine milestone.

use clarity_kernel::assets::AssetMap;
use clarity_kernel::costs::ExecutionCost;
pub use clarity_kernel::engine::{
    AbortCallback, AnalyzedContract, ContractDispatcher, CostBudget, DeployOutcome, Engine,
    EngineError, ExecutionOutcome, TransactionContext,
};
use clarity_kernel::events::StacksTransactionEvent;
use clarity_kernel::resource_limiter::ResourceBudget;
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_types::{ClarityVersion, Value};

use crate::vm::SymbolicExpression;
use crate::vm::analysis::types::ContractAnalysis;
use crate::vm::analysis::{AnalysisDatabase, run_analysis};
use crate::vm::ast::{ContractAST, build_ast};
use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::ClarityEvalError;

/// The interpreter-backed engine for all legacy Clarity versions.
pub struct LegacyEngine;

/// This engine's private payload inside an [`AnalyzedContract`]: the parsed
/// AST that initialization evaluates, and the working analysis (type map,
/// interface) that `save_analysis` persists.
pub struct LegacyAnalysis {
    ast: ContractAST,
    analysis: ContractAnalysis,
}

/// This engine's inter-interaction state, kept in the context's engine-state
/// slot: the cost tracker, so one [`CostBudget`] spans a whole transaction.
struct EngineState {
    tracker: LimitedCostTracker,
}

/// The engine's working parts, taken out of a [`TransactionContext`] for the
/// duration of one interaction and returned to it afterwards.
struct TakenParts<'a> {
    state: EngineState,
    db: ClarityDatabase<'a>,
}

/// What an interaction produces: a value, plus the asset movements and
/// events it generated.
type Produced<R> = (R, AssetMap, Vec<StacksTransactionEvent>);

/// A completed interaction: what it produced, plus the cumulative cost
/// consumed in its [`TransactionContext`] so far.
type InteractionOutcome<R> = Result<(Produced<R>, ExecutionCost), EngineError>;

fn engine_error(err: ClarityEvalError) -> EngineError {
    match err {
        ClarityEvalError::Vm(e) => EngineError::Execution(e),
        ClarityEvalError::Parse(e) => EngineError::Parse(vec![e.diagnostic]),
    }
}

impl LegacyEngine {
    /// Recover this engine's state from the context, building a fresh cost
    /// tracker from the budget on the first interaction.
    fn take_state(
        &self,
        ctx: &mut TransactionContext,
        db: &mut ClarityDatabase,
    ) -> Result<EngineState, EngineError> {
        if let Some(state) = ctx.take_engine_state::<EngineState>() {
            return Ok(*state);
        }
        let tracker = match &ctx.budget {
            CostBudget::Free => LimitedCostTracker::new_free(),
            CostBudget::Limited(limit) => {
                LimitedCostTracker::new(ctx.mainnet, ctx.chain_id, limit.clone(), db, ctx.epoch)
                    .map_err(|e| {
                        EngineError::Internal(format!("Failed to initialize cost tracker: {e}"))
                    })?
            }
        };
        Ok(EngineState { tracker })
    }

    /// Install a host-owned cost tracker into the context.
    ///
    /// Hosts that thread one tracker across many transactions — a Stacks
    /// block connection carries a single [`LimitedCostTracker`] for its
    /// whole block budget — install it here instead of letting the engine
    /// build a fresh one from [`CostBudget`], then recover it afterwards
    /// with [`Self::take_cost_tracker`].
    pub fn install_cost_tracker(ctx: &mut TransactionContext, tracker: LimitedCostTracker) {
        ctx.set_engine_state(EngineState { tracker });
    }

    /// Recover the cost tracker from the context (whether installed by
    /// [`Self::install_cost_tracker`] or built from the context's budget).
    pub fn take_cost_tracker(ctx: &mut TransactionContext) -> Option<LimitedCostTracker> {
        ctx.take_engine_state::<EngineState>()
            .map(|state| state.tracker)
    }

    /// Unwrap an [`AnalyzedContract`] this engine produced back into the
    /// interpreter's own types.
    ///
    /// Transitional: it lets a host route analysis through the ABI while its
    /// own API still hands `ContractAST`/`ContractAnalysis` around. Hosts
    /// that only need the contract's interface should read
    /// [`AnalyzedContract::interface`] instead, which is engine-agnostic.
    /// Returns `None` if the handle came from a different engine.
    pub fn into_legacy_parts(
        analyzed: AnalyzedContract,
    ) -> Option<(ContractAST, ContractAnalysis)> {
        analyzed
            .into_engine_data::<LegacyAnalysis>()
            .map(|legacy| (legacy.ast, legacy.analysis))
    }

    /// Wrap analysis performed through the legacy transaction API in the
    /// engine-neutral handle used by the ABI's state-changing deploy phases.
    ///
    /// This is a migration bridge for hosts that must preserve the legacy
    /// parser error taxonomy while moving initialization and persistence
    /// behind [`Engine`]. New hosts should call [`Engine::analyze_contract`]
    /// directly.
    pub fn from_legacy_parts(
        source: String,
        ast: ContractAST,
        analysis: ContractAnalysis,
    ) -> AnalyzedContract {
        let interface = analysis.to_stored();
        AnalyzedContract::new(source, interface, LegacyAnalysis { ast, analysis })
    }

    /// Take the database and this engine's state out of the context for one
    /// interaction, restoring the database if state recovery fails.
    fn take_parts<'a>(
        &self,
        ctx: &mut TransactionContext<'a>,
    ) -> Result<TakenParts<'a>, EngineError> {
        let mut db = ctx.take_db()?;
        match self.take_state(ctx, &mut db) {
            Ok(state) => Ok(TakenParts { state, db }),
            Err(e) => {
                ctx.restore_db(db);
                Err(e)
            }
        }
    }

    /// Park the state back in the context for the next interaction, and
    /// report the cumulative cost consumed so far.
    fn park_state(&self, ctx: &mut TransactionContext, state: EngineState) -> ExecutionCost {
        let cost = state.tracker.get_total();
        ctx.set_engine_state(state);
        cost
    }

    /// Run `interact` inside an [`OwnedEnvironment`] assembled from the
    /// transaction context's parts, against an outer rollback layer.
    ///
    /// On success, the host's `abort` hook inspects the asset movements and
    /// may still roll the whole interaction back (this is how Stacks
    /// post-conditions are enforced); `output_for_abort` supplies the
    /// `output` field of the resulting [`EngineError::AbortedByCallback`].
    /// On error, everything rolls back. The database and engine state are
    /// restored to the context in all cases.
    fn with_abortable_env<'a, F, R>(
        &self,
        ctx: &mut TransactionContext<'a>,
        parts: TakenParts<'a>,
        execution_budget: &ResourceBudget,
        abort: Option<AbortCallback>,
        output_for_abort: fn(&R) -> Option<Box<Value>>,
        interact: F,
    ) -> InteractionOutcome<R>
    where
        F: FnOnce(&mut OwnedEnvironment) -> Result<Produced<R>, EngineError>,
    {
        let TakenParts { mut state, mut db } = parts;
        db.begin();
        let mut env = OwnedEnvironment::new_cost_limited(
            ctx.mainnet,
            ctx.chain_id,
            db,
            state.tracker,
            ctx.epoch,
        );
        env.set_execution_resource_limiter(execution_budget.start_tracking());
        let result = interact(&mut env);
        let (mut db, tracker) = env
            .destruct()
            .ok_or_else(|| EngineError::Internal("OwnedEnvironment failed to destruct".into()))?;
        state.tracker = tracker;

        match result {
            Ok((value, assets, events)) => {
                let abort_reason = match abort {
                    Some(callback) => callback(&assets, &mut db),
                    None => None,
                };
                match abort_reason {
                    Some(reason) => {
                        let rolled_back = db.roll_back().map_err(EngineError::Execution);
                        ctx.restore_db(db);
                        self.park_state(ctx, state);
                        rolled_back?;
                        Err(EngineError::AbortedByCallback {
                            output: output_for_abort(&value),
                            assets: Box::new(assets),
                            events,
                            reason,
                        })
                    }
                    None => {
                        let committed = db.commit().map_err(EngineError::Execution);
                        ctx.restore_db(db);
                        let cost = self.park_state(ctx, state);
                        committed?;
                        Ok(((value, assets, events), cost))
                    }
                }
            }
            Err(e) => {
                let rolled_back = db.roll_back().map_err(EngineError::Execution);
                ctx.restore_db(db);
                self.park_state(ctx, state);
                rolled_back?;
                Err(e)
            }
        }
    }
}

impl Engine for LegacyEngine {
    fn name(&self) -> &'static str {
        "clarity-legacy-interpreter"
    }

    fn supported_versions(&self) -> &'static [ClarityVersion] {
        ClarityVersion::ALL
    }

    fn analyze_contract(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
        analysis_budget: &ResourceBudget,
    ) -> Result<AnalyzedContract, EngineError> {
        let TakenParts { mut state, db } = self.take_parts(ctx)?;

        // Mirror the production flow: the resource clock starts before AST
        // building so parse time counts against the analysis budget.
        let resource_limiter = analysis_budget.start_tracking();

        // 1) Parse, charging the cost tracker.
        let ast = match build_ast(contract, source, &mut state.tracker, version, ctx.epoch) {
            Ok(ast) => ast,
            Err(e) => {
                ctx.restore_db(db);
                self.park_state(ctx, state);
                return Err(EngineError::Parse(vec![e.diagnostic]));
            }
        };

        // 2) Static analysis, without persisting anything. The analysis
        // database is a different view over the *same* rollback state, so
        // hand the rollback wrapper across rather than the bare store —
        // uncommitted edits in open savepoints (e.g. a host's block-level
        // layer) must survive this round trip.
        let headers_db = db.get_headers_db();
        let burn_state_db = db.get_burn_state_db();
        let mut analysis_db = AnalysisDatabase::new_with_rollback_wrapper(db.destroy());
        let analysis_result = run_analysis(
            contract,
            &ast.expressions,
            &mut analysis_db,
            false,
            state.tracker,
            ctx.epoch,
            version,
            false,
            resource_limiter,
        );
        ctx.restore_db(ClarityDatabase::new_with_rollback_wrapper(
            analysis_db.destroy(),
            headers_db,
            burn_state_db,
        ));
        match analysis_result {
            Ok(mut analysis) => {
                state.tracker = analysis.take_contract_cost_tracker();
                let interface = analysis.to_stored();
                self.park_state(ctx, state);
                debug_assert_eq!(interface.contract_identifier, *contract);
                debug_assert_eq!(interface.clarity_version, version);
                Ok(AnalyzedContract::new(
                    source.to_owned(),
                    interface,
                    LegacyAnalysis { ast, analysis },
                ))
            }
            Err(boxed) => {
                let (check_error, tracker) = *boxed;
                state.tracker = tracker;
                self.park_state(ctx, state);
                Err(EngineError::Static(Box::new(check_error)))
            }
        }
    }

    fn initialize_contract(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
        sponsor: Option<PrincipalData>,
        abort: Option<AbortCallback>,
        execution_budget: &ResourceBudget,
    ) -> Result<DeployOutcome, EngineError> {
        let parts = self.take_parts(ctx)?;
        let legacy = match analyzed.engine_data::<LegacyAnalysis>() {
            Some(legacy) => legacy,
            None => {
                ctx.restore_db(parts.db);
                self.park_state(ctx, parts.state);
                return Err(EngineError::Internal(
                    "AnalyzedContract was produced by a different engine".into(),
                ));
            }
        };

        let (((), assets, events), cost) = self.with_abortable_env(
            ctx,
            parts,
            execution_budget,
            abort,
            |_: &()| None,
            |env| {
                env.initialize_contract_from_ast(
                    analyzed.contract().clone(),
                    analyzed.version(),
                    &legacy.ast,
                    analyzed.source(),
                    sponsor,
                )
                .map_err(EngineError::Execution)
            },
        )?;
        Ok(DeployOutcome {
            assets,
            events,
            cost,
        })
    }

    fn save_analysis(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
    ) -> Result<(), EngineError> {
        let TakenParts { state, db } = self.take_parts(ctx)?;
        let legacy = match analyzed.engine_data::<LegacyAnalysis>() {
            Some(legacy) => legacy,
            None => {
                ctx.restore_db(db);
                self.park_state(ctx, state);
                return Err(EngineError::Internal(
                    "AnalyzedContract was produced by a different engine".into(),
                ));
            }
        };

        // As in `analyze_contract`: hand the rollback wrapper across so any
        // uncommitted edits in open savepoints survive the round trip.
        let headers_db = db.get_headers_db();
        let burn_state_db = db.get_burn_state_db();
        let mut analysis_db = AnalysisDatabase::new_with_rollback_wrapper(db.destroy());
        analysis_db.begin();
        let result = match analysis_db.insert_contract(analyzed.contract(), &legacy.analysis) {
            Ok(()) => analysis_db
                .commit()
                .map_err(|e| EngineError::Static(Box::new(e))),
            Err(e) => {
                let rolled_back = analysis_db
                    .roll_back()
                    .map_err(|e| EngineError::Static(Box::new(e)));
                rolled_back.and(Err(EngineError::Static(Box::new(e))))
            }
        };
        ctx.restore_db(ClarityDatabase::new_with_rollback_wrapper(
            analysis_db.destroy(),
            headers_db,
            burn_state_db,
        ));
        self.park_state(ctx, state);
        result
    }

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
    ) -> Result<ExecutionOutcome, EngineError> {
        let parts = self.take_parts(ctx)?;
        let expr_args: Vec<_> = args
            .iter()
            .map(|arg| SymbolicExpression::atom_value(arg.clone()))
            .collect();
        let ((value, assets, events), cost) = self.with_abortable_env(
            ctx,
            parts,
            execution_budget,
            abort,
            |value: &Value| Some(Box::new(value.clone())),
            |env| {
                env.execute_transaction(sender, sponsor, contract.clone(), function, &expr_args)
                    .map_err(EngineError::Execution)
            },
        )?;
        Ok(ExecutionOutcome {
            value,
            assets,
            events,
            cost,
        })
    }

    fn eval_read_only(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, EngineError> {
        let TakenParts { mut state, db } = self.take_parts(ctx)?;
        let mut env = OwnedEnvironment::new_cost_limited(
            ctx.mainnet,
            ctx.chain_id,
            db,
            state.tracker,
            ctx.epoch,
        );
        let result = env.eval_read_only(contract, program).map_err(engine_error);
        let (db, tracker) = env
            .destruct()
            .ok_or_else(|| EngineError::Internal("OwnedEnvironment failed to destruct".into()))?;
        ctx.restore_db(db);
        state.tracker = tracker;
        self.park_state(ctx, state);
        result.map(|(value, _assets, _events)| value)
    }
}

#[cfg(test)]
mod tests {
    use clarity_kernel::costs::ExecutionCost;
    use clarity_kernel::resource_limiter::ResourceBudget;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::StacksEpochId;

    use super::*;
    use crate::vm::database::{ClarityDatabaseExt, MemoryBackingStore};
    use crate::vm::types::StandardPrincipalData;

    const COUNTER: &str = "(define-data-var count uint u0)
         (define-read-only (get-count) (var-get count))
         (define-public (increment)
           (ok (var-set count (+ (var-get count) u1))))";

    fn setup_store(epoch: StacksEpochId) -> MemoryBackingStore {
        let mut store = MemoryBackingStore::new();
        {
            let mut db = store.as_clarity_db();
            db.begin();
            db.set_clarity_epoch_version(epoch).unwrap();
            db.commit().unwrap();
        }
        store
    }

    fn contract_id(name: &str) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(
            StandardPrincipalData::transient(),
            name.to_string().try_into().unwrap(),
        )
    }

    #[test]
    fn deploy_call_and_read_through_abi_with_metered_costs() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("counter");
        let sender: PrincipalData = StandardPrincipalData::transient().into();

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch)
                .with_budget(CostBudget::Limited(ExecutionCost::max_value()));

        let deploy = engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap();
        assert!(deploy.cost.runtime > 0, "deploy must consume budget");

        let call = engine
            .execute_call(
                &mut ctx,
                sender,
                None,
                &id,
                "increment",
                &[],
                None,
                &ResourceBudget::unlimited(),
            )
            .unwrap();
        assert_eq!(call.value, Value::okay(Value::Bool(true)).unwrap());
        assert!(
            call.cost.runtime > deploy.cost.runtime,
            "cost must accumulate across interactions in one context"
        );

        let count = engine.eval_read_only(&mut ctx, &id, "(get-count)").unwrap();
        assert_eq!(count, Value::UInt(1));
    }

    #[test]
    fn deploy_persists_contract_analysis() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("analyzed");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap();

        let mut db = ctx.into_db().unwrap();
        db.begin();
        let analysis = db.load_contract_analysis(&id).unwrap();
        db.roll_back().unwrap();
        let analysis = analysis.expect("deploy must persist the contract analysis");
        assert!(analysis.read_only_function_types.contains_key("get-count"));
        assert!(analysis.public_function_types.contains_key("increment"));
    }

    #[test]
    fn exhausted_budget_fails_and_context_stays_usable() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("broke");

        // A one-runtime-unit budget cannot even parse the contract.
        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch)
                .with_budget(CostBudget::Limited(ExecutionCost {
                    runtime: 1,
                    ..ExecutionCost::ZERO
                }));

        let err = engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap_err();
        // Budget exhaustion during parsing surfaces as a parse failure; the
        // important property is that it fails rather than executing free.
        assert!(
            matches!(err, EngineError::Parse(_) | EngineError::Execution(_)),
            "unexpected error variant: {err:?}"
        );

        // The context must have its database (and tracker) restored.
        assert!(ctx.into_db().is_some());
    }

    #[test]
    fn static_check_failure_is_reported_and_not_deployed() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("illtyped");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        let err = engine
            .deploy_contract(
                &mut ctx,
                &id,
                "(define-public (bad) (ok (+ u1 1)))",
                ClarityVersion::latest(),
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, EngineError::Static(_)),
            "unexpected error variant: {err:?}"
        );

        let mut db = ctx.into_db().unwrap();
        db.begin();
        assert!(!db.has_contract(&id), "failed deploy must not persist");
        db.roll_back().unwrap();
    }

    /// The kernel's `StoredContractAnalysis` must serialize byte-identically
    /// to the direct serde output of this engine's `ContractAnalysis` — the
    /// stored metadata format must not change. Exercises functions, maps,
    /// variables, tokens, traits, and a built contract interface.
    #[test]
    fn stored_format_is_byte_identical() {
        use clarity_kernel::analysis::StoredContractAnalysis;

        use crate::vm::analysis::contract_interface_builder::build_contract_interface;
        use crate::vm::analysis::{ContractAnalysis, mem_type_check};
        use crate::vm::database::{ClarityDeserializable, ClaritySerializable};

        let source = "(define-trait exchange ((swap (uint uint) (response uint uint))))
             (define-map orders { id: uint } { amount: uint, who: (optional principal) })
             (define-data-var order-count uint u0)
             (define-fungible-token points)
             (define-non-fungible-token badge (string-ascii 32))
             (define-read-only (get-order (id uint)) (map-get? orders { id: id }))
             (define-private (bump) (var-set order-count (+ (var-get order-count) u1)))
             (define-public (place (id uint) (amount uint))
               (begin (bump) (ok (map-insert orders { id: id } { amount: amount, who: none }))))";
        let epoch = StacksEpochId::latest();
        let (_, mut analysis) = mem_type_check(source, ClarityVersion::latest(), epoch).unwrap();
        analysis.contract_interface = Some(build_contract_interface(&analysis).unwrap());

        let direct = serde_json::to_string(&analysis).unwrap();
        let via_stored = ClaritySerializable::serialize(&analysis);
        assert_eq!(direct, via_stored, "stored analysis format changed!");

        // And the load path round-trips through the kernel type.
        let stored = StoredContractAnalysis::deserialize(&via_stored).unwrap();
        assert_eq!(analysis.to_stored(), stored);
        let rehydrated = ContractAnalysis::from_stored(stored);
        assert_eq!(
            serde_json::to_string(&rehydrated).unwrap(),
            direct,
            "round-trip through the stored form must be lossless"
        );
    }

    #[test]
    fn parse_failure_carries_diagnostics() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        let err = engine
            .deploy_contract(
                &mut ctx,
                &contract_id("unparsable"),
                "(define-public (broken",
                ClarityVersion::latest(),
                None,
            )
            .unwrap_err();
        match err {
            EngineError::Parse(diagnostics) => assert!(!diagnostics.is_empty()),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn abort_callback_rolls_back_a_successful_call() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("aborted");
        let sender: PrincipalData = StandardPrincipalData::transient().into();

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap();

        // The call itself succeeds, but the host rejects it post-execution
        // (this is how post-conditions are enforced).
        let mut abort = |_assets: &AssetMap, _db: &mut ClarityDatabase| -> Option<String> {
            Some("post-condition failed".into())
        };
        let err = engine
            .execute_call(
                &mut ctx,
                sender,
                None,
                &id,
                "increment",
                &[],
                Some(&mut abort),
                &ResourceBudget::unlimited(),
            )
            .unwrap_err();
        match err {
            EngineError::AbortedByCallback { output, reason, .. } => {
                assert_eq!(*output.unwrap(), Value::okay(Value::Bool(true)).unwrap());
                assert_eq!(reason, "post-condition failed");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        // The increment must have been rolled back.
        let count = engine.eval_read_only(&mut ctx, &id, "(get-count)").unwrap();
        assert_eq!(count, Value::UInt(0));
    }

    #[test]
    fn phased_deploy_matches_production_flow() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("phased");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);

        // Phase 1: analyze — nothing persisted yet. The host holds the
        // handle across the phases, as the node's transaction path does.
        let analyzed = engine
            .analyze_contract(
                &mut ctx,
                &id,
                COUNTER,
                ClarityVersion::latest(),
                &ResourceBudget::unlimited(),
            )
            .unwrap();
        assert!(
            analyzed
                .interface()
                .public_function_types
                .contains_key("increment")
        );
        assert_eq!(analyzed.contract(), &id);
        assert_eq!(analyzed.version(), ClarityVersion::latest());
        assert_eq!(analyzed.source(), COUNTER);

        // Phase 2: initialize (reuses the analyzed contract's AST).
        engine
            .initialize_contract(
                &mut ctx,
                &analyzed,
                None,
                None,
                &ResourceBudget::unlimited(),
            )
            .unwrap();

        // Phase 3: persist the analysis.
        engine.save_analysis(&mut ctx, &analyzed).unwrap();

        let mut db = ctx.into_db().unwrap();
        db.begin();
        assert!(db.has_contract(&id));
        let analysis = db.load_contract_analysis(&id).unwrap();
        db.roll_back().unwrap();
        assert!(analysis.is_some(), "analysis must be persisted by phase 3");
    }

    #[test]
    fn aborted_initialize_persists_nothing() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("aborted-deploy");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        let analyzed = engine
            .analyze_contract(
                &mut ctx,
                &id,
                COUNTER,
                ClarityVersion::latest(),
                &ResourceBudget::unlimited(),
            )
            .unwrap();

        let mut abort = |_assets: &AssetMap, _db: &mut ClarityDatabase| -> Option<String> {
            Some("rejected".into())
        };
        let err = engine
            .initialize_contract(
                &mut ctx,
                &analyzed,
                None,
                Some(&mut abort),
                &ResourceBudget::unlimited(),
            )
            .unwrap_err();
        assert!(matches!(err, EngineError::AbortedByCallback { .. }));

        let mut db = ctx.into_db().unwrap();
        db.begin();
        assert!(!db.has_contract(&id), "aborted deploy must not persist");
        db.roll_back().unwrap();
    }

    /// Hosts run the ABI against a database with an *open* savepoint holding
    /// uncommitted work — `ClarityTransactionConnection` keeps exactly that
    /// shape (a persisted rollback log at depth 1) across a block. The
    /// analysis phases swap the `ClarityDatabase` for an `AnalysisDatabase`
    /// view, and must carry the rollback state across rather than dropping
    /// back to the bare backing store.
    #[test]
    fn analysis_preserves_uncommitted_rollback_state() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let first = contract_id("first");
        let second = contract_id("second");

        let mut db = store.as_clarity_db();
        // The host's outer, uncommitted layer.
        db.begin();
        let mut ctx = TransactionContext::new(db, false, CHAIN_ID_TESTNET, epoch);

        // Deploy inside the uncommitted layer.
        engine
            .deploy_contract(&mut ctx, &first, COUNTER, ClarityVersion::latest(), None)
            .unwrap();

        // Analyzing another contract must not disturb the open layer.
        engine
            .analyze_contract(
                &mut ctx,
                &second,
                COUNTER,
                ClarityVersion::latest(),
                &ResourceBudget::unlimited(),
            )
            .unwrap();

        let mut db = ctx.into_db().unwrap();
        assert!(
            db.has_contract(&first),
            "uncommitted deploy must survive a later analysis"
        );

        // And it really was uncommitted: rolling the outer layer back drops it.
        db.roll_back().unwrap();
        assert!(!db.has_contract(&first));
    }

    /// A handle produced by another engine must be rejected, not silently
    /// mis-executed.
    #[test]
    fn foreign_analyzed_contract_is_rejected() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("foreign");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        // Some other engine's payload.
        let analyzed = engine
            .analyze_contract(
                &mut ctx,
                &id,
                COUNTER,
                ClarityVersion::latest(),
                &ResourceBudget::unlimited(),
            )
            .unwrap();
        let foreign = AnalyzedContract::new(
            COUNTER.to_owned(),
            analyzed.interface().clone(),
            "not-a-legacy-analysis",
        );

        let err = engine.save_analysis(&mut ctx, &foreign).unwrap_err();
        assert!(matches!(err, EngineError::Internal(_)));
        // The context stays usable.
        assert!(ctx.into_db().is_some());
    }

    /// A host can thread its own (e.g. block-level) cost tracker through the
    /// engine rather than having one built from the context's budget.
    #[test]
    fn host_installed_cost_tracker_is_used_and_recovered() {
        use crate::vm::costs::LimitedCostTracker;

        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("host-tracker");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        let tracker = {
            let mut db = ctx.take_db().unwrap();
            let tracker = LimitedCostTracker::new(
                false,
                CHAIN_ID_TESTNET,
                ExecutionCost::max_value(),
                &mut db,
                epoch,
            )
            .unwrap();
            ctx.restore_db(db);
            tracker
        };
        LegacyEngine::install_cost_tracker(&mut ctx, tracker);
        ctx.set_engine_state::<String>("another engine's state".into());

        engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap();

        let recovered = LegacyEngine::take_cost_tracker(&mut ctx)
            .expect("host must be able to recover its tracker");
        assert!(
            recovered.get_total().runtime > 0,
            "the host's tracker must be the one that was charged"
        );
        assert_eq!(
            *ctx.take_engine_state::<String>()
                .expect("one engine must not overwrite another engine's state"),
            "another engine's state"
        );
    }
}
