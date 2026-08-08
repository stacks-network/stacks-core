// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::mem::replace;

use clarity_kernel::engine::{ContractDispatcher, RuntimeContext, RuntimeSlot};
pub use clarity_kernel::transaction::{CallStack, EventBatch, TransactionFrame};
use clarity_types::representations::ClarityName;
use serde::Serialize;
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::StacksBlockId;

use super::hooks::{
    CallArguments, CallHook, CallTraceFrame, EvalHook, EvalHookNotifier, ExecutionOutcome,
};
use crate::vm::ast::ContractAST;
use crate::vm::ast::errors::{ParseError, ParseErrorKind};
use crate::vm::callables::DefinedFunction;
use crate::vm::contracts::Contract;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::execution_cost::ExecutionCost;
use crate::vm::costs::{
    CostErrors, CostTracker, CostTrackerHandle, LimitedCostTracker, runtime_cost,
};
use crate::vm::database::{
    ClarityDatabase, ClarityDatabaseExt, DataMapMetadata, DataVariableMetadata,
    FungibleTokenMetadata, NonFungibleTokenMetadata,
};
use crate::vm::errors::{
    ClarityEvalError, RuntimeCheckErrorKind, RuntimeError, VmExecutionError, VmInternalError,
};
use crate::vm::events::*;
use crate::vm::representations::SymbolicExpression;
use crate::vm::resource_limiter::ResourceLimiter;
use crate::vm::types::signatures::FunctionSignature;
use crate::vm::types::{
    AssetIdentifier, BuffData, CallableData, PrincipalData, QualifiedContractIdentifier,
    TraitIdentifier, TypeSignature, Value,
};
use crate::vm::version::ClarityVersion;
use crate::vm::{ValueRef, ast, eval, is_reserved, stx_transfer_consolidated};

pub const MAX_CONTEXT_DEPTH: u64 = 256;

/// Immutable metadata describing a single contract invocation.
///
/// `InvocationContext` captures *who* is executing *which contract* under what authority.
/// It contains the principals that define call semantics (`sender`, `caller`, `sponsor`)
/// together with the active `ContractContext`.
///
/// A new `InvocationContext` is derived whenever a contract call changes authority
/// (e.g., `contract-call?`, `as-contract`, or sponsor propagation). It is intentionally
/// immutable so that nested calls cannot mutate the caller's view of authority.
///
/// This type does **not** contain mutable VM state (database, cost tracker, events, stack).
/// Those live in [`ExecutionState`]. Lexical variables and scope live in [`LocalContext`].
///
/// Together:
/// - `InvocationContext` → authority + contract binding
/// - `ExecutionState`    → mutable runtime state
/// - `LocalContext`      → lexical variables/scope
pub struct InvocationContext<'a> {
    /// The contract currently being executed.
    pub contract_context: &'a ContractContext,
    /// The transaction sender for this invocation (tx origin or `as-contract` principal).
    pub sender: Option<PrincipalData>,
    /// The immediate caller of the current contract (may differ from `sender` in nested calls).
    pub caller: Option<PrincipalData>,
    /// The sponsor responsible for paying execution costs, if any.
    pub sponsor: Option<PrincipalData>,
}

impl InvocationContext<'_> {
    /// Returns a derived invocation context executing *as* the given principal.
    ///
    /// Both `sender` and `caller` are set to `sender`
    /// The sponsor and contract context are preserved.
    pub fn with_principal(&self, sender: PrincipalData) -> Self {
        InvocationContext {
            contract_context: self.contract_context,
            sender: Some(sender.clone()),
            caller: Some(sender),
            sponsor: self.sponsor.clone(),
        }
    }

    /// Returns a derived invocation context with a different immediate caller.
    ///
    /// This models a nested contract call where authority flows from the same
    /// transaction sender but the caller changes to the calling contract.
    /// The sender, sponsor, and contract context are preserved.
    pub fn with_caller(&self, caller: PrincipalData) -> Self {
        InvocationContext {
            contract_context: self.contract_context,
            sender: self.sender.clone(),
            caller: Some(caller),
            sponsor: self.sponsor.clone(),
        }
    }

    /// Returns a derived invocation context bound to another contract context.
    ///
    /// Models entering a different contract while preserving the same authority
    /// (sender, caller, and sponsor are carried over unchanged).
    pub fn with_contract_context<'c>(
        &self,
        contract_context: &'c ContractContext,
    ) -> InvocationContext<'c> {
        InvocationContext {
            contract_context,
            sender: self.sender.clone(),
            caller: self.caller.clone(),
            sponsor: self.sponsor.clone(),
        }
    }
}

/// Options for executing a defined function through a transaction boundary.
#[derive(Clone, Copy)]
pub struct FunctionExecutionOptions<'a> {
    next_contract_context: Option<&'a ContractContext>,
    allow_private: bool,
}

impl Default for FunctionExecutionOptions<'_> {
    /// Initializes execution options with the default settings:
    ///
    /// * `next_contract_context`: `None` (execute in the current contract context)
    /// * `allow_private`: `false` (enforce public-call visibility)
    fn default() -> Self {
        Self {
            next_contract_context: None,
            allow_private: false,
        }
    }
}

impl<'a> FunctionExecutionOptions<'a> {
    /// Controls whether private functions are accepted when handling the transaction result.
    pub fn allow_private(mut self, allow_private: bool) -> Self {
        self.allow_private = allow_private;
        self
    }

    /// Executes the function against another contract context.
    pub fn with_next_contract(
        mut self,
        next_contract_context: impl Into<Option<&'a ContractContext>>,
    ) -> Self {
        self.next_contract_context = next_contract_context.into();
        self
    }
}

/// `ExecutionState` contains the parts of the VM environment that may change during
/// evaluation: the global chainstate (`GlobalContext`) and the Clarity call stack.
/// All database writes, event emission, cost tracking, and stack mutations occur
/// through this structure.
///
/// Unlike [`InvocationContext`], this state is shared and mutated throughout the
/// lifetime of a single invocation. Nested contract or function calls reborrow the
/// same `ExecutionState` while deriving new `InvocationContext` and/or `LocalContext`
/// values.
///
/// Separation of concerns:
/// - `ExecutionState`    → mutable VM/runtime state
/// - `InvocationContext` → authority + contract binding
/// - `LocalContext`      → lexical variables/scope
pub struct ExecutionState<'a, 'b, 'hooks> {
    /// Global chainstate and database access for this execution.
    pub global_context: &'a mut GlobalContext<'b, 'hooks>,

    /// The Clarity call stack tracking nested function/contract calls.
    pub call_stack: &'a mut CallStack,
}

pub struct OwnedEnvironment<'a, 'hooks> {
    pub(crate) context: GlobalContext<'a, 'hooks>,
    call_stack: RuntimeSlot<CallStack>,
}

pub use clarity_kernel::assets::{AssetMap, AssetMapEntry};

/** GlobalContext represents the outermost context for a single transaction's
     execution. It tracks any asset changes that occurred during the
     processing of the transaction, whether or not the current context is read_only,
     and is responsible for committing/rolling-back transactions as they error or
     abort.
*/
pub struct GlobalContext<'a, 'hooks> {
    pub transaction: RuntimeSlot<TransactionFrame>,
    pub database: RuntimeSlot<ClarityDatabase<'a>>,
    pub cost_track: RuntimeSlot<CostTrackerHandle>,
    pub mainnet: bool,
    /// This is the epoch of the block that this transaction is executing within.
    pub epoch_id: StacksEpochId,
    /// This is the chain ID of the transaction
    pub chain_id: u32,
    pub eval_hooks: Option<Vec<&'hooks mut dyn EvalHook>>,
    pub dispatcher: Option<&'hooks mut (dyn ContractDispatcher + 'hooks)>,
    /// A resource limiter that will be polled on every `eval` to check that execution
    /// time and heap allocation don't exceed configured maximums
    pub execution_resource_limiter: ResourceLimiter,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ContractContext {
    /// The identifier of this contract
    pub contract_identifier: QualifiedContractIdentifier,
    /// Despite being called `variables`, these are actually the constants defined in the contract
    pub variables: HashMap<ClarityName, Value>,
    /// The functions defined in this contract, mapped by their name
    pub functions: HashMap<ClarityName, DefinedFunction>,
    /// The traits defined in this contract, mapped by their name, to a map of the trait's function
    /// signatures
    pub defined_traits: HashMap<ClarityName, BTreeMap<ClarityName, FunctionSignature>>,
    /// The traits implemented by this contract
    pub implemented_traits: HashSet<TraitIdentifier>,
    /// The names of NFTs, FTs, Maps, and Data Vars, used to ensure that they never are defined twice
    pub persisted_names: HashSet<ClarityName>,
    /// Key/value types for contract defined maps
    pub meta_data_map: HashMap<ClarityName, DataMapMetadata>,
    /// Types for contract defined data variables
    pub meta_data_var: HashMap<ClarityName, DataVariableMetadata>,
    /// Key types for contract defined non-fungible tokens
    pub meta_nft: HashMap<ClarityName, NonFungibleTokenMetadata>,
    /// Total supply for contract defined fungible tokens
    pub meta_ft: HashMap<ClarityName, FungibleTokenMetadata>,
    /// The total size of constants stored by this contract
    pub data_size: u64,
    /// The clarity version of this contract
    clarity_version: ClarityVersion,
    /// True while the contract is being deployed (inside `initialize_from_ast`).
    /// Constants may only be used as `contract-call?` dispatch targets
    /// after deployment, when their values are frozen.
    #[serde(skip)]
    pub is_deploying: bool,
}

pub struct LocalContext<'a> {
    pub function_context: Option<&'a LocalContext<'a>>,
    pub parent: Option<&'a LocalContext<'a>>,
    pub variables: HashMap<ClarityName, Value>,
    pub callable_contracts: HashMap<ClarityName, CallableData>,
    depth: u64,
}

pub const TRANSIENT_CONTRACT_NAME: &str = "__transient";

impl<'a, 'hooks> OwnedEnvironment<'a, 'hooks> {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(database: ClarityDatabase<'a>, epoch: StacksEpochId) -> OwnedEnvironment<'a, 'a> {
        OwnedEnvironment {
            context: GlobalContext::new(
                false,
                stacks_common::consts::CHAIN_ID_TESTNET,
                database,
                LimitedCostTracker::new_free(),
                epoch,
            ),
            call_stack: RuntimeSlot::new(CallStack::new()),
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_toplevel(mut database: ClarityDatabase<'a>) -> OwnedEnvironment<'a, 'a> {
        database.begin();
        let epoch = database.get_clarity_epoch_version().unwrap();
        let version = ClarityVersion::default_for_epoch(epoch);
        database.roll_back().unwrap();

        debug!("Begin OwnedEnvironment(epoch = {epoch}, version = {version})");
        OwnedEnvironment {
            context: GlobalContext::new(
                false,
                stacks_common::consts::CHAIN_ID_TESTNET,
                database,
                LimitedCostTracker::new_free(),
                epoch,
            ),
            call_stack: RuntimeSlot::new(CallStack::new()),
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_max_limit(
        mut database: ClarityDatabase<'a>,
        epoch: StacksEpochId,
        use_mainnet: bool,
    ) -> OwnedEnvironment<'a, 'a> {
        use crate::vm::tests::test_only_mainnet_to_chain_id;
        let cost_track = LimitedCostTracker::new_max_limit(&mut database, epoch, use_mainnet)
            .expect("FAIL: problem instantiating cost tracking");
        let chain_id = test_only_mainnet_to_chain_id(use_mainnet);

        OwnedEnvironment {
            context: GlobalContext::new(use_mainnet, chain_id, database, cost_track, epoch),
            call_stack: RuntimeSlot::new(CallStack::new()),
        }
    }

    pub fn new_free(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        epoch_id: StacksEpochId,
    ) -> OwnedEnvironment<'a, 'a> {
        OwnedEnvironment {
            context: GlobalContext::new(
                mainnet,
                chain_id,
                database,
                LimitedCostTracker::new_free(),
                epoch_id,
            ),
            call_stack: RuntimeSlot::new(CallStack::new()),
        }
    }

    pub fn new_cost_limited(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        cost_tracker: LimitedCostTracker,
        epoch_id: StacksEpochId,
    ) -> OwnedEnvironment<'a, 'a> {
        Self::new_with_cost_tracker_handle(
            mainnet,
            chain_id,
            database,
            CostTrackerHandle::new(cost_tracker),
            epoch_id,
        )
    }

    /// Build an environment around the kernel-owned transaction tracker.
    /// Unlike [`Self::new_cost_limited`], this preserves the concrete tracker
    /// opaquely so it can cross into another engine unchanged.
    pub fn new_with_cost_tracker_handle(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        cost_tracker: CostTrackerHandle,
        epoch_id: StacksEpochId,
    ) -> OwnedEnvironment<'a, 'a> {
        Self::new_with_shared_transaction(
            mainnet,
            chain_id,
            database,
            cost_tracker,
            TransactionFrame::new(),
            CallStack::new(),
            epoch_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_shared_transaction(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        cost_tracker: CostTrackerHandle,
        transaction: TransactionFrame,
        call_stack: CallStack,
        epoch_id: StacksEpochId,
    ) -> OwnedEnvironment<'a, 'a> {
        OwnedEnvironment {
            context: GlobalContext::new_with_transaction_frame(
                mainnet,
                chain_id,
                database,
                cost_tracker,
                transaction,
                epoch_id,
            ),
            call_stack: RuntimeSlot::new(call_stack),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_dispatcher(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        cost_tracker: CostTrackerHandle,
        transaction: TransactionFrame,
        call_stack: CallStack,
        epoch_id: StacksEpochId,
        dispatcher: Option<&'hooks mut (dyn ContractDispatcher + 'hooks)>,
    ) -> OwnedEnvironment<'a, 'hooks> {
        OwnedEnvironment {
            context: GlobalContext::new_with_transaction_frame(
                mainnet,
                chain_id,
                database,
                cost_tracker,
                transaction,
                epoch_id,
            ),
            call_stack: RuntimeSlot::new(call_stack),
        }
        .with_dispatcher(dispatcher)
    }

    fn with_dispatcher(
        mut self,
        dispatcher: Option<&'hooks mut (dyn ContractDispatcher + 'hooks)>,
    ) -> Self {
        self.context.dispatcher = dispatcher;
        self
    }

    /// Registers an evaluation hook for this environment.
    pub fn add_eval_hook(&mut self, hook: &'hooks mut dyn EvalHook) {
        if let Some(mut hooks) = self.context.eval_hooks.take() {
            hooks.push(hook);
            self.context.eval_hooks = Some(hooks);
        } else {
            self.context.eval_hooks = Some(vec![hook]);
        }
    }

    pub fn set_execution_resource_limiter(&mut self, resource_limiter: ResourceLimiter) {
        self.context
            .set_execution_resource_limiter(resource_limiter);
    }

    pub fn get_exec_environment<'b>(
        &'b mut self,
        sender: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        context: &'b ContractContext,
    ) -> (ExecutionState<'b, 'a, 'hooks>, InvocationContext<'b>) {
        self.get_exec_environment_with_caller(sender.clone(), sender, sponsor, context)
    }

    pub fn get_exec_environment_with_caller<'b>(
        &'b mut self,
        sender: Option<PrincipalData>,
        caller: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        context: &'b ContractContext,
    ) -> (ExecutionState<'b, 'a, 'hooks>, InvocationContext<'b>) {
        (
            ExecutionState {
                global_context: &mut self.context,
                call_stack: &mut self.call_stack,
            },
            InvocationContext {
                contract_context: context,
                sender,
                caller,
                sponsor,
            },
        )
    }

    pub fn execute_in_env<F, A, E>(
        &mut self,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        initial_context: Option<ContractContext>,
        f: F,
    ) -> std::result::Result<(A, AssetMap, Vec<StacksTransactionEvent>), E>
    where
        E: From<VmExecutionError>,
        F: FnOnce(&mut ExecutionState, &InvocationContext) -> std::result::Result<A, E>,
    {
        assert!(self.context.is_top_level());
        self.begin();

        let result = {
            let initial_context = initial_context.unwrap_or(ContractContext::new(
                QualifiedContractIdentifier::transient(),
                ClarityVersion::Clarity1,
            ));
            let (mut exec_state, invoke_ctx) =
                self.get_exec_environment(Some(sender), sponsor, &initial_context);
            exec_state.global_context.notify_will_begin_execution();
            let result = f(&mut exec_state, &invoke_ctx);
            let outcome = if result.is_ok() {
                ExecutionOutcome::Success
            } else {
                ExecutionOutcome::Failure
            };
            exec_state
                .global_context
                .notify_did_finish_execution(outcome);
            result
        };

        match result {
            Ok(return_value) => {
                let (asset_map, event_batch) = self.commit()?;
                Ok((return_value, asset_map, event_batch.events))
            }
            Err(e) => {
                self.context.roll_back()?;
                Err(e)
            }
        }
    }

    /// Initialize a contract with the "default" contract context (i.e. clarity1, transient ID).
    /// No longer appropriate outside of testing, now that there are multiple clarity versions.
    #[cfg(any(test, feature = "testing"))]
    pub fn initialize_contract(
        &mut self,
        contract_identifier: QualifiedContractIdentifier,
        contract_content: &str,
        sponsor: Option<PrincipalData>,
    ) -> Result<((), AssetMap, Vec<StacksTransactionEvent>), ClarityEvalError> {
        self.execute_in_env(
            contract_identifier.issuer.clone().into(),
            sponsor,
            None,
            |exec_state, invoke_ctx| {
                exec_state.initialize_contract(invoke_ctx, contract_identifier, contract_content)
            },
        )
    }

    pub fn initialize_versioned_contract(
        &mut self,
        contract_identifier: QualifiedContractIdentifier,
        version: ClarityVersion,
        contract_content: &str,
        sponsor: Option<PrincipalData>,
    ) -> Result<((), AssetMap, Vec<StacksTransactionEvent>), ClarityEvalError> {
        self.execute_in_env(
            contract_identifier.issuer.clone().into(),
            sponsor,
            Some(ContractContext::new(
                QualifiedContractIdentifier::transient(),
                version,
            )),
            |exec_state, invoke_ctx| {
                exec_state.initialize_contract(invoke_ctx, contract_identifier, contract_content)
            },
        )
    }

    pub fn initialize_contract_from_ast(
        &mut self,
        contract_identifier: QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
        contract_content: &ContractAST,
        contract_string: &str,
        sponsor: Option<PrincipalData>,
    ) -> Result<((), AssetMap, Vec<StacksTransactionEvent>), VmExecutionError> {
        self.execute_in_env(
            contract_identifier.issuer.clone().into(),
            sponsor,
            Some(ContractContext::new(
                QualifiedContractIdentifier::transient(),
                clarity_version,
            )),
            |exec_state, invoke_ctx| {
                exec_state.initialize_contract_from_ast(
                    invoke_ctx,
                    contract_identifier,
                    clarity_version,
                    contract_content,
                    contract_string,
                )
            },
        )
    }

    pub fn execute_transaction(
        &mut self,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract_identifier: QualifiedContractIdentifier,
        tx_name: &str,
        args: &[SymbolicExpression],
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), VmExecutionError> {
        self.execute_in_env(sender, sponsor, None, |exec_state, invoke_ctx| {
            exec_state.execute_contract(invoke_ctx, &contract_identifier, tx_name, args, false)
        })
    }

    /// Enter a contract from another engine without creating a new top-level
    /// interaction frame. The caller supplied by the outer engine is retained
    /// verbatim for `contract-caller` and `tx-sender` semantics.
    pub fn execute_nested_transaction(
        &mut self,
        sender: Option<PrincipalData>,
        caller: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        contract_identifier: &QualifiedContractIdentifier,
        tx_name: &str,
        args: &[SymbolicExpression],
    ) -> Result<Value, VmExecutionError> {
        let initial_context = ContractContext::new(
            QualifiedContractIdentifier::transient(),
            ClarityVersion::Clarity1,
        );
        let (mut exec_state, invoke_ctx) =
            self.get_exec_environment_with_caller(sender, caller, sponsor, &initial_context);
        exec_state.execute_contract(&invoke_ctx, contract_identifier, tx_name, args, false)
    }

    pub fn stx_transfer(
        &mut self,
        from: &PrincipalData,
        to: &PrincipalData,
        amount: u128,
        memo: &BuffData,
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), VmExecutionError> {
        self.execute_in_env(from.clone(), None, None, |exec_state, invoke_ctx| {
            exec_state.stx_transfer(invoke_ctx, from, to, amount, memo)
        })
    }

    pub fn is_mainnet(&self) -> bool {
        self.context.mainnet
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn stx_faucet(&mut self, recipient: &PrincipalData, amount: u128) {
        self.execute_in_env::<_, _, VmExecutionError>(
            recipient.clone(),
            None,
            None,
            |exec_state, _invoke_ctx| {
                let mut snapshot = exec_state
                    .global_context
                    .database
                    .get_stx_balance_snapshot(recipient)
                    .unwrap();

                snapshot.credit(amount).unwrap();
                snapshot.save().unwrap();

                exec_state
                    .global_context
                    .database
                    .increment_ustx_liquid_supply(amount)
                    .unwrap();

                let res: std::result::Result<(), VmExecutionError> = Ok(());
                res
            },
        )
        .unwrap();
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn eval_raw(
        &mut self,
        program: &str,
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), ClarityEvalError> {
        self.execute_in_env(
            QualifiedContractIdentifier::transient().issuer.into(),
            None,
            None,
            |exec_state, invoke_ctx| exec_state.eval_raw(invoke_ctx, program),
        )
    }

    pub fn eval_read_only(
        &mut self,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), ClarityEvalError> {
        self.execute_in_env(
            QualifiedContractIdentifier::transient().issuer.into(),
            None,
            None,
            |exec_state, invoke_ctx| exec_state.eval_read_only(invoke_ctx, contract, program),
        )
    }

    pub fn begin(&mut self) {
        self.context.begin();
    }

    pub fn commit(&mut self) -> Result<(AssetMap, EventBatch), VmExecutionError> {
        let (asset_map, event_batch) = self.context.commit()?;
        let asset_map = asset_map.ok_or(VmInternalError::FailedToConstructAssetTable)?;
        let event_batch = event_batch.ok_or(VmInternalError::FailedToConstructEventBatch)?;

        Ok((asset_map, event_batch))
    }

    pub fn get_cost_total(&self) -> ExecutionCost {
        self.context.cost_track.get_total()
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn mut_cost_tracker(&mut self) -> &mut LimitedCostTracker {
        self.context
            .cost_track
            .downcast_mut()
            .expect("test environment does not contain a LimitedCostTracker")
    }

    /// Destroys this environment, returning ownership of its database reference.
    ///  If the context wasn't top-level (i.e., it had uncommitted data), return None,
    ///   because the database is not guaranteed to be in a sane state.
    pub fn destruct(self) -> Option<(ClarityDatabase<'a>, LimitedCostTracker)> {
        let (db, tracker, _) = self.context.destruct()?;
        let tracker = tracker.into_inner::<LimitedCostTracker>().ok()?;
        Some((db, *tracker))
    }

    /// Destroy this environment without exposing the concrete shared tracker.
    pub fn destruct_with_cost_tracker_handle(
        self,
    ) -> Option<(ClarityDatabase<'a>, CostTrackerHandle)> {
        let (db, tracker, _) = self.context.destruct()?;
        Some((db, tracker))
    }

    pub fn destruct_with_shared_transaction(
        self,
    ) -> Option<(
        ClarityDatabase<'a>,
        CostTrackerHandle,
        TransactionFrame,
        CallStack,
    )> {
        let Self {
            context,
            call_stack,
        } = self;
        let (db, tracker, transaction) = context.destruct()?;
        Some((db, tracker, transaction, call_stack.into_inner()?))
    }

    /// Destroy a nested-call environment and recover the shared runtime
    /// without requiring the database to have no open savepoints. External
    /// engines use this to return state borrowed through the kernel ABI to
    /// the suspended caller.
    pub fn destruct_nested_with_shared_transaction(
        self,
    ) -> Option<(
        ClarityDatabase<'a>,
        CostTrackerHandle,
        TransactionFrame,
        CallStack,
    )> {
        let Self {
            context,
            call_stack,
        } = self;
        let (db, tracker, transaction) = context.into_runtime_parts()?;
        Some((db, tracker, transaction, call_stack.into_inner()?))
    }
}

impl CostTracker for ExecutionState<'_, '_, '_> {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> std::result::Result<ExecutionCost, CostErrors> {
        self.global_context
            .cost_track
            .compute_cost(cost_function, input)
    }
    fn add_cost(&mut self, cost: ExecutionCost) -> std::result::Result<(), CostErrors> {
        self.global_context.cost_track.add_cost(cost)
    }
    fn add_memory(&mut self, memory: u64) -> std::result::Result<(), CostErrors> {
        self.global_context.cost_track.add_memory(memory)
    }
    fn drop_memory(&mut self, memory: u64) -> std::result::Result<(), CostErrors> {
        self.global_context.cost_track.drop_memory(memory)
    }
    fn reset_memory(&mut self) {
        self.global_context.cost_track.reset_memory()
    }
    fn short_circuit_contract_call(
        &mut self,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        input: &[u64],
    ) -> std::result::Result<bool, CostErrors> {
        self.global_context
            .cost_track
            .short_circuit_contract_call(contract, function, input)
    }
}

impl CostTracker for GlobalContext<'_, '_> {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> std::result::Result<ExecutionCost, CostErrors> {
        self.cost_track.compute_cost(cost_function, input)
    }

    fn add_cost(&mut self, cost: ExecutionCost) -> std::result::Result<(), CostErrors> {
        self.cost_track.add_cost(cost)
    }
    fn add_memory(&mut self, memory: u64) -> std::result::Result<(), CostErrors> {
        self.cost_track.add_memory(memory)
    }
    fn drop_memory(&mut self, memory: u64) -> std::result::Result<(), CostErrors> {
        self.cost_track.drop_memory(memory)
    }
    fn reset_memory(&mut self) {
        self.cost_track.reset_memory()
    }
    fn short_circuit_contract_call(
        &mut self,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        input: &[u64],
    ) -> std::result::Result<bool, CostErrors> {
        self.cost_track
            .short_circuit_contract_call(contract, function, input)
    }
}

impl<'a, 'b, 'hooks> ExecutionState<'a, 'b, 'hooks> {
    /// Used only for contract-call! cost short-circuiting. Once the short-circuited cost
    ///  has been evaluated and assessed, the contract-call! itself is executed "for free".
    pub fn run_free<F, A>(&mut self, invoke_ctx: &InvocationContext, to_run: F) -> A
    where
        F: FnOnce(&mut ExecutionState, &InvocationContext) -> A,
    {
        let original_tracker = replace(
            &mut *self.global_context.cost_track,
            CostTrackerHandle::free(),
        );
        // note: it is important that this method not return until original_tracker has been
        //  restored. DO NOT use the try syntax (?).
        let result = to_run(self, invoke_ctx);
        *self.global_context.cost_track = original_tracker;
        result
    }

    pub fn eval_read_only(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract_identifier: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, ClarityEvalError> {
        let parsed = self.parse_nonempty_program(invoke_ctx, contract_identifier, program)?;

        self.global_context.begin();

        let contract = self
            .global_context
            .database
            .get_contract(contract_identifier)
            .or_else(|e| {
                self.global_context.roll_back()?;
                Err(e)
            })?;

        let result = {
            let nested_view = InvocationContext {
                contract_context: &contract,
                sender: invoke_ctx.sender.clone(),
                caller: invoke_ctx.caller.clone(),
                sponsor: invoke_ctx.sponsor.clone(),
            };
            let local_context = LocalContext::new();
            eval(&parsed[0], self, &nested_view, &local_context)
                .and_then(|value| value.clone_with_cost(self))
        }
        .map_err(ClarityEvalError::from);

        self.global_context.roll_back()?;
        result
    }

    pub fn eval_raw(
        &mut self,
        invoke_ctx: &InvocationContext,
        program: &str,
    ) -> Result<Value, ClarityEvalError> {
        let parsed = self.parse_nonempty_program(
            invoke_ctx,
            &QualifiedContractIdentifier::transient(),
            program,
        )?;
        let local_context = LocalContext::new();
        eval(&parsed[0], self, invoke_ctx, &local_context)
            .and_then(|value| value.clone_with_cost(self))
            .map_err(ClarityEvalError::from)
    }

    /// Parse `program` into a **non-empty** list of `SymbolicExpression`s.
    ///
    /// This is a wrapper around `ast::build_ast(..)` that enforces the invariant
    /// that a parsed program must contain at least one top-level expression.
    ///
    /// # Errors
    /// - Returns `Err` if the program fails to parse/build an AST.
    /// - Returns `Err(UnexpectedParserFailure)` if parsing succeeds but yields *zero* expressions.
    ///
    /// # Notes
    /// The empty-expression case should be unreachable for normal VM execution because
    /// published/deployed contract code and transaction programs are validated earlier.
    /// It exists as a defensive check for malformed input in tests, fuzzing, or internal
    /// callers that bypass normal validation paths.
    fn parse_nonempty_program(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract_identifier: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Vec<SymbolicExpression>, ClarityEvalError> {
        let expressions = ast::build_ast(
            contract_identifier,
            program,
            self,
            invoke_ctx.contract_context.clarity_version,
            self.global_context.epoch_id,
        )?
        .expressions;

        if expressions.is_empty() {
            return Err(ParseError::from(ParseErrorKind::UnexpectedParserFailure).into());
        }

        Ok(expressions)
    }

    /// This is the epoch of the block that this transaction is executing within.
    /// Note: in the current plans for 2.1, there is also a contract-specific **Clarity version**
    ///  which governs which native functions are available / defined. That is separate from this
    ///  epoch identifier, and most Clarity VM changes should consult that value instead. This
    ///  epoch identifier is used for determining how cost functions should be applied.
    pub fn epoch(&self) -> &StacksEpochId {
        &self.global_context.epoch_id
    }

    pub fn has_contract_dispatcher(&self) -> bool {
        self.global_context.dispatcher.is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_contract_call(
        &mut self,
        sender: Option<PrincipalData>,
        caller: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
    ) -> Result<Value, VmExecutionError> {
        let dispatcher = self.global_context.dispatcher.take().ok_or_else(|| {
            VmInternalError::Expect("Contract dispatcher was not installed".into())
        })?;
        let mut runtime = RuntimeContext {
            db: &mut self.global_context.database,
            cost_tracker: &mut self.global_context.cost_track,
            transaction_frame: &mut self.global_context.transaction,
            call_stack: self.call_stack,
            execution_resource_limiter: self.global_context.execution_resource_limiter,
            epoch: self.global_context.epoch_id,
            mainnet: self.global_context.mainnet,
            chain_id: self.global_context.chain_id,
        };
        let result = (|| {
            let engine = dispatcher.select_engine(&mut runtime, contract)?;
            let mut ctx = runtime.take_transaction_context()?;
            let result = engine.execute_nested_call(
                &mut ctx, dispatcher, sender, caller, sponsor, contract, function, args,
            );
            runtime.restore_transaction_context(ctx)?;
            result
        })();
        self.global_context.dispatcher = Some(dispatcher);
        result.map_err(|e| match e {
            clarity_kernel::engine::EngineError::Execution(e) => e,
            other => {
                VmInternalError::Expect(format!("Nested engine dispatch failed: {other}")).into()
            }
        })
    }

    pub fn execute_contract(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract: &QualifiedContractIdentifier,
        tx_name: &str,
        args: &[SymbolicExpression],
        read_only: bool,
    ) -> Result<Value, VmExecutionError> {
        self.inner_execute_contract(invoke_ctx, contract, tx_name, args, read_only, false)
    }

    /// This method is exposed for callers that need to invoke a private method directly.
    /// For example, this is used by the Stacks chainstate for invoking private methods
    /// on the pox-2 contract. This should not be called by user transaction processing.
    pub fn execute_contract_allow_private(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract: &QualifiedContractIdentifier,
        tx_name: &str,
        args: &[SymbolicExpression],
        read_only: bool,
    ) -> Result<Value, VmExecutionError> {
        self.inner_execute_contract(invoke_ctx, contract, tx_name, args, read_only, true)
    }

    /// This method handles actual execution of contract-calls on a contract.
    ///
    /// `allow_private` should always be set to `false` for user transactions:
    ///  this ensures that only `define-public` and `define-read-only` methods can
    ///  be invoked. The `allow_private` mode should only be used by
    ///  `Environment::execute_contract_allow_private`.
    fn inner_execute_contract(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract_identifier: &QualifiedContractIdentifier,
        tx_name: &str,
        args: &[SymbolicExpression],
        read_only: bool,
        allow_private: bool,
    ) -> Result<Value, VmExecutionError> {
        let contract_size = self
            .global_context
            .database
            .get_contract_size(contract_identifier)?;
        runtime_cost(ClarityCostFunction::LoadContract, self, contract_size)?;

        self.global_context.add_memory(contract_size)?;

        // NOTE: When contract caching is used, then the memory counters here will drop the
        // `contract_size` after the contract execution has completed, but the contracts will remain
        // in the cache (up to the cache eviction policy's limits).
        finally_drop_memory!(self.global_context, contract_size; {
            let contract = self.global_context.database.get_contract(contract_identifier)?;

            let func = contract.lookup_function(tx_name)
                .ok_or_else(|| { RuntimeCheckErrorKind::UndefinedFunction(tx_name.to_string()) })?;
            if !allow_private && !func.is_public() {
                return Err(RuntimeCheckErrorKind::NoSuchPublicFunction(contract_identifier.to_string(), tx_name.to_string()).into());
            } else if read_only && !func.is_read_only() {
                return Err(RuntimeCheckErrorKind::Unreachable(format!("Public function not read-only: {contract_identifier} {tx_name}")).into());
            }

            let args: Result<Vec<Value>, VmExecutionError> = args.iter()
                .map(|arg| {
                    let value = arg.match_atom_value()
                        .ok_or_else(|| VmInternalError::InvariantViolation(format!("Passed non-value expression to exec_tx on {tx_name}!")))?;
                    // sanitize contract-call inputs in epochs >= 2.4
                    // testing todo: ensure sanitize_value() preserves trait callability!
                    let expected_type = TypeSignature::type_of(value)?;
                    let (sanitized_value, _) = Value::sanitize_value(
                        self.epoch(),
                        &expected_type,
                        value.clone(),
                    ).ok_or_else(|| RuntimeCheckErrorKind::TypeValueError(
                            Box::new(expected_type),
                            value.to_error_string(),
                        )
                    )?;

                    Ok(sanitized_value)
                })
                .collect();

            let args = args?;

            let func_identifier = func.get_identifier();
            if self.call_stack.contains(&func_identifier) {
                return Err(RuntimeCheckErrorKind::CircularReference(vec![func_identifier.to_string()]).into())
            }
            self.call_stack.insert(&func_identifier, true);
            let options = FunctionExecutionOptions::default()
                .with_next_contract(&*contract)
                .allow_private(allow_private);

            // This entry/contract-call route is not wrapped by `apply`, so it owns the
            // user-function call frame itself. (The `apply` path emits its own frame.)
            let callee_view = invoke_ctx.with_contract_context(&contract);
            let call = CallTraceFrame::when(self.has_eval_hooks(), || CallHook::UserDefined {
                contract_identifier: &callee_view.contract_context.contract_identifier,
                function: &func,
            });
            call.begin(self, &callee_view, CallArguments::Values(&args));
            call.did_evaluate_arguments(self, &callee_view, &args);

            let res = self.execute_function_as_transaction(invoke_ctx, &func, &args, options);

            call.finish(self, &callee_view, &res);
            self.call_stack.remove(&func_identifier, true)?;

            // Host special cases belong to the legacy boot-contract engines.
            // A Clarity 6 call reaches those engines through the dispatcher,
            // so this engine must not downcast their private handler token
            // after ordinary Clarity 6 calls.
            res
        })
    }

    /// Runs `function` against a transaction boundary: begin (read-only or
    /// writable), execute, then roll back or handle the result.
    ///
    /// Call-trace emission is **owned by callers** (e.g., `apply` and
    /// `inner_execute_contract`); this method intentionally emits no eval hooks,
    /// so a direct caller that wants tracing must open its own `CallTraceFrame`.
    pub fn execute_function_as_transaction(
        &mut self,
        invoke_ctx: &InvocationContext,
        function: &DefinedFunction,
        args: &[Value],
        options: FunctionExecutionOptions<'_>,
    ) -> Result<Value, VmExecutionError> {
        let make_read_only = function.is_read_only();

        if make_read_only {
            self.global_context.begin_read_only();
        } else {
            self.global_context.begin();
        }

        let next_contract_context = options
            .next_contract_context
            .unwrap_or(invoke_ctx.contract_context);

        let callee_view = invoke_ctx.with_contract_context(next_contract_context);

        let result = function.execute_apply(args, self, &callee_view);

        if make_read_only {
            self.global_context.roll_back()?;
            result
        } else {
            self.global_context
                .handle_tx_result(result, options.allow_private)
        }
    }

    pub fn evaluate_at_block<'e>(
        &mut self,
        bhh: StacksBlockId,
        closure: &'e SymbolicExpression,
        invoke_ctx: &'e InvocationContext,
        local: &'e LocalContext,
    ) -> Result<ValueRef<'e>, VmExecutionError> {
        self.global_context.begin_read_only();

        let result = self
            .global_context
            .database
            .set_block_hash(bhh, false)
            .and_then(|prior_bhh| {
                let result = eval(closure, self, invoke_ctx, local);
                self.global_context
                    .database
                    .set_block_hash(prior_bhh, true)
                    .map_err(|_| {
                        VmInternalError::Expect(
                        "ERROR: Failed to restore prior active block after time-shifted evaluation."
                            .into())
                    })?;
                result
            });

        self.global_context.roll_back()?;

        result
    }

    pub fn initialize_contract(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract_identifier: QualifiedContractIdentifier,
        contract_content: &str,
    ) -> Result<(), ClarityEvalError> {
        let clarity_version = invoke_ctx.contract_context.clarity_version;

        let contract_ast = ast::build_ast(
            &contract_identifier,
            contract_content,
            self,
            clarity_version,
            self.global_context.epoch_id,
        )?;
        self.initialize_contract_from_ast(
            invoke_ctx,
            contract_identifier,
            clarity_version,
            &contract_ast,
            contract_content,
        )
        .map_err(ClarityEvalError::from)
    }

    pub fn initialize_contract_from_ast(
        &mut self,
        invoke_ctx: &InvocationContext,
        contract_identifier: QualifiedContractIdentifier,
        contract_version: ClarityVersion,
        contract_content: &ContractAST,
        contract_string: &str,
    ) -> Result<(), VmExecutionError> {
        self.global_context.begin();

        // wrap in a closure so that `?` can be caught and the global_context can roll_back()
        //  before returning.
        let result = (|| {
            runtime_cost(
                ClarityCostFunction::ContractStorage,
                self,
                contract_string.len(),
            )?;

            if self
                .global_context
                .database
                .has_contract(&contract_identifier)
            {
                return Err(RuntimeCheckErrorKind::Unreachable(format!(
                    "Contract already exists: {contract_identifier}"
                ))
                .into());
            }

            // first, store the contract _content hash_ in the data store.
            //    this is necessary before creating and accessing metadata fields in the data store,
            //      --or-- storing any analysis metadata in the data store.
            self.global_context
                .database
                .insert_contract_hash(&contract_identifier, contract_string)?;
            let memory_use = contract_string.len() as u64;
            self.add_memory(memory_use)?;

            let result = Contract::initialize_from_ast(
                contract_identifier.clone(),
                contract_content,
                invoke_ctx.sponsor.clone(),
                self.global_context,
                contract_version,
            );
            self.drop_memory(memory_use)?;
            result
        })();

        match result {
            Ok(contract) => {
                let data_size = contract.data_size;
                self.global_context
                    .database
                    .insert_contract(&contract_identifier, contract)?;
                self.global_context
                    .database
                    .set_contract_data_size(&contract_identifier, data_size)?;

                self.global_context.commit()?;
                Ok(())
            }
            Err(e) => {
                self.global_context.roll_back()?;
                Err(e)
            }
        }
    }

    /// Top-level STX-transfer, invoked by TokenTransfer transactions.
    /// Only commits if the inner stx_transfer_consolidated() returns an (ok true) value.
    /// Rolls back if it returns an (err ..) value, or if the method itself fails for some reason
    /// (miners should never build blocks that spend non-existent STX in a top-level token-transfer)
    pub fn stx_transfer(
        &mut self,
        invoke_ctx: &InvocationContext,
        from: &PrincipalData,
        to: &PrincipalData,
        amount: u128,
        memo: &BuffData,
    ) -> Result<Value, VmExecutionError> {
        self.global_context.begin();
        let result = stx_transfer_consolidated(self, invoke_ctx, from, to, amount, memo);
        match result {
            Ok(value) => match value
                .clone()
                .expect_result()
                .map_err(|_| VmInternalError::Expect("Expected result".into()))?
            {
                Ok(_) => {
                    self.global_context.commit()?;
                    Ok(value)
                }
                Err(_) => {
                    self.global_context.roll_back()?;
                    Err(VmInternalError::InsufficientBalance.into())
                }
            },
            Err(e) => {
                self.global_context.roll_back()?;
                Err(e)
            }
        }
    }

    pub fn run_as_transaction<F, O, E>(
        &mut self,
        invoke_ctx: &InvocationContext,
        f: F,
    ) -> std::result::Result<O, E>
    where
        F: FnOnce(&mut Self, &InvocationContext) -> std::result::Result<O, E>,
        E: From<VmExecutionError>,
    {
        self.global_context.begin();
        let result = f(self, invoke_ctx);
        match result {
            Ok(ret) => {
                self.global_context.commit()?;
                Ok(ret)
            }
            Err(e) => {
                self.global_context.roll_back()?;
                Err(e)
            }
        }
    }

    fn push_to_event_batch(
        &mut self,
        event: StacksTransactionEvent,
    ) -> Result<(), VmExecutionError> {
        let size = if let StacksTransactionEvent::SmartContractEvent(ref ev) = event {
            ev.value.size().map_err(|e| {
                VmInternalError::Expect(format!("Could not calculate event size: {e}"))
            })?
        } else {
            0
        };
        self.global_context
            .transaction
            .push_event(event, size.into())
    }

    pub fn construct_print_transaction_event(
        contract_id: QualifiedContractIdentifier,
        value: Value,
    ) -> StacksTransactionEvent {
        let print_event = SmartContractEventData {
            key: (contract_id, "print".to_string()),
            value,
        };

        StacksTransactionEvent::SmartContractEvent(print_event)
    }

    pub fn register_print_event(
        &mut self,
        invoke_ctx: &InvocationContext,
        value: Value,
    ) -> Result<(), VmExecutionError> {
        let event = Self::construct_print_transaction_event(
            invoke_ctx.contract_context.contract_identifier.clone(),
            value,
        );

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_stx_transfer_event(
        &mut self,
        sender: PrincipalData,
        recipient: PrincipalData,
        amount: u128,
        memo: BuffData,
    ) -> Result<(), VmExecutionError> {
        let event_data = STXTransferEventData {
            sender,
            recipient,
            amount,
            memo,
        };
        let event = StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_stx_burn_event(
        &mut self,
        sender: PrincipalData,
        amount: u128,
    ) -> Result<(), VmExecutionError> {
        let event_data = STXBurnEventData { sender, amount };
        let event = StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_nft_transfer_event(
        &mut self,
        sender: PrincipalData,
        recipient: PrincipalData,
        value: Value,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), VmExecutionError> {
        let event_data = NFTTransferEventData {
            sender,
            recipient,
            asset_identifier,
            value,
        };
        let event = StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_nft_mint_event(
        &mut self,
        recipient: PrincipalData,
        value: Value,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), VmExecutionError> {
        let event_data = NFTMintEventData {
            recipient,
            asset_identifier,
            value,
        };
        let event = StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_nft_burn_event(
        &mut self,
        sender: PrincipalData,
        value: Value,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), VmExecutionError> {
        let event_data = NFTBurnEventData {
            sender,
            asset_identifier,
            value,
        };
        let event = StacksTransactionEvent::NFTEvent(NFTEventType::NFTBurnEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_ft_transfer_event(
        &mut self,
        sender: PrincipalData,
        recipient: PrincipalData,
        amount: u128,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), VmExecutionError> {
        let event_data = FTTransferEventData {
            sender,
            recipient,
            asset_identifier,
            amount,
        };
        let event = StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_ft_mint_event(
        &mut self,
        recipient: PrincipalData,
        amount: u128,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), VmExecutionError> {
        let event_data = FTMintEventData {
            recipient,
            asset_identifier,
            amount,
        };
        let event = StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }

    pub fn register_ft_burn_event(
        &mut self,
        sender: PrincipalData,
        amount: u128,
        asset_identifier: AssetIdentifier,
    ) -> Result<(), VmExecutionError> {
        let event_data = FTBurnEventData {
            sender,
            asset_identifier,
            amount,
        };
        let event = StacksTransactionEvent::FTEvent(FTEventType::FTBurnEvent(event_data));

        self.push_to_event_batch(event)?;
        Ok(())
    }
}

impl ExecutionState<'_, '_, '_> {
    /// Invokes `f` for each registered eval hook.
    fn for_each_eval_hook(&mut self, mut f: impl FnMut(&mut dyn EvalHook, &mut Self)) {
        let Some(mut eval_hooks) = self.global_context.eval_hooks.take() else {
            return;
        };

        for hook in eval_hooks.iter_mut() {
            f(&mut **hook, self);
        }
        self.global_context.eval_hooks = Some(eval_hooks);
    }
}

impl EvalHookNotifier for ExecutionState<'_, '_, '_> {
    fn has_eval_hooks(&self) -> bool {
        self.global_context
            .eval_hooks
            .as_ref()
            .is_some_and(|hooks| !hooks.is_empty())
    }

    fn notify_will_begin_eval(
        &mut self,
        invoke_ctx: &InvocationContext,
        context: &LocalContext,
        expr: &SymbolicExpression,
    ) {
        self.for_each_eval_hook(|hook, env| hook.will_begin_eval(env, invoke_ctx, context, expr));
    }

    fn notify_did_finish_eval<'a>(
        &mut self,
        invoke_ctx: &'a InvocationContext,
        context: &'a LocalContext,
        expr: &SymbolicExpression,
        res: &core::result::Result<ValueRef<'a>, VmExecutionError>,
    ) {
        self.for_each_eval_hook(|hook, env| {
            hook.did_finish_eval(env, invoke_ctx, context, expr, res)
        });
    }

    fn notify_will_begin_call(
        &mut self,
        invoke_ctx: &InvocationContext,
        call: &CallHook,
        args: CallArguments,
    ) {
        self.for_each_eval_hook(|hook, env| hook.will_begin_call(env, invoke_ctx, call, args));
    }

    fn notify_did_evaluate_call_argument(
        &mut self,
        invoke_ctx: &InvocationContext,
        call: &CallHook,
        arg_index: usize,
        value: &Value,
    ) {
        self.for_each_eval_hook(|hook, env| {
            hook.did_evaluate_call_argument(env, invoke_ctx, call, arg_index, value)
        });
    }

    fn notify_did_finish_call(
        &mut self,
        invoke_ctx: &InvocationContext,
        call: &CallHook,
        res: &core::result::Result<Value, VmExecutionError>,
    ) {
        self.for_each_eval_hook(|hook, env| hook.did_finish_call(env, invoke_ctx, call, res));
    }
}

impl<'a, 'hooks> GlobalContext<'a, 'hooks> {
    // Instantiate a new Global Context
    pub fn new(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        cost_track: LimitedCostTracker,
        epoch_id: StacksEpochId,
    ) -> GlobalContext<'a, 'hooks> {
        Self::new_with_cost_tracker_handle(
            mainnet,
            chain_id,
            database,
            CostTrackerHandle::new(cost_track),
            epoch_id,
        )
    }

    pub fn new_with_cost_tracker_handle(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        cost_track: CostTrackerHandle,
        epoch_id: StacksEpochId,
    ) -> GlobalContext<'a, 'hooks> {
        Self::new_with_transaction_frame(
            mainnet,
            chain_id,
            database,
            cost_track,
            TransactionFrame::new(),
            epoch_id,
        )
    }

    pub fn new_with_transaction_frame(
        mainnet: bool,
        chain_id: u32,
        database: ClarityDatabase<'a>,
        cost_track: CostTrackerHandle,
        transaction: TransactionFrame,
        epoch_id: StacksEpochId,
    ) -> GlobalContext<'a, 'hooks> {
        GlobalContext {
            database: RuntimeSlot::new(database),
            cost_track: RuntimeSlot::new(cost_track),
            transaction: RuntimeSlot::new(transaction),
            mainnet,
            epoch_id,
            chain_id,
            eval_hooks: None,
            dispatcher: None,
            execution_resource_limiter: ResourceLimiter::unlimited(),
        }
    }

    pub fn is_top_level(&self) -> bool {
        self.transaction.is_top_level()
    }

    pub fn set_execution_resource_limiter(&mut self, resource_limiter: ResourceLimiter) {
        self.execution_resource_limiter = resource_limiter;
    }

    fn get_asset_map(&mut self) -> Result<&mut AssetMap, VmExecutionError> {
        self.transaction.current_asset_map()
    }

    pub fn get_readonly_asset_map(&mut self) -> Result<&AssetMap, VmExecutionError> {
        self.transaction.current_asset_map_readonly()
    }

    pub fn log_asset_transfer(
        &mut self,
        sender: &PrincipalData,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &ClarityName,
        transferred: Value,
    ) -> Result<(), VmExecutionError> {
        let asset_identifier = AssetIdentifier {
            contract_identifier: contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        self.get_asset_map()?
            .add_asset_transfer(sender, asset_identifier, transferred);
        Ok(())
    }

    pub fn log_token_transfer(
        &mut self,
        sender: &PrincipalData,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &ClarityName,
        transferred: u128,
    ) -> Result<(), VmExecutionError> {
        let asset_identifier = AssetIdentifier {
            contract_identifier: contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        self.get_asset_map()?
            .add_token_transfer(sender, asset_identifier, transferred)
    }

    pub fn log_stx_transfer(
        &mut self,
        sender: &PrincipalData,
        transferred: u128,
    ) -> Result<(), VmExecutionError> {
        self.get_asset_map()?.add_stx_transfer(sender, transferred)
    }

    pub fn log_stx_burn(
        &mut self,
        sender: &PrincipalData,
        transferred: u128,
    ) -> Result<(), VmExecutionError> {
        self.get_asset_map()?.add_stx_burn(sender, transferred)
    }

    pub fn log_stacking(
        &mut self,
        sender: &PrincipalData,
        amount: u128,
    ) -> Result<(), VmExecutionError> {
        let epoch = self.epoch_id;
        self.get_asset_map()?.add_stacking(sender, amount, epoch)
    }

    pub fn log_pox_action(&mut self, sender: &PrincipalData) -> Result<(), VmExecutionError> {
        self.get_asset_map()?.add_pox_action(sender);
        Ok(())
    }

    /// Invokes `f` for each registered eval hook.
    fn for_each_eval_hook(&mut self, mut f: impl FnMut(&mut dyn EvalHook)) {
        let Some(mut eval_hooks) = self.eval_hooks.take() else {
            return;
        };

        for hook in eval_hooks.iter_mut() {
            f(&mut **hook);
        }
        self.eval_hooks = Some(eval_hooks);
    }

    fn notify_will_begin_execution(&mut self) {
        self.for_each_eval_hook(|hook| hook.will_begin_execution());
    }

    fn notify_did_finish_execution(&mut self, outcome: ExecutionOutcome) {
        self.for_each_eval_hook(|hook| hook.did_finish_execution(outcome));
    }

    pub fn execute<F, T>(&mut self, f: F) -> Result<T, VmExecutionError>
    where
        F: FnOnce(&mut Self) -> Result<T, VmExecutionError>,
    {
        self.begin();
        let result = f(self).or_else(|e| {
            self.roll_back()?;
            Err(e)
        })?;
        self.commit()?;
        Ok(result)
    }

    /// Run a snippet of Clarity code in the given contract context
    /// Only use within special-case contract-call handlers.
    /// DO NOT CALL FROM ANYWHERE ELSE!
    pub fn special_cc_handler_execute_read_only<F, A, E>(
        &mut self,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract_context: &ContractContext,
        f: F,
    ) -> std::result::Result<A, E>
    where
        E: From<ClarityEvalError>,
        F: FnOnce(&mut ExecutionState, &InvocationContext) -> std::result::Result<A, E>,
    {
        self.begin();

        let result = {
            // this right here is why it's dangerous to call this anywhere else.
            // the call stack gets reset to empyt each time!
            let mut callstack = CallStack::new();
            let mut exec_state = ExecutionState {
                global_context: self,
                call_stack: &mut callstack,
            };
            let invoke_ctx = InvocationContext {
                contract_context,
                sender: Some(sender.clone()),
                caller: Some(sender),
                sponsor,
            };
            f(&mut exec_state, &invoke_ctx)
        };
        self.roll_back().map_err(ClarityEvalError::from)?;

        match result {
            Ok(return_value) => Ok(return_value),
            Err(e) => Err(e),
        }
    }

    pub fn is_read_only(&self) -> bool {
        self.transaction.is_read_only()
    }

    pub fn begin(&mut self) {
        self.transaction.begin();
        self.database.begin();
    }

    pub fn begin_read_only(&mut self) {
        self.transaction.begin_read_only();
        self.database.begin();
    }

    pub fn commit(&mut self) -> Result<(Option<AssetMap>, Option<EventBatch>), VmExecutionError> {
        trace!("Calling commit");
        let result = match self.transaction.commit(self.epoch_id) {
            Ok(result) => result,
            Err(e) => {
                self.database.roll_back()?;
                return Err(e);
            }
        };

        self.database.commit()?;
        Ok(result)
    }

    pub fn roll_back(&mut self) -> Result<(), VmExecutionError> {
        self.transaction.roll_back()?;
        self.database.roll_back()
    }

    // the allow_private parameter allows private functions calls to return any Clarity type
    // and not just Response. It only has effect is the devtools feature is enabled. eg:
    // clarity = { version = "*", features = ["devtools"] }
    pub fn handle_tx_result(
        &mut self,
        result: Result<Value, VmExecutionError>,
        allow_private: bool,
    ) -> Result<Value, VmExecutionError> {
        if let Ok(result) = result {
            if let Value::Response(data) = result {
                if data.committed {
                    self.commit()?;
                } else {
                    self.roll_back()?;
                }
                Ok(Value::Response(data))
            } else if allow_private && cfg!(feature = "devtools") {
                self.commit()?;
                Ok(result)
            } else {
                Err(RuntimeCheckErrorKind::Unreachable(format!(
                    "Public function must return response: {}",
                    TypeSignature::type_of(&result)?
                ))
                .into())
            }
        } else {
            self.roll_back()?;
            result
        }
    }

    /// Destroys this context, returning ownership of its database reference.
    ///  If the context wasn't top-level (i.e., it had uncommitted data), return None,
    ///   because the database is not guaranteed to be in a sane state.
    pub fn destruct(self) -> Option<(ClarityDatabase<'a>, CostTrackerHandle, TransactionFrame)> {
        if self.is_top_level() {
            self.into_runtime_parts()
        } else {
            None
        }
    }

    fn into_runtime_parts(
        self,
    ) -> Option<(ClarityDatabase<'a>, CostTrackerHandle, TransactionFrame)> {
        Some((
            self.database.into_inner()?,
            self.cost_track.into_inner()?,
            self.transaction.into_inner()?,
        ))
    }
}

impl ContractContext {
    pub fn new(
        contract_identifier: QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
    ) -> Self {
        Self {
            contract_identifier,
            variables: HashMap::new(),
            functions: HashMap::new(),
            defined_traits: HashMap::new(),
            implemented_traits: HashSet::new(),
            persisted_names: HashSet::new(),
            data_size: 0,
            meta_data_map: HashMap::new(),
            meta_data_var: HashMap::new(),
            meta_nft: HashMap::new(),
            meta_ft: HashMap::new(),
            clarity_version,
            is_deploying: false,
        }
    }

    /// Lookup a contract constant by name
    pub fn lookup_variable(&self, name: &str) -> Option<&Value> {
        self.variables.get(name)
    }

    pub fn lookup_function(&self, name: &str) -> Option<DefinedFunction> {
        self.functions.get(name).cloned()
    }

    pub fn lookup_trait_definition(
        &self,
        name: &str,
    ) -> Option<BTreeMap<ClarityName, FunctionSignature>> {
        self.defined_traits.get(name).cloned()
    }

    pub fn is_explicitly_implementing_trait(&self, trait_identifier: &TraitIdentifier) -> bool {
        self.implemented_traits.contains(trait_identifier)
    }

    pub fn is_name_used(&self, name: &str) -> bool {
        is_reserved(name, self.get_clarity_version())
            || self.variables.contains_key(name)
            || self.functions.contains_key(name)
            || self.persisted_names.contains(name)
            || self.defined_traits.contains_key(name)
    }

    pub fn get_clarity_version(&self) -> &ClarityVersion {
        &self.clarity_version
    }

    /// Canonicalize the types for the specified epoch. Only functions and
    /// defined traits are exposed externally, so other types are not
    /// canonicalized.
    pub fn canonicalize_types(&mut self, epoch: &StacksEpochId) -> Result<(), VmExecutionError> {
        for (_, function) in self.functions.iter_mut() {
            function.canonicalize_types(epoch);
        }

        for trait_def in self.defined_traits.values_mut() {
            for (_, function) in trait_def.iter_mut() {
                *function = function.canonicalize(epoch);
            }
        }

        for (_, value) in self.variables.iter_mut() {
            let owned = std::mem::replace(value, Value::none());
            let (sanitized, _) =
                Value::sanitize_value(epoch, &TypeSignature::type_of(&owned)?, owned)
                    .ok_or_else(|| RuntimeCheckErrorKind::CouldNotDetermineType)?;
            *value = sanitized;
        }

        Ok(())
    }
}

impl Default for LocalContext<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> LocalContext<'a> {
    pub fn new() -> LocalContext<'a> {
        LocalContext {
            function_context: Option::None,
            parent: Option::None,
            callable_contracts: HashMap::new(),
            variables: HashMap::new(),
            depth: 0,
        }
    }

    pub fn depth(&self) -> u64 {
        self.depth
    }

    pub fn function_context(&self) -> &LocalContext<'_> {
        match self.function_context {
            Some(context) => context,
            None => self,
        }
    }

    pub fn extend(&'a self) -> Result<LocalContext<'a>, VmExecutionError> {
        if self.depth >= MAX_CONTEXT_DEPTH {
            // `MaxContextDepthReached` in this function is **unreachable** in normal Clarity execution because:
            // - Every function call in Clarity increments both the call stack depth and the local context depth.
            // - The VM enforces the epoch-specific `MAX_CALL_STACK_DEPTH` **before** `MAX_CONTEXT_DEPTH` (256).
            // - This means no contract can create more nested function calls than the epoch limit, preventing context depth from reaching 256.
            // - Nested expressions (`let`, `begin`, `if`, etc.) increment context depth, but the Clarity parser enforces
            //   `ExpressionStackDepthTooDeep` long before MAX_CONTEXT_DEPTH nested contexts can be written.
            // - As a result, `MaxContextDepthReached` can only occur in artificial Rust-level tests calling `LocalContext::extend()`,
            //   not in deployed contract execution.
            Err(RuntimeError::MaxContextDepthReached.into())
        } else {
            Ok(LocalContext {
                function_context: Some(self.function_context()),
                parent: Some(self),
                callable_contracts: HashMap::new(),
                variables: HashMap::new(),
                depth: self.depth + 1,
            })
        }
    }

    pub fn lookup_variable(&self, name: &str) -> Option<&Value> {
        match self.variables.get(name) {
            Some(value) => Some(value),
            None => match self.parent {
                Some(parent) => parent.lookup_variable(name),
                None => None,
            },
        }
    }

    pub fn lookup_callable_contract(&self, name: &str) -> Option<&CallableData> {
        match self.callable_contracts.get(name) {
            Some(found) => Some(found),
            None => match self.parent {
                Some(parent) => parent.lookup_callable_contract(name),
                None => None,
            },
        }
    }
}

#[cfg(all(test, any()))]
mod test {
    use clarity_types::ContractName;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::chainstate::StacksAddress;
    use stacks_common::util::hash::Hash160;

    use super::*;
    use crate::vm::callables::DefineType;
    use crate::vm::database::MemoryBackingStore;
    use crate::vm::tests::{
        TopLevelMemoryEnvironmentGenerator, test_clarity_versions, test_epochs, tl_env_factory,
    };
    use crate::vm::types::StandardPrincipalData;
    use crate::vm::types::signatures::CallableSubtype;

    #[test]
    fn test_asset_map_abort() {
        let a_contract_id = QualifiedContractIdentifier::local("a").unwrap();
        let b_contract_id = QualifiedContractIdentifier::local("b").unwrap();

        let p1 = PrincipalData::Contract(a_contract_id.clone());
        let p2 = PrincipalData::Contract(b_contract_id.clone());

        let t1 = AssetIdentifier {
            contract_identifier: a_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };
        let _t2 = AssetIdentifier {
            contract_identifier: b_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };

        let mut am1 = AssetMap::new();
        let mut am2 = AssetMap::new();

        am1.add_token_transfer(&p1, t1.clone(), 1).unwrap();
        am1.add_token_transfer(&p2, t1.clone(), u128::MAX).unwrap();
        am2.add_token_transfer(&p1, t1.clone(), 1).unwrap();
        am2.add_token_transfer(&p2, t1.clone(), 1).unwrap();

        am1.commit_other(am2, StacksEpochId::Epoch30).unwrap_err();

        let table = am1.to_table();

        assert_eq!(table[&p2][&t1], AssetMapEntry::Token(u128::MAX));
        assert_eq!(table[&p1][&t1], AssetMapEntry::Token(1));
    }

    #[test]
    fn test_asset_map_combinations() {
        let a_contract_id = QualifiedContractIdentifier::local("a").unwrap();
        let b_contract_id = QualifiedContractIdentifier::local("b").unwrap();
        let c_contract_id = QualifiedContractIdentifier::local("c").unwrap();
        let d_contract_id = QualifiedContractIdentifier::local("d").unwrap();
        let e_contract_id = QualifiedContractIdentifier::local("e").unwrap();
        let f_contract_id = QualifiedContractIdentifier::local("f").unwrap();
        let g_contract_id = QualifiedContractIdentifier::local("g").unwrap();

        let p1 = PrincipalData::Contract(a_contract_id.clone());
        let p2 = PrincipalData::Contract(b_contract_id.clone());
        let p3 = PrincipalData::Contract(c_contract_id.clone());
        let _p4 = PrincipalData::Contract(d_contract_id.clone());
        let _p5 = PrincipalData::Contract(e_contract_id.clone());
        let _p6 = PrincipalData::Contract(f_contract_id);
        let _p7 = PrincipalData::Contract(g_contract_id);

        let t1 = AssetIdentifier {
            contract_identifier: a_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };
        let t2 = AssetIdentifier {
            contract_identifier: b_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };
        let t3 = AssetIdentifier {
            contract_identifier: c_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };
        let t4 = AssetIdentifier {
            contract_identifier: d_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };
        let t5 = AssetIdentifier {
            contract_identifier: e_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };
        let t6 = AssetIdentifier::STX();
        let t7 = AssetIdentifier::STX_burned();

        let mut am1 = AssetMap::new();
        let mut am2 = AssetMap::new();

        am1.add_token_transfer(&p1, t1.clone(), 10).unwrap();
        am2.add_token_transfer(&p1, t1.clone(), 15).unwrap();

        am1.add_stx_transfer(&p1, 20).unwrap();
        am2.add_stx_transfer(&p2, 25).unwrap();

        am1.add_stx_burn(&p1, 30).unwrap();
        am2.add_stx_burn(&p2, 35).unwrap();

        // test merging in a token that _didn't_ have an entry in the parent
        am2.add_token_transfer(&p1, t4.clone(), 1).unwrap();

        // test merging in a principal that _didn't_ have an entry in the parent
        am2.add_token_transfer(&p2, t2.clone(), 10).unwrap();
        am2.add_token_transfer(&p2, t2.clone(), 1).unwrap();

        // test merging in a principal that _didn't_ have an entry in the parent
        am2.add_asset_transfer(&p3, t3.clone(), Value::Int(10));

        // test merging in an asset that _didn't_ have an entry in the parent
        am1.add_asset_transfer(&p1, t5.clone(), Value::Int(0));
        am2.add_asset_transfer(&p1, t3.clone(), Value::Int(1));
        am2.add_asset_transfer(&p1, t3.clone(), Value::Int(0));

        // test merging in an asset that _does_ have an entry in the parent
        am1.add_asset_transfer(&p2, t3.clone(), Value::Int(2));
        am1.add_asset_transfer(&p2, t3.clone(), Value::Int(5));
        am2.add_asset_transfer(&p2, t3.clone(), Value::Int(3));
        am2.add_asset_transfer(&p2, t3.clone(), Value::Int(4));

        // test merging in STX transfers
        am1.add_stx_transfer(&p1, 21).unwrap();
        am2.add_stx_transfer(&p2, 26).unwrap();

        // test merging in STX burns
        am1.add_stx_burn(&p1, 31).unwrap();
        am2.add_stx_burn(&p2, 36).unwrap();

        am1.commit_other(am2, StacksEpochId::Epoch30).unwrap();

        let table = am1.to_table();

        // 3 Principals
        assert_eq!(table.len(), 3);

        assert_eq!(table[&p1][&t1], AssetMapEntry::Token(25));
        assert_eq!(table[&p1][&t4], AssetMapEntry::Token(1));

        assert_eq!(table[&p2][&t2], AssetMapEntry::Token(11));

        assert_eq!(
            table[&p2][&t3],
            AssetMapEntry::Asset(vec![
                Value::Int(2),
                Value::Int(5),
                Value::Int(3),
                Value::Int(4)
            ])
        );

        assert_eq!(
            table[&p1][&t3],
            AssetMapEntry::Asset(vec![Value::Int(1), Value::Int(0)])
        );
        assert_eq!(table[&p1][&t5], AssetMapEntry::Asset(vec![Value::Int(0)]));

        assert_eq!(table[&p3][&t3], AssetMapEntry::Asset(vec![Value::Int(10)]));

        assert_eq!(table[&p1][&t6], AssetMapEntry::STX(20 + 21));
        assert_eq!(table[&p2][&t6], AssetMapEntry::STX(25 + 26));

        assert_eq!(table[&p1][&t7], AssetMapEntry::Burn(30 + 31));
        assert_eq!(table[&p2][&t7], AssetMapEntry::Burn(35 + 36));
    }

    /// Merging a child frame whose stacking entry collides with the parent's
    /// is rejected (`PoxStxAssetMapOverwrite`) before Epoch 4.0, but summed in
    /// Epoch 4.0+ (PoX-5). A non-colliding entry merges identically in both.
    #[test]
    fn test_asset_map_stacking_merge() {
        let p1 = PrincipalData::from(StandardPrincipalData::transient());
        let p2 = PrincipalData::Contract(QualifiedContractIdentifier::local("b").unwrap());

        // Pre-Epoch-4.0: a colliding stacking entry is rejected.
        let mut am1 = AssetMap::new();
        let mut am2 = AssetMap::new();
        am1.add_stacking(&p1, 100, StacksEpochId::Epoch40).unwrap();
        am2.add_stacking(&p1, 50, StacksEpochId::Epoch40).unwrap();
        assert!(matches!(
            am1.commit_other(am2, StacksEpochId::Epoch30).unwrap_err(),
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::PoxStxAssetMapOverwrite)
        ));
        // `self` is left unchanged by the aborted merge.
        assert_eq!(am1.get_stacking(&p1), Some(100));

        // Epoch 4.0+: the colliding entry is summed; non-colliding entries pass
        // through unchanged.
        let mut am1 = AssetMap::new();
        let mut am2 = AssetMap::new();
        am1.add_stacking(&p1, 100, StacksEpochId::Epoch40).unwrap();
        am2.add_stacking(&p1, 50, StacksEpochId::Epoch40).unwrap();
        am2.add_stacking(&p2, 25, StacksEpochId::Epoch40).unwrap();
        am1.commit_other(am2, StacksEpochId::Epoch40).unwrap();
        assert_eq!(am1.get_stacking(&p1), Some(150));
        assert_eq!(am1.get_stacking(&p2), Some(25));

        // Epoch 4.0+: a summed stacking amount that overflows `u128` aborts the
        // merge with an arithmetic error rather than panicking, and leaves
        // `self` unchanged.
        let mut am1 = AssetMap::new();
        let mut am2 = AssetMap::new();
        am1.add_stacking(&p1, u128::MAX, StacksEpochId::Epoch40)
            .unwrap();
        am2.add_stacking(&p1, 1, StacksEpochId::Epoch40).unwrap();
        assert!(matches!(
            am1.commit_other(am2, StacksEpochId::Epoch40).unwrap_err(),
            VmExecutionError::Runtime(RuntimeError::ArithmeticOverflow, _)
        ));
        assert_eq!(am1.get_stacking(&p1), Some(u128::MAX));
    }

    /// Test the stx-transfer consolidation tx invalidation
    ///  bug from 2.4.0.1.0-rc1
    #[apply(test_epochs)]
    fn stx_transfer_consolidate_regr_24010(
        epoch: StacksEpochId,
        mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
    ) {
        let mut exec_state = tl_env_factory.get_env(epoch);
        let u1 = StacksAddress::new(0, Hash160([1; 20])).unwrap();
        let u2 = StacksAddress::new(0, Hash160([2; 20])).unwrap();
        // insufficient balance must be a non-includable transaction. it must error here,
        //  not simply rollback the tx and squelch the error as includable.
        let e = exec_state
            .stx_transfer(
                &PrincipalData::from(u1),
                &PrincipalData::from(u2),
                1000,
                &BuffData::empty(),
            )
            .unwrap_err();
        assert_eq!(e.to_string(), "Internal(InsufficientBalance)");
    }

    #[test]
    fn test_canonicalize_contract_context() {
        let trait_id = TraitIdentifier::new(
            StandardPrincipalData::transient(),
            ContractName::from_literal("my-contract"),
            ClarityName::from_literal("my-trait"),
        );
        let mut contract_context = ContractContext::new(
            QualifiedContractIdentifier::local("foo").unwrap(),
            ClarityVersion::Clarity1,
        );
        contract_context.functions.insert(
            ClarityName::from_literal("foo"),
            DefinedFunction::new(
                vec![(
                    ClarityName::from_literal("a"),
                    TypeSignature::TraitReferenceType(trait_id.clone()),
                )],
                SymbolicExpression::atom_value(Value::Int(3)),
                DefineType::Public,
                &ClarityName::from_literal("foo"),
                "testing",
            ),
        );

        let mut trait_functions = BTreeMap::new();
        trait_functions.insert(
            ClarityName::from_literal("alpha"),
            FunctionSignature {
                args: vec![TypeSignature::TraitReferenceType(trait_id.clone())],
                returns: TypeSignature::ResponseType(Box::new((
                    TypeSignature::UIntType,
                    TypeSignature::UIntType,
                ))),
            },
        );
        contract_context
            .defined_traits
            .insert(ClarityName::from_literal("bar"), trait_functions);

        contract_context
            .canonicalize_types(&StacksEpochId::Epoch21)
            .unwrap();

        assert_eq!(
            contract_context.functions["foo"].get_arg_types()[0],
            TypeSignature::CallableType(CallableSubtype::Trait(trait_id.clone()))
        );
        assert_eq!(
            contract_context
                .defined_traits
                .get("bar")
                .unwrap()
                .get("alpha")
                .unwrap()
                .args[0],
            TypeSignature::CallableType(CallableSubtype::Trait(trait_id))
        );
    }

    #[test]
    fn asset_map_arithmetic_overflows() {
        let a_contract_id = QualifiedContractIdentifier::local("a").unwrap();
        let b_contract_id = QualifiedContractIdentifier::local("b").unwrap();
        let p1 = PrincipalData::Contract(a_contract_id.clone());
        let p2 = PrincipalData::Contract(b_contract_id.clone());
        let t1 = AssetIdentifier {
            contract_identifier: a_contract_id,
            asset_name: ClarityName::from_literal("a"),
        };

        let mut am1 = AssetMap::new();
        let mut am2 = AssetMap::new();

        // Token transfer: add u128::MAX followed by 1 to overflow
        am1.add_token_transfer(&p1, t1.clone(), u128::MAX).unwrap();
        assert!(matches!(
            am1.add_token_transfer(&p1, t1.clone(), 1).unwrap_err(),
            VmExecutionError::Runtime(RuntimeError::ArithmeticOverflow, _)
        ));

        // STX burn: add u128::MAX followed by 1 to overflow
        am1.add_stx_burn(&p1, u128::MAX).unwrap();
        assert!(matches!(
            am1.add_stx_burn(&p1, 1).unwrap_err(),
            VmExecutionError::Runtime(RuntimeError::ArithmeticOverflow, _)
        ));

        // STX transfer: add u128::MAX followed by 1 to overflow
        am1.add_stx_transfer(&p1, u128::MAX).unwrap();
        assert!(matches!(
            am1.add_stx_transfer(&p1, 1).unwrap_err(),
            VmExecutionError::Runtime(RuntimeError::ArithmeticOverflow, _)
        ));

        // commit_other: merge two maps where sum exceeds u128::MAX
        am2.add_token_transfer(&p1, t1.clone(), u128::MAX).unwrap();
        assert!(matches!(
            am1.commit_other(am2, StacksEpochId::Epoch30).unwrap_err(),
            VmExecutionError::Runtime(RuntimeError::ArithmeticOverflow, _)
        ));
    }

    #[test]
    fn eval_raw_empty_program() {
        // Setup environment
        let mut tl_env_factory = tl_env_factory();
        let mut exec_state = tl_env_factory.get_env(StacksEpochId::latest());

        // Call eval_read_only with an empty program
        let program = ""; // empty program triggers parsed.is_empty()
        let err = exec_state.eval_raw(program).unwrap_err();
        let expected_err =
            ClarityEvalError::from(ParseError::new(ParseErrorKind::UnexpectedParserFailure));
        assert_eq!(err, expected_err, "Expected a type parse failure");
    }

    #[test]
    fn eval_read_only_empty_program() {
        // Setup environment
        let mut tl_env_factory = tl_env_factory();
        let mut exec_state = tl_env_factory.get_env(StacksEpochId::latest());

        // Construct a dummy contract context
        let contract_id = QualifiedContractIdentifier::local("dummy-contract").unwrap();

        // Call eval_read_only with an empty program
        let program = ""; // empty program triggers parsed.is_empty()
        let err = exec_state
            .eval_read_only(&contract_id, program)
            .unwrap_err();
        let expected_err =
            ClarityEvalError::from(ParseError::new(ParseErrorKind::UnexpectedParserFailure));
        assert_eq!(err, expected_err, "Expected a type parse failure");
    }

    #[test]
    fn max_context_depth_exceeded() {
        let root = LocalContext {
            function_context: None,
            parent: None,
            callable_contracts: HashMap::new(),
            variables: HashMap::new(),
            depth: MAX_CONTEXT_DEPTH - 1,
        };
        // We should be able to extend once successfully.
        let result = root.extend().unwrap();
        // We are now at the MAX_CONTEXT_DEPTH and should fail.
        let result_2 = result.extend();
        assert!(matches!(
            result_2,
            Err(VmExecutionError::Runtime(
                RuntimeError::MaxContextDepthReached,
                _
            ))
        ));
    }

    #[apply(test_clarity_versions)]
    fn vm_initialize_contract_already_exists(
        #[case] version: ClarityVersion,
        #[case] epoch: StacksEpochId,
    ) {
        // --- Setup VM ---
        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch21, // any modern epoch
        );

        let mut call_stack = CallStack::new();

        let contract_context =
            ContractContext::new(QualifiedContractIdentifier::transient(), version);

        let mut exec_state = ExecutionState {
            global_context: &mut global_context,
            call_stack: &mut call_stack,
        };
        let invoke_ctx = InvocationContext {
            contract_context: &contract_context,
            sender: None,
            caller: None,
            sponsor: None,
        };

        let contract_id = QualifiedContractIdentifier::local("dup").unwrap();

        let contract_src = "(define-public (ping) (ok u1))";

        let ast =
            ast::build_ast(&contract_id, contract_src, &mut exec_state, version, epoch).unwrap();

        // First initialization succeeds
        exec_state
            .initialize_contract_from_ast(
                &invoke_ctx,
                contract_id.clone(),
                version,
                &ast,
                contract_src,
            )
            .unwrap();

        // Second initialization hits ContractAlreadyExists
        let err = exec_state
            .initialize_contract_from_ast(
                &invoke_ctx,
                contract_id.clone(),
                version,
                &ast,
                contract_src,
            )
            .unwrap_err();

        assert_eq!(
            err,
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::Unreachable(
                "Contract already exists: S1G2081040G2081040G2081040G208105NK8PE5.dup".to_string()
            ))
        );
    }
}
