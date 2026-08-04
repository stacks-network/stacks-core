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
use std::fmt;

use stacks_common::types::StacksEpochId;

use crate::vm::analysis::{
    AnalysisDatabase, ContractAnalysis, RuntimeCheckErrorKind, StaticCheckError,
    StaticCheckErrorKind,
};
use crate::vm::ast::ContractAST;
use crate::vm::ast::errors::{ParseError, ParseErrorKind};
use crate::vm::contexts::{AssetMap, ExecutionState, InvocationContext, OwnedEnvironment};
use crate::vm::costs::{ExecutionCost, LimitedCostTracker};
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::{ClarityEvalError, VmExecutionError};
use crate::vm::events::StacksTransactionEvent;
use crate::vm::resource_limiter::ResourceBudget;
use crate::vm::types::{BuffData, PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ClarityVersion, ContractContext, SymbolicExpression, Value, analysis, ast};

/// Top-level error type for Clarity contract processing, encompassing errors from parsing,
/// type-checking, runtime evaluation, and transaction execution.
#[derive(Debug)]
pub enum ClarityError {
    /// Error during static type-checking or semantic analysis.
    /// The `StaticCheckError` wraps the specific type-checking error, including diagnostic details.
    StaticCheck(StaticCheckError),
    /// Error during lexical or syntactic parsing.
    /// The `ParseError` wraps the specific parsing error, such as invalid syntax or tokens.
    Parse(ParseError),
    /// Error during runtime evaluation in the virtual machine.
    /// The `VmExecutionError` wraps the specific error, such as runtime errors or dynamic type-checking errors.
    Interpreter(VmExecutionError),
    /// Transaction is malformed or invalid due to blockchain-level issues.
    /// The `String` wraps a human-readable description of the issue, such as incorrect format or invalid signatures.
    BadTransaction(String),
    /// Transaction exceeds the allocated cost budget during execution.
    /// The first `ExecutionCost` represents the total consumed cost, and the second represents the budget limit.
    CostError(ExecutionCost, ExecutionCost),
    /// Transaction aborted by a callback (e.g., post-condition check or custom logic).
    AbortedByCallback {
        /// What the output value of the transaction would have been.
        /// This will be a Some for contract-calls, and None for contract initialization txs.
        output: Option<Box<Value>>,
        /// The asset map which was evaluated by the abort callback
        assets_modified: Box<AssetMap>,
        /// The events from the transaction processing
        tx_events: Vec<StacksTransactionEvent>,
        /// A human-readable explanation for aborting the transaction
        reason: String,
    },
    /// Transaction exceeded the maximum execution time or heap usage allowed.
    ExecutionResourceBudgetExceeded(String),
    /// Contract analysis exceeded the maximum analysis time or heap usage allowed.
    /// Distinct from `ExecutionResourceBudgetExceeded` so an analysis-phase issue is separable end-to-end.
    AnalysisResourceBudgetExceeded(String),
}

impl fmt::Display for ClarityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            ClarityError::CostError(a, b) => {
                write!(f, "Cost Error: {a} cost exceeded budget of {b} cost")
            }
            ClarityError::StaticCheck(e) => fmt::Display::fmt(e, f),
            ClarityError::Parse(e) => fmt::Display::fmt(e, f),
            ClarityError::AbortedByCallback { reason, .. } => {
                write!(f, "Post condition aborted transaction: {reason}")
            }
            ClarityError::Interpreter(e) => fmt::Display::fmt(e, f),
            ClarityError::BadTransaction(s) => fmt::Display::fmt(s, f),
            ClarityError::ExecutionResourceBudgetExceeded(s) => {
                write!(f, "Execution resource budget exceeded: {s}")
            }
            ClarityError::AnalysisResourceBudgetExceeded(s) => {
                write!(f, "Analysis resource budget exceeded: {s}")
            }
        }
    }
}

impl std::error::Error for ClarityError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            ClarityError::CostError(ref _a, ref _b) => None,
            ClarityError::AbortedByCallback { .. } => None,
            ClarityError::StaticCheck(ref e) => Some(e),
            ClarityError::Parse(ref e) => Some(e),
            ClarityError::Interpreter(ref e) => Some(e),
            ClarityError::BadTransaction(ref _s) => None,
            ClarityError::ExecutionResourceBudgetExceeded(_) => None,
            ClarityError::AnalysisResourceBudgetExceeded(_) => None,
        }
    }
}

/// The transaction-level outcome of a [`ClarityError`].
// Left unboxed, as it was in `stackslib`.
#[allow(clippy::large_enum_variant)]
pub enum ClarityRuntimeTxError {
    Acceptable {
        error: ClarityError,
        err_type: &'static str,
    },
    AbortedByCallback {
        /// What the output value of the transaction would have been.
        /// This will be a Some for contract-calls, and None for contract initialization txs.
        output: Option<Value>,
        /// The asset map which was evaluated by the abort callback
        assets_modified: AssetMap,
        /// The events from the transaction processing
        tx_events: Vec<StacksTransactionEvent>,
        /// A human-readable explanation for aborting the transaction
        reason: String,
    },
    CostError(ExecutionCost, ExecutionCost),
    AnalysisError(RuntimeCheckErrorKind),
    ExecutionResourceBudgetExceeded(String),
    Rejectable(ClarityError),
}

impl ClarityRuntimeTxError {
    /// Whether a transaction that failed this way still lands in a block, and so
    /// still debits the fee and consumes the nonce.
    ///
    /// Must agree with `process_transaction_payload`.
    pub fn is_included_in_block(&self, epoch_id: StacksEpochId) -> bool {
        match self {
            Self::Acceptable { .. } | Self::AbortedByCallback { .. } => true,
            // Analysis is not free, so from 2.1 the payer owes the fee.
            Self::AnalysisError(_) => epoch_id >= StacksEpochId::Epoch21,
            Self::CostError(..)
            | Self::ExecutionResourceBudgetExceeded(_)
            | Self::Rejectable(_) => false,
        }
    }
}

/// Classify an execution-phase [`ClarityError`]. Unclassified variants are
/// [`ClarityRuntimeTxError::Rejectable`].
pub fn handle_clarity_runtime_error(error: ClarityError) -> ClarityRuntimeTxError {
    match error {
        // runtime errors are okay
        ClarityError::Interpreter(VmExecutionError::Runtime(_, _)) => {
            ClarityRuntimeTxError::Acceptable {
                error,
                err_type: "runtime error",
            }
        }
        ClarityError::Interpreter(VmExecutionError::EarlyReturn(_)) => {
            ClarityRuntimeTxError::Acceptable {
                error,
                err_type: "short return/panic",
            }
        }
        ClarityError::Interpreter(VmExecutionError::RuntimeCheck(runtime_check_err)) => {
            if runtime_check_err.rejectable() {
                ClarityRuntimeTxError::Rejectable(ClarityError::Interpreter(
                    VmExecutionError::RuntimeCheck(runtime_check_err),
                ))
            } else {
                ClarityRuntimeTxError::AnalysisError(runtime_check_err)
            }
        }
        ClarityError::AbortedByCallback {
            output,
            assets_modified,
            tx_events,
            reason,
        } => ClarityRuntimeTxError::AbortedByCallback {
            output: output.map(|v| *v),
            assets_modified: *assets_modified,
            tx_events,
            reason,
        },
        ClarityError::CostError(cost, budget) => ClarityRuntimeTxError::CostError(cost, budget),
        ClarityError::ExecutionResourceBudgetExceeded(s) => {
            ClarityRuntimeTxError::ExecutionResourceBudgetExceeded(s)
        }
        unhandled_error => ClarityRuntimeTxError::Rejectable(unhandled_error),
    }
}

/// [`ClarityRuntimeTxError::is_included_in_block`] for a deploy whose analysis
/// phase failed. Analysis does not go through [`handle_clarity_runtime_error`],
/// so it is judged on `rejectable_in_epoch` instead.
pub fn analysis_failure_is_included_in_block(
    error: &ClarityError,
    epoch_id: StacksEpochId,
) -> bool {
    match error {
        ClarityError::CostError(..) | ClarityError::AnalysisResourceBudgetExceeded(_) => false,
        ClarityError::Parse(err) => !err.rejectable_in_epoch(epoch_id),
        ClarityError::StaticCheck(err) => !err.err.rejectable_in_epoch(epoch_id),
        _ => true,
    }
}

impl From<StaticCheckError> for ClarityError {
    fn from(e: StaticCheckError) -> Self {
        match *e.err {
            StaticCheckErrorKind::CostOverflow => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            StaticCheckErrorKind::CostBalanceExceeded(a, b) => ClarityError::CostError(a, b),
            StaticCheckErrorKind::MemoryBalanceExceeded(_a, _b) => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            StaticCheckErrorKind::AnalysisResourceBudgetExceeded(s) => {
                ClarityError::AnalysisResourceBudgetExceeded(s)
            }
            _ => ClarityError::StaticCheck(e),
        }
    }
}

impl From<ClarityEvalError> for ClarityError {
    fn from(e: ClarityEvalError) -> Self {
        match e {
            ClarityEvalError::Parse(err) => ClarityError::from(err),
            ClarityEvalError::Vm(err) => ClarityError::from(err),
        }
    }
}

/// Converts [`VmExecutionError`] to [`ClarityError`] for transaction execution contexts.
///
/// This conversion is used in:
/// - [`TransactionConnection::initialize_smart_contract`]
/// - [`TransactionConnection::run_contract_call`]
/// - [`TransactionConnection::run_stx_transfer`]
///
/// # Notes
///
/// - [`RuntimeCheckErrorKind::MemoryBalanceExceeded`] and [`RuntimeCheckErrorKind::CostComputationFailed`]
///   are intentionally not converted to [`ClarityError::CostError`].
///   Instead, they remain wrapped in `ClarityError::Interpreter(VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::MemoryBalanceExceeded))`,
///   which causes the transaction to fail, but still be included in the block.
///
/// - This behavior differs from direct conversions of [`StaticCheckError`] and [`ParseError`] to [`ClarityError`],
///   where [`RuntimeCheckErrorKind::MemoryBalanceExceeded`] is converted to [`ClarityError::CostError`],
///   during contract analysis.
///
///   As a result:
///   - A `MemoryBalanceExceeded` during contract analysis causes the block to be rejected.
///   - A `MemoryBalanceExceeded` during execution (initialization or contract call)
///     causes the transaction to fail, but the block remains valid.
impl From<VmExecutionError> for ClarityError {
    fn from(e: VmExecutionError) -> Self {
        match &e {
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::CostBalanceExceeded(a, b)) => {
                ClarityError::CostError(a.clone(), b.clone())
            }
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::CostOverflow) => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            VmExecutionError::RuntimeCheck(
                RuntimeCheckErrorKind::ExecutionResourceBudgetExceeded(s),
            ) => ClarityError::ExecutionResourceBudgetExceeded(s.clone()),
            _ => ClarityError::Interpreter(e),
        }
    }
}

impl From<ParseError> for ClarityError {
    fn from(e: ParseError) -> Self {
        match *e.err {
            ParseErrorKind::CostOverflow => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            ParseErrorKind::CostBalanceExceeded(a, b) => ClarityError::CostError(a, b),
            ParseErrorKind::MemoryBalanceExceeded(_a, _b) => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            _ => ClarityError::Parse(e),
        }
    }
}

pub trait ClarityConnection {
    /// Do something to the underlying DB that involves only reading.
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase);
    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R;

    fn get_epoch(&self) -> StacksEpochId;

    fn with_clarity_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut ClarityDatabase) -> R,
    {
        self.with_clarity_db_readonly_owned(|mut db| (to_do(&mut db), db))
    }

    #[allow(clippy::too_many_arguments)]
    fn with_readonly_clarity_env<F, R>(
        &mut self,
        mainnet: bool,
        chain_id: u32,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        cost_track: LimitedCostTracker,
        to_do: F,
    ) -> Result<R, ClarityEvalError>
    where
        F: FnOnce(&mut ExecutionState, &InvocationContext) -> Result<R, ClarityEvalError>,
    {
        let epoch_id = self.get_epoch();
        let clarity_version = ClarityVersion::default_for_epoch(epoch_id);
        self.with_clarity_db_readonly_owned(|clarity_db| {
            let initial_context =
                ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);
            let mut vm_env = OwnedEnvironment::new_cost_limited(
                mainnet, chain_id, clarity_db, cost_track, epoch_id,
            );
            let result = vm_env
                .execute_in_env(sender, sponsor, Some(initial_context), to_do)
                .map(|(result, _, _)| result);
            // this expect is allowed, if the database has escaped this context, then it is no longer sane
            //  and we must crash
            #[allow(clippy::expect_used)]
            let (db, _) = {
                vm_env
                    .destruct()
                    .expect("Failed to recover database reference after executing transaction")
            };
            (result, db)
        })
    }
}

pub trait TransactionConnection: ClarityConnection {
    /// Do something with this connection's Clarity environment that can be aborted
    /// with `abort_call_back`.
    ///
    /// This returns the return value of `to_do`:
    /// * the generic term `R`
    /// * the asset changes during `to_do` in an `AssetMap`
    /// * the Stacks events during the transaction
    ///
    /// and an optional string value which is the result of `abort_call_back`,
    /// containing a human-readable reason for aborting the transaction.
    ///
    /// If `to_do` returns an `Err` variant, then the changes are aborted.
    fn with_abort_callback<'hooks, F, A, R, E>(
        &'hooks mut self,
        to_do: F,
        abort_call_back: A,
    ) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>, Option<String>), E>
    where
        A: FnOnce(&AssetMap, &mut ClarityDatabase) -> Option<String>,
        F: FnOnce(
            &mut OwnedEnvironment<'_, 'hooks>,
        ) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>), E>,
        E: From<VmExecutionError>;

    /// Do something with the analysis database and cost tracker
    ///  instance of this transaction connection. This is a low-level
    ///  method that in most cases should not be used except in
    ///  implementing structs of `TransactionConnection`, and the auto
    ///  implemented methods of the `TransactionConnection` trait
    fn with_analysis_db<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase, LimitedCostTracker) -> (LimitedCostTracker, R);

    /// Analyze a provided smart contract with an optional resource budget (wall-clock
    /// deadline and allocation limit) covering AST building and static analysis, but do
    /// not write the analysis to the AnalysisDatabase.
    ///
    /// `analysis_resource_budget` must be limited only on the non-consensus voting paths
    /// (block assembly / block-proposal validation) and [`ResourceBudget::unlimited`]
    /// on deterministic replay/commit, so consensus stays deterministic. When the deadline
    /// elapses or allocations exceed the limit, the analysis aborts with
    /// [`ClarityError::AnalysisResourceBudgetExceeded`].
    ///
    /// The clock starts before AST building so that time counts against the budget;
    /// the deadline itself is only enforced at the cooperative checkpoints inside the
    /// analysis passes. The same goes for measuring the baseline memory usage.
    fn analyze_smart_contract(
        &mut self,
        identifier: &QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
        contract_content: &str,
        analysis_resource_budget: &ResourceBudget,
    ) -> Result<(ContractAST, ContractAnalysis), ClarityError> {
        let epoch_id = self.get_epoch();

        self.with_analysis_db(|db, mut cost_track| {
            // Start the analysis baseline here and take into account AST building.
            let resource_limiter = analysis_resource_budget.start_tracking();

            let ast_result = ast::build_ast(
                identifier,
                contract_content,
                &mut cost_track,
                clarity_version,
                epoch_id,
            );

            let contract_ast = match ast_result {
                Ok(x) => x,
                Err(e) => return (cost_track, Err(e.into())),
            };

            let result = analysis::run_analysis(
                identifier,
                &contract_ast.expressions,
                db,
                false,
                cost_track,
                epoch_id,
                clarity_version,
                false,
                resource_limiter,
            );

            match result {
                Ok(mut contract_analysis) => {
                    let cost_track = contract_analysis.take_contract_cost_tracker();
                    (cost_track, Ok((contract_ast, contract_analysis)))
                }
                Err(e) => (e.1, Err(e.0.into())),
            }
        })
    }

    /// Save a contract analysis output to the AnalysisDatabase
    /// An error here would indicate that something has gone terribly wrong in the processing of a contract insert.
    ///   the caller should likely abort the whole block or panic
    fn save_analysis(
        &mut self,
        identifier: &QualifiedContractIdentifier,
        contract_analysis: &ContractAnalysis,
    ) -> Result<(), StaticCheckError> {
        self.with_analysis_db(|db, cost_tracker| {
            db.begin();
            let result = db.insert_contract(identifier, contract_analysis);
            match result {
                Ok(_) => {
                    let result = db
                        .commit()
                        .map_err(|e| StaticCheckErrorKind::Unreachable(format!("{e:?}")).into());
                    (cost_tracker, result)
                }
                Err(e) => {
                    let result = db
                        .roll_back()
                        .map_err(|e| StaticCheckErrorKind::Unreachable(format!("{e:?}")).into());
                    if result.is_err() {
                        (cost_tracker, result)
                    } else {
                        (cost_tracker, Err(e))
                    }
                }
            }
        })
    }

    /// Execute a STX transfer in the current block.
    /// Will throw an error if it tries to spend STX that the 'from' principal doesn't have.
    fn run_stx_transfer(
        &mut self,
        from: &PrincipalData,
        to: &PrincipalData,
        amount: u128,
        memo: &BuffData,
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), ClarityError> {
        self.with_abort_callback(
            |vm_env| {
                vm_env
                    .stx_transfer(from, to, amount, memo)
                    .map_err(ClarityError::from)
            },
            |_, _| None,
        )
        .map(|(value, assets, events, _)| (value, assets, events))
    }

    /// Execute a contract call in the current block.
    /// If an error occurs while processing the transaction, its modifications will be rolled back.
    /// `abort_call_back` is called with an `AssetMap` and a `ClarityDatabase` reference,
    /// If `abort_call_back` returns `Some(reason)`, all modifications from this transaction will be rolled back.
    /// Otherwise, they will be committed (though they may later be rolled back if the block itself is rolled back).
    #[allow(clippy::too_many_arguments)]
    fn run_contract_call<F>(
        &mut self,
        sender: &PrincipalData,
        sponsor: Option<&PrincipalData>,
        contract: &QualifiedContractIdentifier,
        public_function: &str,
        args: &[Value],
        abort_call_back: F,
        resource_budget: &ResourceBudget,
    ) -> Result<(Value, AssetMap, Vec<StacksTransactionEvent>), ClarityError>
    where
        F: FnOnce(&AssetMap, &mut ClarityDatabase) -> Option<String>,
    {
        let expr_args: Vec<_> = args
            .iter()
            .map(|x| SymbolicExpression::atom_value(x.clone()))
            .collect();

        self.with_abort_callback(
            |vm_env| {
                vm_env
                    .context
                    .set_execution_resource_limiter(resource_budget.start_tracking());
                vm_env
                    .execute_transaction(
                        sender.clone(),
                        sponsor.cloned(),
                        contract.clone(),
                        public_function,
                        &expr_args,
                    )
                    .map_err(ClarityError::from)
            },
            abort_call_back,
        )
        .and_then(|(value, assets_modified, tx_events, reason)| {
            if let Some(reason) = reason {
                Err(ClarityError::AbortedByCallback {
                    output: Some(Box::new(value)),
                    assets_modified: Box::new(assets_modified),
                    tx_events,
                    reason,
                })
            } else {
                Ok((value, assets_modified, tx_events))
            }
        })
    }

    /// Initialize a contract in the current block.
    ///  If an error occurs while processing the initialization, it's modifications will be rolled back.
    /// `abort_call_back` is called with an `AssetMap` and a `ClarityDatabase` reference,
    /// If `abort_call_back` returns `Some(reason)`, all modifications from this transaction will be rolled back.
    /// Otherwise, they will be committed (though they may later be rolled back if the block itself is rolled back).
    #[allow(clippy::too_many_arguments)]
    fn initialize_smart_contract<F>(
        &mut self,
        identifier: &QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
        contract_ast: &ContractAST,
        contract_str: &str,
        sponsor: Option<PrincipalData>,
        abort_call_back: F,
        execution_resource_budget: &ResourceBudget,
    ) -> Result<(AssetMap, Vec<StacksTransactionEvent>), ClarityError>
    where
        F: FnOnce(&AssetMap, &mut ClarityDatabase) -> Option<String>,
    {
        let (_, assets_modified, tx_events, reason) = self.with_abort_callback(
            |vm_env| {
                vm_env
                    .context
                    .set_execution_resource_limiter(execution_resource_budget.start_tracking());

                vm_env
                    .initialize_contract_from_ast(
                        identifier.clone(),
                        clarity_version,
                        contract_ast,
                        contract_str,
                        sponsor,
                    )
                    .map_err(ClarityError::from)
            },
            abort_call_back,
        )?;
        if let Some(reason) = reason {
            Err(ClarityError::AbortedByCallback {
                output: None,
                assets_modified: Box::new(assets_modified),
                tx_events,
                reason,
            })
        } else {
            Ok((assets_modified, tx_events))
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::vm::analysis::errors::StaticCheckErrorKind;
    use crate::vm::ast::errors::ParseErrorKind;

    fn acceptable() -> ClarityRuntimeTxError {
        ClarityRuntimeTxError::Acceptable {
            error: ClarityError::BadTransaction("boom".into()),
            err_type: "runtime error",
        }
    }

    fn aborted_by_callback() -> ClarityRuntimeTxError {
        ClarityRuntimeTxError::AbortedByCallback {
            output: None,
            assets_modified: AssetMap::new(),
            tx_events: vec![],
            reason: "post-condition".into(),
        }
    }

    /// Must match `process_transaction_payload`; `AnalysisError` covered below.
    #[test]
    fn runtime_tx_error_inclusion_matches_variants() {
        let epoch = StacksEpochId::latest();

        assert!(acceptable().is_included_in_block(epoch));
        assert!(aborted_by_callback().is_included_in_block(epoch));

        assert!(
            !ClarityRuntimeTxError::CostError(ExecutionCost::ZERO, ExecutionCost::max_value())
                .is_included_in_block(epoch)
        );
        assert!(
            !ClarityRuntimeTxError::ExecutionResourceBudgetExceeded("too slow".into())
                .is_included_in_block(epoch)
        );
        assert!(
            !ClarityRuntimeTxError::Rejectable(ClarityError::BadTransaction("nope".into()))
                .is_included_in_block(epoch)
        );
    }

    #[test]
    fn analysis_error_inclusion_is_gated_on_epoch_21() {
        let err = || ClarityRuntimeTxError::AnalysisError(RuntimeCheckErrorKind::ValueTooLarge);

        assert!(!err().is_included_in_block(StacksEpochId::Epoch20));
        assert!(!err().is_included_in_block(StacksEpochId::Epoch2_05));
        assert!(err().is_included_in_block(StacksEpochId::Epoch21));
        assert!(err().is_included_in_block(StacksEpochId::latest()));
    }

    #[test]
    fn analysis_failure_excludes_resource_exhaustion() {
        let epoch = StacksEpochId::latest();

        assert!(!analysis_failure_is_included_in_block(
            &ClarityError::CostError(ExecutionCost::ZERO, ExecutionCost::max_value()),
            epoch
        ));
        assert!(!analysis_failure_is_included_in_block(
            &ClarityError::AnalysisResourceBudgetExceeded("too slow".into()),
            epoch
        ));
    }

    #[test]
    fn analysis_failure_excludes_rejectable_errors() {
        let epoch = StacksEpochId::latest();

        // Rejectable in every epoch.
        assert!(!analysis_failure_is_included_in_block(
            &ClarityError::Parse(ParseError::new(ParseErrorKind::InterpreterFailure)),
            epoch
        ));
        assert!(!analysis_failure_is_included_in_block(
            &ClarityError::StaticCheck(StaticCheckError::new(
                StaticCheckErrorKind::TraitReferenceChainTooDeep
            )),
            epoch
        ));
    }

    #[test]
    fn analysis_failure_includes_ordinary_type_errors() {
        let epoch = StacksEpochId::latest();

        assert!(analysis_failure_is_included_in_block(
            &ClarityError::StaticCheck(StaticCheckError::new(
                StaticCheckErrorKind::UnknownFunction("no-such-fn".into())
            )),
            epoch
        ));
    }

    /// `SupertypeTooLarge` stops being rejectable at 3.4.
    #[test]
    fn analysis_failure_rejectability_can_change_with_epoch() {
        let err = || {
            ClarityError::StaticCheck(StaticCheckError::new(
                StaticCheckErrorKind::SupertypeTooLarge,
            ))
        };

        assert!(!analysis_failure_is_included_in_block(
            &err(),
            StacksEpochId::Epoch33
        ));
        assert!(analysis_failure_is_included_in_block(
            &err(),
            StacksEpochId::Epoch34
        ));
    }
}
