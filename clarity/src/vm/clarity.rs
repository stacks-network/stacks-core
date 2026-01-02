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
use std::fmt;

use clarity_types::errors::ClarityEvalError;
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::{
    AnalysisDatabase, CheckErrorKind, ContractAnalysis, StaticCheckError, StaticCheckErrorKind,
};
use crate::vm::ast::errors::{ParseError, ParseErrorKind};
use crate::vm::ast::ContractAST;
use crate::vm::contexts::{AssetMap, Environment, OwnedEnvironment};
use crate::vm::costs::{ExecutionCost, LimitedCostTracker};
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::VmExecutionError;
use crate::vm::events::StacksTransactionEvent;
use crate::vm::types::{BuffData, PrincipalData, QualifiedContractIdentifier};
use crate::vm::{analysis, ast, ClarityVersion, ContractContext, SymbolicExpression, Value};

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
}

impl fmt::Display for ClarityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClarityError::CostError(ref a, ref b) => {
                write!(f, "Cost Error: {a} cost exceeded budget of {b} cost")
            }
            ClarityError::StaticCheck(ref e) => fmt::Display::fmt(e, f),
            ClarityError::Parse(ref e) => fmt::Display::fmt(e, f),
            ClarityError::AbortedByCallback { reason, .. } => {
                write!(f, "Post condition aborted transaction: {reason}")
            }
            ClarityError::Interpreter(ref e) => fmt::Display::fmt(e, f),
            ClarityError::BadTransaction(ref s) => fmt::Display::fmt(s, f),
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
        }
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
            StaticCheckErrorKind::ExecutionTimeExpired => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            _ => ClarityError::StaticCheck(e),
        }
    }
}

impl From<ClarityEvalError> for ClarityError {
    fn from(e: ClarityEvalError) -> Self {
        match e {
            ClarityEvalError::Parse(err) => ClarityError::Parse(err),
            ClarityEvalError::Vm(err) => ClarityError::Interpreter(err),
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
/// - [`CheckErrorKind::MemoryBalanceExceeded`] and [`CheckErrorKind::CostComputationFailed`]
///   are intentionally not converted to [`ClarityError::CostError`].
///   Instead, they remain wrapped in `ClarityError::Interpreter(VmExecutionError::Unchecked(CheckErrorKind::MemoryBalanceExceeded))`,
///   which causes the transaction to fail, but still be included in the block.
///
/// - This behavior differs from direct conversions of [`StaticCheckError`] and [`ParseError`] to [`ClarityError`],
///   where [`CheckErrorKind::MemoryBalanceExceeded`] is converted to [`ClarityError::CostError`],
///   during contract analysis.
///
///   As a result:
///   - A `MemoryBalanceExceeded` during contract analysis causes the block to be rejected.
///   - A `MemoryBalanceExceeded` during execution (initialization or contract call)
///     causes the transaction to fail, but the block remains valid.
impl From<VmExecutionError> for ClarityError {
    fn from(e: VmExecutionError) -> Self {
        match &e {
            VmExecutionError::Unchecked(CheckErrorKind::CostBalanceExceeded(a, b)) => {
                ClarityError::CostError(a.clone(), b.clone())
            }
            VmExecutionError::Unchecked(CheckErrorKind::CostOverflow) => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
            VmExecutionError::Unchecked(CheckErrorKind::ExecutionTimeExpired) => {
                ClarityError::CostError(ExecutionCost::max_value(), ExecutionCost::max_value())
            }
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
            ParseErrorKind::ExecutionTimeExpired => {
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
        F: FnOnce(&mut Environment) -> Result<R, ClarityEvalError>,
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
    fn with_abort_callback<F, A, R, E>(
        &mut self,
        to_do: F,
        abort_call_back: A,
    ) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>, Option<String>), E>
    where
        A: FnOnce(&AssetMap, &mut ClarityDatabase) -> Option<String>,
        F: FnOnce(&mut OwnedEnvironment) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>), E>,
        E: From<VmExecutionError>;

    /// Do something with the analysis database and cost tracker
    ///  instance of this transaction connection. This is a low-level
    ///  method that in most cases should not be used except in
    ///  implementing structs of `TransactionConnection`, and the auto
    ///  implemented methods of the `TransactionConnection` trait
    fn with_analysis_db<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase, LimitedCostTracker) -> (LimitedCostTracker, R);

    /// Analyze a provided smart contract, but do not write the analysis to the AnalysisDatabase
    fn analyze_smart_contract(
        &mut self,
        identifier: &QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
        contract_content: &str,
    ) -> Result<(ContractAST, ContractAnalysis), ClarityError> {
        let epoch_id = self.get_epoch();

        self.with_analysis_db(|db, mut cost_track| {
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
                    let result = db.commit().map_err(|e| {
                        StaticCheckErrorKind::ExpectsRejectable(format!("{e:?}")).into()
                    });
                    (cost_tracker, result)
                }
                Err(e) => {
                    let result = db.roll_back().map_err(|e| {
                        StaticCheckErrorKind::ExpectsRejectable(format!("{e:?}")).into()
                    });
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
        max_execution_time: Option<std::time::Duration>,
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
                if let Some(max_execution_time_duration) = max_execution_time {
                    vm_env
                        .context
                        .set_max_execution_time(max_execution_time_duration);
                }
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
        max_execution_time: Option<std::time::Duration>,
    ) -> Result<(AssetMap, Vec<StacksTransactionEvent>), ClarityError>
    where
        F: FnOnce(&AssetMap, &mut ClarityDatabase) -> Option<String>,
    {
        let (_, assets_modified, tx_events, reason) = self.with_abort_callback(
            |vm_env| {
                if let Some(max_execution_time_duration) = max_execution_time {
                    vm_env
                        .context
                        .set_max_execution_time(max_execution_time_duration);
                }
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
