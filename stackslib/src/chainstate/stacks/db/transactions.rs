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

#[cfg(test)]
use std::time::Duration;

use clarity::vm::analysis::types::ContractAnalysis;
use clarity::vm::contexts::AssetMap;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::errors::{VmExecutionError, VmInternalError};
#[cfg(test)]
use clarity::vm::hooks::EvalHook;
#[cfg(test)]
use clarity::vm::resource_limiter::ResourceBudget;
#[cfg(test)]
use clarity::vm::types::{
    AssetIdentifier, QualifiedContractIdentifier, StacksAddressExtensions as _,
    StandardPrincipalData, TupleData,
};
use clarity::vm::types::{PrincipalData, Value};

use crate::chainstate::stacks::db::*;
#[cfg(test)]
use crate::chainstate::stacks::miner::TransactionResourceBudgets;
use crate::chainstate::stacks::miner::TransactionResult;
use crate::chainstate::stacks::Error;
use crate::clarity_vm::clarity::ClarityError;
use crate::monitoring::increment_unreachable_errors_counter;

// TODO: Move this module root to `transactions/mod.rs` as a separate, mechanical change.
pub mod processing;

pub use self::processing::{TransactionProcessor, TxToProcess};

/// This is a safe-to-hash Clarity value
#[derive(PartialEq, Eq)]
struct HashableClarityValue(Value);

impl TryFrom<Value> for HashableClarityValue {
    type Error = VmExecutionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        // check that serialization _will_ be successful when hashed
        let _bytes = value.serialize_to_vec().map_err(|_| {
            VmExecutionError::Internal(VmInternalError::Expect(
                "Failed to serialize asset in NFT during post-condition checks".into(),
            ))
        })?;
        Ok(Self(value))
    }
}

impl std::hash::Hash for HashableClarityValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        #[allow(clippy::unwrap_used, clippy::collection_is_never_read)]
        // this unwrap is safe _as long as_ TryFrom<Value> was used as a constructor
        // Also, this function has side effects, which cause Clippy to wrongly think `bytes` is unused
        let bytes = self.0.serialize_to_vec().unwrap();
        bytes.hash(state);
    }
}

impl StacksTransactionReceipt {
    pub fn from_stx_transfer(
        tx: StacksTransaction,
        events: Vec<StacksTransactionEvent>,
        result: Value,
        cost: ExecutionCost,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            events,
            result,
            stx_burned: 0,
            post_condition_aborted: false,
            contract_analysis: None,
            transaction: tx.into(),
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: None,
            problematic_skipped: None,
        }
    }

    pub fn from_contract_call(
        tx: StacksTransaction,
        events: Vec<StacksTransactionEvent>,
        result: Value,
        burned: u128,
        cost: ExecutionCost,
        vm_error: Option<String>,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            post_condition_aborted: false,
            events,
            result,
            stx_burned: burned,
            contract_analysis: None,
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error,
            problematic_skipped: None,
        }
    }

    pub fn from_condition_aborted_contract_call(
        tx: StacksTransaction,
        events: Vec<StacksTransactionEvent>,
        result: Value,
        burned: u128,
        cost: ExecutionCost,
        reason: String,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            post_condition_aborted: true,
            events,
            result,
            stx_burned: burned,
            contract_analysis: None,
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: Some(reason),
            problematic_skipped: None,
        }
    }

    pub fn from_smart_contract(
        tx: StacksTransaction,
        events: Vec<StacksTransactionEvent>,
        burned: u128,
        analysis: ContractAnalysis,
        cost: ExecutionCost,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            events,
            post_condition_aborted: false,
            result: Value::okay_true(),
            stx_burned: burned,
            contract_analysis: Some(analysis),
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: None,
            problematic_skipped: None,
        }
    }

    pub fn from_condition_aborted_smart_contract(
        tx: StacksTransaction,
        events: Vec<StacksTransactionEvent>,
        burned: u128,
        analysis: ContractAnalysis,
        cost: ExecutionCost,
        reason: String,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            events,
            post_condition_aborted: true,
            result: Value::okay_true(),
            stx_burned: burned,
            contract_analysis: Some(analysis),
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: Some(reason),
            problematic_skipped: None,
        }
    }

    pub fn from_coinbase(tx: StacksTransaction) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            events: vec![],
            post_condition_aborted: false,
            result: Value::okay_true(),
            stx_burned: 0,
            contract_analysis: None,
            execution_cost: ExecutionCost::ZERO,
            microblock_header: None,
            tx_index: 0,
            vm_error: None,
            problematic_skipped: None,
        }
    }

    pub fn from_analysis_failure(
        tx: StacksTransaction,
        analysis_cost: ExecutionCost,
        error: ClarityError,
    ) -> StacksTransactionReceipt {
        let error_string = match error {
            ClarityError::StaticCheck(ref static_check_error) => {
                if let Some(span) = static_check_error.diagnostic.spans.first() {
                    format!(
                        ":{}:{}: {}",
                        span.start_line, span.start_column, static_check_error.diagnostic.message
                    )
                } else {
                    static_check_error.diagnostic.message.to_string()
                }
            }
            ClarityError::Parse(ref parse_error) => {
                if let Some(span) = parse_error.diagnostic.spans.first() {
                    format!(
                        ":{}:{}: {}",
                        span.start_line, span.start_column, parse_error.diagnostic.message
                    )
                } else {
                    parse_error.diagnostic.message.to_string()
                }
            }
            _ => error.to_string(),
        };
        StacksTransactionReceipt {
            transaction: tx.into(),
            events: vec![],
            post_condition_aborted: false,
            result: Value::err_none(),
            stx_burned: 0,
            contract_analysis: None,
            execution_cost: analysis_cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: Some(error_string),
            problematic_skipped: None,
        }
    }

    pub fn from_poison_microblock(
        tx: StacksTransaction,
        result: Value,
        cost: ExecutionCost,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            events: vec![],
            post_condition_aborted: false,
            result,
            stx_burned: 0,
            contract_analysis: None,
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: None,
            problematic_skipped: None,
        }
    }

    pub fn from_runtime_failure_smart_contract(
        tx: StacksTransaction,
        cost: ExecutionCost,
        contract_analysis: ContractAnalysis,
        error: RuntimeCheckErrorKind,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            post_condition_aborted: false,
            result: Value::err_none(),
            events: vec![],
            stx_burned: 0,
            contract_analysis: Some(contract_analysis),
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: Some(error.to_string()),
            problematic_skipped: None,
        }
    }

    pub fn from_runtime_failure_contract_call(
        tx: StacksTransaction,
        cost: ExecutionCost,
        error: RuntimeCheckErrorKind,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            post_condition_aborted: false,
            result: Value::err_none(),
            events: vec![],
            stx_burned: 0,
            contract_analysis: None,
            execution_cost: cost,
            microblock_header: None,
            tx_index: 0,
            vm_error: Some(error.to_string()),
            problematic_skipped: None,
        }
    }

    pub fn from_tenure_change(tx: StacksTransaction) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            events: vec![],
            post_condition_aborted: false,
            result: Value::okay_true(),
            stx_burned: 0,
            contract_analysis: None,
            execution_cost: ExecutionCost::ZERO,
            microblock_header: None,
            tx_index: 0,
            vm_error: None,
            problematic_skipped: None,
        }
    }

    /// Receipt for a transaction that was marked problematic by the block's
    /// `NakamotoBlockHeader::problematic_txs` list. The transaction's payload
    /// was NOT executed: only the precheck cost is reflected in the block
    /// budget, and the fee was debited / origin (and sponsor) nonces bumped by
    /// [`TransactionProcessor::process`]. `execution_cost` is zero and
    /// `events` is empty.
    pub fn from_problematic_skipped(
        tx: StacksTransaction,
        category: u8,
    ) -> StacksTransactionReceipt {
        StacksTransactionReceipt {
            transaction: tx.into(),
            events: vec![],
            post_condition_aborted: false,
            result: Value::err_none(),
            stx_burned: 0,
            contract_analysis: None,
            execution_cost: ExecutionCost::ZERO,
            microblock_header: None,
            tx_index: 0,
            vm_error: None,
            problematic_skipped: Some(category),
        }
    }

    pub fn is_coinbase_tx(&self) -> bool {
        if let TransactionOrigin::Stacks(ref transaction) = self.transaction {
            if let TransactionPayload::Coinbase(..) = transaction.payload {
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
pub struct TransactionNonceMismatch {
    pub expected: u64,
    pub actual: u64,
    pub txid: Txid,
    pub principal: PrincipalData,
    pub is_origin: bool,
    pub quiet: bool,
}

impl std::fmt::Display for TransactionNonceMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let acct_type = if self.is_origin { "origin" } else { "sponsor" };
        write!(
            f,
            "Bad nonce: {} account {} nonce of tx {} is {} (expected {})",
            acct_type,
            &self.principal,
            &self.txid.to_hex(),
            &self.actual,
            &self.expected
        )
    }
}

impl<T> From<(TransactionNonceMismatch, T)> for Error {
    fn from(e: (TransactionNonceMismatch, T)) -> Error {
        Error::InvalidStacksTransaction(e.0.to_string(), e.0.quiet)
    }
}

impl From<TransactionNonceMismatch> for MemPoolRejection {
    fn from(e: TransactionNonceMismatch) -> MemPoolRejection {
        MemPoolRejection::BadNonces(e)
    }
}

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

/// Log and count unreachable ClarityError variants that should never occur in production.
fn log_unreachable_error(error: &ClarityError, txid: &Txid) {
    match error {
        ClarityError::Parse(parse_err) if parse_err.is_unreachable() => {
            error!("UNREACHABLE_ERROR_TRIGGERED: parse error that should never occur was hit";
                "event_name" => "unreachable_error",
                "error_type" => "parse",
                "txid" => %txid,
                "error" => %parse_err,
            );
            increment_unreachable_errors_counter("parse");
        }
        ClarityError::StaticCheck(static_err) if static_err.err.is_unreachable() => {
            error!("UNREACHABLE_ERROR_TRIGGERED: static check error that should never occur was hit";
                "event_name" => "unreachable_error",
                "error_type" => "static_check",
                "txid" => %txid,
                "error" => %static_err,
            );
            increment_unreachable_errors_counter("static_check");
        }
        ClarityError::Interpreter(VmExecutionError::RuntimeCheck(runtime_check_err))
            if runtime_check_err.is_unreachable() =>
        {
            error!("UNREACHABLE_ERROR_TRIGGERED: runtime check error that should never occur was hit";
                "event_name" => "unreachable_error",
                "error_type" => "runtime_check",
                "txid" => %txid,
                "error" => %runtime_check_err,
            );
            increment_unreachable_errors_counter("runtime_check");
        }
        _ => {}
    }
}

/// Classify a failed transaction into a `TransactionResult`. For failures that
/// charged execution cost before bailing (problematic txs and cost overflows),
/// roll back the cost so the failure does not shrink the remaining block
/// budget for subsequent honest txs.
pub fn finalize_failed_transaction(
    clarity_tx: &mut ClarityTx,
    tx: &StacksTransaction,
    cost_before: &ExecutionCost,
    error: Error,
) -> TransactionResult {
    let (is_problematic, error) =
        TransactionResult::is_problematic(tx, error, clarity_tx.get_epoch());
    if is_problematic {
        // Roll back the cost accumulated by this transaction so it does not
        // shrink the remaining block budget for subsequent honest txs.
        clarity_tx.reset_cost(cost_before.clone());
        TransactionResult::problematic(tx, error)
    } else {
        match &error {
            Error::CostOverflowError(overflow_cost_before, cost_after, total_budget) => {
                // note: this path _does_ not perform the tx block budget % heuristic,
                //  because this code path is not directly called with a mempool handle.
                clarity_tx.reset_cost(cost_before.clone());
                if total_budget.proportion_largest_dimension(overflow_cost_before)
                    < TX_BLOCK_LIMIT_PROPORTION_HEURISTIC
                {
                    warn!(
                        "Transaction {} consumed over {}% of block budget, marking as invalid; budget was {total_budget}",
                        tx.txid(),
                        100 - TX_BLOCK_LIMIT_PROPORTION_HEURISTIC
                    );
                    let mut measured_cost = cost_after.clone();
                    let measured_cost = if measured_cost.sub(overflow_cost_before).is_ok() {
                        Some(measured_cost)
                    } else {
                        warn!("Failed to compute measured cost of a too big transaction");
                        None
                    };
                    TransactionResult::error(tx, Error::TransactionTooBigError(measured_cost))
                } else {
                    warn!(
                        "Transaction {} reached block cost {cost_after}; budget was {total_budget}",
                        tx.txid()
                    );
                    TransactionResult::skipped_due_to_error(tx, Error::BlockTooBigError)
                }
            }
            _ => TransactionResult::error(tx, error),
        }
    }
}

#[cfg(test)]
pub mod test {
    use clarity::util::secp256k1::Secp256k1PrivateKey;
    use clarity::vm::hooks::trace::CallTraceHook;
    use clarity::vm::representations::{ClarityName, ContractName};
    use clarity::vm::test_util::{UnitTestBurnStateDB, TEST_BURN_STATE_DB};
    use clarity::vm::tests::TEST_HEADER_DB;
    use clarity::vm::types::ResponseData;
    use pinny::tag;
    use proptest::prelude::*;
    use rand::Rng;
    use rstest::rstest;
    use stacks_common::types::chainstate::SortitionId;
    use stacks_common::util::hash::*;

    use super::processing::check_transaction_postconditions_for_test;
    use super::*;
    use crate::chainstate::stacks::db::testing::*;
    use crate::chainstate::stacks::{Error, *};

    /// Exercises the complete processor lifecycle in legacy transaction tests.
    fn process_transaction_for_test(
        clarity_tx: &mut ClarityTx,
        tx: &StacksTransaction,
        quiet: bool,
        max_execution_time: Option<Duration>,
    ) -> Result<(u64, StacksTransactionReceipt), Error> {
        let resource_budgets = TransactionResourceBudgets::unlimited().with_execution_budget(
            ResourceBudget::unlimited().with_max_duration(max_execution_time),
        );
        TransactionProcessor::from(tx)
            .using_clarity_tx(clarity_tx)
            .with_resource_policy(resource_budgets)
            .quiet(quiet)
            .process()
    }

    /// Selects a transaction's Clarity version in legacy transaction tests.
    fn get_tx_clarity_version_for_test(
        clarity_tx: &mut ClarityTx,
        tx: &StacksTransaction,
    ) -> Result<ClarityVersion, Error> {
        Ok(TransactionProcessor::from(tx).clarity_version(clarity_tx.get_epoch()))
    }

    pub const TestBurnStateDB_20: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch20,
    };
    pub const TestBurnStateDB_2_05: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch2_05,
    };
    pub const TestBurnStateDB_21: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch21,
    };
    pub const TestBurnStateDB_25: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch25,
    };
    pub const TestBurnStateDB_30: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch30,
    };
    pub const TestBurnStateDB_31: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch31,
    };
    pub const TestBurnStateDB_32: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch32,
    };
    pub const TestBurnStateDB_33: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch33,
    };
    pub const TestBurnStateDB_34: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch34,
    };
    pub const TestBurnStateDB_40: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch40,
    };
    pub const TestBurnStateDB_41: UnitTestBurnStateDB = UnitTestBurnStateDB {
        epoch_id: StacksEpochId::Epoch41,
    };

    pub const ALL_BURN_DBS: &[&dyn BurnStateDB] = &[
        &TestBurnStateDB_20 as &dyn BurnStateDB,
        &TestBurnStateDB_2_05 as &dyn BurnStateDB,
        &TestBurnStateDB_21 as &dyn BurnStateDB,
        &TestBurnStateDB_30 as &dyn BurnStateDB,
        &TestBurnStateDB_31 as &dyn BurnStateDB,
        &TestBurnStateDB_32 as &dyn BurnStateDB,
        &TestBurnStateDB_33 as &dyn BurnStateDB,
        &TestBurnStateDB_34 as &dyn BurnStateDB,
        &TestBurnStateDB_40 as &dyn BurnStateDB,
        &TestBurnStateDB_41 as &dyn BurnStateDB,
    ];

    pub const PRE_33_DBS: &[&dyn BurnStateDB] = &[
        &TestBurnStateDB_20 as &dyn BurnStateDB,
        &TestBurnStateDB_2_05 as &dyn BurnStateDB,
        &TestBurnStateDB_21 as &dyn BurnStateDB,
        &TestBurnStateDB_30 as &dyn BurnStateDB,
        &TestBurnStateDB_31 as &dyn BurnStateDB,
        &TestBurnStateDB_32 as &dyn BurnStateDB,
    ];

    pub const PRE_21_DBS: &[&dyn BurnStateDB] = &[
        &TestBurnStateDB_20 as &dyn BurnStateDB,
        &TestBurnStateDB_2_05 as &dyn BurnStateDB,
    ];

    pub const NAKAMOTO_DBS: &[&dyn BurnStateDB] = &[
        &TestBurnStateDB_30 as &dyn BurnStateDB,
        &TestBurnStateDB_31 as &dyn BurnStateDB,
        &TestBurnStateDB_32 as &dyn BurnStateDB,
        &TestBurnStateDB_33 as &dyn BurnStateDB,
        &TestBurnStateDB_34 as &dyn BurnStateDB,
        &TestBurnStateDB_40 as &dyn BurnStateDB,
        &TestBurnStateDB_41 as &dyn BurnStateDB,
    ];

    #[test]
    fn contract_publish_runtime_error() {
        let contract_id = QualifiedContractIdentifier::local("contract").unwrap();
        let address = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR";
        let sender = PrincipalData::parse(address).unwrap();

        let marf_kv = MarfedKV::temporary();
        let chain_id = 0x80000000;
        let mut clarity_instance = ClarityInstance::new(false, chain_id, marf_kv);
        let mut genesis = clarity_instance.begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            ),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );
        genesis.initialize_epoch_2_05().unwrap();
        genesis.initialize_epoch_2_1().unwrap();
        genesis.as_transaction(|tx_conn| {
            // bump the epoch in the Clarity DB
            tx_conn
                .with_clarity_db(|db| {
                    db.set_clarity_epoch_version(StacksEpochId::Epoch21)
                        .unwrap();
                    Ok(())
                })
                .unwrap();
        });
        genesis.commit_block();

        let mut next_block = clarity_instance.begin_block(
            &StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            ),
            &StacksBlockId([3; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let mut tx_conn = next_block.start_transaction_processing();
        let sk = Secp256k1PrivateKey::random();

        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id,
            auth: TransactionAuth::from_p2pkh(&sk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::from_literal("test-contract"),
                    code_body: StacksString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };
        let origin_account = StacksAccount {
            principal: sender,
            nonce: 0,
            stx_balance: STXBalance::Unlocked { amount: 100 },
        };
        let receipt = TransactionProcessor::from(&tx)
            .with_unlimited_resource_policy()
            .using_clarity_transaction(&mut tx_conn, &origin_account)
            .process_payload()
            .unwrap();

        assert_eq!(receipt.result, Value::err_none());
        assert!(receipt.vm_error.unwrap().starts_with("DivisionByZero"));
    }

    fn run_process_transaction_payload_at_epoch(
        epoch_id: StacksEpochId,
        tx: &StacksTransaction,
    ) -> Result<StacksTransactionReceipt, Error> {
        let marf_kv = MarfedKV::temporary();
        let chain_id = 0x80000000;
        let mut clarity_instance = ClarityInstance::new(false, chain_id, marf_kv);
        let mut genesis = clarity_instance.begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            ),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        genesis.initialize_epoch_2_05().unwrap();
        genesis.initialize_epoch_2_1().unwrap();
        genesis.initialize_epoch_3_0().unwrap();
        genesis.initialize_epoch_3_1().unwrap();
        genesis.initialize_epoch_3_2().unwrap();
        genesis.initialize_epoch_3_3().unwrap();
        if epoch_id >= StacksEpochId::Epoch34 {
            genesis.initialize_epoch_3_4().unwrap();
        }
        if epoch_id >= StacksEpochId::Epoch40 {
            genesis.initialize_epoch_4_0().unwrap();
        }
        if epoch_id >= StacksEpochId::Epoch41 {
            genesis.initialize_epoch_4_1().unwrap();
        }
        genesis.commit_block();

        let burn_db = match epoch_id {
            StacksEpochId::Epoch30 => &TestBurnStateDB_30 as &dyn BurnStateDB,
            StacksEpochId::Epoch31 => &TestBurnStateDB_31 as &dyn BurnStateDB,
            StacksEpochId::Epoch32 => &TestBurnStateDB_32 as &dyn BurnStateDB,
            StacksEpochId::Epoch33 => &TestBurnStateDB_33 as &dyn BurnStateDB,
            StacksEpochId::Epoch34 => &TestBurnStateDB_34 as &dyn BurnStateDB,
            StacksEpochId::Epoch40 => &TestBurnStateDB_40 as &dyn BurnStateDB,
            StacksEpochId::Epoch41 => &TestBurnStateDB_41 as &dyn BurnStateDB,
            _ => panic!("Unsupported epoch in test helper: {epoch_id}"),
        };

        let next_block = clarity_instance.begin_block(
            &StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            ),
            &StacksBlockId([3; 32]),
            &TEST_HEADER_DB,
            burn_db,
        );

        let mut clarity_tx = ClarityTx {
            block: next_block,
            config: DBConfig {
                version: CHAINSTATE_VERSION.to_string(),
                mainnet: false,
                chain_id,
            },
        };

        let (_fee, receipt) =
            validate_transactions_static_epoch_and_process_transaction(&mut clarity_tx, tx, false)?;
        Ok(receipt)
    }

    #[rstest]
    #[case(StacksEpochId::Epoch30, false)]
    #[case(StacksEpochId::Epoch31, false)]
    #[case(StacksEpochId::Epoch32, false)]
    #[case(StacksEpochId::Epoch33, false)]
    #[case(StacksEpochId::Epoch34, true)]
    fn process_transaction_payload_originator_mode_epoch_gate(
        #[case] epoch_id: StacksEpochId,
        #[case] should_succeed: bool,
    ) {
        let sk = Secp256k1PrivateKey::random();
        let auth = TransactionAuth::from_p2pkh(&sk).unwrap();
        let chain_id = 0x80000000;

        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id,
            auth,
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Originator,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::from_literal("test-contract"),
                    code_body: StacksString::from_str("(define-public (ping) (ok true))").unwrap(),
                },
                None,
            ),
        };
        let mut signer = StacksTransactionSigner::new(&tx);
        signer.sign_origin(&sk).unwrap();
        let tx = signer.get_tx().unwrap();

        let result = run_process_transaction_payload_at_epoch(epoch_id, &tx);
        if should_succeed {
            let receipt = result.unwrap();
            assert_eq!(receipt.result, Value::okay_true());
            assert!(!receipt.post_condition_aborted);
        } else {
            match result.unwrap_err() {
                Error::InvalidStacksTransaction(msg, false) => {
                    assert!(msg.contains("target epoch is not activated"), "{msg}");
                }
                _ => panic!("Expected InvalidStacksTransaction for epoch {epoch_id:?}"),
            }
        };
    }

    #[rstest]
    #[case(StacksEpochId::Epoch30, false)]
    #[case(StacksEpochId::Epoch31, false)]
    #[case(StacksEpochId::Epoch32, false)]
    #[case(StacksEpochId::Epoch33, false)]
    #[case(StacksEpochId::Epoch34, true)]
    fn process_transaction_payload_nft_maybe_sent_epoch_gate(
        #[case] epoch_id: StacksEpochId,
        #[case] should_succeed: bool,
    ) {
        let sk = Secp256k1PrivateKey::random();
        let auth = TransactionAuth::from_p2pkh(&sk).unwrap();
        let chain_id = 0x80000000;

        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id,
            auth,
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                AssetInfo {
                    contract_address: StacksAddress::new(1, Hash160([0x11; 20])).unwrap(),
                    contract_name: ContractName::try_from("hello-world").unwrap(),
                    asset_name: ClarityName::try_from("asset").unwrap(),
                },
                Value::Int(1),
                NonfungibleConditionCode::MaybeSent,
            )],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::from_literal("test-contract"),
                    code_body: StacksString::from_str("(define-public (ping) (ok true))").unwrap(),
                },
                None,
            ),
        };
        let mut signer = StacksTransactionSigner::new(&tx);
        signer.sign_origin(&sk).unwrap();
        let tx = signer.get_tx().unwrap();

        let result = run_process_transaction_payload_at_epoch(epoch_id, &tx);
        if should_succeed {
            let receipt = result.unwrap();
            assert_eq!(receipt.result, Value::okay_true());
            assert!(!receipt.post_condition_aborted);
        } else {
            match result.unwrap_err() {
                Error::InvalidStacksTransaction(msg, false) => {
                    assert!(msg.contains("target epoch is not activated"), "{msg}");
                }
                _ => panic!("Expected InvalidStacksTransaction for epoch {epoch_id:?}"),
            }
        };
    }

    #[test]
    fn process_token_transfer_stx_transaction() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let mut tx_stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            // give the spending account some stx
            let _account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            let recv_account =
                StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());

            assert_eq!(recv_account.stx_balance.amount_unlocked(), 0);
            assert_eq!(recv_account.nonce, 0);

            conn.connection().as_transaction(|tx| {
                StacksChainState::account_credit(tx, &addr.to_account_principal(), 223)
            });

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let account_after =
                StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account_after.nonce, 1);
            assert_eq!(account_after.stx_balance.amount_unlocked(), 100);

            let recv_account_after =
                StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            assert_eq!(recv_account_after.nonce, 0);
            assert_eq!(recv_account_after.stx_balance.amount_unlocked(), 123);

            assert_eq!(fee, 0);

            let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
            let recv_addr = PrincipalData::from(QualifiedContractIdentifier {
                issuer: StacksAddress::new(1, Hash160([0xfe; 20])).unwrap().into(),
                name: ContractName::from_literal("contract-hellow"),
            });

            let mut tx_stx_transfer = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth.clone(),
                TransactionPayload::TokenTransfer(
                    recv_addr.clone(),
                    100,
                    TokenTransferMemo([0u8; 34]),
                ),
            );

            tx_stx_transfer.chain_id = 0x80000000;
            tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
            tx_stx_transfer.set_tx_fee(0);
            tx_stx_transfer.set_origin_nonce(1);

            let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
            signer.sign_origin(&privk).unwrap();

            let signed_tx = signer.get_tx().unwrap();

            let recv_account = StacksChainState::get_account(&mut conn, &recv_addr);

            assert_eq!(recv_account.stx_balance.amount_unlocked(), 0);
            assert_eq!(recv_account.nonce, 0);

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let account_after =
                StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account_after.nonce, 2);
            assert_eq!(account_after.stx_balance.amount_unlocked(), 0);

            let recv_account_after = StacksChainState::get_account(&mut conn, &recv_addr);
            assert_eq!(recv_account_after.nonce, 0);
            assert_eq!(recv_account_after.stx_balance.amount_unlocked(), 100);

            assert_eq!(fee, 0);

            conn.commit_block();
        }
    }

    #[test]
    fn process_token_transfer_stx_transaction_invalid() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();

        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let sponsor_addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk_sponsor)],
        )
        .unwrap();
        let recv_addr = addr.clone(); // shouldn't be allowed

        let auth_sponsored = {
            let auth_origin = TransactionAuth::from_p2pkh(&privk).unwrap();
            let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();
            auth_origin.into_sponsored(auth_sponsor).unwrap()
        };

        let mut tx_stx_transfer_same_receiver = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let mut tx_stx_transfer_wrong_network = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::TokenTransfer(
                sponsor_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let mut tx_stx_transfer_wrong_chain_id = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::TokenTransfer(
                sponsor_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let mut tx_stx_transfer_postconditions = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::TokenTransfer(
                sponsor_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        tx_stx_transfer_postconditions.add_post_condition(TransactionPostCondition::STX(
            PostConditionPrincipal::Origin,
            FungibleConditionCode::SentGt,
            0,
        ));

        let mut wrong_nonce_auth = auth;
        wrong_nonce_auth.set_origin_nonce(1);
        let mut tx_stx_transfer_wrong_nonce = StacksTransaction::new(
            TransactionVersion::Testnet,
            wrong_nonce_auth,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let mut wrong_nonce_auth_sponsored = auth_sponsored;
        wrong_nonce_auth_sponsored.set_sponsor_nonce(1).unwrap();
        let mut tx_stx_transfer_wrong_nonce_sponsored = StacksTransaction::new(
            TransactionVersion::Testnet,
            wrong_nonce_auth_sponsored,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        tx_stx_transfer_same_receiver.chain_id = 0x80000000;
        tx_stx_transfer_wrong_network.chain_id = 0x80000000;
        tx_stx_transfer_wrong_chain_id.chain_id = 0x80000001;
        tx_stx_transfer_postconditions.chain_id = 0x80000000;
        tx_stx_transfer_wrong_nonce.chain_id = 0x80000000;
        tx_stx_transfer_wrong_nonce_sponsored.chain_id = 0x80000000;

        tx_stx_transfer_same_receiver.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_network.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_chain_id.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_postconditions.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_nonce.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_nonce_sponsored.post_condition_mode =
            TransactionPostConditionMode::Allow;

        tx_stx_transfer_same_receiver.set_tx_fee(0);
        tx_stx_transfer_wrong_network.set_tx_fee(0);
        tx_stx_transfer_wrong_chain_id.set_tx_fee(0);
        tx_stx_transfer_postconditions.set_tx_fee(0);
        tx_stx_transfer_wrong_nonce.set_tx_fee(0);
        tx_stx_transfer_wrong_nonce_sponsored.set_tx_fee(0);

        let error_frags = vec![
            "address tried to send to itself".to_string(),
            "on testnet; got mainnet".to_string(),
            "invalid chain ID".to_string(),
            "do not support post-conditions".to_string(),
            "Bad nonce".to_string(),
            "Bad nonce".to_string(),
        ];

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            conn.connection().as_transaction(|tx| {
                StacksChainState::account_credit(tx, &addr.to_account_principal(), 123)
            });

            for (tx_stx_transfer, err_frag) in [
                tx_stx_transfer_same_receiver.clone(),
                tx_stx_transfer_wrong_network.clone(),
                tx_stx_transfer_wrong_chain_id.clone(),
                tx_stx_transfer_postconditions.clone(),
                tx_stx_transfer_wrong_nonce.clone(),
                tx_stx_transfer_wrong_nonce_sponsored.clone(),
            ]
            .iter()
            .zip(error_frags.clone())
            {
                let mut signer = StacksTransactionSigner::new(tx_stx_transfer);
                signer.sign_origin(&privk).unwrap();

                if tx_stx_transfer.auth.is_sponsored() {
                    signer.sign_sponsor(&privk_sponsor).unwrap();
                }

                let signed_tx = signer.get_tx().unwrap();

                // give the spending account some stx
                let account =
                    StacksChainState::get_account(&mut conn, &addr.to_account_principal());

                assert_eq!(account.stx_balance.amount_unlocked(), 123);
                assert_eq!(account.nonce, 0);

                let res = process_transaction_for_test(&mut conn, &signed_tx, false, None);
                if let Err(Error::InvalidStacksTransaction(msg, false)) = res {
                    assert!(msg.contains(&err_frag), "{err_frag}");
                } else {
                    panic!("Expected '{err_frag}' error, got {res:?}");
                }

                let account_after =
                    StacksChainState::get_account(&mut conn, &addr.to_account_principal());
                assert_eq!(account_after.stx_balance.amount_unlocked(), 123);
                assert_eq!(account_after.nonce, 0);
            }

            conn.commit_block();
        }
    }

    #[test]
    fn process_token_transfer_stx_sponsored_transaction() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk_origin = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();

        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();
        let auth = auth_origin.into_sponsored(auth_sponsor).unwrap();

        let addr = auth.origin().address_testnet();
        let addr_sponsor = auth.sponsor().unwrap().address_testnet();

        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let mut tx_stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk_origin).unwrap();
        signer.sign_sponsor(&privk_sponsor).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            let account_sponsor =
                StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
            let recv_account =
                StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());

            assert_eq!(account.nonce, 0);
            assert_eq!(account_sponsor.nonce, 0);
            assert_eq!(account_sponsor.stx_balance.amount_unlocked(), 0);
            assert_eq!(recv_account.nonce, 0);
            assert_eq!(recv_account.stx_balance.amount_unlocked(), 0);

            // give the spending account some stx
            conn.connection().as_transaction(|tx| {
                StacksChainState::account_credit(tx, &addr.to_account_principal(), 123)
            });

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let account_after =
                StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account_after.nonce, 1);
            assert_eq!(account_after.stx_balance.amount_unlocked(), 0);

            let account_sponsor_after =
                StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
            assert_eq!(account_sponsor_after.nonce, 1);
            assert_eq!(account_sponsor_after.stx_balance.amount_unlocked(), 0);

            let recv_account_after =
                StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            assert_eq!(recv_account_after.nonce, 0);
            assert_eq!(recv_account_after.stx_balance.amount_unlocked(), 123);

            conn.commit_block();

            assert_eq!(fee, 0);
        }
    }

    #[test]
    fn process_skipped_transaction_charges_fee_and_skips_payload() {
        // A transaction marked problematic must still pay its fee and bump the
        // origin nonce, but its payload must NOT execute. Here a token-transfer
        // of 123 uSTX is skipped: the recipient receives nothing, yet the
        // origin is debited the fee and its nonce advances.
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let mut tx_stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );
        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_tx_fee(100);

        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk).unwrap();
        let signed_tx = signer.get_tx().unwrap();

        // problematic_txs markers are only serialized/honored in Epoch 4.0+
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_40,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );

        // fund the origin enough to cover the fee and the (skipped) transfer
        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &addr.to_account_principal(), 223)
        });

        let category = 7u8;
        let (fee, receipt) = TransactionProcessor::from(TxToProcess::Skip {
            tx: &signed_tx,
            category,
        })
        .with_unlimited_resource_policy()
        .using_clarity_tx(&mut conn)
        .with_check(|_| panic!("skipped transactions must not run receipt checks"))
        .process()
        .unwrap();

        // the fee was charged and the origin nonce bumped, but the 123 uSTX
        // transfer did not happen: balance dropped by exactly the fee.
        let account_after = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account_after.nonce, 1);
        assert_eq!(account_after.stx_balance.amount_unlocked(), 123);

        let recv_account_after =
            StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
        assert_eq!(recv_account_after.nonce, 0);
        assert_eq!(recv_account_after.stx_balance.amount_unlocked(), 0);

        // the receipt reflects the skip: fee returned, tagged with the category
        // byte, zero execution cost, and no events.
        assert_eq!(fee, 100);
        assert_eq!(receipt.problematic_skipped, Some(category));
        assert_eq!(receipt.execution_cost, ExecutionCost::ZERO);
        assert!(receipt.events.is_empty());
        assert!(!receipt.post_condition_aborted);

        conn.commit_block();
    }

    #[test]
    fn process_skipped_transaction_bumps_origin_and_sponsor_nonces() {
        // For a sponsored problematic transaction, both the origin and sponsor
        // nonces advance and the sponsor pays the fee, but the payload is still
        // skipped (so the origin's balance is untouched).
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk_origin = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();

        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();
        let auth = auth_origin.into_sponsored(auth_sponsor).unwrap();

        let addr = auth.origin().address_testnet();
        let addr_sponsor = auth.sponsor().unwrap().address_testnet();
        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let mut tx_stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );
        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_tx_fee(100);

        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk_origin).unwrap();
        signer.sign_sponsor(&privk_sponsor).unwrap();
        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_40,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );

        // the sponsor pays the fee...
        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &addr_sponsor.to_account_principal(), 100)
        });
        // ...and give the origin the transfer amount, to prove it is NOT spent.
        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &addr.to_account_principal(), 123)
        });

        let (fee, receipt) = TransactionProcessor::from(TxToProcess::Skip {
            tx: &signed_tx,
            category: 0,
        })
        .using_clarity_tx(&mut conn)
        .with_unlimited_resource_policy()
        .process()
        .unwrap();

        // both nonces advance; the origin's balance is untouched (no payload).
        let account_after = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account_after.nonce, 1);
        assert_eq!(account_after.stx_balance.amount_unlocked(), 123);

        // the sponsor's nonce advances and it paid the fee.
        let sponsor_after =
            StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
        assert_eq!(sponsor_after.nonce, 1);
        assert_eq!(sponsor_after.stx_balance.amount_unlocked(), 0);

        // the recipient received nothing.
        let recv_after =
            StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
        assert_eq!(recv_after.nonce, 0);
        assert_eq!(recv_after.stx_balance.amount_unlocked(), 0);

        assert_eq!(fee, 100);
        assert_eq!(receipt.problematic_skipped, Some(0));

        conn.commit_block();
    }

    #[test]
    fn process_skipped_transaction_rejected_before_epoch_40() {
        // problematic_txs markers are only valid in Epoch 4.0+. Reaching the
        // skip path in an earlier epoch is a consensus bug, so it must error
        // rather than silently charge a fee.
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let mut tx_stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(recv_addr.into(), 123, TokenTransferMemo([0u8; 34])),
        );
        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk).unwrap();
        let signed_tx = signer.get_tx().unwrap();

        // Epoch 3.4 (any pre-4.0 epoch) must reject the skip path outright.
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_34,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );
        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &addr.to_account_principal(), 223)
        });

        let err = TransactionProcessor::from(TxToProcess::Skip {
            tx: &signed_tx,
            category: 0,
        })
        .using_clarity_tx(&mut conn)
        .with_unlimited_resource_policy()
        .process()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidStacksTransaction(..)));

        conn.commit_block();
    }

    #[test]
    fn process_smart_contract_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(addr.clone()),
                ContractName::from_literal("hello-world"),
            );
            let contract_before_res =
                StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            assert!(contract_before_res.is_none());

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 0);

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 1);

            let contract_res = StacksChainState::get_contract(&mut conn, &contract_id);

            conn.commit_block();

            assert_eq!(fee, 0);
            assert!(contract_res.is_ok());
        }
    }

    #[test]
    fn process_smart_contract_transaction_invalid() {
        let contract_correct = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let contract_syntax_error = "
        (define-data-var bar int 0)) ;; oops
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let contracts = [
                contract_correct,
                contract_correct,
                contract_syntax_error, // should still be mined, even though analysis fails
            ];

            let expected_behavior = [true, false, true];

            let contract_names = ["hello-world-0", "hello-world-0", "hello-world-1"];

            let mut next_nonce = 0;
            for i in 0..contracts.len() {
                let contract_name = contract_names[i].to_string();
                let contract = contracts[i].to_string();

                test_debug!("\ninstantiate contract\n{}\n", &contracts[i]);

                let mut tx_contract = StacksTransaction::new(
                    TransactionVersion::Testnet,
                    auth.clone(),
                    TransactionPayload::new_smart_contract(&contract_name, &contract, None)
                        .unwrap(),
                );

                tx_contract.chain_id = 0x80000000;
                tx_contract.set_tx_fee(0);
                tx_contract.set_origin_nonce(next_nonce);

                let mut signer = StacksTransactionSigner::new(&tx_contract);
                signer.sign_origin(&privk).unwrap();

                let signed_tx = signer.get_tx().unwrap();

                let _contract_id = QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(addr.clone()),
                    ContractName::try_from(contract_name).unwrap(),
                );

                let account =
                    StacksChainState::get_account(&mut conn, &addr.to_account_principal());
                assert_eq!(account.nonce, next_nonce);

                let res = process_transaction_for_test(&mut conn, &signed_tx, false, None);
                if expected_behavior[i] {
                    assert!(res.is_ok());

                    // account nonce should increment
                    let account =
                        StacksChainState::get_account(&mut conn, &addr.to_account_principal());
                    assert_eq!(account.nonce, next_nonce + 1);

                    next_nonce += 1;
                } else {
                    assert!(res.is_err());

                    // account nonce should NOT increment
                    let account =
                        StacksChainState::get_account(&mut conn, &addr.to_account_principal());
                    assert_eq!(account.nonce, next_nonce);
                    continue;
                }
            }
            conn.commit_block();
        }
    }

    #[test]
    fn process_smart_contract_transaction_syntax_error() {
        let contracts = [
            "(define-data-var bar int 0)) ;; oops",
            ";; `Int` instead of `int`
             (define-data-var bar Int 0)",
        ];
        let contract_names = ["hello-world-0", "hello-world-1"];
        let expected_line_num_error = if cfg!(feature = "developer-mode") {
            ":2:14: invalid variable definition"
        } else {
            ":0:0: invalid variable definition"
        };
        let expected_errors = [
            "Tried to close list which isn't open.",
            expected_line_num_error,
        ];
        let expected_errors_2_1 = ["unexpected ')'", expected_line_num_error];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let mut next_nonce = 0;
            for i in 0..contracts.len() {
                let contract_name = contract_names[i];
                let contract = contracts[i].to_string();

                test_debug!("\ninstantiate contract\n{}\n", &contract);

                let mut tx_contract = StacksTransaction::new(
                    TransactionVersion::Testnet,
                    auth.clone(),
                    TransactionPayload::new_smart_contract(contract_name, &contract, None).unwrap(),
                );

                tx_contract.chain_id = 0x80000000;
                tx_contract.set_tx_fee(0);
                tx_contract.set_origin_nonce(next_nonce);

                let mut signer = StacksTransactionSigner::new(&tx_contract);
                signer.sign_origin(&privk).unwrap();

                let signed_tx = signer.get_tx().unwrap();

                let _contract_id = QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(addr.clone()),
                    ContractName::from_literal(contract_name),
                );

                let (fee, receipt) =
                    process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

                // Verify that the syntax error is recorded in the receipt
                let expected_error =
                    if burn_db.get_stacks_epoch(0).unwrap().epoch_id >= StacksEpochId::Epoch21 {
                        expected_errors_2_1[i].to_string()
                    } else {
                        expected_errors[i].to_string()
                    };
                assert_eq!(receipt.vm_error.unwrap(), expected_error);

                next_nonce += 1;
            }

            conn.commit_block();
        }
    }

    #[test]
    fn process_smart_contract_transaction_runtime_error() {
        let contract_correct = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let contract_runtime_error_definition = "
        (define-data-var bar int (/ 1 0))   ;; divide-by-zero
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let contract_runtime_error_bare_code = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))
        (begin (set-bar 1 0) (ok 1))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let contracts = [
                contract_correct,
                contract_runtime_error_definition,
                contract_runtime_error_bare_code,
            ];

            let contract_names = ["hello-world-0", "hello-world-1", "hello-world-2"];

            for i in 0..contracts.len() {
                let contract_name = contract_names[i].to_string();
                let contract = contracts[i].to_string();

                let mut tx_contract = StacksTransaction::new(
                    TransactionVersion::Testnet,
                    auth.clone(),
                    TransactionPayload::new_smart_contract(&contract_name, &contract, None)
                        .unwrap(),
                );

                tx_contract.chain_id = 0x80000000;
                tx_contract.set_tx_fee(0);
                tx_contract.set_origin_nonce(i as u64);

                let mut signer = StacksTransactionSigner::new(&tx_contract);
                signer.sign_origin(&privk).unwrap();

                let signed_tx = signer.get_tx().unwrap();

                let contract_id = QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(addr.clone()),
                    ContractName::try_from(contract_name).unwrap(),
                );
                let contract_before_res =
                    StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
                assert!(contract_before_res.is_none());

                let account =
                    StacksChainState::get_account(&mut conn, &addr.to_account_principal());
                assert_eq!(account.nonce, i as u64);

                // runtime error should be handled
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

                // account nonce should increment
                let account =
                    StacksChainState::get_account(&mut conn, &addr.to_account_principal());
                assert_eq!(account.nonce, (i + 1) as u64);

                // contract is instantiated despite runtime error
                let contract_res = StacksChainState::get_contract(&mut conn, &contract_id);
                assert!(contract_res.is_ok());
            }

            conn.commit_block();
        }
    }

    #[test]
    fn process_smart_contract_sponsored_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk_origin = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();

        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();

        let auth = auth_origin.into_sponsored(auth_sponsor).unwrap();

        let addr = auth.origin().address_testnet();
        let addr_sponsor = auth.sponsor().unwrap().address_testnet();

        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk_origin).unwrap();
        signer.sign_sponsor(&privk_sponsor).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(addr.clone()),
                ContractName::from_literal("hello-world"),
            );
            let contract_before_res =
                StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            assert!(contract_before_res.is_none());

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 0);

            let _account_sponsor =
                StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
            assert_eq!(account.nonce, 0);

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 1);

            let account_sponsor =
                StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
            assert_eq!(account_sponsor.nonce, 1);

            let contract_res = StacksChainState::get_contract(&mut conn, &contract_id);

            conn.commit_block();

            assert_eq!(fee, 0);
            assert!(contract_res.is_ok());
        }
    }

    #[test]
    fn process_smart_contract_contract_call_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        // contract instantiation
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        // contract-call
        let privk_2 = StacksPrivateKey::from_hex(
            "d2c340ebcc0794b6fabdd8ac8b1c983e363b05dc8adcdf7e30db205a3fa54c1601",
        )
        .unwrap();
        let auth_2 = TransactionAuth::from_p2pkh(&privk_2).unwrap();
        let addr_2 = auth.origin().address_testnet();

        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_2,
            TransactionPayload::new_contract_call(
                addr.clone(),
                "hello-world",
                "set-bar",
                vec![Value::Int(6), Value::Int(2)],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(0);

        let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
        signer_2.sign_origin(&privk_2).unwrap();

        let signed_tx_2 = signer_2.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            // process both
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 0);

            let account_2 =
                StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
            assert_eq!(account_2.nonce, 0);

            let contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(addr.clone()),
                ContractName::from_literal("hello-world"),
            );
            let contract_before_res =
                StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            assert!(contract_before_res.is_none());

            let var_before_res =
                StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
            assert!(var_before_res.is_none());

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let var_before_set_res =
                StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
            assert_eq!(var_before_set_res, Some(Value::Int(0)));

            let (fee_2, _) =
                process_transaction_for_test(&mut conn, &signed_tx_2, false, None).unwrap();

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 1);

            let account_2 =
                StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
            assert_eq!(account_2.nonce, 1);

            let contract_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            let var_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();

            conn.commit_block();

            assert_eq!(fee, 0);
            assert_eq!(fee_2, 0);
            assert!(contract_res.is_some());
            assert!(var_res.is_some());
            assert_eq!(var_res, Some(Value::Int(3)));
        }
    }

    // Verify that a contract call transaction which passes a long contract
    // name (> 40 chars and < 128) is processed successfully.
    #[test]
    fn process_contract_call_long_contract_name_transaction() {
        let contract = "
        (define-data-var savedContract principal tx-sender)
        (define-public (save (contract principal)) (ok (var-set savedContract contract)))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        // contract instantiation
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        // contract-call
        let privk_2 = StacksPrivateKey::from_hex(
            "d2c340ebcc0794b6fabdd8ac8b1c983e363b05dc8adcdf7e30db205a3fa54c1601",
        )
        .unwrap();
        let auth_2 = TransactionAuth::from_p2pkh(&privk_2).unwrap();
        let addr_2 = auth.origin().address_testnet();

        let contractPrincipalValue =
            Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
                StandardPrincipalData::from(addr.clone()),
                ContractName::from_literal("aip10-arkadiko-update-tvl-liquidation-ratio"),
            )));
        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_2,
            TransactionPayload::new_contract_call(
                addr.clone(),
                "hello-world",
                "save",
                vec![contractPrincipalValue.clone()],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(0);

        let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
        signer_2.sign_origin(&privk_2).unwrap();

        let signed_tx_2 = signer_2.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            // process both
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 0);

            let account_2 =
                StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
            assert_eq!(account_2.nonce, 0);

            let contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(addr.clone()),
                ContractName::from_literal("hello-world"),
            );
            let contract_before_res =
                StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            assert!(contract_before_res.is_none());

            let var_before_res =
                StacksChainState::get_data_var(&mut conn, &contract_id, "savedContract").unwrap();
            assert!(var_before_res.is_none());

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let var_before_set_res =
                StacksChainState::get_data_var(&mut conn, &contract_id, "savedContract").unwrap();
            assert_eq!(
                var_before_set_res,
                Some(Value::Principal(PrincipalData::from(addr.clone())))
            );

            let (fee_2, _) =
                process_transaction_for_test(&mut conn, &signed_tx_2, false, None).unwrap();

            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account.nonce, 1);

            let account_2 =
                StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
            assert_eq!(account_2.nonce, 1);

            let contract_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            let var_res =
                StacksChainState::get_data_var(&mut conn, &contract_id, "savedContract").unwrap();

            conn.commit_block();

            assert_eq!(fee, 0);
            assert_eq!(fee_2, 0);
            assert!(contract_res.is_some());
            assert!(var_res.is_some());
            assert_eq!(var_res, Some(contractPrincipalValue.clone()));
        }
    }

    #[test]
    fn process_smart_contract_contract_call_runtime_error() {
        let contract = "
        (define-data-var bar int 1)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))
        (define-public (return-error) (err 1))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        // contract instantiation
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(addr.clone()),
                ContractName::from_literal("hello-world"),
            );
            let (_fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            // contract-calls that don't commit
            let contract_calls = vec![
                ("hello-world", "set-bar", vec![Value::Int(1), Value::Int(0)]), // divide-by-zero
                ("hello-world", "return-error", vec![]), // returns an (err ...)
            ];

            // do contract-calls
            let privk_2 = StacksPrivateKey::from_hex(
                "d2c340ebcc0794b6fabdd8ac8b1c983e363b05dc8adcdf7e30db205a3fa54c1601",
            )
            .unwrap();
            let auth_2 = TransactionAuth::from_p2pkh(&privk_2).unwrap();
            let addr_2 = auth_2.origin().address_testnet();

            let mut next_nonce = 0;

            for contract_call in contract_calls {
                let (contract_name, contract_function, contract_args) = contract_call;
                let mut tx_contract_call = StacksTransaction::new(
                    TransactionVersion::Testnet,
                    auth_2.clone(),
                    TransactionPayload::new_contract_call(
                        addr.clone(),
                        contract_name,
                        contract_function,
                        contract_args,
                    )
                    .unwrap(),
                );

                tx_contract_call.chain_id = 0x80000000;
                tx_contract_call.set_tx_fee(0);
                tx_contract_call.set_origin_nonce(next_nonce);

                let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
                signer_2.sign_origin(&privk_2).unwrap();

                let signed_tx_2 = signer_2.get_tx().unwrap();

                let account_2 =
                    StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
                assert_eq!(account_2.nonce, next_nonce);

                let (_fee, _) =
                    process_transaction_for_test(&mut conn, &signed_tx_2, false, None).unwrap();

                // nonce should have incremented
                next_nonce += 1;
                let account_2 =
                    StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
                assert_eq!(account_2.nonce, next_nonce);

                // var should not have changed
                let var_res =
                    StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
                assert!(var_res.is_some());
                assert_eq!(var_res, Some(Value::Int(1)));
            }
            conn.commit_block();
        }
    }

    #[test]
    fn process_smart_contract_user_aborts_2257() {
        let contract = "(asserts! false (err 1))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        // contract instantiation
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr.clone()),
            ContractName::from_literal("hello-world"),
        );

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );
            let (_fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            conn.commit_block();
        }
    }

    #[test]
    fn process_smart_contract_contract_call_invalid() {
        let contract = "
        (define-data-var bar int 1)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        // contract instantiation
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr.clone()),
            ContractName::from_literal("hello-world"),
        );

        // for contract-calls
        let privk_2 = StacksPrivateKey::from_hex(
            "d2c340ebcc0794b6fabdd8ac8b1c983e363b05dc8adcdf7e30db205a3fa54c1601",
        )
        .unwrap();
        let auth_2 = TransactionAuth::from_p2pkh(&privk_2).unwrap();
        let addr_2 = auth_2.origin().address_testnet();

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        // invalid contract-calls
        let contract_calls = vec![
            (
                addr.clone(),
                "hello-world",
                "set-bar-not-a-method",
                vec![Value::Int(1), Value::Int(1)],
            ), // call into non-existant method
            (
                addr.clone(),
                "hello-world-not-a-contract",
                "set-bar",
                vec![Value::Int(1), Value::Int(1)],
            ), // call into non-existant contract
            (
                addr_2.clone(),
                "hello-world",
                "set-bar",
                vec![Value::Int(1), Value::Int(1)],
            ), // address does not have a contract
            (addr.clone(), "hello-world", "set-bar", vec![Value::Int(1)]), // wrong number of args (too few)
            (
                addr.clone(),
                "hello-world",
                "set-bar",
                vec![Value::Int(1), Value::Int(1), Value::Int(1)],
            ), // wrong number of args (too many)
            (
                addr.clone(),
                "hello-world",
                "set-bar",
                vec![Value::buff_from([0xff, 4].to_vec()).unwrap(), Value::Int(1)],
            ), // wrong arg type
            (
                addr.clone(),
                "hello-world",
                "set-bar",
                vec![Value::UInt(1), Value::Int(1)],
            ), // wrong arg type
        ];

        for (dbi, burn_db) in PRE_21_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );
            let (_fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let next_nonce = 0;

            for contract_call in contract_calls.iter() {
                let (contract_addr, contract_name, contract_function, contract_args) =
                    contract_call.clone();
                let mut tx_contract_call = StacksTransaction::new(
                    TransactionVersion::Testnet,
                    auth_2.clone(),
                    TransactionPayload::new_contract_call(
                        contract_addr.clone(),
                        contract_name,
                        contract_function,
                        contract_args,
                    )
                    .unwrap(),
                );

                tx_contract_call.chain_id = 0x80000000;
                tx_contract_call.set_tx_fee(0);

                let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
                signer_2.sign_origin(&privk_2).unwrap();

                let signed_tx_2 = signer_2.get_tx().unwrap();

                let account_2 =
                    StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
                assert_eq!(account_2.nonce, next_nonce);

                // transaction is invalid, and won't be mined
                let res = process_transaction_for_test(&mut conn, &signed_tx_2, false, None);
                assert!(res.is_err());

                // nonce should NOT have incremented
                let account_2 =
                    StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
                assert_eq!(account_2.nonce, next_nonce);

                // var should NOT have changed
                let var_res =
                    StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
                assert!(var_res.is_some());
                assert_eq!(var_res, Some(Value::Int(1)));
            }
            conn.commit_block();
        }

        // in 2.1, all of these are mineable -- the fee will be collected, and the nonce(s) will
        // advance, but no state changes go through
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );
        let (_fee, _) = process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

        let mut next_nonce = 0;

        for contract_call in contract_calls.iter() {
            let (contract_addr, contract_name, contract_function, contract_args) =
                contract_call.clone();
            let mut tx_contract_call = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_2.clone(),
                TransactionPayload::new_contract_call(
                    contract_addr.clone(),
                    contract_name,
                    contract_function,
                    contract_args,
                )
                .unwrap(),
            );

            tx_contract_call.chain_id = 0x80000000;
            tx_contract_call.set_tx_fee(0);
            tx_contract_call.set_origin_nonce(next_nonce);

            let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
            signer_2.sign_origin(&privk_2).unwrap();

            let signed_tx_2 = signer_2.get_tx().unwrap();

            let account_2 =
                StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());

            assert_eq!(account_2.nonce, next_nonce);

            // this is expected to be mined
            let res = process_transaction_for_test(&mut conn, &signed_tx_2, false, None);
            assert!(res.is_ok());

            next_nonce += 1;
            let account_2 =
                StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
            assert_eq!(account_2.nonce, next_nonce);

            // no state change though
            let var_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
            assert!(var_res.is_some());
            assert_eq!(var_res, Some(Value::Int(1)));
        }
    }

    #[test]
    fn process_smart_contract_contract_call_sponsored_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        // contract instantiation
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr_publisher = auth.origin().address_testnet();

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        // sponsored contract-call
        let privk_origin = StacksPrivateKey::from_hex(
            "027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01",
        )
        .unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();

        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();

        let auth_contract_call = auth_origin.into_sponsored(auth_sponsor).unwrap();

        let addr_origin = auth_contract_call.origin().address_testnet();
        let addr_sponsor = auth_contract_call.sponsor().unwrap().address_testnet();

        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_contract_call,
            TransactionPayload::new_contract_call(
                addr_publisher.clone(),
                "hello-world",
                "set-bar",
                vec![Value::Int(6), Value::Int(2)],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(0);

        let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
        signer_2.sign_origin(&privk_origin).unwrap();
        signer_2.sign_sponsor(&privk_sponsor).unwrap();

        let signed_tx_2 = signer_2.get_tx().unwrap();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            // process both
            let account_publisher =
                StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher.nonce, 0);

            let account_origin =
                StacksChainState::get_account(&mut conn, &addr_origin.to_account_principal());
            assert_eq!(account_origin.nonce, 0);

            let account_sponsor =
                StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
            assert_eq!(account_sponsor.nonce, 0);

            let contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(addr_publisher.clone()),
                ContractName::from_literal("hello-world"),
            );
            let contract_before_res =
                StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            assert!(contract_before_res.is_none());

            let var_before_res =
                StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
            assert!(var_before_res.is_none());

            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

            let account_publisher =
                StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher.nonce, 1);

            let var_before_set_res =
                StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
            assert_eq!(var_before_set_res, Some(Value::Int(0)));

            let (fee_2, _) =
                process_transaction_for_test(&mut conn, &signed_tx_2, false, None).unwrap();

            let account_origin =
                StacksChainState::get_account(&mut conn, &addr_origin.to_account_principal());
            assert_eq!(account_origin.nonce, 1);

            let account_sponsor =
                StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
            assert_eq!(account_sponsor.nonce, 1);

            let contract_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
            let var_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();

            conn.commit_block();

            assert_eq!(fee, 0);
            assert_eq!(fee_2, 0);
            assert!(contract_res.is_some());
            assert!(var_res.is_some());
            assert_eq!(var_res, Some(Value::Int(3)));
        }
    }

    #[test]
    fn process_post_conditions_tokens() {
        let contract = "
        (define-data-var bar int 0)
        (define-fungible-token stackaroos)
        (define-non-fungible-token names (buff 50))
        (define-public (send-stackaroos (recipient principal))
          (begin
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok true))
             )
           )
        )
        (define-public (send-name (name (buff 50)) (recipient principal))
          (begin
            (as-contract   ;; used to test post-conditions on contract principal
              (begin (unwrap-panic (nft-mint? names name tx-sender))
                     (unwrap-panic (nft-transfer? names name tx-sender recipient))
                     (ok true))
            )
          )
        )
        (define-public (user-send-stackaroos (recipient principal))
          (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (ok true))
        )
        (define-public (user-send-name (name (buff 50)) (recipient principal))
          (begin
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok true))
        )
        (define-public (send-stackaroos-and-name (name (buff 50)) (recipient principal))
          (begin
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (nft-mint? names name tx-sender))
                      (unwrap-panic (nft-transfer? names name tx-sender recipient))
                      (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok true))
             )
          )
        )
        (define-public (user-send-stackaroos-and-name (name (buff 50)) (recipient principal))
           (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok true))
        )
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let privk_origin = StacksPrivateKey::from_hex(
            "027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01",
        )
        .unwrap();
        let privk_recipient = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();
        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_recv = TransactionAuth::from_p2pkh(&privk_recipient).unwrap();
        let addr_publisher = auth_origin.origin().address_testnet();
        let addr_principal = addr_publisher.to_account_principal();

        let contract_name = ContractName::try_from("hello-world").unwrap();

        let recv_addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk_recipient)],
        )
        .unwrap();
        let recv_principal = recv_addr.to_account_principal();
        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr_publisher.clone()),
            contract_name.clone(),
        );
        let _contract_principal = PrincipalData::Contract(contract_id.clone());

        let asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("stackaroos").unwrap(),
        };

        let name_asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("names").unwrap(),
        };

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_origin.clone(),
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk_origin).unwrap();

        let signed_contract_tx = signer.get_tx().unwrap();

        let mut post_conditions_pass = vec![];
        let mut post_conditions_pass_payback = vec![];
        let mut post_conditions_pass_nft = vec![];
        let mut post_conditions_fail = vec![];
        let mut post_conditions_fail_payback = vec![];
        let mut post_conditions_fail_nft = vec![];
        let mut nonce = 1;
        let mut recv_nonce = 0;
        let mut next_name: u64 = 0;

        let mut tx_contract_call_stackaroos = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_origin.clone(),
            TransactionPayload::new_contract_call(
                addr_publisher.clone(),
                "hello-world",
                "send-stackaroos",
                vec![Value::Principal(recv_principal.clone())],
            )
            .unwrap(),
        );

        tx_contract_call_stackaroos.chain_id = 0x80000000;
        tx_contract_call_stackaroos.set_tx_fee(0);

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent ==, <=, or >= 100 stackaroos
        for pass_condition in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *pass_condition,
                100,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent >= or > 99 stackaroos
        for pass_condition in [FungibleConditionCode::SentGe, FungibleConditionCode::SentGt].iter()
        {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *pass_condition,
                99,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent <= or < 101 stackaroos
        for pass_condition in [FungibleConditionCode::SentLe, FungibleConditionCode::SentLt].iter()
        {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *pass_condition,
                101,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // give recv_addr 100 more stackaroos so we can test failure-to-send-back
        {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                FungibleConditionCode::SentEq,
                100,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        let mut tx_contract_call_user_stackaroos = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_recv,
            TransactionPayload::new_contract_call(
                addr_publisher.clone(),
                "hello-world",
                "user-send-stackaroos",
                vec![Value::Principal(addr_principal.clone())],
            )
            .unwrap(),
        );

        tx_contract_call_user_stackaroos.chain_id = 0x80000000;
        tx_contract_call_user_stackaroos.set_tx_fee(0);

        // recv_addr sends 100 stackaroos back to addr_publisher.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for pass_condition in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        {
            let mut tx_contract_call_pass = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(recv_nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                asset_info.clone(),
                *pass_condition,
                100,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // recv_addr sends 100 stackaroos back to addr_publisher.
        // assert recv_addr sent >= or > 99 stackaroos
        for pass_condition in [FungibleConditionCode::SentGe, FungibleConditionCode::SentGt].iter()
        {
            let mut tx_contract_call_pass = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(recv_nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                asset_info.clone(),
                *pass_condition,
                99,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // recv_addr sends 100 stackaroos back to addr_publisher
        // assert recv_addr sent <= or < 101 stackaroos
        for pass_condition in [FungibleConditionCode::SentLe, FungibleConditionCode::SentLt].iter()
        {
            let mut tx_contract_call_pass = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(recv_nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                asset_info.clone(),
                *pass_condition,
                101,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // mint names to recv_addr, and set a post-condition on the contract-principal to check it.
        // assert contract does not possess the name
        for (_i, pass_condition) in [NonfungibleConditionCode::Sent].iter().enumerate() {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_names = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_origin.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "send-name",
                    vec![name.clone(), Value::Principal(recv_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_names.chain_id = 0x80000000;
            tx_contract_call_names.set_tx_fee(0);
            tx_contract_call_names.set_origin_nonce(nonce);

            tx_contract_call_names.add_post_condition(TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                name_asset_info.clone(),
                name.clone(),
                *pass_condition,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_names);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass_nft.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent < or > 100 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentLt, FungibleConditionCode::SentGt].iter()
        {
            let mut tx_contract_call_fail = tx_contract_call_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *fail_condition,
                100,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent <= or < 99 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentLe, FungibleConditionCode::SentLt].iter()
        {
            let mut tx_contract_call_fail = tx_contract_call_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *fail_condition,
                99,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent > or >= 101 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentGe, FungibleConditionCode::SentGt].iter()
        {
            let mut tx_contract_call_fail = tx_contract_call_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *fail_condition,
                101,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // recv_addr tries sends 100 stackaroos back to addr_publisher
        // assert recv_addr sent < or > 100 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentLt, FungibleConditionCode::SentLt].iter()
        {
            let mut tx_contract_call_fail = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(recv_nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                asset_info.clone(),
                *fail_condition,
                100,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_fail_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // mint names to recv_addr, and set a post-condition on the contract-principal to check it.
        // assert contract still possesses the name (should fail)
        for (_i, fail_condition) in [NonfungibleConditionCode::NotSent].iter().enumerate() {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_names = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_origin.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "send-name",
                    vec![name.clone(), Value::Principal(recv_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_names.chain_id = 0x80000000;
            tx_contract_call_names.set_tx_fee(0);
            tx_contract_call_names.set_origin_nonce(nonce);

            tx_contract_call_names.add_post_condition(TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                name_asset_info.clone(),
                name.clone(),
                *fail_condition,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_names);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail_nft.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            // make sure costs-3 is instantiated, so as-contract works in 2.1
            let mut conn = chainstate.test_genesis_block_begin_2_1(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let account_publisher =
                StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher.nonce, 0);

            // no initial stackaroos balance -- there is no stackaroos token (yet)
            let _ = StacksChainState::get_account_ft(
                &mut conn,
                &contract_id,
                "stackaroos",
                &recv_principal,
            )
            .unwrap_err();

            // publish contract
            let _ =
                process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();

            // no initial stackaroos balance
            let account_stackaroos_balance = StacksChainState::get_account_ft(
                &mut conn,
                &contract_id,
                "stackaroos",
                &recv_principal,
            )
            .unwrap();
            assert_eq!(account_stackaroos_balance, 0);

            let mut expected_stackaroos_balance = 0;
            let mut expected_nonce = 1;
            let mut expected_recv_nonce = 0;
            let mut expected_payback_stackaroos_balance = 0;
            let mut expected_next_name: u64 = 0;

            for tx_pass in post_conditions_pass.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_pass, false, None).unwrap();
                expected_stackaroos_balance += 100;
                expected_nonce += 1;

                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);
            }

            for tx_pass in post_conditions_pass_payback.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_pass, false, None).unwrap();
                expected_stackaroos_balance -= 100;
                expected_payback_stackaroos_balance += 100;
                expected_recv_nonce += 1;

                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                let account_pub_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &addr_principal,
                )
                .unwrap();
                assert_eq!(
                    account_pub_stackaroos_after,
                    expected_payback_stackaroos_balance
                );

                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);

                let account_recv_publisher_after =
                    StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
                assert_eq!(account_recv_publisher_after.nonce, expected_recv_nonce);
            }

            for tx_pass in post_conditions_pass_nft.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_pass, false, None).unwrap();
                expected_nonce += 1;

                let expected_value =
                    Value::buff_from(expected_next_name.to_be_bytes().to_vec()).unwrap();
                expected_next_name += 1;

                let account_recipient_names_after = StacksChainState::get_account_nft(
                    &mut conn,
                    &contract_id,
                    "names",
                    &expected_value,
                )
                .unwrap();
                assert_eq!(account_recipient_names_after, recv_principal);

                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);
            }

            for tx_fail in post_conditions_fail.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_fail, false, None).unwrap();
                expected_nonce += 1;

                // no change in balance
                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                let account_pub_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &addr_principal,
                )
                .unwrap();
                assert_eq!(
                    account_pub_stackaroos_after,
                    expected_payback_stackaroos_balance
                );

                // but nonce _does_ change
                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);
            }

            for tx_fail in post_conditions_fail_payback.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_fail, false, None).unwrap();
                expected_recv_nonce += 1;

                // no change in balance
                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                let account_pub_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &addr_principal,
                )
                .unwrap();
                assert_eq!(
                    account_pub_stackaroos_after,
                    expected_payback_stackaroos_balance
                );

                // nonce for publisher doesn't change
                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);

                // but nonce _does_ change for reciever, who sent back
                let account_publisher_after =
                    StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
                assert_eq!(account_publisher_after.nonce, expected_recv_nonce);
            }

            for tx_fail in post_conditions_fail_nft.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_fail, false, None).unwrap();
                expected_nonce += 1;

                // nft shouldn't exist -- the nft-mint! should have been rolled back
                let expected_value =
                    Value::buff_from(expected_next_name.to_be_bytes().to_vec()).unwrap();
                expected_next_name += 1;

                let res = StacksChainState::get_account_nft(
                    &mut conn,
                    &contract_id,
                    "names",
                    &expected_value,
                );
                assert!(res.is_err());

                // but nonce _does_ change
                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);
            }

            conn.commit_block();
        }
    }

    #[test]
    fn process_post_conditions_tokens_deny() {
        let contract = "
        (define-data-var bar int 0)
        (define-fungible-token stackaroos)
        (define-non-fungible-token names (buff 50))
        (define-public (send-stackaroos (recipient principal))
          (begin
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok true))
             )
           )
        )
        (define-public (send-name (name (buff 50)) (recipient principal))
          (begin
            (as-contract   ;; used to test post-conditions on contract principal
              (begin (unwrap-panic (nft-mint? names name tx-sender))
                     (unwrap-panic (nft-transfer? names name tx-sender recipient))
                     (ok true))
            )
          )
        )
        (define-public (user-send-stackaroos (recipient principal))
          (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (ok true))
        )
        (define-public (user-send-name (name (buff 50)) (recipient principal))
          (begin
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok true))
        )
        (define-public (send-stackaroos-and-name (name (buff 50)) (recipient principal))
          (begin
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (nft-mint? names name tx-sender))
                      (unwrap-panic (nft-transfer? names name tx-sender recipient))
                      (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok true))
             )
          )
        )
        (define-public (user-send-stackaroos-and-name (name (buff 50)) (recipient principal))
           (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok true))
        )
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let privk_origin = StacksPrivateKey::from_hex(
            "027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01",
        )
        .unwrap();
        let privk_recipient = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();
        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_recv = TransactionAuth::from_p2pkh(&privk_recipient).unwrap();
        let addr_publisher = auth_origin.origin().address_testnet();
        let addr_principal = addr_publisher.to_account_principal();

        let contract_name = ContractName::try_from("hello-world").unwrap();

        let recv_addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk_recipient)],
        )
        .unwrap();
        let recv_principal = recv_addr.to_account_principal();
        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr_publisher.clone()),
            contract_name.clone(),
        );
        let _contract_principal = PrincipalData::Contract(contract_id.clone());

        let asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("stackaroos").unwrap(),
        };

        let name_asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("names").unwrap(),
        };

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_origin.clone(),
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk_origin).unwrap();

        let signed_contract_tx = signer.get_tx().unwrap();

        let mut post_conditions_pass = vec![];
        let mut post_conditions_pass_payback = vec![];
        let mut post_conditions_fail = vec![];
        let mut post_conditions_fail_payback = vec![];
        let mut nonce = 1;
        let mut recv_nonce = 0;
        let mut next_name: u64 = 0;
        let mut next_recv_name: u64 = 0;
        let final_recv_name = 3;

        // mint 100 stackaroos and the name to recv_addr, and set a post-condition for each asset on the contract-principal
        // assert contract sent ==, <=, or >= 100 stackaroos
        for (_i, pass_condition) in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        .enumerate()
        {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_origin.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "send-stackaroos-and-name",
                    vec![name.clone(), Value::Principal(recv_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_tx_fee(0);
            tx_contract_call_both.set_origin_nonce(nonce);

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *pass_condition,
                100,
            ));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                name_asset_info.clone(),
                name.clone(),
                NonfungibleConditionCode::Sent,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // give recv_addr 100 more stackaroos so we can test failure-to-send-back
        {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_origin.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "send-stackaroos-and-name",
                    vec![name, Value::Principal(recv_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Allow;
            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_tx_fee(0);
            tx_contract_call_both.set_origin_nonce(nonce);

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        assert_eq!(next_name, final_recv_name + 1);

        // recv_addr sends 100 stackaroos and name back to addr_publisher.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for (_i, pass_condition) in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        .enumerate()
        {
            let name = Value::buff_from(next_recv_name.to_be_bytes().to_vec()).unwrap();
            next_recv_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_recv.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "user-send-stackaroos-and-name",
                    vec![name.clone(), Value::Principal(addr_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_tx_fee(0);
            tx_contract_call_both.set_origin_nonce(recv_nonce);

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                asset_info.clone(),
                *pass_condition,
                100,
            ));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                name_asset_info.clone(),
                name.clone(),
                NonfungibleConditionCode::Sent,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // mint 100 stackaroos and the name to recv_addr, but neglect to set a fungible post-condition.
        // assert contract sent ==, <=, or >= 100 stackaroos, and that the name was removed from
        // the contract
        for (_i, fail_condition) in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        .enumerate()
        {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_origin.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "send-stackaroos-and-name",
                    vec![name.clone(), Value::Principal(recv_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_tx_fee(0);
            tx_contract_call_both.set_origin_nonce(nonce);

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *fail_condition, 100));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                name_asset_info.clone(),
                name.clone(),
                NonfungibleConditionCode::Sent,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos and the name to recv_addr, but neglect to set a non-fungible post-condition.
        // assert contract sent ==, <=, or >= 100 stackaroos, and that the name was removed from
        // the contract
        for (_i, fail_condition) in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        .enumerate()
        {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_origin.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "send-stackaroos-and-name",
                    vec![name.clone(), Value::Principal(recv_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_tx_fee(0);
            tx_contract_call_both.set_origin_nonce(nonce);

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()),
                asset_info.clone(),
                *fail_condition,
                100,
            ));
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Sent));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // recv_addr sends 100 stackaroos and name back to addr_publisher, but forgets a fungible
        // post-condition.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for (_i, fail_condition) in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        .enumerate()
        {
            let name = Value::buff_from(final_recv_name.to_be_bytes().to_vec()).unwrap();

            let mut tx_contract_call_both = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_recv.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "user-send-stackaroos-and-name",
                    vec![name.clone(), Value::Principal(addr_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_tx_fee(0);
            tx_contract_call_both.set_origin_nonce(recv_nonce);

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *fail_condition, 100));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                name_asset_info.clone(),
                name.clone(),
                NonfungibleConditionCode::Sent,
            ));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_fail_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // never read: next_recv_name -= 3;    // reset

        // recv_addr sends 100 stackaroos and name back to addr_publisher, but forgets a non-fungible
        // post-condition.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for (_i, fail_condition) in [
            FungibleConditionCode::SentEq,
            FungibleConditionCode::SentGe,
            FungibleConditionCode::SentLe,
        ]
        .iter()
        .enumerate()
        {
            let name = Value::buff_from(final_recv_name.to_be_bytes().to_vec()).unwrap();

            let mut tx_contract_call_both = StacksTransaction::new(
                TransactionVersion::Testnet,
                auth_recv.clone(),
                TransactionPayload::new_contract_call(
                    addr_publisher.clone(),
                    "hello-world",
                    "user-send-stackaroos-and-name",
                    vec![name.clone(), Value::Principal(addr_principal.clone())],
                )
                .unwrap(),
            );

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_tx_fee(0);
            tx_contract_call_both.set_origin_nonce(recv_nonce);

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(recv_addr.clone()),
                asset_info.clone(),
                *fail_condition,
                100,
            ));
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Standard(recv_addr.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Sent));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_fail_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            // make sure costs-3 is installed so as-contract will work in epoch 2.1
            let mut conn = chainstate.test_genesis_block_begin_2_1(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            let account_publisher =
                StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher.nonce, 0);

            // no initial stackaroos balance -- there is no stackaroos token (yet)
            let _ = StacksChainState::get_account_ft(
                &mut conn,
                &contract_id,
                "stackaroos",
                &recv_principal,
            )
            .unwrap_err();

            // publish contract
            let _ =
                process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();

            // no initial stackaroos balance
            let account_stackaroos_balance = StacksChainState::get_account_ft(
                &mut conn,
                &contract_id,
                "stackaroos",
                &recv_principal,
            )
            .unwrap();
            assert_eq!(account_stackaroos_balance, 0);

            let mut expected_stackaroos_balance = 0;
            let mut expected_nonce = 1;
            let mut expected_recv_nonce = 0;
            let mut expected_payback_stackaroos_balance = 0;

            for tx_pass in post_conditions_pass.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_pass, false, None).unwrap();
                expected_stackaroos_balance += 100;
                expected_nonce += 1;

                // should have gotten stackaroos
                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                // should have gotten name we created here
                let expected_value = match tx_pass.payload {
                    TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                    _ => panic!("Not a contract call"),
                };

                let account_recipient_names_after = StacksChainState::get_account_nft(
                    &mut conn,
                    &contract_id,
                    "names",
                    &expected_value,
                )
                .unwrap();
                assert_eq!(account_recipient_names_after, recv_principal);

                // sender's nonce increased
                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);
            }

            for tx_pass in post_conditions_pass_payback.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_pass, false, None).unwrap();
                expected_stackaroos_balance -= 100;
                expected_payback_stackaroos_balance += 100;
                expected_recv_nonce += 1;

                // recipient should have sent stackaroos
                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                // publisher should have gotten them
                let account_pub_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &addr_principal,
                )
                .unwrap();
                assert_eq!(
                    account_pub_stackaroos_after,
                    expected_payback_stackaroos_balance
                );

                // should have gotten name we created here
                let expected_value = match tx_pass.payload {
                    TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                    _ => panic!("Not a contract call"),
                };

                let account_publisher_names_after = StacksChainState::get_account_nft(
                    &mut conn,
                    &contract_id,
                    "names",
                    &expected_value,
                )
                .unwrap();
                assert_eq!(account_publisher_names_after, addr_principal);

                // no change in nonce
                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);

                // receiver nonce changed
                let account_recv_publisher_after =
                    StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
                assert_eq!(account_recv_publisher_after.nonce, expected_recv_nonce);
            }

            for tx_fail in post_conditions_fail.iter() {
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_fail, false, None).unwrap();
                expected_nonce += 1;

                // no change in balance
                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                let account_pub_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &addr_principal,
                )
                .unwrap();
                assert_eq!(
                    account_pub_stackaroos_after,
                    expected_payback_stackaroos_balance
                );

                // new names the transaction tried to create don't exist -- transaction was aborted
                let expected_value = match tx_fail.payload {
                    TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                    _ => panic!("Not a contract call"),
                };

                let res = StacksChainState::get_account_nft(
                    &mut conn,
                    &contract_id,
                    "names",
                    &expected_value,
                );
                assert!(res.is_err());

                // but nonce _does_ change
                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);
            }

            for tx_fail in post_conditions_fail_payback.iter() {
                eprintln!("tx fail {tx_fail:?}");
                let (_fee, _) =
                    process_transaction_for_test(&mut conn, tx_fail, false, None).unwrap();
                expected_recv_nonce += 1;

                // no change in balance
                let account_recipient_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &recv_principal,
                )
                .unwrap();
                assert_eq!(
                    account_recipient_stackaroos_after,
                    expected_stackaroos_balance
                );

                let account_pub_stackaroos_after = StacksChainState::get_account_ft(
                    &mut conn,
                    &contract_id,
                    "stackaroos",
                    &addr_principal,
                )
                .unwrap();
                assert_eq!(
                    account_pub_stackaroos_after,
                    expected_payback_stackaroos_balance
                );

                // name we tried to send back is still owned by recv_addr
                let expected_value = match tx_fail.payload {
                    TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                    _ => panic!("Not a contract call"),
                };

                // name remains owned by recv_addr
                let res = StacksChainState::get_account_nft(
                    &mut conn,
                    &contract_id,
                    "names",
                    &expected_value,
                );
                assert!(res.is_ok());
                assert_eq!(res.unwrap(), recv_principal);

                // nonce for publisher doesn't change
                let account_publisher_after = StacksChainState::get_account(
                    &mut conn,
                    &addr_publisher.to_account_principal(),
                );
                assert_eq!(account_publisher_after.nonce, expected_nonce);

                // but nonce _does_ change for reciever, who sent back
                let account_publisher_after =
                    StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
                assert_eq!(account_publisher_after.nonce, expected_recv_nonce);
            }

            conn.commit_block();
        }
    }

    #[test]
    fn process_post_conditions_tokens_deny_2097() {
        let privk_origin = StacksPrivateKey::from_hex(
            "027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01",
        )
        .unwrap();
        let privk_recipient = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();
        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_recv = TransactionAuth::from_p2pkh(&privk_recipient).unwrap();
        let addr_publisher = auth_origin.origin().address_testnet();
        let addr_principal = addr_publisher.to_account_principal();

        let contract = "
(define-constant owner 'ST3X2W2SH9XQZRHHYJ21KWGTT1N6WX3D48K1NSTPE)
(define-fungible-token connect-token)
(begin (ft-mint? connect-token u100000000 owner))
(define-public (transfer (recipient principal) (amount uint))
  (ok (ft-transfer? connect-token amount tx-sender recipient)))
"
        .to_string();

        let contract_name = ContractName::try_from("hello-world").unwrap();

        let recv_addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk_recipient)],
        )
        .unwrap();
        let recv_principal = recv_addr.to_account_principal();
        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr_publisher.clone()),
            contract_name.clone(),
        );
        let _contract_principal = PrincipalData::Contract(contract_id);

        let asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name,
            asset_name: ClarityName::try_from("connect-token").unwrap(),
        };

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_origin.clone(),
            TransactionPayload::new_smart_contract("hello-world", &contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk_origin).unwrap();

        let signed_contract_tx = signer.get_tx().unwrap();

        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_origin,
            TransactionPayload::new_contract_call(
                addr_publisher.clone(),
                "hello-world",
                "transfer",
                vec![Value::Principal(recv_principal), Value::UInt(10)],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(0);
        tx_contract_call.set_origin_nonce(1);

        tx_contract_call.post_condition_mode = TransactionPostConditionMode::Deny;
        tx_contract_call.add_post_condition(TransactionPostCondition::Fungible(
            PostConditionPrincipal::Origin,
            asset_info,
            FungibleConditionCode::SentEq,
            10,
        ));

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk_origin).unwrap();
        let contract_call_tx = signer.get_tx().unwrap();

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            // publish contract
            let _ =
                process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();

            let (_fee, receipt) =
                process_transaction_for_test(&mut conn, &contract_call_tx, false, None).unwrap();

            assert!(receipt.post_condition_aborted);
            assert_eq!(receipt.result.to_string(), "(ok (err u1))");

            conn.commit_block();
        }
    }

    fn make_account(principal: &PrincipalData, nonce: u64, balance: u128) -> StacksAccount {
        let stx_balance = STXBalance::initial(balance);
        StacksAccount {
            principal: principal.clone(),
            nonce,
            stx_balance,
        }
    }

    #[test]
    fn test_check_postconditions_multiple_fts() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = addr.to_account_principal();
        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
        let contract_addr = StacksAddress::new(1, Hash160([0x01; 20])).unwrap();

        let asset_info_1 = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("test-asset-1").unwrap(),
        };

        let asset_info_2 = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("test-asset-2").unwrap(),
        };

        let asset_info_3 = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("test-asset-3").unwrap(),
        };

        let asset_id_1 = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::from(asset_info_1.contract_address.clone()),
                asset_info_1.contract_name.clone(),
            ),
            asset_name: asset_info_1.asset_name.clone(),
        };

        let asset_id_2 = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::from(asset_info_2.contract_address.clone()),
                asset_info_2.contract_name.clone(),
            ),
            asset_name: asset_info_2.asset_name.clone(),
        };

        let _asset_id_3 = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::from(asset_info_3.contract_address.clone()),
                asset_info_3.contract_name.clone(),
            ),
            asset_name: asset_info_3.asset_name.clone(),
        };

        // multi-ft
        let mut ft_transfer_2 = AssetMap::new();
        ft_transfer_2
            .add_token_transfer(&origin, asset_id_1, 123)
            .unwrap();
        ft_transfer_2
            .add_token_transfer(&origin, asset_id_2, 123)
            .unwrap();

        let tests = vec![
            // no-postconditions in allow mode
            (
                true,
                vec![],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in allow mode
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // three post-conditions on origin in allow mode, one with sending 0 tokens
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
            // an unchecked address and a vacuous amount
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in allow mode, explicit origin
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // three post-conditions on origin in allow mode, one with sending 0 tokens, explicit
            // origin
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
            // an unchecked address and a vacuous amount, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // no-postconditions in deny mode
            (
                false,
                vec![],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in allow mode
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // three post-conditions on origin in allow mode, one with sending 0 tokens
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
            // an unchecked address and a vacuous amount
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Origin,
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in allow mode, explicit origin
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // three post-conditions on origin in allow mode, one with sending 0 tokens, explicit
            // origin
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
            // an unchecked address and a vacuous amount, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2.clone(),
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_1.clone(),
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_3,
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(recv_addr.clone()),
                        asset_info_1,
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::Fungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info_2,
                        FungibleConditionCode::SentGt,
                        122,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
        ];

        for test in tests {
            let expected_result = test.0;
            let post_conditions = &test.1;
            let mode = &test.2;
            let origin = &test.3;

            let result = check_transaction_postconditions_for_test(
                post_conditions,
                mode,
                origin,
                &ft_transfer_2,
                StacksEpochId::latest(),
                Txid([0; 32]),
            )
            .unwrap();
            assert_eq!(
                result.is_none(),
                expected_result,
                "test failed:\nasset map: {ft_transfer_2:?}\nscenario: {test:?}"
            );
        }
    }

    #[test]
    fn test_check_postconditions_multiple_nfts() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = addr.to_account_principal();
        let _recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
        let contract_addr = StacksAddress::new(1, Hash160([0x01; 20])).unwrap();

        let asset_info = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("test-asset").unwrap(),
        };

        let asset_id = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::from(asset_info.contract_address.clone()),
                asset_info.contract_name.clone(),
            ),
            asset_name: asset_info.asset_name.clone(),
        };

        // multi-nft transfer
        let mut nft_transfer_2 = AssetMap::new();
        nft_transfer_2.add_asset_transfer(&origin, asset_id.clone(), Value::Int(1));
        nft_transfer_2.add_asset_transfer(&origin, asset_id, Value::Int(2));

        let tests = vec![
            // no post-conditions in allow mode
            (
                true,
                vec![],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in allow mode
            (
                true,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // post-condition on a non-sent asset
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(3),
                        NonfungibleConditionCode::NotSent,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in allow mode, explicit origin
            (
                true,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            (
                true,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // post-condition on a non-sent asset, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(3),
                        NonfungibleConditionCode::NotSent,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // no post-conditions in deny mode
            (
                false,
                vec![],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in deny mode
            (
                false,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // post-condition on a non-sent asset
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Origin,
                        asset_info.clone(),
                        Value::Int(3),
                        NonfungibleConditionCode::NotSent,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // one post-condition on origin in deny mode, explicit origin
            (
                false,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            (
                false,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
            // two post-conditions on origin in allow mode, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ),
            // post-condition on a non-sent asset, explicit origin
            (
                true,
                vec![
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(1),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info.clone(),
                        Value::Int(2),
                        NonfungibleConditionCode::Sent,
                    ),
                    TransactionPostCondition::Nonfungible(
                        PostConditionPrincipal::Standard(addr.clone()),
                        asset_info,
                        Value::Int(3),
                        NonfungibleConditionCode::NotSent,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ),
        ];

        for test in tests.iter() {
            let expected_result = test.0;
            let post_conditions = &test.1;
            let mode = &test.2;
            let origin = &test.3;

            let result = check_transaction_postconditions_for_test(
                post_conditions,
                mode,
                origin,
                &nft_transfer_2,
                StacksEpochId::latest(),
                Txid([0; 32]),
            )
            .unwrap();
            assert_eq!(
                result.is_none(),
                expected_result,
                "test failed:\nasset map: {nft_transfer_2:?}\nscenario: {test:?}"
            );
        }
    }

    #[test]
    fn test_check_postconditions_originator_mode_coverage() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let origin_addr = auth.origin().address_testnet();
        let origin = origin_addr.to_account_principal();
        let other_addr = StacksAddress::new(1, Hash160([0xee; 20])).unwrap();
        let other = other_addr.to_account_principal();

        let mut mixed_stx_transfer = AssetMap::new();
        mixed_stx_transfer.add_stx_transfer(&origin, 50).unwrap();
        mixed_stx_transfer.add_stx_transfer(&other, 75).unwrap();

        let tests = vec![
            // in originator mode, uncovered transfers from non-origin principals are permitted
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    50,
                )],
                TransactionPostConditionMode::Originator,
            ),
            // in originator mode, uncovered transfers from origin are forbidden
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(other_addr.clone()),
                    FungibleConditionCode::SentEq,
                    75,
                )],
                TransactionPostConditionMode::Originator,
            ),
            // in originator mode, covering both should pass
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        50,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Standard(other_addr.clone()),
                        FungibleConditionCode::SentEq,
                        75,
                    ),
                ],
                TransactionPostConditionMode::Originator,
            ),
            // sanity check: deny mode still requires all principals to be covered
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    50,
                )],
                TransactionPostConditionMode::Deny,
            ),
        ];

        for (expected_result, post_conditions, mode) in tests {
            let result = check_transaction_postconditions_for_test(
                &post_conditions,
                &mode,
                &make_account(&origin, 1, 123),
                &mixed_stx_transfer,
                StacksEpochId::latest(),
                Txid([0; 32]),
            )
            .unwrap();
            assert_eq!(
                result.is_none(),
                expected_result,
                "test failed:\nasset map: {mixed_stx_transfer:?}\nscenario: {post_conditions:?} mode={mode:?}"
            );
        }
    }

    #[test]
    fn test_check_postconditions_staking() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let origin_addr = auth.origin().address_testnet();
        let origin = origin_addr.to_account_principal();

        // Asset map in which the origin staked 100 uSTX.
        let mut stacked = AssetMap::new();
        stacked
            .add_stacking(&origin, 100, StacksEpochId::Epoch40)
            .unwrap();

        // (expected_pass, post_conditions, mode, epoch)
        let tests = vec![
            // Allow mode: uncovered stacking is permitted.
            (
                true,
                vec![],
                TransactionPostConditionMode::Allow,
                StacksEpochId::Epoch40,
            ),
            // Deny mode: uncovered stacking is forbidden.
            (
                false,
                vec![],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch40,
            ),
            // Deny mode with a covering allowance (stacked <= limit) passes.
            (
                true,
                vec![TransactionPostCondition::Staking(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    100,
                )],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch40,
            ),
            // A limit that is too small (stacked > limit) fails the condition.
            (
                false,
                vec![TransactionPostCondition::Staking(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    99,
                )],
                TransactionPostConditionMode::Allow,
                StacksEpochId::Epoch40,
            ),
            // SentEq matching the exact stacked amount passes even in Deny mode.
            (
                true,
                vec![TransactionPostCondition::Staking(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    100,
                )],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch40,
            ),
            // Before epoch 4.0, stacking is not enforced even in Deny mode.
            (
                true,
                vec![],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch33,
            ),
        ];

        for (expected_pass, post_conditions, mode, epoch) in tests {
            let result = check_transaction_postconditions_for_test(
                &post_conditions,
                &mode,
                &make_account(&origin, 1, 123),
                &stacked,
                epoch,
                Txid([0; 32]),
            )
            .unwrap();
            assert_eq!(
                result.is_none(),
                expected_pass,
                "test failed:\nscenario: {post_conditions:?} mode={mode:?} epoch={epoch:?}"
            );
        }
    }

    #[test]
    fn test_check_postconditions_pox() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let origin_addr = auth.origin().address_testnet();
        let origin = origin_addr.to_account_principal();

        // Asset map in which the origin performed a position-altering PoX action.
        let mut pox_acted = AssetMap::new();
        pox_acted.add_pox_action(&origin);

        let forbid_pox = || {
            TransactionPostCondition::Pox(
                PostConditionPrincipal::Origin,
                PoxConditionCode::NotPerformed,
            )
        };
        let allow_pox = || {
            TransactionPostCondition::Pox(
                PostConditionPrincipal::Origin,
                PoxConditionCode::MaybePerformed,
            )
        };
        let require_pox = || {
            TransactionPostCondition::Pox(
                PostConditionPrincipal::Origin,
                PoxConditionCode::Performed,
            )
        };

        // (expected_pass, post_conditions, mode, epoch)
        let tests = vec![
            // Allow mode: uncovered unstaking is permitted.
            (
                true,
                vec![],
                TransactionPostConditionMode::Allow,
                StacksEpochId::Epoch40,
            ),
            // Deny mode: uncovered unstaking is forbidden.
            (
                false,
                vec![],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch40,
            ),
            // `MaybeUnstaked` opts in, so an unstake passes even in Deny mode.
            (
                true,
                vec![allow_pox()],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch40,
            ),
            // `Unstaked` (must) is satisfied since an unstake occurred.
            (
                true,
                vec![require_pox()],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch40,
            ),
            // `NotUnstaked` fails in allow mode because an unstake occurred.
            (
                false,
                vec![forbid_pox()],
                TransactionPostConditionMode::Allow,
                StacksEpochId::Epoch40,
            ),
            // Before epoch 4.0, unstaking is not enforced even in Deny mode.
            (
                true,
                vec![],
                TransactionPostConditionMode::Deny,
                StacksEpochId::Epoch33,
            ),
        ];

        for (expected_pass, post_conditions, mode, epoch) in tests {
            let result = check_transaction_postconditions_for_test(
                &post_conditions,
                &mode,
                &make_account(&origin, 1, 123),
                &pox_acted,
                epoch,
                Txid([0; 32]),
            )
            .unwrap();
            assert_eq!(
                result.is_none(),
                expected_pass,
                "test failed:\nscenario: {post_conditions:?} mode={mode:?} epoch={epoch:?}"
            );
        }

        // `NotUnstaked` passes when no unstake occurred.
        let empty = AssetMap::new();
        let result = check_transaction_postconditions_for_test(
            &[forbid_pox()],
            &TransactionPostConditionMode::Allow,
            &make_account(&origin, 1, 123),
            &empty,
            StacksEpochId::Epoch40,
            Txid([0; 32]),
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_check_postconditions_nft_maybe_sent() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let origin_addr = auth.origin().address_testnet();
        let origin = origin_addr.to_account_principal();
        let contract_addr = StacksAddress::new(1, Hash160([0x01; 20])).unwrap();

        let asset_info = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("test-asset").unwrap(),
        };

        let asset_id = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::from(asset_info.contract_address.clone()),
                asset_info.contract_name.clone(),
            ),
            asset_name: asset_info.asset_name.clone(),
        };

        let mut nft_sent_value_1 = AssetMap::new();
        nft_sent_value_1.add_asset_transfer(&origin, asset_id.clone(), Value::Int(1));

        let nft_not_sent = AssetMap::new();

        let mut nft_sent_value_2 = AssetMap::new();
        nft_sent_value_2.add_asset_transfer(&origin, asset_id, Value::Int(2));

        let tests = vec![
            // MAY-SEND should pass if the specified NFT is sent
            (
                true,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::MaybeSent,
                )],
                TransactionPostConditionMode::Deny,
                &nft_sent_value_1,
            ),
            // MAY-SEND should also pass if the specified NFT is not sent
            (
                true,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::MaybeSent,
                )],
                TransactionPostConditionMode::Deny,
                &nft_not_sent,
            ),
            // MAY-SEND covers only the specific NFT instance (value 1 does not cover value 2)
            (
                false,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::MaybeSent,
                )],
                TransactionPostConditionMode::Deny,
                &nft_sent_value_2,
            ),
            // allow mode remains permissive regardless
            (
                true,
                vec![TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info,
                    Value::Int(1),
                    NonfungibleConditionCode::MaybeSent,
                )],
                TransactionPostConditionMode::Allow,
                &nft_sent_value_2,
            ),
        ];

        for (expected_result, post_conditions, mode, asset_map) in tests {
            let result = check_transaction_postconditions_for_test(
                &post_conditions,
                &mode,
                &make_account(&origin, 1, 123),
                asset_map,
                StacksEpochId::latest(),
                Txid([0; 32]),
            )
            .unwrap();
            assert_eq!(
                result.is_none(),
                expected_result,
                "test failed:\nasset map: {asset_map:?}\nscenario: {post_conditions:?} mode={mode:?}"
            );
        }
    }

    proptest! {
        #[tag(t_prop)]
        #[test]
        fn proptest_check_postconditions_originator_mode_coverage(
            origin_sent in 1u64..10_000,
            other_sent in 1u64..10_000,
            include_origin_check in any::<bool>(),
            include_other_check in any::<bool>(),
            origin_check_matches in any::<bool>(),
        ) {
            let privk = StacksPrivateKey::from_hex(
                "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
            )
            .unwrap();
            let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
            let origin_addr = auth.origin().address_testnet();
            let origin = origin_addr.to_account_principal();
            let other_addr = StacksAddress::new(1, Hash160([0xee; 20])).unwrap();
            let other = other_addr.to_account_principal();

            let mut asset_map = AssetMap::new();
            asset_map
                .add_stx_transfer(&origin, u128::from(origin_sent))
                .unwrap();
            asset_map
                .add_stx_transfer(&other, u128::from(other_sent))
                .unwrap();

            let mut post_conditions = vec![];
            if include_origin_check {
                let checked_amt = if origin_check_matches {
                    origin_sent
                } else {
                    origin_sent.saturating_add(1)
                };
                post_conditions.push(TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    checked_amt,
                ));
            }
            if include_other_check {
                post_conditions.push(TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(other_addr.clone()),
                    FungibleConditionCode::SentEq,
                    other_sent,
                ));
            }

            let result = check_transaction_postconditions_for_test(
                &post_conditions,
                &TransactionPostConditionMode::Originator,
                &make_account(&origin, 1, 123),
                &asset_map,
                StacksEpochId::latest(),
                Txid([0; 32]),
            )
            .unwrap();

            let expected_pass = include_origin_check && origin_check_matches;
            prop_assert_eq!(result.is_none(), expected_pass);
        }
    }

    proptest! {
        #[tag(t_prop)]
        #[test]
        fn proptest_check_postconditions_nft_maybe_sent_variety(
            checked_id in 0u16..500,
            moved_id in 0u16..500,
            move_asset in any::<bool>(),
            mode_is_allow in any::<bool>(),
        ) {
            let privk = StacksPrivateKey::from_hex(
                "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
            )
            .unwrap();
            let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
            let origin_addr = auth.origin().address_testnet();
            let origin = origin_addr.to_account_principal();

            let asset_info = AssetInfo {
                contract_address: StacksAddress::new(1, Hash160([0x01; 20])).unwrap(),
                contract_name: ContractName::try_from("hello-world").unwrap(),
                asset_name: ClarityName::try_from("test-asset").unwrap(),
            };
            let asset_id = AssetIdentifier {
                contract_identifier: QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(asset_info.contract_address.clone()),
                    asset_info.contract_name.clone(),
                ),
                asset_name: asset_info.asset_name.clone(),
            };

            let mut asset_map = AssetMap::new();
            if move_asset {
                asset_map.add_asset_transfer(
                    &origin,
                    asset_id,
                    Value::UInt(u128::from(moved_id)),
                );
            }

            let mode = if mode_is_allow {
                TransactionPostConditionMode::Allow
            } else {
                TransactionPostConditionMode::Deny
            };

            let post_conditions = vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info,
                Value::UInt(u128::from(checked_id)),
                NonfungibleConditionCode::MaybeSent,
            )];

            let result = check_transaction_postconditions_for_test(
                &post_conditions,
                &mode,
                &make_account(&origin, 1, 123),
                &asset_map,
                StacksEpochId::latest(),
                Txid([0; 32]),
            )
            .unwrap();

            let expected_pass = if mode_is_allow {
                true
            } else {
                !move_asset || checked_id == moved_id
            };
            prop_assert_eq!(result.is_none(), expected_pass);
        }
    }

    #[test]
    fn test_check_postconditions_stx() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = addr.to_account_principal();
        let _recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        // stx-transfer for 123 microstx
        let mut stx_asset_map = AssetMap::new();
        stx_asset_map.add_stx_transfer(&origin, 123).unwrap();

        // stx-burn for 123 microstx
        let mut stx_burn_asset_map = AssetMap::new();
        stx_burn_asset_map.add_stx_burn(&origin, 123).unwrap();

        // stx-transfer and stx-burn for a total of 123 microstx
        let mut stx_transfer_burn_asset_map = AssetMap::new();
        stx_transfer_burn_asset_map
            .add_stx_transfer(&origin, 100)
            .unwrap();
        stx_transfer_burn_asset_map
            .add_stx_burn(&origin, 23)
            .unwrap();

        let tests = vec![
            // no post-conditions in allow mode
            (
                true,
                vec![],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions on origin in allow mode
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions with an explicitly-set address in allow mode
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions with an unrelated contract address in allow mode
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentEq,
                    0,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLe,
                    0,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentGe,
                    0,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLt,
                    1,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions with both the origin and an unrelated contract address in allow mode
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions that fail since the amount is wrong
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    124,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    122,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGe,
                    124,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLt,
                    122,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGt,
                    124,
                )],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            // no post-conditions in deny mode (should fail)
            (
                false,
                vec![],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            // post-conditions on origin in deny mode (should all pass since origin is specified
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions with an explicitly-set address in deny mode (should all pass since
            // address matches the address in the asset map)
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentEq,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentLe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentGe,
                    123,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentLt,
                    124,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(addr.clone()),
                    FungibleConditionCode::SentGt,
                    122,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions with an unrelated contract address in allow mode, with check on
            // origin (should all pass)
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Allow,
                make_account(&origin, 1, 123),
            ), // should fail
            // post-conditions with an unrelated contract address in deny mode (should all fail
            // since stx-transfer isn't covered)
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentEq,
                    0,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLe,
                    0,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentGe,
                    0,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLt,
                    1,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            // post-conditions with an unrelated contract address in deny mode, with check on
            // origin (should all pass)
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            // post-conditions with both the origin and an unrelated contract address in deny mode (should all pass)
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentEq,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentEq,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentLe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentGe,
                        0,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentGe,
                        123,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            (
                true,
                vec![
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Contract(
                            addr.clone(),
                            ContractName::try_from("hello-world").unwrap(),
                        ),
                        FungibleConditionCode::SentLt,
                        1,
                    ),
                    TransactionPostCondition::STX(
                        PostConditionPrincipal::Origin,
                        FungibleConditionCode::SentLt,
                        124,
                    ),
                ],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should pass
            // post-conditions that fail since the amount is wrong, even though all principals are
            // covered
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    124,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    122,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGe,
                    124,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLt,
                    122,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
            (
                false,
                vec![TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGt,
                    124,
                )],
                TransactionPostConditionMode::Deny,
                make_account(&origin, 1, 123),
            ), // should fail
        ];

        for asset_map in &[
            &stx_asset_map,
            &stx_burn_asset_map,
            &stx_transfer_burn_asset_map,
        ] {
            for test in tests.iter() {
                let expected_result = test.0;
                let post_conditions = &test.1;
                let post_condition_mode = &test.2;
                let origin_account = &test.3;

                let result = check_transaction_postconditions_for_test(
                    post_conditions,
                    post_condition_mode,
                    origin_account,
                    asset_map,
                    StacksEpochId::latest(),
                    Txid([0; 32]),
                )
                .unwrap();
                assert_eq!(
                    result.is_none(),
                    expected_result,
                    "test failed:\nasset map: {asset_map:?}\nscenario: {test:?}"
                );
            }
        }
    }

    #[test]
    fn process_smart_contract_fee_check() {
        let contract = r#"
        (define-public (send-stx (amount uint) (recipient principal))
            (stx-transfer? amount tx-sender recipient))
        "#;

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let mut tx_contract_create = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract_create.chain_id = 0x80000000;
        tx_contract_create.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_create);
        signer.sign_origin(&privk).unwrap();

        let signed_contract_tx = signer.get_tx().unwrap();

        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_contract_call(
                addr.clone(),
                "hello-world",
                "send-stx",
                vec![
                    Value::UInt(1000000000),
                    Value::Principal(PrincipalData::from(
                        StacksAddress::from_string("ST1H1B54MY50RMBRRKS7GV2ZWG79RZ1RQ1ETW4E01")
                            .unwrap(),
                    )),
                ],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(1);
        tx_contract_call.set_origin_nonce(1);
        tx_contract_call.post_condition_mode = TransactionPostConditionMode::Allow;

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk).unwrap();

        let signed_contract_call_tx = signer.get_tx().unwrap();

        // in epoch 2.05 and earlier, this fails because we debit the fee _after_ we run the tx,
        // which leads to an InvalidFee error
        for (dbi, burn_db) in PRE_21_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );
            let (fee, _) =
                process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
            let err =
                process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None)
                    .unwrap_err();

            conn.commit_block();

            assert_eq!(fee, 0);
            assert!(matches!(err, Error::InvalidFee), "{err:?}");
        }

        // in epoch 2.1, this passes, since we debit the fee _before_ we run the tx, and then the
        // call to stx-transfer? fails.
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );

        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None).unwrap();

        assert_eq!(fee, 1);
        assert_eq!(
            StacksChainState::get_account(&mut conn, &addr.into())
                .stx_balance
                .get_available_balance_at_burn_block(0, 0, 0, 0, 0)
                .unwrap(),
            (1000000000 - fee) as u128
        );

        conn.commit_block();
    }

    fn make_signed_microblock(
        block_privk: &StacksPrivateKey,
        tx_privk: &StacksPrivateKey,
        parent_block: BlockHeaderHash,
        seq: u16,
    ) -> StacksMicroblock {
        // make transaction
        let contract = r#"
        (define-public (send-stx (amount uint) (recipient principal))
            (stx-transfer? amount tx-sender recipient))
        "#;

        let auth = TransactionAuth::from_p2pkh(tx_privk).unwrap();
        let addr = auth.origin().address_testnet();

        let mut rng = rand::thread_rng();

        let mut tx_contract_create = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract(
                &format!("hello-world-{}", &rng.gen::<u32>()),
                contract,
                None,
            )
            .unwrap(),
        );

        tx_contract_create.chain_id = 0x80000000;
        tx_contract_create.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_create);
        signer.sign_origin(tx_privk).unwrap();

        let signed_contract_tx = signer.get_tx().unwrap();

        // make block
        let txs = vec![signed_contract_tx];
        let txid_vecs: Vec<_> = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();
        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();

        let mut mblock = StacksMicroblock {
            header: StacksMicroblockHeader {
                version: 0x12,
                sequence: seq,
                prev_block: parent_block,
                tx_merkle_root,
                signature: MessageSignature([0u8; 65]),
            },
            txs,
        };
        mblock.sign(block_privk).unwrap();
        mblock
    }

    #[test]
    fn process_poison_microblock_same_block() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let block_privk = StacksPrivateKey::from_hex(
            "2f90f1b148207a110aa58d1b998510407420d7a8065d4fdfc0bbe22c5d9f1c6a01",
        )
        .unwrap();

        let block_pubkh =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&block_privk));

        let reporter_privk = StacksPrivateKey::from_hex(
            "e606e944014b2a9788d0e3c8defaf6bc44b1e3ab881aaba32faa6e32002b7e1f01",
        )
        .unwrap();
        let reporter_addr = TransactionAuth::from_p2pkh(&reporter_privk)
            .unwrap()
            .origin()
            .address_testnet();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            StacksChainState::insert_microblock_pubkey_hash(&mut conn, 1, &block_pubkh).unwrap();

            let height_opt =
                StacksChainState::has_microblock_pubkey_hash(&mut conn, &block_pubkh).unwrap();
            assert_eq!(height_opt.unwrap(), 1);

            // make poison
            let mblock_1 =
                make_signed_microblock(&block_privk, &privk, BlockHeaderHash([0x11; 32]), 123);
            let mblock_2 =
                make_signed_microblock(&block_privk, &privk, BlockHeaderHash([0x11; 32]), 123);
            assert!(mblock_1 != mblock_2);

            // report poison (in the same block)
            let mut tx_poison_microblock = StacksTransaction::new(
                TransactionVersion::Testnet,
                TransactionAuth::from_p2pkh(&reporter_privk).unwrap(),
                TransactionPayload::PoisonMicroblock(
                    mblock_1.header.clone(),
                    mblock_2.header.clone(),
                ),
            );

            tx_poison_microblock.chain_id = 0x80000000;
            tx_poison_microblock.set_tx_fee(0);

            let mut signer = StacksTransactionSigner::new(&tx_poison_microblock);
            signer.sign_origin(&reporter_privk).unwrap();
            let signed_tx_poison_microblock = signer.get_tx().unwrap();

            // process it!
            let (fee, receipt) =
                process_transaction_for_test(&mut conn, &signed_tx_poison_microblock, false, None)
                    .unwrap();

            // there must be a poison record for this microblock, from the reporter, for the microblock
            // sequence.
            let report_opt = StacksChainState::get_poison_microblock_report(&mut conn, 1).unwrap();
            assert_eq!(report_opt.unwrap(), (reporter_addr.clone(), 123));

            // result must encode poison information
            let result_data = receipt.result.expect_tuple().unwrap();

            let height = result_data
                .get("block_height")
                .unwrap()
                .to_owned()
                .expect_u128()
                .unwrap();
            let mblock_pubkh = result_data
                .get("microblock_pubkey_hash")
                .unwrap()
                .to_owned()
                .expect_buff(20)
                .unwrap();
            let reporter = result_data
                .get("reporter")
                .unwrap()
                .to_owned()
                .expect_principal()
                .unwrap();
            let seq = result_data
                .get("sequence")
                .unwrap()
                .to_owned()
                .expect_u128()
                .unwrap();

            assert_eq!(height, 1);
            assert_eq!(mblock_pubkh, block_pubkh.0.to_vec());
            assert_eq!(seq, 123);
            assert_eq!(reporter, reporter_addr.to_account_principal());

            conn.commit_block();
        }
    }

    #[test]
    fn process_poison_microblock_invalid_transaction() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let block_privk = StacksPrivateKey::from_hex(
            "2f90f1b148207a110aa58d1b998510407420d7a8065d4fdfc0bbe22c5d9f1c6a01",
        )
        .unwrap();

        let block_pubkh =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&block_privk));

        let reporter_privk = StacksPrivateKey::from_hex(
            "e606e944014b2a9788d0e3c8defaf6bc44b1e3ab881aaba32faa6e32002b7e1f01",
        )
        .unwrap();
        let reporter_addr = TransactionAuth::from_p2pkh(&reporter_privk)
            .unwrap()
            .origin()
            .address_testnet();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            StacksChainState::insert_microblock_pubkey_hash(&mut conn, 1, &block_pubkh).unwrap();

            let height_opt =
                StacksChainState::has_microblock_pubkey_hash(&mut conn, &block_pubkh).unwrap();
            assert_eq!(height_opt.unwrap(), 1);

            // make poison, but for an unknown microblock fork
            let mblock_1 = make_signed_microblock(&privk, &privk, BlockHeaderHash([0x11; 32]), 123);
            let mblock_2 = make_signed_microblock(&privk, &privk, BlockHeaderHash([0x11; 32]), 123);
            assert!(mblock_1 != mblock_2);

            // report poison (in the same block)
            let mut tx_poison_microblock = StacksTransaction::new(
                TransactionVersion::Testnet,
                TransactionAuth::from_p2pkh(&reporter_privk).unwrap(),
                TransactionPayload::PoisonMicroblock(
                    mblock_1.header.clone(),
                    mblock_2.header.clone(),
                ),
            );

            tx_poison_microblock.chain_id = 0x80000000;
            tx_poison_microblock.set_tx_fee(0);

            let mut signer = StacksTransactionSigner::new(&tx_poison_microblock);
            signer.sign_origin(&reporter_privk).unwrap();
            let signed_tx_poison_microblock = signer.get_tx().unwrap();

            // should fail to process -- the transaction is invalid if it doesn't point to a known
            // microblock pubkey hash.
            let err =
                process_transaction_for_test(&mut conn, &signed_tx_poison_microblock, false, None)
                    .unwrap_err();
            let Error::ClarityError(ClarityError::BadTransaction(msg)) = &err else {
                panic!("Unexpected error type");
            };
            assert!(msg.find("never seen in this fork").is_some());
            conn.commit_block();
        }
    }

    #[test]
    fn process_poison_microblock_multiple_same_block() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let block_privk = StacksPrivateKey::from_hex(
            "2f90f1b148207a110aa58d1b998510407420d7a8065d4fdfc0bbe22c5d9f1c6a01",
        )
        .unwrap();

        let block_pubkh =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&block_privk));

        let reporter_privk_1 = StacksPrivateKey::from_hex(
            "e606e944014b2a9788d0e3c8defaf6bc44b1e3ab881aaba32faa6e32002b7e1f01",
        )
        .unwrap();
        let reporter_privk_2 = StacksPrivateKey::from_hex(
            "ca7ba28b9604418413a16d74e7dbe5c3e0012281183f590940bab0208c40faee01",
        )
        .unwrap();
        let reporter_addr_1 = TransactionAuth::from_p2pkh(&reporter_privk_1)
            .unwrap()
            .origin()
            .address_testnet();
        let reporter_addr_2 = TransactionAuth::from_p2pkh(&reporter_privk_2)
            .unwrap()
            .origin()
            .address_testnet();

        for (dbi, burn_db) in ALL_BURN_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            StacksChainState::insert_microblock_pubkey_hash(&mut conn, 1, &block_pubkh).unwrap();

            let height_opt =
                StacksChainState::has_microblock_pubkey_hash(&mut conn, &block_pubkh).unwrap();
            assert_eq!(height_opt.unwrap(), 1);

            // make two sets of poisons
            let mblock_1_1 =
                make_signed_microblock(&block_privk, &privk, BlockHeaderHash([0x11; 32]), 123);
            let mblock_1_2 =
                make_signed_microblock(&block_privk, &privk, BlockHeaderHash([0x11; 32]), 123);
            assert!(mblock_1_1 != mblock_1_2);

            // report poison (in the same block)
            let mut tx_poison_microblock_1 = StacksTransaction::new(
                TransactionVersion::Testnet,
                TransactionAuth::from_p2pkh(&reporter_privk_1).unwrap(),
                TransactionPayload::PoisonMicroblock(
                    mblock_1_1.header.clone(),
                    mblock_1_2.header.clone(),
                ),
            );

            tx_poison_microblock_1.chain_id = 0x80000000;
            tx_poison_microblock_1.set_tx_fee(0);

            let mut signer = StacksTransactionSigner::new(&tx_poison_microblock_1);
            signer.sign_origin(&reporter_privk_1).unwrap();
            let signed_tx_poison_microblock_1 = signer.get_tx().unwrap();

            // make two sets of poisons
            let mblock_2_1 =
                make_signed_microblock(&block_privk, &privk, BlockHeaderHash([0x10; 32]), 122);
            let mblock_2_2 =
                make_signed_microblock(&block_privk, &privk, BlockHeaderHash([0x10; 32]), 122);
            assert!(mblock_2_1 != mblock_2_2);

            // report poison (in the same block)
            let mut tx_poison_microblock_2 = StacksTransaction::new(
                TransactionVersion::Testnet,
                TransactionAuth::from_p2pkh(&reporter_privk_2).unwrap(),
                TransactionPayload::PoisonMicroblock(
                    mblock_2_1.header.clone(),
                    mblock_2_2.header.clone(),
                ),
            );

            tx_poison_microblock_2.chain_id = 0x80000000;
            tx_poison_microblock_2.set_tx_fee(0);

            let mut signer = StacksTransactionSigner::new(&tx_poison_microblock_2);
            signer.sign_origin(&reporter_privk_2).unwrap();
            let signed_tx_poison_microblock_2 = signer.get_tx().unwrap();

            // process it!
            let (fee, receipt) = process_transaction_for_test(
                &mut conn,
                &signed_tx_poison_microblock_1,
                false,
                None,
            )
            .unwrap();

            // there must be a poison record for this microblock, from the reporter, for the microblock
            // sequence.
            let report_opt = StacksChainState::get_poison_microblock_report(&mut conn, 1).unwrap();
            assert_eq!(report_opt.unwrap(), (reporter_addr_1.clone(), 123));

            // process the second one!
            let (fee, receipt) = process_transaction_for_test(
                &mut conn,
                &signed_tx_poison_microblock_2,
                false,
                None,
            )
            .unwrap();

            // there must be a poison record for this microblock, from the reporter, for the microblock
            // sequence.  Moreover, since the fork was earlier in the stream, the second reporter gets
            // it.
            let report_opt = StacksChainState::get_poison_microblock_report(&mut conn, 1).unwrap();
            assert_eq!(report_opt.unwrap(), (reporter_addr_2.clone(), 122));

            // result must encode poison information
            let result_data = receipt.result.expect_tuple().unwrap();

            let height = result_data
                .get("block_height")
                .unwrap()
                .to_owned()
                .expect_u128()
                .unwrap();
            let mblock_pubkh = result_data
                .get("microblock_pubkey_hash")
                .unwrap()
                .to_owned()
                .expect_buff(20)
                .unwrap();
            let reporter = result_data
                .get("reporter")
                .unwrap()
                .to_owned()
                .expect_principal()
                .unwrap();
            let seq = result_data
                .get("sequence")
                .unwrap()
                .to_owned()
                .expect_u128()
                .unwrap();

            assert_eq!(height, 1);
            assert_eq!(mblock_pubkh, block_pubkh.0.to_vec());
            assert_eq!(seq, 122);
            assert_eq!(reporter, reporter_addr_2.to_account_principal());

            conn.commit_block();
        }
    }

    #[test]
    fn test_get_tx_clarity_version_v205() {
        struct MockedBurnDB {}

        impl BurnStateDB for MockedBurnDB {
            fn get_tip_burn_block_height(&self) -> Option<u32> {
                Some(0)
            }

            fn get_tip_sortition_id(&self) -> Option<SortitionId> {
                Some(SortitionId([0u8; 32]))
            }

            fn get_v1_unlock_height(&self) -> u32 {
                2
            }
            fn get_v2_unlock_height(&self) -> u32 {
                u32::MAX
            }
            fn get_v3_unlock_height(&self) -> u32 {
                u32::MAX
            }
            fn get_pox_3_activation_height(&self) -> u32 {
                u32::MAX
            }
            fn get_pox_4_activation_height(&self) -> u32 {
                u32::MAX
            }
            fn get_pox_5_activation_height(&self) -> u32 {
                u32::MAX
            }
            fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
                Some(sortition_id.0[0] as u32)
            }
            fn get_burn_start_height(&self) -> u32 {
                0
            }
            fn get_pox_prepare_length(&self) -> u32 {
                3
            }
            fn get_pox_reward_cycle_length(&self) -> u32 {
                6
            }
            fn get_pox_rejection_fraction(&self) -> u64 {
                15
            }
            fn get_burn_header_hash(
                &self,
                height: u32,
                sortition_id: &SortitionId,
            ) -> Option<BurnchainHeaderHash> {
                Some(BurnchainHeaderHash([height as u8; 32]))
            }
            fn get_sortition_id_from_consensus_hash(
                &self,
                consensus_hash: &ConsensusHash,
            ) -> Option<SortitionId> {
                Some(SortitionId([consensus_hash.0[0]; 32]))
            }
            fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
                Some(match height {
                    0 => StacksEpoch {
                        epoch_id: StacksEpochId::Epoch2_05,
                        start_height: 1,
                        end_height: 2,
                        block_limit: HELIUM_BLOCK_LIMIT_20,
                        network_epoch: PEER_VERSION_EPOCH_2_05,
                    },
                    _ => StacksEpoch {
                        epoch_id: StacksEpochId::Epoch21,
                        start_height: 2,
                        end_height: u64::MAX,
                        block_limit: HELIUM_BLOCK_LIMIT_20,
                        network_epoch: PEER_VERSION_EPOCH_2_1,
                    },
                })
            }
            fn get_stacks_epoch_by_epoch_id(
                &self,
                epoch_id: &StacksEpochId,
            ) -> Option<StacksEpoch> {
                match epoch_id {
                    StacksEpochId::Epoch10 => Some(StacksEpoch {
                        epoch_id: StacksEpochId::Epoch10,
                        start_height: 0,
                        end_height: 0,
                        block_limit: HELIUM_BLOCK_LIMIT_20,
                        network_epoch: PEER_VERSION_EPOCH_2_0,
                    }),
                    StacksEpochId::Epoch20 => self.get_stacks_epoch(0),
                    StacksEpochId::Epoch2_05 => self.get_stacks_epoch(1),
                    StacksEpochId::Epoch21 => self.get_stacks_epoch(2),
                    StacksEpochId::Epoch22 => self.get_stacks_epoch(3),
                    StacksEpochId::Epoch23 => self.get_stacks_epoch(4),
                    StacksEpochId::Epoch24 => self.get_stacks_epoch(5),
                    StacksEpochId::Epoch25 => self.get_stacks_epoch(6),
                    StacksEpochId::Epoch30 => self.get_stacks_epoch(7),
                    StacksEpochId::Epoch31 => self.get_stacks_epoch(8),
                    StacksEpochId::Epoch32 => self.get_stacks_epoch(9),
                    StacksEpochId::Epoch33 => self.get_stacks_epoch(10),
                    StacksEpochId::Epoch34 => self.get_stacks_epoch(11),
                    StacksEpochId::Epoch40 => self.get_stacks_epoch(12),
                    StacksEpochId::Epoch41 => self.get_stacks_epoch(13),
                }
            }
            fn get_pox_payout_addrs(
                &self,
                height: u32,
                sortition_id: &SortitionId,
            ) -> Option<(Vec<TupleData>, u128)> {
                None
            }
        }

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let smart_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("hello-world").unwrap(),
                    code_body: StacksString::from_str("(print \"hello\")").unwrap(),
                },
                None,
            ),
        );
        let smart_contract_v1 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("hello-world").unwrap(),
                    code_body: StacksString::from_str("(print \"hello\")").unwrap(),
                },
                Some(ClarityVersion::Clarity1),
            ),
        );
        let smart_contract_v2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("hello-world").unwrap(),
                    code_body: StacksString::from_str("(print \"hello\")").unwrap(),
                },
                Some(ClarityVersion::Clarity2),
            ),
        );
        let token_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let txs = vec![
            smart_contract,
            smart_contract_v1,
            smart_contract_v2,
            token_transfer,
        ];
        let mut signed_txs = vec![];
        for mut tx in txs.into_iter() {
            tx.chain_id = 0x80000000;
            tx.post_condition_mode = TransactionPostConditionMode::Allow;
            tx.set_tx_fee(0);

            let mut signer = StacksTransactionSigner::new(&tx);
            signer.sign_origin(&privk).unwrap();
            let signed_tx = signer.get_tx().unwrap();
            signed_txs.push(signed_tx);
        }

        let token_transfer = signed_txs.pop().unwrap();
        let smart_contract_v2 = signed_txs.pop().unwrap();
        let smart_contract_v1 = signed_txs.pop().unwrap();
        let smart_contract = signed_txs.pop().unwrap();

        let burndb = MockedBurnDB {};

        let mut conn = chainstate.block_begin(
            &burndb,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );

        assert_eq!(conn.get_epoch(), StacksEpochId::Epoch2_05);
        assert_eq!(
            ClarityVersion::Clarity1,
            get_tx_clarity_version_for_test(&mut conn, &smart_contract).unwrap()
        );
        assert_eq!(
            ClarityVersion::Clarity1,
            get_tx_clarity_version_for_test(&mut conn, &smart_contract_v1).unwrap()
        );
        assert_eq!(
            ClarityVersion::Clarity2,
            get_tx_clarity_version_for_test(&mut conn, &smart_contract_v2).unwrap()
        );
        assert_eq!(
            ClarityVersion::Clarity1,
            get_tx_clarity_version_for_test(&mut conn, &token_transfer).unwrap()
        );

        // verify that 2.1 gating is applied for clarity2
        if let Err(Error::InvalidStacksTransaction(msg, ..)) =
            process_transaction_for_test(&mut conn, &smart_contract_v2, false, None)
        {
            assert!(msg
                .find("asks for Clarity 2, but current epoch 2.05 only supports up to Clarity 1")
                .is_some());
        } else {
            panic!(
                "FATAL: did not recieve the appropriate error in processing a clarity2 tx in pre-2.1 epoch"
            );
        }

        conn.commit_block();
    }

    #[test]
    fn test_get_tx_clarity_version_v210() {
        struct MockedBurnDB {}

        impl BurnStateDB for MockedBurnDB {
            fn get_tip_burn_block_height(&self) -> Option<u32> {
                Some(0)
            }

            fn get_tip_sortition_id(&self) -> Option<SortitionId> {
                Some(SortitionId([0u8; 32]))
            }

            fn get_v1_unlock_height(&self) -> u32 {
                2
            }
            fn get_v2_unlock_height(&self) -> u32 {
                u32::MAX
            }
            fn get_v3_unlock_height(&self) -> u32 {
                u32::MAX
            }
            fn get_pox_3_activation_height(&self) -> u32 {
                u32::MAX
            }
            fn get_pox_4_activation_height(&self) -> u32 {
                u32::MAX
            }
            fn get_pox_5_activation_height(&self) -> u32 {
                u32::MAX
            }
            fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
                Some(sortition_id.0[0] as u32)
            }
            fn get_burn_start_height(&self) -> u32 {
                0
            }
            fn get_pox_prepare_length(&self) -> u32 {
                3
            }
            fn get_pox_reward_cycle_length(&self) -> u32 {
                6
            }
            fn get_pox_rejection_fraction(&self) -> u64 {
                15
            }
            fn get_burn_header_hash(
                &self,
                height: u32,
                sortition_id: &SortitionId,
            ) -> Option<BurnchainHeaderHash> {
                Some(BurnchainHeaderHash([height as u8; 32]))
            }
            fn get_sortition_id_from_consensus_hash(
                &self,
                consensus_hash: &ConsensusHash,
            ) -> Option<SortitionId> {
                Some(SortitionId([consensus_hash.0[0]; 32]))
            }
            fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
                Some(StacksEpoch {
                    epoch_id: StacksEpochId::Epoch21,
                    start_height: 0,
                    end_height: u64::MAX,
                    block_limit: HELIUM_BLOCK_LIMIT_20,
                    network_epoch: PEER_VERSION_EPOCH_2_1,
                })
            }
            fn get_stacks_epoch_by_epoch_id(
                &self,
                epoch_id: &StacksEpochId,
            ) -> Option<StacksEpoch> {
                match epoch_id {
                    StacksEpochId::Epoch10 => Some(StacksEpoch {
                        epoch_id: StacksEpochId::Epoch10,
                        start_height: 0,
                        end_height: 0,
                        block_limit: HELIUM_BLOCK_LIMIT_20,
                        network_epoch: PEER_VERSION_EPOCH_2_0,
                    }),
                    _ => self.get_stacks_epoch(0),
                }
            }
            fn get_pox_payout_addrs(
                &self,
                height: u32,
                sortition_id: &SortitionId,
            ) -> Option<(Vec<TupleData>, u128)> {
                None
            }
        }

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let smart_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("hello-world").unwrap(),
                    code_body: StacksString::from_str("(print \"hello\")").unwrap(),
                },
                None,
            ),
        );
        let smart_contract_v1 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("hello-world").unwrap(),
                    code_body: StacksString::from_str("(print \"hello\")").unwrap(),
                },
                Some(ClarityVersion::Clarity1),
            ),
        );
        let smart_contract_v2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("hello-world").unwrap(),
                    code_body: StacksString::from_str("(print \"hello\")").unwrap(),
                },
                Some(ClarityVersion::Clarity2),
            ),
        );
        let token_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(
                recv_addr.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let txs = vec![
            smart_contract,
            smart_contract_v1,
            smart_contract_v2,
            token_transfer,
        ];
        let mut signed_txs = vec![];
        for mut tx in txs.into_iter() {
            tx.chain_id = 0x80000000;
            tx.post_condition_mode = TransactionPostConditionMode::Allow;
            tx.set_tx_fee(0);

            let mut signer = StacksTransactionSigner::new(&tx);
            signer.sign_origin(&privk).unwrap();
            let signed_tx = signer.get_tx().unwrap();
            signed_txs.push(signed_tx);
        }

        let token_transfer = signed_txs.pop().unwrap();
        let smart_contract_v2 = signed_txs.pop().unwrap();
        let smart_contract_v1 = signed_txs.pop().unwrap();
        let smart_contract = signed_txs.pop().unwrap();

        let burndb = MockedBurnDB {};

        let mut conn = chainstate.block_begin(
            &burndb,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );

        assert_eq!(conn.get_epoch(), StacksEpochId::Epoch21);
        assert_eq!(
            ClarityVersion::Clarity2,
            get_tx_clarity_version_for_test(&mut conn, &smart_contract).unwrap()
        );
        assert_eq!(
            ClarityVersion::Clarity1,
            get_tx_clarity_version_for_test(&mut conn, &smart_contract_v1).unwrap()
        );
        assert_eq!(
            ClarityVersion::Clarity2,
            get_tx_clarity_version_for_test(&mut conn, &smart_contract_v2).unwrap()
        );
        assert_eq!(
            ClarityVersion::Clarity2,
            get_tx_clarity_version_for_test(&mut conn, &token_transfer).unwrap()
        );

        conn.commit_block();
    }

    #[test]
    fn process_fee_gating() {
        let contract = r#"
        (define-public (send-stx (amount uint) (recipient principal))
            (as-contract
                (stx-transfer? amount tx-sender recipient))
        )

        (stx-transfer? u500000000 tx-sender (as-contract tx-sender))
        "#;

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let privk_recv = StacksPrivateKey::from_hex(
            "9bb626a4b2656a31e70d7828b54ad44efb6e549ac8e59214d5ef0bbabffcc03d01",
        )
        .unwrap();
        let auth_recv = TransactionAuth::from_p2pkh(&privk_recv).unwrap();
        let addr_recv = auth_recv.origin().address_testnet();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let mut tx_contract_create = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("faucet", contract, None).unwrap(),
        );

        tx_contract_create.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_contract_create.chain_id = 0x80000000;
        tx_contract_create.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_create);
        signer.sign_origin(&privk).unwrap();

        let signed_contract_tx = signer.get_tx().unwrap();

        // recipient tries to get some STX, but with a tx fee.
        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_recv,
            TransactionPayload::new_contract_call(
                addr.clone(),
                "faucet",
                "send-stx",
                vec![
                    Value::UInt(100000),
                    Value::Principal(PrincipalData::from(addr_recv.clone())),
                ],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(1);
        tx_contract_call.set_origin_nonce(0);
        tx_contract_call.post_condition_mode = TransactionPostConditionMode::Allow;

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk_recv).unwrap();

        let signed_contract_call_tx = signer.get_tx().unwrap();

        // In 2.0, this will succeed since we debit the fee *after* we run the contract
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_20,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );
        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
        assert_eq!(fee, 0);

        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None).unwrap();
        assert_eq!(fee, 1);

        conn.commit_block();

        // In 2.05, this will succeed since we debit the fee *after* we run the contract
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_2_05,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );
        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
        assert_eq!(fee, 0);

        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None).unwrap();
        assert_eq!(fee, 1);

        conn.commit_block();

        // post-2.1, this will fail since we debit the fee *before* we run the contract
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );
        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
        assert_eq!(fee, 0);

        let err = process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None)
            .unwrap_err();
        conn.commit_block();

        assert!(matches!(err, Error::InvalidFee), "{err:?}");
    }

    #[test]
    fn process_fee_gating_sponsored() {
        let contract = r#"
        (define-public (send-stx (amount uint) (recipient principal))
            (as-contract
                (stx-transfer? amount tx-sender recipient))
        )

        (stx-transfer? u500000000 tx-sender (as-contract tx-sender))
        "#;

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let privk_origin = StacksPrivateKey::from_hex(
            "a469b97ccaa4553767bc1359390d1b239d2e5ec7b69dbc509fe2cd566fd55ec101",
        )
        .unwrap();
        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let addr_origin = auth_origin.origin().address_testnet();

        let privk_recv = StacksPrivateKey::from_hex(
            "9bb626a4b2656a31e70d7828b54ad44efb6e549ac8e59214d5ef0bbabffcc03d01",
        )
        .unwrap();
        let auth_recv = TransactionAuth::from_p2pkh(&privk_recv).unwrap();
        let addr_recv = auth_recv.origin().address_testnet();

        let auth_recv = auth_origin.into_sponsored(auth_recv).unwrap();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let mut tx_contract_create = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract("faucet", contract, None).unwrap(),
        );

        tx_contract_create.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_contract_create.chain_id = 0x80000000;
        tx_contract_create.set_tx_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_create);
        signer.sign_origin(&privk).unwrap();

        let signed_contract_tx = signer.get_tx().unwrap();

        // recipient tries to get some STX, but with a tx fee.
        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth_recv,
            TransactionPayload::new_contract_call(
                addr.clone(),
                "faucet",
                "send-stx",
                vec![
                    Value::UInt(100000),
                    Value::Principal(PrincipalData::from(addr_recv.clone())),
                ],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_tx_fee(1);
        tx_contract_call.set_origin_nonce(0);
        tx_contract_call.set_sponsor_nonce(0).unwrap();
        tx_contract_call.post_condition_mode = TransactionPostConditionMode::Allow;

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk_origin).unwrap();
        signer.sign_sponsor(&privk_recv).unwrap();

        let signed_contract_call_tx = signer.get_tx().unwrap();

        // In 2.0, this will succeed since we debit the fee *after* we run the contract
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_20,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );
        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
        assert_eq!(fee, 0);

        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None).unwrap();
        assert_eq!(fee, 1);

        conn.commit_block();

        // In 2.05, this will succeed since we debit the fee *after* we run the contract
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_2_05,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );
        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
        assert_eq!(fee, 0);

        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None).unwrap();
        assert_eq!(fee, 1);

        conn.commit_block();

        // post-2.1, this will fail since we debit the fee *before* we run the contract
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );
        let (fee, _) =
            process_transaction_for_test(&mut conn, &signed_contract_tx, false, None).unwrap();
        assert_eq!(fee, 0);

        let err = process_transaction_for_test(&mut conn, &signed_contract_call_tx, false, None)
            .unwrap_err();
        conn.commit_block();

        assert!(matches!(err, Error::InvalidFee), "{err:?}");
    }

    /// Call `process_transaction()` with  prechecks
    pub fn validate_transactions_static_epoch_and_process_transaction(
        clarity_block: &mut ClarityTx,
        tx: &StacksTransaction,
        quiet: bool,
    ) -> Result<(u64, StacksTransactionReceipt), Error> {
        let epoch = clarity_block.get_epoch();

        if !StacksBlock::validate_transactions_static_epoch(&vec![tx.clone()], epoch) {
            let msg = format!(
                "Invalid transaction {}: target epoch is not activated",
                tx.txid()
            );
            warn!("{}", &msg);
            return Err(Error::InvalidStacksTransaction(msg, false));
        }

        process_transaction_for_test(clarity_block, tx, quiet, None)
    }

    #[test]
    fn test_checkerrors_at_runtime() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let runtime_checkerror_trait = "
            (define-trait foo
                (
                    (lolwut () (response bool uint))
                )
            )
            "
        .to_string();

        let runtime_checkerror_impl = "
            (impl-trait .foo.foo)

            (define-public (lolwut)
                (ok true)
            )
            "
        .to_string();

        let runtime_checkerror = "
            (use-trait trait .foo.foo)

            (define-data-var mutex bool true)
            (define-data-var executed bool false)

            (define-public (flip)
              (ok (var-set mutex (not (var-get mutex))))
            )

            ;; triggers RuntimeCheckErrorKind because <trait> gets coerced
            ;; into a principal when `internal` is called.
            (define-public (test (ref <trait>))
                (ok (internal (if (var-get mutex)
                    (begin
                        (print \"some case\")
                        (var-set executed true)
                        (some ref)
                    )
                    none
                )))
            )

            (define-private (internal (ref (optional <trait>))) true)
            "
        .to_string();

        let runtime_checkerror_contract = "
            (begin
                (print \"about to contract-call with trait impl\")
                (unwrap-panic (contract-call? .trait-runtime-analysis-error test .foo-impl))
                (print \"contract-call with trait impl finished\")
            )
            ";

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let mut tx_runtime_checkerror_trait_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("foo", &runtime_checkerror_trait, None).unwrap(),
        );

        tx_runtime_checkerror_trait_no_version.post_condition_mode =
            TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_trait_no_version.chain_id = 0x80000000;
        tx_runtime_checkerror_trait_no_version.set_tx_fee(1);
        tx_runtime_checkerror_trait_no_version.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_trait_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_trait_tx_no_version = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_trait = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "foo",
                &runtime_checkerror_trait,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_runtime_checkerror_trait.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_trait.chain_id = 0x80000000;
        tx_runtime_checkerror_trait.set_tx_fee(1);
        tx_runtime_checkerror_trait.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_trait);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_trait_tx = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_impl = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "foo-impl",
                &runtime_checkerror_impl,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_runtime_checkerror_impl.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_impl.chain_id = 0x80000000;
        tx_runtime_checkerror_impl.set_tx_fee(1);
        tx_runtime_checkerror_impl.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_impl);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_impl_tx = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_impl_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("foo-impl", &runtime_checkerror_impl, None)
                .unwrap(),
        );

        tx_runtime_checkerror_impl_no_version.post_condition_mode =
            TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_impl_no_version.chain_id = 0x80000000;
        tx_runtime_checkerror_impl_no_version.set_tx_fee(1);
        tx_runtime_checkerror_impl_no_version.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_impl_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_impl_tx_no_version = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_clar1 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "trait-runtime-analysis-error",
                &runtime_checkerror,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_runtime_checkerror_clar1.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_clar1.chain_id = 0x80000000;
        tx_runtime_checkerror_clar1.set_tx_fee(1);
        tx_runtime_checkerror_clar1.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_clar1);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_tx_clar1 = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_clar1_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "trait-runtime-analysis-error",
                &runtime_checkerror,
                None,
            )
            .unwrap(),
        );

        tx_runtime_checkerror_clar1_no_version.post_condition_mode =
            TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_clar1_no_version.chain_id = 0x80000000;
        tx_runtime_checkerror_clar1_no_version.set_tx_fee(1);
        tx_runtime_checkerror_clar1_no_version.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_clar1_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_tx_clar1_no_version = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_clar2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "trait-runtime-analysis-error",
                &runtime_checkerror,
                Some(ClarityVersion::Clarity2),
            )
            .unwrap(),
        );

        tx_runtime_checkerror_clar2.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_clar2.chain_id = 0x80000000;
        tx_runtime_checkerror_clar2.set_tx_fee(1);
        tx_runtime_checkerror_clar2.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_clar2);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_tx_clar2 = signer.get_tx().unwrap();

        let mut tx_test_trait_runtime_checkerror = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_contract_call(
                addr.clone(),
                "trait-runtime-analysis-error",
                "test",
                vec![Value::Principal(PrincipalData::Contract(
                    QualifiedContractIdentifier::parse(&format!("{}.foo-impl", &addr)).unwrap(),
                ))],
            )
            .unwrap(),
        );

        tx_test_trait_runtime_checkerror.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_test_trait_runtime_checkerror.chain_id = 0x80000000;
        tx_test_trait_runtime_checkerror.set_tx_fee(1);
        tx_test_trait_runtime_checkerror.set_origin_nonce(3);

        let mut signer = StacksTransactionSigner::new(&tx_test_trait_runtime_checkerror);
        signer.sign_origin(&privk).unwrap();

        let signed_test_trait_runtime_checkerror_tx = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_cc_contract_clar1 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "trait-runtime-analysis-error-cc",
                runtime_checkerror_contract,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_runtime_checkerror_cc_contract_clar1.post_condition_mode =
            TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_cc_contract_clar1.chain_id = 0x80000000;
        tx_runtime_checkerror_cc_contract_clar1.set_tx_fee(1);
        tx_runtime_checkerror_cc_contract_clar1.set_origin_nonce(3);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_cc_contract_clar1);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_cc_contract_tx_clar1 = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_cc_contract_clar1_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "trait-runtime-analysis-error-cc",
                runtime_checkerror_contract,
                None,
            )
            .unwrap(),
        );

        tx_runtime_checkerror_cc_contract_clar1_no_version.post_condition_mode =
            TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_cc_contract_clar1_no_version.chain_id = 0x80000000;
        tx_runtime_checkerror_cc_contract_clar1_no_version.set_tx_fee(1);
        tx_runtime_checkerror_cc_contract_clar1_no_version.set_origin_nonce(3);

        let mut signer =
            StacksTransactionSigner::new(&tx_runtime_checkerror_cc_contract_clar1_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_cc_contract_tx_clar1_no_version = signer.get_tx().unwrap();

        let mut tx_runtime_checkerror_cc_contract_clar2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract(
                "trait-runtime-analysis-error-cc",
                runtime_checkerror_contract,
                Some(ClarityVersion::Clarity2),
            )
            .unwrap(),
        );

        tx_runtime_checkerror_cc_contract_clar2.post_condition_mode =
            TransactionPostConditionMode::Allow;
        tx_runtime_checkerror_cc_contract_clar2.chain_id = 0x80000000;
        tx_runtime_checkerror_cc_contract_clar2.set_tx_fee(1);
        tx_runtime_checkerror_cc_contract_clar2.set_origin_nonce(4);

        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_cc_contract_clar2);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_cc_contract_tx_clar2 = signer.get_tx().unwrap();

        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr.clone()),
            ContractName::from_literal("trait-runtime-analysis-error"),
        );

        // in 2.0, this invalidates the block
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_20,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_trait_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_impl_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_tx_clar1_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_trait_runtime_checkerror_tx,
            false,
        )
        .unwrap_err();
        if let Error::ClarityError(ClarityError::Interpreter(VmExecutionError::RuntimeCheck(
            _runtime_check_err,
        ))) = err
        {
        } else {
            panic!("Did not get unchecked interpreter error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_impl_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_tx_clar1,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_trait_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let acct = StacksChainState::get_account(&mut conn, &addr.clone().into());
        assert_eq!(acct.nonce, 3);

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_cc_contract_tx_clar1_no_version,
            false,
        )
        .unwrap_err();
        if let Error::ClarityError(ClarityError::Interpreter(VmExecutionError::RuntimeCheck(
            _runtime_check_err,
        ))) = err
        {
        } else {
            panic!("Did not get unchecked interpreter error");
        }
        let acct = StacksChainState::get_account(&mut conn, &addr.clone().into());
        assert_eq!(acct.nonce, 3);

        conn.commit_block();

        // in 2.05, this invalidates the block
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_2_05,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_trait_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_impl_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_tx_clar1_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_trait_runtime_checkerror_tx,
            false,
        )
        .unwrap_err();
        if let Error::ClarityError(ClarityError::Interpreter(VmExecutionError::RuntimeCheck(
            _runtime_check_err,
        ))) = err
        {
        } else {
            panic!("Did not get unchecked interpreter error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_impl_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_tx_clar1,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_trait_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }
        let acct = StacksChainState::get_account(&mut conn, &addr.clone().into());
        assert_eq!(acct.nonce, 3);

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_cc_contract_tx_clar1_no_version,
            false,
        )
        .unwrap_err();
        if let Error::ClarityError(ClarityError::Interpreter(VmExecutionError::RuntimeCheck(
            _runtime_check_err,
        ))) = err
        {
        } else {
            panic!("Did not get unchecked interpreter error");
        }
        let acct = StacksChainState::get_account(&mut conn, &addr.clone().into());
        assert_eq!(acct.nonce, 3);

        conn.commit_block();

        // in 2.1, this is a runtime error when using clarity 1
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );

        // make this mineable
        tx_runtime_checkerror_cc_contract_clar1.set_origin_nonce(4);
        let mut signer = StacksTransactionSigner::new(&tx_runtime_checkerror_cc_contract_clar1);
        signer.sign_origin(&privk).unwrap();

        let signed_runtime_checkerror_cc_contract_tx_clar1 = signer.get_tx().unwrap();

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = process_transaction_for_test(
            &mut conn,
            &signed_runtime_checkerror_tx_clar1,
            false,
            None,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_trait_runtime_checkerror_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        // nonce keeps advancing despite error
        let acct = StacksChainState::get_account(&mut conn, &addr.clone().into());
        assert_eq!(acct.nonce, 4);

        // no state change materialized
        let executed_var =
            StacksChainState::get_data_var(&mut conn, &contract_id, "executed").unwrap();
        assert_eq!(executed_var, Some(Value::Bool(false)));

        assert!(tx_receipt.vm_error.is_some());
        let err_str = tx_receipt.vm_error.unwrap();
        assert!(err_str
            .find("TypeValueError(OptionalType(CallableType(Trait(TraitIdentifier ")
            .is_some());

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_cc_contract_tx_clar1,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        // nonce keeps advancing despite error
        let acct = StacksChainState::get_account(&mut conn, &addr.clone().into());
        assert_eq!(acct.nonce, 5);

        // no state change materialized
        let executed_var =
            StacksChainState::get_data_var(&mut conn, &contract_id, "executed").unwrap();
        assert_eq!(executed_var, Some(Value::Bool(false)));

        assert!(tx_receipt.vm_error.is_some());
        let err_str = tx_receipt.vm_error.unwrap();
        assert!(err_str
            .find("TypeValueError(OptionalType(CallableType(Trait(TraitIdentifier ")
            .is_some());

        conn.commit_block();

        // in 2.1, this is successful when using clarity 2
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([4u8; 20]),
            &BlockHeaderHash([4u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_tx_clar2,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_trait_runtime_checkerror_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        // nonce keeps advancing
        let acct = StacksChainState::get_account(&mut conn, &addr.clone().into());
        assert_eq!(acct.nonce, 4);

        // state change materialized
        let executed_var =
            StacksChainState::get_data_var(&mut conn, &contract_id, "executed").unwrap();
        assert_eq!(executed_var, Some(Value::Bool(true)));

        assert!(tx_receipt.vm_error.is_none());

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_runtime_checkerror_cc_contract_tx_clar2,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        // nonce keeps advancing
        let acct = StacksChainState::get_account(&mut conn, &addr.into());
        assert_eq!(acct.nonce, 5);

        // state change materialized
        let executed_var =
            StacksChainState::get_data_var(&mut conn, &contract_id, "executed").unwrap();
        assert_eq!(executed_var, Some(Value::Bool(true)));

        assert!(tx_receipt.vm_error.is_none());

        conn.commit_block();
    }

    #[test]
    fn test_embedded_trait() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let foo_trait = "
            (define-trait foo
                (
                    (do-it () (response bool uint))
                )
            )
            "
        .to_string();

        let foo_impl = "
            (impl-trait .foo.foo)

            (define-public (do-it)
                (ok true)
            )
            "
        .to_string();

        let call_foo = "
            (use-trait foo .foo.foo)
            (define-public (call-do-it (opt-f (optional <foo>)))
                (match opt-f
                    f (contract-call? f do-it)
                    (ok false)
                )
            )
            "
        .to_string();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let mut tx_foo_trait = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "foo",
                &foo_trait,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_foo_trait.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_trait.chain_id = 0x80000000;
        tx_foo_trait.set_tx_fee(1);
        tx_foo_trait.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx_foo_trait);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_trait_tx = signer.get_tx().unwrap();

        let mut tx_foo_trait_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("foo", &foo_trait, None).unwrap(),
        );

        tx_foo_trait_no_version.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_trait_no_version.chain_id = 0x80000000;
        tx_foo_trait_no_version.set_tx_fee(1);
        tx_foo_trait_no_version.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx_foo_trait_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_trait_tx_no_version = signer.get_tx().unwrap();

        let mut tx_foo_impl = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "foo-impl",
                &foo_impl,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_foo_impl.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_impl.chain_id = 0x80000000;
        tx_foo_impl.set_tx_fee(1);
        tx_foo_impl.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&tx_foo_impl);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_impl_tx = signer.get_tx().unwrap();

        let mut tx_foo_impl_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("foo-impl", &foo_impl, None).unwrap(),
        );

        tx_foo_impl_no_version.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_impl_no_version.chain_id = 0x80000000;
        tx_foo_impl_no_version.set_tx_fee(1);
        tx_foo_impl_no_version.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&tx_foo_impl_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_impl_tx_no_version = signer.get_tx().unwrap();

        let mut tx_call_foo_clar1 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "call-foo",
                &call_foo,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_call_foo_clar1.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_call_foo_clar1.chain_id = 0x80000000;
        tx_call_foo_clar1.set_tx_fee(1);
        tx_call_foo_clar1.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_call_foo_clar1);
        signer.sign_origin(&privk).unwrap();

        let signed_call_foo_tx_clar1 = signer.get_tx().unwrap();

        let mut tx_call_foo_clar1_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("call-foo", &call_foo, None).unwrap(),
        );

        tx_call_foo_clar1_no_version.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_call_foo_clar1_no_version.chain_id = 0x80000000;
        tx_call_foo_clar1_no_version.set_tx_fee(1);
        tx_call_foo_clar1_no_version.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_call_foo_clar1_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_call_foo_tx_clar1_no_version = signer.get_tx().unwrap();

        let mut tx_call_foo_clar2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "call-foo",
                &call_foo,
                Some(ClarityVersion::Clarity2),
            )
            .unwrap(),
        );

        tx_call_foo_clar2.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_call_foo_clar2.chain_id = 0x80000000;
        tx_call_foo_clar2.set_tx_fee(1);
        tx_call_foo_clar2.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_call_foo_clar2);
        signer.sign_origin(&privk).unwrap();

        let signed_call_foo_tx_clar2 = signer.get_tx().unwrap();

        let mut tx_test_call_foo = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_contract_call(
                addr.clone(),
                "call-foo",
                "call-do-it",
                vec![Value::some(Value::Principal(PrincipalData::Contract(
                    QualifiedContractIdentifier::parse(&format!("{}.foo-impl", &addr)).unwrap(),
                )))
                .unwrap()],
            )
            .unwrap(),
        );

        tx_test_call_foo.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_test_call_foo.chain_id = 0x80000000;
        tx_test_call_foo.set_tx_fee(1);
        tx_test_call_foo.set_origin_nonce(3);

        let mut signer = StacksTransactionSigner::new(&tx_test_call_foo);
        signer.sign_origin(&privk).unwrap();

        let signed_test_call_foo_tx = signer.get_tx().unwrap();

        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr.clone()),
            ContractName::from_literal("trait-runtime-analysis-error"),
        );

        // in 2.0: analysis error should cause contract publish to fail
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_20,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);
        match tx_receipt.result {
            Value::Response(ResponseData {
                committed: false,
                data: _,
            }) => (),
            _ => panic!("expected the contract publish to fail"),
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        conn.commit_block();

        // in 2.05: analysis error should cause contract publish to fail
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_2_05,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);
        match tx_receipt.result {
            Value::Response(ResponseData {
                committed: false,
                data: _,
            }) => (),
            _ => panic!("expected the contract publish to fail"),
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_call_foo_tx,
            false,
        )
        .unwrap_err();
        if let Error::ClarityError(ClarityError::Interpreter(VmExecutionError::RuntimeCheck(
            runtime_check_err,
        ))) = err
        {
        } else {
            panic!("Did not get unchecked interpreter error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        conn.commit_block();

        // in 2.1, using clarity 1: analysis error should cause contract publish to fail
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);
        match tx_receipt.result {
            Value::Response(ResponseData {
                committed: false,
                data: _,
            }) => (),
            _ => panic!("expected the contract publish to fail"),
        }

        conn.commit_block();

        // in 2.1, using clarity 2: success
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([4u8; 20]),
            &BlockHeaderHash([4u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar2,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_call_foo_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);
        match tx_receipt.result {
            Value::Response(ResponseData {
                committed: true,
                data,
            }) => match *data {
                Value::Bool(true) => (),
                _ => panic!("expected (ok true) result"),
            },
            _ => panic!("expected successful call"),
        }

        conn.commit_block();
    }

    #[test]
    fn test_transitive_trait() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let foo_trait = "
            (define-trait foo
                (
                    (do-it () (response bool uint))
                )
            )
            "
        .to_string();

        let transitive_trait = "
            (use-trait foo .foo.foo)
            (define-trait poo
                (
                    (do-it () (response bool uint))
                )
            )
        "
        .to_string();

        let foo_impl = "
            (impl-trait .foo.foo)

            (define-public (do-it)
                (ok true)
            )
            "
        .to_string();

        let call_foo = "
            (use-trait foo .transitive.foo)
            (define-public (call-do-it (f <foo>))
                (contract-call? f do-it)
            )
            "
        .to_string();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let mut tx_foo_trait = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "foo",
                &foo_trait,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_foo_trait.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_trait.chain_id = 0x80000000;
        tx_foo_trait.set_tx_fee(1);
        tx_foo_trait.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx_foo_trait);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_trait_tx = signer.get_tx().unwrap();

        let mut tx_foo_trait_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("foo", &foo_trait, None).unwrap(),
        );

        tx_foo_trait_no_version.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_trait_no_version.chain_id = 0x80000000;
        tx_foo_trait_no_version.set_tx_fee(1);
        tx_foo_trait_no_version.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx_foo_trait_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_trait_tx_no_version = signer.get_tx().unwrap();

        let mut tx_transitive_trait_clar1 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "transitive",
                &transitive_trait,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_transitive_trait_clar1.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_transitive_trait_clar1.chain_id = 0x80000000;
        tx_transitive_trait_clar1.set_tx_fee(1);
        tx_transitive_trait_clar1.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&tx_transitive_trait_clar1);
        signer.sign_origin(&privk).unwrap();

        let signed_transitive_trait_clar1_tx = signer.get_tx().unwrap();

        let mut tx_transitive_trait_clar1_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("transitive", &transitive_trait, None).unwrap(),
        );

        tx_transitive_trait_clar1_no_version.post_condition_mode =
            TransactionPostConditionMode::Allow;
        tx_transitive_trait_clar1_no_version.chain_id = 0x80000000;
        tx_transitive_trait_clar1_no_version.set_tx_fee(1);
        tx_transitive_trait_clar1_no_version.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&tx_transitive_trait_clar1_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_transitive_trait_clar1_tx_no_version = signer.get_tx().unwrap();

        let mut tx_transitive_trait_clar2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "transitive",
                &transitive_trait,
                Some(ClarityVersion::Clarity2),
            )
            .unwrap(),
        );

        tx_transitive_trait_clar2.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_transitive_trait_clar2.chain_id = 0x80000000;
        tx_transitive_trait_clar2.set_tx_fee(1);
        tx_transitive_trait_clar2.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&tx_transitive_trait_clar2);
        signer.sign_origin(&privk).unwrap();

        let signed_transitive_trait_clar2_tx = signer.get_tx().unwrap();

        let mut tx_foo_impl = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "foo-impl",
                &foo_impl,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_foo_impl.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_impl.chain_id = 0x80000000;
        tx_foo_impl.set_tx_fee(1);
        tx_foo_impl.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_foo_impl);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_impl_tx = signer.get_tx().unwrap();

        let mut tx_foo_impl_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("foo-impl", &foo_impl, None).unwrap(),
        );

        tx_foo_impl_no_version.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_foo_impl_no_version.chain_id = 0x80000000;
        tx_foo_impl_no_version.set_tx_fee(1);
        tx_foo_impl_no_version.set_origin_nonce(2);

        let mut signer = StacksTransactionSigner::new(&tx_foo_impl_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_foo_impl_tx_no_version = signer.get_tx().unwrap();

        let mut tx_call_foo_clar1 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "call-foo",
                &call_foo,
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );

        tx_call_foo_clar1.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_call_foo_clar1.chain_id = 0x80000000;
        tx_call_foo_clar1.set_tx_fee(1);
        tx_call_foo_clar1.set_origin_nonce(3);

        let mut signer = StacksTransactionSigner::new(&tx_call_foo_clar1);
        signer.sign_origin(&privk).unwrap();

        let signed_call_foo_tx_clar1 = signer.get_tx().unwrap();

        let mut tx_call_foo_clar1_no_version = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("call-foo", &call_foo, None).unwrap(),
        );

        tx_call_foo_clar1_no_version.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_call_foo_clar1_no_version.chain_id = 0x80000000;
        tx_call_foo_clar1_no_version.set_tx_fee(1);
        tx_call_foo_clar1_no_version.set_origin_nonce(3);

        let mut signer = StacksTransactionSigner::new(&tx_call_foo_clar1_no_version);
        signer.sign_origin(&privk).unwrap();

        let signed_call_foo_tx_clar1_no_version = signer.get_tx().unwrap();

        let mut tx_call_foo_clar2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                "call-foo",
                &call_foo,
                Some(ClarityVersion::Clarity2),
            )
            .unwrap(),
        );

        tx_call_foo_clar2.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_call_foo_clar2.chain_id = 0x80000000;
        tx_call_foo_clar2.set_tx_fee(1);
        tx_call_foo_clar2.set_origin_nonce(3);

        let mut signer = StacksTransactionSigner::new(&tx_call_foo_clar2);
        signer.sign_origin(&privk).unwrap();

        let signed_call_foo_tx_clar2 = signer.get_tx().unwrap();

        let mut tx_test_call_foo = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_contract_call(
                addr.clone(),
                "call-foo",
                "call-do-it",
                vec![Value::Principal(PrincipalData::Contract(
                    QualifiedContractIdentifier::parse(&format!("{}.foo-impl", &addr)).unwrap(),
                ))],
            )
            .unwrap(),
        );

        tx_test_call_foo.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_test_call_foo.chain_id = 0x80000000;
        tx_test_call_foo.set_tx_fee(1);
        tx_test_call_foo.set_origin_nonce(4);

        let mut signer = StacksTransactionSigner::new(&tx_test_call_foo);
        signer.sign_origin(&privk).unwrap();

        let signed_test_call_foo_tx = signer.get_tx().unwrap();

        let contract_id = QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr.clone()),
            ContractName::from_literal("trait-runtime-analysis-error"),
        );

        // in 2.0: calling call-foo invalidates the block
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_20,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar1_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_call_foo_tx,
            false,
        )
        .unwrap_err();
        if let Error::ClarityError(ClarityError::Interpreter(VmExecutionError::RuntimeCheck(
            runtime_check_err,
        ))) = err
        {
        } else {
            panic!("Did not get unchecked interpreter error");
        }
        assert_eq!(fee, 1);

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar1_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        conn.commit_block();

        // in 2.05: calling call-foo invalidates the block
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_2_05,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar1_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1_no_version,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_call_foo_tx,
            false,
        )
        .unwrap_err();
        if let Error::ClarityError(ClarityError::Interpreter(VmExecutionError::RuntimeCheck(
            runtime_check_err,
        ))) = err
        {
            assert!(
                matches!(runtime_check_err, RuntimeCheckErrorKind::TraitReferenceUnknown(ref name) if name == "foo"),
                "Expected TraitReferenceUnknown(\"foo\") runtime check error"
            );
        } else {
            panic!("Did not get unchecked interpreter error");
        };

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar1_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        let err = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1,
            false,
        )
        .unwrap_err();
        if let Error::InvalidStacksTransaction(msg, _ignored) = err {
            assert!(msg.find("target epoch is not activated").is_some());
        } else {
            panic!("Did not get epoch is not activated error");
        }

        conn.commit_block();

        // in 2.1, using clarity 1 for both `transitive` and `call-foo`: calling call-foo causes an analysis error
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar1_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (_fee, receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_call_foo_tx,
            false,
        )
        .unwrap();
        assert_eq!(
            receipt.vm_error.as_deref(),
            Some("TraitReferenceUnknown(\"foo\")"),
            "Expected TraitReferenceUnknown vm_error"
        );

        conn.commit_block();

        // in 2.1, using clarity 1 for `transitive` and clarity 2 for `call-foo`: calling call-foo causes an analysis error
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([4u8; 20]),
            &BlockHeaderHash([4u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar1_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar2,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (_fee, receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_test_call_foo_tx,
            false,
        )
        .unwrap();
        assert_eq!(
            receipt.vm_error.as_deref(),
            Some("TraitReferenceUnknown(\"foo\")"),
            "Expected TraitReferenceUnknown vm_error"
        );

        conn.commit_block();

        // in 2.1, using clarity 2 for both `transitive` and `call-foo`: publishing call-foo triggers an analysis error
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([5u8; 20]),
            &BlockHeaderHash([5u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar2_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar2,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);
        match tx_receipt.result {
            Value::Response(ResponseData {
                committed: false,
                data,
            }) => assert_eq!(*data, Value::none()),
            _ => panic!("expected error response"),
        }

        conn.commit_block();

        // in 2.1, using clarity 2 for `transitive` and clarity 1 for `call-foo`: publishing call-foo triggers an analysis error
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([6u8; 20]),
            &BlockHeaderHash([6u8; 32]),
        );

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_trait_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_transitive_trait_clar2_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, _) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_foo_impl_tx,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);

        let (fee, tx_receipt) = validate_transactions_static_epoch_and_process_transaction(
            &mut conn,
            &signed_call_foo_tx_clar1,
            false,
        )
        .unwrap();
        assert_eq!(fee, 1);
        match tx_receipt.result {
            Value::Response(ResponseData {
                committed: false,
                data,
            }) => assert_eq!(*data, Value::none()),
            _ => panic!("expected error response"),
        }

        conn.commit_block();
    }

    /// Verify that transactions with bare PrincipalDatas in them cannot decode if the version byte
    /// is inappropriate.
    #[test]
    fn test_invalid_address_prevents_tx_decode() {
        // token transfer
        let bad_payload_bytes = vec![
            TransactionPayloadID::TokenTransfer as u8,
            // Clarity value type (StandardPrincipalData)
            0x05,
            // bad address (version byte 32)
            0x20,
            // address body (0x00000000000000000000)
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // amount (1 uSTX)
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            // memo
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
        ];

        let mut good_payload_bytes = bad_payload_bytes.clone();

        // only diff is the address version
        good_payload_bytes[2] = 0x1f;

        let bad_payload: Result<TransactionPayload, _> =
            TransactionPayload::consensus_deserialize(&mut &bad_payload_bytes[..]);
        assert!(bad_payload.is_err());

        let _: TransactionPayload =
            TransactionPayload::consensus_deserialize(&mut &good_payload_bytes[..]).unwrap();

        // contract-call with bad contract address
        let bad_payload_bytes = vec![
            TransactionPayloadID::ContractCall as u8,
            // Stacks address
            // bad version byte
            0x20,
            // address body (0x00000000000000000000)
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // contract name ("hello")
            0x05,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            // function name ("world")
            0x05,
            0x77,
            0x6f,
            0x72,
            0x6c,
            0x64,
            // arguments (good address)
            // length (1)
            0x00,
            0x00,
            0x00,
            0x01,
            // StandardPrincipalData
            0x05,
            // address version (1)
            0x01,
            // address body (0x00000000000000000000)
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let mut good_payload_bytes = bad_payload_bytes.clone();

        // only diff is the address version
        good_payload_bytes[1] = 0x1f;

        let bad_payload: Result<TransactionPayload, _> =
            TransactionPayload::consensus_deserialize(&mut &bad_payload_bytes[..]);
        assert!(bad_payload.is_err());

        let _: TransactionPayload =
            TransactionPayload::consensus_deserialize(&mut &good_payload_bytes[..]).unwrap();

        // contract-call with bad Principal argument
        let bad_payload_bytes = vec![
            TransactionPayloadID::ContractCall as u8,
            // Stacks address
            0x01,
            // address body (0x00000000000000000000)
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // contract name ("hello")
            0x05,
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            // function name ("world")
            0x05,
            0x77,
            0x6f,
            0x72,
            0x6c,
            0x64,
            // arguments (good address)
            // length (1)
            0x00,
            0x00,
            0x00,
            0x01,
            // StandardPrincipalData
            0x05,
            // address version (32 -- bad)
            0x20,
            // address body (0x00000000000000000000)
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let mut good_payload_bytes = bad_payload_bytes.clone();
        good_payload_bytes[39] = 0x1f;

        let bad_payload: Result<TransactionPayload, _> =
            TransactionPayload::consensus_deserialize(&mut &bad_payload_bytes[..]);
        assert!(bad_payload.is_err());

        let _: TransactionPayload =
            TransactionPayload::consensus_deserialize(&mut &good_payload_bytes[..]).unwrap();

        let bad_payload_bytes = vec![
            // payload type ID
            TransactionPayloadID::NakamotoCoinbase as u8,
            // buffer
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            // have contract recipient, so Some(..)
            0x0a,
            // contract address type
            0x06,
            // address (bad version)
            0x20,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            // name length
            0x0c,
            // name ('foo-contract')
            0x66,
            0x6f,
            0x6f,
            0x2d,
            0x63,
            0x6f,
            0x6e,
            0x74,
            0x72,
            0x61,
            0x63,
            0x74,
            // proof bytes
            0x92,
            0x75,
            0xdf,
            0x67,
            0xa6,
            0x8c,
            0x87,
            0x45,
            0xc0,
            0xff,
            0x97,
            0xb4,
            0x82,
            0x01,
            0xee,
            0x6d,
            0xb4,
            0x47,
            0xf7,
            0xc9,
            0x3b,
            0x23,
            0xae,
            0x24,
            0xcd,
            0xc2,
            0x40,
            0x0f,
            0x52,
            0xfd,
            0xb0,
            0x8a,
            0x1a,
            0x6a,
            0xc7,
            0xec,
            0x71,
            0xbf,
            0x9c,
            0x9c,
            0x76,
            0xe9,
            0x6e,
            0xe4,
            0x67,
            0x5e,
            0xbf,
            0xf6,
            0x06,
            0x25,
            0xaf,
            0x28,
            0x71,
            0x85,
            0x01,
            0x04,
            0x7b,
            0xfd,
            0x87,
            0xb8,
            0x10,
            0xc2,
            0xd2,
            0x13,
            0x9b,
            0x73,
            0xc2,
            0x3b,
            0xd6,
            0x9d,
            0xe6,
            0x63,
            0x60,
            0x95,
            0x3a,
            0x64,
            0x2c,
            0x2a,
            0x33,
            0x0a,
        ];

        let mut good_payload_bytes = bad_payload_bytes.clone();
        debug!(
            "index is {:?}",
            good_payload_bytes.iter().find(|x| **x == 0x20)
        );
        good_payload_bytes[35] = 0x1f;

        let bad_payload: Result<TransactionPayload, _> =
            TransactionPayload::consensus_deserialize(&mut &bad_payload_bytes[..]);
        assert!(bad_payload.is_err());

        let _: TransactionPayload =
            TransactionPayload::consensus_deserialize(&mut &good_payload_bytes[..]).unwrap();
    }

    /// Verify that a SIP-034 tenure-extend will be rejected prior to epoch 3.3
    #[test]
    fn process_tenure_change_sip034_rejected_pre_3_3() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();

        let balances = vec![(addr.clone(), 1000000000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let sip034_causes = [
            TenureChangeCause::ExtendedRuntime,
            TenureChangeCause::ExtendedReadCount,
            TenureChangeCause::ExtendedReadLength,
            TenureChangeCause::ExtendedWriteCount,
            TenureChangeCause::ExtendedWriteLength,
        ];

        for (dbi, burn_db) in PRE_33_DBS.iter().enumerate() {
            let mut conn = chainstate.block_begin(
                *burn_db,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([(dbi + 1) as u8; 20]),
                &BlockHeaderHash([(dbi + 1) as u8; 32]),
            );

            for cause in sip034_causes.iter() {
                let mut tx_extend_sip034 = StacksTransaction::new(
                    TransactionVersion::Testnet,
                    auth.clone(),
                    TransactionPayload::TenureChange(TenureChangePayload {
                        tenure_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                        prev_tenure_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                        burn_view_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                        previous_tenure_end: StacksBlockId([0xff; 32]),
                        cause: *cause,
                        previous_tenure_blocks: 0,
                        pubkey_hash: Hash160([0x00; 20]),
                    }),
                );
                tx_extend_sip034.chain_id = 0x80000000;

                let mut signer = StacksTransactionSigner::new(&tx_extend_sip034);
                signer.sign_origin(&privk).unwrap();
                let tx_extend_sip034_signed = signer.get_tx().unwrap();

                // try to process
                let err =
                    process_transaction_for_test(&mut conn, &tx_extend_sip034_signed, false, None)
                        .unwrap_err();

                let expected_msg = format!(
                    "Invalid Stacks transaction: TenureChange cause variant {:?} is not supported in epoch {:?}",
                    cause,
                    conn.get_epoch()
                );

                if let Error::InvalidStacksTransaction(msg, ..) = err {
                    assert_eq!(expected_msg, msg);
                } else {
                    panic!("Got unexpected error {:?}", &err);
                }
            }

            conn.commit_block();
        }
    }

    #[test]
    fn transaction_processor_eval_hook_preserves_transaction_semantics() {
        fn process_contract(
            test_name: &str,
            address: &StacksAddress,
            tx: &StacksTransaction,
            eval_hook: Option<&mut dyn EvalHook>,
        ) -> (StacksTransactionReceipt, StacksAccount, bool) {
            let mut chainstate = TestChainstateBuilder::new_testnet(test_name)
                .with_balances(vec![(address.clone(), 1_000_000_000)])
                .build();
            let mut clarity_tx = chainstate.block_begin(
                &TestBurnStateDB_21,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &ConsensusHash([1u8; 20]),
                &BlockHeaderHash([1u8; 32]),
            );

            let processor = TransactionProcessor::from(TxToProcess::Execute(tx))
                .using_clarity_tx(&mut clarity_tx)
                .with_unlimited_resource_policy();
            let (_, receipt) = match eval_hook {
                Some(eval_hook) => processor.with_eval_hook(eval_hook).process(),
                None => processor.process(),
            }
            .unwrap();

            let account =
                StacksChainState::get_account(&mut clarity_tx, &address.to_account_principal());
            let contract_id = QualifiedContractIdentifier::new(
                address.clone().into(),
                ContractName::from_literal("traceable"),
            );
            let contract_exists = StacksChainState::get_contract(&mut clarity_tx, &contract_id)
                .unwrap()
                .is_some();
            clarity_tx.commit_block();

            (receipt, account, contract_exists)
        }

        let private_key = StacksPrivateKey::random();
        let auth = TransactionAuth::from_p2pkh(&private_key).unwrap();
        let address = auth.origin().address_testnet();
        let contract = r#"
            (define-data-var counter uint u0)
            (define-public (increment)
                (begin
                    (var-set counter (+ (var-get counter) u1))
                    (ok (var-get counter))))
            (+ u1 u2)
        "#;
        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::new_smart_contract(
                "traceable",
                &contract.to_string(),
                Some(ClarityVersion::Clarity1),
            )
            .unwrap(),
        );
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.chain_id = 0x80000000;
        tx.set_tx_fee(1);
        tx.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx);
        signer.sign_origin(&private_key).unwrap();
        let signed_tx = signer.get_tx().unwrap();

        let mut call_trace = CallTraceHook::new();
        let hooked_name = format!("{}-hooked", function_name!());
        let hooked = process_contract(&hooked_name, &address, &signed_tx, Some(&mut call_trace));
        assert!(
            !call_trace.calls().is_empty(),
            "the transaction processor should propagate its eval hook",
        );

        let unhooked_name = format!("{}-unhooked", function_name!());
        let unhooked = process_contract(&unhooked_name, &address, &signed_tx, None);

        assert_eq!(hooked, unhooked);
        assert!(hooked.2, "the published contract should be committed");
    }

    #[test]
    fn transaction_processor_receipt_check_rejection_rolls_back() {
        let private_key = StacksPrivateKey::random();
        let auth = TransactionAuth::from_p2pkh(&private_key).unwrap();
        let sender = auth.origin().address_testnet();
        let recipient = StacksAddress::new(1, Hash160([0x42; 20])).unwrap();
        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            TransactionPayload::TokenTransfer(
                recipient.clone().into(),
                100,
                TokenTransferMemo([0; 34]),
            ),
        );
        tx.chain_id = 0x80000000;
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.set_tx_fee(1);

        let mut signer = StacksTransactionSigner::new(&tx);
        signer.sign_origin(&private_key).unwrap();
        let signed_tx = signer.get_tx().unwrap();

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(vec![(sender.clone(), 1_000)])
            .build();
        let mut clarity_tx = chainstate.block_begin(
            &TestBurnStateDB_21,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1; 20]),
            &BlockHeaderHash([1; 32]),
        );

        let sender_before =
            StacksChainState::get_account(&mut clarity_tx, &sender.to_account_principal());
        let recipient_before =
            StacksChainState::get_account(&mut clarity_tx, &recipient.to_account_principal());
        let cost_before = clarity_tx.cost_so_far();

        let error = TransactionProcessor::from(&signed_tx)
            .using_clarity_tx(&mut clarity_tx)
            .with_unlimited_resource_policy()
            .with_check(|_| Err(Error::BlockCostExceeded))
            .process()
            .unwrap_err();

        assert!(matches!(error, Error::BlockCostExceeded));
        assert_eq!(
            sender_before,
            StacksChainState::get_account(&mut clarity_tx, &sender.to_account_principal()),
        );
        assert_eq!(
            recipient_before,
            StacksChainState::get_account(&mut clarity_tx, &recipient.to_account_principal()),
        );
        assert_eq!(cost_before, clarity_tx.cost_so_far());

        clarity_tx.commit_block();
    }

    #[test]
    fn test_process_transaction_execution_time_expired() {
        let privk = StacksPrivateKey::random();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let balances = vec![(addr.clone(), 1_000_000_000)];

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!())
            .with_balances(balances)
            .build();

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_21, // or whichever Epoch ≥ 2.1 stub fits
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );

        let foo = "
            (define-public (foo)
                (ok true)
            )
            (+ 1 3)
            "
        .to_string();
        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("foo", &foo, Some(ClarityVersion::Clarity1))
                .unwrap(),
        );

        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.chain_id = 0x80000000;
        tx.set_tx_fee(1);
        tx.set_origin_nonce(0);

        let mut signer = StacksTransactionSigner::new(&tx);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let cost_before_deploy = conn.cost_so_far();

        // set max_execution_time to something that will fire on the first eval()
        let err = process_transaction_for_test(
            &mut conn,
            &signed_tx,
            false,
            Some(std::time::Duration::from_nanos(1)),
        )
        .unwrap_err();

        assert!(
            matches!(err, Error::ExecutionResourceBudgetExceeded(_)),
            "expected Error::ExecutionResourceBudgetExceeded, got {err:?}",
        );

        // Exercise the miner-level wrapper: it should classify as Problematic and reset the cost.
        let result = finalize_failed_transaction(&mut conn, &signed_tx, &cost_before_deploy, err);
        assert!(
            matches!(result, TransactionResult::Problematic(_)),
            "expected Problematic verdict, got {result:?}",
        );
        assert_eq!(
            cost_before_deploy,
            conn.cost_so_far(),
            "Expected transaction cost to be reverted on execution time expiry"
        );

        // allow that transaction to be processed with no max_execution_time, so that it gets
        // committed to the chainstate
        process_transaction_for_test(&mut conn, &signed_tx, false, None).unwrap();

        // check that the cost of the transaction was charged this time
        let cost_after_deploy = conn.cost_so_far();
        assert!(
            cost_after_deploy.exceeds(&cost_before_deploy),
            "Expected transaction cost to be charged after successful execution"
        );

        // Make a call to the contract to check the contract-call path also handles execution time
        // expiry correctly
        let mut call_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_contract_call(addr.clone(), "foo", "foo", vec![]).unwrap(),
        );

        call_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        call_tx.chain_id = 0x80000000;
        call_tx.set_tx_fee(1);
        call_tx.set_origin_nonce(1);

        let mut signer = StacksTransactionSigner::new(&call_tx);
        signer.sign_origin(&privk).unwrap();

        let signed_call_tx = signer.get_tx().unwrap();

        let cost_before_call = conn.cost_so_far();
        let err = process_transaction_for_test(
            &mut conn,
            &signed_call_tx,
            false,
            Some(std::time::Duration::from_nanos(1)),
        )
        .unwrap_err();

        assert!(
            matches!(err, Error::ExecutionResourceBudgetExceeded(_)),
            "expected Error::ExecutionResourceBudgetExceeded, got {err:?}",
        );

        // Exercise the miner-level wrapper for the contract-call path too.
        let result =
            finalize_failed_transaction(&mut conn, &signed_call_tx, &cost_before_call, err);
        assert!(
            matches!(result, TransactionResult::Problematic(_)),
            "expected Problematic verdict, got {result:?}",
        );
        assert_eq!(
            cost_before_call,
            conn.cost_so_far(),
            "Expected transaction cost to be reverted on execution time expiry"
        );
    }
}
