use std::{env, path::PathBuf};
use time::Instant;

use rand::seq::SliceRandom;
use rand::Rng;

use cost_estimates::metrics::CostMetric;
use cost_estimates::{EstimatorError, FeeEstimator};
use vm::costs::ExecutionCost;

use chainstate::burn::ConsensusHash;
use chainstate::stacks::db::{StacksEpochReceipt, StacksHeaderInfo};
use chainstate::stacks::events::StacksTransactionReceipt;
use types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockHeader, StacksWorkScore};
use types::proof::TrieHash;
use util::hash::{to_hex, Hash160, Sha512Trunc256Sum};
use util::vrf::VRFProof;

use crate::chainstate::stacks::{
    CoinbasePayload, StacksTransaction, TokenTransferMemo, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionSpendingCondition, TransactionVersion,
};
use crate::cost_estimates::fee_scalar::ScalarFeeRateEstimator;
use crate::cost_estimates::CostEstimator;
use crate::cost_estimates::FeeRateEstimate;
use crate::cost_estimates::PessimisticEstimator;
use crate::types::chainstate::StacksAddress;
use crate::vm::types::{PrincipalData, StandardPrincipalData};
use crate::vm::Value;

fn instantiate_test_db() -> PessimisticEstimator {
    let mut path = env::temp_dir();
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    path.push(&format!("fee_db_{}.sqlite", &to_hex(&random_bytes)[0..8]));

    PessimisticEstimator::open(&path, true).expect("Test failure: could not open fee rate DB")
}

/// This struct implements a simple metric used for unit testing the
/// the fee rate estimator. It always returns a cost of 1, making the
/// fee rate of a transaction always equal to the paid fee.
struct TestCostMetric;

impl CostMetric for TestCostMetric {
    fn from_cost_and_len(
        &self,
        _cost: &ExecutionCost,
        _block_limit: &ExecutionCost,
        _tx_len: u64,
    ) -> u64 {
        1
    }

    fn from_len(&self, _tx_len: u64) -> u64 {
        1
    }

    fn change_per_byte(&self) -> f64 {
        0f64
    }
}

const BLOCK_LIMIT_MAINNET_STACKS20: ExecutionCost = ExecutionCost {
    write_length: 15_000_000, // roughly 15 mb
    write_count: 7_750,
    read_length: 100_000_000,
    read_count: 7_750,
    runtime: 5_000_000_000,
};

#[test]
fn test_empty_pessimistic_estimator() {
    let estimator = instantiate_test_db();
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_transfer_payload())
            .expect_err("Empty pessimistic estimator should error."),
        EstimatorError::NoEstimateAvailable
    );
}

fn make_block_receipt(tx_receipts: Vec<StacksTransactionReceipt>) -> StacksEpochReceipt {
    StacksEpochReceipt {
        header: StacksHeaderInfo {
            anchored_header: StacksBlockHeader {
                version: 1,
                total_work: StacksWorkScore { burn: 1, work: 1 },
                proof: VRFProof::empty(),
                parent_block: BlockHeaderHash([0; 32]),
                parent_microblock: BlockHeaderHash([0; 32]),
                parent_microblock_sequence: 0,
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash([0; 32]),
                microblock_pubkey_hash: Hash160([0; 20]),
            },
            microblock_tail: None,
            block_height: 1,
            index_root: TrieHash([0; 32]),
            consensus_hash: ConsensusHash([2; 20]),
            burn_header_hash: BurnchainHeaderHash([1; 32]),
            burn_header_height: 2,
            burn_header_timestamp: 2,
            anchored_block_size: 1,
        },
        tx_receipts,
        matured_rewards: vec![],
        matured_rewards_info: None,
        parent_microblocks_cost: ExecutionCost::zero(),
        anchored_block_cost: ExecutionCost::zero(),
        parent_burn_block_hash: BurnchainHeaderHash([0; 32]),
        parent_burn_block_height: 1,
        parent_burn_block_timestamp: 1,
    }
}

fn make_dummy_coinbase_tx() -> StacksTransactionReceipt {
    StacksTransactionReceipt::from_coinbase(StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::Coinbase(CoinbasePayload([0; 32])),
    ))
}

fn make_dummy_transfer_payload() -> TransactionPayload {
    TransactionPayload::TokenTransfer(
        PrincipalData::Standard(StandardPrincipalData(0, [0; 20])),
        1,
        TokenTransferMemo([0; 34]),
    )
}

fn make_dummy_transfer_tx() -> StacksTransactionReceipt {
    let tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::TokenTransfer(
            PrincipalData::Standard(StandardPrincipalData(0, [0; 20])),
            1,
            TokenTransferMemo([0; 34]),
        ),
    );

    StacksTransactionReceipt::from_stx_transfer(
        tx,
        vec![],
        Value::okay(Value::Bool(true)).unwrap(),
        ExecutionCost::zero(),
    )
}

fn make_dummy_cc_tx(
    contract_name: &str,
    function_name: &str,
    execution_cost: ExecutionCost,
) -> StacksTransactionReceipt {
    let tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        make_dummy_cc_payload(contract_name, function_name),
    );

    StacksTransactionReceipt::from_contract_call(
        tx,
        vec![],
        Value::okay(Value::Bool(true)).unwrap(),
        0,
        execution_cost,
    )
}

fn make_dummy_cc_payload(contract_name: &str, function_name: &str) -> TransactionPayload {
    TransactionPayload::ContractCall(TransactionContractCall {
        address: StacksAddress::new(0, Hash160([0; 20])),
        contract_name: contract_name.into(),
        function_name: function_name.into(),
        function_args: vec![],
    })
}

#[test]
fn test_cost_estimator_notify_block() {
    let mut estimator = instantiate_test_db();
    let block = vec![
        make_dummy_coinbase_tx(),
        make_dummy_transfer_tx(),
        make_dummy_transfer_tx(),
        make_dummy_cc_tx(
            "contract-1",
            "func1",
            ExecutionCost {
                write_length: 10,
                write_count: 10,
                read_length: 10,
                read_count: 10,
                runtime: 10,
            },
        ),
    ];
    estimator.notify_block(&block, &BLOCK_LIMIT_MAINNET_STACKS20);

    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 10,
            write_count: 10,
            read_length: 10,
            read_count: 10,
            runtime: 10,
        }
    );
}

#[test]
/// This tests the PessimisticEstimator as a unit (i.e., separate
/// from the trait auto-impl method) by providing payload inputs
/// to produce the expected pessimistic result (i.e., mean over a 10-sample
/// window, where the window only updates if the new entry would make a dimension
/// worse). This tests that the average can decline when the window is still
/// being filled
fn test_pessimistic_cost_estimator_declining_average() {
    let mut estimator = instantiate_test_db();
    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &ExecutionCost {
                write_length: 10,
                write_count: 10,
                read_length: 10,
                read_count: 10,
                runtime: 10,
            },
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 10,
            write_count: 10,
            read_length: 10,
            read_count: 10,
            runtime: 10,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &ExecutionCost {
                write_length: 1,
                write_count: 1,
                read_length: 1,
                read_count: 1,
                runtime: 1,
            },
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 5,
            write_count: 5,
            read_length: 5,
            read_count: 5,
            runtime: 5,
        }
    );
}

#[test]
/// This tests the PessimisticEstimator as a unit (i.e., separate
/// from the trait auto-impl method) by providing payload inputs
/// to produce the expected pessimistic result (i.e., mean over a 10-sample
/// window, where the window only updates if the new entry would make a dimension
/// worse).
fn test_pessimistic_cost_estimator() {
    let mut estimator = instantiate_test_db();
    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &ExecutionCost {
                write_length: 1,
                write_count: 1,
                read_length: 1,
                read_count: 1,
                runtime: 1,
            },
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 1,
            write_count: 1,
            read_length: 1,
            read_count: 1,
            runtime: 1,
        }
    );

    let repeated_cost = ExecutionCost {
        write_length: 9,
        write_count: 5,
        read_length: 3,
        read_count: 1,
        runtime: 1,
    };

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 5,
            write_count: 3,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 2 + 1 = 19 / 3: rounds down to 6
    // 5 * 2 + 1 = 11 / 3: rounds down to 3
    // 3 * 2 + 1 = 7 / 3
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 6,
            write_count: 3,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 3 + 1 = 28 / 4
    // 5 * 3 + 1 = 16 / 4
    // 3 * 3 + 1 = 10 / 4
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 7,
            write_count: 4,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 4 + 1 = 37 / 5
    // 5 * 4 + 1 = 21 / 5
    // 3 * 4 + 1 = 13 / 5
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 7,
            write_count: 4,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 5 + 1 = 46 / 6
    // 5 * 5 + 1 = 26 / 6
    // 3 * 5 + 1 = 16 / 6
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 7,
            write_count: 4,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 6 + 1 = 51 / 7
    // 5 * 6 + 1 = 31 / 7
    // 3 * 6 + 1 = 19 / 7
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 7,
            write_count: 4,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 7 + 1 = 64 / 8
    // 5 * 7 + 1 = 36 / 8
    // 3 * 7 + 1 = 22 / 8
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 8,
            write_count: 4,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 8 + 1 = 73 / 9
    // 5 * 8 + 1 = 41 / 9
    // 3 * 8 + 1 = 25 / 9
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 8,
            write_count: 4,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // the updated dimension estimates should be:
    // 9 * 9 + 1 = 82 / 10
    // 5 * 9 + 1 = 41 / 10
    // 3 * 9 + 1 = 28 / 10
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 8,
            write_count: 4,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );

    // Now, the pessimistic estimator should kick out the minimum measures from the
    // estimate

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &repeated_cost,
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // should just be equal to the repeated cost, because all of the costs in the window are equal
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 9,
            write_count: 5,
            read_length: 3,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator
        .notify_event(
            &make_dummy_cc_payload("contract-1", "func1"),
            &ExecutionCost {
                write_length: 1,
                write_count: 1,
                read_length: 1,
                read_count: 1,
                runtime: 1,
            },
            &BLOCK_LIMIT_MAINNET_STACKS20,
        )
        .expect("Should be able to process event");

    // should still be equal to the repeated cost, because the new event will be ignored
    //  by the pessimistic estimator
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 9,
            write_count: 5,
            read_length: 3,
            read_count: 1,
            runtime: 1,
        }
    );
}
