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
use crate::core::StacksEpochId;
use crate::cost_estimates::fee_medians::WeightedMedianFeeRateEstimator;
use crate::cost_estimates::metrics::ProportionalDotProduct;
use crate::cost_estimates::FeeRateEstimate;
use crate::types::chainstate::StacksAddress;
use crate::vm::types::{PrincipalData, StandardPrincipalData};
use crate::vm::Value;

const error_epsilon: f64 = 0.1;

/// Returns `true` iff each value in `left` is within `error_epsilon` of the
/// corresponding value in `right`.
fn is_close(left: FeeRateEstimate, right: FeeRateEstimate) -> bool {
        warn!("Checking ExecutionCost's. {:?} vs {:?}", left, right);
    let is_ok = (left.high - right.high).abs() < error_epsilon
        && (left.middle - right.middle).abs() < error_epsilon
        && (left.low - right.low).abs() < error_epsilon;
    if !is_ok {
        warn!("ExecutionCost's are not close. {:?} vs {:?}", left, right);
    }
    is_ok
}

fn instantiate_test_db<CM: CostMetric>(m: CM) -> WeightedMedianFeeRateEstimator<CM> {
    let mut path = env::temp_dir();
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    path.push(&format!("fee_db_{}.sqlite", &to_hex(&random_bytes)[0..8]));

    let window_size = 5;
    WeightedMedianFeeRateEstimator::open(&path, m, window_size)
        .expect("Test failure: could not open fee rate DB")
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
        evaluated_epoch: StacksEpochId::Epoch20,
    }
}

fn make_dummy_coinbase_tx() -> StacksTransaction {
    StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::Coinbase(CoinbasePayload([0; 32])),
    )
}

fn make_dummy_transfer_tx(fee: u64) -> StacksTransactionReceipt {
    let mut tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::TokenTransfer(
            PrincipalData::Standard(StandardPrincipalData(0, [0; 20])),
            1,
            TokenTransferMemo([0; 34]),
        ),
    );
    tx.set_tx_fee(fee);

    StacksTransactionReceipt::from_stx_transfer(
        tx,
        vec![],
        Value::okay(Value::Bool(true)).unwrap(),
        ExecutionCost::zero(),
    )
}

fn make_dummy_cc_tx(fee: u64, execution_cost: &ExecutionCost) -> StacksTransactionReceipt {
    let mut tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::ContractCall(TransactionContractCall {
            address: StacksAddress::new(0, Hash160([0; 20])),
            contract_name: "cc-dummy".into(),
            function_name: "func-name".into(),
            function_args: vec![],
        }),
    );
    tx.set_tx_fee(fee);
    StacksTransactionReceipt::from_contract_call(
        tx,
        vec![],
        Value::okay(Value::Bool(true)).unwrap(),
        0,
        execution_cost.clone(),
    )
}

const block_limit: ExecutionCost = ExecutionCost {
    write_length: 100,
    write_count: 100,
    read_length: 100,
    read_count: 100,
    runtime: 100,
};

const operation_cost: ExecutionCost = ExecutionCost {
    write_length: 10,
    write_count: 10,
    read_length: 10,
    read_count: 10,
    runtime: 10,
};

#[test]
fn test_empty_fee_estimator() {
    let metric = ProportionalDotProduct::new(10_000);
    let estimator = instantiate_test_db(metric);
    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect_err("Empty rate estimator should error."),
        EstimatorError::NoEstimateAvailable
    );
}

/// If we do not have any transactions in a block, we should fill the space
/// with a transaction with fee rate 1f. This means that, for a totally empty
/// block, the fee rate should be 1f.
#[test]
fn test_empty_block_returns_minimum() {
    let metric = ProportionalDotProduct::new(10_000);
    let mut estimator = instantiate_test_db(metric);

    let empty_block_receipt = make_block_receipt(vec![]);
    estimator
        .notify_block(&empty_block_receipt, &block_limit)
        .expect("Should be able to process an empty block");

    assert!(is_close(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 1f64,
            middle: 1f64,
            low: 1f64
        }
    ));
}

#[test]
fn test_single_contract_call() {
    let metric = ProportionalDotProduct::new(10_000);
    let mut estimator = instantiate_test_db(metric);

    // The scalar cost of `make_dummy_cc_tx(_, &operation_cost)`.
    let operation_cost_basis = 5160;
    let single_tx_receipt = make_block_receipt(vec![
        StacksTransactionReceipt::from_coinbase(make_dummy_coinbase_tx()),
        make_dummy_cc_tx(10 * operation_cost_basis, &operation_cost),
    ]);

    estimator
        .notify_block(&single_tx_receipt, &block_limit)
        .expect("Should be able to process block receipt");

    // The higher fee is 10, because that's what we paid.
    // The lower fee is 1 because of the minimum fee rate padding.
    assert!(is_close(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 9.87f64,
            middle: 1.77f64,
            low: 1f64
        }
    ));
}

#[test]
fn test_five_contract_calls() {
    let metric = ProportionalDotProduct::new(10_000);
    let mut estimator = instantiate_test_db(metric);

    for i in 1..6 {
        warn!("i {}", i);
        let single_tx_receipt = make_block_receipt(vec![
            StacksTransactionReceipt::from_coinbase(make_dummy_coinbase_tx()),
            make_dummy_cc_tx(i * 10, &operation_cost),
        ]);

        estimator
            .notify_block(&single_tx_receipt, &block_limit)
            .expect("Should be able to process block receipt");
    }

    // The higher fee is 10, because of the contract.
    // The lower fee is 1 because of the minimum fee rate padding.
    assert!(is_close(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 10f64,
            middle: 10f64,
            low: 1f64
        }
    ));
}

//
//#[test]
//fn test_fee_estimator() {
//    let metric = ProportionalDotProduct;
//    let mut estimator = instantiate_test_db(metric);
//
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect_err("Empty rate estimator should error."),
//        EstimatorError::NoEstimateAvailable,
//        "Empty rate estimator should return no estimate available"
//    );
//
//    let empty_block_receipt = make_block_receipt(vec![]);
//    let block_limit = ExecutionCost::max_value();
//    estimator
//        .notify_block(&empty_block_receipt, &block_limit)
//        .expect("Should be able to process an empty block");
//
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect_err("Empty rate estimator should error."),
//        EstimatorError::NoEstimateAvailable,
//        "Empty block should not update the estimator"
//    );
//
//    let coinbase_only_receipt = make_block_receipt(vec![StacksTransactionReceipt::from_coinbase(
//        make_dummy_coinbase_tx(),
//    )]);
//
//    estimator
//        .notify_block(&coinbase_only_receipt, &block_limit)
//        .expect("Should be able to process an empty block");
//
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect_err("Empty rate estimator should error."),
//        EstimatorError::NoEstimateAvailable,
//        "Coinbase-only block should not update the estimator"
//    );
//
//    let single_tx_receipt = make_block_receipt(vec![
//        StacksTransactionReceipt::from_coinbase(make_dummy_coinbase_tx()),
//        make_dummy_cc_tx(1),
//    ]);
//
//    estimator
//        .notify_block(&single_tx_receipt, &block_limit)
//        .expect("Should be able to process block receipt");
//
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect("Should be able to create estimate now"),
//        FeeRateEstimate {
//            high: 1f64,
//            middle: 1f64,
//            low: 1f64
//        }
//    );
//
//    let double_tx_receipt = make_block_receipt(vec![
//        StacksTransactionReceipt::from_coinbase(make_dummy_coinbase_tx()),
//        make_dummy_cc_tx(1),
//        make_dummy_transfer_tx(10),
//    ]);
//
//    estimator
//        .notify_block(&double_tx_receipt, &block_limit)
//        .expect("Should be able to process block receipt");
//
//    // estimate should increase for "high" and "middle":
//    // 10 * 1/2 + 1 * 1/2 = 5.5
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect("Should be able to create estimate now"),
//        FeeRateEstimate {
//            high: 5.5f64,
//            middle: 5.5f64,
//            low: 1f64
//        }
//    );
//
//    // estimate should increase for "high" and "middle":
//    // new value: 10 * 1/2 + 5.5 * 1/2 = 7.75
//    estimator
//        .notify_block(&double_tx_receipt, &block_limit)
//        .expect("Should be able to process block receipt");
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect("Should be able to create estimate now"),
//        FeeRateEstimate {
//            high: 7.75f64,
//            middle: 7.75f64,
//            low: 1f64
//        }
//    );
//
//    // estimate should increase for "high" and "middle":
//    // new value: 10 * 1/2 + 7.75 * 1/2 = 8.875
//    estimator
//        .notify_block(&double_tx_receipt, &block_limit)
//        .expect("Should be able to process block receipt");
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect("Should be able to create estimate now"),
//        FeeRateEstimate {
//            high: 8.875f64,
//            middle: 8.875f64,
//            low: 1f64
//        }
//    );
//
//    // estimate should increase for "high" and "middle":
//    // new value: 10 * 1/2 + 8.875 * 1/2 = 9.4375
//    estimator
//        .notify_block(&double_tx_receipt, &block_limit)
//        .expect("Should be able to process block receipt");
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect("Should be able to create estimate now"),
//        FeeRateEstimate {
//            high: 9.4375f64,
//            middle: 9.4375f64,
//            low: 1f64
//        }
//    );
//
//    // estimate should increase for "high" and "middle":
//    // new value: 10 * 1/2 + 9.4375 * 1/2 = 9
//    estimator
//        .notify_block(&double_tx_receipt, &block_limit)
//        .expect("Should be able to process block receipt");
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect("Should be able to create estimate now"),
//        FeeRateEstimate {
//            high: 9.71875f64,
//            middle: 9.71875f64,
//            low: 1f64
//        }
//    );
//
//    // make a large block receipt, and expect:
//    //  measured high = 950, middle = 500, low = 50
//    //  new high: 950/2 + 9.71875/2 = 479.859375
//    //  new middle: 500/2 + 9.71875/2 = 254.859375
//    //  new low: 50/2 + 1/2 = 25.5
//
//    let mut receipts: Vec<_> = (0..100).map(|i| make_dummy_cc_tx(i * 10)).collect();
//    let mut rng = rand::thread_rng();
//    receipts.shuffle(&mut rng);
//
//    estimator
//        .notify_block(&make_block_receipt(receipts), &block_limit)
//        .expect("Should be able to process block receipt");
//
//    assert_eq!(
//        estimator
//            .get_rate_estimates()
//            .expect("Should be able to create estimate now"),
//        FeeRateEstimate {
//            high: 479.859375f64,
//            middle: 254.859375f64,
//            low: 25.5f64
//        }
//    );
//}
