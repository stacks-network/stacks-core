use std::env;
use std::path::PathBuf;

use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use clarity::vm::Value;
use rand::seq::SliceRandom;
use rand::Rng;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksWorkScore, TrieHash,
};
use stacks_common::util::hash::{to_hex, Hash160, Sha512Trunc256Sum};
use stacks_common::util::vrf::VRFProof;
use time::Instant;

use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::db::{StacksEpochReceipt, StacksHeaderInfo};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::{
    CoinbasePayload, StacksBlockHeader, StacksTransaction, TokenTransferMemo, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionSpendingCondition, TransactionVersion,
};
use crate::core::StacksEpochId;
use crate::cost_estimates::fee_scalar::ScalarFeeRateEstimator;
use crate::cost_estimates::metrics::CostMetric;
use crate::cost_estimates::tests::common::make_block_receipt;
use crate::cost_estimates::{EstimatorError, FeeEstimator, FeeRateEstimate};

fn instantiate_test_db<CM: CostMetric>(m: CM) -> ScalarFeeRateEstimator<CM> {
    let mut path = env::temp_dir();
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    path.push(&format!("fee_db_{}.sqlite", &to_hex(&random_bytes)[0..8]));

    ScalarFeeRateEstimator::open(&path, m).expect("Test failure: could not open fee rate DB")
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

#[test]
fn test_empty_fee_estimator() {
    let metric = TestCostMetric;
    let estimator = instantiate_test_db(metric);
    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect_err("Empty rate estimator should error."),
        EstimatorError::NoEstimateAvailable
    );
}

fn make_dummy_coinbase_tx() -> StacksTransaction {
    StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None, None),
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

fn make_dummy_cc_tx(fee: u64) -> StacksTransactionReceipt {
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
        ExecutionCost::zero(),
    )
}

#[test]
fn test_fee_estimator() {
    let metric = TestCostMetric;
    let mut estimator = instantiate_test_db(metric);

    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect_err("Empty rate estimator should error."),
        EstimatorError::NoEstimateAvailable,
        "Empty rate estimator should return no estimate available"
    );

    let empty_block_receipt = make_block_receipt(vec![]);
    let block_limit = ExecutionCost::max_value();
    estimator
        .notify_block(&empty_block_receipt, &block_limit)
        .expect("Should be able to process an empty block");

    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect_err("Empty rate estimator should error."),
        EstimatorError::NoEstimateAvailable,
        "Empty block should not update the estimator"
    );

    let coinbase_only_receipt = make_block_receipt(vec![StacksTransactionReceipt::from_coinbase(
        make_dummy_coinbase_tx(),
    )]);

    estimator
        .notify_block(&coinbase_only_receipt, &block_limit)
        .expect("Should be able to process an empty block");

    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect_err("Empty rate estimator should error."),
        EstimatorError::NoEstimateAvailable,
        "Coinbase-only block should not update the estimator"
    );

    let single_tx_receipt = make_block_receipt(vec![
        StacksTransactionReceipt::from_coinbase(make_dummy_coinbase_tx()),
        make_dummy_cc_tx(1),
    ]);

    estimator
        .notify_block(&single_tx_receipt, &block_limit)
        .expect("Should be able to process block receipt");

    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 1f64,
            middle: 1f64,
            low: 1f64
        }
    );

    let double_tx_receipt = make_block_receipt(vec![
        StacksTransactionReceipt::from_coinbase(make_dummy_coinbase_tx()),
        make_dummy_cc_tx(1),
        make_dummy_transfer_tx(10),
    ]);

    estimator
        .notify_block(&double_tx_receipt, &block_limit)
        .expect("Should be able to process block receipt");

    // estimate should increase for "high" and "middle":
    // 10 * 1/2 + 1 * 1/2 = 5.5
    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 5.5f64,
            middle: 5.5f64,
            low: 1f64
        }
    );

    // estimate should increase for "high" and "middle":
    // new value: 10 * 1/2 + 5.5 * 1/2 = 7.75
    estimator
        .notify_block(&double_tx_receipt, &block_limit)
        .expect("Should be able to process block receipt");
    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 7.75f64,
            middle: 7.75f64,
            low: 1f64
        }
    );

    // estimate should increase for "high" and "middle":
    // new value: 10 * 1/2 + 7.75 * 1/2 = 8.875
    estimator
        .notify_block(&double_tx_receipt, &block_limit)
        .expect("Should be able to process block receipt");
    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 8.875f64,
            middle: 8.875f64,
            low: 1f64
        }
    );

    // estimate should increase for "high" and "middle":
    // new value: 10 * 1/2 + 8.875 * 1/2 = 9.4375
    estimator
        .notify_block(&double_tx_receipt, &block_limit)
        .expect("Should be able to process block receipt");
    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 9.4375f64,
            middle: 9.4375f64,
            low: 1f64
        }
    );

    // estimate should increase for "high" and "middle":
    // new value: 10 * 1/2 + 9.4375 * 1/2 = 9
    estimator
        .notify_block(&double_tx_receipt, &block_limit)
        .expect("Should be able to process block receipt");
    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 9.71875f64,
            middle: 9.71875f64,
            low: 1f64
        }
    );

    // make a large block receipt, and expect:
    //  measured high = 950, middle = 500, low = 50
    //  new high: 950/2 + 9.71875/2 = 479.859375
    //  new middle: 500/2 + 9.71875/2 = 254.859375
    //  new low: 50/2 + 1/2 = 25.5

    let mut receipts: Vec<_> = (0..100).map(|i| make_dummy_cc_tx(i * 10)).collect();
    let mut rng = rand::thread_rng();
    receipts.shuffle(&mut rng);

    estimator
        .notify_block(&make_block_receipt(receipts), &block_limit)
        .expect("Should be able to process block receipt");

    assert_eq!(
        estimator
            .get_rate_estimates()
            .expect("Should be able to create estimate now"),
        FeeRateEstimate {
            high: 479.859375f64,
            middle: 254.859375f64,
            low: 25.5f64
        }
    );
}
