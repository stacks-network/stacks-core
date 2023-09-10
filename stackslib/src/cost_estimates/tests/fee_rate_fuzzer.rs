use clarity::vm::costs::ExecutionCost;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::RngCore;
use rand::SeedableRng;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};

use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::db::{StacksEpochReceipt, StacksHeaderInfo};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::{
    CoinbasePayload, StacksTransaction, TokenTransferMemo, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionSpendingCondition, TransactionVersion,
};
use crate::core::StacksEpochId;
use crate::cost_estimates::fee_rate_fuzzer::FeeRateFuzzer;
use crate::cost_estimates::tests::common::make_block_receipt;
use crate::cost_estimates::FeeRateEstimate;
use crate::cost_estimates::{EstimatorError, FeeEstimator};

struct ConstantFeeEstimator {}

/// Returns a constant fee rate estimate.
impl FeeEstimator for ConstantFeeEstimator {
    fn notify_block(
        &mut self,
        receipt: &StacksEpochReceipt,
        block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        Ok(())
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        Ok(FeeRateEstimate {
            high: 95f64,
            middle: 50f64,
            low: 5f64,
        })
    }
}

/// Test the fuzzer using a fixed random seed.
#[test]
fn test_fuzzing_seed1() {
    let mock_estimator = ConstantFeeEstimator {};
    let rng_creator = Box::new(|| {
        let seed = [0u8; 32];
        let rng: StdRng = SeedableRng::from_seed(seed);
        let r: Box<dyn RngCore> = Box::new(rng);
        r
    });
    let fuzzed_estimator = FeeRateFuzzer::new_custom_creator(mock_estimator, rng_creator, 0.1);

    assert_eq!(
        fuzzed_estimator
            .get_rate_estimates()
            .expect("Estimate should exist."),
        FeeRateEstimate {
            high: 96.20545857700169f64,
            middle: 50.63445188263247f64,
            low: 5.0634451882632465f64
        }
    );
}

/// Test the fuzzer using a fixed random seed. Uses a different seed than test_fuzzing_seed1.
#[test]
fn test_fuzzing_seed2() {
    let mock_estimator = ConstantFeeEstimator {};
    let rng_creator = Box::new(|| {
        let seed = [1u8; 32];
        let rng: StdRng = SeedableRng::from_seed(seed);
        let r: Box<dyn RngCore> = Box::new(rng);
        r
    });
    let fuzzed_estimator = FeeRateFuzzer::new_custom_creator(mock_estimator, rng_creator, 0.1);

    assert_eq!(
        fuzzed_estimator
            .get_rate_estimates()
            .expect("Estimate should exist."),
        FeeRateEstimate {
            high: 100.08112623179122f64,
            middle: 52.67427696410064f64,
            low: 5.267427696410064f64
        }
    );
}

struct CountingFeeEstimator {
    counter: u64,
}

/// This class "counts" the number of times `notify_block` has been called, and returns this as the
/// estimate.
impl FeeEstimator for CountingFeeEstimator {
    fn notify_block(
        &mut self,
        receipt: &StacksEpochReceipt,
        block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        self.counter += 1;
        Ok(())
    }

    fn get_rate_estimates(&self) -> Result<FeeRateEstimate, EstimatorError> {
        Ok(FeeRateEstimate {
            high: self.counter as f64,
            middle: self.counter as f64,
            low: self.counter as f64,
        })
    }
}

/// Tests that the receipt is passed through in `notify_block`.
#[test]
fn test_notify_pass_through() {
    let mock_estimator = CountingFeeEstimator { counter: 0 };
    let rng_creator = Box::new(|| {
        let seed = [1u8; 32];
        let rng: StdRng = SeedableRng::from_seed(seed);
        let r: Box<dyn RngCore> = Box::new(rng);
        r
    });
    let mut fuzzed_estimator = FeeRateFuzzer::new_custom_creator(mock_estimator, rng_creator, 0.1);

    let receipt = make_block_receipt(vec![]);
    fuzzed_estimator
        .notify_block(&receipt, &ExecutionCost::max_value())
        .expect("notify_block should succeed here.");
    fuzzed_estimator
        .notify_block(&receipt, &ExecutionCost::max_value())
        .expect("notify_block should succeed here.");

    // We've called `notify_block` twice, so the values returned are 2f, with some noise from the
    // fuzzer.
    assert_eq!(
        fuzzed_estimator
            .get_rate_estimates()
            .expect("Estimate should exist."),
        FeeRateEstimate {
            high: 2.1069710785640257f64,
            middle: 2.1069710785640257f64,
            low: 2.1069710785640257f64
        },
    );
}
