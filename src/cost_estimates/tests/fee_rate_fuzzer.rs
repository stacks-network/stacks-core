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
use crate::cost_estimates::fee_scalar::ScalarFeeRateEstimator;
use crate::cost_estimates::FeeRateEstimate;
use crate::types::chainstate::StacksAddress;
use crate::vm::types::{PrincipalData, StandardPrincipalData};
use crate::vm::Value;
use cost_estimates::fee_rate_fuzzer::FeeRateFuzzer;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::RngCore;
use rand::SeedableRng;

struct MockFeeEstimator {
    pub receipts: Vec<StacksEpochReceipt>,
}

/// 1) on `notify_block` Inputs are recorded, and not passed anywhere.
/// 2) on `get_rate_estimates`, a constant `FeeRateEstimate` is returned.
impl FeeEstimator for MockFeeEstimator {
    /// Just passes the information straight to `underlying`.
    fn notify_block(
        &mut self,
        receipt: &StacksEpochReceipt,
        block_limit: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        self.receipts.push(receipt.clone());
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
    let mock_estimator = MockFeeEstimator { receipts: vec![] };
    let rng_creator = Box::new(|| {
        let seed = [0u8; 32];
        let rng: StdRng = SeedableRng::from_seed(seed);
        let r: Box<dyn RngCore> = Box::new(rng);
        r
    });
    let fuzzed_estimator =
        FeeRateFuzzer::new_custom_creator(Box::new(mock_estimator), rng_creator, 0.1);

    assert_eq!(
        fuzzed_estimator
            .get_rate_estimates()
            .expect("Estimate should exist."),
        FeeRateEstimate {
            high: 95.01268903765265f64,
            middle: 49.93182838353776f64,
            low: 4.921037454936614f64
        }
    );
}

/// Test the fuzzer using a fixed random seed. Uses a different seed than test_fuzzing_seed1.
#[test]
fn test_fuzzing_seed2() {
    let mock_estimator = MockFeeEstimator { receipts: vec![] };
    let rng_creator = Box::new(|| {
        let seed = [1u8; 32];
        let rng: StdRng = SeedableRng::from_seed(seed);
        let r: Box<dyn RngCore> = Box::new(rng);
        r
    });
    let fuzzed_estimator =
        FeeRateFuzzer::new_custom_creator(Box::new(mock_estimator), rng_creator, 0.1);

    assert_eq!(
        fuzzed_estimator
            .get_rate_estimates()
            .expect("Estimate should exist."),
        FeeRateEstimate {
            high: 95.05348553928201f64,
            middle: 50.031434211372954f64,
            low: 5.043648532116769f64
        }
    );
}
