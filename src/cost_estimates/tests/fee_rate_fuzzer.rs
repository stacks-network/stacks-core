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
    let mock_estimator = ConstantFeeEstimator {};
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
    let mut fuzzed_estimator =
        FeeRateFuzzer::new_custom_creator(Box::new(mock_estimator), rng_creator, 0.1);

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
            high: 2.053485539282013f64,
            middle: 2.0314342113729524f64,
            low: 2.0436485321167686f64
        },
    );
}
