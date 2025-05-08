use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::collections::HashMap;

use madhouse::{State, TestContext};

use crate::tests::signer::v0::MultipleMinerTest;

#[derive(Clone)]
pub struct SignerTestContext {
    pub miners: Arc<Mutex<MultipleMinerTest>>,
}

impl Debug for SignerTestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerTestContext").finish()
    }
}

impl TestContext for SignerTestContext {}

impl SignerTestContext {
    pub fn new(num_signers: usize, num_transfer_txs: u64) -> Self {
        let miners = MultipleMinerTest::new_with_config_modifications(
            num_signers,
            num_transfer_txs,
            |signer_config| {
                signer_config.block_proposal_validation_timeout = Duration::from_secs(1800);
                signer_config.tenure_last_block_proposal_timeout = Duration::from_secs(1800);
                signer_config.first_proposal_burn_block_timing = Duration::from_secs(1800);
            },
            |config| {
                config.miner.block_commit_delay = Duration::from_secs(0);
            },
            |config| {
                config.miner.block_commit_delay = Duration::from_secs(0);
            },
        );

        Self {
            miners: Arc::new(Mutex::new(miners)),
        }
    }

    pub fn get_miner_skip_commit_flag(
        &self,
        miner_index: usize,
    ) -> stacks::util::tests::TestFlag<bool> {
        let miners = self.miners.lock().unwrap();
        match miner_index {
            1 => miners.get_primary_skip_commit_flag(),
            2 => miners.get_secondary_skip_commit_flag(),
            _ => panic!(
                "Invalid miner index: {}. Only miners 1 and 2 are supported.",
                miner_index
            ),
        }
    }

    //TODO: pub fn get_miner_counters() -> 
}

type StacksHeightBefore = u64;
type TxId = String;

#[derive(Debug, Default)]
pub struct SignerTestState {
    pub is_booted_to_nakamoto: bool,
    //TODO: Use a hashmap
    pub is_primary_miner_skip_commit_op: bool,
    pub is_secondary_miner_skip_commit_op: bool,

    pub mining_stalled: bool,
    pub transfer_txs_submitted: Vec<(StacksHeightBefore, TxId)>,
    pub blocks_mined_per_miner: HashMap<usize, usize>,
}

impl SignerTestState {
    // Get total blocks mined across all miners
    pub fn get_total_blocks_mined(&self) -> usize {
        self.blocks_mined_per_miner.values().sum()
    }
    
    // Get blocks mined by a specific miner
    pub fn get_blocks_mined_by_miner(&self, miner_index: usize) -> usize {
        *self.blocks_mined_per_miner.get(&miner_index).unwrap_or(&0)
    }
    
    // Increment blocks mined by a specific miner
    pub fn increment_blocks_mined_by_miner(&mut self, miner_index: usize) {
        *self.blocks_mined_per_miner.entry(miner_index).or_insert(0) += 1;
    }
}

impl State for SignerTestState {}