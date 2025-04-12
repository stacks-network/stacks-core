use crate::tests::signer::v0::MultipleMinerTest;
use madhouse::{State, TestContext};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct SignerTestContext {
    pub miners: Arc<Mutex<MultipleMinerTest>>,
}

impl Debug for SignerTestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerTestContext").finish()
    }
}

impl Clone for SignerTestContext {
    fn clone(&self) -> Self {
        Self {
            miners: self.miners.clone(),
        }
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
}

#[derive(Debug, Default)]
pub struct SignerTestState {
    pub is_booted_to_nakamoto: bool,
    pub is_primary_miner_skip_commit_op: bool,
    pub is_secondary_miner_skip_commit_op: bool,
    pub mining_stalled: bool,
}

impl State for SignerTestState {}
