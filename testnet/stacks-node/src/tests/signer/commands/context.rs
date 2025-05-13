use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use madhouse::{State, TestContext};
use stacks::config::Config as NeonConfig;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util::hash::{Hash160, Sha512Trunc256Sum};

use crate::neon::Counters;
use crate::stacks_common::types::PublicKey;
use crate::tests::signer::v0::{get_nakamoto_headers, MultipleMinerTest};

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

    pub fn get_counters_for_miner(&self, miner_index: usize) -> Counters {
        self.miners
            .lock()
            .unwrap()
            .get_counters_for_miner(miner_index)
    }

    pub fn get_node_configs(&self) -> (NeonConfig, NeonConfig) {
        self.miners.lock().unwrap().get_node_configs()
    }

    pub fn get_peer_stacks_tip_height(&self) -> u64 {
        self.miners.lock().unwrap().get_peer_stacks_tip_height()
    }

    pub fn get_miner_public_keys(&self) -> (StacksPublicKey, StacksPublicKey) {
        self.miners.lock().unwrap().get_miner_public_keys()
    }

    pub fn get_miner_public_key_hashes(&self) -> (Hash160, Hash160) {
        self.miners.lock().unwrap().get_miner_public_key_hashes()
    }

    pub fn get_miner_blocks_after_specified_block_height(
        &self,
        conf: &NeonConfig,
        start_block_height: u64,
        miner_pk: &StacksPublicKey,
    ) -> usize {
        get_nakamoto_headers(conf)
            .into_iter()
            .filter(|block| {
                // TODO: Before it was ==
                // Does it make sense to do <= to exclude previous blocks also?
                if block.stacks_block_height <= start_block_height {
                    return false;
                }
                let nakamoto_block_header = block.anchored_header.as_stacks_nakamoto().unwrap();
                miner_pk
                    .verify(
                        nakamoto_block_header.miner_signature_hash().as_bytes(),
                        &nakamoto_block_header.miner_signature,
                    )
                    .unwrap()
            })
            .count()
    }
}

#[derive(Debug, Default)]
pub struct SignerTestState {
    pub is_booted_to_nakamoto: bool,
    pub mining_stalled: bool,
    pub epoch_3_start_block_height: Option<u64>,
    pub last_block_hash: Option<Sha512Trunc256Sum>,
}

impl SignerTestState {}

impl State for SignerTestState {}
