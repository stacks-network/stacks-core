use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use madhouse::{State, TestContext};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::config::Config as NeonConfig;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util::hash::Hash160;

use crate::neon::Counters;
use crate::stacks_common::types::PublicKey;
use crate::tests::signer::v0::{get_nakamoto_headers, MultipleMinerTest};

#[derive(Clone)]
pub struct SignerTestContext {
    pub miners: Arc<Mutex<MultipleMinerTest>>,
    num_signers: usize,
    num_transfer_txs: u64,
}

impl Debug for SignerTestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerTestContext")
            .field("num_signers", &self.num_signers)
            .field("num_transfer_txs", &self.num_transfer_txs)
            .finish()
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
            num_signers,
            num_transfer_txs,
        }
    }

    // Getter for num_signers
    pub fn get_num_signers(&self) -> usize {
        self.num_signers
    }

    // Getter for num_transfer_txs
    #[allow(dead_code)]
    pub fn get_num_transfer_txs(&self) -> u64 {
        self.num_transfer_txs
    }

    pub fn get_counters_for_miner(&self, miner_index: usize) -> Counters {
        self.miners
            .lock()
            .unwrap()
            .get_counters_for_miner(miner_index)
    }

    pub fn get_node_config(&self, miner_index: usize) -> NeonConfig {
        let configs = self.miners.lock().unwrap().get_node_configs();
        match miner_index {
            1 => configs.0,
            2 => configs.1,
            _ => panic!("Invalid miner_index: {}", miner_index),
        }
    }

    pub fn get_miner_public_key(&self, miner_index: usize) -> StacksPublicKey {
        let keys = self.miners.lock().unwrap().get_miner_public_keys();
        match miner_index {
            1 => keys.0,
            2 => keys.1,
            _ => panic!("Invalid miner_index: {}", miner_index),
        }
    }

    pub fn get_miner_public_key_hash(&self, miner_index: usize) -> Hash160 {
        let hashes = self.miners.lock().unwrap().get_miner_public_key_hashes();
        match miner_index {
            1 => hashes.0,
            2 => hashes.1,
            _ => panic!("Invalid miner_index: {}", miner_index),
        }
    }

    pub fn get_peer_stacks_tip_height(&self) -> u64 {
        self.miners.lock().unwrap().get_peer_stacks_tip_height()
    }

    pub fn get_sortition_db(&self, miner_index: usize) -> SortitionDB {
        let conf = self.get_node_config(miner_index);
        let burnchain = conf.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();
        sortdb
    }

    pub fn get_miner_blocks_after_specified_block_height(
        &self,
        conf: &NeonConfig,
        start_block_height: u64,
        miner_pk: &StacksPublicKey,
    ) -> usize {
        get_nakamoto_headers(
            conf,
            self.miners
                .try_lock()
                .expect("mutex poisoned")
                .get_test_observer(),
        )
        .into_iter()
        .filter(|block| {
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
    pub last_stacks_block_height: Option<u64>,
}

impl SignerTestState {}

impl State for SignerTestState {}
