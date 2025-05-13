use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::time::Duration;

use madhouse::{State, TestContext};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
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
        get_nakamoto_headers(conf)
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

    pub fn _print_counters(&self, miner_index: usize) {
        let counters = self.get_counters_for_miner(miner_index);
        
        println!("=== COUNTERS FOR MINER {} ===", miner_index);
        println!("blocks_processed: {}", counters.blocks_processed.load(Ordering::SeqCst));
        println!("microblocks_processed: {}", counters.microblocks_processed.load(Ordering::SeqCst));
        println!("missed_tenures: {}", counters.missed_tenures.load(Ordering::SeqCst));
        println!("missed_microblock_tenures: {}", counters.missed_microblock_tenures.load(Ordering::SeqCst));
        println!("cancelled_commits: {}", counters.cancelled_commits.load(Ordering::SeqCst));
        println!("sortitions_processed: {}", counters.sortitions_processed.load(Ordering::SeqCst));
        println!("naka_submitted_vrfs: {}", counters.naka_submitted_vrfs.load(Ordering::SeqCst));
        println!("naka_submitted_commits: {}", counters.naka_submitted_commits.load(Ordering::SeqCst));
        println!("naka_submitted_commit_last_burn_height: {}", counters.naka_submitted_commit_last_burn_height.load(Ordering::SeqCst));
        println!("naka_mined_blocks: {}", counters.naka_mined_blocks.load(Ordering::SeqCst));
        println!("naka_rejected_blocks: {}", counters.naka_rejected_blocks.load(Ordering::SeqCst));
        println!("naka_proposed_blocks: {}", counters.naka_proposed_blocks.load(Ordering::SeqCst));
        println!("naka_mined_tenures: {}", counters.naka_mined_tenures.load(Ordering::SeqCst));
        println!("naka_signer_pushed_blocks: {}", counters.naka_signer_pushed_blocks.load(Ordering::SeqCst));
        println!("naka_miner_directives: {}", counters.naka_miner_directives.load(Ordering::SeqCst));
        println!("naka_submitted_commit_last_stacks_tip: {}", counters.naka_submitted_commit_last_stacks_tip.load(Ordering::SeqCst));
        println!("naka_submitted_commit_last_commit_amount: {}", counters.naka_submitted_commit_last_commit_amount.load(Ordering::SeqCst));
        println!("naka_miner_current_rejections: {}", counters.naka_miner_current_rejections.load(Ordering::SeqCst));
        println!("naka_miner_current_rejections_timeout_secs: {}", counters.naka_miner_current_rejections_timeout_secs.load(Ordering::SeqCst));
        println!("naka_skip_commit_op: {}", counters.naka_skip_commit_op.get());
        println!("==============================");
    }
}

#[derive(Debug, Default)]
pub struct SignerTestState {
    // Setted by: BootToEpoch3
    // Gotten by: BootToEpoch3, MineBitcoinBlockAndTenureChange
    pub is_booted_to_nakamoto: bool,

    // Setted by: StacksMining
    // Gotten by: StacksMining, WaitForNakamotoBlock
    pub mining_stalled: bool,

    // Setted by: BootToEpoch3
    // Gotten by: VerifyBlockCountAfterBootToEpoch3
    pub epoch_3_start_block_height: Option<u64>,

    // Setted by: WaitForBlockProposal
    // Gotten by: WaitForBlockRejectionWithRejectReason
    pub last_block_hash: Option<Sha512Trunc256Sum>,

    // Setted by: MineBitcoinBlockAndTenureChange
    // Gotten by: WaitForNakamotoBlock
    pub last_block_height: Option<u64>,
}

impl SignerTestState {}

impl State for SignerTestState {}