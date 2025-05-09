use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks::chainstate::stacks::TenureChangeCause;
use tracing::info;

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;
use crate::tests::signer::v0::{wait_for_block_pushed_by_miner_key, MultipleMinerTest};

/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------

pub struct MineBitcoinBlockTenureChange {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl MineBitcoinBlockTenureChange {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        if miner_index < 1 || miner_index > 2 {
            panic!("Invalid miner index: {}", miner_index);
        }
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for MineBitcoinBlockTenureChange {
    fn check(&self, state: &SignerTestState) -> bool {
        let (conf_1, conf_2) = self.ctx.get_node_configs();
        let conf = match self.miner_index {
            1 => conf_1,
            2 => conf_2,
            _ => panic!("Invalid miner index: {}", self.miner_index),
        };

        let burn_height = get_chain_info(&conf).burn_block_height;

        let (miner_1_submitted_commit_last_burn_height, miner_2_submitted_commit_last_burn_height) = {
            let miners = self.ctx.miners.lock().unwrap();

            let miner_1_height = miners
                .get_primary_submitted_commit_last_burn_height()
                .0
                .load(Ordering::SeqCst);

            let miner_2_height = miners
                .get_secondary_submitted_commit_last_burn_height()
                .0
                .load(Ordering::SeqCst);

            (miner_1_height, miner_2_height)
        };

        let (current_miner_height, other_miner_height) = match self.miner_index {
            1 => (
                miner_1_submitted_commit_last_burn_height,
                miner_2_submitted_commit_last_burn_height,
            ),
            2 => (
                miner_2_submitted_commit_last_burn_height,
                miner_1_submitted_commit_last_burn_height,
            ),
            _ => panic!("Invalid miner index: {}", self.miner_index),
        };

        info!(
            "Checking: Miner {} block verification - burn height: {}, current miner: {}, other miner: {}",
            self.miner_index,
            burn_height,
            current_miner_height,
            other_miner_height
        );

        state.is_booted_to_nakamoto
            && burn_height == current_miner_height
            && burn_height > other_miner_height
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: Miner {} mining Bitcoin block and tenure change tx",
            self.miner_index
        );

        let (stacks_height_before, conf, miner_pk) = {
            let stacks_height_before = self.ctx.get_peer_stacks_tip_height();

            let (conf_1, conf_2) = self.ctx.get_node_configs();
            let conf = match self.miner_index {
                1 => conf_1,
                2 => conf_2,
                _ => panic!("Invalid miner index: {}", self.miner_index),
            };

            let burnchain = conf.get_burnchain();
            let sortdb = burnchain.open_sortition_db(true).unwrap();

            // TODO: Can I make it more elegant?
            self.ctx
                .miners
                .lock()
                .unwrap()
                .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
                .expect("Failed to mine BTC block");

            let (miner_pk_1, miner_pk_2) = self.ctx.get_miner_public_keys();
            let miner_pk = if self.miner_index == 1 {
                miner_pk_1
            } else {
                miner_pk_2
            };

            (stacks_height_before, conf, miner_pk)
        };

        info!(
            "Waiting for Nakamoto block {} pushed by miner {}",
            stacks_height_before + 1,
            self.miner_index
        );

        // This function mines a Nakamoto block
        let miner_block =
            wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk).expect(
                &format!("Failed to get block for miner {}", self.miner_index),
            );

        // FIXME: To remove
        state.increment_blocks_mined_by_miner(self.miner_index);

        let mined_block_height = miner_block.header.chain_length;

        info!(
            "Miner {} mined Nakamoto block height: {}",
            self.miner_index, mined_block_height
        );

        let info_after = get_chain_info(&conf);
        assert_eq!(info_after.stacks_tip, miner_block.header.block_hash());
        assert_eq!(info_after.stacks_tip_height, mined_block_height);
        assert_eq!(mined_block_height, stacks_height_before + 1);
    }

    fn label(&self) -> String {
        format!(
            "MINE_BITCOIN_BLOCK_AND_TENURE_CHANGE_MINER_{}",
            self.miner_index
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(MineBitcoinBlockTenureChange::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}

/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------

pub struct MineBitcoinBlock {
    miners: Arc<Mutex<MultipleMinerTest>>,
    timeout_secs: u64,
}

impl MineBitcoinBlock {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>, timeout_secs: u64) -> Self {
        Self {
            miners,
            timeout_secs,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for MineBitcoinBlock {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!("Checking: Mining tenure. Result: {:?}", true);
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Mining tenure and waiting for it for {:?} seconds",
            self.timeout_secs
        );

        let sortdb = {
            let miners = self.miners.lock().unwrap();
            let (conf_1, _) = miners.get_node_configs();
            let burnchain = conf_1.get_burnchain();
            let sortdb = burnchain.open_sortition_db(true).unwrap();
            sortdb
        };

        {
            let mut miners = self.miners.lock().unwrap();
            miners
                .mine_bitcoin_blocks_and_confirm(&sortdb, 1, self.timeout_secs)
                .expect("Failed to mine BTC block");
        }
    }

    fn label(&self) -> String {
        "MINE_BITCOIN_BLOCK".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (60u64..90u64).prop_map(move |timeout_secs| {
            CommandWrapper::new(MineBitcoinBlock::new(ctx.miners.clone(), timeout_secs))
        })
    }
}

/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------

pub struct BuildNextBitcoinBlocks {
    ctx: Arc<SignerTestContext>,
    num_blocks: u64,
}

impl BuildNextBitcoinBlocks {
    pub fn new(ctx: Arc<SignerTestContext>, num_blocks: u64) -> Self {
        Self { ctx, num_blocks }
    }
}

impl Command<SignerTestState, SignerTestContext> for BuildNextBitcoinBlocks {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Build next {} Bitcoin block(s). Result: {:?}",
            self.num_blocks, true
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Build next {} Bitcoin block(s)", self.num_blocks);

        self.ctx
            .miners
            .lock()
            .unwrap()
            .btc_regtest_controller_mut()
            .build_next_block(self.num_blocks);
    }

    fn label(&self) -> String {
        format!("BUILD_NEXT_{}_BITCOIN_BLOCKS", self.num_blocks)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1u64..=5u64).prop_map(move |num_blocks| {
            CommandWrapper::new(BuildNextBitcoinBlocks::new(ctx.clone(), num_blocks))
        })
    }
}
