use std::num;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks::chainstate::stacks::TenureChangeCause;
use tracing::info;

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;

/// Command to mine a new Bitcoin block and trigger a tenure change for a specified miner.
/// This command simulates the process of a miner finding a Bitcoin block, submitting a tenure
/// change transaction, and then mining a corresponding Stacks Nakamoto block.
pub struct MinerMineBlockAndTriggerTenureChange {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl MinerMineBlockAndTriggerTenureChange {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for MinerMineBlockAndTriggerTenureChange {
    fn check(&self, state: &SignerTestState) -> bool {
        let conf = self.ctx.get_node_config(self.miner_index);
        let burn_height = get_chain_info(&conf).burn_block_height;

        let (miner_1_submitted_commit_last_burn_height, miner_2_submitted_commit_last_burn_height) = {
            let miner_1_height = self
                .ctx
                .get_counters_for_miner(1)
                .naka_submitted_commit_last_burn_height
                .load(Ordering::SeqCst);
            let miner_2_height = self
                .ctx
                .get_counters_for_miner(2)
                .naka_submitted_commit_last_burn_height
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
        info!("Applying: Mining Bitcoin block and tenure change tx");

        state.last_block_height = Some(self.ctx.get_peer_stacks_tip_height());

        let sortdb = self.ctx.get_sortition_db(self.miner_index);

        self.ctx
            .miners
            .lock()
            .unwrap()
            .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
            .expect("Failed to mine BTC block");
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
            Just(CommandWrapper::new(
                MinerMineBlockAndTriggerTenureChange::new(ctx.clone(), miner_index),
            ))
        })
    }
}

/// Command to mine a single Bitcoin block in the test environment and wait for its confirmation.
/// This command simulates the process of mining a new Bitcoin block in the Stacks blockchain
/// testing framework. Unlike the tenure change variant, this command simply advances the
/// Bitcoin chain by one block without explicitly triggering a tenure change transaction.
pub struct MinerMineBtcBlocks {
    ctx: Arc<SignerTestContext>,
    num_blocks: u64,
}

impl MinerMineBtcBlocks {
    fn new(ctx: Arc<SignerTestContext>, num_blocks: u64) -> Self {
        Self {
            ctx,
            num_blocks,
        }
    }

    pub fn one(ctx: Arc<SignerTestContext>) -> Self {
        Self::new(ctx, 1)
    }

    pub fn multiple(ctx: Arc<SignerTestContext>, num_blocks: u64) -> Self {
        Self::new(ctx, num_blocks)
    }
}

impl Command<SignerTestState, SignerTestContext> for MinerMineBtcBlocks {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!("Checking: Mining tenure. Result: {:?}", true);
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Mining {} Bitcoin block(s)",
            self.num_blocks
        );

        // We can use miner 1 sortition db - it's the same for both miners
        let sortdb = self.ctx.get_sortition_db(1);

        self.ctx
            .miners
            .lock()
            .unwrap()
            .mine_bitcoin_blocks_and_confirm(&sortdb, self.num_blocks, 30)
            .expect("Failed to mine BTC block");
    }

    fn label(&self) -> String {
        format!("MINE_{}_BITCOIN_BLOCK(S)", self.num_blocks)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        use proptest::prelude::*;
        prop_oneof![
            Just(CommandWrapper::new(MinerMineBtcBlocks::one(ctx.clone()))),
            (2u64..5u64).prop_map({
                let ctx = ctx.clone();
                move |num_blocks| {
                    CommandWrapper::new(MinerMineBtcBlocks::multiple(ctx.clone(), num_blocks))
                }
            })
        ]
    }
}

/// Command to generate a specified number of Bitcoin blocks in the regtest environment.
/// Unlike other mining commands, this command directly instructs the Bitcoin regtest
/// controller to generate between 1-5 blocks without waiting for confirmations or
/// monitoring their effect on the Stacks chain. It represents a low-level operation
/// to advance the Bitcoin chain state.
pub struct ChainGenerateBtcBlocks {
    ctx: Arc<SignerTestContext>,
    num_blocks: u64,
}

impl ChainGenerateBtcBlocks {
    fn new(ctx: Arc<SignerTestContext>, num_blocks: u64) -> Self {
        Self { ctx, num_blocks }
    }

    pub fn one(ctx: Arc<SignerTestContext>) -> Self {
        Self::new(ctx, 1)
    }

    pub fn multiple(ctx: Arc<SignerTestContext>, num_blocks: u64) -> Self {
        Self::new(ctx, num_blocks)
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainGenerateBtcBlocks {
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
        use proptest::prelude::*;
        prop_oneof![
            Just(CommandWrapper::new(ChainGenerateBtcBlocks::one(ctx.clone()))),
            (2u64..=5u64).prop_map({
                let ctx = ctx.clone();
                move |num_blocks| {
                    CommandWrapper::new(ChainGenerateBtcBlocks::multiple(ctx.clone(), num_blocks))
                }
            })
        ]
    }
}