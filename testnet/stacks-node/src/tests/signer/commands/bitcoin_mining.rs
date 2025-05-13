use std::sync::atomic::Ordering;
use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks::chainstate::stacks::TenureChangeCause;
use tracing::info;

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;
use crate::tests::signer::v0::wait_for_block_pushed_by_miner_key;

/// Command to mine a new Bitcoin block and trigger a tenure change for a specified miner.
/// This command simulates the process of a miner finding a Bitcoin block, submitting a tenure
/// change transaction, and then mining a corresponding Stacks Nakamoto block.
pub struct MineBitcoinBlockTenureChangeAndWaitForNakamotoBlock {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl MineBitcoinBlockTenureChangeAndWaitForNakamotoBlock {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext>
    for MineBitcoinBlockTenureChangeAndWaitForNakamotoBlock
{
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

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Miner {} mining Bitcoin block and tenure change tx",
            self.miner_index
        );

        let stacks_height_before = self.ctx.get_peer_stacks_tip_height();
        let sortdb = self.ctx.get_sortition_db(self.miner_index);

        self.ctx
            .miners
            .lock()
            .unwrap()
            .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
            .expect("Failed to mine BTC block");

        // TODO: We already have the 'WaitForTenureChangeBlock' command, perhalps this is where this command can stop
        // 'WaitForTenureChangeBlock' command calculates the expected height from the last confirmed block for the specified miner - is that ok?

        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);

        let miner_block =
            wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk).expect(
                &format!("Failed to get block for miner {}", self.miner_index),
            );

        let mined_block_height = miner_block.header.chain_length;

        info!(
            "Miner {} mined Nakamoto block height: {}",
            self.miner_index, mined_block_height
        );

        let conf = self.ctx.get_node_config(self.miner_index);
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
            Just(CommandWrapper::new(
                MineBitcoinBlockTenureChangeAndWaitForNakamotoBlock::new(ctx.clone(), miner_index),
            ))
        })
    }
}

/// Command to mine a single Bitcoin block in the test environment and wait for its confirmation.
/// This command simulates the process of mining a new Bitcoin block in the Stacks blockchain
/// testing framework. Unlike the tenure change variant, this command simply advances the
/// Bitcoin chain by one block without explicitly triggering a tenure change transaction.
pub struct MineBitcoinBlock {
    ctx: Arc<SignerTestContext>,
    timeout_secs: u64,
}

impl MineBitcoinBlock {
    pub fn new(ctx: Arc<SignerTestContext>, timeout_secs: u64) -> Self {
        Self { ctx, timeout_secs }
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

        // We can use miner 1 sortition db - it's the same for both miners
        let sortdb = self.ctx.get_sortition_db(1);

        {
            self.ctx
                .miners
                .lock()
                .unwrap()
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
            CommandWrapper::new(MineBitcoinBlock::new(ctx.clone(), timeout_secs))
        })
    }
}

/// Command to generate a specified number of Bitcoin blocks in the regtest environment.
///
/// Unlike other mining commands, this command directly instructs the Bitcoin regtest
/// controller to generate between 1-5 blocks without waiting for confirmations or
/// monitoring their effect on the Stacks chain. It represents a low-level operation
/// to advance the Bitcoin chain state.
///
/// The command:
/// 1. Accesses the Bitcoin regtest controller
/// 2. Retrieves the configured mining public key
/// 3. Generates the specified number of blocks to the corresponding address
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
