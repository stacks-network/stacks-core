use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::strategy::Strategy;
use tracing::info;

use super::context::{SignerTestContext, SignerTestState};

/// Command to mine a single Bitcoin block in the test environment and wait for its confirmation.
/// This command simulates the process of mining a new Bitcoin block in the Stacks blockchain
/// testing framework. Unlike the tenure change variant, this command simply advances the
/// Bitcoin chain by one block without explicitly triggering a tenure change transaction.
pub struct MinerMineBitcoinBlocks {
    ctx: Arc<SignerTestContext>,
    num_blocks: u64,
}

impl MinerMineBitcoinBlocks {
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

impl Command<SignerTestState, SignerTestContext> for MinerMineBitcoinBlocks {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!("Checking: Mining tenure. Result: {}", true);
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!("Applying: Mining {} Bitcoin block(s)", self.num_blocks);

        state.last_stacks_block_height = Some(self.ctx.get_peer_stacks_tip_height());

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
        (1u64..5u64).prop_map({
            move |num_blocks| {
                CommandWrapper::new(MinerMineBitcoinBlocks::multiple(ctx.clone(), num_blocks))
            }
        })
    }
}

/// Command to generate a specified number of Bitcoin blocks in the regtest environment.
/// Unlike other mining commands, this command directly instructs the Bitcoin regtest
/// controller to generate between 1-5 blocks without waiting for confirmations or
/// monitoring their effect on the Stacks chain. It represents a low-level operation
/// to advance the Bitcoin chain state.
pub struct ChainGenerateBitcoinBlocks {
    ctx: Arc<SignerTestContext>,
    num_blocks: u64,
}

impl ChainGenerateBitcoinBlocks {
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

impl Command<SignerTestState, SignerTestContext> for ChainGenerateBitcoinBlocks {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Build next {} Bitcoin block(s). Result: {}",
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
        (1u64..=5u64).prop_map({
            move |num_blocks| {
                CommandWrapper::new(ChainGenerateBitcoinBlocks::multiple(
                    ctx.clone(),
                    num_blocks,
                ))
            }
        })
    }
}
