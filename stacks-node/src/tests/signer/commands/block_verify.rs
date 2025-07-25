use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::context::{SignerTestContext, SignerTestState};

/// Command to verify that a specified miner has produced the expected number of blocks
/// based on different height calculation strategies.
pub struct ChainVerifyMinerNakaBlockCount {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    expected_block_count: usize,
    height_strategy: HeightStrategy,
}

#[derive(Debug)]
enum HeightStrategy {
    AfterBootToEpoch3,
    #[allow(dead_code)]
    AfterSpecificHeight(u64),
}

impl ChainVerifyMinerNakaBlockCount {
    fn new(
        ctx: Arc<SignerTestContext>,
        miner_index: usize,
        expected_block_count: usize,
        height_strategy: HeightStrategy,
    ) -> Self {
        Self {
            ctx,
            miner_index,
            expected_block_count,
            height_strategy,
        }
    }

    pub fn after_boot_to_epoch3(
        ctx: Arc<SignerTestContext>,
        miner_index: usize,
        expected_block_count: usize,
    ) -> Self {
        Self::new(
            ctx,
            miner_index,
            expected_block_count,
            HeightStrategy::AfterBootToEpoch3,
        )
    }

    #[allow(dead_code)]
    pub fn after_specific_height(
        ctx: Arc<SignerTestContext>,
        miner_index: usize,
        expected_block_count: usize,
        height: u64,
    ) -> Self {
        Self::new(
            ctx,
            miner_index,
            expected_block_count,
            HeightStrategy::AfterSpecificHeight(height),
        )
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainVerifyMinerNakaBlockCount {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner {} block count. Result: {}",
            self.miner_index, true
        );
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: Verifying miner {} block count is {} - Strategy: {:?}",
            self.miner_index, self.expected_block_count, self.height_strategy
        );

        let conf = self.ctx.get_node_config(self.miner_index);
        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);

        let miner_blocks_after_height = match self.height_strategy {
            HeightStrategy::AfterBootToEpoch3 => {
                self.ctx.get_miner_blocks_after_specified_block_height(
                    &conf,
                    state.epoch_3_start_block_height.unwrap(),
                    &miner_pk,
                )
            }
            HeightStrategy::AfterSpecificHeight(height) => self
                .ctx
                .get_miner_blocks_after_specified_block_height(&conf, height, &miner_pk),
        };

        assert_eq!(
            self.expected_block_count,
            miner_blocks_after_height,
            "Expected {} blocks from miner {} after {:?}, but found {}",
            self.expected_block_count,
            self.miner_index,
            self.height_strategy,
            miner_blocks_after_height
        );

        info!(
            "Verified miner {} has exactly {} blocks after {:?}",
            self.miner_index, self.expected_block_count, self.height_strategy
        );
    }

    fn label(&self) -> String {
        format!(
            "VERIFY_MINER_{}_BLOCK_COUNT_{:?}",
            self.miner_index, self.height_strategy
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize, 1usize..=5usize).prop_map(move |(miner_index, expected_block_count)| {
            CommandWrapper::new(ChainVerifyMinerNakaBlockCount::after_boot_to_epoch3(
                ctx.clone(),
                miner_index,
                expected_block_count,
            ))
        })
    }
}
