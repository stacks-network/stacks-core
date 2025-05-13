use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};

/// Command to verify that a specified miner has produced the expected number of blocks
/// since the Epoch 3.0 (Nakamoto) transition.
pub struct VerifyBlockCountAfterBootToEpoch3 {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    expected_block_count: usize,
}

impl VerifyBlockCountAfterBootToEpoch3 {
    pub fn new(
        ctx: Arc<SignerTestContext>,
        miner_index: usize,
        expected_block_count: usize,
    ) -> Self {
        Self {
            ctx,
            miner_index,
            expected_block_count,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for VerifyBlockCountAfterBootToEpoch3 {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner {} block count. Result: {:?}",
            self.miner_index, true
        );
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: Verifying miner {} block count is {}",
            self.miner_index, self.expected_block_count
        );

        let conf = self.ctx.get_node_config(self.miner_index);
        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);

        let miner_blocks_after_boot_to_epoch3 =
            self.ctx.get_miner_blocks_after_specified_block_height(
                &conf,
                state.epoch_3_start_block_height.unwrap(),
                &miner_pk,
            );

        assert_eq!(
            self.expected_block_count, miner_blocks_after_boot_to_epoch3,
            "Expected {} blocks from miner {}, but found {}",
            self.expected_block_count, self.miner_index, miner_blocks_after_boot_to_epoch3
        );

        info!(
            "Verified miner {} has exactly {} blocks after epoch 3 boot",
            self.miner_index, 
            self.expected_block_count
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_MINER_{}_BLOCK_COUNT", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize, 1usize..=5usize).prop_flat_map(
            move |(miner_index, expected_block_count)| {
                Just(CommandWrapper::new(VerifyBlockCountAfterBootToEpoch3::new(
                    ctx.clone(),
                    miner_index,
                    expected_block_count,
                )))
            },
        )
    }
}
