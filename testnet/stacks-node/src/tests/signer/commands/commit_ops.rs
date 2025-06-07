use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::context::{SignerTestContext, SignerTestState};

/// Command to enable or disable the block commit operations for a specific
/// miner within the test environment.
/// This command is used to simulate scenarios where a miner might temporarily or
/// intentionally stop sending its block commit transactions to the burn chain.
pub struct ChainMinerCommitOp {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    skip: bool, // true to disable commit operations, false to enable
}

impl ChainMinerCommitOp {
    fn new(ctx: Arc<SignerTestContext>, miner_index: usize, skip: bool) -> Self {
        Self {
            ctx,
            miner_index,
            skip,
        }
    }

    pub fn enable_for(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self::new(ctx, miner_index, false)
    }

    pub fn disable_for(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self::new(ctx, miner_index, true)
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainMinerCommitOp {
    fn check(&self, _state: &SignerTestState) -> bool {
        let current_state = self
            .ctx
            .get_counters_for_miner(self.miner_index)
            .naka_skip_commit_op
            .get();

        let should_apply = current_state != self.skip;
        let operation = if self.skip { "disabl" } else { "enabl" };
        info!(
            "Checking: {}ing commit operations for miner {}. Result: {}",
            operation, self.miner_index, should_apply
        );
        should_apply
    }

    fn apply(&self, _state: &mut SignerTestState) {
        let operation = if self.skip { "disabl" } else { "enabl" };
        info!(
            "Applying: {}ing commit operations for miner {}",
            operation, self.miner_index
        );
        self.ctx
            .get_counters_for_miner(self.miner_index)
            .naka_skip_commit_op
            .set(self.skip);
    }

    fn label(&self) -> String {
        let operation = if self.skip { "DISABLE" } else { "ENABLE" };
        format!("{}_COMMIT_OP_MINER_{}", operation, self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        use proptest::prelude::*;
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            prop_oneof![
                Just(CommandWrapper::new(ChainMinerCommitOp::enable_for(
                    ctx.clone(),
                    miner_index
                ))),
                Just(CommandWrapper::new(ChainMinerCommitOp::disable_for(
                    ctx.clone(),
                    miner_index
                )))
            ]
        })
    }
}
