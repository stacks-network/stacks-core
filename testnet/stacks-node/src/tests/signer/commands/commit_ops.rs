use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::context::{SignerTestContext, SignerTestState};

// 1 and 2 because we currently have two miners in the test
pub const MIN_MINER_INDEX: usize = 1;
pub const MAX_MINER_INDEX: usize = 2;

pub struct MinerCommitOp {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    skip: bool,
    operation: &'static str,
}

impl MinerCommitOp {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize, operation: &'static str) -> Self {
        if miner_index < MIN_MINER_INDEX || miner_index > MAX_MINER_INDEX {
            panic!(
                "Invalid miner index: {}. Must be between {} and {}.",
                miner_index, MIN_MINER_INDEX, MAX_MINER_INDEX
            );
        }
        
        let skip = match operation {
            "enable" => false,
            "disable" => true,
            _ => panic!("Operation must be 'enable' or 'disable'"),
        };
        
        Self {
            ctx,
            miner_index,
            skip,
            operation,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for MinerCommitOp {
    fn check(&self, state: &SignerTestState) -> bool {
        let current_state = state.get_miner_skip_commit_op(self.miner_index);
        let should_apply = current_state != self.skip;

        info!(
            "Checking: {}ing commit operations for miner {}. Result: {:?}",
            self.operation,
            self.miner_index,
            should_apply
        );

        should_apply
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: {}ing commit operations for miner {}",
            self.operation,
            self.miner_index
        );

        self.ctx
            .get_miner_skip_commit_flag(self.miner_index)
            .set(self.skip);

        state.set_miner_skip_commit_op(self.miner_index, self.skip);
    }

    fn label(&self) -> String {
        format!(
            "{}_COMMIT_OP_MINER_{}",
            self.operation.to_uppercase(),
            self.miner_index
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        use proptest::prelude::*;
        (
            (MIN_MINER_INDEX..=MAX_MINER_INDEX).prop_map(|i| i), 
            prop_oneof![Just("enable"), Just("disable")]
        ).prop_map(move |(miner_index, operation)| {
            CommandWrapper::new(MinerCommitOp::new(ctx.clone(), miner_index, operation))
        })
    }
}