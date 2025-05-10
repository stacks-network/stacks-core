use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks::util::tests::TestFlag;

use super::context::{SignerTestContext, SignerTestState};

pub struct SkipCommitOpMiner1 {
    miner_1_skip_commit_flag: TestFlag<bool>,
}

impl SkipCommitOpMiner1 {
    pub fn new(miner_1_skip_commit_flag: TestFlag<bool>) -> Self {
        Self {
            miner_1_skip_commit_flag,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for SkipCommitOpMiner1 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Skipping commit operations for miner 1. Result: {:?}",
            !state.is_primary_miner_skip_commit_op
        );
        !state.is_primary_miner_skip_commit_op
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!("Applying: Skipping commit operations for miner 1");

        self.miner_1_skip_commit_flag.set(true);

        state.is_primary_miner_skip_commit_op = true;
    }

    fn label(&self) -> String {
        "SKIP_COMMIT_OP_MINER_1".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SkipCommitOpMiner1::new(
            ctx.miners.lock().unwrap().get_primary_skip_commit_flag(),
        )))
    }
}

pub struct SkipCommitOpMiner2 {
    miner_2_skip_commit_flag: TestFlag<bool>,
}

impl SkipCommitOpMiner2 {
    pub fn new(miner_2_skip_commit_flag: TestFlag<bool>) -> Self {
        Self {
            miner_2_skip_commit_flag,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for SkipCommitOpMiner2 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Skipping commit operations for miner 2. Result: {:?}",
            !state.is_secondary_miner_skip_commit_op
        );
        !state.is_secondary_miner_skip_commit_op
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!("Applying: Skipping commit operations for miner 2");

        self.miner_2_skip_commit_flag.set(true);

        state.is_secondary_miner_skip_commit_op = true;
    }

    fn label(&self) -> String {
        "SKIP_COMMIT_OP_MINER_2".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SkipCommitOpMiner2::new(
            ctx.miners.lock().unwrap().get_secondary_skip_commit_flag(),
        )))
    }
}

pub struct MinerCommitOp {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    skip: bool,
}

impl MinerCommitOp {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize, skip: bool) -> Self {
        if miner_index != 1 && miner_index != 2 {
            panic!(
                "Invalid miner index: {}. Only miners 1 and 2 are supported.",
                miner_index
            );
        }
        Self {
            ctx,
            miner_index,
            skip,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for MinerCommitOp {
    fn check(&self, state: &SignerTestState) -> bool {
        let current_state = match self.miner_index {
            1 => state.is_primary_miner_skip_commit_op,
            2 => state.is_secondary_miner_skip_commit_op,
            _ => unreachable!(),
        };

        let should_apply = current_state != self.skip;

        info!(
            "Checking: {} commit operations for miner {}. Result: {:?}",
            if self.skip { "Skipping" } else { "Enabling" },
            self.miner_index,
            should_apply
        );

        should_apply
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: {} commit operations for miner {}",
            if self.skip { "Skipping" } else { "Enabling" },
            self.miner_index
        );

        self.ctx
            .get_miner_skip_commit_flag(self.miner_index)
            .set(self.skip);

        match self.miner_index {
            1 => state.is_primary_miner_skip_commit_op = self.skip,
            2 => state.is_secondary_miner_skip_commit_op = self.skip,
            _ => unreachable!(),
        }
    }

    fn label(&self) -> String {
        format!(
            "{}_COMMIT_OP_MINER_{}",
            if self.skip { "SKIP" } else { "ENABLE" },
            self.miner_index
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        use proptest::prelude::*;
        (prop_oneof![Just(1), Just(2)], any::<bool>()).prop_map(move |(miner_index, skip)| {
            CommandWrapper::new(MinerCommitOp::new(ctx.clone(), miner_index, skip))
        })
    }
}
