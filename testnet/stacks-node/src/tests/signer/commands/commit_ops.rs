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
