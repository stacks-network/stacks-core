use super::context::{SignerTestContext, SignerTestState};
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks::util::tests::TestFlag;
use std::sync::Arc;

pub struct SkipCommitOpPrimaryMiner {
    miner_1_skip_commit_flag: TestFlag<bool>,
}

impl SkipCommitOpPrimaryMiner {
    pub fn new(miner_1_skip_commit_flag: TestFlag<bool>) -> Self {
        Self {
            miner_1_skip_commit_flag,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for SkipCommitOpPrimaryMiner {
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Skipping commit operations for miner 1. Result: {:?}",
            !state.is_primary_miner_skip_commit_op
        );
        !state.is_primary_miner_skip_commit_op
    }

    fn apply(&self, state: &mut SignerTestState) {
        println!("Applying: Skipping commit operations for miner 1");

        self.miner_1_skip_commit_flag.set(true);

        state.is_primary_miner_skip_commit_op = true;
    }

    fn label(&self) -> String {
        "SKIP_COMMIT_OP_PRIMARY_MINER".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SkipCommitOpPrimaryMiner::new(
            ctx.miners.lock().unwrap().get_primary_skip_commit_flag(),
        )))
    }
}

pub struct SkipCommitOpSecondaryMiner {
    miner_2_skip_commit_flag: TestFlag<bool>,
}

impl SkipCommitOpSecondaryMiner {
    pub fn new(miner_2_skip_commit_flag: TestFlag<bool>) -> Self {
        Self {
            miner_2_skip_commit_flag,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for SkipCommitOpSecondaryMiner {
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Skipping commit operations for miner 2. Result: {:?}",
            !state.is_secondary_miner_skip_commit_op
        );
        !state.is_secondary_miner_skip_commit_op
    }

    fn apply(&self, state: &mut SignerTestState) {
        println!("Applying: Skipping commit operations for miner 2");

        self.miner_2_skip_commit_flag.set(true);

        state.is_secondary_miner_skip_commit_op = true;
    }

    fn label(&self) -> String {
        "SKIP_COMMIT_OP_SECONDARY_MINER".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SkipCommitOpSecondaryMiner::new(
            ctx.miners.lock().unwrap().get_secondary_skip_commit_flag(),
        )))
    }
}
