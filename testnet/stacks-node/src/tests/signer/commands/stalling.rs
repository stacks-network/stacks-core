use super::context::{SignerTestContext, SignerTestState};
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use std::sync::Arc;

pub struct StallMiningCommand;

impl Command<SignerTestState, SignerTestContext> for StallMiningCommand {
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Stalling mining. Result: {:?}",
            !state.mining_stalled
        );
        !state.mining_stalled
    }

    fn apply(&self, state: &mut SignerTestState) {
        println!("Applying: Stalling mining");
        crate::tests::signer::v0::test_mine_stall_set(true);
        state.mining_stalled = true;
    }

    fn label(&self) -> String {
        "STALL_MINING".to_string()
    }

    fn build(
        _ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(StallMiningCommand))
    }
}

pub struct RecoverFromStallCommand;

impl Command<SignerTestState, SignerTestContext> for RecoverFromStallCommand {
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Recovering from mining stall. Result: {:?}",
            state.mining_stalled
        );
        state.mining_stalled
    }

    fn apply(&self, state: &mut SignerTestState) {
        println!("Applying: Recovering from mining stall");
        crate::tests::signer::v0::test_mine_stall_set(false);
        state.mining_stalled = false;
    }

    fn label(&self) -> String {
        "RECOVER_FROM_STALL".to_string()
    }

    fn build(
        _ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(RecoverFromStallCommand))
    }
}
