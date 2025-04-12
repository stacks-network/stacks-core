use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::MultipleMinerTest;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use std::sync::{Arc, Mutex};

pub struct SendTransferTxCommand {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl SendTransferTxCommand {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for SendTransferTxCommand {
    fn check(&self, _state: &SignerTestState) -> bool {
        println!("Checking: Sending transfer tx. Result: {:?}", true);
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        println!("Applying: Sending transfer tx");

        self.miners.lock().unwrap().send_transfer_tx();
    }

    fn label(&self) -> String {
        "SEND_TRANSFER_TX".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SendTransferTxCommand::new(
            ctx.miners.clone(),
        )))
    }
}
