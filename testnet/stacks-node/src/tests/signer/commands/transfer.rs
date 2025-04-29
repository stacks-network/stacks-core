use std::sync::{Arc, Mutex};

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;
use crate::tests::signer::v0::MultipleMinerTest;

pub struct SendTransferTx {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl SendTransferTx {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for SendTransferTx {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!("Checking: Sending transfer tx. Result: {:?}", true);
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!("Applying: Sending transfer tx");

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let stacks_height_before = get_chain_info(&conf_1).stacks_tip_height;
        let (txid, _) = self.miners.lock().unwrap().send_transfer_tx();

        state
            .transfer_txs_submitted
            .push((stacks_height_before, txid));
    }

    fn label(&self) -> String {
        "SEND_TRANSFER_TX".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SendTransferTx::new(ctx.miners.clone())))
    }
}
