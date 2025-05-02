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

pub struct SendAndMineTransferTx {
    miners: Arc<Mutex<MultipleMinerTest>>,
    timeout_secs: u64,
}

impl SendAndMineTransferTx {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>, timeout_secs: u64) -> Self {
        Self {
            miners,
            timeout_secs,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for SendAndMineTransferTx {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Send and mine transfer tx with timeout {} seconds",
            self.timeout_secs
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Send and mine transfer tx with timeout {} seconds",
            self.timeout_secs
        );

        // Get the configs and check the stacks height before
        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let stacks_height_before = get_chain_info(&conf_1).stacks_tip_height;

        // Execute the send and mine operation
        let mut miners = self.miners.lock().unwrap();
        miners
            .send_and_mine_transfer_tx(self.timeout_secs)
            .expect("Failed to send and mine transfer tx");

        // Check that the stacks height has increased
        let stacks_height_after = get_chain_info(&conf_1).stacks_tip_height;
        assert_eq!(
            stacks_height_after,
            stacks_height_before + 1,
            "Stacks height should have increased by 1 after mining a transfer tx"
        );
    }

    fn label(&self) -> String {
        "SEND_AND_MINE_TRANSFER_TX".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        // Generate a timeout between 20 and 40 seconds
        (20u64..40u64).prop_map(move |timeout_secs| {
            CommandWrapper::new(SendAndMineTransferTx::new(ctx.miners.clone(), timeout_secs))
        })
    }
}
