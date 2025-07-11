use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;

// This command simulates sending a Stacks transfer transaction and then mining a block to confirm it.
// It verifies that the Stacks chain height increases as expected after the mining operation.
pub struct MinerSendAndMineStacksTransferTx {
    ctx: Arc<SignerTestContext>,
    timeout_secs: u64,
}

impl MinerSendAndMineStacksTransferTx {
    pub fn new(ctx: Arc<SignerTestContext>, timeout_secs: u64) -> Self {
        Self { ctx, timeout_secs }
    }
}

impl Command<SignerTestState, SignerTestContext> for MinerSendAndMineStacksTransferTx {
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

        // We can use miner 1 conf to get the sortition db - it's the same for both miners
        let conf = self.ctx.get_node_config(1);
        let stacks_height_before = get_chain_info(&conf).stacks_tip_height;

        self.ctx
            .miners
            .lock()
            .unwrap()
            .send_and_mine_transfer_tx(self.timeout_secs)
            .expect("Failed to send and mine transfer tx");

        let stacks_height_after = get_chain_info(&conf).stacks_tip_height;
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
        (20u64..40u64).prop_map(move |timeout_secs| {
            // Originally, timeout was 30 seconds
            CommandWrapper::new(MinerSendAndMineStacksTransferTx::new(
                ctx.clone(),
                timeout_secs,
            ))
        })
    }
}
