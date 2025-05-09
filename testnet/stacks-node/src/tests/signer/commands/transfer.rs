use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;

// This command simulates sending a Stacks transfer transaction and then mining a block
// (or blocks) to confirm it. It verifies that the Stacks chain height increases
// as expected after the mining operation.

pub struct SendAndMineTransferTx {
    ctx: Arc<SignerTestContext>,
    timeout_secs: u64,
}

impl SendAndMineTransferTx {
    pub fn new(ctx: Arc<SignerTestContext>, timeout_secs: u64) -> Self {
        Self { ctx, timeout_secs }
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

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: Send and mine transfer tx with timeout {} seconds",
            self.timeout_secs
        );

        let (conf_1, _) = self.ctx.get_node_configs();
        let stacks_height_before = get_chain_info(&conf_1).stacks_tip_height;
        
        self.ctx
            .miners
            .lock()
            .unwrap()
            .send_and_mine_transfer_tx(self.timeout_secs)
            .expect("Failed to send and mine transfer tx");

        // FIXME: To remove
        state.increment_blocks_mined_by_miner(2);

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
        (20u64..40u64).prop_map(move |timeout_secs| {
            CommandWrapper::new(SendAndMineTransferTx::new(ctx.clone(), timeout_secs))
        })
    }
}
