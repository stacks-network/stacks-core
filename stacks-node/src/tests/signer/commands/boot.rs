use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;

/// Command to advance the test environment's burn chain and Stacks chain
/// to the beginning of Stacks Epoch 3.0 (Nakamoto).
/// This command also mines a Nakamoto block
pub struct ChainBootToEpoch3 {
    ctx: Arc<SignerTestContext>,
}

impl ChainBootToEpoch3 {
    pub fn new(ctx: Arc<SignerTestContext>) -> Self {
        Self { ctx }
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainBootToEpoch3 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Booting miners to Nakamoto. Result: {}",
            !state.is_booted_to_nakamoto
        );
        // This command should only run if the state indicates it hasn't booted to Nakamoto yet.
        !state.is_booted_to_nakamoto
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!("Applying: Booting miners to Nakamoto");

        self.ctx.miners.lock().unwrap().boot_to_epoch_3();

        // We can use miner 1 conf to get the chain info - it's the same for both miners
        let conf = self.ctx.get_node_config(1);
        let burn_block_height = get_chain_info(&conf).burn_block_height;

        state.epoch_3_start_block_height = Some(self.ctx.get_peer_stacks_tip_height());

        // Epoch 3.0 is expected to start at burn block height 231
        assert_eq!(burn_block_height, 231);

        state.is_booted_to_nakamoto = true;
    }

    fn label(&self) -> String {
        "BOOT_TO_EPOCH_3".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(ChainBootToEpoch3::new(ctx.clone())))
    }
}
