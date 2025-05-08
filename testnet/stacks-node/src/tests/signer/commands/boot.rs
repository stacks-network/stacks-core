use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;

pub struct BootToEpoch3 {
    ctx: Arc<SignerTestContext>,
}

impl BootToEpoch3 {
    pub fn new(ctx: Arc<SignerTestContext>) -> Self {
        Self { ctx }
    }
}

impl Command<SignerTestState, SignerTestContext> for BootToEpoch3 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Booting miners to Nakamoto. Result: {:?}",
            !state.is_booted_to_nakamoto
        );
        !state.is_booted_to_nakamoto
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!("Applying: Booting miners to Nakamoto");

        self.ctx.miners.lock().unwrap().boot_to_epoch_3();

        let (conf_1, _) = self.ctx.get_node_configs();
        let burn_block_height = get_chain_info(&conf_1).burn_block_height;

        assert_eq!(burn_block_height, 231); // Epoch 3 starts at block 231

        state.is_booted_to_nakamoto = true;
    }

    fn label(&self) -> String {
        "BOOT_TO_EPOCH_3".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(BootToEpoch3::new(ctx.clone())))
    }
}
