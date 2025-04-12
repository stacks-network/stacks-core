use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::{get_chain_info_wrapper, MultipleMinerTest};
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use std::sync::{Arc, Mutex};

pub struct BootToEpoch3 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl BootToEpoch3 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for BootToEpoch3 {
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Booting miners to Nakamoto. Result: {:?}",
            !state.is_booted_to_nakamoto
        );
        !state.is_booted_to_nakamoto
    }

    fn apply(&self, state: &mut SignerTestState) {
        println!("Applying: Booting miners to Nakamoto");

        self.miners.lock().unwrap().boot_to_epoch_3();

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burn_block_height = get_chain_info_wrapper(&conf_1).burn_block_height;

        assert_eq!(burn_block_height, 231);

        state.is_booted_to_nakamoto = true;
    }

    fn label(&self) -> String {
        "BOOT_TO_EPOCH_3".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(BootToEpoch3::new(ctx.miners.clone())))
    }
}
