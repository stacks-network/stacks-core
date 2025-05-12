use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::{wait_for_block_pushed_by_miner_key, MultipleMinerTest};

pub struct WaitForTenureChangeBlockFromMiner1 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl WaitForTenureChangeBlockFromMiner1 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForTenureChangeBlockFromMiner1 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for Nakamoto block from miner 1. Result: {:?}",
            !state.mining_stalled
        );
        !state.mining_stalled
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Waiting for Nakamoto block from miner 1");

        let miners_arc = self.miners.clone();

        let (miner_pk_1, last_confirmed_nakamoto_height_counter) = {
            let miners = miners_arc.lock().unwrap();
            let (miner_pk_1, _) = miners.get_miner_public_keys();
            let last_confirmed_nakamoto_height = miners.get_primary_last_stacks_tip_counter();
            (miner_pk_1, last_confirmed_nakamoto_height)
        };

        let last_confirmed_height = last_confirmed_nakamoto_height_counter
            .0
            .load(Ordering::SeqCst);
        let expected_height = last_confirmed_height + 1;

        info!(
            "Waiting for Nakamoto block {} pushed by miner 1",
            expected_height
        );

        let _miner_1_block = wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk_1)
            .expect(&format!("Failed to get block {}", expected_height));
    }

    fn label(&self) -> String {
        "WAIT_FOR_TENURE_CHANGE_BLOCK_FROM_MINER_1".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            WaitForTenureChangeBlockFromMiner1::new(ctx.miners.clone()),
        ))
    }
}

pub struct WaitForTenureChangeBlockFromMiner2 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl WaitForTenureChangeBlockFromMiner2 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForTenureChangeBlockFromMiner2 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for Nakamoto block from miner 2. Result: {:?}",
            !state.mining_stalled
        );
        !state.mining_stalled
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Waiting for Nakamoto block from miner 2");

        let miners_arc = self.miners.clone();

        let (miner_pk_2, last_confirmed_nakamoto_height_counter) = {
            let miners = miners_arc.lock().unwrap();
            let (_, miner_pk_2) = miners.get_miner_public_keys();
            let last_confirmed_nakamoto_height = miners.get_secondary_last_stacks_tip_counter();
            (miner_pk_2, last_confirmed_nakamoto_height)
        };

        let last_confirmed_height = last_confirmed_nakamoto_height_counter
            .0
            .load(Ordering::SeqCst);
        let expected_stacks_height = last_confirmed_height + 1;

        info!(
            "Waiting for Nakamoto block {} pushed by miner 2",
            expected_stacks_height
        );

        let _miner_2_block_n_1 =
            wait_for_block_pushed_by_miner_key(30, expected_stacks_height, &miner_pk_2)
                .expect(&format!("Failed to get block {:?}", expected_stacks_height));
    }

    fn label(&self) -> String {
        "WAIT_FOR_TENURE_CHANGE_BLOCK_FROM_MINER_2".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            WaitForTenureChangeBlockFromMiner2::new(ctx.miners.clone()),
        ))
    }
}
