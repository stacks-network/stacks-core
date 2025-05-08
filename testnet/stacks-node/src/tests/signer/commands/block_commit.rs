use std::sync::{Arc, Mutex};

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::MultipleMinerTest;

pub struct SubmitBlockCommitMiner2 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl SubmitBlockCommitMiner2 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for SubmitBlockCommitMiner2 {
    fn check(&self, _state: &SignerTestState) -> bool {
        //FIXME: This logic can be handled differently. We might want to pass the context instead
        let is_miner_paused = self
            .miners
            .lock()
            .unwrap()
            .get_counters_for_miner(2)
            .naka_skip_commit_op
            .get();

        info!(
            "Checking: Submitting block commit miner {}. Result: {:?}",
            2, is_miner_paused
        );

        // Ensure Miner's automatic commit ops are paused
        is_miner_paused
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Submitting block commit miner 2");

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burnchain = conf_1.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();

        self.miners.lock().unwrap().submit_commit_miner_2(&sortdb);
    }

    fn label(&self) -> String {
        "SUBMIT_BLOCK_COMMIT_MINER_2".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SubmitBlockCommitMiner2::new(
            ctx.miners.clone(),
        )))
    }
}

pub struct SubmitBlockCommitMiner1 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl SubmitBlockCommitMiner1 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for SubmitBlockCommitMiner1 {
    fn check(&self, _state: &SignerTestState) -> bool {
        //FIXME: This logic can be handled differently. We might want to pass the context instead
        let is_miner_paused = self
            .miners
            .lock()
            .unwrap()
            .get_counters_for_miner(1)
            .naka_skip_commit_op
            .get();

        info!(
            "Checking: Submitting block commit miner {}. Result: {:?}",
            1, is_miner_paused
        );

        // Ensure Miner's automatic commit ops are paused
        is_miner_paused
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Submitting block commit miner 1");

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burnchain = conf_1.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();

        self.miners.lock().unwrap().submit_commit_miner_1(&sortdb);
    }

    fn label(&self) -> String {
        "SUBMIT_BLOCK_COMMIT_MINER_1".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(SubmitBlockCommitMiner1::new(
            ctx.miners.clone(),
        )))
    }
}
