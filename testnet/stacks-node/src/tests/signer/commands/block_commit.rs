use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::MultipleMinerTest;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use std::sync::{Arc, Mutex};

pub struct SubmitBlockCommitSecondaryMinerCommand {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl SubmitBlockCommitSecondaryMinerCommand {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for SubmitBlockCommitSecondaryMinerCommand {
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Submitting block commit miner 2. Result: {:?}",
            state.is_secondary_miner_skip_commit_op
        );
        state.is_secondary_miner_skip_commit_op
    }

    fn apply(&self, _state: &mut SignerTestState) {
        println!("Applying: Submitting block commit miner 2");

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burnchain = conf_1.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();

        self.miners.lock().unwrap().submit_commit_miner_2(&sortdb);
    }

    fn label(&self) -> String {
        "SUBMIT_BLOCK_COMMIT_SECONDARY_MINER".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            SubmitBlockCommitSecondaryMinerCommand::new(ctx.miners.clone()),
        ))
    }
}

pub struct SubmitBlockCommitPrimaryMinerCommand {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl SubmitBlockCommitPrimaryMinerCommand {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for SubmitBlockCommitPrimaryMinerCommand {
    fn check(&self, state: &SignerTestState) -> bool {
        println!(
            "Checking: Submitting block commit miner 1. Result: {:?}",
            state.is_primary_miner_skip_commit_op
        );
        state.is_primary_miner_skip_commit_op
    }

    fn apply(&self, _state: &mut SignerTestState) {
        println!("Applying: Submitting block commit miner 1");

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burnchain = conf_1.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();

        self.miners.lock().unwrap().submit_commit_miner_1(&sortdb);
    }

    fn label(&self) -> String {
        "SUBMIT_BLOCK_COMMIT_PRIMARY_MINER".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            SubmitBlockCommitPrimaryMinerCommand::new(ctx.miners.clone()),
        ))
    }
}
