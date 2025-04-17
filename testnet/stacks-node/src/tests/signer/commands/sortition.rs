use std::sync::{Arc, Mutex};

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::SignerTestState;
use super::SignerTestContext;
use crate::tests::signer::v0::{verify_sortition_winner, MultipleMinerTest};

pub struct VerifyMiner1WonSortition {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl VerifyMiner1WonSortition {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for VerifyMiner1WonSortition {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner 1 won sortition. Result: {:?}",
            true
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Verifying miner 1 won sortition");

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burnchain = conf_1.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();
        let (miner_pkh_1, _) = self.miners.lock().unwrap().get_miner_public_key_hashes();

        verify_sortition_winner(&sortdb, &miner_pkh_1);
    }
    fn label(&self) -> String {
        "VERIFY_MINER_1_WON_SORTITION".to_string()
    }
    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(VerifyMiner1WonSortition::new(
            ctx.miners.clone(),
        )))
    }
}

pub struct VerifyMiner2WonSortition {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl VerifyMiner2WonSortition {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for VerifyMiner2WonSortition {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner 2 won sortition. Result: {:?}",
            true
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Verifying miner 2 won sortition");

        let (conf_1, _) = self.miners.lock().unwrap().get_node_configs();
        let burnchain = conf_1.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();
        let (_, miner_pkh_2) = self.miners.lock().unwrap().get_miner_public_key_hashes();

        verify_sortition_winner(&sortdb, &miner_pkh_2);
    }
    fn label(&self) -> String {
        "VERIFY_MINER_2_WON_SORTITION".to_string()
    }
    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(VerifyMiner2WonSortition::new(
            ctx.miners.clone(),
        )))
    }
}

pub struct VerifyLastSortitionWinnerReorged {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl VerifyLastSortitionWinnerReorged {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for VerifyLastSortitionWinnerReorged {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying last sortition winner reorged. Result: {:?}",
            true
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Verifying last sortition winner reorged");
        self.miners
            .lock()
            .unwrap()
            .assert_last_sortition_winner_reorged();
    }

    fn label(&self) -> String {
        "VERIFY_LAST_SORTITION_WINNER_REORGED".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(VerifyLastSortitionWinnerReorged::new(
            ctx.miners.clone(),
        )))
    }
}
