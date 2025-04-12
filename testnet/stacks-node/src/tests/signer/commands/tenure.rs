use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::MultipleMinerTest;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;
use std::sync::{Arc, Mutex};

pub struct MineTenureCommand {
    miners: Arc<Mutex<MultipleMinerTest>>,
    timeout_secs: u64,
}

impl MineTenureCommand {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>, timeout_secs: u64) -> Self {
        Self {
            miners,
            timeout_secs,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for MineTenureCommand {
    fn check(&self, _state: &SignerTestState) -> bool {
        println!("Checking: Mining tenure. Result: {:?}", true);
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        println!(
            "Applying: Mining tenure and waiting for it for {:?} seconds",
            self.timeout_secs
        );

        let sortdb = {
            let miners = self.miners.lock().unwrap();
            let (conf_1, _) = miners.get_node_configs();
            let burnchain = conf_1.get_burnchain();
            let sortdb = burnchain.open_sortition_db(true).unwrap();
            sortdb
        };

        {
            let mut miners = self.miners.lock().unwrap();
            miners
                .mine_bitcoin_blocks_and_confirm(&sortdb, 1, self.timeout_secs)
                .expect("Failed to mine BTC block");
        }
    }

    fn label(&self) -> String {
        "MINE_TENURE".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (60u64..90u64).prop_map(move |timeout_secs| {
            CommandWrapper::new(MineTenureCommand::new(ctx.miners.clone(), timeout_secs))
        })
    }
}
