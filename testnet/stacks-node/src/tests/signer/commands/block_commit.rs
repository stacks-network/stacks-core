use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};

/// Command to manually trigger a block commit submission for a specified miner
pub struct SubmitBlockCommit {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl SubmitBlockCommit {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for SubmitBlockCommit {
    fn check(&self, _state: &SignerTestState) -> bool {
        let is_miner_paused = self
            .ctx
            .get_counters_for_miner(self.miner_index)
            .naka_skip_commit_op
            .get();

        info!(
            "Checking: Submitting block commit miner {}. Result: {:?}",
            self.miner_index, is_miner_paused
        );

        // Ensure Miner's automatic commit ops are paused. If not, this may
        // result in no commit being submitted.
        is_miner_paused
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Submitting block commit miner {}",
            self.miner_index
        );

        let (conf_1, conf_2) = self.ctx.get_node_configs();
        let conf = match self.miner_index {
            1 => conf_1,
            2 => conf_2,
            _ => panic!("Invalid miner index: {}", self.miner_index),
        };

        let burnchain = conf.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();

        match self.miner_index {
            1 => self
                .ctx
                .miners
                .lock()
                .unwrap()
                .submit_commit_miner_1(&sortdb),
            2 => self
                .ctx
                .miners
                .lock()
                .unwrap()
                .submit_commit_miner_2(&sortdb),
            _ => panic!(
                "Invalid miner index: {}. Expected 1 or 2.",
                self.miner_index
            ),
        }

        assert!(
            self.ctx
                .get_counters_for_miner(self.miner_index)
                .naka_skip_commit_op
                .get()
                == true,
        );
    }

    fn label(&self) -> String {
        format!("SUBMIT_BLOCK_COMMIT_MINER_{}", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(SubmitBlockCommit::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}
