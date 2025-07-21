use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{prop_oneof, Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::nakamoto_node::miner::{fault_injection_stall_miner, fault_injection_unstall_miner};

/// Command to globally pause or resume Stacks block mining within the test environment.
/// This command is used to simulate network-wide conditions where Stacks block production might halt or resume.
pub struct ChainStacksMining {
    should_pause: bool,
}

impl ChainStacksMining {
    fn new(should_pause: bool) -> Self {
        Self { should_pause }
    }

    pub fn pause() -> Self {
        Self::new(true)
    }

    pub fn resume() -> Self {
        Self::new(false)
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainStacksMining {
    fn check(&self, state: &SignerTestState) -> bool {
        // Pause should apply if mining is not currently stalled.
        // Resume should apply if mining is currently stalled.
        let should_apply = self.should_pause != state.mining_stalled;
        let operation_desc = if self.should_pause {
            "Pausing Stacks mining"
        } else {
            "Resuming Stacks mining"
        };
        info!("Checking: {}. Result: {}", operation_desc, should_apply);
        should_apply
    }

    fn apply(&self, state: &mut SignerTestState) {
        let operation_desc = if self.should_pause {
            "Pausing Stacks mining"
        } else {
            "Resuming Stacks mining"
        };
        info!("Applying: {}", operation_desc);
        if self.should_pause {
            fault_injection_stall_miner();
        } else {
            fault_injection_unstall_miner();
        }
        state.mining_stalled = self.should_pause;
    }

    fn label(&self) -> String {
        if self.should_pause {
            "PAUSE_STACKS_MINING".to_string()
        } else {
            "RESUME_STACKS_MINING".to_string()
        }
    }

    fn build(
        _ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        prop_oneof![
            Just(CommandWrapper::new(ChainStacksMining::pause())),
            Just(CommandWrapper::new(ChainStacksMining::resume())),
        ]
    }
}
