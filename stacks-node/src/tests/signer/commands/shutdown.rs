use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};

/// Command to attempt to shut down the miner instances managed in the test context.
/// This command is typically intended for use at the end of a test scenario or
/// when simulating a complete halt of mining operations.
pub struct ChainShutdownMiners {
    ctx: Arc<SignerTestContext>,
}

impl ChainShutdownMiners {
    pub fn new(ctx: Arc<SignerTestContext>) -> Self {
        Self { ctx }
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainShutdownMiners {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!("Checking: Shutting down miners. Result: {}", true);
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Shutting down miners");

        let miners_arc = self.ctx.miners.clone();

        // Try to unwrap the Arc - this only works if we're the last reference
        match Arc::try_unwrap(miners_arc) {
            Ok(mutex) => match mutex.into_inner() {
                Ok(miners) => {
                    miners.shutdown();
                    info!("Miners have been shut down");
                }
                Err(_) => {
                    warn!("Mutex was poisoned, cannot shutdown miners cleanly");
                }
            },
            Err(_) => {
                warn!("Cannot shutdown miners: other references to Arc still exist");
                // Could potentially set a flag or use some other coordination mechanism
            }
        }
    }

    fn label(&self) -> String {
        "SHUTDOWN_MINERS".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(ChainShutdownMiners::new(ctx.clone())))
    }
}
