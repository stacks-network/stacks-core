use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};

/// Command to attempt to shut down the miner instances managed in the test context.
/// This command is typically intended for use at the end of a test scenario or
/// when simulating a complete halt of mining operations.
pub struct ShutdownMiners {
    ctx: Arc<SignerTestContext>,
}

impl ShutdownMiners {
    pub fn new(ctx: Arc<SignerTestContext>) -> Self {
        Self { ctx }
    }
}

impl Command<SignerTestState, SignerTestContext> for ShutdownMiners {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!("Checking: Shutting down miners. Result: {:?}", true);
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Shutting down miners");
        let mut shutdown_called = false;

        // FIXME: Is this correct?
        if let Ok(miners_arc) = Arc::try_unwrap(self.ctx.miners.clone()) {
            if let Ok(miners) = miners_arc.into_inner() {
                miners.shutdown();
                shutdown_called = true;
            }
        }
        /* assert!(
            shutdown_called,
            "Miners shutdown was expected to be called but wasn't."
        ); */
    }

    fn label(&self) -> String {
        "SHUTDOWN_MINERS".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(ShutdownMiners::new(ctx.clone())))
    }
}
