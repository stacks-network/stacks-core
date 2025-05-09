use std::sync::{Arc, Mutex};

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::MultipleMinerTest;

/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------
/// ------------------------------------------------------------------------------------------

pub struct ShutdownMiners {
    ctx: Arc<SignerTestContext>,
}

impl ShutdownMiners {
    pub fn new(ctx: Arc<SignerTestContext>,) -> Self {
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

        if let Ok(miners_arc) = Arc::try_unwrap(self.ctx.miners.clone()) {
            if let Ok(miners) = miners_arc.into_inner() {
                miners.shutdown();
            }
        }
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
