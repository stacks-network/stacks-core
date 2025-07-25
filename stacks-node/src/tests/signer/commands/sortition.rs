use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::SignerTestState;
use super::SignerTestContext;
use crate::tests::signer::v0::verify_sortition_winner;

/// Command to verify that a specific miner is correctly recorded as
/// the winner of the latest sortition in that miner's local sortition database.
pub struct ChainExpectSortitionWinner {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl ChainExpectSortitionWinner {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainExpectSortitionWinner {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner {} won sortition. Result: {}",
            self.miner_index, true
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Verifying miner {} won sortition",
            self.miner_index
        );

        // We should only use the first miner's sortition as it is what we use to confirm the bitcoin block was mined
        // Otherwise we will have a race condition as we do not know if the other miner's sortdb has been updated yet
        let sortdb = self.ctx.get_sortition_db(1);
        let miner_pkh = self.ctx.get_miner_public_key_hash(self.miner_index);

        verify_sortition_winner(&sortdb, &miner_pkh);
    }

    fn label(&self) -> String {
        format!("VERIFY_MINER_{}_WON_SORTITION", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(ChainExpectSortitionWinner::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}

/// Command to verify that a Stacks chain reorganization has occurred by comparing consensus hashes.
/// This checks if the last sortition's consensus hash differs from the current Stacks parent consensus hash,
/// indicating that the previously selected sortition winner is no longer part of the canonical chain.
pub struct ChainVerifyLastSortitionWinnerReorged {
    ctx: Arc<SignerTestContext>,
}

impl ChainVerifyLastSortitionWinnerReorged {
    pub fn new(ctx: Arc<SignerTestContext>) -> Self {
        Self { ctx }
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainVerifyLastSortitionWinnerReorged {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying last sortition winner reorged. Result: {}",
            true
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Verifying last sortition winner reorged");
        self.ctx
            .miners
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
        Just(CommandWrapper::new(
            ChainVerifyLastSortitionWinnerReorged::new(ctx.clone()),
        ))
    }
}
