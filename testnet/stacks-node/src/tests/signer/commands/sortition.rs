use std::sync::Arc;

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::SignerTestState;
use super::SignerTestContext;
use crate::tests::signer::v0::verify_sortition_winner;

/// Command to verify that a specific miner (identified by `miner_index`)
/// is correctly recorded as the winner of the latest sortition in that miner's local sortition database.
///
/// This is used after a sortition event to ensure the specified miner's
/// view of the sortition outcome is correct. It calls `verify_sortition_winner`,
/// which asserts that the miner's public key hash is the one recorded for the
/// sortition at the canonical burn chain tip within its sortition database.

pub struct VerifyMinerWonSortition {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl VerifyMinerWonSortition {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for VerifyMinerWonSortition {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner {} won sortition. Result: {:?}",
            self.miner_index, true
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Verifying miner {} won sortition",
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

        let (miner_pkh_1, miner_pkh_2) = self.ctx.get_miner_public_key_hashes();

        let miner_pkh = match self.miner_index {
            1 => miner_pkh_1,
            2 => miner_pkh_2,
            _ => panic!("Invalid miner index: {}", self.miner_index),
        };

        verify_sortition_winner(&sortdb, &miner_pkh);
    }

    fn label(&self) -> String {
        format!("VERIFY_MINER_{}_WON_SORTITION", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(VerifyMinerWonSortition::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}

/// Command to verify that the Stacks chain has reorged such that the burn block
/// containing the last recorded sortition is no longer an ancestor of the current
/// Stacks tip's burn parent. This implies the winner of that sortition was reorged.
///
/// Used in chain reorganization tests. It calls `assert_last_sortition_winner_reorged`,
/// which compares the burn chain history leading to the current Stacks tip's parent
/// against the burn chain history of the last sortition. A mismatch confirms the reorg
/// of the previous sortition event.

pub struct VerifyLastSortitionWinnerReorged {
    ctx: Arc<SignerTestContext>,
}

impl VerifyLastSortitionWinnerReorged {
    pub fn new(ctx: Arc<SignerTestContext>) -> Self {
        Self { ctx }
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
        Just(CommandWrapper::new(VerifyLastSortitionWinnerReorged::new(
            ctx.clone(),
        )))
    }
}
