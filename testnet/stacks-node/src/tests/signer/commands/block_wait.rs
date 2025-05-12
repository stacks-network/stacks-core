use std::sync::atomic::Ordering;
use std::sync::Arc;

use libsigner::v0::messages::RejectReason;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::signer::v0::{
    wait_for_block_global_rejection_with_reject_reason, wait_for_block_proposal,
    wait_for_block_pushed_by_miner_key,
};

/// Command to wait for a specific miner to produce a Nakamoto block during tenure change.
/// This command monitors the blockchain until the specified miner successfully
/// produces their next expected Nakamoto block.
pub struct WaitForTenureChangeBlock {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl WaitForTenureChangeBlock {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForTenureChangeBlock {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for Nakamoto block from miner {}. Result: {:?}",
            self.miner_index, !state.mining_stalled
        );
        !state.mining_stalled
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Waiting for Nakamoto block from miner {}",
            self.miner_index
        );

        let (miner_pk_1, miner_pk_2) = self.ctx.get_miner_public_keys();
        let miner_pk = match self.miner_index {
            1 => miner_pk_1,
            2 => miner_pk_2,
            _ => panic!("Invalid miner index: {}", self.miner_index),
        };

        let miner_last_confirmed_height = self.ctx.get_miner_last_confirmed_nakamoto_height(self.miner_index);
        let expected_height = miner_last_confirmed_height + 1;

        info!(
            "Waiting for Nakamoto block {} pushed by miner {}",
            expected_height, self.miner_index
        );

        let _miner_1_block = wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk)
            .expect(&format!("Failed to get block {}", expected_height));
    }

    fn label(&self) -> String {
        format!(
            "WAIT_FOR_TENURE_CHANGE_BLOCK_FROM_MINER_{:?}",
            self.miner_index
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(WaitForTenureChangeBlock::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}

/// Command to wait for a block proposal from a specific miner in the Nakamoto consensus protocol.
/// This command monitors the blockchain until the specified miner submits a block proposal at the expected height.
pub struct WaitForBlockProposal {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl WaitForBlockProposal {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForBlockProposal {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for block proposal from miner {:?}",
            self.miner_index,
        );
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: Waiting for block proposal from miner {:?}",
            self.miner_index
        );

        let (miner_pk_1, miner_pk_2) = self.ctx.get_miner_public_keys();
        let miner_pk = match self.miner_index {
            1 => miner_pk_1,
            2 => miner_pk_2,
            _ => panic!("Invalid miner index: {}", self.miner_index),
        };

        let miner_last_confirmed_height = self.ctx.get_miner_last_confirmed_nakamoto_height(self.miner_index);
        let expected_height = miner_last_confirmed_height + 1;

        info!(
            "Waiting for block proposal at height {}",
            expected_height
        );

        let proposed_block = wait_for_block_proposal(30, expected_height, &miner_pk)
            .expect("Timed out waiting for block proposal");

        let block_hash = proposed_block.header.signer_signature_hash();
        state.last_block_hash = Some(block_hash.clone());

        info!(
            "Received block proposal at height {} with hash {:?}",
            expected_height, block_hash
        );
    }

    fn label(&self) -> String {
        format!("WAIT_FOR_BLOCK_PROPOSAL_FROM_MINER_{:?}", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(WaitForBlockProposal::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}

/// Command to wait for a specific block to be rejected with an expected rejection reason.
/// This command monitors the network for rejection signatures of a previously identified block.
pub struct WaitForBlockRejectionWithRejectReason {
    _ctx: Arc<SignerTestContext>,
    reason: RejectReason,
    num_signers: usize,
}

impl WaitForBlockRejectionWithRejectReason {
    pub fn new(_ctx: Arc<SignerTestContext>, reason: RejectReason, num_signers: usize) -> Self {
        Self {
            _ctx,
            reason,
            num_signers,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForBlockRejectionWithRejectReason {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for block rejection with reason {:?}. Result: {:?}",
            self.reason,
            state.last_block_hash.is_some();
        );
        state.last_block_hash.is_some()
    }

    fn apply(&self, state: &mut SignerTestState) {
        wait_for_block_global_rejection_with_reject_reason(
            30,
            state.last_block_hash.unwrap(),
            self.num_signers,
            self.reason.clone(),
        )
        .expect("Timed out waiting for block rejection");

        info!(
            "Block was rejected with the expected reason: {:?}",
            self.reason
        );
    }

    fn label(&self) -> String {
        format!(
            "WAIT_FOR_BLOCK_REJECTION_WITH_REJECT_REASON_{:?}",
            self.reason
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=5usize).prop_map(move |num_signers: usize| {
            CommandWrapper::new(WaitForBlockRejectionWithRejectReason::new(
                ctx.clone(),
                RejectReason::ReorgNotAllowed,
                num_signers,
            ))
        })
    }
}
