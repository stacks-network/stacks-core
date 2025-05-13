use std::sync::Arc;

use libsigner::v0::messages::RejectReason;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use proptest::prop_oneof;

use super::context::{SignerTestContext, SignerTestState};
use crate::tests::neon_integrations::get_chain_info;
use crate::tests::signer::v0::{
    wait_for_block_global_rejection_with_reject_reason, wait_for_block_proposal,
    wait_for_block_pushed_by_miner_key,
};

/// Command to wait for a specific miner to produce a Nakamoto block during tenure change.
/// This command monitors the blockchain until the specified miner successfully
/// produces their next expected Nakamoto block.
/// This command expects the miner to propose a block at the next height after that miner's last confirmed block.
pub struct WaitForNakamotoBlock {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    height_strategy: HeightStrategy,
}

#[derive(Debug)]
enum HeightStrategy {
    FromGlobalHeight,
    FromMinerHeight,
}

impl WaitForNakamotoBlock {
    fn new(
        ctx: Arc<SignerTestContext>,
        miner_index: usize,
        height_strategy: HeightStrategy,
    ) -> Self {
        Self {
            ctx,
            miner_index,
            height_strategy,
        }
    }

    pub fn wait_from_global_height(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self::new(ctx, miner_index, HeightStrategy::FromGlobalHeight)
    }

    pub fn wait_from_miner_height(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self::new(ctx, miner_index, HeightStrategy::FromMinerHeight)
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForNakamotoBlock {
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

        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);

        // Calculate expected height based on the strategy
        match self.height_strategy {
            HeightStrategy::FromGlobalHeight => {
                // Use global height approach
                let conf = self.ctx.get_node_config(self.miner_index);
                let stacks_height_before = self.ctx.get_peer_stacks_tip_height();
                let expected_height = stacks_height_before + 1;

                let miner_block =
                    wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk).expect(
                        &format!(
                            "Failed to get block for miner {} - Strategy: {:?}",
                            self.miner_index, self.height_strategy
                        ),
                    );

                let mined_block_height = miner_block.header.chain_length;

                info!(
                    "Miner {} mined Nakamoto block at height {}",
                    self.miner_index, mined_block_height
                );

                let info_after = get_chain_info(&conf);

                assert_eq!(info_after.stacks_tip, miner_block.header.block_hash());
                assert_eq!(info_after.stacks_tip_height, mined_block_height);
                assert_eq!(mined_block_height, stacks_height_before + 1);
            }
            HeightStrategy::FromMinerHeight => {
                // Use miner-specific height approach
                let miner_last_confirmed_height = self
                    .ctx
                    .get_counters_for_miner(self.miner_index)
                    .naka_submitted_commit_last_stacks_tip
                    .load(std::sync::atomic::Ordering::SeqCst);
                let expected_height = miner_last_confirmed_height + 1;

                info!(
                    "Waiting for Nakamoto block {} pushed by miner {}",
                    expected_height, self.miner_index
                );

                let _miner_block =
                    wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk)
                        .expect(&format!("Failed to get block {}", expected_height));

                info!(
                    "Miner {} mined Nakamoto block at height {}",
                    self.miner_index, expected_height
                );
            }
        }
    }

    fn label(&self) -> String {
        format!("WAIT_FOR_NAKAMOTO_BLOCK_FROM_MINER_{:?}", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        use proptest::prelude::*;
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            prop_oneof![
                Just(CommandWrapper::new(
                    WaitForNakamotoBlock::wait_from_global_height(ctx.clone(), miner_index)
                )),
                Just(CommandWrapper::new(
                    WaitForNakamotoBlock::wait_from_miner_height(ctx.clone(), miner_index)
                ))
            ]
        })
    }
}

/// Command to wait for a block proposal from a specific miner in the Nakamoto consensus protocol.
/// This command monitors the blockchain until the specified miner submits a block proposal at the expected height.
/// This command expects the miner to propose a block at the next height after that miner's last confirmed block.
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

        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);

        // Get the last confirmed height for that specific miner
        let miner_last_confirmed_height = self
            .ctx
            .get_counters_for_miner(self.miner_index)
            .naka_submitted_commit_last_stacks_tip
            .load(std::sync::atomic::Ordering::SeqCst);
        let expected_height = miner_last_confirmed_height + 1;

        info!("Waiting for block proposal at height {}", expected_height);

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
