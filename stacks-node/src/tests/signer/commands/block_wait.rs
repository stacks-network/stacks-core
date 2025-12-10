use std::sync::atomic::Ordering;
use std::sync::Arc;

use libsigner::v0::messages::RejectReason;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use proptest::prop_oneof;
use stacks::chainstate::stacks::{TenureChangeCause, TenureChangePayload, TransactionPayload};

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
pub struct ChainExpectNakaBlock {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    height_strategy: HeightStrategy,
}

#[derive(Debug)]
enum HeightStrategy {
    FromMinerHeight,
    FromStateHeight,
}

impl ChainExpectNakaBlock {
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

    pub fn from_miner_height(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self::new(ctx, miner_index, HeightStrategy::FromMinerHeight)
    }

    pub fn from_state_height(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self::new(ctx, miner_index, HeightStrategy::FromStateHeight)
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainExpectNakaBlock {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for Nakamoto block from miner {}. Result: {}",
            self.miner_index, !state.mining_stalled
        );
        !state.mining_stalled
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: Waiting for Nakamoto block from miner {}",
            self.miner_index
        );

        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);

        // Calculate expected height based on the strategy
        match self.height_strategy {
            HeightStrategy::FromMinerHeight => {
                // Use miner-specific height approach
                let conf = self.ctx.get_node_config(self.miner_index);
                let miner_last_confirmed_height = self
                    .ctx
                    .get_counters_for_miner(self.miner_index)
                    .naka_submitted_commit_last_stacks_tip
                    .load(Ordering::SeqCst);
                let expected_height = miner_last_confirmed_height + 1;

                info!(
                    "Waiting for Nakamoto block {} pushed by miner {}",
                    expected_height, self.miner_index
                );

                let miner_block =
                    wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk)
                        .expect(&format!("Failed to get block {}", expected_height));

                let mined_block_height = miner_block.header.chain_length;

                info!(
                    "Miner {} mined Nakamoto block at height {}",
                    self.miner_index, mined_block_height
                );

                let info_after = get_chain_info(&conf);

                assert_eq!(info_after.stacks_tip, miner_block.header.block_hash());
                assert_eq!(info_after.stacks_tip_height, mined_block_height);
                assert_eq!(mined_block_height, expected_height);
            }
            HeightStrategy::FromStateHeight => {
                // Get the height from the state
                let conf = self.ctx.get_node_config(self.miner_index);
                let expected_height = state.last_stacks_block_height.unwrap() + 1;

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
                assert_eq!(mined_block_height, expected_height);
            }
        }
    }

    fn label(&self) -> String {
        format!("WAIT_FOR_NAKAMOTO_BLOCK_FROM_MINER_{}", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        use proptest::prelude::*;
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            prop_oneof![
                Just(CommandWrapper::new(
                    ChainExpectNakaBlock::from_state_height(ctx.clone(), miner_index)
                )),
                Just(CommandWrapper::new(
                    ChainExpectNakaBlock::from_miner_height(ctx.clone(), miner_index)
                ))
            ]
        })
    }
}

/// Command to wait for a block proposal from a specific miner in the Nakamoto consensus protocol.
/// This command monitors the blockchain until the specified miner submits a block proposal at the expected height.
/// Can optionally wait for the proposed block to be rejected or accepted based on the expectation.
#[derive(Debug, Clone)]
enum BlockExpectation {
    JustProposal,                          // Just wait for proposal, don't check outcome
    ExpectRejection(Option<RejectReason>), // Expect rejection with specific reason
    ExpectAcceptance,                      // Expect the block to be accepted/confirmed
}

pub struct ChainExpectNakaBlockProposal {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    expectation: BlockExpectation,
}

impl ChainExpectNakaBlockProposal {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self {
            ctx,
            miner_index,
            expectation: BlockExpectation::JustProposal,
        }
    }

    pub fn with_rejection(
        ctx: Arc<SignerTestContext>,
        miner_index: usize,
        reason: Option<RejectReason>,
    ) -> Self {
        Self {
            ctx,
            miner_index,
            expectation: BlockExpectation::ExpectRejection(reason),
        }
    }

    #[allow(dead_code)]
    pub fn with_ok(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self {
            ctx,
            miner_index,
            expectation: BlockExpectation::ExpectAcceptance,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainExpectNakaBlockProposal {
    fn check(&self, _state: &SignerTestState) -> bool {
        match &self.expectation {
            BlockExpectation::JustProposal => {
                info!(
                    "Checking: Waiting for block proposal from miner {}",
                    self.miner_index,
                );
                true
            }
            BlockExpectation::ExpectRejection(reason) => {
                info!(
                    "Checking: Waiting for block proposal from miner {} and rejection with reason: {reason:?}",
                    self.miner_index
                );
                true
            }
            BlockExpectation::ExpectAcceptance => {
                info!(
                    "Checking: Waiting for block proposal from miner {} and acceptance",
                    self.miner_index,
                );
                true
            }
        }
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Waiting for block proposal from miner {}",
            self.miner_index
        );

        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);

        // Get the last confirmed height for that specific miner
        let miner_last_confirmed_height = self
            .ctx
            .get_counters_for_miner(self.miner_index)
            .naka_submitted_commit_last_stacks_tip
            .load(Ordering::SeqCst);
        let expected_height = miner_last_confirmed_height + 1;

        info!("Waiting for block proposal at height {expected_height}");

        let proposed_block = wait_for_block_proposal(30, expected_height, &miner_pk)
            .expect("Timed out waiting for block proposal");

        let block_hash = proposed_block.header.signer_signature_hash();

        info!("Received block proposal at height {expected_height} with hash {block_hash}");

        // Handle different expectations after the proposal
        match &self.expectation {
            BlockExpectation::JustProposal => {
                panic!("To be implemented: BlockExpectation::JustProposal");
            }
            BlockExpectation::ExpectRejection(reason) => {
                info!("Now waiting for block rejection with reason {reason:?}");

                wait_for_block_global_rejection_with_reject_reason(
                    30,
                    &block_hash,
                    self.ctx.get_num_signers(),
                    reason.clone(),
                )
                .expect("Timed out waiting for block rejection");

                info!("Block was rejected with the expected reason: {reason:?}");
            }
            BlockExpectation::ExpectAcceptance => {
                panic!("To be implemented: BlockExpectation::ExpectAcceptance");
            }
        }
    }

    fn label(&self) -> String {
        format!("WAIT_FOR_BLOCK_PROPOSAL_FROM_MINER_{}", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(ChainExpectNakaBlockProposal::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}

/// Command to wait for a tenure change block from a specific miner.
/// This command waits for a block that contains:
/// 1. A TenureChange transaction with cause BlockFound
/// 2. A Coinbase transaction
/// This verifies that a proper tenure change has occurred.
pub struct ChainExpectStacksTenureChange {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
}

impl ChainExpectStacksTenureChange {
    pub fn new(ctx: Arc<SignerTestContext>, miner_index: usize) -> Self {
        Self { ctx, miner_index }
    }
}

impl Command<SignerTestState, SignerTestContext> for ChainExpectStacksTenureChange {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for tenure change block from miner {}",
            self.miner_index
        );
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        let miner_pk = self.ctx.get_miner_public_key(self.miner_index);
        // Cannot use global height as this would result in a race condition. Cannot gaurantee
        // that the node has not already processed the stacks block. Must use stored state.
        let expected_height = state.last_stacks_block_height.expect(
            "Cannot wait for a tenure change block if we haven't set the last_stacks_block_height",
        ) + 1;

        info!(
            "Applying: Waiting for tenure change block at height {expected_height} from miner {}",
            self.miner_index
        );

        let block =
            wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk).expect(&format!(
                "Failed to get tenure change block for miner {} at height {expected_height}",
                self.miner_index
            ));

        // Verify this is a tenure change block
        let is_tenure_change_block_found = block.txs.len() == 2
            && matches!(
                block.txs[0].payload,
                TransactionPayload::TenureChange(TenureChangePayload {
                    cause: TenureChangeCause::BlockFound,
                    ..
                })
            )
            && matches!(block.txs[1].payload, TransactionPayload::Coinbase(..));

        assert!(
            is_tenure_change_block_found,
            "Block at height {expected_height} from miner {} is not a proper tenure change block. Transactions: {:?}",
            self.miner_index,
            block.txs.iter().map(|tx| &tx.payload).collect::<Vec<_>>()
        );

        info!(
            "Successfully verified tenure change block at height {expected_height} from miner {}",
            self.miner_index
        );
    }

    fn label(&self) -> String {
        format!(
            "WAIT_FOR_TENURE_CHANGE_BLOCK_FROM_MINER_{}",
            self.miner_index
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize).prop_flat_map(move |miner_index| {
            Just(CommandWrapper::new(ChainExpectStacksTenureChange::new(
                ctx.clone(),
                miner_index,
            )))
        })
    }
}
