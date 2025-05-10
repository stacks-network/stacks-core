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

        let last_confirmed_nakamoto_height_counter = self
            .ctx
            .get_counters_for_miner(self.miner_index)
            .naka_submitted_commit_last_stacks_tip;

        let last_confirmed_height = last_confirmed_nakamoto_height_counter
            .0
            .load(Ordering::SeqCst);
        let expected_height = last_confirmed_height + 1;

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

pub struct WaitForBlockProposal {
    ctx: Arc<SignerTestContext>,
    reason: RejectReason,
    expected_block_height: u64,
}

impl WaitForBlockProposal {
    pub fn new(
        ctx: Arc<SignerTestContext>,
        reason: RejectReason,
        expected_block_height: u64,
    ) -> Self {
        Self {
            ctx,
            reason,
            expected_block_height,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForBlockProposal {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for block proposal from miner 1 and verifying rejection with reason {:?}",
            self.reason
        );
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!("Applying: Waiting for block proposal from miner 1 and verifying rejection with reason {:?}", self.reason);

        let miner_pk_1 = {
            let (miner_pk_1, _) = self.ctx.get_miner_public_keys();
            miner_pk_1
        };

        let expected_block_height = state.epoch_3_start_block_height + 2;

        info!(
            "Waiting for block proposal at height {}",
            //TODO: Change expected_block_height with parameter: self.expected_block_height
            expected_block_height
        );

        //TODO: Change expected_block_height with parameter: self.expected_block_height
        let proposed_block = wait_for_block_proposal(30, expected_block_height, &miner_pk_1)
            .expect("Timed out waiting for block proposal");

        let block_hash = proposed_block.header.signer_signature_hash();
        state.last_block_hash = block_hash.clone();

        info!(
            "Received block proposal at height {} with hash {:?}",
            //TODO: Change expected_block_height with parameter: self.expected_block_height
            expected_block_height,
            block_hash
        );
    }

    fn label(&self) -> String {
        "WAIT_FOR_BLOCK_PROPOSAL".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(WaitForBlockProposal::new(
            ctx.clone(),
            RejectReason::ReorgNotAllowed,
            0, // TODO: Don't use a hardcoded value here
        )))
    }
}

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

pub struct WaitForBlockRejectionWithRejectReason {
    ctx: Arc<SignerTestContext>,
    reason: RejectReason,
    num_signers: usize,
}

impl WaitForBlockRejectionWithRejectReason {
    pub fn new(ctx: Arc<SignerTestContext>, reason: RejectReason, num_signers: usize) -> Self {
        Self {
            ctx,
            reason,
            num_signers,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForBlockRejectionWithRejectReason {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for block proposal from miner 1 and verifying rejection with reason {:?}. Result: {:?}",
            self.reason,
            state.last_block_hash != stacks_common::util::hash::Sha512Trunc256Sum([0; 32])
        );
        state.last_block_hash != stacks_common::util::hash::Sha512Trunc256Sum([0; 32])
    }

    fn apply(&self, state: &mut SignerTestState) {
        wait_for_block_global_rejection_with_reject_reason(
            30,
            state.last_block_hash,
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

pub struct VerifyBlockCount {
    ctx: Arc<SignerTestContext>,
    miner_index: usize,
    expected_block_count: usize,
}

impl VerifyBlockCount {
    pub fn new(
        ctx: Arc<SignerTestContext>,
        miner_index: usize,
        expected_block_count: usize,
    ) -> Self {
        Self {
            ctx,
            miner_index,
            expected_block_count,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for VerifyBlockCount {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner {} block count. Result: {:?}",
            self.miner_index, true
        );
        //TODO: Can this always run? Or it must be skipped if the miner is not paused?
        true
    }

    fn apply(&self, state: &mut SignerTestState) {
        info!(
            "Applying: Verifying miner {} block count is {}",
            self.miner_index, self.expected_block_count
        );

        let (conf, miner_pk) = {
            //let current_height = self.ctx.get_peer_stacks_tip_height();
            //FIXME: This must be changed
            // let stacks_height_before = current_height - state.get_blocks_mined_by_miner(2) as u64;

            let (conf_1, conf_2) = self.ctx.get_node_configs();
            let conf = match self.miner_index {
                1 => conf_1,
                2 => conf_2,
                _ => panic!("Invalid miner index: {}", self.miner_index),
            };
            let (miner_pk_1, miner_pk_2) = self.ctx.get_miner_public_keys();
            let miner_pk = match self.miner_index {
                1 => miner_pk_1,
                2 => miner_pk_2,
                _ => panic!("Invalid miner index: {}", self.miner_index),
            };

            (conf, miner_pk)
        };

        let miner_blocks_after_boot_to_epoch3 = self.ctx.get_miner_blocks_after_boot_to_epoch3(
            &conf,
            state.epoch_3_start_block_height,
            &miner_pk,
        );

        assert_eq!(
            miner_blocks_after_boot_to_epoch3, self.expected_block_count,
            "Expected {} blocks from miner {}, but found {}",
            self.expected_block_count, self.miner_index, miner_blocks_after_boot_to_epoch3
        );

        info!(
            "Verified miner {} has exactly {} blocks after epoch 3 boot",
            self.miner_index, self.expected_block_count
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_MINER_{}_BLOCK_COUNT", self.miner_index)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=2usize, 1usize..=5usize).prop_flat_map(
            move |(miner_index, expected_block_count)| {
                Just(CommandWrapper::new(VerifyBlockCount::new(
                    ctx.clone(),
                    miner_index,
                    expected_block_count,
                )))
            },
        )
    }
}
