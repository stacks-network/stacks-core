use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use libsigner::v0::messages::RejectReason;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};

use super::context::{SignerTestContext, SignerTestState};
use crate::stacks_common::types::PublicKey;
use crate::tests::signer::v0::{
    get_nakamoto_headers, wait_for_block_global_rejection_with_reject_reason,
    wait_for_block_proposal, wait_for_block_pushed_by_miner_key, MultipleMinerTest,
};

pub struct WaitForTenureChangeBlockFromMiner1 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl WaitForTenureChangeBlockFromMiner1 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForTenureChangeBlockFromMiner1 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for Nakamoto block from miner 1. Result: {:?}",
            !state.mining_stalled
        );
        !state.mining_stalled
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Waiting for Nakamoto block from miner 1");

        let miners_arc = self.miners.clone();

        let (miner_pk_1, last_confirmed_nakamoto_height_counter) = {
            let miners = miners_arc.lock().unwrap();
            let (miner_pk_1, _) = miners.get_miner_public_keys();
            let last_confirmed_nakamoto_height = miners.get_primary_last_stacks_tip_counter();
            (miner_pk_1, last_confirmed_nakamoto_height)
        };

        let last_confirmed_height = last_confirmed_nakamoto_height_counter
            .0
            .load(Ordering::SeqCst);
        let expected_height = last_confirmed_height + 1;

        info!(
            "Waiting for Nakamoto block {} pushed by miner 1",
            expected_height
        );

        let _miner_1_block = wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk_1)
            .expect(&format!("Failed to get block {}", expected_height));
    }

    fn label(&self) -> String {
        "WAIT_FOR_TENURE_CHANGE_BLOCK_FROM_MINER_1".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            WaitForTenureChangeBlockFromMiner1::new(ctx.miners.clone()),
        ))
    }
}

pub struct WaitForTenureChangeBlockFromMiner2 {
    miners: Arc<Mutex<MultipleMinerTest>>,
}

impl WaitForTenureChangeBlockFromMiner2 {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>) -> Self {
        Self { miners }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForTenureChangeBlockFromMiner2 {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for Nakamoto block from miner 2. Result: {:?}",
            !state.mining_stalled
        );
        !state.mining_stalled
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Waiting for Nakamoto block from miner 2");

        let miners_arc = self.miners.clone();

        let (miner_pk_2, last_confirmed_nakamoto_height_counter) = {
            let miners = miners_arc.lock().unwrap();
            let (_, miner_pk_2) = miners.get_miner_public_keys();
            let last_confirmed_nakamoto_height = miners.get_secondary_last_stacks_tip_counter();
            (miner_pk_2, last_confirmed_nakamoto_height)
        };

        let last_confirmed_height = last_confirmed_nakamoto_height_counter
            .0
            .load(Ordering::SeqCst);
        let expected_stacks_height = last_confirmed_height + 1;

        info!(
            "Waiting for Nakamoto block {} pushed by miner 2",
            expected_stacks_height
        );

        let _miner_2_block_n_1 =
            wait_for_block_pushed_by_miner_key(30, expected_stacks_height, &miner_pk_2)
                .expect(&format!("Failed to get block {:?}", expected_stacks_height));
    }

    fn label(&self) -> String {
        "WAIT_FOR_TENURE_CHANGE_BLOCK_FROM_MINER_2".to_string()
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        Just(CommandWrapper::new(
            WaitForTenureChangeBlockFromMiner2::new(ctx.miners.clone()),
        ))
    }
}

/// ---------------------------------------------------------
/// ---------------------------------------------------------
/// ---------------------------------------------------------
/// ---------------------------------------------------------
/// ---------------------------------------------------------

pub struct WaitForAndVerifyBlockRejection {
    miners: Arc<Mutex<MultipleMinerTest>>,
    reason: RejectReason,
    num_signers: usize,
}

impl WaitForAndVerifyBlockRejection {
    pub fn new(
        miners: Arc<Mutex<MultipleMinerTest>>,
        reason: RejectReason,
        num_signers: usize,
    ) -> Self {
        Self {
            miners,
            reason,
            num_signers,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for WaitForAndVerifyBlockRejection {
    fn check(&self, _state: &SignerTestState) -> bool {
        info!(
            "Checking: Waiting for block proposal from miner 1 and verifying rejection with reason {:?}",
            self.reason
        );
        true
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!("Applying: Waiting for block proposal from miner 1 and verifying rejection with reason {:?}", self.reason);

        // Get the current block height and miner1's public key
        let (block_height, miner_pk_1) = {
            let miners = self.miners.lock().unwrap();
            let (conf_1, _) = miners.get_node_configs();
            let chain_info = crate::tests::neon_integrations::get_chain_info(&conf_1);
            let current_height = chain_info.stacks_tip_height;
            //TODO: let block_n_height = current_height - state.operations_counter as u64;
            let block_n_height = current_height - 3;
            let (miner_pk_1, _) = miners.get_miner_public_keys();
            (block_n_height, miner_pk_1)
        };

        info!("Waiting for block proposal at height {}", block_height + 1);

        // Wait for a block proposal from miner 1 at height N+1
        let proposed_block = wait_for_block_proposal(30, block_height + 1, &miner_pk_1)
            .expect("Timed out waiting for block proposal");

        let block_hash = proposed_block.header.signer_signature_hash();

        info!(
            "Received block proposal at height {} with hash {:?}",
            block_height + 1,
            block_hash
        );

        // Check the block has been rejected with the expected reason
        wait_for_block_global_rejection_with_reject_reason(
            30,
            block_hash,
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
            "WAIT_FOR_AND_VERIFY_BLOCK_REJECTION_WITH_REASON_{:?}",
            self.reason
        )
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        (1usize..=5usize).prop_map(move |num_signers: usize| {
            CommandWrapper::new(WaitForAndVerifyBlockRejection::new(
                ctx.miners.clone(),
                RejectReason::ReorgNotAllowed,
                num_signers,
            ))
        })
    }
}

/// ---------------------------------------------------------
/// ---------------------------------------------------------
/// ---------------------------------------------------------
/// ---------------------------------------------------------
/// ---------------------------------------------------------

pub struct VerifyMiner1BlockCount {
    miners: Arc<Mutex<MultipleMinerTest>>,
    expected_count: usize,
}

impl VerifyMiner1BlockCount {
    pub fn new(miners: Arc<Mutex<MultipleMinerTest>>, expected_count: usize) -> Self {
        Self {
            miners,
            expected_count,
        }
    }
}

impl Command<SignerTestState, SignerTestContext> for VerifyMiner1BlockCount {
    fn check(&self, state: &SignerTestState) -> bool {
        info!(
            "Checking: Verifying miner 1 block count. Will run if miner 1 commit ops are paused: {:?}",
            state.is_primary_miner_skip_commit_op
        );

        // Only run this verification when miner 1's commit operations are paused
        state.is_primary_miner_skip_commit_op
    }

    fn apply(&self, _state: &mut SignerTestState) {
        info!(
            "Applying: Verifying miner 1 block count is {}",
            self.expected_count
        );

        // Extract everything we need from the locked mutex within this scope
        let (stacks_height_before, conf_1, miner_pk_1) = {
            let miners = self.miners.lock().unwrap();
            let current_height = miners.get_peer_stacks_tip_height();
            //TODO: let stacks_height_before = current_height - state.operations_counter as u64;
            let stacks_height_before = current_height - 3;

            // Get the configs and miner public key
            let (conf_1, _) = miners.get_node_configs();
            let (miner_pk_1, _) = miners.get_miner_public_keys();

            // Return the values we need outside the lock
            (stacks_height_before, conf_1, miner_pk_1)
        };

        // Check only expected_count blocks from miner1 have been added after the epoch3 boot
        let miner1_blocks_after_boot_to_epoch3 = get_nakamoto_headers(&conf_1)
            .into_iter()
            .filter(|block| {
                // skip first nakamoto block
                if block.stacks_block_height == stacks_height_before {
                    return false;
                }
                let nakamoto_block_header = block.anchored_header.as_stacks_nakamoto().unwrap();
                miner_pk_1
                    .verify(
                        nakamoto_block_header.miner_signature_hash().as_bytes(),
                        &nakamoto_block_header.miner_signature,
                    )
                    .unwrap()
            })
            .count();

        assert_eq!(
            miner1_blocks_after_boot_to_epoch3, self.expected_count,
            "Expected {} blocks from miner 1, but found {}",
            self.expected_count, miner1_blocks_after_boot_to_epoch3
        );

        info!(
            "Verified miner 1 has exactly {} blocks after epoch 3 boot",
            self.expected_count
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_MINER_1_BLOCK_COUNT_{}", self.expected_count)
    }

    fn build(
        ctx: Arc<SignerTestContext>,
    ) -> impl Strategy<Value = CommandWrapper<SignerTestState, SignerTestContext>> {
        //TODO: randomize expected_count?
        Just(CommandWrapper::new(VerifyMiner1BlockCount::new(
            ctx.miners.clone(),
            1,
        )))
    }
}
