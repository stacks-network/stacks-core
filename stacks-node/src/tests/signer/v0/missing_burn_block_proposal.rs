// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::env;
use std::time::Duration;

use libsigner::v0::messages::RejectCode;
use pinny::tag;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::TransactionPayload;
use stacks::net::api::postblock_proposal::ValidateRejectCode;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util::hash::{MerkleTree, Sha512Trunc256Sum};
use stacks_signer::v0::tests::TEST_IGNORE_ALL_BLOCK_PROPOSALS;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::nakamoto_node::miner::TEST_BROADCAST_PROPOSAL_STALL;
use crate::nakamoto_node::stackerdb_listener::TEST_IGNORE_SIGNERS;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, test_observer};
use crate::tests::signer::v0::{wait_for_block_proposal, wait_for_block_rejections_from_signers};
use crate::tests::signer::SignerTest;

#[tag(bitcoind)]
#[test]
#[ignore]
/// Test that when a block proposal contains a TenureChange referencing an
/// unknown burn view consensus hash or one with `pox_valid = 0`, all
/// signers reject it with `ValidationFailed(NotFoundError)` and will
/// reprocess (not short-circuit) the proposal if it is reproposed.
///
/// Test Setup:
/// The test spins up 5 Stacks signers, one miner Nakamoto node, and a
/// corresponding bitcoind instance. The node is advanced to the Epoch 3.0
/// boundary to allow block signing.
///
/// Test Execution:
/// 1. The miner mines a burn block to start a new tenure.
/// 2. The resulting block proposal is intercepted before signers process it.
/// 3. The TenureChange transaction is modified to reference a bogus
///    burn_view_consensus_hash (one that does not exist in the sortition DB).
/// 4. The transaction Merkle root and miner signature are recomputed.
/// 5. The modified block is proposed to the signers.
/// 6. All signers reject the block during validation with
///    `Chainstate Error: Not found`.
/// 7. The same modified block is reproposed.
/// 8. Signers revalidate the proposal and reject it again with the same
///    `NotFoundError` (rather than returning `RejectedInPriorRound`).
///
/// Test Assertion:
/// - All signers reject the modified block with
///   `ValidationFailed(NotFoundError)`.
/// - Upon reproposal, the block is fully revalidated and rejected again
///   with the same error.
/// - The rejection is treated as re-evaluable rather than terminal.
fn signer_reevaluates_proposal_with_missing_burn_view() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test = SignerTest::new(num_signers, vec![]);
    let all_signers = signer_test.signer_test_pks();
    let conf = signer_test.running_nodes.conf.clone();
    let miner_privk = signer_test.get_miner_key();
    let miner_pubk = StacksPublicKey::from_private(&miner_privk);

    signer_test.boot_to_epoch_3();

    info!("------------------------- Start a new Tenure -------------------------");

    let info_before = get_chain_info(&conf);
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(all_signers.clone());
    // Also ignore the signers so we can repropose the block after it is rejected without the miner reproposing it.
    TEST_IGNORE_SIGNERS.set(true);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);
    wait_for(30, || {
        Ok(get_chain_info(&conf).burn_block_height >= info_before.burn_block_height)
    })
    .expect("Failed to wait for burn block height to update after mining a block");
    info!("------------------------- Retrieve the block proposal for later proposal -------------------------");
    let block_proposal =
        wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pubk)
            .expect("Miner 2 did not propose a tenure change block");
    // Pause the proposal again for granular control
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pubk.clone()]);
    info!("------------------------- Allow signers to consider incoming block proposals -------------------------");
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);

    info!("------------------------- Re-propose block proposal with bad burn view consensus hash -------------------------");
    test_observer::clear();
    let mut block = block_proposal.block.clone();
    let mut tenure_change_tx = block.txs[0].clone();
    let mut tenure_change_payload = tenure_change_tx.try_as_tenure_change().unwrap().clone();
    tenure_change_payload.burn_view_consensus_hash = ConsensusHash([7u8; 20]);
    tenure_change_tx.payload = TransactionPayload::TenureChange(tenure_change_payload);

    block.txs[0] = tenure_change_tx;

    let tx_merkle_root = {
        let txid_vecs: Vec<_> = block
            .txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();
        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };
    block.header.tx_merkle_root = tx_merkle_root;

    block.header.sign_miner(&miner_privk).unwrap();

    let proposed_sighash = block.header.signer_signature_hash();
    signer_test.propose_block(block.clone(), Duration::from_secs(30));
    let proposed_block =
        wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pubk)
            .expect("Miner did not propose a tenure change block");

    assert_eq!(
        proposed_block.block.header.signer_signature_hash(),
        proposed_sighash
    );
    info!("------------------------- Confirm Signers Reject block N due to invalid burn view causing DBError::NotFound -------------------------");
    let rejections = wait_for_block_rejections_from_signers(30, &proposed_sighash, &all_signers)
        .expect("Failed to find block rejections from all signers for the reproposed block");
    rejections.iter().for_each(|rejection| {
        assert_eq!(
            rejection.reason_code,
            RejectCode::ValidationFailed(ValidateRejectCode::NotFoundError)
        );
        assert_eq!(rejection.reason, "Chainstate Error: Not found");
    });

    info!("------------------------- Confirm signers reprocess the block after reproposed even though Rejected previously with NotFoundError -------------------------");
    // This used to return "RejectedInPriorRound" but now that we allow the NotFoundError to be reprocessed it should reply with the same error again
    test_observer::clear();
    signer_test.propose_block(block, Duration::from_secs(30));
    let rejections = wait_for_block_rejections_from_signers(30, &proposed_sighash, &all_signers)
        .expect("Failed to find block rejections from all signers for the reproposed block");
    rejections.iter().for_each(|rejection| {
        assert_eq!(
            rejection.reason_code,
            RejectCode::ValidationFailed(ValidateRejectCode::NotFoundError)
        );
        assert_eq!(rejection.reason, "Chainstate Error: Not found");
    });
    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}
