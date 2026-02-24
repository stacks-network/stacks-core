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

use stacks::types::chainstate::StacksPublicKey;
use stacks_signer::v0::tests::{
    TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_SIGNERS_IGNORE_BLOCK_RESPONSES,
    TEST_SIGNERS_IGNORE_PRE_COMMITS, TEST_SKIP_BLOCK_BROADCAST,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::nakamoto_node::stackerdb_listener::TEST_IGNORE_SIGNERS;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::signer::v0::{
    wait_for_block_acceptance_from_signers, wait_for_block_pre_commits_from_signers,
    wait_for_block_proposal, wait_for_block_pushed,
};

#[test]
#[ignore]
/// Tests that if pre-commits arrive before block proposals, signers reprocess
/// the late proposal and still reach acceptance once a threshold is met.
///
/// Test Setup:
/// - 5 signers attached to one miner
///
/// Test Execution:
/// 1. Configure 2 signers to ignore incoming block proposals.
/// 2. Propose a block to all signers.
/// 3. The other 3 signers pre-commit; the ignoring signers do not.
/// 4. Confirm the ignoring signers did not pre-commit.
/// 5. Switch: allow the 2 signers to process proposals, and make the other 3
///    ignore pre-commits and block responses so only the late signers' signatures
///    can trigger acceptance.
/// 6. Repropose the same block.
///
/// Test Assertions:
/// - Only the non-ignoring signers pre-commit initially (ignoring signers do not).
/// - After reproposal, all signers accept the block once the late signers
///   issue their pre-commits/signatures.
/// - The accepted block is pushed, and the node advances to the expected height.
///
fn signers_reprocess_late_block_proposals_pre_commits() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let all_signers = signer_test.signer_test_pks();
    let ignoring_signers = all_signers.iter().take(2).cloned().collect::<Vec<_>>();
    let non_ignoring_signers = all_signers.iter().skip(2).cloned().collect::<Vec<_>>();
    let miner_pk = StacksPublicKey::from_private(
        &signer_test
            .running_nodes
            .conf
            .miner
            .mining_key
            .clone()
            .unwrap(),
    );
    signer_test.boot_to_epoch_3();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignoring_signers.clone());

    info!("------------------------- Mine Tenure A and Propose Block N -------------------------");
    let expected_height = signer_test.get_peer_info().stacks_tip_height + 1;
    signer_test.mine_bitcoin_block();
    info!("------------------------- Wait for block proposal -------------------------");
    let block_proposal = wait_for_block_proposal(30, expected_height, &miner_pk)
        .expect("Miner failed to propose tenure start block");
    let sighash = block_proposal.block.header.signer_signature_hash();
    info!("------------------------- Wait for block pre-commits -------------------------");
    wait_for_block_pre_commits_from_signers(30, &sighash, &non_ignoring_signers)
        .expect("Non-ignoring signers failed to pre-commit to block proposal");
    // Only wait a few seconds longer than it takes for the non-ignoring signers to pre-commit to ensure the ignoring signers are not pre-committing
    assert!(
        wait_for_block_pre_commits_from_signers(5, &sighash, &ignoring_signers).is_err(),
        "Ignoring signers should not have pre-committed to block proposal"
    );
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(non_ignoring_signers.clone());
    // Set the non-ignoring signers to ignore block responses to ensure the trigger for signing the block is
    // the late signers issuing their signatures
    TEST_SIGNERS_IGNORE_PRE_COMMITS.set(non_ignoring_signers.clone());

    info!("------------------------- Resend the same block proposal -------------------------");
    signer_test.send_block_proposal(block_proposal, Duration::from_secs(20));
    wait_for_block_acceptance_from_signers(30, &sighash, &all_signers)
        .expect("All signers should have accepted the block proposal after it was reproposed");
    info!("------------------------- Wait for block pushed -------------------------");
    wait_for_block_pushed(30, &sighash)
        .expect("Block should have been pushed to the node after being accepted by all signers");
    wait_for(30, || {
        Ok(signer_test.get_peer_info().stacks_tip_height == expected_height)
    })
    .expect("Node should have advanced to expected height after block acceptance");
}

#[test]
#[ignore]
/// Test that signers still process block proposals that arrive after they have received enough pre-commits and signatures to exceed the acceptance threshold
///
/// Test Setup:
/// - 5 signers attached to one miner
///
/// Test Execution:
/// 1. Configure 1 signer to ignore incoming block proposals, configure all signers
///    to skip block broadcast, and the miner to ignore signatures so that the only
///    trigger for block acceptance is the late signer's signatures.
/// 2. Propose a block to all signers.
/// 3. The other 4 signers pre-commit/issue signatures across the block; the ignoring signers do not.
/// 4. Confirm the ignoring signers did not pre-commit/issue signatures.
/// 5. Switch: allow the 1 signer to process proposals, and make the other 4 ignore responses
///    ignore pre-commits and block responses so only the late signers' signatures
///    can trigger acceptance.
/// 6. Repropose the same block.
///
/// Test Assertions:
/// - Only the non-ignoring signers pre-commit/issue signatures initially (ignoring signers do not).
/// - After reproposal, the late signer accepts the block and issues its signature and broadcasts the block
/// - The accepted block is pushed, and the node advances to the expected height.
fn signers_reprocess_late_block_proposals_signatures() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let all_signers = signer_test.signer_test_pks();
    let ignoring_signers = all_signers.iter().take(1).cloned().collect::<Vec<_>>();
    let non_ignoring_signers = all_signers.iter().skip(1).cloned().collect::<Vec<_>>();
    let miner_pk = StacksPublicKey::from_private(
        &signer_test
            .running_nodes
            .conf
            .miner
            .mining_key
            .clone()
            .unwrap(),
    );
    signer_test.boot_to_epoch_3();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignoring_signers.clone());
    TEST_IGNORE_SIGNERS.set(true);
    TEST_SKIP_BLOCK_BROADCAST.set(true);

    info!("------------------------- Mine Tenure A and Propose Block N -------------------------");
    let expected_height = signer_test.get_peer_info().stacks_tip_height + 1;
    signer_test.mine_bitcoin_block();
    info!("------------------------- Wait for block proposal -------------------------");
    let block_proposal = wait_for_block_proposal(30, expected_height, &miner_pk)
        .expect("Miner failed to propose tenure start block");
    let sighash = block_proposal.block.header.signer_signature_hash();
    info!(
        "------------------------- Wait for block pre-commits/signatures -------------------------"
    );
    wait_for_block_pre_commits_from_signers(30, &sighash, &non_ignoring_signers)
        .expect("Non-ignoring signers failed to pre-commit to block proposal");
    wait_for_block_acceptance_from_signers(30, &sighash, &non_ignoring_signers)
        .expect("Non-ignoring signers failed to sign the block proposal");
    // Only wait a few seconds longer than it takes for the non-ignoring signers to pre-commit/sign
    // as they are sharing the same node and shouldn't be far behind.
    assert!(
        wait_for_block_pre_commits_from_signers(5, &sighash, &ignoring_signers).is_err(),
        "Ignoring signer should not have pre-committed to block proposal"
    );
    assert!(
        wait_for_block_acceptance_from_signers(5, &sighash, &ignoring_signers).is_err(),
        "Ignoring signer should not have signed the block proposal"
    );
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(non_ignoring_signers.clone());
    // Set the non-ignoring signers to ignore block responses to ensure the trigger for signing the block is
    // the late signers issuing their signatures
    TEST_SIGNERS_IGNORE_PRE_COMMITS.set(non_ignoring_signers.clone());
    TEST_SIGNERS_IGNORE_BLOCK_RESPONSES.set(non_ignoring_signers.clone());
    TEST_SKIP_BLOCK_BROADCAST.set(false);
    assert!(signer_test.get_peer_info().stacks_tip_height < expected_height, "Node should not have advanced to expected height yet since the block should not have been accepted yet");

    info!("------------------------- Resend the same block proposal -------------------------");
    signer_test.send_block_proposal(block_proposal, Duration::from_secs(20));
    wait_for_block_acceptance_from_signers(30, &sighash, &ignoring_signers)
        .expect("Ignoring signer should have accepted the block proposal after it was reproposed");
    info!("------------------------- Wait for block pushed -------------------------");
    wait_for_block_pushed(30, &sighash)
        .expect("Block should have been pushed to the node after the threshold was exceeded by the late signer");
    wait_for(30, || {
        Ok(signer_test.get_peer_info().stacks_tip_height == expected_height)
    })
    .expect("Node should have advanced to expected height after block acceptance");
}
