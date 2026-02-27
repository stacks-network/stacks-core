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

use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::RejectCode;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::TenureChangeCause;
use stacks::core::test_util::{make_stacks_transfer_serialized, to_addr};
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::{
    TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_REJECT_ALL_BLOCK_PROPOSAL,
    TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::nakamoto_node::stackerdb_listener::TEST_IGNORE_SIGNERS;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{submit_tx, test_observer};
use crate::tests::signer::v0::{
    wait_for_block_acceptance_from_signers, wait_for_block_global_acceptance_from_signers,
    wait_for_block_pre_commits_from_signers, wait_for_block_proposal, wait_for_block_pushed,
    wait_for_block_pushed_by_miner_key, wait_for_block_rejections_from_signers, MultipleMinerTest,
};
use crate::tests::signer::SignerTest;

#[test]
#[ignore]
/// Tests that signers will not reconsider blocks that they have already responded to that have been marked GloballyAccepted.
///
/// Test Setup:
/// - Distribute signers across two miners (4 on miner 1, 1 on miner 2)
/// - Need to be able to ensure the signer on miner 2 does not receive the block validate responses for the first proposed block
///
/// Test Execution:
/// 1. Configure the one signer on miner 2 to reject all proposals.
/// 2. Propose a block to all signers.
/// 3. The other 4 signers pre-commit/sign the block; the rejecting signer rejects.
/// 4. Allow rejecting signer to process proposals again.
/// 5. Repropose the same block.
/// 6. Confirm the previously rejecting signer does not reject the block again.
///
/// Test Assertions:
/// - Only the non-rejecting signers pre-commit/sign initially (rejecting signer does not).
/// - After reproposal, the previously rejecting signer does not reject the block again.
fn signers_do_not_reconsider_globally_accepted_and_responded_blocks() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");

    // Create a multiple miner test with 5 signers
    // They will be distributed: 4 to miner 1, 1 to miner 2
    let num_signers = 5;
    let node_2_auth = "node_2".to_string();
    let node_1_auth = "node_1".to_string();
    let mut miners = MultipleMinerTest::new_with_signer_dist(
        num_signers,
        0,
        |config| {
            if config.endpoint.port() % 5 == 0 {
                config.auth_password = node_2_auth.clone();
            } else {
                config.auth_password = node_1_auth.clone();
            }
        },
        |config| {
            config.burnchain.pox_reward_length = Some(30);
            config.connection_options.auth_token = Some(node_1_auth.clone());
        },
        |config| {
            config.connection_options.auth_token = Some(node_2_auth.clone());
        },
        // Distribute signers so first 4 go to node 1, last 1 goes to node 2
        |port| if port % 5 == 0 { 1 } else { 0 },
        None,
    );
    let all_signers = miners.signer_test.signer_test_pks();
    let signer_configs = &miners.signer_test.signer_configs;
    let (conf_1, conf_2) = miners.get_node_configs();
    let mut approving_signers = Vec::new();
    let mut rejecting_signer = Vec::new();
    for (config, signer_pk) in signer_configs.iter().zip(all_signers.iter()) {
        if config.node_host == conf_2.node.rpc_bind {
            rejecting_signer.push(signer_pk.clone());
        } else {
            approving_signers.push(signer_pk.clone());
        }
    }
    assert_eq!(
        rejecting_signer.len(),
        1,
        "Expected exactly one signer to be assigned to miner 2"
    );
    let (miner_pk_1, _miner_pk_2) = miners.get_miner_public_keys();

    miners.pause_commits_miner_2();
    miners.boot_to_epoch_3();

    // Make sure we know which miner will win in the stalled block
    miners.pause_commits_miner_1();
    info!("------------------------- Mine First Block N -------------------------");

    let sortdb = SortitionDB::open(
        &conf_1.get_burn_db_file_path(),
        false,
        conf_1.get_burnchain().pox_constants,
    )
    .unwrap();
    // Mine an initial block to establish state
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");
    miners.submit_commit_miner_1(&sortdb);
    miners.signer_test.check_signer_states_normal();

    let info_before = miners.get_peer_info();
    info!("------------------------- Force 1 Signer to Reject blocks -------------------------");
    // Stall block validation submission on the signer connected to miner 2
    // This prevents that signer from validating the next proposed block
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signer.clone());

    info!("------------------------- Mine Block N+1 -------------------------");
    // Mine a new tenure which will issue a block proposal to all signers for its tenure change.
    miners.signer_test.mine_bitcoin_block();

    let block_proposal =
        wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pk_1)
            .expect("Failed to receive block proposal for block N+1");
    let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
    // The 4 signers on miner 1 should have validated and sent pre-commits
    // The 1 signer on miner 2 should immediately issue a block rejection.
    wait_for_block_pushed(30, &signer_signature_hash).expect("Failed to mine block N+1");
    info!("------------------------- Check Signer Rejected Due to TestingDirective -------------------------");
    let rejections =
        wait_for_block_rejections_from_signers(30, &signer_signature_hash, &rejecting_signer)
            .expect("Did not receive expected block rejection from rejecting signer");
    assert_eq!(
        rejections.len(),
        1,
        "Expected exactly one block rejection from rejecting signer"
    );
    assert_eq!(
        rejections[0].reason_code,
        RejectCode::TestingDirective,
        "Got an unexpected rejection reason from the rejecting signer"
    );

    info!("------------------------- Repropose {signer_signature_hash} -------------------------");
    test_observer::clear();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]); // Unset the reject all block proposals condition so the rejecting signer will reprocess the block proposal.
    miners
        .signer_test
        .send_block_proposal(block_proposal, Duration::from_secs(30));
    assert!(
        wait_for_block_rejections_from_signers(30, &signer_signature_hash, &rejecting_signer)
            .is_err(),
        "Rejecting signer already issued a response and should not issue another"
    );
}

#[test]
#[ignore]
/// Test that signers still process block proposals that arrive after the block has been marked as GloballyAccepted, but that we have not issued a response for.
///
/// Test Setup:
/// - 1 signer attached to miner 2, 4 signers attached to miner 1
/// - Separate the signers so their validations do not affect each other.
///
/// Test Execution:
/// 1. Configure 1 signer to insert block proposals without processing.
/// 2. Propose a block to all signers.
/// 3. The other 4 signers pre-commit/issue signatures across the block; the nonprocessing signer does not.
/// 4. Confirm the nonprocessing signer did not pre-commit/issue a signature, but that the chain has advanced (the block is globally accepted).
/// 5. Allow the 1 signer to process proposals.
/// 6. Repropose the same block.
/// 7. Confirm the signer that the signer that previously did not process the block proposal now issues a rejection (since the block would be reorging itself)
///
/// Test Assertions:
/// - Only the nonprocessing signers pre-commit/issue signatures initially (nonprocessing signer does not).
/// - The accepted block is pushed, and the node advances to the expected height.
/// - After reproposal, the late signer issues a rejection for the block proposal (previously nonprocessed block proposals that were marked globally accepted would simply be ignored)
fn signers_respond_to_unprocessed_globally_accepted_block_proposals() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    // Create a multiple miner test with 5 signers
    // They will be distributed: 4 to miner 1, 1 to miner 2
    let num_signers = 5;
    let mut miners = MultipleMinerTest::new_with_signer_dist(
        num_signers,
        0,
        |_| {},
        |_| {},
        |_| {},
        // Distribute signers so first 1 goes to node 2, last 4 go to node 1
        |port| if port < 3001 { 1 } else { 0 },
        None,
    );
    let all_signers = miners.signer_test.signer_test_pks();
    let signer_configs = &miners.signer_test.signer_configs;
    let mut processing_signers = Vec::new();
    let mut nonprocessing_signers = Vec::new();
    for (config, signer_pk) in signer_configs.iter().zip(all_signers.iter()) {
        if config.endpoint.port() < 3001 {
            nonprocessing_signers.push(signer_pk.clone());
        } else {
            processing_signers.push(signer_pk.clone());
        }
    }
    let all_signers = miners.signer_test.signer_test_pks();
    let nonprocessing_signers = all_signers.iter().take(1).cloned().collect::<Vec<_>>();
    let processing_signers = all_signers.iter().skip(1).cloned().collect::<Vec<_>>();
    let (_conf_1, _conf_2) = miners.get_node_configs();
    let (miner_pk_1, _miner_pk_2) = miners.get_miner_public_keys();
    miners.pause_commits_miner_2();
    miners.boot_to_epoch_3();

    // Make sure we know which miner will win the tenure
    miners.pause_commits_miner_1();
    TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING.set(nonprocessing_signers.clone());

    info!("------------------------- Mine Tenure A and Propose Block N -------------------------");
    let expected_height = miners.signer_test.get_peer_info().stacks_tip_height + 1;
    miners.signer_test.mine_bitcoin_block();
    info!("------------------------- Wait for block proposal -------------------------");
    let block_proposal = wait_for_block_proposal(30, expected_height, &miner_pk_1)
        .expect("Miner failed to propose tenure start block");
    let sighash = block_proposal.block.header.signer_signature_hash();
    wait_for_block_pushed(30, &sighash).expect("Block proposal was not globally accepted");
    info!(
        "------------------------- Wait for block pre-commits/signatures -------------------------"
    );
    // The block was already pushed so shouldn't have to wait at all for these pre-commits/signatures.
    wait_for_block_pre_commits_from_signers(10, &sighash, &processing_signers)
        .expect("Non-processing signers failed to pre-commit to block proposal");
    wait_for_block_acceptance_from_signers(10, &sighash, &processing_signers)
        .expect("Non-processing signers failed to sign the block proposal");
    // Only wait a few seconds longer than it takes for the non-processing signers to pre-commit/sign
    // as they are sharing the same node and shouldn't be far behind.
    assert!(
        wait_for_block_pre_commits_from_signers(2, &sighash, &nonprocessing_signers).is_err(),
        "Non-processing signer should not have pre-committed to block proposal"
    );
    assert!(
        wait_for_block_acceptance_from_signers(2, &sighash, &nonprocessing_signers).is_err(),
        "Non-processing signer should not have signed the block proposal"
    );
    assert!(
        wait_for_block_rejections_from_signers(2, &sighash, &nonprocessing_signers).is_err(),
        "Non-processing signer should not have rejected the block proposal"
    );
    assert_eq!(miners.signer_test.get_peer_info().stacks_tip_height, expected_height, "Node should have advanced to expected height and the block should be marked as globally accepted");

    info!(
        "------------------------- Allow the non-processing signer to process the reproposal -------------------------"
    );
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(processing_signers.clone());
    TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING.set(vec![]);

    info!("------------------------- Resend the same block proposal -------------------------");
    miners
        .signer_test
        .send_block_proposal(block_proposal, Duration::from_secs(20));
    let rejections = wait_for_block_rejections_from_signers(30, &sighash, &nonprocessing_signers)
        .expect(
            "Non-processing signer should have rejected the block proposal after it was reproposed",
        );
    assert_eq!(rejections[0].reason_code, RejectCode::SortitionViewMismatch, "The block proposal should be rejected as it would be reorging a block that is already globally accepted (itself)");
    miners.shutdown();
}

#[test]
#[ignore]
/// Test that signers still process block proposals that arrive after the block has been marked as GloballyRejected, but that we have not issued a response for.
///
/// Test Setup:
/// - 5 signers attached to one miner
///
/// Test Execution:
/// 1. Configure 1 signer to insert block proposals without processing. Configure the remaining 4 to automatically reject all block proposals. Set the miner to ignore
///   responses so that the block will be marked as globally rejected without the miner reproposing a new block (enables us to better control the test)
/// 2. Propose a block to all signers.
/// 3. Confirm the 4 rejecting signers did indeed reject the block proposal. (>30% rejection threshold so its globally rejected)
/// 4. Configure the 1 signer to process block proposals.
/// 5. Repropose the same block.
/// 6. Confirm the 1 signer that the signer that previously did not process the block proposal now issues an acceptance.
/// 7. Allow rejecting signers to process proposals again and confirm the block is globally accepted.
///
/// Test Assertions:
/// - The 4 signers configured to reject block proposals do indeed reject the initial block proposal.
/// - After reproposal, the late signer issues an acceptance for the block proposal.
/// - The block eventually is accepted and the tip advances
fn signers_respond_to_unprocessed_globally_rejected_block_proposals() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, (send_amt + send_fee) * 2)]);
    let all_signers = signer_test.signer_test_pks();
    let nonprocessing_signers = all_signers.iter().take(1).cloned().collect::<Vec<_>>();
    let processing_signers = all_signers.iter().skip(1).cloned().collect::<Vec<_>>();
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

    info!("------------------------- Mine Tenure A and block N to establish state -------------------------");
    let expected_height = signer_test.get_peer_info().stacks_tip_height + 1;
    signer_test.mine_bitcoin_block();
    let _ = wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pk)
        .expect("Failed to mine block N");
    let expected_height = expected_height.saturating_add(1);
    info!("------------------------- Force 1 Signer to reject blocks and the rest to reject all proposals -------------------------");

    TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING.set(nonprocessing_signers.clone());
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(processing_signers.clone());
    TEST_IGNORE_SIGNERS.set(true);

    info!("------------------------- Force block proposal N+1 -------------------------");
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let _ = submit_tx(&http_origin, &transfer_tx);
    let block_proposal = wait_for_block_proposal(30, expected_height, &miner_pk)
        .expect("Miner failed to propose tenure start block");
    let sighash = block_proposal.block.header.signer_signature_hash();
    info!("------------------------- Wait for block rejections of {sighash} -------------------------");
    wait_for_block_rejections_from_signers(30, &sighash, &processing_signers)
        .expect("Processing signers failed to reject block proposal");
    // Only wait a few seconds longer than it takes for the non-processing signers to reject for the remaining non-processing signer.
    assert!(
        wait_for_block_pre_commits_from_signers(2, &sighash, &nonprocessing_signers).is_err(),
        "Non-processing signer should not have pre-committed to block proposal"
    );
    assert!(
        wait_for_block_acceptance_from_signers(2, &sighash, &nonprocessing_signers).is_err(),
        "Non-processing signer should not have signed the block proposal"
    );
    assert!(
        wait_for_block_rejections_from_signers(2, &sighash, &nonprocessing_signers).is_err(),
        "Non-processing signer should not have rejected the block proposal"
    );
    assert!(signer_test.get_peer_info().stacks_tip_height < expected_height, "Node should NOT have advanced to expected height and the block should be marked as globally rejected");

    info!(
        "------------------------- Allow the non-processing signer to process the reproposal -------------------------"
    );
    TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING.set(vec![]);

    signer_test.send_block_proposal(block_proposal.clone(), Duration::from_secs(20));
    wait_for_block_pre_commits_from_signers(30, &sighash, &nonprocessing_signers).expect(
        "Non-processing signers failed to pre-commit to the block proposal after being allowed to process it",
    );

    info!("------------------------- Allow rejecting signers to process the reproposal -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);
    signer_test.send_block_proposal(block_proposal, Duration::from_secs(20));
    wait_for_block_global_acceptance_from_signers(30, &sighash, &all_signers).expect(
        "Failed to globally accept the block proposal after allowing all signers to process it",
    );
    wait_for(30, || {
        let info = signer_test.get_peer_info();
        Ok(info.stacks_tip_height >= expected_height)
    }).expect("Node should have advanced to expected height and the block should be marked as globally accepted");
    signer_test.shutdown();
}
