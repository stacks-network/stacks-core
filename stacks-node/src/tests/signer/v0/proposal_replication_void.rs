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

use libsigner::v0::messages::RejectReason;
use pinny::tag;
use stacks::core::test_util::to_addr;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util::get_epoch_time_secs;
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::TEST_IGNORE_ALL_BLOCK_PROPOSALS;
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, test_observer};
use crate::tests::signer::v0::{
    wait_for_block_proposal, wait_for_block_pushed_and_tip, wait_for_block_rejections_from_signers,
};

#[tag(bitcoind)]
#[test]
#[ignore]
/// Reproduce a "replication void", where the miner's block proposal reaches no
/// signer at all, for less time than `block_proposal_max_age_secs`.
///
/// Test Setup:
/// Five signers, one miner Nakamoto node, bitcoind. The miner's
/// block_rejection_timeout is shrunk to 20s so the resend loop is observable
/// quickly.
///
/// Test Execution:
/// 1. All signers are set to ignore incoming proposals (the void).
/// 2. A transfer tx forces the miner to mine and propose block N.
/// 3. Wait for the first re-send of the proposal and assert it is verbatim:
///    identical signer_signature_hash and header timestamp, and the chain tip
///    has not advanced.
/// 4. Lift the void. The signers accept the *original* proposal.
///
/// Test Assertion:
/// The block that finally advances the tip is the original block N proposal —
/// same hash, same (now old) header timestamp. This proves that a void
/// shorter than block_proposal_max_age_secs ends with an old-timestamped
/// block on chain, NOT a freshly mined one.
fn proposal_void_shorter_than_max_age_recovers_with_original_block() {
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
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_| {},
        |config| {
            // make the miner's SignatureTimeout resend loop fast enough to observe
            config.miner.block_rejection_timeout_steps = [(0, Duration::from_secs(20))].into();
        },
        None,
        None,
    );
    signer_test.boot_to_epoch_3();

    let conf = signer_test.running_nodes.conf.clone();
    let miner_sk = conf.miner.mining_key.clone().unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();

    info!("------------------------- Open the Void: All Signers Ignore Proposals -------------------------");
    test_observer::clear();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(all_signers);

    let info_before = get_chain_info(&conf);
    info!("------------------------- Force Miner to Propose Block N -------------------------");
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit transfer tx");

    let proposal_1 = wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pk)
        .expect("Timed out waiting for the initial proposal of block N");
    let sighash_1 = proposal_1.block.header.signer_signature_hash();
    let timestamp_1 = proposal_1.block.header.timestamp;

    info!("------------------------- Wait for the Verbatim Re-Send -------------------------";
        "signer_signature_hash" => %sighash_1,
        "timestamp" => timestamp_1,
    );
    test_observer::clear();
    let proposal_2 = wait_for_block_proposal(60, info_before.stacks_tip_height + 1, &miner_pk)
        .expect("Timed out waiting for the miner to re-send the proposal into the void");
    assert_eq!(
        proposal_2.block.header.signer_signature_hash(),
        sighash_1,
        "Miner should re-send the SAME proposal on SignatureTimeout, not re-mine"
    );
    assert_eq!(
        proposal_2.block.header.timestamp, timestamp_1,
        "Re-sent proposal must keep the original header timestamp"
    );
    let info_during = get_chain_info(&conf);
    assert_eq!(
        info_during.stacks_tip_height, info_before.stacks_tip_height,
        "Chain must not advance while the proposal reaches no signer"
    );

    info!("------------------------- Lift the Void -------------------------");
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);

    let block_n =
        wait_for_block_pushed_and_tip(60, info_before.stacks_tip_height + 1, &miner_pk, || {
            get_chain_info(&conf).stacks_tip
        })
        .expect("Block N was not accepted after the void was lifted");
    assert_eq!(
        block_n.header.signer_signature_hash(),
        sighash_1,
        "The block that ends the stall must be the ORIGINAL proposal"
    );
    assert_eq!(
        block_n.header.timestamp, timestamp_1,
        "The accepted block must carry the original (old) header timestamp"
    );
    // the accepted timestamp is genuinely old relative to acceptance time
    assert!(
        get_epoch_time_secs() >= timestamp_1 + 20,
        "Test expected at least one full resend cycle to elapse before acceptance"
    );
    signer_test.shutdown();
}

#[tag(bitcoind)]
#[test]
#[ignore]
/// Verify that a "replication void" longer than `block_proposal_max_age_secs`
/// no longer livelocks the tenure.
///
/// Historically, signers silently dropped proposals whose header timestamp
/// was older than `block_proposal_max_age_secs`, broadcasting no rejection.
/// The miner's resend loop exits only on rejections reaching 30% weight, a
/// burn/stacks tip change, or the block appearing in the staging DB — none of
/// which can happen when every signer stays silent — so the miner re-sent the
/// same stale block forever and the tenure livelocked until the next
/// sortition. Signers now reject stale proposals with
/// `RejectReason::ProposalTooOld`, which trips the miner's rejection
/// threshold and makes it re-mine a fresh block.
///
/// Test Setup:
/// Five signers with block_proposal_max_age_secs = 30, one miner with a 15s
/// rejection timeout.
///
/// Test Execution:
/// 1. All signers ignore proposals (the void); the miner proposes block N.
/// 2. Hold the void for > 30s so the proposal goes stale, then lift it.
/// 3. The miner re-sends the stale proposal; every signer rejects it with
///    ProposalTooOld.
/// 4. The miner re-mines and the chain advances — with NO new bitcoin block.
///
/// Test Assertion:
/// - All signers reject the stale proposal with reason ProposalTooOld.
/// - The chain recovers within the same tenure (no new sortition needed) and
///   the recovery block is a fresh re-mine: different signer_signature_hash
///   and a newer header timestamp.
fn proposal_void_longer_than_max_age_recovers_by_rejection_and_remine() {
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
    let max_age_secs = 30;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.block_proposal_max_age_secs = max_age_secs;
        },
        |config| {
            config.miner.block_rejection_timeout_steps = [(0, Duration::from_secs(15))].into();
        },
        None,
        None,
    );
    signer_test.boot_to_epoch_3();

    let conf = signer_test.running_nodes.conf.clone();
    let miner_sk = conf.miner.mining_key.clone().unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();

    info!("------------------------- Open the Void: All Signers Ignore Proposals -------------------------");
    test_observer::clear();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(all_signers.clone());

    let info_before = get_chain_info(&conf);
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit transfer tx");

    let proposal_1 = wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pk)
        .expect("Timed out waiting for the initial proposal of block N");
    let sighash_1 = proposal_1.block.header.signer_signature_hash();
    let timestamp_1 = proposal_1.block.header.timestamp;

    info!("------------------------- Hold the Void Until the Proposal Is Stale -------------------------";
        "signer_signature_hash" => %sighash_1,
        "timestamp" => timestamp_1,
        "max_age_secs" => max_age_secs,
    );
    // wait until the proposal is comfortably past max age (measured from its
    // own header timestamp), while the miner keeps re-sending into the void
    wait_for(max_age_secs * 3, || {
        Ok(get_epoch_time_secs() > timestamp_1 + max_age_secs + 5)
    })
    .expect("Timed out waiting for wall clock to pass proposal max age");

    info!(
        "------------------------- Lift the Void; Proposal Is Now Stale -------------------------"
    );
    test_observer::clear();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);

    // the miner must still be re-sending the same stale block
    let proposal_stale = wait_for_block_proposal(60, info_before.stacks_tip_height + 1, &miner_pk)
        .expect("Timed out waiting for the miner to re-send the stale proposal");
    assert_eq!(
        proposal_stale.block.header.signer_signature_hash(),
        sighash_1,
        "Miner should still be re-sending the SAME stale proposal"
    );

    info!("------------------------- Signers Reject the Stale Proposal -------------------------");
    let rejections = wait_for_block_rejections_from_signers(60, &sighash_1, &all_signers)
        .expect("Timed out waiting for ProposalTooOld rejections from all signers");
    for rejection in &rejections {
        assert_eq!(
            rejection.response_data.reject_reason,
            RejectReason::ProposalTooOld,
            "Stale proposal must be rejected as ProposalTooOld"
        );
    }

    info!(
        "------------------------- Miner Re-Mines Within the Same Tenure -------------------------"
    );
    // no new bitcoin block: recovery must come from the miner re-mining after
    // the rejections trip its threshold
    let burn_height_before = get_chain_info(&conf).burn_block_height;
    let recovery_block =
        wait_for_block_pushed_and_tip(120, info_before.stacks_tip_height + 1, &miner_pk, || {
            get_chain_info(&conf).stacks_tip
        })
        .expect("Chain did not recover via re-mine after the stale proposal was rejected");
    assert_eq!(
        get_chain_info(&conf).burn_block_height,
        burn_height_before,
        "Recovery must not depend on a new sortition"
    );
    assert_ne!(
        recovery_block.header.signer_signature_hash(),
        sighash_1,
        "Recovery block must be freshly mined, not the stale proposal"
    );
    assert!(
        recovery_block.header.timestamp > timestamp_1,
        "Recovery block must carry a fresh header timestamp"
    );
    signer_test.shutdown();
}
