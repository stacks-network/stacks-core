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
use std::time::{Duration, Instant};

use libsigner::v0::messages::RejectReason;
use stacks::types::chainstate::StacksPublicKey;
use stacks_signer::v0::tests::{
    TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_REJECT_ALL_BLOCK_PROPOSAL,
    TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

use crate::tests::nakamoto_integrations::{next_block_and, wait_for};
use crate::tests::neon_integrations::test_observer;
use crate::tests::signer::v0::{
    wait_for_block_proposal_block, wait_for_block_rejections_from_signers,
};
use crate::tests::signer::SignerTest;

#[test]
#[ignore]
/// Test that the miner re-proposes a block promptly when signers reject it for
/// a transient reason, but keeps the normal rejection-based timeout otherwise.
///
/// Test Setup:
/// The test spins up five stacks signers and one miner Nakamoto node. The
/// miner's rejection timeout steps are `{0: 180s, 20: 30s}` and its transient
/// rejection retry timeout is 3s.
///
/// Test Execution:
/// One signer (20% of the weight) rejects every proposal and the other four
/// ignore every proposal, so the tenure's first block can neither be approved
/// nor rejected.
/// 1. The rejecting signer uses `NoSignerConsensus` (transient).
/// 2. The rejecting signer switches to `TestingDirective` (not transient).
/// 3. All signers stop rejecting/ignoring proposals.
///
/// Test Assertion:
/// 1. The miner's timeout is set to 3s, and it re-sends the same proposal
///    repeatedly, each time well within the 30s step timeout.
/// 2. The miner's timeout goes back to the 30s step, and it does not re-send
///    the proposal early.
/// 3. The next re-proposal is accepted and the block is mined.
fn transient_rejection_retry_timeout() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let step_timeout = Duration::from_secs(30);
    let retry_timeout = Duration::from_secs(3);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |_| {},
        |config| {
            config.miner.block_rejection_timeout_steps =
                [(0, Duration::from_secs(180)), (20, step_timeout)].into();
            config.miner.transient_rejection_retry_timeout = retry_timeout;
        },
        None,
        None,
    );
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();
    let counters = &signer_test.running_nodes.counters;

    signer_test.boot_to_epoch_3();

    let (reject_signers, ignore_signers) = all_signers.split_at(1);
    TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON.set(RejectReason::NoSignerConsensus);
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(reject_signers.to_vec());
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignore_signers.to_vec());

    info!(
        "------------------------- Mine Tenure With Transient Rejections -------------------------"
    );
    test_observer::clear();
    let height_before = signer_test.get_peer_info().stacks_tip_height;
    let blocks_before = test_observer::get_mined_nakamoto_blocks().len();
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        30,
        || Ok(test_observer::get_mined_nakamoto_blocks().len() > blocks_before),
    )
    .unwrap();

    let proposal = wait_for_block_proposal_block(30, height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal");
    let signer_signature_hash = proposal.header.signer_signature_hash();

    let rejections =
        wait_for_block_rejections_from_signers(30, &signer_signature_hash, reject_signers)
            .expect("Timed out waiting for block rejections");
    for rejection in &rejections {
        assert_eq!(
            rejection.response_data.reject_reason,
            RejectReason::NoSignerConsensus
        );
    }

    wait_for(30, || {
        Ok(counters.naka_miner_current_rejections_timeout_secs.get() == retry_timeout.as_secs())
    })
    .expect("Miner did not set its timeout to the transient retry timeout");

    info!("------------------------- Verify Prompt Re-proposals -------------------------");
    // Each re-proposal must arrive near the retry timeout, well before the
    // 30s step timeout that a non-transient rejection would select.
    let max_reproposal_interval = retry_timeout + Duration::from_secs(5);
    assert!(max_reproposal_interval < step_timeout);
    for _ in 0..3 {
        let proposed_before = counters.naka_proposed_blocks.get();
        let start = Instant::now();
        wait_for(step_timeout.as_secs(), || {
            Ok(counters.naka_proposed_blocks.get() > proposed_before)
        })
        .expect("Miner did not re-propose the block");
        let elapsed = start.elapsed();
        assert!(
            elapsed <= max_reproposal_interval,
            "Miner took {elapsed:?} to re-propose after a transient rejection"
        );
    }

    let proposals: Vec<_> = signer_test
        .get_miner_proposal_messages()
        .into_iter()
        .filter(|proposal| proposal.block.header.chain_length == height_before + 1)
        .collect();
    assert!(proposals.len() >= 4, "Expected the proposal to be re-sent");
    for proposal in &proposals {
        assert_eq!(
            proposal.block.header.signer_signature_hash(),
            signer_signature_hash,
            "Miner should re-send the same proposal"
        );
    }
    assert_eq!(
        signer_test.get_peer_info().stacks_tip_height,
        height_before,
        "Block should not have been mined yet"
    );

    info!("------------------------- Switch To Non-transient Rejections -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON.set(RejectReason::TestingDirective);
    wait_for(30, || {
        Ok(counters.naka_miner_current_rejections_timeout_secs.get() == step_timeout.as_secs())
    })
    .expect("Miner did not restore the step timeout for non-transient rejections");

    // The miner must now wait for the full step timeout before re-proposing.
    let proposed_before = counters.naka_proposed_blocks.get();
    std::thread::sleep(step_timeout / 2);
    assert_eq!(
        counters.naka_proposed_blocks.get(),
        proposed_before,
        "Miner re-proposed early after a non-transient rejection"
    );

    info!("------------------------- Allow Block To Be Signed -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);
    wait_for(step_timeout.as_secs() * 2, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > height_before)
    })
    .expect("Block was not mined after signers stopped rejecting it");

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that the miner re-sends the same proposal, rather than abandoning it,
/// when the signers' rejections only exceed the blocking minority because of
/// transient rejections.
///
/// Test Setup:
/// The test spins up five stacks signers and one miner Nakamoto node. The
/// miner's rejection timeout steps are `{0: 180s, 20: 30s, 30: 0s}` and its
/// transient rejection retry timeout is 3s.
///
/// Test Execution:
/// Two signers (40% of the weight, above the 30% blocking minority) reject
/// every proposal and the other three ignore every proposal.
/// 1. The rejecting signers use `NoSignerConsensus` (transient).
/// 2. The rejecting signers switch to `TestingDirective` (not transient).
/// 3. All signers stop rejecting/ignoring proposals.
///
/// Test Assertion:
/// 1. The miner does not treat the block as rejected, and re-sends the same
///    proposal after the 3s retry timeout (not the 0s step timeout).
/// 2. The miner treats the block as rejected.
/// 3. A block is mined.
fn transient_rejection_over_blocking_minority_resends() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let retry_timeout = Duration::from_secs(3);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |_| {},
        |config| {
            config.miner.block_rejection_timeout_steps = [
                (0, Duration::from_secs(180)),
                (20, Duration::from_secs(30)),
                (30, Duration::from_secs(0)),
            ]
            .into();
            config.miner.transient_rejection_retry_timeout = retry_timeout;
        },
        None,
        None,
    );
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();
    let counters = &signer_test.running_nodes.counters;

    signer_test.boot_to_epoch_3();

    let (reject_signers, ignore_signers) = all_signers.split_at(2);
    TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON.set(RejectReason::NoSignerConsensus);
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(reject_signers.to_vec());
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignore_signers.to_vec());

    info!(
        "------------------------- Mine Tenure With Transient Rejections -------------------------"
    );
    test_observer::clear();
    let height_before = signer_test.get_peer_info().stacks_tip_height;
    let blocks_before = test_observer::get_mined_nakamoto_blocks().len();
    let rejected_before = counters.naka_rejected_blocks.get();
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        30,
        || Ok(test_observer::get_mined_nakamoto_blocks().len() > blocks_before),
    )
    .unwrap();

    let proposal = wait_for_block_proposal_block(30, height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal");
    let signer_signature_hash = proposal.header.signer_signature_hash();

    wait_for_block_rejections_from_signers(30, &signer_signature_hash, reject_signers)
        .expect("Timed out waiting for block rejections");

    info!("------------------------- Verify Re-sent Proposals -------------------------");
    // The miner must select the retry timeout rather than the 0s step for
    // these rejections. This is the primary check; the timing below is a
    // loose sanity check on top of it.
    wait_for(30, || {
        Ok(counters.naka_miner_current_rejections_timeout_secs.get() == retry_timeout.as_secs())
    })
    .expect("Miner did not select the transient retry timeout");

    // The miner's retry timer started when it sent the proposal, not when the
    // rejections became visible to this test, so wait for one re-send first.
    // The span measured below then starts at a proposal boundary.
    let proposed_before = counters.naka_proposed_blocks.get();
    wait_for(30, || {
        Ok(counters.naka_proposed_blocks.get() > proposed_before)
    })
    .expect("Miner did not re-send the proposal");

    // Measure three re-sends as a single span, so that the test's polling lag
    // is paid once rather than once per re-send. Each re-send must wait for the
    // retry timeout (3s), so the span must take well over the ~1s that
    // immediate re-sends would, and well under the 30s that the next longer
    // step would.
    let num_resends: u32 = 3;
    let min_span = retry_timeout * num_resends - Duration::from_millis(1_500);
    let max_span = (retry_timeout + Duration::from_secs(5)) * num_resends;
    let proposed_before = counters.naka_proposed_blocks.get();
    let start = Instant::now();
    wait_for(max_span.as_secs() + 5, || {
        Ok(counters.naka_proposed_blocks.get() >= proposed_before + u64::from(num_resends))
    })
    .expect("Miner did not re-send the proposal");
    let elapsed = start.elapsed();
    assert!(
        elapsed <= max_span,
        "Miner took {elapsed:?} to re-send {num_resends} times after transient rejections"
    );
    assert!(
        elapsed >= min_span,
        "Miner re-sent {num_resends} times in only {elapsed:?}, without waiting for the retry timeout"
    );
    assert_eq!(
        counters.naka_rejected_blocks.get(),
        rejected_before,
        "Miner should not treat a transiently rejected block as rejected"
    );

    let proposals: Vec<_> = signer_test
        .get_miner_proposal_messages()
        .into_iter()
        .filter(|proposal| proposal.block.header.chain_length == height_before + 1)
        .collect();
    assert!(proposals.len() >= 4, "Expected the proposal to be re-sent");
    for proposal in &proposals {
        assert_eq!(
            proposal.block.header.signer_signature_hash(),
            signer_signature_hash,
            "Miner should re-send the same proposal"
        );
    }

    info!("------------------------- Switch To Non-transient Rejections -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL_REASON.set(RejectReason::TestingDirective);
    wait_for(30, || {
        Ok(counters.naka_rejected_blocks.get() > rejected_before)
    })
    .expect("Miner did not treat the block as rejected after non-transient rejections");

    info!("------------------------- Allow Block To Be Signed -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);
    wait_for(60, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > height_before)
    })
    .expect("Block was not mined after signers stopped rejecting it");

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}
