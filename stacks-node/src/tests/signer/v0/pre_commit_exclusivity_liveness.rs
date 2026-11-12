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

use libsigner::v0::messages::{BlockResponse, SignerMessage};
use stacks::core::test_util::to_addr;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::{TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_REJECT_ALL_BLOCK_PROPOSAL};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::nakamoto_node::miner::TEST_MINER_FORCE_REMINE;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, test_observer};
use crate::tests::signer::v0::{
    get_stackerdb_signer_messages, wait_for_block_pre_commits_from_signers,
    wait_for_block_proposal, wait_for_block_rejections_from_signers,
};

/// The exclusivity window. Long enough that the sibling is comfortably inside it when it
/// arrives, so the bar is what the assertions observe rather than a race against the clock,
/// but well short of `RESEND_CADENCE` so that the miner's retry -- not the window -- is what
/// dominates a stall. That ordering matches production, where the window defaults to 30s and
/// the first rejection-timeout step to 180s, and it is what makes the transient-rejection
/// signal measurable here: that signal shortens the cadence, so a test whose window dominates
/// cannot see it work.
const EXCLUSIVITY_WINDOW: Duration = Duration::from_secs(30);
/// How long the miner sleeps after a blocking minority rejects a block, before it rebuilds.
/// This is the window in which the test clears the reject flag, so it has to be comfortably
/// longer than it takes the committing signers to validate and pre-commit block A.
const FIRST_REJECTION_PAUSE: Duration = Duration::from_secs(10);
/// The miner's re-send cadence when a proposal draws no responses at all: the slow path the
/// transient-rejection signal exists to avoid. Deliberately long, so that recovery landing
/// anywhere near it means the signal did not engage and the miner fell back to waiting out its
/// rejection timeout.
const RESEND_CADENCE: Duration = Duration::from_secs(120);
/// The miner's re-send cadence while a transient rejection is outstanding, which is what the
/// bar now emits. This is the signer default for `transient_rejection_retry_timeout`.
const TRANSIENT_RETRY: Duration = Duration::from_secs(5);
/// The re-send cadence for `split_pre_commits_converge`, which needs the opposite of what
/// `RESEND_CADENCE` gives. That test builds its sibling with `TEST_MINER_FORCE_REMINE`, a hook
/// consumed on the `SignatureTimeout` branch -- so the sibling cannot appear any sooner than
/// the rejection timeout. At `RESEND_CADENCE` the sibling would arrive long after the
/// exclusivity window had lapsed and there would be no split left to observe. That test is
/// about whether a split converges at all, not about how quickly the miner is prompted, so a
/// short cadence costs it nothing.
const SPLIT_RESEND_CADENCE: Duration = Duration::from_secs(10);
/// Slack on top of `EXCLUSIVITY_WINDOW + TRANSIENT_RETRY`. The resulting budget sits far below
/// `RESEND_CADENCE`, so a recovery that only arrives on the slow path fails rather than merely
/// running long.
const RECOVERY_SLACK: Duration = Duration::from_secs(30);
/// How early, by the test's clock, the bar may lift. The clock starts only once the test has
/// polled and seen A's pre-commits and rejections, after the signers recorded them, and the
/// signer stores `committed_at` in whole seconds, so the window can be observed to lapse short
/// of `EXCLUSIVITY_WINDOW` even when the bar held for all of it.
const WINDOW_LAPSE_TOLERANCE: Duration = Duration::from_secs(3);

#[test]
#[ignore]
/// Verify that barring a pre-commit delays a sibling but does not strand the tenure.
///
/// `pre_commit_exclusivity_timeout` stops a signer pre-committing to a block at a height where
/// it is already committed to a different one. The signer withholds its pre-commit but answers
/// with a transient `NoSignerConsensus` rejection, because the proposal may be perfectly valid
/// and it simply is not free to promise a signature for it yet.
///
/// Answering is what keeps the bar cheap. Nothing re-evaluates a barred block on a timer --
/// evaluation is driven by incoming messages -- so the only thing that can revive the sibling
/// once the window lapses is the miner proposing it again. A miner hearing nothing at all sits
/// on the `SignatureTimeout` path, whose timeout with zero rejections is the first
/// `block_rejection_timeout_steps` entry, 180s by default, which would make a bar cost
/// `max(exclusivity window, miner re-send cadence)`. A transient rejection instead has the
/// miner re-send this same block after `transient_rejection_retry_timeout`, so the cost is the
/// window plus that retry. It has to stay transient: a rejection carrying a blocking minority
/// would have the miner rebuild into a fresh sibling and restart every signer's window.
///
/// Which recovery paths exist depends on whether the tenure has a signed block yet.
/// `SortitionState::is_timed_out` returns false as soon as `has_signed_block_in_tenure` is
/// true, so the miner-inactivity fallback governed by `block_proposal_timeout` only applies
/// before a tenure's first signed block. (A pre-commit deliberately does not count there, so
/// that a tenure stalled on pre-commits alone can still fall back.) This test runs the
/// mid-tenure case, where that fallback is already disabled and no safety net is left.
///
/// Test Setup:
/// Five signers, one miner Nakamoto node, bitcoind. Two signers (40% of weight, above the 30%
/// blocking minority) reject block A, which is what makes the miner rebuild -- the same path
/// that produced the sibling at mainnet tenure 970508, where B followed A by 11 seconds. The
/// other three (60%, below the 70% threshold) pre-commit A and so never sign it, which is the
/// state the window governs.
///
/// Test Execution:
/// 1. The rejecting pair is armed and the miner proposes A. The committing trio pre-commits it;
///    the pair rejects it, tripping the blocking minority.
/// 2. The reject flag is cleared while the miner is inside `first_rejection_pause_ms`, before
///    it has rebuilt. Were it left armed the pair would reject the sibling too, trip the
///    minority again, and drive a fresh rebuild -- the livelock, not the case under test.
/// 3. The miner rebuilds into sibling B, inside the window. The committing trio is barred: it
///    withholds its pre-commit and rejects B transiently. The pair, which never committed at
///    this height, pre-commits it. B sits at 40%.
/// 4. The window lapses and the miner re-sends B.
///
/// Test Assertion:
/// - While the window is live the bar holds: neither a pre-commit nor an acceptance of B from
///   the committing trio, and the tip does not move.
/// - Any rejection of B, from anyone, is transient. A non-transient one would trip the blocking
///   minority and have the miner rebuild, which is the livelock rather than the hold.
/// - The tenure recovers, but no sooner than the window: the bar's cost is real and measured.
/// - Recovery arrives within the window plus one transient retry plus slack. That budget is far
///   below the re-send cadence a miner falls back to when it hears nothing, so overrunning it
///   means the rejections never reached the miner and the fast path was not taken.
/// - The block that ends the stall is B, re-sent verbatim. A fresh sibling would mean the miner
///   rebuilt again, restarting every signer's window.
fn pre_commit_bar_does_not_stall_the_tenure() {
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
        vec![(sender_addr, (send_amt + send_fee) * 2)],
        |config| {
            config.pre_commit_exclusivity_timeout = EXCLUSIVITY_WINDOW;
        },
        |config| {
            config.miner.block_rejection_timeout_steps = [(0, RESEND_CADENCE)].into();
            config.miner.first_rejection_pause_ms = FIRST_REJECTION_PAUSE.as_millis() as u64;
            config.miner.subsequent_rejection_pause_ms = FIRST_REJECTION_PAUSE.as_millis() as u64;
        },
        None,
        None,
    );
    signer_test.boot_to_epoch_3();

    let conf = signer_test.running_nodes.conf.clone();
    let miner_sk = conf.miner.mining_key.clone().unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();
    // 40% rejects (above the 30% blocking minority, so the miner rebuilds); 60% pre-commits
    // (below the 70% threshold, so it never signs and stays merely committed).
    let (rejecting, committing) = all_signers.split_at(2);
    let (rejecting, committing) = (rejecting.to_vec(), committing.to_vec());

    info!(
        "------------------------- Establish the Mid-Tenure Precondition -------------------------"
    );
    // Land one ordinary block first, so the tenure has a signed block. From here
    // `has_signed_block_in_tenure` is true, `is_timed_out` is pinned to false, and the
    // miner-inactivity fallback can no longer rescue this tenure -- which is precisely the
    // regime the assertions below are about.
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit the priming transfer tx");
    let primed = get_chain_info(&conf);
    wait_for(60, || {
        Ok(get_chain_info(&conf).stacks_tip_height > primed.stacks_tip_height)
    })
    .expect("Timed out waiting for a first, ordinary block to land in this tenure");
    let tenure_under_test = get_chain_info(&conf).pox_consensus;

    let info_before = get_chain_info(&conf);
    let target_height = info_before.stacks_tip_height + 1;

    info!("------------------------- Arm the Rejecting Minority and Propose A -------------------------");
    test_observer::clear();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting.clone());
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit transfer tx");

    let proposal_a = wait_for_block_proposal(30, target_height, &miner_pk)
        .expect("Timed out waiting for the proposal of block A");
    let sighash_a = proposal_a.block.header.signer_signature_hash();
    let tenure_a = proposal_a.block.header.consensus_hash.clone();
    assert_eq!(
        tenure_a, tenure_under_test,
        "Block A must be in the tenure that already has a signed block: in a fresh tenure the \
         miner-inactivity fallback would still be live and could end the stall on its own"
    );

    // The committing trio has to be committed to A *before* the sibling exists, or there is
    // nothing to bar. Waiting on their pre-commits is what orders that.
    wait_for_block_pre_commits_from_signers(60, &sighash_a, &committing)
        .expect("Timed out waiting for the committing signers to pre-commit block A");
    wait_for_block_rejections_from_signers(60, &sighash_a, &rejecting)
        .expect("Timed out waiting for the rejecting signers to reject block A");

    info!("------------------------- Disarm Before the Rebuild -------------------------");
    // The miner is now inside `first_rejection_pause_ms` and has not started rebuilding, so
    // clearing here lands before the sibling is proposed. Leaving it armed would have the pair
    // reject the sibling too and trip the minority again, rebuilding indefinitely.
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);
    let pre_commit_a_observed = Instant::now();

    info!("------------------------- Capture the Sibling -------------------------");
    let mut sibling = None;
    wait_for(120, || {
        for (_chunk, message) in get_stackerdb_signer_messages() {
            let SignerMessage::BlockProposal(proposal) = message else {
                continue;
            };
            if proposal.block.header.chain_length == target_height
                && proposal.block.header.signer_signature_hash() != sighash_a
                && proposal.block.header.recover_miner_pk().as_ref() == Some(&miner_pk)
            {
                sibling = Some(proposal);
                return Ok(true);
            }
        }
        Ok(false)
    })
    .expect("Timed out waiting for the miner to rebuild into a sibling of block A");
    let proposal_b = sibling.expect("Sibling proposal was not captured");
    let sighash_b = proposal_b.block.header.signer_signature_hash();

    assert_eq!(
        proposal_b.block.header.consensus_hash, tenure_a,
        "Block B must be in the same tenure as A: a different tenure is a reorg, not a sibling"
    );
    assert!(
        pre_commit_a_observed.elapsed() < EXCLUSIVITY_WINDOW,
        "The sibling arrived after the exclusivity window had already lapsed ({:?} >= {:?}), so \
         the bar was never engaged and the assertions below would be vacuous",
        pre_commit_a_observed.elapsed(),
        EXCLUSIVITY_WINDOW,
    );

    info!("------------------------- The Bar Holds While the Window Is Live -------------------------";
        "signer_signature_hash" => %sighash_b,
    );
    // Sample inside the window rather than at its edge, so this cannot pass by racing it.
    // Paced off the transient retry, not `RESEND_CADENCE`: that constant is now the slow path
    // the fix avoids, and sleeping twice it would overshoot the window entirely and check
    // these assertions against a tenure that had already recovered.
    std::thread::sleep(TRANSIENT_RETRY * 2);
    for (chunk, message) in get_stackerdb_signer_messages() {
        let Ok(sender) = chunk.recover_pk() else {
            continue;
        };
        match message {
            SignerMessage::BlockPreCommit(hash) if committing.contains(&sender) => assert_ne!(
                hash, sighash_b,
                "A committing signer pre-committed block B while its commitment to sibling A \
                 was still live"
            ),
            SignerMessage::BlockResponse(BlockResponse::Accepted(accepted))
                if committing.contains(&sender) =>
            {
                assert_ne!(
                    accepted.signer_signature_hash, sighash_b,
                    "A committing signer accepted block B while its commitment to sibling A \
                     was still live"
                )
            }
            // The bar answers rather than staying silent, so a rejection of B is expected --
            // but only a transient one. A non-transient rejection carrying a blocking minority
            // would make the miner rebuild into a fresh sibling instead of re-sending this one,
            // which is the livelock rather than the hold.
            SignerMessage::BlockResponse(BlockResponse::Rejected(rejected))
                if rejected.signer_signature_hash == sighash_b =>
            {
                assert!(
                    rejected.response_data.reject_reason.is_transient(),
                    "Block B drew a non-transient rejection ({:?}); the miner will rebuild \
                     rather than re-send it",
                    rejected.response_data.reject_reason,
                )
            }
            _ => {}
        }
    }
    assert_eq!(
        get_chain_info(&conf).stacks_tip_height,
        info_before.stacks_tip_height,
        "The tenure must not advance while the committing majority is barred"
    );

    info!("------------------------- Recovery Once the Window Lapses -------------------------");
    let budget = EXCLUSIVITY_WINDOW + TRANSIENT_RETRY + RECOVERY_SLACK;
    let recovered = wait_for(budget.as_secs(), || {
        Ok(get_chain_info(&conf).stacks_tip_height >= target_height)
    });
    let elapsed = pre_commit_a_observed.elapsed();
    assert!(
        recovered.is_ok(),
        "Tenure did not recover within {budget:?} of the committing signers pre-committing A. \
         That budget is well under the {RESEND_CADENCE:?} the miner waits when it hears nothing \
         at all, so this means the barred signers' transient rejections did not reach it and it \
         fell back to the slow path",
    );
    assert!(
        elapsed + WINDOW_LAPSE_TOLERANCE >= EXCLUSIVITY_WINDOW,
        "Tenure recovered in {elapsed:?}, before the {EXCLUSIVITY_WINDOW:?} window could lapse \
         (allowing {WINDOW_LAPSE_TOLERANCE:?} for observation lag and whole-second rounding), \
         so the bar cannot have been what delayed it and this test is not measuring what it \
         claims"
    );

    info!("------------------------- The Recovery Block Is B, Re-Sent -------------------------");
    let proposals_of_b = get_stackerdb_signer_messages()
        .into_iter()
        .filter(|(_chunk, message)| {
            matches!(message, SignerMessage::BlockProposal(proposal)
                if proposal.block.header.signer_signature_hash() == sighash_b)
        })
        .count();
    assert!(
        proposals_of_b > 1,
        "Expected the miner to re-send block B verbatim; a fresh sibling instead means it \
         rebuilt again, which restarts every signer's exclusivity window"
    );

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Verify that a pre-commit split across two siblings converges, rather than persisting.
///
/// `pre_commit_bar_does_not_stall_the_tenure` covers one sibling and one bar. This covers the
/// case that motivated the bar's design review: the set divided across *two* siblings, each
/// group barred from the other's block by its own live window, with neither block anywhere
/// near the 70% threshold. The worry is that a signer's window runs from its own earliest
/// commitment at that height rather than from the latest sibling, so windows across the set
/// are staggered, and nothing in the protocol makes the set agree on *which* block to commit
/// to -- only that each signer commits to at most one.
///
/// There is a structural reason to expect convergence rather than livelock, which this test
/// exists to confirm empirically. A miner only rebuilds when a blocking minority (>30% of
/// weight) rejects, and a signer that rejects does not pre-commit. So while rebuilds are being
/// driven, at most 70% of weight is available to pre-commit anything, and no block at that
/// height could reach the threshold regardless of this bar. Repeated rebuilds and completion
/// are mutually exclusive; once the rejections stop the miner settles on one block and re-sends
/// it, and the set converges as windows lapse. The split is therefore transient by
/// construction, and this test measures how transient.
///
/// Test Setup:
/// Five signers, one miner, bitcoind, mid-tenure as above. Proposal delivery is partitioned so
/// that two signers (40%) see only block A and three (60%) see only its sibling B -- neither
/// group reaching the threshold, and each ending up committed to a different block.
///
/// Test Execution:
/// 1. The late trio ignores proposals. The miner proposes A, which only the early pair sees
///    and pre-commits.
/// 2. Delivery is swapped: the early pair now ignores proposals and the late trio resumes.
/// 3. `TEST_MINER_FORCE_REMINE` makes the miner rebuild into sibling B, which only the late
///    trio sees and pre-commits.
/// 4. Delivery is fully restored. Both groups now receive both blocks, and each is barred from
///    the other's by its own live window.
///
/// Test Assertion:
/// - The split is real: A and B each hold pre-commits, neither reaches the threshold, and the
///   tenure does not advance while both windows are live.
/// - The set converges and the tenure advances within one window plus a re-send cadence plus
///   slack. Exceeding that means the staggered windows kept the set misaligned, which is the
///   livelock this test is here to rule out.
///
/// Observed, and worth recording because it bounds what this test can show: the bar fires in
/// one direction only. The early pair is barred from B, but the late trio is never barred from
/// A, because once the miner has rebuilt it re-sends only B -- A is simply never offered again,
/// so the trio has nothing to be barred by. A single miner holds one block at a time, so a
/// two-sided split cannot be *sustained* at all: the abandoned sibling stops being proposed and
/// the set has only one live candidate to converge on. That is a second, independent reason the
/// livelock is unreachable here, and it means a genuinely two-sided standoff would need two
/// miners -- which puts the siblings in different tenures, where these rules do not apply.
fn split_pre_commits_converge() {
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
        vec![(sender_addr, (send_amt + send_fee) * 2)],
        |config| {
            config.pre_commit_exclusivity_timeout = EXCLUSIVITY_WINDOW;
        },
        |config| {
            config.miner.block_rejection_timeout_steps = [(0, SPLIT_RESEND_CADENCE)].into();
        },
        None,
        None,
    );
    signer_test.boot_to_epoch_3();

    let conf = signer_test.running_nodes.conf.clone();
    let miner_sk = conf.miner.mining_key.clone().unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();
    // Neither group can reach 70% on its own, so each ends up committed to a different block
    // with no way to finish it: the split.
    let (early, late) = all_signers.split_at(2);
    let (early, late) = (early.to_vec(), late.to_vec());

    info!(
        "------------------------- Establish the Mid-Tenure Precondition -------------------------"
    );
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit the priming transfer tx");
    let primed = get_chain_info(&conf);
    wait_for(60, || {
        Ok(get_chain_info(&conf).stacks_tip_height > primed.stacks_tip_height)
    })
    .expect("Timed out waiting for a first, ordinary block to land in this tenure");
    let tenure_under_test = get_chain_info(&conf).pox_consensus;

    let info_before = get_chain_info(&conf);
    let target_height = info_before.stacks_tip_height + 1;

    info!("------------------------- Deliver A to the Early Pair Only -------------------------");
    test_observer::clear();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(late.clone());
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit transfer tx");

    let proposal_a = wait_for_block_proposal(30, target_height, &miner_pk)
        .expect("Timed out waiting for the proposal of block A");
    let sighash_a = proposal_a.block.header.signer_signature_hash();
    let tenure_a = proposal_a.block.header.consensus_hash.clone();
    assert_eq!(tenure_a, tenure_under_test, "Block A must be mid-tenure");

    wait_for_block_pre_commits_from_signers(60, &sighash_a, &early)
        .expect("Timed out waiting for the early pair to pre-commit block A");

    info!("------------------------- Swap Delivery, Then Rebuild Into B -------------------------");
    // Swap before the rebuild, so the sibling reaches only the late trio. The early pair is now
    // committed to A and deaf to B; the trio is about to be committed to B and deaf to A.
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(early.clone());
    TEST_MINER_FORCE_REMINE.set(true);
    let split_formed = Instant::now();

    let mut sibling = None;
    wait_for(120, || {
        for (_chunk, message) in get_stackerdb_signer_messages() {
            let SignerMessage::BlockProposal(proposal) = message else {
                continue;
            };
            if proposal.block.header.chain_length == target_height
                && proposal.block.header.signer_signature_hash() != sighash_a
                && proposal.block.header.recover_miner_pk().as_ref() == Some(&miner_pk)
            {
                sibling = Some(proposal);
                return Ok(true);
            }
        }
        Ok(false)
    })
    .expect("Timed out waiting for the miner to rebuild into a sibling of block A");
    let proposal_b = sibling.expect("Sibling proposal was not captured");
    let sighash_b = proposal_b.block.header.signer_signature_hash();
    assert_eq!(
        proposal_b.block.header.consensus_hash, tenure_a,
        "Block B must be in the same tenure as A: a different tenure is a reorg, not a sibling"
    );

    wait_for_block_pre_commits_from_signers(60, &sighash_b, &late)
        .expect("Timed out waiting for the late trio to pre-commit block B");

    info!("------------------------- Restore Delivery; the Set Is Now Split -------------------------";
        "block_a" => %sighash_a,
        "block_b" => %sighash_b,
    );
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);
    assert!(
        split_formed.elapsed() < EXCLUSIVITY_WINDOW,
        "The split took {:?} to form, longer than the {:?} window, so by now the earlier \
         commitments have lapsed and there is no split left to converge",
        split_formed.elapsed(),
        EXCLUSIVITY_WINDOW,
    );
    assert_eq!(
        get_chain_info(&conf).stacks_tip_height,
        info_before.stacks_tip_height,
        "Neither sibling can reach the threshold while the set is split, so the tenure must \
         not have advanced"
    );

    info!("------------------------- Convergence -------------------------");
    let budget = EXCLUSIVITY_WINDOW + SPLIT_RESEND_CADENCE + RECOVERY_SLACK;
    let converged = wait_for(budget.as_secs(), || {
        Ok(get_chain_info(&conf).stacks_tip_height >= target_height)
    });
    assert!(
        converged.is_ok(),
        "The set did not converge within {budget:?} of splitting. Each signer's window runs \
         from its own earliest commitment, so staggered windows can keep the set landing on \
         different blocks indefinitely -- the livelock this test exists to rule out",
    );
    info!("Converged"; "elapsed_secs" => split_formed.elapsed().as_secs());

    signer_test.shutdown();
}
