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

use libsigner::v0::messages::{BlockResponse, SignerMessage};
use stacks::core::test_util::to_addr;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::TEST_SIGNERS_IGNORE_PRE_COMMITS;
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::nakamoto_node::miner::TEST_MINER_FORCE_REMINE;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, test_observer};
use crate::tests::signer::v0::{
    get_stackerdb_signer_messages, wait_for_block_acceptance_from_signers,
    wait_for_block_pre_commits_from_signers, wait_for_block_proposal,
};

/// How long a signature is treated as fresh. The point of this test is what happens *after* it
/// lapses, so it is short.
const STALENESS_WINDOW: Duration = Duration::from_secs(5);
/// How long a pre-commit holds a signer to one block at a height. The signers that must carry
/// the sibling over the threshold are released by this lapsing, so it is short too.
const EXCLUSIVITY_WINDOW: Duration = Duration::from_secs(5);

#[test]
#[ignore]
/// Verify that a signer already committed to a block never accepts a sibling of it -- a
/// different block at the same height in the same tenure -- and that the rest of the set
/// adopts the sibling regardless.
///
/// A signer that has signed a block refuses to pre-commit any sibling of it, permanently. That
/// refusal costs one signer's signature; it must not cost the height. This test splits the
/// weight so both halves are visible at once: a minority is bound by its signature on block A,
/// while a majority that never signed A is free to carry sibling B over the threshold.
///
/// Test Setup:
/// Five signers, one miner Nakamoto node, bitcoind. The staleness and pre-commit exclusivity
/// windows are both 5s, so the test spends its time on behaviour rather than waiting.
///
/// Test Execution:
/// 1. Four of the five signers ignore each other's pre-commits. All five still emit one for
///    block A, so only the fifth ever observes the threshold and signs. A holds one signature
///    out of five, far below the 70% it needs, so it never reaches any node.
/// 2. `TEST_MINER_FORCE_REMINE` makes the miner abandon A and mine sibling B.
/// 3. Pre-commit delivery is restored and both windows lapse, freeing the four signers that
///    never signed A to pre-commit B and carry it over the threshold.
///
/// Test Assertion:
/// - The signer holding a signature on A never accepts B.
/// - B is adopted by the other four and the tenure advances.
fn signer_committed_to_a_sibling_never_accepts_the_other() {
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
        |config| {
            config.tenure_last_block_proposal_timeout = STALENESS_WINDOW;
            config.pre_commit_exclusivity_timeout = EXCLUSIVITY_WINDOW;
        },
        |config| {
            config.miner.block_rejection_timeout_steps = [(0, Duration::from_secs(10))].into();
        },
        None,
        None,
    );
    signer_test.boot_to_epoch_3();

    let conf = signer_test.running_nodes.conf.clone();
    let miner_sk = conf.miner.mining_key.clone().unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();
    // One signer will sign A and be bound by it; the other four never see the threshold, never
    // sign, and are therefore free to carry the sibling over it later.
    let (bound, free) = all_signers.split_at(1);
    let (bound, free) = (bound.to_vec(), free.to_vec());

    let info_before = get_chain_info(&conf);
    let target_height = info_before.stacks_tip_height + 1;

    info!("------------------------- Let Only One Signer Reach the Threshold -------------------------");
    // Each signer still emits and tallies its own pre-commit -- that path calls
    // `handle_block_pre_commit` directly rather than through the message dispatch -- but the
    // four ignore everyone else's, so only the fifth ever observes 70% and signs.
    test_observer::clear();
    TEST_SIGNERS_IGNORE_PRE_COMMITS.set(free.clone());

    info!("------------------------- Force Miner to Propose Block A -------------------------");
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit transfer tx");

    let proposal_a = wait_for_block_proposal(30, target_height, &miner_pk)
        .expect("Timed out waiting for the proposal of block A");
    let sighash_a = proposal_a.block.header.signer_signature_hash();
    let tenure_a = proposal_a.block.header.consensus_hash.clone();

    wait_for_block_pre_commits_from_signers(60, &sighash_a, &all_signers)
        .expect("Timed out waiting for all signers to pre-commit block A");
    // The whole scenario rests on this one signature existing; without it there is no rule to
    // test and every assertion below would hold vacuously.
    wait_for_block_acceptance_from_signers(60, &sighash_a, &bound)
        .expect("Timed out waiting for the bound signer to sign block A");

    info!("------------------------- Make the Miner Abandon A and Mine Sibling B -------------------------";
        "signer_signature_hash" => %sighash_a,
    );
    TEST_MINER_FORCE_REMINE.set(true);
    TEST_SIGNERS_IGNORE_PRE_COMMITS.set(vec![]);

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
    .expect("Timed out waiting for the miner to mine a sibling of block A");
    let proposal_b = sibling.expect("Sibling proposal was not captured");
    let sighash_b = proposal_b.block.header.signer_signature_hash();

    assert_ne!(sighash_b, sighash_a, "Block B must differ from block A");
    assert_eq!(
        proposal_b.block.header.chain_length, target_height,
        "Block B must be at the same height as A"
    );
    assert_eq!(
        proposal_b.block.header.consensus_hash, tenure_a,
        "Block B must be in the same tenure as A: a different tenure is a reorg, not a sibling"
    );

    info!("------------------------- The Free Majority Carries B Over the Threshold -------------------------";
        "signer_signature_hash" => %sighash_b,
    );
    // This is what makes the bound signer evaluate B at all: the guard under test runs when a
    // block crosses the pre-commit threshold, and only the four can take it there.
    wait_for_block_pre_commits_from_signers(120, &sighash_b, &free)
        .expect("Timed out waiting for the free signers to pre-commit block B");
    wait_for_block_acceptance_from_signers(120, &sighash_b, &free)
        .expect("Timed out waiting for the free signers to sign block B");
    info!("------------------------- The Bound Signer Never Accepts B -------------------------");
    for (chunk, message) in get_stackerdb_signer_messages() {
        let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message else {
            continue;
        };
        if accepted.signer_signature_hash != sighash_b {
            continue;
        }
        let Ok(sender) = chunk.recover_pk() else {
            continue;
        };
        assert!(
            !bound.contains(&sender),
            "The signer holding a signature on sibling A also accepted B, which is two \
             signatures at one height in one tenure"
        );
    }

    info!("------------------------- The Tenure Still Advances -------------------------");
    // B carries 80% of the weight without the bound signer, so the rule costs one signature
    // rather than the height.
    wait_for(60, || {
        Ok(get_chain_info(&conf).stacks_tip_height >= target_height)
    })
    .expect("Block B was not adopted: the rule should cost one signer's signature, not the tenure");

    signer_test.shutdown();
}
