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

use stacks::chainstate::burn::db::sortdb::{SortitionDB, TEST_PAUSE_BLOCK_SORTITION_COMMIT};
use stacks::chainstate::stacks::TenureChangeCause;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

use crate::tests::signer::v0::{
    MultipleMinerTest, wait_for_block_pre_commits_from_signers, wait_for_block_proposal, wait_for_block_pushed, wait_for_block_rejections_from_signers
};

#[test]
#[ignore]
/// Tests that signers reconsider stacks blocks that rely on Bitcoin blocks that were not found yet.
///
/// This test verifies a race condition where a signer receives a block proposal building on a Bitcoin block
/// that has not yet been fully processed by the Stacks node. The signer should reconsider the block
/// proposal after the Bitcoin block is processed, allowing it to validate against the correct state
///
/// Test Setup:
/// - Distribute signers across two miners (3 on miner 1, 2 on miner 2)
///
/// Test Execution:
/// 1. Propose a block to all signers
/// 2. Pause bitcoin block processing on the node connect to the two signers (miner 2) to simulate the condition where the block proposal is received before the Bitcoin block is fully processed
/// 3. 3 signers on miner 1 issue pre-commits
/// 4. 2 signers on miner 2 issue a rejection due to the missing Bitcoin block
/// 5. Resume Bitcoin block processing
/// 6. Confirm the two miners on miner 2 reconsider the block proposal and issue pre-commits
/// 7. Confirm the block is accepted the node advances its tip.
///
/// Test Assertion:
/// The two signers issue rejections to the proposal
/// The two signers then reconsider the proposal after Bitcoin block processing is resumed issue pre-commits
/// The node tip advances after the block is reconsidered and accepted
fn signers_reprocess_bitcoin_block_not_found_proposals() {
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
        // Distribute signers so first 2 go to node 2, last 3 go to node 1
        |port| if port < 3002 { 1 } else { 0 },
        None,
    );
    let all_signers = miners.signer_test.signer_test_pks();
    let signer_configs = &miners.signer_test.signer_configs;
    let (conf_1, conf_2) = miners.get_node_configs();
    let mut regular_signers = Vec::new();
    let mut stalled_signers = Vec::new();
    for (config, signer_pk) in signer_configs.iter().zip(all_signers.iter()) {
        if config.endpoint.port() < 3002 {
            stalled_signers.push(signer_pk.clone());
        } else {
            regular_signers.push(signer_pk.clone());
        }
    }
    assert_eq!(
        stalled_signers.len(),
        2,
        "Expected exactly two signers to be assigned to miner 2"
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
    info!("------------------------- Stall burn block processing on Miner 2 -------------------------");
    // Stall block sortition commit for miner 2
    // This prevents that signer from validating the next proposed block as it will be validating
    // against an old burnchain state
    TEST_PAUSE_BLOCK_SORTITION_COMMIT.set(vec![conf_2.get_burn_db_file_path()]);

    info!("------------------------- Mine Block N+1 with Stalled Block Broadcasting -------------------------");
    // Mine a new tenure which will issue a block proposal to all signers for its tenure change.
    miners.signer_test.mine_bitcoin_block();

    // The 3 signers on miner 1 should have validated and sent pre-commits
    // The 2 signers on miner 2 should have issued a block rejection due to the stalled sortition commit preventing them from validating the block proposal
    let block_proposal =
        wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pk_1)
            .expect("Failed to mine block N+1");
    let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
    info!("------------------------- Proposed {signer_signature_hash}. Checking for Pre-Commits for {} Signers-------------------------", regular_signers.len());
    wait_for_block_pre_commits_from_signers(30, &signer_signature_hash, &regular_signers)
        .expect("Failed to receive pre-commits from approving signers");
    wait_for_block_rejections_from_signers(30, &signer_signature_hash, &stalled_signers)
        .expect("Failed to receive block rejections from stalled signers");
    // At this point, we should NOT have received a signature from the stalled signer
    // because it hasn't yet validated the block.
    info!("------------------------- Resume Block Processing -------------------------");
    TEST_PAUSE_BLOCK_SORTITION_COMMIT.set(vec![]); // Unset the stall condition
    info!("------------------------- Wait for Block Response -------------------------");
    // Now that validation is resumed, the stalled signer should issue an approval
    wait_for_block_pre_commits_from_signers(30, &signer_signature_hash, &stalled_signers)
        .expect("Stalled signers failed to issue commits");
    wait_for_block_pushed(30, &signer_signature_hash).expect("Failed to mine block N+1");
    info!("------------------------- Shutting down -------------------------");
    miners.shutdown();
}
