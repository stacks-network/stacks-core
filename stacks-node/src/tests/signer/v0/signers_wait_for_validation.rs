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

use libsigner::v0::messages::{BlockResponse, SignerMessage};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::TenureChangeCause;
use stacks::codec::StacksMessageCodec;
use stacks::net::api::postblock_proposal::TEST_VALIDATE_STALL;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::test_observer;
use crate::tests::signer::v0::{
    wait_for_block_pre_commits_from_signers, wait_for_block_pushed_by_miner_key, MultipleMinerTest,
};

#[test]
#[ignore]
/// Test that signers don't issue signatures until they have validated the block
///
/// This test verifies a race condition where a signer receives enough pre-commits
/// to exceed the 70% threshold before receiving its own block validation response.
/// The signer should NOT issue a signature until it has confirmed the block is valid.
///
/// Test Setup:
/// - Distribute signers across two miners (4 on miner 1, 1 on miner 2)
/// - Signers on different miners use different validation endpoints
///
/// Test Execution:
/// 1. Propose a block to all signers
/// 2. Pause block validation on miner 2 (the single signer)
/// 3. 4 signers on miner 1 issue pre-commits, pushing threshold over 70%
/// 4. The single signer on miner 2 receives all pre-commits but its validation is stalled
/// 5. Verify the single signer does NOT issue a signature until validation completes
/// 6. Resume validation and confirm the block is accepted
///
/// Test Assertion:
/// The signer waits for its own validation before issuing a signature, preventing
/// race conditions where it could sign before discovering the block is invalid.
fn signer_waits_for_validation_before_signing() {
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
    let mut stalled_signer = Vec::new();
    for (config, signer_pk) in signer_configs.iter().zip(all_signers.iter()) {
        if config.node_host == conf_2.node.rpc_bind {
            stalled_signer.push(signer_pk.clone());
        } else {
            approving_signers.push(signer_pk.clone());
        }
    }
    assert_eq!(
        stalled_signer.len(),
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
    info!("------------------------- Stall Validation on Miner 2 -------------------------");
    // Stall block validation submission on the signer connected to miner 2
    // This prevents that signer from validating the next proposed block
    TEST_VALIDATE_STALL.set(vec![Some(node_2_auth)]);

    info!("------------------------- Mine Block N+1 with Stalled Validation -------------------------");
    // Mine a new tenure which will issue a block proposal to all signers for its tenure change.
    miners.signer_test.mine_bitcoin_block();

    // The 4 signers on miner 1 should have validated and sent pre-commits
    // The 1 signer on miner 2 should be waiting for validation and should NOT have issued a signature
    let block =
        wait_for_block_pushed_by_miner_key(30, info_before.stacks_tip_height + 1, &miner_pk_1)
            .expect("Failed to mine block N+1");
    let signer_signature_hash = block.header.signer_signature_hash();
    info!("------------------------- Mined {signer_signature_hash}. Checking for Pre-Commits for {} Signers-------------------------", approving_signers.len());
    wait_for_block_pre_commits_from_signers(30, &signer_signature_hash, &approving_signers)
        .expect("Failed to receive pre-commits from approving signers");
    // We only wait a small amount of time for each of these checks since we already received block commits from everyone else.
    let stalled_pk = stalled_signer[0].clone();
    assert!(
        wait_for(15, || {
            for chunk in test_observer::get_stackerdb_chunks()
                .into_iter()
                .flat_map(|chunk| chunk.modified_slots)
            {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");

                let pk = chunk.recover_pk().expect("Failed to recover pk");
                if stalled_pk != pk {
                    continue;
                }

                match message {
                    SignerMessage::BlockPreCommit(pre_commit) => {
                        assert_ne!(
                            signer_signature_hash, pre_commit,
                            "Stalled signer should not have issued a pre-commit yet."
                        );
                    }
                    SignerMessage::BlockResponse(BlockResponse::Accepted(acceptance)) => {
                        assert_ne!(
                            signer_signature_hash, acceptance.signer_signature_hash,
                            "Stalled signer should not have accepted the block yet"
                        );
                    }
                    SignerMessage::BlockResponse(BlockResponse::Rejected(rejection)) => {
                        assert_ne!(
                            signer_signature_hash, rejection.signer_signature_hash,
                            "Stalled signer should not have rejected the block yet"
                        );
                    }
                    _ => {}
                }
            }
            Ok(false)
        })
        .is_err(),
        "Stalled signer issued a pre-commit or response before validation completed"
    );
    // At this point, we should NOT have received a signature from the stalled signer
    // because it hasn't yet validated the block. We're checking this happened correctly
    // by the fact that we can now resume validation without issues.
    info!("------------------------- Resume Validation -------------------------");
    TEST_VALIDATE_STALL.set(vec![]); // Unset the stall condition
    info!("------------------------- Wait for Block Response -------------------------");
    // Now that validation is resumed, the stalled signer should issue a response
    let mut found_commit = false;
    let mut found_accept = false;
    wait_for(15, || {
        for chunk in test_observer::get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                .expect("Failed to deserialize SignerMessage");

            let pk = chunk.recover_pk().expect("Failed to recover pk");
            if stalled_pk != pk {
                continue;
            }
            match message {
                SignerMessage::BlockPreCommit(pre_commit) => {
                    if signer_signature_hash == pre_commit {
                        found_commit = true;
                    }
                }
                SignerMessage::BlockResponse(BlockResponse::Accepted(acceptance)) => {
                    if signer_signature_hash == acceptance.signer_signature_hash {
                        found_accept = true;
                    }
                }
                SignerMessage::BlockResponse(BlockResponse::Rejected(rejection)) => {
                    assert_ne!(
                        signer_signature_hash, rejection.signer_signature_hash,
                        "Stalled signer should not have rejected the block"
                    );
                }
                _ => {}
            }
        }
        Ok(found_accept && found_commit)
    })
    .expect("Stalled signer did not issue a pre-commit and acceptance after validation resumed");
    miners.shutdown();
}
