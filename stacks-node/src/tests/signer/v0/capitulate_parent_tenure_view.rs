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
use stacks::codec::StacksMessageCodec;
use stacks::core::test_util::make_stacks_transfer_serialized;
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::{
    TEST_REJECT_ALL_BLOCK_PROPOSAL, TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT,
    TEST_SIGNERS_IGNORE_BLOCK_RESPONSES, TEST_SIGNERS_IGNORE_PRE_COMMITS,
    TEST_SKIP_BLOCK_BROADCAST,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::{fmt, EnvFilter};

use super::{SignerTest, *};
use crate::nakamoto_node::miner::TEST_BLOCK_ANNOUNCE_STALL;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, submit_tx, test_observer};

#[test]
#[ignore]
/// Test that when the chain halts due to a 50/50 split view, signers capitulate their view
/// of the parent tenure last block to the node's tip after a timeout. Specifically, tests
/// that all signers capitulate to block N when N+1 was not globally accepted.
///
/// Test Setup:
/// The test spins up 10 stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// 1. All signers are configured with a tenure_last_block_proposal_timeout = 30 seconds, capitulate_miner_view_timeout = 30 seconds.
/// 2. The node mines 1 stacks block N (all signers sign it).
/// 3. 50% of the signers are configured to to auto reject any block proposals and to ignore any block responses, broadcast of new blocks are skipped, and miners are configured to ignore signers responses.
/// 4. The miner proposes a new stacks block N+1.
/// 5. 50% of the signers pre-commit to block N+1, while the other 50% reject it. However, the 50% that pre-commit due not recognize these rejections so the block remains locally accepted.
/// 6. A new tenure starts.
/// 7. The miner proposes a new stacks block N+1'.
/// 8. The 50% of signers that pre-committed to block N+1, reject block N+1' and the other 50% pre-commit to block N+1'.
/// 9. The chain halts. After the timeout period, all signers capitulate their view of the parent tenure last block to the node's tip (block N).
/// 10. The node mines block N+1' successfully with all signers signing it.
///
/// Test Assertion:
/// - All signers accepted block N.
/// - 50% of signers pre-commit to block N+1, while the other 50% reject it.
/// - After the timeout period, all signers see the parent tenure last block as block N.
/// - All signers accept block N+1' as valid.
fn deadlock_50_50_split_capitulates_to_node_tip() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 10;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 4;

    let capitulate_miner_view_timeout = Duration::from_secs(20);
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |config| {
            config.capitulate_miner_view_timeout = capitulate_miner_view_timeout;
            config.tenure_last_block_proposal_timeout = capitulate_miner_view_timeout;
            config.block_proposal_timeout = Duration::from_secs(u64::MAX); // Don't time out the miner
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        None,
        None,
    );

    let all_signers = signer_test.signer_test_pks();
    let rejecting_signers = all_signers[0..num_signers / 2].to_vec();
    let approving_signers = all_signers[num_signers / 2..].to_vec();
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = 30;
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let info_before = signer_test.get_peer_info();

    test_observer::clear();
    // submit a tx so that the miner will mine a stacks block N
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine block N");

    wait_for(short_timeout, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for N to be mined and processed");

    // Ensure that the block was accepted globally so the stacks tip has advanced to N
    let block_n =
        wait_for_block_pushed_by_miner_key(30, info_before.stacks_tip_height + 1, &miner_pk)
            .expect("Timed out waiting for block N to be mined");

    let info_after = signer_test.get_peer_info();
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );

    info!("------------------------- Mine Nakamoto Block N+1 -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers.clone());
    TEST_SIGNERS_IGNORE_BLOCK_RESPONSES.set(approving_signers.clone());
    test_observer::clear();

    // submit a tx so that the miner will mine a stacks block N+1
    let info_before = signer_test.get_peer_info();
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to mine block N+1");

    let block_n_1 = wait_for_block_proposal_block(30, info_before.stacks_tip_height + 1, &miner_pk)
        .expect("Timed out waiting for block N+1 to be proposed");

    wait_for_block_rejections_from_signers(
        30,
        &block_n_1.header.signer_signature_hash(),
        &rejecting_signers,
    )
    .expect("Rejecting signers did not reject block N+1");

    info!("------------------------- Start Next Tenure -------------------------");
    test_observer::clear();
    signer_test.mine_bitcoin_block();
    let now = std::time::Instant::now();
    let info = get_chain_info(&signer_test.running_nodes.conf);
    info!(
        "------------------------- Wait for State to Update with Split View -------------------------";
        "burn_block_height" => info.burn_block_height,
        "consenus_hash" => %info.pox_consensus,
        "parent_tenure_last_block_height_n" => info_before.stacks_tip_height,
        "parent_tenure_last_block_height_n_1" => info_before.stacks_tip_height + 1,
    );

    let block_id_n = StacksBlockId::new(
        &info_before.stacks_tip_consensus_hash,
        &info_before.stacks_tip,
    );
    let block_id_n_1 = StacksBlockId::new(
        &block_n_1.header.consensus_hash,
        &block_n_1.header.block_hash(),
    );
    let rejecting_signer_addrs: Vec<StacksAddress> = rejecting_signers
        .iter()
        .map(|signer| StacksAddress::p2pkh(false, signer))
        .collect();
    let approving_signer_addrs: Vec<StacksAddress> = approving_signers
        .iter()
        .map(|signer| StacksAddress::p2pkh(false, signer))
        .collect();
    let signer_addresses = signer_test.signer_addresses_versions();
    wait_for(30, || {
        let stackerdb_events = test_observer::get_stackerdb_chunks();
        let mut found_updates_n: HashSet<StacksAddress> = HashSet::new();
        let mut found_updates_n_1: HashSet<StacksAddress> = HashSet::new();
        for chunk in stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            let SignerMessage::StateMachineUpdate(update) = message else {
                continue;
            };
            let StateMachineUpdateMinerState::ActiveMiner {
                parent_tenure_last_block,
                tenure_id,
                ..
            } = update.content.current_miner()
            else {
                continue;
            };
            if tenure_id != &info.pox_consensus {
                continue;
            }

            let Some((address, _)) = signer_addresses
                .iter()
                .find(|(addr, _)| chunk.verify(addr).unwrap_or(false))
            else {
                continue;
            };
            if parent_tenure_last_block == &block_id_n {
                rejecting_signer_addrs
                    .iter()
                    .find(|a| *a == address)
                    .map(|a| {
                        found_updates_n.insert(a.clone());
                    })
                    .expect("Only rejecting signers should report parent tenure last block as N");
            } else if parent_tenure_last_block == &block_id_n_1 {
                approving_signer_addrs
                    .iter()
                    .find(|a| *a == address)
                    .map(|a| {
                        found_updates_n_1.insert(a.clone());
                    })
                    .expect("Only approving signers should report parent tenure last block as N+1");
            }
        }
        Ok(found_updates_n.len() + found_updates_n_1.len() == signer_addresses.len())
    })
    .expect("Signers did not update state machine with split view of parent tenure last block");

    // capitulate_viewpoint has TWO guards that must both be satisfied:
    // 1. last_capitulate_miner_view must be older than capitulate_miner_view_timeout
    // 2. time_since_last_approved (since block N was signed) must be >= capitulate_miner_view_timeout
    let time_to_wait = (capitulate_miner_view_timeout).saturating_sub(now.elapsed());
    info!(
        "------------------------- Waiting {} seconds for capitulation -------------------------",
        time_to_wait.as_secs()
    );
    std::thread::sleep(time_to_wait);
    wait_for(30, || {
        let stackerdb_events = test_observer::get_stackerdb_chunks();
        let mut found_updates_n: HashSet<StacksAddress> = HashSet::new();
        for chunk in stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            let SignerMessage::StateMachineUpdate(update) = message else {
                continue;
            };
            let StateMachineUpdateMinerState::ActiveMiner {
                parent_tenure_last_block,
                tenure_id,
                ..
            } = update.content.current_miner()
            else {
                continue;
            };
            if tenure_id != &info.pox_consensus {
                continue;
            }

            let Some(address) = approving_signer_addrs
                .iter()
                .find(|addr| chunk.verify(addr).unwrap_or(false))
            else {
                continue;
            };
            if parent_tenure_last_block == &block_id_n {
                found_updates_n.insert(address.clone());
            }
        }
        Ok(found_updates_n.len() == approving_signer_addrs.len())
    })
    .expect("Originally approving signers did not update state machine to capitulated parent tenure last block N");

    info!("------------------------- Waiting for block N+1' approval from capitulated signer -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(Vec::new());
    TEST_SIGNERS_IGNORE_BLOCK_RESPONSES.set(vec![]);
    let block_n_1_prime =
        wait_for_block_pushed_by_miner_key(30, info_before.stacks_tip_height + 1, &miner_pk)
            .expect("Failed to mine block N+1' after signers capitulated");
    assert_ne!(
        block_n_1_prime, block_n_1,
        "Block N+1' should be different from original block N+1"
    );
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that minority signers (20%) capitulate their view to the supermajority (80%) view
/// when the chain advances. Specifically, tests that the 20% minority capitulates to block
/// N+1 when N+1 was globally accepted by the supermajority.
///
/// Test Setup:
/// The test spins up 10 stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// 1. All signers are configured with a tenure_last_block_proposal_timeout = 30 seconds, capitulate_miner_view_timeout = 10 seconds.
/// 2. The node mines 1 stacks block N (all signers sign it).
/// 3. 20% of the signers are configured to to auto reject any block proposals and ignore incoming block responses, broadcast of new blocks are skipped.
/// 4. A new tenure starts and miner proposes block N+1.
/// 7. The 80% of signers that signed block N+1, view the last block of the parent tenure as block N+1. The 20% of signers that rejected block N+1, view the last block of the parent tenure as block N.
/// 8. The 20% of signers that rejected block N+1 eventually capitulate their view of the parent tenure last block to block N+1 after the timeout period.
/// 9. The node mines block N+2 successfully with all signers signing it.
///
/// Test Assertion:
/// - All signers accepted block N.
/// - 80% of signers pre-commit/sign block N+1, while the other 20% reject it.
/// - After the timeout period, all signers see the parent tenure last block as block N+1.
/// - All signers accept block N+2 as valid.
fn minority_signers_capitulate_to_supermajority_consensus() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 10;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 4;

    let capitulate_miner_view_timeout = Duration::from_secs(15);
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |config| {
            config.capitulate_miner_view_timeout = capitulate_miner_view_timeout;
            config.tenure_last_block_proposal_timeout = capitulate_miner_view_timeout;
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        None,
        None,
    );

    let all_signers = signer_test.signer_test_pks();
    let rejecting_signers = all_signers[..2].to_vec();
    let approving_signers = all_signers[2..].to_vec();
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = 30;
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let info_before = signer_test.get_peer_info();

    test_observer::clear();
    // submit a tx so that the miner will mine a stacks block N
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine block N");

    wait_for(short_timeout, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for N to be mined and processed");

    // Ensure that the block was accepted globally so the stacks tip has advanced to N
    let block_n =
        wait_for_block_pushed_by_miner_key(30, info_before.stacks_tip_height + 1, &miner_pk)
            .expect("Timed out waiting for block N to be mined");

    let info_after = signer_test.get_peer_info();
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );

    info!("------------------------- Mine Nakamoto Block N+1 -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers.clone());
    TEST_SIGNERS_IGNORE_BLOCK_RESPONSES.set(rejecting_signers.clone());
    TEST_SIGNERS_IGNORE_PRE_COMMITS.set(rejecting_signers.clone());
    TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT.set(rejecting_signers.clone());
    TEST_SKIP_BLOCK_BROADCAST.set(true);
    TEST_BLOCK_ANNOUNCE_STALL.set(true);
    test_observer::clear();

    // submit a tx so that the miner will mine a stacks block N+1
    let info_before = signer_test.get_peer_info();
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to mine block N+1");
    let block_n_1 = wait_for_block_proposal_block(30, info_before.stacks_tip_height + 1, &miner_pk)
        .expect("Timed out waiting for block N+1 to be proposed");

    wait_for_block_rejections_from_signers(
        30,
        &block_n_1.header.signer_signature_hash(),
        &rejecting_signers,
    )
    .expect("Rejecting signers did not reject block N+1");

    info!("------------------------- Start Next Tenure -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(Vec::new());
    TEST_SIGNERS_IGNORE_PRE_COMMITS.set(vec![]);
    TEST_SIGNERS_IGNORE_BLOCK_RESPONSES.set(vec![]);
    test_observer::clear();
    signer_test.mine_bitcoin_block();
    let now = std::time::Instant::now();
    let info = get_chain_info(&signer_test.running_nodes.conf);
    info!(
        "------------------------- Wait for State to Update with Split View -------------------------";
        "burn_block_height" => info.burn_block_height,
        "consenus_hash" => %info.pox_consensus,
        "parent_tenure_last_block_height_n" => info_before.stacks_tip_height,
        "parent_tenure_last_block_height_n_1" => info_before.stacks_tip_height + 1,
    );

    let block_id_n = StacksBlockId::new(
        &info_before.stacks_tip_consensus_hash,
        &info_before.stacks_tip,
    );
    let block_id_n_1 = StacksBlockId::new(
        &block_n_1.header.consensus_hash,
        &block_n_1.header.block_hash(),
    );
    let rejecting_signer_addrs: Vec<StacksAddress> = rejecting_signers
        .iter()
        .map(|signer| StacksAddress::p2pkh(false, signer))
        .collect();
    let approving_signer_addrs: Vec<StacksAddress> = approving_signers
        .iter()
        .map(|signer| StacksAddress::p2pkh(false, signer))
        .collect();
    let signer_addresses = signer_test.signer_addresses_versions();
    wait_for(30, || {
        let stackerdb_events = test_observer::get_stackerdb_chunks();
        let mut found_updates_n: HashSet<StacksAddress> = HashSet::new();
        let mut found_updates_n_1: HashSet<StacksAddress> = HashSet::new();
        for chunk in stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            let SignerMessage::StateMachineUpdate(update) = message else {
                continue;
            };
            let StateMachineUpdateMinerState::ActiveMiner {
                parent_tenure_last_block,
                tenure_id,
                ..
            } = update.content.current_miner()
            else {
                continue;
            };
            if tenure_id != &info.pox_consensus {
                continue;
            }

            let Some((address, _)) = signer_addresses
                .iter()
                .find(|(addr, _)| chunk.verify(addr).unwrap_or(false))
            else {
                continue;
            };
            if parent_tenure_last_block == &block_id_n {
                rejecting_signer_addrs
                    .iter()
                    .find(|a| *a == address)
                    .map(|a| {
                        found_updates_n.insert(a.clone());
                    })
                    .expect("Only rejecting signers should report parent tenure last block as N");
            } else if parent_tenure_last_block == &block_id_n_1 {
                approving_signer_addrs
                    .iter()
                    .find(|a| *a == address)
                    .map(|a| {
                        found_updates_n_1.insert(a.clone());
                    })
                    .expect("Only approving signers should report parent tenure last block as N+1");
            }
        }
        Ok(found_updates_n.len() + found_updates_n_1.len() == signer_addresses.len())
    })
    .expect("Signers did not update state machine with split view of parent tenure last block");

    TEST_SIGNERS_IGNORE_BLOCK_ANNOUNCEMENT.set(vec![]);
    TEST_SKIP_BLOCK_BROADCAST.set(false);
    TEST_BLOCK_ANNOUNCE_STALL.set(false);

    // capitulate_viewpoint has TWO guards that must both be satisfied:
    // 1. last_capitulate_miner_view must be older than capitulate_miner_view_timeout
    // 2. time_since_last_approved (since block N was signed) must be >= capitulate_miner_view_timeout
    let time_to_wait = (capitulate_miner_view_timeout).saturating_sub(now.elapsed());
    info!(
        "------------------------- Waiting {} seconds for capitulation -------------------------",
        time_to_wait.as_secs()
    );
    std::thread::sleep(time_to_wait);
    wait_for(30, || {
        let stackerdb_events = test_observer::get_stackerdb_chunks();
        let mut found_updates_n_1: HashSet<StacksAddress> = HashSet::new();
        for chunk in stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            let SignerMessage::StateMachineUpdate(update) = message else {
                continue;
            };
            let StateMachineUpdateMinerState::ActiveMiner {
                parent_tenure_last_block,
                tenure_id,
                ..
            } = update.content.current_miner()
            else {
                continue;
            };
            if tenure_id != &info.pox_consensus {
                continue;
            }

            let Some((address, _)) = signer_addresses
                .iter()
                .find(|(addr, _)| chunk.verify(addr).unwrap_or(false))
            else {
                continue;
            };
            if parent_tenure_last_block == &block_id_n_1 {
                rejecting_signer_addrs.iter().find(|a| *a == address).map(|a| {
                    found_updates_n_1.insert(a.clone());
                });
            }
        }
        Ok(found_updates_n_1.len() == rejecting_signer_addrs.len())
    })
    .expect("Originally approving signers did not update state machine to capitulated parent tenure last block N+1");

    info!("------------------------- Waiting for block N+2 approval from capitulated signer -------------------------");
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to mine block N+2");

    let block_n_2 =
        wait_for_block_pushed_by_miner_key(30, info_before.stacks_tip_height + 2, &miner_pk)
            .expect("Failed to mine block N+2' after signers capitulated");
    wait_for_block_global_acceptance_from_signers(
        30,
        &block_n_2.header.signer_signature_hash(),
        &rejecting_signers,
    )
    .expect("Capitulating signers failed to sign block N+2");
    signer_test.shutdown();
}
