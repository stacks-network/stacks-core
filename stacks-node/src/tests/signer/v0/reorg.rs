// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, thread};

use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::{BlockResponse, RejectReason};
use stacks::burnchains::Txid;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::LeaderBlockCommitOp;
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo};
use stacks::chainstate::stacks::TenureChangeCause;
use stacks::codec::StacksMessageCodec;
use stacks::core::test_util::{make_stacks_transfer_serialized, to_addr};
use stacks::core::StacksEpochId;
use stacks::net::relay::fault_injection::set_ignore_block;
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::types::PublicKey;
use stacks::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::types::chainstate::TrieHash;
use stacks_common::util::sleep_ms;
use stacks_signer::v0::tests::{
    TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION, TEST_REJECT_ALL_BLOCK_PROPOSAL,
    TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST, TEST_SKIP_BLOCK_BROADCAST,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::{fmt, EnvFilter};

use super::{SignerTest, *};
use crate::event_dispatcher::MinedNakamotoBlockEvent;
use crate::nakamoto_node::miner::{
    fault_injection_stall_miner, fault_injection_unstall_miner, TEST_BLOCK_ANNOUNCE_STALL,
    TEST_BROADCAST_PROPOSAL_STALL, TEST_MINE_SKIP, TEST_P2P_BROADCAST_STALL,
};
use crate::neon::Counters;
use crate::run_loop::boot_nakamoto;
use crate::tests::nakamoto_integrations::{next_block_and, next_block_and_controller, wait_for};
use crate::tests::neon_integrations::{
    get_account, get_chain_info, get_chain_info_opt, get_sortition_info, submit_tx, TestProxy,
};
use crate::tests::{self, gen_random_port};
use crate::{BitcoinRegtestController, Keychain};

#[test]
#[ignore]
/// Test that signers count a block proposal that was rejected due to a reorg towards miner activity since it showed up BEFORE
/// the reorg_attempts_activity_timeout
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing. The block proposal timeout is set to 20 seconds.
///
/// Test Execution:
/// Test validation endpoint is stalled.
/// The miner proposes a block N.
/// A new tenure is started.
/// The miner proposes a block N'.
/// The test waits for block proposal timeout + 1 second.
/// The validation endpoint is resumed.
/// The signers accept block N.
/// The signers reject block N'.
/// The miner proposes block N+1.
/// The signers accept block N+1.
///
/// Test Assertion:
/// Stacks tip advances to N+1
fn reorg_attempts_count_towards_miner_validity() {
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
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let block_proposal_timeout = Duration::from_secs(60);
    let reorg_attempts_activity_timeout = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.block_proposal_timeout = block_proposal_timeout;
            config.reorg_attempts_activity_timeout = reorg_attempts_activity_timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let commits_submitted = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();

    signer_test.boot_to_epoch_3();

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    info!("------------------------- Test Mine Block N -------------------------");
    let chain_before = get_chain_info(&signer_test.running_nodes.conf);
    // Stall validation so signers will be unable to process the tenure change block for Tenure B.
    TEST_VALIDATE_STALL.set(true);
    signer_test.running_nodes.test_observer.clear();
    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    let block_proposal_n = wait_for_block_proposal(
        30,
        chain_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block proposal N");
    let chain_after = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(chain_after, chain_before);
    signer_test.running_nodes.test_observer.clear();

    info!("------------------------- Start Tenure B  -------------------------");
    TEST_MINE_SKIP.set(true);
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let chain_before = get_chain_info(&signer_test.running_nodes.conf);
    let start = std::time::Instant::now();
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            Ok(commits_submitted.load(Ordering::SeqCst) > commits_before
                && get_chain_info(&signer_test.running_nodes.conf).burn_block_height
                    > chain_before.burn_block_height)
        },
    )
    .unwrap();
    let chain_after = get_chain_info(&signer_test.running_nodes.conf);
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &chain_after.pox_consensus,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to update signer states to expected miner tenure id");
    TEST_MINE_SKIP.set(false);
    let block_proposal_n_prime = wait_for_block_proposal(
        30,
        chain_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block proposal N'");
    signer_test.running_nodes.test_observer.clear();

    assert_ne!(block_proposal_n, block_proposal_n_prime);
    let chain_before = get_chain_info(&signer_test.running_nodes.conf);
    TEST_MINE_SKIP.set(true);
    TEST_VALIDATE_STALL.set(false);

    info!("------------------------- Advance Tip to Block N -------------------------");
    wait_for(30, || {
        let chain_info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(chain_info.stacks_tip_height > chain_before.stacks_tip_height)
    })
    .expect("Timed out waiting for stacks tip to advance to block N");

    let chain_after = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(
        chain_after.stacks_tip_height,
        block_proposal_n.header.chain_length
    );
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &chain_after.pox_consensus,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to update signer state to expected miner tenure id");
    info!("------------------------- Wait for Block N' Rejection -------------------------");
    wait_for_block_global_rejection(
        30,
        &block_proposal_n_prime.header.signer_signature_hash(),
        num_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to see majority rejections of block N'");

    let wait_for = block_proposal_timeout
        .saturating_sub(start.elapsed())
        .add(Duration::from_secs(1));
    info!(
        "------------------------ Wait {} Seconds for Block Proposal timeout to Be Exceeded",
        wait_for.as_secs()
    );
    std::thread::sleep(wait_for);
    TEST_MINE_SKIP.set(false);

    info!(
        "------------------------- Test Mine Block N+1 at height {} -------------------------",
        block_proposal_n.header.chain_length + 1
    );
    // The signer should automatically attempt to mine a new block once the signers eventually tell it to abandon the previous block
    // It will accept it even though block proposal timeout is exceeded because the miner did manage to propose block N' BEFORE the timeout.
    let block_n_1 = wait_for_block_pushed_by_miner_key(
        30,
        block_proposal_n.header.chain_length + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get mined block N+1");
    assert!(block_n_1
        .get_tenure_tx_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::BlockFound),);
    let chain_after = get_chain_info(&signer_test.running_nodes.conf);

    assert_eq!(chain_after.stacks_tip, block_n_1.header.block_hash());
    assert_eq!(
        block_n_1.header.chain_length,
        block_proposal_n_prime.header.chain_length + 1
    );
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers do not count a block proposal that was rejected due to a reorg towards miner activity since it showed up AFTER
/// the reorg_attempts_activity_timeout
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing. The block proposal timeout is set to 20 seconds.
///
/// Test Execution:
/// Test validation endpoint is stalled.
/// The miner A proposes a block N.
/// Block proposals are stalled.
/// A new tenure is started.
/// The test waits for reorg_attempts_activity_timeout + 1 second.
/// The miner B proposes a block N'.
/// The test waits for block proposal timeout + 1 second.
/// The validation endpoint is resumed.
/// The signers accept block N.
/// The signers reject block N'.
/// The miner B proposes block N+1.
/// The signers reject block N+1.
///
/// Test Assertion:
/// Stacks tip advances to N.
fn reorg_attempts_activity_timeout_exceeded() {
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
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let block_proposal_timeout = Duration::from_secs(30);
    let reorg_attempts_activity_timeout = Duration::from_secs(20);
    let tenure_extend_wait_timeout = Duration::from_secs(1000);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.block_proposal_timeout = block_proposal_timeout;
            config.reorg_attempts_activity_timeout = reorg_attempts_activity_timeout;
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine Block N -------------------------");
    let chain_start = get_chain_info(&signer_test.running_nodes.conf);
    // Stall validation so signers will be unable to process the tenure change block for Tenure B.
    // And so the incoming miner proposes a block N' (the reorging block).
    TEST_VALIDATE_STALL.set(true);
    signer_test.running_nodes.test_observer.clear();
    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    let block_proposal_n = wait_for_block_proposal(
        30,
        chain_start.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to propose block N");
    let chain_after = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(chain_after, chain_start);
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk.clone()]);

    info!("------------------------- Start Tenure B  -------------------------");
    signer_test.running_nodes.test_observer.clear();
    let chain_before = chain_after;
    signer_test.mine_bitcoin_block();
    let chain_after = get_chain_info(&signer_test.running_nodes.conf);
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &chain_after.pox_consensus,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to update to Tenure B");

    // Make sure that no subsequent proposal arrives before the block_proposal_timeout is exceeded
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk.clone()]);
    info!(
        "------------------------- Wait for block N {} to arrive late  -------------------------",
        block_proposal_n.header.signer_signature_hash()
    );
    // Allow block N validation to finish, but don't broadcast it yet
    TEST_VALIDATE_STALL.set(false);
    TEST_PAUSE_BLOCK_BROADCAST.set(true);
    let reward_cycle = signer_test.get_current_reward_cycle();
    wait_for_block_global_acceptance_from_signers(
        30,
        &block_proposal_n.header.signer_signature_hash(),
        &signer_test.get_signer_public_keys(reward_cycle),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block proposal N to be globally accepted");

    let wait_time = reorg_attempts_activity_timeout.add(Duration::from_secs(1));
    info!("------------------------- Waiting {} Seconds for Reorg Activity Timeout to be Exceeded-------------------------", wait_time.as_secs());
    // Make sure to wait the reorg_attempts_activity_timeout AFTER the block is globally signed over
    // as this is the point where signers start considering from.
    std::thread::sleep(wait_time);
    signer_test.running_nodes.test_observer.clear();

    // Allow incoming miner to propose block N'
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);
    let block_proposal_n_prime = wait_for_block_proposal(
        30,
        chain_start.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block proposal N'");
    assert_ne!(block_proposal_n, block_proposal_n_prime);

    // Pause proposals again to avoid any additional proposals
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk.clone()]);
    // Allow the block broadcast to proceed and then make sure we've advanced to block N
    TEST_PAUSE_BLOCK_BROADCAST.set(false);
    wait_for(30, || {
        let chain_info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(chain_info.stacks_tip_height > chain_before.stacks_tip_height)
    })
    .expect("Timed out waiting for stacks tip to advance to block N");
    let chain_after = get_chain_info(&signer_test.running_nodes.conf);

    // We wait the remainder of the block proposal timeout
    let wait_time = block_proposal_timeout
        .saturating_sub(reorg_attempts_activity_timeout)
        .saturating_add(Duration::from_secs(1));
    info!("------------------------- Waiting {} Seconds for Miner to be Considered Inactive -------------------------", wait_time.as_secs());
    std::thread::sleep(wait_time);

    info!("------------------------- Waiting for Miner To be Marked Invalid -------------------------");
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &chain_start.pox_consensus,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to revert back to prior miner's tenure");
    let chain_before = chain_after;

    info!(
        "------------------------- Wait for Block N' {} Rejection -------------------------",
        block_proposal_n_prime.header.signer_signature_hash()
    );
    wait_for_block_global_rejection(
        30,
        &block_proposal_n_prime.header.signer_signature_hash(),
        num_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("FAIL: Timed out waiting for block proposal rejections of N'");

    info!("------------------------- Wait for Block N+1 Proposal -------------------------");
    signer_test.running_nodes.test_observer.clear();
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);
    // The miner will automatically reattempt to mine a block N+1 once it sees the stacks tip advance to block N.
    // N+1 will still be rejected however as the signers will have already marked the miner as invalid since the reorg
    // block N' arrived AFTER the reorg_attempts_activity_timeout and the subsequent block N+1 arrived AFTER the
    // block_proposal_timeout.
    let block_proposal_n_1 = wait_for_block_proposal(
        30,
        chain_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block proposal N+1");

    info!("------------------------- Wait for Block N+1 Rejection -------------------------");
    wait_for_block_global_rejection(
        30,
        &block_proposal_n_1.header.signer_signature_hash(),
        num_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("FAIL: Timed out waiting for block proposal rejections of N+1");

    info!("------------------------- Ensure chain halts -------------------------");
    // Just in case, wait again and ensure that the chain is still halted (once marked invalid, the miner can do nothing to satisfy the signers)
    assert!(wait_for(reorg_attempts_activity_timeout.as_secs(), || {
        let chain_info = get_chain_info(&signer_test.running_nodes.conf);
        assert_eq!(chain_info.stacks_tip_height, chain_before.stacks_tip_height);
        Ok(false)
    })
    .is_err());
    signer_test.shutdown();
}

/// Test a scenario where:
/// Two miners boot to Nakamoto.
/// Sortition occurs. Miner 1 wins.
/// Miner 1 proposes a block N
/// Signers accept and the stacks tip advances to N
/// Miner 1's block commits are paused so it cannot confirm the next tenure.
/// Sortition occurs. Miner 2 wins.
/// Miner 2 successfully mines blocks N+1
/// Sortition occurs quickly, within first_proposal_burn_block_timing_secs. Miner 1 wins.
/// Miner 1 proposes block N+1'
/// Signers approve N+1', saying "Miner is not building off of most recent tenure. A tenure they
///   reorg has already mined blocks, but the block was poorly timed, allowing the reorg."
/// Miner 1 proposes N+2' and it is accepted.
/// Miner 1 wins the next tenure and mines N+3, off of miner 1's tip. (miner 2's N+1 gets reorg)
#[test]
#[ignore]
fn allow_reorg_within_first_proposal_burn_block_timing_secs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 3;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            // Lets make sure we never time out since we need to stall some things to force our scenario
            signer_config.block_proposal_validation_timeout = Duration::from_secs(1800);
            signer_config.tenure_last_block_proposal_timeout = Duration::from_secs(1800);
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(1800);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );
    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commits -------------------------");
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Nakamoto Block N -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by Block N");

    let miner_1_block_n = wait_for_block_pushed_by_miner_key(
        30,
        stacks_height_before + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N");

    let block_n_height = miner_1_block_n.header.chain_length;
    info!("Block N: {block_n_height}");
    let info_after = get_chain_info(&conf_1);
    assert_eq!(info_after.stacks_tip, miner_1_block_n.header.block_hash());
    assert_eq!(info_after.stacks_tip_height, block_n_height);
    assert_eq!(block_n_height, stacks_height_before + 1);

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 2 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Pause Miner 2's Block Proposals -------------------------");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_2.clone()]);

    info!("------------------------- Mine Tenure -------------------------");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Failed to mine BTC block");

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("------------------------- Miner 1 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 2 Mines Block N+1 -------------------------");
    miners.signer_test.running_nodes.test_observer.clear();
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1.clone()]);
    let miner_2_block_n_1 = wait_for_block_pushed_by_miner_key(
        30,
        block_n_height + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N+1");

    assert_eq!(
        get_chain_info(&conf_1).stacks_tip_height,
        block_n_height + 1
    );

    info!("------------------------- Miner 1 Wins the Next Tenure, Mines N+1' -------------------------");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_2]);
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");
    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);
    let miner_1_block_n_1_prime = wait_for_block_pushed_by_miner_key(
        30,
        block_n_height + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N+1'");
    assert_ne!(miner_1_block_n_1_prime, miner_2_block_n_1);

    info!("------------------------- Miner 1 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Mines N+2' -------------------------");

    // Cannot use send_and_mine_transfer_tx as this relies on the peer's height
    miners.send_transfer_tx();
    let _ = wait_for_block_pushed_by_miner_key(
        30,
        block_n_height + 2,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N+2'");

    info!("------------------------- Miner 1 Mines N+3 in Next Tenure -------------------------");

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by Block N+2");
    let miner_1_block_n_3 = wait_for_block_pushed_by_miner_key(
        30,
        block_n_height + 3,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N+3");

    let peer_info = miners.get_peer_info();
    assert_eq!(peer_info.stacks_tip_height, block_n_height + 3);
    assert_eq!(peer_info.stacks_tip, miner_1_block_n_3.header.block_hash());

    miners.shutdown();
}

#[test]
#[ignore]
fn allow_reorg_within_first_proposal_burn_block_timing_secs_scenario() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    pub const MINER1: usize = 1;
    pub const MINER2: usize = 2;

    let num_signers = 5;
    let num_transfer_txs = 3;

    let test_context = Arc::new(SignerTestContext::new(num_signers, num_transfer_txs));

    scenario![
        test_context,
        (ChainMinerCommitOp::disable_for(test_context.clone(), MINER2)),
        ChainBootToEpoch3,
        (ChainMinerCommitOp::disable_for(test_context.clone(), MINER1)),
        (ChainStacksMining::pause()),
        (MinerMineBitcoinBlocks::one(test_context.clone())),
        (ChainExpectSortitionWinner::new(test_context.clone(), MINER1)),
        (MinerSubmitNakaBlockCommit::new(test_context.clone(), MINER2)),
        (ChainStacksMining::resume()),
        (ChainExpectNakaBlock::from_miner_height(test_context.clone(), MINER1)),
        (MinerMineBitcoinBlocks::one(test_context.clone())),
        (ChainExpectSortitionWinner::new(test_context.clone(), MINER2)),
        ChainVerifyLastSortitionWinnerReorged,
        (ChainExpectNakaBlock::from_miner_height(test_context.clone(), MINER2)),
        ChainShutdownMiners
    ]
}

/// Test a scenario where:
/// Two miners boot to Nakamoto.
/// Sortition occurs. Miner 1 wins.
/// Miner 1 proposes a block N
/// Signers accept and the stacks tip advances to N
/// Miner 1's block commits are paused so it cannot confirm the next tenure.
/// Sortition occurs. Miner 2 wins.
/// Miner 2 successfully mines blocks N+1, N+2, and N+3
/// Sortition occurs quickly, within first_proposal_burn_block_timing_secs. Miner 1 wins.
/// Miner 1 proposes block N+1' but gets rejected as more than one block has been mined in the current tenure (by miner2)
#[test]
#[ignore]
fn disallow_reorg_within_first_proposal_burn_block_timing_secs_but_more_than_one_block() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 3;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            // Lets make sure we never time out since we need to stall some things to force our scenario
            signer_config.block_proposal_validation_timeout = Duration::from_secs(1800);
            signer_config.tenure_last_block_proposal_timeout = Duration::from_secs(1800);
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(1800);
        },
        |_| {},
        |_| {},
    );
    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commits -------------------------");
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Nakamoto Block N -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by Block N");

    let miner_1_block_n = wait_for_block_pushed_by_miner_key(
        30,
        stacks_height_before + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N");

    let block_n_height = miner_1_block_n.header.chain_length;
    info!("Block N: {block_n_height}");
    let info_after = get_chain_info(&conf_1);
    assert_eq!(info_after.stacks_tip, miner_1_block_n.header.block_hash());
    assert_eq!(info_after.stacks_tip_height, block_n_height);
    assert_eq!(block_n_height, stacks_height_before + 1);

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 2 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Pause Miner 2's Block Mining -------------------------");
    fault_injection_stall_miner();

    info!("------------------------- Mine Tenure -------------------------");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Failed to mine BTC block");

    info!("------------------------- Miner 1 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 2 Mines Block N+1 -------------------------");

    fault_injection_unstall_miner();
    let _ = wait_for_block_pushed_by_miner_key(
        30,
        block_n_height + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N+1");

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    assert_eq!(
        get_chain_info(&conf_1).stacks_tip_height,
        block_n_height + 1
    );

    info!("------------------------- Miner 2 Mines N+2 and N+3 -------------------------");
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to send and mine transfer tx");
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to send and mine transfer tx");
    assert_eq!(
        get_chain_info(&conf_1).stacks_tip_height,
        block_n_height + 3
    );
    info!("------------------------- Miner 1 Wins the Next Tenure, Mines N+1', got rejected -------------------------");
    miners.signer_test.mine_bitcoin_block();
    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);
    // wait for a block N+1' proposal from miner1
    let proposed_block = wait_for_block_proposal(
        30,
        block_n_height + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block proposal");
    // check it has been rejected
    wait_for_block_global_rejection(
        30,
        &proposed_block.header.signer_signature_hash(),
        num_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for a block proposal to be rejected");

    // check only 1 block from miner1 has been added after the epoch3 boot
    let miner1_blocks_after_boot_to_epoch3 =
        get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer)
            .into_iter()
            .filter(|block| {
                // skip first nakamoto block
                if block.stacks_block_height == stacks_height_before {
                    return false;
                }
                let nakamoto_block_header = block.anchored_header.as_stacks_nakamoto().unwrap();
                miner_pk_1
                    .verify(
                        nakamoto_block_header.miner_signature_hash().as_bytes(),
                        &nakamoto_block_header.miner_signature,
                    )
                    .unwrap()
            })
            .count();

    assert_eq!(miner1_blocks_after_boot_to_epoch3, 1);

    info!("------------------------- Shutdown -------------------------");
    miners.shutdown();
}

#[test]
#[ignore]
fn disallow_reorg_within_first_proposal_burn_block_timing_secs_but_more_than_one_block_scenario() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    pub const MINER1: usize = 1;
    pub const MINER2: usize = 2;

    let num_signers = 5;
    let num_txs = 3;

    let test_context = Arc::new(SignerTestContext::new(num_signers, num_txs));

    scenario![
        test_context,
        (ChainMinerCommitOp::disable_for(test_context.clone(), MINER2)),
        ChainBootToEpoch3,
        (ChainMinerCommitOp::disable_for(test_context.clone(), MINER1)),
        (MinerMineBitcoinBlocks::one(test_context.clone())), // Sets block height in the state
        (ChainExpectStacksTenureChange::new(test_context.clone(), MINER1)),
        (ChainExpectNakaBlock::from_state_height(test_context.clone(), MINER1)), // Uses block height from the state
        (ChainExpectSortitionWinner::new(test_context.clone(), MINER1)),
        (MinerSubmitNakaBlockCommit::new(test_context.clone(), MINER2)),
        (ChainStacksMining::pause()),
        (MinerMineBitcoinBlocks::one(test_context.clone())),
        (MinerSubmitNakaBlockCommit::new(test_context.clone(), MINER1)),
        (ChainStacksMining::resume()),
        (ChainExpectNakaBlock::from_miner_height(test_context.clone(), MINER2)),
        (ChainExpectSortitionWinner::new(test_context.clone(), MINER2)),
        MinerSendAndMineStacksTransferTx,
        MinerSendAndMineStacksTransferTx,
        (ChainGenerateBitcoinBlocks::one(test_context.clone())),
        (ChainExpectNakaBlockProposal::with_rejection(test_context.clone(), MINER1, None)),
        (ChainVerifyMinerNakaBlockCount::after_boot_to_epoch3(test_context.clone(), MINER1, 1)), // FIXME: This takes the expected block count as a parameter - can we avoid that?
        ChainShutdownMiners, // FIXME: miners.shutdown() says: Cannot shutdown miners: other references to Arc still exist
    ]
}

#[test]
#[ignore]
/// Test that a miner that begins mining before seeing the last block of the
/// previous tenure can be interrupted when its tip advances to the last block,
/// then successfully mine a block on top of that block.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// Miner 1 mines a tenure change block, then mines a second block, block N,
/// but the signers will not broadcast it, and the miner will stall before
/// broadcasting. Miner 2 wins the next sortition and proposes a block N',
/// since it has not seen N, but signers are ignoring proposals so that it is
/// not rejected. Miner 1 then announces N. Miner 2 sees N, stops waiting
/// for signatures on N' and submits a new proposal, N+1, which is accepted.
/// Finally a new tenure arrives and N+2 is mined.
///
/// Test Assertion:
/// Stacks tip advances to N+1'
fn interrupt_miner_on_new_stacks_tip() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 5;
    let num_txs = 2;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            // we're deliberately stalling proposals: don't punish this in this test!
            signer_config.block_proposal_timeout = Duration::from_secs(240);
            // make sure that we don't allow forking due to burn block timing
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(60);
        },
        |config| {
            config.miner.block_rejection_timeout_steps = [(0, Duration::from_secs(1200))].into();
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let skip_commit_op_rl1 = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let skip_commit_op_rl2 = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, conf_2) = miners.get_node_configs();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    let all_signers = miners.signer_test.signer_test_pks();

    // Pause Miner 2's commits to ensure Miner 1 wins the first sortition.
    skip_commit_op_rl2.set(true);
    miners.boot_to_epoch_3();

    let sortdb = conf_1.get_burnchain().open_sortition_db(true).unwrap();

    info!("Pausing miner 1's block commit submissions");
    skip_commit_op_rl1.set(true);

    info!("------------------------- RL1 Wins Sortition -------------------------");
    info!("Mine RL1 Tenure");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    // Make the miner stall before broadcasting the block once it has been approved
    TEST_P2P_BROADCAST_STALL.set(true);
    // Make the signers not broadcast the block once it has been approved
    TEST_SKIP_BLOCK_BROADCAST.set(true);

    // submit a tx so that the miner will mine a stacks block
    let (tx, _) = miners.send_transfer_tx();
    // Wait for the block with this transfer to be accepted
    wait_for(30, || {
        Ok(miners
            .signer_test
            .running_nodes
            .test_observer
            .get_mined_nakamoto_blocks()
            .last()
            .unwrap()
            .tx_events
            .iter()
            .any(|t| {
                let TransactionEvent::Success(TransactionSuccessEvent { txid, .. }) = t else {
                    return false;
                };
                txid.to_hex() == tx
            }))
    })
    .expect("Timed out waiting for the transfer tx to be mined");

    let blocks = miners
        .signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks();
    let block_n = blocks.last().expect("No blocks mined");
    wait_for_block_global_acceptance_from_signers(
        30,
        &block_n.signer_signature_hash,
        &all_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block acceptance of N");
    info!("Block N is {}", block_n.stacks_height);

    info!("------------------------- RL2 Wins Sortition -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("Make signers ignore all block proposals, so that they don't reject it quickly");
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(all_signers.clone());

    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");
    // make sure the tenure was won by RL2
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("------------------------- RL2 Proposes Block N' -------------------------");

    let miner_2_block_n_prime = wait_for_block_proposal(
        30,
        stacks_height_before + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to propose block N'");
    assert_eq!(
        miner_2_block_n_prime.header.chain_length,
        block_n.stacks_height
    );

    info!("------------------------- Block N is Announced -------------------------");

    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1.clone(), miner_pk_2.clone()]);
    TEST_P2P_BROADCAST_STALL.set(false);

    // Wait for RL2's tip to advance to the last block
    wait_for(30, || {
        let Some(chain_info_2) = get_chain_info_opt(&conf_2) else {
            return Ok(false);
        };
        Ok(chain_info_2.stacks_tip_height == block_n.stacks_height)
    })
    .expect("Timed out waiting for RL2 to advance to block N");

    info!("------------------------- RL2 Proposes Block N+1 -------------------------");
    // Miner 2 should be interrupted from waiting for N' to be accepted when it sees N
    info!("Stop signers from ignoring proposals");
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(Vec::new());
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    let miner_2_block_n_1 = wait_for_block_proposal(
        30,
        stacks_height_before + 2,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to propose block N+1");
    assert_eq!(
        miner_2_block_n_1.header.chain_length,
        block_n.stacks_height + 1
    );

    info!("------------------------- Signers Accept Block N+1 -------------------------");
    let miner_2_block_n_1 = wait_for_block_pushed(
        30,
        &miner_2_block_n_1.header.signer_signature_hash(),
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to see block acceptance of Miner 2's Block N+1");
    assert_eq!(
        miner_2_block_n_1.header.block_hash(),
        miners.get_peer_stacks_tip()
    );

    info!("------------------------- Next Tenure Builds on N+1 -------------------------");
    miners.submit_commit_miner_1(&sortdb);
    miners.submit_commit_miner_2(&sortdb);

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");

    wait_for(30, || {
        let Some(chain_info) = get_chain_info_opt(&conf_1) else {
            return Ok(false);
        };
        Ok(chain_info.stacks_tip_height == block_n.stacks_height + 2)
    })
    .expect("Timed out waiting for height to advance to block N+2");

    miners.wait_for_chains(120);
    miners.shutdown();
}

#[test]
#[ignore]
/// Test that signers do not mark a block as globally accepted if it was not announced by the node.
/// This will simulate this case via testing flags, and ensure that a block can be reorged across tenure
/// boundaries now (as it is only marked locally accepted and no longer gets marked globally accepted
/// by simply seeing the threshold number of signatures).
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// 1. The node mines 1 stacks block N (all signers sign it).
/// 2. <30% of signers are configured to auto reject any block proposals, broadcast of new blocks are skipped, and miners are configured to ignore signers responses.
/// 3. The node mines 1 stacks block N+1 (all signers sign it, but one which rejects it) but eventually all mark the block as locally accepted.
/// 4. A new tenure starts and the miner attempts to mine a new sister block N+1' (as it does not see the threshold number of signatures or any block push from signers).
/// 5. The signers accept this sister block as a valid reorg and the node advances to block N+1'.
///
/// Test Assertion:
/// - All signers accepted block N.
/// - Less than 30% of the signers rejected block N+1.
/// - All signers accept block N+1' as a valid reorg.
/// - The node advances to block N+1'
fn global_acceptance_depends_on_block_announcement() {
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
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 4;

    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |config| {
            // Just accept all reorg attempts
            config.tenure_last_block_proposal_timeout = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        None,
        None,
    );

    let all_signers = signer_test.signer_test_pks();
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let miner_pkh = Hash160::from_node_public_key(&miner_pk);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = 30;
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let info_before = signer_test.get_peer_info();

    signer_test.running_nodes.test_observer.clear();
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
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N to be mined");

    let info_after = signer_test.get_peer_info();
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );

    info!("------------------------- Mine Nakamoto Block N+1 -------------------------");
    // Make less than 30% of the signers reject the block and ensure it is accepted by the node, but not announced.
    let rejecting_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers * 3 / 10)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers);
    TEST_SKIP_BLOCK_ANNOUNCEMENT.set(true);
    TEST_IGNORE_SIGNERS.set(true);
    TEST_SKIP_BLOCK_BROADCAST.set(true);
    signer_test.running_nodes.test_observer.clear();

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

    let block_n_1 = wait_for_block_proposal(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1 to be proposed");

    // Even though one of the signers rejected the block, it will eventually accept the block as it sees the 70% threshold of signatures
    wait_for_block_global_acceptance_from_signers(
        30,
        &block_n_1.header.signer_signature_hash(),
        &all_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block acceptance of N+1 by a majority of signers");

    info!("------------------------- Start Next Tenure -------------------------");

    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(Vec::new());
    TEST_IGNORE_SIGNERS.set(false);
    signer_test.running_nodes.test_observer.clear();
    signer_test.mine_bitcoin_block();

    let info = get_chain_info(&signer_test.running_nodes.conf);
    info!(
        "------------------------- Wait for State to Update -------------------------";
        "burn_block_height" => info.burn_block_height,
        "consenus_hash" => %info.pox_consensus,
        "parent_tenure_last_block_height" => info.stacks_tip_height,
    );
    wait_for_state_machine_update(
        30,
        &info.pox_consensus,
        info.burn_block_height,
        Some((miner_pkh, info_before.stacks_tip_height)),
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for the signers to update their state");
    TEST_SKIP_BLOCK_ANNOUNCEMENT.set(false);
    TEST_SKIP_BLOCK_BROADCAST.set(false);

    info!("------------------------- Waiting for block N+1' -------------------------");
    // Cannot use wait_for_block_pushed_by_miner_key as we could have more than one block proposal for the same height from the miner
    let sister_block = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get pushed sister block");
    assert_ne!(
        sister_block.header.signer_signature_hash(),
        block_n_1.header.signer_signature_hash()
    );
    assert_eq!(
        sister_block.header.chain_length,
        block_n_1.header.chain_length
    );

    // Assert the block was mined and the tip has changed.
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_after.stacks_tip_height,
        sister_block.header.chain_length
    );
    assert_eq!(info_after.stacks_tip, sister_block.header.block_hash());
    assert_eq!(
        info_after.stacks_tip_consensus_hash,
        sister_block.header.consensus_hash
    );
    assert_eq!(
        sister_block.header.chain_length,
        block_n_1.header.chain_length
    );
    assert_eq!(sister_block.header.parent_block_id, block_n.block_id());
    assert_ne!(sister_block, block_n_1);
}

/// Test a scenario where:
/// Two miners boot to Nakamoto.
/// Sortition occurs. Miner 1 wins.
/// Miner 1 proposes a block N
/// Signers accept and the stacks tip advances to N
/// Sortition occurs. Miner 2 wins.
/// Miner 2 proposes block N+1
/// Sortition occurs. Miner 1 wins.
/// Miner 1 proposes block N+1'
/// N+1 passes signers initial checks and is submitted to the node for validation.
/// N+1' arrives at the signers and passes inital checks, but BEFORE N+1' can be submitted for validation:
/// N+1 finishes being processed at the node and sits in the signers queue.
/// Signers THEN submit N+1' for node validation.
/// Signers process N+1 validation response ok, followed immediately by the N+1' validation response ok.
/// Signers broadcast N+1 acceptance
/// Signers broadcast N+1' rejection
/// Miner 2 proposes a new N+2 block built upon N+1
/// Asserts:
/// - N+1 is signed and broadcasted
/// - N+1' is rejected as a sortition view mismatch
/// - The tip advances to N+1 (Signed by Miner 1)
/// - The tip advances to N+2 (Signed by Miner 2)
#[test]
#[ignore]
fn no_reorg_due_to_successive_block_validation_ok() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 1;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            // Lets make sure we never time out since we need to stall some things to force our scenario
            signer_config.block_proposal_validation_timeout = Duration::from_secs(u64::MAX);
            signer_config.tenure_last_block_proposal_timeout = Duration::from_secs(u64::MAX);
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(u64::MAX);
            signer_config.block_proposal_timeout = Duration::from_secs(u64::MAX);
        },
        |config| {
            // Override this option, because this test depends on a block commit being submitted
            //  without a tenure change being detected. The default option would work, but it would
            //  make the test take unnecessarily long (and could be close to test failing timeouts)
            config.miner.block_commit_delay = Duration::from_secs(5);
        },
        |config| {
            // Override this option, because this test depends on a block commit being submitted
            //  without a tenure change being detected. The default option would work, but it would
            //  make the test take unnecessarily long (and could be close to test failing timeouts)
            config.miner.block_commit_delay = Duration::from_secs(5);
        },
    );

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();

    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let blocks_mined1 = miners
        .signer_test
        .running_nodes
        .counters
        .naka_mined_blocks
        .clone();

    let Counters {
        naka_skip_commit_op: rl2_skip_commit_op,
        naka_mined_blocks: blocks_mined2,
        naka_rejected_blocks: rl2_rejections,
        ..
    } = miners.rl2_counters.clone();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;

    info!("------------------------- Pause Miner 1's Block Commits -------------------------");
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Nakamoto Block N (Globally Accepted) -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine Block N");
    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        stacks_height_before + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to find block N");
    let block_n_signature_hash = block_n.header.signer_signature_hash();

    assert_eq!(miners.get_peer_stacks_tip(), block_n.header.block_hash());
    debug!("Miner 1 mined block N: {block_n_signature_hash}");

    info!("------------------------- Pause Block Validation Response of N+1 -------------------------");
    TEST_VALIDATE_STALL.set(true);
    let rejections_before_2 = rl2_rejections.load(Ordering::SeqCst);
    let blocks_before = miners
        .signer_test
        .running_nodes
        .test_observer
        .get_blocks()
        .len();
    let blocks_processed_before_1 = blocks_mined1.load(Ordering::SeqCst);
    let blocks_processed_before_2 = blocks_mined2.load(Ordering::SeqCst);

    let stacks_height_before = miners.get_peer_stacks_tip_height();
    // Force miner 1 to submit a block
    // submit a tx so that the miner will mine an extra block
    miners.send_transfer_tx();

    let block_n_1 = wait_for_block_proposal(
        30,
        stacks_height_before + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to find block N+1");
    let block_n_1_signature_hash = block_n_1.header.signer_signature_hash();

    assert_ne!(miners.get_peer_stacks_tip(), block_n_1.header.block_hash());
    assert_eq!(block_n_1.header.parent_block_id, block_n.header.block_id());
    debug!("Miner 1 proposed block N+1: {block_n_1_signature_hash}");

    info!("------------------------- Unpause Miner 2's Block Commits -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Pause Block Validation Submission of N+1'-------------------------");
    TEST_STALL_BLOCK_VALIDATION_SUBMISSION.set(true);
    // Don't mine so we can enforce exactly one proposal AFTER consensus reached by the signers
    TEST_MINE_SKIP.set(true);
    info!("------------------------- Start Miner 2's Tenure-------------------------");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Failed to Start Miner 2's Tenure");
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    TEST_MINE_SKIP.set(false);
    let block_n_1_prime = wait_for_block_proposal(
        30,
        stacks_height_before + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to find block N+1'");

    let block_n_1_prime_signature_hash = block_n_1_prime.header.signer_signature_hash();

    debug!("Miner 2 proposed N+1': {block_n_1_prime_signature_hash}");

    // Make sure that the tip is still at block N
    assert_eq!(miners.get_peer_stacks_tip(), block_n.header.block_hash());

    // Just a precaution to make sure no stacks blocks has been processed between now and our original pause
    assert_eq!(rejections_before_2, rl2_rejections.load(Ordering::SeqCst));
    assert_eq!(
        blocks_processed_before_1,
        blocks_mined1.load(Ordering::SeqCst)
    );
    assert_eq!(
        blocks_processed_before_2,
        blocks_mined2.load(Ordering::SeqCst)
    );
    assert_eq!(
        blocks_before,
        miners
            .signer_test
            .running_nodes
            .test_observer
            .get_blocks()
            .len()
    );

    info!("------------------------- Unpause Block Validation Response of N+1 -------------------------");

    TEST_VALIDATE_STALL.set(false);

    // Verify that the node accepted the proposed N+1, sending back a validate ok response
    wait_for(30, || {
        for proposal in miners
            .signer_test
            .running_nodes
            .test_observer
            .get_proposal_responses()
        {
            if let BlockValidateResponse::Ok(response) = proposal {
                if response.signer_signature_hash == block_n_1_signature_hash {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })
    .expect("Timed out waiting for validation response for N+1");

    debug!(
        "Node finished processing proposal validation request for N+1: {block_n_1_signature_hash}"
    );

    // This is awful but I can't gurantee signers have reached the submission stall and we need to ensure the event order is as expected.
    sleep_ms(5_000);

    info!("------------------------- Unpause Block Validation Submission and Response for N+1' -------------------------");
    TEST_STALL_BLOCK_VALIDATION_SUBMISSION.set(false);

    info!("------------------------- Confirm N+1' is Rejected ------------------------");
    // Confirm that every single signer has rejected the block and recorded its own rejection signature in its own DB
    wait_for(30, || {
        Ok(miners.signer_test.signer_configs.iter().all(|config| {
            let conn = Connection::open(config.db_path.clone()).unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT 1 FROM block_rejection_signer_addrs
                WHERE signer_signature_hash = ?1 AND signer_addr = ?2
                LIMIT 1",
                )
                .unwrap();

            let mut rows = stmt
                .query(rusqlite::params![
                    block_n_1_prime_signature_hash,
                    config.stacks_address
                ])
                .unwrap();
            rows.next().unwrap().is_some()
        }))
    })
    .expect("Failed to verify all signers recorded a signature rejection");
    wait_for_block_global_rejection(
        30,
        &block_n_1_prime_signature_hash,
        num_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to find block N+1'");

    info!("------------------------- Confirm N+1 Accepted -------------------------");
    let mined_block_n_1 = miners
        .signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .into_iter()
        .find(|block| block.signer_signature_hash == block_n_1_signature_hash)
        .expect("Failed to find block N+1");

    // Miner 2 will see block N+1 as a valid block and reattempt to mine N+2 on top.
    info!("------------------------- Confirm N+2 Accepted ------------------------");
    let block_n_2 = wait_for_block_pushed_by_miner_key(
        30,
        block_n_1.header.chain_length + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to find block N+2");
    assert_eq!(miners.get_peer_stacks_tip(), block_n_2.header.block_hash());
    info!("------------------------- Confirm Stacks Chain is As Expected ------------------------");
    let info_after = get_chain_info(&conf_1);
    assert_eq!(info_after.stacks_tip_height, block_n_2.header.chain_length);
    assert_eq!(info_after.stacks_tip_height, starting_peer_height + 3);
    assert_eq!(info_after.stacks_tip, block_n_2.header.block_hash());
    assert_ne!(
        info_after.stacks_tip_consensus_hash,
        block_n_1.header.consensus_hash
    );
    assert_eq!(
        info_after.stacks_tip_consensus_hash,
        block_n_2.header.consensus_hash
    );
    assert_eq!(
        block_n_2.header.parent_block_id.to_string(),
        mined_block_n_1.block_id
    );
    assert_eq!(block_n_1.header.parent_block_id, block_n.header.block_id());

    miners.shutdown();
}

#[test]
#[ignore]
fn forked_tenure_invalid() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let Some(result) = forked_tenure_testing(Duration::from_secs(5), Duration::from_secs(7), false)
    else {
        warn!("Snapshot created. Run test again.");
        return;
    };

    assert_ne!(
        result.tip_b.index_block_hash(),
        result.tip_a.index_block_hash(),
        "Tip B should not be the same as tip A"
    );
    assert_ne!(
        result.tip_b.index_block_hash(),
        result.tip_c.index_block_hash(),
        "Tip B should not be the same as tip C"
    );
    assert_ne!(result.tip_c, result.tip_a);

    // Block B was built atop block A
    assert_eq!(
        result.tip_b.stacks_block_height,
        result.tip_a.stacks_block_height + 1
    );
    assert_eq!(
        result.mined_b.parent_block_id,
        result.tip_a.index_block_hash().to_string()
    );

    // Block C was built AFTER Block B was built, but BEFORE it was broadcasted,
    // but it should still be extended from block B
    assert_eq!(
        result.mined_c.parent_block_id,
        result.tip_b.index_block_hash().to_string()
    );
    assert_eq!(
        result
            .tip_c
            .anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .signer_signature_hash(),
        result.mined_c.signer_signature_hash,
        "Mined block during tenure C should have become the chain tip"
    );

    assert!(result.tip_c_2.is_none());
    assert!(result.mined_c_2.is_none());

    // Tenure D should continue progress
    assert_ne!(result.tip_c, result.tip_d);
    assert_ne!(
        result.tip_b.index_block_hash(),
        result.tip_d.index_block_hash()
    );
    assert_ne!(result.tip_a, result.tip_d);

    // Tenure D builds off of Tenure c
    assert_eq!(
        result.tip_d.stacks_block_height,
        result.tip_c.stacks_block_height + 1,
    );
    assert_eq!(
        result.mined_d.parent_block_id,
        result.tip_c.index_block_hash().to_string()
    );
}

#[test]
#[ignore]
fn forked_tenure_okay() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let Some(result) =
        forked_tenure_testing(Duration::from_secs(360), Duration::from_secs(0), true)
    else {
        warn!("Snapshot created. Run test again.");
        return;
    };

    assert_ne!(result.tip_b, result.tip_a);
    assert_ne!(result.tip_b, result.tip_c);
    assert_ne!(result.tip_c, result.tip_a);

    // Block B was built atop block A
    assert_eq!(
        result.tip_b.stacks_block_height,
        result.tip_a.stacks_block_height + 1
    );
    assert_eq!(
        result.mined_b.parent_block_id,
        result.tip_a.index_block_hash().to_string()
    );

    // Block C was built AFTER Block B was built, but BEFORE it was broadcasted, so it should be built off of Block A
    assert_eq!(
        result.tip_c.stacks_block_height,
        result.tip_a.stacks_block_height + 1
    );
    assert_eq!(
        result.mined_c.parent_block_id,
        result.tip_a.index_block_hash().to_string()
    );

    let tenure_c_2 = result.tip_c_2.unwrap();
    assert_ne!(result.tip_c, tenure_c_2);
    assert_ne!(tenure_c_2, result.tip_d);
    assert_ne!(result.tip_c, result.tip_d);

    // Second block of tenure C builds off of block C
    assert_eq!(
        tenure_c_2.stacks_block_height,
        result.tip_c.stacks_block_height + 1,
    );
    assert_eq!(
        result.mined_c_2.unwrap().parent_block_id,
        result.tip_c.index_block_hash().to_string()
    );

    // Tenure D builds off of the second block of tenure C
    assert_eq!(
        result.tip_d.stacks_block_height,
        tenure_c_2.stacks_block_height + 1,
    );
    assert_eq!(
        result.mined_d.parent_block_id,
        tenure_c_2.index_block_hash().to_string()
    );
}

struct TenureForkingResult {
    tip_a: StacksHeaderInfo,
    tip_b: StacksHeaderInfo,
    tip_c: StacksHeaderInfo,
    tip_c_2: Option<StacksHeaderInfo>,
    tip_d: StacksHeaderInfo,
    mined_b: MinedNakamotoBlockEvent,
    mined_c: MinedNakamotoBlockEvent,
    mined_c_2: Option<MinedNakamotoBlockEvent>,
    mined_d: MinedNakamotoBlockEvent,
}

/// This test spins up a nakamoto-neon node.
/// It starts in Epoch 2.0, mines with `neon_node` to Epoch 3.0, and then switches
///  to Nakamoto operation (activating pox-4 by submitting a stack-stx tx). The BootLoop
///  struct handles the epoch-2/3 tear-down and spin-up.
/// Miner A mines a regular tenure, its last block being block a_x.
/// Miner B starts its tenure, Miner B produces a Stacks block b_0, but miner C submits its block commit before b_0 is broadcasted.
/// Bitcoin block C, containing Miner C's block commit, is mined BEFORE miner C has a chance to update their block commit with b_0's information.
/// This test asserts:
///  * tenure C ignores b_0, and correctly builds off of block a_x.
fn forked_tenure_testing(
    proposal_limit: Duration,
    post_btc_block_pause: Duration,
    expect_tenure_c: bool,
) -> Option<TenureForkingResult> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), send_amt + send_fee)],
            |config| {
                // make the duration long enough that the reorg attempt will definitely be accepted
                config.first_proposal_burn_block_timing = proposal_limit;
                // don't allow signers to post signed blocks (limits the amount of fault injection we
                // need)
                TEST_SKIP_BLOCK_BROADCAST.set(true);
            },
            |config| {
                config.miner.tenure_cost_limit_per_block_percentage = None;
                // this test relies on the miner submitting these timed out commits.
                // the test still passes without this override, but the default timeout
                // makes the test take longer than strictly necessary
                config.miner.block_commit_delay = Duration::from_secs(10);
            },
            None,
            None,
            Some(format!("forked_tenure_testing_{expect_tenure_c}").as_str()),
        );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return None;
    }

    sleep_ms(1000);
    info!("------------------------- Reached Epoch 3.0 -------------------------");

    let naka_conf = signer_test.running_nodes.conf.clone();
    let miner_sk = naka_conf.miner.mining_key.clone().unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let Counters {
        naka_submitted_commits: commits_submitted,
        naka_mined_blocks: mined_blocks,
        naka_proposed_blocks: proposed_blocks,
        naka_skip_commit_op: skip_commit_op,
        ..
    } = signer_test.running_nodes.counters.clone();

    let coord_channel = signer_test.running_nodes.coord_channel.clone();
    let blocks_processed_before = coord_channel
        .lock()
        .expect("Mutex poisoned")
        .get_stacks_blocks_processed();

    info!("Starting Tenure A.");
    // In the next block, the miner should win the tenure and submit a stacks block
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);

    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            let blocks_count = mined_blocks.load(Ordering::SeqCst);
            let blocks_processed = coord_channel
                .lock()
                .expect("Mutex poisoned")
                .get_stacks_blocks_processed();
            Ok(commits_count > commits_before
                && blocks_count > blocks_before
                && blocks_processed > blocks_processed_before)
        },
    )
    .unwrap();

    signer_test.check_signer_states_normal();

    sleep_ms(1000);

    let tip_a = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    // For the next tenure, submit the commit op but do not allow any stacks blocks to be broadcasted
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk]);
    TEST_BLOCK_ANNOUNCE_STALL.set(true);

    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let commits_before = commits_submitted.load(Ordering::SeqCst);

    info!("Starting Tenure B.");
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count > commits_before)
        },
    )
    .unwrap();

    signer_test.check_signer_states_normal();

    info!("Commit op is submitted; unpause tenure B's block");

    // Unpause the broadcast of Tenure B's block, do not submit commits.
    // However, do not allow B to be processed just yet
    skip_commit_op.set(true);
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    // Wait for a stacks block to be broadcasted
    let start_time = Instant::now();
    while mined_blocks.load(Ordering::SeqCst) <= blocks_before {
        assert!(
            start_time.elapsed() < Duration::from_secs(30),
            "FAIL: Test timed out while waiting for block production",
        );
        thread::sleep(Duration::from_secs(1));
    }

    info!("Tenure B broadcasted a block. Wait {post_btc_block_pause:?}, issue the next bitcoin block, and un-stall block commits.");
    thread::sleep(post_btc_block_pause);

    // the block will be stored, not processed, so load it out of staging
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
        .expect("Failed to get sortition tip");

    let tip_b_block = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_tenure_start_blocks(&tip_sn.consensus_hash)
        .unwrap()
        .first()
        .cloned()
        .unwrap();

    // synthesize a StacksHeaderInfo from this unprocessed block
    let tip_b = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(tip_b_block.header.clone()),
        microblock_tail: None,
        stacks_block_height: tip_b_block.header.chain_length,
        index_root: TrieHash([0x00; 32]), // we can't know this yet since the block hasn't been processed
        consensus_hash: tip_b_block.header.consensus_hash.clone(),
        burn_header_hash: tip_sn.burn_header_hash,
        burn_header_height: tip_sn.block_height as u32,
        burn_header_timestamp: tip_sn.burn_header_timestamp,
        anchored_block_size: tip_b_block.serialize_to_vec().len() as u64,
        burn_view: Some(tip_b_block.header.consensus_hash),
        total_tenure_size: 0,
    };

    let test_observer = &signer_test.running_nodes.test_observer;

    let blocks = test_observer.get_mined_nakamoto_blocks();
    let mined_b = blocks.last().unwrap().clone();

    // Block B was built atop block A
    assert_eq!(tip_b.stacks_block_height, tip_a.stacks_block_height + 1);
    assert_eq!(
        mined_b.parent_block_id,
        tip_a.index_block_hash().to_string()
    );
    assert_ne!(tip_b, tip_a);

    if !expect_tenure_c {
        // allow B to process, so it'll be distinct from C
        TEST_BLOCK_ANNOUNCE_STALL.set(false);
        sleep_ms(1000);
    }

    info!("Starting Tenure C.");

    // Submit a block commit op for tenure C
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = if expect_tenure_c {
        mined_blocks.load(Ordering::SeqCst)
    } else {
        proposed_blocks.load(Ordering::SeqCst)
    };
    skip_commit_op.set(false);

    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            if commits_count > commits_before {
                // now allow block B to process if it hasn't already.
                TEST_BLOCK_ANNOUNCE_STALL.set(false);
            }
            let blocks_count = mined_blocks.load(Ordering::SeqCst);
            let rbf_count = if expect_tenure_c { 1 } else { 0 };

            Ok(commits_count > commits_before + rbf_count && blocks_count > blocks_before)
        },
    )
    .unwrap_or_else(|_| {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        let blocks_count = mined_blocks.load(Ordering::SeqCst);
        let rbf_count = if expect_tenure_c { 1 } else { 0 };
        error!("Tenure C failed to produce a block";
            "commits_count" => commits_count,
            "commits_before" => commits_before,
            "rbf_count" => rbf_count as u64,
            "blocks_count" => blocks_count,
            "blocks_before" => blocks_before,
        );
        panic!();
    });

    let signer_pks = signer_test.signer_test_pks();
    if expect_tenure_c {
        signer_test.check_signer_states_reorg(&signer_pks, &[]);
    } else {
        signer_test.check_signer_states_reorg(&[], &signer_pks);
    };

    // allow blocks B and C to be processed
    sleep_ms(1000);

    info!("Tenure C produced (or proposed) a block!");
    let tip_c = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    let blocks = test_observer.get_mined_nakamoto_blocks();
    let mined_c = blocks.last().unwrap().clone();

    assert_ne!(tip_b.index_block_hash(), tip_c.index_block_hash());
    assert_ne!(tip_c, tip_a);

    let (tip_c_2, mined_c_2) = if !expect_tenure_c {
        (None, None)
    } else {
        // Now let's produce a second block for tenure C and ensure it builds off of block C.
        // submit a tx so that the miner will mine an extra block
        let sender_nonce = 0;
        let transfer_tx = make_stacks_transfer_serialized(
            &sender_sk,
            sender_nonce,
            send_fee,
            naka_conf.burnchain.chain_id,
            &recipient,
            send_amt,
        );
        let tx = submit_tx(&http_origin, &transfer_tx);
        info!("Submitted tx {tx} in Tenure C to mine a second block");
        wait_for(60, || {
            Ok(get_account(&http_origin, &sender_addr).nonce > sender_nonce)
        })
        .unwrap();

        info!("Tenure C produced a second block!");

        let block_2_tenure_c =
            NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
                .unwrap()
                .unwrap();
        let blocks = test_observer.get_mined_nakamoto_blocks();
        let block_2_c = blocks.last().cloned().unwrap();
        (Some(block_2_tenure_c), Some(block_2_c))
    };

    // make sure that a block commit has been submitted
    let burn_ht = signer_test.get_peer_info().burn_block_height;
    wait_for(60, || {
        let submitted_ht = signer_test
            .running_nodes
            .counters
            .naka_submitted_commit_last_burn_height
            .load(Ordering::SeqCst);
        Ok(submitted_ht >= burn_ht)
    })
    .unwrap();

    info!("Starting Tenure D.");

    // Mine tenure D
    signer_test.mine_nakamoto_block(Duration::from_secs(60), false);

    if expect_tenure_c {
        signer_test.check_signer_states_normal();
    } else {
        signer_test.check_signer_states_reorg(&signer_pks, &[]);
    }

    let tip_d = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    let blocks = test_observer.get_mined_nakamoto_blocks();
    let mined_d = blocks.last().unwrap().clone();
    signer_test.shutdown();
    Some(TenureForkingResult {
        tip_a,
        tip_b,
        tip_c,
        tip_c_2,
        tip_d,
        mined_b,
        mined_c,
        mined_c_2,
        mined_d,
    })
}

#[test]
#[ignore]
fn bitcoind_forking_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_| {},
        |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            let epochs = node_config.burnchain.epochs.as_mut().unwrap();
            epochs[StacksEpochId::Epoch30].end_height = 3_015;
            epochs[StacksEpochId::Epoch31].start_height = 3_015;
            epochs[StacksEpochId::Epoch31].end_height = 3_055;
            epochs[StacksEpochId::Epoch32].start_height = 3_055;
            epochs[StacksEpochId::Epoch32].end_height = 3_065;
            epochs[StacksEpochId::Epoch33].start_height = 3_065;
        },
        None,
        None,
    );
    let conf = signer_test.running_nodes.conf.clone();
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let miner_address = Keychain::default(conf.node.seed.clone())
        .origin_address(conf.is_mainnet())
        .unwrap();
    let miner_pk = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_mining_pubkey()
        .as_deref()
        .map(Secp256k1PublicKey::from_hex)
        .unwrap()
        .unwrap();

    let get_unconfirmed_commit_data = |btc_controller: &BitcoinRegtestController| {
        let unconfirmed_utxo = btc_controller
            .get_all_utxos(&miner_pk)
            .into_iter()
            .find(|utxo| utxo.confirmations == 0)?;
        let unconfirmed_txid = Txid::from_bitcoin_tx_hash(&unconfirmed_utxo.txid);
        let unconfirmed_tx = btc_controller.get_raw_transaction(&unconfirmed_txid);
        let unconfirmed_tx_opreturn_bytes = unconfirmed_tx.output[0].script_pubkey.as_bytes();
        info!(
            "Unconfirmed tx bytes: {}",
            stacks::util::hash::to_hex(unconfirmed_tx_opreturn_bytes)
        );
        let data = LeaderBlockCommitOp::parse_data(
            &unconfirmed_tx_opreturn_bytes[unconfirmed_tx_opreturn_bytes.len() - 77..],
        )
        .unwrap();
        Some(data)
    };

    signer_test.boot_to_epoch_3();
    info!("------------------------- Reached Epoch 3.0 -------------------------");
    let pre_epoch_3_nonce = get_account(&http_origin, &miner_address).nonce;
    let pre_fork_tenures = 10;

    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
        signer_test.check_signer_states_normal();
    }

    let pre_fork_1_nonce = get_account(&http_origin, &miner_address).nonce;

    assert_eq!(pre_fork_1_nonce, pre_epoch_3_nonce + 2 * pre_fork_tenures);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");

    let burn_block_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
    let burn_header_hash_to_fork = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_block_hash(burn_block_height);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .invalidate_block(&burn_header_hash_to_fork);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);

    // note, we should still have normal signer states!
    signer_test.check_signer_states_normal();

    info!("Wait for block off of shallow fork");

    fault_injection_stall_miner();

    let submitted_commits = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();

    // we need to mine some blocks to get back to being considered a frequent miner
    for i in 0..3 {
        let current_burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
        info!(
            "Mining block #{i} to be considered a frequent miner";
            "current_burn_height" => current_burn_height,
        );
        let commits_count = submitted_commits.load(Ordering::SeqCst);
        next_block_and_controller(
            &signer_test.running_nodes.btc_regtest_controller,
            60,
            |btc_controller| {
                let commits_submitted = submitted_commits
                    .load(Ordering::SeqCst);
                if commits_submitted <= commits_count {
                    // wait until a commit was submitted
                    return Ok(false)
                }
                let Some(payload) = get_unconfirmed_commit_data(btc_controller) else {
                    warn!("Commit submitted, but bitcoin doesn't see it in the unconfirmed UTXO set, will try to wait.");
                    return Ok(false)
                };
                let burn_parent_modulus = payload.burn_parent_modulus;
                let current_modulus = u8::try_from((current_burn_height + 1) % 5).unwrap();
                info!(
                    "Ongoing Commit Operation check";
                    "burn_parent_modulus" => burn_parent_modulus,
                    "current_modulus" => current_modulus,
                    "payload" => ?payload,
                );
                Ok(burn_parent_modulus == current_modulus)
            },
        )
        .unwrap();
        signer_test.check_signer_states_normal_missed_sortition();
    }

    let post_fork_1_nonce = get_account(&http_origin, &miner_address).nonce;

    // We should have forked 1 block (-2 nonces)
    assert_eq!(post_fork_1_nonce, pre_fork_1_nonce - 2);

    fault_injection_unstall_miner();
    for i in 0..5 {
        info!("Mining post-fork tenure {} of 5", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
        if i == 0 {
            signer_test.check_signer_states_reorg(&signer_test.signer_test_pks(), &[]);
        } else {
            signer_test.check_signer_states_normal();
        }
    }

    let pre_fork_2_nonce = get_account(&http_origin, &miner_address).nonce;
    assert_eq!(pre_fork_2_nonce, post_fork_1_nonce + 2 * 5);

    info!(
        "New chain info: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );

    info!("------------------------- Triggering Deeper Bitcoin Fork -------------------------");

    let burn_block_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
    let burn_header_hash_to_fork = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_block_hash(burn_block_height - 3);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .invalidate_block(&burn_header_hash_to_fork);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(4);

    signer_test.check_signer_states_normal();
    info!("Wait for block off of deep fork");

    let commits_submitted = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();
    // we need to mine some blocks to get back to being considered a frequent miner
    fault_injection_stall_miner();
    for i in 0..3 {
        let current_burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
        info!(
            "Mining block #{i} to be considered a frequent miner";
            "current_burn_height" => current_burn_height,
        );
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        next_block_and_controller(
            &signer_test.running_nodes.btc_regtest_controller,
            60,
            |btc_controller| {
                let commits_submitted = commits_submitted
                    .load(Ordering::SeqCst);
                if commits_submitted <= commits_count {
                    // wait until a commit was submitted
                    return Ok(false)
                }
                let Some(payload) = get_unconfirmed_commit_data(btc_controller) else {
                    warn!("Commit submitted, but bitcoin doesn't see it in the unconfirmed UTXO set, will try to wait.");
                    return Ok(false)
                };
                let burn_parent_modulus = payload.burn_parent_modulus;
                let current_modulus = u8::try_from((current_burn_height + 1) % 5).unwrap();
                info!(
                    "Ongoing Commit Operation check";
                    "burn_parent_modulus" => burn_parent_modulus,
                    "current_modulus" => current_modulus,
                    "payload" => ?payload,
                );
                Ok(burn_parent_modulus == current_modulus)
            },
        )
        .unwrap();
        signer_test.check_signer_states_normal_missed_sortition();
    }

    let post_fork_2_nonce = get_account(&http_origin, &miner_address).nonce;

    assert_eq!(post_fork_2_nonce, pre_fork_2_nonce - 4 * 2);

    fault_injection_unstall_miner();

    for i in 0..5 {
        info!("Mining post-fork tenure {} of 5", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
        if i == 0 {
            signer_test.check_signer_states_reorg(&signer_test.signer_test_pks(), &[]);
        } else {
            signer_test.check_signer_states_normal();
        }
    }

    let test_end_nonce = get_account(&http_origin, &miner_address).nonce;
    assert_eq!(test_end_nonce, post_fork_2_nonce + 2 * 5);

    info!(
        "New chain info: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );
    signer_test.shutdown();
}

/// This test involves two miners, 1 and 2. During miner 1's first tenure, miner
/// 2 is forced to ignore one of the blocks in that tenure. The next time miner
/// 2 mines a block, it should attempt to fork the chain at that point. The test
/// verifies that the fork is not successful and that miner 1 is able to
/// continue mining after this fork attempt.
#[test]
#[ignore]
fn partial_tenure_fork() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let max_nakamoto_tenures = 30;
    let inter_blocks_per_tenure = 5;

    // setup sender + recipient for a test stx transfer
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");

    // All signers are listening to node 1
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(
            sender_addr.clone(),
            (send_amt + send_fee) * max_nakamoto_tenures * inter_blocks_per_tenure,
        )],
        |signer_config| {
            signer_config.node_host = node_1_rpc_bind.clone();
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(0);
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.node.pox_sync_sample_secs = 30;
            config.miner.block_commit_delay = Duration::from_secs(0);

            config.node.seed = btc_miner_1_seed.clone();
            config.node.local_peer_seed = btc_miner_1_seed.clone();
            config.burnchain.local_mining_public_key = Some(btc_miner_1_pk.to_hex());
            config.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[1]));

            // Increase the reward cycle length to avoid missing a prepare phase
            // while we are intentionally forking.
            config.burnchain.pox_reward_length = Some(40);
            config.burnchain.pox_prepare_length = Some(10);

            // Move epoch 2.5 and 3.0 earlier, so we have more time for the
            // test before re-stacking is required.
            if let Some(epochs) = config.burnchain.epochs.as_mut() {
                epochs[StacksEpochId::Epoch24].end_height = 131;
                epochs[StacksEpochId::Epoch25].start_height = 131;
                epochs[StacksEpochId::Epoch25].end_height = 166;
                epochs[StacksEpochId::Epoch30].start_height = 166;
            } else {
                panic!("Expected epochs to be set");
            }
        },
        Some(vec![btc_miner_1_pk.clone(), btc_miner_2_pk.clone()]),
        None,
    );

    let conf = signer_test.running_nodes.conf.clone();
    let mut conf_node_2 = conf.clone();
    conf_node_2.node.rpc_bind = format!("{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.seed = btc_miner_2_seed.clone();
    conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
    conf_node_2.node.local_peer_seed = btc_miner_2_seed;
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let mining_pk_1 = StacksPublicKey::from_private(&conf.miner.mining_key.clone().unwrap());
    let mining_pk_2 = StacksPublicKey::from_private(&conf_node_2.miner.mining_key.clone().unwrap());
    let mining_pkh_1 = Hash160::from_node_public_key(&mining_pk_1);
    let mining_pkh_2 = Hash160::from_node_public_key(&mining_pk_2);
    debug!("The mining key for miner 1 is {mining_pkh_1}");
    debug!("The mining key for miner 2 is {mining_pkh_2}");

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let rl2_coord_channels = run_loop_2.coordinator_channels();
    let run_loop_stopper_2 = run_loop_2.get_termination_switch();
    let Counters {
        naka_skip_commit_op: rl2_skip_commit_op,
        ..
    } = run_loop_2.counters();
    let rl2_counters = run_loop_2.counters();
    let rl1_counters = signer_test.running_nodes.counters.clone();

    signer_test.boot_to_epoch_3();

    // Pause block commits from miner 2 to make sure
    //  miner 1 wins the first block
    rl2_skip_commit_op.set(true);

    let run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    wait_for(200, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for follower to catch up to the miner");

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    let rl1_skip_commit_op = signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();

    let sortdb = SortitionDB::open(
        &conf.get_burn_db_file_path(),
        false,
        conf.get_burnchain().pox_constants,
    )
    .unwrap();

    info!("-------- Waiting miner 2 to catch up to miner 1 --------");

    // Wait for miner 2 to catch up to miner 1
    // (note: use a high timeout to avoid potential failing on github workflow)
    wait_for(600, || {
        let info_1 = get_chain_info(&conf);
        let info_2 = get_chain_info(&conf_node_2);
        Ok(info_1.stacks_tip_height == info_2.stacks_tip_height)
    })
    .expect("Timed out waiting for miner 2 to catch up to miner 1");

    info!("-------- Miner 2 caught up to miner 1 --------");

    let info_before = get_chain_info(&conf);

    info!("-------- Miner 1 starting next tenure --------");

    wait_for(60, || {
        Ok(rl1_counters.naka_submitted_commit_last_burn_height.get()
            >= info_before.burn_block_height)
    })
    .unwrap();
    info!("-------- Blocking Miner 1 so that Miner 2 will win the next next tenure --------");
    rl1_skip_commit_op.set(true);

    // Mine the first block
    signer_test.mine_bitcoin_block();
    signer_test.check_signer_states_normal();

    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_1.clone()));

    // Setup miner 2 to ignore a block in this tenure
    let ignore_block = info_before.stacks_tip_height + 3;
    set_ignore_block(ignore_block, &conf_node_2.node.working_dir);

    // mine the interim blocks
    for interim_block_ix in 0..inter_blocks_per_tenure {
        info!(
            "Mining interim block #{interim_block_ix} in Miner 1's first tenure (the to-be-forked tenure)";
        );

        let (_, sender_nonce) = signer_test
            .submit_transfer_tx(&sender_sk, send_fee, send_amt)
            .unwrap();

        wait_for(60, || {
            Ok(get_account(&http_origin, &sender_addr).nonce > sender_nonce)
        })
        .unwrap();
    }

    info!("------- Unblocking Miner 2 ------");
    rl2_skip_commit_op.set(false);
    wait_for(60, || {
        Ok(rl2_counters.naka_submitted_commit_last_burn_height.get()
            > info_before.burn_block_height
            && rl2_counters.naka_submitted_commit_last_stacks_tip.get()
                > info_before.stacks_tip_height)
    })
    .unwrap();
    let proposals_before = rl2_counters.naka_proposed_blocks.get();
    let rejections_before = rl2_counters.naka_rejected_blocks.get();
    let peer_info_before = signer_test.get_peer_info();
    info!("------- Miner 2 wins first tenure post-fork ------");
    signer_test.mine_bitcoin_block();
    // Miner 2's tenure is "normal", even though it will end up being rejected by signers because miner 2
    //  is trying to reorg Miner 1's tenure
    signer_test.check_signer_states_normal();
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_2.clone()));

    wait_for(60, || {
        Ok(rl2_counters.naka_proposed_blocks.get() > proposals_before
            && rl2_counters.naka_rejected_blocks.get() > rejections_before)
    })
    .expect("Miner 2 should propose blocks that get rejected");

    let peer_info = signer_test.get_peer_info();
    assert_eq!(
        peer_info.stacks_tip_height,
        peer_info_before.stacks_tip_height
    );
    wait_for(60, || {
        Ok(
            rl2_counters.naka_submitted_commit_last_burn_height.get()
                >= peer_info.burn_block_height,
        )
    })
    .unwrap();

    info!("------- Miner 2 wins second tenure post-fork ------");
    rl2_skip_commit_op.set(true);
    signer_test.mine_bitcoin_block();
    info!("------- Unblocking Miner 1 so they can win the next tenure ------");
    rl1_skip_commit_op.set(false);

    // Miner 2's tenure is an allowed reorg before the prior tenure had no blocks
    signer_test.check_signer_states_reorg(&signer_test.signer_test_pks(), &[]);
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_2.clone()));

    let peer_info = signer_test.get_peer_info();
    assert_eq!(
        peer_info.stacks_tip_height,
        peer_info_before.stacks_tip_height
    );
    wait_for(60, || {
        Ok(
            rl1_counters.naka_submitted_commit_last_burn_height.get()
                >= peer_info.burn_block_height,
        )
    })
    .unwrap();

    rl1_skip_commit_op.set(true);
    info!("------- Miner 1 wins the third tenure post-fork ------");
    signer_test.mine_bitcoin_block();
    info!("------- Unblocking Miner 2 so they can win the next tenure ------");
    rl2_skip_commit_op.set(false);
    signer_test.check_signer_states_reorg(&signer_test.signer_test_pks(), &[]);
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_1.clone()));

    for interim_block_ix in 0..inter_blocks_per_tenure {
        info!(
            "Mining interim block #{interim_block_ix} in Miner 1's first tenure (the to-be-forked tenure)";
        );

        let (_, sender_nonce) = signer_test
            .submit_transfer_tx(&sender_sk, send_fee, send_amt)
            .unwrap();

        wait_for(60, || {
            Ok(get_account(&http_origin, &sender_addr).nonce > sender_nonce)
        })
        .unwrap();
    }

    info!("------- Miner 2 wins the fourth tenure post-fork ------");
    let proposals_before = rl2_counters.naka_proposed_blocks.get();
    let mined_before = rl2_counters.naka_mined_blocks.get();
    let peer_info_before = signer_test.get_peer_info();
    signer_test.mine_bitcoin_block();
    // now, miner 2 is reorging an entire miner 1 tenure, which should lead
    //  the signer set to treat miner 2's reorg as rejected.
    signer_test.check_signer_states_reorg(&[], &signer_test.signer_test_pks());
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_2.clone()));

    wait_for(60, || {
        Ok(rl2_counters.naka_proposed_blocks.get() > proposals_before)
    })
    .expect("Miner 2 should propose blocks that get rejected");

    wait_for(120, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > peer_info_before.stacks_tip_height)
    })
    .expect("Miner 1 should submit a tenure extend and have it globally accepted");

    assert_eq!(
        mined_before,
        rl2_counters.naka_mined_blocks.get(),
        "Miner 2 should not have mined any new blocks"
    );

    rl2_coord_channels
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper_2.store(false, Ordering::SeqCst);
    run_loop_2_thread.join().unwrap();
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers that accept a block locally, but that was rejected globally will accept a subsequent attempt
/// by the miner essentially reorg their prior locally accepted/signed block, i.e. the globally rejected block overrides
/// their local view.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but rejected by >30% of the signers.
/// The miner then attempts to mine N+1', and all signers accept the block.
///
/// Test Assertion:
/// Stacks tip advances to N+1'
fn locally_accepted_blocks_overriden_by_global_rejection() {
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
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 3;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let short_timeout_secs = 20;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
    );

    let all_signers = signer_test.signer_test_pks();

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let info_before = signer_test.get_peer_info();
    // submit a tx so that the miner will mine a stacks block
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
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N to be mined");
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 -------------------------");
    // Make half of the signers reject the block proposal by the miner to ensure its marked globally rejected
    let rejecting_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers / 2 + num_signers % 2)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers.clone());
    signer_test.running_nodes.test_observer.clear();
    let info_before = signer_test.get_peer_info();
    // Make a new stacks transaction to create a different block signature, but make sure to propose it
    // AFTER the signers are unfrozen so they don't inadvertently prevent the new block being accepted
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} to mine block N+1");

    let proposed_block_n_1 = wait_for_block_proposal(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1' to be proposed");
    wait_for_block_rejections_from_signers(
        short_timeout_secs,
        &proposed_block_n_1.header.signer_signature_hash(),
        &rejecting_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block rejection of N+1");
    let info_after = signer_test.get_peer_info();
    assert_eq!(info_before, info_after);

    info!("------------------------- Test Mine Nakamoto Block N+1' -------------------------");
    let info_before = signer_test.get_peer_info();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(Vec::new());
    signer_test.running_nodes.test_observer.clear();

    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} to mine block N+1'");

    let block_n_1_prime = wait_for_block_pushed_by_miner_key(
        short_timeout_secs,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1' to be mined");

    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );
    assert_eq!(info_after.stacks_tip, block_n_1_prime.header.block_hash());
    assert_ne!(block_n_1_prime, proposed_block_n_1);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers that reject a block locally, but that was accepted globally will accept
/// a subsequent block built on top of the accepted block
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but rejected by <30% of the signers.
/// The miner then attempts to mine N+2, and all signers accept the block.
///
/// Test Assertion:
/// Stacks tip advances to N+2
fn locally_rejected_blocks_overriden_by_global_acceptance() {
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
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 3;

    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
    );

    let all_signers: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect();

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
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N to be mined");
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());

    info!("------------------------- Mine Nakamoto Block N+1 -------------------------");
    // Make less than 30% of the signers reject the block and ensure it is STILL marked globally accepted
    let rejecting_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers * 3 / 10)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers.clone());
    signer_test.running_nodes.test_observer.clear();

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
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine block N+1");
    // The rejecting signers will reject the block, but it will still be accepted globally
    let block_n_1 = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1 to be mined");

    wait_for_block_rejections_from_signers(
        short_timeout,
        &block_n_1.header.signer_signature_hash(),
        &rejecting_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block rejection of N+1");

    // Assert the block was mined and the tip advanced to N+1
    let info_after = signer_test.get_peer_info();
    assert_eq!(info_after.stacks_tip, block_n_1.header.block_hash());
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );

    info!("------------------------- Test Mine Nakamoto Block N+2 -------------------------");
    // Ensure that all signers accept the block proposal N+2
    let info_before = signer_test.get_peer_info();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(Vec::new());

    // submit a tx so that the miner will mine a stacks block N+2 and ensure ALL signers accept it
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
    let block_n_2 = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+2 to be pushed");
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height,
    );
    assert_eq!(info_after.stacks_tip, block_n_2.header.block_hash());
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers that have accepted a locally signed block N+1 built in tenure A can sign a block proposed during a
/// new tenure B built upon the last globally accepted block N if the timeout is exceeded, i.e. a reorg can occur at a tenure boundary.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but <30% pre-commit to it. The remaining signers
/// do not make a decision on the block. A new tenure begins and the miner proposes a new block N+1' which all signers accept.
///
/// Test Assertion:
/// Stacks tip advances to N+1'
fn reorg_locally_accepted_blocks_across_tenures_succeeds() {
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
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 2;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |config| {
            // Just accept all reorg attempts
            config.tenure_last_block_proposal_timeout = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        None,
        None,
    );
    let all_signers = signer_test.signer_test_pks();
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    signer_test.boot_to_epoch_3();
    info!("------------------------- Starting Tenure A -------------------------");
    let info_before = signer_test.get_peer_info();
    info!("------------------------- Test Mine Nakamoto Block N at Height {} -------------------------", info_before.stacks_tip_height + 1);
    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let txid = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N to be mined");
    assert!(block_n
        .txs
        .iter()
        .any(|tx| { tx.txid().to_string() == txid }));
    // Ensure that the block was accepted globally so the stacks tip has advanced to N
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 at Height {} -------------------------", info_before.stacks_tip_height + 2);
    // Make more than >70% of the signers ignore the block proposal to ensure it it is not globally accepted/rejected
    let ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers * 7 / 10)
        .collect();
    let non_ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .skip(num_signers * 7 / 10)
        .collect();
    TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST.set(ignoring_signers.clone());
    // Clear the stackerdb chunks
    signer_test.running_nodes.test_observer.clear();

    let info_before = signer_test.get_peer_info();
    // submit a tx so that the miner will ATTEMPT to mine a stacks block N+1
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to attempt to mine block N+1");
    let block_n_1_proposal = wait_for_block_proposal(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1 to be proposed");
    // Make sure that the non ignoring signers do actually accept it though
    wait_for_block_pre_commits_from_signers(
        30,
        &block_n_1_proposal.header.signer_signature_hash(),
        &non_ignoring_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block pre-commits of N+1");
    let info_after = signer_test.get_peer_info();
    assert_eq!(info_after, info_before);
    assert_ne!(
        block_n_1_proposal.header.signer_signature_hash(),
        block_n.header.signer_signature_hash()
    );

    info!("------------------------- Starting Tenure B -------------------------");
    signer_test.running_nodes.test_observer.clear();
    // Start a new tenure and ensure the miner can propose a new block N+1' that is accepted by all signers
    let commits_submitted = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let chain_before = get_chain_info(&signer_test.running_nodes.conf);
    TEST_MINE_SKIP.set(true);
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let info = get_chain_info(&signer_test.running_nodes.conf);
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count > commits_before
                && info.burn_block_height > chain_before.burn_block_height)
        },
    )
    .unwrap();
    let chain_after = get_chain_info(&signer_test.running_nodes.conf);
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &chain_after.pox_consensus,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for the signers to update their state");
    info!(
        "------------------------- Mine Nakamoto Block N+1' at Height {} -------------------------",
        info_before.stacks_tip_height + 1
    );
    let info_before = signer_test.get_peer_info();
    signer_test.running_nodes.test_observer.clear();
    TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST.set(Vec::new());
    TEST_MINE_SKIP.set(false);

    let block_n_1_prime = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1' to be mined");
    // Ensure that the block was accepted globally so the stacks tip has advanced to N+1' (even though they signed a sister block in the prior tenure)
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    assert_eq!(info_after.stacks_tip, block_n_1_prime.header.block_hash());
    assert_ne!(
        block_n_1_prime.header.signer_signature_hash(),
        block_n_1_proposal.header.signer_signature_hash()
    );
    assert_eq!(
        block_n_1_prime.header.chain_length,
        block_n_1_proposal.header.chain_length
    );

    info!(
        "------------------------- Mine Nakamoto Block N+2 at Height {} -------------------------",
        info_before.stacks_tip_height + 2
    );
    let block_n_2 = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 2,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+2 to be mined");

    wait_for(30, || {
        let info = signer_test.get_peer_info();
        Ok(info.stacks_tip_height > info_before.stacks_tip_height + 1)
    })
    .expect("Timed out waiting for the chain tip to advance");
    // Ensure that the block was accepted globally so the stacks tip has advanced to N+2 (built on N+1' even though they signed a sister block in the prior tenure)
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_before.stacks_tip_height + 2,
        info_after.stacks_tip_height
    );
    assert_eq!(info_after.stacks_tip, block_n_2.header.block_hash());
    assert_eq!(block_n_2.header.parent_block_id, block_n_1_prime.block_id());
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers that have accepted a locally signed block N+1 built in tenure A cannot sign a block proposed during a
/// new tenure B built upon the last globally accepted block N if the timeout is not exceeded, i.e. a reorg cannot occur at a tenure boundary
/// before the specified timeout has been exceeded.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but <30% accept it. The remaining signers
/// do not make a decision on the block. A new tenure begins and the miner proposes a new block N+1' which all signers reject as the timeout
/// has not been exceeded.
///
/// Test Assertion:
/// Stacks tip remains at N.
fn reorg_locally_accepted_blocks_across_tenures_fails() {
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
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 2;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |config| {
            // Do not alow any reorg attempts essentially
            config.tenure_last_block_proposal_timeout = Duration::from_secs(100_000);
        },
        |_| {},
        None,
        None,
    );
    let all_signers = signer_test.signer_test_pks();
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    signer_test.boot_to_epoch_3();
    info!("------------------------- Starting Tenure A -------------------------");
    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let info_before = signer_test.get_peer_info();

    // submit a tx so that the miner will mine a stacks block
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
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N to be mined");
    // Due to a potential race condition in processing and block pushed...have to wait
    wait_for(30, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Stacks tip failed to advance");
    // Ensure that the block was accepted globally so the stacks tip has advanced to N
    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 -------------------------");
    // Make more than >70% of the signers ignore the block proposal to ensure it it is not globally accepted/rejected
    let ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers * 7 / 10)
        .collect();
    let non_ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .skip(num_signers * 7 / 10)
        .collect();
    TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST.set(ignoring_signers.clone());
    // Clear the stackerdb chunks
    signer_test.running_nodes.test_observer.clear();

    let info_before = signer_test.get_peer_info();
    // submit a tx so that the miner will ATTEMPT to mine a stacks block N+1
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);

    info!("Submitted tx {tx} in to attempt to mine block N+1");
    let block_n_1 = wait_for_block_proposal(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1 to be proposed");
    wait_for_block_acceptance_from_signers(
        30,
        &block_n_1.header.signer_signature_hash(),
        &non_ignoring_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block acceptances of N+1");

    let info_after = signer_test.get_peer_info();
    // Ensure that the block was NOT accepted globally so the stacks tip has NOT advanced to N+1
    assert_eq!(info_after, info_before);

    info!("------------------------- Starting Tenure B -------------------------");
    let info_before = signer_test.get_peer_info();

    // Clear the test observer so any old rejections are not counted
    signer_test.running_nodes.test_observer.clear();

    // Start a new tenure and ensure the we see the expected rejections
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);
    let proposal = wait_for_block_proposal(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1 to be proposed");
    wait_for_block_rejections_from_signers(
        30,
        &proposal.header.signer_signature_hash(),
        &non_ignoring_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block rejections of N+1");

    let info_after = signer_test.get_peer_info();
    // Ensure that the block was NOT accepted globally so the stacks tip has NOT advanced to N+1'
    assert_eq!(info_after.stacks_tip, info_before.stacks_tip);
}

#[test]
#[ignore]
fn bitcoin_reorg_extended_tenure() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 5;

    let mut miners = MultipleMinerTest::new_with_signer_dist(
        num_signers,
        60,
        |signer_config| {
            // We don't want the miner of the "inactive" sortition before the flash block
            //  to get timed out.
            signer_config.block_proposal_timeout = Duration::from_secs(600);
        },
        |_| {},
        |config| {
            // we will interpose with the testproxy on the second node's bitcoind
            //  connection, so that we can shut off communication before the reorg.
            config.burnchain.rpc_port = 28132;
            config.burnchain.peer_port = 28133;
        },
        |signer_port| {
            // only put 1 out of 5 signers on the second node.
            // this way, the 4 out of 5 signers can approve a block in bitcoin fork
            // that the fifth signer does not witness
            if signer_port % 5 == 0 {
                1
            } else {
                0
            }
        },
        None,
    );

    let (conf_1, _conf_2) = miners.get_node_configs();
    let btc_p2p_proxy = TestProxy {
        bind_port: 28133,
        forward_port: conf_1.burnchain.peer_port,
        drop_control: Arc::new(Mutex::new(false)),
        keep_running: Arc::new(Mutex::new(true)),
    };
    let btc_rpc_proxy = TestProxy {
        bind_port: 28132,
        forward_port: conf_1.burnchain.rpc_port,
        drop_control: Arc::new(Mutex::new(false)),
        keep_running: Arc::new(Mutex::new(true)),
    };

    btc_p2p_proxy.spawn();
    btc_rpc_proxy.spawn();

    let rl1_counters = miners.signer_test.running_nodes.counters.clone();

    let sortdb = SortitionDB::open(
        &conf_1.get_burn_db_file_path(),
        false,
        conf_1.get_burnchain().pox_constants,
    )
    .unwrap();

    miners.pause_commits_miner_2();
    let (mining_pkh_1, _mining_pkh_2) = miners.get_miner_public_key_hashes();

    miners.boot_to_epoch_3();

    miners
        .signer_test
        .submit_burn_block_contract_and_wait(&miners.sender_sk)
        .expect("Timed out waiting for contract publish");

    let info = get_chain_info(&conf_1);

    wait_for(60, || {
        Ok(rl1_counters
            .naka_submitted_commit_last_parent_tenure_id
            .get()
            == info.stacks_tip_consensus_hash)
    })
    .expect("Timed out waiting for commits from Miner 1 for Tenure 1 of the test");

    for _ in 0..2 {
        miners
            .signer_test
            .submit_burn_block_call_and_wait(&miners.sender_sk)
            .expect("Timed out waiting for contract-call");
    }

    miners.pause_commits_miner_1();
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .unwrap();

    for _ in 0..2 {
        miners
            .signer_test
            .submit_burn_block_call_and_wait(&miners.sender_sk)
            .expect("Timed out waiting for contract-call");
    }

    miners.signer_test.check_signer_states_normal();
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_1.clone()));

    let last_active_sortition = get_sortition_info(&conf_1);
    assert!(last_active_sortition.was_sortition);

    let tenure_1_info = get_chain_info(&conf_1);

    info!("Mining empty block!");
    // make sure that the second node *doesn't* get this bitcoin block
    //  that way they will never see the losing side of the btc fork.
    *btc_p2p_proxy.drop_control.lock().unwrap() = true;
    *btc_rpc_proxy.drop_control.lock().unwrap() = true;

    miners.btc_regtest_controller_mut().build_next_block(1);

    wait_for(60, || {
        let info = get_chain_info(&conf_1);
        Ok(info.burn_block_height >= 1 + tenure_1_info.burn_block_height)
    })
    .expect("Timed out waiting for the flash blocks to be processed by the stacks nodes");

    let cur_empty_sortition = get_sortition_info(&conf_1);
    assert!(!cur_empty_sortition.was_sortition);

    // after the flash block, make sure we get block processing without a new bitcoin block
    //   being mined.
    for _ in 0..2 {
        miners
            .signer_test
            .submit_burn_block_call_and_wait(&miners.sender_sk)
            .expect("Timed out waiting for contract-call");
    }

    let last_nonce = miners
        .signer_test
        .get_account(&to_addr(&miners.sender_sk))
        .nonce;

    info!("------------------------- Triggering Bitcoin Fork -------------------------");

    let burn_block_height = get_chain_info(&conf_1).burn_block_height;
    let burn_header_hash_to_fork = miners
        .signer_test
        .running_nodes
        .btc_regtest_controller
        .get_block_hash(burn_block_height);
    let before_fork = get_chain_info(&conf_1).pox_consensus;

    miners
        .signer_test
        .running_nodes
        .btc_regtest_controller
        .invalidate_block(&burn_header_hash_to_fork);
    miners
        .signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(2);

    *btc_p2p_proxy.drop_control.lock().unwrap() = false;
    *btc_rpc_proxy.drop_control.lock().unwrap() = false;

    info!("Bitcoin fork triggered"; "ch" => %before_fork, "btc_height" => burn_block_height);
    info!("Chain info before fork: {:?}", get_chain_info(&conf_1));

    // Make sure signers don't perform block broadcast for the next bits:
    //  we want to ensure that the *miner* is the one broadcast blocks,
    //  because when we stall p2p broadcast, we don't want to accidentally
    //  stall the miner in the situation where they produce block A, signers broadcast it,
    //  we initiate the stall, and then the miner attempts to broadcast A.
    stacks_signer::v0::tests::TEST_SKIP_BLOCK_BROADCAST.set(true);

    let mut after_fork = get_chain_info(&conf_1).pox_consensus;
    wait_for(60, || {
        after_fork = get_chain_info(&conf_1).pox_consensus;
        Ok(after_fork != before_fork)
    })
    .unwrap();

    info!("Chain info after fork: {:?}", get_chain_info(&conf_1));

    // get blocks produced with the "reorged" txs before we stall broadcasts
    //  to check signer approvals
    miners
        .signer_test
        .wait_for_nonce_increase(&to_addr(&miners.sender_sk), last_nonce - 1)
        .unwrap();

    miners.wait_for_chains(60);

    // stall p2p broadcast and signer block announcements
    //  so that we can ensure all the signers approve the proposal
    //  before it gets accepted by stacks-nodes
    TEST_P2P_BROADCAST_STALL.set(true);

    info!("Stalled broadcast, submitting a contract call!");

    // the signer signature hash is the same as the block header hash.
    // we use the latest_signer_sighash to make sure we're getting block responses for the
    //  block we expect to be mined after the next contract call is submitted.
    miners.signer_test.running_nodes.test_observer.clear();
    let chain_info = get_chain_info(&conf_1);
    let latest_signer_sighash = Sha512Trunc256Sum(chain_info.stacks_tip.0);
    info!("------------------------- Submitting Contract Call -------------------------");
    miners
        .signer_test
        .submit_contract_call(
            &miners.sender_sk,
            1000,
            "burn-height-local",
            "run-update",
            &[],
        )
        .unwrap();

    let rc = miners.signer_test.get_current_reward_cycle();
    let slot_ids = miners.signer_test.get_signer_indices(rc);
    let mut block_responses: Vec<_> = vec![];

    wait_for(60, || {
        block_responses = slot_ids
            .iter()
            .filter_map(|slot_id| {
                let latest_br = miners.signer_test.get_latest_block_response(slot_id.0);
                info!(
                    "[{}] Checking response for {}. accepted = {}",
                    slot_id.0,
                    latest_br.get_signer_signature_hash(),
                    latest_br.as_block_accepted().is_some()
                );
                if latest_br.get_signer_signature_hash() != &latest_signer_sighash {
                    Some(latest_br)
                } else {
                    None
                }
            })
            .collect();
        let Some(sighash) = block_responses
            .first()
            .map(BlockResponse::get_signer_signature_hash)
        else {
            return Ok(false);
        };
        let all_same_block = block_responses
            .iter()
            .all(|x| x.get_signer_signature_hash() == sighash);
        let all_responded = block_responses.len() == num_signers;
        Ok(all_same_block && all_responded)
    })
    .unwrap();

    TEST_P2P_BROADCAST_STALL.set(false);
    TEST_SKIP_BLOCK_BROADCAST.set(false);

    miners
        .signer_test
        .submit_burn_block_call_and_wait(&miners.sender_sk)
        .expect("Timed out waiting for contract-call");

    miners.submit_commit_miner_1(&sortdb);
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .unwrap();

    let last_active_sortition = get_sortition_info(&conf_1);
    assert!(last_active_sortition.was_sortition);
    miners
        .signer_test
        .submit_burn_block_call_and_wait(&miners.sender_sk)
        .expect("Timed out waiting for contract-call");

    miners.shutdown();
}

#[test]
#[ignore]
fn reorging_signers_capitulate_to_nonreorging_signers_during_tenure_fork() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 5;

    let disallow_reorg_proposal_timeout = Duration::from_secs(10);
    let allow_reorg_proposal_timeout = Duration::from_secs(360);
    let post_btc_block_pause =
        disallow_reorg_proposal_timeout.saturating_add(Duration::from_secs(1));
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |config| {
            config.first_proposal_burn_block_timing = if config.endpoint.port() % 2 == 1 {
                // 2/5 or 40% of signers will allow the reorg
                allow_reorg_proposal_timeout
            } else {
                // 3/5 or 60% of signers will reject the reorg
                disallow_reorg_proposal_timeout
            };
            // don't allow signers to post signed blocks (limits the amount of fault injection we
            // need)
            TEST_SKIP_BLOCK_BROADCAST.set(true);
        },
        |config| {
            config.burnchain.pox_reward_length = Some(30);
            config.miner.tenure_cost_limit_per_block_percentage = None;
            // this test relies on the miner submitting these timed out commits.
            // the test still passes without this override, but the default timeout
            // makes the test take longer than strictly necessary
            config.miner.block_commit_delay = Duration::from_secs(10);
        },
        |_| {},
    );
    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();

    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();

    let allow_reorg_signers: Vec<_> = miners
        .signer_test
        .signer_addresses_versions()
        .iter()
        .enumerate()
        .filter_map(|(i, key)| if i % 2 == 0 { None } else { Some(key.clone()) })
        .collect();
    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        conf_1.is_mainnet(),
        conf_1.burnchain.chain_id,
        &conf_1.get_chainstate_path_str(),
        None,
    )
    .unwrap();
    info!("------------------------- Pause Miner 1's Block Commit -------------------------");

    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Wins Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 1 Mines Another Block -------------------------");
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");

    let tip_a = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    info!("------------------------- Pause Block Proposals -------------------------");
    // For the next tenure, submit the commit op but do not allow any stacks blocks to be broadcasted
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1.clone()]);
    TEST_BLOCK_ANNOUNCE_STALL.set(true);

    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Wins Tenure B -------------------------");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");
    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("----------------- Miner 2 Submits Block Commit for Tenure C Before Any Tenure B Blocks Produced ------------------");
    miners.submit_commit_miner_2(&sortdb);

    let info = get_chain_info(&conf_1);
    info!("----------------------------- Resume Block Production for Tenure B -----------------------------");

    let stacks_height_before = miners.get_peer_stacks_tip_height();
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    let tenure_b_block_proposal = wait_for_block_proposal(
        30,
        stacks_height_before + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for Tenure B block to be proposed");
    info!("Tenure B broadcasted a block. Wait {post_btc_block_pause:?}, issue the next bitcoin block, and un-stall block commits.");
    thread::sleep(post_btc_block_pause);

    // the block will be stored, not processed, so load it out of staging
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
        .expect("Failed to get sortition tip");

    let tenure_b_block = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_tenure_start_blocks(&tip_sn.consensus_hash)
        .unwrap()
        .first()
        .cloned()
        .unwrap();

    // synthesize a StacksHeaderInfo from this unprocessed block
    let tip_b = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(tenure_b_block.header.clone()),
        microblock_tail: None,
        stacks_block_height: tenure_b_block.header.chain_length,
        index_root: TrieHash([0x00; 32]), // we can't know this yet since the block hasn't been processed
        consensus_hash: tenure_b_block.header.consensus_hash.clone(),
        burn_header_hash: tip_sn.burn_header_hash,
        burn_header_height: tip_sn.block_height as u32,
        burn_header_timestamp: tip_sn.burn_header_timestamp,
        anchored_block_size: tenure_b_block.serialize_to_vec().len() as u64,
        burn_view: Some(tenure_b_block.header.consensus_hash),
        total_tenure_size: 0,
    };

    // Block B was built atop block A
    assert_ne!(tip_b.index_block_hash(), tip_a.index_block_hash());
    assert_eq!(tip_b.stacks_block_height, tip_a.stacks_block_height + 1);
    assert_eq!(
        tenure_b_block.header.parent_block_id,
        tip_a.index_block_hash()
    );
    assert_ne!(tip_b, tip_a);

    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let burn_height_before = chain_tip.block_height;

    // allow B to process, so it'll be distinct from C
    TEST_BLOCK_ANNOUNCE_STALL.set(false);
    wait_for(30, || {
        Ok(get_chain_info(&conf_1).stacks_tip_height > info.stacks_tip_height)
    })
    .expect("Failed to announce block");

    let info = get_chain_info(&conf_1);
    info!("--------------- Miner 2 Wins Tenure C With Old Block Commit ----------------");
    info!("Prevent Miner 1 from extending at first");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1.clone()]);

    miners.signer_test.running_nodes.test_observer.clear();
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Failed to mine bitcoin block");
    // assure we have a successful sortition that miner 2
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    // Note tenure C block will attempt to reorg the prior miner so its expected height should be the same as prior to block B processing.
    let tenure_c_block_proposal = wait_for_block_proposal(
        30,
        tip_b.stacks_block_height,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for miner 2's Tenure C block");

    assert_ne!(tenure_c_block_proposal, tenure_b_block_proposal);

    let tip_c = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

    assert_eq!(
        tip_b.index_block_hash(),
        tip_c.get_canonical_stacks_block_id()
    );
    assert_ne!(tip_c.consensus_hash, tip_a.consensus_hash);
    assert_ne!(tip_c.burn_header_hash, tip_a.burn_header_hash);
    assert_eq!(tip_c.block_height, burn_height_before + 1);

    info!("--------------- Waiting for {} Signers to Capitulate to Miner {miner_pkh_1} with tenure id {} ----------------",  allow_reorg_signers.len(), info.pox_consensus);
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &info.pox_consensus,
        &allow_reorg_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to update signer state machines");
    info!("--------------- Miner 1 Extends Tenure B over Tenure C ---------------");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);
    let _tenure_extend_block = wait_for_block_pushed_by_miner_key(
        30,
        tip_b.stacks_block_height + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to mine miner 1's tenure extend block");

    info!("------------------------- Miner 1 Mines Another Block -------------------------");
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");

    info!("------------------------- Miner 2 Mines the Next Tenure -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");

    // assure we have a successful sortition that miner 2 won and it had a block found tenure change
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    miners.shutdown();

    // Block C was built AFTER Block B was built, but BEFORE it was broadcasted, so it should be built off of Block A
    assert_eq!(
        tenure_c_block_proposal.header.parent_block_id,
        tip_a.index_block_hash()
    );
}

/// Test a scenario where:
/// Two miners boot to Nakamoto.
/// Sortition occurs. Miner 1 wins.
/// Miner 1 proposes a block N
/// Signers accept and the stacks tip advances to N
/// Miner 1's block commits are paused so it cannot confirm the next tenure.
/// Sortition occurs. Miner 2 wins.
/// Miner 2 successfully mines blocks N+1
/// Miner 1 wins the next sortition, with its block commit not confirming the last tenure.
/// Miner 1 proposes block N+1'
/// 3 signers approve N+1', saying "Miner is not building off of most recent tenure. A tenure they
///   reorg has already mined blocks, but the block was poorly timed, allowing the reorg."
/// The other 3 signers reject N+1', because their `first_proposal_burn_block_timing_secs` is
///   shorter and has been exceeded.
/// Miner 1 proposes N+1' again, and all signers reject it this time.
/// Miner 2 proposes N+2, a tenure extend block and it is accepted by all signers.
#[test]
#[ignore]
fn mark_miner_as_invalid_if_reorg_is_rejected_v1() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    info!("------------------------- Test Setup -------------------------");

    let num_signers = 5;
    let num_txs = 3;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            // Lets make sure we never time out since we need to stall some things to force our scenario
            signer_config.block_proposal_validation_timeout = Duration::from_secs(1800);
            signer_config.tenure_last_block_proposal_timeout = Duration::from_secs(1800);
            signer_config.capitulate_miner_view_timeout = Duration::from_secs(1800);
            if signer_config.endpoint.port() % 2 == 0 {
                // Even signers will allow a reorg for a long time
                signer_config.first_proposal_burn_block_timing = Duration::from_secs(1800);
            } else {
                // Odd signers will not allow a reorg at all
                signer_config.first_proposal_burn_block_timing = Duration::from_secs(0);
            }
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );
    let all_signers = miners.signer_test.signer_test_pks();
    // Pin all the signers to version 1;
    let pinned_signers = all_signers.iter().map(|key| (key.clone(), 1)).collect();
    TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION.set(pinned_signers);
    let mut approving_signers = vec![];
    let mut rejecting_signers = vec![];
    for (i, signer_config) in miners.signer_test.signer_configs.iter().enumerate() {
        let public_key = all_signers[i].clone();
        if signer_config.endpoint.port() % 2 == 0 {
            // Even signers will allow a reorg for a long time
            approving_signers.push(public_key);
        } else {
            // Odd signers will not allow a reorg at all
            rejecting_signers.push(public_key);
        }
    }
    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commits -------------------------");
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Nakamoto Block N -------------------------");
    let info_before = get_chain_info(&conf_1);
    // Because rl1 is not submitting commits, we cannot use mine_nakamoto_block (commit will never advance)
    next_block_and(&miners.btc_regtest_controller_mut(), 30, || {
        let chain_info = get_chain_info(&conf_1);
        Ok(chain_info.stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for block");

    verify_sortition_winner(&sortdb, &miner_pkh_1);

    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N");
    let block_n_height = block_n.header.chain_length;
    info!("Block N: {block_n_height}");

    let info_after = get_chain_info(&conf_1);
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );
    assert_eq!(info_after.stacks_tip_height, block_n_height);

    info!("------------------------- Miner 2 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Pause Miner 2's Block Mining -------------------------");
    fault_injection_stall_miner();

    info!("------------------------- Mine 2 wins the Next Tenure -------------------------");
    miners.signer_test.mine_bitcoin_block();
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    miners.signer_test.check_signer_states_normal();

    info!("------------------------- Miner 1 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 2 Mines Block N+1 -------------------------");
    fault_injection_unstall_miner();

    let block_n_1 = wait_for_block_pushed_by_miner_key(
        30,
        block_n_height + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N+1");

    let info_after = get_chain_info(&conf_1);
    assert_eq!(info_after.stacks_tip_height, block_n_height + 1);
    assert_eq!(info_after.stacks_tip, block_n_1.header.block_hash());

    // Wait for both chains to be in sync
    miners.wait_for_chains(30);

    info!("------------------------- Miner 1 Wins the Next Tenure, Mines N+1' -------------------------");
    miners.signer_test.running_nodes.test_observer.clear();
    miners.signer_test.mine_bitcoin_block();

    let block_n_1_prime = wait_for_block_proposal(
        30,
        block_n_height + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block proposal N+1'");
    // Stall the miner from proposing again until we're ready
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1.clone()]);
    miners
        .signer_test
        .check_signer_states_reorg(&approving_signers, &rejecting_signers);

    let signer_signature_hash = block_n_1_prime.header.signer_signature_hash();
    info!("------------------------- Wait for 3 acceptances and 2 rejections of {signer_signature_hash} -------------------------");
    let rejections = wait_for_block_rejections_from_signers(
        30,
        &signer_signature_hash,
        &rejecting_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block rejection from rejecting signers");
    for rejection in rejections {
        assert_eq!(
            rejection.response_data.reject_reason,
            RejectReason::ReorgNotAllowed,
            "Reject reason is not ReorgNotAllowed"
        );
    }
    wait_for_block_pre_commits_from_signers(
        30,
        &signer_signature_hash,
        &approving_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block pre-commits from approving signers");

    info!("------------------------- Miner 1 Proposes N+1' Again -------------------------");
    miners.signer_test.running_nodes.test_observer.clear();
    // Allow the miner to propose again
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);
    let block_n_1_prime = wait_for_block_proposal(
        30,
        block_n_height + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to propose block N+1' again");

    info!("------------------------- Wait for 5 rejections -------------------------");

    let signer_signature_hash = block_n_1_prime.header.signer_signature_hash();
    let rejections = wait_for_block_rejections_from_signers(
        30,
        &signer_signature_hash,
        &all_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block rejection from all signers");
    for rejection in rejections {
        assert!(
            rejection.response_data.reject_reason == RejectReason::ReorgNotAllowed
                || rejection.response_data.reject_reason == RejectReason::InvalidMiner
        );
    }
    miners.shutdown();
}

#[test]
#[ignore]
// Test two nakamoto miners, with the signer set split between them.
//  One of the miners (run-loop-2) is prevented from submitting "good" block commits
//  using the "commit stall" test flag in combination with "block broadcast stalls".
//  (Because RL2 isn't able to RBF their initial commits after the tip is broadcasted).
// This test works by tracking two different scenarios:
//   1. RL2 must win a sortition that this block commit behavior would lead to a fork in.
//   2. After such a sortition, RL1 must win another block.
// The test asserts that every nakamoto sortition either has a successful tenure, or if
//  RL2 wins and they would be expected to fork, no blocks are produced. The test asserts
//  that every block produced increments the chain length.
fn miner_forking() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let first_proposal_burn_block_timing = 1;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        5,
        0,
        |signer_config| {
            // we're deliberately stalling proposals: don't punish this in this test!
            signer_config.block_proposal_timeout = Duration::from_secs(240);
            // make sure that we don't allow forking due to burn block timing
            signer_config.first_proposal_burn_block_timing =
                Duration::from_secs(first_proposal_burn_block_timing);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let (conf_1, conf_2) = miners.get_node_configs();
    let (mining_pk_1, mining_pk_2) = miners.get_miner_public_keys();
    let (mining_pkh_1, mining_pkh_2) = miners.get_miner_public_key_hashes();

    let skip_commit_op_rl1 = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let skip_commit_op_rl2 = miners.rl2_counters.naka_skip_commit_op.clone();

    // Make sure that the first miner wins the first sortition.
    info!("Pausing miner 2's block commit submissions");
    skip_commit_op_rl2.set(true);
    miners.boot_to_epoch_3();

    let sortdb = conf_1.get_burnchain().open_sortition_db(true).unwrap();
    let nakamoto_blocks_count_before =
        get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer).len();
    let pre_nakamoto_peer_1_height = get_chain_info(&conf_1).stacks_tip_height;

    info!("------------------------- RL1 Wins Sortition -------------------------");
    info!("Pausing stacks block proposal to force an empty tenure commit from RL2");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![mining_pk_1.clone(), mining_pk_2.clone()]);

    info!("Pausing commits from RL1");
    skip_commit_op_rl1.set(true);

    info!("Mine RL1 Tenure");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block.");
    miners.wait_for_chains(120);

    miners.signer_test.check_signer_states_normal();
    // make sure the tenure was won by RL1
    verify_sortition_winner(&sortdb, &mining_pkh_1);
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

    info!(
        "------------------------- RL2 Wins Sortition With Outdated View -------------------------"
    );
    miners.submit_commit_miner_2(&sortdb);

    // unblock block mining
    let blocks_len = miners
        .signer_test
        .running_nodes
        .test_observer
        .get_blocks()
        .len();
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    // Wait for the block to be broadcasted and processed
    wait_for(30, || {
        Ok(miners
            .signer_test
            .running_nodes
            .test_observer
            .get_blocks()
            .len()
            > blocks_len)
    })
    .expect("Timed out waiting for a block to be processed");

    // sleep for 2*first_proposal_burn_block_timing to prevent the block timing from allowing a fork by the signer set
    thread::sleep(Duration::from_secs(first_proposal_burn_block_timing * 2));

    let nakamoto_headers: HashMap<_, _> = get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer)
    .into_iter()
    .map(|header| {
        info!("Nakamoto block"; "height" => header.stacks_block_height, "consensus_hash" => %header.consensus_hash, "last_sortition_hash" => %tip.consensus_hash);
        (header.consensus_hash.clone(), header)
    })
    .collect();

    let header_info = nakamoto_headers.get(&tip.consensus_hash).unwrap();
    let header = header_info
        .anchored_header
        .as_stacks_nakamoto()
        .unwrap()
        .clone();

    mining_pk_1
        .verify(
            header.miner_signature_hash().as_bytes(),
            &header.miner_signature,
        )
        .unwrap();

    info!("Mine RL2 Tenure");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::Extended, 60)
        .expect("Failed to mine BTC block followed by tenure change tx.");
    miners
        .signer_test
        .check_signer_states_reorg(&[], &miners.signer_test.signer_test_pks());
    miners.wait_for_chains(120);
    // fetch the current sortition info
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    // make sure the tenure was won by RL2
    verify_sortition_winner(&sortdb, &mining_pkh_2);

    let header_info =
        get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer)
            .into_iter()
            .last()
            .unwrap();
    let header = header_info
        .anchored_header
        .as_stacks_nakamoto()
        .unwrap()
        .clone();

    mining_pk_1
        .verify(
            header.miner_signature_hash().as_bytes(),
            &header.miner_signature,
        )
        .expect("RL1 did not produce our last block");

    let nakamoto_headers: HashMap<_, _> = get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer)
        .into_iter()
        .map(|header| {
            info!("Nakamoto block"; "height" => header.stacks_block_height, "consensus_hash" => %header.consensus_hash, "last_sortition_hash" => %tip.consensus_hash);
            (header.consensus_hash.clone(), header)
        })
        .collect();

    assert!(
        !nakamoto_headers.contains_key(&tip.consensus_hash),
        "RL1 produced a block with the current consensus hash."
    );

    info!("------------------------- RL1 RBFs its Own Commit -------------------------");
    info!("Pausing stacks block proposal to test RBF capability");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![mining_pk_1.clone(), mining_pk_2.clone()]);
    miners.submit_commit_miner_1(&sortdb);

    info!("Mine RL1 Tenure");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Failed to mine BTC block.");
    miners
        .signer_test
        .check_signer_states_reorg(&miners.signer_test.signer_test_pks(), &[]);
    miners.submit_commit_miner_1(&sortdb);
    // unblock block mining
    let blocks_len = miners
        .signer_test
        .running_nodes
        .test_observer
        .get_blocks()
        .len();
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    // Wait for the block to be broadcasted and processed
    wait_for(30, || {
        Ok(miners
            .signer_test
            .running_nodes
            .test_observer
            .get_blocks()
            .len()
            > blocks_len)
    })
    .expect("Timed out waiting for a block to be processed");

    info!("Ensure that RL1 performs an RBF after unblocking block broadcast");
    miners.submit_commit_miner_1(&sortdb);

    info!("Mine RL1 Tenure");
    miners
        .mine_bitcoin_blocks_and_confirm_with_test_observer(&sortdb, 1, 60)
        .expect("Failed to mine BTC block.");
    miners.signer_test.check_signer_states_normal();
    // fetch the current sortition info
    miners.wait_for_chains(120);
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    // make sure the tenure was won by RL1
    verify_sortition_winner(&sortdb, &mining_pkh_1);

    let nakamoto_headers: HashMap<_, _> = get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer)
        .into_iter()
        .map(|header| {
            info!("Nakamoto block"; "height" => header.stacks_block_height, "consensus_hash" => %header.consensus_hash, "last_sortition_hash" => %tip.consensus_hash);
            (header.consensus_hash.clone(), header)
        })
        .collect();

    let header_info = nakamoto_headers.get(&tip.consensus_hash).unwrap();
    let header = header_info
        .anchored_header
        .as_stacks_nakamoto()
        .unwrap()
        .clone();

    mining_pk_1
        .verify(
            header.miner_signature_hash().as_bytes(),
            &header.miner_signature,
        )
        .unwrap();

    info!("------------------------- Verify Peer Data -------------------------");

    let peer_1_height = get_chain_info(&conf_1).stacks_tip_height;
    let peer_2_height = get_chain_info(&conf_2).stacks_tip_height;
    let nakamoto_blocks_count =
        get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer).len();
    info!("Peer height information"; "peer_1" => peer_1_height, "peer_2" => peer_2_height, "pre_naka_height" => pre_nakamoto_peer_1_height);
    info!("Nakamoto blocks count before test: {nakamoto_blocks_count_before}, Nakamoto blocks count now: {nakamoto_blocks_count}");
    assert_eq!(peer_1_height, peer_2_height);

    let nakamoto_blocks_count =
        get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer).len();

    assert_eq!(
        peer_1_height - pre_nakamoto_peer_1_height,
        u64::try_from(nakamoto_blocks_count - nakamoto_blocks_count_before).unwrap(), // subtract 1 for the first Nakamoto block
        "There should be no forks in this test"
    );

    miners.shutdown();
}

#[test]
#[ignore]
fn revalidate_unknown_parent() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let max_nakamoto_tenures = 30;
    let inter_blocks_per_tenure = 5;

    // setup sender + recipient for a test stx transfer
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");

    // All signers are listening to node 1
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(
            sender_addr.clone(),
            (send_amt + send_fee) * max_nakamoto_tenures * inter_blocks_per_tenure,
        )],
        |signer_config| {
            signer_config.node_host = node_1_rpc_bind.clone();
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(0);
            // rely on actually checking that the block is processed
            signer_config.proposal_wait_for_parent_time = Duration::from_secs(600);
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.node.pox_sync_sample_secs = 30;
            config.miner.block_commit_delay = Duration::from_secs(0);

            config.node.seed = btc_miner_1_seed.clone();
            config.node.local_peer_seed = btc_miner_1_seed.clone();
            config.burnchain.local_mining_public_key = Some(btc_miner_1_pk.to_hex());
            config.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[1]));

            // Increase the reward cycle length to avoid missing a prepare phase
            // while we are intentionally forking.
            config.burnchain.pox_reward_length = Some(40);
            config.burnchain.pox_prepare_length = Some(10);

            // Move epoch 2.5 and 3.0 earlier, so we have more time for the
            // test before re-stacking is required.
            if let Some(epochs) = config.burnchain.epochs.as_mut() {
                epochs[StacksEpochId::Epoch24].end_height = 131;
                epochs[StacksEpochId::Epoch25].start_height = 131;
                epochs[StacksEpochId::Epoch25].end_height = 166;
                epochs[StacksEpochId::Epoch30].start_height = 166;
            } else {
                panic!("Expected epochs to be set");
            }
        },
        Some(vec![btc_miner_1_pk.clone(), btc_miner_2_pk.clone()]),
        None,
    );

    let conf = signer_test.running_nodes.conf.clone();
    let mut conf_node_2 = conf.clone();
    conf_node_2.node.rpc_bind = format!("{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.seed = btc_miner_2_seed.clone();
    conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
    conf_node_2.node.local_peer_seed = btc_miner_2_seed;
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let mining_pk_1 = StacksPublicKey::from_private(&conf.miner.mining_key.clone().unwrap());
    let mining_pk_2 = StacksPublicKey::from_private(&conf_node_2.miner.mining_key.clone().unwrap());
    let mining_pkh_1 = Hash160::from_node_public_key(&mining_pk_1);
    let mining_pkh_2 = Hash160::from_node_public_key(&mining_pk_2);
    debug!("The mining key for miner 1 is {mining_pkh_1}");
    debug!("The mining key for miner 2 is {mining_pkh_2}");

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let rl2_coord_channels = run_loop_2.coordinator_channels();
    let run_loop_stopper_2 = run_loop_2.get_termination_switch();
    let Counters {
        naka_skip_commit_op: rl2_skip_commit_op,
        ..
    } = run_loop_2.counters();
    let rl2_counters = run_loop_2.counters();
    let rl1_counters = signer_test.running_nodes.counters.clone();

    signer_test.boot_to_epoch_3();

    // Pause block commits from miner 2 to make sure
    //  miner 1 wins the first block
    rl2_skip_commit_op.set(true);

    let run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    wait_for(200, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for follower to catch up to the miner");

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    let rl1_skip_commit_op = signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();

    let sortdb = SortitionDB::open(
        &conf.get_burn_db_file_path(),
        false,
        conf.get_burnchain().pox_constants,
    )
    .unwrap();

    info!("-------- Waiting miner 2 to catch up to miner 1 --------");

    // Wait for miner 2 to catch up to miner 1
    // (note: use a high timeout to avoid potential failing on github workflow)
    wait_for(600, || {
        let info_1 = get_chain_info(&conf);
        let info_2 = get_chain_info(&conf_node_2);
        Ok(info_1.stacks_tip_height == info_2.stacks_tip_height)
    })
    .expect("Timed out waiting for miner 2 to catch up to miner 1");

    info!("-------- Miner 2 caught up to miner 1 --------");

    let info_before = get_chain_info(&conf);

    info!("-------- Miner 1 starting next tenure --------");

    wait_for(60, || {
        Ok(rl1_counters.naka_submitted_commit_last_burn_height.get()
            >= info_before.burn_block_height)
    })
    .unwrap();
    info!("-------- Blocking Miner 1 so that Miner 2 will win the next next tenure --------");
    rl1_skip_commit_op.set(true);

    // Mine the first block
    signer_test.mine_bitcoin_block();
    signer_test.check_signer_states_normal();

    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_1.clone()));

    info!("------- Unblocking Miner 2 ------");
    rl2_skip_commit_op.set(false);
    wait_for(60, || {
        Ok(rl2_counters.naka_submitted_commit_last_burn_height.get()
            > info_before.burn_block_height
            && rl2_counters.naka_submitted_commit_last_stacks_tip.get()
                > info_before.stacks_tip_height)
    })
    .unwrap();
    let peer_info_before = signer_test.get_peer_info();
    info!("------- Miner 2 wins first tenure ------");
    signer_test.mine_bitcoin_block();
    signer_test.check_signer_states_normal();
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_2.clone()));

    // Setup miner 1 to ignore a block in this tenure
    let ignore_block = peer_info_before.stacks_tip_height + 2;
    set_ignore_block(ignore_block, &conf.node.working_dir);

    // wait for the tenure to start (i.e., the tenure change block to be produced,
    //  which should be mined and not ignored)
    wait_for(60, || {
        Ok(signer_test.get_peer_info().stacks_tip_height == ignore_block - 1)
    })
    .unwrap();

    info!(
        "Mining 1st interim block in Miner 2's first tenure";
    );

    let (_, sender_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    wait_for(60, || {
        let http_origin = &conf_node_2.node.data_url;
        Ok(get_account(http_origin, &sender_addr).nonce > sender_nonce)
    })
    .unwrap();

    // should not have updated yet in node 1
    assert_eq!(get_account(&http_origin, &sender_addr).nonce, sender_nonce);

    info!(
        "Mining 2nd interim block in Miner 2's first tenure";
    );

    let sender_nonce = get_account(&conf_node_2.node.data_url, &sender_addr).nonce;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );

    // should be no pending proposals yet.
    signer_test
        .get_all_states()
        .iter()
        .for_each(|state| assert_eq!(state.pending_proposals_count, 0));

    submit_tx_fallible(&http_origin, &transfer_tx).unwrap();

    wait_for(60, || {
        Ok(signer_test.get_all_states().iter().all(|state| {
            info!(
                "State: pending_proposal_count = {}",
                state.pending_proposals_count
            );
            state.pending_proposals_count == 1
        }))
    })
    .unwrap();

    // sleep to make sure that the pending proposal isn't just temporarily pending
    thread::sleep(Duration::from_secs(5));

    signer_test
        .get_all_states()
        .iter()
        .for_each(|state| assert_eq!(state.pending_proposals_count, 1));
    assert_eq!(
        get_account(&http_origin, &sender_addr).nonce,
        sender_nonce - 1
    );

    // clear the block ignore and make sure that the proposal gets processed by miner 1
    clear_ignore_block();

    wait_for(60, || {
        Ok(get_account(&http_origin, &sender_addr).nonce > sender_nonce)
    })
    .unwrap();

    rl2_coord_channels
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper_2.store(false, Ordering::SeqCst);
    run_loop_2_thread.join().unwrap();
    signer_test.shutdown();
}

/// Test scenario:
///
/// - Miner A proposes a block in tenure A
/// - While that block is pending validation,
///   Miner B proposes a new block in tenure B
/// - After A's block is validated, Miner B's block is
///   rejected (because it's a sister block)
/// - Miner B retries and successfully mines a block
#[test]
#[ignore]
fn new_tenure_while_validating_previous_scenario() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let timeout = Duration::from_secs(30);
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_| {},
        |_| {},
        None,
        None,
    );
    let db_path = signer_test.signer_configs[0].db_path.clone();
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    info!("----- Starting test -----";
        "db_path" => db_path.clone().to_str(),
    );
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers, true);
    TEST_VALIDATE_DELAY_DURATION_SECS.set(30);

    let proposals_before = signer_test.get_miner_proposal_messages().len();

    let peer_info_before_stall = signer_test.get_peer_info();
    let burn_height_before_stall = peer_info_before_stall.burn_block_height;
    let stacks_height_before_stall = peer_info_before_stall.stacks_tip_height;

    // STEP 1: Miner A proposes a block in tenure A

    // submit a tx so that the miner will attempt to mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("----- Waiting for miner to propose a block -----");

    // Wait for the miner to propose a block
    wait_for(30, || {
        Ok(signer_test.get_miner_proposal_messages().len() > proposals_before)
    })
    .expect("Timed out waiting for miner to propose a block");

    let proposals_before = signer_test.get_miner_proposal_messages().len();
    let info_before = signer_test.get_peer_info();

    // STEP 2: Miner B proposes a block in tenure B, while A's block is pending validation

    info!("----- Mining a new BTC block -----");
    TEST_MINE_SKIP.set(true);
    signer_test.mine_bitcoin_block();

    let info = signer_test.get_peer_info();
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &info.pox_consensus,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to update signer states");
    info!("----- Attempting to Mine a Sister Block -----");
    TEST_MINE_SKIP.set(false);

    let mut last_log = Instant::now();
    last_log -= Duration::from_secs(5);
    let mut new_block_hash = None;
    wait_for(120, || {
        let proposals = signer_test.get_miner_proposal_messages();
        let new_proposal = proposals.iter().find(|p| {
            p.burn_height > burn_height_before_stall
                && p.block.header.chain_length == info_before.stacks_tip_height + 1
        });

        let has_new_proposal = new_proposal.is_some() && proposals.len() > proposals_before;
        if last_log.elapsed() > Duration::from_secs(5) && !has_new_proposal {
            info!(
                "----- Waiting for a new proposal -----";
                "proposals_len" => proposals.len(),
                "burn_height_before" => info_before.burn_block_height,
            );
            last_log = Instant::now();
        }
        if let Some(proposal) = new_proposal {
            new_block_hash = Some(proposal.block.header.signer_signature_hash());
        }
        Ok(has_new_proposal)
    })
    .expect("Timed out waiting for pending block proposal");

    info!("----- Waiting for pending block validation to be submitted -----");
    let new_block_hash = new_block_hash.unwrap();

    // Set the delay to 0 so that the block validation finishes quickly
    TEST_VALIDATE_DELAY_DURATION_SECS.set(0);

    wait_for(30, || {
        let proposal_responses = signer_test
            .running_nodes
            .test_observer
            .get_proposal_responses();
        let found_proposal = proposal_responses
            .iter()
            .any(|p| p.signer_signature_hash() == &new_block_hash);
        Ok(found_proposal)
    })
    .expect("Timed out waiting for pending block validation to be submitted");

    // STEP 3: Miner B is rejected, retries, and mines a block
    info!("----- Mining BlockFound -----");
    // Now, wait for miner B to propose a new block
    let block_pushed = wait_for_block_pushed_by_miner_key(
        30,
        stacks_height_before_stall + 2,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+2 to be mined");
    // Ensure that we didn't tenure extend
    assert!(block_pushed
        .try_get_tenure_change_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::BlockFound));
    let peer_info = signer_test.get_peer_info();
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before_stall + 2);
    assert_eq!(peer_info.stacks_tip, block_pushed.header.block_hash());

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}

/// Test a scenario where:
/// Two miners boot to Nakamoto (first miner has max_execution_time set to 0).
/// Sortition occurs. Miner 1 wins.
/// Miner 1 successfully mines block N with contract-publish
/// Miner 1 successfully mines block N+1 with transfer and a contract-call that gets rejected (by max_execution_time)
/// Miner 1 successfully mines block N+2 with transfer tx (this is mainly for ensuring everything still works after the expiration time)
/// Sortition occurs. Miner 2 wins.
/// Miner 2 successfully mines block N+3 including the contract-call previously rejected by miner 1
/// Ensures both the miners are aligned
#[test]
#[ignore]
fn miner_rejection_by_contract_call_execution_time_expired() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 3;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            // Lets make sure we never time out since we need to stall some things to force our scenario
            signer_config.block_proposal_validation_timeout = Duration::from_secs(1800);
            signer_config.tenure_last_block_proposal_timeout = Duration::from_secs(1800);
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(1800);
        },
        |config| config.miner.max_execution_time_secs = Some(0),
        |config| config.miner.max_execution_time_secs = None,
    );
    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (_miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commits -------------------------");
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Nakamoto Block N -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by Block N");

    miners.wait_for_test_observer_blocks(60);

    // First, lets deploy the contract
    let dummy_contract_src = "(define-public (dummy (number uint)) (begin (ok (+ number u1))))";

    let sender_nonce = 0;

    let _ = miners
        .send_and_mine_contract_publish(sender_nonce, "dummy-contract", dummy_contract_src, 60)
        .expect("Failed to publish contract in a new block");

    info!("------------------------- Miner 1 Mines a Nakamoto Block N+1 -------------------------");

    let stacks_height_before = miners.get_peer_stacks_tip_height();

    let (tx1, sender_nonce) = miners.send_transfer_tx();

    // try calling the contract (has to fail)
    let contract_call_txid = miners.send_contract_call(
        sender_nonce + 1,
        "dummy-contract",
        "dummy",
        &[clarity::vm::Value::UInt(1)],
    );

    let _ = wait_for(60, || {
        Ok(miners.get_peer_stacks_tip_height() > stacks_height_before)
    });

    miners.wait_for_test_observer_blocks(60);

    assert_eq!(
        last_block_contains_txid(&tx1, &miners.signer_test.running_nodes.test_observer),
        true
    );
    assert_eq!(
        last_block_contains_txid(
            &contract_call_txid,
            &miners.signer_test.running_nodes.test_observer
        ),
        false
    );

    info!("------------------------- Miner 1 Mines a Nakamoto Block N+2 -------------------------");

    let tx2 = miners
        .send_and_mine_transfer_tx(60)
        .expect("Failed to mine N + 2");

    miners.wait_for_test_observer_blocks(60);

    assert_eq!(
        last_block_contains_txid(&tx2, &miners.signer_test.running_nodes.test_observer),
        true
    );

    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 2 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Mine Tenure -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by Block N+3");

    info!("------------------------- Miner 2 Mines Block N+3 -------------------------");

    let stacks_height_before = miners.get_peer_stacks_tip_height();

    let contract_call_txid = miners.send_contract_call(
        sender_nonce + 2,
        "dummy-contract",
        "dummy",
        &[clarity::vm::Value::UInt(1)],
    );

    let _ = wait_for_block_pushed_by_miner_key(
        30,
        stacks_height_before + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block N+3");

    miners.wait_for_test_observer_blocks(60);

    assert_eq!(
        last_block_contains_txid(
            &contract_call_txid,
            &miners.signer_test.running_nodes.test_observer
        ),
        true
    );

    verify_sortition_winner(&sortdb, &miner_pkh_2);

    // ensure both miners are aligned
    miners.wait_for_chains(60);

    info!("------------------------- Shutdown -------------------------");
    miners.shutdown();
}

/// Test a scenario where:
/// Two miners boot to Nakamoto (first miner has max_execution_time set to 0).
/// Sortition occurs. Miner 1 wins.
/// Miner 1 fails to mine block N with contract-publish
/// Sortition occurs. Miner 2 wins.
/// Miner 2 successfully mines block N including the contract-publish previously rejected by miner 1
/// Ensures both the miners are aligned
#[test]
#[ignore]
fn miner_rejection_by_contract_publish_execution_time_expired() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 3;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            // Lets make sure we never time out since we need to stall some things to force our scenario
            signer_config.block_proposal_validation_timeout = Duration::from_secs(1800);
            signer_config.tenure_last_block_proposal_timeout = Duration::from_secs(1800);
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(1800);
        },
        |config| config.miner.max_execution_time_secs = Some(0),
        |config| config.miner.max_execution_time_secs = None,
    );
    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (_miner_pk_1, _) = miners.get_miner_public_keys();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commits -------------------------");
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Nakamoto Block N -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by Block N");

    miners.wait_for_test_observer_blocks(60);

    // First, lets deploy the contract
    let dummy_contract_src =
        "(define-public (dummy (number uint)) (begin (ok (+ number u1))))(+ 1 1)";

    let (tx1, sender_nonce) = miners.send_transfer_tx();

    let _ = miners
        .send_and_mine_contract_publish(sender_nonce + 1, "dummy-contract", dummy_contract_src, 60)
        .expect_err("Expected an error while publishing contract in a new block");

    assert_eq!(
        last_block_contains_txid(&tx1, &miners.signer_test.running_nodes.test_observer),
        true
    );

    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 2 Submits a Block Commit -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Mine Tenure -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by Block N+3");

    info!("------------------------- Miner 2 Mines Block N+1 -------------------------");

    let _ = miners
        .send_and_mine_contract_publish(sender_nonce + 1, "dummy-contract", dummy_contract_src, 60)
        .expect("Failed to publish contract in a new block");

    verify_sortition_winner(&sortdb, &miner_pkh_2);

    // ensure both miners are aligned
    miners.wait_for_chains(60);

    info!("------------------------- Shutdown -------------------------");
    miners.shutdown();
}
