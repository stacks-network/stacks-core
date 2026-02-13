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
use std::env;
use std::sync::atomic::Ordering;
use std::time::Duration;

use libsigner::v0::messages::RejectReason;
use libsigner::StacksBlockEvent;
use reqwest::header::AUTHORIZATION;
use stacks::burnchains::Txid;
use stacks::chainstate::burn::operations::{BlockstackOperationType, PreStxOp, TransferStxOp};
use stacks::chainstate::stacks::miner::TEST_EXCLUDE_REPLAY_TXS;
use stacks::chainstate::stacks::{TenureChangeCause, TenureChangePayload, TransactionPayload};
use stacks::core::test_util::make_big_read_count_contract;
use stacks::core::{StacksEpochId, HELIUM_BLOCK_LIMIT_20};
use stacks::net::api::gettransaction::TransactionResponse;
use stacks::net::api::postblock_proposal::{ValidateRejectCode, TEST_REJECT_REPLAY_TXS};
use stacks::types::chainstate::{BurnchainHeaderHash, StacksPublicKey};
use stacks::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_signer::v0::signer_state::TEST_IGNORE_BITCOIN_FORK_PUBKEYS;
use stacks_signer::v0::SpawnedSigner;

use super::{SignerTest, *};
use crate::nakamoto_node::miner::{fault_injection_stall_miner, fault_injection_unstall_miner};
use crate::operations::BurnchainOpSigner;
use crate::tests::nakamoto_integrations::{next_block_and, wait_for};
use crate::tests::neon_integrations::{
    get_account, get_chain_info, test_observer, wait_for_tenure_change_tx,
};
use crate::tests::{self};
use crate::{BitcoinRegtestController, BurnchainController, Keychain};
#[test]
#[ignore]
/// Trigger a Bitcoin fork and ensure that the signer
/// both detects the fork and moves into a tx replay state
///
/// The test flow is:
///
/// - Mine 10 tenures after epoch 3
/// - Include a STX transfer in the 10th tenure
/// - Trigger a Bitcoin fork (3 blocks)
/// - Verify that the signer moves into tx replay state
/// - Verify that the signer correctly includes the stx transfer
///   in the tx replay set
///
/// Then, a second fork scenario is tested, which
/// includes multiple txs across multiple tenures.
fn tx_replay_forking_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let deploy_fee = 1000000;
    let call_fee = 1000;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(
                sender_addr.clone(),
                (send_amt + send_fee) * 10 + deploy_fee + call_fee,
            )],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let stacks_miner_pk = StacksPublicKey::from_private(&conf.miner.mining_key.clone().unwrap());

    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 2;

    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    signer_test.check_signer_states_normal();

    let tip = get_chain_info(conf);
    // Make a transfer tx (this will get forked)
    let (txid, _) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    wait_for(30, || {
        let new_tip = get_chain_info(&conf);
        Ok(new_tip.stacks_tip_height > tip.stacks_tip_height)
    })
    .expect("Timed out waiting for transfer tx to be mined");

    let pre_fork_1_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(pre_fork_1_nonce, 1);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");

    let tip_before = signer_test.get_peer_info();
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");

    signer_test.wait_for_replay_set_eq(30, vec![txid.clone()]);

    btc_controller.build_next_block(1);
    wait_for(30, || {
        let tip = signer_test.get_peer_info();
        Ok(tip.stacks_tip_height < tip_before.stacks_tip_height)
    })
    .expect("Timed out waiting for stacks tip to decrease");

    let post_fork_1_nonce = get_account(&http_origin, &sender_addr).nonce;

    signer_test.wait_for_replay_set_eq(30, vec![txid.clone()]);

    // We should have forked 1 tx
    assert_eq!(post_fork_1_nonce, pre_fork_1_nonce - 1);

    fault_injection_unstall_miner();

    // Now, wait for the tx replay set to be cleared
    signer_test
        .wait_for_signer_state_check(30, |state| {
            let tx_replay_set = state.get_tx_replay_set();
            Ok(tx_replay_set.is_none())
        })
        .expect("Timed out waiting for tx replay set to be cleared");

    // Now, we'll trigger another fork, with more txs, across tenures

    // The forked blocks are:
    // Tenure 1:
    // - Block with stx transfer
    // Tenure 2:
    // - Block with contract deploy
    // - Block with contract call

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let pre_fork_2_tip = get_chain_info(&conf);

    let contract_code = "
    (define-public (call-fn)
      (ok true)
    )
    ";
    let contract_name = "test-contract";

    let (transfer_txid, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit transfer tx");
    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .expect("Failed to wait for nonce increase");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let (contract_deploy_txid, deploy_nonce) = signer_test
        .submit_contract_deploy(&sender_sk, deploy_fee, contract_code, contract_name)
        .expect("Failed to submit contract deploy");
    signer_test
        .wait_for_nonce_increase(&sender_addr, deploy_nonce)
        .expect("Failed to wait for nonce increase");

    let (contract_call_txid, contract_call_nonce) = signer_test
        .submit_contract_call(&sender_sk, call_fee, contract_name, "call-fn", &[])
        .expect("Failed to submit contract call");
    signer_test
        .wait_for_nonce_increase(&sender_addr, contract_call_nonce)
        .expect("Failed to wait for nonce increase");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    fault_injection_stall_miner();

    info!("---- Triggering deeper fork ----");

    let tip_before = signer_test.get_peer_info();

    let burn_header_hash_to_fork = btc_controller.get_block_hash(pre_fork_2_tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(4);

    wait_for(30, || {
        let tip = signer_test.get_peer_info();
        Ok(tip.stacks_tip_height < tip_before.stacks_tip_height)
    })
    .expect("Timed out waiting for stacks tip to decrease");

    let expected_tx_replay_txids = vec![transfer_txid, contract_deploy_txid, contract_call_txid];

    signer_test.wait_for_replay_set_eq(30, expected_tx_replay_txids.clone());

    info!("---- Mining post-fork block to clear tx replay set ----");
    let tip_after_fork = get_chain_info(&conf);
    let stacks_height_before = tip_after_fork.stacks_tip_height;

    test_observer::clear();

    fault_injection_unstall_miner();

    let expected_height = stacks_height_before + 2;
    info!(
        "---- Waiting for block pushed at height: {:?} ----",
        expected_height
    );

    let block = wait_for_block_pushed_by_miner_key(60, expected_height, &stacks_miner_pk)
        .expect("Timed out waiting for block pushed after fork");

    info!("---- Block: {:?} ----", block);

    for (block_tx, expected_txid) in block
        .txs
        .iter()
        .filter(|tx| {
            // In this case, the miner issued a tenure extend in the block,
            // because it's continuing a late tenure.
            !matches!(
                tx.payload,
                TransactionPayload::TenureChange(TenureChangePayload {
                    cause: TenureChangeCause::Extended,
                    ..
                })
            )
        })
        .zip(expected_tx_replay_txids.iter())
    {
        assert_eq!(block_tx.txid().to_hex(), *expected_txid);
    }

    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be cleared");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Trigger a Bitcoin fork and ensure that the signer
/// both detects the fork and moves into a tx replay state
/// and causes the miner to mine the appropriate list of
/// transactions in the subsequent blocks
///
/// The test flow is:
///
/// - Mine 10 tenures after epoch 3
/// - Include a STX transfer in the 10th tenure
/// - Trigger a Bitcoin fork (3 blocks)
/// - Verify that the signer moves into tx replay state
/// - Verify that the signer correctly includes the stx transfer
///   in the tx replay set
/// - Force the miner to ignore replay transactions and attempt
///   to mine a regular block
/// - Verify the signers reject this proposed block due to it
///   missing the replay transactions
/// - Allow the miner to consider the replay transactions
/// - Verify the miner correctly constructs a block containing the
///   tx replay set
/// - Verify the signers approve subsequent blocks
fn tx_replay_reject_invalid_proposals_during_replay() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let sender_sk2 = Secp256k1PrivateKey::from_seed("sender_2".as_bytes());
    let sender_addr2 = tests::to_addr(&sender_sk2);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![
                (sender_addr.clone(), send_amt + send_fee),
                (sender_addr2, send_amt + send_fee),
            ],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;

    let stacks_miner_pk = StacksPublicKey::from_private(&conf.miner.mining_key.clone().unwrap());

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 2;

    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    let tip = get_chain_info(&conf);
    // Make a transfer tx (this will get forked)
    let (txid, _) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    wait_for(30, || {
        let new_tip = get_chain_info(&conf);
        Ok(new_tip.stacks_tip_height > tip.stacks_tip_height)
    })
    .expect("Timed out waiting for transfer tx to be mined");

    let pre_fork_1_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(pre_fork_1_nonce, 1);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");

    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");

    signer_test.wait_for_replay_set_eq(30, vec![txid.clone()]);

    let post_fork_1_nonce = get_account(&http_origin, &sender_addr).nonce;

    // We should have forked 1 tx
    assert_eq!(post_fork_1_nonce, pre_fork_1_nonce - 1);

    let tip_after_fork = get_chain_info(&conf);
    let stacks_height_before = tip_after_fork.stacks_tip_height;

    // Make sure the miner skips replay transactions in its considerations
    TEST_EXCLUDE_REPLAY_TXS.set(true);
    let (txid_2, _) = signer_test
        .submit_transfer_tx(&sender_sk2, send_fee, send_amt)
        .unwrap();
    test_observer::clear();
    fault_injection_unstall_miner();
    // First we will get the tenure change block. It shouldn't contain our two transfer transactions.
    info!(
        "---- Waiting for block pushed at height: {:?} ----",
        stacks_height_before + 1
    );
    // This block will just be the tenure change block which signers will approve without issue.
    let block = wait_for_block_pushed_by_miner_key(60, stacks_height_before + 1, &stacks_miner_pk)
        .expect("Timed out waiting for block pushed after fork");
    assert!(!block.txs.iter().any(|tx| tx.txid().to_string() == txid));
    assert!(!block.txs.iter().any(|tx| tx.txid().to_string() == txid_2));
    info!(
        "---- Wait for block proposal at stacks block height {} ----",
        stacks_height_before + 2
    );
    // Next the miner will attempt to propose a block that does not contain the necessary replay tx and signers will reject it
    let rejected_block =
        wait_for_block_proposal_block(30, stacks_height_before + 2, &stacks_miner_pk)
            .expect("Timed out waiting for block proposal after fork");
    assert!(rejected_block
        .txs
        .iter()
        .any(|tx| tx.txid().to_string() == txid_2));
    info!(
        "---- Ensure signers reject block {} due to an invalid transaction replay ----",
        rejected_block.header.signer_signature_hash()
    );
    wait_for_block_global_rejection_with_reject_reason(
        30,
        &rejected_block.header.signer_signature_hash(),
        num_signers,
        Some(RejectReason::ValidationFailed(
            ValidateRejectCode::InvalidTransactionReplay,
        )),
    )
    .expect("Timed out waiting for global block rejection due to invalid transaction replay");
    TEST_EXCLUDE_REPLAY_TXS.set(false);
    info!(
        "---- Wait for block pushed at stacks block height {} ----",
        stacks_height_before + 2
    );
    let accepted_block =
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 2, &stacks_miner_pk)
            .expect("Failed to mine block stacks_height_before + 2");
    info!(
        "---- Ensure signers accept block at height {:?} with a valid transaction replay ----",
        stacks_height_before + 2
    );
    assert!(
        accepted_block
            .txs
            .iter()
            .any(|tx| tx.txid().to_string() == txid),
        "Block should contain a replay tx"
    );
    assert!(
        !accepted_block
            .txs
            .iter()
            .any(|tx| tx.txid().to_string() == txid_2),
        "Block should not contain a non-replay tx"
    );
    info!("---- Ensure signers accept block with non-replay tx ----");
    wait_for(30, || {
        let blocks = test_observer::get_blocks();
        let block = blocks.last().unwrap();
        let block: StacksBlockEvent = serde_json::from_value(block.clone()).unwrap();
        Ok(block
            .transactions
            .iter()
            .any(|tx| tx.txid().to_string() == txid_2))
    })
    .expect("Timed out waiting for a block with a non-replay tx");

    info!("---- Ensure signers cleared the tx replay set ----");
    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be cleared");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Transaction replay test using a stacks-on-bitcoin transaction
/// to demonstrate a replay set that contains an unminable transaction.
///
/// Test scenario:
///
/// - Alice sends STX to Bob in a stacks-on-bitcoin transaction
/// - Bob transfers that STX
/// - A fork occurs, which drops Alice's transaction, meaning
///   Bob no longer has STX
/// - The replay set is validated to contain only Bob's transaction
/// - Since the replay set contains no mineable transactions, the
///   replay set is cleared after an initial TenureChange block
fn tx_replay_btc_on_stx_invalidation() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let mut sender_burnop_signer = BurnchainOpSigner::new(sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient_sk = Secp256k1PrivateKey::from_seed("recipient_1".as_bytes());
    let recipient_addr = tests::to_addr(&recipient_sk);
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |c| {
                c.validate_with_replay_tx = true;
                c.reset_replay_set_after_fork_blocks = 5;
            },
            |node_config| {
                node_config.node.txindex = true;
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );

    let conf = &signer_test.running_nodes.conf;
    let mut miner_keychain = Keychain::default(conf.node.seed.clone()).generate_op_signer();
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let mut btc_controller = BitcoinRegtestController::new(conf.clone(), None);
    let submitted_commits = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Beginning test -------------------------");

    let burnchain = conf.get_burnchain();

    let tip = signer_test.get_peer_info();
    let pox_info = signer_test.get_pox_data();

    info!("---- Burnchain ----";
        // "burnchain" => ?conf.burnchain,
        "pox_constants" => ?burnchain.pox_constants,
        "cycle" => burnchain.pox_constants.reward_cycle_index(0, tip.burn_block_height),
        "pox_info" => ?pox_info,
    );

    info!("Submitting first pre-stx op");
    let pre_stx_op = PreStxOp {
        output: sender_addr.clone(),
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };

    assert!(
        btc_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                BlockstackOperationType::PreStx(pre_stx_op),
                &mut miner_keychain,
            )
            .is_ok(),
        "Pre-stx operation should submit successfully"
    );

    let pre_fork_tenures = 10;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    info!("Submitting transfer STX op");
    let recipient_balance = send_amt + send_fee;
    let transfer_stx_op = TransferStxOp {
        sender: sender_addr,
        recipient: recipient_addr.clone(),
        transfered_ustx: recipient_balance.into(),
        memo: vec![],
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };
    assert!(
        btc_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                BlockstackOperationType::TransferStx(transfer_stx_op),
                &mut sender_burnop_signer
            )
            .is_ok(),
        "Transfer STX operation should submit successfully"
    );

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    wait_for(30, || {
        let account = get_account(&http_origin, &recipient_addr);
        Ok(account.balance == recipient_balance.into())
    })
    .expect("Timed out waiting for balance to be updated");

    info!("---- Submitting transfer STX from recipient ----");

    let (txid, recipient_nonce) = signer_test
        .submit_transfer_tx(&recipient_sk, send_fee, send_amt)
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&recipient_addr, recipient_nonce)
        .expect("Timed out waiting for STX transfer from recipient");

    info!("---- Triggering Bitcoin fork ----");

    let tip = signer_test.get_peer_info();
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height - 2);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(3);

    fault_injection_stall_miner();

    // we need to mine some blocks to get back to being considered a frequent miner
    for i in 0..3 {
        let current_burn_height = get_chain_info(&conf).burn_block_height;
        info!(
            "Mining block #{i} to be considered a frequent miner";
            "current_burn_height" => current_burn_height,
        );
        let commits_count = submitted_commits.load(Ordering::SeqCst);
        next_block_and(&btc_controller, 60, || {
            Ok(submitted_commits.load(Ordering::SeqCst) > commits_count)
        })
        .unwrap();
    }

    info!("---- Wait for tx replay set to be updated ----");

    signer_test
        .wait_for_signer_state_check(30, |state| {
            let Some(tx_replay_set) = state.get_tx_replay_set() else {
                info!("---- No tx replay set");
                return Ok(false);
            };
            let len_ok = tx_replay_set.len() == 1;
            let txid_ok = tx_replay_set[0].txid().to_hex() == txid;
            info!("---- Signer state check ----";
                "tx_replay_set" => ?tx_replay_set,
                "len_ok" => len_ok,
                "txid_ok" => txid_ok,
            );
            Ok(len_ok && txid_ok)
        })
        .expect("Timed out waiting for tx replay set to be updated");

    info!("---- Waiting for tx replay set to be cleared ----");
    test_observer::clear();
    fault_injection_unstall_miner();
    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be cleared");

    let mut found_block = false;
    // Ensure that we don't mine any of the replay transactions in a sufficient amount of elapsed time
    let _ = wait_for(30, || {
        let blocks = test_observer::get_blocks();
        for block in blocks {
            let block: StacksBlockEvent =
                serde_json::from_value(block).expect("Failed to parse block");
            for tx in block.transactions {
                match tx.payload {
                    TransactionPayload::TenureChange(TenureChangePayload {
                        cause: TenureChangeCause::BlockFound,
                        ..
                    })
                    | TransactionPayload::Coinbase(..) => {
                        found_block = true;
                    }
                    TransactionPayload::TenureChange(TenureChangePayload {
                        cause: TenureChangeCause::Extended,
                        ..
                    }) => {
                        continue;
                    }
                    _ => {
                        panic!("We should not see any transactions mined beyond tenure change or coinbase txs");
                    }
                }
            }
        }
        Ok(false)
    });

    assert!(found_block, "Failed to mine the tenure change block");
    // Ensure that in the 30 seconds, the nonce did not increase. This also asserts that no tx replays were mined.
    let account = get_account(&http_origin, &recipient_addr);
    assert_eq!(account.nonce, 0, "Expected recipient nonce to be 0");

    // Call `/v3/transaction/{txid}` and verify that `is_canonical` is false
    let get_transaction = |txid: &String| {
        let url = &format!("{http_origin}/v3/transaction/{txid}");
        info!("Send request: GET {url}");
        reqwest::blocking::Client::new()
            .get(url)
            .header(
                AUTHORIZATION,
                conf.connection_options.auth_token.clone().unwrap(),
            )
            .send()
            .unwrap_or_else(|e| panic!("GET request failed: {e}"))
            .json::<TransactionResponse>()
            .unwrap()
    };

    let transaction = get_transaction(&txid);
    assert!(
        !transaction.is_canonical,
        "Expected transaction response to be non-canonical"
    );
    assert!(
        transaction.block_height.is_none(),
        "Expected block height of tx response to be none"
    );

    signer_test.shutdown();
}

/// Test scenario to ensure that the replay set is cleared
/// if there have been multiple tenures with a stalled replay set.
///
/// This test is executed by triggering a fork, and then using
/// a test flag to reject any transaction replay blocks.
///
/// The test mines a number of burn blocks during replay before
/// validating that the replay set is eventually cleared.
#[ignore]
#[test]
fn tx_replay_failsafe() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );

    let conf = &signer_test.running_nodes.conf;
    let _http_origin = format!("http://{}", &conf.node.rpc_bind);
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;

    let miner_pk = btc_controller
        .get_mining_pubkey()
        .as_deref()
        .map(Secp256k1PublicKey::from_hex)
        .unwrap()
        .unwrap();

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Beginning test -------------------------");

    let burnchain = conf.get_burnchain();

    let tip = signer_test.get_peer_info();
    let pox_info = signer_test.get_pox_data();

    info!("---- Burnchain ----";
        // "burnchain" => ?conf.burnchain,
        "pox_constants" => ?burnchain.pox_constants,
        "cycle" => burnchain.pox_constants.reward_cycle_index(0, tip.burn_block_height),
        "pox_info" => ?pox_info,
    );

    let pre_fork_tenures = 3;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    info!("---- Submitting STX transfer ----");

    let tip = get_chain_info(&conf);
    // Make a transfer tx (this will get forked)
    let (txid, nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    // Ensure we got a new block with this tx
    signer_test
        .wait_for_nonce_increase(&sender_addr, nonce)
        .expect("Timed out waiting for transfer tx to be mined");

    wait_for(30, || {
        let new_tip = get_chain_info(&conf);
        Ok(new_tip.stacks_tip_height > tip.stacks_tip_height)
    })
    .expect("Timed out waiting for transfer tx to be mined");

    let tip_before = get_chain_info(&conf);

    info!("---- Triggering Bitcoin fork ----";
        "tip.stacks_tip_height" => tip_before.stacks_tip_height,
        "tip.burn_block_height" => tip_before.burn_block_height,
    );

    let mut commit_txid: Option<Txid> = None;
    wait_for(30, || {
        let Some(txid) = signer_test.get_parent_block_commit_txid(&miner_pk) else {
            return Ok(false);
        };
        commit_txid = Some(txid);
        Ok(true)
    })
    .expect("Failed to get unconfirmed tx");

    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip_before.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(1);

    fault_injection_stall_miner();

    // Wait for the block commit re-broadcast to be confirmed
    wait_for(10, || {
        let is_confirmed = btc_controller.is_transaction_confirmed(commit_txid.as_ref().unwrap());
        Ok(is_confirmed)
    })
    .expect("Timed out waiting for transaction to be confirmed");

    let tip_before = get_chain_info(&conf);

    info!("---- Building next block ----";
        "tip_before.stacks_tip_height" => tip_before.stacks_tip_height,
        "tip_before.burn_block_height" => tip_before.burn_block_height,
    );

    btc_controller.build_next_block(1);
    wait_for(30, || {
        let tip = get_chain_info(&conf);
        Ok(tip.stacks_tip_height < tip_before.stacks_tip_height)
    })
    .expect("Timed out waiting for next block to be mined");

    info!("---- Wait for tx replay set to be updated ----");

    signer_test.wait_for_replay_set_eq(30, vec![txid.clone()]);

    let tip_after_fork = get_chain_info(&conf);

    info!("---- Waiting for two tenures, without replay set cleared ----";
        "tip_after_fork.stacks_tip_height" => tip_after_fork.stacks_tip_height,
        "tip_after_fork.burn_block_height" => tip_after_fork.burn_block_height
    );

    TEST_REJECT_REPLAY_TXS.set(true);
    fault_injection_unstall_miner();

    wait_for(30, || {
        let tip = get_chain_info(&conf);
        Ok(tip.stacks_tip_height > tip_after_fork.stacks_tip_height)
    })
    .expect("Timed out waiting for one TenureChange block to be mined");

    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_some()))
        .expect("Expected replay set to still be set");

    info!("---- Mining a second tenure ----");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    wait_for(30, || {
        let tip = get_chain_info(&conf);
        Ok(tip.stacks_tip_height > tip_after_fork.stacks_tip_height + 1)
    })
    .expect("Timed out waiting for a TenureChange block to be mined");

    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_some()))
        .expect("Expected replay set to still be set");

    info!("---- Mining a third tenure ----");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    wait_for(30, || {
        let tip = get_chain_info(&conf);
        Ok(tip.stacks_tip_height > tip_after_fork.stacks_tip_height + 2)
    })
    .expect("Timed out waiting for a TenureChange block to be mined");

    info!("---- Waiting for tx replay set to be cleared ----");

    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Expected replay set to be cleared");

    signer_test.shutdown();
}

/// Simple/fast test scenario for transaction replay.
///
/// We fork one tenure, which has a STX transfer. The test
/// verifies that the replay set is updated correctly, and then
/// exits.
#[ignore]
#[test]
fn tx_replay_starts_correctly() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );

    let conf = &signer_test.running_nodes.conf;
    let _http_origin = format!("http://{}", &conf.node.rpc_bind);
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Beginning test -------------------------");

    let tip = signer_test.get_peer_info();

    info!("---- Tip ----";
        "tip.stacks_tip_height" => tip.stacks_tip_height,
        "tip.burn_block_height" => tip.burn_block_height,
    );

    let pre_fork_tenures = 1;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    info!("---- Submitting STX transfer ----");

    // let tip = get_chain_info(&conf);
    // Make a transfer tx (this will get forked)
    let (txid, nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    // Ensure we got a new block with this tx
    signer_test
        .wait_for_nonce_increase(&sender_addr, nonce)
        .expect("Timed out waiting for transfer tx to be mined");

    let tip_before = get_chain_info(&conf);

    info!("---- Triggering Bitcoin fork ----";
        "tip.stacks_tip_height" => tip_before.stacks_tip_height,
        "tip.burn_block_height" => tip_before.burn_block_height,
        "tip.consensus_hash" => %tip_before.pox_consensus,
    );

    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip_before.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    wait_for(30, || {
        let tip = get_chain_info(&conf);
        Ok(tip.stacks_tip_height < tip_before.stacks_tip_height)
    })
    .expect("Timed out waiting for next block to be mined");

    let tip = get_chain_info(&conf);

    info!("---- Tip after fork ----";
        "tip.stacks_tip_height" => tip.stacks_tip_height,
        "tip.burn_block_height" => tip.burn_block_height,
    );

    info!("---- Wait for tx replay set to be updated ----");

    signer_test.wait_for_replay_set_eq(5, vec![txid.clone()]);

    signer_test.shutdown();
}

/// Test scenario where two signers disagree on the tx replay set,
/// which means there is no consensus on the tx replay set.
#[test]
#[ignore]
fn tx_replay_disagreement() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr, (send_amt + send_fee) * 10)],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
            },
            None,
            None,
            Some(function_name!()),
        );

    let conf = &signer_test.running_nodes.conf;
    let _http_origin = format!("http://{}", &conf.node.rpc_bind);
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Beginning test -------------------------");

    let miner_pk = btc_controller
        .get_mining_pubkey()
        .as_deref()
        .map(Secp256k1PublicKey::from_hex)
        .unwrap()
        .unwrap();

    let pre_fork_tenures = 2;

    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    let ignore_bitcoin_fork_keys = signer_test
        .signer_stacks_private_keys
        .iter()
        .enumerate()
        .filter_map(|(i, sk)| {
            if i % 2 == 0 {
                None
            } else {
                Some(Secp256k1PublicKey::from_private(sk))
            }
        })
        .collect::<Vec<_>>();
    TEST_IGNORE_BITCOIN_FORK_PUBKEYS.set(ignore_bitcoin_fork_keys);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");
    let tip = get_chain_info(&conf);
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &tip.pox_consensus,
        &signer_test.signer_addresses_versions(),
    )
    .expect("Failed to update signers state machines");
    // Make a transfer tx (this will get forked)
    let (txid, _) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    wait_for(30, || {
        let new_tip = get_chain_info(&conf);
        Ok(new_tip.stacks_tip_height > tip.stacks_tip_height)
    })
    .expect("Timed out waiting for transfer tx to be mined");

    let mut commit_txid: Option<Txid> = None;
    wait_for(30, || {
        let Some(txid) = signer_test.get_parent_block_commit_txid(&miner_pk) else {
            return Ok(false);
        };
        commit_txid = Some(txid);
        Ok(true)
    })
    .expect("Failed to get unconfirmed tx");

    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(1);

    // Wait for the block commit re-broadcast to be confirmed
    wait_for(10, || {
        let is_confirmed = btc_controller.is_transaction_confirmed(commit_txid.as_ref().unwrap());
        Ok(is_confirmed)
    })
    .expect("Timed out waiting for transaction to be confirmed");

    let tip_before = get_chain_info(&conf);

    info!("---- Building next block ----";
        "tip_before.stacks_tip_height" => tip_before.stacks_tip_height,
        "tip_before.burn_block_height" => tip_before.burn_block_height,
    );

    btc_controller.build_next_block(1);
    wait_for(30, || {
        let tip = get_chain_info(&conf);
        Ok(tip.stacks_tip_height < tip_before.stacks_tip_height)
    })
    .expect("Timed out waiting for next block to be mined");

    fault_injection_stall_miner();

    btc_controller.build_next_block(1);

    // Wait for the signer states to be updated. Odd indexed signers
    // should not have a replay set.
    wait_for(30, || {
        let (signer_states, _) = signer_test.get_burn_updated_states();
        let all_pass = signer_states.iter().enumerate().all(|(i, state)| {
            if i % 2 == 0 {
                let Some(tx_replay_set) = state.get_tx_replay_set() else {
                    return false;
                };
                tx_replay_set.len() == 1 && tx_replay_set[0].txid().to_hex() == txid
            } else {
                state.get_tx_replay_set().is_none()
            }
        });
        Ok(all_pass)
    })
    .expect("Timed out waiting for signer states to be updated");

    let tip = get_chain_info(&conf);

    fault_injection_unstall_miner();

    // Now, wait for the tx replay set to be cleared

    wait_for(30, || {
        let new_tip = get_chain_info(&conf);
        Ok(new_tip.stacks_tip_height >= tip.stacks_tip_height + 2)
    })
    .expect("Timed out waiting for transfer tx to be mined");

    signer_test
        .wait_for_signer_state_check(30, |state| {
            let tx_replay_set = state.get_tx_replay_set();
            Ok(tx_replay_set.is_none())
        })
        .expect("Timed out waiting for tx replay set to be cleared");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Demonstrates that transaction replay can be "solved" using mempool transactions,
/// by coincidence, rather than using the Tx Replay Set as the source.
/// This works because the transactions in the mempool happen to match those in the replay set.
///
/// The test flow is:
///
/// - Boot to Epoch 3
/// - Submit 2 STX Transfer txs (Tx1, Tx2) in the last tenure
/// - Trigger a Bitcoin fork (3 blocks)
/// - Verify that signers move into tx replay state [Tx1, Tx2]
/// - Force miner to solve replay with mempool [Tx1, Tx2]
fn tx_replay_solved_by_mempool_txs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender1_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender1_addr = tests::to_addr(&sender1_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 2;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender1_addr.clone(), (send_amt + send_fee) * num_txs)],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }
    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 2;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }
    signer_test.check_signer_states_normal();

    // Make a transfer tx (this will get forked)
    let (sender1_tx1, sender1_nonce) = signer_test
        .submit_transfer_tx(&sender1_sk, send_fee, send_amt)
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, sender1_nonce)
        .expect("Expect sender1 nonce increased");

    let (sender1_tx2, sender1_nonce) = signer_test
        .submit_transfer_tx(&sender1_sk, send_fee, send_amt)
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, sender1_nonce)
        .expect("Expect sender1 nonce increased");

    let sender1_nonce = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(2, sender1_nonce);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");
    let tip = get_chain_info(&conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");
    fault_injection_stall_miner();

    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx1.clone(), sender1_tx2.clone()]);

    // We should have forked 2 txs
    let sender1_nonce_post_fork = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(0, sender1_nonce_post_fork);

    info!("------------------------- Mine Tx Replay Set -------------------------");
    TEST_EXCLUDE_REPLAY_TXS.set(true); //Force solving Tx Replay with mempool txs
    fault_injection_unstall_miner();

    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be updated");

    let sender1_nonce_post_replay = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(2, sender1_nonce_post_replay);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Trigger a Bitcoin fork across reward cycle
/// and ensure that the signers detect the fork,
/// but reject to move into a tx replay state
///
/// The test flow is:
///
/// - Boot to Epoch 3 (that is in the middle of reward cycle N)
/// - Mine until the last tenure of the reward cycle N
/// - Include a STX transfer in the last tenure
/// - Mine 1 Bitcoin block in the next reward cycle N+1
/// - Trigger a Bitcoin fork from reward cycle N (3 blocks)
/// - Verify that signers don't move into tx replay state
/// - In the end, the STX transfer transaction is not replayed
fn tx_replay_rejected_when_forking_across_reward_cycle() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 1;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr.clone(), (send_amt + send_fee) * num_txs)],
        |_| {},
        |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.miner.replay_transactions = true;
        },
        None,
        None,
    );
    let conf = signer_test.running_nodes.conf.clone();
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let burn_chain = btc_controller.get_burnchain();
    let counters = &signer_test.running_nodes.counters;

    signer_test.boot_to_epoch_3();
    info!("------------------------- Reached Epoch 3.0 -------------------------");

    let burn_block_height = get_chain_info(&conf).burn_block_height;
    let initial_reward_cycle = signer_test.get_current_reward_cycle();
    let rc_last_height = burn_chain.nakamoto_last_block_of_cycle(initial_reward_cycle);

    info!("----- Mine to the end of reward cycle {initial_reward_cycle} height {rc_last_height} -----");
    let pre_fork_tenures = rc_last_height - burn_block_height;
    for i in 1..=pre_fork_tenures {
        info!("Mining pre-fork tenure {i} of {pre_fork_tenures}");
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }
    signer_test.check_signer_states_normal();

    info!("----- Submit Stx transfer in last tenure height {rc_last_height} -----");
    // Make a transfer tx that will get forked
    let tip = get_chain_info(&conf);
    let _ = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();
    wait_for(30, || {
        let new_tip = get_chain_info(&conf);
        Ok(new_tip.stacks_tip_height > tip.stacks_tip_height)
    })
    .expect("Timed out waiting for transfer tx to be mined");

    let pre_fork_tx_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(1, pre_fork_tx_nonce);

    info!("----- Mine 1 block in new reward cycle -----");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    let next_reward_cycle = initial_reward_cycle + 1;
    let new_burn_block_height = get_chain_info(&conf).burn_block_height;
    assert_eq!(next_reward_cycle, signer_test.get_current_reward_cycle());
    assert_eq!(
        new_burn_block_height,
        burn_chain.nakamoto_first_block_of_cycle(next_reward_cycle)
    );

    info!("----- Trigger Bitcoin fork -----");
    //Fork on the third-to-last tenure of prev reward cycle
    let burn_block_hash_to_fork = btc_controller.get_block_hash(new_burn_block_height - 2);
    btc_controller.invalidate_block(&burn_block_hash_to_fork);
    btc_controller.build_next_block(3);

    // note, we should still have normal signer states!
    signer_test.check_signer_states_normal();

    //mine throught the fork (just check commits because of naka block mining stalled)
    fault_injection_stall_miner();

    let submitted_commits = counters.naka_submitted_commits.clone();
    for i in 0..3 {
        let current_burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
        info!(
            "Mining block #{i} to be considered a frequent miner";
            "current_burn_height" => current_burn_height,
        );
        let commits_count = submitted_commits.load(Ordering::SeqCst);
        next_block_and(btc_controller, 60, || {
            let commits_submitted = submitted_commits.load(Ordering::SeqCst);
            Ok(commits_submitted > commits_count
                && get_chain_info(&signer_test.running_nodes.conf).burn_block_height
                    > current_burn_height)
        })
        .unwrap();
    }

    let post_fork_tx_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(0, post_fork_tx_nonce);

    info!("----- Check Signers Tx Replay state -----");
    wait_for(30, || {
        let (states, _) = signer_test.get_burn_updated_states();
        if states.is_empty() {
            return Ok(false);
        }
        Ok(states
            .iter()
            .all(|state| state.get_tx_replay_set().is_none()))
    })
    .expect("Unable to confirm tx replay state");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Demonstrates Tx Replay state is kept by Signers after a fork
/// occurred before the miner start replaying transactions
///
/// The test flow is:
///
/// - Boot to Epoch 3
/// - Mine 12 tenures (to handle multiple forks in Cycle #12)
/// - Submit a STX transfer (Tx1) in the last tenure
/// - Trigger a Bitcoin fork
/// - Verify that signers move into tx replay state [Tx1]
/// - Trigger a Bitcoin fork
/// - Verify that signers stay into tx replay state [Tx1]
/// - In the end, let the miner solve the Tx Replay Set
fn tx_replay_with_fork_occured_before_starting_replaying_txs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender1_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender1_addr = tests::to_addr(&sender1_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 1;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender1_addr.clone(), (send_amt + send_fee) * num_txs)],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }
    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 12; //go to 2nd tenure of 12th cycle
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    // Make 1 transfer tx (this will get forked)
    let (sender1_tx1, sender1_nonce) = signer_test
        .submit_transfer_tx(&sender1_sk, send_fee, send_amt)
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, sender1_nonce)
        .expect("Expect sender1 nonce increased");

    let sender1_nonce = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(1, sender1_nonce);

    info!("------------------------- Triggering Bitcoin Fork #1 -------------------------");
    let tip = get_chain_info(&conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");

    // Signers move in Tx Replay mode
    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx1.clone()]);

    // We should have forked 1 tx
    let sender1_nonce_post_fork = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(0, sender1_nonce_post_fork);

    info!("------------------------- Triggering Bitcoin Fork #2 -------------------------");
    let tip = get_chain_info(&conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    //Signers still are in the initial state of Tx Replay mode
    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx1.clone()]);

    info!("----------- Solve TX Replay ------------");
    fault_injection_unstall_miner();

    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be updated");

    let sender1_nonce_after_replay = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(1, sender1_nonce_after_replay);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Demonstrates that the Tx Replay state is preserved by signers after a fork
/// that occurs following an "empty" tenure,
/// but before the miner begins replaying transactions.
///
/// The test flow is:
///
/// - Boot to Epoch 3
/// - Mine 10 tenures (to handle multiple forks in Cycle #12)
/// - Submit a STX transfer (Tx1) in the last tenure
/// - Trigger a Bitcoin fork
/// - Verify that signers move into tx replay state [Tx1]
/// - Force the miner to mine an "empty" tenure (only Block Found)
/// - Trigger a Bitcoin fork
/// - Verify that signers stay into tx replay state [Tx1]
/// - In the end, let the miner solve the Tx Replay Set
fn tx_replay_with_fork_after_empty_tenures_before_starting_replaying_txs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender1_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender1_addr = tests::to_addr(&sender1_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 1;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender1_addr.clone(), (send_amt + send_fee) * num_txs)],
            |c| {
                c.validate_with_replay_tx = true;
                c.reset_replay_set_after_fork_blocks = 5;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }
    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 10; //go to Tenure #4 in Cycle #12
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    info!("------------------------- Sending Transactions -------------------------");
    // Make a transfer tx (this will get forked)
    let (sender1_tx1, sender1_nonce) = signer_test
        .submit_transfer_tx(&sender1_sk, send_fee, send_amt)
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, sender1_nonce)
        .expect("Expect sender1 nonce increased");

    let sender1_nonce = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(1, sender1_nonce);

    info!("------------------------- Triggering Bitcoin Fork #1 -------------------------");
    let tip = get_chain_info(&conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");

    // Signers moved in Tx Replay mode
    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx1.clone()]);

    // We should have forked tx1
    let sender1_nonce_post_fork = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(0, sender1_nonce_post_fork);

    info!("------------------- Produce Empty Tenure -------------------------");
    fault_injection_unstall_miner();
    let tip = get_chain_info(&conf);
    _ = wait_for_tenure_change_tx(30, TenureChangeCause::BlockFound, tip.stacks_tip_height + 1);
    fault_injection_stall_miner();

    signer_test
        .wait_for_signer_state_check(30, |state| {
            let Some(tx_replay_set) = state.get_tx_replay_set() else {
                return Ok(false);
            };
            let len_ok = tx_replay_set.len() == 1;
            let txid_ok = tx_replay_set[0].txid().to_hex() == sender1_tx1;
            Ok(len_ok && txid_ok)
        })
        .expect("Timed out waiting for tx replay set to be updated");

    info!("------------------------- Triggering Bitcoin Fork #2 -------------------------");
    test_observer::clear();

    let tip = get_chain_info(&conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");

    // Signers still are in Tx Replay mode (as the initial replay state)
    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx1.clone()]);

    info!("------------------------- Mine Tx Replay Set -------------------------");
    fault_injection_unstall_miner();
    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be updated");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Demonstrates Tx Replay Set to be updated from a deepest fork
/// than the one that made Tx Replay to start
///
/// The test flow is:
///
/// - Boot to Epoch 3
/// - Mine 10 tenures (to handle multiple forks in Cycle #12)
/// - Submit a STX transfer (Tx1) in the last tenure
/// - Mine 3 new tenures
/// - Submit a STX transfer (Tx2) in the last tenure
/// - Trigger a Bitcoin fork (involving Tx2 only)
/// - Verify that signers move into tx replay state [Tx2]
/// - Trigger a Bitcoin fork (deepest to involve Tx1)
/// - Verify that signers update tx replay state to [Tx1, Tx2]
/// - In the end, let the miner solve the Tx Replay Set
fn tx_replay_with_fork_causing_replay_set_to_be_updated() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender1_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender1_addr = tests::to_addr(&sender1_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 2;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender1_addr.clone(), (send_amt + send_fee) * num_txs)],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }
    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 10;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    // Make 2 transfer txs, each in its own tenure so that can be forked in different forks
    let tip_at_tx1 = get_chain_info(&conf);
    assert_eq!(241, tip_at_tx1.burn_block_height);
    let (sender1_tx1, sender1_nonce) = signer_test
        .submit_transfer_tx(&sender1_sk, send_fee, send_amt)
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, sender1_nonce)
        .expect("Expect sender1 nonce increased");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let tip_at_tx2 = get_chain_info(&conf);
    assert_eq!(242, tip_at_tx2.burn_block_height);
    let (sender1_tx2, sender1_nonce) = signer_test
        .submit_transfer_tx(&sender1_sk, send_fee, send_amt)
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, sender1_nonce)
        .expect("Expect sender1 nonce increased");

    let sender1_nonce = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(2, sender1_nonce);

    info!("------------------------- Triggering Bitcoin Fork #1 -------------------------");
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip_at_tx2.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(1);

    info!("Wait for block off of shallow fork");
    fault_injection_stall_miner();
    btc_controller.build_next_block(1);

    wait_for(10, || {
        let tip = get_chain_info(&conf);
        Ok(tip.burn_block_height == 243)
    })
    .expect("Timed out waiting for burn block height to be 243");

    // Signers move in Tx Replay mode
    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx2.clone()]);

    // We should have forked one tx (Tx2)
    let sender1_nonce_post_fork = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(1, sender1_nonce_post_fork);

    info!(
        "------------------------- Triggering Bitcoin Fork #2 from {} -------------------------",
        tip_at_tx1.burn_block_height
    );
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip_at_tx1.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(4);
    wait_for(10, || {
        let tip = get_chain_info(&conf);
        info!("Burn block height: {}", tip.burn_block_height);
        Ok(tip.burn_block_height == 244)
    })
    .expect("Timed out waiting for burn block height to be 244");

    info!("Wait for block off of shallow fork");
    fault_injection_stall_miner();

    //Signers should update the Tx Replay Set
    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx1.clone(), sender1_tx2.clone()]);

    info!("----------- Solve TX Replay ------------");
    fault_injection_unstall_miner();

    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be updated");

    let sender1_nonce_after_replay = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(2, sender1_nonce_after_replay);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Demonstrates Tx Replay Set to be cleared from a deepest fork
/// than the one that made Tx Replay to start, that led to
/// previous reward cylce
///
/// The test flow is:
///
/// - Boot to Epoch 3
/// - Mine 8 tenures (to arrive at Cycle #11 boundary)
/// - Mine 3 more tenures (to enter Cycle #12)
/// - Submit a STX transfer (Tx1) in the last tenure
/// - Trigger a Bitcoin fork (in Cycle #12)
/// - Verify that signers move into tx replay state [Tx1]
/// - Trigger a Bitcoin fork (deepest to involve Cycle #11)
/// - Verify that signers clear the tx replay state
fn tx_replay_with_fork_causing_replay_to_be_cleared_due_to_cycle() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender1_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender1_addr = tests::to_addr(&sender1_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 2;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender1_addr.clone(), (send_amt + send_fee) * num_txs)],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }
    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 8;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
        signer_test.check_signer_states_normal();
    }

    let tip_at_rc11 = get_chain_info(&conf);
    assert_eq!(239, tip_at_rc11.burn_block_height);
    assert_eq!(11, signer_test.get_current_reward_cycle());

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let tip_at_rc12 = get_chain_info(&conf);
    assert_eq!(242, tip_at_rc12.burn_block_height);
    assert_eq!(12, signer_test.get_current_reward_cycle());

    // Make 2 transfer txs, each in its own tenure so that can be forked in different forks
    let (sender1_tx1, sender1_nonce) = signer_test
        .submit_transfer_tx(&sender1_sk, send_fee, send_amt)
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, sender1_nonce)
        .expect("Expect sender1 nonce increased");

    let sender1_nonce = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(1, sender1_nonce);

    info!("------------------------- Triggering Bitcoin Fork #1 -------------------------");
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip_at_rc12.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    // Signers move in Tx Replay mode
    signer_test.wait_for_replay_set_eq(30, vec![sender1_tx1.clone()]);

    // We should have forked one tx (Tx2)
    let sender1_nonce_post_fork = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(0, sender1_nonce_post_fork);

    info!("------------------------- Triggering Bitcoin Fork #2 -------------------------");
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip_at_rc11.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(6);

    info!("Wait for block off of shallow fork");

    //Signers should clear the Tx Replay Set
    signer_test
        .wait_for_signer_state_check(30, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be updated");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Demonstrates Tx Replay restart from scratch while it is in progress
/// (partially replayed a subset of transaction) and a fork occurs.
/// In this case, partial replay is allowed because of tenure extend,
/// due to Tenure Budget exceeded.
///
/// The test flow is:
///
/// - Boot to Epoch 3
/// - Deploy 1 Big Contract and mine 2 tenures (to escape fork)
/// - Submit 2 Contract Call txs (Tx1, Tx2) in the last tenure,
///   requiring Tenure Extend due to Tenure Budget exceeded
/// - Trigger a Bitcoin fork
/// - Verify that signers move into tx replay state [Tx1, Tx2]
/// - Force Miner to do a partial replay (only Tx1),
///   blocking Tenure extension
/// - Trigger a Bitcoin fork
/// - In the end, Tx Replay Set is solved from scratch [Tx1, Tx2]
fn tx_replay_with_fork_middle_replay_while_tenure_extending() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 1000000;
    let call_fee = 1000;
    let call_num = 2;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), deploy_fee + call_fee * call_num)],
            |c| {
                c.validate_with_replay_tx = true;
                c.tenure_idle_timeout = Duration::from_secs(10);
                c.reset_replay_set_after_fork_blocks = 5;
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let stacks_miner_pk = StacksPublicKey::from_private(&conf.miner.mining_key.clone().unwrap());

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }
    info!("------------------------- Beginning test -------------------------");

    let pre_fork_tenures = 2;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }
    signer_test.check_signer_states_normal();

    info!("---- Deploying big contract ----");
    // First, just deploy the contract in its own tenure
    let contract_code = make_big_read_count_contract(HELIUM_BLOCK_LIMIT_20, 50);
    let (_deploy_txid, deploy_nonce) = signer_test
        .submit_contract_deploy(
            &sender_sk,
            deploy_fee,
            contract_code.as_str(),
            "big-contract",
        )
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender_addr, deploy_nonce)
        .expect("Timed out waiting for nonce to increase");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    // Then, sumbmit 2 Contract Calls that require Tenure Extension to be addressed.
    info!("---- Submit big tx1 to be mined ----");
    let (txid1, txid1_nonce) = signer_test
        .submit_contract_call(&sender_sk, call_fee, "big-contract", "big-tx", &vec![])
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender_addr, txid1_nonce)
        .expect("Timed out waiting for nonce to increase");

    info!("---- Submit big tx2 to be mined ----");
    let tip = get_chain_info(conf);

    let (txid2, txid2_nonce) = signer_test
        .submit_contract_call(&sender_sk, call_fee, "big-contract", "big-tx", &vec![])
        .unwrap();

    // Tenure Extend happen because of tenure budget exceeded
    _ = wait_for_tenure_change_tx(30, TenureChangeCause::Extended, tip.stacks_tip_height + 1);

    signer_test
        .wait_for_nonce_increase(&sender_addr, txid2_nonce)
        .expect("Timed out waiting for nonce to increase");

    let sender1_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(3, sender1_nonce);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");
    let tip = get_chain_info(conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    signer_test.wait_for_replay_set_eq(30, vec![txid1.clone(), txid2.clone()]);

    let post_fork_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(1, post_fork_nonce); //due to contract deploy tx

    info!("---- Force Partial Tx Replay ----");
    // Only Tx1 is replayed, preventing Tenure Extension stalling the miner
    fault_injection_unstall_miner();
    let tip = get_chain_info(&conf);
    _ = wait_for_tenure_change_tx(30, TenureChangeCause::BlockFound, tip.stacks_tip_height + 1);
    _ = wait_for_block_proposal_block(30, tip.stacks_tip_height + 2, &stacks_miner_pk);
    fault_injection_stall_miner();

    // Signers still waiting for the Tx Replay set to be completed
    signer_test.wait_for_replay_set_eq(30, vec![txid1.clone(), txid2.clone()]);

    info!("------------------------- Triggering Bitcoin Fork #2 -------------------------");
    //Fork in the middle of Tx Replay
    let tip = get_chain_info(&conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height - 1);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");
    fault_injection_stall_miner();

    signer_test.wait_for_replay_set_eq(30, vec![txid1.clone(), txid2.clone()]);

    let post_fork_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(1, post_fork_nonce); //due to contract deploy tx

    info!("---- Waiting for replay set to be cleared ----");
    fault_injection_unstall_miner();

    signer_test
        .wait_for_signer_state_check(60, |state| {
            let tx_replay_set = state.get_tx_replay_set();
            Ok(tx_replay_set.is_none())
        })
        .expect("Timed out waiting for tx replay set to be cleared");

    let post_replay_nonce = get_account(&http_origin, &sender_addr).nonce;
    assert_eq!(3, post_replay_nonce); //1 contract deploy tx + 2 contract call txs

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Demonstrates Tx Replay restart from scratch while it is in progress
/// (partially replayed a subset of transaction), other transactions
/// are submitted, and then a fork occurs.
/// In this case, partial replay is allowed because of tenure extend,
/// due to Tenure Budget exceeded.
///
/// The test flow is:
///
/// - Boot to Epoch 3
/// - Deploy 1 Big Contract and mine 2 tenures (to escape fork)
/// - Submit 2 Contract Call txs (Tx1, Tx2) in the last tenure,
///   requiring Tenure Extend due to Tenure Budget exceeded
/// - Trigger a Bitcoin fork
/// - Verify that signers move into tx replay state [Tx1, Tx2]
/// - Force Miner to do a partial replay (only Tx1),
///   blocking Tenure extension
/// - Submit a STX Transfer tx (Tx3) in the last tenure
/// - Trigger a Bitcoin fork
/// - In the end:
///   - first, Tx Replay Set is solved from scratch [Tx1, Tx2]
///   - then, Tx3 is mined normally
fn tx_replay_with_fork_middle_replay_while_tenure_extending_and_new_tx_submitted() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender1_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender1_addr = tests::to_addr(&sender1_sk);
    let send1_deploy_fee = 1000000;
    let send1_call_fee = 1000;
    let send1_call_num = 2;
    let sender2_sk = Secp256k1PrivateKey::from_seed("sender_2".as_bytes());
    let sender2_addr = tests::to_addr(&sender2_sk);
    let send2_amt = 100;
    let send2_fee = 180;
    let send2_txs = 1;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![
                (
                    sender1_addr.clone(),
                    send1_deploy_fee + send1_call_fee * send1_call_num,
                ),
                (sender2_addr.clone(), (send2_amt + send2_fee) * send2_txs),
            ],
            |c| {
                c.validate_with_replay_tx = true;
                c.tenure_idle_timeout = Duration::from_secs(10);
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let stacks_miner_pk = StacksPublicKey::from_private(&conf.miner.mining_key.clone().unwrap());

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }
    info!("------------------------- Beginning test -------------------------");
    let pre_fork_tenures = 2;
    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }
    signer_test.check_signer_states_normal();

    info!("---- Deploying big contract ----");
    // First, just deploy the contract in its own tenure
    let contract_code = make_big_read_count_contract(HELIUM_BLOCK_LIMIT_20, 50);
    let (_deploy_txid, deploy_nonce) = signer_test
        .submit_contract_deploy(
            &sender1_sk,
            send1_deploy_fee,
            contract_code.as_str(),
            "big-contract",
        )
        .unwrap();
    signer_test
        .wait_for_nonce_increase(&sender1_addr, deploy_nonce)
        .expect("Timed out waiting for nonce to increase");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    // Then, sumbmit 2 Contract Calls that require Tenure Extension to be addressed.
    info!("---- Waiting for first big tx to be mined ----");
    let (txid1, txid1_nonce) = signer_test
        .submit_contract_call(
            &sender1_sk,
            send1_call_fee,
            "big-contract",
            "big-tx",
            &vec![],
        )
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&sender1_addr, txid1_nonce)
        .expect("Timed out waiting for nonce to increase");

    info!("---- Waiting for second big tx to be mined ----");
    let (txid2, txid2_nonce) = signer_test
        .submit_contract_call(
            &sender1_sk,
            send1_call_fee,
            "big-contract",
            "big-tx",
            &vec![],
        )
        .unwrap();

    // Tenure Extend happen because of tenure budget exceeded
    let tip = get_chain_info(conf);
    _ = wait_for_tenure_change_tx(30, TenureChangeCause::Extended, tip.stacks_tip_height + 1);

    signer_test
        .wait_for_nonce_increase(&sender1_addr, txid2_nonce)
        .expect("Timed out waiting for nonce to increase");

    let sender1_nonce = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(3, sender1_nonce);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");
    let tip = get_chain_info(conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(2);

    signer_test.wait_for_replay_set_eq(30, vec![txid1.clone(), txid2.clone()]);

    let post_fork_nonce = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(1, post_fork_nonce); //due to contract deploy tx

    info!("---- Force Partial Tx Replay ----");
    // Only Tx1 is replayed, preventing Tenure Extension stalling the miner
    fault_injection_unstall_miner();
    let tip = get_chain_info(&conf);
    _ = wait_for_tenure_change_tx(30, TenureChangeCause::BlockFound, tip.stacks_tip_height + 1);
    _ = wait_for_block_proposal_block(30, tip.stacks_tip_height + 2, &stacks_miner_pk);
    fault_injection_stall_miner();

    // Signers still waiting for the Tx Replay set to be completed
    signer_test.wait_for_replay_set_eq(30, vec![txid1.clone(), txid2.clone()]);

    info!("---- New Transaction is Submitted ----");
    // Tx3 reach the mempool, meanwhile mining is stalled
    let (_sender2_tx3, sender2_nonce) = signer_test
        .submit_transfer_tx(&sender2_sk, send2_fee, send2_amt)
        .unwrap();

    info!("------------------------- Triggering Bitcoin Fork #2 -------------------------");
    //Fork in the middle of Tx Replay
    let tip = get_chain_info(&conf);
    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    btc_controller.build_next_block(2);

    info!("Wait for block off of shallow fork");
    fault_injection_stall_miner();

    signer_test.wait_for_replay_set_eq(30, vec![txid1.clone(), txid2.clone()]);

    let sender1_nonce_post_fork = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(1, sender1_nonce_post_fork); //due to contract deploy tx

    let sender2_nonce_post_fork = get_account(&http_origin, &sender2_addr).nonce;
    assert_eq!(0, sender2_nonce_post_fork);

    info!("---- Waiting for replay set to be cleared ----");
    fault_injection_unstall_miner();

    signer_test
        .wait_for_signer_state_check(60, |state| {
            let tx_replay_set = state.get_tx_replay_set();
            Ok(tx_replay_set.is_none() && get_account(&http_origin, &sender1_addr).nonce >= 3)
        })
        .expect("Timed out waiting for tx replay set to be cleared");

    let sender1_nonce_post_replay = get_account(&http_origin, &sender1_addr).nonce;
    assert_eq!(3, sender1_nonce_post_replay); //1 contract deploy tx + 2 contract call txs

    //waiting for Tx3 to be processed normally
    signer_test
        .wait_for_nonce_increase(&sender2_addr, sender2_nonce)
        .expect("Timed out waiting for nonce to increase");
    let sender2_nonce_post_replay = get_account(&http_origin, &sender2_addr).nonce;
    assert_eq!(1, sender2_nonce_post_replay);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Trigger a Bitcoin fork that creates a replay set that
/// contains more transactions than can fit into a tenure's budget.
fn tx_replay_budget_exceeded_tenure_extend() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk =
        Secp256k1PrivateKey::from_seed(format!("sender_{}", function_name!()).as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 1000000;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 1000)],
            |c| {
                c.validate_with_replay_tx = true;
                c.tenure_idle_timeout = Duration::from_secs(60);
            },
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );
    let conf = &signer_test.running_nodes.conf;
    let _http_origin = format!("http://{}", &conf.node.rpc_bind);
    let _stacks_miner_pk = StacksPublicKey::from_private(&conf.miner.mining_key.clone().unwrap());

    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Reached Epoch 3.0 -------------------------");
    let pre_fork_tenures = 1;

    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    signer_test.check_signer_states_normal();

    info!("---- Deploying big contract ----");

    // First, just deploy the contract in its own tenure
    let contract_code = make_big_read_count_contract(HELIUM_BLOCK_LIMIT_20, 50);

    let (_deploy_txid, deploy_nonce) = signer_test
        .submit_contract_deploy(&sender_sk, 1000000, contract_code.as_str(), "big-contract")
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&sender_addr, deploy_nonce)
        .expect("Timed out waiting for nonce to increase");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let tip = get_chain_info(conf);

    let (txid1, txid1_nonce) = signer_test
        .submit_contract_call(&sender_sk, send_fee, "big-contract", "big-tx", &vec![])
        .unwrap();

    info!("---- Waiting for first big tx to be mined ----");

    signer_test
        .wait_for_nonce_increase(&sender_addr, txid1_nonce)
        .expect("Timed out waiting for nonce to increase");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let (txid2, txid2_nonce) = signer_test
        .submit_contract_call(&sender_sk, send_fee, "big-contract", "big-tx", &vec![])
        .unwrap();

    info!("---- Waiting for second big tx to be mined ----");

    signer_test
        .wait_for_nonce_increase(&sender_addr, txid2_nonce)
        .expect("Timed out waiting for nonce to increase");

    wait_for(30, || {
        let new_tip = get_chain_info(&conf);
        Ok(new_tip.stacks_tip_height > tip.stacks_tip_height)
    })
    .expect("Timed out waiting for transfer tx to be mined");

    info!("------------------------- Triggering Bitcoin Fork -------------------------");

    let burn_header_hash_to_fork = btc_controller.get_block_hash(tip.burn_block_height);
    btc_controller.invalidate_block(&burn_header_hash_to_fork);
    fault_injection_stall_miner();
    btc_controller.build_next_block(3);

    signer_test.wait_for_replay_set_eq(30, vec![txid1, txid2.clone()]);

    // Clear the test observer so we know that if we see txid1 and txid2 again, that it means they were remined
    test_observer::clear();
    fault_injection_unstall_miner();

    info!("---- Waiting for replay set to be cleared ----");

    // Now, wait for the tx replay set to be cleared
    signer_test
        .wait_for_signer_state_check(60, |state| Ok(state.get_tx_replay_set().is_none()))
        .expect("Timed out waiting for tx replay set to be cleared");
    let mut found_block: Option<StacksBlockEvent> = None;
    wait_for(60, || {
        let blocks = test_observer::get_blocks();
        for block in blocks {
            let block: StacksBlockEvent =
                serde_json::from_value(block.clone()).expect("Failed to parse block");
            if block
                .transactions
                .iter()
                .find(|tx| tx.txid().to_hex() == txid2)
                .is_some()
            {
                found_block = Some(block);
                return Ok(true);
            }
        }
        Ok(false)
    })
    .expect("Failed to mine the replay txs");
    let block = found_block.expect("Failed to find block with txid2");
    assert_eq!(block.transactions.len(), 2);
    assert!(matches!(
        block.transactions[0].payload,
        TransactionPayload::TenureChange(TenureChangePayload {
            cause: TenureChangeCause::Extended,
            ..
        })
    ));

    signer_test.shutdown();
}
