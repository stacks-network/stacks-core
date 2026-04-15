// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use libsigner::v0::messages::{
    BlockRejection, BlockResponse, MessageSlotID, RejectReason, SignerMessage,
};
use libsigner::{SignerSession, StackerDBSession};
use pinny::tag;
use stacks::burnchains::Txid;
use stacks::codec::StacksMessageCodec;
use stacks::core::test_util::{make_stacks_transfer_serialized, to_addr};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::api::postblock_proposal::ValidateRejectCode;
use stacks::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks::util::get_epoch_time_secs;
use stacks_signer::v0::tests::TEST_IGNORE_ALL_BLOCK_PROPOSALS;
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::nakamoto_node::miner::TEST_MINE_SKIP;
use crate::tests::neon_integrations::submit_tx_fallible;
use crate::tests::signer::v0::{wait_for_block_proposal, wait_for_block_pushed_by_miner_key};
use crate::tests::signer::{test_observer, SignerTest};

/// Holds context from the shared test setup so individual tests can
/// make their own assertions after the rejection-triggered reproposal.
struct FailedTxTestContext {
    signer_test: SignerTest<SpawnedSigner>,
    sender_b_sk: StacksPrivateKey,
    txid_a0: Txid,
    txid_a1: Txid,
}

/// Shared test scaffolding for failed_txid rejection tests.
///
/// Sets up 5 signers and 2 sender accounts, boots to epoch 3, submits
/// 4 transfer txs (sender A nonces 0,1 and sender B nonces 0,1), waits
/// for the first block proposal containing all 4, then injects
/// `BlockRejection` messages from all 5 signers with `failed_txid` =
/// sender A's nonce-0 txid using the given `reject_code`.
///
/// After injections, unpauses mining and signers so the miner can
/// repropose. Returns a context struct for the caller to assert on
/// subsequent blocks.
fn setup_failed_tx_test(reject_code: ValidateRejectCode) -> FailedTxTestContext {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_a_sk = StacksPrivateKey::from_seed(&[100; 32]);
    let sender_b_sk = StacksPrivateKey::from_seed(&[101; 32]);
    let sender_a_addr = to_addr(&sender_a_sk);
    let sender_b_addr = to_addr(&sender_b_sk);

    let initial_balances = vec![
        (sender_a_addr.clone(), 1_000_000),
        (sender_b_addr.clone(), 1_000_000),
    ];

    info!("------------------------- Test Setup -------------------------");
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |_| {},
        |_| {},
        None,
        None,
    );

    let all_signer_pks: Vec<StacksPublicKey> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect();

    let miner_privk = signer_test.get_miner_key();
    let miner_pubk = StacksPublicKey::from_private(miner_privk);

    signer_test.boot_to_epoch_3();

    // Tell all signers to ignore block proposals so we control responses manually
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(all_signer_pks.clone());
    // Pause block proposals so we can ensure all txs are in the mempool before the first proposal goes out
    TEST_MINE_SKIP.set(true);
    info!("------------------------- Submit Transfer Transactions -------------------------");
    let http_origin = signer_test.running_nodes.rpc_origin();
    let chain_id = signer_test.running_nodes.conf.burnchain.chain_id;
    let send_fee = 300;
    let send_amt = 1_000;
    let recipient = clarity::vm::types::PrincipalData::from(StacksAddress::burn_address(false));

    // Sender A: nonce 0
    let tx_a0 =
        make_stacks_transfer_serialized(&sender_a_sk, 0, send_fee, chain_id, &recipient, send_amt);
    let txid_a0_hex =
        submit_tx_fallible(&http_origin, &tx_a0).expect("Failed to submit sender A tx 0");
    info!("Submitted sender A tx 0: {txid_a0_hex}");

    // Sender A: nonce 1
    let tx_a1 =
        make_stacks_transfer_serialized(&sender_a_sk, 1, send_fee, chain_id, &recipient, send_amt);
    let txid_a1_hex =
        submit_tx_fallible(&http_origin, &tx_a1).expect("Failed to submit sender A tx 1");
    info!("Submitted sender A tx 1: {txid_a1_hex}");

    // Sender B: nonce 0
    let tx_b0 =
        make_stacks_transfer_serialized(&sender_b_sk, 0, send_fee, chain_id, &recipient, send_amt);
    let txid_b0_hex =
        submit_tx_fallible(&http_origin, &tx_b0).expect("Failed to submit sender B tx 0");
    info!("Submitted sender B tx 0: {txid_b0_hex}");

    // Sender B: nonce 1
    let tx_b1 =
        make_stacks_transfer_serialized(&sender_b_sk, 1, send_fee, chain_id, &recipient, send_amt);
    let txid_b1_hex =
        submit_tx_fallible(&http_origin, &tx_b1).expect("Failed to submit sender B tx 1");
    info!("Submitted sender B tx 1: {txid_b1_hex}");

    let txid_a0 = Txid::from_hex(&txid_a0_hex).expect("Failed to parse txid_a0");
    let txid_a1 = Txid::from_hex(&txid_a1_hex).expect("Failed to parse txid_a1");
    let txid_b0 = Txid::from_hex(&txid_b0_hex).expect("Failed to parse txid_b0");
    let txid_b1 = Txid::from_hex(&txid_b1_hex).expect("Failed to parse txid_b1");

    // Unpause mining so the miner can propose a block (which we will manually reject)
    TEST_MINE_SKIP.set(false);
    let expected_height = signer_test.get_peer_info().stacks_tip_height + 1;
    info!("------------------------- Wait for first block proposal -------------------------");
    let first_proposal = wait_for_block_proposal(30, expected_height, &miner_pubk)
        .expect("Miner did not propose a block");

    // Pause mining so we can inject rejections without the miner immediately reproposing
    TEST_MINE_SKIP.set(true);
    // Verify the first proposal contains all 4 transfer txs
    let first_txids: Vec<_> = first_proposal
        .block
        .txs
        .iter()
        .map(|tx| tx.txid())
        .collect();
    assert!(
        first_txids.contains(&txid_a0),
        "First proposal should contain sender A tx 0"
    );
    assert!(
        first_txids.contains(&txid_a1),
        "First proposal should contain sender A tx 1"
    );
    assert!(
        first_txids.contains(&txid_b0),
        "First proposal should contain sender B tx 0"
    );
    assert!(
        first_txids.contains(&txid_b1),
        "First proposal should contain sender B tx 1"
    );

    let proposed_sighash = first_proposal.block.header.signer_signature_hash();

    info!("------------------------- Inject block rejections -------------------------");
    let reward_cycle = signer_test.get_current_reward_cycle();
    let signer_slots = signer_test
        .get_signer_slots(reward_cycle)
        .expect("Failed to get signer slots");

    for (i, signer_private_key) in signer_test.signer_stacks_private_keys.iter().enumerate() {
        let mut rejection = BlockRejection::new(
            proposed_sighash.clone(),
            RejectReason::ValidationFailed(reject_code),
            signer_private_key,
            false, // testnet
            get_epoch_time_secs().saturating_add(u64::MAX),
            get_epoch_time_secs().saturating_add(u64::MAX),
        );
        rejection.response_data.failed_txid = Some(txid_a0.clone());

        let message = SignerMessage::BlockResponse(BlockResponse::Rejected(rejection));

        let signers_contract_id =
            MessageSlotID::BlockResponse.stacker_db_contract(false, reward_cycle);
        let mut session = StackerDBSession::new(
            &signer_test.running_nodes.conf.node.rpc_bind,
            signers_contract_id,
            signer_test.running_nodes.conf.miner.stackerdb_timeout,
        );

        let signer_addr = to_addr(signer_private_key);
        let slot_id = signer_slots
            .iter()
            .position(|(addr, _)| addr == &signer_addr)
            .expect("Signer not found in slot list") as u32;

        info!("------------------------- Manually submitting signer {i} (slot {slot_id}) block rejection -------------------------");
        let mut accepted = false;
        let mut version = 0;
        let start = Instant::now();
        while !accepted {
            let mut chunk = StackerDBChunkData::new(slot_id, version, message.serialize_to_vec());
            chunk
                .sign(signer_private_key)
                .expect("Failed to sign message chunk");
            let result = session.put_chunk(&chunk).expect("Failed to put chunk");
            accepted = result.accepted;
            version += 1;
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "Timed out waiting for signer {i} rejection to be accepted"
            );
        }
    }
    test_observer::clear();
    // Allow signers to handle the block proposal again
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);
    // Unpause mining so the miner can re-propose a block without the failed_txid
    TEST_MINE_SKIP.set(false);

    info!("------------------------- Wait to mine second block -------------------------");
    let second_block = wait_for_block_pushed_by_miner_key(30, expected_height, &miner_pubk)
        .expect("Miner did not propose a second block");
    info!("------------------------- Verify second block excludes sender A's txs -------------------------");
    let second_txids: Vec<_> = second_block.txs.iter().map(|tx| tx.txid()).collect();
    assert_eq!(
        second_txids.len(),
        2,
        "Second block should contain 2 transactions (sender B's only)"
    );
    assert!(
        !second_txids.contains(&txid_a0),
        "Second block must NOT contain sender A tx 0 (it was marked as failed_txid)"
    );
    assert!(
        !second_txids.contains(&txid_a1),
        "Second block must NOT contain sender A tx 1 (nonce gap due to excluded nonce 0)"
    );
    assert!(
        second_txids.contains(&txid_b0),
        "Second block should contain sender B tx 0"
    );
    assert!(
        second_txids.contains(&txid_b1),
        "Second block should contain sender B tx 1"
    );

    FailedTxTestContext {
        signer_test,
        sender_b_sk,
        txid_a0,
        txid_a1,
    }
}

#[tag(bitcoind)]
#[test]
#[ignore]
/// Test that when a signer rejects a block with a `failed_txid`, the miner
/// excludes that transaction (and any nonce-dependent successors from the
/// same sender) from the next block proposal only. The exclusion is not
/// permanent — the miner re-includes the transactions in the subsequent block.
///
/// Test Assertions:
/// - The second block excludes sender A's nonce-0 tx (banned) and
///   sender A's nonce-1 tx (can't include due to nonce gap), but includes
///   sender B's 2 transfers.
/// - The third block re-includes sender A's txs (the ban was only for
///   the immediately next block proposal).
fn miner_excludes_failed_txid_and_nonce_dependent_txs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let ctx = setup_failed_tx_test(ValidateRejectCode::BadTransaction);

    let miner_pubk = StacksPublicKey::from_private(ctx.signer_test.get_miner_key());

    info!("------------------------- Wait for third block with sender A's txs -------------------------");
    // The exclusion only lasts one block, so the miner should re-include sender A's txs
    let third_block = wait_for_block_pushed_by_miner_key(
        30,
        ctx.signer_test.get_peer_info().stacks_tip_height + 1,
        &miner_pubk,
    )
    .expect("Miner did not mine a third block");
    let third_txids: Vec<_> = third_block.txs.iter().map(|tx| tx.txid()).collect();
    assert!(
        third_txids.contains(&ctx.txid_a0),
        "Third block should contain sender A tx 0 (exclusion only lasts one block)"
    );
    assert!(
        third_txids.contains(&ctx.txid_a1),
        "Third block should contain sender A tx 1 (nonce gap resolved after nonce 0 re-included)"
    );
    info!("------------------------- Shutdown -------------------------");
    ctx.signer_test.shutdown();
}

#[tag(bitcoind)]
#[test]
#[ignore]
/// Test that when signers reject a block with a `failed_txid` and reject code
/// `ProblematicTransaction`, the miner permanently bans that transaction from
/// the mempool (via `drop_and_blacklist_txs`). Unlike the `BadTransaction`
/// case where the exclusion lasts only one block, a problematic transaction
/// should never reappear in subsequent proposals.
///
/// Test Assertions:
/// - The second block excludes sender A's nonce-0 tx (blacklisted) and
///   sender A's nonce-1 tx (can't include due to nonce gap), but includes
///   sender B's 2 transfers.
/// - The third block still excludes sender A's txs (permanent ban, unlike
///   the `BadTransaction` case where they would come back).
fn miner_permanently_bans_problematic_txid() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let ctx = setup_failed_tx_test(ValidateRejectCode::ProblematicTransaction);

    let miner_pubk = StacksPublicKey::from_private(ctx.signer_test.get_miner_key());
    let http_origin = ctx.signer_test.running_nodes.rpc_origin();
    let chain_id = ctx.signer_test.running_nodes.conf.burnchain.chain_id;
    let send_fee = 300;
    let send_amt = 1_000;
    let recipient = clarity::vm::types::PrincipalData::from(StacksAddress::burn_address(false));

    info!("------------------------- Wait for third block — sender A's txs should STILL be excluded -------------------------");
    // Trigger another block mine by submitting a third sender B transaction
    let tx_b2 = make_stacks_transfer_serialized(
        &ctx.sender_b_sk,
        2,
        send_fee,
        chain_id,
        &recipient,
        send_amt,
    );
    let txid_b2_hex =
        submit_tx_fallible(&http_origin, &tx_b2).expect("Failed to submit sender B tx 2");
    info!("Submitted sender B tx 2: {txid_b2_hex}");
    let txid_b2 = Txid::from_hex(&txid_b2_hex).expect("Failed to parse txid_b2");

    // Unlike BadTransaction where the exclusion only lasts one block,
    // ProblematicTransaction causes a permanent ban via drop_and_blacklist_txs.
    // Sender A's txs should NOT come back.
    let third_block = wait_for_block_pushed_by_miner_key(
        30,
        ctx.signer_test.get_peer_info().stacks_tip_height + 1,
        &miner_pubk,
    )
    .expect("Miner did not mine a third block");
    let third_txids: Vec<_> = third_block.txs.iter().map(|tx| tx.txid()).collect();
    assert_eq!(
        third_txids.len(),
        1,
        "Third block should contain 1 transaction (sender B's nonce 2)"
    );
    assert!(
        !third_txids.contains(&ctx.txid_a0),
        "Third block must NOT contain sender A tx 0 (permanently blacklisted as problematic)"
    );
    assert!(
        !third_txids.contains(&ctx.txid_a1),
        "Third block must NOT contain sender A tx 1 (nonce gap — nonce 0 permanently blacklisted)"
    );
    assert!(
        third_txids.contains(&txid_b2),
        "Third block should contain sender B tx 2 (new tx to trigger mining)"
    );
    info!("------------------------- Shutdown -------------------------");
    ctx.signer_test.shutdown();
}
