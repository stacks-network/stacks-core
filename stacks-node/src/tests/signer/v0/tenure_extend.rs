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
use std::collections::{HashMap, HashSet};
use std::ops::Add;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::{env, thread};

use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::{BlockResponse, RejectCode, RejectReason, SignerMessage};
use pinny::tag;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction};
use stacks::chainstate::stacks::{TenureChangeCause, TenureChangePayload};
use stacks::codec::StacksMessageCodec;
use stacks::config::DEFAULT_MAX_TENURE_BYTES;
use stacks::core::test_util::{
    make_contract_call, make_contract_publish, make_stacks_transfer_serialized,
    make_tenure_change_tx,
};
use stacks::core::StacksEpochId;
use stacks::net::api::postblock_proposal::TEST_VALIDATE_DELAY_DURATION_SECS;
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::{hex_bytes, Hash160, Sha512Trunc256Sum};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::bitvec::BitVec;
use stacks_common::util::sleep_ms;
use stacks_signer::chainstate::v1::SortitionsView;
use stacks_signer::chainstate::ProposalEvalConfig;
use stacks_signer::config::DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS;
use stacks_signer::v0::SpawnedSigner;
use stdext::prelude::DurationExt;
use tracing_subscriber::{fmt, EnvFilter};

use super::{SignerTest, *};
use crate::clarity::vm::clarity::ClarityConnection;
use crate::nakamoto_node::miner::{
    fault_injection_stall_miner, fault_injection_unstall_miner, TEST_BROADCAST_PROPOSAL_STALL,
};
use crate::nakamoto_node::relayer::TEST_MINER_COMMIT_TIP;
use crate::nakamoto_node::stackerdb_listener::TEST_IGNORE_SIGNERS;
use crate::neon::Counters;
use crate::tests::nakamoto_integrations::{next_block_and, wait_for};
use crate::tests::neon_integrations::{
    get_account, get_chain_info, submit_tx, submit_tx_fallible, test_observer,
    wait_for_tenure_change_tx,
};
use crate::tests::{self};

#[test]
#[ignore]
/// This test verifies that a miner will produce a read-count
/// extension after the signers' read count idle timeout is reached.
fn read_count_extend_after_idle_signers() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let idle_timeout = Duration::from_secs(30);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |config| {
            // use a different timeout to ensure that the correct timeout
            //  is read by the miner
            config.tenure_idle_timeout = Duration::from_secs(36000);
            config.read_count_idle_timeout = idle_timeout;
        },
        |node_config| {
            node_config.miner.tenure_extend_cost_threshold = 0;
            node_config.miner.read_count_extend_cost_threshold = 0;

            // boot directly to epoch 3.3
            let epochs = node_config.burnchain.epochs.as_mut().unwrap();
            let epoch_30_height = epochs[StacksEpochId::Epoch30].start_height;

            epochs[StacksEpochId::Epoch30].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch33].start_height = epoch_30_height;
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();

    info!("---- Nakamoto booted, starting test ----");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    info!("---- Waiting for a tenure extend ----");

    // Now, wait for a block with a tenure extend
    wait_for(idle_timeout.as_secs() + 10, || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::ExtendedReadCount,
        ))
    })
    .expect("Timed out waiting for a block with a tenure extend");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a miner will produce a TenureExtend transaction after the signers' idle timeout is reached.
fn tenure_extend_after_idle_signers() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let idle_timeout = Duration::from_secs(30);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
        },
        |config| {
            config.miner.tenure_extend_cost_threshold = 0;
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();

    info!("---- Nakamoto booted, starting test ----");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    info!("---- Waiting for a tenure extend ----");

    // Now, wait for a block with a tenure extend
    wait_for(idle_timeout.as_secs() + 10, || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::Extended,
        ))
    })
    .expect("Timed out waiting for a block with a tenure extend");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a miner will include other transactions with a TenureExtend transaction.
fn tenure_extend_with_other_transactions() {
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
    let idle_timeout = Duration::from_secs(30);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * 2)],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
            config.tenure_idle_timeout_buffer = Duration::from_secs(1);
        },
        |config| {
            config.miner.tenure_extend_cost_threshold = 0;
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
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    info!("---- Nakamoto booted, starting test ----");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    info!("Pause miner so it doesn't propose a block before the tenure extend");
    fault_injection_stall_miner();

    info!("---- Trigger a block proposal but pause its broadcast ----");
    let stacks_tip_height = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;
    // Submit a transaction to force a response from signers that indicate that the tenure extend timeout is exceeded
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let _ = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;

    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk]);
    fault_injection_unstall_miner();

    info!("---- Wait for tenure extend timeout ----");
    sleep_ms(idle_timeout.as_millis() as u64 + 5);

    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);
    fault_injection_stall_miner();
    // Submit a transaction to be included with the tenure extend
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let to_find = submit_tx(&http_origin, &transfer_tx);

    info!("---- Resume miner to propose a block with the tenure extend and transfer tx ----");
    fault_injection_unstall_miner();
    // Now, wait for a block with a tenure extend
    let block = wait_for_tenure_change_tx(
        idle_timeout.as_secs() + 10,
        TenureChangeCause::Extended,
        stacks_tip_height + 2,
    )
    .expect("Timed out waiting for a block with a tenure extend");
    let transactions = block["transactions"].as_array().unwrap();
    assert!(
        transactions.len() > 1,
        "Expected at least 2 transactions in the block"
    );
    assert!(
        transactions.iter().any(|tx| {
            let tx = tx.as_object().unwrap();
            let txid = tx["txid"].as_str().unwrap();
            txid[2..] == to_find
        }),
        "Failed to find the transfer tx in the block"
    );
    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a miner will produce a TenureExtend transaction
/// after the signers' idle timeout, plus buffer, is reached.
fn tenure_extend_after_idle_signers_with_buffer() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let idle_timeout = Duration::from_secs(1);
    let buffer = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
            config.tenure_idle_timeout_buffer = buffer;
        },
        |config| {
            config.miner.tenure_extend_cost_threshold = 0;
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();

    info!("---- Nakamoto booted, starting test ----");
    // Get the unix timestamp before the block is mined
    let before_timestamp = get_epoch_time_secs();
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    // Check the tenure extend timestamps to verify that they have factored in the buffer
    let blocks = test_observer::get_mined_nakamoto_blocks();
    let last_block = blocks.last().expect("No blocks mined");
    let timestamps: HashSet<_> = test_observer::get_stackerdb_chunks()
        .into_iter()
        .flat_map(|chunk| chunk.modified_slots)
        .filter_map(|chunk| {
            let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                .expect("Failed to deserialize SignerMessage");

            match message {
                SignerMessage::BlockResponse(BlockResponse::Accepted(accepted))
                    if accepted.signer_signature_hash == last_block.signer_signature_hash =>
                {
                    Some(accepted.response_data.tenure_extend_timestamp)
                }
                _ => None,
            }
        })
        .collect();
    for timestamp in timestamps {
        assert!(
            timestamp >= before_timestamp + buffer.as_secs(),
            "Timestamp {} is not greater than or equal to {}",
            timestamp,
            before_timestamp + buffer.as_secs()
        );
    }

    info!("---- Waiting for a tenure extend ----");

    // Now, wait for a block with a tenure extend, to make sure it eventually does extend
    wait_for((idle_timeout + buffer * 2).as_secs(), || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::Extended,
        ))
    })
    .expect("Timed out waiting for a block with a tenure extend");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a miner will produce a TenureExtend transaction after the miner's idle timeout
/// even if they do not see the signers' tenure extend timestamp responses.
fn tenure_extend_after_idle_miner() {
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
    let _recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let idle_timeout = Duration::from_secs(30);
    let miner_idle_timeout = idle_timeout + Duration::from_secs(10);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
        },
        |config| {
            config.miner.tenure_timeout = miner_idle_timeout;
            config.miner.tenure_extend_cost_threshold = 0;
        },
        None,
        None,
    );
    let _http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    info!("---- Nakamoto booted, starting test ----");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    info!("---- Start a new tenure but ignore block signatures so no timestamps are recorded ----");
    let tip_height_before = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;
    TEST_IGNORE_SIGNERS.set(true);
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        30,
        || {
            let tip_height = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;
            Ok(tip_height > tip_height_before)
        },
    )
    .expect("Failed to mine the tenure change block");

    // Now, wait for a block with a tenure change due to the new block
    wait_for_tenure_change_tx(30, TenureChangeCause::BlockFound, tip_height_before + 1)
        .expect("Timed out waiting for a block with a tenure change");

    info!("---- Waiting for a tenure extend ----");

    TEST_IGNORE_SIGNERS.set(false);
    // Now, wait for a block with a tenure extend
    wait_for_tenure_change_tx(
        miner_idle_timeout.as_secs() + 20,
        TenureChangeCause::Extended,
        tip_height_before + 2,
    )
    .expect("Timed out waiting for a block with a tenure extend");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a miner that attempts to produce a tenure extend too early will be rejected by the signers,
/// but will eventually succeed after the signers' idle timeout has passed.
fn tenure_extend_succeeds_after_rejected_attempt() {
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
    let _recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let idle_timeout = Duration::from_secs(30);
    let miner_idle_timeout = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
        },
        |config| {
            config.miner.tenure_timeout = miner_idle_timeout;
            config.miner.tenure_extend_cost_threshold = 0;
        },
        None,
        None,
    );
    let _http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    signer_test.boot_to_epoch_3();

    info!("---- Nakamoto booted, starting test ----");
    let stacks_tip_height = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    info!("---- Waiting for a rejected tenure extend ----");
    // Now, wait for a block with a tenure extend proposal from the miner, but ensure it is rejected.
    let proposed_block = wait_for_block_proposal_block(30, stacks_tip_height + 2, &miner_pk)
        .expect("Timed out waiting for a tenure extend proposal");
    wait_for_block_global_rejection(
        30,
        &proposed_block.header.signer_signature_hash(),
        num_signers,
    )
    .expect("Timed out waiting for a tenure extend proposal to be rejected");
    assert!(proposed_block
        .try_get_tenure_change_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::Extended));

    info!("---- Waiting for an accepted tenure extend ----");
    wait_for(idle_timeout.as_secs() + 10, || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::Extended,
        ))
    })
    .expect("Test timed out while waiting for an accepted tenure extend");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Verify that Nakamoto blocks that don't modify the tenure's execution cost
/// don't modify the idle timeout.
fn stx_transfers_dont_effect_idle_timeout() {
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
    let num_txs = 5;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let idle_timeout = Duration::from_secs(60);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * num_txs)],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
        },
        |config| {
            config.miner.tenure_extend_cost_threshold = 0;
        },
        None,
        None,
    );
    let naka_conf = signer_test.running_nodes.conf.clone();
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    // Add a delay to the block validation process
    TEST_VALIDATE_DELAY_DURATION_SECS.set(5);

    let info_before = signer_test.get_peer_info();
    let blocks_before = signer_test.running_nodes.counters.naka_mined_blocks.get();
    info!("---- Nakamoto booted, starting test ----";
        "info_height" => info_before.stacks_tip_height,
        "blocks_before" => blocks_before,
    );
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    info!("---- Getting current idle timeout ----");

    let reward_cycle = signer_test.get_current_reward_cycle();

    let signer_slot_ids = signer_test.get_signer_indices(reward_cycle).into_iter();
    assert_eq!(signer_slot_ids.count(), num_signers);

    let get_last_block_hash = || {
        let blocks = test_observer::get_blocks();
        let last_block = blocks.last().unwrap();
        let block_hash =
            hex_bytes(&last_block.get("block_hash").unwrap().as_str().unwrap()[2..]).unwrap();
        Sha512Trunc256Sum::from_vec(&block_hash).unwrap()
    };

    let last_block_hash = get_last_block_hash();

    let slot_id = 0_u32;

    let initial_acceptance = signer_test.get_latest_block_acceptance(slot_id);
    assert_eq!(initial_acceptance.signer_signature_hash, last_block_hash);

    info!(
        "---- Last idle timeout: {} ----",
        initial_acceptance.response_data.tenure_extend_timestamp
    );

    // Now, mine a few nakamoto blocks with just transfers

    let mut sender_nonce = 0;

    // Note that this response was BEFORE the block was globally accepted. it will report a guestimated idle time
    let initial_acceptance = initial_acceptance;
    let mut first_global_acceptance = None;
    for i in 0..num_txs {
        info!("---- Mining interim block {} ----", i + 1);
        signer_test.wait_for_nakamoto_block(30, || {
            let transfer_tx = make_stacks_transfer_serialized(
                &sender_sk,
                sender_nonce,
                send_fee,
                naka_conf.burnchain.chain_id,
                &recipient,
                send_amt,
            );
            submit_tx(&http_origin, &transfer_tx);
            sender_nonce += 1;
        });

        let latest_acceptance = signer_test.get_latest_block_acceptance(slot_id);
        let last_block_hash = get_last_block_hash();

        assert_eq!(latest_acceptance.signer_signature_hash, last_block_hash);

        if first_global_acceptance.is_none() {
            assert!(latest_acceptance.response_data.tenure_extend_timestamp < initial_acceptance.response_data.tenure_extend_timestamp, "First global acceptance should be less than initial guesstimated acceptance as its based on block proposal time rather than epoch time at time of response.");
            first_global_acceptance = Some(latest_acceptance);
        } else {
            // Because the block only contains transfers, the idle timeout should not have changed between blocks post the tenure change
            assert_eq!(
                latest_acceptance.response_data.tenure_extend_timestamp,
                first_global_acceptance
                    .as_ref()
                    .map(|acceptance| acceptance.response_data.tenure_extend_timestamp)
                    .unwrap()
            );
        };
    }

    info!("---- Waiting for a tenure extend ----");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Verify that a tenure extend will occur after an idle timeout
/// while actively mining.
fn idle_tenure_extend_active_mining() {
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
    let deployer_sk = Secp256k1PrivateKey::random();
    let deployer_addr = tests::to_addr(&deployer_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 5;
    let num_naka_blocks = 5;
    let tenure_count = 2;
    let tx_fee = 10000;
    let deploy_fee = 190200;
    let amount =
        deploy_fee + tx_fee * num_txs * tenure_count * num_naka_blocks * 100 + 100 * tenure_count;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let idle_timeout = Duration::from_secs(30);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, amount), (deployer_addr.clone(), amount)],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
        },
        |config| {
            // accept all proposals in the node
            config.connection_options.block_proposal_max_age_secs = u64::MAX;
            config.miner.tenure_extend_cost_threshold = 0;
        },
        None,
        None,
    );
    let naka_conf = signer_test.running_nodes.conf.clone();
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    let mut sender_nonces: HashMap<String, u64> = HashMap::new();

    let get_and_increment_nonce =
        |sender_sk: &Secp256k1PrivateKey, sender_nonces: &mut HashMap<String, u64>| {
            let nonce = sender_nonces.get(&sender_sk.to_hex()).unwrap_or(&0);
            let result = *nonce;
            sender_nonces.insert(sender_sk.to_hex(), result + 1);
            result
        };

    signer_test.boot_to_epoch_3();

    // Add a delay to the block validation process
    TEST_VALIDATE_DELAY_DURATION_SECS.set(3);

    signer_test.mine_nakamoto_block(Duration::from_secs(60), true);

    info!("---- Getting current idle timeout ----");

    let get_last_block_hash = || {
        let blocks = test_observer::get_blocks();
        let last_block = blocks.last().unwrap();
        let block_hash =
            hex_bytes(&last_block.get("block_hash").unwrap().as_str().unwrap()[2..]).unwrap();
        Sha512Trunc256Sum::from_vec(&block_hash).unwrap()
    };

    let slot_id = 0_u32;

    let log_idle_diff = |timestamp: u64| {
        let now = get_epoch_time_secs();
        let diff = timestamp.saturating_sub(now);
        info!("----- Idle diff: {diff} seconds -----");
    };

    let initial_response = signer_test.get_latest_block_response(slot_id);
    assert_eq!(
        initial_response.get_signer_signature_hash(),
        &get_last_block_hash()
    );

    info!(
        "---- Last idle timeout: {} ----",
        initial_response.get_tenure_extend_timestamp()
    );

    // Deploy a contract that will be called a lot

    let contract_src = format!(
        r#"
(define-data-var my-var uint u0)
(define-public (f) (begin {} (ok 1))) (begin (f))
        "#,
        ["(var-get my-var)"; 250].join(" ")
    );

    // First, lets deploy the contract
    let deployer_nonce = get_and_increment_nonce(&deployer_sk, &mut sender_nonces);
    let contract_tx = make_contract_publish(
        &deployer_sk,
        deployer_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "small-contract",
        &contract_src,
    );
    submit_tx(&http_origin, &contract_tx);

    // Wait for this transaction to be mined in a block
    info!("----- Submitted deploy txs, waiting for block -----");
    wait_for(60, || {
        Ok(get_account(&http_origin, &deployer_addr).nonce > deployer_nonce)
    })
    .unwrap();

    info!("----- Mining BTC block -----");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    let mut last_response = signer_test.get_latest_block_response(slot_id);

    // Make multiple tenures that get extended through idle timeouts
    for t in 1..=tenure_count {
        info!("----- Mining tenure {t} -----");
        log_idle_diff(last_response.get_tenure_extend_timestamp());
        // Now, start a tenure with contract calls
        for i in 1..=num_naka_blocks {
            // Just in case these Nakamoto blocks pass the idle timeout (probably because CI is slow), exit early
            if i != 1 && last_block_contains_tenure_change_tx(TenureChangeCause::Extended) {
                info!("---- Tenure extended before mining {i} nakamoto blocks -----");
                break;
            }
            info!("----- Mining nakamoto block {i} in tenure {t} -----");

            signer_test.wait_for_nakamoto_block(30, || {
                // Stall the miner while we submit transactions, so that they
                // are all included in the same block
                fault_injection_stall_miner();

                // Throw in a STX transfer to test mixed blocks
                let sender_nonce = get_and_increment_nonce(&sender_sk, &mut sender_nonces);
                let transfer_tx = make_stacks_transfer_serialized(
                    &sender_sk,
                    sender_nonce,
                    send_fee,
                    naka_conf.burnchain.chain_id,
                    &recipient,
                    send_amt,
                );
                submit_tx(&http_origin, &transfer_tx);

                for _ in 0..num_txs {
                    let deployer_nonce = get_and_increment_nonce(&deployer_sk, &mut sender_nonces);
                    // Fill up the mempool with contract calls
                    let contract_tx = make_contract_call(
                        &deployer_sk,
                        deployer_nonce,
                        tx_fee,
                        naka_conf.burnchain.chain_id,
                        &deployer_addr,
                        "small-contract",
                        "f",
                        &[],
                    );
                    match submit_tx_fallible(&http_origin, &contract_tx) {
                        Ok(_txid) => {}
                        Err(_e) => {
                            // If we fail to submit a tx, we need to make sure we don't
                            // increment the nonce for this sender, so we don't end up
                            // skipping a tx.
                            sender_nonces.insert(deployer_sk.to_hex(), deployer_nonce);
                        }
                    }
                }
                fault_injection_unstall_miner();
            });

            // We must actually have a new block response to ensure its tenure extend timestamp advances
            wait_for(30, || {
                Ok(signer_test.get_latest_block_response(slot_id) != last_response)
            })
            .expect("Failed to find a new block response");

            let latest_response = signer_test.get_latest_block_response(slot_id);
            let naka_blocks = test_observer::get_mined_nakamoto_blocks();
            info!(
                "----- Latest tenure extend timestamp: {} -----",
                latest_response.get_tenure_extend_timestamp()
            );
            log_idle_diff(latest_response.get_tenure_extend_timestamp());
            info!(
                "----- Latest block transaction events: {} -----",
                naka_blocks.last().unwrap().tx_events.len()
            );
            assert_eq!(
                latest_response.get_signer_signature_hash(),
                &get_last_block_hash(),
                "Expected the latest block response to be for the latest block"
            );
            assert_ne!(
                last_response.get_tenure_extend_timestamp(),
                latest_response.get_tenure_extend_timestamp(),
                "Tenure extend timestamp should change with each block"
            );
            last_response = latest_response;
        }

        let current_time = get_epoch_time_secs();
        let extend_diff = last_response
            .get_tenure_extend_timestamp()
            .saturating_sub(current_time);

        info!(
            "----- After mining {num_naka_blocks} nakamoto blocks in tenure {t}, waiting for TenureExtend -----";
            "tenure_extend_timestamp" => last_response.get_tenure_extend_timestamp(),
            "extend_diff" => extend_diff,
            "current_time" => current_time,
        );

        // Now, wait for the idle timeout to trigger
        wait_for(idle_timeout.as_secs() * 2, || {
            Ok(last_block_contains_tenure_change_tx(
                TenureChangeCause::Extended,
            ))
        })
        .expect("Expected a tenure extend after idle timeout");

        last_response = signer_test.get_latest_block_response(slot_id);

        info!("----- Tenure {t} extended -----");
        log_idle_diff(last_response.get_tenure_extend_timestamp());
    }

    // After the last extend, mine a few more naka blocks
    for i in 1..=num_naka_blocks {
        // Just in case these Nakamoto blocks pass the idle timeout (probably because CI is slow), exit early
        if i != 1 && last_block_contains_tenure_change_tx(TenureChangeCause::Extended) {
            info!("---- Tenure extended before mining {i} nakamoto blocks -----");
            break;
        }
        info!("----- Mining nakamoto block {i} after last tenure extend -----");

        signer_test.wait_for_nakamoto_block(30, || {
            // Throw in a STX transfer to test mixed blocks
            let sender_nonce = get_and_increment_nonce(&sender_sk, &mut sender_nonces);
            let transfer_tx = make_stacks_transfer_serialized(
                &sender_sk,
                sender_nonce,
                send_fee,
                naka_conf.burnchain.chain_id,
                &recipient,
                send_amt,
            );
            submit_tx(&http_origin, &transfer_tx);
        });
    }

    info!("------------------------- Test Shutdown -------------------------");
    signer_test.shutdown();
}

#[tag(bitcoind)]
#[test]
#[ignore]
/// Test that a signer will reject a SIP-034 tenure extension (for now).
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
///
/// Test Execution:
/// The stacks node is advanced to epoch 3.3 reward set calculation to ensure the signer set is determined.
/// A block proposal with a SIP-034 tenure extension is forcibly written to the miner's slot to
/// simulate the miner proposing a block.
///
/// The signers ought to reject the block before posting it to the Stacks node for validation,
/// since they are configured by default to reject such blocks until the appropriate throttling
/// logic can be written (post-SIP-034 activation)
///
/// The signer that submitted the initial block validation request, should issue a broadcast a rejection of the
/// miner's proposed block back to the respective .signers-XXX-YYY contract.
///
/// Test Assertion:
/// Each signer successfully rejects the invalid block proposal.
fn sip034_tenure_extend_proposal_rejection() {
    sip034_tenure_extend_proposal(
        false,
        &[
            TenureChangeCause::ExtendedReadLength,
            TenureChangeCause::ExtendedRuntime,
            TenureChangeCause::ExtendedWriteLength,
            TenureChangeCause::ExtendedWriteCount,
        ],
    )
}

#[tag(bitcoind)]
#[test]
#[ignore]
/// Test that a signer will allow a SIP-034 tenure extension (for now).
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
///
/// Test Execution:
/// The stacks node is advanced to epoch 3.3 reward set calculation to ensure the signer set is determined.
/// A block proposal with a SIP-034 tenure extension is forcibly written to the miner's slot to
/// simulate the miner proposing a block.
///
/// The signers ought to accept the block, given the (test-only) configuration override.
///
/// Test Assertion:
/// Each signer successfully accepts the block proposal.
fn sip034_tenure_extend_proposal_acceptance() {
    sip034_tenure_extend_proposal(true, &[TenureChangeCause::ExtendedReadCount])
}

fn sip034_tenure_extend_proposal(allow: bool, extend_types: &[TenureChangeCause]) {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |signer_config| {
            signer_config.tenure_idle_timeout = Duration::from_millis(0);
            signer_config.read_count_idle_timeout = Duration::from_millis(0);
        },
        |node_config| {
            // boot directly to epoch 3.3
            let epochs = node_config.burnchain.epochs.as_mut().unwrap();
            let epoch_30_height = epochs[StacksEpochId::Epoch30].start_height;

            epochs[StacksEpochId::Epoch30].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch33].start_height = epoch_30_height;
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();

    let naka_conf = signer_test.running_nodes.conf.clone();
    let all_signers = signer_test.signer_test_pks();
    let miner_sk = naka_conf.miner.mining_key.clone().unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let miner_addr = tests::to_addr(&miner_sk);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (mut chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    // confirm that we booted to epoch 3.3
    let epoch_version = chainstate.with_read_only_clarity_tx(
        &sortdb
            .index_handle_at_block(&chainstate, &tip.index_block_hash())
            .unwrap(),
        &tip.index_block_hash(),
        |conn| conn.with_clarity_db_readonly(|db| db.get_clarity_epoch_version().unwrap()),
    );

    assert_eq!(epoch_version, Some(StacksEpochId::Epoch33));

    let short_timeout = Duration::from_secs(30);
    let proposal_conf = ProposalEvalConfig {
        proposal_wait_for_parent_time: Duration::from_secs(0),
        first_proposal_burn_block_timing: Duration::from_secs(0),
        block_proposal_timeout: Duration::from_secs(100),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(30),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
        read_count_idle_timeout: Duration::from_secs(12000),
    };

    // Propose tenure-extends
    for (i, extend_cause) in extend_types.iter().enumerate() {
        // force timestamp to advance
        sleep_ms(2000);

        let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap();
        let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn())
            .expect("Failed to get sortition tip");
        let sort_tip_sn = SortitionDB::get_block_snapshot(sortdb.conn(), &sort_tip)
            .unwrap()
            .unwrap();
        let db_handle = sortdb.index_handle(&sort_tip);
        let snapshot = db_handle
            .get_block_snapshot(&tip.burn_header_hash)
            .expect("Failed to get block snapshot")
            .expect("No snapshot");

        let miner_account = get_account(&http_origin, &miner_addr);
        let total_burn = snapshot.total_burn;
        let tenure_cause = *extend_cause;
        let tenure_change = make_tenure_change_tx(
            &miner_sk,
            miner_account.nonce,
            0,
            naka_conf.burnchain.chain_id,
            TenureChangePayload {
                tenure_consensus_hash: sort_tip_sn.consensus_hash.clone(),
                prev_tenure_consensus_hash: tip.consensus_hash.clone(),
                burn_view_consensus_hash: sort_tip_sn.consensus_hash.clone(),
                previous_tenure_end: tip.index_block_hash(),
                previous_tenure_blocks: 1 + (i as u32),
                cause: tenure_cause,
                pubkey_hash: Hash160::from_node_public_key(&miner_pk),
            },
        );

        let mut block = {
            let mut builder = NakamotoBlockBuilder::new(
                &tip,
                &tip.consensus_hash,
                total_burn,
                Some(&tenure_change),
                None,
                1,
                None,
                None,
                None,
                u64::from(DEFAULT_MAX_TENURE_BYTES),
            )
            .expect("Failed to build Nakamoto block");

            let burn_dbconn = sortdb.index_handle_at_tip();
            let mut miner_tenure_info = builder
                .load_tenure_info(&mut chainstate, &burn_dbconn, tenure_cause.into())
                .unwrap();
            let burn_chain_height = miner_tenure_info.burn_tip_height;
            let mut tenure_tx = builder
                .tenure_begin(&burn_dbconn, &mut miner_tenure_info)
                .unwrap();

            builder
                .try_mine_tx_with_len(
                    &mut tenure_tx,
                    &tenure_change,
                    tenure_change.serialize_to_vec().len() as u64,
                    &BlockLimitFunction::NO_LIMIT_HIT,
                    None,
                    &mut 0,
                )
                .unwrap();
            let block = builder.mine_nakamoto_block(&mut tenure_tx, burn_chain_height);
            let _ = builder.tenure_finish(tenure_tx).unwrap();
            block
        };

        let view =
            SortitionsView::fetch_view(proposal_conf.clone(), &signer_test.stacks_client).unwrap();
        block.header.pox_treatment = BitVec::ones(1).unwrap();
        block.header.consensus_hash = view.cur_sortition.data.consensus_hash;

        block.header.sign_miner(&miner_sk).unwrap();
        let block_signer_signature_hash_tenure_extend = block.header.signer_signature_hash();

        info!(
            "Produced SIP-034 tenure-extend block with signer signature hash {}: {:?}",
            &block_signer_signature_hash_tenure_extend, &block
        );

        info!("------------------------- Send SIP-034 Tenure Extend for {:?} Block Proposal To Signers -------------------------", extend_cause);
        signer_test.propose_block(block.clone(), short_timeout);

        if allow {
            // wait for all signers to accept
            let _ = wait_for_block_acceptance_from_signers(
                short_timeout.as_secs(),
                &block_signer_signature_hash_tenure_extend,
                &all_signers,
            )
            .unwrap();
        } else {
            // wait for all signers to reject
            let rejections = wait_for_block_rejections_from_signers(
                short_timeout.as_secs(),
                &block_signer_signature_hash_tenure_extend,
                &all_signers,
            )
            .unwrap();

            for rejection in rejections {
                info!("Rejection: {:?}", &rejection);
                assert_eq!(
                    rejection.reason_code,
                    RejectCode::from(&RejectReason::InvalidTenureExtend)
                );
            }
        }
    }

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Scenario: 2 miners, and one winning miner commits to a stale tip.
/// We're verifying that, in this scenario, the tenure is extended,
/// instead of a new one being created (and forking the tip).
///
/// This test is quite similar to `tenure_extend_after_bad_commit`, but
/// with the difference of the fact that there are 2 blocks mined in tenure B,
/// which means signers will always reject a reorg attempt (regardless of timing).
///
/// - Miner 1 wins tenure A
/// - Miner 2 wins tenure B, with 2 blocks
/// - Miner 1 wins tenure C, but with a block commit to tip A
/// - We verify that Miner 1 extends Tenure B
fn tenure_extend_after_stale_commit_different_miner() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let num_txs = 5;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            signer_config.block_proposal_timeout = Duration::from_secs(60);
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pk_1, _) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    miners.pause_commits_miner_2();
    miners.boot_to_epoch_3();

    miners.pause_commits_miner_1();

    let sortdb = conf_1.get_burnchain().open_sortition_db(true).unwrap();

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .unwrap();

    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Wins Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .unwrap();
    verify_sortition_winner(&sortdb, &miner_pkh_1);
    miners.send_and_mine_transfer_tx(60).unwrap();
    let tip_a_height = miners.get_peer_stacks_tip_height();
    let prev_tip = get_chain_info(&conf_1);

    info!("------------------------- Miner 2 Wins Tenure B -------------------------");
    miners.submit_commit_miner_2(&sortdb);
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .unwrap();
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    miners.send_and_mine_transfer_tx(60).unwrap();
    let tip_b_height = miners.get_peer_stacks_tip_height();
    let tenure_b_ch = miners.get_peer_stacks_tip_ch();

    info!("------------------------- Miner 1 Wins Tenure C with stale commit -------------------------");

    // We can't use `submit_commit_miner_1` here because we are using the stale view
    {
        TEST_MINER_COMMIT_TIP.set(Some((prev_tip.pox_consensus, prev_tip.stacks_tip)));
        let rl1_commits_before = miners
            .signer_test
            .running_nodes
            .counters
            .naka_submitted_commits
            .load(Ordering::SeqCst);

        miners
            .signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .set(false);

        wait_for(30, || {
            let commits_after = miners
                .signer_test
                .running_nodes
                .counters
                .naka_submitted_commits
                .load(Ordering::SeqCst);
            let last_commit_tip = miners
                .signer_test
                .running_nodes
                .counters
                .naka_submitted_commit_last_stacks_tip
                .load(Ordering::SeqCst);

            Ok(commits_after > rl1_commits_before && last_commit_tip == prev_tip.stacks_tip_height)
        })
        .expect("Timed out waiting for miner 1 to submit a commit op");

        miners
            .signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .set(true);
        TEST_MINER_COMMIT_TIP.set(None);
    }

    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .unwrap();
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!(
        "------------------------- Miner 1's proposal for C is rejected -------------------------"
    );
    let proposed_block = wait_for_block_proposal_block(60, tip_a_height + 1, &miner_pk_1).unwrap();
    wait_for_block_global_rejection(
        60,
        &proposed_block.header.signer_signature_hash(),
        num_signers,
    )
    .unwrap();

    assert_eq!(miners.get_peer_stacks_tip_ch(), tenure_b_ch);

    info!("------------------------- Miner 2 Extends Tenure B -------------------------");
    wait_for_tenure_change_tx(60, TenureChangeCause::Extended, tip_b_height + 1).unwrap();

    let final_height = miners.get_peer_stacks_tip_height();
    assert_eq!(miners.get_peer_stacks_tip_ch(), tenure_b_ch);
    assert!(final_height >= tip_b_height + 1);

    miners.shutdown();
}

#[test]
#[ignore]
/// Scenario: same miner extends tenure when the block-commit for the next tenure still confirms N-1
///
/// Flow:
/// - Miner A wins tenure N
/// - Miner A submits a block-commit confirming N-1 (commit submitted before N's block gets approved)
/// - Miner A mines at least 2 blocks in tenure N
/// - Miner A wins tenure N+1 with the stale commit (confirming N-1)
/// - Miner A cannot mine a normal tenure-change + coinbase in N+1 (would reorg its own N blocks)
/// - Miner A should issue a TenureExtend on top of tenure N
fn tenure_extend_after_stale_commit_same_miner() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |signer_cfg| {
                signer_cfg.block_proposal_timeout = Duration::from_minutes(60);
            },
            |node_cfg| {
                node_cfg.miner.block_commit_delay = Duration::from_secs(0);
            },
            None,
            None,
            Some(function_name!()),
        );

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = &signer_test.running_nodes.conf;
    let miner_pk =
        StacksPublicKey::from_private(&conf.miner.mining_key.clone().expect("Missing mining key"));
    let miner_pkh = Hash160::from_node_public_key(&miner_pk);
    let sortdb = conf.get_burnchain().open_sortition_db(true).unwrap();

    let pre_test_tenures = 4;
    for i in 1..=pre_test_tenures {
        info!("Mining pre-test tenure {i} of {pre_test_tenures}");
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    // We are now in "N-1"
    let prev_tip = get_chain_info(&signer_test.running_nodes.conf);

    info!("---- Waiting for block-commit to N-1 ----";
        "Current height" => prev_tip.burn_block_height,
    );

    let Counters {
        naka_skip_commit_op: skip_commit_op,
        naka_submitted_commit_last_burn_height: last_commit_burn_height,
        ..
    } = signer_test.running_nodes.counters.clone();

    wait_for(30, || {
        let last_height = last_commit_burn_height.get();
        Ok(last_height == prev_tip.burn_block_height)
    })
    .expect("Timed out waiting for block-commit to N-1");

    skip_commit_op.set(true);

    let prev_tip = get_chain_info(&signer_test.running_nodes.conf);

    signer_test.mine_nakamoto_block_without_commit(Duration::from_secs(30), true);

    TEST_MINER_COMMIT_TIP.set(Some((prev_tip.pox_consensus, prev_tip.stacks_tip)));

    // Now in tenure N

    // Mine a second block in tenure N to ensure that
    // signers will reject a reorg attempt
    let (_, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .unwrap();

    skip_commit_op.set(false);

    info!("---- Waiting for block commit to N-1 ----");

    wait_for(30, || {
        let last_height = last_commit_burn_height.get();
        Ok(last_height == prev_tip.burn_block_height)
    })
    .expect("Timed out waiting for block commit to N-1");

    // Start a new tenure (N+1)

    let info_before = get_chain_info(conf);
    let stacks_height_before = info_before.stacks_tip_height;

    signer_test.mine_bitcoin_block();

    verify_sortition_winner(&sortdb, &miner_pkh);

    info!("---- Waiting for a tenure extend block in tenure N+1 ----";
        "stacks_height_before" => stacks_height_before,
    );

    wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal in tenure N+1");

    // Verify that the next block is a TenureExtend at the expected height
    wait_for_tenure_change_tx(30, TenureChangeCause::Extended, stacks_height_before + 1)
        .expect("Timed out waiting for a TenureExtend block atop tenure N in tenure N+1");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Scenario: same miner extends tenure when the block-commit for the next tenure still confirms N-1
///
/// Flow:
/// - Miner A wins tenure N
/// - Miner A submits a block-commit confirming N-1 (commit submitted before N's block gets approved)
/// - Miner A mines at least 2 blocks in tenure N
/// - Miner A wins tenure N+1 with the stale commit (confirming N-1)
/// - Miner A cannot mine a normal tenure-change + coinbase in N+1 (would reorg its own N blocks)
/// - Miner A should issue a TenureExtend on top of tenure N
/// - The next sortition has no winner, so Miner A should again issue a TenureExtend on top of tenure N
fn tenure_extend_after_stale_commit_same_miner_then_no_winner() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |signer_cfg| {
                signer_cfg.block_proposal_timeout = Duration::from_minutes(60);
            },
            |node_cfg| {
                node_cfg.miner.block_commit_delay = Duration::from_secs(0);
            },
            None,
            None,
            Some(function_name!()),
        );

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = &signer_test.running_nodes.conf;
    let miner_pk =
        StacksPublicKey::from_private(&conf.miner.mining_key.clone().expect("Missing mining key"));
    let miner_pkh = Hash160::from_node_public_key(&miner_pk);
    let sortdb = conf.get_burnchain().open_sortition_db(true).unwrap();

    let pre_test_tenures = 4;
    for i in 1..=pre_test_tenures {
        info!("Mining pre-test tenure {i} of {pre_test_tenures}");
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    // We are now in "N-1"
    let prev_tip = get_chain_info(&signer_test.running_nodes.conf);

    info!("---- Waiting for block-commit to N-1 ----";
        "Current height" => prev_tip.burn_block_height,
    );

    let Counters {
        naka_skip_commit_op: skip_commit_op,
        naka_submitted_commit_last_burn_height: last_commit_burn_height,
        ..
    } = signer_test.running_nodes.counters.clone();

    wait_for(30, || {
        let last_height = last_commit_burn_height.get();
        Ok(last_height == prev_tip.burn_block_height)
    })
    .expect("Timed out waiting for block-commit to N-1");

    skip_commit_op.set(true);

    let prev_tip = get_chain_info(&signer_test.running_nodes.conf);

    signer_test.mine_nakamoto_block_without_commit(Duration::from_secs(30), true);

    TEST_MINER_COMMIT_TIP.set(Some((prev_tip.pox_consensus, prev_tip.stacks_tip)));

    // Now in tenure N

    // Mine a second block in tenure N to ensure that
    // signers will reject a reorg attempt
    let (_, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .unwrap();

    skip_commit_op.set(false);

    info!("---- Waiting for block commit to N-1 ----");

    wait_for(30, || {
        let last_height = last_commit_burn_height.get();
        Ok(last_height == prev_tip.burn_block_height)
    })
    .expect("Timed out waiting for block commit to N-1");

    // Start a new tenure (N+1)

    let info_before = get_chain_info(conf);
    let stacks_height_before = info_before.stacks_tip_height;

    // Don't submit any block commits in this upcoming tenure
    skip_commit_op.set(true);

    signer_test.mine_bitcoin_block();

    verify_sortition_winner(&sortdb, &miner_pkh);

    info!("---- Waiting for a tenure extend block in tenure N+1 ----";
        "stacks_height_before" => stacks_height_before,
    );

    wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal in tenure N+1");

    // Verify that the next block is a TenureExtend at the expected height
    wait_for_tenure_change_tx(30, TenureChangeCause::Extended, stacks_height_before + 1)
        .expect("Timed out waiting for a TenureExtend block atop tenure N in tenure N+1");

    wait_for(30, || {
        let info = get_chain_info(conf);
        Ok(info.stacks_tip_height == stacks_height_before + 1)
    })
    .expect("Timed out waiting for stacks tip to advance after tenure extend");

    let info_before = get_chain_info(conf);
    let stacks_height_before = info_before.stacks_tip_height;

    // Now, mine the next bitcoin block, which should have no winner
    signer_test.mine_bitcoin_block();

    info!("---- Waiting for a tenure extend block in tenure N+2 ----";
        "stacks_height_before" => stacks_height_before,
    );

    wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal in tenure N+1");

    // Verify that the next block is a TenureExtend at the expected height
    wait_for_tenure_change_tx(30, TenureChangeCause::Extended, stacks_height_before + 1)
        .expect("Timed out waiting for a TenureExtend block atop tenure N in tenure N+2");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a miner will produce a TenureExtend transaction
/// only after it has reached the cost threshold.
fn tenure_extend_cost_threshold() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let deployer_sk = Secp256k1PrivateKey::random();
    let deployer_addr = tests::to_addr(&deployer_sk);
    let num_txs = 10;
    let tx_fee = 10000;
    let deploy_fee = 190200;

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let idle_timeout = Duration::from_secs(10);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(deployer_addr.clone(), deploy_fee + tx_fee * num_txs)],
        |config| {
            config.tenure_idle_timeout = idle_timeout;
        },
        |config| {
            config.miner.tenure_extend_cost_threshold = 5;
        },
        None,
        None,
    );
    let naka_conf = signer_test.running_nodes.conf.clone();
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    info!("---- Nakamoto booted, starting test ----");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    info!("---- Waiting for a tenure extend ----");

    // Now, wait for a block with a tenure extend
    wait_for(idle_timeout.as_secs() + 10, || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::Extended,
        ))
    })
    .expect_err("Received a tenure extend before cost threshold was reached");

    // Now deploy a contract and call it in order to cross the threshold.
    let contract_src = format!(
        r#"
(define-data-var my-var uint u0)
(define-public (f) (begin {} (ok 1))) (begin (f))
        "#,
        ["(var-get my-var)"; 250].join(" ")
    );

    // First, lets deploy the contract
    let mut nonce = 0;
    let contract_tx = make_contract_publish(
        &deployer_sk,
        nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "small-contract",
        &contract_src,
    );
    submit_tx(&http_origin, &contract_tx);
    nonce += 1;

    // Wait for the contract to be included in a block
    wait_for(60, || {
        let account = get_account(&http_origin, &deployer_addr);
        Ok(account.nonce == nonce)
    })
    .expect("Contract not included in block");

    // Ensure the tenure was not extended in that block
    assert!(!last_block_contains_tenure_change_tx(
        TenureChangeCause::Extended
    ));

    // Now, lets call the contract a bunch of times to increase the tenure cost
    for _ in 0..num_txs {
        let call_tx = make_contract_call(
            &deployer_sk,
            nonce,
            tx_fee,
            naka_conf.burnchain.chain_id,
            &deployer_addr,
            "small-contract",
            "f",
            &[],
        );
        submit_tx(&http_origin, &call_tx);
        nonce += 1;
    }

    // Now, wait for a block with a tenure extend
    wait_for(idle_timeout.as_secs() + 10, || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::Extended,
        ))
    })
    .expect("Timed out waiting for a block with a tenure extend");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that a miner will extend its tenure after the succeding miner fails to mine a block.
/// - Miner 1 wins a tenure and mines normally
/// - Miner 2 wins a tenure but fails to mine a block
/// - Miner 1 extends its tenure
fn tenure_extend_after_failed_miner() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 2;
    let block_proposal_timeout = Duration::from_secs(30);
    let tenure_extend_wait_timeout = block_proposal_timeout;

    info!("------------------------- Test Setup -------------------------");
    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            signer_config.block_proposal_timeout = block_proposal_timeout;
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    info!("------------------------- Miner 1 Wins Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to start Tenure A");

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 1 Mines Another Block -------------------------");
    // submit a tx so that the miner will mine an extra block
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");

    info!("------------------------- Pause Block Proposals -------------------------");
    fault_injection_stall_miner();
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Miner 2 Wins Tenure B, Mines No Blocks -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    test_observer::clear();
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");

    // assure we have a successful sortition that miner B won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("------------------------- Wait for Block Proposal Timeout -------------------------");
    sleep_ms(block_proposal_timeout.as_millis() as u64 * 2);

    info!("------------------------- Miner 1 Extends Tenure A -------------------------");
    let info_before = get_chain_info(&conf_1);
    wait_for_state_machine_update(
        30,
        &info_before.pox_consensus,
        info_before.burn_block_height,
        Some((miner_pkh_1.clone(), starting_peer_height)),
        &miners.signer_test.signer_addresses_versions(),
    )
    .expect("Failed to update signer state");
    // Re-enable block mining, for both miners.
    // Since miner B has been offline, it won't be able to mine.
    fault_injection_unstall_miner();

    // wait for a tenure extend block from miner 1 to be processed
    wait_for_tenure_change_tx(30, TenureChangeCause::Extended, stacks_height_before + 1)
        .expect("Failed to mine tenure extend tx");

    info!("------------------------- Miner 1 Mines Another Block -------------------------");

    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");

    miners.shutdown();
}

#[test]
#[ignore]
/// Test that a miner will extend its tenure after the succeding miner commits to the wrong block.
///
/// This test is quite similar to `tenure_extend_after_stale_commit_different_miner`,
/// with the difference that signers will reject a reorg attempt due to the reorg attempt
/// being more than `first_proposal_burn_block_timing` seconds.
///
/// - Miner 1 wins a tenure and mines normally
/// - Miner 1 wins another tenure and mines normally, but miner 2 does not see any blocks from this tenure
/// - Miner 2 wins a tenure and is unable to mine a block
/// - Miner 1 extends its tenure and mines an additional block
/// - Miner 2 wins the next tenure and mines normally
fn tenure_extend_after_bad_commit() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 2;

    let first_proposal_burn_block_timing = Duration::from_secs(1);
    let block_proposal_timeout = Duration::from_secs(30);
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            signer_config.block_proposal_timeout = block_proposal_timeout;
            signer_config.first_proposal_burn_block_timing = first_proposal_burn_block_timing;
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

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

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

    info!("------------------------- Pause Block Proposals -------------------------");
    fault_injection_stall_miner();
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Wins Tenure B -------------------------");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");
    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("----------------- Miner 2 Submits Block Commit Before Any Blocks ------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("----------------------------- Resume Block Production -----------------------------");

    let stacks_height_before = miners.get_peer_stacks_tip_height();
    fault_injection_unstall_miner();

    wait_for_tenure_change_tx(30, TenureChangeCause::BlockFound, stacks_height_before + 1)
        .expect("Failed to mine tenure change tx");

    info!("--------------- Miner 2 Wins Tenure C With Old Block Commit ----------------");
    // Sleep enough time to pass the first proposal burn block timing
    let sleep_duration = first_proposal_burn_block_timing.saturating_add(Duration::from_secs(2));
    info!(
        "Sleeping for {} seconds before issuing next burn block.",
        sleep_duration.as_secs()
    );
    thread::sleep(sleep_duration);

    info!("--------------- Miner 1 Extends Tenure B over Tenure C ---------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::Extended, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");

    // assure we have a successful sortition that miner 2
    verify_sortition_winner(&sortdb, &miner_pkh_2);

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
}

#[test]
#[ignore]
/// Test that a miner will extend its tenure after the succeeding miner commits to the wrong block.
/// - Miner 1 wins a tenure and mines normally
/// - Miner 1 wins another tenure and mines normally, but miner 2 does not see any blocks from this tenure
/// - Miner 2 wins a tenure and is unable to mine a block
/// - Miner 1 extends its tenure and mines an additional block
/// - Miner 2 wins another tenure and is still unable to mine a block
/// - Miner 1 extends its tenure again and mines an additional block
/// - Miner 2 wins the next tenure and mines normally
fn tenure_extend_after_2_bad_commits() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 2;

    let block_proposal_timeout = Duration::from_secs(30);

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            signer_config.block_proposal_timeout = block_proposal_timeout;
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
    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Wins Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by tenure change tx");

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 1 Mines Another Block -------------------------");
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");
    let stacks_height_before = miners.get_peer_stacks_tip_height();

    info!("------------------------- Pause Block Proposals -------------------------");
    fault_injection_stall_miner();
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Wins Tenure B -------------------------");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("----------------- Miner 2 Submits Block Commit Before Any Blocks ------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("----------------------------- Resume Block Production -----------------------------");

    fault_injection_unstall_miner();
    wait_for_tenure_change_tx(30, TenureChangeCause::BlockFound, stacks_height_before + 1)
        .expect("Failed to mine tenure change tx");

    info!("--------------- Miner 2 Wins Tenure C With Old Block Commit ----------------");
    // Pause block production again so that we can make sure miner 2 commits
    // to the wrong block again.
    fault_injection_stall_miner();

    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("---------- Miner 2 Submits Block Commit Before Any Blocks (again) ----------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Miner 1 Extends Tenure B -------------------------");

    fault_injection_unstall_miner();

    // wait for a tenure extend block from miner 1 to be processed
    // (miner 2's proposals will be rejected)
    wait_for_tenure_change_tx(60, TenureChangeCause::Extended, stacks_height_before + 2)
        .expect("Failed to mine tenure extend tx");

    info!("------------------------- Miner 1 Mines Another Block -------------------------");
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");

    info!("------------ Miner 2 Wins Tenure C With Old Block Commit (again) -----------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to mine BTC block");

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    miners.submit_commit_miner_2(&sortdb);

    info!("---------------------- Miner 1 Extends Tenure B (again) ---------------------");

    fault_injection_unstall_miner();

    // wait for a tenure extend block from miner 1 to be processed
    // (miner 2's proposals will be rejected)
    wait_for_tenure_change_tx(30, TenureChangeCause::Extended, stacks_height_before + 1)
        .expect("Failed to mine tenure extend tx");

    info!("------------------------- Miner 1 Mines Another Block -------------------------");
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");

    info!("----------------------- Miner 2 Mines the Next Tenure -----------------------");
    miners.submit_commit_miner_2(&sortdb);

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");

    // assure we have a successful sortition that miner 2 won and it had a block found tenure change
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    miners.shutdown();
}

/// Test a scenario where a previous miner can extend a tenure when it is favoured by signers over the incoming miner.
/// Two miners boot to Nakamoto.
/// Miner 1 wins the first tenure.
/// Miner 1 proposes a block N with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N
/// Miner 2 wins the second tenure B.
/// Miner 2 proposes block N+1' AFTER signers' block proposal timeout.
/// Signers reject block N+1' and mark miner 2 as malicious
/// Miner 1 proposes block N+1 with a TenureChangeCause::Extended
/// Signers accept and the stacks tip advances to N+1
/// Miner 2 wins the third tenure C and proposes a block N+2 with a TenureChangeCause::BlockFound
/// Signers accept block N+2.
///
/// Asserts:
/// - Block N contains the TenureChangeCause::BlockFound
/// - Block N+1 contains the TenureChangeCause::Extended
/// - Block N+2 contains the TenureChangeCause::BlockFound
/// - The stacks tip advances to N+2
#[test]
#[ignore]
fn prev_miner_extends_if_incoming_miner_fails_to_mine_success() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;

    let block_proposal_timeout = Duration::from_secs(30);
    let tenure_extend_wait_timeout = block_proposal_timeout;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |signer_config| {
            signer_config.block_proposal_timeout = block_proposal_timeout;
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
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

    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Timed out mining BTC block followed by tenure change tx");
    btc_blocks_mined += 1;

    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    // Pause the block proposal broadcast so that miner 2 will be unable to broadcast its
    // tenure change proposal BEFORE the block_proposal_timeout and will be marked invalid.
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_2.clone()]);

    info!("------------------------- Miner 2 Mines an Empty Tenure B -------------------------");
    test_observer::clear();
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Timed out waiting for BTC block");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    info!(
        "------------------------- Wait for Miner 2 to be Marked Invalid -------------------------"
    );
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    let chain_before = get_chain_info(&miners.signer_test.running_nodes.conf);
    // Make sure that miner 2 gets marked invalid by not proposing a block BEFORE block_proposal_timeout
    wait_for_state_machine_update(
        block_proposal_timeout.as_secs() + 30,
        &chain_before.pox_consensus,
        chain_before.burn_block_height,
        Some((miner_pkh_1, stacks_height_before.saturating_sub(1))),
        &miners.signer_test.signer_addresses_versions(),
    )
    .expect("Timed out waiting for Miner 2 be marked Invalid");

    // Unpause miner 2's block proposal broadcast
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    info!("------------------------- Wait for Miner 1's Block N+1 to be Mined ------------------------";
        "stacks_height_before" => %stacks_height_before);

    let miner_1_block_n_1 =
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_1)
            .expect("Timed out waiting for block proposal N+1 from miner 1");

    let miner_2_block_n_1 =
        wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_2)
            .expect("Timed out waiting for block proposal N+1' from miner 2");
    info!("------------------------- Verify Miner 2's N+1' was Rejected -------------------------");
    wait_for_block_global_rejection(
        30,
        &miner_2_block_n_1.header.signer_signature_hash(),
        num_signers,
    )
    .expect("Timed out waiting for global rejection of Miner 2's block N+1'");

    let peer_info = miners.get_peer_info();
    assert_eq!(peer_info.stacks_tip, miner_1_block_n_1.header.block_hash());
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before + 1);

    info!(
        "------------------------- Verify Tenure Change Extend Tx in Miner 1's Block N+1 -------------------------"
    );
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::Extended);

    info!("------------------------- Unpause Miner 2's Block Commits -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Miner 2 Mines a Normal Tenure C -------------------------");

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by a tenure change tx");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(
        miners.get_peer_stacks_tip_height(),
        starting_peer_height + 3
    );
    miners.shutdown();
}

/// Test a scenario where a previous miner is unable to extend its tenure if the signers are configured to favour the incoming miner.
/// Two miners boot to Nakamoto.
/// Miner 1 wins the first tenure A.
/// Miner 1 proposes a block N with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N
/// Miner 2 wins the second tenure B.
/// Miner 2 is paused and cannot propose block N+1.
/// Miner 1 attempts to extend tenure A with block N+1' containg a TenureChangeCause::Extended
/// Signers reject block N+1' and the stacks tip remains at N
/// Miner 2 is unpaused
/// Miner 2 proposes block N+1 with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N+1
/// Miner 2 wins the third tenure C
/// Miner 2 proposes block N+2 with a TenureChangeCause::BlockFound
///
/// Asserts:
/// - Block N contains the TenureChangeCause::BlockFound
/// - Block N+1' contains a TenureChangeCause::Extended and is rejected
/// - Block N+1 contains the TenureChangeCause::BlockFound
/// - Block N+2 contains the TenureChangeCause::BlockFound
/// - The stacks tip advances to N+2
#[test]
#[ignore]
fn prev_miner_extends_if_incoming_miner_fails_to_mine_failure() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;

    // Ensure Miner 1 will attempt to extend BEFORE signers are willing to consider it.
    let block_proposal_timeout = Duration::from_secs(500); // make it way in the future so miner 1 is rejected
    let tenure_extend_wait_timeout = Duration::from_secs(30);

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |signer_config| {
            signer_config.block_proposal_timeout = block_proposal_timeout;
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
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
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by a tenure change tx");
    btc_blocks_mined += 1;

    // Confirm that Miner 1 won the tenure.
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners.submit_commit_miner_2(&sortdb);

    let burn_height_before = get_burn_height();

    // Pause the block proposal broadcast so that miner 2 will be unable to broadcast its
    // tenure change proposal BEFORE miner 1 attempts to extend.
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_2.clone()]);

    info!("------------------------- Miner 2 Wins Tenure B -------------------------";
        "burn_height_before" => burn_height_before,
        "stacks_height_before" => %stacks_height_before
    );
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Failed to mine BTC block");
    btc_blocks_mined += 1;

    assert_eq!(stacks_height_before, miners.get_peer_stacks_tip_height());

    // Confirm that Miner 2 won the tenure.
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!(
        "------------------------- Wait for Miner 1 to think Miner 2 is Invalid -------------------------"
    );
    // Make sure that miner 1 thinks miner 2 is invalid.
    std::thread::sleep(tenure_extend_wait_timeout.add(Duration::from_secs(1)));

    info!("------------------------- Wait for Miner 1's Block N+1' to be Proposed ------------------------";
        "stacks_height_before" => %stacks_height_before);

    let miner_1_block_n_1 =
        wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_1)
            .expect("Timed out waiting for N+1' block proposal from miner 1");
    assert!(miner_1_block_n_1
        .try_get_tenure_change_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::Extended));

    info!("------------------------- Verify that Miner 1's Block N+1' was Rejected ------------------------");
    // Miner 1's proposed block should get rejected by the signers
    wait_for_block_global_rejection(
        30,
        &miner_1_block_n_1.header.signer_signature_hash(),
        num_signers,
    )
    .expect("Timed out waiting for Block N+1' to be globally rejected");

    assert_eq!(stacks_height_before, miners.get_peer_stacks_tip_height());

    info!("------------------------- Wait for Miner 2's Block N+1 BlockFound to be Proposed ------------------------";
        "stacks_height_before" => %stacks_height_before
    );

    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    // Get miner 2's N+1 block proposal
    let miner_2_block_n_1 =
        wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_2)
            .expect("Timed out waiting for N+1 block proposal from miner 2");

    info!("------------------------- Wait for Miner 2's Block N+1 to be Approved ------------------------";
        "stacks_height_before" => %stacks_height_before
    );

    // Miner 2's proposed block should get approved and pushed
    let miner_2_block_n_1 =
        wait_for_block_pushed(30, &miner_2_block_n_1.header.signer_signature_hash())
            .expect("Timed out waiting for Block N+1 to be pushed");

    let peer_info = miners.get_peer_info();
    assert_eq!(peer_info.stacks_tip, miner_2_block_n_1.header.block_hash());
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before + 1);

    info!(
        "------------------------- Verify BlockFound in Miner 2's Block N+1 -------------------------"
    );
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::BlockFound);

    info!("------------------------- Unpause Miner 2's Block Commits -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    info!("------------------------- Miner 2 Mines a Normal Tenure C -------------------------");

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by a tenure change tx");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    info!(
        "------------------------- Verify Tenure Change Tx in Miner 2's Block N+2 -------------------------"
    );
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::BlockFound);

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(
        miners.get_peer_stacks_tip_height(),
        starting_peer_height + 3
    );

    miners.shutdown();
}

/// Test a scenario where:
/// Two miners boot to Nakamoto.
/// Miner 1 wins the first tenure A.
/// Miner 1 proposes a block N with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N
/// Miner 2 wins the second tenure B.
/// Miner 2 proposes block N+1 with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N+1
/// Miner 1 never issues a TenureExtend transaction
/// Miner 2 wins the third tenure C
/// Miner 2 proposes block N+2 with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N+2
///
/// Asserts:
/// - Block N contains the TenureChangeCause::BlockFound
/// - Block N+1 contains the TenureChangeCause::BlockFound
/// - Block N+2 contains the TenureChangeCause::BlockFound
/// - The stacks tip advances to N+2
/// - Miner 1 does not produce a tenure extend block at all
#[test]
#[ignore]
fn prev_miner_will_not_attempt_to_extend_if_incoming_miner_produces_a_block() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;

    let block_proposal_timeout = Duration::from_secs(100);
    let tenure_extend_wait_timeout = Duration::from_secs(20);
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |signer_config| {
            signer_config.block_proposal_timeout = block_proposal_timeout;
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by a tenure change tx");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner A won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners.submit_commit_miner_2(&sortdb);

    let burn_height_before = get_burn_height();

    info!("------------------------- Miner 2 Mines Tenure B -------------------------";
        "burn_height_before" => burn_height_before,
        "stacks_height_before" => stacks_height_before
    );
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("------------------------- Get Miner 2's N+1 block -------------------------");

    let miner_2_block_n_1 =
        wait_for_block_proposal_block(60, stacks_height_before + 1, &miner_pk_2)
            .expect("Timed out waiting for N+1 block proposal from miner 2");
    let miner_2_block_n_1 =
        wait_for_block_pushed(30, &miner_2_block_n_1.header.signer_signature_hash())
            .expect("Timed out waiting for N+1 block to be approved");

    let peer_info = miners.get_peer_info();
    assert_eq!(peer_info.stacks_tip, miner_2_block_n_1.header.block_hash());
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before + 1);

    let stacks_height_before = peer_info.stacks_tip_height;

    info!("------------------------- Ensure Miner 1 Never Isues a Tenure Extend -------------------------";
        "stacks_height_before" => %stacks_height_before);

    // Ensure the tenure extend wait timeout is passed so if a miner was going to extend, it would be now.
    std::thread::sleep(tenure_extend_wait_timeout.add(Duration::from_secs(1)));

    assert!(
        wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_1).is_err(),
        "Miner 1 should not have proposed a block N+1'"
    );

    assert_eq!(stacks_height_before, miners.get_peer_stacks_tip_height());

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(stacks_height_before, starting_peer_height + 2);
    miners.shutdown();
}

#[test]
#[ignore]
/// Test that we can mine a tenure extend and then continue mining afterwards.
fn continue_after_tenure_extend() {
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
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, (send_amt + send_fee) * 5)]);
    let timeout = Duration::from_secs(200);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    let burnchain = signer_test.running_nodes.conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    signer_test.boot_to_epoch_3();
    info!("------------------------- Mine A Normal Tenure -------------------------");
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers, true);

    info!("------------------------- Pause Block Commits-------------------------");
    signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .set(true);
    info!("------------------------- Flush Pending Commits -------------------------");
    // Mine a couple blocks to flush the last submitted commit out.
    let peer_info = signer_test.get_peer_info();
    let burn_height_before = peer_info.burn_block_height;
    let stacks_height_before = peer_info.stacks_tip_height;
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(2);
    wait_for(30, || {
        let peer_info = signer_test.get_peer_info();
        Ok(peer_info.burn_block_height > burn_height_before + 1)
    })
    .expect("Timed out waiting for burn block height to increase");
    // assure we have NO sortition
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert!(!tip.sortition);

    info!("------------------------- Extend Tenure -------------------------");
    wait_for_tenure_change_tx(30, TenureChangeCause::Extended, stacks_height_before + 2)
        .expect("Timed out waiting for tenure change tx");

    // Verify that the miner can continue mining in the tenure with the tenure extend
    info!("------------------------- Mine After Tenure Extend -------------------------");
    for sender_nonce in 0..5 {
        let stacks_height_before = signer_test.get_peer_info().stacks_tip_height;
        // submit a tx so that the miner will mine an extra block
        let transfer_tx = make_stacks_transfer_serialized(
            &sender_sk,
            sender_nonce,
            send_fee,
            signer_test.running_nodes.conf.burnchain.chain_id,
            &recipient,
            send_amt,
        );
        submit_tx(&http_origin, &transfer_tx);
        info!("Submitted transfer tx and waiting for block proposal");
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk)
            .expect("Timed out waiting to mine block");
    }

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks the behavior of `burn-block-height` within a normal
/// Nakamoto block and within a tenure-extend block.
fn burn_block_height_behavior() {
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
    let deployer_sk = Secp256k1PrivateKey::random();
    let deployer_addr = tests::to_addr(&deployer_sk);
    let tx_fee = 10000;
    let deploy_fee = 200000;
    let block_proposal_timeout = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![
            (sender_addr, send_amt + send_fee),
            (deployer_addr.clone(), deploy_fee + tx_fee * 3),
        ],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    let Counters {
        naka_skip_commit_op: skip_commit_op,
        ..
    } = signer_test.running_nodes.counters.clone();

    info!("------------------------- Test Mine Regular Tenure A  -------------------------");

    let contract_src = "(define-public (foo) (ok burn-block-height))";

    // First, lets deploy the contract
    let mut deployer_nonce = 0;
    let contract_tx = make_contract_publish(
        &deployer_sk,
        deployer_nonce,
        deploy_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        "foo",
        &contract_src,
    );
    submit_tx(&http_origin, &contract_tx);
    deployer_nonce += 1;

    // Wait for this transaction to be mined in a block
    info!("----- Submitted deploy txs, waiting for block -----");
    wait_for(60, || {
        Ok(get_account(&http_origin, &deployer_addr).nonce == deployer_nonce)
    })
    .unwrap();

    // Stall block commits, so the next block will have no sortition
    skip_commit_op.set(true);

    // Mine a regular tenure
    signer_test.mine_nakamoto_block_without_commit(Duration::from_secs(30), true);

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info.stacks_tip_height;
    let burn_height_before = info.burn_block_height;

    info!("------------------------- submit contract call 1 -------------------------");
    let call_tx = make_contract_call(
        &deployer_sk,
        deployer_nonce,
        tx_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &deployer_addr,
        "foo",
        "foo",
        &[],
    );
    let txid = submit_tx(&http_origin, &call_tx);
    deployer_nonce += 1;

    info!("------------------------- wait for the call tx to be mined -------------------------");
    // Wait for the call tx to be mined in a new Nakamoto block
    wait_for(60, || {
        test_observer::get_mined_nakamoto_blocks()
            .last()
            .and_then(|block| {
                block.tx_events.iter().find_map(|tx| match tx {
                    TransactionEvent::Success(tx) if tx.txid.to_string() == txid => {
                        let result = tx
                            .result
                            .clone()
                            .expect_result_ok()
                            .ok()?
                            .expect_u128()
                            .ok()?;
                        Some(result)
                    }
                    _ => None,
                })
            })
            .map_or(Ok(false), |result_height| {
                assert_eq!(result_height, burn_height_before as u128);
                Ok(true)
            })
    })
    .expect("Timed out waiting for call tx to be mined");

    info!("------------------------- Wait for the block to be processed -------------------------");
    // Wait for the block to be processed
    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Timed out waiting for block to be processed");

    // Stall mining, so that the next call will get included in the tenure extend block
    fault_injection_stall_miner();

    // Wait to ensure the miner reaches the stalled state
    // This is necessary because it's possible that the miner will mine the
    // following transaction before reaching the stall state, causing the test
    // to be flaky.
    sleep_ms(5000);

    info!("------------------------- submit contract call 2 -------------------------");
    let call_tx = make_contract_call(
        &deployer_sk,
        deployer_nonce,
        tx_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &deployer_addr,
        "foo",
        "foo",
        &[],
    );
    let txid = submit_tx(&http_origin, &call_tx);

    info!(
        "------------------------- mine bitcoin block with no sortition -------------------------"
    );
    let info = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info.stacks_tip_height;
    let burn_height_before = info.burn_block_height;

    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.burn_block_height == burn_height_before + 1)
    })
    .expect("Failed to advance chain tip");

    info!("------------------------- wait for tenure change block -------------------------");

    // Resume mining and wait for the next block to be mined
    fault_injection_unstall_miner();
    wait_for_tenure_change_tx(60, TenureChangeCause::Extended, stacks_height_before + 1)
        .expect("Timed out waiting for tenure extend");

    let blocks = test_observer::get_mined_nakamoto_blocks();
    let last_block = blocks.last().unwrap();
    let txs = &last_block.tx_events;
    assert_eq!(txs.len(), 2, "Expected 2 txs in the tenure extend block");
    let _tenure_extend_tx = txs.first().unwrap();
    let call_tx = txs.last().unwrap();
    match call_tx {
        TransactionEvent::Success(tx) => {
            if tx.txid.to_string() == txid {
                let result_height = tx
                    .result
                    .clone()
                    .expect_result_ok()
                    .unwrap()
                    .expect_u128()
                    .unwrap();
                assert_eq!(result_height, burn_height_before as u128 + 1);
            }
        }
        _ => {}
    }

    info!("------------------------- shutdown -------------------------");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Scenario: burn block arrives while miner is in the middle of mining a block.
///
/// Flow:
/// - Miner wins tenure N
/// - Miner mines tenure change block and one additional block in tenure N
/// - Block validation is paused so the next block proposal cannot be accepted yet
/// - Miner proposes block M
/// - Next burn block, N+1 arrives, with no block commits, so no sortition winner
/// - Unpause block validation, block M is accepted
/// - Miner mines tenure extend in block M+1
fn new_tenure_no_winner_while_proposing_block() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |signer_cfg| {
                signer_cfg.block_proposal_timeout = Duration::from_minutes(60);
            },
            |node_cfg| {
                node_cfg.miner.block_commit_delay = Duration::from_secs(0);
            },
            None,
            None,
            Some(function_name!()),
        );

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = &signer_test.running_nodes.conf;
    let miner_pk =
        StacksPublicKey::from_private(&conf.miner.mining_key.clone().expect("Missing mining key"));

    let pre_test_tenures = 4;
    for i in 1..=pre_test_tenures {
        info!("Mining pre-test tenure {i} of {pre_test_tenures}");
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    // We are now in "N-1"
    let prev_tip = get_chain_info(&signer_test.running_nodes.conf);

    info!("---- Waiting for block-commit to N-1 ----";
        "Current height" => prev_tip.burn_block_height,
    );

    let Counters {
        naka_skip_commit_op: skip_commit_op,
        naka_submitted_commit_last_burn_height: last_commit_burn_height,
        ..
    } = signer_test.running_nodes.counters.clone();

    wait_for(30, || {
        let last_height = last_commit_burn_height.get();
        Ok(last_height == prev_tip.burn_block_height)
    })
    .expect("Timed out waiting for block-commit to N-1");

    // Disable block commits so that N+1 has no winner
    skip_commit_op.set(true);

    info!("---- Mining two blocks in tenure N ----");
    signer_test.mine_nakamoto_block_without_commit(Duration::from_secs(30), true);

    // Now in tenure N

    // Mine a second block in tenure N
    let (_, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .unwrap();

    // Pause block validation so that the next proposal cannot be accepted yet
    TEST_VALIDATE_STALL.set(true);

    info!("---- Proposing 3rd block in tenure N ----");

    // Mine a third block in tenure N
    signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info_before.stacks_tip_height;

    // Wait for the block proposal to be issued
    let proposed_block = wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal in tenure N");

    // Mine a new burn block, N+1, which should have no sortition winner
    info!("---- Mining burn block N+1 with no sortition winner ----");

    signer_test.mine_bitcoin_block();
    let info_after = get_chain_info(conf);
    wait_for_state_machine_update(
        30,
        &info_after.pox_consensus,
        info_after.burn_block_height,
        None,
        &signer_test.signer_addresses_versions(),
    )
    .expect("Timed out waiting for the signers to update their state");

    info!("---- Unpausing block validation ----");
    TEST_VALIDATE_STALL.set(false);

    info!("---- Waiting for original block proposal acceptance after unpausing validation ----");
    wait_for_block_global_acceptance_from_signers(
        30,
        &proposed_block.header.signer_signature_hash(),
        &signer_test.signer_test_pks(),
    )
    .expect("Timed out waiting for block acceptance after unpausing validation");

    // Verify that the next block is a TenureExtend at the expected height
    info!(
        "---- Waiting for a tenure extend block at height {} ----",
        proposed_block.header.chain_length + 1
    );
    wait_for_tenure_change_tx(
        30,
        TenureChangeCause::Extended,
        proposed_block.header.chain_length + 1,
    )
    .expect("Timed out waiting for a TenureExtend block atop tenure N in tenure N+1");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Scenario: burn block arrives while miner is in the middle of mining a block.
///
/// Flow:
/// - Miner wins tenure N
/// - Miner mines tenure change block and one additional block in tenure N
/// - Block validation is paused so the next block proposal cannot be accepted yet
/// - Miner proposes block M
/// - Next burn block, N+1 arrives, with no block commits, so no sortition winner
/// - Unpause block validation and force signers to reject
/// - Miner mines tenure extend in block M' when signers stop rejecting
fn new_tenure_no_winner_while_proposing_block_then_rejected() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |signer_cfg| {
                signer_cfg.block_proposal_timeout = Duration::from_minutes(60);
            },
            |node_cfg| {
                node_cfg.miner.block_commit_delay = Duration::from_secs(0);
            },
            None,
            None,
            Some(function_name!()),
        );

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = &signer_test.running_nodes.conf;
    let miner_pk =
        StacksPublicKey::from_private(&conf.miner.mining_key.clone().expect("Missing mining key"));

    let pre_test_tenures = 4;
    for i in 1..=pre_test_tenures {
        info!("Mining pre-test tenure {i} of {pre_test_tenures}");
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    // We are now in "N-1"
    let prev_tip = get_chain_info(&signer_test.running_nodes.conf);

    info!("---- Waiting for block-commit to N-1 ----";
        "Current height" => prev_tip.burn_block_height,
    );

    let Counters {
        naka_skip_commit_op: skip_commit_op,
        naka_submitted_commit_last_burn_height: last_commit_burn_height,
        ..
    } = signer_test.running_nodes.counters.clone();

    wait_for(30, || {
        let last_height = last_commit_burn_height.get();
        Ok(last_height == prev_tip.burn_block_height)
    })
    .expect("Timed out waiting for block-commit to N-1");

    // Disable block commits so that N+1 has no winner
    skip_commit_op.set(true);

    info!("---- Mining two blocks in tenure N ----");
    signer_test.mine_nakamoto_block_without_commit(Duration::from_secs(30), true);

    // Now in tenure N

    // Mine a second block in tenure N
    let (_, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .unwrap();

    // Pause block validation so that the next proposal cannot be accepted yet
    TEST_VALIDATE_STALL.set(true);

    info!("---- Proposing 3rd block in tenure N ----");

    // make all signers reject the block
    let rejecting_signers: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .take(num_signers)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers);

    // And pause the signers from sending the block responses as well
    TEST_STALL_BLOCK_RESPONSE.set(true);

    // Mine a third block in tenure N
    let (_, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info_before.stacks_tip_height;

    // Wait for the block proposal to be issued
    let proposed_block = wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal in tenure N");
    info!(
        "---- Proposed block {} at height {} ----",
        proposed_block.header.signer_signature_hash(),
        proposed_block.header.chain_length
    );

    // Now stall the miner so that it cannot propose a new block
    fault_injection_try_stall_miner();

    // Mine a new burn block, N+1, which should have no sortition winner
    info!("---- Mining burn block N+1 with no sortition winner ----");

    signer_test.mine_bitcoin_block();

    info!("---- Unpausing block validation and block response ----");
    TEST_VALIDATE_STALL.set(false);
    TEST_STALL_BLOCK_RESPONSE.set(false);

    info!("---- Waiting for original block proposal rejection after unpausing validation ----");
    wait_for_block_global_rejection(
        30,
        &proposed_block.header.signer_signature_hash(),
        num_signers,
    )
    .expect("Timed out waiting for block rejection after unpausing validation");

    // Stop the signers from rejecting all blocks
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);

    // Unstall the miner
    fault_injection_unstall_miner();

    // Verify that the next block is a TenureExtend at the expected height
    info!(
        "---- Waiting for a tenure extend block at height {} ----",
        proposed_block.header.chain_length
    );
    wait_for_tenure_change_tx(
        30,
        TenureChangeCause::Extended,
        proposed_block.header.chain_length,
    )
    .expect("Timed out waiting for a TenureExtend block atop tenure N in tenure N+1");

    // That last block should have also included the transfer
    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .unwrap();

    let info = get_chain_info(conf);
    assert_eq!(
        info.stacks_tip_height, proposed_block.header.chain_length,
        "Stacks tip height should be equal to the proposed block height"
    );

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Scenario: burn block arrives while miner is in the middle of mining a block.
///
/// Flow:
/// - Miner wins tenure N
/// - Miner mines tenure change block and one additional block in tenure N
/// - Block validation is paused so the next block proposal cannot be accepted yet
/// - Miner proposes block M, but it is ignored by the signers
/// - Next burn block, N+1 arrives, with no block commits, so no sortition winner
/// - Miner mines tenure extend in block M'
fn new_tenure_no_winner_while_proposing_block_then_ignored() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |signer_cfg| {
                signer_cfg.block_proposal_timeout = Duration::from_minutes(60);
            },
            |node_cfg| {
                node_cfg.miner.block_commit_delay = Duration::from_secs(0);
            },
            None,
            None,
            Some(function_name!()),
        );

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = &signer_test.running_nodes.conf;
    let miner_pk =
        StacksPublicKey::from_private(&conf.miner.mining_key.clone().expect("Missing mining key"));

    let pre_test_tenures = 4;
    for i in 1..=pre_test_tenures {
        info!("Mining pre-test tenure {i} of {pre_test_tenures}");
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    }

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    // We are now in "N-1"
    let prev_tip = get_chain_info(&signer_test.running_nodes.conf);

    info!("---- Waiting for block-commit to N-1 ----";
        "Current height" => prev_tip.burn_block_height,
    );

    let Counters {
        naka_skip_commit_op: skip_commit_op,
        naka_submitted_commit_last_burn_height: last_commit_burn_height,
        ..
    } = signer_test.running_nodes.counters.clone();

    wait_for(30, || {
        let last_height = last_commit_burn_height.get();
        Ok(last_height == prev_tip.burn_block_height)
    })
    .expect("Timed out waiting for block-commit to N-1");

    // Disable block commits so that N+1 has no winner
    skip_commit_op.set(true);

    info!("---- Mining two blocks in tenure N ----");
    signer_test.mine_nakamoto_block_without_commit(Duration::from_secs(30), true);

    // Now in tenure N

    // Mine a second block in tenure N
    let (_, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .unwrap();

    // Pause block validation so that the next proposal cannot be accepted yet
    TEST_VALIDATE_STALL.set(true);

    info!("---- Proposing 3rd block in tenure N ----");

    // make all signers ignore the block
    let ignoring_signers: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .take(num_signers)
        .collect();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignoring_signers);

    // Mine a third block in tenure N
    let (_, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .unwrap();

    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info_before.stacks_tip_height;

    // Wait for the block proposal to be issued
    let proposed_block = wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk)
        .expect("Timed out waiting for block proposal in tenure N");
    info!(
        "---- Proposed block {} at height {} ----",
        proposed_block.header.signer_signature_hash(),
        proposed_block.header.chain_length
    );

    // Now stall the miner so that it cannot propose a new block
    fault_injection_try_stall_miner();

    // Mine a new burn block, N+1, which should have no sortition winner
    info!("---- Mining burn block N+1 with no sortition winner ----");

    signer_test.mine_bitcoin_block();

    info!("---- Unpausing block validation and block response ----");
    TEST_VALIDATE_STALL.set(false);
    TEST_STALL_BLOCK_RESPONSE.set(false);

    // Stop the signers from ignoring all blocks
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);

    // Unstall the miner
    fault_injection_unstall_miner();

    // Verify that the next block is a TenureExtend at the expected height
    info!(
        "---- Waiting for a tenure extend block at height {} ----",
        proposed_block.header.chain_length
    );
    wait_for_tenure_change_tx(
        30,
        TenureChangeCause::Extended,
        proposed_block.header.chain_length,
    )
    .expect("Timed out waiting for a TenureExtend block atop tenure N in tenure N+1");

    // That last block should have also included the transfer
    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .unwrap();

    let info = get_chain_info(conf);
    assert_eq!(
        info.stacks_tip_height, proposed_block.header.chain_length,
        "Stacks tip height should be equal to the proposed block height"
    );

    signer_test.shutdown();
}

/// Test a scenario where a non-blocking minority of signers are configured to favour the incoming miner.
/// The previous miner should extend its tenure and succeed as a majority are configured to favour it
/// and its subsequent blocks should be be approved.
/// Two miners boot to Nakamoto.
/// Miner 1 wins the first tenure A.
/// Miner 1 proposes a block N with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N
/// Miner 2 wins the second tenure B.
/// A majority of signers mark miner 2 as invalid.
/// Miner 2 proposes block N+1' with a TenureChangeCause::BlockFound
/// A majority fo signers reject block N+1'.
/// Miner 1 proposes block N+1 with a TenureChangeCause::Extended
/// A majority of signers accept and the stacks tip advances to N+1
/// Miner 1 proposes block N+2 with a transfer tx
/// ALL signers should accept block N+2.
/// Miner 2 wins the third tenure C.
/// Miner 2 proposes block N+3 with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N+3
///
/// Asserts:
/// - Block N contains the TenureChangeCause::BlockFound
/// - Block N+1' contains a TenureChangeCause::BlockFound and is rejected
/// - Block N+1 contains the TenureChangeCause::Extended
/// - Block N+2 is accepted.
/// - Block N+3 contains the TenureChangeCause::BlockFound.
/// - The stacks tip advances to N+3
#[test]
#[ignore]
fn non_blocking_minority_configured_to_favour_incoming_miner() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 1;
    let non_block_minority = num_signers * 2 / 10;

    let favour_prev_miner_block_proposal_timeout = Duration::from_secs(20);
    let favour_incoming_miner_block_proposal_timeout = Duration::from_secs(500);
    // Make sure the miner attempts to extend after the minority mark the incoming as invalid
    let tenure_extend_wait_timeout = favour_prev_miner_block_proposal_timeout;

    info!("------------------------- Test Setup -------------------------");
    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            let port = signer_config.endpoint.port();
            // Note signer ports are based on the number of them, the first being 3000, the last being 3000 + num_signers - 1
            if port < 3000 + non_block_minority as u16 {
                signer_config.block_proposal_timeout = favour_incoming_miner_block_proposal_timeout;
            } else {
                signer_config.block_proposal_timeout = favour_prev_miner_block_proposal_timeout;
            }
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to start Tenure A");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners.submit_commit_miner_2(&sortdb);
    let burn_height_before = get_burn_height();
    // Pause the block proposal broadcast so that miner 2 AND miner 1 are unable to propose
    // a block BEFORE block_proposal_timeout
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_2.clone(), miner_pk_1.clone()]);

    info!("------------------------- Miner 2 Wins Tenure B -------------------------";
        "burn_height_before" => burn_height_before,
        "stacks_height_before" => %stacks_height_before
    );
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to start Tenure B");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!(
        "------------------------- Wait for Miner 2 to be Marked Invalid by a Majority of Signers -------------------------"
    );
    // Make sure that miner 1 and a majority of signers thinks miner 2 is invalid.
    std::thread::sleep(tenure_extend_wait_timeout.add(Duration::from_secs(1)));

    // Allow miner 2 to attempt to start their tenure.
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1.clone()]);

    info!("------------------------- Wait for Miner 2's Block N+1' to be Proposed ------------------------";
        "stacks_height_before" => %stacks_height_before);

    let miner_2_block_n_1 =
        wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_2)
            .expect("Miner 2 did not propose Block N+1'");

    assert!(miner_2_block_n_1
        .try_get_tenure_change_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::BlockFound));

    info!("------------------------- Verify that Miner 2's Block N+1' was Rejected ------------------------");

    // Miner 2's proposed block should get rejected by the signers
    wait_for_block_global_rejection(
        30,
        &miner_2_block_n_1.header.signer_signature_hash(),
        num_signers,
    )
    .expect("Timed out waiting for Block N+1' to be globally rejected");

    assert_eq!(miners.get_peer_stacks_tip_height(), stacks_height_before,);

    info!("------------------------- Wait for Miner 1's Block N+1 Extended to be Mined ------------------------";
        "stacks_height_before" => %stacks_height_before
    );

    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    // Get miner 1's N+1 block proposal
    let miner_1_block_n_1 =
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_1)
            .expect("Timed out waiting for Miner 1 to mine N+1");
    let peer_info = miners.get_peer_info();

    assert_eq!(peer_info.stacks_tip, miner_1_block_n_1.header.block_hash());
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before + 1);

    info!(
        "------------------------- Verify BlockFound in Miner 1's Block N+1 -------------------------"
    );
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::Extended);

    info!("------------------------- Miner 1 Mines Block N+2 with Transfer Tx -------------------------");
    let stacks_height_before = peer_info.stacks_tip_height;
    // submit a tx so that the miner will mine an extra block
    let _ = miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine transfer tx");

    // Get miner 1's N+2 block proposal
    let miner_1_block_n_2 =
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_1)
            .expect("Timed out waiting for miner 1 to mine N+2");

    let peer_info = miners.get_peer_info();
    assert_eq!(peer_info.stacks_tip, miner_1_block_n_2.header.block_hash());
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before + 1);

    info!("------------------------- Unpause Miner 2's Block Commits -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    let burn_height_before = get_burn_height();

    info!("------------------------- Miner 2 Mines a Normal Tenure C -------------------------";
    "burn_height_before" => burn_height_before);

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by a tenure change tx");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!(
        "------------------------- Verify Tenure Change Tx in Miner 2's Block N+3 -------------------------"
    );
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::BlockFound);

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(
        miners.get_peer_stacks_tip_height(),
        starting_peer_height + 4
    );
    miners.shutdown();
}

/// Test a scenario where a non-blocking majority of signers are configured to favour the previous miner
/// extending their tenure when the incoming miner is slow to propose a block. The incoming miner should succeed
/// and its subsequent blocks should be be approved.
/// Two miners boot to Nakamoto.
/// Miner 1 wins the first tenure A.
/// Miner 1 proposes a block N with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N
/// Miner 2 wins the second tenure B.
/// A minority of signers mark miner 2 as invalid.
/// Miner 1 proposes block N+1' with a TenureChangeCause::Extended
/// A majority of signers reject block N+1'
/// Miner 2 proposes block N+1 with a TenureChangeCause::BlockFound
/// A majority fo signers accept block N+1.
/// Miner 2 proposes block N+2 with a transfer tx
/// A majority of signers should accept block N+2.
/// Miner 1 wins the third tenure C.
/// Miner 1 proposes block N+3 with a TenureChangeCause::BlockFound
/// Signers accept and the stacks tip advances to N+3
///
/// Asserts:
/// - Block N contains the TenureChangeCause::BlockFound
/// - Block N+1' contains a TenureChangeCause::Extended and is rejected
/// - Block N+1 contains the TenureChangeCause::BlockFound
/// - Block N+2 is accepted.
/// - Block N+3 contains the TenureChangeCause::BlockFound.
/// - The stacks tip advances to N+3
#[test]
#[ignore]
fn non_blocking_minority_configured_to_favour_prev_miner() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let non_block_minority = num_signers * 2 / 10;
    let num_txs = 1;

    let favour_prev_miner_block_proposal_timeout = Duration::from_secs(20);
    let favour_incoming_miner_block_proposal_timeout = Duration::from_secs(500);
    // Make sure the miner attempts to extend after the minority mark the incoming as invalid
    let tenure_extend_wait_timeout = favour_prev_miner_block_proposal_timeout;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            let port = signer_config.endpoint.port();
            // Note signer ports are based on the number of them, the first being 3000, the last being 3000 + num_signers - 1
            if port < 3000 + non_block_minority as u16 {
                signer_config.block_proposal_timeout = favour_prev_miner_block_proposal_timeout;
            } else {
                signer_config.block_proposal_timeout = favour_incoming_miner_block_proposal_timeout;
            }
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block and Tenure Change Tx Block");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    miners.submit_commit_miner_2(&sortdb);
    // Pause the block proposal broadcast so that miner 2 will be unable to broadcast its
    // tenure change proposal BEFORE miner 1 attempts to extend.
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_2.clone()]);

    let stacks_height_before = miners.get_peer_stacks_tip_height();
    info!("------------------------- Miner 2 Wins Tenure B -------------------------";
        "stacks_height_before" => %stacks_height_before);
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
        .expect("Failed to start Tenure B");
    btc_blocks_mined += 1;

    assert_eq!(stacks_height_before, miners.get_peer_stacks_tip_height());

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    info!(
        "------------------------- Wait for Miner 1 to think Miner 2 is Invalid -------------------------"
    );
    // Make sure that miner 1 thinks miner 2 is invalid.
    std::thread::sleep(tenure_extend_wait_timeout.add(Duration::from_secs(1)));

    info!("------------------------- Wait for Miner 1's Block N+1' to be Proposed ------------------------";
        "stacks_height_before" => %stacks_height_before);

    let miner_1_block_n_1_prime =
        wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_1)
            .expect("Miner 1 failed to propose block N+1'");
    assert!(miner_1_block_n_1_prime
        .try_get_tenure_change_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::Extended));

    info!("------------------------- Verify that Miner 1's Block N+1' was Rejected ------------------------");
    wait_for_block_global_rejection(
        30,
        &miner_1_block_n_1_prime.header.signer_signature_hash(),
        num_signers,
    )
    .expect("Failed to reach rejection consensus for Miner 1's Block N+1'");

    assert_eq!(stacks_height_before, miners.get_peer_stacks_tip_height());

    info!("------------------------- Wait for Miner 2's Block N+1 BlockFound to be Proposed and Approved------------------------";
        "stacks_height_before" => %stacks_height_before
    );

    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    let miner_2_block_n_1 =
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_2)
            .expect("Miner 2's block N+1 was not mined");
    let peer_info = miners.get_peer_info();
    assert_eq!(peer_info.stacks_tip, miner_2_block_n_1.header.block_hash());
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before + 1);

    info!("------------------------- Verify Minority of Signer's Rejected Miner 2's Block N+1 -------------------------");
    wait_for_block_rejections(
        30,
        &miner_2_block_n_1.header.signer_signature_hash(),
        non_block_minority,
    )
    .expect("Failed to get expected rejections for Miner 2's block N+1.");
    info!(
        "------------------------- Verify BlockFound in Miner 2's Block N+1 -------------------------"
    );
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::BlockFound);

    info!("------------------------- Miner 2 Mines Block N+2 with Transfer Tx -------------------------");
    let stacks_height_before = miners.get_peer_stacks_tip_height();
    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to Mine Block N+2");

    let miner_2_block_n_2 =
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 1, &miner_pk_2)
            .expect("Miner 2's block N+1 was not mined");
    let peer_info = miners.get_peer_info();
    assert_eq!(peer_info.stacks_tip, miner_2_block_n_2.header.block_hash());
    assert_eq!(peer_info.stacks_tip_height, stacks_height_before + 1);

    info!(
        "------------------------- Verify Miner 2's Block N+2 is still Rejected by Minority Signers -------------------------"
    );
    wait_for_block_rejections(
        30,
        &miner_2_block_n_2.header.signer_signature_hash(),
        non_block_minority,
    )
    .expect("Failed to get expected rejections for Miner 2's block N+2.");

    info!("------------------------- Unpause Miner 1's Block Commits -------------------------");
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Mines a Normal Tenure C -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to start Tenure C and mine block N+3");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(
        miners.get_peer_stacks_tip_height(),
        starting_peer_height + 4
    );
    miners.shutdown();
}

#[test]
#[ignore]
/// This test checks the behavior of signers when an empty sortition arrives
/// before the first block of the previous tenure has been approved.
/// Specifically:
/// - The empty sortition will trigger the miner to attempt a tenure extend.
/// - Signers will accept the tenure extend and sign subsequent blocks built
///   off the old sortition
fn empty_sortition_before_approval() {
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
    let block_proposal_timeout = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    let Counters {
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposed_blocks,
        naka_skip_commit_op: skip_commit_op,
        ..
    } = signer_test.running_nodes.counters.clone();

    let commits_before = commits_submitted.load(Ordering::SeqCst);
    next_block_and_process_new_stacks_block(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .unwrap();

    wait_for(30, || {
        Ok(commits_submitted.load(Ordering::SeqCst) > commits_before)
    })
    .expect("Timed out waiting for commit to be submitted for Tenure A");

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info.stacks_tip_height;

    info!("Forcing miner to ignore signatures for next block");
    TEST_IGNORE_SIGNERS.set(true);

    info!("Pausing block commits to trigger an empty sortition.");
    skip_commit_op.set(true);

    info!("------------------------- Test Mine Tenure A  -------------------------");
    let proposed_before = proposed_blocks.load(Ordering::SeqCst);
    // Mine a regular tenure and wait for a block proposal
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || Ok(proposed_blocks.load(Ordering::SeqCst) > proposed_before),
    )
    .expect("Failed to mine tenure A and propose a block");
    signer_test.check_signer_states_normal();

    info!("------------------------- Test Mine Empty Tenure B  -------------------------");

    // Trigger an empty tenure
    signer_test.mine_bitcoin_block();
    signer_test.check_signer_states_normal_missed_sortition();

    info!("Unpause block commits");
    skip_commit_op.set(false);

    info!("Stop ignoring signers and wait for the tip to advance");
    TEST_IGNORE_SIGNERS.set(false);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip");

    let info = get_chain_info(&signer_test.running_nodes.conf);
    info!("Current state: {:?}", info);

    // Wait for a block with a tenure extend to be mined
    wait_for(60, || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::Extended,
        ))
    })
    .expect("Timed out waiting for tenure extend");

    let stacks_height_before = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;

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

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip with STX transfer");

    next_block_and_process_new_stacks_block(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .expect("Failed to mine a normal tenure after the tenure extend");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks the behavior of signers when an empty sortition arrives
/// before the first block of the previous tenure has been proposed.
/// Specifically:
/// - The empty sortition will trigger the miner to attempt a tenure extend.
/// - Signers will accept the tenure extend and sign subsequent blocks built
///   off the old sortition
fn empty_sortition_before_proposal() {
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
    let block_proposal_timeout = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    let skip_commit_op = signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();

    signer_test.boot_to_epoch_3();

    next_block_and_process_new_stacks_block(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .unwrap();

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info.stacks_tip_height;

    info!("Pause block commits to ensure we get an empty sortition");
    skip_commit_op.set(true);

    info!("Pause miner so it doesn't propose a block before the next tenure arrives");
    fault_injection_stall_miner();

    let burn_height_before = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;

    info!("------------------------- Test Mine Tenure A and B  -------------------------");
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(2);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.burn_block_height == burn_height_before + 2)
    })
    .expect("Failed to advance chain tip");

    signer_test.check_signer_states_normal_missed_sortition();

    info!("Unpause miner");
    fault_injection_unstall_miner();

    info!("Unpause block commits");
    skip_commit_op.set(false);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip");

    let info = get_chain_info(&signer_test.running_nodes.conf);
    info!("Current state: {info:?}");

    info!("------------------------- Ensure Miner Extends Tenure  -------------------------");

    // Wait for a block with a tenure extend to be mined
    wait_for(60, || {
        let blocks = test_observer::get_blocks();
        let last_block = blocks.last().unwrap();
        info!("Last block mined: {:?}", last_block);
        for tx in last_block["transactions"].as_array().unwrap() {
            let raw_tx = tx["raw_tx"].as_str().unwrap();
            if raw_tx == "0x00" {
                continue;
            }
            let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
            let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
            if let TransactionPayload::TenureChange(payload) = &parsed.payload {
                match payload.cause {
                    TenureChangeCause::Extended => {
                        info!("Found tenure extend block");
                        return Ok(true);
                    }
                    TenureChangeCause::BlockFound => {}
                    _ => {
                        panic!("Unexpected tenure extension cause {:?}", &payload.cause);
                    }
                }
            };
        }
        Ok(false)
    })
    .expect("Timed out waiting for tenure extend");

    info!("------------------------- Test Miner Mines Transfer Tx  -------------------------");

    let stacks_height_before = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;

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

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip with STX transfer");

    info!("------------------------- Test Miner Tenure C  -------------------------");

    next_block_and_process_new_stacks_block(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .expect("Failed to mine a normal tenure after the tenure extend");
    signer_test.check_signer_states_normal();

    info!("------------------------- Shutdown -------------------------");

    signer_test.shutdown();
}

/// Test a scenario where:
/// Two miners boot to Nakamoto.
/// Miner 1 wins the first tenure and proposes a block N with a TenureChangePayload
/// Signers accept and the stacks tip advances to N
/// Miner 2 wins the second tenure B but its proposed blocks are rejected by the signers.
/// Mine 2 empty burn blocks (simulate fast blocks scenario)
/// Miner 2 proposes block N+1 with a TenureChangePayload
/// Signers accept and the stacks tip advances to N+1
/// Miner 2 proposes block N+2 with a TenureExtend
/// Signers accept and the stacks tip advances to N+2
/// Miner 2 proposes block N+3 with a TokenTransfer
/// Signers accept and the stacks tip advances to N+3
/// Mine an empty burn block
/// Miner 2 proposes block N+4 with a TenureExtend
/// Signers accept and the chain advances to N+4
/// Miner 1 wins the next tenure and proposes a block N+5 with a TenureChangePayload
/// Signers accept and the chain advances to N+5
/// Asserts:
/// - Block N+1 contains the TenureChangePayload
/// - Block N+2 contains the TenureExtend
/// - Block N+3 contains the TokenTransfer
/// - Block N+4 contains the TenureExtend
/// - Block N+5 contains the TenureChangePayload
/// - The stacks tip advances to N+5
#[test]
#[ignore]
fn continue_after_fast_block_no_sortition() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let num_txs = 1;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |_| {},
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );
    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (_, miner_pk_2) = miners.get_miner_public_keys();

    let Counters {
        naka_rejected_blocks: rl1_rejections,
        naka_skip_commit_op: rl1_skip_commit_op,
        naka_submitted_commits: rl1_commits,
        naka_mined_blocks: blocks_mined1,
        ..
    } = miners.signer_test.running_nodes.counters.clone();

    let Counters {
        naka_skip_commit_op: rl2_skip_commit_op,
        naka_submitted_commits: rl2_commits,
        naka_mined_blocks: blocks_mined2,
        ..
    } = miners.rl2_counters.clone();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let all_signers = miners.signer_test.signer_test_pks();
    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Mines a Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to start Tenure A");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Make Signers Reject All Subsequent Proposals -------------------------");

    let stacks_height_before = miners.get_peer_stacks_tip_height();

    // Make all signers ignore block proposals
    let ignoring_signers = all_signers.to_vec();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(ignoring_signers);

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    let rejections_before = rl1_rejections.load(Ordering::SeqCst);
    miners.submit_commit_miner_2(&sortdb);
    let burn_height_before = get_burn_height();

    info!("------------------------- Miner 2 Mines an Empty Tenure B -------------------------";
        "burn_height_before" => burn_height_before,
        "rejections_before" => rejections_before,
    );
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Failed to start Tenure B");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 1 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("----- Waiting for block rejections -----");
    let miner_2_block = wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_2)
        .expect("Failed to get Miner 2's Block Proposal");
    wait_for_block_global_rejection(
        30,
        &miner_2_block.header.signer_signature_hash(),
        num_signers,
    )
    .expect("Failed to get expected block rejections for Miner 2's block proposal");

    // Mine another couple burn blocks and ensure there is _no_ sortition
    info!("------------------------- Mine Two Burn Block(s) with No Sortitions -------------------------");
    for _ in 0..2 {
        let blocks_processed_before_1 = blocks_mined1.load(Ordering::SeqCst);
        let blocks_processed_before_2 = blocks_mined2.load(Ordering::SeqCst);
        let commits_before_1 = rl1_commits.load(Ordering::SeqCst);
        let commits_before_2 = rl2_commits.load(Ordering::SeqCst);

        miners
            .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 30)
            .expect("Failed to mine empty sortition");
        btc_blocks_mined += 1;

        assert_eq!(rl1_commits.load(Ordering::SeqCst), commits_before_1);
        assert_eq!(rl2_commits.load(Ordering::SeqCst), commits_before_2);
        assert_eq!(
            blocks_mined1.load(Ordering::SeqCst),
            blocks_processed_before_1
        );
        assert_eq!(
            blocks_mined2.load(Ordering::SeqCst),
            blocks_processed_before_2
        );

        // assure we have NO sortition
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        assert!(!tip.sortition);
    }

    // Verify that no Stacks blocks have been mined (signers are ignoring) and no commits have been submitted by either miner
    let stacks_height = miners.get_peer_stacks_tip_height();
    assert_eq!(stacks_height, stacks_height_before);
    let stacks_height_before = stacks_height;

    info!("------------------------- Enabling Signer Block Proposals -------------------------";
        "stacks_height" => stacks_height_before,
    );
    // Allow signers to respond to proposals again
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(Vec::new());

    info!("------------------------- Wait for Miner B's Block N+1 -------------------------";
        "stacks_height_before" => %stacks_height_before);

    // wait for the new block to be processed
    // Since we may be proposing a ton of the same height, cannot use wait_for_block_pushed_by_miner_key for block N+1.
    let miner_2_block_n_1 =
        wait_for_block_proposal_block(30, stacks_height_before + 1, &miner_pk_2)
            .expect("Did not mine Miner 2's Block N+1");

    info!(
        "------------------------- Verify Tenure Change Tx in Miner B's Block N+1 -------------------------"
    );
    assert!(miner_2_block_n_1
        .try_get_tenure_change_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::BlockFound));

    info!("------------------------- Wait for Miner B's Block N+2 -------------------------");

    let miner_2_block_n_2 =
        wait_for_block_pushed_by_miner_key(30, stacks_height_before + 2, &miner_pk_2)
            .expect("Did not mine Miner 2's Block N+2");
    assert_eq!(
        miners.get_peer_stacks_tip(),
        miner_2_block_n_2.header.block_hash()
    );

    info!("------------------------- Verify Miner B's Block N+2 -------------------------");
    assert!(miner_2_block_n_2
        .try_get_tenure_change_payload()
        .unwrap()
        .cause
        .is_eq(&TenureChangeCause::Extended));

    info!("------------------------- Wait for Miner B's Block N+3 -------------------------");

    // submit a tx so that the miner will mine an extra block
    let txid = miners
        .send_and_mine_transfer_tx(30)
        .expect("Timed out waiting to mine Block N+3");

    info!("------------------------- Verify Miner B's Block N+3 -------------------------");

    let block_n_3 = wait_for_block_pushed_by_miner_key(30, stacks_height_before + 3, &miner_pk_2)
        .expect("Did not mine Miner 2's Block N+3");
    assert!(block_n_3
        .txs
        .iter()
        .any(|tx| { tx.txid().to_string() == txid }));

    info!("------------------------- Mine An Empty Sortition -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::Extended, 60)
        .expect("Failed to mine Miner B's Tenure Extend in Block N+4");
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert!(!tip.sortition);
    btc_blocks_mined += 1;

    info!("------------------------- Unpause Miner A's Block Commits -------------------------");
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Run Miner A's Tenure -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine Miner A's Tenure Change in Block N+5");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner A won
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    let peer_info = miners.get_peer_info();

    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(peer_info.stacks_tip_height, starting_peer_height + 6);

    info!("------------------------- Shutdown -------------------------");
    miners.shutdown();
}

#[test]
#[ignore]
fn fast_sortition() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);

    let mut sender_nonce = 0;
    let send_amt = 100;
    let send_fee = 400;
    let num_transfers = 3;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(
        num_signers,
        vec![(sender_addr.clone(), num_transfers * (send_amt + send_fee))],
    );

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    info!("------------------------- Mine a Block -------------------------");
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;

    wait_for(60, || {
        Ok(get_account(&http_origin, &sender_addr).nonce == sender_nonce)
    })
    .expect("Timed out waiting for call tx to be mined");

    info!("------------------------- Cause a missed sortition -------------------------");

    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);
    next_block_and_process_new_stacks_block(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .expect("Failed to mine a block");

    info!("------------------------- Mine a Block -------------------------");
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;

    wait_for(60, || {
        Ok(get_account(&http_origin, &sender_addr).nonce == sender_nonce)
    })
    .expect("Timed out waiting for call tx to be mined");

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test spins up two nakamoto nodes, both configured to mine.
/// After Nakamoto blocks are mined, it issues a normal tenure, then issues
///  two bitcoin blocks in quick succession -- the first will contain block commits,
///  and the second "flash block" will contain no block commits.
/// The test asserts that the winner of the first block is different than the previous tenure.
/// and performs the actual test: asserting that the miner wakes up and produces valid blocks.
/// This test uses the burn-block-height to ensure consistent calculation of the burn view between
///   the miner thread and the block processor
fn multiple_miners_empty_sortition() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 5;

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        60,
        |signer_config| {
            // We don't want the miner of the "inactive" sortition before the flash block
            //  to get timed out.
            signer_config.block_proposal_timeout = Duration::from_secs(600);
        },
        |_| {},
        |_| {},
    );

    let (conf_1, _conf_2) = miners.get_node_configs();

    let rl1_counters = miners.signer_test.running_nodes.counters.clone();

    let sortdb = SortitionDB::open(
        &conf_1.get_burn_db_file_path(),
        false,
        conf_1.get_burnchain().pox_constants,
    )
    .unwrap();

    miners.pause_commits_miner_2();
    let (mining_pkh_1, mining_pkh_2) = miners.get_miner_public_key_hashes();

    miners.boot_to_epoch_3();

    let info = get_chain_info(&conf_1);

    miners
        .signer_test
        .submit_burn_block_contract_and_wait(&miners.sender_sk)
        .expect("Timed out waiting for contract publish");

    wait_for(60, || {
        Ok(
            rl1_counters.naka_submitted_commit_last_burn_height.get() >= info.burn_block_height
                && rl1_counters.naka_submitted_commit_last_stacks_tip.get()
                    >= info.stacks_tip_height,
        )
    })
    .expect("Timed out waiting for commits from Miner 1 for Tenure 1 of the test");

    for _ in 0..2 {
        miners
            .signer_test
            .submit_burn_block_call_and_wait(&miners.sender_sk)
            .expect("Timed out waiting for contract-call");
    }

    let tenure_0_stacks_height = get_chain_info(&conf_1).stacks_tip_height;
    miners.pause_commits_miner_1();
    miners.signer_test.mine_bitcoin_block();
    miners.signer_test.check_signer_states_normal();
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert_eq!(tip_sn.miner_pk_hash, Some(mining_pkh_1.clone()));

    wait_for(60, || {
        Ok(get_chain_info(&conf_1).stacks_tip_height > tenure_0_stacks_height)
    })
    .expect("Timed out waiting for Miner 1 to mine the first block of Tenure 1");
    miners.submit_commit_miner_2(&sortdb);

    for _ in 0..2 {
        miners
            .signer_test
            .submit_burn_block_call_and_wait(&miners.sender_sk)
            .expect("Timed out waiting for contract-call");
    }

    let last_active_sortition = get_sortition_info(&conf_1);
    assert!(last_active_sortition.was_sortition);

    let tenure_1_info = get_chain_info(&conf_1);
    info!("Mining flash block!");
    miners.btc_regtest_controller_mut().build_next_block(2);

    wait_for(60, || {
        let info = get_chain_info(&conf_1);
        Ok(info.burn_block_height >= 2 + tenure_1_info.burn_block_height)
    })
    .expect("Timed out waiting for the flash blocks to be processed by the stacks nodes");

    let cur_empty_sortition = get_sortition_info(&conf_1);
    assert!(!cur_empty_sortition.was_sortition);
    let inactive_sortition = get_sortition_info_ch(
        &conf_1,
        cur_empty_sortition.last_sortition_ch.as_ref().unwrap(),
    );
    assert!(inactive_sortition.was_sortition);
    assert_eq!(
        inactive_sortition.burn_block_height,
        last_active_sortition.burn_block_height + 1
    );
    assert_eq!(
        inactive_sortition.miner_pk_hash160,
        Some(mining_pkh_2),
        "Miner 2 should have won the inactive sortition"
    );

    // after the flash block, make sure we get block processing without a new bitcoin block
    //   being mined.
    for _ in 0..2 {
        miners
            .signer_test
            .submit_burn_block_call_and_wait(&miners.sender_sk)
            .expect("Timed out waiting for contract-call");
    }

    miners
        .signer_test
        .check_signer_states_normal_missed_sortition();

    miners.shutdown();
}

#[tag(bitcoind, flaky, slow)]
#[test]
#[ignore]
/// This test spins up a single nakamoto node configured to mine.
/// After Nakamoto blocks are mined, it waits for a normal tenure, then issues
///  two bitcoin blocks in quick succession -- the first will contain block commits,
///  and the second "flash block" will contain no block commits.
/// The test then tries to continue producing a normal tenure: issuing a bitcoin block
///   with a sortition in it.
/// The test does 3 rounds of this to make sure that the network continues producing blocks throughout.
fn single_miner_empty_sortition() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_fee = 180;

    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_fee * 2 * 60 + 1000)]);
    let conf = signer_test.running_nodes.conf.clone();

    signer_test.boot_to_epoch_3();

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    signer_test
        .submit_burn_block_contract_and_wait(&sender_sk)
        .expect("Timed out waiting for contract publish");

    let rl1_commits = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();
    let rl1_counters = signer_test.running_nodes.counters.clone();
    let rl1_conf = signer_test.running_nodes.conf.clone();

    for _i in 0..3 {
        // Mine 1 nakamoto tenures
        info!("Mining tenure...");

        signer_test.mine_block_wait_on_processing(
            &[&rl1_conf],
            &[&rl1_counters],
            Duration::from_secs(30),
        );

        // mine the interim blocks
        for _ in 0..2 {
            signer_test
                .submit_burn_block_call_and_wait(&sender_sk)
                .expect("Timed out waiting for contract-call");
        }

        let last_active_sortition = get_sortition_info(&conf);
        assert!(last_active_sortition.was_sortition);

        // lets mine a btc flash block
        let rl1_commits_before = rl1_commits.load(Ordering::SeqCst);
        let info_before = get_chain_info(&conf);
        signer_test
            .running_nodes
            .btc_regtest_controller
            .build_next_block(2);

        wait_for(60, || {
            let info = get_chain_info(&conf);
            Ok(info.burn_block_height >= 2 + info_before.burn_block_height
                && rl1_commits.load(Ordering::SeqCst) > rl1_commits_before)
        })
        .unwrap();

        let cur_empty_sortition = get_sortition_info(&conf);
        assert!(!cur_empty_sortition.was_sortition);
        let inactive_sortition = get_sortition_info_ch(
            &conf,
            cur_empty_sortition.last_sortition_ch.as_ref().unwrap(),
        );
        assert!(inactive_sortition.was_sortition);
        assert_eq!(
            inactive_sortition.burn_block_height,
            last_active_sortition.burn_block_height + 1
        );

        info!("==================== Mined a flash block ====================");
        info!("Flash block sortition info";
              "last_active_winner" => ?last_active_sortition.miner_pk_hash160,
              "last_winner" => ?inactive_sortition.miner_pk_hash160,
              "last_active_ch" => %last_active_sortition.consensus_hash,
              "last_winner_ch" => %inactive_sortition.consensus_hash,
              "cur_empty_sortition" => %cur_empty_sortition.consensus_hash,
        );
    }
    signer_test.shutdown();
}

#[test]
#[ignore]
fn read_count_extend_after_burn_view_change() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let num_txs = 5;
    let idle_timeout = Duration::from_secs(30);
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| {
            signer_config.block_proposal_timeout = Duration::from_secs(60);
            signer_config.first_proposal_burn_block_timing = Duration::from_secs(0);
            // use a different timeout to ensure that the correct timeout
            //  is read by the miner
            signer_config.tenure_idle_timeout = Duration::from_secs(36000);
            signer_config.read_count_idle_timeout = idle_timeout;
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
            let epochs = config.burnchain.epochs.as_mut().unwrap();
            let epoch_30_height = epochs[StacksEpochId::Epoch30].start_height;
            epochs[StacksEpochId::Epoch30].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch33].start_height = epoch_30_height;
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
            config.miner.tenure_extend_cost_threshold = 0;
            config.miner.read_count_extend_cost_threshold = 0;

            let epochs = config.burnchain.epochs.as_mut().unwrap();
            let epoch_30_height = epochs[StacksEpochId::Epoch30].start_height;
            epochs[StacksEpochId::Epoch30].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch33].start_height = epoch_30_height;
        },
    );

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pk_1, _) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    miners.pause_commits_miner_2();
    miners.boot_to_epoch_3();

    miners.pause_commits_miner_1();

    let sortdb = conf_1.get_burnchain().open_sortition_db(true).unwrap();

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .unwrap();

    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Wins Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .unwrap();
    verify_sortition_winner(&sortdb, &miner_pkh_1);
    miners.send_and_mine_transfer_tx(60).unwrap();
    let tip_a_height = miners.get_peer_stacks_tip_height();
    let prev_tip = get_chain_info(&conf_1);

    info!("------------------------- Miner 2 Wins Tenure B -------------------------");
    miners.submit_commit_miner_2(&sortdb);
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .unwrap();
    verify_sortition_winner(&sortdb, &miner_pkh_2);
    miners.send_and_mine_transfer_tx(60).unwrap();
    let tip_b_height = miners.get_peer_stacks_tip_height();
    let tenure_b_ch = miners.get_peer_stacks_tip_ch();

    info!("------------------------- Miner 1 Wins Tenure C with stale commit -------------------------");

    // We can't use `submit_commit_miner_1` here because we are using the stale view
    {
        TEST_MINER_COMMIT_TIP.set(Some((prev_tip.pox_consensus, prev_tip.stacks_tip)));
        let rl1_commits_before = miners
            .signer_test
            .running_nodes
            .counters
            .naka_submitted_commits
            .load(Ordering::SeqCst);

        miners
            .signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .set(false);

        wait_for(30, || {
            let commits_after = miners
                .signer_test
                .running_nodes
                .counters
                .naka_submitted_commits
                .load(Ordering::SeqCst);
            let last_commit_tip = miners
                .signer_test
                .running_nodes
                .counters
                .naka_submitted_commit_last_stacks_tip
                .load(Ordering::SeqCst);

            Ok(commits_after > rl1_commits_before && last_commit_tip == prev_tip.stacks_tip_height)
        })
        .expect("Timed out waiting for miner 1 to submit a commit op");

        miners
            .signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .set(true);
        TEST_MINER_COMMIT_TIP.set(None);
    }

    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .unwrap();
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!(
        "------------------------- Miner 1's proposal for C is rejected -------------------------"
    );
    let proposed_block = wait_for_block_proposal(60, tip_a_height + 1, &miner_pk_1).unwrap();
    wait_for_block_global_rejection(
        60,
        &proposed_block.header.signer_signature_hash(),
        num_signers,
    )
    .unwrap();

    assert_eq!(miners.get_peer_stacks_tip_ch(), tenure_b_ch);

    info!("------------------------- Miner 2 Extends Tenure B -------------------------");
    wait_for_tenure_change_tx(60, TenureChangeCause::Extended, tip_b_height + 1).unwrap();

    let final_height = miners.get_peer_stacks_tip_height();
    assert_eq!(miners.get_peer_stacks_tip_ch(), tenure_b_ch);
    assert!(final_height >= tip_b_height + 1);

    info!("---- Waiting for a tenure extend ----");

    // Now, wait for a block with a tenure extend
    wait_for(idle_timeout.as_secs() + 10, || {
        Ok(last_block_contains_tenure_change_tx(
            TenureChangeCause::ExtendedReadCount,
        ))
    })
    .expect("Timed out waiting for a block with a tenure extend");

    miners.shutdown();
}
