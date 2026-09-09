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

//! Live custom-signet qualification using the production node and signer run loops.

use std::sync::atomic::Ordering;
use std::time::Duration;
use std::{env, thread};

use clarity::vm::types::QualifiedContractIdentifier;
use pinny::tag;
use stacks::burnchains::bitcoin::{signet, BitcoinNetworkType};
use stacks::burnchains::MagicBytes;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::config::Config;
use stacks::core::{StacksEpochId, STACKS_EPOCH_MAX};
use stacks::types::chainstate::StacksPrivateKey;
use stacks::util::secp256k1::Secp256k1PublicKey;

use super::MultipleMinerTest;
use crate::run_loop::boot_nakamoto::BootRunLoop;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{
    get_account, get_chain_info, get_chain_info_opt, get_pox_info, test_observer,
};
use crate::tests::signer::wait_for_node_commit;
use crate::tests::{gen_random_port, to_addr};

/// Apply the shipped development schedule and PoX defaults to an isolated OP_TRUE signet.
fn configure_signet(config: &mut Config, rpc_port: u16, peer_port: u16) {
    config.burnchain.mode = "signet".into();
    config.burnchain.signet_challenge = Some(vec![0x51]);
    config.burnchain.magic_bytes = MagicBytes::from(b"S2".as_ref());
    config.burnchain.rpc_port = rpc_port;
    config.burnchain.peer_port = peer_port;
    config.burnchain.timeout = 600;
    config.burnchain.epochs = Some(signet::default_epochs());
    config.burnchain.pox_reward_length = None;
    config.burnchain.pox_prepare_length = None;
    config.miner.block_commit_delay = Duration::from_secs(1);
}

/// Wait for agreement on the burn view and the full Stacks tip identity.
fn assert_node_agreement(first: &Config, second: &Config) {
    wait_for(90, || {
        let (Some(a), Some(b)) = (get_chain_info_opt(first), get_chain_info_opt(second)) else {
            return Ok(false);
        };
        Ok(a.burn_block_height == b.burn_block_height
            && a.pox_consensus == b.pox_consensus
            && a.stacks_tip == b.stacks_tip
            && a.stacks_tip_consensus_hash == b.stacks_tip_consensus_hash
            && a.stacks_tip_height == b.stacks_tip_height)
    })
    .expect("Signet nodes must agree on burn consensus and the Stacks tip");
}

/// Configure a shorter signet bootstrap while preserving coinbase maturity and PoX phases.
fn configure_signet_smoke(config: &mut Config, rpc_port: u16, peer_port: u16) {
    configure_signet(config, rpc_port, peer_port);
    let epochs = config.burnchain.epochs.as_mut().unwrap();
    let epoch_25_start = epochs.get(StacksEpochId::Epoch25).unwrap().start_height;
    let epoch_30_start = epochs.get(StacksEpochId::Epoch30).unwrap().start_height;
    // Bootstrap to 105 for mature miner funding; Epoch 2.5 at 111 precedes preparation at 116.
    // Epoch 3.0 starts at 122 to avoid the excluded reward-cycle offsets 0 and 1.
    for epoch in epochs.iter_mut() {
        for height in [&mut epoch.start_height, &mut epoch.end_height] {
            if *height >= epoch_30_start && *height < STACKS_EPOCH_MAX {
                *height -= epoch_30_start - 122;
            } else if *height >= epoch_25_start && *height < epoch_30_start {
                *height -= epoch_25_start - 111;
            }
        }
    }
}

/// Mine a transfer and verify its successful receipt in a signer-approved block.
/// Both fixtures use five equally weighted signers, so a quorum requires four signatures.
fn send_and_confirm_transfer(miners: &mut MultipleMinerTest, timeout_secs: u64) {
    let txid = format!(
        "0x{}",
        miners.send_and_mine_transfer_tx(timeout_secs).unwrap()
    );
    wait_for(timeout_secs, || {
        Ok(test_observer::get_blocks().iter().any(|block| {
            block["signer_signature"]
                .as_array()
                .is_some_and(|signatures| signatures.len() >= 4)
                && block["transactions"].as_array().unwrap().iter().any(|tx| {
                    tx["txid"].as_str() == Some(txid.as_str())
                        && tx["status"].as_str() == Some("success")
                        && tx["raw_result"].as_str() == Some("0x0703")
                })
        }))
    })
    .expect("Signet transfer must have a successful execution receipt");
}

/// Check custom-signet startup, signed tenures, and successful transfer replication.
#[tag(slow, bitcoind)]
#[test]
#[ignore = "requires Bitcoin Core on PATH; mines real signet PoW"]
fn signet_signed_transfer_smoke() {
    assert_eq!(env::var("BITCOIND_TEST").as_deref(), Ok("1"));
    let rpc_port = gen_random_port();
    let peer_port = gen_random_port();
    let mut miners = MultipleMinerTest::new_with_signer_dist(
        5,
        2,
        |_| {},
        |config| configure_signet_smoke(config, rpc_port, peer_port),
        |config| configure_signet_smoke(config, rpc_port, peer_port),
        |_| 0,
        None,
    );
    miners.boot_to_epoch_3();
    let (first, second) = miners.get_node_configs();
    for config in [&first, &second] {
        assert_eq!(
            config.burnchain.get_bitcoin_network().1,
            BitcoinNetworkType::Signet
        );
    }
    assert_node_agreement(&first, &second);
    let sortdb = first.get_burnchain().open_sortition_db(true).unwrap();
    let before = get_chain_info(&first);
    miners
        .wait_for_both_miners_committed_to_current_tenure(&sortdb, 60)
        .unwrap();
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .unwrap();
    send_and_confirm_transfer(&mut miners, 60);
    assert_node_agreement(&first, &second);
    let sender = to_addr(&miners.sender_sk);
    for config in [&first, &second] {
        assert_eq!(
            get_account(&format!("http://{}", config.node.rpc_bind), &sender).nonce,
            1
        );
    }
    let after = get_chain_info(&first);
    assert!(after.burn_block_height > before.burn_block_height);
    assert!(after.stacks_tip_height > before.stacks_tip_height);
    assert_eq!(after.stacks_tip_consensus_hash, after.pox_consensus);
    miners.shutdown();
}

/// Qualify PoX-5 over three complete reward cycles, transactions, peer agreement, and recovery.
#[tag(slow, bitcoind, ci_skip)]
#[test]
#[ignore = "requires Bitcoin Core on PATH; mines real signet PoW and runs two miners/five signers"]
fn signet_pox5_epoch40_stability_and_restart() {
    assert_eq!(env::var("BITCOIND_TEST").as_deref(), Ok("1"));
    let rpc_port = gen_random_port();
    let peer_port = gen_random_port();
    let publisher = StacksPrivateKey::from_seed(b"signet-pox5-qualification-publisher");
    let publisher_addr = to_addr(&publisher);
    let token_name = "sbtc-token-stub";
    let registry_name = "sbtc-registry-stub";
    let token_id = QualifiedContractIdentifier::new(
        publisher_addr.clone().into(),
        token_name.to_string().try_into().unwrap(),
    );
    let registry_id = QualifiedContractIdentifier::new(
        publisher_addr.clone().into(),
        registry_name.to_string().try_into().unwrap(),
    );
    let aggregate_key: [u8; 33] = Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(
        b"signet-pox5-qualification-aggregate",
    ))
    .to_bytes_compressed()
    .try_into()
    .unwrap();
    let mut miners = MultipleMinerTest::new_with_signer_dist(
        5,
        100,
        |_| {},
        |config| {
            configure_signet(config, rpc_port, peer_port);
            config.node.pox_5_sbtc_contract = Some(token_id.clone());
            config.node.pox_5_sbtc_registry_contract = Some(registry_id.clone());
            config.add_initial_balance(publisher_addr.to_string(), 1_000_000);
        },
        |config| configure_signet(config, rpc_port, peer_port),
        // All signers stay connected to node 1 during node 2's outage.
        |_| 0,
        None,
    );
    let (first, second) = miners.get_node_configs();
    miners.boot_to_epoch_4_with_pox5_lockups(
        &publisher,
        0,
        token_name,
        registry_name,
        &aggregate_key,
        100_000_000_000,
        12,
    );
    assert_node_agreement(&first, &second);
    let http_origin = format!("http://{}", first.node.rpc_bind);
    let pox = get_pox_info(&http_origin).unwrap();
    assert_eq!(pox.current_epoch, StacksEpochId::Epoch40);
    assert!(pox.contract_id.ends_with(".pox-5"));
    assert_eq!(pox.reward_cycle_length, 20);
    assert_eq!(pox.prepare_cycle_length, 5);
    let first_complete_cycle = pox.current_cycle.id + 1;
    let end_height = (first_complete_cycle + 3) * pox.reward_cycle_length;
    let sortdb = first.get_burnchain().open_sortition_db(true).unwrap();
    let mut previous_tip_height = get_chain_info(&first).stacks_tip_height;
    let mut completed_cycles = Vec::new();
    while get_chain_info(&first).burn_block_height < end_height {
        miners
            .wait_for_both_miners_committed_to_current_tenure(&sortdb, 90)
            .unwrap();
        miners
            .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 90)
            .unwrap();
        wait_for(90, || {
            let info = get_chain_info(&first);
            Ok(info.stacks_tip_height > previous_tip_height
                && info.stacks_tip_consensus_hash == info.pox_consensus)
        })
        .expect("Each signet tenure must produce a signed Stacks block");
        assert_node_agreement(&first, &second);
        let info = get_chain_info(&first);
        let pox = get_pox_info(&http_origin).unwrap();
        assert_eq!(pox.current_epoch, StacksEpochId::Epoch40);
        assert!(pox.contract_id.ends_with(".pox-5"));
        let cycle = pox.current_cycle.id;
        if cycle >= first_complete_cycle && !completed_cycles.contains(&cycle) {
            assert_eq!(miners.signer_test.get_reward_set_signers(cycle).len(), 5);
            send_and_confirm_transfer(&mut miners, 90);
            assert_node_agreement(&first, &second);
            completed_cycles.push(cycle);
        }
        previous_tip_height = info.stacks_tip_height;
    }
    for cycle in first_complete_cycle..first_complete_cycle + 3 {
        assert!(
            completed_cycles.contains(&cycle),
            "Missing confirmed transfer in cycle {cycle}"
        );
    }

    // Establish an accepted node-1 tenure before taking node 2 offline.
    miners.pause_commits_miner_2();
    let (miner_1_hash, _) = miners.get_miner_public_key_hashes();
    let mut drain_blocks = 0;
    loop {
        assert!(
            drain_blocks < 12,
            "Node 1 must take over within 12 burn blocks"
        );
        wait_for_node_commit(&first, &miners.signer_test.running_nodes.counters, 90);
        miners
            .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 90)
            .unwrap();
        drain_blocks += 1;
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        if tip.sortition && tip.miner_pk_hash.as_ref() == Some(&miner_1_hash) {
            wait_for(90, || {
                let a = get_chain_info(&first);
                let b = get_chain_info(&second);
                Ok(a.stacks_tip_consensus_hash == tip.consensus_hash
                    && b.stacks_tip_consensus_hash == tip.consensus_hash
                    && a.stacks_tip == b.stacks_tip)
            })
            .expect("Both nodes must accept the surviving miner's tenure before the outage");
            assert_node_agreement(&first, &second);
            break;
        }
    }
    miners
        .rl2_coord_channels
        .lock()
        .unwrap()
        .stop_chains_coordinator();
    miners.rl2_stopper.store(false, Ordering::SeqCst);
    miners.rl2_thread.join().unwrap();
    let before_outage = get_chain_info(&first);
    for _ in 0..3 {
        wait_for_node_commit(&first, &miners.signer_test.running_nodes.counters, 90);
        let before = get_chain_info(&first);
        miners
            .signer_test
            .running_nodes
            .btc_regtest_controller
            .build_next_block(1);
        wait_for(90, || {
            let info = get_chain_info(&first);
            // A null-miner sortition legitimately extends the previous tenure.
            Ok(info.burn_block_height > before.burn_block_height
                && info.stacks_tip_height > before.stacks_tip_height)
        })
        .expect("Node 1 must continue signed block production while node 2 is offline");
    }
    let after_outage = get_chain_info(&first);
    assert!(after_outage.stacks_tip_height > before_outage.stacks_tip_height);
    assert!(after_outage.burn_block_height >= before_outage.burn_block_height + 3);
    let mut restarted = BootRunLoop::new(second.clone()).unwrap();
    miners.rl2_stopper = restarted.get_termination_switch();
    miners.rl2_coord_channels = restarted.coordinator_channels();
    miners.rl2_counters = restarted.counters();
    miners.rl2_thread = thread::Builder::new()
        .name("signet-restarted-miner".into())
        .spawn(move || restarted.start(None, 0))
        .unwrap();
    assert_node_agreement(&first, &second);
    wait_for_node_commit(&first, &miners.signer_test.running_nodes.counters, 90);
    wait_for_node_commit(&second, &miners.rl2_counters, 90);
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 90)
        .unwrap();
    send_and_confirm_transfer(&mut miners, 90);
    assert_node_agreement(&first, &second);
    miners.shutdown();
}
