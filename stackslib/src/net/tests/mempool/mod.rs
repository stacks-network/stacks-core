// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
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

use std::{thread, time};

use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::types::StacksAddressExtensions;
use clarity::vm::MAX_CALL_STACK_DEPTH;
use rand;
use rand::RngCore;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::{log, sleep_ms};

use super::*;
use crate::burnchains::burnchain::*;
use crate::burnchains::*;
use crate::chainstate::stacks::test::*;
use crate::chainstate::stacks::*;
use crate::core::StacksEpochExtension;
use crate::net::atlas::*;
use crate::net::codec::*;
use crate::net::db::*;
use crate::net::test::*;
use crate::net::tests::relay::epoch2x::make_contract_tx;
use crate::net::*;
use crate::util_lib::test::*;

#[test]
fn test_mempool_sync_2_peers() {
    // peer 1 gets some transactions; verify peer 2 gets the recent ones and not the old
    // ones
    let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
    let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

    peer_1_config.connection_opts.mempool_sync_interval = 1;
    peer_2_config.connection_opts.mempool_sync_interval = 1;

    let num_txs = 10;
    let pks: Vec<_> = (0..num_txs).map(|_| StacksPrivateKey::new()).collect();
    let addrs: Vec<_> = pks.iter().map(|pk| to_addr(pk)).collect();
    let initial_balances: Vec<_> = addrs
        .iter()
        .map(|a| (a.to_account_principal(), 1000000000))
        .collect();

    peer_1_config.initial_balances = initial_balances.clone();
    peer_2_config.initial_balances = initial_balances.clone();

    let mut peer_1 = TestPeer::new(peer_1_config);
    let mut peer_2 = TestPeer::new(peer_2_config);

    peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
    peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    for i in 0..(num_blocks / 2) {
        let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

        peer_1.next_burnchain_block(burn_ops.clone());
        peer_2.next_burnchain_block(burn_ops.clone());

        peer_1.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }

    let addr = StacksAddress {
        version: C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        bytes: Hash160([0xff; 20]),
    };

    let stacks_tip_ch = peer_1.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bhh = peer_1.network.stacks_tip.block_hash.clone();

    // old transactions
    let num_txs = 10;
    let mut old_txs = HashMap::new();
    let mut peer_1_mempool = peer_1.mempool.take().unwrap();
    let mut mempool_tx = peer_1_mempool.tx_begin().unwrap();
    for i in 0..num_txs {
        let pk = &pks[i];
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&pk).unwrap();

        let tx = tx_signer.get_tx().unwrap();

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        old_txs.insert(tx.txid(), tx.clone());

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            peer_1.chainstate(),
            &stacks_tip_ch,
            &stacks_tip_bhh,
            true,
            txid.clone(),
            tx_bytes,
            tx_fee,
            (num_blocks / 2) as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
    }
    mempool_tx.commit().unwrap();
    peer_1.mempool = Some(peer_1_mempool);

    // keep mining to make these txs old
    for i in (num_blocks / 2)..num_blocks {
        let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

        peer_1.next_burnchain_block(burn_ops.clone());
        peer_2.next_burnchain_block(burn_ops.clone());

        peer_1.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }

    let num_burn_blocks = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    let stacks_tip_ch = peer_1.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bhh = peer_1.network.stacks_tip.block_hash.clone();

    let mut txs = HashMap::new();
    let mut peer_1_mempool = peer_1.mempool.take().unwrap();
    let mut mempool_tx = peer_1_mempool.tx_begin().unwrap();
    for i in 0..num_txs {
        let pk = &pks[i];
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(1);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&pk).unwrap();

        let tx = tx_signer.get_tx().unwrap();

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        txs.insert(tx.txid(), tx.clone());

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            peer_1.chainstate(),
            &stacks_tip_ch,
            &stacks_tip_bhh,
            true,
            txid.clone(),
            tx_bytes,
            tx_fee,
            num_blocks as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
    }
    mempool_tx.commit().unwrap();
    peer_1.mempool = Some(peer_1_mempool);

    let mut round = 0;
    let mut peer_1_mempool_txs = 0;
    let mut peer_2_mempool_txs = 0;

    while peer_1_mempool_txs < num_txs || peer_2_mempool_txs < num_txs {
        if let Ok(mut result) = peer_1.step_with_ibd(false) {
            let lp = peer_1.network.local_peer.clone();
            let burnchain = peer_1.network.burnchain.clone();
            peer_1
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        if let Ok(mut result) = peer_2.step_with_ibd(false) {
            let lp = peer_2.network.local_peer.clone();
            let burnchain = peer_2.network.burnchain.clone();
            peer_2
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        round += 1;

        let mp = peer_1.mempool.take().unwrap();
        peer_1_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap().len();
        peer_1.mempool.replace(mp);

        let mp = peer_2.mempool.take().unwrap();
        peer_2_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap().len();
        peer_2.mempool.replace(mp);

        info!(
            "Peer 1: {}, Peer 2: {}",
            peer_1_mempool_txs, peer_2_mempool_txs
        );
    }

    info!("Completed mempool sync in {} step(s)", round);

    let mp = peer_2.mempool.take().unwrap();
    let peer_2_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap();
    peer_2.mempool.replace(mp);

    // peer 2 has all the recent txs
    // peer 2 has none of the old ones
    for tx in peer_2_mempool_txs {
        assert_eq!(&tx.tx, txs.get(&tx.tx.txid()).unwrap());
        assert!(old_txs.get(&tx.tx.txid()).is_none());
    }
}

#[test]
fn test_mempool_sync_2_peers_paginated() {
    // peer 1 gets some transactions; verify peer 2 gets them all
    let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
    let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

    peer_1_config.connection_opts.mempool_sync_interval = 1;
    peer_2_config.connection_opts.mempool_sync_interval = 1;

    let num_txs = 1024;
    let pks: Vec<_> = (0..num_txs).map(|_| StacksPrivateKey::new()).collect();
    let addrs: Vec<_> = pks.iter().map(|pk| to_addr(pk)).collect();
    let initial_balances: Vec<_> = addrs
        .iter()
        .map(|a| (a.to_account_principal(), 1000000000))
        .collect();

    peer_1_config.initial_balances = initial_balances.clone();
    peer_2_config.initial_balances = initial_balances.clone();

    let mut peer_1 = TestPeer::new(peer_1_config);
    let mut peer_2 = TestPeer::new(peer_2_config);

    peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
    peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    for i in 0..num_blocks {
        let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

        peer_1.next_burnchain_block(burn_ops.clone());
        peer_2.next_burnchain_block(burn_ops.clone());

        peer_1.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }

    let addr = StacksAddress {
        version: C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        bytes: Hash160([0xff; 20]),
    };

    let stacks_tip_ch = peer_1.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bhh = peer_1.network.stacks_tip.block_hash.clone();

    // fill peer 1 with lots of transactions
    let mut txs = HashMap::new();
    let mut peer_1_mempool = peer_1.mempool.take().unwrap();
    let mut mempool_tx = peer_1_mempool.tx_begin().unwrap();
    for i in 0..num_txs {
        let pk = &pks[i];
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&pk).unwrap();

        let tx = tx_signer.get_tx().unwrap();

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        txs.insert(tx.txid(), tx.clone());

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            peer_1.chainstate(),
            &stacks_tip_ch,
            &stacks_tip_bhh,
            true,
            txid.clone(),
            tx_bytes,
            tx_fee,
            num_blocks,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
    }
    mempool_tx.commit().unwrap();
    peer_1.mempool = Some(peer_1_mempool);

    let num_burn_blocks = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    let mut round = 0;
    let mut peer_1_mempool_txs = 0;
    let mut peer_2_mempool_txs = 0;

    while peer_1_mempool_txs < num_txs || peer_2_mempool_txs < num_txs {
        if let Ok(mut result) = peer_1.step_with_ibd(false) {
            let lp = peer_1.network.local_peer.clone();
            let burnchain = peer_1.network.burnchain.clone();
            peer_1
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        if let Ok(mut result) = peer_2.step_with_ibd(false) {
            let lp = peer_2.network.local_peer.clone();
            let burnchain = peer_2.network.burnchain.clone();
            peer_2
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        round += 1;

        let mp = peer_1.mempool.take().unwrap();
        peer_1_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap().len();
        peer_1.mempool.replace(mp);

        let mp = peer_2.mempool.take().unwrap();
        peer_2_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap().len();
        peer_2.mempool.replace(mp);

        info!(
            "Peer 1: {}, Peer 2: {}",
            peer_1_mempool_txs, peer_2_mempool_txs
        );
    }

    info!("Completed mempool sync in {} step(s)", round);

    let mp = peer_2.mempool.take().unwrap();
    let peer_2_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap();
    peer_2.mempool.replace(mp);

    for tx in peer_2_mempool_txs {
        assert_eq!(&tx.tx, txs.get(&tx.tx.txid()).unwrap());
    }
}

#[test]
fn test_mempool_sync_2_peers_blacklisted() {
    // peer 1 gets some transactions; peer 2 blacklists some of them;
    // verify peer 2 gets only the non-blacklisted ones.
    let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
    let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

    peer_1_config.connection_opts.mempool_sync_interval = 1;
    peer_2_config.connection_opts.mempool_sync_interval = 1;

    let num_txs = 1024;
    let pks: Vec<_> = (0..num_txs).map(|_| StacksPrivateKey::new()).collect();
    let addrs: Vec<_> = pks.iter().map(|pk| to_addr(pk)).collect();
    let initial_balances: Vec<_> = addrs
        .iter()
        .map(|a| (a.to_account_principal(), 1000000000))
        .collect();

    peer_1_config.initial_balances = initial_balances.clone();
    peer_2_config.initial_balances = initial_balances.clone();

    let mut peer_1 = TestPeer::new(peer_1_config);
    let mut peer_2 = TestPeer::new(peer_2_config);

    peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
    peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    for i in 0..num_blocks {
        let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

        peer_1.next_burnchain_block(burn_ops.clone());
        peer_2.next_burnchain_block(burn_ops.clone());

        peer_1.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }

    let addr = StacksAddress {
        version: C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        bytes: Hash160([0xff; 20]),
    };

    let stacks_tip_ch = peer_1.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bhh = peer_1.network.stacks_tip.block_hash.clone();

    // fill peer 1 with lots of transactions
    let mut txs = HashMap::new();
    let mut peer_1_mempool = peer_1.mempool.take().unwrap();
    let mut mempool_tx = peer_1_mempool.tx_begin().unwrap();
    let mut peer_2_blacklist = vec![];
    for i in 0..num_txs {
        let pk = &pks[i];
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&pk).unwrap();

        let tx = tx_signer.get_tx().unwrap();

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        txs.insert(tx.txid(), tx.clone());

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            peer_1.chainstate(),
            &stacks_tip_ch,
            &stacks_tip_bhh,
            true,
            txid.clone(),
            tx_bytes,
            tx_fee,
            num_blocks,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);

        if i % 2 == 0 {
            // peer 2 blacklists even-numbered txs
            peer_2_blacklist.push(txid);
        }
    }
    mempool_tx.commit().unwrap();
    peer_1.mempool = Some(peer_1_mempool);

    // peer 2 blacklists them all
    let mut peer_2_mempool = peer_2.mempool.take().unwrap();

    // blacklisted txs never time out
    peer_2_mempool.blacklist_timeout = u64::MAX / 2;

    let mempool_tx = peer_2_mempool.tx_begin().unwrap();
    MemPoolDB::inner_blacklist_txs(&mempool_tx, &peer_2_blacklist, get_epoch_time_secs()).unwrap();
    mempool_tx.commit().unwrap();

    peer_2.mempool = Some(peer_2_mempool);

    let num_burn_blocks = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    let mut round = 0;
    let mut peer_1_mempool_txs = 0;
    let mut peer_2_mempool_txs = 0;

    while peer_1_mempool_txs < num_txs || peer_2_mempool_txs < num_txs / 2 {
        if let Ok(mut result) = peer_1.step_with_ibd(false) {
            let lp = peer_1.network.local_peer.clone();
            let burnchain = peer_1.network.burnchain.clone();
            peer_1
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        if let Ok(mut result) = peer_2.step_with_ibd(false) {
            let lp = peer_2.network.local_peer.clone();
            let burnchain = peer_2.network.burnchain.clone();
            peer_2
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        round += 1;

        let mp = peer_1.mempool.take().unwrap();
        peer_1_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap().len();
        peer_1.mempool.replace(mp);

        let mp = peer_2.mempool.take().unwrap();
        peer_2_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap().len();
        peer_2.mempool.replace(mp);

        info!(
            "Peer 1: {}, Peer 2: {}",
            peer_1_mempool_txs, peer_2_mempool_txs
        );
    }

    info!("Completed mempool sync in {} step(s)", round);

    let mp = peer_2.mempool.take().unwrap();
    let peer_2_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap();
    peer_2.mempool.replace(mp);

    for tx in peer_2_mempool_txs {
        assert_eq!(&tx.tx, txs.get(&tx.tx.txid()).unwrap());
        assert!(!peer_2_blacklist.contains(&tx.tx.txid()));
    }
}

/// Make sure mempool sync never stores problematic transactions
#[test]
fn test_mempool_sync_2_peers_problematic() {
    // peer 1 gets some transactions; peer 2 blacklists them all due to being invalid.
    // verify peer 2 stores nothing.
    let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
    let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

    peer_1_config.connection_opts.mempool_sync_interval = 1;
    peer_2_config.connection_opts.mempool_sync_interval = 1;

    let num_txs = 128;
    let pks: Vec<_> = (0..num_txs).map(|_| StacksPrivateKey::new()).collect();
    let addrs: Vec<_> = pks.iter().map(|pk| to_addr(pk)).collect();
    let initial_balances: Vec<_> = addrs
        .iter()
        .map(|a| (a.to_account_principal(), 1000000000))
        .collect();

    peer_1_config.initial_balances = initial_balances.clone();
    peer_2_config.initial_balances = initial_balances.clone();

    let mut peer_1 = TestPeer::new(peer_1_config);
    let mut peer_2 = TestPeer::new(peer_2_config);

    peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
    peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    for i in 0..num_blocks {
        let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

        peer_1.next_burnchain_block(burn_ops.clone());
        peer_2.next_burnchain_block(burn_ops.clone());

        peer_1.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }

    let addr = StacksAddress {
        version: C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        bytes: Hash160([0xff; 20]),
    };

    let stacks_tip_ch = peer_1.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bhh = peer_1.network.stacks_tip.block_hash.clone();

    // fill peer 1 with lots of transactions
    let mut txs = HashMap::new();
    let mut peer_1_mempool = peer_1.mempool.take().unwrap();
    let mut mempool_tx = peer_1_mempool.tx_begin().unwrap();
    for i in 0..num_txs {
        let pk = &pks[i];

        let exceeds_repeat_factor = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64);
        let tx_exceeds_body_start = "{ a : ".repeat(exceeds_repeat_factor as usize);
        let tx_exceeds_body_end = "} ".repeat(exceeds_repeat_factor as usize);
        let tx_exceeds_body = format!("{}u1 {}", tx_exceeds_body_start, tx_exceeds_body_end);

        let tx = make_contract_tx(
            &pk,
            0,
            (tx_exceeds_body.len() * 100) as u64,
            "test-exceeds",
            &tx_exceeds_body,
        );

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        txs.insert(tx.txid(), tx.clone());

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            peer_1.chainstate(),
            &stacks_tip_ch,
            &stacks_tip_bhh,
            true,
            txid.clone(),
            tx_bytes,
            tx_fee,
            num_blocks,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
    }
    mempool_tx.commit().unwrap();
    peer_1.mempool = Some(peer_1_mempool);

    // blacklisted txs never time out
    let mut peer_2_mempool = peer_2.mempool.take().unwrap();
    peer_2_mempool.blacklist_timeout = u64::MAX / 2;
    peer_2.mempool = Some(peer_2_mempool);

    let num_burn_blocks = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer_1.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height + 1
    };

    let mut round = 0;
    let mut peer_1_mempool_txs = 0;

    while peer_1_mempool_txs < num_txs
        || peer_2
            .network
            .mempool_sync
            .as_ref()
            .unwrap()
            .mempool_sync_txs
            < (num_txs as u64)
    {
        if let Ok(mut result) = peer_1.step_with_ibd(false) {
            let lp = peer_1.network.local_peer.clone();
            let burnchain = peer_1.network.burnchain.clone();
            peer_1
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        if let Ok(mut result) = peer_2.step_with_ibd(false) {
            let lp = peer_2.network.local_peer.clone();
            let burnchain = peer_2.network.burnchain.clone();
            peer_2
                .with_db_state(|sortdb, chainstate, relayer, mempool| {
                    relayer.process_network_result(
                        &lp,
                        &mut result,
                        &burnchain,
                        sortdb,
                        chainstate,
                        mempool,
                        false,
                        None,
                        None,
                    )
                })
                .unwrap();
        }

        round += 1;

        let mp = peer_1.mempool.take().unwrap();
        peer_1_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap().len();
        peer_1.mempool.replace(mp);

        info!(
            "Peer 1: {}, Peer 2: {}",
            peer_1_mempool_txs,
            peer_2
                .network
                .mempool_sync
                .as_ref()
                .unwrap()
                .mempool_sync_txs
        );
    }

    info!("Completed mempool sync in {} step(s)", round);

    let mp = peer_2.mempool.take().unwrap();
    let peer_2_mempool_txs = MemPoolDB::get_all_txs(mp.conn()).unwrap();
    peer_2.mempool.replace(mp);

    assert_eq!(peer_2_mempool_txs.len(), 128);
}
