// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::fs;

use crate::net::stackerdb::{db::SlotValidation, SlotMetadata, StackerDBConfig, StackerDBs};

use crate::net::Error as net_error;
use crate::net::StackerDBChunkData;

use clarity::vm::ContractName;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::StacksAddress;

use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};

use stacks_common::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
};
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};

use rand::prelude::*;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;

use crate::net::relay::Relayer;
use crate::net::test::TestPeer;
use crate::net::test::TestPeerConfig;
use crate::net::ContractIdExtension;

use crate::net::ContractId;

use crate::util_lib::test::with_timeout;

const BASE_PORT: u16 = 33000;

// Minimum chunk size for FROST is 97 + T * 33, where T = 3000
const CHUNK_SIZE: u64 = 2 * (97 + 3000 * 33);

// Number of neighbors to test with
const NUM_NEIGHBORS: usize = 8;

/// Some testable configurations for stacker DB configs
impl StackerDBConfig {
    #[cfg(test)]
    pub fn one_chunk() -> StackerDBConfig {
        StackerDBConfig {
            chunk_size: CHUNK_SIZE,
            write_freq: 0,
            max_writes: u32::MAX,
            hint_peers: vec![],
            num_neighbors: NUM_NEIGHBORS,
            num_slots: 1,
        }
    }

    #[cfg(test)]
    pub fn ten_chunks() -> StackerDBConfig {
        StackerDBConfig {
            chunk_size: CHUNK_SIZE,
            write_freq: 0,
            max_writes: u32::MAX,
            hint_peers: vec![],
            num_neighbors: NUM_NEIGHBORS,
            num_slots: 10,
        }
    }
}

/// Add a stacker DB to a node's config.
/// Return its index into the list of configured stacker DBs (can be used as `idx` in the call to
/// `setup_stackerdb()`
fn add_stackerdb(config: &mut TestPeerConfig, stackerdb_config: Option<StackerDBConfig>) -> usize {
    let name = ContractName::try_from(format!("db-{}", config.stacker_dbs.len())).unwrap();
    let addr = StacksAddress {
        version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        bytes: Hash160::from_data(&config.stacker_dbs.len().to_be_bytes()),
    };

    let stackerdb_config = stackerdb_config.unwrap_or(StackerDBConfig::noop());

    config.stacker_dbs.push(ContractId::from_parts(addr, name));
    config.stacker_db_configs.push(Some(stackerdb_config));

    config.stacker_dbs.len() - 1
}

/// Set up a stacker DB and optionally fill it with random data.
/// `idx` refers to the `idx`th stacker DB in the node config struct.
fn setup_stackerdb(peer: &mut TestPeer, idx: usize, fill: bool) {
    let contract_id = &peer.config.stacker_dbs[idx];
    let rc_consensus_hash = &peer.network.get_chain_view().rc_consensus_hash;

    let noop = StackerDBConfig::noop();
    let stackerdb_config = peer.config.stacker_db_configs[idx]
        .as_ref()
        .unwrap_or(&noop);
    let num_slots = stackerdb_config.num_slots;
    let chunk_size = stackerdb_config.chunk_size;

    let mut k: u64 = 0;
    let mut pks = vec![];
    let mut slots = vec![];
    for i in 0..num_slots {
        // deterministically generate private keys
        let pk = loop {
            let h = Sha512Trunc256Sum::from_data(&k.to_be_bytes());
            k += 1;

            if let Ok(pk) = Secp256k1PrivateKey::from_slice(&h.0) {
                break pk;
            }
        };
        let pubk = StacksPublicKey::from_private(&pk);
        let addr = StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            bytes: Hash160::from_node_public_key(&pubk),
        };

        pks.push(pk);
        slots.push((addr, 1));
    }

    let tx = peer
        .network
        .stackerdbs
        .tx_begin(stackerdb_config.clone())
        .unwrap();

    tx.create_stackerdb(contract_id, &slots).unwrap();

    if fill {
        for i in 0..num_slots {
            // deterministically generate chunk data
            let mut inner_data = vec![0x00; chunk_size as usize];
            thread_rng().fill(&mut inner_data[..]);

            let mut chunk_data = StackerDBChunkData::new(i as u32, 1, inner_data);
            chunk_data.sign(&pks[i as usize]).unwrap();

            let chunk_md = chunk_data.get_slot_metadata();
            tx.try_replace_chunk(contract_id, &chunk_md, &chunk_data.data)
                .unwrap();
        }
    }

    tx.commit().unwrap();
}

/// Load up the entire stacker DB, including its metadata
fn load_stackerdb(peer: &TestPeer, idx: usize) -> Vec<(SlotMetadata, Vec<u8>)> {
    let num_slots = peer.config.stacker_db_configs[idx]
        .as_ref()
        .unwrap_or(&StackerDBConfig::noop())
        .num_slots;
    let rc_consensus_hash = &peer.network.get_chain_view().rc_consensus_hash;
    let mut ret = vec![];
    for i in 0..num_slots {
        let chunk_metadata = peer
            .network
            .stackerdbs
            .get_slot_metadata(&peer.config.stacker_dbs[idx], i as u32)
            .unwrap()
            .unwrap();
        let chunk = peer
            .network
            .stackerdbs
            .get_latest_chunk(&peer.config.stacker_dbs[idx], i as u32)
            .unwrap()
            .unwrap_or(vec![]);
        ret.push((chunk_metadata, chunk));
    }
    ret
}

#[test]
fn test_stackerdb_replica_2_neighbors_1_chunk() {
    with_timeout(600, || {
        std::env::set_var("STACKS_TEST_DISABLE_EDGE_TRIGGER_TEST", "1");
        let mut peer_1_config = TestPeerConfig::from_port(BASE_PORT);
        let mut peer_2_config = TestPeerConfig::from_port(BASE_PORT + 2);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        // set up stacker DBs for both peers
        let idx_1 = add_stackerdb(&mut peer_1_config, Some(StackerDBConfig::one_chunk()));
        let idx_2 = add_stackerdb(&mut peer_2_config, Some(StackerDBConfig::one_chunk()));

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 gets the DB
        setup_stackerdb(&mut peer_1, idx_1, true);
        setup_stackerdb(&mut peer_2, idx_2, false);

        // verify that peer 1 got the data
        let peer_1_db_chunks = load_stackerdb(&peer_1, idx_1);
        assert_eq!(peer_1_db_chunks.len(), 1);
        assert_eq!(peer_1_db_chunks[0].0.slot_id, 0);
        assert_eq!(peer_1_db_chunks[0].0.slot_version, 1);
        assert!(peer_1_db_chunks[0].1.len() > 0);

        // verify that peer 2 did NOT get the data
        let peer_2_db_chunks = load_stackerdb(&peer_2, idx_2);
        assert_eq!(peer_2_db_chunks.len(), 1);
        assert_eq!(peer_2_db_chunks[0].0.slot_id, 0);
        assert_eq!(peer_2_db_chunks[0].0.slot_version, 0);
        assert!(peer_2_db_chunks[0].1.len() == 0);

        let peer_1_db_configs = peer_1.config.get_stacker_db_configs();
        let peer_2_db_configs = peer_2.config.get_stacker_db_configs();

        let mut i = 0;
        loop {
            // run peer network state-machines
            let res_1 = peer_1.step();
            let res_2 = peer_2.step();

            if let Ok(mut res) = res_1 {
                Relayer::process_stacker_db_chunks(
                    &mut peer_1.network.stackerdbs,
                    &peer_1_db_configs,
                    &res.stacker_db_sync_results,
                )
                .unwrap();
                Relayer::process_pushed_stacker_db_chunks(
                    &mut peer_1.network.stackerdbs,
                    &peer_1_db_configs,
                    &mut res.unhandled_messages,
                )
                .unwrap();
            }

            if let Ok(mut res) = res_2 {
                Relayer::process_stacker_db_chunks(
                    &mut peer_2.network.stackerdbs,
                    &peer_2_db_configs,
                    &res.stacker_db_sync_results,
                )
                .unwrap();
                Relayer::process_pushed_stacker_db_chunks(
                    &mut peer_2.network.stackerdbs,
                    &peer_2_db_configs,
                    &mut res.unhandled_messages,
                )
                .unwrap();
            }

            let db1 = load_stackerdb(&peer_1, idx_1);
            let db2 = load_stackerdb(&peer_2, idx_2);

            if db1 == db2 {
                break;
            }
            i += 1;
        }

        debug!("Completed stacker DB sync in {} step(s)", i);
    })
}

#[test]
fn test_stackerdb_replica_2_neighbors_10_chunks() {
    inner_test_stackerdb_replica_2_neighbors_10_chunks(false);
}

#[test]
fn test_stackerdb_replica_2_neighbors_10_push_chunks() {
    inner_test_stackerdb_replica_2_neighbors_10_chunks(true);
}

fn inner_test_stackerdb_replica_2_neighbors_10_chunks(push_only: bool) {
    with_timeout(600, move || {
        std::env::set_var("STACKS_TEST_DISABLE_EDGE_TRIGGER_TEST", "1");
        let mut peer_1_config = TestPeerConfig::from_port(BASE_PORT + 4);
        let mut peer_2_config = TestPeerConfig::from_port(BASE_PORT + 6);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        if push_only {
            peer_1_config.connection_opts.disable_stackerdb_get_chunks = true;
            peer_2_config.connection_opts.disable_stackerdb_get_chunks = true;
        }

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        // set up stacker DBs for both peers
        let idx_1 = add_stackerdb(&mut peer_1_config, Some(StackerDBConfig::ten_chunks()));
        let idx_2 = add_stackerdb(&mut peer_2_config, Some(StackerDBConfig::ten_chunks()));

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 gets the DB
        setup_stackerdb(&mut peer_1, idx_1, true);
        setup_stackerdb(&mut peer_2, idx_2, false);

        // verify that peer 1 got the data
        let peer_1_db_chunks = load_stackerdb(&peer_1, idx_1);
        assert_eq!(peer_1_db_chunks.len(), 10);
        for i in 0..10 {
            assert_eq!(peer_1_db_chunks[i].0.slot_id, i as u32);
            assert_eq!(peer_1_db_chunks[i].0.slot_version, 1);
            assert!(peer_1_db_chunks[i].1.len() > 0);
        }

        // verify that peer 2 did NOT get the data
        let peer_2_db_chunks = load_stackerdb(&peer_2, idx_2);
        assert_eq!(peer_2_db_chunks.len(), 10);
        for i in 0..10 {
            assert_eq!(peer_2_db_chunks[i].0.slot_id, i as u32);
            assert_eq!(peer_2_db_chunks[i].0.slot_version, 0);
            assert!(peer_2_db_chunks[i].1.len() == 0);
        }

        let peer_1_db_configs = peer_1.config.get_stacker_db_configs();
        let peer_2_db_configs = peer_2.config.get_stacker_db_configs();

        let mut i = 0;
        loop {
            // run peer network state-machines
            let res_1 = peer_1.step();
            let res_2 = peer_2.step();

            if let Ok(mut res) = res_1 {
                Relayer::process_stacker_db_chunks(
                    &mut peer_1.network.stackerdbs,
                    &peer_1_db_configs,
                    &res.stacker_db_sync_results,
                )
                .unwrap();
                Relayer::process_pushed_stacker_db_chunks(
                    &mut peer_1.network.stackerdbs,
                    &peer_1_db_configs,
                    &mut res.unhandled_messages,
                )
                .unwrap();
            }

            if let Ok(mut res) = res_2 {
                Relayer::process_stacker_db_chunks(
                    &mut peer_2.network.stackerdbs,
                    &peer_2_db_configs,
                    &res.stacker_db_sync_results,
                )
                .unwrap();
                Relayer::process_pushed_stacker_db_chunks(
                    &mut peer_2.network.stackerdbs,
                    &peer_2_db_configs,
                    &mut res.unhandled_messages,
                )
                .unwrap();
            }

            let db1 = load_stackerdb(&peer_1, idx_1);
            let db2 = load_stackerdb(&peer_2, idx_2);

            if db1 == db2 {
                break;
            }
            i += 1;

            debug!("StackerDB sync step {}", i);
        }

        debug!("Completed stacker DB sync in {} step(s)", i);
    })
}

#[test]
fn test_stackerdb_replica_10_neighbors_line_10_chunks() {
    inner_test_stackerdb_replica_10_neighbors_line_10_chunks(false);
}

#[test]
fn test_stackerdb_replica_10_neighbors_line_push_10_chunks() {
    inner_test_stackerdb_replica_10_neighbors_line_10_chunks(true);
}

fn inner_test_stackerdb_replica_10_neighbors_line_10_chunks(push_only: bool) {
    with_timeout(600, move || {
        std::env::set_var("STACKS_TEST_DISABLE_EDGE_TRIGGER_TEST", "1");
        let num_peers: usize = 10;
        let mut peer_configs = vec![];
        let mut peer_db_idxs = vec![];
        let mut peers = vec![];
        let mut peer_db_configs = vec![];

        for i in 0..num_peers {
            let mut peer_config = TestPeerConfig::from_port(
                BASE_PORT + 8 + (2 * i as u16) + (if push_only { 28 } else { 0 }),
            );

            peer_config.allowed = -1;

            if push_only {
                peer_config.connection_opts.disable_stackerdb_get_chunks = true;
            }

            // short-lived walks...
            peer_config.connection_opts.walk_max_duration = 10;
            let idx = add_stackerdb(&mut peer_config, Some(StackerDBConfig::ten_chunks()));

            peer_configs.push(peer_config);
            peer_db_idxs.push(idx);
        }

        // line topology: neighbor N connects to neighbors N-1 and N+1
        for i in 1..(num_peers - 1) {
            let n1 = peer_configs[i - 1].to_neighbor();
            let n2 = peer_configs[i + 1].to_neighbor();
            peer_configs[i].add_neighbor(&n1);
            peer_configs[i].add_neighbor(&n2);
        }

        for (i, peer_config) in peer_configs.into_iter().enumerate() {
            let mut peer = TestPeer::new(peer_config);

            if i == 0 {
                // peer 0 -- at one end of the line -- gets the initial DB
                setup_stackerdb(&mut peer, peer_db_idxs[i], true);

                // verify instantiation
                let peer_db_chunks = load_stackerdb(&peer, peer_db_idxs[i]);
                assert_eq!(peer_db_chunks.len(), 10);
                for j in 0..10 {
                    assert_eq!(peer_db_chunks[j].0.slot_id, j as u32);
                    assert_eq!(peer_db_chunks[j].0.slot_version, 1);
                    assert!(peer_db_chunks[j].1.len() > 0);
                }
            } else {
                // everyone else gets nothing
                setup_stackerdb(&mut peer, peer_db_idxs[i], false);

                // verify instantiation
                let peer_db_chunks = load_stackerdb(&peer, peer_db_idxs[i]);
                assert_eq!(peer_db_chunks.len(), 10);
                for j in 0..10 {
                    assert_eq!(peer_db_chunks[j].0.slot_id, j as u32);
                    assert_eq!(peer_db_chunks[j].0.slot_version, 0);
                    assert!(peer_db_chunks[j].1.len() == 0);
                }
            }

            peers.push(peer);
        }

        for (i, peer) in peers.iter().enumerate() {
            let peer_db_config = peer.config.get_stacker_db_configs();
            peer_db_configs.push(peer_db_config);
        }
        let mut step_count = 0;
        loop {
            // run peer network state-machines
            for i in 0..num_peers {
                let res = peers[i].step();
                if let Ok(mut res) = res {
                    let rc_consensus_hash =
                        peers[i].network.get_chain_view().rc_consensus_hash.clone();
                    Relayer::process_stacker_db_chunks(
                        &mut peers[i].network.stackerdbs,
                        &peer_db_configs[i],
                        &res.stacker_db_sync_results,
                    )
                    .unwrap();
                    Relayer::process_pushed_stacker_db_chunks(
                        &mut peers[i].network.stackerdbs,
                        &peer_db_configs[i],
                        &mut res.unhandled_messages,
                    )
                    .unwrap();
                }
            }

            let mut db_state = None;
            let mut different = false;
            for i in 0..num_peers {
                let db = load_stackerdb(&peers[i], peer_db_idxs[i]);
                if let Some(cmp_db) = db_state.as_ref() {
                    if &db != cmp_db {
                        different = true;
                        break;
                    }
                } else {
                    db_state = Some(db);
                }
            }

            if !different {
                break;
            }
            step_count += 1;
        }

        debug!("Completed stacker DB sync in {} step(s)", step_count);
    })
}

#[test]
fn test_stackerdb_10_replicas_10_neighbors_line_10_chunks() {
    with_timeout(600, || {
        std::env::set_var("STACKS_TEST_DISABLE_EDGE_TRIGGER_TEST", "1");
        let num_peers: usize = 10;
        let num_dbs: usize = 10;
        let mut peer_configs = vec![];
        let mut peer_db_idxs = vec![];
        let mut peers = vec![];
        let mut peer_db_configs = vec![];

        for i in 0..num_peers {
            let mut peer_config = TestPeerConfig::from_port(BASE_PORT + 56 + (2 * i as u16));

            peer_config.allowed = -1;

            // short-lived walks...
            peer_config.connection_opts.walk_max_duration = 10;

            // bigger inbox/outbox
            peer_config.connection_opts.inbox_maxlen = 101;
            peer_config.connection_opts.outbox_maxlen = 101;

            let mut idxs = vec![];
            for j in 0..10 {
                let idx = add_stackerdb(&mut peer_config, Some(StackerDBConfig::ten_chunks()));
                idxs.push(idx);
            }

            peer_configs.push(peer_config);
            peer_db_idxs.push(idxs);
        }

        // line topology: neighbor N connects to neighbors N-1 and N+1
        for i in 1..(num_peers - 1) {
            let n1 = peer_configs[i - 1].to_neighbor();
            let n2 = peer_configs[i + 1].to_neighbor();
            peer_configs[i].add_neighbor(&n1);
            peer_configs[i].add_neighbor(&n2);
        }

        for (i, peer_config) in peer_configs.into_iter().enumerate() {
            let mut peer = TestPeer::new(peer_config);

            if i == 0 {
                for j in 0..peer_db_idxs[i].len() {
                    // peer 0 -- at one end of the line -- gets the initial DBs
                    setup_stackerdb(&mut peer, peer_db_idxs[i][j], true);

                    // verify instantiation
                    let peer_db_chunks = load_stackerdb(&peer, peer_db_idxs[i][j]);
                    assert_eq!(peer_db_chunks.len(), 10);
                    for k in 0..10 {
                        assert_eq!(peer_db_chunks[k].0.slot_id, k as u32);
                        assert_eq!(peer_db_chunks[k].0.slot_version, 1);
                        assert!(peer_db_chunks[k].1.len() > 0);
                    }
                }
            } else {
                for j in 0..peer_db_idxs[i].len() {
                    // everyone else gets nothing
                    setup_stackerdb(&mut peer, peer_db_idxs[i][j], false);

                    // verify instantiation
                    let peer_db_chunks = load_stackerdb(&peer, peer_db_idxs[i][j]);
                    assert_eq!(peer_db_chunks.len(), 10);
                    for k in 0..10 {
                        assert_eq!(peer_db_chunks[k].0.slot_id, k as u32);
                        assert_eq!(peer_db_chunks[k].0.slot_version, 0);
                        assert!(peer_db_chunks[k].1.len() == 0);
                    }
                }
            }

            peers.push(peer);
        }

        for (i, peer) in peers.iter().enumerate() {
            let peer_db_config = peer.config.get_stacker_db_configs();
            peer_db_configs.push(peer_db_config);
        }
        let mut step_count = 0;
        loop {
            // run peer network state-machines
            for i in 0..num_peers {
                let res = peers[i].step();
                if let Ok(mut res) = res {
                    let rc_consensus_hash =
                        peers[i].network.get_chain_view().rc_consensus_hash.clone();
                    Relayer::process_stacker_db_chunks(
                        &mut peers[i].network.stackerdbs,
                        &peer_db_configs[i],
                        &res.stacker_db_sync_results,
                    )
                    .unwrap();
                    Relayer::process_pushed_stacker_db_chunks(
                        &mut peers[i].network.stackerdbs,
                        &peer_db_configs[i],
                        &mut res.unhandled_messages,
                    )
                    .unwrap();
                }
            }

            let mut different = false;
            for k in 0..num_dbs {
                for i in 0..num_peers {
                    let db1 = load_stackerdb(&peers[i], peer_db_idxs[i][k]);
                    for j in (i + 1)..num_peers {
                        let db2 = load_stackerdb(&peers[j], peer_db_idxs[j][k]);
                        if db1 != db2 {
                            debug!("Different {}: {} != {}", k, i, j);
                            different = true;
                            break;
                        }
                    }
                    if different {
                        break;
                    }
                }
                if different {
                    break;
                }
            }

            if !different {
                break;
            }
            step_count += 1;
        }

        debug!("Completed stacker DB sync in {} step(s)", step_count);

        // we were efficient
        for (i, peer) in peers.iter().enumerate() {
            for (_, sync_state) in peer.network.stacker_db_syncs.as_ref().unwrap().iter() {
                if i != 0 {
                    assert!(sync_state.total_stored >= 10);
                }
            }
        }
    })
}
