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

use clarity::vm::types::{StacksAddressExtensions, StandardPrincipalData};
use rand::prelude::*;
use rand::thread_rng;
use stacks_common::util::hash::*;
use stacks_common::util::sleep_ms;

use crate::core::{
    StacksEpoch, StacksEpochId, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_TESTNET, STACKS_EPOCH_MAX,
};
use crate::net::asn::*;
use crate::net::chat::*;
use crate::net::db::*;
use crate::net::neighbors::*;
use crate::net::test::*;
use crate::net::{Error as net_error, *};
use crate::util_lib::test::*;

const TEST_IN_OUT_DEGREES: u64 = 0x1;

#[test]
#[ignore]
fn test_step_walk_1_neighbor_plain() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(31890);
        let peer_2_config = TestPeerConfig::from_port(31892);

        // peer 1 crawls peer 2, but not vice versa
        // (so only peer 1 will learn its public IP)
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        while (walk_1_count < 20 || walk_2_count < 20)
            || (!peer_1.network.public_ip_confirmed)
            || peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .is_none()
        {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 1 learned and confirmed its public IP address from peer 2
        assert!(peer_1.network.get_local_peer().public_ip_address.is_some());
        assert_eq!(
            peer_1
                .network
                .get_local_peer()
                .public_ip_address
                .clone()
                .unwrap(),
            (
                PeerAddress::from_socketaddr(
                    &format!("127.0.0.1:1").parse::<SocketAddr>().unwrap()
                ),
                31890
            )
        );
        assert!(peer_1.network.public_ip_learned);
        assert!(peer_1.network.public_ip_confirmed);

        // peer 2 learned nothing, despite trying
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
        assert!(peer_2.network.public_ip_learned);
        assert!(!peer_2.network.public_ip_confirmed);
    })
}

#[test]
#[ignore]
fn test_step_walk_1_neighbor_plain_no_natpunch() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(31980);
        let mut peer_2_config = TestPeerConfig::from_port(31982);

        // simulate peer 2 not knowing how to handle a natpunch request
        peer_2_config.connection_opts.disable_natpunch = true;

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        let mut stats_1 = None;

        while (walk_1_count < 20 || walk_2_count < 20) || stats_1.is_none() {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            if let Some(s) = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
            {
                stats_1 = Some(s);
            }

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = stats_1.unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 1 did not learn IP address
        assert!(peer_1.network.get_local_peer().public_ip_address.is_none());
        assert!(!peer_1.network.public_ip_confirmed);

        // peer 2 did not learn IP address
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
        assert!(!peer_2.network.public_ip_confirmed);
    })
}

#[test]
#[ignore]
fn test_step_walk_1_neighbor_denied() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(31994);
        let mut peer_2_config = TestPeerConfig::from_port(31996);

        // peer 1 crawls peer 2, but peer 1 has denied peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        peer_1_config.connection_opts.walk_retry_count = 10;
        peer_2_config.connection_opts.walk_retry_count = 10;
        peer_1_config.connection_opts.walk_interval = 1;
        peer_2_config.connection_opts.walk_interval = 1;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        {
            let mut tx = peer_1.network.peerdb.tx_begin().unwrap();
            PeerDB::add_deny_cidr(&mut tx, &PeerAddress::from_ipv4(127, 0, 0, 1), 128).unwrap();
            tx.commit().unwrap();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut walk_1_retries = 0;
        let mut walk_2_retries = 0;
        let mut walk_1_total = 0;
        let mut walk_2_total = 0;

        // walks just don't start.
        // neither peer learns their public IP addresses.
        while walk_1_retries < 20 && walk_2_retries < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            walk_1_total = peer_1.network.walk_count;
            walk_2_total = peer_2.network.walk_count;

            assert_eq!(walk_1_total, 0);
            assert_eq!(walk_2_total, 0);

            walk_1_retries = peer_1.network.walk_retries;
            walk_2_retries = peer_2.network.walk_retries;

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        assert!(peer_1.network.public_ip_learned);
        assert!(!peer_1.network.public_ip_confirmed);
        assert!(peer_1.network.get_local_peer().public_ip_address.is_none());

        assert!(peer_2.network.public_ip_learned);
        assert!(!peer_2.network.public_ip_confirmed);
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
    })
}

#[test]
#[ignore]
fn test_step_walk_1_neighbor_bad_epoch() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(31998);
        let mut peer_2_config = TestPeerConfig::from_port(31990);

        peer_1_config.connection_opts.walk_retry_count = 10;
        peer_2_config.connection_opts.walk_retry_count = 10;
        peer_1_config.connection_opts.walk_interval = 1;
        peer_2_config.connection_opts.walk_interval = 1;

        // peer 1 thinks its always epoch 2.0
        peer_1_config.peer_version = 0x18000000;
        peer_1_config.epochs = Some(vec![StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        }]);

        // peer 2 thinks its always epoch 2.05
        peer_2_config.peer_version = 0x18000005;
        peer_2_config.epochs = Some(vec![StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        }]);

        // peers know about each other, but peer 2 never talks to peer 1 since it believes that
        // it's in a wholly different epoch
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut walk_1_retries = 0;
        let mut walk_2_retries = 0;
        let mut walk_1_total = 0;
        let mut walk_2_total = 0;

        // walks just don't start.
        // neither peer learns their public IP addresses.
        while walk_1_retries < 20 && walk_2_retries < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            walk_1_total = peer_1.network.walk_count;
            walk_2_total = peer_2.network.walk_count;

            assert_eq!(walk_1_total, 0);
            assert_eq!(walk_2_total, 0);

            walk_1_retries = peer_1.network.walk_attempts;
            walk_2_retries = peer_2.network.walk_attempts;

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;

            debug!("attempts: {},{}", walk_1_retries, walk_2_retries);
        }

        assert!(peer_1.network.public_ip_learned);
        assert!(!peer_1.network.public_ip_confirmed);
        assert!(peer_1.network.get_local_peer().public_ip_address.is_none());

        assert!(peer_2.network.public_ip_learned);
        assert!(!peer_2.network.public_ip_confirmed);
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
    })
}

#[test]
#[ignore]
fn test_step_walk_1_neighbor_heartbeat_ping() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32992);
        let mut peer_2_config = TestPeerConfig::from_port(32994);

        peer_1_config.connection_opts.heartbeat = 10;
        peer_2_config.connection_opts.heartbeat = 10;

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        info!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        assert_eq!(peer_1.network.relay_handles.len(), 0);
        assert_eq!(peer_2.network.relay_handles.len(), 0);

        info!("Wait 60 seconds for ping timeout");
        sleep_ms(60000);

        peer_1.network.queue_ping_heartbeats();
        peer_2.network.queue_ping_heartbeats();

        // pings queued
        assert_eq!(peer_1.network.relay_handles.len(), 1);
        assert_eq!(peer_2.network.relay_handles.len(), 1);
    })
}

#[test]
#[ignore]
fn test_step_walk_1_neighbor_bootstrapping() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32100);
        let peer_2_config = TestPeerConfig::from_port(32102);

        // peer 1 crawls peer 2, but peer 1 doesn't add peer 2 to its frontier becuase peer 2 is
        // too far behind.
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // advance peer 1
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
            peer_1.add_empty_burnchain_block();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        let neighbor_2 = peer_2.to_neighbor();

        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);

                    // peer 2 never gets added to peer 1's frontier
                    assert!(w.frontier.get(&neighbor_2.addr).is_none());
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    })
}

#[test]
#[ignore]
fn test_step_walk_1_neighbor_behind() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32200);
        let mut peer_2_config = TestPeerConfig::from_port(32202);

        peer_1_config.connection_opts.disable_natpunch = true;
        peer_2_config.connection_opts.disable_natpunch = true;

        // peer 1 crawls peer 2, and peer 1 adds peer 2 to its frontier even though peer 2 does
        // not, because peer 2 is too far ahead
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // advance peer 2
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
            peer_2.add_empty_burnchain_block();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        while (walk_1_count < 20 && walk_2_count < 20)
            || peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .is_none()
        {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);

                    // peer 1 never gets added to peer 2's frontier
                    assert!(w.frontier.get(&neighbor_1.addr).is_none());
                }
                None => {}
            };

            i += 1;

            debug!("Peer 1 begin neighbor stats:");
            for (nk, _) in peer_1.network.events.iter() {
                match peer_1.network.get_neighbor_stats(nk) {
                    Some(ns) => {
                        debug!("   have stats for {:?}", &nk);
                    }
                    None => {
                        debug!("   (no stats for {:?})", &nk);
                    }
                }
            }
            debug!("Peer 1 end neighbor stats");
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 was added to the peer DB of peer 1, even though peer 1 is very behind peer 2
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }
    })
}

#[test]
#[ignore]
fn test_step_walk_10_neighbors_of_neighbor_plain() {
    with_timeout(600, || {
        // peer 1 has peer 2 as its neighbor.
        // peer 2 has 10 other neighbors.
        // Goal: peer 1 learns about the 10 other neighbors.
        let mut peer_1_config = TestPeerConfig::from_port(32300);
        let mut peer_2_config = TestPeerConfig::from_port(32302);

        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let mut peer_2_neighbors = vec![];
        for i in 0..10 {
            let mut n = TestPeerConfig::from_port(2 * i + 4 + 32300);

            // turn off features we don't use
            n.connection_opts.disable_inv_sync = true;
            n.connection_opts.disable_block_download = true;

            peer_2_config.add_neighbor(&n.to_neighbor());

            let p = TestPeer::new(n);
            peer_2_neighbors.push(p);
        }

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // next, make peer 1 discover peer 2's neighbors and peer 2's in/out degree.
        // Do two full walks
        let mut i = 0;
        let mut did_connect = false;
        while !did_connect {
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            while walk_1_count < 20 && walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                for j in 0..10 {
                    let _ = peer_2_neighbors[j].step();
                }

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;
            }

            // peer 1 must have handshaked with all of peer 2's neighbors if this test will pass
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            let mut num_handshakes = 0;
            for peer in &peer_2_neighbors {
                let n = peer.to_neighbor();
                let p_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    n.addr.network_id,
                    &n.addr.addrbytes,
                    n.addr.port,
                )
                .unwrap();
                match p_opt {
                    None => {
                        test_debug!("no such peer: {:?}", &n.addr);
                    }
                    Some(p) => {
                        assert_eq!(p.public_key, n.public_key);
                        assert_eq!(p.expire_block, n.expire_block);
                        num_handshakes += 1;
                    }
                }
            }

            if num_handshakes < 10 {
                continue;
            }

            // peer 1 learned that peer 2 has an out-degree of 10 (10 neighbors) and an in-degree of 1 if this test will pass
            let n2 = peer_2.to_neighbor();
            let p2_opt = PeerDB::get_peer(
                peer_1_dbconn,
                n2.addr.network_id,
                &n2.addr.addrbytes,
                n2.addr.port,
            )
            .unwrap();
            match p2_opt {
                None => {
                    test_debug!("no peer 2");
                }
                Some(p2) => {
                    if p2.out_degree >= 11 && p2.in_degree >= 1 {
                        assert_eq!(p2.out_degree, 11);
                        did_connect = true;
                    }
                }
            }
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    })
}

#[test]
#[ignore]
fn test_step_walk_10_neighbors_of_neighbor_bootstrapping() {
    with_timeout(600, || {
        // peer 1 has peer 2 as its neighbor.
        // peer 2 has 10 other neighbors, 5 of which are too far behind peer 1.
        // Goal: peer 1 learns about the 5 fresher neighbors.
        let mut peer_1_config = TestPeerConfig::from_port(32400);
        let mut peer_2_config = TestPeerConfig::from_port(32402);

        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let mut peer_2_neighbors = vec![];
        for i in 0..10 {
            let mut n = TestPeerConfig::from_port(2 * i + 4 + 32400);

            // turn off features we don't use
            n.connection_opts.disable_inv_sync = true;
            n.connection_opts.disable_block_download = true;

            peer_2_config.add_neighbor(&n.to_neighbor());

            let p = TestPeer::new(n);
            peer_2_neighbors.push(p);
        }

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // advance peer 1 and peer 2, and some of peer 2's neighbors
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
            peer_1.add_empty_burnchain_block();
            peer_2.add_empty_burnchain_block();
            for j in 0..5 {
                peer_2_neighbors[j].add_empty_burnchain_block();
            }
        }

        // next, make peer 1 discover peer 2's neighbors and peer 2's in/out degree.
        let mut steps = 0;
        let mut did_handshakes = false;
        while !did_handshakes {
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            while walk_1_count < 20 && walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                for j in 0..10 {
                    let _ = peer_2_neighbors[j].step();
                }

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                steps += 1;
            }

            peer_1.dump_frontier();
            peer_2.dump_frontier();

            // check if peer 1 handshaked with all of peer 2's _fresh_ neighbors
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            let mut num_contacted = 0; // should be 5 when test finishes
            for i in 0..5 {
                let peer = &peer_2_neighbors[i];
                let n = peer.to_neighbor();
                let p_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    n.addr.network_id,
                    &n.addr.addrbytes,
                    n.addr.port,
                )
                .unwrap();
                match p_opt {
                    None => {
                        test_debug!("no such peer: {:?}", &n.addr);
                    }
                    Some(p) => {
                        assert_eq!(p.public_key, n.public_key);
                        assert_eq!(p.expire_block, n.expire_block);
                        num_contacted += 1;
                    }
                }

                let stale_peer = &peer_2_neighbors[i + 5];
                let stale_n = stale_peer.to_neighbor();
                let stale_peer_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    stale_n.addr.network_id,
                    &stale_n.addr.addrbytes,
                    stale_n.addr.port,
                )
                .unwrap();
                match stale_peer_opt {
                    None => {}
                    Some(_) => {
                        test_debug!("stale peer contacted: {:?}", &stale_n.addr);
                        assert!(false);
                    }
                }
            }

            test_debug!(
                "Peer 1 has contactd {} of Peer 2's neighbors",
                num_contacted
            );

            if num_contacted < 5 {
                continue;
            }

            // peer 1 learned that peer 2 has an out-degree of 6 (peer_1 + 5 fresh neighbors) and an in-degree of 1
            let n2 = peer_2.to_neighbor();
            let p2_opt = PeerDB::get_peer(
                peer_1_dbconn,
                n2.addr.network_id,
                &n2.addr.addrbytes,
                n2.addr.port,
            )
            .unwrap();
            match p2_opt {
                None => {
                    test_debug!("no peer 2");
                }
                Some(p2) => {
                    if p2.out_degree >= 6 && p2.in_degree >= 1 {
                        assert_eq!(p2.out_degree, 6);
                        did_handshakes = true;
                    }
                }
            }
        }

        debug!("Completed walk round {} step(s)", steps);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    })
}

#[test]
fn test_step_walk_2_neighbors_plain() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32500);
        let mut peer_2_config = TestPeerConfig::from_port(32502);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        // NOTE: 2x the max walk duration
        while walk_1_count < 20 || walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        // peer 2 contacted peer 1
        let stats_2 = peer_2
            .network
            .get_neighbor_stats(&peer_1.to_neighbor().addr)
            .unwrap();
        assert!(stats_2.last_contact_time > 0);
        assert!(stats_2.last_handshake_time > 0);
        assert!(stats_2.last_send_time > 0);
        assert!(stats_2.last_recv_time > 0);
        assert!(stats_2.bytes_rx > 0);
        assert!(stats_2.bytes_tx > 0);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 was added to the peer DB of peer 1
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 1 was added to the peer DB of peer 2
        let peer_2_dbconn = peer_2.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_2_dbconn,
            neighbor_1.addr.network_id,
            &neighbor_1.addr.addrbytes,
            neighbor_1.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_1.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_1.public_key);
                assert_eq!(p.expire_block, neighbor_1.expire_block);
            }
        }

        // walks were reset at least once
        assert!(peer_1.network.walk_count > 0);
        assert!(peer_2.network.walk_count > 0);
    })
}

#[test]
fn test_step_walk_2_neighbors_state_timeout() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32504);
        let mut peer_2_config = TestPeerConfig::from_port(32506);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        peer_1_config.connection_opts.walk_state_timeout = 1;
        peer_2_config.connection_opts.walk_state_timeout = 1;

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        for _i in 0..10 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            let walk_1_count = peer_1.network.walk_total_step_count;
            let walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            sleep_ms(3_000);
        }

        // state resets trigger walk resets
        assert!(peer_1.network.walk_resets > 0);
        assert!(peer_2.network.walk_resets > 0);
    })
}

#[test]
fn test_step_walk_2_neighbors_walk_timeout() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32508);
        let mut peer_2_config = TestPeerConfig::from_port(32510);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        peer_1_config.connection_opts.walk_state_timeout = 20;
        peer_2_config.connection_opts.walk_state_timeout = 20;

        peer_1_config.connection_opts.walk_reset_interval = 10;
        peer_2_config.connection_opts.walk_reset_interval = 10;

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_step_count = 0;
        let mut walk_2_step_count = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        while walk_1_step_count < 20 || walk_2_step_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_step_count = peer_1.network.walk_total_step_count;
            walk_2_step_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_step_count,
                walk_2_step_count
            );

            if walk_1_count < peer_1.network.walk_count || walk_2_count < peer_2.network.walk_count
            {
                // force walk to time out
                sleep_ms(11_000);
            }

            walk_1_count = peer_1
                .network
                .walk
                .as_ref()
                .map(|w| w.walk_step_count)
                .unwrap_or(0);
            walk_2_count = peer_1
                .network
                .walk
                .as_ref()
                .map(|w| w.walk_step_count)
                .unwrap_or(0);

            i += 1;
        }

        // walk timeouts trigger walk resets
        assert!(peer_1.network.walk_resets > 0);
        assert!(peer_2.network.walk_resets > 0);
    })
}

#[test]
#[ignore]
fn test_step_walk_3_neighbors_inbound() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32520);
        let mut peer_2_config = TestPeerConfig::from_port(32522);
        let mut peer_3_config = TestPeerConfig::from_port(32524);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;
        peer_3_config.allowed = -1;

        peer_1_config.connection_opts.disable_pingbacks = true;
        peer_2_config.connection_opts.disable_pingbacks = true;
        peer_3_config.connection_opts.disable_pingbacks = true;

        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_3_config.connection_opts.disable_inv_sync = true;

        peer_1_config.connection_opts.disable_block_download = true;
        peer_2_config.connection_opts.disable_block_download = true;
        peer_3_config.connection_opts.disable_block_download = true;

        // Peer 2 and peer 3 are public nodes that don't know about each other, but peer 1 lists
        // both of them as outbound neighbors.  Goal is for peer 2 to learn about peer 3, and vice
        // versa, by crawling peer 1 through an inbound neighbor walk.
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_1_config.add_neighbor(&peer_3_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);
        let mut peer_3 = TestPeer::new(peer_3_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut walk_3_count = 0;
        let mut peer_1_frontier_size = 0;
        let mut peer_2_frontier_size = 0;
        let mut peer_3_frontier_size = 0;
        while peer_2_frontier_size < 2 || peer_3_frontier_size < 2 {
            let _ = peer_1.step();
            let _ = peer_2.step();
            let _ = peer_3.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;
            walk_3_count = peer_3.network.walk_total_step_count;

            test_debug!("========");
            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps; peer 3 took {} steps",
                walk_1_count,
                walk_2_count,
                walk_3_count
            );
            test_debug!(
                "peer 1 frontier size: {}, peer 2 frontier size: {}, peer 3 frontier size: {}",
                peer_1_frontier_size,
                peer_2_frontier_size,
                peer_3_frontier_size
            );
            test_debug!("========");

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_3.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            for (i, peer) in [&peer_1, &peer_2, &peer_3].iter().enumerate() {
                let db = peer.get_peerdb_conn();
                let neighbors = PeerDB::get_all_peers(db).unwrap();
                test_debug!("Begin neighbor dump from {:?}", &peer.to_neighbor().addr);
                for n in neighbors {
                    test_debug!("   {:?}", &n.addr);
                }
                test_debug!("End neighbor dump from {:?}", &peer.to_neighbor().addr);
            }

            peer_1_frontier_size = PeerDB::get_all_peers(peer_1.get_peerdb_conn())
                .unwrap()
                .len();
            peer_2_frontier_size = PeerDB::get_all_peers(peer_2.get_peerdb_conn())
                .unwrap()
                .len();
            peer_3_frontier_size = PeerDB::get_all_peers(peer_3.get_peerdb_conn())
                .unwrap()
                .len();

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();
        let neighbor_3 = peer_3.to_neighbor();

        // peer 2 was added to the peer DB of peer 1
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer_by_port(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 3 was added to the peer DB of peer 1
        match PeerDB::get_peer_by_port(
            peer_1_dbconn,
            neighbor_3.addr.network_id,
            neighbor_3.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_3.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_3.public_key);
                assert_eq!(p.expire_block, neighbor_3.expire_block);
            }
        }

        // peer 2 was added to the peer DB of peer 3
        let peer_2_dbconn = peer_2.get_peerdb_conn();
        match PeerDB::get_peer_by_port(
            peer_2_dbconn,
            neighbor_3.addr.network_id,
            neighbor_3.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_3.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_3.public_key);
                assert_eq!(p.expire_block, neighbor_3.expire_block);
            }
        }

        // peer 3 was added to the peer DB of peer 2
        let peer_3_dbconn = peer_3.get_peerdb_conn();
        match PeerDB::get_peer_by_port(
            peer_3_dbconn,
            neighbor_2.addr.network_id,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }
    })
}

#[test]
#[ignore]
fn test_step_walk_2_neighbors_rekey() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::from_port(32600);
        let mut peer_2_config = TestPeerConfig::from_port(32602);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // turn off features we don't use
        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let first_block_height = peer_1_config.current_block + 1;

        // make keys expire soon
        peer_1_config.private_key_expire = first_block_height + 3;
        peer_2_config.private_key_expire = first_block_height + 4;

        peer_1_config.connection_opts.private_key_lifetime = 5;
        peer_2_config.connection_opts.private_key_lifetime = 5;

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let initial_public_key_1 = peer_1.get_public_key();
        let initial_public_key_2 = peer_2.get_public_key();

        // walk for a bit
        for i in 0..10 {
            for j in 0..5 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };
            }

            peer_1.add_empty_burnchain_block();
            peer_2.add_empty_burnchain_block();
        }

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        // peer 2 contacted peer 1
        let stats_2 = peer_2
            .network
            .get_neighbor_stats(&peer_1.to_neighbor().addr)
            .unwrap();
        assert!(stats_2.last_contact_time > 0);
        assert!(stats_2.last_handshake_time > 0);
        assert!(stats_2.last_send_time > 0);
        assert!(stats_2.last_recv_time > 0);
        assert!(stats_2.bytes_rx > 0);
        assert!(stats_2.bytes_tx > 0);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 1 was added to the peer DB of peer 2
        assert!(PeerDB::get_peer(
            peer_1.network.peerdb.conn(),
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port
        )
        .unwrap()
        .is_some());

        // peer 2 was added to the peer DB of peer 1
        assert!(PeerDB::get_peer(
            peer_2.network.peerdb.conn(),
            neighbor_1.addr.network_id,
            &neighbor_1.addr.addrbytes,
            neighbor_1.addr.port
        )
        .unwrap()
        .is_some());

        // new keys
        assert!(peer_1.get_public_key() != initial_public_key_1);
        assert!(peer_2.get_public_key() != initial_public_key_2);
    })
}

#[test]
fn test_step_walk_2_neighbors_different_networks() {
    with_timeout(600, || {
        // peer 1 and 2 try to handshake but never succeed since they have different network IDs
        let mut peer_1_config = TestPeerConfig::from_port(32700);
        let mut peer_2_config = TestPeerConfig::from_port(32702);

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        // peer 2 thinks peer 1 has the same network ID that it does
        println!("1 ~~~ {}", peer_1_config.network_id);
        println!("2 ~~~ {}", peer_2_config.network_id);

        peer_1_config.network_id = peer_1_config.network_id + 1;
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());
        peer_1_config.network_id = peer_1_config.network_id - 1;

        // different network IDs
        peer_2_config.network_id = peer_1_config.network_id + 1;

        println!("3 ~~~ {}", peer_1_config.network_id);
        println!("4 ~~~ {}", peer_2_config.network_id);

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);
        println!("5 ~~~");

        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut i = 0;
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 did NOT contact peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr);
        assert!(stats_1.is_none());

        // peer 2 did NOT contact peer 1
        let stats_2 = peer_2
            .network
            .get_neighbor_stats(&peer_1.to_neighbor().addr);
        assert!(stats_2.is_none());

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 1 was NOT added to the peer DB of peer 2
        assert!(PeerDB::get_peer(
            peer_1.network.peerdb.conn(),
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port
        )
        .unwrap()
        .is_none());

        // peer 2 was NOT added to the peer DB of peer 1
        assert!(PeerDB::get_peer(
            peer_2.network.peerdb.conn(),
            neighbor_1.addr.network_id,
            &neighbor_1.addr.addrbytes,
            neighbor_1.addr.port
        )
        .unwrap()
        .is_none());
    })
}

fn stacker_db_id(i: usize) -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::new(
        StandardPrincipalData(0x01, [i as u8; 20]),
        format!("db-{}", i).as_str().into(),
    )
}

fn make_stacker_db_ids(i: usize) -> Vec<QualifiedContractIdentifier> {
    let mut dbs = vec![];
    for j in 0..i {
        dbs.push(stacker_db_id(j));
    }
    dbs
}

fn setup_peer_config(
    i: usize,
    port_base: u16,
    neighbor_count: usize,
    peer_count: usize,
) -> TestPeerConfig {
    let mut conf = TestPeerConfig::from_port(port_base + (2 * i as u16));
    conf.connection_opts.num_neighbors = neighbor_count as u64;
    conf.connection_opts.soft_num_neighbors = neighbor_count as u64;

    conf.connection_opts.num_clients = 256;
    conf.connection_opts.soft_num_clients = 128;

    conf.connection_opts.max_http_clients = 1000;
    conf.connection_opts.max_neighbors_of_neighbor = neighbor_count as u64;

    conf.connection_opts.max_clients_per_host = MAX_NEIGHBORS_DATA_LEN as u64;
    conf.connection_opts.soft_max_clients_per_host = peer_count as u64;

    conf.connection_opts.max_neighbors_per_host = MAX_NEIGHBORS_DATA_LEN as u64;
    conf.connection_opts.soft_max_neighbors_per_host = (neighbor_count / 2) as u64;
    conf.connection_opts.soft_max_neighbors_per_org = (neighbor_count / 2) as u64;

    conf.connection_opts.walk_interval = 0;

    conf.connection_opts.disable_inv_sync = true;
    conf.connection_opts.disable_block_download = true;

    let j = i as u32;
    conf.burnchain.peer_version = PEER_VERSION_TESTNET | (j << 16) | (j << 8) | j; // different non-major versions for each peer

    // even-number peers support stacker DBs.
    // odd-number peers do not
    if i % 2 == 0 {
        conf.services = (ServiceFlags::RELAY as u16)
            | (ServiceFlags::RPC as u16)
            | (ServiceFlags::STACKERDB as u16);
        conf.stacker_dbs = make_stacker_db_ids(i);
    } else {
        conf.services = (ServiceFlags::RELAY as u16) | (ServiceFlags::RPC as u16);
        conf.stacker_dbs = vec![];
    }

    conf
}

#[test]
#[ignore]
fn test_walk_ring_allow_15() {
    with_timeout(600, || {
        // all initial peers are allowed
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 32800, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = -1; // always allowed
            conf.denied = 0;

            conf.connection_opts.timeout = 100000;
            conf.connection_opts.handshake_timeout = 100000;
            conf.connection_opts.disable_natpunch = true; // breaks allow checks

            peer_configs.push(conf);
        }

        test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);
    })
}

#[test]
#[ignore]
fn test_walk_ring_15_plain() {
    with_timeout(600, || {
        // initial peers are neither white- nor denied
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 32900, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;

            peer_configs.push(conf);
        }

        test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);
    })
}

#[test]
#[ignore]
fn test_walk_ring_15_pingback() {
    with_timeout(600, || {
        // initial peers are neither white- nor denied
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 32950, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;
            conf.connection_opts.disable_pingbacks = true;
            conf.connection_opts.disable_inbound_walks = false;

            peer_configs.push(conf);
        }

        test_walk_ring_pingback(&mut peer_configs, NEIGHBOR_COUNT);
    })
}

#[test]
#[ignore]
fn test_walk_ring_15_org_biased() {
    with_timeout(600, || {
        // one outlier peer has a different org than the others.
        use std::env;

        // ::33000 is in AS 1
        env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33000", "1");

        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33000, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;
            if i == 0 {
                conf.asn = 1;
                conf.org = 1;
            } else {
                conf.asn = 0;
                conf.org = 0;
            }

            peer_configs.push(conf);
        }

        // all peers see peer ::33000 as having ASN and Org ID 1
        let peer_0 = peer_configs[0].to_neighbor();

        let peers = test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);

        for i in 1..PEER_COUNT {
            match PeerDB::get_peer(
                peers[i].network.peerdb.conn(),
                peer_0.addr.network_id,
                &peer_0.addr.addrbytes,
                peer_0.addr.port,
            )
            .unwrap()
            {
                Some(p) => {
                    assert_eq!(p.asn, 1);
                    assert_eq!(p.org, 1);
                }
                None => {}
            }
        }

        // no peer pruned peer ::33000
        for i in 1..PEER_COUNT {
            match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                None => {}
                Some(count) => {
                    assert_eq!(*count, 0);
                }
            }
        }
    })
}

fn test_walk_ring_ex(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
    test_pingback: bool,
) -> Vec<TestPeer> {
    // arrange neighbors into a "ring" topology, where
    // neighbor N is connected to neighbor (N-1)%NUM_NEIGHBORS and (N+1)%NUM_NEIGHBORS.
    // If test_pingback is true, then neighbor N is only connected to (N+1)%NUM_NEIGHBORS
    let mut peers = vec![];

    let PEER_COUNT = peer_configs.len();
    let NEIGHBOR_COUNT = neighbor_count;

    for i in 0..PEER_COUNT {
        let n = (i + 1) % PEER_COUNT;
        let neighbor = peer_configs[n].to_neighbor();
        peer_configs[i].add_neighbor(&neighbor);
    }

    if !test_pingback {
        for i in 1..PEER_COUNT + 1 {
            let p = i - 1;
            let neighbor = peer_configs[p].to_neighbor();
            peer_configs[i % PEER_COUNT].add_neighbor(&neighbor);
        }
    }

    for i in 0..PEER_COUNT {
        let p = TestPeer::new(peer_configs[i].clone());
        peers.push(p);
    }

    run_topology_test(&mut peers, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);

    // no nacks or handshake-rejects
    for i in 0..PEER_COUNT {
        for (_, convo) in peers[i].network.peers.iter() {
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::Nack)
                    .unwrap_or(&0)
                    == 0
            );
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::HandshakeReject)
                    .unwrap_or(&0)
                    == 0
            );
        }
    }

    peers
}

fn test_walk_ring(peer_configs: &mut Vec<TestPeerConfig>, neighbor_count: usize) -> Vec<TestPeer> {
    test_walk_ring_ex(peer_configs, neighbor_count, false)
}

fn test_walk_ring_pingback(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
) -> Vec<TestPeer> {
    test_walk_ring_ex(peer_configs, neighbor_count, true)
}

#[test]
#[ignore]
fn test_walk_line_allowed_15() {
    with_timeout(600, || {
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33100, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = -1;
            conf.denied = 0;

            conf.connection_opts.timeout = 100000;
            conf.connection_opts.handshake_timeout = 100000;
            conf.connection_opts.disable_natpunch = true; // breaks allow checks

            peer_configs.push(conf);
        }

        test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
    })
}

#[test]
#[ignore]
fn test_walk_line_15_plain() {
    with_timeout(600, || {
        // initial peers are neither white- nor denied
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33200, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;

            peer_configs.push(conf);
        }

        test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
    })
}

#[test]
#[ignore]
fn test_walk_line_15_org_biased() {
    with_timeout(600, || {
        // one outlier peer has a different org than the others.
        use std::env;

        // ::33300 is in AS 1
        env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33300", "1");

        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3; // make this a little bigger to speed this test up
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33300, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;
            if i == 0 {
                conf.asn = 1;
                conf.org = 1;
            } else {
                conf.asn = 0;
                conf.org = 0;
            }

            peer_configs.push(conf);
        }
        // all peers see peer ::33300 as having ASN and Org ID 1
        let peer_0 = peer_configs[0].to_neighbor();

        let peers = test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, 0);

        for i in 1..PEER_COUNT {
            match PeerDB::get_peer(
                peers[i].network.peerdb.conn(),
                peer_0.addr.network_id,
                &peer_0.addr.addrbytes,
                peer_0.addr.port,
            )
            .unwrap()
            {
                Some(p) => {
                    assert_eq!(p.asn, 1);
                    assert_eq!(p.org, 1);
                }
                None => {}
            }
        }

        // no peer pruned peer ::33300
        for i in 1..PEER_COUNT {
            match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                None => {}
                Some(count) => {
                    assert_eq!(*count, 0);
                }
            }
        }
    })
}

#[test]
#[ignore]
fn test_walk_line_15_pingback() {
    with_timeout(600, || {
        // initial peers are neither white- nor denied
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33350, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;
            conf.connection_opts.disable_pingbacks = false;
            conf.connection_opts.disable_inbound_walks = true;

            peer_configs.push(conf);
        }

        test_walk_line_pingback(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
    })
}

fn test_walk_line(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
    tests: u64,
) -> Vec<TestPeer> {
    test_walk_line_ex(peer_configs, neighbor_count, tests, false)
}

fn test_walk_line_pingback(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
    tests: u64,
) -> Vec<TestPeer> {
    test_walk_line_ex(peer_configs, neighbor_count, tests, true)
}

fn test_walk_line_ex(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
    tests: u64,
    pingback_test: bool,
) -> Vec<TestPeer> {
    // arrange neighbors into a "line" topology.
    // If pingback_test is true, then the topology is unidirectional:
    //
    // 0 ---> 1 ---> 2 ---> ... ---> NEIGHBOR_COUNT
    //
    // If pingback_test is false, then the topology is bidirectional
    //
    // 0 <--> 1 <--> 2 <--> ... <--> NEIGHBOR_COUNT
    //
    // all initial peers are allowed
    let mut peers = vec![];

    let PEER_COUNT = peer_configs.len();
    let NEIGHBOR_COUNT = neighbor_count;
    for i in 0..PEER_COUNT - 1 {
        let n = i + 1;
        let neighbor = peer_configs[n].to_neighbor();
        peer_configs[i].add_neighbor(&neighbor);
    }

    if !pingback_test {
        for i in 1..PEER_COUNT {
            let p = i - 1;
            let neighbor = peer_configs[p].to_neighbor();
            peer_configs[i].add_neighbor(&neighbor);
        }
    }

    for i in 0..PEER_COUNT {
        let p = TestPeer::new(peer_configs[i].clone());
        peers.push(p);
    }

    run_topology_test(&mut peers, NEIGHBOR_COUNT, tests);

    // no nacks or handshake-rejects
    for i in 0..PEER_COUNT {
        for (_, convo) in peers[i].network.peers.iter() {
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::Nack)
                    .unwrap_or(&0)
                    == 0
            );
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::HandshakeReject)
                    .unwrap_or(&0)
                    == 0
            );
        }
    }

    peers
}

#[test]
#[ignore]
fn test_walk_star_allowed_15() {
    with_timeout(600, || {
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33400, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = -1; // always allowed
            conf.denied = 0;

            conf.connection_opts.timeout = 100000;
            conf.connection_opts.handshake_timeout = 100000;
            conf.connection_opts.disable_natpunch = true; // breaks allow checks

            peer_configs.push(conf);
        }

        test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);
    })
}

#[test]
#[ignore]
fn test_walk_star_15_plain() {
    with_timeout(600, || {
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33500, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;

            peer_configs.push(conf);
        }

        test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);
    })
}

#[test]
#[ignore]
fn test_walk_star_15_pingback() {
    with_timeout(600, || {
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33550, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;
            conf.connection_opts.disable_pingbacks = false;
            conf.connection_opts.disable_inbound_walks = true;
            conf.connection_opts.soft_max_neighbors_per_org = PEER_COUNT as u64;

            peer_configs.push(conf);
        }

        test_walk_star_pingback(&mut peer_configs, NEIGHBOR_COUNT);
    })
}

#[test]
#[ignore]
fn test_walk_star_15_org_biased() {
    with_timeout(600, || {
        // one outlier peer has a different org than the others.
        use std::env;

        // ::33600 is in AS 1
        env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33600", "1");

        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 3;
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33600, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;
            if i == 0 {
                conf.asn = 1;
                conf.org = 1;
            } else {
                conf.asn = 0;
                conf.org = 0;
            }

            peer_configs.push(conf);
        }
        // all peers see peer ::33600 as having ASN and Org ID 1
        let peer_0 = peer_configs[0].to_neighbor();

        let peers = test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);

        for i in 1..PEER_COUNT {
            match PeerDB::get_peer(
                peers[i].network.peerdb.conn(),
                peer_0.addr.network_id,
                &peer_0.addr.addrbytes,
                peer_0.addr.port,
            )
            .unwrap()
            {
                Some(p) => {
                    assert_eq!(p.asn, 1);
                    assert_eq!(p.org, 1);
                }
                None => {}
            }
        }

        // no peer pruned peer ::33600
        for i in 1..PEER_COUNT {
            match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                None => {}
                Some(count) => {
                    assert_eq!(*count, 0);
                }
            }
        }
    })
}

fn test_walk_star(peer_configs: &mut Vec<TestPeerConfig>, neighbor_count: usize) -> Vec<TestPeer> {
    test_walk_star_ex(peer_configs, neighbor_count, false)
}

fn test_walk_star_pingback(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
) -> Vec<TestPeer> {
    test_walk_star_ex(peer_configs, neighbor_count, true)
}

fn test_walk_star_ex(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
    pingback_test: bool,
) -> Vec<TestPeer> {
    // arrange neighbors into a "star" topology.
    // If pingback_test is true, then initial connections are unidirectional -- each neighbor (except
    // for 0) only knows about 0.  Neighbor 0 knows about no one.
    // If pingback_test is false, then initial connections are bidirectional.

    let mut peers = vec![];
    let PEER_COUNT = peer_configs.len();
    let NEIGHBOR_COUNT = neighbor_count;

    for i in 1..PEER_COUNT {
        let neighbor = peer_configs[i].to_neighbor();
        let hub = peer_configs[0].to_neighbor();
        if !pingback_test {
            peer_configs[0].add_neighbor(&neighbor);
        }

        peer_configs[i].add_neighbor(&hub);
    }

    for i in 0..PEER_COUNT {
        let p = TestPeer::new(peer_configs[i].clone());
        peers.push(p);
    }

    run_topology_test(&mut peers, NEIGHBOR_COUNT, 0);

    // no nacks or handshake-rejects
    for i in 0..PEER_COUNT {
        for (_, convo) in peers[i].network.peers.iter() {
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::Nack)
                    .unwrap_or(&0)
                    == 0
            );
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::HandshakeReject)
                    .unwrap_or(&0)
                    == 0
            );
        }
    }

    peers
}

fn test_walk_inbound_line(
    peer_configs: &mut Vec<TestPeerConfig>,
    neighbor_count: usize,
) -> Vec<TestPeer> {
    // arrange neighbors into a two-tiered "line" topology, where even-numbered neighbors are
    // "NAT'ed" but connected to both the predecessor and successor odd neighbors.  Odd
    // numbered neighbors are not connected to anyone.  The first and last even-numbered
    // neighbor is only connected to its successor and predecessor, respectively.
    //
    //    1     3     5
    //   ^ ^   ^ ^   ^ ^
    //  /   \ /   \ /   \   ... etc ...
    // 0     2     4     6
    //
    // The goal of this test is that odd-numbered neighbors all learn about each other

    let mut peers = vec![];
    let PEER_COUNT = peer_configs.len();
    let NEIGHBOR_COUNT = neighbor_count;

    for i in 0..PEER_COUNT {
        if i % 2 == 0 {
            if i > 0 {
                let predecessor = peer_configs[i - 1].to_neighbor();
                peer_configs[i].add_neighbor(&predecessor);
            }
            if i + 1 < PEER_COUNT {
                let successor = peer_configs[i + 1].to_neighbor();
                peer_configs[i].add_neighbor(&successor);
            }
        }
    }

    for i in 0..PEER_COUNT {
        let p = TestPeer::new(peer_configs[i].clone());
        peers.push(p);
    }

    run_topology_test_ex(
        &mut peers,
        NEIGHBOR_COUNT,
        0,
        |peers: &Vec<TestPeer>| {
            let mut done = true;
            for i in 0..PEER_COUNT {
                // only check "public" peers
                if i % 2 != 0 {
                    let all_neighbors =
                        PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
                    if (all_neighbors.len() as u64) < ((PEER_COUNT / 2 - 1) as u64) {
                        let nk = peers[i].config.to_neighbor().addr;
                        test_debug!(
                            "waiting for public peer {:?} to fill up its frontier: {}",
                            &nk,
                            all_neighbors.len()
                        );
                        done = false;
                    }
                }
            }
            done
        },
        true,
    );

    // no nacks or handshake-rejects
    for i in 0..PEER_COUNT {
        for (_, convo) in peers[i].network.peers.iter() {
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::Nack)
                    .unwrap_or(&0)
                    == 0
            );
            assert!(
                *convo
                    .stats
                    .msg_rx_counts
                    .get(&StacksMessageID::HandshakeReject)
                    .unwrap_or(&0)
                    == 0
            );
        }
    }

    peers
}

#[test]
#[ignore]
fn test_walk_inbound_line_15() {
    with_timeout(600, || {
        let mut peer_configs = vec![];
        let PEER_COUNT: usize = 15;
        let NEIGHBOR_COUNT: usize = 15; // make this test go faster

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33250, NEIGHBOR_COUNT, PEER_COUNT);

            conf.allowed = 0;
            conf.denied = 0;
            conf.connection_opts.disable_pingbacks = true;
            conf.connection_opts.disable_inbound_walks = false;
            conf.connection_opts.walk_inbound_ratio = 2;
            // basically, don't timeout (so public nodes can ask non-public inbound nodes about
            // neighbors indefinitely)
            conf.connection_opts.connect_timeout = 60000;
            conf.connection_opts.timeout = 60000;
            conf.connection_opts.handshake_timeout = 60000;
            conf.connection_opts.soft_max_neighbors_per_org = (NEIGHBOR_COUNT + 1) as u64;
            conf.connection_opts.soft_max_neighbors_per_host = (NEIGHBOR_COUNT + 1) as u64;

            peer_configs.push(conf);
        }

        test_walk_inbound_line(&mut peer_configs, NEIGHBOR_COUNT);
    })
}

fn dump_peers(peers: &Vec<TestPeer>) -> () {
    test_debug!("\n=== PEER DUMP ===");
    for i in 0..peers.len() {
        let mut neighbor_index = vec![];
        let mut outbound_neighbor_index = vec![];
        for j in 0..peers.len() {
            let stats_opt = peers[i]
                .network
                .get_neighbor_stats(&peers[j].to_neighbor().addr);
            match stats_opt {
                Some(stats) => {
                    neighbor_index.push(j);
                    if stats.outbound {
                        outbound_neighbor_index.push(j);
                    }
                }
                None => {}
            }
        }

        let all_neighbors = PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
        let num_allowed = all_neighbors.iter().fold(0, |mut sum, ref n2| {
            sum += if n2.allowed < 0 { 1 } else { 0 };
            sum
        });
        test_debug!("Neighbor {} (all={}, outbound={}) (total neighbors = {}, total allowed = {}): outbound={:?} all={:?}", i, neighbor_index.len(), outbound_neighbor_index.len(), all_neighbors.len(), num_allowed, &outbound_neighbor_index, &neighbor_index);
    }
    test_debug!("\n");
}

fn dump_peer_histograms(peers: &Vec<TestPeer>) -> () {
    let mut outbound_hist: HashMap<usize, usize> = HashMap::new();
    let mut inbound_hist: HashMap<usize, usize> = HashMap::new();
    let mut all_hist: HashMap<usize, usize> = HashMap::new();
    for i in 0..peers.len() {
        let mut neighbor_index = vec![];
        let mut inbound_neighbor_index = vec![];
        let mut outbound_neighbor_index = vec![];
        for j in 0..peers.len() {
            let stats_opt = peers[i]
                .network
                .get_neighbor_stats(&peers[j].to_neighbor().addr);
            match stats_opt {
                Some(stats) => {
                    neighbor_index.push(j);
                    if stats.outbound {
                        outbound_neighbor_index.push(j);
                    } else {
                        inbound_neighbor_index.push(j);
                    }
                }
                None => {}
            }
        }
        for inbound in inbound_neighbor_index.iter() {
            if inbound_hist.contains_key(inbound) {
                let c = inbound_hist.get(inbound).unwrap().to_owned();
                inbound_hist.insert(*inbound, c + 1);
            } else {
                inbound_hist.insert(*inbound, 1);
            }
        }
        for outbound in outbound_neighbor_index.iter() {
            if outbound_hist.contains_key(outbound) {
                let c = outbound_hist.get(outbound).unwrap().to_owned();
                outbound_hist.insert(*outbound, c + 1);
            } else {
                outbound_hist.insert(*outbound, 1);
            }
        }
        for n in neighbor_index.iter() {
            if all_hist.contains_key(n) {
                let c = all_hist.get(n).unwrap().to_owned();
                all_hist.insert(*n, c + 1);
            } else {
                all_hist.insert(*n, 1);
            }
        }
    }

    test_debug!("=== PEER HISTOGRAM ===");
    for i in 0..peers.len() {
        test_debug!(
            "Neighbor {}: #in={} #out={} #all={}",
            i,
            inbound_hist.get(&i).unwrap_or(&0),
            outbound_hist.get(&i).unwrap_or(&0),
            all_hist.get(&i).unwrap_or(&0)
        );
    }
    test_debug!("\n");
}

fn run_topology_test(peers: &mut Vec<TestPeer>, neighbor_count: usize, test_bits: u64) -> () {
    run_topology_test_ex(peers, neighbor_count, test_bits, |_| false, false)
}

fn run_topology_test_ex<F>(
    peers: &mut Vec<TestPeer>,
    neighbor_count: usize,
    test_bits: u64,
    mut finished_check: F,
    use_finished_check: bool,
) -> ()
where
    F: FnMut(&Vec<TestPeer>) -> bool,
{
    let PEER_COUNT = peers.len();

    let mut initial_allowed: HashMap<NeighborKey, Vec<NeighborKey>> = HashMap::new();
    let mut initial_denied: HashMap<NeighborKey, Vec<NeighborKey>> = HashMap::new();

    for i in 0..PEER_COUNT {
        // turn off components we don't need
        peers[i].config.connection_opts.disable_inv_sync = true;
        peers[i].config.connection_opts.disable_block_download = true;
        let nk = peers[i].config.to_neighbor().addr.clone();
        for j in 0..peers[i].config.initial_neighbors.len() {
            let initial = &peers[i].config.initial_neighbors[j];
            if initial.allowed < 0 {
                if !initial_allowed.contains_key(&nk) {
                    initial_allowed.insert(nk.clone(), vec![]);
                }
                initial_allowed
                    .get_mut(&nk)
                    .unwrap()
                    .push(initial.addr.clone());
            }
            if initial.denied < 0 {
                if !initial_denied.contains_key(&nk) {
                    initial_denied.insert(nk.clone(), vec![]);
                }
                initial_denied
                    .get_mut(&nk)
                    .unwrap()
                    .push(initial.addr.clone());
            }
        }
    }

    for i in 0..PEER_COUNT {
        peers[i].connect_initial().unwrap();
    }

    // go until each neighbor knows about each other neighbor
    let mut finished = false;
    let mut count = 0;
    while !finished {
        finished = true;
        let mut peer_counts = 0;
        let mut random_order = vec![0usize; PEER_COUNT];
        for i in 0..PEER_COUNT {
            random_order[i] = i;
        }
        let mut rng = thread_rng();
        random_order.shuffle(&mut rng);

        debug!("Random order = {:?}", &random_order);
        for i in random_order.into_iter() {
            let _ = peers[i].step_with_ibd(false);
            let nk = peers[i].config.to_neighbor().addr;
            debug!("Step peer {:?}", &nk);

            // allowed peers are still connected
            match initial_allowed.get(&nk) {
                Some(ref peer_list) => {
                    for pnk in peer_list.iter() {
                        if !peers[i].network.events.contains_key(&pnk.clone()) {
                            error!(
                                "{:?}: Perma-allowed peer {:?} not connected anymore",
                                &nk, &pnk
                            );
                            assert!(false);
                        }
                    }
                }
                None => {}
            };

            // denied peers are never connected
            match initial_denied.get(&nk) {
                Some(ref peer_list) => {
                    for pnk in peer_list.iter() {
                        if peers[i].network.events.contains_key(&pnk.clone()) {
                            error!("{:?}: Perma-denied peer {:?} connected", &nk, &pnk);
                            assert!(false);
                        }
                    }
                }
                None => {}
            };

            // all ports are unique in the p2p socket table
            let mut ports: HashSet<u16> = HashSet::new();
            for k in peers[i].network.events.keys() {
                if ports.contains(&k.port) {
                    error!("duplicate port {} from {:?}", k.port, k);
                    assert!(false);
                }
                ports.insert(k.port);
            }

            // done?
            let now_finished = if use_finished_check {
                finished_check(&peers)
            } else {
                let mut done = true;
                let all_neighbors = PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
                peer_counts += all_neighbors.len();
                test_debug!("Peer {} ({}) has {} neighbors", i, &nk, all_neighbors.len());

                if (all_neighbors.len() as u64) < ((PEER_COUNT - 1) as u64) {
                    test_debug!(
                        "waiting for {:?} to fill up its frontier: {} < {}",
                        &nk,
                        all_neighbors.len(),
                        PEER_COUNT - 1
                    );
                    done = false;
                } else {
                    test_debug!(
                        "not waiting for {:?} to fill up its frontier: {} >= {}",
                        &nk,
                        all_neighbors.len(),
                        PEER_COUNT - 1
                    );
                }
                done
            };

            finished = finished && now_finished;
        }

        count += 1;

        test_debug!(
            "Network convergence rate: {}%",
            (100.0 * (peer_counts as f64)) / ((PEER_COUNT * PEER_COUNT) as f64),
        );

        if finished {
            break;
        }

        test_debug!("Finished walking the network {} times", count);
        dump_peers(&peers);
        dump_peer_histograms(&peers);
    }

    test_debug!("Converged after {} calls to network.run()", count);
    dump_peers(&peers);
    dump_peer_histograms(&peers);

    // each peer learns each other peer's stacker DBs
    for (i, peer) in peers.iter().enumerate() {
        if i % 2 != 0 {
            continue;
        }
        let mut expected_dbs = PeerDB::get_local_peer(peer.network.peerdb.conn())
            .unwrap()
            .stacker_dbs;
        expected_dbs.sort();
        for (j, other_peer) in peers.iter().enumerate() {
            if i == j {
                continue;
            }

            let all_neighbors = PeerDB::get_all_peers(other_peer.network.peerdb.conn()).unwrap();

            if (all_neighbors.len() as u64) < ((PEER_COUNT - 1) as u64) {
                // this is a simulated-NAT'ed node -- it won't learn about other NAT'ed nodes'
                // DBs
                continue;
            }

            // what does the other peer see as this peer's stacker DBs?
            let mut other_peer_dbs = other_peer
                .network
                .peerdb
                .get_peer_stacker_dbs(&peer.config.to_neighbor())
                .unwrap();
            other_peer_dbs.sort();

            if j % 2 == 0 {
                test_debug!(
                    "Compare stacker DBs of {} vs {}",
                    &peer.config.to_neighbor(),
                    &other_peer.config.to_neighbor()
                );
                assert_eq!(expected_dbs, other_peer_dbs);
            } else {
                // this peer doesn't support Stacker DBs
                assert_eq!(other_peer_dbs, vec![]);
            }
        }
    }
}
