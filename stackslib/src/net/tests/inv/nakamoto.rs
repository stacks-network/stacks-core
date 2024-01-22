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

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::thread::JoinHandle;

use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::types::StacksEpoch;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::nakamoto::coordinator::tests::{
    simple_nakamoto_coordinator_10_extended_tenures_10_sortitions,
    simple_nakamoto_coordinator_10_tenures_10_sortitions,
    simple_nakamoto_coordinator_2_tenures_3_sortitions,
};
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::core::StacksEpochExtension;
use crate::net::inv::nakamoto::InvGenerator;
use crate::net::test::TestPeer;
use crate::net::{
    Error as NetError, GetNakamotoInvData, HandshakeData, NakamotoInvData, StacksMessage,
    StacksMessageType,
};
use crate::util_lib::db::Error as DBError;

/// Handshake with and get the reward cycle inventories for a range of reward cycles
fn peer_get_nakamoto_invs(
    mut peer: TestPeer<'static>,
    reward_cycles: &[u64],
) -> (TestPeer<'static>, Vec<StacksMessageType>) {
    let privk = StacksPrivateKey::new();
    let mut convo = peer.make_client_convo();
    let client_peer = peer.make_client_local_peer(privk.clone());
    let peer_addr = peer.p2p_socketaddr();
    let chain_view = peer.network.get_chain_view().clone();

    let mut get_nakamoto_invs = vec![];
    for reward_cycle in reward_cycles {
        let consensus_hash = {
            let sortdb = peer.sortdb();
            let reward_cycle_start_height = sortdb
                .pox_constants
                .reward_cycle_to_block_height(sortdb.first_block_height, *reward_cycle);
            let ih = sortdb.index_handle_at_tip();
            let Some(rc_start_sn) = ih
                .get_block_snapshot_by_height(reward_cycle_start_height)
                .unwrap()
            else {
                continue;
            };
            rc_start_sn.consensus_hash
        };

        let get_nakamoto_inv =
            StacksMessageType::GetNakamotoInv(GetNakamotoInvData { consensus_hash });
        let signed_get_nakamoto_inv = convo
            .sign_message(&chain_view, &privk, get_nakamoto_inv)
            .unwrap();
        get_nakamoto_invs.push(signed_get_nakamoto_inv);
    }

    let (shutdown_send, shutdown_recv) = sync_channel(1);
    let join_handle = thread::spawn(move || {
        loop {
            peer.step_with_ibd(false).unwrap();
            if let Ok(..) = shutdown_recv.try_recv() {
                break;
            }
        }
        peer
    });

    let mut tcp_socket = TcpStream::connect(peer_addr).unwrap();

    // first, handshake
    let handshake_data = StacksMessageType::Handshake(HandshakeData::from_local_peer(&client_peer));
    let signed_handshake_data = convo
        .sign_message(&chain_view, &privk, handshake_data)
        .unwrap();
    signed_handshake_data
        .consensus_serialize(&mut tcp_socket)
        .unwrap();

    // read back handshake-accept
    let msg: StacksMessage = read_next(&mut tcp_socket).unwrap();
    match msg.payload {
        StacksMessageType::HandshakeAccept(..)
        | StacksMessageType::StackerDBHandshakeAccept(..) => {}
        x => {
            error!("Peer returned {:?}", &x);
            panic!();
        }
    }

    let mut replies = vec![];
    for get_nakamoto_inv in get_nakamoto_invs {
        // send getnakamotoinv
        get_nakamoto_inv
            .consensus_serialize(&mut tcp_socket)
            .unwrap();

        loop {
            // read back the message
            let msg: StacksMessage = read_next(&mut tcp_socket).unwrap();
            let is_inv_reply = if let StacksMessageType::NakamotoInv(..) = &msg.payload {
                true
            } else {
                false
            };
            if is_inv_reply {
                replies.push(msg.payload);
                break;
            } else {
                debug!("Got spurious meessage {:?}", &msg);
            }
        }
    }

    shutdown_send.send(true).unwrap();
    let peer = join_handle.join().unwrap();

    (peer, replies)
}

#[test]
fn test_nakamoto_inv_10_tenures_10_sortitions() {
    let peer = simple_nakamoto_coordinator_10_tenures_10_sortitions();

    // sanity check -- nakamoto begins at height 37
    assert_eq!(
        peer.config.epochs,
        Some(StacksEpoch::unit_test_3_0_only(37))
    );

    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(reward_cycle_invs.len(), 10);

    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();

    let mut inv_generator = InvGenerator::new();

    // processed 10 tenures
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 46);

    // check the reward cycles
    for (rc, inv) in reward_cycle_invs.into_iter().enumerate() {
        let bitvec = inv_generator
            .make_tenure_bitvector(&tip, sort_db, chainstate, rc as u64)
            .unwrap();
        debug!(
            "At reward cycle {}: {:?}, mesasge = {:?}",
            rc, &bitvec, &inv
        );

        if rc <= 6 {
            // prior to start of nakamoto
            assert_eq!(bitvec, vec![false, false, false, false, false]);
        } else if rc == 7 {
            // first Nakamoto tenure starts at block 37
            assert_eq!(bitvec, vec![false, false, true, true, true]);
        } else if rc == 8 {
            // full reward cycle of nakamoto
            assert_eq!(bitvec, vec![true, true, true, true, true]);
        } else if rc == 9 {
            // we stopped at height 46
            assert_eq!(bitvec, vec![true, true]);
        } else if rc >= 10 {
            // haven't processed this high yet
            assert_eq!(bitvec.len(), 0);
        }

        let StacksMessageType::NakamotoInv(inv) = inv else {
            panic!("Did not receive an inv for reward cycle {}", rc);
        };
        assert_eq!(NakamotoInvData::bools_to_bitvec(&bitvec), inv.tenures);
        assert_eq!(bitvec.len() as u16, inv.bitlen);
    }
}

#[test]
fn test_nakamoto_inv_2_tenures_3_sortitions() {
    let peer = simple_nakamoto_coordinator_2_tenures_3_sortitions();

    // sanity check -- nakamoto begins at height 37
    assert_eq!(
        peer.config.epochs,
        Some(StacksEpoch::unit_test_3_0_only(37))
    );

    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(reward_cycle_invs.len(), 8);

    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();

    let mut inv_generator = InvGenerator::new();

    // processed 3 sortitions
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 39);

    for (rc, inv) in reward_cycle_invs.into_iter().enumerate() {
        let bitvec = inv_generator
            .make_tenure_bitvector(&tip, sort_db, chainstate, rc as u64)
            .unwrap();
        debug!(
            "At reward cycle {}: {:?}, mesasge = {:?}",
            rc, &bitvec, &inv
        );

        if rc <= 6 {
            // prior to start of nakamoto
            assert_eq!(bitvec, vec![false, false, false, false, false]);
        } else if rc == 7 {
            // nakamoto starts at height 37, but we skipeed the sortition at 38
            assert_eq!(bitvec, vec![false, false, true, false, true]);
        } else {
            assert_eq!(bitvec.len(), 0);
        }
        let StacksMessageType::NakamotoInv(inv) = inv else {
            panic!("Did not receive an inv for reward cycle {}", rc);
        };
        assert_eq!(NakamotoInvData::bools_to_bitvec(&bitvec), inv.tenures);
        assert_eq!(bitvec.len() as u16, inv.bitlen);
    }
}

#[test]
fn test_nakamoto_inv_10_extended_tenures_10_sortitions() {
    let peer = simple_nakamoto_coordinator_10_extended_tenures_10_sortitions();

    // sanity check -- nakamoto begins at height 37
    assert_eq!(
        peer.config.epochs,
        Some(StacksEpoch::unit_test_3_0_only(37))
    );

    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(reward_cycle_invs.len(), 10);

    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();

    let mut inv_generator = InvGenerator::new();

    // processed 10 tenures
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 46);

    for (rc, inv) in reward_cycle_invs.into_iter().enumerate() {
        let bitvec = inv_generator
            .make_tenure_bitvector(&tip, sort_db, chainstate, rc as u64)
            .unwrap();
        debug!("At reward cycle {}: {:?}", rc, &bitvec);

        if rc <= 6 {
            // prior to start of nakamoto
            assert_eq!(bitvec, vec![false, false, false, false, false]);
        } else if rc == 7 {
            // first Nakamoto tenure starts at block 37
            assert_eq!(bitvec, vec![false, false, true, true, true]);
        } else if rc == 8 {
            // full reward cycle of nakamoto
            assert_eq!(bitvec, vec![true, true, true, true, true]);
        } else if rc == 9 {
            // we stopped at height 46
            assert_eq!(bitvec, vec![true, true]);
        } else if rc >= 10 {
            // haven't processed this high yet
            assert_eq!(bitvec.len(), 0);
        }
        let StacksMessageType::NakamotoInv(inv) = inv else {
            panic!("Did not receive an inv for reward cycle {}", rc);
        };
        assert_eq!(NakamotoInvData::bools_to_bitvec(&bitvec), inv.tenures);
        assert_eq!(bitvec.len() as u16, inv.bitlen);
    }
}
