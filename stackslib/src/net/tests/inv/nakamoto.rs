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

use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::types::net::PeerAddress;
use stacks_common::types::StacksEpoch;
use stacks_common::util::hash::Hash160;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::nakamoto::coordinator::tests::{
    simple_nakamoto_coordinator_10_extended_tenures_10_sortitions,
    simple_nakamoto_coordinator_10_tenures_10_sortitions,
    simple_nakamoto_coordinator_2_tenures_3_sortitions,
};
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TokenTransferMemo, TransactionAnchorMode,
    TransactionAuth, TransactionPayload, TransactionVersion,
};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::core::StacksEpochExtension;
use crate::net::inv::nakamoto::{InvGenerator, NakamotoInvStateMachine, NakamotoTenureInv};
use crate::net::neighbors::comms::NeighborComms;
use crate::net::test::{TestEventObserver, TestPeer};
use crate::net::tests::{NakamotoBootPlan, NakamotoBootStep, NakamotoBootTenure};
use crate::net::{
    Error as NetError, GetNakamotoInvData, HandshakeData, NakamotoInvData, NeighborAddress,
    PeerNetworkComms, StacksMessage, StacksMessageType,
};
use crate::stacks_common::types::Address;
use crate::util_lib::db::Error as DBError;

/// Handshake with and get the reward cycle inventories for a range of reward cycles
pub fn peer_get_nakamoto_invs<'a>(
    mut peer: TestPeer<'a>,
    reward_cycles: &[u64],
) -> (TestPeer<'a>, Vec<StacksMessageType>) {
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
        let mut tcp_socket = TcpStream::connect(peer_addr).unwrap();

        // first, handshake
        let handshake_data =
            StacksMessageType::Handshake(HandshakeData::from_local_peer(&client_peer));
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
        replies
    });

    loop {
        peer.step_with_ibd(false).unwrap();
        if let Ok(..) = shutdown_recv.try_recv() {
            break;
        }
    }

    let replies = join_handle.join().unwrap();

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
        assert_eq!(
            NakamotoInvData::try_from(&bitvec).unwrap().tenures,
            inv.tenures
        );
        assert_eq!(bitvec.len() as u16, inv.tenures.len());
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
        assert_eq!(
            NakamotoInvData::try_from(&bitvec).unwrap().tenures,
            inv.tenures
        );
        assert_eq!(bitvec.len() as u16, inv.tenures.len());
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
        assert_eq!(
            NakamotoInvData::try_from(&bitvec).unwrap().tenures,
            inv.tenures
        );
        assert_eq!(bitvec.len() as u16, inv.tenures.len());
    }
}

/// NOTE: The second return value does _not_ need `<'a>`, since `observer` is never installed into
/// the peers here.  However, it appears unavoidable to the borrow-checker.
pub fn make_nakamoto_peers_from_invs<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    rc_len: u32,
    prepare_len: u32,
    bitvecs: Vec<Vec<bool>>,
    num_peers: usize,
) -> (TestPeer<'a>, Vec<TestPeer<'a>>) {
    for bitvec in bitvecs.iter() {
        assert_eq!(bitvec.len() as u32, rc_len);
    }

    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let mut sender_nonce = 0;

    let mut next_stx_transfer = || {
        let mut stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&private_key).unwrap(),
            TransactionPayload::TokenTransfer(
                recipient_addr.clone().to_account_principal(),
                1,
                TokenTransferMemo([0x00; 34]),
            ),
        );
        stx_transfer.chain_id = 0x80000000;
        stx_transfer.anchor_mode = TransactionAnchorMode::OnChainOnly;
        stx_transfer.set_tx_fee(1);
        stx_transfer.auth.set_origin_nonce(sender_nonce);
        sender_nonce += 1;

        let mut tx_signer = StacksTransactionSigner::new(&stx_transfer);
        tx_signer.sign_origin(&private_key).unwrap();
        let stx_transfer_signed = tx_signer.get_tx().unwrap();

        stx_transfer_signed
    };

    let mut boot_tenures = vec![];
    for bitvec in bitvecs.iter() {
        for has_tenure in bitvec {
            if *has_tenure {
                boot_tenures.push(NakamotoBootTenure::Sortition(vec![
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                ]));
            } else {
                boot_tenures.push(NakamotoBootTenure::NoSortition(vec![
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                ]));
            }
        }
    }

    let plan = NakamotoBootPlan::new(test_name)
        .with_private_key(private_key)
        .with_pox_constants(rc_len, prepare_len)
        .with_initial_balances(vec![(addr.into(), 1_000_000)])
        .with_extra_peers(num_peers);

    let (peer, other_peers) = plan.boot_into_nakamoto_peers(boot_tenures, Some(observer));
    (peer, other_peers)
}

pub fn make_nakamoto_peer_from_invs<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    rc_len: u32,
    prepare_len: u32,
    bitvecs: Vec<Vec<bool>>,
) -> TestPeer<'a> {
    make_nakamoto_peers_from_invs(test_name, observer, rc_len, prepare_len, bitvecs, 0).0
}

fn check_inv_messages(
    bitvecs: Vec<Vec<bool>>,
    rc_len: u32,
    nakamoto_start_burn_height: u64,
    messages: Vec<StacksMessageType>,
) {
    for (msg_idx, msg) in messages.into_iter().enumerate() {
        let StacksMessageType::NakamotoInv(inv) = msg else {
            panic!("Did not receive an inv for reward cycle {}", msg_idx);
        };
        for bit in 0..(inv.tenures.len() as usize) {
            let burn_block_height = (msg_idx as u64) * u64::from(rc_len) + (bit as u64);
            let msg_bit = inv.tenures.get(bit as u16).unwrap_or(false);
            if burn_block_height < nakamoto_start_burn_height {
                // inv doesn't cover epoch 2
                assert!(
                    !msg_bit,
                    "Bit {} in message {} is set but is before nakamoto-start height {} ({})",
                    bit, msg_idx, nakamoto_start_burn_height, burn_block_height
                );
                continue;
            }

            let inv_offset: u64 = burn_block_height - nakamoto_start_burn_height;
            let bitvec_idx = (inv_offset / u64::from(rc_len)) as usize;
            let expected_bit = if bitvec_idx >= bitvecs.len() {
                false
            } else {
                bitvecs[bitvec_idx][(inv_offset % u64::from(rc_len)) as usize]
            };
            assert_eq!(msg_bit, expected_bit, "Bit {} in message {} is {}, but expected {}. burn_block_height = {}, inv_offset = {}, bitvec_idx = {}, nakamoto_start_burn_height = {}",
                       bit, msg_idx, msg_bit, expected_bit, burn_block_height, inv_offset, bitvec_idx, nakamoto_start_burn_height);
        }
    }
}

fn check_inv_state(
    bitvecs: Vec<Vec<bool>>,
    rc_len: u32,
    nakamoto_start_burn_height: u64,
    inv_state: &NakamotoTenureInv,
) {
    for (i, (tenure_rc, tenure_inv)) in inv_state.tenures_inv.iter().enumerate() {
        for bit in 0..(rc_len as usize) {
            let msg_bit = if bit / 8 >= tenure_inv.len().into() {
                // only allowed at the end
                debug!(
                    "bit = {}, tenure_rc = {}, tenure_inv = {:?}",
                    bit, tenure_rc, &tenure_inv
                );
                assert_eq!(i, inv_state.tenures_inv.len() - 1);
                false
            } else {
                tenure_inv.get(bit.try_into().unwrap()).unwrap_or(false)
            };

            let burn_block_height = (*tenure_rc as u64) * u64::from(rc_len) + (bit as u64);
            if burn_block_height < nakamoto_start_burn_height {
                // inv doesn't cover epoch 2
                assert!(
                    !msg_bit,
                    "Bit {} in tenure {} is set but is before nakamoto-start height {} ({})",
                    bit, tenure_rc, nakamoto_start_burn_height, burn_block_height
                );
                continue;
            }

            let inv_offset: u64 = burn_block_height - nakamoto_start_burn_height;
            let bitvec_idx = (inv_offset / u64::from(rc_len)) as usize;
            let expected_bit = if bitvec_idx >= bitvecs.len() {
                false
            } else {
                bitvecs[bitvec_idx][(inv_offset % u64::from(rc_len)) as usize]
            };
            assert_eq!(msg_bit, expected_bit, "Bit {} in tenure {} is {}, but expected {}. burn_block_height = {}, inv_offset = {}, bitvec_idx = {}, nakamoto_start_burn_height = {}",
                       bit, tenure_rc, msg_bit, expected_bit, burn_block_height, inv_offset, bitvec_idx, nakamoto_start_burn_height);
        }
    }
}

#[test]
fn test_nakamoto_invs_full() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 10);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_invs_alternating() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![
            true, false, true, false, true, false, true, true, true, true,
        ],
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        vec![
            true, false, true, false, true, false, true, true, true, true,
        ],
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        vec![
            true, false, true, false, true, false, true, true, true, true,
        ],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 10);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_invs_sparse() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        vec![
            false, true, false, false, false, false, false, true, true, true,
        ],
        vec![
            false, false, true, false, false, false, false, true, true, true,
        ],
        vec![
            false, false, false, true, false, false, false, true, true, true,
        ],
        vec![
            false, false, false, false, true, false, false, true, true, true,
        ],
        vec![
            false, false, false, false, false, true, false, true, true, true,
        ],
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 12);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_invs_different_anchor_blocks() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![true, true, true, true, true, true, false, true, true, true],
        vec![true, true, true, true, true, false, false, true, true, true],
        vec![
            true, true, true, true, false, false, false, true, true, true,
        ],
        vec![
            true, true, true, false, false, false, false, true, true, true,
        ],
        vec![
            true, true, false, false, false, false, false, true, true, true,
        ],
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        vec![
            false, false, false, false, false, false, false, true, true, true,
        ],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 12);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_tenure_inv() {
    let na = NeighborAddress {
        addrbytes: PeerAddress([
            0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]),
        port: 65535,
        public_key_hash: Hash160([0x11; 20]),
    };
    let mut nakamoto_inv = NakamotoTenureInv::new(100, 100, 0, na);
    assert!(!nakamoto_inv.has_ith_tenure(0));
    assert!(!nakamoto_inv.has_ith_tenure(99));
    assert!(!nakamoto_inv.has_ith_tenure(100));
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 0);

    let full_tenure = NakamotoInvData::try_from(&[true; 100]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 1);
    assert!(learned);

    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.tenures, 1);
    assert!(!learned);

    debug!("nakamoto_inv = {:?}", &nakamoto_inv);
    for i in 0..200 {
        assert!(!nakamoto_inv.has_ith_tenure(i));
    }
    for i in 200..300 {
        assert!(nakamoto_inv.has_ith_tenure(i));
    }
    assert!(!nakamoto_inv.has_ith_tenure(199));
    assert!(nakamoto_inv.has_ith_tenure(200));
    assert!(!nakamoto_inv.has_ith_tenure(300));
    assert!(!nakamoto_inv.has_ith_tenure(301));
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 1);

    let mut partial_tenure_bools = vec![];
    for i in 0..100 {
        partial_tenure_bools.push(i % 2 == 0);
    }

    // has_ith_tenure() works (non-triial case)
    let partial_tenure = NakamotoInvData::try_from(&partial_tenure_bools).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(partial_tenure.clone().tenures, 2);
    assert!(learned);

    for i in 300..400 {
        assert_eq!(nakamoto_inv.has_ith_tenure(i), i % 2 == 0);
    }
    assert!(!nakamoto_inv.has_ith_tenure(199));
    assert!(nakamoto_inv.has_ith_tenure(299));
    assert!(nakamoto_inv.has_ith_tenure(300));
    assert!(nakamoto_inv.has_ith_tenure(398));
    assert!(!nakamoto_inv.has_ith_tenure(399));
    assert!(!nakamoto_inv.has_ith_tenure(400));
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 2);

    // supports sparse updates
    let full_tenure = NakamotoInvData::try_from(&[true; 100]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.tenures, 4);
    assert!(learned);

    for i in 400..500 {
        assert!(!nakamoto_inv.has_ith_tenure(i));
    }
    for i in 500..600 {
        assert!(nakamoto_inv.has_ith_tenure(i));
    }
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 4);

    // can overwrite tenures
    let full_tenure = NakamotoInvData::try_from(&[true; 100]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 2);
    assert!(learned);
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 4);

    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 2);
    assert!(!learned);
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 4);

    for i in 300..400 {
        assert!(nakamoto_inv.has_ith_tenure(i));
    }

    // partial data
    let partial_tenure = NakamotoInvData::try_from(&[true; 50]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 5);
    assert!(learned);
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 5);

    // state machine advances when we say so
    assert_eq!(nakamoto_inv.reward_cycle(), 0);
    assert!(nakamoto_inv.is_online());
    nakamoto_inv.set_online(false);
    assert!(!nakamoto_inv.is_online());

    nakamoto_inv.next_reward_cycle();
    assert_eq!(nakamoto_inv.reward_cycle(), 1);

    nakamoto_inv.try_reset_comms(0, 0, 0);
    assert_eq!(nakamoto_inv.reward_cycle(), 0);
    assert!(nakamoto_inv.is_online());
}

#[test]
fn test_nakamoto_inv_sync_state_machine() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
        // sparse rc
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        // atlernating rc
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        // sparse rc
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    // boot two peers, and cannibalize the second one for its network and sortdb so we can use them
    // to directly drive a state machine.
    let (mut peer, mut other_peers) =
        make_nakamoto_peers_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone(), 1);
    let mut other_peer = other_peers.pop().unwrap();

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let tip = {
        let sort_db = peer.sortdb.as_mut().unwrap();
        SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
    };
    let total_rcs = peer
        .config
        .burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap()
        + 1;

    // run peer and other_peer until they connect
    loop {
        let _ = peer.step_with_ibd(false);
        let _ = other_peer.step_with_ibd(false);

        let event_ids: Vec<usize> = peer
            .network
            .iter_peer_event_ids()
            .map(|e_id| *e_id)
            .collect();
        let other_event_ids: Vec<usize> = other_peer
            .network
            .iter_peer_event_ids()
            .map(|e_id| *e_id)
            .collect();

        if event_ids.len() > 0 && other_event_ids.len() > 0 {
            break;
        }
    }

    debug!("Peers are connected");
    let peer_addr = NeighborAddress::from_neighbor(&peer.to_neighbor());

    let (sx, rx) = sync_channel(1);
    let mut inv_machine = NakamotoInvStateMachine::new(PeerNetworkComms::new());

    // ::scope is necessary because Rust is forced to think that `other_peers` has the same lifetime
    // as `observer`, which prohibits running a bare thread in which `other_peers` outlives
    // `observer`
    std::thread::scope(|s| {
        s.spawn(|| {
            let sortdb = other_peer.sortdb.take().unwrap();
            inv_machine
                .process_getnakamotoinv_begins(&mut other_peer.network, &sortdb, false)
                .unwrap();
            other_peer.sortdb = Some(sortdb);

            let mut last_learned_rc = 0;
            loop {
                let _ = other_peer.step_with_ibd(false);
                let ev_ids: Vec<_> = other_peer.network.iter_peer_event_ids().collect();
                if ev_ids.len() == 0 {
                    // disconnected
                    panic!("Disconnected");
                }

                let (num_msgs, learned) = inv_machine
                    .process_getnakamotoinv_finishes(&mut other_peer.network)
                    .unwrap();

                for (_, inv) in inv_machine.inventories.iter() {
                    debug!(
                        "inv is at rc {}, last learned rc is {}, total rcs = {}",
                        inv.reward_cycle(),
                        last_learned_rc,
                        total_rcs
                    );
                    last_learned_rc = last_learned_rc.max(inv.reward_cycle());
                }

                if last_learned_rc >= total_rcs {
                    break;
                }

                let sortdb = other_peer.sortdb.take().unwrap();
                inv_machine
                    .process_getnakamotoinv_begins(&mut other_peer.network, &sortdb, false)
                    .unwrap();
                other_peer.sortdb = Some(sortdb);
            }

            sx.send(true).unwrap();
        });

        loop {
            let _ = peer.step_with_ibd(false);
            if rx.try_recv().is_ok() {
                break;
            }
        }
    });

    // inv_machine learned everything
    for (_, inv) in inv_machine.inventories.iter() {
        debug!("Check inv state: {:?}", inv);
        check_inv_state(bitvecs.clone(), 10, nakamoto_start, inv);
    }
}

#[test]
fn test_nakamoto_inv_sync_across_epoch_change() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
        // sparse rc
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        // atlernating rc
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        // sparse rc
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    // boot two peers, and cannibalize the second one for its network and sortdb so we can use them
    // to directly drive a state machine.
    let (mut peer, mut other_peers) =
        make_nakamoto_peers_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone(), 1);
    let mut other_peer = other_peers.pop().unwrap();

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let tip = {
        let sort_db = peer.sortdb.as_mut().unwrap();
        SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
    };
    let total_rcs = peer
        .config
        .burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();

    // run peer and other_peer until they connect
    loop {
        let _ = peer.step_with_ibd(false);
        let _ = other_peer.step_with_ibd(false);

        let event_ids: Vec<usize> = peer
            .network
            .iter_peer_event_ids()
            .map(|e_id| *e_id)
            .collect();
        let other_event_ids: Vec<usize> = other_peer
            .network
            .iter_peer_event_ids()
            .map(|e_id| *e_id)
            .collect();

        if event_ids.len() > 0 && other_event_ids.len() > 0 {
            break;
        }
    }

    debug!("Peers are connected");

    // force peers to sync their epoch 2.x inventories
    let old_burn_chain_tip = peer.network.burnchain_tip.block_height;
    let num_epoch2_blocks = nakamoto_start - 26; // TestPeer starts making blocks at sortition 26

    // check epoch 2.x state machine
    let mut round = 0;
    let mut inv_1_count = 0;
    let mut inv_2_count = 0;
    let mut highest_rc_1 = 0;
    let mut highest_rc_2 = 0;

    let burn_tip_start = peer.network.get_current_epoch().start_height;

    while inv_1_count < num_epoch2_blocks
        || inv_2_count < num_epoch2_blocks
        || highest_rc_1 < total_rcs
        || highest_rc_2 < total_rcs
    {
        // trick the work loop into thinking that the current chain view is this
        peer.network.connection_opts.force_nakamoto_epoch_transition = true;
        other_peer
            .network
            .connection_opts
            .force_nakamoto_epoch_transition = true;

        let _ = peer.step_with_ibd(false);
        let _ = other_peer.step_with_ibd(false);

        inv_1_count = peer
            .network
            .inv_state
            .as_ref()
            .map(|inv| inv.get_inv_num_blocks(&other_peer.to_neighbor().addr))
            .unwrap_or(0);
        inv_2_count = other_peer
            .network
            .inv_state
            .as_ref()
            .map(|inv| inv.get_inv_num_blocks(&peer.to_neighbor().addr))
            .unwrap_or(0);

        highest_rc_1 = peer
            .network
            .inv_state_nakamoto
            .as_ref()
            .map(|inv| inv.highest_reward_cycle())
            .unwrap_or(0);
        highest_rc_2 = other_peer
            .network
            .inv_state_nakamoto
            .as_ref()
            .map(|inv| inv.highest_reward_cycle())
            .unwrap_or(0);

        // nothing should break
        match peer.network.inv_state {
            Some(ref inv) => {
                assert_eq!(inv.get_broken_peers().len(), 0);
                assert_eq!(inv.get_dead_peers().len(), 0);
                assert_eq!(inv.get_diverged_peers().len(), 0);
            }
            None => {}
        }

        match other_peer.network.inv_state {
            Some(ref inv) => {
                assert_eq!(inv.get_broken_peers().len(), 0);
                assert_eq!(inv.get_dead_peers().len(), 0);
                assert_eq!(inv.get_diverged_peers().len(), 0);
            }
            None => {}
        }

        round += 1;

        info!(
            "Epoch 2.x state machine: Peer 1: {}, Peer 2: {} (total {})",
            inv_1_count, inv_2_count, num_epoch2_blocks
        );
        info!(
            "Nakamoto state machine: Peer 1: {}, Peer 2: {} (total {})",
            highest_rc_1, highest_rc_2, total_rcs
        );
    }
}
