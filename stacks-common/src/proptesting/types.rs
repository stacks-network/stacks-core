// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::any;

use proptest::prelude::*;

use super::bytes;
use crate::types::chainstate::{StacksAddress, StacksBlockId};
use crate::types::net::{PeerAddress, PeerHost};
use crate::types::StacksPublicKeyBuffer;
use crate::util::hash::Hash160;

pub fn stacks_public_key_buffer() -> impl Strategy<Value = StacksPublicKeyBuffer> {
    bytes(33).prop_map(|vec| {
        let arr: [u8; 33] = vec.try_into().expect("failed to generate 33-byte array");

        StacksPublicKeyBuffer::from(arr)
    })
}

pub fn stacks_address() -> impl Strategy<Value = StacksAddress> {
    bytes(20).prop_map(|vec| {
        let arr: [u8; 20] = vec.try_into().expect("failed to generate 20-byte array");

        StacksAddress {
            version: 1,
            bytes: Hash160(arr),
        }
    })
}

pub fn peer_address() -> impl Strategy<Value = PeerAddress> {
    bytes(16).prop_map(|vec| {
        let arr: [u8; 16] = vec.try_into().expect("failed to generate 16-byte array");

        PeerAddress(arr)
    })
}

pub fn peer_host() -> impl Strategy<Value = PeerHost> {
    prop_oneof![
        (peer_address(), any::<u16>()).prop_map(|(peer, port)| PeerHost::IP(peer, port)),
        (any::<String>(), any::<u16>()).prop_map(|(host, port)| PeerHost::DNS(host, port))
    ]
}

pub fn stacks_block_id() -> impl Strategy<Value = StacksBlockId> {
    bytes(32).prop_map(|vec| {
        let arr: [u8; 32] = vec.try_into().expect("failed to generate 32-byte array");

        StacksBlockId(arr)
    })
}
