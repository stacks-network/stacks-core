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
