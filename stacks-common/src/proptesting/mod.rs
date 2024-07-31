pub mod hashmap;
pub mod hashset;
pub mod types;

pub use hashmap::stacks_hash_map;
pub use hashset::stacks_hash_set;
use proptest::prelude::*;
use proptest::sample::SizeRange;
pub use types::*;

use crate::util::hash::{to_hex, Hash160, Sha512Trunc256Sum};

pub fn sha_512_trunc_256_sum() -> impl Strategy<Value = Sha512Trunc256Sum> {
    prop::collection::vec(any::<u8>(), 32..=32).prop_map(|vec| {
        let arr: [u8; 32] = vec.try_into().expect("failed to generate 32-byte array");

        Sha512Trunc256Sum::from(arr)
    })
}

/// Generate a random hex string representing a byte array of the given length.
/// i.e. the string will be `2 * byte_len` characters long.
pub fn hex_string(byte_len: impl Into<SizeRange>) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), byte_len).prop_map(|vec| to_hex(&vec))
}

pub fn bytes(len: impl Into<SizeRange>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), len)
}

pub fn hash_160() -> impl Strategy<Value = Hash160> {
    prop::collection::vec(any::<u8>(), 20..=20).prop_map(|vec| {
        let arr: [u8; 20] = vec.try_into().expect("failed to generate 20-byte array");

        Hash160(arr)
    })
}
