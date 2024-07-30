use proptest::prelude::*;
use stacks_common::proptesting::bytes;

use crate::burnchains::Txid;

pub fn txid() -> impl Strategy<Value = Txid> {
    bytes(32).prop_map(|vec| {
        let arr: [u8; 32] = vec.try_into().expect("failed to generate 32-byte array");

        Txid(arr)
    })
}
