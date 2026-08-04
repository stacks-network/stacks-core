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

//! Shared `proptest` strategies for the property tests in
//! `vm::functions::bitcoin::tests` and `vm::tests::bitcoin`.
//!
//! Only helpers that must be byte-identical across both layers belong here.
//! Independent oracles (e.g. a test-local `canonical_merkle_depth`) stay in
//! their consumer module so drift in one layer doesn't propagate to the other.

use proptest::prelude::*;
use stacks_common::deps_common::bitcoin::blockdata::script::Script;
use stacks_common::deps_common::bitcoin::blockdata::transaction::{
    OutPoint, Transaction, TxIn, TxOut,
};
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;

use crate::vm::functions::bitcoin::GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN;

/// Walk a Bitcoin-style merkle proof bottom-up using the canonical tree shape
/// implied by `tx_count`, forcing the duplicated-padding sibling at every
/// odd-row edge to equal the running hash. Returns `(siblings, root)`. Lets
/// tests synthesize proofs valid by construction against the hardened
/// `verify_merkle` (which rejects non-canonical padding-slot siblings and
/// non-padding sibling==cur collisions) without materializing 2^24-leaf trees.
///
/// This shares the padding/hashing logic with `verify_merkle` by design, so a
/// roundtrip through it pins determinism and that synthesis and verification
/// agree on the canonical tree shape — NOT the soundness of `verify_merkle`'s
/// rejection paths. The independent ground truth for the hashing itself is the
/// real-mainnet fixtures (`real_genesis_coinbase_tx`, `real_pizza_tx`,
/// `real_mainnet_segwit_tx`) in `vm::functions::bitcoin::tests`.
pub(crate) fn synth_canonical_proof(
    leaf: [u8; 32],
    tx_index: u128,
    tx_count: u128,
    raw_siblings: &[[u8; 32]],
) -> (Vec<[u8; 32]>, [u8; 32]) {
    let mut siblings = Vec::with_capacity(raw_siblings.len());
    let mut cur = leaf;
    let mut idx = tx_index;
    let mut row_count = tx_count;
    let mut buf = [0u8; 64];
    for raw in raw_siblings {
        let sibling = if (idx | 1) >= row_count { cur } else { *raw };
        siblings.push(sibling);
        if idx & 1 == 1 {
            buf[..32].copy_from_slice(&sibling);
            buf[32..].copy_from_slice(&cur);
        } else {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(&sibling);
        }
        cur = Sha256dHash::from_data(&buf).0;
        idx >>= 1;
        row_count = (row_count + 1) >> 1;
    }
    (siblings, cur)
}

/// Empty witness (non-segwit serialization) or 1..=4 witness items of
/// 0..=128 bytes (segwit marker/flag/witness encoding). On a single-input
/// tx this toggles the whole tx between the two encodings.
pub(crate) fn arb_witness() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop_oneof![
        Just(Vec::new()),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=128), 1..=4),
    ]
}

prop_compose! {
    /// Tx with 1..=16 outputs and scripts spanning the full 0..=1024-byte
    /// allowed range. Randomized witness exercises both segwit and
    /// non-segwit encodings; `get-bitcoin-tx-output?` returns the canonical
    /// (witness-stripped) txid in both cases.
    pub(crate) fn arb_simple_tx()(
        witness in arb_witness(),
        outputs in prop::collection::vec(
            (
                any::<u64>(),
                prop::collection::vec(any::<u8>(), 0..=GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN),
            ),
            1..=16,
        ),
    ) -> (Transaction, Vec<(u64, Vec<u8>)>) {
        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Sha256dHash([0u8; 32]),
                    vout: 0,
                },
                script_sig: Script::from(Vec::<u8>::new()),
                sequence: 0xffffffff,
                witness,
            }],
            output: outputs
                .iter()
                .map(|(amount, script)| TxOut {
                    value: *amount,
                    script_pubkey: Script::from(script.clone()),
                })
                .collect(),
        };
        (tx, outputs)
    }
}
