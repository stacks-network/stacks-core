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

//! Property tests for the Clarity-language-level `verify-merkle-proof` and
//! `get-bitcoin-tx-output?` builtins. These complement the Rust-helper
//! property tests in `vm::functions::bitcoin::tests`: they exercise the
//! lowering from Clarity-source arguments through the special-form
//! dispatcher into the underlying Rust helpers, and back into Clarity
//! `Value`s.

use clarity_types::ClarityName;
use pinny::tag;
use proptest::prelude::*;
use stacks_common::deps_common::bitcoin::blockdata::script::Script;
use stacks_common::deps_common::bitcoin::blockdata::transaction::{
    OutPoint, Transaction, TxIn, TxOut,
};
use stacks_common::deps_common::bitcoin::network::serialize::serialize as btc_serialize;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::to_hex;

use crate::vm::functions::bitcoin::{
    GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN, VERIFY_MERKLE_PROOF_MAX_DEPTH,
};
use crate::vm::types::{TupleData, Value};
use crate::vm::{ClarityVersion, execute_with_parameters};

/// The bitcoin builtins are gated on Clarity 6 / Epoch 4.0.
const TEST_CLARITY: ClarityVersion = ClarityVersion::Clarity6;
const TEST_EPOCH: StacksEpochId = StacksEpochId::Epoch40;

fn buff_literal(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}

/// Render a list of 32-byte buffers as a Clarity `(list ...)` source literal.
fn buff_list_literal(items: &[[u8; 32]]) -> String {
    if items.is_empty() {
        // Empty literal — the runtime accepts an empty `(list)` for the
        // single-leaf "depth 0" case.
        "(list)".to_string()
    } else {
        let inner: Vec<String> = items.iter().map(|b| buff_literal(b)).collect();
        format!("(list {})", inner.join(" "))
    }
}

fn execute(snippet: &str) -> Value {
    execute_with_parameters(snippet, TEST_CLARITY, TEST_EPOCH, false)
        .expect("execution should succeed")
        .expect("should return a value")
}

/// Walk a Bitcoin-style merkle proof bottom-up using the canonical tree
/// shape implied by `tx_count`, forcing the duplicated-padding sibling at
/// every odd-row edge to equal the running hash. Returns the synthesized
/// `(siblings, root)` pair. Lets us synthesize valid proofs at the full
/// 0..=24 depth range without materializing 2^24-leaf trees in memory.
/// The canonical tree-construction direction is covered independently by
/// the real-mainnet unit tests in `vm::functions::bitcoin::tests`.
fn synth_canonical_proof(
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

/// `ceil(log2(n))` for `n >= 2`, or 0 for `n <= 1` — local copy of the
/// helper in `vm::functions::bitcoin`.
fn canonical_merkle_depth(tx_count: u128) -> u32 {
    if tx_count <= 1 {
        0
    } else {
        (tx_count - 1).ilog2() + 1
    }
}

prop_compose! {
    /// Synthesize a valid merkle proof spanning the full supported range:
    /// `tx_count` ranges over `1..=2^24` (depths 0..=24, the cap enforced by
    /// the `(list 24 (buff 32))` sibling type). Returns
    /// `(leaf, root, tx_index, tx_count, siblings)` where `siblings` matches
    /// the canonical Bitcoin tree shape for `(tx_index, tx_count)` and `root`
    /// is the synthesized root, so the proof verifies by construction.
    fn arb_merkle_proof()(
        tx_count in 1u128..=(1u128 << VERIFY_MERKLE_PROOF_MAX_DEPTH),
        leaf in any::<[u8; 32]>(),
    )(
        tx_index in 0u128..tx_count,
        leaf in Just(leaf),
        tx_count in Just(tx_count),
        raw_siblings in prop::collection::vec(
            any::<[u8; 32]>(),
            canonical_merkle_depth(tx_count) as usize,
        ),
    ) -> ([u8; 32], [u8; 32], u128, u128, Vec<[u8; 32]>) {
        let (siblings, root) = synth_canonical_proof(leaf, tx_index, tx_count, &raw_siblings);
        (leaf, root, tx_index, tx_count, siblings)
    }
}

/// Either an empty witness (forces non-segwit serialization) or 1..=4
/// witness items of 0..=128 bytes (forces segwit marker/flag/witness
/// encoding). With a single input, this toggles the whole tx between the
/// two encodings.
fn arb_witness() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop_oneof![
        Just(Vec::new()),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=128), 1..=4),
    ]
}

/// Tx with 1..=16 outputs and scripts spanning the full 0..=1024-byte
/// allowed range. Randomized witness exercises both segwit and non-segwit
/// encodings; `get-bitcoin-tx-output?` is expected to return the canonical
/// (witness-stripped) txid in both cases.
fn arb_simple_tx() -> impl Strategy<Value = (Transaction, Vec<(u64, Vec<u8>)>)> {
    (
        arb_witness(),
        prop::collection::vec(
            (
                any::<u64>(),
                prop::collection::vec(any::<u8>(), 0..=GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN),
            ),
            1..=16,
        ),
    )
        .prop_map(|(witness, outputs)| {
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
        })
}

fn merkle_proof_snippet(
    leaf: &[u8; 32],
    root: &[u8; 32],
    tx_index: u128,
    tx_count: u128,
    siblings: &[[u8; 32]],
) -> String {
    format!(
        "(verify-merkle-proof {leaf} {root} u{idx} u{count} {sibs})",
        leaf = buff_literal(leaf),
        root = buff_literal(root),
        idx = tx_index,
        count = tx_count,
        sibs = buff_list_literal(siblings),
    )
}

proptest! {
    /// A canonical proof generated at the Rust level must verify when passed
    /// to the Clarity builtin as source literals, at any depth up to 24.
    #[tag(t_prop)]
    #[test]
    fn prop_clarity_verify_merkle_proof_roundtrip(
        (leaf, root, tx_index, tx_count, siblings) in arb_merkle_proof(),
    ) {
        let snippet = merkle_proof_snippet(
            &leaf, &root, tx_index, tx_count, &siblings,
        );
        prop_assert_eq!(Value::Bool(true), execute(&snippet));
    }

    /// Tampering the root at the Clarity layer must surface as `false`, not
    /// as a runtime error. This covers the contract-author expectation that
    /// "bad proof" is a boolean signal.
    #[tag(t_prop)]
    #[test]
    fn prop_clarity_verify_merkle_proof_tampered_root_returns_false(
        (leaf, root, tx_index, tx_count, siblings) in arb_merkle_proof(),
        byte_idx in 0usize..32,
        bit in 0u8..8,
    ) {
        let mut tampered = root;
        tampered[byte_idx] ^= 1u8 << bit;
        // XOR by a non-zero single-bit mask always flips one bit, so
        // `tampered != root` holds by construction — no `prop_assume!` needed.
        let snippet = merkle_proof_snippet(
            &leaf, &tampered, tx_index, tx_count, &siblings,
        );
        prop_assert_eq!(Value::Bool(false), execute(&snippet));
    }

    /// `get-bitcoin-tx-output?` must round-trip a freshly-built tx: for each
    /// vout we get back the original amount and script, plus the canonical
    /// (witness-stripped) txid — invariant across segwit and non-segwit
    /// encodings.
    #[tag(t_prop)]
    #[test]
    fn prop_clarity_get_bitcoin_tx_output_roundtrip(
        (tx, outputs) in arb_simple_tx(),
    ) {
        let bytes = btc_serialize(&tx).expect("serialize tx");
        let expected_txid = tx.txid().0;
        for (vout, (amount, script)) in outputs.iter().enumerate() {
            let snippet = format!(
                "(get-bitcoin-tx-output? {tx_bytes} u{vout})",
                tx_bytes = buff_literal(&bytes),
                vout = vout,
            );
            let expected_inner = TupleData::from_data(vec![
                (
                    ClarityName::from_literal("script"),
                    Value::buff_from(script.clone()).expect("script fits in (buff 1024)"),
                ),
                (
                    ClarityName::from_literal("amount"),
                    Value::UInt(u128::from(*amount)),
                ),
                (
                    ClarityName::from_literal("txid"),
                    Value::buff_from(expected_txid.to_vec())
                        .expect("32-byte txid is a valid (buff 32)"),
                ),
            ])
            .expect("ok-tuple should construct");
            let expected = Value::okay(Value::Tuple(expected_inner))
                .expect("response wrapping should succeed");
            prop_assert_eq!(expected, execute(&snippet));
        }
    }

    /// `vout >= n_outputs` must surface as `(err u2)` (the VoutOutOfRange
    /// code) — confirming the runtime path correctly maps the underlying
    /// error to a Clarity response.
    #[tag(t_prop)]
    #[test]
    fn prop_clarity_get_bitcoin_tx_output_vout_oob_returns_err_u2(
        (tx, outputs) in arb_simple_tx(),
        slop in 0u64..8,
    ) {
        let bytes = btc_serialize(&tx).expect("serialize tx");
        let bad_vout = outputs.len() as u64 + slop;
        let snippet = format!(
            "(get-bitcoin-tx-output? {tx_bytes} u{vout})",
            tx_bytes = buff_literal(&bytes),
            vout = bad_vout,
        );
        let expected = Value::err_uint(2);
        prop_assert_eq!(expected, execute(&snippet));
    }

    /// Feeding arbitrary bytes as `tx-bytes` must never panic or surface a
    /// runtime error. The builtin must always produce a Clarity Response —
    /// `(ok ...)` if the bytes happen to parse as a tx (vanishingly rare on
    /// random input), `(err uN)` otherwise. `execute()` itself would
    /// `panic!` on a runtime error, so reaching the assertion at all
    /// already proves the no-leak guarantee; the Response-shape check pins
    /// down that we got a usable value, not e.g. a runtime trap masked into
    /// some other Value variant.
    #[tag(t_prop)]
    #[test]
    fn prop_clarity_get_bitcoin_tx_output_garbage_bytes(
        tx_bytes in prop::collection::vec(any::<u8>(), 0..=2048),
        vout in any::<u128>(),
    ) {
        let snippet = format!(
            "(get-bitcoin-tx-output? {tx_bytes} u{vout})",
            tx_bytes = buff_literal(&tx_bytes),
            vout = vout,
        );
        let result = execute(&snippet);
        prop_assert!(matches!(result, Value::Response(_)));
    }

    /// Off-by-one boundary on `GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN` (1024
    /// bytes). A script of exactly 1024 bytes must be accepted as
    /// `(ok ...)`; one byte over (1025) must be rejected as `(err u3)`
    /// (`ScriptTooLarge`). The randomized script body and amount catch any
    /// content-dependent regression in the boundary check.
    #[tag(t_prop)]
    #[test]
    fn prop_clarity_get_bitcoin_tx_output_script_at_boundary(
        script in prop::collection::vec(
            any::<u8>(),
            GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN..=GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN + 1,
        ),
        amount in any::<u64>(),
    ) {
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
                witness: vec![],
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: Script::from(script.clone()),
            }],
        };
        let bytes = btc_serialize(&tx).expect("serialize tx");
        let snippet = format!(
            "(get-bitcoin-tx-output? {tx_bytes} u0)",
            tx_bytes = buff_literal(&bytes),
        );
        let result = execute(&snippet);
        if script.len() == GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN {
            // At the cap — must be accepted.
            prop_assert!(
                matches!(&result, Value::Response(r) if r.committed),
                "1024-byte script must yield (ok ...), got {:?}",
                result,
            );
        } else {
            // One over the cap — must surface as (err u3).
            prop_assert_eq!(Value::err_uint(3), result);
        }
    }
}
