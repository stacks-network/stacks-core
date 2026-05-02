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

// Native Clarity 6 Bitcoin helpers:
//
// - `verify-merkle-proof` — Bitcoin-style merkle inclusion proof using
//   double-SHA-256 with the "duplicate last node on odd rows" rule.
// - `get-bitcoin-tx-output?` — parse a Bitcoin transaction (with or without
//   SegWit witness data) and return the output at a given index, along with
//   the canonical (non-witness) txid.
//
// Both follow clarity-bitcoin.clar's convention that 32-byte hashes (txids,
// merkle roots, sibling hashes) are passed in *internal* byte order — the raw
// double-SHA-256 result, which is the reverse of how Bitcoin txids and block
// hashes are typically displayed. The returned `txid` is also in internal
// byte order, ready to feed straight into `verify-merkle-proof`.

use clarity_types::ClarityName;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize as btc_deserialize;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;

use crate::vm::contexts::{ExecutionState, InvocationContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{
    RuntimeCheckErrorKind, VmExecutionError, VmInternalError, check_argument_count,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{BuffData, ListData, SequenceData, TupleData, TypeSignature, Value};
use crate::vm::{LocalContext, eval};

/// Parse a Bitcoin transaction (SegWit or non-SegWit) and pluck the output at
/// `vout`, along with the canonical (non-witness) txid in internal byte order.
///
/// Returns `None` if the bytes don't form a valid Bitcoin tx, if `vout` is
/// out of range, or if there are trailing bytes after the tx.
fn parse_tx_output(raw: &[u8], vout: u64) -> Option<(Vec<u8>, u64, [u8; 32])> {
    let tx: Transaction = btc_deserialize(raw).ok()?;
    let vout_idx = usize::try_from(vout).ok()?;
    let txout = tx.output.get(vout_idx)?;
    let script = txout.script_pubkey.as_bytes().to_vec();
    let amount = txout.value;
    let txid = tx.txid().0;
    Some((script, amount, txid))
}

/// Verify that `leaf` reaches `root` along the merkle path described by
/// `siblings` and `tx_index`, using Bitcoin's double-SHA-256 hashing.
fn verify_merkle(leaf: [u8; 32], root: [u8; 32], tx_index: u128, siblings: &[[u8; 32]]) -> bool {
    let mut cur = leaf;
    let mut idx = tx_index;
    let mut buf = [0u8; 64];

    for sibling in siblings {
        if idx & 1 == 1 {
            // current node is the right child, sibling is on the left
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&cur);
        } else {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(sibling);
        }
        cur = Sha256dHash::from_data(&buf).0;
        idx >>= 1;
    }

    cur == root
}

/// Helper to coerce a Clarity buffer value into a fixed-size byte array.
fn buff_to_array_32(value: &Value) -> Option<[u8; 32]> {
    match value {
        Value::Sequence(SequenceData::Buffer(BuffData { data })) if data.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(data);
            Some(out)
        }
        _ => None,
    }
}

/// Implements the `verify-merkle-proof` Clarity 6 builtin.
///
/// `(verify-merkle-proof leaf-hash root-hash tx-index sibling-hashes)`
/// returns `bool`. Hashes are expected in internal byte order. Returns
/// `false` for any structurally invalid proof; only argument-shape errors
/// (wrong types, wrong arity) propagate as runtime errors.
pub fn special_verify_merkle_proof(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(4, args)?;

    let leaf_value = eval(&args[0], exec_state, invoke_ctx, context)?;
    let leaf = match buff_to_array_32(leaf_value.as_ref()) {
        Some(b) => b,
        None => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::BUFFER_32),
                leaf_value.as_ref().to_error_string(),
            )
            .into());
        }
    };

    let root_value = eval(&args[1], exec_state, invoke_ctx, context)?;
    let root = match buff_to_array_32(root_value.as_ref()) {
        Some(b) => b,
        None => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::BUFFER_32),
                root_value.as_ref().to_error_string(),
            )
            .into());
        }
    };

    let tx_index_value = eval(&args[2], exec_state, invoke_ctx, context)?;
    let tx_index = match tx_index_value.as_ref() {
        Value::UInt(v) => *v,
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::UIntType),
                tx_index_value.as_ref().to_error_string(),
            )
            .into());
        }
    };

    let siblings_value = eval(&args[3], exec_state, invoke_ctx, context)?;
    let siblings_data = match siblings_value.as_ref() {
        Value::Sequence(SequenceData::List(ListData { data, .. })) => data.clone(),
        _ => {
            return Err(RuntimeCheckErrorKind::Unreachable(
                "verify-merkle-proof expected a list of (buff 32)".into(),
            )
            .into());
        }
    };

    runtime_cost(
        ClarityCostFunction::VerifyMerkleProof,
        exec_state,
        u64::try_from(siblings_data.len()).unwrap_or(u64::MAX),
    )?;

    let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(siblings_data.len());
    for v in &siblings_data {
        match buff_to_array_32(v) {
            Some(b) => siblings.push(b),
            // A list element that isn't a 32-byte buff is structurally invalid
            // — return false rather than a runtime error so that callers can
            // treat all proof failures uniformly.
            None => return Ok(Value::Bool(false)),
        }
    }

    Ok(Value::Bool(verify_merkle(leaf, root, tx_index, &siblings)))
}

/// Implements the `get-bitcoin-tx-output?` Clarity 6 builtin.
///
/// `(get-bitcoin-tx-output? tx-bytes vout)` returns
/// `(response { script: (buff 1024), amount: uint, txid: (buff 32) } uint)`,
/// where the txid is in internal byte order (ready for `verify-merkle-proof`).
/// On any parse failure or out-of-range vout, returns `(err u1)`.
pub fn special_get_bitcoin_tx_output(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    let tx_value = eval(&args[0], exec_state, invoke_ctx, context)?;
    let tx_bytes = match tx_value.as_ref() {
        Value::Sequence(SequenceData::Buffer(BuffData { data })) => data.clone(),
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::BUFFER_MAX),
                tx_value.as_ref().to_error_string(),
            )
            .into());
        }
    };

    let vout_value = eval(&args[1], exec_state, invoke_ctx, context)?;
    let vout = match vout_value.as_ref() {
        Value::UInt(v) => *v,
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::UIntType),
                vout_value.as_ref().to_error_string(),
            )
            .into());
        }
    };

    runtime_cost(
        ClarityCostFunction::GetBitcoinTxOutput,
        exec_state,
        u64::try_from(tx_bytes.len()).unwrap_or(u64::MAX),
    )?;

    let vout_u64 = match u64::try_from(vout) {
        Ok(v) => v,
        Err(_) => return Ok(Value::error(Value::UInt(1))?),
    };

    let result = match parse_tx_output(&tx_bytes, vout_u64) {
        Some((script, amount, txid)) => {
            let tuple = TupleData::from_data(vec![
                (
                    ClarityName::from_literal("script"),
                    Value::buff_from(script)?,
                ),
                (
                    ClarityName::from_literal("amount"),
                    Value::UInt(u128::from(amount)),
                ),
                (
                    ClarityName::from_literal("txid"),
                    Value::buff_from(txid.to_vec())?,
                ),
            ])
            .map_err(|_| {
                VmInternalError::Expect(
                    "FATAL: failed to build get-bitcoin-tx-output? result tuple".into(),
                )
            })?;
            Value::okay(Value::Tuple(tuple))?
        }
        None => Value::error(Value::UInt(1))?,
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pre-built minimal non-segwit tx (version 1, 1 in, 1 out, locktime 0).
    /// `txid` (internal byte order) was computed independently and is cached
    /// as a sanity check that our parser produces the right hash.
    const SAMPLE_TX_HEX: &str = concat!(
        "01000000",                                                         // version
        "01",                                                               // n_in
        "0000000000000000000000000000000000000000000000000000000000000000", // prev txid
        "00000000",                                                         // prev vout
        "00",                                                               // scriptSig len
        "ffffffff",                                                         // sequence
        "01",                                                               // n_out
        "e803000000000000",                                                 // amount = 1000
        "16",                                                               // script len = 22
        "0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",                     // P2WPKH
        "00000000",                                                         // locktime
    );

    fn hex(s: &str) -> Vec<u8> {
        let bytes: Result<Vec<u8>, _> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect();
        bytes.unwrap()
    }

    #[test]
    fn parse_minimal_non_segwit_tx() {
        let raw = hex(SAMPLE_TX_HEX);
        let (script, amount, _txid) = parse_tx_output(&raw, 0).expect("valid tx should parse");
        assert_eq!(amount, 1000);
        assert_eq!(script[0], 0x00);
        assert_eq!(script[1], 0x14);
        assert_eq!(script.len(), 22);
    }

    #[test]
    fn parse_returns_canonical_txid() {
        let raw = hex(SAMPLE_TX_HEX);
        // For a non-segwit tx the txid preimage equals the raw bytes.
        let expected = Sha256dHash::from_data(&raw).0;
        let (_, _, txid) = parse_tx_output(&raw, 0).unwrap();
        assert_eq!(txid, expected);
    }

    #[test]
    fn parse_rejects_out_of_range_vout() {
        let raw = hex(SAMPLE_TX_HEX);
        assert!(parse_tx_output(&raw, 1).is_none());
    }

    #[test]
    fn parse_rejects_truncated_tx() {
        let raw = hex(SAMPLE_TX_HEX);
        assert!(parse_tx_output(&raw[..raw.len() - 1], 0).is_none());
    }

    #[test]
    fn merkle_single_leaf_only_block() {
        // With one tx the txid IS the merkle root; an empty proof should verify
        // trivially.
        let leaf = [0x42u8; 32];
        assert!(verify_merkle(leaf, leaf, 0, &[]));
    }

    #[test]
    fn merkle_two_leaves() {
        let l = [0x11u8; 32];
        let r = [0x22u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&l);
        buf[32..].copy_from_slice(&r);
        let root = Sha256dHash::from_data(&buf).0;

        // Left leaf: tx_index 0, sibling is the right leaf.
        assert!(verify_merkle(l, root, 0, &[r]));
        // Right leaf: tx_index 1, sibling is the left leaf.
        assert!(verify_merkle(r, root, 1, &[l]));
        // Wrong index → fails.
        assert!(!verify_merkle(l, root, 1, &[r]));
    }

    #[test]
    fn parse_segwit_tx() {
        // version | marker | flag | n_in | prev_txid | prev_vout | scriptSig_len | sequence
        // | n_out | amount | script_len | script | n_witnesses | wit_len | wit | locktime
        let segwit_hex = concat!(
            "01000000",                                                         // version
            "0001",                                                             // marker+flag
            "01",                                                               // n_in
            "0000000000000000000000000000000000000000000000000000000000000000", // prev txid
            "00000000",                                                         // prev vout
            "00",                                                               // scriptSig len
            "ffffffff",                                                         // sequence
            "01",                                                               // n_out
            "e803000000000000",                                                 // 1000 sats
            "16",                                                               // 22-byte script
            "0014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",                     // P2WPKH
            "01",                                                               // 1 witness item
            "02",                                                               // 2-byte witness
            "abcd",
            "00000000", // locktime
        );
        let raw = hex(segwit_hex);
        let (_, amount, txid) = parse_tx_output(&raw, 0).expect("valid segwit tx");
        assert_eq!(amount, 1000);

        // The txid for a segwit tx must match dsha256 of the *non-witness*
        // serialization (i.e., the same bytes as our SAMPLE_TX_HEX above).
        let expected_preimage = hex(SAMPLE_TX_HEX);
        let expected = Sha256dHash::from_data(&expected_preimage).0;
        assert_eq!(txid, expected);
    }

    /// Display-order (big-endian) hex → internal-byte-order array. Bitcoin
    /// txids/blockhashes are conventionally shown reversed, so block explorers
    /// print the byte-flipped form of what double-SHA-256 actually outputs.
    fn txid_from_display_hex(s: &str) -> [u8; 32] {
        let mut out: [u8; 32] = hex(s).try_into().expect("32-byte txid");
        out.reverse();
        out
    }

    /// Mainnet tx `8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c`,
    /// the BIP141 announcement tx in block 481824. P2SH-wrapped P2WPKH spend
    /// (so it has witness data); 2 outputs (P2SH + OP_RETURN with the
    /// "Hello SegWit" message).
    const REAL_SEGWIT_TX_HEX: &str =
        include_str!("bitcoin_test_fixtures/segwit_announcement_tx.hex");

    /// The Bitcoin genesis block coinbase tx,
    /// `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b`.
    /// Non-segwit, single P2PK output for 50 BTC, prev_txid is all-zeros.
    const GENESIS_COINBASE_TX_HEX: &str =
        include_str!("bitcoin_test_fixtures/genesis_coinbase_tx.hex");

    /// The "Bitcoin pizza" tx,
    /// `a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d` —
    /// 10,000 BTC paid by Laszlo Hanyecz for two pizzas in May 2010. 131
    /// inputs, 1 output (P2PKH).
    const PIZZA_TX_HEX: &str = include_str!("bitcoin_test_fixtures/pizza_tx.hex");

    #[test]
    fn real_mainnet_segwit_tx() {
        let raw = hex(REAL_SEGWIT_TX_HEX);

        // vout 0: P2SH output, 311_000 sats.
        let (script0, amount0, txid) = parse_tx_output(&raw, 0).expect("vout 0 parses");
        assert_eq!(amount0, 311_000);
        assert_eq!(
            script0,
            hex("a91422c17a06117b40516f9826804800003562e834c987"),
        );
        // The witness-stripped txid must match what mainnet actually agreed on.
        assert_eq!(
            txid,
            txid_from_display_hex(
                "8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c",
            ),
        );

        // vout 1: OP_RETURN with the BIP141 announcement, 0 sats.
        let (script1, amount1, _) = parse_tx_output(&raw, 1).expect("vout 1 parses");
        assert_eq!(amount1, 0);
        assert_eq!(script1[0], 0x6a, "expected OP_RETURN prefix");
    }

    #[test]
    fn real_pizza_tx() {
        let raw = hex(PIZZA_TX_HEX);
        let (script, amount, txid) = parse_tx_output(&raw, 0).expect("pizza tx parses");
        // 10,000 BTC = 1,000,000,000,000 sats.
        assert_eq!(amount, 1_000_000_000_000);
        // P2PKH output.
        assert_eq!(
            script,
            hex("76a91446af3fb481837fadbb421727f9959c2d32a3682988ac"),
        );
        assert_eq!(
            txid,
            txid_from_display_hex(
                "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
            ),
        );
    }

    #[test]
    fn real_genesis_coinbase_tx() {
        let raw = hex(GENESIS_COINBASE_TX_HEX);
        let (script, amount, txid) = parse_tx_output(&raw, 0).expect("coinbase parses");
        assert_eq!(amount, 50 * 100_000_000);
        // P2PK to Satoshi's coinbase pubkey.
        assert_eq!(
            script,
            hex(
                "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
            ),
        );
        assert_eq!(
            txid,
            txid_from_display_hex(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            ),
        );
    }
}
