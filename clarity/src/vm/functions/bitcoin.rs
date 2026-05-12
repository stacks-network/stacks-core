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

use crate::vm::analysis::errors::get_arguments_exact;
use crate::vm::contexts::{ExecutionState, InvocationContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{RuntimeCheckErrorKind, VmExecutionError, VmInternalError};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{BuffData, ListData, SequenceData, TupleData, TypeSignature, Value};
use crate::vm::{LocalContext, eval};

/// Maximum supported merkle proof depth for `(verify-merkle-proof ...)`.
const VERIFY_MERKLE_PROOF_MAX_DEPTH: u32 = 24;

/// Maximum supported `scriptPubKey` size for `(get-bitcoin-tx-output? ...)`.
const GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN: usize = 1024;

/// Failure modes of `(get-bitcoin-tx-output? ...)`. Mapped to Clarity `(err
/// uN)` codes so callers can distinguish "the tx didn't parse" from "the tx
/// parsed but the output you asked for doesn't exist" without re-parsing.
#[derive(Debug, PartialEq, Eq)]
enum ParseTxError {
    /// Tx bytes failed to deserialize as a Bitcoin transaction, or had
    /// trailing bytes after a successful parse.
    InvalidTx,
    /// `vout` is `>=` the number of outputs in the tx.
    VoutOutOfRange,
    /// The output's `scriptPubKey` is larger than
    /// `GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN`.
    ScriptTooLarge,
}

impl ParseTxError {
    /// Clarity `(err uN)` code that this failure is reported as.
    fn as_error_code(&self) -> u128 {
        match self {
            ParseTxError::InvalidTx => 1,
            ParseTxError::VoutOutOfRange => 2,
            ParseTxError::ScriptTooLarge => 3,
        }
    }
}

/// Parse a Bitcoin transaction (SegWit or non-SegWit) and pluck the output at
/// `vout`, along with the canonical (non-witness) txid in internal byte order.
fn parse_tx_output(raw: &[u8], vout: u64) -> Result<(Vec<u8>, u64, [u8; 32]), ParseTxError> {
    let tx: Transaction = btc_deserialize(raw).map_err(|_| ParseTxError::InvalidTx)?;
    let vout_idx = usize::try_from(vout).map_err(|_| ParseTxError::VoutOutOfRange)?;
    let txout = tx
        .output
        .get(vout_idx)
        .ok_or(ParseTxError::VoutOutOfRange)?;
    let script_bytes = txout.script_pubkey.as_bytes();
    if script_bytes.len() > GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN {
        return Err(ParseTxError::ScriptTooLarge);
    }
    let script = script_bytes.to_vec();
    let amount = txout.value;
    let txid = tx.txid().0;
    Ok((script, amount, txid))
}

/// Canonical Bitcoin merkle-tree depth for a block containing `tx_count`
/// transactions. Returns `0` for an empty or single-tx tree (the leaf is the
/// root); otherwise `ceil(log2(tx_count))`.
fn canonical_merkle_depth(tx_count: u128) -> u32 {
    if tx_count <= 1 {
        0
    } else {
        // ceil(log2(n)) for n >= 2 == floor(log2(n - 1)) + 1
        (tx_count - 1).ilog2() + 1
    }
}

/// Verify that `leaf` reaches `root` along the merkle path described by
/// `siblings` and `tx_index`, using Bitcoin's double-SHA-256 hashing.
///
/// Validates the proof against the canonical tree shape implied by
/// `tx_count`: rejects proofs whose path length doesn't match
/// `ceil(log2(tx_count))`, and rejects `tx_index >= tx_count`. Together these
/// prevent the CVE-2012-2459 ambiguity where an intermediate node `H(C, C)`
/// in an odd-row-padded tree could pose as a leaf.
fn verify_merkle(
    leaf: [u8; 32],
    root: [u8; 32],
    tx_index: u128,
    tx_count: u128,
    siblings: &[[u8; 32]],
) -> bool {
    if tx_count == 0 || tx_index >= tx_count {
        return false;
    }
    let expected_depth = canonical_merkle_depth(tx_count);
    if siblings.len() as u64 != u64::from(expected_depth) {
        return false;
    }

    let mut cur = leaf;
    let mut idx = tx_index;
    let mut buf = [0u8; 64];

    for sibling in siblings {
        if idx & 1 == 1 {
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
/// `(verify-merkle-proof leaf-hash root-hash tx-index tx-count sibling-hashes)`
/// returns `bool`. Hashes are expected in internal byte order. Returns
/// `false` for any structurally invalid proof; only argument-shape errors
/// (wrong types, wrong arity) propagate as runtime errors.
///
/// `tx-count` is the total number of transactions in the block whose merkle
/// root is being checked. It pins down the canonical tree shape and prevents
/// CVE-2012-2459-style attacks where an intermediate node could be passed
/// off as a leaf.
pub fn special_verify_merkle_proof(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    let [leaf_arg, root_arg, tx_index_arg, tx_count_arg, siblings_arg] =
        get_arguments_exact::<_, 5>(args)?;

    let leaf_value = eval(leaf_arg, exec_state, invoke_ctx, context)?;
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

    let root_value = eval(root_arg, exec_state, invoke_ctx, context)?;
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

    let tx_index_value = eval(tx_index_arg, exec_state, invoke_ctx, context)?;
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

    let tx_count_value = eval(tx_count_arg, exec_state, invoke_ctx, context)?;
    let tx_count = match tx_count_value.as_ref() {
        Value::UInt(v) => *v,
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::UIntType),
                tx_count_value.as_ref().to_error_string(),
            )
            .into());
        }
    };

    let siblings_value = eval(siblings_arg, exec_state, invoke_ctx, context)?;
    let siblings_data = match siblings_value.as_ref() {
        Value::Sequence(SequenceData::List(ListData { data, .. })) => data.clone(),
        _ => {
            let expected =
                TypeSignature::list_of(TypeSignature::BUFFER_32, VERIFY_MERKLE_PROOF_MAX_DEPTH)
                    .map_err(|_| {
                        VmInternalError::Expect(
                            "FATAL: failed to build (list 24 (buff 32)) type".into(),
                        )
                    })?;
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(expected),
                siblings_value.as_ref().to_error_string(),
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

    Ok(Value::Bool(verify_merkle(
        leaf, root, tx_index, tx_count, &siblings,
    )))
}

/// Implements the `get-bitcoin-tx-output?` Clarity 6 builtin.
///
/// `(get-bitcoin-tx-output? tx-bytes vout)` returns
/// `(response { script: (buff 1024), amount: uint, txid: (buff 32) } uint)`,
/// where the txid is in internal byte order (ready for `verify-merkle-proof`).
/// On failure, returns one of:
/// - `(err u1)` — `tx-bytes` did not deserialize as a Bitcoin transaction.
/// - `(err u2)` — `vout` is out of range for this tx.
/// - `(err u3)` — the output's `scriptPubKey` exceeds the 1024-byte cap.
pub fn special_get_bitcoin_tx_output(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    let [tx_bytes_arg, vout_arg] = get_arguments_exact::<_, 2>(args)?;

    let tx_value = eval(tx_bytes_arg, exec_state, invoke_ctx, context)?;
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

    let vout_value = eval(vout_arg, exec_state, invoke_ctx, context)?;
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
        Err(_) => {
            return Ok(Value::error(Value::UInt(
                ParseTxError::VoutOutOfRange.as_error_code(),
            ))?);
        }
    };

    let result = match parse_tx_output(&tx_bytes, vout_u64) {
        Ok((script, amount, txid)) => {
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
        Err(e) => Value::err_uint(e.as_error_code()),
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
        assert_eq!(parse_tx_output(&raw, 1), Err(ParseTxError::VoutOutOfRange));
    }

    #[test]
    fn parse_rejects_truncated_tx() {
        let raw = hex(SAMPLE_TX_HEX);
        assert_eq!(
            parse_tx_output(&raw[..raw.len() - 1], 0),
            Err(ParseTxError::InvalidTx),
        );
    }

    #[test]
    fn parse_rejects_oversized_script() {
        // Build a tx with a single output whose scriptPubKey is 1025 bytes
        // (one byte over the cap). The serialized length prefix uses a
        // CompactSize: 0xfd 0x01 0x04 = 0x401 = 1025.
        let mut raw = hex(concat!(
            "01000000",                                                         // version
            "01",                                                               // n_in
            "0000000000000000000000000000000000000000000000000000000000000000", // prev txid
            "00000000",                                                         // prev vout
            "00",                                                               // scriptSig len
            "ffffffff",                                                         // sequence
            "01",                                                               // n_out
            "e803000000000000",                                                 // amount
            "fd0104",                                                           // script len = 1025
        ));
        raw.extend(std::iter::repeat_n(0x51u8, 1025)); // 1025 bytes of OP_1
        raw.extend_from_slice(&hex("00000000")); // locktime

        assert_eq!(parse_tx_output(&raw, 0), Err(ParseTxError::ScriptTooLarge),);
    }

    #[test]
    fn merkle_single_leaf_only_block() {
        // With one tx the txid IS the merkle root; an empty proof should verify
        // trivially.
        let leaf = [0x42u8; 32];
        assert!(verify_merkle(leaf, leaf, 0, 1, &[]));
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
        assert!(verify_merkle(l, root, 0, 2, &[r]));
        // Right leaf: tx_index 1, sibling is the left leaf.
        assert!(verify_merkle(r, root, 1, 2, &[l]));
        // Wrong index → fails.
        assert!(!verify_merkle(l, root, 1, 2, &[r]));
    }

    #[test]
    fn merkle_rejects_oversized_tx_index() {
        let l = [0x11u8; 32];
        let r = [0x22u8; 32];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&l);
        buf[32..].copy_from_slice(&r);
        let root = Sha256dHash::from_data(&buf).0;

        assert!(verify_merkle(l, root, 0, 2, &[r]));
        // tx_index >= tx_count must be rejected.
        assert!(!verify_merkle(l, root, 2, 2, &[r]));
        assert!(!verify_merkle(l, root, u128::MAX, 2, &[r]));
    }

    #[test]
    fn merkle_rejects_cve_2012_2459_intermediate_node() {
        // Build a 3-leaf tree, which Bitcoin pads as [A, B, C, C].
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let c = [0x03u8; 32];
        let mut buf = [0u8; 64];

        buf[..32].copy_from_slice(&a);
        buf[32..].copy_from_slice(&b);
        let h_ab = Sha256dHash::from_data(&buf).0;

        buf[..32].copy_from_slice(&c);
        buf[32..].copy_from_slice(&c);
        let h_cc = Sha256dHash::from_data(&buf).0;

        buf[..32].copy_from_slice(&h_ab);
        buf[32..].copy_from_slice(&h_cc);
        let root = Sha256dHash::from_data(&buf).0;

        // Real leaf C at index 2 (canonical depth is 2; siblings are [C, h_ab]).
        assert!(verify_merkle(c, root, 2, 3, &[c, h_ab]));

        // Forgery 1: claim h_cc (an intermediate node) is a leaf at index 1
        // with depth-1 proof. With tx_count=3 we expect depth 2, so reject.
        assert!(!verify_merkle(h_cc, root, 1, 3, &[h_ab]));

        // Forgery 2: claim a leaf at the duplicated-slot index 3. With
        // tx_count=3 we reject any index >= 3.
        assert!(!verify_merkle(c, root, 3, 3, &[c, h_ab]));
    }

    #[test]
    fn canonical_depth_table() {
        assert_eq!(canonical_merkle_depth(0), 0);
        assert_eq!(canonical_merkle_depth(1), 0);
        assert_eq!(canonical_merkle_depth(2), 1);
        assert_eq!(canonical_merkle_depth(3), 2);
        assert_eq!(canonical_merkle_depth(4), 2);
        assert_eq!(canonical_merkle_depth(5), 3);
        assert_eq!(canonical_merkle_depth(8), 3);
        assert_eq!(canonical_merkle_depth(9), 4);
        assert_eq!(canonical_merkle_depth(16), 4);
        assert_eq!(canonical_merkle_depth(17), 5);
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

    // ---------------------------------------------------------------------
    // Real-block merkle proof tests.
    //
    // These exercise `verify_merkle` against actual Bitcoin mainnet blocks,
    // and double as worked examples of how to assemble the arguments
    // `verify-merkle-proof` expects from a Clarity contract.
    //
    // How the inputs below were collected: Blockstream's public API is shown
    // for concreteness; any Bitcoin Core / block-explorer endpoint will give
    // the same values. Set `TXID` to the (display-order) txid of the
    // transaction you want to prove:
    //
    //   1. `leaf` (the txid being proven, internal byte order):
    //         curl -s "https://blockstream.info/api/tx/$TXID/hex"
    //      Feed those bytes into `parse_tx_output` and use the third return
    //      value — it's the *non-witness* (canonical) txid in internal byte
    //      order, which is what the block's merkle tree commits to.
    //
    //   2. Locate the containing block and grab its merkle root + tx_count:
    //         BLOCK=$(curl -s \
    //           "https://blockstream.info/api/tx/$TXID/merkle-proof" \
    //           | jq -r .block_height)
    //         BLOCKHASH=$(curl -s \
    //           "https://blockstream.info/api/block-height/$BLOCK")
    //         curl -s "https://blockstream.info/api/block/$BLOCKHASH" \
    //           | jq '{merkle_root, tx_count}'
    //      The `merkle_root` is in *display* byte order — reverse it to get
    //      internal order. `txid_from_display_hex` below does this for us.
    //
    //   3. `tx_index` and `siblings` come from the same merkle-proof call:
    //         curl -s \
    //           "https://blockstream.info/api/tx/$TXID/merkle-proof" \
    //           | jq '{pos, merkle}'
    //      `pos` is `tx_index`; `merkle` is the sibling array, ordered
    //      leaf-to-root, each entry in display byte order (reverse each).
    //      With Bitcoin Core directly:
    //         bitcoin-cli gettxoutproof '["'"$TXID"'"]'
    //      gives the same data as a serialized merkleblock for offline
    //      decoding.
    //
    // Sanity check before running: the returned path length must equal
    // `ceil(log2(tx_count))` — `verify_merkle` rejects mismatched depths to
    // close CVE-2012-2459. If the API gives you a different length, you've
    // probably mixed up `tx_count` or grabbed an old (pre-soft-fork)
    // explorer endpoint.
    // ---------------------------------------------------------------------

    /// End-to-end merkle proof check for the genesis coinbase. Block 0 has a
    /// single transaction, so the merkle root equals the txid and the proof
    /// path is empty (depth 0).
    #[test]
    fn merkle_proof_genesis_coinbase() {
        let raw = hex(GENESIS_COINBASE_TX_HEX);
        let (_, _, leaf) = parse_tx_output(&raw, 0).expect("genesis coinbase parses");

        // For block 0, merkle_root == coinbase txid.
        let root = txid_from_display_hex(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        );

        assert!(verify_merkle(leaf, root, 0, 1, &[]));

        // tx_index >= tx_count must reject even when leaf == root.
        assert!(!verify_merkle(leaf, root, 1, 1, &[]));
        // A spurious sibling on a 1-tx block breaks the depth check.
        assert!(!verify_merkle(leaf, root, 0, 1, &[[0u8; 32]]));
    }

    /// End-to-end merkle proof check for the "Bitcoin pizza" tx in mainnet
    /// block 57043. The block has exactly two transactions (coinbase + pizza),
    /// so the proof is a single sibling — the coinbase txid — and the pizza
    /// is the right child at index 1.
    #[test]
    fn merkle_proof_pizza_tx_block_57043() {
        let raw = hex(PIZZA_TX_HEX);
        let (_, _, leaf) = parse_tx_output(&raw, 0).expect("pizza tx parses");

        // Block 57043 merkle root:
        //   curl -s https://blockstream.info/api/block/\
        //     00000000152340ca42227603908689183edc47355204e7aca59383b0aaac1fd8 \
        //     | jq -r .merkle_root
        let root = txid_from_display_hex(
            "5c1d2211f598cd6498f42b269fe3ce4a6fdb40eaa638f86a0579c4e63a721b5a",
        );
        // Sole sibling (the coinbase txid at index 0):
        //   curl -s https://blockstream.info/api/tx/\
        //     a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d/\
        //     merkle-proof | jq -r '.merkle[0]'
        let coinbase = txid_from_display_hex(
            "bd9075d78e65a98fb054cb33cf0ecf14e3e7f8b3150231df8680919a79ac8fe5",
        );

        assert!(verify_merkle(leaf, root, 1, 2, &[coinbase]));

        // Wrong tx_index — pizza is at 1, not 0.
        assert!(!verify_merkle(leaf, root, 0, 2, &[coinbase]));
        // Tampered root.
        let mut bad_root = root;
        bad_root[0] ^= 0x01;
        assert!(!verify_merkle(leaf, bad_root, 1, 2, &[coinbase]));
        // Wrong tx_count — depth check rejects (depth(3) = 2, but we pass 1 sibling).
        assert!(!verify_merkle(leaf, root, 1, 3, &[coinbase]));
    }

    /// End-to-end merkle proof check for the BIP141 SegWit announcement tx
    /// in mainnet block 481824. That block contained 1866 transactions, so
    /// the path is 11 deep — exercising verification of a real, deep proof
    /// against a witness-stripped txid.
    #[test]
    fn merkle_proof_segwit_announcement_block_481824() {
        let raw = hex(REAL_SEGWIT_TX_HEX);
        let (_, _, leaf) = parse_tx_output(&raw, 0).expect("segwit announcement parses");

        // Block 481824 merkle root and tx_count:
        //   curl -s https://blockstream.info/api/block/\
        //     0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893 \
        //     | jq '{merkle_root, tx_count}'
        let root = txid_from_display_hex(
            "6438250cad442b982801ae6994edb8a9ec63c0a0ba117779fbe7ef7f07cad140",
        );

        // Merkle path:
        //   curl -s https://blockstream.info/api/tx/\
        //     8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c/\
        //     merkle-proof | jq '{pos, merkle}'
        // → {"pos": 12, "merkle": [...]}. Depth = ceil(log2(1866)) = 11, so
        // we expect 11 siblings; entries are ordered leaf-to-root.
        let siblings: [[u8; 32]; 11] = [
            txid_from_display_hex(
                "e07a53ab1fa190f726fb1417f3c20e675cf29f9dd8acecc9360eeed776a928db",
            ),
            txid_from_display_hex(
                "21223cecc3a07af99236b87eda3b6415b0b7c5d7a95633f22feb48157b896705",
            ),
            txid_from_display_hex(
                "d62fd49076d83a2342c9dcb96ed5a8dd156b5b7d785e294a368ce7c9e263c25d",
            ),
            txid_from_display_hex(
                "ce51fbe82e60649a62540ef016cb36e35db5f0257046318b73d8ee83281fe429",
            ),
            txid_from_display_hex(
                "af310a3344d96e14141142e334552ad1fa75a4a365cd895c1cfbd0961de6cd41",
            ),
            txid_from_display_hex(
                "2812b22e24414bae49286160a78ef765848b375bde5b67f2fd7209f07a24902d",
            ),
            txid_from_display_hex(
                "d0da4f69356c1c7739a1971f76384829ebe1517635778d4ce0b0a91b56d282cc",
            ),
            txid_from_display_hex(
                "0cfa885934de2d374d14ecdcf1f2a03dba36fbe6ca034202ca17a0a58aefa9bf",
            ),
            txid_from_display_hex(
                "6632f3c95dcf284f86569018d081853473c1f8416009856103384e218e412df5",
            ),
            txid_from_display_hex(
                "b3c8b80f3aca397fba2062b35cc042ff806655d0e593c5ef50d6df48d7360836",
            ),
            txid_from_display_hex(
                "66532296fd04814bf47c9b0bbe2760262d5e452a77671c5cac90624d6d8c8554",
            ),
        ];

        assert!(verify_merkle(leaf, root, 12, 1866, &siblings));

        // Wrong index — adjacent slot must fail.
        assert!(!verify_merkle(leaf, root, 13, 1866, &siblings));
        // Truncated proof — depth check rejects.
        assert!(!verify_merkle(leaf, root, 12, 1866, &siblings[..10]));
        // Tamper any sibling — proof must fail.
        let mut tampered = siblings;
        tampered[5][0] ^= 0x01;
        assert!(!verify_merkle(leaf, root, 12, 1866, &tampered));
    }
}
