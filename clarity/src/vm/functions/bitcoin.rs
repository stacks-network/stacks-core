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

use crate::vm::errors::{RuntimeCheckErrorKind, VmExecutionError, VmInternalError};
use crate::vm::functions::buff_to_array;
use crate::vm::types::{BuffData, ListData, SequenceData, TupleData, TypeSignature, Value};

/// Maximum supported merkle proof depth for `(verify-merkle-proof ...)`.
/// Also pins the `(list N (buff 32))` type the type checker enforces for the
/// `sibling-hashes` argument.
pub(crate) const VERIFY_MERKLE_PROOF_MAX_DEPTH: u32 = 24;

/// Maximum supported `scriptPubKey` size for `(get-bitcoin-tx-output? ...)`.
pub(crate) const GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN: usize = 1024;

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
/// `tx_count`. At every level the verifier tracks the real row size
/// (`(row_count + 1) >> 1` per step up) and applies two consistency checks
/// against each supplied sibling:
///
/// 1. If the sibling sits in the duplicated-padding slot of an odd row
///    (`idx ^ 1 >= row_count`), it must equal the running hash — the only
///    canonical value Bitcoin's "duplicate the last node" rule produces.
/// 2. Otherwise the sibling must *not* equal the running hash. In a
///    CVE-2012-2459-clean Bitcoin tree two adjacent subtrees can only share
///    a hash if they share leaves, which the consensus rule forbids; a
///    sibling that happens to equal `cur` at a non-padding position is
///    therefore the fingerprint of an inflated-`tx_count` forgery that
///    tries to relocate the last real leaf into the padded region (claiming
///    e.g. `tx_count = 4` for a real 3-leaf tree).
///
/// Together with the `tx_index < tx_count` and path-length checks, these
/// pin the proof to the canonical tree of a real Bitcoin block.
pub(crate) fn verify_merkle(
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
    let mut row_count = tx_count;
    let mut buf = [0u8; 64];

    for sibling in siblings {
        let sibling_idx = idx | 1;
        if sibling_idx >= row_count {
            // Canonical duplicated-padding slot: only valid when we are at
            // the last position of an odd-sized row and the sibling is the
            // duplicate of `cur` itself.
            if row_count & 1 == 0 || idx != row_count - 1 || sibling != &cur {
                return false;
            }
        } else if sibling == &cur {
            // Non-padding position: a sibling equal to `cur` would require
            // duplicate leaves below, which is invalid.
            return false;
        }

        if idx & 1 == 1 {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&cur);
        } else {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(sibling);
        }
        cur = Sha256dHash::from_data(&buf).0;
        idx >>= 1;
        row_count = (row_count + 1) >> 1;
    }

    cur == root
}

/// Cost-input function for `verify-merkle-proof`: the number of siblings in
/// the proof, which is what `ClarityCostFunction::VerifyMerkleProof` scales
/// on. Ignore and default around type errors here since they are already
/// caught by the type-checker and again in the implementation.
pub fn cost_input_verify_merkle_proof(args: &[Value]) -> Result<u64, VmExecutionError> {
    let len = match args.get(4) {
        Some(Value::Sequence(SequenceData::List(ListData { data, .. }))) => data.len(),
        _ => 0,
    };
    Ok(u64::try_from(len).unwrap_or(u64::MAX))
}

/// Implements the `verify-merkle-proof` Clarity 6 builtin.
///
/// `(verify-merkle-proof leaf-hash root-hash tx-index tx-count sibling-hashes)`
/// returns `bool`. Hashes are expected in internal byte order. Returns
/// `false` for any structurally invalid proof; only argument-shape errors
/// (wrong types, wrong arity) propagate as runtime errors.
///
/// `tx-count` is the total number of transactions in the block whose merkle
/// root is being checked. It pins down the canonical tree shape: the
/// verifier tracks the real row size at every level and rejects proofs
/// whose path does not match a real Bitcoin block, including the
/// CVE-2012-2459 "intermediate node posing as a leaf" and the
/// inflated-`tx-count` variant where the last real leaf of an odd-sized
/// tree is relocated into the duplicated-padding region.
pub fn native_verify_merkle_proof(args: Vec<Value>) -> Result<Value, VmExecutionError> {
    let [
        leaf_value,
        root_value,
        tx_index_value,
        tx_count_value,
        siblings_value,
    ]: [Value; 5] = args
        .try_into()
        .map_err(|_| VmInternalError::Expect("verify-merkle-proof received wrong arity".into()))?;

    let leaf = buff_to_array::<32>(&leaf_value).ok_or_else(|| {
        RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::BUFFER_32),
            leaf_value.to_error_string(),
        )
    })?;
    let root = buff_to_array::<32>(&root_value).ok_or_else(|| {
        RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::BUFFER_32),
            root_value.to_error_string(),
        )
    })?;
    let tx_index = match &tx_index_value {
        Value::UInt(v) => *v,
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::UIntType),
                tx_index_value.to_error_string(),
            )
            .into());
        }
    };
    let tx_count = match &tx_count_value {
        Value::UInt(v) => *v,
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::UIntType),
                tx_count_value.to_error_string(),
            )
            .into());
        }
    };
    let siblings_data = match siblings_value {
        Value::Sequence(SequenceData::List(ListData { data, .. })) => data,
        other => {
            let expected =
                TypeSignature::list_of(TypeSignature::BUFFER_32, VERIFY_MERKLE_PROOF_MAX_DEPTH)
                    .map_err(|_| {
                        VmInternalError::Expect(
                            "FATAL: failed to build (list 24 (buff 32)) type".into(),
                        )
                    })?;
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(expected),
                other.to_error_string(),
            )
            .into());
        }
    };

    let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(siblings_data.len());
    for v in &siblings_data {
        match buff_to_array::<32>(v) {
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

/// Cost-input function for `get-bitcoin-tx-output?`: the length of the raw
/// transaction buffer, which is what `ClarityCostFunction::GetBitcoinTxOutput`
/// scales on. Ignore and default around type errors here since they are
/// already caught by the type-checker and again in the implementation.
pub fn cost_input_get_bitcoin_tx_output(args: &[Value]) -> Result<u64, VmExecutionError> {
    let len = match args.first() {
        Some(Value::Sequence(SequenceData::Buffer(BuffData { data }))) => data.len(),
        _ => 0,
    };
    Ok(u64::try_from(len).unwrap_or(u64::MAX))
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
pub fn native_get_bitcoin_tx_output(
    tx_value: Value,
    vout_value: Value,
) -> Result<Value, VmExecutionError> {
    let tx_bytes = match &tx_value {
        Value::Sequence(SequenceData::Buffer(BuffData { data })) => data.clone(),
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::BUFFER_MAX),
                tx_value.to_error_string(),
            )
            .into());
        }
    };

    let vout = match &vout_value {
        Value::UInt(v) => *v,
        _ => {
            return Err(RuntimeCheckErrorKind::TypeValueError(
                Box::new(TypeSignature::UIntType),
                vout_value.to_error_string(),
            )
            .into());
        }
    };

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

        // Forgery 3: inflate tx_count to 4 to claim C is at index 3 of an
        // even-sized tree. canonical_merkle_depth(4) == 2, so the path-length
        // check still passes; what catches the forgery is the per-level
        // tree-shape consistency check (the supplied sibling at the leaf
        // level would equal `cur`, which a real Bitcoin block — clean of
        // CVE-2012-2459 duplicate-txid forgeries — never produces at a
        // non-padding position).
        assert!(!verify_merkle(c, root, 3, 4, &[c, h_ab]));
    }

    #[test]
    fn merkle_rejects_inflated_tx_count_deep_relocation() {
        // 5-leaf tree, padded canonically as:
        //   row 0: [A, B, C, D, E, E]
        //   row 1: [H(A,B), H(C,D), H(E,E), H(E,E)]
        //   row 2: [H1, H2]
        //   row 3: Root
        // The last real leaf E sits at index 4 with siblings [E, H(E,E), H1].
        // The same siblings re-verify against the same root for every index
        // in {5, 6, 7} if tx_count is inflated to 6, 7, or 8 — exactly the
        // CVE-2012-2459 relocation window that this test pins shut.
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let c = [0x03u8; 32];
        let d = [0x04u8; 32];
        let e = [0x05u8; 32];
        let mut buf = [0u8; 64];

        let mut h = |l: &[u8; 32], r: &[u8; 32]| {
            buf[..32].copy_from_slice(l);
            buf[32..].copy_from_slice(r);
            Sha256dHash::from_data(&buf).0
        };

        let h_ab = h(&a, &b);
        let h_cd = h(&c, &d);
        let h_ee = h(&e, &e);
        let h1 = h(&h_ab, &h_cd);
        let h2 = h(&h_ee, &h_ee);
        let root = h(&h1, &h2);

        // Real proof for E at index 4 with tx_count=5 verifies.
        assert!(verify_merkle(e, root, 4, 5, &[e, h_ee, h1]));

        // Every relocation forgery is rejected.
        for (idx, tx_count) in [(5u128, 6u128), (5, 8), (6, 7), (6, 8), (7, 8)] {
            assert!(
                !verify_merkle(e, root, idx, tx_count, &[e, h_ee, h1]),
                "forgery (idx={idx}, tx_count={tx_count}) must be rejected",
            );
        }

        // Sanity: also reject staying at the real index 4 but with an
        // inflated tx_count=8 (forces a depth-3 path against an even tree).
        // The forgery must still rebuild the same root, so the leaf-level
        // sibling has to be E itself — caught by the non-padding equality
        // check.
        assert!(!verify_merkle(e, root, 4, 8, &[e, h_ee, h1]));
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

    // ---------------------------------------------------------------------
    // Property tests.
    //
    // These probe the same invariants as the unit tests above across a
    // randomized search space, to catch corner cases we wouldn't think to
    // hand-write.
    // ---------------------------------------------------------------------

    use pinny::tag;
    use proptest::prelude::*;
    use stacks_common::deps_common::bitcoin::blockdata::script::Script;
    use stacks_common::deps_common::bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
    use stacks_common::deps_common::bitcoin::network::serialize::serialize as btc_serialize;

    use crate::vm::tests::proptest_strategies::{arb_simple_tx, synth_canonical_proof};

    prop_compose! {
        /// Synthesize a valid merkle proof spanning the full supported range:
        /// `tx_count` ranges over `1..=2^24` (depths 0..=24, the cap enforced
        /// by `VERIFY_MERKLE_PROOF_MAX_DEPTH`). Returns
        /// `(leaf, root, tx_index, tx_count, siblings)` where `siblings`
        /// matches the canonical Bitcoin tree shape for `(tx_index, tx_count)`
        /// and `root` is the synthesized root, so the proof verifies by
        /// construction.
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

    prop_compose! {
        /// Same as [`arb_merkle_proof`] but restricted to `tx_count >= 2`,
        /// guaranteeing `canonical_depth(tx_count) >= 1` and hence at least
        /// one sibling. Use for tampering tests that need a non-empty
        /// siblings vector (the sibling-tamper variant cannot operate on
        /// an empty list).
        fn arb_merkle_proof_with_nonempty_siblings()(
            tx_count in 2u128..=(1u128 << VERIFY_MERKLE_PROOF_MAX_DEPTH),
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

    prop_compose! {
        /// A valid merkle proof plus a `bad_tx_count` whose canonical depth
        /// is GUARANTEED different from the original `tx_count`'s depth.
        /// Used by [`prop_merkle_cross_tree_fails`] to exercise the
        /// depth-downgrade defense without needing a runtime
        /// `prop_assume!` filter.
        ///
        /// Construction: pick `depth_shift in 1..=MAX_DEPTH`, then
        /// `target_depth = (n_depth + depth_shift) mod (MAX_DEPTH + 1)`.
        /// Because `depth_shift in 1..=MAX_DEPTH`, the modulus result is
        /// never `n_depth`, so the depth differs by construction.
        fn arb_merkle_proof_with_different_depth_tx_count()(
            (leaf, root, tx_index, tx_count, siblings) in arb_merkle_proof(),
            depth_shift in 1u32..=VERIFY_MERKLE_PROOF_MAX_DEPTH,
        ) -> ([u8; 32], [u8; 32], u128, u128, Vec<[u8; 32]>, u128) {
            let n_depth = canonical_merkle_depth(tx_count);
            let target_depth =
                (n_depth + depth_shift) % (VERIFY_MERKLE_PROOF_MAX_DEPTH + 1);
            debug_assert_ne!(
                target_depth, n_depth,
                "depth_shift in 1..=MAX_DEPTH guarantees target_depth != n_depth"
            );
            let bad_tx_count = if target_depth == 0 {
                1u128
            } else {
                (1u128 << (target_depth - 1)) + 1
            };
            (leaf, root, tx_index, tx_count, siblings, bad_tx_count)
        }
    }

    /// `buff_to_array::<32>` must reject any buffer whose length is not exactly 32
    /// and return `None`, never panic. Clarity `(buff 32)` is a *maximum*
    /// length, so a shorter buffer is a type-valid argument to
    /// `verify-merkle-proof`; without the length guard the `copy_from_slice`
    /// below would panic on a short buffer — a node-crash vector on consensus
    /// input. The 32-byte case is accepted.
    #[test]
    fn buff_to_array_32_rejects_non_32_length() {
        for len in [0usize, 1, 31, 33, 64, 100] {
            let v = Value::buff_from(vec![0xabu8; len]).unwrap();
            assert!(
                buff_to_array::<32>(&v).is_none(),
                "buffer of length {len} must be rejected, not coerced",
            );
        }
        let exact = Value::buff_from(vec![0x07u8; 32]).unwrap();
        assert_eq!(buff_to_array::<32>(&exact), Some([0x07u8; 32]));
        // A non-buffer value is also rejected.
        assert!(buff_to_array::<32>(&Value::UInt(32)).is_none());
    }

    proptest! {
        /// Any canonical proof we hand to the verifier must verify. The
        /// synthesizer (`synth_canonical_proof`) shares the padding/hashing
        /// logic with `verify_merkle`, so this pins determinism and tree-shape
        /// agreement, not the rejection paths; those are covered by the
        /// tampering/wrong-depth/cross-tree properties and the real-mainnet
        /// fixtures below.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_roundtrip_verifies(
            (leaf, root, tx_index, tx_count, siblings) in arb_merkle_proof(),
        ) {
            prop_assert!(verify_merkle(leaf, root, tx_index, tx_count, &siblings));
        }

        /// `tx_index >= tx_count` must never verify, regardless of proof
        /// contents.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_out_of_range_index_fails(
            (leaf, root, _idx, tx_count, siblings) in arb_merkle_proof(),
            slop in 0u128..1024,
        ) {
            let bad_idx = tx_count.saturating_add(slop);
            prop_assert!(!verify_merkle(leaf, root, bad_idx, tx_count, &siblings));
        }

        /// Flipping a bit of the LEAF breaks the proof.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_tampered_leaf_fails(
            (leaf, root, tx_index, tx_count, siblings) in arb_merkle_proof(),
            byte_idx in 0usize..32,
            bit in 0u8..8,
        ) {
            let mask = 1u8 << bit;
            let mut tampered = leaf;
            tampered[byte_idx] ^= mask;
            // A bit-flip is by definition a change, so the bit can never
            // collide with the original byte at that position.
            debug_assert_ne!(tampered, leaf);
            prop_assert!(!verify_merkle(
                tampered, root, tx_index, tx_count, &siblings,
            ));
        }

        /// Flipping a bit of the ROOT breaks the proof.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_tampered_root_fails(
            (leaf, root, tx_index, tx_count, siblings) in arb_merkle_proof(),
            byte_idx in 0usize..32,
            bit in 0u8..8,
        ) {
            let mask = 1u8 << bit;
            let mut tampered = root;
            tampered[byte_idx] ^= mask;
            debug_assert_ne!(tampered, root);
            prop_assert!(!verify_merkle(
                leaf, tampered, tx_index, tx_count, &siblings,
            ));
        }

        /// Flipping a bit in any SIBLING breaks the proof. Uses the
        /// nonempty-siblings generator so the test never operates on an
        /// empty proof.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_tampered_sibling_fails(
            (leaf, root, tx_index, tx_count, siblings)
                in arb_merkle_proof_with_nonempty_siblings(),
            sibling_seed in 0usize..VERIFY_MERKLE_PROOF_MAX_DEPTH as usize,
            byte_idx in 0usize..32,
            bit in 0u8..8,
        ) {
            let mask = 1u8 << bit;
            let pick = sibling_seed % siblings.len();
            let mut tampered = siblings.clone();
            tampered[pick][byte_idx] ^= mask;
            debug_assert_ne!(tampered, siblings);
            prop_assert!(!verify_merkle(
                leaf, root, tx_index, tx_count, &tampered,
            ));
        }

        /// A proof whose sibling count doesn't match canonical depth must
        /// fail. Closes the CVE-2012-2459 family of attacks.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_wrong_depth_fails(
            (leaf, root, tx_index, tx_count, siblings) in arb_merkle_proof(),
        ) {
            // Truncated proof rejects (skip when proof is already empty).
            if !siblings.is_empty() {
                prop_assert!(!verify_merkle(
                    leaf, root, tx_index, tx_count, &siblings[..siblings.len() - 1],
                ));
            }
            // Extra sibling rejects.
            let mut extended = siblings.clone();
            extended.push([0u8; 32]);
            prop_assert!(!verify_merkle(
                leaf, root, tx_index, tx_count, &extended,
            ));
        }

        /// `canonical_merkle_depth(n)` agrees with a naive halving reference
        /// across the full u128 range.
        #[tag(t_prop)]
        #[test]
        fn prop_canonical_depth_matches_naive(n in any::<u128>()) {
            let mut k = 0u32;
            let mut count = n;
            while count > 1 {
                count = count.div_ceil(2);
                k += 1;
            }
            prop_assert_eq!(canonical_merkle_depth(n), k);
        }

        /// Parsing a freshly-built tx must recover the original amounts and
        /// scripts, and the returned txid must equal the canonical
        /// (witness-stripped) hash — invariant across segwit and non-segwit
        /// encodings.
        #[tag(t_prop)]
        #[test]
        fn prop_parse_tx_roundtrips_outputs(
            (tx, outputs) in arb_simple_tx(),
        ) {
            let bytes = btc_serialize(&tx).expect("serialize tx");
            let expected_txid = tx.txid().0;
            for (vout, (amount, script)) in outputs.iter().enumerate() {
                let (got_script, got_amount, got_txid) =
                    parse_tx_output(&bytes, vout as u64).expect("vout in range");
                prop_assert_eq!(got_amount, *amount);
                prop_assert_eq!(got_script, script.clone());
                prop_assert_eq!(got_txid, expected_txid);
            }
        }

        /// `vout >= n_outputs` must always return `VoutOutOfRange`, for any
        /// valid tx.
        #[tag(t_prop)]
        #[test]
        fn prop_parse_tx_vout_out_of_range(
            (tx, outputs) in arb_simple_tx(),
            slop in 0u64..16,
        ) {
            let bytes = btc_serialize(&tx).expect("serialize tx");
            let bad_vout = outputs.len() as u64 + slop;
            prop_assert_eq!(
                parse_tx_output(&bytes, bad_vout),
                Err(ParseTxError::VoutOutOfRange),
            );
        }

        /// Any output whose scriptPubKey exceeds the 1024-byte cap is
        /// rejected with `ScriptTooLarge` — even by 1 byte, all the way up
        /// to scripts approaching the OP_PUSHDATA2 boundary.
        #[tag(t_prop)]
        #[test]
        fn prop_parse_tx_script_too_large(extra in 1usize..=65_535 - GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN) {
            let script_len = GET_BITCOIN_TX_OUTPUT_MAX_SCRIPT_LEN + extra;
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
                    value: 1,
                    script_pubkey: Script::from(vec![0x51u8; script_len]),
                }],
            };
            let bytes = btc_serialize(&tx).expect("serialize tx");
            prop_assert_eq!(
                parse_tx_output(&bytes, 0),
                Err(ParseTxError::ScriptTooLarge),
            );
        }

        /// `tx_count == 0` describes an empty block, which has no leaves and
        /// thus no valid inclusion proof. The verifier must reject regardless
        /// of leaf, root, tx_index, or sibling contents — there's nothing to
        /// be included in.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_zero_tx_count_always_false(
            leaf in any::<[u8; 32]>(),
            root in any::<[u8; 32]>(),
            tx_index in any::<u128>(),
            siblings in prop::collection::vec(
                any::<[u8; 32]>(),
                0..=VERIFY_MERKLE_PROOF_MAX_DEPTH as usize,
            ),
        ) {
            prop_assert!(!verify_merkle(leaf, root, tx_index, 0, &siblings));
        }

        /// Substituting `tx_count` with a value of a *different* canonical
        /// depth must always reject a valid proof. The path-length check is
        /// the defense against CVE-2012-2459-style depth-downgrade attacks:
        /// claiming a smaller `tx_count` to pass off an intermediate node
        /// as a leaf necessarily mismatches the sibling count, and the
        /// verifier rejects before walking.
        ///
        /// Note: this invariant only holds across different *depths*. Two
        /// distinct `tx_count` values that share a canonical depth (e.g. 5
        /// and 8 both have depth 3) reach the same walk and verify the
        /// same synthetic proof — a real on-chain merkle root would differ,
        /// but a property test using synthetic siblings cannot distinguish
        /// them. The depth-mismatch case is the one the codebase actually
        /// defends against.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_cross_tree_fails(
            (leaf, root, tx_index, _tx_count, siblings, bad_tx_count)
                in arb_merkle_proof_with_different_depth_tx_count(),
        ) {
            prop_assert!(!verify_merkle(
                leaf, root, tx_index, bad_tx_count, &siblings,
            ));
        }

        /// A CVE-2012-2459 *deflation* collision is accepted by `verify_merkle`,
        /// by design. Bitcoin pads odd rows by duplicating the last node, so a
        /// 3-leaf block `[A, B, C]` has shape `[A, B, C, C]` and
        /// `root = H(H(A, B), H(C, C))`. The node `H(C, C)` is also a valid leaf
        /// of a 2-leaf tree with sibling `H(A, B)` and the same root, so
        /// presenting it at index 1 with `tx_count = 2` verifies: an honest
        /// 2-leaf proof that happens to collide with the 3-leaf root.
        ///
        /// The builtin cannot reject this without an authenticated `tx_count` —
        /// from `(leaf, root, tx_index, tx_count, siblings)` alone it cannot tell
        /// the root came from a 3-leaf tree. Upstream commit 9fccbe7bea closed
        /// the complementary *inflation* variant (claiming a larger `tx_count`
        /// to relocate the last real leaf into the padded region) via the
        /// per-level sibling-shape checks; this deflation collision is
        /// fundamental to Merkle proofs and is not closeable here.
        ///
        /// Real callers are safe regardless: pox-5.clar's `validate-l1-lockup`
        /// passes a `leaf` of `SHA256d(tx-bytes)` from a parsed transaction and a
        /// `root` authenticated against the burnchain header. Hitting the
        /// collision would need a txid equal to an internal node `H(C, C)` — a
        /// SHA256d preimage — so the leaf can never be aimed at an internal node.
        ///
        /// The assertion pins this accepted-by-design behavior; flip it only if
        /// the builtin is ever changed to reject honest small-tree proofs.
        #[tag(t_prop)]
        #[test]
        fn prop_merkle_deflated_tx_count_collision_accepted(
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
            c in any::<[u8; 32]>(),
        ) {
            // Canonical 3-leaf padded tree: [a, b, c, c].
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

            // h_cc is a valid leaf of the 2-leaf tree [_, h_cc] with sibling
            // h_ab; the walk reaches the real 3-leaf root. Accepted by design.
            prop_assert!(verify_merkle(h_cc, root, 1, 2, &[h_ab]));
        }

        /// `cost_input_verify_merkle_proof` must return exactly the
        /// siblings-list length: the cost scales linearly with the proof
        /// depth, and a wrong length lets an attacker either over- or
        /// under-charge the verification gas. Pins the function against
        /// `Ok(0)` / `Ok(1)` / fall-through mutants that lose the length
        /// signal.
        #[tag(t_prop)]
        #[test]
        fn prop_cost_verify_merkle_proof_equals_siblings_len(
            siblings_len in 0usize..=VERIFY_MERKLE_PROOF_MAX_DEPTH as usize,
            leaf in any::<[u8; 32]>(),
            root in any::<[u8; 32]>(),
            tx_index in any::<u128>(),
            tx_count in any::<u128>(),
        ) {
            let siblings: Vec<Value> = (0..siblings_len)
                .map(|_| Value::buff_from(vec![0u8; 32]).unwrap())
                .collect();
            let args = vec![
                Value::buff_from(leaf.to_vec()).unwrap(),
                Value::buff_from(root.to_vec()).unwrap(),
                Value::UInt(tx_index),
                Value::UInt(tx_count),
                Value::cons_list_unsanitized(siblings).unwrap(),
            ];
            let cost = cost_input_verify_merkle_proof(&args).unwrap();
            prop_assert_eq!(cost, siblings_len as u64);
        }

        /// `cost_input_get_bitcoin_tx_output` must return exactly the
        /// raw-tx buffer length. Same mutant-killing rationale as the
        /// merkle counterpart above.
        #[tag(t_prop)]
        #[test]
        fn prop_cost_get_bitcoin_tx_output_equals_buffer_len(
            tx_bytes in prop::collection::vec(any::<u8>(), 0..=2048),
            vout in any::<u128>(),
        ) {
            let args = vec![
                Value::buff_from(tx_bytes.clone()).unwrap(),
                Value::UInt(vout),
            ];
            let cost = cost_input_get_bitcoin_tx_output(&args).unwrap();
            prop_assert_eq!(cost, tx_bytes.len() as u64);
        }
    }
}
