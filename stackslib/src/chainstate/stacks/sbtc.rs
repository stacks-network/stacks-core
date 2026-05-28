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

//! sBTC P2TR (taproot) deposit-script derivation.
//!
//! The per-cycle sBTC recipient is a witness-v1 P2TR output committing to a
//! 2-leaf script tree:
//!
//! - deposit: `<deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-pubkey> OP_CHECKSIG`
//!   where `<deposit-data> = <max-fee:u64-be> || <consensus-encoded recipient principal>`.
//! - reclaim: `<lock_time push> OP_CSV <user-supplied-bytes>`. PoX-5 scaffolding
//!   uses `lock_time = u16::MAX` and `[OP_RETURN]` for user bytes, disabling
//!   the reclaim path.
//!
//! The taproot internal key is the BIP-0341 NUMS x-coordinate (no known
//! discrete log), so neither leaf is reachable via key-path; only script-path
//! through the two leaves.
//!
//! Taproot primitives (tagged hashes, leaf/branch hashing, key tweak) are
//! implemented inline against `sha2::Sha256` and `secp256k1`'s
//! `XOnlyPublicKey::add_tweak`. Pulling in the `bitcoin` crate would add a
//! second `secp256k1` version and a `bitcoin::script::PushBytes` impl that
//! ambiguates `[u8; N].as_ref()` elsewhere. The reference fixtures in the
//! test module validate the inline impl byte-for-byte against the sBTC source.
//!
//! `secp256k1` is imported directly rather than via `Secp256k1PublicKey`
//! because the project wrapper does not expose `XOnlyPublicKey` /
//! `add_tweak`, and widening it for one consumer is not worth it.

use clarity::vm::types::PrincipalData;
use secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::{All as Opcode, OP_CSV};
use stacks_common::deps_common::bitcoin::blockdata::script::{Builder, Script};

use crate::chainstate::stacks::Error as ChainstateError;
use crate::core::NUMS_X_COORDINATE;

/// Default tapscript leaf version (BIP-342).
const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// Compute the 32-byte witness-v1 P2TR output key for an sBTC deposit
/// recipient, given:
/// * the aggregate signer's x-only (32-byte) pubkey,
/// * the recipient principal
/// * the deposit-data max-fee value
/// * the reclaim script's CSV lock_time
/// * and the user reclaim bytes (appended after `OP_CSV` in the reclaim script)
///
/// The internal taproot key is the BIP-0341 NUMS coordinate; the script
/// tree has two leaves at depth 1 (`deposit`, `reclaim`).
pub fn sbtc_deposit_taproot_output_key(
    aggregate_pubkey_xonly: &[u8; 32],
    recipient: &PrincipalData,
    max_fee_sats: u64,
    lock_time: u16,
    user_reclaim_script: &[u8],
) -> Result<[u8; 32], ChainstateError> {
    // Validate the supplied aggregate pubkey is on-curve early; the value
    // isn't otherwise needed below since the deposit script encodes the
    // raw 32-byte x-only.
    let _aggregate_xonly = XOnlyPublicKey::from_slice(aggregate_pubkey_xonly)
        .map_err(|_| ChainstateError::Expects("aggregate pubkey not on curve".into()))?;

    let deposit_script = build_deposit_script(aggregate_pubkey_xonly, recipient, max_fee_sats);
    let reclaim_script = build_reclaim_script(lock_time, user_reclaim_script);

    let deposit_leaf = tap_leaf_hash(deposit_script.as_bytes());
    let reclaim_leaf = tap_leaf_hash(reclaim_script.as_bytes());
    let merkle_root = tap_branch_hash(deposit_leaf, reclaim_leaf);
    let tweak = tap_tweak(&NUMS_X_COORDINATE, &merkle_root);
    apply_tweak(&NUMS_X_COORDINATE, &tweak)
}

/// PoX-5 wrapper around `sbtc_deposit_taproot_output_key`.
///
/// Bakes in the values PoX-5 uses:
/// (`lock_time = u16::MAX`, user-script `[OP_RETURN]`)
///  and accepts the
/// pubkey in 33-byte compressed form (which is what
/// `get-current-aggregate-pubkey` returns).
pub fn sbtc_pox5_deposit_taproot_output_key(
    aggregate_pubkey_compressed: &[u8; 33],
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Result<[u8; 32], ChainstateError> {
    let xonly: &[u8; 32] = aggregate_pubkey_compressed[1..]
        .try_into()
        .expect("constant slice length");
    sbtc_deposit_taproot_output_key(
        xonly,
        recipient,
        max_fee_sats,
        u16::MAX,
        &[Opcode::OP_RETURN as u8],
    )
}

/// `<deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-pubkey> OP_CHECKSIG`
fn build_deposit_script(
    aggregate_pubkey_xonly: &[u8; 32],
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Script {
    let mut deposit_data = max_fee_sats.to_be_bytes().to_vec();
    let mut principal_bytes = vec![];
    recipient
        .consensus_serialize(&mut principal_bytes)
        .expect("PrincipalData consensus_serialize is infallible to in-memory writer");
    deposit_data.extend_from_slice(&principal_bytes);

    Builder::new()
        .push_slice(&deposit_data)
        .push_opcode(Opcode::OP_DROP)
        .push_slice(aggregate_pubkey_xonly)
        .push_opcode(Opcode::OP_CHECKSIG)
        .into_script()
}

/// `<lock_time push> OP_CSV <user_reclaim_script bytes>`
///
/// User bytes are appended raw (not parsed or validated here).
///
/// `lock_time` is widened from `u16` to `i64` for the CScriptNum encoding;
/// `Builder::push_int` then chooses the minimal encoding (e.g.,
/// `OP_PUSHNUM_6` for 6, `OP_PUSHBYTES_3 0xFF 0xFF 0x00` for `u16::MAX`).
fn build_reclaim_script(lock_time: u16, user_reclaim_script: &[u8]) -> Script {
    let mut bytes = Builder::new()
        .push_int(i64::from(lock_time))
        .push_opcode(OP_CSV)
        .into_script()
        .into_bytes();
    bytes.extend_from_slice(user_reclaim_script);
    Script::from(bytes)
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`.
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(data);
    h.finalize().into()
}

/// BIP-341 leaf hash with the default tapscript leaf version (0xC0):
/// `tagged_hash("TapLeaf", leaf_version || compact_size(script_len) || script)`.
fn tap_leaf_hash(script_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 9 + script_bytes.len());
    buf.push(TAPSCRIPT_LEAF_VERSION);
    write_compact_size(&mut buf, script_bytes.len() as u64);
    buf.extend_from_slice(script_bytes);
    tagged_hash(b"TapLeaf", &buf)
}

/// BIP-341 branch hash: lex-sort the two child hashes, then
/// `tagged_hash("TapBranch", min(a, b) || max(a, b))`.
fn tap_branch_hash(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    if a <= b {
        buf[..32].copy_from_slice(&a);
        buf[32..].copy_from_slice(&b);
    } else {
        buf[..32].copy_from_slice(&b);
        buf[32..].copy_from_slice(&a);
    }
    tagged_hash(b"TapBranch", &buf)
}

/// BIP-341 taproot tweak: `tagged_hash("TapTweak", internal_x || merkle_root)`.
fn tap_tweak(internal_xonly: &[u8; 32], merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(internal_xonly);
    buf[32..].copy_from_slice(merkle_root);
    tagged_hash(b"TapTweak", &buf)
}

/// Apply the taproot tweak to the internal x-only key:
/// `output = even-Y(internal + tweak * G)`. Returns the resulting x-only.
fn apply_tweak(internal_xonly: &[u8; 32], tweak: &[u8; 32]) -> Result<[u8; 32], ChainstateError> {
    let internal = XOnlyPublicKey::from_slice(internal_xonly)
        .map_err(|_| ChainstateError::Expects("internal xonly not on curve".into()))?;
    let scalar = Scalar::from_be_bytes(*tweak)
        .map_err(|_| ChainstateError::Expects("tweak >= curve order".into()))?;
    let secp = Secp256k1::verification_only();
    let (output, _parity) = internal
        .add_tweak(&secp, &scalar)
        .map_err(|_| ChainstateError::Expects("taproot tweak failed".into()))?;
    Ok(output.serialize())
}

/// Bitcoin compact-size (varint) length prefix.
fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use clarity::vm::types::{
        PrincipalData, QualifiedContractIdentifier, StandardPrincipalData,
    };
    use clarity::vm::ContractName;
    use serde::Deserialize;
    use stacks_common::util::hash::{hex_bytes, to_hex};

    use super::*;

    /// Bitcoin varint reference table covering each branch + boundary of
    /// `write_compact_size`:
    /// - `n < 0xfd`: single byte
    /// - `0xfd <= n <= 0xffff`: `0xfd` + u16 LE
    /// - `0x10000 <= n <= 0xffff_ffff`: `0xfe` + u32 LE
    /// - `n >= 0x1_0000_0000`: `0xff` + u64 LE
    ///
    /// A wrong encoding feeds into the sBTC P2TR deposit script and changes
    /// the taproot output hash, sending funds to the wrong on-chain address.
    /// Explicit fixtures pin each branch so a comparator flip surfaces.
    #[test]
    fn compact_size_boundary_table() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (252, &[0xfc]),
            (253, &[0xfd, 0xfd, 0x00]),
            (0xffff, &[0xfd, 0xff, 0xff]),
            (0x10000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
            (0xffff_ffff, &[0xfe, 0xff, 0xff, 0xff, 0xff]),
            (
                0x1_0000_0000,
                &[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
            (
                u64::MAX,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (n, expected) in cases {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, *n);
            assert_eq!(
                buf, *expected,
                "write_compact_size({n}) = {buf:?}, expected {expected:?}"
            );
        }
    }

    /// Reference fixtures generated from stacks-sbtc/sbtc's
    /// `sbtc::deposits::to_script_pubkey` via
    /// `aaronb-stacks/sbtc-fixtures` script.
    const FIXTURES_JSON: &str = r#"{
  "fixtures": [
    {
      "description": "Standard mainnet stacks address recipient (burn address); small lock_time that uses OP_PUSHNUM; empty user-supplied reclaim script.",
      "expected": {
        "script_pubkey_hex": "51203a900085e4603715fd25abda9299a4989a9f94a490f0d6f1892bc8a1c6babf1a"
      },
      "inputs": {
        "lock_time": 6,
        "max_fee": 15000,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000003a9805160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "62ff1e284841c8b5655ffe1e1e5815eac12cb498d38b6f3b2d638a1c15648158",
        "merkle_root_hex": "f242112a4a0a232d5a77a6b100ca75054b76b2c8745ce5ee6ca0bf8ed33d9c88",
        "reclaim_script_hex": "56b2",
        "reclaim_tapleaf_hash_hex": "4b49f80fd3b1a30785b34bc7f0aa362a5a22aa4cc1ef0570489efec975526d28",
        "taproot_output_key_xonly_hex": "3a900085e4603715fd25abda9299a4989a9f94a490f0d6f1892bc8a1c6babf1a"
      },
      "name": "standard_mainnet_recipient_simple_reclaim"
    },
    {
      "description": "Standard testnet stacks address recipient (burn address); small lock_time; empty user-supplied reclaim script.",
      "expected": {
        "script_pubkey_hex": "51206601c757b0f7d2e5cfb45a938be833c17afbea7f6d5f8b293b454d3563008ba0"
      },
      "inputs": {
        "lock_time": 144,
        "max_fee": 100000000,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000005f5e100051a00000000000000000000000000000000000000007520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "1110862072f1eb0877efaf240d5f2e8e3a524c6e53561d8baccb61fa674d2852",
        "merkle_root_hex": "d2d9a9b96c0881bc199a686662a49ffc71d9eed5a71716f1023297dc791f0dcf",
        "reclaim_script_hex": "029000b2",
        "reclaim_tapleaf_hash_hex": "454bd4c344b99a80a157d5e97bd0526d1fb12d26411f3fab1c49747e0bf1ed4b",
        "taproot_output_key_xonly_hex": "6601c757b0f7d2e5cfb45a938be833c17afbea7f6d5f8b293b454d3563008ba0"
      },
      "name": "standard_testnet_recipient_simple_reclaim"
    },
    {
      "description": "Contract principal recipient with a short contract-name; medium lock_time; reclaim user script is a single OP_DROP.",
      "expected": {
        "script_pubkey_hex": "5120b2e483a39cc83c83ed0e0ae613ae2443b5d4bfa554c6d3752301ffeb2669fd9b"
      },
      "inputs": {
        "lock_time": 1024,
        "max_fee": 0,
        "recipient_principal": "ST000000000000000000002AMW42H.my-contract",
        "reclaim_user_script_hex": "75",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "2a0000000000000000061a00000000000000000000000000000000000000000b6d792d636f6e7472616374752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "a943750ad40e7cf2c822c4589ad5da847bcc52083bb78488b945ae23a93b713d",
        "merkle_root_hex": "50e71558eb44d8c6cece84a81fe8abf70d0bcdd2482b2a6d166ed14d1d37d02a",
        "reclaim_script_hex": "020004b275",
        "reclaim_tapleaf_hash_hex": "6e72448b2a47baf78970c0d5a3b57f414f0d7498572da1cc4bbd56de44335822",
        "taproot_output_key_xonly_hex": "b2e483a39cc83c83ed0e0ae613ae2443b5d4bfa554c6d3752301ffeb2669fd9b"
      },
      "name": "contract_recipient_short_name"
    },
    {
      "description": "Contract principal recipient with a longer contract-name (40 bytes). The deposit OP_DROP data exceeds 75 bytes, forcing OP_PUSHDATA1 in the deposit script. Larger lock_time; non-trivial reclaim user script.",
      "expected": {
        "script_pubkey_hex": "51207796ada72f5f892234230446bef7c897b638bead6479b1adbdb6c3542a2326ed"
      },
      "inputs": {
        "lock_time": 65535,
        "max_fee": 1234567,
        "recipient_principal": "ST000000000000000000002AMW42H.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reclaim_user_script_hex": "20000000000000000000000000000000000000000000000000000000000000000075",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "47000000000012d687061a000000000000000000000000000000000000000028616161616161616161616161616161616161616161616161616161616161616161616161616161617520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "05b21b1cf20c3bff18c61e667a35bdf320d84a68a7c93f2174518923e3b00ce8",
        "merkle_root_hex": "bce95b41e7caa60ee8beb29d1cd1eee251e4cbe595af2d4afc729c6f02d4b779",
        "reclaim_script_hex": "03ffff00b220000000000000000000000000000000000000000000000000000000000000000075",
        "reclaim_tapleaf_hash_hex": "c92bbca25a0644acce8f214e24a837544e5ef29d8304184858a915de30cc8f2c",
        "taproot_output_key_xonly_hex": "7796ada72f5f892234230446bef7c897b638bead6479b1adbdb6c3542a2326ed"
      },
      "name": "contract_recipient_long_name_pushdata1"
    },
    {
      "description": "Lock_time large enough to need a 3-byte push in the script, while staying block-based. BIP-68 reserves bit 22 (0x400000) as the type flag: setting it switches the lock-time to time-based, which the validator rejects (UnsupportedLockTimeUnits). 0x3f_ff_ff is the largest 3-byte-encoded value with bit 22 clear. User reclaim script combines a push with OP_EQUAL.",
      "expected": {
        "script_pubkey_hex": "5120fd5e38a5c16f1e3df25ec70051b8eb1de1da880956c4e6181b64f1b30234fd22"
      },
      "inputs": {
        "lock_time": 4194303,
        "max_fee": 42,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "02abcd87",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1e000000000000002a05160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "257bdae7d9e24d8abcaec346878f63b0418c7ae6dda627cff38dea37bb341100",
        "merkle_root_hex": "de9b211ae7e18e1879140418a2d94d8fe62ed568d451f54fcb8d18a7afa96ab9",
        "reclaim_script_hex": "03ffff00b202abcd87",
        "reclaim_tapleaf_hash_hex": "b748b56a4e5a77c7ed2e39068620bc5872d2840e0f0182d215061a9d50e71967",
        "taproot_output_key_xonly_hex": "fd5e38a5c16f1e3df25ec70051b8eb1de1da880956c4e6181b64f1b30234fd22"
      },
      "name": "high_lock_time_with_user_script"
    },
    {
      "description": "max_fee = 0 (8 leading zero bytes in the deposit data prefix). Standard testnet recipient, empty reclaim user-script. Smallest legal lock_time of 1.",
      "expected": {
        "script_pubkey_hex": "512015df47f9f35347183eadea820aecb745c144e3e4cf20c58f40cb12ca02e0ed2f"
      },
      "inputs": {
        "lock_time": 1,
        "max_fee": 0,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000000000051a00000000000000000000000000000000000000007520f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac",
        "deposit_tapleaf_hash_hex": "56ccfebe0f3b7966524bb2c4df69d0549a97ed89c9266c68f6a309bb5d7a2db3",
        "merkle_root_hex": "0b10bc3e783b461c3794c2a93c5e1db111045c9287502031ad28b038c2153ea0",
        "reclaim_script_hex": "51b2",
        "reclaim_tapleaf_hash_hex": "d5d02fadcf3cff8d20c521cb244b23f8029a11f1625978884026f5d4125063f6",
        "taproot_output_key_xonly_hex": "15df47f9f35347183eadea820aecb745c144e3e4cf20c58f40cb12ca02e0ed2f"
      },
      "name": "max_fee_zero_minimal"
    },
    {
      "description": "max_fee = u64::MAX. The 8-byte big-endian prefix is all 0xff. Useful for catching off-by-one or signedness bugs in the prefix encoder.",
      "expected": {
        "script_pubkey_hex": "51202b404aeae41af5ddc55eed518df8ff82d4e7b302428d0a4dddad72b551664f54"
      },
      "inputs": {
        "lock_time": 100,
        "max_fee": 18446744073709551615,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1effffffffffffffff05160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "3044c7b1a313589014414cedebd3d54419fe93839b1522e181811fb57f5d43ca",
        "merkle_root_hex": "840a316154aedf83cac24e89558bf4488720eab5372d9b467f5bf355c6e3e341",
        "reclaim_script_hex": "0164b2",
        "reclaim_tapleaf_hash_hex": "2e4fa0084100dc5355b5d1d0bc2e6e0e67513ace2282812e0eaa930158051f32",
        "taproot_output_key_xonly_hex": "2b404aeae41af5ddc55eed518df8ff82d4e7b302428d0a4dddad72b551664f54"
      },
      "name": "max_fee_u64_max"
    },
    {
      "description": "Contract-name length is 44 bytes. Total deposit data length is 8 + 1 + 1 + 20 + 1 + 44 = 75 bytes, the largest size for which the bitcoin script builder still emits OP_PUSHBYTES_75 rather than OP_PUSHDATA1. Pair this with the next case to cover both sides of that boundary.",
      "expected": {
        "script_pubkey_hex": "5120fd756efcda9d7ff3c9e69f87eb52a9cc43beb70900ec313426fae9f2901ac273"
      },
      "inputs": {
        "lock_time": 50,
        "max_fee": 7,
        "recipient_principal": "ST000000000000000000002AMW42H.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "4b0000000000000007061a00000000000000000000000000000000000000002c6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "4cfd8a35fb20658d8d9d3cae47fd453695eca7a530668b55cfa443dfbdc45d53",
        "merkle_root_hex": "76538274b025b82022140c923a632d58aee3caa51a39e95828029089b5fd064b",
        "reclaim_script_hex": "0132b2",
        "reclaim_tapleaf_hash_hex": "d08e126224478587e0426d7d534affde56d0b0f940612babf36b919a4f140d36",
        "taproot_output_key_xonly_hex": "fd756efcda9d7ff3c9e69f87eb52a9cc43beb70900ec313426fae9f2901ac273"
      },
      "name": "contract_name_44_pushbytes_boundary"
    },
    {
      "description": "Contract-name length is 45 bytes. Total deposit data length is 76 bytes, the smallest size that triggers OP_PUSHDATA1 in the deposit-script encoding. Otherwise identical to the 44-byte case.",
      "expected": {
        "script_pubkey_hex": "51202762a90adc00f30c7d718f60be6970a5336906f7ebf4473719164fa025333960"
      },
      "inputs": {
        "lock_time": 50,
        "max_fee": 7,
        "recipient_principal": "ST000000000000000000002AMW42H.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "4c4c0000000000000007061a00000000000000000000000000000000000000002d616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "8f62366217618e7086a3f8da75e727d8ec22967efcc296f0f6f334d6f4cceb7e",
        "merkle_root_hex": "6041c4dd9d6ca8bea17133c7aa7974d5c65eaac54ee56da10e8a0c9e90d8d130",
        "reclaim_script_hex": "0132b2",
        "reclaim_tapleaf_hash_hex": "d08e126224478587e0426d7d534affde56d0b0f940612babf36b919a4f140d36",
        "taproot_output_key_xonly_hex": "2762a90adc00f30c7d718f60be6970a5336906f7ebf4473719164fa025333960"
      },
      "name": "contract_name_45_pushdata1_boundary"
    },
    {
      "description": "lock_time = 0. In bitcoin script this encodes as OP_0 (a single 0x00 byte, which is a push of the empty byte-string) rather than a 1-byte push of 0x00. Exercises the empty-push branch of the script-num encoder.",
      "expected": {
        "script_pubkey_hex": "51201a9cfb07c82a6bf5147adc968816e1759a795a07bfb9e47364e59ec3496aaed4"
      },
      "inputs": {
        "lock_time": 0,
        "max_fee": 1,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000000001051600000000000000000000000000000000000000007520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "2fbc2300e180827c419953a6c3bae55f3dfcca06cd12bd5caf5f2669370dae13",
        "merkle_root_hex": "02e2defd794263bb543dd39e2a4c571f29da6fbf87ad3d9a77b2c666ec37e039",
        "reclaim_script_hex": "00b2",
        "reclaim_tapleaf_hash_hex": "b45bd313fdb88c774cedf0e8435fc15678f0edd8a43c2791008f7db0d2f89b6e",
        "taproot_output_key_xonly_hex": "1a9cfb07c82a6bf5147adc968816e1759a795a07bfb9e47364e59ec3496aaed4"
      },
      "name": "lock_time_zero"
    },
    {
      "description": "lock_time = 0x100 (256). Smallest value that needs a 2-byte little-endian push in the script-num encoding (1-byte values cover up to 0xff; 0x100 is the first to require a second byte).",
      "expected": {
        "script_pubkey_hex": "51202e0980724fb67bfb978bb44b209f8e8bbff654fd06cb8cc0ff9c987e04dcc6e6"
      },
      "inputs": {
        "lock_time": 256,
        "max_fee": 9999,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      },
      "intermediate": {
        "deposit_script_hex": "1e000000000000270f051a00000000000000000000000000000000000000007520f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac",
        "deposit_tapleaf_hash_hex": "ab051c6ded9411d42008b56926cadee6048e2e220908e8b7eb0c70c55da02e38",
        "merkle_root_hex": "433073c68e3c5c96a5c8de249c756c7566597a219f3bfdd7cf29824c501bb03d",
        "reclaim_script_hex": "020001b2",
        "reclaim_tapleaf_hash_hex": "4107d1688b77534bd3dfe3c8a8c0a0e9fb1159befeb61cca57cefdb336fd53bc",
        "taproot_output_key_xonly_hex": "2e0980724fb67bfb978bb44b209f8e8bbff654fd06cb8cc0ff9c987e04dcc6e6"
      },
      "name": "lock_time_two_byte_push"
    },
    {
      "description": "Standard principal on mainnet (version byte 22) with hash160 = 0x11..11. Together with the burn-address cases this means the SIP-005 version byte and the 20 hash bytes both vary across the fixture set.",
      "expected": {
        "script_pubkey_hex": "512044e23abf259d1109b0ce4c63664cf15d2779d7412d9e53327636da93c7bba3b6"
      },
      "inputs": {
        "lock_time": 200,
        "max_fee": 555,
        "recipient_principal": "SP8H248H248H248H248H248H248H248H24ARTQ82",
        "reclaim_user_script_hex": "75",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "1e000000000000022b051611111111111111111111111111111111111111117520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "dd24bea2b39e7e4fc8d7e7bc70502a292409072bfe837afa6dd0475941097e96",
        "merkle_root_hex": "a829fc5de1048cd04c007def7876bf72588256310cfd2cac3f3de7ee1c6df14b",
        "reclaim_script_hex": "02c800b275",
        "reclaim_tapleaf_hash_hex": "cc0aa182176facbf8c1768a42c6b70adb180cca5adec16e381e88f040fb20bf9",
        "taproot_output_key_xonly_hex": "44e23abf259d1109b0ce4c63664cf15d2779d7412d9e53327636da93c7bba3b6"
      },
      "name": "nonzero_hash_mainnet_principal"
    },
    {
      "description": "User reclaim script is exactly 2048 bytes (sbtc::MAX_RECLAIM_SCRIPT_LENGTH), the upper bound the validator accepts. Filled with OP_DROP (0x75), which is neither an OP_SUCCESSx nor a push opcode — passes validation and produces a deterministic byte pattern. Exercises tapleaf hashing over a large script.",
      "expected": {
        "script_pubkey_hex": "51200900b1b63da96ca9a8bdd794a54d53e0ee4f5c5372b676e824b7b02845b6e533"
      },
      "inputs": {
        "lock_time": 10,
        "max_fee": 100,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "7575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000000064051a0000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "17a2d34646cd2c607b8a005cade01384bfba07a516c3cf7e47bec36ec5855bf1",
        "merkle_root_hex": "0afbfd14892580cd2bac43800bb36317723611e708162a364c7561f46f0851d2",
        "reclaim_script_hex": "5ab27575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575",
        "reclaim_tapleaf_hash_hex": "1ec1ec76d3a3ced9a7822d25c46ea6a4756edf63a901b31278f039a71dc27e8f",
        "taproot_output_key_xonly_hex": "0900b1b63da96ca9a8bdd794a54d53e0ee4f5c5372b676e824b7b02845b6e533"
      },
      "name": "max_reclaim_user_script_length"
    }
  ],
  "nums_x_coordinate_hex": "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
  "source": "https://github.com/stacks-sbtc/sbtc",
  "source_commit": "b0c9da395403438b2811b7c0945de88b6a5911f4",
  "source_function": "sbtc::deposits::to_script_pubkey (in sbtc/src/deposits.rs)"
}"#;

    #[derive(Deserialize)]
    struct FixturesFile {
        fixtures: Vec<Fixture>,
        nums_x_coordinate_hex: String,
    }

    #[derive(Deserialize)]
    struct Fixture {
        name: String,
        inputs: Inputs,
        intermediate: Intermediate,
    }

    #[derive(Deserialize)]
    struct Inputs {
        /// `u32` because some upstream fixtures provide oversized values that
        /// the API truncates: the helper takes a `u16` (widened to `i64` for
        /// CScriptNum encoding), and callers pre-truncate.
        lock_time: u32,
        max_fee: u64,
        recipient_principal: String,
        reclaim_user_script_hex: String,
        signers_public_key_xonly_hex: String,
    }

    #[derive(Deserialize)]
    struct Intermediate {
        deposit_script_hex: String,
        deposit_tapleaf_hash_hex: String,
        merkle_root_hex: String,
        reclaim_script_hex: String,
        reclaim_tapleaf_hash_hex: String,
        taproot_output_key_xonly_hex: String,
    }

    fn xonly_array(hex_str: &str) -> [u8; 32] {
        hex_bytes(hex_str)
            .expect("fixture pubkey is valid hex")
            .try_into()
            .expect("fixture pubkey is 32 bytes")
    }

    /// Check the sbtc taproot derivation against the embedded reference fixtures.
    #[test]
    fn matches_sbtc_reference_fixtures() {
        let parsed: FixturesFile =
            serde_json::from_str(FIXTURES_JSON).expect("embedded fixtures parse");

        // Sanity-check the fixture file's NUMS x-coordinate matches the in-tree constant.
        assert_eq!(
            to_hex(&NUMS_X_COORDINATE),
            parsed.nums_x_coordinate_hex,
            "NUMS x-coordinate drift between fixtures and core::NUMS_X_COORDINATE",
        );

        for fixture in &parsed.fixtures {
            let pubkey_xonly = xonly_array(&fixture.inputs.signers_public_key_xonly_hex);
            let recipient = PrincipalData::parse(&fixture.inputs.recipient_principal)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}: failed to parse recipient principal {:?}: {e:?}",
                        fixture.name, fixture.inputs.recipient_principal,
                    )
                });
            let user_reclaim = hex_bytes(&fixture.inputs.reclaim_user_script_hex)
                .expect("fixture reclaim_user_script is valid hex");
            // sBTC widens lock_time to i64 and truncates inputs to u16.
            let lock_time = fixture.inputs.lock_time as u16;

            let actual_deposit_script =
                build_deposit_script(&pubkey_xonly, &recipient, fixture.inputs.max_fee);
            let actual_reclaim_script = build_reclaim_script(lock_time, &user_reclaim);
            assert_eq!(
                to_hex(actual_deposit_script.as_bytes()),
                fixture.intermediate.deposit_script_hex,
                "{}: deposit_script",
                fixture.name,
            );
            assert_eq!(
                to_hex(actual_reclaim_script.as_bytes()),
                fixture.intermediate.reclaim_script_hex,
                "{}: reclaim_script",
                fixture.name,
            );

            let actual_deposit_leaf = tap_leaf_hash(actual_deposit_script.as_bytes());
            let actual_reclaim_leaf = tap_leaf_hash(actual_reclaim_script.as_bytes());
            assert_eq!(
                to_hex(&actual_deposit_leaf),
                fixture.intermediate.deposit_tapleaf_hash_hex,
                "{}: deposit_tapleaf_hash",
                fixture.name,
            );
            assert_eq!(
                to_hex(&actual_reclaim_leaf),
                fixture.intermediate.reclaim_tapleaf_hash_hex,
                "{}: reclaim_tapleaf_hash",
                fixture.name,
            );

            let actual_merkle_root = tap_branch_hash(actual_deposit_leaf, actual_reclaim_leaf);
            assert_eq!(
                to_hex(&actual_merkle_root),
                fixture.intermediate.merkle_root_hex,
                "{}: merkle_root",
                fixture.name,
            );

            let actual_output_key = sbtc_deposit_taproot_output_key(
                &pubkey_xonly,
                &recipient,
                fixture.inputs.max_fee,
                lock_time,
                &user_reclaim,
            )
            .unwrap_or_else(|e| panic!("{}: derivation failed: {e:?}", fixture.name));
            assert_eq!(
                to_hex(&actual_output_key),
                fixture.intermediate.taproot_output_key_xonly_hex,
                "{}: taproot_output_key",
                fixture.name,
            );
        }
    }

    // Property tests covering derivation invariants: determinism, per-input
    // sensitivity, rejection of malformed pubkeys, and wrapper/generic
    // agreement across a randomized search space the reference fixtures above
    // cannot exhaustively cover.

    use pinny::tag;
    use proptest::prelude::*;

    thread_local! {
        /// Lazily-built `Secp256k1` context, reused across iterations.
        /// `Secp256k1::new` precomputes multiplication tables; sharing the
        /// context keeps the proptest budget on the property, not setup.
        static SECP_CTX: Secp256k1<secp256k1::All> = Secp256k1::new();
    }

    /// 32 bytes that form a valid x-only secp256k1 point.
    ///
    /// Maps a uniform 32-byte input through `SecretKey -> PublicKey -> x`.
    /// `SecretKey::from_slice` rejects only zero and `>= n` (curve order);
    /// both have probability ~2^-128 over uniform input, so the rejection
    /// budget is effectively untouched. `prop_filter_map` is kept for total
    /// correctness rather than `unwrap`-ing.
    fn arb_valid_xonly_pubkey() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>().prop_filter_map("scalar not in [1, n)", |sk_bytes| {
            let sk = secp256k1::SecretKey::from_slice(&sk_bytes).ok()?;
            SECP_CTX.with(|secp| {
                let pk = secp256k1::PublicKey::from_secret_key(secp, &sk);
                // Compressed: `[parity, x[0..32]]`; drop parity for x-only.
                let compressed = pk.serialize();
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&compressed[1..]);
                Some(xonly)
            })
        })
    }

    /// 33-byte compressed secp256k1 pubkey: prefix `0x02`/`0x03` + valid
    /// x-coordinate. Matches `get-current-aggregate-pubkey`'s output.
    fn arb_valid_compressed_pubkey_33() -> impl Strategy<Value = [u8; 33]> {
        (arb_valid_xonly_pubkey(), prop_oneof![Just(0x02u8), Just(0x03u8)]).prop_map(
            |(xonly, prefix)| {
                let mut compressed = [0u8; 33];
                compressed[0] = prefix;
                compressed[1..].copy_from_slice(&xonly);
                compressed
            },
        )
    }

    /// Standard principal (version < 32, arbitrary 20-byte hash).
    /// `version < 32` is enforced by the range, so construction is total.
    fn arb_standard_principal() -> impl Strategy<Value = StandardPrincipalData> {
        (0u8..32u8, any::<[u8; 20]>()).prop_map(|(version, bytes)| {
            StandardPrincipalData::new(version, bytes).expect("version < 32 by construction")
        })
    }

    /// Valid Clarity contract name: fixed `t-` prefix + `[a-z0-9-]{0,37}`,
    /// total length 2..=39 (under the 40-char cap).
    ///
    /// Why the fixed prefix: every Clarity reserved keyword is a full word
    /// (`tx-sender`, `block-height`, `as-contract`), never `<letter>-<x>`.
    /// `t-XXX` therefore cannot collide with a reserved name and
    /// `ContractName::try_from` cannot reject it.
    fn arb_contract_name() -> impl Strategy<Value = ContractName> {
        prop::collection::vec(
            prop_oneof![b'a'..=b'z', b'0'..=b'9', Just(b'-')],
            0..38,
        )
        .prop_map(|rest| {
            let mut s = String::with_capacity(2 + rest.len());
            s.push_str("t-");
            for c in rest {
                s.push(c as char);
            }
            ContractName::try_from(s).expect("structurally valid contract name")
        })
    }

    /// Standard- or Contract-variant principal, uniformly weighted. The
    /// recipient sensitivity tests below assume both shapes are exercised.
    fn arb_principal_data() -> impl Strategy<Value = PrincipalData> {
        prop_oneof![
            arb_standard_principal().prop_map(PrincipalData::Standard),
            (arb_standard_principal(), arb_contract_name()).prop_map(|(issuer, name)| {
                PrincipalData::Contract(QualifiedContractIdentifier::new(issuer, name))
            }),
        ]
    }

    /// sBTC's `MAX_RECLAIM_SCRIPT_LENGTH` (2048). Larger inputs are rejected
    /// upstream by the validator.
    const MAX_USER_RECLAIM_SCRIPT_LEN: usize = 2048;

    // Generator validity properties. A generator bug masquerades as N bugs
    // across unrelated downstream properties; these proptests pin each
    // generator to its claimed invariant so a refactor that breaks the
    // generator surfaces here, not as false positives elsewhere.

    proptest! {
        /// `arb_valid_xonly_pubkey` claims to produce 32 bytes that are
        /// always a valid x-only secp256k1 point. Pins that claim.
        #[tag(t_prop)]
        #[test]
        fn prop_gen_arb_valid_xonly_pubkey_parses(
            bytes in arb_valid_xonly_pubkey(),
        ) {
            prop_assert!(
                XOnlyPublicKey::from_slice(&bytes).is_ok(),
                "arb_valid_xonly_pubkey produced invalid x-only bytes",
            );
        }

        /// `arb_valid_compressed_pubkey_33` claims to produce 33-byte
        /// compressed pubkeys that secp256k1 accepts. Pins the prefix
        /// (`0x02` or `0x03`) and the x-only tail simultaneously.
        #[tag(t_prop)]
        #[test]
        fn prop_gen_arb_valid_compressed_pubkey_33_parses(
            bytes in arb_valid_compressed_pubkey_33(),
        ) {
            prop_assert!(
                bytes[0] == 0x02 || bytes[0] == 0x03,
                "compressed pubkey prefix must be 0x02 or 0x03, got {:#04x}",
                bytes[0],
            );
            prop_assert!(
                secp256k1::PublicKey::from_slice(&bytes).is_ok(),
                "arb_valid_compressed_pubkey_33 produced invalid compressed bytes",
            );
        }

        /// `arb_principal_data` claims to produce well-formed Clarity
        /// principals. Pins it by stringifying and parsing back —
        /// `PrincipalData::parse` is the canonical accept oracle.
        #[tag(t_prop)]
        #[test]
        fn prop_gen_arb_principal_data_roundtrips(
            principal in arb_principal_data(),
        ) {
            let s = format!("'{principal}");
            let parsed = PrincipalData::parse(&s);
            prop_assert!(
                parsed.is_ok(),
                "arb_principal_data produced unparseable string: {s}",
            );
            prop_assert_eq!(parsed.unwrap(), principal);
        }

        /// `arb_contract_name` claims structurally-valid names within
        /// the 40-char cap and using only `[a-z0-9-]` with `t-` prefix.
        /// Pins via `ContractName::try_from` (the constructor used
        /// downstream by Clarity).
        #[tag(t_prop)]
        #[test]
        fn prop_gen_arb_contract_name_valid(
            name in arb_contract_name(),
        ) {
            let s: &str = name.as_str();
            prop_assert!(s.starts_with("t-"), "missing t- prefix: {s}");
            prop_assert!(s.len() <= 40, "name longer than 40 chars: {s}");
            prop_assert!(
                s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "name contains non-[a-z0-9-] chars: {s}",
            );
            prop_assert!(
                ContractName::try_from(s.to_string()).is_ok(),
                "ContractName::try_from rejected name produced by generator: {s}",
            );
        }
    }

    proptest! {
        /// The output key derivation is a pure function. Same inputs in,
        /// same 32-byte key out, every time. Pins down that no hidden
        /// stateful path (e.g. a thread-local secp context with mutable
        /// state) leaks into the result.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_deterministic(
            pubkey_xonly in arb_valid_xonly_pubkey(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            let key1 = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time, &user_reclaim,
            ).expect("valid x-only pubkey should derive");
            let key2 = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time, &user_reclaim,
            ).expect("valid x-only pubkey should derive");
            prop_assert_eq!(key1, key2);
        }

        /// Two different recipients must produce different deposit
        /// addresses, with everything else fixed. If they collided, two
        /// stakers would share the same on-chain deposit address — a
        /// fund-loss vector.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_distinct_by_recipient(
            pubkey_xonly in arb_valid_xonly_pubkey(),
            recipient_a in arb_principal_data(),
            recipient_b in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            prop_assume!(recipient_a != recipient_b);
            let key_a = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient_a, max_fee, lock_time, &user_reclaim,
            ).expect("valid");
            let key_b = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient_b, max_fee, lock_time, &user_reclaim,
            ).expect("valid");
            prop_assert_ne!(key_a, key_b);
        }

        /// Two different `max_fee` values must produce different deposit
        /// addresses, with everything else fixed. `max_fee` is encoded
        /// inside the deposit script's data prefix; a collision would let
        /// an attacker swap fee values without changing the on-chain
        /// address that the signers watch.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_distinct_by_max_fee(
            pubkey_xonly in arb_valid_xonly_pubkey(),
            recipient in arb_principal_data(),
            max_fee_a in any::<u64>(),
            max_fee_b in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            prop_assume!(max_fee_a != max_fee_b);
            let key_a = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee_a, lock_time, &user_reclaim,
            ).expect("valid");
            let key_b = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee_b, lock_time, &user_reclaim,
            ).expect("valid");
            prop_assert_ne!(key_a, key_b);
        }

        /// Arbitrary 32-byte input that is not a valid x-only secp256k1
        /// point must return `Err`, never panic. The first thing the
        /// derivation does is validate the pubkey on-curve; a regression
        /// that bypasses that guard would land here. Inputs that *do*
        /// parse as valid x-coords are allowed either result (Ok or Err)
        /// — we only pin the no-panic behavior in that branch.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_invalid_pubkey_no_panic(
            pubkey_xonly in any::<[u8; 32]>(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            let is_valid_xonly = XOnlyPublicKey::from_slice(&pubkey_xonly).is_ok();
            let result = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time, &user_reclaim,
            );
            if !is_valid_xonly {
                prop_assert!(
                    result.is_err(),
                    "off-curve x-coord must return Err, got {:?}", result.is_ok(),
                );
            }
            // Either branch: reaching here without panic is the property.
        }

        /// The PoX-5 wrapper must be an exact specialization of the
        /// generic derivation: same x-only portion of the pubkey, same
        /// recipient and fee, with `lock_time = u16::MAX` and
        /// user-reclaim `[OP_RETURN]` baked in. Any drift between the two
        /// would silently change the watched address for PoX-5 deposits.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_pox5_wrapper_matches_generic(
            pubkey_compressed in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            let xonly: [u8; 32] = pubkey_compressed[1..].try_into().expect("33 - 1 = 32");
            let wrapper = sbtc_pox5_deposit_taproot_output_key(
                &pubkey_compressed, &recipient, max_fee,
            ).expect("valid pubkey");
            let generic = sbtc_deposit_taproot_output_key(
                &xonly,
                &recipient,
                max_fee,
                u16::MAX,
                &[Opcode::OP_RETURN as u8],
            ).expect("valid pubkey");
            prop_assert_eq!(wrapper, generic);
        }
    }
}
