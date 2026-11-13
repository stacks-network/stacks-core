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
//! 2-leaf script tree. Two deposit formats exist; the epoch of the block that
//! computes the reward set selects between them
//! (`StacksEpochId::sbtc_deposit_format`).
//!
//! v1 (Epoch 4.0; sBTC WSTS/FROST aggregate key):
//!
//! - deposit: `<deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-pubkey> OP_CHECKSIG`
//!   where `<deposit-data> = <max-fee:u64-be> || <consensus-encoded recipient principal>`
//!   and `<x-only-pubkey>` is the registry's `current-aggregate-pubkey`.
//! - internal key: the BIP-0341 NUMS x-coordinate (`core::NUMS_X_COORDINATE`).
//!
//! v2 (Epoch 4.1+; sBTC Taproot script-path multisig, stacks-sbtc/sbtc#2138):
//!
//! - deposit: `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <commitment> OP_EQUALVERIFY`
//!   followed by the signers' `multi_a` script
//!   `<k_1> OP_CHECKSIG <k_2> OP_CHECKSIGADD ... <k_n> OP_CHECKSIGADD <threshold> OP_NUMEQUAL`,
//!   where `<commitment> = SHA256(SHA256(<deposit-data>))` and each `k_i` is the
//!   signer's BIP-32 `/0/0` signing key derived from its registry key
//!   ([`derive_sbtc_signing_xonly`]), deduplicated and sorted.
//! - internal key: the v2 NUMS x-coordinate (`core::SBTC_V2_NUMS_X_COORDINATE`).
//!
//! Both formats share the reclaim leaf
//! `<lock_time push> OP_CSV <user-supplied-bytes>`. PoX-5 scaffolding uses
//! `lock_time = u16::MAX` and `[OP_RETURN]` for user bytes, disabling the
//! reclaim path.
//!
//! The internal keys have no known discrete log, so neither leaf is reachable
//! via key-path; only script-path through the two leaves.
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

use std::collections::BTreeSet;

use clarity::vm::types::PrincipalData;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256, Sha512};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::deps_common::bitcoin::blockdata::opcodes::{All as Opcode, OP_CSV};
use stacks_common::deps_common::bitcoin::blockdata::script::{Builder, Script};

use crate::chainstate::stacks::Error as ChainstateError;
use crate::core::{NUMS_X_COORDINATE, SBTC_V2_MAX_SIGNERS, SBTC_V2_NUMS_X_COORDINATE};

/// Default tapscript leaf version (BIP-342).
const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// BIP-342 `OP_CHECKSIGADD`. The vendored opcode table predates tapscript and
/// has no named entry for it.
const OP_CHECKSIGADD: u8 = 0xba;

/// Domain-separation prefix of the BIP-32 chain code of an sBTC signer's
/// extended public key (sBTC's `signer_keys::CHAIN_CODE_DOMAIN`).
const SBTC_SIGNER_CHAIN_CODE_DOMAIN: &[u8] = b"sbtc/signer/chain-code/v1";

/// Number of unhardened BIP-32 steps (`/0/0`) from a signer's extended public
/// key to its Bitcoin signing key (sBTC's `signer_keys::SIGNING_PATH`).
const SBTC_SIGNING_PATH_DEPTH: usize = 2;

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
    deposit_tree_output_key(&NUMS_X_COORDINATE, &deposit_script, &reclaim_script)
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

/// Derive the x-only Bitcoin signing key of an sBTC signer from its registry
/// (33-byte compressed secp256k1) public key.
///
/// Mirrors sBTC's `signer_keys::derive_signing_public_key`: the registry key
/// is the root of a BIP-32 extended public key whose chain code is
/// `SHA256("sbtc/signer/chain-code/v1" || compressed_pubkey)`, and the signing
/// key is its unhardened `/0/0` child, i.e. CKDpub applied twice with index 0:
///
/// ```text
/// I   = HMAC-SHA512(key = c_par, data = ser_P(K_par) || ser32(0))
/// K_i = K_par + parse256(I_L) * G
/// c_i = I_R
/// ```
///
/// The result's parity is dropped (x-only), as in a `multi_a` tapscript.
pub fn derive_sbtc_signing_xonly(
    signer_pubkey_compressed: &[u8; 33],
) -> Result<[u8; 32], ChainstateError> {
    let key = PublicKey::from_slice(signer_pubkey_compressed)
        .map_err(|_| ChainstateError::Expects("sBTC signer pubkey not on curve".into()))?;
    let chain_code: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(SBTC_SIGNER_CHAIN_CODE_DOMAIN);
        hasher.update(signer_pubkey_compressed);
        hasher.finalize().into()
    };
    let signing_key = bip32_unhardened_zero_path(key, chain_code, SBTC_SIGNING_PATH_DEPTH)?;
    Ok(signing_key.x_only_public_key().0.serialize())
}

/// Apply BIP-32 public child derivation (CKDpub) `depth` times with the
/// unhardened index 0, i.e. derive the `/0/…/0` descendant of the extended
/// public key (`key`, `chain_code`).
fn bip32_unhardened_zero_path(
    mut key: PublicKey,
    mut chain_code: [u8; 32],
    depth: usize,
) -> Result<PublicKey, ChainstateError> {
    let secp = Secp256k1::verification_only();
    for _ in 0..depth {
        let mut mac =
            Hmac::<Sha512>::new_from_slice(&chain_code).expect("HMAC accepts any key length");
        mac.update(&key.serialize());
        mac.update(&0u32.to_be_bytes());
        let hmac_output = mac.finalize().into_bytes();
        let (i_left, i_right) = hmac_output.split_at(32);
        let tweak = Scalar::from_be_bytes(i_left.try_into().expect("constant slice length"))
            .map_err(|_| {
                ChainstateError::Expects(
                    "sBTC signer key derivation: child tweak is not a valid scalar".into(),
                )
            })?;
        key = key.add_exp_tweak(&secp, &tweak).map_err(|_| {
            ChainstateError::Expects(
                "sBTC signer key derivation: child key is the point at infinity".into(),
            )
        })?;
        chain_code.copy_from_slice(i_right);
    }
    Ok(key)
}

/// A validated sBTC v2 signer key set: the distinct x-only signing keys in
/// sorted order, and the number of signatures required to spend.
///
/// Mirrors sBTC's `signer_keys::SignerKeySet`. Duplicate keys collapse and
/// keys are sorted bytewise, so the input order does not affect the set, its
/// `multi_a` script, or any address derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbtcSignerKeySet {
    xonly_keys: Vec<[u8; 32]>,
    signatures_required: u16,
}

impl SbtcSignerKeySet {
    /// Build a key set from already-derived x-only signing keys.
    ///
    /// Rejects an empty set, more than `SBTC_V2_MAX_SIGNERS` distinct keys, a
    /// zero threshold, a threshold above the distinct key count, and any key
    /// that is not an x-only secp256k1 point.
    pub fn new(
        xonly_keys: impl IntoIterator<Item = [u8; 32]>,
        signatures_required: u16,
    ) -> Result<Self, ChainstateError> {
        let keys: BTreeSet<[u8; 32]> = xonly_keys.into_iter().collect();
        let signer_count = keys.len();
        if signer_count == 0 || signer_count > SBTC_V2_MAX_SIGNERS {
            return Err(ChainstateError::Expects(format!(
                "sBTC v2 key set has {signer_count} distinct signer keys; expected 1..={SBTC_V2_MAX_SIGNERS}"
            )));
        }
        if signatures_required == 0 || usize::from(signatures_required) > signer_count {
            return Err(ChainstateError::Expects(format!(
                "sBTC v2 key set threshold {signatures_required} is not in 1..={signer_count}"
            )));
        }
        for key in &keys {
            XOnlyPublicKey::from_slice(key)
                .map_err(|_| ChainstateError::Expects("sBTC v2 signer key not on curve".into()))?;
        }
        Ok(Self {
            xonly_keys: keys.into_iter().collect(),
            signatures_required,
        })
    }

    /// Build the key set that the sBTC signers derive from the registry's
    /// `current-signer-set` (33-byte compressed keys) and
    /// `current-signature-threshold`.
    pub fn from_registry(
        signer_keys: &[[u8; 33]],
        signature_threshold: u128,
    ) -> Result<Self, ChainstateError> {
        let signatures_required = u16::try_from(signature_threshold).map_err(|_| {
            ChainstateError::Expects(format!(
                "sBTC registry signature threshold {signature_threshold} does not fit in u16"
            ))
        })?;
        let xonly_keys = signer_keys
            .iter()
            .map(derive_sbtc_signing_xonly)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(xonly_keys, signatures_required)
    }

    /// The distinct x-only signing keys, sorted bytewise.
    pub fn xonly_keys(&self) -> &[[u8; 32]] {
        &self.xonly_keys
    }

    /// The number of signatures required to spend.
    pub fn signatures_required(&self) -> u16 {
        self.signatures_required
    }

    /// The descriptor-compatible `multi_a` tapscript:
    /// `<k_1> OP_CHECKSIG <k_2> OP_CHECKSIGADD ... <k_n> OP_CHECKSIGADD <threshold> OP_NUMEQUAL`
    pub fn signing_script(&self) -> Script {
        let mut bytes = Vec::with_capacity(self.xonly_keys.len() * 34 + 2);
        for (index, key) in self.xonly_keys.iter().enumerate() {
            bytes.extend_from_slice(Builder::new().push_slice(key).into_script().as_bytes());
            bytes.push(if index == 0 {
                Opcode::OP_CHECKSIG as u8
            } else {
                OP_CHECKSIGADD
            });
        }
        bytes.extend_from_slice(
            Builder::new()
                .push_int(i64::from(self.signatures_required))
                .push_opcode(Opcode::OP_NUMEQUAL)
                .into_script()
                .as_bytes(),
        );
        Script::from(bytes)
    }

    /// The 32-byte P2TR output key of the signers' own UTXO: the `multi_a`
    /// script as the sole leaf under the v2 NUMS internal key.
    ///
    /// PoX does not pay to this output. It is exposed so the key derivation,
    /// script encoding, and tweak can be pinned against the scriptPubKeys sBTC
    /// publishes (and checks against Bitcoin Core) for known signer sets.
    pub fn signer_utxo_output_key(&self) -> Result<[u8; 32], ChainstateError> {
        let leaf = tap_leaf_hash(self.signing_script().as_bytes());
        let tweak = tap_tweak(&SBTC_V2_NUMS_X_COORDINATE, &leaf);
        apply_tweak(&SBTC_V2_NUMS_X_COORDINATE, &tweak)
    }
}

/// Compute the 32-byte witness-v1 P2TR output key for an sBTC v2 deposit
/// recipient, given:
/// * the signers' v2 key set,
/// * the recipient principal,
/// * the deposit-data max-fee value,
/// * the reclaim script's CSV lock_time,
/// * and the user reclaim bytes (appended after `OP_CSV` in the reclaim script).
///
/// The internal taproot key is the v2 NUMS coordinate; the script tree has
/// two leaves at depth 1 (`deposit`, `reclaim`).
pub fn sbtc_v2_deposit_taproot_output_key(
    key_set: &SbtcSignerKeySet,
    recipient: &PrincipalData,
    max_fee_sats: u64,
    lock_time: u16,
    user_reclaim_script: &[u8],
) -> Result<[u8; 32], ChainstateError> {
    let deposit_script = build_v2_deposit_script(key_set, recipient, max_fee_sats);
    let reclaim_script = build_reclaim_script(lock_time, user_reclaim_script);
    deposit_tree_output_key(&SBTC_V2_NUMS_X_COORDINATE, &deposit_script, &reclaim_script)
}

/// PoX-5 wrapper around `sbtc_v2_deposit_taproot_output_key`.
///
/// Bakes in the values PoX-5 uses (`lock_time = u16::MAX`, user-script
/// `[OP_RETURN]`), the same as the v1 wrapper.
pub fn sbtc_pox5_v2_deposit_taproot_output_key(
    key_set: &SbtcSignerKeySet,
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Result<[u8; 32], ChainstateError> {
    sbtc_v2_deposit_taproot_output_key(
        key_set,
        recipient,
        max_fee_sats,
        u16::MAX,
        &[Opcode::OP_RETURN as u8],
    )
}

/// Two-leaf taproot output key: `deposit` and `reclaim` leaves at depth 1
/// under `internal_xonly`.
fn deposit_tree_output_key(
    internal_xonly: &[u8; 32],
    deposit_script: &Script,
    reclaim_script: &Script,
) -> Result<[u8; 32], ChainstateError> {
    let deposit_leaf = tap_leaf_hash(deposit_script.as_bytes());
    let reclaim_leaf = tap_leaf_hash(reclaim_script.as_bytes());
    let merkle_root = tap_branch_hash(deposit_leaf, reclaim_leaf);
    let tweak = tap_tweak(internal_xonly, &merkle_root);
    apply_tweak(internal_xonly, &tweak)
}

/// `<max-fee:u64-be> || <consensus-encoded recipient principal>`
fn deposit_data(recipient: &PrincipalData, max_fee_sats: u64) -> Vec<u8> {
    let mut deposit_data = max_fee_sats.to_be_bytes().to_vec();
    recipient
        .consensus_serialize(&mut deposit_data)
        .expect("PrincipalData consensus_serialize is infallible to in-memory writer");
    deposit_data
}

/// The hash a v2 deposit script commits to: `SHA256(SHA256(<deposit-data>))`.
/// The signers reveal the inner hash (the preimage) when spending.
fn v2_deposit_data_commitment(recipient: &PrincipalData, max_fee_sats: u64) -> [u8; 32] {
    let preimage: [u8; 32] = Sha256::digest(deposit_data(recipient, max_fee_sats)).into();
    Sha256::digest(preimage).into()
}

/// `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <commitment> OP_EQUALVERIFY` followed
/// by the key set's `multi_a` script.
fn build_v2_deposit_script(
    key_set: &SbtcSignerKeySet,
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Script {
    let commitment = v2_deposit_data_commitment(recipient, max_fee_sats);
    let mut bytes = Builder::new()
        .push_opcode(Opcode::OP_SIZE)
        .push_int(32)
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_SHA256)
        .push_slice(&commitment)
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .into_script()
        .into_bytes();
    bytes.extend_from_slice(key_set.signing_script().as_bytes());
    Script::from(bytes)
}

/// `<deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-pubkey> OP_CHECKSIG`
fn build_deposit_script(
    aggregate_pubkey_xonly: &[u8; 32],
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Script {
    Builder::new()
        .push_slice(&deposit_data(recipient, max_fee_sats))
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
    use clarity::vm::representations::CONTRACT_MAX_NAME_LENGTH;
    use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
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

    // ---- sBTC v2: Taproot script-path multisig ----

    /// The sBTC devenv signer set (compressed registry keys), as pinned in
    /// sBTC's `signer_keys` tests.
    const SBTC_DEVENV_SIGNER_KEYS: [&str; 3] = [
        "035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46",
        "031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380",
        "02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c",
    ];

    /// The bootstrap signing set in sBTC's sample testnet signer config.
    const SBTC_TESTNET_SIGNER_KEYS: [&str; 15] = [
        "03fc6197a1396680f7acc4241ac3935ba4af560deac0224abec45c47c5e73ea638",
        "0390d76b21867e9c5aa25a903423d3ddb0da65604f0470390ed903f2056c5adb4b",
        "03fb16c76ae6773951b2ea957f723dc0f5f4ccd795313793308a38a37a3c4aa582",
        "024681893c76fb2d52bdbcd6341c66f15f14698aed638d6c1a2fc9440948b5f11a",
        "0341a8f3562d805ab240c2ce2dd220313329ef75459f115bd818b250a2ad2df6aa",
        "02a963be44cd7efd07e59e28f02f5d2bafdf28b5b13b3b13b5c2a9e3f4c1b1e5bf",
        "03c4382afb075bf577acbb13196e6130c386a3d8261326402f587fb7c42d0dbd5e",
        "02c2b53974a2b1a05103a7c42a4861c859c9b999ed196c065bcec952438ae8ec9b",
        "034646af6402dab3a265688b2ea67a7aa88d9fc6eca663385a6e92336f7f081c59",
        "02629d043197e659ac45f0332b219760b9542d22499ff6431c113ec64d60e86628",
        "033f3dd6b1e8e4cfff219054dce240d312b6deda10386c3a815459224a2ba0f411",
        "031c7e1267b272d5a11257f46c61e0e5005337ebcebb6f2b71798addfd04e5a38a",
        "02ae3a560f4f67ce8c0f4b2e46d24f51232a768cfc69cf08a02ea02426d77bd64c",
        "026fb0b3c3ea60a3197e94f2dcd37d7f302e6d33c75351f4f5024e9c31ac327c11",
        "0374e256948a14799c2a788960ab6657dc5d322b070abae4ce83b2a0df4df2c727",
    ];

    /// A single-signer set from sBTC's `signer_keys` tests.
    const SBTC_RANDOM_SIGNER_KEYS: [&str; 1] =
        ["027212421e4a9c34e251a7cd523146c4434451e42c230d576b07fe8874f97a694d"];

    fn compressed_array(hex_str: &str) -> [u8; 33] {
        hex_bytes(hex_str)
            .expect("fixture pubkey is valid hex")
            .try_into()
            .expect("fixture pubkey is 33 bytes")
    }

    fn key_set_from_hex(keys: &[&str], threshold: u128) -> SbtcSignerKeySet {
        let keys: Vec<[u8; 33]> = keys.iter().map(|key| compressed_array(key)).collect();
        SbtcSignerKeySet::from_registry(&keys, threshold).expect("valid key set")
    }

    /// x-only keys with secret scalars `1..=count`, for bounds tests.
    fn xonly_keys_from_small_scalars(count: u8) -> Vec<[u8; 32]> {
        SECP_CTX.with(|secp| {
            (1..=count)
                .map(|scalar| {
                    let mut secret = [0u8; 32];
                    secret[31] = scalar;
                    let sk = secp256k1::SecretKey::from_slice(&secret).expect("small scalar");
                    secp256k1::PublicKey::from_secret_key(secp, &sk)
                        .x_only_public_key()
                        .0
                        .serialize()
                })
                .collect()
        })
    }

    /// sBTC pins the signer-UTXO scriptPubKey of these key sets in
    /// `signer_keys::tests::key_set_script_pubkey_is_stable`, each checked
    /// against Bitcoin Core's derivation of the equivalent `tr(NUMS,multi_a(...))`
    /// descriptor. Matching them pins our BIP-32 child derivation, key
    /// ordering, `multi_a` encoding, leaf hashing, and v2-NUMS tweak against
    /// the upstream implementation, independently of the deposit-tree
    /// fixtures below.
    #[test]
    fn signer_utxo_output_key_matches_sbtc_pinned_script_pubkeys() {
        let cases: [(&[&str], u128, &str); 3] = [
            (
                &SBTC_DEVENV_SIGNER_KEYS,
                2,
                "44d42c5fdc191818e50ec6591d2103f17ec2771c1a0ea5dc1db95ca56dd377b5",
            ),
            (
                &SBTC_TESTNET_SIGNER_KEYS,
                11,
                "36beeeb78d2eff65baa60f8da199b5ecd06ee833dd3c8f6340f8b6d4102a595c",
            ),
            (
                &SBTC_RANDOM_SIGNER_KEYS,
                1,
                "a014d46c5ec41d7d059755296e1d12566ca7416d3707a7789d2a3c88ee1eeca2",
            ),
        ];
        for (keys, threshold, expected_output_key) in cases {
            let key_set = key_set_from_hex(keys, threshold);
            let output_key = key_set
                .signer_utxo_output_key()
                .expect("signer UTXO derivation");
            assert_eq!(
                to_hex(&output_key),
                expected_output_key,
                "{}-of-{} signer UTXO output key",
                threshold,
                keys.len()
            );
        }
    }

    /// sBTC documents the v2 NUMS point as the `/0/0` child of the BIP-341
    /// NUMS point treated as an xpub with an all-zero chain code. Reproducing
    /// it checks the CKDpub implementation against a value that does not
    /// depend on the signer chain-code domain.
    #[test]
    fn v2_nums_is_zero_chain_code_child_of_nums() {
        let nums = XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE)
            .expect("NUMS on curve")
            .public_key(secp256k1::Parity::Even);
        let child = bip32_unhardened_zero_path(nums, [0u8; 32], SBTC_SIGNING_PATH_DEPTH)
            .expect("derivation succeeds");
        assert_eq!(
            child.x_only_public_key().0.serialize(),
            SBTC_V2_NUMS_X_COORDINATE
        );
    }

    /// Reference fixtures for the v2 deposit tree.
    ///
    /// Generated directly from the pinned sBTC crate by
    /// `contrib/tools/sbtc-fixtures`. See its README for regeneration steps.
    const V2_FIXTURES_JSON: &str = include_str!("fixtures/sbtc-v2.json");

    #[derive(Deserialize)]
    struct V2FixturesFile {
        fixtures: Vec<V2Fixture>,
        v2_nums_x_coordinate_hex: String,
    }

    #[derive(Deserialize)]
    struct V2Fixture {
        name: String,
        inputs: V2Inputs,
        intermediate: V2Intermediate,
        expected: V2Expected,
    }

    #[derive(Deserialize)]
    struct V2Inputs {
        signer_keys_compressed_hex: Vec<String>,
        signatures_required: u16,
        recipient_principal: String,
        max_fee: u64,
        lock_time: u32,
        reclaim_user_script_hex: String,
    }

    #[derive(Deserialize)]
    struct V2Intermediate {
        derived_xonly_keys_sorted_hex: Vec<String>,
        signing_script_hex: String,
        key_set_script_pubkey_hex: String,
        deposit_script_hex: String,
        reclaim_script_hex: String,
        deposit_tapleaf_hash_hex: String,
        reclaim_tapleaf_hash_hex: String,
        merkle_root_hex: String,
        taproot_output_key_xonly_hex: String,
    }

    #[derive(Deserialize)]
    struct V2Expected {
        script_pubkey_hex: String,
    }

    #[test]
    fn matches_sbtc_v2_reference_fixtures() {
        let parsed: V2FixturesFile =
            serde_json::from_str(V2_FIXTURES_JSON).expect("embedded fixtures parse");

        assert_eq!(
            to_hex(&SBTC_V2_NUMS_X_COORDINATE),
            parsed.v2_nums_x_coordinate_hex,
            "v2 NUMS x-coordinate drift between fixtures and core::SBTC_V2_NUMS_X_COORDINATE",
        );
        assert!(!parsed.fixtures.is_empty());

        for fixture in &parsed.fixtures {
            let name = &fixture.name;
            let signer_keys: Vec<[u8; 33]> = fixture
                .inputs
                .signer_keys_compressed_hex
                .iter()
                .map(|key| compressed_array(key))
                .collect();
            let key_set = SbtcSignerKeySet::from_registry(
                &signer_keys,
                u128::from(fixture.inputs.signatures_required),
            )
            .unwrap_or_else(|e| panic!("{name}: key set rejected: {e:?}"));

            let actual_keys: Vec<String> =
                key_set.xonly_keys().iter().map(|key| to_hex(key)).collect();
            assert_eq!(
                actual_keys, fixture.intermediate.derived_xonly_keys_sorted_hex,
                "{name}: derived signing keys"
            );
            assert_eq!(
                to_hex(key_set.signing_script().as_bytes()),
                fixture.intermediate.signing_script_hex,
                "{name}: signing_script"
            );
            assert_eq!(
                format!("5120{}", to_hex(&key_set.signer_utxo_output_key().unwrap())),
                fixture.intermediate.key_set_script_pubkey_hex,
                "{name}: signer UTXO scriptPubKey"
            );

            let recipient = PrincipalData::parse(&fixture.inputs.recipient_principal)
                .unwrap_or_else(|e| panic!("{name}: bad recipient principal: {e:?}"));
            let user_reclaim = hex_bytes(&fixture.inputs.reclaim_user_script_hex)
                .expect("fixture reclaim_user_script is valid hex");
            let lock_time =
                u16::try_from(fixture.inputs.lock_time).expect("fixture lock_time fits u16");

            let actual_deposit_script =
                build_v2_deposit_script(&key_set, &recipient, fixture.inputs.max_fee);
            let actual_reclaim_script = build_reclaim_script(lock_time, &user_reclaim);
            assert_eq!(
                to_hex(actual_deposit_script.as_bytes()),
                fixture.intermediate.deposit_script_hex,
                "{name}: deposit_script"
            );
            assert_eq!(
                to_hex(actual_reclaim_script.as_bytes()),
                fixture.intermediate.reclaim_script_hex,
                "{name}: reclaim_script"
            );

            let actual_deposit_leaf = tap_leaf_hash(actual_deposit_script.as_bytes());
            let actual_reclaim_leaf = tap_leaf_hash(actual_reclaim_script.as_bytes());
            assert_eq!(
                to_hex(&actual_deposit_leaf),
                fixture.intermediate.deposit_tapleaf_hash_hex,
                "{name}: deposit_tapleaf_hash"
            );
            assert_eq!(
                to_hex(&actual_reclaim_leaf),
                fixture.intermediate.reclaim_tapleaf_hash_hex,
                "{name}: reclaim_tapleaf_hash"
            );
            assert_eq!(
                to_hex(&tap_branch_hash(actual_deposit_leaf, actual_reclaim_leaf)),
                fixture.intermediate.merkle_root_hex,
                "{name}: merkle_root"
            );

            let actual_output_key = sbtc_v2_deposit_taproot_output_key(
                &key_set,
                &recipient,
                fixture.inputs.max_fee,
                lock_time,
                &user_reclaim,
            )
            .unwrap_or_else(|e| panic!("{name}: derivation failed: {e:?}"));
            assert_eq!(
                to_hex(&actual_output_key),
                fixture.intermediate.taproot_output_key_xonly_hex,
                "{name}: taproot_output_key"
            );
            assert_eq!(
                format!("5120{}", to_hex(&actual_output_key)),
                fixture.expected.script_pubkey_hex,
                "{name}: script_pubkey"
            );

            // Fixtures in the PoX-5 shape must also match the PoX-5 wrapper.
            if lock_time == u16::MAX && user_reclaim == [Opcode::OP_RETURN as u8] {
                let wrapper_output_key = sbtc_pox5_v2_deposit_taproot_output_key(
                    &key_set,
                    &recipient,
                    fixture.inputs.max_fee,
                )
                .unwrap_or_else(|e| panic!("{name}: PoX-5 wrapper failed: {e:?}"));
                assert_eq!(
                    wrapper_output_key, actual_output_key,
                    "{name}: PoX-5 wrapper"
                );
            }
        }
    }

    /// `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <commitment> OP_EQUALVERIFY`
    /// is 39 bytes; `<32>` is a one-byte data push (`01 20`), not
    /// `OP_PUSHNUM`. The commitment is a double SHA-256 of the deposit data,
    /// so the signers reveal a 32-byte preimage that `OP_SIZE` checks.
    #[test]
    fn v2_deposit_prefix_has_expected_wire_encoding() {
        let key_set = key_set_from_hex(&SBTC_RANDOM_SIGNER_KEYS, 1);
        let recipient = PrincipalData::parse("SP000000000000000000002Q6VF78").unwrap();
        let max_fee = 15_000;

        let data = deposit_data(&recipient, max_fee);
        assert_eq!(&data[..8], &max_fee.to_be_bytes());
        let preimage: [u8; 32] = Sha256::digest(&data).into();
        let commitment = v2_deposit_data_commitment(&recipient, max_fee);
        assert_eq!(commitment, <[u8; 32]>::from(Sha256::digest(preimage)));

        let mut expected_prefix = vec![0x82, 0x01, 0x20, 0x88, 0xa8, 0x20];
        expected_prefix.extend_from_slice(&commitment);
        expected_prefix.push(0x88);
        assert_eq!(expected_prefix.len(), 39);

        let script = build_v2_deposit_script(&key_set, &recipient, max_fee);
        assert_eq!(&script.as_bytes()[..39], &expected_prefix[..]);
        assert_eq!(
            &script.as_bytes()[39..],
            key_set.signing_script().as_bytes(),
            "the signing script follows the prefix unchanged"
        );
    }

    /// `<k_1> OP_CHECKSIG <k_2> OP_CHECKSIGADD ... <threshold> OP_NUMEQUAL`,
    /// with each key as a 32-byte push and the threshold as `OP_PUSHNUM_k`.
    #[test]
    fn signing_script_encodes_multi_a() {
        let key_set = key_set_from_hex(&SBTC_DEVENV_SIGNER_KEYS, 2);
        let keys = key_set.xonly_keys();
        assert_eq!(keys.len(), 3);

        let mut expected = vec![0x20];
        expected.extend_from_slice(&keys[0]);
        expected.push(Opcode::OP_CHECKSIG as u8);
        for key in &keys[1..] {
            expected.push(0x20);
            expected.extend_from_slice(key);
            expected.push(OP_CHECKSIGADD);
        }
        expected.push(Opcode::OP_PUSHNUM_2 as u8);
        expected.push(Opcode::OP_NUMEQUAL as u8);
        assert_eq!(key_set.signing_script().as_bytes(), &expected[..]);
    }

    /// Input order and duplicates do not affect the key set: keys are
    /// deduplicated and sorted bytewise (sBTC's `BTreeSet<XOnlyPublicKey>`).
    #[test]
    fn key_set_is_order_and_duplicate_independent() {
        let canonical = key_set_from_hex(&SBTC_DEVENV_SIGNER_KEYS, 2);
        let mut reversed = SBTC_DEVENV_SIGNER_KEYS.to_vec();
        reversed.reverse();
        reversed.push(SBTC_DEVENV_SIGNER_KEYS[0]);
        let shuffled = key_set_from_hex(&reversed, 2);
        assert_eq!(canonical, shuffled);
        assert_eq!(canonical.xonly_keys().len(), 3);
        assert!(
            canonical
                .xonly_keys()
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "keys are strictly ascending"
        );
        assert_eq!(canonical.signatures_required(), 2);
    }

    /// `1 <= distinct keys <= 16` and `1 <= threshold <= distinct keys`.
    #[test]
    fn key_set_bounds() {
        let seventeen = xonly_keys_from_small_scalars(17);

        assert!(SbtcSignerKeySet::new(vec![], 1).is_err(), "empty set");
        assert!(
            SbtcSignerKeySet::new(seventeen[..1].to_vec(), 0).is_err(),
            "zero threshold"
        );
        assert!(
            SbtcSignerKeySet::new(seventeen[..1].to_vec(), 2).is_err(),
            "threshold > n"
        );
        assert!(
            SbtcSignerKeySet::new(seventeen[..1].to_vec(), 1).is_ok(),
            "1-of-1"
        );
        assert!(
            SbtcSignerKeySet::new(seventeen[..16].to_vec(), 16).is_ok(),
            "16-of-16"
        );
        assert!(
            SbtcSignerKeySet::new(seventeen[..16].to_vec(), 17).is_err(),
            "17-of-16"
        );
        assert!(
            SbtcSignerKeySet::new(seventeen.clone(), 1).is_err(),
            "17 keys"
        );

        // Duplicates are collapsed before the bounds apply.
        let mut sixteen_plus_dup = seventeen[..16].to_vec();
        sixteen_plus_dup.push(seventeen[0]);
        let key_set = SbtcSignerKeySet::new(sixteen_plus_dup, 16).expect("16 distinct keys");
        assert_eq!(key_set.xonly_keys().len(), SBTC_V2_MAX_SIGNERS);

        // A 32-byte value that is not an x coordinate on the curve.
        assert!(
            SbtcSignerKeySet::new(vec![[0xff; 32]], 1).is_err(),
            "off-curve key"
        );
    }

    #[test]
    fn from_registry_rejects_malformed_inputs() {
        let devenv: Vec<[u8; 33]> = SBTC_DEVENV_SIGNER_KEYS
            .iter()
            .map(|key| compressed_array(key))
            .collect();
        assert!(
            SbtcSignerKeySet::from_registry(&[], 1).is_err(),
            "empty signer set"
        );
        assert!(
            SbtcSignerKeySet::from_registry(&devenv, 0).is_err(),
            "zero threshold"
        );
        assert!(
            SbtcSignerKeySet::from_registry(&devenv, 4).is_err(),
            "threshold > n"
        );
        assert!(
            SbtcSignerKeySet::from_registry(&devenv, u128::from(u16::MAX) + 1).is_err(),
            "threshold overflows u16"
        );
        let mut off_curve = [0xff; 33];
        off_curve[0] = 0x02;
        assert!(
            SbtcSignerKeySet::from_registry(&[off_curve], 1).is_err(),
            "off-curve registry key"
        );
        // A v2-rotated registry stores `0xFF || block-hash` in the aggregate
        // pubkey field; that value is never a valid signer key either.
        assert!(derive_sbtc_signing_xonly(&[0xff; 33]).is_err());
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
        (
            arb_valid_xonly_pubkey(),
            prop_oneof![Just(0x02u8), Just(0x03u8)],
        )
            .prop_map(|(xonly, prefix)| {
                let mut compressed = [0u8; 33];
                compressed[0] = prefix;
                compressed[1..].copy_from_slice(&xonly);
                compressed
            })
    }

    /// Standard principal (version < 32, arbitrary 20-byte hash).
    /// `version < 32` is enforced by the range, so construction is total.
    fn arb_standard_principal() -> impl Strategy<Value = StandardPrincipalData> {
        (0u8..32u8, any::<[u8; 20]>()).prop_map(|(version, bytes)| {
            StandardPrincipalData::new(version, bytes).expect("version < 32 by construction")
        })
    }

    /// Valid Clarity contract name spanning the full structural domain: a
    /// leading `[a-zA-Z]` followed by `0..CONTRACT_MAX_NAME_LENGTH` body chars
    /// from `[a-zA-Z0-9-_]`, for a total length of
    /// `1..=CONTRACT_MAX_NAME_LENGTH`.
    fn arb_contract_name() -> impl Strategy<Value = ContractName> {
        let lead = prop_oneof![b'a'..=b'z', b'A'..=b'Z'];
        let body = prop::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b'-'),
                Just(b'_')
            ],
            0..CONTRACT_MAX_NAME_LENGTH,
        );
        (lead, body).prop_map(|(lead, body)| {
            let mut s = String::with_capacity(1 + body.len());
            s.push(lead as char);
            for c in body {
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

    proptest! {
        /// `tap_branch_hash` lex-sorts its inputs (BIP-341), so it is
        /// commutative. Pins the sort directly: dropping or reversing it makes
        /// `H(a || b) != H(b || a)` for `a != b`, failing this property. The
        /// reference fixtures only exercise the sort when their two leaves
        /// happen to reorder, so this is the direct guard.
        #[tag(t_prop)]
        #[test]
        fn prop_tap_branch_hash_commutes(
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
        ) {
            prop_assert_eq!(tap_branch_hash(a, b), tap_branch_hash(b, a));
        }

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

        /// Two different aggregate signer pubkeys must produce different
        /// deposit addresses, with everything else fixed. The pubkey is pushed
        /// into the deposit leaf (`OP_PUSHBYTES_32 <x-only>`); a collision
        /// would let two distinct signer sets share one watched deposit
        /// address.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_distinct_by_pubkey(
            pubkey_a in arb_valid_xonly_pubkey(),
            pubkey_b in arb_valid_xonly_pubkey(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            prop_assume!(pubkey_a != pubkey_b);
            let key_a = sbtc_deposit_taproot_output_key(
                &pubkey_a, &recipient, max_fee, lock_time, &user_reclaim,
            ).expect("valid");
            let key_b = sbtc_deposit_taproot_output_key(
                &pubkey_b, &recipient, max_fee, lock_time, &user_reclaim,
            ).expect("valid");
            prop_assert_ne!(key_a, key_b);
        }

        /// Two different reclaim `lock_time` values must produce different
        /// deposit addresses, with everything else fixed. `lock_time` is
        /// CScriptNum-encoded into the reclaim leaf (`<lock_time> OP_CSV …`);
        /// a collision would let the timelock change without moving the
        /// watched address.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_distinct_by_lock_time(
            pubkey_xonly in arb_valid_xonly_pubkey(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time_a in any::<u16>(),
            lock_time_b in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            prop_assume!(lock_time_a != lock_time_b);
            let key_a = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time_a, &user_reclaim,
            ).expect("valid");
            let key_b = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time_b, &user_reclaim,
            ).expect("valid");
            prop_assert_ne!(key_a, key_b);
        }

        /// Two different user-supplied reclaim scripts must produce different
        /// deposit addresses, with everything else fixed. The user bytes are
        /// appended into the reclaim leaf (`… OP_CSV <user bytes>`); a
        /// collision would let the reclaim spend path change without moving
        /// the watched address.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_distinct_by_user_reclaim_script(
            pubkey_xonly in arb_valid_xonly_pubkey(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim_a in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
            user_reclaim_b in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            prop_assume!(user_reclaim_a != user_reclaim_b);
            let key_a = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time, &user_reclaim_a,
            ).expect("valid");
            let key_b = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time, &user_reclaim_b,
            ).expect("valid");
            prop_assert_ne!(key_a, key_b);
        }

        /// An x-only input that is not a valid secp256k1 point must be
        /// rejected with `Err`, never a panic. The derivation validates the
        /// pubkey on-curve before any script work, so an off-curve key can
        /// never produce a deposit address. The `prop_filter` keeps only
        /// off-curve inputs; the happy path (valid key → Ok) is covered by
        /// `prop_sbtc_key_deterministic`.
        #[tag(t_prop)]
        #[test]
        fn prop_sbtc_key_off_curve_pubkey_rejected(
            pubkey_xonly in any::<[u8; 32]>().prop_filter(
                "off-curve x-only only",
                |b| XOnlyPublicKey::from_slice(b).is_err(),
            ),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            let result = sbtc_deposit_taproot_output_key(
                &pubkey_xonly, &recipient, max_fee, lock_time, &user_reclaim,
            );
            prop_assert!(result.is_err(), "off-curve x-only must be rejected, got Ok");
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

    /// A registry signer set: 1..=16 distinct compressed keys and a threshold
    /// in `1..=n`. Random keys collide with probability ~2^-256, so the
    /// threshold is still clamped to the distinct count for total correctness.
    fn arb_v2_registry_signer_set() -> impl Strategy<Value = (Vec<[u8; 33]>, u16)> {
        prop::collection::vec(arb_valid_compressed_pubkey_33(), 1..=SBTC_V2_MAX_SIGNERS)
            .prop_flat_map(|keys| {
                let distinct = keys.iter().collect::<BTreeSet<_>>().len() as u16;
                (Just(keys), 1..=distinct)
            })
    }

    fn v2_pox5_key(
        keys: &[[u8; 33]],
        threshold: u16,
        recipient: &PrincipalData,
        max_fee: u64,
    ) -> [u8; 32] {
        let key_set = SbtcSignerKeySet::from_registry(keys, u128::from(threshold))
            .expect("valid registry signer set");
        sbtc_pox5_v2_deposit_taproot_output_key(&key_set, recipient, max_fee)
            .expect("valid key set derives")
    }

    proptest! {
        /// Registry key order does not affect the recipient: the key set is
        /// sorted and deduplicated, as in sBTC.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_independent_of_registry_order(
            (keys, shuffled, threshold) in arb_v2_registry_signer_set().prop_flat_map(
                |(keys, threshold)| (Just(keys.clone()), Just(keys).prop_shuffle(), Just(threshold))
            ),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assert_eq!(
                v2_pox5_key(&keys, threshold, &recipient, max_fee),
                v2_pox5_key(&shuffled, threshold, &recipient, max_fee),
            );
        }

        /// Derivation is a pure function of its inputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_deterministic(
            (keys, threshold) in arb_v2_registry_signer_set(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
            lock_time in any::<u16>(),
            user_reclaim in prop::collection::vec(any::<u8>(), 0..=MAX_USER_RECLAIM_SCRIPT_LEN),
        ) {
            let key_set = SbtcSignerKeySet::from_registry(&keys, u128::from(threshold))
                .expect("valid registry signer set");
            let key1 = sbtc_v2_deposit_taproot_output_key(
                &key_set, &recipient, max_fee, lock_time, &user_reclaim,
            ).expect("derives");
            let key2 = sbtc_v2_deposit_taproot_output_key(
                &key_set, &recipient, max_fee, lock_time, &user_reclaim,
            ).expect("derives");
            prop_assert_eq!(key1, key2);
        }

        /// Different thresholds over the same keys lock different outputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_threshold(
            (keys, threshold_a) in arb_v2_registry_signer_set(),
            threshold_b in 1..=SBTC_V2_MAX_SIGNERS as u16,
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            let distinct = keys.iter().collect::<BTreeSet<_>>().len() as u16;
            prop_assume!(threshold_b <= distinct && threshold_a != threshold_b);
            prop_assert_ne!(
                v2_pox5_key(&keys, threshold_a, &recipient, max_fee),
                v2_pox5_key(&keys, threshold_b, &recipient, max_fee),
            );
        }

        /// Different recipients lock different outputs: the commitment binds
        /// the recipient principal.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_recipient(
            (keys, threshold) in arb_v2_registry_signer_set(),
            recipient_a in arb_principal_data(),
            recipient_b in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assume!(recipient_a != recipient_b);
            prop_assert_ne!(
                v2_pox5_key(&keys, threshold, &recipient_a, max_fee),
                v2_pox5_key(&keys, threshold, &recipient_b, max_fee),
            );
        }

        /// Different max fees lock different outputs: the commitment binds
        /// the max fee.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_max_fee(
            (keys, threshold) in arb_v2_registry_signer_set(),
            recipient in arb_principal_data(),
            max_fee_a in any::<u64>(),
            max_fee_b in any::<u64>(),
        ) {
            prop_assume!(max_fee_a != max_fee_b);
            prop_assert_ne!(
                v2_pox5_key(&keys, threshold, &recipient, max_fee_a),
                v2_pox5_key(&keys, threshold, &recipient, max_fee_b),
            );
        }

        /// A key set with one extra signer locks a different output.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_signer_set(
            (keys, threshold) in arb_v2_registry_signer_set(),
            extra in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assume!(keys.len() < SBTC_V2_MAX_SIGNERS && !keys.contains(&extra));
            let mut extended = keys.clone();
            extended.push(extra);
            prop_assert_ne!(
                v2_pox5_key(&keys, threshold, &recipient, max_fee),
                v2_pox5_key(&extended, threshold, &recipient, max_fee),
            );
        }

        /// The v2 PoX-5 wrapper is an exact specialization of the generic
        /// derivation with `lock_time = u16::MAX` and `[OP_RETURN]`.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_pox5_wrapper_matches_generic(
            (keys, threshold) in arb_v2_registry_signer_set(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            let key_set = SbtcSignerKeySet::from_registry(&keys, u128::from(threshold))
                .expect("valid registry signer set");
            let wrapper = sbtc_pox5_v2_deposit_taproot_output_key(&key_set, &recipient, max_fee)
                .expect("derives");
            let generic = sbtc_v2_deposit_taproot_output_key(
                &key_set,
                &recipient,
                max_fee,
                u16::MAX,
                &[Opcode::OP_RETURN as u8],
            ).expect("derives");
            prop_assert_eq!(wrapper, generic);
        }

        /// Even a single-signer v2 deposit never collides with the v1 deposit
        /// for the same signer, recipient and fee: the leaf format and the
        /// internal key both differ, so the epoch switch always moves funds
        /// to a new address.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_differs_from_v1(
            key in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            let v1 = sbtc_pox5_deposit_taproot_output_key(&key, &recipient, max_fee)
                .expect("valid pubkey");
            let v2 = v2_pox5_key(&[key], 1, &recipient, max_fee);
            prop_assert_ne!(v1, v2);
        }
    }
}
