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
//! script tree with two leaves:
//!
//! * **deposit**: `<deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-pubkey> OP_CHECKSIG`
//!   where `<deposit-data> = <max-fee:u64-be> || <consensus-encoded recipient principal>`.
//! * **reclaim**: `<lock_time push> OP_CSV <user-supplied-bytes>`. For PoX-5
//!   scaffolding we use `lock_time = u16::MAX` and `[OP_RETURN]` as the
//!   user-supplied bytes — that disables the reclaim path entirely.
//!
//! The taproot internal key is the BIP-0341 NUMS x-coordinate (no known
//! discrete logarithm), so neither leaf is reachable via key-path; only via
//! script-path through the two leaves.
//!
//! This module imports `bitcoin::secp256k1` directly rather than going
//! through the project's `Secp256k1PublicKey` wrapper. That's a deliberate
//! exception — the `bitcoin` crate's taproot helpers consume types from its
//! own `secp256k1` re-export, and keeping the boundary here avoids leaking
//! the second `secp256k1` version into the rest of the codebase.

use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_RETURN};
use bitcoin::script::{Builder, PushBytesBuf, ScriptBuf};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TaprootBuilder;
use clarity::vm::types::PrincipalData;
use stacks_common::codec::StacksMessageCodec;

use crate::chainstate::stacks::Error as ChainstateError;
use crate::core::NUMS_X_COORDINATE;

/// Compute the 32-byte witness-v1 P2TR output key for an sBTC deposit
/// recipient, given the aggregate signer's x-only (32-byte) pubkey, the
/// recipient principal, the deposit-data max-fee value, the reclaim
/// script's CSV lock_time, and the user-supplied bytes appended after
/// `OP_CSV` in the reclaim script.
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
    let aggregate_xonly = XOnlyPublicKey::from_slice(aggregate_pubkey_xonly)
        .map_err(|_| ChainstateError::Expects("aggregate pubkey not on curve".into()))?;
    let internal_key = XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE)
        .expect("NUMS_X_COORDINATE is a valid x-only pubkey");

    let deposit_script = build_deposit_script(&aggregate_xonly, recipient, max_fee_sats);
    let reclaim_script = build_reclaim_script(lock_time, user_reclaim_script);

    let secp = Secp256k1::verification_only();
    let spend_info = TaprootBuilder::new()
        .add_leaf(1, deposit_script)
        .map_err(|e| ChainstateError::Expects(format!("taproot add_leaf (deposit): {e:?}")))?
        .add_leaf(1, reclaim_script)
        .map_err(|e| ChainstateError::Expects(format!("taproot add_leaf (reclaim): {e:?}")))?
        .finalize(&secp, internal_key)
        .map_err(|_| ChainstateError::Expects("taproot finalize failed".into()))?;

    Ok(spend_info.output_key().serialize())
}

/// Pox-5 scaffolding wrapper around `sbtc_deposit_taproot_output_key`.
/// Bakes in the values the PoX-5 reward-set computation uses today
/// (`lock_time = u16::MAX`, user-script `[OP_RETURN]`) and accepts the
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
        &[OP_RETURN.to_u8()],
    )
}

/// `<deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-pubkey> OP_CHECKSIG`
fn build_deposit_script(
    aggregate_xonly: &XOnlyPublicKey,
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> ScriptBuf {
    let mut deposit_data = max_fee_sats.to_be_bytes().to_vec();
    let mut principal_bytes = vec![];
    recipient
        .consensus_serialize(&mut principal_bytes)
        .expect("PrincipalData consensus_serialize is infallible to in-memory writer");
    deposit_data.extend_from_slice(&principal_bytes);

    let push_data =
        PushBytesBuf::try_from(deposit_data).expect("deposit data is within bitcoin push limits");

    Builder::new()
        .push_slice(&push_data)
        .push_opcode(OP_DROP)
        .push_slice(aggregate_xonly.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// `<lock_time push> OP_CSV <user_reclaim_script bytes>`. The user bytes
/// are appended raw — they're presumed to be valid bitcoin script chosen
/// by the caller (not parsed or validated here).
///
/// `lock_time` is widened from `u16` to `i64` for the CScriptNum encoding;
/// `Builder::push_int` then chooses the minimal encoding (e.g.,
/// `OP_PUSHNUM_6` for 6, `OP_PUSHBYTES_3 0xFF 0xFF 0x00` for `u16::MAX`).
fn build_reclaim_script(lock_time: u16, user_reclaim_script: &[u8]) -> ScriptBuf {
    let mut bytes = Builder::new()
        .push_int(i64::from(lock_time))
        .push_opcode(OP_CSV)
        .into_script()
        .into_bytes();
    bytes.extend_from_slice(user_reclaim_script);
    ScriptBuf::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use clarity::vm::types::PrincipalData;
    use stacks_common::util::hash::{hex_bytes, to_hex};

    use super::*;

    /// One reference fixture: a set of inputs and the expected outputs at
    /// every step of the derivation. Sourced from a known-good external
    /// implementation.
    struct SbtcFixture {
        name: &'static str,
        // inputs
        signers_pubkey_xonly_hex: &'static str,
        recipient_principal: &'static str,
        max_fee: u64,
        /// sBTC's spec defines the CSV `lock_time` as a `u16` that is
        /// widened to `i64` and CScriptNum-encoded. Inputs from upstream
        /// fixtures may be wider integers; truncate to `u16` at the API
        /// boundary, which is what the helper itself accepts.
        lock_time: u16,
        reclaim_user_script_hex: &'static str,
        // intermediates (expected)
        deposit_script_hex: &'static str,
        deposit_tapleaf_hash_hex: &'static str,
        reclaim_script_hex: &'static str,
        reclaim_tapleaf_hash_hex: &'static str,
        merkle_root_hex: &'static str,
        output_key_xonly_hex: &'static str,
        // final output (expected)
        script_pubkey_hex: &'static str,
    }

    const FIXTURES: &[SbtcFixture] = &[
        SbtcFixture {
            name: "standard_mainnet_recipient_simple_reclaim",
            signers_pubkey_xonly_hex:
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            recipient_principal: "SP000000000000000000002Q6VF78",
            max_fee: 15_000,
            lock_time: 6,
            reclaim_user_script_hex: "",
            deposit_script_hex:
                "1e0000000000003a9805160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
            deposit_tapleaf_hash_hex:
                "62ff1e284841c8b5655ffe1e1e5815eac12cb498d38b6f3b2d638a1c15648158",
            reclaim_script_hex: "56b2",
            reclaim_tapleaf_hash_hex:
                "4b49f80fd3b1a30785b34bc7f0aa362a5a22aa4cc1ef0570489efec975526d28",
            merkle_root_hex:
                "f242112a4a0a232d5a77a6b100ca75054b76b2c8745ce5ee6ca0bf8ed33d9c88",
            output_key_xonly_hex:
                "3a900085e4603715fd25abda9299a4989a9f94a490f0d6f1892bc8a1c6babf1a",
            script_pubkey_hex:
                "51203a900085e4603715fd25abda9299a4989a9f94a490f0d6f1892bc8a1c6babf1a",
        },
        SbtcFixture {
            name: "standard_testnet_recipient_simple_reclaim",
            signers_pubkey_xonly_hex:
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            recipient_principal: "ST000000000000000000002AMW42H",
            max_fee: 100_000_000,
            lock_time: 144,
            reclaim_user_script_hex: "",
            deposit_script_hex:
                "1e0000000005f5e100051a00000000000000000000000000000000000000007520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
            deposit_tapleaf_hash_hex:
                "1110862072f1eb0877efaf240d5f2e8e3a524c6e53561d8baccb61fa674d2852",
            reclaim_script_hex: "029000b2",
            reclaim_tapleaf_hash_hex:
                "454bd4c344b99a80a157d5e97bd0526d1fb12d26411f3fab1c49747e0bf1ed4b",
            merkle_root_hex:
                "d2d9a9b96c0881bc199a686662a49ffc71d9eed5a71716f1023297dc791f0dcf",
            output_key_xonly_hex:
                "6601c757b0f7d2e5cfb45a938be833c17afbea7f6d5f8b293b454d3563008ba0",
            script_pubkey_hex:
                "51206601c757b0f7d2e5cfb45a938be833c17afbea7f6d5f8b293b454d3563008ba0",
        },
        SbtcFixture {
            name: "contract_recipient_short_name",
            signers_pubkey_xonly_hex:
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            recipient_principal: "ST000000000000000000002AMW42H.my-contract",
            max_fee: 0,
            lock_time: 1024,
            reclaim_user_script_hex: "75",
            deposit_script_hex:
                "2a0000000000000000061a00000000000000000000000000000000000000000b6d792d636f6e7472616374752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
            deposit_tapleaf_hash_hex:
                "a943750ad40e7cf2c822c4589ad5da847bcc52083bb78488b945ae23a93b713d",
            reclaim_script_hex: "020004b275",
            reclaim_tapleaf_hash_hex:
                "6e72448b2a47baf78970c0d5a3b57f414f0d7498572da1cc4bbd56de44335822",
            merkle_root_hex:
                "50e71558eb44d8c6cece84a81fe8abf70d0bcdd2482b2a6d166ed14d1d37d02a",
            output_key_xonly_hex:
                "b2e483a39cc83c83ed0e0ae613ae2443b5d4bfa554c6d3752301ffeb2669fd9b",
            script_pubkey_hex:
                "5120b2e483a39cc83c83ed0e0ae613ae2443b5d4bfa554c6d3752301ffeb2669fd9b",
        },
        SbtcFixture {
            name: "contract_recipient_long_name_pushdata1",
            signers_pubkey_xonly_hex:
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            recipient_principal:
                "ST000000000000000000002AMW42H.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            max_fee: 1_234_567,
            lock_time: 65_535,
            reclaim_user_script_hex:
                "20000000000000000000000000000000000000000000000000000000000000000075",
            deposit_script_hex:
                "47000000000012d687061a000000000000000000000000000000000000000028616161616161616161616161616161616161616161616161616161616161616161616161616161617520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
            deposit_tapleaf_hash_hex:
                "05b21b1cf20c3bff18c61e667a35bdf320d84a68a7c93f2174518923e3b00ce8",
            reclaim_script_hex:
                "03ffff00b220000000000000000000000000000000000000000000000000000000000000000075",
            reclaim_tapleaf_hash_hex:
                "c92bbca25a0644acce8f214e24a837544e5ef29d8304184858a915de30cc8f2c",
            merkle_root_hex:
                "bce95b41e7caa60ee8beb29d1cd1eee251e4cbe595af2d4afc729c6f02d4b779",
            output_key_xonly_hex:
                "7796ada72f5f892234230446bef7c897b638bead6479b1adbdb6c3542a2326ed",
            script_pubkey_hex:
                "51207796ada72f5f892234230446bef7c897b638bead6479b1adbdb6c3542a2326ed",
        },
        SbtcFixture {
            name: "high_lock_time_with_user_script",
            signers_pubkey_xonly_hex:
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            recipient_principal: "SP000000000000000000002Q6VF78",
            max_fee: 42,
            // sBTC fixture json has `lock_time: 4194303` but truncates to u16
            // before encoding (= 65535).
            lock_time: 4_194_303_u32 as u16,
            reclaim_user_script_hex: "02abcd87",
            deposit_script_hex:
                "1e000000000000002a05160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
            deposit_tapleaf_hash_hex:
                "257bdae7d9e24d8abcaec346878f63b0418c7ae6dda627cff38dea37bb341100",
            reclaim_script_hex: "03ffff00b202abcd87",
            reclaim_tapleaf_hash_hex:
                "b748b56a4e5a77c7ed2e39068620bc5872d2840e0f0182d215061a9d50e71967",
            merkle_root_hex:
                "de9b211ae7e18e1879140418a2d94d8fe62ed568d451f54fcb8d18a7afa96ab9",
            output_key_xonly_hex:
                "fd5e38a5c16f1e3df25ec70051b8eb1de1da880956c4e6181b64f1b30234fd22",
            script_pubkey_hex:
                "5120fd5e38a5c16f1e3df25ec70051b8eb1de1da880956c4e6181b64f1b30234fd22",
        },
    ];

    fn xonly_array(hex_str: &str) -> [u8; 32] {
        hex_bytes(hex_str)
            .expect("fixture pubkey is valid hex")
            .try_into()
            .expect("fixture pubkey is 32 bytes")
    }

    #[test]
    fn matches_sbtc_reference_fixtures() {
        for fixture in FIXTURES {
            let pubkey_xonly = xonly_array(fixture.signers_pubkey_xonly_hex);
            let recipient = PrincipalData::parse(fixture.recipient_principal).unwrap_or_else(|e| {
                panic!(
                    "{}: failed to parse recipient principal {:?}: {e:?}",
                    fixture.name, fixture.recipient_principal,
                )
            });
            let user_reclaim = hex_bytes(fixture.reclaim_user_script_hex)
                .expect("fixture reclaim_user_script is valid hex");

            let actual_output_key = sbtc_deposit_taproot_output_key(
                &pubkey_xonly,
                &recipient,
                fixture.max_fee,
                fixture.lock_time,
                &user_reclaim,
            )
            .unwrap_or_else(|e| panic!("{}: derivation failed: {e:?}", fixture.name));

            let as_xonly = XOnlyPublicKey::from_slice(&pubkey_xonly)
                .unwrap_or_else(|e| panic!("{}: x-only pubkey parse failed: {e:?}", fixture.name));
            let actual_deposit_script =
                build_deposit_script(&as_xonly, &recipient, fixture.max_fee);
            let actual_reclaim_script = build_reclaim_script(fixture.lock_time, &user_reclaim);

            assert_eq!(
                to_hex(actual_deposit_script.as_bytes()),
                fixture.deposit_script_hex,
                "{}: deposit_script",
                fixture.name,
            );
            assert_eq!(
                to_hex(actual_reclaim_script.as_bytes()),
                fixture.reclaim_script_hex,
                "{}: reclaim_script",
                fixture.name,
            );
            assert_eq!(
                to_hex(&actual_output_key),
                fixture.output_key_xonly_hex,
                "{}: output_key",
                fixture.name,
            );
        }
    }
}
