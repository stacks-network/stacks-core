// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! sBTC P2TR (taproot) deposit-script derivation for the PoX-5 waterfall.
//!
//! The per-cycle sBTC recipient is a witness-v1 P2TR output committing to a
//! script tree with two leaves:
//!
//! * **deposit**: `<deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-pubkey> OP_CHECKSIG`
//!   where `<deposit-data> = <max-fee:u64-be> || <consensus-encoded recipient principal>`
//!   and `<x-only-pubkey>` is the aggregate signer key from `pox-5`.
//! * **reclaim**: `u16::MAX OP_CSV OP_RETURN`. The `OP_RETURN` makes the
//!   leaf unspendable; the reclaim path exists only as a structural
//!   placeholder in the tree.
//!
//! The taproot internal key is the BIP-0341 NUMS x-coordinate (no known
//! discrete logarithm), so neither path can be spent via key-path; only the
//! deposit leaf, signed by the aggregate key, is reachable.
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
/// recipient, given the aggregate signer's compressed (33-byte) pubkey, the
/// recipient principal, and the deposit-data max-fee value.
///
/// The internal taproot key is the BIP-0341 NUMS coordinate; the script
/// tree has two leaves at depth 1 (`deposit`, `reclaim`). Callers wrap the
/// returned bytes as `PoxAddress::Addr32(.., P2TR, output_key)`.
pub fn sbtc_deposit_taproot_output_key(
    aggregate_pubkey_compressed: &[u8; 33],
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Result<[u8; 32], ChainstateError> {
    // Drop the compression flag → 32-byte x-only.
    let aggregate_xonly = XOnlyPublicKey::from_slice(&aggregate_pubkey_compressed[1..])
        .map_err(|_| ChainstateError::Expects("aggregate pubkey not on curve".into()))?;
    let internal_key = XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE)
        .expect("NUMS_X_COORDINATE is a valid x-only pubkey");

    let deposit_script = build_deposit_script(&aggregate_xonly, recipient, max_fee_sats);
    let reclaim_script = build_reclaim_script();

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

/// Convenience wrapper around `sbtc_deposit_taproot_output_key` that returns
/// the full 34-byte witness-v1 scriptPubKey (`OP_1 OP_PUSHBYTES_32 <key>`).
/// Currently unused outside of tests but kept for symmetry / future use.
#[cfg(any(test, feature = "testing"))]
pub fn sbtc_deposit_script_pubkey(
    aggregate_pubkey_compressed: &[u8; 33],
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Result<ScriptBuf, ChainstateError> {
    use bitcoin::key::TweakedPublicKey;
    let key_bytes =
        sbtc_deposit_taproot_output_key(aggregate_pubkey_compressed, recipient, max_fee_sats)?;
    let xonly = XOnlyPublicKey::from_slice(&key_bytes)
        .expect("output key from taproot finalize is a valid x-only pubkey");
    Ok(ScriptBuf::new_p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(xonly),
    ))
}

/// `u16::MAX OP_CSV OP_RETURN` — the `OP_RETURN` makes the script
/// unspendable; the leaf only exists to populate the script tree.
fn build_reclaim_script() -> ScriptBuf {
    Builder::new()
        .push_int(u16::MAX as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_RETURN)
        .into_script()
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
