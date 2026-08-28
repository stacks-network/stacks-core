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

//! Signature-verification tests shared by the native and wasm backends.
//!
//! Run the wasm tests with:
//!
//! ```text
//! cd stacks-codec && wasm-pack test --node --features wasm-web
//! ```
//!
//! The vectors are deterministic so failures are reproducible.

#![cfg(test)]

use clarity_types::representations::{ClarityName, ContractName};
use clarity_types::types::{PrincipalData, StandardPrincipalData, Value};
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
#[cfg(target_family = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use crate::strings::StacksString;
use crate::transaction::{
    StacksTransaction, TokenTransferMemo, TransactionAuth, TransactionAuthVerificationMode,
    TransactionContractCall, TransactionPayload, TransactionSmartContract,
    TransactionSpendingCondition, TransactionVersion,
};

/// Enough keys to exercise multiple recovery IDs.
const KEY_COUNT: u8 = 12;

/// Deterministic signing key `i`.
fn key(i: u8) -> StacksPrivateKey {
    let bytes = Sha512Trunc256Sum::from_data(&[b'v', b'e', b'r', b'i', b'f', b'y', i]);
    StacksPrivateKey::from_slice(bytes.as_bytes())
        .expect("BUG: hashed key material is not a valid secp256k1 scalar")
}

fn compressed_key(i: u8) -> StacksPrivateKey {
    let mut k = key(i);
    k.set_compress_public(true);
    k
}

fn uncompressed_key(i: u8) -> StacksPrivateKey {
    let mut k = key(i);
    k.set_compress_public(false);
    k
}

/// Payloads that produce distinct initial sighashes.
fn payloads() -> Vec<(&'static str, TransactionPayload)> {
    vec![
        (
            "token-transfer",
            TransactionPayload::TokenTransfer(
                PrincipalData::Standard(StandardPrincipalData::transient()),
                12_345,
                TokenTransferMemo([0x42; 34]),
            ),
        ),
        (
            "contract-call",
            TransactionPayload::ContractCall(TransactionContractCall {
                address: StacksAddress::new(1, Hash160([0xab; 20])).unwrap(),
                contract_name: ContractName::try_from("verify-target").unwrap(),
                function_name: ClarityName::try_from("do-thing").unwrap(),
                function_args: vec![Value::Int(-7), Value::UInt(7)],
            }),
        ),
        (
            "smart-contract",
            TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("verify-deploy").unwrap(),
                    code_body: StacksString::from_str("(define-read-only (f) u1)").unwrap(),
                },
                None,
            ),
        ),
    ]
}

/// Build and fully sign a single-signature transaction.
fn signed_singlesig(
    auth: TransactionAuth,
    privk: &StacksPrivateKey,
    version: TransactionVersion,
    payload: TransactionPayload,
    nonce: u64,
) -> StacksTransaction {
    let mut tx = StacksTransaction::new(version, auth, payload);
    tx.set_tx_fee(180 + nonce);
    tx.set_origin_nonce(nonce);
    tx.sign_next_origin(&tx.sign_begin(), privk)
        .expect("BUG: failed to sign the origin");
    tx
}

/// Single-signature transaction vectors.
fn singlesig_vectors() -> Vec<(String, StacksTransaction)> {
    let mut out = vec![];

    for i in 0..KEY_COUNT {
        for (payload_name, payload) in payloads() {
            let version = if i % 2 == 0 {
                TransactionVersion::Testnet
            } else {
                TransactionVersion::Mainnet
            };

            // The common client-generated shape.
            let privk = compressed_key(i);
            out.push((
                format!("p2pkh-compressed/{payload_name}/key{i}"),
                signed_singlesig(
                    TransactionAuth::from_p2pkh(&privk).unwrap(),
                    &privk,
                    version,
                    payload.clone(),
                    i as u64,
                ),
            ));

            // Exercise the uncompressed-key branch.
            let privk = uncompressed_key(i);
            out.push((
                format!("p2pkh-uncompressed/{payload_name}/key{i}"),
                signed_singlesig(
                    TransactionAuth::from_p2pkh(&privk).unwrap(),
                    &privk,
                    version,
                    payload.clone(),
                    i as u64,
                ),
            ));

            // Exercise the segwit-style hash mode.
            let privk = compressed_key(i);
            out.push((
                format!("p2wpkh/{payload_name}/key{i}"),
                signed_singlesig(
                    TransactionAuth::from_p2wpkh(&privk).unwrap(),
                    &privk,
                    version,
                    payload.clone(),
                    i as u64,
                ),
            ));
        }
    }

    out
}

/// Ordered 2-of-3 multisig vectors exercise rolling signature hashes.
fn multisig_vectors() -> Vec<(String, StacksTransaction)> {
    let mut out = vec![];

    for i in 0..KEY_COUNT {
        let signers = [compressed_key(i), compressed_key(i + 40)];
        let spectator = compressed_key(i + 80);
        let all = [signers[0].clone(), signers[1].clone(), spectator.clone()];

        for (payload_name, payload) in payloads() {
            for (shape, auth) in [
                ("p2sh", TransactionAuth::from_p2sh(&all, 2).unwrap()),
                ("p2wsh", TransactionAuth::from_p2wsh(&all, 2).unwrap()),
            ] {
                let mut tx =
                    StacksTransaction::new(TransactionVersion::Testnet, auth, payload.clone());
                tx.set_tx_fee(300);
                tx.set_origin_nonce(i as u64);

                let mut sighash = tx.sign_begin();
                for privk in &signers {
                    sighash = tx
                        .sign_next_origin(&sighash, privk)
                        .expect("BUG: failed to add a multisig signature");
                }
                // The third participant contributes only its public key.
                tx.append_next_origin(&StacksPublicKey::from_private(&spectator))
                    .expect("BUG: failed to append the trailing public key");

                out.push((format!("multisig-{shape}-2of3/{payload_name}/key{i}"), tx));
            }
        }
    }

    out
}

/// Sponsored vectors exercise origin and sponsor verification.
fn sponsored_vectors() -> Vec<(String, StacksTransaction)> {
    let mut out = vec![];

    for i in 0..KEY_COUNT {
        let origin = compressed_key(i);
        let sponsor = compressed_key(i + 120);

        for (payload_name, payload) in payloads() {
            let auth = TransactionAuth::from_p2pkh(&origin)
                .unwrap()
                .into_sponsored(TransactionAuth::from_p2pkh(&sponsor).unwrap())
                .unwrap();

            let mut tx = StacksTransaction::new(TransactionVersion::Mainnet, auth, payload);
            tx.set_tx_fee(240);
            tx.set_origin_nonce(i as u64);
            tx.set_sponsor_nonce(u64::from(i) + 1).unwrap();

            let origin_sighash = tx
                .sign_next_origin(&tx.sign_begin(), &origin)
                .expect("BUG: failed to sign the origin");
            tx.sign_next_sponsor(&origin_sighash, &sponsor)
                .expect("BUG: failed to sign the sponsor");

            out.push((format!("sponsored-p2pkh/{payload_name}/key{i}"), tx));
        }
    }

    out
}

fn all_vectors() -> Vec<(String, StacksTransaction)> {
    let mut out = singlesig_vectors();
    out.extend(multisig_vectors());
    out.extend(sponsored_vectors());
    out
}

/// Correctly signed transactions verify.
#[test]
fn correctly_signed_transactions_verify() {
    let vectors = all_vectors();
    assert!(
        vectors.len() >= 100,
        "the vector set collapsed to {} cases; a shrinking suite silently \
         stops covering recovery ids",
        vectors.len()
    );

    let mut failures = vec![];
    for (name, tx) in &vectors {
        if let Err(e) = tx.verify(TransactionAuthVerificationMode::EnforceLowS) {
            failures.push(format!("{name}: {e}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} correctly signed transactions failed to verify.\nFirst 5:\n  {}",
        failures.len(),
        vectors.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// `AllowHighS` uses a separate recovery entry point.
#[test]
fn correctly_signed_transactions_verify_allowing_high_s() {
    let vectors = all_vectors();
    let mut failures = vec![];
    for (name, tx) in &vectors {
        if let Err(e) = tx.verify(TransactionAuthVerificationMode::AllowHighS) {
            failures.push(format!("{name}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} transactions failed to verify under AllowHighS.\nFirst 5:\n  {}",
        failures.len(),
        vectors.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// Ensure the deterministic vectors cover multiple recovery IDs.
#[test]
fn vectors_cover_multiple_recovery_ids() {
    let mut seen = [0usize; 256];
    for (_, tx) in singlesig_vectors() {
        if let TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(ref data)) =
            tx.auth
        {
            // Byte 0 of a `MessageSignature` is the recovery id.
            seen[data.signature.as_bytes()[0] as usize] += 1;
        }
    }

    let distinct = seen.iter().filter(|c| **c > 0).count();
    assert!(
        distinct >= 2,
        "the vectors only produced {distinct} distinct recovery id(s): {:?}. \
         A byte-order bug can pass for one and fail for another, so the suite \
         must span at least two.",
        seen.iter()
            .enumerate()
            .filter(|(_, c)| **c > 0)
            .map(|(id, c)| (id, *c))
            .collect::<Vec<_>>()
    );
}

/// Verification rejects changes to signed fields.
#[test]
fn tampered_transactions_do_not_verify() {
    for (name, tx) in all_vectors() {
        for (what, mut tampered) in [("nonce", tx.clone()), ("fee", tx.clone())] {
            match what {
                "nonce" => tampered.set_origin_nonce(tx.get_origin_nonce() ^ 0xff),
                _ => tampered.set_tx_fee(tx.get_tx_fee() + 1),
            }

            assert!(
                tampered
                    .verify(TransactionAuthVerificationMode::EnforceLowS)
                    .is_err(),
                "{name}: verification accepted a transaction with a tampered {what}"
            );
        }
    }
}

/// High-S signatures are accepted only when explicitly allowed.
#[test]
fn high_s_signatures_are_rejected_only_when_enforcing_low_s() {
    for (name, tx) in singlesig_vectors() {
        let high_s = tx.with_negated_s_in_signature();

        assert!(
            high_s
                .verify(TransactionAuthVerificationMode::EnforceLowS)
                .is_err(),
            "{name}: a high-S signature was accepted under EnforceLowS"
        );
        assert!(
            high_s
                .verify(TransactionAuthVerificationMode::AllowHighS)
                .is_ok(),
            "{name}: a high-S signature was rejected under AllowHighS"
        );
    }
}

/// Directly exercise the recovery function fixed by this change.
#[test]
fn recovering_a_public_key_round_trips() {
    use stacks_common::types::PrivateKey;

    let mut failures = vec![];
    for i in 0..KEY_COUNT {
        let privk = compressed_key(i);
        let expected = StacksPublicKey::from_private(&privk);
        let sighash = Sha512Trunc256Sum::from_data(&[b'm', b's', b'g', i]);

        let sig: MessageSignature = privk
            .sign(sighash.as_bytes())
            .expect("BUG: failed to sign a 32-byte hash");

        match StacksPublicKey::recover_to_pubkey(sighash.as_bytes(), &sig) {
            Ok(recovered) if recovered.to_hex() == expected.to_hex() => {}
            Ok(recovered) => failures.push(format!(
                "key{i}: recovered {} instead of {}",
                recovered.to_hex(),
                expected.to_hex()
            )),
            Err(e) => failures.push(format!("key{i}: {e}")),
        }
    }

    assert!(
        failures.is_empty(),
        "{}/{KEY_COUNT} keys failed to round-trip through recover_to_pubkey:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
