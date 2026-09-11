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

//! Signature-verification tests shared by the native and Wasm backends.
//!
//! Run the Wasm tests with:
//!
//! ```text
//! cd stacks-codec && wasm-pack test --node --features wasm-web
//! ```
//!
//! The vectors are deterministic so failures are reproducible.

#![cfg(test)]

use clarity_types::representations::{ClarityName, ContractName};
use clarity_types::types::{PrincipalData, StandardPrincipalData, Value};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::{PrivateKey, PublicKey};
use stacks_common::util::hash::{hex_bytes, Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
#[cfg(target_family = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use crate::strings::StacksString;
use crate::transaction::{
    StacksMicroblockHeader, StacksTransaction, TokenTransferMemo, TransactionAuth,
    TransactionAuthVerificationMode, TransactionContractCall, TransactionPayload,
    TransactionSmartContract, TransactionSpendingCondition, TransactionVersion,
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

/// Order-independent 2-of-3 multisig vectors. Unlike the ordered form, every
/// signature is checked against the *initial* sighash rather than a rolling one,
/// so this is a separate path into `recover_to_pubkey()`.
fn order_independent_multisig_vectors() -> Vec<(String, StacksTransaction)> {
    let mut out = vec![];

    for i in 0..KEY_COUNT {
        let signers = [compressed_key(i), compressed_key(i + 40)];
        let spectator = compressed_key(i + 80);
        let all = [signers[0].clone(), signers[1].clone(), spectator.clone()];

        for (payload_name, payload) in payloads() {
            for (shape, auth) in [
                (
                    "p2sh",
                    TransactionAuth::from_order_independent_p2sh(&all, 2).unwrap(),
                ),
                (
                    "p2wsh",
                    TransactionAuth::from_order_independent_p2wsh(&all, 2).unwrap(),
                ),
            ] {
                let mut tx =
                    StacksTransaction::new(TransactionVersion::Testnet, auth, payload.clone());
                tx.set_tx_fee(300);
                tx.set_origin_nonce(i as u64);

                // Every signer signs the same initial sighash, which is what makes
                // the field order irrelevant.
                let sighash = tx.sign_begin();
                for privk in &signers {
                    tx.sign_next_origin(&sighash, privk)
                        .expect("BUG: failed to add an order-independent signature");
                }
                // The third participant contributes only its public key.
                tx.append_next_origin(&StacksPublicKey::from_private(&spectator))
                    .expect("BUG: failed to append the trailing public key");

                out.push((
                    format!("order-independent-{shape}-2of3/{payload_name}/key{i}"),
                    tx,
                ));
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
    out.extend(order_independent_multisig_vectors());
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
    for (name, tx) in all_vectors() {
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

/// Reference signatures produced by the native backend, as
/// `(message hash, signature, public key)`.
///
/// These ensure that both backends accept the same signature bytes.
const REFERENCE_SIGNATURES: &[(&str, &str, &str)] = &[
    (
        "4a2944a5d0ea8e79f5845f6e053aa7ff030707ce2a543041bec5d1e79fc3e406",
        "00badd6360ac3aea39c1ef69f215623861306b9285c9ebbba4309b5c475f2d6b5873999c350f8fced1fafdcf2163a69ee6209a72788eea92b15bc53f1ad515f2c6",
        "03487a92ff8ab40f9394d08bd77802abdee2d356f3b7ab3c1dfb56c50eae4f67dc",
    ),
    (
        "b1f660b68b4c927e89ea6de8f6d7872de9c1022033da7cce59f141e0750ac55a",
        "0027cd6a55705de1a83cad8e92bb28b4d808cc256020e08aa5ac65932a2b24ed331f4432e5dbc7215ca762bbbb48eac2ccdf01efd0082a2130ad3331d74eab5d29",
        "0369707efb096923bd8d21d4fd9003403c9c124ff3d8f2203218f07e8f8732b824",
    ),
    (
        "df1193b90d202b715788f9eea12fb35569cc3db3e3b66c34859fcaf093f1a739",
        "0190ccee424514ebd2e7fdab36ed00bf9f2545e3327d16a6be14259df3df7d32bc75e8913d57bdb1090e6a3362ac01a4d00f2473f2aa593ab50fb6a224cf7848c0",
        "028f88ca7be209a0c45fe7da3242e9983257aff9c3a9c144b796c84c05c061e126",
    ),
    (
        "77d094338f2caa17f8531a9405db2469e307324691bda3959f2df4445c885547",
        "0008f11e809c32f9abd9d7299c16fa23fa2598d0e3faf4f964979624eaa587f45d4bae7b9c7983bcaf61c6251d9615cd1a320141436ac8bc4ae476dc567857a669",
        "035369282f28dbc0ae9a4f02dded5eccc20115e8d91635d369e1ae15a896c8abd1",
    ),
];

/// One fully signed, natively serialized transaction per auth shape.
const REFERENCE_TRANSACTIONS: &[(&str, &str)] = &[
    ("p2pkh-compressed/token-transfer/key0", "800000000004001bcb71024dc180cd823e7d9c7fb2832dce430e8c000000000000000000000000000000b40000eb1ec09783fcfe64886e2bf3c6d47c3f910384b08116c259be319bd938f5fe217c6d5213c1bad7bbe00fef81b16421d2b914065bccd1a76c892645c1cb882aff0302000000000005010101010101010101010101010101010101010101000000000000303942424242424242424242424242424242424242424242424242424242424242424242"),
    ("p2pkh-uncompressed/token-transfer/key0", "80000000000400832ddef530dc5c3da0ce87e2ec8d0e04555cb453000000000000000000000000000000b40100f576a06afdf2418e047a2d741e89c909ee47e1b4fcbe6fa5b4b5bb26900d860904c561e5fe4f3a7f3abd4bf9d49bc5b928c3978bb432726071250cd6b89424e30302000000000005010101010101010101010101010101010101010101000000000000303942424242424242424242424242424242424242424242424242424242424242424242"),
    ("p2wpkh/contract-call/key1", "0000000000040213b8083c5d82453b338feafa754b2452ff9e19cf000000000000000100000000000000b50000e02cd617cc8c176f7a08fec4b31f270839c5a09b9f15800e15d1a79773930a4c119becf7d66098ca1d1d842418ee510958e6139dcbc62b09c312249130e95fe50302000000000201abababababababababababababababababababab0d7665726966792d74617267657408646f2d7468696e670000000200fffffffffffffffffffffffffffffff90100000000000000000000000000000007"),
    ("multisig-p2sh-2of3/token-transfer/key0", "800000000004016d19203ede791c0ab9e2959e01cec910b784d53e0000000000000000000000000000012c000000030200c57bf5ee3557ec14414a1849e6ae4328ce88e4b98227fc116944fdf3ec15019f178414fe4e783cd8729a77137dd1b16ab916f74e5369c47cfc5481b76a01fac6020176af8397ebf61795e490fe61bc743841a696dd96b1524fa243dfc47162ffe4eb44bb953f6ef160cbf340469b23f39854382b41f681f635fb4844482c9c0aa5510002f9e2e210e7706dc8dc35f7c8d45585a41767c10096889474830f7eeb8b94a51300020302000000000005010101010101010101010101010101010101010101000000000000303942424242424242424242424242424242424242424242424242424242424242424242"),
    ("multisig-p2wsh-2of3/contract-call/key3", "800000000004036dae79777a210821fc234c33a1ad277e85cab7f60000000000000003000000000000012c000000030201f4ad601e3604b0193aba16cb60464653ea0908b2c3c9ced93649a84c593436ad4eba8efbfab0fe33f63f142b365df35401f85c97d2115eceaba62176436dba36020108252de92dd8a9d67101e2ed535b4992c5cdd48b91ecd531918a970cd2c189d341e43bd72dd558c6ad5155db39943c3f215f23d1b82a17dbbdb573b413b5c91b00034f128bc856f15a8ce111498549cdada39a22cc5639c8697f5de5c4e7a5d2ec7300020302000000000201abababababababababababababababababababab0d7665726966792d74617267657408646f2d7468696e670000000200fffffffffffffffffffffffffffffff90100000000000000000000000000000007"),
    ("order-independent-p2sh-2of3/token-transfer/key0", "800000000004056d19203ede791c0ab9e2959e01cec910b784d53e0000000000000000000000000000012c0000000302013b2f96897a152a9edc228d762167f04a068b76c976038bf37a31db9c5ec47cba173217b75bb562c89936ffe0a9a9ff4c042cdd691e459700462b5fd80f5440a90201bb4ca34565e553ae07b2ce96d99df8587e8184fc0116947258cc1029295362956cff0469c133df81e2148eb54deafdae52b5f01b2ec6741e44fd1b758579a1c20002f9e2e210e7706dc8dc35f7c8d45585a41767c10096889474830f7eeb8b94a51300020302000000000005010101010101010101010101010101010101010101000000000000303942424242424242424242424242424242424242424242424242424242424242424242"),
    ("order-independent-p2wsh-2of3/smart-contract/key5", "800000000004077169787ececfc855c04c8b55c9176016819de0550000000000000005000000000000012c000000030201b915a06f9dc46822b620f5c61e8f89fd00893d42ab9fd1c1236896eb888756a71ed372c1d71fe14cedc47c1eef71c7a609d8e658aeac70be0eaf3fdca47056450201fc87be9d8e9f1df15e0fbcaa80b4e21a5b52ee71cf0d439ff614d5a098eb8b711d984d1873284f621f75aa8ff05bc8121296307b00d97e6a3fb4d7153a235c9900037da48101551591fede0d2b28629573ca1268ba155d2b1883b46e070118a1d3e80002030200000000010d7665726966792d6465706c6f790000001928646566696e652d726561642d6f6e6c792028662920753129"),
    ("sponsored-p2pkh/smart-contract/key2", "00000000000500a83d3582e571d4381ca9024ab45db4642f35ddfa0000000000000002000000000000000000000935acb8ff83fc7116727fa38b2f1a0cc5d9fd2989fa26aef46552ce437a41ce3277d81e87f7874bbd68b72edb3d2774e47136cafba6a64506a5df136a5dbf1a009d2585f991265316113e5a1ac864b56d41180188000000000000000300000000000000f00001dd888bb9ead98f681d25afa59539f01449715b5c05e9fb08611c1bfa8d06174967f148a5d694accf691cdcd2d4b3c622abc4288cc083017131ec6c6ce4e936fc030200000000010d7665726966792d6465706c6f790000001928646566696e652d726561642d6f6e6c792028662920753129"),
];

/// Recovery and verification accept signatures produced by the native backend.
#[test]
fn native_reference_signatures_verify() {
    for (i, (hash_hex, sig_hex, pubkey_hex)) in REFERENCE_SIGNATURES.iter().enumerate() {
        let hash = hex_bytes(hash_hex).expect("BUG: bad reference hash hex");
        let sig = MessageSignature::from_hex(sig_hex).expect("BUG: bad reference signature hex");

        assert_eq!(
            StacksPublicKey::recover_to_pubkey(&hash, &sig)
                .unwrap_or_else(|e| panic!("reference {i}: {e}"))
                .to_hex(),
            *pubkey_hex,
            "reference {i}: recovery from the native signature returned the wrong key"
        );
        assert!(
            StacksPublicKey::from_hex(pubkey_hex)
                .unwrap()
                .verify(&hash, &sig)
                .unwrap_or_else(|e| panic!("reference {i}: {e}")),
            "reference {i}: verification rejected the native signature"
        );
    }
}

/// Transactions serialized and signed by the native backend verify.
#[test]
fn native_reference_transactions_verify() {
    for (name, tx_hex) in REFERENCE_TRANSACTIONS {
        let bytes = hex_bytes(tx_hex).expect("BUG: bad reference transaction hex");
        let tx = StacksTransaction::consensus_deserialize(&mut &bytes[..])
            .unwrap_or_else(|e| panic!("{name}: failed to decode: {e:?}"));

        tx.verify(TransactionAuthVerificationMode::EnforceLowS)
            .unwrap_or_else(|e| panic!("{name}: reference transaction failed to verify: {e}"));
    }
}

/// `PublicKey::verify()` is a separate entry point from `tx.verify()`, which
/// compares address hashes after forcing the recovered key's encoding.
#[test]
fn public_key_verify_accepts_both_key_encodings() {
    for i in 0..KEY_COUNT {
        let privk = compressed_key(i);
        let hash = Sha512Trunc256Sum::from_data(&[b'v', b'r', b'f', i]);
        let sig = privk
            .sign(hash.as_bytes())
            .expect("BUG: failed to sign a 32-byte hash");

        // `recover_to_pubkey()` always returns a compressed key, so a `verify()`
        // that compares whole `Secp256k1PublicKey` values -- `compressed` flag
        // included -- would reject every uncompressed key.
        for compressed in [true, false] {
            let mut pubk = StacksPublicKey::from_private(&privk);
            pubk.set_compressed(compressed);
            assert!(
                pubk.verify(hash.as_bytes(), &sig)
                    .unwrap_or_else(|e| panic!("key{i}: {e}")),
                "key{i}: verify() rejected a valid signature for a {} key",
                if compressed {
                    "compressed"
                } else {
                    "uncompressed"
                }
            );
        }

        let other = StacksPublicKey::from_private(&compressed_key(i + 40));
        assert!(
            !other
                .verify(hash.as_bytes(), &sig)
                .unwrap_or_else(|e| panic!("key{i}: {e}")),
            "key{i}: verify() accepted a signature made by a different key"
        );

        assert!(
            StacksPublicKey::from_private(&privk)
                .verify(hash.as_bytes(), &sig.with_negated_s())
                .is_err(),
            "key{i}: verify() accepted a high-S signature"
        );
    }
}

/// The recovery path rejects each kind of malformed input with the same error on
/// both backends. None of these branches are reachable from a signed
/// transaction.
#[test]
fn recover_to_pubkey_rejects_malformed_input() {
    let privk = compressed_key(0);
    let hash = Sha512Trunc256Sum::from_data(b"reject");
    let sig = privk
        .sign(hash.as_bytes())
        .expect("BUG: failed to sign a 32-byte hash");

    // The message must be exactly 32 bytes.
    for len in [0usize, 31, 33, 64] {
        assert_eq!(
            StacksPublicKey::recover_to_pubkey(&vec![0u8; len], &sig),
            Err("Invalid message: failed to decode data hash: must be a 32-byte hash"),
            "a {len}-byte message hash was not rejected"
        );
    }

    // When the message and the signature are both malformed, both backends
    // report the message first.
    assert_eq!(
        StacksPublicKey::recover_to_pubkey(&[], &MessageSignature([0xff; 65])),
        Err("Invalid message: failed to decode data hash: must be a 32-byte hash"),
        "a malformed message and signature did not report the message error"
    );

    // The recovery id occupies byte 0 and must be in 0..=3.
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(sig.as_bytes());
    for recovery_id in [4u8, 0x80, 0xff] {
        bytes[0] = recovery_id;
        assert_eq!(
            StacksPublicKey::recover_to_pubkey(hash.as_bytes(), &MessageSignature(bytes)),
            Err("Invalid signature: failed to decode recoverable signature"),
            "recovery id {recovery_id} was not rejected"
        );
    }

    // A valid recovery id over a point that is not on the curve.
    let mut unrecoverable = [0u8; 65];
    unrecoverable[0] = 1;
    assert_eq!(
        StacksPublicKey::recover_to_pubkey(hash.as_bytes(), &MessageSignature(unrecoverable)),
        Err("Invalid signature: failed to recover public key"),
        "an all-zero signature was not rejected"
    );

    // High-S is rejected only by the low-S entry point.
    let high_s = sig.with_negated_s();
    assert_eq!(
        StacksPublicKey::recover_to_pubkey(hash.as_bytes(), &high_s),
        Err("Invalid signature: high-S"),
        "a high-S signature was not rejected by recover_to_pubkey()"
    );
    assert!(
        StacksPublicKey::recover_to_pubkey_without_validating_low_s(hash.as_bytes(), &high_s)
            .is_ok(),
        "a high-S signature was rejected by the entry point that allows it"
    );
}

/// `StacksMicroblockHeader` recovers its signer through
/// `recover_to_pubkey_without_validating_low_s()`, which no transaction vector
/// above reaches under `EnforceLowS`.
#[test]
fn microblock_header_signatures_verify() {
    for i in 0..KEY_COUNT {
        let privk = compressed_key(i);
        let signer = Hash160::from_node_public_key(&StacksPublicKey::from_private(&privk));

        let mut header = StacksMicroblockHeader {
            version: 0x12,
            sequence: u16::from(i),
            prev_block: BlockHeaderHash([0x33; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x44; 32]),
            signature: MessageSignature::empty(),
        };
        header
            .sign(&privk)
            .expect("BUG: failed to sign the microblock header");

        header
            .verify(&signer)
            .unwrap_or_else(|e| panic!("key{i}: a correctly signed header failed to verify: {e}"));

        let other =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&compressed_key(i + 40)));
        assert!(
            header.verify(&other).is_err(),
            "key{i}: verification accepted the wrong signer"
        );

        let mut tampered = header.clone();
        tampered.sequence ^= 0xff;
        assert!(
            tampered.verify(&signer).is_err(),
            "key{i}: verification accepted a header with a tampered sequence"
        );
    }
}
