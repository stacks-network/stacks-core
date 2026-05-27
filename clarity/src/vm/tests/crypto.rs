use clarity_types::types::MAX_VALUE_SIZE;
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
use pinny::tag;
use proptest::collection::vec;
use proptest::prelude::*;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::ed25519::{self, Ed25519PrivateKey, Ed25519PublicKey, MessageSignature};
use stacks_common::util::hash::{Sha256Sum, hex_bytes, to_hex};
use stacks_common::util::secp256k1::MessageSignature as Secp256k1Signature;
use stacks_common::util::secp256r1::{Secp256r1PrivateKey, Secp256r1PublicKey};

use crate::vm::errors::{ClarityEvalError, RuntimeCheckErrorKind, VmExecutionError};
use crate::vm::types::{ResponseData, TypeSignature, Value};
use crate::vm::{ClarityVersion, execute_with_parameters};

struct NistVector {
    msg: &'static str,
    d: &'static str,
    q_x: &'static str,
    q_y: &'static str,
    k: &'static str,
    r: &'static str,
    s: &'static str,
}

// Test vectors from NIST,
// https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Component-Testing
static NIST_VECTORS: &[NistVector] = &[
    NistVector {
        msg: "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56",
        d: "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
        q_x: "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
        q_y: "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
        k: "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de",
        r: "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
        s: "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903",
    },
    NistVector {
        msg: "9b2db89cb0e8fa3cc7608b4d6cc1dec0114e0b9ff4080bea12b134f489ab2bbc",
        d: "0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813",
        q_x: "e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8a",
        q_y: "bfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39",
        k: "6d3e71882c3b83b156bb14e0ab184aa9fb728068d3ae9fac421187ae0b2f34c6",
        r: "976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db",
        s: "1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932",
    },
    NistVector {
        msg: "b804cf88af0c2eff8bbbfb3660ebb3294138e9d3ebd458884e19818061dacff0",
        d: "e283871239837e13b95f789e6e1af63bf61c918c992e62bca040d64cad1fc2ef",
        q_x: "74ccd8a62fba0e667c50929a53f78c21b8ff0c3c737b0b40b1750b2302b0bde8",
        q_y: "29074e21f3a0ef88b9efdf10d06aa4c295cc1671f758ca0e4cd108803d0f2614",
        k: "ad5e887eb2b380b8d8280ad6e5ff8a60f4d26243e0124c2f31a297b5d0835de2",
        r: "35fb60f5ca0f3ca08542fb3cc641c8263a2cab7a90ee6a5e1583fac2bb6f6bd1",
        s: "ee59d81bc9db1055cc0ed97b159d8784af04e98511d0a9a407b99bb292572e96",
    },
    NistVector {
        msg: "85b957d92766235e7c880ac5447cfbe97f3cb499f486d1e43bcb5c2ff9608a1a",
        d: "a3d2d3b7596f6592ce98b4bfe10d41837f10027a90d7bb75349490018cf72d07",
        q_x: "322f80371bf6e044bc49391d97c1714ab87f990b949bc178cb7c43b7c22d89e1",
        q_y: "3c15d54a5cc6b9f09de8457e873eb3deb1fceb54b0b295da6050294fae7fd999",
        k: "24fc90e1da13f17ef9fe84cc96b9471ed1aaac17e3a4bae33a115df4e5834f18",
        r: "d7c562370af617b581c84a2468cc8bd50bb1cbf322de41b7887ce07c0e5884ca",
        s: "b46d9f2d8c4bf83546ff178f1d78937c008d64e8ecc5cbb825cb21d94d670d89",
    },
    NistVector {
        msg: "3360d699222f21840827cf698d7cb635bee57dc80cd7733b682d41b55b666e22",
        d: "53a0e8a8fe93db01e7ae94e1a9882a102ebd079b3a535827d583626c272d280d",
        q_x: "1bcec4570e1ec2436596b8ded58f60c3b1ebc6a403bc5543040ba82963057244",
        q_y: "8af62a4c683f096b28558320737bf83b9959a46ad2521004ef74cf85e67494e1",
        k: "5d833e8d24cc7a402d7ee7ec852a3587cddeb48358cea71b0bedb8fabe84e0c4",
        r: "18caaf7b663507a8bcd992b836dec9dc5703c080af5e51dfa3a9a7c387182604",
        s: "77c68928ac3b88d985fb43fb615fb7ff45c18ba5c81af796c613dfa98352d29c",
    },
    NistVector {
        msg: "c413c4908cd0bc6d8e32001aa103043b2cf5be7fcbd61a5cec9488c3a577ca57",
        d: "4af107e8e2194c830ffb712a65511bc9186a133007855b49ab4b3833aefc4a1d",
        q_x: "a32e50be3dae2c8ba3f5e4bdae14cf7645420d425ead94036c22dd6c4fc59e00",
        q_y: "d623bf641160c289d6742c6257ae6ba574446dd1d0e74db3aaa80900b78d4ae9",
        k: "e18f96f84dfa2fd3cdfaec9159d4c338cd54ad314134f0b31e20591fc238d0ab",
        r: "8524c5024e2d9a73bde8c72d9129f57873bbad0ed05215a372a84fdbc78f2e68",
        s: "d18c2caf3b1072f87064ec5e8953f51301cada03469c640244760328eb5a05cb",
    },
    NistVector {
        msg: "88fc1e7d849794fc51b135fa135deec0db02b86c3cd8cebdaa79e8689e5b2898",
        d: "78dfaa09f1076850b3e206e477494cddcfb822aaa0128475053592c48ebaf4ab",
        q_x: "8bcfe2a721ca6d753968f564ec4315be4857e28bef1908f61a366b1f03c97479",
        q_y: "0f67576a30b8e20d4232d8530b52fb4c89cbc589ede291e499ddd15fe870ab96",
        k: "295544dbb2da3da170741c9b2c6551d40af7ed4e891445f11a02b66a5c258a77",
        r: "c5a186d72df452015480f7f338970bfe825087f05c0088d95305f87aacc9b254",
        s: "84a58f9e9d9e735344b316b1aa1ab5185665b85147dc82d92e969d7bee31ca30",
    },
    NistVector {
        msg: "41fa8d8b4cd0a5fdf021f4e4829d6d1e996bab6b4a19dcb85585fe76c582d2bc",
        d: "80e692e3eb9fcd8c7d44e7de9f7a5952686407f90025a1d87e52c7096a62618a",
        q_x: "a88bc8430279c8c0400a77d751f26c0abc93e5de4ad9a4166357952fe041e767",
        q_y: "2d365a1eef25ead579cc9a069b6abc1b16b81c35f18785ce26a10ba6d1381185",
        k: "7c80fd66d62cc076cef2d030c17c0a69c99611549cb32c4ff662475adbe84b22",
        r: "9d0c6afb6df3bced455b459cc21387e14929392664bb8741a3693a1795ca6902",
        s: "d7f9ddd191f1f412869429209ee3814c75c72fa46a9cccf804a2f5cc0b7e739f",
    },
    NistVector {
        msg: "2d72947c1731543b3d62490866a893952736757746d9bae13e719079299ae192",
        d: "5e666c0db0214c3b627a8e48541cc84a8b6fd15f300da4dff5d18aec6c55b881",
        q_x: "1bc487570f040dc94196c9befe8ab2b6de77208b1f38bdaae28f9645c4d2bc3a",
        q_y: "ec81602abd8345e71867c8210313737865b8aa186851e1b48eaca140320f5d8f",
        k: "2e7625a48874d86c9e467f890aaa7cd6ebdf71c0102bfdcfa24565d6af3fdce9",
        r: "2f9e2b4e9f747c657f705bffd124ee178bbc5391c86d056717b140c153570fd9",
        s: "f5413bfd85949da8d83de83ab0d19b2986613e224d1901d76919de23ccd03199",
    },
    NistVector {
        msg: "e138bd577c3729d0e24a98a82478bcc7482499c4cdf734a874f7208ddbc3c116",
        d: "f73f455271c877c4d5334627e37c278f68d143014b0a05aa62f308b2101c5308",
        q_x: "b8188bd68701fc396dab53125d4d28ea33a91daf6d21485f4770f6ea8c565dde",
        q_y: "423f058810f277f8fe076f6db56e9285a1bf2c2a1dae145095edd9c04970bc4a",
        k: "62f8665fd6e26b3fa069e85281777a9b1f0dfd2c0b9f54a086d0c109ff9fd615",
        r: "1cc628533d0004b2b20e7f4baad0b8bb5e0673db159bbccf92491aef61fc9620",
        s: "880e0bbf82a8cf818ed46ba03cf0fc6c898e36fca36cc7fdb1d2db7503634430",
    },
];

#[test]
fn secp256r1_verify_valid_signatures_nist() {
    use stacks_common::util::hash::hex_bytes;
    use stacks_common::util::secp256r1::MessageSignature;

    for NistVector {
        msg,
        d,
        q_x,
        q_y,
        k,
        r,
        s,
    } in NIST_VECTORS
    {
        let message_hash = hex_bytes(msg).unwrap();
        let privk = Secp256r1PrivateKey::from_hex(d).unwrap();
        let mut pubk = Secp256r1PublicKey::from_hex(&format!("04{q_x}{q_y}")).unwrap();
        pubk.set_compressed(true);

        let signature_dh = privk.sign(&message_hash).unwrap();
        let signature_nist = MessageSignature::from_hex(&format!("{r}{s}")).unwrap();

        let verified_double_hash = pubk.verify(&message_hash, &signature_dh).is_ok();
        let verified_nist_sign = pubk.verify_digest(&message_hash, &signature_nist).is_ok();

        info!(
            "Signed with SK";
            "nist_signature" => format!("{r}{s}"),
            "double_hash" => to_hex(&signature_dh.0),
            "pubk" => to_hex(&pubk.to_bytes()),
            "verified_double_hash" => verified_double_hash,
            "verified_nist_sign" => verified_nist_sign,
        );

        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&message_hash),
            buff_literal(&signature_dh.0),
            buff_literal(&pubk.to_bytes())
        );

        assert_eq!(
            Value::Bool(true),
            execute_with_parameters(
                program.as_str(),
                ClarityVersion::Clarity4,
                StacksEpochId::Epoch33,
                false
            )
            .expect("execution should succeed")
            .expect("should return a value")
        );

        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&message_hash),
            buff_literal(&signature_nist.0),
            buff_literal(&pubk.to_bytes())
        );

        assert_eq!(
            Value::Bool(true),
            execute_with_parameters(
                program.as_str(),
                ClarityVersion::latest(),
                StacksEpochId::latest(),
                false
            )
            .expect("execution should succeed")
            .expect("should return a value")
        );
    }
}

/// Returns (message_hash, signature, pubkey) for secp256r1 using double-hash signing
/// (Clarity 4 and earlier behavior: `sign()` hashes the message again internally).
fn secp256r1_vectors() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let privk = Secp256r1PrivateKey::from_seed(&[7u8; 32]);
    let pubk = Secp256r1PublicKey::from_private(&privk);
    let message_hash = Sha256Sum::from_data(b"clarity-secp256r1-tests");
    let signature = privk
        .sign(message_hash.as_bytes())
        .expect("secp256r1 signing should succeed");

    (
        message_hash.as_bytes().to_vec(),
        signature.0.to_vec(),
        pubk.to_bytes_compressed(),
    )
}

/// Returns (message_hash, signature, pubkey) for secp256r1 using digest signing
/// (Clarity 5+ behavior: `sign_digest()` uses the message hash directly without re-hashing).
fn secp256r1_vectors_digest() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let privk = Secp256r1PrivateKey::from_seed(&[7u8; 32]);
    let pubk = Secp256r1PublicKey::from_private(&privk);
    let message_hash = Sha256Sum::from_data(b"clarity-secp256r1-tests");
    let signature = privk
        .sign_digest(message_hash.as_bytes())
        .expect("secp256r1 digest signing should succeed");

    (
        message_hash.as_bytes().to_vec(),
        signature.0.to_vec(),
        pubk.to_bytes_compressed(),
    )
}

fn secp256k1_vectors() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let privk = StacksPrivateKey::from_seed(&[9u8; 32]);
    let pubk = StacksPublicKey::from_private(&privk);
    let message_hash = Sha256Sum::from_data(b"clarity-secp256k1-tests");
    let signature: Secp256k1Signature = privk
        .sign(message_hash.as_bytes())
        .expect("secp256k1 signing should succeed");
    // Clarity expects R || S || v ordering.
    let signature_bytes = signature.to_rsv();

    (
        message_hash.as_bytes().to_vec(),
        signature_bytes,
        pubk.to_bytes_compressed(),
    )
}

fn buff_literal(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}

fn zeroed_buff_literal(len: usize) -> String {
    buff_literal(&vec![0u8; len])
}

#[test]
fn test_secp256r1_verify_valid_signature_returns_true() {
    // Clarity 4 (double-hash): sign() hashes internally, secp256r1-verify hashes again
    let (message, signature, pubkey) = secp256r1_vectors();
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );

    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );

    // Same double-hash signature must NOT verify under Clarity 5+ (direct digest)
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );

    // Clarity 5+ (direct digest): sign_digest() signs the hash directly
    let (message, signature, pubkey) = secp256r1_vectors_digest();
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );

    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );

    // Same digest signature must NOT verify under Clarity 4 (double-hash)
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256r1_verify_valid_high_s_signature_returns_true() {
    use stacks_common::util::secp256r1::MessageSignature;

    // secp256r1-verify accepts high-S signatures (unlike secp256k1-verify).

    // Clarity 4 (double-hash path)
    let (message, signature, pubkey) = secp256r1_vectors();
    let high_s_sig = MessageSignature(signature.as_slice().try_into().unwrap())
        .to_high_s()
        .expect("should create high-S signature");
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&high_s_sig.0),
        buff_literal(&pubkey)
    );
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
            false
        )
        .expect("execution should succeed")
        .expect("should return a value"),
        "High-S signature should verify in Clarity 4"
    );

    // Clarity 5+ (direct digest path)
    let (message, signature, pubkey) = secp256r1_vectors_digest();
    let high_s_sig = MessageSignature(signature.as_slice().try_into().unwrap())
        .to_high_s()
        .expect("should create high-S signature");
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&high_s_sig.0),
        buff_literal(&pubkey)
    );
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value"),
        "High-S signature should verify in Clarity 5+"
    );
}

#[test]
fn test_secp256r1_verify_invalid_signature_returns_false() {
    // Clarity 4 (double-hash)
    let (message, mut signature, pubkey) = secp256r1_vectors();
    signature[0] ^= 0x01;
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );

    // Clarity 5+ (direct digest)
    let (message, mut signature, pubkey) = secp256r1_vectors_digest();
    signature[0] ^= 0x01;
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256r1_verify_signature_too_short_returns_false() {
    // Clarity 4 (double-hash)
    let (message, mut signature, pubkey) = secp256r1_vectors();
    signature.truncate(63);
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );

    // Clarity 5+ (direct digest)
    let (message, mut signature, pubkey) = secp256r1_vectors_digest();
    signature.truncate(63);
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256r1_verify_signature_too_long_errors() {
    // Clarity 4 (double-hash)
    let (message, mut signature, pubkey) = secp256r1_vectors();
    signature.push(0x00);
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );
    let err = execute_with_parameters(
        program.as_str(),
        ClarityVersion::Clarity4,
        StacksEpochId::Epoch33,
        false,
    )
    .unwrap_err();
    match err {
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::TypeValueError(expected, _),
        )) => {
            assert_eq!(*expected, TypeSignature::BUFFER_64);
        }
        _ => panic!("expected BUFFER_64 type error, found {err:?}"),
    }

    // Clarity 5+ (direct digest)
    let (message, mut signature, pubkey) = secp256r1_vectors_digest();
    signature.push(0x00);
    let program = format!(
        "(secp256r1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );
    let err = execute_with_parameters(
        program.as_str(),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        false,
    )
    .unwrap_err();
    match err {
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::TypeValueError(expected, _),
        )) => {
            assert_eq!(*expected, TypeSignature::BUFFER_64);
        }
        _ => panic!("expected BUFFER_64 type error, found {err:?}"),
    }
}

#[test]
fn test_secp256k1_verify_valid_signature_returns_true() {
    let (message, signature, pubkey) = secp256k1_vectors();
    let program = format!(
        "(secp256k1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );

    println!("program: {program}");

    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256k1_verify_valid_high_s_signature_returns_false() {
    let message = "0x89171d7815da4bc1f644665a3234bc99d1680afa0b3285eff4878f4275fbfa89";
    let signature = "0x54cd3f378a424a3e50ff1c911b7d80cf424e1b86dddecadbcf39077e62fa1e54ee6514347c1608df2c3995e7356f2d60a1fab60878214642134d78cd923ce27a01";
    let pubkey = "0x0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967";

    let program = format!("(secp256k1-verify {message} {signature} {pubkey})");

    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256k1_verify_invalid_signature_returns_false() {
    let (message, mut signature, pubkey) = secp256k1_vectors();
    signature[10] ^= 0x01;

    let program = format!(
        "(secp256k1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );

    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256k1_verify_signature_too_short_returns_false() {
    let (message, mut signature, pubkey) = secp256k1_vectors();
    signature.truncate(63);

    let program = format!(
        "(secp256k1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );

    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256k1_verify_recovery_id_out_of_range_returns_false() {
    let (message, mut signature, pubkey) = secp256k1_vectors();
    if let Some(last) = signature.last_mut() {
        *last = 0x04;
    }

    let program = format!(
        "(secp256k1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );

    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256k1_verify_signature_too_long_errors() {
    let (message, mut signature, pubkey) = secp256k1_vectors();
    signature.extend([0x00, 0x01]);

    let program = format!(
        "(secp256k1-verify {} {} {})",
        buff_literal(&message),
        buff_literal(&signature),
        buff_literal(&pubkey)
    );

    let err = execute_with_parameters(
        program.as_str(),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        false,
    )
    .unwrap_err();
    match err {
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::TypeValueError(expected, _),
        )) => {
            assert_eq!(*expected, TypeSignature::BUFFER_65);
        }
        _ => panic!("expected BUFFER_65 type error, found {err:?}"),
    }
}

#[test]
fn test_secp256k1_recover_returns_expected_public_key() {
    let (message, signature, pubkey) = secp256k1_vectors();
    let fallback = zeroed_buff_literal(33);
    let program = format!(
        "(is-eq (unwrap! (secp256k1-recover? {} {}) {}) {})",
        buff_literal(&message),
        buff_literal(&signature),
        fallback,
        buff_literal(&pubkey)
    );

    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_secp256k1_recover_invalid_signature_returns_err_code() {
    let (message, mut signature, _pubkey) = secp256k1_vectors();
    signature[5] ^= 0x02;

    let program = format!(
        "(secp256k1-recover? {} {})",
        buff_literal(&message),
        buff_literal(&signature)
    );

    match execute_with_parameters(
        program.as_str(),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        false,
    )
    .expect("execution should succeed")
    .expect("should return a value")
    {
        Value::Response(ResponseData { data, .. }) => {
            assert_eq!(data, Box::new(Value::UInt(1)));
        }
        other => panic!("expected err response, found {other:?}"),
    }
}

#[test]
fn test_ed25519_verify_valid_signature_returns_true() {
    let sk = Ed25519PrivateKey::random();
    let pk = Ed25519PublicKey::from_private(&sk);

    let message = b"Hello World";

    let signature = sk.sign(message).unwrap();

    let program = format!(
        "(ed25519-verify {} {} {})",
        buff_literal(message),
        buff_literal(&signature.to_bytes()),
        buff_literal(&pk.to_bytes())
    );

    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_ed25519_verify_rfc_test_vectors_returns_true() {
    let test_vectors = |public_key, message, signature| {
        let program = format!(
            "(ed25519-verify {} {} {})",
            buff_literal(&hex_bytes(message).unwrap()),
            buff_literal(&hex_bytes(signature).unwrap()),
            buff_literal(&hex_bytes(public_key).unwrap())
        );

        assert_eq!(
            Value::Bool(true),
            execute_with_parameters(
                program.as_str(),
                ClarityVersion::latest(),
                StacksEpochId::latest(),
                false
            )
            .expect("execution should succeed")
            .expect("should return a value")
        );
    };

    test_vectors(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    test_vectors(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );

    test_vectors(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    );

    test_vectors(
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    );
}

#[test]
fn test_ed25519_verify_empty_signature_returns_err() {
    let sk = Ed25519PrivateKey::random();
    let pk = Ed25519PublicKey::from_private(&sk);

    let message = b"Hello World";

    let program = format!(
        "(ed25519-verify {} {} {})",
        buff_literal(message),
        buff_literal(&[]),
        buff_literal(&pk.to_bytes())
    );

    let err = execute_with_parameters(
        program.as_str(),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        false,
    )
    .unwrap_err();
    match err {
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::TypeValueError(expected, _),
        )) => {
            assert_eq!(*expected, TypeSignature::BUFFER_64);
        }
        _ => panic!("expected BUFFER_64 type error, found {err:?}"),
    }
}

#[test]
fn test_ed25519_verify_short_signature_returns_false() {
    let sk = Ed25519PrivateKey::random();
    let pk = Ed25519PublicKey::from_private(&sk);

    let message = b"Hello World";

    let program = format!(
        "(ed25519-verify {} {} {})",
        buff_literal(message),
        buff_literal(&[0u8; 4]),
        buff_literal(&pk.to_bytes())
    );

    let err = execute_with_parameters(
        program.as_str(),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
        false,
    )
    .unwrap_err();
    match err {
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::TypeValueError(expected, _),
        )) => {
            assert_eq!(*expected, TypeSignature::BUFFER_64);
        }
        _ => panic!("expected BUFFER_64 type error, found {err:?}"),
    }
}

#[test]
fn test_ed25519_verify_zero_signature_returns_false() {
    let sk = Ed25519PrivateKey::random();
    let pk = Ed25519PublicKey::from_private(&sk);

    let message = b"Hello World";

    let signature = MessageSignature::empty();

    let program = format!(
        "(ed25519-verify {} {} {})",
        buff_literal(message),
        buff_literal(&signature.to_bytes()),
        buff_literal(&pk.to_bytes())
    );

    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

#[test]
fn test_ed25519_verify_invalid_signature_returns_false() {
    let sk = Ed25519PrivateKey::random();
    let pk = Ed25519PublicKey::from_private(&sk);

    let message = b"Hello World";

    let signature = MessageSignature::from_raw(&[1u8; 64]);

    let program = format!(
        "(ed25519-verify {} {} {})",
        buff_literal(message),
        buff_literal(&signature.to_bytes()),
        buff_literal(&pk.to_bytes())
    );

    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false
        )
        .expect("execution should succeed")
        .expect("should return a value")
    );
}

proptest! {
    #[tag(t_prop)]
    #[test]
    fn prop_secp256k1_verify_accepts_valid_signatures(
        seed in any::<[u8; 32]>(),
        message in any::<[u8; 32]>()
    ) {
        let privk = StacksPrivateKey::from_seed(&seed);
        let pubk = StacksPublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes_compressed();
        let message = message.to_vec();
        let signature: Secp256k1Signature = privk.sign(&message).expect("secp256k1 signing should succeed");
        let signature_bytes = signature.to_rsv();
        let program = format!(
            "(secp256k1-verify {} {} {})",
            buff_literal(&message),
            buff_literal(&signature_bytes),
            buff_literal(&pubkey_bytes)
        );

        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");

        prop_assert_eq!(Value::Bool(true), result);
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256k1_recover_matches_public_key(
        seed in any::<[u8; 32]>(),
        message in any::<[u8; 32]>()
    ) {
        let privk = StacksPrivateKey::from_seed(&seed);
        let pubk = StacksPublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes_compressed();
        let message = message.to_vec();
        let signature: Secp256k1Signature = privk.sign(&message).expect("secp256k1 signing should succeed");
        let signature_bytes = signature.to_rsv();
        let program = format!(
            "(is-eq (unwrap! (secp256k1-recover? {} {}) (err u1)) {})",
            buff_literal(&message),
            buff_literal(&signature_bytes),
            buff_literal(&pubkey_bytes)
        );

        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");

        prop_assert_eq!(Value::Bool(true), result);
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256r1_verify_accepts_valid_signatures(
        seed in any::<[u8; 32]>(),
        message in any::<[u8; 32]>()
    ) {
        let privk = Secp256r1PrivateKey::from_seed(&seed);
        let pubk = Secp256r1PublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes_compressed();
        let message = message.to_vec();

        // Clarity 4: sign() does double-hash
        let signature = privk.sign(&message).expect("secp256r1 signing should succeed");
        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&message),
            buff_literal(&signature.0),
            buff_literal(&pubkey_bytes)
        );
        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");
        prop_assert_eq!(Value::Bool(true), result.clone(), "Clarity 4 double-hash verify failed");

        // Clarity 5+: sign_digest() uses hash directly
        let signature = privk.sign_digest(&message).expect("secp256r1 digest signing should succeed");
        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&message),
            buff_literal(&signature.0),
            buff_literal(&pubkey_bytes)
        );
        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");
        prop_assert_eq!(Value::Bool(true), result, "Clarity 5+ digest verify failed");
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256k1_verify_rejects_tampered_msg(
        seed in any::<[u8; 32]>(),
        message in any::<[u8; 32]>(),
        bit in 0usize..32
    ) {
        let privk = StacksPrivateKey::from_seed(&seed);
        let pubk = StacksPublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes_compressed();
        let mut m = message.to_vec();
        let sig: Secp256k1Signature = privk.sign(&m).unwrap();
        let sig_bytes = sig.to_rsv();

        // flip one bit
        m[bit] ^= 0x01;

        let program = format!(
            "(secp256k1-verify {} {} {})",
            buff_literal(&m),
            buff_literal(&sig_bytes),
            buff_literal(&pubkey_bytes)
        );
        let result = execute_with_parameters(
            &program, ClarityVersion::latest(), StacksEpochId::latest(), false
        ).unwrap().unwrap();

        prop_assert_eq!(Value::Bool(false), result);
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256r1_verify_rejects_tampered_msg(
        seed in any::<[u8; 32]>(),
        message in any::<[u8; 32]>(),
        bit in 0usize..32
    ) {
        let privk = Secp256r1PrivateKey::from_seed(&seed);
        let pubk = Secp256r1PublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes_compressed();
        let message = message.to_vec();

        // Clarity 4: sign() does double-hash
        let signature = privk.sign(&message).expect("secp256r1 signing should succeed");
        let mut tampered = message.clone();
        tampered[bit] ^= 0x01;
        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&tampered),
            buff_literal(&signature.0),
            buff_literal(&pubkey_bytes)
        );
        let result = execute_with_parameters(
            &program, ClarityVersion::Clarity4, StacksEpochId::Epoch33, false
        ).unwrap().unwrap();
        prop_assert_eq!(Value::Bool(false), result.clone(), "Clarity 4 tampered msg should fail");

        // Clarity 5+: sign_digest() uses hash directly
        let signature = privk.sign_digest(&message).expect("secp256r1 digest signing should succeed");
        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&tampered),
            buff_literal(&signature.0),
            buff_literal(&pubkey_bytes)
        );
        let result = execute_with_parameters(
            &program, ClarityVersion::latest(), StacksEpochId::latest(), false
        ).unwrap().unwrap();
        prop_assert_eq!(Value::Bool(false), result, "Clarity 5+ tampered msg should fail");
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256k1_recover_fails_to_match_with_tampered_msg(
        seed in any::<[u8; 32]>(),
        message in any::<[u8; 32]>(),
        bit in 0usize..32
    ) {
        let privk = StacksPrivateKey::from_seed(&seed);
        let pubk = StacksPublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes_compressed();
        let mut message = message.to_vec();
        let signature: Secp256k1Signature = privk.sign(&message).expect("secp256k1 signing should succeed");
        let signature_bytes = signature.to_rsv();

        // flip one bit
        message[bit] ^= 0x01;

        let program = format!(
            "(is-eq (unwrap! (secp256k1-recover? {} {}) (err u1)) {})",
            buff_literal(&message),
            buff_literal(&signature_bytes),
            buff_literal(&pubkey_bytes)
        );

        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");

        prop_assert_eq!(Value::Bool(false), result);
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256r1_verify_rejects_wrong_key(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        message in any::<[u8; 32]>()
    ) {
        prop_assume!(seed_a != seed_b);

        let priv_a = Secp256r1PrivateKey::from_seed(&seed_a);
        let pub_b  = Secp256r1PublicKey::from_private(&Secp256r1PrivateKey::from_seed(&seed_b));
        let pub_b_bytes = pub_b.to_bytes_compressed();
        let msg = message.to_vec();

        // Clarity 4: sign() does double-hash
        let signature = priv_a.sign(&msg).unwrap();
        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&msg),
            buff_literal(&signature.0),
            buff_literal(&pub_b_bytes)
        );
        let result = execute_with_parameters(
            &program, ClarityVersion::Clarity4, StacksEpochId::Epoch33, false
        ).unwrap().unwrap();
        prop_assert_eq!(Value::Bool(false), result.clone(), "Clarity 4 wrong key should fail");

        // Clarity 5+: sign_digest() uses hash directly
        let signature = priv_a.sign_digest(&msg).unwrap();
        let program = format!(
            "(secp256r1-verify {} {} {})",
            buff_literal(&msg),
            buff_literal(&signature.0),
            buff_literal(&pub_b_bytes)
        );
        let result = execute_with_parameters(
            &program, ClarityVersion::latest(), StacksEpochId::latest(), false
        ).unwrap().unwrap();
        prop_assert_eq!(Value::Bool(false), result, "Clarity 5+ wrong key should fail");
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256k1_verify_rejects_wrong_key(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        message in any::<[u8; 32]>()
    ) {
        prop_assume!(seed_a != seed_b);
        let priv_a = StacksPrivateKey::from_seed(&seed_a);
        let pub_b  = StacksPublicKey::from_private(&StacksPrivateKey::from_seed(&seed_b));
        let pub_b_bytes = pub_b.to_bytes_compressed();

        let message = message.to_vec();
        let signature: Secp256k1Signature = priv_a.sign(&message).expect("secp256k1 signing should succeed");
        let signature_bytes = signature.to_rsv();
        let program = format!(
            "(secp256k1-verify {} {} {})",
            buff_literal(&message),
            buff_literal(&signature_bytes),
            buff_literal(&pub_b_bytes)
        );

        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");

        prop_assert_eq!(Value::Bool(false), result);
    }

    #[tag(t_prop)]
    #[test]
    fn prop_secp256k1_recover_fails_to_match_with_wrong_key(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        message in any::<[u8; 32]>()
    ) {
        let priv_a = StacksPrivateKey::from_seed(&seed_a);
        let pub_b  = StacksPublicKey::from_private(&StacksPrivateKey::from_seed(&seed_b));
        let pub_b_bytes = pub_b.to_bytes_compressed();

        let message = message.to_vec();
        let signature: Secp256k1Signature = priv_a.sign(&message).expect("secp256k1 signing should succeed");
        let signature_bytes = signature.to_rsv();
        let program = format!(
            "(is-eq (unwrap! (secp256k1-recover? {} {}) (err u1)) {})",
            buff_literal(&message),
            buff_literal(&signature_bytes),
            buff_literal(&pub_b_bytes)
        );

        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");

        prop_assert_eq!(Value::Bool(false), result);
    }

    #[tag(t_prop)]
    #[test]
    fn prop_ed25519_verify_accepts_valid_signatures(
        seed in any::<[u8; 32]>(),
        message_bytes in vec(any::<u8>(), 0..MAX_VALUE_SIZE as usize)
    ) {
        let privk = Ed25519PrivateKey::from_seed(&seed);
        let pubk = Ed25519PublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes();

        let signature: ed25519::MessageSignature = privk.sign(&message_bytes).expect("ed25519 signing should succeed");
        let signature_bytes = signature.to_bytes();
        let program = format!(
            "(ed25519-verify {} {} {})",
            buff_literal(&message_bytes),
            buff_literal(&signature_bytes),
            buff_literal(&pubkey_bytes)
        );

        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");

        prop_assert_eq!(Value::Bool(true), result);
    }

    #[tag(t_prop)]
    #[test]
    fn prop_ed25519_verify_rejects_malleable_scalar_overflow_signatures(
        seed in any::<[u8; 32]>(),
        message_bytes in vec(any::<u8>(), 0..MAX_VALUE_SIZE as usize)
    ) {
        let privk = Ed25519PrivateKey::from_seed(&seed);
        let pubk = Ed25519PublicKey::from_private(&privk);
        let pubkey_bytes = pubk.to_bytes();

        // 1. Generate a valid signature (64 bytes total: [0..32] is R, [32..64] is S)
        let signature = privk.sign(&message_bytes).expect("ed25519 signing should succeed");
        let mut tampered_signature_bytes = signature.to_bytes();

        // 2. Extract the canonical scalar S value
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&tampered_signature_bytes[32..64]);

        // 3. Define the Ed25519 Curve Group Order L in Little-Endian format
        let curve_order_l = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];

        // 4. Compute S' = S + L.
        // We use modular/overflowing math because if S + L >= 2^256, it wraps around.
        // However, it will still yield a value greater than or equal to L, ensuring an overflow condition.
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = s_bytes[i] as u16 + curve_order_l[i] as u16 + carry;
            s_bytes[i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }

        // 5. Inject the mutated, non-canonical S' scalar back into the signature byte array
        tampered_signature_bytes[32..64].copy_from_slice(&s_bytes);

        let program = format!(
            "(ed25519-verify {} {} {})",
            buff_literal(&message_bytes),
            buff_literal(&tampered_signature_bytes),
            buff_literal(&pubkey_bytes)
        );

        let result = execute_with_parameters(
            program.as_str(),
            ClarityVersion::latest(),
            StacksEpochId::latest(),
            false,
        )
        .expect("execution should succeed")
        .expect("should return a value");

        prop_assert_eq!(Value::Bool(false), result);
    }
}
