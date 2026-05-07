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
use proptest::prelude::*;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::{PrivateKey, PublicKey, StacksEpochId};
use stacks_common::util::hash::{Sha256Sum, hex_bytes, to_hex};
use stacks_common::util::secp256k1::{
    MessageSignature as Secp256k1Signature, Secp256k1PrivateKey, Secp256k1PublicKey,
};
use stacks_common::util::secp256r1::{Secp256r1PrivateKey, Secp256r1PublicKey};

use crate::vm::errors::{ClarityEvalError, RuntimeCheckErrorKind, VmExecutionError};
use crate::vm::types::{BuffData, ResponseData, SequenceData, TypeSignature, Value};
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
fn test_secp256k1_decompress_returns_expected_public_key() {
    let mut sk = StacksPrivateKey::random();
    sk.set_compress_public(true);
    let pk_compressed = StacksPublicKey::from_private(&sk);
    sk.set_compress_public(false);
    let pk_uncompressed = StacksPublicKey::from_private(&sk);

    let program = format!(
        "(secp256k1-decompress? {})",
        buff_literal(&pk_compressed.to_bytes_compressed())
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
            assert_eq!(
                data,
                Box::new(Value::Sequence(SequenceData::Buffer(BuffData {
                    data: pk_uncompressed.to_bytes(),
                })))
            );
        }
        other => panic!("expected ok response, found {other:?}"),
    }
}

#[test]
fn test_secp256k1_decompress_returns_err_on_invalid_public_key() {
    let program = format!("(secp256k1-decompress? {})", buff_literal(&[0x00; 33]));

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
fn test_secp256k1_decompress_returns_err_on_shorter_public_key() {
    let program = format!("(secp256k1-decompress? {})", buff_literal(&[0x00; 32]));

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
            assert_eq!(*expected, TypeSignature::BUFFER_33);
        }
        _ => panic!("expected BUFFER_33 type error, found {err:?}"),
    }
}

#[test]
fn test_secp256k1_decompress_returns_err_on_longer_public_key() {
    let program = format!("(secp256k1-decompress? {})", buff_literal(&[0x00; 34]));

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
            assert_eq!(*expected, TypeSignature::BUFFER_33);
        }
        _ => panic!("expected BUFFER_33 type error, found {err:?}"),
    }
}

#[test]
fn test_secp256k1_decompress_derive_ethereum_address() {
    let compressed_pubkey = Secp256k1PublicKey::from_hex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let program = format!(
        "(unwrap-panic (slice? (keccak256 (unwrap-panic (slice? (unwrap-panic (secp256k1-decompress? {})) u1 u65))) u12 u32))",
        buff_literal(&compressed_pubkey.to_bytes_compressed())
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
        Value::Sequence(SequenceData::Buffer(BuffData { data, .. })) => {
            assert_eq!(
                data,
                hex_bytes("7E5F4552091A69125D5DFCB7B8C2659029395BDF").unwrap()
            );
        }
        other => panic!("expected ok response, found {other:?}"),
    }
}

#[test]
fn test_secp256k1_decompress_with_wormhole_test_pubkeys() {
    let wormhole_keys: Vec<(&str, &str)> = vec![
        (
            "049a1e801daa25d9808e70aae9981353086f958955cc94ef33a461b0e596feaef90a8474dd10cf6ae967143f86105c16d6304a3d268ea952fda9389139d4bb9da1",
            "5893b5a76c3f739645648885bdccc06cd70a3cd3",
        ),
        (
            "042766db08820e311b22e109801ab8ea505b12e3df3d91ebc87c999ffb6929d1abb0ade987c74aa37db26eea4086ee738a2f34a5594edb8760da0eac5be356b731",
            "ff6cb952589bde862c25ef4392132fb9d4a42157",
        ),
        (
            "0454177ff4a8329520b76efd86f8bfce5c942554db16e673267dc1133b3f5e230b2d8cbf90fe274946045d4491de288d736680edc2ee9ee5b1b15416b0a34806c4",
            "114de8460193bdf3a2fcf81f86a09765f4762fd1",
        ),
        (
            "047fa3e98fcc2621337b217b61408a98facaabd25bad2b158438728ce863c14708cfcda1f3b50a16ca0211199079fb338d479a54546ec3c5f775af23a7d7f4fb24",
            "107a0086b32d7a0977926a205131d8731d39cbeb",
        ),
        (
            "040bdcbccc0297c2a4f92a7c39358c42f22a8ed700a78bd05c39c8b61aaf2338e825b6c0d26d1f2a2ae4129cd751201f73d7234c753bd0735212a5288b19748fd2",
            "8c82b2fd82faed2711d59af0f2499d16e726f6b2",
        ),
        (
            "040a872a7c2cfb93710baee3c1a91e7e3050c5a1a04a02873133b456c24f25d88b861a21afb9cbfc55be9608356b7cd2a7db8eddd86190206ae6147e47e601a625",
            "42579bffbcf4276e290ab8e4c162bd4052b97970",
        ),
        (
            "04b1afbe24acb53ac1306f3bdde910f554e06d374efee41598fbd403557c3114b5af6d363bfbd78af16a258844041e04f6dfe67fe62f305e6097c6ece48ccc92c4",
            "938f104aeb5581293216ce97d771e0cb721221b1",
        ),
        (
            "0467d211cc0c1324606495d10100d3b629d5d4d83dca1e15b9842bad4b7b1d38db29cc9e0c41e0886232998333efa34b943b32a8fc588b1ab2be4c92348808ef7d",
            "18e41674ccf26329cd111406c1d05c6c80b23edc",
        ),
        (
            "04838aba2428289fe2b798e32db1396a856c0d0c671d9b1f5a55fc0e8eb072de8c757ff6a79699d1a76df64c2ca1758a4f2c4872d2720f4332cea6dcf678f2bef3",
            "9d16870160e703324d057c3361c34c5befba2c34",
        ),
        (
            "04d9fa78b5b958bea1929080b8ad96dc555d34b051a27aebf711eb1186b807b0448316d994606ac807121838d6c41a58f308bc6307acdf69491fa4b17282f3e66f",
            "000ac0076727b35fbea2dac28fee5ccb0fea768e",
        ),
        (
            "04cc64af75ec2e2741fb9af9f6191cb9ee187d6d26af4d1e96d7bab47e6ec09be12d3192030dc4bbf54d1da319a7a2acfc7a9dd4c644af6646a4aaa02b1024bbab",
            "af45ced136b9d9e24903464ae889f5c8a723fc14",
        ),
        (
            "04b5943b6e284682ad2e011d6962d41febf86af2f5fc0c9c8f4b81358ff077f9c96ba0880eaf93541eae94b4fa41dba66dab7fb0201cc9af7c75681e5719b0c95f",
            "f93124b7c738843cbb89e864c862c38cddcccf95",
        ),
        (
            "040cfc9d5b5dcf702a1525f9d4ed1841e8eb8b34434cc82470dd35435f1dbdc73ffb51544b7500394eac9c7fa567868b495326075147a2d809ebbfd43273eeec91",
            "d2cc37a4dc036a8d232b48f62cdd4731412f4890",
        ),
        (
            "040aa78894d894a15933969f5826347439e2c309f2049277a10066c9197840499498ad19ee3d1b291f932ec0890bbdafcec292c4f02a446670cd0084f997e25e2f",
            "da798f6896a3331f64b48c12d1d57fd9cbe70811",
        ),
        (
            "049caaefc70b0491eca9782cbba710d93cdf5cf7e28c892621a867ab08b684ed5ab4ea5cd8f3e14724a94b146e8ab0bc07d72b5295593248eb6f33ae0f2865eb29",
            "d1f64e26238811de5553c40f64af41ee1b6057cc",
        ),
        (
            "04cc8705b669a9c20e44e3c3a646f3235851cb199c7b2423555a59118bd976c64a1aaead56499c52fb92515e26032a52a9edf7c668acec1af7e2d4fe3266a65ebb",
            "3f851ad586a47cef8d04748f33ab0d71395f06b4",
        ),
        (
            "044881345cbb299fa7c60ab2d16cb7fe7bf8d14675506ef6eb6037038b5b7092ea0a9e4d0b53ba3904edd99f86717d6ba81dffe44eb5b23c6fd22c91ab73c33021",
            "178e21ad2e77ae06711549cfbb1f9c7a9d8096e8",
        ),
        (
            "04fe7e6f982e4f74234e7ed3b49ce96b7dd7cf838a4cae13d9c25c67a38eec75a7c03bf6072f712c88935f128d1e5e9c7515c1f894f59a7f6c839ad1829ab0adac",
            "7899ceab1dc961dae9defdb7a4f521269a5448fc",
        ),
        (
            "0421f338444e96af31cf44958acf5764844efbddace3b823ed761c340c59ed2685d829818c83eebe8f00f783f1048a53515845536668a9e0c059ade7579a0f4204",
            "6fbebc898f403e4773e95feb15e80c9a99c8348d",
        ),
    ];

    for (pubkey, ethereum_address) in wormhole_keys {
        let mut uncompressed_pubkey = Secp256k1PublicKey::from_hex(pubkey).unwrap();
        uncompressed_pubkey.set_compressed(true);
        let program: String = format!(
            "(unwrap-panic (slice? (keccak256 (unwrap-panic (slice? (unwrap-panic (secp256k1-decompress? {})) u1 u65))) u12 u32))",
            buff_literal(&uncompressed_pubkey.to_bytes_compressed())
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
            Value::Sequence(SequenceData::Buffer(BuffData { data, .. })) => {
                assert_eq!(data, hex_bytes(ethereum_address).unwrap());
            }
            other => panic!("expected ok response, found {other:?}"),
        }
    }
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
    fn prop_secp256k1_decompress_matches_public_key(
        seed in any::<[u8; 32]>(),
    ) {
        let mut privk = Secp256k1PrivateKey::from_seed(&seed);

        privk.set_compress_public(true);
        let pubkey_compressed_bytes = Secp256k1PublicKey::from_private(&privk).to_bytes_compressed();

        privk.set_compress_public(false);
        let pubkey_uncompressed_bytes = Secp256k1PublicKey::from_private(&privk).to_bytes();

        let program = format!(
            "(is-eq (unwrap! (secp256k1-decompress? {}) (err u1)) {})",
            buff_literal(&pubkey_compressed_bytes),
            buff_literal(&pubkey_uncompressed_bytes),
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
}
