use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::hash::{to_hex, Sha256Sum};
use stacks_common::util::secp256k1::MessageSignature as Secp256k1Signature;
use stacks_common::util::secp256r1::{Secp256r1PrivateKey, Secp256r1PublicKey};

use crate::vm::errors::{CheckErrors, Error};
use crate::vm::types::{ResponseData, TypeSignature, Value};
use crate::vm::{execute_with_parameters, ClarityVersion};

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
}

#[test]
fn test_secp256r1_verify_valid_high_s_signature_returns_false() {
    let message = "0xc3abef6a775793dfbc8e0719e7a1de1fc2f90d37a7912b1ce8e300a5a03b06a8";
    let signature = "0xf2b8c0645caa7250e3b96d633cf40a88456e4ffbddffb69200c4e019039dfd31f153a6d5c3dc192a5574f3a261b1b70570971b92d8ebf86c17b7670d13591c4e";
    let pubkey = "0x031e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e";

    let program = format!("(secp256r1-verify {message} {signature} {pubkey})");

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
fn test_secp256r1_verify_invalid_signature_returns_false() {
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
}

#[test]
fn test_secp256r1_verify_signature_too_short_returns_false() {
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
}

#[test]
fn test_secp256r1_verify_signature_too_long_errors() {
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
        Error::Unchecked(CheckErrors::TypeValueError(expected, _)) => {
            assert_eq!(*expected, TypeSignature::BUFFER_64);
        }
        _ => panic!("expected BUFFER_65 type error, found {err:?}"),
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
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
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
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
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
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
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
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
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
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
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
        ClarityVersion::Clarity4,
        StacksEpochId::Epoch33,
        false,
    )
    .unwrap_err();
    match err {
        Error::Unchecked(CheckErrors::TypeValueError(expected, _)) => {
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
            ClarityVersion::Clarity4,
            StacksEpochId::Epoch33,
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
        ClarityVersion::Clarity4,
        StacksEpochId::Epoch33,
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
