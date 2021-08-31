use std::convert::TryFrom;
use util::hash::hex_bytes;
use vm::execute_against_version_and_network;
use vm::types::BufferLength;
use vm::types::SequenceSubtype::{BufferType, StringType};
use vm::types::StringSubtype::ASCII;
use vm::types::TypeSignature::{PrincipalType, SequenceType};
use vm::types::{
    BuffData, PrincipalData, ResponseData, SequenceData, StandardPrincipalData, TupleData, Value,
};
use vm::ClarityVersion;

use crate::clarity_vm::database::MemoryBackingStore;
use std::collections::HashMap;
use vm::callables::{DefineType, DefinedFunction};
use vm::costs::LimitedCostTracker;
use vm::errors::{
    CheckErrors, Error, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use vm::eval;
use vm::execute;
use vm::types::TypeSignature;
use vm::{
    CallStack, ContractContext, Environment, GlobalContext, LocalContext, SymbolicExpression,
};

#[test]
fn test_simple_is_standard_check_inputs() {
    let wrong_type_test = "(is-standard u10)";
    assert_eq!(
        execute_against_version_and_network(wrong_type_test, ClarityVersion::Clarity2, true)
            .unwrap_err(),
        CheckErrors::TypeValueError(PrincipalType, Value::UInt(10)).into()
    );
}

#[test]
fn test_simple_is_standard_testnet_cases() {
    let testnet_addr_test = "(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );

    let testnet_addr_test = "(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );

    let testnet_addr_test = "(is-standard 'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );

    let testnet_addr_test = "(is-standard 'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );
}

fn test_simple_is_standard_mainnet_cases() {
    let mainnet_addr_test = "(is-standard 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(mainnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
}

#[test]
fn test_simple_is_standard_undefined_cases() {
    // When an address is neither a testnet nor a mainnet address, the result should be false.
    let invalid_addr_test = "(is-standard 'S1G2081040G2081040G2081040G208105NK8PE5)";
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(invalid_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(invalid_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    let invalid_addr_test = "(is-standard 'S1G2081040G2081040G2081040G208105NK8PE5.tokens)";
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(invalid_addr_test, ClarityVersion::Clarity2, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_version_and_network(invalid_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
}

/// Creates a Tuple which is the result of parsing a Principal tuple into a Tuple of its `version`
/// and `hash-bytes`.
fn create_principal_parse_tuple_from_strings(version: &str, hash_bytes: &str) -> Value {
    Value::Tuple(
        TupleData::from_data(vec![
            (
                "version".into(),
                Value::Sequence(SequenceData::Buffer(BuffData {
                    data: hex_bytes(version).unwrap(),
                })),
            ),
            (
                "hash-bytes".into(),
                Value::Sequence(SequenceData::Buffer(BuffData {
                    data: hex_bytes(hash_bytes).unwrap(),
                })),
            ),
        ])
        .expect("FAIL: Failed to initialize tuple."),
    )
}

#[test]
// Test that we can parse well-formed principals.
fn test_principal_parse_good() {
    // SP is mainnet single-sig.
    let input = r#"(principal-parse 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)"#;
    assert_eq!(
        create_principal_parse_tuple_from_strings("16", "fa6bf38ed557fe417333710d6033e9419391a320"),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    // SM is mainnet multi-sig.
    let input = r#"(principal-parse 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D341M9C5X7)"#;
    assert_eq!(
        create_principal_parse_tuple_from_strings("14", "fa6bf38ed557fe417333710d6033e9419391a320"),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    // ST is testnet single-sig.
    let input = r#"(principal-parse 'ST3X6QWWETNBZWGBK6DRGTR1KX50S74D3425Q1TPK)"#;
    assert_eq!(
        create_principal_parse_tuple_from_strings("1a", "fa6bf38ed557fe417333710d6033e9419391a320"),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    // SN is testnet multi-sig.
    let input = r#"(principal-parse 'SN3X6QWWETNBZWGBK6DRGTR1KX50S74D340JWTSC7)"#;
    assert_eq!(
        create_principal_parse_tuple_from_strings("15", "fa6bf38ed557fe417333710d6033e9419391a320"),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
}

#[test]
// Test that we fail on principals that do not correspond to valid version bytes.
fn test_principal_parse_bad_version_byte() {
    // SZ is not a valid prefix for any Stacks network.
    let testnet_addr_test = r#"(principal-parse 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#;
    assert_eq!(
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(Value::Tuple(
                TupleData::from_data(vec![
                    ("error_int".into(), Value::UInt(2 as u128)),
                    (
                        "value".into(),
                        Value::some(create_principal_parse_tuple_from_strings(
                            "1f",
                            "a46ff88886c2ef9762d970b4d2c63678835bd39d"
                        ))
                        .expect("Value::some failed.")
                    ),
                ])
                .expect("FAIL: Failed to initialize tuple."),
            )),
        }),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
}

#[test]
// Standard case where construction should work.  We compare the output of the
// Clarity function to hand-built principals.
fn test_principal_construct_good() {
    // We always use the the same bytes buffer.
    let bytes = hex_bytes("fa6bf38ed557fe417333710d6033e9419391a320").unwrap();
    let mut transfer_buffer = [0u8; 20];
    for i in 0..bytes.len() {
        transfer_buffer[i] = bytes[i];
    }

    // Mainnet single-sig.
    let input = r#"(principal-construct 0x16 0xfa6bf38ed557fe417333710d6033e9419391a320)"#;
    assert_eq!(
        Value::Principal(PrincipalData::Standard(
                StandardPrincipalData(22, transfer_buffer)
            ))
        ,
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    // Mainnet multi-sig.
    let input = r#"(principal-construct 0x14 0xfa6bf38ed557fe417333710d6033e9419391a320)"#;
    assert_eq!(
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(
            20,
            transfer_buffer
        ))),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    // Testnet single-sig.
    let input = r#"(principal-construct 0x1a 0xfa6bf38ed557fe417333710d6033e9419391a320)"#;
    assert_eq!(
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(
            26,
            transfer_buffer
        ))),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    // Testnet multi-sig.
    let input = r#"(principal-construct 0x15 0xfa6bf38ed557fe417333710d6033e9419391a320)"#;
    assert_eq!(
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(
            21,
            transfer_buffer
        ))),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
}
//
//#[test]
//// Test cases where the version byte is of the right type `(buff 1)`, but where the byte doesn't
//// match a recognized network. This is meant for compatibility with "future" network bytes, so
//// is still valid.
//fn test_principal_construct_version_byte_future() {
//    // The version byte 0xef is invalid.
//    let input = r#"(principal-construct 0xef 0x0102030405060708091011121314151617181920)"#;
//    assert_eq!(
//        create_principal_parse_response("ef", "0102030405060708091011121314151617181920", false),
//        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
//            .unwrap()
//            .unwrap()
//    );
//}
//
//// Test cases in which the version byte is not of the right type `(buff 1)`, and so isn't valid,
//// even in the future.
//fn test_principal_construct_version_byte_inadmissible() {
//    // The version bytes 0x5904934 are invalid.
//    let input = r#"(principal-construct 0x590493 0x0102030405060708091011121314151617181920)"#;
//    assert_eq!(
//        Err(CheckErrors::TypeValueError(
//            SequenceType(BufferType(BufferLength(1))),
//            Value::Sequence(SequenceData::Buffer(BuffData {
//                data: hex_bytes("590493").unwrap()
//            }))
//        )
//        .into()),
//        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
//    );
//
//    // u22 is not a byte buffer, so is invalid.
//    let input = r#"(principal-construct u22 0x0102030405060708091011121314151617181920)"#;
//    assert_eq!(
//        Err(CheckErrors::TypeValueError(TypeSignature::UIntType, Value::UInt(22)).into()),
//        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
//    );
//}
//
//#[test]
//// Tests cases in which the input buffers are too small. This cannot be caught
//// by the type checker, because `(buff N)` is a sub-type of `(buff M)` if `N < M`.
//fn test_principal_construct_buffer_wrong_size() {
//    // Version byte is too small, should have length 1.
//    let input = r#"(principal-construct 0x 0x0102030405060708091011121314151617181920)"#;
//    assert_eq!(
//        execute_against_version_and_network(input, ClarityVersion::Clarity2, false).unwrap_err(),
//        CheckErrors::TypeValueError(
//            SequenceType(BufferType(BufferLength(1))),
//            Value::Sequence(SequenceData::Buffer(BuffData { data: vec![] }))
//        )
//        .into()
//    );
//
//    // Hash key part is too small, should have length 20.
//    let input = r#"(principal-construct 0x16 0x01020304050607080910111213141516171819)"#;
//    assert_eq!(
//        execute_against_version_and_network(input, ClarityVersion::Clarity2, false).unwrap_err(),
//        CheckErrors::TypeValueError(
//            SequenceType(BufferType(BufferLength(20))),
//            Value::Sequence(SequenceData::Buffer(BuffData {
//                data: hex_bytes("01020304050607080910111213141516171819").unwrap()
//            }))
//        )
//        .into()
//    );
//
//    // Hash key part is too large, should have length 20.
//    let input = r#"(principal-construct 0x16 0x010203040506070809101112131415161718192021)"#;
//    assert_eq!(
//        execute_against_version_and_network(input, ClarityVersion::Clarity2, false).unwrap_err(),
//        CheckErrors::TypeValueError(
//            SequenceType(BufferType(BufferLength(20))),
//            Value::Sequence(SequenceData::Buffer(BuffData {
//                data: hex_bytes("010203040506070809101112131415161718192021").unwrap()
//            }))
//        )
//        .into()
//    );
//}
