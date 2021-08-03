use std::convert::TryFrom;
use util::hash::hex_bytes;
use vm::execute_against_version_and_network;
use vm::types::BufferLength;
use vm::types::SequenceSubtype::{BufferType, StringType};
use vm::types::StringSubtype::ASCII;
use vm::types::TypeSignature::{PrincipalType, SequenceType};
use vm::types::{
    ASCIIData, BuffData, CharType, PrincipalData, SequenceData, StandardPrincipalData, TupleData,
    Value,
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
use vm::representations::ClarityName;
use vm::types::{QualifiedContractIdentifier, TupleTypeSignature, TypeSignature};
use vm::{
    CallStack, ContractContext, Environment, GlobalContext, LocalContext, SymbolicExpression,
};

pub use vm::types::signatures::{BUFF_1, BUFF_20};

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

#[test]
fn test_parse_principal_good() {
    // Test that we can parse well-formed principals.
    
    // ST is testnet singlesig.
    let testnet_addr_test = r#"(parse-principal 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)"#;
    assert_eq!(
        Value::Tuple(
            TupleData::from_data(vec![
                (
                    "version".into(),
                    Value::Sequence(SequenceData::Buffer(BuffData {
                        data: hex_bytes("1a").unwrap(),
                    })),
                ),
                (
                    "hashbytes".into(),
                    Value::Sequence(SequenceData::Buffer(BuffData {
                        data: hex_bytes("164247d6f2b425ac5771423ae6c80c754f7172b0").unwrap(),
                    })),
                ),
            ])
            .expect("FAIL: Failed to initialize tuple.")
        ),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );
}

#[test]
fn test_parse_principal_bad_version_byte() {
    // Test that we fail on principals that do not correspond to valid version bytes.

    // SZ is not a valid prefix for any Stacks network.
    let testnet_addr_test = r#"(parse-principal 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#;
    assert_eq!(
        Err(CheckErrors::InvalidVersionByte.into()),
        execute_against_version_and_network(testnet_addr_test, ClarityVersion::Clarity2, false)
    );
}

#[test]
fn test_principal_construct_good() {
    // Standard case where construction should work.  We compare the output of the
    // Clarity function to hand-built principals.

    // Assmble the bytes buffer.
    let bytes = hex_bytes("fa6bf38ed557fe417333710d6033e9419391a320").unwrap();
    let mut transfer_buffer = [0u8; 20];
    for i in 0..bytes.len() {
        transfer_buffer[i] = bytes[i];
    }

    // Mainnet singlesig.
    let input = r#"(principal-construct 0x16 0xfa6bf38ed557fe417333710d6033e9419391a320)"#;
    assert_eq!(
        Value::Principal(PrincipalData::Standard(StandardPrincipalData(
            22,
            transfer_buffer
        ))),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
            .unwrap()
            .unwrap()
    );

    // Mainnet multisig.
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

    // Testnet singlesig.
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

    // Testnet multisig.
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

#[test]
fn test_principal_construct_bad_version_byte() {
    // Test case where the version byte is bad.

    // Failure because the version byte 0xef is invalid.
    let input =
        r#"(principal-construct 0xef 0x0102030405060708091011121314151617181920)"#;
    let bytes = hex_bytes("0102030405060708091011121314151617181920").unwrap();
    assert_eq!(
        Err(CheckErrors::InvalidVersionByte.into()),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
    );

    // Failure because the version byte 0x5904934 is invalid.
    let input =
        r#"(principal-construct 0x590493 0x0102030405060708091011121314151617181920)"#;
    let bytes = hex_bytes("0102030405060708091011121314151617181920").unwrap();
    let mut transfer_buffer = [0u8; 20];
    for i in 0..bytes.len() {
        transfer_buffer[i] = bytes[i];
    }
    assert_eq!(
        Err(CheckErrors::TypeValueError(SequenceType(BufferType(BufferLength(1))), Value::Sequence(SequenceData::Buffer(BuffData {data: hex_bytes("590493").unwrap()}))).into()),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
    );

    // Failure because the version byte 0xef is invalid.
    let input =
        r#"(principal-construct u22 0x0102030405060708091011121314151617181920)"#;
    let bytes = hex_bytes("0102030405060708091011121314151617181920").unwrap();
    let mut transfer_buffer = [0u8; 20];
    for i in 0..bytes.len() {
        transfer_buffer[i] = bytes[i];
    }
    assert_eq!(
        Err(CheckErrors::TypeValueError(TypeSignature::UIntType, Value::UInt(22)).into()),
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false)
    );
}

#[test]
fn test_principal_construct_buffer_wrong_size() {
    // Tests cases in which the input buffers are too small. This cannot be caught
    // by the type checker, because `(buff N)` is a sub-type of `(buff M)` if `N < M`.

    // Version byte is too small.
    let input = r#"(principal-construct 0x 0x0102030405060708091011121314151617181920)"#;
    assert_eq!(
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false).unwrap_err(),
        CheckErrors::TypeValueError(
            SequenceType(BufferType(BufferLength(1))),
            Value::Sequence(SequenceData::Buffer(BuffData { data: vec![] }))
        )
        .into()
    );

    // Hash key part is too small.
    let input = r#"(principal-construct 0x16 0x01020304050607080910111213141516171819)"#;
    assert_eq!(
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false).unwrap_err(),
        CheckErrors::TypeValueError(
            SequenceType(BufferType(BufferLength(20))),
            Value::Sequence(SequenceData::Buffer(BuffData {
                data: hex_bytes("01020304050607080910111213141516171819").unwrap()
            }))
        )
        .into()
    );

    // Hash key part is too large.
    let input = r#"(principal-construct 0x16 0x010203040506070809101112131415161718192021)"#;
    assert_eq!(
        execute_against_version_and_network(input, ClarityVersion::Clarity2, false).unwrap_err(),
        CheckErrors::TypeValueError(
            SequenceType(BufferType(BufferLength(20))),
            Value::Sequence(SequenceData::Buffer(BuffData {
                data: hex_bytes("010203040506070809101112131415161718192021").unwrap()
            }))
        )
        .into()
    );
}