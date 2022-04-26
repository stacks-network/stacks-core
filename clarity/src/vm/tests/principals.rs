use crate::vm::execute_with_parameters;
use crate::vm::types::BufferLength;
use crate::vm::types::SequenceSubtype::{BufferType, StringType};
use crate::vm::types::StringSubtype::ASCII;
use crate::vm::types::TypeSignature::{PrincipalType, SequenceType};
use crate::vm::types::{ASCIIData, BuffData, CharType, SequenceData, Value};
use crate::vm::ClarityVersion;

use crate::clarity_vm::database::MemoryBackingStore;
use crate::core::StacksEpochId;
use std::collections::HashMap;
use crate::vm::callables::{DefineType, DefinedFunction};
use crate::vm::costs::LimitedCostTracker;
use crate::vm::errors::{
    CheckErrors, Error, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use crate::vm::eval;
use crate::vm::execute;
use crate::vm::types::{QualifiedContractIdentifier, TypeSignature};
use crate::vm::{
    CallStack, ContractContext, Environment, GlobalContext, LocalContext, SymbolicExpression,
};

#[test]
fn test_simple_is_standard_check_inputs() {
    let wrong_type_test = "(is-standard u10)";
    assert_eq!(
        execute_with_parameters(
            wrong_type_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap_err(),
        CheckErrors::TypeValueError(PrincipalType, Value::UInt(10)).into()
    );
}

#[test]
fn test_simple_is_standard_testnet_cases() {
    let testnet_addr_test = "(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );

    let testnet_addr_test = "(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );

    let testnet_addr_test = "(is-standard 'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );

    let testnet_addr_test = "(is-standard 'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            testnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );
}

fn test_simple_is_standard_mainnet_cases() {
    let mainnet_addr_test = "(is-standard 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            mainnet_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
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
        execute_with_parameters(
            invalid_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            invalid_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );

    let invalid_addr_test = "(is-standard 'S1G2081040G2081040G2081040G208105NK8PE5.tokens)";
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            invalid_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            true
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_with_parameters(
            invalid_addr_test,
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
            false
        )
        .unwrap()
        .unwrap()
    );
}
