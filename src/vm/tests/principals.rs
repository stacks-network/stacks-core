use vm::execute_program_with_context;
use vm::types::BufferLength;
use vm::types::SequenceSubtype::{BufferType, StringType};
use vm::types::StringSubtype::ASCII;
use vm::types::TypeSignature::{PrincipalType, SequenceType};
use vm::types::{ASCIIData, BuffData, CharType, SequenceData, Value};
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
use vm::types::{QualifiedContractIdentifier, TypeSignature};
use vm::{
    CallStack, ContractContext, Environment, GlobalContext, LocalContext, SymbolicExpression,
};

pub fn execute_against_mainnet(program: &str, as_mainnet: bool) -> Result<Option<Value>> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone(), ClarityVersion::Clarity2);
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(as_mainnet, conn, LimitedCostTracker::new_free());
    execute_program_with_context(program, contract_id, contract_context, global_context)
}

#[test]
fn test_simple_principal_check_inputs() {
    let wrong_type_test = "(is-standard u10)";
    assert_eq!(
        execute_against_mainnet(wrong_type_test, false).unwrap_err(),
        CheckErrors::TypeValueError(PrincipalType, Value::UInt(10)).into()
    );
}

#[test]
fn test_simple_principal_testnet_cases() {
    let testnet_addr_test = "(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(testnet_addr_test, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(testnet_addr_test, true)
            .unwrap()
            .unwrap()
    );

    let testnet_addr_test = "(is-standard 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(testnet_addr_test, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(testnet_addr_test, true)
            .unwrap()
            .unwrap()
    );

    let testnet_addr_test = "(is-standard 'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(testnet_addr_test, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(testnet_addr_test, true)
            .unwrap()
            .unwrap()
    );

    let testnet_addr_test = "(is-standard 'SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(testnet_addr_test, false)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(testnet_addr_test, true)
            .unwrap()
            .unwrap()
    );
}

fn test_simple_principal_mainnet_cases() {
    let mainnet_addr_test = "(is-standard 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(mainnet_addr_test, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(mainnet_addr_test, false)
            .unwrap()
            .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(mainnet_addr_test, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(mainnet_addr_test, false)
            .unwrap()
            .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(mainnet_addr_test, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(mainnet_addr_test, false)
            .unwrap()
            .unwrap()
    );

    let mainnet_addr_test = "(is-standard 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(
        Value::Bool(true),
        execute_against_mainnet(mainnet_addr_test, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(mainnet_addr_test, false)
            .unwrap()
            .unwrap()
    );
}

#[test]
fn test_simple_principal_undefined_cases() {
    // When an address is neither a testnet nor a mainnet address, the result should be false.
    let invalid_addr_test = "(is-standard 'S1G2081040G2081040G2081040G208105NK8PE5)";
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(invalid_addr_test, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(invalid_addr_test, false)
            .unwrap()
            .unwrap()
    );

    let invalid_addr_test = "(is-standard 'S1G2081040G2081040G2081040G208105NK8PE5.tokens)";
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(invalid_addr_test, true)
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        Value::Bool(false),
        execute_against_mainnet(invalid_addr_test, false)
            .unwrap()
            .unwrap()
    );
}
