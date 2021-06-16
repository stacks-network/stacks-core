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

pub fn execute_against_mainnet(program: &str, as_mainnet:bool) -> Result<Option<Value>> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone(), ClarityVersion::Clarity2);
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(as_mainnet, conn, LimitedCostTracker::new_free());
    execute_program_with_context(program, contract_id, contract_context, global_context)
}

#[test]
fn test_simple_principal_check_inputs() {
    let wrong_type_test = "(principal-matches u10)";
    assert_eq!(
        execute_against_mainnet(wrong_type_test, false).unwrap_err(),
        CheckErrors::TypeValueError(PrincipalType, Value::UInt(10)).into()
    );
}

#[test]
fn test_simple_principal_testnet_cases() {
    let testnet_addr_test = "(principal-matches 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(testnet_addr_test, false).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(testnet_addr_test, true).unwrap().unwrap());

    let testnet_addr_test = "(principal-matches 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6.tokens)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(testnet_addr_test, false).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(testnet_addr_test, true).unwrap().unwrap());

    let testnet_addr_test = "(principal-matches 'SNB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(testnet_addr_test, false).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(testnet_addr_test, true).unwrap().unwrap());

    let testnet_addr_test = "(principal-matches 'SNB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6.tokens)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(testnet_addr_test, false).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(testnet_addr_test, true).unwrap().unwrap());
}

fn test_simple_principal_mainnet_cases() {
    let mainnet_addr_test = "(principal-matches 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(mainnet_addr_test, true).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(mainnet_addr_test, false).unwrap().unwrap());

    let mainnet_addr_test = "(principal-matches 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(mainnet_addr_test, true).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(mainnet_addr_test, false).unwrap().unwrap());

    let mainnet_addr_test = "(principal-matches 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(mainnet_addr_test, true).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(mainnet_addr_test, false).unwrap().unwrap());

    let mainnet_addr_test = "(principal-matches 'SM3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY.tokens)";
    assert_eq!(Value::Bool(true), execute_against_mainnet(mainnet_addr_test, true).unwrap().unwrap());
    assert_eq!(Value::Bool(false), execute_against_mainnet(mainnet_addr_test, false).unwrap().unwrap());
}

// fn test_simple_principal_main_cases2() {
//     let good1_test = "(principal-matches 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.tokens)";
//     let good1_expected = Value::Bool(true);
//     assert_eq!(good1_expected, execute_against_mainnet(good1_test, false).unwrap().unwrap());

// }

//     let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
//     let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");
//     let p3 = execute("'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY");
