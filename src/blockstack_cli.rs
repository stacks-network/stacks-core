#![allow(unused_imports)]
#![allow(unused_assignments)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate blockstack_lib;

use std::env;
use std::convert::TryFrom;
use blockstack_lib::util::{log, strings::StacksString};
use blockstack_lib::vm::{
    Value, ClarityName, ContractName, errors::RuntimeErrorType, errors::Error as ClarityError };
use blockstack_lib::chainstate::stacks::{
    StacksPrivateKey,
    StacksTransaction, TransactionSmartContract, TransactionContractCall, StacksAddress };
use blockstack_lib::burnchains::Address;
use blockstack_lib::net::StacksMessageCodec;

enum CliError {
    ClarityRuntimeError(RuntimeErrorType),
    ClarityGeneralError(ClarityError),
    Message(String),
}

impl From<&str> for CliError {
    fn from(value: &str) -> Self {
        CliError::Message(value.into())
    }
}

impl From<RuntimeErrorType> for CliError {
    fn from(value: RuntimeErrorType) -> Self {
        CliError::ClarityRuntimeError(value)
    }
}

impl From<ClarityError> for CliError {
    fn from(value: ClarityError) -> Self {
        CliError::ClarityGeneralError(value)
    }
}

fn make_contract_publish(contract_name: String, contract_content: String) -> Result<TransactionSmartContract, CliError> {
    let name = ContractName::try_from(contract_name)?;
    let code_body = StacksString::from_string(&contract_content)
        .ok_or("Non-legal characters in contract-content")?;
    Ok(TransactionSmartContract { name, code_body })
}

fn make_contract_call(contract_address: String, contract_name: String, function_name: String, args: Vec<String>) -> Result<TransactionContractCall, CliError> {
    let address = StacksAddress::from_string(&contract_address)
        .ok_or("Failed to parse contract address")?;
    let contract_name = ContractName::try_from(contract_name)?;
    let function_name = ClarityName::try_from(function_name)?;

    // note: as this CLI develops the ability to query for state information,
    //        we should be able to typecheck the arguments before supplying them here.
    let function_args: Result<Vec<_>, ClarityError> = args.iter()
        .map(|x| Value::try_deserialize_untyped(&x))
        .collect();
    let function_args = function_args?;

    Ok(TransactionContractCall {
        address, contract_name, function_name, function_args
    })
}

fn sign_transaction_single_sig_standard(transaction: &str, secret_key: &str) -> Result<(), CliError> {
    let transaction = StacksTransaction::deserialize(&transaction.as_bytes().to_vec(), &mut 0, u32::max_value());
    let secret_key = StacksPrivateKey::from_hex(secret_key)?;
    Ok(())
}

fn main() {
    log::set_loglevel(log::LOG_DEBUG).unwrap();
    let argv : Vec<String> = env::args().collect();
}
