#![allow(unused_imports)]
#![allow(unused_assignments)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate blockstack_lib;

use std::{io, fs, env};
use std::convert::TryFrom;
use std::io::Read;
use blockstack_lib::util::{log, strings::StacksString, hash::hex_bytes, hash::to_hex};
use blockstack_lib::vm;
use blockstack_lib::vm::{
    Value, ClarityName, ContractName, errors::RuntimeErrorType, errors::Error as ClarityError };
use blockstack_lib::chainstate::stacks::{
    StacksPrivateKey, TransactionSpendingCondition, TransactionAuth, TransactionVersion,
    StacksPublicKey, TransactionPayload, StacksTransactionSigner,
    StacksTransaction, TransactionSmartContract, TransactionContractCall, StacksAddress };
use blockstack_lib::burnchains::Address;
use blockstack_lib::net::{Error as NetError, StacksMessageCodec};

const USAGE: &str = "blockstack-cli (options) [method] [args...]

This CLI allows you to generate simple signed transactions for blockstack-core
to process.

This CLI has two methods:

  publish          used to generate and sign a contract publish transaction
  contract-call    used to generate and sign a contract-call transaction

For usage information on those methods, call `blockstack-cli [method] -h`

`blockstack-cli` accepts flag options as well:

   --testnet       instruct the transaction generator to use a testnet version byte instead of MAINNET (default)

";

const PUBLISH_USAGE: &str = "blockstack-cli (options) publish [publisher-secret-key-hex] [fee-rate] [nonce] [contract-name] [file-name.clar]

The publish command generates and signs a contract publish transaction. If successful,
this command outputs the hex string encoding of the transaction to stdout, and exits with
code 0";

const CALL_USAGE: &str = "blockstack-cli (options) contract-call [origin-secret-key-hex] [fee-rate] [nonce] [contract-publisher-address] [contract-name] [function-name] [args...]

The contract-call command generates and signs a contract-call transaction. If successful,
this command outputs the hex string encoding of the transaction to stdout, and exits with
code 0

Arguments are supplied in one of two ways: through script evaluation or via hex encoding
of the value serialization format. The method for supplying arguments is chosen by
prefacing each argument with a flag:

  -e  indicates the argument should be _evaluated_
  -x  indicates the argument is supplied as a hexstring of the value serialization

e.g.,

   blockstack-cli contract-call $secret_key SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4 foo-contract \\
      transfer-fookens -e \\'SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4 \\
                       -e \"(+ 1 2)\" \\
                       -x 0000000000000000000000000000000001 \\
                       -x 050011deadbeef11ababffff11deadbeef11ababffff
";

#[derive(Debug)]
enum CliError {
    ClarityRuntimeError(RuntimeErrorType),
    ClarityGeneralError(ClarityError),
    Message(String),
    Usage,
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::ClarityRuntimeError(e) => Some(e),
            CliError::ClarityGeneralError(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::ClarityRuntimeError(e) => write!(f, "Clarity error: {:?}", e), 
            CliError::ClarityGeneralError(e) => write!(f, "Clarity error: {}", e), 
            CliError::Message(e) => write!(f, "{}", e),
            CliError::Usage => write!(f, "{}", USAGE),
        }
    }
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

impl From<NetError> for CliError {
    fn from(value: NetError) -> Self {
        CliError::Message(format!("Stacks NetError: {}", value))
    }
}

impl From<std::num::ParseIntError> for CliError {
    fn from(value: std::num::ParseIntError) -> Self {
        CliError::Message(format!("Failed to parse integer: {}", value))
    }
}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        CliError::Message(format!("IO error reading CLI input: {}", value))
    }
}

impl From<blockstack_lib::util::HexError> for CliError {
    fn from(value: blockstack_lib::util::HexError) -> Self {
        CliError::Message(format!("Bad hex string supplied: {}", value))
    }
}

fn make_contract_publish(contract_name: String, contract_content: String) -> Result<TransactionSmartContract, CliError> {
    let name = ContractName::try_from(contract_name)?;
    let code_body = StacksString::from_string(&contract_content)
        .ok_or("Non-legal characters in contract-content")?;
    Ok(TransactionSmartContract { name, code_body })
}

fn make_contract_call(contract_address: String, contract_name: String, function_name: String, function_args: Vec<Value>) -> Result<TransactionContractCall, CliError> {
    let address = StacksAddress::from_string(&contract_address)
        .ok_or("Failed to parse contract address")?;
    let contract_name = ContractName::try_from(contract_name)?;
    let function_name = ClarityName::try_from(function_name)?;

    Ok(TransactionContractCall {
        address, contract_name, function_name, function_args
    })
}


fn make_standard_single_sig_tx(version: TransactionVersion, payload: TransactionPayload,
                               publicKey: &StacksPublicKey, nonce: u64, fee_rate: u64) -> StacksTransaction {
    let mut spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(publicKey.clone())
        .expect("Failed to create p2pkh spending condition from public key.");
    spending_condition.set_nonce(nonce);
    spending_condition.set_fee_rate(fee_rate);
    let auth = TransactionAuth::Standard(spending_condition);
    StacksTransaction::new(version, auth, payload)
}

fn sign_transaction_single_sig_standard(transaction: &str, secret_key: &StacksPrivateKey) -> Result<StacksTransaction, CliError> {
    let transaction = StacksTransaction::deserialize(&hex_bytes(transaction)?, &mut 0, u32::max_value())?;

    let mut tx_signer = StacksTransactionSigner::new(&transaction);
    tx_signer.sign_origin(secret_key)?;

    Ok(tx_signer.get_tx()
       .ok_or("TX did not finish signing -- was this a standard single signature transaction?")?)
}

fn handle_contract_publish(args: &[String], version: TransactionVersion) -> Result<(), CliError> {
    if args.len() > 1 && args[0] == "-h" {
        return Err(CliError::Message(format!("USAGE:\n {}", PUBLISH_USAGE)))
    }
    if args.len() != 5 {
        return Err(CliError::Message(format!("Incorrect argument count supplied \n\nUSAGE:\n {}", PUBLISH_USAGE)))
    }
    let sk_publisher = &args[0];
    let fee_rate = args[1].parse()?;
    let nonce = args[2].parse()?;
    let contract_name = &args[3];
    let contract_file = &args[4];

    let contract_contents = if contract_file == "-" {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        fs::read_to_string(contract_file)?
    };

    let sk_publisher = StacksPrivateKey::from_hex(sk_publisher)?;

    let payload = make_contract_publish(contract_name.clone(), contract_contents)?;
    let unsigned_tx = make_standard_single_sig_tx(version, payload.into(), &StacksPublicKey::from_private(&sk_publisher),
                                                  nonce, fee_rate);
    let signed_tx = sign_transaction_single_sig_standard(
        &to_hex(&unsigned_tx.serialize()), &sk_publisher)?;

    println!("{}", to_hex(&signed_tx.serialize()));

    Ok(())
}

fn handle_contract_call(args: &[String], version: TransactionVersion) -> Result<(), CliError> {
    if args.len() > 1 && args[0] == "-h" {
        return Err(CliError::Message(format!("USAGE:\n {}", CALL_USAGE)))
    }
    if args.len() < 6 {
        return Err(CliError::Message(format!("Incorrect argument count supplied \n\nUSAGE:\n {}", CALL_USAGE)))
    }
    let sk_origin = &args[0];
    let fee_rate = args[1].parse()?;
    let nonce = args[2].parse()?;
    let contract_address = &args[3];
    let contract_name = &args[4];
    let function_name = &args[5];

    let val_args = &args[6..];

    if val_args.len() % 2 != 0 {
        return Err("contract-call arguments must be supplied as a list of `-e ...` or `-x 0000...` pairs".into())
    }

    let mut arg_iterator = 0;
    let mut values = Vec::new();
    while arg_iterator < val_args.len() {
        let eval_method = &val_args[arg_iterator];
        let input = &val_args[arg_iterator+1];
        let value = match eval_method.as_str() {
            "-x" => {
                Value::try_deserialize_untyped(input)?
            },
            "-e" => {
                vm::execute(input)?
                    .ok_or("Supplied argument did not evaluate to a Value")?
            },
            _ => {
                return Err("contract-call arguments must be supplied as a list of `-e ...` or `-x 0000...` pairs".into())
            }
        };

        values.push(value);
        arg_iterator += 2;
    }

    let sk_origin = StacksPrivateKey::from_hex(sk_origin)?;

    let payload = make_contract_call(contract_address.clone(), contract_name.clone(), function_name.clone(), values)?;
    let unsigned_tx = make_standard_single_sig_tx(version, payload.into(), &StacksPublicKey::from_private(&sk_origin),
                                                  nonce, fee_rate);
    let signed_tx = sign_transaction_single_sig_standard(
        &to_hex(&unsigned_tx.serialize()), &sk_origin)?;

    println!("{}", to_hex(&signed_tx.serialize()));

    Ok(())
}

fn main() {
    log::set_loglevel(log::LOG_DEBUG).unwrap();
    let argv : Vec<String> = env::args().collect();

    match main_handler(argv) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

fn main_handler(mut argv: Vec<String>) -> Result<(), CliError> {
    let tx_version = if let Some(ix) = argv.iter().position(|x| x == "--testnet") {
        argv.remove(ix);
        TransactionVersion::Testnet
    } else {
        TransactionVersion::Mainnet
    };

    if let Some((method, args)) = argv.split_first() {
        match method.as_str() {
            "contract-call" => handle_contract_call(args, tx_version),
            "publish" => handle_contract_publish(args, tx_version),
            _ => Err(CliError::Usage)
        }
    } else {
        Err(CliError::Usage)
    }
}
