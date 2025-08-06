// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate blockstack_lib;
extern crate clarity;
extern crate stacks_common;

#[cfg(test)]
use std::io::prelude::*;
use std::io::Read;
use std::{env, fs, io};

use blockstack_lib::burnchains::bitcoin::address::{
    ADDRESS_VERSION_MAINNET_SINGLESIG, ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use blockstack_lib::burnchains::Address;
use blockstack_lib::chainstate::stacks::{
    StacksBlock, StacksBlockHeader, StacksMicroblock, StacksPrivateKey, StacksPublicKey,
    StacksTransaction, StacksTransactionSigner, TokenTransferMemo, TransactionAnchorMode,
    TransactionAuth, TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSmartContract, TransactionSpendingCondition, TransactionVersion,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use blockstack_lib::clarity_cli::vm_execute;
use blockstack_lib::core::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use blockstack_lib::net::Error as NetError;
use blockstack_lib::util_lib::strings::StacksString;
use clarity::vm::errors::{Error as ClarityError, RuntimeErrorType};
use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};
use stacks_common::address::{b58, AddressHashMode};
use stacks_common::codec::{Error as CodecError, StacksMessageCodec};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::{hex_bytes, to_hex};
use stacks_common::util::retry::LogReader;

const USAGE: &str = "blockstack-cli (options) [method] [args...]

This CLI allows you to generate simple signed transactions for blockstack-core
to process.

This CLI has these methods:

  publish            used to generate and sign a contract publish transaction
  contract-call      used to generate and sign a contract-call transaction
  generate-sk        used to generate a secret key for transaction signing
  token-transfer     used to generate and sign a transfer transaction
  addresses          used to get both Bitcoin and Stacks addresses from a private key
  decode-tx          used to decode a hex-encoded transaction into a human-readable representation
  decode-header      used to decode a hex-encoded Stacks header into a human-readable representation
  decode-block       used to decode a hex-encoded Stacks block into a human-readable representation
  decode-microblock  used to decode a hex-encoded Stacks microblock into a human-readable representation
  decode-microblocks used to decode a hex-encoded stream of Stacks microblocks into a human-readable representation

For usage information on those methods, call `blockstack-cli [method] -h`

`blockstack-cli` accepts flag options as well:

   --testnet[=chain-id]
                     instruct the transaction generator to use a testnet version byte instead of MAINNET (default)
                     optionally, you can specify a custom chain ID to use for the transaction

";

const PUBLISH_USAGE: &str = "blockstack-cli (options) publish [publisher-secret-key-hex] [fee-rate] [nonce] [contract-name] [file-name.clar]

The publish command generates and signs a contract publish transaction. If successful,
this command outputs the hex string encoding of the transaction to stdout, and exits with
code 0

A smart contract can be mined in a Stacks block, a Stacks microblock, or either.  The default
is that the miner chooses, but you can decide which with the following options:

  --microblock-only  indicates to mine this transaction only in a microblock
  --block-only       indicates to mine this transaction only in a block

The post-condition mode for the transaction can be controlled with the following option:

  --postcondition-mode  indicates the post-condition mode for the contract. Allowed values: [`allow`, `deny`]. Default: `deny`.
";

const CALL_USAGE: &str = "blockstack-cli (options) contract-call [origin-secret-key-hex] [fee-rate] [nonce] [contract-publisher-address] [contract-name] [function-name] [args...]

The contract-call command generates and signs a contract-call transaction. If successful,
this command outputs the hex string encoding of the transaction to stdout, and exits with
code 0.

A contract-call can be mined in a Stacks block, a Stacks microblock, or either.  The default
is that the miner chooses, but you can decide which with the following options:

  --microblock-only  indicates to mine this transaction only in a microblock
  --block-only       indicates to mine this transaction only in a block

Arguments are supplied in one of two ways: through script evaluation or via hex encoding
of the value serialization format. The method for supplying arguments is chosen by
prefacing each argument with a flag:

  -e                     indicates the argument should be _evaluated_
  -x                     indicates the argument that a serialized Clarity value is being passed (hex-serialized)
 --hex-file <file_path>  same as `-x`, but reads the serialized Clarity value from a file

e.g.,

   blockstack-cli contract-call $secret_key 10 0 SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4 foo-contract \\
      transfer-fookens -e \\'SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4 \\
                       -e \"(+ 1 2)\" \\
                       -x 0000000000000000000000000000000001 \\
                       -x 050011deadbeef11ababffff11deadbeef11ababffff \\
                       --hex-file /path/to/value.hex
";

const TOKEN_TRANSFER_USAGE: &str = "blockstack-cli (options) token-transfer [origin-secret-key-hex] [fee-rate] [nonce] [recipient-address] [amount] [memo] [args...]

The transfer command generates and signs a STX transfer transaction. If successful,
this command outputs the hex string encoding of the transaction to stdout, and exits with
code 0

A token-transfer can be mined in a Stacks block, a Stacks microblock, or either.  The default
is that the miner chooses, but you can decide which with the following options:

  --microblock-only  indicates to mine this transaction only in a microblock
  --block-only       indicates to mine this transaction only in a block
";

const GENERATE_USAGE: &str = "blockstack-cli (options) generate-sk

This method generates a secret key, outputting the hex encoding of the
secret key, the corresponding public key, and the corresponding P2PKH Stacks address.";

const ADDRESSES_USAGE: &str = "blockstack-cli (options) addresses [secret-key-hex]

The addresses command calculates both the Bitcoin and Stacks addresses from a secret key.
If successful, this command outputs both the Bitcoin and Stacks addresses to stdout, formatted
as JSON, and exits with code 0.";

const DECODE_TRANSACTION_USAGE: &str =
    "blockstack-cli (options) decode-tx [transaction-hex-or-stdin]

The decode-tx command decodes a serialized Stacks transaction and prints it to stdout as JSON.
The transaction, if given, must be a hex string.  Alternatively, you may pass `-` instead, and the
raw binary transaction will be read from stdin.";

const DECODE_HEADER_USAGE: &str = "blockstack-cli (options) decode-header [block-path-or-stdin]

The decode-header command decodes a serialized Stacks header and prints it to stdout as JSON.
The header, if given, must be a hex string.  Alternatively, you may pass `-` instead, and the
raw binary header will be read from stdin.";

const DECODE_BLOCK_USAGE: &str = "blockstack-cli (options) decode-block [block-path-or-stdin]

The decode-block command decodes a serialized Stacks block and prints it to stdout as JSON.
The block, if given, must be a hex string.  Alternatively, you may pass `-` instead, and the
raw binary block will be read from stdin.";

const DECODE_MICROBLOCK_USAGE: &str = "blockstack-cli (options) decode-microblock [microblock-path-or-stdin]

The decode-microblock command decodes a serialized Stacks microblock and prints it to stdout as JSON.
The microblock, if given, must be a hex string.  Alternatively, you may pass `-` instead, and the
raw binary microblock will be read from stdin.

N.B. Stacks microblocks are not stored as files in the Stacks chainstate -- they are stored in
block's sqlite database.";

const DECODE_MICROBLOCKS_USAGE: &str = "blockstack-cli (options) decode-microblocks [microblocks-path-or-stdin]

The decode-microblocks command decodes a serialized list of Stacks microblocks and prints it to stdout as JSON.
The microblocks, if given, must be a hex string.  Alternatively, you may pass `-` instead, and the
raw binary microblocks will be read from stdin.

N.B. Stacks microblocks are not stored as files in the Stacks chainstate -- they are stored in
block's sqlite database.";

#[derive(Debug)]
enum CliError {
    ClarityRuntimeError(RuntimeErrorType),
    ClarityGeneralError(ClarityError),
    Message(String),
    Usage,
    InvalidChainId(std::num::ParseIntError),
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
            CliError::InvalidChainId(e) => write!(f, "Invalid chain ID: {}", e),
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

impl From<CodecError> for CliError {
    fn from(value: CodecError) -> Self {
        CliError::Message(format!("Stacks CodecError: {}", value))
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

impl From<stacks_common::util::HexError> for CliError {
    fn from(value: stacks_common::util::HexError) -> Self {
        CliError::Message(format!("Bad hex string supplied: {}", value))
    }
}

impl From<clarity::vm::types::serialization::SerializationError> for CliError {
    fn from(value: clarity::vm::types::serialization::SerializationError) -> Self {
        CliError::Message(format!("Failed to deserialize: {}", value))
    }
}

fn make_contract_publish(
    contract_name: String,
    contract_content: String,
) -> Result<TransactionSmartContract, CliError> {
    let name = ContractName::try_from(contract_name)?;
    let code_body = StacksString::from_string(&contract_content)
        .ok_or("Non-legal characters in contract-content")?;
    Ok(TransactionSmartContract { name, code_body })
}

fn make_contract_call(
    contract_address: String,
    contract_name: String,
    function_name: String,
    function_args: Vec<Value>,
) -> Result<TransactionContractCall, CliError> {
    let address =
        StacksAddress::from_string(&contract_address).ok_or("Failed to parse contract address")?;
    let contract_name = ContractName::try_from(contract_name)?;
    let function_name = ClarityName::try_from(function_name)?;

    Ok(TransactionContractCall {
        address,
        contract_name,
        function_name,
        function_args,
    })
}

fn make_standard_single_sig_tx(
    version: TransactionVersion,
    chain_id: u32,
    payload: TransactionPayload,
    publicKey: &StacksPublicKey,
    nonce: u64,
    tx_fee: u64,
) -> StacksTransaction {
    let mut spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(publicKey.clone())
            .expect("Failed to create p2pkh spending condition from public key.");
    spending_condition.set_nonce(nonce);
    spending_condition.set_tx_fee(tx_fee);
    let auth = TransactionAuth::Standard(spending_condition);
    let mut tx = StacksTransaction::new(version, auth, payload);
    tx.chain_id = chain_id;
    tx
}

fn sign_transaction_single_sig_standard(
    transaction: &str,
    secret_key: &StacksPrivateKey,
) -> Result<StacksTransaction, CliError> {
    let transaction =
        StacksTransaction::consensus_deserialize(&mut io::Cursor::new(&hex_bytes(transaction)?))?;

    let mut tx_signer = StacksTransactionSigner::new(&transaction);
    tx_signer.sign_origin(secret_key)?;

    Ok(tx_signer
        .get_tx()
        .ok_or("TX did not finish signing -- was this a standard single signature transaction?")?)
}

/// Counts how many times a specific flag appears in the argument list.
///
/// # Arguments
///
/// * `args` - A reference to a vector of argument strings.
/// * `flag` - The flag to count occurrences of.
///
/// # Returns
///
/// The number of times `flag` appears in `args`.
fn count_flag(args: &Vec<String>, flag: &str) -> usize {
    args.iter().filter(|&arg| arg == flag).count()
}

/// Removes the first occurrence of a flag from the argument list.
///
/// # Arguments
///
/// * `args` - A mutable reference to a vector of argument strings.
/// * `flag` - The flag to remove.
///
/// # Returns
///
/// `true` if the flag was found and removed; `false` otherwise.
fn extract_flag(args: &mut Vec<String>, flag: &str) -> bool {
    args.iter()
        .position(|arg| arg == flag)
        .map(|flag_index| {
            args.remove(flag_index);
        })
        .is_some()
}

/// Removes a flag and its following value from the argument list.
///
/// # Arguments
///
/// * `args` - A mutable reference to a vector of argument strings.
/// * `flag` - The flag whose value to extract and remove.
///
/// # Returns
///
/// An `Option<String>` containing the value following the flag if both were found and removed;
/// returns `None` if the flag was not found or no value follows the flag.
fn extract_flag_with_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|flag_index| {
            if flag_index + 1 < args.len() {
                let value = args.remove(flag_index + 1);
                args.remove(flag_index);
                Some(value)
            } else {
                None
            }
        })
}

/// Parses anchor mode flags from the CLI arguments.
///
/// This function checks for the presence of `--microblock-only` and `--block-only` flags
/// in the provided `args` vector, and returns the corresponding `TransactionAnchorMode`.
///
/// The user may specify **at most one** of these flags:
/// - `--microblock-only` maps to `TransactionAnchorMode::OffChainOnly`
/// - `--block-only` maps to `TransactionAnchorMode::OnChainOnly`
///
/// If **neither flag is provided**, the default mode `TransactionAnchorMode::Any` is returned.
///
/// Both flags are removed from the `args` vector if present.
///
/// # Arguments
///
/// * `args` - A mutable reference to a vector of CLI arguments.
/// * `usage` - A usage string displayed in error messages.
///
/// # Returns
///
/// * `Ok(TransactionAnchorMode)` - On successful parsing or if no anchor mode is specified.
/// * `Err(CliError)` - If either flag is duplicated, or if both are present simultaneously.
///
/// # Errors
///
/// Returns a `CliError::Message` if:
/// - `--microblock-only` or `--block-only` appears more than once.
/// - Both flags are specified together (mutually exclusive).
///
/// # Side Effects
///
/// Removes `--microblock-only` or `--block-only` from the `args` vector if found.
fn parse_anchor_mode(
    args: &mut Vec<String>,
    usage: &str,
) -> Result<TransactionAnchorMode, CliError> {
    const FLAG_MICROBLOCK: &str = "--microblock-only";
    const FLAG_BLOCK: &str = "--block-only";

    let count_micro = count_flag(args, FLAG_MICROBLOCK);
    let count_block = count_flag(args, FLAG_BLOCK);

    if count_micro > 1 || count_block > 1 {
        return Err(CliError::Message(format!(
            "Duplicated anchor mode detected.\n\nUSAGE:\n{}",
            usage,
        )));
    }

    let has_microblock = extract_flag(args, FLAG_MICROBLOCK);
    let has_block = extract_flag(args, FLAG_BLOCK);

    match (has_microblock, has_block) {
        (true, true) => Err(CliError::Message(format!(
            "Both anchor modes detected.\n\nUSAGE:\n{}",
            usage
        ))),
        (true, false) => Ok(TransactionAnchorMode::OffChainOnly),
        (false, true) => Ok(TransactionAnchorMode::OnChainOnly),
        (false, false) => Ok(TransactionAnchorMode::Any),
    }
}

/// Parses the `--postcondition-mode` flag from the CLI arguments.
///
/// This function looks for the `--postcondition-mode` flag in the provided `args` vector
/// and extracts its associated value. The flag must be specified at most once, and the value
/// must be either `"allow"` or `"deny"`. If the flag is not present, the default mode
/// `TransactionPostConditionMode::Deny` is returned.
///
/// The flag and its value are removed from `args` if found.
///
/// # Arguments
///
/// * `args` - A mutable reference to a vector of CLI arguments.
/// * `usage` - A usage string that is displayed in error messages.
///
/// # Returns
///
/// * `Ok(TransactionPostConditionMode)` - If the flag is parsed successfully or not present (defaults to `Deny`).
/// * `Err(CliError)` - If the flag is duplicated, missing a value, or contains an invalid value.
///
/// # Errors
///
/// Returns a `CliError::Message` if:
/// - The flag appears more than once.
/// - The flag is present but missing a value.
/// - The flag value is not `"allow"` or `"deny"`.
///
/// # Side Effects
///
/// This function modifies the `args` vector by removing the parsed flag and its value if found.
fn parse_postcondition_mode(
    args: &mut Vec<String>,
    usage: &str,
) -> Result<TransactionPostConditionMode, CliError> {
    const FLAG_POSTCONDITION: &str = "--postcondition-mode";
    const VALUE_ALLOW: &str = "allow";
    const VALUE_DENY: &str = "deny";

    match count_flag(args, FLAG_POSTCONDITION) {
        0 => return Ok(TransactionPostConditionMode::Deny),
        1 => { /* continue below */ }
        _ => {
            return Err(CliError::Message(format!(
                "Duplicated `{}`.\n\nUSAGE:\n{}",
                FLAG_POSTCONDITION, usage
            )));
        }
    }

    match extract_flag_with_value(args, FLAG_POSTCONDITION) {
        Some(value) => match value.as_str() {
            VALUE_ALLOW => Ok(TransactionPostConditionMode::Allow),
            VALUE_DENY => Ok(TransactionPostConditionMode::Deny),
            _ => Err(CliError::Message(format!(
                "Invalid value for `{}`.\n\nUSAGE:\n{}",
                FLAG_POSTCONDITION, usage
            ))),
        },
        None => Err(CliError::Message(format!(
            "Missing value for `{}`.\n\nUSAGE:\n{}",
            FLAG_POSTCONDITION, usage
        ))),
    }
}

#[allow(clippy::indexing_slicing)]
fn handle_contract_publish(
    args_slice: &[String],
    version: TransactionVersion,
    chain_id: u32,
) -> Result<String, CliError> {
    let mut args = args_slice.to_vec();

    if !args.is_empty() && args[0] == "-h" {
        return Err(CliError::Message(format!("USAGE:\n{}", PUBLISH_USAGE)));
    }
    if args.len() < 5 {
        return Err(CliError::Message(format!(
            "Incorrect argument count supplied \n\nUSAGE:\n{}",
            PUBLISH_USAGE
        )));
    }
    let anchor_mode = parse_anchor_mode(&mut args, PUBLISH_USAGE)?;
    let postcond_mode = parse_postcondition_mode(&mut args, PUBLISH_USAGE)?;
    let sk_publisher = &args[0];
    let tx_fee = args[1].parse()?;
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
    let mut unsigned_tx = make_standard_single_sig_tx(
        version,
        chain_id,
        payload.into(),
        &StacksPublicKey::from_private(&sk_publisher),
        nonce,
        tx_fee,
    );
    unsigned_tx.anchor_mode = anchor_mode;
    unsigned_tx.post_condition_mode = postcond_mode;

    let mut unsigned_tx_bytes = vec![];
    unsigned_tx
        .consensus_serialize(&mut unsigned_tx_bytes)
        .expect("FATAL: invalid transaction");
    let signed_tx =
        sign_transaction_single_sig_standard(&to_hex(&unsigned_tx_bytes), &sk_publisher)?;

    let mut signed_tx_bytes = vec![];
    signed_tx
        .consensus_serialize(&mut signed_tx_bytes)
        .expect("FATAL: invalid signed transaction");
    Ok(to_hex(&signed_tx_bytes))
}

#[allow(clippy::indexing_slicing)]
fn handle_contract_call(
    args_slice: &[String],
    version: TransactionVersion,
    chain_id: u32,
    clarity_version: ClarityVersion,
) -> Result<String, CliError> {
    let mut args = args_slice.to_vec();
    if !args.is_empty() && args[0] == "-h" {
        return Err(CliError::Message(format!("USAGE:\n {}", CALL_USAGE)));
    }
    if args.len() < 6 {
        return Err(CliError::Message(format!(
            "Incorrect argument count supplied \n\nUSAGE:\n {}",
            CALL_USAGE
        )));
    }
    let anchor_mode = parse_anchor_mode(&mut args, CALL_USAGE)?;
    let sk_origin = &args[0];
    let tx_fee = args[1].parse()?;
    let nonce = args[2].parse()?;
    let contract_address = &args[3];
    let contract_name = &args[4];
    let function_name = &args[5];

    let val_args = &args[6..];

    if val_args.len() % 2 != 0 {
        return Err(
            "contract-call arguments must be supplied as a list of `-e ...` or `-x 0000...` or `--hex-file <file_path>` pairs"
                .into(),
        );
    }

    let mut arg_iterator = 0;
    let mut values = Vec::new();
    while arg_iterator < val_args.len() {
        let eval_method = &val_args[arg_iterator];
        let input = &val_args[arg_iterator + 1];
        let value = match eval_method.as_str() {
            "-x" => {
                Value::try_deserialize_hex_untyped(input)?
            },
            "-e" => {
                vm_execute(input, clarity_version)?
                    .ok_or("Supplied argument did not evaluate to a Value")?
            },
            "--hex-file" => {
                let content = fs::read_to_string(input)
                    .map_err(|e| {
                        let err_msg = format!("Cannot read file: {input}. Reason: {e}");
                        CliError::Message(err_msg)
                    })?;
                Value::try_deserialize_hex_untyped(&content)?
            }
            _ => {
                return Err("contract-call arguments must be supplied as a list of `-e ...` or `-x 0000...` or `--hex-file <file_path>` pairs".into())
            }
        };

        values.push(value);
        arg_iterator += 2;
    }

    let sk_origin = StacksPrivateKey::from_hex(sk_origin)?;

    let payload = make_contract_call(
        contract_address.clone(),
        contract_name.clone(),
        function_name.clone(),
        values,
    )?;
    let mut unsigned_tx = make_standard_single_sig_tx(
        version,
        chain_id,
        payload.into(),
        &StacksPublicKey::from_private(&sk_origin),
        nonce,
        tx_fee,
    );
    unsigned_tx.anchor_mode = anchor_mode;

    let mut unsigned_tx_bytes = vec![];
    unsigned_tx
        .consensus_serialize(&mut unsigned_tx_bytes)
        .expect("FATAL: invalid transaction");
    let signed_tx = sign_transaction_single_sig_standard(&to_hex(&unsigned_tx_bytes), &sk_origin)?;

    let mut signed_tx_bytes = vec![];
    signed_tx
        .consensus_serialize(&mut signed_tx_bytes)
        .expect("FATAL: invalid signed transaction");
    Ok(to_hex(&signed_tx_bytes))
}

#[allow(clippy::indexing_slicing)]
fn handle_token_transfer(
    args_slice: &[String],
    version: TransactionVersion,
    chain_id: u32,
) -> Result<String, CliError> {
    let mut args = args_slice.to_vec();
    if !args.is_empty() && args[0] == "-h" {
        return Err(CliError::Message(format!(
            "USAGE:\n {}",
            TOKEN_TRANSFER_USAGE
        )));
    }
    if args.len() < 5 {
        return Err(CliError::Message(format!(
            "Incorrect argument count supplied \n\nUSAGE:\n {}",
            TOKEN_TRANSFER_USAGE
        )));
    }

    let anchor_mode = parse_anchor_mode(&mut args, TOKEN_TRANSFER_USAGE)?;
    let sk_origin = StacksPrivateKey::from_hex(&args[0])?;
    let tx_fee = args[1].parse()?;
    let nonce = args[2].parse()?;
    let recipient_address =
        PrincipalData::parse(&args[3]).map_err(|_e| "Failed to parse recipient")?;
    let amount = &args[4].parse()?;
    let memo = {
        let mut memo = [0; 34];
        let mut bytes = if args.len() == 6 {
            args[5].as_bytes().to_vec()
        } else {
            vec![]
        };
        bytes.resize(34, 0);
        memo.copy_from_slice(&bytes);
        TokenTransferMemo(memo)
    };

    let payload = TransactionPayload::TokenTransfer(recipient_address, *amount, memo);
    let mut unsigned_tx = make_standard_single_sig_tx(
        version,
        chain_id,
        payload,
        &StacksPublicKey::from_private(&sk_origin),
        nonce,
        tx_fee,
    );
    unsigned_tx.anchor_mode = anchor_mode;

    let mut unsigned_tx_bytes = vec![];
    unsigned_tx
        .consensus_serialize(&mut unsigned_tx_bytes)
        .expect("FATAL: invalid transaction");
    let signed_tx = sign_transaction_single_sig_standard(&to_hex(&unsigned_tx_bytes), &sk_origin)?;

    let mut signed_tx_bytes = vec![];
    signed_tx
        .consensus_serialize(&mut signed_tx_bytes)
        .expect("FATAL: invalid signed transaction");
    Ok(to_hex(&signed_tx_bytes))
}

#[allow(clippy::indexing_slicing)]
fn generate_secret_key(args: &[String], version: TransactionVersion) -> Result<String, CliError> {
    if !args.is_empty() && args[0] == "-h" {
        return Err(CliError::Message(format!("USAGE:\n {}", GENERATE_USAGE)));
    }

    let sk = StacksPrivateKey::random();
    let pk = StacksPublicKey::from_private(&sk);
    let version = match version {
        TransactionVersion::Mainnet => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        TransactionVersion::Testnet => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    };

    let address = StacksAddress::from_public_keys(
        version,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![pk.clone()],
    )
    .expect("Failed to generate address from public key");
    Ok(format!(
        "{{
  \"secretKey\": \"{}\",
  \"publicKey\": \"{}\",
  \"stacksAddress\": \"{}\"
}}",
        sk.to_hex(),
        pk.to_hex(),
        address
    ))
}

#[allow(clippy::indexing_slicing)]
fn get_addresses(args: &[String], version: TransactionVersion) -> Result<String, CliError> {
    if (!args.is_empty() && args[0] == "-h") || args.len() != 1 {
        return Err(CliError::Message(format!("USAGE:\n {}", ADDRESSES_USAGE)));
    }

    let sk = StacksPrivateKey::from_hex(&args[0]).expect("Failed to load private key");

    let pk = StacksPublicKey::from_private(&sk);
    let c32_version = match version {
        TransactionVersion::Mainnet => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        TransactionVersion::Testnet => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    };

    let b58_version = match version {
        TransactionVersion::Mainnet => ADDRESS_VERSION_MAINNET_SINGLESIG,
        TransactionVersion::Testnet => ADDRESS_VERSION_TESTNET_SINGLESIG,
    };

    let stx_address = StacksAddress::from_public_keys(
        c32_version,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![pk.clone()],
    )
    .expect("Failed to generate address from public key");

    let mut b58_addr_slice = [0u8; 21];
    b58_addr_slice[0] = b58_version;
    b58_addr_slice[1..].copy_from_slice(&stx_address.bytes().0);
    let b58_address_string = b58::check_encode_slice(&b58_addr_slice);
    Ok(format!(
        "{{
    \"STX\": \"{}\",
    \"BTC\": \"{}\"
}}",
        &stx_address, &b58_address_string
    ))
}

#[allow(clippy::indexing_slicing)]
fn decode_transaction(args: &[String], _version: TransactionVersion) -> Result<String, CliError> {
    if (!args.is_empty() && args[0] == "-h") || args.len() != 1 {
        return Err(CliError::Message(format!(
            "Usage: {}\n",
            DECODE_TRANSACTION_USAGE
        )));
    }

    let tx_str = if args[0] == "-" {
        // read from stdin
        let mut tx_str = Vec::new();
        io::stdin()
            .read_to_end(&mut tx_str)
            .expect("Failed to read transaction from stdin");
        tx_str
    } else {
        // given as a command-line arg
        hex_bytes(&args[0].clone()).expect("Failed to decode transaction: must be a hex string")
    };

    let mut cursor = io::Cursor::new(&tx_str);
    let mut debug_cursor = LogReader::from_reader(&mut cursor);

    match StacksTransaction::consensus_deserialize(&mut debug_cursor) {
        Ok(tx) => Ok(serde_json::to_string(&tx).expect("Failed to serialize transaction to JSON")),
        Err(e) => {
            let mut ret = String::new();
            ret.push_str(&format!("Failed to decode transaction: {:?}\n", &e));
            ret.push_str("Bytes consumed:\n");
            for buf in debug_cursor.log().iter() {
                ret.push_str(&format!("   {}", to_hex(buf)));
            }
            ret.push('\n');
            Ok(ret)
        }
    }
}

#[allow(clippy::indexing_slicing)]
fn decode_header(args: &[String], _version: TransactionVersion) -> Result<String, CliError> {
    if (!args.is_empty() && args[0] == "-h") || args.len() != 1 {
        return Err(CliError::Message(format!(
            "Usage: {}\n",
            DECODE_HEADER_USAGE
        )));
    }
    let header_data = if args[0] == "-" {
        // read from stdin
        let mut header_str = Vec::new();
        io::stdin()
            .read_to_end(&mut header_str)
            .expect("Failed to read header from stdin");
        header_str
    } else {
        // given as a command-line arg
        hex_bytes(&args[0].clone()).expect("Failed to decode header: must be a hex string")
    };

    let mut cursor = io::Cursor::new(&header_data);
    let mut debug_cursor = LogReader::from_reader(&mut cursor);

    match StacksBlockHeader::consensus_deserialize(&mut debug_cursor) {
        Ok(header) => {
            Ok(serde_json::to_string(&header).expect("Failed to serialize header to JSON"))
        }
        Err(e) => {
            let mut ret = String::new();
            ret.push_str(&format!("Failed to decode header: {:?}\n", &e));
            ret.push_str("Bytes consumed:\n");
            for buf in debug_cursor.log().iter() {
                ret.push_str(&format!("   {}", to_hex(buf)));
            }
            ret.push('\n');
            Ok(ret)
        }
    }
}

#[allow(clippy::indexing_slicing)]
fn decode_block(args: &[String], _version: TransactionVersion) -> Result<String, CliError> {
    if (!args.is_empty() && args[0] == "-h") || args.len() != 1 {
        return Err(CliError::Message(format!(
            "Usage: {}\n",
            DECODE_BLOCK_USAGE
        )));
    }
    let block_data = if args[0] == "-" {
        // read from stdin
        let mut block_str = Vec::new();
        io::stdin()
            .read_to_end(&mut block_str)
            .expect("Failed to read block from stdin");
        block_str
    } else {
        // given as a command-line arg
        hex_bytes(&args[0].clone()).expect("Failed to decode block: must be a hex string")
    };

    let mut cursor = io::Cursor::new(&block_data);
    let mut debug_cursor = LogReader::from_reader(&mut cursor);

    match StacksBlock::consensus_deserialize(&mut debug_cursor) {
        Ok(block) => Ok(serde_json::to_string(&block).expect("Failed to serialize block to JSON")),
        Err(e) => {
            let mut ret = String::new();
            ret.push_str(&format!("Failed to decode block: {:?}\n", &e));
            ret.push_str("Bytes consumed:\n");
            for buf in debug_cursor.log().iter() {
                ret.push_str(&format!("   {}", to_hex(buf)));
            }
            ret.push('\n');
            Ok(ret)
        }
    }
}

#[allow(clippy::indexing_slicing)]
fn decode_microblock(args: &[String], _version: TransactionVersion) -> Result<String, CliError> {
    if (!args.is_empty() && args[0] == "-h") || args.len() != 1 {
        return Err(CliError::Message(format!(
            "Usage: {}\n",
            DECODE_MICROBLOCK_USAGE
        )));
    }
    let mblock_data = if args[0] == "-" {
        // read from stdin
        let mut block_str = Vec::new();
        io::stdin()
            .read_to_end(&mut block_str)
            .expect("Failed to read block from stdin");
        block_str
    } else {
        // given as a command-line arg
        hex_bytes(&args[0].clone()).expect("Failed to decode microblock: must be a hex string")
    };

    let mut cursor = io::Cursor::new(&mblock_data);
    let mut debug_cursor = LogReader::from_reader(&mut cursor);

    match StacksMicroblock::consensus_deserialize(&mut debug_cursor) {
        Ok(block) => {
            Ok(serde_json::to_string(&block).expect("Failed to serialize microblock to JSON"))
        }
        Err(e) => {
            let mut ret = String::new();
            ret.push_str(&format!("Failed to decode microblock: {:?}\n", &e));
            ret.push_str("Bytes consumed:\n");
            for buf in debug_cursor.log().iter() {
                ret.push_str(&format!("   {}", to_hex(buf)));
            }
            ret.push('\n');
            Ok(ret)
        }
    }
}

#[allow(clippy::indexing_slicing)]
fn decode_microblocks(args: &[String], _version: TransactionVersion) -> Result<String, CliError> {
    if (!args.is_empty() && args[0] == "-h") || args.len() != 1 {
        return Err(CliError::Message(format!(
            "Usage: {}\n",
            DECODE_MICROBLOCKS_USAGE
        )));
    }
    let mblock_data = if args[0] == "-" {
        // read from stdin
        let mut block_str = Vec::new();
        io::stdin()
            .read_to_end(&mut block_str)
            .expect("Failed to read block from stdin");
        block_str
    } else {
        // given as a command-line arg
        hex_bytes(&args[0].clone()).expect("Failed to decode microblock: must be a hex string")
    };

    let mut cursor = io::Cursor::new(&mblock_data);
    let mut debug_cursor = LogReader::from_reader(&mut cursor);

    match Vec::<StacksMicroblock>::consensus_deserialize(&mut debug_cursor) {
        Ok(blocks) => {
            Ok(serde_json::to_string(&blocks).expect("Failed to serialize microblock to JSON"))
        }
        Err(e) => {
            let mut ret = String::new();
            ret.push_str(&format!("Failed to decode microblocks: {:?}\n", &e));
            ret.push_str("Bytes consumed:\n");
            for buf in debug_cursor.log().iter() {
                ret.push_str(&format!("   {}\n", to_hex(buf)));
            }
            ret.push('\n');
            Ok(ret)
        }
    }
}

fn main() {
    let mut argv: Vec<String> = env::args().collect();

    argv.remove(0);

    match main_handler(argv) {
        Ok(s) => {
            println!("{}", s);
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

fn main_handler(mut argv: Vec<String>) -> Result<String, CliError> {
    let mut tx_version = TransactionVersion::Mainnet;
    let mut chain_id = CHAIN_ID_MAINNET;

    // Look for the `--testnet` flag
    if let Some(ix) = argv.iter().position(|x| x.starts_with("--testnet")) {
        let flag = argv.remove(ix);

        // Check if `--testnet=<chain_id>` is used
        if let Some(custom_chain_id) = flag.split('=').nth(1) {
            // Attempt to parse the custom chain ID from hex
            chain_id = u32::from_str_radix(custom_chain_id.trim_start_matches("0x"), 16)
                .map_err(CliError::InvalidChainId)?;
        } else {
            // Use the default testnet chain ID
            chain_id = CHAIN_ID_TESTNET;
        }

        // Set the transaction version to Testnet
        tx_version = TransactionVersion::Testnet;
    }

    if let Some((method, args)) = argv.split_first() {
        match method.as_str() {
            "contract-call" => {
                handle_contract_call(args, tx_version, chain_id, ClarityVersion::Clarity2)
            }
            "publish" => handle_contract_publish(args, tx_version, chain_id),
            "token-transfer" => handle_token_transfer(args, tx_version, chain_id),
            "generate-sk" => generate_secret_key(args, tx_version),
            "addresses" => get_addresses(args, tx_version),
            "decode-tx" => decode_transaction(args, tx_version),
            "decode-header" => decode_header(args, tx_version),
            "decode-block" => decode_block(args, tx_version),
            "decode-microblock" => decode_microblock(args, tx_version),
            "decode-microblocks" => decode_microblocks(args, tx_version),
            _ => Err(CliError::Usage),
        }
    } else {
        Err(CliError::Usage)
    }
}

#[cfg(test)]
mod test {
    use std::panic;

    use blockstack_lib::chainstate::stacks::TransactionPostCondition;
    use stacks_common::util::cargo_workspace;
    use tempfile::NamedTempFile;

    use super::*;

    mod utils {
        use super::*;
        pub fn tx_deserialize(hex_str: &str) -> StacksTransaction {
            let tx_str = hex_bytes(&hex_str).expect("Failed to get hex byte from tx str!");
            let mut cursor = io::Cursor::new(&tx_str);
            StacksTransaction::consensus_deserialize(&mut cursor).expect("Failed deserialize tx!")
        }

        pub fn file_read(file_path: &str) -> String {
            fs::read_to_string(file_path).expect("Failed to read file contents")
        }
    }

    #[test]
    fn generate_should_work() {
        assert!(main_handler(vec!["generate-sk".into(), "--testnet".into()]).is_ok());
        assert!(main_handler(vec!["generate-sk".into()]).is_ok());
        assert!(generate_secret_key(&["-h".into()], TransactionVersion::Mainnet).is_err());
    }

    fn to_string_vec(x: &[&str]) -> Vec<String> {
        x.iter().map(|&x| x.into()).collect()
    }

    #[test]
    fn test_contract_publish_ok_with_mandatory_params() {
        let contract_path = cargo_workspace("sample/contracts/tokens.clar")
            .display()
            .to_string();
        let publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
        ];

        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_ok());

        let serial_tx = result.unwrap();
        let deser_tx = utils::tx_deserialize(&serial_tx);

        assert_eq!(TransactionVersion::Mainnet, deser_tx.version);
        assert_eq!(CHAIN_ID_MAINNET, deser_tx.chain_id);
        assert!(matches!(deser_tx.auth, TransactionAuth::Standard(..)));
        assert_eq!(1, deser_tx.get_tx_fee());
        assert_eq!(0, deser_tx.get_origin_nonce());
        assert_eq!(TransactionAnchorMode::Any, deser_tx.anchor_mode);
        assert_eq!(
            TransactionPostConditionMode::Deny,
            deser_tx.post_condition_mode
        );
        assert_eq!(
            Vec::<TransactionPostCondition>::new(),
            deser_tx.post_conditions
        );

        let (contract, clarity) = match deser_tx.payload {
            TransactionPayload::SmartContract(a, b) => (a, b),
            _ => panic!("Should not happen!"),
        };
        assert_eq!("foo-contract", contract.name.as_str());
        assert_eq!(
            utils::file_read(&contract_path),
            contract.code_body.to_string()
        );
        assert_eq!(None, clarity);
    }

    #[test]
    fn test_contract_publish_fails_on_unexistent_file() {
        let publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &cargo_workspace("sample/contracts/non-existent-tokens.clar")
                .display()
                .to_string(),
        ];

        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.starts_with("IO error reading CLI input:"));
    }

    #[test]
    fn test_contract_publish_ok_with_anchor_mode() {
        let contract_path = cargo_workspace("sample/contracts/tokens.clar")
            .display()
            .to_string();

        let mut publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
            "--microblock-only",
        ];

        // Scenario OK with anchor mode = `offchain`
        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_ok());

        let serial_tx = result.unwrap();
        let deser_tx = utils::tx_deserialize(&serial_tx);
        assert_eq!(TransactionAnchorMode::OffChainOnly, deser_tx.anchor_mode);

        // Scenario OK with anchor mode = `onchain`
        publish_args[6] = "--block-only";
        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_ok());

        let serial_tx = result.unwrap();
        let deser_tx = utils::tx_deserialize(&serial_tx);
        assert_eq!(TransactionAnchorMode::OnChainOnly, deser_tx.anchor_mode);
    }

    #[test]
    fn test_contract_publish_fails_with_anchor_mode() {
        let contract_path = cargo_workspace("sample/contracts/tokens.clar")
            .display()
            .to_string();

        // Scenario FAIL using both anchor modes
        let publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
            "--microblock-only",
            "--block-only",
        ];

        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_err());

        let exp_err_msg = format!(
            "{}\n\nUSAGE:\n{}",
            "Both anchor modes detected.", PUBLISH_USAGE
        );
        assert_eq!(exp_err_msg, result.unwrap_err().to_string());

        // Scenario FAIL using duplicated anchor mode
        let publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
            "--microblock-only",
            "--microblock-only",
        ];

        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_err());

        let exp_err_msg = format!(
            "{}\n\nUSAGE:\n{}",
            "Duplicated anchor mode detected.", PUBLISH_USAGE
        );
        assert_eq!(exp_err_msg, result.unwrap_err().to_string());
    }

    #[test]
    fn test_contract_publish_ok_with_postcond_mode() {
        let contract_path = cargo_workspace("sample/contracts/tokens.clar")
            .display()
            .to_string();

        let mut publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
            "--postcondition-mode",
            "allow",
        ];

        // Scenario OK with post-condition = `allow`
        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_ok());

        let serial_tx = result.unwrap();
        let deser_tx = utils::tx_deserialize(&serial_tx);
        assert_eq!(
            TransactionPostConditionMode::Allow,
            deser_tx.post_condition_mode
        );

        // Scenario OK with post-condition = `deny`
        publish_args[7] = "deny";
        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_ok());
    }

    #[test]
    fn test_contract_publish_fails_with_postcond_mode() {
        let contract_path = cargo_workspace("sample/contracts/tokens.clar")
            .display()
            .to_string();

        // Scenario FAIL with invalid post-condition
        let publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
            "--postcondition-mode",
            "invalid",
        ];

        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_err());

        let exp_err_msg = format!(
            "{}\n\nUSAGE:\n{}",
            "Invalid value for `--postcondition-mode`.", PUBLISH_USAGE
        );
        assert_eq!(exp_err_msg, result.unwrap_err().to_string());

        // Scenario FAIL with missing post-condition value
        let publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
            "--postcondition-mode",
        ];

        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_err());

        let exp_err_msg = format!(
            "{}\n\nUSAGE:\n{}",
            "Missing value for `--postcondition-mode`.", PUBLISH_USAGE
        );
        assert_eq!(exp_err_msg, result.unwrap_err().to_string());

        // Scenario FAIL with duplicated post-condition
        let publish_args = [
            "publish",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "foo-contract",
            &contract_path,
            "--postcondition-mode",
            "allow",
            "--postcondition-mode",
        ];

        let result = main_handler(to_string_vec(&publish_args));
        assert!(result.is_err());

        let exp_err_msg = format!(
            "{}\n\nUSAGE:\n{}",
            "Duplicated `--postcondition-mode`.", PUBLISH_USAGE
        );
        assert_eq!(exp_err_msg, result.unwrap_err().to_string());
    }

    #[test]
    fn simple_token_transfer() {
        let tt_args = [
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "ST1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
        ];

        assert!(main_handler(to_string_vec(&tt_args)).is_ok());

        let tt_args = [
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "--block-only",
            "0",
            "ST1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
        ];

        assert!(main_handler(to_string_vec(&tt_args)).is_ok());

        let tt_args = [
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "--microblock-only",
            "0",
            "ST1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
        ];

        assert!(main_handler(to_string_vec(&tt_args)).is_ok());

        let tt_args = [
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "ST1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
            "Memo",
        ];

        assert!(main_handler(to_string_vec(&tt_args)).is_ok());

        let tt_args = [
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "ST1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "-1",
        ];

        assert!(
            format!("{}", main_handler(to_string_vec(&tt_args)).unwrap_err())
                .contains("Failed to parse integer")
        );

        let tt_args = [
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SX1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
        ];

        assert!(
            format!("{}", main_handler(to_string_vec(&tt_args)).unwrap_err())
                .contains("Failed to parse recipient")
        );

        let tt_args = [
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SX1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
            "--microblock-only",
            "--block-only",
        ];

        assert!(main_handler(to_string_vec(&tt_args)).is_err());
    }

    #[test]
    fn simple_cc() {
        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-e",
            "(+ 1 0)",
            "-e",
            "2",
        ];

        let exec_1 = main_handler(to_string_vec(&cc_args)).unwrap();

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-e",
            "(+ 0 1)",
            "-e",
            "(+ 1 1)",
        ];

        let exec_2 = main_handler(to_string_vec(&cc_args)).unwrap();

        assert_eq!(exec_1, exec_2);

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-x",
            "0000000000000000000000000000000001",
            "-x",
            "0000000000000000000000000000000002",
        ];

        let exec_3 = main_handler(to_string_vec(&cc_args)).unwrap();

        assert_eq!(exec_2, exec_3);

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-e",
            "(+ 0 1)",
            "-e",
        ];

        assert!(
            format!("{}", main_handler(to_string_vec(&cc_args)).unwrap_err())
                .contains("arguments must be supplied as")
        );

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-e",
            "(/ 1 0)",
        ];

        assert!(
            format!("{}", main_handler(to_string_vec(&cc_args)).unwrap_err())
                .contains("Clarity error")
        );

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "quryey",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-e",
            "1",
        ];

        assert!(
            format!("{}", main_handler(to_string_vec(&cc_args)).unwrap_err())
                .contains("parse integer")
        );

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000fz",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-e",
            "1",
        ];

        assert!(
            format!("{}", main_handler(to_string_vec(&cc_args)).unwrap_err())
                .contains("Failed to decode hex")
        );

        let sk = StacksPrivateKey::random();
        let s = format!(
            "{}",
            sign_transaction_single_sig_standard("01zz", &sk).unwrap_err()
        );
        println!("{}", s);
        assert!(s.contains("Bad hex string"));

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "-x",
            "1010",
        ];

        assert!(
            format!("{}", main_handler(to_string_vec(&cc_args)).unwrap_err())
                .contains("deserialize")
        );
    }

    #[test]
    fn test_contract_call_with_serialized_arg_from_file_ok() {
        let mut file = NamedTempFile::new().expect("Cannot create tempfile!");
        write!(file, "0000000000000000000000000000000001").expect("Cannot Write to temp file");

        let file_path = file.path().to_str().unwrap();
        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "--hex-file",
            file_path,
        ];

        let result = main_handler(to_string_vec(&cc_args));
        assert!(result.is_ok(), "Result should be ok!");

        let expected_tx = "0000000001040021a3c334fc0ee50359353799e8b2605ac6be1fe400000000000000000000000000000001010011db0868db0cd44c463b3a8a8b3b428ddaad15661e7b7d8c92c814c142c526e30abffe74e1e098f517037a1ee74969f4db27630407f4c958cb0d6e1d7485fe06030200000000021625a2a51cf0712a9d228e2788e2fe7acf8917ec810c666f6f2d636f6e7472616374107472616e736665722d666f6f6b656e73000000010000000000000000000000000000000001";
        assert_eq!(expected_tx, result.unwrap());
    }

    #[test]
    fn test_contract_call_with_serialized_arg_from_file_fails_due_to_file() {
        let file_path = "/tmp/this-file-not-exists";
        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "--hex-file",
            file_path,
        ];

        let result = main_handler(to_string_vec(&cc_args));
        assert!(result.is_err(), "Result should be err!");

        let expected_msg = format!("Cannot read file: {}. Reason: ", file_path);
        assert!(result.unwrap_err().to_string().starts_with(&expected_msg));
    }

    #[test]
    fn test_contract_call_with_serialized_arg_from_file_fails_due_to_bad_hex() {
        let mut file = NamedTempFile::new().expect("Cannot create tempfile!");
        // Bad hex string but (good except for the \n)
        write!(file, "0000000000000000000000000000000001\n").expect("Cannot Write to temp file");
        let file_path = file.path().to_str().unwrap();

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "--hex-file",
            &file_path,
        ];

        let result = main_handler(to_string_vec(&cc_args));
        assert!(result.is_err(), "Result should be err!");

        let expected_msg = "Failed to deserialize: Deserialization error: Bad hex string";
        assert_eq!(expected_msg, result.unwrap_err().to_string());
    }

    #[test]
    fn test_contract_call_with_serialized_arg_from_file_fails_due_to_short_buffer() {
        let mut file = NamedTempFile::new().expect("Cannot create tempfile!");
        // hex buffer is short
        write!(file, "0101").expect("Cannot Write to temp file");
        let file_path = file.path().to_str().unwrap();

        let cc_args = [
            "contract-call",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "SPJT598WY1RJN792HRKRHRQYFB7RJ5ZCG6J6GEZ4",
            "foo-contract",
            "transfer-fookens",
            "--hex-file",
            &file_path,
        ];

        let result = main_handler(to_string_vec(&cc_args));
        assert!(result.is_err(), "Result should be err!");

        let expected_msg =
            "Failed to deserialize: Serialization error caused by IO: failed to fill whole buffer";
        assert_eq!(expected_msg, result.unwrap_err().to_string());
    }

    #[test]
    fn simple_addresses() {
        let addr_args = [
            "addresses",
            "2945c6be8758994652a498f0445d534d0fadb0b2025b37c72297b059ebf887ed01",
        ];

        let result = main_handler(to_string_vec(&addr_args)).unwrap();
        assert!(result.contains("SP36T883PDD2EK4PHVTA5GFHC8NQW6558XG7YX1GD"));
        assert!(result.contains("1KkL94EPD3mz7RFCZPmRBy3KjbWZ4qo58E"));

        let addr_args = [
            "--testnet",
            "addresses",
            "2945c6be8758994652a498f0445d534d0fadb0b2025b37c72297b059ebf887ed01",
        ];

        let result = main_handler(to_string_vec(&addr_args)).unwrap();
        assert!(result.contains("mzGHS7KN25DEtXipGxjo1tFebb7Fw5aAkp"));
        assert!(result.contains("ST36T883PDD2EK4PHVTA5GFHC8NQW6558XJQX6Q3K"));
    }

    #[test]
    fn simple_decode_tx() {
        let tx_args = [
            "decode-tx",
            "8080000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000100000000000000000100c90ae0235365f3a73c595f8c6ab3c529807feb3cb269247329c9a24218d50d3f34c7eef5d28ba26831affa652a73ec32f098fec4bf1decd1ceb3fde4b8ce216b030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010d00000003666f6f"
        ];

        let result = main_handler(to_string_vec(&tx_args)).unwrap();
        eprintln!("result:\n{}", result);
    }

    #[test]
    fn simple_decode_block() {
        let block_args = [
            "decode-block",
            "000000000000395f800000000000000179cb51f6bbd6d90cb257616e77a495919667c3772dd08ea7c4f5c372739490bc91da6609c5c95c96f612dbc8cab2f7a0d8bfb83abdb630167579ccc36b66c03c1d0d250cd3b3615c03afcdaef313dbd30d3d5b0fd10ed5acbc35d042abfba66cdfc32881c5a665ad9685a2eb6e0c131fb400000000000000000000000000000000000000000000000000000000000000000000e87f28593f66d77ae3c57abd4e5ae0e632b837b2596be14c2b2572cd4d0015229976eb5c4a5b08816b31f485513d2e6501f6cd29ee240a2c4056b1f7cc32c2e118ef6499e0fcc575da75fca8cc409e5c884eb3450000000180800000000400403e2ff80a8a8ecacfb827dcf6adddd21fdd4c3c000000000000017800000000000000000000f3f497268f8a12e318f96ba4f1ad3ed2485e87cefe75b88bf735bb1bbb7db754746e6a244ba869183a2ab73002c6465936b7d9b059ffc5a94488bee7b5afb33c010200000000040000000000000000000000000000000000000000000000000000000000000000",
        ];

        let result = main_handler(to_string_vec(&block_args)).unwrap();
        eprintln!("result:\n{}", result);
    }

    #[test]
    fn simple_decode_header() {
        let header_args = [
            "decode-header",
            "24000000000000000100000000000000019275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a2154900325010cc49a050c23e6ffb0581afebbb27f41e65a5ecfd68548982f824f7a33ed32849b7524eceec0a9f29d9d624314059d56fefd55bca56944f3fe2d003488d4a00c92575d68c6f6dd659046585f5d5209e65829a3a673c04692f5e3dc2802020202020202020202020202020202020202020202020202020202020202023ad2cf6dfced0536fc850eb86827df634877c035",
        ];

        let result = main_handler(to_string_vec(&header_args)).unwrap();
        eprintln!("result:\n{}", result);
    }

    #[test]
    fn custom_chain_id() {
        // Standard chain id
        let tt_args = [
            "--testnet",
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "ST1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
        ];

        let result = main_handler(to_string_vec(&tt_args));
        assert!(result.is_ok());

        let result = result.unwrap();
        let tx = decode_transaction(&[result], TransactionVersion::Testnet).unwrap();
        assert!(tx.contains("chain_id\":2147483648"));

        // Custom chain id
        let tt_args = [
            "--testnet=0x12345678",
            "token-transfer",
            "043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3",
            "1",
            "0",
            "ST1A14RBKJ289E3DP89QAZE2RRHDPWP5RHMYFRCHV",
            "10",
        ];

        let result = main_handler(to_string_vec(&tt_args));
        assert!(result.is_ok());

        let result = result.unwrap();
        let tx = decode_transaction(&[result], TransactionVersion::Testnet).unwrap();
        assert!(tx.contains("chain_id\":305419896"));
    }
}
