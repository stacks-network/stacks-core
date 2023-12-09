use stacks_common::util::hash::Hash160;

use crate::vm::{database::StoreType, types::{QualifiedContractIdentifier, PrincipalData}, analysis::CheckErrors, errors::Error};
use super::super::super::errors::InterpreterResult as Result;

/// Generates a key for the given variable name and data type, to be stored in the
/// database's metadata storage.
pub fn make_metadata_key(data: StoreType, var_name: &str) -> String {
    format!("vm-metadata::{}::{}", data as u8, var_name)
}

pub fn clarity_state_epoch_key() -> &'static str {
    "vm-epoch::epoch-version"
}

/// Generates a key for a given contract and data variable. "Trip" is short for "triple", as
/// in the key is made up of three parts.
pub fn make_key_for_trip(
    contract_identifier: &QualifiedContractIdentifier,
    data: StoreType,
    var_name: &str,
) -> String {
    format!("vm::{}::{}::{}", contract_identifier, data as u8, var_name)
}

/// Generates a key for a given contract and data variable. "Quad" is short for "quadruple", as
/// in the key is made up of four parts.
pub fn make_key_for_quad(
    contract_identifier: &QualifiedContractIdentifier,
    data: StoreType,
    var_name: &str,
    key_value: &str,
) -> String {
    format!(
        "vm::{}::{}::{}::{}",
        contract_identifier, data as u8, var_name, key_value
    )
}

pub fn make_key_for_account(principal: &PrincipalData, data: StoreType) -> String {
    format!("vm-account::{}::{}", principal, data as u8)
}

pub fn make_key_for_account_balance(principal: &PrincipalData) -> String {
    make_key_for_account(principal, StoreType::STXBalance)
}

pub fn make_key_for_account_nonce(principal: &PrincipalData) -> String {
    make_key_for_account(principal, StoreType::Nonce)
}

pub fn make_key_for_account_stx_locked(principal: &PrincipalData) -> String {
    make_key_for_account(principal, StoreType::PoxSTXLockup)
}

pub fn make_key_for_account_unlock_height(principal: &PrincipalData) -> String {
    make_key_for_account(principal, StoreType::PoxUnlockHeight)
}

pub fn make_microblock_pubkey_height_key(pubkey_hash: &Hash160) -> String {
    format!("microblock-pubkey-hash::{}", pubkey_hash)
}

pub fn make_microblock_poison_key(height: u32) -> String {
    format!("microblock-poison::{}", height)
}

pub fn make_contract_hash_key(contract: &QualifiedContractIdentifier) -> String {
    format!("clarity-contract::{}", contract)
}

// this is used so that things like load_map, load_var, load_nft, etc.
//   will throw NoSuchFoo errors instead of NoSuchContract errors.
pub fn map_no_contract_as_none<T>(
    res: Result<Option<T>>
) -> Result<Option<T>> {
    res.or_else(|e| match e {
        Error::Unchecked(CheckErrors::NoSuchContract(_)) => Ok(None),
        x => Err(x),
    })
}