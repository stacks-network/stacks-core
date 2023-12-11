#![warn(unused_imports)]

use std::fmt::Display;

use stacks_common::{types::{chainstate::StacksBlockId, StacksEpochId}, util::hash::Sha512Trunc256Sum};
use crate::vm::{contracts::Contract, types::{QualifiedContractIdentifier, TypeSignature, serialization::SerializationError}, analysis::{ContractAnalysis, CheckErrors}, Value, errors::{RuntimeErrorType, InterpreterError, ShortReturnType}, costs::CostErrors};
use crate::vm::errors::Error;
use super::{ClaritySerializable, ClarityDeserializable, key_value_wrapper::ValueResult};

pub mod undo_log;
pub mod ustx;
pub mod blocks;
pub mod microblocks;
pub mod vars;
pub mod maps;
pub mod assets;
pub mod stx;
pub mod burnchain;
pub mod utils;
pub mod analysis;
pub mod kv_store;
pub mod transactional;

pub use undo_log::*;
pub use ustx::*;
pub use blocks::*;
pub use microblocks::*;
pub use vars::*;
pub use maps::*;
pub use assets::*;
pub use stx::*;
pub use burnchain::*;
pub use utils::*;
pub use analysis::*;
pub use kv_store::*;
pub use transactional::*;

pub trait ClarityDB
where
    Self: TransactionalClarityDb 
    + ClarityDbMicroblocks 
    + ClarityDbStx
    + ClarityDbUstx
    + ClarityDbAssets
    + ClarityDbVars
    + ClarityDbMaps
    + 'static
{}

impl<T> ClarityDB for T 
where
    T: TransactionalClarityDb 
    + ClarityDbMicroblocks 
    + ClarityDbStx
    + ClarityDbUstx
    + ClarityDbAssets
    + ClarityDbVars
    + ClarityDbMaps
    + 'static
{}

#[derive(Debug)]
pub enum ClarityDbError {
    Check(CheckErrors),
    Runtime(RuntimeErrorType),
    Cost(CostErrors),
    Interpreter(InterpreterError),
    ShortReturn(ShortReturnType),
    Serialization(SerializationError)
}

impl Display for ClarityDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClarityDbError::Check(e) => write!(f, "Check error: {}", e),
            ClarityDbError::Runtime(e) => write!(f, "Runtime error: {}", e),
            ClarityDbError::Cost(e) => write!(f, "Cost error: {:?}", e),
            ClarityDbError::Interpreter(e) => write!(f, "Interpreter error: {:?}", e),
            ClarityDbError::ShortReturn(e) => write!(f, "Short return error: {:?}", e),
            ClarityDbError::Serialization(e) => write!(f, "Serialization error: {:?}", e),
        }
    }
}

impl From<SerializationError> for ClarityDbError {
    fn from(err: SerializationError) -> Self {
        Self::Serialization(err)
    }
}

impl From<CheckErrors> for ClarityDbError {
    fn from(err: CheckErrors) -> Self {
        Self::Check(err)
    }
}

impl From<RuntimeErrorType> for ClarityDbError {
    fn from(err: RuntimeErrorType) -> Self {
        Self::Runtime(err)
    }
}

impl From<CostErrors> for ClarityDbError {
    fn from(err: CostErrors) -> Self {
        Self::Cost(err)
    }
}

impl From<InterpreterError> for ClarityDbError {
    fn from(err: InterpreterError) -> Self {
        Self::Interpreter(err)
    }
}

impl From<crate::vm::errors::Error> for ClarityDbError {
    fn from(err: crate::vm::errors::Error) -> Self {
        match err {
            Error::Interpreter(e) => Self::Interpreter(e),
            Error::Runtime(e, _) => Self::Runtime(e),
            Error::Unchecked(e) => Self::Check(e),
            Error::ShortReturn(e) => Self::ShortReturn(e),
        }
    }
}

impl From<ClarityDbError> for CostErrors {
    fn from(err: ClarityDbError) -> Self {
        match err {
            ClarityDbError::Cost(e) => e,
            _ => unimplemented!("Cannot convert {:?} to CostErrors", err)
        }
    }
}

pub type Result<T> = std::result::Result<T, ClarityDbError>;

pub trait ClarityDb {
    fn set_block_hash(
        &mut self,
        bhh: StacksBlockId,
        query_pending_data: bool,
    ) -> Result<StacksBlockId>;

    /// Serializes and stores the given value under the specified key.
    fn put(
        &mut self, 
        key: &str, 
        value: &impl ClaritySerializable
    ) -> Result<()> 
    where 
        Self: Sized;

    /// Like `put()`, but returns the serialized byte size of the stored value
    fn put_with_size(
        &mut self, 
        key: &str, 
        value: &impl ClaritySerializable
    ) -> Result<u64>
    where
        Self: Sized;

    /// put K-V data into the committed datastore
    fn put_all(
        &mut self, 
        items: Vec<(String, String)>
    ) -> Result<()> 
    where
        Self: Sized
    {
        for (key, value) in items.into_iter() {
            self.put(&key, &value)?;
        }

        Ok(())
    }

    /// Deserializes and returns the value stored under the specified key.
    fn get<T>(&mut self, key: &str) -> Result<Option<T>>
    where
        T: ClarityDeserializable<T>,
        Self: Sized;

    /// TODO: Description.
    fn put_value(&mut self, key: &str, value: Value, epoch: &StacksEpochId) -> Result<()>;

    /// Like `put_value()`, but returns the serialized byte size of the stored value.
    fn put_value_with_size(
        &mut self,
        key: &str,
        value: Value,
        epoch: &StacksEpochId,
    ) -> Result<u64>;

    /// TODO: Description.
    fn get_value(
        &mut self,
        key: &str,
        expected: &TypeSignature,
        epoch: &StacksEpochId,
    ) -> Result<Option<ValueResult>>;

    /// TODO: Description.
    fn get_with_proof<T>(&mut self, key: &str) -> Result<Option<(T, Vec<u8>)>>
    where
        T: ClarityDeserializable<T>,
        Self: Sized;

    /// Inserts the given contract hash into the metadata storage.
    fn insert_contract_hash(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract_content: &str,
    ) -> Result<()>;

    /// Retrieves the source code of the contract for the given contract identifier.
    fn get_contract_src(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<String>>;

    /// Sets the given metadata key to the given value.
    fn set_metadata(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
        data: &str,
    ) -> Result<()>;

    /// Inserts a metadata key-value pair into the metadata storage, returning an
    /// error if the key already exists.
    fn insert_metadata<T: ClaritySerializable>(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
        data: &T,
    ) -> Result<()>
    where
        Self: Sized;

    fn put_all_metadata(
        &mut self, 
        items: Vec<((QualifiedContractIdentifier, String), String)>
    ) -> Result<()> 
    where
        Self: Sized
    {
        for ((contract, key), value) in items.into_iter() {
            self.insert_metadata(&contract, &key, &value)?;
        }

        Ok(())
    }

    /// Retrieves the deserialized metadata value for the given contract identifier 
    /// and key, attempting to deserialize to the type `T`.
    fn fetch_metadata<T>(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        T: ClarityDeserializable<T>,
        Self: Sized;

    /// TODO: Description.
    fn fetch_metadata_manual<T>(
        &mut self,
        at_height: u32,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        Self: Sized;

    /// Retrieves the contract analysis for the given contract identifier.
    fn load_contract_analysis(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<ContractAnalysis>>;

    /// Fetches the size of the contract for the given contract identifier. Contract
    /// size is defined as the `contract-size` + `contract-data-size` metadata values.
    fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<u64>;

    /// Sets the contract size for the given contract identifier. Used for adding the
    /// memory usage of `define-constant` variables to the contract size.
    fn set_contract_data_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        data_size: u64,
    ) -> Result<()>;

    /// Stores the given contract's serialized [Contract] in the metadata store.
    fn insert_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: Contract,
    ) -> Result<()>;

    /// Returns whether or not a contract with the specified identifier exists in
    /// metadata storage.
    fn has_contract(
        &mut self, 
        contract_identifier: &QualifiedContractIdentifier
    ) -> Result<bool>;

    /// Retrieves the given contract's deserialized [Contract] from the metadata store.
    fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Contract>;

    /// The contract commitment is the hash of the contract, plus the block height in
    ///   which the contract was initialized.
    fn make_contract_commitment(
        &mut self, 
        contract_hash: Sha512Trunc256Sum
    ) -> Result<String>;

    /// Returns the epoch version currently applied in the stored Clarity state.
    /// Since Clarity did not exist in stacks 1.0, the lowest valid epoch ID is stacks 2.0.
    /// The instantiation of subsequent epochs may bump up the epoch version in the clarity DB if
    /// Clarity is updated in that epoch.
    fn get_clarity_epoch_version(&mut self) -> Result<StacksEpochId> 
    where Self: Sized
    {
        match self.get(clarity_state_epoch_key())? {
            Some(x) => u32::try_into(x).map_err(|_|
                CheckErrors::InvalidEpochVersion(x.to_string()).into()),
            None => Ok(StacksEpochId::Epoch20),
        }
    }

    /// Should be called _after_ all of the epoch's initialization has been invoked.
    fn set_clarity_epoch_version(&mut self, epoch: StacksEpochId) -> Result<()> 
    where
        Self: Sized
    {
        self.put(clarity_state_epoch_key(), &(epoch as u32))
    }

    fn is_in_regtest(&self) -> bool {
        cfg!(test)
    }
}