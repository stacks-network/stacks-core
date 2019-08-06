use std::convert::TryFrom;

use rusqlite::{Connection, OptionalExtension, NO_PARAMS, Row, Savepoint};
use rusqlite::types::{ToSql, FromSql};

use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, UncheckedError, InterpreterResult as Result, IncomparableError};
use vm::types::{Value, OptionalData, TypeSignature, TupleTypeSignature, AtomTypeIdentifier, PrincipalData, NONE};

use chainstate::burn::{VRFSeed, BlockHeaderHash};
use burnchains::BurnchainHeaderHash;

pub trait ClaritySerializable <T> {
    fn serialize(&self) -> String;
    fn deserialize(json: &str) -> T;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleTokenMetadata {
    pub total_supply: Option<i128>
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonFungibleTokenMetadata {
    pub key_type: TypeSignature
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMapMetadata {
    pub key_type: TypeSignature,
    pub value_type: TypeSignature
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataVariableMetadata {
    pub value_type: TypeSignature
}

#[derive(Serialize, Deserialize)]
pub struct ContractMetadata {
    pub contract: Contract
}

impl ClaritySerializable<NonFungibleTokenMetadata> for NonFungibleTokenMetadata {
    fn deserialize(json: &str) -> Self {
        serde_json::from_str(json)
            .expect("Failed to deserialize vm.Value")
    }

    fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.Value")
    }
}

impl ClaritySerializable<DataMapMetadata> for DataMapMetadata {
    fn deserialize(json: &str) -> Self {
        serde_json::from_str(json)
            .expect("Failed to deserialize vm.Value")
    }

    fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.Value")
    }
}

impl ClaritySerializable<FungibleTokenMetadata> for FungibleTokenMetadata {
    fn deserialize(json: &str) -> Self {
        serde_json::from_str(json)
            .expect("Failed to deserialize vm.Value")
    }

    fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.Value")
    }
}

impl ClaritySerializable<ContractMetadata> for ContractMetadata {
    fn deserialize(json: &str) -> Self {
        serde_json::from_str(json)
            .expect("Failed to deserialize vm.Value")
    }

    fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.Value")
    }
}

impl ClaritySerializable<DataVariableMetadata> for DataVariableMetadata {
    fn deserialize(json: &str) -> Self {
        serde_json::from_str(json)
            .expect("Failed to deserialize vm.Value")
    }

    fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.Value")
    }
}
