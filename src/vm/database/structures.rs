use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, InterpreterResult as Result, IncomparableError};
use vm::types::{Value, OptionalData, TypeSignature, TupleTypeSignature, PrincipalData, NONE};

pub trait ClaritySerializable {
    fn serialize(&self) -> String;
}

pub trait ClarityDeserializable<T> {
    fn deserialize(json: &str) -> T;
}

macro_rules! clarity_serializable {
    ($Name:ident) =>
    {
        impl ClaritySerializable for $Name {
            fn serialize(&self) -> String {
                serde_json::to_string(self)
                    .expect("Failed to serialize vm.Value")
            }
        }
        impl ClarityDeserializable<$Name> for $Name {
            fn deserialize(json: &str) -> Self {
                serde_json::from_str(json)
                    .expect("Failed to serialize vm.Value")
            }
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleTokenMetadata {
    pub total_supply: Option<i128>
}

clarity_serializable!(FungibleTokenMetadata);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonFungibleTokenMetadata {
    pub key_type: TypeSignature
}

clarity_serializable!(NonFungibleTokenMetadata);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMapMetadata {
    pub key_type: TypeSignature,
    pub value_type: TypeSignature
}

clarity_serializable!(DataMapMetadata);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataVariableMetadata {
    pub value_type: TypeSignature
}

clarity_serializable!(DataVariableMetadata);

#[derive(Serialize, Deserialize)]
pub struct ContractMetadata {
    pub contract: Contract
}

clarity_serializable!(ContractMetadata);


#[derive(Serialize, Deserialize)]
pub struct SimmedBlock {
    pub block_height: u64,
    pub block_time: u64,
    pub block_header_hash: [u8; 32],
    pub burn_chain_header_hash: [u8; 32],
    pub vrf_seed: [u8; 32],
}

clarity_serializable!(SimmedBlock);

clarity_serializable!(PrincipalData);
clarity_serializable!(i128);
clarity_serializable!(u128);
clarity_serializable!(u64);
clarity_serializable!(Contract);
