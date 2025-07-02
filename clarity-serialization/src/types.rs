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

use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};
use crate::representations::{ClarityName, QualifiedContractIdentifier};
use crate::traits::{ClaritySerializable, ClarityDeserializable};
use crate::{clarity_serializable};

pub const MAX_VALUE_SIZE: u32 = 1024 * 1024; // 1MB
pub const BOUND_VALUE_SERIALIZATION_BYTES: u32 = MAX_VALUE_SIZE * 2;
pub const BOUND_VALUE_SERIALIZATION_HEX: u32 = BOUND_VALUE_SERIALIZATION_BYTES * 2;

pub const MAX_TYPE_DEPTH: u8 = 32;
pub const WRAPPER_VALUE_SIZE: u32 = 1;

/// Main Clarity Value type for serialization
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Int(i128),
    UInt(u128),
    Bool(bool),
    Sequence(SequenceData),
    Principal(PrincipalData),
    Tuple(TupleData),
    Optional(OptionalData),
    Response(ResponseData),
    CallableContract(CallableData),
}

/// Sequence data for different string and buffer types
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SequenceData {
    Buffer(BuffData),
    List(ListData),
    String(CharType),
}

/// Tuple data structure with type signature and data map
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct TupleData {
    pub type_signature: TupleTypeSignature,
    pub data_map: BTreeMap<ClarityName, Value>,
}

/// Buffer data structure
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuffData {
    pub data: Vec<u8>,
}

/// List data structure with type signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListData {
    pub data: Vec<Value>,
    pub type_signature: ListTypeData,
}

/// Optional data structure
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OptionalData {
    pub data: Option<Box<Value>>,
}

/// Response data structure for Ok/Error results
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResponseData {
    pub committed: bool,
    pub data: Box<Value>,
}

/// Callable contract data
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallableData {
    pub contract_identifier: QualifiedContractIdentifier,
    pub trait_identifier: Option<TraitIdentifier>,
}

/// Principal data for addresses
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrincipalData {
    Standard(StandardPrincipalData),
    Contract(QualifiedContractIdentifier),
}

/// Standard principal data with address version and bytes
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct StandardPrincipalData(pub u8, pub [u8; 20]);

/// Character type for strings (ASCII vs UTF8)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum CharType {
    ASCII(ASCIIData),
    UTF8(UTF8Data),
}

/// ASCII string data
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ASCIIData {
    pub data: Vec<u8>,
}

/// UTF8 string data  
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UTF8Data {
    pub data: Vec<u8>,
}

/// Type signature for values
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeSignature {
    IntType,
    UIntType,
    BoolType,
    BufferType(BufferLength),
    OptionalType(Box<TypeSignature>),
    ResponseType(Box<(TypeSignature, TypeSignature)>),
    SequenceType(SequenceSubtype),
    PrincipalType,
    TupleType(TupleTypeSignature),
    CallableType(CallableSubtype),
    TraitReferenceType(TraitIdentifier),
}

/// Tuple type signature
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TupleTypeSignature {
    pub type_map: BTreeMap<ClarityName, TypeSignature>,
}

/// List type data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListTypeData {
    pub max_len: u32,
    pub entry_type: Box<TypeSignature>,
}

/// Buffer length specification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BufferLength {
    Fixed(u32),
}

/// Sequence subtype for lists and buffers
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]  
pub enum SequenceSubtype {
    BufferType(BufferLength),
    ListType(ListTypeData),
    StringType(StringSubtype),
}

/// String subtype (ASCII vs UTF8)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringSubtype {
    ASCII(BufferLength),
    UTF8(StringUTF8Length),
}

/// UTF8 string length specification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringUTF8Length {
    Fixed(u32),
}

/// Callable subtype
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallableSubtype {
    Principal(QualifiedContractIdentifier),
}

/// Trait identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraitIdentifier {
    pub name: ClarityName,
    pub contract_identifier: QualifiedContractIdentifier,
}

// Implement serialization traits for core types
clarity_serializable!(Value);
clarity_serializable!(TypeSignature);
clarity_serializable!(TupleData);
clarity_serializable!(ListData);
clarity_serializable!(OptionalData);
clarity_serializable!(ResponseData);
clarity_serializable!(CallableData);
clarity_serializable!(PrincipalData);
clarity_serializable!(TupleTypeSignature);
clarity_serializable!(ListTypeData);

// Implement PartialEq for TupleData
impl PartialEq for TupleData {
    fn eq(&self, other: &Self) -> bool {
        self.type_signature == other.type_signature && self.data_map == other.data_map
    }
}

// Implement Debug for BuffData
impl std::fmt::Debug for BuffData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuffData")
            .field("data", &crate::serialization::to_hex(&self.data))
            .finish()
    }
}

impl StandardPrincipalData {
    pub fn new(version: u8, bytes: [u8; 20]) -> Result<Self, Box<dyn std::error::Error>> {
        if version >= 32 {
            return Err("Unexpected principal data".into());
        }
        Ok(Self(version, bytes))
    }

    pub fn transient() -> StandardPrincipalData {
        Self(
            1,
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        )
    }
}

impl Value {
    /// Create a None optional value
    pub fn none() -> Value {
        Value::Optional(OptionalData { data: None })
    }

    /// Create a Some optional value  
    pub fn some(v: Value) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(Value::Optional(OptionalData {
            data: Some(Box::new(v)),
        }))
    }

    /// Create an Ok response value
    pub fn ok(v: Value) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(Value::Response(ResponseData {
            committed: true,
            data: Box::new(v),
        }))
    }

    /// Create an Error response value
    pub fn error(v: Value) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(Value::Response(ResponseData {
            committed: false,
            data: Box::new(v),
        }))
    }
}