// Copyright (C) 2025 Stacks Open Internet Foundation
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

pub mod serialization;
pub mod signatures;

use core::error;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::{char, fmt, str};

use regex::Regex;
use serde::{Deserialize, Serialize};
use stacks_common::address::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, c32,
};
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::StacksAddress;
#[cfg(any(test, feature = "testing"))]
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::util::hash;

pub use self::signatures::{
    AssetIdentifier, BufferLength, ListTypeData, SequenceSubtype, StringSubtype, StringUTF8Length,
    TupleTypeSignature, TypeSignature,
};
use crate::representations::{ClarityName, ContractName, SymbolicExpression};

/// Maximum size in bytes allowed for types.
pub const MAX_VALUE_SIZE: u32 = 1024 * 1024; // 1MB
/// Bytes serialization upper limit.
pub const BOUND_VALUE_SERIALIZATION_BYTES: u32 = MAX_VALUE_SIZE * 2;
/// Hex serialization upper limit.
pub const BOUND_VALUE_SERIALIZATION_HEX: u32 = BOUND_VALUE_SERIALIZATION_BYTES * 2;
/// Maximum length for UFT8 string.
pub const MAX_UTF8_VALUE_SIZE: u32 = MAX_VALUE_SIZE / 4;
/// Maximum string length returned from `to-ascii?`.
/// 5 bytes reserved for embedding in response.
pub const MAX_TO_ASCII_RESULT_LEN: u32 = MAX_VALUE_SIZE - 5;
/// Maximum buffer length returned from `to-ascii?`.
/// 2 bytes reserved for "0x" prefix and 2 characters per byte.
pub const MAX_TO_ASCII_BUFFER_LEN: u32 = (MAX_TO_ASCII_RESULT_LEN - 2) / 2;
/// Maximum allowed nesting depth of types.
pub const MAX_TYPE_DEPTH: u8 = 32;
/// this is the charged size for wrapped values, i.e., response or optionals
pub const WRAPPER_VALUE_SIZE: u32 = 1;

/// Errors originating purely from the Clarity type system layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClarityTypeError {
    // Size & Depth Invariants
    /// The constructed value exceeds the maximum allowed Clarity value size.
    ValueTooLarge,
    /// The constructed value exceeds the maximum allowed nesting depth.
    TypeSignatureTooDeep,

    // String & Encoding Errors
    /// A non-ASCII byte was found in an ASCII string.
    InvalidAsciiCharacter(u8),
    /// The provided bytes did not form valid UTF-8.
    InvalidUtf8Encoding,

    // List, Tuple, & Structural Type Errors
    /// A list operation failed because element types do not match.
    ListTypeMismatch,
    /// An index was out of bounds for a sequence.
    ValueOutOfBounds,
    /// A tuple was constructed with duplicate field names.
    DuplicateTupleField(String),
    /// Referenced tuple field does not exist in the tuple type.
    /// The `String` wraps the requested field name, and the `TupleTypeSignature` wraps the tuple’s type.
    NoSuchTupleField(String, TupleTypeSignature),
    /// Value does not match the expected type.
    /// The `Box<TypeSignature>` wraps the expected type, and the `Box<Value>` wraps the invalid value.
    TypeMismatchValue(Box<TypeSignature>, Box<Value>),
    /// Expected type does not match the actual type during analysis.
    /// The first `Box<TypeSignature>` wraps the expected type, and the second wraps the actual type.
    TypeMismatch(Box<TypeSignature>, Box<TypeSignature>),
    /// Expected a different response type
    ResponseTypeMismatch {
        /// Whether the response type should be an `Ok` response
        expected_ok: bool,
    },
    /// Invalid contract name.
    /// The `String` represents the offending value.
    InvalidContractName(String),
    /// Invalid Clarity name.
    /// The `String` represents the offending value.
    InvalidClarityName(String),
    /// Invalid URL.
    /// The `String` represents the offending value.
    InvalidUrlString(String),
    /// Empty tuple is not allowed in Clarity.
    EmptyTuplesNotAllowed,
    /// Supertype (e.g., trait or union) exceeds the maximum allowed size or complexity.
    SupertypeTooLarge,
    /// Type description is invalid or malformed, preventing proper type-checking.
    InvalidTypeDescription,
    /// Sequence element length mismatch
    SequenceElementArityMismatch { expected: usize, found: usize },
    /// Expected a sequence value
    ExpectedSequenceValue,

    // Principal & Identifier Errors
    /// An invalid version byte was used for a principal.
    InvalidPrincipalVersion(u8),
    /// An invalid principal byte length was supplied.
    InvalidPrincipalLength(usize),
    /// C32 decode failed
    InvalidPrincipalEncoding(String),
    /// An invalid qualified identifier was supplied with a missing '.' separator.
    QualifiedContractMissingDot,
    /// An invalid qualified identifier was supplied with a missing issuer.
    QualifiedContractEmptyIssuer,

    // Type Resolution & Abstract Type Failures
    /// The value has a valid abstract type, but it cannot be serialized
    /// into a concrete consensus representation.
    CouldNotDetermineSerializationType,
    /// The type signature could not be determined.
    CouldNotDetermineType,

    /// Type is unsupported in the given epoch
    UnsupportedTypeInEpoch(Box<TypeSignature>, StacksEpochId),
    /// Unsupported epoch
    UnsupportedEpoch(StacksEpochId),
    /// Something unexpected happened that should not be possible
    InvariantViolation(String),
}

impl fmt::Display for ClarityTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl error::Error for ClarityTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct TupleData {
    // todo: remove type_signature
    pub type_signature: TupleTypeSignature,
    pub data_map: BTreeMap<ClarityName, Value>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuffData {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct ListData {
    pub data: Vec<Value>,
    // todo: remove type_signature
    pub type_signature: ListTypeData,
}

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct StandardPrincipalData(u8, pub [u8; 20]);

impl StandardPrincipalData {
    pub fn transient() -> StandardPrincipalData {
        Self(
            1,
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        )
    }
}

impl StandardPrincipalData {
    pub fn new(version: u8, bytes: [u8; 20]) -> Result<Self, ClarityTypeError> {
        if version >= 32 {
            return Err(ClarityTypeError::InvalidPrincipalVersion(version));
        }
        Ok(Self(version, bytes))
    }

    /// NEVER, EVER use this in ANY production code.
    /// `version` must NEVER be greater than 31.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_unsafe(version: u8, bytes: [u8; 20]) -> Self {
        Self(version, bytes)
    }

    pub fn null_principal() -> Self {
        Self::new(0, [0; 20]).unwrap()
    }

    pub fn version(&self) -> u8 {
        self.0
    }

    pub fn to_address(&self) -> String {
        c32::c32_address(self.0, &self.1[..]).unwrap_or_else(|_| "INVALID_C32_ADD".to_string())
    }

    pub fn destruct(self) -> (u8, [u8; 20]) {
        let Self(version, bytes) = self;
        (version, bytes)
    }

    pub fn is_mainnet(self) -> bool {
        self.0 == C32_ADDRESS_VERSION_MAINNET_MULTISIG
            || self.0 == C32_ADDRESS_VERSION_MAINNET_SINGLESIG
    }

    pub fn is_multisig(self) -> bool {
        self.0 == C32_ADDRESS_VERSION_MAINNET_MULTISIG
            || self.0 == C32_ADDRESS_VERSION_TESTNET_MULTISIG
    }
}

impl fmt::Display for StandardPrincipalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let c32_str = self.to_address();
        write!(f, "{c32_str}")
    }
}

impl fmt::Debug for StandardPrincipalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let c32_str = self.to_address();
        write!(f, "StandardPrincipalData({c32_str})")
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<&StacksPrivateKey> for StandardPrincipalData {
    fn from(o: &StacksPrivateKey) -> StandardPrincipalData {
        use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
        use stacks_common::types::chainstate::StacksPublicKey;

        let stacks_addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(o)],
        )
        .unwrap();
        StandardPrincipalData::from(stacks_addr)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct QualifiedContractIdentifier {
    pub issuer: StandardPrincipalData,
    pub name: ContractName,
}

impl QualifiedContractIdentifier {
    pub fn new(issuer: StandardPrincipalData, name: ContractName) -> QualifiedContractIdentifier {
        Self { issuer, name }
    }

    pub fn local(name: &str) -> Result<QualifiedContractIdentifier, ClarityTypeError> {
        let name = name.to_string().try_into()?;
        Ok(Self::new(StandardPrincipalData::transient(), name))
    }

    #[allow(clippy::unwrap_used)]
    pub fn transient() -> QualifiedContractIdentifier {
        let name = String::from("__transient").try_into().unwrap();
        Self {
            issuer: StandardPrincipalData::transient(),
            name,
        }
    }

    /// Was this contract issued by the null issuer address? (i.e., is it a "boot contract")
    pub fn is_boot(&self) -> bool {
        self.issuer.1 == [0; 20]
    }

    pub fn parse(literal: &str) -> Result<QualifiedContractIdentifier, ClarityTypeError> {
        let split: Vec<_> = literal.splitn(2, '.').collect();
        if split.len() != 2 {
            return Err(ClarityTypeError::QualifiedContractMissingDot);
        }
        let sender = PrincipalData::parse_standard_principal(split[0])?;
        let name = split[1].to_string().try_into()?;
        Ok(QualifiedContractIdentifier::new(sender, name))
    }
}

impl fmt::Display for QualifiedContractIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.issuer, self.name)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PrincipalData {
    Standard(StandardPrincipalData),
    Contract(QualifiedContractIdentifier),
}

#[cfg(any(test, feature = "testing"))]
impl From<&StacksPrivateKey> for PrincipalData {
    fn from(o: &StacksPrivateKey) -> PrincipalData {
        PrincipalData::Standard(StandardPrincipalData::from(o))
    }
}

pub enum ContractIdentifier {
    Relative(ContractName),
    Qualified(QualifiedContractIdentifier),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionalData {
    pub data: Option<Box<Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseData {
    pub committed: bool,
    pub data: Box<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallableData {
    pub contract_identifier: QualifiedContractIdentifier,
    pub trait_identifier: Option<TraitIdentifier>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct TraitIdentifier {
    pub name: ClarityName,
    pub contract_identifier: QualifiedContractIdentifier,
}

pub trait StacksAddressExtensions {
    fn to_account_principal(&self) -> PrincipalData;
}

impl StacksAddressExtensions for StacksAddress {
    fn to_account_principal(&self) -> PrincipalData {
        PrincipalData::Standard(
            StandardPrincipalData::new(self.version(), *self.bytes().as_bytes()).unwrap(),
        )
    }
}

impl TraitIdentifier {
    pub fn new(
        issuer: StandardPrincipalData,
        contract_name: ContractName,
        name: ClarityName,
    ) -> TraitIdentifier {
        Self {
            name,
            contract_identifier: QualifiedContractIdentifier {
                issuer,
                name: contract_name,
            },
        }
    }

    pub fn parse_fully_qualified(literal: &str) -> Result<TraitIdentifier, ClarityTypeError> {
        let (issuer, contract_name, name) = Self::parse(literal)?;
        let issuer = issuer.ok_or(ClarityTypeError::QualifiedContractEmptyIssuer)?;
        Ok(TraitIdentifier::new(issuer, contract_name, name))
    }

    pub fn parse_sugared_syntax(
        literal: &str,
    ) -> Result<(ContractName, ClarityName), ClarityTypeError> {
        let (_, contract_name, name) = Self::parse(literal)?;
        Ok((contract_name, name))
    }

    pub fn parse(
        literal: &str,
    ) -> Result<(Option<StandardPrincipalData>, ContractName, ClarityName), ClarityTypeError> {
        let split: Vec<_> = literal.splitn(3, '.').collect();
        if split.len() != 3 {
            return Err(ClarityTypeError::QualifiedContractMissingDot);
        }

        let issuer = match split[0].len() {
            0 => None,
            _ => Some(PrincipalData::parse_standard_principal(split[0])?),
        };
        let contract_name = split[1].to_string().try_into()?;
        let name = split[2].to_string().try_into()?;

        Ok((issuer, contract_name, name))
    }
}

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
    // NOTE: any new value variants which may contain _other values_ (i.e.,
    //  compound values like `Optional`, `Tuple`, `Response`, or `Sequence(List)`)
    //  must be handled in the value sanitization routine!
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SequenceData {
    Buffer(BuffData),
    List(ListData),
    String(CharType),
}

/// A helper to properly propogate errors from retain_values
#[derive(Debug)]
pub enum RetainValuesError<E> {
    /// An internal error from Clarity type system operations occurred
    Internal(ClarityTypeError),
    /// The provided predicate returned an error
    Predicate(E),
}

impl SequenceData {
    pub fn type_signature(&self) -> Result<TypeSignature, ClarityTypeError> {
        match self {
            SequenceData::Buffer(b) => b.type_signature(),
            SequenceData::List(l) => l.type_signature(),
            SequenceData::String(CharType::ASCII(a)) => a.type_signature(),
            SequenceData::String(CharType::UTF8(u)) => u.type_signature(),
        }
    }

    pub fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>, ClarityTypeError> {
        match self {
            SequenceData::Buffer(data) => data.atom_values(),
            SequenceData::List(data) => data.atom_values(),
            SequenceData::String(CharType::ASCII(data)) => data.atom_values(),
            SequenceData::String(CharType::UTF8(data)) => data.atom_values(),
        }
    }

    pub fn element_size(&self) -> Result<u32, ClarityTypeError> {
        let out = match self {
            SequenceData::Buffer(..) => TypeSignature::BUFFER_MIN.size(),
            SequenceData::List(data) => data.type_signature.get_list_item_type().size(),
            SequenceData::String(CharType::ASCII(..)) => TypeSignature::STRING_ASCII_MIN.size(),
            SequenceData::String(CharType::UTF8(..)) => TypeSignature::STRING_UTF8_MIN.size(),
        }?;
        Ok(out)
    }

    pub fn len(&self) -> usize {
        match &self {
            SequenceData::Buffer(data) => data.items().len(),
            SequenceData::List(data) => data.items().len(),
            SequenceData::String(CharType::ASCII(data)) => data.items().len(),
            SequenceData::String(CharType::UTF8(data)) => data.items().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn element_at(self, index: usize) -> Result<Option<Value>, ClarityTypeError> {
        if self.len() <= index {
            return Ok(None);
        }
        let result = match self {
            SequenceData::Buffer(data) => Value::buff_from_byte(data.data[index]),
            SequenceData::List(mut data) => data.data.remove(index),
            SequenceData::String(CharType::ASCII(data)) => {
                Value::string_ascii_from_bytes(vec![data.data[index]])?
            }
            SequenceData::String(CharType::UTF8(mut data)) => {
                Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data {
                    data: vec![data.data.remove(index)],
                })))
            }
        };

        Ok(Some(result))
    }

    pub fn replace_at(
        self,
        epoch: &StacksEpochId,
        index: usize,
        element: Value,
    ) -> Result<Value, ClarityTypeError> {
        let seq_length = self.len();

        // Check that the length of the provided element is 1. In the case that SequenceData
        // is a list, we check that the provided element is the right type below.
        if !self.is_list() {
            if let Value::Sequence(data) = &element {
                let elem_length = data.len();
                if elem_length != 1 {
                    return Err(ClarityTypeError::SequenceElementArityMismatch {
                        expected: 1,
                        found: elem_length,
                    });
                }
            } else {
                return Err(ClarityTypeError::ExpectedSequenceValue);
            }
        }
        if index >= seq_length {
            return Err(ClarityTypeError::ValueOutOfBounds);
        }

        let new_seq_data = match (self, element) {
            (SequenceData::Buffer(mut data), Value::Sequence(SequenceData::Buffer(elem))) => {
                data.data[index] = elem.data[0];
                SequenceData::Buffer(data)
            }
            (SequenceData::List(mut data), elem) => {
                let entry_type = data.type_signature.get_list_item_type();
                if !entry_type.admits(epoch, &elem)? {
                    return Err(ClarityTypeError::ListTypeMismatch);
                }
                data.data[index] = elem;
                SequenceData::List(data)
            }
            (
                SequenceData::String(CharType::ASCII(mut data)),
                Value::Sequence(SequenceData::String(CharType::ASCII(elem))),
            ) => {
                data.data[index] = elem.data[0];
                SequenceData::String(CharType::ASCII(data))
            }
            (
                SequenceData::String(CharType::UTF8(mut data)),
                Value::Sequence(SequenceData::String(CharType::UTF8(mut elem))),
            ) => {
                data.data[index] = elem.data.swap_remove(0);
                SequenceData::String(CharType::UTF8(data))
            }
            (seq, element) => {
                return Err(ClarityTypeError::TypeMismatchValue(
                    Box::new(seq.type_signature()?),
                    Box::new(element),
                ));
            }
        };

        Value::some(Value::Sequence(new_seq_data))
    }

    pub fn contains(&self, to_find: Value) -> Result<Option<usize>, ClarityTypeError> {
        match self {
            SequenceData::Buffer(data) => {
                if let Value::Sequence(SequenceData::Buffer(to_find_vec)) = to_find {
                    if to_find_vec.data.len() != 1 {
                        Ok(None)
                    } else {
                        for (index, entry) in data.data.iter().enumerate() {
                            if entry == &to_find_vec.data[0] {
                                return Ok(Some(index));
                            }
                        }
                        Ok(None)
                    }
                } else {
                    Err(ClarityTypeError::TypeMismatchValue(
                        Box::new(TypeSignature::BUFFER_MIN),
                        Box::new(to_find),
                    ))
                }
            }
            SequenceData::List(data) => {
                for (index, entry) in data.data.iter().enumerate() {
                    if entry == &to_find {
                        return Ok(Some(index));
                    }
                }
                Ok(None)
            }
            SequenceData::String(CharType::ASCII(data)) => {
                if let Value::Sequence(SequenceData::String(CharType::ASCII(to_find_vec))) = to_find
                {
                    if to_find_vec.data.len() != 1 {
                        Ok(None)
                    } else {
                        for (index, entry) in data.data.iter().enumerate() {
                            if entry == &to_find_vec.data[0] {
                                return Ok(Some(index));
                            }
                        }
                        Ok(None)
                    }
                } else {
                    Err(ClarityTypeError::TypeMismatchValue(
                        Box::new(TypeSignature::STRING_ASCII_MIN),
                        Box::new(to_find),
                    ))
                }
            }
            SequenceData::String(CharType::UTF8(data)) => {
                if let Value::Sequence(SequenceData::String(CharType::UTF8(to_find_vec))) = to_find
                {
                    if to_find_vec.data.len() != 1 {
                        Ok(None)
                    } else {
                        for (index, entry) in data.data.iter().enumerate() {
                            if entry == &to_find_vec.data[0] {
                                return Ok(Some(index));
                            }
                        }
                        Ok(None)
                    }
                } else {
                    Err(ClarityTypeError::TypeMismatchValue(
                        Box::new(TypeSignature::STRING_UTF8_MIN),
                        Box::new(to_find),
                    ))
                }
            }
        }
    }

    /// Retains elements where the predicate returns Ok(true).
    /// Removes elements where it returns Ok(false).
    /// Propagates the first error returned either by internal operations or the provided predicate.
    pub fn retain_values<E, F>(&mut self, predicate: &mut F) -> Result<(), RetainValuesError<E>>
    where
        F: FnMut(Value) -> Result<bool, E>,
    {
        // Note: this macro can probably get removed once
        // ```Vec::drain_filter<F>(&mut self, filter: F) -> DrainFilter<T, F>```
        // is available in rust stable channel (experimental at this point).
        macro_rules! drain_filter {
            ($data:expr, $seq_type:ident) => {
                let mut i = 0;
                while i != $data.data.len() {
                    let v =
                        $seq_type::to_value(&$data.data[i]).map_err(RetainValuesError::Internal)?;
                    if predicate(v).map_err(RetainValuesError::Predicate)? {
                        i += 1
                    } else {
                        $data.data.remove(i);
                    }
                }
            };
        }

        match self {
            SequenceData::Buffer(data) => {
                drain_filter!(data, BuffData);
            }
            SequenceData::List(data) => {
                drain_filter!(data, ListData);
            }
            SequenceData::String(CharType::ASCII(data)) => {
                drain_filter!(data, ASCIIData);
            }
            SequenceData::String(CharType::UTF8(data)) => {
                drain_filter!(data, UTF8Data);
            }
        }
        Ok(())
    }

    pub fn concat(
        &mut self,
        epoch: &StacksEpochId,
        other_seq: SequenceData,
    ) -> Result<(), ClarityTypeError> {
        match (self, other_seq) {
            (SequenceData::List(inner_data), SequenceData::List(other_inner_data)) => {
                inner_data.append(epoch, other_inner_data)?;
            }
            (SequenceData::Buffer(inner_data), SequenceData::Buffer(ref mut other_inner_data)) => {
                inner_data.append(other_inner_data);
            }
            (
                SequenceData::String(CharType::ASCII(inner_data)),
                SequenceData::String(CharType::ASCII(ref mut other_inner_data)),
            ) => inner_data.append(other_inner_data),
            (
                SequenceData::String(CharType::UTF8(inner_data)),
                SequenceData::String(CharType::UTF8(ref mut other_inner_data)),
            ) => inner_data.append(other_inner_data),
            (seq, other_seq) => {
                return Err(ClarityTypeError::TypeMismatch(
                    Box::new(seq.type_signature()?),
                    Box::new(other_seq.type_signature()?),
                ));
            }
        };
        Ok(())
    }

    pub fn slice(
        self,
        epoch: &StacksEpochId,
        left_position: usize,
        right_position: usize,
    ) -> Result<Value, ClarityTypeError> {
        let empty_seq = left_position == right_position;

        let result = match self {
            SequenceData::Buffer(data) => {
                let data = if empty_seq {
                    vec![]
                } else {
                    data.data[left_position..right_position].to_vec()
                };
                Value::buff_from(data)
            }
            SequenceData::List(data) => {
                let data = if empty_seq {
                    vec![]
                } else {
                    data.data[left_position..right_position].to_vec()
                };
                Value::cons_list(data, epoch)
            }
            SequenceData::String(CharType::ASCII(data)) => {
                let data = if empty_seq {
                    vec![]
                } else {
                    data.data[left_position..right_position].to_vec()
                };
                Value::string_ascii_from_bytes(data)
            }
            SequenceData::String(CharType::UTF8(data)) => {
                let data = if empty_seq {
                    vec![]
                } else {
                    data.data[left_position..right_position].to_vec()
                };
                Ok(Value::Sequence(SequenceData::String(CharType::UTF8(
                    UTF8Data { data },
                ))))
            }
        }?;

        Ok(result)
    }

    pub fn is_list(&self) -> bool {
        matches!(self, SequenceData::List(..))
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum CharType {
    UTF8(UTF8Data),
    ASCII(ASCIIData),
}

impl fmt::Display for CharType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CharType::ASCII(string) => write!(f, "{string}"),
            CharType::UTF8(string) => write!(f, "{string}"),
        }
    }
}

impl fmt::Debug for CharType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ASCIIData {
    pub data: Vec<u8>,
}

impl fmt::Display for ASCIIData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut escaped_str = String::new();
        for c in self.data.iter() {
            let escaped_char = format!("{}", std::ascii::escape_default(*c));
            escaped_str.push_str(&escaped_char);
        }
        write!(f, "\"{escaped_str}\"")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UTF8Data {
    pub data: Vec<Vec<u8>>,
}

impl fmt::Display for UTF8Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = String::new();
        for c in self.data.iter() {
            if c.len() > 1 {
                // We escape extended charset
                result.push_str(&format!("\\u{{{}}}", hash::to_hex(&c[..])));
            } else {
                // We render an ASCII char, escaped
                let escaped_char = format!("{}", std::ascii::escape_default(c[0]));
                result.push_str(&escaped_char);
            }
        }
        write!(f, "u\"{result}\"")
    }
}

pub trait SequencedValue<T> {
    fn type_signature(&self) -> std::result::Result<TypeSignature, ClarityTypeError>;

    fn items(&self) -> &Vec<T>;

    fn drained_items(&mut self) -> Vec<T>;

    fn to_value(v: &T) -> Result<Value, ClarityTypeError>;

    fn atom_values(&mut self) -> Result<Vec<SymbolicExpression>, ClarityTypeError> {
        self.drained_items()
            .iter()
            .map(|item| Ok(SymbolicExpression::atom_value(Self::to_value(item)?)))
            .collect()
    }
}

impl SequencedValue<Value> for ListData {
    fn items(&self) -> &Vec<Value> {
        &self.data
    }

    fn drained_items(&mut self) -> Vec<Value> {
        self.data.drain(..).collect()
    }

    fn type_signature(&self) -> std::result::Result<TypeSignature, ClarityTypeError> {
        Ok(TypeSignature::SequenceType(SequenceSubtype::ListType(
            self.type_signature.clone(),
        )))
    }

    fn to_value(v: &Value) -> Result<Value, ClarityTypeError> {
        Ok(v.clone())
    }
}

impl SequencedValue<u8> for BuffData {
    fn items(&self) -> &Vec<u8> {
        &self.data
    }

    fn drained_items(&mut self) -> Vec<u8> {
        self.data.drain(..).collect()
    }

    fn type_signature(&self) -> Result<TypeSignature, ClarityTypeError> {
        let buff_length = BufferLength::try_from(self.data.len()).map_err(|_| {
            ClarityTypeError::InvariantViolation(
                "ERROR: too large of a buffer successfully constructed.".into(),
            )
        })?;
        Ok(TypeSignature::SequenceType(SequenceSubtype::BufferType(
            buff_length,
        )))
    }

    fn to_value(v: &u8) -> Result<Value, ClarityTypeError> {
        Ok(Value::buff_from_byte(*v))
    }
}

impl SequencedValue<u8> for ASCIIData {
    fn items(&self) -> &Vec<u8> {
        &self.data
    }

    fn drained_items(&mut self) -> Vec<u8> {
        self.data.drain(..).collect()
    }

    fn type_signature(&self) -> std::result::Result<TypeSignature, ClarityTypeError> {
        let buff_length = BufferLength::try_from(self.data.len()).map_err(|_| {
            ClarityTypeError::InvariantViolation(
                "ERROR: too large of a buffer successfully constructed.".into(),
            )
        })?;
        Ok(TypeSignature::SequenceType(SequenceSubtype::StringType(
            StringSubtype::ASCII(buff_length),
        )))
    }

    fn to_value(v: &u8) -> Result<Value, ClarityTypeError> {
        Value::string_ascii_from_bytes(vec![*v])
    }
}

impl SequencedValue<Vec<u8>> for UTF8Data {
    fn items(&self) -> &Vec<Vec<u8>> {
        &self.data
    }

    fn drained_items(&mut self) -> Vec<Vec<u8>> {
        self.data.drain(..).collect()
    }

    fn type_signature(&self) -> std::result::Result<TypeSignature, ClarityTypeError> {
        let str_len = StringUTF8Length::try_from(self.data.len()).map_err(|_| {
            ClarityTypeError::InvariantViolation(
                "ERROR: Too large of a buffer successfully constructed.".into(),
            )
        })?;
        Ok(TypeSignature::SequenceType(SequenceSubtype::StringType(
            StringSubtype::UTF8(str_len),
        )))
    }

    fn to_value(v: &Vec<u8>) -> Result<Value, ClarityTypeError> {
        Value::string_utf8_from_bytes(v.clone())
    }
}

impl OptionalData {
    pub fn type_signature(&self) -> Result<TypeSignature, ClarityTypeError> {
        match self.data {
            Some(ref v) => TypeSignature::new_option(TypeSignature::type_of(v)?),
            None => TypeSignature::new_option(TypeSignature::NoType),
        }
        .map_err(|_| {
            ClarityTypeError::InvariantViolation(
                "ERROR: Should not have constructed too large of a type.".into(),
            )
        })
    }
}

impl ResponseData {
    pub fn type_signature(&self) -> Result<TypeSignature, ClarityTypeError> {
        match self.committed {
            true => TypeSignature::new_response(
                TypeSignature::type_of(&self.data)?,
                TypeSignature::NoType,
            ),
            false => TypeSignature::new_response(
                TypeSignature::NoType,
                TypeSignature::type_of(&self.data)?,
            ),
        }
        .map_err(|_| {
            ClarityTypeError::InvariantViolation(
                "ERROR: Should not have constructed too large of a type.".into(),
            )
        })
    }
}

impl PartialEq for ListData {
    fn eq(&self, other: &ListData) -> bool {
        self.data == other.data
    }
}

impl PartialEq for TupleData {
    fn eq(&self, other: &TupleData) -> bool {
        self.data_map == other.data_map
    }
}

pub const NONE: Value = Value::Optional(OptionalData { data: None });

impl Value {
    pub fn some(data: Value) -> Result<Value, ClarityTypeError> {
        if data.size()? + WRAPPER_VALUE_SIZE > MAX_VALUE_SIZE {
            Err(ClarityTypeError::ValueTooLarge)
        } else if data.depth()? + 1 > MAX_TYPE_DEPTH {
            Err(ClarityTypeError::TypeSignatureTooDeep)
        } else {
            Ok(Value::Optional(OptionalData {
                data: Some(Box::new(data)),
            }))
        }
    }

    pub fn none() -> Value {
        NONE.clone()
    }

    pub fn okay_true() -> Value {
        Value::Response(ResponseData {
            committed: true,
            data: Box::new(Value::Bool(true)),
        })
    }

    pub fn err_uint(ecode: u128) -> Value {
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(Value::UInt(ecode)),
        })
    }

    pub fn err_none() -> Value {
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(NONE.clone()),
        })
    }

    pub fn okay(data: Value) -> Result<Value, ClarityTypeError> {
        if data.size()? + WRAPPER_VALUE_SIZE > MAX_VALUE_SIZE {
            Err(ClarityTypeError::ValueTooLarge)
        } else if data.depth()? + 1 > MAX_TYPE_DEPTH {
            Err(ClarityTypeError::TypeSignatureTooDeep)
        } else {
            Ok(Value::Response(ResponseData {
                committed: true,
                data: Box::new(data),
            }))
        }
    }

    pub fn error(data: Value) -> Result<Value, ClarityTypeError> {
        if data.size()? + WRAPPER_VALUE_SIZE > MAX_VALUE_SIZE {
            Err(ClarityTypeError::ValueTooLarge)
        } else if data.depth()? + 1 > MAX_TYPE_DEPTH {
            Err(ClarityTypeError::TypeSignatureTooDeep)
        } else {
            Ok(Value::Response(ResponseData {
                committed: false,
                data: Box::new(data),
            }))
        }
    }

    pub fn size(&self) -> Result<u32, ClarityTypeError> {
        TypeSignature::type_of(self)?.size()
    }

    pub fn depth(&self) -> Result<u8, ClarityTypeError> {
        Ok(TypeSignature::type_of(self)?.depth())
    }

    // TODO: remove this comment. This is to help reviewers: list_with_type is only called in
    // serialization.rs where its returned error is immediately ignored. Therefore changes to the error
    // types in here are not consensus-breaking
    pub fn list_with_type(
        epoch: &StacksEpochId,
        list_data: Vec<Value>,
        expected_type: ListTypeData,
    ) -> Result<Value, ClarityTypeError> {
        if (expected_type.get_max_len() as usize) < list_data.len() {
            return Err(ClarityTypeError::ValueTooLarge);
        }

        {
            let expected_item_type = expected_type.get_list_item_type();

            for item in &list_data {
                if !expected_item_type.admits(epoch, item).unwrap_or(false) {
                    return Err(ClarityTypeError::ListTypeMismatch);
                }
            }
        }

        Ok(Value::Sequence(SequenceData::List(ListData {
            data: list_data,
            type_signature: expected_type,
        })))
    }

    pub fn cons_list_unsanitized(list_data: Vec<Value>) -> Result<Value, ClarityTypeError> {
        let type_sig = TypeSignature::construct_parent_list_type(&list_data)?;
        Ok(Value::Sequence(SequenceData::List(ListData {
            data: list_data,
            type_signature: type_sig,
        })))
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn list_from(list_data: Vec<Value>) -> Result<Value, ClarityTypeError> {
        Value::cons_list_unsanitized(list_data)
    }

    pub fn cons_list(
        list_data: Vec<Value>,
        epoch: &StacksEpochId,
    ) -> Result<Value, ClarityTypeError> {
        // Constructors for TypeSignature ensure that the size of the Value cannot
        //   be greater than MAX_VALUE_SIZE (they error on such constructions)
        // Aaron: at this point, we've _already_ allocated memory for this type.
        //     (e.g., from a (map...) call, or a (list...) call.
        //     this is a problem _if_ the static analyzer cannot already prevent
        //     this case. This applies to all the constructor size checks.
        let type_sig = TypeSignature::construct_parent_list_type(&list_data)?;
        let list_data_opt: Option<_> = list_data
            .into_iter()
            .map(|item| {
                Value::sanitize_value(epoch, type_sig.get_list_item_type(), item)
                    .map(|(value, _did_sanitize)| value)
            })
            .collect();
        let list_data = list_data_opt.ok_or_else(|| ClarityTypeError::ListTypeMismatch)?;
        Ok(Value::Sequence(SequenceData::List(ListData {
            data: list_data,
            type_signature: type_sig,
        })))
    }

    /// # Errors
    /// - ClarityTypeError::ValueTooLarge if `buff_data` is too large.
    pub fn buff_from(buff_data: Vec<u8>) -> Result<Value, ClarityTypeError> {
        // check the buffer size
        BufferLength::try_from(buff_data.len())?;
        // construct the buffer
        Ok(Value::Sequence(SequenceData::Buffer(BuffData {
            data: buff_data,
        })))
    }

    pub fn buff_from_byte(byte: u8) -> Value {
        Value::Sequence(SequenceData::Buffer(BuffData { data: vec![byte] }))
    }

    pub fn string_ascii_from_bytes(bytes: Vec<u8>) -> Result<Value, ClarityTypeError> {
        // check the string size
        BufferLength::try_from(bytes.len())?;

        for b in bytes.iter() {
            if !b.is_ascii_alphanumeric() && !b.is_ascii_punctuation() && !b.is_ascii_whitespace() {
                return Err(ClarityTypeError::InvalidAsciiCharacter(*b));
            }
        }
        // construct the string
        Ok(Value::Sequence(SequenceData::String(CharType::ASCII(
            ASCIIData { data: bytes },
        ))))
    }

    // This is parsing escaped clarity literals and is essentially part of the lexer
    pub fn string_utf8_from_string_utf8_literal(
        tokenized_str: String,
    ) -> Result<Value, ClarityTypeError> {
        let wrapped_codepoints_matcher = Regex::new("^\\\\u\\{(?P<value>[[:xdigit:]]+)\\}")
            .map_err(|_| ClarityTypeError::InvariantViolation("Bad regex".into()))?;
        let mut window = tokenized_str.as_str();
        let mut cursor = 0;
        let mut data: Vec<Vec<u8>> = vec![];
        while !window.is_empty() {
            if let Some(captures) = wrapped_codepoints_matcher.captures(window) {
                let matched = captures.name("value").ok_or_else(|| {
                    ClarityTypeError::InvariantViolation("Expected capture".into())
                })?;
                let scalar_value = window[matched.start()..matched.end()].to_string();
                let unicode_char = {
                    // This first InvalidUTF8Encoding is logically unreachable: the escape regex rejects non-hex digits,
                    // so from_str_radix only sees valid hex and never errors here.
                    let u = u32::from_str_radix(&scalar_value, 16)
                        .map_err(|_| ClarityTypeError::InvalidUtf8Encoding)?;
                    let c =
                        char::from_u32(u).ok_or_else(|| ClarityTypeError::InvalidUtf8Encoding)?;
                    let mut encoded_char: Vec<u8> = vec![0; c.len_utf8()];
                    c.encode_utf8(&mut encoded_char[..]);
                    encoded_char
                };

                data.push(unicode_char);
                cursor += scalar_value.len() + 4;
            } else {
                let ascii_char = window[0..1].to_string().into_bytes();
                data.push(ascii_char);
                cursor += 1;
            }
            // check the string size
            StringUTF8Length::try_from(data.len())?;

            window = &tokenized_str[cursor..];
        }
        // construct the string
        Ok(Value::Sequence(SequenceData::String(CharType::UTF8(
            UTF8Data { data },
        ))))
    }

    pub fn string_utf8_from_bytes(bytes: Vec<u8>) -> Result<Value, ClarityTypeError> {
        let validated_utf8_str =
            str::from_utf8(&bytes).map_err(|_| ClarityTypeError::InvalidUtf8Encoding)?;
        let data = validated_utf8_str
            .chars()
            .map(|char| {
                let mut encoded_char = vec![0u8; char.len_utf8()];
                char.encode_utf8(&mut encoded_char);
                encoded_char
            })
            .collect::<Vec<_>>();
        // check the string size
        StringUTF8Length::try_from(data.len())?;

        Ok(Value::Sequence(SequenceData::String(CharType::UTF8(
            UTF8Data { data },
        ))))
    }

    /// TODO: remove this comment. For code reviewers. Expect ascii is only called in load_cost_functions and immediately
    /// is mapped to a CostError
    pub fn expect_ascii(self) -> Result<String, ClarityTypeError> {
        if let Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) = self {
            String::from_utf8(data).map_err(|_| ClarityTypeError::InvalidUtf8Encoding)
        } else {
            error!("Value '{self:?}' is not an ASCII string");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::STRING_ASCII_MIN),
                Box::new(self),
            ))
        }
    }

    pub fn expect_u128(self) -> Result<u128, ClarityTypeError> {
        if let Value::UInt(inner) = self {
            Ok(inner)
        } else {
            error!("Value '{self:?}' is not a u128");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::UIntType),
                Box::new(self),
            ))
        }
    }

    /// TODO: from this comment. For code reviewers. This is only called in tests and/or immediately unwrapped
    /// (see calls in pox-locking/src/pox_*).
    /// Therefore, its returned value is not currently important.
    pub fn expect_i128(self) -> Result<i128, ClarityTypeError> {
        if let Value::Int(inner) = self {
            Ok(inner)
        } else {
            error!("Value '{self:?}' is not an i128");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::IntType),
                Box::new(self),
            ))
        }
    }

    pub fn expect_buff(self, sz: usize) -> Result<Vec<u8>, ClarityTypeError> {
        if let Value::Sequence(SequenceData::Buffer(buffdata)) = self {
            if buffdata.data.len() <= sz {
                Ok(buffdata.data)
            } else {
                error!(
                    "Value buffer has len {}, expected {sz}",
                    buffdata.data.len()
                );
                Err(ClarityTypeError::ValueOutOfBounds)
            }
        } else {
            error!("Value '{self:?}' is not a buff");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::BUFFER_MIN),
                Box::new(self),
            ))
        }
    }

    pub fn expect_list(self) -> Result<Vec<Value>, ClarityTypeError> {
        if let Value::Sequence(SequenceData::List(listdata)) = self {
            Ok(listdata.data)
        } else {
            error!("Value '{self:?}' is not a list");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::SequenceType(SequenceSubtype::ListType(
                    TypeSignature::empty_list(),
                ))),
                Box::new(self),
            ))
        }
    }

    pub fn expect_buff_padded(self, sz: usize, pad: u8) -> Result<Vec<u8>, ClarityTypeError> {
        let mut data = self.expect_buff(sz)?;
        if sz > data.len() {
            for _ in data.len()..sz {
                data.push(pad)
            }
        }
        Ok(data)
    }

    /// TODO: remove this comment. For code reviwers: this is only ever called in tests and/or immediately unwrapped
    /// (only non test call is its use in is_pox_active)
    pub fn expect_bool(self) -> Result<bool, ClarityTypeError> {
        if let Value::Bool(b) = self {
            Ok(b)
        } else {
            error!("Value '{self:?}' is not a bool");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::BoolType),
                Box::new(self),
            ))
        }
    }

    pub fn expect_tuple(self) -> Result<TupleData, ClarityTypeError> {
        if let Value::Tuple(data) = self {
            Ok(data)
        } else {
            error!("Value '{self:?}' is not a tuple");
            Err(ClarityTypeError::TypeMismatchValue(
                // Unfortunately cannot construct an empty Tuple type
                // And to add it now would be intrusive.
                Box::new(TypeSignature::NoType),
                Box::new(self),
            ))
        }
    }

    pub fn expect_optional(self) -> Result<Option<Value>, ClarityTypeError> {
        if let Value::Optional(opt) = self {
            match opt.data {
                Some(boxed_value) => Ok(Some(*boxed_value)),
                None => Ok(None),
            }
        } else {
            error!("Value '{self:?}' is not an optional");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::OptionalType(Box::new(TypeSignature::NoType))),
                Box::new(self),
            ))
        }
    }

    pub fn expect_principal(self) -> Result<PrincipalData, ClarityTypeError> {
        if let Value::Principal(p) = self {
            Ok(p)
        } else {
            error!("Value '{self:?}' is not a principal");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::PrincipalType),
                Box::new(self),
            ))
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn expect_callable(self) -> Result<CallableData, ClarityTypeError> {
        if let Value::CallableContract(t) = self {
            Ok(t)
        } else {
            error!("Value '{self:?}' is not a callable contract");
            // Unfortunately cannot construct an empty Callable type
            // And to add it now would be intrusive.
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::NoType),
                Box::new(self),
            ))
        }
    }

    pub fn expect_result(self) -> Result<Result<Value, Value>, ClarityTypeError> {
        if let Value::Response(res_data) = self {
            if res_data.committed {
                Ok(Ok(*res_data.data))
            } else {
                Ok(Err(*res_data.data))
            }
        } else {
            error!("Value '{self:?}' is not a response");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::ResponseType(Box::new((
                    TypeSignature::NoType,
                    TypeSignature::NoType,
                )))),
                Box::new(self),
            ))
        }
    }

    pub fn expect_result_ok(self) -> Result<Value, ClarityTypeError> {
        if let Value::Response(res_data) = self.clone() {
            if res_data.committed {
                Ok(*res_data.data)
            } else {
                error!("Value is not a (ok ..)");
                Err(ClarityTypeError::ResponseTypeMismatch { expected_ok: true })
            }
        } else {
            error!("Value '{self:?}' is not a response");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::ResponseType(Box::new((
                    TypeSignature::NoType,
                    TypeSignature::NoType,
                )))),
                Box::new(self),
            ))
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn expect_result_err(self) -> Result<Value, ClarityTypeError> {
        if let Value::Response(res_data) = self.clone() {
            if !res_data.committed {
                Ok(*res_data.data)
            } else {
                error!("Value is not a (err ..)");
                Err(ClarityTypeError::ResponseTypeMismatch { expected_ok: false })
            }
        } else {
            error!("Value '{self:?}' is not a response");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::ResponseType(Box::new((
                    TypeSignature::NoType,
                    TypeSignature::NoType,
                )))),
                Box::new(self),
            ))
        }
    }

    pub fn expect_string_ascii(self) -> Result<String, ClarityTypeError> {
        if let Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) = self {
            String::from_utf8(data).map_err(|_| ClarityTypeError::InvalidUtf8Encoding)
        } else {
            error!("Value '{self:?}' is not an ASCII string");
            Err(ClarityTypeError::TypeMismatchValue(
                Box::new(TypeSignature::STRING_ASCII_MIN),
                Box::new(self),
            ))
        }
    }
}

impl BuffData {
    pub fn len(&self) -> Result<BufferLength, ClarityTypeError> {
        self.data.len().try_into()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn append(&mut self, other_seq: &mut BuffData) {
        self.data.append(&mut other_seq.data);
    }

    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }
}

impl ListData {
    pub fn len(&self) -> Result<u32, ClarityTypeError> {
        self.data
            .len()
            .try_into()
            .map_err(|_| ClarityTypeError::ValueTooLarge)
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn append(
        &mut self,
        epoch: &StacksEpochId,
        other_seq: ListData,
    ) -> Result<(), ClarityTypeError> {
        let entry_type_a = self.type_signature.get_list_item_type();
        let entry_type_b = other_seq.type_signature.get_list_item_type();
        let entry_type = TypeSignature::factor_out_no_type(epoch, entry_type_a, entry_type_b)?;
        let max_len = self.type_signature.get_max_len() + other_seq.type_signature.get_max_len();
        for item in other_seq.data.into_iter() {
            let (item, _) = Value::sanitize_value(epoch, &entry_type, item)
                .ok_or_else(|| ClarityTypeError::ListTypeMismatch)?;
            self.data.push(item);
        }

        self.type_signature = ListTypeData::new_list(entry_type, max_len)?;
        Ok(())
    }
}

impl ASCIIData {
    fn append(&mut self, other_seq: &mut ASCIIData) {
        self.data.append(&mut other_seq.data);
    }

    pub fn len(&self) -> Result<BufferLength, ClarityTypeError> {
        self.data.len().try_into()
    }
}

impl UTF8Data {
    fn append(&mut self, other_seq: &mut UTF8Data) {
        self.data.append(&mut other_seq.data);
    }

    pub fn len(&self) -> Result<BufferLength, ClarityTypeError> {
        self.data.len().try_into()
    }
}

impl fmt::Display for OptionalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.data {
            Some(ref x) => write!(f, "(some {x})"),
            None => write!(f, "none"),
        }
    }
}

impl fmt::Display for ResponseData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.committed {
            true => write!(f, "(ok {})", self.data),
            false => write!(f, "(err {})", self.data),
        }
    }
}

impl fmt::Display for BuffData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hash::to_hex(&self.data))
    }
}

impl fmt::Debug for BuffData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Value::Int(int) => write!(f, "{int}"),
            Value::UInt(int) => write!(f, "u{int}"),
            Value::Bool(boolean) => write!(f, "{boolean}"),
            Value::Tuple(data) => write!(f, "{data}"),
            Value::Principal(principal_data) => write!(f, "{principal_data}"),
            Value::Optional(opt_data) => write!(f, "{opt_data}"),
            Value::Response(res_data) => write!(f, "{res_data}"),
            Value::Sequence(SequenceData::Buffer(vec_bytes)) => write!(f, "0x{vec_bytes}"),
            Value::Sequence(SequenceData::String(string)) => write!(f, "{string}"),
            Value::Sequence(SequenceData::List(list_data)) => {
                write!(f, "(")?;
                for (ix, v) in list_data.data.iter().enumerate() {
                    if ix > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, ")")
            }
            Value::CallableContract(callable_data) => write!(f, "{callable_data}"),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<&StacksPrivateKey> for Value {
    fn from(o: &StacksPrivateKey) -> Value {
        Value::from(StandardPrincipalData::from(o))
    }
}

impl PrincipalData {
    pub fn version(&self) -> u8 {
        match self {
            PrincipalData::Standard(p) => p.version(),
            PrincipalData::Contract(QualifiedContractIdentifier { issuer, name: _ }) => {
                issuer.version()
            }
        }
    }

    /// A version is only valid if it fits into 5 bits.
    /// This is enforced by the constructor, but it was historically possible to assemble invalid
    /// addresses.  This function is used to validate historic addresses.
    pub fn has_valid_version(&self) -> bool {
        self.version() < 32
    }

    pub fn parse(literal: &str) -> Result<PrincipalData, ClarityTypeError> {
        // be permissive about leading single-quote
        let literal = literal.strip_prefix('\'').unwrap_or(literal);

        if literal.contains('.') {
            PrincipalData::parse_qualified_contract_principal(literal)
        } else {
            PrincipalData::parse_standard_principal(literal).map(PrincipalData::from)
        }
    }

    pub fn parse_qualified_contract_principal(
        literal: &str,
    ) -> Result<PrincipalData, ClarityTypeError> {
        let contract_id = QualifiedContractIdentifier::parse(literal)?;
        Ok(PrincipalData::Contract(contract_id))
    }

    pub fn parse_standard_principal(
        literal: &str,
    ) -> Result<StandardPrincipalData, ClarityTypeError> {
        let (version, data) = c32::c32_address_decode(literal).map_err(|x| {
            // This `InvalidPrincipalLiteral` is unreachable in normal Clarity execution.
            // - All principal literals are validated by the Clarity lexer *before* reaching `parse_standard_principal`.
            // - The lexer rejects any literal containing characters outside the C32 alphabet.
            // Therefore, only malformed input fed directly into low-level VM entry points can cause this branch to execute.
            ClarityTypeError::InvalidPrincipalEncoding(x.to_string())
        })?;
        if data.len() != 20 {
            return Err(ClarityTypeError::InvalidPrincipalLength(data.len()));
        }
        let mut fixed_data = [0; 20];
        fixed_data.copy_from_slice(&data[..20]);
        StandardPrincipalData::new(version, fixed_data)
    }
}

impl fmt::Display for PrincipalData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrincipalData::Standard(sender) => write!(f, "{sender}"),
            PrincipalData::Contract(contract_identifier) => write!(
                f,
                "{}.{}",
                contract_identifier.issuer, contract_identifier.name
            ),
        }
    }
}

impl fmt::Display for CallableData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(trait_identifier) = &self.trait_identifier {
            write!(f, "({} as <{trait_identifier}>)", self.contract_identifier)
        } else {
            write!(f, "{}", self.contract_identifier,)
        }
    }
}

impl fmt::Display for TraitIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.contract_identifier, self.name)
    }
}

/// TODO: Do we want to make these return errors? I know in theory its infallible, but there is a lot of
/// in theory infallible that return errors instead of straight expects.
impl From<StacksAddress> for StandardPrincipalData {
    fn from(addr: StacksAddress) -> Self {
        let (version, bytes) = addr.destruct();

        // should be infallible because it's impossible to construct a StacksAddress with an
        // unsupported version byte
        Self::new(version, bytes.0)
            .expect("FATAL: could not convert StacksAddress to StandardPrincipalData")
    }
}

impl From<StacksAddress> for PrincipalData {
    fn from(addr: StacksAddress) -> Self {
        PrincipalData::from(StandardPrincipalData::from(addr))
    }
}

/// TODO: Do we want to make these return errors? I know in theory its infallible, but there is a lot of
/// in theory infallible that return errors instead of straight expects.
impl From<StandardPrincipalData> for StacksAddress {
    fn from(o: StandardPrincipalData) -> StacksAddress {
        // should be infallible because it's impossible to construct a StandardPrincipalData with
        // an unsupported version byte
        StacksAddress::new(o.version(), hash::Hash160(o.1))
            .expect("FATAL: could not convert a StandardPrincipalData to StacksAddress")
    }
}

impl From<StandardPrincipalData> for Value {
    fn from(principal: StandardPrincipalData) -> Self {
        Value::Principal(PrincipalData::from(principal))
    }
}

impl From<QualifiedContractIdentifier> for Value {
    fn from(principal: QualifiedContractIdentifier) -> Self {
        Value::Principal(PrincipalData::Contract(principal))
    }
}

impl From<PrincipalData> for Value {
    fn from(p: PrincipalData) -> Self {
        Value::Principal(p)
    }
}

impl From<StandardPrincipalData> for PrincipalData {
    fn from(p: StandardPrincipalData) -> Self {
        PrincipalData::Standard(p)
    }
}

impl From<QualifiedContractIdentifier> for PrincipalData {
    fn from(principal: QualifiedContractIdentifier) -> Self {
        PrincipalData::Contract(principal)
    }
}

impl From<TupleData> for Value {
    fn from(t: TupleData) -> Self {
        Value::Tuple(t)
    }
}

impl From<ASCIIData> for Value {
    fn from(ascii: ASCIIData) -> Self {
        Value::Sequence(SequenceData::String(CharType::ASCII(ascii)))
    }
}
impl From<ContractName> for ASCIIData {
    fn from(name: ContractName) -> Self {
        // ContractName is guaranteed to be between 5 and 40 bytes and contains only printable
        // ASCII already, so this conversion should not fail.
        ASCIIData {
            data: name.as_str().as_bytes().to_vec(),
        }
    }
}

impl TupleData {
    fn new(
        type_signature: TupleTypeSignature,
        data_map: BTreeMap<ClarityName, Value>,
    ) -> TupleData {
        TupleData {
            type_signature,
            data_map,
        }
    }

    /// Return the number of fields in this tuple value
    pub fn len(&self) -> u64 {
        self.data_map.len() as u64
    }

    /// Checks whether the tuple value is empty
    pub fn is_empty(&self) -> bool {
        self.data_map.is_empty()
    }

    // TODO: add tests from mutation testing results #4833
    #[cfg_attr(test, mutants::skip)]
    pub fn from_data(data: Vec<(ClarityName, Value)>) -> Result<TupleData, ClarityTypeError> {
        let mut type_map = BTreeMap::new();
        let mut data_map = BTreeMap::new();
        for (name, value) in data.into_iter() {
            let type_info = TypeSignature::type_of(&value)?;
            let entry = type_map.entry(name.clone());
            match entry {
                Entry::Vacant(e) => e.insert(type_info),
                Entry::Occupied(_) => {
                    return Err(ClarityTypeError::DuplicateTupleField(name.into()));
                }
            };
            data_map.insert(name, value);
        }

        Ok(Self::new(TupleTypeSignature::try_from(type_map)?, data_map))
    }

    // TODO: add tests from mutation testing results #4834
    // TODO: remove this comment. This is to help reviewers: from_data_typed is only called in
    // serialization.rs where its returned error is immediately ignored. Therefore changes to the error
    // types in here are not consensus-breaking
    #[cfg_attr(test, mutants::skip)]
    pub fn from_data_typed(
        epoch: &StacksEpochId,
        data: Vec<(ClarityName, Value)>,
        expected: &TupleTypeSignature,
    ) -> Result<TupleData, ClarityTypeError> {
        let mut data_map = BTreeMap::new();

        for (name, value) in data.into_iter() {
            // User provided a field not declared in the expected tuple type
            let expected_type = expected.field_type(&name).ok_or_else(|| {
                ClarityTypeError::NoSuchTupleField(name.to_string(), expected.clone())
            })?;

            // User provided a value that does not match the declared field type
            if !expected_type.admits(epoch, &value).unwrap_or(false) {
                return Err(ClarityTypeError::TypeMismatchValue(
                    Box::new(expected_type.clone()),
                    Box::new(value),
                ));
            }

            data_map.insert(name, value);
        }

        Ok(Self::new(expected.clone(), data_map))
    }

    pub fn get(&self, name: &str) -> Result<&Value, ClarityTypeError> {
        self.data_map.get(name).ok_or_else(|| {
            ClarityTypeError::NoSuchTupleField(name.to_string(), self.type_signature.clone())
        })
    }

    pub fn get_owned(mut self, name: &str) -> Result<Value, ClarityTypeError> {
        self.data_map.remove(name).ok_or_else(|| {
            ClarityTypeError::NoSuchTupleField(name.to_string(), self.type_signature.clone())
        })
    }

    pub fn shallow_merge(mut base: TupleData, updates: TupleData) -> TupleData {
        let TupleData {
            data_map,
            mut type_signature,
        } = updates;
        for (name, value) in data_map.into_iter() {
            base.data_map.insert(name, value);
        }
        base.type_signature.shallow_merge(&mut type_signature);
        base
    }
}

impl fmt::Display for TupleData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(tuple")?;
        for (name, value) in self.data_map.iter() {
            write!(f, " ")?;
            write!(f, "({} {value})", &**name)?;
        }
        write!(f, ")")
    }
}

/// Given the serialized string representation of a Clarity value,
///  return the size of the same byte representation.
pub fn byte_len_of_serialization(serialized: &str) -> u64 {
    serialized.len() as u64 / 2
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct FunctionIdentifier {
    identifier: String,
}

impl fmt::Display for FunctionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl FunctionIdentifier {
    pub fn new_native_function(name: &str) -> FunctionIdentifier {
        let identifier = format!("_native_:{name}");
        FunctionIdentifier { identifier }
    }

    pub fn new_user_function(name: &str, context: &str) -> FunctionIdentifier {
        let identifier = format!("{context}:{name}");
        FunctionIdentifier { identifier }
    }
}
