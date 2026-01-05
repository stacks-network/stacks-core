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

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;
use std::sync::Arc;
use std::{cmp, fmt};

use serde::{Deserialize, Serialize};
use stacks_common::types::StacksEpochId;

use crate::representations::{CONTRACT_MAX_NAME_LENGTH, ClarityName, ContractName};
use crate::types::{
    CharType, ClarityTypeError, MAX_TO_ASCII_BUFFER_LEN, MAX_TO_ASCII_RESULT_LEN, MAX_TYPE_DEPTH,
    MAX_UTF8_VALUE_SIZE, MAX_VALUE_SIZE, PrincipalData, QualifiedContractIdentifier, SequenceData,
    SequencedValue, StandardPrincipalData, TraitIdentifier, Value, WRAPPER_VALUE_SIZE,
};

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Serialize, Deserialize, Hash)]
pub struct AssetIdentifier {
    pub contract_identifier: QualifiedContractIdentifier,
    pub asset_name: ClarityName,
}

impl AssetIdentifier {
    #[allow(non_snake_case)]
    #[allow(clippy::unwrap_used)]
    pub fn STX() -> AssetIdentifier {
        AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::null_principal(),
                ContractName::try_from("STX".to_string()).unwrap(),
            ),
            asset_name: ClarityName::try_from("STX".to_string()).unwrap(),
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::unwrap_used)]
    pub fn STX_burned() -> AssetIdentifier {
        AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::null_principal(),
                ContractName::try_from("BURNED".to_string()).unwrap(),
            ),
            asset_name: ClarityName::try_from("BURNED".to_string()).unwrap(),
        }
    }

    pub fn sugared(&self) -> String {
        format!(".{}.{}", self.contract_identifier.name, self.asset_name)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TupleTypeSignature {
    #[serde(with = "tuple_type_map_serde")]
    type_map: Arc<BTreeMap<ClarityName, TypeSignature>>,
}

mod tuple_type_map_serde {
    use std::collections::BTreeMap;
    use std::ops::Deref;
    use std::sync::Arc;

    use serde::{Deserializer, Serializer};

    use super::TypeSignature;
    use crate::representations::ClarityName;

    pub fn serialize<S: Serializer>(
        map: &Arc<BTreeMap<ClarityName, TypeSignature>>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(map.deref(), ser)
    }

    pub fn deserialize<'de, D>(
        deser: D,
    ) -> Result<Arc<BTreeMap<ClarityName, TypeSignature>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: BTreeMap<ClarityName, TypeSignature> = serde::Deserialize::deserialize(deser)?;
        Ok(Arc::new(map))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BufferLength(u32);

impl BufferLength {
    /// Attempts to create a [`BufferLength`] from a [`u32`] as an [`Option`].
    ///
    /// This function is primarily intended for internal use when defining
    /// `const` values, since it returns an [`Option`] that can be unwrapped
    /// with [`Option::expect`] in a `const fn`.
    const fn try_from_u32_as_opt(value: u32) -> Option<BufferLength> {
        if value > MAX_VALUE_SIZE {
            None
        } else {
            Some(BufferLength(value))
        }
    }

    /// Attempts to create a [`BufferLength`] from a [`i128`] as a [`Result`].
    ///
    /// This function is primarily intended for internal runtime use,
    /// and serves as the central place for all integer validation logic.
    fn try_from_i128(data: i128) -> Result<Self, ClarityTypeError> {
        if data > (MAX_VALUE_SIZE as i128) {
            Err(ClarityTypeError::ValueTooLarge)
        } else if data < 0 {
            Err(ClarityTypeError::ValueOutOfBounds)
        } else {
            Ok(BufferLength(data as u32))
        }
    }
}

/// Test-only utilities for [`BufferLength`].
#[cfg(test)]
impl BufferLength {
    /// Allow to create a [`BufferLength`] in unsafe way,
    /// allowing direct write-access to its internal state.
    pub fn new_unsafe(value: u32) -> Self {
        Self(value)
    }

    /// Returns the underlying [`u32`] value of this [`BufferLength`].
    /// This to have an easy read-access to its internal state.
    pub fn get_value(&self) -> u32 {
        self.0
    }
}

impl From<&BufferLength> for u32 {
    fn from(v: &BufferLength) -> u32 {
        v.0
    }
}

impl From<BufferLength> for u32 {
    fn from(v: BufferLength) -> u32 {
        v.0
    }
}

impl TryFrom<u32> for BufferLength {
    type Error = ClarityTypeError;
    fn try_from(data: u32) -> Result<BufferLength, ClarityTypeError> {
        Self::try_from(data as i128)
    }
}

impl TryFrom<usize> for BufferLength {
    type Error = ClarityTypeError;
    fn try_from(data: usize) -> Result<BufferLength, ClarityTypeError> {
        Self::try_from(data as i128)
    }
}

impl TryFrom<i128> for BufferLength {
    type Error = ClarityTypeError;
    fn try_from(data: i128) -> Result<BufferLength, ClarityTypeError> {
        Self::try_from_i128(data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringUTF8Length(u32);

impl StringUTF8Length {
    /// Attempts to create a [`StringUTF8Length`] from a [`u32`] as an [`Option`].
    ///
    /// This function is primarily intended for internal use when defining
    /// `const` values, since it returns an [`Option`] that can be unwrapped
    /// with [`Option::expect`] in a `const fn`.
    const fn try_from_u32_as_opt(value: u32) -> Option<StringUTF8Length> {
        if value > MAX_UTF8_VALUE_SIZE {
            None
        } else {
            Some(StringUTF8Length(value))
        }
    }

    /// Attempts to create a [`StringUTF8Length`] from a [`i128`] as a [`Result`].
    ///
    /// This function is primarily intended for internal runtime use,
    /// and serves as the central place for all integer validation logic.
    fn try_from_i128(value: i128) -> Result<Self, ClarityTypeError> {
        if value > MAX_UTF8_VALUE_SIZE as i128 {
            Err(ClarityTypeError::ValueTooLarge)
        } else if value < 0 {
            Err(ClarityTypeError::ValueOutOfBounds)
        } else {
            Ok(StringUTF8Length(value as u32))
        }
    }
}

/// Test-only utilities for [`StringUTF8Length`].
#[cfg(test)]
impl StringUTF8Length {
    /// Allow to create a [`StringUTF8Length`] in unsafe way,
    /// allowing direct write-access to its internal state.
    pub fn new_unsafe(value: u32) -> Self {
        Self(value)
    }

    /// Returns the underlying [`u32`] value of this [`StringUTF8Length`].
    /// This to have an easy read-access to its internal state.
    pub fn get_value(&self) -> u32 {
        self.0
    }
}

impl From<&StringUTF8Length> for u32 {
    fn from(v: &StringUTF8Length) -> u32 {
        v.0
    }
}

impl From<StringUTF8Length> for u32 {
    fn from(v: StringUTF8Length) -> u32 {
        v.0
    }
}

impl TryFrom<u32> for StringUTF8Length {
    type Error = ClarityTypeError;
    fn try_from(data: u32) -> Result<StringUTF8Length, ClarityTypeError> {
        Self::try_from(data as i128)
    }
}

impl TryFrom<usize> for StringUTF8Length {
    type Error = ClarityTypeError;
    fn try_from(data: usize) -> Result<StringUTF8Length, ClarityTypeError> {
        Self::try_from(data as i128)
    }
}

impl TryFrom<i128> for StringUTF8Length {
    type Error = ClarityTypeError;
    fn try_from(data: i128) -> Result<StringUTF8Length, ClarityTypeError> {
        Self::try_from_i128(data)
    }
}

// INVARIANTS enforced by the Type Signatures.
//   1. A TypeSignature constructor will always fail rather than construct a
//        type signature for a too large or invalid type. This is why any variable length
//        type signature has a guarded constructor.
//   2. The only methods which may be called on TypeSignatures that are too large
//        (i.e., the only function that can be called by the constructor before
//         it fails) is the `.size()` method, which may be used to check the size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSignature {
    NoType,
    IntType,
    UIntType,
    BoolType,
    SequenceType(SequenceSubtype),
    PrincipalType,
    TupleType(TupleTypeSignature),
    OptionalType(Box<TypeSignature>),
    ResponseType(Box<(TypeSignature, TypeSignature)>),
    CallableType(CallableSubtype),
    // Suppose we have a list of contract principal literals, e.g.
    // `(list .foo .bar)`. This list could be used as a list of `principal`
    // types, or it could be passed into a function where it is used a list of
    // some trait type, which every contract in the list implements, e.g.
    // `(list 4 <my-trait>)`. There could also be a trait value, `t`, in that
    // list. In that case, the list could no longer be coerced to a list of
    // principals, but it could be coerced to a list of traits, either the type
    // of `t`, or a compatible sub-trait of that type. `ListUnionType` is a
    // data structure to maintain the set of types in the list, so that when
    // we reach the place where the coercion needs to happen, we can perform
    // the check -- see `concretize` method.
    ListUnionType(HashSet<CallableSubtype>),
    // This is used only below epoch 2.1. It has been replaced by CallableType.
    TraitReferenceType(TraitIdentifier),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SequenceSubtype {
    BufferType(BufferLength),
    ListType(ListTypeData),
    StringType(StringSubtype),
}

impl SequenceSubtype {
    pub fn unit_type(&self) -> TypeSignature {
        match &self {
            SequenceSubtype::ListType(list_data) => list_data.clone().destruct().0,
            SequenceSubtype::BufferType(_) => TypeSignature::BUFFER_MIN,
            SequenceSubtype::StringType(StringSubtype::ASCII(_)) => TypeSignature::STRING_ASCII_MIN,
            SequenceSubtype::StringType(StringSubtype::UTF8(_)) => TypeSignature::STRING_UTF8_MIN,
        }
    }

    pub fn is_list_type(&self) -> bool {
        matches!(self, SequenceSubtype::ListType(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringSubtype {
    ASCII(BufferLength),
    UTF8(StringUTF8Length),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum CallableSubtype {
    Principal(QualifiedContractIdentifier),
    Trait(TraitIdentifier),
}

use self::TypeSignature::{
    BoolType, CallableType, IntType, ListUnionType, NoType, OptionalType, PrincipalType,
    ResponseType, SequenceType, TraitReferenceType, TupleType, UIntType,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListTypeData {
    max_len: u32,
    entry_type: Box<TypeSignature>,
}

impl From<ListTypeData> for TypeSignature {
    fn from(data: ListTypeData) -> Self {
        SequenceType(SequenceSubtype::ListType(data))
    }
}

impl From<TupleTypeSignature> for TypeSignature {
    fn from(data: TupleTypeSignature) -> Self {
        TupleType(data)
    }
}

impl ListTypeData {
    pub fn new_list(
        entry_type: TypeSignature,
        max_len: u32,
    ) -> Result<ListTypeData, ClarityTypeError> {
        let would_be_depth = 1 + entry_type.depth();
        if would_be_depth > MAX_TYPE_DEPTH {
            return Err(ClarityTypeError::TypeSignatureTooDeep);
        }

        let list_data = ListTypeData {
            entry_type: Box::new(entry_type),
            max_len,
        };
        let would_be_size = list_data
            .inner_size()?
            .ok_or_else(|| ClarityTypeError::ValueTooLarge)?;
        if would_be_size > MAX_VALUE_SIZE {
            Err(ClarityTypeError::ValueTooLarge)
        } else {
            Ok(list_data)
        }
    }

    pub fn destruct(self) -> (TypeSignature, u32) {
        (*self.entry_type, self.max_len)
    }

    // if checks like as-max-len pass, they may _reduce_
    //   but should not increase the type signatures max length
    pub fn reduce_max_len(&mut self, new_max_len: u32) {
        if new_max_len <= self.max_len {
            self.max_len = new_max_len;
        }
    }

    pub fn get_max_len(&self) -> u32 {
        self.max_len
    }

    pub fn get_list_item_type(&self) -> &TypeSignature {
        &self.entry_type
    }
}

impl TypeSignature {
    pub fn new_option(inner_type: TypeSignature) -> Result<TypeSignature, ClarityTypeError> {
        let new_size = WRAPPER_VALUE_SIZE + inner_type.size()?;
        let new_depth = 1 + inner_type.depth();
        if new_size > MAX_VALUE_SIZE {
            Err(ClarityTypeError::ValueTooLarge)
        } else if new_depth > MAX_TYPE_DEPTH {
            Err(ClarityTypeError::TypeSignatureTooDeep)
        } else {
            Ok(OptionalType(Box::new(inner_type)))
        }
    }

    pub fn new_response(
        ok_type: TypeSignature,
        err_type: TypeSignature,
    ) -> Result<TypeSignature, ClarityTypeError> {
        let new_size = WRAPPER_VALUE_SIZE + cmp::max(ok_type.size()?, err_type.size()?);
        let new_depth = 1 + cmp::max(ok_type.depth(), err_type.depth());

        if new_size > MAX_VALUE_SIZE {
            Err(ClarityTypeError::ValueTooLarge)
        } else if new_depth > MAX_TYPE_DEPTH {
            Err(ClarityTypeError::TypeSignatureTooDeep)
        } else {
            Ok(ResponseType(Box::new((ok_type, err_type))))
        }
    }

    pub fn is_response_type(&self) -> bool {
        matches!(self, TypeSignature::ResponseType(_))
    }

    pub fn is_no_type(&self) -> bool {
        &TypeSignature::NoType == self
    }

    pub fn admits(&self, epoch: &StacksEpochId, x: &Value) -> Result<bool, ClarityTypeError> {
        let x_type = TypeSignature::type_of(x)?;
        self.admits_type(epoch, &x_type)
    }

    pub fn admits_type(
        &self,
        epoch: &StacksEpochId,
        other: &TypeSignature,
    ) -> Result<bool, ClarityTypeError> {
        match epoch {
            StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => self.admits_type_v2_0(other),
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => self.admits_type_v2_1(other),
            StacksEpochId::Epoch10 => Err(ClarityTypeError::UnsupportedEpoch(*epoch)),
        }
    }

    pub fn admits_type_v2_0(&self, other: &TypeSignature) -> Result<bool, ClarityTypeError> {
        match self {
            SequenceType(SequenceSubtype::ListType(my_list_type)) => {
                if let SequenceType(SequenceSubtype::ListType(other_list_type)) = other {
                    if other_list_type.max_len == 0 {
                        // if other is an empty list, a list type should always admit.
                        Ok(true)
                    } else if my_list_type.max_len >= other_list_type.max_len {
                        my_list_type
                            .entry_type
                            .admits_type_v2_0(&other_list_type.entry_type)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            SequenceType(SequenceSubtype::BufferType(my_len)) => {
                if let SequenceType(SequenceSubtype::BufferType(other_len)) = other {
                    Ok(my_len.0 >= other_len.0)
                } else {
                    Ok(false)
                }
            }
            SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(len))) => {
                if let SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(other_len))) =
                    other
                {
                    Ok(len.0 >= other_len.0)
                } else {
                    Ok(false)
                }
            }
            SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(len))) => {
                if let SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(other_len))) =
                    other
                {
                    Ok(len.0 >= other_len.0)
                } else {
                    Ok(false)
                }
            }
            OptionalType(my_inner_type) => {
                if let OptionalType(other_inner_type) = other {
                    // Option types will always admit a "NoType" OptionalType -- which
                    //   can only be a None
                    if other_inner_type.is_no_type() {
                        Ok(true)
                    } else {
                        my_inner_type.admits_type_v2_0(other_inner_type)
                    }
                } else {
                    Ok(false)
                }
            }
            ResponseType(my_inner_type) => {
                if let ResponseType(other_inner_type) = other {
                    // ResponseTypes admit according to the following rule:
                    //   if other.ErrType is NoType, and other.OkType admits => admit
                    //   if other.OkType is NoType, and other.ErrType admits => admit
                    //   if both OkType and ErrType admit => admit
                    //   otherwise fail.
                    if other_inner_type.0.is_no_type() {
                        my_inner_type.1.admits_type_v2_0(&other_inner_type.1)
                    } else if other_inner_type.1.is_no_type() {
                        my_inner_type.0.admits_type_v2_0(&other_inner_type.0)
                    } else {
                        Ok(my_inner_type.1.admits_type_v2_0(&other_inner_type.1)?
                            && my_inner_type.0.admits_type_v2_0(&other_inner_type.0)?)
                    }
                } else {
                    Ok(false)
                }
            }
            TupleType(tuple_sig) => {
                if let TupleType(other_tuple_sig) = other {
                    tuple_sig.admits(&StacksEpochId::Epoch2_05, other_tuple_sig)
                } else {
                    Ok(false)
                }
            }
            NoType => Err(ClarityTypeError::CouldNotDetermineType),
            CallableType(_) | ListUnionType(_) => Err(ClarityTypeError::UnsupportedTypeInEpoch(
                Box::new(self.clone()),
                StacksEpochId::Epoch20,
            )),
            _ => Ok(other == self),
        }
    }

    fn admits_type_v2_1(&self, other: &TypeSignature) -> Result<bool, ClarityTypeError> {
        let other = match other.concretize() {
            Ok(other) => other,
            Err(_) => {
                return Ok(false);
            }
        };

        match self {
            SequenceType(SequenceSubtype::ListType(my_list_type)) => {
                if let SequenceType(SequenceSubtype::ListType(other_list_type)) = &other {
                    if other_list_type.max_len == 0 {
                        // if other is an empty list, a list type should always admit.
                        Ok(true)
                    } else if my_list_type.max_len >= other_list_type.max_len {
                        my_list_type
                            .entry_type
                            .admits_type_v2_1(&other_list_type.entry_type)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            SequenceType(SequenceSubtype::BufferType(my_len)) => {
                if let SequenceType(SequenceSubtype::BufferType(other_len)) = &other {
                    Ok(my_len.0 >= other_len.0)
                } else {
                    Ok(false)
                }
            }
            SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(len))) => {
                if let SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(other_len))) =
                    &other
                {
                    Ok(len.0 >= other_len.0)
                } else {
                    Ok(false)
                }
            }
            SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(len))) => {
                if let SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(other_len))) =
                    &other
                {
                    Ok(len.0 >= other_len.0)
                } else {
                    Ok(false)
                }
            }
            OptionalType(my_inner_type) => {
                if let OptionalType(other_inner_type) = &other {
                    // Option types will always admit a "NoType" OptionalType -- which
                    //   can only be a None
                    if other_inner_type.is_no_type() {
                        Ok(true)
                    } else {
                        my_inner_type.admits_type_v2_1(other_inner_type)
                    }
                } else {
                    Ok(false)
                }
            }
            ResponseType(my_inner_type) => {
                if let ResponseType(other_inner_type) = &other {
                    // ResponseTypes admit according to the following rule:
                    //   if other.ErrType is NoType, and other.OkType admits => admit
                    //   if other.OkType is NoType, and other.ErrType admits => admit
                    //   if both OkType and ErrType admit => admit
                    //   otherwise fail.
                    if other_inner_type.0.is_no_type() {
                        my_inner_type.1.admits_type_v2_1(&other_inner_type.1)
                    } else if other_inner_type.1.is_no_type() {
                        my_inner_type.0.admits_type_v2_1(&other_inner_type.0)
                    } else {
                        Ok(my_inner_type.1.admits_type_v2_1(&other_inner_type.1)?
                            && my_inner_type.0.admits_type_v2_1(&other_inner_type.0)?)
                    }
                } else {
                    Ok(false)
                }
            }
            TupleType(tuple_sig) => {
                if let TupleType(other_tuple_sig) = &other {
                    tuple_sig.admits(&StacksEpochId::Epoch21, other_tuple_sig)
                } else {
                    Ok(false)
                }
            }
            NoType => Err(ClarityTypeError::CouldNotDetermineType),
            _ => Ok(&other == self),
        }
    }

    /// Canonicalize a type.
    /// This method will convert types from previous epochs with the appropriate
    /// types for the specified epoch.
    pub fn canonicalize(&self, epoch: &StacksEpochId) -> TypeSignature {
        match epoch {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            // Epoch-2.2 had a regression in canonicalization, so it must be preserved here.
            | StacksEpochId::Epoch22 => self.clone(),
            // Note for future epochs: Epochs >= 2.3 should use the canonicalize_v2_1() routine
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => self.canonicalize_v2_1(),
        }
    }

    pub fn canonicalize_v2_1(&self) -> TypeSignature {
        match self {
            SequenceType(SequenceSubtype::ListType(list_type)) => {
                SequenceType(SequenceSubtype::ListType(ListTypeData {
                    max_len: list_type.max_len,
                    entry_type: Box::new(list_type.entry_type.canonicalize_v2_1()),
                }))
            }
            OptionalType(inner_type) => OptionalType(Box::new(inner_type.canonicalize_v2_1())),
            ResponseType(inner_type) => ResponseType(Box::new((
                inner_type.0.canonicalize_v2_1(),
                inner_type.1.canonicalize_v2_1(),
            ))),
            TupleType(tuple_sig) => {
                let mut canonicalized_fields = BTreeMap::new();
                for (field_name, field_type) in tuple_sig.get_type_map() {
                    canonicalized_fields.insert(field_name.clone(), field_type.canonicalize_v2_1());
                }
                TypeSignature::from(TupleTypeSignature {
                    type_map: Arc::new(canonicalized_fields),
                })
            }
            TraitReferenceType(trait_id) => CallableType(CallableSubtype::Trait(trait_id.clone())),
            _ => self.clone(),
        }
    }

    /// Concretize the type. The input to this method may include
    /// `ListUnionType` and the `CallableType` variant for a `principal.
    /// This method turns these "temporary" types into actual types.
    pub fn concretize(&self) -> Result<TypeSignature, ClarityTypeError> {
        match self {
            ListUnionType(types) => {
                let mut is_trait = None;
                let mut is_principal = true;
                for partial in types {
                    match partial {
                        CallableSubtype::Principal(_) => {
                            if is_trait.is_some() {
                                return Err(ClarityTypeError::TypeMismatch(
                                    Box::new(TypeSignature::CallableType(partial.clone())),
                                    Box::new(TypeSignature::PrincipalType),
                                ));
                            } else {
                                is_principal = true;
                            }
                        }
                        CallableSubtype::Trait(t) => {
                            if is_principal {
                                return Err(ClarityTypeError::TypeMismatch(
                                    Box::new(TypeSignature::PrincipalType),
                                    Box::new(TypeSignature::CallableType(partial.clone())),
                                ));
                            } else {
                                is_trait = Some(t.clone());
                            }
                        }
                    }
                }
                if let Some(t) = is_trait {
                    Ok(TypeSignature::CallableType(CallableSubtype::Trait(t)))
                } else {
                    Ok(TypeSignature::PrincipalType)
                }
            }
            CallableType(CallableSubtype::Principal(_)) => Ok(TypeSignature::PrincipalType),
            _ => Ok(self.clone()),
        }
    }
}

impl TryFrom<Vec<(ClarityName, TypeSignature)>> for TupleTypeSignature {
    type Error = ClarityTypeError;
    fn try_from(
        type_data: Vec<(ClarityName, TypeSignature)>,
    ) -> Result<TupleTypeSignature, ClarityTypeError> {
        if type_data.is_empty() {
            return Err(ClarityTypeError::EmptyTuplesNotAllowed);
        }

        let mut type_map = BTreeMap::new();
        for (name, type_info) in type_data.into_iter() {
            if let Entry::Vacant(e) = type_map.entry(name.clone()) {
                e.insert(type_info);
            } else {
                return Err(ClarityTypeError::DuplicateTupleField(name.into()));
            }
        }
        TupleTypeSignature::try_from(type_map)
    }
}

impl TryFrom<BTreeMap<ClarityName, TypeSignature>> for TupleTypeSignature {
    type Error = ClarityTypeError;
    fn try_from(
        type_map: BTreeMap<ClarityName, TypeSignature>,
    ) -> Result<TupleTypeSignature, ClarityTypeError> {
        if type_map.is_empty() {
            return Err(ClarityTypeError::EmptyTuplesNotAllowed);
        }
        for child_sig in type_map.values() {
            if (1 + child_sig.depth()) > MAX_TYPE_DEPTH {
                return Err(ClarityTypeError::TypeSignatureTooDeep);
            }
        }
        let type_map = Arc::new(type_map.into_iter().collect());
        let result = TupleTypeSignature { type_map };
        let would_be_size = result
            .inner_size()?
            .ok_or_else(|| ClarityTypeError::ValueTooLarge)?;
        if would_be_size > MAX_VALUE_SIZE {
            Err(ClarityTypeError::ValueTooLarge)
        } else {
            Ok(result)
        }
    }
}

impl TupleTypeSignature {
    /// Return the number of fields in this tuple type
    pub fn len(&self) -> u64 {
        self.type_map.len() as u64
    }

    /// Returns whether the tuple type is empty
    pub fn is_empty(&self) -> bool {
        self.type_map.is_empty()
    }

    pub fn field_type(&self, field: &str) -> Option<&TypeSignature> {
        self.type_map.get(field)
    }

    pub fn get_type_map(&self) -> &BTreeMap<ClarityName, TypeSignature> {
        &self.type_map
    }

    pub fn admits(
        &self,
        epoch: &StacksEpochId,
        other: &TupleTypeSignature,
    ) -> Result<bool, ClarityTypeError> {
        if self.type_map.len() != other.type_map.len() {
            return Ok(false);
        }

        for (name, my_type_sig) in self.type_map.iter() {
            if let Some(other_type_sig) = other.type_map.get(name) {
                if !my_type_sig.admits_type(epoch, other_type_sig)? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn shallow_merge(&mut self, update: &mut TupleTypeSignature) {
        Arc::make_mut(&mut self.type_map).append(Arc::make_mut(&mut update.type_map));
    }
}

impl TypeSignature {
    /// Buffer type with minimum length. Alias for [`TypeSignature::BUFFER_1`].
    pub const BUFFER_MIN: TypeSignature = TypeSignature::BUFFER_1;
    /// Buffer type with maximum length ([`MAX_VALUE_SIZE`]).
    pub const BUFFER_MAX: TypeSignature = Self::type_buffer_const(MAX_VALUE_SIZE);
    /// Buffer type with length 1.
    pub const BUFFER_1: TypeSignature = Self::type_buffer_const(1);
    /// Buffer type with length 20.
    pub const BUFFER_20: TypeSignature = Self::type_buffer_const(20);
    /// Buffer type with length 32.
    pub const BUFFER_32: TypeSignature = Self::type_buffer_const(32);
    /// Buffer type with length 33.
    pub const BUFFER_33: TypeSignature = Self::type_buffer_const(33);
    /// Buffer type with length 64.
    pub const BUFFER_64: TypeSignature = Self::type_buffer_const(64);
    /// Buffer type with length 65.
    pub const BUFFER_65: TypeSignature = Self::type_buffer_const(65);

    /// String ASCII type with minimum length (`1`).
    pub const STRING_ASCII_MIN: TypeSignature = Self::type_ascii_const(1);
    /// String ASCII type with maximum length ([`MAX_VALUE_SIZE`]).
    pub const STRING_ASCII_MAX: TypeSignature = Self::type_ascii_const(MAX_VALUE_SIZE);
    /// String ASCII type with length 40.
    pub const STRING_ASCII_40: TypeSignature = Self::type_ascii_const(40);
    /// String ASCII type with length 128.
    pub const STRING_ASCII_128: TypeSignature = Self::type_ascii_const(128);

    /// String UTF8 type with minimum length (`1`).
    pub const STRING_UTF8_MIN: TypeSignature = Self::type_string_utf8(1);
    /// String UTF8 type with maximum length ([`MAX_UTF8_VALUE_SIZE`]).
    pub const STRING_UTF8_MAX: TypeSignature = Self::type_string_utf8(MAX_UTF8_VALUE_SIZE);
    /// String UTF8 type with length 40.
    pub const STRING_UTF8_40: TypeSignature = Self::type_string_utf8(40);

    /// Longest ([`MAX_TO_ASCII_BUFFER_LEN`]) buffer allowed for `to-ascii?` call.
    pub const TO_ASCII_BUFFER_MAX: TypeSignature = Self::type_buffer_const(MAX_TO_ASCII_BUFFER_LEN);
    /// Longest ([`MAX_TO_ASCII_RESULT_LEN`]) string allowed for `to-ascii?` call.
    pub const TO_ASCII_STRING_ASCII_MAX: TypeSignature =
        Self::type_ascii_const(MAX_TO_ASCII_RESULT_LEN);
    /// Longest string result possible for `(to-ascii? <int>)` result
    /// e.g. "-170141183460469231731687303715884105728"
    pub const TO_ASCII_INT_RESULT_MAX: TypeSignature = Self::type_ascii_const(40);
    /// Longest string result possible for `(to-ascii? <uint>)` result
    /// e.g. "u340282366920938463463374607431768211455"
    pub const TO_ASCII_UINT_RESULT_MAX: TypeSignature = Self::type_ascii_const(40);
    /// Longest string result possible for `(to-ascii? <bool>)` result
    /// e.g. "false"
    pub const TO_ASCII_BOOL_RESULT_MAX: TypeSignature = Self::type_ascii_const(5);
    /// Longest string result possible for `(to-ascii? <principal>)` result
    /// e.g. "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.contract-name-can-be-up-to-128-characters-long-so-41-characters-for-the-address-plus-1-for-the-dot-plus-128-for-the-name-is-170-"
    pub const TO_ASCII_PRINCIPAL_RESULT_MAX: TypeSignature = Self::type_ascii_const(170);

    /// Longest ([`CONTRACT_MAX_NAME_LENGTH`]) string allowed for `contract-name`.
    pub const CONTRACT_NAME_STRING_ASCII_MAX: TypeSignature =
        Self::type_ascii_const(CONTRACT_MAX_NAME_LENGTH as u32);

    /// Creates a buffer type with the specified length.
    ///
    /// # Note
    /// This function is intended for use in constant contexts or for testing purposes.
    /// It may panic if the provided length is invalid.
    const fn type_buffer_const(len: u32) -> Self {
        SequenceType(SequenceSubtype::BufferType(
            BufferLength::try_from_u32_as_opt(len).expect("Invalid buffer length!"),
        ))
    }

    /// Creates a string ASCII type with the specified length.
    ///
    /// # Note
    /// This function is intended for use in constant contexts or for testing purposes.
    /// It may panic if the provided length is invalid.
    const fn type_ascii_const(len: u32) -> Self {
        SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
            BufferLength::try_from_u32_as_opt(len).expect("Invalid ascii length!"),
        )))
    }

    /// Creates a string UTF8 type with the specified length.
    ///
    /// # Note
    /// This function is intended for use in constant contexts or for testing purposes.
    /// It may panic if the provided length is invalid.
    const fn type_string_utf8(len: u32) -> Self {
        SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
            StringUTF8Length::try_from_u32_as_opt(len).expect("Invalid utf8 length!"),
        )))
    }

    /// Creates a string ASCII type with the specified length.
    /// It may panic if the provided length is invalid.
    #[cfg(any(test, feature = "testing"))]
    pub const fn new_ascii_type_checked(len: u32) -> Self {
        Self::type_ascii_const(len)
    }

    /// Creates a string ASCII type with the specified length.
    /// Returns an error if the provided length is invalid.
    pub fn new_ascii_type(len: i128) -> Result<Self, ClarityTypeError> {
        Ok(SequenceType(SequenceSubtype::StringType(
            StringSubtype::ASCII(BufferLength::try_from_i128(len)?),
        )))
    }

    /// If one of the types is a NoType, return Ok(the other type), otherwise return least_supertype(a, b)
    pub(crate) fn factor_out_no_type(
        epoch: &StacksEpochId,
        a: &TypeSignature,
        b: &TypeSignature,
    ) -> Result<TypeSignature, ClarityTypeError> {
        if a.is_no_type() {
            Ok(b.clone())
        } else if b.is_no_type() {
            Ok(a.clone())
        } else {
            Self::least_supertype(epoch, a, b)
        }
    }

    /// Returns the most-restrictive type that admits _both_ A and B (something like a least common supertype),
    /// or Errors if no such type exists. On error, it throws TypeError(A,B), unless a constructor error'ed,
    /// in which case, it throws SupertypeTooLarge.
    ///
    /// The behavior varies by epoch:
    /// - Epoch 2.0/2.05: Uses [`TypeSignature::least_supertype_v2_0`]
    /// - Epoch 2.1+: Uses [`TypeSignature::least_supertype_v2_1`], Adds support for CallableTypes and ListUnionTypes
    ///
    /// For two Tuples:
    ///     least_supertype(A, B) := (tuple \for_each(key k) least_supertype(type_a_k, type_b_k))
    ///     Note: `A`'s keys must be a subset of `B`'s.
    /// For two Lists:
    ///     least_supertype(A, B) := (list max_len: max(max_len A, max_len B), entry: least_supertype(entry_a, entry_b))
    ///     If max_len A | max_len B is 0: entry := Non-empty list entry
    /// For two Responses:
    ///     least_supertype(A, B) := (response least_supertype(ok_a, ok_b), least_supertype(err_a, err_b))
    ///     If any entries are NoType, use the other type's entry
    /// For two Options:
    ///     least_supertype(A, B) := (option least_supertype(some_a, some_b))
    ///     If some_a | some_b is NoType, use the other type's entry
    /// For Buffers:
    ///     least_supertype(A, B) := (buff len: max(len A, len B))
    /// For ASCII/UTF8 Strings:
    ///     least_supertype(A, B) := (string len: max(len A, len B))
    ///     Note: ASCII and UTF8 strings cannot be unified
    /// For NoType:
    ///     least_supertype(NoType, X) := X
    /// For CallableTypes (v2.1+ only):
    ///     - Two identical CallableTypes unify to themselves
    ///     - Two different CallableTypes unify to a ListUnionType containing both
    ///     - CallableType and ListUnionType unify by adding the callable to the union
    ///     - Principal type unifies with CallableSubtype::Principal(_) to PrincipalType
    ///     - Principal type unifies with ListUnionType if all members are principals
    /// For ListUnionTypes (v2.1+ only):
    ///     least_supertype(A, B) := ListUnionType with the union of both sets
    /// For other types (ints, uints, principals, bools):
    ///     least_supertype(A, B) := if A != B, error, else A
    pub fn least_supertype(
        epoch: &StacksEpochId,
        a: &TypeSignature,
        b: &TypeSignature,
    ) -> Result<TypeSignature, ClarityTypeError> {
        match epoch {
            StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => Self::least_supertype_v2_0(a, b),
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32
            | StacksEpochId::Epoch33 => Self::least_supertype_v2_1(a, b),
            StacksEpochId::Epoch10 => Err(ClarityTypeError::UnsupportedEpoch(*epoch)),
        }
    }

    fn least_supertype_v2_0(
        a: &TypeSignature,
        b: &TypeSignature,
    ) -> Result<TypeSignature, ClarityTypeError> {
        match (a, b) {
            (
                TupleType(TupleTypeSignature { type_map: types_a }),
                TupleType(TupleTypeSignature { type_map: types_b }),
            ) => {
                let mut type_map_out = BTreeMap::new();
                for (name, entry_a) in types_a.iter() {
                    let entry_b = types_b.get(name).ok_or(ClarityTypeError::TypeMismatch(
                        Box::new(a.clone()),
                        Box::new(b.clone()),
                    ))?;
                    let entry_out = Self::least_supertype_v2_0(entry_a, entry_b)?;
                    type_map_out.insert(name.clone(), entry_out);
                }
                Ok(TupleTypeSignature::try_from(type_map_out)
                    .map(|x| x.into())
                    .map_err(|_| ClarityTypeError::SupertypeTooLarge)?)
            }
            (
                SequenceType(SequenceSubtype::ListType(ListTypeData {
                    max_len: len_a,
                    entry_type: entry_a,
                })),
                SequenceType(SequenceSubtype::ListType(ListTypeData {
                    max_len: len_b,
                    entry_type: entry_b,
                })),
            ) => {
                let entry_type = if *len_a == 0 {
                    *(entry_b.clone())
                } else if *len_b == 0 {
                    *(entry_a.clone())
                } else {
                    Self::least_supertype_v2_0(entry_a, entry_b)?
                };
                let max_len = cmp::max(len_a, len_b);
                Ok(Self::list_of(entry_type, *max_len)
                    .map_err(|_| ClarityTypeError::SupertypeTooLarge)?)
            }
            (ResponseType(resp_a), ResponseType(resp_b)) => {
                let ok_type =
                    Self::factor_out_no_type(&StacksEpochId::Epoch2_05, &resp_a.0, &resp_b.0)?;
                let err_type =
                    Self::factor_out_no_type(&StacksEpochId::Epoch2_05, &resp_a.1, &resp_b.1)?;
                Ok(Self::new_response(ok_type, err_type)?)
            }
            (OptionalType(some_a), OptionalType(some_b)) => {
                let some_type =
                    Self::factor_out_no_type(&StacksEpochId::Epoch2_05, some_a, some_b)?;
                Ok(Self::new_option(some_type)?)
            }
            (
                SequenceType(SequenceSubtype::BufferType(buff_a)),
                SequenceType(SequenceSubtype::BufferType(buff_b)),
            ) => {
                let buff_len = if u32::from(buff_a) > u32::from(buff_b) {
                    buff_a
                } else {
                    buff_b
                }
                .clone();
                Ok(SequenceType(SequenceSubtype::BufferType(buff_len)))
            }
            (
                SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(string_a))),
                SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(string_b))),
            ) => {
                let str_len = if u32::from(string_a) > u32::from(string_b) {
                    string_a
                } else {
                    string_b
                }
                .clone();
                Ok(SequenceType(SequenceSubtype::StringType(
                    StringSubtype::ASCII(str_len),
                )))
            }
            (
                SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(string_a))),
                SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(string_b))),
            ) => {
                let str_len = if u32::from(string_a) > u32::from(string_b) {
                    string_a
                } else {
                    string_b
                }
                .clone();
                Ok(SequenceType(SequenceSubtype::StringType(
                    StringSubtype::UTF8(str_len),
                )))
            }
            (NoType, x) | (x, NoType) => Ok(x.clone()),
            (x, y) => {
                if x == y {
                    Ok(x.clone())
                } else {
                    Err(ClarityTypeError::TypeMismatch(
                        Box::new(a.clone()),
                        Box::new(b.clone()),
                    ))
                }
            }
        }
    }

    pub(crate) fn least_supertype_v2_1(
        a: &TypeSignature,
        b: &TypeSignature,
    ) -> Result<TypeSignature, ClarityTypeError> {
        match (a, b) {
            (
                TupleType(TupleTypeSignature { type_map: types_a }),
                TupleType(TupleTypeSignature { type_map: types_b }),
            ) => {
                let mut type_map_out = BTreeMap::new();
                for (name, entry_a) in types_a.iter() {
                    let entry_b = types_b.get(name).ok_or(ClarityTypeError::TypeMismatch(
                        Box::new(a.clone()),
                        Box::new(b.clone()),
                    ))?;
                    let entry_out = Self::least_supertype_v2_1(entry_a, entry_b)?;
                    type_map_out.insert(name.clone(), entry_out);
                }
                Ok(TupleTypeSignature::try_from(type_map_out)
                    .map(|x| x.into())
                    .map_err(|_| ClarityTypeError::SupertypeTooLarge)?)
            }
            (
                SequenceType(SequenceSubtype::ListType(ListTypeData {
                    max_len: len_a,
                    entry_type: entry_a,
                })),
                SequenceType(SequenceSubtype::ListType(ListTypeData {
                    max_len: len_b,
                    entry_type: entry_b,
                })),
            ) => {
                let entry_type = if *len_a == 0 {
                    *(entry_b.clone())
                } else if *len_b == 0 {
                    *(entry_a.clone())
                } else {
                    Self::least_supertype_v2_1(entry_a, entry_b)?
                };
                let max_len = cmp::max(len_a, len_b);
                Ok(Self::list_of(entry_type, *max_len)
                    .map_err(|_| ClarityTypeError::SupertypeTooLarge)?)
            }
            (ResponseType(resp_a), ResponseType(resp_b)) => {
                let ok_type =
                    Self::factor_out_no_type(&StacksEpochId::Epoch21, &resp_a.0, &resp_b.0)?;
                let err_type =
                    Self::factor_out_no_type(&StacksEpochId::Epoch21, &resp_a.1, &resp_b.1)?;
                Ok(Self::new_response(ok_type, err_type)?)
            }
            (OptionalType(some_a), OptionalType(some_b)) => {
                let some_type = Self::factor_out_no_type(&StacksEpochId::Epoch21, some_a, some_b)?;
                Ok(Self::new_option(some_type)?)
            }
            (
                SequenceType(SequenceSubtype::BufferType(buff_a)),
                SequenceType(SequenceSubtype::BufferType(buff_b)),
            ) => {
                let buff_len = if u32::from(buff_a) > u32::from(buff_b) {
                    buff_a
                } else {
                    buff_b
                }
                .clone();
                Ok(SequenceType(SequenceSubtype::BufferType(buff_len)))
            }
            (
                SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(string_a))),
                SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(string_b))),
            ) => {
                let str_len = if u32::from(string_a) > u32::from(string_b) {
                    string_a
                } else {
                    string_b
                }
                .clone();
                Ok(SequenceType(SequenceSubtype::StringType(
                    StringSubtype::ASCII(str_len),
                )))
            }
            (
                SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(string_a))),
                SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(string_b))),
            ) => {
                let str_len = if u32::from(string_a) > u32::from(string_b) {
                    string_a
                } else {
                    string_b
                }
                .clone();
                Ok(SequenceType(SequenceSubtype::StringType(
                    StringSubtype::UTF8(str_len),
                )))
            }
            (NoType, x) | (x, NoType) => Ok(x.clone()),
            (CallableType(x), CallableType(y)) => {
                if x == y {
                    Ok(a.clone())
                } else {
                    Ok(ListUnionType(HashSet::from([x.clone(), y.clone()])))
                }
            }
            (ListUnionType(l), CallableType(c)) | (CallableType(c), ListUnionType(l)) => {
                let mut l1 = l.clone();
                l1.insert(c.clone());
                Ok(ListUnionType(l1))
            }
            (PrincipalType, CallableType(CallableSubtype::Principal(_)))
            | (CallableType(CallableSubtype::Principal(_)), PrincipalType) => Ok(PrincipalType),
            (PrincipalType, ListUnionType(l)) | (ListUnionType(l), PrincipalType) => {
                let mut all_principals = true;
                for ty in l {
                    match ty {
                        CallableSubtype::Trait(_) => {
                            all_principals = false;
                        }
                        CallableSubtype::Principal(_) => (),
                    }
                }
                if all_principals {
                    Ok(PrincipalType)
                } else {
                    Err(ClarityTypeError::TypeMismatch(
                        Box::new(a.clone()),
                        Box::new(b.clone()),
                    ))
                }
            }
            (ListUnionType(l1), ListUnionType(l2)) => {
                Ok(ListUnionType(l1.union(l2).cloned().collect()))
            }
            (x, y) => {
                if x == y {
                    Ok(x.clone())
                } else {
                    Err(ClarityTypeError::TypeMismatch(
                        Box::new(a.clone()),
                        Box::new(b.clone()),
                    ))
                }
            }
        }
    }

    pub fn list_of(
        item_type: TypeSignature,
        max_len: u32,
    ) -> Result<TypeSignature, ClarityTypeError> {
        ListTypeData::new_list(item_type, max_len).map(|x| x.into())
    }

    pub fn empty_list() -> ListTypeData {
        ListTypeData {
            entry_type: Box::new(TypeSignature::NoType),
            max_len: 0,
        }
    }

    pub fn type_of(x: &Value) -> Result<TypeSignature, ClarityTypeError> {
        let out = match x {
            Value::Principal(_) => PrincipalType,
            Value::Int(_v) => IntType,
            Value::UInt(_v) => UIntType,
            Value::Bool(_v) => BoolType,
            Value::Tuple(v) => TupleType(v.type_signature.clone()),
            Value::Sequence(SequenceData::List(list_data)) => list_data.type_signature()?,
            Value::Sequence(SequenceData::Buffer(buff_data)) => buff_data.type_signature()?,
            Value::Sequence(SequenceData::String(CharType::ASCII(ascii_data))) => {
                ascii_data.type_signature()?
            }
            Value::Sequence(SequenceData::String(CharType::UTF8(utf8_data))) => {
                utf8_data.type_signature()?
            }
            Value::Optional(v) => v.type_signature()?,
            Value::Response(v) => v.type_signature()?,
            Value::CallableContract(v) => {
                if let Some(trait_identifier) = &v.trait_identifier {
                    CallableType(CallableSubtype::Trait(trait_identifier.clone()))
                } else {
                    CallableType(CallableSubtype::Principal(v.contract_identifier.clone()))
                }
            }
        };

        Ok(out)
    }

    pub fn literal_type_of(x: &Value) -> Result<TypeSignature, ClarityTypeError> {
        match x {
            Value::Principal(PrincipalData::Contract(contract_id)) => Ok(CallableType(
                CallableSubtype::Principal(contract_id.clone()),
            )),
            _ => Self::type_of(x),
        }
    }

    // Checks if resulting type signature is of valid size.
    pub fn construct_parent_list_type(args: &[Value]) -> Result<ListTypeData, ClarityTypeError> {
        let children_types: Result<Vec<_>, ClarityTypeError> =
            args.iter().map(TypeSignature::type_of).collect();
        TypeSignature::parent_list_type(&children_types?)
    }

    pub fn parent_list_type(children: &[TypeSignature]) -> Result<ListTypeData, ClarityTypeError> {
        if let Some((first, rest)) = children.split_first() {
            let mut current_entry_type = first.clone();
            for next_entry in rest.iter() {
                current_entry_type = Self::least_supertype_v2_1(&current_entry_type, next_entry)?;
            }
            let len = u32::try_from(children.len()).map_err(|_| ClarityTypeError::ValueTooLarge)?;
            ListTypeData::new_list(current_entry_type, len)
        } else {
            Ok(TypeSignature::empty_list())
        }
    }
}

/// These implement the size calculations in TypeSignatures
///    in constructors of TypeSignatures, only `.inner_size()` may be called.
///    .inner_size is a failable method to compute the size of the type signature,
///    Failures indicate that a type signature represents _too large_ of a value.
/// TypeSignature constructors will fail instead of constructing such a type.
///   because of this, the public interface to size is infallible.
impl TypeSignature {
    pub fn depth(&self) -> u8 {
        // unlike inner_size, depth will never threaten to overflow,
        //  because a new type can only increase depth by 1.
        match self {
            // NoType's may be asked for their size at runtime --
            //  legal constructions like `(ok 1)` have NoType parts (if they have unknown error variant types).
            CallableType(_)
            | TraitReferenceType(_)
            | ListUnionType(_)
            | NoType
            | IntType
            | UIntType
            | BoolType
            | PrincipalType
            | SequenceType(SequenceSubtype::BufferType(_))
            | SequenceType(SequenceSubtype::StringType(_)) => 1,
            TupleType(tuple_sig) => 1 + tuple_sig.max_depth(),
            SequenceType(SequenceSubtype::ListType(list_type)) => {
                1 + list_type.get_list_item_type().depth()
            }
            OptionalType(t) => 1 + t.depth(),
            ResponseType(v) => 1 + cmp::max(v.0.depth(), v.1.depth()),
        }
    }

    pub fn size(&self) -> Result<u32, ClarityTypeError> {
        self.inner_size()?.ok_or_else(|| {
            ClarityTypeError::InvariantViolation(
                "FAIL: .size() overflowed on too large of a type. Construction should have failed!"
                    .into(),
            )
        })
    }

    fn inner_size(&self) -> Result<Option<u32>, ClarityTypeError> {
        let out = match self {
            // NoType's may be asked for their size at runtime --
            //  legal constructions like `(ok 1)` have NoType parts (if they have unknown error variant types).
            NoType => Some(1),
            IntType => Some(16),
            UIntType => Some(16),
            BoolType => Some(1),
            PrincipalType => Some(148), // 20+128
            TupleType(tuple_sig) => tuple_sig.inner_size()?,
            SequenceType(SequenceSubtype::BufferType(len))
            | SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(len))) => {
                Some(4 + u32::from(len))
            }
            SequenceType(SequenceSubtype::ListType(list_type)) => list_type.inner_size()?,
            SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(len))) => {
                Some(4 + 4 * u32::from(len))
            }
            OptionalType(t) => t.size()?.checked_add(WRAPPER_VALUE_SIZE),
            ResponseType(v) => {
                // ResponseTypes are 1 byte for the committed bool,
                //   plus max(err_type, ok_type)
                let (t, s) = (&v.0, &v.1);
                let t_size = t.size()?;
                let s_size = s.size()?;
                cmp::max(t_size, s_size).checked_add(WRAPPER_VALUE_SIZE)
            }
            CallableType(CallableSubtype::Principal(_)) | ListUnionType(_) => Some(148), // 20+128
            CallableType(CallableSubtype::Trait(_)) | TraitReferenceType(_) => Some(276), // 20+128+128
        };
        Ok(out)
    }

    pub fn type_size(&self) -> Result<u32, ClarityTypeError> {
        self.inner_type_size()
            .ok_or_else(|| ClarityTypeError::ValueTooLarge)
    }

    /// Returns the size of the _type signature_
    fn inner_type_size(&self) -> Option<u32> {
        match self {
            // NoType's may be asked for their size at runtime --
            //  legal constructions like `(ok 1)` have NoType parts (if they have unknown error variant types).
            // These types all only use ~1 byte for their type enum
            NoType | IntType | UIntType | BoolType | PrincipalType => Some(1),
            // u32 length + type enum
            TupleType(tuple_sig) => tuple_sig.type_size(),
            SequenceType(SequenceSubtype::BufferType(_)) => Some(1 + 4),
            SequenceType(SequenceSubtype::ListType(list_type)) => list_type.type_size(),
            SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(_))) => Some(1 + 4),
            SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(_))) => Some(1 + 4),
            OptionalType(t) => t.inner_type_size()?.checked_add(1),
            ResponseType(v) => {
                let (t, s) = (&v.0, &v.1);
                t.inner_type_size()?
                    .checked_add(s.inner_type_size()?)?
                    .checked_add(1)
            }
            CallableType(_) | TraitReferenceType(_) | ListUnionType(_) => Some(1),
        }
    }
}

impl ListTypeData {
    /// List Size: type_signature_size + max_len * entry_type.size()
    fn inner_size(&self) -> Result<Option<u32>, ClarityTypeError> {
        let total_size = self
            .entry_type
            .size()?
            .checked_mul(self.max_len)
            .and_then(|x| x.checked_add(self.type_size()?));
        match total_size {
            Some(total_size) => {
                if total_size > MAX_VALUE_SIZE {
                    Ok(None)
                } else {
                    Ok(Some(total_size))
                }
            }
            None => Ok(None),
        }
    }

    fn type_size(&self) -> Option<u32> {
        let total_size = self.entry_type.inner_type_size()?.checked_add(4 + 1)?; // 1 byte for Type enum, 4 for max_len.
        if total_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(total_size)
        }
    }
}

impl TupleTypeSignature {
    /// Tuple Size:
    ///    size( btreemap<name, type> ) = 2*map.len() + sum(names) + sum(values)
    pub fn type_size(&self) -> Option<u32> {
        let mut type_map_size = u32::try_from(self.type_map.len()).ok()?.checked_mul(2)?;

        for (name, type_signature) in self.type_map.iter() {
            // we only accept ascii names, so 1 char = 1 byte.
            type_map_size = type_map_size
                .checked_add(type_signature.inner_type_size()?)?
                // name.len() is bound to MAX_STRING_LEN (128), so `as u32` won't ever truncate
                .checked_add(name.len() as u32)?;
        }

        if type_map_size > MAX_VALUE_SIZE {
            None
        } else {
            Some(type_map_size)
        }
    }

    pub fn size(&self) -> Result<u32, ClarityTypeError> {
        self.inner_size()?.ok_or_else(|| {
            ClarityTypeError::InvariantViolation("size() overflowed on a constructed type.".into())
        })
    }

    fn max_depth(&self) -> u8 {
        let mut max = 0;
        for (_name, type_signature) in self.type_map.iter() {
            max = cmp::max(max, type_signature.depth())
        }
        max
    }

    /// Tuple Size:
    ///    size( btreemap<name, value> ) + type_size
    ///    size( btreemap<name, value> ) = 2*map.len() + sum(names) + sum(values)
    fn inner_size(&self) -> Result<Option<u32>, ClarityTypeError> {
        let Some(mut total_size) = u32::try_from(self.type_map.len())
            .ok()
            .and_then(|x| x.checked_mul(2))
            .and_then(|x| x.checked_add(self.type_size()?))
        else {
            return Ok(None);
        };

        for (name, type_signature) in self.type_map.iter() {
            // we only accept ascii names, so 1 char = 1 byte.
            total_size = if let Some(new_size) = total_size.checked_add(type_signature.size()?) {
                new_size
            } else {
                return Ok(None);
            };
            total_size = if let Some(new_size) = total_size.checked_add(name.len() as u32) {
                new_size
            } else {
                return Ok(None);
            };
        }

        if total_size > MAX_VALUE_SIZE {
            Ok(None)
        } else {
            Ok(Some(total_size))
        }
    }
}

impl fmt::Display for TupleTypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(tuple")?;
        let mut type_strs: Vec<_> = self.type_map.iter().collect();
        type_strs.sort_unstable_by_key(|x| x.0);
        for (field_name, field_type) in type_strs {
            write!(f, " ({} {})", &**field_name, field_type)?;
        }
        write!(f, ")")
    }
}

impl fmt::Debug for TupleTypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TupleTypeSignature {{")?;
        for (field_name, field_type) in self.type_map.iter() {
            write!(f, " \"{}\": {},", &**field_name, field_type)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for AssetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}::{}",
            &*self.contract_identifier.to_string(),
            &*self.asset_name
        )
    }
}

impl fmt::Display for TypeSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NoType => write!(f, "UnknownType"),
            IntType => write!(f, "int"),
            UIntType => write!(f, "uint"),
            BoolType => write!(f, "bool"),
            OptionalType(t) => write!(f, "(optional {t})"),
            ResponseType(v) => write!(f, "(response {} {})", v.0, v.1),
            TupleType(t) => write!(f, "{t}"),
            PrincipalType => write!(f, "principal"),
            SequenceType(SequenceSubtype::BufferType(len)) => write!(f, "(buff {len})"),
            SequenceType(SequenceSubtype::ListType(list_type_data)) => write!(
                f,
                "(list {} {})",
                list_type_data.max_len, list_type_data.entry_type
            ),
            SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(len))) => {
                write!(f, "(string-ascii {len})")
            }
            SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(len))) => {
                write!(f, "(string-utf8 {len})")
            }
            CallableType(CallableSubtype::Trait(trait_id)) | TraitReferenceType(trait_id) => {
                write!(f, "<{trait_id}>")
            }
            CallableType(CallableSubtype::Principal(contract_id)) => {
                write!(f, "(principal {contract_id})")
            }
            ListUnionType(_) => write!(f, "principal"),
        }
    }
}

impl fmt::Display for BufferLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for StringUTF8Length {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
