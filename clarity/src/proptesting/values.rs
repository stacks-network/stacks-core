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

use proptest::prelude::*;

use super::*;
use crate::vm::types::{
    BuffData, CharType, ListData, ListTypeData, OptionalData, PrincipalData,
    QualifiedContractIdentifier, ResponseData, SequenceData, SequenceSubtype,
    StandardPrincipalData, StringSubtype, TupleData, TupleTypeSignature, TypeSignature, UTF8Data,
};
use crate::vm::{ContractName, Value};

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of a
/// the specified ([`TypeSignature`]).
pub fn value(ty: TypeSignature) -> impl Strategy<Value = Value> {
    match ty {
        TypeSignature::NoType => unreachable!(),
        TypeSignature::IntType => int().boxed(),
        TypeSignature::UIntType => uint().boxed(),
        TypeSignature::BoolType => bool().boxed(),
        TypeSignature::OptionalType(ty) => optional(*ty).boxed(),
        TypeSignature::ResponseType(ok_err) => response(ok_err.0, ok_err.1).boxed(),
        TypeSignature::SequenceType(SequenceSubtype::BufferType(size)) => {
            buffer(size.into()).boxed()
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(size))) => {
            string_ascii(size.into()).boxed()
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(size))) => {
            string_utf8(size.into()).boxed()
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list_type_data)) => {
            list(list_type_data).boxed()
        }
        TypeSignature::TupleType(tuple_ty) => tuple(tuple_ty).boxed(),
        TypeSignature::PrincipalType => {
            prop_oneof![principal_standard(), principal_contract()].boxed()
        }
        // TODO
        TypeSignature::ListUnionType(_) => todo!(),
        TypeSignature::CallableType(_) => todo!(),
        TypeSignature::TraitReferenceType(_) => todo!(),
    }
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::Int`].
pub fn int() -> impl Strategy<Value = Value> {
    any::<i128>().prop_map(Value::Int)
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::UInt`].
pub fn uint() -> impl Strategy<Value = Value> {
    any::<u128>().prop_map(Value::UInt)
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::Bool`].
pub fn bool() -> impl Strategy<Value = Value> {
    any::<bool>().prop_map(Value::Bool)
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::None`].
pub fn string_ascii(size: u32) -> impl Strategy<Value = Value> {
    let size = size as usize;
    prop::collection::vec(0x20u8..0x7e, size..=size).prop_map(|bytes| {
        Value::Sequence(SequenceData::String(crate::vm::types::CharType::ASCII(
            crate::vm::types::ASCIIData { data: bytes },
        )))
    })
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::Sequence`] with an inner type of [`UTF8Data`].
pub fn string_utf8(size: u32) -> impl Strategy<Value = Value> {
    prop::collection::vec(any::<char>(), size as usize).prop_map(|chars| {
        let mut data = Vec::with_capacity(chars.len());
        for c in chars {
            let mut encoded_char = vec![0; c.len_utf8()];
            c.encode_utf8(encoded_char.as_mut());
            data.push(encoded_char);
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data })))
    })
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::Sequence`] with an inner type of [`BuffData`].
pub fn buffer(size: u32) -> impl Strategy<Value = Value> {
    let size = size as usize;
    prop::collection::vec(any::<u8>(), size..=size)
        .prop_map(|bytes| Value::Sequence(SequenceData::Buffer(BuffData { data: bytes })))
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::Optional`], with the inner type being the specified [`TypeSignature`].
pub fn optional(inner_ty: TypeSignature) -> impl Strategy<Value = Value> {
    match inner_ty {
        TypeSignature::NoType => Just(Value::none()).boxed(),
        _ => prop::option::of(value(inner_ty))
            .prop_map(|v| {
                Value::Optional(OptionalData {
                    data: v.map(Box::new),
                })
            })
            .boxed(),
    }
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::Response`], with the ok/err types being the specified [`TypeSignature`]s.
pub fn response(ok_ty: TypeSignature, err_ty: TypeSignature) -> impl Strategy<Value = Value> {
    match (ok_ty, err_ty) {
        (TypeSignature::NoType, err_ty) => value(err_ty)
            .prop_map(|err| {
                Value::Response(ResponseData {
                    committed: false,
                    data: Box::new(err),
                })
            })
            .boxed(),
        (ok_ty, TypeSignature::NoType) => value(ok_ty)
            .prop_map(|ok| {
                Value::Response(ResponseData {
                    committed: true,
                    data: Box::new(ok),
                })
            })
            .boxed(),
        (ok_ty, err_ty) => prop::result::maybe_err(value(ok_ty), value(err_ty))
            .prop_map(|res| {
                Value::Response(ResponseData {
                    committed: res.is_ok(),
                    data: res.map_or_else(Box::new, Box::new),
                })
            })
            .boxed(),
    }
}

/// Returns a [`Strategy`] for generating a randomized [`Value`] instance of variant
/// [`Value::Sequence`] with the inner type being a list ([`SequenceData`]) of
/// the specified [`ListTypeData`].
pub fn list(list_type_data: ListTypeData) -> impl Strategy<Value = Value> {
    prop::collection::vec(
        value(list_type_data.get_list_item_type().clone()),
        0..=list_type_data.get_max_len() as usize,
    )
    .prop_map(move |v| {
        Value::Sequence(SequenceData::List(ListData {
            data: v,
            type_signature: list_type_data.clone(),
        }))
    })
}

pub fn tuple(tuple_ty: TupleTypeSignature) -> impl Strategy<Value = Value> {
    let fields: Vec<_> = tuple_ty.get_type_map().keys().cloned().collect();
    let strategies: Vec<_> = tuple_ty
        .get_type_map()
        .values()
        .cloned()
        .map(value)
        .collect();
    strategies.prop_map(move |vec_values| {
        TupleData {
            type_signature: tuple_ty.clone(),
            data_map: fields.clone().into_iter().zip(vec_values).collect(),
        }
        .into()
    })
}

pub fn principal_standard() -> impl Strategy<Value = Value> {
    (0u8..32, prop::collection::vec(any::<u8>(), 20))
        .prop_map(|(v, hash)| {
            Value::Principal(PrincipalData::Standard(StandardPrincipalData(
                v,
                hash.try_into().unwrap(),
            )))
        })
        .no_shrink()
}

pub fn principal_contract() -> impl Strategy<Value = Value> {
    (principal_standard(), "[a-zA-Z]{1,40}").prop_map(|(issuer_value, name)| {
        let Value::Principal(PrincipalData::Standard(issuer)) = issuer_value else {
            unreachable!()
        };
        let name = ContractName::from(&*name);
        Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier {
            issuer,
            name,
        }))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropValue(Value);

impl From<Value> for PropValue {
    fn from(value: Value) -> Self {
        PropValue(value)
    }
}

impl From<PropValue> for Value {
    fn from(value: PropValue) -> Self {
        value.0
    }
}

impl PropValue {
    pub fn any() -> impl Strategy<Value = Self> {
        type_signature().prop_flat_map(value).prop_map_into()
    }

    pub fn from_type(ty: TypeSignature) -> impl Strategy<Value = Self> {
        value(ty).prop_map_into()
    }

    pub fn many_from_type(ty: TypeSignature, count: usize) -> impl Strategy<Value = Vec<Self>> {
        prop::collection::vec(Self::from_type(ty.clone()), count)
    }

    pub fn any_sequence(size: usize) -> impl Strategy<Value = Self> {
        let any_list = type_signature()
            .prop_ind_flat_map2(move |ty| prop::collection::vec(value(ty), size))
            .prop_map(move |(ty, vec)| {
                Value::Sequence(SequenceData::List(ListData {
                    data: vec,
                    type_signature: ListTypeData::new_list(ty, size as u32).unwrap(),
                }))
            });
        // TODO: add string-utf8
        prop_oneof![
            // 10% chance for a buffer
            1 => buffer(size as u32),
            // 10% chance for a string-ascii
            1 => string_ascii(size as u32),
            // 10% change for a string-utf8
            1 => string_utf8(size as u32),
            // 70% chance for a list
            7 => any_list
        ]
        .prop_map_into()
    }
}

impl TryFrom<Vec<PropValue>> for PropValue {
    type Error = crate::vm::errors::Error;

    fn try_from(values: Vec<PropValue>) -> Result<Self, Self::Error> {
        let values = values.into_iter().map(Value::from).collect();
        Value::cons_list_unsanitized(values).map(PropValue::from)
    }
}
