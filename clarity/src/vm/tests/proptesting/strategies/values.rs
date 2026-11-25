// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

//! Values of generated types.

use clarity_types::Value;
use clarity_types::types::{SequenceSubtype, StringSubtype, TupleData, TypeSignature};
use proptest::collection::vec;
use proptest::prelude::*;
use stacks_common::types::StacksEpochId;

use super::chars::{printable_ascii_byte_strategy, utf8_char_strategy};
use super::principals::writable_principal_strategy;
use super::types::{type_signature_no_response_strategy, type_signature_strategy};

/// A generated type and a value of that type.
pub fn typed_value_strategy() -> impl Strategy<Value = (TypeSignature, Value)> {
    type_signature_strategy().prop_flat_map(|ty| (Just(ty.clone()), value_of_type_strategy(ty)))
}

/// Values of any generated type.
pub fn clarity_value_strategy() -> BoxedStrategy<Value> {
    type_signature_strategy()
        .prop_flat_map(value_of_type_strategy)
        .boxed()
}

/// Values of generated types without responses at any depth.
pub fn clarity_value_no_response_strategy() -> BoxedStrategy<Value> {
    type_signature_no_response_strategy()
        .prop_flat_map(value_of_type_strategy)
        .boxed()
}

/// Values admitted by `ty`, which must have values (as every generated type does). Principals are
/// writable, so every value renders as Clarity source with
/// [`crate::vm::tests::proptesting::literals::value_to_clarity_literal`].
pub fn value_of_type_strategy(ty: TypeSignature) -> BoxedStrategy<Value> {
    match ty {
        TypeSignature::IntType => any::<i128>().prop_map(Value::Int).boxed(),
        TypeSignature::UIntType => any::<u128>().prop_map(Value::UInt).boxed(),
        TypeSignature::BoolType => any::<bool>().prop_map(Value::Bool).boxed(),
        TypeSignature::PrincipalType => writable_principal_strategy()
            .prop_map(Value::Principal)
            .boxed(),
        TypeSignature::SequenceType(SequenceSubtype::BufferType(len)) => {
            vec(any::<u8>(), 0..=u32::from(len) as usize)
                .prop_map(|bytes| Value::buff_from(bytes).unwrap())
                .boxed()
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(len))) => {
            vec(printable_ascii_byte_strategy(), 0..=u32::from(len) as usize)
                .prop_map(|bytes| Value::string_ascii_from_bytes(bytes).unwrap())
                .boxed()
        }
        TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(len))) => {
            vec(utf8_char_strategy(), 0..=u32::from(len) as usize)
                .prop_map(|chars| {
                    Value::string_utf8_from_bytes(chars.into_iter().collect::<String>().into())
                        .unwrap()
                })
                .boxed()
        }
        TypeSignature::OptionalType(some) if *some == TypeSignature::NoType => {
            Just(Value::none()).boxed()
        }
        TypeSignature::OptionalType(some) => prop_oneof![
            Just(Value::none()),
            value_of_type_strategy(*some).prop_map(|v| Value::some(v).unwrap()),
        ]
        .boxed(),
        TypeSignature::ResponseType(types) => {
            let (ok, err) = *types;
            let mut branches = Vec::new();
            if ok != TypeSignature::NoType {
                branches.push(
                    value_of_type_strategy(ok)
                        .prop_map(|v| Value::okay(v).unwrap())
                        .boxed(),
                );
            }
            if err != TypeSignature::NoType {
                branches.push(
                    value_of_type_strategy(err)
                        .prop_map(|v| Value::error(v).unwrap())
                        .boxed(),
                );
            }
            proptest::strategy::Union::new(branches).boxed()
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list_type))
            if list_type.get_max_len() == 0
                || *list_type.get_list_item_type() == TypeSignature::NoType =>
        {
            // Only the empty list fits: either nothing fits, or the entry type has no values, as in
            // `(list 1 UnknownType)` inferred for `(as-max-len? (list) u1)`. Return the canonical
            // empty list: carrying the requested type instead would not be admitted when its entry
            // type has no values.
            Just(Value::list_from(vec![]).unwrap()).boxed()
        }
        TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)) => {
            let entry = list_type.get_list_item_type().clone();
            vec(
                value_of_type_strategy(entry),
                0..=list_type.get_max_len() as usize,
            )
            .prop_map(move |items| {
                Value::list_with_type(&StacksEpochId::latest(), items, list_type.clone()).unwrap()
            })
            .boxed()
        }
        TypeSignature::TupleType(tuple_type) => tuple_type
            .get_type_map()
            .iter()
            .map(|(name, field_type)| {
                let name = name.clone();
                value_of_type_strategy(field_type.clone()).prop_map(move |v| (name.clone(), v))
            })
            .collect::<Vec<_>>()
            .prop_map(|fields| Value::Tuple(TupleData::from_data(fields).unwrap()))
            .boxed(),
        TypeSignature::NoType
        | TypeSignature::CallableType(_)
        | TypeSignature::ListUnionType(_)
        | TypeSignature::TraitReferenceType(_) => panic!("no values are generated for {ty}"),
    }
}
