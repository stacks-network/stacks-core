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

//! Type signatures that have values: `int`, `uint`, `bool`, `principal`, buffers and strings,
//! nested up to three levels in optionals, responses, tuples and lists. Use
//! [`super::values::value_of_type_strategy`] for values of a generated type.

use clarity_types::types::{ListTypeData, SequenceSubtype, StringSubtype, TypeSignature};
use proptest::prelude::*;
use proptest::strategy::Union;

use super::names::field_name_strategy;

#[derive(Clone, Copy)]
struct TypeOptions {
    /// Generate response types.
    responses: bool,
    /// Only generate types that can be written in Clarity source: no `NoType` (an optional or
    /// response side that can never hold a value), and no zero-length sequences.
    writable: bool,
}

/// Any type that has values, including optionals and responses with an empty side.
pub fn type_signature_strategy() -> BoxedStrategy<TypeSignature> {
    type_signature_with(TypeOptions {
        responses: true,
        writable: false,
    })
}

/// As [`type_signature_strategy`], without response types at any depth.
pub fn type_signature_no_response_strategy() -> BoxedStrategy<TypeSignature> {
    type_signature_with(TypeOptions {
        responses: false,
        writable: false,
    })
}

/// Types that can be written in Clarity source; their `Display` form parses as a type.
pub fn writable_type_signature_strategy() -> BoxedStrategy<TypeSignature> {
    type_signature_with(TypeOptions {
        responses: true,
        writable: true,
    })
}

/// Sequence lengths: mostly short, sometimes up to `max`.
fn length_strategy(min: u32, usual_max: u32, max: u32) -> impl Strategy<Value = u32> {
    prop_oneof![4 => min..=usual_max, 1 => min..=max]
}

fn type_signature_with(options: TypeOptions) -> BoxedStrategy<TypeSignature> {
    let min_len = u32::from(options.writable);
    let leaf = prop_oneof![
        Just(TypeSignature::IntType),
        Just(TypeSignature::UIntType),
        Just(TypeSignature::BoolType),
        Just(TypeSignature::PrincipalType),
        length_strategy(min_len, 64, 1024).prop_map(|len| TypeSignature::SequenceType(
            SequenceSubtype::BufferType(len.try_into().unwrap())
        )),
        length_strategy(min_len, 64, 1024).prop_map(|len| TypeSignature::SequenceType(
            SequenceSubtype::StringType(StringSubtype::ASCII(len.try_into().unwrap()))
        )),
        length_strategy(min_len, 16, 256).prop_map(|len| TypeSignature::SequenceType(
            SequenceSubtype::StringType(StringSubtype::UTF8(len.try_into().unwrap()))
        )),
    ];

    leaf.prop_recursive(3, 24, 4, move |inner| {
        let value_side = if options.writable {
            inner.clone()
        } else {
            prop_oneof![1 => Just(TypeSignature::NoType), 4 => inner.clone()].boxed()
        };

        let mut composites = vec![
            value_side
                .clone()
                .prop_filter_map("optional too large", |some| {
                    TypeSignature::new_option(some).ok()
                })
                .boxed(),
            prop::collection::btree_map(field_name_strategy(), inner.clone(), 1..6)
                .prop_filter_map("tuple too large", |fields| {
                    fields.try_into().ok().map(TypeSignature::TupleType)
                })
                .boxed(),
            (inner, min_len..=6)
                .prop_filter_map("list too large", |(entry, max_len)| {
                    ListTypeData::new_list(entry, max_len).ok().map(Into::into)
                })
                .boxed(),
        ];
        if options.responses {
            composites.push(
                (value_side.clone(), value_side)
                    .prop_filter_map("response needs a value side and a size", |(ok, err)| {
                        if ok == TypeSignature::NoType && err == TypeSignature::NoType {
                            return None;
                        }
                        TypeSignature::new_response(ok, err).ok()
                    })
                    .boxed(),
            );
        }
        Union::new(composites)
    })
    .boxed()
}
