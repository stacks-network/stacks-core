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
use std::collections::BTreeSet;

use rstest::rstest;

use stacks_common::types::StacksEpochId;

use crate::errors::ClarityTypeError;
use crate::representations::CONTRACT_MAX_NAME_LENGTH;
use crate::types::TypeSignature::{BoolType, IntType, ListUnionType, UIntType};
use crate::types::signatures::{CallableSubtype, TypeSignature};
use crate::types::{
    BufferLength, CallableData, MAX_TO_ASCII_BUFFER_LEN, MAX_TO_ASCII_RESULT_LEN, MAX_TYPE_DEPTH,
    MAX_UTF8_VALUE_SIZE, MAX_VALUE_SIZE, QualifiedContractIdentifier, SequenceSubtype,
    StandardPrincipalData, StringSubtype, StringUTF8Length, TraitIdentifier, TupleData,
    TupleTypeSignature, WRAPPER_VALUE_SIZE,
};
use crate::{ClarityName, Value};

#[test]
fn test_core_constants() {
    assert_eq!(1_048_576, MAX_VALUE_SIZE);
    assert_eq!(262_144, MAX_UTF8_VALUE_SIZE);
    assert_eq!(1_048_571, MAX_TO_ASCII_RESULT_LEN);
    assert_eq!(524_284, MAX_TO_ASCII_BUFFER_LEN);
    assert_eq!(32, MAX_TYPE_DEPTH);
    assert_eq!(1, WRAPPER_VALUE_SIZE);
}

#[test]
fn test_buffer_length_try_from_u32_trait() {
    let buffer = BufferLength::try_from(0_u32).unwrap();
    assert_eq!(0, buffer.get_value());

    let buffer = BufferLength::try_from(MAX_VALUE_SIZE).unwrap();
    assert_eq!(MAX_VALUE_SIZE, buffer.get_value());

    let err = BufferLength::try_from(MAX_VALUE_SIZE + 1).unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);
}

#[test]
fn test_buffer_length_try_from_usize_trait() {
    let buffer = BufferLength::try_from(0_usize).unwrap();
    assert_eq!(0, buffer.get_value());

    let buffer = BufferLength::try_from(MAX_VALUE_SIZE as usize).unwrap();
    assert_eq!(MAX_VALUE_SIZE, buffer.get_value());

    let err = BufferLength::try_from(MAX_VALUE_SIZE as usize + 1).unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);
}

#[test]
fn test_buffer_length_try_from_i128_trait() {
    let buffer = BufferLength::try_from(0_i128).unwrap();
    assert_eq!(0, buffer.get_value());

    let buffer = BufferLength::try_from(MAX_VALUE_SIZE as i128).unwrap();
    assert_eq!(MAX_VALUE_SIZE, buffer.get_value());

    let err = BufferLength::try_from(MAX_VALUE_SIZE as i128 + 1).unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);

    let err = BufferLength::try_from(-1_i128).unwrap_err();
    assert_eq!(ClarityTypeError::ValueOutOfBounds, err);
}

#[test]
fn test_buffer_length_to_u32_using_from_trait() {
    let buffer = BufferLength::new_unsafe(0);
    assert_eq!(0, u32::from(&buffer));
    assert_eq!(0, u32::from(buffer));
}

#[test]
fn test_type_buffer_min_to_be_buffer_1() {
    assert_eq!(TypeSignature::BUFFER_1, TypeSignature::BUFFER_MIN);
}

#[test]
fn test_type_buffer_max() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::BufferType(
        BufferLength::new_unsafe(MAX_VALUE_SIZE),
    ));
    let actual = TypeSignature::BUFFER_MAX;

    assert_eq!(expected, actual);
    assert_eq!(
        1_048_580,
        actual.size().unwrap(),
        "size should be 1_048_580"
    );
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_buffer_1() {
    let expected =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::new_unsafe(1)));
    let actual = TypeSignature::BUFFER_1;

    assert_eq!(expected, actual);
    assert_eq!(5, actual.size().unwrap(), "size should be 5");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_buffer_20() {
    let expected =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::new_unsafe(20)));
    let actual = TypeSignature::BUFFER_20;

    assert_eq!(expected, actual);
    assert_eq!(24, actual.size().unwrap(), "size should be 24");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_buffer_32() {
    let expected =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::new_unsafe(32)));
    let actual = TypeSignature::BUFFER_32;

    assert_eq!(expected, actual);
    assert_eq!(36, actual.size().unwrap(), "size should be 36");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_buffer_33() {
    let expected =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::new_unsafe(33)));
    let actual = TypeSignature::BUFFER_33;

    assert_eq!(expected, actual);
    assert_eq!(37, actual.size().unwrap(), "size should be 37");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_buffer_64() {
    let expected =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::new_unsafe(64)));
    let actual = TypeSignature::BUFFER_64;

    assert_eq!(expected, actual);
    assert_eq!(68, actual.size().unwrap(), "size should be 68");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_buffer_65() {
    let expected =
        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::new_unsafe(65)));
    let actual = TypeSignature::BUFFER_65;

    assert_eq!(expected, actual);
    assert_eq!(69, actual.size().unwrap(), "size should be 69");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_string_ascii_min() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
        BufferLength::new_unsafe(1),
    )));
    let actual = TypeSignature::STRING_ASCII_MIN;

    assert_eq!(expected, actual);
    assert_eq!(5, actual.size().unwrap(), "size should be 5");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_string_ascii_max() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
        BufferLength::new_unsafe(MAX_VALUE_SIZE),
    )));
    let actual = TypeSignature::STRING_ASCII_MAX;

    assert_eq!(expected, actual);
    assert_eq!(
        1_048_580,
        actual.size().unwrap(),
        "size should be 1_048_580"
    );
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_string_ascii_40() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
        BufferLength::new_unsafe(40),
    )));
    let actual = TypeSignature::STRING_ASCII_40;

    assert_eq!(expected, actual);
    assert_eq!(44, actual.size().unwrap(), "size should be 44");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_string_utf8_length_try_from_u32_trait() {
    let string = StringUTF8Length::try_from(0_u32).unwrap();
    assert_eq!(0, string.get_value());

    let string = StringUTF8Length::try_from(1_u32).unwrap();
    assert_eq!(1, string.get_value());

    let string = StringUTF8Length::try_from(MAX_UTF8_VALUE_SIZE).unwrap();
    assert_eq!(MAX_UTF8_VALUE_SIZE, string.get_value());

    let err = StringUTF8Length::try_from(MAX_UTF8_VALUE_SIZE + 1).unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);
}

#[test]
fn test_string_utf8_length_try_from_usize_trait() {
    let string = StringUTF8Length::try_from(0_usize).unwrap();
    assert_eq!(0, string.get_value());

    let string = StringUTF8Length::try_from(1_usize).unwrap();
    assert_eq!(1, string.get_value());

    let string = StringUTF8Length::try_from(MAX_UTF8_VALUE_SIZE as usize).unwrap();
    assert_eq!(MAX_UTF8_VALUE_SIZE, string.get_value());

    let err = StringUTF8Length::try_from(MAX_UTF8_VALUE_SIZE as usize + 1).unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);
}

#[test]
fn test_string_utf8_length_try_from_i128_trait() {
    let string = StringUTF8Length::try_from(0_i128).unwrap();
    assert_eq!(0, string.get_value());

    let string = StringUTF8Length::try_from(1_i128).unwrap();
    assert_eq!(1, string.get_value());

    let string = StringUTF8Length::try_from(MAX_UTF8_VALUE_SIZE as i128).unwrap();
    assert_eq!(MAX_UTF8_VALUE_SIZE, string.get_value());

    let err = StringUTF8Length::try_from(MAX_UTF8_VALUE_SIZE as i128 + 1).unwrap_err();
    assert_eq!(ClarityTypeError::ValueTooLarge, err);

    let err = StringUTF8Length::try_from(-1_i128).unwrap_err();
    assert_eq!(ClarityTypeError::ValueOutOfBounds, err);
}

#[test]
fn test_type_string_utf8_min() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
        StringUTF8Length::new_unsafe(1),
    )));
    let actual = TypeSignature::STRING_UTF8_MIN;

    assert_eq!(expected, actual);
    assert_eq!(8, actual.size().unwrap(), "size should be 8");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_string_utf8_max() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
        StringUTF8Length::new_unsafe(MAX_UTF8_VALUE_SIZE),
    )));
    let actual = TypeSignature::STRING_UTF8_MAX;

    assert_eq!(expected, actual);
    assert_eq!(TypeSignature::STRING_UTF8_MAX, actual);
    assert_eq!(
        1_048_580,
        actual.size().unwrap(),
        "size should be 1_048_580"
    );
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_string_utf8_40() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
        StringUTF8Length::new_unsafe(40),
    )));
    let actual = TypeSignature::STRING_UTF8_40;

    assert_eq!(expected, actual);
    assert_eq!(164, actual.size().unwrap(), "size should be 164");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_buffer_max_for_to_ascii_call() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::BufferType(
        BufferLength::new_unsafe(MAX_TO_ASCII_BUFFER_LEN),
    ));
    let actual = TypeSignature::TO_ASCII_BUFFER_MAX;

    assert_eq!(expected, actual);
    assert_eq!(524_288, actual.size().unwrap(), "size should be 524_288");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_string_max_ascii_for_to_ascii_call() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
        BufferLength::new_unsafe(MAX_TO_ASCII_RESULT_LEN),
    )));
    let actual = TypeSignature::TO_ASCII_STRING_ASCII_MAX;

    assert_eq!(expected, actual);
    assert_eq!(
        1_048_575,
        actual.size().unwrap(),
        "size should be 1_048_575"
    );
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_string_max_ascii_for_contract_name() {
    let expected = TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
        BufferLength::new_unsafe(CONTRACT_MAX_NAME_LENGTH as u32),
    )));
    let actual = TypeSignature::CONTRACT_NAME_STRING_ASCII_MAX;

    assert_eq!(expected, actual);
    assert_eq!(44, actual.size().unwrap(), "size should be 44");
    assert_eq!(4, actual.min_size().unwrap(), "min_size should be 4");
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_type_min_size_optional() {
    let actual = TypeSignature::new_option(TypeSignature::IntType).unwrap();
    assert_eq!(17, actual.size().unwrap(), "size should be 17");
    assert_eq!(
        2,
        actual.min_size().unwrap(),
        "min_size should be 2 (`none` path = NoType + 1 wrapper)"
    );
}

#[test]
fn test_type_min_size_response() {
    let actual =
        TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType).unwrap();
    assert_eq!(
        17,
        actual.size().unwrap(),
        "size should be 17 (max(16, 1) + 1)"
    );
    assert_eq!(
        2,
        actual.min_size().unwrap(),
        "min_size should be 2 (min(16, 1) + 1)"
    );
}

#[test]
fn test_type_min_size_list() {
    let actual = TypeSignature::list_of(TypeSignature::IntType, 10).unwrap();
    assert!(actual.size().unwrap() > 6);
    assert_eq!(
        6,
        actual.min_size().unwrap(),
        "min_size should be 6 (entry type enum + list type enum + max_len)"
    );
}

#[test]
fn test_type_min_size_tuple() {
    let actual = TypeSignature::TupleType(
        TupleTypeSignature::try_from(vec![
            (ClarityName::from_literal("a"), TypeSignature::IntType),
            (ClarityName::from_literal("b"), TypeSignature::BoolType),
        ])
        .unwrap(),
    );
    // 2*len + type_size + (min_size(int)+len("a")) + (min_size(bool)+len("b")) = 4 + 8 + 17 + 2 = 31
    assert_eq!(
        31,
        actual.min_size().unwrap(),
        "min_size should match tuple formula"
    );
    assert!(actual.min_size().unwrap() <= actual.size().unwrap());
}

#[test]
fn test_type_min_size_optional_matches_none_value() {
    let declared_type = TypeSignature::new_option(TypeSignature::IntType).unwrap();
    let min_value = Value::none();
    let min_value_type = TypeSignature::type_of(&min_value).unwrap();

    assert!(
        declared_type
            .admits_type(&StacksEpochId::latest(), &min_value_type)
            .unwrap()
    );
    assert_eq!(min_value.size().unwrap(), declared_type.min_size().unwrap());
}

#[test]
fn test_type_min_size_response_matches_smallest_branch_value() {
    let declared_type =
        TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType).unwrap();
    let min_value = Value::error(Value::Bool(true)).unwrap();
    let min_value_type = TypeSignature::type_of(&min_value).unwrap();

    assert!(
        declared_type
            .admits_type(&StacksEpochId::latest(), &min_value_type)
            .unwrap()
    );
    assert_eq!(min_value.size().unwrap(), declared_type.min_size().unwrap());
}

#[test]
fn test_type_min_size_list_matches_empty_list_value() {
    let declared_type = TypeSignature::list_of(TypeSignature::IntType, 10).unwrap();
    let min_value = Value::cons_list_unsanitized(vec![]).unwrap();
    let min_value_type = TypeSignature::type_of(&min_value).unwrap();

    assert!(
        declared_type
            .admits_type(&StacksEpochId::latest(), &min_value_type)
            .unwrap()
    );
    assert_eq!(min_value.size().unwrap(), declared_type.min_size().unwrap());
}

#[test]
fn test_type_min_size_principal_matches_minimum_value_kind() {
    let declared_type = TypeSignature::PrincipalType;
    let min_value = Value::from(StandardPrincipalData::transient());
    let min_value_type = TypeSignature::type_of(&min_value).unwrap();

    assert_eq!(TypeSignature::PrincipalType, min_value_type);
    assert!(
        declared_type
            .admits_type(&StacksEpochId::latest(), &min_value_type)
            .unwrap()
    );
    assert_eq!(min_value.size().unwrap(), declared_type.min_size().unwrap());
}

#[test]
fn test_type_min_size_callable_trait_matches_minimum_value_kind() {
    let trait_id = TraitIdentifier {
        name: ClarityName::from_literal("t"),
        contract_identifier: QualifiedContractIdentifier::local("trait-def").unwrap(),
    };
    let declared_type = TypeSignature::CallableType(CallableSubtype::Trait(trait_id.clone()));
    let min_value = Value::CallableContract(CallableData {
        contract_identifier: QualifiedContractIdentifier::local("a").unwrap(),
        trait_identifier: Some(trait_id.clone()),
    });
    let min_value_type = TypeSignature::type_of(&min_value).unwrap();

    assert_eq!(declared_type, min_value_type);
    assert!(
        declared_type
            .admits_type(&StacksEpochId::latest(), &min_value_type)
            .unwrap()
    );
    assert_eq!(min_value.size().unwrap(), declared_type.min_size().unwrap());
}

#[test]
fn test_type_min_size_tuple_with_list_matches_minimum_value() {
    let declared_type = TypeSignature::TupleType(
        TupleTypeSignature::try_from(vec![
            (
                ClarityName::from_literal("items"),
                TypeSignature::list_of(TypeSignature::IntType, 10).unwrap(),
            ),
            (ClarityName::from_literal("ok"), TypeSignature::BoolType),
            (
                ClarityName::from_literal("maybe"),
                TypeSignature::new_option(TypeSignature::UIntType).unwrap(),
            ),
        ])
        .unwrap(),
    );
    let min_value = Value::from(
        TupleData::from_data(vec![
            (
                ClarityName::from_literal("items"),
                Value::cons_list_unsanitized(vec![]).unwrap(),
            ),
            (ClarityName::from_literal("ok"), Value::Bool(false)),
            (ClarityName::from_literal("maybe"), Value::none()),
        ])
        .unwrap(),
    );
    let min_value_type = TypeSignature::type_of(&min_value).unwrap();

    assert!(
        declared_type
            .admits_type(&StacksEpochId::latest(), &min_value_type)
            .unwrap()
    );
    assert_eq!(min_value.size().unwrap(), declared_type.min_size().unwrap());
}

#[test]
fn test_least_supertype() {
    let callables = [
        CallableSubtype::Principal(QualifiedContractIdentifier::local("foo").unwrap()),
        CallableSubtype::Trait(TraitIdentifier {
            name: ClarityName::from_literal("foo"),
            contract_identifier: QualifiedContractIdentifier::transient(),
        }),
    ];
    let list_union = ListUnionType(callables.clone().into());
    let callables2 = [
        CallableSubtype::Principal(QualifiedContractIdentifier::local("bar").unwrap()),
        CallableSubtype::Trait(TraitIdentifier {
            name: ClarityName::from_literal("bar"),
            contract_identifier: QualifiedContractIdentifier::transient(),
        }),
    ];
    let list_union2 = ListUnionType(callables2.clone().into());
    let list_union_merged = ListUnionType(BTreeSet::from_iter(
        [callables, callables2].concat().iter().cloned(),
    ));
    let callable_principals = [
        CallableSubtype::Principal(QualifiedContractIdentifier::local("foo").unwrap()),
        CallableSubtype::Principal(QualifiedContractIdentifier::local("bar").unwrap()),
    ];
    let list_union_principals = ListUnionType(callable_principals.into());

    let notype_pairs = [
        // NoType with X should result in X
        (
            (TypeSignature::NoType, TypeSignature::NoType),
            TypeSignature::NoType,
        ),
        (
            (TypeSignature::NoType, TypeSignature::IntType),
            TypeSignature::IntType,
        ),
        (
            (TypeSignature::NoType, TypeSignature::UIntType),
            TypeSignature::UIntType,
        ),
        (
            (TypeSignature::NoType, TypeSignature::BoolType),
            TypeSignature::BoolType,
        ),
        (
            (TypeSignature::NoType, TypeSignature::BUFFER_MIN),
            TypeSignature::BUFFER_MIN,
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
            ),
            TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::new_ascii_type_checked(17),
            ),
            TypeSignature::new_ascii_type_checked(17),
        ),
        (
            (TypeSignature::NoType, TypeSignature::STRING_UTF8_MAX),
            TypeSignature::STRING_UTF8_MAX,
        ),
        (
            (TypeSignature::NoType, TypeSignature::PrincipalType),
            TypeSignature::PrincipalType,
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        ClarityName::from_literal("a"),
                        TypeSignature::IntType,
                    )])
                    .unwrap(),
                ),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::from_literal("a"),
                    TypeSignature::IntType,
                )])
                .unwrap(),
            ),
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::new_option(TypeSignature::IntType).unwrap(),
            ),
            TypeSignature::new_option(TypeSignature::IntType).unwrap(),
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                    .unwrap(),
            ),
            TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType).unwrap(),
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
            ),
            TypeSignature::CallableType(CallableSubtype::Principal(
                QualifiedContractIdentifier::transient(),
            )),
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                    name: ClarityName::from_literal("foo"),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
            ),
            TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                name: ClarityName::from_literal("foo"),
                contract_identifier: QualifiedContractIdentifier::transient(),
            })),
        ),
        (
            (TypeSignature::NoType, list_union.clone()),
            list_union.clone(),
        ),
    ];

    for (pair, expected) in notype_pairs {
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
            expected
        );
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
            expected
        );
    }

    let simple_pairs = [
        ((IntType, IntType), IntType),
        ((UIntType, UIntType), UIntType),
        ((BoolType, BoolType), BoolType),
        (
            (TypeSignature::BUFFER_MAX, TypeSignature::BUFFER_MAX),
            TypeSignature::BUFFER_MAX,
        ),
        (
            (
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
            ),
            TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
        ),
        (
            (
                TypeSignature::new_ascii_type_checked(17),
                TypeSignature::new_ascii_type_checked(17),
            ),
            TypeSignature::new_ascii_type_checked(17),
        ),
        (
            (
                TypeSignature::STRING_UTF8_MAX,
                TypeSignature::STRING_UTF8_MAX,
            ),
            TypeSignature::STRING_UTF8_MAX,
        ),
        (
            (TypeSignature::PrincipalType, TypeSignature::PrincipalType),
            TypeSignature::PrincipalType,
        ),
        (
            (
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        ClarityName::from_literal("a"),
                        TypeSignature::IntType,
                    )])
                    .unwrap(),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        ClarityName::from_literal("a"),
                        TypeSignature::IntType,
                    )])
                    .unwrap(),
                ),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::from_literal("a"),
                    TypeSignature::IntType,
                )])
                .unwrap(),
            ),
        ),
        (
            (
                TypeSignature::new_option(TypeSignature::IntType).unwrap(),
                TypeSignature::new_option(TypeSignature::IntType).unwrap(),
            ),
            TypeSignature::new_option(TypeSignature::IntType).unwrap(),
        ),
        (
            (
                TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                    .unwrap(),
                TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType)
                    .unwrap(),
            ),
            TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType).unwrap(),
        ),
        (
            (
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
            ),
            TypeSignature::CallableType(CallableSubtype::Principal(
                QualifiedContractIdentifier::transient(),
            )),
        ),
        (
            (
                TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                    name: ClarityName::from_literal("foo"),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
                TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                    name: ClarityName::from_literal("foo"),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
            ),
            TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                name: ClarityName::from_literal("foo"),
                contract_identifier: QualifiedContractIdentifier::transient(),
            })),
        ),
        ((list_union.clone(), list_union.clone()), list_union.clone()),
    ];

    for (pair, expected) in simple_pairs {
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
            expected
        );
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
            expected
        );
    }

    let matched_pairs = [
        (
            (TypeSignature::BUFFER_MAX, TypeSignature::BUFFER_MIN),
            TypeSignature::BUFFER_MAX,
        ),
        (
            (
                TypeSignature::list_of(TypeSignature::IntType, 17).unwrap(),
                TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
            ),
            TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
        ),
        (
            (
                TypeSignature::STRING_ASCII_MIN,
                TypeSignature::new_ascii_type_checked(17),
            ),
            TypeSignature::new_ascii_type_checked(17),
        ),
        (
            (
                TypeSignature::STRING_UTF8_MIN,
                TypeSignature::STRING_UTF8_MAX,
            ),
            TypeSignature::STRING_UTF8_MAX,
        ),
        (
            (
                TypeSignature::PrincipalType,
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
            ),
            TypeSignature::PrincipalType,
        ),
        (
            (TypeSignature::PrincipalType, list_union_principals.clone()),
            TypeSignature::PrincipalType,
        ),
        (
            (
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::local("foo").unwrap(),
                )),
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::local("bar").unwrap(),
                )),
            ),
            list_union_principals.clone(),
        ),
        (
            (list_union.clone(), list_union2.clone()),
            list_union_merged.clone(),
        ),
    ];

    for (pair, expected) in matched_pairs {
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
            expected
        );
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
            expected
        );
    }

    let compound_pairs = [
        (
            (
                TypeSignature::list_of(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        16_u32.try_into().unwrap(),
                    )),
                    5,
                )
                .unwrap(),
                TypeSignature::list_of(TypeSignature::BUFFER_MIN, 3).unwrap(),
            ),
            TypeSignature::list_of(
                TypeSignature::SequenceType(SequenceSubtype::BufferType(
                    16_u32.try_into().unwrap(),
                )),
                5,
            )
            .unwrap(),
        ),
        (
            (
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        ClarityName::from_literal("b"),
                        TypeSignature::STRING_ASCII_MIN,
                    )])
                    .unwrap(),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        ClarityName::from_literal("b"),
                        TypeSignature::new_ascii_type_checked(17),
                    )])
                    .unwrap(),
                ),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::from_literal("b"),
                    TypeSignature::new_ascii_type_checked(17),
                )])
                .unwrap(),
            ),
        ),
        (
            (
                TypeSignature::new_option(TypeSignature::STRING_ASCII_MIN).unwrap(),
                TypeSignature::new_option(TypeSignature::new_ascii_type_checked(17)).unwrap(),
            ),
            TypeSignature::new_option(TypeSignature::new_ascii_type_checked(17)).unwrap(),
        ),
        (
            (
                TypeSignature::new_response(TypeSignature::PrincipalType, list_union.clone())
                    .unwrap(),
                TypeSignature::new_response(
                    TypeSignature::CallableType(CallableSubtype::Principal(
                        QualifiedContractIdentifier::transient(),
                    )),
                    list_union2.clone(),
                )
                .unwrap(),
            ),
            TypeSignature::new_response(TypeSignature::PrincipalType, list_union_merged).unwrap(),
        ),
    ];

    for (pair, expected) in compound_pairs {
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap(),
            expected
        );
        assert_eq!(
            TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap(),
            expected
        );
    }

    let bad_pairs = [
        (IntType, UIntType),
        (BoolType, IntType),
        (TypeSignature::BUFFER_MAX, TypeSignature::STRING_ASCII_MAX),
        (
            TypeSignature::list_of(TypeSignature::UIntType, 42).unwrap(),
            TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
        ),
        (
            TypeSignature::STRING_UTF8_MIN,
            TypeSignature::new_ascii_type_checked(17),
        ),
        (TypeSignature::STRING_UTF8_MIN, TypeSignature::BUFFER_MIN),
        (
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::from_literal("a"),
                    TypeSignature::IntType,
                )])
                .unwrap(),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::from_literal("a"),
                    TypeSignature::UIntType,
                )])
                .unwrap(),
            ),
        ),
        (
            TypeSignature::new_option(TypeSignature::IntType).unwrap(),
            TypeSignature::new_option(TypeSignature::STRING_UTF8_MIN).unwrap(),
        ),
        (
            TypeSignature::new_response(TypeSignature::IntType, TypeSignature::BoolType).unwrap(),
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        (
            TypeSignature::CallableType(CallableSubtype::Principal(
                QualifiedContractIdentifier::transient(),
            )),
            TypeSignature::IntType,
        ),
        (
            TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                name: ClarityName::from_literal("foo"),
                contract_identifier: QualifiedContractIdentifier::transient(),
            })),
            TypeSignature::PrincipalType,
        ),
        (list_union.clone(), TypeSignature::PrincipalType),
        (TypeSignature::STRING_ASCII_MIN, list_union_principals),
        (
            TypeSignature::list_of(
                TypeSignature::SequenceType(SequenceSubtype::BufferType(
                    16_u32.try_into().unwrap(),
                )),
                5,
            )
            .unwrap(),
            TypeSignature::list_of(TypeSignature::STRING_ASCII_MIN, 3).unwrap(),
        ),
        (
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::from_literal("b"),
                    TypeSignature::STRING_ASCII_MIN,
                )])
                .unwrap(),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::from_literal("b"),
                    TypeSignature::UIntType,
                )])
                .unwrap(),
            ),
        ),
        (
            TypeSignature::new_option(TypeSignature::STRING_ASCII_MIN).unwrap(),
            TypeSignature::new_option(TypeSignature::STRING_UTF8_MIN).unwrap(),
        ),
        (
            TypeSignature::new_response(TypeSignature::PrincipalType, list_union).unwrap(),
            TypeSignature::new_response(
                list_union2,
                TypeSignature::CallableType(CallableSubtype::Principal(
                    QualifiedContractIdentifier::transient(),
                )),
            )
            .unwrap(),
        ),
    ];

    for pair in bad_pairs {
        matches!(
            TypeSignature::least_supertype_v2_1(&pair.0, &pair.1).unwrap_err(),
            ClarityTypeError::TypeMismatch(..)
        );
        matches!(
            TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap_err(),
            ClarityTypeError::TypeMismatch(..)
        );
    }
}

fn trait_id(contract: &str, name: &str) -> TraitIdentifier {
    TraitIdentifier {
        name: ClarityName::try_from(name.to_string()).unwrap(),
        contract_identifier: QualifiedContractIdentifier::local(contract).unwrap(),
    }
}

fn callable_principal_subtype(contract: &str) -> CallableSubtype {
    CallableSubtype::Principal(QualifiedContractIdentifier::local(contract).unwrap())
}

fn callable_trait_subtype(contract: &str, name: &str) -> CallableSubtype {
    CallableSubtype::Trait(trait_id(contract, name))
}

fn list_union_type(members: Vec<CallableSubtype>) -> TypeSignature {
    TypeSignature::ListUnionType(members.into_iter().collect())
}

fn buff_type(len: u32) -> TypeSignature {
    TypeSignature::SequenceType(SequenceSubtype::BufferType(
        BufferLength::try_from(len).unwrap(),
    ))
}

fn ascii_type(len: u32) -> TypeSignature {
    TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
        BufferLength::try_from(len).unwrap(),
    )))
}

fn utf8_type(len: u32) -> TypeSignature {
    TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
        StringUTF8Length::try_from(len).unwrap(),
    )))
}

/// The equal-type fast path in `parent_list_type_from_iter` is only sound if
/// `least_supertype_v2_1(T, T) == Ok(T)` for every `T`. Each case seeds one
/// leaf type; its nested compounds (~64 shapes) are generated in the body.
#[rstest]
#[case::no_type(TypeSignature::NoType)]
#[case::int(TypeSignature::IntType)]
#[case::uint(TypeSignature::UIntType)]
#[case::bool(TypeSignature::BoolType)]
#[case::principal(TypeSignature::PrincipalType)]
#[case::buffer_zero_len(buff_type(0))]
#[case::buffer(buff_type(17))]
#[case::string_ascii(ascii_type(5))]
#[case::string_utf8(utf8_type(3))]
#[case::callable_principal(TypeSignature::CallableType(callable_principal_subtype("contract-a")))]
#[case::callable_trait(TypeSignature::CallableType(callable_trait_subtype(
    "contract-a",
    "trait-a"
)))]
#[case::trait_reference(TypeSignature::TraitReferenceType(trait_id("contract-a", "trait-a")))]
#[case::list_union_single(list_union_type(vec![callable_principal_subtype("contract-a")]))]
#[case::list_union_mixed(list_union_type(vec![
    callable_principal_subtype("contract-a"),
    callable_principal_subtype("contract-b"),
    callable_trait_subtype("contract-a", "trait-a"),
    callable_trait_subtype("contract-b", "trait-b"),
]))]
#[case::empty_list(TypeSignature::from(TypeSignature::empty_list()))]
fn test_least_supertype_v2_1_idempotent(#[case] leaf: TypeSignature) {
    use crate::types::TypeSignature::*;

    let mut corpus = vec![leaf];
    // two wrapping rounds cover nested compounds
    for _ in 0..2 {
        let snapshot = corpus.clone();
        for t in snapshot {
            corpus.push(OptionalType(Box::new(t.clone())));
            corpus.push(ResponseType(Box::new((t.clone(), NoType))));
            corpus.push(ResponseType(Box::new((NoType, t.clone()))));
            corpus.push(ResponseType(Box::new((t.clone(), t.clone()))));
            corpus.push(TypeSignature::list_of(t.clone(), 0).unwrap());
            corpus.push(TypeSignature::list_of(t.clone(), 4).unwrap());
            corpus.push(
                TupleTypeSignature::try_from(vec![(
                    ClarityName::try_from("field-a".to_string()).unwrap(),
                    t,
                )])
                .unwrap()
                .into(),
            );
        }
    }

    for t in &corpus {
        assert_eq!(
            TypeSignature::least_supertype_v2_1(t, t).as_ref(),
            Ok(t),
            "least_supertype_v2_1 must be idempotent for {t:?}"
        );
    }
}

fn buff_value(len: usize) -> Value {
    Value::buff_from(vec![0; len]).unwrap()
}

fn ascii_value(s: &str) -> Value {
    Value::string_ascii_from_bytes(s.as_bytes().to_vec()).unwrap()
}

fn callable_value(contract: &str) -> Value {
    Value::CallableContract(CallableData {
        contract_identifier: QualifiedContractIdentifier::local(contract).unwrap(),
        trait_identifier: None,
    })
}

fn tuple_value(v: Value) -> Value {
    Value::from(
        TupleData::from_data(vec![(
            ClarityName::try_from("field-a".to_string()).unwrap(),
            v,
        )])
        .unwrap(),
    )
}

/// `construct_parent_list_type` and `parent_list_type` must stay equivalent
/// for values satisfying constructor invariants, including identical errors.
#[rstest]
#[case::empty(vec![])]
#[case::homogeneous_bools(vec![Value::Bool(true), Value::Bool(false), Value::Bool(true)])]
#[case::homogeneous_ints(vec![Value::Int(1), Value::Int(2)])]
#[case::int_uint_mismatch(vec![Value::Int(1), Value::UInt(2)])]
#[case::bool_int_mismatch(vec![Value::Bool(true), Value::Int(1)])]
#[case::buffers_different_lengths(vec![buff_value(3), buff_value(5)])]
#[case::ascii_different_lengths(vec![ascii_value("abc"), ascii_value("defgh")])]
#[case::identical_callables(vec![callable_value("contract-a"), callable_value("contract-a")])]
#[case::distinct_callables(vec![callable_value("contract-a"), callable_value("contract-b")])]
#[case::callable_with_standard_principal(vec![
    callable_value("contract-a"),
    Value::from(StandardPrincipalData::transient()),
])]
#[case::optional_none_and_some(vec![Value::none(), Value::some(Value::Int(5)).unwrap()])]
#[case::response_ok_and_err(vec![
    Value::okay(Value::Int(1)).unwrap(),
    Value::error(Value::Bool(false)).unwrap(),
])]
#[case::empty_and_nonempty_lists(vec![
    Value::cons_list_unsanitized(vec![]).unwrap(),
    Value::cons_list_unsanitized(vec![Value::Int(3)]).unwrap(),
])]
#[case::tuple_field_supertype(vec![tuple_value(buff_value(3)), tuple_value(buff_value(5))])]
fn test_construct_parent_list_type_matches_parent_list_type(#[case] values: Vec<Value>) {
    let streamed = TypeSignature::construct_parent_list_type(&values);
    let children: Vec<_> = values
        .iter()
        .map(|v| TypeSignature::type_of(v).unwrap())
        .collect();
    let collected = TypeSignature::parent_list_type(&children);
    assert_eq!(
        streamed, collected,
        "construct_parent_list_type diverged from parent_list_type for {values:?}"
    );
}
