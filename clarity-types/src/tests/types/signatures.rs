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
use std::collections::HashSet;

use crate::errors::ClarityTypeError;
use crate::representations::CONTRACT_MAX_NAME_LENGTH;
use crate::types::TypeSignature::{BoolType, IntType, ListUnionType, UIntType};
use crate::types::signatures::{CallableSubtype, TypeSignature};
use crate::types::{
    BufferLength, MAX_TO_ASCII_BUFFER_LEN, MAX_TO_ASCII_RESULT_LEN, MAX_TYPE_DEPTH,
    MAX_UTF8_VALUE_SIZE, MAX_VALUE_SIZE, QualifiedContractIdentifier, SequenceSubtype,
    StringSubtype, StringUTF8Length, TraitIdentifier, TupleTypeSignature, WRAPPER_VALUE_SIZE,
};

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
    assert_eq!(5, actual.type_size().unwrap(), "type size should be 5");
    assert_eq!(1, actual.depth(), "depth should be 1");
}

#[test]
fn test_least_supertype() {
    let callables = [
        CallableSubtype::Principal(QualifiedContractIdentifier::local("foo").unwrap()),
        CallableSubtype::Trait(TraitIdentifier {
            name: "foo".into(),
            contract_identifier: QualifiedContractIdentifier::transient(),
        }),
    ];
    let list_union = ListUnionType(callables.clone().into());
    let callables2 = [
        CallableSubtype::Principal(QualifiedContractIdentifier::local("bar").unwrap()),
        CallableSubtype::Trait(TraitIdentifier {
            name: "bar".into(),
            contract_identifier: QualifiedContractIdentifier::transient(),
        }),
    ];
    let list_union2 = ListUnionType(callables2.clone().into());
    let list_union_merged = ListUnionType(HashSet::from_iter(
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
                    TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                        .unwrap(),
                ),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)]).unwrap(),
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
                    name: "foo".into(),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
            ),
            TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                name: "foo".into(),
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
                    TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                        .unwrap(),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)])
                        .unwrap(),
                ),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)]).unwrap(),
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
                    name: "foo".into(),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
                TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                    name: "foo".into(),
                    contract_identifier: QualifiedContractIdentifier::transient(),
                })),
            ),
            TypeSignature::CallableType(CallableSubtype::Trait(TraitIdentifier {
                name: "foo".into(),
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
                        "b".into(),
                        TypeSignature::STRING_ASCII_MIN,
                    )])
                    .unwrap(),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        "b".into(),
                        TypeSignature::new_ascii_type_checked(17),
                    )])
                    .unwrap(),
                ),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    "b".into(),
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
                TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::IntType)]).unwrap(),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![("a".into(), TypeSignature::UIntType)]).unwrap(),
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
                name: "foo".into(),
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
                TupleTypeSignature::try_from(vec![("b".into(), TypeSignature::STRING_ASCII_MIN)])
                    .unwrap(),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![("b".into(), TypeSignature::UIntType)]).unwrap(),
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
