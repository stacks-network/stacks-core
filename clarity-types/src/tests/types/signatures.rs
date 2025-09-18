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
use std::collections::HashSet;

use crate::errors::CheckErrors;
use crate::types::TypeSignature::{BoolType, IntType, ListUnionType, UIntType};
use crate::types::signatures::{CallableSubtype, TypeSignature};
use crate::types::{
    BufferLength, MAX_VALUE_SIZE, QualifiedContractIdentifier, SequenceSubtype, TraitIdentifier,
    TupleTypeSignature,
};

#[test]
fn test_buffer_length_from_u32_runtime() {
    let buffer = BufferLength::try_from_u32(0).unwrap();
    assert_eq!(0, buffer.get_value());

    let buffer = BufferLength::try_from_u32(MAX_VALUE_SIZE).unwrap();
    assert_eq!(MAX_VALUE_SIZE, buffer.get_value());

    let err = BufferLength::try_from_u32(MAX_VALUE_SIZE + 1).unwrap_err();
    assert_eq!(CheckErrors::ValueTooLarge, err);
}

#[test]
fn test_buffer_length_from_u32_compile_time() {
    const B_0: BufferLength = BufferLength::from_const_u32::<0>();
    assert_eq!(0, B_0.get_value());

    const B_MAX: BufferLength = BufferLength::from_const_u32::<MAX_VALUE_SIZE>();
    assert_eq!(MAX_VALUE_SIZE, B_MAX.get_value());

    //moved to runtime check, otherwise it emits a compilation error
    std::panic::catch_unwind(|| {
        const OUT_RANGE: u32 = MAX_VALUE_SIZE + 1;
        let _ = BufferLength::from_const_u32::<OUT_RANGE>();
    })
    .expect_err("panic");
}

#[test]
fn test_buffer_length_try_from_u32_trait() {
    let buffer = BufferLength::try_from(0u32).unwrap();
    assert_eq!(0, buffer.get_value());

    let buffer = BufferLength::try_from(MAX_VALUE_SIZE).unwrap();
    assert_eq!(MAX_VALUE_SIZE, buffer.get_value());

    let err = BufferLength::try_from(MAX_VALUE_SIZE + 1).unwrap_err();
    assert_eq!(CheckErrors::ValueTooLarge, err);
}

#[test]
fn test_buffer_length_to_u32_with_from_trait() {
    let buffer = BufferLength::new_unsafe(0);
    assert_eq!(0, u32::from(&buffer));
    assert_eq!(0, u32::from(buffer));
}

#[test]
fn test_type_buffer_min_to_be_buffer_1() {
    assert_eq!(TypeSignature::BUFFER_1, TypeSignature::BUFFER_MIN);
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
                TypeSignature::bound_string_ascii_type(17).unwrap(),
            ),
            TypeSignature::bound_string_ascii_type(17).unwrap(),
        ),
        (
            (
                TypeSignature::NoType,
                TypeSignature::max_string_utf8().unwrap(),
            ),
            TypeSignature::max_string_utf8().unwrap(),
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
            (
                TypeSignature::max_buffer().unwrap(),
                TypeSignature::max_buffer().unwrap(),
            ),
            TypeSignature::max_buffer().unwrap(),
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
                TypeSignature::bound_string_ascii_type(17).unwrap(),
                TypeSignature::bound_string_ascii_type(17).unwrap(),
            ),
            TypeSignature::bound_string_ascii_type(17).unwrap(),
        ),
        (
            (
                TypeSignature::max_string_utf8().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ),
            TypeSignature::max_string_utf8().unwrap(),
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
            (
                TypeSignature::max_buffer().unwrap(),
                TypeSignature::BUFFER_MIN,
            ),
            TypeSignature::max_buffer().unwrap(),
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
                TypeSignature::min_string_ascii().unwrap(),
                TypeSignature::bound_string_ascii_type(17).unwrap(),
            ),
            TypeSignature::bound_string_ascii_type(17).unwrap(),
        ),
        (
            (
                TypeSignature::min_string_utf8().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ),
            TypeSignature::max_string_utf8().unwrap(),
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
                        TypeSignature::min_string_ascii().unwrap(),
                    )])
                    .unwrap(),
                ),
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![(
                        "b".into(),
                        TypeSignature::bound_string_ascii_type(17).unwrap(),
                    )])
                    .unwrap(),
                ),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    "b".into(),
                    TypeSignature::bound_string_ascii_type(17).unwrap(),
                )])
                .unwrap(),
            ),
        ),
        (
            (
                TypeSignature::new_option(TypeSignature::min_string_ascii().unwrap()).unwrap(),
                TypeSignature::new_option(TypeSignature::bound_string_ascii_type(17).unwrap())
                    .unwrap(),
            ),
            TypeSignature::new_option(TypeSignature::bound_string_ascii_type(17).unwrap()).unwrap(),
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
        (
            TypeSignature::max_buffer().unwrap(),
            TypeSignature::max_string_ascii().unwrap(),
        ),
        (
            TypeSignature::list_of(TypeSignature::UIntType, 42).unwrap(),
            TypeSignature::list_of(TypeSignature::IntType, 42).unwrap(),
        ),
        (
            TypeSignature::min_string_utf8().unwrap(),
            TypeSignature::bound_string_ascii_type(17).unwrap(),
        ),
        (
            TypeSignature::min_string_utf8().unwrap(),
            TypeSignature::BUFFER_MIN,
        ),
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
            TypeSignature::new_option(TypeSignature::min_string_utf8().unwrap()).unwrap(),
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
        (
            TypeSignature::min_string_ascii().unwrap(),
            list_union_principals,
        ),
        (
            TypeSignature::list_of(
                TypeSignature::SequenceType(SequenceSubtype::BufferType(
                    16_u32.try_into().unwrap(),
                )),
                5,
            )
            .unwrap(),
            TypeSignature::list_of(TypeSignature::min_string_ascii().unwrap(), 3).unwrap(),
        ),
        (
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![(
                    "b".into(),
                    TypeSignature::min_string_ascii().unwrap(),
                )])
                .unwrap(),
            ),
            TypeSignature::TupleType(
                TupleTypeSignature::try_from(vec![("b".into(), TypeSignature::UIntType)]).unwrap(),
            ),
        ),
        (
            TypeSignature::new_option(TypeSignature::min_string_ascii().unwrap()).unwrap(),
            TypeSignature::new_option(TypeSignature::min_string_utf8().unwrap()).unwrap(),
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
            CheckErrors::TypeError(..)
        );
        matches!(
            TypeSignature::least_supertype_v2_1(&pair.1, &pair.0).unwrap_err(),
            CheckErrors::TypeError(..)
        );
    }
}

#[test]
fn test_type_signature_bound_string_ascii_type_returns_check_errors() {
    let err = TypeSignature::bound_string_ascii_type(MAX_VALUE_SIZE + 1).unwrap_err();
    assert_eq!(
        CheckErrors::Expects(
            "FAIL: Max Clarity Value Size is no longer realizable in ASCII Type".to_string()
        ),
        err
    );
}
