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
use clarity_types::ClarityName;
use clarity_types::errors::analysis::StaticCheckErrorKind;
use clarity_types::types::{
    BufferLength, ListTypeData, MAX_TO_ASCII_BUFFER_LEN, SequenceSubtype, StringSubtype,
    TypeSignature,
};
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::mem_type_check as mem_run_analysis;
use crate::vm::tests::test_clarity_versions;
use crate::vm::{ClarityVersion, execute_with_parameters};

/// Pass various types to `to-ascii?`
#[apply(test_clarity_versions)]
fn test_to_ascii(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let to_ascii_response_type = |ty: TypeSignature| -> Option<TypeSignature> {
        Some(TypeSignature::new_response(ty, TypeSignature::UIntType).unwrap())
    };
    let to_ascii_max_response_type = Some(
        TypeSignature::new_response(
            TypeSignature::TO_ASCII_STRING_ASCII_MAX,
            TypeSignature::UIntType,
        )
        .unwrap(),
    );
    let to_ascii_expected_types = vec![
        TypeSignature::IntType,
        TypeSignature::UIntType,
        TypeSignature::BoolType,
        TypeSignature::PrincipalType,
        TypeSignature::TO_ASCII_BUFFER_MAX,
        TypeSignature::STRING_UTF8_MAX,
    ];
    let test_cases = [
        (
            "(to-ascii? 123)",
            "int type",
            Ok(to_ascii_response_type(
                TypeSignature::TO_ASCII_INT_RESULT_MAX,
            )),
        ),
        (
            "(to-ascii? u123)",
            "uint type",
            Ok(to_ascii_response_type(
                TypeSignature::TO_ASCII_UINT_RESULT_MAX,
            )),
        ),
        (
            "(to-ascii? true)",
            "bool type",
            Ok(to_ascii_response_type(
                TypeSignature::TO_ASCII_BOOL_RESULT_MAX,
            )),
        ),
        (
            "(to-ascii? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)",
            "standard principal",
            Ok(to_ascii_response_type(
                TypeSignature::TO_ASCII_PRINCIPAL_RESULT_MAX,
            )),
        ),
        (
            "(to-ascii? 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.foo)",
            "contract principal",
            Ok(to_ascii_response_type(
                TypeSignature::TO_ASCII_PRINCIPAL_RESULT_MAX,
            )),
        ),
        (
            "(to-ascii? 0x1234)",
            "buffer type",
            Ok(to_ascii_response_type(
                TypeSignature::new_ascii_type_checked(6),
            )),
        ),
        (
            &format!("(to-ascii? 0x{})", "ff".repeat(524284)),
            "max len buffer type",
            Ok(to_ascii_response_type(
                TypeSignature::new_ascii_type_checked(MAX_TO_ASCII_BUFFER_LEN * 2 + 2),
            )),
        ),
        (
            &format!("(to-ascii? 0x{})", "ff".repeat(524285)),
            "oversized buffer type",
            Err(StaticCheckErrorKind::UnionTypeError(
                to_ascii_expected_types.clone(),
                Box::new(TypeSignature::SequenceType(SequenceSubtype::BufferType(
                    BufferLength::try_from(524285u32).unwrap(),
                ))),
            )),
        ),
        (
            // Note that this will result in a runtime error due to the emoji, but
            // type-checking should pass.
            "(to-ascii? u\"This is fine. \\u{1F605}\")",
            "utf8 string with emoji",
            Ok(to_ascii_response_type(
                TypeSignature::new_ascii_type_checked(15),
            )),
        ),
        (
            "(to-ascii? u\"I am serious, and don't call me Shirley.\")",
            "utf8 string",
            Ok(to_ascii_response_type(
                TypeSignature::new_ascii_type_checked(40),
            )),
        ),
        (
            "(to-ascii? \"60 percent of the time, it works every time\")",
            "ascii string",
            Err(StaticCheckErrorKind::UnionTypeError(
                to_ascii_expected_types.clone(),
                Box::new(TypeSignature::SequenceType(SequenceSubtype::StringType(
                    StringSubtype::ASCII(BufferLength::try_from(43u32).unwrap()),
                ))),
            )),
        ),
        (
            "(to-ascii? (list 1 2 3))",
            "list type",
            Err(StaticCheckErrorKind::UnionTypeError(
                to_ascii_expected_types.clone(),
                Box::new(TypeSignature::SequenceType(SequenceSubtype::ListType(
                    ListTypeData::new_list(TypeSignature::IntType, 3).unwrap(),
                ))),
            )),
        ),
        (
            "(to-ascii? { a: 1, b: u2 })",
            "tuple type",
            Err(StaticCheckErrorKind::UnionTypeError(
                to_ascii_expected_types.clone(),
                Box::new(TypeSignature::TupleType(
                    vec![
                        (ClarityName::from("a"), TypeSignature::IntType),
                        (ClarityName::from("b"), TypeSignature::UIntType),
                    ]
                    .try_into()
                    .unwrap(),
                )),
            )),
        ),
        (
            "(to-ascii? (some u789))",
            "optional type",
            Err(StaticCheckErrorKind::UnionTypeError(
                to_ascii_expected_types.clone(),
                Box::new(TypeSignature::new_option(TypeSignature::UIntType).unwrap()),
            )),
        ),
        (
            "(to-ascii? (ok true))",
            "response type",
            Err(StaticCheckErrorKind::UnionTypeError(
                to_ascii_expected_types.clone(),
                Box::new(
                    TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::NoType)
                        .unwrap(),
                ),
            )),
        ),
    ];

    for (source, description, clarity4_expected) in test_cases.iter() {
        let result = mem_run_analysis(source, version, epoch);
        let actual = result.map(|(type_sig, _)| type_sig).map_err(|e| *e.err);

        let expected = if version >= ClarityVersion::Clarity4 {
            clarity4_expected
        } else {
            &Err(StaticCheckErrorKind::UnknownFunction(
                "to-ascii?".to_string(),
            ))
        };

        assert_eq!(&actual, expected, "Failed for test case: {description}");

        if let Ok(Some(expected_type)) = expected {
            assert!(
                expected_type
                    .admits(
                        &epoch,
                        &execute_with_parameters(source, version, epoch, false)
                            .expect("execution failed")
                            .expect("no return value")
                    )
                    .expect("admits failed"),
                "Expected type did not admit run time value for test case: {description}"
            );
        }
    }
}
