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

use clarity_types::errors::CheckErrors;
use clarity_types::types::TypeSignature;
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::type_checker::v2_1::tests::type_check_helper_version;
use crate::vm::tests::test_clarity_versions;
use crate::vm::ClarityVersion;

/// Test type-checking for `restrict-assets?` expressions
#[apply(test_clarity_versions)]
fn test_restrict_assets(#[case] version: ClarityVersion, #[case] _epoch: StacksEpochId) {
    let good = [
        // simple
        (
            "(restrict-assets? tx-sender ((with-stx u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // literal asset owner
        (
            "(restrict-assets? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4 ((with-stx u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // literal asset owner with contract id
        (
            "(restrict-assets? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token ((with-stx u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // variable asset owner
        (
            "(let ((p tx-sender))
                (restrict-assets? p ((with-stx u1000)) true))",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // no allowances
        (
            "(restrict-assets? tx-sender () true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // multiple allowances
        (
            "(restrict-assets? tx-sender ((with-stx u1000) (with-ft .token \"foo\" u5000) (with-nft .token \"foo\" 0x01) (with-stacking u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // multiple body expressions
        (
            "(restrict-assets? tx-sender ((with-stx u1000)) (+ u1 u2) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
    ];
    let bad = [
        // with-all-assets-unsafe
        (
            "(restrict-assets? tx-sender ((with-all-assets-unsafe)) true)",
            CheckErrors::WithAllAllowanceNotAllowed,
        ),
        // no asset-owner
        (
            "(restrict-assets? ((with-stx u5000)) true)",
            CheckErrors::RequiresAtLeastArguments(3, 2),
        ),
        // no asset-owner, 3 args
        (
            "(restrict-assets? ((with-stx u5000)) true true)",
            CheckErrors::NonFunctionApplication,
        ),
        // bad asset-owner type
        (
            "(restrict-assets? u100 ((with-stx u5000)) true)",
            CheckErrors::TypeError(
                TypeSignature::PrincipalType.into(),
                TypeSignature::UIntType.into(),
            ),
        ),
        // no allowances
        (
            "(restrict-assets? tx-sender true)",
            CheckErrors::RequiresAtLeastArguments(3, 2),
        ),
        // allowance not in list
        (
            "(restrict-assets? tx-sender (with-stx u1) true)",
            CheckErrors::ExpectedListApplication,
        ),
        // other value in place of allowance list
        (
            "(restrict-assets? tx-sender u1 true)",
            CheckErrors::ExpectedListOfAllowances("restrict-assets?".into(), 2),
        ),
        // non-allowance in allowance list
        (
            "(restrict-assets? tx-sender (u1) true)",
            CheckErrors::ExpectedListApplication,
        ),
        // empty list in allowance list
        (
            "(restrict-assets? tx-sender (()) true)",
            CheckErrors::NonFunctionApplication,
        ),
        // list with literal in allowance list
        (
            "(restrict-assets? tx-sender ((123)) true)",
            CheckErrors::NonFunctionApplication,
        ),
        // non-allowance function in allowance list
        (
            "(restrict-assets? tx-sender ((foo)) true)",
            CheckErrors::UnknownFunction("foo".into()),
        ),
        // no body expressions
        (
            "(restrict-assets? tx-sender ((with-stx u5000)))",
            CheckErrors::RequiresAtLeastArguments(3, 2),
        ),
        // unhandled response in only body expression
        (
            "(restrict-assets? tx-sender ((with-stx u1000)) (err u1))",
            CheckErrors::UncheckedIntermediaryResponses,
        ),
        // unhandled response in last body expression
        (
            "(restrict-assets? tx-sender ((with-stx u1000)) true (err u1))",
            CheckErrors::UncheckedIntermediaryResponses,
        ),
        // unhandled response in other body expression
        (
            "(restrict-assets? tx-sender ((with-stx u1000)) (err u1) true)",
            CheckErrors::UncheckedIntermediaryResponses,
        ),
    ];

    for (good_code, expected_type) in &good {
        info!("test good code: '{}'", good_code);
        if version < ClarityVersion::Clarity4 {
            // restrict-assets? is only available in Clarity 4+
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(good_code, version)
                    .unwrap_err()
                    .err
            );
        } else {
            assert_eq!(
                expected_type,
                &type_check_helper_version(good_code, version).unwrap()
            );
        }
    }

    for (bad_code, expected_err) in &bad {
        info!("test bad code: '{}'", bad_code);
        if version < ClarityVersion::Clarity4 {
            // restrict-assets? is only available in Clarity 4+
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(bad_code, version)
                    .unwrap_err()
                    .err
            );
        } else {
            assert_eq!(
                expected_err,
                type_check_helper_version(bad_code, version)
                    .unwrap_err()
                    .err
                    .as_ref()
            );
        }
    }
}

/// Test type-checking for `as-contract?` expressions
#[apply(test_clarity_versions)]
fn test_as_contract(#[case] version: ClarityVersion, #[case] _epoch: StacksEpochId) {
    let good = [
        // simple
        (
            "(as-contract? ((with-stx u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // no allowances
        (
            "(as-contract? () true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // multiple allowances
        (
            "(as-contract? ((with-stx u1000) (with-ft .token \"foo\" u5000) (with-nft .token \"foo\" (list 0x01)) (with-stacking u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // multiple body expressions
        (
            "(as-contract? ((with-stx u1000)) (+ u1 u2) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // with-all-assets-unsafe
        (
            "(as-contract? ((with-all-assets-unsafe)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),

    ];
    let bad = [
        // no allowances
        (
            "(as-contract? true)",
            CheckErrors::RequiresAtLeastArguments(2, 1),
        ),
        // allowance not in list
        (
            "(as-contract? (with-stx u1) true)",
            CheckErrors::ExpectedListApplication,
        ),
        // other value in place of allowance list
        (
            "(as-contract? u1 true)",
            CheckErrors::ExpectedListOfAllowances("as-contract?".into(), 1),
        ),
        // non-allowance in allowance list
        (
            "(as-contract? (u1) true)",
            CheckErrors::ExpectedListApplication,
        ),
        // empty list in allowance list
        (
            "(as-contract? (()) true)",
            CheckErrors::NonFunctionApplication,
        ),
        // list with literal in allowance list
        (
            "(as-contract? ((123)) true)",
            CheckErrors::NonFunctionApplication,
        ),
        // non-allowance function in allowance list
        (
            "(as-contract? ((foo)) true)",
            CheckErrors::UnknownFunction("foo".into()),
        ),
        // no body expressions
        (
            "(as-contract? ((with-stx u5000)))",
            CheckErrors::RequiresAtLeastArguments(2, 1),
        ),
        // unhandled response in only body expression
        (
            "(as-contract? ((with-stx u1000)) (err u1))",
            CheckErrors::UncheckedIntermediaryResponses,
        ),
        // unhandled response in last body expression
        (
            "(as-contract? ((with-stx u1000)) true (err u1))",
            CheckErrors::UncheckedIntermediaryResponses,
        ),
        // unhandled response in other body expression
        (
            "(as-contract? ((with-stx u1000)) (err u1) true)",
            CheckErrors::UncheckedIntermediaryResponses,
        ),
        // other allowances together with with-all-assets-unsafe (first)
        (
            "(as-contract? ((with-all-assets-unsafe) (with-stx u1000)) true)",
            CheckErrors::WithAllAllowanceNotAlone,
        ),
        // other allowances together with with-all-assets-unsafe (second)
        (
            "(as-contract? ((with-stx u1000) (with-all-assets-unsafe)) true)",
            CheckErrors::WithAllAllowanceNotAlone,
        ),
    ];

    for (code, expected_type) in &good {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            // as-contract? is only available in Clarity 4+
            assert_eq!(
                CheckErrors::UnknownFunction("as-contract?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_type,
                &type_check_helper_version(code, version).unwrap()
            );
        }
    }

    for (code, expected_err) in &bad {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            // as-contract? is only available in Clarity 4+
            assert_eq!(
                CheckErrors::UnknownFunction("as-contract?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_err,
                type_check_helper_version(code, version)
                    .unwrap_err()
                    .err
                    .as_ref()
            );
        }
    }
}

/// Test type-checking for `with-stx` allowance expressions
#[apply(test_clarity_versions)]
fn test_with_stx_allowance(#[case] version: ClarityVersion, #[case] _epoch: StacksEpochId) {
    let good = [
        // basic usage
        (
            "(restrict-assets? tx-sender ((with-stx u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // zero amount
        (
            "(restrict-assets? tx-sender ((with-stx u0)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // large amount
        (
            "(restrict-assets? tx-sender ((with-stx u340282366920938463463374607431768211455)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
        // variable amount
        (
            "(let ((amount u1000)) (restrict-assets? tx-sender ((with-stx amount)) true))",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap()
        ),
    ];

    let bad = [
        // no arguments
        (
            "(restrict-assets? tx-sender ((with-stx)) true)",
            CheckErrors::IncorrectArgumentCount(1, 0),
        ),
        // too many arguments
        (
            "(restrict-assets? tx-sender ((with-stx u1000 u2000)) true)",
            CheckErrors::IncorrectArgumentCount(1, 2),
        ),
        // wrong type - string instead of uint
        (
            r#"(restrict-assets? tx-sender ((with-stx "1000")) true)"#,
            CheckErrors::TypeError(
                TypeSignature::UIntType.into(),
                TypeSignature::new_string_ascii(4).unwrap().into(),
            ),
        ),
        // wrong type - int instead of uint
        (
            "(restrict-assets? tx-sender ((with-stx 1000)) true)",
            CheckErrors::TypeError(
                TypeSignature::UIntType.into(),
                TypeSignature::IntType.into(),
            ),
        ),
    ];

    for (code, expected_type) in &good {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_type,
                &type_check_helper_version(code, version).unwrap()
            );
        }
    }

    for (code, expected_err) in &bad {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_err,
                type_check_helper_version(code, version)
                    .unwrap_err()
                    .err
                    .as_ref()
            );
        }
    }
}

/// Test type-checking for `with-ft` allowance expressions
#[apply(test_clarity_versions)]
fn test_with_ft_allowance(#[case] version: ClarityVersion, #[case] _epoch: StacksEpochId) {
    let good = [
        // basic usage with shortcut contract principal
        (
            r#"(restrict-assets? tx-sender ((with-ft .token "token-name" u1000)) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // full literal principal
        (
            r#"(restrict-assets? tx-sender ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.token "token-name" u1000)) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // variable principal
        (
            r#"(let ((contract .token)) (restrict-assets? tx-sender ((with-ft contract "token-name" u1000)) true))"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // variable token name
        (
            r#"(let ((name "token-name")) (restrict-assets? tx-sender ((with-ft .token name u1000)) true))"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // variable amount
        (
            r#"(let ((amount u1000)) (restrict-assets? tx-sender ((with-ft .token "token-name" amount)) true))"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // "*" token name
        (
            r#"(restrict-assets? tx-sender ((with-ft .token "*" u1000)) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // empty token name
        (
            r#"(restrict-assets? tx-sender ((with-ft .token "" u1000)) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
    ];

    let bad = [
        // no arguments
        (
            "(restrict-assets? tx-sender ((with-ft)) true)",
            CheckErrors::IncorrectArgumentCount(3, 0),
        ),
        // one argument
        (
            "(restrict-assets? tx-sender ((with-ft .token)) true)",
            CheckErrors::IncorrectArgumentCount(3, 1),
        ),
        // two arguments
        (
            r#"(restrict-assets? tx-sender ((with-ft .token "token-name")) true)"#,
            CheckErrors::IncorrectArgumentCount(3, 2),
        ),
        // too many arguments
        (
            r#"(restrict-assets? tx-sender ((with-ft .token "token-name" u1000 u2000)) true)"#,
            CheckErrors::IncorrectArgumentCount(3, 4),
        ),
        // wrong type for contract-id - uint instead of principal
        (
            r#"(restrict-assets? tx-sender ((with-ft u123 "token-name" u1000)) true)"#,
            CheckErrors::TypeError(
                TypeSignature::PrincipalType.into(),
                TypeSignature::UIntType.into(),
            ),
        ),
        // wrong type for token-name - uint instead of string
        (
            "(restrict-assets? tx-sender ((with-ft .token u123 u1000)) true)",
            CheckErrors::TypeError(
                TypeSignature::new_string_ascii(128).unwrap().into(),
                TypeSignature::UIntType.into(),
            ),
        ),
        // wrong type for amount - string instead of uint
        (
            r#"(restrict-assets? tx-sender ((with-ft .token "token-name" "1000")) true)"#,
            CheckErrors::TypeError(
                TypeSignature::UIntType.into(),
                TypeSignature::new_string_ascii(4).unwrap().into(),
            ),
        ),
        // wrong type for amount - int instead of uint
        (
            r#"(restrict-assets? tx-sender ((with-ft .token "token-name" 1000)) true)"#,
            CheckErrors::TypeError(
                TypeSignature::UIntType.into(),
                TypeSignature::IntType.into(),
            ),
        ),
        // too long token name (longer than 128 chars)
        (
            "(restrict-assets? tx-sender ((with-ft .token \"this-token-name-is-way-too-long-to-be-valid-because-it-has-more-than-one-hundred-and-twenty-eight-characters-in-it-so-it-is-not-a-valid-token-name\" u1000)) true)",
            CheckErrors::TypeError(
                TypeSignature::new_string_ascii(128).unwrap().into(),
                TypeSignature::new_string_ascii(146).unwrap().into(),
            ),
        ),
    ];

    for (code, expected_type) in &good {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_type,
                &type_check_helper_version(code, version).unwrap()
            );
        }
    }

    for (code, expected_err) in &bad {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_err,
                type_check_helper_version(code, version)
                    .unwrap_err()
                    .err
                    .as_ref()
            );
        }
    }
}

/// Test type-checking for `with-nft` allowance expressions
#[apply(test_clarity_versions)]
fn test_with_nft_allowance(#[case] version: ClarityVersion, #[case] _epoch: StacksEpochId) {
    let good = [
        // basic usage with shortcut contract principal
        (
            r#"(restrict-assets? tx-sender ((with-nft .token "token-name" (list u1000))) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // full literal principal
        (
            r#"(restrict-assets? tx-sender ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.token "token-name" (list u1000))) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // variable principal
        (
            r#"(let ((contract .token)) (restrict-assets? tx-sender ((with-nft contract "token-name" (list u1000))) true))"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // variable token name
        (
            r#"(let ((name "token-name")) (restrict-assets? tx-sender ((with-nft .token name (list u1000))) true))"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // "*" token name
        (
            r#"(restrict-assets? tx-sender ((with-nft .token "*" (list u1000))) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // empty token name
        (
            r#"(restrict-assets? tx-sender ((with-nft .token "" (list u1000))) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // string asset-id
        (
            r#"(restrict-assets? tx-sender ((with-nft .token "token-name" (list "asset-123"))) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // buffer asset-id
        (
            r#"(restrict-assets? tx-sender ((with-nft .token "token-name" (list 0x0123456789))) true)"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // variable asset-id
        (
            r#"(let ((asset-id (list u123))) (restrict-assets? tx-sender ((with-nft .token "token-name" asset-id)) true))"#,
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
    ];

    let bad = [
        // no arguments
        (
            "(restrict-assets? tx-sender ((with-nft)) true)",
            CheckErrors::IncorrectArgumentCount(3, 0),
        ),
        // one argument
        (
            "(restrict-assets? tx-sender ((with-nft .token)) true)",
            CheckErrors::IncorrectArgumentCount(3, 1),
        ),
        // two arguments
        (
            r#"(restrict-assets? tx-sender ((with-nft .token "token-name")) true)"#,
            CheckErrors::IncorrectArgumentCount(3, 2),
        ),
        // too many arguments
        (
            r#"(restrict-assets? tx-sender ((with-nft .token "token-name" (list u123) (list u456))) true)"#,
            CheckErrors::IncorrectArgumentCount(3, 4),
        ),
        // wrong type for contract-id - uint instead of principal
        (
            r#"(restrict-assets? tx-sender ((with-nft u123 "token-name" (list u456))) true)"#,
            CheckErrors::TypeError(
                TypeSignature::PrincipalType.into(),
                TypeSignature::UIntType.into(),
            ),
        ),
        // wrong type for token-name - uint instead of string
        (
            "(restrict-assets? tx-sender ((with-nft .token u123 (list u456))) true)",
            CheckErrors::TypeError(
                TypeSignature::new_string_ascii(128).unwrap().into(),
                TypeSignature::UIntType.into(),
            ),
        ),
        // too long token name (longer than 128 chars)
        (
            "(restrict-assets? tx-sender ((with-ft .token \"this-token-name-is-way-too-long-to-be-valid-because-it-has-more-than-one-hundred-and-twenty-eight-characters-in-it-so-it-is-not-a-valid-token-name\" u1000)) true)",
            CheckErrors::TypeError(
                TypeSignature::new_string_ascii(128).unwrap().into(),
                TypeSignature::new_string_ascii(146).unwrap().into(),
            ),
        ),
    ];

    for (code, expected_type) in &good {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_type,
                &type_check_helper_version(code, version).unwrap()
            );
        }
    }

    for (code, expected_err) in &bad {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_err,
                type_check_helper_version(code, version)
                    .unwrap_err()
                    .err
                    .as_ref()
            );
        }
    }
}

/// Test type-checking for `with-stacking` allowance expressions
#[apply(test_clarity_versions)]
fn test_with_stacking_allowance(#[case] version: ClarityVersion, #[case] _epoch: StacksEpochId) {
    let good = [
        // basic usage
        (
            "(restrict-assets? tx-sender ((with-stacking u1000)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // zero amount
        (
            "(restrict-assets? tx-sender ((with-stacking u0)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
        // variable amount
        (
            "(let ((amount u1000)) (restrict-assets? tx-sender ((with-stacking amount)) true))",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
    ];

    let bad = [
        // no arguments
        (
            "(restrict-assets? tx-sender ((with-stacking)) true)",
            CheckErrors::IncorrectArgumentCount(1, 0),
        ),
        // too many arguments
        (
            "(restrict-assets? tx-sender ((with-stacking u1000 u2000)) true)",
            CheckErrors::IncorrectArgumentCount(1, 2),
        ),
        // wrong type - string instead of uint
        (
            r#"(restrict-assets? tx-sender ((with-stacking "1000")) true)"#,
            CheckErrors::TypeError(
                TypeSignature::UIntType.into(),
                TypeSignature::new_string_ascii(4).unwrap().into(),
            ),
        ),
        // wrong type - int instead of uint
        (
            "(restrict-assets? tx-sender ((with-stacking 1000)) true)",
            CheckErrors::TypeError(
                TypeSignature::UIntType.into(),
                TypeSignature::IntType.into(),
            ),
        ),
    ];

    for (code, expected_type) in &good {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_type,
                &type_check_helper_version(code, version).unwrap()
            );
        }
    }

    for (code, expected_err) in &bad {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_err,
                type_check_helper_version(code, version)
                    .unwrap_err()
                    .err
                    .as_ref()
            );
        }
    }
}

/// Test type-checking for `with-all-assets-unsafe` allowance expressions
#[apply(test_clarity_versions)]
fn test_with_all_assets_unsafe_allowance(
    #[case] version: ClarityVersion,
    #[case] _epoch: StacksEpochId,
) {
    let good = [
        // basic usage
        (
            "(as-contract? ((with-all-assets-unsafe)) true)",
            TypeSignature::new_response(TypeSignature::BoolType, TypeSignature::IntType).unwrap(),
        ),
    ];

    let bad = [
        // with-all-assets-unsafe in restrict-assets? (not allowed)
        (
            "(restrict-assets? tx-sender ((with-all-assets-unsafe)) true)",
            CheckErrors::WithAllAllowanceNotAllowed,
        ),
        // with-all-assets-unsafe with arguments (should take 0)
        (
            "(restrict-assets? tx-sender ((with-all-assets-unsafe u123)) true)",
            CheckErrors::IncorrectArgumentCount(0, 1),
        ),
    ];

    for (code, expected_type) in &good {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("as-contract?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_type,
                &type_check_helper_version(code, version).unwrap()
            );
        }
    }

    for (code, expected_err) in &bad {
        info!("test code: '{}'", code);
        if version < ClarityVersion::Clarity4 {
            assert_eq!(
                CheckErrors::UnknownFunction("restrict-assets?".to_string()),
                *type_check_helper_version(code, version).unwrap_err().err
            );
        } else {
            assert_eq!(
                expected_err,
                type_check_helper_version(code, version)
                    .unwrap_err()
                    .err
                    .as_ref()
            );
        }
    }
}
