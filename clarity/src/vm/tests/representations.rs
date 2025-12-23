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

use clarity_types::types::ClarityTypeError;
use proptest::prelude::*;
use proptest::string::string_regex;
use stacks_common::codec::StacksMessageCodec;

use crate::vm::representations::{
    CLARITY_NAME_REGEX_STRING, CONTRACT_MAX_NAME_LENGTH, CONTRACT_MIN_NAME_LENGTH,
    CONTRACT_NAME_REGEX_STRING, MAX_STRING_LEN,
};
use crate::vm::{ClarityName, ContractName};

fn assert_regex_unchanged(actual: &str, expected: &str) {
    assert_eq!(actual, expected, "Regex has changed");
}

/// Generates a proptest strategy for valid Clarity names.
///
/// This function creates a branched strategy based on the `CLARITY_NAME_REGEX_STRING` pattern.
///
/// The strategy covers three categories of valid names:
/// - Letter-based names starting with a letter followed by alphanumeric or symbol characters
/// - Single arithmetic operators (`-`, `+`, `=`, `/`, `*`)
/// - Comparison operators (`<`, `>`, `<=`, `>=`)
fn any_valid_clarity_name() -> impl Strategy<Value = String> {
    // Ensure the regex branches match the actual validator.
    assert_regex_unchanged(
        CLARITY_NAME_REGEX_STRING.as_str(),
        "^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$",
    );

    let letter_names = string_regex(&format!(
        "[a-zA-Z][a-zA-Z0-9_!?+<>=/*-]{{0,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    let single_ops = prop_oneof![
        Just("-".to_string()),
        Just("+".to_string()),
        Just("=".to_string()),
        Just("/".to_string()),
        Just("*".to_string()),
    ];

    let comparison_ops = prop_oneof![
        Just("<".to_string()),
        Just(">".to_string()),
        Just("<=".to_string()),
        Just(">=".to_string()),
    ];

    prop_oneof![letter_names, single_ops, comparison_ops]
}

#[test]
fn prop_clarity_name_valid_patterns() {
    proptest!(|(name in any_valid_clarity_name())| {
        prop_assume!(!name.is_empty());
        prop_assume!(name.len() <= MAX_STRING_LEN as usize);

        let clarity_name = ClarityName::try_from(name.clone())
            .unwrap_or_else(|_| panic!("Should parse valid clarity name: {name}"));
        prop_assert_eq!(clarity_name.as_str(), name);
    });
}

/// Generates a proptest strategy for invalid Clarity names.
///
/// This function creates a strategy that generates strings that should be rejected
/// by `ClarityName::try_from()` validation by systematically violating each valid branch.
///
/// The strategy generates names that violate the three valid branches:
/// - Branch 1 violations: Invalid starting characters or invalid characters in letter-based names
/// - Branch 2 violations: Multi-character strings starting with single operators
/// - Branch 3 violations: Invalid extensions to comparison operators
/// - General violations: Empty strings and length violations
///
/// Valid branches being violated:
/// 1. `^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$` - Letter-based names
/// 2. `^[-+=/*]$` - Single arithmetic operators
/// 3. `^[<>]=?$` - Comparison operators
fn any_invalid_clarity_name() -> impl Strategy<Value = String> {
    // Ensure the regex branches match the actual validator.
    assert_regex_unchanged(
        CLARITY_NAME_REGEX_STRING.as_str(),
        "^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$",
    );

    let empty_string = Just("".to_string());

    // Names starting with numbers (violates first branch requirement of starting with letter).
    let starts_with_number = string_regex(&format!(
        "[0-9][a-zA-Z0-9_!?+<>=/*-]{{0,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    // Names starting with invalid symbols (violates all branches - not letters, not valid single
    // operators, not comparison operators).
    let starts_with_invalid_symbol = string_regex(&format!(
        "[@ #$%&.,;:|\\\"'\\[\\](){{}}][a-zA-Z0-9_!?+<>=/*-]{{0,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    // Names starting with letters but containing invalid characters (violates first branch
    // character set restrictions).
    let invalid_chars_in_letter_names = string_regex(
        "[a-zA-Z][a-zA-Z0-9_!?+<>=/*-]*[@ #$%&.,;:|\\\"'\\[\\](){{}}][a-zA-Z0-9_!?+<>=/*-]*",
    )
    .unwrap();

    // Multi-character strings starting with single operators (violates second branch which only
    // allows single characters).
    // Covers: --, ++, ==, //, **, -a, +1, =x, etc.
    let invalid_operator_extensions = string_regex(&format!(
        "[-+=/*][a-zA-Z0-9_!?+<>=/*-]{{1,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    // Invalid comparison operator extensions (violates third branch pattern).
    // Covers: <<, >>, <a, >1, <=x, >=z, <==, >==, etc.
    let invalid_comparison_ops = string_regex(&format!(
        "[<>](=[a-zA-Z0-9_!?+<>=/*-]|[a-zA-Z0-9_!?+<>/*-]){{1,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    // Names that are too long (exceeds MAX_STRING_LEN).
    let too_long = (MAX_STRING_LEN as usize + 1..=MAX_STRING_LEN as usize + 10)
        .prop_map(|len| "a".repeat(len));

    prop_oneof![
        empty_string,
        starts_with_number,
        starts_with_invalid_symbol,
        invalid_chars_in_letter_names,
        invalid_operator_extensions,
        invalid_comparison_ops,
        too_long,
    ]
}

#[test]
fn prop_clarity_name_invalid_patterns() {
    proptest!(|(name in any_invalid_clarity_name())| {
        let result = ClarityName::try_from(name.clone());
        prop_assert!(result.is_err(), "Expected invalid name '{name}' to be rejected");
        prop_assert!(matches!(
            result.unwrap_err(),
            ClarityTypeError::InvalidClarityName(_)
        ), "Expected BadNameValue error for invalid name '{name}'");
    });
}

#[test]
fn prop_clarity_name_roundtrip() {
    proptest!(|(s in any_valid_clarity_name())| {
        let name = ClarityName::try_from(s.clone()).unwrap();
        prop_assert_eq!(name.as_str(), s);

        let mut buf = Vec::new();
        name.consensus_serialize(&mut buf).unwrap();
        prop_assert_eq!(buf.first().copied(), Some(name.len()));
        prop_assert_eq!(&buf[1..], name.as_bytes());

        let back = ClarityName::consensus_deserialize(&mut buf.as_slice()).unwrap();
        prop_assert_eq!(back, name);
    });
}

/// Generates a proptest strategy for valid contract names.
///
/// This function creates a strategy based on the `CONTRACT_NAME_REGEX_STRING` pattern
/// and includes the special `"__transient"` contract name.
///
/// The strategy generates:
/// - 90% regular contract names (letter followed by letters, digits, hyphens, or underscores)
/// - 10% the special `"__transient"` contract name
fn any_valid_contract_name() -> impl Strategy<Value = String> {
    // Ensure the regex branches match the actual validator.
    let expected_regex = format!(
        r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
        CONTRACT_MIN_NAME_LENGTH - 1,
        MAX_STRING_LEN - 1
    );
    assert_regex_unchanged(CONTRACT_NAME_REGEX_STRING.as_str(), &expected_regex);

    let regular_names = string_regex(&format!(
        "[a-zA-Z][a-zA-Z0-9_-]{{0,{}}}",
        CONTRACT_MAX_NAME_LENGTH
            .saturating_sub(1)
            .min((MAX_STRING_LEN as usize).saturating_sub(1))
    ))
    .unwrap();

    // 90% regular names, 10% the special "__transient" contract name.
    prop_oneof![
        9 => regular_names,
        1 => Just("__transient".to_string()),
    ]
}

#[test]
fn prop_contract_name_valid_patterns() {
    proptest!(|(name in any_valid_contract_name())| {
        prop_assume!(!name.is_empty());
        prop_assume!(name.len() <= MAX_STRING_LEN as usize);

        let contract_name = ContractName::try_from(name.clone())
            .unwrap_or_else(|_| panic!("Should parse valid contract name: {name}"));
        prop_assert_eq!(contract_name.as_str(), name);
    });
}

/// Generates a proptest strategy for invalid contract names.
///
/// This function creates a strategy that generates strings that should be rejected by
/// `ContractName::try_from()` validation by systematically violating the validation rules.
///
/// The strategy generates names that violate the contract name validation:
/// - Empty strings
/// - Names starting with invalid characters (numbers, symbols)
/// - Names containing invalid characters (symbols not allowed in contract names)
/// - Names that are too short or too long
/// - Names that violate length constraints
fn any_invalid_contract_name() -> impl Strategy<Value = String> {
    // Ensure the regex pattern matches the actual validator.
    let expected_regex = format!(
        r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
        CONTRACT_MIN_NAME_LENGTH - 1,
        MAX_STRING_LEN - 1
    );
    assert_regex_unchanged(CONTRACT_NAME_REGEX_STRING.as_str(), &expected_regex);

    let empty_string = Just("".to_string());

    // Names starting with numbers (violates requirement of starting with letter).
    let starts_with_number = string_regex(&format!(
        "[0-9][a-zA-Z0-9_-]{{0,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    // Names starting with invalid symbols (violates starting letter requirement).
    let starts_with_invalid_symbol = string_regex(&format!(
        "[!@#$%^&*()+=\\[\\]{{}}|\\\\:;\"'<>,.?/~`][a-zA-Z0-9_-]{{0,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    // Names starting with letters but containing invalid characters.
    let invalid_chars_in_names = string_regex(
        "[a-zA-Z][a-zA-Z0-9_-]*[!@#$%^&*()+=\\[\\]{{}}|\\\\:;\"'<>,.?/~`][a-zA-Z0-9_-]*",
    )
    .unwrap();

    // Names that are too long.
    let too_long = (MAX_STRING_LEN as usize + 1..=MAX_STRING_LEN as usize + 10)
        .prop_map(|len| "a".repeat(len));

    // Invalid variations of the __transient name (close but not exact).
    let invalid_transient_variants = prop_oneof![
        Just("_transient".to_string()),   // Single underscore.
        Just("___transient".to_string()), // Triple underscore.
        Just("__Transient".to_string()),  // Wrong case.
        Just("__TRANSIENT".to_string()),  // All caps.
        Just("__transient_".to_string()), // Extra underscore.
        Just("__transient1".to_string()), // Extra character.
    ];

    prop_oneof![
        empty_string,
        starts_with_number,
        starts_with_invalid_symbol,
        invalid_chars_in_names,
        too_long,
        invalid_transient_variants,
    ]
}

#[test]
fn prop_contract_name_invalid_patterns() {
    proptest!(|(name in any_invalid_contract_name())| {
        let result = ContractName::try_from(name.clone());
        prop_assert!(result.is_err(), "Expected invalid contract name '{name}' to be rejected");
        prop_assert!(matches!(
            result.unwrap_err(),
            ClarityTypeError::InvalidContractName(_)
        ), "Expected BadNameValue error for invalid contract name '{name}'");
    });
}

#[test]
fn prop_contract_name_roundtrip() {
    proptest!(|(s in any_valid_contract_name())| {
        let name = ContractName::try_from(s.clone()).unwrap();
        prop_assert_eq!(name.as_str(), s);

        let mut buf = Vec::with_capacity((name.len() + 1) as usize);
        name.consensus_serialize(&mut buf).unwrap();
        prop_assert_eq!(buf.first().copied(), Some(name.len()));
        prop_assert_eq!(&buf[1..], name.as_bytes());

        let back = ContractName::consensus_deserialize(&mut buf.as_slice()).unwrap();
        prop_assert_eq!(back, name);
    });
}

#[test]
fn prop_contract_name_length_bounds() {
    proptest!(|(extra in 0usize..3)| {
        let min = CONTRACT_MIN_NAME_LENGTH;
        let max = CONTRACT_MAX_NAME_LENGTH;
        let hard = MAX_STRING_LEN as usize;

        // Too short must fail to parse.
        let short = "a".repeat(min.saturating_sub(1));
        prop_assert!(ContractName::try_from(short).is_err());

        // At max parses and serializes.
        let at_len = max.min(hard);
        let at = "a".repeat(at_len);
        let name = ContractName::try_from(at).unwrap();
        let mut buf = Vec::new();
        name.consensus_serialize(&mut buf).unwrap();

        // Over contract max parses, but serialization must fail.
        if max < hard {
            let over_len = (max + 1 + extra).min(hard);
            let over = "a".repeat(over_len);
            let name = ContractName::try_from(over).unwrap();
            let mut b = Vec::new();
            prop_assert!(name.consensus_serialize(&mut b).is_err());
        }
    });
}
