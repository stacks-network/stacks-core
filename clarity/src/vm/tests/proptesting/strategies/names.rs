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

//! Clarity names and contract names.

use proptest::prelude::*;
use proptest::string::string_regex;

use crate::vm::representations::{
    CLARITY_NAME_REGEX_STRING, CONTRACT_MAX_NAME_LENGTH, CONTRACT_MIN_NAME_LENGTH,
    CONTRACT_NAME_REGEX_STRING, MAX_STRING_LEN,
};
use crate::vm::{ClarityName, ContractName};

/// Fails when a validator regex no longer matches the grammar a strategy was written for.
pub fn assert_regex_unchanged(actual: &str, expected: &str) {
    assert_eq!(actual, expected, "Regex has changed");
}

/// Every form `ClarityName` accepts: letter-led names of up to `MAX_STRING_LEN` characters, the
/// arithmetic operators (`-`, `+`, `=`, `/`, `*`) and the comparisons (`<`, `>`, `<=`, `>=`).
pub fn clarity_name_string_strategy() -> impl Strategy<Value = String> {
    assert_regex_unchanged(
        CLARITY_NAME_REGEX_STRING.as_str(),
        "^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$",
    );

    let letter_names = string_regex(&format!(
        "[a-zA-Z][a-zA-Z0-9_!?+<>=/*-]{{0,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();
    let single_ops = prop::sample::select(vec!["-", "+", "=", "/", "*"]).prop_map(String::from);
    let comparison_ops = prop::sample::select(vec!["<", ">", "<=", ">="]).prop_map(String::from);

    prop_oneof![letter_names, single_ops, comparison_ops]
}

/// Whether `name` lexes as a `uint` literal (`u` followed by a digit) rather than a name, so it
/// cannot be written in Clarity source even though the name grammar accepts it.
fn reads_as_uint_literal(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next() == Some('u') && chars.next().is_some_and(|c| c.is_ascii_digit())
}

/// Short letter-led Clarity names of letters, digits and hyphens, which can be written as tuple
/// fields anywhere in Clarity source, including type signatures.
pub fn field_name_strategy() -> impl Strategy<Value = ClarityName> {
    string_regex("[a-zA-Z][a-zA-Z0-9-]{0,15}")
        .unwrap()
        .prop_filter("must not read as a uint literal", |name| {
            !reads_as_uint_literal(name)
        })
        .prop_map(|name| ClarityName::try_from(name).expect("generated from the name grammar"))
}

/// Contract names of up to `CONTRACT_MAX_NAME_LENGTH` characters: a letter followed by letters,
/// digits, `-` or `_`. Excludes the special `__transient` name.
pub fn contract_name_string_strategy() -> impl Strategy<Value = String> {
    assert_regex_unchanged(
        CONTRACT_NAME_REGEX_STRING.as_str(),
        &format!(
            r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
            CONTRACT_MIN_NAME_LENGTH - 1,
            MAX_STRING_LEN - 1
        ),
    );

    string_regex(&format!(
        "[a-zA-Z][a-zA-Z0-9_-]{{0,{}}}",
        CONTRACT_MAX_NAME_LENGTH
            .saturating_sub(1)
            .min((MAX_STRING_LEN as usize).saturating_sub(1))
    ))
    .unwrap()
}

/// Valid contract names; see [`contract_name_string_strategy`].
pub fn contract_name_strategy() -> impl Strategy<Value = ContractName> {
    contract_name_string_strategy()
        .prop_map(|name| ContractName::try_from(name).expect("generated from the name grammar"))
}

/// Contract names that can be written in Clarity source: [`contract_name_strategy`] without the
/// names that read as `uint` literals.
pub fn writable_contract_name_strategy() -> impl Strategy<Value = ContractName> {
    contract_name_string_strategy()
        .prop_filter("must not read as a uint literal", |name| {
            !reads_as_uint_literal(name)
        })
        .prop_map(|name| ContractName::try_from(name).expect("generated from the name grammar"))
}
