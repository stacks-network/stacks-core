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

//! Clarity source snippets for simple values.

use clarity_types::types::{
    MAX_TO_ASCII_BUFFER_LEN, MAX_UTF8_VALUE_SIZE, MAX_VALUE_SIZE, QualifiedContractIdentifier,
};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::string::string_regex;
use stacks_common::util::hash::to_hex;

use super::names::contract_name_strategy;
use super::principals::standard_principal_strategy;

const UTF8_SIMPLE_ESCAPES: [&str; 6] = ["\\\"", "\\\\", "\\n", "\\t", "\\r", "\\0"];

/// A strategy that generates `uint` snippets
pub fn uint_snippet_strategy() -> impl Strategy<Value = String> {
    any::<u128>().prop_map(|value| format!("u{value}"))
}

/// A strategy that generates `int` snippets
pub fn int_snippet_strategy() -> impl Strategy<Value = String> {
    any::<i128>().prop_map(|value| value.to_string())
}

/// A strategy that generates `bool` snippets
pub fn bool_snippet_strategy() -> impl Strategy<Value = String> {
    any::<bool>().prop_map(|value| value.to_string())
}

/// A strategy that generates standard `principal` snippets
pub fn standard_principal_snippet_strategy() -> impl Strategy<Value = String> {
    standard_principal_strategy().prop_map(|principal| format!("'{principal}"))
}

/// A strategy that generates contract `principal` snippets
pub fn contract_principal_snippet_strategy() -> impl Strategy<Value = String> {
    (standard_principal_strategy(), contract_name_strategy()).prop_map(|(issuer, name)| {
        let contract_id = QualifiedContractIdentifier::new(issuer, name);
        format!("'{contract_id}")
    })
}

/// A strategy that generates `principal` snippets, either standard or contract
pub fn principal_snippet_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        standard_principal_snippet_strategy().boxed(),
        contract_principal_snippet_strategy().boxed(),
    ]
}

/// A strategy that generates `buff` snippets
pub fn buffer_snippet_strategy() -> impl Strategy<Value = String> {
    vec(any::<u8>(), 0..MAX_VALUE_SIZE as usize).prop_map(|bytes| {
        let hex = to_hex(&bytes);
        format!("0x{hex}")
    })
}

pub fn to_ascii_buffer_snippet_strategy() -> impl Strategy<Value = String> {
    vec(any::<u8>(), 0..=MAX_TO_ASCII_BUFFER_LEN as usize).prop_map(|bytes| {
        let hex = to_hex(&bytes);
        format!("0x{hex}")
    })
}

/// A strategy that generates ASCII snippets
pub fn ascii_string_snippet_strategy() -> impl Strategy<Value = String> {
    string_regex(&format!(
        r#"(?x)
        "                              # opening quote
        (?:                            # body: zero or more of...
          [\x20\x21\x23-\x5B\x5D-\x7E] #   printable ASCII except " and \
          | \\[\\"ntr]                 #   valid escape sequences
        ){{0,{}}}                      # up to MAX_VALUE_SIZE
        "                              # closing quote
        "#,
        MAX_VALUE_SIZE
    ))
    .unwrap()
}

/// A strategy that generates UTF8 snippets that only contain ASCII characters
pub fn utf8_string_ascii_only_snippet_strategy() -> impl Strategy<Value = String> {
    string_regex(&format!(
        r#"(?x)
        u"                             # opening quote
        (?:                            # body: zero or more of...
          [\x20\x21\x23-\x5B\x5D-\x7E] #   printable ASCII except " and \
          | \\[\\"ntr]                 #   valid escape sequences
        ){{0,{}}}                      # up to MAX_UTF8_VALUE_SIZE
        "                              # closing quote
        "#,
        MAX_UTF8_VALUE_SIZE
    ))
    .unwrap()
}

/// A strategy that generates UTF-8 string snippets
pub fn utf8_string_snippet_strategy() -> impl Strategy<Value = String> {
    let ascii_chars: Vec<char> = (0x20u8..=0x7E)
        .filter(|byte| *byte != b'"' && *byte != b'\\')
        .map(|byte| byte as char)
        .collect();

    let ascii_char_segment = prop::sample::select(ascii_chars).prop_map(|ch| ch.to_string());

    let simple_escape_segment =
        prop::sample::select(&UTF8_SIMPLE_ESCAPES).prop_map(|escape| escape.to_string());

    let unicode_escape_segment =
        proptest::char::any().prop_map(|ch| format!("\\u{{{:X}}}", ch as u32));

    vec(
        prop_oneof![
            ascii_char_segment,
            simple_escape_segment,
            unicode_escape_segment,
        ],
        0..=MAX_UTF8_VALUE_SIZE as usize,
    )
    .prop_map(|segments: Vec<String>| format!("u\"{}\"", segments.concat()))
}

/// A strategy that generates simple Clarity value snippets
/// including uint, int, bool, principal, buffer, and string types.
pub fn simple_value_snippet_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        uint_snippet_strategy().boxed(),
        int_snippet_strategy().boxed(),
        bool_snippet_strategy().boxed(),
        principal_snippet_strategy().boxed(),
        buffer_snippet_strategy().boxed(),
        ascii_string_snippet_strategy().boxed(),
        utf8_string_snippet_strategy().boxed(),
    ]
}
