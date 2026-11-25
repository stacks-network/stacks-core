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

//! Render values as Clarity source literals.

use clarity_types::Value;
use clarity_types::types::{CharType, SequenceData, UTF8Data};
use stacks_common::util::hash::to_hex;

/// A `0x`-prefixed buffer literal.
pub fn buff_literal(bytes: &[u8]) -> String {
    format!("0x{}", to_hex(bytes))
}

/// A `(list ...)` literal of already-rendered items; `(list)` when empty.
pub fn list_literal<I>(items: I) -> String
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut literal = String::from("(list");
    for item in items {
        literal.push(' ');
        literal.push_str(item.as_ref());
    }
    literal.push(')');
    literal
}

/// A `"..."` ASCII string literal, escaping `"`, `\` and the control characters Clarity has
/// escapes for.
pub fn ascii_string_literal(bytes: &[u8]) -> String {
    let mut literal = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' => literal.push_str("\\\""),
            b'\\' => literal.push_str("\\\\"),
            b'\n' => literal.push_str("\\n"),
            b'\t' => literal.push_str("\\t"),
            b'\r' => literal.push_str("\\r"),
            b'\0' => literal.push_str("\\0"),
            _ => literal.push(char::from(byte)),
        }
    }
    literal.push('"');
    literal
}

/// A `u"..."` UTF-8 string literal: printable ASCII as-is (with `"` and `\` escaped), every
/// other character as `\u{...}`.
pub fn utf8_chars_literal<I: IntoIterator<Item = char>>(chars: I) -> String {
    let mut literal = String::from("u\"");
    for ch in chars {
        match ch {
            '"' => literal.push_str("\\\""),
            '\\' => literal.push_str("\\\\"),
            ' '..='~' => literal.push(ch),
            _ => literal.push_str(&format!("\\u{{{:X}}}", u32::from(ch))),
        }
    }
    literal.push('"');
    literal
}

/// A `u"..."` literal for Clarity UTF-8 string data.
pub fn utf8_string_literal(data: &UTF8Data) -> String {
    utf8_chars_literal(data.data.iter().map(|bytes| {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|s| s.chars().next())
            .expect("UTF-8 data should hold one scalar per entry")
    }))
}

/// A Clarity source literal that evaluates to `value`.
pub fn value_to_clarity_literal(value: &Value) -> String {
    match value {
        Value::Sequence(SequenceData::List(list_data)) => {
            list_literal(list_data.data.iter().map(value_to_clarity_literal))
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(data))) => {
            ascii_string_literal(&data.data)
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(data))) => utf8_string_literal(data),
        Value::Optional(optional) => match optional.data.as_deref() {
            Some(inner) => format!("(some {})", value_to_clarity_literal(inner)),
            None => "none".to_string(),
        },
        Value::Response(response) => {
            let inner = value_to_clarity_literal(response.data.as_ref());
            if response.committed {
                format!("(ok {inner})")
            } else {
                format!("(err {inner})")
            }
        }
        Value::Principal(principal) => format!("'{principal}"),
        Value::Tuple(tuple) => {
            let mut literal = String::from("(tuple");
            for (name, field) in tuple.data_map.iter() {
                literal.push_str(&format!(" ({name} {})", value_to_clarity_literal(field)));
            }
            literal.push(')');
            literal
        }
        _ => format!("{value}"),
    }
}
