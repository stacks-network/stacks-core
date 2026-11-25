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

/// Convert a Clarity `Value` into a Clarity literal string.
pub fn value_to_clarity_literal(value: &Value) -> String {
    match value {
        Value::Sequence(SequenceData::List(list_data)) => {
            let items: Vec<_> = list_data
                .data
                .iter()
                .map(value_to_clarity_literal)
                .collect();
            if items.is_empty() {
                "(list)".to_string()
            } else {
                format!("(list {})", items.join(" "))
            }
        }
        Value::Sequence(SequenceData::String(CharType::ASCII(data))) => format!("{data}"),
        Value::Sequence(SequenceData::String(CharType::UTF8(data))) => utf8_string_literal(data),
        Value::Optional(optional) => match optional.data.as_deref() {
            Some(inner) => format!("(some {})", value_to_clarity_literal(inner)),
            None => "none".to_string(),
        },
        Value::Response(response) => {
            let inner = value_to_clarity_literal(response.data.as_ref());
            if response.committed {
                format!("(ok {})", inner)
            } else {
                format!("(err {})", inner)
            }
        }
        Value::Principal(principal) => format!("'{}", principal),
        Value::Tuple(tuple) => {
            let mut literal = String::from("(tuple");
            for (name, field) in tuple.data_map.iter() {
                literal.push(' ');
                literal.push('(');
                literal.push_str(&name.to_string());
                literal.push(' ');
                literal.push_str(&value_to_clarity_literal(field));
                literal.push(')');
            }
            literal.push(')');
            literal
        }
        _ => format!("{value}"),
    }
}

/// Convert UTF-8 data into a Clarity UTF-8 string literal.
pub fn utf8_string_literal(data: &UTF8Data) -> String {
    let mut literal = String::from("u\"");
    for bytes in &data.data {
        if bytes.len() == 1 {
            for escaped in std::ascii::escape_default(bytes[0]) {
                literal.push(escaped as char);
            }
        } else {
            let ch = std::str::from_utf8(bytes)
                .expect("UTF-8 data should decode to a scalar value")
                .chars()
                .next()
                .expect("UTF-8 data should contain at least one scalar");
            literal.push_str(&format!("\\u{{{:X}}}", ch as u32));
        }
    }
    literal.push('"');
    literal
}
