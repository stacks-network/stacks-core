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

//! Characters for Clarity string values. Both sets render as source literals with
//! [`crate::vm::tests::proptesting::literals`].

use proptest::prelude::*;

/// Printable ASCII bytes (`0x20..=0x7E`), which `string-ascii` values accept.
///
/// Sampled from the set rather than filtered from all bytes, so long strings add no rejects.
pub fn printable_ascii_byte_strategy() -> impl Strategy<Value = u8> {
    prop::sample::select((0x20u8..=0x7E).collect::<Vec<_>>())
}

/// Characters for `string-utf8` values: printable ASCII, non-control BMP characters and emoji.
pub fn utf8_char_strategy() -> impl Strategy<Value = char> {
    prop_oneof![
        printable_ascii_byte_strategy().prop_map(char::from),
        (0xA1u32..=0xD7FF).prop_filter_map("valid BMP char", |n| {
            char::from_u32(n).filter(|c| !c.is_control())
        }),
        (0x1F300u32..=0x1F6FF).prop_filter_map("valid emoji", char::from_u32),
    ]
}
