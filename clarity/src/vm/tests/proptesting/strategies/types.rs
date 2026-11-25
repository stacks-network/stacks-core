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

//! Clarity type signatures as source strings.

use proptest::prelude::*;

/// Non-tuple Clarity type signatures for `consensus-buff?` tests.
fn consensus_buff_leaf_type_strategy() -> BoxedStrategy<String> {
    let len_range = 1u32..=128;

    prop_oneof![
        Just("int".to_string()),
        Just("uint".to_string()),
        Just("bool".to_string()),
        Just("principal".to_string()),
        len_range.clone().prop_map(|n| format!("(buff {n})")),
        len_range
            .clone()
            .prop_map(|n| format!("(string-ascii {n})")),
        len_range.clone().prop_map(|n| format!("(string-utf8 {n})")),
        Just("(optional int)".to_string()),
        len_range.prop_map(|n| format!("(list {n} int)")),
        Just("(response int int)".to_string()),
    ]
    .boxed()
}

/// A strategy that generates valid Clarity type signature strings suitable for
/// `from-consensus-buff?`. Includes scalars, parameterized types, and tuples.
pub fn consensus_buff_type_strategy() -> BoxedStrategy<String> {
    let leaf = consensus_buff_leaf_type_strategy();

    prop_oneof![
        leaf.clone(),
        proptest::collection::vec(leaf, 1..=4).prop_map(|types| {
            let fields: Vec<_> = types
                .iter()
                .enumerate()
                .map(|(i, t)| format!("f-{i}: {t}"))
                .collect();
            format!("{{ {} }}", fields.join(", "))
        }),
    ]
    .boxed()
}
