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

//! Contract names.

use clarity_types::ContractName;
use proptest::prelude::*;
use proptest::string::string_regex;

/// A strategy that generates valid Clarity contract names.
pub fn contract_name_strategy() -> BoxedStrategy<ContractName> {
    prop_oneof![
        string_regex("[a-tv-z][a-z0-9-?!]{0,39}").unwrap(),
        string_regex("u[a-z-?!][a-z0-9-?!]{0,38}").unwrap(),
    ]
    .prop_filter_map("Invalid contract name", |name| {
        ContractName::try_from(name).ok()
    })
    .boxed()
}
