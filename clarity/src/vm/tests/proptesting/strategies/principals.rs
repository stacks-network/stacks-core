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

//! Standard principals.

use clarity_types::types::StandardPrincipalData;
use proptest::array::uniform20;
use proptest::prelude::*;

/// A strategy that generates standard `principal`s
/// The version is restricted to those currently valid: 20, 21, 22, and 26
pub fn standard_principal_strategy() -> impl Strategy<Value = StandardPrincipalData> {
    (
        prop::sample::select(&[20u8, 21u8, 22u8, 26u8]),
        uniform20(any::<u8>()),
    )
        .prop_filter_map("Invalid standard principal", |(version, bytes)| {
            StandardPrincipalData::new(version, bytes).ok()
        })
}
