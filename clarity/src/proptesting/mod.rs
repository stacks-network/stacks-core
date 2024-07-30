// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use proptest::prop_oneof;
use proptest::strategy::{Just, Strategy, ValueTree};
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use rand::Rng;
use stacks_common::types::StacksHashMap as HashMap;

pub mod callables;
pub mod contracts;
pub mod representations;
pub mod types;
pub mod values;

pub use callables::*;
pub use contracts::*;
pub use representations::*;
pub use types::*;
pub use values::*;

use crate::vm::ClarityVersion;

/// Returns a [`Strategy`] for randomly generating a [`ClarityVersion`] instance.
pub fn clarity_version() -> impl Strategy<Value = ClarityVersion> {
    prop_oneof![
        Just(crate::vm::ClarityVersion::Clarity1),
        Just(crate::vm::ClarityVersion::Clarity2),
    ]
}
