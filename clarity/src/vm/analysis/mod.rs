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

pub mod errors;

#[cfg(feature = "vm")]
pub mod analysis_db;
#[cfg(feature = "vm")]
pub mod arithmetic_checker;
#[cfg(feature = "vm")]
pub mod contract_interface_builder;
#[cfg(feature = "vm")]
pub mod read_only_checker;
#[cfg(feature = "vm")]
pub mod trait_checker;
#[cfg(feature = "vm")]
pub mod type_checker;
#[cfg(feature = "vm")]
pub mod types;

#[cfg(feature = "vm")]
pub mod engine;
#[cfg(feature = "vm")]
pub use engine::*;

#[cfg(test)]
mod tests;
