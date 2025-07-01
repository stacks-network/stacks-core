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
#![allow(clippy::result_large_err)]

pub mod analysis;
#[macro_use]
pub mod costs;
pub mod ast;
pub mod diagnostic;
pub mod errors;
pub mod representations;
pub mod types;
pub mod version;

#[cfg(any(test, feature = "testing"))]
pub mod test_util;
#[cfg(any(test, feature = "testing"))]
pub mod tests;

#[cfg(feature = "vm")]
pub mod callables;
#[cfg(feature = "vm")]
pub mod clarity;
#[cfg(feature = "vm")]
pub mod contexts;
#[cfg(feature = "vm")]
pub mod contracts;
#[cfg(feature = "vm")]
pub mod coverage;
#[cfg(feature = "vm")]
pub mod database;
#[cfg(feature = "vm")]
pub mod docs;
#[cfg(feature = "vm")]
pub mod events;
#[cfg(feature = "vm")]
pub mod functions;
#[cfg(feature = "rusqlite")]
pub mod tooling;
#[cfg(feature = "vm")]
pub mod variables;

#[cfg(feature = "vm")]
pub mod core;
#[cfg(feature = "vm")]
pub use core::*;

pub use self::representations::{
    ClarityName, ContractName, SymbolicExpression, SymbolicExpressionType,
};
pub use self::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TypeSignature, Value,
};
pub use self::version::ClarityVersion;

pub const MAX_CALL_STACK_DEPTH: usize = 64;
