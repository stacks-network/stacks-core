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

//! Lightweight serialization component for Clarity values
//!
//! This crate provides core serialization and deserialization functionality 
//! for Clarity Value types without the heavy dependencies of the full Clarity VM.

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![cfg_attr(test, allow(unused_variables, unused_assignments))]

#[macro_use]
extern crate serde_derive;

extern crate serde_json;

#[cfg(any(test, feature = "testing"))]
#[macro_use]
extern crate rstest;

#[cfg(any(test, feature = "testing"))]
#[macro_use]
pub extern crate rstest_reuse;

extern crate stacks_common;

pub use stacks_common::{
    codec, consts, impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_message_codec,
    impl_byte_array_serde, util,
};

/// Core serialization traits and types
pub mod traits;

/// Core Clarity value types for serialization
pub mod types;

/// Serialization and deserialization implementations
pub mod serialization;

/// Basic representations and identifiers
pub mod representations;

/// Error types for serialization operations
pub mod errors;

// Re-export commonly used types
pub use traits::{ClaritySerializable, ClarityDeserializable};
pub use types::{Value, TypeSignature, PrincipalData};
pub use errors::SerializationError;
pub use serialization::{to_hex, from_hex};
pub use representations::{ClarityName, ContractName, QualifiedContractIdentifier};