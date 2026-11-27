// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! The Stacks chain ABI for Wasm contracts, as data and codecs.
//!
//! The chain ABI is the contract between any compiler and the chain: the
//! module format, the host interface, and the encodings, limits and outcomes
//! the chain enforces. This crate holds the parts of it that are definition
//! rather than execution, so the host, the node, compilers and tools all
//! derive from one place. It has no node dependency and builds for the
//! browser with the `wasm-web` feature.
//!
//! Section numbers in this crate's documentation ("ABI 2.1") refer to the
//! chain ABI specification.
//!
//! - [`names`]: the grammar of function, token, event and contract names
//!   (ABI 2.1).
//! - [`principals`]: the one canonical encoding of a principal (ABI 2.2).
//! - [`limits`]: the limits fixed by an ABI version (ABI 9.3).
//! - [`classes`]: the classes of runtime error a receipt names (ABI 10.2).
//! - [`status`]: the status codes host functions return (ABI 6.2).

pub mod classes;
pub mod limits;
pub mod names;
pub mod principals;
pub mod status;

#[cfg(test)]
mod tests;
