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

//! The Clarity runtime kernel: state and services shared by every Clarity
//! execution engine, regardless of language version.
//!
//! Code in this crate is consensus-critical and shared by all engines
//! simultaneously — it must remain additive-only once published. Engine
//! crates (parsers, type checkers, evaluators) depend on this crate; this
//! crate never depends on an engine.

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate stacks_common;

pub mod costs;
pub mod events;

pub use clarity_types;
