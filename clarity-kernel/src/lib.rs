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

// Match the lint posture of the `clarity` crate this code was extracted
// from (e.g. `STXBalance`'s lowercase associated constants).
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![cfg_attr(test, allow(unused_variables, unused_assignments))]

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

// The logging macros re-exported by `stacks_common` (`error!`, `warn!`,
// `trace!`, ...) expand to `slog` macro invocations, so `slog`'s macros must
// be in scope crate-wide even though nothing names them directly.
#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

pub mod analysis;
pub mod assets;
pub mod contract_interface;
pub mod costs;
pub mod database;
pub mod diagnostic;
pub mod engine;
pub mod errors;
pub mod events;
pub mod signatures;

pub use clarity_types;
