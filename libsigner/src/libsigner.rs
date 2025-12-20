// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

#![forbid(missing_docs)]
/*!
# libsigner: a library for creating and operating a Stacks Nakamato compliant signer.

Usage documentation can be found in the [README](https://github.com/stacks-network/stacks-blockchain/libsigner/README.md).
*/

#![allow(dead_code)]
#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate stacks_common;
extern crate clarity;
extern crate libc;

#[cfg(test)]
mod tests;

mod error;
mod events;
mod http;
mod runloop;
mod session;
mod signer_set;
/// v0 signer related code
pub mod v0;

use std::cmp::Eq;
use std::fmt::Debug;
use std::hash::Hash;

use blockstack_lib::version_string;
use clarity::codec::StacksMessageCodec;
use clarity::vm::types::QualifiedContractIdentifier;
use std::sync::LazyLock;

/// The version string for the signer
pub static VERSION_STRING: LazyLock<String> = LazyLock::new(|| {
    let pkg_version = option_env!("STACKS_NODE_VERSION").or(Some(STACKS_SIGNER_VERSION));
    // NOTE: we don't include the package name here because clap (used in the CLI)
    // already prepends the binary name to the version string.
    version_string("", pkg_version).trim_start().to_string()
});

#[test]
fn test_version_string() {
    assert!(VERSION_STRING.starts_with(STACKS_SIGNER_VERSION));
}
