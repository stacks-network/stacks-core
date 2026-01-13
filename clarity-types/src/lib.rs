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
#[doc = include_str!("../README.md")]
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate stacks_common;

pub use stacks_common::{
    codec, consts, impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_message_codec,
    impl_byte_array_serde, types as stacks_types, util,
};

pub mod diagnostic;
pub mod errors;
pub mod execution_cost;
pub mod representations;
pub mod token;
pub mod types;

pub use errors::{ClarityTypeError, IncomparableError};
pub use representations::{ClarityName, ContractName};
pub use types::Value;

pub const MAX_CALL_STACK_DEPTH: usize = 64;

#[cfg(test)]
pub mod tests;

// set via _compile-time_ envars
const GIT_BRANCH: Option<&'static str> = option_env!("GIT_BRANCH");
const GIT_COMMIT: Option<&'static str> = option_env!("GIT_COMMIT");
const GIT_TREE_CLEAN: Option<&'static str> = option_env!("GIT_TREE_CLEAN");

#[cfg(debug_assertions)]
const BUILD_TYPE: &str = "debug";
#[cfg(not(debug_assertions))]
const BUILD_TYPE: &str = "release";

pub fn version_string(pkg_name: &str, pkg_version: &str) -> String {
    let git_branch = GIT_BRANCH.unwrap_or("");
    let git_commit = GIT_COMMIT.unwrap_or("");
    let git_tree_clean = GIT_TREE_CLEAN.unwrap_or("");

    format!(
        "{pkg_name} {pkg_version} ({git_branch}:{git_commit}{git_tree_clean}, {BUILD_TYPE} build, {} [{}])",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}
