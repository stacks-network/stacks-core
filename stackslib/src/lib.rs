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

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![cfg_attr(test, allow(unused_variables, unused_assignments))]

#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

#[macro_use]
extern crate serde_derive;

#[cfg(test)]
#[macro_use]
extern crate rstest;

#[cfg(test)]
#[macro_use]
extern crate rstest_reuse;

#[cfg(feature = "monitoring_prom")]
pub extern crate prometheus;

#[macro_use]
extern crate stacks_common;

#[macro_use]
pub extern crate clarity;

use std::env::consts::{ARCH, OS};

use stacks_common::versions::{GIT_COMMIT, GIT_TREE_CLEAN, STACKS_NODE_VERSION};
pub use stacks_common::{address, codec, types, util};

#[macro_use]
pub mod util_lib;

#[macro_use]
pub mod net;

pub extern crate libstackerdb;

#[macro_use]
pub mod chainstate;

pub mod burnchains;
/// A high level library for interacting with the Clarity vm
pub mod clarity_vm;
pub mod config;
pub mod core;
pub mod cost_estimates;
pub mod deps;
pub mod monitoring;

#[cfg(test)]
/// Utilities and strategy definitions for proptesting
///  common stackslib arguments
pub mod proptest_utils;

// set via _compile-time_ envars
const GIT_BRANCH_ENV: Option<&'static str> = option_env!("GIT_BRANCH");
const GIT_COMMIT_ENV: Option<&'static str> = option_env!("GIT_COMMIT");
const GIT_TREE_CLEAN_ENV: Option<&'static str> = option_env!("GIT_TREE_CLEAN");

#[cfg(debug_assertions)]
const BUILD_TYPE: &str = "debug";
#[cfg(not(debug_assertions))]
const BUILD_TYPE: &str = "release";

/// Returns a version string with package name
pub fn version_string(pkg_name: &str, pkg_version: Option<&str>) -> String {
    let pkg_version = pkg_version.unwrap_or(STACKS_NODE_VERSION);
    inner_version_string(Some(pkg_name), pkg_version)
}

/// Returns a version string without package name
pub fn version_only_string(pkg_version: &str) -> String {
    inner_version_string(None, pkg_version)
}

/// Returns a formatted version string given a optional package name and a version
fn inner_version_string(pkg_name: Option<&str>, pkg_version: &str) -> String {
    let git_commit = GIT_COMMIT_ENV.unwrap_or_else(|| GIT_COMMIT.unwrap_or(""));
    let git_tree_clean = GIT_TREE_CLEAN_ENV.unwrap_or_else(|| GIT_TREE_CLEAN.unwrap_or(""));
    let suffix = format!("({git_commit}{git_tree_clean}, {BUILD_TYPE} build, {OS} [{ARCH}])");
    match pkg_name {
        Some(name) => format!("{name} {pkg_version} {suffix}"),
        None => format!("{pkg_version} {suffix}"),
    }
}

#[cfg(test)]
mod lib_tests {
    use stacks_common::versions::STACKS_NODE_VERSION;

    use super::*;

    fn expected_version_named(pkg_name: &str, pkg_version: &str) -> String {
        let git_commit = GIT_COMMIT_ENV.unwrap_or_else(|| GIT_COMMIT.unwrap_or(""));
        let git_tree_clean = GIT_TREE_CLEAN_ENV.unwrap_or_else(|| GIT_TREE_CLEAN.unwrap_or(""));
        format!(
            "{pkg_name} {pkg_version} ({git_commit}{git_tree_clean}, {BUILD_TYPE} build, {OS} [{ARCH}])"
        )
    }

    fn expected_version_only(pkg_version: &str) -> String {
        let git_commit = GIT_COMMIT_ENV.unwrap_or_else(|| GIT_COMMIT.unwrap_or(""));
        let git_tree_clean = GIT_TREE_CLEAN_ENV.unwrap_or_else(|| GIT_TREE_CLEAN.unwrap_or(""));
        format!("{pkg_version} ({git_commit}{git_tree_clean}, {BUILD_TYPE} build, {OS} [{ARCH}])")
    }

    #[test]
    fn test_version_named_string_explicit_version() {
        let version = version_string("mypackage", Some("1.2.3"));
        assert_eq!(expected_version_named("mypackage", "1.2.3"), version);
    }

    #[test]
    fn test_version_named_string_default_version() {
        let version = version_string("mypackage", None);
        assert_eq!(
            expected_version_named("mypackage", STACKS_NODE_VERSION),
            version
        );
    }

    #[test]
    fn test_version_only_string() {
        let version = version_only_string("1.2.3");
        assert_eq!(expected_version_only("1.2.3"), version);
    }
}
