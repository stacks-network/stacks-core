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

use std::process::Command;

fn main() {
    // Build profile name (e.g. "debug", "release", "release-lite").
    let profile = std::env::var("PROFILE").unwrap_or_default();
    println!("cargo:rustc-env=STACKS_BENCH_PROFILE={profile}");

    // Optimisation level (0–3, "s", "z").
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_default();
    println!("cargo:rustc-env=STACKS_BENCH_OPT_LEVEL={opt_level}");

    // Target triple (e.g. "aarch64-apple-darwin").
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=STACKS_BENCH_TARGET={target}");

    // Whether debug_assertions are enabled (mirrors cfg!(debug_assertions) at
    // build-script time via the CARGO_CFG_ prefix).
    let debug_assertions = std::env::var("CARGO_CFG_DEBUG_ASSERTIONS").is_ok();
    println!("cargo:rustc-env=STACKS_BENCH_DEBUG_ASSERTIONS={debug_assertions}");

    // overflow_checks: cfg!(overflow_checks) is unstable, but Cargo exposes
    // CARGO_CFG_OVERFLOW_CHECKS when the setting is active.
    let overflow_checks = std::env::var("CARGO_CFG_OVERFLOW_CHECKS").is_ok();
    println!("cargo:rustc-env=STACKS_BENCH_OVERFLOW_CHECKS={overflow_checks}");

    // rustc version string.
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=STACKS_BENCH_RUSTC_VERSION={rustc_version}");
}
