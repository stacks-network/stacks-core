// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::collections::HashMap;

use prometheus::{opts, register_int_gauge, IntGauge};

use crate::versions::{CUSTOM_VERSION_STRING, GIT_COMMIT, STACKS_NODE_VERSION};

/// Register one build-info series with value 1. Call once per process.
pub fn register_build_info(version: String) -> IntGauge {
    let labels = HashMap::from([
        ("version".into(), version),
        (
            "stacks_node_version".into(),
            option_env!("STACKS_NODE_VERSION")
                .unwrap_or(STACKS_NODE_VERSION)
                .into(),
        ),
        ("git_commit".into(), GIT_COMMIT.unwrap_or("").into()),
        (
            "custom_version".into(),
            CUSTOM_VERSION_STRING.unwrap_or("").into(),
        ),
    ]);
    let metric = register_int_gauge!(opts!(
        "stacks_build_info",
        "Build information for the Stacks process."
    )
    .const_labels(labels))
    .unwrap();
    metric.set(1);
    metric
}
