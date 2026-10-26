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

use crate::versions::{CUSTOM_VERSION_STRING, GIT_COMMIT, STACKS_NODE_VERSION};

/// Return the compile-time metadata labels for the build-info metric.
pub fn build_info_labels(version: String) -> HashMap<String, String> {
    HashMap::from([
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
    ])
}
