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

use std::thread;
use std::time::Duration;

use crate::versions::{CUSTOM_VERSION_STRING, GIT_COMMIT, STACKS_NODE_VERSION};

/// Log build metadata immediately and every minute for the lifetime of the process.
pub fn start_build_info_logging(version: String) {
    thread::Builder::new()
        .name("build-info".into())
        .spawn(move || loop {
            info!("Build information";
                "version" => version.as_str(),
                "stacks_node_version" => option_env!("STACKS_NODE_VERSION").unwrap_or(STACKS_NODE_VERSION),
                "git_commit" => GIT_COMMIT,
                "custom_version" => CUSTOM_VERSION_STRING
            );
            thread::sleep(Duration::from_secs(60));
        })
        .expect("FATAL: failed to start build information logging thread");
}
