// Copyright (C) 2025 Stacks Open Internet Foundation
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
mod errors;
mod representations;
mod types;

use crate::{BUILD_TYPE, version_string};

#[test]
fn test_version_string_basic_no_env() {
    let version = version_string("test-package", "1.0.0");

    assert_eq!(
        version,
        format!(
            "test-package 1.0.0 (:, {BUILD_TYPE} build, {} [{}])",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    );
}
