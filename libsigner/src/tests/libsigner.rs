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

use stacks_common::versions::STACKS_SIGNER_VERSION;

use crate::{VERSION_ONLY_STRING, VERSION_STRING};

#[test]
fn test_version_named_string() {
    assert!(VERSION_STRING.starts_with(&format!("stacks-signer {STACKS_SIGNER_VERSION}")));
}

#[test]
fn test_version_only_string() {
    assert!(VERSION_ONLY_STRING.starts_with(STACKS_SIGNER_VERSION));
}
