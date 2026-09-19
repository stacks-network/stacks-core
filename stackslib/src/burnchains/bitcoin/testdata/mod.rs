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

//! Bitcoin header fixtures shared by offline tests.

use stacks_common::deps_common::bitcoin::blockdata::block::BlockHeader;
use stacks_common::deps_common::bitcoin::network::serialize;
use stacks_common::util::hash::hex_bytes;

/// Decode public signet headers in height order, starting with genesis.
pub fn signet_headers() -> Vec<BlockHeader> {
    include_str!("signet-headers-0-4033.hex")
        .lines()
        .enumerate()
        .map(|(height, line)| {
            assert_eq!(line.len(), 160, "Invalid header length at height {height}");
            let bytes = hex_bytes(line).expect("Fixture headers must be hexadecimal");
            serialize::deserialize(&bytes).expect("Fixture headers must decode as Bitcoin headers")
        })
        .collect()
}
