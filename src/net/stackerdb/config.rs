// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use crate::net::stackerdb::StackerDBConfig;

/// Minimum chunk size for FROST is 97 + T * 33, where T = 3000
const MIN_CHUNK_SIZE: u64 = 97 + 3000 * 33;

const CHUNK_SIZE: u64 = MIN_CHUNK_SIZE * 2;
const WRITE_FREQ: u64 = 60;
const MAX_WRITES: u32 = 1024;
const NUM_NEIGHBORS: usize = 8;

impl StackerDBConfig {
    pub fn noop() -> StackerDBConfig {
        StackerDBConfig {
            chunk_size: u64::MAX,
            write_freq: 0,
            max_writes: u32::MAX,
            hint_peers: vec![],
            num_neighbors: NUM_NEIGHBORS,
            num_chunks: 4096,
        }
    }

    pub fn default_pox() -> StackerDBConfig {
        StackerDBConfig {
            chunk_size: CHUNK_SIZE,
            write_freq: WRITE_FREQ,
            max_writes: MAX_WRITES,
            hint_peers: vec![],
            num_neighbors: NUM_NEIGHBORS,
            num_chunks: 4096,
        }
    }

    #[cfg(test)]
    pub fn one_chunk() -> StackerDBConfig {
        StackerDBConfig {
            chunk_size: CHUNK_SIZE,
            write_freq: 0,
            max_writes: u32::MAX,
            hint_peers: vec![],
            num_neighbors: NUM_NEIGHBORS,
            num_chunks: 1,
        }
    }

    #[cfg(test)]
    pub fn ten_chunks() -> StackerDBConfig {
        StackerDBConfig {
            chunk_size: CHUNK_SIZE,
            write_freq: 0,
            max_writes: u32::MAX,
            hint_peers: vec![],
            num_neighbors: NUM_NEIGHBORS,
            num_chunks: 10,
        }
    }
}
