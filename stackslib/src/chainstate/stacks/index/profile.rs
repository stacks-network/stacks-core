// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use std::time::SystemTime;

/// Fine-grained profiling data for Trie storage ops.
/// The implementation is only active when compiled for tests; nothing happens in production.
#[derive(Debug, Clone)]
pub struct TrieBenchmark {
    /// Total number of nanoseconds spent reading a node from storage
    total_read_nodetype_time_ns: u128,
    /// Total number of nanoseconds spent reading a node's hash from storage
    total_read_node_hash_time_ns: u128,
    /// Total number of nanoseconds spent calculating a node's hash (i.e. hashing its children)
    total_write_children_hashes_time_ns: u128,
    /// Total number of nanoseconds spent seeking to a block
    total_open_block_time_ns: u128,
    /// Total number of nanoseconds spent copying out a node's hash from storage, with the cache
    total_get_block_hash_caching_time_ns: u128,

    /// Total number of calls to read_nodetype()
    total_read_nodetype: u128,
    /// Total number of calls to read_node_hash()
    total_read_node_hash: u128,
    /// Total number of calls to write_children_hashes()
    total_write_children_hashes: u128,
    /// Total number of calls to open_block()
    total_open_block: u128,
    /// Total number of times when open_block() opened the uncommitted trie RAM
    total_open_block_ram: u128,
    /// Total number of cache hits in calls to read_nodetype()
    cache_hits_read_nodetype: u128,
    /// Total number of cache hits in calls to read_node_hash()
    cache_hits_read_node_hash: u128,
    /// Total number of calls to write_children_hashes(), where the node in question was part of a
    /// TrieRAM (uncommitted state)
    write_children_hashes_ram: u128,

    /// Total number of calls within write_children_hashes() where the node's child slot was empty
    total_write_children_hashes_empty: u128,
    /// Total number of calls within write_children_hashes() where the node's child slot pointed to
    /// a node in the same block
    total_write_children_hashes_same_block: u128,
    /// Total number of calls within write_children_hashes() where the node's child slot pointed to
    /// a node in an anestor block
    total_write_children_hashes_ancestor_block: u128,

    /// Total number of nanoseconds spent within write_children_hashes() where the node's child
    /// slot was empty
    total_write_children_hashes_empty_time_ns: u128,
    /// Total number of nanoseconds spent within write_children_hashes() where the node's child
    /// slot pointed to a node in the same trie
    total_write_children_hashes_same_block_time_ns: u128,
    /// Total number of seconds spent within write_children_hashes() where the node's child slot
    /// pointed to a node in an ancestor trie
    total_write_children_hashes_ancestor_block_time_ns: u128,

    /// Total number of naonseconds spent in calls to the inner loop of MARF::walk_from(), which
    /// handles walking down a MARF path.  Does not include the time taken to load the trie root or
    /// open the trie to walk from.
    total_marf_walk_from_time_ns: u128,
    /// Total number of nanoseconds spent in calls to MARF::walk_backptr()
    total_marf_walk_backptr_time_ns: u128,
    /// Total number of nanoseconds spent in calls to Trie::walk_backptr() where the backptr needed
    /// to be resolved.
    total_marf_walk_find_backptr_node_time_ns: u128,

    /// Temporary timestamps used to hold when the caller began measuring a particular MARF
    /// operation
    read_nodetype_start_time: SystemTime,
    read_node_hash_start_time: SystemTime,
    open_block_start_time: SystemTime,
    get_block_hash_caching_start_time: SystemTime,
    marf_walk_from_start_time: SystemTime,
    marf_walk_backptr_start_time: SystemTime,
    marf_walk_find_backptr_node_start_time: SystemTime,

    /// Number of elapsed() errors encountered (i.e. due to clock skew)
    time_errors: u64,
}

#[cfg(test)]
impl TrieBenchmark {
    pub fn new() -> TrieBenchmark {
        TrieBenchmark {
            total_read_nodetype_time_ns: 0,
            total_read_node_hash_time_ns: 0,
            total_write_children_hashes_time_ns: 0,
            total_open_block_time_ns: 0,
            total_get_block_hash_caching_time_ns: 0,

            total_read_nodetype: 0,
            total_read_node_hash: 0,
            total_write_children_hashes: 0,
            total_open_block: 0,
            total_open_block_ram: 0,
            cache_hits_read_nodetype: 0,
            cache_hits_read_node_hash: 0,
            write_children_hashes_ram: 0,

            total_write_children_hashes_empty: 0,
            total_write_children_hashes_same_block: 0,
            total_write_children_hashes_ancestor_block: 0,

            total_write_children_hashes_empty_time_ns: 0,
            total_write_children_hashes_same_block_time_ns: 0,
            total_write_children_hashes_ancestor_block_time_ns: 0,

            total_marf_walk_from_time_ns: 0,
            total_marf_walk_backptr_time_ns: 0,
            total_marf_walk_find_backptr_node_time_ns: 0,

            read_nodetype_start_time: SystemTime::now(),
            read_node_hash_start_time: SystemTime::now(),
            open_block_start_time: SystemTime::now(),
            get_block_hash_caching_start_time: SystemTime::now(),
            marf_walk_from_start_time: SystemTime::now(),
            marf_walk_backptr_start_time: SystemTime::now(),
            marf_walk_find_backptr_node_start_time: SystemTime::now(),

            time_errors: 0,
        }
    }

    /// Reset a benchmark by zeroing out all counts
    pub fn reset(&mut self) {
        self.total_read_nodetype_time_ns = 0;
        self.total_read_node_hash_time_ns = 0;
        self.total_write_children_hashes_time_ns = 0;
        self.total_open_block_time_ns = 0;
        self.total_get_block_hash_caching_time_ns = 0;

        self.total_read_nodetype = 0;
        self.total_read_node_hash = 0;
        self.total_write_children_hashes = 0;
        self.total_open_block = 0;
        self.total_open_block_ram = 0;
        self.cache_hits_read_nodetype = 0;
        self.cache_hits_read_node_hash = 0;
        self.write_children_hashes_ram = 0;

        self.total_write_children_hashes_empty = 0;
        self.total_write_children_hashes_same_block = 0;
        self.total_write_children_hashes_ancestor_block = 0;

        self.total_write_children_hashes_empty_time_ns = 0;
        self.total_write_children_hashes_same_block_time_ns = 0;
        self.total_write_children_hashes_ancestor_block_time_ns = 0;

        self.total_marf_walk_from_time_ns = 0;
        self.total_marf_walk_backptr_time_ns = 0;
        self.total_marf_walk_find_backptr_node_time_ns = 0;

        self.time_errors = 0;
    }

    /// Combine two benchmarks by adding up all timestamps and counts
    pub fn add(&mut self, other: &TrieBenchmark) {
        self.total_read_nodetype_time_ns += other.total_read_nodetype_time_ns;
        self.total_read_node_hash_time_ns += other.total_read_node_hash_time_ns;
        self.total_write_children_hashes_time_ns += other.total_write_children_hashes_time_ns;
        self.total_open_block_time_ns += other.total_open_block_time_ns;
        self.total_get_block_hash_caching_time_ns += other.total_get_block_hash_caching_time_ns;

        self.total_read_nodetype += other.total_read_nodetype;
        self.total_read_node_hash += other.total_read_node_hash;
        self.total_write_children_hashes += other.total_write_children_hashes;
        self.total_open_block += other.total_open_block;
        self.total_open_block_ram += other.total_open_block_ram;
        self.cache_hits_read_nodetype += other.cache_hits_read_nodetype;
        self.cache_hits_read_node_hash += other.cache_hits_read_node_hash;
        self.write_children_hashes_ram += other.write_children_hashes_ram;

        self.total_write_children_hashes_empty += other.total_write_children_hashes_empty;
        self.total_write_children_hashes_same_block += other.total_write_children_hashes_same_block;
        self.total_write_children_hashes_ancestor_block +=
            other.total_write_children_hashes_ancestor_block;

        self.total_write_children_hashes_empty_time_ns +=
            other.total_write_children_hashes_empty_time_ns;
        self.total_write_children_hashes_same_block_time_ns +=
            other.total_write_children_hashes_same_block_time_ns;
        self.total_write_children_hashes_ancestor_block_time_ns +=
            other.total_write_children_hashes_ancestor_block_time_ns;

        self.total_marf_walk_from_time_ns += other.total_marf_walk_from_time_ns;
        self.total_marf_walk_backptr_time_ns += other.total_marf_walk_backptr_time_ns;
        self.total_marf_walk_find_backptr_node_time_ns +=
            other.total_marf_walk_find_backptr_node_time_ns;

        self.time_errors += other.time_errors;
    }

    /// Begin measuring a call to read_nodetype()
    pub fn read_nodetype_start(&mut self) {
        self.read_nodetype_start_time = SystemTime::now();
    }

    /// Finish measuring a call to read_nodetype().  Record whether or not the node and hash were
    /// cached with `cache_hit`.
    pub fn read_nodetype_finish(&mut self, cache_hit: bool) {
        if let Ok(elapsed) = self.read_nodetype_start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_read_nodetype += 1;
            self.total_read_nodetype_time_ns += total_time;
            if cache_hit {
                self.cache_hits_read_nodetype += 1;
            }
        } else {
            self.time_errors += 1;
        }
    }

    /// Begin measuring a call to read_node_hash()
    pub fn read_node_hash_start(&mut self) {
        self.read_node_hash_start_time = SystemTime::now();
    }

    /// Finish measuring a call to read_node_hash().  Record whether or not the hash was cached
    /// with `cache_hit`.
    pub fn read_node_hash_finish(&mut self, cache_hit: bool) {
        if let Ok(elapsed) = self.read_node_hash_start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_read_node_hash += 1;
            self.total_read_node_hash_time_ns += total_time;
            if cache_hit {
                self.cache_hits_read_node_hash += 1;
            }
        } else {
            self.time_errors += 1;
        }
    }

    /// Start measuring a call to write_children_hashes().  Returns a `SystemTime` that must be
    /// passed into `write_children_hashes_finish()`.
    pub fn write_children_hashes_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    /// Finish measuring a call to write_children_hashes().  Record whether or not the caller was
    /// invoking this method on a TrieRAM via `in_ram`.
    pub fn write_children_hashes_finish(&mut self, start_time: SystemTime, in_ram: bool) {
        if let Ok(elapsed) = start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_write_children_hashes += 1;
            self.total_write_children_hashes_time_ns += total_time;
            if in_ram {
                self.write_children_hashes_ram += 1;
            }
        } else {
            self.time_errors += 1;
        }
    }

    /// Start measuring the code path in write_children_hashes() where the node's child is empty.
    /// Returns a `SystemTime` that must be passed to write_children_hashes_empty_finish().
    pub fn write_children_hashes_empty_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    /// Finish measuring the code path in write_children_hashes() where the node's child is empty.
    pub fn write_children_hashes_empty_finish(&mut self, start_time: SystemTime) {
        if let Ok(elapsed) = start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_write_children_hashes_empty += 1;
            self.total_write_children_hashes_empty_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }

    /// Start measuring the code path in write_children_hashes() where the node's child is in the
    /// smae trie.  Returns a `SystemTime` that must be passed to
    /// write_children_hashes_same_block_finish().
    pub fn write_children_hashes_same_block_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    /// Finish measuring the code path in write_children_hashes() where the node's child is in the
    /// same trie.
    pub fn write_children_hashes_same_block_finish(&mut self, start_time: SystemTime) {
        if let Ok(elapsed) = start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_write_children_hashes_same_block += 1;
            self.total_write_children_hashes_same_block_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }

    /// Start measuring the code path in write_children_hashes() where the node's child is in an
    /// ancestor trie.  Returns a `SystemTime` that must be passed to
    /// write_children_hashes_ancestor_block_finish()
    pub fn write_children_hashes_ancestor_block_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    /// Finish measuring the code path in write_children_hashes() where the node's child is in an
    /// ancestor trie.  Pass `true` to `cache_hit` if the hash was cached.
    pub fn write_children_hashes_ancestor_block_finish(&mut self, start_time: SystemTime) {
        if let Ok(elapsed) = start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_write_children_hashes_ancestor_block += 1;
            self.total_write_children_hashes_ancestor_block_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }

    /// Start measuring the runtime of a call to open_block()
    pub fn open_block_start(&mut self) {
        self.open_block_start_time = SystemTime::now();
    }

    /// Finish measuring the runtime of a call to open_block().
    /// If the uncommitted state was opened, then pass `true` for `in_ram`.
    pub fn open_block_finish(&mut self, in_ram: bool) {
        if let Ok(elapsed) = self.open_block_start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_open_block += 1;
            self.total_open_block_time_ns += total_time;

            if in_ram {
                self.total_open_block_ram += 1;
            }
        } else {
            self.time_errors += 1;
        }
    }

    /// Start recording the time taken to call get_block_hash_caching()
    pub fn get_block_hash_caching_start(&mut self) {
        self.get_block_hash_caching_start_time = SystemTime::now();
    }

    /// Finish recording the time taken to call get_block_hash_caching()
    pub fn get_block_hash_caching_finish(&mut self) {
        if let Ok(elapsed) = self.get_block_hash_caching_start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_get_block_hash_caching_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }

    /// Start recording the time taken to call one pass of the walk loop in MARF::walk_from()
    pub fn marf_walk_from_start(&mut self) {
        self.marf_walk_from_start_time = SystemTime::now();
    }

    /// Finish recording the time taken to call one pass of the walk loop in MARF::walk_from()
    pub fn marf_walk_from_finish(&mut self) {
        if let Ok(elapsed) = self.marf_walk_from_start_time.elapsed() {
            let total_time = elapsed.as_nanos();
            self.total_marf_walk_from_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }

    /// Start recording the time taken to call MARF::walk_backptr()
    pub fn marf_walk_backptr_start(&mut self) {
        self.marf_walk_backptr_start_time = SystemTime::now();
    }

    /// Finish recording the time taken to call MARF::walk_backptr()
    pub fn marf_walk_backptr_finish(&mut self) {
        if let Ok(elapsed) = self.marf_walk_backptr_start_time.elapsed() {
            let total_time = elapsed.as_nanos();
            self.total_marf_walk_backptr_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }

    /// Start recording the time taken to resolve a backptr in Trie::walk_backptr()
    pub fn marf_find_backptr_node_start(&mut self) {
        self.marf_walk_find_backptr_node_start_time = SystemTime::now();
    }

    /// Finish recording the time taken to resolve a backptr in Trie::walk_backptr()
    pub fn marf_find_backptr_node_finish(&mut self) {
        if let Ok(elapsed) = self.marf_walk_find_backptr_node_start_time.elapsed() {
            let total_time = elapsed.as_nanos();
            self.total_marf_walk_find_backptr_node_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }
}

#[cfg(not(test))]
impl TrieBenchmark {
    pub fn new() -> TrieBenchmark {
        TrieBenchmark {
            total_read_nodetype_time_ns: 0,
            total_read_node_hash_time_ns: 0,
            total_write_children_hashes_time_ns: 0,
            total_open_block_time_ns: 0,
            total_get_block_hash_caching_time_ns: 0,

            total_read_nodetype: 0,
            total_read_node_hash: 0,
            total_write_children_hashes: 0,
            total_open_block: 0,
            total_open_block_ram: 0,
            cache_hits_read_nodetype: 0,
            cache_hits_read_node_hash: 0,
            write_children_hashes_ram: 0,

            total_write_children_hashes_empty: 0,
            total_write_children_hashes_same_block: 0,
            total_write_children_hashes_ancestor_block: 0,

            total_write_children_hashes_empty_time_ns: 0,
            total_write_children_hashes_same_block_time_ns: 0,
            total_write_children_hashes_ancestor_block_time_ns: 0,

            total_marf_walk_from_time_ns: 0,
            total_marf_walk_backptr_time_ns: 0,
            total_marf_walk_find_backptr_node_time_ns: 0,

            read_nodetype_start_time: SystemTime::now(),
            read_node_hash_start_time: SystemTime::now(),
            open_block_start_time: SystemTime::now(),
            get_block_hash_caching_start_time: SystemTime::now(),
            marf_walk_from_start_time: SystemTime::now(),
            marf_walk_backptr_start_time: SystemTime::now(),
            marf_walk_find_backptr_node_start_time: SystemTime::now(),

            time_errors: 0,
        }
    }

    pub fn reset(&mut self) {}

    pub fn add(&mut self, _other: &TrieBenchmark) {}

    pub fn read_nodetype_start(&mut self) {}

    pub fn read_nodetype_finish(&mut self, _cache_hit: bool) {}

    pub fn read_node_hash_start(&mut self) {}

    pub fn read_node_hash_finish(&mut self, _cache_hit: bool) {}

    pub fn write_children_hashes_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    pub fn write_children_hashes_finish(&mut self, _start_time: SystemTime, _in_ram: bool) {}

    pub fn write_children_hashes_empty_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    pub fn write_children_hashes_empty_finish(&mut self, _start_time: SystemTime) {}

    pub fn write_children_hashes_same_block_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    pub fn write_children_hashes_same_block_finish(&mut self, _start_time: SystemTime) {}

    pub fn write_children_hashes_ancestor_block_start(&mut self) -> SystemTime {
        SystemTime::now()
    }

    pub fn write_children_hashes_ancestor_block_finish(&mut self, _start_time: SystemTime) {}

    pub fn open_block_start(&mut self) {}

    pub fn open_block_finish(&mut self, _in_ram: bool) {}

    pub fn get_block_hash_caching_start(&mut self) {}

    pub fn get_block_hash_caching_finish(&mut self) {}

    pub fn marf_walk_from_start(&mut self) {}

    pub fn marf_walk_from_finish(&mut self) {}

    pub fn marf_walk_backptr_start(&mut self) {}

    pub fn marf_walk_backptr_finish(&mut self) {}

    pub fn marf_find_backptr_node_start(&mut self) {}

    pub fn marf_find_backptr_node_finish(&mut self) {}
}
