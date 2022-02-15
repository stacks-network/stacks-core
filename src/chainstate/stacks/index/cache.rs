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

use std::char::from_digit;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::env;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::os;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{cmp, error};

use regex::Regex;
use rusqlite::{
    types::{FromSql, ToSql},
    Connection, Error as SqliteError, ErrorCode as SqliteErrorCode, OpenFlags, OptionalExtension,
    Transaction, NO_PARAMS,
};

use chainstate::stacks::index::bits::{
    get_node_byte_len, get_node_hash, read_block_identifier, read_hash_bytes, read_node_hash_bytes,
    read_nodetype, read_root_hash, write_nodetype_bytes,
};
use chainstate::stacks::index::node::{
    clear_backptr, is_backptr, set_backptr, TrieNode, TrieNode16, TrieNode256, TrieNode4,
    TrieNode48, TrieNodeID, TrieNodeType, TriePath, TriePtr,
};
use chainstate::stacks::index::Error;
use chainstate::stacks::index::TrieLeaf;
use chainstate::stacks::index::{trie_sql, BlockMap, ClarityMarfTrieId, MarfTrieId};
use util_lib::db::sql_pragma;
use util_lib::db::sqlite_open;
use util_lib::db::tx_begin_immediate;
use util_lib::db::tx_busy_handler;
use util_lib::db::Error as db_error;
use util_lib::db::SQLITE_MMAP_SIZE;

use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BLOCK_HEADER_HASH_ENCODED_SIZE;
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

/// Fully-qualified address of a Trie node.  Includes both the block ID and the pointer within the
/// block's blob as to where it is stored.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TrieNodeAddr(u32, TriePtr);

/// Cache state for all node caching strategies.
pub struct TrieCacheState<T: MarfTrieId> {
    /// Mapping between trie blob IDs (i.e. rowids) and the MarfTrieId of the trie.  Contents are
    /// never evicted, since the size of this map grows only at the rate of new Stacks blocks.
    block_hash_cache: HashMap<u32, T>,

    /// cached nodes
    node_cache: HashMap<TrieNodeAddr, TrieNodeType>,
    /// cached trie root hashes
    hash_cache: HashMap<TrieNodeAddr, TrieHash>,
}

impl<T: MarfTrieId> TrieCacheState<T> {
    pub fn new() -> TrieCacheState<T> {
        TrieCacheState {
            block_hash_cache: HashMap::new(),
            node_cache: HashMap::new(),
            hash_cache: HashMap::new(),
        }
    }

    pub fn load_node(&self, block_id: u32, trieptr: &TriePtr) -> Option<(TrieNodeType, TrieHash)> {
        match (
            self.node_cache
                .get(&TrieNodeAddr(block_id, trieptr.clone())),
            self.hash_cache
                .get(&TrieNodeAddr(block_id, trieptr.clone())),
        ) {
            (Some(ref node), Some(ref hash)) => Some(((*node).clone(), (*hash).clone())),
            _ => None,
        }
    }

    pub fn load_node_hash(&self, block_id: u32, trieptr: &TriePtr) -> Option<TrieHash> {
        self.hash_cache
            .get(&TrieNodeAddr(block_id, trieptr.clone()))
            .cloned()
    }

    pub fn store_node(
        &mut self,
        block_id: u32,
        trieptr: TriePtr,
        node: TrieNodeType,
        hash: TrieHash,
    ) {
        self.node_cache
            .insert(TrieNodeAddr(block_id, trieptr.clone()), node);
        self.hash_cache
            .insert(TrieNodeAddr(block_id, trieptr), hash);
    }

    pub fn store_node_hash(&mut self, block_id: u32, trieptr: TriePtr, hash: TrieHash) {
        self.hash_cache
            .insert(TrieNodeAddr(block_id, trieptr), hash);
    }

    pub fn load_block_hash(&self, block_id: u32) -> Option<T> {
        self.block_hash_cache.get(&block_id).cloned()
    }

    pub fn store_block_hash(&mut self, block_id: u32, block_hash: T) {
        self.block_hash_cache.insert(block_id, block_hash);
    }

    pub fn ref_block_hash(&self, block_id: u32) -> Option<&T> {
        self.block_hash_cache.get(&block_id)
    }
}

/// Trie node cache strategies
pub enum TrieCache<T: MarfTrieId> {
    /// Do nothing
    Noop(TrieCacheState<T>),
    /// Cache every node in RAM
    Everything(TrieCacheState<T>),
    /// Cache only TrieNode256's
    Node256(TrieCacheState<T>),
}

impl<T: MarfTrieId> TrieCache<T> {
    pub fn default(conn: &Connection) -> Result<TrieCache<T>, Error> {
        if let Ok(strategy) = std::env::var("STACKS_MARF_CACHE_STRATEGY") {
            TrieCache::new(&strategy, conn)
        } else {
            Ok(TrieCache::Noop(TrieCacheState::new()))
        }
    }

    pub fn new(strategy: &str, _conn: &Connection) -> Result<TrieCache<T>, Error> {
        match strategy {
            "noop" => Ok(TrieCache::Noop(TrieCacheState::new())),
            "everything" => Ok(TrieCache::Everything(TrieCacheState::new())),
            "node256" => Ok(TrieCache::Node256(TrieCacheState::new())),
            _ => {
                panic!("Unsupported trie cache strategy '{}'", strategy);
            }
        }
    }

    pub fn load_node(
        &mut self,
        block_id: u32,
        trieptr: &TriePtr,
    ) -> Option<(TrieNodeType, TrieHash)> {
        match self {
            TrieCache::Noop(_) => {
                trace!("Noop node cache load for ({},{:?})", block_id, trieptr);
                None
            }
            TrieCache::Everything(ref state) => state.load_node(block_id, trieptr),
            TrieCache::Node256(ref state) => state.load_node(block_id, trieptr),
        }
    }

    pub fn load_node_hash(&mut self, block_id: u32, trieptr: &TriePtr) -> Option<TrieHash> {
        match self {
            TrieCache::Noop(_) => {
                trace!("Noop node hash cache load for ({},{:?})", block_id, trieptr);
                None
            }
            TrieCache::Everything(ref state) => state.load_node_hash(block_id, trieptr),
            TrieCache::Node256(ref state) => state.load_node_hash(block_id, trieptr),
        }
    }

    pub fn store_node(
        &mut self,
        block_id: u32,
        trieptr: TriePtr,
        node: TrieNodeType,
        hash: TrieHash,
    ) {
        match self {
            TrieCache::Noop(_) => {
                trace!(
                    "Noop node cache store for ({},{:?},{})",
                    block_id,
                    &trieptr,
                    &hash
                );
            }
            TrieCache::Everything(ref mut state) => {
                state.store_node(block_id, trieptr, node, hash);
            }
            TrieCache::Node256(ref mut state) => match node {
                TrieNodeType::Node256(data) => {
                    state.store_node(block_id, trieptr, TrieNodeType::Node256(data), hash);
                }
                _ => {}
            },
        }
    }

    pub fn store_node_hash(&mut self, block_id: u32, trieptr: TriePtr, hash: TrieHash) {
        match self {
            TrieCache::Noop(_) => {
                trace!(
                    "Noop node hash cache store for ({},{:?},{})",
                    block_id,
                    &trieptr,
                    &hash
                );
            }
            TrieCache::Everything(ref mut state) => {
                state.store_node_hash(block_id, trieptr, hash);
            }
            TrieCache::Node256(ref mut state) => match trieptr.id {
                x if x == TrieNodeID::Node256 as u8 => {
                    state.store_node_hash(block_id, trieptr, hash);
                }
                _ => {}
            },
        }
    }

    pub fn load_block_hash(&mut self, block_id: u32) -> Option<T> {
        match self {
            TrieCache::Noop(ref mut state) => state.load_block_hash(block_id),
            TrieCache::Everything(ref mut state) => state.load_block_hash(block_id),
            TrieCache::Node256(ref mut state) => state.load_block_hash(block_id),
        }
    }

    pub fn store_block_hash(&mut self, block_id: u32, block_hash: T) {
        match self {
            TrieCache::Noop(ref mut state) => {
                state.store_block_hash(block_id, block_hash);
            }
            TrieCache::Everything(ref mut state) => {
                state.store_block_hash(block_id, block_hash);
            }
            TrieCache::Node256(ref mut state) => {
                state.store_block_hash(block_id, block_hash);
            }
        }
    }

    pub fn ref_block_hash(&self, block_id: u32) -> Option<&T> {
        match self {
            TrieCache::Noop(ref state) => state.ref_block_hash(block_id),
            TrieCache::Everything(ref state) => state.ref_block_hash(block_id),
            TrieCache::Node256(ref state) => state.ref_block_hash(block_id),
        }
    }
}

/// Fine-grained benchmarking data for Trie storage ops
#[derive(Debug, Clone)]
pub struct TrieBenchmark {
    total_read_nodetype_time_ns: u128,
    total_read_node_hash_time_ns: u128,
    total_write_children_hashes_time_ns: u128,
    total_open_block_time_ns: u128,
    total_get_block_hash_caching_time_ns: u128,

    total_read_nodetype: u128,
    total_read_node_hash: u128,
    total_write_children_hashes: u128,
    total_open_block: u128,
    total_open_block_ram: u128,
    cache_hits_read_nodetype: u128,
    cache_hits_read_node_hash: u128,
    cache_hits_write_children_hashes_same_block_hash: u128,
    cache_hits_write_children_hashes_ancestor_block_hash: u128,
    write_children_hashes_ram: u128,

    total_write_children_hashes_empty: u128,
    total_write_children_hashes_same_block: u128,
    total_write_children_hashes_ancestor_block: u128,

    total_write_children_hashes_empty_time_ns: u128,
    total_write_children_hashes_same_block_time_ns: u128,
    total_write_children_hashes_ancestor_block_time_ns: u128,

    read_nodetype_start_time: SystemTime,
    read_node_hash_start_time: SystemTime,
    open_block_start_time: SystemTime,
    write_children_hashes_start_time: SystemTime,
    write_children_hashes_empty_start_time: SystemTime,
    write_children_hashes_same_block_start_time: SystemTime,
    write_children_hashes_ancestor_block_start_time: SystemTime,
    get_block_hash_caching_start_time: SystemTime,

    time_errors: u64,
}

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
            cache_hits_write_children_hashes_same_block_hash: 0,
            cache_hits_write_children_hashes_ancestor_block_hash: 0,
            write_children_hashes_ram: 0,

            total_write_children_hashes_empty: 0,
            total_write_children_hashes_same_block: 0,
            total_write_children_hashes_ancestor_block: 0,

            total_write_children_hashes_empty_time_ns: 0,
            total_write_children_hashes_same_block_time_ns: 0,
            total_write_children_hashes_ancestor_block_time_ns: 0,

            read_nodetype_start_time: SystemTime::now(),
            read_node_hash_start_time: SystemTime::now(),
            open_block_start_time: SystemTime::now(),
            write_children_hashes_start_time: SystemTime::now(),
            write_children_hashes_empty_start_time: SystemTime::now(),
            write_children_hashes_same_block_start_time: SystemTime::now(),
            write_children_hashes_ancestor_block_start_time: SystemTime::now(),
            get_block_hash_caching_start_time: SystemTime::now(),

            time_errors: 0,
        }
    }

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
        self.cache_hits_write_children_hashes_same_block_hash = 0;
        self.cache_hits_write_children_hashes_ancestor_block_hash = 0;
        self.write_children_hashes_ram = 0;

        self.total_write_children_hashes_empty = 0;
        self.total_write_children_hashes_same_block = 0;
        self.total_write_children_hashes_ancestor_block = 0;

        self.total_write_children_hashes_empty_time_ns = 0;
        self.total_write_children_hashes_same_block_time_ns = 0;
        self.total_write_children_hashes_ancestor_block_time_ns = 0;

        self.time_errors += 0;
    }

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
        self.cache_hits_write_children_hashes_same_block_hash +=
            other.cache_hits_write_children_hashes_same_block_hash;
        self.cache_hits_write_children_hashes_ancestor_block_hash +=
            other.cache_hits_write_children_hashes_ancestor_block_hash;
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

        self.time_errors += other.time_errors;
    }

    pub fn read_nodetype_start(&mut self) {
        self.read_nodetype_start_time = SystemTime::now();
    }

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

    pub fn read_node_hash_start(&mut self) {
        self.read_node_hash_start_time = SystemTime::now();
    }

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

    pub fn write_children_hashes_start(&mut self) {
        self.write_children_hashes_start_time = SystemTime::now();
    }

    pub fn write_children_hashes_finish(&mut self, in_ram: bool) {
        if let Ok(elapsed) = self.write_children_hashes_start_time.elapsed() {
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

    pub fn write_children_hashes_empty_start(&mut self) {
        self.write_children_hashes_empty_start_time = SystemTime::now();
    }

    pub fn write_children_hashes_empty_finish(&mut self) {
        if let Ok(elapsed) = self.write_children_hashes_empty_start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_write_children_hashes_empty += 1;
            self.total_write_children_hashes_empty_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }

    pub fn write_children_hashes_same_block_start(&mut self) {
        self.write_children_hashes_same_block_start_time = SystemTime::now();
    }

    pub fn write_children_hashes_same_block_finish(&mut self, cache_hit: bool) {
        if let Ok(elapsed) = self.write_children_hashes_same_block_start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_write_children_hashes_same_block += 1;
            self.total_write_children_hashes_same_block_time_ns += total_time;

            if cache_hit {
                self.cache_hits_write_children_hashes_same_block_hash += 1;
            }
        } else {
            self.time_errors += 1;
        }
    }

    pub fn write_children_hashes_ancestor_block_start(&mut self) {
        self.write_children_hashes_ancestor_block_start_time = SystemTime::now();
    }

    pub fn write_children_hashes_ancestor_block_finish(&mut self, cache_hit: bool) {
        if let Ok(elapsed) = self
            .write_children_hashes_ancestor_block_start_time
            .elapsed()
        {
            let total_time = elapsed.as_nanos();

            self.total_write_children_hashes_ancestor_block += 1;
            self.total_write_children_hashes_ancestor_block_time_ns += total_time;

            if cache_hit {
                self.cache_hits_write_children_hashes_ancestor_block_hash += 1;
            }
        } else {
            self.time_errors += 1;
        }
    }

    pub fn open_block_start(&mut self) {
        self.open_block_start_time = SystemTime::now();
    }

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

    pub fn get_block_hash_caching_start(&mut self) {
        self.get_block_hash_caching_start_time = SystemTime::now();
    }

    pub fn get_block_hash_caching_finish(&mut self) {
        if let Ok(elapsed) = self.get_block_hash_caching_start_time.elapsed() {
            let total_time = elapsed.as_nanos();

            self.total_get_block_hash_caching_time_ns += total_time;
        } else {
            self.time_errors += 1;
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::collections::VecDeque;
    use std::fs;

    use chainstate::stacks::index::marf::*;
    use chainstate::stacks::index::node::*;
    use chainstate::stacks::index::storage::*;
    use chainstate::stacks::index::*;

    use super::*;

    use rand::thread_rng;
    use rand::Rng;

    use sha2::Digest;
    use util::hash::Sha512Trunc256Sum;

    use std::time::SystemTime;

    /// Deterministic random keys to insert
    fn make_test_insert_data(
        num_inserts_per_block: u64,
        num_blocks: u64,
    ) -> Vec<Vec<(String, MARFValue)>> {
        let mut data = vec![0u8; 32];
        let mut ret = vec![];

        for blk in 0..num_blocks {
            let mut block_data = vec![];
            test_debug!("Make block {}", blk);
            for val in 0..num_inserts_per_block {
                let path_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&path_bytes[0..32]);

                let path = to_hex(&path_bytes);

                let value_bytes = Sha512Trunc256Sum::from_data(&data).as_bytes().to_vec();
                data.copy_from_slice(&value_bytes[0..32]);

                let mut value_bytes_slice = [0u8; 40];
                value_bytes_slice[0..32].copy_from_slice(&value_bytes);

                let value = MARFValue(value_bytes_slice);
                block_data.push((path, value));
            }
            ret.push(block_data);
        }
        ret
    }

    fn test_marf_with_cache(
        test_name: &str,
        cache_strategy: &str,
        hash_strategy: TrieHashCalculationMode,
        data: &[Vec<(String, MARFValue)>],
        batch_size: Option<usize>,
    ) -> TrieHash {
        let test_dir = format!("/tmp/stacks-marf-tests/{}", test_name);
        if fs::metadata(&test_dir).is_ok() {
            fs::remove_dir_all(&test_dir).unwrap();
        }
        fs::create_dir_all(&test_dir).unwrap();

        let test_file = format!(
            "{}/marf-cache-{}-{:?}.sqlite",
            &test_dir, cache_strategy, hash_strategy
        );

        let marf_opts = MARFOpenOpts::new(hash_strategy, cache_strategy);
        let f = TrieFileStorage::open(&test_file, marf_opts).unwrap();
        let mut marf = MARF::from_storage(f);
        let mut last_block_header = BlockHeaderHash::sentinel();
        let batch_size = batch_size.unwrap_or(0);

        for (i, block_data) in data.iter().enumerate() {
            test_debug!("Write block {}", i);
            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

            let block_header = BlockHeaderHash(block_hash_bytes);
            marf.begin(&last_block_header, &block_header).unwrap();

            if batch_size > 0 {
                for b in (0..block_data.len()).step_by(batch_size) {
                    let batch = &block_data[b..cmp::min(block_data.len(), b + batch_size)];
                    let keys = batch.iter().map(|(k, _)| k.clone()).collect();
                    let values = batch.iter().map(|(_, v)| v.clone()).collect();
                    marf.insert_batch(&keys, values).unwrap();
                }
            } else {
                for (key, value) in block_data.iter() {
                    let path = TriePath::from_key(key);
                    let leaf = TrieLeaf::from_value(&vec![], value.clone());
                    marf.insert_raw(path, leaf).unwrap();
                }
            }

            marf.commit().unwrap();
            last_block_header = block_header;
        }

        let write_bench = marf.borrow_storage_backend().get_benchmarks();
        marf.borrow_storage_backend().reset_benchmarks();
        eprintln!("MARF bench writes: {:#?}", &write_bench);

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        let mut total_read_time = 0;
        let mut root_hash = TrieHash([0u8; 32]);
        for (i, block_data) in data.iter().enumerate() {
            test_debug!("Read block {}", i);
            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

            let block_header = BlockHeaderHash(block_hash_bytes);
            for (key, value) in block_data.iter() {
                let path = TriePath::from_key(key);
                let marf_leaf = TrieLeaf::from_value(&vec![], value.clone());

                let read_time = SystemTime::now();
                let leaf = MARF::get_path(&mut marf.borrow_storage_backend(), &block_header, &path)
                    .unwrap()
                    .unwrap();

                let read_time = read_time.elapsed().unwrap().as_nanos();
                total_read_time += read_time;

                assert_eq!(leaf.data.to_vec(), marf_leaf.data.to_vec());
                assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);
            }

            root_hash = marf.get_root_hash_at(&block_header).unwrap();
        }

        let read_bench = marf.borrow_storage_backend().get_benchmarks();
        eprintln!(
            "MARF bench reads ({} total): {:#?}",
            total_read_time, &read_bench
        );

        let mut bench = write_bench.clone();
        bench.add(&read_bench);

        eprintln!("MARF bench total: {:#?}", &bench);

        root_hash
    }

    #[test]
    fn test_marf_node_cache_noop() {
        let test_data = make_test_insert_data(128, 128);
        let root_hash = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            None,
        );
        eprintln!("Final root hash is {}", root_hash);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(64),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(128),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(67),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(13),
        );
        assert_eq!(root_hash, root_hash_batched);
    }

    #[test]
    fn test_marf_node_cache_noop_deferred() {
        let test_data = make_test_insert_data(128, 128);
        let root_hash = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            None,
        );
        eprintln!("Final root hash is {}", root_hash);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Deferred,
            &test_data,
            None,
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(64),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(128),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(67),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_noop",
            "noop",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(13),
        );
        assert_eq!(root_hash, root_hash_batched);
    }

    #[test]
    fn test_marf_node_cache_everything() {
        let test_data = make_test_insert_data(128, 128);
        let root_hash = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            None,
        );
        eprintln!("Final root hash is {}", root_hash);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(64),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(128),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(67),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(13),
        );
        assert_eq!(root_hash, root_hash_batched);
    }

    #[test]
    fn test_marf_node_cache_everything_deferred() {
        let test_data = make_test_insert_data(128, 128);
        let root_hash = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            None,
        );
        eprintln!("Final root hash is {}", root_hash);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(64),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(128),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(67),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_everything",
            "everything",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(13),
        );
        assert_eq!(root_hash, root_hash_batched);
    }

    #[test]
    fn test_marf_node_cache_node256() {
        let test_data = make_test_insert_data(128, 128);
        let root_hash = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            None,
        );
        eprintln!("Final root hash is {}", root_hash);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(64),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(128),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(67),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Immediate,
            &test_data,
            Some(13),
        );
        assert_eq!(root_hash, root_hash_batched);
    }

    #[test]
    fn test_marf_node_cache_node256_deferred() {
        let test_data = make_test_insert_data(128, 128);
        let root_hash = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            None,
        );
        eprintln!("Final root hash is {}", root_hash);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(64),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(128),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(67),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(13),
        );
        assert_eq!(root_hash, root_hash_batched);
    }

    #[test]
    fn test_marf_node_cache_node256_deferred_15500() {
        let test_data = make_test_insert_data(15500, 10);
        let root_hash = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "noop",
            TrieHashCalculationMode::Immediate,
            &test_data,
            None,
        );
        eprintln!("Final root hash is {}", root_hash);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(64),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(128),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(67),
        );
        assert_eq!(root_hash, root_hash_batched);

        let root_hash_batched = test_marf_with_cache(
            "test_marf_node_cache_node256",
            "node256",
            TrieHashCalculationMode::Deferred,
            &test_data,
            Some(13),
        );
        assert_eq!(root_hash, root_hash_batched);
    }
}
