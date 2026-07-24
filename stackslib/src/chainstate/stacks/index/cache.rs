// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
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

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::chainstate::stacks::index::MarfTrieId;

/// Cache MARF block hash/block ID lookups.
pub struct BlockHashCache<T: MarfTrieId> {
    /// Mapping between trie blob IDs (i.e. rowids) and the MarfTrieId of the trie.  Contents are
    /// never evicted, since the size of this map grows only at the rate of new Stacks blocks.
    block_hash_cache: HashMap<u32, T>,

    /// Mapping between trie blob hashes and their IDs
    block_id_cache: HashMap<T, u32>,
}

impl<T: MarfTrieId> BlockHashCache<T> {
    pub fn new() -> BlockHashCache<T> {
        BlockHashCache {
            block_hash_cache: HashMap::new(),
            block_id_cache: HashMap::new(),
        }
    }

    /// Get cached entry for a block hash, given its ID, or, if not
    ///  found, use `lookup` to get the corresponding block hash and
    ///  store it in the cache
    pub fn get_block_hash_caching<E, F: FnOnce(u32) -> Result<T, E>>(
        &mut self,
        id: u32,
        lookup: F,
    ) -> Result<&T, E> {
        match self.block_hash_cache.entry(id) {
            Entry::Occupied(occupied_entry) => Ok(occupied_entry.into_mut()),
            Entry::Vacant(vacant_entry) => {
                let block_hash = lookup(id)?;
                let block_hash_ref = vacant_entry.insert(block_hash.clone());
                self.block_id_cache.insert(block_hash, id);
                Ok(block_hash_ref)
            }
        }
    }

    /// Cache a block hash, given its ID
    pub fn store_block_hash(&mut self, block_id: u32, block_hash: T) {
        assert!(!self.block_hash_cache.contains_key(&block_id));
        self.block_id_cache.insert(block_hash.clone(), block_id);
        self.block_hash_cache.insert(block_id, block_hash);
    }

    /// Get an immutable reference to a block hash, given the ID
    pub fn ref_block_hash(&self, block_id: u32) -> Option<&T> {
        self.block_hash_cache.get(&block_id)
    }

    /// Get the block ID, given its hash
    pub fn load_block_id(&self, block_hash: &T) -> Option<u32> {
        self.block_id_cache.get(block_hash).copied()
    }
}
