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


use std::collections::VecDeque;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::{Deref, DerefMut};
use std::fmt;
#[cfg(test)]
use std::collections::HashMap;

use sha2::Digest;
use stacks_common::util::hash::to_hex;
use stacks_common::{trace, test_debug, warn, debug, error};
use stacks_common::types::chainstate::{
    TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE, TRIEHASH_ENCODED_SIZE,
};

use crate::bits::{
    get_node_byte_len, read_hash_bytes, read_nodetype, read_root_hash, write_nodetype_bytes,
};
use crate::{cache::*, MARFOpenOpts, trie};
use crate::db::TrieDbTransaction;
use crate::file::{TrieFile, TrieFileNodeHashReader};
use crate::node::{
    is_backptr, TrieNode, TrieNodeID, TrieNodeType, TriePtr,
};
use crate::profile::TrieBenchmark;
use crate::trie::Trie;
use crate::{
    BlockMap, MarfError, MarfTrieId, TrieHashExtension, TrieHasher,
};

use super::{Result, db::TrieDb};

/// A trait for reading the hash of a node into a given Write impl, given the pointer to a node in
/// a trie.
pub trait NodeHashReader {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<()>;
}

impl<Id, DB> BlockMap for TrieFileStorage<Id, DB>
where
    Id: MarfTrieId,
    DB: TrieDb
{
    type TrieId = Id;

    fn get_block_hash(&self, id: u32) -> Result<Id> {
        self.db.get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Id> {
        if !self.is_block_hash_cached(id) {
            let block_hash = self.get_block_hash(id)?;
            self.cache.store_block_hash(id, block_hash.clone());
        }
        self.cache.ref_block_hash(id).ok_or(MarfError::NotFoundError)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &Id) -> Result<u32> {
        self.db.get_block_identifier(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &Id) -> Result<u32> {
        // don't use the cache if we're unconfirmed
        if self.data.unconfirmed {
            self.get_block_id(block_hash)
        } else {
            if let Some(block_id) = self.cache.load_block_id(block_hash) {
                Ok(block_id)
            } else {
                let block_id = self.get_block_id(block_hash)?;
                self.cache.store_block_hash(block_id, block_hash.clone());
                Ok(block_id)
            }
        }
    }
}

impl<'a, Id, TrieDB> BlockMap for TrieStorageConnection<'a, Id, TrieDB> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    type TrieId = Id;

    fn get_block_hash(&self, id: u32) -> Result<Id> {
        self.db.get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Id> {
        if !self.is_block_hash_cached(id) {
            let block_hash = self.get_block_hash(id)?;
            self.cache.store_block_hash(id, block_hash.clone());
        }
        self.cache.ref_block_hash(id).ok_or(MarfError::NotFoundError)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &Id) -> Result<u32> {
        self.db.get_block_identifier(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &Id) -> Result<u32> {
        // don't use the cache if we're unconfirmed
        if self.data.unconfirmed {
            self.get_block_id(block_hash)
        } else {
            if let Some(block_id) = self.cache.load_block_id(block_hash) {
                Ok(block_id)
            } else {
                let block_id = self.get_block_id(block_hash)?;
                self.cache.store_block_hash(block_id, block_hash.clone());
                Ok(block_id)
            }
        }
    }
}

impl<'a, Id, TrieDB> BlockMap for TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    type TrieId = Id;

    fn get_block_hash(&self, id: u32) -> Result<Id> {
        self.deref().get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Id> {
        self.deref_mut().get_block_hash_caching(id)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.deref().is_block_hash_cached(id)
    }

    fn get_block_id(&self, block_hash: &Id) -> Result<u32> {
        self.deref().get_block_id(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &Id) -> Result<u32> {
        self.deref_mut().get_block_id_caching(block_hash)
    }
}

impl<Id, TrieDB> BlockMap for TrieSqlHashMapCursor<'_, Id, TrieDB> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    type TrieId = Id;

    fn get_block_hash(&self, id: u32) -> Result<Id> {
        self.db.get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Id> {
        if !self.is_block_hash_cached(id) {
            let block_hash = self.get_block_hash(id)?;
            self.cache.store_block_hash(id, block_hash.clone());
        }
        self.cache.ref_block_hash(id).ok_or(MarfError::NotFoundError)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &Id) -> Result<u32> {
        self.db.get_block_identifier(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &Id) -> Result<u32> {
        // don't use the cache if we're unconfirmed
        if self.unconfirmed {
            self.get_block_id(block_hash)
        } else {
            if let Some(block_id) = self.cache.load_block_id(block_hash) {
                Ok(block_id)
            } else {
                let block_id = self.get_block_id(block_hash)?;
                self.cache.store_block_hash(block_id, block_hash.clone());
                Ok(block_id)
            }
        }
    }
}

enum FlushOptions<'a, T: MarfTrieId> {
    CurrentHeader,
    NewHeader(&'a T),
    MinedTable(&'a T),
    UnconfirmedTable,
}

impl<T: MarfTrieId> fmt::Display for FlushOptions<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FlushOptions::CurrentHeader => write!(f, "self"),
            FlushOptions::MinedTable(bhh) => write!(f, "{}.mined", bhh),
            FlushOptions::NewHeader(bhh) => write!(f, "{}", bhh),
            FlushOptions::UnconfirmedTable => write!(f, "self.unconfirmed"),
        }
    }
}

/// Uncommitted storage state to be flushed
#[derive(Clone)]
pub enum UncommittedState<Id> 
where
    Id: MarfTrieId,
{
    /// read-write
    RW(TrieRAM<Id>),
    /// read-only, sealed, with root hash
    Sealed(TrieRAM<Id>, TrieHash),
}

impl<Id> UncommittedState<Id> 
where
    Id: MarfTrieId
{
    /// Clear the contents
    pub fn format(&mut self) -> Result<()> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => trie_ram.format(),
            _ => {
                panic!("FATAL: cannot format a sealed TrieRAM");
            }
        }
    }

    /// Get a hint as to how big the uncommitted state is
    pub fn size_hint(&self) -> usize {
        match self {
            UncommittedState::RW(ref trie_ram) => trie_ram.size_hint(),
            UncommittedState::Sealed(ref trie_ram, _) => trie_ram.size_hint(),
        }
    }

    /// Get an immutable reference to the inner TrieRAM
    pub fn trie_ram_ref<'b>(&'b self) -> &'b TrieRAM<Id> {
        match self {
            UncommittedState::RW(ref trie_ram) => trie_ram,
            UncommittedState::Sealed(ref trie_ram, ..) => trie_ram,
        }
    }

    /// Get a mutable reference to the inner TrieRAM
    pub fn trie_ram_mut(&mut self) -> &mut TrieRAM<Id> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => trie_ram,
            UncommittedState::Sealed(ref mut trie_ram, ..) => trie_ram,
        }
    }

    /// Read a node's hash
    pub fn read_node_hash(&self, ptr: &TriePtr) -> Result<TrieHash> {
        self.trie_ram_ref().read_node_hash(ptr)
    }

    /// Read a node's hash and the node itself
    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash)> {
        self.trie_ram_mut().read_nodetype(ptr)
    }

    /// Write a node and its hash to a particular slot in the TrieRAM.
    /// Panics of the UncommittedState is sealed already.
    pub fn write_nodetype(
        &mut self,
        node_array_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<()> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => {
                trie_ram.write_nodetype(node_array_ptr, node, hash)
            }
            UncommittedState::Sealed(..) => {
                panic!("FATAL: tried to write to a sealed TrieRAM");
            }
        }
    }

    /// Write a node hash to a particular slot in the TrieRAM.
    /// Panics of the UncommittedState is sealed already.
    pub fn write_node_hash(&mut self, node_array_ptr: u32, hash: TrieHash) -> Result<()> {
        match self {
            UncommittedState::RW(ref mut trie_ram) => {
                trie_ram.write_node_hash(node_array_ptr, hash)
            }
            UncommittedState::Sealed(..) => {
                panic!("FATAL: tried to write to a sealed TrieRAM");
            }
        }
    }

    /// Get the last pointer (i.e. last slot) of the TrieRAM
    pub fn last_ptr(&mut self) -> Result<u32> {
        self.trie_ram_mut().last_ptr()
    }

    /// Seal the TrieRAM.  Calculate its root hash and prevent any subsequent writes from
    /// succeeding.
    fn seal<'a, TrieDB>(
        self,
        storage_tx: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>,
    ) -> Result<UncommittedState<Id>> 
    where
        TrieDB: TrieDb
    {
        match self {
            UncommittedState::RW(mut trie_ram) => {
                let root_hash = trie_ram.inner_seal(storage_tx)?;
                Ok(UncommittedState::Sealed(trie_ram, root_hash))
            }
            _ => {
                panic!("FATAL: tried to re-seal a sealed TrieRAM");
            }
        }
    }

    /// Dump the TrieRAM to the given writeable `f`.  If the TrieRAM is not sealed yet, then seal
    /// it first and then dump it.
    fn dump<'a, TrieDB, F>(
        self,
        storage_tx: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>,
        f: &mut F,
        bhh: &Id,
    ) -> Result<()> 
    where
        TrieDB: TrieDb,
        F: Write + Seek
    {
        if self.trie_ram_ref().block_header != *bhh {
            error!("Failed to dump {:?}: not the current block", bhh);
            return Err(MarfError::NotFoundError);
        }

        match self {
            UncommittedState::RW(mut trie_ram) => {
                // seal it first, then dump it
                debug!("Seal and dump trie for {}", bhh);
                trie_ram.inner_seal_dump(storage_tx)?;
                trie_ram.dump_consume(f)?;
                Ok(())
            }
            UncommittedState::Sealed(trie_ram, _rh) => {
                // already sealed
                debug!(
                    "Dump already-sealed trie for {} (root hash was {})",
                    bhh, _rh
                );
                trie_ram.dump_consume(f)?;
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub fn print_to_stderr(&self) {
        self.trie_ram_ref().print_to_stderr()
    }
}

/// In-RAM trie storage.
/// Used by TrieFileStorage to buffer the next trie being built.
#[derive(Clone)]
pub struct TrieRAM<T: MarfTrieId> {
    data: Vec<(TrieNodeType, TrieHash)>,
    block_header: T,
    readonly: bool,

    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    total_bytes: usize,

    /// does this TrieRAM represent data temporarily moved out of another TrieRAM?
    is_moved: bool,

    parent: T,
}

/// Trie in RAM without the serialization overhead
impl<Id> TrieRAM<Id> 
where
    Id: MarfTrieId
{
    pub fn new(block_header: &Id, capacity_hint: usize, parent: &Id) -> TrieRAM<Id> {
        TrieRAM {
            data: Vec::with_capacity(capacity_hint),
            block_header: block_header.clone(),
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0,

            is_moved: false,

            parent: parent.clone(),
        }
    }

    /// Inner method to instantiate a TrieRAM from existing Trie data.
    fn from_data(block_header: Id, data: Vec<(TrieNodeType, TrieHash)>, parent: Id) -> TrieRAM<Id> {
        TrieRAM {
            data,
            block_header,
            readonly: false,

            read_count: 0,
            read_backptr_count: 0,
            read_node_count: 0,
            read_leaf_count: 0,

            write_count: 0,
            write_node_count: 0,
            write_leaf_count: 0,

            total_bytes: 0,

            is_moved: false,

            parent,
        }
    }

    /// Instantiate a `TrieRAM` from this `TrieRAM`'s `data` and `block_header`.  This TrieRAM will
    /// have its data set to an empty list.  The new TrieRAM will have its `is_moved` field set to
    /// `true`.
    /// The purpose of this method is to temporarily "re-instate" a `TrieRAM` into a
    /// `TrieFileStorage` while it is being flushed, so that all of the `TrieFileStorage` methods
    /// will continue to work on it.
    ///
    /// Do not call directly; instead, use `with_reinstated_data()`.
    fn move_to(&mut self) -> TrieRAM<Id> {
        let moved_data = std::mem::replace(&mut self.data, vec![]);
        TrieRAM {
            data: moved_data,
            block_header: self.block_header.clone(),
            readonly: self.readonly,

            read_count: self.read_count,
            read_backptr_count: self.read_backptr_count,
            read_node_count: self.read_node_count,
            read_leaf_count: self.read_leaf_count,

            write_count: self.write_count,
            write_node_count: self.write_node_count,
            write_leaf_count: self.write_leaf_count,

            total_bytes: self.total_bytes,

            is_moved: true,

            parent: self.parent.clone(),
        }
    }

    /// Take a given `TrieRAM` and move its `data` to this `TrieRAM`'s data.
    /// The given `TrieRAM` *must* have been created with a prior call to `self.move_to()`.
    ///
    /// Do not call directly; instead use `with_reinstated_data()`.
    fn replace_from(&mut self, other: TrieRAM<Id>) {
        assert!(!self.is_moved);
        assert!(other.is_moved);
        assert_eq!(self.block_header, other.block_header);
        let _ = std::mem::replace(&mut self.data, other.data);
    }

    /// Temporarily re-instate this TrieRAM's data as the `uncommitted_writes` field in a given storage
    /// connection, run the closure `f` with it, and then restore the original `uncommitted_writes` data.
    /// This method does not compose -- calling `with_reinstated_data` within the given closure `f`
    /// will lead to a runtime panic.
    ///
    /// The purpose of this method is to calculate the trie root hash from a trie that is in the
    /// process of being flushed.
    fn with_reinstated_data<'a, TrieDB, F, R>(
        &'_ mut self, 
        storage: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>, 
        f: F
    ) -> R
    where
        TrieDB: TrieDb,
        F: FnOnce(&mut TrieRAM<Id>, &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>) -> R,
    {
        // do NOT call this function within another instance of this function.  Only tears and
        // misery would result.
        assert!(
            !self.is_moved,
            "FATAL: tried to move a TrieRAM after it had been moved"
        );

        let old_uncommitted_writes = storage.data.uncommitted_writes.take();

        let moved_trie_ram = self.move_to();
        storage.data.uncommitted_writes = Some((
            self.block_header.clone(),
            UncommittedState::RW(moved_trie_ram),
        ));

        let result = f(self, storage);

        // restore
        let (_, moved_extended) = storage
            .data
            .uncommitted_writes
            .take()
            .expect("FATAL: unable to retake moved TrieRAM");

        match moved_extended {
            UncommittedState::RW(trie_ram) => {
                self.replace_from(trie_ram);
            }
            _ => {
                unreachable!()
            }
        };

        storage.data.uncommitted_writes = old_uncommitted_writes;
        result
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.read_count;
        let w = self.write_count;
        self.read_count = 0;
        self.write_count = 0;
        (r, w)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn node_stats(&mut self) -> (u64, u64, u64) {
        let nr = self.read_node_count;
        let br = self.read_backptr_count;
        let nw = self.write_node_count;

        self.read_node_count = 0;
        self.read_backptr_count = 0;
        self.write_node_count = 0;

        (nr, br, nw)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn leaf_stats(&mut self) -> (u64, u64) {
        let lr = self.read_leaf_count;
        let lw = self.write_leaf_count;

        self.read_leaf_count = 0;
        self.write_leaf_count = 0;

        (lr, lw)
    }

    /// write the trie data to f, using node_data_order to
    ///   iterate over node_data
    pub fn write_trie_indirect<F: Write + Seek>(
        f: &mut F,
        node_data_order: &[u32],
        node_data: &[(TrieNodeType, TrieHash)],
        offsets: &[u32],
        parent_hash: &Id,
    ) -> Result<()> {
        assert_eq!(node_data_order.len(), offsets.len());

        // write parent block ptr
        f.seek(SeekFrom::Start(0))?;
        f.write_all(parent_hash.as_bytes())
            .map_err(|e| MarfError::IOError(e))?;
        // write zero-identifier (TODO: this is a convenience hack for now, we should remove the
        //    identifier from the trie data blob)
        f.seek(SeekFrom::Start(BLOCK_HEADER_HASH_ENCODED_SIZE as u64))?;
        f.write_all(&0u32.to_le_bytes())
            .map_err(|e| MarfError::IOError(e))?;

        for (ix, indirect) in node_data_order.iter().enumerate() {
            // dump the node to storage
            write_nodetype_bytes(
                f,
                &node_data[*indirect as usize].0,
                node_data[*indirect as usize].1,
            )?;

            // next node
            f.seek(SeekFrom::Start(offsets[ix] as u64))?;
        }

        Ok(())
    }

    /// Calculate the MARF root hash from a trie root hash.
    /// This hashes the trie root hash with a geometric series of prior trie hashes.
    fn calculate_marf_root_hash<'a, TrieDB>(
        &mut self,
        storage: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>,
        root_hash: &TrieHash,
    ) -> TrieHash 
    where
        TrieDB: TrieDb
    {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();

        storage.data.set_block(self.block_header.clone(), None);

        let marf_root_hash = Trie::get_trie_root_hash(storage, root_hash)
            .expect("FATAL: unable to calculate MARF root hash from moved TrieRAM");

        test_debug!("cur_block_hash = {}, cur_block_id = {:?}, self.block_header = {}, have last extended? {}, root_hash: {}, trie_root_hash = {}", &cur_block_hash, &cur_block_id, &self.block_header, storage.data.uncommitted_writes.is_some(), root_hash, &marf_root_hash);

        storage.data.set_block(cur_block_hash, cur_block_id);

        marf_root_hash
    }

    /// Calculate and store the MARF root hash, as well as any necessary intermediate nodes.  Do
    /// this only for deferred hashing mode.
    fn inner_seal_marf<'a, TrieDB>(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>,
    ) -> Result<TrieHash> 
    where
        TrieDB: TrieDb
    {
        // find trie root hash
        debug!("Calculate trie root hash");
        let root_trie_hash = self.calculate_node_hashes(storage_tx, 0)?;

        // find marf root hash -- the hash of the trie root node hash, and the hashes of the
        // geometric series of ancestor tries.  Because the trie is already in the process of
        // being flushed, we have to temporarily reinstate its data into `storage_tx` so we can
        // use it to walk down the various MARF paths needed to query ancestor tries.
        let marf_root_hash = self.with_reinstated_data(storage_tx, move |moved_trieram, storage| {
            debug!("Calculate marf root hash");
            let tmp = moved_trieram.calculate_marf_root_hash(storage, &root_trie_hash);
            tmp
        });

        if TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode {
            // If we are doing both eager and deferred hashing (i.e. via a test), then verify
            // that we get the same marf hash either way.
            let (_, expected_root_hash) = self.get_nodetype(0)?;
            assert_eq!(expected_root_hash, &marf_root_hash);
        }

        // need to store this hash too, since we deferred calculation
        self.write_node_hash(0, marf_root_hash.clone())?;
        Ok(marf_root_hash)
    }

    /// Get the trie root hash of the trie ram, and update all nodes' root hashes if we're in
    /// deferred hash mode.  Returns the resulting MARF root.  This is part of the seal operation.
    fn inner_seal<'a, TrieDB>(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>,
    ) -> Result<TrieHash> 
    where
        TrieDB: TrieDb
    {
        if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
            || TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode
        {
            self.inner_seal_marf(storage_tx)
        } else {
            // already available
            let marf_root_hash =
                self.read_node_hash(&TriePtr::new(TrieNodeID::Node256 as u8, 0, 0))?;
            Ok(marf_root_hash)
        }
    }

    #[cfg(test)]
    pub fn test_inner_seal<'a, TrieDB>(
        &'a mut self,
        storage_tx: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>,
    ) -> Result<TrieHash> 
    where
        TrieDB: TrieDb
    {
        self.inner_seal(storage_tx)
    }

    /// Seal a trie ram while in the process of dumping it.  If the storage's hash calculation mode
    /// is Deferred, then this updates all the node hashes as well and stores the new node hash.
    /// Otherwise, this is a no-op.
    /// This part of the seal operation.
    fn inner_seal_dump<'a, TrieDB>(
        &mut self, 
        storage_tx: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>
    ) -> Result<()> 
    where
        TrieDB: TrieDb
    {
        if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
            || TrieHashCalculationMode::All == storage_tx.deref().hash_calculation_mode
        {
            let marf_root_hash = self.inner_seal_marf(storage_tx)?;
            debug!("Deferred root hash calculation is {}", &marf_root_hash);
        }
        Ok(())
    }

    /// Recursively calculate all node hashes in this `TrieRAM`.  The top-most call to this method
    /// should pass `0` for `node_ptr`, since this is the pointer to the root node.  Returns the
    /// node hash for the `TrieNode` at `node_ptr`.
    /// If the given `storage_tx`'s hash calculation mode is set to
    /// `TrieHashCalculationMode::Deferred`, then this method will also store each non-leaf node's
    /// hash.
    fn calculate_node_hashes<'a, TrieDB>(
        &mut self,
        storage_tx: &mut TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>,
        node_ptr: u64,
    ) -> Result<TrieHash> 
    where
        TrieDB: TrieDb,
    {
        let start_time = storage_tx.bench.write_children_hashes_start();
        let mut start_node_time = Some(storage_tx.bench.write_children_hashes_same_block_start());
        let (node, node_hash) = self.get_nodetype(node_ptr as u32)?.to_owned();
        if node.is_leaf() {
            // base case: we already have the hash of the leaf, so return it.
            Ok(node_hash)
        } else {
            // inductive case: calculate children hashes, hash them, and return that hash.
            let mut hasher = TrieHasher::new();
            let empty_node_hash = TrieHash::from_data(&[]);

            node.write_consensus_bytes(storage_tx, &mut hasher)
                .expect("IO Failure pushing to hasher.");

            // count get_nodetype load time for write_children_hashes_same_block benchmark, but
            // only if that code path will be exercised.
            for ptr in node.ptrs().iter() {
                if !is_backptr(ptr.id()) && ptr.id() != TrieNodeID::Empty as u8 {
                    if let Some(start_node_time) = start_node_time.take() {
                        // count the time taken to load the root node in this case,
                        // but only do so once.
                        storage_tx
                            .bench
                            .write_children_hashes_same_block_finish(start_node_time);
                        break;
                    }
                }
            }

            // calculate the hashes of this node's children, and store them if they're in the
            // same trie.
            for ptr in node.ptrs().iter() {
                if ptr.id() == TrieNodeID::Empty as u8 {
                    // hash of empty string
                    let start_time = storage_tx.bench.write_children_hashes_empty_start();

                    hasher.write_all(empty_node_hash.as_bytes())?;

                    storage_tx
                        .bench
                        .write_children_hashes_empty_finish(start_time);
                } else if !is_backptr(ptr.id()) {
                    // hash is the hash of this node's children
                    let node_hash = self.calculate_node_hashes(storage_tx, ptr.ptr() as u64)?;

                    // count the time taken to store the hash towards the
                    // write_children_hashes_same_benchmark
                    let start_time = storage_tx.bench.write_children_hashes_same_block_start();
                    trace!(
                        "calculate_node_hashes({:?}): at chr {} ptr {}: {:?} {:?}",
                        &self.block_header,
                        ptr.chr(),
                        ptr.ptr(),
                        &node_hash,
                        node
                    );
                    hasher.write_all(node_hash.as_bytes())?;

                    if TrieHashCalculationMode::Deferred == storage_tx.deref().hash_calculation_mode
                        && ptr.id() != TrieNodeID::Leaf as u8
                    {
                        // need to store this hash too, since we deferred calculation
                        self.write_node_hash(ptr.ptr(), node_hash)?;
                    }

                    storage_tx
                        .bench
                        .write_children_hashes_same_block_finish(start_time);
                } else {
                    // hash is that of the block that contains this node
                    let start_time = storage_tx
                        .bench
                        .write_children_hashes_ancestor_block_start();

                    let block_hash = storage_tx.get_block_hash_caching(ptr.back_block())?;
                    trace!(
                        "calculate_node_hashes({:?}): at chr {} bkptr {}: {:?} {:?}",
                        &self.block_header,
                        ptr.chr(),
                        ptr.ptr(),
                        &block_hash,
                        node
                    );
                    hasher.write_all(block_hash.as_bytes())?;

                    storage_tx
                        .bench
                        .write_children_hashes_ancestor_block_finish(start_time);
                }
            }

            // only measure full trie
            if node_ptr == 0 {
                storage_tx
                    .bench
                    .write_children_hashes_finish(start_time, true);
            }

            let node_hash = {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(hasher.finalize().as_slice());
                TrieHash(buf)
            };

            Ok(node_hash)
        }
    }

    /// Walk through the buffered TrieNodes and dump them to f.
    /// This consumes this TrieRAM instance.
    fn dump_consume<F: Write + Seek>(mut self, f: &mut F) -> Result<u64> {
        // step 1: write out each node in breadth-first order to get their ptr offsets
        let mut frontier: VecDeque<u32> = VecDeque::new();

        let mut node_data = vec![];
        let mut offsets = vec![];

        let start = TriePtr::new(TrieNodeID::Node256 as u8, 0, 0).ptr();
        frontier.push_back(start);

        // first 32 bytes is reserved for the parent block hash
        //    next 4 bytes is the local block identifier
        let mut ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;

        while let Some(pointer) = frontier.pop_front() {
            let (node, _node_hash) = self.get_nodetype(pointer)?;
            // calculate size
            let num_written = get_node_byte_len(&node);
            ptr += num_written as u64;

            // queue each child
            if !node.is_leaf() {
                let ptrs = node.ptrs();
                let num_children = ptrs.len();
                for i in 0..num_children {
                    if ptrs[i].id != TrieNodeID::Empty as u8 && !is_backptr(ptrs[i].id) {
                        frontier.push_back(ptrs[i].ptr());
                    }
                }
            }

            node_data.push(pointer);
            offsets.push(ptr as u32);
        }

        assert_eq!(offsets.len(), node_data.len());

        // step 2: update ptrs in all nodes
        let mut i = 0;
        for j in 0..node_data.len() {
            let next_node = &mut self.data[node_data[j] as usize].0;
            if !next_node.is_leaf() {
                let ptrs = next_node.ptrs_mut();
                let num_children = ptrs.len();
                for k in 0..num_children {
                    if ptrs[k].id != TrieNodeID::Empty as u8 && !is_backptr(ptrs[k].id) {
                        ptrs[k].ptr = offsets[i];
                        i += 1;
                    }
                }
            }
        }

        // step 3: write out each node (now that they have the write ptrs)
        TrieRAM::write_trie_indirect(
            f,
            &node_data,
            self.data.as_slice(),
            offsets.as_slice(),
            &self.parent,
        )?;

        Ok(ptr)
    }

    /// load the trie from F.
    /// The trie will have the same structure as the on-disk trie, but it may have nodes in a
    /// different order.
    pub fn load<F: Read + Seek>(f: &mut F, bhh: &Id) -> Result<TrieRAM<Id>> {
        let mut data = vec![];
        let mut frontier = VecDeque::new();

        // read parent
        f.seek(SeekFrom::Start(0))?;
        let parent_hash_bytes = read_hash_bytes(f)?;
        let parent_hash = Id::from_bytes(parent_hash_bytes);

        let root_disk_ptr = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;

        let root_ptr = TriePtr::new(TrieNodeID::Node256 as u8, 0, root_disk_ptr as u32);
        let (mut root_node, root_hash) = read_nodetype(f, &root_ptr).map_err(|e| {
            error!("Failed to read root node info for {:?}: {:?}", bhh, &e);
            e
        })?;

        let mut next_index = 1;

        if let TrieNodeType::Node256(ref mut data) = root_node {
            // queue children in the same order we stored them
            for ptr in data.ptrs.iter_mut() {
                if ptr.id() != TrieNodeID::Empty as u8 && !is_backptr(ptr.id()) {
                    frontier.push_back((*ptr).clone());

                    // fix up ptrs
                    ptr.ptr = next_index;
                    next_index += 1;
                }
            }
        } else {
            return Err(MarfError::CorruptionError(
                "First TrieRAM node is not a Node256".to_string(),
            ));
        }

        data.push((root_node, root_hash));

        while frontier.len() > 0 {
            let next_ptr = frontier
                .pop_front()
                .expect("BUG: no ptr in non-empty frontier");
            let (mut next_node, next_hash) = read_nodetype(f, &next_ptr).map_err(|e| {
                error!("Failed to read node at {:?}: {:?}", &next_ptr, &e);
                e
            })?;

            if !next_node.is_leaf() {
                // queue children in the same order we stored them
                let ptrs: &mut [TriePtr] = match next_node {
                    TrieNodeType::Node4(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node16(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node48(ref mut data) => &mut data.ptrs,
                    TrieNodeType::Node256(ref mut data) => &mut data.ptrs,
                    _ => {
                        unreachable!();
                    }
                };

                for ptr in ptrs {
                    if ptr.id() != TrieNodeID::Empty as u8 && !is_backptr(ptr.id()) {
                        frontier.push_back((*ptr).clone());

                        // fix up ptrs
                        ptr.ptr = next_index;
                        next_index += 1;
                    }
                }
            }

            data.push((next_node, next_hash));
        }

        Ok(TrieRAM::from_data((*bhh).clone(), data, parent_hash))
    }

    /// Hint as to how many entries to allocate for the inner Vec when creating a TrieRAM
    fn size_hint(&self) -> usize {
        self.write_count as usize
        // the size hint is used for a capacity guess on the data vec, which is _nodes_
        //  NOT bytes. this led to enormous over-allocations
    }

    /// Clear the TrieRAM contents
    pub fn format(&mut self) -> Result<()> {
        if self.readonly {
            trace!("Read-only!");
            return Err(MarfError::ReadOnlyError);
        }

        self.data.clear();
        Ok(())
    }

    /// Read a node's hash from the TrieRAM.  ptr.ptr() is an array index.
    pub fn read_node_hash(&self, ptr: &TriePtr) -> Result<TrieHash> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize).ok_or_else(|| {
            error!(
                "TrieRAM: Failed to read node bytes: {} >= {}",
                ptr.ptr(),
                self.data.len()
            );
            MarfError::NotFoundError
        })?;

        Ok(node_trie_hash.clone())
    }

    /// Get an immutable reference to a node and its hash from the TrieRAM.  ptr.ptr() is an array index.
    pub fn get_nodetype(&self, ptr: u32) -> Result<&(TrieNodeType, TrieHash)> {
        self.data.get(ptr as usize).ok_or_else(|| {
            error!(
                "TrieRAM get_nodetype({:?}): Failed to read node: {} >= {}",
                &self.block_header,
                ptr,
                self.data.len()
            );
            MarfError::NotFoundError
        })
    }

    /// Get an owned instance of a node and its hash from the TrieRAM.  ptr.ptr() is an array
    /// index.
    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash)> {
        trace!(
            "TrieRAM: read_nodetype({:?}): at {:?}",
            &self.block_header,
            ptr
        );

        self.read_count += 1;
        if is_backptr(ptr.id()) {
            self.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.read_leaf_count += 1;
        } else {
            self.read_node_count += 1;
        }

        if (ptr.ptr() as u64) >= (self.data.len() as u64) {
            error!(
                "TrieRAM read_nodetype({:?}): Failed to read node {:?}: {} >= {}",
                &self.block_header,
                ptr,
                ptr.ptr(),
                self.data.len()
            );
            Err(MarfError::NotFoundError)
        } else {
            Ok(self.data[ptr.ptr() as usize].clone())
        }
    }

    /// Store a node and its hash to the TrieRAM at the given slot.
    pub fn write_nodetype(
        &mut self,
        node_array_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<()> {
        if self.readonly {
            trace!("Read-only!");
            return Err(MarfError::ReadOnlyError);
        }

        trace!(
            "TrieRAM: write_nodetype({:?}): at {}: {:?} {:?}",
            &self.block_header,
            node_array_ptr,
            &hash,
            node
        );

        self.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.write_leaf_count += 1;
            }
            _ => {
                self.write_node_count += 1;
            }
        }

        if node_array_ptr < (self.data.len() as u32) {
            self.data[node_array_ptr as usize] = (node.clone(), hash);
            Ok(())
        } else if node_array_ptr == (self.data.len() as u32) {
            self.data.push((node.clone(), hash));
            self.total_bytes += get_node_byte_len(node);
            Ok(())
        } else {
            error!("Failed to write node bytes: off the end of the buffer");
            Err(MarfError::NotFoundError)
        }
    }

    /// Store a node hash into the TrieRAM at a given node slot.
    pub fn write_node_hash(&mut self, node_array_ptr: u32, hash: TrieHash) -> Result<()> {
        if self.readonly {
            trace!("Read-only!");
            return Err(MarfError::ReadOnlyError);
        }

        trace!(
            "TrieRAM: write_node_hash({:?}): at {}: {:?}",
            &self.block_header,
            node_array_ptr,
            &hash,
        );

        // can only set the hash of an existing node
        if node_array_ptr < (self.data.len() as u32) {
            self.data[node_array_ptr as usize].1 = hash;
            Ok(())
        } else {
            error!("Failed to write node hash bytes: off the end of the buffer");
            Err(MarfError::NotFoundError)
        }
    }

    /// Get the next ptr value for a node to store.
    pub fn last_ptr(&mut self) -> Result<u32> {
        Ok(self.data.len() as u32)
    }

    #[cfg(test)]
    pub fn print_to_stderr(&self) {
        for dat in self.data.iter() {
            eprintln!("{}: {:?}", &dat.1, &dat.0);
        }
    }

    #[cfg(test)]
    pub fn data(&self) -> &Vec<(TrieNodeType, TrieHash)> {
        &self.data
    }
}

impl<Id> NodeHashReader for TrieRAM<Id> 
where
    Id: MarfTrieId
{
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<()> {
        let (_, node_trie_hash) = self.data.get(ptr.ptr() as usize).ok_or_else(|| {
            error!(
                "TrieRAM: Failed to read node bytes: {} >= {}",
                ptr.ptr(),
                self.data.len()
            );
            MarfError::NotFoundError
        })?;
        w.write_all(node_trie_hash.as_bytes())?;
        Ok(())
    }
}

pub struct TrieSqlCursor<'a, TrieDB> 
where
    TrieDB: TrieDb
{
    db: &'a TrieDB,
    block_id: u32,
}

pub struct TrieSqlHashMapCursor<'a, Id, TrieDB> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    db: &'a TrieDB,
    cache: &'a mut TrieCache<Id>,
    unconfirmed: bool,
}

impl<TrieDB> NodeHashReader for TrieSqlCursor<'_, TrieDB> 
where
    TrieDB: TrieDb
{
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<()> {
        self.db.read_node_hash_bytes(w, self.block_id, ptr)
    }
}

impl<'a, Id, TrieDB> Deref for TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    type Target = TrieStorageConnection<'a, Id, TrieDB>;
    fn deref(&self) -> &TrieStorageConnection<'a, Id, TrieDB> {
        &self.storage
    }
}

impl<'a, Id, TrieDB> DerefMut for TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb,
{
    fn deref_mut(&mut self) -> &mut TrieStorageConnection<'a, Id, TrieDB> {
        &mut self.storage
    }
}

///
/// TrieStorageTransaction is a pointer to an open TrieFileStorage with an
///   open SQLite transaction. Any storage methods which require a transaction
///   are defined _only_ for this struct (e.g., the flush methods).
///
pub struct TrieStorageTransaction<'a, Id, TrieDB, TrieTX> 
where 
    Id: MarfTrieId, 
    TrieDB: TrieDb,
    TrieTX: TrieDbTransaction<'a, TrieDB>
{
    storage: TrieStorageConnection<'a, Id, TrieDB>,
    db_tx: TrieTX
}

/// Hash calculation mode
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TrieHashCalculationMode {
    /// Calculate all trie node hashes as we insert leaves
    Immediate,
    /// Do not calculate trie node hashes until we dump the trie to disk
    Deferred,
    /// Calculate trie hashes both on leaf insert and on trie dump.  Used for testing.
    All,
}

///
///  TrieStorageConnection is a pointer to an open TrieFileStorage,
///    with either a SQLite &Connection (non-mut, so it cannot start a TX)
///    or a Transaction. Mutations on TrieStorageConnection's `data` field
///    propagate to the TrieFileStorage that created the connection.
///  This is the main interface to the storage methods, and defines most
///    of the storage functionality.
///
pub struct TrieStorageConnection<'a, Id, TrieDB> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    pub db_path: &'a str,
    db: &'a TrieDB,
    blobs: Option<&'a mut TrieFile>,
    data: &'a mut TrieStorageTransientData<Id>,
    cache: &'a mut TrieCache<Id>,
    bench: &'a mut TrieBenchmark,
    pub hash_calculation_mode: TrieHashCalculationMode,

    /// row ID of a trie that represents unconfirmed state (i.e. trie state that will never become
    /// part of the MARF, but nevertheless represents a persistent scratch space).  If this field
    /// is Some(..), then the storage connection here was used to (re-)open an unconfirmed trie
    /// (via `open_unconfirmed()` or `open_block()` when `self.unconfirmed()` is `true`), or used
    /// to create an unconfirmed trie (via `extend_to_unconfirmed_block()`).
    unconfirmed_block_id: Option<u32>,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: &'a mut Option<Id>,
}

///
///  TrieStorageTransientData holds all the data that _isn't_ committed
///   to the underlying SQL storage. Used internally to simplify
///   the TrieStorageConnection/TrieFileStorage interactions
///
pub struct TrieStorageTransientData<Id> 
where
    Id: MarfTrieId
{
    /// This is all the nodes written but not yet committed to disk.
    pub uncommitted_writes: Option<(Id, UncommittedState<Id>)>,

    /// Currently-open block (may be `uncommitted_writes.unwrap().0`)
    cur_block: Id,
    /// Tracking the row_id for the cur_block. If cur_block == uncommitted_writes,
    ///   this value should always be None
    cur_block_id: Option<u32>,

    /// Runtime statistics on reading nodes
    read_count: u64,
    read_backptr_count: u64,
    read_node_count: u64,
    read_leaf_count: u64,

    /// Runtime statistics on writing nodes
    write_count: u64,
    write_node_count: u64,
    write_leaf_count: u64,

    /// List of ancestral trie root hashes that must be hashed with the `uncommitted_writes` root node
    /// hash to produce the MarfTrieId for the trie when it gets written to disk.  This is
    /// maintained by the MARF whenever it needs to update the trie root hash after a leaf insert,
    /// so that a batch of leaf inserts into `uncommitted_writes` don't require an ancestor trie hash
    /// query more than once.
    trie_ancestor_hash_bytes_cache: Option<(Id, Vec<TrieHash>)>,

    /// Is the trie opened read-only?
    is_readonly: bool,

    /// Does this trie represent unconfirmed state?
    unconfirmed: bool,
}

// disk-backed Trie.
// Keeps the last-extended Trie in-RAM and flushes it to disk on either a call to flush() or a call
// to extend_to_block() with a different block header hash.
pub struct TrieFileStorage<Id, DB>
where
    Id: MarfTrieId,
    DB: TrieDb
{
    pub db_path: String,

    db: DB,
    blobs: Option<TrieFile>,
    data: TrieStorageTransientData<Id>,
    cache: TrieCache<Id>,
    bench: TrieBenchmark,
    hash_calculation_mode: TrieHashCalculationMode,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: Option<Id>,
}

impl<Id> TrieStorageTransientData<Id> 
where
    Id: MarfTrieId
{
    /// Target the transient data to a particular block, and optionally its block ID
    fn set_block(&mut self, bhh: Id, id: Option<u32>) {
        trace!("set_block({},{:?})", &bhh, &id);
        self.cur_block_id = id;
        self.cur_block = bhh;
    }

    fn clear_block_id(&mut self) {
        self.cur_block_id = None;
    }

    fn retarget_block(&mut self, bhh: Id) {
        self.cur_block = bhh;
    }
}

impl<Id, TrieDB> TrieFileStorage<Id, TrieDB>
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    pub fn is_readonly(&self) -> bool {
        self.data.is_readonly
    }

    // TODO: What's the purpose of TrieStorageConnection?
    pub fn connection(&mut self) -> TrieStorageConnection<Id, TrieDB> {
        TrieStorageConnection {
            db: &self.db,
            db_path: &self.db_path,
            data: &mut self.data,
            blobs: self.blobs.as_mut(),
            cache: &mut self.cache,
            bench: &mut self.bench,
            hash_calculation_mode: self.hash_calculation_mode,
            unconfirmed_block_id: None,

            #[cfg(test)]
            test_genesis_block: &mut self.test_genesis_block,
        }
    }

    pub fn transaction<'a>(
        &'a mut self
    ) -> Result<TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>> {
        if self.data.is_readonly {
            return Err(MarfError::ReadOnlyError);
        }
        
        let tx = self.db.transaction()?;

        let conn = TrieStorageConnection {
            db: &self.db,
            db_path: &self.db_path,
            data: &mut self.data,
            blobs: self.blobs.as_mut(),
            cache: &mut self.cache,
            bench: &mut self.bench,
            hash_calculation_mode: self.hash_calculation_mode,
            unconfirmed_block_id: None,

            #[cfg(test)]
            test_genesis_block: &mut self.test_genesis_block,
        };

        Ok(TrieStorageTransaction {
            storage: conn,
            db_tx: tx,
        })
    }

    /*pub fn sqlite_conn(&self) -> &Connection {
        &self.db
    }

    pub fn sqlite_tx<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        tx_begin_immediate(&mut self.db)
    }

    pub fn into_sqlite_conn(self) -> Connection {
        self.db
    }
    */

    pub fn open(trie_db: TrieDB, readonly: bool, unconfirmed: bool, marf_opts: MARFOpenOpts) -> Result<TrieFileStorage<Id, TrieDB>> {
        let blobs = if marf_opts.external_blobs {
            Some(TrieFile::from_db(&trie_db)?)
        } else {
            None
        };

        let cache = TrieCache::new(&marf_opts.cache_strategy);

        let ret = TrieFileStorage {
            db_path: trie_db.db_path()?.to_string(),
            db: trie_db,
            cache,
            blobs,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: marf_opts.hash_calculation_mode,

            data: TrieStorageTransientData {
                uncommitted_writes: None,
                cur_block: Id::sentinel(),
                cur_block_id: None,

                read_count: 0,
                read_backptr_count: 0,
                read_node_count: 0,
                read_leaf_count: 0,

                write_count: 0,
                write_node_count: 0,
                write_leaf_count: 0,

                trie_ancestor_hash_bytes_cache: None,

                is_readonly: readonly,
                unconfirmed: unconfirmed,
            },

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: None,
        };

        Ok(ret)
    }

    /*pub fn open(
        trie_db: TrieDB, 
        marf_opts: MARFOpenOpts
    ) -> Result<TrieFileStorage<Id, TrieDB>> {
        TrieFileStorage::open_opts(db_path, false, false, marf_opts)
    }

    pub fn open_readonly(
        trie_db: TrieDB,
        marf_opts: MARFOpenOpts,
    ) -> Result<TrieFileStorage<Id, TrieDB>> {
        TrieFileStorage::open_opts(db_path, true, false, marf_opts)
    }

    pub fn open_unconfirmed(
        trie_db: TrieDB,
        mut marf_opts: MARFOpenOpts,
    ) -> Result<TrieFileStorage<Id, TrieDB>> {
        // no caching allowed for unconfirmed tries, since they can disappear
        marf_opts.cache_strategy = "noop".to_string();
        TrieFileStorage::open_opts(trie_db, false, true, marf_opts)
    }

    pub fn is_readonly(&self) -> bool {
        self.data.readonly
    }*/

    /// Return true if this storage connection was opened with the intention of operating on an
    /// unconfirmed trie -- i.e. this is a storage connection for reading and writing a persisted
    /// scratch space trie, such as one for storing unconfirmed microblock transactions in the
    /// chain state.
    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    /// Returns a new TrieFileStorage in read-only mode.
    ///
    /// Returns Err if the underlying SQLite database connection cannot be created.
    pub fn reopen_readonly(&self) -> Result<TrieFileStorage<Id, TrieDB>> {
        //let db = marf_sqlite_open(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
        let db = self.db.reopen_readonly()?;
        let cache = TrieCache::default();
        let blobs = if self.blobs.is_some() {
            Some(TrieFile::from_db_path(&self.db_path, true)?)
        } else {
            None
        };

        trace!("Make read-only view of TrieFileStorage: {}", &self.db_path);

        // TODO: borrow self.uncommitted_writes; don't copy them
        let ret = TrieFileStorage {
            db_path: self.db_path.clone(),
            db: db,
            blobs,
            cache: cache,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: self.hash_calculation_mode,

            data: TrieStorageTransientData {
                uncommitted_writes: self.data.uncommitted_writes.clone(),
                cur_block: self.data.cur_block.clone(),
                cur_block_id: self.data.cur_block_id.clone(),

                read_count: 0,
                read_backptr_count: 0,
                read_node_count: 0,
                read_leaf_count: 0,

                write_count: 0,
                write_node_count: 0,
                write_leaf_count: 0,

                trie_ancestor_hash_bytes_cache: None,

                is_readonly: true,
                unconfirmed: self.unconfirmed(),
            },

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: self.test_genesis_block.clone(),
        };

        Ok(ret)
    }

    pub fn get_benchmarks(&self) -> TrieBenchmark {
        self.bench.clone()
    }

    pub fn bench_mut(&mut self) -> &mut TrieBenchmark {
        &mut self.bench
    }

    pub fn reset_benchmarks(&mut self) {
        self.bench.reset();
    }
}

impl<'a, Id, TrieDB> TrieStorageTransaction<'a, Id, TrieDB, TrieDB::TxType<'a>>
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    /// reopen this transaction as a read-only marf.
    ///  _does not_ preserve the cur_block/open tip
    pub fn reopen_readonly(
        &self
    ) -> Result<TrieFileStorage<Id, TrieDB>> {
        //let db = marf_sqlite_open(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
        let db = self.db.reopen_readonly()?;
        let blobs = if self.blobs.is_some() {
            Some(TrieFile::from_db_path(&self.db_path, true)?)
        } else {
            None
        };

        trace!(
            "Make read-only view of TrieStorageTransaction: {}",
            &self.db_path
        );

        let cache = TrieCache::default();

        // TODO: borrow self.uncommitted_writes; don't copy them
        let ret = TrieFileStorage {
            db_path: self.db_path.to_string(),
            db: db,
            blobs: blobs,
            cache: cache,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: self.hash_calculation_mode,

            data: TrieStorageTransientData {
                uncommitted_writes: None,
                cur_block: Id::sentinel(),
                cur_block_id: None,

                read_count: 0,
                read_backptr_count: 0,
                read_node_count: 0,
                read_leaf_count: 0,

                write_count: 0,
                write_node_count: 0,
                write_leaf_count: 0,

                trie_ancestor_hash_bytes_cache: None,

                is_readonly: true,
                unconfirmed: self.unconfirmed(),
            },

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: self.test_genesis_block.clone(),
        };

        Ok(ret)
    }

    /// Run `cls` with a mutable reference to the inner trie blobs opt.
    fn with_trie_blobs<F, R>(&mut self, cls: F) -> R
    where
        F: FnOnce(&TrieDB, &mut Option<&mut TrieFile>) -> R,
    {
        let mut blobs = self.blobs.take();
        let res = cls(&self.db, &mut blobs);
        self.blobs = blobs;
        res
    }

    /// Inner method for flushing the UncommittedState's TrieRAM to disk.
    fn inner_flush(&mut self, flush_options: FlushOptions<'_, Id>) -> Result<()> {
        // save the currently-buffered Trie to disk, and atomically put it into place (possibly to
        // a different block than the one opened, as indicated by final_bhh).
        // Runs once -- subsequent calls are no-ops.
        // Panics on a failure to rename the Trie file into place (i.e. if the the actual commitment
        // fails).
        self.clear_cached_ancestor_hashes_bytes();
        if self.data.is_readonly {
            return Err(MarfError::ReadOnlyError);
        }
        if let Some((bhh, trie_ram)) = self.data.uncommitted_writes.take() {
            trace!("Buffering block flush started.");
            let mut buffer = Cursor::new(Vec::new());
            trie_ram.dump(self, &mut buffer, &bhh)?;

            // consume the cursor, get the buffer
            let buffer = buffer.into_inner();
            trace!("Buffering block flush finished.");

            debug!("Flush: {} to {}", &bhh, flush_options);

            let block_id = match flush_options {
                FlushOptions::CurrentHeader => {
                    if self.unconfirmed() {
                        return Err(MarfError::UnconfirmedError);
                    }
                    self.with_trie_blobs(|db, blobs| match blobs {
                        Some(blobs) => blobs.store_trie_blob(db, &bhh, &buffer),
                        None => {
                            test_debug!("Stored trie blob {} to db", &bhh);
                            db.write_trie_blob(&bhh, &buffer)
                        }
                    })?
                }
                FlushOptions::NewHeader(real_bhh) => {
                    // If we opened a block with a given hash, but want to store it as a block with a *different*
                    // hash, then call this method to update the internal storage state to make it so.  This is
                    // necessary for validating blocks in the blockchain, since the miner will always build a
                    // block whose hash is all 0's (since it can't know the final block hash).  As such, a peer
                    // will process a block as if it's hash is all 0's (in order to validate the state root), and
                    // then use this method to switch over the block hash to the "real" block hash.
                    if self.data.unconfirmed {
                        return Err(MarfError::UnconfirmedError);
                    }
                    if real_bhh != &bhh {
                        // note: this was moved from the block_retarget function
                        //  to avoid stepping on the borrow checker.
                        debug!("Retarget block {} to {}", bhh, real_bhh);
                        // switch over state
                        self.data.retarget_block(real_bhh.clone());
                    }
                    self.with_trie_blobs(|db, blobs| match blobs {
                        Some(blobs) => blobs.store_trie_blob(db, real_bhh, &buffer),
                        None => {
                            test_debug!("Stored trie blob {} to db", real_bhh);
                            db.write_trie_blob(real_bhh, &buffer)
                        }
                    })?
                }
                FlushOptions::MinedTable(real_bhh) => {
                    if self.unconfirmed() {
                        return Err(MarfError::UnconfirmedError);
                    }
                    self.db.write_trie_blob_to_mined(real_bhh, &buffer)?
                }
                FlushOptions::UnconfirmedTable => {
                    if !self.unconfirmed() {
                        return Err(MarfError::UnconfirmedError);
                    }
                    self.db.write_trie_blob_to_unconfirmed(&bhh, &buffer)?
                    //trie_sql::write_trie_blob_to_unconfirmed(&self.db, &bhh, &buffer)?
                }
            };

            //trie_sql::drop_lock(&self.db, &bhh)?;
            self.db.drop_lock(&bhh)?;

            debug!("Flush: identifier of {} is {}", flush_options, block_id);
        }

        Ok(())
    }

    /// Flush uncommitted state to disk.
    pub fn flush(&mut self) -> Result<()> {
        if self.data.unconfirmed {
            self.inner_flush(FlushOptions::UnconfirmedTable)
        } else {
            self.inner_flush(FlushOptions::CurrentHeader)
        }
    }

    /// Flush uncommitted state to disk, but under the given block hash.
    pub fn flush_to(&mut self, bhh: &Id) -> Result<()> {
        self.inner_flush(FlushOptions::NewHeader(bhh))
    }

    /// Flush uncommitted state to disk for a mined block (i.e. not part of the chainstate, and not
    /// an ancestor of any block), and do so under a given block hash.
    pub fn flush_mined(&mut self, bhh: &Id) -> Result<()> {
        self.inner_flush(FlushOptions::MinedTable(bhh))
    }

    /// Drop the uncommitted state and any associated cached state.
    pub fn drop_extending_trie(&mut self) {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.is_readonly {
            if let Some((ref bhh, _)) = self.data.uncommitted_writes.take() {
                self.db.drop_lock(bhh)
                    .expect("Corruption: Failed to drop the extended trie lock");
            }
            self.data.uncommitted_writes = None;
            self.data.clear_block_id();
            self.data.trie_ancestor_hash_bytes_cache = None;
        }
    }

    /// Drop the unconfirmed state and uncommitted state.
    pub fn drop_unconfirmed_trie(&mut self, bhh: &Id) {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.is_readonly && self.data.unconfirmed {
            self.db.drop_unconfirmed_trie(bhh)
                .expect("Corruption: Failed to drop unconfirmed trie");
            self.db.drop_lock(bhh)
                .expect("Corruption: Failed to drop the extended trie lock");
            self.data.uncommitted_writes = None;
            self.data.clear_block_id();
            self.data.trie_ancestor_hash_bytes_cache = None;
        }
    }

    /// Seal the inner uncommitted TrieRAM and return the MARF root hash.
    /// Only works if there's an uncommitted TrieRAM extension; panics if not.
    pub fn seal(&mut self) -> Result<TrieHash> {
        if let Some((bhh, trie_ram)) = self.data.uncommitted_writes.take() {
            let sealed_trie_ram = trie_ram.seal(self)?;
            let root_hash = match sealed_trie_ram {
                UncommittedState::Sealed(_, root_hash) => root_hash.clone(),
                _ => {
                    unreachable!("FATAL: .seal() did not make a sealed trieram");
                }
            };
            self.data.uncommitted_writes = Some((bhh, sealed_trie_ram));
            Ok(root_hash)
        } else {
            panic!("FATAL: tried to a .seal() a trie that was not extended");
        }
    }

    /// Extend the forest of Tries to include a new confirmed block.
    /// Fails if the block already exists, or if the storage is read-only, or open
    /// only for unconfirmed state.
    pub fn extend_to_block(&mut self, bhh: &Id) -> Result<()> {
        self.clear_cached_ancestor_hashes_bytes();
        if self.data.is_readonly {
            return Err(MarfError::ReadOnlyError);
        }
        if self.data.unconfirmed {
            return Err(MarfError::UnconfirmedError);
        }

        if self.get_block_id_caching(bhh).is_ok() {
            warn!("Block already exists: {}", &bhh);
            return Err(MarfError::ExistsError);
        }

        self.flush()?;

        let size_hint = match self.data.uncommitted_writes {
            Some((_, ref trie_storage)) => 2 * trie_storage.size_hint(),
            None => 1024, // don't try to guess _byte_ allocation here.
        };

        let trie_buf = TrieRAM::new(bhh, size_hint, &self.data.cur_block);

        // place a lock on this block, so we can't extend to it again
        if !self.db_tx.lock_bhh_for_extension(bhh, false)? {
            warn!("Block already extended: {}", &bhh);
            return Err(MarfError::ExistsError);
        }

        self.switch_trie(bhh, UncommittedState::RW(trie_buf));
        Ok(())
    }

    /// Extend the forest of Tries to include a new unconfirmed block.
    /// If the unconfirmed block (bhh) already exists, then load up its trie as the uncommitted_writes
    /// trie.
    pub fn extend_to_unconfirmed_block(&mut self, bhh: &Id) -> Result<bool> {
        self.clear_cached_ancestor_hashes_bytes();
        if !self.data.unconfirmed {
            return Err(MarfError::UnconfirmedError);
        }

        self.flush()?;

        // try to load up the trie
        let (trie_buf, created, unconfirmed_block_id) =
            if let Some(block_id) = self.db.get_unconfirmed_block_identifier(bhh)? {
                debug!("Reload unconfirmed trie {} ({})", bhh, block_id);

                // restore trie
                let fd = self.db.open_trie_blob(block_id)?;
                let mut cursor = Cursor::new(fd);

                test_debug!("Unconfirmed trie block ID for {} is {}", bhh, block_id);
                (TrieRAM::load(&mut cursor, bhh)?, false, Some(block_id))
            } else {
                debug!("Instantiate unconfirmed trie {}", bhh);

                // new trie
                let size_hint = match self.data.uncommitted_writes {
                    Some((_, ref trie_storage)) => 2 * trie_storage.size_hint(),
                    None => 1024, // don't try to guess _byte_ allocation here.
                };

                (
                    TrieRAM::new(bhh, size_hint, &self.data.cur_block),
                    true,
                    None,
                )
            };

        // place a lock on this block, so we can't extend to it again
        if !self.db.tx_lock_bhh_for_extension(bhh, true)? {
            warn!("Block already extended: {}", &bhh);
            return Err(MarfError::ExistsError);
        }

        self.unconfirmed_block_id = unconfirmed_block_id;
        self.switch_trie(bhh, UncommittedState::RW(trie_buf));
        Ok(created)
    }

    /// Clear out the underlying storage.
    pub fn format(&mut self) -> Result<()> {
        if self.data.is_readonly {
            return Err(MarfError::ReadOnlyError);
        }

        debug!("Format TrieFileStorage");

        // blow away db
        self.db.format()?;

        match self.data.uncommitted_writes {
            Some((_, ref mut trie_storage)) => trie_storage.format()?,
            None => {}
        };

        self.data.set_block(Id::sentinel(), None);

        self.data.uncommitted_writes = None;
        self.clear_cached_ancestor_hashes_bytes();

        Ok(())
    }

    pub fn commit(self) {
        // TODO: Commit
    }

    pub fn rollback(self) {
        // TODO: Rollback
    }
}

impl<'a, Id, TrieDB> TrieStorageConnection<'a, Id, TrieDB> 
where
    Id: MarfTrieId,
    TrieDB: TrieDb
{
    pub fn readonly(&self) -> bool {
        self.data.is_readonly
    }

    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    pub fn set_cached_ancestor_hashes_bytes(&mut self, bhh: &Id, bytes: Vec<TrieHash>) {
        self.data.trie_ancestor_hash_bytes_cache = Some((bhh.clone(), bytes));
    }

    pub fn clear_cached_ancestor_hashes_bytes(&mut self) {
        self.data.trie_ancestor_hash_bytes_cache = None;
    }

    pub fn get_root_hash_at(&mut self, tip: &Id) -> Result<TrieHash> {
        let cur_block_hash = self.get_cur_block();

        self.open_block(tip)?;
        let root_hash_res = read_root_hash(self);

        // restore
        self.open_block(&cur_block_hash)?;
        root_hash_res
    }

    pub fn check_cached_ancestor_hashes_bytes(&mut self, bhh: &Id) -> Option<Vec<TrieHash>> {
        if let Some((ref cached_bhh, ref cached_bytes)) = self.data.trie_ancestor_hash_bytes_cache {
            if cached_bhh == bhh {
                return Some(cached_bytes.clone());
            }
        }
        None
    }

    #[cfg(test)]
    pub fn stats(&mut self) -> (u64, u64) {
        let r = self.data.read_count;
        let w = self.data.write_count;
        self.data.read_count = 0;
        self.data.write_count = 0;
        (r, w)
    }

    #[cfg(test)]
    pub fn node_stats(&mut self) -> (u64, u64, u64) {
        let nr = self.data.read_node_count;
        let br = self.data.read_backptr_count;
        let nw = self.data.write_node_count;

        self.data.read_node_count = 0;
        self.data.read_backptr_count = 0;
        self.data.write_node_count = 0;

        (nr, br, nw)
    }

    #[cfg(test)]
    pub fn leaf_stats(&mut self) -> (u64, u64) {
        let lr = self.data.read_leaf_count;
        let lw = self.data.write_leaf_count;

        self.data.read_leaf_count = 0;
        self.data.write_leaf_count = 0;

        (lr, lw)
    }

    /// Recover from partially-written state -- i.e. blow it away.
    /// Doesn't get called automatically.
    /*pub fn recover(db_path: &String) -> Result<()> {
        let conn: dyn TrieDb = marf_sqlite_open(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE, false)?;
        conn.clear_lock_data()
    }*/

    /// Read the Trie root node's hash from the block table.
    #[cfg(test)]
    pub fn read_block_root_hash(&mut self, bhh: &Id) -> Result<TrieHash> {
        let root_hash_ptr = TriePtr::new(
            TrieNodeID::Node256 as u8,
            0,
            TrieStorageConnection::<Id, TrieDB>::root_ptr_disk(),
        );
        if let Some(blobs) = self.blobs.as_mut() {
            // stored in a blobs file
            blobs.get_node_hash_bytes_by_bhh(self.db, bhh, &root_hash_ptr)
        } else {
            // stored to DB
            self.db.get_node_hash_bytes_by_bhh(bhh, &root_hash_ptr)
        }
    }

    /// internal procedure for locking a trie hash for work
    fn switch_trie(&mut self, bhh: &Id, trie_buf: UncommittedState<Id>) {
        trace!("Extended from {} to {}", &self.data.cur_block, bhh);

        // update internal structures
        self.data.set_block(bhh.clone(), None);
        self.clear_cached_ancestor_hashes_bytes();

        self.data.uncommitted_writes = Some((bhh.clone(), trie_buf));
    }

    /// Is the given block in the marf_data DB table, and is it part of the block history (i.e. it's not mined and
    /// its not unconfirmed)?
    pub fn has_confirmed_block(&self, bhh: &Id) -> Result<bool> {
        match self.db.get_confirmed_block_identifier(bhh) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Is the given block in the marf_data DB table, and is it unconfirmed?
    pub fn has_unconfirmed_block(&self, bhh: &Id) -> Result<bool> {
        match self.db.get_unconfirmed_block_identifier(bhh) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Is the given block represented in either the confirmed or unconfirmed block tables?
    /// The mined table is ignored.
    pub fn has_block(&self, bhh: &Id) -> Result<bool> {
        Ok(self.has_confirmed_block(bhh)? || self.has_unconfirmed_block(bhh)?)
    }

    /// Used for providing a option<block identifier> when re-opening a block --
    ///   because the previously open block may have been the uncommitted_writes block,
    ///   id may have been None.
    pub fn open_block_maybe_id(&mut self, bhh: &Id, id: Option<u32>) -> Result<()> {
        match id {
            Some(id) => self.open_block_known_id(bhh, id),
            None => self.open_block(bhh),
        }
    }

    /// Used for providing a block identifier when opening a block -- usually used
    ///   when following a backptr, which stores the block identifier directly.
    pub fn open_block_known_id(&mut self, bhh: &Id, id: u32) -> Result<()> {
        trace!(
            "open_block_known_id({},{}) (unconfirmed={:?},{})",
            bhh,
            id,
            &self.unconfirmed_block_id,
            self.unconfirmed()
        );
        if *bhh == self.data.cur_block && self.data.cur_block_id.is_some() {
            // no-op
            return Ok(());
        }

        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if uncommitted_bhh == bhh {
                panic!("BUG: passed id of a currently building block");
            }
        }

        // opening a different Trie than the one we're extending
        self.data.set_block(bhh.clone(), Some(id));
        Ok(())
    }

    /// Open a trie's block, identified by `bhh`.  Updates the internal state to point to it, so
    /// that all node reads will occur relative to it.
    pub fn open_block(&mut self, bhh: &Id) -> Result<()> {
        trace!(
            "open_block({}) (unconfirmed={:?},{})",
            bhh,
            &self.unconfirmed_block_id,
            self.unconfirmed()
        );
        self.bench.open_block_start();

        if *bhh == self.data.cur_block && self.data.cur_block_id.is_some() {
            // no-op
            if self.unconfirmed() {
                if self.data.cur_block_id
                    == self.db.get_unconfirmed_block_identifier(bhh)?
                {
                    test_debug!(
                        "{} unconfirmed trie block ID is {:?}",
                        bhh,
                        &self.data.cur_block_id
                    );
                    self.unconfirmed_block_id = self.data.cur_block_id.clone();
                }
            }

            self.bench.open_block_finish(true);
            return Ok(());
        }

        let sentinel = Id::sentinel();
        if *bhh == sentinel {
            // just reset to newly opened state
            // did we write to the sentinel?
            let block_id_opt = self.get_block_id_caching(bhh).ok();
            self.data.set_block(sentinel, block_id_opt);
            self.bench.open_block_finish(true);
            return Ok(());
        }

        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if uncommitted_bhh == bhh {
                // nothing to do -- we're already ready.
                // just clear out.
                if self.unconfirmed() {
                    if self.data.cur_block_id
                        == self.db.get_unconfirmed_block_identifier(bhh)?
                    {
                        test_debug!(
                            "{} unconfirmed trie block ID is {:?}",
                            bhh,
                            &self.data.cur_block_id
                        );
                        self.unconfirmed_block_id = self.data.cur_block_id.clone();
                    }
                }
                self.data.set_block(bhh.clone(), None);
                self.bench.open_block_finish(true);
                return Ok(());
            }
        }

        if self.unconfirmed() {
            if let Some(block_id) = self.db.get_unconfirmed_block_identifier(bhh)? {
                // this is an unconfirmed trie being opened
                self.data.set_block(bhh.clone(), Some(block_id));
                self.bench.open_block_finish(false);

                // reads to this block will hit sqlite
                test_debug!("{} unconfirmed trie block ID is {}", bhh, block_id);
                self.unconfirmed_block_id = Some(block_id);
                return Ok(());
            }
        }

        // opening a different Trie than the one we're extending
        let block_id = self.get_block_id_caching(bhh).map_err(|e| {
            test_debug!("Failed to open {:?}: {:?}", bhh, e);
            e
        })?;

        self.data.set_block(bhh.clone(), Some(block_id));
        self.bench.open_block_finish(false);
        Ok(())
    }

    /// Return the block_identifier / row_id for a given bhh. If that bhh
    ///  is currently being extended, return None, since the row_id won't
    ///  be known until the extended trie is flushed.
    pub fn get_block_identifier(&mut self, bhh: &Id) -> Option<u32> {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if bhh == uncommitted_bhh {
                return None;
            }
        }

        self.get_block_id_caching(bhh).ok()
    }

    /// Get the currently-open block identifier (its row ID)
    pub fn get_cur_block_identifier(&self) -> Result<u32> {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if &self.data.cur_block == uncommitted_bhh {
                return Err(MarfError::RequestedIdentifierForExtensionTrie);
            }
        }

        self.data.cur_block_id.ok_or_else(|| MarfError::NotOpenedError)
    }

    /// Get the currently-open block hash
    pub fn get_cur_block(&self) -> Id {
        self.data.cur_block.clone()
    }

    /// Get the currently-open block hash and block ID (row ID)
    pub fn get_cur_block_and_id(&self) -> (Id, Option<u32>) {
        (self.data.cur_block.clone(), self.data.cur_block_id.clone())
    }

    /// Get the block hash of a given block ID (i.e. row ID)
    pub fn get_block_from_local_id(&mut self, local_id: u32) -> Result<&Id> {
        let res = self.get_block_hash_caching(local_id);
        res
    }

    /// Get the TriePtr::ptr() value for the root node in the currently-open block.
    pub fn root_ptr(&self) -> u32 {
        if let Some((ref uncommitted_bhh, _)) = self.data.uncommitted_writes {
            if &self.data.cur_block == uncommitted_bhh {
                return 0;
            }
        }

        TrieStorageConnection::<Id, TrieDB>::root_ptr_disk()
    }

    /// Get a TriePtr to the currently-open block's trie's root node.
    pub fn root_trieptr(&self) -> TriePtr {
        TriePtr::new(TrieNodeID::Node256 as u8, 0, self.root_ptr())
    }

    /// Get the TriePtr::ptr() value for a trie's root node if the node is stored to disk.
    pub fn root_ptr_disk() -> u32 {
        // first 32 bytes are the block parent hash
        //   next 4 are the identifier
        (BLOCK_HEADER_HASH_ENCODED_SIZE as u32) + 4
    }

    /// Read a node's children's hashes into the provided <Write> implementation.
    /// This only works for intermediate nodes and leafs (the latter of which have no children).
    ///
    /// This method is designed to only access hashes that are either (1) in this Trie, or (2) in
    /// RAM already (i.e. as part of the block map)
    ///
    /// This means that the hash of a node that is in a previous Trie will _not_ be its
    /// hash (as that would require a disk access), but would instead be the root hash of the Trie
    /// that contains it.  While this makes the Merkle proof construction a bit more complicated,
    /// it _significantly_ improves the performance of this method (which is crucial since this is on
    /// the write path, which must be as short as possible).
    ///
    /// Rules:
    /// If a node is empty, pass in an empty hash.
    /// If a node is in this Trie, pass its hash.
    /// If a node is in a previous Trie, pass the root hash of its Trie.
    ///
    /// On err, S may point to a prior block.  The caller should call s.open(...) if an error
    /// occurs.
    ///
    /// NOTE: this method should only be called if `hash_calculation_mode` is set to
    /// `TrieHashCalculationMode::All` or `TrieHashCalculationMode::Immediate`.  There is no need
    /// to call if the hash mode is `::Deferred`.  The only way this gets called while not in
    /// `::Deferred` mode is when generating a Merkle proof.
    pub fn write_children_hashes<W: Write>(
        &mut self,
        node: &TrieNodeType,
        w: &mut W,
    ) -> Result<()> {
        if self.data.is_readonly {
            return Err(MarfError::ReadOnlyError);
        }

        trace!("write_children_hashes for {:?}", node);

        let mut map = TrieSqlHashMapCursor {
            db: self.db,
            cache: &mut self.cache,
            unconfirmed: self.data.unconfirmed,
        };

        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                // storage currently points to uncommitted state
                let start_time = self.bench.write_children_hashes_start();
                let res = TrieStorageConnection::<Id, TrieDB>::inner_write_children_hashes(
                    uncommitted_trie.trie_ram_mut(),
                    &mut map,
                    node,
                    w,
                    &mut self.bench,
                );
                self.bench.write_children_hashes_finish(start_time, true);
                return res;
            }
        }

        // storage points to committed state
        if let Some(blobs) = self.blobs.as_mut() {
            // tries stored on file
            let start_time = self.bench.write_children_hashes_start();
            let block_id = self.data.cur_block_id.ok_or_else(|| {
                error!("Failed to get cur block as hash reader");
                MarfError::NotFoundError
            })?;
            let mut cursor = TrieFileNodeHashReader::new(self.db, blobs, block_id);
            let res = TrieStorageConnection::<Id, TrieDB>::inner_write_children_hashes(
                &mut cursor,
                &mut map,
                node,
                w,
                &mut self.bench,
            );
            self.bench.write_children_hashes_finish(start_time, false);
            res
        } else {
            // tries stored in DB
            let start_time = self.bench.write_children_hashes_start();
            let mut cursor = TrieSqlCursor {
                db: self.db,
                block_id: self.data.cur_block_id.ok_or_else(|| {
                    error!("Failed to get cur block as hash reader");
                    MarfError::NotFoundError
                })?,
            };
            let res = TrieStorageConnection::<Id, TrieDB>::inner_write_children_hashes(
                &mut cursor,
                &mut map,
                node,
                w,
                &mut self.bench,
            );
            self.bench.write_children_hashes_finish(start_time, false);
            res
        }
    }

    /// Inner method for calculating a node's hash, by hashing its children.
    fn inner_write_children_hashes<W: Write, H: NodeHashReader, M: BlockMap>(
        hash_reader: &mut H,
        map: &mut M,
        node: &TrieNodeType,
        w: &mut W,
        bench: &mut TrieBenchmark,
    ) -> Result<()> {
        trace!("inner_write_children_hashes begin for node {:?}:", &node);
        for ptr in node.ptrs().iter() {
            if ptr.id() == TrieNodeID::Empty as u8 {
                // hash of empty string
                let start_time = bench.write_children_hashes_empty_start();

                trace!(
                    "inner_write_children_hashes for node {:?}: {:?} empty",
                    &node,
                    &ptr
                );
                w.write_all(TrieHash::from_data(&[]).as_bytes())?;

                bench.write_children_hashes_empty_finish(start_time);
            } else if !is_backptr(ptr.id()) {
                // hash is in the same block as this node
                let start_time = bench.write_children_hashes_same_block_start();

                let mut buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
                hash_reader.read_node_hash_bytes(ptr, &mut buf)?;
                trace!(
                    "inner_write_children_hashes for node {:?}: {:?} same block {}",
                    &node,
                    &ptr,
                    &to_hex(&buf)
                );
                w.write_all(&buf[..])?;

                bench.write_children_hashes_same_block_finish(start_time);
            } else {
                // hash is in a different block altogether, so we just use the ancestor block hash.  The
                // ptr.ptr() value points to the actual node in the ancestor block.
                let start_time = bench.write_children_hashes_ancestor_block_start();

                let block_hash = map.get_block_hash_caching(ptr.back_block())?;
                trace!(
                    "inner_write_children_hashes for node {:?}: {:?} back block {:?}",
                    &node,
                    &ptr,
                    &block_hash
                );
                w.write_all(block_hash.as_bytes())?;

                bench.write_children_hashes_ancestor_block_finish(start_time);
            }
        }
        trace!("inner_write_children_hashes end for node {:?}:", &node);

        Ok(())
    }

    /// read a persisted node's hash
    fn inner_read_persisted_node_hash(
        &mut self,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash> {
        if self.unconfirmed_block_id == Some(block_id) {
            // read from unconfirmed trie
            test_debug!(
                "Read persisted node hash from unconfirmed block id {}",
                block_id
            );
            return self.db.get_node_hash_bytes(block_id, ptr);
        }
        let node_hash = match self.blobs.as_mut() {
            Some(blobs) => blobs.get_node_hash_bytes(self.db, block_id, ptr),
            None => self.db.get_node_hash_bytes(block_id, ptr),
        }?;
        Ok(node_hash)
    }

    /// Read a persisted node's hash
    pub fn read_node_hash_bytes(&mut self, ptr: &TriePtr) -> Result<TrieHash> {
        if let Some((ref uncommitted_bhh, ref mut trie_ram)) = self.data.uncommitted_writes {
            // special case
            if &self.data.cur_block == uncommitted_bhh {
                return trie_ram.read_node_hash(ptr);
            }
        }

        // some other block or ptr
        match self.data.cur_block_id {
            Some(block_id) => {
                self.bench.read_node_hash_start();
                if let Some(node_hash) = self.cache.load_node_hash(block_id, ptr) {
                    let res = node_hash;
                    self.bench.read_node_hash_finish(true);
                    Ok(res)
                } else {
                    let node_hash = self.inner_read_persisted_node_hash(block_id, ptr)?;
                    self.cache
                        .store_node_hash(block_id, ptr.clone(), node_hash.clone());
                    self.bench.read_node_hash_finish(false);
                    Ok(node_hash)
                }
            }
            None => {
                error!("Not found (no file is open)");
                Err(MarfError::NotFoundError)
            }
        }
    }

    /// Read a persisted node and its hash.
    pub fn read_nodetype(&mut self, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash)> {
        self.read_nodetype_maybe_hash(ptr, true)
    }

    /// Read a persisted node
    pub fn read_nodetype_nohash(&mut self, ptr: &TriePtr) -> Result<TrieNodeType> {
        self.read_nodetype_maybe_hash(ptr, false)
            .map(|(node, _)| node)
    }

    /// Inner method for reading a node, and optionally its hash as well.
    /// Uses either the DB or the .blobs file, depending on which is configured.
    /// If `read_hash` is `false`, then the returned hash is just the empty hash of all 0's.
    fn inner_read_persisted_nodetype(
        &mut self,
        block_id: u32,
        ptr: &TriePtr,
        read_hash: bool,
    ) -> Result<(TrieNodeType, TrieHash)> {
        trace!(
            "inner_read_persisted_nodetype({}): {:?} (unconfirmed={:?},{})",
            block_id,
            ptr,
            &self.unconfirmed_block_id,
            self.unconfirmed()
        );
        if self.unconfirmed_block_id == Some(block_id) {
            trace!("Read persisted node from unconfirmed block id {}", block_id);

            // read from unconfirmed trie
            if read_hash {
                return self.db.read_node_type(block_id, &ptr);
            } else {
                return self.db.read_node_type_nohash(block_id, &ptr)
                    .map(|node| (node, TrieHash([0u8; TRIEHASH_ENCODED_SIZE])));
            }
        }
        let (node_inst, node_hash) = match self.blobs.as_mut() {
            Some(blobs) => {
                if read_hash {
                    blobs.read_node_type(self.db, block_id, &ptr)?
                } else {
                    blobs
                        .read_node_type_nohash(self.db, block_id, &ptr)
                        .map(|node| (node, TrieHash([0u8; TRIEHASH_ENCODED_SIZE])))?
                }
            }
            None => {
                if read_hash {
                    self.db.read_node_type(block_id, &ptr)?
                } else {
                    self.db.read_node_type_nohash(block_id, &ptr)
                        .map(|node| (node, TrieHash([0u8; TRIEHASH_ENCODED_SIZE])))?
                }
            }
        };
        Ok((node_inst, node_hash))
    }

    /// Read a node and optionally its hash.  If `read_hash` is false, then an empty hash will be
    /// returned
    /// NOTE: ptr will not be treated as a backptr -- the node returned will be from the
    /// currently-open trie.
    fn read_nodetype_maybe_hash(
        &mut self,
        ptr: &TriePtr,
        read_hash: bool,
    ) -> Result<(TrieNodeType, TrieHash)> {
        trace!("read_nodetype({:?}): {:?}", &self.data.cur_block, ptr);

        self.data.read_count += 1;
        if is_backptr(ptr.id()) {
            self.data.read_backptr_count += 1;
        } else if ptr.id() == TrieNodeID::Leaf as u8 {
            self.data.read_leaf_count += 1;
        } else {
            self.data.read_node_count += 1;
        }

        let clear_ptr = ptr.from_backptr();

        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            // special case
            if &self.data.cur_block == uncommitted_bhh {
                return uncommitted_trie.read_nodetype(&clear_ptr);
            }
        }

        // some other block
        match self.data.cur_block_id {
            Some(id) => {
                self.bench.read_nodetype_start();
                let (node_inst, node_hash) = if read_hash {
                    if let Some((node_inst, node_hash)) =
                        self.cache.load_node_and_hash(id, &clear_ptr)
                    {
                        (node_inst, node_hash)
                    } else {
                        let (node_inst, node_hash) =
                            self.inner_read_persisted_nodetype(id, &clear_ptr, read_hash)?;
                        self.cache.store_node_and_hash(
                            id,
                            clear_ptr.clone(),
                            node_inst.clone(),
                            node_hash.clone(),
                        );
                        (node_inst, node_hash)
                    }
                } else {
                    if let Some(node_inst) = self.cache.load_node(id, &clear_ptr) {
                        (node_inst, TrieHash([0u8; TRIEHASH_ENCODED_SIZE]))
                    } else {
                        let (node_inst, _) =
                            self.inner_read_persisted_nodetype(id, &clear_ptr, read_hash)?;
                        self.cache
                            .store_node(id, clear_ptr.clone(), node_inst.clone());
                        (node_inst, TrieHash([0u8; TRIEHASH_ENCODED_SIZE]))
                    }
                };

                self.bench.read_nodetype_finish(false);
                Ok((node_inst, node_hash))
            }
            None => {
                debug!("Not found (no file is open)");
                Err(MarfError::NotFoundError)
            }
        }
    }

    /// Store a node and its hash to the uncommitted state.
    /// If the uncommitted state is not instantiated, then this panics.
    pub fn write_nodetype(
        &mut self,
        disk_ptr: u32,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<()> {
        if self.data.is_readonly {
            return Err(MarfError::ReadOnlyError);
        }

        trace!(
            "write_nodetype({:?}): at {}: {:?} {:?}",
            &self.data.cur_block,
            disk_ptr,
            &hash,
            node
        );

        self.data.write_count += 1;
        match node {
            TrieNodeType::Leaf(_) => {
                self.data.write_leaf_count += 1;
            }
            _ => {
                self.data.write_node_count += 1;
            }
        }

        // Only allow writes when the cur_block is the current in-RAM extending block.
        if let Some((ref uncommitted_bhh, ref mut uncommitted_trie)) = self.data.uncommitted_writes
        {
            if &self.data.cur_block == uncommitted_bhh {
                return uncommitted_trie.write_nodetype(disk_ptr, node, hash);
            }
        }

        panic!("Tried to write to another Trie besides the currently-buffered one.  This should never happen -- only flush() can write to disk!");
    }

    /// Store a node and its hash to uncommitted state.
    pub fn write_node<N: TrieNode + std::fmt::Debug>(
        &mut self,
        ptr: u32,
        node: &N,
        hash: TrieHash,
    ) -> Result<()> {
        if self.data.is_readonly {
            return Err(MarfError::ReadOnlyError);
        }

        let node_type = node.as_trie_node_type();
        self.write_nodetype(ptr, &node_type, hash)
    }

    /// Get the last slot into which a node will be inserted in the uncommitted state.
    /// Panics if there is no uncommmitted state instantiated.
    pub fn last_ptr(&mut self) -> Result<u32> {
        if let Some((_, ref mut uncommitted_trie)) = self.data.uncommitted_writes {
            uncommitted_trie.last_ptr()
        } else {
            panic!("Cannot allocate new ptrs in a Trie that is not in RAM");
        }
    }

    /// Count up the number of trie blocks this storage represents
    pub fn num_blocks(&self) -> usize {
        let result = if self.data.uncommitted_writes.is_some() {
            1
        } else {
            0
        };
        result
            + (self.db.count_blocks()
                .expect("Corruption: SQL Error on a non-fallible query.") as usize)
    }

    pub fn get_benchmarks(&self) -> TrieBenchmark {
        self.bench.clone()
    }

    pub fn bench_mut(&mut self) -> &mut TrieBenchmark {
        self.bench
    }

    pub fn reset_benchmarks(&mut self) {
        self.bench.reset();
    }

    #[cfg(test)]
    pub fn transient_data(&self) -> &TrieStorageTransientData<Id> {
        &self.data
    }

    #[cfg(test)]
    pub fn transient_data_mut(&mut self) -> &mut TrieStorageTransientData<Id> {
        &mut self.data
    }
}
