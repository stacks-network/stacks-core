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

use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::DerefMut;
use std::path::PathBuf;

use rusqlite::{Connection, Transaction};
use sha2::Digest;

use crate::chainstate::stacks::index::bits::{get_leaf_hash, get_node_hash, read_root_hash};
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, set_backptr, CursorError, TrieCursor, TrieNode, TrieNode16,
    TrieNode256, TrieNode4, TrieNode48, TrieNodeID, TrieNodeType, TriePath, TriePtr, TRIEPTR_SIZE,
};
use crate::chainstate::stacks::index::storage::{
    TrieFileStorage, TrieStorageConnection, TrieStorageTransaction,
};
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::Error;
use crate::chainstate::stacks::index::MARFValue;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::util_lib::db::Error as db_error;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::log;

use crate::chainstate::stacks::index::TrieHashExtension;
use crate::chainstate::stacks::index::{ClarityMarfTrieId, TrieLeaf, TrieMerkleProof};
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::TRIEHASH_ENCODED_SIZE;

pub const BLOCK_HASH_TO_HEIGHT_MAPPING_KEY: &str = "__MARF_BLOCK_HASH_TO_HEIGHT";
pub const BLOCK_HEIGHT_TO_HASH_MAPPING_KEY: &str = "__MARF_BLOCK_HEIGHT_TO_HASH";
pub const OWN_BLOCK_HEIGHT_KEY: &str = "__MARF_BLOCK_HEIGHT_SELF";

/// Merklized Adaptive-Radix Forest -- a collection of Merklized Adaptive-Radix Tries.
pub struct MARF<T: MarfTrieId> {
    storage: TrieFileStorage<T>,
    open_chain_tip: Option<WriteChainTip<T>>,
}

pub struct MarfTransaction<'a, T: MarfTrieId> {
    storage: TrieStorageTransaction<'a, T>,
    open_chain_tip: &'a mut Option<WriteChainTip<T>>,
}

#[derive(Clone)]
struct WriteChainTip<T> {
    block_hash: T,
    height: u32,
}

///
/// This trait defines functions that are defined for both
///  MARF structs and MarfTransactions
///
pub trait MarfConnection<T: MarfTrieId> {
    fn with_conn<F, R>(&mut self, exec: F) -> R
    where
        F: FnOnce(&mut TrieStorageConnection<T>) -> R;

    fn sqlite_conn(&self) -> &Connection;

    /// Resolve a key from the MARF to a MARFValue with respect to the given block height.
    fn get(&mut self, block_hash: &T, key: &str) -> Result<Option<MARFValue>, Error> {
        self.with_conn(|c| MARF::get_by_key(c, block_hash, key))
    }

    fn get_with_proof(
        &mut self,
        block_hash: &T,
        key: &str,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        self.with_conn(|conn| {
            let marf_value = match MARF::get_by_key(conn, block_hash, key)? {
                None => return Ok(None),
                Some(x) => x,
            };
            let proof = TrieMerkleProof::from_raw_entry(conn, key, &marf_value, block_hash)?;
            Ok(Some((marf_value, proof)))
        })
    }

    fn get_block_at_height(&mut self, height: u32, tip: &T) -> Result<Option<T>, Error> {
        self.with_conn(|c| MARF::get_block_at_height(c, height, tip))
    }

    fn get_block_height(&mut self, ancestor: &T, tip: &T) -> Result<Option<u32>, Error> {
        self.with_conn(|c| MARF::get_block_height(c, ancestor, tip))
    }

    /// Get the current root trie hash
    fn get_root_hash(&mut self) -> Result<TrieHash, Error> {
        self.with_conn(|c| read_root_hash(c))
    }

    /// Get the root trie hash at a particular block
    fn get_root_hash_at(&mut self, block_hash: &T) -> Result<TrieHash, Error> {
        self.with_conn(|c| c.get_root_hash_at(block_hash))
    }

    /// Check if a block can open successfully, i.e.,
    ///   it's a known block, the storage system isn't issueing IOErrors, _and_ it's in the same fork
    ///   as the current block
    /// The MARF _must_ be open to a valid block for this check to be evaluated.
    fn check_ancestor_block_hash(&mut self, bhh: &T) -> Result<(), Error> {
        self.with_conn(|conn| {
            let cur_block_hash = conn.get_cur_block();
            if cur_block_hash == *bhh {
                // a block is in its own fork
                return Ok(());
            }

            let bhh_height =
                MARF::get_block_height(conn, bhh, &cur_block_hash)?.ok_or_else(|| {
                    Error::NonMatchingForks(bhh.clone().to_bytes(), cur_block_hash.clone().to_bytes())
                })?;

            let actual_block_at_height = MARF::get_block_at_height(conn, bhh_height, &cur_block_hash)?
                .ok_or_else(|| Error::CorruptionError(format!(
                    "ERROR: Could not find block for height {}, but it was returned by MARF::get_block_height()", bhh_height)))?;

            if bhh != &actual_block_at_height {
                test_debug!("non-matching forks: {} != {}", bhh, &actual_block_at_height);
                return Err(Error::NonMatchingForks(
                    bhh.clone().to_bytes(),
                    cur_block_hash.to_bytes(),
                ));
            }

            // test open
            let result = conn.open_block(bhh);

            // restore
            conn.open_block(&cur_block_hash)
                .map_err(|e| Error::RestoreMarfBlockError(Box::new(e)))?;

            result
        })
    }
}

impl<'a, T: MarfTrieId> MarfConnection<T> for MarfTransaction<'a, T> {
    fn with_conn<F, R>(&mut self, exec: F) -> R
    where
        F: FnOnce(&mut TrieStorageConnection<T>) -> R,
    {
        exec(&mut self.storage)
    }
    fn sqlite_conn(&self) -> &Connection {
        self.storage.sqlite_tx()
    }
}

impl<T: MarfTrieId> MarfConnection<T> for MARF<T> {
    fn with_conn<F, R>(&mut self, exec: F) -> R
    where
        F: FnOnce(&mut TrieStorageConnection<T>) -> R,
    {
        let mut conn = self.storage.connection();
        exec(&mut conn)
    }
    fn sqlite_conn(&self) -> &Connection {
        self.storage.sqlite_conn()
    }
}

///
/// MarfTransaction represents a connection to a MARF index,
///   with an open storage transaction. If this struct is
///   dropped without calling commit(), the storage transaction is
///   aborted
///
impl<'a, T: MarfTrieId> MarfTransaction<'a, T> {
    pub fn commit(mut self) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush()?;
        }
        self.storage.commit_tx();
        Ok(())
    }

    /// Finish writing the next trie in the MARF, but change the hash of the current Trie's
    /// block hash to something other than what we opened it as.  This persists all changes.
    pub fn commit_to(mut self, real_bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush_to(real_bhh)?;
            self.storage.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF -- this is used by miners
    ///   to commit the mined block, but write it to the mined_block table,
    ///   rather than out to the marf_data table (this prevents the
    ///   miner's block from getting stepped on after the sortition).
    pub fn commit_mined(mut self, bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush_mined(bhh)?;
            self.storage.commit_tx();
        }
        Ok(())
    }

    pub fn get_open_chain_tip(&self) -> Option<&T> {
        self.open_chain_tip.as_ref().map(|tip| &tip.block_hash)
    }

    pub fn get_open_chain_tip_height(&self) -> Option<u32> {
        self.open_chain_tip.as_ref().map(|tip| tip.height)
    }

    pub fn get_block_height_of(
        &mut self,
        bhh: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        if Some(bhh) == self.get_open_chain_tip() {
            return Ok(self.get_open_chain_tip_height());
        } else {
            MARF::get_block_height_miner_tip(&mut self.storage, bhh, current_block_hash)
        }
    }

    #[cfg(test)]
    fn commit_tx(self) {
        self.storage.commit_tx()
    }

    pub fn sqlite_tx(&self) -> &Transaction<'a> {
        self.storage.sqlite_tx()
    }

    pub fn sqlite_tx_mut(&mut self) -> &mut Transaction<'a> {
        self.storage.sqlite_tx_mut()
    }

    /// Reopen this MARF transaction with readonly storage.
    ///   NOTE: any pending operations in the SQLite transaction _will not_
    ///         have materialized in the reopened view.
    pub fn reopen_readonly(&self) -> Result<MARF<T>, Error> {
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(Error::InProgressError);
        }

        let ro_storage = self.storage.reopen_readonly()?;
        Ok(MARF {
            storage: ro_storage,
            open_chain_tip: None,
        })
    }

    /// Begin writing the next trie in the MARF, given the block header hash that will contain the
    /// associated block's new state.  Call commit() or commit_to() to persist the changes.
    /// Fails if the block already exists.
    /// Storage will point to new chain tip on success.
    pub fn begin(&mut self, chain_tip: &T, next_chain_tip: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.open_chain_tip.is_some() {
            return Err(Error::InProgressError);
        }
        if self.storage.has_block(next_chain_tip)? {
            error!("Block data already exists: {}", next_chain_tip);
            return Err(Error::ExistsError);
        }

        let block_height = self.inner_get_extension_height(chain_tip, next_chain_tip)?;
        MARF::extend_trie(&mut self.storage, next_chain_tip)?;
        self.inner_setup_extension(chain_tip, next_chain_tip, block_height, true)
    }

    /// Set up the trie extension we're making.
    /// Sets storage pointer to chain_tip.
    /// Returns the height next_chain_tip would be at.
    fn inner_get_extension_height(
        &mut self,
        chain_tip: &T,
        next_chain_tip: &T,
    ) -> Result<u32, Error> {
        // current chain tip must exist if it's not the "sentinel"
        let is_parent_sentinel = chain_tip == &T::sentinel();
        if !is_parent_sentinel {
            debug!("Extending off of existing node {}", chain_tip);
        } else {
            debug!("First-ever block {}", next_chain_tip; "block" => %next_chain_tip);
        }

        self.storage.open_block(chain_tip)?;

        let block_height = if !is_parent_sentinel {
            let height = MARF::get_block_height_miner_tip(&mut self.storage, chain_tip, chain_tip)?
                .ok_or(Error::CorruptionError(format!(
                    "Failed to find block height for `{:?}`",
                    chain_tip
                )))?;
            height
                .checked_add(1)
                .expect("FATAL: block height overflow!")
        } else {
            0
        };

        Ok(block_height)
    }

    /// Set up a new extension.
    /// Opens storage to chain_tip/
    fn inner_setup_extension(
        &mut self,
        chain_tip: &T,
        next_chain_tip: &T,
        block_height: u32,
        new_extension: bool,
    ) -> Result<(), Error> {
        self.storage.open_block(next_chain_tip)?;
        self.open_chain_tip.replace(WriteChainTip {
            block_hash: next_chain_tip.clone(),
            height: block_height,
        });

        if new_extension {
            self.set_block_heights(chain_tip, next_chain_tip, block_height)
                .map_err(|e| {
                    self.open_chain_tip.take();
                    e
                })?;
        }

        debug!("Opened {} to {}", chain_tip, next_chain_tip);
        Ok(())
    }

    pub fn set_block_heights(
        &mut self,
        block_hash: &T,
        next_block_hash: &T,
        height: u32,
    ) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        let mut keys = vec![];
        let mut values = vec![];

        let height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height);
        let hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash);

        debug!(
            "Set {}::{} = {}",
            BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height, next_block_hash
        );
        debug!(
            "Set {}::{} = {}",
            BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash, height
        );
        debug!("Set {} = {}", OWN_BLOCK_HEIGHT_KEY, height);

        keys.push(OWN_BLOCK_HEIGHT_KEY.to_string());
        values.push(MARFValue::from(height));

        keys.push(height_key);
        values.push(MARFValue::from(next_block_hash.clone()));

        keys.push(hash_key);
        values.push(MARFValue::from(height));

        if height > 0 {
            let prev_height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height - 1);
            let prev_hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash);

            debug!(
                "Set {}::{} = {}",
                BLOCK_HEIGHT_TO_HASH_MAPPING_KEY,
                height - 1,
                block_hash
            );
            debug!(
                "Set {}::{} = {}",
                BLOCK_HASH_TO_HEIGHT_MAPPING_KEY,
                block_hash,
                height - 1
            );

            keys.push(prev_height_key);
            values.push(MARFValue::from(block_hash.clone()));

            keys.push(prev_hash_key);
            values.push(MARFValue::from(height - 1));
        }

        self.insert_batch(&keys, values)?;
        Ok(())
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    pub fn insert_batch(
        &mut self,
        keys: &Vec<String>,
        values: Vec<MARFValue>,
    ) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        assert_eq!(keys.len(), values.len());

        let block_hash = match self.open_chain_tip {
            None => Err(Error::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => Ok(block_hash.clone()),
        }?;

        if keys.len() == 0 {
            return Ok(());
        }

        MARF::inner_insert_batch(&mut self.storage, &block_hash, keys, values)?;
        Ok(())
    }

    /// Begin extending the MARF to an unconfirmed trie.  The resulting trie will have a block hash
    /// equal to MARF::make_unconfirmed_block_hash(chain_tip) to avoid collision
    /// and block hash reuse.
    pub fn begin_unconfirmed(&mut self, chain_tip: &T) -> Result<T, Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.open_chain_tip.is_some() {
            return Err(Error::InProgressError);
        }
        if !self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }

        // chain_tip must exist and must be confirmed
        if !self.storage.has_confirmed_block(chain_tip)? {
            error!("No such confirmed block {}", chain_tip);
            return Err(Error::NotFoundError);
        }

        let unconfirmed_tip = MARF::make_unconfirmed_chain_tip(chain_tip);

        let block_height = self.inner_get_extension_height(chain_tip, &unconfirmed_tip)?;

        let created = self.storage.extend_to_unconfirmed_block(&unconfirmed_tip)?;
        if created {
            MARF::root_copy(&mut self.storage, chain_tip)?;
        }

        self.inner_setup_extension(chain_tip, &unconfirmed_tip, block_height, created)?;
        Ok(unconfirmed_tip)
    }

    /// Drop the current trie from the MARF. This rolls back all
    ///   changes in the block, and closes the current chain tip.
    pub fn drop_current(mut self) {
        if !self.storage.readonly() {
            self.storage.drop_extending_trie();
            self.open_chain_tip.take();
            self.storage
                .open_block(&T::sentinel())
                .expect("BUG: should never fail to open the block sentinel");
            self.storage.rollback()
        }
    }

    /// Drop the current trie from the MARF, and roll back all unconfirmed state
    pub fn drop_unconfirmed(mut self) {
        if !self.storage.readonly() && self.storage.unconfirmed() {
            if let Some(tip) = self.open_chain_tip.take() {
                self.storage.drop_unconfirmed_trie(&tip.block_hash);
                self.storage
                    .open_block(&T::sentinel())
                    .expect("BUG: should never fail to open the block sentinel");
                // Dropping unconfirmed state cannot be done with a tx rollback,
                //   because the unconfirmed state may already have been written
                //   to the sqlite table before this transaction began
                self.storage.commit_tx()
            }
        }
    }
}

// static methods
impl<T: MarfTrieId> MARF<T> {
    #[cfg(test)]
    pub fn from_storage_opened(storage: TrieFileStorage<T>, opened_to: &T) -> MARF<T> {
        MARF {
            storage,
            open_chain_tip: Some(WriteChainTip {
                block_hash: opened_to.clone(),
                height: 0,
            }),
        }
    }

    #[cfg(test)]
    pub fn begin(&mut self, chain_tip: &T, next_chain_tip: &T) -> Result<(), Error> {
        let mut tx = self.begin_tx()?;
        tx.begin(chain_tip, next_chain_tip)?;
        tx.commit_tx();
        Ok(())
    }

    #[cfg(test)]
    pub fn begin_unconfirmed(&mut self, chain_tip: &T) -> Result<T, Error> {
        let mut tx = self.begin_tx()?;
        let result = tx.begin_unconfirmed(chain_tip)?;
        tx.commit_tx();
        Ok(result)
    }

    // helper method for walking a node's backpr
    fn walk_backptr(
        storage: &mut TrieStorageConnection<T>,
        start_node: &TrieNodeType,
        chr: u8,
        cursor: &mut TrieCursor<T>,
    ) -> Result<(TrieNodeType, TrieHash, TriePtr, u32), Error> {
        if start_node.is_leaf() {
            panic!("Did not get an intermediate node");
        }

        let ptr_opt = start_node.walk(chr);
        match ptr_opt {
            None => {
                // this node never had a child for this chr
                trace!("Failed to walk to '{}' from {:?}", chr, start_node);
                Err(Error::BackptrNotFoundError)
            }
            Some(ptr) => {
                trace!(
                    "Walk backptrs for {:?} to {:?} from {:?}",
                    cursor,
                    &ptr,
                    &start_node
                );

                // this node had a child for this chr at one point
                let (node, node_hash, node_ptr) = Trie::walk_backptr(storage, &ptr, cursor)?;
                Ok((node, node_hash, node_ptr, ptr.back_block))
            }
        }
    }

    fn node_copy_update_ptrs(ptrs: &mut [TriePtr], child_block_id: u32) -> () {
        for pointer in ptrs.iter_mut() {
            // if the node is empty, do nothing, if it's a back pointer,
            if pointer.id() == TrieNodeID::Empty as u8 || is_backptr(pointer.id()) {
                continue;
            } else {
                // make backptr
                pointer.back_block = child_block_id;
                pointer.id = set_backptr(pointer.id());
            }
        }
    }

    fn node_copy_update(node: &mut TrieNodeType, child_block_id: u32) -> Result<TrieHash, Error> {
        let hash = match node {
            TrieNodeType::Leaf(leaf) => get_leaf_hash(leaf),
            _ => {
                MARF::<T>::node_copy_update_ptrs(node.ptrs_mut(), child_block_id);
                TrieHash::from_data(&[])
            }
        };

        Ok(hash)
    }

    /// Given a node, and the chr of one of its children, go find the last instance of that child in
    /// the MARF and copy it forward.  Update its ptrs to point to its descendents.
    /// s must point to the block hash in which this node lives, to which the child will be copied.
    fn node_child_copy(
        storage: &mut TrieStorageConnection<T>,
        node: &TrieNodeType,
        chr: u8,
        cursor: &mut TrieCursor<T>,
    ) -> Result<(TrieNodeType, TrieHash, TriePtr, T), Error> {
        trace!(
            "Copy to {:?} child {:x} of {:?}",
            storage.get_cur_block(),
            chr,
            node
        );

        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        let (mut child_node, _, child_ptr, _) = MARF::walk_backptr(storage, node, chr, cursor)?;
        let child_block_hash = storage.get_cur_block();
        let child_block_identifier = storage.get_cur_block_identifier()?;

        // update child_node with new ptrs and hashes
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_hash = MARF::<T>::node_copy_update(&mut child_node, child_block_identifier)
            .map_err(|e| Error::BlockHashMapCorruptionError(Some(Box::new(e))))?;

        // store it in this trie
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_disk_ptr = storage.last_ptr()?;
        let child_ptr = TriePtr::new(child_ptr.id(), chr, child_disk_ptr);
        storage.write_nodetype(child_disk_ptr, &child_node, child_hash.clone())?;

        trace!(
            "Copied child 0x{:02x} to {:?}: ptr={:?} child={:?}",
            chr,
            &cur_block_hash,
            &child_ptr,
            &child_node
        );
        Ok((child_node, child_hash, child_ptr, child_block_hash))
    }

    /// Copy the root node from the previous Trie to this Trie, updating its ptrs.
    /// s must point to the target Trie
    fn root_copy(storage: &mut TrieStorageConnection<T>, prev_block_hash: &T) -> Result<(), Error> {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        storage.open_block(prev_block_hash)?;
        let prev_block_identifier = storage.get_cur_block_identifier().expect(&format!(
            "called open_block on {}, but found no identifier",
            prev_block_hash
        ));

        let (mut prev_root, _) = Trie::read_root(storage)?;
        let new_root_hash = MARF::<T>::node_copy_update(&mut prev_root, prev_block_identifier)?;

        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        let root_ptr = storage.root_ptr();
        storage.write_nodetype(root_ptr, &prev_root, new_root_hash)?;
        Ok(())
    }

    /// create or open a particular Trie.
    /// If the trie doesn't exist, then extend it from the current Trie and create a root node that
    /// has back pointers to its immediate children in the current trie.
    /// On Ok, s will point to new_bhh and will be open for reading.
    /// Returns true/false, based on whether or not the trie will be created (this can return false
    /// if we're resuming work on an unconfirmed trie)
    pub fn extend_trie(storage: &mut TrieStorageTransaction<T>, new_bhh: &T) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        let (cur_bhh, cur_block_id) = storage.get_cur_block_and_id();
        if storage.num_blocks() == 0 || cur_bhh == T::sentinel() {
            // brand new storage
            trace!("Brand new storage -- start with {:?}", new_bhh);
            storage.extend_to_block(new_bhh)?;
            let node = TrieNode256::new(&vec![]);
            let hash = get_node_hash(&node, &vec![], storage.deref_mut());
            let root_ptr = storage.root_ptr();
            storage.write_nodetype(root_ptr, &TrieNodeType::Node256(Box::new(node)), hash)?;
            Ok(())
        } else {
            // existing storage
            match storage.open_block(new_bhh) {
                Ok(_) => {
                    trace!("Switch to Trie {:?}", new_bhh);
                    Ok(())
                }
                Err(e) => {
                    match e {
                        Error::NotFoundError => {
                            // bring root forward
                            debug!("Extend {:?} to {:?}", &cur_bhh, new_bhh);
                            storage.open_block_maybe_id(&cur_bhh, cur_block_id)?;
                            storage.extend_to_block(new_bhh)?;
                            MARF::root_copy(storage, &cur_bhh)?;
                            storage.open_block(new_bhh)?;
                            Ok(())
                        }
                        _ => Err(e),
                    }
                }
            }
        }
    }

    /// Walk down this MARF at the given block hash, doing a copy-on-write for intermediate nodes in this block's Trie from any prior Tries.
    /// s must point to the last filled-in Trie -- i.e. block_hash points to the _new_ Trie that is
    /// being filled in.
    fn walk_cow(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TriePath,
    ) -> Result<TrieCursor<T>, Error> {
        let block_id = storage.get_block_identifier(block_hash);
        MARF::extend_trie(storage, block_hash)?;

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        // walk to insertion point
        let (mut node, _) = Trie::read_root(storage)?;
        let mut node_ptr = TriePtr::new(0, 0, 0);

        for _ in 0..(cursor.path.len() + 1) {
            match Trie::walk_from(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((next_node_ptr, next_node, _)) => {
                            // end of node path.
                            // keep walking.
                            node = next_node;
                            node_ptr = next_node_ptr;
                            continue;
                        }
                        None => {
                            // end of path.  Should have found leaf.
                            if !node.is_leaf()
                                || clear_backptr(node_ptr.id()) != TrieNodeID::Leaf as u8
                            {
                                error!("Out-of-path but encountered a non-leaf");
                                return Err(Error::CorruptionError(
                                    "Non-leaf encountered at end of path".to_string(),
                                ));
                            }

                            trace!(
                                "Out of path in {:?} -- we're done. Node at {:?}",
                                storage.get_cur_block(),
                                &node_ptr
                            );
                            storage.open_block_maybe_id(block_hash, block_id)?;
                            return Ok(cursor);
                        }
                    }
                }
                Err(e) => {
                    match e {
                        Error::CursorError(cursor_error) => {
                            match cursor_error {
                                CursorError::PathDiverged => {
                                    // we're done -- path diverged.  Will need to copy-on-write
                                    // some nodes over.
                                    trace!("Path diverged -- we're done.");
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    return Ok(cursor);
                                }
                                CursorError::ChrNotFound => {
                                    // end-of-node-path but no such child -- not even a backptr.
                                    trace!("ChrNotFound encountered at {:?} -- we're done (node not found)", storage.get_cur_block());
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    return Ok(cursor);
                                }
                                CursorError::BackptrEncountered(ptr) => {
                                    // at intermediate node whose child is not present in this trie.
                                    // bring the child forward and take the step, if possible.
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    let (next_node, _, next_node_ptr, next_node_block_hash) =
                                        MARF::node_child_copy(
                                            storage,
                                            &node,
                                            ptr.chr(),
                                            &mut cursor,
                                        )?;

                                    // finish taking the step
                                    cursor.repair_backptr_finish(
                                        &next_node_ptr,
                                        next_node_block_hash,
                                    );

                                    // keep walking
                                    node = next_node;
                                    node_ptr = next_node_ptr;

                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                }
                            }
                        }
                        _ => {
                            // some other error (e.g. I/O error)
                            return Err(e);
                        }
                    }
                }
            }
        }

        trace!("Trie has a cycle");
        return Err(Error::CorruptionError("Trie has a cycle".to_string()));
    }

    /// Walk down this MARF at the given block hash, resolving backptrs to previous tries.
    /// Return the cursor and the last node visited.
    /// s will point to the block in which the leaf was found, or the last block visited.
    fn walk(
        storage: &mut TrieStorageConnection<T>,
        block_hash: &T,
        path: &TriePath,
    ) -> Result<(TrieCursor<T>, TrieNodeType), Error> {
        storage.open_block(block_hash)?;

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        // walk to insertion point
        let (mut node, _) = Trie::read_root(storage)?;

        for _ in 0..(cursor.path.len() + 1) {
            match Trie::walk_from(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((_, next_node, _)) => {
                            // end-of-node-path, and found a child.
                            // keep walking
                            node = next_node;
                            continue;
                        }
                        None => {
                            // end of path.  Must be at a leaf.
                            if clear_backptr(cursor.ptr().id()) != TrieNodeID::Leaf as u8 {
                                return Err(Error::CorruptionError(
                                    "Non-leaf encountered at end of path".to_string(),
                                ));
                            }

                            trace!("Cursor reached leaf {:?}", &node);
                            return Ok((cursor, node));
                        }
                    }
                }
                Err(e) => {
                    match e {
                        Error::CursorError(cursor_error) => {
                            match cursor_error {
                                CursorError::PathDiverged => {
                                    // we're done -- path diverged.  No backptr-walking can help us.
                                    trace!("Path diverged -- we're done.");
                                    return Err(Error::NotFoundError);
                                }
                                CursorError::ChrNotFound => {
                                    // we're done -- end-of-node-path, but no child node.
                                    // Not even a backptr.
                                    trace!("ChrNotFound encountered -- node does not exist");
                                    return Err(Error::NotFoundError);
                                }
                                CursorError::BackptrEncountered(ptr) => {
                                    // at intermediate node whose child is not present in this trie.
                                    // try to shunt to the prior node that has the child itself.
                                    let (next_node, _, next_node_ptr, _) =
                                        MARF::walk_backptr(storage, &node, ptr.chr(), &mut cursor)?;

                                    // finish taking the step
                                    cursor.repair_backptr_finish(
                                        &next_node_ptr,
                                        storage.get_cur_block(),
                                    );

                                    // keep going
                                    node = next_node;
                                    continue;
                                }
                            }
                        }
                        _ => {
                            // some other error (e.g. I/O error)
                            return Err(e);
                        }
                    }
                }
            }
        }

        trace!("Trie has a cycle");
        return Err(Error::CorruptionError("Trie has a cycle".to_string()));
    }

    pub fn format(
        storage: &mut TrieStorageTransaction<T>,
        first_block_hash: &T,
    ) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        storage.format()?;
        storage.extend_to_block(first_block_hash)?;
        let node = TrieNode256::new(&vec![]);
        let hash = get_node_hash(&node, &vec![], storage.deref_mut());
        let root_ptr = storage.root_ptr();
        let node_type = TrieNodeType::Node256(Box::new(node));
        storage.write_nodetype(root_ptr, &node_type, hash)
    }

    pub fn get_path(
        storage: &mut TrieStorageConnection<T>,
        block_hash: &T,
        path: &TriePath,
    ) -> Result<Option<TrieLeaf>, Error> {
        trace!("MARF::get_path({:?}) {:?}", block_hash, path);

        // a NotFoundError _here_ means that a block didn't exist
        storage.open_block(block_hash)?;
        // a NotFoundError _here_ means that the key doesn't exist in this view
        let (cursor, node) = MARF::walk(storage, block_hash, path)?;
        // both of these get caught by get_by_key and turned into Ok(None)
        //   and a lot of downstream code seems to depend on that behavior, but
        //   should these two different cases be differentiable?

        if cursor.block_hashes.len() + 1 != cursor.node_ptrs.len() {
            trace!("cursor.block_hashes = {:?}", &cursor.block_hashes);
            trace!("cursor.node_ptrs = {:?}", cursor.node_ptrs);
            assert!(false);
        }

        assert!(cursor.eop());

        // out of path and reached the end.
        match node {
            TrieNodeType::Leaf(data) => {
                // found!
                return Ok(Some(data));
            }
            _ => {
                // Trie invariant violation -- a full path reached a non-leaf
                return Err(Error::CorruptionError(
                    "Path reached a non-leaf".to_string(),
                ));
            }
        }
    }

    fn do_insert_leaf(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TriePath,
        leaf_value: &TrieLeaf,
        update_skiplist: bool,
    ) -> Result<(), Error> {
        let mut value = leaf_value.clone();
        let mut cursor = MARF::walk_cow(storage, block_hash, path)?;

        if cursor.block_hashes.len() + 1 != cursor.node_ptrs.len() {
            trace!("c.block_hashes = {:?}", &cursor.block_hashes);
            trace!("c.node_ptrs = {:?}", cursor.node_ptrs);
            assert!(false);
        }

        debug!(
            "MARF Insert in {}: '{}' = '{}' (...{:?})",
            block_hash, path, leaf_value.data, &leaf_value.path
        );

        Trie::add_value(storage, &mut cursor, &mut value)?;

        if update_skiplist {
            Trie::update_root_hash(storage, &cursor)?;
        } else {
            Trie::update_root_node_hash(storage, &cursor)?;
        }
        Ok(())
    }

    pub fn insert_leaf(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TriePath,
        value: &TrieLeaf,
    ) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }
        MARF::do_insert_leaf(storage, block_hash, path, value, true)
    }

    // like insert_leaf, but don't update the merkle skiplist
    pub fn insert_leaf_in_batch(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TriePath,
        value: &TrieLeaf,
    ) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        MARF::do_insert_leaf(storage, block_hash, path, value, false)
    }

    /// Instantiate the MARF from a TrieFileStorage instance
    pub fn from_storage(storage: TrieFileStorage<T>) -> MARF<T> {
        MARF {
            storage: storage,
            open_chain_tip: None,
        }
    }

    /// Instantiate the MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path(path: &str) -> Result<MARF<T>, Error> {
        let file_storage = TrieFileStorage::open(path)?;
        Ok(MARF::from_storage(file_storage))
    }

    /// Instantiate an unconfirmed MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path_unconfirmed(path: &str) -> Result<MARF<T>, Error> {
        let file_storage = TrieFileStorage::open_unconfirmed(path)?;
        Ok(MARF::from_storage(file_storage))
    }

    pub fn get_by_key(
        storage: &mut TrieStorageConnection<T>,
        block_hash: &T,
        key: &str,
    ) -> Result<Option<MARFValue>, Error> {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();

        let path = TriePath::from_key(key);

        let result = MARF::get_path(storage, block_hash, &path).or_else(|e| match e {
            Error::NotFoundError => Ok(None),
            _ => Err(e),
        });

        // restore
        storage
            .open_block_maybe_id(&cur_block_hash, cur_block_id)
            .map_err(|e| {
                warn!(
                    "Failed to re-open {} {:?}: {:?}",
                    &cur_block_hash, cur_block_id, &e
                );
                warn!("Result of failed key lookup '{}': {:?}", key, &result);
                e
            })?;

        result.map(|option_result| option_result.map(|leaf| leaf.data))
    }

    pub fn get_block_height_miner_tip(
        storage: &mut TrieStorageConnection<T>,
        block_hash: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        let hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash);
        #[cfg(test)]
        {
            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            if storage.test_genesis_block.as_ref() == Some(current_block_hash) {
                return Ok(Some(0));
            }
        }

        let marf_value = if block_hash == current_block_hash {
            MARF::get_by_key(storage, current_block_hash, OWN_BLOCK_HEIGHT_KEY)?
        } else {
            MARF::get_by_key(storage, current_block_hash, &hash_key)?
        };

        Ok(marf_value.map(u32::from))
    }

    pub fn get_block_height(
        storage: &mut TrieStorageConnection<T>,
        block_hash: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        MARF::get_block_height_miner_tip(storage, block_hash, current_block_hash)
    }

    pub fn get_block_at_height(
        storage: &mut TrieStorageConnection<T>,
        height: u32,
        current_block_hash: &T,
    ) -> Result<Option<T>, Error> {
        #[cfg(test)]
        {
            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            if height == 0 {
                match storage.test_genesis_block {
                    Some(ref s) => return Ok(Some(s.clone())),
                    _ => {}
                }
            }
        }

        let current_block_height =
            match MARF::get_block_height(storage, current_block_hash, current_block_hash)? {
                Some(x) => x,
                None => {
                    error!(
                        "Could not fetch block height for {}, likely not a known block",
                        current_block_hash
                    );
                    return Ok(None);
                }
            };

        if height == current_block_height {
            return Ok(Some(current_block_hash.clone()));
        }

        let height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height);

        MARF::get_by_key(storage, current_block_hash, &height_key)
            .map(|option_result| option_result.map(T::from))
    }

    /// Make an unconfirmed chain tip from an existing chain tip, so that it won't conflict with
    /// the "true" chain tip after the state it represents is later reprocessed and confirmed.
    pub fn make_unconfirmed_chain_tip(chain_tip: &T) -> T {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(chain_tip.as_bytes());
        bytes[32..64].copy_from_slice(chain_tip.as_bytes());

        let h = Sha512Trunc256Sum::from_data(&bytes);
        let mut res_bytes = [0u8; 32];
        res_bytes[0..32].copy_from_slice(h.as_bytes());

        T::from_bytes(res_bytes)
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    fn inner_insert_batch(
        conn: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        keys: &Vec<String>,
        values: Vec<MARFValue>,
    ) -> Result<(), Error> {
        assert_eq!(keys.len(), values.len());

        if keys.len() == 0 {
            return Ok(());
        }

        let (cur_block_hash, cur_block_id) = conn.get_cur_block_and_id();

        let last = keys.len() - 1;
        let mut progress = 0;
        let eta_enabled = keys.len() > 10_000;
        let mut result = keys[0..last]
            .iter()
            .enumerate()
            .zip(values[0..last].iter())
            .try_for_each(|((index, key), value)| {
                let marf_leaf = TrieLeaf::from_value(&vec![], value.clone());
                let path = TriePath::from_key(key);

                if eta_enabled {
                    let updated_progress = 100 * index / last;
                    if updated_progress > progress {
                        progress = updated_progress;
                        info!(
                            "Batching insertions in MARF: {}% ({} out of {})",
                            progress, index, last
                        );
                    }
                }
                MARF::insert_leaf_in_batch(conn, block_hash, &path, &marf_leaf)
            });

        if result.is_ok() {
            // last insert updates the root with the skiplist hash
            let marf_leaf = TrieLeaf::from_value(&vec![], values[last].clone());
            let path = TriePath::from_key(&keys[last]);
            result = MARF::insert_leaf(conn, block_hash, &path, &marf_leaf);
        }

        // restore
        conn.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        result
    }
}

// instance methods
impl<T: MarfTrieId> MARF<T> {
    pub fn begin_tx<'a>(&'a mut self) -> Result<MarfTransaction<'a, T>, Error> {
        let storage = self.storage.transaction()?;
        Ok(MarfTransaction {
            storage,
            open_chain_tip: &mut self.open_chain_tip,
        })
    }

    /// Target the MARF's storage at a given block.
    pub fn open_block(&mut self, block_hash: &T) -> Result<(), Error> {
        self.storage.connection().open_block(block_hash)
    }

    pub fn get_with_proof(
        &mut self,
        block_hash: &T,
        key: &str,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        let mut conn = self.storage.connection();
        let marf_value = match MARF::get_by_key(&mut conn, block_hash, key)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof = TrieMerkleProof::from_raw_entry(&mut conn, key, &marf_value, block_hash)?;
        Ok(Some((marf_value, proof)))
    }

    pub fn get_bhh_at_height(&mut self, block_hash: &T, height: u32) -> Result<Option<T>, Error> {
        MARF::get_block_at_height(&mut self.storage.connection(), height, block_hash)
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    pub fn insert_batch(
        &mut self,
        keys: &Vec<String>,
        values: Vec<MARFValue>,
    ) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        assert_eq!(keys.len(), values.len());

        let block_hash = match self.open_chain_tip {
            None => Err(Error::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => Ok(block_hash.clone()),
        }?;

        if keys.len() == 0 {
            return Ok(());
        }

        let mut tx = self.storage.transaction()?;
        MARF::inner_insert_batch(&mut tx, &block_hash, keys, values)?;
        tx.commit_tx();
        Ok(())
    }

    pub fn insert(&mut self, key: &str, value: MARFValue) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        let marf_leaf = TrieLeaf::from_value(&vec![], value);
        let path = TriePath::from_key(key);
        self.insert_raw(path, marf_leaf)
    }

    /// Insert the given (key, value) pair into the MARF.  Inserting the same key twice silently
    /// overwrites the existing key.  Succeeds if there are no storage errors.
    /// Must be called after a call to .begin() (will fail otherwise)
    pub fn insert_raw(&mut self, path: TriePath, marf_leaf: TrieLeaf) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        match self.open_chain_tip {
            None => Err(Error::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => {
                let mut tx = self.storage.transaction()?;
                let (cur_block_hash, cur_block_id) = tx.get_cur_block_and_id();

                let result = MARF::insert_leaf(&mut tx, block_hash, &path, &marf_leaf);

                // restore
                tx.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
                tx.commit_tx();

                result
            }
        }
    }

    /// Drop the current trie from the MARF. This rolls back all
    ///   changes in the block, and closes the current chain tip.
    pub fn drop_current(&mut self) {
        if !self.storage.readonly() {
            let mut tx = self
                .storage
                .transaction()
                .expect("BUG: failed to start transaction to drop trie");
            tx.drop_extending_trie();
            self.open_chain_tip.take();
            tx.open_block(&T::sentinel())
                .expect("BUG: should never fail to open the block sentinel");
            tx.commit_tx();
        }
    }

    /// Drop the current trie from the MARF, and roll back all unconfirmed state
    pub fn drop_unconfirmed(&mut self) {
        if !self.storage.readonly() && self.storage.unconfirmed() {
            if let Some(tip) = self.open_chain_tip.take() {
                let mut tx = self
                    .storage
                    .transaction()
                    .expect("BUG: failed to start transaction to drop trie");
                tx.drop_unconfirmed_trie(&tip.block_hash);
                tx.open_block(&T::sentinel())
                    .expect("BUG: should never fail to open the block sentinel");
                tx.commit_tx();
            }
        }
    }

    /// Finish writing the next trie in the MARF.  This persists all changes.
    /// Works for both confirmed and unconfirmed tries
    pub fn commit(&mut self) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush()?;
            tx.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF -- this is used by miners
    ///   to commit the mined block, but write it to the mined_block table,
    ///   rather than out to the marf_data table (this prevents the
    ///   miner's block from getting stepped on after the sortition).
    pub fn commit_mined(&mut self, bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush_mined(bhh)?;
            tx.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF, but change the hash of the current Trie's
    /// block hash to something other than what we opened it as.  This persists all changes.
    pub fn commit_to(&mut self, real_bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush_to(real_bhh)?;
            tx.commit_tx();
        }
        Ok(())
    }

    pub fn get_block_height_of(
        &mut self,
        bhh: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        if Some(bhh) == self.get_open_chain_tip() {
            return Ok(self.get_open_chain_tip_height());
        } else {
            MARF::get_block_height_miner_tip(
                &mut self.storage.connection(),
                bhh,
                current_block_hash,
            )
        }
    }

    /// Get open chain tip
    pub fn get_open_chain_tip(&self) -> Option<&T> {
        self.open_chain_tip.as_ref().map(|x| &x.block_hash)
    }

    /// Get open chain tip
    pub fn get_open_chain_tip_height(&self) -> Option<u32> {
        self.open_chain_tip.as_ref().map(|x| x.height)
    }

    /// Access internal storage
    #[cfg(test)]
    pub fn borrow_storage_backend(&mut self) -> TrieStorageConnection<T> {
        self.storage.connection()
    }

    #[cfg(test)]
    pub fn borrow_storage_transaction(&mut self) -> TrieStorageTransaction<T> {
        self.storage.transaction().unwrap()
    }

    /// Make a raw transaction to the underlying storage
    pub fn storage_tx<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        self.storage.sqlite_tx()
    }

    /// Reopen storage read-only
    pub fn reopen_storage_readonly(&self) -> Result<TrieFileStorage<T>, Error> {
        self.storage.reopen_readonly()
    }

    /// Reopen this MARF with readonly storage.
    pub fn reopen_readonly(&self) -> Result<MARF<T>, Error> {
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(Error::InProgressError);
        }

        let ro_storage = self.storage.reopen_readonly()?;
        Ok(MARF {
            storage: ro_storage,
            open_chain_tip: None,
        })
    }

    /// Get the current root trie hash
    pub fn get_root_hash(&mut self) -> Result<TrieHash, Error> {
        read_root_hash(&mut self.storage.connection())
    }

    /// Get the root trie hash at a particular block
    pub fn get_root_hash_at(&mut self, block_hash: &T) -> Result<TrieHash, Error> {
        self.storage.connection().get_root_hash_at(block_hash)
    }
}

#[cfg(test)]
mod test {

    #![allow(unused_variables)]
    #![allow(unused_assignments)]

    use std::fs;
    use std::io::Cursor;

    use crate::chainstate::stacks::index::bits::*;
    use crate::chainstate::stacks::index::marf::*;
    use crate::chainstate::stacks::index::node::*;
    use crate::chainstate::stacks::index::proofs::*;
    use crate::chainstate::stacks::index::storage::*;
    use crate::chainstate::stacks::index::test::*;
    use crate::chainstate::stacks::index::trie::*;
    use stacks_common::util::get_epoch_time_ms;
    use stacks_common::util::hash::to_hex;

    use crate::types::chainstate::StacksBlockId;

    use super::*;

    #[test]
    fn marf_insert_different_leaf_same_block_100() {
        let filename = "/tmp/rust_marf_insert_different_leaf_same_block_100";

        let f = TrieFileStorage::new_memory().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let path_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let path = TriePath::from_bytes(&path_bytes).unwrap();

        for i in 0..100 {
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path.clone(), value).unwrap();
        }

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        let value = TrieLeaf::new(&vec![], &[99; 40].to_vec());
        let leaf = MARF::get_path(&mut marf.borrow_storage_backend(), &block_header, &path)
            .unwrap()
            .unwrap();

        assert_eq!(leaf.data.to_vec(), [99; 40].to_vec());
        assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

        merkle_test_marf(
            &mut marf.borrow_storage_backend(),
            &block_header,
            &path_bytes.to_vec(),
            &[99; 40].to_vec(),
            None,
        );
    }

    #[test]
    fn marf_insert_different_leaf_different_path_different_block_100() {
        let filename = "/tmp/rust_marf_insert_different_leaf_different_path_different_block_100";

        let f = TrieFileStorage::new_memory().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        for i in 0..100 {
            debug!("insert {}", i);
            let block_header = BlockHeaderHash::from_bytes(&[i + 1 as u8; 32]).unwrap();
            let path_bytes = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, i as u8,
            ];
            marf.commit().unwrap();
            marf.begin(&BlockHeaderHash::sentinel(), &block_header)
                .unwrap();
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        for i in 0..100 {
            let block_header = BlockHeaderHash::from_bytes(&[i + 1 as u8; 32]).unwrap();
            let path_bytes = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, i as u8,
            ];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(&mut marf.borrow_storage_backend(), &block_header, &path)
                .unwrap()
                .unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &block_header,
                &path_bytes.to_vec(),
                &[i as u8; 40].to_vec(),
                None,
            );
        }
    }

    #[test]
    fn marf_insert_same_leaf_different_block_100() {
        let path = "/tmp/rust_marf_same_leaf_different_block_100";

        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let path_bytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let path = TriePath::from_bytes(&path_bytes).unwrap();

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1 as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.commit().unwrap();
            marf.begin(&BlockHeaderHash::sentinel(), &next_block_header)
                .unwrap();
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1 as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(
                marf.borrow_storage_backend().get_cur_block(),
                next_block_header
            );

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &path_bytes.to_vec(),
                &[i as u8; 40].to_vec(),
                None,
            );
        }
    }

    #[test]
    fn marf_insert_leaf_sequence_2() {
        let path = "/tmp/rust_marf_insert_leaf_sequence_2";
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        for i in 0..2 {
            let path_bytes = [
                i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            let prior_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1 as u8; 32]).unwrap();
            marf.commit().unwrap();
            marf.begin(&prior_block_header, &next_block_header).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }

        marf.commit().unwrap();
        let last_block_header = BlockHeaderHash::from_bytes(&[2; 32]).unwrap();

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        for i in 0..2 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i + 1 as u8; 32]).unwrap();
            let path_bytes = [
                i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(
                marf.borrow_storage_backend().get_cur_block(),
                next_block_header
            );

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path_bytes.to_vec(),
                &[i as u8; 40].to_vec(),
                None,
            );
        }
    }

    #[test]
    fn marf_insert_leaf_sequence_100() {
        let path = "/tmp/rust_marf_insert_leaf_sequence_100";
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let mut last_block_header = block_header.clone();

        for i in 1..101 {
            let path_bytes = [
                i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            marf.commit().unwrap();
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.begin(&last_block_header, &next_block_header).unwrap();
            last_block_header = next_block_header;

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }

        debug!("---------");
        debug!("MARF gets");
        debug!("---------");

        let mut f = marf.borrow_storage_backend();

        for i in 1..101 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let path_bytes = [
                i as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            eprintln!("Finding value inserted at {}", &next_block_header);
            let leaf = MARF::get_path(&mut f, &last_block_header, &path)
                .unwrap()
                .unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            // NOTE: this assertion no longer holds, since the path prefix may now overlap
            //         with data related to block_height!
            // assert_eq!(f.get_cur_block(), next_block_header);

            merkle_test_marf(
                &mut f,
                &last_block_header,
                &path_bytes.to_vec(),
                &[i as u8; 40].to_vec(),
                None,
            );
        }
    }

    #[test]
    #[ignore]
    fn marf_walk_cow_node4_20() {
        marf_walk_cow_test(
            |s| {
                // make a deep path
                let path_segments = vec![
                    (vec![], 0),
                    (vec![], 1),
                    (vec![], 2),
                    (vec![], 3),
                    (vec![], 4),
                    (vec![], 5),
                    (vec![], 6),
                    (vec![], 7),
                    (vec![], 8),
                    (vec![], 9),
                    (vec![], 10),
                    (vec![], 11),
                    (vec![], 12),
                    (vec![], 13),
                    (vec![], 14),
                    (vec![], 15),
                    (vec![], 16),
                    (vec![], 17),
                    (vec![], 18),
                    (vec![], 19),
                    (vec![], 20),
                    (vec![], 21),
                    (vec![], 22),
                    (vec![], 23),
                    (vec![], 24),
                    (vec![], 25),
                    (vec![], 26),
                    (vec![], 27),
                    (vec![], 28),
                    (vec![], 29),
                    (vec![], 30),
                    (vec![], 31),
                ];
                make_node4_path(s, &path_segments, [31u8; 40].to_vec())
            },
            |i, mut p| {
                p[i as usize] = 32;
                p
            },
        );
    }

    #[test]
    #[ignore]
    fn marf_walk_cow_node4_20_reversed() {
        marf_walk_cow_test(
            |s| {
                // make a deep path
                let path_segments = vec![
                    (vec![], 0),
                    (vec![], 1),
                    (vec![], 2),
                    (vec![], 3),
                    (vec![], 4),
                    (vec![], 5),
                    (vec![], 6),
                    (vec![], 7),
                    (vec![], 8),
                    (vec![], 9),
                    (vec![], 10),
                    (vec![], 11),
                    (vec![], 12),
                    (vec![], 13),
                    (vec![], 14),
                    (vec![], 15),
                    (vec![], 16),
                    (vec![], 17),
                    (vec![], 18),
                    (vec![], 19),
                    (vec![], 20),
                    (vec![], 21),
                    (vec![], 22),
                    (vec![], 23),
                    (vec![], 24),
                    (vec![], 25),
                    (vec![], 26),
                    (vec![], 27),
                    (vec![], 28),
                    (vec![], 29),
                    (vec![], 30),
                    (vec![], 31),
                ];
                make_node4_path(s, &path_segments, [31u8; 40].to_vec())
            },
            |i, mut p| {
                p[31 - i as usize] = 32;
                p
            },
        );
    }

    fn marf_walk_cow_4_test<F>(filename: &str, path_gen: F)
    where
        F: Fn(u32, [u8; 32]) -> [u8; 32],
    {
        for node_id in [
            TrieNodeID::Node4,
            TrieNodeID::Node16,
            TrieNodeID::Node48,
            TrieNodeID::Node256,
        ]
        .iter()
        {
            let path_segments = vec![
                (vec![], 4),
                (vec![0, 1, 2, 3, 5, 6, 7, 8], 9),
                (vec![10, 11, 12, 13], 14),
                (vec![15, 16, 17, 18], 19),
                (vec![20, 21, 22, 23], 24),
                (vec![25, 26, 27, 28], 29),
                (vec![30], 31),
            ];

            marf_walk_cow_test(
                |s| make_node_path(s, node_id.to_u8(), &path_segments, [31u8; 40].to_vec()),
                |x, y| path_gen(x, y),
            );
        }
    }

    fn marf_walk_cow_test<F, G>(path_init: G, path_gen: F)
    where
        F: Fn(u32, [u8; 32]) -> [u8; 32],
        G: FnOnce(
            &mut TrieStorageConnection<BlockHeaderHash>,
        ) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>),
    {
        let mut f_store = TrieFileStorage::new_memory().unwrap();
        let path = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let mut last_block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();

        let (nodes, node_ptrs, hashes) = {
            let mut f = f_store.transaction().unwrap();
            MARF::format(&mut f, &last_block_header).unwrap();
            f.test_genesis_block.replace(last_block_header.clone());

            let r = path_init(&mut f);
            f.commit_tx();
            r
        };

        let mut marf = MARF::from_storage(f_store);

        for i in 1..31 {
            debug!("----------------");
            debug!("i = {}", i);
            debug!("----------------");

            // switch to the next block
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.commit().unwrap();
            marf.begin(&last_block_header, &next_block_header).unwrap();
            last_block_header = next_block_header;
            // add a leaf at the end of the path

            let next_path = path_gen(i, path.clone());

            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());

            debug!("----------------");
            debug!("insert");
            debug!("----------------");
            marf.insert_raw(triepath.clone(), value.clone()).unwrap();

            // verify that this leaf exists in _this_ Trie
            debug!("----------------");
            debug!("get");
            debug!("----------------");
            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &TriePath::from_bytes(&next_path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), [i as u8; 40].to_vec());
            // assertion is no longer necessarily true, because of block height data!
            //
            //   assert_eq!(read_value.path, next_path[i..].to_vec());
            assert_eq!(
                marf.borrow_storage_backend().get_cur_block(),
                next_block_header
            );

            // can get all previous leaves from _this_ Trie
            for j in 1..(i + 1) {
                debug!("----------------");
                debug!("get-prev {} of {}", j, i);
                debug!("----------------");

                let prev_path = path_gen(j, path.clone());

                let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                let read_value = MARF::get_path(
                    &mut marf.borrow_storage_backend(),
                    &next_block_header,
                    &TriePath::from_bytes(&prev_path[..]).unwrap(),
                )
                .unwrap()
                .unwrap();
                assert_eq!(read_value.data.to_vec(), [j as u8; 40].to_vec());

                // assertion no longer true, because inserting the block height information
                //   can cause a COW.
                // assert_eq!(f.get_cur_block(), prev_block_header);

                debug!("---------------------------------------");
                debug!(
                    "MARF verify {:?} {:?} from current block header {:?}",
                    &prev_path,
                    &[j as u8; 40].to_vec(),
                    &next_block_header
                );
                debug!("----------------------------------------");
                merkle_test_marf(
                    &mut marf.borrow_storage_backend(),
                    &next_block_header,
                    &prev_path.to_vec(),
                    &[j as u8; 40].to_vec(),
                    None,
                );
            }

            marf.borrow_storage_backend()
                .open_block(&next_block_header)
                .unwrap();

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &next_block_header,
                &next_path.to_vec(),
                &[i as u8; 40].to_vec(),
                None,
            );
        }

        // all leaves are reachable from the last block
        for i in 1..31 {
            // add a leaf at the end of the path
            let next_path = path_gen(i, path.clone());

            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = MARFValue([i as u8; 40]);

            assert_eq!(
                MARF::get_path(
                    &mut marf.borrow_storage_backend(),
                    &last_block_header,
                    &triepath
                )
                .unwrap()
                .unwrap()
                .data,
                value
            );

            debug!("---------------------------------------");
            debug!(
                "MARF verify {:?} {:?} from last block header {:?}",
                &next_path,
                &[i as u8; 40].to_vec(),
                &last_block_header
            );
            debug!("----------------------------------------");
            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &next_path.to_vec(),
                &[i as u8; 40].to_vec(),
                None,
            );
        }
    }

    #[test]
    #[ignore]
    fn marf_walk_cow_4() {
        marf_walk_cow_4_test("/tmp/rust_marf_walk_cow_node4_20", |i, mut p| {
            p[i as usize] = 32;
            p
        })
    }

    #[test]
    #[ignore]
    fn marf_walk_cow_4_reversed() {
        marf_walk_cow_4_test("/tmp/rust_marf_walk_cow_node4_20_reversed", |i, mut p| {
            p[31 - i as usize] = 32;
            p
        })
    }

    #[test]
    fn marf_invalid_ancestor() {
        let f1 = TrieFileStorage::new_memory().unwrap();
        let f2 = TrieFileStorage::new_memory().unwrap();
        let mut m1 = MARF::from_storage(f1);
        let mut m2 = MARF::from_storage(f2);

        let mock_miner_hash = BlockHeaderHash([1; 32]);

        m1.begin(&BlockHeaderHash::sentinel(), &mock_miner_hash)
            .unwrap();
        m1.commit_to(&BlockHeaderHash([2; 32])).unwrap();
        m1.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
            .unwrap();
        m1.commit_to(&BlockHeaderHash([3; 32])).unwrap();
        m1.begin(&BlockHeaderHash([3; 32]), &mock_miner_hash)
            .unwrap();
        m1.drop_current();

        // m1 should be dirty...

        m2.begin(&BlockHeaderHash::sentinel(), &mock_miner_hash)
            .unwrap();
        m2.commit_to(&BlockHeaderHash([2; 32])).unwrap();
        m2.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
            .unwrap();
        m2.commit_to(&BlockHeaderHash([3; 32])).unwrap();
        m2.begin(&BlockHeaderHash([3; 32]), &mock_miner_hash)
            .unwrap();
        m2.commit_to(&BlockHeaderHash([4; 32])).unwrap();

        // m2 is clean...

        // now let's make a block whose parent is _2_ (not _3_)

        m1.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
            .unwrap();
        m2.begin(&BlockHeaderHash([2; 32]), &mock_miner_hash)
            .unwrap();

        let hash_1 = m1.get_root_hash().unwrap();
        let hash_2 = m2.get_root_hash().unwrap();

        eprintln!("{} == {}", hash_1, hash_2);

        assert_eq!(hash_1, hash_2);
    }

    #[test]
    fn marf_merkle_verify_backptrs() {
        for node_id in [
            TrieNodeID::Node4,
            TrieNodeID::Node16,
            TrieNodeID::Node48,
            TrieNodeID::Node256,
        ]
        .iter()
        {
            let mut f_store = TrieFileStorage::new_memory().unwrap();

            let path_segments = vec![
                (vec![], 12),
                (
                    vec![
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                        24,
                    ],
                    25,
                ),
                (vec![26, 27, 28, 29, 30], 31),
            ];

            let path = vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];

            let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();

            let (nodes, node_ptrs, hashes) = {
                let mut f = f_store.transaction().unwrap();
                MARF::format(&mut f, &block_header_1).unwrap();
                f.test_genesis_block.replace(block_header_1.clone());

                let r =
                    make_node_path(&mut f, node_id.to_u8(), &path_segments, [31u8; 40].to_vec());
                f.commit_tx();

                r
            };

            let mut marf = MARF::from_storage(f_store);

            let block_header_2 = BlockHeaderHash::from_bytes(&[1u8; 32]).unwrap();
            let path_2 = vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 32,
            ];

            debug!("----------------");
            debug!("Extend to {:?}", block_header_2);
            debug!("----------------");

            marf.commit().unwrap();
            marf.begin(&block_header_1, &block_header_2).unwrap();
            marf.insert_raw(
                TriePath::from_bytes(&path_2[..]).unwrap(),
                TrieLeaf::new(&vec![], &[20 as u8; 40].to_vec()),
            )
            .unwrap();

            let block_header_3 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
            let path_3 = vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 33,
            ];

            debug!("----------------");
            debug!("Extend to {:?}", block_header_3);
            debug!("----------------");

            marf.commit().unwrap();
            marf.begin(&block_header_2, &block_header_3).unwrap();
            marf.insert_raw(
                TriePath::from_bytes(&path_3[..]).unwrap(),
                TrieLeaf::new(&vec![], &[21 as u8; 40].to_vec()),
            )
            .unwrap();

            debug!("----------------");
            debug!(
                "Merkle verify {:?} from {:?}",
                &to_hex(&[21 as u8; 40]),
                block_header_3
            );
            debug!("----------------");

            merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &block_header_3,
                &path_3,
                &[21 as u8; 40].to_vec(),
                None,
            );
        }
    }

    fn marf_insert<F>(
        filename: &str,
        mut path_gen: F,
        count: u32,
        check_merkle_proof: bool,
    ) -> MARF<BlockHeaderHash>
    where
        F: FnMut(u32) -> ([u8; 32], Option<BlockHeaderHash>),
    {
        let f = TrieFileStorage::new_memory().unwrap();
        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let mut root_table_cache = None;

        let mut blocks = vec![block_header.clone()];

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;

            let (path, next_block_header) = path_gen(i);

            let triepath = TriePath::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &vec![],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
                ]
                .to_vec(),
            );

            if let Some(next_block_header) = next_block_header {
                marf.commit().unwrap();
                marf.begin(&block_header, &next_block_header).unwrap();
                block_header = next_block_header;
                blocks.push(block_header.clone())
            }

            marf.insert_raw(triepath, value.clone()).unwrap();

            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &block_header,
                &TriePath::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

            if check_merkle_proof {
                root_table_cache = Some(merkle_test_marf(
                    &mut marf.borrow_storage_backend(),
                    &block_header,
                    &path.to_vec(),
                    &value.data.to_vec(),
                    root_table_cache,
                ));
            }
        }

        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(
                MARF::get_block_height(&mut marf.borrow_storage_backend(), block, &block_header)
                    .unwrap(),
                Some(i as u32)
            );
            assert_eq!(
                MARF::get_block_at_height(
                    &mut marf.borrow_storage_backend(),
                    i as u32,
                    &block_header
                )
                .unwrap(),
                Some(block.clone())
            );
        }

        root_table_cache = None;

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;
            let (path, _next_block_header) = path_gen(i);

            let triepath = TriePath::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &vec![],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
                ]
                .to_vec(),
            );

            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &block_header,
                &TriePath::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());

            // can make a merkle proof to each one
            if check_merkle_proof {
                root_table_cache = Some(merkle_test_marf(
                    &mut marf.borrow_storage_backend(),
                    &block_header,
                    &path.to_vec(),
                    &value.data.to_vec(),
                    root_table_cache,
                ));
            }
        }

        marf
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 128 keys, make a new trie
    #[test]
    #[ignore]
    fn marf_insert_4096_128_seq_low() {
        marf_insert(
            "/tmp/rust_marf_insert_4096_128_seq_low",
            |i| {
                let path = [
                    0,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                    10,
                    11,
                    12,
                    13,
                    14,
                    15,
                    16,
                    17,
                    18,
                    19,
                    20,
                    21,
                    22,
                    23,
                    24,
                    25,
                    26,
                    27,
                    28,
                    29,
                    (i / 256) as u8,
                    (i % 256) as u8,
                ];
                let block_header = if (i + 1) % 128 == 0 {
                    // next block
                    Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
                } else {
                    None
                };
                (path, block_header)
            },
            4096,
            true,
        );
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the high-order bits.
    // every 128 keys, make a new trie
    #[test]
    #[ignore]
    fn marf_insert_4096_128_seq_high() {
        marf_insert(
            "/tmp/rust_marf_insert_4096_128_seq_high",
            |i| {
                let i0 = i / 256;
                let i1 = i % 256;
                let path = [
                    i0 as u8, i1 as u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                let block_header = if (i + 1) % 128 == 0 {
                    // next block
                    Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
                } else {
                    None
                };
                (path, block_header)
            },
            4096,
            true,
        );
    }

    // insert a leaf, open a new block, and attempt to split the leaf
    // TODO: try also when the leaf to split dangles from an intermediate node, not off of the root
    // (since we have a different backptr copy routine there)
    #[test]
    fn marf_split_leaf_path() {
        let path = "/tmp/rust_marf_split_leaf_path";
        let f = TrieFileStorage::new_memory().unwrap();

        let mut marf = MARF::from_storage(f);
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();

        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();

        let path = [0u8; 32];
        let triepath = TriePath::from_bytes(&path[..]).unwrap();
        let value = TrieLeaf::new(&vec![], &[0u8; 40].to_vec());

        debug!("----------------");
        debug!(
            "insert ({:?}, {:?}) in {:?}",
            &triepath, &value, &block_header
        );
        debug!("----------------");

        marf.insert_raw(triepath.clone(), value.clone()).unwrap();

        // insert a leaf along the same path but in a different block
        let block_header_2 = BlockHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap();
        let path_2 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1,
        ];
        let triepath_2 = TriePath::from_bytes(&path_2[..]).unwrap();
        let value_2 = TrieLeaf::new(&vec![], &[1u8; 40].to_vec());

        debug!("----------------");
        debug!(
            "insert ({:?}, {:?}) in {:?}",
            &triepath_2, &value_2, &block_header_2
        );
        debug!("----------------");

        marf.commit().unwrap();
        marf.begin(&block_header, &block_header_2).unwrap();
        marf.insert_raw(triepath_2.clone(), value_2.clone())
            .unwrap();

        debug!("----------------");
        debug!(
            "get ({:?}, {:?}) in {:?}",
            &triepath, &value, &block_header_2
        );
        debug!("----------------");

        let read_value = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &block_header_2,
            &triepath,
        )
        .unwrap()
        .unwrap();
        assert_eq!(read_value.data.to_vec(), value.data.to_vec());

        debug!("----------------");
        debug!(
            "get ({:?}, {:?}) in {:?}",
            &triepath_2, &value_2, &block_header_2
        );
        debug!("----------------");

        let read_value_2 = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &block_header_2,
            &triepath_2,
        )
        .unwrap()
        .unwrap();
        assert_eq!(read_value_2.data.to_vec(), value_2.data.to_vec());
    }

    // insert a random sequence of 65536 keys.  Every 2048 inserts, start a new block.
    //   *these aren't forks* `insert_leaf` on a non-existent bhh creates a block extension in
    //   walk_cow via `MARF::extend_trie`.

    #[test]
    #[ignore]
    fn marf_insert_random_65536_2048() {
        let filename = "/tmp/rust_marf_insert_random_65536_2048";
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        marf_insert(
            filename,
            |i| {
                let mut path = [0; 32];
                path.copy_from_slice(
                    &TrieHash::from_data(if i == 0 { &[] } else { seed.as_slice() }).as_bytes()
                        [0..32],
                );
                seed = path.to_vec();

                let block_header = if (i + 1) % 2048 == 0 {
                    // next block
                    Some(
                        BlockHeaderHash::from_bytes(&[
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            ((i + 1) / 2048) as u8,
                            ((i + 1) % 2048) as u8,
                        ])
                        .unwrap(),
                    )
                } else {
                    None
                };
                (path, block_header)
            },
            65536,
            false,
        );
    }

    // insert a random sequence of 1024 * 1024 * 10 keys.  Every 4096 inserts, fork.
    // Use file storage, and use batching.
    // Used mainly for performance analysis.
    #[test]
    fn marf_insert_random_10485760_4096_file_storage() {
        // this takes too long to run, so disable it by default
        if std::env::var("BLOCKSTACK_BIG_TEST") != Ok("1".to_string()) {
            debug!("Skipping this test because it will take too long.  Run with BLOCKSTACK_BIG_TEST=1 to activate.");
            return;
        }

        let path = "/tmp/rust_marf_insert_random_10485760_4096_file_storage".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            }
            Err(_) => {}
        };
        let f = TrieFileStorage::open(&path).unwrap();
        let mut m = MARF::from_storage(f);

        let mut block_header = BlockHeaderHash::sentinel();

        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut start_time = get_epoch_time_ms();
        let mut end_time = 0;
        let mut block_start_time = start_time;
        let mut prev_block_header = block_header.clone();

        let mut i: u64 = 1;
        let num_iterations = 1024 * 1024 * 10;
        let block_size = 4096;

        while i <= num_iterations {
            let mut keys = vec![];
            let mut values = vec![];

            let i0 = (i & 0xff000000) >> 24;
            let i1 = (i & 0x00ff0000) >> 16;
            let i2 = (i & 0x0000ff00) >> 8;
            let i3 = i & 0x000000ff;

            prev_block_header = block_header.clone();
            block_header = BlockHeaderHash::from_bytes(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                i0 as u8, i1 as u8, i2 as u8, i3 as u8,
            ])
            .unwrap();

            for _ in 0..block_size {
                let i0 = (i & 0xff000000) >> 24;
                let i1 = (i & 0x00ff0000) >> 16;
                let i2 = (i & 0x0000ff00) >> 8;
                let i3 = i & 0x000000ff;

                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let value = to_hex(
                    &[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8, i3 as u8,
                    ]
                    .to_vec(),
                );

                keys.push(key);
                values.push(value);
                i += 1;
            }

            block_start_time = get_epoch_time_ms();
            m.begin(&prev_block_header, &block_header).unwrap();

            start_time = get_epoch_time_ms();

            let values = values
                .drain(..)
                .map(|x| MARFValue::from_value(&x))
                .collect();

            m.insert_batch(&keys, values).unwrap();
            end_time = get_epoch_time_ms();

            let flush_start_time = get_epoch_time_ms();
            m.commit().unwrap();
            let flush_end_time = get_epoch_time_ms();

            eprintln!(
                "Inserted {} in {} (1 insert = {} ms).  Processed {} keys in {} ms (flush = {} ms)",
                i,
                end_time - start_time,
                ((end_time - start_time) as f64) / (block_size as f64),
                block_size,
                flush_end_time - block_start_time,
                flush_end_time - flush_start_time
            );
        }

        i = 1;
        seed = TrieHash::from_data(&[]).as_bytes().to_vec();

        while i <= num_iterations {
            let mut keys = vec![];
            let mut values = vec![];

            for _ in 0..block_size {
                let i0 = (i & 0xff000000) >> 24;
                let i1 = (i & 0x00ff0000) >> 16;
                let i2 = (i & 0x0000ff00) >> 8;
                let i3 = i & 0x000000ff;

                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let value = to_hex(
                    &[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8, i3 as u8,
                    ]
                    .to_vec(),
                );

                keys.push(key);
                values.push(value);
                i += 1;
            }

            start_time = get_epoch_time_ms();

            for j in 0..block_size {
                let read_value = m.get(&block_header, &keys[j]).unwrap().unwrap();
                assert_eq!(read_value, MARFValue::from_value(&values[j]));
            }

            end_time = get_epoch_time_ms();

            eprintln!(
                "Got {} in {} (1 get = {} ms)",
                i,
                end_time - start_time,
                ((end_time - start_time) as f64) / (block_size as f64)
            );
        }
    }

    // insert a random sequence of 4096 keys.  Every 128 inserts, fork.
    // Use file storage, and use batching.
    // Do merkle tests each key/value inserted -- both immediately after the batch containing them
    // is inserted, and once all inserts complete.
    #[test]
    #[ignore]
    fn marf_insert_random_4096_128_file_storage_merkle_proof() {
        let path = "/tmp/rust_marf_insert_4096_128_file_storage_merkle_proof";
        let f = TrieFileStorage::new_memory().unwrap();

        let mut m = MARF::from_storage(f);

        let mut block_header = BlockHeaderHash::sentinel();

        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut prev_block_header = block_header.clone();

        let mut i = 1;
        while i <= 4096 {
            let mut keys = vec![];
            let mut values = vec![];

            let i0 = (i & 0xff0000) >> 12;
            let i1 = (i & 0x00ff00) >> 8;
            let i2 = i & 0x0000ff;

            prev_block_header = block_header.clone();
            block_header = BlockHeaderHash::from_bytes(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, i0 as u8, i1 as u8, i2 as u8,
            ])
            .unwrap();

            for _ in 0..128 {
                let i0 = (i & 0xff0000) >> 12;
                let i1 = (i & 0x00ff00) >> 8;
                let i2 = i & 0x0000ff;

                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let raw_value = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8,
                ]
                .to_vec();
                let value = to_hex(&raw_value);

                debug!("Insert ({:?}, {:?})", &key, &value);

                keys.push(key);
                values.push(value);
                i += 1;
            }

            m.begin(&prev_block_header, &block_header).unwrap();

            let marf_values = values.iter().map(|x| MARFValue::from_value(&x)).collect();

            m.insert_batch(&keys, marf_values).unwrap();
            m.commit().unwrap();

            let mut block_table_cache = None;
            for j in 0..128 {
                debug!("Prove {:?} == {:?}", &keys[j], &values[j]);
                block_table_cache = Some(merkle_test_marf_key_value(
                    &mut m.borrow_storage_backend(),
                    &block_header,
                    &keys[j],
                    &values[j],
                    block_table_cache,
                ));
            }
        }

        i = 1;
        seed = TrieHash::from_data(&[]).as_bytes().to_vec();

        let mut block_table_cache = None;
        while i <= 4096 {
            let mut keys = vec![];
            let mut values = vec![];

            for _ in 0..128 {
                let i0 = (i & 0xff0000) >> 12;
                let i1 = (i & 0x00ff00) >> 8;
                let i2 = i & 0x0000ff;

                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let raw_value = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8,
                ]
                .to_vec();
                let value = to_hex(&raw_value);

                keys.push(key);
                values.push(value);

                i += 1;
            }

            for j in 0..128 {
                debug!("Get {:?}, should be {:?}", &keys[j], &values[j]);

                let read_value = m.get(&block_header, &keys[j]).unwrap().unwrap();
                assert_eq!(read_value, MARFValue::from_value(&values[j]));

                debug!("Get {:?}, should be {:?}", &keys[j], &values[j]);
                block_table_cache = Some(merkle_test_marf_key_value(
                    &mut m.borrow_storage_backend(),
                    &block_header,
                    &keys[j],
                    &values[j],
                    block_table_cache,
                ));
            }
        }
    }

    // Test reads specifically on existing test data.
    // Not usually meant to be run, so #[test] is commented out below.
    #[test]
    fn marf_read_random_1048576_4096_file_storage() {
        // this takes too long to run, so disable it by default
        if std::env::var("BLOCKSTACK_BIG_TEST") != Ok("1".to_string()) {
            debug!("Skipping this test because it will take too long.  Run with BLOCKSTACK_BIG_TEST=1 to activate.");
            return;
        }

        let path = "/tmp/rust_marf_insert_random_1048576_4096_file_storage".to_string();
        match fs::metadata(&path) {
            Err(_) => {
                eprintln!("Run the marf_insert_random_1048576_4096_file_storage test first");
                return;
            }
            Ok(_) => {}
        };
        let mut f_store = TrieFileStorage::new_memory().unwrap();
        let mut f = f_store.connection();

        let block_header = BlockHeaderHash::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0xf0, 0xff, 0xff,
        ])
        .unwrap();
        f.open_block(&block_header).unwrap();

        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut start_time = 0;

        start_time = get_epoch_time_ms();
        for i in 0..1048576 {
            // can read them all back
            let i0 = (i & 0xff0000) >> 12;
            let i1 = (i & 0x00ff00) >> 8;
            let i2 = i & 0x0000ff;

            let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
            seed = path.clone();

            let triepath = TriePath::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &vec![],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8, i2 as u8,
                ]
                .to_vec(),
            );

            let read_value = MARF::get_path(
                &mut f,
                &block_header,
                &TriePath::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());

            // can make a merkle proof to each one
            // merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec(), None);
            if i % 128 == 0 {
                let end_time = get_epoch_time_ms();
                let (read_count, write_count) = f.stats();
                let (node_reads, backptr_reads, node_writes) = f.node_stats();
                let (leaf_reads, leaf_writes) = f.leaf_stats();
                debug!("Got {} in {} (1 get = {} ms).  Read = {}, Write = {}, Node Reads = {}, Node Writes = {}, Backptr Reads = {}, Leaf Reads = {}, Leaf Writes = {}",
                         i, end_time - start_time, ((end_time - start_time) as f64) / 128.0, read_count, write_count, node_reads, node_writes, backptr_reads, leaf_reads, leaf_writes);

                start_time = get_epoch_time_ms();
            }
        }
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 128 keys, make a new trie.
    // Use the TrieFileStorage backend
    #[test]
    fn marf_insert_128_32_file_storage() {
        let mut marf = marf_insert(
            "/tmp/rust_marf_insert_128_32_file_storage",
            |i| {
                let i0 = i / 256;
                let i1 = i % 256;
                let path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
                ];
                let block_header = if (i + 1) % 32 == 0 {
                    // next block
                    Some(BlockHeaderHash::from_bytes(&[((i + 1) / 32) as u8; 32]).unwrap())
                } else {
                    None
                };
                (path, block_header)
            },
            128,
            true,
        );

        marf.commit().unwrap();

        for i in 0..(128 / 32) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.borrow_storage_backend()
                .open_block(&block_header)
                .unwrap();
            dump_trie(&mut marf.borrow_storage_backend());
        }
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 128 keys, make a new trie.
    // Use the TrieFileStorage backend
    #[test]
    #[ignore]
    fn marf_insert_4096_128_file_storage() {
        let mut marf = marf_insert(
            "/tmp/rust_marf_insert_4096_128_file_storage",
            |i| {
                let i0 = i / 256;
                let i1 = i % 256;
                let path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
                ];
                let block_header = if (i + 1) % 128 == 0 {
                    // next block
                    Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
                } else {
                    None
                };
                (path, block_header)
            },
            4096,
            true,
        );

        marf.commit().unwrap();

        for i in 0..(4096 / 128) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.borrow_storage_backend()
                .open_block(&block_header)
                .unwrap();
            dump_trie(&mut marf.borrow_storage_backend());
        }
    }

    // insert a range of 256 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 16 keys, make a new trie.
    // Use the TrieFileStorage backend
    #[test]
    fn marf_insert_256_16_file_storage() {
        let mut marf = marf_insert(
            "/tmp/rust_marf_insert_256_16_file_storage",
            |i| {
                let i0 = i / 256;
                let i1 = i % 256;
                let path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
                ];
                let block_header = if (i + 1) % 16 == 0 {
                    // next block
                    Some(BlockHeaderHash::from_bytes(&[((i + 1) / 16) as u8; 32]).unwrap())
                } else {
                    None
                };
                (path, block_header)
            },
            256,
            true,
        );

        marf.commit().unwrap();

        for i in 0..(256 / 16) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.borrow_storage_backend()
                .open_block(&block_header)
                .unwrap();
            dump_trie(&mut marf.borrow_storage_backend());
        }
    }

    #[test]
    #[ignore]
    fn marf_insert_get_128_fork_256() {
        // create 256 forks organized as a binary tree, and insert 128 values into each one.
        // make sure we can read them all from each chain tip, and make sure we can generate merkle
        // proofs of each one's value.
        let path = ":memory:".to_string();

        let mut m = MARF::from_path(&path).unwrap();
        let mut fork_headers = vec![];

        let mut pattern = 0u8;
        for c in 0..8 {
            let mut next_fork_row = vec![];
            for i in 0..(1 << c) {
                next_fork_row.push(BlockHeaderHash([pattern; 32]));
                pattern += 1;
            }
            fork_headers.push(next_fork_row);
        }

        m.begin(&BlockHeaderHash::sentinel(), &BlockHeaderHash([0u8; 32]))
            .unwrap();
        m.commit().unwrap();

        for i in 1..8 {
            let parent_row = &fork_headers[i - 1];
            for j in 0..parent_row.len() {
                let parent_hash = &parent_row[j];
                for k in (2 * j)..(2 * j + 2) {
                    let child_hash = &fork_headers[i][k];

                    debug!("Branch from {:?} to {:?}", parent_hash, child_hash);
                    m.begin(parent_hash, child_hash).unwrap();

                    let mut keys = vec![];
                    let mut values = vec![];

                    for l in 0..128 {
                        let raw_value = [
                            i as u8, j as u8, k as u8, l as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ]
                        .to_vec();
                        let value = to_hex(&raw_value);
                        let key = format!("{}-{}-{}-{}", i, j, k, l);

                        keys.push(key);
                        values.push(value);
                    }

                    let values = values
                        .drain(..)
                        .map(|x| MARFValue::from_value(&x))
                        .collect();

                    m.insert_batch(&keys, values).unwrap();
                    m.commit().unwrap();
                }
            }
        }

        for (height, fork_row) in fork_headers.iter().enumerate() {
            for block in fork_row.iter() {
                assert_eq!(
                    MARF::get_block_height(&mut m.borrow_storage_backend(), block, block).unwrap(),
                    Some(height as u32)
                );
                assert_eq!(
                    MARF::get_block_at_height(
                        &mut m.borrow_storage_backend(),
                        height as u32,
                        block
                    )
                    .unwrap(),
                    Some(block.clone())
                );
            }
        }

        let mut expected_chain_tips = fork_headers[fork_headers.len() - 1].clone();
        expected_chain_tips.sort();

        let mut block_table = None;

        for k in 0..expected_chain_tips.len() {
            for l in 0..128 {
                let raw_value = [
                    7u8,
                    (k / 2) as u8,
                    k as u8,
                    l as u8,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
                .to_vec();
                let expected_value = to_hex(&raw_value);
                let key = format!("{}-{}-{}-{}", 7, (k / 2), k, l);

                let marf_value = m.get(&expected_chain_tips[k], &key).unwrap().unwrap();
                assert_eq!(marf_value, MARFValue::from_value(&expected_value));

                block_table = Some(merkle_test_marf_key_value(
                    &mut m.borrow_storage_backend(),
                    &expected_chain_tips[k],
                    &key,
                    &expected_value,
                    block_table,
                ));
            }
        }
    }

    #[test]
    #[ignore]
    fn marf_insert_flush_to_different_block() {
        let path = "/tmp/marf_insert_flush_to_different_block".to_string();
        let f = TrieFileStorage::new_memory().unwrap();

        let target_block = BlockHeaderHash([1u8; 32]);

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &target_block)
            .unwrap();

        let mut root_table_cache = None;

        let mut blocks = vec![];
        let num_blocks_created = 8;
        let count = 256 * num_blocks_created;

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
            ];
            let next_block_header = if (i + 1) % 256 == 0 {
                // next block
                Some(BlockHeaderHash::from_bytes(&[
                    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    2, 2, 2, 2, i0 as u8, i1 as u8,
                ]))
                .unwrap()
            } else {
                None
            };

            let triepath = TriePath::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &vec![],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
                ]
                .to_vec(),
            );

            if let Some(next_block_header) = next_block_header {
                marf.commit_to(&block_header).unwrap();
                marf.begin(&block_header, &target_block).unwrap();
                blocks.push(block_header.clone());
                block_header = next_block_header;
            }

            marf.insert_raw(triepath, value.clone()).unwrap();

            // all I/O happens off the target block
            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &target_block,
                &TriePath::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();

            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), target_block);

            // can prove off of the target block
            root_table_cache = Some(merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &target_block,
                &path.to_vec(),
                &value.data.to_vec(),
                root_table_cache,
            ));
        }

        // would have been the next block
        let final_block_header = BlockHeaderHash::from_bytes(&[
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            2,
            (num_blocks_created - 1) as u8,
            0xff,
        ])
        .unwrap();
        marf.commit_to(&final_block_header).unwrap();

        let num_blocks = blocks.len();

        block_header = final_block_header.clone();
        blocks.push(block_header.clone());

        for (i, block) in blocks.iter().enumerate() {
            debug!(
                "Verify block height and hash at {} {} from {}",
                i, block, block_header
            );
            assert_eq!(
                MARF::get_block_height_miner_tip(
                    &mut marf.borrow_storage_backend(),
                    block,
                    &block_header
                )
                .unwrap(),
                Some(i as u32)
            );

            // get_block_at_height should now always return the correct block_header
            assert_eq!(
                MARF::get_block_at_height(
                    &mut marf.borrow_storage_backend(),
                    i as u32,
                    &block_header
                )
                .unwrap(),
                Some(block.clone())
            );
        }

        root_table_cache = None;

        for i in (0..count).rev() {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, i0 as u8, i1 as u8,
            ];

            let triepath = TriePath::from_bytes(&path[..]).unwrap();
            let value = TrieLeaf::new(
                &vec![],
                &[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i0 as u8, i1 as u8,
                ]
                .to_vec(),
            );

            // all but the final value are dangling off of block_header.
            // the last value is dangling off of target_block.

            let read_from_block = final_block_header.clone();

            // all I/O happens off the final block header
            debug!("{}: Get {} off of {}", i, &triepath, &read_from_block);
            let read_value = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &read_from_block,
                &TriePath::from_bytes(&path[..]).unwrap(),
            )
            .unwrap()
            .unwrap();

            assert_eq!(read_value.data.to_vec(), value.data.to_vec());

            if i == 2046 {
                //    std::env::set_var("BLOCKSTACK_TRACE", "1");
            }
            // can make a merkle proof to each one using the final committed block header
            debug!(
                "{}: Check proof for {} off of {}",
                i, &triepath, &read_from_block
            );
            root_table_cache = Some(merkle_test_marf(
                &mut marf.borrow_storage_backend(),
                &read_from_block,
                &path.to_vec(),
                &value.data.to_vec(),
                root_table_cache,
            ));
        }
    }

    #[test]
    fn test_marf_read_only() {
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let marf = MARF::from_storage(f);
        let mut ro_marf = marf.reopen_readonly().unwrap();

        let path = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let triepath = TriePath::from_bytes(&path[..]).unwrap();
        let leaf = TrieLeaf::new(
            &vec![],
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
            .to_vec(),
        );
        let value = MARFValue::from(0x1234);

        // functions that require a transaction _cannot_ be called on a readonly marf, because
        //   both the storage function for initiating a tx _and_ sqlite will have errored before
        //   you could call the function.
        if let Err(Error::ReadOnlyError) = ro_marf.begin_tx() {
        } else {
            assert!(false);
        }
        if let Err(Error::ReadOnlyError) = ro_marf.insert("foo", value.clone()) {
        } else {
            assert!(false);
        }
        if let Err(Error::ReadOnlyError) = ro_marf.insert_raw(triepath.clone(), leaf.clone()) {
        } else {
            assert!(false);
        }
        if let Err(Error::ReadOnlyError) =
            ro_marf.insert_batch(&vec!["foo".to_string()], vec![value.clone()])
        {
        } else {
            assert!(false);
        }
        if let Err(Error::ReadOnlyError) = ro_marf.commit() {
        } else {
            assert!(false);
        }
        if let Err(Error::ReadOnlyError) = ro_marf.commit_mined(&BlockHeaderHash([0x22; 32])) {
        } else {
            assert!(false);
        }
        if let Err(Error::ReadOnlyError) = ro_marf.commit_to(&BlockHeaderHash([0x33; 32])) {
        } else {
            assert!(false);
        }
        if let Err(Error::ReadOnlyError) =
            ro_marf.begin(&BlockHeaderHash([0x22; 32]), &BlockHeaderHash([0x33; 32]))
        {
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_marf_begin_from_sentinel_twice() {
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header_1 = BlockHeaderHash::from_bytes(&[1u8; 32]).unwrap();
        let block_header_2 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);

        let path_1 = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let triepath_1 = TriePath::from_bytes(&path_1[..]).unwrap();

        let path_2 = [
            1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let triepath_2 = TriePath::from_bytes(&path_2[..]).unwrap();

        let value_1 = TrieLeaf::new(&vec![], &vec![1u8; 40]);
        let value_2 = TrieLeaf::new(&vec![], &vec![2u8; 40]);

        marf.begin(&BlockHeaderHash::sentinel(), &block_header_1)
            .unwrap();
        marf.insert_raw(triepath_1, value_1.clone()).unwrap();
        marf.commit_to(&block_header_1).unwrap();

        marf.begin(&BlockHeaderHash::sentinel(), &block_header_2)
            .unwrap();
        marf.insert_raw(triepath_2, value_2.clone()).unwrap();
        marf.commit_to(&block_header_2).unwrap();

        let read_value_1 = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &block_header_1,
            &triepath_1,
        )
        .unwrap()
        .unwrap();
        eprintln!(
            "read_value_1 from {:?} is {:?}",
            &block_header_1, &read_value_1
        );

        let read_value_2 = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &block_header_2,
            &triepath_2,
        )
        .unwrap()
        .unwrap();
        eprintln!(
            "read_value_2 from {:?} is {:?}",
            &block_header_2, &read_value_2
        );

        // should fail
        let read_value_1 = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &block_header_2,
            &triepath_1,
        )
        .unwrap_err();
        if let Error::NotFoundError = read_value_1 {
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_marf_unconfirmed() {
        let marf_path = "/tmp/test_marf_unconfirmed";
        if let Ok(_) = std::fs::metadata(marf_path) {
            std::fs::remove_file(marf_path).unwrap();
        }
        let f = TrieFileStorage::<StacksBlockId>::open_unconfirmed(marf_path).unwrap();
        let mut marf = MARF::<StacksBlockId>::from_storage(f);

        let path_1 = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let triepath_1 = TriePath::from_bytes(&path_1[..]).unwrap();
        let value_1 = TrieLeaf::new(&vec![], &vec![1u8; 40]);

        let path_2 = [
            1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let triepath_2 = TriePath::from_bytes(&path_2[..]).unwrap();
        let value_2 = TrieLeaf::new(&vec![], &vec![2u8; 40]);

        let block_header = StacksBlockId([0x33u8; 32]);

        // set up a confirmed MARF
        {
            let cf = TrieFileStorage::<StacksBlockId>::open(marf_path).unwrap();
            let mut confirmed_marf = MARF::<StacksBlockId>::from_storage(cf);
            confirmed_marf
                .begin(&StacksBlockId::sentinel(), &StacksBlockId([0x11; 32]))
                .unwrap();
            confirmed_marf.commit_to(&block_header).unwrap();
        }

        let unconfirmed_tip = marf.begin_unconfirmed(&block_header).unwrap();
        marf.insert_raw(triepath_1, value_1.clone()).unwrap();
        marf.commit().unwrap();

        // read succeeds
        let read_value_1 = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &unconfirmed_tip,
            &triepath_1,
        )
        .unwrap()
        .unwrap();
        eprintln!(
            "read_value_1 from {:?} is {:?}",
            &unconfirmed_tip, &read_value_1
        );

        marf.begin_unconfirmed(&block_header).unwrap();
        marf.insert_raw(triepath_2, value_2.clone()).unwrap();
        marf.drop_current();

        // read still succeeds -- only current trie is dropped
        let read_value_1 = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &unconfirmed_tip,
            &triepath_1,
        )
        .unwrap()
        .unwrap();
        eprintln!(
            "read_value_1 from {:?} is {:?}",
            &unconfirmed_tip, &read_value_1
        );

        // value 2 is dropped
        let e = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &unconfirmed_tip,
            &triepath_2,
        )
        .unwrap_err();
        if let Error::NotFoundError = e {
        } else {
            assert!(false);
        }

        marf.begin_unconfirmed(&block_header).unwrap();
        marf.drop_unconfirmed();

        // value 1 is dropped
        let e = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &unconfirmed_tip,
            &triepath_1,
        )
        .unwrap_err();
        if let Error::NotFoundError = e {
        } else {
            assert!(false);
        }

        // value 2 is dropped
        let e = MARF::get_path(
            &mut marf.borrow_storage_backend(),
            &unconfirmed_tip,
            &triepath_2,
        )
        .unwrap_err();
        if let Error::NotFoundError = e {
        } else {
            assert!(false);
        }
    }
}
