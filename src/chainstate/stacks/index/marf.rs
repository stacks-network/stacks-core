/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::fmt;
use std::error;
use std::io;
use std::io::{
    Read,
    Write,
    Seek,
    SeekFrom,
    Cursor
};

use std::marker::PhantomData;
use std::fs;

use sha2::Digest;

use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::index::bits::{
    get_node_hash,
    get_nodetype_hash,
    get_nodetype_hash_bytes
};

use chainstate::stacks::index::node::{
    TrieNodeID,
    TrieNodeType,
    TrieNode,
    TrieNode4,
    TrieNode16,
    TrieNode48,
    TrieNode256,
    TrieLeaf,
    TriePtr,
    TRIEPTR_SIZE,
    TrieCursor,
    CursorError,
    TriePath,
    is_backptr,
    set_backptr,
    clear_backptr,
};

use chainstate::stacks::index::storage::{
    TrieFileStorage
};

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
    fast_extend_from_slice,
    MARFValue
};

use chainstate::stacks::index::trie::{
    Trie,
};

use chainstate::stacks::index::Error as Error;

use util::log;

/// Merklized Adaptive-Radix Forest -- a collection of Merklized Adaptive-Radix Tries.
pub struct MARF {
    storage: TrieFileStorage,
    open_chain_tip: Option<BlockHeaderHash>
}

impl MARF {
    // helper method for walking a node's backpr
    fn walk_backptr(storage: &mut TrieFileStorage, start_node: &TrieNodeType, chr: u8, cursor: &mut TrieCursor) -> Result<(TrieNodeType, TrieHash, TriePtr, u32), Error> {
        if start_node.is_leaf() {
            panic!("Did not get an intermediate node");
        }

        let ptr_opt = start_node.walk(chr);
        match ptr_opt {
            None => {
                // this node never had a child for this chr
                trace!("Failed to walk to '{}' from {:?}", chr, start_node);
                Err(Error::BackptrNotFoundError)
            },
            Some(ptr) => {
                trace!("Walk backptrs for {:?} to {:?} from {:?}", cursor, &ptr, &start_node);
                
                // this node had a child for this chr at one point
                let (node, node_hash, node_ptr) = Trie::walk_backptr(storage, &ptr, cursor)?;
                Ok((node, node_hash, node_ptr, ptr.back_block))
            }
        }
    }

    fn node_copy_update_ptrs(ptrs: &mut [TriePtr], node_dist: u32) -> () {
        for i in 0..ptrs.len() {
            if ptrs[i].id() == TrieNodeID::Empty {
                continue;
            }
            else if is_backptr(ptrs[i].id()) {
                // increase depth
                ptrs[i].back_block += node_dist;
            }
            else {
                // make backptr
                ptrs[i].back_block = node_dist;
                ptrs[i].id = set_backptr(ptrs[i].id());
            }
        }
    }
   
    fn node_copy_update(node: &mut TrieNodeType, node_dist: u32) -> Result<TrieHash, Error> {
        let hash = 
            if node.is_leaf() {
                get_nodetype_hash_bytes(&node, &vec![])
            }
            else {
                MARF::node_copy_update_ptrs(node.ptrs_mut(), node_dist);
                TrieHash::from_data(&[])
            };
        
        Ok(hash)
    }
    
    /// Given a node, and the chr of one of its children, go find the last instance of that child in
    /// the MARF and copy it forward.  Update its ptrs to point to its descendents.
    /// s must point to the block hash in which this node lives, to which the child will be copied.
    fn node_child_copy(storage: &mut TrieFileStorage, node: &TrieNodeType, chr: u8, cursor: &mut TrieCursor) -> Result<(TrieNodeType, TrieHash, TriePtr, BlockHeaderHash), Error> {
        trace!("Copy to {:?} child {:x} of {:?}", storage.get_cur_block(), chr, node);

        let cur_block_hash = storage.get_cur_block();
        let (mut child_node, _, child_ptr, child_dist) = MARF::walk_backptr(storage, node, chr, cursor)?;
        let child_block_hash = storage.get_cur_block();

        // update child_node with new ptrs and hashes
        storage.open_block(&cur_block_hash, true)?;
        let child_hash = MARF::node_copy_update(&mut child_node, child_dist)?;

        // store it in this trie
        storage.open_block(&cur_block_hash, true)?;
        let child_disk_ptr = storage.last_ptr()?;
        let child_ptr = TriePtr::new(child_ptr.id(), chr, child_disk_ptr);
        storage.write_nodetype(child_disk_ptr, &child_node, child_hash.clone())?;

        trace!("Copied child 0x{:02x} to {:?}: ptr={:?} child={:?}", chr, &cur_block_hash, &child_ptr, &child_node);
        Ok((child_node, child_hash, child_ptr, child_block_hash))
    }

    /// Copy the root node from the previous Trie to this Trie, updating its ptrs.
    /// s must point to the target Trie
    fn root_copy(storage: &mut TrieFileStorage, prev_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        let cur_block_hash = storage.get_cur_block();
        storage.open_block(prev_block_hash, false)?;
        
        let (mut prev_root, _) = Trie::read_root(storage)?;
        let new_root_hash = MARF::node_copy_update(&mut prev_root, 1)?;
        
        storage.open_block(&cur_block_hash, true)?;
        
        let root_ptr = storage.root_ptr();
        storage.write_nodetype(root_ptr, &prev_root, new_root_hash)?;
        Ok(())
    }
    
    /// create or open a particular Trie.
    /// If the trie doesn't exist, then extend it from the current Trie and create a root node that
    /// has back pointers to its immediate children in the current trie.
    /// On Ok, s will point to new_bhh and will be open for reading
    pub fn extend_trie(storage: &mut TrieFileStorage, new_bhh: &BlockHeaderHash) -> Result<(), Error> {
        let cur_bhh = storage.get_cur_block();
        if storage.num_blocks() == 0 {
            // brand new storage
            trace!("Brand new storage -- start with {:?}", new_bhh);
            storage.extend_to_block(new_bhh)?;
            let node = TrieNode256::new(&vec![]);
            let hash = get_node_hash(&node, &vec![]);
            let root_ptr = storage.root_ptr();
            storage.write_nodetype(root_ptr, &TrieNodeType::Node256(node), hash)
        }
        else {
            // existing storage
            match storage.open_block(new_bhh, true) {
                Ok(_) => {
                    trace!("Switch to Trie {:?}", new_bhh);
                    Ok(())
                }
                Err(e) => {
                    match e {
                        Error::NotFoundError => {
                            // bring root forward
                            trace!("Extend {:?} to {:?}", &cur_bhh, new_bhh);
                            storage.open_block(&cur_bhh, true)?;
                            storage.extend_to_block(new_bhh)?;
                            MARF::root_copy(storage, &cur_bhh)?;
                            storage.open_block(new_bhh, false)?;
                            Ok(())
                        },
                        _ => {
                            Err(e)
                        }
                    }
                }
            }
        }
    }

    /// Walk down this MARF at the given block hash, doing a copy-on-write for intermediate nodes in this block's Trie from any prior Tries.
    /// s must point to the last filled-in Trie -- i.e. block_hash points to the _new_ Trie that is
    /// being filled in.
    fn walk_cow(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath) -> Result<TrieCursor, Error> {
        MARF::extend_trie(storage, block_hash)?;

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        // walk to insertion point 
        let (mut node, _) = Trie::read_root(storage)?;
        let mut node_ptr = TriePtr::new(0,0,0);

        for _ in 0..(cursor.path.len()+1) {
            match Trie::walk_from(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((next_node_ptr, next_node, _)) => {
                            // end of node path.
                            // keep walking.
                            node = next_node;
                            node_ptr = next_node_ptr;
                            continue;
                        },
                        None => {
                            // end of path.  Should have found leaf.
                            if !node.is_leaf() || clear_backptr(node_ptr.id()) != TrieNodeID::Leaf {
                                error!("Out-of-path but encountered a non-leaf");
                                return Err(Error::CorruptionError("Non-leaf encountered at end of path".to_string()));
                            }

                            trace!("Out of path in {:?} -- we're done. Node at {:?}", storage.get_cur_block(), &node_ptr);
                            storage.open_block(block_hash, true)?;
                            return Ok(cursor);
                        }
                    }
                },
                Err(e) => {
                    match e {
                        Error::CursorError(cursor_error) => {
                            match cursor_error {
                                CursorError::PathDiverged => {
                                    // we're done -- path diverged.  Will need to copy-on-write
                                    // some nodes over.
                                    trace!("Path diverged -- we're done.");
                                    storage.open_block(block_hash, true)?;
                                    return Ok(cursor);
                                },
                                CursorError::ChrNotFound => {
                                    // end-of-node-path but no such child -- not even a backptr.
                                    trace!("ChrNotFound encountered at {:?} -- we're done (node not found)", storage.get_cur_block());
                                    storage.open_block(block_hash, true)?;
                                    return Ok(cursor);
                                },
                                CursorError::BackptrEncountered(ptr) => {
                                    // at intermediate node whose child is not present in this trie.
                                    // bring the child forward and take the step, if possible.
                                    storage.open_block(block_hash, true)?;
                                    let (next_node, _, next_node_ptr, next_node_block_hash) = MARF::node_child_copy(storage, &node, ptr.chr(), &mut cursor)?;

                                    // finish taking the step
                                    cursor.repair_backptr_finish(&next_node_ptr, &next_node_block_hash);
                                    
                                    // keep walking
                                    node = next_node;
                                    node_ptr = next_node_ptr;
                                    
                                    storage.open_block(block_hash, true)?;
                                }
                            }
                        },
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
    fn walk(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath) -> Result<(TrieCursor, TrieNodeType), Error> {
        storage.open_block(block_hash, false)?;

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        // walk to insertion point 
        let (mut node, _) = Trie::read_root(storage)?;
        let mut node_ptr = TriePtr::new(0,0,0);

        for _ in 0..(cursor.path.len()+1) {
            match Trie::walk_from(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((next_node_ptr, next_node, _)) => {
                            // end-of-node-path, and found a child.
                            // keep walking
                            node = next_node;
                            node_ptr = next_node_ptr;
                            continue;
                        },
                        None => {
                            // end of path.  Must be at a leaf.
                            if clear_backptr(cursor.ptr().id()) != TrieNodeID::Leaf {
                                return Err(Error::CorruptionError("Non-leaf encountered at end of path".to_string()));
                            }

                            return Ok((cursor, node));
                        }
                    }
                },
                Err(e) => {
                    match e {
                        Error::CursorError(cursor_error) => {
                            match cursor_error {
                                CursorError::PathDiverged => {
                                    // we're done -- path diverged.  No backptr-walking can help us.
                                    trace!("Path diverged -- we're done.");
                                    return Err(Error::NotFoundError);
                                },
                                CursorError::ChrNotFound => {
                                    // we're done -- end-of-node-path, but no child node.
                                    // Not even a backptr.
                                    trace!("ChrNotFound encountered -- node does not exist");
                                    return Err(Error::NotFoundError);
                                },
                                CursorError::BackptrEncountered(ptr) => {
                                    // at intermediate node whose child is not present in this trie.
                                    // try to shunt to the prior node that has the child itself.
                                    let (next_node, _, next_node_ptr, _) = MARF::walk_backptr(storage, &node, ptr.chr(), &mut cursor)?;
                                   
                                    // finish taking the step
                                    cursor.repair_backptr_finish(&next_node_ptr, &storage.get_cur_block());

                                    // keep going
                                    node = next_node;
                                    node_ptr = next_node_ptr;
                                    continue;
                                }
                            }
                        },
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

    pub fn format(storage: &mut TrieFileStorage, first_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        storage.format()?;
        storage.extend_to_block(first_block_hash)?;
        let node = TrieNodeType::Node256(TrieNode256::new(&vec![]));
        let hash = get_nodetype_hash(&node, &vec![]);
        let root_ptr = storage.root_ptr();
        storage.write_nodetype(root_ptr, &node, hash)
    }

    pub fn get_path(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath) -> Result<Option<TrieLeaf>, Error> {
        trace!("MARF::get_path({:?}) {:?}", block_hash, path);

        storage.open_block(block_hash, false)?;
        let (cursor, node) = MARF::walk(storage, block_hash, path)?;

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
            },
            _ => {
                // Trie invariant violation -- a full path reached a non-leaf
                return Err(Error::CorruptionError("Path reached a non-leaf".to_string()));
            }
        }
    }

    fn do_insert_leaf(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath, leaf_value: &TrieLeaf, update_skiplist: bool) -> Result<(), Error> {
        let mut value = leaf_value.clone();
        let mut cursor = MARF::walk_cow(storage, block_hash, path)?;
        
        if cursor.block_hashes.len() + 1 != cursor.node_ptrs.len() {
            trace!("c.block_hashes = {:?}", &cursor.block_hashes);
            trace!("c.node_ptrs = {:?}", cursor.node_ptrs);
            assert!(false);
        }
        
        Trie::add_value(storage, &mut cursor, &mut value)?;

        if update_skiplist {
            Trie::update_root_hash(storage, &cursor)?;
        }
        else {
            Trie::update_root_node_hash(storage, &cursor)?;
        }
        Ok(())
    }

    pub fn insert_leaf(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath, value: &TrieLeaf) -> Result<(), Error> {
        MARF::do_insert_leaf(storage, block_hash, path, value, true)
    }
    
    // like insert_leaf, but don't update the merkle skiplist
    pub fn insert_leaf_in_batch(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath, value: &TrieLeaf) -> Result<(), Error> {
        MARF::do_insert_leaf(storage, block_hash, path, value, false)
    }

    /// Instantiate the MARF from a TrieFileStorage instance 
    pub fn from_storage(storage: TrieFileStorage) -> MARF {
        MARF {
            storage: storage,
            open_chain_tip: None,
        }
    }

    /// Instantiate the MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path(path: &str) -> Result<MARF, Error> {
        let mut file_storage = TrieFileStorage::new(path)?;
        match fs::metadata(path) {
            Ok(_) => {},
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::IOError(e));
                }

                MARF::format(&mut file_storage, &TrieFileStorage::block_sentinel())?;
            }
        };

        Ok(MARF::from_storage(file_storage))
    }

    /// Resolve a key from the MARF to a MARFValue with respect to the given block height.
    pub fn get(&mut self, block_hash: &BlockHeaderHash, key: &str) -> Result<Option<MARFValue>, Error> {
        let cur_block_hash = self.storage.get_cur_block();
        let cur_block_rw = self.storage.readwrite();

        let path = TriePath::from_key(key);

        let leaf_opt_res = MARF::get_path(&mut self.storage, block_hash, &path)?;

        // restore
        self.storage.open_block(&cur_block_hash, cur_block_rw)?;

        match leaf_opt_res {
            None => {
                Ok(None)
            },
            Some(leaf) => {
                Ok(Some(leaf.data))
            }
        }
    }

    /// Insert the given (key, value) pair into the MARF.  Inserting the same key twice silently
    /// overwrites the existing key.  Succeeds if there are no storage errors.
    /// Must be called after a call to .begin() (will fail otherwise)
    pub fn insert(&mut self, key: &str, value: MARFValue) -> Result<(), Error> {
        match self.open_chain_tip {
            None => {
                Err(Error::WriteNotBegunError)
            },
            Some(ref block_hash) => {
                let cur_block_hash = self.storage.get_cur_block();
                let cur_block_rw = self.storage.readwrite();

                let marf_leaf = TrieLeaf::from_value(&vec![], value);
                let path = TriePath::from_key(key);

                MARF::insert_leaf(&mut self.storage, block_hash, &path, &marf_leaf)?;
                
                // restore
                self.storage.open_block(&cur_block_hash, cur_block_rw)?;
                Ok(())
            }
        }
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    pub fn insert_batch(&mut self, keys: &Vec<String>, values: Vec<MARFValue>) -> Result<(), Error> {
        assert_eq!(keys.len(), values.len());

        match self.open_chain_tip {
            None => {
                Err(Error::WriteNotBegunError)
            },
            Some(ref block_hash) => {
                if keys.len() == 0 {
                    return Ok(());
                }
        
                let cur_block_hash = self.storage.get_cur_block();
                let cur_block_rw = self.storage.readwrite();
                
                let mut i = 0;
                while i < keys.len() - 1 {
                    let key = &keys[i];
                    let value = &values[i];
                
                    let marf_leaf = TrieLeaf::from_value(&vec![], value.clone());
                    let path = TriePath::from_key(key);

                    MARF::insert_leaf_in_batch(&mut self.storage, block_hash, &path, &marf_leaf)?;
                    i += 1;
                }

                // last insert updates the root with the skiplist hash
                let marf_leaf = TrieLeaf::from_value(&vec![], values[i].clone());
                let path = TriePath::from_key(&keys[i]);
                MARF::insert_leaf(&mut self.storage, block_hash, &path, &marf_leaf)?;

                // restore
                self.storage.open_block(&cur_block_hash, cur_block_rw)?;
                Ok(())
            }
        }
    }

    /// Begin writing the next trie in the MARF, given the block header hash that will contain the
    /// associated block's new state.  Call commit() to persist the changes.
    /// Fails if the block already exists.
    /// Storage will point to new chain tip on success.
    pub fn begin(&mut self, chain_tip: &BlockHeaderHash, next_chain_tip: &BlockHeaderHash) -> Result<(), Error> {
        if self.open_chain_tip.is_some() {
            return Err(Error::InProgressError);
        }

        // new chain tip must not exist
        if self.storage.open_block(next_chain_tip, true).is_ok() {
            return Err(Error::ExistsError);
        }

        // current chain tip must exist
        if self.chain_tips().len() > 0 {
            self.storage.open_block(chain_tip, false)?;
        }

        MARF::extend_trie(&mut self.storage, next_chain_tip)?;
        self.open_chain_tip = Some(next_chain_tip.clone());
        Ok(())
    }

    /// Finish writing the next trie in the MARF.  This persists all changes.
    pub fn commit(&mut self) -> Result<(), Error> {
        match self.open_chain_tip.take() {
            Some(tip) => {
                self.storage.flush()?;
            },
            None => {}
        };
        Ok(())
    }

    /// Get open chain tip
    pub fn get_open_chain_tip(&self) -> Option<&BlockHeaderHash> {
        self.open_chain_tip.as_ref()
    }

    /// Get all known chain tips
    pub fn chain_tips(&mut self) -> Vec<BlockHeaderHash> {
        self.storage.chain_tips()
    }

    /// Check if a block can open successfully, i.e.,
    ///   it's a known block, the storage system isn't issueing IOErrors, _and_ it's in the same fork
    ///   as the current block
    /// The MARF _must_ be open to a valid block for this check to be evaluated.
    pub fn check_block_hash(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        let cur_block_hash = self.storage.get_cur_block();
        let cur_block_rw = self.storage.readwrite();

        let cur_block_fork_ptr = self.storage.fork_table.get_fork_ptr(&cur_block_hash)
            .unwrap_or_else(|e| match e {
                Error::NotFoundError => panic!("Fork table does not contain entry for the current MARF block {:?}", cur_block_hash),
                e => panic!("Unexpected fork table error {}", e)
            });

        let bhh_fork_ptr = self.storage.fork_table.get_fork_ptr(bhh)?;

        if bhh_fork_ptr.fork_id != cur_block_fork_ptr.fork_id {
            return Err(Error::NonMatchingForks(bhh_fork_ptr.fork_id, cur_block_fork_ptr.fork_id))
        }

        // test open
        let result = self.storage.open_block(bhh, false);

        // restore
        self.storage.open_block(&cur_block_hash, cur_block_rw)
            .map_err(|e| Error::RestoreMarfBlockError(Box::new(e)))?;

        result
    }

    /// Access internal storage
    #[cfg(test)]
    pub fn borrow_storage_backend(&mut self) -> &mut TrieFileStorage {
        &mut self.storage
    }
}

#[cfg(test)]
mod test {

    #![allow(unused_variables)]
    #![allow(unused_assignments)]
    use super::*;
    use std::io::{
        Cursor
    };
    use std::fs;

    use chainstate::stacks::index::test::*;
    
    use chainstate::stacks::index::bits::*;
    use chainstate::stacks::index::fork_table::*;
    use chainstate::stacks::index::marf::*;
    use chainstate::stacks::index::node::*;
    use chainstate::stacks::index::proofs::*;
    use chainstate::stacks::index::storage::*;
    use chainstate::stacks::index::trie::*;

    use util::get_epoch_time_ms;
    use util::hash::to_hex;

    #[test]
    fn marf_insert_different_leaf_same_block_100() {
        let path = "/tmp/rust_marf_insert_different_leaf_same_block_100".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header_1).unwrap();

        let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let path = TriePath::from_bytes(&path_bytes).unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0; 32]).unwrap();

        for i in 0..100 {
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            MARF::insert_leaf(&mut f, &block_header, &path, &value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        let value = TrieLeaf::new(&vec![], &[99; 40].to_vec());
        let leaf = MARF::get_path(&mut f, &block_header, &path).unwrap().unwrap();

        assert_eq!(leaf.data.to_vec(), [99; 40].to_vec());
        assert_eq!(f.get_cur_block(), block_header);

        merkle_test_marf(&mut f, &block_header, &path_bytes.to_vec(), &[99; 40].to_vec());
    }
    
    #[test]
    fn marf_insert_different_leaf_different_path_different_block_100() {
        let path = "/tmp/rust_marf_insert_different_leaf_different_path_different_block_100".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header_1).unwrap();

        for i in 0..100 {
            test_debug!("insert {}", i);
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,i as u8];
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            MARF::insert_leaf(&mut f, &block_header, &path, &value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..100 {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,i as u8];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(&mut f, &block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.get_cur_block(), block_header);

            merkle_test_marf(&mut f, &block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec());
        }
    }

    #[test]
    fn marf_insert_same_leaf_different_block_100() {
        let path = "/tmp/rust_marf_same_leaf_different_block_100".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header_1).unwrap();

        let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let path = TriePath::from_bytes(&path_bytes).unwrap();

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            MARF::insert_leaf(&mut f, &next_block_header, &path, &value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(&mut f, &next_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.get_cur_block(), next_block_header);

            merkle_test_marf(&mut f, &next_block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec());
        }
    }
    
    #[test]
    fn marf_insert_leaf_sequence_2() {
        let path = "/tmp/rust_marf_insert_leaf_sequence_2".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header_1).unwrap();

        for i in 0..2 {
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            MARF::insert_leaf(&mut f, &next_block_header, &path, &value).unwrap();
        }
        
        let last_block_header = BlockHeaderHash::from_bytes(&[1; 32]).unwrap();

        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..2 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(&mut f, &last_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.get_cur_block(), next_block_header);

            merkle_test_marf(&mut f, &last_block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec());
        }
    }
    
    #[test]
    fn marf_insert_leaf_sequence_100() {
        let path = "/tmp/rust_marf_insert_leaf_sequence_100".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header_1).unwrap();

        for i in 0..100 {
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            MARF::insert_leaf(&mut f, &next_block_header, &path, &value).unwrap();
        }
        
        let last_block_header = BlockHeaderHash::from_bytes(&[99; 32]).unwrap();

        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(&mut f, &last_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.get_cur_block(), next_block_header);

            merkle_test_marf(&mut f, &last_block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec());
        }
    }

    #[test]
    fn marf_walk_cow_node4_20() {
        let path = "/tmp/rust_marf_walk_cow_node4_20".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header_1).unwrap();

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
        let path = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];

        let (nodes, node_ptrs, hashes) = make_node4_path(&mut f, &path_segments, [31u8; 40].to_vec());
        dump_trie(&mut f);

        for i in 1..31 {
            test_debug!("----------------");
            test_debug!("i = {}", i);
            test_debug!("----------------");

            // switch to the next block
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();

            // add a leaf at the end of the path
            let mut next_path = path.clone();
            next_path[i] = 32;
            
            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            
            test_debug!("----------------");
            test_debug!("insert");
            test_debug!("----------------");
            MARF::insert_leaf(&mut f, &next_block_header, &triepath, &value).unwrap();

            // verify that this leaf exists in _this_ Trie
            test_debug!("----------------");
            test_debug!("get");
            test_debug!("----------------");
            let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(read_value.path, next_path[i+1..].to_vec());
            assert_eq!(f.get_cur_block(), next_block_header);

            // can get all previous leaves from _this_ Trie
            for j in 1..(i+1) {
                test_debug!("----------------");
                test_debug!("get-prev {} of {}", j, i);
                test_debug!("----------------");

                let mut prev_path = path.clone();
                prev_path[j] = 32;
            
                let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.data.to_vec(), [j as u8; 40].to_vec());
                assert_eq!(f.get_cur_block(), prev_block_header);
            }

            f.open_block(&next_block_header, false).unwrap();

            dump_trie(&mut f);
           
            merkle_test_marf(&mut f, &next_block_header, &next_path, &[i as u8; 40].to_vec());
        }

        // all leaves are reachable from the last block 
        let last_block_header = BlockHeaderHash::from_bytes(&[30u8; 32]).unwrap();
        for i in 1..19 {
            // add a leaf at the end of the path
            let mut next_path = path.clone();
            next_path[i] = 32;
            
            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = TrieLeaf::new(&next_path[i+1..].to_vec(), &[i as u8; 40].to_vec());

            assert_eq!(MARF::get_path(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
            
            merkle_test_marf(&mut f, &last_block_header, &next_path, &[i as u8; 40].to_vec());
        }
    }

    #[test]
    fn marf_walk_cow_node4_20_reversed() {
        let path = "/tmp/rust_marf_walk_cow_node4_20_reversed".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header_1).unwrap();

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
        let path = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];

        let (nodes, node_ptrs, hashes) = make_node4_path(&mut f, &path_segments, [31u8; 40].to_vec());
        dump_trie(&mut f);

        for i in 1..31 {
            test_debug!("----------------");
            test_debug!("i = {}", i);
            test_debug!("----------------");

            // switch to the next block
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();

            // add a leaf at the end of the path
            let mut next_path = path.clone();
            next_path[31 - i] = 32;
            
            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            
            test_debug!("----------------");
            test_debug!("insert");
            test_debug!("----------------");
            MARF::insert_leaf(&mut f, &next_block_header, &triepath, &value).unwrap();

            // verify that this leaf exists in _this_ Trie
            test_debug!("----------------");
            test_debug!("get");
            test_debug!("----------------");
            let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(read_value.path, next_path[31-i+1..].to_vec());
            assert_eq!(f.get_cur_block(), next_block_header);

            // can get all previous leaves from _this_ Trie
            for j in 1..(i+1) {
                test_debug!("----------------");
                test_debug!("get-prev {} of {}", j, i);
                test_debug!("----------------");

                let mut prev_path = path.clone();
                prev_path[31-j] = 32;
            
                let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.data.to_vec(), [j as u8; 40].to_vec());
                assert_eq!(f.get_cur_block(), prev_block_header);
            }

            f.open_block(&next_block_header, false).unwrap();

            dump_trie(&mut f);
            
            merkle_test_marf(&mut f, &next_block_header, &next_path, &[i as u8; 40].to_vec());
        }

        // all leaves are reachable from the last block 
        let last_block_header = BlockHeaderHash::from_bytes(&[30u8; 32]).unwrap();
        for i in 1..31 {
            // add a leaf at the end of the path
            let mut next_path = path.clone();
            next_path[31-i] = 32;
            
            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = TrieLeaf::new(&next_path[31-i+1..].to_vec(), &[i as u8; 40].to_vec());

            assert_eq!(MARF::get_path(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
            
            merkle_test_marf(&mut f, &last_block_header, &next_path, &[i as u8; 40].to_vec());
        }
    }

    #[test]
    fn marf_walk_cow_4() {
        for node_id in [TrieNodeID::Node4, TrieNodeID::Node16, TrieNodeID::Node48, TrieNodeID::Node256].iter() {
            let path = format!("/tmp/rust_marf_walk_cow_node4_20_reversed-{}", node_id);
            match fs::metadata(&path) {
                Ok(_) => {
                    fs::remove_dir_all(&path).unwrap();
                },
                Err(_) => {}
            };
            let mut f = TrieFileStorage::new(&path).unwrap();

            let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
            MARF::format(&mut f, &block_header_1).unwrap();

            let path_segments = vec![
                (vec![0,1,2,3], 4),
                (vec![5,6,7,8], 9),
                (vec![10,11,12,13], 14),
                (vec![15,16,17,18], 19),
                (vec![20,21,22,23], 24),
                (vec![25,26,27,28], 29),
                (vec![30], 31),
            ];
            let path = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];

            let (nodes, node_ptrs, hashes) = make_node_path(&mut f, *node_id, &path_segments, [31u8; 40].to_vec());
            dump_trie(&mut f);

            for i in 1..31 {
                test_debug!("----------------");
                test_debug!("i = {}", i);
                test_debug!("----------------");

                // switch to the next block
                let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();

                // add a leaf at the end of the path
                let mut next_path = path.clone();
                next_path[i] = 32;
                
                let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
                let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
                
                test_debug!("----------------");
                test_debug!("insert");
                test_debug!("----------------");
                MARF::insert_leaf(&mut f, &next_block_header, &triepath, &value).unwrap();

                // verify that this leaf exists in _this_ Trie
                test_debug!("----------------");
                test_debug!("get");
                test_debug!("----------------");
                let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.data.to_vec(), [i as u8; 40].to_vec());
                assert_eq!(read_value.path, next_path[i+1..].to_vec());
                assert_eq!(f.get_cur_block(), next_block_header);

                // can get all previous leaves from _this_ Trie
                for j in 1..(i+1) {
                    test_debug!("----------------");
                    test_debug!("get-prev {} of {}", j, i);
                    test_debug!("----------------");

                    let mut prev_path = path.clone();
                    prev_path[j] = 32;
                
                    let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                    let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                    assert_eq!(read_value.data.to_vec(), [j as u8; 40].to_vec());
                    assert_eq!(f.get_cur_block(), prev_block_header);
                
                    test_debug!("---------------------------------------");
                    test_debug!("MARF verify {:?} {:?} from current block header {:?}", &prev_path, &[j as u8; 40].to_vec(), &next_block_header);
                    test_debug!("----------------------------------------");
                    merkle_test_marf(&mut f, &next_block_header, &prev_path, &[j as u8; 40].to_vec());
                }

                f.open_block(&next_block_header, false).unwrap();
                dump_trie(&mut f);
                
                merkle_test_marf(&mut f, &next_block_header, &next_path, &[i as u8; 40].to_vec());
            }

            // all leaves are reachable from the last block 
            let last_block_header = BlockHeaderHash::from_bytes(&[30u8; 32]).unwrap();
            for i in 1..31 {
                // add a leaf at the end of the path
                let mut next_path = path.clone();
                next_path[i] = 32;
                
                let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
                let value = TrieLeaf::new(&next_path[i+1..].to_vec(), &[i as u8; 40].to_vec());

                assert_eq!(MARF::get_path(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
                
                test_debug!("---------------------------------------");
                test_debug!("MARF verify {:?} {:?} from last block header {:?}", &next_path, &[i as u8; 40].to_vec(), &last_block_header);
                test_debug!("----------------------------------------");
                merkle_test_marf(&mut f, &last_block_header, &next_path, &[i as u8; 40].to_vec());
            }
        }
    }
    
    #[test]
    fn marf_merkle_verify_backptrs() {
        for node_id in [TrieNodeID::Node4, TrieNodeID::Node16, TrieNodeID::Node48, TrieNodeID::Node256].iter() {
            let path = format!("/tmp/rust_marf_merkle_verify_backptrs-{}", node_id);
            match fs::metadata(&path) {
                Ok(_) => {
                    fs::remove_dir_all(&path).unwrap();
                },
                Err(_) => {}
            };
            let mut f = TrieFileStorage::new(&path).unwrap();

            let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
            MARF::format(&mut f, &block_header_1).unwrap();

            let path_segments = vec![
                (vec![0,1,2,3,4,5,6,7,8,9,10,11], 12),
                (vec![13,14,15,16,17,18,19,20,21,24], 25),
                (vec![26,27,28,29,30], 31)
            ];
            
            let path = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];

            let (nodes, node_ptrs, hashes) = make_node_path(&mut f, *node_id, &path_segments, [31u8; 40].to_vec());
            dump_trie(&mut f);

            let block_header_2 = BlockHeaderHash::from_bytes(&[1u8; 32]).unwrap();
            let path_2 = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,32];
            
            test_debug!("----------------");
            test_debug!("Extend to {:?}", block_header_2);
            test_debug!("----------------");

            MARF::insert_leaf(&mut f, &block_header_2, &TriePath::from_bytes(&path_2[..]).unwrap(), &TrieLeaf::new(&vec![], &[20 as u8; 40].to_vec())).unwrap();
            
            let block_header_3 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
            let path_3 = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,33];
            
            test_debug!("----------------");
            test_debug!("Extend to {:?}", block_header_3);
            test_debug!("----------------");

            MARF::insert_leaf(&mut f, &block_header_3, &TriePath::from_bytes(&path_3[..]).unwrap(), &TrieLeaf::new(&vec![], &[21 as u8; 40].to_vec())).unwrap();

            test_debug!("----------------");
            test_debug!("MARF at {:?}", &block_header_1);
            test_debug!("----------------");
            f.open_block(&block_header_1, false).unwrap();
            dump_trie(&mut f);

            test_debug!("----------------");
            test_debug!("MARF at {:?}", &block_header_2);
            test_debug!("----------------");
            f.open_block(&block_header_2, false).unwrap();
            dump_trie(&mut f);


            test_debug!("----------------");
            test_debug!("MARF at {:?}", &block_header_3);
            test_debug!("----------------");
            f.open_block(&block_header_3, false).unwrap();
            dump_trie(&mut f);

            test_debug!("----------------");
            test_debug!("Merkle verify {:?} from {:?}", &to_hex(&[21 as u8; 40]), block_header_3);
            test_debug!("----------------");

            merkle_test_marf(&mut f, &block_header_3, &path_3, &[21 as u8; 40].to_vec());
        }
    }

    #[test]
    fn marf_walk_cow_4_reversed() {
        for node_id in [TrieNodeID::Node4, TrieNodeID::Node16, TrieNodeID::Node48, TrieNodeID::Node256].iter() {
            let path = format!("/tmp/rust_marf_walk_cow_4_reversed-{}", node_id);
            match fs::metadata(&path) {
                Ok(_) => {
                    fs::remove_dir_all(&path).unwrap();
                },
                Err(_) => {}
            };
            let mut f = TrieFileStorage::new(&path).unwrap();

            let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
            MARF::format(&mut f, &block_header_1).unwrap();

            let path_segments = vec![
                (vec![0,1,2,3], 4),
                (vec![5,6,7,8], 9),
                (vec![10,11,12,13], 14),
                (vec![15,16,17,18], 19),
                (vec![20,21,22,23], 24),
                (vec![25,26,27,28], 29),
                (vec![30], 31)
            ];
            let path = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];

            let (nodes, node_ptrs, hashes) = make_node_path(&mut f, *node_id, &path_segments, [31u8; 40].to_vec());
            dump_trie(&mut f);

            for i in 1..31 {
                test_debug!("----------------");
                test_debug!("i = {}", i);
                test_debug!("----------------");

                // switch to the next block
                let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();

                // add a leaf at the end of the path
                let mut next_path = path.clone();
                next_path[31 - i] = 32;
                
                let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
                let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
                
                test_debug!("----------------");
                test_debug!("insert");
                test_debug!("----------------");
                MARF::insert_leaf(&mut f, &next_block_header, &triepath, &value).unwrap();

                // verify that this leaf exists in _this_ Trie
                test_debug!("----------------");
                test_debug!("get");
                test_debug!("----------------");
                let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.data.to_vec(), [i as u8; 40].to_vec());
                assert_eq!(read_value.path, next_path[31-i+1..].to_vec());
                assert_eq!(f.get_cur_block(), next_block_header);

                // can get all previous leaves from _this_ Trie
                for j in 1..(i+1) {
                    test_debug!("----------------");
                    test_debug!("get-prev {} of {}", j, i);
                    test_debug!("----------------");

                    let mut prev_path = path.clone();
                    prev_path[31-j] = 32;
                
                    let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                    let read_value = MARF::get_path(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                    assert_eq!(read_value.data.to_vec(), [j as u8; 40].to_vec());
                    assert_eq!(f.get_cur_block(), prev_block_header);
                }

                f.open_block(&next_block_header, false).unwrap();

                dump_trie(&mut f);
                
                merkle_test_marf(&mut f, &next_block_header, &next_path, &[i as u8; 40].to_vec());
            }

            // all leaves are reachable from the last block 
            let last_block_header = BlockHeaderHash::from_bytes(&[30u8; 32]).unwrap();
            for i in 1..31 {
                // add a leaf at the end of the path
                let mut next_path = path.clone();
                next_path[31-i] = 32;
                
                let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
                let value = TrieLeaf::new(&next_path[31-i+1..].to_vec(), &[i as u8; 40].to_vec());

                assert_eq!(MARF::get_path(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
                
                test_debug!("---------------------------------------");
                test_debug!("MARF verify {:?} {:?} from last block header {:?}", &next_path, &[i as u8; 40].to_vec(), &last_block_header);
                test_debug!("----------------------------------------");
                merkle_test_marf(&mut f, &last_block_header, &next_path, &[i as u8; 40].to_vec());
            }
        }
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 128 keys, make a new trie
    #[test]
    fn marf_insert_4096_128_seq_low() {
        let path = "/tmp/rust_marf_insert_4096_128_seq_low".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();

        for i in 0..4096 {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if (i + 1) % 128 == 0 {
                // next block 
                block_header = BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap();
            }

            MARF::insert_leaf(&mut f, &block_header, &triepath, &value).unwrap();
             
            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(f.get_cur_block(), block_header);
        }

        for i in 0..4096 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the high-order bits.
    // every 128 keys, make a new trie
    #[test]
    fn marf_insert_4096_128_seq_high() {
        let path = "/tmp/rust_marf_insert_4096_128_seq_high".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();

        for i in 0..4096 {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [i0 as u8, i1 as u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if (i + 1) % 128 == 0 {
                // next block 
                block_header = BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap();
            }

            MARF::insert_leaf(&mut f, &block_header, &triepath, &value).unwrap();
             
            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(f.get_cur_block(), block_header);
        }

        for i in 0..4096 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [i0 as u8, i1 as u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }
    }

    // insert a leaf, open a new block, and attempt to split the leaf
    // TODO: try also when the leaf to split dangles from an intermediate node, not off of the root
    // (since we have a different backptr copy routine there)
    #[test]
    fn marf_split_leaf_path() {
        let path = "/tmp/rust_marf_insert_4096_128_seq_high".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();

        let path = [0u8; 32];
        let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
        let value = TrieLeaf::new(&vec![], &[0u8; 40].to_vec());

        test_debug!("----------------");
        test_debug!("insert ({:?}, {:?}) in {:?}", &triepath, &value, &block_header);
        test_debug!("----------------");

        MARF::insert_leaf(&mut f, &block_header, &triepath, &value).unwrap();

        // insert a leaf along the same path but in a different block
        let block_header_2 = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap();
        let path_2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
        let triepath_2 = TriePath::from_bytes(&path_2[..]).unwrap(); 
        let value_2 = TrieLeaf::new(&vec![], &[1u8; 40].to_vec());
    
        test_debug!("----------------");
        test_debug!("insert ({:?}, {:?}) in {:?}", &triepath_2, &value_2, &block_header_2);
        test_debug!("----------------");

        MARF::insert_leaf(&mut f, &block_header_2, &triepath_2, &value_2).unwrap();

        test_debug!("----------------");
        test_debug!("get ({:?}, {:?}) in {:?}", &triepath, &value, &block_header_2);
        test_debug!("----------------");

        let read_value = MARF::get_path(&mut f, &block_header_2, &triepath).unwrap().unwrap();
        assert_eq!(read_value.data.to_vec(), value.data.to_vec());
        
        test_debug!("----------------");
        test_debug!("get ({:?}, {:?}) in {:?}", &triepath_2, &value_2, &block_header_2);
        test_debug!("----------------");

        let read_value_2 = MARF::get_path(&mut f, &block_header_2, &triepath_2).unwrap().unwrap();
        assert_eq!(read_value_2.data.to_vec(), value_2.data.to_vec());
    }

    
    // insert a random sequence of 65536 keys.  Every 2048 inserts, fork.
    #[test]
    fn marf_insert_random_65536_2048() {
        let path = "/tmp/rust_marf_insert_random_65536_2048".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut block_header = BlockHeaderHash([0u8; 32]);
        MARF::format(&mut f, &block_header).unwrap();
        
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut start_time = get_epoch_time_ms();
        for i in 0..65536 {
            let i0 = i / 256;
            let i1 = i % 256;
            
            let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
            seed = path.clone();

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if (i + 1) % 2048 == 0 {
                // next block
                test_debug!("next block!");
                block_header = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,((i+1)/2048) as u8,((i+1)%2048) as u8]).unwrap();
            }

            MARF::insert_leaf(&mut f, &block_header, &triepath, &value).unwrap();

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(f.get_cur_block(), block_header);

            if i % 128 == 0 {
                let end_time = get_epoch_time_ms();
                let (read_count, write_count) = f.stats();
                let (node_reads, backptr_reads, node_writes) = f.node_stats();
                let (leaf_reads, leaf_writes) = f.leaf_stats();
                test_debug!("inserted {} in {} (1 insert = {} ms).  Read = {}, Write = {}, Node Reads = {}, Node Writes = {}, Backptr Reads = {}, Leaf Reads = {}, Leaf Writes = {}",
                         i, end_time - start_time, ((end_time - start_time) as f64) / 128.0, read_count, write_count, node_reads, node_writes, backptr_reads, leaf_reads, leaf_writes);

                start_time = get_epoch_time_ms();
            }
        }
        
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();

        start_time = get_epoch_time_ms();
        for i in 0..65536 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            
            let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
            seed = path.clone();

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            if i % 128 == 0 {
                let end_time = get_epoch_time_ms();
                let (read_count, write_count) = f.stats();
                let (node_reads, backptr_reads, node_writes) = f.node_stats();
                let (leaf_reads, leaf_writes) = f.leaf_stats();
                test_debug!("Got {} in {} (1 get = {} ms).  Read = {}, Write = {}, Node Reads = {}, Node Writes = {}, Backptr Reads = {}, Leaf Reads = {}, Leaf Writes = {}",
                         i, end_time - start_time, ((end_time - start_time) as f64) / 128.0, read_count, write_count, node_reads, node_writes, backptr_reads, leaf_reads, leaf_writes);
                
                start_time = get_epoch_time_ms();
            }
        }
    }
    
    // insert a random sequence of 1024 * 1024 * 10 keys.  Every 4096 inserts, fork.
    // Use file storage, and use batching.
    // Used mainly for performance analysis.
    #[test]
    fn marf_insert_random_10485760_4096_file_storage() {
        // this takes too long to run, so disable it by default
        if std::env::var("BLOCKSTACK_BIG_TEST") != Ok("1".to_string()) {
            test_debug!("Skipping this test because it will take too long.  Run with BLOCKSTACK_BIG_TEST=1 to activate.");
            return;
        }

        let path = "/tmp/rust_marf_insert_random_10485760_4096_file_storage".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let f = TrieFileStorage::new(&path).unwrap();
        let mut m = MARF::from_storage(f);

        let mut block_header = TrieFileStorage::block_sentinel();
        
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut start_time = get_epoch_time_ms();
        let mut end_time = 0;
        let mut block_start_time = start_time;
        let mut prev_block_header = block_header.clone();
       
        let mut i : u64 = 1;
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
            block_header = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8, i3 as u8]).unwrap();

            for _ in 0..block_size {
                let i0 = (i & 0xff000000) >> 24;
                let i1 = (i & 0x00ff0000) >> 16;
                let i2 = (i & 0x0000ff00) >> 8;
                let i3 = i & 0x000000ff;
               
                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let value = to_hex(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8, i3 as u8].to_vec());

                keys.push(key);
                values.push(value);
                i += 1;
            }

            block_start_time = get_epoch_time_ms();
            m.begin(&prev_block_header, &block_header).unwrap();

            start_time = get_epoch_time_ms();

            let values = values.drain(..).map(|x| MARFValue::from_value(&x)).collect();

            m.insert_batch(&keys, values).unwrap();
            end_time = get_epoch_time_ms();

            let flush_start_time = get_epoch_time_ms();
            m.commit().unwrap();
            let flush_end_time = get_epoch_time_ms();

            test_debug!("Inserted {} in {} (1 insert = {} ms).  Processed {} keys in {} ms (flush = {} ms)",
                        i, end_time - start_time, ((end_time - start_time) as f64) / (block_size as f64), block_size, flush_end_time - block_start_time, flush_end_time - flush_start_time);
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
                let value = to_hex(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8, i3 as u8].to_vec());

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
            
            test_debug!("Got {} in {} (1 get = {} ms)", i, end_time - start_time, ((end_time - start_time) as f64) / (block_size as f64));
        }
    }

    // insert a random sequence of 4096 keys.  Every 128 inserts, fork.
    // Use file storage, and use batching.
    // Do merkle tests each key/value inserted -- both immediately after the batch containing them
    // is inserted, and once all inserts complete.
    #[test]
    fn marf_insert_random_4096_128_file_storage_merkle_proof() {
        let path = "/tmp/rust_marf_insert_random_4096_128_file_storage".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let f = TrieFileStorage::new(&path).unwrap();
        let mut m = MARF::from_storage(f);

        let mut block_header = TrieFileStorage::block_sentinel();
        
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
            block_header = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8]).unwrap();

            for _ in 0..128 {
                let i0 = (i & 0xff0000) >> 12;
                let i1 = (i & 0x00ff00) >> 8;
                let i2 = i & 0x0000ff;
               
                let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
                seed = path.clone();

                let key = to_hex(&path);
                let raw_value = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8].to_vec();
                let value = to_hex(&raw_value);

                test_debug!("Insert ({:?}, {:?})", &key, &value);

                keys.push(key);
                values.push(value);
                i += 1;
            }

            m.begin(&prev_block_header, &block_header).unwrap();

            let marf_values = values.iter().map(|x| MARFValue::from_value(&x)).collect();

            m.insert_batch(&keys, marf_values).unwrap();
            m.commit().unwrap();

            for j in 0..128 {
                test_debug!("Prove {:?} == {:?}", &keys[j], &values[j]);
                merkle_test_marf_key_value(m.borrow_storage_backend(), &block_header, &keys[j], &values[j]);
            }
        }

        i = 1;
        seed = TrieHash::from_data(&[]).as_bytes().to_vec();

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
                let raw_value = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8].to_vec();
                let value = to_hex(&raw_value);

                keys.push(key);
                values.push(value);

                i += 1;
            }

            for j in 0..128 {
                test_debug!("Get {:?}, should be {:?}", &keys[j], &values[j]);

                let read_value = m.get(&block_header, &keys[j]).unwrap().unwrap();
                assert_eq!(read_value, MARFValue::from_value(&values[j]));
                
                test_debug!("Get {:?}, should be {:?}", &keys[j], &values[j]);
                merkle_test_marf_key_value(m.borrow_storage_backend(), &block_header, &keys[j], &values[j]);
            }
        }
    }
    
    // Test reads specifically on existing test data.
    // Not usually meant to be run, so #[test] is commented out below.
    #[test]
    fn marf_read_random_1048576_4096_file_storage() {
        // this takes too long to run, so disable it by default
        if std::env::var("BLOCKSTACK_BIG_TEST") != Ok("1".to_string()) {
            test_debug!("Skipping this test because it will take too long.  Run with BLOCKSTACK_BIG_TEST=1 to activate.");
            return;
        }

        let path = "/tmp/rust_marf_insert_random_1048576_4096_file_storage".to_string();
        match fs::metadata(&path) {
            Err(_) => {
                eprintln!("Run the marf_insert_random_1048576_4096_file_storage test first");
                return;
            },
            Ok(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xf0,0xff,0xff]).unwrap();
        f.open_block(&block_header, false).unwrap();

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
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            // merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
            if i % 128 == 0 {
                let end_time = get_epoch_time_ms();
                let (read_count, write_count) = f.stats();
                let (node_reads, backptr_reads, node_writes) = f.node_stats();
                let (leaf_reads, leaf_writes) = f.leaf_stats();
                test_debug!("Got {} in {} (1 get = {} ms).  Read = {}, Write = {}, Node Reads = {}, Node Writes = {}, Backptr Reads = {}, Leaf Reads = {}, Leaf Writes = {}",
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
        let path = "/tmp/rust_marf_insert_128_32_file_storage".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };

        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();

        for i in 0..128 {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if (i + 1) % 32 == 0 {
                // next block
                block_header = BlockHeaderHash::from_bytes(&[((i + 1) / 32) as u8; 32]).unwrap();
                test_debug!("block header is now {:?}", &block_header);
                f.flush().unwrap();
            }

            test_debug!("insert {}", i);
            MARF::insert_leaf(&mut f, &block_header, &triepath, &value).unwrap();
             
            test_debug!("get {}", i);
            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(f.get_cur_block(), block_header);
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }
        
        f.flush().unwrap();

        f.open_block(&block_header, false).unwrap();
        dump_trie(&mut f);

        test_debug!("------------");
        test_debug!("get all and get merkle proofs");
        test_debug!("------------");

        for i in 0..128 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }

        for i in 0..(128/32) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            f.open_block(&block_header, false).unwrap();
            dump_trie(&mut f);
        }
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 128 keys, make a new trie.
    // Use the TrieFileStorage backend
    #[test]
    fn marf_insert_4096_128_file_storage() {
        let path = "/tmp/rust_marf_insert_4096_128_file_storage".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };

        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();

        for i in 0..4096 {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if (i + 1) % 128 == 0 {
                // next block
                block_header = BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap();
                test_debug!("block header is now {:?}", &block_header);
                f.flush().unwrap();
            }

            test_debug!("insert {}", i);
            MARF::insert_leaf(&mut f, &block_header, &triepath, &value).unwrap();
             
            test_debug!("get {}", i);
            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(f.get_cur_block(), block_header);
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }
        
        f.flush().unwrap();

        test_debug!("------------");
        test_debug!("get all and get merkle proofs");
        test_debug!("------------");

        for i in 0..4096 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }

        for i in 0..(4096/128) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            f.open_block(&block_header, false).unwrap();
            dump_trie(&mut f);
        }
    }

    // insert a range of 256 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 16 keys, make a new trie.
    // Use the TrieFileStorage backend
    #[test]
    fn marf_insert_256_16_file_storage() {
        let path = "/tmp/rust_marf_insert_256_16_file_storage".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };

        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();

        for i in 0..256 {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if (i + 1) % 16 == 0 {
                // next block
                block_header = BlockHeaderHash::from_bytes(&[((i + 1) / 16) as u8; 32]).unwrap();
                test_debug!("block header is now {:?}", &block_header);
                f.flush().unwrap();
            }

            test_debug!("insert {}", i);
            MARF::insert_leaf(&mut f, &block_header, &triepath, &value).unwrap();
             
            test_debug!("get {}", i);
            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(f.get_cur_block(), block_header);
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }
        
        f.flush().unwrap();

        test_debug!("------------");
        test_debug!("get all and get merkle proofs");
        test_debug!("------------");

        for i in 0..256 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec());
        }

        for i in 0..(256/16) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            f.open_block(&block_header, false).unwrap();
            dump_trie(&mut f);
        }
    }

    #[test]
    fn marf_insert_get_128_fork_256() {
        // create 256 forks organized as a binary tree, and insert 128 values into each one.
        // make sure we can read them all from each chain tip, and make sure we can generate merkle
        // proofs of each one's value.
        let path = "/tmp/rust_marf_insert_get_128_fork_256".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };

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
       
        m.begin(&TrieFileStorage::block_sentinel(), &BlockHeaderHash([0u8; 32])).unwrap();
        m.commit().unwrap();

        for i in 1..8 {
            let parent_row = &fork_headers[i-1];
            for j in 0..parent_row.len() {
                let parent_hash = &parent_row[j];
                for k in (2*j)..(2*j+2) {
                    let child_hash = &fork_headers[i][k];

                    test_debug!("Branch from {:?} to {:?}", parent_hash, child_hash);
                    m.begin(parent_hash, child_hash).unwrap();

                    let mut keys = vec![];
                    let mut values = vec![];

                    for l in 0..128 {
                        let raw_value = [i as u8, j as u8, k as u8, l as u8, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].to_vec();
                        let value = to_hex(&raw_value);
                        let key = format!("{}-{}-{}-{}", i, j, k, l);

                        keys.push(key);
                        values.push(value);
                    }

                    let values = values.drain(..).map(|x| MARFValue::from_value(&x)).collect();

                    m.insert_batch(&keys, values).unwrap();
                    m.commit().unwrap();
                }
            }
        }

        let mut chain_tips = m.chain_tips();
        chain_tips.sort();

        let mut expected_chain_tips = fork_headers[fork_headers.len() - 1].clone();
        expected_chain_tips.sort();

        assert_eq!(chain_tips, expected_chain_tips);

        for k in 0..chain_tips.len() {
            for l in 0..128 {
                let raw_value = [7u8, (k/2) as u8, k as u8, l as u8, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].to_vec();
                let expected_value = to_hex(&raw_value);
                let key = format!("{}-{}-{}-{}", 7, (k/2), k, l);

                let marf_value = m.get(&chain_tips[k], &key).unwrap().unwrap();
                assert_eq!(marf_value, MARFValue::from_value(&expected_value));
                
                merkle_test_marf_key_value(m.borrow_storage_backend(), &chain_tips[k], &key, &expected_value);
            }
        }
    }
}

