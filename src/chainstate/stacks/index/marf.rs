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

use std::path::{
    PathBuf
};

use std::marker::PhantomData;
use std::fs;

use sha2::Digest;

use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::index::bits::{
    get_leaf_hash,
    get_node_hash,
    read_root_hash,
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
    proofs::TrieMerkleProof,
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
    MARFValue
};

use chainstate::stacks::index::trie::{
    Trie,
};

use chainstate::stacks::index::Error as Error;

use util::log;

pub const BLOCK_HASH_TO_HEIGHT_MAPPING_KEY: &str = "__MARF_BLOCK_HASH_TO_HEIGHT";
pub const BLOCK_HEIGHT_TO_HASH_MAPPING_KEY: &str = "__MARF_BLOCK_HEIGHT_TO_HASH";
pub const OWN_BLOCK_HEIGHT_KEY: &str = "__MARF_BLOCK_HEIGHT_SELF";

/// Merklized Adaptive-Radix Forest -- a collection of Merklized Adaptive-Radix Tries.
pub struct MARF {
    storage: TrieFileStorage,
    open_chain_tip: Option<WriteChainTip>,
    readonly: bool
}

#[derive(Clone)]
struct WriteChainTip {
    block_hash: BlockHeaderHash,
    height: u32
}

impl MARF {

    #[cfg(test)]
    pub fn from_storage_opened(storage: TrieFileStorage, opened_to: &BlockHeaderHash) -> MARF {
        MARF {
            storage,
            open_chain_tip: Some(WriteChainTip { block_hash: opened_to.clone(),
                                                 height: 0 }),
            readonly: false,
        }
    }

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
                MARF::node_copy_update_ptrs(node.ptrs_mut(), child_block_id);
                TrieHash::from_data(&[])
            }
        };
        
        Ok(hash)
    }
    
    /// Given a node, and the chr of one of its children, go find the last instance of that child in
    /// the MARF and copy it forward.  Update its ptrs to point to its descendents.
    /// s must point to the block hash in which this node lives, to which the child will be copied.
    fn node_child_copy(storage: &mut TrieFileStorage, node: &TrieNodeType, chr: u8, cursor: &mut TrieCursor) -> Result<(TrieNodeType, TrieHash, TriePtr, BlockHeaderHash), Error> {
        trace!("Copy to {:?} child {:x} of {:?}", storage.get_cur_block(), chr, node);

        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        let (mut child_node, _, child_ptr, _) = MARF::walk_backptr(storage, node, chr, cursor)?;
        let child_block_hash = storage.get_cur_block();
        let child_block_identifier = storage.get_cur_block_identifier()?;

        // update child_node with new ptrs and hashes
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_hash = MARF::node_copy_update(&mut child_node, child_block_identifier)
            .map_err(|e| Error::BlockHashMapCorruptionError(Some(Box::new(e))))?;

        // store it in this trie
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_disk_ptr = storage.last_ptr()?;
        let child_ptr = TriePtr::new(child_ptr.id(), chr, child_disk_ptr);
        storage.write_nodetype(child_disk_ptr, &child_node, child_hash.clone())?;

        trace!("Copied child 0x{:02x} to {:?}: ptr={:?} child={:?}", chr, &cur_block_hash, &child_ptr, &child_node);
        Ok((child_node, child_hash, child_ptr, child_block_hash))
    }

    /// Copy the root node from the previous Trie to this Trie, updating its ptrs.
    /// s must point to the target Trie
    fn root_copy(storage: &mut TrieFileStorage, prev_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        storage.open_block(prev_block_hash)?;
        let prev_block_identifier = storage.get_cur_block_identifier()
            .expect(&format!("called open_block on {}, but found no identifier", prev_block_hash));
        
        let (mut prev_root, _) = Trie::read_root(storage)?;
        let new_root_hash = MARF::node_copy_update(&mut prev_root, prev_block_identifier)?;
        
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        
        let root_ptr = storage.root_ptr();
        storage.write_nodetype(root_ptr, &prev_root, new_root_hash)?;
        Ok(())
    }
    
    /// create or open a particular Trie.
    /// If the trie doesn't exist, then extend it from the current Trie and create a root node that
    /// has back pointers to its immediate children in the current trie.
    /// On Ok, s will point to new_bhh and will be open for reading
    pub fn extend_trie(storage: &mut TrieFileStorage, new_bhh: &BlockHeaderHash) -> Result<(), Error> {
        if storage.readonly {
            return Err(Error::ReadOnlyError);
        }

        let (cur_bhh, cur_block_id) = storage.get_cur_block_and_id();
        if storage.num_blocks() == 0 || cur_bhh == TrieFileStorage::block_sentinel() {
            // brand new storage
            trace!("Brand new storage -- start with {:?}", new_bhh);
            storage.extend_to_block(new_bhh)?;
            let node = TrieNode256::new(&vec![]);
            let hash = get_node_hash(&node, &vec![], storage);
            let root_ptr = storage.root_ptr();
            storage.write_nodetype(root_ptr, &TrieNodeType::Node256(node), hash)
        }
        else {
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
        let block_id = storage.get_block_identifier(block_hash);
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
                            if !node.is_leaf() || clear_backptr(node_ptr.id()) != TrieNodeID::Leaf as u8 {
                                error!("Out-of-path but encountered a non-leaf");
                                return Err(Error::CorruptionError("Non-leaf encountered at end of path".to_string()));
                            }

                            trace!("Out of path in {:?} -- we're done. Node at {:?}", storage.get_cur_block(), &node_ptr);
                            storage.open_block_maybe_id(block_hash, block_id)?;
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
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    return Ok(cursor);
                                },
                                CursorError::ChrNotFound => {
                                    // end-of-node-path but no such child -- not even a backptr.
                                    trace!("ChrNotFound encountered at {:?} -- we're done (node not found)", storage.get_cur_block());
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    return Ok(cursor);
                                },
                                CursorError::BackptrEncountered(ptr) => {
                                    // at intermediate node whose child is not present in this trie.
                                    // bring the child forward and take the step, if possible.
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    let (next_node, _, next_node_ptr, next_node_block_hash) = MARF::node_child_copy(storage, &node, ptr.chr(), &mut cursor)?;

                                    // finish taking the step
                                    cursor.repair_backptr_finish(&next_node_ptr, next_node_block_hash);
                                    
                                    // keep walking
                                    node = next_node;
                                    node_ptr = next_node_ptr;
                                    
                                    storage.open_block_maybe_id(block_hash, block_id)?;
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
        storage.open_block(block_hash)?;

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        // walk to insertion point 
        let (mut node, _) = Trie::read_root(storage)?;

        for _ in 0..(cursor.path.len()+1) {
            match Trie::walk_from(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((_, next_node, _)) => {
                            // end-of-node-path, and found a child.
                            // keep walking
                            node = next_node;
                            continue;
                        },
                        None => {
                            // end of path.  Must be at a leaf.
                            if clear_backptr(cursor.ptr().id()) != TrieNodeID::Leaf as u8 {
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
                                    cursor.repair_backptr_finish(&next_node_ptr, storage.get_cur_block());

                                    // keep going
                                    node = next_node;
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
        if storage.readonly {
            return Err(Error::ReadOnlyError);
        }

        storage.format()?;
        storage.extend_to_block(first_block_hash)?;
        let node = TrieNode256::new(&vec![]);
        let hash = get_node_hash(&node, &vec![], storage);
        let root_ptr = storage.root_ptr();
        let node_type = TrieNodeType::Node256(node);
        storage.write_nodetype(root_ptr, &node_type, hash)
    }

    pub fn get_path(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath) -> Result<Option<TrieLeaf>, Error> {
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

        test_debug!("MARF Insert in {}: '{}' = '{}' (...{:?})", block_hash, path, leaf_value.data, &leaf_value.path);
        
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
        if storage.readonly {
            return Err(Error::ReadOnlyError);
        }
        MARF::do_insert_leaf(storage, block_hash, path, value, true)
    }
    
    // like insert_leaf, but don't update the merkle skiplist
    pub fn insert_leaf_in_batch(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, path: &TriePath, value: &TrieLeaf) -> Result<(), Error> {
        if storage.readonly {
            return Err(Error::ReadOnlyError);
        }
        MARF::do_insert_leaf(storage, block_hash, path, value, false)
    }

    /// Instantiate the MARF from a TrieFileStorage instance 
    pub fn from_storage(storage: TrieFileStorage) -> MARF {
        MARF {
            storage: storage,
            open_chain_tip: None,
            readonly: false,
        }
    }

    /// Instantiate the MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path(path: &str, miner_tip: Option<&BlockHeaderHash>) -> Result<MARF, Error> {
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

        if let Some(ref miner_tip) = miner_tip {
            file_storage.set_miner_tip(*miner_tip.clone());
        }

        Ok(MARF::from_storage(file_storage))
    }

    /// Resolve a key from the MARF to a MARFValue with respect to the given block height.
    pub fn get(&mut self, block_hash: &BlockHeaderHash, key: &str) -> Result<Option<MARFValue>, Error> {
        MARF::get_by_key(&mut self.storage, block_hash, key)
    }

    pub fn get_with_proof(&mut self, block_hash: &BlockHeaderHash, key: &str) -> Result<Option<(MARFValue, TrieMerkleProof)>, Error> {
        let marf_value = match MARF::get_by_key(&mut self.storage, block_hash, key)? {
            None => return Ok(None),
            Some(x) => x
        };
        let proof = TrieMerkleProof::from_raw_entry(&mut self.storage, key, &marf_value, block_hash)?;
        Ok(Some((marf_value, proof)))
    }

    pub fn get_bhh_at_height(&mut self, block_hash: &BlockHeaderHash, height: u32) -> Result<Option<BlockHeaderHash>, Error> {
        MARF::get_block_at_height(&mut self.storage, height, block_hash)
    }

    pub fn get_by_key(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, key: &str) -> Result<Option<MARFValue>, Error> {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();

        let path = TriePath::from_key(key);

        let result = MARF::get_path(storage, block_hash, &path)
            .or_else(|e| match e {
                Error::NotFoundError => Ok(None),
                _ => Err(e)
            });

        // restore
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        result.map(|option_result| option_result.map(|leaf| {
            leaf.data
        }))
    }

    pub fn get_block_height_miner_tip(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, current_block_hash: &BlockHeaderHash) -> Result<Option<u32>, Error> {
        let hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash);
        #[cfg(test)] {
            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            if storage.test_genesis_block.as_ref() == Some(current_block_hash) {
                return Ok(Some(0))
            }
        }

        let marf_value =
            if block_hash == current_block_hash {
                MARF::get_by_key(storage, current_block_hash, OWN_BLOCK_HEIGHT_KEY)?
            } else {
                MARF::get_by_key(storage, current_block_hash, &hash_key)?
            };

        Ok(marf_value.map(u32::from))
    }
    
    pub fn get_block_height(storage: &mut TrieFileStorage, block_hash: &BlockHeaderHash, current_block_hash: &BlockHeaderHash) -> Result<Option<u32>, Error> {
        MARF::get_block_height_miner_tip(storage, block_hash, current_block_hash)
    }

    pub fn get_block_at_height(storage: &mut TrieFileStorage, height: u32, current_block_hash: &BlockHeaderHash) -> Result<Option<BlockHeaderHash>, Error> {
        #[cfg(test)] {
            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            if height == 0 {
                match storage.test_genesis_block {
                    Some(ref s) => return Ok(Some(s.clone())),
                    _ => {}
                }
            }
        }

        let current_block_height = match MARF::get_block_height(storage, current_block_hash, current_block_hash)? {
            Some(x) => x,
            None => return Ok(None)
        };

        if height == current_block_height {
            return Ok(Some(current_block_hash.clone()))
        }

        let height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height);

        MARF::get_by_key(storage, current_block_hash, &height_key)
            .map(|option_result| {
                option_result.map(|marf_value| { 
                    let block_hash = BlockHeaderHash::from(marf_value);
                    block_hash
                })
            })
    }

    pub fn set_block_heights(&mut self, block_hash: &BlockHeaderHash, next_block_hash: &BlockHeaderHash, height: u32) -> Result<(), Error> {
        if self.readonly {
            return Err(Error::ReadOnlyError);
        }
        let mut keys = vec![];
        let mut values = vec![];

        let height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height);
        let hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash);

        test_debug!("Set {}::{} = {}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height, next_block_hash);
        test_debug!("Set {}::{} = {}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash, height);
        test_debug!("Set {} = {}", OWN_BLOCK_HEIGHT_KEY, height);

        keys.push(OWN_BLOCK_HEIGHT_KEY.to_string());
        values.push(MARFValue::from(height));

        keys.push(height_key);
        values.push(MARFValue::from(next_block_hash.clone()));

        keys.push(hash_key);
        values.push(MARFValue::from(height));

        if height > 0 {
            let prev_height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height - 1);
            let prev_hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash);

            test_debug!("Set {}::{} = {}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height - 1, block_hash);
            test_debug!("Set {}::{} = {}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash, height - 1);

            keys.push(prev_height_key);
            values.push(MARFValue::from(block_hash.clone()));

            keys.push(prev_hash_key);
            values.push(MARFValue::from(height - 1));
        }

        self.insert_batch(&keys, values)?;
        Ok(())
    }

    pub fn insert(&mut self, key: &str, value: MARFValue) -> Result<(), Error> {
        if self.readonly {
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
        if self.readonly {
            return Err(Error::ReadOnlyError);
        }
        match self.open_chain_tip {
            None => {
                Err(Error::WriteNotBegunError)
            },
            Some(WriteChainTip{ ref block_hash, .. }) => {
                let (cur_block_hash, cur_block_id) = self.storage.get_cur_block_and_id();

                let result = MARF::insert_leaf(&mut self.storage, block_hash, &path, &marf_leaf);
                
                // restore
                self.storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
                
                result
            }
        }
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    pub fn insert_batch(&mut self, keys: &Vec<String>, values: Vec<MARFValue>) -> Result<(), Error> {
        if self.readonly {
            return Err(Error::ReadOnlyError);
        }
        assert_eq!(keys.len(), values.len());

        let block_hash = match self.open_chain_tip {
            None => {
                Err(Error::WriteNotBegunError)
            },
            Some(WriteChainTip{ ref block_hash, .. }) => {
                Ok(block_hash.clone())
            }
        }?;

        if keys.len() == 0 {
            return Ok(());
        }
        
        let (cur_block_hash, cur_block_id) = self.storage.get_cur_block_and_id();
                
        let last = keys.len() - 1;
        
        let mut result = keys[0..last].iter().zip(values[0..last].iter())
            .try_for_each(|(key, value)| {
                let marf_leaf = TrieLeaf::from_value(&vec![], value.clone());
                let path = TriePath::from_key(key);
                        
                MARF::insert_leaf_in_batch(&mut self.storage, &block_hash, &path, &marf_leaf)
            });

        if result.is_ok() {
            // last insert updates the root with the skiplist hash
            let marf_leaf = TrieLeaf::from_value(&vec![], values[last].clone());
            let path = TriePath::from_key(&keys[last]);
            result = MARF::insert_leaf(&mut self.storage, &block_hash, &path, &marf_leaf);
        }

        // restore
        self.storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        result
    }

    /// Begin writing the next trie in the MARF, given the block header hash that will contain the
    /// associated block's new state.  Call commit() or commit_to() to persist the changes.
    /// Fails if the block already exists.
    /// Storage will point to new chain tip on success.
    pub fn begin(&mut self, chain_tip: &BlockHeaderHash, next_chain_tip: &BlockHeaderHash) -> Result<(), Error> {
        if self.readonly {
            return Err(Error::ReadOnlyError);
        }
        if self.open_chain_tip.is_some() {
            return Err(Error::InProgressError);
        }

        // new chain tip must not exist
        if self.storage.open_block(next_chain_tip).is_ok() {
            error!("Block data already exists: {}", next_chain_tip);
            return Err(Error::ExistsError);
        }

        // current chain tip must exist if it's not the "sentinel"
        let is_parent_sentinel = chain_tip == &TrieFileStorage::block_sentinel();
        if !is_parent_sentinel {
            debug!("Extending off of existing node {} in {}", chain_tip, self.storage.dir_path);
        }
        else {
            info!("First-ever block {} in {}", next_chain_tip, self.storage.dir_path);
        }
        self.storage.open_block(chain_tip)?;

        let block_height = 
            if !is_parent_sentinel {
                let height = MARF::get_block_height_miner_tip(&mut self.storage, chain_tip, chain_tip)?
                    .ok_or(Error::CorruptionError(format!("Failed to find block height for `{:?}`", chain_tip)))?;
                height.checked_add(1).expect("FATAL: block height overflow!")
            } else {
                0
            };

        MARF::extend_trie(&mut self.storage, next_chain_tip)?;
        self.open_chain_tip = Some(WriteChainTip{ block_hash: next_chain_tip.clone(),
                                                  height: block_height });

        self.set_block_heights(chain_tip, next_chain_tip, block_height)
            .map_err(|e| {
                self.open_chain_tip = None;
                e
            })?;

        test_debug!("Opened {} in {}", chain_tip, self.storage.dir_path);
        Ok(())
    }
    
    /// Drop the current trie from the MARF. This rolls back all
    ///   changes in the block, and closes the current chain tip.
    pub fn drop_current(&mut self) {
        if !self.readonly {
            self.storage.drop_extending_trie();
            self.open_chain_tip = None;
        }
    }

    /// Finish writing the next trie in the MARF.  This persists all changes.
    pub fn commit(&mut self) -> Result<(), Error> {
        if self.readonly {
            return Err(Error::ReadOnlyError);
        }
        match self.open_chain_tip.take() {
            Some(_tip) => {
                self.storage.flush()?;
            },
            None => {}
        };
        Ok(())
    }

    /// Finish writing the next trie in the MARF -- this is used by miners
    ///   to commit the mined block, but write it to the mined_block table,
    ///   rather than out to the marf_data table (this prevents the
    ///   miner's block from getting stepped on after the sortition).
    pub fn commit_mined(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        if self.readonly {
            return Err(Error::ReadOnlyError);
        }
        match self.open_chain_tip.take() {
            Some(_tip) => {
                self.storage.flush_mined(bhh)?;
            },
            None => {}
        };
        Ok(())
    }
    
    /// Finish writing the next trie in the MARF, but change the hash of the current Trie's 
    /// block hash to something other than what we opened it as.  This persists all changes.
    pub fn commit_to(&mut self, real_bhh: &BlockHeaderHash) -> Result<(), Error> {
        if self.readonly {
            return Err(Error::ReadOnlyError);
        }
        match self.open_chain_tip.take() {
            Some(_tip) => {
                self.storage.flush_to(real_bhh)?;
            },
            None => {}
        };
        Ok(())
    }

    pub fn get_block_height_of(&mut self, bhh: &BlockHeaderHash, current_block_hash: &BlockHeaderHash) -> Result<Option<u32>, Error> {
        if Some(bhh) == self.get_open_chain_tip() {
            return Ok(self.get_open_chain_tip_height())
        } else {
            MARF::get_block_height_miner_tip(&mut self.storage, bhh, current_block_hash)
        }
    }

    /// Get open chain tip
    pub fn get_open_chain_tip(&self) -> Option<&BlockHeaderHash> {
        self.open_chain_tip.as_ref()
            .map(|x| &x.block_hash)
    }

    /// Get open chain tip
    pub fn get_open_chain_tip_height(&self) -> Option<u32> {
        self.open_chain_tip.as_ref()
            .map(|x| x.height)
    }

    /// Check if a block can open successfully, i.e.,
    ///   it's a known block, the storage system isn't issueing IOErrors, _and_ it's in the same fork
    ///   as the current block
    /// The MARF _must_ be open to a valid block for this check to be evaluated.
    pub fn check_ancestor_block_hash(&mut self, bhh: &BlockHeaderHash) -> Result<(), Error> {
        let cur_block_hash = self.storage.get_cur_block();
        if cur_block_hash == *bhh {
            // a block is in its own fork
            return Ok(());
        }

        let bhh_height = MARF::get_block_height(&mut self.storage, bhh, &cur_block_hash)?
            .ok_or_else(|| Error::NonMatchingForks(bhh.clone(), cur_block_hash.clone()))?;

        let actual_block_at_height = MARF::get_block_at_height(&mut self.storage, bhh_height, &cur_block_hash)?
            .ok_or_else(|| Error::CorruptionError(format!(
                "ERROR: Could not find block for height {}, but it was returned by MARF::get_block_height()", bhh_height)))?;

        if *bhh != actual_block_at_height {
            return Err(Error::NonMatchingForks(bhh.clone(), cur_block_hash.clone()))
        }

        // test open
        let result = self.storage.open_block(bhh);

        // restore
        self.storage.open_block(&cur_block_hash)
            .map_err(|e| Error::RestoreMarfBlockError(Box::new(e)))?;

        result
    }

    /// Access internal storage
    pub fn borrow_storage_backend(&mut self) -> &mut TrieFileStorage {
        &mut self.storage
    }

    /// Reopen storage read-only
    pub fn reopen_storage_readonly(&self) -> Result<TrieFileStorage, Error> {
        self.storage.reopen_readonly()
    }

    /// Reopen this MARF with readonly storage.
    pub fn reopen_readonly(&self) -> Result<MARF, Error> {
        if self.open_chain_tip.is_some() {
            error!("MARF at {} is already in the process of writing", &self.storage.dir_path);
            return Err(Error::InProgressError);
        }

        let ro_storage = self.storage.reopen_readonly()?;
        Ok(MARF {
            storage: ro_storage,
            open_chain_tip: None,
            readonly: true,
        })
    }

    /// Get the current root trie hash
    pub fn get_root_hash(&mut self) -> Result<TrieHash, Error> {
        read_root_hash(&mut self.storage)
    }
    
    /// Get the root trie hash at a particular block
    pub fn get_root_hash_at(&mut self, block_hash: &BlockHeaderHash) -> Result<TrieHash, Error> {
        let cur_block_hash = self.storage.get_cur_block();

        self.storage.open_block(block_hash)?;
        let root_hash_res = read_root_hash(&mut self.storage);

        // restore
        self.storage.open_block(&cur_block_hash)?;
        root_hash_res
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
    use chainstate::stacks::index::marf::*;
    use chainstate::stacks::index::node::*;
    use chainstate::stacks::index::proofs::*;
    use chainstate::stacks::index::storage::*;
    use chainstate::stacks::index::trie::*;

    use util::get_epoch_time_ms;
    use util::hash::to_hex;

    #[test]
    fn marf_insert_different_leaf_same_block_100() {
        let filename = "/tmp/rust_marf_insert_different_leaf_same_block_100";

        let f = TrieFileStorage::new_memory().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();

        let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let path = TriePath::from_bytes(&path_bytes).unwrap();

        for i in 0..100 {
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path.clone(), value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        let value = TrieLeaf::new(&vec![], &[99; 40].to_vec());
        let leaf = MARF::get_path(marf.borrow_storage_backend(), &block_header, &path).unwrap().unwrap();

        assert_eq!(leaf.data.to_vec(), [99; 40].to_vec());
        assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

        merkle_test_marf(marf.borrow_storage_backend(), &block_header, &path_bytes.to_vec(), &[99; 40].to_vec(), None);
    }
    
    #[test]
    fn marf_insert_different_leaf_different_path_different_block_100() {
        let filename = "/tmp/rust_marf_insert_different_leaf_different_path_different_block_100";

        let f = TrieFileStorage::new_memory().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();

        for i in 0..100 {
            test_debug!("insert {}", i);
            let block_header = BlockHeaderHash::from_bytes(&[i+1 as u8; 32]).unwrap();
            let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,i as u8];
            marf.commit().unwrap();
            marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..100 {
            let block_header = BlockHeaderHash::from_bytes(&[i+1 as u8; 32]).unwrap();
            let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,i as u8];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(marf.borrow_storage_backend(), &block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

            merkle_test_marf(marf.borrow_storage_backend(), &block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec(), None);
        }
    }

    #[test]
    fn marf_insert_same_leaf_different_block_100() {
        let path = "/tmp/rust_marf_same_leaf_different_block_100";

        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();


        let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let path = TriePath::from_bytes(&path_bytes).unwrap();

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i+1 as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.commit().unwrap();
            marf.begin(&TrieFileStorage::block_sentinel(), &next_block_header).unwrap();
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i+1 as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(marf.borrow_storage_backend(), &next_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), next_block_header);

            merkle_test_marf(marf.borrow_storage_backend(), &next_block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec(), None);
        }
    }

    
    #[test]
    fn marf_insert_leaf_sequence_2() {
        let path = "/tmp/rust_marf_insert_leaf_sequence_2";
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();

        for i in 0..2 {
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            let prior_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let next_block_header = BlockHeaderHash::from_bytes(&[i+1 as u8; 32]).unwrap();
            marf.commit().unwrap();
            marf.begin(&prior_block_header, &next_block_header).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }
        
        marf.commit().unwrap();
        let last_block_header = BlockHeaderHash::from_bytes(&[2; 32]).unwrap();

        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..2 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i+1 as u8; 32]).unwrap();
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get_path(marf.borrow_storage_backend(), &last_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), next_block_header);

            merkle_test_marf(marf.borrow_storage_backend(), &last_block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec(), None);
        }
    }
    
    #[test]
    fn marf_insert_leaf_sequence_100() {
        let path = "/tmp/rust_marf_insert_leaf_sequence_100";
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();

        let mut last_block_header = block_header.clone();

        for i in 1..101 {
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            marf.commit().unwrap();
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.begin(&last_block_header, &next_block_header).unwrap();
            last_block_header = next_block_header;

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            marf.insert_raw(path, value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        let f = marf.borrow_storage_backend();

        for i in 1..101 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let path_bytes = [i as u8,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
            let path = TriePath::from_bytes(&path_bytes).unwrap();
            
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            eprintln!("Finding value inserted at {}", &next_block_header);
            let leaf = MARF::get_path(f, &last_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.data.to_vec(), [i as u8; 40].to_vec());
            // NOTE: this assertion no longer holds, since the path prefix may now overlap 
            //         with data related to block_height!
            // assert_eq!(f.get_cur_block(), next_block_header);

            merkle_test_marf(f, &last_block_header, &path_bytes.to_vec(), &[i as u8; 40].to_vec(), None);
        }
    }

    #[test]
    #[ignore]
    fn marf_walk_cow_node4_20() {
        marf_walk_cow_test(|s| {
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
        }, |i, mut p| {
            p[i as usize] = 32;
            p
        });
    }

    #[test]
    #[ignore]
    fn marf_walk_cow_node4_20_reversed() {
        marf_walk_cow_test(|s| {
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
        }, |i, mut p| {
            p[31-i as usize] = 32;
            p
        });
    }

    fn marf_walk_cow_4_test <F> (filename: &str, path_gen: F)
    where F: Fn(u32, [u8; 32]) -> [u8; 32] {
        for node_id in [TrieNodeID::Node4, TrieNodeID::Node16, TrieNodeID::Node48, TrieNodeID::Node256].iter() {
            let path_segments = vec![
                (vec![], 4),
                (vec![0,1,2,3,5,6,7,8], 9),
                (vec![10,11,12,13], 14),
                (vec![15,16,17,18], 19),
                (vec![20,21,22,23], 24),
                (vec![25,26,27,28], 29),
                (vec![30], 31),
            ];

            marf_walk_cow_test(|s| {
                make_node_path(s, node_id.to_u8(), &path_segments, [31u8; 40].to_vec())
            }, |x,y| { path_gen(x, y) });
        }
    }

    fn marf_walk_cow_test <F, G> (path_init: G, path_gen: F)
    where F: Fn(u32, [u8; 32]) -> [u8; 32],
          G: FnOnce(&mut TrieFileStorage) -> (Vec<TrieNodeType>, Vec<TriePtr>, Vec<TrieHash>) {
        let mut f = TrieFileStorage::new_memory().unwrap();
        let mut last_block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &last_block_header).unwrap();
        f.test_genesis_block = Some(last_block_header.clone());

        let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];

        let (nodes, node_ptrs, hashes) = path_init(&mut f);

        let mut marf = MARF::from_storage(f);

        for i in 1..31 {
            test_debug!("----------------");
            test_debug!("i = {}", i);
            test_debug!("----------------");

            // switch to the next block
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.commit().unwrap();
            marf.begin(&last_block_header, &next_block_header).unwrap();
            last_block_header = next_block_header;
            // add a leaf at the end of the path
            
            let next_path = path_gen(i, path.clone());
            
            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            
            test_debug!("----------------");
            test_debug!("insert");
            test_debug!("----------------");
            marf.insert_raw(triepath.clone(), value.clone()).unwrap();
            
            // verify that this leaf exists in _this_ Trie
            test_debug!("----------------");
            test_debug!("get");
            test_debug!("----------------");
            let read_value = MARF::get_path(marf.borrow_storage_backend(), &next_block_header, 
                                            &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), [i as u8; 40].to_vec());
            // assertion is no longer necessarily true, because of block height data!
            //
            //   assert_eq!(read_value.path, next_path[i..].to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), next_block_header);
            
            // can get all previous leaves from _this_ Trie
            for j in 1..(i+1) {
                test_debug!("----------------");
                test_debug!("get-prev {} of {}", j, i);
                test_debug!("----------------");
                
                let prev_path = path_gen(j, path.clone());
                
                let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();
                
                let read_value = MARF::get_path(marf.borrow_storage_backend(), &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.data.to_vec(), [j as u8; 40].to_vec());
                
                // assertion no longer true, because inserting the block height information
                //   can cause a COW.
                // assert_eq!(f.get_cur_block(), prev_block_header);
                
                test_debug!("---------------------------------------");
                test_debug!("MARF verify {:?} {:?} from current block header {:?}", &prev_path, &[j as u8; 40].to_vec(), &next_block_header);
                test_debug!("----------------------------------------");
                merkle_test_marf(marf.borrow_storage_backend(), &next_block_header, &prev_path.to_vec(), &[j as u8; 40].to_vec(), None);
            }
            
            marf.borrow_storage_backend().open_block(&next_block_header).unwrap();
            
            merkle_test_marf(marf.borrow_storage_backend(), &next_block_header, &next_path.to_vec(), &[i as u8; 40].to_vec(), None);
        }
        
        // all leaves are reachable from the last block 
        for i in 1..31 {
            // add a leaf at the end of the path
            let next_path = path_gen(i, path.clone());
            
            let triepath = TriePath::from_bytes(&next_path[..]).unwrap();
            let value = MARFValue([i as u8; 40]);
            
            assert_eq!(MARF::get_path(marf.borrow_storage_backend(), &last_block_header, &triepath).unwrap().unwrap().data,
                       value);
            
            test_debug!("---------------------------------------");
            test_debug!("MARF verify {:?} {:?} from last block header {:?}", &next_path, &[i as u8; 40].to_vec(), &last_block_header);
            test_debug!("----------------------------------------");
                merkle_test_marf(marf.borrow_storage_backend(), &last_block_header, &next_path.to_vec(), &[i as u8; 40].to_vec(), None);
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
            p[31-i as usize] = 32;
            p
        })
    }
    
    #[test]
    fn marf_merkle_verify_backptrs() {
        for node_id in [TrieNodeID::Node4, TrieNodeID::Node16, TrieNodeID::Node48, TrieNodeID::Node256].iter() {
            let mut f = TrieFileStorage::new_memory().unwrap();

            let block_header_1 = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
            MARF::format(&mut f, &block_header_1).unwrap();
            f.test_genesis_block = Some(block_header_1.clone());

            let path_segments = vec![
                (vec![], 12),
                (vec![0,1,2,3,4,5,6,7,8,9,10,11,13,14,15,16,17,18,19,20,21,24], 25),
                (vec![26,27,28,29,30], 31)
            ];
            
            let path = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];

            let (nodes, node_ptrs, hashes) = make_node_path(&mut f, node_id.to_u8(), &path_segments, [31u8; 40].to_vec());
            let mut marf = MARF::from_storage(f);

            let block_header_2 = BlockHeaderHash::from_bytes(&[1u8; 32]).unwrap();
            let path_2 = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,32];
            
            test_debug!("----------------");
            test_debug!("Extend to {:?}", block_header_2);
            test_debug!("----------------");

            marf.commit().unwrap();
            marf.begin(&block_header_1, &block_header_2).unwrap();
            marf.insert_raw(TriePath::from_bytes(&path_2[..]).unwrap(), TrieLeaf::new(&vec![], &[20 as u8; 40].to_vec())).unwrap();

            let block_header_3 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
            let path_3 = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,33];
            
            test_debug!("----------------");
            test_debug!("Extend to {:?}", block_header_3);
            test_debug!("----------------");

            marf.commit().unwrap();
            marf.begin(&block_header_2, &block_header_3).unwrap();
            marf.insert_raw(TriePath::from_bytes(&path_3[..]).unwrap(), TrieLeaf::new(&vec![], &[21 as u8; 40].to_vec())).unwrap();

            test_debug!("----------------");
            test_debug!("Merkle verify {:?} from {:?}", &to_hex(&[21 as u8; 40]), block_header_3);
            test_debug!("----------------");

            merkle_test_marf(marf.borrow_storage_backend(), &block_header_3, 
                             &path_3, &[21 as u8; 40].to_vec(), None);
        }
    }

    fn marf_insert<F>(filename: &str, mut path_gen: F, count: u32, check_merkle_proof: bool) -> MARF
        where F: FnMut(u32) -> ([u8; 32], Option<BlockHeaderHash>) {

        let f = TrieFileStorage::new_memory().unwrap();
        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();

        let mut root_table_cache = None;

        let mut blocks = vec![block_header.clone()];

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;

            let (path, next_block_header) = path_gen(i);

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if let Some(next_block_header) = next_block_header {
                marf.commit().unwrap();
                marf.begin(&block_header, &next_block_header).unwrap();
                block_header = next_block_header;
                blocks.push(block_header.clone())
            }

            marf.insert_raw(triepath, value.clone()).unwrap();
             
            let read_value = MARF::get_path(marf.borrow_storage_backend(), &block_header, 
                                            &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), block_header);

            if check_merkle_proof {
                root_table_cache = Some(
                    merkle_test_marf(marf.borrow_storage_backend(), &block_header, &path.to_vec(), &value.data.to_vec(), root_table_cache));
            }
        }

        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(MARF::get_block_height(marf.borrow_storage_backend(), block, &block_header).unwrap(),
                       Some(i as u32));
            assert_eq!(MARF::get_block_at_height(marf.borrow_storage_backend(), i as u32, &block_header).unwrap(),
                       Some(block.clone()));
        }

        root_table_cache = None;

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;
            let (path, _next_block_header) = path_gen(i);

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get_path(marf.borrow_storage_backend(), &block_header,
                                            &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            if check_merkle_proof {
                root_table_cache = Some(
                    merkle_test_marf(marf.borrow_storage_backend(), &block_header, &path.to_vec(), &value.data.to_vec(), root_table_cache));
            }
        }

        marf
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 128 keys, make a new trie
    #[test]
        #[ignore]
    fn marf_insert_4096_128_seq_low() {
        marf_insert("/tmp/rust_marf_insert_4096_128_seq_low", |i| {
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29, (i / 256) as u8, (i % 256) as u8];
            let block_header = if (i + 1) % 128 == 0 {
                // next block 
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        }, 4096, true);
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the high-order bits.
    // every 128 keys, make a new trie
    #[test]
    #[ignore]
    fn marf_insert_4096_128_seq_high() {
        marf_insert("/tmp/rust_marf_insert_4096_128_seq_high", |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [i0 as u8, i1 as u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
            let block_header = if (i + 1) % 128 == 0 {
                // next block 
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        }, 4096, true);
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

        marf.begin(&TrieFileStorage::block_sentinel(), &block_header).unwrap();

        let path = [0u8; 32];
        let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
        let value = TrieLeaf::new(&vec![], &[0u8; 40].to_vec());

        test_debug!("----------------");
        test_debug!("insert ({:?}, {:?}) in {:?}", &triepath, &value, &block_header);
        test_debug!("----------------");

        marf.insert_raw(triepath.clone(), value.clone()).unwrap();

        // insert a leaf along the same path but in a different block
        let block_header_2 = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap();
        let path_2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
        let triepath_2 = TriePath::from_bytes(&path_2[..]).unwrap(); 
        let value_2 = TrieLeaf::new(&vec![], &[1u8; 40].to_vec());
    
        test_debug!("----------------");
        test_debug!("insert ({:?}, {:?}) in {:?}", &triepath_2, &value_2, &block_header_2);
        test_debug!("----------------");

        marf.commit().unwrap();
        marf.begin(&block_header, &block_header_2).unwrap();
        marf.insert_raw(triepath_2.clone(), value_2.clone()).unwrap();

        test_debug!("----------------");
        test_debug!("get ({:?}, {:?}) in {:?}", &triepath, &value, &block_header_2);
        test_debug!("----------------");

        let read_value = MARF::get_path(marf.borrow_storage_backend(), &block_header_2, &triepath).unwrap().unwrap();
        assert_eq!(read_value.data.to_vec(), value.data.to_vec());
        
        test_debug!("----------------");
        test_debug!("get ({:?}, {:?}) in {:?}", &triepath_2, &value_2, &block_header_2);
        test_debug!("----------------");

        let read_value_2 = MARF::get_path(marf.borrow_storage_backend(), &block_header_2, &triepath_2).unwrap().unwrap();
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
        marf_insert(filename, |i| {
            let mut path = [0; 32];
            path.copy_from_slice(&
                TrieHash::from_data(
                    if i == 0 {
                        &[]
                    } else {
                        seed.as_slice()
                    }).as_bytes()[0..32]);
            seed = path.to_vec();

            let block_header = if (i + 1) % 2048 == 0 {
                // next block 
                Some(BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,((i+1)/2048) as u8,((i+1)%2048) as u8])
                     .unwrap())
            } else {
                None
            };
            (path, block_header)
        }, 65536, false);

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
    #[ignore]
    fn marf_insert_random_4096_128_file_storage_merkle_proof() {
        let path = "/tmp/rust_marf_insert_4096_128_file_storage_merkle_proof";
        let f = TrieFileStorage::new_memory().unwrap();

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

            let mut block_table_cache = None;
            for j in 0..128 {
                test_debug!("Prove {:?} == {:?}", &keys[j], &values[j]);
                block_table_cache = Some(merkle_test_marf_key_value(m.borrow_storage_backend(), &block_header, &keys[j], &values[j], block_table_cache));
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
                block_table_cache = Some(merkle_test_marf_key_value(m.borrow_storage_backend(), &block_header, &keys[j], &values[j], block_table_cache));
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
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8].to_vec());

            let read_value = MARF::get_path(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            
            // can make a merkle proof to each one
            // merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.data.to_vec(), None);
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
        let mut marf = marf_insert("/tmp/rust_marf_insert_128_32_file_storage", |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];
            let block_header = if (i + 1) % 32 == 0 {
                // next block 
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 32) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        }, 128, true);

        marf.commit().unwrap();

        for i in 0..(128/32) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.borrow_storage_backend().open_block(&block_header).unwrap();
            dump_trie(marf.borrow_storage_backend());
        }
    }

    // insert a range of 4096 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 128 keys, make a new trie.
    // Use the TrieFileStorage backend
    #[test]
    #[ignore]
    fn marf_insert_4096_128_file_storage() {
        let mut marf = marf_insert("/tmp/rust_marf_insert_4096_128_file_storage", |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];
            let block_header = if (i + 1) % 128 == 0 {
                // next block 
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 128) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        }, 4096, true);

        marf.commit().unwrap();

        for i in 0..(4096/128) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.borrow_storage_backend().open_block(&block_header).unwrap();
            dump_trie(marf.borrow_storage_backend());
        }
    }

    // insert a range of 256 consecutive keys (forcing node promotions) by varying the low-order bits.
    // every 16 keys, make a new trie.
    // Use the TrieFileStorage backend
    #[test]
    fn marf_insert_256_16_file_storage() {
        let mut marf = marf_insert("/tmp/rust_marf_insert_256_16_file_storage", |i| {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];
            let block_header = if (i + 1) % 16 == 0 {
                // next block 
                Some(BlockHeaderHash::from_bytes(&[((i + 1) / 16) as u8; 32]).unwrap())
            } else {
                None
            };
            (path, block_header)
        }, 256, true);

        marf.commit().unwrap();

        for i in 0..(256/16) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            marf.borrow_storage_backend().open_block(&block_header).unwrap();
            dump_trie(marf.borrow_storage_backend());
        }
    }

    #[test]
    #[ignore]
    fn marf_insert_get_128_fork_256() {
        // create 256 forks organized as a binary tree, and insert 128 values into each one.
        // make sure we can read them all from each chain tip, and make sure we can generate merkle
        // proofs of each one's value.
        let path = ":memory:".to_string();

        let mut m = MARF::from_path(&path, None).unwrap();
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

        for (height, fork_row) in fork_headers.iter().enumerate() {
            for block in fork_row.iter(){
                assert_eq!(MARF::get_block_height(m.borrow_storage_backend(), block, block).unwrap(),
                           Some(height as u32));
                assert_eq!(MARF::get_block_at_height(m.borrow_storage_backend(), height as u32, block).unwrap(),
                           Some(block.clone()));
            }
        }

        let mut expected_chain_tips = fork_headers[fork_headers.len() - 1].clone();
        expected_chain_tips.sort();

        let mut block_table = None;

        for k in 0..expected_chain_tips.len() {
            for l in 0..128 {
                let raw_value = [7u8, (k/2) as u8, k as u8, l as u8, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].to_vec();
                let expected_value = to_hex(&raw_value);
                let key = format!("{}-{}-{}-{}", 7, (k/2), k, l);

                let marf_value = m.get(&expected_chain_tips[k], &key).unwrap().unwrap();
                assert_eq!(marf_value, MARFValue::from_value(&expected_value));
                
                block_table = Some(
                    merkle_test_marf_key_value(m.borrow_storage_backend(), &expected_chain_tips[k], &key, &expected_value, block_table));
            }
        }
    }

    #[test]
    #[ignore]
    fn marf_insert_flush_to_different_block() {
        let path = "/tmp/marf_insert_flush_to_different_block".to_string();
        let mut f = TrieFileStorage::new_memory().unwrap();

        let target_block = BlockHeaderHash([1u8; 32]);

        f.set_miner_tip(target_block.clone());

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&TrieFileStorage::block_sentinel(), &target_block).unwrap();

        let mut root_table_cache = None;

        let mut blocks = vec![];
        let num_blocks_created = 8;
        let count = 256 * num_blocks_created;

        for i in 0..count {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];
            let next_block_header = 
                if (i + 1) % 256 == 0 {
                    // next block 
                    Some(BlockHeaderHash::from_bytes(&[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,i0 as u8, i1 as u8])).unwrap()
                } else {
                    None
                };

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            if let Some(next_block_header) = next_block_header {
                marf.commit_to(&block_header).unwrap();
                marf.begin(&block_header, &target_block).unwrap();
                blocks.push(block_header.clone());
                block_header = next_block_header;
            }

            marf.insert_raw(triepath, value.clone()).unwrap();
            
            // all I/O happens off the target block
            let read_value = MARF::get_path(marf.borrow_storage_backend(), &target_block,
                                            &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();

            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
            assert_eq!(marf.borrow_storage_backend().get_cur_block(), target_block);

            // can prove off of the target block
            root_table_cache = Some(
                merkle_test_marf(marf.borrow_storage_backend(), &target_block, &path.to_vec(), &value.data.to_vec(), root_table_cache));
        }
        
        // would have been the next block
        let final_block_header = BlockHeaderHash::from_bytes(&[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,(num_blocks_created - 1) as u8,0xff]).unwrap();
        marf.commit_to(&final_block_header).unwrap();
         
        let num_blocks = blocks.len();

        block_header = final_block_header.clone();
        blocks.push(block_header.clone());

        for (i, block) in blocks.iter().enumerate() {
            debug!("Verify block height and hash at {} {} from {}", i, block, block_header);
            assert_eq!(MARF::get_block_height_miner_tip(marf.borrow_storage_backend(), block, &block_header).unwrap(),
                       Some(i as u32));

            // get_block_at_height should now always return the correct block_header
            assert_eq!(MARF::get_block_at_height(marf.borrow_storage_backend(), i as u32, &block_header).unwrap(),
                       Some(block.clone()));
        }

        root_table_cache = None;

        for i in (0..count).rev() {
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            // all but the final value are dangling off of block_header.
            // the last value is dangling off of target_block.
            
            let read_from_block = final_block_header.clone();

            // all I/O happens off the final block header
            debug!("{}: Get {} off of {}", i, &triepath, &read_from_block);
            let read_value = MARF::get_path(marf.borrow_storage_backend(), &read_from_block,
                                            &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();

            assert_eq!(read_value.data.to_vec(), value.data.to_vec());
          

            if i == 2046 {
            //    std::env::set_var("BLOCKSTACK_TRACE", "1");
            }
            // can make a merkle proof to each one using the final committed block header
            debug!("{}: Check proof for {} off of {}", i, &triepath, &read_from_block);
            root_table_cache = Some(
                merkle_test_marf(marf.borrow_storage_backend(), &read_from_block, &path.to_vec(), &value.data.to_vec(), root_table_cache));
        }
    }

    #[test]
    fn test_marf_read_only() {
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let marf = MARF::from_storage(f);
        let mut ro_marf = marf.reopen_readonly().unwrap();
            
        let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
        let leaf = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].to_vec());
        let value = MARFValue::from(0x1234);

        if let Err(Error::ReadOnlyError) = MARF::extend_trie(ro_marf.borrow_storage_backend(), &BlockHeaderHash([0x11; 32])) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = MARF::format(ro_marf.borrow_storage_backend(), &BlockHeaderHash([0x01; 32])) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = MARF::insert_leaf(ro_marf.borrow_storage_backend(), &BlockHeaderHash([0x11; 32]), &triepath, &leaf) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = MARF::insert_leaf_in_batch(ro_marf.borrow_storage_backend(), &BlockHeaderHash([0x11; 32]), &triepath, &leaf) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.set_block_heights(&BlockHeaderHash([0x11; 32]), &BlockHeaderHash([0x22; 32]), 123) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.insert("foo", value.clone()) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.insert_raw(triepath.clone(), leaf.clone()) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.insert_batch(&vec!["foo".to_string()], vec![value.clone()]) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.commit() {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.commit_mined(&BlockHeaderHash([0x22; 32])) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.commit_to(&BlockHeaderHash([0x33; 32])) {} else { assert!(false); }
        if let Err(Error::ReadOnlyError) = ro_marf.begin(&BlockHeaderHash([0x22; 32]), &BlockHeaderHash([0x33; 32])) {} else { assert!(false); }
    }

    #[test]
    fn test_marf_begin_from_sentinel_twice() {
        let f = TrieFileStorage::new_memory().unwrap();
        let block_header_1 = BlockHeaderHash::from_bytes(&[1u8; 32]).unwrap();
        let block_header_2 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        
        let path_1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let triepath_1 = TriePath::from_bytes(&path_1[..]).unwrap(); 
        
        let path_2 = [1,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let triepath_2 = TriePath::from_bytes(&path_2[..]).unwrap(); 

        let value_1 = TrieLeaf::new(&vec![], &vec![1u8; 40]);
        let value_2 = TrieLeaf::new(&vec![], &vec![2u8; 40]);

        marf.begin(&TrieFileStorage::block_sentinel(), &block_header_1).unwrap();
        marf.insert_raw(triepath_1, value_1.clone()).unwrap();
        marf.commit_to(&block_header_1).unwrap();

        marf.begin(&TrieFileStorage::block_sentinel(), &block_header_2).unwrap();
        marf.insert_raw(triepath_2, value_2.clone()).unwrap();
        marf.commit_to(&block_header_2).unwrap();
            
        let read_value_1 = MARF::get_path(marf.borrow_storage_backend(), &block_header_1, &triepath_1).unwrap().unwrap();
        eprintln!("read_value_1 from {:?} is {:?}", &block_header_1, &read_value_1);

        let read_value_2 = MARF::get_path(marf.borrow_storage_backend(), &block_header_2, &triepath_2).unwrap().unwrap();
        eprintln!("read_value_2 from {:?} is {:?}", &block_header_2, &read_value_2);
       
        // should fail
        let read_value_1 = MARF::get_path(marf.borrow_storage_backend(), &block_header_2, &triepath_1).unwrap_err();
        if let Error::NotFoundError = read_value_1 {} else { assert!(false); }
    }
}

