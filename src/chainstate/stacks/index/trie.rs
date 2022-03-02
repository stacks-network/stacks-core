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
/// This module defines the methods for reading and inserting into a Trie
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;

use sha2::Digest;

use chainstate::stacks::index::bits::{get_leaf_hash, get_node_hash, get_nodetype_hash_bytes};
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::node::{
    clear_backptr, is_backptr, set_backptr, CursorError, TrieCursor, TrieNode, TrieNode16,
    TrieNode256, TrieNode4, TrieNode48, TrieNodeID, TrieNodeType, TriePtr,
};
use chainstate::stacks::index::storage::{TrieFileStorage, TrieStorageConnection};
use chainstate::stacks::index::Error;
use chainstate::stacks::index::{MarfTrieId, TrieHasher};
use util::hash::to_hex;
use util::log;
use util::macros::is_trace;

use chainstate::stacks::index::TrieHashExtension;
use chainstate::stacks::index::TrieLeaf;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::BLOCK_HEADER_HASH_ENCODED_SIZE;
use stacks_common::types::chainstate::TRIEHASH_ENCODED_SIZE;

/// We don't actually instantiate a Trie, but we still need to pass a type parameter for the
/// storage implementation.
pub struct Trie {}

/// Fetch children hashes and compute the node's hash
fn get_nodetype_hash<T: MarfTrieId>(
    storage: &mut TrieStorageConnection<T>,
    node: &TrieNodeType,
) -> Result<TrieHash, Error> {
    let mut hasher = TrieHasher::new();

    node.write_consensus_bytes(storage, &mut hasher)
        .expect("IO Failure pushing to hasher.");

    storage.write_children_hashes(node, &mut hasher)?;

    let mut res = [0u8; 32];
    res.copy_from_slice(hasher.finalize().as_slice());

    let ret = TrieHash(res);

    trace!("get_node_hash: hash {:?} = {:?} + ::children::", &ret, node);
    Ok(ret)
}

impl Trie {
    /// Read the root node.  First try to read it as a back-pointer (since all root nodes except for
    /// the root node in the very first trie will be back-pointers), and if that fails due to a
    /// node ID mismatch (i.e. CorruptionError), then try to read it as a non-backpointer.
    pub fn read_root<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
    ) -> Result<(TrieNodeType, TrieHash), Error> {
        let ptr = TriePtr::new(
            set_backptr(TrieNodeID::Node256 as u8),
            0,
            storage.root_ptr(),
        );
        let res = storage.read_nodetype(&ptr);
        match res {
            Err(Error::CorruptionError(_)) => {
                let non_backptr_ptr = storage.root_trieptr();
                storage.read_nodetype(&non_backptr_ptr)
            }
            Err(e) => Err(e),
            Ok(data) => Ok(data),
        }
    }

    /// Walk from the given node to the next node on the path, advancing the cursor.
    /// Return the TriePtr followed, the _next_ node to walk, and the hash of the _current_ node.
    /// Returns None if we either didn't find the node, or we're out of path, or we're at a leaf.
    /// NOTE: This only works if we're walking a Trie, not a MARF.  Returns Ok(None) if a
    /// back-pointer is found.
    pub fn walk_from<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        node: &TrieNodeType,
        cursor: &mut TrieCursor<T>,
    ) -> Result<Option<(TriePtr, TrieNodeType, TrieHash)>, Error> {
        match cursor.walk(node, &storage.get_cur_block()) {
            Ok(ptr_opt) => {
                match ptr_opt {
                    None => {
                        // end of path
                        Ok(None)
                    }
                    Some(ptr) => {
                        // end of node path
                        trace!("Walked to {:?}", &ptr);
                        let (node, hash) = storage.read_nodetype(&ptr)?;
                        Ok(Some((ptr, node, hash)))
                    }
                }
            }
            Err(e) => Err(Error::CursorError(e)),
        }
    }

    /// Follow a back-pointer back to a trie node in a previous trie.
    ///
    /// If the ptr is a back-pointer, then shunt to the block that contains the target node, read
    /// it, and update the cursor to record that we followed the back-pointer.
    ///
    /// If the ptr is not a back-pointer, read the node from this trie.
    /// s must point to this trie's block, not the block pointed at by the ptr.
    ///
    /// Either way, return the node, its hash, and the ptr to the node in the block in which it was
    /// found (it will _not_ be a back-pointer).
    pub fn walk_backptr<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        ptr: &TriePtr,
        cursor: &mut TrieCursor<T>,
    ) -> Result<(TrieNodeType, TrieHash, TriePtr), Error> {
        if !is_backptr(ptr.id()) {
            // child is in this block
            if ptr.id() == (TrieNodeID::Empty as u8) {
                // shouldn't happen
                return Err(Error::CorruptionError("ptr is empty".to_string()));
            }
            let (node, node_hash) = storage.read_nodetype(ptr)?;
            return Ok((node, node_hash, ptr.clone()));
        } else {
            // ptr is a backptr -- find the block
            let back_block_hash = storage.get_block_from_local_id(ptr.back_block())?.clone();
            storage.open_block_known_id(&back_block_hash, ptr.back_block())?;

            let backptr = ptr.from_backptr();
            let (node, node_hash) = storage.read_nodetype(&backptr)?;

            cursor.repair_backptr_step_backptr(&node, &backptr, storage.get_cur_block());
            Ok((node, node_hash, backptr))
        }
    }

    /// Read a node's children's hashes as a vector of TrieHashes.
    /// This only works for intermediate nodes and leafs (the latter of which have no children).
    ///
    /// See: TrieStorageConnection::write_children_hashes for more information on the hash contents.
    pub fn get_children_hashes<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        node: &TrieNodeType,
    ) -> Result<Vec<TrieHash>, Error> {
        let mut buffer = Vec::with_capacity(node.ptrs().len() * TRIEHASH_ENCODED_SIZE);
        storage.write_children_hashes(node, &mut buffer)?;
        assert_eq!(buffer.len() % TRIEHASH_ENCODED_SIZE, 0);

        let trie_hashes: Vec<_> = buffer
            .chunks_exact(TRIEHASH_ENCODED_SIZE)
            .map(|x| {
                TrieHash::from_bytes(x).expect("Failed to re-encode TrieHash from byte buffer")
            })
            .collect();

        Ok(trie_hashes)
    }

    /// Given an existing leaf, replace it with the new leaf.
    /// c must point to the node to replace.
    fn replace_leaf<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &mut TrieCursor<T>,
        value: &mut TrieLeaf,
    ) -> Result<TriePtr, Error> {
        let (cur_leaf, _) = storage.read_nodetype(&cursor.ptr())?;
        if !cur_leaf.is_leaf() {
            return Err(Error::CorruptionError(format!(
                "Not a leaf: {:?}",
                &cursor.ptr()
            )));
        }

        value.path = cur_leaf.path_bytes().clone();

        let leaf_hash = get_leaf_hash(value);

        let leaf_ptr = cursor.ptr();
        storage.write_node(leaf_ptr.ptr(), value, leaf_hash)?;

        trace!("replace_leaf: wrote {:?} at {:?}", &value, &cursor.ptr());
        Ok(cursor.ptr())
    }

    /// Append a leaf to the trie, and return the TriePtr to it.
    /// Do lazy expansion -- have the leaf store the trailing path to it.
    /// Return the TriePtr to the newly-written leaf
    fn append_leaf<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &mut TrieCursor<T>,
        value: &mut TrieLeaf,
    ) -> Result<TriePtr, Error> {
        assert!(cursor.chr().is_some());

        let ptr = storage.last_ptr()?;
        let chr = cursor.chr().unwrap();

        value.path = cursor.path.as_bytes()[cursor.index..].to_vec();

        let leaf_hash = get_leaf_hash(value);
        let leaf_ptr = TriePtr::new(TrieNodeID::Leaf as u8, chr, ptr);
        storage.write_node(ptr, value, leaf_hash)?;

        trace!("append_leaf: append {:?} at {:?}", value, &leaf_ptr);
        Ok(leaf_ptr)
    }

    /// Given a leaf and a cursor that is _not_ EOP, and a new leaf, create a node4 with the two
    /// leaves as its children and return its pointer.
    ///
    /// f must point to the start of cur_leaf.
    ///
    /// before:
    ///
    /// leaf[path=aabbccddeeff00112233]=123456
    ///
    /// insert (aabbccddeeff99887766, 98765)
    ///
    /// after:
    ///                          [00]leaf[path=112233]=123456
    ///                         /
    /// node4[path=aabbccddeeff]
    ///                         \
    ///                          [99]leaf[887766]=98765
    ///
    fn promote_leaf_to_node4<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &mut TrieCursor<T>,
        cur_leaf_data: &mut TrieLeaf,
        new_leaf_data: &mut TrieLeaf,
    ) -> Result<TriePtr, Error> {
        // can only work if we're not at the end of the path, and the current node has a path
        assert!(!cursor.eop());
        assert!(cur_leaf_data.path.len() > 0);

        // switch from lazy expansion to path compression --
        // * the current and new leaves will have unique suffixes
        // * the node4 will have their shared prefix
        let cur_leaf_ptr = cursor.ptr();

        let node4_path = cur_leaf_data.path[0..(cursor.ntell())].to_vec();
        let node4_chr = cur_leaf_ptr.chr();

        let cur_leaf_chr = cur_leaf_data.path[cursor.ntell()];
        let cur_leaf_path = cur_leaf_data.path[(if cursor.ntell() >= cur_leaf_data.path.len() {
            cursor.ntell()
        } else {
            cursor.ntell() + 1
        })..]
            .to_vec();

        // update current leaf (path changed) and save it
        let cur_leaf_disk_ptr = cur_leaf_ptr.ptr();
        let cur_leaf_new_ptr = TriePtr::new(
            TrieNodeID::Leaf as u8,
            cur_leaf_chr,
            cur_leaf_disk_ptr as u32,
        );

        assert!(cur_leaf_path.len() <= cur_leaf_data.path.len());
        let _sav_cur_leaf_data = cur_leaf_data.clone();
        cur_leaf_data.path = cur_leaf_path;
        let cur_leaf_hash = get_leaf_hash(cur_leaf_data);

        // NOTE: this is safe since the current leaf's byte representation has gotten shorter
        storage.write_node(cur_leaf_ptr.ptr(), cur_leaf_data, cur_leaf_hash.clone())?;

        // append the new leaf and the end of the file.
        let new_leaf_disk_ptr = storage.last_ptr()?;
        let new_leaf_chr = cursor.path[cursor.tell()]; // NOTE: this is safe because !cursor.eop()
        let new_leaf_path = cursor.path[(if cursor.tell() + 1 <= cursor.path.len() {
            cursor.tell() + 1
        } else {
            cursor.path.len()
        })..]
            .to_vec();
        new_leaf_data.path = new_leaf_path;
        let new_leaf_hash = get_leaf_hash(new_leaf_data);

        // put new leaf at the end of this Trie
        let new_leaf_ptr = TriePtr::new(TrieNodeID::Leaf as u8, new_leaf_chr, new_leaf_disk_ptr);

        storage.write_node(new_leaf_disk_ptr, new_leaf_data, new_leaf_hash.clone())?;

        // append the Node4 that points to both of them, and put it after the new leaf
        let mut node4_data = TrieNode4::new(&node4_path);

        assert!(node4_data.insert(&cur_leaf_new_ptr));
        assert!(node4_data.insert(&new_leaf_ptr));

        let node4_hash = get_node_hash(
            &node4_data,
            &vec![
                cur_leaf_hash,
                new_leaf_hash,
                TrieHash::from_data(&[]),
                TrieHash::from_data(&[]),
            ],
            storage,
        );

        let node4 = TrieNodeType::Node4(node4_data);

        // append the node4 to the end of the trie
        let node4_disk_ptr = storage.last_ptr()?;

        let ret = TriePtr::new(TrieNodeID::Node4 as u8, node4_chr, node4_disk_ptr);
        storage.write_nodetype(node4_disk_ptr, &node4, node4_hash)?;

        // update cursor to point to this node4 as the last-node-visited, and set the newly-created
        // ptr as the last ptr traversed (so the cursor still points to this leaf, but accurately
        // reflects the path taken to it).
        cursor.repair_retarget(&node4, &ret, &storage.get_cur_block());

        trace!(
            "Promoted {:?} to {:?}, {:?}, {:?}, new ptr = {:?}",
            _sav_cur_leaf_data,
            cur_leaf_data,
            &node4,
            new_leaf_data,
            &ret
        );
        Ok(ret)
    }

    fn node_has_space(chr: u8, children: &[TriePtr]) -> bool {
        let mut i = (children.len() - 1) as i64;
        while i >= 0 {
            if children[i as usize].id() == (TrieNodeID::Empty as u8)
                || children[i as usize].chr() == chr
            {
                return true;
            }
            i -= 1;
        }
        return false;
    }

    /// Try to insert a leaf node into the given node, if there's space to do so and if the leaf
    /// belongs as a child of this node.
    /// If so, then save the leaf and its hash, update the node's ptrs and hash, and return the
    /// node's ptr and the node's new hash so we can update the trie.
    /// Return None if there's no space, or if the leaf doesn't share its full path prefix with the
    /// given node.
    ///
    /// ```text
    /// before:
    ///                          [00]nodeY[path=112233] ...
    ///                         /
    /// nodeX[path=aabbccddeeff]
    ///
    /// insert (aabbccddeeff99887766, 123456)
    ///
    ///                          [00]nodeY[path=112233] ...
    ///                         /
    /// nodeX[path=aabbccddeeff]
    ///                         \
    ///                          [99]leaf[path=887766]=123456
    /// ```
    fn try_attach_leaf<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &mut TrieCursor<T>,
        leaf: &mut TrieLeaf,
        node: &mut TrieNodeType,
    ) -> Result<Option<TriePtr>, Error> {
        // can only do this if we're at the end of the node's path
        if !cursor.eonp(node) {
            // nope
            return Ok(None);
        }
        assert!(cursor.chr().is_some());
        assert!(!node.is_leaf());

        let has_space = Trie::node_has_space(cursor.chr().unwrap(), node.ptrs());
        if !has_space {
            // nope!
            return Ok(None);
        }

        // write leaf and update parent
        let leaf_ptr = Trie::append_leaf(storage, cursor, leaf)?;
        let inserted = node.insert(&leaf_ptr);

        assert!(inserted);

        let new_node_hash = get_nodetype_hash(storage, node)?;

        storage.write_nodetype(cursor.ptr().ptr(), node, new_node_hash)?;

        Ok(Some(cursor.ptr()))
    }

    /// Given a node and a leaf, attach the leaf.  Promote the intermediate node if necessary.
    /// Does the same thing as try_attach_leaf, but the node might get expanaded.  In this case, the
    /// new node will be appended and the old node will be leaked in the storage implementation
    /// (leakage isn't a concern in practice, because the "leak" will happen inside the TrieRAM
    /// storage implementation, which will be garbage-collected and dumped to disk once we finish
    /// all the block's inserts and call the TrieRAM's containing TrieStorageConnection instance's
    /// flush() method).
    fn insert_leaf<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &mut TrieCursor<T>,
        leaf: &mut TrieLeaf,
        node: &mut TrieNodeType,
    ) -> Result<TriePtr, Error> {
        // can only do this if we're at the end of the node's path
        assert!(cursor.eonp(node));

        let res = Trie::try_attach_leaf(storage, cursor, leaf, node)?;
        if res.is_some() {
            // success!
            return Ok(res.unwrap());
        }

        // not enough space -- need to promote node
        let mut new_node = match node {
            TrieNodeType::Leaf(_) => panic!("Cannot insert into a leaf"),
            TrieNodeType::Node256(_) => panic!("Somehow could not insert into a Node256"),
            TrieNodeType::Node4(ref data) => TrieNodeType::Node16(TrieNode16::from_node4(data)),
            TrieNodeType::Node16(ref data) => {
                TrieNodeType::Node48(Box::new(TrieNode48::from_node16(data)))
            }
            TrieNodeType::Node48(ref data) => {
                TrieNodeType::Node256(Box::new(TrieNode256::from_node48(data.as_ref())))
            }
        };

        let node_ptr = cursor.ptr();
        let leaf_ptr = Trie::append_leaf(storage, cursor, leaf)?;
        let inserted = new_node.insert(&leaf_ptr);
        assert!(inserted);

        let new_node_hash = get_nodetype_hash(storage, &new_node)?;

        // append this leaf to the Trie
        let new_node_disk_ptr = storage.last_ptr()?;

        let ret = TriePtr::new(new_node.id(), node_ptr.chr(), new_node_disk_ptr as u32);
        storage.write_nodetype(new_node_disk_ptr, &new_node, new_node_hash)?;

        // update the cursor so its path of nodes and ptrs accurately reflects that we would have
        // visited this leaf on its path.
        cursor.repair_retarget(&new_node, &ret, &storage.get_cur_block());
        Ok(ret)
    }

    /// Given a node and a leaf to insert, break apart the node's compressed path into the shared
    /// prefix and the node- and leaf-specific segments, and add a Node4 at the break with the
    /// leaf.  Updates the given node and leaf, and returns the node4's ptr and hash.
    ///
    /// ```text
    /// before:
    ///                                        [00]nodeY[path=112233]...
    ///                                       /
    /// (parent)----[aa]nodeX[path=bbccddeeff]
    ///                                       \
    ///                                        [99]nodeZ[path=887766]...
    ///
    /// insert (aabbccffccbbaa, 123456)
    ///
    /// after:
    ///
    ///                                  [ff]leaf[path=ccbbaa]=123456
    ///                                 /
    /// (parent)----[aa]node4[path=bbcc]---[dd]nodeX[path=eeff]---[00]nodeY[path=112233]...
    ///                                                        \
    ///                                                         [99]nodeZ[path=887766]...
    ///
    /// ```
    /// (if nodeX was the root, then there is no parent, and the resulting node will be a node256
    /// instead of a node4).
    ///
    fn splice_leaf<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &mut TrieCursor<T>,
        leaf: &mut TrieLeaf,
        node: &mut TrieNodeType,
    ) -> Result<TriePtr, Error> {
        assert!(!cursor.eop());
        assert!(!cursor.eonp(node));
        assert!(cursor.chr().is_some());
        assert!(!node.is_leaf());

        let node_path = node.path_bytes().clone();
        let shared_path_prefix = node_path[0..cursor.ntell()].to_vec();
        let leaf_path = cursor.path[cursor.tell() + 1..].to_vec();
        let new_cur_node_path = node_path[cursor.ntell() + 1..].to_vec();
        let new_cur_node_chr = node_path[cursor.ntell()]; // chr for node-X post-update

        // store leaf
        leaf.path = leaf_path;
        let leaf_chr = cursor.path[cursor.tell()];
        let leaf_disk_ptr = storage.last_ptr()?;
        let leaf_hash = get_leaf_hash(leaf);
        let leaf_ptr = TriePtr::new(TrieNodeID::Leaf as u8, leaf_chr, leaf_disk_ptr);
        storage.write_node(leaf_disk_ptr, leaf, leaf_hash.clone())?;

        // update current node (node-X) and make a new path and ptr for it
        let cur_node_cur_ptr = cursor.ptr();
        let new_cur_node_disk_ptr = storage.last_ptr()?;
        let new_cur_node_ptr = TriePtr::new(
            cur_node_cur_ptr.id(),
            new_cur_node_chr,
            new_cur_node_disk_ptr as u32,
        );

        node.set_path(new_cur_node_path);

        let new_cur_node_hash = get_nodetype_hash(storage, &node)?;

        let mut new_node4 = TrieNode4::new(&shared_path_prefix);
        new_node4.insert(&leaf_ptr);
        new_node4.insert(&new_cur_node_ptr);

        let new_node_hash = get_node_hash(
            &new_node4,
            &vec![
                leaf_hash,
                new_cur_node_hash,
                TrieHash::from_data(&[]),
                TrieHash::from_data(&[]),
            ],
            storage,
        );

        let (new_node_id, new_node) = if cursor.node_ptrs.len() == 1 {
            // we just split the compressed path in the root node,
            // so make sure the root node _stays_ as a node256.
            // Note that the hash we write here doesn't matter -- it'll get overwritten in the
            // subsequent call to update_root_hash()
            (
                TrieNodeID::Node256,
                TrieNode256::from_node4(&new_node4).as_trie_node_type(),
            )
        } else {
            (TrieNodeID::Node4, TrieNodeType::Node4(new_node4))
        };

        // store node4 where node-X used to be
        storage.write_nodetype(cur_node_cur_ptr.ptr(), &new_node, new_node_hash)?;

        // store node-X at the end
        storage.write_nodetype(new_cur_node_disk_ptr, node, new_cur_node_hash)?;

        let ret = TriePtr::new(
            new_node_id as u8,
            cur_node_cur_ptr.chr(),
            cur_node_cur_ptr.ptr(),
        );
        cursor.repair_retarget(&new_node, &ret, &storage.get_cur_block());

        trace!("splice_leaf: node-X' at {:?}", &ret);
        Ok(ret)
    }

    /// Add a new value to the Trie at the location pointed at by the cursor.
    /// Returns a ptr to be inserted into the last node visited by the cursor.
    pub fn add_value<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &mut TrieCursor<T>,
        value: &mut TrieLeaf,
    ) -> Result<TriePtr, Error> {
        let mut node = match cursor.node() {
            Some(n) => n,
            None => panic!("Cursor is uninitialized"),
        };

        if cursor.eop() {
            match node {
                TrieNodeType::Leaf(_) => Trie::replace_leaf(storage, cursor, value),
                _ => Trie::insert_leaf(storage, cursor, value, &mut node),
            }
        } else {
            // didn't reach the end of the path, so we're on an intermediate node
            // or we're somewhere in the path of a leaf.
            // Either tack the leaf on (possibly promoting the node), or splice the leaf in.
            if cursor.eonp(&node) {
                trace!(
                    "eop = {}, eonp = {}, c = {:?}, node = {:?}",
                    cursor.eop(),
                    cursor.eonp(&node),
                    cursor,
                    &node
                );
                Trie::insert_leaf(storage, cursor, value, &mut node)
            } else {
                match node {
                    TrieNodeType::Leaf(ref mut data) => {
                        Trie::promote_leaf_to_node4(storage, cursor, data, value)
                    }
                    _ => Trie::splice_leaf(storage, cursor, value, &mut node),
                }
            }
        }
    }

    /// Perform the reads, lookups, etc. for computing the ancestor byte vector.
    /// This method _does not_ restore the previously open block on failure, the caller will do that.
    fn inner_get_trie_ancestor_hashes_bytes<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
    ) -> Result<Vec<TrieHash>, Error> {
        let cur_block_header = storage.get_cur_block();
        // definitely enough space for the foreseeable future
        //    ancestor depth _cannot_ exceed 32 -- 2^32 > max size of u32
        //    (which is how we are identifying blocks).
        let mut hash_buf = Vec::with_capacity(33);

        // here is where some mind-bending things begin to happen.
        //   we want to find the block at a given _height_. but how to do so?
        //   use the data stored already in the MARF.
        let cur_block_height =
            MARF::get_block_height_miner_tip(storage, &cur_block_header, &cur_block_header)
                .map_err(|e| match e {
                    Error::NotFoundError => Error::CorruptionError(format!(
                        "Could not obtain block height for block {}",
                        &cur_block_header
                    )),
                    x => x,
                })?
                .ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "Could not obtain block height for block {}",
                        &cur_block_header
                    ))
                })?;
        let mut log_depth = 0;
        while log_depth < 32 && (1u32 << log_depth) <= cur_block_height {
            let prev_block_header = MARF::get_block_at_height(
                storage,
                cur_block_height - (1u32 << log_depth),
                &cur_block_header,
            )?
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "Could not obtain block hash at block height {}",
                    cur_block_height - (1u32 << log_depth)
                ))
            })?;

            storage.open_block(&prev_block_header)?;

            let root_ptr = storage.root_trieptr();

            let ancestor_hash = storage.read_node_hash_bytes(&root_ptr)?;

            trace!(
                "Include root hash {} from block {} in ancestor #{}",
                ancestor_hash,
                prev_block_header,
                1u32 << log_depth
            );

            hash_buf.push(ancestor_hash);

            log_depth += 1;
        }

        Ok(hash_buf)
    }

    /// Calculate the byte vector of the ancestor root hashes of this trie.
    /// s must point to the block that contains the trie's root.
    pub fn get_trie_ancestor_hashes_bytes<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
    ) -> Result<Vec<TrieHash>, Error> {
        let (cur_block_header, cur_block_id) = storage.get_cur_block_and_id();
        if let Some(cached_ancestor_hashes_bytes) =
            storage.check_cached_ancestor_hashes_bytes(&cur_block_header)
        {
            Ok(cached_ancestor_hashes_bytes)
        } else {
            let result = Trie::inner_get_trie_ancestor_hashes_bytes(storage);
            if let Ok(ref result) = result {
                storage.set_cached_ancestor_hashes_bytes(&cur_block_header, result.clone());
            }

            // restore
            storage.open_block_maybe_id(&cur_block_header, cur_block_id)?;
            result
        }
    }

    /// Calculate the bytes of the ancestor root hashes of this trie, plus the current trie's root.
    /// Return the resulting sequence of hashes a a single byte buffer.
    pub fn get_trie_root_ancestor_hashes_bytes<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        children_root_hash: &TrieHash,
    ) -> Result<Vec<TrieHash>, Error> {
        trace!(
            "Calculate Trie hash from root node digest {:?}",
            children_root_hash
        );
        let mut ancestor_bytes = Trie::get_trie_ancestor_hashes_bytes(storage)?;
        ancestor_bytes.insert(0, children_root_hash.clone());

        Ok(ancestor_bytes)
    }

    /// Calculate the root hash of the trie (i.e. the hash for the root node) by including both the
    /// digest of this Trie, as well as a geometric sequence of prior Trie root hashes as far back
    /// as we can go.
    pub fn get_trie_root_hash<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        children_root_hash: &TrieHash,
    ) -> Result<TrieHash, Error> {
        let hashes = Trie::get_trie_root_ancestor_hashes_bytes(storage, children_root_hash)?;
        if hashes.len() == 1 {
            Ok(hashes[0])
        } else {
            Ok(TrieHash::from_data_array(hashes.as_slice()))
        }
    }

    /// Unwind a TrieCursor to update the Merkle root of the trie.
    /// The root hashes of each trie form a Merkle skip-list -- the hash of Trie i is calculated
    /// from the hash of its children, plus the hash Tries i-1, i-2, i-4, i-8, ..., i-2**j, ...
    /// This is required for Merkle proofs to work (specifically, the shunt proofs).
    fn recalculate_root_hash<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &TrieCursor<T>,
        update_skiplist: bool,
    ) -> Result<(), Error> {
        assert!(cursor.node_ptrs.len() > 0);

        let mut ptrs = cursor.node_ptrs.clone();
        trace!("update_root_hash: ptrs = {:?}", &ptrs);
        let mut child_ptr = ptrs.pop().unwrap();

        if ptrs.len() == 0 {
            // root node was already updated by trie operations, but it will have the wrong hash.
            // we need to "fix" the root node so it mixes in its ancestor hashes.
            trace!("Fix up root node so it mixes in its ancestor hashes");
            let (node, _cur_hash) = storage.read_nodetype(&child_ptr)?;
            if !node.is_node256() {
                return Err(Error::CorruptionError(
                    "Only ptr was not a node256".to_string(),
                ));
            }

            if child_ptr != storage.root_trieptr() {
                return Err(Error::CorruptionError(
                    "Only ptr is not the root".to_string(),
                ));
            }

            let my_hash = get_nodetype_hash(storage, &node)?;

            let h = if update_skiplist {
                trace!("Update root skiplist");
                Trie::get_trie_root_hash(storage, &my_hash)?
            } else {
                trace!("Not updating root skiplist");
                my_hash
            };

            // for debug purposes
            if is_trace() {
                let node_hash = my_hash.clone();
                let _ = Trie::get_trie_root_ancestor_hashes_bytes(storage, &node_hash)
                    .and_then(|_hs| {
                        storage.clear_cached_ancestor_hashes_bytes();
                        trace!("update_root_hash: Updated {:?} with {:?} from {} to {} + {:?} = {} (fixed root)", &node, &child_ptr, &_cur_hash, &node_hash, &_hs[1..].to_vec(), &h);
                        Ok(())
                    });
            }

            debug!(
                "Next root hash is {} (update_skiplist={})",
                h, update_skiplist
            );

            storage.write_nodetype(child_ptr.ptr(), &node, h)?;
        } else {
            while let Some(ptr) = ptrs.pop() {
                if is_backptr(ptr.id()) {
                    // this node was not altered, but instead queued to the cursor as part of walking a
                    // backptr skiplist.  Do nothing.
                    continue;
                }

                let (mut node, _cur_hash) = storage.read_nodetype(&ptr)?;
                assert!(!node.is_leaf());

                // this child_ptr _must_ be in the node.
                let updated = node.replace(&child_ptr);
                if !updated {
                    trace!(
                        "FAILED TO UPDATE {:?} WITH {:?}: {:?}",
                        &node,
                        &child_ptr,
                        cursor
                    );
                    assert!(updated);
                }

                let content_hash = get_nodetype_hash(storage, &node)?;

                // flush the current node to storage --
                //  necessary because computing ancestor hashes requires that the trie's pointers
                //  all be intact, since it does ancestor lookups!
                // however, since we're going to update the hash in the next write anyways, just write an empty buff
                storage.write_nodetype(ptr.ptr(), &node, TrieHash([0; 32]))?;

                let h = if !node.is_node256() {
                    trace!(
                        "update_root_hash: Updated {:?} with {:?} from {:?} to {:?}",
                        node,
                        &child_ptr,
                        &_cur_hash,
                        &content_hash
                    );
                    content_hash.clone()
                } else {
                    let root_ptr = storage.root_trieptr();
                    let node_hash = if ptr == root_ptr {
                        let h = if update_skiplist {
                            Trie::get_trie_root_hash(storage, &content_hash)?
                        } else {
                            content_hash.clone()
                        };

                        if is_trace() {
                            let _ = Trie::get_trie_root_ancestor_hashes_bytes(storage, &content_hash)
                                        .and_then(|_hs| {
                                            storage.clear_cached_ancestor_hashes_bytes();
                                            trace!("update_root_hash: Updated {:?} with {:?} from {:?} to {:?} + {:?} = {:?}", &node, &child_ptr, &_cur_hash, &content_hash, &_hs[1..].to_vec(), &h);
                                            Ok(())
                                        });
                        }

                        debug!(
                            "Next root hash is {} (update_skiplist={})",
                            h, update_skiplist
                        );
                        h
                    } else {
                        trace!(
                            "update_root_hash: Updated {:?} with {:?} from {:?} to {:?}",
                            &node,
                            &child_ptr,
                            &_cur_hash,
                            &content_hash
                        );
                        content_hash
                    };
                    node_hash
                };

                storage.write_nodetype(ptr.ptr(), &node, h)?;

                child_ptr = ptr;
                child_ptr.id = clear_backptr(child_ptr.id);
            }
        }
        // must be at the root
        assert_eq!(child_ptr, storage.root_trieptr());
        Ok(())
    }

    pub fn update_root_hash<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &TrieCursor<T>,
    ) -> Result<(), Error> {
        Trie::recalculate_root_hash(storage, cursor, true)
    }

    pub fn update_root_node_hash<T: MarfTrieId>(
        storage: &mut TrieStorageConnection<T>,
        cursor: &TrieCursor<T>,
    ) -> Result<(), Error> {
        Trie::recalculate_root_hash(storage, cursor, false)
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_variables)]
    #![allow(unused_assignments)]

    use std::io::Cursor;

    use chainstate::stacks::index::bits::*;
    use chainstate::stacks::index::marf::*;
    use chainstate::stacks::index::node::*;
    use chainstate::stacks::index::proofs::*;
    use chainstate::stacks::index::storage::*;
    use chainstate::stacks::index::test::*;
    use chainstate::stacks::index::trie::*;
    use chainstate::stacks::index::ClarityMarfTrieId;

    use super::*;

    fn walk_to_insertion_point(
        f: &mut TrieStorageConnection<BlockHeaderHash>,
        cursor: &mut TrieCursor<BlockHeaderHash>,
    ) -> (TriePtr, TrieNodeType, TrieHash) {
        let (mut node, root_hash) = Trie::read_root(f).unwrap();
        let mut node_hash = TrieHash::from_empty_data();
        let mut node_ptr = f.root_trieptr();

        for _ in 0..cursor.path.len() {
            match Trie::walk_from(f, &node, cursor) {
                Ok(node_data_opt) => match node_data_opt {
                    Some((next_nodeptr, next_node, next_node_hash)) => {
                        node = next_node;
                        node_ptr = next_nodeptr;
                        node_hash = next_node_hash;
                        continue;
                    }
                    None => {
                        panic!("No insertion point found -- reached leaf");
                    }
                },
                Err(e) => {
                    match e {
                        Error::CursorError(_) => {
                            // don't care about backptrs in this suite of tests
                            return (node_ptr, node, node_hash);
                        }
                        _ => {
                            panic!("Encountered error: {:?}", e);
                        }
                    }
                }
            }
        }

        panic!("Encountered a loop in the trie");
    }

    #[test]
    fn trie_cursor_try_attach_leaf() {
        for node_id in [
            TrieNodeID::Node4,
            TrieNodeID::Node16,
            TrieNodeID::Node48,
            TrieNodeID::Node256,
        ]
        .iter()
        {
            let mut f_store = TrieFileStorage::new_memory().unwrap();
            let mut f = f_store.transaction().unwrap();

            let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
            MARF::format(&mut f, &block_header).unwrap();

            // used to short-circuit block-height lookups, so that we don't
            //   mess up these tests expected trie structures.
            f.test_genesis_block.replace(block_header.clone());

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
            let (nodes, node_ptrs, hashes) =
                make_node_path(&mut f, node_id.to_u8(), &path_segments, [31u8; 40].to_vec());

            let mut ptrs = vec![];

            // append a leaf to each node
            for i in 0..32 {
                let mut path = vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[i] = 32;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());
                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                // end of path -- cursor points to the insertion point.
                // all nodes have space,
                f.open_block(&block_header).unwrap();
                let ptr_opt_res = Trie::try_attach_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[i as u8; 40].to_vec()),
                    &mut node,
                );
                assert!(ptr_opt_res.is_ok());

                let ptr_opt = ptr_opt_res.unwrap();
                assert!(ptr_opt.is_some());

                let ptr = ptr_opt.unwrap();
                ptrs.push(ptr.clone());

                let update_res = Trie::update_root_hash(&mut f, &c);
                assert!(update_res.is_ok());

                // we must be able to query it now
                let leaf_opt_res = MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap(),
                );
                assert!(leaf_opt_res.is_ok());

                let leaf_opt = leaf_opt_res.unwrap();
                assert!(leaf_opt.is_some());

                let leaf = leaf_opt.unwrap();
                assert_eq!(
                    leaf,
                    TrieLeaf::new(&path[i + 1..].to_vec(), &[i as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path, &[i as u8; 40].to_vec());
            }

            // look up each leaf we inserted
            for i in 0..32 {
                let mut path = vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[i] = 32;

                let leaf_opt_res = MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap(),
                );
                assert!(leaf_opt_res.is_ok());

                let leaf_opt = leaf_opt_res.unwrap();
                assert!(leaf_opt.is_some());

                let leaf = leaf_opt.unwrap();
                assert_eq!(
                    leaf,
                    TrieLeaf::new(&path[i + 1..].to_vec(), &[i as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path, &[i as u8; 40].to_vec());
            }

            // each ptr must be a node with two children
            for i in 0..32 {
                let ptr = &ptrs[i];
                let (node, hash) = f.read_nodetype(ptr).unwrap();
                match node {
                    TrieNodeType::Node4(ref data) => assert_eq!(count_children(&data.ptrs), 2),
                    TrieNodeType::Node16(ref data) => assert_eq!(count_children(&data.ptrs), 2),
                    TrieNodeType::Node48(ref data) => assert_eq!(count_children(&data.ptrs), 2),
                    TrieNodeType::Node256(ref data) => assert_eq!(count_children(&data.ptrs), 2),
                    _ => assert!(false),
                };
            }

            dump_trie(&mut f);
        }
    }

    #[test]
    fn trie_cursor_promote_leaf_to_node4() {
        let mut f_store = TrieFileStorage::new_memory().unwrap();
        let mut f = f_store.transaction().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();

        // used to short-circuit block-height lookups, so that we don't
        //   mess up these tests expected trie structures.
        f.test_genesis_block.replace(block_header.clone());

        let (node, root_hash) = Trie::read_root(&mut f).unwrap();

        // add a single leaf
        let mut c = TrieCursor::new(
            &TriePath::from_bytes(&[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ])
            .unwrap(),
            f.root_trieptr(),
        );

        let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

        f.open_block(&block_header).unwrap();
        Trie::try_attach_leaf(
            &mut f,
            &mut c,
            &mut TrieLeaf::new(&vec![], &[128; 40].to_vec()),
            &mut node,
        )
        .unwrap()
        .unwrap();
        Trie::update_root_hash(&mut f, &c).unwrap();

        assert_eq!(
            MARF::get_path(
                &mut f,
                &block_header,
                &TriePath::from_bytes(&[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31
                ])
                .unwrap()
            )
            .unwrap()
            .unwrap(),
            TrieLeaf::new(
                &vec![
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25, 26, 27, 28, 29, 30, 31
                ],
                &[128; 40].to_vec()
            )
        );

        merkle_test(
            &mut f,
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]
            .to_vec(),
            &[128; 40].to_vec(),
        );

        let mut ptrs = vec![];

        // add more leaves -- unzip this path completely
        for i in 1..32 {
            // add a leaf that would go after the prior leaf
            let mut path = vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[i] = 32;

            let mut c =
                TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

            let (nodeptr, node, node_hash) = walk_to_insertion_point(&mut f, &mut c);
            // end of path -- cursor points to the insertion point
            let mut leaf_data = match node {
                TrieNodeType::Leaf(ref data) => data.clone(),
                _ => panic!("not a leaf"),
            };

            f.open_block(&block_header).unwrap();
            let ptr = Trie::promote_leaf_to_node4(
                &mut f,
                &mut c,
                &mut leaf_data,
                &mut TrieLeaf::new(&vec![], &[(i + 128) as u8; 40].to_vec()),
            )
            .unwrap();
            ptrs.push(ptr);

            Trie::update_root_hash(&mut f, &c).unwrap();

            // make sure we can query it again
            let leaf_opt_res = MARF::get_path(
                &mut f,
                &block_header,
                &TriePath::from_bytes(&path[..]).unwrap(),
            );
            assert!(leaf_opt_res.is_ok());

            let leaf_opt = leaf_opt_res.unwrap();
            assert!(leaf_opt.is_some());

            let leaf = leaf_opt.unwrap();
            assert_eq!(
                leaf,
                TrieLeaf::new(&path[i + 1..].to_vec(), &[(i + 128) as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path, &[(i + 128) as u8; 40].to_vec());
        }

        // look up each leaf we inserted
        for i in 1..31 {
            let mut path = vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[i] = 32;

            let leaf_opt_res = MARF::get_path(
                &mut f,
                &block_header,
                &TriePath::from_bytes(&path[..]).unwrap(),
            );
            assert!(leaf_opt_res.is_ok());

            let leaf_opt = leaf_opt_res.unwrap();
            assert!(leaf_opt.is_some());

            let leaf = leaf_opt.unwrap();
            assert_eq!(
                leaf,
                TrieLeaf::new(&path[i + 1..].to_vec(), &[(i + 128) as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path, &[(i + 128) as u8; 40].to_vec());
        }

        // each ptr must be a node with two children
        for i in 0..31 {
            let ptr = &ptrs[i];
            let (node, hash) = f.read_nodetype(ptr).unwrap();
            match node {
                TrieNodeType::Node4(ref data) => assert_eq!(count_children(&data.ptrs), 2),
                TrieNodeType::Node256(ref data) => assert_eq!(count_children(&data.ptrs), 2),
                _ => assert!(false),
            };
        }

        dump_trie(&mut f);
    }

    #[test]
    fn trie_cursor_promote_node4_to_node16() {
        let mut f_store = TrieFileStorage::new_memory().unwrap();
        let mut f = f_store.transaction().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();
        // used to short-circuit block-height lookups, so that we don't
        //   mess up these tests expected trie structures.
        f.test_genesis_block.replace(block_header.clone());

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
        let (nodes, node_ptrs, hashes) =
            make_node4_path(&mut f, &path_segments, [31u8; 40].to_vec());

        let (node, root_hash) = Trie::read_root(&mut f).unwrap();

        // fill each node4
        for k in 0..31 {
            for j in 0..3 {
                let mut path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[k] = j + 32;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());
                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                f.open_block(&block_header).unwrap();
                Trie::try_attach_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[128 + j as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap()
                .unwrap();
                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[k + 1..].to_vec(), &[128 + j as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path.to_vec(), &[(j + 128) as u8; 40].to_vec());
            }
        }

        test_debug!("");
        test_debug!("");
        test_debug!("");

        let mut ptrs = vec![];

        // promote each node4 to a node16
        for k in 1..31 {
            let mut path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[k] = 128;

            let mut c =
                TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

            let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

            f.open_block(&block_header).unwrap();
            let new_ptr = Trie::insert_leaf(
                &mut f,
                &mut c,
                &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                &mut node,
            )
            .unwrap();
            ptrs.push(new_ptr);

            Trie::update_root_hash(&mut f, &c).unwrap();

            // should have inserted
            assert_eq!(
                MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap()
                )
                .unwrap()
                .unwrap(),
                TrieLeaf::new(&path[k + 1..].to_vec(), &[192 + k as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
        }

        // each ptr we got should point to a node16 with 5 children
        for ptr in ptrs.iter() {
            let (node, hash) = f.read_nodetype(ptr).unwrap();
            match node {
                TrieNodeType::Node16(ref data) => {
                    assert_eq!(count_children(&data.ptrs), 5);
                }
                _ => {
                    assert!(false);
                }
            }
        }

        dump_trie(&mut f);
    }

    #[test]
    fn trie_cursor_promote_node16_to_node48() {
        let mut f_store = TrieFileStorage::new_memory().unwrap();
        let mut f = f_store.transaction().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();
        // used to short-circuit block-height lookups, so that we don't
        //   mess up these tests expected trie structures.
        f.test_genesis_block.replace(block_header.clone());

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
        let (nodes, node_ptrs, hashes) =
            make_node4_path(&mut f, &path_segments, [31u8; 40].to_vec());

        let (node, root_hash) = Trie::read_root(&mut f).unwrap();

        // fill each node4
        for k in 0..31 {
            for j in 0..3 {
                let mut path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[k] = j + 32;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                f.open_block(&block_header).unwrap();
                Trie::try_attach_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[128 + j as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap()
                .unwrap();

                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[k + 1..].to_vec(), &[128 + j as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path.to_vec(), &[(j + 128) as u8; 40].to_vec());
            }
        }

        test_debug!("");
        test_debug!("promote all node4 to node16");
        test_debug!("");

        let mut ptrs = vec![];

        // promote each node4 to a node16 by inserting one more leaf
        for k in 1..31 {
            let mut path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[k] = 128;

            let mut c =
                TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

            let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

            f.open_block(&block_header).unwrap();
            let new_ptr = Trie::insert_leaf(
                &mut f,
                &mut c,
                &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                &mut node,
            )
            .unwrap();
            ptrs.push(new_ptr);

            Trie::update_root_hash(&mut f, &c).unwrap();

            // should have inserted
            assert_eq!(
                MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap()
                )
                .unwrap()
                .unwrap(),
                TrieLeaf::new(&path[k + 1..].to_vec(), &[192 + k as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
        }

        // each ptr we got should point to a node16 with 5 children
        for ptr in ptrs.iter() {
            let (node, hash) = f.read_nodetype(ptr).unwrap();
            match node {
                TrieNodeType::Node16(ref data) => {
                    assert_eq!(count_children(&data.ptrs), 5);
                }
                _ => {
                    assert!(false);
                }
            }
        }

        // fill each node16 with leaves
        for k in 0..31 {
            for j in 0..11 {
                let mut path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[k] = j + 40;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                f.open_block(&block_header).unwrap();
                Trie::try_attach_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[128 + j as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap()
                .unwrap();

                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[k + 1..].to_vec(), &[128 + j as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path.to_vec(), &[(j + 128) as u8; 40].to_vec());
            }
        }

        test_debug!("");
        test_debug!("promote all node16 to node48");
        test_debug!("");

        ptrs.clear();

        // promote each node16 to a node48 by inserting one more leaf
        for k in 1..31 {
            let mut path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[k] = 129;

            let mut c =
                TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

            let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

            f.open_block(&block_header).unwrap();

            let new_ptr = Trie::insert_leaf(
                &mut f,
                &mut c,
                &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                &mut node,
            )
            .unwrap();
            ptrs.push(new_ptr);

            Trie::update_root_hash(&mut f, &c).unwrap();

            // should have inserted
            assert_eq!(
                MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap()
                )
                .unwrap()
                .unwrap(),
                TrieLeaf::new(&path[k + 1..].to_vec(), &[192 + k as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
        }

        // each ptr we got should point to a node48 with 17 children
        for ptr in ptrs.iter() {
            let (node, hash) = f.read_nodetype(ptr).unwrap();
            match node {
                TrieNodeType::Node48(ref data) => {
                    assert_eq!(count_children(&data.ptrs), 17);
                }
                _ => {
                    assert!(false);
                }
            }
        }

        dump_trie(&mut f);
    }

    #[test]
    fn trie_cursor_promote_node48_to_node256() {
        let mut f_store = TrieFileStorage::new_memory().unwrap();
        let mut f = f_store.transaction().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();
        // used to short-circuit block-height lookups, so that we don't
        //   mess up these tests expected trie structures.
        f.test_genesis_block.replace(block_header.clone());

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
        let (nodes, node_ptrs, hashes) =
            make_node4_path(&mut f, &path_segments, [31u8; 40].to_vec());

        let (node, root_hash) = Trie::read_root(&mut f).unwrap();

        // fill each node4
        for k in 0..31 {
            for j in 0..3 {
                let mut path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[k] = j + 32;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                f.open_block(&block_header).unwrap();
                Trie::try_attach_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[128 + j as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap()
                .unwrap();

                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[k + 1..].to_vec(), &[128 + j as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path.to_vec(), &[(j + 128) as u8; 40].to_vec());
            }
        }

        test_debug!("");
        test_debug!("promote all node4 to node16");
        test_debug!("");

        let mut ptrs = vec![];

        // promote each node4 to a node16 by inserting one more leaf
        for k in 1..31 {
            let mut path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[k] = 128;

            let mut c =
                TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

            let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

            f.open_block(&block_header).unwrap();
            let new_ptr = Trie::insert_leaf(
                &mut f,
                &mut c,
                &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                &mut node,
            )
            .unwrap();
            ptrs.push(new_ptr);

            Trie::update_root_hash(&mut f, &c).unwrap();

            // should have inserted
            assert_eq!(
                MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap()
                )
                .unwrap()
                .unwrap(),
                TrieLeaf::new(&path[k + 1..].to_vec(), &[192 + k as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
        }

        // each ptr we got should point to a node16 with 5 children
        for ptr in ptrs.iter() {
            let (node, hash) = f.read_nodetype(ptr).unwrap();
            match node {
                TrieNodeType::Node16(ref data) => {
                    assert_eq!(count_children(&data.ptrs), 5);
                }
                _ => {
                    assert!(false);
                }
            }
        }

        // fill each node16 with leaves
        for k in 0..31 {
            for j in 0..11 {
                let mut path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[k] = j + 40;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                f.open_block(&block_header).unwrap();
                Trie::try_attach_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[128 + j as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap()
                .unwrap();
                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[k + 1..].to_vec(), &[128 + j as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path.to_vec(), &[(j + 128) as u8; 40].to_vec());
            }
        }

        test_debug!("");
        test_debug!("promote all node16 to node48");
        test_debug!("");

        ptrs.clear();

        // promote each node16 to a node48 by inserting one more leaf
        for k in 1..31 {
            let mut path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[k] = 129;

            let mut c =
                TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

            let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

            f.open_block(&block_header).unwrap();
            let new_ptr = Trie::insert_leaf(
                &mut f,
                &mut c,
                &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                &mut node,
            )
            .unwrap();
            ptrs.push(new_ptr);

            Trie::update_root_hash(&mut f, &c).unwrap();

            // should have inserted
            assert_eq!(
                MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap()
                )
                .unwrap()
                .unwrap(),
                TrieLeaf::new(&path[k + 1..].to_vec(), &[192 + k as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
        }

        // each ptr we got should point to a node48 with 17 children
        for ptr in ptrs.iter() {
            let (node, hash) = f.read_nodetype(ptr).unwrap();
            match node {
                TrieNodeType::Node48(ref data) => {
                    assert_eq!(count_children(&data.ptrs), 17);
                }
                _ => {
                    assert!(false);
                }
            }
        }

        // fill each node48 with leaves
        for k in 0..31 {
            for j in 0..31 {
                let mut path = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[k] = j + 90;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                f.open_block(&block_header).unwrap();
                Trie::try_attach_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[128 + j as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap()
                .unwrap();

                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[k + 1..].to_vec(), &[128 + j as u8; 40].to_vec())
                );

                merkle_test(&mut f, &path.to_vec(), &[(j + 128) as u8; 40].to_vec());
            }
        }

        test_debug!("");
        test_debug!("promote all node48 to node256");
        test_debug!("");

        ptrs.clear();

        // promote each node48 to a node256 by inserting one more leaf
        for k in 1..31 {
            let mut path = [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];
            path[k] = 130;

            let mut c =
                TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

            let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

            f.open_block(&block_header).unwrap();
            let new_ptr = Trie::insert_leaf(
                &mut f,
                &mut c,
                &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                &mut node,
            )
            .unwrap();
            ptrs.push(new_ptr);

            Trie::update_root_hash(&mut f, &c).unwrap();

            // should have inserted
            assert_eq!(
                MARF::get_path(
                    &mut f,
                    &block_header,
                    &TriePath::from_bytes(&path[..]).unwrap()
                )
                .unwrap()
                .unwrap(),
                TrieLeaf::new(&path[k + 1..].to_vec(), &[192 + k as u8; 40].to_vec())
            );

            merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
        }

        // each ptr we got should point to a node256 with 49 children
        for ptr in ptrs.iter() {
            let (node, hash) = f.read_nodetype(ptr).unwrap();
            match node {
                TrieNodeType::Node256(ref data) => {
                    assert_eq!(count_children(&data.ptrs), 49);
                }
                _ => {
                    assert!(false);
                }
            }
        }

        dump_trie(&mut f);
    }

    #[test]
    fn trie_cursor_splice_leaf_4() {
        for node_id in [
            TrieNodeID::Node4,
            TrieNodeID::Node16,
            TrieNodeID::Node48,
            TrieNodeID::Node256,
        ]
        .iter()
        {
            let mut f_store = TrieFileStorage::new_memory().unwrap();
            let mut f = f_store.transaction().unwrap();

            let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
            MARF::format(&mut f, &block_header).unwrap();

            // used to short-circuit block-height lookups, so that we don't
            //   mess up these tests expected trie structures.
            f.test_genesis_block.replace(block_header.clone());

            let path_segments = vec![
                (vec![0, 1, 2, 3], 4),
                (vec![5, 6, 7, 8], 9),
                (vec![10, 11, 12, 13], 14),
                (vec![15, 16, 17, 18], 19),
                (vec![20, 21, 22, 23], 24),
                (vec![25, 26, 27, 28], 29),
                (vec![30], 31),
            ];

            let (nodes, node_ptrs, hashes) =
                make_node_path(&mut f, node_id.to_u8(), &path_segments, [31u8; 40].to_vec());

            let mut ptrs = vec![];

            // splice in a node in each path segment
            for k in 0..5 {
                let mut path = vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[5 * k + 2] = 32;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

                test_debug!("Start splice-insert at {:?}", &c);
                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                test_debug!("Splice leaf pattern={} at {:?}", 192 + k, &c);
                f.open_block(&block_header).unwrap();

                eprintln!("Splicing Node @ {}", nodeptr.ptr());
                eprintln!("Splicing Node @ {:x}", c.chr().unwrap());

                let new_ptr = Trie::splice_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap();
                ptrs.push(new_ptr);

                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[5 * k + 3..].to_vec(), &[192 + k as u8; 40].to_vec())
                );
                merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
            }

            dump_trie(&mut f);
        }
    }

    #[test]
    fn trie_cursor_splice_leaf_2() {
        for node_id in [
            TrieNodeID::Node4,
            TrieNodeID::Node16,
            TrieNodeID::Node48,
            TrieNodeID::Node256,
        ]
        .iter()
        {
            let mut f_store = TrieFileStorage::new_memory().unwrap();
            let mut f = f_store.transaction().unwrap();

            let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
            MARF::format(&mut f, &block_header).unwrap();

            // used to short-circuit block-height lookups, so that we don't
            //   mess up these tests expected trie structures.
            f.test_genesis_block.replace(block_header.clone());

            let path_segments = vec![
                (vec![0, 1], 2),
                (vec![3, 4], 5),
                (vec![6, 7], 8),
                (vec![9, 10], 11),
                (vec![12, 13], 14),
                (vec![15, 16], 17),
                (vec![18, 19], 20),
                (vec![21, 22], 23),
                (vec![24, 25], 26),
                (vec![27, 28], 29),
                (vec![30], 31),
            ];

            let (nodes, node_ptrs, hashes) =
                make_node_path(&mut f, node_id.to_u8(), &path_segments, [31u8; 40].to_vec());
            let mut ptrs = vec![];

            // splice in a node in each path segment
            for k in 0..10 {
                let mut path = vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                path[3 * k + 1] = 32;

                let mut c =
                    TrieCursor::new(&TriePath::from_bytes(&path[..]).unwrap(), f.root_trieptr());

                test_debug!("Start splice-insert at {:?}", &c);
                let (nodeptr, mut node, node_hash) = walk_to_insertion_point(&mut f, &mut c);

                test_debug!("Splice leaf pattern={} at {:?}", 192 + k, &c);
                f.open_block(&block_header).unwrap();
                let new_ptr = Trie::splice_leaf(
                    &mut f,
                    &mut c,
                    &mut TrieLeaf::new(&vec![], &[192 + k as u8; 40].to_vec()),
                    &mut node,
                )
                .unwrap();
                ptrs.push(new_ptr);

                Trie::update_root_hash(&mut f, &c).unwrap();

                // should have inserted
                assert_eq!(
                    MARF::get_path(
                        &mut f,
                        &block_header,
                        &TriePath::from_bytes(&path[..]).unwrap()
                    )
                    .unwrap()
                    .unwrap(),
                    TrieLeaf::new(&path[3 * k + 2..].to_vec(), &[192 + k as u8; 40].to_vec())
                );

                // proofs should still work
                merkle_test(&mut f, &path.to_vec(), &[(k + 192) as u8; 40].to_vec());
            }

            dump_trie(&mut f);
        }
    }

    fn insert_n_test<F>(filename: &str, merkle_check: bool, count: u32, mut path_gen: F)
    where
        F: FnMut(u32) -> [u8; 32],
    {
        let f = TrieFileStorage::new_memory().unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        let mut marf = MARF::from_storage(f);
        marf.begin(&BlockHeaderHash::sentinel(), &block_header)
            .unwrap();
        MARF::get_block_height(
            &mut marf.borrow_storage_backend(),
            &block_header,
            &block_header,
        )
        .unwrap()
        .unwrap();

        for i in 0..count {
            eprintln!("{}", i);
            let path = path_gen(i);
            let triepath = TriePath::from_bytes(&path).unwrap();
            let value = TrieLeaf::new(
                &vec![],
                &[
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
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (i / 256) as u8,
                    (i % 256) as u8,
                ]
                .to_vec(),
            );
            marf.insert_raw(triepath, value).unwrap();

            if merkle_check {
                merkle_test(
                    &mut marf.borrow_storage_backend(),
                    &path.to_vec(),
                    &[
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
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (i / 256) as u8,
                        (i % 256) as u8,
                    ]
                    .to_vec(),
                );
            }
        }

        for i in 0..count {
            let path = path_gen(i);
            let triepath = TriePath::from_bytes(&path).unwrap();
            let value =
                MARF::get_path(&mut marf.borrow_storage_backend(), &block_header, &triepath)
                    .unwrap()
                    .unwrap();
            assert_eq!(
                value.data.to_vec(),
                [
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
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (i / 256) as u8,
                    (i % 256) as u8
                ]
                .to_vec()
            );
            if merkle_check {
                merkle_test(
                    &mut marf.borrow_storage_backend(),
                    &path.to_vec(),
                    &[
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
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (i / 256) as u8,
                        (i % 256) as u8,
                    ]
                    .to_vec(),
                );
            }
        }
    }

    #[test]
    fn insert_1024_seq_low() {
        insert_n_test("/tmp/rust_marf_insert_1024_seq_low", true, 1024, |i| {
            [
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
            ]
        })
    }

    #[test]
    fn insert_1024_seq_high() {
        insert_n_test("/tmp/rust_marf_insert_1024_seq_high", true, 1024, |i| {
            [
                (i / 256) as u8,
                (i % 256) as u8,
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
                30,
                31,
            ]
        })
    }

    #[test]
    fn insert_1024_seq_mid() {
        insert_n_test("/tmp/rust_marf_insert_1024_seq_mid", true, 1024, |i| {
            let i0 = i / 256;
            let i1 = (i % 256) / 32;
            let i2 = (i % 256) % 32;
            let i3 = (i % 256) % 16;
            [
                0, 1, i0 as u8, i1 as u8, i2 as u8, i3 as u8, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]
        })
    }

    #[test]
    #[ignore]
    fn insert_65536_random_deterministic() {
        // deterministic random insert of 65536 keys
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();

        insert_n_test(
            "/tmp/rust_marf_insert_65536_random_deterministic",
            false,
            65536,
            |i| {
                let mut path = [0; 32];
                path.copy_from_slice(
                    &TrieHash::from_data(if i == 0 { &[] } else { seed.as_slice() }).as_bytes()
                        [0..32],
                );
                seed = path.to_vec();
                eprintln!("{}", to_hex(&path));
                path
            },
        )
    }

    #[test]
    fn insert_1024_random_deterministic_merkle_proof() {
        // deterministic random insert of 1024 keys
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();

        insert_n_test(
            "/tmp/rust_marf_insert_1024_random_deterministic_merkle_proof",
            true,
            1024,
            |i| {
                let mut path = [0; 32];
                path.copy_from_slice(
                    &TrieHash::from_data(if i == 0 { &[] } else { seed.as_slice() }).as_bytes()
                        [0..32],
                );
                seed = path.to_vec();
                eprintln!("{}", to_hex(&path));
                path
            },
        )
    }
}
