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

use sha2::Digest;

use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::index::bits::{
    get_node_hash,
    get_node_hash_bytes
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
    TriePath,
    is_backptr,
    set_backptr,
    clear_backptr
};

use chainstate::stacks::index::storage::{
    read_all,
    write_all,
    fseek,
    fseek_end,
    TrieStorage
};

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
    fast_extend_from_slice,
};

use chainstate::stacks::index::trie::{
    Trie,
};

use chainstate::stacks::index::Error as Error;

use util::log;
use util::macros::set_trace;


/// Merklized Adaptive-Radix Forest -- a collection of Merklized Adaptive-Radix Tries.
/// We don't ever directly instantiate one, but we parameterize its methods with a storage
/// implementation.
pub struct MARF<S>
where
    S: TrieStorage + Seek
{
    _phantom: PhantomData<S>
}

impl<S> MARF<S>
where
    S: TrieStorage + Seek
{

    // helper method for walking a node's backpr
    fn walk_backptr(s: &mut S, start_node: &TrieNodeType, chr: u8, c: &mut TrieCursor) -> Result<(TrieNodeType, TrieHash, TriePtr, u32), Error> {
        let ptr_opt = match start_node {
            TrieNodeType::Node4(ref data) => data.walk(chr),
            TrieNodeType::Node16(ref data) => data.walk(chr),
            TrieNodeType::Node48(ref data) => data.walk(chr),
            TrieNodeType::Node256(ref data) => data.walk(chr),
            _ => {
                panic!("Did not get an intermediate node");
            }
        };
        match ptr_opt {
            None => {
                // this node never had a child for this chr
                trace!("Failed to walk to '{}' from {:?}", chr, start_node);
                Err(Error::BackptrNotFoundError)
            },
            Some(ptr) => {
                trace!("Walk backptrs for {:?} to {:?} from {:?}", c, &ptr, &start_node);
                
                // this node had a child for this chr at one point
                let (node, node_hash, node_ptr) = match start_node {
                    TrieNodeType::Node4(_) => Trie::walk_backptr(s, &ptr, c)?,
                    TrieNodeType::Node16(_) => Trie::walk_backptr(s, &ptr, c)?,
                    TrieNodeType::Node48(_) => Trie::walk_backptr(s, &ptr, c)?,
                    TrieNodeType::Node256(_) => Trie::walk_backptr(s, &ptr, c)?,
                    _ => {
                        unreachable!();
                    }
                };

                Ok((node, node_hash, node_ptr, ptr.back_block))
            }
        }
    }
   
    fn node_copy_update(_s: &mut S, node: &mut TrieNodeType, node_dist: u32) -> Result<TrieHash, Error> {
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

        let hash = match node {
            TrieNodeType::Node4(ref mut data) => {
                node_copy_update_ptrs(&mut data.ptrs, node_dist);
                TrieHash::from_data(&[])
            },
            TrieNodeType::Node16(ref mut data) => {
                node_copy_update_ptrs(&mut data.ptrs, node_dist);
                TrieHash::from_data(&[])
            },
            TrieNodeType::Node48(ref mut data) => {
                node_copy_update_ptrs(&mut data.ptrs, node_dist);
                TrieHash::from_data(&[])
            },
            TrieNodeType::Node256(ref mut data) => {
                node_copy_update_ptrs(&mut data.ptrs, node_dist);
                TrieHash::from_data(&[])
            },
            TrieNodeType::Leaf(ref mut data) => {
                get_node_hash_bytes(data, &vec![])
            },
        };
        Ok(hash)
    }
    
    /// Given a node, and the chr of one of its children, go find the last instance of that child in
    /// the MARF and copy it forward.  Update its ptrs to point to its descendents.
    /// s must point to the block hash in which this node lives, to which the child will be copied.
    fn node_child_copy(s: &mut S, node: &TrieNodeType, chr: u8, c: &mut TrieCursor) -> Result<(TrieNodeType, TrieHash, TriePtr, BlockHeaderHash), Error> {
        trace!("Copy to {:?} child {:x} of {:?}", s.tell(), chr, node);

        let cur_block_hash = s.tell();
        let (mut child_node, _, child_ptr, child_dist) = MARF::walk_backptr(s, node, chr, c)?;
        let child_block_hash = s.tell();

        // update child_node with new ptrs and hashes
        s.open(&cur_block_hash, true)?;
        let child_hash = MARF::node_copy_update(s, &mut child_node, child_dist)?;

        // store it in this trie
        s.open(&cur_block_hash, true)?;
        let child_disk_ptr = fseek_end(s)?;
        let child_ptr = TriePtr::new(child_ptr.id(), chr, child_disk_ptr as u32);
        s.write_node(&child_node, child_hash.clone())?;

        trace!("Copied child 0x{:02x} to {:?}: ptr={:?} child={:?}", chr, &cur_block_hash, &child_ptr, &child_node);
        Ok((child_node, child_hash, child_ptr, child_block_hash))
    }

    /// Copy the root node from the previous Trie to this Trie, updating its ptrs.
    /// s must point to the target Trie
    fn root_copy(s: &mut S, prev_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        let cur_block_hash = s.tell();
        s.open(prev_block_hash, false)?;
        
        let (mut prev_root, _) = Trie::read_root(s)?;
        let new_root_hash = MARF::node_copy_update(s, &mut prev_root, 1)?;
        
        s.open(&cur_block_hash, true)?;
        let root_ptr = s.root_ptr();
        fseek(s, root_ptr)?;

        s.write_node(&prev_root, new_root_hash)?;
        Ok(())
    }
    
    /// create or open a particular Trie.
    /// If the trie doesn't exist, then extend it from the current Trie and create a root node that
    /// has back pointers to its immediate children in the current trie.
    /// On Ok, s will point to new_bhh and will be open for reading
    pub fn extend_trie(s: &mut S, new_bhh: &BlockHeaderHash) -> Result<(), Error> {
        let cur_bhh = s.tell();
        if s.num_blocks() == 0 {
            // brand new storage
            s.extend(new_bhh)?;
            let node = TrieNode256::new(&vec![]);
            let hash = get_node_hash(&node, &vec![]);
            s.write_node(&TrieNodeType::Node256(node), hash)
        }
        else {
            // existing storage
            match s.open(new_bhh, true) {
                Ok(_) => {
                    trace!("Switch to Trie {:?}", new_bhh);
                    Ok(())
                }
                Err(e) => {
                    match e {
                        Error::NotFoundError => {
                            // bring root forward
                            s.open(&cur_bhh, true)?;
                            s.extend(new_bhh)?;
                            MARF::root_copy(s, &cur_bhh)?;
                            s.open(new_bhh, false)?;
                            let root_ptr = s.root_ptr();
                            fseek(s, root_ptr)?;
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
    fn walk_cow(s: &mut S, block_hash: &BlockHeaderHash, k: &TriePath) -> Result<TrieCursor, Error> {
        MARF::extend_trie(s, block_hash)?;

        let root_ptr = s.root_ptr();
        let mut c = TrieCursor::new(k, root_ptr);

        // walk to insertion point 
        let (mut node, _) = Trie::read_root(s)?;
        let mut node_ptr = TriePtr::new(0,0,0);

        for _ in 0..(c.path.len()+1) {
            let next_opt = Trie::walk_from(s, &node, &mut c)?;
            match next_opt {
                Some((next_node_ptr, next_node, _)) => {
                    // keep walking
                    node = next_node;
                    node_ptr = next_node_ptr;
                    continue;
                },
                None => {
                    if c.div() {
                        // we're done -- path diverged.  No node-copying can help us.
                        trace!("Path diverged -- we're done.");
                        s.open(block_hash, true)?;
                        fseek(s, node_ptr.ptr() as u64)?;
                        return Ok(c);
                    }
                    else if c.eop() {
                        // we're done
                        trace!("Out of path in {:?} -- we're done. Seek to {:?}", s.tell(), &node_ptr);
                        s.open(block_hash, true)?;
                        fseek(s, node_ptr.ptr() as u64)?;
                        return Ok(c);
                    }
                    else {
                        // we're not done with this path.  Either no node exists, or it exists off
                        // of a prior version of the last-visited node.
                        let chr = c.chr().unwrap();     // guaranteed to succeed since we walked some path.
                        match node {
                            TrieNodeType::Leaf(_) => {
                                // at an existing leaf with a different path.
                                // we're done.
                                trace!("Existing leaf with different path encountered at {:?} at {:?} -- we're done (not found)", &node_ptr, s.tell());
                                s.open(block_hash, true)?;
                                fseek_end(s)?;
                                return Ok(c);
                            },
                            _ => {}
                        };

                        // at intermediate node whose child is not present in this trie.
                        // bring the child forward and take the step, if possible.
                        s.open(block_hash, true)?;
                        let (next_node, _, next_node_ptr, next_node_block_hash) = match MARF::node_child_copy(s, &node, chr, &mut c) {
                            Ok(res) => {
                                res
                            }
                            Err(e) => {
                                match e {
                                    Error::BackptrNotFoundError => {
                                        // no prior version of this node has a ptr for this chr.
                                        // we're done -- target node not found.
                                        trace!("BackptrNotFoundError encountered at {:?} -- we're done (not found)", s.tell());
                                        s.open(block_hash, true)?;
                                        fseek_end(s)?;
                                        return Ok(c);
                                    },
                                    _ => {
                                        return Err(e);
                                    }
                                }
                            }
                        };

                        // finish taking the step
                        c.walk_backptr_finish(&next_node_ptr, &next_node_block_hash);
                        
                        node = next_node;
                        node_ptr = next_node_ptr;
                        
                        s.open(block_hash, true)?;
                    }
                }
            }
        }

        trace!("Trie has a cycle");
        return Err(Error::CorruptionError("Trie has a cycle".to_string()));
    }


    /// Walk down this MARF at the given block hash, resolving backptrs to previous tries.
    /// Return the cursor and the last node visited
    fn walk(s: &mut S, block_hash: &BlockHeaderHash, k: &TriePath) -> Result<(TrieCursor, TrieNodeType), Error> {
        s.open(block_hash, false)?;

        let root_ptr = s.root_ptr();
        let mut c = TrieCursor::new(k, root_ptr);

        // walk to insertion point 
        let (mut node, _) = Trie::read_root(s)?;
        let mut node_ptr = TriePtr::new(0,0,0);

        for _ in 0..(c.path.len()+1) {
            let next_opt = Trie::walk_from(s, &node, &mut c)?;
            match next_opt {
                Some((next_node_ptr, next_node, _)) => {
                    // keep walking
                    node = next_node;
                    node_ptr = next_node_ptr;
                    continue;
                },
                None => {
                    if c.div() {
                        // we're done -- path diverged.  No backptr-walking can help us.
                        trace!("Path diverged -- we're done.");
                        return Err(Error::NotFoundError);
                    }
                    else {
                        // we're not done with this path.  Either no node exists, or it exists off
                        // of a prior version of the last-visited node.
                        let chr = c.chr().unwrap();     // guaranteed to succeed since we walked some path.
                        let found_leaf = match node {
                            TrieNodeType::Leaf(_) => {
                                if !c.eop() {
                                    // at an existing leaf with a different path.
                                    // we're done.
                                    trace!("Existing but different leaf encountered at {:?} at {:?} -- we're done", &node_ptr, s.tell());
                                    return Err(Error::NotFoundError);
                                }
                                else {
                                    // we're done -- we found the leaf
                                    true
                                }
                            },
                            _ => {
                                false
                            }
                        };

                        if found_leaf {
                            return Ok((c, node));
                        }

                        // cursor grabbed a copy of node, but not yet a ptr.
                        // at intermediate node whose child is not present in this trie.
                        // try to shunt to the prior node that has the child itself.
                        let (next_node, _, next_node_ptr, _) = MARF::walk_backptr(s, &node, chr, &mut c)?;
                       
                        // finish taking the step
                        c.walk_backptr_finish(&next_node_ptr, &s.tell());

                        // keep going
                        node = next_node;
                        node_ptr = next_node_ptr;
                    }
                }
            }
        }
        
        trace!("Trie has a cycle");
        return Err(Error::CorruptionError("Trie has a cycle".to_string()));
    }

    pub fn format(s: &mut S, first_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        Trie::format(s, first_block_hash)
    }

    pub fn get(s: &mut S, block_hash: &BlockHeaderHash, k: &TriePath) -> Result<Option<TrieLeaf>, Error> {
        trace!("MARF::get({:?}) {:?}", block_hash, k);
        s.open(block_hash, false)?;
        let (c, node) = MARF::walk(s, block_hash, k)?;

        if c.block_hashes.len() + 1 != c.node_ptrs.len() {
            trace!("c.block_hashes = {:?}", &c.block_hashes);
            trace!("c.node_ptrs = {:?}", c.node_ptrs);
            assert!(false);
        }

        if c.eop() {
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
        else {
            // path didn't match a node 
            trace!("MARF get: found nothing at {:?}", k);
            return Ok(None);
        }
    }

    pub fn insert(s: &mut S, block_hash: &BlockHeaderHash, k: &TriePath, v: &TrieLeaf) -> Result<(), Error> {
        let mut value = v.clone();
        let mut c = MARF::walk_cow(s, block_hash, k)?;
        
        if c.block_hashes.len() + 1 != c.node_ptrs.len() {
            trace!("c.block_hashes = {:?}", &c.block_hashes);
            trace!("c.node_ptrs = {:?}", c.node_ptrs);
            assert!(false);
        }
        
        Trie::add_value(s, &mut c, &mut value)?;
        Trie::update_root_hash(s, &c)?;
        Ok(())
    }

    // TODO: insert batch? (avoid excessive re-hashes)
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
            MARF::insert(&mut f, &block_header, &path, &value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        let value = TrieLeaf::new(&vec![], &[99; 40].to_vec());
        let leaf = MARF::get(&mut f, &block_header, &path).unwrap().unwrap();

        assert_eq!(leaf.reserved.to_vec(), [99; 40].to_vec());
        assert_eq!(f.tell(), block_header);

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
            MARF::insert(&mut f, &block_header, &path, &value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..100 {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let path_bytes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,i as u8];
            let path = TriePath::from_bytes(&path_bytes).unwrap();

            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get(&mut f, &block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.reserved.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.tell(), block_header);

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
            MARF::insert(&mut f, &next_block_header, &path, &value).unwrap();
        }
        
        test_debug!("---------");
        test_debug!("MARF gets");
        test_debug!("---------");

        for i in 0..100 {
            let next_block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            let value = TrieLeaf::new(&vec![], &[i as u8; 40].to_vec());
            let leaf = MARF::get(&mut f, &next_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.reserved.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.tell(), next_block_header);

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
            MARF::insert(&mut f, &next_block_header, &path, &value).unwrap();
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
            let leaf = MARF::get(&mut f, &last_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.reserved.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.tell(), next_block_header);

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
            MARF::insert(&mut f, &next_block_header, &path, &value).unwrap();
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
            let leaf = MARF::get(&mut f, &last_block_header, &path).unwrap().unwrap();

            assert_eq!(leaf.reserved.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(f.tell(), next_block_header);

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
            MARF::insert(&mut f, &next_block_header, &triepath, &value).unwrap();

            // verify that this leaf exists in _this_ Trie
            test_debug!("----------------");
            test_debug!("get");
            test_debug!("----------------");
            let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(read_value.path, next_path[i+1..].to_vec());
            assert_eq!(f.tell(), next_block_header);

            // can get all previous leaves from _this_ Trie
            for j in 1..(i+1) {
                test_debug!("----------------");
                test_debug!("get-prev {} of {}", j, i);
                test_debug!("----------------");

                let mut prev_path = path.clone();
                prev_path[j] = 32;
            
                let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.reserved.to_vec(), [j as u8; 40].to_vec());
                assert_eq!(f.tell(), prev_block_header);
            }

            f.open(&next_block_header, false).unwrap();

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

            assert_eq!(MARF::get(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
            
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
            MARF::insert(&mut f, &next_block_header, &triepath, &value).unwrap();

            // verify that this leaf exists in _this_ Trie
            test_debug!("----------------");
            test_debug!("get");
            test_debug!("----------------");
            let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), [i as u8; 40].to_vec());
            assert_eq!(read_value.path, next_path[31-i+1..].to_vec());
            assert_eq!(f.tell(), next_block_header);

            // can get all previous leaves from _this_ Trie
            for j in 1..(i+1) {
                test_debug!("----------------");
                test_debug!("get-prev {} of {}", j, i);
                test_debug!("----------------");

                let mut prev_path = path.clone();
                prev_path[31-j] = 32;
            
                let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.reserved.to_vec(), [j as u8; 40].to_vec());
                assert_eq!(f.tell(), prev_block_header);
            }

            f.open(&next_block_header, false).unwrap();

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

            assert_eq!(MARF::get(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
            
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
                MARF::insert(&mut f, &next_block_header, &triepath, &value).unwrap();

                // verify that this leaf exists in _this_ Trie
                test_debug!("----------------");
                test_debug!("get");
                test_debug!("----------------");
                let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.reserved.to_vec(), [i as u8; 40].to_vec());
                assert_eq!(read_value.path, next_path[i+1..].to_vec());
                assert_eq!(f.tell(), next_block_header);

                // can get all previous leaves from _this_ Trie
                for j in 1..(i+1) {
                    test_debug!("----------------");
                    test_debug!("get-prev {} of {}", j, i);
                    test_debug!("----------------");

                    let mut prev_path = path.clone();
                    prev_path[j] = 32;
                
                    let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                    let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                    assert_eq!(read_value.reserved.to_vec(), [j as u8; 40].to_vec());
                    assert_eq!(f.tell(), prev_block_header);
                
                    test_debug!("---------------------------------------");
                    test_debug!("MARF verify {:?} {:?} from current block header {:?}", &prev_path, &[j as u8; 40].to_vec(), &next_block_header);
                    test_debug!("----------------------------------------");
                    merkle_test_marf(&mut f, &next_block_header, &prev_path, &[j as u8; 40].to_vec());
                }

                f.open(&next_block_header, false).unwrap();
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

                assert_eq!(MARF::get(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
                
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

            MARF::insert(&mut f, &block_header_2, &TriePath::from_bytes(&path_2[..]).unwrap(), &TrieLeaf::new(&vec![], &[20 as u8; 40].to_vec())).unwrap();
            
            let block_header_3 = BlockHeaderHash::from_bytes(&[2u8; 32]).unwrap();
            let path_3 = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,33];
            
            test_debug!("----------------");
            test_debug!("Extend to {:?}", block_header_3);
            test_debug!("----------------");

            MARF::insert(&mut f, &block_header_3, &TriePath::from_bytes(&path_3[..]).unwrap(), &TrieLeaf::new(&vec![], &[21 as u8; 40].to_vec())).unwrap();

            test_debug!("----------------");
            test_debug!("MARF at {:?}", &block_header_1);
            test_debug!("----------------");
            f.open(&block_header_1, false).unwrap();
            dump_trie(&mut f);

            test_debug!("----------------");
            test_debug!("MARF at {:?}", &block_header_2);
            test_debug!("----------------");
            f.open(&block_header_2, false).unwrap();
            dump_trie(&mut f);


            test_debug!("----------------");
            test_debug!("MARF at {:?}", &block_header_3);
            test_debug!("----------------");
            f.open(&block_header_3, false).unwrap();
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
                MARF::insert(&mut f, &next_block_header, &triepath, &value).unwrap();

                // verify that this leaf exists in _this_ Trie
                test_debug!("----------------");
                test_debug!("get");
                test_debug!("----------------");
                let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&next_path[..]).unwrap()).unwrap().unwrap();
                assert_eq!(read_value.reserved.to_vec(), [i as u8; 40].to_vec());
                assert_eq!(read_value.path, next_path[31-i+1..].to_vec());
                assert_eq!(f.tell(), next_block_header);

                // can get all previous leaves from _this_ Trie
                for j in 1..(i+1) {
                    test_debug!("----------------");
                    test_debug!("get-prev {} of {}", j, i);
                    test_debug!("----------------");

                    let mut prev_path = path.clone();
                    prev_path[31-j] = 32;
                
                    let prev_block_header = BlockHeaderHash::from_bytes(&[j as u8; 32]).unwrap();

                    let read_value = MARF::get(&mut f, &next_block_header, &TriePath::from_bytes(&prev_path[..]).unwrap()).unwrap().unwrap();
                    assert_eq!(read_value.reserved.to_vec(), [j as u8; 40].to_vec());
                    assert_eq!(f.tell(), prev_block_header);
                }

                f.open(&next_block_header, false).unwrap();

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

                assert_eq!(MARF::get(&mut f, &last_block_header, &triepath).unwrap(), Some(value));
                
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

            MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();
             
            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            assert_eq!(f.tell(), block_header);
        }

        for i in 0..4096 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,i0 as u8, i1 as u8];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
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

            MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();
             
            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            assert_eq!(f.tell(), block_header);
        }

        for i in 0..4096 {
            // can read them all back
            let i0 = i / 256;
            let i1 = i % 256;
            let path = [i0 as u8, i1 as u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8].to_vec());

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
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

        MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();

        // insert a leaf along the same path but in a different block
        let block_header_2 = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap();
        let path_2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
        let triepath_2 = TriePath::from_bytes(&path_2[..]).unwrap(); 
        let value_2 = TrieLeaf::new(&vec![], &[1u8; 40].to_vec());
    
        test_debug!("----------------");
        test_debug!("insert ({:?}, {:?}) in {:?}", &triepath_2, &value_2, &block_header_2);
        test_debug!("----------------");

        MARF::insert(&mut f, &block_header_2, &triepath_2, &value_2).unwrap();

        test_debug!("----------------");
        test_debug!("get ({:?}, {:?}) in {:?}", &triepath, &value, &block_header_2);
        test_debug!("----------------");

        let read_value = MARF::get(&mut f, &block_header_2, &triepath).unwrap().unwrap();
        assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
        
        test_debug!("----------------");
        test_debug!("get ({:?}, {:?}) in {:?}", &triepath_2, &value_2, &block_header_2);
        test_debug!("----------------");

        let read_value_2 = MARF::get(&mut f, &block_header_2, &triepath_2).unwrap().unwrap();
        assert_eq!(read_value_2.reserved.to_vec(), value_2.reserved.to_vec());
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

            MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            assert_eq!(f.tell(), block_header);

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

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            // merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
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
    
    // insert a random sequence of 1024 * 1024 keys.  Every 4096 inserts, fork.
    // Use file storage
    #[test]
    fn marf_insert_random_1048576_4096_file_storage() {
        let path = "/tmp/rust_marf_insert_random_1048576_4096".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut block_header = BlockHeaderHash::from_bytes(&[0u8; 32]).unwrap();
        MARF::format(&mut f, &block_header).unwrap();
        
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
        let mut start_time = get_epoch_time_ms();
        let mut end_time = 0;
        let mut block_start_time = start_time;
        let mut prev_block_header = block_header.clone();
        
        set_trace(false);

        for i in 0..1048576 {
            let i0 = (i & 0xff0000) >> 12;
            let i1 = (i & 0x00ff00) >> 8;
            let i2 = i & 0x0000ff;
            
            let path = TrieHash::from_data(&seed[..]).as_bytes()[0..32].to_vec();
            seed = path.clone();

            let triepath = TriePath::from_bytes(&path[..]).unwrap(); 
            let value = TrieLeaf::new(&vec![], &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8].to_vec());

            if (i + 1) % 4096 == 0 {
                // next block
                end_time = get_epoch_time_ms();

                let flush_start_time = get_epoch_time_ms();
                f.flush().unwrap();
                let flush_end_time = get_epoch_time_ms();

                test_debug!("next block! Processed 4096 keys in {} ms (flush = {} ms)", end_time - block_start_time, flush_end_time - flush_start_time);

                block_header = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i0 as u8, i1 as u8, i2 as u8]).unwrap();
                block_start_time = get_epoch_time_ms();
            }

            MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();

            if i % 128 == 0 {
                if block_header == prev_block_header {
                    end_time = get_epoch_time_ms();
                }
                else {
                    prev_block_header = block_header.clone();
                }
                let (read_count, write_count) = f.stats();
                let (node_reads, backptr_reads, node_writes) = f.node_stats();
                let (leaf_reads, leaf_writes) = f.leaf_stats();
                test_debug!("inserted {} in {} (1 insert = {} ms).  Read = {}, Write = {}, Node Reads = {}, Node Writes = {}, Backptr Reads = {}, Leaf Reads = {}, Leaf Writes = {}",
                         i, end_time - start_time, ((end_time - start_time) as f64) / 128.0, read_count, write_count, node_reads, node_writes, backptr_reads, leaf_reads, leaf_writes);

                start_time = get_epoch_time_ms();
            }
        }
        
        f.flush().unwrap();
        
        let mut seed = TrieHash::from_data(&[]).as_bytes().to_vec();
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

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            // merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
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
    
    #[test]
    fn marf_read_random_1048576_4096_file_storage() {
        let path = "/tmp/rust_marf_insert_random_1048576_4096".to_string();
        match fs::metadata(&path) {
            Err(_) => {
                eprintln!("Run the marf_insert_random_1048576_4096 test first");
                return;
            },
            Ok(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let block_header = BlockHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xf0,0xff,0xff]).unwrap();
        f.open(&block_header, false).unwrap();

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

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            // merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
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
            MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();
             
            test_debug!("get {}", i);
            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            assert_eq!(f.tell(), block_header);
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
        }
        
        f.flush().unwrap();

        f.open(&block_header, false).unwrap();
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

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
        }

        for i in 0..(128/32) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            f.open(&block_header, false).unwrap();
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
            MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();
             
            test_debug!("get {}", i);
            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            assert_eq!(f.tell(), block_header);
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
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

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
        }

        for i in 0..(4096/128) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            f.open(&block_header, false).unwrap();
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
            MARF::insert(&mut f, &block_header, &triepath, &value).unwrap();
             
            test_debug!("get {}", i);
            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            assert_eq!(f.tell(), block_header);
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
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

            let read_value = MARF::get(&mut f, &block_header, &TriePath::from_bytes(&path[..]).unwrap()).unwrap().unwrap();
            assert_eq!(read_value.reserved.to_vec(), value.reserved.to_vec());
            
            // can make a merkle proof to each one
            merkle_test_marf(&mut f, &block_header, &path.to_vec(), &value.reserved.to_vec());
        }

        for i in 0..(256/16) {
            let block_header = BlockHeaderHash::from_bytes(&[i as u8; 32]).unwrap();
            f.open(&block_header, false).unwrap();
            dump_trie(&mut f);
        }
    }
}

