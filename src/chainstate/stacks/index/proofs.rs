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

use std::char::from_digit;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use hashbrown::HashMap;
use std::collections::VecDeque;
use std::collections::HashSet;

use std::fs;
use std::path::{
    Path,
    PathBuf
};

use sha2::Sha512Trunc256 as TrieHasher;
use sha2::Digest;

use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::index::bits::{
    read_root_hash,
    hash_buf_to_trie_hashes,
    get_node_hash_bytes,
    get_node_hash,
    trie_hash_from_bytes
};

use chainstate::stacks::index::node::{
    clear_backptr,
    is_backptr,
    set_backptr,
    TrieNode,
    TrieNodeType,
    TrieNode4,
    TrieNode16,
    TrieNode48,
    TrieNode256,
    TrieLeaf,
    TrieCursor,
    TrieNodeID,
    TriePtr,
    TriePath
};

use chainstate::stacks::index::fork_table::{
    TrieForkPtr,
    TrieForkTable
};

use chainstate::stacks::index::{
    TrieHash,
    MARFValue,
    TRIEHASH_ENCODED_SIZE,
    fast_extend_from_slice,
    slice_partialeq
};

use chainstate::stacks::index::storage::{
    TrieStorage
};

use chainstate::stacks::index::trie::{
    Trie
};

use chainstate::stacks::index::Error as Error;

use util::log;

#[derive(Clone)]
pub enum TrieMerkleProofType {
    Node4((u8, TrieNode4, [TrieHash; 3])),
    Node16((u8, TrieNode16, [TrieHash; 15])),
    Node48((u8, TrieNode48, [TrieHash; 47])),
    Node256((u8, TrieNode256, [TrieHash; 255])),
    Leaf((u8, TrieLeaf)),
    Shunt((i64, Vec<TrieHash>))
}

pub fn hashes_fmt(hashes: &[TrieHash]) -> String {
    let mut strs = vec![];
    if hashes.len() < 48 {
        for i in 0..hashes.len() {
            strs.push(format!("{:?}", hashes[i]));
        }
        strs.join(",")
    }
    else {
        for i in 0..hashes.len()/4 {
            strs.push(format!("{:?},{:?},{:?},{:?}", hashes[4*i], hashes[4*i+1], hashes[4*i+2], hashes[4*i+3]));
        }
        format!("\n{}", strs.join("\n"))
    }
}

impl fmt::Debug for TrieMerkleProofType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TrieMerkleProofType::Node4((ref chr, ref node, ref hashes)) => write!(f, "TrieMerkleProofType::Node4(0x{:02x}, node={:?}, hashes={})", chr, node, hashes_fmt(hashes)),
            TrieMerkleProofType::Node16((ref chr, ref node, ref hashes)) => write!(f, "TrieMerkleProofType::Node16(0x{:02x}, node={:?}, hashes={})", chr, node, hashes_fmt(hashes)),
            TrieMerkleProofType::Node48((ref chr, ref node, ref hashes)) => write!(f, "TrieMerkleProofType::Node48(0x{:02x}, node={:?}, hashes={})", chr, node, hashes_fmt(hashes)),
            TrieMerkleProofType::Node256((ref chr, ref node, ref hashes)) => write!(f, "TrieMerkleProofType::Node256(0x{:02x}, node={:?}, hashes={})", chr, node, hashes_fmt(hashes)),
            TrieMerkleProofType::Leaf((ref chr, ref node)) => write!(f, "TrieMerkleProofType::Leaf(0x{:02x}, node={:?})", chr, node),
            TrieMerkleProofType::Shunt((ref idx, ref hashes)) => write!(f, "TrieMerkleProofType::Shunt(idx={}, hashes={:?})", idx, hashes)
        }
    }
}

impl PartialEq for TrieMerkleProofType {
    fn eq(&self, other: &TrieMerkleProofType) -> bool {
        match (self, other) {
            (TrieMerkleProofType::Node4((ref chr, ref node, ref hashes)), TrieMerkleProofType::Node4((ref other_chr, ref other_node, ref other_hashes))) => {
                chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes)
            },
            (TrieMerkleProofType::Node16((ref chr, ref node, ref hashes)), TrieMerkleProofType::Node16((ref other_chr, ref other_node, ref other_hashes))) => {
                chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes)
            },
            (TrieMerkleProofType::Node48((ref chr, ref node, ref hashes)), TrieMerkleProofType::Node48((ref other_chr, ref other_node, ref other_hashes))) => {
                chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes)
            },
            (TrieMerkleProofType::Node256((ref chr, ref node, ref hashes)), TrieMerkleProofType::Node256((ref other_chr, ref other_node, ref other_hashes))) => {
                chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes)
            },
            (TrieMerkleProofType::Leaf((ref chr, ref node)), TrieMerkleProofType::Leaf((ref other_chr, ref other_node))) => {
                chr == other_chr && node == other_node
            },
            (TrieMerkleProofType::Shunt((ref idx_1, ref hashes_1)), TrieMerkleProofType::Shunt((ref idx_2, ref hashes_2))) => {
                idx_1 == idx_2 && hashes_1 == hashes_2
            },
            (_, _) => false
        }
    }
}

#[derive(Debug)]
pub struct TrieMerkleProof(Vec<TrieMerkleProofType>);

impl Deref for TrieMerkleProof {
    type Target = Vec<TrieMerkleProofType>;
    fn deref(&self) -> &Vec<TrieMerkleProofType> {
        &self.0
    }
}

impl TrieMerkleProof {
    /// Given a TriePtr to the _currently-visited_ node and the chr of the _previous_ node, calculate a
    /// Merkle proof node.  Include all the children hashes _except_ for the one that corresponds
    /// to the previous node.
    fn ptr_to_segment_proof_node<S: TrieStorage + Seek>(s: &mut S, ptr: &TriePtr, prev_chr: u8) -> Result<TrieMerkleProofType, Error> {
        trace!("ptr_to_proof_node: ptr={:?}, prev_chr=0x{:02x}", ptr, prev_chr);
        let (node, _) = Trie::read_node(s, ptr)?;
        let all_hashes = Trie::get_children_hashes(s, &node)?;

        fn make_proof_hashes<T: TrieNode + std::fmt::Debug>(data: &T, all_hashes: &Vec<TrieHash>, chr: u8) -> Result<Vec<TrieHash>, Error> {
            let mut hashes = vec![];
            assert!(all_hashes.len() == data.ptrs().len());

            for i in 0..data.ptrs().len() {
                if data.ptrs()[i].id() == TrieNodeID::Empty {
                    hashes.push(TrieHash::from_data(&[]));
                }
                else if data.ptrs()[i].chr() != chr {
                    hashes.push(all_hashes[i].clone());
                }
            }

            if hashes.len() + 1 != data.ptrs().len() {
                trace!("Char 0x{:02x} does not appear in this node: {:?}", chr, data);
                return Err(Error::NotFoundError);
            }

            Ok(hashes)
        }
        
        let proof_node = match node {
            TrieNodeType::Leaf(ref data) => {
                TrieMerkleProofType::Leaf((prev_chr, data.clone()))
            },
            TrieNodeType::Node4(ref data) => {
                let hashes = make_proof_hashes(data, &all_hashes, prev_chr)?;

                let mut hash_slice = [TrieHash::from_data(&[]); 3];
                hash_slice.copy_from_slice(&hashes[0..3]);

                TrieMerkleProofType::Node4((prev_chr, data.clone(), hash_slice))
            },
            TrieNodeType::Node16(ref data) => {
                let hashes = make_proof_hashes(data, &all_hashes, prev_chr)?;
                
                let mut hash_slice = [TrieHash::from_data(&[]); 15];
                hash_slice.copy_from_slice(&hashes[0..15]);

                TrieMerkleProofType::Node16((prev_chr, data.clone(), hash_slice))
            },
            TrieNodeType::Node48(ref data) => {
                let hashes = make_proof_hashes(data, &all_hashes, prev_chr)?;
                
                let mut hash_slice = [TrieHash::from_data(&[]); 47];
                hash_slice.copy_from_slice(&hashes[0..47]);

                TrieMerkleProofType::Node48((prev_chr, data.clone(), hash_slice))
            },
            TrieNodeType::Node256(ref data) => {
                let hashes = make_proof_hashes(data, &all_hashes, prev_chr)?;

                let mut hash_slice = [TrieHash::from_data(&[]); 255];
                hash_slice.copy_from_slice(&hashes[0..255]);

                TrieMerkleProofType::Node256((prev_chr, data.clone(), hash_slice))      // ancestor hashes to be filled in later
            }
        };
        Ok(proof_node)
    }

    /// Given a node's (non-backptr) ptr, and the node's backptr, make a shunt proof that links
    /// them.  That is, make a proof that the current trie's root node hash and ptr are only reachable from the
    /// corresponding non-backptr root in this trie's ${ptr.back_block()}th ancestor back.
    /// s must point to the block from which we're going to walk back from.
    /// 
    /// The first entry of the shunt proof is the set of Trie root hashes _excluding_ the one from
    /// backptr, as well as the index into the list of Trie root hashes into which the backptr hash
    /// should be inserted (this root hash is calculated from the segment proof for that backptr
    /// node).
    ///
    /// The last entry of the shunt proof is the set of root hashes _excluding_ the final root
    /// hash, which will be the root hash for the segment proof for the non-backptr copy of this
    /// node.
    ///
    /// All intermediate shunt proofs will contain all ancestor hashes for each node in-between the
    /// backptr and the non-backptr node.  The intermediate root hashes will be calculated by the verifier.
    fn make_shunt_proof<S: TrieStorage + Seek>(s: &mut S, backptr: &TriePtr) -> Result<Vec<TrieMerkleProofType>, Error> {
        // the proof is built "backwards" -- starting from the current block all the way back to backptr.
        // Note that it is okay if backptr is not an actual backptr
        let mut proof = vec![];
        
        let mut back_block = backptr.back_block();
        let mut block_header = s.tell();

        let ancestor_block_hash = s.block_walk(back_block)?;
        s.open(&ancestor_block_hash, false)?;

        let ancestor_root_hash = read_root_hash(s)?;

        let mut found_backptr = false;
        
        // find last and intermediate entries in the shunt proof -- exclude the root hashes; just
        // include the ancestor hashes.
        while back_block > 0 && !found_backptr {
            s.open(&block_header, false)?;
            let cur_root_hash = read_root_hash(s)?;
            trace!("Shunt proof: walk back {} from {:?} ({:?})", back_block, &block_header, &cur_root_hash);

            let mut ancestor_hash_buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE * 256);
            Trie::get_trie_ancestor_hashes_bytes(s, &mut ancestor_hash_buf)?;

            let ancestor_hashes = hash_buf_to_trie_hashes(&ancestor_hash_buf);
            trace!("Ancestors of {:?} ({:?}): {:?}", &block_header, &cur_root_hash, &ancestor_hashes);

            // did we reach the backptr's root hash?
            for i in 0..ancestor_hashes.len() {
                if ancestor_hashes[i] == ancestor_root_hash {
                    found_backptr = true;
                    break;
                }
            }

            // what's the next block we'll shunt to?
            let mut idx = 0;
            for i in 0..ancestor_hashes.len() {
                if (1u32 << i) <= back_block {
                    idx = i;
                }
            }

            back_block -= 1u32 << idx;
            block_header = s.block_walk(1u32 << idx)?;

            let mut trimmed_ancestor_hashes = Vec::with_capacity(ancestor_hashes.len() - 1);
            for i in 0..ancestor_hashes.len() {
                if i == idx {
                    continue;
                }
                trimmed_ancestor_hashes.push(ancestor_hashes[i].clone());
            }
            
            idx += 1;

            // need the target node's root trie ptr, unless this is the first proof (in which case
            // it's a junction proof)
            if proof.len() > 0 {
                let root_ptr = TriePtr::new(TrieNodeID::Node256, 0, s.root_ptr() as u32);
                let (root_node, _) = s.read_node(&root_ptr)?;

                let root_hash = match root_node {
                    TrieNodeType::Node256(ref root_data) => {
                        let mut root_hashes_bytes = Vec::with_capacity(256 * TRIEHASH_ENCODED_SIZE);
                        Trie::read_child_hashes_bytes(s, root_data.ptrs(), &mut root_hashes_bytes)?;
                        let root_hash = get_node_hash_bytes(root_data, &root_hashes_bytes);
                        root_hash
                    },
                    _ => {
                        return Err(Error::CorruptionError(format!("Root node at {:?} is not a TrieNode256", &block_header)));
                    }
                };
                
                trimmed_ancestor_hashes.insert(0, root_hash);
                idx += 1;

                trace!("Tail proof: Added intermediate proof node's root data hash is {:?}", &root_hash);
            }

            if !found_backptr {
                trace!("Backptr not found yet: trim ancestor hashes at idx={} from {:?} to {:?}", idx, &ancestor_hashes, &trimmed_ancestor_hashes);
                trace!("Backptr not found yet.  Shunt to {:?} and walk back {}; Add shunt proof ({}, {:?})", &block_header, back_block, idx, &trimmed_ancestor_hashes);
            }
            else {
                trace!("Backptr found: trim ancestor hashes at idx={} from {:?} to {:?}", idx, &ancestor_hashes, &trimmed_ancestor_hashes);
                trace!("Backptr found (back_block = {}, header = {:?}).  Intermediate shunt proof is ({}, {:?})", back_block, &block_header, idx, &trimmed_ancestor_hashes);
            };
                
            let shunt_proof_node = TrieMerkleProofType::Shunt((idx as i64, trimmed_ancestor_hashes));
            proof.push(shunt_proof_node);
        }

        s.open(&block_header, false)?;

        if proof.len() == 0 {
            // first entry in the shunt proof -- all ancestors of backptr, but not the non-backptr trie root
            let mut backptr_ancestor_hash_buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE * 256);
            Trie::get_trie_ancestor_hashes_bytes(s, &mut backptr_ancestor_hash_buf)?;
            
            let backptr_ancestor_hashes = hash_buf_to_trie_hashes(&backptr_ancestor_hash_buf);
            trace!("First shunt proof node: (0, {:?})", &backptr_ancestor_hashes);

            let backptr_proof = TrieMerkleProofType::Shunt((0, backptr_ancestor_hashes));
            
            proof.push(backptr_proof);
        }

        proof.reverse();

        // put the proof in the right order. we're done!
        Ok(proof)
    }
    
    fn get_shunt_proof_node_hash(hashes: &[TrieHash]) -> TrieHash {
        let mut hash_buf = Vec::with_capacity(TRIEHASH_ENCODED_SIZE * hashes.len());
        for i in 0..hashes.len() {
            fast_extend_from_slice(&mut hash_buf, hashes[i].as_bytes());
        }
        TrieHash::from_data(&hash_buf[..])
    }

    fn next_shunt_hash(hash: &TrieHash, idx: i64, hashes: &[TrieHash]) -> Option<TrieHash> {
        let mut all_hashes = Vec::with_capacity(hashes.len() + 1);
        let mut hash_idx = 0;
        for i in 0..hashes.len()+1 {
            if idx == 0 {
                trace!("Intermediate shunt proof entry must have idx > 0");
                return None;
            }

            if idx - 1 == (i as i64) {
                all_hashes.push(hash.clone());
            }
            else {
                if hash_idx >= hashes.len() {
                    trace!("Invalid proof: hash_idx = {}, hashes.len() = {}", hash_idx, hashes.len());
                    return None;
                }
                all_hashes.push(hashes[hash_idx].clone());
                hash_idx += 1;
            }
        }
        trace!("Shunt proof node: idx={}, all_hashes={:?}", idx, all_hashes);
        let next_hash = TrieMerkleProof::get_shunt_proof_node_hash(&all_hashes[..]);
        Some(next_hash)
    }

    /// Verify the head of a shunt proof
    fn verify_shunt_proof_head(node_root_hash: &TrieHash, shunt_proof_head: &TrieMerkleProofType) -> Option<TrieHash> {
        // ancestor hashes are always the first item 
        let hash = match shunt_proof_head {
            TrieMerkleProofType::Shunt((ref idx, ref hashes)) => {
                if *idx != 0 {
                    trace!("First shunt proof entry must have idx == 0");
                    return None;
                }
        
                if hashes.len() == 0 {
                    // special case -- if this shunt proof has no hashes (i.e. this is a leaf from the first
                    // block), then we can safely skip this step
                    trace!("Special case for a 0-ancestor node: hash is just the trie hash: {:?}", node_root_hash);
                    node_root_hash.clone()
                }
                else {
                    let mut all_hashes = Vec::with_capacity(hashes.len() + 1);
                    all_hashes.push(node_root_hash.clone());
                    for h in hashes {
                        all_hashes.push(h.clone());
                    }
                    let ret = TrieMerkleProof::get_shunt_proof_node_hash(&all_hashes[..]);
                    trace!("Shunt proof head: hash = {:?}, all_hashes = {:?}", &ret, &all_hashes);
                    ret
                }
            },
            _ => {
                trace!("Shunt proof head is not a shunt proof node");
                return None;
            }
        };

        Some(hash)
    }

    /// Verify the tail of a shunt proof, given the backptr root hash.
    /// Calculate the root hash of the next segment proof.
    fn verify_shunt_proof_tail(initial_hash: &TrieHash, shunt_proof: &[TrieMerkleProofType]) -> Option<TrieHash> {
        let mut hash = initial_hash.clone();

        // walk subsequent legs of a shunt proof, except for the last (since we need the next
        // segment proof for that)
        for i in 0..shunt_proof.len() {
            let proof_node = &shunt_proof[i];
            hash = match proof_node {
                TrieMerkleProofType::Shunt((ref idx, ref hashes)) => {
                    if *idx == 0 {
                        trace!("Invalid shunt proof tail: idx == 0");
                        return None;
                    }

                    match TrieMerkleProof::next_shunt_hash(&hash, *idx, hashes) {
                        Some(h) => {
                            h
                        },
                        None => {
                            return None;
                        }
                    }
                },
                _ => {
                    trace!("Shunt proof item is not a shunt proof node");
                    return None;
                }
            };
        }
        Some(hash)
    }
    
    /// Verify a shunt juncture, where a shunt proof tail and a segment proof meet.
    /// Returns the hash of the root of the junction
    fn verify_shunt_proof_junction(node_root_hash: &TrieHash, penultimate_trie_hash: &TrieHash, shunt_proof_junction: &TrieMerkleProofType) -> Option<TrieHash> {
        // at the juncture, we include the node root hash (from the subsequent segment proof) as
        // the first hash, and include the penultimate trie hash in its idx
        let hash = match shunt_proof_junction {
            TrieMerkleProofType::Shunt((ref idx, ref hashes)) => {
                if *idx == 0 {
                    trace!("Shunt proof junction entry must not have idx == 0");
                    return None;
                }

                let mut all_hashes = Vec::with_capacity(hashes.len() + 1);
                let mut hash_idx = 0;

                all_hashes.push(node_root_hash.clone());

                for i in 0..hashes.len() + 1 {
                    if *idx - 1 == (i as i64) {
                        all_hashes.push(penultimate_trie_hash.clone());
                    }
                    else {
                        if hash_idx >= hashes.len() {
                            trace!("ran out of hashes: hash_idx = {}, hashes.len() = {}", hash_idx, hashes.len());
                            return None;
                        }

                        all_hashes.push(hashes[hash_idx].clone());
                        hash_idx += 1;
                    }
                }
               
                trace!("idx = {}, hashes = {:?}, penultimate = {:?}, node root = {:?}", *idx, hashes, penultimate_trie_hash, node_root_hash);
                trace!("Shunt proof junction: all_hashes = {:?}", &all_hashes);
                TrieMerkleProof::get_shunt_proof_node_hash(&all_hashes[..])
            },
            _ => {
                trace!("Shunt proof junction is not a shunt proof node");
                return None;
            }
        };

        Some(hash)
    }

    /// Given a list of non-backptr ptrs and a root block header hash, calculate a Merkle proof.
    fn make_segment_proof<S: TrieStorage + Seek>(s: &mut S, ptrs: &Vec<TriePtr>, starting_chr: u8) -> Result<Vec<TrieMerkleProofType>, Error> {
        trace!("make_segment_proof: ptrs = {:?}", &ptrs);

        assert!(ptrs.len() > 0);
        assert_eq!(ptrs[0], TriePtr::new(TrieNodeID::Node256, 0, s.root_ptr() as u32));
        for i in 1..ptrs.len() {
            assert!(!is_backptr(ptrs[i].id()));
        }

        let mut proof_segment = Vec::with_capacity(ptrs.len());
        let mut prev_chr = starting_chr;

        trace!("make_segment_proof: Trie segment from {:?} starting at {:?}: {:?}", &s.tell(), starting_chr, ptrs);
        let mut i = ptrs.len() - 1;
        loop {
            let ptr = &ptrs[i];
            let proof_node = TrieMerkleProof::ptr_to_segment_proof_node(s, &ptr, prev_chr)?;

            trace!("make_segment_proof: Add proof node from {:?} child 0x{:02x}: {:?}", &ptr, prev_chr, &proof_node);

            proof_segment.push(proof_node);
            prev_chr = ptr.chr();
            
            if i == 0 {
                break;
            }
            else {
                i -= 1;
            }
        }

        Ok(proof_segment)
    }

    /// Given a segment proof, the deepest node's hash, and the hash of the trie root, verify that
    /// the segment proof is well-formed.
    /// If so, calculate the root hash of the segment and return it.
    fn verify_segment_proof(proof: &[TrieMerkleProofType], node_hash: &TrieHash) -> Option<TrieHash> {

        /// Given a node in a segment proof, find the hash
        fn get_segment_proof_hash<T: TrieNode + std::fmt::Debug>(node: &T, hash: &TrieHash, chr: u8, hashes: &[TrieHash], count: usize) -> Option<TrieHash> {
            let mut all_hashes = vec![];
            let mut ih = 0;

            assert!(node.ptrs().len() == count);
            assert!(hashes.len() == 0 || (count > 0 && hashes.len() == count - 1));

            for i in 0..count {
                if node.ptrs()[i].id() != TrieNodeID::Empty && node.ptrs()[i].chr() == chr {
                    all_hashes.push(hash.clone());
                }
                else {
                    if ih >= hashes.len() {
                        trace!("verify_get_hash: {} >= {}", ih, hashes.len());
                        return None;
                    }
                    else {
                        all_hashes.push(hashes[ih].clone());
                        ih += 1;
                    }
                }
            }
            if all_hashes.len() != count {
                trace!("verify_get_hash: {} != {}", all_hashes.len(), count);
                return None
            }

            Some(get_node_hash(node, &all_hashes))
        }

        let mut hash = node_hash.clone();
        for i in 0..proof.len() {
            let hash_opt = match proof[i] {
                TrieMerkleProofType::Leaf((ref chr, ref node)) => {
                    get_segment_proof_hash(node, &hash, *chr, &vec![], 0)
                },
                TrieMerkleProofType::Node4((ref chr, ref node, ref hashes)) => {
                    get_segment_proof_hash(node, &hash, *chr, hashes, 4)
                },
                TrieMerkleProofType::Node16((ref chr, ref node, ref hashes)) => {
                    get_segment_proof_hash(node, &hash, *chr, hashes, 16)
                },
                TrieMerkleProofType::Node48((ref chr, ref node, ref hashes)) => {
                    get_segment_proof_hash(node, &hash, *chr, hashes, 48)
                },
                TrieMerkleProofType::Node256((ref chr, ref node, ref hashes)) => {
                    get_segment_proof_hash(node, &hash, *chr, hashes, 256)
                },
                _ => {
                    trace!("Invalid proof -- encountered a non-node proof type");
                    return None;
                }
            };
            let mut next_hash = match hash_opt {
                None => {
                    return None;
                }
                Some(h) => h.clone()
            };

            hash = next_hash;
        }

        trace!("verify segment: calculated root hash = {:?}", hash);
        Some(hash)
    }

    /// Given a segment proof, extract the path prefix it encodes
    fn get_segment_proof_path_prefix(segment_proof: &[TrieMerkleProofType]) -> Option<Vec<u8>> {
        let mut path_parts = vec![];
        for proof_node in segment_proof {
            match proof_node {
                TrieMerkleProofType::Leaf((ref chr, ref node)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                },
                TrieMerkleProofType::Node4((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                },
                TrieMerkleProofType::Node16((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                },
                TrieMerkleProofType::Node48((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                },
                TrieMerkleProofType::Node256((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                },
                _ => {
                    trace!("Not a valid segment proof: got a non-node proof node");
                    return None;
                }
            }
        }

        let mut path = vec![];
        for i in 0..path_parts.len() {
            let idx = path_parts.len() - 1 - i;
            path.extend_from_slice(&path_parts[idx]);
        }
        Some(path)
    }

    /// Verify that a proof is well-formed:
    /// * it must have the same number of segment and shunt proofs
    /// * segment proof i+1 must be a prefix of segment proof i
    /// * segment proof 0 must end in a leaf
    /// * all segment proofs must end in a Node256 (a root)
    fn is_proof_well_formed(proof: &Vec<TrieMerkleProofType>) -> bool {
        if proof.len() == 0 {
            trace!("Proof is empty");
            return false;
        }

        match proof[0] {
            TrieMerkleProofType::Leaf(_) => {},
            _ => {
                trace!("First proof node is not a leaf");
                return false;
            }
        }

        // must be alternating segment and shunt proofs
        let mut i = 0;
        let mut path_bytes = vec![];

        while i < proof.len() {
            // next segment proof
            let mut j = i + 1;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt(_) => {
                        break;
                    },
                    _ => {
                        j += 1;
                    }
                }
            }

            let segment_proof = &proof[i..j];
            
            if i == 0 {
                // detect the path
                path_bytes = match TrieMerkleProof::get_segment_proof_path_prefix(segment_proof) {
                    Some(bytes) => {
                        bytes
                    },
                    None => {
                        trace!("Failed to get the path from the proof");
                        return false;
                    }
                };
            }
            else {
                // make sure that this segment proof is a prefix of the last
                let new_path_bytes = match TrieMerkleProof::get_segment_proof_path_prefix(segment_proof) {
                    Some(bytes) => {
                        bytes
                    },
                    None => {
                        trace!("Failed to et the path prefix from the proof");
                        return false;
                    }
                };

                if path_bytes.len() < new_path_bytes.len() {
                    trace!("Segment proof path is {}, which is longer than the previous segment proof length {}", path_bytes.len(), new_path_bytes.len());
                    trace!("path_bytes: {:?}", &path_bytes);
                    trace!("new path bytes: {:?}", &new_path_bytes);
                    return false;
                }

                for i in 0..new_path_bytes.len() {
                    if path_bytes[i] != new_path_bytes[i] {
                        trace!("Segment path {:?} is not a prefix of previous segment path {:?}", &new_path_bytes, &path_bytes);
                        return false;
                    }
                }

                path_bytes = new_path_bytes;
            }

            // next shunt proof 
            i = j;
            if i >= proof.len() {
                trace!("Proof is incomplete -- must end with a shunt proof");
                return false;
            }

            j = i + 1;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt(_) => {
                        j += 1;
                    },
                    _ => {
                        break;
                    }
                }
            }

            // end of shunt proof
            i = j;
        }

        true
    }


    /// Given a value and the root hash from which this proof was
    /// (supposedly) generated go and verify whether or not it is consistent with the root hash.
    /// For the proof validation to work, the verifier needs to know which Trie roots correspond to
    /// which block headers.  This can be calculated and verified independently from the blockchain
    /// headers.
    /// NOTE: Trie root hashes are globally unique by design, even if they represent the same contents, so the root_to_block map is bijective with high probability.
    pub fn verify_proof(proof: &Vec<TrieMerkleProofType>, root_hash: &TrieHash, root_to_block: &HashMap<TrieHash, BlockHeaderHash>) -> bool {
        if !TrieMerkleProof::is_proof_well_formed(&proof) {
            return false;
        }

        let mut node_hash = match proof[0] {
            TrieMerkleProofType::Leaf((_, ref node)) => {
                get_node_hash(node, &vec![])
            },
            _ => {
                unreachable!()
            }
        };

        let mut i = 0;

        // verify the very first segment proof 
        let mut j = i + 1;
        while j < proof.len() {
            match proof[j] {
                TrieMerkleProofType::Shunt(_) => {
                    break;
                },
                _ => {
                    j += 1;
                }
            }
        }

        trace!("verify segment proof in range {}..{}", i, j);
        let node_root_hash = match TrieMerkleProof::verify_segment_proof(&proof[i..j], &node_hash) {
            Some(h) => {
                h
            },
            None => {
                return false;
            }
        };
        
        i = j;
        if i >= proof.len() {
            trace!("Proof is too short -- needed at least one shunt proof for the first segment");
            return false;
        }

        // verify the very first shunt proof head.
        trace!("verify shunt proof head at {}: {:?}", i, &proof[i]);
        let mut trie_hash = match TrieMerkleProof::verify_shunt_proof_head(&node_root_hash, &proof[i]) {
            Some(h) => {
                h
            },
            None => {
                return false;
            }
        };
        trace!("shunt proof head hash: {:?}", &trie_hash);

        i += 1;
        if i >= proof.len() {
            // done -- no further shunts
            return true;
        }

        // next node hash is the hash of the block from which its root came
        node_hash = match root_to_block.get(&trie_hash) {
            Some(bhh) => {
                trace!("Block hash for {:?} is {:?}", &trie_hash, bhh);

                // safe because block header hashes are 32 bytes long
                trie_hash_from_bytes(&bhh.as_bytes().to_vec())
            },
            None => {
                trace!("Trie hash not found in root-to-block map: {:?}", &trie_hash);
                return false;
            }
        };

        // next proof item should be part of a segment proof
        match proof[i] {
            TrieMerkleProofType::Shunt(_) => {
                trace!("Malformed proof -- exepcted segment proof following first shunt proof head at {}", i);
                return false;
            },
            _ => {}
        }

        while i < proof.len() {
            // find the next segment proof
            j = i + 1;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt(_) => {
                        break;
                    },
                    _ => {
                        j += 1;
                    }
                }
            }

            trace!("verify segment proof in range {}..{}", i, j);
            let next_node_root_hash = match TrieMerkleProof::verify_segment_proof(&proof[i..j], &node_hash) {
                Some(h) => {
                    h
                },
                None => {
                    return false;
                }
            };

            i = j;
            if i >= proof.len() {
                trace!("Proof to short -- no shunt proof tail");
                return false;
            }

            // find the tail end
            j = i;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt((ref idx, _)) => {
                        if *idx == 0 {
                            break;
                        }
                        j += 1;
                    },
                    _ => {
                        break;
                    }
                }
            }
            j -= 1;

            if j < i {
                trace!("Proof is malformed -- no tail or junction proof");
                return false;
            }

            trace!("verify shunt proof tail in range {}..{} initial hash = {:?}: {:?}", i, j, &trie_hash, &proof[i..j]);
            let penultimate_trie_hash = match TrieMerkleProof::verify_shunt_proof_tail(&trie_hash, &proof[i..j]) {
                Some(h) => {
                    h
                },
                None => {
                    return false;
                }
            };
            trace!("verify shunt proof tail in range {}..{}: penultimate trie hash is {:?}", i, j, &penultimate_trie_hash);

            i = j;
            if i >= proof.len() {
                trace!("Proof to short -- no junction proof");
                return false;
            }

            trace!("verify shunt junction proof at {} next_node_root_hash = {:?} penultimate hash = {:?}: {:?}", i, &next_node_root_hash, &penultimate_trie_hash, &proof[i]);
            let next_trie_hash = match TrieMerkleProof::verify_shunt_proof_junction(&next_node_root_hash, &penultimate_trie_hash, &proof[i]) {
                Some(h) => {
                    h
                },
                None => {
                    return false;
                }
            };
            
            // next node hash is the hash of the block from which its root came
            trie_hash = next_trie_hash;
            node_hash = match root_to_block.get(&trie_hash) {
                Some(bhh) => {
                    trace!("Block hash for {:?} is {:?}", &trie_hash, bhh);

                    // safe because block header hashes are 32 bytes long
                    trie_hash_from_bytes(&bhh.as_bytes().to_vec())
                },
                None => {
                    trace!("Trie hash not found in root-to-block map: {:?}", &trie_hash);
                    return false;
                }
            };

            i += 1;

            if trie_hash == *root_hash {
                trace!("Appeared to find the root hash early, with the remaining proof:\n{:?}", &proof[i..]);
                break;
            }
        }

        trace!("Verify proof: {:?} =?= {:?}", root_hash, &trie_hash);
        *root_hash == trie_hash
    }

    /// Verify this proof
    pub fn verify(&self, root_hash: &TrieHash, root_to_block: &HashMap<TrieHash, BlockHeaderHash>) -> bool {
        TrieMerkleProof::verify_proof(&self.0, root_hash, root_to_block)
    }

    /// Walk down the trie pointed to by s until we reach a backptr or a leaf
    fn walk_to_leaf_or_backptr<S: TrieStorage + Seek>(s: &mut S, k: &TriePath) -> Result<(TrieCursor, TrieNodeType, TriePtr), Error> {
        trace!("Walk path {:?} from {:?} to the first backptr", k, &s.tell());
        
        let mut node_ptr = TriePtr::new(TrieNodeID::Node256, 0, s.root_ptr() as u32);
        let (mut node, _) = Trie::read_root(s)?;
        let mut c = TrieCursor::new(k, s.root_ptr());

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
                        let ptr_opt = match node {
                            TrieNodeType::Node4(ref data) => data.walk(chr),
                            TrieNodeType::Node16(ref data) => data.walk(chr),
                            TrieNodeType::Node48(ref data) => data.walk(chr),
                            TrieNodeType::Node256(ref data) => data.walk(chr),
                            TrieNodeType::Leaf(_) => {
                                if !c.eop() {
                                    // at an existing leaf with a different path.
                                    // we're done.
                                    trace!("Existing but different leaf encountered at {:?} at {:?} -- we're done", &node_ptr, s.tell());
                                    return Err(Error::NotFoundError);
                                }
                                else {
                                    // we're done -- we found the leaf
                                    trace!("Found leaf {:?}", &node);
                                    return Ok((c, node, node_ptr));
                                }
                            }
                        };

                        match ptr_opt {
                            None => {
                                // not found
                                trace!("Failed to walk to '{}' from {:?}", chr, &node);
                                return Err(Error::NotFoundError)
                            },
                            Some(ptr) => {
                                // expect backptr
                                if !is_backptr(ptr.id()) {
                                    return Err(Error::CorruptionError(format!("Failed to walk 0x{:02x} -- got non-backptr", chr)))
                                }

                                // we're done -- we found a backptr
                                trace!("Found backptr {:?}", &ptr);
                                return Ok((c, node, ptr));
                            }
                        }
                    }
                }
            }
        }
        
        trace!("Trie has a cycle");
        return Err(Error::CorruptionError("Trie has a cycle".to_string()));
    }

    /// Make a merkle proof of inclusion from a path.
    /// If the path doesn't resolve, return an error (NotFoundError)
    pub fn from_path<S: TrieStorage + Seek>(s: &mut S, path: &TriePath, expected_value: &TrieLeaf, root_block_header: &BlockHeaderHash) -> Result<TrieMerkleProof, Error> {
        // accumulate proofs in reverse order -- each proof will be from an earlier and earlier
        // trie, so we'll reverse them in the end so the proof starts with the latest trie.
        let mut segment_proofs = vec![];
        let mut shunt_proofs = vec![];
        let mut block_header = root_block_header.clone();

        loop {
            s.open(&block_header, false)?;

            trace!("Walk {:?} path {:?} to leaf or backptr", &s.tell(), path);
            let (cursor, reached_node, backptr) = TrieMerkleProof::walk_to_leaf_or_backptr(s, path)?;
            
            // make a proof to this node
            trace!("Make segment proof at {:?} from {:?}", &s.tell(), &cursor.node_ptrs);
            let segment_proof = TrieMerkleProof::make_segment_proof(s, &cursor.node_ptrs, cursor.chr().unwrap())?;
            segment_proofs.push(segment_proof);

            // make a shunt proof to this segment proof's root
            trace!("Make shunt proof {:?} back to the block containing {:?} (cursor ptrs = {:?})", &s.tell(), &backptr, &cursor.node_ptrs);
            let shunt_proof = TrieMerkleProof::make_shunt_proof(s, &backptr)?;
            shunt_proofs.push(shunt_proof);

            if cursor.ptr().id() == TrieNodeID::Leaf {
                match reached_node {
                    TrieNodeType::Leaf(ref data) => {
                        if data.data.to_vec() != expected_value.data.to_vec() {
                            trace!("Did not find leaf {:?} at {:?} (but got {:?})", expected_value, path, data);
                            return Err(Error::NotFoundError);
                        }
                    },
                    _ => {
                        trace!("Did not find leaf at {:?}", path);
                        return Err(Error::NotFoundError);
                    }
                }
                break;
            }

            s.open(&block_header, false)?;

            trace!("Walk back for {:?} from {:?}", &backptr, &s.tell());
            block_header = s.block_walk(backptr.back_block())?;
        }

        assert_eq!(shunt_proofs.len(), segment_proofs.len());

        // leaf proof needs to be first
        segment_proofs.reverse();
        shunt_proofs.reverse();

        let mut proof = Vec::with_capacity(segment_proofs.len() + shunt_proofs.len());
        for i in 0..shunt_proofs.len() {
            trace!("Append segment proof\n{:?}", &segment_proofs[i]);
            proof.append(&mut segment_proofs[i]);
            
            trace!("Append shunt proof\n{:?}", &shunt_proofs[i]);
            proof.append(&mut shunt_proofs[i]);
        }
        
        Ok(TrieMerkleProof(proof))
    }
    
    /// Make a merkle proof of inclusion from a key/value pair.
    /// If the path doesn't resolve, return an error (NotFoundError)
    pub fn from_entry<S: TrieStorage + Seek>(s: &mut S, key: &String, value: &String, root_block_header: &BlockHeaderHash) -> Result<TrieMerkleProof, Error> {
        let marf_value = MARFValue::from_value(value);
        let marf_leaf = TrieLeaf::from_value(&vec![], marf_value);
        let path = TriePath::from_key(key);
        TrieMerkleProof::from_path(s, &path, &marf_leaf, root_block_header)
    }
}


