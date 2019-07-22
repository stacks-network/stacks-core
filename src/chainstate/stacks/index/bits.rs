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

/// This file contains low-level methods for reading and manipulating Trie node data.

use std::fmt;
use std::error;
use std::io;
use std::io::{
    Read,
    Write,
    Seek,
};

use sha2::Sha512Trunc256 as TrieHasher;
use sha2::Digest;

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
    fast_extend_from_slice
};

use chainstate::stacks::index::node::{
    clear_backptr,
    TrieNodeID,
    TrieNodeType,
    TrieNode4,
    TrieNode16,
    TrieNode48,
    TrieNode256,
    TrieLeaf,
    TriePtr,
    TRIEPTR_SIZE
};

use chainstate::stacks::index::storage::{
    read_all,
    write_all,
    fseek,
    ftell,
    TrieStorage
};

use chainstate::stacks::index::node::{
    TRIEPATH_MAX_LEN,
    TrieNode
};

use chainstate::stacks::index::Error;

use util::log;
use util::macros::is_trace;

/// Get the size of a Trie path (note that a Trie path is 32 bytes long, and can definitely _not_
/// be over 255 bytes).
pub fn get_path_byte_len(p: &Vec<u8>) -> usize {
    assert!(p.len() < 255);
    let path_len_byte_len = 1;
    path_len_byte_len + p.len()
}

/// Encode a Trie path to a byte buffer.
pub fn path_to_bytes(p: &Vec<u8>, buf: &mut Vec<u8>) -> () {
    // always true by construction
    assert!(p.len() < 256);
    buf.push(p.len() as u8);
    buf.append(&mut p.clone());
}

/// Decode a trie path from a Readable object.
/// Returns Error::CorruptionError if the path doens't decode.
pub fn path_from_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, Error> {
    let mut lenbuf = [0u8; 1];
    let l_lenbuf = read_all(r, &mut lenbuf)?;

    if l_lenbuf != 1 {
        return Err(Error::CorruptionError("Could not read node path length".to_string()));
    }
    if lenbuf[0] as usize > TRIEPATH_MAX_LEN {
        trace!("Path length is {} (expected <= {})", lenbuf[0], TRIEPATH_MAX_LEN);
        return Err(Error::CorruptionError(format!("Node path is longer than {} bytes (got {})", TRIEPATH_MAX_LEN, lenbuf[0])));
    }

    let mut retbuf = vec![0; lenbuf[0] as usize];
    let l_retbuf = read_all(r, &mut retbuf)?;

    if l_retbuf != (lenbuf[0] as usize) {
        return Err(Error::CorruptionError(format!("Could not read full node path: only got {} out of {} bytes", l_retbuf, lenbuf[0])));
    }
    
    Ok(retbuf)
}

/// Helper to verify that a Trie node's ID byte is valid.
#[inline]
pub fn check_node_id(nid: u8) -> bool {
    let node_id = clear_backptr(nid);
    node_id == TrieNodeID::Leaf ||
    node_id == TrieNodeID::Node4 ||
    node_id == TrieNodeID::Node16 ||
    node_id == TrieNodeID::Node48 ||
    node_id == TrieNodeID::Node256
}

/// Helper to return the number of children in a Trie, given its ID.
#[inline]
pub fn node_id_to_ptr_count(node_id: u8) -> usize {
    match clear_backptr(node_id) {
        TrieNodeID::Leaf => 1,
        TrieNodeID::Node4 => 4,
        TrieNodeID::Node16 => 16,
        TrieNodeID::Node48 => 48,
        TrieNodeID::Node256 => 256,
        _ => panic!("Unknown node ID {}", node_id)
    }
}

/// Helper to determine how many bytes a Trie node's child pointers will take to encode.
#[inline]
pub fn get_ptrs_byte_len(ptrs: &[TriePtr]) -> usize {
    let node_id_len = 1;
    node_id_len + TRIEPTR_SIZE * ptrs.len()
}

/// Encode a Trie node's child pointers as a byte string by appending them to the given buffer.
#[inline]
pub fn ptrs_to_bytes(node_id: u8, ptrs: &[TriePtr], buf: &mut Vec<u8>) -> () {
    assert!(check_node_id(node_id));
    assert_eq!(node_id_to_ptr_count(node_id), ptrs.len());

    buf.push(node_id);

    // In benchmarks, this while() loop is noticeably faster than the more idiomatic "for ptr in ptrs.iter()"
    let mut i = 0;
    while i < ptrs.len() {
        ptrs[i].to_bytes(buf);
        i += 1;
    }
}

/// Encode only the consensus-relevant bits of a Trie node's child pointers to the given buffer.
#[inline]
pub fn ptrs_to_consensus_bytes(node_id: u8, ptrs: &[TriePtr], buf: &mut Vec<u8>) -> () {
    assert!(check_node_id(node_id));

    buf.push(node_id);
    
    // In benchmarks, this while() loop is noticeably faster than the more idiomatic "for ptr in ptrs.iter()"
    let mut i = 0;
    while i < ptrs.len() {
        ptrs[i].to_consensus_bytes(buf);
        i += 1;
    }
}

/// Read a Trie node's children from a Readable object, and write them to the given ptrs_buf slice.
/// Returns the Trie node ID detected.
#[inline]
pub fn ptrs_from_bytes<R: Read>(node_id: u8, r: &mut R, ptrs_buf: &mut [TriePtr]) -> Result<u8, Error> {
    if !check_node_id(node_id) {
        trace!("Bad node ID {:x}", node_id);
        return Err(Error::CorruptionError(format!("Bad node ID: {:x}", node_id)));
    }

    let mut idbuf = [0u8; 1];
    let l_idbuf = read_all(r, &mut idbuf)?;

    if l_idbuf != 1 {
        trace!("Bad l_idbuf: {}", l_idbuf);
        return Err(Error::CorruptionError("Failed to read node ID".to_string()));
    }
    let nid = idbuf[0];

    if clear_backptr(nid) != clear_backptr(node_id) {
        trace!("Bad idbuf: {:x} != {:x}", nid, node_id);
        return Err(Error::CorruptionError("Failed to read expected node ID".to_string()));
    }

    let num_ptrs = node_id_to_ptr_count(node_id);
    let mut bytes = vec![0u8; num_ptrs * TRIEPTR_SIZE];
    let l_bytes = read_all(r, &mut bytes)?;

    if l_bytes != num_ptrs * TRIEPTR_SIZE {
        trace!("Bad l_bytes: {} != {}", l_bytes, num_ptrs * TRIEPTR_SIZE);
        return Err(Error::CorruptionError(format!("Failed to read node: got {} out of {} bytes", l_bytes, num_ptrs * TRIEPTR_SIZE)));
    }
    
    // not a for-loop because "for i in 0..num_ptrs" is noticeably slow
    let mut i = 0;
    while i < num_ptrs {
        ptrs_buf[i] = TriePtr::from_bytes(&bytes[i*TRIEPTR_SIZE..(i+1)*TRIEPTR_SIZE]);
        i += 1;
    }
    Ok(nid)
}

/// Calculate the hash of a TrieNode, given its childrens' hashes.
pub fn get_node_hash<T: TrieNode + std::fmt::Debug>(node: &T, child_hashes: &Vec<TrieHash>) -> TrieHash {
    let mut hasher = TrieHasher::new();
    let mut buf = Vec::with_capacity(node.byte_len());

    node.to_consensus_bytes(&mut buf);
    hasher.input(&buf);
    for child_hash in child_hashes {
        hasher.input(&child_hash.as_bytes());
    }
    
    let mut res = [0u8; 32];
    res.copy_from_slice(hasher.result().as_slice());

    let ret = TrieHash(res);
    trace!("get_node_hash: hash {:?} = {:?} + {:?}", &ret, node, child_hashes);
    ret
}

/// Calculate the hash of a TrieNode, given a byte buffer encoding all of its children's hashes.
pub fn get_node_hash_bytes<T: TrieNode + std::fmt::Debug>(node: &T, child_hash_bytes: &Vec<u8>) -> TrieHash {
    assert_eq!(child_hash_bytes.len() % TRIEHASH_ENCODED_SIZE, 0);

    let mut hasher = TrieHasher::new();
    let mut buf = Vec::with_capacity(node.byte_len());

    node.to_consensus_bytes(&mut buf);
    hasher.input(&buf);
    hasher.input(child_hash_bytes);
    
    let mut res = [0u8; 32];
    res.copy_from_slice(hasher.result().as_slice());

    let ret = TrieHash(res);

    if is_trace() {
        // not in prod -- can spend a few cycles on fancy debug output
        if child_hash_bytes.len() >= 50 {
            // extract individual hashes
            let mut all_hashes = Vec::with_capacity(child_hash_bytes.len() / TRIEHASH_ENCODED_SIZE);
            for i in 0..child_hash_bytes.len() / TRIEHASH_ENCODED_SIZE {
                let mut h_slice = [0u8; TRIEHASH_ENCODED_SIZE];
                h_slice.copy_from_slice(&child_hash_bytes[TRIEHASH_ENCODED_SIZE*i..TRIEHASH_ENCODED_SIZE*(i+1)]);
                all_hashes.push(TrieHash(h_slice))
            }
            trace!("get_node_hash_bytes: hash {:?} = {:?} + {:?}... ({})", &ret, node, &all_hashes, child_hash_bytes.len());
        }
        else {
            trace!("get_node_hash_bytes: hash {:?} = {:?} + {:?}... ({})", &ret, node, &child_hash_bytes, child_hash_bytes.len());
        }
    }
    ret
}

/// Low-level method for reading a TrieHash into a byte buffer.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_hash_bytes<F: Read + Write + Seek>(f: &mut F, buf: &mut Vec<u8>) -> Result<(), Error> {
    let mut hashbytes = [0u8; 32];
    f.read(&mut hashbytes)
        .map_err(Error::IOError)?;
    
    fast_extend_from_slice(buf, &hashbytes);
    Ok(())
}

/// Read a node's hash bytes into a buffer.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_node_hash_bytes<F: Read + Write + Seek>(f: &mut F, ptr: &TriePtr, buf: &mut Vec<u8>) -> Result<(), Error> {
    fseek(f, ptr.ptr() as u64)?;
    read_hash_bytes(f, buf)
}

/// Read the root hash from a TrieStorage implementation.
pub fn read_root_hash<S: TrieStorage + Seek>(s: &mut S) -> Result<TrieHash, Error> {
    let ptr = TriePtr::new(TrieNodeID::Node256, 0, s.root_ptr() as u32);
    let mut hash_bytes = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
    s.read_node_hash_bytes(&ptr, &mut hash_bytes)?;

    // safe because this is TRIEHASH_ENCODED_SIZE bytes long
    Ok(trie_hash_from_bytes(&hash_bytes))
}

/// Converts a vec of bytes to a TrieHash.
/// Panics if the vec isn't TRIEHASH_ENCODED_SIZE bytes long
#[inline]
pub fn trie_hash_from_bytes(v: &Vec<u8>) -> TrieHash {
    assert_eq!(v.len(), TRIEHASH_ENCODED_SIZE);
    TrieHash::from_bytes(&v[..]).unwrap()
}

/// count the number of allocated children in a list of a node's children pointers.
pub fn count_children(children: &[TriePtr]) -> usize {
    let mut cnt = 0;
    for i in 0..children.len() {
        if children[i].id() != TrieNodeID::Empty {
            cnt += 1;
        }
    }
    cnt
}

/// Convert a buffer of hash data into a list of TrieHashes.
/// Used for proof generation and for debugging/testing purposes.
pub fn hash_buf_to_trie_hashes(hashes_buf: &Vec<u8>) -> Vec<TrieHash> {
    assert_eq!(hashes_buf.len() % TRIEHASH_ENCODED_SIZE, 0);

    // extract individual hashes
    let mut all_hashes = Vec::with_capacity(hashes_buf.len() / TRIEHASH_ENCODED_SIZE);
    for i in 0..hashes_buf.len() / TRIEHASH_ENCODED_SIZE {
        let mut h_slice = [0u8; TRIEHASH_ENCODED_SIZE];
        h_slice.copy_from_slice(&hashes_buf[TRIEHASH_ENCODED_SIZE*i..TRIEHASH_ENCODED_SIZE*(i+1)]);
        all_hashes.push(TrieHash(h_slice))
    }
    all_hashes
}

/// Deserialize a node.
/// Node wire format:
/// 0               32 33               33+X         33+X+Y
/// |---------------|--|------------------|-----------|
///   node hash      id  ptrs & ptr data      path
///
/// X is fixed and determined by the TrieNodeType variant.
/// Y is variable, but no more than TriePath::len()
pub fn read_nodetype<F: Read + Write + Seek>(f: &mut F, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
    trace!("read_nodetype at {:?}", ptr);
    let mut h_bytes = Vec::with_capacity(TRIEHASH_ENCODED_SIZE);
    read_node_hash_bytes(f, ptr, &mut h_bytes)?;

    let node = match ptr.id() {
        TrieNodeID::Node4 => {
            let node = TrieNode4::from_bytes(f)?;
            TrieNodeType::Node4(node)
        },
        TrieNodeID::Node16 => {
            let node = TrieNode16::from_bytes(f)?;
            TrieNodeType::Node16(node)
        },
        TrieNodeID::Node48 => {
            let node = TrieNode48::from_bytes(f)?;
            TrieNodeType::Node48(node)
        },
        TrieNodeID::Node256 => {
            let node = TrieNode256::from_bytes(f)?;
            TrieNodeType::Node256(node)
        },
        TrieNodeID::Leaf => {
            let node = TrieLeaf::from_bytes(f)?;
            TrieNodeType::Leaf(node)
        },
        _ => {
            return Err(Error::CorruptionError(format!("read_node_type: Unknown trie node type {}", ptr.id())));
        }
    };

    let mut h = [0u8; TRIEHASH_ENCODED_SIZE];
    h.copy_from_slice(&h_bytes[0..TRIEHASH_ENCODED_SIZE]);
    Ok((node, TrieHash(h)))
}

/// calculate how many bytes a node will be when serialized, including its hash. 
pub fn get_node_byte_len(node: &TrieNodeType) -> usize {
    let hash_len = TRIEHASH_ENCODED_SIZE;
    let node_byte_len = match node {
        TrieNodeType::Leaf(ref data) => data.byte_len(),
        TrieNodeType::Node4(ref data) => data.byte_len(),
        TrieNodeType::Node16(ref data) => data.byte_len(),
        TrieNodeType::Node48(ref data) => data.byte_len(),
        TrieNodeType::Node256(ref data) => data.byte_len()
    };
    hash_len + node_byte_len
}

/// write all the bytes for a node, including its hash, to the given Writeable object.
/// Returns the number of bytes written.
pub fn write_node_bytes<F: Read + Write + Seek, T: TrieNode + std::fmt::Debug>(f: &mut F, node: &T, hash: TrieHash) -> Result<usize, Error> {
    let mut bytes = Vec::with_capacity(node.byte_len() + TRIEHASH_ENCODED_SIZE);
    
    fast_extend_from_slice(&mut bytes, hash.as_bytes());
    node.to_bytes(&mut bytes);
    
    assert_eq!(bytes.len(), node.byte_len() + TRIEHASH_ENCODED_SIZE);

    let ptr = ftell(f)?;
    trace!("write_node: {:?} {:?} at {}-{}", node, &hash, ptr, ptr + bytes.len() as u64);

    write_all(f, &bytes[..])
}

