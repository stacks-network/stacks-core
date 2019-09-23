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
    SeekFrom,
    ErrorKind
};

use sha2::Sha512Trunc256 as TrieHasher;
use sha2::Digest;

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
};

use chainstate::stacks::index::storage::{BlockHashMap};

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
    fseek,
    ftell,
    TrieFileStorage,
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

/// Decode a trie path from a Readable object.
/// Returns Error::CorruptionError if the path doens't decode.
pub fn path_from_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, Error> {
    let mut lenbuf = [0u8; 1];
    r.read_exact(&mut lenbuf)
        .map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                Error::CorruptionError("Failed to read len buf".to_string())
            }
            else {
                eprintln!("failed: {:?}", &e);
                Error::IOError(e)
            }
        })?;
    
    if lenbuf[0] as usize > TRIEPATH_MAX_LEN {
        trace!("Path length is {} (expected <= {})", lenbuf[0], TRIEPATH_MAX_LEN);
        return Err(Error::CorruptionError(format!("Node path is longer than {} bytes (got {})", TRIEPATH_MAX_LEN, lenbuf[0])));
    }

    let mut retbuf = vec![0; lenbuf[0] as usize];
    r.read_exact(&mut retbuf)
        .map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                Error::CorruptionError(format!("Failed to read {} bytes of path", lenbuf[0]))
            }
            else {
                eprintln!("failed: {:?}", &e);
                Error::IOError(e)
            }
        })?;
    
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

/// Helper to determine how many bytes a Trie node's child pointers will take to encode for consensus.
#[inline]
pub fn get_ptrs_consensus_byte_len(ptrs: &[TriePtr]) -> usize {
    let node_id_len = 1;
    let consensus_trie_ptr_size = 2 + 32;// 2: id + chr, 32: block header hash
    node_id_len + consensus_trie_ptr_size * ptrs.len()
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
    r.read_exact(&mut idbuf)
        .map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                Error::CorruptionError("Failed to read ptrs buf length".to_string())
            }
            else {
                eprintln!("failed: {:?}", &e);
                Error::IOError(e)
            }
        })?;
    
    let nid = idbuf[0];

    if clear_backptr(nid) != clear_backptr(node_id) {
        trace!("Bad idbuf: {:x} != {:x}", nid, node_id);
        return Err(Error::CorruptionError("Failed to read expected node ID".to_string()));
    }

    let num_ptrs = node_id_to_ptr_count(node_id);
    let mut bytes = vec![0u8; num_ptrs * TRIEPTR_SIZE];
    r.read_exact(&mut bytes)
        .map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                Error::CorruptionError(format!("Failed to read {} bytes of ptrs", num_ptrs * TRIEPTR_SIZE))
            }
            else {
                eprintln!("failed: {:?}", &e);
                Error::IOError(e)
            }
        })?;
    
    // not a for-loop because "for i in 0..num_ptrs" is noticeably slow
    let mut i = 0;
    while i < num_ptrs {
        ptrs_buf[i] = TriePtr::from_bytes(&bytes[i*TRIEPTR_SIZE..(i+1)*TRIEPTR_SIZE]);
        i += 1;
    }
    Ok(nid)
}

/// Calculate the hash of a TrieNode, given its childrens' hashes.
pub fn get_node_hash<T: TrieNode + std::fmt::Debug>(node: &T, child_hashes: &Vec<TrieHash>, map: &BlockHashMap) -> TrieHash {
    let mut hasher = TrieHasher::new();

    node.write_consensus_bytes(map, &mut hasher)
        .expect("IO Failure pushing to hasher.");

    for child_hash in child_hashes {
        hasher.input(child_hash.as_ref());
    }

    let mut res = [0u8; 32];
    res.copy_from_slice(hasher.result().as_slice());

    let ret = TrieHash(res);

    trace!("get_node_hash: hash {:?} = {:?} + {:?}", &ret, node, child_hashes);
    ret
}

/// Calculate the hash of a TrieNode, given its childrens' hashes.
pub fn get_leaf_hash(node: &TrieLeaf) -> TrieHash {
    let mut hasher = TrieHasher::new();
    node.write_consensus_bytes_leaf(&mut hasher)
        .expect("IO Failure pushing to hasher.");

    let mut res = [0u8; 32];
    res.copy_from_slice(hasher.result().as_slice());

    let ret = TrieHash(res);

    trace!("get_leaf_hash: hash {:?} = {:?} + []", &ret, node);
    ret
}

#[inline]
pub fn get_nodetype_hash_bytes(node: &TrieNodeType, child_hash_bytes: &Vec<TrieHash>, map: &BlockHashMap) -> TrieHash {
    match node {
        TrieNodeType::Node4(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node16(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node48(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node256(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Leaf(ref data) => get_node_hash(data, child_hash_bytes, map),
    }
}

/// Low-level method for reading a TrieHash into a byte buffer from a Read-able and Seek-able struct.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_hash_bytes<F: Read + Seek>(f: &mut F) -> Result<[u8; 32], Error> {
    let mut hashbytes = [0u8; 32];
    f.read_exact(&mut hashbytes)
        .map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                Error::CorruptionError(format!("Failed to read hash in full from {}", f.seek(SeekFrom::Current(0)).unwrap()))
            }
            else {
                eprintln!("failed: {:?}", &e);
                Error::IOError(e)
            }
        })?;
    
    Ok(hashbytes)
}

pub fn read_4_bytes<F: Read + Seek>(f: &mut F) -> Result<[u8; 4], Error> {
    let mut bytes = [0u8; 4];
    f.read_exact(&mut bytes)
        .map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                Error::CorruptionError(format!("Failed to read hash in full from {}", f.seek(SeekFrom::Current(0)).unwrap()))
            }
            else {
                eprintln!("failed: {:?}", &e);
                Error::IOError(e)
            }
        })?;
    
    Ok(bytes)
}

/// Low-level method for reading a node's hash bytes into a buffer from a Read-able and Seek-able struct.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_node_hash_bytes<F: Read + Seek>(f: &mut F, ptr: &TriePtr) -> Result<[u8; 32], Error> {
    fseek(f, ptr.ptr() as u64)?;
    read_hash_bytes(f)
}

/// Read the root hash from a TrieFileStorage instance
pub fn read_root_hash(s: &mut TrieFileStorage) -> Result<TrieHash, Error> {
    let ptr = s.root_trieptr();
    Ok(s.read_node_hash_bytes(&ptr)?)
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

/// Deserialize a node.
/// Node wire format:
/// 0               32 33               33+X         33+X+Y
/// |---------------|--|------------------|-----------|
///   node hash      id  ptrs & ptr data      path
///
/// X is fixed and determined by the TrieNodeType variant.
/// Y is variable, but no more than TriePath::len()
pub fn read_nodetype<F: Read + Seek>(f: &mut F, ptr: &TriePtr) -> Result<(TrieNodeType, TrieHash), Error> {
    trace!("read_nodetype at {:?}", ptr);
    let h = read_node_hash_bytes(f, ptr)?;

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

    Ok((node, TrieHash(h)))
}

/// calculate how many bytes a node will be when serialized, including its hash. 
pub fn get_node_byte_len(node: &TrieNodeType) -> usize {
    let hash_len = TRIEHASH_ENCODED_SIZE;
    let node_byte_len = node.byte_len();
    hash_len + node_byte_len
}

/// write all the bytes for a node, including its hash, to the given Writeable object.
/// Returns the number of bytes written.
pub fn write_nodetype_bytes<F: Write + Seek>(f: &mut F, node: &TrieNodeType, hash: TrieHash) -> Result<usize, Error> {
    let start = ftell(f)?;

    f.write_all(hash.as_bytes())?;
    node.write_bytes(f)?;

    let end = ftell(f)?;
    trace!("write_nodetype: {:?} {:?} at {}-{}", node, &hash, start, end);

    Ok((end - start) as usize)
}
