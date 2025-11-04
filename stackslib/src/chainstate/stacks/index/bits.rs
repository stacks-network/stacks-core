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

/// This file contains low-level methods for reading and manipulating Trie node data.
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha512_256 as TrieHasher};

use crate::chainstate::stacks::index::node::{
    clear_compressed, clear_ctrl_bits, is_compressed, ptrs_fmt, ConsensusSerializable, TrieNode,
    TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeID, TrieNodePatch, TrieNodeType,
    TriePtr, TRIEPTR_SIZE,
};
use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::chainstate::stacks::index::{BlockMap, Error, MarfTrieId, TrieLeaf};
use crate::codec::StacksMessageCodec;
use crate::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};
use crate::util::hash::to_hex;

/// Get the size of a Trie path (note that a Trie path is 32 bytes long, and can definitely _not_
/// be over 255 bytes).
pub fn get_path_byte_len(p: &[u8]) -> usize {
    assert!(p.len() < 255);
    let path_len_byte_len = 1;
    path_len_byte_len + p.len()
}

/// Decode a trie path from a Readable object.
/// Returns Error::CorruptionError if the path doesn't decode.
pub fn path_from_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, Error> {
    let mut lenbuf = [0u8; 1];
    r.read_exact(&mut lenbuf).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError("Failed to read len buf".to_string())
        } else {
            error!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    if lenbuf[0] as usize > TRIEHASH_ENCODED_SIZE {
        trace!(
            "Path length is {} (expected <= {})",
            lenbuf[0],
            TRIEHASH_ENCODED_SIZE
        );
        return Err(Error::CorruptionError(format!(
            "Node path is longer than {} bytes (got {})",
            TRIEHASH_ENCODED_SIZE, lenbuf[0]
        )));
    }

    let mut retbuf = vec![0; lenbuf[0] as usize];
    r.read_exact(&mut retbuf).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError(format!("Failed to read {} bytes of path", lenbuf[0]))
        } else {
            error!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    Ok(retbuf)
}

/// Helper to return the number of children in a Trie, given its ID.
fn node_id_to_ptr_count(node_id: u8) -> usize {
    match TrieNodeID::from_u8(clear_ctrl_bits(node_id))
        .unwrap_or_else(|| panic!("Unknown node ID {}", node_id))
    {
        TrieNodeID::Leaf => 1,
        TrieNodeID::Node4 => 4,
        TrieNodeID::Node16 => 16,
        TrieNodeID::Node48 => 48,
        TrieNodeID::Node256 => 256,
        TrieNodeID::Empty | TrieNodeID::Patch => {
            panic!("node_id_to_ptr_count: tried getting empty node pointer count")
        }
    }
}

/// Helper to determine how many bytes a Trie node's child pointers will take to encode.
pub fn get_ptrs_byte_len(ptrs: &[TriePtr]) -> usize {
    let node_id_len = 1;
    node_id_len + TRIEPTR_SIZE * ptrs.len()
}

/// Helper to determine a sparse ptr list's bitmap size
pub fn get_sparse_ptrs_bitmap_size(id: u8) -> Option<usize> {
    match TrieNodeID::from_u8(clear_ctrl_bits(id))? {
        TrieNodeID::Leaf => None,
        TrieNodeID::Node4 => Some(1),
        TrieNodeID::Node16 => Some(2),
        TrieNodeID::Node48 => Some(6),
        TrieNodeID::Node256 => Some(32),
        TrieNodeID::Empty => None,
        TrieNodeID::Patch => None,
    }
}

/// Helper to determine what the compressed size of a ptrs list will be, depending on whether or
/// not it's sparse or dense.
/// Returns Some((size, sparse?)) on success
/// Returns None if the node doesn't have ptrs
pub fn get_compressed_ptrs_size(id: u8, ptrs: &[TriePtr]) -> Option<(usize, bool)> {
    let bitmap_size = get_sparse_ptrs_bitmap_size(id)?;

    // compute stored ptrs size
    let mut sparse_ptrs_size = 0;
    let mut ptrs_size = 0;
    for ptr in ptrs.iter() {
        if ptr.id() != TrieNodeID::Empty as u8 {
            sparse_ptrs_size += ptr.compressed_size();
        }
        ptrs_size += ptr.compressed_size();
    }

    // +1 is for the 0xff bitmap marker
    let sparse_size = usize::try_from(1 + bitmap_size + sparse_ptrs_size).expect("infallible");
    if sparse_size < ptrs_size {
        return Some((sparse_size, true));
    } else {
        return Some((ptrs_size, false));
    }
}

/// Helper to determine how many bytes a Trie node's child pointers will take to encode.
/// Size is id + ptrs encoding
pub fn get_ptrs_byte_len_compressed(id: u8, ptrs: &[TriePtr]) -> usize {
    1 + get_compressed_ptrs_size(id, ptrs)
        .map(|(sz, _)| sz)
        .unwrap_or(0)
}

/// Read a Trie node's children from a Read object, and write them to the given ptrs_buf slice.
/// Returns Ok(the Trie node ID detected) on success.  If the node was compressed, the compressed
/// bit in the ID will be cleared.  But if the backptr is set, then the backptr bit will be
/// preserved.
///
/// Returns Err(CorruptionError(..)) if the node ID is invalid, the read node ID is missing, or the
/// read node ID does not match the given node ID
/// Returns Err(IOError(..)) on read failure
/// Returns Err(OverflowError) on integer overflow, should that happen
pub fn ptrs_from_bytes<R: Read + Seek>(
    node_id: u8,
    r: &mut R,
    ptrs_buf: &mut [TriePtr],
) -> Result<u8, Error> {
    let Some(trie_node_id) = TrieNodeID::from_u8(clear_ctrl_bits(node_id)) else {
        error!("Bad node ID {:x}", node_id);
        return Err(Error::CorruptionError(format!(
            "Bad node ID: {:x}",
            node_id
        )));
    };

    let num_ptrs = node_id_to_ptr_count(node_id);

    // NOTE: this may overshoot the length of the readable object, since this is the maximum possible size of the
    // concatenated ptr bytes.  As such, treat EOF as a non-error
    let ptrs_start_disk_ptr = r
        .seek(SeekFrom::Current(0))
        .inspect_err(|e| error!("Failed to ftell the read handle"))?;

    trace!(
        "Read ptrs for node {} at offset {}",
        node_id,
        ptrs_start_disk_ptr
    );

    let mut bytes = vec![0u8; 1 + num_ptrs * TRIEPTR_SIZE];
    let mut offset = 0;
    loop {
        let nr = match r.read(&mut bytes[offset..]) {
            Ok(nr) => nr,
            Err(e) => match e.kind() {
                ErrorKind::UnexpectedEof => {
                    // done
                    0
                }
                ErrorKind::Interrupted => {
                    // try again
                    continue;
                }
                _ => {
                    error!("Failed to read trie ptrs: {e:?}");
                    return Err(Error::IOError(e));
                }
            },
        };
        if nr == 0 {
            // EOF
            break;
        }
        offset = offset.checked_add(nr).ok_or_else(|| Error::OverflowError)?;
    }

    trace!("Read bytes ({}) {}", bytes.len(), &to_hex(&bytes));

    // verify the id is correct
    let nid = bytes
        .first()
        .ok_or_else(|| Error::CorruptionError("Failed to read 1st byte from bytes array".into()))?;

    if clear_ctrl_bits(*nid) != clear_ctrl_bits(node_id) {
        let Some(nid_node_id) = TrieNodeID::from_u8(clear_ctrl_bits(*nid)) else {
            return Err(Error::CorruptionError(
                "Failed to read expected node ID -- not a valid ID".to_string(),
            ));
        };
        if nid_node_id == TrieNodeID::Patch {
            trace!("Encountered a patch node at offset {}", ptrs_start_disk_ptr);
            // this is really a node that patches the target node.
            // try and read the patch node instead
            let patch_node = TrieNodePatch::consensus_deserialize(&mut &bytes[..])
                .map_err(|e| Error::CorruptionError(format!("Failed to read patch node: {e:?}")))?;

            // the caller should read the node that this node patches
            return Err(Error::Patch(None, patch_node));
        }

        error!("Bad idbuf: {:x} != {:x}", nid, node_id);
        return Err(Error::CorruptionError(
            "Failed to read expected node ID".to_string(),
        ));
    }

    let ptr_bytes = bytes
        .get(1..)
        .ok_or_else(|| Error::CorruptionError("Failed to read >1 bytes from bytes array".into()))?;

    if is_compressed(*nid) {
        trace!("Node {} has compressed ptrs", clear_ctrl_bits(*nid));
        let sparse_flag = ptr_bytes.get(0).ok_or_else(|| {
            Error::CorruptionError("Failed to read 2nd byte from bytes array".into())
        })?;

        if *sparse_flag == 0xff {
            trace!("Node {} has sparse compressed ptrs", clear_ctrl_bits(*nid));
            // this is a sparse ptrs list
            let ptr_bytes = ptr_bytes.get(1..).ok_or_else(|| {
                Error::CorruptionError("Failed to read >2 bytes from bytes array".into())
            })?;

            let bitmap_size =
                get_sparse_ptrs_bitmap_size(clear_ctrl_bits(*nid)).ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "Unable to determine bitmap size for node type {}",
                        clear_ctrl_bits(*nid)
                    ))
                })?;

            if ptr_bytes.len() < bitmap_size {
                return Err(Error::CorruptionError(
                    "Tried to read a bitmap but not enough bytes".to_string(),
                ));
            }
            let bitmap = &ptr_bytes.get(0..bitmap_size).ok_or_else(|| {
                Error::CorruptionError("Tried to read a bitmap but not enough bytes".to_string())
            })?;

            trace!(
                "Node {} has sparse compressed ptrs bitmap {}",
                clear_ctrl_bits(*nid),
                to_hex(&bitmap)
            );

            let ptr_bytes = &ptr_bytes.get(bitmap_size..).ok_or_else(|| {
                Error::CorruptionError("Failed to read bitmap_size bytes from bytes array".into())
            })?;

            let mut nextptr = 0;
            let mut cursor = 0;
            for i in 0..(8 * bitmap_size) {
                if nextptr >= ptrs_buf.len() {
                    break;
                }
                let bi = i / 8;
                let bt = i % 8;
                let mask = 1u8 << bt;
                if bitmap[bi] & mask == 0 {
                    // empty
                    ptrs_buf[nextptr] = TriePtr::default();
                } else {
                    trace!(
                        "read sparse ptr {} at {}",
                        &to_hex(&ptr_bytes[cursor..(cursor + TRIEPTR_SIZE).min(ptr_bytes.len())]),
                        cursor
                    );
                    ptrs_buf[nextptr] = TriePtr::from_bytes_compressed(&ptr_bytes[cursor..]);
                    cursor = cursor
                        .checked_add(ptrs_buf[nextptr].compressed_size())
                        .ok_or_else(|| Error::OverflowError)?;
                }
                nextptr += 1;
            }
            trace!(
                "Node {} sparse compressed ptrs ({} bytes): {}",
                clear_ctrl_bits(*nid),
                cursor,
                &ptrs_fmt(&ptrs_buf)
            );

            // seek to the end of the decoded ptrs
            // the +2 is for the nid and bitmap marker
            r.seek(SeekFrom::Start(
                ptrs_start_disk_ptr
                    .checked_add(u64::try_from(cursor + 2 + bitmap_size).expect("infallible"))
                    .expect("FATAL: read far too many bytes"),
            ))
            .inspect_err(|e| error!("Failed to seek to the end of the sparse compressed ptrs"))?;
        } else {
            trace!("Node {} has dense compressed ptrs", clear_ctrl_bits(*nid));
            // this is a nearly-full ptrs list
            // ptrs list is compresesd, meaning each ptr might be a different size
            let mut cursor = 0;
            for nextptr in 0..num_ptrs {
                let next_ptrs_buf = &mut ptrs_buf[nextptr];
                *next_ptrs_buf = TriePtr::from_bytes_compressed(&ptr_bytes[cursor..]);
                cursor = cursor
                    .checked_add(next_ptrs_buf.compressed_size())
                    .ok_or_else(|| Error::OverflowError)?;
            }
            trace!(
                "Node {} dense compressed ptrs: {}",
                clear_ctrl_bits(*nid),
                &ptrs_fmt(&ptrs_buf)
            );

            // seek to the end of the decoded ptrs
            // the +1 is for the nid
            r.seek(SeekFrom::Start(
                ptrs_start_disk_ptr
                    .checked_add(u64::try_from(cursor + 1).expect("infallible"))
                    .expect("FATAL: read far too many bytes"),
            ))
            .inspect_err(|e| error!("Failed to seek to the end of the dense compressed ptrs"))?;
        }
    } else {
        // ptrs list is not compressed
        // iterate over the read-in bytes in chunks of TRIEPTR_SIZE and store them
        //   to `ptrs_buf`
        trace!("Node {} has uncompressed ptrs", clear_ctrl_bits(*nid));
        let reading_ptrs = ptr_bytes
            .chunks_exact(TRIEPTR_SIZE)
            .zip(ptrs_buf.iter_mut());
        for (next_ptr_bytes, ptr_slot) in reading_ptrs {
            *ptr_slot = TriePtr::from_bytes(next_ptr_bytes);
        }
    }

    Ok(clear_compressed(*nid))
}

/// Calculate the hash of a TrieNode, given its childrens' hashes.
pub fn get_node_hash<M, T: ConsensusSerializable<M> + std::fmt::Debug>(
    node: &T,
    child_hashes: &[TrieHash],
    map: &mut M,
) -> TrieHash {
    let mut hasher = TrieHasher::new();

    node.write_consensus_bytes(map, &mut hasher)
        .expect("IO Failure pushing to hasher.");

    for child_hash in child_hashes {
        hasher.update(child_hash.as_ref());
    }

    let res = hasher.finalize().into();
    let ret = TrieHash(res);

    trace!(
        "get_node_hash: hash {:?} = {:?} + {:?}",
        &ret,
        node,
        child_hashes
    );
    ret
}

/// Calculate the hash of a TrieLeaf
pub fn get_leaf_hash(node: &TrieLeaf) -> TrieHash {
    let mut hasher = TrieHasher::new();
    node.write_bytes(&mut hasher)
        .expect("IO Failure pushing to hasher.");

    let res = hasher.finalize().into();
    let ret = TrieHash(res);

    trace!("get_leaf_hash: hash {:?} = {:?} + []", &ret, node);
    ret
}

pub fn get_nodetype_hash_bytes<T: MarfTrieId, M: BlockMap>(
    node: &TrieNodeType,
    child_hash_bytes: &[TrieHash],
    map: &mut M,
) -> TrieHash {
    match node {
        TrieNodeType::Node4(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node16(ref data) => get_node_hash(data, child_hash_bytes, map),
        TrieNodeType::Node48(ref data) => get_node_hash(data.as_ref(), child_hash_bytes, map),
        TrieNodeType::Node256(ref data) => get_node_hash(data.as_ref(), child_hash_bytes, map),
        TrieNodeType::Leaf(ref data) => get_node_hash(data, child_hash_bytes, map),
    }
}

/// Low-level method for reading a TrieHash into a byte buffer from a Read-able and Seek-able struct.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_hash_bytes<F: Read>(f: &mut F) -> Result<[u8; TRIEHASH_ENCODED_SIZE], Error> {
    let mut hashbytes = [0u8; TRIEHASH_ENCODED_SIZE];
    f.read_exact(&mut hashbytes).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError(format!(
                "Failed to read hash in full from {}",
                to_hex(&hashbytes)
            ))
        } else {
            eprintln!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    Ok(hashbytes)
}

pub fn read_block_identifier<F: Read + Seek>(f: &mut F) -> Result<u32, Error> {
    let mut bytes = [0u8; 4];
    f.read_exact(&mut bytes).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            Error::CorruptionError(format!(
                "Failed to read hash in full from {}",
                f.seek(SeekFrom::Current(0)).unwrap()
            ))
        } else {
            eprintln!("failed: {:?}", &e);
            Error::IOError(e)
        }
    })?;

    Ok(u32::from_le_bytes(bytes))
}

/// Low-level method for reading a node's hash bytes into a buffer from a Read-able and Seek-able struct.
/// The byte buffer must have sufficient space to hold the hash, or this program panics.
pub fn read_node_hash_bytes<F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
) -> Result<[u8; TRIEHASH_ENCODED_SIZE], Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    read_hash_bytes(f)
}

/// Read the root hash from a TrieFileStorage instance
pub fn read_root_hash<T: MarfTrieId>(s: &mut TrieStorageConnection<T>) -> Result<TrieHash, Error> {
    let ptr = s.root_trieptr();
    Ok(s.read_node_hash_bytes(&ptr)?)
}

/// count the number of allocated children in a list of a node's children pointers.
pub fn count_children(children: &[TriePtr]) -> usize {
    let mut cnt = 0;
    for child in children.iter() {
        if child.id() != TrieNodeID::Empty as u8 {
            cnt += 1;
        }
    }
    cnt
}

/// Read a node and its hash
pub fn read_nodetype<F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
) -> Result<(TrieNodeType, TrieHash), Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    trace!("read_nodetype at {:?}", ptr);
    read_nodetype_at_head(f, ptr.id())
}

/// Read a node
pub fn read_nodetype_nohash<F: Read + Seek>(
    f: &mut F,
    ptr: &TriePtr,
) -> Result<TrieNodeType, Error> {
    f.seek(SeekFrom::Start(ptr.ptr() as u64))
        .map_err(Error::IOError)?;
    trace!("read_nodetype_nohash at {:?}", ptr);
    read_nodetype_at_head_nohash(f, ptr.id())
}

/// Read a node and hash at the stream's current position
pub fn read_nodetype_at_head<F: Read + Seek>(
    f: &mut F,
    ptr_id: u8,
) -> Result<(TrieNodeType, TrieHash), Error> {
    inner_read_nodetype_at_head(f, ptr_id, true).map(|(node, hash_opt)| {
        (
            node,
            hash_opt.expect("FATAL: queried hash but received None"),
        )
    })
}

/// Read a node at the stream's current position
pub fn read_nodetype_at_head_nohash<F: Read + Seek>(
    f: &mut F,
    ptr_id: u8,
) -> Result<TrieNodeType, Error> {
    inner_read_nodetype_at_head(f, ptr_id, false).map(|(node, _)| node)
}

/// Deserialize a node.
/// Node wire format for non-patch nodes:
/// 0               32 33               33+X         33+X+Y
/// |---------------|--|------------------|-----------|
///   node hash      id  ptrs & ptr data      path
///
/// X is fixed and determined by the TrieNodeType variant.
///
/// Y is variable, but no more than TrieHash::len().
///
/// If `read_hash` is false, then the contents of the node hash are undefined.
fn inner_read_nodetype_at_head<F: Read + Seek>(
    f: &mut F,
    ptr_id: u8,
    read_hash: bool,
) -> Result<(TrieNodeType, Option<TrieHash>), Error> {
    let h = if read_hash {
        let h = read_hash_bytes(f)?;
        Some(TrieHash(h))
    } else {
        f.seek(SeekFrom::Current(TRIEHASH_ENCODED_SIZE as i64))?;
        None
    };

    let node = match TrieNodeID::from_u8(ptr_id).ok_or_else(|| {
        Error::CorruptionError(format!(
            "inner_read_nodetype_at_head: Unknown trie node type {}",
            ptr_id
        ))
    })? {
        TrieNodeID::Node4 => {
            let node = TrieNode4::from_bytes(f).map_err(|e| {
                if let Error::Patch(_, patch) = e {
                    Error::Patch(h, patch)
                } else {
                    e
                }
            })?;
            TrieNodeType::Node4(node)
        }
        TrieNodeID::Node16 => {
            let node = TrieNode16::from_bytes(f).map_err(|e| {
                if let Error::Patch(_, patch) = e {
                    Error::Patch(h, patch)
                } else {
                    e
                }
            })?;
            TrieNodeType::Node16(node)
        }
        TrieNodeID::Node48 => {
            let node = TrieNode48::from_bytes(f).map_err(|e| {
                if let Error::Patch(_, patch) = e {
                    Error::Patch(h, patch)
                } else {
                    e
                }
            })?;
            TrieNodeType::Node48(Box::new(node))
        }
        TrieNodeID::Node256 => {
            let node = TrieNode256::from_bytes(f).map_err(|e| {
                if let Error::Patch(_, patch) = e {
                    Error::Patch(h, patch)
                } else {
                    e
                }
            })?;
            TrieNodeType::Node256(Box::new(node))
        }
        TrieNodeID::Leaf => {
            let node = TrieLeaf::from_bytes(f).map_err(|e| {
                if let Error::Patch(_, patch) = e {
                    Error::Patch(h, patch)
                } else {
                    e
                }
            })?;
            TrieNodeType::Leaf(node)
        }
        TrieNodeID::Empty => {
            return Err(Error::CorruptionError(
                "inner_read_nodetype_at_head: stored empty node type".to_string(),
            ))
        }
        TrieNodeID::Patch => {
            let patch = TrieNodePatch::consensus_deserialize(f).map_err(|e| {
                Error::CorruptionError(format!(
                    "inner_read_nodetype_at_head: failed to read patch node: {e:?}"
                ))
            })?;
            return Err(Error::Patch(h, patch));
        }
    };

    Ok((node, h))
}

/// calculate how many bytes a node will be when serialized, including its hash.
pub fn get_node_byte_len(node: &TrieNodeType) -> usize {
    let hash_len = TRIEHASH_ENCODED_SIZE;
    let node_byte_len = node.byte_len();
    hash_len + node_byte_len
}

/// calculate how many bytes a node will be when serialized, including its hash, using a compressed
/// representation
pub fn get_node_byte_len_compressed(node: &TrieNodeType) -> usize {
    let hash_len = TRIEHASH_ENCODED_SIZE;
    let node_byte_len = node.byte_len_compressed();
    hash_len + node_byte_len
}

/// write all the bytes for a node, including its hash, to the given Writeable object.
/// Returns the number of bytes written.
pub fn write_nodetype_bytes<F: Write + Seek>(
    f: &mut F,
    node: &TrieNodeType,
    hash: TrieHash,
) -> Result<u64, Error> {
    let start = f.stream_position().map_err(Error::IOError)?;
    f.write_all(hash.as_bytes())?;
    node.write_bytes(f)?;
    let end = f.stream_position().map_err(Error::IOError)?;
    trace!(
        "write_nodetype_bytes: {:?} {:?} at {}-{}",
        node,
        &hash,
        start,
        end
    );

    Ok(end - start)
}

pub fn write_nodetype_bytes_compressed<F: Write + Seek>(
    f: &mut F,
    node: &TrieNodeType,
    hash: TrieHash,
) -> Result<u64, Error> {
    let start = f.stream_position().map_err(Error::IOError)?;
    f.write_all(hash.as_bytes())?;
    node.write_bytes_compressed(f)?;
    let end = f.stream_position().map_err(Error::IOError)?;
    trace!(
        "write_nodetype_bytes_compressed: {:?} {:?} at {}-{}",
        node,
        &hash,
        start,
        end
    );

    Ok(end - start)
}

pub fn write_path_to_bytes<W: Write>(path: &[u8], w: &mut W) -> Result<(), Error> {
    w.write_all(&[path.len() as u8])?;
    w.write_all(path)?;
    Ok(())
}
