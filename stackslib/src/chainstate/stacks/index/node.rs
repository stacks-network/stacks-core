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

use std::io::{Read, Seek, Write};
use std::{error, fmt};

use crate::chainstate::stacks::index::bits::{
    get_compressed_ptrs_size, get_path_byte_len, get_ptrs_byte_len, get_ptrs_byte_len_compressed,
    get_sparse_ptrs_bitmap_size, path_from_bytes, ptrs_from_bytes, write_path_to_bytes,
};
use crate::chainstate::stacks::index::{
    BlockMap, ClarityMarfTrieId, Error, MARFValue, MarfTrieId, TrieLeaf, MARF_VALUE_ENCODED_SIZE,
};
use crate::codec::{read_next, write_next, Error as codec_error, StacksMessageCodec};
use crate::types::chainstate::{TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE};
use crate::util::hash::to_hex;

#[derive(Debug, Clone, PartialEq)]
pub enum CursorError {
    PathDiverged,
    BackptrEncountered(TriePtr),
    ChrNotFound,
}

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CursorError::PathDiverged => write!(f, "Path diverged"),
            CursorError::BackptrEncountered(_) => write!(f, "Back-pointer encountered"),
            CursorError::ChrNotFound => write!(f, "Node child not found"),
        }
    }
}

impl error::Error for CursorError {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

// All numeric values of a Trie node when encoded.
// They are all 6-bit numbers
// * the 8th bit is used to indicate whether or not the value
// identifies a back-pointer to be followed.
// * the 7th bit is used to indicate whether or not the ptrs
// are compressed. This bit is cleared on read.
define_u8_enum!(TrieNodeID {
    Empty = 0,
    Leaf = 1,
    Node4 = 2,
    Node16 = 3,
    Node48 = 4,
    Node256 = 5,
    Patch = 6
});

/// A node ID encodes a back-pointer if its high bit is set
pub fn is_backptr(id: u8) -> bool {
    id & 0x80 != 0
}

/// Set the back-pointer bit
pub fn set_backptr(id: u8) -> u8 {
    id | 0x80
}

/// Clear the back-pointer bit
pub fn clear_backptr(id: u8) -> u8 {
    id & 0x7f
}

/// Is this node compressed?
pub fn is_compressed(id: u8) -> bool {
    id & 0x40 != 0
}

/// Set the compressed bit
pub fn set_compressed(id: u8) -> u8 {
    id | 0x40
}

/// Clear the compressed bit
pub fn clear_compressed(id: u8) -> u8 {
    id & 0xbf
}

/// Clear all control bits (backptr and compressed)
pub fn clear_ctrl_bits(id: u8) -> u8 {
    id & 0x3f
}

// Byte writing operations for pointer lists, paths.

/// Write out the list of TriePtrs to the given Write object.
/// The written pointers will NOT be compressed.
/// Returns Ok(()) on success
/// Returns Err(IOError(..)) on disk I/O error
fn write_ptrs_to_bytes<W: Write>(ptrs: &[TriePtr], w: &mut W) -> Result<(), Error> {
    for ptr in ptrs.iter() {
        ptr.write_bytes(w)?;
    }
    Ok(())
}

/// Write the list of TriePtrs to the given Write object.
/// The given `id` is a node ID with some control bits set -- in particular, the compressed bit.
/// If the compressed bit is set, then the TriePtr list will be compressed as best as possible
/// before written.  See `bits::ptrs_to_bytes()` for details.
///
/// Returns Ok(()) on success
/// Returns Err(CorruptionError(..)) if the id does not correspond to a valid node ID or is a patch
/// node ID
/// Returns Err(IOError(..)) on disk I/O error
fn write_ptrs_to_bytes_compressed<W: Write>(
    id: u8,
    ptrs: &[TriePtr],
    w: &mut W,
) -> Result<(), Error> {
    let Some(node_id) = TrieNodeID::from_u8(id) else {
        return Err(Error::CorruptionError(
            "Tried to store invalid trie node ID".to_string(),
        ));
    };
    if node_id == TrieNodeID::Patch {
        // NB the only proper way to store a patch node is to have it dumped as part of a TrieRAM
        return Err(Error::CorruptionError(
            "Tried to store patch node's ptrs improperly".to_string(),
        ));
    }

    let Some((ptrs_size, is_sparse)) = get_compressed_ptrs_size(id, ptrs) else {
        // doesn't apply -- this node has no ptrs
        return Ok(());
    };

    if is_sparse {
        // do a sparse write -- just write the bitmap and the non-empty trieptrs.
        // the first byte is 0xff to indicate that this is a sparse list, since 0xff cannot be a
        // valid trie node ID
        w.write_all(&[0xff])?;

        // compute the bitmap
        let bitmap_size = get_sparse_ptrs_bitmap_size(id).ok_or_else(|| {
            Error::CorruptionError(format!("No bitmap size defined for node id {id}"))
        })?;

        let mut bitmap = vec![0u8; bitmap_size];
        for (i, ptr) in ptrs.iter().enumerate() {
            if ptr.id() != TrieNodeID::Empty as u8 {
                // SAFETY: have checked ptrs.len() against bitmap size
                let bi = i / 8;
                let bt = i % 8;
                let mask = 1u8 << bt;
                let byte_mut = bitmap
                    .get_mut(bi)
                    .ok_or_else(|| Error::CorruptionError("bitmap not long enough".into()))?;
                *byte_mut |= mask;
            }
        }
        trace!(
            "Write sparse compressed ptrs list ({} bytes) for node {}; bitmap {}",
            ptrs_size,
            id,
            to_hex(&bitmap)
        );

        // write out bitmap
        w.write_all(&bitmap)?;

        // write out non-empty ptrs
        for ptr in ptrs.iter() {
            if ptr.id() != TrieNodeID::Empty as u8 {
                let mut byte_buffer = vec![];
                ptr.write_bytes_compressed(&mut byte_buffer)?;
                trace!("write sparse ptr {}", &to_hex(&byte_buffer));
                ptr.write_bytes_compressed(w)?;
            }
        }
        return Ok(());
    }

    // ptrs are not sparse enough.
    // compute a bitmap of which ptrs are non-empty
    trace!(
        "Write dense compressed ptrs list ({} bytes) for node {}",
        ptrs_size,
        id
    );
    for ptr in ptrs.iter() {
        ptr.write_bytes_compressed(w)?;
    }
    Ok(())
}

fn ptrs_consensus_hash<W: Write, M: BlockMap>(
    ptrs: &[TriePtr],
    map: &mut M,
    w: &mut W,
) -> Result<(), Error> {
    for ptr in ptrs.iter() {
        ptr.write_consensus_bytes(map, w)?;
    }
    Ok(())
}

/// Copy-on-write pointer to a node.  When the MARF writes a new key/value pair, it copies
/// intermediate nodes from the parent trie into the new trie being built.  This struct is a
/// pointer stored in the new trie's nodes which point back to the node it was copied from.
///
/// This data is not stored anywhere.  It is used instead to compute TrieNodePatch nodes to write
/// to disk as a space-efficient alternative to copying over the same lightly-modified node over
/// and over again.
///
/// Fields are (trie block hash holding the node, pointer to the node in the trie)
#[derive(Clone, PartialEq, Copy)]
pub struct TrieCowPtr([u8; 32], TriePtr);

impl TrieCowPtr {
    pub fn new<T: MarfTrieId>(trie_id: T, ptr: TriePtr) -> Self {
        Self(trie_id.to_bytes(), ptr)
    }

    pub fn block_id<T: MarfTrieId>(&self) -> T {
        T::from_bytes(self.0)
    }

    pub fn ptr(&self) -> &TriePtr {
        &self.1
    }
}

impl fmt::Debug for TrieCowPtr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieCowPtr({},{})",
            &to_hex(&self.0),
            &ptrs_fmt(&[self.1])
        )
    }
}

/// All Trie nodes implement the following methods:
pub trait TrieNode {
    /// Node ID for encoding/decoding
    fn id(&self) -> u8;

    /// Is the node devoid of children?
    fn empty() -> Self;

    /// Follow a path character to a child pointer
    fn walk(&self, chr: u8) -> Option<TriePtr>;

    /// Insert a child pointer if the path character slot is not occupied.
    /// Return true if inserted, false if the slot is already filled
    fn insert(&mut self, ptr: &TriePtr) -> bool;

    /// Replace an existing child pointer with a new one.  Returns true if replaced; false if the
    /// child does not exist.
    fn replace(&mut self, ptr: &TriePtr) -> bool;

    /// Read an encoded instance of this node from a byte stream and instantiate it.
    fn from_bytes<R: Read + Seek>(r: &mut R) -> Result<Self, Error>
    where
        Self: Sized;

    /// Get a reference to the children of this node.
    fn ptrs(&self) -> &[TriePtr];

    /// Get a reference to the children of this node.
    fn path(&self) -> &Vec<u8>;

    /// Construct a TrieNodeType from a TrieNode
    fn as_trie_node_type(&self) -> TrieNodeType;

    /// Get the ptr to the node we were copied from (on COW)
    fn get_cow_ptr(&self) -> Option<&TrieCowPtr>;

    /// Set the ptr to the node we were copied from (on COW)
    fn set_cow_ptr(&mut self, cowptr: TrieCowPtr);

    /// Apply a list of TrieNodePatches to produce this node
    fn apply_patches(
        self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Option<Self>
    where
        Self: Sized;

    /// Encode this node instance into a byte stream and write it to w.
    /// The TriePtrs willl NOT be compressed
    fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[self.id()])?;
        write_ptrs_to_bytes(self.ptrs(), w)?;
        write_path_to_bytes(self.path().as_slice(), w)
    }

    /// Encode this node instance into a byte stream and write it to w.
    /// The TriePtrs will be compressed to the smallest possible size.
    fn write_bytes_compressed<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[set_compressed(self.id())])?;
        write_ptrs_to_bytes_compressed(self.id(), self.ptrs(), w)?;
        write_path_to_bytes(self.path().as_slice(), w)
    }

    #[cfg(test)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut r = Vec::new();
        self.write_bytes(&mut r)
            .expect("Failed to write to byte buffer");
        r
    }

    /// Calculate how many bytes this node will take to encode.
    fn byte_len(&self) -> usize {
        get_ptrs_byte_len(self.ptrs()) + get_path_byte_len(self.path())
    }

    /// Calculate how many bytes this node will take to encode.
    fn byte_len_compressed(&self) -> usize {
        get_ptrs_byte_len_compressed(self.id(), self.ptrs()) + get_path_byte_len(self.path())
    }
}

/// Trait for types that can serialize to consensus bytes
/// This is implemented by `TrieNode`s and `ProofTrieNode`s
///  and allows hash calculation routines to be the same for
///  both types.
/// The type `M` is used for any additional data structures required
///   (BlockHashMap for TrieNode and () for ProofTrieNode)
pub trait ConsensusSerializable<M> {
    /// Encode the consensus-relevant bytes of this node and write it to w.
    fn write_consensus_bytes<W: Write>(
        &self,
        additional_data: &mut M,
        w: &mut W,
    ) -> Result<(), Error>;

    #[cfg(test)]
    fn to_consensus_bytes(&self, additional_data: &mut M) -> Vec<u8> {
        let mut r = Vec::new();
        self.write_consensus_bytes(additional_data, &mut r)
            .expect("Failed to write to byte buffer");
        r
    }
}

impl<T: TrieNode, M: BlockMap> ConsensusSerializable<M> for T {
    fn write_consensus_bytes<W: Write>(&self, map: &mut M, w: &mut W) -> Result<(), Error> {
        w.write_all(&[self.id()])?;
        ptrs_consensus_hash(self.ptrs(), map, w)?;
        write_path_to_bytes(self.path().as_slice(), w)
    }
}

/// Child pointer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TriePtr {
    pub id: u8, // ID of the child.  Will have bit 0x80 set if the child is a back-pointer (in which case, back_block will be nonzero)
    pub chr: u8, // Path character at which this child resides
    pub ptr: u32, // Storage-specific pointer to where the child's encoded bytes can be found
    pub back_block: u32, // Pointer back to the block that contains the child, if it's not in this trie
}

pub const TRIEPTR_SIZE: usize = 10; // full size of a TriePtr
pub const TRIEPTR_SIZE_COMPRESSED: usize = 6; // full size of a compressed TriePtr

pub fn ptrs_fmt(ptrs: &[TriePtr]) -> String {
    let mut strs = vec![];
    for ptr in ptrs.iter() {
        if ptr.id != TrieNodeID::Empty as u8 {
            strs.push(format!(
                "id({})chr({:02x})ptr({})bblk({})",
                ptr.id, ptr.chr, ptr.ptr, ptr.back_block
            ))
        }
    }
    strs.join(",")
}

impl Default for TriePtr {
    #[inline]
    fn default() -> TriePtr {
        TriePtr {
            id: 0,
            chr: 0,
            ptr: 0,
            back_block: 0,
        }
    }
}

impl TriePtr {
    #[inline]
    pub fn new(id: u8, chr: u8, ptr: u32) -> TriePtr {
        TriePtr {
            id,
            chr,
            ptr,
            back_block: 0,
        }
    }

    #[inline]
    pub fn id(&self) -> u8 {
        self.id
    }

    #[inline]
    /// Is the TriePtr an unoccupied slot?
    pub fn is_empty(&self) -> bool {
        self.id() == TrieNodeID::Empty as u8
    }

    #[inline]
    pub fn chr(&self) -> u8 {
        self.chr
    }

    #[inline]
    pub fn ptr(&self) -> u32 {
        self.ptr
    }

    #[inline]
    pub fn back_block(&self) -> u32 {
        self.back_block
    }

    #[inline]
    pub fn from_backptr(&self) -> TriePtr {
        TriePtr {
            id: clear_backptr(self.id),
            chr: self.chr,
            ptr: self.ptr,
            back_block: 0,
        }
    }

    #[inline]
    pub fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[self.id(), self.chr()])?;
        w.write_all(&self.ptr().to_be_bytes())?;
        w.write_all(&self.back_block().to_be_bytes())?;
        Ok(())
    }

    #[inline]
    pub fn write_bytes_compressed<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[set_compressed(self.id()), self.chr()])?;
        w.write_all(&self.ptr().to_be_bytes())?;
        if is_backptr(self.id()) {
            w.write_all(&self.back_block().to_be_bytes())?;
        }
        Ok(())
    }

    /// The parts of a child pointer that are relevant for consensus are only its ID, path
    /// character, and referred-to block hash.  The software doesn't care about the details of how/where
    /// nodes are stored.
    pub fn write_consensus_bytes<W: Write, M: BlockMap>(
        &self,
        block_map: &mut M,
        w: &mut W,
    ) -> Result<(), Error> {
        w.write_all(&[self.id(), self.chr()])?;

        if is_backptr(self.id()) {
            w.write_all(
                block_map
                    .get_block_hash_caching(self.back_block())
                    .expect("Block identifier {} refered to an unknown block. Consensus failure.")
                    .as_bytes(),
            )?;
        } else {
            w.write_all(&[0; BLOCK_HEADER_HASH_ENCODED_SIZE])?;
        }
        Ok(())
    }

    #[inline]
    #[allow(clippy::indexing_slicing)]
    pub fn from_bytes(bytes: &[u8]) -> TriePtr {
        assert!(bytes.len() >= TRIEPTR_SIZE);
        let id = bytes[0];
        let chr = bytes[1];
        let ptr = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let back_block = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

        TriePtr {
            id,
            chr,
            ptr,
            back_block,
        }
    }

    /// Load up this TriePtr from a slice of bytes, assuming that they represent a compresesd
    /// TriePtr.  A TriePtr that is compressed will not have a stored `back_block` field if the
    /// node ID does not have the backptr bit set.
    #[inline]
    #[allow(clippy::indexing_slicing)]
    pub fn from_bytes_compressed(bytes: &[u8]) -> TriePtr {
        assert!(bytes.len() >= TRIEPTR_SIZE_COMPRESSED);
        let id = clear_compressed(bytes[0]);
        let chr = bytes[1];
        let ptr = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);

        let back_block = if is_backptr(id) {
            assert!(bytes.len() >= TRIEPTR_SIZE);
            u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]])
        } else {
            0
        };

        TriePtr {
            id,
            chr,
            ptr,
            back_block,
        }
    }

    /// Load up a compressed TriePtr from a Read object.
    /// Returns Ok(ptr) on success
    /// Returns Err(codec_error::*) on disk I/O failure, or failure to decode the requested bytes
    #[inline]
    pub fn read_bytes_compressed<R: Read>(fd: &mut R) -> Result<TriePtr, codec_error> {
        let id_bits: u8 = read_next(fd)?;
        let id = clear_compressed(id_bits);
        let chr: u8 = read_next(fd)?;
        let ptr_be_bytes: [u8; 4] = read_next(fd)?;
        let ptr = u32::from_be_bytes(ptr_be_bytes);
        let back_block = if is_backptr(id) {
            let bytes: [u8; 4] = read_next(fd)?;
            u32::from_be_bytes(bytes)
        } else {
            0
        };

        Ok(TriePtr {
            id,
            chr,
            ptr,
            back_block,
        })
    }

    /// Size of this TriePtr on disk, if compression is to be used.
    #[inline]
    pub fn compressed_size(&self) -> usize {
        if !is_backptr(self.id) {
            TRIEPTR_SIZE_COMPRESSED
        } else {
            TRIEPTR_SIZE
        }
    }
}

/// Cursor structure for walking down one or more Tries.  This structure helps other parts of the
/// codebase remember which nodes were visited, which blocks they came from, and which pointers
/// were walked.  In particular, it's useful for figuring out where to insert a new node, and which
/// nodes to visit when updating the root node hash.
#[derive(Debug, Clone, PartialEq)]
pub struct TrieCursor<T: MarfTrieId> {
    pub path: TrieHash,                  // the path to walk
    pub index: usize,                    // index into the path
    pub node_path_index: usize,          // index into the currently-visited node's compressed path
    pub nodes: Vec<TrieNodeType>,        // list of nodes this cursor visits
    pub node_ptrs: Vec<TriePtr>,         // list of ptr branches this cursor has taken
    pub block_hashes: Vec<T>, // list of Tries we've visited.  block_hashes[i] corresponds to node_ptrs[i]
    pub last_error: Option<CursorError>, // last error encountered while walking (used to make sure the client calls the right "recovery" method)
}

impl<T: MarfTrieId> TrieCursor<T> {
    pub fn new(path: &TrieHash, root_ptr: TriePtr) -> TrieCursor<T> {
        TrieCursor {
            path: *path,
            index: 0,
            node_path_index: 0,
            nodes: vec![],
            node_ptrs: vec![root_ptr],
            block_hashes: vec![],
            last_error: None,
        }
    }

    /// what point in the path are we at now?
    /// Will be None only if we haven't taken a step yet.
    pub fn chr(&self) -> Option<u8> {
        if self.index > 0 {
            self.path.as_bytes().get(self.index - 1).copied()
        } else {
            None
        }
    }

    /// what offset in the path are we at?
    pub fn tell(&self) -> usize {
        self.index
    }

    /// what is the offset in the node's compressed path?
    pub fn ntell(&self) -> usize {
        self.node_path_index
    }

    /// Are we a the [E]nd [O]f [P]ath?
    pub fn eop(&self) -> bool {
        self.index == self.path.len()
    }

    /// last ptr visited
    pub fn ptr(&self) -> TriePtr {
        // should always be true by construction
        assert!(!self.node_ptrs.is_empty());
        *self.node_ptrs.last().unwrap()
    }

    /// last node visited.
    /// Will only be None if we haven't taken a step yet.
    pub fn node(&self) -> Option<TrieNodeType> {
        self.nodes.last().cloned()
    }

    /// Are we at the [E]nd [O]f a [N]ode's [P]ath?
    pub fn eonp(&self, node: &TrieNodeType) -> bool {
        match node {
            TrieNodeType::Leaf(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node4(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node16(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node48(ref data) => self.node_path_index == data.path.len(),
            TrieNodeType::Node256(ref data) => self.node_path_index == data.path.len(),
        }
    }

    /// Walk to the next node, following its compressed path as far as we can and then walking to
    /// its child pointer.  If we successfully follow the path, then return the pointer we reached.
    /// Otherwise, if we reach the end of the path, return None.  If the path diverges or a node
    /// cannot be found, then return an Err.
    ///
    /// This method does not follow back-pointers, and will return Err if a back-pointer is
    /// reached.  The caller will need to manually call walk() on the last node visited to get the
    /// back-pointer, shunt to the node it points to, and then call walk_backptr_step_backptr() to
    /// record the back-pointer that was followed.  Once the back-pointer has been followed,
    /// caller should call walk_backptr_step_finish().  This is specifically relevant to the MARF,
    /// not to the individual tries.
    pub fn walk(
        &mut self,
        node: &TrieNodeType,
        block_hash: &T,
    ) -> Result<Option<TriePtr>, CursorError> {
        // can only be called if we called the appropriate "repair" method or if there is no error
        assert!(self.last_error.is_none());

        trace!("cursor: walk: node = {:?} block = {:?}", node, block_hash);

        // walk this node
        self.nodes.push((*node).clone());
        self.node_path_index = 0;

        if self.index >= self.path.len() {
            trace!("cursor: out of path");
            return Ok(None);
        }

        let node_path = node.path_bytes();
        let path_bytes = self.path.as_bytes();

        // consume as much of the compressed path as we can
        for (_i, path_set) in node_path.iter().enumerate() {
            let Some(path_head) = path_bytes.get(self.index) else {
                trace!("cursor: out of path");
                return Ok(None);
            };
            if path_set != path_head {
                // diverged
                trace!("cursor: diverged({} != {}): i = {_i}, self.index = {}, self.node_path_index = {}", to_hex(node_path), to_hex(path_bytes), self.index, self.node_path_index);
                self.last_error = Some(CursorError::PathDiverged);
                return Err(CursorError::PathDiverged);
            }
            self.index += 1;
            self.node_path_index += 1;
        }

        // walked to end of the node's compressed path.
        // Find the pointer to the next node.
        if let Some(chr) = path_bytes.get(self.index) {
            self.index += 1;
            let mut ptr_opt = node.walk(*chr);

            let do_walk = match &ptr_opt {
                Some(ptr) => {
                    if !is_backptr(ptr.id()) {
                        // not going to follow a back-pointer
                        self.node_ptrs.push(*ptr);
                        self.block_hashes.push(block_hash.clone());
                        true
                    } else {
                        // the caller will need to follow the backptr, and call
                        // repair_backptr_step_backptr() for each node visited, and then repair_backptr_finish()
                        // once the final ptr and block_hash are discovered.
                        self.last_error = Some(CursorError::BackptrEncountered(*ptr));
                        false
                    }
                }
                None => {
                    self.last_error = Some(CursorError::ChrNotFound);
                    false
                }
            };

            if !do_walk {
                ptr_opt = None;
            }

            if ptr_opt.is_none() {
                assert!(self.last_error.is_some());

                trace!(
                    "cursor: not found: chr = 0x{:02x}, self.index = {}, self.path = {:?}",
                    chr,
                    self.index - 1,
                    &path_bytes
                );
                return Err(self.last_error.clone().unwrap());
            } else {
                return Ok(ptr_opt);
            }
        } else {
            trace!("cursor: now out of path");
            return Ok(None);
        }
    }

    /// Replace the last-visited node and ptr within this trie.  Used when doing a copy-on-write or
    /// promoting a node, so the cursor state accurately reflects the nodes and tries visited.
    #[inline]
    pub fn repair_retarget(&mut self, node: &TrieNodeType, ptr: &TriePtr, hash: &T) {
        // this can only be called if we failed to walk to a node (this method _should not_ be
        // called if we walked to a backptr).
        if Some(CursorError::ChrNotFound) != self.last_error
            && Some(CursorError::PathDiverged) != self.last_error
        {
            eprintln!("{:?}", &self.last_error);
            panic!();
        }

        self.nodes.pop();
        self.node_ptrs.pop();
        self.block_hashes.pop();

        self.nodes.push(node.clone());
        self.node_ptrs.push(*ptr);
        self.block_hashes.push(hash.clone());

        self.last_error = None;
    }

    /// Record that a node was walked to by way of a back-pointer.
    /// next_node should be the node walked to.
    /// ptr is the ptr we'll be walking from, off of next_node.
    /// block_hash is the block where next_node came from.
    #[inline]
    pub fn repair_backptr_step_backptr(
        &mut self,
        next_node: &TrieNodeType,
        ptr: &TriePtr,
        block_hash: T,
    ) {
        // this can only be called if we walked to a backptr.
        // If it's anything else, we're in trouble.
        if Some(CursorError::ChrNotFound) == self.last_error
            || Some(CursorError::PathDiverged) == self.last_error
        {
            eprintln!("{:?}", &self.last_error);
            panic!();
        }

        trace!(
            "Cursor: repair_backptr_step_backptr ptr={:?} block_hash={:?} next_node={:?}",
            ptr,
            &block_hash,
            next_node
        );

        let backptr = TriePtr::new(set_backptr(ptr.id()), ptr.chr(), ptr.ptr()); // set_backptr() informs update_root_hash() to skip this node
        self.node_ptrs.push(backptr);
        self.block_hashes.push(block_hash);

        self.nodes.push(next_node.clone());
    }

    /// Record that we landed on a non-backptr from a backptr.
    /// ptr is a non-backptr that refers to the node we landed on.
    #[inline]
    pub fn repair_backptr_finish(&mut self, ptr: &TriePtr, block_hash: T) {
        // this can only be called if we walked to a backptr.
        // If it's anything else, we're in trouble.
        if Some(CursorError::ChrNotFound) == self.last_error
            || Some(CursorError::PathDiverged) == self.last_error
        {
            eprintln!("{:?}", &self.last_error);
            panic!();
        }
        assert!(!is_backptr(ptr.id()));

        trace!("Cursor: repair_backptr_finish ptr={ptr:?} block_hash={block_hash:?}");

        self.node_ptrs.push(*ptr);
        self.block_hashes.push(block_hash);

        self.last_error = None;
    }
}

impl PartialEq for TrieLeaf {
    fn eq(&self, other: &TrieLeaf) -> bool {
        self.path == other.path && self.data.as_bytes() == other.data.as_bytes()
    }
}

impl TrieLeaf {
    pub fn new(path: &[u8], data: &[u8]) -> TrieLeaf {
        assert!(data.len() <= 40);
        let mut bytes = [0u8; 40];
        bytes.copy_from_slice(data);
        TrieLeaf {
            path: path.to_owned(),
            data: MARFValue(bytes),
        }
    }

    pub fn from_value(path: &[u8], value: MARFValue) -> TrieLeaf {
        TrieLeaf {
            path: path.to_owned(),
            data: value,
        }
    }
}

impl fmt::Debug for TrieLeaf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieLeaf(path={} data={})",
            &to_hex(&self.path),
            &self.data.to_hex()
        )
    }
}

impl StacksMessageCodec for TrieLeaf {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.path.consensus_serialize(fd)?;
        self.data.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TrieLeaf, codec_error> {
        let path = read_next(fd)?;
        let data = read_next(fd)?;

        Ok(TrieLeaf { path, data })
    }
}

/// Trie node with four children
#[derive(Clone, PartialEq)]
pub struct TrieNode4 {
    pub path: Vec<u8>,
    pub ptrs: [TriePtr; 4],
    /// If this node was created by copy-on-write, then this points to the node it was copied from.
    pub cowptr: Option<TrieCowPtr>,
    /// List of patches applied to this node.  Fields are (node block ID, pointer to node, patch itself)
    pub patches: Vec<(u32, TriePtr, TrieNodePatch)>,
}

impl fmt::Debug for TrieNode4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode4(path={} ptrs={})",
            &to_hex(&self.path),
            ptrs_fmt(&self.ptrs)
        )
    }
}

impl TrieNode4 {
    pub fn new(path: &[u8]) -> TrieNode4 {
        TrieNode4 {
            path: path.to_owned(),
            ptrs: [TriePtr::default(); 4],
            cowptr: None,
            patches: vec![],
        }
    }
}

/// Trie node with 16 children
#[derive(Clone, PartialEq)]
pub struct TrieNode16 {
    pub path: Vec<u8>,
    pub ptrs: [TriePtr; 16],
    /// If this node was created by copy-on-write, then this points to the node it was copied from.
    pub cowptr: Option<TrieCowPtr>,
    /// List of patches applied to this node.  Fields are (node block ID, pointer to node, patch itself)
    pub patches: Vec<(u32, TriePtr, TrieNodePatch)>,
}

impl fmt::Debug for TrieNode16 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode16(path={} ptrs={})",
            &to_hex(&self.path),
            ptrs_fmt(&self.ptrs)
        )
    }
}

impl TrieNode16 {
    pub fn new(path: &[u8]) -> TrieNode16 {
        TrieNode16 {
            path: path.to_owned(),
            ptrs: [TriePtr::default(); 16],
            cowptr: None,
            patches: vec![],
        }
    }

    /// Promote a Node4 to a Node16
    pub fn from_node4(node4: &TrieNode4) -> TrieNode16 {
        let mut ptrs = [TriePtr::default(); 16];
        ptrs[..4].copy_from_slice(&node4.ptrs[..4]);
        TrieNode16 {
            path: node4.path.clone(),
            ptrs,
            cowptr: None,
            patches: vec![],
        }
    }
}

/// Trie node with 48 children
#[derive(Clone)]
pub struct TrieNode48 {
    pub path: Vec<u8>,
    indexes: [i8; 256], // indexes[i], if non-negative, is an index into ptrs.
    pub ptrs: [TriePtr; 48],
    /// If this node was created by copy-on-write, then this points to the node it was copied from.
    pub cowptr: Option<TrieCowPtr>,
    /// List of patches applied to this node.  Fields are (node block ID, pointer to node, patch itself)
    pub patches: Vec<(u32, TriePtr, TrieNodePatch)>,
}

impl fmt::Debug for TrieNode48 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode48(path={} ptrs={})",
            &to_hex(&self.path),
            ptrs_fmt(&self.ptrs)
        )
    }
}

impl PartialEq for TrieNode48 {
    fn eq(&self, other: &TrieNode48) -> bool {
        self.path == other.path && self.ptrs == other.ptrs && self.indexes == other.indexes
    }
}

impl TrieNode48 {
    pub fn new(path: &[u8]) -> TrieNode48 {
        TrieNode48 {
            path: path.to_owned(),
            indexes: [-1; 256],
            ptrs: [TriePtr::default(); 48],
            cowptr: None,
            patches: vec![],
        }
    }

    /// Promote a node16 to a node48
    // allow indexing: this function only indexes constant-size arrays
    // with constant-sized indexes
    #[allow(clippy::indexing_slicing)]
    pub fn from_node16(node16: &TrieNode16) -> TrieNode48 {
        let mut ptrs = [TriePtr::default(); 48];
        let mut indexes = [-1i8; 256];
        for i in 0..16 {
            ptrs[i] = node16.ptrs[i];
            indexes[ptrs[i].chr() as usize] = i as i8;
        }
        TrieNode48 {
            path: node16.path.clone(),
            indexes,
            ptrs,
            cowptr: None,
            patches: vec![],
        }
    }
}

/// Trie node with 256 children
#[derive(Clone)]
pub struct TrieNode256 {
    pub path: Vec<u8>,
    pub ptrs: [TriePtr; 256],
    /// If this node was created by copy-on-write, then this points to the node it was copied from.
    pub cowptr: Option<TrieCowPtr>,
    /// List of patches applied to this node.  Fields are (node block ID, pointer to node, patch itself)
    pub patches: Vec<(u32, TriePtr, TrieNodePatch)>,
}

impl fmt::Debug for TrieNode256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode256(path={} ptrs={})",
            &to_hex(&self.path),
            ptrs_fmt(&self.ptrs)
        )
    }
}

impl PartialEq for TrieNode256 {
    fn eq(&self, other: &TrieNode256) -> bool {
        self.path == other.path && self.ptrs == other.ptrs
    }
}

impl TrieNode256 {
    pub fn new(path: &[u8]) -> TrieNode256 {
        TrieNode256 {
            path: path.to_owned(),
            ptrs: [TriePtr::default(); 256],
            cowptr: None,
            patches: vec![],
        }
    }

    // allow indexing because this function operates on
    //  fixed size arrays (256 array can always be indexed by u8)
    #[allow(clippy::indexing_slicing)]
    pub fn from_node4(node4: &TrieNode4) -> TrieNode256 {
        let mut ptrs = [TriePtr::default(); 256];
        for node4_ptr in node4.ptrs.iter() {
            let c = node4_ptr.chr();
            ptrs[c as usize] = *node4_ptr;
        }
        TrieNode256 {
            path: node4.path.clone(),
            ptrs,
            cowptr: None,
            patches: vec![],
        }
    }

    /// Promote a node48 to a node256
    // allow indexing because this function operates on
    //  fixed size arrays (256 array can always be indexed by u8)
    #[allow(clippy::indexing_slicing)]
    pub fn from_node48(node48: &TrieNode48) -> TrieNode256 {
        let mut ptrs = [TriePtr::default(); 256];
        for node48_ptr in node48.ptrs.iter() {
            let c = node48_ptr.chr();
            ptrs[c as usize] = *node48_ptr;
        }
        TrieNode256 {
            path: node48.path.clone(),
            ptrs,
            cowptr: None,
            patches: vec![],
        }
    }
}

/// This is a non-consensus "patch node" that applies a diff atop a base node.  There can be up to
/// MAX_PATCH_DEPTH patch nodes applied atop the base node.
#[derive(Clone, PartialEq)]
pub struct TrieNodePatch {
    /// Pointer to the node we're patching (will always be a back-block ptr)
    pub ptr: TriePtr,
    /// Field of ptrs to insert atop the base node
    pub ptr_diff: Vec<TriePtr>,
}

impl fmt::Debug for TrieNodePatch {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNodePatch(ptr={} ptr_diff={})",
            &ptrs_fmt(&[self.ptr]),
            ptrs_fmt(&self.ptr_diff)
        )
    }
}

impl StacksMessageCodec for TrieNodePatch {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(TrieNodeID::Patch as u8))?;
        self.ptr
            .write_bytes_compressed(fd)
            .map_err(|e| codec_error::SerializeError(format!("Failed to serialize .ptr: {e:?}")))?;

        let num_ptrs = self.ptr_diff.len();
        if num_ptrs >= 256 {
            return Err(codec_error::SerializeError(
                "Cannot serialize TrieNodePatch with more than 256 ptrs".to_string(),
            ));
        }
        // SAFETY: checked that num_ptrs < 256
        let num_ptrs_u8 = u8::try_from(num_ptrs).expect("infallible");
        write_next(fd, &num_ptrs_u8).map_err(|e| {
            codec_error::SerializeError(format!("Failed to serialize .ptr_diff.len(): {e:?}"))
        })?;

        for ptr in self.ptr_diff.iter() {
            ptr.write_bytes_compressed(fd).map_err(|e| {
                codec_error::SerializeError(format!("Failed to serialize ptr in .ptr_diff: {e:?}"))
            })?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, codec_error> {
        let id: u8 = read_next(fd)?;
        if id != TrieNodeID::Patch as u8 {
            return Err(codec_error::DeserializeError(
                "Did not read a TrieNodeID::Patch".to_string(),
            ));
        }

        let ptr = TriePtr::read_bytes_compressed(fd)?;
        let num_ptrs: u8 = read_next(fd)?;
        let num_ptrs = usize::try_from(num_ptrs).expect("infallible");
        let mut ptr_diff: Vec<TriePtr> = Vec::with_capacity(num_ptrs);
        for _ in 0..num_ptrs {
            ptr_diff.push(TriePtr::read_bytes_compressed(fd)?);
        }
        Ok(Self { ptr, ptr_diff })
    }
}

/// Turn each non-empty, non-backptr in `ptrs` into a backptr pointing at `child_block_id`
pub(crate) fn node_copy_update_ptrs(ptrs: &mut [TriePtr], child_block_id: u32) {
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

/// Given the current block ID, convert every backptr pointer whose back_block is equal to
/// `cur_block_id` to a normal pointer.  This is used when applying patches.
fn node_normalize_ptrs(ptrs: &mut [TriePtr], cur_block_id: u32) {
    for ptr in ptrs.iter_mut() {
        if is_backptr(ptr.id) && ptr.back_block == cur_block_id {
            // normalize
            ptr.id = clear_backptr(ptr.id);
            ptr.back_block = 0;
        }
    }
}

impl TrieNodePatch {
    /// Compute the difference between `old_ptrs` and `new_ptrs`. In particular, if a pointer in
    /// `new_ptrs` is in the same block as indicatd by `old_node_ptr`, this code will first need to
    /// normalize it (i.e. convert it into a non-backpointer) in order to compare it against the
    /// corresponding pointer in `old_ptrs` (which might have that very same pointer, but not yet
    /// made into a backptr by a COW)
    fn make_ptr_diff(
        old_node_ptr: &TriePtr,
        old_ptrs: &[TriePtr],
        new_ptrs: &[TriePtr],
    ) -> Vec<TriePtr> {
        let mut ret = Vec::with_capacity(new_ptrs.len());
        let mut mapped: [Option<&TriePtr>; 256] = [None; 256];
        for old_ptr in old_ptrs.iter() {
            // SAFETY: chr() is a u8, so it's in range [0, 256)
            if !old_ptr.is_empty() {
                let mapped_ptr = mapped
                    .get_mut(old_ptr.chr() as usize)
                    .expect("infallible: mapped has 256 elements and .chr() is a u8");
                *mapped_ptr = Some(old_ptr);
            }
        }

        for new_ptr in new_ptrs.iter() {
            if new_ptr.is_empty() {
                continue;
            }
            // SAFETY: chr() is a u8, so it's in range [0, 256)
            if let Some(old_ptr) = *mapped
                .get(new_ptr.chr() as usize)
                .expect("infallible: mapped has 256 elements and .chr() is a u8")
            {
                if !is_backptr(old_ptr.id())
                    && is_backptr(new_ptr.id())
                    && new_ptr.back_block == old_node_ptr.back_block
                {
                    // new_ptr may be the backptr-ified version of old_ptr
                    let mut normalized_new_ptr =
                        TriePtr::new(clear_ctrl_bits(new_ptr.id()), new_ptr.chr(), new_ptr.ptr());
                    normalized_new_ptr.back_block = 0;
                    if *old_ptr != normalized_new_ptr {
                        trace!(
                            "new overritten ptr: {:?} != {:?}",
                            &normalized_new_ptr,
                            old_ptr
                        );
                        ret.push(*new_ptr);
                    }
                } else {
                    if old_ptr != new_ptr {
                        trace!("new overritten ptr: {:?} != {:?}", &new_ptr, old_ptr);
                        ret.push(*new_ptr);
                    }
                }
            } else {
                ret.push(*new_ptr);
            }
        }
        ret
    }

    /// Create a patch from one node4 to another
    pub fn from_node4(old_node_ptr: TriePtr, old_node: &TrieNode4, new_node: &TrieNode4) -> Self {
        let ptr_diff = Self::make_ptr_diff(&old_node_ptr, old_node.ptrs(), new_node.ptrs());
        Self {
            ptr: old_node_ptr,
            ptr_diff: ptr_diff,
        }
    }

    /// Create a patch from one node16 to another
    pub fn from_node16(
        old_node_ptr: TriePtr,
        old_node: &TrieNode16,
        new_node: &TrieNode16,
    ) -> Self {
        let ptr_diff = Self::make_ptr_diff(&old_node_ptr, old_node.ptrs(), new_node.ptrs());
        Self {
            ptr: old_node_ptr,
            ptr_diff: ptr_diff,
        }
    }

    /// Create a patch from one node48 to another
    pub fn from_node48(
        old_node_ptr: TriePtr,
        old_node: &TrieNode48,
        new_node: &TrieNode48,
    ) -> Self {
        let ptr_diff = Self::make_ptr_diff(&old_node_ptr, old_node.ptrs(), new_node.ptrs());
        Self {
            ptr: old_node_ptr,
            ptr_diff: ptr_diff,
        }
    }

    /// Create a patch from one node256 to another
    pub fn from_node256(
        old_node_ptr: TriePtr,
        old_node: &TrieNode256,
        new_node: &TrieNode256,
    ) -> Self {
        let ptr_diff = Self::make_ptr_diff(&old_node_ptr, old_node.ptrs(), new_node.ptrs());
        Self {
            ptr: old_node_ptr,
            ptr_diff: ptr_diff,
        }
    }

    /// Create a patch from one nodetype to a another.  If they're not the same nodetype, then this
    /// function returns None.
    pub fn try_from_nodetype(
        old_node_ptr: TriePtr,
        old_node: &TrieNodeType,
        new_node: &TrieNodeType,
    ) -> Option<Self> {
        if clear_ctrl_bits(old_node.id()) != clear_ctrl_bits(new_node.id()) {
            return None;
        }

        let patch_opt = match (old_node, new_node) {
            (TrieNodeType::Node4(old_data), TrieNodeType::Node4(new_data)) => {
                Some(Self::from_node4(old_node_ptr, old_data, new_data))
            }
            (TrieNodeType::Node16(old_data), TrieNodeType::Node16(new_data)) => {
                Some(Self::from_node16(old_node_ptr, old_data, new_data))
            }
            (TrieNodeType::Node48(old_data), TrieNodeType::Node48(new_data)) => {
                Some(Self::from_node48(old_node_ptr, old_data, new_data))
            }
            (TrieNodeType::Node256(old_data), TrieNodeType::Node256(new_data)) => {
                Some(Self::from_node256(old_node_ptr, old_data, new_data))
            }
            (_, _) => None,
        };
        let Some(patch) = patch_opt else {
            return None;
        };
        if patch.ptr_diff.len() == 0 {
            return None;
        }
        Some(patch)
    }

    /// Create a patch from one patch ao a node
    pub fn try_from_patch(
        old_patch_ptr: TriePtr,
        old_patch: &TrieNodePatch,
        new_node: &TrieNodeType,
    ) -> Option<Self> {
        if clear_ctrl_bits(old_patch.ptr.id) != clear_ctrl_bits(new_node.id()) {
            return None;
        }

        let ptr_diff = Self::make_ptr_diff(&old_patch_ptr, &old_patch.ptr_diff, new_node.ptrs());
        let patch = Self {
            ptr: old_patch_ptr,
            ptr_diff,
        };
        if patch.ptr_diff.len() == 0 {
            return None;
        }
        return Some(patch);
    }

    /// Apply this patch to a node4, given the node, block ID where the patch was found, and block
    /// ID where the node was written.
    pub fn apply_node4(
        &self,
        mut old_node: TrieNode4,
        patch_block_id: u32,
        cur_block_id: u32,
    ) -> Option<TrieNode4> {
        trace!("Apply patch {self:?} read from block ID {patch_block_id} to {old_node:?}");
        node_copy_update_ptrs(&mut old_node.ptrs, self.ptr.back_block);
        for ptr in self.ptr_diff.iter() {
            if !old_node.insert(ptr) {
                return None;
            }
        }
        node_copy_update_ptrs(&mut old_node.ptrs, patch_block_id);
        node_normalize_ptrs(&mut old_node.ptrs, cur_block_id);
        trace!("Patched up to {old_node:?}");
        Some(old_node)
    }

    /// Apply this patch to a node16, given the node, block ID where the patch was found, and block
    /// ID where the node was written.
    pub fn apply_node16(
        &self,
        mut old_node: TrieNode16,
        patch_block_id: u32,
        cur_block_id: u32,
    ) -> Option<TrieNode16> {
        trace!("Apply patch {self:?} read from block ID {patch_block_id} to {old_node:?}");
        node_copy_update_ptrs(&mut old_node.ptrs, self.ptr.back_block);
        for ptr in self.ptr_diff.iter() {
            if !old_node.insert(ptr) {
                return None;
            }
        }
        node_copy_update_ptrs(&mut old_node.ptrs, patch_block_id);
        node_normalize_ptrs(&mut old_node.ptrs, cur_block_id);
        trace!("Patched up to {old_node:?}");
        Some(old_node)
    }

    /// Apply this patch to a node48, given the node, block ID where the patch was found, and block
    /// ID where the node was written.
    pub fn apply_node48(
        &self,
        mut old_node: TrieNode48,
        patch_block_id: u32,
        cur_block_id: u32,
    ) -> Option<TrieNode48> {
        trace!("Apply patch {self:?} read from block ID {patch_block_id} to {old_node:?}");
        node_copy_update_ptrs(&mut old_node.ptrs, self.ptr.back_block);
        for ptr in self.ptr_diff.iter() {
            if !old_node.insert(ptr) {
                return None;
            }
        }
        node_copy_update_ptrs(&mut old_node.ptrs, patch_block_id);
        node_normalize_ptrs(&mut old_node.ptrs, cur_block_id);
        trace!("Patched up to {old_node:?}");
        Some(old_node)
    }

    /// Apply this patch to a node256, given the node, block ID where the patch was found, and block
    /// ID where the node was written.
    pub fn apply_node256(
        &self,
        mut old_node: TrieNode256,
        patch_block_id: u32,
        cur_block_id: u32,
    ) -> Option<TrieNode256> {
        trace!("Apply patch {self:?} read from block ID {patch_block_id} to {old_node:?}");
        node_copy_update_ptrs(&mut old_node.ptrs, self.ptr.back_block);
        for ptr in self.ptr_diff.iter() {
            if !old_node.insert(ptr) {
                return None;
            }
        }
        node_copy_update_ptrs(&mut old_node.ptrs, patch_block_id);
        node_normalize_ptrs(&mut old_node.ptrs, cur_block_id);
        trace!("Patched up to {old_node:?}");
        Some(old_node)
    }

    /// Compute the size of the TriePatchNode. Its pointers are always compressed.
    #[inline]
    pub fn size(&self) -> usize {
        // ID
        let mut sz = 1;
        // previous node ptr
        sz += self.ptr.compressed_size();
        // length prefix
        sz += 1;
        // ptr_diff
        for ptr in self.ptr_diff.iter() {
            sz += ptr.compressed_size();
        }
        sz
    }

    /// Load a TrieNodePatch from a Read object
    /// Returns Ok(Self) on success
    /// Returns Err(codec_error::*) on failure to decode the bytes
    /// Returns Err(IOError(..)) on disk I/O failure
    pub fn from_bytes<R: Read>(f: &mut R) -> Result<Self, Error> {
        Self::consensus_deserialize(f)
            .map_err(|e| Error::CorruptionError(format!("Codec error: {e:?}")))
    }
}

impl TrieNode for TrieNode4 {
    fn id(&self) -> u8 {
        TrieNodeID::Node4 as u8
    }

    fn empty() -> TrieNode4 {
        TrieNode4 {
            path: vec![],
            ptrs: [TriePtr::default(); 4],
            cowptr: None,
            patches: vec![],
        }
    }

    fn walk(&self, chr: u8) -> Option<TriePtr> {
        for ptr in self.ptrs.iter() {
            if !ptr.is_empty() && ptr.chr() == chr {
                return Some(*ptr);
            }
        }
        None
    }

    fn from_bytes<R: Read + Seek>(r: &mut R) -> Result<TrieNode4, Error> {
        let mut ptrs_slice = [TriePtr::default(); 4];
        ptrs_from_bytes(TrieNodeID::Node4 as u8, r, &mut ptrs_slice)?;
        let path = path_from_bytes(r)?;

        Ok(TrieNode4 {
            path,
            ptrs: ptrs_slice,
            cowptr: None,
            patches: vec![],
        })
    }

    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }

        for slot in self.ptrs.iter_mut() {
            if slot.is_empty() {
                *slot = *ptr;
                return true;
            }
        }
        false
    }

    fn replace(&mut self, ptr: &TriePtr) -> bool {
        for slot in self.ptrs.iter_mut() {
            if !slot.is_empty() && slot.chr() == ptr.chr() {
                *slot = *ptr;
                return true;
            }
        }
        false
    }

    fn ptrs(&self) -> &[TriePtr] {
        &self.ptrs
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Node4(self.clone())
    }

    fn get_cow_ptr(&self) -> Option<&TrieCowPtr> {
        self.cowptr.as_ref()
    }

    fn set_cow_ptr(&mut self, cowptr: TrieCowPtr) {
        self.cowptr.replace(cowptr);
    }

    fn apply_patches(
        self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Option<Self> {
        let mut node = self;
        for (patch_block_id, _, patch) in patches.iter() {
            let Some(next_node) = patch.apply_node4(node, *patch_block_id, cur_block_id) else {
                return None;
            };
            node = next_node;
        }
        node.patches.extend_from_slice(patches);
        Some(node)
    }
}

impl TrieNode for TrieNode16 {
    fn id(&self) -> u8 {
        TrieNodeID::Node16 as u8
    }

    fn empty() -> TrieNode16 {
        TrieNode16 {
            path: vec![],
            ptrs: [TriePtr::default(); 16],
            cowptr: None,
            patches: vec![],
        }
    }

    fn walk(&self, chr: u8) -> Option<TriePtr> {
        for ptr in self.ptrs.iter() {
            if !ptr.is_empty() && ptr.chr() == chr {
                return Some(*ptr);
            }
        }
        None
    }

    fn from_bytes<R: Read + Seek>(r: &mut R) -> Result<TrieNode16, Error> {
        let mut ptrs_slice = [TriePtr::default(); 16];
        ptrs_from_bytes(TrieNodeID::Node16 as u8, r, &mut ptrs_slice)?;

        let path = path_from_bytes(r)?;

        Ok(TrieNode16 {
            path,
            ptrs: ptrs_slice,
            cowptr: None,
            patches: vec![],
        })
    }

    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }

        for slot in self.ptrs.iter_mut() {
            if slot.is_empty() {
                *slot = *ptr;
                return true;
            }
        }
        false
    }

    fn replace(&mut self, ptr: &TriePtr) -> bool {
        for slot in self.ptrs.iter_mut() {
            if !slot.is_empty() && slot.chr() == ptr.chr() {
                *slot = *ptr;
                return true;
            }
        }
        false
    }

    fn ptrs(&self) -> &[TriePtr] {
        &self.ptrs
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Node16(self.clone())
    }

    fn get_cow_ptr(&self) -> Option<&TrieCowPtr> {
        self.cowptr.as_ref()
    }

    fn set_cow_ptr(&mut self, cowptr: TrieCowPtr) {
        self.cowptr.replace(cowptr);
    }

    fn apply_patches(
        self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Option<Self> {
        let mut node = self;
        for (patch_block_id, _, patch) in patches.iter() {
            let Some(next_node) = patch.apply_node16(node, *patch_block_id, cur_block_id) else {
                return None;
            };
            node = next_node;
        }
        node.patches.extend_from_slice(patches);
        Some(node)
    }
}

impl TrieNode for TrieNode48 {
    fn id(&self) -> u8 {
        TrieNodeID::Node48 as u8
    }

    fn empty() -> TrieNode48 {
        TrieNode48 {
            path: vec![],
            indexes: [-1; 256],
            ptrs: [TriePtr::default(); 48],
            cowptr: None,
            patches: vec![],
        }
    }

    // allow indexing here because self.indexes is an array of
    // 256, so it can always return a u8
    #[allow(clippy::indexing_slicing)]
    fn walk(&self, chr: u8) -> Option<TriePtr> {
        let idx = self.indexes[chr as usize];
        let ptr = self.ptrs.get(usize::try_from(idx).ok()?)?;
        if ptr.is_empty() {
            return None;
        }
        Some(*ptr)
    }

    fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[self.id()])?;
        write_ptrs_to_bytes(self.ptrs(), w)?;

        for i in self.indexes.iter() {
            w.write_all(&[*i as u8])?;
        }

        write_path_to_bytes(self.path().as_slice(), w)
    }

    fn write_bytes_compressed<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[set_compressed(self.id())])?;
        write_ptrs_to_bytes_compressed(self.id(), self.ptrs(), w)?;

        for i in self.indexes.iter() {
            w.write_all(&[*i as u8])?;
        }

        write_path_to_bytes(self.path().as_slice(), w)
    }

    fn byte_len(&self) -> usize {
        get_ptrs_byte_len(&self.ptrs) + 256 + get_path_byte_len(&self.path)
    }

    fn byte_len_compressed(&self) -> usize {
        get_ptrs_byte_len_compressed(self.id(), &self.ptrs) + 256 + get_path_byte_len(&self.path)
    }

    #[allow(clippy::indexing_slicing)]
    fn from_bytes<R: Read + Seek>(r: &mut R) -> Result<TrieNode48, Error> {
        let mut ptrs_slice = [TriePtr::default(); 48];
        ptrs_from_bytes(TrieNodeID::Node48 as u8, r, &mut ptrs_slice)?;

        let mut indexes = [0u8; 256];
        r.read_exact(&mut indexes).inspect_err(|e| {
            error!("I/O error reading TrieNode48 indexes: {e:?}");
        })?;

        let path = path_from_bytes(r)?;

        let indexes_slice: [i8; 256] = indexes.map(|i| i as i8);

        let all_ptrs_valid = ptrs_slice.iter().all(|ptr| {
            ptr.is_empty()
                || indexes_slice[ptr.chr() as usize] >= 0 && indexes_slice[ptr.chr() as usize] < 48
        });
        if !all_ptrs_valid {
            return Err(Error::CorruptionError(
                "Node48: corrupt index array: invalid index value".to_string(),
            ));
        }

        let all_indexes_valid = indexes_slice.iter().all(|index| {
            let Ok(index) = usize::try_from(*index) else {
                // if the index is < 0, then no corresponding ptr is
                // stored in the slice and so the index is valid
                return true;
            };
            let Some(ptr) = ptrs_slice.get(index) else {
                // if the index is out of bounds, it is invalid
                return false;
            };
            // if the index references a pointer, it must reference a
            // non-empty one
            !ptr.is_empty()
        });
        if !all_indexes_valid {
            return Err(Error::CorruptionError(
                "Node48: corrupt index array: index points to empty node".to_string(),
            ));
        }

        Ok(TrieNode48 {
            path,
            indexes: indexes_slice,
            ptrs: ptrs_slice,
            cowptr: None,
            patches: vec![],
        })
    }

    #[allow(clippy::indexing_slicing)]
    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }

        let c = ptr.chr();
        for i in 0..48 {
            if self.ptrs[i].is_empty() {
                self.indexes[c as usize] = i as i8;
                self.ptrs[i] = *ptr;
                return true;
            }
        }
        false
    }

    #[allow(clippy::indexing_slicing)]
    fn replace(&mut self, ptr: &TriePtr) -> bool {
        let i = self.indexes[ptr.chr() as usize];
        if i >= 0 {
            self.ptrs[i as usize] = *ptr;
            true
        } else {
            false
        }
    }

    fn ptrs(&self) -> &[TriePtr] {
        &self.ptrs
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Node48(Box::new(self.clone()))
    }

    fn get_cow_ptr(&self) -> Option<&TrieCowPtr> {
        self.cowptr.as_ref()
    }

    fn set_cow_ptr(&mut self, cowptr: TrieCowPtr) {
        self.cowptr.replace(cowptr);
    }

    fn apply_patches(
        self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Option<Self> {
        let mut node = self;
        for (patch_block_id, _, patch) in patches.iter() {
            let Some(next_node) = patch.apply_node48(node, *patch_block_id, cur_block_id) else {
                return None;
            };
            node = next_node;
        }
        node.patches.extend_from_slice(patches);
        Some(node)
    }
}

impl TrieNode for TrieNode256 {
    fn id(&self) -> u8 {
        TrieNodeID::Node256 as u8
    }

    fn empty() -> TrieNode256 {
        TrieNode256 {
            path: vec![],
            ptrs: [TriePtr::default(); 256],
            cowptr: None,
            patches: vec![],
        }
    }

    #[allow(clippy::indexing_slicing)]
    fn walk(&self, chr: u8) -> Option<TriePtr> {
        let ptr = self.ptrs.get(chr as usize)?;
        if ptr.is_empty() {
            return None;
        }
        Some(*ptr)
    }

    fn from_bytes<R: Read + Seek>(r: &mut R) -> Result<TrieNode256, Error> {
        let mut ptrs_slice = [TriePtr::default(); 256];
        ptrs_from_bytes(TrieNodeID::Node256 as u8, r, &mut ptrs_slice)?;

        let path = path_from_bytes(r)?;

        Ok(TrieNode256 {
            path,
            ptrs: ptrs_slice,
            cowptr: None,
            patches: vec![],
        })
    }

    #[allow(clippy::indexing_slicing)]
    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }
        let c = ptr.chr() as usize;
        self.ptrs[c] = *ptr;
        true
    }

    #[allow(clippy::indexing_slicing)]
    fn replace(&mut self, ptr: &TriePtr) -> bool {
        let c = ptr.chr() as usize;
        if !self.ptrs[c].is_empty() && self.ptrs[c].chr() == ptr.chr() {
            self.ptrs[c] = *ptr;
            true
        } else {
            false
        }
    }

    fn ptrs(&self) -> &[TriePtr] {
        &self.ptrs
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Node256(Box::new(self.clone()))
    }

    fn get_cow_ptr(&self) -> Option<&TrieCowPtr> {
        self.cowptr.as_ref()
    }

    fn set_cow_ptr(&mut self, cowptr: TrieCowPtr) {
        self.cowptr.replace(cowptr);
    }

    fn apply_patches(
        self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Option<Self> {
        let mut node = self;
        for (patch_block_id, _, patch) in patches.iter() {
            let Some(next_node) = patch.apply_node256(node, *patch_block_id, cur_block_id) else {
                return None;
            };
            node = next_node;
        }
        node.patches.extend_from_slice(patches);
        Some(node)
    }
}

impl TrieNode for TrieLeaf {
    fn id(&self) -> u8 {
        TrieNodeID::Leaf as u8
    }

    fn empty() -> TrieLeaf {
        TrieLeaf::new(&[], &[0u8; 40])
    }

    fn walk(&self, _chr: u8) -> Option<TriePtr> {
        None
    }

    fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[self.id()])?;
        write_path_to_bytes(&self.path, w)?;
        w.write_all(&self.data.0[..])?;
        Ok(())
    }

    fn write_bytes_compressed<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[self.id()])?;
        write_path_to_bytes(&self.path, w)?;
        w.write_all(&self.data.0[..])?;
        Ok(())
    }

    fn byte_len(&self) -> usize {
        1 + get_path_byte_len(&self.path) + self.data.len()
    }

    fn byte_len_compressed(&self) -> usize {
        1 + get_path_byte_len(&self.path) + self.data.len()
    }

    fn from_bytes<R: Read + Seek>(r: &mut R) -> Result<TrieLeaf, Error> {
        let mut idbuf = [0u8; 1];
        r.read_exact(&mut idbuf).inspect_err(|e| {
            error!("I/O error reading TrieLeaf ID: {e:?}");
        })?;

        if clear_ctrl_bits(idbuf[0]) != TrieNodeID::Leaf as u8 {
            return Err(Error::CorruptionError(format!(
                "Leaf: bad ID 0x{:02x}",
                idbuf[0]
            )));
        }

        let path = path_from_bytes(r)?;
        let mut leaf_data = [0u8; MARF_VALUE_ENCODED_SIZE as usize];

        r.read_exact(&mut leaf_data).inspect_err(|e| {
            error!(
                "I/O error reading TrieLeaf data: {e:?}. Got idbuf = {:02x}, path = {}",
                &idbuf[0],
                &to_hex(&path)
            );
        })?;

        Ok(TrieLeaf {
            path,
            data: MARFValue(leaf_data),
        })
    }

    fn insert(&mut self, _ptr: &TriePtr) -> bool {
        panic!("can't insert into a leaf");
    }

    fn replace(&mut self, _ptr: &TriePtr) -> bool {
        panic!("can't replace in a leaf");
    }

    fn ptrs(&self) -> &[TriePtr] {
        &[]
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Leaf(self.clone())
    }

    fn get_cow_ptr(&self) -> Option<&TrieCowPtr> {
        // no-op
        None
    }

    fn set_cow_ptr(&mut self, _cowptr: TrieCowPtr) {
        // no-op
    }

    fn apply_patches(
        self,
        _patches: &[(u32, TriePtr, TrieNodePatch)],
        _cur_block_id: u32,
    ) -> Option<Self> {
        Some(self)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrieNodeType {
    Node4(TrieNode4),
    Node16(TrieNode16),
    Node48(Box<TrieNode48>),
    Node256(Box<TrieNode256>),
    Leaf(TrieLeaf),
}

macro_rules! with_node {
    ($self: expr, $pat:pat, $s:expr) => {
        match $self {
            TrieNodeType::Node4($pat) => $s,
            TrieNodeType::Node16($pat) => $s,
            TrieNodeType::Node48($pat) => $s,
            TrieNodeType::Node256($pat) => $s,
            TrieNodeType::Leaf($pat) => $s,
        }
    };
}

impl TrieNodeType {
    pub fn is_leaf(&self) -> bool {
        matches!(self, TrieNodeType::Leaf(_))
    }

    pub fn is_node4(&self) -> bool {
        matches!(self, TrieNodeType::Node4(_))
    }

    pub fn is_node16(&self) -> bool {
        matches!(self, TrieNodeType::Node16(_))
    }

    pub fn is_node48(&self) -> bool {
        matches!(self, TrieNodeType::Node48(_))
    }

    pub fn is_node256(&self) -> bool {
        matches!(self, TrieNodeType::Node256(_))
    }

    pub fn id(&self) -> u8 {
        with_node!(self, ref data, data.id())
    }

    pub fn walk(&self, chr: u8) -> Option<TriePtr> {
        with_node!(self, ref data, data.walk(chr))
    }

    pub fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        with_node!(self, ref data, data.write_bytes(w))
    }

    pub fn write_bytes_compressed<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        with_node!(self, ref data, data.write_bytes_compressed(w))
    }

    pub fn write_consensus_bytes<W: Write, M: BlockMap>(
        &self,
        map: &mut M,
        w: &mut W,
    ) -> Result<(), Error> {
        with_node!(self, ref data, data.write_consensus_bytes(map, w))
    }

    pub fn byte_len(&self) -> usize {
        with_node!(self, ref data, data.byte_len())
    }

    pub fn byte_len_compressed(&self) -> usize {
        with_node!(self, ref data, data.byte_len_compressed())
    }

    pub fn insert(&mut self, ptr: &TriePtr) -> bool {
        with_node!(self, ref mut data, data.insert(ptr))
    }

    pub fn replace(&mut self, ptr: &TriePtr) -> bool {
        with_node!(self, ref mut data, data.replace(ptr))
    }

    pub fn ptrs(&self) -> &[TriePtr] {
        with_node!(self, ref data, data.ptrs())
    }

    pub fn ptrs_mut(&mut self) -> &mut [TriePtr] {
        match self {
            TrieNodeType::Node4(ref mut data) => &mut data.ptrs,
            TrieNodeType::Node16(ref mut data) => &mut data.ptrs,
            TrieNodeType::Node48(ref mut data) => &mut data.ptrs,
            TrieNodeType::Node256(ref mut data) => &mut data.ptrs,
            TrieNodeType::Leaf(_) => panic!("Leaf has no ptrs"),
        }
    }

    pub fn max_ptrs(&self) -> usize {
        match self {
            TrieNodeType::Node4(_) => 4,
            TrieNodeType::Node16(_) => 16,
            TrieNodeType::Node48(_) => 48,
            TrieNodeType::Node256(_) => 256,
            TrieNodeType::Leaf(_) => 0,
        }
    }

    pub fn path_bytes(&self) -> &Vec<u8> {
        with_node!(self, ref data, &data.path)
    }

    pub fn set_path(&mut self, new_path: Vec<u8>) {
        with_node!(self, ref mut data, data.path = new_path)
    }

    pub fn get_cow_ptr(&self) -> Option<&TrieCowPtr> {
        with_node!(self, ref data, data.get_cow_ptr())
    }

    pub fn set_cow_ptr(&mut self, cowptr: TrieCowPtr) {
        with_node!(self, ref mut data, data.set_cow_ptr(cowptr))
    }

    pub fn apply_patches(
        self,
        patches: &[(u32, TriePtr, TrieNodePatch)],
        cur_block_id: u32,
    ) -> Option<Self> {
        match self {
            TrieNodeType::Node4(data) => {
                let Some(new_data) = data.apply_patches(patches, cur_block_id) else {
                    return None;
                };
                Some(TrieNodeType::Node4(new_data))
            }
            TrieNodeType::Node16(data) => {
                let Some(new_data) = data.apply_patches(patches, cur_block_id) else {
                    return None;
                };
                Some(TrieNodeType::Node16(new_data))
            }
            TrieNodeType::Node48(data) => {
                let Some(new_data) = data.apply_patches(patches, cur_block_id) else {
                    return None;
                };
                Some(TrieNodeType::Node48(Box::new(new_data)))
            }
            TrieNodeType::Node256(data) => {
                let Some(new_data) = data.apply_patches(patches, cur_block_id) else {
                    return None;
                };
                Some(TrieNodeType::Node256(Box::new(new_data)))
            }
            TrieNodeType::Leaf(data) => Some(TrieNodeType::Leaf(data)),
        }
    }

    pub fn get_patches(&self) -> &[(u32, TriePtr, TrieNodePatch)] {
        match self {
            TrieNodeType::Node4(ref data) => &data.patches,
            TrieNodeType::Node16(ref data) => &data.patches,
            TrieNodeType::Node48(ref data) => &data.patches,
            TrieNodeType::Node256(ref data) => &data.patches,
            TrieNodeType::Leaf(_) => panic!("Leaf has no patches"),
        }
    }
}
