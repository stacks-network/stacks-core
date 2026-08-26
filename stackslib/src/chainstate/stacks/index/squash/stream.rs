// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::io::{Seek, SeekFrom, Write};
use std::time::Instant;

use sha2::Digest as _;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};

use super::fmt_duration;
use super::node_store::{CountingWriter, NodeStore};
use crate::chainstate::stacks::index::bits::{
    get_leaf_hash, get_node_byte_len, is_inline_child_ptr, reserved_root_size,
    resolve_inline_child_offsets, write_nodetype_bytes,
};
use crate::chainstate::stacks::index::node::{is_backptr, TrieNodeType};
use crate::chainstate::stacks::index::{blob_layout, BlockMap, Error, MarfTrieId, TrieHasher};

/// Recompute content hashes in reverse NodeStore order.
///
/// The squash collector writes tree nodes in DFS preorder, so inline children
/// are expected to appear after their parent.
pub(super) fn recompute_content_hashes(store: &mut NodeStore) -> Result<(), Error> {
    // Flush any buffered writes from earlier passes so the reader handle
    // sees the latest node bytes. Just in case.
    store.flush()?;
    let empty_hash = TrieHash::EMPTY;
    let node_count = store.len();
    let start = Instant::now();

    for idx in (0..node_count).rev() {
        let node = store.read_node(idx)?;
        if let TrieNodeType::Leaf(ref leaf) = node {
            store.set_hash(idx, get_leaf_hash(leaf));
            continue;
        }

        let ptrs = node.ptrs();
        let mut child_hashes = Vec::with_capacity(ptrs.len());
        for child_ptr in ptrs {
            // After `remap_child_ptrs`, the squash invariant guarantees that
            // no backpointers remain. A leftover backpointer would cause us
            // to silently hash an empty child here, so fail instead.
            if is_backptr(child_ptr.id()) {
                return Err(Error::CorruptionError(format!(
                    "squash invariant: node {idx} still has backpointer child \
                     after remap; refusing to recompute hash"
                )));
            }
            if !is_inline_child_ptr(child_ptr) {
                child_hashes.push(empty_hash);
            } else {
                let child_idx = child_ptr.ptr() as usize;
                // Reverse order only works for parent-before-child storage.
                if child_idx <= idx || child_idx >= node_count {
                    return Err(Error::CorruptionError(format!(
                        "invalid child index {child_idx} at node {idx} \
                         (node_count={node_count}); preorder DFS invariant requires \
                         parent < child < node_count"
                    )));
                }
                child_hashes.push(*store.get_hash(child_idx));
            }
        }

        let new_hash = compute_node_hash(&node, &child_hashes);
        store.set_hash(idx, new_hash);
    }

    info!(
        "Trie hash: {node_count} nodes in {}",
        fmt_duration(start.elapsed())
    );
    Ok(())
}

/// Stream the squash blob into an arbitrary `Write + Seek` sink.
///
/// Reads nodes one-at-a-time from the NodeStore temp file and serializes them
/// directly into `sink`.
///
/// This mirrors `TrieRAM::dump_consume`: reserve worst-case root space at the
/// front of the blob, write descendants in child-before-parent order so child
/// offsets are known, then seek back and write the root.
///
/// The blob is written starting at the sink's current position.
/// All internal offsets (header, node pointers) are relative to the blob
/// start, not to the absolute file position.
///
/// Returns the number of bytes written.
pub(crate) fn stream_squash_blob<T: MarfTrieId, F: Write + Seek>(
    store: &mut NodeStore,
    parent_hash: &T,
    sink: &mut F,
) -> Result<u64, Error> {
    let n = store.len();
    if n == 0 {
        return Err(Error::CorruptionError(
            "Cannot stream empty squash trie".to_string(),
        ));
    }

    // Record the base offset so all writes are relative to blob start.
    let base = sink.stream_position().map_err(Error::IOError)?;
    // We use CountingWriter to track the cursor locally. Otherwise using `BufWriter::stream_position()`
    // would flush and seek on every offset lookup.
    let mut sink = CountingWriter::with_position(sink, base);
    let header_size = blob_layout::ROOT_NODE_OFFSET as u64;

    let root_node = store.read_node(0)?;
    let root_reserved_size = reserved_root_size(get_node_byte_len(&root_node), root_node.ptrs())?;

    // Write the fixed blob header.
    sink.write_all(parent_hash.as_bytes())
        .map_err(Error::IOError)?;
    sink.seek(SeekFrom::Start(
        base + blob_layout::RESERVED_FIELD_OFFSET as u64,
    ))
    .map_err(Error::IOError)?;
    sink.write_all(&0u32.to_le_bytes())
        .map_err(Error::IOError)?;

    sink.seek(SeekFrom::Start(
        base.checked_add(header_size)
            .and_then(|x| x.checked_add(root_reserved_size))
            .ok_or(Error::OverflowError)?,
    ))
    .map_err(Error::IOError)?;

    // Map from NodeStore index to offset inside this blob. Offset 0 means
    // "not written yet"; real node offsets always come after the header.
    let mut blob_offsets = vec![0u64; n];

    // NodeStore is collected in root-first DFS preorder. Reversing all
    // descendants writes children before parents, so parent pointer remapping
    // never needs a fixpoint pass.
    for idx in (1..n).rev() {
        let current = sink.position();
        *blob_offsets
            .get_mut(idx)
            .ok_or_else(|| Error::CorruptionError("blob offset index out of bounds".into()))? =
            current.checked_sub(base).ok_or(Error::OverflowError)?;

        let mut node = store.read_node(idx)?;
        let hash = store.get_hash(idx);

        // Convert array-index pointers to byte offsets (relative to blob start)
        if !node.is_leaf() {
            resolve_inline_child_offsets(node.ptrs_mut(), &blob_offsets)?;
        }

        write_nodetype_bytes(&mut sink, &node, hash)?;
    }

    let end = sink.position();
    let total_size = end.checked_sub(base).ok_or(Error::OverflowError)?;

    // Write the root into its reserved slot.
    *blob_offsets
        .get_mut(0)
        .ok_or_else(|| Error::CorruptionError("empty blob offset table".into()))? = header_size;
    let mut root_node = store.read_node(0)?;
    if !root_node.is_leaf() {
        resolve_inline_child_offsets(root_node.ptrs_mut(), &blob_offsets)?;
    }

    sink.seek(SeekFrom::Start(
        base.checked_add(header_size).ok_or(Error::OverflowError)?,
    ))
    .map_err(Error::IOError)?;
    let root_written = write_nodetype_bytes(&mut sink, &root_node, store.get_hash(0))?;
    debug_assert!(
        root_written <= root_reserved_size,
        "root wrote {root_written} bytes but only {root_reserved_size} were reserved"
    );

    // Leave the caller positioned at the end of the blob, as if the write had
    // been a single forward stream.
    sink.seek(SeekFrom::Start(end)).map_err(Error::IOError)?;

    Ok(total_size)
}

/// A `BlockMap` for nodes whose backpointers were already made inline.
///
/// `write_consensus_bytes` should never ask this map for a block hash; the
/// debug assertion in `compute_node_hash` checks that precondition.
struct BackptrFreeBlockMap;

impl BlockMap for BackptrFreeBlockMap {
    type TrieId = StacksBlockId;

    fn get_block_hash(&self, _id: u32) -> Result<Self::TrieId, Error> {
        unreachable!("BackptrFreeBlockMap: no backpointers in squash trie")
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&Self::TrieId, Error> {
        unreachable!("BackptrFreeBlockMap: no backpointers in squash trie")
    }
    fn is_block_hash_cached(&self, _id: u32) -> bool {
        false
    }
    fn get_block_id(&self, _bhh: &Self::TrieId) -> Result<u32, Error> {
        unreachable!("BackptrFreeBlockMap: no backpointers in squash trie")
    }
    fn get_block_id_caching(&mut self, _bhh: &Self::TrieId) -> Result<u32, Error> {
        unreachable!("BackptrFreeBlockMap: no backpointers in squash trie")
    }
}

/// Compute the content hash of a `TrieNodeType` given pre-collected child hashes.
///
/// Equivalent to `bits::get_node_hash` but works on the `TrieNodeType` enum
/// directly (which does not implement `ConsensusSerializable<M>`).
///
/// Precondition: every child pointer of `node` has its backptr bit cleared.
/// `BackptrFreeBlockMap` panics if that precondition is violated.
pub(crate) fn compute_node_hash(node: &TrieNodeType, child_hashes: &[TrieHash]) -> TrieHash {
    debug_assert!(
        node.is_leaf() || node.ptrs().iter().all(|p| !is_backptr(p.id)),
        "compute_node_hash precondition violated: node still has backpointer children"
    );
    let mut hasher = TrieHasher::new();
    node.write_consensus_bytes(&mut BackptrFreeBlockMap, &mut hasher)
        .expect("IO failure pushing to hasher");
    for h in child_hashes {
        hasher.update(h.as_ref());
    }
    TrieHash(hasher.finalize().into())
}
