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

//! MARF squashing: offline snapshot creation and validation.
//!
//! A squashed MARF contains only the canonical state at a given
//! height H plus the metadata needed for ancestor hash lookups and
//! block-height resolution.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use rusqlite::{params, DatabaseName};
use sha2::Digest as _;
use stacks_common::types::chainstate::{
    StacksBlockId, TrieHash, BLOCK_HEADER_HASH_ENCODED_SIZE, TRIEHASH_ENCODED_SIZE,
};

use crate::chainstate::stacks::index::bits::{
    get_leaf_hash, get_node_byte_len, write_nodetype_bytes,
};
use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF,
};
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeID,
    TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::storage::{
    SquashInfo, TrieFileStorage, TrieStorageConnection,
};
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{
    trie_sql, BlockMap, Error, MARFValue, MarfTrieId, TrieHasher, TrieLeaf,
};

/// Classify a child pointer: resolve the `(block_id, byte_offset)` pair that
/// locates the child in blob storage. Backpointers carry the target block_id
/// directly; inline pointers belong to `origin_block_id`.
/// Returns `None` for empty pointers.
#[inline]
fn resolve_child_ptr(ptr: &TriePtr, origin_block_id: u32) -> Option<(u32, u64)> {
    if ptr.id() == TrieNodeID::Empty as u8 {
        return None;
    }
    if is_backptr(ptr.id()) {
        Some((ptr.back_block(), ptr.from_backptr().ptr()))
    } else {
        Some((origin_block_id, ptr.ptr()))
    }
}

/// Returns `true` when a pointer is an inline child (non-empty, non-backptr)
/// — i.e. it points to a node in the same blob, not to an ancestor block.
#[inline]
fn is_inline_child_ptr(ptr: &TriePtr) -> bool {
    ptr.id() != TrieNodeID::Empty as u8 && !is_backptr(ptr.id())
}

/// Format a `Duration` as `X.YZ secs` or `X min Y.ZW secs`.
fn fmt_duration(d: Duration) -> String {
    let total_centis = d.as_millis() / 10;
    let mins = total_centis / 6000;
    let secs = (total_centis % 6000) as f64 / 100.0;
    if mins == 0 {
        format!("{secs:.2} secs")
    } else {
        format!("{mins} min {secs:.2} secs")
    }
}

// ---------------------------------------------------------------------------
// NodeStore: disk-backed storage for collected trie nodes.
//
// Instead of holding all 50M+ collected nodes in a giant in-memory vector,
// this stores the full node data in a temporary file and keeps only
// lightweight per-node metadata in memory (~4 GB).
// ---------------------------------------------------------------------------

/// Tag bytes for node serialization to the temp file.
const TAG_LEAF: u8 = 0;
const TAG_NODE4: u8 = 1;
const TAG_NODE16: u8 = 2;
const TAG_NODE48: u8 = 3;
const TAG_NODE256: u8 = 4;

/// Serialize a single `TriePtr` to the writer.
fn write_trie_ptr<W: Write>(w: &mut W, p: &TriePtr) -> Result<(), Error> {
    w.write_all(&[p.id, p.chr])?;
    w.write_all(&p.ptr.to_le_bytes())?;
    w.write_all(&p.back_block.to_le_bytes())?;
    Ok(())
}

/// Deserialize a single `TriePtr` from the reader.
fn read_trie_ptr<R: std::io::Read>(r: &mut R) -> Result<TriePtr, Error> {
    let mut buf2 = [0u8; 2];
    r.read_exact(&mut buf2)?;
    let mut buf8 = [0u8; 8];
    r.read_exact(&mut buf8)?;
    let ptr = u64::from_le_bytes(buf8);
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4)?;
    let back_block = u32::from_le_bytes(buf4);
    Ok(TriePtr {
        id: buf2[0],
        chr: buf2[1],
        ptr,
        back_block,
    })
}

/// Serialize a `TrieNodeType` to the writer in a compact binary format.
/// Format: [tag: u8] [path_len: u32] [path bytes] [variant data]
pub(crate) fn serialize_node<W: Write>(w: &mut W, node: &TrieNodeType) -> Result<(), Error> {
    match node {
        TrieNodeType::Leaf(leaf) => {
            w.write_all(&[TAG_LEAF])?;
            w.write_all(&(leaf.path.len() as u32).to_le_bytes())?;
            w.write_all(&leaf.path)?;
            w.write_all(&leaf.data.0)?;
        }
        TrieNodeType::Node4(n) => {
            w.write_all(&[TAG_NODE4])?;
            w.write_all(&(n.path.len() as u32).to_le_bytes())?;
            w.write_all(&n.path)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
        TrieNodeType::Node16(n) => {
            w.write_all(&[TAG_NODE16])?;
            w.write_all(&(n.path.len() as u32).to_le_bytes())?;
            w.write_all(&n.path)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
        TrieNodeType::Node48(n) => {
            w.write_all(&[TAG_NODE48])?;
            w.write_all(&(n.path.len() as u32).to_le_bytes())?;
            w.write_all(&n.path)?;
            // Write the 256-byte indexes array
            let indexes = n.indexes.map(|idx| idx as u8);
            w.write_all(&indexes)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
        TrieNodeType::Node256(n) => {
            w.write_all(&[TAG_NODE256])?;
            w.write_all(&(n.path.len() as u32).to_le_bytes())?;
            w.write_all(&n.path)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
    }
    Ok(())
}

/// Deserialize a `TrieNodeType` from the reader.
pub(crate) fn deserialize_node<R: std::io::Read>(r: &mut R) -> Result<TrieNodeType, Error> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    let mut path_len_buf = [0u8; 4];
    r.read_exact(&mut path_len_buf)?;
    let path_len = u32::from_le_bytes(path_len_buf) as usize;
    let mut path = vec![0u8; path_len];
    if path_len > 0 {
        r.read_exact(&mut path)?;
    }

    match tag[0] {
        TAG_LEAF => {
            let mut data = [0u8; 40];
            r.read_exact(&mut data)?;
            Ok(TrieNodeType::Leaf(TrieLeaf {
                path,
                data: MARFValue(data),
            }))
        }
        TAG_NODE4 => {
            let mut ptrs = [TriePtr::default(); 4];
            for p in ptrs.iter_mut() {
                *p = read_trie_ptr(r)?;
            }
            Ok(TrieNodeType::Node4(TrieNode4 {
                path,
                ptrs,
                cowptr: None,
                patches: vec![],
            }))
        }
        TAG_NODE16 => {
            let mut ptrs = [TriePtr::default(); 16];
            for p in ptrs.iter_mut() {
                *p = read_trie_ptr(r)?;
            }
            Ok(TrieNodeType::Node16(TrieNode16 {
                path,
                ptrs,
                cowptr: None,
                patches: vec![],
            }))
        }
        TAG_NODE48 => {
            let mut indexes_u8 = [0u8; 256];
            r.read_exact(&mut indexes_u8)?;
            let indexes = indexes_u8.map(|idx| idx as i8);
            let mut ptrs = [TriePtr::default(); 48];
            for p in ptrs.iter_mut() {
                *p = read_trie_ptr(r)?;
            }
            Ok(TrieNodeType::Node48(Box::new(TrieNode48 {
                path,
                indexes,
                ptrs,
                cowptr: None,
                patches: vec![],
            })))
        }
        TAG_NODE256 => {
            let mut ptrs = [TriePtr::default(); 256];
            for p in ptrs.iter_mut() {
                *p = read_trie_ptr(r)?;
            }
            Ok(TrieNodeType::Node256(Box::new(TrieNode256 {
                path,
                ptrs,
                cowptr: None,
                patches: vec![],
            })))
        }
        _ => Err(Error::CorruptionError(format!(
            "NodeStore: invalid tag byte {0}",
            tag[0]
        ))),
    }
}

/// Disk-backed store for collected trie nodes.
///
/// Full node data is serialized to a temporary file. Only lightweight
/// per-node metadata (hash, block_id, file offset) is kept in memory.
pub(crate) struct NodeStore {
    /// Temp file holding serialized nodes (write handle).
    writer: BufWriter<File>,
    /// Path to the temp file (for re-opening as reader).
    pub(crate) path: std::path::PathBuf,
    /// Byte offset in the temp file for each node.
    pub(crate) file_offsets: Vec<u64>,
    /// Per-node hash.
    hashes: Vec<TrieHash>,
    /// Per-node origin block ID.
    block_ids: Vec<u32>,
}

impl NodeStore {
    pub(crate) fn new(dir: &str) -> Result<Self, Error> {
        let pid = std::process::id();
        // Try up to 16 times with atomic create_new to avoid collision.
        for attempt in 0u32..16 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::path::PathBuf::from(format!(
                "{}/.squash_nodes_{pid}_{nanos}_{attempt}.tmp",
                dir
            ));
            match File::options().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok(NodeStore {
                        writer: BufWriter::with_capacity(1 << 20, file),
                        path,
                        file_offsets: Vec::new(),
                        hashes: Vec::new(),
                        block_ids: Vec::new(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(Error::IOError(e)),
            }
        }
        Err(Error::IOError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to create unique NodeStore temp file after 16 attempts",
        )))
    }

    pub(crate) fn len(&self) -> usize {
        self.file_offsets.len()
    }

    /// Append a node. Returns the node's index.
    pub(crate) fn push(
        &mut self,
        node: &TrieNodeType,
        hash: TrieHash,
        block_id: u32,
    ) -> Result<usize, Error> {
        let idx = self.file_offsets.len();
        let offset = self.writer.stream_position().map_err(Error::IOError)?;
        self.file_offsets.push(offset);
        self.hashes.push(hash);
        self.block_ids.push(block_id);
        serialize_node(&mut self.writer, node)?;
        Ok(idx)
    }

    /// Flush the writer and return a sequential reader over all nodes.
    pub(crate) fn finish_writing(&mut self) -> Result<(), Error> {
        self.writer.flush().map_err(Error::IOError)?;
        Ok(())
    }

    /// Open a reader for random-access reads.
    pub(crate) fn open_reader(&self) -> Result<BufReader<File>, Error> {
        let file = File::open(&self.path).map_err(Error::IOError)?;
        Ok(BufReader::with_capacity(1 << 20, file))
    }

    /// Read a node from the temp file using the given reader.
    pub(crate) fn read_node_with(
        &self,
        reader: &mut BufReader<File>,
        idx: usize,
    ) -> Result<TrieNodeType, Error> {
        let offset = *self.file_offsets.get(idx).ok_or_else(|| {
            Error::CorruptionError(format!("NodeStore: index {idx} out of bounds"))
        })?;
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(Error::IOError)?;
        deserialize_node(reader)
    }

    pub(crate) fn hash(&self, idx: usize) -> TrieHash {
        self.hashes.get(idx).copied().unwrap_or_else(|| {
            panic!(
                "NodeStore::hash: index {idx} out of bounds (len={})",
                self.hashes.len()
            )
        })
    }

    pub(crate) fn set_hash(&mut self, idx: usize, hash: TrieHash) {
        if let Some(slot) = self.hashes.get_mut(idx) {
            *slot = hash;
        } else {
            panic!(
                "NodeStore::set_hash: index {idx} out of bounds (len={})",
                self.hashes.len()
            );
        }
    }

    pub(crate) fn block_id(&self, idx: usize) -> u32 {
        self.block_ids.get(idx).copied().unwrap_or_else(|| {
            panic!(
                "NodeStore::block_id: index {idx} out of bounds (len={})",
                self.block_ids.len()
            )
        })
    }

    /// Drop the block_ids Vec to free memory after remap.
    fn drop_block_ids(&mut self) {
        self.block_ids = Vec::new();
    }

    /// Clean up the temp file.
    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for NodeStore {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Remap child pointers in a `NodeStore` for the squashed trie layout.
///
/// For each non-leaf node, reads it from the temp file, remaps its child
/// pointers from source (block_id, offset) to sequential indices, and
/// writes the modified node back.
///
/// When `block_id_map` is `Some`, each child's `back_block` is set to the
/// squashed equivalent of its origin block (needed for the real squash blob
/// so that COW and hash computation preserve block identity). When `None`,
/// `back_block` is zeroed (used by `recompute_squash_root_node_hash` where
/// block identity is irrelevant).
fn remap_child_ptrs(
    store: &mut NodeStore,
    source_to_idx: &HashMap<(u32, u64), usize>,
    block_id_map: Option<&HashMap<u32, u32>>,
    label: &str,
) -> Result<(), Error> {
    let remap_start = Instant::now();
    let node_count = store.len();
    let mut reader = store.open_reader()?;

    let write_file = std::fs::OpenOptions::new()
        .write(true)
        .open(&store.path)
        .map_err(Error::IOError)?;
    let mut writer = BufWriter::with_capacity(1 << 20, write_file);

    for idx in 0..node_count {
        if idx > 0 && idx % 1_000_000 == 0 {
            info!(
                "[{label}] Remap trie pointers: {idx}/{node_count} nodes in {}",
                fmt_duration(remap_start.elapsed())
            );
        }

        let mut node = store.read_node_with(&mut reader, idx)?;
        let origin_block_id = store.block_id(idx);

        if node.is_leaf() {
            continue;
        }

        let ptrs = node.ptrs_mut();
        let mut modified = false;
        for ptr in ptrs.iter_mut() {
            let Some((child_block_id, read_ptr_val)) = resolve_child_ptr(ptr, origin_block_id)
            else {
                continue;
            };

            let source_key = (child_block_id, read_ptr_val);
            let child_idx = *source_to_idx.get(&source_key).ok_or_else(|| {
                Error::CorruptionError(format!(
                    "remap_child_ptrs: child {source_key:?} not in source_to_idx"
                ))
            })?;

            ptr.ptr = child_idx as u64;
            ptr.id = clear_backptr(ptr.id);

            ptr.back_block = match block_id_map {
                Some(map) => *map.get(&child_block_id).ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "remap_child_ptrs: block_id {child_block_id} not in block_id_map"
                    ))
                })?,
                None => 0,
            };
            modified = true;
        }

        if modified {
            let offset = *store.file_offsets.get(idx).ok_or_else(|| {
                Error::CorruptionError(format!("remap: file_offsets index {idx} out of bounds"))
            })?;
            writer
                .seek(SeekFrom::Start(offset))
                .map_err(Error::IOError)?;
            serialize_node(&mut writer, &node)?;
        }
    }
    writer.flush().map_err(Error::IOError)?;

    info!(
        "[{label}] Remap trie pointers complete: {node_count} nodes in {}",
        fmt_duration(remap_start.elapsed())
    );
    Ok(())
}

/// Recompute content hashes using a `NodeStore`.
///
/// Leaf hashes are computed by reading each leaf from the temp file.
/// Internal node hashes are computed bottom-up (reverse order) using
/// the in-memory hashes Vec for child lookups and reading the node
/// structure from the temp file.
fn recompute_content_hashes(store: &mut NodeStore) -> Result<(), Error> {
    let empty_hash = TrieHash::from_data(&[]);
    let node_count = store.len();
    let mut reader = store.open_reader()?;
    let start = Instant::now();

    // Pass 1: compute leaf hashes
    for idx in 0..node_count {
        let node = store.read_node_with(&mut reader, idx)?;
        if let TrieNodeType::Leaf(ref leaf) = node {
            store.set_hash(idx, get_leaf_hash(leaf));
        }
    }
    info!(
        "Trie hash: leaf pass done in {}",
        fmt_duration(start.elapsed())
    );

    // Pass 2: internal nodes in reverse order
    for idx in (0..node_count).rev() {
        let node = store.read_node_with(&mut reader, idx)?;
        if node.is_leaf() {
            continue;
        }

        // Collect child hashes
        let ptrs = node.ptrs();
        let mut child_hashes = Vec::with_capacity(ptrs.len());
        for child_ptr in ptrs {
            if !is_inline_child_ptr(child_ptr) {
                child_hashes.push(empty_hash);
            } else {
                let child_idx = child_ptr.ptr() as usize;
                if child_idx >= node_count {
                    return Err(Error::CorruptionError(format!(
                        "Invalid child index {child_idx} at node {idx}"
                    )));
                }
                child_hashes.push(store.hash(child_idx));
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

/// Replace array-index child pointers in `node` with the corresponding
/// blob byte offsets from `blob_offsets`.  Only forward (non-back, non-empty)
/// pointers are remapped.
pub(crate) fn remap_ptrs_to_blob_offsets(
    node: &mut TrieNodeType,
    blob_offsets: &[u64],
) -> Result<(), Error> {
    if node.is_leaf() {
        return Ok(());
    }
    for ptr in node.ptrs_mut() {
        if is_inline_child_ptr(ptr) {
            let child_idx = ptr.ptr() as usize;
            ptr.ptr = *blob_offsets.get(child_idx).ok_or_else(|| {
                Error::CorruptionError(format!(
                    "blob offset remap: child index {child_idx} out of bounds"
                ))
            })?;
        }
    }
    Ok(())
}

/// Compute per-node byte offsets within the serialized blob.
///
/// Returns `(blob_offsets, total_size)` where `blob_offsets[i]` is the byte
/// position where node `i` starts in the blob (after the header).
pub(crate) fn compute_blob_offsets(store: &mut NodeStore) -> Result<(Vec<u64>, u64), Error> {
    compute_blob_offsets_inner(store, u32::MAX as u64)
}

/// Inner implementation with a configurable early-exit threshold.
/// When `current_offset <= early_exit_threshold` after pass 1, the fixpoint
/// loop is skipped because no pointer will switch to u64 encoding.
pub(crate) fn compute_blob_offsets_inner(
    store: &mut NodeStore,
    early_exit_threshold: u64,
) -> Result<(Vec<u64>, u64), Error> {
    let n = store.len();
    let mut reader = store.open_reader()?;
    let header_size = BLOCK_HEADER_HASH_ENCODED_SIZE as u64 + 4;
    let mut blob_offsets: Vec<u64> = Vec::with_capacity(n);
    let mut current_offset = header_size;
    let mut forward_ptr_count: usize = 0;

    // Per-node byte lengths cached during Pass 1.  For nodes without
    // forward pointers the length is constant across fixpoint passes,
    // so we can skip re-reading them from disk entirely.
    let mut byte_lens: Vec<u64> = Vec::with_capacity(n);
    // True when a node has forward pointers (must be re-read in fixpoint).
    let mut has_forward_ptrs: Vec<bool> = Vec::with_capacity(n);

    // Pass 1: compute offsets using original (array-index) pointer values.
    for idx in 0..n {
        blob_offsets.push(current_offset);
        let node = store.read_node_with(&mut reader, idx)?;
        let mut has_fwd = false;
        if !node.is_leaf() {
            for ptr in node.ptrs() {
                if is_inline_child_ptr(ptr) {
                    forward_ptr_count = forward_ptr_count
                        .checked_add(1)
                        .ok_or(Error::OverflowError)?;
                    has_fwd = true;
                }
            }
        }
        has_forward_ptrs.push(has_fwd);
        let byte_len = get_node_byte_len(&node) as u64;
        byte_lens.push(byte_len);
        current_offset += byte_len;
    }

    // If the blob fits in 4 GiB, no pointer will switch to u64 encoding.
    if current_offset <= early_exit_threshold {
        return Ok((blob_offsets, current_offset));
    }

    // Pass 2+: recompute with blob-offset pointer values until stable.
    // Each forward pointer widens from u32 to u64 at most once, so
    // `forward_ptr_count + 2` bounds convergence (same as dump_consume).
    let max_passes = forward_ptr_count.saturating_add(2);
    let mut converged = false;
    for _ in 0..max_passes {
        let prev_total = current_offset;
        current_offset = header_size;

        for idx in 0..n {
            // Temporary mutable borrow - released at the semicolon so
            // `remap_ptrs_to_blob_offsets` can borrow `blob_offsets` immutably.
            *blob_offsets.get_mut(idx).ok_or_else(|| {
                Error::CorruptionError("blob offset index out of bounds".into())
            })? = current_offset;

            let has_fwd = *has_forward_ptrs.get(idx).ok_or_else(|| {
                Error::CorruptionError("has_forward_ptrs index out of bounds".into())
            })?;
            if has_fwd {
                let mut node = store.read_node_with(&mut reader, idx)?;
                remap_ptrs_to_blob_offsets(&mut node, &blob_offsets)?;
                *byte_lens.get_mut(idx).ok_or_else(|| {
                    Error::CorruptionError("byte_lens index out of bounds".into())
                })? = get_node_byte_len(&node) as u64;
            }

            current_offset += *byte_lens
                .get(idx)
                .ok_or_else(|| Error::CorruptionError("byte_lens index out of bounds".into()))?;
        }

        if current_offset == prev_total {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(Error::CorruptionError(format!(
            "compute_blob_offsets layout did not converge after {max_passes} passes"
        )));
    }

    Ok((blob_offsets, current_offset))
}

/// Stream the squash blob into an arbitrary `Write + Seek` sink.
///
/// Reads nodes one-at-a-time from the NodeStore temp file, converts
/// array-index child pointers to byte offsets, and serializes directly
/// into `sink`. No intermediate `Vec<u8>` is allocated for the full blob.
///
/// The blob is written starting at the sink's current position.
/// All internal offsets (header, node pointers) are relative to the blob
/// start, not to the absolute file position, so this works correctly when
/// appending to a `.blobs` file that already contains data.
///
/// Returns the number of bytes written.
pub(crate) fn stream_squash_blob<T: MarfTrieId, F: Write + Seek>(
    store: &mut NodeStore,
    parent_hash: &T,
    blob_offsets: &[u64],
    sink: &mut F,
) -> Result<u64, Error> {
    let n = store.len();
    let mut reader = store.open_reader()?;

    // Record the base offset so all writes are relative to blob start.
    let base = sink.stream_position().map_err(Error::IOError)?;

    // Write header: parent block hash + zero identifier
    sink.write_all(parent_hash.as_bytes())
        .map_err(Error::IOError)?;
    sink.seek(SeekFrom::Start(
        base + BLOCK_HEADER_HASH_ENCODED_SIZE as u64,
    ))
    .map_err(Error::IOError)?;
    sink.write_all(&0u32.to_le_bytes())
        .map_err(Error::IOError)?;

    for idx in 0..n {
        let mut node = store.read_node_with(&mut reader, idx)?;
        let hash = store.hash(idx);

        // Convert array-index pointers to byte offsets (relative to blob start)
        remap_ptrs_to_blob_offsets(&mut node, blob_offsets)?;

        write_nodetype_bytes(sink, &node, hash)?;
    }

    let end = sink.stream_position().map_err(Error::IOError)?;
    Ok(end - base)
}

/// Per-height block metadata: `(height, block_hash, root_hash)`.
type BlockInfo<T> = (u32, T, TrieHash);

/// Reads root hashes from either an external `.blobs` file or from SQLite
/// internal `marf_data.data` BLOB columns.
enum BlobReader {
    External(BufReader<File>),
    Internal(rusqlite::Connection),
}

impl BlobReader {
    fn new(db_path: &str, external_blobs: bool) -> Result<Self, Error> {
        if external_blobs {
            let blobs_path = format!("{db_path}.blobs");
            let file = File::open(&blobs_path).map_err(Error::IOError)?;
            Ok(BlobReader::External(BufReader::with_capacity(
                64 * 1024,
                file,
            )))
        } else {
            let conn = rusqlite::Connection::open_with_flags(
                db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            Ok(BlobReader::Internal(conn))
        }
    }

    /// Read the root hash for a block.
    ///
    /// For `External`, seeks to `blob_offset + root_ptr_offset` in the `.blobs` file.
    /// For `Internal`, opens the SQLite blob for `block_id` and seeks within it.
    fn read_root_hash(&mut self, block_id: u32, blob_offset: u64) -> Result<TrieHash, Error> {
        let root_ptr_offset = (BLOCK_HEADER_HASH_ENCODED_SIZE as u64) + 4;
        let mut hash_bytes = [0u8; TRIEHASH_ENCODED_SIZE];
        match self {
            BlobReader::External(reader) => {
                reader.seek(SeekFrom::Start(blob_offset + root_ptr_offset))?;
                reader.read_exact(&mut hash_bytes)?;
            }
            BlobReader::Internal(conn) => {
                let mut blob = conn.blob_open(
                    DatabaseName::Main,
                    "marf_data",
                    "data",
                    block_id.into(),
                    true, // readonly
                )?;
                blob.seek(SeekFrom::Start(root_ptr_offset))?;
                blob.read_exact(&mut hash_bytes)?;
            }
        }
        Ok(TrieHash(hash_bytes))
    }
}

/// A `BlockMap` adapter for trie nodes that have no backpointer children.
///
/// After the remap pass all pointers in the squash blob are inline.
/// `write_consensus_bytes` writes zeroed block hashes for non-backptr
/// children and never queries the `BlockMap`, so every method here is
/// unreachable.
struct InlineOnlyBlockMap;

impl BlockMap for InlineOnlyBlockMap {
    type TrieId = StacksBlockId;

    fn get_block_hash(&self, _id: u32) -> Result<Self::TrieId, Error> {
        unreachable!("InlineOnlyBlockMap: no backpointers in squash trie")
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&Self::TrieId, Error> {
        unreachable!("InlineOnlyBlockMap: no backpointers in squash trie")
    }
    fn is_block_hash_cached(&self, _id: u32) -> bool {
        false
    }
    fn get_block_id(&self, _bhh: &Self::TrieId) -> Result<u32, Error> {
        unreachable!("InlineOnlyBlockMap: no backpointers in squash trie")
    }
    fn get_block_id_caching(&mut self, _bhh: &Self::TrieId) -> Result<u32, Error> {
        unreachable!("InlineOnlyBlockMap: no backpointers in squash trie")
    }
}

/// Compute the content hash of a `TrieNodeType` given pre-collected child hashes.
///
/// Equivalent to `bits::get_node_hash` but works on the `TrieNodeType` enum
/// directly (which does not implement `ConsensusSerializable<M>`).
fn compute_node_hash(node: &TrieNodeType, child_hashes: &[TrieHash]) -> TrieHash {
    let mut hasher = TrieHasher::new();
    node.write_consensus_bytes(&mut InlineOnlyBlockMap, &mut hasher)
        .expect("IO failure pushing to hasher");
    for h in child_hashes {
        hasher.update(h.as_ref());
    }
    TrieHash(hasher.finalize().into())
}

fn read_proc_status_kib(field: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with(field))?;
    let mut parts = line.split_whitespace();
    let _ = parts.next()?;
    parts.next()?.parse::<u64>().ok()
}

fn log_memory_snapshot(stage: &str) {
    let rss_kib = read_proc_status_kib("VmRSS:");
    let hwm_kib = read_proc_status_kib("VmHWM:");

    match (rss_kib, hwm_kib) {
        (Some(rss), Some(hwm)) => info!(
            "Squash memory ({stage}): VmRSS={} MiB, VmHWM={} MiB",
            rss / 1024,
            hwm / 1024
        ),
        (Some(rss), None) => info!("Squash memory ({stage}): VmRSS={} MiB", rss / 1024),
        _ => info!("Squash memory ({stage}): unavailable"),
    }
}

/// Key that stores the squashed root hash at the snapshot tip.
pub const MARF_SQUASH_ROOT_KEY: &str = "__MARF_SQUASH_ROOT";
/// Key that stores the snapshot height for a squashed MARF.
pub const MARF_SQUASH_HEIGHT_KEY: &str = "__MARF_SQUASH_HEIGHT";
/// Prefix for per-height root hashes preserved in squashed MARFs.
/// Each key has the form `__MARF_SQUASHED_BLOCK_ROOT_HASH::<height>`.
pub const MARF_SQUASHED_BLOCK_ROOT_HASH_KEY: &str = "__MARF_SQUASHED_BLOCK_ROOT_HASH";

/// Summary statistics from a squashing run.
#[derive(Debug, Clone)]
pub struct SquashStats {
    /// Total number of nodes collected into the squashed MARF.
    pub node_count: u64,
}

/// Summary statistics from a validation run.
///
/// The default validation checks:
/// - Per-height root hashes stored in `marf_squash_archival_marf_roots` match the
///   archival source (guarantees correct ancestor hash computation for the
///   skip-list at blocks > H).
/// - Squash metadata (`marf_squash_info`) is present and correct.
/// - All historical `marf_data` entries share the tip block's blob offset.
///
/// When `full_leaf_scan` is enabled, the validator additionally walks every
/// leaf in both MARFs and cross-checks them, which is O(leaf_count) and much
/// slower but useful for debugging.
#[derive(Debug, Clone)]
pub struct SquashValidationStats {
    // --- Fast-path (always populated) ---
    /// Whether the squashed root key was found in the SQL metadata.
    pub archival_root_present: bool,
    /// Whether the stored archival root hash at the squash height
    /// matches the source MARF's root hash at that height.
    pub archival_root_matches: bool,
    /// Per-height root hashes missing from the SQL table.
    pub root_hash_missing: u64,
    /// Per-height root hashes with mismatched values.
    pub root_hash_mismatches: u64,
    /// Number of historical `marf_data` entries that do NOT share the
    /// tip block's blob offset (should be 0 for a correct squash).
    pub blob_offset_mismatches: u64,
    /// Whether the `squash_root_node_hash` was found in SQL metadata
    /// (a `TrieHash::from_data(&[])` value counts as absent).
    pub squash_node_hash_present: bool,
    /// Whether the stored `squash_root_node_hash` matches the value
    /// recomputed from the committed squash trie blob (DFS walk + bottom-up hash).
    pub squash_node_hash_matches: bool,

    // --- Full leaf scan (only populated when full_leaf_scan = true) ---
    /// Total keys compared from the source MARF (0 when fast-only).
    pub source_keys_checked: u64,
    /// Total keys compared from the squashed MARF (0 when fast-only).
    pub squashed_keys_checked: u64,
    /// Keys present in source but missing in squashed (0 when fast-only).
    pub missing_in_squashed: u64,
    /// Keys present in squashed but missing in source (0 when fast-only).
    pub missing_in_source: u64,
    /// Keys present in both but with different values (0 when fast-only).
    pub value_mismatches: u64,
}

impl SquashValidationStats {
    /// Returns `true` if all validation checks passed.
    pub fn is_valid(&self) -> bool {
        let fast_valid = self.archival_root_present
            && self.archival_root_matches
            && self.squash_node_hash_present
            && self.squash_node_hash_matches
            && self.root_hash_missing == 0
            && self.root_hash_mismatches == 0
            && self.blob_offset_mismatches == 0;

        // If a full leaf scan was performed (either direction checked any keys),
        // also validate the leaf-level results.
        let full_scan_performed = self.source_keys_checked > 0 || self.squashed_keys_checked > 0;
        let leaf_valid = !full_scan_performed
            || (self.missing_in_squashed == 0
                && self.missing_in_source == 0
                && self.value_mismatches == 0);

        fast_valid && leaf_valid
    }
}

/// Step 1: Build an in-memory block_map from all `marf_data` entries.
fn collect_block_map<T: MarfTrieId>(src: &MARF<T>) -> Result<HashMap<T, (u32, u64)>, Error> {
    let all_blocks = trie_sql::bulk_read_block_entries::<T>(src.sqlite_conn())?;
    Ok(all_blocks
        .into_iter()
        .map(|(id, bh, offset)| (bh, (id, offset)))
        .collect())
}

/// Step 2: For each height 0..=H, resolve (block_hash, root_hash) via trie
/// walk + direct blob seek.
fn collect_per_height_metadata<T: MarfTrieId>(
    src: &mut MARF<T>,
    source_tip: &T,
    block_map: &HashMap<T, (u32, u64)>,
    blob_reader: &mut BlobReader,
    height: u32,
    label: &str,
) -> Result<Vec<BlockInfo<T>>, Error> {
    let mut block_info: Vec<BlockInfo<T>> = Vec::with_capacity((height + 1) as usize);
    let mut last_log = Instant::now();
    let start = Instant::now();

    for h in 0..=height {
        let h_key = format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{h}");
        let val = src
            .with_conn(|conn| MARF::<T>::get_by_key(conn, source_tip, &h_key))?
            .ok_or_else(|| {
                Error::CorruptionError(format!("Missing height mapping for height {h}"))
            })?;
        let bh = T::from(val);

        let &(block_id, blob_offset) = block_map.get(&bh).ok_or_else(|| {
            Error::CorruptionError(format!(
                "Missing block map entry for block hash at height {h}"
            ))
        })?;

        let rh = blob_reader.read_root_hash(block_id, blob_offset)?;

        block_info.push((h, bh, rh));

        if last_log.elapsed().as_secs() >= 30 || (h > 0 && h % 100_000 == 0) {
            info!(
                "[{label}] [2/8] Build height index: {}/{} heights in {}",
                h + 1,
                height + 1,
                fmt_duration(start.elapsed())
            );
            last_log = Instant::now();
        }
    }
    info!(
        "[{label}] [2/8] Build height index: {} heights in {}",
        height + 1,
        fmt_duration(start.elapsed())
    );

    Ok(block_info)
}

/// Step 4: Bulk-insert `marf_data` placeholder rows for blocks 0..H-1.
///
/// Returns a mapping from archival block_id to squashed block_id.
fn insert_placeholder_blocks<T: MarfTrieId>(
    conn: &rusqlite::Connection,
    block_info: &[BlockInfo<T>],
    block_at_height: &T,
    block_map: &HashMap<T, (u32, u64)>,
    label: &str,
) -> Result<HashMap<u32, u32>, Error> {
    let start = Instant::now();
    let mut archival_to_squashed: HashMap<u32, u32> = HashMap::new();
    let mut stmt = conn.prepare(PLACEHOLDER_INSERT_SQL)?;
    for (h, bh, _) in block_info {
        if bh == block_at_height {
            continue;
        }
        let (archival_id, _) = block_map.get(bh).ok_or(Error::NotFoundError)?;
        let empty_blob: &[u8] = &[];
        let squashed_id: u32 = stmt
            .insert(params![bh.to_string(), empty_blob, 0i64, 0i64])?
            .try_into()
            .expect("block_id overflow");
        archival_to_squashed.insert(*archival_id, squashed_id);
        if *h % 100_000 == 0 && *h > 0 {
            info!(
                "[{label}] [4/8] Register placeholder blocks: {h} of {} in {}",
                block_info.len(),
                fmt_duration(start.elapsed())
            );
        }
    }
    info!(
        "[{label}] [4/8] Register placeholder blocks: {} entries in {}",
        archival_to_squashed.len(),
        fmt_duration(start.elapsed())
    );
    Ok(archival_to_squashed)
}

/// SQL used to insert an empty placeholder row into `marf_data`.
const PLACEHOLDER_INSERT_SQL: &str =
    "INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) \
     VALUES (?1, ?2, 0, ?3, ?4)";

/// Step 6: Write all squash SQL metadata in one transaction scope.
fn persist_squash_metadata<T: MarfTrieId>(
    conn: &rusqlite::Connection,
    block_info: &[BlockInfo<T>],
    source_root_hash: &TrieHash,
    height: u32,
) -> Result<(), Error> {
    let start = Instant::now();
    trie_sql::write_squash_info(conn, source_root_hash, height)?;
    let mut stmt = conn.prepare(
        "INSERT OR REPLACE INTO marf_squash_archival_marf_roots (height, marf_root_hash) VALUES (?1, ?2)",
    )?;
    let mut stmt_bh = conn.prepare(
        "INSERT OR REPLACE INTO marf_squash_block_heights (block_hash, height) VALUES (?1, ?2)",
    )?;
    for (h, bh, rh) in block_info {
        stmt.execute(params![*h as i64, rh.as_bytes().to_vec()])?;
        stmt_bh.execute(params![bh.to_string(), *h as i64])?;
    }
    info!(
        "Squash: wrote {} root hashes and block heights in {}",
        block_info.len(),
        fmt_duration(start.elapsed())
    );
    Ok(())
}

/// Post-commit: persist `squash_root_node_hash` and share blob offsets.
fn finalize_shared_blob_offsets<T: MarfTrieId>(
    dst: &mut MARF<T>,
    block_at_height: &T,
    squash_root_node_hash: &TrieHash,
) -> Result<usize, Error> {
    // Persist squash_root_node_hash to SQL.
    {
        let conn = dst.sqlite_conn();
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| Error::CorruptionError(format!("BEGIN squash_root_node_hash: {e}")))?;
        trie_sql::update_squash_root_node_hash(conn, squash_root_node_hash)?;
        conn.execute_batch("COMMIT")
            .map_err(|e| Error::CorruptionError(format!("COMMIT squash_root_node_hash: {e}")))?;
    }

    // Bulk-update placeholders to share the tip block's blob offset.
    let start = Instant::now();
    let conn = dst.sqlite_conn();
    let bh_id = trie_sql::get_block_identifier(conn, block_at_height)?;
    let (offset, length) = trie_sql::get_external_trie_offset_length(conn, bh_id)?;

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| Error::CorruptionError(format!("BEGIN: {e}")))?;
    let updated = trie_sql::bulk_update_blob_offsets(conn, offset, length, block_at_height)?;
    conn.execute_batch("COMMIT")
        .map_err(|e| Error::CorruptionError(format!("COMMIT: {e}")))?;
    info!(
        "Squash: updated {} placeholder blob offsets in {}",
        updated,
        fmt_duration(start.elapsed())
    );
    Ok(updated)
}

impl<T: MarfTrieId> MARF<T> {
    /// Squash the MARF at `height` into a new database at `dst_path`.
    ///
    /// Produces a hash-preserving squash: the squashed MARF contains a single
    /// shared trie storage with all trie nodes reachable at `height`. Each historical
    /// block (0..=height) has a `marf_data` row pointing at this shared trie storage so
    /// that `get_block_hash_caching(local_id)` returns the correct original
    /// `StacksBlockId`.
    ///
    /// Backpointer identity is preserved via `TriePtr.back_block` annotations.
    /// Children that were backpointers in the archival MARF are stored inline in
    /// the blob but with `back_block` set to the squashed DB's local_id for the
    /// original block.  When the squashed MARF is extended to height H+1,
    /// `node_copy_update_ptrs` preserves these annotations, ensuring
    /// that `inner_write_children_hashes` uses the same `StacksBlockId` values
    /// as the archival MARF.  This guarantees identical per-block root hashes.
    pub fn squash_to_path(
        src_path: &str,
        dst_path: &str,
        open_opts: MARFOpenOpts,
        height: u32,
        label: &str,
    ) -> Result<SquashStats, Error> {
        if open_opts.compress {
            return Err(Error::CorruptionError(
                "squash_to_path does not support compress=true; \
                 the direct blob write path only emits uncompressed nodes"
                    .to_string(),
            ));
        }

        let overall_start = Instant::now();

        // Step 1: bulk SQL block map
        let src_storage = TrieFileStorage::open_readonly(src_path, open_opts.clone())?;
        let mut src = MARF::from_storage(src_storage);

        let tip = trie_sql::get_latest_confirmed_block_hash::<T>(src.sqlite_conn())?;
        let block_at_height = src
            .get_block_at_height(height, &tip)?
            .ok_or(Error::NotFoundError)?;

        let start = Instant::now();
        let block_map = collect_block_map(&src)?;
        info!(
            "[{label}] [1/8] Load block map: {} entries in {}",
            block_map.len(),
            fmt_duration(start.elapsed())
        );

        // [2/8] Build height index
        info!(
            "[{label}] [2/8] Build height index: reading {} heights...",
            height + 1
        );
        let mut blob_reader = BlobReader::new(src_path, open_opts.external_blobs)?;
        let block_info = collect_per_height_metadata(
            &mut src,
            &tip,
            &block_map,
            &mut blob_reader,
            height,
            label,
        )?;

        // [3/8] Collect trie nodes (DFS walk)
        //
        // Derive the temp directory from dst_path: use the parent directory.
        let tmp_dir = std::path::Path::new(dst_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .and_then(|p| p.to_str())
            .unwrap_or(".");
        log_memory_snapshot("before trie DFS");
        info!("[{label}] [3/8] Collect trie nodes: starting DFS...");
        let start = Instant::now();
        let (mut node_store, source_to_idx) = src.with_conn(|conn| {
            MARF::<T>::collect_reachable_nodes(conn, &block_at_height, tmp_dir)
        })?;
        let node_count = node_store.len() as u64;
        info!(
            "[{label}] [3/8] Collect trie nodes: {node_count} nodes in {}",
            fmt_duration(start.elapsed())
        );
        log_memory_snapshot("after trie DFS");

        let mut dst_open_opts = open_opts.clone();
        dst_open_opts.external_blobs = true;

        // Open destination MARF and begin transaction
        let mut dst = MARF::from_path(dst_path, dst_open_opts.clone())?;
        let mut tx = dst.begin_tx()?;
        tx.begin(&T::sentinel(), &block_at_height)?;

        // [4/8] Register placeholder blocks
        let mut archival_to_squashed = insert_placeholder_blocks(
            tx.sqlite_tx(),
            &block_info,
            &block_at_height,
            &block_map,
            label,
        )?;

        // Build `block_id_map`: every archival `block_id` that appears
        // as a node origin in the DFS must be mappable. insert_placeholder_blocks
        // covers heights 0..H-1 but skips block_at_height and sentinel.
        // Add them explicitly so `remap_child_ptrs` can resolve all children.
        //
        // Sentinel: flushed to marf_data by tx.begin() -> flush().
        let sentinel = T::sentinel();
        if let Some((archival_sentinel_id, _)) = block_map.get(&sentinel) {
            let squashed_sentinel_id: u32 = tx.sqlite_tx().query_row(
                "SELECT block_id FROM marf_data WHERE block_hash = ?1",
                rusqlite::params![sentinel.to_string()],
                |row| row.get(0),
            )?;
            archival_to_squashed.insert(*archival_sentinel_id, squashed_sentinel_id);
        }

        // block_at_height: not yet in the destination `marf_data` (only in
        // `block_extension_locks`). Insert an empty placeholder now to get a
        // real `block_id`. Step [7/8] will UPDATE this row instead of
        // inserting a new one via `update_external_trie_blob`.
        let squashed_tip_placeholder_id = {
            let (archival_tip_id, _) = block_map
                .get(&block_at_height)
                .ok_or(Error::NotFoundError)?;
            let empty_blob: &[u8] = &[];
            let placeholder_id = tx
                .sqlite_tx()
                .prepare(PLACEHOLDER_INSERT_SQL)?
                .insert(params![block_at_height.to_string(), empty_blob, 0i64, 0i64])?
                .try_into()
                .expect("block_id overflow");
            archival_to_squashed.insert(*archival_tip_id, placeholder_id);
            placeholder_id
        };
        drop(block_map);

        // [5/8] Remap trie pointers (disk-backed)
        log_memory_snapshot("before pointer remap");
        info!("[{label}] [5/8] Remap trie pointers: {node_count} nodes...");
        let start = Instant::now();
        remap_child_ptrs(
            &mut node_store,
            &source_to_idx,
            Some(&archival_to_squashed),
            label,
        )?;
        info!(
            "[{label}] [5/8] Remap trie pointers: {node_count} nodes in {}",
            fmt_duration(start.elapsed())
        );
        drop(source_to_idx);
        drop(archival_to_squashed);
        node_store.drop_block_ids(); // free ~200 MB
        log_memory_snapshot("after pointer remap");

        // [6/8] Recompute node hashes (disk-backed)
        log_memory_snapshot("before hash recompute");
        info!("[{label}] [6/8] Recompute node hashes: {node_count} nodes...");
        let start = Instant::now();
        recompute_content_hashes(&mut node_store)?;
        info!(
            "[{label}] [6/8] Recompute node hashes: {node_count} nodes in {}",
            fmt_duration(start.elapsed())
        );
        log_memory_snapshot("after hash recompute");

        let squash_root_node_hash = if node_store.len() > 0 {
            node_store.hash(0)
        } else {
            return Err(Error::CorruptionError(
                "No nodes in squash trie".to_string(),
            ));
        };

        // [7/8] Write trie blob (compute offsets + stream to destination)
        log_memory_snapshot("before blob write");
        info!("[{label}] [7/8] Write trie blob: {node_count} nodes...");
        let start = Instant::now();
        let parent_hash = T::sentinel();

        let (blob_offsets, total_blob_size) = compute_blob_offsets(&mut node_store)?;
        // Destination squash MARFs always use external blobs.
        let block_id = tx.storage.with_trie_blobs(|db, blobs| {
            let Some(trie_file) = blobs else {
                return Err(Error::CorruptionError(
                    "squash destination requires external .blobs file but handle is unavailable"
                        .to_string(),
                ));
            };
            let offset = trie_sql::get_external_blobs_length(db)?;
            trie_file
                .seek(SeekFrom::Start(offset))
                .map_err(Error::IOError)?;
            // buffer size is 1 MiB, completely arbitrary.
            let mut buf_writer = BufWriter::with_capacity(1 << 20, trie_file);
            stream_squash_blob(
                &mut node_store,
                &parent_hash,
                &blob_offsets,
                &mut buf_writer,
            )?;
            buf_writer.flush().map_err(Error::IOError)?;
            let trie_file = buf_writer.into_inner().map_err(|e| {
                Error::IOError(std::io::Error::other(format!(
                    "failed to flush BufWriter: {e}"
                )))
            })?;
            trie_file.flush().map_err(Error::IOError)?;
            trie_file.sync_data().map_err(Error::IOError)?;
            trie_sql::update_external_trie_blob(
                db,
                &block_at_height,
                offset,
                total_blob_size,
                squashed_tip_placeholder_id,
            )
        })?;
        info!(
            "[{label}] [7/8] Write trie blob: block_id={block_id}, {total_blob_size} bytes in {}",
            fmt_duration(start.elapsed())
        );
        drop(blob_offsets);
        drop(node_store); // free temp file + metadata
        log_memory_snapshot("after blob write");

        // [8/8] Persist metadata & commit
        let step8_start = Instant::now();
        let source_root_hash = block_info
            .iter()
            .find(|(_, bh, _)| bh == &block_at_height)
            .map(|(_, _, rh)| *rh)
            .ok_or(Error::NotFoundError)?;
        persist_squash_metadata(tx.sqlite_tx(), &block_info, &source_root_hash, height)?;
        info!("[{label}] Squash root hash: {squash_root_node_hash}");

        tx.set_squash_info(Some(SquashInfo {
            archival_marf_root_hash: source_root_hash,
            squash_root_node_hash,
            height,
        }));

        // Commit the SQL transaction without flushing TrieRAM (we already wrote the blob directly)
        tx.commit_squash()?;

        // Post-commit: share blob offsets across placeholder blocks
        finalize_shared_blob_offsets(&mut dst, &block_at_height, &squash_root_node_hash)?;

        info!(
            "[{label}] [8/8] Persist metadata & commit: finished in {}",
            fmt_duration(step8_start.elapsed())
        );

        info!(
            "[{label}] Squash complete: {node_count} nodes, total time {}",
            fmt_duration(overall_start.elapsed())
        );

        Ok(SquashStats { node_count })
    }

    /// DFS collection pass: gather all trie nodes reachable from `block_hash`.
    ///
    /// Uses a disk-backed `NodeStore` to avoid holding ~50M full node objects
    /// in memory (~20 GB). Only lightweight metadata (hashes, block_ids,
    /// file offsets) is kept in RAM (~4 GB).
    ///
    /// Uses iterative DFS instead of BFS. The DFS stack holds at most
    /// `trie_height` frames (~32), each with one node's child pointer list.
    /// Total stack memory is ~128 KB, compared to the BFS frontier which
    /// could hold millions of entries (~GBs) for wide, hash-distributed tries.
    ///
    /// Nodes are pushed in DFS preorder (parent before children), which is
    /// all the remap and hash-recompute passes require.
    ///
    /// Returns:
    /// - `node_store`: disk-backed node data + in-memory metadata.
    /// - `source_to_idx`: `(source_block_id, byte_offset) -> node index` map
    ///   needed by the remap pass.
    fn collect_reachable_nodes(
        source: &mut TrieStorageConnection<T>,
        block_hash: &T,
        tmp_dir: &str,
    ) -> Result<(NodeStore, HashMap<(u32, u64), usize>), Error> {
        source.open_block(block_hash)?;
        let (root_node, root_hash) = Trie::read_root(source)?;
        let root_block_id = source.get_cur_block_identifier()?;

        let mut store = NodeStore::new(tmp_dir)?;
        let mut source_to_idx: HashMap<(u32, u64), usize> = HashMap::new();

        let root_disk_ptr = TrieStorageConnection::<T>::root_ptr_disk();
        source_to_idx.insert((root_block_id, root_disk_ptr), 0);

        let root_is_leaf = root_node.is_leaf();
        let root_ptrs: Vec<TriePtr> = if root_is_leaf {
            vec![]
        } else {
            root_node.ptrs().to_vec()
        };
        store.push(&root_node, root_hash, root_block_id)?;

        // DFS stack frame: holds remaining child pointers for one node.
        // Stack depth is bounded by trie height (~32), so total memory is
        // ~32 * max_ptrs * sizeof(TriePtr) ≈ 128 KB - negligible.
        struct DfsFrame {
            origin_block_id: u32,
            child_ptrs: Vec<TriePtr>,
            next_child: usize,
        }

        let mut stack: Vec<DfsFrame> = Vec::new();
        if !root_is_leaf {
            stack.push(DfsFrame {
                origin_block_id: root_block_id,
                child_ptrs: root_ptrs,
                next_child: 0,
            });
        }

        let dfs_start = Instant::now();
        let mut nodes_collected: u64 = 1; // root already counted
        let mut last_log = Instant::now();

        while !stack.is_empty() {
            let stack_depth = stack.len();
            let frame = stack.last_mut().expect("stack is non-empty");
            // Scan this frame's remaining children for the next one to descend into.
            let mut descend_frame: Option<DfsFrame> = None;

            while frame.next_child < frame.child_ptrs.len() {
                let ptr = *frame
                    .child_ptrs
                    .get(frame.next_child)
                    .expect("BUG: next_child within bounds");
                frame.next_child += 1;

                if ptr.id() == TrieNodeID::Empty as u8 {
                    continue;
                }

                let (child_block_id, read_ptr) = if is_backptr(ptr.id()) {
                    (ptr.back_block(), ptr.from_backptr())
                } else {
                    (frame.origin_block_id, ptr)
                };

                let source_key = (child_block_id, read_ptr.ptr());
                if source_to_idx.contains_key(&source_key) {
                    continue;
                }

                let child_bh = source.get_block_from_local_id(child_block_id)?.clone();
                source.open_block_maybe_id(&child_bh, Some(child_block_id))?;
                let (child_node, child_hash) = source.read_nodetype(&read_ptr)?;

                let child_is_leaf = child_node.is_leaf();
                let child_ptrs_vec: Vec<TriePtr> = if child_is_leaf {
                    vec![]
                } else {
                    child_node.ptrs().to_vec()
                };

                source_to_idx.insert(source_key, store.len());
                store.push(&child_node, child_hash, child_block_id)?;

                nodes_collected += 1;
                if last_log.elapsed().as_secs() >= 30 || nodes_collected % 1_000_000 == 0 {
                    info!(
                        "Trie DFS: {nodes_collected} nodes, stack depth {stack_depth}, {} elapsed",
                        fmt_duration(dfs_start.elapsed())
                    );
                    last_log = Instant::now();
                }

                // If internal node, descend into it (push frame and break).
                // If leaf, continue scanning siblings.
                if !child_is_leaf {
                    descend_frame = Some(DfsFrame {
                        origin_block_id: child_block_id,
                        child_ptrs: child_ptrs_vec,
                        next_child: 0,
                    });
                    break;
                }
            }

            match descend_frame {
                Some(new_frame) => stack.push(new_frame),
                None => {
                    // All children of this frame processed, backtrack.
                    stack.pop();
                }
            }
        }

        store.finish_writing()?;

        info!(
            "Trie DFS: {} nodes in {}",
            store.len(),
            fmt_duration(dfs_start.elapsed())
        );

        Ok((store, source_to_idx))
    }
}
