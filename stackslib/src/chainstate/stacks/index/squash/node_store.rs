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

use std::fs::File;
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};

use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

use crate::chainstate::stacks::index::file::read_exact_at;
use crate::chainstate::stacks::index::node::{
    TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::{Error, MARFValue, TrieLeaf};

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
fn read_trie_ptr<R: Read>(r: &mut R) -> Result<TriePtr, Error> {
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
/// Format: [tag: u8] [path_len: u8] [path bytes] [variant data]
pub(crate) fn serialize_node<W: Write>(w: &mut W, node: &TrieNodeType) -> Result<(), Error> {
    fn write_path<W: Write>(w: &mut W, path: &[u8]) -> Result<(), Error> {
        if path.len() > TRIEHASH_ENCODED_SIZE {
            return Err(Error::CorruptionError(format!(
                "serialize_node: path length {} exceeds {TRIEHASH_ENCODED_SIZE}",
                path.len()
            )));
        }
        // `path.len() <= 32` so this never widens.
        let len = path.len() as u8;
        w.write_all(&[len])?;
        w.write_all(path)?;
        Ok(())
    }
    match node {
        TrieNodeType::Leaf(leaf) => {
            w.write_all(&[TAG_LEAF])?;
            write_path(w, &leaf.path)?;
            w.write_all(&leaf.data.0)?;
        }
        TrieNodeType::Node4(n) => {
            w.write_all(&[TAG_NODE4])?;
            write_path(w, &n.path)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
        TrieNodeType::Node16(n) => {
            w.write_all(&[TAG_NODE16])?;
            write_path(w, &n.path)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
        TrieNodeType::Node48(n) => {
            w.write_all(&[TAG_NODE48])?;
            write_path(w, &n.path)?;
            let indexes = n.indexes.map(|idx| idx as u8);
            w.write_all(&indexes)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
        TrieNodeType::Node256(n) => {
            w.write_all(&[TAG_NODE256])?;
            write_path(w, &n.path)?;
            for p in &n.ptrs {
                write_trie_ptr(w, p)?;
            }
        }
    }
    Ok(())
}

/// Deserialize a `TrieNodeType` from the reader.
pub(crate) fn deserialize_node<R: Read>(r: &mut R) -> Result<TrieNodeType, Error> {
    let mut tag = [0u8; 1];
    r.read_exact(&mut tag)?;
    let mut path_len_buf = [0u8; 1];
    r.read_exact(&mut path_len_buf)?;
    let path_len = path_len_buf[0] as usize;
    if path_len > TRIEHASH_ENCODED_SIZE {
        return Err(Error::CorruptionError(format!(
            "deserialize_node: path length {path_len} exceeds {TRIEHASH_ENCODED_SIZE}"
        )));
    }
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

/// `Write`/`Seek` adapter that keeps the current stream position in memory.
pub(super) struct CountingWriter<W> {
    inner: W,
    offset: u64,
}

impl<W> CountingWriter<W> {
    /// Create a writer whose inner stream is known to be positioned at 0.
    pub(super) fn new(inner: W) -> Self {
        Self { inner, offset: 0 }
    }

    /// Create a writer whose current position is already known.
    pub(super) fn with_position(inner: W, offset: u64) -> Self {
        Self { inner, offset }
    }

    pub(super) fn position(&self) -> u64 {
        self.offset
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.offset = self
            .offset
            .checked_add(written as u64)
            .ok_or_else(|| std::io::Error::other("CountingWriter offset overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for CountingWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let offset = self.inner.seek(pos)?;
        self.offset = offset;
        Ok(offset)
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.offset)
    }
}

/// Disk-backed store for collected trie nodes.
///
/// Full node data is serialized to a temporary file. Only lightweight
/// per-node metadata (hash, block_id, file offset) is kept in memory.
pub(crate) struct NodeStore {
    /// Temp file holding serialized nodes (write handle).
    writer: CountingWriter<BufWriter<File>>,
    /// Read handle to the temp file.
    reader: File,
    /// Reusable `read_node` buffer.
    scratch: Vec<u8>,
    /// End offset of the last pushed node.
    total_bytes: u64,
    /// Set once `overwrite_node` has been called. While the store is sealed
    /// no further `push` is allowed.
    sealed: bool,
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
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut path = std::path::PathBuf::from(dir);
        path.push(format!(".squash_nodes_{pid}_{nanos}.tmp"));
        let temp_file = File::options().write(true).create_new(true).open(&path)?;
        Ok(NodeStore {
            writer: CountingWriter::new(BufWriter::with_capacity(1 << 20, temp_file)),
            reader: File::open(&path)?,
            // Node256 (the largest) has a size of 3.7KiB.
            scratch: vec![0; 4 * 1024],
            total_bytes: 0,
            sealed: false,
            path,
            file_offsets: Vec::new(),
            hashes: Vec::new(),
            block_ids: Vec::new(),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.file_offsets.len()
    }

    /// Append a node. Returns the node's index.
    ///
    /// Errors once `overwrite_node` has been called: the writer is no
    /// longer at end-of-file, so an append would corrupt an earlier node.
    pub(crate) fn push(
        &mut self,
        node: &TrieNodeType,
        hash: TrieHash,
        block_id: u32,
    ) -> Result<usize, Error> {
        if self.sealed {
            return Err(Error::CorruptionError(
                "NodeStore::push: store is sealed; cannot push after overwrite_node".to_string(),
            ));
        }
        let idx = self.file_offsets.len();

        self.file_offsets.push(self.writer.position());
        self.hashes.push(hash);
        self.block_ids.push(block_id);
        serialize_node(&mut self.writer, node)?;
        // Used as the end boundary for the last node.
        self.total_bytes = self.writer.position();
        Ok(idx)
    }

    /// Overwrite the node at `idx` in place.
    ///
    /// The new serialization length must match the original.
    /// Seals the store before writing.
    pub(crate) fn overwrite_node(&mut self, idx: usize, node: &TrieNodeType) -> Result<(), Error> {
        let offset = *self.file_offsets.get(idx).ok_or_else(|| {
            Error::CorruptionError(format!("overwrite_node: index {idx} out of bounds"))
        })?;
        let slot_end = self
            .file_offsets
            .get(idx + 1)
            .copied()
            .unwrap_or(self.total_bytes);
        let slot_len = slot_end.checked_sub(offset).ok_or_else(|| {
            Error::CorruptionError(format!(
                "overwrite_node: slot_end {slot_end} < offset {offset} for idx {idx}"
            ))
        })?;

        // Seal before touching the writer so a partial or mismatched
        // overwrite still locks out subsequent pushes.
        self.sealed = true;

        if self.writer.position() != offset {
            self.writer
                .seek(SeekFrom::Start(offset))
                .map_err(Error::IOError)?;
        }
        serialize_node(&mut self.writer, node)?;

        let written = self.writer.position().checked_sub(offset).ok_or_else(|| {
            Error::CorruptionError("overwrite_node: writer position regressed".to_string())
        })?;
        if written != slot_len {
            return Err(Error::CorruptionError(format!(
                "overwrite_node: re-serialized node {idx} changed length \
                 from {slot_len} to {written} bytes"
            )));
        }

        Ok(())
    }

    /// Flush buffered writes so subsequent `read_node` calls see them.
    pub(crate) fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush().map_err(Error::IOError)?;
        Ok(())
    }

    /// Read the node at `idx`.
    ///
    /// `read_node` uses an independent file handle and cannot observe
    /// writes still sitting in the `BufWriter`. After a remap pass
    /// that called `overwrite_node`, a `flush` is required before the
    /// next read pass.
    pub(crate) fn read_node(&mut self, idx: usize) -> Result<TrieNodeType, Error> {
        let size = self.node_size(idx)?;
        let offset = *self.file_offsets.get(idx).ok_or_else(|| {
            Error::CorruptionError(format!("NodeStore: index {idx} out of bounds"))
        })?;

        if self.scratch.len() < size {
            self.scratch.resize(size, 0);
        }
        let scratch_mut = self.scratch.get_mut(..size).ok_or_else(|| {
            Error::CorruptionError(format!("NodeStore: scratch < {size} after resize"))
        })?;
        read_exact_at(&self.reader, scratch_mut, offset).map_err(Error::IOError)?;
        let scratch_ref = self.scratch.get(..size).ok_or_else(|| {
            Error::CorruptionError(format!("NodeStore: scratch < {size} after read"))
        })?;
        let mut cursor = Cursor::new(scratch_ref);
        deserialize_node(&mut cursor)
    }

    /// Serialized byte size of node `idx`.
    fn node_size(&self, idx: usize) -> Result<usize, Error> {
        let off = *self.file_offsets.get(idx).ok_or_else(|| {
            Error::CorruptionError(format!("NodeStore::node_size: idx {idx} out of bounds"))
        })?;
        let end = self
            .file_offsets
            .get(idx + 1)
            .copied()
            .unwrap_or(self.total_bytes);
        if end < off {
            return Err(Error::CorruptionError(format!(
                "NodeStore::node_size: end {end} < off {off} for idx {idx}"
            )));
        }
        usize::try_from(end - off).map_err(|_| Error::OverflowError)
    }

    pub(crate) fn get_hash(&self, idx: usize) -> &TrieHash {
        self.hashes.get(idx).unwrap_or_else(|| {
            panic!(
                "NodeStore::get_hash: index {idx} out of bounds (len={})",
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
    pub(crate) fn drop_block_ids(&mut self) {
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
