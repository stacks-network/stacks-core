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

//! Shared constants for the MARF trie blob header.
//!
//! ```text
//! offset  size  field
//!      0    32  parent_hash         (T::sentinel for the squash blob)
//!     32     4  reserved            (historically a local block-id; written as 0u32 LE)
//!     36   ...  root node           (first 32 bytes are its TrieHash)
//! ```
//!
//! The root node's first bytes are its hash.

use stacks_common::types::chainstate::{BLOCK_HEADER_HASH_ENCODED_SIZE, TRIEHASH_ENCODED_SIZE};

/// Offset of the reserved 4-byte field.
pub const RESERVED_FIELD_OFFSET: usize = BLOCK_HEADER_HASH_ENCODED_SIZE;

/// Length of the reserved field.
pub const RESERVED_FIELD_LEN: usize = 4;

/// Offset where the root node, and therefore the root hash, begins.
pub const ROOT_NODE_OFFSET: usize = RESERVED_FIELD_OFFSET + RESERVED_FIELD_LEN;

/// Bytes needed to read `parent_hash || reserved || root_hash`.
pub const READER_PREFIX_LEN: usize = ROOT_NODE_OFFSET + TRIEHASH_ENCODED_SIZE;

// If these values change, update the blob writers in `storage.rs`
// (`TrieRAM::dump_consume`, `TrieRAM::dump_compressed_consume`) and the
// header reader in `file.rs` (`TrieFile::read_parent_and_root_hash`).
const _: () = {
    assert!(BLOCK_HEADER_HASH_ENCODED_SIZE == 32);
    assert!(TRIEHASH_ENCODED_SIZE == 32);
    assert!(RESERVED_FIELD_OFFSET == 32);
    assert!(ROOT_NODE_OFFSET == 36);
    assert!(READER_PREFIX_LEN == 68);
};
