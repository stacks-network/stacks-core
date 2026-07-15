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

//! MARF squashing: offline snapshot creation.
//!
//! A squashed MARF contains only the canonical state at a given
//! height H plus the metadata needed for ancestor hash lookups and
//! block-height resolution.

use std::collections::HashMap;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::params;
use stacks_common::types::chainstate::TrieHash;

use crate::chainstate::stacks::index::blob_layout::BlobHeader;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection as _, MARF};
use crate::chainstate::stacks::index::node::{clear_backptr, is_backptr, TrieNodeID, TriePtr};
use crate::chainstate::stacks::index::storage::{
    SquashInfo, TrieFileStorage, TrieHashCalculationMode, TrieStorageConnection,
};
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{trie_sql, Error, MarfDataEntry, MarfTrieId};

mod node_store;
mod stream;

pub(crate) use node_store::NodeStore;
#[cfg(test)]
pub(crate) use node_store::{deserialize_node, serialize_node};
#[cfg(test)]
pub(crate) use stream::compute_node_hash;
use stream::recompute_content_hashes;
pub(crate) use stream::stream_squash_blob;

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

/// Emit a progress log every this many heights walked.
const LOG_PROGRESS_HEIGHT_INTERVAL: u32 = 100_000;
/// Emit a progress log every this many nodes processed.
const LOG_PROGRESS_NODE_INTERVAL: u64 = 1_000_000;
/// Emit a progress log at least this often, regardless of count.
const LOG_PROGRESS_TIME_INTERVAL_SECS: u64 = 30;

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

/// Use faster SQLite settings while building the fresh squash output.
///
/// If the build fails the partial output is expected to be discarded, so
/// rollback journaling and fsyncs add no value during the one-shot build.
/// Call [`restore_default_squash_pragmas`] before returning the completed MARF.
fn apply_offline_squash_pragmas(conn: &rusqlite::Connection) -> Result<(), Error> {
    conn.pragma_update(None, "journal_mode", "OFF")?;
    conn.pragma_update(None, "synchronous", "OFF")?;
    Ok(())
}

/// Restore SQLite defaults after [`apply_offline_squash_pragmas`].
fn restore_default_squash_pragmas(conn: &rusqlite::Connection) -> Result<(), Error> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

/// Remap child pointers in a `NodeStore` for the squashed trie layout.
///
/// For each non-leaf node, reads it from the temp file, remaps its child
/// pointers from source (block_id, offset) to sequential indices, and
/// writes the modified node back.
///
/// Each child's `back_block` becomes its squashed block id, preserving block
/// identity when the squashed MARF is extended later.
fn remap_child_ptrs(
    store: &mut NodeStore,
    source_to_idx: &HashMap<(u32, u64), usize>,
    block_id_map: &[u32],
    label: &str,
) -> Result<(), Error> {
    let remap_start = Instant::now();
    let node_count = store.len();

    for idx in 0..node_count {
        if idx > 0 && idx as u64 % LOG_PROGRESS_NODE_INTERVAL == 0 {
            info!(
                "[{label}] Remap trie pointers: {idx}/{node_count} nodes in {}",
                fmt_duration(remap_start.elapsed())
            );
        }

        let mut node = store.read_node(idx)?;
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

            ptr.back_block = block_id_map
                .get(child_block_id as usize)
                .copied()
                .filter(|&v| v != 0)
                .ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "remap_child_ptrs: block_id {child_block_id} not in block_id_map"
                    ))
                })?;
            modified = true;
        }

        if modified {
            store.overwrite_node(idx, &node)?;
        }
    }
    store.flush()?;

    info!(
        "[{label}] Remap trie pointers complete: {node_count} nodes in {}",
        fmt_duration(remap_start.elapsed())
    );
    Ok(())
}

/// Per-height block metadata used to build the squash side table.
#[derive(Debug, Clone)]
struct BlockInfo<T> {
    height: u32,
    block_hash: T,
    root_hash: TrieHash,
}

/// Wall-clock duration of each squash step.
#[derive(Debug, Clone, Default)]
pub struct SquashStepDurations {
    /// [1/8] Load confirmed block ids, hashes, and blob offsets.
    pub load_block_map: Duration,
    /// [2/8] Walk per-height keys and resolve each block's root hash.
    pub build_height_index: Duration,
    /// [3/8] DFS over the reachable trie nodes at the squash tip.
    pub collect_trie_nodes: Duration,
    /// [4/8] Bulk-insert placeholder rows for blocks 0..H-1.
    pub register_placeholders: Duration,
    /// [5/8] Disk-backed remap of inline pointers and backpointers.
    pub remap_pointers: Duration,
    /// [6/8] Recompute leaf and internal node hashes.
    pub recompute_hashes: Duration,
    /// [7/8] Stream the squashed trie blob to the destination.
    pub write_trie_blob: Duration,
    /// [8/8] Persist squash metadata, broadcast blob offsets, commit.
    pub persist_metadata: Duration,
}

/// Summary statistics from a squashing run.
#[derive(Debug, Clone)]
pub struct SquashStats {
    /// Total number of nodes collected into the squashed MARF.
    pub node_count: u64,
    /// MARF height the squash was created at (blocks 0..=squash_height are squashed).
    /// Stacks block height for clarity/index MARFs, sortition block height for
    /// the sortition MARF.
    pub squash_height: u32,
    /// Path to the destination MARF SQLite database.
    pub dst_db_path: PathBuf,
    /// Path to the destination `.blobs` file containing the shared trie.
    pub dst_blobs_path: PathBuf,
    /// Size in bytes of the squashed trie blob written to `.blobs`.
    pub blob_size: u64,
    /// Number of placeholder rows inserted for historical blocks 0..H-1.
    pub historical_placeholder_count: u64,
    /// Root hash of the archival MARF at `squash_height`.
    pub source_root_hash: TrieHash,
    /// Hash of the squashed trie root node.
    pub squash_root_node_hash: TrieHash,
    /// Per-step wall-clock durations.
    pub step_durations: SquashStepDurations,
    /// End-to-end wall-clock duration of `squash_to_path`.
    pub total_duration: Duration,
}

/// Step 1: load the confirmed [`MarfDataEntry`] rows and seed the
/// blob-offset cache from the same scan.
///
/// Later steps reuse this Vec: header pre-read sorts it by offset, and
/// placeholder insertion consumes it to build a `block_hash -> id` map.
fn collect_block_entries<T: MarfTrieId>(src: &mut MARF<T>) -> Result<Vec<MarfDataEntry<T>>, Error> {
    src.with_conn(|conn| {
        let block_entries = trie_sql::bulk_read_block_entries::<T>(conn.sqlite_conn())?;
        conn.warm_trie_offsets_from_entries(&block_entries);
        Ok(block_entries)
    })
}

/// Check that blob-header parsing agrees with the MARF root reader for the
/// tip block. Looks up the tip's block_id via the indexed `block_hash` query
fn verify_blob_root_matches_marf<T: MarfTrieId>(
    conn: &mut TrieStorageConnection<T>,
    block_hash: &T,
) -> Result<(), Error> {
    let block_id = trie_sql::get_block_identifier(conn.sqlite_conn(), block_hash)?;
    let root_from_blob = conn.read_blob_header(block_id)?.root_hash;
    let root_from_marf = conn.get_root_hash_at(block_hash)?;
    if root_from_blob != root_from_marf {
        return Err(Error::CorruptionError(format!(
            "Blob root mismatch for {block_hash}: blob={root_from_blob}, marf={root_from_marf}"
        )));
    }
    Ok(())
}

/// Read blob headers in storage order for the later in-memory chain walk.
///
/// Caller must pre-sort `block_entries` by `external_offset`;
/// `bulk_read_blob_headers_sorted` splits that order into contiguous chunks
/// so each parallel reader stays in one file region. Falls back to per-row
/// reads through SQLite `blob_open` when the source MARF stores blobs
/// inside the SQLite database.
fn pre_read_blob_headers<T: MarfTrieId + Send + Sync>(
    conn: &mut TrieStorageConnection<T>,
    block_entries: &[MarfDataEntry<T>],
    label: &str,
) -> Result<HashMap<T, BlobHeader<T>>, Error> {
    let start = Instant::now();
    info!(
        "[{label}] [2/8] Pre-reading {} blob headers (sorted by offset)...",
        block_entries.len()
    );

    let headers = conn.bulk_read_blob_headers_sorted(block_entries)?;

    info!(
        "[{label}] [2/8] Pre-read {} headers in {}",
        headers.len(),
        fmt_duration(start.elapsed())
    );
    Ok(headers)
}

/// For each height 0..=height, resolve (block_hash, root_hash).
///
/// Headers are pre-read in storage order, then the parent walk uses the
/// in-memory map. Re-squash fills old heights from `marf_squashed_blocks`.
fn collect_per_height_metadata<T: MarfTrieId + Send + Sync>(
    conn: &mut TrieStorageConnection<T>,
    block_at_height: &T,
    block_entries: &mut [MarfDataEntry<T>],
    src_squash_height: Option<u32>,
    height: u32,
    label: &str,
) -> Result<Vec<BlockInfo<T>>, Error> {
    let mut block_info: Vec<BlockInfo<T>> = Vec::with_capacity((height + 1) as usize);
    let start = Instant::now();

    let sentinel = T::sentinel();
    // Rows below this come from the source squash table.
    let walk_floor = src_squash_height.map(|sh| sh + 1).unwrap_or(0);
    debug_assert!(walk_floor <= height);

    // Pre-read in offset order. Each parallel reader sweeps a
    // contiguous file region. `block_id` is only helpful for squashed
    // marfs (where every row shares the squash blob's offset);
    // no downstream logic depends on `block_id. ordering.
    block_entries.sort_unstable_by_key(|e| (e.external_offset, e.block_id));
    let headers = pre_read_blob_headers(conn, block_entries, label)?;

    // Walk down to the squash boundary, if any.
    let walk_start = Instant::now();
    let mut current = block_at_height.clone();
    for h in (walk_floor..=height).rev() {
        if current == sentinel {
            return Err(Error::CorruptionError(format!(
                "Block walk hit sentinel at height {h} (expected non-sentinel \
                 until height {walk_floor}); likely an off-by-one in caller's \
                 height arg or a truncated chain"
            )));
        }
        let header = headers.get(&current).ok_or_else(|| {
            Error::CorruptionError(format!(
                "Pre-read missing header for block hash {current} at height {h}"
            ))
        })?;
        block_info.push(BlockInfo {
            height: h,
            block_hash: current.clone(),
            root_hash: header.root_hash,
        });

        if h == 0 {
            // Genesis must point at sentinel.
            if header.parent_hash != sentinel {
                return Err(Error::CorruptionError(format!(
                    "Block at height 0 ({current}) has non-sentinel parent {}",
                    header.parent_hash
                )));
            }
        } else {
            current = header.parent_hash.clone();
        }
    }
    info!(
        "[{label}] [2/8] In-memory chain walk: {} heights in {}",
        height + 1 - walk_floor,
        fmt_duration(walk_start.elapsed())
    );
    // Release the header map before the node-collection step allocates more RAM.
    drop(headers);

    // Re-squash: fill pre-existing squash rows from the source side table.
    if walk_floor > 0 {
        let side_table = trie_sql::bulk_read_squashed_blocks::<T>(conn.sqlite_conn())?;
        let max_h = walk_floor - 1;
        // The first post-squash block must chain to the old squash tip.
        let boundary_bh = side_table
            .iter()
            .find(|(h, _, _)| *h == max_h)
            .map(|(_, bh, _)| bh.clone())
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "Source squash side table missing row for height {max_h}"
                ))
            })?;
        if current != boundary_bh {
            return Err(Error::CorruptionError(format!(
                "Re-squash boundary mismatch: block at height {walk_floor} \
                 claims parent {current}, but source squash side table has \
                 {boundary_bh} at height {max_h}"
            )));
        }
        for (h, bh, rh) in side_table {
            if h > max_h {
                return Err(Error::CorruptionError(format!(
                    "Source squash side table has row at height {h} > \
                     declared src_squash_height {max_h}"
                )));
            }
            block_info.push(BlockInfo {
                height: h,
                block_hash: bh,
                root_hash: rh,
            });
        }
        info!(
            "[{label}] [2/8] Build height index: filled heights 0..={max_h} from \
             source squash side table"
        );
    }

    if block_info.len() != (height as usize) + 1 {
        return Err(Error::CorruptionError(format!(
            "Build height index: expected {} entries, got {}",
            (height as usize) + 1,
            block_info.len()
        )));
    }

    block_info.sort_by_key(|b| b.height);

    info!(
        "[{label}] [2/8] Build height index: {} heights in {}",
        height + 1,
        fmt_duration(start.elapsed())
    );

    Ok(block_info)
}

/// Step 4: register historical block placeholders and the squash-tip row that
/// step [7/8] will later update with the real blob offset and length.
///
/// Consumes `block_entries` to build a temporary `block_hash -> archival_id`
/// map. Returns the archival-id -> squashed-id lookup for pointer remapping,
/// the tip placeholder id, and the historical placeholder count.
fn insert_placeholder_blocks<T: MarfTrieId>(
    conn: &rusqlite::Connection,
    block_info: &[BlockInfo<T>],
    block_at_height: &T,
    block_entries: Vec<MarfDataEntry<T>>,
    label: &str,
) -> Result<(Vec<u32>, u32, u64), Error> {
    let start = Instant::now();

    // Step [2/8] may have sorted the entries by offset.
    let max_archival_id = block_entries.iter().map(|e| e.block_id).max().unwrap_or(0);

    // Short-lived map for placeholder insertion.
    let block_map: HashMap<T, u32> = block_entries
        .into_iter()
        .map(|e| (e.block_hash, e.block_id))
        .collect();

    // Index by archival block_id; 0 means not mapped.
    let mut archival_to_squashed = vec![0u32; (max_archival_id as usize) + 1];
    let mut stmt = conn.prepare(PLACEHOLDER_INSERT_SQL)?;
    let mut historical_count: u64 = 0;
    for entry in block_info {
        if entry.block_hash == *block_at_height {
            continue;
        }
        let archival_id = *block_map
            .get(&entry.block_hash)
            .ok_or(Error::NotFoundError)?;
        let empty_blob: &[u8] = &[];
        let squashed_id: u32 = stmt
            .insert(params![
                entry.block_hash.to_string(),
                empty_blob,
                0i64,
                0i64
            ])?
            .try_into()
            .expect("block_id overflow");
        assert_ne!(
            squashed_id, 0,
            "SQLite rowid 0 collides with absent sentinel"
        );
        *archival_to_squashed
            .get_mut(archival_id as usize)
            .ok_or(Error::OverflowError)? = squashed_id;
        historical_count += 1;
        if entry.height % LOG_PROGRESS_HEIGHT_INTERVAL == 0 && entry.height > 0 {
            info!(
                "[{label}] [4/8] Register placeholder blocks: {} of {} in {}",
                entry.height,
                block_info.len(),
                fmt_duration(start.elapsed())
            );
        }
    }

    // Every archival `block_id` that appears as a node origin in the DFS
    // must be mappable in `archival_to_squashed`. The loop above covers the
    // historical heights but skips `block_at_height` and the sentinel; add
    // them explicitly so `remap_child_ptrs` can resolve all children.
    //
    // Sentinel: already flushed to the destination `marf_data` by
    // `tx.begin()` -> `flush()`, so mirror its id when the source has one.
    let sentinel = T::sentinel();
    if let Some(&archival_sentinel_id) = block_map.get(&sentinel) {
        let squashed_sentinel_id: u32 = conn.query_row(
            "SELECT block_id FROM marf_data WHERE block_hash = ?1",
            params![sentinel.to_string()],
            |row| row.get(0),
        )?;
        *archival_to_squashed
            .get_mut(archival_sentinel_id as usize)
            .ok_or(Error::OverflowError)? = squashed_sentinel_id;
    }

    // `block_at_height`: not yet in the destination `marf_data` (only in
    // `block_extension_locks`). Insert an empty placeholder now to get a
    // real `block_id`; step [7/8] will UPDATE this row with the real blob
    // via `update_external_trie_blob` instead of inserting a new one.
    let archival_tip_id = *block_map.get(block_at_height).ok_or(Error::NotFoundError)?;
    let empty_blob: &[u8] = &[];
    let squashed_tip_placeholder_id: u32 = stmt
        .insert(params![block_at_height.to_string(), empty_blob, 0i64, 0i64])?
        .try_into()
        .expect("block_id overflow");
    *archival_to_squashed
        .get_mut(archival_tip_id as usize)
        .ok_or(Error::OverflowError)? = squashed_tip_placeholder_id;

    info!(
        "[{label}] [4/8] Register placeholder blocks: {historical_count} historical + sentinel + tip in {}",
        fmt_duration(start.elapsed())
    );

    drop(block_map);

    Ok((
        archival_to_squashed,
        squashed_tip_placeholder_id,
        historical_count,
    ))
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
    squash_height: u32,
) -> Result<(), Error> {
    let start = Instant::now();
    trie_sql::write_squash_info(conn, source_root_hash, squash_height)?;

    const CHUNK_ROWS: usize = 500;

    let mut chunks = block_info.chunks_exact(CHUNK_ROWS);
    let tail = chunks.remainder();

    // Full chunks share one prepared statement.
    let full_sql = build_squashed_blocks_insert_sql(CHUNK_ROWS);
    let mut full_stmt = conn.prepare(&full_sql)?;
    for chunk in &mut chunks {
        bind_squashed_blocks_chunk(&mut full_stmt, chunk)?;
        full_stmt.raw_execute()?;
    }

    if !tail.is_empty() {
        let tail_sql = build_squashed_blocks_insert_sql(tail.len());
        let mut tail_stmt = conn.prepare(&tail_sql)?;
        bind_squashed_blocks_chunk(&mut tail_stmt, tail)?;
        tail_stmt.raw_execute()?;
    }
    info!(
        "Squash: wrote {} root hashes and block heights in {}",
        block_info.len(),
        fmt_duration(start.elapsed())
    );
    Ok(())
}

/// Bind one chunk of `(height, block_hash, marf_root_hash)` rows to a statement.
fn bind_squashed_blocks_chunk<T: MarfTrieId>(
    stmt: &mut rusqlite::Statement<'_>,
    chunk: &[BlockInfo<T>],
) -> rusqlite::Result<()> {
    for (i, entry) in chunk.iter().enumerate() {
        let base = i * 3;
        stmt.raw_bind_parameter(base + 1, i64::from(entry.height))?;
        stmt.raw_bind_parameter(base + 2, entry.block_hash.as_bytes())?;
        stmt.raw_bind_parameter(base + 3, entry.root_hash.as_bytes())?;
    }
    Ok(())
}

/// Build `INSERT INTO marf_squashed_blocks (...) VALUES (?,?,?),(?,?,?),...`
fn build_squashed_blocks_insert_sql(rows: usize) -> String {
    assert!(
        rows > 0,
        "build_squashed_blocks_insert_sql: rows must be >= 1"
    );
    let mut sql = String::from(
        "INSERT INTO marf_squashed_blocks (height, block_hash, marf_root_hash) VALUES (?,?,?)",
    );
    sql.push_str(&",(?,?,?)".repeat(rows - 1));
    sql
}

/// Persist `squash_root_node_hash` and broadcast the tip blob offset to every
/// confirmed `marf_data` row.
fn finalize_shared_blob_offsets<T: MarfTrieId>(
    conn: &rusqlite::Connection,
    block_at_height: &T,
    squash_root_node_hash: &TrieHash,
) -> Result<usize, Error> {
    trie_sql::update_squash_root_node_hash(conn, squash_root_node_hash)?;

    let start = Instant::now();
    let bh_id = trie_sql::get_block_identifier(conn, block_at_height)?;
    let (offset, length) = trie_sql::get_external_trie_offset_length(conn, bh_id)?;
    let updated = trie_sql::bulk_update_blob_offsets(conn, offset, length)?;
    info!(
        "Squash: updated {updated} marf_data blob offsets in {}",
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
    ///
    /// `tip` is used to identify the canonical fork the squash height
    /// lives on: it must be at or above `height`.
    ///
    /// # Squash preconditions
    ///
    /// `squash_to_path` rewrites one MARF. The boot-snapshot orchestrator
    /// must enforce these chainstate-wide invariants:
    ///
    /// 1. **Squash MARFs together.** Index, Clarity, and Sortition guards
    ///    must activate in one operation. Heights may differ by use case.
    /// 2. **Cap copied SQL at the boundary.** Side-tables and other
    ///    chainstate DBs contain only rows at or below their squash height;
    ///    post-squash data is synced after boot.
    /// 3. **Epoch 3.4 or later.** Earlier `at-block` reads arbitrary
    ///    historical state, which squashing cannot preserve.
    /// 4. **Finality buffer.** The boundary is at least six bitcoin tenures
    ///    behind the bitcoin tip, so copied data will not be reorged away.
    /// 5. **Canonical-only.** Squashed MARFs and copied side-tables contain
    ///    no orphan/pruned-fork rows; below the boundary the snapshot is
    ///    canonical by construction.
    pub fn squash_to_path(
        src_path: &str,
        dst_path: &str,
        src_open_opts: MARFOpenOpts,
        tip: &T,
        squash_height: u32,
        label: &str,
    ) -> Result<SquashStats, Error>
    where
        T: Send + Sync,
    {
        let dst_db_path = PathBuf::from(dst_path);
        let dst_blobs_path = PathBuf::from(format!("{dst_path}.blobs"));
        let dst_dir = match dst_db_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.canonicalize(),
            _ => std::env::current_dir(),
        }
        .map_err(Error::IOError)?;

        if dst_db_path.exists() {
            return Err(Error::DestinationExists(dst_path.to_string()));
        }
        if dst_blobs_path.exists() {
            return Err(Error::DestinationExists(
                dst_blobs_path.to_string_lossy().into_owned(),
            ));
        }

        let result = Self::squash_to_path_inner(
            src_path,
            &dst_dir,
            &dst_db_path,
            &dst_blobs_path,
            src_open_opts,
            tip,
            squash_height,
            label,
        );

        if let Err(e) = &result {
            error!(
                "[{label}] squash failed: {e}; leaving partial output at {dst_path} \
                 - remove before retrying"
            );
        }
        result
    }

    fn squash_to_path_inner(
        src_path: &str,
        dst_dir: &Path,
        dst_db_path: &Path,
        dst_blobs_path: &Path,
        src_open_opts: MARFOpenOpts,
        tip: &T,
        squash_height: u32,
        label: &str,
    ) -> Result<SquashStats, Error>
    where
        T: Send + Sync,
    {
        let dst_path = dst_db_path.to_str().ok_or_else(|| {
            Error::CorruptionError(format!(
                "squash dst path is not valid UTF-8: {}",
                dst_db_path.display()
            ))
        })?;
        let dst_dir = dst_dir.to_str().ok_or_else(|| {
            Error::CorruptionError(format!(
                "squash dst parent dir is not valid UTF-8: {}",
                dst_dir.display()
            ))
        })?;

        let overall_start = Instant::now();
        let mut step_durations = SquashStepDurations::default();

        let src_storage = TrieFileStorage::open_readonly(src_path, src_open_opts)?;
        let mut src = MARF::from_storage(src_storage);

        // Re-squashing at or below the source boundary would rely on history already pruned.
        let src_squash_height =
            trie_sql::read_squash_info(src.sqlite_conn())?.map(|info| info.squash_height);
        if let Some(sh) = src_squash_height {
            if squash_height <= sh {
                return Err(Error::CorruptionError(format!(
                    "Cannot re-squash at squash_height {squash_height}: source is already squashed \
                     at squash_height {sh}; the new squash_height must be strictly greater"
                )));
            }
        }

        let block_at_height = src
            .get_block_at_height(squash_height, tip)?
            .ok_or(Error::NotFoundError)?;

        // Destination requires `external_blobs = true` and `compress = false`;
        // the rest is unused because we bypass the normal MARF write path.
        let dst_open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
        let mut dst = MARF::from_path(dst_path, dst_open_opts)?;
        apply_offline_squash_pragmas(dst.sqlite_conn())?;

        // [1/8] Load block entries
        let start = Instant::now();
        let mut block_entries = collect_block_entries(&mut src)?;
        step_durations.load_block_map = start.elapsed();
        info!(
            "[{label}] [1/8] Load block entries: {} rows in {}",
            block_entries.len(),
            fmt_duration(step_durations.load_block_map)
        );

        // [2/8] Build squash_height index
        info!(
            "[{label}] [2/8] Build squash_height index: reading {} heights...",
            squash_height + 1
        );
        let start = Instant::now();
        let block_info = src.with_conn(|conn| {
            verify_blob_root_matches_marf(conn, &block_at_height)?;
            collect_per_height_metadata(
                conn,
                &block_at_height,
                &mut block_entries,
                src_squash_height,
                squash_height,
                label,
            )
        })?;
        step_durations.build_height_index = start.elapsed();

        // [3/8] Collect trie nodes (DFS walk)
        info!("[{label}] [3/8] Collect trie nodes: starting DFS...");
        let start = Instant::now();
        let (mut node_store, source_to_idx) =
            src.with_conn(|conn| MARF::collect_reachable_nodes(conn, &block_at_height, dst_dir))?;
        let node_count = node_store.len() as u64;
        step_durations.collect_trie_nodes = start.elapsed();
        info!(
            "[{label}] [3/8] Collect trie nodes: {node_count} nodes in {}",
            fmt_duration(step_durations.collect_trie_nodes)
        );

        let mut tx = dst.begin_tx()?;
        tx.begin(&T::sentinel(), &block_at_height)?;

        // [4/8] Register placeholder blocks and build the archival -> squashed id map.
        let start = Instant::now();
        let (archival_to_squashed, squashed_tip_placeholder_id, historical_placeholder_count) =
            insert_placeholder_blocks(
                tx.sqlite_tx(),
                &block_info,
                &block_at_height,
                block_entries,
                label,
            )?;
        step_durations.register_placeholders = start.elapsed();

        // [5/8] Remap trie pointers (disk-backed)
        info!("[{label}] [5/8] Remap trie pointers: {node_count} nodes...");
        let start = Instant::now();
        remap_child_ptrs(
            &mut node_store,
            &source_to_idx,
            &archival_to_squashed,
            label,
        )?;
        step_durations.remap_pointers = start.elapsed();
        info!(
            "[{label}] [5/8] Remap trie pointers: {node_count} nodes in {}",
            fmt_duration(step_durations.remap_pointers)
        );
        drop(source_to_idx);
        drop(archival_to_squashed);
        node_store.drop_block_ids(); // release per-node origin ids

        // [6/8] Recompute node hashes (disk-backed)
        info!("[{label}] [6/8] Recompute node hashes: {node_count} nodes...");
        let start = Instant::now();
        recompute_content_hashes(&mut node_store)?;
        step_durations.recompute_hashes = start.elapsed();
        info!(
            "[{label}] [6/8] Recompute node hashes: {node_count} nodes in {}",
            fmt_duration(step_durations.recompute_hashes)
        );

        let squash_root_node_hash = if node_store.len() > 0 {
            *node_store.get_hash(0)
        } else {
            return Err(Error::CorruptionError(
                "No nodes in squash trie".to_string(),
            ));
        };

        // [7/8] Write trie blob (compute offsets + stream to destination)
        info!("[{label}] [7/8] Write trie blob: {node_count} nodes...");
        let start = Instant::now();
        let parent_hash = T::sentinel();

        // Destination squash MARFs always use external blobs.
        let (block_id, total_blob_size) = tx.storage.with_trie_blobs(|db, blobs| {
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
            let total_blob_size =
                stream_squash_blob(&mut node_store, &parent_hash, &mut buf_writer)?;
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
            .map(|block_id| (block_id, total_blob_size))
        })?;
        step_durations.write_trie_blob = start.elapsed();
        info!(
            "[{label}] [7/8] Write trie blob: block_id={block_id}, {total_blob_size} bytes in {}",
            fmt_duration(step_durations.write_trie_blob)
        );

        drop(node_store); // free temp file + metadata

        // [8/8] Persist metadata, share blob offsets, and commit.
        let step8_start = Instant::now();
        let source_root_hash = block_info
            .iter()
            .find(|b| b.block_hash == block_at_height)
            .map(|b| b.root_hash)
            .ok_or(Error::NotFoundError)?;
        persist_squash_metadata(
            tx.sqlite_tx(),
            &block_info,
            &source_root_hash,
            squash_height,
        )?;
        info!("[{label}] Squash root hash: {squash_root_node_hash}");

        finalize_shared_blob_offsets(tx.sqlite_tx(), &block_at_height, &squash_root_node_hash)?;

        tx.set_squash_info(Some(SquashInfo {
            archival_marf_root_hash: source_root_hash,
            squash_root_node_hash,
            squash_height,
        }));

        // Commit the SQL transaction without flushing TrieRAM (we already wrote the blob directly)
        tx.commit_squash()?;

        // Restore default SQLite pragmas so the squashed output behaves like
        // any other MARF DB for subsequent readers/writers.
        restore_default_squash_pragmas(dst.sqlite_conn())?;

        step_durations.persist_metadata = step8_start.elapsed();
        info!(
            "[{label}] [8/8] Persist metadata & commit: finished in {}",
            fmt_duration(step_durations.persist_metadata)
        );

        let total_duration = overall_start.elapsed();
        info!(
            "[{label}] Squash complete: {node_count} nodes, total time {}",
            fmt_duration(total_duration)
        );

        Ok(SquashStats {
            node_count,
            squash_height,
            dst_db_path: dst_db_path.to_path_buf(),
            dst_blobs_path: dst_blobs_path.to_path_buf(),
            blob_size: total_blob_size,
            historical_placeholder_count,
            source_root_hash,
            squash_root_node_hash,
            step_durations,
            total_duration,
        })
    }

    /// DFS collection pass: gather trie nodes reachable from `block_hash`.
    ///
    /// Nodes are stored on disk; only metadata and the source lookup stay in
    /// memory. The iterative DFS keeps root at index 0 and visits parents
    /// before children, which later remap and hash passes rely on.
    ///
    /// Uses iterative DFS instead of BFS. The DFS stack holds at most
    /// `trie_height` frames (~32), each with one node's child pointer list.
    /// Total stack memory is ~128 KB, compared to the BFS frontier which
    /// could hold millions of entries (~GBs) for wide, hash-distributed tries.
    ///
    /// Nodes are pushed in DFS preorder (parent before children), which is
    /// what all the remap and hash-recompute passes require.
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

        let root_is_leaf = root_node.is_leaf();
        let root_ptrs: Vec<TriePtr> = if root_is_leaf {
            vec![]
        } else {
            root_node.ptrs().to_vec()
        };
        let root_disk_ptr = TrieStorageConnection::<T>::root_ptr_disk();
        let root_idx = store.push(&root_node, root_hash, root_block_id)?;
        source_to_idx.insert((root_block_id, root_disk_ptr), root_idx);

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
                if last_log.elapsed().as_secs() >= LOG_PROGRESS_TIME_INTERVAL_SECS
                    || nodes_collected % LOG_PROGRESS_NODE_INTERVAL == 0
                {
                    info!(
                        "Trie DFS: {nodes_collected} nodes, stack depth {stack_depth}, {} elapsed",
                        fmt_duration(dfs_start.elapsed())
                    );
                    last_log = Instant::now();
                }

                // Internal children descend immediately to preserve DFS preorder.
                if !child_is_leaf {
                    // Async-prefetch each non-empty grandchild's page so the
                    // foreground reads a few iterations later land warm.
                    // Already-collected nodes are skipped: the DFS never
                    // reads them again, so their readahead would be wasted.
                    for ptr in child_ptrs_vec.iter() {
                        if ptr.id() == TrieNodeID::Empty as u8 {
                            continue;
                        }
                        let (target_block_id, target_in_block_ptr) = if is_backptr(ptr.id()) {
                            (ptr.back_block(), ptr.from_backptr().ptr())
                        } else {
                            (child_block_id, ptr.ptr())
                        };
                        if source_to_idx.contains_key(&(target_block_id, target_in_block_ptr)) {
                            continue;
                        }
                        source.prefetch_node(target_block_id, target_in_block_ptr, ptr.id());
                    }
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

        store.flush()?;

        info!(
            "Trie DFS: {} nodes in {}",
            store.len(),
            fmt_duration(dfs_start.elapsed())
        );

        Ok((store, source_to_idx))
    }
}
