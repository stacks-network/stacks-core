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
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::params;
use stacks_common::types::chainstate::TrieHash;

use crate::chainstate::stacks::index::marf::{
    MARFOpenOpts, MarfConnection as _, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF,
};
use crate::chainstate::stacks::index::node::{clear_backptr, is_backptr, TrieNodeID, TriePtr};
use crate::chainstate::stacks::index::storage::{
    SquashInfo, TrieFileStorage, TrieStorageConnection,
};
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{trie_sql, Error, MarfTrieId};

mod node_store;
mod stream;

pub(crate) use node_store::NodeStore;
#[cfg(test)]
pub(crate) use node_store::{deserialize_node, serialize_node};
pub(crate) use stream::stream_squash_blob;
use stream::{recompute_content_hashes, BlobReader};

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

/// Remap child pointers in a `NodeStore` for the squashed trie layout.
///
/// For each non-leaf node, reads it from the temp file, remaps its child
/// pointers from source (block_id, offset) to sequential indices, and
/// writes the modified node back.
///
/// Each child's `back_block` is set to the squashed equivalent of its origin
/// block via `block_id_map`. The annotation is needed for the squash blob so
/// that COW and hash computation preserve block identity when the squashed
/// MARF is later extended.
fn remap_child_ptrs(
    store: &mut NodeStore,
    source_to_idx: &HashMap<(u32, u64), usize>,
    block_id_map: &HashMap<u32, u32>,
    label: &str,
) -> Result<(), Error> {
    let remap_start = Instant::now();
    let node_count = store.len();
    let mut reader = store.open_reader()?;

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

            ptr.back_block = *block_id_map.get(&child_block_id).ok_or_else(|| {
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

/// Per-height block metadata: `(height, block_hash, root_hash)`.
type BlockInfo<T> = (u32, T, TrieHash);

/// Wall-clock duration of each squash step.
#[derive(Debug, Clone, Default)]
pub struct SquashStepDurations {
    /// [1/8] Build the block_id -> blob offset map from `marf_data`.
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
    /// Squash height (blocks 0..=height are squashed).
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
    tip: &T,
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
            .with_conn(|conn| MARF::<T>::get_by_key(conn, tip, &h_key))?
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
        "INSERT OR REPLACE INTO marf_squashed_blocks (height, block_hash, marf_root_hash) VALUES (?1, ?2, ?3)",
    )?;
    for (h, bh, rh) in block_info {
        stmt.execute(params![
            i64::from(*h),
            bh.as_bytes(),
            rh.as_bytes().to_vec()
        ])?;
    }
    info!(
        "Squash: wrote {} root hashes and block heights in {}",
        block_info.len(),
        fmt_duration(start.elapsed())
    );
    Ok(())
}

/// Persist `squash_root_node_hash` and broadcast the tip blob offset to all
/// placeholder rows.
fn finalize_shared_blob_offsets<T: MarfTrieId>(
    conn: &rusqlite::Connection,
    block_at_height: &T,
    squash_root_node_hash: &TrieHash,
) -> Result<usize, Error> {
    trie_sql::update_squash_root_node_hash(conn, squash_root_node_hash)?;

    let start = Instant::now();
    let bh_id = trie_sql::get_block_identifier(conn, block_at_height)?;
    let (offset, length) = trie_sql::get_external_trie_offset_length(conn, bh_id)?;
    let updated = trie_sql::bulk_update_blob_offsets(conn, offset, length, block_at_height)?;
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
        tip: &T,
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

        let dst_db_path = PathBuf::from(dst_path);
        let dst_blobs_path = PathBuf::from(format!("{dst_path}.blobs"));
        if dst_db_path.exists() {
            return Err(Error::DestinationExists(dst_path.to_string()));
        }
        if dst_blobs_path.exists() {
            return Err(Error::DestinationExists(
                dst_blobs_path.to_string_lossy().into_owned(),
            ));
        }

        // Run the actual squash work. On any failure after this point we may
        // have created `dst_db_path` and/or `dst_blobs_path`, so remove them
        // before propagating the error.
        let result = Self::squash_to_path_inner(
            src_path,
            &dst_db_path,
            &dst_blobs_path,
            open_opts,
            tip,
            height,
            label,
        );

        if result.is_err() {
            let _ = std::fs::remove_file(&dst_db_path);
            let _ = std::fs::remove_file(&dst_blobs_path);
        }
        result
    }

    fn squash_to_path_inner(
        src_path: &str,
        dst_db_path: &Path,
        dst_blobs_path: &Path,
        open_opts: MARFOpenOpts,
        tip: &T,
        height: u32,
        label: &str,
    ) -> Result<SquashStats, Error> {
        let dst_path = dst_db_path.to_str().ok_or_else(|| {
            Error::CorruptionError(format!(
                "squash dst path is not valid UTF-8: {}",
                dst_db_path.display()
            ))
        })?;

        let overall_start = Instant::now();
        let mut step_durations = SquashStepDurations::default();

        // Step 1: bulk SQL block map
        let src_storage = TrieFileStorage::open_readonly(src_path, open_opts.clone())?;
        let mut src = MARF::from_storage(src_storage);

        let block_at_height = src
            .get_block_at_height(height, tip)?
            .ok_or(Error::NotFoundError)?;

        let start = Instant::now();
        let block_map = collect_block_map(&src)?;
        step_durations.load_block_map = start.elapsed();
        info!(
            "[{label}] [1/8] Load block map: {} entries in {}",
            block_map.len(),
            fmt_duration(step_durations.load_block_map)
        );

        // [2/8] Build height index
        info!(
            "[{label}] [2/8] Build height index: reading {} heights...",
            height + 1
        );
        let start = Instant::now();
        let mut blob_reader = BlobReader::new(src_path, open_opts.external_blobs)?;
        let block_info = collect_per_height_metadata(
            &mut src,
            tip,
            &block_map,
            &mut blob_reader,
            height,
            label,
        )?;
        step_durations.build_height_index = start.elapsed();

        // [3/8] Collect trie nodes (DFS walk)
        //
        // Derive the temp directory from dst_path: use the parent directory.
        let tmp_dir = dst_db_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .and_then(|p| p.to_str())
            .unwrap_or(".");
        info!("[{label}] [3/8] Collect trie nodes: starting DFS...");
        let start = Instant::now();
        let (mut node_store, source_to_idx) = src.with_conn(|conn| {
            MARF::<T>::collect_reachable_nodes(conn, &block_at_height, tmp_dir)
        })?;
        let node_count = node_store.len() as u64;
        step_durations.collect_trie_nodes = start.elapsed();
        info!(
            "[{label}] [3/8] Collect trie nodes: {node_count} nodes in {}",
            fmt_duration(step_durations.collect_trie_nodes)
        );

        let mut dst_open_opts = open_opts;
        dst_open_opts.external_blobs = true;

        // Open destination MARF and begin transaction
        let mut dst = MARF::from_path(dst_path, dst_open_opts)?;
        let mut tx = dst.begin_tx()?;
        tx.begin(&T::sentinel(), &block_at_height)?;

        // [4/8] Register placeholder blocks
        let start = Instant::now();
        let mut archival_to_squashed = insert_placeholder_blocks(
            tx.sqlite_tx(),
            &block_info,
            &block_at_height,
            &block_map,
            label,
        )?;
        let historical_placeholder_count = archival_to_squashed.len() as u64;

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
        node_store.drop_block_ids(); // free ~200 MB

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
            node_store.hash(0)
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
            .find(|(_, bh, _)| bh == &block_at_height)
            .map(|(_, _, rh)| *rh)
            .ok_or(Error::NotFoundError)?;
        persist_squash_metadata(tx.sqlite_tx(), &block_info, &source_root_hash, height)?;
        info!("[{label}] Squash root hash: {squash_root_node_hash}");

        finalize_shared_blob_offsets(tx.sqlite_tx(), &block_at_height, &squash_root_node_hash)?;

        tx.set_squash_info(Some(SquashInfo {
            archival_marf_root_hash: source_root_hash,
            squash_root_node_hash,
            height,
        }));

        // Commit the SQL transaction without flushing TrieRAM (we already wrote the blob directly)
        tx.commit_squash()?;

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
            squash_height: height,
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
