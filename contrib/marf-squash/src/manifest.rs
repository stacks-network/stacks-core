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

//! `PCS_manifest.toml` - its schema and writer. The manifest is the
//! self-describing record of a Pruned Chainstate Snapshot: the three MARFs' squash
//! root node hashes and archival root hashes, the block range, and SHA-256
//! checksums (file-level for the fixed artifacts, one aggregate hash for the
//! epoch-2 block archive).
//!
//! `squash` writes this for a full PCS (`--all`); nothing in this crate reads it
//! back. It is the artifact format consumed by an external/offline verifier (a
//! separate tool). The manifest is part of the untrusted artifact and is not
//! itself authenticated.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use stacks_common::types::chainstate::{SortitionId, StacksBlockId};
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts, MarfConnection};
use stackslib::chainstate::stacks::index::{MarfTrieId, trie_sql};
use stackslib::util_lib::db::sqlite_open;

use crate::checksums::{compute_aggregate_checksum, compute_checksums};
use crate::db::{
    DbConfig, derive_expected_epoch2_block_rel_paths, read_db_config_from_conn, read_marf_open_opts,
};
use crate::layout::{
    BURNCHAIN_DB_REL, HEADERS_DB_REL, NAKAMOTO_DB_REL, PCS_MANIFEST, TargetPaths,
    canonical_rel_path,
};

#[derive(Serialize, Deserialize)]
pub struct SquashManifest {
    pub snapshot: SnapshotSection,
    pub roots: RootsSection,
    pub squash_roots: SquashRootsSection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<BlocksSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksums: Option<ChecksumsSection>,
}

#[derive(Serialize, Deserialize)]
pub struct SnapshotSection {
    pub version: u32,
    pub stacks_height: u32,
    pub bitcoin_height: u32,
    pub block_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub chain_id: u32,
    pub mainnet: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RootsSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clarity_archival_marf_root_hash: Option<String>,
    pub index_archival_marf_root_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sortition_archival_marf_root_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SquashRootsSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clarity_squash_root_node_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_squash_root_node_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sortition_squash_root_node_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct BlocksSection {
    pub epoch2x_files: u64,
    pub epoch2x_bytes: u64,
    pub epoch2x_microblock_rows: u64,
    pub epoch2x_microblock_bytes: u64,
    pub nakamoto_rows: u64,
    pub nakamoto_bytes: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ChecksumsSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch2_block_archive_hash: Option<String>,
    pub files: BTreeMap<String, String>,
}

/// The inputs needed to write a PCS manifest: the three squashed MARF output
/// paths, the resolved squash boundary (heights + the anchor tips the squash was
/// resolved against), and the block-copy stats. Threaded through the manifest
/// builders so each reads only the fields it needs.
pub struct ManifestInputs<'a> {
    pub out_dir: &'a Path,
    pub clarity_out: &'a TargetPaths,
    pub index_out: &'a TargetPaths,
    pub sortition_paths: &'a TargetPaths,
    pub stacks_height: u32,
    pub bitcoin_height: u32,
    pub sortition_marf_height: u32,
    pub expected_stacks_tip: &'a StacksBlockId,
    pub expected_sortition_tip: &'a SortitionId,
    pub blocks_section: BlocksSection,
}

/// Squash metadata read from a just-squashed MARF DB.
pub struct ReadSquashMetadata<T: MarfTrieId> {
    pub tip: T,
    pub archival_root_hash: String,
    pub squash_root_node_hash: String,
    pub squash_height: u32,
}

/// Read squash metadata from a just-squashed MARF DB.
pub fn read_squash_metadata<T: MarfTrieId + std::fmt::Display>(
    db_path: &str,
    open_opts: MARFOpenOpts,
) -> ReadSquashMetadata<T> {
    let marf = MARF::<T>::from_path(db_path, open_opts).unwrap_or_else(|e| {
        eprintln!("Failed to open squashed MARF for manifest: {e:?}");
        std::process::exit(1);
    });
    let tip = trie_sql::get_latest_confirmed_block_hash(marf.sqlite_conn()).unwrap_or_else(|e| {
        eprintln!("Failed to read latest block hash: {e:?}");
        std::process::exit(1);
    });
    let info = trie_sql::read_squash_info(marf.sqlite_conn())
        .unwrap_or_else(|e| {
            eprintln!("Failed to read squash info: {e:?}");
            std::process::exit(1);
        })
        .unwrap_or_else(|| {
            eprintln!("No squash info found in DB");
            std::process::exit(1);
        });
    ReadSquashMetadata {
        tip,
        archival_root_hash: format!("0x{}", info.archival_marf_root_hash),
        squash_root_node_hash: format!("0x{}", info.squash_root_node_hash),
        squash_height: info.squash_height,
    }
}

/// Insert the relative path of `abs_path` (relative to `base`) into `set`.
fn insert_expected_rel(base: &Path, abs_path: &Path, set: &mut HashSet<String>) {
    if let Ok(rel) = abs_path.strip_prefix(base) {
        set.insert(canonical_rel_path(rel));
    }
}

/// Assert that a squashed DB stores the squash height the caller expected.
/// Exits on mismatch.
fn assert_squash_height(label: &str, actual: u32, expected: u32) {
    if actual != expected {
        eprintln!("Manifest error: {label} squash MARF height {actual} != expected {expected}");
        std::process::exit(1);
    }
}

/// Read the squashed sortition ID stored at `sortition_marf_height` in the
/// squashed sortition DB's `marf_squashed_blocks` table. Exits on failure.
fn read_sortition_id_at_height(conn: &rusqlite::Connection, sortition_marf_height: u32) -> String {
    conn.query_row(
        "SELECT lower(hex(block_hash)) FROM marf_squashed_blocks WHERE height = ?1",
        [sortition_marf_height],
        |row| row.get(0),
    )
    .unwrap_or_else(|e| {
        eprintln!(
            "Failed to read sortition ID at sortition MARF height {sortition_marf_height} from squashed sortition DB: {e}"
        );
        std::process::exit(1);
    })
}

/// Convert a Unix timestamp to ISO-8601 UTC without an external crate.
fn format_timestamp(unix_ts: i64) -> String {
    const SECS_PER_DAY: i64 = 86400;
    const SECS_PER_HOUR: i64 = 3600;
    const SECS_PER_MIN: i64 = 60;

    let days = unix_ts / SECS_PER_DAY;
    let rem = unix_ts % SECS_PER_DAY;
    let hour = rem / SECS_PER_HOUR;
    let min = (rem % SECS_PER_HOUR) / SECS_PER_MIN;
    let sec = rem % SECS_PER_MIN;

    // Civil date from days since 1970-01-01 (algorithm from Howard Hinnant).
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Read the burn_header_timestamp for the snapshot at the squash height
/// from the squashed sortition DB. Exits on failure.
pub fn read_snapshot_timestamp(conn: &rusqlite::Connection, sortition_marf_height: u32) -> String {
    let sort_id = read_sortition_id_at_height(conn, sortition_marf_height);
    let ts: i64 = conn
        .query_row(
            "SELECT burn_header_timestamp FROM snapshots WHERE sortition_id = ?1",
            [&sort_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to read burn_header_timestamp for sortition_id {sort_id}: {e}");
            std::process::exit(1);
        });
    format_timestamp(ts)
}

/// Assert that a squashed MARF's tip is the anchor the squash was resolved
/// against, catching a cross-wired anchor. Exits on mismatch.
fn assert_squash_tip<T: MarfTrieId + std::fmt::Display>(label: &str, actual: &T, expected: &T) {
    if actual != expected {
        eprintln!(
            "Manifest error: {label} squash MARF tip {actual} != expected anchor tip {expected}"
        );
        std::process::exit(1);
    }
}

/// Read squash metadata for the three MARFs, asserting their squash heights, that
/// Clarity and Index squashed the same tip, and that the squashed Index/Clarity
/// and sortition tips equal the resolved anchor tips (`expected_stacks_tip`,
/// `expected_sortition_tip`). Returns `(clarity, index, sortition)`. Exits on any
/// mismatch.
#[allow(clippy::type_complexity)]
fn read_all_marf_metadata(
    inputs: &ManifestInputs,
) -> (
    ReadSquashMetadata<StacksBlockId>,
    ReadSquashMetadata<StacksBlockId>,
    ReadSquashMetadata<SortitionId>,
) {
    let index_meta = read_squash_metadata::<StacksBlockId>(
        inputs.index_out.db.to_str().unwrap(),
        read_marf_open_opts(&inputs.index_out.db),
    );
    assert_squash_height("Index", index_meta.squash_height, inputs.stacks_height);
    assert_squash_tip("Index", &index_meta.tip, inputs.expected_stacks_tip);

    let clarity_meta = read_squash_metadata::<StacksBlockId>(
        inputs.clarity_out.db.to_str().unwrap(),
        read_marf_open_opts(&inputs.clarity_out.db),
    );
    assert_squash_height("Clarity", clarity_meta.squash_height, inputs.stacks_height);
    if clarity_meta.tip != index_meta.tip {
        eprintln!(
            "Manifest error: Clarity tip {} != Index tip {}",
            clarity_meta.tip, index_meta.tip
        );
        std::process::exit(1);
    }

    let sortition_meta = read_squash_metadata::<SortitionId>(
        inputs.sortition_paths.db.to_str().unwrap(),
        read_marf_open_opts(&inputs.sortition_paths.db),
    );
    assert_squash_height(
        "Sortition",
        sortition_meta.squash_height,
        inputs.sortition_marf_height,
    );
    assert_squash_tip(
        "Sortition",
        &sortition_meta.tip,
        inputs.expected_sortition_tip,
    );

    (clarity_meta, index_meta, sortition_meta)
}

/// Read the boundary sortition's burn header hash, asserting it sits at
/// `bitcoin_height` (a mismatch means the snapshot's `bitcoin_height` disagrees
/// with the sortition MARF it squashed). Exits on mismatch.
fn read_bitcoin_block_hash(
    sortition_conn: &rusqlite::Connection,
    sortition_marf_height: u32,
    bitcoin_height: u32,
) -> String {
    let sort_id = read_sortition_id_at_height(sortition_conn, sortition_marf_height);
    let (btc_hash, snapshot_burn_height): (String, i64) = sortition_conn
        .query_row(
            "SELECT burn_header_hash, block_height FROM snapshots WHERE sortition_id = ?1",
            [&sort_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to read snapshot for sortition_id {sort_id}: {e}");
            std::process::exit(1);
        });
    if snapshot_burn_height != i64::from(bitcoin_height) {
        eprintln!(
            "Manifest error: boundary sortition Bitcoin height {snapshot_burn_height} != manifest bitcoin_height {bitcoin_height}"
        );
        std::process::exit(1);
    }
    format!("0x{btc_hash}")
}

/// Assemble the manifest's `[snapshot]` section, reading `db_config`, the
/// snapshot timestamp, and the boundary Bitcoin block hash from the squashed DBs.
fn build_snapshot_section(
    inputs: &ManifestInputs,
    index_conn: &rusqlite::Connection,
    sortition_conn: &rusqlite::Connection,
    index_tip: &StacksBlockId,
) -> SnapshotSection {
    let DbConfig { mainnet, chain_id } = read_db_config_from_conn(index_conn);
    let timestamp = Some(read_snapshot_timestamp(
        sortition_conn,
        inputs.sortition_marf_height,
    ));
    let bitcoin_block_hash = read_bitcoin_block_hash(
        sortition_conn,
        inputs.sortition_marf_height,
        inputs.bitcoin_height,
    );
    SnapshotSection {
        version: 1,
        stacks_height: inputs.stacks_height,
        bitcoin_height: inputs.bitcoin_height,
        block_hash: format!("0x{index_tip}"),
        bitcoin_block_hash: Some(bitcoin_block_hash),
        timestamp,
        chain_id,
        mainnet,
    }
}

/// The set of individually hashed output files (MARF dbs + blobs, bitcoin aux,
/// `nakamoto.sqlite`), so that stale files in a reused out-dir are rejected
/// rather than blessed into the manifest. Epoch-2 block files are covered by a
/// single aggregate hash, not listed here.
fn build_expected_files(
    out_dir: &Path,
    clarity_out: &TargetPaths,
    index_out: &TargetPaths,
    sortition_paths: &TargetPaths,
) -> HashSet<String> {
    let mut expected = HashSet::new();

    // MARF databases + blobs.
    insert_expected_rel(out_dir, &clarity_out.db, &mut expected);
    if let Some(b) = &clarity_out.blobs {
        insert_expected_rel(out_dir, b, &mut expected);
    }
    insert_expected_rel(out_dir, &index_out.db, &mut expected);
    if let Some(b) = &index_out.blobs {
        insert_expected_rel(out_dir, b, &mut expected);
    }
    insert_expected_rel(out_dir, &sortition_paths.db, &mut expected);
    if let Some(b) = &sortition_paths.blobs {
        insert_expected_rel(out_dir, b, &mut expected);
    }

    // Bitcoin auxiliary files + nakamoto.sqlite.
    expected.insert(BURNCHAIN_DB_REL.to_string());
    expected.insert(HEADERS_DB_REL.to_string());
    expected.insert(NAKAMOTO_DB_REL.to_string());
    expected
}

/// Assemble the manifest's `[checksums]` section: per-file SHA-256 over the
/// `expected` set plus one aggregate hash over the epoch-2 block archive. Asserts
/// the index's epoch-2 file count matches the copy's. Exits on any mismatch.
fn build_checksums_section(
    out_dir: &Path,
    index_conn: &rusqlite::Connection,
    expected: &HashSet<String>,
    blocks_section: &BlocksSection,
) -> ChecksumsSection {
    let epoch2_block_rel_paths =
        derive_expected_epoch2_block_rel_paths(index_conn).unwrap_or_else(|e| {
            eprintln!("Failed to derive epoch-2 block files from index.sqlite: {e}");
            std::process::exit(1);
        });
    if epoch2_block_rel_paths.len() as u64 != blocks_section.epoch2x_files {
        eprintln!(
            "Manifest error: index lists {} epoch-2 block files, but the copy reported {}",
            epoch2_block_rel_paths.len(),
            blocks_section.epoch2x_files
        );
        std::process::exit(1);
    }

    let skipped_epoch2: HashSet<String> = epoch2_block_rel_paths.iter().cloned().collect();
    let files =
        compute_checksums(out_dir, Some(expected), Some(&skipped_epoch2)).unwrap_or_else(|e| {
            eprintln!("Failed to compute checksums: {e}");
            std::process::exit(1);
        });
    let epoch2_block_archive_hash = compute_aggregate_checksum(out_dir, &epoch2_block_rel_paths)
        .unwrap_or_else(|e| {
            eprintln!("Failed to compute epoch-2 block archive hash: {e}");
            std::process::exit(1);
        });
    println!(
        "Computed SHA-256 checksums for {} files plus one epoch-2 block archive hash",
        files.len()
    );
    ChecksumsSection {
        files,
        epoch2_block_archive_hash: Some(epoch2_block_archive_hash),
    }
}

/// Serialize `manifest` to TOML and write it to `<out_dir>/PCS_manifest.toml`.
fn write_manifest_file(out_dir: &Path, manifest: &SquashManifest) {
    let toml_str = toml::to_string(manifest).unwrap_or_else(|e| {
        eprintln!("Failed to serialize manifest: {e}");
        std::process::exit(1);
    });
    let manifest_path = out_dir.join(PCS_MANIFEST);
    fs::write(&manifest_path, toml_str).unwrap_or_else(|e| {
        eprintln!(
            "Failed to write manifest to '{}': {e}",
            manifest_path.display()
        );
        std::process::exit(1);
    });
    println!("Manifest written to {}", manifest_path.display());
}

/// Generate the PCS manifest. Only called for a complete PCS (all MARFs +
/// blocks + bitcoin aux).
pub fn generate_manifest(inputs: ManifestInputs) {
    let (clarity_meta, index_meta, sortition_meta) = read_all_marf_metadata(&inputs);

    // One read-only connection per squashed output DB, reused by all the
    // metadata reads below.
    let index_conn = sqlite_open(
        &inputs.index_out.db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        false,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to open squashed index DB: {e}");
        std::process::exit(1);
    });
    let sortition_conn = sqlite_open(
        &inputs.sortition_paths.db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        false,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to open squashed sortition DB: {e}");
        std::process::exit(1);
    });

    let snapshot = build_snapshot_section(&inputs, &index_conn, &sortition_conn, &index_meta.tip);

    let expected = build_expected_files(
        inputs.out_dir,
        inputs.clarity_out,
        inputs.index_out,
        inputs.sortition_paths,
    );
    let checksums = build_checksums_section(
        inputs.out_dir,
        &index_conn,
        &expected,
        &inputs.blocks_section,
    );

    let manifest = SquashManifest {
        snapshot,
        roots: RootsSection {
            clarity_archival_marf_root_hash: Some(clarity_meta.archival_root_hash),
            index_archival_marf_root_hash: index_meta.archival_root_hash,
            sortition_archival_marf_root_hash: Some(sortition_meta.archival_root_hash),
        },
        squash_roots: SquashRootsSection {
            clarity_squash_root_node_hash: Some(clarity_meta.squash_root_node_hash),
            index_squash_root_node_hash: Some(index_meta.squash_root_node_hash),
            sortition_squash_root_node_hash: Some(sortition_meta.squash_root_node_hash),
        },
        blocks: Some(inputs.blocks_section),
        checksums: Some(checksums),
    };

    write_manifest_file(inputs.out_dir, &manifest);
}
