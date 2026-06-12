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

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use rusqlite::{params, Connection, OpenFlags};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

use super::common::{
    clone_schemas_from_source, copied_rows, execute_copy_specs, with_indexes_dropped,
    with_offline_write_session, TableCopySpec,
};
use crate::chainstate::nakamoto::staging_blocks::{
    nakamoto_staging_block_columns, nakamoto_staging_blocks_membership_predicate,
    nakamoto_staging_blocks_source_select, nakamoto_staging_copy_db_version,
};
use crate::chainstate::stacks::db::blocks::index_block_hash_to_rel_path;
use crate::chainstate::stacks::index::Error;
use crate::core::EMPTY_MICROBLOCK_PARENT_HASH;
use crate::util_lib::db::sqlite_open;

/// Statistics for confirmed epoch-2 microblock stream copy.
#[derive(Debug, Clone, Default)]
pub struct Epoch2MicroblockCopyStats {
    pub streams_copied: u64,
    pub streams_skipped: u64,
    pub microblock_rows_copied: u64,
    pub microblock_bytes_copied: u64,
}

/// Statistics for epoch-2 block file copy.
#[derive(Debug, Clone, Default)]
pub struct Epoch2BlockFileCopyStats {
    pub files_copied: u64,
    pub total_bytes: u64,
    pub genesis_skipped: u64,
    pub copied_paths: Vec<String>,
}

/// Statistics for nakamoto staging block copy.
#[derive(Debug, Clone, Default)]
pub struct NakamotoBlockCopyStats {
    pub rows_copied: u64,
    pub total_blob_bytes: u64,
}

/// Tables copied from the source Nakamoto staging-blocks DB. The index-side
/// staging tables (`staging_microblocks*`) come from the index DB and are
/// classified in `index.rs`.
pub(super) const NAKAMOTO_STAGING_TABLES: &[&str] = &["nakamoto_staging_blocks", "db_version"];

/// Return the hashes of confirmed microblocks descending from `parent_ibh`.
fn get_confirmed_microblock_hashes(
    conn: &Connection,
    parent_ibh: &StacksBlockId,
    max_seq: u32,
) -> Result<Vec<BlockHeaderHash>, Error> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT microblock_hash \
             FROM src.staging_microblocks \
             WHERE index_block_hash = ?1 \
               AND sequence <= ?2 \
               AND processed = 1 \
               AND orphaned = 0 \
             ORDER BY sequence ASC",
        )
        .map_err(Error::SQLError)?;

    let hashes = stmt
        .query_map(params![parent_ibh, max_seq], |row| {
            row.get::<_, BlockHeaderHash>(0)
        })
        .map_err(Error::SQLError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::SQLError)?;

    Ok(hashes)
}

/// Enumerate canonical child blocks that reference a microblock stream.
/// Returns (selected_hashes, selected_parents, stats).
fn derive_confirmed_microblock_set(
    conn: &Connection,
) -> Result<
    (
        HashSet<BlockHeaderHash>,
        HashSet<StacksBlockId>,
        Epoch2MicroblockCopyStats,
    ),
    Error,
> {
    let mut stmt = conn
        .prepare(
            "SELECT parent_consensus_hash, parent_anchored_block_hash, \
                    parent_microblock_hash, parent_microblock_seq \
             FROM staging_blocks",
        )
        .map_err(Error::SQLError)?;

    let children: Vec<(ConsensusHash, BlockHeaderHash, BlockHeaderHash, u32)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, ConsensusHash>(0)?,
                row.get::<_, BlockHeaderHash>(1)?,
                row.get::<_, BlockHeaderHash>(2)?,
                row.get::<_, u32>(3)?,
            ))
        })
        .map_err(Error::SQLError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::SQLError)?;
    drop(stmt);

    let mut selected_hashes: HashSet<BlockHeaderHash> = HashSet::new();
    let mut selected_parents: HashSet<StacksBlockId> = HashSet::new();
    let mut stats = Epoch2MicroblockCopyStats::default();

    for (parent_ch, parent_bh, parent_mblock_hash, parent_mblock_seq) in &children {
        if *parent_mblock_hash == EMPTY_MICROBLOCK_PARENT_HASH && *parent_mblock_seq == 0 {
            continue;
        }

        let parent_ibh = StacksBlockId::new(parent_ch, parent_bh);
        let hashes = get_confirmed_microblock_hashes(conn, &parent_ibh, *parent_mblock_seq)?;

        if hashes.is_empty() {
            warn!(
                "[microblocks] no confirmed microblocks found for parent {parent_ch}/{parent_bh} \
                 (tip {parent_mblock_hash}, seq {parent_mblock_seq}), skipping stream"
            );
            stats.streams_skipped += 1;
            continue;
        }

        selected_parents.insert(parent_ibh);
        for h in hashes {
            selected_hashes.insert(h);
        }
        stats.streams_copied += 1;
    }

    Ok((selected_hashes, selected_parents, stats))
}

/// Populate temp tables with selected microblock hashes and parent IBHs.
fn populate_microblock_temp_tables(
    conn: &Connection,
    selected_hashes: &HashSet<BlockHeaderHash>,
    selected_parents: &HashSet<StacksBlockId>,
) -> Result<(), Error> {
    conn.execute_batch(
        "CREATE TEMP TABLE selected_microblocks (hash TEXT NOT NULL PRIMARY KEY); \
         CREATE TEMP TABLE selected_parents (ibh TEXT NOT NULL PRIMARY KEY);",
    )
    .map_err(Error::SQLError)?;

    {
        let mut ins_hash = conn
            .prepare("INSERT INTO temp.selected_microblocks (hash) VALUES (?1)")
            .map_err(Error::SQLError)?;
        for h in selected_hashes {
            ins_hash.execute(params![h]).map_err(Error::SQLError)?;
        }
    }
    {
        let mut ins_parent = conn
            .prepare("INSERT INTO temp.selected_parents (ibh) VALUES (?1)")
            .map_err(Error::SQLError)?;
        for p in selected_parents {
            ins_parent.execute(params![p]).map_err(Error::SQLError)?;
        }
    }

    Ok(())
}

/// Copy specs for the confirmed-microblock tables, filtered by the temp
/// tables [`populate_microblock_temp_tables`] builds.
fn microblock_copy_specs() -> Vec<TableCopySpec> {
    vec![
        TableCopySpec {
            table: "staging_microblocks",
            source_sql: "SELECT s.* FROM src.staging_microblocks s \
                 WHERE s.microblock_hash IN (SELECT hash FROM temp.selected_microblocks) \
                   AND s.index_block_hash IN (SELECT ibh FROM temp.selected_parents) \
                   AND s.orphaned = 0"
                .into(),
        },
        TableCopySpec {
            table: "staging_microblocks_data",
            source_sql: "SELECT s.* FROM src.staging_microblocks_data s \
                 WHERE s.block_hash IN (SELECT hash FROM temp.selected_microblocks)"
                .into(),
        },
    ]
}

/// Copy confirmed canonical epoch-2 microblock streams.
pub fn copy_confirmed_epoch2_microblocks(
    src_index_path: &str,
    dst_index_path: &str,
) -> Result<Epoch2MicroblockCopyStats, Error> {
    with_offline_write_session(dst_index_path, &[("src", src_index_path)], "", |conn| {
        let (selected_hashes, selected_parents, mut stats) = derive_confirmed_microblock_set(conn)?;

        if !selected_hashes.is_empty() {
            populate_microblock_temp_tables(conn, &selected_hashes, &selected_parents)?;

            let results = execute_copy_specs(conn, &microblock_copy_specs())?;
            stats.microblock_rows_copied = copied_rows(&results, "staging_microblocks");

            stats.microblock_bytes_copied = conn
                .query_row(
                    "SELECT COALESCE(SUM(LENGTH(block_data)), 0) FROM staging_microblocks_data",
                    [],
                    |row| row.get(0),
                )
                .map_err(Error::SQLError)?;
        }

        Ok(stats)
    })
}

/// Copy canonical epoch 2.x block flat files.
pub fn copy_epoch2_block_files(
    squashed_index_path: &str,
    src_blocks_dir: &str,
    dst_blocks_dir: &str,
) -> Result<Epoch2BlockFileCopyStats, Error> {
    let conn = sqlite_open(squashed_index_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)
        .map_err(Error::SQLError)?;

    let mut stmt = conn
        .prepare(
            "SELECT index_block_hash, block_height \
             FROM block_headers ORDER BY block_height",
        )
        .map_err(Error::SQLError)?;

    let rows: Vec<(StacksBlockId, u64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(Error::SQLError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::SQLError)?;
    drop(stmt);

    let mut stats = Epoch2BlockFileCopyStats::default();

    for (index_block_hash, block_height) in &rows {
        if *block_height == 0 {
            stats.genesis_skipped += 1;
            continue;
        }

        let rel_path = index_block_hash_to_rel_path(index_block_hash);
        let src_path = Path::new(src_blocks_dir).join(&rel_path);
        let dst_path = Path::new(dst_blocks_dir).join(&rel_path);

        if !src_path.exists() {
            return Err(Error::CorruptionError(format!(
                "Missing source epoch-2 block file for height {block_height} hash {index_block_hash}: {}. \
                 A complete source archive is required to preserve block serving.",
                src_path.display()
            )));
        }

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::CorruptionError(format!(
                    "Failed to create directory {}: {e:?}",
                    parent.display(),
                ))
            })?;
        }

        let bytes_copied = fs::copy(&src_path, &dst_path).map_err(|e| {
            Error::CorruptionError(format!(
                "Failed to copy block file {} -> {}: {e:?}",
                src_path.display(),
                dst_path.display(),
            ))
        })?;

        stats.files_copied += 1;
        stats.total_bytes += bytes_copied;
        stats
            .copied_paths
            .push(rel_path.to_string_lossy().into_owned());

        if stats.files_copied % 1000 == 0 {
            info!(
                "[blocks] copied {} epoch 2.x block files ({} bytes)...",
                stats.files_copied, stats.total_bytes
            );
        }
    }

    Ok(stats)
}

/// Create and populate `nakamoto.sqlite` with canonical `nakamoto_staging_blocks` rows.
///
/// The retained set is bounded entirely by `squashed_index_path`: a non-orphan row is kept
/// iff its `index_block_hash` is in that index's `nakamoto_block_headers`. This function has no
/// independent notion of the squash boundary H, so the index must already be scoped to H
/// -- passing a full or stale index would copy post-boundary rows into the artifact.
pub fn copy_nakamoto_staging_blocks(
    src_nakamoto_path: &str,
    dst_nakamoto_path: &str,
    squashed_index_path: &str,
) -> Result<NakamotoBlockCopyStats, Error> {
    with_offline_write_session(
        dst_nakamoto_path,
        &[("src", src_nakamoto_path), ("idx", squashed_index_path)],
        "",
        |conn| {
            clone_schemas_from_source(conn, NAKAMOTO_STAGING_TABLES)?;

            nakamoto_staging_copy_db_version(conn)
                .map_err(|e| Error::CorruptionError(format!("cannot copy db_version: {e}")))?;

            let membership = nakamoto_staging_blocks_membership_predicate("s");

            // The membership filter also drops orphans: an in-index block should
            // never be orphaned, but `set_block_orphaned` cascades via
            // parent_block_id, so the filter keeps non-canonical rows out.
            with_indexes_dropped(conn, "nakamoto_staging_blocks", |conn| {
                conn.execute(
                    &format!(
                        "INSERT INTO nakamoto_staging_blocks ({}) \
                         {} \
                         WHERE {membership}",
                        nakamoto_staging_block_columns(),
                        nakamoto_staging_blocks_source_select("s")
                    ),
                    [],
                )
                .map_err(Error::SQLError)?;
                Ok(())
            })?;

            let stats: NakamotoBlockCopyStats = conn
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM nakamoto_staging_blocks",
                    [],
                    |row| {
                        Ok(NakamotoBlockCopyStats {
                            rows_copied: row.get::<_, i64>(0)? as u64,
                            total_blob_bytes: row.get::<_, i64>(1)? as u64,
                        })
                    },
                )
                .map_err(Error::SQLError)?;
            Ok(stats)
        },
    )
}
