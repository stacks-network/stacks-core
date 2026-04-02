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
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};

use super::common::{clone_schemas_from_source, full_row_except_match};
use crate::chainstate::stacks::db::blocks::index_block_hash_to_rel_path;
use crate::chainstate::stacks::index::Error;
use crate::core::EMPTY_MICROBLOCK_PARENT_HASH;

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

/// Validation result for confirmed microblock streams in the squashed index DB.
#[derive(Debug, Clone)]
pub struct MicroblockValidation {
    pub staging_microblocks_match: bool,
    pub staging_microblocks_data_match: bool,
    pub staging_microblocks_no_extra_rows: bool,
}

impl MicroblockValidation {
    pub fn is_valid(&self) -> bool {
        self.staging_microblocks_match
            && self.staging_microblocks_data_match
            && self.staging_microblocks_no_extra_rows
    }
}

/// Validation result for nakamoto staging blocks.
#[derive(Debug, Clone)]
pub struct NakamotoBlockValidation {
    pub metadata_match: bool,
    pub no_extra_blocks: bool,
    pub blob_bytes_match: bool,
    pub db_version_match: bool,
    pub schema_match: bool,
}

impl NakamotoBlockValidation {
    pub fn is_valid(&self) -> bool {
        self.metadata_match
            && self.no_extra_blocks
            && self.blob_bytes_match
            && self.db_version_match
            && self.schema_match
    }
}

/// Validation result for epoch 2.x block files.
#[derive(Debug, Clone)]
pub struct Epoch2BlockFileValidation {
    pub all_files_present: bool,
    pub no_extra_files: bool,
    pub all_bytes_match: bool,
}

impl Epoch2BlockFileValidation {
    pub fn is_valid(&self) -> bool {
        self.all_files_present && self.no_extra_files && self.all_bytes_match
    }
}

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
                "No confirmed microblocks found for parent {parent_ch}/{parent_bh} (tip {parent_mblock_hash}, seq {parent_mblock_seq}), skipping stream"
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
    hash_table: &str,
    parent_table: &str,
) -> Result<(), Error> {
    conn.execute_batch(&format!(
        "CREATE TEMP TABLE {hash_table} (hash TEXT NOT NULL PRIMARY KEY); \
         CREATE TEMP TABLE {parent_table} (ibh TEXT NOT NULL PRIMARY KEY);"
    ))
    .map_err(Error::SQLError)?;

    {
        let mut ins_hash = conn
            .prepare(&format!("INSERT INTO temp.{hash_table} (hash) VALUES (?1)"))
            .map_err(Error::SQLError)?;
        for h in selected_hashes {
            ins_hash.execute(params![h]).map_err(Error::SQLError)?;
        }
    }
    {
        let mut ins_parent = conn
            .prepare(&format!(
                "INSERT INTO temp.{parent_table} (ibh) VALUES (?1)"
            ))
            .map_err(Error::SQLError)?;
        for p in selected_parents {
            ins_parent.execute(params![p]).map_err(Error::SQLError)?;
        }
    }

    Ok(())
}

/// Copy confirmed canonical epoch-2 microblock streams.
pub fn copy_confirmed_epoch2_microblocks(
    src_index_path: &str,
    dst_index_path: &str,
) -> Result<Epoch2MicroblockCopyStats, Error> {
    let conn = Connection::open_with_flags(
        dst_index_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS src", params![src_index_path])
        .map_err(Error::SQLError)?;

    let (selected_hashes, selected_parents, mut stats) = derive_confirmed_microblock_set(&conn)?;

    if !selected_hashes.is_empty() {
        populate_microblock_temp_tables(
            &conn,
            &selected_hashes,
            &selected_parents,
            "selected_microblocks",
            "selected_parents",
        )?;

        stats.microblock_rows_copied = conn
            .execute(
                "INSERT INTO staging_microblocks \
                 SELECT s.* FROM src.staging_microblocks s \
                 WHERE s.microblock_hash IN (SELECT hash FROM temp.selected_microblocks) \
                   AND s.index_block_hash IN (SELECT ibh FROM temp.selected_parents) \
                   AND s.orphaned = 0",
                [],
            )
            .map_err(Error::SQLError)? as u64;

        conn.execute(
            "INSERT INTO staging_microblocks_data \
             SELECT s.* FROM src.staging_microblocks_data s \
             WHERE s.block_hash IN (SELECT hash FROM temp.selected_microblocks)",
            [],
        )
        .map_err(Error::SQLError)?;

        stats.microblock_bytes_copied = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(block_data)), 0) FROM staging_microblocks_data",
                [],
                |row| row.get(0),
            )
            .map_err(Error::SQLError)?;

        conn.execute_batch(
            "DROP TABLE IF EXISTS temp.selected_microblocks; \
             DROP TABLE IF EXISTS temp.selected_parents;",
        )
        .map_err(Error::SQLError)?;
    }

    conn.execute_batch("DETACH DATABASE src")
        .map_err(Error::SQLError)?;

    Ok(stats)
}

/// Copy canonical epoch 2.x block flat files.
pub fn copy_epoch2_block_files(
    squashed_index_path: &str,
    src_blocks_dir: &str,
    dst_blocks_dir: &str,
) -> Result<Epoch2BlockFileCopyStats, Error> {
    let conn = Connection::open_with_flags(
        squashed_index_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
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
                "Copied {} epoch 2.x block files ({} bytes)...",
                stats.files_copied, stats.total_bytes
            );
        }
    }

    Ok(stats)
}

/// Create and populate `nakamoto.sqlite` with canonical `nakamoto_staging_blocks` rows.
pub fn copy_nakamoto_staging_blocks(
    src_nakamoto_path: &str,
    dst_nakamoto_path: &str,
    squashed_index_path: &str,
) -> Result<NakamotoBlockCopyStats, Error> {
    let conn = Connection::open_with_flags(
        dst_nakamoto_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS src", params![src_nakamoto_path])
        .map_err(Error::SQLError)?;

    clone_schemas_from_source(&conn, &["nakamoto_staging_blocks", "db_version"])?;

    conn.execute("INSERT INTO db_version SELECT * FROM src.db_version", [])
        .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS idx", params![squashed_index_path])
        .map_err(Error::SQLError)?;

    conn.execute(
        "INSERT INTO nakamoto_staging_blocks \
         SELECT s.* FROM src.nakamoto_staging_blocks s \
         INNER JOIN idx.nakamoto_block_headers nh \
           ON s.index_block_hash = nh.index_block_hash",
        [],
    )
    .map_err(Error::SQLError)?;

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

    conn.execute_batch("DETACH DATABASE idx; DETACH DATABASE src")
        .map_err(Error::SQLError)?;

    Ok(stats)
}

/// Validate confirmed microblock streams.
pub fn validate_microblock_streams(
    src_index_path: &str,
    dst_index_path: &str,
) -> Result<MicroblockValidation, Error> {
    let conn = Connection::open_with_flags(
        dst_index_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS src", params![src_index_path])
        .map_err(Error::SQLError)?;

    let (selected_hashes, selected_parents, _stats) = derive_confirmed_microblock_set(&conn)?;

    populate_microblock_temp_tables(
        &conn,
        &selected_hashes,
        &selected_parents,
        "val_selected_mblocks",
        "val_selected_parents",
    )?;

    let staging_microblocks_match = full_row_except_match(
        &conn,
        "SELECT * FROM staging_microblocks",
        "SELECT s.* FROM src.staging_microblocks s \
         WHERE s.microblock_hash IN (SELECT hash FROM temp.val_selected_mblocks) \
           AND s.index_block_hash IN (SELECT ibh FROM temp.val_selected_parents) \
           AND s.orphaned = 0",
    );

    let staging_microblocks_data_match = full_row_except_match(
        &conn,
        "SELECT block_hash, block_data FROM staging_microblocks_data",
        "SELECT s.block_hash, s.block_data FROM src.staging_microblocks_data s \
         WHERE s.block_hash IN (SELECT hash FROM temp.val_selected_mblocks)",
    );

    let staging_microblocks_no_extra_rows = conn
        .query_row(
            "SELECT COUNT(*) FROM staging_microblocks \
             WHERE microblock_hash NOT IN (SELECT hash FROM temp.val_selected_mblocks)",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1)
        == 0
        && conn
            .query_row(
                "SELECT COUNT(*) FROM staging_microblocks_data \
                 WHERE block_hash NOT IN (SELECT hash FROM temp.val_selected_mblocks)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(1)
            == 0;

    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.val_selected_mblocks; \
         DROP TABLE IF EXISTS temp.val_selected_parents;",
    )
    .map_err(Error::SQLError)?;

    conn.execute_batch("DETACH DATABASE src")
        .map_err(Error::SQLError)?;

    Ok(MicroblockValidation {
        staging_microblocks_match,
        staging_microblocks_data_match,
        staging_microblocks_no_extra_rows,
    })
}

/// Validate nakamoto staging blocks.
pub fn validate_nakamoto_staging_blocks(
    src_nakamoto_path: &str,
    dst_nakamoto_path: &str,
    squashed_index_path: &str,
) -> Result<NakamotoBlockValidation, Error> {
    let conn = Connection::open_with_flags(
        dst_nakamoto_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS src", params![src_nakamoto_path])
        .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS idx", params![squashed_index_path])
        .map_err(Error::SQLError)?;

    let metadata_columns = "block_hash, consensus_hash, parent_block_id, is_tenure_start, \
                            burn_attachable, processed, orphaned, height, index_block_hash, \
                            processed_time, obtain_method, signing_weight";

    let metadata_match = full_row_except_match(
        &conn,
        &format!("SELECT {metadata_columns} FROM nakamoto_staging_blocks"),
        &format!(
            "SELECT {metadata_columns} FROM src.nakamoto_staging_blocks \
             WHERE index_block_hash IN (SELECT index_block_hash FROM idx.nakamoto_block_headers)"
        ),
    );

    let no_extra_blocks = conn
        .query_row(
            "SELECT COUNT(*) FROM nakamoto_staging_blocks \
             WHERE index_block_hash NOT IN \
               (SELECT index_block_hash FROM idx.nakamoto_block_headers)",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1)
        == 0;

    let blob_bytes_match = conn
        .query_row(
            "SELECT COUNT(*) FROM nakamoto_staging_blocks n \
             INNER JOIN src.nakamoto_staging_blocks s \
               ON n.index_block_hash = s.index_block_hash \
             WHERE n.data != s.data",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1)
        == 0;

    let db_version_match = full_row_except_match(
        &conn,
        "SELECT * FROM db_version",
        "SELECT * FROM src.db_version",
    );

    let schema_match = full_row_except_match(
        &conn,
        "SELECT type, name, tbl_name, \
                REPLACE(REPLACE(sql, 'IF NOT EXISTS ', ''), 'IF NOT EXISTS', '') \
         FROM sqlite_master \
         WHERE type IN ('table', 'index') AND sql IS NOT NULL",
        "SELECT type, name, tbl_name, \
                REPLACE(REPLACE(sql, 'IF NOT EXISTS ', ''), 'IF NOT EXISTS', '') \
         FROM src.sqlite_master \
         WHERE type IN ('table', 'index') AND sql IS NOT NULL",
    );

    conn.execute_batch("DETACH DATABASE idx; DETACH DATABASE src")
        .map_err(Error::SQLError)?;

    Ok(NakamotoBlockValidation {
        metadata_match,
        no_extra_blocks,
        blob_bytes_match,
        db_version_match,
        schema_match,
    })
}

/// Validate epoch 2.x block files.
pub fn validate_epoch2_block_files(
    squashed_index_path: &str,
    src_blocks_dir: &str,
    dst_blocks_dir: &str,
) -> Result<Epoch2BlockFileValidation, Error> {
    let conn = Connection::open_with_flags(
        squashed_index_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::SQLError)?;

    let mut stmt = conn
        .prepare("SELECT index_block_hash, block_height FROM block_headers ORDER BY block_height")
        .map_err(Error::SQLError)?;

    let rows: Vec<(StacksBlockId, u64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(Error::SQLError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::SQLError)?;
    drop(stmt);

    let mut expected_files: HashSet<PathBuf> = HashSet::new();
    let mut all_files_present = true;
    let mut all_bytes_match = true;

    for (index_block_hash, block_height) in &rows {
        if *block_height == 0 {
            continue;
        }

        let rel_path = index_block_hash_to_rel_path(index_block_hash);
        let src_path = Path::new(src_blocks_dir).join(&rel_path);
        let dst_path = Path::new(dst_blocks_dir).join(&rel_path);

        if !src_path.exists() {
            return Err(Error::CorruptionError(format!(
                "Missing source epoch-2 block file for height {block_height} hash {index_block_hash}: {}. \
                 Validation requires a complete source archive.",
                src_path.display()
            )));
        }

        expected_files.insert(rel_path);

        if !dst_path.exists() {
            all_files_present = false;
            continue;
        }

        let src_bytes = fs::read(&src_path).map_err(|e| {
            Error::CorruptionError(format!("Failed to read {}: {e:?}", src_path.display()))
        })?;
        let dst_bytes = fs::read(&dst_path).map_err(|e| {
            Error::CorruptionError(format!("Failed to read {}: {e:?}", dst_path.display()))
        })?;
        if src_bytes != dst_bytes {
            all_bytes_match = false;
        }
    }

    // Walk destination directory to find extra files.
    let mut no_extra_files = true;
    let dst_root = Path::new(dst_blocks_dir);
    if dst_root.exists() {
        let mut dirs_to_visit = vec![dst_root.to_path_buf()];
        while let Some(dir) = dirs_to_visit.pop() {
            let entries = fs::read_dir(&dir).map_err(|e| {
                Error::CorruptionError(format!("Failed to read dir {}: {e:?}", dir.display()))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    Error::CorruptionError(format!("Failed to read dir entry: {e:?}"))
                })?;
                let ft = entry.file_type().map_err(|e| {
                    Error::CorruptionError(format!("Failed to get file type: {e:?}"))
                })?;
                if ft.is_dir() {
                    dirs_to_visit.push(entry.path());
                } else if ft.is_file() {
                    let rel = entry
                        .path()
                        .strip_prefix(dst_root)
                        .unwrap_or(&entry.path())
                        .to_path_buf();
                    let fname = entry.file_name();
                    if fname == "nakamoto.sqlite"
                        || fname == "nakamoto.sqlite-journal"
                        || fname == "nakamoto.sqlite-wal"
                        || fname == "nakamoto.sqlite-shm"
                    {
                        continue;
                    }
                    if !expected_files.contains(&rel) {
                        no_extra_files = false;
                        break;
                    }
                }
            }
            if !no_extra_files {
                break;
            }
        }
    }

    Ok(Epoch2BlockFileValidation {
        all_files_present,
        no_extra_files,
        all_bytes_match,
    })
}
