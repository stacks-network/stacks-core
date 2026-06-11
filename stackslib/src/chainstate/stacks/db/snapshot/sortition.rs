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

use rusqlite::{params, Connection};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, SortitionId};

use super::common::{
    clone_schemas_from_source, copied_rows, execute_copy_specs, with_offline_write_session,
    TableCopySpec,
};
use super::fork_storage::{collect_canonical_leaf_hashes, copy_canonical_fork_storage};
use crate::chainstate::stacks::index::{trie_sql, Error, MARFValue};
use crate::util_lib::db::u64_to_sql;

/// Required sortition tables always present in production.
pub(super) const REQUIRED_TABLES: &[&str] = &[
    "db_config",
    "snapshots",
    "leader_keys",
    "block_commits",
    "block_commit_parents",
    "snapshot_transition_ops",
    "stacks_chain_tips",
    "stacks_chain_tips_by_burn_view",
    "missed_commits",
    "stack_stx",
    "transfer_stx",
    "delegate_stx",
    "vote_for_aggregate_key",
    "preprocessed_reward_sets",
    "epochs",
];

/// Row-count statistics returned by [`copy_sortition_side_tables`].
#[derive(Debug, Clone)]
pub struct SortitionSideTableStats {
    pub snapshots_rows: u64,
    pub leader_keys_rows: u64,
    pub block_commits_rows: u64,
    pub block_commit_parents_rows: u64,
    pub snapshot_transition_ops_rows: u64,
    pub stacks_chain_tips_rows: u64,
    pub stacks_chain_tips_by_burn_view_rows: u64,
    pub preprocessed_reward_sets_rows: u64,
    pub missed_commits_rows: u64,
    pub stack_stx_rows: u64,
    pub transfer_stx_rows: u64,
    pub delegate_stx_rows: u64,
    pub vote_for_aggregate_key_rows: u64,
    pub epochs_rows: u64,
    pub db_config_rows: u64,
    pub fork_storage_rows: u64,
}

/// Stacks-side boundary used when copying sortition tip memo tables.
///
/// A squash can anchor the sortition MARF at a burn view whose runtime source
/// tip is later than the copied Stacks MARF. In that case, the memoized
/// sortition tip must be rewritten to the copied Stacks anchor so a booting
/// node still processes the intra-tenure descendants (re-fetched from peers)
/// instead of believing they are already processed.
#[derive(Debug, Clone)]
pub struct SortitionTipCopyBoundary {
    pub max_stacks_height: u64,
    pub anchor_consensus_hash: ConsensusHash,
    pub anchor_burn_view_consensus_hash: ConsensusHash,
    pub anchor_block_hash: BlockHeaderHash,
    pub anchor_block_height: u64,
}

/// Fill the (already-created) `canonical_sortitions` temp table from the
/// squashed MARF metadata, read through the MARF-domain accessor
/// [`trie_sql::bulk_read_squashed_blocks`] rather than a raw read of the
/// MARF-owned `marf_squashed_blocks` table. The `SortitionId` binds as its
/// lowercase-hex form, matching the `sortition_id` TEXT in `src.snapshots`.
/// Returns the number of ids inserted.
fn insert_canonical_sortition_ids(conn: &Connection) -> Result<usize, Error> {
    let canonical = trie_sql::bulk_read_squashed_blocks::<SortitionId>(conn)?;
    let mut insert = conn
        .prepare("INSERT INTO canonical_sortitions (sortition_id) VALUES (?1)")
        .map_err(Error::SQLError)?;
    let mut inserted = 0usize;
    for (_, sortition_id, _) in &canonical {
        inserted += insert
            .execute(params![sortition_id])
            .map_err(Error::SQLError)?;
    }
    Ok(inserted)
}

/// Build temp tables for the canonical sortition set and canonical burn hashes.
fn populate_canonical_sortitions(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch("CREATE TEMP TABLE canonical_sortitions (sortition_id TEXT PRIMARY KEY)")
        .map_err(Error::SQLError)?;
    let inserted = insert_canonical_sortition_ids(conn)?;
    if inserted == 0 {
        return Err(Error::CorruptionError(
            "marf_squashed_blocks is empty; post-squash dst must have at least one canonical sortition"
                .into(),
        ));
    }
    // Source-completeness: every canonical sortition must exist in
    // src.snapshots. A canonical sortition_id missing from src is
    // corruption. The squash claimed a sortition that src doesn't have.
    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM canonical_sortitions \
             WHERE sortition_id NOT IN (SELECT sortition_id FROM src.snapshots)",
            [],
            |row| row.get(0),
        )
        .map_err(Error::SQLError)?;
    if orphans > 0 {
        return Err(Error::CorruptionError(format!(
            "{orphans} canonical sortition(s) in marf_squashed_blocks are absent from src.snapshots"
        )));
    }

    conn.execute_batch(
        "CREATE TEMP TABLE canonical_burn_hashes (burn_header_hash TEXT PRIMARY KEY)",
    )
    .map_err(Error::SQLError)?;
    conn.execute(
        "INSERT OR IGNORE INTO canonical_burn_hashes (burn_header_hash) \
         SELECT DISTINCT s.burn_header_hash FROM src.snapshots s \
         INNER JOIN canonical_sortitions cs ON s.sortition_id = cs.sortition_id",
        [],
    )
    .map_err(Error::SQLError)?;

    Ok(())
}

fn validate_tip_boundary(boundary: Option<&SortitionTipCopyBoundary>) -> Result<(), Error> {
    if let Some(boundary) = boundary {
        if boundary.anchor_block_height > boundary.max_stacks_height {
            return Err(Error::CorruptionError(format!(
                "sortition tip rewrite anchor height {} exceeds Stacks boundary {}",
                boundary.anchor_block_height, boundary.max_stacks_height
            )));
        }
        u64_to_sql(boundary.max_stacks_height)?;
        u64_to_sql(boundary.anchor_block_height)?;
    }
    Ok(())
}

/// Build the copy source SQL for a sortition Stacks-tip memo table.
///
/// Handles both `stacks_chain_tips` and (with `include_burn_view`)
/// `stacks_chain_tips_by_burn_view`; the latter carries an extra
/// `burn_view_consensus_hash` column and a correspondingly stricter anchor
/// match. With a `boundary`, rows whose `block_height` exceeds it are rewritten
/// down to the anchor (see [`SortitionTipCopyBoundary`]).
fn stacks_chain_tip_memo_source_sql(
    table: &str,
    sid: &str,
    include_burn_view: bool,
    boundary: Option<&SortitionTipCopyBoundary>,
) -> String {
    let Some(boundary) = boundary else {
        return format!("SELECT * FROM src.{table} WHERE sortition_id IN ({sid})");
    };
    let max_height = boundary.max_stacks_height;
    let anchor_height = boundary.anchor_block_height;
    let anchor_ch = &boundary.anchor_consensus_hash;
    let anchor_bhh = &boundary.anchor_block_hash;
    let anchor_burn_view_ch = &boundary.anchor_burn_view_consensus_hash;
    let burn_view_column = if include_burn_view {
        format!(
            "CASE WHEN block_height > {max_height} THEN '{anchor_burn_view_ch}' \
                  ELSE burn_view_consensus_hash END, "
        )
    } else {
        String::new()
    };
    let anchor_match = if include_burn_view {
        format!(
            "(consensus_hash = '{anchor_ch}' \
              AND burn_view_consensus_hash = '{anchor_burn_view_ch}')"
        )
    } else {
        format!("consensus_hash = '{anchor_ch}'")
    };
    format!(
        "SELECT sortition_id, \
                CASE WHEN block_height > {max_height} THEN '{anchor_ch}' ELSE consensus_hash END, \
                {burn_view_column}\
                CASE WHEN block_height > {max_height} THEN '{anchor_bhh}' ELSE block_hash END, \
                CASE WHEN block_height > {max_height} THEN {anchor_height} ELSE block_height END \
         FROM src.{table} \
         WHERE sortition_id IN ({sid}) \
           AND (block_height <= {max_height} OR {anchor_match})"
    )
}

fn sortition_tip_heights_within_boundary(
    conn: &Connection,
    boundary: Option<&SortitionTipCopyBoundary>,
) -> Result<bool, Error> {
    let Some(boundary) = boundary else {
        return Ok(true);
    };
    let max_height = u64_to_sql(boundary.max_stacks_height)?;
    conn.query_row(
        "SELECT COUNT(*) = 0 FROM ( \
             SELECT block_height FROM stacks_chain_tips WHERE block_height > ?1 \
             UNION ALL \
             SELECT block_height FROM stacks_chain_tips_by_burn_view WHERE block_height > ?1 \
         )",
        params![max_height],
        |row| row.get(0),
    )
    .map_err(Error::SQLError)
}

/// Build the copy specs for sortition side tables.
///
/// Tables are grouped by their filter key:
/// - `sortition_id` filtered
/// - `burn_header_hash` filtered
/// - full-copy
fn sortition_copy_specs(boundary: Option<&SortitionTipCopyBoundary>) -> Vec<TableCopySpec> {
    let sid = "SELECT sortition_id FROM canonical_sortitions";
    let bhh = "SELECT burn_header_hash FROM canonical_burn_hashes";

    vec![
        TableCopySpec {
            table: "db_config",
            source_sql: "SELECT * FROM src.db_config".into(),
        },
        // sortition_id-filtered tables
        TableCopySpec {
            table: "snapshots",
            source_sql: format!("SELECT * FROM src.snapshots WHERE sortition_id IN ({sid})"),
        },
        TableCopySpec {
            table: "leader_keys",
            source_sql: format!("SELECT * FROM src.leader_keys WHERE sortition_id IN ({sid})"),
        },
        TableCopySpec {
            table: "block_commits",
            source_sql: format!("SELECT * FROM src.block_commits WHERE sortition_id IN ({sid})"),
        },
        TableCopySpec {
            table: "block_commit_parents",
            source_sql: format!(
                "SELECT * FROM src.block_commit_parents WHERE block_commit_sortition_id IN ({sid})"
            ),
        },
        TableCopySpec {
            table: "snapshot_transition_ops",
            source_sql: format!(
                "SELECT * FROM src.snapshot_transition_ops WHERE sortition_id IN ({sid})"
            ),
        },
        TableCopySpec {
            table: "stacks_chain_tips",
            source_sql: stacks_chain_tip_memo_source_sql("stacks_chain_tips", sid, false, boundary),
        },
        TableCopySpec {
            table: "stacks_chain_tips_by_burn_view",
            source_sql: stacks_chain_tip_memo_source_sql(
                "stacks_chain_tips_by_burn_view",
                sid,
                true,
                boundary,
            ),
        },
        TableCopySpec {
            table: "preprocessed_reward_sets",
            source_sql: format!(
                "SELECT * FROM src.preprocessed_reward_sets WHERE sortition_id IN ({sid})"
            ),
        },
        TableCopySpec {
            table: "missed_commits",
            source_sql: format!(
                "SELECT * FROM src.missed_commits WHERE intended_sortition_id IN ({sid})"
            ),
        },
        // burn_header_hash-filtered tables
        TableCopySpec {
            table: "stack_stx",
            source_sql: format!("SELECT * FROM src.stack_stx WHERE burn_header_hash IN ({bhh})"),
        },
        TableCopySpec {
            table: "transfer_stx",
            source_sql: format!("SELECT * FROM src.transfer_stx WHERE burn_header_hash IN ({bhh})"),
        },
        TableCopySpec {
            table: "delegate_stx",
            source_sql: format!("SELECT * FROM src.delegate_stx WHERE burn_header_hash IN ({bhh})"),
        },
        TableCopySpec {
            table: "vote_for_aggregate_key",
            source_sql: format!(
                "SELECT * FROM src.vote_for_aggregate_key WHERE burn_header_hash IN ({bhh})"
            ),
        },
        // Full-copy tables
        TableCopySpec {
            table: "epochs",
            source_sql: "SELECT * FROM src.epochs".to_string(),
        },
    ]
}

/// Copy required non-MARF tables from the source sortition DB into the
/// squashed destination. Only canonical rows (determined by the squashed MARF's
/// `marf_squashed_blocks`) are included.
pub fn copy_sortition_side_tables(
    src_path: &str,
    dst_path: &str,
) -> Result<SortitionSideTableStats, Error> {
    copy_sortition_side_tables_with_boundary(src_path, dst_path, None)
}

pub fn copy_sortition_side_tables_with_boundary(
    src_path: &str,
    dst_path: &str,
    stacks_boundary: Option<&SortitionTipCopyBoundary>,
) -> Result<SortitionSideTableStats, Error> {
    validate_tip_boundary(stacks_boundary)?;
    // Walk the squashed trie before opening dst R/W.
    let leaf_hashes = collect_canonical_leaf_hashes::<SortitionId>(dst_path)?;

    with_offline_write_session(dst_path, &[("src", src_path)], "", |conn| {
        clone_schemas_from_source(conn, REQUIRED_TABLES)?;
        copy_sortition_tables_inner(conn, &leaf_hashes, stacks_boundary)
    })
}

fn copy_sortition_tables_inner(
    conn: &Connection,
    leaf_hashes: &HashSet<MARFValue>,
    stacks_boundary: Option<&SortitionTipCopyBoundary>,
) -> Result<SortitionSideTableStats, Error> {
    // Copy only canonical __fork_storage rows. The squashed MARF trie
    // leaves reference these by value_hash. Non-canonical fork entries
    // are excluded.
    let fork_storage_rows = copy_canonical_fork_storage(conn, leaf_hashes)?;

    // Build canonical sortition set from squash metadata.
    populate_canonical_sortitions(conn)?;

    // Execute descriptor-driven copies.
    let specs = sortition_copy_specs(stacks_boundary);
    let results = execute_copy_specs(conn, &specs)?;
    if !sortition_tip_heights_within_boundary(conn, stacks_boundary)? {
        return Err(Error::CorruptionError(
            "copied sortition tip row points past the Stacks MARF boundary".into(),
        ));
    }

    conn.execute_batch("DROP TABLE IF EXISTS canonical_sortitions")
        .map_err(Error::SQLError)?;
    conn.execute_batch("DROP TABLE IF EXISTS canonical_burn_hashes")
        .map_err(Error::SQLError)?;

    Ok(SortitionSideTableStats {
        snapshots_rows: copied_rows(&results, "snapshots"),
        leader_keys_rows: copied_rows(&results, "leader_keys"),
        block_commits_rows: copied_rows(&results, "block_commits"),
        block_commit_parents_rows: copied_rows(&results, "block_commit_parents"),
        snapshot_transition_ops_rows: copied_rows(&results, "snapshot_transition_ops"),
        stacks_chain_tips_rows: copied_rows(&results, "stacks_chain_tips"),
        stacks_chain_tips_by_burn_view_rows: copied_rows(
            &results,
            "stacks_chain_tips_by_burn_view",
        ),
        preprocessed_reward_sets_rows: copied_rows(&results, "preprocessed_reward_sets"),
        missed_commits_rows: copied_rows(&results, "missed_commits"),
        stack_stx_rows: copied_rows(&results, "stack_stx"),
        transfer_stx_rows: copied_rows(&results, "transfer_stx"),
        delegate_stx_rows: copied_rows(&results, "delegate_stx"),
        vote_for_aggregate_key_rows: copied_rows(&results, "vote_for_aggregate_key"),
        epochs_rows: copied_rows(&results, "epochs"),
        db_config_rows: copied_rows(&results, "db_config"),
        fork_storage_rows,
    })
}
