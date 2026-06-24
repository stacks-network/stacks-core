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

use rusqlite::{params, Connection, OpenFlags};
use stacks_common::types::chainstate::SortitionId;

use super::common::{
    assert_source_schema, clone_schemas_from_source, copied_rows, execute_copy_specs,
    with_offline_write_session, TableCopySpec, MARF_INFRA_TABLES,
};
use super::fork_storage::{collect_canonical_leaf_hashes, copy_canonical_fork_storage};
use crate::chainstate::burn::db::sortdb::SortitionDB;
pub use crate::chainstate::burn::db::sortdb::SortitionTipCopyBoundary;
use crate::chainstate::stacks::index::{trie_sql, Error, MARFValue};
use crate::util_lib::db::sqlite_open;

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

/// Tables that may appear in a source sortition DB but are deliberately not
/// copied. `snapshot_burn_distributions` is written only under the `testing`
/// feature (`SortitionDBTx::store_burn_distribution`), never in production.
pub(super) const IGNORED_TABLES: &[&str] = &["snapshot_burn_distributions"];

/// Every table the sortition snapshot accounts for: content-copied
/// ([`REQUIRED_TABLES`]), owned by the MARF squash itself
/// ([`MARF_INFRA_TABLES`]), or deliberately skipped ([`IGNORED_TABLES`]).
fn known_sortition_tables() -> Vec<&'static str> {
    REQUIRED_TABLES
        .iter()
        .chain(MARF_INFRA_TABLES)
        .chain(IGNORED_TABLES)
        .copied()
        .collect()
}

/// The sortition snapshot's source-schema guard (see [`assert_source_schema`]);
/// `test_no_unclassified_sortition_tables` runs it against a fresh schema.
pub(super) fn assert_source_tables_classified(src_conn: &Connection) -> Result<(), Error> {
    assert_source_schema(
        src_conn,
        &known_sortition_tables(),
        "sortition DB",
        "REQUIRED_TABLES (to copy) or IGNORED_TABLES (to skip) in snapshot/sortition.rs",
    )
}

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

/// Build temp tables for the canonical sortition set and canonical burn
/// hashes. Each `SortitionId` binds as its lowercase-hex form, matching the
/// `sortition_id` TEXT in `src.snapshots`.
fn populate_canonical_sortitions(
    src_conn: &Connection,
    session_conn: &Connection,
) -> Result<(), Error> {
    let canonical = trie_sql::bulk_read_squashed_blocks::<SortitionId>(session_conn)?;
    if canonical.is_empty() {
        return Err(Error::CorruptionError(
            "marf_squashed_blocks is empty; post-squash dst must have at least one canonical sortition"
                .into(),
        ));
    }

    // Source-completeness: every canonical sortition must exist in
    // src.snapshots. A canonical sortition_id missing from src is
    // corruption. The squash claimed a sortition that src doesn't have.
    let mut burn_hashes: HashSet<String> = HashSet::new();
    let mut orphans: u64 = 0;
    for (_, sortition_id, _) in &canonical {
        match SortitionDB::get_snapshot_burn_header_hash(src_conn, sortition_id)? {
            Some(burn_header_hash) => {
                burn_hashes.insert(burn_header_hash);
            }
            None => orphans += 1,
        }
    }
    if orphans > 0 {
        return Err(Error::CorruptionError(format!(
            "{orphans} canonical sortition(s) in marf_squashed_blocks are absent from src.snapshots"
        )));
    }

    session_conn
        .execute_batch("CREATE TEMP TABLE canonical_sortitions (sortition_id TEXT PRIMARY KEY)")?;
    session_conn.execute_batch(
        "CREATE TEMP TABLE canonical_burn_hashes (burn_header_hash TEXT PRIMARY KEY)",
    )?;
    // A savepoint batches the temp-table inserts whether or not the session
    // already holds an open transaction.
    session_conn.execute_batch("SAVEPOINT canonical_sortitions")?;
    let mut insert =
        session_conn.prepare("INSERT INTO canonical_sortitions (sortition_id) VALUES (?1)")?;
    for (_, sortition_id, _) in &canonical {
        insert.execute(params![sortition_id])?;
    }
    drop(insert);
    let mut insert =
        session_conn.prepare("INSERT INTO canonical_burn_hashes (burn_header_hash) VALUES (?1)")?;
    for burn_header_hash in &burn_hashes {
        insert.execute([burn_header_hash])?;
    }
    drop(insert);
    session_conn.execute_batch("RELEASE canonical_sortitions")?;

    Ok(())
}

fn validate_tip_boundary(boundary: Option<&SortitionTipCopyBoundary>) -> Result<(), Error> {
    if let Some(boundary) = boundary {
        boundary.validate()?;
    }
    Ok(())
}

/// Build the copy specs for sortition side tables.
///
/// Tables are grouped by their filter key:
/// - `sortition_id` filtered
/// - `burn_header_hash` filtered
/// - full-copy
///
/// The set of tables is independent of `boundary`; the boundary only rewrites
/// the `stacks_chain_tips*` source SQL.
pub(super) fn sortition_copy_specs(
    boundary: Option<&SortitionTipCopyBoundary>,
) -> Vec<TableCopySpec> {
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
            source_sql: SortitionDB::stacks_tip_memo_copy_sql(
                "stacks_chain_tips",
                "src",
                sid,
                false,
                boundary,
            ),
        },
        TableCopySpec {
            table: "stacks_chain_tips_by_burn_view",
            source_sql: SortitionDB::stacks_tip_memo_copy_sql(
                "stacks_chain_tips_by_burn_view",
                "src",
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
///
/// `dst_path` is the squashed sortition DB already created by `MARF::squash_to_path`.
pub fn copy_sortition_side_tables(
    src_path: &str,
    dst_path: &str,
) -> Result<SortitionSideTableStats, Error> {
    copy_sortition_side_tables_with_boundary(src_path, dst_path, None)
}

/// [`copy_sortition_side_tables`] with an explicit Stacks-tip boundary: the
/// `stacks_chain_tips*` memo rows are rewritten/dropped relative to
/// `stacks_boundary` (see [`SortitionTipCopyBoundary`]).
/// A `None` boundary copies all the memo rows.
pub fn copy_sortition_side_tables_with_boundary(
    src_path: &str,
    dst_path: &str,
    stacks_boundary: Option<&SortitionTipCopyBoundary>,
) -> Result<SortitionSideTableStats, Error> {
    validate_tip_boundary(stacks_boundary)?;
    // Read-only source handle for the sortdb-owned readers; the session below
    // still attaches src for the copy specs.
    let src_conn = sqlite_open(src_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
    // Reject an unrecognized source schema before any destination work.
    assert_source_tables_classified(&src_conn)?;
    // Walk the squashed trie before opening dst R/W.
    let leaf_hashes = collect_canonical_leaf_hashes::<SortitionId>(dst_path)?;

    with_offline_write_session(dst_path, &[("src", src_path)], "", |conn| {
        clone_schemas_from_source(conn, REQUIRED_TABLES)?;
        copy_sortition_tables_inner(&src_conn, conn, &leaf_hashes, stacks_boundary)
    })
}

fn copy_sortition_tables_inner(
    src_conn: &Connection,
    session_conn: &Connection,
    leaf_hashes: &HashSet<MARFValue>,
    stacks_boundary: Option<&SortitionTipCopyBoundary>,
) -> Result<SortitionSideTableStats, Error> {
    // Copy only canonical __fork_storage rows. The squashed MARF trie
    // leaves reference these by value_hash. Non-canonical fork entries
    // are excluded.
    let fork_storage_rows = copy_canonical_fork_storage(session_conn, leaf_hashes)?;

    // Build canonical sortition set from squash metadata.
    populate_canonical_sortitions(src_conn, session_conn)?;

    // Execute descriptor-driven copies.
    let specs = sortition_copy_specs(stacks_boundary);
    let results = execute_copy_specs(session_conn, &specs)?;
    if !SortitionDB::stacks_tip_memos_within_boundary(session_conn, stacks_boundary)? {
        return Err(Error::CorruptionError(
            "copied sortition tip row points past the Stacks MARF boundary".into(),
        ));
    }

    session_conn.execute_batch("DROP TABLE IF EXISTS temp.canonical_sortitions")?;
    session_conn.execute_batch("DROP TABLE IF EXISTS temp.canonical_burn_hashes")?;

    let stats = SortitionSideTableStats {
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
    };
    info!(
        "Copied sortition side tables";
        "snapshots_rows" => stats.snapshots_rows,
        "fork_storage_rows" => stats.fork_storage_rows
    );
    Ok(stats)
}
