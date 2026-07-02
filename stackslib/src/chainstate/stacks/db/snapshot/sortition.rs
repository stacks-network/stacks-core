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

use rusqlite::types::Value;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use stacks_common::types::chainstate::{BurnchainHeaderHash, SortitionId};
use stacks_common::types::sqlite::NO_PARAMS;

use super::common::{
    clone_schemas_from_source, copied_rows, with_offline_write_session, DbSnapshotSpec,
    TableCopyBind, TableCopySpec, TableCopySpecs, MARF_INFRA_TABLES,
};
use super::fork_storage::{collect_canonical_leaf_hashes, copy_canonical_fork_storage};
pub use crate::chainstate::burn::db::sortdb::SortitionTipCopyBoundary;
use crate::chainstate::stacks::index::{trie_sql, Error, MARFValue};
use crate::util_lib::db::{sqlite_open, u64_to_sql, Error as db_error};

/// Snapshot-only reads over a sortition DB connection.
pub(crate) trait SortitionSnapshotExt {
    /// Distinct burn header hashes of all snapshots, forks included. Only on a
    /// squashed sortition DB is this exactly the canonical burnchain.
    fn get_all_snapshot_burn_header_hashes(&self) -> Result<Vec<BurnchainHeaderHash>, db_error>;
    /// Burn header hash of the snapshot with the given sortition ID (raw stored
    /// TEXT, byte-for-byte), or `None` if no such snapshot exists.
    fn get_snapshot_burn_header_hash(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<Option<String>, db_error>;
    /// Whether every Stacks-tip memo row (both memo tables) sits at or below the
    /// boundary's Stacks height. A `None` boundary trivially passes. The copy
    /// counterpart of [`stacks_tip_memo_copy_sql`]'s height rewrite.
    fn stacks_tip_memos_within_boundary(
        &self,
        boundary: Option<&SortitionTipCopyBoundary>,
    ) -> Result<bool, db_error>;
}

impl SortitionSnapshotExt for Connection {
    fn get_all_snapshot_burn_header_hashes(&self) -> Result<Vec<BurnchainHeaderHash>, db_error> {
        let mut stmt = self.prepare("SELECT DISTINCT burn_header_hash FROM snapshots")?;
        let rows = stmt.query_map(NO_PARAMS, |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_error::from)
    }

    fn get_snapshot_burn_header_hash(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<Option<String>, db_error> {
        self.prepare_cached("SELECT burn_header_hash FROM snapshots WHERE sortition_id = ?1")?
            .query_row(params![sortition_id], |row| row.get(0))
            .optional()
            .map_err(db_error::from)
    }

    fn stacks_tip_memos_within_boundary(
        &self,
        boundary: Option<&SortitionTipCopyBoundary>,
    ) -> Result<bool, db_error> {
        let Some(boundary) = boundary else {
            return Ok(true);
        };
        let max_height = u64_to_sql(boundary.max_stacks_height)?;
        // Check if ANY above-boundary memo row exists.
        self.query_row(
            "SELECT NOT EXISTS( \
                 SELECT 1 FROM stacks_chain_tips WHERE block_height > ?1 \
                 UNION ALL \
                 SELECT 1 FROM stacks_chain_tips_by_burn_view WHERE block_height > ?1 \
             )",
            params![max_height],
            |row| row.get(0),
        )
        .map_err(db_error::from)
    }
}

/// Static source-projection SQL template for copying a Stacks-tip memo table
/// (`stacks_chain_tips`, or `stacks_chain_tips_by_burn_view` when
/// `include_burn_view`) from `src`, keeping rows whose `sortition_id` is in the
/// `canonical_sortitions` temp table. With a boundary (`has_boundary`), memo rows
/// above the boundary's Stacks height are rewritten down to the anchor (see
/// [`SortitionTipCopyBoundary`]); the anchor values are the `?1..?5` placeholders
/// supplied by [`stacks_tip_memo_copy_binds`].
const fn stacks_tip_memo_copy_sql(include_burn_view: bool, has_boundary: bool) -> &'static str {
    match (include_burn_view, has_boundary) {
        (false, false) => {
            "SELECT * FROM src.stacks_chain_tips \
             WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)"
        }
        (true, false) => {
            "SELECT * FROM src.stacks_chain_tips_by_burn_view \
             WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)"
        }
        (false, true) => {
            "SELECT sortition_id, \
                    CASE WHEN block_height > ?1 THEN ?2 ELSE consensus_hash END, \
                    CASE WHEN block_height > ?1 THEN ?3 ELSE block_hash END, \
                    CASE WHEN block_height > ?1 THEN ?4 ELSE block_height END \
             FROM src.stacks_chain_tips \
             WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions) \
               AND (block_height <= ?1 OR consensus_hash = ?2)"
        }
        (true, true) => {
            "SELECT sortition_id, \
                    CASE WHEN block_height > ?1 THEN ?2 ELSE consensus_hash END, \
                    CASE WHEN block_height > ?1 THEN ?5 ELSE burn_view_consensus_hash END, \
                    CASE WHEN block_height > ?1 THEN ?3 ELSE block_hash END, \
                    CASE WHEN block_height > ?1 THEN ?4 ELSE block_height END \
             FROM src.stacks_chain_tips_by_burn_view \
             WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions) \
               AND (block_height <= ?1 OR (consensus_hash = ?2 AND burn_view_consensus_hash = ?5))"
        }
    }
}

/// Positional `?N` bind values for [`stacks_tip_memo_copy_sql`]'s boundary-rewrite
/// template; empty when `boundary` is `None` (the plain template has no
/// placeholders). Order: `?1` max Stacks height, `?2` anchor consensus hash, `?3`
/// anchor block hash, `?4` anchor block height, and (for `include_burn_view`)
/// `?5` anchor burn-view consensus hash.
fn stacks_tip_memo_copy_binds(
    boundary: Option<&SortitionTipCopyBoundary>,
    include_burn_view: bool,
) -> Result<Vec<Value>, Error> {
    let Some(boundary) = boundary else {
        return Ok(Vec::new());
    };
    let mut params = vec![
        Value::Integer(u64_to_sql(boundary.max_stacks_height)?),
        Value::Text(boundary.anchor_consensus_hash.to_string()),
        Value::Text(boundary.anchor_block_hash.to_string()),
        Value::Integer(u64_to_sql(boundary.anchor_block_height)?),
    ];
    if include_burn_view {
        params.push(Value::Text(
            boundary.anchor_burn_view_consensus_hash.to_string(),
        ));
    }
    Ok(params)
}

/// Tables that may appear in a source sortition DB but are deliberately not
/// copied. `snapshot_burn_distributions` is written only under the `testing`
/// feature (`SortitionDBTx::store_burn_distribution`), never in production.
pub(super) const IGNORED_TABLES: &[&str] = &["snapshot_burn_distributions"];

/// The sortition (`marf.sqlite` side-tables) snapshot spec. The `boundary`
/// selects the `stacks_chain_tips*` memo template (plain vs rewrite) and feeds
/// the rewrite anchors as `?N` binds; the table-name set is independent of it.
/// MARF infra ([`MARF_INFRA_TABLES`], created by the squash engine) and
/// deliberately-skipped ([`IGNORED_TABLES`]) tables are recognized by the guard
/// but not row-copied.
pub(super) struct SortitionDbSnapshotSpec {
    pub boundary: Option<SortitionTipCopyBoundary>,
}

impl SortitionDbSnapshotSpec {
    /// For source-schema classification only: the recognized table-name set is
    /// independent of the boundary, so the guard uses a `None` boundary.
    fn for_classification() -> Self {
        Self { boundary: None }
    }
}

impl DbSnapshotSpec for SortitionDbSnapshotSpec {
    fn copy_specs(&self) -> TableCopySpecs<'static> {
        TableCopySpecs::new(sortition_copy_specs(self.boundary.is_some()))
    }

    fn bind_params(&self, bind: TableCopyBind) -> Result<Vec<Value>, Error> {
        match bind {
            TableCopyBind::None => Ok(Vec::new()),
            TableCopyBind::SortitionTipMemo { include_burn_view } => {
                stacks_tip_memo_copy_binds(self.boundary.as_ref(), include_burn_view)
            }
            other => Err(Error::CorruptionError(format!(
                "BUG: sortition snapshot does not handle table-copy bind {other:?}"
            ))),
        }
    }

    fn extra_recognized_tables(&self) -> Vec<&'static str> {
        MARF_INFRA_TABLES
            .iter()
            .copied()
            .chain(IGNORED_TABLES.iter().copied())
            .collect()
    }

    fn db_label(&self) -> &'static str {
        "sortition DB"
    }

    fn classify_hint(&self) -> &'static str {
        "sortition_copy_specs() (to copy) or IGNORED_TABLES (to skip) in snapshot/sortition.rs"
    }
}

/// The sortition snapshot's source-schema guard (see
/// [`DbSnapshotSpec::assert_source_classified`]); `test_no_unclassified_sortition_tables`
/// runs it against a fresh schema. The recognized set is independent of the boundary.
pub(super) fn assert_source_tables_classified(src_conn: &Connection) -> Result<(), Error> {
    SortitionDbSnapshotSpec::for_classification().assert_source_classified(src_conn)
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
        match src_conn.get_snapshot_burn_header_hash(sortition_id)? {
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
pub(super) fn sortition_copy_specs(has_boundary: bool) -> &'static [TableCopySpec] {
    // The only runtime values are the `stacks_chain_tips*` boundary-rewrite
    // anchors, supplied as `?N` binds; `has_boundary` selects the rewrite vs
    // plain memo template (see `stacks_tip_memo_copy_sql`). The plain and rewrite
    // lists differ only in those two memo specs, so a local macro builds both
    // from one definition.
    macro_rules! sortition_specs {
        ($has_boundary:expr) => {
            &[
                TableCopySpec::sql("db_config", "SELECT * FROM src.db_config"),
                // sortition_id-filtered tables
                TableCopySpec::sql(
                    "snapshots",
                        "SELECT * FROM src.snapshots \
                         WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)",
                ),
                TableCopySpec::sql(
                    "leader_keys",
                        "SELECT * FROM src.leader_keys \
                         WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)",
                ),
                TableCopySpec::sql(
                    "block_commits",
                        "SELECT * FROM src.block_commits \
                         WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)",
                ),
                TableCopySpec::sql(
                    "block_commit_parents",
                        "SELECT * FROM src.block_commit_parents \
                         WHERE block_commit_sortition_id IN (SELECT sortition_id FROM canonical_sortitions)",
                ),
                TableCopySpec::sql(
                    "snapshot_transition_ops",
                        "SELECT * FROM src.snapshot_transition_ops \
                         WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)",
                ),
                TableCopySpec::sql_with_bind(
                    "stacks_chain_tips",
                    stacks_tip_memo_copy_sql(false, $has_boundary),
                    TableCopyBind::SortitionTipMemo {
                        include_burn_view: false,
                    },
                ),
                TableCopySpec::sql_with_bind(
                    "stacks_chain_tips_by_burn_view",
                    stacks_tip_memo_copy_sql(true, $has_boundary),
                    TableCopyBind::SortitionTipMemo {
                        include_burn_view: true,
                    },
                ),
                TableCopySpec::sql(
                    "preprocessed_reward_sets",
                        "SELECT * FROM src.preprocessed_reward_sets \
                         WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)",
                ),
                TableCopySpec::sql(
                    "missed_commits",
                        "SELECT * FROM src.missed_commits \
                         WHERE intended_sortition_id IN (SELECT sortition_id FROM canonical_sortitions)",
                ),
                // burn_header_hash-filtered tables
                TableCopySpec::sql(
                    "stack_stx",
                        "SELECT * FROM src.stack_stx \
                         WHERE burn_header_hash IN (SELECT burn_header_hash FROM canonical_burn_hashes)",
                ),
                TableCopySpec::sql(
                    "transfer_stx",
                        "SELECT * FROM src.transfer_stx \
                         WHERE burn_header_hash IN (SELECT burn_header_hash FROM canonical_burn_hashes)",
                ),
                TableCopySpec::sql(
                    "delegate_stx",
                        "SELECT * FROM src.delegate_stx \
                         WHERE burn_header_hash IN (SELECT burn_header_hash FROM canonical_burn_hashes)",
                ),
                TableCopySpec::sql(
                    "vote_for_aggregate_key",
                        "SELECT * FROM src.vote_for_aggregate_key \
                         WHERE burn_header_hash IN (SELECT burn_header_hash FROM canonical_burn_hashes)",
                ),
                // Full-copy tables
                TableCopySpec::sql("epochs", "SELECT * FROM src.epochs"),
            ]
        };
    }
    static PLAIN: &[TableCopySpec] = sortition_specs!(false);
    static REWRITE: &[TableCopySpec] = sortition_specs!(true);
    if has_boundary {
        REWRITE
    } else {
        PLAIN
    }
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
        // Clone only the spec tables' schemas; MARF infra is created by the
        // squash engine and ignored tables are intentionally absent from the dst.
        clone_schemas_from_source(
            conn,
            &SortitionDbSnapshotSpec::for_classification()
                .copy_specs()
                .table_names(),
        )?;
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
    let spec = SortitionDbSnapshotSpec {
        boundary: stacks_boundary.cloned(),
    };
    let results = spec.run_copy(session_conn)?;
    if !session_conn.stacks_tip_memos_within_boundary(stacks_boundary)? {
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
