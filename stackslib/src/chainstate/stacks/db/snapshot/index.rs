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
use std::time::Instant;

use rusqlite::types::Value;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use stacks_common::types::chainstate::StacksBlockId;

use super::common::{
    clone_schemas_from_source, copied_rows, with_offline_write_session, DbSnapshotSpec,
    TableCopyBind, TableCopySpec, TableCopySpecs, MARF_INFRA_TABLES,
};
use super::fork_storage::{collect_canonical_leaf_hashes, copy_canonical_fork_storage};
use crate::burnchains::PoxConstants;
use crate::chainstate::stacks::index::{trie_sql, Error, MARFValue};
use crate::util_lib::db::{sqlite_open, u64_to_sql};

/// The index (`index.sqlite`) side-table snapshot spec. `max_reward_cycle` feeds
/// the `signer_stats` `?N` bind only -- the table-name set is independent of it.
/// The MARF infra tables ([`MARF_INFRA_TABLES`]) are created by the squash
/// engine, so they're recognized by the guard but not row-copied.
pub(super) struct IndexDbSnapshotSpec {
    pub max_reward_cycle: u64,
}

impl IndexDbSnapshotSpec {
    /// For source-schema classification only: the recognized table-name set is
    /// independent of `max_reward_cycle`, so the guard/clone use a zero sentinel.
    fn for_classification() -> Self {
        Self {
            max_reward_cycle: 0,
        }
    }
}

impl DbSnapshotSpec for IndexDbSnapshotSpec {
    fn copy_specs(&self) -> TableCopySpecs<'static> {
        TableCopySpecs::new(index_copy_specs())
    }

    fn bind_params(&self, bind: TableCopyBind) -> Result<Vec<Value>, Error> {
        match bind {
            TableCopyBind::None => Ok(Vec::new()),
            // `signer_stats` filters `reward_cycle <= ?1`.
            TableCopyBind::IndexMaxRewardCycle => {
                Ok(vec![Value::Integer(u64_to_sql(self.max_reward_cycle)?)])
            }
            other => Err(Error::CorruptionError(format!(
                "BUG: index snapshot does not handle table-copy bind {other:?}"
            ))),
        }
    }

    fn extra_recognized_tables(&self) -> Vec<&'static str> {
        MARF_INFRA_TABLES.to_vec()
    }

    fn db_label(&self) -> &'static str {
        "index DB"
    }

    fn classify_hint(&self) -> &'static str {
        "index_copy_specs() in snapshot/index.rs"
    }
}

/// The index snapshot's source-schema guard (see
/// [`DbSnapshotSpec::assert_source_classified`]);
/// `test_no_unclassified_source_tables` runs it against a fresh schema.
pub(super) fn assert_source_tables_classified(src_conn: &Connection) -> Result<(), Error> {
    IndexDbSnapshotSpec::for_classification().assert_source_classified(src_conn)
}

/// Row-count statistics returned by [`copy_index_side_tables`].
#[derive(Debug, Clone)]
pub struct IndexSideTableStats {
    pub block_headers_rows: u64,
    pub nakamoto_block_headers_rows: u64,
    pub payments_rows: u64,
    pub transactions_rows: u64,
    pub nakamoto_tenure_events_rows: u64,
    pub nakamoto_reward_sets_rows: u64,
    pub signer_stats_rows: u64,
    pub matured_rewards_rows: u64,
    pub burnchain_txids_rows: u64,
    pub epoch_transitions_rows: u64,
    pub staging_blocks_rows: u64,
    pub fork_storage_rows: u64,
}

/// Populate a temp table with the canonical block hashes from the squashed
/// MARF's metadata. Chainstate `index_block_hash` columns are lowercase
/// hex TEXT, so each id is inserted as its hex form to keep the joins
/// compatible. Returns the canonical tip (the highest squashed block).
fn populate_canonical_blocks(conn: &Connection) -> Result<StacksBlockId, Error> {
    let canonical = trie_sql::bulk_read_squashed_blocks::<StacksBlockId>(conn)?;
    let Some((_, tip, _)) = canonical.last() else {
        return Err(Error::CorruptionError(
            "marf_squashed_blocks is empty; post-squash dst must have at least one canonical block"
                .into(),
        ));
    };
    let tip = tip.clone();

    conn.execute_batch("CREATE TEMP TABLE canonical_blocks (index_block_hash TEXT PRIMARY KEY)")
        .map_err(Error::SQLError)?;
    let mut insert = conn
        .prepare("INSERT INTO canonical_blocks (index_block_hash) VALUES (?1)")
        .map_err(Error::SQLError)?;
    for (_, block_hash, _) in &canonical {
        insert
            .execute(params![block_hash])
            .map_err(Error::SQLError)?;
    }
    drop(insert);

    // Source-completeness: every canonical block must exist in src as an
    // epoch-2 or Nakamoto header. A canonical ID not in src is corruption.
    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM canonical_blocks \
             WHERE index_block_hash NOT IN (SELECT index_block_hash FROM src.block_headers) \
               AND index_block_hash NOT IN (SELECT index_block_hash FROM src.nakamoto_block_headers)",
            [],
            |row| row.get(0),
        )
        .map_err(Error::SQLError)?;
    if orphans > 0 {
        return Err(Error::CorruptionError(format!(
            "{orphans} canonical block(s) in marf_squashed_blocks are absent from \
             src.block_headers and src.nakamoto_block_headers"
        )));
    }
    Ok(tip)
}

/// Derive the `signer_stats` cutoff: the reward cycle of the canonical tip,
/// which must be a Nakamoto block.
///
/// Tip-cycle counters are copied as stored in src; `signer_stats` is a
/// non-consensus RPC counter (`/v3/signer`), so counts that include
/// post-boundary signatures are acceptable.
fn derive_max_reward_cycle(
    conn: &Connection,
    canonical_tip: &StacksBlockId,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<u64, Error> {
    let tip_burn_height: u64 = conn
        .query_row(
            "SELECT burn_header_height FROM src.nakamoto_block_headers \
             WHERE index_block_hash = ?1",
            params![canonical_tip],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(Error::SQLError)?
        .map(|h| h as u64)
        .ok_or_else(|| {
            Error::CorruptionError(
                "canonical tip is not a Nakamoto block (no match in \
                 src.nakamoto_block_headers); squashing requires an epoch 3.4+ chainstate"
                    .into(),
            )
        })?;

    let cycle = PoxConstants::static_block_height_to_reward_cycle(
        tip_burn_height,
        first_burn_height,
        reward_cycle_len,
    )
    .ok_or_else(|| {
        Error::CorruptionError(format!(
            "cannot derive reward cycle: tip_burn_height={tip_burn_height}, \
             first_burn_height={first_burn_height}, reward_cycle_len={reward_cycle_len}"
        ))
    })?;
    info!("[index] derive_max_reward_cycle: {cycle} (tip_burn_height={tip_burn_height})");
    Ok(cycle)
}

/// Build the copy specs for every SQL-expressible index-table copy.
/// Most tables filter uniformly by `index_block_hash IN canonical_blocks`.
///
/// Special cases:
/// - `db_config` is copied in full.
/// - `staging_blocks` adds a check for processend and non-orphaned blocks.
/// - `signer_stats` is cut off at the canonical tip's  reward cycle.
pub(super) fn index_copy_specs() -> &'static [TableCopySpec] {
    // `signer_stats`'s reward-cycle bound is the only runtime value, passed as
    // the `?1` bind.
    static SPECS: &[TableCopySpec] = &[
        TableCopySpec::sql("db_config", "SELECT * FROM src.db_config"),
        TableCopySpec::sql(
            "block_headers",
            "SELECT * FROM src.block_headers \
                 WHERE index_block_hash IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "nakamoto_block_headers",
            "SELECT * FROM src.nakamoto_block_headers \
                 WHERE index_block_hash IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "payments",
            "SELECT * FROM src.payments \
                 WHERE index_block_hash IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "transactions",
            "SELECT * FROM src.transactions \
                 WHERE index_block_hash IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "nakamoto_tenure_events",
            "SELECT * FROM src.nakamoto_tenure_events \
                 WHERE block_id IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "nakamoto_reward_sets",
            "SELECT * FROM src.nakamoto_reward_sets \
                 WHERE index_block_hash IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "matured_rewards",
            "SELECT * FROM src.matured_rewards \
                 WHERE child_index_block_hash IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "burnchain_txids",
            "SELECT * FROM src.burnchain_txids \
                 WHERE index_block_hash IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "epoch_transitions",
            "SELECT * FROM src.epoch_transitions \
                 WHERE block_id IN (SELECT index_block_hash FROM canonical_blocks)",
        ),
        TableCopySpec::sql(
            "staging_blocks",
            // Only canonical, fully-processed, non-orphaned blocks.
            "SELECT s.* FROM src.staging_blocks s \
                 WHERE s.index_block_hash IN (SELECT index_block_hash FROM canonical_blocks) \
                   AND s.processed = 1 \
                   AND s.orphaned = 0",
        ),
        TableCopySpec::sql_with_bind(
            "signer_stats",
            "SELECT * FROM src.signer_stats WHERE reward_cycle <= ?1",
            TableCopyBind::IndexMaxRewardCycle,
        ),
        // Schema-only: schema cloned for fidelity, not row-copied here.
        // `staging_microblocks`/`_data` are populated later by the
        // block-preservation phase; the other two stay empty.
        TableCopySpec::schema_only("staging_microblocks"),
        TableCopySpec::schema_only("staging_microblocks_data"),
        // Only written when orphaning epoch 2.x blocks.
        TableCopySpec::schema_only("invalidated_microblocks_data"),
        // Dead table: zero runtime references.
        TableCopySpec::schema_only("user_supporters"),
    ];
    SPECS
}

/// Copy required non-MARF tables from the source `index.sqlite` into the
/// squashed destination. Only canonical rows (determined by the squashed MARF's
/// `marf_squashed_blocks`) are included, excluding non-canonical fork data.
///
/// Per the squash preconditions, src must be an epoch 3.4+ chainstate:
/// the canonical set must contain a Nakamoto tip.
pub fn copy_index_side_tables(
    src_path: &str,
    dst_path: &str,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<IndexSideTableStats, Error> {
    // Reject an unrecognized source schema before any destination work.
    let src_conn = sqlite_open(src_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
    assert_source_tables_classified(&src_conn)?;
    drop(src_conn);

    let leaf_hashes = collect_canonical_leaf_hashes::<StacksBlockId>(dst_path)?;

    with_offline_write_session(dst_path, &[("src", src_path)], "", |conn| {
        // Clone only the spec tables' schemas; MARF infra tables are created by
        // the squash engine, not cloned here.
        clone_schemas_from_source(conn, &TableCopySpecs::new(index_copy_specs()).table_names())?;
        copy_tables_inner(conn, &leaf_hashes, first_burn_height, reward_cycle_len)
    })
}

fn copy_tables_inner(
    conn: &Connection,
    leaf_hashes: &HashSet<MARFValue>,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<IndexSideTableStats, Error> {
    let total_start = Instant::now();

    // Copy only canonical __fork_storage rows. The squashed MARF trie
    // leaves reference these by value_hash. Non-canonical fork entries
    // are excluded.
    let fork_storage_rows = copy_canonical_fork_storage(conn, leaf_hashes)?;

    // Build canonical block set from squash metadata.
    let t = Instant::now();
    let canonical_tip = populate_canonical_blocks(conn)?;
    info!(
        "[index] canonical_blocks temp table built in {:?}",
        t.elapsed()
    );

    let max_reward_cycle =
        derive_max_reward_cycle(conn, &canonical_tip, first_burn_height, reward_cycle_len)?;

    let spec = IndexDbSnapshotSpec { max_reward_cycle };
    let results = spec.run_copy(conn)?;

    conn.execute_batch("DROP TABLE IF EXISTS canonical_blocks")
        .map_err(Error::SQLError)?;

    info!("[index] all tables done in {:?}", total_start.elapsed());

    Ok(IndexSideTableStats {
        block_headers_rows: copied_rows(&results, "block_headers"),
        nakamoto_block_headers_rows: copied_rows(&results, "nakamoto_block_headers"),
        payments_rows: copied_rows(&results, "payments"),
        transactions_rows: copied_rows(&results, "transactions"),
        nakamoto_tenure_events_rows: copied_rows(&results, "nakamoto_tenure_events"),
        nakamoto_reward_sets_rows: copied_rows(&results, "nakamoto_reward_sets"),
        signer_stats_rows: copied_rows(&results, "signer_stats"),
        matured_rewards_rows: copied_rows(&results, "matured_rewards"),
        burnchain_txids_rows: copied_rows(&results, "burnchain_txids"),
        epoch_transitions_rows: copied_rows(&results, "epoch_transitions"),
        staging_blocks_rows: copied_rows(&results, "staging_blocks"),
        fork_storage_rows,
    })
}
