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

use rusqlite::{params, Connection, OptionalExtension};
use stacks_common::types::chainstate::StacksBlockId;

use super::common::{
    clone_schemas_from_source, execute_copy_specs, with_offline_write_session, TableCopySpec,
};
use super::fork_storage::{collect_canonical_leaf_hashes, copy_canonical_fork_storage};
use crate::burnchains::PoxConstants;
use crate::chainstate::stacks::index::Error;

/// Tables copied (with canonical-filtered content) into the squashed index DB.
pub(crate) const COPIED_TABLES: &[&str] = &[
    "db_config",
    "block_headers",
    "nakamoto_block_headers",
    "payments",
    "transactions",
    "nakamoto_tenure_events",
    "nakamoto_reward_sets",
    "signer_stats",
    "matured_rewards",
    "burnchain_txids",
    "epoch_transitions",
    "staging_blocks",
];

/// Tables the index copy clones for schema fidelity but does not populate. They
/// are intentionally schema-only in this slice (never written by the index
/// copy); cloning their schema prevents missing-table crashes if any code path
/// references them.
pub(crate) const SCHEMA_ONLY_TABLES: &[&str] = &[
    "staging_microblocks",
    "staging_microblocks_data",
    "invalidated_microblocks_data", // Epoch 2.x block orphaning only (blocks.rs:2189)
    "user_supporters",              // Dead table: zero runtime references
];

/// Every table whose schema must exist in the squashed dst (copied + schema-only).
fn all_required_tables() -> Vec<&'static str> {
    COPIED_TABLES
        .iter()
        .chain(SCHEMA_ONLY_TABLES)
        .copied()
        .collect()
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

/// Populate a temp table with the canonical block hashes from the squashed MARF's
/// `marf_squashed_blocks` metadata. The MARF stores `block_hash` as raw BLOB
/// bytes, but chainstate `index_block_hash` columns are lowercase hex TEXT,
/// so we convert via `lower(hex(block_hash))` to keep the joins compatible.
fn populate_canonical_blocks(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch("CREATE TEMP TABLE canonical_blocks (index_block_hash TEXT PRIMARY KEY)")
        .map_err(Error::SQLError)?;
    let inserted = conn
        .execute(
            "INSERT OR IGNORE INTO canonical_blocks (index_block_hash) \
             SELECT lower(hex(block_hash)) FROM marf_squashed_blocks",
            [],
        )
        .map_err(Error::SQLError)?;
    if inserted == 0 {
        return Err(Error::CorruptionError(
            "marf_squashed_blocks is empty; post-squash dst must have at least one canonical block"
                .into(),
        ));
    }
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
    Ok(())
}

/// Scope of `signer_stats` rows the squashed dst should retain.
#[derive(Debug, Clone, Copy)]
pub enum RewardCycleScope {
    /// Post-Nakamoto state with a canonical tip: keep `signer_stats`
    /// rows where `reward_cycle <= cycle`.
    Through(u64),
    /// Pre-Nakamoto state: `src.nakamoto_block_headers` is empty, so
    /// `src.signer_stats` must also be empty (asserted at derivation).
    /// No rows to copy.
    PreNakamoto,
}

/// Determine the `signer_stats` cutoff. Three real states:
/// - Post-Nakamoto with canonical tip → `Through(cycle)`.
/// - Pre-Nakamoto (no `nakamoto_block_headers` in src) → `PreNakamoto`,
///   after asserting `src.signer_stats` is empty (it would be otherwise
///   unfilterable).
/// - `nakamoto_block_headers` non-empty but no canonical join match →
///   `CorruptionError` (squashed canonical set absent from src).
fn derive_max_reward_cycle(
    conn: &Connection,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<RewardCycleScope, Error> {
    let src_has_nakamoto: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM src.nakamoto_block_headers",
            [],
            |row| row.get(0),
        )
        .map_err(Error::SQLError)?;
    if !src_has_nakamoto {
        let signer_stats_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM src.signer_stats", [], |row| {
                row.get(0)
            })
            .map_err(Error::SQLError)?;
        if signer_stats_count > 0 {
            return Err(Error::CorruptionError(format!(
                "pre-Nakamoto src (no nakamoto_block_headers) has {signer_stats_count} \
                 signer_stats rows; expected empty"
            )));
        }
        info!("[index] derive_max_reward_cycle: pre-Nakamoto (signer_stats empty)");
        return Ok(RewardCycleScope::PreNakamoto);
    }

    let tip_burn_height: u64 = conn
        .query_row(
            "SELECT nh.burn_header_height \
             FROM marf_squashed_blocks mh \
             JOIN src.nakamoto_block_headers nh \
               ON nh.index_block_hash = lower(hex(mh.block_hash)) \
             ORDER BY mh.height DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(Error::SQLError)?
        .map(|h| h as u64)
        .ok_or_else(|| {
            Error::CorruptionError(
                "src.nakamoto_block_headers has rows but none match marf_squashed_blocks; \
                 squashed canonical set is absent from src"
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
    Ok(RewardCycleScope::Through(cycle))
}

/// Build the copy specs for descriptor-driven index tables.
/// These are the uniform `index_block_hash IN canonical_blocks` tables.
fn index_copy_specs() -> Vec<TableCopySpec> {
    let cb = "SELECT index_block_hash FROM canonical_blocks";
    vec![
        TableCopySpec {
            table: "block_headers",
            source_sql: format!("SELECT * FROM src.block_headers WHERE index_block_hash IN ({cb})"),
        },
        TableCopySpec {
            table: "nakamoto_block_headers",
            source_sql: format!(
                "SELECT * FROM src.nakamoto_block_headers WHERE index_block_hash IN ({cb})"
            ),
        },
        TableCopySpec {
            table: "payments",
            source_sql: format!("SELECT * FROM src.payments WHERE index_block_hash IN ({cb})"),
        },
        TableCopySpec {
            table: "transactions",
            source_sql: format!("SELECT * FROM src.transactions WHERE index_block_hash IN ({cb})"),
        },
        TableCopySpec {
            table: "nakamoto_tenure_events",
            source_sql: format!(
                "SELECT * FROM src.nakamoto_tenure_events WHERE block_id IN ({cb})"
            ),
        },
        TableCopySpec {
            table: "nakamoto_reward_sets",
            source_sql: format!(
                "SELECT * FROM src.nakamoto_reward_sets WHERE index_block_hash IN ({cb})"
            ),
        },
        TableCopySpec {
            table: "matured_rewards",
            source_sql: format!(
                "SELECT * FROM src.matured_rewards WHERE child_index_block_hash IN ({cb})"
            ),
        },
        TableCopySpec {
            table: "burnchain_txids",
            source_sql: format!(
                "SELECT * FROM src.burnchain_txids WHERE index_block_hash IN ({cb})"
            ),
        },
        TableCopySpec {
            table: "epoch_transitions",
            source_sql: format!("SELECT * FROM src.epoch_transitions WHERE block_id IN ({cb})"),
        },
    ]
}

/// Copy required non-MARF tables from the source `index.sqlite` into the
/// squashed destination. Only canonical rows (determined by the squashed MARF's
/// `marf_squashed_blocks`) are included, excluding non-canonical fork data.
pub fn copy_index_side_tables(
    src_path: &str,
    dst_path: &str,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<IndexSideTableStats, Error> {
    let leaf_hashes = collect_canonical_leaf_hashes::<StacksBlockId>(dst_path)?;

    with_offline_write_session(dst_path, &[("src", src_path)], "", |conn| {
        clone_schemas_from_source(conn, &all_required_tables())?;
        copy_tables_inner(conn, &leaf_hashes, first_burn_height, reward_cycle_len)
    })
}

fn copy_tables_inner(
    conn: &Connection,
    leaf_hashes: &HashSet<String>,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<IndexSideTableStats, Error> {
    let total_start = Instant::now();

    // Copy db_config verbatim.
    let t = Instant::now();
    conn.execute(
        "INSERT OR REPLACE INTO db_config SELECT * FROM src.db_config",
        [],
    )
    .map_err(Error::SQLError)?;
    info!("[index] db_config done in {:?}", t.elapsed());

    // Copy only canonical __fork_storage rows. The squashed MARF trie
    // leaves reference these by value_hash. Non-canonical fork entries
    // are excluded.
    let fork_storage_rows = copy_canonical_fork_storage(conn, leaf_hashes)?;

    // Build canonical block set from squash metadata.
    let t = Instant::now();
    populate_canonical_blocks(conn)?;
    info!(
        "[index] canonical_blocks temp table built in {:?}",
        t.elapsed()
    );

    // Execute descriptor-driven copies for uniform tables.
    let specs = index_copy_specs();
    let results = execute_copy_specs(conn, &specs)?;

    let get = |name: &str| -> u64 {
        results
            .iter()
            .find(|(t, _)| *t == name)
            .map(|(_, r)| *r)
            .unwrap_or(0)
    };

    // Custom: signer_stats filtered by derived reward cycle.
    let signer_stats_scope = derive_max_reward_cycle(conn, first_burn_height, reward_cycle_len)?;

    let t = Instant::now();
    let signer_stats_rows = match signer_stats_scope {
        RewardCycleScope::Through(cycle) => conn
            .execute(
                "INSERT INTO signer_stats SELECT * FROM src.signer_stats \
                 WHERE reward_cycle <= ?1",
                params![cycle as i64],
            )
            .map_err(Error::SQLError)? as u64,
        // Pre-Nakamoto: `derive_max_reward_cycle` already verified
        // `src.signer_stats` is empty; nothing to copy.
        RewardCycleScope::PreNakamoto => 0,
    };
    info!(
        "[index] signer_stats ({signer_stats_rows} rows) in {:?}",
        t.elapsed()
    );

    // Custom: staging_blocks with semantic predicate.
    let t = Instant::now();
    let staging_blocks_rows = conn
        .execute(
            "INSERT INTO staging_blocks \
             SELECT s.* FROM src.staging_blocks s \
             WHERE s.index_block_hash IN (SELECT index_block_hash FROM canonical_blocks) \
               AND s.processed = 1 \
               AND s.orphaned = 0",
            [],
        )
        .map_err(Error::SQLError)? as u64;
    info!(
        "[index] staging_blocks ({staging_blocks_rows} rows) in {:?}",
        t.elapsed()
    );

    conn.execute_batch("DROP TABLE IF EXISTS canonical_blocks")
        .map_err(Error::SQLError)?;

    info!("[index] all tables done in {:?}", total_start.elapsed());

    Ok(IndexSideTableStats {
        block_headers_rows: get("block_headers"),
        nakamoto_block_headers_rows: get("nakamoto_block_headers"),
        payments_rows: get("payments"),
        transactions_rows: get("transactions"),
        nakamoto_tenure_events_rows: get("nakamoto_tenure_events"),
        nakamoto_reward_sets_rows: get("nakamoto_reward_sets"),
        signer_stats_rows,
        matured_rewards_rows: get("matured_rewards"),
        burnchain_txids_rows: get("burnchain_txids"),
        epoch_transitions_rows: get("epoch_transitions"),
        staging_blocks_rows,
        fork_storage_rows,
    })
}
