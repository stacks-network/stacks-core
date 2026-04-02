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

use std::time::Instant;

use rusqlite::{params, Connection, OptionalExtension};
use stacks_common::types::chainstate::StacksBlockId;

use super::common::{
    clone_schemas_from_source, collect_leaf_value_hashes, copy_canonical_fork_storage,
    execute_copy_specs, full_row_except_match, table_exists, TableCopySpec,
};
use crate::burnchains::PoxConstants;
use crate::chainstate::stacks::index::Error;

/// Required table names that must be present in the squashed index DB.
const REQUIRED_TABLES: &[&str] = &[
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
    "staging_microblocks",
    "staging_microblocks_data",
    // Schema fidelity: these tables exist in archival nodes but are expected
    // unused in a Nakamoto-era GSS node. Included to prevent missing-table
    // crashes if any code path references them.
    "invalidated_microblocks_data", // Epoch 2.x block orphaning only (blocks.rs:2189)
    "user_supporters",              // Dead table: zero runtime references
];

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

/// Validation result for index side tables in a squashed DB.
#[derive(Debug, Clone)]
pub struct IndexSideTableValidation {
    pub tables_present: bool,
    pub db_config_matches: bool,
    pub fork_storage_match: bool,
    pub block_headers_count_match: bool,
    pub nakamoto_headers_count_match: bool,
    pub payments_count_match: bool,
    pub transactions_count_match: bool,
    pub nakamoto_tenure_events_count_match: bool,
    pub nakamoto_reward_sets_match: bool,
    pub signer_stats_match: bool,
    pub matured_rewards_match: bool,
    pub burnchain_txids_match: bool,
    pub epoch_transitions_match: bool,
    pub staging_blocks_match: bool,
    pub invalidated_microblocks_data_empty: bool,
    pub transactions_no_extra_blocks: bool,
    pub tenure_events_no_extra_blocks: bool,
}

impl IndexSideTableValidation {
    pub fn is_valid(&self) -> bool {
        self.tables_present
            && self.db_config_matches
            && self.fork_storage_match
            && self.block_headers_count_match
            && self.nakamoto_headers_count_match
            && self.payments_count_match
            && self.transactions_count_match
            && self.nakamoto_tenure_events_count_match
            && self.nakamoto_reward_sets_match
            && self.signer_stats_match
            && self.matured_rewards_match
            && self.burnchain_txids_match
            && self.epoch_transitions_match
            && self.staging_blocks_match
            && self.invalidated_microblocks_data_empty
            && self.transactions_no_extra_blocks
            && self.tenure_events_no_extra_blocks
    }
}

/// Populate a temp table with the canonical block hashes from the squashed MARF's
/// `marf_squash_block_heights` metadata.
fn populate_canonical_blocks(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch("CREATE TEMP TABLE canonical_blocks (index_block_hash TEXT PRIMARY KEY)")
        .map_err(Error::SQLError)?;
    conn.execute(
        "INSERT OR IGNORE INTO canonical_blocks (index_block_hash) \
         SELECT block_hash FROM marf_squash_block_heights",
        [],
    )
    .map_err(Error::SQLError)?;
    Ok(())
}

/// Derive the maximum reward cycle from the canonical squashed tip's burn height.
fn derive_max_reward_cycle(
    conn: &Connection,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<Option<u64>, Error> {
    let tip_burn_height: Option<u64> = conn
        .query_row(
            "SELECT nh.burn_header_height \
             FROM marf_squash_block_heights mh \
             JOIN src.nakamoto_block_headers nh ON nh.index_block_hash = mh.block_hash \
             ORDER BY mh.height DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(Error::SQLError)?
        .map(|h| h as u64);

    match tip_burn_height {
        Some(tbh) => {
            let cycle = PoxConstants::static_block_height_to_reward_cycle(
                tbh,
                first_burn_height,
                reward_cycle_len,
            )
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "cannot derive reward cycle: tip_burn_height={tbh}, \
                     first_burn_height={first_burn_height}, reward_cycle_len={reward_cycle_len}"
                ))
            })?;
            info!("  derive_max_reward_cycle: {cycle} (tip_burn_height={tbh})");
            Ok(Some(cycle))
        }
        None => Ok(None),
    }
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
/// `marf_squash_block_heights`) are included, excluding non-canonical fork data.
pub fn copy_index_side_tables(
    src_path: &str,
    dst_path: &str,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<IndexSideTableStats, Error> {
    let conn = Connection::open(dst_path).map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS src", params![src_path])
        .map_err(Error::SQLError)?;

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(Error::SQLError)?;

    if let Err(e) = clone_schemas_from_source(&conn, REQUIRED_TABLES) {
        let _ = conn.execute_batch("ROLLBACK");
        let _ = conn.execute_batch("DETACH DATABASE src");
        return Err(e);
    }

    let result = copy_tables_inner(&conn, dst_path, first_burn_height, reward_cycle_len);

    match result {
        Ok(stats) => {
            conn.execute_batch("COMMIT").map_err(Error::SQLError)?;
            conn.execute_batch("DETACH DATABASE src")
                .map_err(Error::SQLError)?;
            Ok(stats)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            let _ = conn.execute_batch("DETACH DATABASE src");
            Err(e)
        }
    }
}

fn copy_tables_inner(
    conn: &Connection,
    dst_path: &str,
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
    info!("  copy_side_tables: db_config done in {:?}", t.elapsed());

    // Copy only canonical __fork_storage rows - the squashed MARF trie
    // leaves reference these by value_hash. Non-canonical fork entries
    // are excluded.
    let fork_storage_rows = copy_canonical_fork_storage::<StacksBlockId>(conn, dst_path)?;

    // Build canonical block set from squash metadata.
    let t = Instant::now();
    populate_canonical_blocks(conn)?;
    info!(
        "  copy_side_tables: canonical_blocks temp table built in {:?}",
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
    let max_reward_cycle = derive_max_reward_cycle(conn, first_burn_height, reward_cycle_len)?;

    let t = Instant::now();
    let signer_stats_rows = match max_reward_cycle {
        Some(cycle) => conn
            .execute(
                "INSERT INTO signer_stats SELECT * FROM src.signer_stats \
                 WHERE reward_cycle <= ?1",
                params![cycle as i64],
            )
            .map_err(Error::SQLError)? as u64,
        None => conn
            .execute(
                "INSERT INTO signer_stats SELECT * FROM src.signer_stats",
                [],
            )
            .map_err(Error::SQLError)? as u64,
    };
    info!(
        "  copy_side_tables: signer_stats ({signer_stats_rows} rows) in {:?}",
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
        "  copy_side_tables: staging_blocks ({staging_blocks_rows} rows) in {:?}",
        t.elapsed()
    );

    conn.execute_batch("DROP TABLE IF EXISTS canonical_blocks")
        .map_err(Error::SQLError)?;

    info!(
        "  copy_side_tables: all tables done in {:?}",
        total_start.elapsed()
    );

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

/// Validate that the squashed index DB has the correct side tables by
/// comparing against the source.
pub fn validate_index_side_tables(
    src_path: &str,
    dst_path: &str,
    first_burn_height: u64,
    reward_cycle_len: u64,
) -> Result<IndexSideTableValidation, Error> {
    let conn = Connection::open(dst_path).map_err(Error::SQLError)?;
    conn.execute("ATTACH DATABASE ?1 AS src", params![src_path])
        .map_err(Error::SQLError)?;

    // Check all required tables exist.
    let tables_present = REQUIRED_TABLES.iter().all(|table| {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![table],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
            > 0
    });

    // db_config verbatim match.
    let db_config_matches = conn
        .query_row(
            "SELECT COUNT(*) FROM (
                SELECT version, mainnet, chain_id FROM db_config
                EXCEPT
                SELECT version, mainnet, chain_id FROM src.db_config
            )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1)
        == 0
        && conn
            .query_row(
                "SELECT COUNT(*) FROM (
                    SELECT version, mainnet, chain_id FROM src.db_config
                    EXCEPT
                    SELECT version, mainnet, chain_id FROM db_config
                )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(1)
            == 0;

    // __fork_storage: canonical-only copy. Validate against the canonical
    // filtered source set (same leaf-hash filter used by copy_canonical_fork_storage).
    let fork_storage_match = {
        let dst_has = table_exists(&conn, "", "__fork_storage");
        let src_has = table_exists(&conn, "src", "__fork_storage");
        match (dst_has, src_has) {
            (false, false) => true,
            (true, true) => {
                let has_marf_data = table_exists(&conn, "", "marf_data");

                if has_marf_data {
                    let (_tip, leaf_hashes) = collect_leaf_value_hashes::<StacksBlockId>(dst_path)?;

                    conn.execute_batch(
                        "CREATE TEMP TABLE val_fork_leaf_values (value_hash TEXT PRIMARY KEY)",
                    )
                    .map_err(Error::SQLError)?;

                    {
                        let mut stmt = conn
                            .prepare(
                                "INSERT OR IGNORE INTO val_fork_leaf_values (value_hash) VALUES (?1)",
                            )
                            .map_err(Error::SQLError)?;
                        for hash in &leaf_hashes {
                            stmt.execute([hash]).map_err(Error::SQLError)?;
                        }
                    }

                    let ok = full_row_except_match(
                        &conn,
                        "SELECT * FROM __fork_storage",
                        "SELECT f.* FROM src.__fork_storage f \
                         INNER JOIN val_fork_leaf_values lv ON f.value_hash = lv.value_hash",
                    );

                    conn.execute_batch("DROP TABLE IF EXISTS val_fork_leaf_values")
                        .map_err(Error::SQLError)?;

                    ok
                } else {
                    // fixture fallback, matching copy_canonical_fork_storage()
                    full_row_except_match(
                        &conn,
                        "SELECT * FROM __fork_storage",
                        "SELECT * FROM src.__fork_storage",
                    )
                }
            }
            _ => false,
        }
    };

    // Build canonical block set.
    let _ = conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS val_canonical_blocks (index_block_hash TEXT PRIMARY KEY)",
    );
    let _ = conn.execute(
        "INSERT OR IGNORE INTO val_canonical_blocks (index_block_hash) \
         SELECT block_hash FROM marf_squash_block_heights",
        [],
    );

    let cb = "SELECT index_block_hash FROM val_canonical_blocks";

    // Count-match validations (cheaper for large tables).
    let block_headers_count_match = {
        let src_count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM src.block_headers WHERE index_block_hash IN ({cb})"),
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        let dst_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM block_headers", [], |row| row.get(0))
            .unwrap_or(-2);
        src_count == dst_count
    };

    let nakamoto_headers_count_match = {
        let src_count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM src.nakamoto_block_headers \
                     WHERE index_block_hash IN ({cb})"
                ),
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        let dst_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM nakamoto_block_headers", [], |row| {
                row.get(0)
            })
            .unwrap_or(-2);
        src_count == dst_count
    };

    let payments_count_match = {
        let src_count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM src.payments WHERE index_block_hash IN ({cb})"),
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        let dst_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM payments", [], |row| row.get(0))
            .unwrap_or(-2);
        src_count == dst_count
    };

    let transactions_count_match = {
        let src_count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM src.transactions WHERE index_block_hash IN ({cb})"),
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        let dst_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))
            .unwrap_or(-2);
        src_count == dst_count
    };

    let nakamoto_tenure_events_count_match = {
        let src_count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM src.nakamoto_tenure_events WHERE block_id IN ({cb})"
                ),
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        let dst_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM nakamoto_tenure_events", [], |row| {
                row.get(0)
            })
            .unwrap_or(-2);
        src_count == dst_count
    };

    // No out-of-range rows leaked.
    let transactions_no_extra_blocks = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM transactions \
                 WHERE index_block_hash NOT IN ({cb})"
            ),
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1)
        == 0;

    let tenure_events_no_extra_blocks = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM nakamoto_tenure_events \
                 WHERE block_id NOT IN ({cb})"
            ),
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1)
        == 0;

    // staging_blocks: bidirectional full-row EXCEPT against canonical source rows.
    let staging_blocks_match = full_row_except_match(
        &conn,
        "SELECT * FROM staging_blocks",
        &format!(
            "SELECT s.* FROM src.staging_blocks s \
             WHERE s.index_block_hash IN ({cb}) \
               AND s.processed = 1 AND s.orphaned = 0"
        ),
    );

    // Schema-fidelity tables should be empty.
    let invalidated_microblocks_data_empty = conn
        .query_row(
            "SELECT COUNT(*) FROM invalidated_microblocks_data",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1)
        == 0;

    // Canonical-filtered tables: bidirectional full-row EXCEPT match.
    let nakamoto_reward_sets_match = full_row_except_match(
        &conn,
        "SELECT * FROM nakamoto_reward_sets",
        &format!("SELECT * FROM src.nakamoto_reward_sets WHERE index_block_hash IN ({cb})"),
    );

    let max_reward_cycle = derive_max_reward_cycle(&conn, first_burn_height, reward_cycle_len)?;

    let signer_stats_match = match max_reward_cycle {
        Some(cycle) => full_row_except_match(
            &conn,
            "SELECT * FROM signer_stats",
            &format!("SELECT * FROM src.signer_stats WHERE reward_cycle <= {cycle}"),
        ),
        None => full_row_except_match(
            &conn,
            "SELECT * FROM signer_stats",
            "SELECT * FROM src.signer_stats",
        ),
    };

    let matured_rewards_match = full_row_except_match(
        &conn,
        "SELECT * FROM matured_rewards",
        &format!("SELECT * FROM src.matured_rewards WHERE child_index_block_hash IN ({cb})"),
    );

    let burnchain_txids_match = full_row_except_match(
        &conn,
        "SELECT * FROM burnchain_txids",
        &format!("SELECT * FROM src.burnchain_txids WHERE index_block_hash IN ({cb})"),
    );

    let epoch_transitions_match = full_row_except_match(
        &conn,
        "SELECT * FROM epoch_transitions",
        &format!("SELECT * FROM src.epoch_transitions WHERE block_id IN ({cb})"),
    );

    let _ = conn.execute_batch("DROP TABLE IF EXISTS val_canonical_blocks");

    conn.execute_batch("DETACH DATABASE src")
        .map_err(Error::SQLError)?;

    Ok(IndexSideTableValidation {
        tables_present,
        db_config_matches,
        fork_storage_match,
        block_headers_count_match,
        nakamoto_headers_count_match,
        payments_count_match,
        transactions_count_match,
        nakamoto_tenure_events_count_match,
        nakamoto_reward_sets_match,
        signer_stats_match,
        matured_rewards_match,
        burnchain_txids_match,
        epoch_transitions_match,
        staging_blocks_match,
        invalidated_microblocks_data_empty,
        transactions_no_extra_blocks,
        tenure_events_no_extra_blocks,
    })
}
