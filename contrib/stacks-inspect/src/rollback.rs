// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

//! Chainstate rollback utility.
//!
//! Rolls back committed Stacks chainstate to a target Stacks block height by removing all block
//! data above that height from the underlying SQLite databases.
//!
//! # Use cases
//!
//! - **Testing**: Reset chainstate to a known-good height in order to replay scenarios such as
//!   epoch transitions or upgrade paths. You can then restart the node and observe how it
//!   reprocesses those blocks, or inject a different binary to test a new code path.
//!
//! - **Unclean shutdown recovery**: When a node is killed mid-write, the chainstate can be left
//!   in a partially-applied state.  Rolling back a few blocks returns the database to a
//!   consistent snapshot that the node can safely continue from on the next startup.
//!
//! - **Failed upgrade recovery**: If a consensus-breaking upgrade (hardfork) was applied
//!   incorrectly, rolling back to a height *before* the hardfork activation window closes
//!   allows an operator to deploy a corrected binary and let the node resync the affected
//!   blocks before the network diverges.
//!
//! # What is rolled back
//!
//! The operation targets two database files inside the chainstate directory:
//!
//! * `chainstate/vm/index.sqlite` — the primary chainstate database.  This file contains both
//!   the Stacks block headers (Epoch 2 and Nakamoto) and the embedded MARF trie nodes that
//!   back all Clarity state.  All rows whose Stacks block height exceeds `target_height` are
//!   removed, along with all dependent metadata (transactions, payments, matured rewards,
//!   burnchain txids, epoch transitions, reward sets, and tenure events).
//!
//! * `chainstate/blocks/nakamoto.sqlite` — the Nakamoto staging block queue.  All queued blocks
//!   at height > `target_height` are removed; they will be re-downloaded from peers when the
//!   node restarts.
//!
//! # What is NOT rolled back
//!
//! * The sortition database (`burnchain/sortition/`) is **not** modified.  Sortition state
//!   tracks Bitcoin-anchored data and is independent of the Stacks block height being rolled
//!   back.  The node will re-derive the correct canonical Stacks tip from the remaining
//!   chainstate on startup.
//!
//! * Epoch 2 block flat-files (`chainstate/blocks/…`) are **not** deleted, even when their
//!   corresponding staging entries are removed.  The disk overhead is usually acceptable for
//!   recovery purposes and the node will ignore orphaned files.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, params};

/// Statistics describing the outcome of a rollback operation.
#[derive(Debug, Default, PartialEq)]
pub struct RollbackStats {
    /// Number of Nakamoto `block_headers` rows removed.
    pub nakamoto_blocks_removed: u64,
    /// Number of Epoch 2 `block_headers` rows removed.
    pub epoch2_blocks_removed: u64,
    /// Number of `transactions` rows removed.
    pub transactions_removed: u64,
    /// Number of `payments` rows removed.
    pub payments_removed: u64,
    /// Number of `matured_rewards` rows removed.
    pub matured_rewards_removed: u64,
    /// Number of `burnchain_txids` rows removed.
    pub burnchain_txids_removed: u64,
    /// Number of `epoch_transitions` rows removed.
    pub epoch_transitions_removed: u64,
    /// Number of `nakamoto_reward_sets` rows removed.
    pub nakamoto_reward_sets_removed: u64,
    /// Number of `nakamoto_tenure_events` / `nakamoto_tenures` rows removed.
    pub tenure_events_removed: u64,
    /// Number of `marf_data` trie-node rows removed.
    pub marf_entries_removed: u64,
    /// Number of Epoch 2 `staging_blocks` rows removed.
    pub epoch2_staging_removed: u64,
    /// Number of `nakamoto_staging_blocks` rows removed.
    pub nakamoto_staging_removed: u64,
}

impl RollbackStats {
    /// Total number of block records removed across both epochs.
    pub fn total_blocks_removed(&self) -> u64 {
        self.nakamoto_blocks_removed + self.epoch2_blocks_removed
    }
}

/// Roll back all committed chainstate at Stacks block heights above `target_height`.
///
/// `db_path` is the network-specific working directory — the directory that contains the
/// `chainstate/` and `burnchain/` subdirectories (e.g. `~/.stacks-node/mainnet`).
///
/// When `dry_run` is `true` the function reports what *would* be removed but makes no
/// changes to disk.
pub fn chainstate_rollback(
    db_path: &str,
    target_height: u64,
    dry_run: bool,
) -> Result<RollbackStats, String> {
    let index_db_path = format!("{db_path}/chainstate/vm/index.sqlite");
    let nakamoto_staging_db_path = format!("{db_path}/chainstate/blocks/nakamoto.sqlite");
    rollback_from_paths(&index_db_path, &nakamoto_staging_db_path, target_height, dry_run)
}

/// Core rollback function that accepts explicit database paths.
///
/// This entry point exists primarily for testing, where callers control the exact file
/// locations.  Most callers should use [`chainstate_rollback`] instead.
pub fn rollback_from_paths(
    index_db_path: &str,
    nakamoto_staging_db_path: &str,
    target_height: u64,
    dry_run: bool,
) -> Result<RollbackStats, String> {
    let open_flags = if dry_run {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };

    let mut conn = Connection::open_with_flags(index_db_path, open_flags)
        .map_err(|e| format!("Failed to open index DB at {index_db_path}: {e}"))?;

    let mut stats = rollback_index_db(&mut conn, target_height, dry_run)?;

    if Path::new(nakamoto_staging_db_path).exists() {
        let mut naka_conn =
            Connection::open_with_flags(nakamoto_staging_db_path, open_flags)
                .map_err(|e| format!("Failed to open Nakamoto staging DB at {nakamoto_staging_db_path}: {e}"))?;
        let naka_stats = rollback_nakamoto_staging_db(&mut naka_conn, target_height, dry_run)?;
        stats.nakamoto_staging_removed = naka_stats.nakamoto_staging_removed;
    }

    Ok(stats)
}

/// Perform the rollback within the main index database.
///
/// All committed block records at `block_height > target_height` are removed together with
/// every row that references them in dependent tables.  The MARF trie entries for those
/// blocks are also deleted so that Clarity state remains consistent with the new chain tip.
///
/// On success the function returns populated [`RollbackStats`].
/// In dry-run mode it only reads the database and returns counts of what *would* change.
pub fn rollback_index_db(
    conn: &mut Connection,
    target_height: u64,
    dry_run: bool,
) -> Result<RollbackStats, String> {
    let mut stats = RollbackStats::default();

    // ------------------------------------------------------------------
    // Count rows that will be affected.  We always do this so callers get
    // accurate numbers whether or not dry_run is set.
    // ------------------------------------------------------------------
    stats.nakamoto_blocks_removed =
        try_count(conn, "SELECT COUNT(*) FROM nakamoto_block_headers WHERE block_height > ?1", target_height);
    stats.epoch2_blocks_removed =
        try_count(conn, "SELECT COUNT(*) FROM block_headers WHERE block_height > ?1", target_height);

    if dry_run || stats.total_blocks_removed() == 0 {
        // Report additional counts in dry-run mode so the user sees the full picture.
        stats.transactions_removed = try_count(
            conn,
            "SELECT COUNT(*) FROM transactions WHERE index_block_hash IN (
                SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
                UNION ALL
                SELECT index_block_hash FROM block_headers WHERE block_height > ?1
            )",
            target_height,
        );
        stats.payments_removed = try_count(
            conn,
            "SELECT COUNT(*) FROM payments WHERE index_block_hash IN (
                SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
                UNION ALL
                SELECT index_block_hash FROM block_headers WHERE block_height > ?1
            )",
            target_height,
        );
        stats.marf_entries_removed = try_count(
            conn,
            "SELECT COUNT(*) FROM marf_data WHERE block_hash IN (
                SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
                UNION ALL
                SELECT index_block_hash FROM block_headers WHERE block_height > ?1
            )",
            target_height,
        );
        stats.epoch2_staging_removed =
            try_count(conn, "SELECT COUNT(*) FROM staging_blocks WHERE height > ?1", target_height);
        return Ok(stats);
    }

    // ------------------------------------------------------------------
    // Execute all deletions inside a single atomic transaction so that
    // a crash mid-way leaves the database unchanged.
    // ------------------------------------------------------------------
    let tx = conn
        .transaction()
        .map_err(|e| format!("Failed to begin rollback transaction: {e}"))?;

    // Dependent tables must be cleaned up *before* the header rows they
    // reference are deleted, because their WHERE clauses use subqueries
    // against the header tables.

    stats.transactions_removed = exec_delete(
        &tx,
        "DELETE FROM transactions WHERE index_block_hash IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
            UNION ALL
            SELECT index_block_hash FROM block_headers WHERE block_height > ?1
        )",
        target_height,
        "transactions",
    )?;

    stats.payments_removed = exec_delete(
        &tx,
        "DELETE FROM payments WHERE index_block_hash IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
            UNION ALL
            SELECT index_block_hash FROM block_headers WHERE block_height > ?1
        )",
        target_height,
        "payments",
    )?;

    stats.matured_rewards_removed = exec_delete(
        &tx,
        "DELETE FROM matured_rewards
         WHERE child_index_block_hash IN (
                 SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
                 UNION ALL
                 SELECT index_block_hash FROM block_headers WHERE block_height > ?1
               )
            OR parent_index_block_hash IN (
                 SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
                 UNION ALL
                 SELECT index_block_hash FROM block_headers WHERE block_height > ?1
               )",
        target_height,
        "matured_rewards",
    )?;

    stats.burnchain_txids_removed = exec_delete(
        &tx,
        "DELETE FROM burnchain_txids WHERE index_block_hash IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
            UNION ALL
            SELECT index_block_hash FROM block_headers WHERE block_height > ?1
        )",
        target_height,
        "burnchain_txids",
    )?;

    stats.epoch_transitions_removed = exec_delete(
        &tx,
        "DELETE FROM epoch_transitions WHERE block_id IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
            UNION ALL
            SELECT index_block_hash FROM block_headers WHERE block_height > ?1
        )",
        target_height,
        "epoch_transitions",
    )?;

    // Nakamoto-specific tables may not exist on pure Epoch 2 chainstates.
    stats.nakamoto_reward_sets_removed += try_exec_delete(
        &tx,
        "DELETE FROM nakamoto_reward_sets WHERE index_block_hash IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
        )",
        target_height,
        "nakamoto_reward_sets",
    );

    // Try the current table name first, then fall back to the older one.
    stats.tenure_events_removed += try_exec_delete(
        &tx,
        "DELETE FROM nakamoto_tenure_events WHERE block_id IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
        )",
        target_height,
        "nakamoto_tenure_events",
    );
    stats.tenure_events_removed += try_exec_delete(
        &tx,
        "DELETE FROM nakamoto_tenures WHERE block_id IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
        )",
        target_height,
        "nakamoto_tenures",
    );

    // Remove MARF trie nodes for rolled-back blocks so that Clarity state
    // cannot be read at heights that no longer exist.
    stats.marf_entries_removed = exec_delete(
        &tx,
        "DELETE FROM marf_data WHERE block_hash IN (
            SELECT index_block_hash FROM nakamoto_block_headers WHERE block_height > ?1
            UNION ALL
            SELECT index_block_hash FROM block_headers WHERE block_height > ?1
        )",
        target_height,
        "marf_data",
    )?;

    // Staging block queues.
    stats.epoch2_staging_removed = exec_delete(
        &tx,
        "DELETE FROM staging_blocks WHERE height > ?1",
        target_height,
        "staging_blocks",
    )?;

    // Microblock staging entries for rolled-back parent blocks.
    let _ = tx.execute(
        "DELETE FROM staging_microblocks WHERE index_block_hash IN (
            SELECT index_block_hash FROM block_headers WHERE block_height > ?1
        )",
        params![target_height],
    );

    // Finally remove the header records themselves.  These must come last
    // because the earlier subqueries depend on them.
    try_exec_delete(
        &tx,
        "DELETE FROM nakamoto_block_headers WHERE block_height > ?1",
        target_height,
        "nakamoto_block_headers",
    );
    exec_delete(
        &tx,
        "DELETE FROM block_headers WHERE block_height > ?1",
        target_height,
        "block_headers",
    )?;

    tx.commit()
        .map_err(|e| format!("Failed to commit rollback transaction: {e}"))?;

    Ok(stats)
}

/// Remove Nakamoto staging blocks above `target_height` from the staging database.
pub fn rollback_nakamoto_staging_db(
    conn: &mut Connection,
    target_height: u64,
    dry_run: bool,
) -> Result<RollbackStats, String> {
    let mut stats = RollbackStats::default();

    stats.nakamoto_staging_removed =
        try_count(conn, "SELECT COUNT(*) FROM nakamoto_staging_blocks WHERE height > ?1", target_height);

    if dry_run || stats.nakamoto_staging_removed == 0 {
        return Ok(stats);
    }

    let tx = conn
        .transaction()
        .map_err(|e| format!("Failed to begin nakamoto staging transaction: {e}"))?;

    exec_delete(
        &tx,
        "DELETE FROM nakamoto_staging_blocks WHERE height > ?1",
        target_height,
        "nakamoto_staging_blocks",
    )?;

    tx.commit()
        .map_err(|e| format!("Failed to commit nakamoto staging rollback: {e}"))?;

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run a `SELECT COUNT(*)` query with a single `u64` parameter and return the
/// count, or `0` if the table does not exist or the query otherwise fails.
fn try_count(conn: &Connection, sql: &str, height: u64) -> u64 {
    conn.query_row(sql, params![height], |row| row.get::<_, i64>(0))
        .map(|n| n.max(0) as u64)
        .unwrap_or(0)
}

/// Execute a DELETE statement with a single `u64` parameter and return the
/// number of rows deleted.  Returns an error if the table exists but the
/// DELETE fails for reasons other than a missing table.
fn exec_delete(
    tx: &rusqlite::Transaction<'_>,
    sql: &str,
    height: u64,
    table_name: &str,
) -> Result<u64, String> {
    tx.execute(sql, params![height])
        .map(|n| n as u64)
        .map_err(|e| format!("DELETE from {table_name} failed: {e}"))
}

/// Execute a DELETE statement, silently ignoring "no such table" errors.
/// This is used for tables that may not exist across all supported schema versions.
/// Returns the number of rows deleted, or `0` on any error.
fn try_exec_delete(
    tx: &rusqlite::Transaction<'_>,
    sql: &str,
    height: u64,
    _table_name: &str,
) -> u64 {
    tx.execute(sql, params![height])
        .map(|n| n as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    // ------------------------------------------------------------------
    // Helpers that build minimal in-memory schemas
    // ------------------------------------------------------------------

    /// Create a minimal schema matching the tables that `rollback_index_db` touches.
    fn setup_index_db(conn: &Connection) {
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = OFF;

            CREATE TABLE IF NOT EXISTS block_headers (
                block_height    INTEGER NOT NULL,
                index_block_hash TEXT UNIQUE NOT NULL,
                block_hash      TEXT NOT NULL,
                consensus_hash  TEXT UNIQUE NOT NULL,
                PRIMARY KEY(consensus_hash, block_hash)
            );

            CREATE TABLE IF NOT EXISTS nakamoto_block_headers (
                block_height    INTEGER NOT NULL,
                index_block_hash TEXT UNIQUE NOT NULL,
                block_hash      TEXT NOT NULL,
                consensus_hash  TEXT NOT NULL,
                PRIMARY KEY(consensus_hash, block_hash)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                txid TEXT NOT NULL,
                index_block_hash TEXT NOT NULL,
                tx_hex TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL DEFAULT '',
                UNIQUE(txid, index_block_hash)
            );

            CREATE TABLE IF NOT EXISTS payments (
                address TEXT NOT NULL,
                index_block_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                consensus_hash TEXT NOT NULL,
                parent_block_hash TEXT NOT NULL DEFAULT '',
                parent_consensus_hash TEXT NOT NULL DEFAULT '',
                coinbase TEXT NOT NULL DEFAULT '0',
                tx_fees_anchored TEXT NOT NULL DEFAULT '0',
                tx_fees_streamed TEXT NOT NULL DEFAULT '0',
                stx_burns TEXT NOT NULL DEFAULT '0',
                burnchain_commit_burn INT NOT NULL DEFAULT 0,
                burnchain_sortition_burn INT NOT NULL DEFAULT 0,
                miner INT NOT NULL DEFAULT 1,
                stacks_block_height INTEGER NOT NULL,
                vtxindex INT NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS matured_rewards (
                address TEXT NOT NULL,
                vtxindex INTEGER NOT NULL,
                coinbase TEXT NOT NULL,
                tx_fees_anchored TEXT NOT NULL DEFAULT '0',
                tx_fees_streamed_confirmed TEXT NOT NULL DEFAULT '0',
                tx_fees_streamed_produced TEXT NOT NULL DEFAULT '0',
                child_index_block_hash TEXT NOT NULL,
                parent_index_block_hash TEXT NOT NULL,
                PRIMARY KEY(parent_index_block_hash, child_index_block_hash, coinbase)
            );

            CREATE TABLE IF NOT EXISTS burnchain_txids (
                index_block_hash TEXT PRIMARY KEY,
                txids TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS epoch_transitions (
                block_id TEXT PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS nakamoto_reward_sets (
                index_block_hash TEXT PRIMARY KEY,
                reward_set TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS nakamoto_tenure_events (
                tenure_id_consensus_hash TEXT NOT NULL,
                prev_tenure_id_consensus_hash TEXT NOT NULL DEFAULT '',
                burn_view_consensus_hash TEXT NOT NULL,
                cause INTEGER NOT NULL DEFAULT 0,
                block_hash TEXT NOT NULL,
                block_id TEXT NOT NULL,
                coinbase_height INTEGER NOT NULL DEFAULT 0,
                num_blocks_confirmed INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(burn_view_consensus_hash, block_id)
            );

            CREATE TABLE IF NOT EXISTS marf_data (
                block_id INTEGER PRIMARY KEY,
                block_hash TEXT UNIQUE NOT NULL,
                data BLOB NOT NULL DEFAULT X'',
                unconfirmed INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS staging_blocks (
                anchored_block_hash TEXT NOT NULL,
                parent_anchored_block_hash TEXT NOT NULL DEFAULT '',
                consensus_hash TEXT NOT NULL,
                parent_consensus_hash TEXT NOT NULL DEFAULT '',
                parent_microblock_hash TEXT NOT NULL DEFAULT '',
                parent_microblock_seq INT NOT NULL DEFAULT 0,
                microblock_pubkey_hash TEXT NOT NULL DEFAULT '',
                height INT NOT NULL,
                attachable INT NOT NULL DEFAULT 1,
                orphaned INT NOT NULL DEFAULT 0,
                processed INT NOT NULL DEFAULT 1,
                commit_burn INT NOT NULL DEFAULT 0,
                sortition_burn INT NOT NULL DEFAULT 0,
                index_block_hash TEXT NOT NULL,
                download_time INT NOT NULL DEFAULT 0,
                arrival_time INT NOT NULL DEFAULT 0,
                processed_time INT NOT NULL DEFAULT 0,
                PRIMARY KEY(anchored_block_hash, consensus_hash)
            );

            CREATE TABLE IF NOT EXISTS staging_microblocks (
                anchored_block_hash TEXT NOT NULL,
                consensus_hash TEXT NOT NULL,
                index_block_hash TEXT NOT NULL,
                microblock_hash TEXT NOT NULL,
                parent_hash TEXT NOT NULL DEFAULT '',
                index_microblock_hash TEXT NOT NULL DEFAULT '',
                sequence INT NOT NULL DEFAULT 0,
                processed INT NOT NULL DEFAULT 1,
                orphaned INT NOT NULL DEFAULT 0,
                PRIMARY KEY(anchored_block_hash, consensus_hash, microblock_hash)
            );
            "#,
        )
        .expect("failed to create test schema");
    }

    /// Create the minimal schema for the Nakamoto staging database.
    fn setup_nakamoto_staging_db(conn: &Connection) {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS nakamoto_staging_blocks (
                block_hash TEXT NOT NULL,
                consensus_hash TEXT NOT NULL,
                parent_block_id TEXT NOT NULL DEFAULT '',
                is_tenure_start BOOL NOT NULL DEFAULT 0,
                burn_attachable INT NOT NULL DEFAULT 1,
                processed INT NOT NULL DEFAULT 0,
                orphaned INT NOT NULL DEFAULT 0,
                height INT NOT NULL,
                index_block_hash TEXT NOT NULL,
                download_time INT,
                arrival_time INT,
                processed_time INT,
                data BLOB NOT NULL DEFAULT X'',
                PRIMARY KEY(block_hash, consensus_hash)
            );
            "#,
        )
        .expect("failed to create nakamoto staging schema");
    }

    /// Insert a fake Epoch 2 block at the given height.
    fn insert_epoch2_block(conn: &Connection, height: u64, suffix: &str) {
        let ibh = format!("epoch2_ibh_{height}_{suffix}");
        let bh = format!("epoch2_bh_{height}_{suffix}");
        let ch = format!("epoch2_ch_{height}_{suffix}");
        conn.execute(
            "INSERT OR IGNORE INTO block_headers(block_height, index_block_hash, block_hash, consensus_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![height, ibh, bh, ch],
        )
        .expect("insert epoch2 block");

        // Insert a MARF entry for this block.
        conn.execute(
            "INSERT OR IGNORE INTO marf_data(block_hash, data, unconfirmed) VALUES (?1, X'', 0)",
            params![ibh],
        )
        .expect("insert marf entry");

        // Insert a staging_blocks entry.
        conn.execute(
            "INSERT OR IGNORE INTO staging_blocks(anchored_block_hash, consensus_hash, index_block_hash, height, processed)
             VALUES (?1, ?2, ?3, ?4, 1)",
            params![bh, ch, ibh, height],
        )
        .expect("insert staging block");
    }

    /// Insert a fake Nakamoto block at the given height.
    fn insert_nakamoto_block(conn: &Connection, height: u64, suffix: &str) {
        let ibh = format!("naka_ibh_{height}_{suffix}");
        let bh = format!("naka_bh_{height}_{suffix}");
        let ch = format!("naka_ch_{height}_{suffix}");
        conn.execute(
            "INSERT OR IGNORE INTO nakamoto_block_headers(block_height, index_block_hash, block_hash, consensus_hash)
             VALUES (?1, ?2, ?3, ?4)",
            params![height, ibh, bh, ch],
        )
        .expect("insert nakamoto block");

        conn.execute(
            "INSERT OR IGNORE INTO marf_data(block_hash, data, unconfirmed) VALUES (?1, X'', 0)",
            params![ibh],
        )
        .expect("insert marf entry");
    }

    /// Insert a fake Nakamoto staging block.
    fn insert_nakamoto_staging(conn: &Connection, height: u64, suffix: &str) {
        let ibh = format!("naka_ibh_{height}_{suffix}");
        let bh = format!("naka_bh_{height}_{suffix}");
        let ch = format!("naka_ch_{height}_{suffix}");
        conn.execute(
            "INSERT OR IGNORE INTO nakamoto_staging_blocks(block_hash, consensus_hash, index_block_hash, height, data)
             VALUES (?1, ?2, ?3, ?4, X'')",
            params![bh, ch, ibh, height],
        )
        .expect("insert nakamoto staging block");
    }

    /// Count rows in a table.
    fn count(conn: &Connection, table: &str) -> u64 {
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {table}"),
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n as u64)
        .unwrap_or(0)
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    #[test]
    fn test_rollback_removes_blocks_above_target() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");
        insert_epoch2_block(&conn, 3, "c");
        insert_epoch2_block(&conn, 4, "d");

        let stats = rollback_index_db(&mut conn, 2, false).unwrap();

        assert_eq!(stats.epoch2_blocks_removed, 2, "blocks 3 and 4 should be removed");
        assert_eq!(count(&conn, "block_headers"), 2, "blocks 1 and 2 should remain");
    }

    #[test]
    fn test_rollback_preserves_target_height_block() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 5, "a");
        insert_epoch2_block(&conn, 6, "b");
        insert_epoch2_block(&conn, 7, "c");

        rollback_index_db(&mut conn, 6, false).unwrap();

        // Block at height 6 must survive.
        let remaining: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM block_headers WHERE block_height = 6",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1, "target-height block must not be removed");

        // Block at height 7 must be gone.
        let above: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM block_headers WHERE block_height = 7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(above, 0, "block above target must be removed");
    }

    #[test]
    fn test_rollback_removes_nakamoto_blocks() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_nakamoto_block(&conn, 100, "a");
        insert_nakamoto_block(&conn, 101, "b");
        insert_nakamoto_block(&conn, 102, "c");

        let stats = rollback_index_db(&mut conn, 100, false).unwrap();

        assert_eq!(stats.nakamoto_blocks_removed, 2);
        assert_eq!(count(&conn, "nakamoto_block_headers"), 1);
    }

    #[test]
    fn test_rollback_cleans_marf_entries() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 10, "a");
        insert_epoch2_block(&conn, 11, "b");
        insert_nakamoto_block(&conn, 12, "c");

        let before = count(&conn, "marf_data");
        assert_eq!(before, 3);

        let stats = rollback_index_db(&mut conn, 10, false).unwrap();

        assert_eq!(stats.marf_entries_removed, 2, "MARF entries for heights 11 and 12 removed");
        assert_eq!(count(&conn, "marf_data"), 1, "MARF entry for height 10 remains");
    }

    #[test]
    fn test_rollback_cleans_transactions() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");

        // Insert transactions referencing each block.
        conn.execute(
            "INSERT INTO transactions(txid, index_block_hash, tx_hex, result) VALUES ('tx1', 'epoch2_ibh_1_a', '', '')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transactions(txid, index_block_hash, tx_hex, result) VALUES ('tx2', 'epoch2_ibh_2_b', '', '')",
            [],
        )
        .unwrap();

        rollback_index_db(&mut conn, 1, false).unwrap();

        assert_eq!(count(&conn, "transactions"), 1, "only tx1 should remain");
        let remaining_txid: String = conn
            .query_row("SELECT txid FROM transactions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining_txid, "tx1");
    }

    #[test]
    fn test_rollback_cleans_payments() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");

        conn.execute(
            "INSERT INTO payments(address, index_block_hash, block_hash, consensus_hash, stacks_block_height)
             VALUES ('addr1', 'epoch2_ibh_1_a', 'bh1', 'ch1', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO payments(address, index_block_hash, block_hash, consensus_hash, stacks_block_height)
             VALUES ('addr2', 'epoch2_ibh_2_b', 'bh2', 'ch2', 2)",
            [],
        )
        .unwrap();

        rollback_index_db(&mut conn, 1, false).unwrap();

        assert_eq!(count(&conn, "payments"), 1);
    }

    #[test]
    fn test_rollback_cleans_matured_rewards() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");
        insert_epoch2_block(&conn, 3, "c");

        // Reward row referencing heights 1 (parent) and 2 (child) — should survive.
        conn.execute(
            "INSERT INTO matured_rewards(address, vtxindex, coinbase, child_index_block_hash, parent_index_block_hash)
             VALUES ('addr', 0, '100', 'epoch2_ibh_2_b', 'epoch2_ibh_1_a')",
            [],
        )
        .unwrap();
        // Reward row referencing heights 2 (parent) and 3 (child) — both above target=1.
        conn.execute(
            "INSERT INTO matured_rewards(address, vtxindex, coinbase, child_index_block_hash, parent_index_block_hash)
             VALUES ('addr', 0, '200', 'epoch2_ibh_3_c', 'epoch2_ibh_2_b')",
            [],
        )
        .unwrap();

        rollback_index_db(&mut conn, 1, false).unwrap();

        // The reward row with child at height 2 is removed (child is above target).
        // The reward row with child at height 3 is also removed.
        assert_eq!(count(&conn, "matured_rewards"), 0);
    }

    #[test]
    fn test_rollback_cleans_staging_blocks() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");
        insert_epoch2_block(&conn, 3, "c");

        rollback_index_db(&mut conn, 1, false).unwrap();

        assert_eq!(
            count(&conn, "staging_blocks"),
            1,
            "only height-1 staging entry remains"
        );
    }

    #[test]
    fn test_rollback_dry_run_makes_no_changes() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");
        insert_epoch2_block(&conn, 3, "c");

        let before_headers = count(&conn, "block_headers");
        let before_marf = count(&conn, "marf_data");

        let stats = rollback_index_db(&mut conn, 1, true).unwrap();

        // Counts must reflect what *would* change …
        assert_eq!(stats.epoch2_blocks_removed, 2);
        // … but the database must be untouched.
        assert_eq!(count(&conn, "block_headers"), before_headers);
        assert_eq!(count(&conn, "marf_data"), before_marf);
    }

    #[test]
    fn test_rollback_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");
        insert_epoch2_block(&conn, 3, "c");

        let stats1 = rollback_index_db(&mut conn, 1, false).unwrap();
        assert_eq!(stats1.epoch2_blocks_removed, 2);

        // Second rollback to same height must be a no-op.
        let stats2 = rollback_index_db(&mut conn, 1, false).unwrap();
        assert_eq!(stats2.epoch2_blocks_removed, 0);
        assert_eq!(count(&conn, "block_headers"), 1);
    }

    #[test]
    fn test_rollback_to_height_zero_removes_all() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");
        insert_nakamoto_block(&conn, 3, "c");

        rollback_index_db(&mut conn, 0, false).unwrap();

        assert_eq!(count(&conn, "block_headers"), 0);
        assert_eq!(count(&conn, "nakamoto_block_headers"), 0);
        assert_eq!(count(&conn, "marf_data"), 0);
    }

    #[test]
    fn test_rollback_mixed_epoch_and_nakamoto() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_epoch2_block(&conn, 1, "a");
        insert_epoch2_block(&conn, 2, "b");
        insert_nakamoto_block(&conn, 3, "c");
        insert_nakamoto_block(&conn, 4, "d");

        let stats = rollback_index_db(&mut conn, 2, false).unwrap();

        assert_eq!(stats.epoch2_blocks_removed, 0);
        assert_eq!(stats.nakamoto_blocks_removed, 2);
        assert_eq!(count(&conn, "block_headers"), 2);
        assert_eq!(count(&conn, "nakamoto_block_headers"), 0);
        assert_eq!(count(&conn, "marf_data"), 2, "MARF entries for heights 1-2 remain");
    }

    #[test]
    fn test_rollback_nakamoto_reward_sets_cleaned() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_nakamoto_block(&conn, 10, "a");
        insert_nakamoto_block(&conn, 11, "b");

        conn.execute(
            "INSERT INTO nakamoto_reward_sets(index_block_hash, reward_set) VALUES ('naka_ibh_10_a', 'rs10')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nakamoto_reward_sets(index_block_hash, reward_set) VALUES ('naka_ibh_11_b', 'rs11')",
            [],
        )
        .unwrap();

        rollback_index_db(&mut conn, 10, false).unwrap();

        assert_eq!(count(&conn, "nakamoto_reward_sets"), 1);
    }

    #[test]
    fn test_rollback_tenure_events_cleaned() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_index_db(&conn);

        insert_nakamoto_block(&conn, 10, "a");
        insert_nakamoto_block(&conn, 11, "b");

        conn.execute(
            "INSERT INTO nakamoto_tenure_events(tenure_id_consensus_hash, burn_view_consensus_hash, block_hash, block_id)
             VALUES ('ch10', 'bvch10', 'bh10', 'naka_ibh_10_a')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO nakamoto_tenure_events(tenure_id_consensus_hash, burn_view_consensus_hash, block_hash, block_id)
             VALUES ('ch11', 'bvch11', 'bh11', 'naka_ibh_11_b')",
            [],
        )
        .unwrap();

        rollback_index_db(&mut conn, 10, false).unwrap();

        assert_eq!(count(&conn, "nakamoto_tenure_events"), 1);
    }

    #[test]
    fn test_rollback_nakamoto_staging_db() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_nakamoto_staging_db(&conn);

        insert_nakamoto_staging(&conn, 5, "a");
        insert_nakamoto_staging(&conn, 6, "b");
        insert_nakamoto_staging(&conn, 7, "c");

        let stats = rollback_nakamoto_staging_db(&mut conn, 5, false).unwrap();

        assert_eq!(stats.nakamoto_staging_removed, 2);
        assert_eq!(count(&conn, "nakamoto_staging_blocks"), 1);
    }

    #[test]
    fn test_rollback_nakamoto_staging_dry_run() {
        let mut conn = Connection::open_in_memory().unwrap();
        setup_nakamoto_staging_db(&conn);

        insert_nakamoto_staging(&conn, 5, "a");
        insert_nakamoto_staging(&conn, 6, "b");

        let stats = rollback_nakamoto_staging_db(&mut conn, 5, true).unwrap();

        assert_eq!(stats.nakamoto_staging_removed, 1);
        // Database must be unchanged.
        assert_eq!(count(&conn, "nakamoto_staging_blocks"), 2);
    }
}
