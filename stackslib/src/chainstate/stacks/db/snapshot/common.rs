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

use rusqlite::{params, Connection};
use stacks_common::util::hash::to_hex;

use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::chainstate::stacks::index::{trie_sql, Error, MarfTrieId};

/// A spec for copying a single table from the ATTACHed `src` database.
///
/// The `source_sql` is the exact `SELECT` used to filter source rows.
/// Copy uses plain `INSERT ... SELECT` (no `OR IGNORE`) so that unexpected
/// pre-population in the destination fails loudly.
pub struct TableCopySpec {
    pub table: &'static str,
    /// The exact SELECT for the source side, e.g.
    /// `"SELECT * FROM src.snapshots WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)"`.
    pub source_sql: String,
}

/// Clone table and index schemas from the source DB (via `sqlite_master`) into the
/// destination connection. This avoids duplicating any CREATE TABLE / ALTER TABLE /
/// CREATE INDEX statements and is always in sync with whatever migration version the
/// source is at.
///
/// Expects the source DB to be ATTACHed as `src`.
pub fn clone_schemas_from_source(conn: &Connection, tables: &[&str]) -> Result<(), Error> {
    let mut stmts: Vec<String> = Vec::new();

    for table in tables {
        let sql: Option<String> = conn
            .query_row(
                "SELECT sql FROM src.sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .ok();

        if let Some(create_sql) = sql {
            let safe_sql = if create_sql.contains("IF NOT EXISTS") {
                create_sql
            } else {
                create_sql.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1)
            };
            stmts.push(safe_sql);
        }

        let mut idx_stmt = conn
            .prepare("SELECT sql FROM src.sqlite_master WHERE type='index' AND tbl_name=?1 AND sql IS NOT NULL")
            .map_err(Error::SQLError)?;
        let idx_rows = idx_stmt
            .query_map(params![table], |row| row.get::<_, String>(0))
            .map_err(Error::SQLError)?;
        for idx_sql in idx_rows {
            let idx_sql = idx_sql.map_err(Error::SQLError)?;
            let safe_sql = if idx_sql.contains("IF NOT EXISTS") {
                idx_sql
            } else {
                idx_sql.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1)
            };
            stmts.push(safe_sql);
        }
    }

    for stmt in &stmts {
        conn.execute_batch(stmt).map_err(Error::SQLError)?;
    }

    Ok(())
}

/// Clone schemas only for tables that exist in the source DB.
/// Returns the list of tables that were actually cloned.
pub fn clone_optional_schemas_from_source(
    conn: &Connection,
    tables: &[&str],
) -> Result<Vec<String>, Error> {
    let mut present = Vec::new();
    for table in tables {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM src.sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(Error::SQLError)?;
        if exists {
            clone_schemas_from_source(conn, &[table])?;
            present.push(table.to_string());
        }
    }
    Ok(present)
}

/// Check if a table exists in the given schema prefix (empty for main, "src" for attached).
pub fn table_exists(conn: &Connection, schema: &str, table: &str) -> bool {
    let master = if schema.is_empty() {
        "sqlite_master".to_string()
    } else {
        format!("{schema}.sqlite_master")
    };
    conn.query_row(
        &format!("SELECT COUNT(*) > 0 FROM {master} WHERE type='table' AND name=?1"),
        params![table],
        |row| row.get(0),
    )
    .unwrap_or(false)
}

/// Check bidirectional full-row EXCEPT equality.
/// Returns true if the two result sets are identical.
pub fn full_row_except_match(conn: &Connection, dst_sql: &str, src_sql: &str) -> bool {
    let extra_in_dst: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM ({dst_sql} EXCEPT {src_sql})"),
            [],
            |row| row.get(0),
        )
        .unwrap_or(1);
    let extra_in_src: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM ({src_sql} EXCEPT {dst_sql})"),
            [],
            |row| row.get(0),
        )
        .unwrap_or(1);
    extra_in_dst == 0 && extra_in_src == 0
}

/// Execute a slice of copy specs inside the current transaction.
/// Returns a vec of (table_name, rows_copied).
pub fn execute_copy_specs(
    conn: &Connection,
    specs: &[TableCopySpec],
) -> Result<Vec<(&'static str, u64)>, Error> {
    let mut results = Vec::with_capacity(specs.len());
    for spec in specs {
        let t = Instant::now();
        let sql = format!("INSERT INTO {} {}", spec.table, spec.source_sql);
        let rows = conn.execute(&sql, []).map_err(Error::SQLError)? as u64;
        info!(
            "  copy: {} ({} rows) in {:?}",
            spec.table,
            rows,
            t.elapsed()
        );
        results.push((spec.table, rows));
    }
    Ok(results)
}

/// Check an optional table's match status.
/// Returns None if absent in both, Some(false) if present in one but not other,
/// Some(true/false) from full-row EXCEPT if present in both.
pub fn check_optional_table_match(
    conn: &Connection,
    table: &str,
    src_filter: Option<&str>,
) -> Option<bool> {
    let in_dst = table_exists(conn, "", table);
    let in_src = table_exists(conn, "src", table);

    match (in_dst, in_src) {
        (false, false) => None,
        (true, false) | (false, true) => Some(false),
        (true, true) => {
            let src_sql = match src_filter {
                Some(filter) => format!("SELECT * FROM src.{table} {filter}"),
                None => format!("SELECT * FROM src.{table}"),
            };
            Some(full_row_except_match(
                conn,
                &format!("SELECT * FROM {table}"),
                &src_sql,
            ))
        }
    }
}

/// Collect the hex-encoded `MARFValue` of every leaf in the squashed trie.
///
/// Opens the MARF at `db_path` read-only, resolves the tip, and walks the
/// trie via `for_each_leaf`.  Auto-detects external blobs.
///
/// Returns `(tip_block_hash, leaf_value_hashes)`.
pub fn collect_leaf_value_hashes<T: MarfTrieId>(
    db_path: &str,
) -> Result<(T, HashSet<String>), Error> {
    let external_blobs = std::path::Path::new(&format!("{db_path}.blobs")).exists();
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", external_blobs);
    let storage = TrieFileStorage::open_readonly(db_path, open_opts)?;
    let mut marf = MARF::<T>::from_storage(storage);
    let tip = trie_sql::get_latest_confirmed_block_hash::<T>(marf.sqlite_conn())?;

    let mut hashes = HashSet::new();
    marf.with_conn(|conn| {
        MARF::for_each_leaf(conn, &tip, |_hash, value| {
            hashes.insert(to_hex(&value.to_vec()));
            Ok(())
        })
    })?;

    Ok((tip, hashes))
}

/// Copy only the `__fork_storage` rows that are referenced by leaf nodes
/// in the squashed MARF trie. Non-canonical entries from forks are excluded.
///
/// Opens the squashed MARF read-only and walks the trie via `for_each_leaf`
/// to collect canonical leaf value hashes, then copies only the matching
/// `__fork_storage` rows from the source.
///
/// Falls back to a full copy if `marf_data` is absent (e.g. in test
/// fixtures that don't go through `squash_to_path`).
///
/// Returns the number of rows copied.
pub fn copy_canonical_fork_storage<T: MarfTrieId>(
    conn: &Connection,
    dst_path: &str,
) -> Result<u64, Error> {
    // Check if the source even has __fork_storage (test fixtures may not).
    let src_has_table: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM src.sqlite_master WHERE type='table' AND name='__fork_storage'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !src_has_table {
        info!("  copy_canonical_fork_storage: source has no __fork_storage, skipping");
        return Ok(0);
    }

    // Ensure the destination table exists (clone schema from source).
    clone_schemas_from_source(conn, &["__fork_storage"])?;

    // If marf_data doesn't exist, fall back to full copy.
    let has_marf_data: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='marf_data'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !has_marf_data {
        let rows = conn
            .execute(
                "INSERT OR REPLACE INTO __fork_storage SELECT * FROM src.__fork_storage",
                [],
            )
            .map_err(Error::SQLError)? as u64;
        info!("  copy_canonical_fork_storage: no marf_data table, full copy ({rows} rows)");
        return Ok(rows);
    }

    let t = Instant::now();

    let (_tip, leaf_hashes) = collect_leaf_value_hashes::<T>(dst_path)?;
    let insert_count = leaf_hashes.len() as u64;

    // Build a temp table of canonical leaf value hashes.
    conn.execute_batch("CREATE TEMP TABLE __squash_leaf_values (value_hash TEXT PRIMARY KEY)")
        .map_err(Error::SQLError)?;

    {
        let mut stmt = conn
            .prepare("INSERT OR IGNORE INTO __squash_leaf_values (value_hash) VALUES (?1)")
            .map_err(Error::SQLError)?;
        for hash in &leaf_hashes {
            stmt.execute(params![hash]).map_err(Error::SQLError)?;
        }
    }
    drop(leaf_hashes);

    info!(
        "  copy_canonical_fork_storage: extracted {insert_count} leaf hashes in {:?}",
        t.elapsed()
    );

    // Copy only the referenced rows.
    let t2 = Instant::now();
    let rows = conn
        .execute(
            "INSERT OR REPLACE INTO __fork_storage \
             SELECT f.* FROM src.__fork_storage f \
             INNER JOIN __squash_leaf_values lv ON f.value_hash = lv.value_hash",
            [],
        )
        .map_err(Error::SQLError)? as u64;

    conn.execute_batch("DROP TABLE IF EXISTS __squash_leaf_values")
        .map_err(Error::SQLError)?;

    info!(
        "  copy_canonical_fork_storage: copied {rows} rows (from {insert_count} leaves) in {:?}",
        t2.elapsed()
    );

    Ok(rows)
}

pub fn checkpoint_destination_wal(conn: &Connection) -> Result<(), Error> {
    let _: (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(Error::SQLError)?;
    Ok(())
}
