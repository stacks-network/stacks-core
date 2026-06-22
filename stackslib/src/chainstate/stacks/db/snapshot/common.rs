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

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rusqlite::{params, Connection, OptionalExtension};

use crate::chainstate::stacks::index::Error;

/// A spec for copying a single table from the ATTACHed `src` database.
///
/// The `source_sql` is the exact `SELECT` used to filter source rows.
/// Copy uses plain `INSERT ... SELECT` (no `OR IGNORE`/`OR REPLACE`) so that
/// unexpected pre-population in the destination fails loudly.
pub struct TableCopySpec {
    pub table: &'static str,
    /// The exact SELECT for the source side, e.g.
    /// `"SELECT * FROM src.snapshots WHERE sortition_id IN (SELECT sortition_id FROM canonical_sortitions)"`.
    pub source_sql: String,
}

/// Clone table and index schemas from the source DB (via `sqlite_master`)
/// into the destination connection. **Strict**: every requested table
/// must exist in `src`, otherwise returns `CorruptionError`. This
/// avoids duplicating CREATE TABLE / ALTER TABLE / CREATE INDEX
/// statements and stays in sync with whatever migration version the
/// source is at.
///
/// Expects the source DB to be ATTACHed as `src`.
pub fn clone_schemas_from_source(conn: &Connection, tables: &[&str]) -> Result<(), Error> {
    let mut stmts: Vec<String> = Vec::new();

    for table in tables {
        let create_sql: String = conn
            .query_row(
                "SELECT sql FROM src.sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .optional()
            .map_err(Error::SQLError)?
            .ok_or_else(|| {
                Error::CorruptionError(format!(
                    "src is missing required table `{table}`; expected on any chainstate \
                     that ran the matching migration"
                ))
            })?;

        // sqlite_master stores the normalized statement (any `IF NOT
        // EXISTS` is stripped), so add the guard back.
        stmts.push(create_sql.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1));

        let mut idx_stmt = conn
            .prepare("SELECT sql FROM src.sqlite_master WHERE type='index' AND tbl_name=?1 AND sql IS NOT NULL")
            .map_err(Error::SQLError)?;
        let idx_rows = idx_stmt
            .query_map(params![table], |row| row.get::<_, String>(0))
            .map_err(Error::SQLError)?;
        for idx_sql in idx_rows {
            let idx_sql = idx_sql.map_err(Error::SQLError)?;
            stmts.push(idx_sql.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1));
        }
    }

    for stmt in &stmts {
        conn.execute_batch(stmt).map_err(Error::SQLError)?;
    }

    Ok(())
}

/// Execute copy specs inside the current transaction, dropping each
/// table's secondary indexes around the bulk INSERT and rebuilding
/// them once at the end (one rebuild vs N per-row B-tree updates).
/// `sqlite_autoindex_*` have `sql IS NULL` and are skipped.
///
/// Returns a vec of (table_name, rows_copied).
pub fn execute_copy_specs(
    conn: &Connection,
    specs: &[TableCopySpec],
) -> Result<Vec<(&'static str, u64)>, Error> {
    let mut results = Vec::with_capacity(specs.len());
    for spec in specs {
        let t_total = Instant::now();
        let rows = with_indexes_dropped(conn, spec.table, |conn| {
            let sql = format!("INSERT INTO {} {}", spec.table, spec.source_sql);
            Ok(conn.execute(&sql, []).map_err(Error::SQLError)? as u64)
        })?;
        info!(
            "[copy] {} ({} rows) in {:?}",
            spec.table,
            rows,
            t_total.elapsed(),
        );
        results.push((spec.table, rows));
    }
    Ok(results)
}

/// Look up the rows-copied count for `table` in [`execute_copy_specs`]
/// results. Panics if `table` had no spec: that is a bug in the caller's
/// spec list, not a data error.
pub fn copied_rows(results: &[(&'static str, u64)], table: &str) -> u64 {
    results
        .iter()
        .find(|(t, _)| *t == table)
        .map(|(_, rows)| *rows)
        .unwrap_or_else(|| panic!("BUG: no copy-spec result for `{table}`"))
}

/// Collect every user-defined index on `main.table` along with its
/// CREATE statement so the caller can drop and later rebuild them.
/// Excludes `sqlite_autoindex_*` (those have `sql IS NULL` and are
/// recreated implicitly with the table).
pub(crate) fn collect_user_indexes(
    conn: &Connection,
    table: &str,
) -> Result<Vec<(String, String)>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT name, sql FROM sqlite_master \
             WHERE type='index' AND tbl_name=?1 AND sql IS NOT NULL",
        )
        .map_err(Error::SQLError)?;
    let rows = stmt
        .query_map(params![table], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(Error::SQLError)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Error::SQLError)?;
    Ok(rows)
}

/// Chars to percent-encode inside a SQLite `file:<path>?mode=ro` URI.
/// Encodes URI-structural chars and parser-hostile bytes; leaves `/`
/// and `:` intact so absolute Unix paths and Windows drive letters
/// round-trip cleanly. Non-ASCII bytes are encoded by
/// `utf8_percent_encode` regardless of the set.
const SQLITE_URI_PATH_RESERVED: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn percent_encode_path(path: &str) -> String {
    utf8_percent_encode(path, SQLITE_URI_PATH_RESERVED).to_string()
}

/// Open `dst_path` (created if missing), ATTACH each source read-only
/// via `file:<path>?mode=ro` URI, run `body` inside `BEGIN IMMEDIATE`,
/// then `COMMIT`, `DETACH`, and restore `journal_mode = WAL` so
/// downstream readers (`marf_sqlite_open`) keep working.
///
/// Body runs with an aggressive offline pragma profile
/// (`journal_mode = OFF`, `synchronous = OFF`, `locking_mode =
/// EXCLUSIVE`, `temp_store = MEMORY`, 4 GiB mmap, 256 MiB cache), all
/// `main.`-scoped. Read-only ATTACH keeps `BEGIN IMMEDIATE` from
/// locking the source files, so a live node sharing them is not blocked.
///
/// On error, propagate without rollback - the caller discards
/// `dst_path` (marf-squash restarts on any failure).
///
/// `pre_begin_pragmas` runs before ATTACH/BEGIN - use it for pragmas
/// SQLite ignores mid-transaction (e.g. `foreign_keys`).
///
/// `alias` is interpolated into SQL; pass only trusted fixed
/// identifiers (current callers use literals).
pub fn with_offline_write_session<F, T>(
    dst_path: &str,
    attachments: &[(&'static str, &str)],
    pre_begin_pragmas: &str,
    body: F,
) -> Result<T, Error>
where
    F: FnOnce(&Connection) -> Result<T, Error>,
{
    let conn = Connection::open(dst_path).map_err(Error::SQLError)?;
    // `main.`-scoped so the aggressive profile applies only to dst.
    // Safe given the offline + wipe-on-failure precondition (no
    // rollback recovery needed).
    conn.execute_batch(
        "PRAGMA main.journal_mode = OFF; \
         PRAGMA main.synchronous = OFF; \
         PRAGMA main.mmap_size = 4294967296; \
         PRAGMA main.temp_store = MEMORY; \
         PRAGMA main.locking_mode = EXCLUSIVE; \
         PRAGMA main.cache_size = -262144;",
    )
    .map_err(Error::SQLError)?;
    if !pre_begin_pragmas.is_empty() {
        conn.execute_batch(pre_begin_pragmas)
            .map_err(Error::SQLError)?;
    }

    for (alias, path) in attachments {
        let uri = format!("file:{}?mode=ro", percent_encode_path(path));
        conn.execute(&format!("ATTACH DATABASE ?1 AS {alias}"), params![uri])
            .map_err(Error::SQLError)?;
    }

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(Error::SQLError)?;

    let value = body(&conn)?;

    conn.execute_batch("COMMIT").map_err(Error::SQLError)?;
    for (alias, _) in attachments.iter().rev() {
        conn.execute_batch(&format!("DETACH DATABASE {alias}"))
            .map_err(Error::SQLError)?;
    }
    // Restore WAL on disk so downstream readonly openers (which
    // force-set WAL via marf_sqlite_open) don't fail SQLITE_READONLY.
    conn.execute_batch("PRAGMA main.journal_mode = WAL;")
        .map_err(Error::SQLError)?;
    Ok(value)
}

/// Drop user-defined indexes on `main.table` while `body` bulk-loads
/// it, then recreate them on `Ok` (one rebuild vs N per-row B-tree
/// updates). On `Err`, indexes are not recreated.
pub fn with_indexes_dropped<F, T>(conn: &Connection, table: &str, body: F) -> Result<T, Error>
where
    F: FnOnce(&Connection) -> Result<T, Error>,
{
    let saved = collect_user_indexes(conn, table)?;
    for (name, _) in &saved {
        conn.execute(&format!("DROP INDEX IF EXISTS \"{name}\""), [])
            .map_err(Error::SQLError)?;
    }
    let value = body(conn)?;
    for (_, create_sql) in &saved {
        conn.execute(create_sql, []).map_err(Error::SQLError)?;
    }
    Ok(value)
}

/// The user tables in `conn`'s `main` schema not in `known`. Each squash copy
/// module lists the tables it handles; both the runtime source-schema check and
/// the drift-guard tests assert this is empty, so a new migration can't silently
/// drop a table from the copy.
pub(super) fn unclassified_tables(conn: &Connection, known: &[&str]) -> Vec<String> {
    let known: std::collections::HashSet<&str> = known.iter().copied().collect();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .expect("query sqlite_master");
    let tables: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("read table names")
        .map(Result::unwrap)
        .collect();
    tables
        .into_iter()
        .filter(|t| !known.contains(t.as_str()))
        .collect()
}

/// Reject snapshotting a source DB whose schema has tables `known` doesn't
/// cover: the snapshot would omit them and a node booting from it would recreate
/// them empty. Runs on the real source DB, so it also catches tables that reached
/// disk outside the tool's migration path (a newer node, an ad-hoc `CREATE
/// TABLE`) that a compile-time list check would miss. `db_label` names the DB in
/// the error; `classify_hint` says where to classify a newly added table.
pub(super) fn assert_source_schema(
    src_conn: &Connection,
    known: &[&str],
    db_label: &str,
    classify_hint: &str,
) -> Result<(), Error> {
    let unknown = unclassified_tables(src_conn, known);
    if !unknown.is_empty() {
        return Err(Error::CorruptionError(format!(
            "source {db_label} has unrecognized table(s) {unknown:?}: the snapshot would omit them \
             and a node booting from it would recreate them empty. The tool may be older than the \
             DB's schema (upgrade it to match the node); if this is a newly added table, classify \
             each in {classify_hint}"
        )));
    }
    Ok(())
}

/// MARF / Clarity-store infrastructure tables. They live in every MARF-backed
/// source DB and are created by the squash engine (`MARF::squash_to_path`) or
/// store init — not by a side-table copy — so the drift guards treat them as
/// already handled.
pub(super) const MARF_INFRA_TABLES: &[&str] = &[
    "marf_data",
    "__fork_storage",
    "marf_squash_info",
    "marf_squashed_blocks",
    "mined_blocks",
    "block_extension_locks",
    "schema_version",
    "migrated_version",
];

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::percent_encode_path;

    /// Representative paths survive the `file:` URI percent-encoding used
    /// by [`super::with_offline_write_session`]'s read-only ATTACH.
    #[rstest]
    #[case::unix_absolute("/tmp/marf-squash/index.sqlite", "/tmp/marf-squash/index.sqlite")]
    #[case::windows_drive_letter("C:/Users/test/index.sqlite", "C:/Users/test/index.sqlite")]
    #[case::unreserved_chars_pass_through("/abc-DEF_123.~", "/abc-DEF_123.~")]
    #[case::space_and_uri_structurals("/tmp/has space/file?x#y", "/tmp/has%20space/file%3Fx%23y")]
    #[case::percent_literal_encoded("/tmp/100%/x", "/tmp/100%25/x")]
    // `é` is U+00E9 = 0xC3 0xA9 in UTF-8; non-ASCII bytes always encode.
    #[case::non_ascii_as_utf8_bytes("/tmp/café", "/tmp/caf%C3%A9")]
    fn percent_encode_path_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(percent_encode_path(input), expected);
    }
}
