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

use std::fs;
use std::path::Path;

use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::sqlite::NO_PARAMS;

use super::common::{
    classify_hint, clone_schemas_from_source, copied_rows, with_offline_write_session,
    DbSnapshotSpec, NoBind, TableCopySpec, TableCopySpecs,
};
use super::sortition::SortitionSnapshotExt;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::index::Error;
use crate::util_lib::db::{sqlite_open, Error as DBError};

/// Snapshot-only reads over a burnchain DB connection.
trait BurnchainSnapshotExt {
    /// Count the burn header hashes yielded by `canonical_sql` that have no
    /// `burnchain_db_block_headers` row. Both arguments are interpolated
    /// into SQL; pass only trusted fixed fragments.
    fn count_canonical_burn_hashes_missing_from(
        &self,
        headers_schema: &str,
        canonical_sql: &str,
    ) -> Result<u64, DBError>;
}

impl BurnchainSnapshotExt for Connection {
    fn count_canonical_burn_hashes_missing_from(
        &self,
        headers_schema: &str,
        canonical_sql: &str,
    ) -> Result<u64, DBError> {
        self.query_row(
            &format!(
                "SELECT COUNT(*) FROM ({canonical_sql}) \
                 WHERE burn_header_hash NOT IN \
                     (SELECT block_hash FROM {headers_schema}.burnchain_db_block_headers)"
            ),
            NO_PARAMS,
            |row| row.get(0),
        )
        .map_err(DBError::from)
    }
}

/// The burnchain (`burnchain.sqlite`) snapshot spec.
struct BurnchainDbSnapshotSpec;

impl DbSnapshotSpec for BurnchainDbSnapshotSpec {
    type Bind = NoBind;

    fn copy_spec_list() -> TableCopySpecs<'static, NoBind> {
        burnchain_copy_specs()
    }

    fn db_label() -> &'static str {
        "burnchain DB"
    }

    fn classify_hint() -> &'static str {
        classify_hint!(burnchain_copy_specs)
    }

    fn bind_params(&self, bind: NoBind) -> Result<Vec<Value>, Error> {
        match bind {}
    }
}

/// The canonical burn-hash set staged by [`populate_canonical_burn_hashes`],
/// as a SELECT fragment.
const CANONICAL_BURN_HASHES_SQL: &str = "SELECT burn_header_hash FROM canonical_burn_hashes";

/// The burnchain snapshot's source-schema guard (see
/// [`DbSnapshotSpec::assert_source_classified`]);
/// `test_no_unclassified_burnchain_tables` runs it against a fresh schema.
pub fn assert_source_tables_classified(src_conn: &Connection) -> Result<(), Error> {
    BurnchainDbSnapshotSpec::assert_source_classified(src_conn)
}

/// Row-count statistics returned by [`copy_burnchain_db`].
#[derive(Debug, Clone)]
pub struct BurnchainDbCopyStats {
    pub block_headers_rows: u64,
    pub block_ops_rows: u64,
    pub block_commit_metadata_rows: u64,
    pub anchor_blocks_rows: u64,
}

/// Open a read-only connection to the squashed sortition DB.
fn open_squashed_sortition_db(squashed_sortition_path: &str) -> Result<Connection, Error> {
    sqlite_open(
        squashed_sortition_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
        false,
    )
    .map_err(|e| {
        Error::CorruptionError(format!(
            "cannot open squashed sortition DB {squashed_sortition_path}: {e}"
        ))
    })
}

/// Read the canonical burn set (tip height plus all burn header hashes)
/// from a squashed sortition DB connection via [`SortitionDB`] readers, so
/// this module never queries sortition-owned tables directly.
fn read_squashed_sortition_canonical_set(
    conn: &Connection,
) -> Result<(u64, Vec<BurnchainHeaderHash>), Error> {
    // Panics if `snapshots` is empty; a squashed sortition DB always holds
    // at least the genesis snapshot.
    let tip_height = SortitionDB::get_highest_known_burn_chain_tip(conn)
        .map_err(|e| Error::CorruptionError(format!("cannot read squashed sortition tip: {e}")))?
        .block_height;
    let hashes = conn.get_all_snapshot_burn_header_hashes().map_err(|e| {
        Error::CorruptionError(format!("cannot read squashed sortition snapshots: {e}"))
    })?;
    Ok((tip_height, hashes))
}

/// Build a temp table of the canonical burn header hashes read from the
/// squashed sortition DB.
fn populate_canonical_burn_hashes(
    conn: &Connection,
    canonical_hashes: &[BurnchainHeaderHash],
) -> Result<(), Error> {
    conn.execute_batch(
        "CREATE TEMP TABLE canonical_burn_hashes (burn_header_hash TEXT PRIMARY KEY)",
    )?;
    // A savepoint batches the inserts whether or not the session already
    // holds an open transaction (the copy session does, and
    // autocommit-per-row would be slow).
    conn.execute_batch("SAVEPOINT canonical_burn_hashes")?;
    let mut stmt =
        conn.prepare("INSERT INTO canonical_burn_hashes (burn_header_hash) VALUES (?1)")?;
    for hash in canonical_hashes {
        stmt.execute([hash.to_string()])?;
    }
    drop(stmt);
    conn.execute_batch("RELEASE canonical_burn_hashes")?;
    Ok(())
}

/// Copy canonical rows from source `burnchain.sqlite` into a new destination,
/// using the squashed sortition DB as the authoritative canonical set.
///
/// Returns an error if a required source is missing or if the destination
/// already exists.
///
/// Preserves dependency-ordered copy:
/// 1. Canonical headers and ops (burn_header_hash filtered)
/// 2. Canonical block_commit_metadata
/// 3. anchor_blocks derived from copied commit metadata
pub fn copy_burnchain_db(
    src_burnchain_db_path: &str,
    dst_burnchain_db_path: &str,
    squashed_sortition_path: &str,
    expected_burn_height: u64,
) -> Result<BurnchainDbCopyStats, Error> {
    if Path::new(dst_burnchain_db_path).exists() {
        return Err(Error::DestinationExists(dst_burnchain_db_path.to_string()));
    }

    // Reject an unrecognized source schema before any destination work.
    let src_conn = sqlite_open(
        src_burnchain_db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
        false,
    )?;
    assert_source_tables_classified(&src_conn)?;
    drop(src_conn);

    if let Some(parent) = Path::new(dst_burnchain_db_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let sort_conn = open_squashed_sortition_db(squashed_sortition_path)?;
    let (sortition_tip_height, canonical_hashes) =
        read_squashed_sortition_canonical_set(&sort_conn)?;
    drop(sort_conn);
    assert_sortition_tip_height(sortition_tip_height, expected_burn_height)?;

    with_offline_write_session(
        dst_burnchain_db_path,
        &[("src", src_burnchain_db_path)],
        // FK off must run before BEGIN IMMEDIATE; per-connection only.
        "PRAGMA foreign_keys = OFF;",
        |conn| copy_burnchain_db_inner(conn, &canonical_hashes),
    )
}

/// Build the copy specs for the burnchain DB, in dependency order: canonical
/// headers and ops (burn-hash filtered), commit metadata, and `anchor_blocks`
/// derived from the copied commit metadata. `overrides` is schema-only:
/// reward-cycle affirmation-map overrides are never read or written by any
/// production path, so its schema is cloned for fidelity but no rows are copied.
pub fn burnchain_copy_specs() -> TableCopySpecs<'static, NoBind> {
    static SPECS: &[TableCopySpec<NoBind>] = &[
        TableCopySpec::sql("db_config", "SELECT * FROM src.db_config"),
        TableCopySpec::sql(
            "burnchain_db_block_headers",
            "SELECT * FROM src.burnchain_db_block_headers \
                 WHERE block_hash IN (SELECT burn_header_hash FROM canonical_burn_hashes)",
        ),
        TableCopySpec::sql(
            "burnchain_db_block_ops",
            "SELECT * FROM src.burnchain_db_block_ops \
                 WHERE block_hash IN (SELECT burn_header_hash FROM canonical_burn_hashes)",
        ),
        TableCopySpec::sql(
            "block_commit_metadata",
            "SELECT * FROM src.block_commit_metadata \
                 WHERE burn_block_hash IN (SELECT burn_header_hash FROM canonical_burn_hashes)",
        ),
        TableCopySpec::sql(
            "anchor_blocks",
            "SELECT * FROM src.anchor_blocks \
                 WHERE reward_cycle IN ( \
                     SELECT DISTINCT anchor_block FROM block_commit_metadata \
                     WHERE anchor_block IS NOT NULL \
                 )",
        ),
        TableCopySpec::schema_only("overrides"),
    ];
    TableCopySpecs::new(SPECS)
}

/// Consistency assertion: the squashed sortition DB's tip must match the
/// caller's expected burn height.
fn assert_sortition_tip_height(
    sortition_tip_height: u64,
    expected_burn_height: u64,
) -> Result<(), Error> {
    if sortition_tip_height != expected_burn_height {
        return Err(Error::CorruptionError(format!(
            "Sortition tip height mismatch: expected {expected_burn_height}, got {sortition_tip_height}"
        )));
    }
    Ok(())
}

fn copy_burnchain_db_inner(
    conn: &Connection,
    canonical_hashes: &[BurnchainHeaderHash],
) -> Result<BurnchainDbCopyStats, Error> {
    clone_schemas_from_source(conn, &BurnchainDbSnapshotSpec::table_names())?;

    populate_canonical_burn_hashes(conn, canonical_hashes)?;

    // Completeness assertion: every canonical burn hash must exist in source.
    let missing_count = conn
        .count_canonical_burn_hashes_missing_from("src", CANONICAL_BURN_HASHES_SQL)
        .map_err(|e| Error::CorruptionError(format!("cannot check canonical burn hashes: {e}")))?;
    if missing_count > 0 {
        return Err(Error::CorruptionError(format!(
            "{missing_count} canonical burn hashes missing from source burnchain DB"
        )));
    }

    let results = BurnchainDbSnapshotSpec.run_copy(conn)?;

    let stats = BurnchainDbCopyStats {
        block_headers_rows: copied_rows(&results, "burnchain_db_block_headers"),
        block_ops_rows: copied_rows(&results, "burnchain_db_block_ops"),
        block_commit_metadata_rows: copied_rows(&results, "block_commit_metadata"),
        anchor_blocks_rows: copied_rows(&results, "anchor_blocks"),
    };
    info!(
        "Copied burnchain DB";
        "block_headers_rows" => stats.block_headers_rows,
        "block_ops_rows" => stats.block_ops_rows,
        "block_commit_metadata_rows" => stats.block_commit_metadata_rows,
        "anchor_blocks_rows" => stats.anchor_blocks_rows
    );
    Ok(stats)
}
