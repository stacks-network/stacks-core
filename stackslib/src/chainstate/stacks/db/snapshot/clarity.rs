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

use clarity::vm::database::clarity_store::make_contract_hash_key;
use clarity::vm::database::{SqliteConnection, DATA_TABLE_NAME, METADATA_TABLE_NAME};
use clarity::vm::types::QualifiedContractIdentifier;
use rusqlite::{Connection, OpenFlags};
use stacks_common::types::chainstate::StacksBlockId;

use super::common::{
    assert_source_schema, clone_schemas_from_source, with_indexes_dropped,
    with_offline_write_session, MARF_INFRA_TABLES,
};
use super::fork_storage::{collect_leaf_value_hashes, copy_leaf_referenced_rows};
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection as _, MARF};
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::chainstate::stacks::index::Error;
use crate::util_lib::db::sqlite_open;

/// Clarity side-storage tables copied by [`copy_clarity_side_tables`].
pub(super) const CLARITY_SIDE_TABLES: &[&str] = &[DATA_TABLE_NAME, METADATA_TABLE_NAME];

/// Every table the Clarity snapshot accounts for: side-storage copied by
/// [`copy_clarity_side_tables`] ([`CLARITY_SIDE_TABLES`]) or owned by the MARF
/// trie itself, recreated by [`MARF::squash_to_path`] ([`MARF_INFRA_TABLES`]).
fn known_clarity_tables() -> Vec<&'static str> {
    CLARITY_SIDE_TABLES
        .iter()
        .chain(MARF_INFRA_TABLES)
        .copied()
        .collect()
}

/// The clarity snapshot's source-schema guard (see [`assert_source_schema`]);
/// `test_no_unclassified_clarity_source_tables` runs it against a fresh schema.
pub(super) fn assert_source_tables_classified(src_conn: &Connection) -> Result<(), Error> {
    assert_source_schema(
        src_conn,
        &known_clarity_tables(),
        "clarity DB",
        "CLARITY_SIDE_TABLES (to copy) in snapshot/clarity.rs",
    )
}

/// Copy Clarity side-storage tables (`data_table`, `metadata_table`) from a
/// source MARF database to a squashed MARF database.
///
/// **Must be called after [`MARF::squash_to_path`]** has created the squashed
/// trie in `dst_db_path`.
///
/// This function:
/// 1. Reads the squashed trie to determine which side-storage rows are still reachable.
/// 2. Attaches the source database.
/// 3. Clones the side-table schemas from the source and copies only the
///    required rows.
pub fn copy_clarity_side_tables(
    src_db_path: &str,
    dst_db_path: &str,
) -> Result<ClaritySideTableStats, Error> {
    let total_start = Instant::now();

    // Reject an unrecognized source schema before any destination work.
    let src_conn = open_readonly_clarity_db(src_db_path)?;
    assert_source_tables_classified(&src_conn)?;

    // Walk the squashed trie before opening dst for writes. we need
    // the readonly MARF view, and `marf_sqlite_open` would fight the
    // writer's lock on dst.
    let t = Instant::now();
    let (squashed_tip, needed_keys) = collect_leaf_value_hashes::<StacksBlockId>(dst_db_path)?;
    info!(
        "[clarity] collect_leaf_value_hashes: {} keys in {:?}",
        needed_keys.len(),
        t.elapsed()
    );

    let required_contract_ids = resolve_required_contracts(src_db_path, &squashed_tip)?;

    let stats = with_offline_write_session(
        dst_db_path,
        &[("src", src_db_path)],
        "",
        |conn| -> Result<ClaritySideTableStats, Error> {
            clone_schemas_from_source(conn, CLARITY_SIDE_TABLES)?;

            let t = Instant::now();
            let src_data_count = SqliteConnection::count_data_rows(&src_conn)?;
            let needed_count = needed_keys.len() as u64;
            let pruned_count = src_data_count.saturating_sub(needed_count);
            info!(
                "[clarity] src.data_table = {src_data_count}, pruning {pruned_count} \
                 (keep {needed_count}) in {:?}",
                t.elapsed()
            );

            // data_table is content-addressed (key = hex MARFValue), like
            // the index `__fork_storage`, so it shares the same stream-filter.
            let data_rows = copy_leaf_referenced_rows(conn, DATA_TABLE_NAME, "key", &needed_keys)?;

            let t = Instant::now();
            let (metadata_scanned, metadata_rows) =
                with_indexes_dropped(conn, METADATA_TABLE_NAME, |conn| {
                    copy_required_metadata_rows(&src_conn, conn, &required_contract_ids)
                })?;
            info!(
                "[clarity] metadata_table scan+filter: scanned {metadata_scanned}, \
                 inserted {metadata_rows} in {:?}",
                t.elapsed()
            );

            Ok(ClaritySideTableStats {
                data_table_rows: data_rows,
                metadata_table_rows: metadata_rows,
            })
        },
    )?;

    info!("[clarity] total {:?}", total_start.elapsed());
    Ok(stats)
}

/// Open a read-only connection to the Clarity side-storage DB at `path`.
fn open_readonly_clarity_db(path: &str) -> Result<Connection, Error> {
    sqlite_open(path, OpenFlags::SQLITE_OPEN_READ_ONLY, false).map_err(Error::SQLError)
}

/// Open the MARF at `db_path` strictly read-only: contract probes must
/// never take a write lock (the source may be a live node's file).
fn open_readonly_marf(db_path: &str) -> Result<MARF<StacksBlockId>, Error> {
    // Clarity MARF always stores external blobs, whether archival or squashed.
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
    let storage = TrieFileStorage::open_readonly(db_path, open_opts)?;
    Ok(MARF::from_storage(storage))
}

/// Stream the source `metadata_table` into the destination, keeping only rows
/// whose contract id is in `required`. Every key must be in the `clr-meta::`
/// format (the only format any writer produces); a key that doesn't parse is
/// treated as corruption. Returns `(scanned, copied)` row counts.
fn copy_required_metadata_rows(
    src_conn: &Connection,
    dst_conn: &Connection,
    required: &HashSet<String>,
) -> Result<(u64, u64), Error> {
    let mut scanned: u64 = 0;
    let mut copied: u64 = 0;
    SqliteConnection::visit_metadata_rows(src_conn, |row| {
        scanned += 1;
        let Some((contract_id, _meta_key)) = SqliteConnection::parse_metadata_key(row.key) else {
            return Err(Error::CorruptionError(format!(
                "metadata_table key is not in clr-meta:: format: {}",
                row.key
            )));
        };
        if !required.contains(contract_id) {
            return Ok(());
        }
        SqliteConnection::insert_metadata_row(dst_conn, row)?;
        copied += 1;
        Ok(())
    })?;
    Ok((scanned, copied))
}

/// The distinct contract ids appearing in `metadata_table` keys on `conn`,
/// in the visitor's ascending key order. Every key must be in the
/// `clr-meta::` format; a key that doesn't parse is corruption.
fn scan_metadata_contract_ids(conn: &Connection) -> Result<Vec<String>, Error> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut ordered: Vec<String> = Vec::new();
    SqliteConnection::visit_metadata_keys(conn, |key| {
        let Some((contract_id, _meta_key)) = SqliteConnection::parse_metadata_key(key) else {
            return Err(Error::CorruptionError(format!(
                "metadata_table key is not in clr-meta:: format: {key}"
            )));
        };
        if seen.insert(contract_id.to_string()) {
            ordered.push(contract_id.to_string());
        }
        Ok(())
    })?;
    Ok(ordered)
}

/// Probe the MARF at `db_path` for each contract's hash key at `tip`; the
/// contracts still present in the trie are the ones whose metadata rows
/// must be retained.
fn filter_required_contracts(
    db_path: &str,
    tip: &StacksBlockId,
    contract_ids: &[String],
) -> Result<HashSet<String>, Error> {
    let mut marf = open_readonly_marf(db_path)?;
    let mut required: HashSet<String> = HashSet::new();
    for contract_id in contract_ids {
        let contract = QualifiedContractIdentifier::parse(contract_id).map_err(|e| {
            Error::CorruptionError(format!(
                "Failed to parse contract identifier '{contract_id}': {e:?}"
            ))
        })?;
        let key = make_contract_hash_key(&contract);
        if marf.get(tip, &key)?.is_some() {
            required.insert(contract_id.clone());
        }
    }
    Ok(required)
}

/// Scan `src.metadata_table` for the set of contract ids that appear,
/// then probe the squashed trie to find which are still required.
fn resolve_required_contracts(
    src_db_path: &str,
    squashed_tip: &StacksBlockId,
) -> Result<HashSet<String>, Error> {
    let t = Instant::now();
    let src_conn = open_readonly_clarity_db(src_db_path)?;
    let contract_ids = scan_metadata_contract_ids(&src_conn)?;
    info!(
        "[clarity] contract ids in src.metadata_table: {} unique in {:?}",
        contract_ids.len(),
        t.elapsed()
    );

    let t = Instant::now();
    let required_contract_ids =
        filter_required_contracts(src_db_path, squashed_tip, &contract_ids)?;
    info!(
        "[clarity] MARF.get per contract: {} required of {} in {:?}",
        required_contract_ids.len(),
        contract_ids.len(),
        t.elapsed()
    );

    Ok(required_contract_ids)
}

/// Row-count statistics returned by [`copy_clarity_side_tables`].
#[derive(Debug, Clone)]
pub struct ClaritySideTableStats {
    /// Number of rows copied into `data_table`.
    pub data_table_rows: u64,
    /// Number of rows copied into `metadata_table`.
    pub metadata_table_rows: u64,
}
