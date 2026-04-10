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

use clarity::vm::database::clarity_store::make_contract_hash_key;
use clarity::vm::database::SqliteConnection;
use rusqlite::Connection;
use stacks_common::types::chainstate::StacksBlockId;

use crate::chainstate::stacks::db::snapshot::common::{
    checkpoint_destination_wal, collect_leaf_value_hashes,
};
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::{trie_sql, Error};

/// Copy Clarity side-storage tables (`data_table`, `metadata_table`) from a
/// source MARF database to a squashed MARF database.
///
/// **Must be called after [`MARF::squash_to_path`]** has created the squashed
/// trie in `dst_db_path`.
///
/// This function:
/// 1. Initialises the Clarity schema on the destination (tables + indices + WAL).
/// 2. Attaches the source database.
/// 3. Reads the squashed trie to determine which side-storage rows are still reachable.
/// 4. Copies only the required rows in a single transaction.
pub fn copy_clarity_side_tables(
    src_db_path: &str,
    dst_db_path: &str,
) -> Result<ClaritySideTableStats, Error> {
    let conn = Connection::open(dst_db_path).map_err(Error::SQLError)?;

    SqliteConnection::initialize_conn(&conn).map_err(|e| {
        Error::CorruptionError(format!("Failed to initialize Clarity schema: {e:?}"))
    })?;

    conn.execute("ATTACH DATABASE ?1 AS src", [src_db_path])
        .map_err(Error::SQLError)?;

    let (squashed_tip, needed_keys) = collect_leaf_value_hashes::<StacksBlockId>(dst_db_path)?;

    let src_data_count: u64 = conn
        .query_row("SELECT COUNT(*) FROM src.data_table", [], |row| row.get(0))
        .map_err(Error::SQLError)?;
    let needed_count = needed_keys.len() as u64;
    let pruned_count = src_data_count.saturating_sub(needed_count);
    info!(
        "Clarity side-table copy: copying {} of {} data_table values (pruning {})",
        needed_count, src_data_count, pruned_count
    );

    let mut contract_ids: HashSet<String> = HashSet::new();
    {
        let mut stmt = conn
            .prepare("SELECT key FROM src.metadata_table")
            .map_err(Error::SQLError)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(Error::SQLError)?;
        for row in rows {
            if let Ok(key) = row {
                if let Some(rest) = key.strip_prefix("clr-meta::") {
                    if let Some((contract_id, _meta_key)) = rest.split_once("::") {
                        contract_ids.insert(contract_id.to_string());
                    }
                }
            }
        }
    }

    let mut required_contract_ids: HashSet<String> = HashSet::new();
    {
        let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
        let mut marf = MARF::<StacksBlockId>::from_path(src_db_path, open_opts)?;
        for contract_id in contract_ids.iter() {
            let contract = clarity::vm::types::QualifiedContractIdentifier::parse(contract_id)
                .map_err(|e| {
                    Error::CorruptionError(format!(
                        "Failed to parse contract identifier '{contract_id}': {e:?}"
                    ))
                })?;
            let key = make_contract_hash_key(&contract);
            if marf.get(&squashed_tip, &key)?.is_some() {
                required_contract_ids.insert(contract_id.clone());
            }
        }
    }

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(Error::SQLError)?;

    let copy_result = (|| -> Result<ClaritySideTableStats, Error> {
        conn.execute_batch("CREATE TEMP TABLE needed_keys (key TEXT PRIMARY KEY)")
            .map_err(Error::SQLError)?;
        const NEEDED_KEYS_BATCH_SIZE: usize = 500;
        for chunk in needed_keys
            .iter()
            .collect::<Vec<_>>()
            .chunks(NEEDED_KEYS_BATCH_SIZE)
        {
            let mut placeholders = Vec::with_capacity(chunk.len());
            let mut params = Vec::with_capacity(chunk.len());
            for (idx, key) in chunk.iter().enumerate() {
                placeholders.push(format!("(?{})", idx + 1));
                params.push(*key);
            }
            let sql = format!(
                "INSERT OR IGNORE INTO needed_keys (key) VALUES {}",
                placeholders.join(", ")
            );
            conn.execute(&sql, rusqlite::params_from_iter(params))
                .map_err(Error::SQLError)?;
        }

        let data_rows: u64 = conn
            .execute(
                "INSERT OR IGNORE INTO data_table \
                 SELECT key, value FROM src.data_table \
                 WHERE key IN (SELECT key FROM needed_keys)",
                [],
            )
            .map_err(Error::SQLError)? as u64;

        let mut metadata_rows: u64 = 0;
        let mut stmt = conn
            .prepare("SELECT key, blockhash, value FROM src.metadata_table")
            .map_err(Error::SQLError)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(Error::SQLError)?;
        let mut insert = conn
            .prepare(
                "INSERT OR IGNORE INTO metadata_table (key, blockhash, value) VALUES (?1, ?2, ?3)",
            )
            .map_err(Error::SQLError)?;
        for row in rows {
            let (key, blockhash, value) = row.map_err(Error::SQLError)?;
            if let Some(rest) = key.strip_prefix("clr-meta::") {
                if let Some((contract_id, _meta_key)) = rest.split_once("::") {
                    if !required_contract_ids.contains(contract_id) {
                        continue;
                    }
                    insert
                        .execute([key, blockhash, value])
                        .map_err(Error::SQLError)?;
                    metadata_rows += 1;
                }
            }
        }

        Ok(ClaritySideTableStats {
            data_table_rows: data_rows,
            metadata_table_rows: metadata_rows,
        })
    })();

    match copy_result {
        Ok(stats) => {
            conn.execute_batch("COMMIT").map_err(Error::SQLError)?;
            conn.execute_batch("DETACH src").map_err(Error::SQLError)?;
            checkpoint_destination_wal(&conn)?;
            Ok(stats)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            let _ = conn.execute_batch("DETACH src");
            Err(e)
        }
    }
}

/// Row-count statistics returned by [`copy_clarity_side_tables`].
#[derive(Debug, Clone)]
pub struct ClaritySideTableStats {
    /// Number of rows copied into `data_table`.
    pub data_table_rows: u64,
    /// Number of rows copied into `metadata_table`.
    pub metadata_table_rows: u64,
}

/// Validate that a squashed Clarity MARF's side tables match the source.
///
/// Checks:
/// - All trie-referenced `data_table` keys are present in the destination.
/// - All required `metadata_table` rows (exhaustive across all contracts) are present.
/// - A diagnostic sample of contracts is reported for troubleshooting.
pub fn validate_clarity_side_tables(
    src_db_path: &str,
    dst_db_path: &str,
) -> Result<ClaritySideTableValidation, Error> {
    let src_conn = Connection::open_with_flags(
        src_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::SQLError)?;

    let dst_conn = Connection::open_with_flags(
        dst_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Error::SQLError)?;

    let src_data_rows: u64 =
        src_conn.query_row("SELECT COUNT(*) FROM data_table", [], |row| row.get(0))?;
    let dst_data_rows: u64 =
        dst_conn.query_row("SELECT COUNT(*) FROM data_table", [], |row| row.get(0))?;

    let src_meta_rows: u64 =
        src_conn.query_row("SELECT COUNT(*) FROM metadata_table", [], |row| row.get(0))?;
    let dst_meta_rows: u64 =
        dst_conn.query_row("SELECT COUNT(*) FROM metadata_table", [], |row| row.get(0))?;

    const SAMPLE_CONTRACT_LIMIT: usize = 20;
    let mut all_contract_ids_ordered: Vec<String> = Vec::new();
    let mut contract_ids: HashSet<String> = HashSet::new();
    {
        let mut stmt = src_conn
            .prepare("SELECT key FROM metadata_table")
            .map_err(Error::SQLError)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(Error::SQLError)?;
        for row in rows {
            if let Ok(key) = row {
                if let Some(rest) = key.strip_prefix("clr-meta::") {
                    if let Some((contract_id, _meta_key)) = rest.split_once("::") {
                        if contract_ids.insert(contract_id.to_string()) {
                            all_contract_ids_ordered.push(contract_id.to_string());
                        }
                    }
                }
            }
        }
    }

    let sample_contract_ids: Vec<&str> = all_contract_ids_ordered
        .iter()
        .take(SAMPLE_CONTRACT_LIMIT)
        .map(|s| s.as_str())
        .collect();

    let mut sample_contracts_checked: u64 = 0;
    let mut sample_contracts_missing_in_trie: u64 = 0;
    let mut sample_contracts_missing_in_data_table: u64 = 0;

    if !sample_contract_ids.is_empty() {
        let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
        let mut marf = MARF::<StacksBlockId>::from_path(dst_db_path, open_opts)?;
        let tip = trie_sql::get_latest_confirmed_block_hash::<StacksBlockId>(marf.sqlite_conn())?;

        for contract_id in sample_contract_ids.iter() {
            sample_contracts_checked += 1;
            let contract = clarity::vm::types::QualifiedContractIdentifier::parse(contract_id)
                .map_err(|e| {
                    Error::CorruptionError(format!(
                        "Failed to parse contract identifier '{contract_id}': {e:?}"
                    ))
                })?;
            let key = make_contract_hash_key(&contract);
            let trie_value = marf.get(&tip, &key)?;
            let Some(trie_value) = trie_value else {
                sample_contracts_missing_in_trie += 1;
                continue;
            };

            let side_key = trie_value.to_hex();
            let exists: bool = dst_conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM data_table WHERE key = ?1",
                    [side_key],
                    |row| row.get(0),
                )
                .map_err(Error::SQLError)?;
            if !exists {
                sample_contracts_missing_in_data_table += 1;
            }
        }
    }

    let (_tip, needed_keys) = collect_leaf_value_hashes::<StacksBlockId>(dst_db_path)?;
    dst_conn
        .execute("ATTACH DATABASE ?1 AS src", [src_db_path])
        .map_err(Error::SQLError)?;
    dst_conn
        .execute_batch("CREATE TEMP TABLE trie_values (key TEXT PRIMARY KEY)")
        .map_err(Error::SQLError)?;
    {
        let mut stmt = dst_conn
            .prepare("INSERT OR IGNORE INTO trie_values (key) VALUES (?1)")
            .map_err(Error::SQLError)?;
        for key in needed_keys.iter() {
            stmt.execute([key]).map_err(Error::SQLError)?;
        }
    }
    let missing_required_data_table_keys: u64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM src.data_table \
         WHERE key IN (SELECT key FROM trie_values) \
           AND key NOT IN (SELECT key FROM data_table)",
            [],
            |row| row.get(0),
        )
        .map_err(Error::SQLError)?;
    dst_conn
        .execute_batch("DETACH src")
        .map_err(Error::SQLError)?;

    let mut required_contract_ids: HashSet<String> = HashSet::new();
    {
        let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);
        let mut marf = MARF::<StacksBlockId>::from_path(dst_db_path, open_opts)?;
        let tip = trie_sql::get_latest_confirmed_block_hash::<StacksBlockId>(marf.sqlite_conn())?;
        for contract_id in all_contract_ids_ordered.iter() {
            let contract = clarity::vm::types::QualifiedContractIdentifier::parse(contract_id)
                .map_err(|e| {
                    Error::CorruptionError(format!(
                        "Failed to parse contract identifier '{contract_id}': {e:?}"
                    ))
                })?;
            let key = make_contract_hash_key(&contract);
            if marf.get(&tip, &key)?.is_some() {
                required_contract_ids.insert(contract_id.clone());
            }
        }
    }

    let mut missing_required_metadata_rows: u64 = 0;
    {
        let mut stmt = src_conn
            .prepare("SELECT key, blockhash, value FROM metadata_table")
            .map_err(Error::SQLError)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(Error::SQLError)?;
        for row in rows {
            let (key, blockhash, value) = row.map_err(Error::SQLError)?;
            if let Some(rest) = key.strip_prefix("clr-meta::") {
                if let Some((contract_id, _meta_key)) = rest.split_once("::") {
                    if !required_contract_ids.contains(contract_id) {
                        continue;
                    }
                    let exists: bool = dst_conn.query_row(
                        "SELECT COUNT(*) > 0 FROM metadata_table WHERE key = ?1 AND blockhash = ?2 AND value = ?3",
                        [key, blockhash, value],
                        |row| row.get(0),
                    )?;
                    if !exists {
                        missing_required_metadata_rows += 1;
                    }
                }
            }
        }
    }

    Ok(ClaritySideTableValidation {
        required_data_keys_present: missing_required_data_table_keys == 0,
        src_data_table_rows: src_data_rows,
        dst_data_table_rows: dst_data_rows,
        required_metadata_present: missing_required_metadata_rows == 0,
        src_metadata_table_rows: src_meta_rows,
        dst_metadata_table_rows: dst_meta_rows,
        sample_contracts_checked,
        sample_contracts_missing_in_trie,
        sample_contracts_missing_in_data_table,
        missing_required_data_table_keys,
        missing_required_metadata_rows,
    })
}

/// Validation results for Clarity side tables.
#[derive(Debug, Clone)]
pub struct ClaritySideTableValidation {
    /// All trie-referenced data_table keys are present in the destination.
    pub required_data_keys_present: bool,
    /// Source `data_table` row count.
    pub src_data_table_rows: u64,
    /// Destination `data_table` row count.
    pub dst_data_table_rows: u64,
    /// All required metadata rows (for contracts with trie commitments) are
    /// present in the destination. Checked exhaustively over all contracts.
    pub required_metadata_present: bool,
    /// Source `metadata_table` row count.
    pub src_metadata_table_rows: u64,
    /// Destination `metadata_table` row count.
    pub dst_metadata_table_rows: u64,
    /// Number of contract identifiers sampled from metadata_table (diagnostic).
    pub sample_contracts_checked: u64,
    /// Sampled contracts missing from the trie (diagnostic, should be 0).
    pub sample_contracts_missing_in_trie: u64,
    /// Sampled contracts whose trie values are missing from data_table (diagnostic, should be 0).
    pub sample_contracts_missing_in_data_table: u64,
    /// Required data_table keys missing from destination (should be 0).
    pub missing_required_data_table_keys: u64,
    /// Required metadata rows missing from destination (should be 0).
    pub missing_required_metadata_rows: u64,
}

impl ClaritySideTableValidation {
    /// Returns `true` if all required data and metadata are present.
    pub fn is_valid(&self) -> bool {
        self.required_data_keys_present && self.required_metadata_present
    }
}
