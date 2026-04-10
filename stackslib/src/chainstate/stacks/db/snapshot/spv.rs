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

use rusqlite::{params, Connection, OpenFlags};

use super::common::{
    clone_optional_schemas_from_source, clone_schemas_from_source, full_row_except_match,
    table_exists,
};
use crate::chainstate::stacks::db::snapshot::common::checkpoint_destination_wal;
use crate::chainstate::stacks::index::Error;

/// Tables required in all headers.sqlite versions.
const REQUIRED_TABLES: &[&str] = &["headers", "db_config"];

/// Tables present only in SPV schema v2+ (may be absent in very old DBs).
const OPTIONAL_TABLES: &[&str] = &[
    "chain_work", // Added in SPV_SCHEMA_2
];

/// Bitcoin difficulty chunk size (2016 blocks per difficulty interval).
const DIFFICULTY_CHUNK_SIZE: u32 = 2016;

/// Row-count statistics returned by [`copy_spv_headers`].
#[derive(Debug, Clone)]
pub struct SpvHeadersCopyStats {
    pub headers_rows: u64,
    pub chain_work_rows: u64,
}

/// Validation result for a copied headers.sqlite.
#[derive(Debug, Clone)]
pub struct SpvHeadersValidation {
    pub headers_match: bool,
    pub chain_work_match: bool,
    pub db_config_match: bool,
    pub no_extra_headers: bool,
}

impl SpvHeadersValidation {
    pub fn is_valid(&self) -> bool {
        self.headers_match && self.chain_work_match && self.db_config_match && self.no_extra_headers
    }
}

/// Copy canonical SPV headers up to `burn_height` into a new destination.
///
/// Returns an error if the source file does not exist.
pub fn copy_spv_headers(
    src_path: &str,
    dst_path: &str,
    burn_height: u32,
) -> Result<SpvHeadersCopyStats, Error> {
    if !Path::new(src_path).exists() {
        return Err(Error::IOError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("SPV headers source not found: {src_path}"),
        )));
    }

    if let Some(parent) = Path::new(dst_path).parent() {
        fs::create_dir_all(parent).map_err(Error::IOError)?;
    }

    let conn = Connection::open(dst_path).map_err(Error::SQLError)?;

    // Match the journal mode used by stacks-node (WAL) so the database can be
    // opened later without needing write access to switch modes.
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS src", params![src_path])
        .map_err(Error::SQLError)?;

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(Error::SQLError)?;

    let result = copy_spv_headers_inner(&conn, burn_height);

    match result {
        Ok(stats) => {
            conn.execute_batch("COMMIT").map_err(Error::SQLError)?;
            conn.execute_batch("DETACH DATABASE src")
                .map_err(Error::SQLError)?;
            checkpoint_destination_wal(&conn)?;
            Ok(stats)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            let _ = conn.execute_batch("DETACH DATABASE src");
            Err(e)
        }
    }
}

fn copy_spv_headers_inner(
    conn: &Connection,
    burn_height: u32,
) -> Result<SpvHeadersCopyStats, Error> {
    clone_schemas_from_source(conn, REQUIRED_TABLES)?;
    let optional_present = clone_optional_schemas_from_source(conn, OPTIONAL_TABLES)?;
    let has_chain_work = optional_present.contains(&"chain_work".to_string());

    conn.execute("INSERT INTO db_config SELECT * FROM src.db_config", [])
        .map_err(Error::SQLError)?;

    let headers_rows = conn
        .execute(
            "INSERT INTO headers SELECT * FROM src.headers WHERE height <= ?1",
            params![burn_height],
        )
        .map_err(Error::SQLError)? as u64;

    // Copy chain_work for complete intervals only.
    let chain_work_rows = if has_chain_work {
        conn.execute(
            "INSERT INTO chain_work SELECT * FROM src.chain_work \
             WHERE (interval + 1) * ?1 - 1 <= ?2",
            params![DIFFICULTY_CHUNK_SIZE, burn_height],
        )
        .map_err(Error::SQLError)? as u64
    } else {
        0
    };

    Ok(SpvHeadersCopyStats {
        headers_rows,
        chain_work_rows,
    })
}

/// Validate a copied headers.sqlite against its source.
pub fn validate_spv_headers(
    src_path: &str,
    dst_path: &str,
    burn_height: u32,
) -> Result<SpvHeadersValidation, Error> {
    if !Path::new(src_path).exists() {
        return Err(Error::IOError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("SPV headers source not found: {src_path}"),
        )));
    }
    if !Path::new(dst_path).exists() {
        return Err(Error::NotFoundError);
    }

    let conn = Connection::open_with_flags(dst_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(Error::SQLError)?;

    conn.execute("ATTACH DATABASE ?1 AS src", params![src_path])
        .map_err(Error::SQLError)?;

    let db_config_match = full_row_except_match(
        &conn,
        "SELECT * FROM db_config",
        "SELECT * FROM src.db_config",
    );

    let headers_match = full_row_except_match(
        &conn,
        "SELECT * FROM headers",
        &format!("SELECT * FROM src.headers WHERE height <= {burn_height}"),
    );

    let has_src_cw = table_exists(&conn, "src", "chain_work");
    let has_dst_cw = table_exists(&conn, "", "chain_work");

    let chain_work_match = match (has_src_cw, has_dst_cw) {
        (false, false) => true,
        (true, true) => full_row_except_match(
            &conn,
            "SELECT * FROM chain_work",
            &format!(
                "SELECT * FROM src.chain_work \
                 WHERE (interval + 1) * {DIFFICULTY_CHUNK_SIZE} - 1 <= {burn_height}"
            ),
        ),
        _ => false,
    };

    // No headers above burn_height in destination.
    let extra_above: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM headers WHERE height > {burn_height}"),
            [],
            |row| row.get(0),
        )
        .unwrap_or(1);
    let no_extra_headers = extra_above == 0;

    conn.execute_batch("DETACH DATABASE src")
        .map_err(Error::SQLError)?;

    Ok(SpvHeadersValidation {
        headers_match,
        chain_work_match,
        db_config_match,
        no_extra_headers,
    })
}
