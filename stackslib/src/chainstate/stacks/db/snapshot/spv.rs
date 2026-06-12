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

use rusqlite::Connection;

use super::common::{
    clone_schemas_from_source, copied_rows, execute_copy_specs, with_offline_write_session,
    TableCopySpec,
};
use crate::burnchains::bitcoin::spv::num_complete_chain_work_intervals;
use crate::chainstate::stacks::index::Error;

/// Tables required in all headers.sqlite versions.
pub(super) const REQUIRED_TABLES: &[&str] = &["headers", "db_config", "chain_work"];

/// Row-count statistics returned by [`copy_spv_headers`].
#[derive(Debug, Clone)]
pub struct SpvHeadersCopyStats {
    pub headers_rows: u64,
    pub chain_work_rows: u64,
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

    with_offline_write_session(dst_path, &[("src", src_path)], "", |conn| {
        copy_spv_headers_inner(conn, burn_height)
    })
}

/// Build the copy specs for the SPV headers DB: `db_config` verbatim,
/// `headers` up to `burn_height`, `chain_work` for complete difficulty
/// intervals only.
fn spv_copy_specs(burn_height: u32) -> Vec<TableCopySpec> {
    let complete_intervals = num_complete_chain_work_intervals(u64::from(burn_height));
    vec![
        TableCopySpec {
            table: "db_config",
            source_sql: "SELECT * FROM src.db_config".into(),
        },
        TableCopySpec {
            table: "headers",
            source_sql: format!("SELECT * FROM src.headers WHERE height <= {burn_height}"),
        },
        TableCopySpec {
            table: "chain_work",
            source_sql: format!(
                "SELECT * FROM src.chain_work WHERE interval < {complete_intervals}"
            ),
        },
    ]
}

fn copy_spv_headers_inner(
    conn: &Connection,
    burn_height: u32,
) -> Result<SpvHeadersCopyStats, Error> {
    clone_schemas_from_source(conn, REQUIRED_TABLES)?;

    let results = execute_copy_specs(conn, &spv_copy_specs(burn_height))?;

    Ok(SpvHeadersCopyStats {
        headers_rows: copied_rows(&results, "headers"),
        chain_work_rows: copied_rows(&results, "chain_work"),
    })
}
