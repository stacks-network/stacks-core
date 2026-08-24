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

use rusqlite::{Connection, OpenFlags};

use super::common::{
    assert_source_schema, clone_schemas_from_source, copied_rows, execute_copy_specs,
    with_offline_write_session, TableCopySpec,
};
use crate::burnchains::bitcoin::spv::num_complete_chain_work_intervals;
use crate::chainstate::stacks::index::Error;
use crate::util_lib::db::sqlite_open;

/// Tables required for the current headers.sqlite schema.
pub(super) const REQUIRED_TABLES: &[&str] = &["headers", "db_config", "chain_work"];

/// Every table the SPV headers snapshot accounts for. headers.sqlite is not
/// MARF-backed, so unlike the other slices there are no MARF infra tables to
/// exempt — the content-copied [`REQUIRED_TABLES`] are the whole schema.
fn known_spv_tables() -> Vec<&'static str> {
    REQUIRED_TABLES.to_vec()
}

/// The spv snapshot's source-schema guard (see [`assert_source_schema`]);
/// `test_no_unclassified_spv_tables` runs it against a fresh schema.
pub(super) fn assert_source_tables_classified(src_conn: &Connection) -> Result<(), Error> {
    assert_source_schema(
        src_conn,
        &known_spv_tables(),
        "headers.sqlite",
        "REQUIRED_TABLES in snapshot/spv.rs",
    )
}

/// Row-count statistics returned by [`copy_spv_headers`].
#[derive(Debug, Clone)]
pub struct SpvHeadersCopyStats {
    pub headers_rows: u64,
    pub chain_work_rows: u64,
}

/// Copy canonical SPV headers up to `burn_height` into a new destination.
///
/// Returns [`Error::DestinationExists`] if the destination already exists.
pub fn copy_spv_headers(
    src_path: &str,
    dst_path: &str,
    burn_height: u64,
) -> Result<SpvHeadersCopyStats, Error> {
    if Path::new(dst_path).exists() {
        return Err(Error::DestinationExists(dst_path.to_string()));
    }

    if let Some(parent) = Path::new(dst_path).parent() {
        fs::create_dir_all(parent)?;
    }

    // Reject an unrecognized source schema before any destination work.
    // The copy session only ATTACHes src, so open it read-only here for the check.
    let src_conn = sqlite_open(src_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
    assert_source_tables_classified(&src_conn)?;
    drop(src_conn);

    with_offline_write_session(dst_path, &[("src", src_path)], "", |conn| {
        copy_spv_headers_inner(conn, burn_height)
    })
}

/// Build the copy specs for the SPV headers DB: `db_config` verbatim,
/// `headers` up to `burn_height`, `chain_work` for complete difficulty
/// intervals only.
pub(super) fn spv_copy_specs(burn_height: u64) -> Vec<TableCopySpec> {
    let complete_intervals = num_complete_chain_work_intervals(burn_height);
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
    burn_height: u64,
) -> Result<SpvHeadersCopyStats, Error> {
    clone_schemas_from_source(conn, REQUIRED_TABLES)?;

    let results = execute_copy_specs(conn, &spv_copy_specs(burn_height))?;

    let stats = SpvHeadersCopyStats {
        headers_rows: copied_rows(&results, "headers"),
        chain_work_rows: copied_rows(&results, "chain_work"),
    };
    info!(
        "Copied SPV headers";
        "headers_rows" => stats.headers_rows,
        "chain_work_rows" => stats.chain_work_rows
    );
    Ok(stats)
}
