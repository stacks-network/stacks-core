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

use super::common::{
    clone_schemas_from_source, copied_rows, with_offline_write_session, DbSnapshotSpec,
    TableCopySpec, TableCopySpecs,
};
use crate::burnchains::bitcoin::spv::num_complete_chain_work_intervals;
use crate::chainstate::stacks::index::Error;
use crate::util_lib::db::{sqlite_open, u64_to_sql};

/// The SPV headers snapshot's `?N` binds, both derived from `burn_height`.
#[derive(Clone, Copy)]
pub(super) enum SpvBind {
    /// `headers` filters `height <= ?1`.
    BurnHeight,
    /// `chain_work` filters `interval < ?1`.
    CompleteChainWorkIntervals,
}

/// The SPV headers (`headers.sqlite`) snapshot spec. The row-copied specs
/// are the whole schema. `burn_height` only feeds the `?N` binds, not the
/// table-name set.
pub(super) struct SpvDbSnapshotSpec {
    pub burn_height: u64,
}

impl DbSnapshotSpec for SpvDbSnapshotSpec {
    type Bind = SpvBind;

    fn table_names() -> Vec<&'static str> {
        TableCopySpecs::new(spv_copy_specs()).table_names()
    }

    fn db_label() -> &'static str {
        "headers.sqlite"
    }

    fn classify_hint() -> &'static str {
        "spv_copy_specs() in snapshot/spv.rs"
    }

    fn copy_specs(&self) -> TableCopySpecs<'static, SpvBind> {
        TableCopySpecs::new(spv_copy_specs())
    }

    fn bind_params(&self, bind: SpvBind) -> Result<Vec<Value>, Error> {
        match bind {
            SpvBind::BurnHeight => Ok(vec![Value::Integer(u64_to_sql(self.burn_height)?)]),
            SpvBind::CompleteChainWorkIntervals => Ok(vec![Value::Integer(u64_to_sql(
                num_complete_chain_work_intervals(self.burn_height),
            )?)]),
        }
    }
}

/// The spv snapshot's source-schema guard (see
/// [`DbSnapshotSpec::assert_source_classified`]); `test_no_unclassified_spv_tables`
/// runs it against a fresh schema. The recognized set is independent of
/// `burn_height`.
pub(super) fn assert_source_tables_classified(src_conn: &Connection) -> Result<(), Error> {
    SpvDbSnapshotSpec::assert_source_classified(src_conn)
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

/// The copy specs for the SPV headers DB: `db_config` verbatim, `headers` up to
/// `?1` (burn height), `chain_work` for complete difficulty intervals
/// (`interval < ?1`). The runtime values are bound via
/// [`SpvDbSnapshotSpec::bind_params`].
pub(super) fn spv_copy_specs() -> &'static [TableCopySpec<SpvBind>] {
    static SPECS: &[TableCopySpec<SpvBind>] = &[
        TableCopySpec::sql("db_config", "SELECT * FROM src.db_config"),
        TableCopySpec::sql_with_bind(
            "headers",
            "SELECT * FROM src.headers WHERE height <= ?1",
            SpvBind::BurnHeight,
        ),
        TableCopySpec::sql_with_bind(
            "chain_work",
            "SELECT * FROM src.chain_work WHERE interval < ?1",
            SpvBind::CompleteChainWorkIntervals,
        ),
    ];
    SPECS
}

fn copy_spv_headers_inner(
    conn: &Connection,
    burn_height: u64,
) -> Result<SpvHeadersCopyStats, Error> {
    let spec = SpvDbSnapshotSpec { burn_height };
    clone_schemas_from_source(conn, &SpvDbSnapshotSpec::table_names())?;

    let results = spec.run_copy(conn)?;

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
