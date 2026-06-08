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

//! MARF-aware helpers for copying the canonical `__fork_storage` table.
//!
//! These sit apart from the generic SQL utilities in [`super::common`]
//! because they understand MARF leaf semantics: they walk the squashed
//! trie to learn which `value_hash` entries are canonical, then copy only
//! those rows.

use std::collections::HashSet;
use std::time::Instant;

use rusqlite::{params, Connection};

use super::common::clone_schemas_from_source;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::chainstate::stacks::index::{trie_sql, Error, MARFValue, MarfTrieId};

/// Collect the `MARFValue` of every leaf in the squashed trie.
///
/// Opens the MARF at `db_path` read-only, resolves the tip, and walks the
/// trie via `for_each_leaf`.  Auto-detects external blobs.
///
/// Returns `(tip_block_hash, leaf_value_hashes)`.
pub fn collect_leaf_value_hashes<T: MarfTrieId>(
    db_path: &str,
) -> Result<(T, HashSet<MARFValue>), Error> {
    let external_blobs = std::path::Path::new(&format!("{db_path}.blobs")).exists();
    let open_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", external_blobs);
    let storage = TrieFileStorage::open_readonly(db_path, open_opts)?;
    let mut marf = MARF::<T>::from_storage(storage);
    let tip = trie_sql::get_latest_confirmed_block_hash::<T>(marf.sqlite_conn())?;

    let mut hashes = HashSet::new();
    marf.with_conn(|conn| {
        MARF::for_each_leaf(conn, &tip, |_hash, value| {
            hashes.insert(value);
            Ok(())
        })
    })?;

    Ok((tip, hashes))
}

/// Walk the squashed MARF at `dst_path` read-only and return its canonical
/// leaf value hashes (for [`copy_canonical_fork_storage`]). A dst that was
/// not squashed into a MARF fails at open.
pub fn collect_canonical_leaf_hashes<T: MarfTrieId>(
    dst_path: &str,
) -> Result<HashSet<MARFValue>, Error> {
    let t = Instant::now();
    let (_tip, leaf_hashes) = collect_leaf_value_hashes::<T>(dst_path)?;
    info!(
        "[fork_storage] collected {} leaf hashes in {:?}",
        leaf_hashes.len(),
        t.elapsed()
    );
    Ok(leaf_hashes)
}

/// Copy canonical `__fork_storage` rows from `src` into `main`. i.e.
/// only the rows whose `value_hash` is referenced by a leaf in the
/// squashed MARF.
///
/// An empty `leaf_hashes` results in zero rows copied. the strict
/// `clone_schemas_from_source` ensures the schema is still cloned.
pub fn copy_canonical_fork_storage(
    conn: &Connection,
    leaf_hashes: &HashSet<MARFValue>,
) -> Result<u64, Error> {
    let src_has_table: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM src.sqlite_master WHERE type='table' AND name='__fork_storage'",
            [],
            |row| row.get(0),
        )
        .map_err(Error::SQLError)?;

    if !src_has_table {
        return Err(Error::CorruptionError(
            "src has no __fork_storage; expected on any chainstate that ran the MARF migration"
                .into(),
        ));
    }

    clone_schemas_from_source(conn, &["__fork_storage"])?;

    // `value_hash` is borrowed via `get_ref` and validated for every row;
    // only rows matching a canonical leaf allocate and copy `value`.
    let t = Instant::now();
    let mut select = conn
        .prepare("SELECT value_hash, value FROM src.__fork_storage")
        .map_err(Error::SQLError)?;
    let mut insert = conn
        .prepare("INSERT INTO __fork_storage (value_hash, value) VALUES (?1, ?2)")
        .map_err(Error::SQLError)?;
    let mut rows: u64 = 0;
    let mut scanned: u64 = 0;
    let mut rows_iter = select.query([]).map_err(Error::SQLError)?;
    while let Some(row) = rows_iter.next().map_err(Error::SQLError)? {
        scanned += 1;
        let key_ref = row.get_ref(0).map_err(Error::SQLError)?;
        let key_str = key_ref.as_str().map_err(|e| {
            Error::CorruptionError(format!("src.__fork_storage.value_hash is not TEXT: {e:?}"))
        })?;
        let key = MARFValue::from_hex(key_str).map_err(|e| {
            Error::CorruptionError(format!(
                "src.__fork_storage.value_hash `{key_str}` is not a hex MARFValue: {e:?}"
            ))
        })?;
        // `store_indexed` writes lowercase hex and the runtime reads it
        // back the same way; any other encoding is a foreign writer and
        // the copied row would be unreachable in dst.
        if !key_str
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(Error::CorruptionError(format!(
                "src.__fork_storage.value_hash `{key_str}` is not canonical lowercase hex"
            )));
        }
        if leaf_hashes.contains(&key) {
            let value: String = row.get(1).map_err(Error::SQLError)?;
            insert
                .execute(params![key_str, &value])
                .map_err(Error::SQLError)?;
            rows += 1;
        }
    }
    info!(
        "[fork_storage] stream-filter src.__fork_storage: scanned {scanned}, \
         copied {rows} rows in {:?}",
        t.elapsed()
    );

    Ok(rows)
}
