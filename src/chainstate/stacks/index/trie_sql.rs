/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::char::from_digit;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::os;
use std::path::{Path, PathBuf};

use regex::Regex;
use rusqlite::{
    blob::Blob,
    types::{FromSql, ToSql},
    Connection, Error as SqliteError, OptionalExtension, Transaction, NO_PARAMS,
};

use crate::chainstate::stacks::index::bits::{
    get_node_byte_len, get_node_hash, read_block_identifier, read_hash_bytes,
    read_node_hash_bytes as bits_read_node_hash_bytes, read_nodetype, write_nodetype_bytes,
};
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, set_backptr, TrieNode, TrieNode16, TrieNode256, TrieNode4,
    TrieNode48, TrieNodeID, TrieNodeType, TriePath, TriePtr,
};
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieStorageConnection};
use crate::chainstate::stacks::index::Error;
use crate::chainstate::stacks::index::{trie_sql, BlockMap, MarfTrieId};
use crate::util_lib::db::sql_pragma;
use crate::util_lib::db::tx_begin_immediate;
use stacks_common::util::log;

use crate::chainstate::stacks::index::TrieLeaf;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BLOCK_HEADER_HASH_ENCODED_SIZE;
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

static SQL_MARF_DATA_TABLE: &str = "
CREATE TABLE IF NOT EXISTS marf_data (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   data BLOB NOT NULL,
   unconfirmed INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_marf_data ON marf_data(block_hash);
CREATE INDEX IF NOT EXISTS unconfirmed_marf_data ON marf_data(unconfirmed);
";
static SQL_MARF_MINED_TABLE: &str = "
CREATE TABLE IF NOT EXISTS mined_blocks (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   data BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_mined_blocks ON mined_blocks(block_hash);
";

static SQL_EXTENSION_LOCKS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS block_extension_locks (block_hash TEXT PRIMARY KEY);
";

pub fn create_tables_if_needed(conn: &mut Connection) -> Result<(), Error> {
    let tx = tx_begin_immediate(conn)?;

    tx.execute_batch(SQL_MARF_DATA_TABLE)?;
    tx.execute_batch(SQL_MARF_MINED_TABLE)?;
    tx.execute_batch(SQL_EXTENSION_LOCKS_TABLE)?;

    tx.commit().map_err(|e| e.into())
}

pub fn get_block_identifier<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<u32, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |row| row.get("block_id"),
    )
    .map_err(|e| e.into())
}

pub fn get_mined_block_identifier<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<u32, Error> {
    conn.query_row(
        "SELECT block_id FROM mined_blocks WHERE block_hash = ?",
        &[bhh],
        |row| row.get("block_id"),
    )
    .map_err(|e| e.into())
}

pub fn get_confirmed_block_identifier<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<Option<u32>, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 0",
        &[bhh],
        |row| row.get("block_id"),
    )
    .optional()
    .map_err(|e| e.into())
}

pub fn get_unconfirmed_block_identifier<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<Option<u32>, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
        &[bhh],
        |row| row.get("block_id"),
    )
    .optional()
    .map_err(|e| e.into())
}

pub fn get_block_hash<T: MarfTrieId>(conn: &Connection, local_id: u32) -> Result<T, Error> {
    let result = conn
        .query_row(
            "SELECT block_hash FROM marf_data WHERE block_id = ?",
            &[local_id],
            |row| row.get("block_hash"),
        )
        .optional()?;
    result.ok_or_else(|| {
        error!("Failed to get block header hash of local ID {}", local_id);
        Error::NotFoundError
    })
}

pub fn write_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    let args: &[&dyn ToSql] = &[block_hash, &data, &0];
    let mut s =
        conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed) VALUES (?, ?, ?)")?;
    let block_id = s
        .insert(args)?
        .try_into()
        .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");

    debug!("Wrote block trie {} to rowid {}", block_hash, block_id);
    Ok(block_id)
}

pub fn write_trie_blob_to_mined<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    if let Ok(block_id) = get_mined_block_identifier(conn, block_hash) {
        // already exists; update
        let args: &[&dyn ToSql] = &[&data, &block_id];
        let mut s = conn.prepare("UPDATE mined_blocks SET data = ? WHERE block_id = ?")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    } else {
        // doesn't exist yet; insert
        let args: &[&dyn ToSql] = &[block_hash, &data];
        let mut s = conn.prepare("INSERT INTO mined_blocks (block_hash, data) VALUES (?, ?)")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    };

    let block_id = get_mined_block_identifier(conn, block_hash)?;

    debug!(
        "Wrote mined block trie {} to rowid {}",
        block_hash, block_id
    );
    Ok(block_id)
}

pub fn write_trie_blob_to_unconfirmed<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    if let Ok(Some(_)) = get_confirmed_block_identifier(conn, block_hash) {
        panic!("BUG: tried to overwrite confirmed MARF trie {}", block_hash);
    }

    if let Ok(Some(block_id)) = get_unconfirmed_block_identifier(conn, block_hash) {
        // already exists; update
        let args: &[&dyn ToSql] = &[&data, &block_id];
        let mut s = conn.prepare("UPDATE marf_data SET data = ? WHERE block_id = ?")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    } else {
        // doesn't exist yet; insert
        let args: &[&dyn ToSql] = &[block_hash, &data, &1];
        let mut s =
            conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed) VALUES (?, ?, ?)")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    };

    let block_id = get_unconfirmed_block_identifier(conn, block_hash)?
        .expect(&format!("BUG: stored {} but got no block ID", block_hash));

    debug!(
        "Wrote unconfirmed block trie {} to rowid {}",
        block_hash, block_id
    );
    Ok(block_id)
}

pub fn open_trie_blob<'a>(conn: &'a Connection, block_id: u32) -> Result<Blob<'a>, Error> {
    let blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    Ok(blob)
}

#[cfg(test)]
pub fn read_all_block_hashes_and_roots<T: MarfTrieId>(
    conn: &Connection,
) -> Result<Vec<(TrieHash, T)>, Error> {
    let mut s = conn.prepare("SELECT block_hash, data FROM marf_data WHERE unconfirmed = 0")?;
    let rows = s.query_and_then(NO_PARAMS, |row| {
        let block_hash: T = row.get_unwrap("block_hash");
        let data = row
            .get_raw("data")
            .as_blob()
            .expect("DB Corruption: MARF data is non-blob");
        let start = TrieStorageConnection::<T>::root_ptr_disk() as usize;
        let trie_hash = TrieHash(read_hash_bytes(&mut &data[start..])?);
        Ok((trie_hash, block_hash))
    })?;
    rows.collect()
}

pub fn read_node_hash_bytes<W: Write>(
    conn: &Connection,
    w: &mut W,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<(), Error> {
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    w.write_all(&hash_buff).map_err(|e| e.into())
}

pub fn read_node_hash_bytes_by_bhh<W: Write, T: MarfTrieId>(
    conn: &Connection,
    w: &mut W,
    bhh: &T,
    ptr: &TriePtr,
) -> Result<(), Error> {
    let row_id: i64 = conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |r| r.get("block_id"),
    )?;
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        row_id,
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    w.write_all(&hash_buff).map_err(|e| e.into())
}

pub fn read_node_type(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<(TrieNodeType, TrieHash), Error> {
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    read_nodetype(&mut blob, ptr)
}

pub fn get_node_hash_bytes(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<TrieHash, Error> {
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    Ok(TrieHash(hash_buff))
}

pub fn get_node_hash_bytes_by_bhh<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
    ptr: &TriePtr,
) -> Result<TrieHash, Error> {
    let row_id: i64 = conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |r| r.get("block_id"),
    )?;
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        row_id,
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    Ok(TrieHash(hash_buff))
}

pub fn tx_lock_bhh_for_extension<T: MarfTrieId>(
    tx: &Connection,
    bhh: &T,
    unconfirmed: bool,
) -> Result<bool, Error> {
    if !unconfirmed {
        // confirmed tries can only be extended once.
        // unconfirmed tries can be overwritten.
        let is_bhh_committed = tx
            .query_row(
                "SELECT 1 FROM marf_data WHERE block_hash = ? LIMIT 1",
                &[bhh],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        if is_bhh_committed {
            return Ok(false);
        }
    }

    let is_bhh_locked = tx
        .query_row(
            "SELECT 1 FROM block_extension_locks WHERE block_hash = ? LIMIT 1",
            &[bhh],
            |_row| Ok(()),
        )
        .optional()?
        .is_some();
    if is_bhh_locked {
        return Ok(false);
    }

    tx.execute(
        "INSERT INTO block_extension_locks (block_hash) VALUES (?)",
        &[bhh],
    )?;
    Ok(true)
}

pub fn lock_bhh_for_extension<T: MarfTrieId>(
    tx: &Transaction,
    bhh: &T,
    unconfirmed: bool,
) -> Result<bool, Error> {
    tx_lock_bhh_for_extension(tx, bhh, unconfirmed)?;
    Ok(true)
}

pub fn count_blocks(conn: &Connection) -> Result<u32, Error> {
    let result = conn.query_row(
        "SELECT IFNULL(MAX(block_id), 0) AS count FROM marf_data WHERE unconfirmed = 0",
        NO_PARAMS,
        |row| row.get("count"),
    )?;
    Ok(result)
}

pub fn drop_lock<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM block_extension_locks WHERE block_hash = ?",
        &[bhh],
    )?;
    Ok(())
}

pub fn drop_unconfirmed_trie<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<(), Error> {
    debug!("Drop unconfirmed trie sqlite blob {}", bhh);
    conn.execute(
        "DELETE FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
        &[bhh],
    )?;
    debug!("Dropped unconfirmed trie sqlite blob {}", bhh);
    Ok(())
}

pub fn clear_lock_data(conn: &Connection) -> Result<(), Error> {
    conn.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
    Ok(())
}

pub fn clear_tables(tx: &Transaction) -> Result<(), Error> {
    tx.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
    tx.execute("DELETE FROM marf_data", NO_PARAMS)?;
    tx.execute("DELETE FROM mined_blocks", NO_PARAMS)?;
    Ok(())
}
