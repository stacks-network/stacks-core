// Copyright (C) 2025 Stacks Open Internet Foundation
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

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use stacks::config::Config;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util_lib::db::{sqlite_open, tx_begin_immediate, Error as DBError};

/// Structure for storing **non-confidential** miner information
///  which can be reused between restarts
pub struct MinerDB {
    db: Connection,
}

static CREATE_STACKERDB_TRACKING: &str = "
CREATE TABLE stackerdb_tracking(
   public_key TEXT NOT NULL,
   slot_id INTEGER NOT NULL,
   slot_version INTEGER NOT NULL,
   PRIMARY KEY (public_key, slot_id)
) STRICT;
";

static CREATE_DB_CONFIG: &str = "
CREATE TABLE db_config(
   version INTEGER NOT NULL
) STRICT;
";

static SCHEMA_0: &[&str] = &[
    CREATE_STACKERDB_TRACKING,
    CREATE_DB_CONFIG,
    "INSERT INTO db_config VALUES (0);",
];

pub static CURRENT_SCHEMA: u32 = 0;
pub static MINER_DB_NAME: &str = "miner.sqlite";

impl MinerDB {
    fn get_schema_version(conn: &Connection) -> Result<Option<u32>, DBError> {
        let qry_db_exists =
            "SELECT name FROM sqlite_master WHERE type='table' AND name='db_config'";
        let db_exists = conn
            .query_row(&qry_db_exists, [], |_| Ok(true))
            .optional()?
            .is_some();
        if !db_exists {
            return Ok(None);
        }
        let version = conn.query_row("SELECT MAX(version) FROM db_config", [], |row| row.get(0))?;
        Ok(Some(version))
    }

    fn apply_schema_changes(conn: &Connection, changes: &[&str]) -> Result<(), DBError> {
        for query in changes.iter() {
            conn.execute_batch(query)?
        }
        Ok(())
    }

    fn apply_schema(db: &mut Connection) -> Result<(), DBError> {
        let tx = tx_begin_immediate(db)?;

        loop {
            match Self::get_schema_version(&tx)? {
                None => Self::apply_schema_changes(&tx, SCHEMA_0)?,
                Some(v) if v == CURRENT_SCHEMA => break,
                Some(v) => {
                    error!("Unexpected DB schema for minerdb: {v}. Latest supported schema is {CURRENT_SCHEMA}");
                    return Err(DBError::Corruption);
                }
            }
        }

        tx.commit()?;

        Ok(())
    }

    pub fn miner_db_path(config: &Config) -> PathBuf {
        let mut path = config.get_chainstate_path();
        path.set_file_name(MINER_DB_NAME);
        path
    }

    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self, DBError> {
        let open_flags = OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE;
        let mut db = sqlite_open(db_path, open_flags, false)?;
        Self::apply_schema(&mut db)?;
        Ok(Self { db })
    }

    pub fn open_with_config(config: &Config) -> Result<Self, DBError> {
        let db_path = Self::miner_db_path(config);
        Self::open(db_path)
    }

    /// Get the latest known version from the db for the given slot_id/pk pair
    pub fn get_latest_chunk_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
    ) -> Result<Option<u32>, DBError> {
        self.db
            .query_row(
                "SELECT slot_version FROM stackerdb_tracking WHERE public_key = ? AND slot_id = ?",
                params![pk.to_hex(), slot_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(DBError::from)
    }

    /// Set the latest known version for the given slot_id/pk pair
    pub fn set_latest_chunk_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
        slot_version: u32,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO stackerdb_tracking (public_key, slot_id, slot_version) VALUES (?, ?, ?)",
            params![pk.to_hex(), slot_id, slot_version],
        )?;
        Ok(())
    }
}
