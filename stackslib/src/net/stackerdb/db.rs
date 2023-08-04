// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::collections::HashMap;
use std::collections::HashSet;

use std::fs;
use std::io;
use std::path::Path;

use crate::chainstate::stacks::address::PoxAddress;
use crate::net::stackerdb::{
    SlotMetadata, StackerDBConfig, StackerDBSet, StackerDBTx, STACKERDB_INV_MAX,
};
use crate::net::Error as net_error;
use crate::net::{
    ContractId, StackerDBChunkData, StackerDBChunkInvData, StackerDBGetChunkInvData,
    StackerDBHandshakeData,
};

use rusqlite::{
    types::ToSql, Connection, OpenFlags, OptionalExtension, Row, Transaction, NO_PARAMS,
};

use crate::util_lib::db::{
    opt_u64_to_sql, query_row, query_row_panic, query_rows, sql_pragma, sqlite_open,
    tx_begin_immediate, tx_busy_handler, u64_to_sql, DBConn, Error as db_error, FromColumn,
    FromRow,
};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use clarity::vm::ContractName;

const STACKER_DB_SCHEMA: &'static [&'static str] = &[
    r#"
    PRAGMA foreign_keys = ON;
    "#,
    r#"
    CREATE TABLE databases(
        -- smart contract for this stackerdb
        stackerdb_id INTEGER NOT NULL,
        smart_contract_id TEXT UNIQUE NOT NULL,
        PRIMARY KEY(stackerdb_id)
    );
    "#,
    r#"
    CREATE INDEX on_database_contract_names ON databases(smart_contract_id);
    "#,
    r#"
    CREATE TABLE chunks(
        -- associated stacker DB
        stackerdb_id INTEGER NOT NULL,
        -- slot ID
        slot_id INTEGER NOT NULL,
        -- lamport clock of the chunk.
        version INTEGER NOT NULL,
        -- hash of the data to be stored
        data_hash TEXT NOT NULL,
        -- secp256k1 recoverable signature from the stacker over the above columns
        signature TEXT NOT NULL,

        -- the following is NOT covered by the signature
        -- address of the creator of this chunk
        stacker STRING NOT NULL,
        -- the chunk data itself
        data BLOB NOT NULL,
        -- UNIX timestamp when the chunk was written.
        write_time INTEGER NOT NULL,
        
        PRIMARY KEY(stackerdb_id,slot_id),
        FOREIGN KEY(stackerdb_id) REFERENCES databases(stackerdb_id) ON DELETE CASCADE
    );
    "#,
    r#"
    CREATE INDEX on_stacker_db_slots ON chunks(stackerdb_id,slot_id,version);
    "#,
];

pub const NO_VERSION: i64 = 0;

/// Private struct for loading the data we need to validate an incoming chunk
pub struct SlotValidation {
    pub stacker: StacksAddress,
    pub version: u32,
    pub write_time: u64,
}

impl FromRow<SlotMetadata> for SlotMetadata {
    fn from_row<'a>(row: &'a Row) -> Result<SlotMetadata, db_error> {
        let slot_id: u32 = row.get_unwrap("slot_id");
        let slot_version: u32 = row.get_unwrap("version");
        let data_hash_str: String = row.get_unwrap("data_hash");
        let data_hash =
            Sha512Trunc256Sum::from_hex(&data_hash_str).map_err(|_| db_error::ParseError)?;
        let message_sig_str: String = row.get_unwrap("signature");
        let signature =
            MessageSignature::from_hex(&message_sig_str).map_err(|_| db_error::ParseError)?;

        Ok(SlotMetadata {
            slot_id,
            slot_version,
            data_hash,
            signature,
        })
    }
}

impl FromRow<SlotValidation> for SlotValidation {
    fn from_row<'a>(row: &'a Row) -> Result<SlotValidation, db_error> {
        let stacker = StacksAddress::from_column(row, "stacker")?;
        let version: u32 = row.get_unwrap("version");
        let write_time_i64: i64 = row.get_unwrap("write_time");
        if write_time_i64 < 0 {
            return Err(db_error::ParseError);
        }
        let write_time = write_time_i64 as u64;

        Ok(SlotValidation {
            stacker,
            version,
            write_time,
        })
    }
}

impl FromRow<StackerDBChunkData> for StackerDBChunkData {
    fn from_row<'a>(row: &'a Row) -> Result<StackerDBChunkData, db_error> {
        let slot_id: u32 = row.get_unwrap("slot_id");
        let slot_version: u32 = row.get_unwrap("version");
        let data: Vec<u8> = row.get_unwrap("data");
        let message_sig_str: String = row.get_unwrap("signature");
        let sig = MessageSignature::from_hex(&message_sig_str).map_err(|_| db_error::ParseError)?;

        Ok(StackerDBChunkData {
            slot_id,
            slot_version,
            sig,
            data,
        })
    }
}

/// Get the local numeric ID of a stacker DB.
/// Returns Err(NoSuchStackerDB(..)) if it doesn't exist
fn inner_get_stackerdb_id(conn: &DBConn, smart_contract: &ContractId) -> Result<i64, net_error> {
    let sql = "SELECT rowid FROM databases WHERE smart_contract_id = ?1";
    let args: &[&dyn ToSql] = &[&smart_contract.to_string()];
    Ok(query_row(conn, sql, args)?.ok_or(net_error::NoSuchStackerDB(smart_contract.clone()))?)
}

/// Load up chunk metadata from the database, keyed by the chunk's database's smart contract and
/// its identifier.
/// Inner method body for related methods in both the DB instance and the transaction instance.
fn inner_get_slot_metadata(
    conn: &DBConn,
    smart_contract: &ContractId,
    slot_id: u32,
) -> Result<Option<SlotMetadata>, net_error> {
    let stackerdb_id = inner_get_stackerdb_id(conn, smart_contract)?;
    let sql = "SELECT slot_id,version,data_hash,signature FROM chunks WHERE stackerdb_id = ?1 AND slot_id = ?2";
    let args: &[&dyn ToSql] = &[&stackerdb_id, &slot_id];
    query_row(conn, &sql, args).map_err(|e| e.into())
}

/// Load up validation information from the database, keyed by the chunk's database's smart
/// contract and its identifier.
/// Inner method body for related methods in both the DB instance and the transaction instance.
fn inner_get_slot_validation(
    conn: &DBConn,
    smart_contract: &ContractId,
    slot_id: u32,
) -> Result<Option<SlotValidation>, net_error> {
    let stackerdb_id = inner_get_stackerdb_id(conn, smart_contract)?;
    let sql =
        "SELECT stacker,write_time,version FROM chunks WHERE stackerdb_id = ?1 AND slot_id = ?2";
    let args: &[&dyn ToSql] = &[&stackerdb_id, &slot_id];
    query_row(conn, &sql, args).map_err(|e| e.into())
}

impl<'a> StackerDBTx<'a> {
    pub fn commit(self) -> Result<(), net_error> {
        self.sql_tx.commit().map_err(net_error::from)
    }

    pub fn conn(&self) -> &DBConn {
        &self.sql_tx
    }

    /// Delete a stacker DB table and its contents.
    /// Idempotent.
    pub fn delete_stackerdb(&self, smart_contract_id: &ContractId) -> Result<(), net_error> {
        let qry = "DELETE FROM databases WHERE smart_contract_id = ?1";
        let args: &[&dyn ToSql] = &[&smart_contract_id.to_string()];
        let mut stmt = self.sql_tx.prepare(qry)?;
        stmt.execute(args)?;
        Ok(())
    }

    /// List all stacker DB smart contracts we have available
    pub fn get_stackerdb_contract_ids(&self) -> Result<Vec<ContractId>, net_error> {
        let sql = "SELECT smart_contract_id FROM databases ORDER BY smart_contract_id";
        query_rows(&self.conn(), sql, NO_PARAMS).map_err(|e| e.into())
    }

    /// Get the Stacker DB ID for a smart contract
    pub fn get_stackerdb_id(&self, smart_contract: &ContractId) -> Result<i64, net_error> {
        inner_get_stackerdb_id(&self.conn(), smart_contract)
    }

    /// Set up a database's storage slots.
    /// The slots must be in a deterministic order, since they are used to determine the chunk ID
    /// (and thus the key used to authenticate them)
    pub fn create_stackerdb(
        &self,
        smart_contract: &ContractId,
        slots: &[(StacksAddress, u64)],
    ) -> Result<(), net_error> {
        if slots.len() > (STACKERDB_INV_MAX as usize) {
            return Err(net_error::ArrayTooLong);
        }

        if self.get_stackerdb_id(smart_contract).is_ok() {
            return Err(net_error::StackerDBExists(smart_contract.clone()));
        }

        let qry = "INSERT OR REPLACE INTO databases (smart_contract_id) VALUES (?1)";
        let mut stmt = self.sql_tx.prepare(&qry)?;
        let args: &[&dyn ToSql] = &[&smart_contract.to_string()];
        stmt.execute(args)?;

        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;

        let qry = "INSERT OR REPLACE INTO chunks (stackerdb_id,stacker,slot_id,version,write_time,data,data_hash,signature) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)";
        let mut stmt = self.sql_tx.prepare(&qry)?;
        let mut slot_id = 0u32;

        for (principal, slot_count) in slots.iter() {
            for _ in 0..*slot_count {
                let args: &[&dyn ToSql] = &[
                    &stackerdb_id,
                    &principal.to_string(),
                    &slot_id,
                    &NO_VERSION,
                    &0,
                    &vec![],
                    &Sha512Trunc256Sum([0u8; 32]),
                    &MessageSignature::empty(),
                ];
                stmt.execute(args)?;

                slot_id += 1;
            }
        }

        Ok(())
    }

    /// Clear a database's slots and its data.
    /// Idempotent.
    /// Fails if the DB doesn't exist
    pub fn clear_stackerdb_slots(&self, smart_contract: &ContractId) -> Result<(), net_error> {
        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;

        let qry = "DELETE FROM chunks WHERE stackerdb_id = ?1";
        let args: &[&dyn ToSql] = &[&stackerdb_id];
        let mut stmt = self.sql_tx.prepare(&qry)?;
        stmt.execute(args)?;
        Ok(())
    }

    /// Get the slot metadata
    pub fn get_slot_metadata(
        &self,
        smart_contract: &ContractId,
        slot_id: u32,
    ) -> Result<Option<SlotMetadata>, net_error> {
        inner_get_slot_metadata(self.conn(), smart_contract, slot_id)
    }

    /// Get a chunk's validation data
    pub fn get_slot_validation(
        &self,
        smart_contract: &ContractId,
        slot_id: u32,
    ) -> Result<Option<SlotValidation>, net_error> {
        inner_get_slot_validation(self.conn(), smart_contract, slot_id)
    }

    /// Insert a chunk into the DB.
    /// It must be authenticated, and its lamport clock must be higher than the one that's already
    /// there.  These will not be checked.
    fn insert_chunk(
        &self,
        smart_contract: &ContractId,
        slot_desc: &SlotMetadata,
        chunk: &[u8],
    ) -> Result<(), net_error> {
        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;
        let sql = "UPDATE chunks SET version = ?1, data_hash = ?2, signature = ?3, data = ?4, write_time = ?5 WHERE stackerdb_id = ?6 AND slot_id = ?7";
        let mut stmt = self.sql_tx.prepare(&sql)?;

        let args: &[&dyn ToSql] = &[
            &slot_desc.slot_version,
            &Sha512Trunc256Sum::from_data(chunk),
            &slot_desc.signature,
            &chunk,
            &u64_to_sql(get_epoch_time_secs())?,
            &stackerdb_id,
            &slot_desc.slot_id,
        ];

        stmt.execute(args)?;
        Ok(())
    }

    /// Add or replace a chunk for a given reward cycle, if it is valid
    /// Otherwise, this errors out with Error::StaleChunk
    pub fn try_replace_chunk(
        &self,
        smart_contract: &ContractId,
        slot_desc: &SlotMetadata,
        chunk: &[u8],
    ) -> Result<(), net_error> {
        let slot_validation = self
            .get_slot_validation(smart_contract, slot_desc.slot_id)?
            .ok_or(net_error::NoSuchSlot(
                smart_contract.clone(),
                slot_desc.slot_id,
            ))?;

        if !slot_desc.verify(&slot_validation.stacker)? {
            return Err(net_error::BadSlotSigner(
                slot_validation.stacker,
                slot_desc.slot_id,
            ));
        }
        if slot_desc.slot_version <= slot_validation.version {
            return Err(net_error::StaleChunk(
                slot_validation.version,
                slot_desc.slot_version,
            ));
        }
        if slot_desc.slot_version > self.config.max_writes {
            return Err(net_error::TooManySlotWrites(
                self.config.max_writes,
                slot_validation.version,
            ));
        }
        if slot_validation.write_time + self.config.write_freq >= get_epoch_time_secs() {
            return Err(net_error::TooFrequentSlotWrites(
                slot_validation.write_time + self.config.write_freq,
            ));
        }
        self.insert_chunk(smart_contract, slot_desc, chunk)
    }
}

impl StackerDBSet {
    /// Instantiate the DB
    fn instantiate(path: &str, readwrite: bool) -> Result<StackerDBSet, net_error> {
        let mut create_flag = false;

        let open_flags = if path != ":memory:" {
            match fs::metadata(path) {
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        // need to create
                        if readwrite {
                            create_flag = true;
                            let ppath = Path::new(path);
                            let pparent_path = ppath
                                .parent()
                                .expect(&format!("BUG: no parent of '{}'", path));
                            fs::create_dir_all(&pparent_path).map_err(|e| db_error::IOError(e))?;

                            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                        } else {
                            return Err(db_error::NoDBError.into());
                        }
                    } else {
                        return Err(db_error::IOError(e).into());
                    }
                }
                Ok(_md) => {
                    // can just open
                    if readwrite {
                        OpenFlags::SQLITE_OPEN_READ_WRITE
                    } else {
                        OpenFlags::SQLITE_OPEN_READ_ONLY
                    }
                }
            }
        } else {
            create_flag = true;
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        };

        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = StackerDBSet { conn };

        if create_flag {
            let db_tx = db.tx_begin(StackerDBConfig::noop())?;
            for sql in STACKER_DB_SCHEMA.iter() {
                db_tx.sql_tx.execute_batch(sql)?;
            }
            db_tx.commit()?;
        }

        Ok(db)
    }

    /// Connect to a stacker DB, creating it if it doesn't exist and if readwrite is true.
    /// Readwrite is enforced by the underling sqlite connection.
    pub fn connect(path: &str, readwrite: bool) -> Result<StackerDBSet, net_error> {
        Self::instantiate(path, readwrite)
    }

    #[cfg(test)]
    pub fn connect_memory() -> StackerDBSet {
        Self::instantiate(":memory:", true).unwrap()
    }

    /// Open a transaction on the Stacker DB.
    /// The config would be obtained from a DBSelector instance
    pub fn tx_begin<'a>(
        &'a mut self,
        config: StackerDBConfig,
    ) -> Result<StackerDBTx<'a>, net_error> {
        let sql_tx = tx_begin_immediate(&mut self.conn)?;
        Ok(StackerDBTx { sql_tx, config })
    }

    /// Get the Stacker DB ID for a smart contract
    pub fn get_stackerdb_id(&self, smart_contract: &ContractId) -> Result<i64, net_error> {
        inner_get_stackerdb_id(&self.conn, smart_contract)
    }

    /// List all stacker DB smart contracts we have available
    pub fn get_stackerdb_contract_ids(&self) -> Result<Vec<ContractId>, net_error> {
        let sql = "SELECT smart_contract_id FROM databases ORDER BY smart_contract_id";
        query_rows(&self.conn, sql, NO_PARAMS).map_err(|e| e.into())
    }

    /// Get the principal who signs a particular slot in a particular stacker DB.
    /// Returns Ok(Some(addr)) if this slot exists in the DB
    /// Returns Ok(None) if the slot does not exist
    /// Returns Err(..) if the DB doesn't exist of some other DB error happens
    pub fn get_slot_signer(
        &self,
        smart_contract: &ContractId,
        slot_id: u32,
    ) -> Result<Option<StacksAddress>, net_error> {
        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;
        let sql = "SELECT stacker FROM chunks WHERE stackerdb_id = ?1 AND slot_id = ?2";
        let args: &[&dyn ToSql] = &[&stackerdb_id, &slot_id];
        query_row(&self.conn, &sql, args).map_err(|e| e.into())
    }

    /// Get the slot metadata
    pub fn get_slot_metadata(
        &self,
        smart_contract: &ContractId,
        slot_id: u32,
    ) -> Result<Option<SlotMetadata>, net_error> {
        inner_get_slot_metadata(&self.conn, smart_contract, slot_id)
    }

    /// Get a slot's validation data
    pub fn get_slot_validation(
        &self,
        smart_contract: &ContractId,
        slot_id: u32,
    ) -> Result<Option<SlotValidation>, net_error> {
        inner_get_slot_validation(&self.conn, smart_contract, slot_id)
    }

    /// Get the list of slot ID versions for a given DB instance at a given reward cycle
    pub fn get_slot_versions(&self, smart_contract: &ContractId) -> Result<Vec<u32>, net_error> {
        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;
        let sql = "SELECT version FROM chunks WHERE stackerdb_id = ?1 ORDER BY slot_id";
        let args: &[&dyn ToSql] = &[&stackerdb_id];
        query_rows(&self.conn, &sql, args).map_err(|e| e.into())
    }

    /// Get the list of slot write timestamps for a given DB instance at a given reward cycle
    pub fn get_slot_write_timestamps(
        &self,
        smart_contract: &ContractId,
    ) -> Result<Vec<u64>, net_error> {
        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;
        let sql = "SELECT write_time FROM chunks WHERE stackerdb_id = ?1 ORDER BY slot_id";
        let args: &[&dyn ToSql] = &[&stackerdb_id];
        query_rows(&self.conn, &sql, args).map_err(|e| e.into())
    }

    /// Get the latest chunk out of the database.
    /// Returns Ok(Some(data)) if the chunk exists
    /// Returns Ok(None) if the chunk does not exist
    /// Returns Err(..) if the DB does not exist, or some other DB error occurs
    pub fn get_latest_chunk(
        &self,
        smart_contract: &ContractId,
        slot_id: u32,
    ) -> Result<Option<Vec<u8>>, net_error> {
        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;
        let qry = "SELECT data FROM chunks WHERE stackerdb_id = ?1 AND slot_id = ?2";
        let args: &[&dyn ToSql] = &[&stackerdb_id, &slot_id];

        let mut stmt = self
            .conn
            .prepare(&qry)
            .map_err(|e| net_error::DBError(e.into()))?;

        let mut rows = stmt.query(args).map_err(|e| net_error::DBError(e.into()))?;

        let mut data = None;
        while let Some(row) = rows.next().map_err(|e| net_error::DBError(e.into()))? {
            data = Some(row.get_unwrap(0));
            break;
        }
        Ok(data)
    }

    /// Get a versioned chunk out of this database.  If the version is not present, then None will
    /// be returned.
    pub fn get_chunk(
        &self,
        smart_contract: &ContractId,
        slot_id: u32,
        slot_version: u32,
    ) -> Result<Option<StackerDBChunkData>, net_error> {
        let stackerdb_id = self.get_stackerdb_id(smart_contract)?;
        let qry = "SELECT slot_id,version,signature,data FROM chunks WHERE stackerdb_id = ?1 AND slot_id = ?2 AND version = ?3";
        let args: &[&dyn ToSql] = &[&stackerdb_id, &slot_id, &slot_version];
        query_row(&self.conn, &qry, args).map_err(|e| e.into())
    }
}
