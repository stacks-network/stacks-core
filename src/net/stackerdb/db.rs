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
    ChunkMetadata, StackerDB, StackerDBConfig, StackerDBTx, STACKERDB_INV_MAX,
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
        -- table name
        table_name TEXT NOT NULL,
        smart_contract_id TEXT NOT NULL,
        PRIMARY KEY(table_name)
    );
    "#,
];

const CHUNKS_DB_TABLE_BODY: &'static str = r#"
    (
        -- reward cycle in which this chunk exists.
        -- this is a consensus hash of the start of a reward cycle
        rc_consensus_hash TEXT NOT NULL,
        -- chunk ID
        chunk_id INTEGER NOT NULL,
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
        
        PRIMARY KEY(rc_consensus_hash,chunk_id)
    );
    "#;

const CHUNKS_DB_INDEX_BODIES: &'static [(&'static str, &'static str)] =
    &[("chunk_versions", "(rc_consensus_hash,chunk_id,version)")];

pub const NO_VERSION: i64 = 0;

/// Private struct for loading the data we need to validate an incoming chunk
pub struct ChunkValidation {
    pub stacker: StacksAddress,
    pub version: u32,
    pub write_time: u64,
}

impl FromRow<ChunkMetadata> for ChunkMetadata {
    fn from_row<'a>(row: &'a Row) -> Result<ChunkMetadata, db_error> {
        let rc_consensus_hash: ConsensusHash =
            ConsensusHash::from_column(row, "rc_consensus_hash")?;
        let chunk_id: u32 = row.get_unwrap("chunk_id");
        let chunk_version: u32 = row.get_unwrap("version");
        let data_hash_str: String = row.get_unwrap("data_hash");
        let data_hash =
            Sha512Trunc256Sum::from_hex(&data_hash_str).map_err(|_| db_error::ParseError)?;
        let message_sig_str: String = row.get_unwrap("signature");
        let signature =
            MessageSignature::from_hex(&message_sig_str).map_err(|_| db_error::ParseError)?;

        Ok(ChunkMetadata {
            rc_consensus_hash,
            chunk_id,
            chunk_version,
            data_hash,
            signature,
        })
    }
}

impl FromRow<ChunkValidation> for ChunkValidation {
    fn from_row<'a>(row: &'a Row) -> Result<ChunkValidation, db_error> {
        let stacker = StacksAddress::from_column(row, "stacker")?;
        let version: u32 = row.get_unwrap("version");
        let write_time_i64: i64 = row.get_unwrap("write_time");
        if write_time_i64 < 0 {
            return Err(db_error::ParseError);
        }
        let write_time = write_time_i64 as u64;

        Ok(ChunkValidation {
            stacker,
            version,
            write_time,
        })
    }
}

impl FromRow<StackerDBChunkData> for StackerDBChunkData {
    fn from_row<'a>(row: &'a Row) -> Result<StackerDBChunkData, db_error> {
        let chunk_id: u32 = row.get_unwrap("chunk_id");
        let chunk_version: u32 = row.get_unwrap("version");
        let data: Vec<u8> = row.get_unwrap("data");
        let message_sig_str: String = row.get_unwrap("signature");
        let sig = MessageSignature::from_hex(&message_sig_str).map_err(|_| db_error::ParseError)?;

        Ok(StackerDBChunkData {
            chunk_id,
            chunk_version,
            sig,
            data,
        })
    }
}

/// Convert a smart contract name to a table name
pub fn stackerdb_table(addr: &ContractId) -> String {
    let normalized_name = format!("{}", &addr)
        .replace("-", "\\x2d")
        .replace("_", "\\x5f")
        .replace(".", "_");

    format!("stackerdb_{}", normalized_name)
}

/// Load up chunk metadata from the database, given the primary key.
/// Inner method body for related methods in both the DB instance and the transaction instance.
fn inner_get_chunk_metadata(
    conn: &DBConn,
    smart_contract: &ContractId,
    rc_consensus_hash: &ConsensusHash,
    chunk_id: u32,
) -> Result<Option<ChunkMetadata>, net_error> {
    let sql = format!("SELECT chunk_id,rc_consensus_hash,version,data_hash,signature FROM {} WHERE rc_consensus_hash = ?1 AND chunk_id = ?2", stackerdb_table(smart_contract));
    let args: &[&dyn ToSql] = &[rc_consensus_hash, &chunk_id];
    query_row(conn, &sql, args).map_err(|e| e.into())
}

/// Load up validation information from the database, given the primary key
/// Inner method body for related methods in both the DB instance and the transaction instance.
fn inner_get_chunk_validation(
    conn: &DBConn,
    smart_contract: &ContractId,
    rc_consensus_hash: &ConsensusHash,
    chunk_id: u32,
) -> Result<Option<ChunkValidation>, net_error> {
    let sql = format!(
        "SELECT stacker,write_time,version FROM {} WHERE rc_consensus_hash = ?1 AND chunk_id = ?2",
        stackerdb_table(smart_contract)
    );
    let args: &[&dyn ToSql] = &[rc_consensus_hash, &chunk_id];
    query_row(conn, &sql, args).map_err(|e| e.into())
}

impl<'a> StackerDBTx<'a> {
    pub fn commit(self) -> Result<(), net_error> {
        self.sql_tx.commit().map_err(net_error::from)
    }

    pub fn conn(&self) -> &DBConn {
        &self.sql_tx
    }

    /// Create a stacker DB table and its indexes.
    /// Idempotent.
    pub fn create_stackerdb(&self, smart_contract: &ContractId) -> Result<(), net_error> {
        let qry = format!(
            "CREATE TABLE IF NOT EXISTS {}{}",
            stackerdb_table(smart_contract),
            CHUNKS_DB_TABLE_BODY
        );
        let mut stmt = self.sql_tx.prepare(&qry)?;
        stmt.execute(NO_PARAMS)?;

        for (index_name, index_body) in CHUNKS_DB_INDEX_BODIES.iter() {
            let qry = format!(
                "CREATE INDEX IF NOT EXISTS index_{}_{} ON {}{}",
                stackerdb_table(smart_contract),
                index_name,
                stackerdb_table(smart_contract),
                index_body
            );
            let mut stmt = self.sql_tx.prepare(&qry)?;
            stmt.execute(NO_PARAMS)?;
        }

        let qry = "REPLACE INTO databases (table_name,smart_contract_id) VALUES (?1,?2)";
        let args: &[&dyn ToSql] = &[&stackerdb_table(smart_contract), &smart_contract];
        let mut stmt = self.sql_tx.prepare(&qry)?;
        stmt.execute(args)?;

        Ok(())
    }

    /// Delete a stacker DB table and its indexes.
    /// Idempotent.
    pub fn delete_stackerdb(&self, smart_contract: &ContractId) -> Result<(), net_error> {
        let qry = "DELETE FROM databases WHERE table_name = ?1";
        let mut stmt = self.sql_tx.prepare(&qry)?;
        stmt.execute(&[&stackerdb_table(smart_contract)])?;

        let qry = format!("DROP TABLE IF EXISTS {}", stackerdb_table(smart_contract));
        let mut stmt = self.sql_tx.prepare(&qry)?;
        stmt.execute(NO_PARAMS)?;

        for (index_name, _) in CHUNKS_DB_INDEX_BODIES.iter() {
            let qry = format!(
                "DROP INDEX IF EXISTS index_{}_{}",
                stackerdb_table(smart_contract),
                index_name
            );
            let mut stmt = self.sql_tx.prepare(&qry)?;
            stmt.execute(NO_PARAMS)?;
        }

        Ok(())
    }

    /// List all stacker DB smart contracts we have available
    pub fn get_stackerdbs(&self) -> Result<Vec<ContractId>, net_error> {
        let sql = "SELECT smart_contract_id FROM databases ORDER BY table_name";
        query_rows(&self.conn(), sql, NO_PARAMS).map_err(|e| e.into())
    }

    /// Set up a database's storage slots.
    /// The slots must be in a deterministic order, since they are used to determine the chunk ID
    /// (and thus the key used to authenticate them)
    pub fn prepare_stackerdb_slots(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        slots: &[(StacksAddress, u64)],
    ) -> Result<(), net_error> {
        if slots.len() > (STACKERDB_INV_MAX as usize) {
            return Err(net_error::ArrayTooLong);
        }

        let qry = format!("REPLACE INTO {} (rc_consensus_hash,stacker,chunk_id,version,write_time,data,data_hash,signature) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", stackerdb_table(smart_contract));
        let mut stmt = self.sql_tx.prepare(&qry)?;
        let mut chunk_id = 0u32;

        for (principal, slot_count) in slots.iter() {
            for _ in 0..*slot_count {
                let args: &[&dyn ToSql] = &[
                    rc_consensus_hash,
                    &principal.to_string(),
                    &chunk_id,
                    &NO_VERSION,
                    &0,
                    &vec![],
                    &Sha512Trunc256Sum([0u8; 32]),
                    &MessageSignature::empty(),
                ];
                stmt.execute(args)?;

                chunk_id += 1;
            }
        }

        Ok(())
    }

    /// Clear a database's slots and its data
    pub fn clear_stackerdb_slots(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
    ) -> Result<(), net_error> {
        let qry = format!(
            "DELETE FROM {} WHERE rc_consensus_hash = ?1",
            stackerdb_table(smart_contract)
        );
        let mut stmt = self.sql_tx.prepare(&qry)?;

        let args: &[&dyn ToSql] = &[rc_consensus_hash];
        stmt.execute(args)?;
        Ok(())
    }

    /// Get the chunk metadata
    pub fn get_chunk_metadata(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        chunk_id: u32,
    ) -> Result<Option<ChunkMetadata>, net_error> {
        inner_get_chunk_metadata(self.conn(), smart_contract, rc_consensus_hash, chunk_id)
    }

    /// Get a chunk's validation data
    pub fn get_chunk_validation(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        chunk_id: u32,
    ) -> Result<Option<ChunkValidation>, net_error> {
        inner_get_chunk_validation(self.conn(), smart_contract, rc_consensus_hash, chunk_id)
    }

    /// Insert a chunk into the DB.
    /// It must be authenticated, and its lamport clock must be higher than the one that's already
    /// there.  These will not be checked.
    fn insert_chunk(
        &self,
        smart_contract: &ContractId,
        chunk_desc: &ChunkMetadata,
        chunk: &[u8],
    ) -> Result<(), net_error> {
        let sql = format!("UPDATE {} SET version = ?1, data_hash = ?2, signature = ?3, data = ?4, write_time = ?5 WHERE rc_consensus_hash = ?6 AND chunk_id = ?7", stackerdb_table(smart_contract));
        let mut stmt = self.sql_tx.prepare(&sql)?;

        let args: &[&dyn ToSql] = &[
            &chunk_desc.chunk_version,
            &Sha512Trunc256Sum::from_data(chunk),
            &chunk_desc.signature,
            &chunk,
            &u64_to_sql(get_epoch_time_secs())?,
            &chunk_desc.rc_consensus_hash,
            &chunk_desc.chunk_id,
        ];

        stmt.execute(args)?;
        Ok(())
    }

    /// Add or replace a chunk for a given reward cycle, if it is valid
    /// Otherwise, this errors out with Error::StaleChunk
    pub fn try_replace_chunk(
        &self,
        smart_contract: &ContractId,
        chunk_desc: &ChunkMetadata,
        chunk: &[u8],
    ) -> Result<(), net_error> {
        let chunk_validation = self
            .get_chunk_validation(
                smart_contract,
                &chunk_desc.rc_consensus_hash,
                chunk_desc.chunk_id,
            )?
            .ok_or(net_error::NoSuchChunk(
                smart_contract.clone(),
                chunk_desc.chunk_id,
            ))?;

        if !chunk_desc.verify(&chunk_validation.stacker)? {
            return Err(net_error::BadChunkSigner(
                chunk_validation.stacker,
                chunk_desc.chunk_id,
            ));
        }
        if chunk_desc.chunk_version <= chunk_validation.version {
            return Err(net_error::StaleChunk(
                chunk_validation.version,
                chunk_desc.chunk_version,
            ));
        }
        if chunk_desc.chunk_version > self.config.max_writes {
            return Err(net_error::TooManyChunkWrites(
                self.config.max_writes,
                chunk_validation.version,
            ));
        }
        if chunk_validation.write_time + self.config.write_freq >= get_epoch_time_secs() {
            return Err(net_error::TooFrequentChunkWrites(
                chunk_validation.write_time + self.config.write_freq,
            ));
        }
        self.insert_chunk(smart_contract, chunk_desc, chunk)
    }
}

impl StackerDB {
    /// Instantiate the DB
    fn instantiate(path: &str, readwrite: bool) -> Result<StackerDB, net_error> {
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
        let mut db = StackerDB { conn };

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
    pub fn connect(path: &str, readwrite: bool) -> Result<StackerDB, net_error> {
        Self::instantiate(path, readwrite)
    }

    #[cfg(test)]
    pub fn connect_memory() -> StackerDB {
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

    /// List all stacker DB smart contracts we have available
    pub fn get_stackerdbs(&self) -> Result<Vec<ContractId>, net_error> {
        let sql = "SELECT smart_contract_id FROM databases ORDER BY table_name";
        query_rows(&self.conn, sql, NO_PARAMS).map_err(|e| e.into())
    }

    /// Get the principal who signs a particular chunk in a particular stacker DB
    pub fn get_chunk_signer(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        chunk_id: u32,
    ) -> Result<Option<StacksAddress>, net_error> {
        let sql = &format!(
            "SELECT stacker FROM {} WHERE rc_consensus_hash = ?1 AND chunk_id = ?2",
            stackerdb_table(smart_contract)
        );
        let args: &[&dyn ToSql] = &[rc_consensus_hash, &chunk_id];
        query_row(&self.conn, &sql, args).map_err(|e| e.into())
    }

    /// Get the chunk metadata
    pub fn get_chunk_metadata(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        chunk_id: u32,
    ) -> Result<Option<ChunkMetadata>, net_error> {
        inner_get_chunk_metadata(&self.conn, smart_contract, rc_consensus_hash, chunk_id)
    }

    /// Get a chunk's validation data
    pub fn get_chunk_validation(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        chunk_id: u32,
    ) -> Result<Option<ChunkValidation>, net_error> {
        inner_get_chunk_validation(&self.conn, smart_contract, rc_consensus_hash, chunk_id)
    }

    /// Get the list of chunk ID versions for a given DB instance at a given reward cycle
    pub fn get_chunk_versions(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
    ) -> Result<Vec<u32>, net_error> {
        let sql = format!(
            "SELECT version FROM {} WHERE rc_consensus_hash = ?1 ORDER BY chunk_id",
            stackerdb_table(smart_contract)
        );
        let args: &[&dyn ToSql] = &[rc_consensus_hash];
        query_rows(&self.conn, &sql, args).map_err(|e| e.into())
    }

    /// Get the list of chunk ID write timestamps for a given DB instance at a given reward cycle
    pub fn get_chunk_write_timestamps(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
    ) -> Result<Vec<u64>, net_error> {
        let sql = format!(
            "SELECT write_time FROM {} WHERE rc_consensus_hash = ?1 ORDER BY chunk_id",
            stackerdb_table(smart_contract)
        );
        let args: &[&dyn ToSql] = &[rc_consensus_hash];
        query_rows(&self.conn, &sql, args).map_err(|e| e.into())
    }

    /// Get the latest chunk out of the database.
    pub fn get_latest_chunk(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        chunk_id: u32,
    ) -> Result<Vec<u8>, net_error> {
        let qry = format!(
            "SELECT data FROM {} where rc_consensus_hash = ?1 AND chunk_id = ?2",
            stackerdb_table(smart_contract)
        );
        let args: &[&dyn ToSql] = &[rc_consensus_hash, &chunk_id];

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
        Ok(data.unwrap_or(vec![]))
    }

    /// Get a versioned chunk out of this database.  If the version is not present, then None will
    /// be returned.
    pub fn get_chunk(
        &self,
        smart_contract: &ContractId,
        rc_consensus_hash: &ConsensusHash,
        chunk_id: u32,
        chunk_version: u32,
    ) -> Result<Option<StackerDBChunkData>, net_error> {
        let qry = format!("SELECT chunk_id,version,signature,data FROM {} where rc_consensus_hash = ?1 AND chunk_id = ?2 AND version = ?3", stackerdb_table(smart_contract));
        let args: &[&dyn ToSql] = &[rc_consensus_hash, &chunk_id, &chunk_version];
        query_row(&self.conn, &qry, args).map_err(|e| e.into())
    }
}
