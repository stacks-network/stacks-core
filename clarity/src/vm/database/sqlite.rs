// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::cell::RefCell;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use lazy_static::lazy_static;
use rand::{thread_rng, Rng};
use rusqlite::types::{FromSql, ToSql};
use rusqlite::{
    params, Connection, DatabaseName, Error as SqliteError, ErrorCode as SqliteErrorCode,
    OptionalExtension, Row, Savepoint, NO_PARAMS,
};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::db_common::tx_busy_handler;
use stacks_common::util::hash::{hex_bytes, to_hex};

use super::structures::{
    ClarityDeserializable, ContractAnalysisData, ContractData, ContractSizeData,
};
use crate::vm::analysis::ContractAnalysis;
use crate::vm::contracts::Contract;
use crate::vm::database::structures::BlockData;
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::{
    Error, IncomparableError, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use crate::vm::ContractContext;

lazy_static! {
    static ref INIT_LOOKUP: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

pub struct SqliteConnection {
    conn: Connection,
}

fn sqlite_put_data(conn: &Connection, key: &str, value: &str) -> Result<()> {
    //trace!("sqlite_put_data: {} -> {}", key, value);
    let params: [&dyn ToSql; 2] = [&key, &value];
    match conn.execute(
        "REPLACE INTO data_table (key, value) VALUES (?, ?)",
        &params,
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Failed to insert/replace ({},{}): {:?}", key, value, &e);
            Err(InterpreterError::SqliteError(IncomparableError { err: e }).into())
        }
    }
}

fn sqlite_get_data(conn: &Connection, key: &str) -> Result<Option<String>> {
    //trace!("sqlite_get_data: {}", key);
    let params: [&dyn ToSql; 1] = [&key];
    let res = match conn
        .query_row(
            "SELECT value FROM data_table WHERE key = ?",
            &params,
            |row| row.get(0),
        )
        .optional()
    {
        Ok(x) => Ok(x),
        Err(e) => {
            error!("Failed to query '{}': {:?}", key, &e);
            Err(InterpreterError::SqliteError(IncomparableError { err: e }).into())
        }
    };

    //trace!(" -> {:?}", &res);
    //trace!("sqlite_get {}: {:?}", key, &res);
    res
}

fn sqlite_has_entry(conn: &Connection, key: &str) -> Result<bool> {
    Ok(sqlite_get_data(conn, key)?.is_some())
}

impl SqliteConnection {
    pub fn put_data(conn: &Connection, key: &str, value: &str) -> Result<()> {
        sqlite_put_data(conn, key, value)
    }

    pub fn get_data(conn: &Connection, key: &str) -> Result<Option<String>> {
        sqlite_get_data(conn, key)
    }

    pub fn get_contract_sizes(
        conn: &Connection,
        issuer: &str,
        name: &str,
        bhh: &StacksBlockId,
    ) -> Result<ContractSizeData> {
        // #[cfg(feature = "testing")]
        // Self::print_contracts(conn)?;

        let mut statement = conn.prepare_cached(
            "
            SELECT 
                source_size,
                data_size,
                contract_size
            FROM 
                contract 
            WHERE 
                issuer = ? 
                AND name = ? 
                AND block_hash = ?
            ",
        )?;

        let result = statement.query_row(
            [
                &issuer as &dyn ToSql,
                &name as &dyn ToSql,
                &bhh.0.to_vec() as &dyn ToSql,
            ],
            |row| {
                Ok(ContractSizeData {
                    source_size: row.get(0)?,
                    data_size: row.get(1)?,
                    contract_size: row.get(2)?,
                })
            },
        )?;

        Ok(result)
    }

    /// Checks if a contract exists which was deployed at the given block height
    /// and has the given issuer and name.
    pub fn contract_exists(
        conn: &Connection,
        issuer: &str,
        name: &str,
        bhh: &StacksBlockId,
    ) -> Result<bool> {
        let mut statement = conn.prepare_cached(
            "
            SELECT EXISTS(
                SELECT 
                    1 
                FROM 
                    contract 
                WHERE 
                    issuer = ? 
                    AND name = ? 
                    AND block_hash = ?
            );
            ",
        )?;

        let result = statement.query_row(
            [
                &issuer as &dyn ToSql,
                &name as &dyn ToSql,
                &bhh.0.to_vec() as &dyn ToSql,
            ],
            |row| Ok(row.get::<_, u32>(0)?),
        )?;

        Ok(result == 1)
    }

    pub fn get_internal_contract_id(
        conn: &Connection,
        issuer: &str,
        name: &str,
        bhh: &StacksBlockId,
    ) -> Result<Option<u32>> {
        let mut statement = conn.prepare_cached(
            "
            SELECT 
                id
            FROM 
                contract 
            WHERE 
                issuer = ? 
                AND name = ? 
                AND block_hash = ?
            ",
        )?;

        let result = statement
            .query_row(
                [
                    &issuer as &dyn ToSql,
                    &name as &dyn ToSql,
                    &bhh.0.to_vec() as &dyn ToSql,
                ],
                |row| Ok(row.get::<_, u32>(0)?),
            )
            .optional()?;

        Ok(result)
    }

    pub fn insert_contract(
        conn: &Connection,
        bhh: &StacksBlockId,
        data: &mut ContractData,
    ) -> Result<()> {
        let mut statement = conn.prepare_cached(
            "
            INSERT INTO contract (
                issuer, 
                name, 
                block_hash, 
                source, 
                source_size, 
                data_size, 
                contract, 
                contract_size,
                contract_hash
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT (issuer, name, block_hash) DO NOTHING
            ",
        )?;

        let contract_id = match statement.insert([
            &data.issuer as &dyn ToSql,
            &data.name as &dyn ToSql,
            &bhh.0.to_vec() as &dyn ToSql,
            &data.source as &dyn ToSql,
            &data.source_size as &dyn ToSql,
            &data.data_size as &dyn ToSql,
            &data.contract as &dyn ToSql,
            &data.contract_size as &dyn ToSql,
            &data.contract_hash as &dyn ToSql,
        ]) {
            Ok(x) => x,
            // Err(SqliteError::StatementChangedRows(0)) => {
            //     warn!(
            //         "Contract already exists (replaced): {} {} {}",
            //         &data.issuer, &data.name, &bhh
            //     );
            //     Self::get_internal_contract_id(conn, &data.issuer, &data.name, bhh)?
            //         .expect("Contract was updated but the id was not returned")
            //         .into()
            // }
            Err(e) => {
                error!("Failed to insert contract: {:?}", &e);
                return Err(InterpreterError::SqliteError(IncomparableError { err: e }).into());
            }
        };

        data.id = contract_id as u32;

        Ok(())
    }

    pub fn insert_contract_analysis(
        conn: &Connection,
        contract_id: u32,
        data: &[u8],
        size: usize,
    ) -> Result<()> {
        let mut statement = conn.prepare_cached(
            "
            INSERT INTO contract_analysis (
                contract_id, 
                analysis, 
                analysis_size
            ) VALUES (
                ?, 
                ?, 
                ?
            );
            ",
        )?;

        statement.insert([&contract_id, &data as &dyn ToSql, &(size as u32)])?;

        Ok(())
    }

    pub fn get_contract(
        conn: &Connection,
        contract_issuer: &str,
        contract_name: &str,
        bhh: &StacksBlockId,
    ) -> Result<Option<ContractData>> {
        let mut statement = conn.prepare_cached(
            "
                SELECT 
                    id, 
                    issuer, 
                    name, 
                    block_hash, 
                    source, 
                    source_size,
                    data_size, 
                    contract, 
                    contract_size,
                    contract_hash
                FROM 
                    contract 
                WHERE 
                    issuer = ? 
                    AND name = ? 
                    AND block_hash = ?
                ",
        )?;

        let result = statement
            .query_row(
                [
                    &contract_issuer as &dyn ToSql,
                    &contract_name as &dyn ToSql,
                    &bhh.0.to_vec() as &dyn ToSql,
                ],
                |row| {
                    Ok(ContractData {
                        id: row.get(0)?,
                        issuer: row.get(1)?,
                        name: row.get(2)?,
                        source: row.get(4)?,
                        source_size: row.get(5)?,
                        data_size: row.get(6)?,
                        contract: row.get(7)?,
                        contract_size: row.get(8)?,
                        contract_hash: row.get(9)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    pub fn get_contract_analysis(
        conn: &Connection,
        contract_id: u32,
    ) -> Result<Option<ContractAnalysisData>> {
        let mut statement = conn
            .prepare_cached(
                "
            SELECT
                contract_id,
                analysis,
                analysis_size
            FROM
                contract_analysis
            WHERE
                contract_id = ?
            ",
            )
            .expect("Failed to prepare contract analysis select statement");

        let result = statement
            .query_row([&contract_id], |row| {
                Ok(ContractAnalysisData {
                    contract_id: row.get(0)?,
                    analysis: row.get(1)?,
                    analysis_size: row.get(2)?,
                })
            })
            .optional()?;

        Ok(result)
    }

    pub fn insert_metadata(
        conn: &Connection,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 3] = [bhh, &key, &value];

        if let Err(e) = conn.execute(
            "INSERT INTO metadata_table (blockhash, key, value) VALUES (?, ?, ?)",
            &params,
        ) {
            error!(
                "Failed to insert ({},{},{}): {:?}",
                &bhh,
                &key,
                &value.to_string(),
                &e
            );
            return Err(InterpreterError::SqliteError(IncomparableError { err: e }).into());
        }
        Ok(())
    }

    pub fn commit_metadata_to(
        conn: &Connection,
        from: &StacksBlockId,
        to: &StacksBlockId,
    ) -> Result<()> {
        if from == to {
            return Ok(());
        }

        let params = [to, from];

        let mut statement =
            conn.prepare_cached("UPDATE metadata_table SET blockhash = ? WHERE blockhash = ?")?;

        if let Err(e) = statement.execute(&params) {
            error!("Failed to update {} to {}: {:?}", &from, &to, &e);
            return Err(InterpreterError::SqliteError(IncomparableError { err: e }).into());
        }

        Self::commit_contracts_to(conn, from, to)
    }

    pub fn commit_contracts_to(
        conn: &Connection,
        from: &StacksBlockId,
        to: &StacksBlockId,
    ) -> Result<()> {
        match conn.execute(
            "UPDATE contract SET block_hash = ? WHERE block_hash = ?",
            &[to.0.to_vec(), from.0.to_vec()],
        ) {
            Ok(rows_updated) => {
                trace!("updated {} contracts from {} to {}", rows_updated, from, to);
            }
            Err(e) => {
                error!("Failed to update {} to {}: {:?}", &from, &to, &e);
                return Err(InterpreterError::SqliteError(IncomparableError { err: e }).into());
            }
        }

        Ok(())
    }

    pub fn drop_metadata(conn: &Connection, from: &StacksBlockId) -> Result<()> {
        if let Err(e) = conn.execute("DELETE FROM metadata_table WHERE blockhash = ?", &[from]) {
            error!("Failed to drop metadata from {}: {:?}", &from, &e);
            return Err(InterpreterError::SqliteError(IncomparableError { err: e }).into());
        }

        Self::delete_contracts_for_block(conn, from)
    }

    pub fn delete_contracts_for_block(conn: &Connection, bhh: &StacksBlockId) -> Result<()> {
        if let Err(e) = conn.execute(
            "DELETE FROM contract_analysis WHERE contract_id IN (SELECT id FROM contract WHERE block_hash = ?)",
            &[bhh.0.to_vec()],
        ) {
            error!("Failed to delete contract analysis for {}: {:?}", bhh, &e);
            return Err(InterpreterError::SqliteError(IncomparableError { err: e }).into());
        }

        if let Err(e) = conn.execute(
            "DELETE FROM contract WHERE block_hash = ?",
            &[bhh.0.to_vec()],
        ) {
            error!("Failed to delete contracts for {}: {:?}", bhh, &e);
            return Err(InterpreterError::SqliteError(IncomparableError { err: e }).into());
        }

        Ok(())
    }

    pub fn get_metadata(
        conn: &Connection,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
    ) -> Result<Option<String>> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 2] = [&bhh, &key];

        match conn
            .query_row(
                "SELECT value FROM metadata_table WHERE blockhash = ? AND key = ?",
                &params,
                |row| row.get(0),
            )
            .optional()
        {
            Ok(x) => Ok(x),
            Err(e) => {
                error!("Failed to query ({},{}): {:?}", &bhh, &key, &e);
                Err(InterpreterError::SqliteError(IncomparableError { err: e }).into())
            }
        }
    }

    pub fn has_entry(conn: &Connection, key: &str) -> Result<bool> {
        sqlite_has_entry(conn, key)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn contract_count(conn: &Connection) -> u32 {
        let mut statement = conn
            .prepare_cached("SELECT COUNT(*) FROM contract")
            .expect("Failed to prepare contract count statement");
        let result = statement
            .query_row(NO_PARAMS, |row| Ok(row.get::<_, u32>(0)?))
            .expect("Failed to query contract count");
        result
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn analysis_count(conn: &Connection) -> u32 {
        let mut statement = conn
            .prepare_cached("SELECT COUNT(*) FROM contract_analysis")
            .expect("Failed to prepare contract analysis count statement");
        let result = statement
            .query_row(NO_PARAMS, |row| Ok(row.get::<_, u32>(0)?))
            .expect("Failed to query contract analysis count");
        result
    }
}

impl SqliteConnection {
    pub fn initialize_conn(conn: &Connection, path_str: &str) -> Result<()> {
        let version = conn
            .query_row("SELECT * FROM pragma_user_version;", NO_PARAMS, |row| {
                let version: i64 = row.get(0)?;
                Ok(version)
            })
            .expect("failed to get user version");

        if version > 0 {
            trace!("clarity sqlite database already initialized: {}", path_str);
            return Ok(());
        }
        debug!("initializing clarity sqlite database: {}", path_str);

        conn.query_row("PRAGMA journal_mode = WAL;", NO_PARAMS, |_row| Ok(()))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS data_table
                      (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;",
            NO_PARAMS,
        )
        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata_table
                      (key TEXT NOT NULL, blockhash TEXT, value TEXT,
                       PRIMARY KEY (key, blockhash)) WITHOUT ROWID;",
            NO_PARAMS,
        )
        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.execute(
            "
                CREATE TABLE IF NOT EXISTS contract (
                    id INTEGER PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    name TEXT NOT NULL,
                    block_hash BINARY NOT NULL,
                    source BINARY NOT NULL,
                    source_size INTEGER NOT NULL,
                    data_size INTEGER NOT NULL,
                    contract BINARY NOT NULL,
                    contract_size INTEGER NOT NULL,
                    contract_hash BINARY NOT NULL,
                
                    UNIQUE (issuer, name, block_hash)
                );
                ",
            NO_PARAMS,
        )
        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.execute(
            "
                CREATE TABLE IF NOT EXISTS contract_analysis (
                    contract_id INTEGER PRIMARY KEY,
                    analysis BINARY NOT NULL,
                    analysis_size INTEGER NOT NULL,

                    CONSTRAINT fk_contract_id
                        FOREIGN KEY (contract_id)
                        REFERENCES contract (id)
                );
                ",
            NO_PARAMS,
        )
        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Self::check_schema(conn)?;
        Self::check_migrate_contracts(conn)?;

        conn.execute("PRAGMA user_version = 1;", NO_PARAMS)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Ok(())
    }

    pub fn memory() -> Result<Connection> {
        let mut contract_db = SqliteConnection::inner_open(":memory:")?;
        SqliteConnection::initialize_conn(
            &mut contract_db,
            &format!(":memory:{}", thread_rng().gen_range(100000..999999)),
        )?;

        Ok(contract_db)
    }

    pub fn open(filename: &str) -> Result<Connection> {
        let contract_db = SqliteConnection::inner_open(filename)?;
        SqliteConnection::check_schema(&contract_db)?;

        Ok(contract_db)
    }

    pub fn check_schema(conn: &Connection) -> Result<()> {
        let sql = "SELECT sql FROM sqlite_master WHERE name=?";

        let _: String = conn
            .query_row(sql, &["data_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        let _: String = conn
            .query_row(sql, &["metadata_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        let _: String = conn
            .query_row(sql, &["contract"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        let _: String = conn
            .query_row(sql, &["contract_analysis"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Ok(())
    }

    pub fn inner_open(filename: &str) -> Result<Connection> {
        let conn = Connection::open(filename)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.set_prepared_statement_cache_capacity(1000);
        conn.pragma_update(None, "cache_size", &-8000 as &dyn ToSql)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.busy_handler(Some(tx_busy_handler))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Ok(conn)
    }

    pub fn check_migrate_contracts(conn: &Connection) -> Result<()> {
        let contracts_in_metadata_table: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM metadata_table WHERE key LIKE '%::contract'",
                NO_PARAMS,
                |row| row.get(0),
            )
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        if contracts_in_metadata_table == 0 {
            return Ok(());
        }

        info!("Migrating {contracts_in_metadata_table} contracts from metadata_table to contract table");

        let mut statement = conn.prepare_cached(
            "SELECT blockhash, key, value FROM metadata_table WHERE key LIKE '%::contract' ORDER BY key ASC"
        )?;

        let mut results = statement.query(NO_PARAMS)?;
        while let Some(row) = results.next()? {
            let blockhash: String = row.get(0)?;
            let key: String = row.get(1)?;
            let value: String = row.get(2)?;

            let split = key.split("::").collect::<Vec<&str>>();
            let contract_data: Contract =
                Contract::deserialize(&value).expect("Failed to deserialize contract data");

            let issuer = split[1].to_string();
            let name = split[2].to_string();
            let key_prefix = format!("clr-meta::{}::{}::vm-metadata::9", &issuer, &name);

            let mut contract_migration_dto = ContractMigrationDto {
                block_hash: hex_bytes(&blockhash).expect("Failed to decode blockhash"),
                issuer: issuer.clone(),
                name: name.clone(),
                contract: contract_data,
                source: None,
                analysis: None,
                data_size: None,
            };

            let source_str: String = conn
                .query_row(
                    "SELECT value FROM metadata_table WHERE blockhash = ? AND key = ?",
                    &[&blockhash, &format!("{}::contract-src", &key_prefix)],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_else(|| {
                    panic!("Failed to get source for contract: {} {}", &issuer, &name)
                });
            contract_migration_dto.source = Some(source_str);

            let data_size: u32 = conn
                .query_row(
                    "SELECT value FROM metadata_table WHERE blockhash = ? AND key = ?",
                    &[&blockhash, &format!("{}::contract-data-size", &key_prefix)],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or_else(|| {
                    panic!(
                        "Failed to get data size for contract: {} {}",
                        &issuer, &name
                    )
                });
            contract_migration_dto.data_size = Some(data_size);

            let analysis = conn
                .query_row(
                    "SELECT value FROM metadata_table WHERE blockhash = ? AND key = ?",
                    &[
                        &blockhash,
                        &format!("clr-meta::{}::{}::analysis", &issuer, &name),
                    ],
                    |row| {
                        let analysis: String = row.get(0)?;
                        let analysis = ContractAnalysis::deserialize(&analysis)
                            .expect("msg: Failed to deserialize contract analysis");
                        Ok(analysis)
                    },
                )
                .optional()?
                .unwrap_or_else(|| {
                    panic!("Failed to get analysis for contract: {} {}", &issuer, &name)
                });
            contract_migration_dto.analysis = Some(analysis);
        }

        Ok(())
    }
}

struct ContractMigrationDto {
    block_hash: Vec<u8>,
    issuer: String,
    name: String,
    contract: Contract,
    source: Option<String>,
    analysis: Option<ContractAnalysis>,
    data_size: Option<u32>,
}
