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

use rusqlite::types::{FromSql, ToSql};
use rusqlite::{
    params, Connection, Error as SqliteError, ErrorCode as SqliteErrorCode, OptionalExtension, Row, Savepoint, NO_PARAMS
};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::db_common::tx_busy_handler;
use exec_time::exec_time;

use crate::vm::contracts::Contract;
use crate::vm::database::structures::BlockData;
use crate::vm::errors::{
    Error, IncomparableError, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};

use super::structures::{ContractAnalysisData, ContractData};

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";

pub struct SqliteConnection {
    conn: Connection,
}

fn sqlite_put_data(conn: &Connection, key: &str, value: &str) -> Result<()> {
    let params: [&dyn ToSql; 2] = [&key, &value];
    match conn.execute(
        "REPLACE INTO data_table (key, value) VALUES (?, ?)",
        &params,
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Failed to insert/replace ({},{}): {:?}", key, value, &e);
            Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into())
        }
    }
}

fn sqlite_get_data(conn: &Connection, key: &str) -> Result<Option<String>> {
    trace!("sqlite_get {}", key);
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
            Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into())
        }
    };

    trace!("sqlite_get {}: {:?}", key, &res);
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

    pub fn insert_contract(
        conn: &Connection,
        bhh: &StacksBlockId,
        block_height: u32,
        data: &ContractData
    ) -> u32 {

        let mut statement = conn.prepare_cached(
            "
            INSERT INTO contract (
                issuer, 
                name, 
                block_hash, 
                block_height, 
                source, 
                source_size, 
                source_plaintext_size, 
                data_size, 
                ast, 
                ast_size 
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            );
            "
        ).expect("Failed to prepare contract insert statement");

        let contract_id = statement.insert(
            [
                &data.contract_issuer as &dyn ToSql, 
                &data.contract_name as &dyn ToSql, 
                &bhh.0.as_slice() as &dyn ToSql, 
                &block_height as &dyn ToSql, 
                &data.source_code as &dyn ToSql, 
                &data.source_code_size as &dyn ToSql, 
                &data.raw_source_code_size as &dyn ToSql, 
                &data.data_size as &dyn ToSql, 
                &data.ast as &dyn ToSql, 
                &data.ast_size as &dyn ToSql
            ]).unwrap_or_else(|err| {
                error!("Failed to insert contract: {:?}", err);
                panic!("{}", SQL_FAIL_MESSAGE);
            });

        contract_id as u32
    }

    pub fn insert_contract_analysis(
        conn: &Connection,
        data: &ContractAnalysisData,
    ) {
        let mut statement = conn.prepare_cached(
            "
            INSERT INTO contract_analysis (
                contract_id, 
                analysis, 
                analysis_size
            ) VALUES (
                ?, ?, ?
            );
            "
            ).expect("Failed to prepare contract analysis insert statement");

        statement.insert(
            [
                &data.contract_id as &dyn ToSql, 
                &data.analysis as &dyn ToSql, 
                &data.analysis_size as &dyn ToSql
            ]).unwrap_or_else(|err| {
                error!("Failed to insert contract analysis: {:?}", err);
                panic!("{}", SQL_FAIL_MESSAGE);
            });
    }

    pub fn get_contract(
        conn: &Connection,
        contract_issuer: &str,
        contract_name: &str,
        bhh: &StacksBlockId,
    ) -> Option<ContractData> {
        let mut statement = conn.prepare_cached(
                "
                SELECT 
                    id, 
                    issuer, 
                    name, 
                    block_hash, 
                    block_height, 
                    source, 
                    source_size, 
                    source_plaintext_size, 
                    data_size, 
                    ast, 
                    ast_size 
                FROM 
                    contract 
                WHERE 
                    issuer = ? 
                    AND name = ? 
                    AND block_hash = ?
                "
            ).expect("Failed to prepare contract select statement");

        statement.query_row(
            [
                &contract_issuer as &dyn ToSql, 
                &contract_name  as &dyn ToSql, 
                &bhh.0.as_slice() as &dyn ToSql
            ],
            |row| {
                Ok(ContractData {
                    id: Some(row.get(0)?),
                    contract_issuer: row.get(1)?,
                    contract_name: row.get(2)?,
                    source_code: row.get(5)?,
                    source_code_size: row.get(6)?,
                    raw_source_code_size: row.get(7)?,
                    data_size: row.get(8)?,
                    ast: row.get(9)?,
                    ast_size: row.get(10)?,
                })
            })
            .optional()
            .unwrap_or_else(|err| {
                error!("Failed to get contract: {:?}", err);
                panic!("{}", SQL_FAIL_MESSAGE);
            })
    }

    pub fn get_contract_analysis(
        conn: &Connection,
        contract_id: u32,
    ) -> Option<ContractAnalysisData> {
        let mut statement = conn.prepare_cached(
            "
            SELECT
                contract_id,
                analysis,
                analysis_size
            FROM
                contract_analysis
            WHERE
                contract_id = ?
            ").expect("Failed to prepare contract analysis select statement");

        statement.query_row(
            [
                &contract_id as &dyn ToSql
            ],
            |row| {
                Ok(ContractAnalysisData {
                    contract_id: row.get(0)?,
                    analysis: row.get(1)?,
                    analysis_size: row.get(2)?,
                })
            }
        )
        .optional()
        .unwrap_or_else(|err| {
            error!("Failed to get contract analysis: {:?}", err);
            panic!("{}", SQL_FAIL_MESSAGE);
        })
    }

    pub fn insert_metadata(
        conn: &Connection,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 3] = [&bhh, &key, &value];

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
            return Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into());
        }
        Ok(())
    }

    pub fn commit_metadata_to(
        conn: &Connection,
        from: &StacksBlockId,
        to: &StacksBlockId,
    ) -> Result<()> {
        let params = [to, from];
        if let Err(e) = conn.execute(
            "UPDATE metadata_table SET blockhash = ? WHERE blockhash = ?",
            &params,
        ) {
            error!("Failed to update {} to {}: {:?}", &from, &to, &e);
            return Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into());
        }
        Ok(())
    }

    pub fn drop_metadata(conn: &Connection, from: &StacksBlockId) -> Result<()> {
        if let Err(e) = conn.execute("DELETE FROM metadata_table WHERE blockhash = ?", &[from]) {
            error!("Failed to drop metadata from {}: {:?}", &from, &e);
            return Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into());
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
                Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into())
            }
        }
    }

    pub fn has_entry(conn: &Connection, key: &str) -> Result<bool> {
        sqlite_has_entry(conn, key)
    }
}

impl SqliteConnection {
    pub fn initialize_conn(conn: &Connection) -> Result<()> {
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
                    block_height INTEGER NOT NULL,
                    source BINARY NOT NULL,
                    source_size INTEGER NOT NULL,
                    source_plaintext_size INTEGER NOT NULL,
                    data_size INTEGER NOT NULL,
                    ast BINARY NOT NULL,
                    ast_size INTEGER NOT NULL,
                
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

        Ok(())
    }
    
    pub fn memory() -> Result<Connection> {
        let contract_db = SqliteConnection::inner_open(":memory:")?;
        SqliteConnection::initialize_conn(&contract_db)?;

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
}
