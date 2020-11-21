// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
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
    Connection, Error as SqliteError, ErrorCode as SqliteErrorCode, OptionalExtension, Row,
    Savepoint, NO_PARAMS,
};

use chainstate::stacks::StacksBlockId;

use util::db::tx_busy_handler;

use vm::contracts::Contract;
use vm::errors::{
    Error, IncomparableError, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";

pub struct SqliteConnection {
    conn: Connection,
}

fn sqlite_put(conn: &Connection, key: &str, value: &str) {
    let params: [&dyn ToSql; 2] = [&key, &value];
    match conn.execute(
        "REPLACE INTO data_table (key, value) VALUES (?, ?)",
        &params,
    ) {
        Ok(_) => {}
        Err(e) => {
            error!("Failed to insert/replace ({},{}): {:?}", key, value, &e);
            panic!(SQL_FAIL_MESSAGE);
        }
    };
}

fn sqlite_get(conn: &Connection, key: &str) -> Option<String> {
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
        Ok(x) => x,
        Err(e) => {
            error!("Failed to query '{}': {:?}", key, &e);
            panic!(SQL_FAIL_MESSAGE);
        }
    };

    trace!("sqlite_get {}: {:?}", key, &res);
    res
}
fn sqlite_has_entry(conn: &Connection, key: &str) -> bool {
    sqlite_get(conn, key).is_some()
}

impl SqliteConnection {
    pub fn put(&mut self, key: &str, value: &str) {
        sqlite_put(&self.conn, key, value)
    }

    pub fn get(&mut self, key: &str) -> Option<String> {
        sqlite_get(&self.conn, key)
    }

    pub fn insert_metadata(
        &mut self,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
        value: &str,
    ) {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 3] = [&bhh, &key, &value.to_string()];

        match self.conn.execute(
            "INSERT INTO metadata_table (blockhash, key, value) VALUES (?, ?, ?)",
            &params,
        ) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Failed to insert ({},{},{}): {:?}",
                    &bhh,
                    &key,
                    &value.to_string(),
                    &e
                );
                panic!(SQL_FAIL_MESSAGE);
            }
        }
    }

    pub fn commit_metadata_to(&mut self, from: &StacksBlockId, to: &StacksBlockId) {
        let params = [to, from];
        match self.conn.execute(
            "UPDATE metadata_table SET blockhash = ? WHERE blockhash = ?",
            &params,
        ) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to update {} to {}: {:?}", &from, &to, &e);
                panic!(SQL_FAIL_MESSAGE);
            }
        }
    }

    pub fn get_metadata(
        &mut self,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
    ) -> Option<String> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 2] = [&bhh, &key];

        match self
            .conn
            .query_row(
                "SELECT value FROM metadata_table WHERE blockhash = ? AND key = ?",
                &params,
                |row| row.get(0),
            )
            .optional()
        {
            Ok(x) => x,
            Err(e) => {
                error!("Failed to query ({},{}): {:?}", &bhh, &key, &e);
                panic!(SQL_FAIL_MESSAGE);
            }
        }
    }

    pub fn has_entry(&mut self, key: &str) -> bool {
        sqlite_has_entry(&self.conn, key)
    }

    /// begin, commit, rollback a save point identified by key
    ///    this is used to clean up any data from aborted blocks
    ///     (NOT aborted transactions that is handled by the clarity vm directly).
    /// The block header hash is used for identifying savepoints.
    ///     this _cannot_ be used to rollback to arbitrary prior block hash, because that
    ///     blockhash would already have committed and no longer exist in the save point stack.
    /// this is a "lower-level" rollback than the roll backs performed in
    ///   ClarityDatabase or AnalysisDatabase -- this is done at the backing store level.

    pub fn begin(&mut self, key: &StacksBlockId) {
        trace!("SAVEPOINT SP{}", key);
        match self
            .conn
            .execute(&format!("SAVEPOINT SP{}", key), NO_PARAMS)
        {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to begin savepoint {}: {:?}", &key, &e);
                panic!(SQL_FAIL_MESSAGE);
            }
        }
    }

    pub fn rollback(&mut self, key: &StacksBlockId) {
        trace!(
            "ROLLBACK TO SAVEPOINT SP{}; RELEASE SAVEPOINT SP{}",
            key,
            key
        );
        match self.conn.execute_batch(&format!(
            "ROLLBACK TO SAVEPOINT SP{}; RELEASE SAVEPOINT SP{}",
            key, key
        )) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Failed to rollback and release savepoint {}: {:?}",
                    &key, &e
                );
                panic!(SQL_FAIL_MESSAGE);
            }
        }
    }

    pub fn delete_unconfirmed(&mut self, key: &StacksBlockId) {
        trace!("DELETE FROM metadata_table WHERE block_hash = {}", key);
        match self
            .conn
            .execute("DELETE FROM metadata_table WHERE blockhash = ?", &[key])
        {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to delete from metadata_table {}: {:?}", &key, &e);
                panic!(SQL_FAIL_MESSAGE);
            }
        }
    }

    pub fn rollback_unconfirmed(&mut self, key: &StacksBlockId) {
        trace!(
            "ROLLBACK TO SAVEPOINT SP{}; RELEASE SAVEPOINT SP{}",
            key,
            key
        );
        match self.conn.execute_batch(&format!(
            "ROLLBACK TO SAVEPOINT SP{}; RELEASE SAVEPOINT SP{}",
            key, key
        )) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Failed to rollback and release unconfirmed savepoint {}: {:?}",
                    &key, &e
                );
                panic!(SQL_FAIL_MESSAGE);
            }
        }

        self.delete_unconfirmed(key);
    }

    pub fn commit(&mut self, key: &StacksBlockId) {
        trace!("RELEASE SAVEPOINT SP{}", key);
        match self
            .conn
            .execute(&format!("RELEASE SAVEPOINT SP{}", key), NO_PARAMS)
        {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to release savepoint {}: {:?}", &key, &e);
                panic!("PANIC: Failed to SQL commit in Smart Contract VM.");
            }
        }
    }
}

impl SqliteConnection {
    pub fn initialize(filename: &str) -> Result<Self> {
        let contract_db = Self::inner_open(filename)?;
        contract_db
            .conn
            .execute(
                "CREATE TABLE IF NOT EXISTS data_table
                      (key TEXT PRIMARY KEY, value TEXT)",
                NO_PARAMS,
            )
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        contract_db
            .conn
            .execute(
                "CREATE TABLE IF NOT EXISTS metadata_table
                      (key TEXT NOT NULL, blockhash TEXT, value TEXT,
                       UNIQUE (key, blockhash))",
                NO_PARAMS,
            )
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        contract_db.check_schema()?;

        Ok(contract_db)
    }
    pub fn memory() -> Result<Self> {
        Self::initialize(":memory:")
    }
    pub fn open(filename: &str) -> Result<Self> {
        let contract_db = Self::inner_open(filename)?;

        contract_db.check_schema()?;
        Ok(contract_db)
    }
    pub fn check_schema(&self) -> Result<()> {
        let sql = "SELECT sql FROM sqlite_master WHERE name=?";
        let _: String = self
            .conn
            .query_row(sql, &["data_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
        let _: String = self
            .conn
            .query_row(sql, &["metadata_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
        Ok(())
    }

    pub fn inner_open(filename: &str) -> Result<Self> {
        let conn = Connection::open(filename)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.busy_handler(Some(tx_busy_handler))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Ok(SqliteConnection { conn })
    }

    #[cfg(test)]
    pub fn mut_conn(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

#[cfg(test)]
#[test]
#[should_panic(expected = "Failed to SQL commit")]
fn test_rollback() {
    let mut conn = SqliteConnection::memory().unwrap();
    let bhh = StacksBlockId([1; 32]);
    conn.begin(&bhh);
    conn.rollback(&bhh);
    conn.commit(&bhh); // shouldn't be on the stack!
}
