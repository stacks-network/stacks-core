use rusqlite::{ErrorCode as SqliteErrorCode, Error as SqliteError, Connection, OptionalExtension, NO_PARAMS, Row, Savepoint};
use rusqlite::types::{ToSql, FromSql};

use chainstate::burn::BlockHeaderHash;

use util::db::tx_busy_handler;

use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, InterpreterResult as Result, IncomparableError};

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";

pub struct SqliteConnection {
    conn: Connection
}

fn sqlite_put(conn: &Connection, key: &str, value: &str) {
    let params: [&dyn ToSql; 2] = [&key, &value];
    conn.execute("REPLACE INTO data_table (key, value) VALUES (?, ?)",
                      &params)
        .expect(SQL_FAIL_MESSAGE);
}

fn sqlite_get(conn: &Connection, key: &str) -> Option<String> {
    let params: [&dyn ToSql; 1] = [&key];
    conn.query_row(
        "SELECT value FROM data_table WHERE key = ?",
        &params,
        |row| row.get(0))
        .optional()
        .expect(SQL_FAIL_MESSAGE)
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

    pub fn insert_metadata(&mut self, bhh: &BlockHeaderHash, contract_hash: &str, key: &str, value: &str) {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 3] = [&bhh, &key, &value.to_string()];

        self.conn.execute("INSERT INTO metadata_table (blockhash, key, value) VALUES (?, ?, ?)", &params)
            .expect(SQL_FAIL_MESSAGE);
    }

    pub fn commit_metadata_to(&mut self, from: &BlockHeaderHash, to: &BlockHeaderHash) {
        let params = [to, from];
        self.conn.execute(
            "UPDATE metadata_table SET blockhash = ? WHERE blockhash = ?",
            &params)
            .expect(SQL_FAIL_MESSAGE);
    }

    pub fn get_metadata(&mut self, bhh: &BlockHeaderHash, contract_hash: &str, key: &str) -> Option<String> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 2] = [&bhh, &key];

        self.conn.query_row(
            "SELECT value FROM metadata_table WHERE blockhash = ? AND key = ?",
            &params,
            |row| row.get(0))
            .optional()
            .expect(SQL_FAIL_MESSAGE)
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

    pub fn begin(&mut self, key: &BlockHeaderHash) {
        self.conn.execute(&format!("SAVEPOINT SP{}", key), NO_PARAMS)
            .expect(SQL_FAIL_MESSAGE);
    }

    pub fn rollback(&mut self, key: &BlockHeaderHash) {
        self.conn.execute_batch(&format!("ROLLBACK TO SAVEPOINT SP{}; RELEASE SAVEPOINT SP{}", key, key))
            .expect(SQL_FAIL_MESSAGE);
    }

    pub fn commit(&mut self, key: &BlockHeaderHash) {
        self.conn.execute(&format!("RELEASE SAVEPOINT SP{}", key), NO_PARAMS)
            .expect("PANIC: Failed to SQL commit in Smart Contract VM.");
    }
}


impl SqliteConnection {
    pub fn initialize(filename: &str) -> Result<Self> {
        let contract_db = Self::inner_open(filename)?;
        contract_db.conn.execute("CREATE TABLE IF NOT EXISTS data_table
                      (key TEXT PRIMARY KEY, value TEXT)", NO_PARAMS)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError{ err: x }))?;

        contract_db.conn.execute("CREATE TABLE IF NOT EXISTS metadata_table
                      (key TEXT NOT NULL, blockhash TEXT, value TEXT,
                       UNIQUE (key, blockhash))", NO_PARAMS)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError{ err: x }))?;

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
        let _: String = self.conn.query_row(sql, &["data_table"],
                                            |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError{ err: x }))?;
        let _: String = self.conn.query_row(sql, &["metadata_table"],
                                            |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError{ err: x }))?;
        Ok(())
    }

    pub fn inner_open(filename: &str) -> Result<Self> {
        let conn = Connection::open(filename)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError{ err: x }))?;
        
        conn.busy_handler(Some(tx_busy_handler))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError{ err: x }))?;

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
    let bhh = BlockHeaderHash([1; 32]);
    conn.begin(&bhh);
    conn.rollback(&bhh);
    conn.commit(&bhh); // shouldn't be on the stack!
}
