use rusqlite::{Connection, OptionalExtension, NO_PARAMS, Row, Savepoint};
use rusqlite::types::{ToSql, FromSql};

use vm::database::{KeyType, KeyValueStorage};

use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, UncheckedError, InterpreterResult as Result, IncomparableError};

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";
const DESERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in Smart Contract VM.";

pub struct SqliteStore <'a> {
    conn: &'a Connection
}

pub struct SqliteConnection {
    conn: Connection
}

impl <'a> KeyValueStorage for SqliteStore<'a> {
    fn put(&mut self, key: &KeyType, value: &str) {
        let params: [&ToSql; 2] = [&key.to_vec(), &value.to_string()];
        self.conn.execute("REPLACE INTO data_table (key, value) VALUES (?, ?)",
                          &params)
            .expect(SQL_FAIL_MESSAGE);
    }

    fn get(&mut self, key: &KeyType) -> Option<String> {
        let params: [&ToSql; 1] = [&key.to_vec()];
        self.conn.query_row(
            "SELECT value FROM data_table WHERE key = ?",
            &params,
            |row| row.get(0))
            .optional()
            .expect(SQL_FAIL_MESSAGE)
    }

    fn has_entry(&mut self, key: &KeyType) -> bool {
        self.get(key).is_some()
    }
}

impl KeyValueStorage for SqliteConnection {
    fn put(&mut self, key: &KeyType, value: &str) {
        let params: [&ToSql; 2] = [&key.to_vec(), &value.to_string()];
        self.conn.execute("REPLACE INTO data_table (key, value) VALUES (?, ?)",
                          &params)
            .expect(SQL_FAIL_MESSAGE);
    }

    fn get(&mut self, key: &KeyType) -> Option<String> {
        let params: [&ToSql; 1] = [&key.to_vec()];
        self.conn.query_row(
            "SELECT value FROM data_table WHERE key = ?",
            &params,
            |row| row.get(0))
            .optional()
            .expect(SQL_FAIL_MESSAGE)
    }

    fn has_entry(&mut self, key: &KeyType) -> bool {
        self.get(key).is_some()
    }
}

impl <'a> SqliteStore <'a> {
    pub fn new(conn: &'a Connection) -> SqliteStore<'a> {
        SqliteStore { conn }
    }
}

impl SqliteConnection {
    pub fn initialize(filename: &str) -> Result<Self> {
        let contract_db = Self::inner_open(filename)?;
        contract_db.conn.execute("CREATE TABLE IF NOT EXISTS data_table
                      (key TEXT PRIMARY KEY, value TEXT)", NO_PARAMS)
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
        Ok(())
    }

    pub fn inner_open(filename: &str) -> Result<Self> {
        let conn = Connection::open(filename)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError{ err: x }))?;
        Ok(SqliteConnection { conn })
    }

    pub fn begin_save_point_raw<'a>(&'a mut self) -> Savepoint<'a> {
        self.conn.savepoint().unwrap()
    }
}
