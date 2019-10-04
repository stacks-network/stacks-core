use rusqlite::{Connection, OptionalExtension, NO_PARAMS, Row, Savepoint};
use rusqlite::types::{ToSql, FromSql};

use vm::database::{KeyValueStorage};

use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, InterpreterResult as Result, IncomparableError};

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";

pub struct SqliteStore <'a> {
    conn: &'a Connection
}

pub struct SqliteConnection {
    conn: Connection
}

fn sqlite_put(conn: &Connection, key: &str, value: &str) {
    let params: [&dyn ToSql; 2] = [&key, &value.to_string()];
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

impl <'a> KeyValueStorage for SqliteStore<'a> {
    fn put(&mut self, key: &str, value: &str) {
        sqlite_put(&self.conn, key, value)
    }

    fn get(&mut self, key: &str) -> Option<String> {
        sqlite_get(&self.conn, key)
    }

    fn has_entry(&mut self, key: &str) -> bool {
        sqlite_has_entry(&self.conn, key)
    }
}

impl KeyValueStorage for SqliteConnection {
    fn put(&mut self, key: &str, value: &str) {
        sqlite_put(&self.conn, key, value)
    }

    fn get(&mut self, key: &str) -> Option<String> {
        sqlite_get(&self.conn, key)
    }

    fn has_entry(&mut self, key: &str) -> bool {
        sqlite_has_entry(&self.conn, key)
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
