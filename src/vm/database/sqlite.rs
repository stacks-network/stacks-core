use rusqlite::{Connection, OptionalExtension, NO_PARAMS, Row, Savepoint};
use rusqlite::types::{ToSql, FromSql};

use chainstate::burn::BlockHeaderHash;
use vm::database::{KeyValueStorage};

use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, InterpreterResult as Result, IncomparableError};

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";

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

impl KeyValueStorage for SqliteConnection {
    fn put(&mut self, key: &str, value: &str) {
        sqlite_put(&self.conn, key, value)
    }

    fn get(&mut self, key: &str) -> Option<String> {
        sqlite_get(&self.conn, key)
    }

    fn put_non_consensus(&mut self, key: &str, value: &str) {
        let key = format!("nc::{}", key);
        sqlite_put(&self.conn, &key, value)
    }

    fn get_non_consensus(&mut self, key: &str) -> Option<String> {
        let key = format!("nc::{}", key);
        sqlite_get(&self.conn, &key)
    }

    fn has_entry(&mut self, key: &str) -> bool {
        sqlite_has_entry(&self.conn, key)
    }

    fn begin(&mut self, key: &BlockHeaderHash) {
        self.conn.execute(&format!("SAVEPOINT SP{};", key.to_hex()), NO_PARAMS)
            .expect(SQL_FAIL_MESSAGE);
    }

    fn rollback(&mut self, key: &BlockHeaderHash) {
        self.conn.execute(&format!("ROLLBACK TO SAVEPOINT SP{};", key.to_hex()), NO_PARAMS)
            .expect(SQL_FAIL_MESSAGE);
    }

    fn commit(&mut self, key: &BlockHeaderHash) {
        self.conn.execute(&format!("RELEASE SAVEPOINT SP{};", key.to_hex()), NO_PARAMS)
            .expect(SQL_FAIL_MESSAGE);
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

    #[cfg(test)]
    pub fn mut_conn(&mut self) -> &mut Connection {
        &mut self.conn
    }
}
