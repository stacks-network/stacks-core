use rusqlite::{Connection, NO_PARAMS, TransactionBehavior, ToSql};
use stacks_common::{debug, error};

use crate::SqliteTrieDb;
use stacks_marf::{Result, MarfError};

pub static SQL_MARF_SCHEMA_VERSION: u64 = 2;

pub static SQL_MARF_DATA_TABLE: &str = "
CREATE TABLE IF NOT EXISTS marf_data (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   -- the trie itself.
   -- if not used, then set to a zero-byte entry.
   data BLOB NOT NULL,
   unconfirmed INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_marf_data ON marf_data(block_hash);
CREATE INDEX IF NOT EXISTS unconfirmed_marf_data ON marf_data(unconfirmed);
";

pub static SQL_MARF_MINED_TABLE: &str = "
CREATE TABLE IF NOT EXISTS mined_blocks (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   data BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_mined_blocks ON mined_blocks(block_hash);
";

pub static SQL_EXTENSION_LOCKS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS block_extension_locks (block_hash TEXT PRIMARY KEY);
";

pub static SQL_MARF_DATA_TABLE_SCHEMA_2: &str = "
-- pointer to a .blobs file with the externally-stored blob data.
-- if not used, then set to 1.
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER DEFAULT 1 NOT NULL
);
CREATE TABLE IF NOT EXISTS migrated_version (
    version INTEGER DEFAULT 1 NOT NULL
);
ALTER TABLE marf_data ADD COLUMN external_offset INTEGER DEFAULT 0 NOT NULL;
ALTER TABLE marf_data ADD COLUMN external_length INTEGER DEFAULT 0 NOT NULL;
CREATE INDEX IF NOT EXISTS index_external_offset ON marf_data(external_offset);

INSERT OR REPLACE INTO schema_version (version) VALUES (2);
INSERT OR REPLACE INTO migrated_version (version) VALUES (1);
";

impl SqliteTrieDb {
    pub fn create_tables_if_needed(conn: &mut Connection) -> Result<()> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
    
        tx.execute_batch(SQL_MARF_DATA_TABLE)
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
        tx.execute_batch(SQL_MARF_MINED_TABLE)
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
        tx.execute_batch(SQL_EXTENSION_LOCKS_TABLE)
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
    
        tx.commit().map_err(|e| MarfError::SQLError(e.to_string()))
    }
    
    fn get_schema_version(conn: &Connection) -> u64 {
        // if the table doesn't exist, then the version is 1.
        let sql = "SELECT version FROM schema_version";
        match conn.query_row(sql, NO_PARAMS, |row| row.get::<_, i64>("version")) {
            Ok(x) => x as u64,
            Err(e) => {
                debug!("Failed to get schema version: {:?}", &e);
                1u64
            }
        }
    }
    
    /// Get the last schema version before the last attempted migration
    fn get_migrated_version(conn: &Connection) -> u64 {
        // if the table doesn't exist, then the version is 1.
        let sql = "SELECT version FROM migrated_version";
        match conn.query_row(sql, NO_PARAMS, |row| row.get::<_, i64>("version")) {
            Ok(x) => x as u64,
            Err(e) => {
                debug!("Failed to get schema version: {:?}", &e);
                1u64
            }
        }
    }

    /// Do we have a partially-migrated database?
    /// Either all tries have offset and length 0, or they all don't.  If we have a mixture, then we're
    /// corrupted.
    pub fn detect_partial_migration(conn: &Connection) -> Result<bool> {
        let migrated_version = Self::get_migrated_version(conn);
        let schema_version = Self::get_schema_version(conn);
        if migrated_version == schema_version {
            return Ok(false);
        }

        let num_migrated = Self::query_count(
            conn,
            "SELECT COUNT(*) FROM marf_data WHERE external_offset = 0 AND external_length = 0 AND unconfirmed = 0",
            NO_PARAMS,
        )?;
        let num_not_migrated = Self::query_count(
            conn,
            "SELECT COUNT(*) FROM marf_data WHERE external_offset != 0 AND external_length != 0 AND unconfirmed = 0",
            NO_PARAMS,
        )?;
        Ok(num_migrated > 0 && num_not_migrated > 0)
    }

    pub fn query_count<P>(conn: &Connection, sql_query: &str, sql_args: P) -> Result<i64>
    where
        P: IntoIterator,
        P::Item: ToSql,
    {
        Self::query_int(conn, sql_query, sql_args)
    }

    /// Boilerplate for querying a single integer (first and only item of the query must be an int)
    pub fn query_int<P>(conn: &Connection, sql_query: &str, sql_args: P) -> Result<i64>
    where
        P: IntoIterator,
        P::Item: ToSql,
    {
        Self::log_sql_eqp(conn, sql_query);
        let mut stmt = conn.prepare(sql_query)
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
        let mut rows = stmt.query(sql_args)
            .map_err(|e| MarfError::DbError(e.to_string()))?;
        let mut row_data = vec![];
        while let Some(row) = rows.next().map_err(|e| MarfError::SQLError(e.to_string()))? {
            if row_data.len() > 0 {
                return Err(MarfError::DbError("overflow; expected only one row".to_string()));
            }
            let i: i64 = row.get_unwrap(0);
            row_data.push(i);
        }

        if row_data.len() == 0 {
            return Err(MarfError::NotFoundError);
        }

        Ok(row_data[0])
    }

    /// Mark a migration as completed
    pub fn set_migrated(conn: &Connection) -> Result<()> {
        conn.execute(
            "UPDATE migrated_version SET version = ?1",
            &[&Self::u64_to_sql(SQL_MARF_SCHEMA_VERSION)?],
        )
        .map_err(|e| MarfError::SQLError(e.to_string()))
        .and_then(|_| Ok(()))
    }

    pub fn u64_to_sql(x: u64) -> Result<i64> {
        if x > (i64::MAX as u64) {
            return Err(MarfError::DbError("error converting u64 to i64".to_string()));
        }
        Ok(x as i64)
    }
    
    /// Migrate the MARF database to the currently-supported schema.
    /// Returns the version of the DB prior to the migration.
    pub fn migrate_tables_if_needed(conn: &mut Connection) -> Result<u64> {
        let first_version = Self::get_schema_version(conn);
        loop {
            let version = Self::get_schema_version(conn);
            match version {
                1 => {
                    debug!("Migrate MARF data from schema 1 to schema 2");
    
                    // add external_* fields
                    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(|e| MarfError::SQLError(e.to_string()))?;
                    tx.execute_batch(SQL_MARF_DATA_TABLE_SCHEMA_2)
                        .map_err(|e| MarfError::SQLError(e.to_string()))?;
                    tx.commit()
                        .map_err(|e| MarfError::SQLError(e.to_string()))?;
                }
                x if x == SQL_MARF_SCHEMA_VERSION => {
                    // done
                    debug!("Migrated MARF data to schema {}", &SQL_MARF_SCHEMA_VERSION);
                    break;
                }
                x => {
                    let msg = format!(
                        "Unable to migrate MARF data table: unrecognized schema {}",
                        x
                    );
                    error!("{}", &msg);
                    panic!("{}", &msg);
                }
            }
        }
        if first_version == SQL_MARF_SCHEMA_VERSION
            && Self::get_migrated_version(conn) != SQL_MARF_SCHEMA_VERSION
            && !Self::detect_partial_migration(conn)?
        {
            // no migration will need to happen, so stop checking
            debug!("Marking MARF data as fully-migrated");
            Self::set_migrated(conn)?;
        }
        Ok(first_version)
    }

    /// Generate debug output to be fed into an external script to examine query plans.
    /// TODO: it uses mocked arguments, which it assumes are strings. This does not always result in a
    /// valid query.
    #[cfg(test)]
    fn log_sql_eqp(conn: &Connection, sql_query: &str) {
        if std::env::var("BLOCKSTACK_DB_TRACE") != Ok("1".to_string()) {
            return;
        }

        let mut parts = sql_query.clone().split(" ");
        let mut full_sql = if let Some(part) = parts.next() {
            part.to_string()
        } else {
            sql_query.to_string()
        };

        while let Some(part) = parts.next() {
            if part.starts_with("?") {
                full_sql = format!("{} \"mock_arg\"", full_sql.trim());
            } else {
                full_sql = format!("{} {}", full_sql.trim(), part.trim());
            }
        }

        let path = Self::get_db_path(conn).unwrap_or("ERROR!".to_string());
        let eqp_sql = format!("\"{}\" EXPLAIN QUERY PLAN {}", &path, full_sql.trim());
        debug!("{}", &eqp_sql);
    }

    #[cfg(not(test))]
    fn log_sql_eqp(_conn: &Connection, _sql_query: &str) {}

    /// Load the path of the database from the connection
    #[cfg(test)]
    fn get_db_path(conn: &Connection) -> Result<String> {
        let sql = "PRAGMA database_list";
        let path: std::result::Result<Option<String>, rusqlite::Error> =
            conn.query_row_and_then(sql, NO_PARAMS, |row| row.get(2));
        match path {
            Ok(Some(path)) => Ok(path),
            Ok(None) => Ok("<unknown>".to_string()),
            Err(e) => Err(MarfError::SQLError(e.to_string())),
        }
    }
}