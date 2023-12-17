use std::{path::{PathBuf, Path}, ops::{Deref, DerefMut}, fs, io, rc::Rc};

use rand::{thread_rng, Rng};
use rusqlite::{Connection, OpenFlags, ToSql, NO_PARAMS, Transaction, OptionalExtension};
use stacks_common::{debug, util::sleep_ms, error};
use stacks_marf::*;
use stacks_marf::errors::MarfError;

mod migrations;
mod trie_db_impl;
mod memory;

#[cfg(test)]
mod tests;

pub struct SqliteTrieDb {
    conn: Rc<Connection>,
}

impl SqliteTrieDb {
    fn new_from_connection(conn: Rc<Connection>) -> Result<Self> {
        Ok(Self { conn })
    }

    pub fn open(path: PathBuf, readonly: bool, force_db_migration: bool) -> Result<Self> {
        let mut create_flag = false;
        let open_flags = if path.to_str() != Some(":memory:") {
            match fs::metadata(path.to_str().expect("failed to read path")) {
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        // need to create
                        if !readonly {
                            create_flag = true;
                            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                        } else {
                            return Err(MarfError::NotFoundError);
                        }
                    } else {
                        return Err(MarfError::IOError(e));
                    }
                }
                Ok(_md) => {
                    // can just open
                    if !readonly {
                        OpenFlags::SQLITE_OPEN_READ_WRITE
                    } else {
                        OpenFlags::SQLITE_OPEN_READ_ONLY
                    }
                }
            }
        } else {
            create_flag = true;
            if !readonly {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_CREATE
            }
        };

        let mut conn = Connection::open(path)
            .map_err(|e| MarfError::SQLError(e.to_string()))?;

        if create_flag {
            Self::create_tables_if_needed(&mut conn)?;
        }

        let prev_schema_version = Self::migrate_tables_if_needed(&mut conn)?;

        if Self::detect_partial_migration(&conn)? {
            panic!("PARTIAL MIGRATION DETECTED! This is an irrecoverable error. You will need to restart your node from genesis.");
        }

        Ok(Self { conn: Rc::new(conn) })
    }

    pub fn clear_tables(&self, tx: &Transaction) -> Result<()> {
        tx.execute("DELETE FROM block_extension_locks", NO_PARAMS)
            .expect("failed to delete from 'block_extension_locks'");
        tx.execute("DELETE FROM marf_data", NO_PARAMS)
            .expect("failed to delete from 'marf_data'");
        tx.execute("DELETE FROM mined_blocks", NO_PARAMS)
            .expect("failed to delete from 'mined-blocks'");
        Ok(())
    }

    pub fn tx_busy_handler(run_count: i32) -> bool {
        let mut sleep_count = 2;
        if run_count > 0 {
            sleep_count = 2u64.saturating_pow(run_count as u32);
        }
        sleep_count = sleep_count.saturating_add(thread_rng().gen::<u64>() % sleep_count);
    
        if sleep_count > 100 {
            let jitter = thread_rng().gen::<u64>() % 20;
            sleep_count = 100 - jitter;
        }
    
        debug!(
            "Database is locked; sleeping {}ms and trying again",
            &sleep_count
        );
    
        sleep_ms(sleep_count);
        true
    }

    /// Open a database connection and set some typically-used pragmas
    fn sqlite_open<P: AsRef<Path>>(
        path: P,
        flags: OpenFlags,
        foreign_keys: bool,
    ) -> Result<Connection> {
        let db = Connection::open_with_flags(path, flags)
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
        #[cfg(feature = "profile-sqlite")]
        db.profile(Some(trace_profile));
        db.busy_handler(Some(Self::tx_busy_handler))
            .map_err(|e| MarfError::SQLError(e.to_string()))?;
        Self::inner_sql_pragma(&db, "journal_mode", &"WAL")?;
        Self::inner_sql_pragma(&db, "synchronous", &"NORMAL")?;
        if foreign_keys {
            Self::inner_sql_pragma(&db, "foreign_keys", &true)?;
        }
        Ok(db)
    }

    /// Helper to open a MARF
    fn marf_sqlite_open<P: AsRef<Path>>(
        db_path: P,
        open_flags: OpenFlags,
        foreign_keys: bool,
    ) -> Result<Connection> {
        let db = Self::sqlite_open(db_path, open_flags, foreign_keys)?;
        Self::inner_sql_pragma(&db, "mmap_size", &SQLITE_MMAP_SIZE)?;
        Self::inner_sql_pragma(&db, "page_size", &SQLITE_MARF_PAGE_SIZE)?;
        Ok(db)
    }

    fn inner_sql_pragma(
        conn: &Connection,
        pragma_name: &str,
        pragma_value: &dyn ToSql,
    ) -> Result<()> {
        conn.pragma_update(None, pragma_name, pragma_value)
            .map_err(|e| MarfError::SQLError(e.to_string()))
            .and_then(|_| Ok(()))
    }

    /// Run a VACUUM command
    pub fn sql_vacuum(conn: &Connection) -> Result<()> {
        conn.execute("VACUUM", NO_PARAMS)
            .map_err(|e| MarfError::SQLError(e.to_string()))
            .and_then(|_| Ok(()))
    }

    /// Returns true if the database table `table_name` exists in the active
    ///  database of the provided SQLite connection.
    pub fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
        let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
        conn.query_row(sql, &[table_name], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|e| MarfError::SQLError(e.to_string()))
            .map(|r| r.is_some())
    }
}

pub struct SqliteTrieDbTransaction<'a> {
    db: &'a SqliteTrieDb
}

impl<'a> TrieDbTransaction<'a, SqliteTrieDb> for SqliteTrieDbTransaction<'a> {
}

impl Deref for SqliteTrieDbTransaction<'_> {
    type Target = SqliteTrieDb;

    fn deref(&self) -> &Self::Target {
        self.db
    }
}