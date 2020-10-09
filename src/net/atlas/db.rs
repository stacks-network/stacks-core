use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};

use std::convert::From;
use std::convert::TryFrom;
use std::fs;

use util::db::tx_begin_immediate;
use util::db::DBConn;
use util::db::Error as db_error;
use util::db::{query_count, query_row, query_rows, u64_to_sql, FromColumn, FromRow};

use util;
use util::hash::{bin_bytes, hex_bytes, to_bin, to_hex, Hash160, Sha256Sum, Sha512Trunc256Sum};
use util::log;
use util::macros::is_big_endian;
use util::secp256k1::Secp256k1PrivateKey;
use util::secp256k1::Secp256k1PublicKey;

use super::ZonefileHash;

pub const ATLASDB_VERSION: &'static str = "23.0.0.0";

const ATLASDB_SETUP: &'static [&'static str] = &[
    r#"
    CREATE TABLE zonefiles(
        zonefile_id INTEGER UNIQUE NOT NULL,
        name STRING NOT NULL,
        zonefile_hash TEXT NOT NULL,
        zonefile_content TEXT NOT NULL,
        txid STRING UNIQUE NOT NULL,
        stacks_block_id INTEGER NOT NULL,
        present INTEGER NOT NULL,
        tried_storage TEXT NOT NULL,
        block_height INTEGER NOT NULL );

        PRIMARY KEY(zonefile_id)
    );"#,
    r#"
    CREATE TABLE records(
        record_id INTEGER UNIQUE NOT NULL,
        zonefile_id INTEGER NOT NULL,

        PRIMARY KEY(record_id)
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];

pub struct AtlasDB {
    pub conn: Connection,
    pub readwrite: bool,
}

impl AtlasDB {
    fn instantiate(&mut self) -> Result<(), db_error> {
        let tx = self.tx_begin()?;

        for row_text in ATLASDB_SETUP {
            tx.execute(row_text, NO_PARAMS)
                .map_err(db_error::SqliteError)?;
        }

        tx.execute(
            "INSERT INTO db_version (version) VALUES (?1)",
            &[&ATLASDB_VERSION],
        )
        .map_err(db_error::SqliteError)?;

        tx.commit().map_err(db_error::SqliteError)?;

        Ok(())
    }

    // Open the burn database at the given path.  Open read-only or read/write.
    // If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(
        path: &String,
        readwrite: bool,
    ) -> Result<AtlasDB, db_error> {
        let mut create_flag = false;
        let open_flags = if fs::metadata(path).is_err() {
            // need to create
            if readwrite {
                create_flag = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                return Err(db_error::NoDBError);
            }
        } else {
            // can just open
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            }
        };

        let conn =
            Connection::open_with_flags(path, open_flags).map_err(|e| db_error::SqliteError(e))?;

        let mut db = AtlasDB {
            conn: conn,
            readwrite: readwrite,
        };

        if create_flag {
            db.instantiate()?;
        }
        Ok(db)
    }

    // Open a burn database in memory (used for testing)
    #[cfg(test)]
    pub fn connect_memory() -> Result<AtlasDB, db_error> {
        let conn = Connection::open_in_memory().map_err(|e| db_error::SqliteError(e))?;

        let mut db = AtlasDB {
            conn: conn,
            readwrite: true,
        };

        db.instantiate()?;
        Ok(db)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn tx_begin<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = tx_begin_immediate(&mut self.conn)?;
        Ok(tx)
    }

    // Read the local peer record
    pub fn get_zonefiles_hashes_in_range_desc(&self, min: u32, max: u32) -> Result<Vec<ZonefileHash>, db_error> {
        let qry = "SELECT inv_index, zonefile_hash FROM zonefiles WHERE inv_index >= ?1 AND inv_index < ?2 ORDER BY inv_index DESC".to_string();
        let args = [&min as &dyn ToSql, &max as &dyn ToSql];
        let rows = query_rows::<ZonefileHash, _>(&self.conn, &qry, &args)?;
        Ok(rows)
    }

}
