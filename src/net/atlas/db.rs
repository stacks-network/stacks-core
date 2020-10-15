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
use util::hash::{bin_bytes, hex_bytes, to_bin, to_hex, Hash160};
use util::log;
use util::macros::is_big_endian;
use util::secp256k1::Secp256k1PrivateKey;
use util::secp256k1::Secp256k1PublicKey;

use super::bns::ZonefileHash;
use super::Attachment;

pub const ATLASDB_VERSION: &'static str = "23.0.0.0";

const ATLASDB_SETUP: &'static [&'static str] = &[
    r#"
    CREATE TABLE attachments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        content TEXT NOT NULL,
        txid STRING UNIQUE NOT NULL,
        stacks_block_id INTEGER NOT NULL,
        inv_index INTEGER NOT NULL,
        present INTEGER NOT NULL,
        tried_storage TEXT NOT NULL,
        block_height INTEGER NOT NULL
    );"#,
    r#"
    CREATE TABLE unprocessed_attachments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        content TEXT NOT NULL
    );"#, // todo(ludo): should content be a BLOB instead? 
    r#"
    CREATE TABLE records(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        zonefile_id INTEGER NOT NULL,
        name STRING NOT NULL
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

    // todo(ludo): parse error: Invalid numeric literal at line 1, column 7

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
    fn get_zonefiles_hashes_in_range_desc(&self, min: u32, max: u32) -> Result<Vec<ZonefileHash>, db_error> { // todo(ludo): can't fork, won't work
        let qry = "SELECT inv_index, content_hash FROM attachments WHERE inv_index >= ?1 AND inv_index < ?2 ORDER BY inv_index DESC".to_string();
        let args = [&min as &dyn ToSql, &max as &dyn ToSql];
        let rows = query_rows::<ZonefileHash, _>(&self.conn, &qry, &args)?;
        Ok(rows)
    }

    pub fn get_processed_zonefiles_hashes_at_page(&self, min: u32, max: u32) -> Vec<Option<ZonefileHash>> {

        let mut downloaded_zonefiles = match self.get_zonefiles_hashes_in_range_desc(min, max) {
            Ok(zonefiles) => zonefiles,
            Err(e) => {
                println!("{:?}", e);
                panic!() // todo(ludo)
            }
        };

        let mut zonefiles_hashes = vec![];        
        for cursor in min..max {
            let entry = match downloaded_zonefiles.len() {
                0 => None,
                len => match downloaded_zonefiles[len - 1].zonefile_id {
                    index if index == cursor => downloaded_zonefiles.pop(),
                    _ => None,
                }
            };
            zonefiles_hashes.push(entry);
        }

        zonefiles_hashes
    }

    pub fn insert_unprocessed_attachment(&mut self, attachment: Attachment) -> Result<(), db_error> {

        // Check hash + content

        // Do we already have an entry (proceessed or unprocessed) for this attachment? - todo(ludo) think more about this
        let qry = "SELECT count(*) FROM unprocessed_attachments WHERE content_hash = ?1".to_string();
        let args = [&attachment.content_hash as &dyn ToSql];
        let count = query_count(&self.conn, &qry, &args)?;
        if count != 0 {
            // todo(ludo): early return
            return Ok(())
        }

        let tx = self.tx_begin()?;

        let now = util::get_epoch_time_secs() as i64;

        let res = tx.execute(
            "INSERT INTO unprocessed_attachments (content_hash, content, created_at) VALUES (?1, ?2, ?3)",
            &[
                &attachment.content_hash as &dyn ToSql, 
                &attachment.content as &dyn ToSql,
                &now as &dyn ToSql
            ]
        );

        res.map_err(db_error::SqliteError)?;

        tx.commit().map_err(db_error::SqliteError)?;

        Ok(())
    }
}
