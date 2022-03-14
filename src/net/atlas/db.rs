// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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

use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};

use std::collections::HashSet;
use std::convert::From;
use std::convert::TryFrom;
use std::fs;

use util_lib::db::sqlite_open;
use util_lib::db::tx_begin_immediate;
use util_lib::db::DBConn;
use util_lib::db::Error as db_error;
use util_lib::db::{
    query_count, query_int, query_row, query_rows, u64_to_sql, FromColumn, FromRow,
};

use util;
use util::hash::{bin_bytes, hex_bytes, to_bin, to_hex, Hash160};
use util::log;
use util::macros::is_big_endian;
use util::secp256k1::Secp256k1PrivateKey;
use util::secp256k1::Secp256k1PublicKey;

use vm::types::QualifiedContractIdentifier;

use crate::codec::StacksMessageCodec;
use crate::types::chainstate::StacksBlockId;
use burnchains::Txid;

use super::{AtlasConfig, Attachment, AttachmentInstance};

pub const ATLASDB_VERSION: &'static str = "1";

const ATLASDB_INITIAL_SCHEMA: &'static [&'static str] = &[
    r#"
    CREATE TABLE attachments(
        hash TEXT UNIQUE PRIMARY KEY,
        content BLOB NOT NULL,
        was_instantiated INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    );"#,
    r#"
    CREATE TABLE attachment_instances(
        content_hash TEXT,
        created_at INTEGER NOT NULL,
        index_block_hash STRING NOT NULL,
        attachment_index INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        is_available INTEGER NOT NULL,
        metadata TEXT NOT NULL,
        contract_id STRING NOT NULL,
        tx_id STRING NOT NULL,
        PRIMARY KEY(index_block_hash, contract_id, attachment_index)
    );"#,
    "CREATE TABLE db_config(version TEXT NOT NULL);",
];

const ATLASDB_INDEXES: &'static [&'static str] =
    &["CREATE INDEX IF NOT EXISTS index_was_instantiated ON attachments(was_instantiated);"];

impl FromRow<Attachment> for Attachment {
    fn from_row<'a>(row: &'a Row) -> Result<Attachment, db_error> {
        let content: Vec<u8> = row.get_unwrap("content");
        Ok(Attachment { content })
    }
}

impl FromRow<AttachmentInstance> for AttachmentInstance {
    fn from_row<'a>(row: &'a Row) -> Result<AttachmentInstance, db_error> {
        let hex_content_hash: String = row.get_unwrap("content_hash");
        let attachment_index: u32 = row.get_unwrap("attachment_index");
        let block_height =
            u64::from_column(row, "block_height").map_err(|_| db_error::TypeError)?;
        let content_hash = Hash160::from_hex(&hex_content_hash).map_err(|_| db_error::TypeError)?;
        let index_block_hash = StacksBlockId::from_column(row, "index_block_hash")?;
        let metadata: String = row.get_unwrap("metadata");
        let contract_id = QualifiedContractIdentifier::from_column(row, "contract_id")?;
        let hex_tx_id: String = row.get_unwrap("tx_id");
        let tx_id = Txid::from_hex(&hex_tx_id).map_err(|_| db_error::TypeError)?;

        Ok(AttachmentInstance {
            content_hash,
            attachment_index,
            index_block_hash,
            stacks_block_height: block_height,
            metadata,
            contract_id,
            tx_id,
            canonical_stacks_tip_height: None,
        })
    }
}

impl FromRow<(u32, u32)> for (u32, u32) {
    fn from_row<'a>(row: &'a Row) -> Result<(u32, u32), db_error> {
        let t1: u32 = row.get_unwrap(0);
        let t2: u32 = row.get_unwrap(1);
        Ok((t1, t2))
    }
}

#[derive(Debug)]
pub struct AtlasDB {
    pub atlas_config: AtlasConfig,
    pub conn: Connection,
    pub readwrite: bool,
}

impl AtlasDB {
    fn add_indexes(&mut self) -> Result<(), db_error> {
        let tx = self.tx_begin()?;
        for row_text in ATLASDB_INDEXES {
            tx.execute_batch(row_text).map_err(db_error::SqliteError)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn instantiate(&mut self) -> Result<(), db_error> {
        let genesis_attachments = self.atlas_config.genesis_attachments.take();

        let tx = self.tx_begin()?;

        for row_text in ATLASDB_INITIAL_SCHEMA {
            tx.execute_batch(row_text).map_err(db_error::SqliteError)?;
        }

        tx.execute(
            "INSERT INTO db_config (version) VALUES (?1)",
            &[&ATLASDB_VERSION],
        )
        .map_err(db_error::SqliteError)?;

        if let Some(attachments) = genesis_attachments {
            let now = util::get_epoch_time_secs() as i64;
            for attachment in attachments {
                tx.execute(
                    "INSERT INTO attachments (hash, content, was_instantiated, created_at) VALUES (?, ?, 1, ?)",
                    &[
                        &attachment.hash() as &dyn ToSql,
                        &attachment.content as &dyn ToSql,
                        &now as &dyn ToSql,
                    ],
                )
                .map_err(db_error::SqliteError)?;
            }
        }

        tx.commit().map_err(db_error::SqliteError)?;

        self.add_indexes()?;
        Ok(())
    }

    pub fn should_keep_attachment(
        &self,
        contract_id: &QualifiedContractIdentifier,
        attachment: &Attachment,
    ) -> bool {
        if !self.atlas_config.contracts.contains(contract_id) {
            info!(
                "Atlas: will discard posted attachment - {} not in supported contracts",
                contract_id
            );
            return false;
        }
        if attachment.content.len() as u32 > self.atlas_config.attachments_max_size {
            info!("Atlas: will discard posted attachment - attachment too large");
            return false;
        }
        true
    }

    // Open the burn database at the given path.  Open read-only or read/write.
    // If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(
        atlas_config: AtlasConfig,
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

        let conn = sqlite_open(path, open_flags, false)?;
        let mut db = AtlasDB {
            atlas_config,
            conn,
            readwrite,
        };
        if create_flag {
            db.instantiate()?;
        }
        if readwrite {
            db.add_indexes()?;
        }
        Ok(db)
    }

    // Open an atlas database in memory (used for testing)
    #[cfg(test)]
    pub fn connect_memory(atlas_config: AtlasConfig) -> Result<AtlasDB, db_error> {
        let conn = Connection::open_in_memory().map_err(|e| db_error::SqliteError(e))?;
        let mut db = AtlasDB {
            atlas_config,
            conn,
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

    pub fn get_minmax_heights_window_for_page_index(
        &self,
        page_index: u32,
    ) -> Result<(u64, u64), db_error> {
        let min = page_index * AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
        let max = (page_index + 1) * AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
        let qry = "SELECT MIN(block_height) as min, MAX(block_height) as max FROM attachment_instances WHERE attachment_index >= ?1 AND attachment_index < ?2";
        let args = [&min as &dyn ToSql, &max as &dyn ToSql];
        let mut stmt = self.conn.prepare(&qry)?;
        let mut rows = stmt.query(&args)?;

        match rows.next() {
            Ok(Some(row)) => {
                let min: i64 = row.get("min").map_err(|_| db_error::NotFoundError)?;
                let max: i64 = row.get("max").map_err(|_| db_error::NotFoundError)?;
                Ok((min as u64, max as u64))
            }
            _ => Err(db_error::NotFoundError),
        }
    }

    pub fn get_attachments_available_at_page_index(
        &self,
        page_index: u32,
        block_id: &StacksBlockId,
    ) -> Result<Vec<u8>, db_error> {
        let page = self.get_attachments_missing_at_page_index(page_index, block_id)?;
        let mut bit_vector = vec![];
        for (_index, is_attachment_missing) in page.iter().enumerate() {
            // todo(ludo): use a bitvector instead
            bit_vector.push(if *is_attachment_missing { 0 } else { 1 });
        }
        Ok(bit_vector)
    }

    pub fn get_attachments_missing_at_page_index(
        &self,
        page_index: u32,
        block_id: &StacksBlockId,
    ) -> Result<Vec<bool>, db_error> {
        let min = page_index * AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
        let max = min + AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
        let qry = "SELECT attachment_index, is_available FROM attachment_instances WHERE attachment_index >= ?1 AND attachment_index < ?2 AND index_block_hash = ?3 ORDER BY attachment_index ASC";
        let args = [
            &min as &dyn ToSql,
            &max as &dyn ToSql,
            block_id as &dyn ToSql,
        ];
        let rows = query_rows::<(u32, u32), _>(&self.conn, &qry, &args)?;

        let mut bool_vector = vec![true; AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE as usize];
        for (attachment_index, is_available) in rows.into_iter() {
            let index = attachment_index % AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
            bool_vector[index as usize] = is_available == 0;
        }
        Ok(bool_vector)
    }

    pub fn insert_uninstantiated_attachment(
        &mut self,
        attachment: &Attachment,
    ) -> Result<(), db_error> {
        // Insert the new attachment
        let uninstantiated_attachments = self.count_uninstantiated_attachments()?;
        if uninstantiated_attachments >= self.atlas_config.max_uninstantiated_attachments {
            let to_delete =
                1 + uninstantiated_attachments - self.atlas_config.max_uninstantiated_attachments;
            self.evict_k_oldest_uninstantiated_attachments(to_delete)?;
        }

        let tx = self.tx_begin()?;
        let now = util::get_epoch_time_secs() as i64;
        let res = tx.execute(
            "INSERT OR REPLACE INTO attachments (hash, content, was_instantiated, created_at) VALUES (?, ?, 0, ?)",
            &[
                &attachment.hash() as &dyn ToSql,
                &attachment.content as &dyn ToSql,
                &now as &dyn ToSql,
            ],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn evict_k_oldest_uninstantiated_attachments(&mut self, k: u32) -> Result<(), db_error> {
        let tx = self.tx_begin()?;
        let res = tx.execute(
            "DELETE FROM attachments WHERE hash IN (SELECT hash FROM attachments WHERE was_instantiated = 0 ORDER BY created_at ASC LIMIT ?)",
            &[&k as &dyn ToSql],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn evict_expired_uninstantiated_attachments(&mut self) -> Result<(), db_error> {
        let now = util::get_epoch_time_secs() as i64;
        let cut_off = now - self.atlas_config.uninstantiated_attachments_expire_after as i64;
        let tx = self.tx_begin()?;
        let res = tx.execute(
            "DELETE FROM attachments WHERE was_instantiated = 0 AND created_at < ?",
            &[&cut_off as &dyn ToSql],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn count_uninstantiated_attachments(&self) -> Result<u32, db_error> {
        let qry = "SELECT COUNT(rowid) FROM attachments
                   WHERE was_instantiated = 0";
        let count = query_count(&self.conn, qry, NO_PARAMS)? as u32;
        Ok(count)
    }

    pub fn count_unresolved_attachment_instances(&self) -> Result<u32, db_error> {
        let qry = "SELECT COUNT(rowid) FROM attachment_instances
                   WHERE is_available = 0";
        let count = query_count(&self.conn, qry, NO_PARAMS)? as u32;
        Ok(count)
    }

    pub fn insert_instantiated_attachment(
        &mut self,
        attachment: &Attachment,
    ) -> Result<(), db_error> {
        let now = util::get_epoch_time_secs() as i64;
        let tx = self.tx_begin()?;
        tx.execute(
            "INSERT OR REPLACE INTO attachments (hash, content, was_instantiated, created_at) VALUES (?, ?, 1, ?)",
            &[
                &attachment.hash() as &dyn ToSql,
                &attachment.content as &dyn ToSql,
                &now as &dyn ToSql,
            ],
        )
        .map_err(db_error::SqliteError)?;
        tx.execute(
            "UPDATE attachment_instances SET is_available = 1 WHERE content_hash = ?1",
            &[&attachment.hash() as &dyn ToSql],
        )
        .map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn find_uninstantiated_attachment(
        &mut self,
        content_hash: &Hash160,
    ) -> Result<Option<Attachment>, db_error> {
        let hex_content_hash = to_hex(&content_hash.0[..]);
        let qry = "SELECT content, hash FROM attachments WHERE hash = ?1 AND was_instantiated = 0"
            .to_string();
        let args = [&hex_content_hash as &dyn ToSql];
        let row = query_row::<Attachment, _>(&self.conn, &qry, &args)?;
        Ok(row)
    }

    pub fn evict_expired_unresolved_attachment_instances(&mut self) -> Result<(), db_error> {
        let now = util::get_epoch_time_secs() as i64;
        let cut_off = now
            - self
                .atlas_config
                .unresolved_attachment_instances_expire_after as i64;
        let tx = self.tx_begin()?;
        let res = tx.execute(
            "DELETE FROM attachment_instances WHERE is_available = 0 AND created_at < ?",
            &[&cut_off as &dyn ToSql],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn find_unresolved_attachment_instances(
        &mut self,
    ) -> Result<Vec<AttachmentInstance>, db_error> {
        let qry = "SELECT * FROM attachment_instances WHERE is_available = 0".to_string();
        let rows = query_rows::<AttachmentInstance, _>(&self.conn, &qry, NO_PARAMS)?;
        Ok(rows)
    }

    pub fn find_all_attachment_instances(
        &mut self,
        content_hash: &Hash160,
    ) -> Result<Vec<AttachmentInstance>, db_error> {
        let hex_content_hash = to_hex(&content_hash.0[..]);
        let qry = "SELECT * FROM attachment_instances WHERE content_hash = ?1".to_string();
        let args = [&hex_content_hash as &dyn ToSql];
        let rows = query_rows::<AttachmentInstance, _>(&self.conn, &qry, &args)?;
        Ok(rows)
    }

    pub fn find_attachment(
        &mut self,
        content_hash: &Hash160,
    ) -> Result<Option<Attachment>, db_error> {
        let hex_content_hash = to_hex(&content_hash.0[..]);
        let qry = "SELECT content, hash FROM attachments WHERE hash = ?1 AND was_instantiated = 1"
            .to_string();
        let args = [&hex_content_hash as &dyn ToSql];
        let row = query_row::<Attachment, _>(&self.conn, &qry, &args)?;
        Ok(row)
    }

    pub fn insert_uninstantiated_attachment_instance(
        &mut self,
        attachment: &AttachmentInstance,
        is_available: bool,
    ) -> Result<(), db_error> {
        let hex_content_hash = to_hex(&attachment.content_hash.0[..]);
        let hex_tx_id = attachment.tx_id.to_hex();
        let tx = self.tx_begin()?;
        let now = util::get_epoch_time_secs() as i64;
        let res = tx.execute(
            "INSERT OR REPLACE INTO attachment_instances (content_hash, created_at, index_block_hash, attachment_index, block_height, is_available, metadata, contract_id, tx_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            &[
                &hex_content_hash as &dyn ToSql,
                &now as &dyn ToSql,
                &attachment.index_block_hash as &dyn ToSql,
                &attachment.attachment_index as &dyn ToSql,
                &u64_to_sql(attachment.stacks_block_height)?,
                &is_available as &dyn ToSql,
                &attachment.metadata as &dyn ToSql,
                &attachment.contract_id.to_string() as &dyn ToSql,
                &hex_tx_id as &dyn ToSql,
            ]
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }
}
