// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use lazy_static::lazy_static;
use rusqlite::blob::Blob;
use rusqlite::types::{FromSql, FromSqlError};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, ToSql, NO_PARAMS};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::util::{get_epoch_time_secs, sleep_ms};

use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::{Error as ChainstateError, StacksBlock, StacksBlockHeader};
use crate::stacks_common::codec::StacksMessageCodec;
use crate::util_lib::db::{
    query_int, query_row, query_row_panic, query_rows, sqlite_open, tx_begin_immediate, u64_to_sql,
    DBConn, Error as DBError, FromRow,
};

pub const NAKAMOTO_STAGING_DB_SCHEMA_1: &'static [&'static str] = &[
    r#"
  -- Table for staging nakamoto blocks
  CREATE TABLE nakamoto_staging_blocks (
                 -- SHA512/256 hash of this block
                 block_hash TEXT NOT NULL,
                 -- The consensus hash of the burnchain block that selected this block's miner's block-commit.
                 -- This identifies the tenure to which this block belongs.
                 consensus_hash TEXT NOT NULL,
                 -- the parent index_block_hash
                 parent_block_id TEXT NOT NULL,
                 -- whether or not this is the first block in its tenure
                 is_tenure_start BOOL NOT NULL,

                 -- has the burnchain block with this block's `consensus_hash` been processed?
                 burn_attachable INT NOT NULL,
                 -- has this block been processed?
                 processed INT NOT NULL,
                 -- set to 1 if this block can never be attached
                 orphaned INT NOT NULL,

                 -- block height
                 height INT NOT NULL,

                 -- used internally -- this is the StacksBlockId of this block's consensus hash and block hash
                 index_block_hash TEXT NOT NULL,
                 -- how long the block was in-flight
                 download_time INT NOT NULL,
                 -- when this block was stored
                 arrival_time INT NOT NULL,
                 -- when this block was processed
                 processed_time INT NOT NULL,

                 -- block data
                 data BLOB NOT NULL,
                
                 PRIMARY KEY(block_hash,consensus_hash)
    );"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_index_block_hash ON nakamoto_staging_blocks(index_block_hash);"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_index_block_hash_and_consensus_hash ON nakamoto_staging_blocks(index_block_hash,consensus_hash);"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_tenure_start_block ON nakamoto_staging_blocks(is_tenure_start,consensus_hash);"#,
];

pub struct NakamotoStagingBlocksConn(rusqlite::Connection);

impl Deref for NakamotoStagingBlocksConn {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NakamotoStagingBlocksConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NakamotoStagingBlocksConn {
    pub fn conn(&self) -> NakamotoStagingBlocksConnRef {
        NakamotoStagingBlocksConnRef(&self.0)
    }
}

pub struct NakamotoStagingBlocksConnRef<'a>(&'a rusqlite::Connection);

impl<'a> NakamotoStagingBlocksConnRef<'a> {
    pub fn conn(&self) -> NakamotoStagingBlocksConnRef<'a> {
        NakamotoStagingBlocksConnRef(self.0)
    }
}

impl Deref for NakamotoStagingBlocksConnRef<'_> {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

pub struct NakamotoStagingBlocksTx<'a>(rusqlite::Transaction<'a>);

impl<'a> NakamotoStagingBlocksTx<'a> {
    pub fn commit(self) -> Result<(), rusqlite::Error> {
        self.0.commit()
    }

    pub fn conn(&self) -> NakamotoStagingBlocksConnRef {
        NakamotoStagingBlocksConnRef(self.0.deref())
    }
}

impl<'a> Deref for NakamotoStagingBlocksTx<'a> {
    type Target = rusqlite::Transaction<'a>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for NakamotoStagingBlocksTx<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NakamotoStagingBlocksConn {
    /// Open a Blob handle to a Nakamoto block
    pub fn open_nakamoto_block<'a>(
        &'a self,
        rowid: i64,
        readwrite: bool,
    ) -> Result<Blob<'a>, ChainstateError> {
        let blob = self.blob_open(
            rusqlite::DatabaseName::Main,
            "nakamoto_staging_blocks",
            "data",
            rowid,
            !readwrite,
        )?;
        Ok(blob)
    }
}

impl<'a> NakamotoStagingBlocksConnRef<'a> {
    /// Determine if there exists any unprocessed Nakamoto blocks
    /// Returns Ok(true) if so
    /// Returns Ok(false) if not
    pub fn has_any_unprocessed_nakamoto_block(&self) -> Result<bool, ChainstateError> {
        let qry = "SELECT 1 FROM nakamoto_staging_blocks WHERE processed = 0 LIMIT 1";
        let res: Option<i64> = query_row(self, qry, NO_PARAMS)?;
        Ok(res.is_some())
    }

    /// Determine whether or not we have processed at least one Nakamoto block in this sortition history.
    /// NOTE: the relevant field queried from `nakamoto_staging_blocks` is updated by a separate
    /// tx from block-processing, so it's imperative that the thread that calls this function is
    /// the *same* thread as the one that processes blocks.
    /// Returns Ok(true) if at least one block in `nakamoto_staging_blocks` has `processed = 1`
    /// Returns Ok(false) if not
    /// Returns Err(..) on DB error
    fn has_processed_nakamoto_block<SH: SortitionHandle>(
        &self,
        sortition_handle: &SH,
    ) -> Result<bool, ChainstateError> {
        let Some((ch, bhh, _height)) = sortition_handle.get_nakamoto_tip()? else {
            return Ok(false);
        };

        // this block must be a processed Nakamoto block
        let ibh = StacksBlockId::new(&ch, &bhh);
        let qry = "SELECT 1 FROM nakamoto_staging_blocks WHERE processed = 1 AND index_block_hash = ?1 LIMIT 1";
        let args: &[&dyn ToSql] = &[&ibh];
        let res: Option<i64> = query_row(self, qry, args)?;
        Ok(res.is_some())
    }

    /// Determine if we have a particular block
    /// Returns Ok(true) if so
    /// Returns Ok(false) if not
    /// Returns Err(..) on DB error
    pub fn has_nakamoto_block(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<bool, ChainstateError> {
        let qry = "SELECT 1 FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args: &[&dyn ToSql] = &[index_block_hash];
        let res: Option<i64> = query_row(self, qry, args)?;
        Ok(res.is_some())
    }

    /// Get a staged Nakamoto tenure-start block
    pub fn get_nakamoto_tenure_start_block(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<NakamotoBlock>, ChainstateError> {
        let qry = "SELECT data FROM nakamoto_staging_blocks WHERE is_tenure_start = 1 AND consensus_hash = ?1";
        let args: &[&dyn ToSql] = &[consensus_hash];
        let data: Option<Vec<u8>> = query_row(self, qry, args)?;
        let Some(block_bytes) = data else {
            return Ok(None);
        };
        let block = NakamotoBlock::consensus_deserialize(&mut block_bytes.as_slice())?;
        if &block.header.consensus_hash != consensus_hash {
            error!(
                "Staging DB corruption: expected {}, got {}",
                consensus_hash, block.header.consensus_hash
            );
            return Err(DBError::Corruption.into());
        }
        Ok(Some(block))
    }

    /// Get the rowid of a Nakamoto block
    pub fn get_nakamoto_block_rowid(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<i64>, ChainstateError> {
        let sql = "SELECT rowid FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args: &[&dyn ToSql] = &[index_block_hash];
        let res: Option<i64> = query_row(self, sql, args)?;
        Ok(res)
    }

    /// Get a Nakamoto block by index block hash, as well as its size.
    /// Verifies its integrity.
    /// Returns Ok(Some(block, size)) if the block was present
    /// Returns Ok(None) if there was no such block
    /// Returns Err(..) on DB error, including block corruption
    pub fn get_nakamoto_block(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<(NakamotoBlock, u64)>, ChainstateError> {
        let qry = "SELECT data FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args: &[&dyn ToSql] = &[index_block_hash];
        let res: Option<Vec<u8>> = query_row(self, qry, args)?;
        let Some(block_bytes) = res else {
            return Ok(None);
        };
        let block = NakamotoBlock::consensus_deserialize(&mut block_bytes.as_slice())?;
        if &block.header.block_id() != index_block_hash {
            error!(
                "Staging DB corruption: expected {}, got {}",
                index_block_hash,
                &block.header.block_id()
            );
            return Err(DBError::Corruption.into());
        }
        Ok(Some((
            block,
            u64::try_from(block_bytes.len()).expect("FATAL: block is greater than a u64"),
        )))
    }

    /// Get the size of a Nakamoto block, given its index block hash
    /// Returns Ok(Some(size)) if the block was present
    /// Returns Ok(None) if there was no such block
    /// Returns Err(..) on DB error, including block corruption
    pub fn get_nakamoto_block_size(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<u64>, ChainstateError> {
        let qry = "SELECT length(data) FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args: &[&dyn ToSql] = &[index_block_hash];
        let res = query_row(self, qry, args)?
            .map(|size: i64| u64::try_from(size).expect("FATAL: block size exceeds i64::MAX"));
        Ok(res)
    }

    /// Find the next ready-to-process Nakamoto block, given a connection to the staging blocks DB.
    /// NOTE: the relevant field queried from `nakamoto_staging_blocks` are updated by a separate
    /// tx from block-processing, so it's imperative that the thread that calls this function is
    /// the *same* thread that goes to process blocks.
    /// Returns (the block, the size of the block)
    pub(crate) fn next_ready_nakamoto_block<SH: SortitionHandle>(
        &self,
        header_conn: &Connection,
        sortition_handle: &SH,
    ) -> Result<Option<(NakamotoBlock, u64)>, ChainstateError> {
        let query = "SELECT child.data FROM nakamoto_staging_blocks child JOIN nakamoto_staging_blocks parent
                     ON child.parent_block_id = parent.index_block_hash
                     WHERE child.burn_attachable = 1
                       AND child.orphaned = 0
                       AND child.processed = 0
                       AND parent.processed = 1
                     ORDER BY child.height ASC";
        self
            .query_row_and_then(query, NO_PARAMS, |row| {
                let data: Vec<u8> = row.get("data")?;
                let block = NakamotoBlock::consensus_deserialize(&mut data.as_slice())?;
                Ok(Some((
                    block,
                    u64::try_from(data.len()).expect("FATAL: block is bigger than a u64"),
                )))
            })
            .or_else(|e| {
                if let ChainstateError::DBError(DBError::SqliteError(
                    rusqlite::Error::QueryReturnedNoRows,
                )) = e
                {
                    // This query can fail if the parent of `child` is not a Nakamoto block, which
                    // is allowed -- a Nakamoto block can descend from an epoch2 block (but since
                    // Nakamoto does not fork without a Bitcoin fork, it'll be the only such child
                    // within that Bitcoin forok).
                    //
                    // So, if at least one Nakamoto block is processed in this Bitcoin fork,
                    // then the next ready block's parent *must* be a Nakamoto block.  So
                    // if the below is true, then there are no ready blocks.
                    if self.has_processed_nakamoto_block(sortition_handle)? {
                        return Ok(None);
                    }

                    // no nakamoto blocks processed yet, so the parent *must* be an epoch2 block!
                    // go find it.  Note that while this is expensive, it only has to be done
                    // _once_, and it will only touch at most one reward cycle's worth of blocks.
                    let sql = "SELECT index_block_hash,parent_block_id FROM nakamoto_staging_blocks WHERE processed = 0 AND orphaned = 0 AND burn_attachable = 1 ORDER BY height ASC";
                    let mut stmt = self.deref().prepare(sql)?;
                    let mut qry = stmt.query(NO_PARAMS)?;
                    let mut next_nakamoto_block_id = None;
                    while let Some(row) = qry.next()? {
                        let index_block_hash : StacksBlockId = row.get(0)?;
                        let parent_block_id : StacksBlockId = row.get(1)?;

                        let Some(_parent_epoch2_block) = NakamotoChainState::get_block_header_epoch2(header_conn, &parent_block_id)? else {
                            continue;
                        };

                        // epoch2 parent exists, so this Nakamoto block is processable!
                        next_nakamoto_block_id = Some(index_block_hash);
                        break;
                    }
                    let Some(next_nakamoto_block_id) = next_nakamoto_block_id else {
                        // no stored nakamoto block had an epoch2 parent
                        return Ok(None);
                    };

                    self.get_nakamoto_block(&next_nakamoto_block_id)
                } else {
                    Err(e)
                }
            })
    }
}

impl<'a> NakamotoStagingBlocksTx<'a> {
    /// Notify the staging database that a given stacks block has been processed.
    /// This will update the attachable status for children blocks, as well as marking the stacks
    ///  block itself as processed.
    pub fn set_block_processed(&self, block: &StacksBlockId) -> Result<(), ChainstateError> {
        let clear_staged_block =
            "UPDATE nakamoto_staging_blocks SET processed = 1, processed_time = ?2
                                  WHERE index_block_hash = ?1";
        self.execute(
            &clear_staged_block,
            params![&block, &u64_to_sql(get_epoch_time_secs())?],
        )?;

        Ok(())
    }

    /// Modify the staging database that a given stacks block can never be processed.
    /// This will update the attachable status for children blocks, as well as marking the stacks
    /// block itself as orphaned.
    pub fn set_block_orphaned(&self, block: &StacksBlockId) -> Result<(), ChainstateError> {
        let update_dependents = "UPDATE nakamoto_staging_blocks SET orphaned = 1
                                 WHERE parent_block_id = ?";

        self.execute(&update_dependents, &[&block])?;

        let clear_staged_block =
            "UPDATE nakamoto_staging_blocks SET processed = 1, processed_time = ?2, orphaned = 1
                                  WHERE index_block_hash = ?1";
        self.execute(
            &clear_staged_block,
            params![&block, &u64_to_sql(get_epoch_time_secs())?],
        )?;

        Ok(())
    }

    /// Notify the staging database that a given burn block has been processed.
    /// This is required for staged blocks to be eligible for processing.
    pub fn set_burn_block_processed(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<(), ChainstateError> {
        let update_dependents = "UPDATE nakamoto_staging_blocks SET burn_attachable = 1
                                 WHERE consensus_hash = ?";
        self.execute(&update_dependents, &[consensus_hash])?;

        Ok(())
    }
}

impl StacksChainState {
    /// Begin a transaction against the staging blocks DB.
    /// Note that this DB is (or will eventually be) in a separate database from the headers.
    pub fn staging_db_tx_begin<'a>(
        &'a mut self,
    ) -> Result<NakamotoStagingBlocksTx<'a>, ChainstateError> {
        let tx = tx_begin_immediate(&mut self.nakamoto_staging_blocks_conn)?;
        Ok(NakamotoStagingBlocksTx(tx))
    }

    /// Begin a tx to both the headers DB and the staging DB
    pub fn headers_and_staging_tx_begin<'a>(
        &'a mut self,
    ) -> Result<(rusqlite::Transaction<'a>, NakamotoStagingBlocksTx<'a>), ChainstateError> {
        let header_tx = self
            .state_index
            .storage_tx()
            .map_err(ChainstateError::DBError)?;
        let staging_tx = tx_begin_immediate(&mut self.nakamoto_staging_blocks_conn)?;
        Ok((header_tx, NakamotoStagingBlocksTx(staging_tx)))
    }

    /// Open a connection to the headers DB, and open a tx to the staging DB
    pub fn headers_conn_and_staging_tx_begin<'a>(
        &'a mut self,
    ) -> Result<(&'a rusqlite::Connection, NakamotoStagingBlocksTx<'a>), ChainstateError> {
        let header_conn = self.state_index.sqlite_conn();
        let staging_tx = tx_begin_immediate(&mut self.nakamoto_staging_blocks_conn)?;
        Ok((header_conn, NakamotoStagingBlocksTx(staging_tx)))
    }

    /// Get a ref to the nakamoto staging blocks connection
    pub fn nakamoto_blocks_db(&self) -> NakamotoStagingBlocksConnRef {
        NakamotoStagingBlocksConnRef(&self.nakamoto_staging_blocks_conn)
    }

    /// Get the path to the Nakamoto staging blocks DB.
    /// It's separate from the headers DB in order to avoid DB contention between downloading
    /// blocks and processing them.
    pub fn static_get_nakamoto_staging_blocks_path(
        root_path: PathBuf,
    ) -> Result<String, ChainstateError> {
        let mut nakamoto_blocks_path = Self::blocks_path(root_path);
        nakamoto_blocks_path.push("nakamoto.sqlite");
        Ok(nakamoto_blocks_path
            .to_str()
            .ok_or(ChainstateError::DBError(DBError::ParseError))?
            .to_string())
    }

    /// Get the path to the Nakamoto staging blocks DB.
    pub fn get_nakamoto_staging_blocks_path(&self) -> Result<String, ChainstateError> {
        Self::static_get_nakamoto_staging_blocks_path(PathBuf::from(self.root_path.as_str()))
    }

    /// Open and set up a DB for nakamoto staging blocks.
    /// If it doesn't exist, then instantiate it if `readwrite` is true.
    pub fn open_nakamoto_staging_blocks(
        path: &str,
        readwrite: bool,
    ) -> Result<NakamotoStagingBlocksConn, ChainstateError> {
        let exists = fs::metadata(&path).is_ok();
        let flags = if !exists {
            // try to instantiate
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                return Err(DBError::NotFoundError.into());
            }
        } else {
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            }
        };
        let conn = sqlite_open(path, flags, false)?;
        if !exists {
            for cmd in NAKAMOTO_STAGING_DB_SCHEMA_1.iter() {
                conn.execute(cmd, NO_PARAMS)?;
            }
        }
        Ok(NakamotoStagingBlocksConn(conn))
    }
}
