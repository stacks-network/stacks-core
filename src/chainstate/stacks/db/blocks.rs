/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::io;
use std::io::prelude::*;
use std::fmt;
use std::fs;
use hashbrown::HashMap;
use hashbrown::HashSet;

use chainstate::stacks::Error;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::*;
use chainstate::stacks::db::*;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    DBConn,
    RowOrder,
    FromRow,
    query_rows,
    query_count,
    query_int
};

use util::strings::StacksString;

use util::hash::to_hex;

use chainstate::burn::db::burndb::*;

use net::Error as net_error;

use vm::types::{
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier
};

use vm::contexts::{
    AssetMap
};

use vm::ast::build_ast;
use vm::analysis::run_analysis;
use vm::types::{
    Value,
    AssetIdentifier
};

use vm::clarity::{
    ClarityBlockConnection,
    ClarityInstance
};

pub use vm::analysis::errors::CheckErrors;
use vm::errors::Error as clarity_vm_error;

use vm::database::ClarityDatabase;

use vm::contracts::Contract;

use rand::RngCore;
use rand::thread_rng;

#[derive(Debug, Clone, PartialEq)]
pub struct StagingMicroblock {
    pub burn_header_hash: BurnchainHeaderHash,
    pub anchored_block_hash: BlockHeaderHash,
    pub microblock_hash: BlockHeaderHash,
    pub sequence: u8,
    pub processed: bool,
    pub block_data: Vec<u8>
}

#[derive(Debug, Clone, PartialEq)]
pub struct StagingBlock {
    pub burn_header_hash: BurnchainHeaderHash,
    pub anchored_block_hash: BlockHeaderHash,
    pub parent_burn_header_hash: BurnchainHeaderHash,
    pub parent_anchored_block_hash: BlockHeaderHash,
    pub microblock_pubkey_hash: Hash160,
    pub processed: bool,
    pub block_data: Vec<u8>
}

impl StagingBlock {
    pub fn is_genesis(&self) -> bool {
        self.parent_burn_header_hash == BurnchainHeaderHash([0u8; 32]) && self.parent_anchored_block_hash == BlockHeaderHash([0u8; 32])
    }
}

impl RowOrder for StagingMicroblock {
    fn row_order() -> Vec<&'static str> {
        vec!["anchored_block_hash", "burn_header_hash", "microblock_hash", "sequence", "processed", "block_data"]
    }
}

impl FromRow<StagingMicroblock> for StagingMicroblock {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StagingMicroblock, db_error> {
        let anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_row(row, index + 0)?;
        let burn_header_hash : BurnchainHeaderHash = BurnchainHeaderHash::from_row(row, index + 1)?;
        let microblock_hash : BlockHeaderHash = BlockHeaderHash::from_row(row, index + 2)?;
        let sequence_i64 : i64 = row.get(index + 3);
        let processed_i64 : i64 = row.get(index + 4);
        let block_data : Vec<u8> = row.get(index + 5);

        if sequence_i64 > (u8::max_value() as i64) || sequence_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let processed = if processed_i64 != 0 { true } else { false };

        let sequence = sequence_i64 as u8;
        Ok(StagingMicroblock {
            burn_header_hash,
            anchored_block_hash,
            microblock_hash,
            sequence,
            processed,
            block_data
        })
    }
}

impl RowOrder for StagingBlock {
    fn row_order() -> Vec<&'static str> {
        vec!["anchored_block_hash", "parent_anchored_block_hash", "burn_header_hash", "parent_burn_header_hash", "microblock_pubkey_hash", "processed", "block_data"]
    }
}

impl FromRow<StagingBlock> for StagingBlock {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StagingBlock, db_error> {
        let anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_row(row, index + 0)?;
        let parent_anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_row(row, index + 1)?;
        let burn_header_hash : BurnchainHeaderHash = BurnchainHeaderHash::from_row(row, index + 2)?;
        let parent_burn_header_hash: BurnchainHeaderHash = BurnchainHeaderHash::from_row(row, index + 3)?;
        let microblock_pubkey_hash : Hash160 = Hash160::from_row(row, index + 4)?;
        let processed_i64 : i64 = row.get(index + 5);
        let block_data : Vec<u8> = row.get(index + 6);

        let processed = if processed_i64 != 0 { true } else { false };

        Ok(StagingBlock {
            anchored_block_hash,
            parent_anchored_block_hash,
            burn_header_hash,
            parent_burn_header_hash,
            microblock_pubkey_hash,
            processed,
            block_data
        })
    }
}

const STACKS_BLOCK_INDEX_SQL : &'static [&'static str]= &[
    r#"
    -- Staging microblocks -- preprocessed microblocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_microblocks(anchored_block_hash TEXT NOT NULL,
                                     burn_header_hash TEXT NOT NULL,
                                     microblock_hash TEXT NOT NULL,
                                     sequence INT NOT NULL,
                                     block_data BLOB NOT NULL,      -- cannot exceed 1 billion bytes, per sqlite3 defaults
                                     processed INT NOT NULL,
                                     PRIMARY KEY(anchored_block_hash,burn_header_hash,microblock_hash)
    );
    "#,
    r#"
    -- Staging blocks -- preprocessed blocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_blocks(anchored_block_hash TEXT NOT NULL,
                                parent_anchored_block_hash TEXT NOT NULL,
                                burn_header_hash TEXT NOT NULL,
                                parent_burn_header_hash TEXT NOT NULL,
                                microblock_pubkey_hash TEXT NOT NULL,
                                processed INT NOT NULL,
                                block_data BLOB NOT NULL,           -- cannot exceed 1 billion bytes, per sqlite3 defaults
                                PRIMARY KEY(anchored_block_hash,burn_header_hash)
    );
    "#,
];


impl StacksChainState {
    fn instantiate_blocks_db(conn: &mut DBConn) -> Result<(), Error> {
        let tx = conn.transaction().map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        for cmd in STACKS_BLOCK_INDEX_SQL {
            tx.execute(cmd, NO_PARAMS).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }

        tx.commit().map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        Ok(())
    }
    
    pub fn open_blocks_db(db_path: &str) -> Result<DBConn, Error> {
        let mut create_flag = false;
        let open_flags =
            if fs::metadata(db_path).is_err() {
                // need to create 
                create_flag = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            }
            else {
                // can just open 
                OpenFlags::SQLITE_OPEN_READ_WRITE
            };

        let mut conn = DBConn::open_with_flags(db_path, open_flags).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        if create_flag {
            // instantiate!
            StacksChainState::instantiate_blocks_db(&mut conn)?;
        }
        
        Ok(conn)
    }
    
    /// Get the path to a block in the chunk store
    fn get_block_path(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let mut block_path = PathBuf::from(&self.blocks_path);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));
        block_path.push(format!("{}-{}", to_hex(block_hash_bytes), burn_header_hash.to_hex()));

        let blocks_path_str = block_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(blocks_path_str)
    }

    /// Make a directory tree for storing this block to the chunk store, and return the block's path
    fn make_block_dir(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let mut block_path = PathBuf::from(&self.blocks_path);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));

        let _ = StacksChainState::mkdirs(&block_path)?;

        block_path.push(format!("{}-{}", to_hex(block_hash_bytes), burn_header_hash.to_hex()));
        let blocks_path_str = block_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(blocks_path_str)
    }

    pub fn atomic_file_write(path: &String, bytes: &Vec<u8>) -> Result<(), Error> {
        let path_tmp = format!("{}.tmp", path);
        let mut fd = fs::OpenOptions::new()
                    .read(false)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&path_tmp)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", &path_tmp);
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        fd.write_all(bytes).map_err(|e| Error::DBError(db_error::IOError(e)))?;
        fd.sync_all().map_err(|e| Error::DBError(db_error::IOError(e)))?;

        // atomically put this trie file in place
        trace!("Rename {:?} to {:?}", &path_tmp, &path);
        fs::rename(&path_tmp, &path).map_err(|e| Error::DBError(db_error::IOError(e)))?;

        Ok(())
    }

    pub fn file_load(path: &String) -> Result<Vec<u8>, Error> {
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", path);
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        let sz = match fs::metadata(path) {
            Ok(md) => {
                md.len()
            },
            Err(e) => {
                return Err(Error::DBError(db_error::IOError(e)));
            }
        };

        if sz >= usize::max_value() as u64 {
            return Err(Error::DBError(db_error::Corruption));
        }

        let mut buf = Vec::with_capacity(sz as usize);
        fd.read_to_end(&mut buf).map_err(|e| Error::DBError(db_error::IOError(e)))?;
        Ok(buf)
    }

    /// Do we have a stored block in the chunk store?
    pub fn has_stored_block(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let block_path = self.get_block_path(burn_header_hash, block_hash)?;
        match fs::metadata(block_path) {
            Ok(md) => {
                Ok(true)
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    Ok(false)
                }
                else {
                    Err(Error::DBError(db_error::IOError(e)))
                }
            }
        }
    }

    /// Have we committed to and stored a microblock stream in the chunk store?
    /// The given burn_header_hash is the burnchain header hash of the snapshot that selected this
    /// stream's anchored block.
    pub fn has_stored_microblocks(&self, burn_header_hash: &BurnchainHeaderHash, tail_header: &BlockHeaderHash) -> Result<bool, Error> {
        if *tail_header == BlockHeaderHash([0u8; 32]) {
            // empty
            Ok(true)
        }
        else {
            self.has_stored_block(burn_header_hash, tail_header)
        }
    }

    /// Store a block to the chunk store, named by its hash
    pub fn store_block(&mut self, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock) -> Result<(), Error> {
        let block_hash = block.block_hash();
        let block_path = self.make_block_dir(burn_header_hash, &block_hash)?;
        let block_data = block.serialize();
        StacksChainState::atomic_file_write(&block_path, &block_data)
    }
    
    /// Store an empty block to the chunk store, named by its hash.
    /// Used to mark an invalid block
    pub fn store_empty_block(&mut self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<(), Error> {
        let block_path = self.make_block_dir(burn_header_hash, &block_hash)?;
        StacksChainState::atomic_file_write(&block_path, &vec![])
    }

    /// Truncate an (invalid) block.  Frees up space while marking the block as processed so we
    /// don't process it again.
    fn free_block(&self, burn_header_hash: &BurnchainHeaderHash, block_header_hash: &BlockHeaderHash) -> Result<(), Error> {
        let block_path = self.get_block_path(burn_header_hash, block_header_hash)?;
        match fs::metadata(&block_path) {
            Ok(_) => {
                let f = fs::OpenOptions::new()
                            .read(false)
                            .write(true)
                            .truncate(true)
                            .open(&block_path)
                            .map_err(|e| {
                                if e.kind() == io::ErrorKind::NotFound {
                                    error!("File not found: {:?}", &block_path);
                                    Error::DBError(db_error::NotFoundError)
                                }
                                else {
                                    Error::DBError(db_error::IOError(e))
                                }
                            })?;
                Ok(())
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    // didn't exist anyway
                    Ok(())
                }
                else {
                    Err(Error::DBError(db_error::IOError(e)))
                }
            }
        }
    }

    /// Free up all state for an invalid block
    pub fn free_block_state(&mut self, burn_header_hash: &BurnchainHeaderHash, block_header: &StacksBlockHeader) -> Result<(), Error> {
        self.free_block(burn_header_hash, &block_header.block_hash())?;
        Ok(())
    }

    /// Load up a block from the chunk store.
    /// Returns Ok(Some(block)) if found.
    /// Returns Ok(None) if this block was found, but is known to be invalid 
    /// Returns Err(...) on not found or I/O error
    pub fn load_block(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlock>, Error> {
        let block_path = self.get_block_path(burn_header_hash, block_hash)?;
        let block_bytes = StacksChainState::file_load(&block_path)?;
        if block_bytes.len() == 0 {
            debug!("Zero-sized block {}", block_hash.to_hex());
            return Ok(None);
        }

        let mut index = 0;
        let block = StacksBlock::deserialize(&block_bytes, &mut index, block_bytes.len() as u32).map_err(Error::NetError)?;
        if index != (block_bytes.len() as u32) {
            error!("Corrupt block {}: read {} out of {} bytes", block_hash.to_hex(), index, block_bytes.len());
            return Err(Error::DBError(db_error::Corruption));
        }

        Ok(Some(block))
    }
    
    /// Load up an anchored block header from the chunk store.
    /// Returns Ok(Some(blockheader)) if found.
    /// Returns Ok(None) if this block was found, but is known to be invalid 
    /// Returns Err(...) on not found or I/O error
    pub fn load_block_header(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlockHeader>, Error> {
        let block_path = self.get_block_path(burn_header_hash, block_hash)?;
        let block_bytes = StacksChainState::file_load(&block_path)?;
        if block_bytes.len() == 0 {
            debug!("Zero-sized block {}", block_hash.to_hex());
            return Ok(None);
        }

        let mut index = 0;
        let block_header = StacksBlockHeader::deserialize(&block_bytes, &mut index, block_bytes.len() as u32).map_err(Error::NetError)?;
        Ok(Some(block_header))
    }

    /// Store a stream of microblocks to the chunk store, named by its tail block's hash.
    /// The given burn_header_hash is the burnchain header hash of the snapshot that selected this
    /// stream's anchored block.
    pub fn store_microblock_stream(&mut self, burn_header_hash: &BurnchainHeaderHash, microblocks: &Vec<StacksMicroblock>) -> Result<(), Error> {
        let block_hash = microblocks[microblocks.len() - 1].block_hash();
        let block_path = self.make_block_dir(burn_header_hash, &block_hash)?;

        let mut buf = vec![];
        for mblock in microblocks {
            let mut mblock_buf = mblock.serialize();
            buf.append(&mut mblock_buf);
        }

        StacksChainState::atomic_file_write(&block_path, &buf)
    }

    /// Load a stream of microblocks from the chunk store, given its tail block's hash.
    /// The given burn_header_hash is the burnchain header hash of the snapshot that selected this
    /// stream's anchored block.
    /// Returns Ok(Some(microblocks)) if the data was found
    /// Returns Ok(None) if the microblocks stream was previously processed and is known to be invalid
    /// Returns Err(...) for not found, I/O error, etc.
    fn load_microblock_stream(&self, burn_header_hash: &BurnchainHeaderHash, microblock_tail_hash: &BlockHeaderHash) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        let block_path = self.get_block_path(burn_header_hash, microblock_tail_hash)?;
        let block_bytes = StacksChainState::file_load(&block_path)?;
        if block_bytes.len() == 0 {
            // known-invalid
            debug!("Zero-sized microblock stream {}", microblock_tail_hash.to_hex());
            return Ok(None);
        }

        let mut index : u32 = 0;
        let mut microblocks = vec![];
        while (index as usize) < block_bytes.len() {
            let microblock = StacksMicroblock::deserialize(&block_bytes, &mut index, block_bytes.len() as u32).map_err(Error::NetError)?;
            microblocks.push(microblock);
        }

        if (index as usize) != block_bytes.len() {
            error!("Corrupt microblock stream {}: read {} out of {} bytes", microblock_tail_hash.to_hex(), index, block_bytes.len());
            return Err(Error::DBError(db_error::Corruption));
        }

        Ok(Some(microblocks))
    }

    /// Load up a preprocessed (queued) but still unprocessed block.
    fn load_staging_block(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlock>, Error> {
        let row_order = StagingBlock::row_order().join(",");
        let sql = format!("SELECT {} FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2", row_order);
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql];
        let rows = query_rows::<StagingBlock, _>(&self.blocks_db, &sql, &args).map_err(Error::DBError)?;
        match rows.len() {
            0 => {
                Ok(None)
            }
            1 => {
                let mut index = 0;
                match StacksBlock::deserialize(&rows[0].block_data, &mut index, rows[0].block_data.len() as u32) {
                    Ok(block) => Ok(Some(block)),
                    Err(e) => Ok(None)
                }
            },
            _ => {
                // should be impossible since this is the primary key
                panic!("Got two or more block rows with same burn and block hashes");
            }
        }
    }
    
    /// Load up a queued block's queued pubkey hash
    fn load_staging_block_pubkey_hash(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<Hash160>, Error> {
        let sql = format!("SELECT microblock_pubkey_hash FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND processed = 0");
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql];
        let rows = query_rows::<Hash160, _>(&self.blocks_db, &sql, &args).map_err(Error::DBError)?;
        match rows.len() {
            0 => {
                Ok(None)
            }
            1 => {
                Ok(Some(rows[0].clone()))
            },
            _ => {
                // should be impossible since this is the primary key
                panic!("Got two or more block rows with same burn and block hashes");
            }
        }
    }

    /// Load up a preprocessed but still unprocessed microblock.  Also loads up its parent anchor block's hash.
    fn load_staging_microblock(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<Option<StacksMicroblock>, Error> {
        let row_order = StagingMicroblock::row_order().join(",");
        let sql = format!("SELECT {} FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND microblock_hash = ?3", row_order);
        let args = [&burn_header_hash.to_hex() as &dyn ToSql, &block_hash.to_hex() as &dyn ToSql, &microblock_hash.to_hex() as &dyn ToSql];
        let rows = query_rows::<StagingMicroblock, _>(&self.blocks_db, &sql, &args).map_err(Error::DBError)?;
        match rows.len() {
            0 => {
                Ok(None)
            },
            1 => {
                let mut index = 0;
                let microblock = StacksMicroblock::deserialize(&rows[0].block_data, &mut index, rows[0].block_data.len() as u32)
                    .map_err(Error::NetError)?;
                Ok(Some(microblock))
            },
            _ => {
                // should be impossible since microblocks are unique
                panic!("Got two or more microblock rows with the same hash");
            }
        }
    }

    /// Load up a preprocessed but still unprocessed microblock stream, given its parent's anchored
    /// block's hash and burn hash.
    /// Does not check for duplicates or invalid data; feed the stream into validate_parent_microblock_stream() for that.
    fn load_staging_microblock_stream(&self, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        let row_order = StagingMicroblock::row_order().join(",");
        let sql = format!("SELECT {} FROM staging_microblocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 ORDER BY sequence", row_order);
        let args = [&anchored_block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql];
        let rows = query_rows::<StagingMicroblock, _>(&self.blocks_db, &sql, &args)
            .map_err(Error::DBError)?;

        let mut num_processed = 0;
        let mut num_unprocessed = 0;
        for row in rows.iter() {
            if row.processed {
                num_processed += 1;
            }
            else {
                num_unprocessed += 1;
            }
        }

        if num_processed == 0 && num_unprocessed == 0 {
            // no microblocks
            return Ok(None);
        }
        else if num_processed > 0 && num_unprocessed == 0 {
            // all processed
            return Ok(None);
        }
        else if num_processed > 0 && num_unprocessed > 0 {
            // not possible 
            return Err(Error::DBError(db_error::Corruption));
        }

        // all unprocessed
        let mut microblocks = vec![];
        for row in rows.iter() {
            let mut index = 0;
            let microblock = StacksMicroblock::deserialize(&row.block_data, &mut index, row.block_data.len() as u32)
                .map_err(Error::NetError)?;
            microblocks.push(microblock);
        }
        Ok(Some(microblocks))
    }
    
    /// Store a preprocessed block, queuing it up for subsequent processing.
    /// The caller should at least verify that the block is attached to some fork in the burn
    /// chain.
    fn store_staging_block(&mut self, burn_hash: &BurnchainHeaderHash, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash) -> Result<(), Error> {
        let block_hash = block.block_hash();
        let block_bytes = block.serialize();

        let sql = "INSERT OR REPLACE INTO staging_blocks (anchored_block_hash, parent_anchored_block_hash, burn_header_hash, parent_burn_header_hash, microblock_pubkey_hash, processed, block_data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
        let args = [&block_hash.to_hex() as &dyn ToSql, &block.header.parent_block.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql, &parent_burn_header_hash.to_hex() as &dyn ToSql,
                    &block.header.microblock_pubkey_hash.to_hex() as &dyn ToSql, &0 as &dyn ToSql, &block_bytes as &dyn ToSql];

        let tx = self.blocks_tx_begin()?;
        tx.execute(&sql, &args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        tx.commit().map_err(Error::DBError)?;
        Ok(())
    }

    /// Store a preprocessed microblock, queueing it up for subsequent processing.
    /// The caller should at least verify that this block was signed by the miner of the ancestor
    /// anchored block that this microblock builds off of.  Because microblocks may arrive out of
    /// order, this method does not check that 
    fn store_staging_microblock(&mut self, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, microblock: &StacksMicroblock) -> Result<(), Error> {
        let microblock_bytes = microblock.serialize();

        let sql = "INSERT OR REPLACE INTO staging_microblocks (anchored_block_hash, burn_header_hash, microblock_hash, sequence, processed, block_data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
        let args = [&anchored_block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql, &microblock.block_hash().to_hex() as &dyn ToSql, &microblock.header.sequence as &dyn ToSql, &0 as &dyn ToSql, &microblock_bytes as &dyn ToSql];

        let tx = self.blocks_tx_begin()?;
        tx.execute(&sql, &args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        tx.commit().map_err(Error::DBError)?;
        Ok(())
    }

    /// Do we have a block queued up, and if so, is it being processed?.
    /// Return Some(processed) if the block is queued up
    /// Return None if the block is not queued up
    fn get_staging_block_status(&self, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<bool>, Error> {
        let sql = "SELECT processed FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2".to_string();
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql];

        let processed_i64 = match query_int::<_>(&self.blocks_db, &sql, &args) {
            Ok(processed) => processed,
            Err(e) => {
                match e {
                    db_error::NotFoundError => {
                        return Ok(None);
                    },
                    _ => {
                        return Err(Error::DBError(e));
                    }
                }
            }
        };

        Ok(Some(processed_i64 != 0))
    }

    /// Do we have a microblock queued up, and if so, is it being processed?
    /// Return Some(processed) if the microblock is queued up
    /// Return None if the microblock is not queued up
    fn get_staging_microblock_status(&self, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<Option<bool>, Error> {
        let sql = "SELECT processed FROM staging_microblocks WHERE anchored_block_hash = ?1 AND microblock_hash = ?2 AND burn_header_hash = ?3".to_string();
        let args = [&block_hash.to_hex() as &dyn ToSql, &microblock_hash.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql];

        let processed_i64 = match query_int::<_>(&self.blocks_db, &sql, &args) {
            Ok(processed) => processed,
            Err(e) => {
                match e {
                    db_error::NotFoundError => {
                        return Ok(None);
                    },
                    _ => {
                        return Err(Error::DBError(e));
                    }
                }
            }
        };

        Ok(Some(processed_i64 != 0))
    }
    
    /// Do we have a microblock stream queued up, and if so, is it being processed?
    /// Return Some(processed) if the microblock is queued up
    /// Return None if there is no microblock stream
    fn get_staging_microblock_stream_status(&self, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<bool>, Error> {
        let sql = "SELECT processed FROM staging_microblocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2".to_string();
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql];
        
        let mut stmt = self.blocks_db.prepare(&sql)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let mut rows = stmt.query(&args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let mut num_processed = 0;
        let mut num_unprocessed = 0;

        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let processed : i64 = row.get(0);
                    if processed == 0 {
                        num_unprocessed += 1;
                    }
                    else {
                        num_processed += 1;
                    }
                },
                Err(e) => {
                    return Err(Error::DBError(db_error::SqliteError(e)));
                }
            };
        }

        if num_processed == 0 && num_unprocessed == 0 {
            // no rows, period 
            return Ok(None);
        }
        else if num_processed == 0 && num_unprocessed > 0 {
            // not processed
            return Ok(Some(false));
        }
        else if num_processed > 0 && num_unprocessed == 0 {
            // processed
            return Ok(Some(true));
        }
        else {
            // corrupt
            return Err(Error::DBError(db_error::Corruption));
        }
    }

    /// Do we have a staging block?
    pub fn has_staging_block(&self, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let res = self.get_staging_block_status(burn_hash, block_hash)?.is_some();
        Ok(res)
    }

    /// Do we have a staging microblock?
    pub fn has_staging_microblock(&self, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let res = self.get_staging_microblock_status(burn_hash, block_hash, microblock_hash)?.is_some();
        Ok(res)
    }

    /// Clear out a staging block -- move it to the chunk store (either wholly, or mark it invalid
    /// by writing an empty file)
    fn set_block_processed(&mut self, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, accept: bool) -> Result<(), Error> {
        let row_order = StagingBlock::row_order().join(",");
        let sql = format!("SELECT {} FROM staging_blocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2", row_order);
        let args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql];
      
        let has_stored_block = self.has_stored_block(burn_hash, anchored_block_hash)?;
        let block_path = self.make_block_dir(burn_hash, anchored_block_hash)?;

        let tx = self.blocks_tx_begin()?;
        let rows = query_rows::<StagingBlock, _>(&tx, &sql, &args).map_err(Error::DBError)?;
        let block = match rows.len() {
            0 => {
                return Err(Error::DBError(db_error::NotFoundError));
            },
            1 => {
                rows[0].clone()
            },
            _ => {
                // should never happen
                panic!("Multiple staging blocks with same burn hash and block hash");
            }
        };

        if !block.processed {
            if !has_stored_block {
                if accept {
                    debug!("Accept block {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
                    StacksChainState::atomic_file_write(&block_path, &block.block_data)?;
                }
                else {
                    debug!("Reject block {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
                    StacksChainState::atomic_file_write(&block_path, &vec![])?;
                }
            }
            else {
                debug!("Already stored block {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
            }
        }
        else {
            debug!("Already processed block {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
        }

        let update_sql = "UPDATE staging_blocks SET processed = 1, block_data = ?1 WHERE burn_header_hash = ?2 AND anchored_block_hash = ?3".to_string();
        let update_args = [&(vec![] as Vec<u8>) as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql];

        tx.execute(&update_sql, &update_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        tx.commit()
            .map_err(Error::DBError)?;

        Ok(())
    }

    /// Mark a stream of microblocks as processed -- move them to the chunk store.
    /// All the corresponding blocks must have been validated and proven contiguous
    fn set_microblocks_processed(&mut self, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, accept: bool) -> Result<(), Error> {
        let row_order = StagingMicroblock::row_order().join(",");

        let row_order = StagingMicroblock::row_order().join(",");
        let sql = format!("SELECT {} FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 ORDER BY sequence ASC", row_order);
        let args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql];
        let staging_microblocks = query_rows::<StagingMicroblock, _>(&self.blocks_db, &sql, &args).map_err(Error::DBError)?;

        let mut microblocks = Vec::with_capacity(staging_microblocks.len());
        for smb in staging_microblocks.iter() {
            let mut index = 0;
            let microblock = StacksMicroblock::deserialize(&smb.block_data, &mut index, smb.block_data.len() as u32).map_err(Error::NetError)?;
            microblocks.push(microblock);
        }

        if microblocks.len() > 0 {
            let num_microblocks = microblocks.len();
            if !self.has_stored_block(burn_hash, &microblocks[num_microblocks - 1].block_hash())? {
                if accept {
                    debug!("Accept microblock stream rooted at {}/{}-{}", burn_hash.to_hex(), anchored_block_hash.to_hex(), microblocks[num_microblocks-1].block_hash().to_hex());
                    self.store_microblock_stream(burn_hash, &microblocks)?;
                }
                else {
                    debug!("Reject microblock stream rooted at {}/{}-{}", burn_hash.to_hex(), anchored_block_hash.to_hex(), microblocks[num_microblocks-1].block_hash().to_hex());
                    self.store_empty_block(burn_hash, &microblocks[num_microblocks - 1].block_hash())?;
                }
            }
            else {
                debug!("Already processed microblock stream {}/{}-{}", burn_hash.to_hex(), anchored_block_hash.to_hex(), microblocks[num_microblocks-1].block_hash().to_hex());
            }

            let tx = self.blocks_tx_begin()?;

            // clear out of queue 
            let sql = "UPDATE staging_microblocks SET processed = 1, block_data = ?1 WHERE burn_header_hash = ?2 AND anchored_block_hash = ?3".to_string();
            let args = [&(vec![] as Vec<u8>) as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql];

            tx.execute(&sql, &args)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

            tx.commit()
                .map_err(Error::DBError)?;
        }
        Ok(())
    }
     
    /// Given a microblock stream, does it connect the parent and child anchored blocks?
    /// * verify that the blocks are a contiguous sequence, with no duplicate sequence numbers
    /// * verify that each microblock is signed by the parent anchor block's key
    /// The stream must be in order by sequence number, and there must be no duplicates.
    /// If the stream connects to the anchored block, then
    /// return the index in the given microblocks vec that corresponds to the highest valid
    /// block -- i.e. the microblock indicated by the anchored header as the parent.
    /// If there was a duplicate sequence number, then also return a poison-microblock
    /// transaction for the two headers with the lowest duplicate sequence number.
    /// Return None if the stream does not connect to this block (e.g. it's incomplete or the like)
    fn validate_parent_microblock_stream(parent_anchored_block_header: &StacksBlockHeader, anchored_block_header: &StacksBlockHeader, microblocks: &Vec<StacksMicroblock>) -> Option<(usize, Option<TransactionPayload>)> {
        if parent_anchored_block_header.is_genesis() {
            // there had better be zero microblocks
            if anchored_block_header.parent_microblock == BlockHeaderHash([0u8; 32]) && anchored_block_header.parent_microblock_sequence == 0 {
                return Some((0, None));
            }
            else {
                debug!("Block {} has no ancestor, and should have no microblock parents", anchored_block_header.block_hash().to_hex());
                return None;
            }
        }

        // filter out only signed microblocks
        let mut signed_microblocks = vec![];
        for microblock in microblocks.iter() {
            let mut dup = microblock.clone();
            if dup.verify(&parent_anchored_block_header.microblock_pubkey_hash).is_err() {
                debug!("Microblock {} not signed by {}", microblock.block_hash().to_hex(), parent_anchored_block_header.microblock_pubkey_hash.to_hex());
                continue;
            }
            signed_microblocks.push(microblock.clone());
        }
        
        if signed_microblocks.len() == 0 {
            if anchored_block_header.parent_microblock == BlockHeaderHash([0u8; 32]) && anchored_block_header.parent_microblock_sequence == 0 {
                // expected empty
                debug!("No microblocks between {} and {}", parent_anchored_block_header.block_hash().to_hex(), anchored_block_header.block_hash().to_hex());
                return Some((0, None));
            }
            else {
                // did not expect empty
                debug!("Missing microblocks between {} and {}", parent_anchored_block_header.block_hash().to_hex(), anchored_block_header.block_hash().to_hex());
                return None;
            }
        }
        
        if signed_microblocks[0].header.sequence != 0 {
            // discontiguous -- must start with seq 0
            debug!("Discontiguous stream -- first microblock header sequence is {}", signed_microblocks[0].header.sequence);
            return None;
        }

        if signed_microblocks[0].header.prev_block != parent_anchored_block_header.block_hash() {
            // discontiguous -- not connected to parent
            debug!("Discontiguous stream -- does not connect to parent");
            return None;
        }

        // sanity check -- in order by sequence and no sequence duplicates
        for i in 1..signed_microblocks.len() {
            if signed_microblocks[i-1].header.sequence > signed_microblocks[i].header.sequence {
                panic!("BUG: out-of-sequence microblock stream");
            }
            let cur_seq = (signed_microblocks[i-1].header.sequence as u32) + 1;
            if cur_seq < (signed_microblocks[i].header.sequence as u32) {
                // discontiguous
                debug!("Discontiguous stream -- {} < {}", cur_seq, signed_microblocks[i].header.sequence);
                return None;
            }
        }

        // sanity check -- all parent block hashes are unique.  If there are duplicates, then the
        // miner equivocated.
        let mut parent_hashes : HashMap<BlockHeaderHash, StacksMicroblockHeader> = HashMap::new();
        for i in 0..signed_microblocks.len() {
            let signed_microblock = &signed_microblocks[i];
            if parent_hashes.contains_key(&signed_microblock.header.prev_block) {
                debug!("Deliberate microblock fork: duplicate parent {}", signed_microblock.header.prev_block.to_hex());
                let conflicting_microblock_header = parent_hashes.get(&signed_microblock.header.prev_block).unwrap();

                return Some((i - 1, Some(TransactionPayload::PoisonMicroblock(signed_microblock.header.clone(), conflicting_microblock_header.clone()))));
            }
            parent_hashes.insert(signed_microblock.header.prev_block.clone(), signed_microblock.header.clone());
        }

        // hashes are contiguous enough -- for each seqnum, there is a block with seqnum+1 with the
        // block at seqnum as its parent.  There may be more than one.
        for i in 1..signed_microblocks.len() {
            if signed_microblocks[i - 1].header.sequence == signed_microblocks[i].header.sequence && signed_microblocks[i - 1].block_hash() != signed_microblocks[i].block_hash() {
                // deliberate microblock fork
                debug!("Deliberate microblock fork at sequence {}", signed_microblocks[i-1].header.sequence);
                return Some((i - 1, Some(TransactionPayload::PoisonMicroblock(signed_microblocks[i - 1].header.clone(), signed_microblocks[i].header.clone()))));
            }

            if signed_microblocks[i - 1].block_hash() != signed_microblocks[i].header.prev_block {
                // discontiguous
                debug!("Discontinuous stream -- blocks not linked by hash");
                return None;
            }
        }
        
        if anchored_block_header.parent_microblock == BlockHeaderHash([0u8; 32]) && anchored_block_header.parent_microblock_sequence == 0 {
            // expected empty
            debug!("Empty microblock stream between {} and {}", parent_anchored_block_header.block_hash().to_hex(), anchored_block_header.block_hash().to_hex());
            return Some((0, None));
        }

        let num_microblocks = microblocks.len();

        let mut end = 0;
        let mut connects = false;
        for i in 0..num_microblocks {
            if microblocks[i].block_hash() == anchored_block_header.parent_microblock {
                end = i + 1;
                connects = true;
                break;
            }
        }

        if !connects {
            // discontiguous
            debug!("Discontiguous stream: block {} does not connect to tail", anchored_block_header.block_hash().to_hex());
            return None;
        }

        return Some((end, None));
    }

    /// Validate an anchored block against the burn chain state.
    /// * burn_header_hash is the burnchain block header hash of the burnchain block whose sortition
    /// (ostensibly) selected this block for inclusion.
    pub fn validate_anchored_block_burnchain<'a>(tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock) -> Result<bool, Error> {
        // sortition-winning block commit for this block?
        let block_commit = match BurnDB::get_block_commit_for_stacks_block(tx, burn_header_hash, &block.block_hash()).map_err(Error::DBError)? {
            Some(bc) => bc,
            None => {
                // unsoliciated
                return Ok(false);
            }
        };

        // burn chain tip that selected this commit's block
        let burn_chain_tip = BurnDB::get_block_snapshot(tx, &block_commit.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no block snapshot");
        
        // snapshot that elected this block commit
        let sortition_snapshot = BurnDB::get_block_snapshot_in_fork(tx, block_commit.block_height - 1, &block_commit.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no sortition snapshot");

        // key of the winning leader
        let leader_key = BurnDB::get_leader_key_at(tx, block_commit.key_block_ptr as u64, block_commit.key_vtxindex as u32, &burn_chain_tip.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no leader key");

        // get the stacks chain tip this block commit builds off of
        let stacks_chain_tip = 
            if block_commit.parent_block_ptr == 0 && block_commit.parent_vtxindex == 0 {
                // no parent -- this is the first-ever Stacks block in this fork
                BurnDB::get_first_block_snapshot(tx).map_err(Error::DBError)?
            }
            else {
                let parent_commit = match BurnDB::get_block_commit_parent(tx, block_commit.parent_block_ptr.into(), block_commit.parent_vtxindex.into(), burn_header_hash).map_err(Error::DBError)? {
                    Some(commit) => commit,
                    None => {
                        // unsolicited -- orphaned
                        return Ok(false);
                    }
                };

                BurnDB::get_block_snapshot(tx, &parent_commit.burn_header_hash)
                    .map_err(Error::DBError)?
                    .expect("FATAL: burn DB does not have snapshot for parent block commit")
            };

        let valid = block.header.validate_burnchain(&burn_chain_tip, &sortition_snapshot, &leader_key, &block_commit, &stacks_chain_tip);
        Ok(valid)
    }

    /// Pre-process and store an anchored block to staging, queuing it up for
    /// subsequent processing once all of its ancestors have been processed.
    ///
    /// Caller must have called BurnDB::expects_stacks_block() to determine if this block belongs
    /// to the blockchain.  The burn_header_hash is the hash of the burnchain block whose sortition
    /// elected the given Stacks block.
    pub fn preprocess_anchored_block<'a>(&mut self, burn_tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash) -> Result<bool, Error> {
        // already in queue or already processed?
        if self.has_stored_block(burn_header_hash, &block.block_hash())? || self.has_staging_block(burn_header_hash, &block.block_hash())? {
            return Ok(false);
        }
        
        // does this block match the burnchain state? skip if so
        let valid_burnchain = StacksChainState::validate_anchored_block_burnchain(burn_tx, burn_header_hash, block)?;
        if !valid_burnchain {
            let msg = format!("Invalid block {}: does not correspond to burn chain state", block.block_hash());
            warn!("{}", &msg);

            return Err(Error::InvalidStacksBlock(msg));
        }
     
        // queue block up for processing
        self.store_staging_block(burn_header_hash, &block, parent_burn_header_hash)?;

        // ready to go
        Ok(true)
    }

    /// Pre-process and store a microblock to staging, queueing it up for subsequent processing
    /// once all of its ancestors have been processed.
    /// 
    /// The anchored block this microblock builds off of must have already been stored somewhere,
    /// staging or accepted, so we can verify the signature over this block.
    ///
    /// Because microblocks are stored in a file named after their tail block's hash, the file will
    /// be renamed.
    ///
    /// This method is `&mut self` to ensure that concurrent renames don't corrupt our chain state.
    pub fn preprocess_streamed_microblock<'a>(&mut self, burn_tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, microblock: &StacksMicroblock) -> Result<bool, Error> {
        // already queued or already processed?
        if self.has_staging_microblock(burn_header_hash, anchored_block_hash, &microblock.block_hash())? {
            return Ok(true);
        }

        let pubkey_hash = match self.load_staging_block_pubkey_hash(burn_header_hash, anchored_block_hash)? {
            Some(pubkey_hash) => pubkey_hash,
            None => {
                // maybe it's already processed?
                let header = match self.load_block_header(burn_header_hash, anchored_block_hash)? {
                    Some(block_header) => block_header,
                    None => {
                        // parent isn't available
                        return Ok(false);
                    }
                };
                header.microblock_pubkey_hash.clone()
            }
        };

        let mut dup = microblock.clone();
        if dup.verify(&pubkey_hash).is_err() {
            test_debug!("Invalid microblock {}: failed to verify", microblock.block_hash().to_hex());
            return Ok(false);
        }

        // add to staging
        self.store_staging_microblock(burn_header_hash, anchored_block_hash, microblock)?;
        Ok(true)
    }

    /// Get the coinbase at this block height
    fn get_coinbase_reward(block_height: u64) -> u128 {
        /*
        From the token whitepaper:

        """
        We expect that once native mining goes live, approximately 4383 blocks will be pro-
        cessed per month, or approximately 52,596 blocks will be processed per year. With our
        design for the adaptive mint and burn mechanism, min mint is equal to 500 tokens per
        block for the first approximately five years (or 262,980 blocks), 400 tokens per block for
        the next approximately five years, and then 300 tokens per block for all years thereafter.
        During these times, a minimum of 500 tokens, 400 tokens, and 300 tokens, respectively,
        will be released per block regardless of Stacks tokens burned on the network.
        """
        */
        let blocks_per_year = 52596;
        if block_height < blocks_per_year * 5 {
            500
        }
        else if block_height < blocks_per_year * 10 {
            400
        }
        else {
            300
        }
    }

    /// Create the block reward
    fn make_miner_reward(mainnet: bool, block: &StacksBlock, block_height: u64, tx_fees: u128, streamed_fees: u128, burns: u128) -> Result<MinerPaymentSchedule, Error> {
        let coinbase_tx = block.get_coinbase_tx().ok_or(Error::InvalidStacksBlock("No coinbase transaction".to_string()))?;
        let miner_auth = coinbase_tx.get_origin();
        let miner_addr = 
            if mainnet {
                miner_auth.address_mainnet()
            }
            else {
                miner_auth.address_testnet()
            };

        let miner_reward = MinerPaymentSchedule {
            address: miner_addr,
            block_hash: block.block_hash(),
            coinbase: StacksChainState::get_coinbase_reward(block_height),
            tx_fees_anchored: tx_fees,
            tx_fees_streamed: streamed_fees,
            burns: burns
        };
        
        Ok(miner_reward)
    }
   
    /// Given a staging block, load up its parent microblock stream from staging.
    /// Return Ok(Some(microblocks)) if we got microblocks (even if it's an empty stream)
    /// Return Ok(None) if there are no staging microblocks yet
    fn find_next_staging_microblock_stream(&self, staging_block: &StagingBlock) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        match self.load_staging_microblock_stream(&staging_block.parent_burn_header_hash, &staging_block.parent_anchored_block_hash)? {
            Some(microblocks) => {
                return Ok(Some(microblocks));
            }
            None => {
                // either all processed, or no microblocks
                let mut index = 0;
                let block = StacksBlock::deserialize(&staging_block.block_data, &mut index, staging_block.block_data.len() as u32).map_err(Error::NetError)?;
                if block.header.parent_microblock_sequence == 0 && block.header.parent_microblock == BlockHeaderHash([0u8; 32]) {
                    // no microblocks in the first place
                    return Ok(Some(vec![]));
                }
                else {
                    // microblocks haven't arrived yet
                    debug!("No parent microblock stream for {}: expected {},{}", block.block_hash().to_hex(), block.header.parent_microblock.to_hex(), block.header.parent_microblock_sequence);
                    return Ok(None);
                }
            }
        }
    }

    /// Find the next queued microblock stream and anchored block to process, if available.
    /// Try to process blocks whose parents are in the list of priority_chain_tips.
    fn find_next_staging_block(&self, priority_chain_tips: &Vec<StacksHeaderInfo>) -> Result<Option<(StagingBlock, Vec<StacksMicroblock>)>, Error> {
        let row_order = StagingBlock::row_order().join(",");
        for priority_chain_tip in priority_chain_tips.iter() {
            let sql = format!("SELECT {} FROM staging_blocks WHERE processed = 0 AND parent_anchored_block_hash = ?1 AND parent_burn_header_hash = ?2 LIMIT 1", &row_order);
            let args = [&priority_chain_tip.anchored_header.block_hash().to_hex() as &dyn ToSql, &priority_chain_tip.burn_header_hash.to_hex() as &dyn ToSql];
            let rows = query_rows::<StagingBlock, _>(&self.blocks_db, &sql, &args).map_err(Error::DBError)?;
            if rows.len() > 0 {
                let staging_block = rows[0].clone();
                let microblocks = match self.find_next_staging_microblock_stream(&staging_block)? {
                    Some(microblocks) => {
                        return Ok(Some((staging_block, microblocks)));
                    }
                    None => {}
                };
            }
        }

        // pick a random block 
        let sql = format!("SELECT {} FROM staging_blocks WHERE processed = 0 ORDER BY RANDOM() LIMIT 1", &row_order);
        let rows = query_rows::<StagingBlock, _>(&self.blocks_db, &sql, NO_PARAMS).map_err(Error::DBError)?;
        if rows.len() > 0 {
            let staging_block = rows[0].clone();
            let microblocks = match self.find_next_staging_microblock_stream(&staging_block)? {
                Some(microblocks) => {
                    return Ok(Some((staging_block, microblocks)));
                }
                None => {
                    debug!("Missing parent microblock stream for {}", staging_block.anchored_block_hash.to_hex());
                }
            };
        }

        // no staging blocks, or no staging blocks with parent microblock streams
        return Ok(None);
    }

    /// Process a stream of microblocks
    /// Return the fees and burns.
    fn process_microblocks_transactions<'a>(clarity_tx: &mut ClarityTx<'a>, microblocks: &Vec<StacksMicroblock>) -> Result<(u128, u128), Error> {
        let mut fees = 0u128;
        let mut burns = 0u128;
        for microblock in microblocks.iter() {
            for tx in microblock.txs.iter() {
                let (tx_fee, tx_burns) = StacksChainState::process_transaction(clarity_tx, tx)?;
                fees = fees.checked_add(tx_fee as u128).expect("Fee overflow");
                burns = burns.checked_add(tx_burns as u128).expect("Burns overflow");
            }
        }
        Ok((fees, burns))
    }

    /// Process a single anchored block.
    /// Return the fees and burns.
    fn process_block_transactions<'a>(clarity_tx: &mut ClarityTx<'a>, block: &StacksBlock) -> Result<(u128, u128), Error> {
        let mut fees = 0u128;
        let mut burns = 0u128;
        for tx in block.txs.iter() {
            let (tx_fee, tx_burns) = StacksChainState::process_transaction(clarity_tx, tx)?;
            fees = fees.checked_add(tx_fee as u128).expect("Fee overflow");
            burns = burns.checked_add(tx_burns as u128).expect("Burns overflow");
        }
        Ok((fees, burns))
    }

    /// Process the next pre-processed staging block.
    /// We've already processed parent_chain_tip.  chain_tip refers to a block we have _not_
    /// processed yet.
    /// Returns a StacksHeaderInfo with the microblock stream and chain state index root hash filled in, corresponding to the next block to process.
    /// Returns None if we're out of blocks to process.
    fn append_block(&mut self, parent_chain_tip: &StacksHeaderInfo, chain_tip_burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock, microblocks: &Vec<StacksMicroblock>) -> Result<StacksHeaderInfo, Error> {
        let mainnet = self.mainnet;
        let block_hash = block.block_hash();
        let next_block_height = parent_chain_tip.block_height.checked_add(1).expect("Blockchain overflow");
        if next_block_height > (u32::max_value() as u64) {
            panic!("Blockchain overflow!");
        }

        // this looks awkward, but it keeps the borrow checker happy
        let inner_process_block = |state: &mut StacksChainState| {
            let (parent_burn_header_hash, parent_block_hash) = 
                if block.header.is_genesis() {
                    // has to be all 0's if this block has no parent
                    (BurnchainHeaderHash([0u8; 32]), BlockHeaderHash([0u8; 32]))
                }
                else {
                    (parent_chain_tip.burn_header_hash.clone(), parent_chain_tip.anchored_header.block_hash())
                };

            debug!("Append block {}/{} off of {}/{}", chain_tip_burn_header_hash.to_hex(), block.block_hash().to_hex(), parent_burn_header_hash.to_hex(), parent_block_hash.to_hex());
            
            // NOTE: need to insert the child block's hashes as all 0's, since this is what the
            // miner would have done when they mined the block.
            let mut clarity_tx = state.block_begin(&parent_burn_header_hash, &parent_block_hash, &BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]));
            let (microblock_fees, microblock_burns) = match StacksChainState::process_microblocks_transactions(&mut clarity_tx, &microblocks) {
                Err(e) => {
                    let msg = format!("Invalid Stacks microblocks {},{}: {:?}", block.header.parent_microblock.to_hex(), block.header.parent_microblock_sequence, &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok((fees, burns)) => {
                    (fees, burns)
                }
            };

            let (block_fees, block_burns) = match StacksChainState::process_block_transactions(&mut clarity_tx, &block) {
                Err(e) => {
                    let msg = format!("Invalid Stacks block {}: {:?}", block.block_hash().to_hex(), &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok((block_fees, block_burns)) => (block_fees, block_burns)
            };

            let root_hash = clarity_tx.get_root_hash();
            if root_hash != block.header.state_index_root {
                let msg = format!("Block {} state root mismatch: expected {}, got {}", block.block_hash(), root_hash, block.header.state_index_root);
                warn!("{}", &msg);
                
                clarity_tx.rollback_block();
                return Err(Error::InvalidStacksBlock(msg));
            }

            debug!("Reached state root {}", root_hash.to_hex());

            let miner_reward = match StacksChainState::make_miner_reward(mainnet, &block, next_block_height, block_fees, microblock_fees, block_burns) {
                Err(e) => {
                    let msg = format!("Invalid Stacks block {}: failed to find coinbase", block.block_hash().to_hex());
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok(reward) => reward
            };

            // good to go!
            clarity_tx.commit_to_block(next_block_height as u32, chain_tip_burn_header_hash, &block.block_hash());
            Ok(miner_reward)
        };

        let miner_reward = match inner_process_block(self) {
            Err(e) => {
                self.free_block_state(chain_tip_burn_header_hash, &block.header).expect("Failed to free block state");
                return Err(e);
            },
            Ok(reward) => reward
        };
        
        let mut new_tip = self.advance_tip(&parent_chain_tip.anchored_header, &parent_chain_tip.burn_header_hash, parent_chain_tip.block_height, &block.header, chain_tip_burn_header_hash, &miner_reward)?;
        new_tip.microblock_tail = match microblocks.len() {
            0 => None,
            x => Some(microblocks[x - 1].header.clone())
        };

        Ok(new_tip)
    }

    /// Find and process the next staging block.
    /// Return the next chain tip if we processed this block, or None if we couldn't.
    /// Return a poison microblock transaction payload if the microblock stream contains a
    /// deliberate miner fork.
    pub fn process_next_staging_block(&mut self, priority_chain_tips: &Vec<StacksHeaderInfo>) -> Result<(Option<StacksHeaderInfo>, Option<TransactionPayload>), Error> {
        let (next_staging_block, mut next_microblocks) = match self.find_next_staging_block(priority_chain_tips)? {
            Some((next_staging_block, next_microblocks)) => (next_staging_block, next_microblocks),
            None => {
                // no more work to do!
                debug!("No staging blocks");
                return Ok((None, None));
            }
        };

        debug!("Process staging block {}/{}", next_staging_block.burn_header_hash.to_hex(), next_staging_block.anchored_block_hash.to_hex());

        let parent_block_header_info = {
            let header_tx = self.headers_tx_begin()?;
            
            let parent_block_header_info = match StacksChainState::get_anchored_block_header_info(&header_tx, &next_staging_block.parent_burn_header_hash, &next_staging_block.parent_anchored_block_hash)? {
                Some(parent_info) => {
                    debug!("Found parent info {}/{}", next_staging_block.parent_burn_header_hash.to_hex(), next_staging_block.parent_anchored_block_hash.to_hex());
                    parent_info
                },
                None => {
                    if next_staging_block.is_genesis() {
                        // this is the first-ever block
                        debug!("This is the first-ever block in this fork.  Parent is 00000000..00000000/00000000..00000000");
                        StacksHeaderInfo::genesis()
                    }
                    else {
                        // no parent stored
                        debug!("No parent block for {}/{} processed yet", next_staging_block.burn_header_hash.to_hex(), next_staging_block.anchored_block_hash.to_hex());
                        return Ok((None, None));
                    }
                }
            };

            parent_block_header_info
        };

        let block = {
            let mut index = 0;
            StacksBlock::deserialize(&next_staging_block.block_data, &mut index, next_staging_block.block_data.len() as u32).map_err(Error::NetError)?
        };

        let block_hash = block.block_hash();
        if block_hash != next_staging_block.anchored_block_hash {
            // database corruption
            error!("Staging DB corruption: expected block {}, got {}", block_hash.to_hex(), next_staging_block.anchored_block_hash.to_hex());
            return Err(Error::DBError(db_error::Corruption));
        }

        // sanity check
        if self.has_stored_block(&next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash)? {
            debug!("Block already processed: {}/{}", &next_staging_block.burn_header_hash.to_hex(), &next_staging_block.anchored_block_hash.to_hex());

            // clear out
            self.set_block_processed(&next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash, true)?;
            return Ok((None, None));
        }

        // validate microblocks
        let (microblock_terminus, poison_microblock_opt) = match StacksChainState::validate_parent_microblock_stream(&parent_block_header_info.anchored_header, &block.header, &next_microblocks) {
            Some((terminus, poison_opt)) => (terminus, poison_opt),
            None => {
                debug!("Stopping at block {}/{} -- discontiguous header stream", next_staging_block.burn_header_hash.to_hex(), block_hash.to_hex());
                return Ok((None, None));
            }
        };

        match poison_microblock_opt {
            Some(poison_microblock) => {
                // miner created a deliberate fork
                return Ok((None, Some(poison_microblock)));
            }
            None => {}
        }

        // drop trailing microblocks
        if microblock_terminus < next_microblocks.len() {
            debug!("Truncate microblock stream from parent {}/{} from {} to {} items", parent_block_header_info.burn_header_hash.to_hex(), parent_block_header_info.anchored_header.block_hash().to_hex(), next_microblocks.len(), microblock_terminus);
            next_microblocks.truncate(microblock_terminus);
        }

        // find the corresponding stacks chain tip
        let next_chain_tip = self.append_block(&parent_block_header_info, &next_staging_block.burn_header_hash, &block, &next_microblocks)?;
        assert_eq!(next_chain_tip.anchored_header.block_hash(), block.block_hash());
        assert_eq!(next_chain_tip.burn_header_hash, next_staging_block.burn_header_hash);

        debug!("Reached chain tip {}/{} from {}/{}", next_chain_tip.burn_header_hash.to_hex(), next_chain_tip.anchored_header.block_hash().to_hex(), next_staging_block.parent_burn_header_hash.to_hex(), next_staging_block.parent_anchored_block_hash.to_hex());

        // move over to chunk store
        self.set_block_processed(&next_chain_tip.burn_header_hash, &next_chain_tip.anchored_header.block_hash(), true)?;
        self.set_microblocks_processed(&next_chain_tip.burn_header_hash, &next_chain_tip.anchored_header.block_hash(), true)?;
        
        Ok((Some(next_chain_tip), None))
    }

    /// Process some staging blocks, up to max_blocks.
    /// Return new chain tips, and optionally any poison microblock payloads for each chain tip
    /// found.
    pub fn process_blocks(&mut self, burndb_conn: &DBConn, max_blocks: usize) -> Result<Vec<(Option<StacksHeaderInfo>, Option<TransactionPayload>)>, Error> {
        let mut ret = vec![];

        if max_blocks == 0 {
            // nothing to do
            return Ok(vec![]);
        }

        // prioritize processing the best chain tip
        let best_chain_tip_snapshot = match BurnDB::get_canonical_stacks_chain_tip(burndb_conn).map_err(Error::DBError)? {
            Some(sn) => sn,
            None => {
                // nothing to do
                debug!("No Stacks blocks mined yet");
                return Ok(vec![]);
            }
        };

        let best_chain_tips = match StacksChainState::get_anchored_block_header_info(&self.headers_db, &best_chain_tip_snapshot.burn_header_hash, &best_chain_tip_snapshot.winning_stacks_block_hash)? {
            Some(tip) => {
                debug!("Canonical stacks chain tip is {}/{}", &best_chain_tip_snapshot.burn_header_hash.to_hex(), &best_chain_tip_snapshot.winning_stacks_block_hash.to_hex());
                vec![tip]
            },
            None => {
                debug!("No canonical stacks chain tip yet");
                vec![]
            }
        };

        let (next_tip_opt, next_microblock_poison_opt) = self.process_next_staging_block(&best_chain_tips)?;
        match next_tip_opt {
            Some(next_tip) => {
                ret.push((Some(next_tip), next_microblock_poison_opt));
            },
            None => {
                match next_microblock_poison_opt {
                    Some(poison) => {
                        ret.push((None, Some(poison)));
                    },
                    None => {}
                }
            }
        }

        for i in 0..(max_blocks-1) {
            // process any other pending 
            let (next_tip_opt, next_microblock_poison_opt) = self.process_next_staging_block(&vec![])?;
            match next_tip_opt {
                Some(next_tip) => {
                    ret.push((Some(next_tip), next_microblock_poison_opt));
                },
                None => {
                    match next_microblock_poison_opt {
                        Some(poison) => {
                            ret.push((None, Some(poison)));
                        },
                        None => {}
                    }
                }
            }
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chainstate::stacks::*;
    use chainstate::stacks::db::*;
    use chainstate::stacks::db::test::*;
        
    use burnchains::*;
    use chainstate::burn::*;
    use util::db::*;
    use util::hash::*;

    use std::fs;

    fn make_empty_coinbase_block(mblock_key: &StacksPrivateKey) -> StacksBlock {
        let privk = StacksPrivateKey::from_hex("59e4d5e18351d6027a37920efe53c2f1cbadc50dca7d77169b7291dff936ed6d01").unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let proof_bytes = hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();
        
        let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Testnet, auth, TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);

        tx_signer.sign_origin(&privk).unwrap();

        let tx_coinbase_signed = tx_signer.get_tx().unwrap();
        let txs = vec![tx_coinbase_signed];

        let txid_vecs = txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();

        let work_score = StacksWorkScore {
            burn: 123,
            work: 456,
        };

        let parent_header = StacksBlockHeader {
            version: 0x01,
            total_work: StacksWorkScore {
                burn: 234,
                work: 567,
            },
            proof: proof.clone(),
            parent_block: BlockHeaderHash([5u8; 32]),
            parent_microblock: BlockHeaderHash([6u8; 32]),
            parent_microblock_sequence: 4,
            tx_merkle_root: Sha512Trunc256Sum([7u8; 32]),
            state_index_root: TrieHash([8u8; 32]),
            microblock_pubkey_hash: Hash160([9u8; 20]),
        };
        
        let parent_microblock_header = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: BlockHeaderHash([0x0au8; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x0bu8; 32]),
            signature: MessageSignature([0x0cu8; 65]),
        };

        let mblock_pubkey_hash = Hash160::from_data(&StacksPublicKey::from_private(mblock_key).to_bytes());
        let mut block = StacksBlock::from_parent(&parent_header, &parent_microblock_header, txs.clone(), &work_score, &proof, &TrieHash([2u8; 32]), &mblock_pubkey_hash);
        block.header.version = 0x24;
        block
    }

    fn make_sample_microblock_stream(privk: &StacksPrivateKey, anchored_block_hash: &BlockHeaderHash) -> Vec<StacksMicroblock> {
        let mut all_txs = vec![];
        let mut microblocks : Vec<StacksMicroblock> = vec![];

        for i in 0..49 {
            let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
            let tx_smart_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                           auth.clone(),
                                                           TransactionPayload::new_smart_contract(&"name".to_string(), &format!("hello smart contract {}", i)).unwrap());
            let mut tx_signer = StacksTransactionSigner::new(&tx_smart_contract);
            tx_signer.sign_origin(&privk).unwrap();

            let tx_signed = tx_signer.get_tx().unwrap();
            all_txs.push(tx_signed);
        }

        // make microblocks with 3 transactions each (or fewer)
        for i in 0..(all_txs.len() / 3) {
            let txs = vec![
                all_txs[3*i].clone(),
                all_txs[3*i+1].clone(),
                all_txs[3*i+2].clone()
            ];

            let txid_vecs = txs
                .iter()
                .map(|tx| tx.txid().as_bytes().to_vec())
                .collect();

            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
            let tx_merkle_root = merkle_tree.root();

            let prev_block = 
                if i == 0 { 
                    anchored_block_hash.clone() 
                }
                else { 
                    let l = microblocks.len();
                    microblocks[l-1].block_hash()
                };

            let header = StacksMicroblockHeader {
                version: 0x12,
                sequence: i as u8,
                prev_block: prev_block,
                tx_merkle_root: tx_merkle_root,
                signature: MessageSignature([0u8; 65])
            };
            
            let mut mblock = StacksMicroblock {
                header: header,
                txs: txs
            };

            mblock.sign(privk).unwrap();
            microblocks.push(mblock);
        }

        microblocks
    }

    fn resign_microblocks(microblocks: &mut Vec<StacksMicroblock>, privk: &StacksPrivateKey) -> BlockHeaderHash {
        for i in 0..microblocks.len() {
            microblocks[i].header.signature = MessageSignature([0u8; 65]);
            microblocks[i].sign(privk).unwrap();
            if i + 1 < microblocks.len() {
                microblocks[i+1].header.prev_block = microblocks[i].block_hash();
            }
        }
        let l = microblocks.len();
        microblocks[l-1].block_hash()
    }

    #[test]
    fn stacks_db_block_load_store_empty() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_block_load_store_empty");
       
        let path = chainstate.get_block_path(&BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap();
        assert!(fs::metadata(&path).is_err());
        assert!(!chainstate.has_stored_block(&BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap());

        chainstate.store_empty_block(&BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap();
        assert!(fs::metadata(&path).is_ok());
        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap().is_none());
    }

    #[test]
    fn stacks_db_block_load_store() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_block_load_store");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let mut block = make_empty_coinbase_block(&privk);

        // don't worry about freeing microblcok state yet
        block.header.parent_microblock_sequence = 0;
        block.header.parent_microblock = BlockHeaderHash([0u8; 32]);

        let path = chainstate.get_block_path(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap();
        assert!(fs::metadata(&path).is_err());
        assert!(!chainstate.has_stored_block(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());

        chainstate.store_block(&BurnchainHeaderHash([1u8; 32]), &block).unwrap();
        assert!(fs::metadata(&path).is_ok());
        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_block(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(chainstate.load_block_header(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header);

        chainstate.free_block_state(&BurnchainHeaderHash([1u8; 32]), &block.header).unwrap();

        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_none());
        assert!(chainstate.load_block_header(&BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_none());
    }

    #[test]
    fn stacks_db_staging_block_load_store_accept() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        chainstate.store_staging_block(&BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32])).unwrap();

        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), false);

        assert!(!chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert!(chainstate.load_block_header(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert_eq!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header.microblock_pubkey_hash);

        chainstate.set_block_processed(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), true).unwrap();

        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(chainstate.load_block_header(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header);
        assert!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), true);
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
    }
    
    #[test]
    fn stacks_db_staging_block_load_store_reject() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_reject");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        chainstate.store_staging_block(&BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32])).unwrap();

        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), false);

        assert!(!chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert!(chainstate.load_block_header(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert_eq!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header.microblock_pubkey_hash);

        chainstate.set_block_processed(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), false).unwrap();

        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
        assert!(chainstate.load_block_header(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
        assert!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), true);
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
    }

    #[test]
    fn stacks_db_load_store_microblock_stream() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_load_store_microblock_stream");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        let num_mblocks = microblocks.len();

        let path = chainstate.get_block_path(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap();
        assert!(fs::metadata(&path).is_err());
        assert!(!chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap());
        assert!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).is_err());

        chainstate.store_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks).unwrap();

        assert!(fs::metadata(&path).is_ok());
        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap());
        assert!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap().unwrap(), microblocks);

        chainstate.free_block(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap();

        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap());
        assert!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap().is_none());
    }

    #[test]
    fn stacks_db_staging_microblock_stream_load_store_accept() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_microblock_stream_load_store_accept");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        let num_mblocks = microblocks.len();
        
        assert!(chainstate.load_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_none());
        assert!(chainstate.load_staging_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        chainstate.store_staging_block(&BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32])).unwrap();
        for mb in microblocks.iter() {
            chainstate.store_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), mb).unwrap();
        }

        // block should be stored to staging
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), false);

        // microblock stream should be stored to staging
        assert!(chainstate.load_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().unwrap(), microblocks[0]);
        assert_eq!(chainstate.load_staging_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), microblocks);

        // block should _not_ be in the chunk store
        assert!(!chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert!(chainstate.load_block_header(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert_eq!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header.microblock_pubkey_hash);

        // microblocks should _not_ be in the chunk store
        assert!(!chainstate.has_stored_microblocks(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap());
        assert!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).is_err());

        chainstate.set_block_processed(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), true).unwrap();
        chainstate.set_microblocks_processed(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), true).unwrap();

        // block should be stored to chunk store now
        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(chainstate.load_block_header(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header);

        // block should be processed in staging, but the data should not be in the staging DB
        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), true);
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
        assert!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        // microblocks should be in the chunk store
        assert!(chainstate.has_stored_microblocks(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap());
        assert_eq!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap().unwrap(), microblocks);

        // microblocks should be absent from staging
        for mb in microblocks.iter() {
            assert!(chainstate.get_staging_microblock_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().is_some());
            assert_eq!(chainstate.get_staging_microblock_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().unwrap(), true);
        }
        
        assert!(chainstate.load_staging_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
    }
    
    #[test]
    fn stacks_db_staging_microblock_stream_load_store_reject() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_microblock_stream_load_store_reject");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        let num_mblocks = microblocks.len();
        
        assert!(chainstate.load_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_none());
        assert!(chainstate.load_staging_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        chainstate.store_staging_block(&BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32])).unwrap();
        for mb in microblocks.iter() {
            chainstate.store_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), mb).unwrap();
        }

        // block should be stored to staging
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), false);

        // microblock stream should be stored to staging
        assert!(chainstate.load_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_some());
        assert_eq!(chainstate.load_staging_microblock(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().unwrap(), microblocks[0]);
        assert_eq!(chainstate.load_staging_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), microblocks);

        // block should _not_ be in the chunk store
        assert!(!chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert!(chainstate.load_block_header(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).is_err());
        assert_eq!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header.microblock_pubkey_hash);

        // microblocks should _not_ be in the chunk store
        assert!(!chainstate.has_stored_microblocks(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap());
        assert!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).is_err());

        chainstate.set_block_processed(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), false).unwrap();
        chainstate.set_microblocks_processed(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), false).unwrap();

        // empty block should be stored to chunk store now
        assert!(chainstate.has_stored_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap());
        assert!(chainstate.load_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        // block should be processed in staging, but the data should not be in the staging DB
        assert_eq!(chainstate.get_staging_block_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().unwrap(), true);
        assert!(chainstate.load_staging_block(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
        assert!(chainstate.load_staging_block_pubkey_hash(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        // microblocks should not be in the chunk store (just an empty file)
        assert!(chainstate.has_stored_microblocks(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap());
        assert!(chainstate.load_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &microblocks[num_mblocks-1].block_hash()).unwrap().is_none());

        // microblocks should be absent from staging
        for mb in microblocks.iter() {
            assert!(chainstate.get_staging_microblock_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().is_some());
            assert_eq!(chainstate.get_staging_microblock_status(&BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().unwrap(), true);
        }
        
        assert!(chainstate.load_staging_microblock_stream(&BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());
    }

    #[test]
    fn stacks_db_validate_parent_microblock_stream() {
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        let num_mblocks = microblocks.len();

        let proof_bytes = hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

        let child_block_header = StacksBlockHeader {
            version: 0x01,
            total_work: StacksWorkScore {
                burn: 234,
                work: 567,
            },
            proof: proof.clone(),
            parent_block: block.block_hash(),
            parent_microblock: microblocks[num_mblocks-1].block_hash(),
            parent_microblock_sequence: microblocks[num_mblocks-1].header.sequence,
            tx_merkle_root: Sha512Trunc256Sum([7u8; 32]),
            state_index_root: TrieHash([8u8; 32]),
            microblock_pubkey_hash: Hash160([9u8; 20])
        };
 
        // contiguous, non-empty stream
        {
            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header, &microblocks);
            assert!(res.is_some());

            let (cutoff, poison_opt) = res.unwrap();
            assert!(poison_opt.is_none());
            assert_eq!(cutoff, num_mblocks);
        }

        // empty stream
        { 
            let mut child_block_header_empty = child_block_header.clone();
            child_block_header_empty.parent_microblock = BlockHeaderHash([0u8; 32]);
            child_block_header_empty.parent_microblock_sequence = 0;

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_empty, &vec![]);
            assert!(res.is_some());

            let (cutoff, poison_opt) = res.unwrap();
            assert!(poison_opt.is_none());
            assert_eq!(cutoff, 0);
        }
        
        // non-empty stream, but child drops all microblocks
        { 
            let mut child_block_header_empty = child_block_header.clone();
            child_block_header_empty.parent_microblock = BlockHeaderHash([0u8; 32]);
            child_block_header_empty.parent_microblock_sequence = 0;

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_empty, &microblocks);
            assert!(res.is_some());

            let (cutoff, poison_opt) = res.unwrap();
            assert!(poison_opt.is_none());
            assert_eq!(cutoff, 0);
        }
        
        // non-empty stream, but child drops some microblocks
        {
            for i in 0..num_mblocks-1 {
                let mut child_block_header_trunc = child_block_header.clone();
                child_block_header_trunc.parent_microblock = microblocks[i].block_hash();
                child_block_header_trunc.parent_microblock_sequence = microblocks[i].header.sequence;

                let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_trunc, &microblocks);
                assert!(res.is_some());

                let (cutoff, poison_opt) = res.unwrap();
                assert!(poison_opt.is_none());
                assert_eq!(cutoff, i+1);
            }
        }
        
        // non-empty stream, but child does not identify any block as its parent
        { 
            let mut child_block_header_broken = child_block_header.clone();
            child_block_header_broken.parent_microblock = BlockHeaderHash([1u8; 32]);
            child_block_header_broken.parent_microblock_sequence = 5;

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_broken, &microblocks);
            assert!(res.is_none());
        }

        // non-empty stream, but missing first microblock
        { 
            let mut broken_microblocks = vec![];
            for i in 1..num_mblocks {
                broken_microblocks.push(microblocks[i].clone());
            }
            
            let mut new_child_block_header = child_block_header.clone();
            new_child_block_header.parent_microblock = resign_microblocks(&mut broken_microblocks, &privk);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks);
            assert!(res.is_none());
        }
        
        // non-empty stream, but missing intermediate microblock
        { 
            let mut broken_microblocks = vec![];
            let missing = num_mblocks / 2;
            for i in 0..num_mblocks {
                if i != missing {
                    broken_microblocks.push(microblocks[i].clone());
                }
            }
            
            let mut new_child_block_header = child_block_header.clone();
            new_child_block_header.parent_microblock = resign_microblocks(&mut broken_microblocks, &privk);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks);
            assert!(res.is_none());
        }
        
        // nonempty stream, but discontiguous first microblock (doesn't connect to parent block)
        {
            let mut broken_microblocks = microblocks.clone();
            broken_microblocks[0].header.prev_block = BlockHeaderHash([1u8; 32]);

            let mut new_child_block_header = child_block_header.clone();
            new_child_block_header.parent_microblock = resign_microblocks(&mut broken_microblocks, &privk);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks);
            assert!(res.is_none());
        }
        
        // nonempty stream, but discontiguous first microblock (wrong sequence)
        {
            let mut broken_microblocks = microblocks.clone();
            broken_microblocks[0].header.sequence = 1;
            
            let mut new_child_block_header = child_block_header.clone();
            new_child_block_header.parent_microblock = resign_microblocks(&mut broken_microblocks, &privk);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks);
            assert!(res.is_none());
        }

        // nonempty stream, but discontiguous hash chain
        {
            let mut broken_microblocks = microblocks.clone();

            let mut new_child_block_header = child_block_header.clone();

            for i in 0..broken_microblocks.len() {
                broken_microblocks[i].header.signature = MessageSignature([0u8; 65]);
                broken_microblocks[i].sign(&privk).unwrap();
                if i + 1 < broken_microblocks.len() {
                    if i != num_mblocks/2 {
                        broken_microblocks[i+1].header.prev_block = broken_microblocks[i].block_hash();
                    }
                    else {
                        broken_microblocks[i+1].header.prev_block = BlockHeaderHash([1u8; 32]);
                    }
                }
            }
            let l = broken_microblocks.len();
            new_child_block_header.parent_microblock = broken_microblocks[l-1].block_hash();

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks);
            assert!(res.is_none());
        }
        
        // nonempty string, but bad signature
        {
            let mut broken_microblocks = microblocks.clone();
            broken_microblocks[num_mblocks/2].header.signature = MessageSignature([1u8; 65]);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header, &broken_microblocks);
            assert!(res.is_none());
        }

        // deliberate miner fork 
        {
            let mut broken_microblocks = microblocks.clone();
            let mut forked_microblocks = vec![];

            let mut new_child_block_header = child_block_header.clone();
            let mut conflicting_microblock = microblocks[0].clone();

            for i in 0..broken_microblocks.len() {
                broken_microblocks[i].header.signature = MessageSignature([0u8; 65]);
                broken_microblocks[i].sign(&privk).unwrap();
                if i + 1 < broken_microblocks.len() {
                    broken_microblocks[i+1].header.prev_block = broken_microblocks[i].block_hash();
                }

                forked_microblocks.push(broken_microblocks[i].clone());
                if i == num_mblocks/2 {
                    conflicting_microblock = broken_microblocks[i].clone();

                    let extra_tx = {
                        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
                        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                                       auth.clone(),
                                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &format!("conflicting smart contract {}", i)).unwrap());
                        let mut tx_signer = StacksTransactionSigner::new(&tx_smart_contract);
                        tx_signer.sign_origin(&privk).unwrap();
                        tx_signer.get_tx().unwrap()
                    };
                    
                    conflicting_microblock.txs.push(extra_tx);
                    
                    let txid_vecs = conflicting_microblock.txs
                        .iter()
                        .map(|tx| tx.txid().as_bytes().to_vec())
                        .collect();

                    let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);

                    conflicting_microblock.header.tx_merkle_root = merkle_tree.root();

                    conflicting_microblock.sign(&privk).unwrap();
                    forked_microblocks.push(conflicting_microblock.clone());
                }
            }

            let l = broken_microblocks.len();
            new_child_block_header.parent_microblock = broken_microblocks[l-1].block_hash();
            
            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header, &forked_microblocks);
            assert!(res.is_some());
            
            let (cutoff, poison_opt) = res.unwrap();
            assert_eq!(cutoff, num_mblocks/2);
            assert!(poison_opt.is_some());

            let poison = poison_opt.unwrap();
            match poison {
                TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                    assert_eq!(*h2, forked_microblocks[num_mblocks/2].header);
                    assert_eq!(*h1, conflicting_microblock.header);
                }
                _ => {
                    assert!(false);
                }
            }
        }
    }
}
