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
use std::collections::{HashMap, HashSet};

use core::*;

use chainstate::burn::operations::*;

use chainstate::stacks::Error;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::db::accounts::MinerReward;
use chainstate::stacks::*;
use chainstate::stacks::db::*;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    DBConn,
    FromRow,
    FromColumn,
    query_rows,
    query_row_columns,
    query_count,
    query_int
};

use util::strings::StacksString;

use util::hash::to_hex;

use chainstate::burn::db::burndb::*;

use net::Error as net_error;

use vm::types::{
    Value,
    AssetIdentifier,
    TupleData,
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier
};

use vm::contexts::{
    AssetMap
};

use vm::ast::build_ast;
use vm::analysis::run_analysis;

use vm::clarity::{
    ClarityBlockConnection,
    ClarityInstance
};

pub use vm::analysis::errors::CheckErrors;

use vm::database::ClarityDatabase;

use vm::contracts::Contract;

use rand::RngCore;
use rand::thread_rng;

#[derive(Debug, Clone, PartialEq)]
pub struct StagingMicroblock {
    pub burn_header_hash: BurnchainHeaderHash,
    pub anchored_block_hash: BlockHeaderHash,
    pub microblock_hash: BlockHeaderHash,
    pub sequence: u16,
    pub processed: bool,
    pub orphaned: bool,
    pub block_data: Vec<u8>
}

#[derive(Debug, Clone, PartialEq)]
pub struct StagingBlock {
    pub burn_header_hash: BurnchainHeaderHash,
    pub anchored_block_hash: BlockHeaderHash,
    pub parent_burn_header_hash: BurnchainHeaderHash,
    pub parent_anchored_block_hash: BlockHeaderHash,
    pub parent_microblock_hash: BlockHeaderHash,
    pub parent_microblock_seq: u16,
    pub microblock_pubkey_hash: Hash160,
    pub processed: bool,
    pub attacheable: bool,
    pub orphaned: bool,
    pub commit_burn: u64,
    pub sortition_burn: u64,
    pub block_data: Vec<u8>
}

#[derive(Debug, Clone, PartialEq)]
pub struct StagingUserBurnSupport {
    pub burn_header_hash: BurnchainHeaderHash,
    pub anchored_block_hash: BlockHeaderHash,
    pub address: StacksAddress,
    pub burn_amount: u64,
    pub vtxindex: u32,
}

impl StagingBlock {
    pub fn is_genesis(&self) -> bool {
        self.parent_anchored_block_hash == FIRST_STACKS_BLOCK_HASH
    }
}

impl FromRow<StagingMicroblock> for StagingMicroblock {
    fn from_row<'a>(row: &'a Row) -> Result<StagingMicroblock, db_error> {
        let anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "anchored_block_hash")?;
        let burn_header_hash : BurnchainHeaderHash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let microblock_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "microblock_hash")?;
        let sequence_i64 : i64 = row.get("sequence");
        let processed_i64 : i64 = row.get("processed");
        let orphaned_i64 : i64 = row.get("orphaned");
        let block_data : Vec<u8> = vec![];

        if sequence_i64 > (u16::max_value() as i64) || sequence_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let processed = if processed_i64 != 0 { true } else { false };
        let orphaned = if orphaned_i64 != 0 { true } else { false };
        let sequence = sequence_i64 as u16;

        Ok(StagingMicroblock {
            burn_header_hash,
            anchored_block_hash,
            microblock_hash,
            sequence,
            processed,
            orphaned,
            block_data
        })
    }
}

impl FromRow<StagingBlock> for StagingBlock {
    fn from_row<'a>(row: &'a Row) -> Result<StagingBlock, db_error> {
        let anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "anchored_block_hash")?;
        let parent_anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "parent_anchored_block_hash")?;
        let burn_header_hash : BurnchainHeaderHash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let parent_burn_header_hash: BurnchainHeaderHash = BurnchainHeaderHash::from_column(row, "parent_burn_header_hash")?;
        let parent_microblock_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "parent_microblock_hash")?;
        let parent_microblock_seq : u16 = row.get("parent_microblock_seq");
        let microblock_pubkey_hash : Hash160 = Hash160::from_column(row, "microblock_pubkey_hash")?;
        let attacheable_i64 : i64 = row.get("attacheable");
        let processed_i64 : i64 = row.get("processed");
        let orphaned_i64 : i64 = row.get("orphaned");
        let commit_burn_i64 : i64 = row.get("commit_burn");
        let sortition_burn_i64 : i64 = row.get("sortition_burn");
        let block_data : Vec<u8> = vec![];

        let processed = if processed_i64 != 0 { true } else { false };
        let attacheable = if attacheable_i64 != 0 { true } else { false };
        let orphaned = if orphaned_i64 == 0 { true } else { false };

        let commit_burn = commit_burn_i64 as u64;
        let sortition_burn = sortition_burn_i64 as u64;

        Ok(StagingBlock {
            anchored_block_hash,
            parent_anchored_block_hash,
            burn_header_hash,
            parent_burn_header_hash,
            parent_microblock_hash,
            parent_microblock_seq,
            microblock_pubkey_hash,
            processed,
            attacheable,
            orphaned,
            commit_burn,
            sortition_burn,
            block_data
        })
    }
}

impl FromRow<StagingUserBurnSupport> for StagingUserBurnSupport {
    fn from_row<'a>(row: &'a Row) -> Result<StagingUserBurnSupport, db_error> {
        let anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "anchored_block_hash")?;
        let burn_header_hash : BurnchainHeaderHash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let address : StacksAddress = StacksAddress::from_column(row, "address")?;
        let burn_amount_i64 : i64 = row.get("burn_amount");
        let vtxindex : u32 = row.get("vtxindex");

        if burn_amount_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let burn_amount = burn_amount_i64 as u64;

        Ok(StagingUserBurnSupport {
            anchored_block_hash,
            burn_header_hash,
            address,
            burn_amount,
            vtxindex
        })
    }
}

impl StagingMicroblock {
    pub fn try_into_microblock(self) -> Result<StacksMicroblock, StagingMicroblock> {
        let mut index = 0;
        StacksMicroblock::deserialize(&self.block_data, &mut index, self.block_data.len() as u32).map_err(|_e| self)
    }
}

const STACKS_BLOCK_INDEX_SQL : &'static [&'static str]= &[
    r#"
    -- Staging microblocks -- preprocessed microblocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_microblocks(anchored_block_hash TEXT NOT NULL,     -- this is the hash of the parent anchored block
                                     burn_header_hash TEXT NOT NULL,        -- this is the hash of the burn chain block that holds the parent anchored block's block-commit
                                     microblock_hash TEXT NOT NULL,
                                     sequence INT NOT NULL,
                                     processed INT NOT NULL,
                                     orphaned INT NOT NULL,
                                     PRIMARY KEY(anchored_block_hash,burn_header_hash,microblock_hash)
    );
    "#,
    r#"
    -- Staging microblocks data
    CREATE TABLE staging_microblocks_data(block_hash TEXT NOT NULL,
                                          block_data BLOB NOT NULL,
                                          PRIMARY KEY(block_hash)
    );
    "#,
    r#"
    -- Staging blocks -- preprocessed blocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_blocks(anchored_block_hash TEXT NOT NULL,
                                parent_anchored_block_hash TEXT NOT NULL,
                                burn_header_hash TEXT NOT NULL,
                                parent_burn_header_hash TEXT NOT NULL,
                                parent_microblock_hash TEXT NOT NULL,
                                parent_microblock_seq INT NOT NULL,
                                microblock_pubkey_hash TEXT NOT NULL,
                                attacheable INT NOT NULL,           -- set to 1 if this block's parent is processed; 0 if not
                                orphaned INT NOT NULL,              -- set to 1 if this block can never be attached
                                processed INT NOT NULL,
                                commit_burn INT NOT NULL,
                                sortition_burn INT NOT NULL,
                                PRIMARY KEY(anchored_block_hash,burn_header_hash)
    );
    "#,
    r#"
    -- Staging block data
    CREATE TABLE staging_blocks_data(block_hash TEXT NOT NULL,
                                     block_data BLOB NOT NULL,
                                     PRIMARY KEY(block_hash)
    );
    "#,
    r#"
    -- users who burned in support of a block
    CREATE TABLE staging_user_burn_support(anchored_block_hash TEXT NOT NULL,
                                           burn_header_hash TEXT NOT NULL,
                                           address TEXT NOT NULL,
                                           burn_amount INT NOT NULL,
                                           vtxindex INT NOT NULL
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
    fn get_block_path(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let mut block_path = PathBuf::from(blocks_dir);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));
        block_path.push(format!("{}-{}", to_hex(block_hash_bytes), burn_header_hash.to_hex()));

        let blocks_path_str = block_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(blocks_path_str)
    }
    
    /// Make a directory tree for storing this block to the chunk store, and return the block's path
    fn make_block_dir(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let mut block_path = PathBuf::from(blocks_dir);

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
        // TODO: this is atomic but not crash-consistent!  need to fsync the dir as well
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
                            debug!("File not found: {:?}", path);
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
    pub fn has_stored_block(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let block_path = StacksChainState::get_block_path(blocks_dir, burn_header_hash, block_hash)?;
        match fs::metadata(block_path) {
            Ok(_) => {
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
    pub fn has_stored_microblocks(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, tail_header: &BlockHeaderHash) -> Result<bool, Error> {
        if *tail_header == EMPTY_MICROBLOCK_PARENT_HASH {
            // empty
            Ok(true)
        }
        else {
            StacksChainState::has_stored_block(blocks_dir, burn_header_hash, tail_header)
        }
    }

    /// Store a block to the chunk store, named by its hash
    pub fn store_block(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock) -> Result<(), Error> {
        let block_hash = block.block_hash();
        let block_path = StacksChainState::make_block_dir(blocks_dir, burn_header_hash, &block_hash)?;
        let block_data = block.serialize();
        StacksChainState::atomic_file_write(&block_path, &block_data)
    }
    
    /// Store an empty block to the chunk store, named by its hash.
    /// Used to mark an invalid block
    pub fn store_empty_block(blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<(), Error> {
        let block_path = StacksChainState::make_block_dir(blocks_path, burn_header_hash, &block_hash)?;
        StacksChainState::atomic_file_write(&block_path, &vec![])
    }

    /// Truncate an (invalid) block.  Frees up space while marking the block as processed so we
    /// don't process it again.
    fn free_block(blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, block_header_hash: &BlockHeaderHash) -> () {
        let block_path = StacksChainState::make_block_dir(blocks_path, burn_header_hash, &block_header_hash)
            .expect("FATAL: failed to create block directory");
        fs::OpenOptions::new()
            .read(false)
            .write(true)
            .truncate(true)
            .open(&block_path)
            .expect(&format!("FATAL: Failed to mark block path '{}' as free", &block_path));
    }

    /// Free up all state for an invalid block
    pub fn free_block_state(blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, block_header: &StacksBlockHeader) -> () {
        StacksChainState::free_block(blocks_path, burn_header_hash, &block_header.block_hash())
    }

    /// Get a list of all anchored blocks' hashes, and their burnchain headers
    #[cfg(test)]
    pub fn list_blocks(blocks_conn: &DBConn, blocks_dir: &String) -> Result<Vec<(BurnchainHeaderHash, BlockHeaderHash)>, Error> {
        let list_block_sql = "SELECT * FROM staging_blocks".to_string();
        let mut blocks = query_rows::<StagingBlock, _>(blocks_conn, &list_block_sql, NO_PARAMS)
            .map_err(Error::DBError)?;

        Ok(blocks.drain(..).map(|b| (b.burn_header_hash, b.anchored_block_hash)).collect())
    }

    /// Get a list of all microblocks' hashes, and their anchored blocks' hashes
    #[cfg(test)]
    pub fn list_microblocks(blocks_conn: &DBConn, blocks_dir: &String) -> Result<Vec<(BurnchainHeaderHash, BlockHeaderHash, Vec<BlockHeaderHash>)>, Error> {
        let mut blocks = StacksChainState::list_blocks(blocks_conn, blocks_dir)?;
        let mut ret = vec![];
        
        for (burn_hash, block_hash) in blocks.drain(..) {
            let list_microblock_sql = "SELECT * FROM staging_microblocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 ORDER BY sequence".to_string();
            let list_microblock_args = [&block_hash.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql];
            let mut microblocks = query_rows::<StagingMicroblock, _>(blocks_conn, &list_microblock_sql, &list_microblock_args)
                .map_err(Error::DBError)?;

            let microblock_hashes = microblocks.drain(..).map(|mb| mb.microblock_hash).collect();
            ret.push((burn_hash, block_hash, microblock_hashes));
        }
        
        Ok(ret)
    }

    /// Load up a block from the chunk store.
    /// Returns Ok(Some(block)) if found.
    /// Returns Ok(None) if this block was found, but is known to be invalid 
    /// Returns Err(...) on not found or I/O error
    pub fn load_block(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlock>, Error> {
        let block_path = StacksChainState::get_block_path(blocks_dir, burn_header_hash, block_hash)?;
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
    pub fn load_block_header(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlockHeader>, Error> {
        let block_path = StacksChainState::get_block_path(blocks_dir, burn_header_hash, block_hash)?;
        let block_bytes = StacksChainState::file_load(&block_path)?;
        if block_bytes.len() == 0 {
            debug!("Zero-sized block {}", block_hash.to_hex());
            return Ok(None);
        }

        let mut index = 0;
        let block_header = StacksBlockHeader::deserialize(&block_bytes, &mut index, block_bytes.len() as u32).map_err(Error::NetError)?;
        Ok(Some(block_header))
    }

    /// Store a stream of microblocks to the chunk store, named by its header block's hash.
    /// The given burn_header_hash is the burnchain header hash of the snapshot that selected this
    /// stream's anchored block.
    ///
    /// The stored file is effectively an append-only file.  Microblocks may be appended to it
    /// later if e.g. multiple anchored blocks build off of different microblocks in the stream.
    /// Regardless, the file contains the longest stream built on by any anchored block discovered
    /// so far.
    pub fn store_microblock_stream(blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, microblocks: &Vec<StacksMicroblock>) -> Result<(), Error> {
        if microblocks.len() == 0 {
            StacksChainState::store_empty_block(blocks_path, burn_header_hash, &EMPTY_MICROBLOCK_PARENT_HASH)?;
            return Ok(())
        }

        let block_hash = microblocks[0].block_hash();
        let block_path = StacksChainState::make_block_dir(blocks_path, burn_header_hash, &block_hash)?;

        let mut buf = vec![];
        for mblock in microblocks {
            let mut mblock_buf = mblock.serialize();
            buf.append(&mut mblock_buf);
        }

        StacksChainState::atomic_file_write(&block_path, &buf)
    }

    /// Load a stream of microblocks from the chunk store, given its first block's hash.
    /// The given burn_header_hash is the burnchain header hash of the snapshot that selected this
    /// stream's anchored block.
    /// Returns Ok(Some(microblocks)) if the data was found
    /// Returns Ok(None) if the microblocks stream was previously processed and is known to be invalid
    /// Returns Err(...) for not found, I/O error, etc.
    fn load_microblock_stream(blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, microblock_head_hash: &BlockHeaderHash) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        let block_path = StacksChainState::get_block_path(blocks_path, burn_header_hash, microblock_head_hash)?;
        let block_bytes = StacksChainState::file_load(&block_path)?;
        if block_bytes.len() == 0 {
            // known-invalid
            debug!("Zero-sized microblock stream {}", microblock_head_hash.to_hex());
            return Ok(None);
        }

        let mut index : u32 = 0;
        let mut microblocks = vec![];
        while (index as usize) < block_bytes.len() {
            let microblock = StacksMicroblock::deserialize(&block_bytes, &mut index, block_bytes.len() as u32).map_err(Error::NetError)?;
            microblocks.push(microblock);
        }

        if (index as usize) != block_bytes.len() {
            error!("Corrupt microblock stream {}: read {} out of {} bytes", microblock_head_hash.to_hex(), index, block_bytes.len());
            return Err(Error::DBError(db_error::Corruption));
        }

        Ok(Some(microblocks))
    }

    /// Closure for defaulting to an empty microblock stream if a microblock stream file is not found
    fn empty_stream(e: Error) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        match e {
            Error::DBError(ref dbe) => match dbe {
                db_error::NotFoundError => Ok(Some(vec![])),
                _ => Err(e)
            },
            _ => Err(e)
        }
    }

    /// Load up a blob of data.
    /// Query should be structured to return rows of BLOBs
    fn load_block_data_blobs<P>(conn: &DBConn, sql_query: &String, sql_args: P) -> Result<Vec<Vec<u8>>, Error>
    where
        P: IntoIterator,
        P::Item: ToSql
    {
        
        let mut stmt = conn.prepare(sql_query)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let mut rows = stmt.query(sql_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // gather 
        let mut blobs = vec![];
        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let next_blob : Vec<u8> = row.get(0);
                    blobs.push(next_blob);
                },
                Err(e) => {
                    return Err(Error::DBError(db_error::SqliteError(e)));
                }
            };
        }

        Ok(blobs)
    }

    /// Load up a staging block or microblock's bytes, given its hash and which table to use
    /// Treat an empty array as None.
    fn inner_load_staging_block_bytes(block_conn: &DBConn, table: &str, block_hash: &BlockHeaderHash) -> Result<Option<Vec<u8>>, Error> {
        let sql = format!("SELECT block_data FROM {} WHERE block_hash = ?1", table);
        let args = [&block_hash.to_hex() as &dyn ToSql];
        let mut blobs = StacksChainState::load_block_data_blobs(block_conn, &sql, &args)?;
        let len = blobs.len();
        match len {
            0 => Ok(None),
            1 => {
                let blob = blobs.pop().unwrap();
                if blob.len() == 0 {
                    // cleared
                    Ok(None)
                }
                else {
                    Ok(Some(blob))
                }
            }
            _ => {
                unreachable!("Got multiple blocks for the same block hash");
            }
        }
    }
    
    fn load_staging_block_bytes(block_conn: &DBConn, block_hash: &BlockHeaderHash) -> Result<Option<Vec<u8>>, Error> {
        StacksChainState::inner_load_staging_block_bytes(block_conn, "staging_blocks_data", block_hash)
    }

    fn load_staging_microblock_bytes(block_conn: &DBConn, block_hash: &BlockHeaderHash) -> Result<Option<Vec<u8>>, Error> {
        StacksChainState::inner_load_staging_block_bytes(block_conn, "staging_microblocks_data", block_hash)
    }

    /// Load up a preprocessed (queued) but still unprocessed block.
    pub fn load_staging_block(block_conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StagingBlock>, Error> {
        let sql = "SELECT * FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND orphaned = 0".to_string();
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql];
        let mut rows = query_rows::<StagingBlock, _>(block_conn, &sql, &args).map_err(Error::DBError)?;
        let len = rows.len();
        match len {
            0 => {
                Ok(None)
            }
            1 => {
                let mut staging_block = rows.pop().unwrap();

                // load up associated block data 
                staging_block.block_data = StacksChainState::load_staging_block_bytes(block_conn, block_hash)?.unwrap_or(vec![]);
                Ok(Some(staging_block))
            },
            _ => {
                // should be impossible since this is the primary key
                panic!("Got two or more block rows with same burn and block hashes");
            }
        }
    }

    #[cfg(test)]
    fn load_staging_block_data(block_conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlock>, Error> {
        match StacksChainState::load_staging_block(block_conn, burn_header_hash, block_hash)? {
            Some(staging_block) => {
                if staging_block.block_data.len() == 0 {
                    return Ok(None);
                }

                let mut index = 0;
                match StacksBlock::deserialize(&staging_block.block_data, &mut index, staging_block.block_data.len() as u32) {
                    Ok(block) => Ok(Some(block)),
                    Err(e) => Err(Error::NetError(e))
                }
            },
            None => Ok(None)
        }
    }

    /// Load up the list of users who burned for an unprocessed block.
    fn load_staging_block_user_supports(block_conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Vec<StagingUserBurnSupport>, Error> {
        let sql = "SELECT * FROM staging_user_burn_support WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2".to_string();
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql];
        let rows = query_rows::<StagingUserBurnSupport, _>(block_conn, &sql, &args).map_err(Error::DBError)?;
        Ok(rows)
    }
    
    /// Load up a queued block's queued pubkey hash
    fn load_staging_block_pubkey_hash(block_conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<Hash160>, Error> {
        let sql = format!("SELECT microblock_pubkey_hash FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND processed = 0 AND orphaned = 0");
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql];
        let rows = query_row_columns::<Hash160, _>(block_conn, &sql, &args, "microblock_pubkey_hash").map_err(Error::DBError)?;
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

    /// Load up a preprocessed but still unprocessed microblock.
    pub fn load_staging_microblock(blocks_conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<Option<StagingMicroblock>, Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND microblock_hash = ?3 AND orphaned = 0".to_string();
        let args = [&burn_header_hash.to_hex() as &dyn ToSql, &block_hash.to_hex() as &dyn ToSql, &microblock_hash.to_hex() as &dyn ToSql];
        let mut rows = query_rows::<StagingMicroblock, _>(blocks_conn, &sql, &args).map_err(Error::DBError)?;
        let len = rows.len();
        match len {
            0 => {
                Ok(None)
            },
            1 => {
                // load associated block data 
                let mut staging_microblock = rows.pop().unwrap();
                staging_microblock.block_data = StacksChainState::load_staging_microblock_bytes(blocks_conn, microblock_hash)?.unwrap_or(vec![]);
                Ok(Some(staging_microblock))
            },
            _ => {
                // should be impossible since microblocks are unique
                panic!("Got two or more microblock rows with the same hash");
            }
        }
    }

    /// Merge two sorted microblock streams.
    /// Resulting stream will be sorted by sequence.
    /// if staging_microblocks[i].processed is true, then it must have a non-empty block_data
    /// array.  If this is not true, then you'll get back a NetError
    fn merge_microblock_streams(staging_microblocks: Vec<StagingMicroblock>, disk_microblocks: Vec<StacksMicroblock>) -> Result<Vec<StacksMicroblock>, Error> {
        let num_staging_microblocks = staging_microblocks.len();
        let num_disk_microblocks = disk_microblocks.len();
        let cnt = if num_staging_microblocks < num_disk_microblocks { num_staging_microblocks } else { num_disk_microblocks };

        // merge staging and on-disk streams
        let mut microblocks = vec![];
        for i in 0..cnt {
            // favor DB-stored microblock over disk-stored, since the DB is less likely to be
            // corrupt!
            if !staging_microblocks[i].processed {
                if staging_microblocks[i].block_data.len() == 0 {
                    return Err(Error::NetError(net_error::DeserializeError(format!("Microblock {} does not have block data", staging_microblocks[i].microblock_hash.to_hex()))));
                }

                let mut index = 0;
                let microblock = StacksMicroblock::deserialize(&staging_microblocks[i].block_data, &mut index, staging_microblocks[i].block_data.len() as u32)
                    .map_err(Error::NetError)?;
                microblocks.push(microblock);
            }
            else {
                microblocks.push(disk_microblocks[i].clone());
            }
        }

        if cnt < num_staging_microblocks {
            for i in cnt..num_staging_microblocks {
                if !staging_microblocks[i].processed {
                    if staging_microblocks[i].block_data.len() == 0 {
                        return Err(Error::NetError(net_error::DeserializeError(format!("Microblock {} does not have block data", staging_microblocks[i].microblock_hash.to_hex()))));
                    }

                    let mut index = 0;
                    let microblock = StacksMicroblock::deserialize(&staging_microblocks[i].block_data, &mut index, staging_microblocks[i].block_data.len() as u32)
                        .map_err(Error::NetError)?;
                    microblocks.push(microblock);
                }
                else {
                    // discontiguous -- there's a processed microblock occurring later in the
                    // sequence than an unprocessed microblock.  Shouldn't happen.
                    return Err(Error::DBError(db_error::Corruption));
                }
            }
        }

        else if cnt < num_disk_microblocks {
            for i in cnt..num_disk_microblocks {
                microblocks.push(disk_microblocks[i].clone());
            }
        }

        // just to be sure...
        microblocks.sort_by(|a, b| a.header.sequence.partial_cmp(&b.header.sequence).unwrap());
        
        Ok(microblocks)
    }

    /// Load up a block's descendent microblock stream, given its block hash and burn header hash.
    ///
    /// Does not check for duplicates or invalid data; feed the stream into validate_parent_microblock_stream() for that.
    ///
    /// Note that it's possible that some of the microblock data was already processed and moved to the chunk store.  If so,
    /// then this method goes and fetches them as well.
    pub fn load_staging_microblock_stream(blocks_conn: &DBConn, blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, last_seq: u16) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND sequence <= ?3 AND orphaned = 0 ORDER BY sequence".to_string();
        let args = [&anchored_block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql, &last_seq as &dyn ToSql];
        let mut staging_microblocks = query_rows::<StagingMicroblock, _>(blocks_conn, &sql, &args)
            .map_err(Error::DBError)?;

        if staging_microblocks.len() == 0 {
            // haven't seen any microblocks that descend from this block yet
            test_debug!("No microblocks built on {}/{} up to {}", &burn_header_hash.to_hex(), &anchored_block_hash.to_hex(), last_seq);
            return Ok(None);
        }

        // load associated staging microblock data 
        for i in 0..staging_microblocks.len() {
            staging_microblocks[i].block_data = StacksChainState::load_staging_microblock_bytes(blocks_conn, &staging_microblocks[i].microblock_hash)?.unwrap_or(vec![]);
        }

        let microblock_head_hash = &staging_microblocks[0].microblock_hash;

        // load any matching already-confirmed microblocks up.  This block may also confirm them
        // (but in a different fork).
        let disk_microblocks = match StacksChainState::load_microblock_stream(blocks_path, burn_header_hash, microblock_head_hash).or_else(StacksChainState::empty_stream)? {
            Some(mblocks) => mblocks,
            None => vec![]
        };
        
        let microblocks = StacksChainState::merge_microblock_streams(staging_microblocks, disk_microblocks)?;

        Ok(Some(microblocks))
    }
    
    /// Store a preprocessed block, queuing it up for subsequent processing.
    /// The caller should at least verify that the block is attached to some fork in the burn
    /// chain.
    fn store_staging_block<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash, commit_burn: u64, sortition_burn: u64) -> Result<(), Error> {
        assert!(commit_burn < i64::max_value() as u64);
        assert!(sortition_burn < i64::max_value() as u64);

        let block_hash = block.block_hash();
        let block_bytes = block.serialize();

        let attacheable = {
            // if this block has an unprocessed staging parent, then it's not attacheable until its parent is.
            let has_parent_sql = "SELECT anchored_block_hash FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND processed = 0 AND orphaned = 0 LIMIT 1".to_string();
            let has_parent_args = [&block.header.parent_block.to_hex() as &dyn ToSql, &parent_burn_header_hash.to_hex() as &dyn ToSql];
            let rows = query_row_columns::<BlockHeaderHash, _>(&tx, &has_parent_sql, &has_parent_args, "anchored_block_hash").map_err(Error::DBError)?;
            if rows.len() > 0 {
                // still have unprocessed parent -- this block is not attacheable
                0
            }
            else {
                // no unprocessed parents -- this block is potentially attacheable
                1
            }
        };

        // store block metadata
        let sql = "INSERT OR REPLACE INTO staging_blocks \
                   (anchored_block_hash, parent_anchored_block_hash, burn_header_hash, parent_burn_header_hash, parent_microblock_hash, parent_microblock_seq, microblock_pubkey_hash, attacheable, processed, orphaned, commit_burn, sortition_burn) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
        let args = [&block_hash.to_hex() as &dyn ToSql, &block.header.parent_block.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql, &parent_burn_header_hash.to_hex() as &dyn ToSql,
                    &block.header.parent_microblock.to_hex() as &dyn ToSql, &block.header.parent_microblock_sequence as &dyn ToSql,
                    &block.header.microblock_pubkey_hash.to_hex() as &dyn ToSql, &attacheable as &dyn ToSql, &0 as &dyn ToSql, &0 as &dyn ToSql, &(commit_burn as i64) as &dyn ToSql, &(sortition_burn as i64) as &dyn ToSql];

        tx.execute(&sql, &args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // store block bytes
        let block_sql = "INSERT OR REPLACE INTO staging_blocks_data \
                         (block_hash, block_data)
                         VALUES (?1, ?2)";
        let block_args = [&block_hash.to_hex() as &dyn ToSql, &block_bytes as &dyn ToSql];

        tx.execute(&block_sql, &block_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // mark all children of this new block as unattacheable -- need to attach this block first!
        // this should be done across all burnchains.
        let children_sql = "UPDATE staging_blocks SET attacheable = 0 WHERE parent_anchored_block_hash = ?1";
        let children_args = [&block_hash.to_hex() as &dyn ToSql];

        tx.execute(&children_sql, &children_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    /// Store a preprocessed microblock, queueing it up for subsequent processing.
    /// The caller should at least verify that this block was signed by the miner of the ancestor
    /// anchored block that this microblock builds off of.  Because microblocks may arrive out of
    /// order, this method does not check that.
    /// The burn_header_hash and anchored_block_hash correspond to the _parent_ Stacks block.
    /// Microblocks ought to only be stored if they are first confirmed to have been signed.
    fn store_staging_microblock<'a>(tx: &mut BlocksDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, microblock: &StacksMicroblock) -> Result<(), Error> {
        let microblock_bytes = microblock.serialize();

        // store microblock metadata
        let sql = "INSERT OR REPLACE INTO staging_microblocks (anchored_block_hash, burn_header_hash, microblock_hash, sequence, processed, orphaned) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
        let args = [&anchored_block_hash.to_hex() as &dyn ToSql, &burn_header_hash.to_hex() as &dyn ToSql, &microblock.block_hash().to_hex() as &dyn ToSql, &microblock.header.sequence as &dyn ToSql, &0 as &dyn ToSql, &0 as &dyn ToSql];

        tx.execute(&sql, &args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        // store microblock bytes
        let block_sql = "INSERT OR REPLACE INTO staging_microblocks_data \
                         (block_hash, block_data)
                         VALUES (?1, ?2)";
        let block_args = [&microblock.block_hash().to_hex() as &dyn ToSql, &microblock_bytes as &dyn ToSql];

        tx.execute(&block_sql, &block_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    /// Store users who burned in support of a block
    fn store_staging_block_user_burn_supports<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, burn_supports: &Vec<UserBurnSupportOp>) -> Result<(), Error> {
        for burn_support in burn_supports.iter() {
            assert!(burn_support.burn_fee < i64::max_value() as u64);
        }

        for burn_support in burn_supports.iter() {
            let sql = "INSERT OR REPLACE INTO staging_user_burn_support (anchored_block_hash, burn_header_hash, address, burn_amount, vtxindex) VALUES (?1, ?2, ?3, ?4, ?5)";
            let args = [&burn_hash.to_hex() as &dyn ToSql, &block_hash.to_hex() as &dyn ToSql, &burn_support.address.to_string() as &dyn ToSql, &(burn_support.burn_fee as i64) as &dyn ToSql, &burn_support.vtxindex as &dyn ToSql];

            tx.execute(&sql, &args)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }

        Ok(())
    }

    /// Do we have a block queued up, and if so, is it being processed?.
    /// Return Some(processed) if the block is queued up -- true if processed, false if not
    /// Return None if the block is not queued up
    fn get_staging_block_status(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<bool>, Error> {
        let sql = "SELECT processed FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2".to_string();
        let args = [&block_hash.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql];

        let processed_i64 = match query_int::<_>(blocks_conn, &sql, &args) {
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
    fn get_staging_microblock_status(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<Option<bool>, Error> {
        let sql = "SELECT processed FROM staging_microblocks WHERE anchored_block_hash = ?1 AND microblock_hash = ?2 AND burn_header_hash = ?3".to_string();
        let args = [&block_hash.to_hex() as &dyn ToSql, &microblock_hash.to_hex() as &dyn ToSql, &burn_hash.to_hex() as &dyn ToSql];

        let processed_i64 = match query_int::<_>(blocks_conn, &sql, &args) {
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

    /// What's the first microblock hash in a stream?
    fn get_microblock_stream_head_hash(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, anchored_header_hash: &BlockHeaderHash) -> Result<Option<BlockHeaderHash>, Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND sequence = 0 AND orphaned = 0".to_string();
        let args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_header_hash.to_hex() as &dyn ToSql];
        let staging_microblocks = query_rows::<StagingMicroblock, _>(blocks_conn, &sql, &args).map_err(Error::DBError)?;
        match staging_microblocks.len() {
            0 => Ok(None),
            1 => Ok(Some(staging_microblocks[0].microblock_hash.clone())),
            _ => Ok(None)       // leader equivocated
        }
    }
    
    /// Do we have a staging block?
    pub fn has_staging_block(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let res = StacksChainState::get_staging_block_status(blocks_conn, burn_hash, block_hash)?.is_some();
        Ok(res)
    }

    /// Do we have a staging microblock?
    pub fn has_staging_microblock(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let res = StacksChainState::get_staging_microblock_status(blocks_conn, burn_hash, block_hash, microblock_hash)?.is_some();
        Ok(res)
    }

    /// Clear raw block data from the chunk store
    fn inner_delete_staging_block_data<'a>(tx: &mut BlocksDBTx<'a>, table_name: &str, block_hash: &BlockHeaderHash) -> Result<(), Error> {
        // clear out the block data from staging
        let clear_sql = format!("DELETE FROM {} WHERE block_hash = ?1", table_name);
        let clear_args = [&block_hash.to_hex() as &dyn ToSql];

        tx.execute(&clear_sql, &clear_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }
    
    /// Delete a block's data from staging
    fn delete_staging_block_data<'a>(tx: &mut BlocksDBTx<'a>, block_hash: &BlockHeaderHash) -> Result<(), Error> {
        StacksChainState::inner_delete_staging_block_data(tx, "staging_blocks_data", block_hash)
    }

    /// Delete a microblock's data from staging 
    fn delete_staging_microblock_data<'a>(tx: &mut BlocksDBTx<'a>, microblock_hash: &BlockHeaderHash) -> Result<(), Error> {
        StacksChainState::inner_delete_staging_block_data(tx, "staging_microblocks_data", microblock_hash)
    }

    /// Move raw block data to the chunk store out of the staging blocks data table
    fn move_staging_block_data_to_file<'a>(tx: &mut BlocksDBTx<'a>, block_hash: &BlockHeaderHash, block_path: &String) -> Result<(), Error> {
        let block_data = match StacksChainState::inner_load_staging_block_bytes(tx, "staging_blocks_data", block_hash)? {
            Some(block_data) => block_data,
            None => {
                // already done
                return Ok(());
            }
        };

        StacksChainState::atomic_file_write(block_path, &block_data)?;
        StacksChainState::delete_staging_block_data(tx, block_hash)?;
        Ok(())
    }

    /// Mark an anchored block as orphaned and both orphan and delete its parent microblock data.
    /// The blocks database will eventually delete all orphaned data.
    fn delete_orphaned_epoch_data<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        // This block is orphaned
        let update_block_sql = "UPDATE staging_blocks SET orphaned = 1, processed = 1, attacheable = 0 WHERE anchored_block_hash = ?1".to_string();
        let update_block_args = [&anchored_block_hash.to_hex() as &dyn ToSql];

        // All descendents of this processed block are never attacheable.
        // Indicate this by marking all children as orphaned (but not procesed), across all burnchain forks.
        let update_children_sql = "UPDATE staging_blocks SET orphaned = 1, processed = 0, attacheable = 0 WHERE parent_anchored_block_hash = ?1".to_string();
        let update_children_args = [&anchored_block_hash.to_hex() as &dyn ToSql];
        
        // find all orphaned microblocks hashes, and delete the block data
        let find_orphaned_microblocks_sql = "SELECT microblock_hash FROM staging_microblocks WHERE anchored_block_hash = ?1".to_string();
        let find_orphaned_microblocks_args = [&anchored_block_hash.to_hex() as &dyn ToSql];
        let orphaned_microblock_hashes = query_row_columns::<BlockHeaderHash, _>(tx, &find_orphaned_microblocks_sql, &find_orphaned_microblocks_args, "microblock_hash")
            .map_err(Error::DBError)?;
        
        // drop microblocks (this processes them)
        let update_microblock_children_sql = "UPDATE staging_microblocks SET orphaned = 1, processed = 1 WHERE anchored_block_hash = ?1".to_string();
        let update_microblock_children_args = [&anchored_block_hash.to_hex() as &dyn ToSql];

        tx.execute(&update_block_sql, &update_block_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        tx.execute(&update_children_sql, &update_children_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        tx.execute(&update_microblock_children_sql, &update_microblock_children_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        StacksChainState::delete_staging_block_data(tx, anchored_block_hash)?;

        for mblock_hash in orphaned_microblock_hashes {
            StacksChainState::delete_staging_microblock_data(tx, &mblock_hash)?;
        }
        
        // store empty file in chunk store for this block
        let block_path = StacksChainState::make_block_dir(tx.get_blocks_path(), burn_hash, anchored_block_hash)?;
        StacksChainState::atomic_file_write(&block_path, &vec![])?;

        Ok(())
    }

    /// Clear out a staging block -- move it to the chunk store (either wholly, or mark it invalid
    /// by writing an empty file).
    /// Mark its children as attacheable.
    /// Idempotent.
    fn set_block_processed<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, accept: bool) -> Result<(), Error> {
        let sql = "SELECT * FROM staging_blocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND orphaned = 0".to_string();
        let args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql];
      
        let has_stored_block = StacksChainState::has_stored_block(tx.get_blocks_path(), burn_hash, anchored_block_hash)?;
        let block_path = StacksChainState::make_block_dir(tx.get_blocks_path(), burn_hash, anchored_block_hash)?;

        let rows = query_rows::<StagingBlock, _>(tx, &sql, &args).map_err(Error::DBError)?;
        let block = match rows.len() {
            0 => {
                // not an error if this block was already orphaned
                let orphan_sql = "SELECT * FROM staging_blocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND orphaned = 1".to_string();
                let orphan_args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql];
                let orphan_rows = query_rows::<StagingBlock, _>(tx, &orphan_sql, &orphan_args).map_err(Error::DBError)?;
                if orphan_rows.len() == 1 {
                    return Ok(());
                }
                else {
                    test_debug!("No such block at {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
                    return Err(Error::DBError(db_error::NotFoundError));
                }
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
                    StacksChainState::move_staging_block_data_to_file(tx, anchored_block_hash, &block_path)?;
                }
                else {
                    debug!("Reject block {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
                }
            }
            else {
                debug!("Already stored block {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
            }
        }
        else {
            debug!("Already processed block {}/{}", burn_hash.to_hex(), anchored_block_hash.to_hex());
        }

        let update_sql = "UPDATE staging_blocks SET processed = 1 WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2".to_string();
        let update_args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql];

        tx.execute(&update_sql, &update_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
       
        if accept {
            // if we accepted this block, then children of this processed block are now attacheable.
            // Applies across all burnchain forks
            let update_children_sql = "UPDATE staging_blocks SET attacheable = 1 WHERE parent_anchored_block_hash = ?1".to_string();
            let update_children_args = [&anchored_block_hash.to_hex() as &dyn ToSql];

            tx.execute(&update_children_sql, &update_children_args)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }
        else {
            // Otherwise, all descendents of this processed block are never attacheable.
            // Mark this block's children as orphans, blow away its data, and blow away its descendent microblocks.
            StacksChainState::delete_orphaned_epoch_data(tx, burn_hash, anchored_block_hash)?;
        }

        Ok(())
    }

    /// Drop a trail of staging microblocks.  Mark them as orphaned and delete their data.
    /// Also, orphan any anchored children blocks that build off of the now-orphaned microblocks.
    fn drop_staging_microblocks<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, invalid_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        // find offending sequence
        let seq_sql = "SELECT sequence FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND microblock_hash = ?3 AND processed = 0 AND orphaned = 0".to_string();
        let seq_args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql, &invalid_block_hash.to_hex() as &dyn ToSql];
        let seq = match query_int::<_>(tx, &seq_sql, &seq_args) {
            Ok(seq) => seq,
            Err(e) => match e {
                db_error::NotFoundError => {
                    // no microblocks to delete
                    return Ok(());
                },
                _ => {
                    return Err(Error::DBError(e));
                }
            }
        };

        test_debug!("Drop staging microblocks {}/{} up to {} ({})", burn_hash.to_hex(), anchored_block_hash.to_hex(), invalid_block_hash.to_hex(), seq);

        // drop staging children at and beyond the invalid block
        let update_microblock_children_sql = "UPDATE staging_microblocks SET orphaned = 1, processed = 1 WHERE anchored_block_hash = ?1 AND sequence >= ?2".to_string();
        let update_microblock_children_args = [&anchored_block_hash.to_hex() as &dyn ToSql, &seq as &dyn ToSql];
            
        tx.execute(&update_microblock_children_sql, &update_microblock_children_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // find all orphaned microblocks hashes, and delete the block data
        let find_orphaned_microblocks_sql = "SELECT microblock_hash FROM staging_microblocks WHERE anchored_block_hash = ?1 AND sequence >= ?2".to_string();
        let find_orphaned_microblocks_args = [&anchored_block_hash.to_hex() as &dyn ToSql, &seq as &dyn ToSql];
        let orphaned_microblock_hashes = query_row_columns::<BlockHeaderHash, _>(tx, &find_orphaned_microblocks_sql, &find_orphaned_microblocks_args, "microblock_hash")
            .map_err(Error::DBError)?;
            
        for mblock_hash in orphaned_microblock_hashes.iter() {
            StacksChainState::delete_staging_microblock_data(tx, &mblock_hash)?;
        }

        for mblock_hash in orphaned_microblock_hashes.iter() {
            // orphan any staging blocks that build on the now-invalid microblocks
            let update_block_children_sql = "UPDATE staging_blocks SET orphaned = 1, processed = 0, attacheable = 0 WHERE parent_microblock_hash = ?1".to_string();
            let update_block_children_args = [&mblock_hash.to_hex() as &dyn ToSql];
            
            tx.execute(&update_block_children_sql, &update_block_children_args)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }

        Ok(())
    }

    /// Mark a range of a stream of microblocks as confirmed -- move them to the chunk store if
    /// they're not there already.
    ///
    /// All the corresponding blocks must have been validated and proven contiguous.
    fn set_microblocks_confirmed<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, last_seq: u16) -> Result<(), Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND sequence <= ?3 AND orphaned = 0 ORDER BY sequence ASC".to_string();
        let args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql, &last_seq as &dyn ToSql];
        let mut staging_microblocks = query_rows::<StagingMicroblock, _>(tx, &sql, &args).map_err(Error::DBError)?;

        // load associated staging microblock data, if present 
        for i in 0..staging_microblocks.len() {
            staging_microblocks[i].block_data = StacksChainState::load_staging_microblock_bytes(tx, &staging_microblocks[i].microblock_hash)?.unwrap_or(vec![]);
        }

        // what's the first microblock in this stream?
        let first_microblock_hash = match StacksChainState::get_microblock_stream_head_hash(tx, burn_hash, anchored_block_hash)? {
            Some(bhh) => bhh,
            None => {
                unreachable!("BUG: No staging microblocks head hash, but loaded staging microblocks!");
            }
        };

        // merge with chunk-stored microblock stream, if present
        let stored_microblocks = match StacksChainState::load_microblock_stream(tx.get_blocks_path(), burn_hash, &first_microblock_hash).or_else(StacksChainState::empty_stream)? {
            Some(mblocks) => mblocks,
            None => vec![]
        };
    
        let microblocks = StacksChainState::merge_microblock_streams(staging_microblocks, stored_microblocks)?;

        debug!("Accept microblock stream rooted at {}/{}-{} (up to {})", burn_hash.to_hex(), anchored_block_hash.to_hex(), microblocks[0].block_hash().to_hex(), last_seq);
        StacksChainState::store_microblock_stream(tx.get_blocks_path(), burn_hash, &microblocks)?;

        // clear out of staging
        let sql = "UPDATE staging_microblocks SET processed = 1 WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND sequence <= ?3".to_string();
        let args = [&burn_hash.to_hex() as &dyn ToSql, &anchored_block_hash.to_hex() as &dyn ToSql, &last_seq as &dyn ToSql];

        tx.execute(&sql, &args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        for i in 0..microblocks.len() {
            StacksChainState::delete_staging_microblock_data(tx, &microblocks[i].block_hash())?;
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
    fn validate_parent_microblock_stream(parent_anchored_block_header: &StacksBlockHeader, anchored_block_header: &StacksBlockHeader, microblocks: &Vec<StacksMicroblock>, verify_signatures: bool) -> Option<(usize, Option<TransactionPayload>)> {
        if anchored_block_header.is_genesis() {
            // there had better be zero microblocks
            if anchored_block_header.parent_microblock == EMPTY_MICROBLOCK_PARENT_HASH && anchored_block_header.parent_microblock_sequence == 0 {
                return Some((0, None));
            }
            else {
                warn!("Block {} has no ancestor, and should have no microblock parents", anchored_block_header.block_hash().to_hex());
                return None;
            }
        }

        let signed_microblocks = 
            if verify_signatures {
                let mut signed_microblocks = vec![];
                for microblock in microblocks.iter() {
                    let mut dup = microblock.clone();
                    if dup.verify(&parent_anchored_block_header.microblock_pubkey_hash).is_err() {
                        warn!("Microblock {} not signed by {}", microblock.block_hash().to_hex(), parent_anchored_block_header.microblock_pubkey_hash.to_hex());
                        continue;
                    }
                    signed_microblocks.push(microblock.clone());
                }
                signed_microblocks
            }
            else {
                microblocks.clone()
            };
        
        if signed_microblocks.len() == 0 {
            if anchored_block_header.parent_microblock == EMPTY_MICROBLOCK_PARENT_HASH && anchored_block_header.parent_microblock_sequence == 0 {
                // expected empty
                warn!("No microblocks between {} and {}", parent_anchored_block_header.block_hash().to_hex(), anchored_block_header.block_hash().to_hex());
                return Some((0, None));
            }
            else {
                // did not expect empty
                warn!("Missing microblocks between {} and {}", parent_anchored_block_header.block_hash().to_hex(), anchored_block_header.block_hash().to_hex());
                return None;
            }
        }
        
        if signed_microblocks[0].header.sequence != 0 {
            // discontiguous -- must start with seq 0
            warn!("Discontiguous stream -- first microblock header sequence is {}", signed_microblocks[0].header.sequence);
            return None;
        }

        if signed_microblocks[0].header.prev_block != parent_anchored_block_header.block_hash() {
            // discontiguous -- not connected to parent
            warn!("Discontiguous stream -- does not connect to parent");
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
                warn!("Discontiguous stream -- {} < {}", cur_seq, signed_microblocks[i].header.sequence);
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
        
        if anchored_block_header.parent_microblock == EMPTY_MICROBLOCK_PARENT_HASH && anchored_block_header.parent_microblock_sequence == 0 {
            // expected empty
            debug!("Empty microblock stream between {} and {}", parent_anchored_block_header.block_hash().to_hex(), anchored_block_header.block_hash().to_hex());
            return Some((0, None));
        }

        let mut end = 0;
        let mut connects = false;
        for i in 0..signed_microblocks.len() {
            if signed_microblocks[i].block_hash() == anchored_block_header.parent_microblock {
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
    /// Returns Some(commit burn, total burn) if valid
    /// Returns None if not valid
    /// * burn_header_hash is the burnchain block header hash of the burnchain block whose sortition
    /// (ostensibly) selected this block for inclusion.
    pub fn validate_anchored_block_burnchain<'a>(tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock, mainnet: bool, chain_id: u32) -> Result<Option<(u64, u64)>, Error> {
        // sortition-winning block commit for this block?
        let block_commit = match BurnDB::get_block_commit_for_stacks_block(tx, burn_header_hash, &block.block_hash()).map_err(Error::DBError)? {
            Some(bc) => bc,
            None => {
                // unsoliciated
                return Ok(None);
            }
        };

        // burn chain tip that selected this commit's block
        let burn_chain_tip = BurnDB::get_block_snapshot(tx, &block_commit.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no block snapshot");
       
        // this is the penultimate burnchain snapshot with the VRF seed that this
        // block's miner had to prove on to generate the block-commit and block itself.
        let penultimate_sortition_snapshot = BurnDB::get_block_snapshot_in_fork(tx, block_commit.block_height - 1, &block_commit.burn_header_hash)
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
                        return Ok(None);
                    }
                };

                BurnDB::get_block_snapshot(tx, &parent_commit.burn_header_hash)
                    .map_err(Error::DBError)?
                    .expect("FATAL: burn DB does not have snapshot for parent block commit")
            };

        // attaches to burn chain
        match block.header.validate_burnchain(&burn_chain_tip, &penultimate_sortition_snapshot, &leader_key, &block_commit, &stacks_chain_tip) {
            Ok(_) => {},
            Err(_) => {
                return Ok(None);
            }
        };

        // static checks on transactions all pass
        let valid = block.validate_transactions_static(mainnet, chain_id);
        if !valid {
            return Ok(None);
        }

        let sortition_burns = BurnDB::get_block_burn_amount(tx, block_commit.block_height - 1, &block_commit.burn_header_hash)
            .expect("FATAL: have block commit but no total burns in its sortition");

        Ok(Some((block_commit.burn_fee, sortition_burns)))
    }

    /// Pre-process and store an anchored block to staging, queuing it up for
    /// subsequent processing once all of its ancestors have been processed.
    ///
    /// Caller must have called BurnDB::expects_stacks_block() to determine if this block belongs
    /// to the blockchain.  The burn_header_hash is the hash of the burnchain block whose sortition
    /// elected the given Stacks block.
    /// 
    /// If we find the same Stacks block in two or more burnchain forks, insert it there too
    /// 
    /// TODO: consider how full the block is (i.e. how much computational budget it consumes) when
    /// deciding whether or not it can be processed.
    pub fn preprocess_anchored_block<'a>(&mut self, burn_tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash) -> Result<bool, Error> {
        // already in queue or already processed?
        if StacksChainState::has_stored_block(&self.blocks_path, burn_header_hash, &block.block_hash())? || StacksChainState::has_staging_block(&self.blocks_db, burn_header_hash, &block.block_hash())? {
            test_debug!("Block already stored and/or processed: {}/{}", burn_header_hash.to_hex(), &block.block_hash());
            return Ok(false);
        }
        
        // does this block match the burnchain state? skip if not
        let (commit_burn, sortition_burn) = match StacksChainState::validate_anchored_block_burnchain(burn_tx, burn_header_hash, block, self.mainnet, self.chain_id)? {
            Some((commit_burn, sortition_burn)) => (commit_burn, sortition_burn),
            None => { 
                let msg = format!("Invalid block {}: does not correspond to burn chain state", block.block_hash());
                warn!("{}", &msg);
                return Err(Error::InvalidStacksBlock(msg));
            }
        };
    
        // find all user burns that supported this block 
        let user_burns = BurnDB::get_winning_user_burns_by_block(burn_tx, burn_header_hash)
            .map_err(Error::DBError)?;

        let mut block_tx = self.blocks_tx_begin()?;
     
        // queue block up for processing
        StacksChainState::store_staging_block(&mut block_tx, burn_header_hash, &block, parent_burn_header_hash, commit_burn, sortition_burn)?;

        // store users who burned for this block so they'll get rewarded if we process it
        StacksChainState::store_staging_block_user_burn_supports(&mut block_tx, burn_header_hash, &block.block_hash(), &user_burns)?;

        block_tx.commit().map_err(Error::DBError)?;

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
    ///
    /// If we find the same microblock in multiple burnchain forks, insert it into both.
    pub fn preprocess_streamed_microblock(&mut self, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, microblock: &StacksMicroblock) -> Result<bool, Error> {
        // already queued or already processed?
        if StacksChainState::has_staging_microblock(&self.blocks_db, burn_header_hash, anchored_block_hash, &microblock.block_hash())? {
            test_debug!("Microblock already stored and/or processed: {}/{} {} {}", burn_header_hash.to_hex(), &anchored_block_hash.to_hex(), microblock.block_hash().to_hex(), microblock.header.sequence);
            return Ok(true);
        }

        let mainnet = self.mainnet;
        let chain_id = self.chain_id;

        let mut blocks_tx = self.blocks_tx_begin()?;

        let pubkey_hash = match StacksChainState::load_staging_block_pubkey_hash(&mut blocks_tx, burn_header_hash, anchored_block_hash)? {
            Some(pubkey_hash) => pubkey_hash,
            None => {
                // maybe it's already processed?
                let header = match StacksChainState::load_block_header(blocks_tx.get_blocks_path(), burn_header_hash, anchored_block_hash)? {
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
            warn!("Invalid microblock {}: failed to verify signature with {}", microblock.block_hash().to_hex(), pubkey_hash.to_hex());
            return Ok(false);
        }

        // static checks on transactions all pass
        let valid = microblock.validate_transactions_static(mainnet, chain_id);
        if !valid {
            warn!("Invalid microblock {}: one or more transactions failed static tests", microblock.block_hash().to_hex());
            return Ok(false);
        }

        // add to staging
        StacksChainState::store_staging_microblock(&mut blocks_tx, burn_header_hash, anchored_block_hash, microblock)?;
        
        blocks_tx.commit().map_err(Error::DBError)?;

        Ok(true)
    }

    /// Get the coinbase at this block height, in microSTX
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
            500 * 100_000
        }
        else if block_height < blocks_per_year * 10 {
            400 * 100_000
        }
        else {
            300 * 100_000
        }
    }

    /// Create the block reward.
    /// TODO: calculate how full the block was.
    /// TODO: tx_fees needs to be normalized _a priori_ to be equal to the block-determined fee
    /// rate, times the fraction of the block's total utilization.
    fn make_scheduled_miner_reward(mainnet: bool, 
                                   parent_block_hash: &BlockHeaderHash, 
                                   parent_burn_header_hash: &BurnchainHeaderHash, 
                                   block: &StacksBlock, 
                                   block_burn_header_hash: &BurnchainHeaderHash, 
                                   block_height: u64, 
                                   tx_fees: u128, 
                                   streamed_fees: u128, 
                                   stx_burns: u128,
                                   burnchain_commit_burn: u64,
                                   burnchain_sortition_burn: u64,
                                   fill: u64) -> Result<MinerPaymentSchedule, Error> 
    {
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
            burn_header_hash: block_burn_header_hash.clone(),
            parent_block_hash: parent_block_hash.clone(),
            parent_burn_header_hash: parent_burn_header_hash.clone(),
            coinbase: StacksChainState::get_coinbase_reward(block_height),
            tx_fees_anchored: tx_fees,
            tx_fees_streamed: streamed_fees,
            stx_burns: stx_burns,
            burnchain_commit_burn: burnchain_commit_burn,
            burnchain_sortition_burn: burnchain_sortition_burn,
            fill: fill,
            miner: true,
            stacks_block_height: block_height,
            vtxindex: 0 
        };
        
        Ok(miner_reward)
    }
   
    /// Given a staging block, load up its parent microblock stream from staging.
    /// All of the parent anchored block's microblocks will be loaded, if we have them and they're
    /// not orphaned.
    /// Return Ok(Some(microblocks)) if we got microblocks (even if it's an empty stream)
    /// Return Ok(None) if there are no staging microblocks yet
    fn find_parent_staging_microblock_stream(blocks_conn: &DBConn, blocks_path: &String, staging_block: &StagingBlock) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        if staging_block.parent_microblock_hash == EMPTY_MICROBLOCK_PARENT_HASH && staging_block.parent_microblock_seq == 0 {
            // no parent microblocks, ever
            return Ok(Some(vec![]));
        }

        match StacksChainState::load_staging_microblock_stream(blocks_conn, blocks_path, &staging_block.parent_burn_header_hash, &staging_block.parent_anchored_block_hash, u16::max_value())? {
            Some(microblocks) => {
                return Ok(Some(microblocks));
            }
            None => {
                // parent microblocks haven't arrived yet, or there are none
                debug!("No parent microblock stream for {}: expected {},{}", staging_block.anchored_block_hash.to_hex(), staging_block.parent_microblock_hash.to_hex(), staging_block.parent_microblock_seq);
                return Ok(None);
            }
        }
    }

    /// Find a block that we accepted to staging, but had a parent that we ended up
    /// rejecting.  Garbage-collect its data.
    /// Call this method repeatedly to remove long chains of orphaned blocks and microblocks from
    /// staging.
    /// Returns true if an orphan block was processed
    fn process_next_orphaned_staging_block<'a>(blocks_tx: &mut BlocksDBTx<'a>) -> Result<bool, Error> {
        test_debug!("Find next orphaned block");

        // go through staging blocks and see if any of them have not been processed yet, but are
        // orphaned
        let sql = "SELECT * FROM staging_blocks WHERE processed = 0 AND orphaned = 1 ORDER BY RANDOM() LIMIT 1".to_string();
        let mut rows = query_rows::<StagingBlock, _>(blocks_tx, &sql, NO_PARAMS).map_err(Error::DBError)?;
        if rows.len() == 0 {
            return Ok(false);
        }

        let orphan_block = rows.pop().unwrap();

        test_debug!("Delete orphaned block {}/{} and its microblocks, and orphan its children", &orphan_block.burn_header_hash.to_hex(), &orphan_block.anchored_block_hash.to_hex());

        StacksChainState::delete_orphaned_epoch_data(blocks_tx, &orphan_block.burn_header_hash, &orphan_block.anchored_block_hash)?;
        Ok(true)
    }

    /// Given access to the chain state (headers) and the staging blocks, find a staging block we
    /// can process, as well as its parent microblocks that it confirms
    /// Returns Some(microblocks, staging block) if we found a sequence of blocks to process.
    /// Returns None if not.
    fn find_next_staging_block(blocks_conn: &DBConn, blocks_path: &String, headers_conn: &DBConn) -> Result<Option<(Vec<StacksMicroblock>, StagingBlock)>, Error> {
        test_debug!("Find next staging block");

        // go through staging blocks and see if any of them match headers and are attacheable.
        // pick randomly -- don't allow the network sender to choose the processing order!
        let sql = "SELECT * FROM staging_blocks WHERE processed = 0 AND attacheable = 1 AND orphaned = 0 ORDER BY RANDOM()".to_string();
        
        let mut stmt = blocks_conn.prepare(&sql)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let mut rows = stmt.query(NO_PARAMS)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let candidate = StagingBlock::from_row(&row).map_err(Error::DBError)?;
                    
                    test_debug!("Consider block {}/{} whose parent is {}/{}", 
                                &candidate.burn_header_hash.to_hex(), &candidate.anchored_block_hash.to_hex(),
                                &candidate.parent_burn_header_hash.to_hex(), &candidate.parent_anchored_block_hash.to_hex());
        
                    let can_attach = {
                        if candidate.parent_anchored_block_hash == FIRST_STACKS_BLOCK_HASH {
                            // this block's parent is the boot code -- it's the first-ever block,
                            // so it can be processed immediately 
                            true
                        }
                        else {
                            // not the first-ever block.  Does this connect to a previously-accepted
                            // block in the headers database?
                            let hdr_sql = "SELECT * FROM block_headers WHERE block_hash = ?1 AND burn_header_hash = ?2".to_string();
                            let hdr_rows = query_rows::<StacksHeaderInfo, _>(headers_conn, &hdr_sql, &[&candidate.parent_anchored_block_hash.to_hex() as &dyn ToSql, &candidate.parent_burn_header_hash.to_hex() as &dyn ToSql])
                                .map_err(Error::DBError)?;

                            match hdr_rows.len() {
                                0 => {
                                    // no parent processed for this block
                                    false
                                }
                                1 => {
                                    // can process this block 
                                    true
                                },
                                _ => {
                                    // should be impossible -- stored the same block twice
                                    unreachable!("Stored the same block twice: {}/{}", &candidate.parent_anchored_block_hash.to_hex(), &candidate.parent_burn_header_hash.to_hex());
                                }
                            }
                        }
                    };

                    if can_attach {
                        // try and load up this staging block and its microblocks
                        match StacksChainState::load_staging_block(blocks_conn, &candidate.burn_header_hash, &candidate.anchored_block_hash)? {
                            Some(staging_block) => {
                                // must be unprocessed -- must have a block
                                if staging_block.block_data.len() == 0 {
                                    return Err(Error::NetError(net_error::DeserializeError(format!("No block data for staging block {}", candidate.anchored_block_hash.to_hex()))));
                                }

                                // find its microblock parent stream
                                match StacksChainState::find_parent_staging_microblock_stream(blocks_conn, blocks_path, &staging_block)? {
                                    Some(parent_staging_microblocks) => {
                                        return Ok(Some((parent_staging_microblocks, staging_block)));
                                    },
                                    None => {
                                        // no microblock data yet
                                    }
                                }
                            },
                            None => {
                                // should be impossible -- selected unprocessed blocks
                                unreachable!("Failed to load staging block when an earlier query indicated that it was present");
                            }
                        }
                    }
                },
                Err(e) => {
                    return Err(Error::DBError(db_error::SqliteError(e)));
                }
            }
        }

        // no blocks available
        Ok(None)
    }

    /// Process a stream of microblocks
    /// Return the fees and burns.
    /// TODO: if we find an invalid Stacks microblock, then punish the miner who produced it
    pub fn process_microblocks_transactions<'a>(clarity_tx: &mut ClarityTx<'a>, microblocks: &Vec<StacksMicroblock>) -> Result<(u128, u128), (Error, BlockHeaderHash)> {
        let mut fees = 0u128;
        let mut burns = 0u128;
        for microblock in microblocks.iter() {
            for tx in microblock.txs.iter() {
                let (tx_fee, tx_burns) = StacksChainState::process_transaction(clarity_tx, tx)
                    .map_err(|e| (e, microblock.block_hash()))?;

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

    /// Process a single matured miner reward.
    /// Grant it STX tokens in the miner trust fund contract from the chain's boot code.
    fn process_matured_miner_reward<'a>(clarity_tx: &mut ClarityTx<'a>, miner_reward: &MinerReward) -> Result<(), Error> {
        let boot_code_address = StacksAddress::from_string(&STACKS_BOOT_CODE_CONTRACT_ADDRESS.to_string()).unwrap();
        let miner_contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(boot_code_address.clone()), ContractName::try_from(BOOT_CODE_MINER_CONTRACT_NAME.to_string()).unwrap());
        
        let miner_participant_principal = ClarityName::try_from(BOOT_CODE_MINER_REWARDS_PARTICIPANT.to_string()).unwrap();
        let miner_available_name = ClarityName::try_from(BOOT_CODE_MINER_REWARDS_AVAILABLE.to_string()).unwrap();
        let miner_authorized_name = ClarityName::try_from(BOOT_CODE_MINER_REWARDS_AUTHORIZED.to_string()).unwrap();
        
        let miner_principal = Value::Tuple(TupleData::from_data(vec![
                (miner_participant_principal, Value::Principal(PrincipalData::Standard(StandardPrincipalData::from(miner_reward.address.clone()))))])
            .expect("FATAL: failed to construct miner principal key"));

        let miner_reward_total = miner_reward.total();
      
        clarity_tx.connection().with_clarity_db(|ref mut db| {
            // (+ reward (get available (default-to (tuple (available 0) (authorized 'false)) (map-get rewards ((miner))))))
            let miner_status_opt = db.fetch_entry(&miner_contract_id, BOOT_CODE_MINER_REWARDS_MAP, &miner_principal)?;
            let new_miner_status = 
                match miner_status_opt {
                    Value::Optional(ref optional_data) => {
                        match optional_data.data {
                            None => {
                                // this miner doesn't have an entry in the contract yet
                                Value::Tuple(TupleData::from_data(vec![
                                    (miner_available_name, Value::UInt(miner_reward_total)),
                                    (miner_authorized_name, Value::Bool(false)),
                                ]).expect("FATAL: failed to construct miner reward tuple"))
                            },
                            Some(ref miner_status) => {
                                match **miner_status {
                                    Value::Tuple(ref tuple) => {
                                        let new_available = match tuple.get(&miner_available_name).expect("FATAL: no miner name in tuple") {
                                            Value::UInt(ref available) => {
                                                let new_available = available.checked_add(miner_reward_total).expect("FATAL: STX reward overflow");
                                                Value::UInt(new_available)
                                            },
                                            _ => {
                                                panic!("FATAL: miner reward data map is malformed");
                                            }
                                        };
                                        
                                        let mut new_tuple = tuple.clone();
                                        new_tuple.data_map.insert(miner_available_name.clone(), new_available);
                                        Value::Tuple(new_tuple)
                                    },
                                    ref x => {
                                        panic!("FATAL: miner status is not a tuple: {:?}", &x);
                                    }
                                }
                            }
                        }
                    },
                    ref x => {
                        panic!("FATAL: fetched miner status it not an optional: {:?}", &x);
                    }
                };

            debug!("Grant miner {} {} STX", miner_reward.address.to_string(), miner_reward_total);
            db.set_entry(&miner_contract_id, BOOT_CODE_MINER_REWARDS_MAP, miner_principal, new_miner_status)?;
            Ok(())
        }).map_err(Error::ClarityError)?;
        Ok(())
    }

    /// Process matured miner rewards for this block
    pub fn process_matured_miner_rewards<'a>(clarity_tx: &mut ClarityTx<'a>, miner_rewards: &Vec<MinerReward>) -> Result<(), Error> {
        // must all be in order by vtxindex, and the first reward (the miner's) must have vtxindex 0
        assert!(miner_rewards.len() > 0);
        assert!(miner_rewards[0].vtxindex == 0);
        for i in 0..miner_rewards.len()-1 {
            assert!(miner_rewards[i].vtxindex < miner_rewards[i+1].vtxindex);
        }

        // store each reward into the miner trust fund contract in the chain boot code
        for reward in miner_rewards.iter() {
            StacksChainState::process_matured_miner_reward(clarity_tx, reward)?;
        }
        Ok(())
    }

    /// Process the next pre-processed staging block.
    /// We've already processed parent_chain_tip.  chain_tip refers to a block we have _not_
    /// processed yet.
    /// Returns a StacksHeaderInfo with the microblock stream and chain state index root hash filled in, corresponding to the next block to process.
    /// Returns None if we're out of blocks to process.
    fn append_block<'a>(chainstate_tx: &mut ChainstateTx<'a>,
                        clarity_instance: &'a mut ClarityInstance,
                        parent_chain_tip: &StacksHeaderInfo, 
                        chain_tip_burn_header_hash: &BurnchainHeaderHash, 
                        block: &StacksBlock, 
                        microblocks: &Vec<StacksMicroblock>,  // parent microblocks 
                        burnchain_commit_burn: u64, 
                        burnchain_sortition_burn: u64, 
                        user_burns: &Vec<StagingUserBurnSupport>) -> Result<StacksHeaderInfo, Error>
    {
        let mainnet = chainstate_tx.get_config().mainnet;
        let next_block_height = block.header.total_work.work;

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        let matured_miner_rewards_opt = {
            StacksChainState::find_mature_miner_rewards(&mut chainstate_tx.headers_tx, parent_chain_tip)?
        };

        let scheduled_miner_reward = {
            let (parent_burn_header_hash, parent_block_hash) = 
                if block.header.is_genesis() {
                    // has to be the sentinal hashes if this block has no parent
                    (FIRST_BURNCHAIN_BLOCK_HASH.clone(), FIRST_STACKS_BLOCK_HASH.clone())
                }
                else {
                    (parent_chain_tip.burn_header_hash.clone(), parent_chain_tip.anchored_header.block_hash())
                };
 
            let (last_microblock_hash, last_microblock_seq) = 
                if microblocks.len() > 0 {
                    let _first_mblock_hash = microblocks[0].block_hash();
                    let num_mblocks = microblocks.len();
                    let last_microblock_hash = microblocks[num_mblocks-1].block_hash();
                    let last_microblock_seq = microblocks[num_mblocks-1].header.sequence;

                    test_debug!("\n\nAppend {} microblocks {}/{}-{} off of {}/{}\n", num_mblocks, chain_tip_burn_header_hash.to_hex(), _first_mblock_hash, last_microblock_hash, parent_burn_header_hash.to_hex(), parent_block_hash.to_hex());
                    (last_microblock_hash, last_microblock_seq)
                }
                else {
                    (EMPTY_MICROBLOCK_PARENT_HASH.clone(), 0)
                };

            if last_microblock_hash != block.header.parent_microblock || last_microblock_seq != block.header.parent_microblock_sequence {
                // the pre-processing step should prevent this from being reached
                panic!("BUG: received discontiguous headers for processing: {} (seq={}) does not connect to {} (microblock parent is {} (seq {}))",
                       last_microblock_hash.to_hex(), last_microblock_seq, block.block_hash(), block.header.parent_microblock.to_hex(), block.header.parent_microblock_sequence);
            }
            
            let mut clarity_tx = StacksChainState::chainstate_block_begin(chainstate_tx, clarity_instance, &parent_burn_header_hash, &parent_block_hash, &MINER_BLOCK_BURN_HEADER_HASH, &MINER_BLOCK_HEADER_HASH);

            // process microblock stream
            let (microblock_fees, _microblock_burns) = match StacksChainState::process_microblocks_transactions(&mut clarity_tx, &microblocks) {
                Err((e, offending_mblock_header_hash)) => {
                    let msg = format!("Invalid Stacks microblocks {},{} (offender {}): {:?}", block.header.parent_microblock.to_hex(), block.header.parent_microblock_sequence, offending_mblock_header_hash.to_hex(), &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksMicroblock(msg, offending_mblock_header_hash));
                },
                Ok((fees, burns)) => {
                    (fees, burns)
                }
            };
            
            test_debug!("\n\nAppend block {}/{} off of {}/{}\nStacks block height: {}, Total Burns: {}\nMicroblock parent: {} (seq {}) (count {})\n", 
                        chain_tip_burn_header_hash.to_hex(), block.block_hash().to_hex(), parent_burn_header_hash.to_hex(), parent_block_hash.to_hex(),
                        block.header.total_work.work, block.header.total_work.burn,
                        last_microblock_hash.to_hex(), last_microblock_seq, microblocks.len());

            // process anchored block
            let (block_fees, block_burns) = match StacksChainState::process_block_transactions(&mut clarity_tx, &block) {
                Err(e) => {
                    let msg = format!("Invalid Stacks block {}: {:?}", block.block_hash().to_hex(), &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok((block_fees, block_burns)) => (block_fees, block_burns)
            };

            // grant matured miner rewards
            if let Some(mature_miner_rewards) = matured_miner_rewards_opt {
                // grant in order by miner, then users
                StacksChainState::process_matured_miner_rewards(&mut clarity_tx, &mature_miner_rewards)?;
            }

            let root_hash = clarity_tx.get_root_hash();
            if root_hash != block.header.state_index_root {
                let msg = format!("Block {} state root mismatch: expected {}, got {}", block.block_hash(), root_hash, block.header.state_index_root);
                warn!("{}", &msg);
                
                clarity_tx.rollback_block();
                return Err(Error::InvalidStacksBlock(msg));
            }

            debug!("Reached state root {}", root_hash.to_hex());
            
            // good to go!
            clarity_tx.commit_to_block(chain_tip_burn_header_hash, &block.block_hash());

            // calculate reward for this block's miner
            let scheduled_miner_reward = StacksChainState::make_scheduled_miner_reward(mainnet, 
                                                                                       &parent_block_hash, 
                                                                                       &parent_burn_header_hash, 
                                                                                       &block, 
                                                                                       chain_tip_burn_header_hash, 
                                                                                       next_block_height, 
                                                                                       block_fees,                // TODO: calculate (STX/compute unit) * (compute used) 
                                                                                       microblock_fees, 
                                                                                       block_burns,
                                                                                       burnchain_commit_burn,
                                                                                       burnchain_sortition_burn,
                                                                                       0xffffffffffffffff)        // TODO: calculate total compute budget and scale up
                .expect("FATAL: parsed and processed a block without a coinbase");

             scheduled_miner_reward
        };
       
        let microblock_tail_opt = match microblocks.len() {
            0 => None,
            x => Some(microblocks[x - 1].header.clone())
        };

        let new_tip = StacksChainState::advance_tip(&mut chainstate_tx.headers_tx, 
                                                    &parent_chain_tip.anchored_header, 
                                                    &parent_chain_tip.burn_header_hash, 
                                                    &block.header, 
                                                    chain_tip_burn_header_hash, 
                                                    microblock_tail_opt,
                                                    &scheduled_miner_reward, 
                                                    user_burns)
            .expect("FATAL: failed to advance chain tip");

        Ok(new_tip)
    }

    /// Find and process the next staging block.
    /// Return the next chain tip if we processed this block, or None if we couldn't.
    /// Return a poison microblock transaction payload if the microblock stream contains a
    /// deliberate miner fork.
    ///
    /// Occurs as a single, atomic transaction against the (marf'ed) headers database and
    /// (un-marf'ed) staging block database, as well as against the chunk store.
    pub fn process_next_staging_block(&mut self) -> Result<(Option<StacksHeaderInfo>, Option<TransactionPayload>), Error> {
        let (mut chainstate_tx, clarity_instance) = self.chainstate_tx_begin()?;

        let blocks_path = chainstate_tx.blocks_tx.get_blocks_path().clone();

        // this is a transaction against both the headers and staging blocks databases!
        let (mut next_microblocks, next_staging_block) = match StacksChainState::find_next_staging_block(&chainstate_tx.blocks_tx, &blocks_path, &chainstate_tx.headers_tx)? {
            Some((next_microblocks, next_staging_block)) => (next_microblocks, next_staging_block),
            None => {
                // no more work to do!
                debug!("No staging blocks");
                return Ok((None, None));
            }
        };

        debug!("Process staging block {}/{}", next_staging_block.burn_header_hash.to_hex(), next_staging_block.anchored_block_hash.to_hex());

        let parent_block_header_info = {
            let parent_block_header_info = match StacksChainState::get_anchored_block_header_info(&chainstate_tx.headers_tx, &next_staging_block.parent_burn_header_hash, &next_staging_block.parent_anchored_block_hash)? {
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

        // sanity check -- don't process this block again if we already did so
        if StacksChainState::has_stored_block(chainstate_tx.blocks_tx.get_blocks_path(), &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash)? {
            debug!("Block already processed: {}/{}", &next_staging_block.burn_header_hash.to_hex(), &next_staging_block.anchored_block_hash.to_hex());

            // clear out
            StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash, true)?;
            return Ok((None, None));
        }

        // validation check -- we can't have seen this block's microblock public key hash before in
        // this fork
        if StacksChainState::has_microblock_pubkey_hash(&mut chainstate_tx.headers_tx, &parent_block_header_info.burn_header_hash, &parent_block_header_info.anchored_header, &block.header.microblock_pubkey_hash)? {
            let msg = format!("Invalid stacks block -- already used microblock pubkey hash {}", &block.header.microblock_pubkey_hash.to_hex());
            warn!("{}", &msg);
            return Err(Error::InvalidStacksBlock(msg));
        }

        // validate microblocks
        // NOTE: since we got the microblocks from staging, where their signatures were already
        // validated, we don't need to validate them again.
        let (microblock_terminus, poison_microblock_opt) = match StacksChainState::validate_parent_microblock_stream(&parent_block_header_info.anchored_header, &block.header, &next_microblocks, false) {
            Some((terminus, poison_opt)) => (terminus, poison_opt),
            None => {
                debug!("Stopping at block {}/{} -- discontiguous header stream", next_staging_block.burn_header_hash.to_hex(), block_hash.to_hex());
                return Ok((None, None));
            }
        };

        match poison_microblock_opt {
            Some(poison_microblock) => {
                // miner created a deliberate fork.
                //
                // TODO: a miner can build off of any microblock fork it wants as long as there isn't yet a PoisonMicroblock
                // transaction that publishes the existence of the fork.
                // Once this happens, then no one can't mine off of any microblock at or beyond the announced
                // microblock fork within the Stacks fork that published the PoisonMicroblock.
                // Moreover, if there are multiple PoisonMicroblock transactions, the reward for the PoisonMicroblock
                // is transferred to the _earliest_ fork-publisher.
                return Ok((None, Some(poison_microblock)));
            }
            None => {}
        }

        // do not consider trailing microblocks that this anchored block does _not_ confirm
        if microblock_terminus < next_microblocks.len() {
            debug!("Truncate microblock stream from parent {}/{} from {} to {} items", parent_block_header_info.burn_header_hash.to_hex(), parent_block_header_info.anchored_header.block_hash().to_hex(), next_microblocks.len(), microblock_terminus);
            next_microblocks.truncate(microblock_terminus);
        }

        let (last_microblock_hash, last_microblock_seq) = match next_microblocks.len() {
            0 => (EMPTY_MICROBLOCK_PARENT_HASH.clone(), 0),
            _ => {
                let l = next_microblocks.len();
                (next_microblocks[l - 1].block_hash(), next_microblocks[l - 1].header.sequence)
            }
        };

        // find users that burned in support of this block, so we can calculate the miner reward
        let user_supports = StacksChainState::load_staging_block_user_supports(&chainstate_tx.blocks_tx, &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash)?;

        // attach the block to the chain state and calculate the next chain tip.
        // Execute the confirmed microblocks' transactions against the chain state, and then
        // execute the anchored block's transactions against the chain state.
        let next_chain_tip = match StacksChainState::append_block(&mut chainstate_tx, 
                                                                  clarity_instance, 
                                                                  &parent_block_header_info, 
                                                                  &next_staging_block.burn_header_hash, 
                                                                  &block, 
                                                                  &next_microblocks, 
                                                                  next_staging_block.commit_burn, 
                                                                  next_staging_block.sortition_burn, 
                                                                  &user_supports) {
            Ok(next_chain_tip) => next_chain_tip,
            Err(e) => {
                // something's wrong with this epoch -- either a microblock was invalid, or the
                // anchored block was invalid.  Either way, the anchored block will _never be_
                // valid, so we can drop it from the chunk store and orphan all of its descendents.
                StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, &next_staging_block.burn_header_hash, &block.header.block_hash(), false)
                    .expect(&format!("FATAL: failed to clear invalid block {}/{}", next_staging_block.burn_header_hash.to_hex(), &block.header.block_hash().to_hex()));
                
                StacksChainState::free_block_state(&blocks_path, &next_staging_block.burn_header_hash, &block.header);

                match e {
                    Error::InvalidStacksMicroblock(ref msg, ref header_hash) => {
                        // specifically, an ancestor microblock was invalid.  Drop any descendent microblocks --
                        // they're never going to be valid in _any_ fork, even if they have a clone
                        // in a neighboring burnchain fork.
                        error!("Parent microblock stream from {}/{} is invalid at microblock {}: {}", parent_block_header_info.burn_header_hash.to_hex(), parent_block_header_info.anchored_header.block_hash().to_hex(), header_hash, msg);
                        StacksChainState::drop_staging_microblocks(&mut chainstate_tx.blocks_tx, &parent_block_header_info.burn_header_hash, &parent_block_header_info.anchored_header.block_hash(), header_hash)?;
                    },
                    _ => {
                        // block was invalid, but this means all the microblocks it confirmed are
                        // still (potentially) valid.  However, they are not confirmed yet, so
                        // leave them in the staging database.
                    }
                }
                return Err(e);
            }
        };

        assert_eq!(next_chain_tip.anchored_header.block_hash(), block.block_hash());
        assert_eq!(next_chain_tip.burn_header_hash, next_staging_block.burn_header_hash);
        assert_eq!(next_chain_tip.anchored_header.parent_microblock, last_microblock_hash);
        assert_eq!(next_chain_tip.anchored_header.parent_microblock_sequence, last_microblock_seq);

        debug!("Reached chain tip {}/{} from {}/{}", next_chain_tip.burn_header_hash.to_hex(), next_chain_tip.anchored_header.block_hash().to_hex(), next_staging_block.parent_burn_header_hash.to_hex(), next_staging_block.parent_anchored_block_hash.to_hex());

        if next_staging_block.parent_microblock_hash != EMPTY_MICROBLOCK_PARENT_HASH || next_staging_block.parent_microblock_seq != 0 {
            // confirmed one or more parent microblocks
            StacksChainState::set_microblocks_confirmed(&mut chainstate_tx.blocks_tx, &next_staging_block.parent_burn_header_hash, &next_staging_block.parent_anchored_block_hash, last_microblock_seq)?;
        }
        StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, &next_chain_tip.burn_header_hash, &next_chain_tip.anchored_header.block_hash(), true)?;
       
        chainstate_tx.commit()
            .map_err(Error::DBError)?;

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

        for i in 0..max_blocks {
            // process up to max_blocks pending blocks
            let (next_tip_opt, next_microblock_poison_opt) = self.process_next_staging_block()?;
            match next_tip_opt {
                Some(next_tip) => {
                    ret.push((Some(next_tip), next_microblock_poison_opt));
                },
                None => {
                    match next_microblock_poison_opt {
                        Some(poison) => {
                            ret.push((None, Some(poison)));
                        },
                        None => {
                            debug!("No more staging blocks -- processed {} in total", i);
                            break;
                        }
                    }
                }
            }
        }

        let mut block_tx = self.blocks_tx_begin()?;
        for i in 0..max_blocks {
            // delete up to max_blocks blocks
            let deleted = StacksChainState::process_next_orphaned_staging_block(&mut block_tx)?;
            if !deleted {
                break;
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
        let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
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
                sequence: i as u16,
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

    fn assert_block_staging_not_processed(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock) -> () {
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), *block);
        assert_eq!(StacksChainState::get_staging_block_status(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), false);
    }

    fn assert_block_not_stored(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock) -> () {
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, burn_header, &block.block_hash()).is_err());
        assert!(StacksChainState::load_block_header(&chainstate.blocks_path, burn_header, &block.block_hash()).is_err());
        assert_eq!(StacksChainState::load_staging_block_pubkey_hash(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), block.header.microblock_pubkey_hash);
    }
    
    fn assert_block_stored_rejected(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock) -> () {
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_block_header(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_staging_block_pubkey_hash(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());
        
        assert_eq!(StacksChainState::get_staging_block_status(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), true);
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());
    }

    fn assert_block_stored_not_staging(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock) -> () {
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap(), *block);
        assert_eq!(StacksChainState::load_block_header(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap(), block.header);
        assert!(StacksChainState::load_staging_block_pubkey_hash(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());

        assert_eq!(StacksChainState::get_staging_block_status(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), true);
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());
    }

    fn store_staging_block(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock, parent_burn_header: &BurnchainHeaderHash, commit_burn: u64, sortition_burn: u64) {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::store_staging_block(&mut tx, burn_header, block, parent_burn_header, commit_burn, sortition_burn).unwrap();
        tx.commit().unwrap();
    }

    fn store_staging_microblock(chainstate: &mut StacksChainState, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, microblock: &StacksMicroblock) {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::store_staging_microblock(&mut tx, burn_header_hash, anchored_block_hash, microblock).unwrap();
        tx.commit().unwrap();
    }
    
    fn set_block_processed(chainstate: &mut StacksChainState, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, accept: bool) {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::set_block_processed(&mut tx, burn_hash, anchored_block_hash, accept).unwrap();
        tx.commit().unwrap();
    }

    fn set_microblocks_confirmed(chainstate: &mut StacksChainState, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, last_seq: u16) {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::set_microblocks_confirmed(&mut tx, burn_hash, anchored_block_hash, last_seq).unwrap();
        tx.commit().unwrap();
    }

    fn process_next_orphaned_staging_block(chainstate: &mut StacksChainState) -> bool {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        let res = StacksChainState::process_next_orphaned_staging_block(&mut tx).unwrap();
        tx.commit().unwrap();
        res
    }
   
    fn drop_staging_microblocks(chainstate: &mut StacksChainState, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, invalid_microblock: &BlockHeaderHash) {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::drop_staging_microblocks(&mut tx, burn_hash, anchored_block_hash, invalid_microblock).unwrap();
        tx.commit().unwrap();
    }
    
    #[test]
    fn stacks_db_block_load_store_empty() {
        let chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_block_load_store_empty");
       
        let path = StacksChainState::get_block_path(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap();
        assert!(fs::metadata(&path).is_err());
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap());

        StacksChainState::store_empty_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap();
        assert!(fs::metadata(&path).is_ok());
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap().is_none());
    }

    #[test]
    fn stacks_db_block_load_store() {
        let chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_block_load_store");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let mut block = make_empty_coinbase_block(&privk);

        // don't worry about freeing microblcok state yet
        block.header.parent_microblock_sequence = 0;
        block.header.parent_microblock = EMPTY_MICROBLOCK_PARENT_HASH.clone();

        let path = StacksChainState::get_block_path(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap();
        assert!(fs::metadata(&path).is_err());
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());

        StacksChainState::store_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block).unwrap();
        assert!(fs::metadata(&path).is_ok());
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(StacksChainState::load_block_header(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header);

        StacksChainState::free_block_state(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.header);

        assert!(StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_block_header(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_none());
    }

    #[test]
    fn stacks_db_staging_block_load_store_accept() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);

        assert_block_staging_not_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);
        assert_block_not_stored(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);

        set_block_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), true);

        assert_block_stored_not_staging(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);
        
        // should be idempotent
        set_block_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), true);

        assert_block_stored_not_staging(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);
    }
    
    #[test]
    fn stacks_db_staging_block_load_store_reject() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_reject");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);

        assert_block_staging_not_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);
        assert_block_not_stored(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);

        set_block_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), false);
    
        assert_block_stored_rejected(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);
        
        // should be idempotent
        set_block_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), false);
    
        assert_block_stored_rejected(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);
    }

    #[test]
    fn stacks_db_load_store_microblock_stream() {
        let chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_load_store_microblock_stream");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());

        let path = StacksChainState::get_block_path(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap();
        assert!(fs::metadata(&path).is_err());
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).is_err());

        StacksChainState::store_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks).unwrap();

        assert!(fs::metadata(&path).is_ok());
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().unwrap(), microblocks);

        StacksChainState::free_block(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash());

        assert!(StacksChainState::has_stored_block(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().is_none());
    }

    #[test]
    fn stacks_db_staging_microblock_stream_load_store_confirm_all() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_microblock_stream_load_store_accept");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        
        assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().is_none());

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);
        for mb in microblocks.iter() {
            store_staging_microblock(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), mb);
        }

        // block should be stored to staging
        assert_block_staging_not_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);

        // microblock stream should be stored to staging
        assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().unwrap().try_into_microblock().unwrap(), microblocks[0]);
        assert_eq!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().unwrap(), microblocks);

        // block should _not_ be in the chunk store
        assert_block_not_stored(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);

        // microblocks should _not_ be in the chunk store
        assert!(!StacksChainState::has_stored_microblocks(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).is_err());

        set_block_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), true);
        set_microblocks_confirmed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), (microblocks.len() - 1) as u16);

        // block should be stored to chunk store now
        assert_block_stored_not_staging(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);

        // microblocks should be in the chunk store
        assert!(StacksChainState::has_stored_microblocks(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert_eq!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().unwrap(), microblocks);

        // microblocks should be absent from staging
        for mb in microblocks.iter() {
            assert!(StacksChainState::get_staging_microblock_status(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().is_some());
            assert_eq!(StacksChainState::get_staging_microblock_status(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().unwrap(), true);
        }
        
        // but we should still load the full stream if asked
        assert!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().is_some());
        assert_eq!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().unwrap(), microblocks);
    }
    
    #[test]
    fn stacks_db_staging_microblock_stream_load_store_partial_confirm() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_microblock_stream_load_store_reject");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        
        assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().is_none());

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);
        for mb in microblocks.iter() {
            store_staging_microblock(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), mb);
        }

        // block should be stored to staging
        assert_block_staging_not_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);
        assert_block_not_stored(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);

        // microblock stream should be stored to staging
        assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &microblocks[0].block_hash()).unwrap().unwrap().try_into_microblock().unwrap(), microblocks[0]);
        assert_eq!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().unwrap(), microblocks);

        // microblocks should _not_ be in the chunk store
        assert!(!StacksChainState::has_stored_microblocks(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).is_err());

        // confirm the 0th microblock, but not the 1st or later.
        // do not confirm the block.
        set_block_processed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), true);
        set_microblocks_confirmed(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), 0);

        // block should be processed in staging, but the data should not be in the staging DB
        assert_block_stored_not_staging(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), &block);

        // microblocks should not be in the chunk store, except for block 0 which was confirmed
        assert!(StacksChainState::has_stored_microblocks(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().unwrap(), vec![microblocks[0].clone()]);
        
        // microblocks should be present in staging, except for block 0 
        for mb in microblocks.iter() {
            assert!(StacksChainState::get_staging_microblock_status(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().is_some());
            
            if mb.header.sequence == 0 {
                assert_eq!(StacksChainState::get_staging_microblock_status(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().unwrap(), true);
            }
            else {
                // not processed since seq=0 was the last block to be accepted
                assert_eq!(StacksChainState::get_staging_microblock_status(&chainstate.blocks_db, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), &mb.block_hash()).unwrap().unwrap(), false);
            }
        }
        
        // can load the entire stream still
        assert!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().is_some());
        assert_eq!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash(), u16::max_value()).unwrap().unwrap(), microblocks);
    }

    #[test]
    fn stacks_db_validate_parent_microblock_stream() {
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
        let block = make_empty_coinbase_block(&privk);
        let microblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        let num_mblocks = microblocks.len();

        let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
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
            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header, &microblocks, true);
            assert!(res.is_some());

            let (cutoff, poison_opt) = res.unwrap();
            assert!(poison_opt.is_none());
            assert_eq!(cutoff, num_mblocks);
        }

        // empty stream
        { 
            let mut child_block_header_empty = child_block_header.clone();
            child_block_header_empty.parent_microblock = EMPTY_MICROBLOCK_PARENT_HASH.clone();
            child_block_header_empty.parent_microblock_sequence = 0;

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_empty, &vec![], true);
            assert!(res.is_some());

            let (cutoff, poison_opt) = res.unwrap();
            assert!(poison_opt.is_none());
            assert_eq!(cutoff, 0);
        }
        
        // non-empty stream, but child drops all microblocks
        { 
            let mut child_block_header_empty = child_block_header.clone();
            child_block_header_empty.parent_microblock = EMPTY_MICROBLOCK_PARENT_HASH.clone();
            child_block_header_empty.parent_microblock_sequence = 0;

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_empty, &microblocks, true);
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

                let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_trunc, &microblocks, true);
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

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header_broken, &microblocks, true);
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

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks, true);
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

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks, true);
            assert!(res.is_none());
        }
        
        // nonempty stream, but discontiguous first microblock (doesn't connect to parent block)
        {
            let mut broken_microblocks = microblocks.clone();
            broken_microblocks[0].header.prev_block = BlockHeaderHash([1u8; 32]);

            let mut new_child_block_header = child_block_header.clone();
            new_child_block_header.parent_microblock = resign_microblocks(&mut broken_microblocks, &privk);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks, true);
            assert!(res.is_none());
        }
        
        // nonempty stream, but discontiguous first microblock (wrong sequence)
        {
            let mut broken_microblocks = microblocks.clone();
            broken_microblocks[0].header.sequence = 1;
            
            let mut new_child_block_header = child_block_header.clone();
            new_child_block_header.parent_microblock = resign_microblocks(&mut broken_microblocks, &privk);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks, true);
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

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &new_child_block_header, &broken_microblocks, true);
            assert!(res.is_none());
        }
        
        // nonempty string, but bad signature
        {
            let mut broken_microblocks = microblocks.clone();
            broken_microblocks[num_mblocks/2].header.signature = MessageSignature([1u8; 65]);

            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header, &broken_microblocks, true);
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
            
            let res = StacksChainState::validate_parent_microblock_stream(&block.header, &child_block_header, &forked_microblocks, true);
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
    
    #[test]
    fn stacks_db_staging_block_load_store_accept_attacheable() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept_attacheable");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block_1 = make_empty_coinbase_block(&privk);
        let mut block_2 = make_empty_coinbase_block(&privk);
        let mut block_3 = make_empty_coinbase_block(&privk);
        let mut block_4 = make_empty_coinbase_block(&privk);

        block_2.header.parent_block = block_1.block_hash();
        block_3.header.parent_block = block_2.block_hash();
        block_4.header.parent_block = block_3.block_hash();

        let burn_headers = vec![
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
            BurnchainHeaderHash([5u8; 32]),
        ];

        let parent_burn_headers = vec![
            BurnchainHeaderHash([1u8; 32]),
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
        ];

        let blocks = &[&block_1, &block_2, &block_3, &block_4];
       
        // store each block
        for ((block, burn_header), parent_burn_header) in blocks.iter().zip(&burn_headers).zip(&parent_burn_headers) {
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, burn_header, block, parent_burn_header, 1, 2);
            assert_block_staging_not_processed(&mut chainstate, burn_header, block);
        }

        // first block is attacheable, but all the rest are not
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &burn_headers[0], &block_1.block_hash()).unwrap().unwrap().attacheable, true);

        for (block, burn_header) in blocks[1..].iter().zip(&burn_headers[1..]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap().attacheable, false);
        }

        // process all blocks, and check that processing a parent makes the child attacheable
        for (i, (block, burn_header)) in blocks.iter().zip(&burn_headers).enumerate() {
            // child block is not attacheable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attacheable, false);
            }

            // block not stored yet
            assert_block_not_stored(&mut chainstate, burn_header, block);

            set_block_processed(&mut chainstate, burn_header, &block.block_hash(), true);

            // block is now stored
            assert_block_stored_not_staging(&mut chainstate, burn_header, block);

            // child block is attacheable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attacheable, true);
            }
        }
    }

    #[test]
    fn stacks_db_staging_block_load_store_accept_attacheable_reversed() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept_attacheable");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block_1 = make_empty_coinbase_block(&privk);
        let mut block_2 = make_empty_coinbase_block(&privk);
        let mut block_3 = make_empty_coinbase_block(&privk);
        let mut block_4 = make_empty_coinbase_block(&privk);

        block_2.header.parent_block = block_1.block_hash();
        block_3.header.parent_block = block_2.block_hash();
        block_4.header.parent_block = block_3.block_hash();

        let burn_headers = vec![
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
            BurnchainHeaderHash([5u8; 32]),
        ];

        let parent_burn_headers = vec![
            BurnchainHeaderHash([1u8; 32]),
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
        ];

        let blocks = &[&block_1, &block_2, &block_3, &block_4];
       
        // store each block, in reverse order!
        for ((block, burn_header), parent_burn_header) in blocks.iter().zip(&burn_headers).zip(&parent_burn_headers).rev() {
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, burn_header, block, parent_burn_header, 1, 2);
            assert_block_staging_not_processed(&mut chainstate, burn_header, block);
        }

        // first block is accepted, but all the rest are not
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &burn_headers[0], &block_1.block_hash()).unwrap().unwrap().attacheable, true);

        for (block, burn_header) in blocks[1..].iter().zip(&burn_headers[1..]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap().attacheable, false);
        }

        // process all blocks, and check that processing a parent makes the child attacheable
        for (i, (block, burn_header)) in blocks.iter().zip(&burn_headers).enumerate() {
            // child block is not attacheable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attacheable, false);
            }

            // block not stored yet
            assert_block_not_stored(&mut chainstate, burn_header, block);

            set_block_processed(&mut chainstate, burn_header, &block.block_hash(), true);

            // block is now stored
            assert_block_stored_not_staging(&mut chainstate, burn_header, block);

            // child block is attacheable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attacheable, true);
            }
        }
    }
    
    #[test]
    fn stacks_db_staging_block_load_store_accept_attacheable_fork() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept_attacheable");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block_1 = make_empty_coinbase_block(&privk);
        let mut block_2 = make_empty_coinbase_block(&privk);
        let mut block_3 = make_empty_coinbase_block(&privk);
        let mut block_4 = make_empty_coinbase_block(&privk);
        
        //            block_3 -- block_4
        // block_1 --/
        //           \
        //            block_2
        //
        // storing block_1 to staging renders block_2 and block_3 unattacheable
        // processing and accepting block_1 renders both block_2 and block_3 attacheable again

        block_2.header.parent_block = block_1.block_hash();
        block_3.header.parent_block = block_1.block_hash();
        block_4.header.parent_block = block_3.block_hash();

        let burn_headers = vec![
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
            BurnchainHeaderHash([5u8; 32]),
        ];

        let parent_burn_headers = vec![
            BurnchainHeaderHash([1u8; 32]),
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
        ];

        let blocks = &[&block_1, &block_2, &block_3, &block_4];
      
        // store each block in reverse order, except for block_1
        for ((block, burn_header), parent_burn_header) in blocks[1..].iter().zip(&burn_headers[1..]).zip(&parent_burn_headers[1..]).rev() {
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, burn_header, block, parent_burn_header, 1, 2);
            assert_block_staging_not_processed(&mut chainstate, burn_header, block);
        }

        // block 4 is not attacheable
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &burn_headers[3], &block_4.block_hash()).unwrap().unwrap().attacheable, false);

        // blocks 2 and 3 are attacheable
        for (block, burn_header) in [&block_2, &block_3].iter().zip(&[&burn_headers[1], &burn_headers[2]]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap().attacheable, true);
        }

        // store block 1
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &burn_headers[0], &block_1.block_hash()).unwrap().is_none());
        store_staging_block(&mut chainstate, &burn_headers[0], &block_1, &parent_burn_headers[0], 1, 2);
        assert_block_staging_not_processed(&mut chainstate, &burn_headers[0], &block_1);
        
        // first block is attacheable
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &burn_headers[0], &block_1.block_hash()).unwrap().unwrap().attacheable, true);

        // blocks 2 and 3 are no longer attacheable
        for (block, burn_header) in [&block_2, &block_3].iter().zip(&[&burn_headers[1], &burn_headers[2]]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap().attacheable, false);
        }

        // process block 1, and confirm that it makes block 2 and 3 attacheable
        assert_block_not_stored(&mut chainstate, &burn_headers[0], &block_1);
        set_block_processed(&mut chainstate, &burn_headers[0], &block_1.block_hash(), true);
        assert_block_stored_not_staging(&mut chainstate, &burn_headers[0], &block_1);
        
        // now block 2 and 3 are attacheable
        for (block, burn_header) in blocks[1..3].iter().zip(&burn_headers[1..3]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap().attacheable, true);
        }

        // and block 4 is still not
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &burn_headers[3], &block_4.block_hash()).unwrap().unwrap().attacheable, false);
    }

    #[test]
    fn stacks_db_staging_microblocks_multiple_descendents() {
        // multiple anchored blocks build off of different microblock parents 
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept_attacheable");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block_1 = make_empty_coinbase_block(&privk);
        let mut block_2 = make_empty_coinbase_block(&privk);
        let mut block_3 = make_empty_coinbase_block(&privk);
        let mut block_4 = make_empty_coinbase_block(&privk);
    
        let mut mblocks = make_sample_microblock_stream(&privk, &block_1.block_hash());
        mblocks.truncate(3);

        // 
        //
        // block_1 --> mblocks[0] --> mblocks[1] --> mblocks[2] --> block_4
        //             \              \              
        //              block_2        block_3
        //

        block_2.header.parent_block = block_1.block_hash();
        block_3.header.parent_block = block_1.block_hash();
        block_4.header.parent_block = block_1.block_hash();

        block_2.header.parent_microblock = mblocks[0].block_hash();
        block_2.header.parent_microblock_sequence = mblocks[0].header.sequence;
        
        block_3.header.parent_microblock = mblocks[1].block_hash();
        block_3.header.parent_microblock_sequence = mblocks[1].header.sequence;

        block_4.header.parent_microblock = mblocks[2].block_hash();
        block_4.header.parent_microblock_sequence = mblocks[2].header.sequence;
        
        let burn_headers = vec![
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([2u8; 32]),
        ];

        let parent_burn_headers = vec![
            BurnchainHeaderHash([1u8; 32]),
            BurnchainHeaderHash([1u8; 32]),
            BurnchainHeaderHash([1u8; 32]),
            BurnchainHeaderHash([1u8; 32]),
        ];

        let blocks = &[&block_1, &block_2, &block_3, &block_4];

        // store all microblocks to staging
        for mblock in mblocks.iter() {
            store_staging_microblock(&mut chainstate, &burn_headers[0], &blocks[0].block_hash(), mblock);
        }

        // store block 1 to staging
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &burn_headers[0], &blocks[0].block_hash()).unwrap().is_none());
        store_staging_block(&mut chainstate, &burn_headers[0], &blocks[0], &parent_burn_headers[0], 1, 2);
        assert_block_staging_not_processed(&mut chainstate, &burn_headers[0], &blocks[0]);

        set_block_processed(&mut chainstate, &burn_headers[0], &blocks[0].block_hash(), true);
        assert_block_stored_not_staging(&mut chainstate, &burn_headers[0], &blocks[0]);

        // process and store blocks 1 and N, as well as microblocks in-between
        let len = blocks.len();
        for i in 1..len {
            // this is what happens at the end of append_block()
            // store block to staging and process it
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &burn_headers[i], &blocks[i].block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, &burn_headers[i], &blocks[i], &parent_burn_headers[i], 1, 2);
            assert_block_staging_not_processed(&mut chainstate, &burn_headers[i], &blocks[i]);

            // set different parts of this stream as confirmed
            set_microblocks_confirmed(&mut chainstate, &burn_headers[0], &blocks[0].block_hash(), blocks[i].header.parent_microblock_sequence);

            set_block_processed(&mut chainstate, &burn_headers[i], &blocks[i].block_hash(), true);
            assert_block_stored_not_staging(&mut chainstate, &burn_headers[i], &blocks[i]);
            
            let mblocks_confirmed = StacksChainState::load_microblock_stream(&chainstate.blocks_path, &burn_headers[0], &mblocks[0].block_hash()).unwrap().unwrap();
            assert_eq!(mblocks_confirmed.as_slice(), &mblocks[0..i]);
        }
    }

    #[test]
    fn stacks_db_staging_blocks_orphaned() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept_attacheable");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block_1 = make_empty_coinbase_block(&privk);
        let block_2 = make_empty_coinbase_block(&privk);
        let block_3 = make_empty_coinbase_block(&privk);
        let block_4 = make_empty_coinbase_block(&privk);
        
        let mut blocks = vec![
            block_1,
            block_2,
            block_3,
            block_4
        ];

        let mut microblocks = vec![];

        for i in 0..blocks.len() {
            // make a sample microblock stream for block i
            let mut mblocks = make_sample_microblock_stream(&privk, &blocks[i].block_hash());
            mblocks.truncate(3);
        
            if i + 1 < blocks.len() {
                blocks[i+1].header.parent_block = blocks[i].block_hash();
                blocks[i+1].header.parent_microblock = mblocks[2].block_hash();
                blocks[i+1].header.parent_microblock_sequence = mblocks[2].header.sequence;
            }

            microblocks.push(mblocks);
        }

        let burn_headers = vec![
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
            BurnchainHeaderHash([5u8; 32]),
        ];

        let parent_burn_headers = vec![
            BurnchainHeaderHash([1u8; 32]),
            BurnchainHeaderHash([2u8; 32]),
            BurnchainHeaderHash([3u8; 32]),
            BurnchainHeaderHash([4u8; 32]),
        ];

        // store all microblocks to staging
        for ((block, burn_header), mblocks) in blocks.iter().zip(&burn_headers).zip(&microblocks) {
            for mblock in mblocks {
                store_staging_microblock(&mut chainstate, burn_header, &block.block_hash(), mblock);
                assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, burn_header, &block.block_hash(), &mblock.block_hash()).unwrap().is_some());
            }
        }

        // store blocks to staging
        for i in 0..blocks.len() {
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &burn_headers[i], &blocks[i].block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, &burn_headers[i], &blocks[i], &parent_burn_headers[i], 1, 2);
            assert_block_staging_not_processed(&mut chainstate, &burn_headers[i], &blocks[i]);
        }

        // reject block 1
        set_block_processed(&mut chainstate, &burn_headers[0], &blocks[0].block_hash(), false);

        // destroy all descendents
        for i in 0..blocks.len() {
            // confirm that block i is deleted, as are its microblocks 
            assert_block_stored_rejected(&mut chainstate, &burn_headers[i], &blocks[i]);

            // block i's microblocks should all be marked as processed, orphaned, and deleted
            for mblock in microblocks[i].iter() {
                assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &burn_headers[i], &blocks[i].block_hash(), &mblock.block_hash()).unwrap().is_none());
                assert!(StacksChainState::load_staging_microblock_bytes(&chainstate.blocks_db, &mblock.block_hash()).unwrap().is_none());
            }

            if i + 1 < blocks.len() {
                // block i+1 should be marked as an orphan, but its data should still be there
                assert!(StacksChainState::load_staging_block(&chainstate.blocks_db, &burn_headers[i+1], &blocks[i+1].block_hash()).unwrap().is_none());
                assert!(StacksChainState::load_staging_block_bytes(&chainstate.blocks_db, &blocks[i+1].block_hash()).unwrap().unwrap().len() > 0);
                
                for mblock in microblocks[i+1].iter() {
                    let staging_mblock = StacksChainState::load_staging_microblock(&chainstate.blocks_db, &burn_headers[i+1], &blocks[i+1].block_hash(), &mblock.block_hash()).unwrap().unwrap();
                    assert!(!staging_mblock.processed);
                    assert!(!staging_mblock.orphaned);
                    assert!(staging_mblock.block_data.len() > 0);
                }
            }

            // process next orphan block (should be block i+1)
            let res = process_next_orphaned_staging_block(&mut chainstate);

            if i < blocks.len() - 1 {
                // have more to do
                assert!(res);
            }
            else {
                // should be done
                assert!(!res);
            }
        }
    }

    #[test]
    fn stacks_db_drop_staging_microblocks() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept_attacheable");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
        
        let block = make_empty_coinbase_block(&privk);
        let mut mblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        mblocks.truncate(3);
        
        let burn_header = BurnchainHeaderHash([2u8; 32]);
        let parent_burn_header = BurnchainHeaderHash([1u8; 32]);

        // store microblocks to staging
        for mblock in mblocks.iter() {
            store_staging_microblock(&mut chainstate, &burn_header, &block.block_hash(), mblock);
            assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &burn_header, &block.block_hash(), &mblock.block_hash()).unwrap().is_some());
        }

        // store block to staging
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &burn_header, &block.block_hash()).unwrap().is_none());
        store_staging_block(&mut chainstate, &burn_header, &block, &parent_burn_header, 1, 2);
        assert_block_staging_not_processed(&mut chainstate, &burn_header, &block);

        // drop microblocks
        let len = mblocks.len();
        for i in 0..len {
            drop_staging_microblocks(&mut chainstate, &burn_header, &block.block_hash(), &mblocks[len - i - 1].block_hash());
            if i < len - 1 {
                assert_eq!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &burn_header, &block.block_hash(), u16::max_value()).unwrap().unwrap().as_slice(), &mblocks[0..len - i - 1]);
            }
            else {
                // last time we do this, there will be no more stream
                assert!(StacksChainState::load_staging_microblock_stream(&chainstate.blocks_db, &chainstate.blocks_path, &burn_header, &block.block_hash(), u16::max_value()).unwrap().is_none());
            }
        }
    }
   
    // TODO: test multiple anchored blocks confirming the same microblock stream (in the same
    // place, and different places, with/without orphans)
    // TODO: process_next_staging_block
}
