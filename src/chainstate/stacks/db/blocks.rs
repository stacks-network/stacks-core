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
use std::io::{Read, Write, Seek, SeekFrom};
use std::fmt;
use std::fs;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::convert::From;

use rusqlite::Connection;
use rusqlite::DatabaseName;

use core::*;

use chainstate::burn::operations::*;

use chainstate::stacks::Error;
use chainstate::stacks::db::accounts::MinerReward;
use chainstate::stacks::*;
use chainstate::stacks::db::*;
use chainstate::stacks::db::transactions::TransactionNonceMismatch;

use chainstate::burn::BlockSnapshot;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    DBConn,
    FromRow,
    FromColumn,
    query_row,
    query_rows,
    query_row_columns,
    query_count,
    query_int,
    tx_busy_handler,
};

use util::strings::StacksString;
use util::get_epoch_time_secs;
use util::hash::to_hex;
use util::db::u64_to_sql;

use util::retry::BoundReader;

use chainstate::burn::db::burndb::*;

use net::MAX_MESSAGE_LEN;
use net::BLOCKS_INV_DATA_MAX_BITLEN;
use net::BlocksInvData;
use net::Error as net_error;

use vm::types::{
    Value,
    AssetIdentifier,
    TupleData,
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier,
    TypeSignature
};

use vm::contexts::{
    AssetMap
};

use vm::ast::build_ast;
use vm::analysis::run_analysis;

use vm::clarity::{
    ClarityBlockConnection,
    ClarityConnection,
    ClarityInstance
};

pub use vm::analysis::errors::{CheckErrors, CheckError};

use vm::database::ClarityDatabase;

use vm::contracts::Contract;

use rand::RngCore;
use rand::thread_rng;

use rusqlite::{
    Error as sqlite_error,
    OptionalExtension
};

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
    pub burn_header_timestamp: u64,
    pub anchored_block_hash: BlockHeaderHash,
    pub parent_burn_header_hash: BurnchainHeaderHash,
    pub parent_anchored_block_hash: BlockHeaderHash,
    pub parent_microblock_hash: BlockHeaderHash,
    pub parent_microblock_seq: u16,
    pub microblock_pubkey_hash: Hash160,
    pub height: u64,
    pub processed: bool,
    pub attachable: bool,
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

#[derive(Debug)]
pub enum MemPoolRejection {
    SerializationFailure(net_error),
    DeserializationFailure(net_error),
    FailedToValidate(Error),
    FeeTooLow(u64, u64),
    BadNonces(TransactionNonceMismatch),
    NotEnoughFunds(u128, u128),
    NoSuchContract,
    NoSuchPublicFunction,
    BadFunctionArgument(CheckError),
    ContractAlreadyExists(QualifiedContractIdentifier),
    PoisonMicroblocksDoNotConflict,
    NoAnchorBlockWithPubkeyHash(Hash160),
    InvalidMicroblocks,
    BadAddressVersionByte,
    NoCoinbaseViaMempool,
    NoSuchChainTip(BurnchainHeaderHash,BlockHeaderHash),
    DBError(db_error),
    Other(String),
}

impl MemPoolRejection {
    pub fn into_json(self, txid: &Txid) -> serde_json::Value {
        use self::MemPoolRejection::*;
        let (reason_code, reason_data) = match self {
            SerializationFailure(e) => ("Serialization", 
                                        Some(json!({"message": e.to_string()}))),
            DeserializationFailure(e) => ("Deserialization",
                                          Some(json!({"message": e.to_string()}))),
            FailedToValidate(e) => ("SignatureValidation",
                                    Some(json!({"message": e.to_string()}))),
            FeeTooLow(actual, expected) => ("FeeTooLow", 
                                            Some(json!({
                                                "expected": expected,
                                                "actual": actual}))),
            BadNonces(TransactionNonceMismatch {
                expected, actual, principal, is_origin, .. }) =>
                ("BadNonce",
                 Some(json!({
                     "expected": expected,
                     "actual": actual,
                     "principal": principal.to_string(),
                     "is_origin": is_origin}))),
            NotEnoughFunds(expected, actual) => 
                ("NotEnoughFunds",
                 Some(json!({
                     "expected": format!("0x{}", to_hex(&expected.to_be_bytes())),
                     "actual": format!("0x{}", to_hex(&actual.to_be_bytes()))
                 }))),
            NoSuchContract => ("NoSuchContract", None),
            NoSuchPublicFunction => ("NoSuchPublicFunction", None),
            BadFunctionArgument(e) => ("BadFunctionArgument",
                                       Some(json!({"message": e.to_string()}))),
            ContractAlreadyExists(id) => ("ContractAlreadyExists",
                                          Some(json!({ "contract_identifier": id.to_string() }))),
            PoisonMicroblocksDoNotConflict => ("PoisonMicroblocksDoNotConflict", None),
            NoAnchorBlockWithPubkeyHash(_h) => ("PoisonMicroblockHasUnknownPubKeyHash", None),
            InvalidMicroblocks => ("PoisonMicroblockIsInvalid", None),
            BadAddressVersionByte => ("BadAddressVersionByte", None),
            NoCoinbaseViaMempool => ("NoCoinbaseViaMempool", None),
            // this should never happen via the RPC interface
            NoSuchChainTip(..) => ("ServerFailureNoSuchChainTip", None),
            DBError(e) => ("ServerFailureDatabase",
                                    Some(json!({"message": e.to_string()}))),                           
            Other(s) => ("ServerFailureOther", Some(json!({ "message": s })))
        };
        let mut result = json!({
            "txid": format!("{}", txid.to_hex()),
            "error": "transaction rejected",
            "reason": reason_code,
        });
        if let Some(reason_data) = reason_data {
            result.as_object_mut().unwrap()
                .insert("reason_data".to_string(), reason_data);
        }
        result
    }
}

impl From<db_error> for MemPoolRejection {
    fn from(e: db_error) -> MemPoolRejection {
        MemPoolRejection::DBError(e)
    }
}

// These constants are mempool acceptance heuristics, but
//  not part of the protocol consensus (i.e., a block
//  that includes a transaction that violates these won't
//  be invalid)
pub const MINIMUM_TX_FEE: u64 = 1;
pub const MINIMUM_TX_FEE_RATE_PER_BYTE: u64 = 1;

impl StagingBlock {
    pub fn is_first_mined(&self) -> bool {
        self.parent_anchored_block_hash == FIRST_STACKS_BLOCK_HASH
    }
}

impl FromRow<StagingMicroblock> for StagingMicroblock {
    fn from_row<'a>(row: &'a Row) -> Result<StagingMicroblock, db_error> {
        let anchored_block_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "anchored_block_hash")?;
        let burn_header_hash : BurnchainHeaderHash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let microblock_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "microblock_hash")?;
        let sequence : u16 = row.get("sequence");
        let processed_i64 : i64 = row.get("processed");
        let orphaned_i64 : i64 = row.get("orphaned");
        let block_data : Vec<u8> = vec![];

        let processed = processed_i64 != 0;
        let orphaned = orphaned_i64 != 0;

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
        let burn_header_timestamp = u64::from_column(row, "burn_header_timestamp")?;
        let parent_burn_header_hash: BurnchainHeaderHash = BurnchainHeaderHash::from_column(row, "parent_burn_header_hash")?;
        let parent_microblock_hash : BlockHeaderHash = BlockHeaderHash::from_column(row, "parent_microblock_hash")?;
        let parent_microblock_seq : u16 = row.get("parent_microblock_seq");
        let microblock_pubkey_hash : Hash160 = Hash160::from_column(row, "microblock_pubkey_hash")?;
        let height = u64::from_column(row, "height")?;
        let attachable_i64 : i64 = row.get("attachable");
        let processed_i64 : i64 = row.get("processed");
        let orphaned_i64 : i64 = row.get("orphaned");
        let commit_burn = u64::from_column(row, "commit_burn")?;
        let sortition_burn = u64::from_column(row, "sortition_burn")?;
        let block_data : Vec<u8> = vec![];

        let processed = processed_i64 != 0;
        let attachable = attachable_i64 != 0;
        let orphaned = orphaned_i64 == 0;

        Ok(StagingBlock {
            anchored_block_hash,
            parent_anchored_block_hash,
            burn_header_hash,
            burn_header_timestamp,
            parent_burn_header_hash,
            parent_microblock_hash,
            parent_microblock_seq,
            microblock_pubkey_hash,
            height,
            processed,
            attachable,
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
        let burn_amount = u64::from_column(row, "burn_amount")?;
        let vtxindex : u32 = row.get("vtxindex");

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
    #[cfg(test)]
    pub fn try_into_microblock(self) -> Result<StacksMicroblock, StagingMicroblock> {
        StacksMicroblock::consensus_deserialize(&mut &self.block_data[..]).map_err(|_e| self)
    }
}

impl BlockStreamData {
    pub fn new_block(index_block_hash: StacksBlockId) -> BlockStreamData {
        BlockStreamData {
            block_hash: index_block_hash,
            rowid: None,
            offset: 0,
            total_bytes: 0,
            is_microblock: false,
            seq: 0,
            in_staging: false
        }
    }

    pub fn new_microblock_confirmed(anchored_index_block_hash: StacksBlockId) -> BlockStreamData {
        BlockStreamData {
            block_hash: anchored_index_block_hash,
            rowid: None,
            offset: 0,
            total_bytes: 0,
            is_microblock: true,
            seq: 0,
            in_staging: false
        }
    }
    
    pub fn new_microblock_unconfirmed(anchored_index_block_hash: StacksBlockId, seq: u16) -> BlockStreamData {
        BlockStreamData {
            block_hash: anchored_index_block_hash,
            rowid: None,
            offset: 0,
            total_bytes: 0,
            is_microblock: true,
            seq: seq,
            in_staging: true
        }
    }

    pub fn stream_to<W: Write>(&mut self, chainstate: &mut StacksChainState, fd: &mut W, count: u64) -> Result<u64, Error> {
        if self.is_microblock {
            if self.in_staging {
                chainstate.stream_microblocks_unconfirmed(fd, self, count)
            }
            else {
                chainstate.stream_microblocks_confirmed(fd, self, count)
            }
        }
        else {
            chainstate.stream_block(fd, self, count)
        }
    }
}


const STACKS_BLOCK_INDEX_SQL : &'static [&'static str]= &[
    r#"
    -- Staging microblocks -- preprocessed microblocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_microblocks(anchored_block_hash TEXT NOT NULL,     -- this is the hash of the parent anchored block
                                     burn_header_hash TEXT NOT NULL,        -- this is the hash of the burn chain block that holds the parent anchored block's block-commit
                                     index_block_hash TEXT NOT NULL,        -- this is the anchored block's index hash
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
                                burn_header_timestamp INT NOT NULL,
                                parent_burn_header_hash TEXT NOT NULL,
                                parent_microblock_hash TEXT NOT NULL,
                                parent_microblock_seq INT NOT NULL,
                                microblock_pubkey_hash TEXT NOT NULL,
                                height INT NOT NULL,
                                attachable INT NOT NULL,           -- set to 1 if this block's parent is processed; 0 if not
                                orphaned INT NOT NULL,              -- set to 1 if this block can never be attached
                                processed INT NOT NULL,
                                commit_burn INT NOT NULL,
                                sortition_burn INT NOT NULL,
                                index_block_hash TEXT NOT NULL,        -- used internally; hash of burn header and block header
                                PRIMARY KEY(anchored_block_hash,burn_header_hash)
    );
    CREATE INDEX processed_stacks_blocks ON staging_blocks(processed,anchored_blcok_hash,burn_header_hash);
    CREATE INDEX orphaned_stacks_blocks ON staging_blocks(orphaned,anchored_block_hash,burn_header_hash);
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
        let tx = tx_begin_immediate(conn)?;
        
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
        conn.busy_handler(Some(tx_busy_handler)).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        if create_flag {
            // instantiate!
            StacksChainState::instantiate_blocks_db(&mut conn)?;
        }
        
        Ok(conn)
    }
    
    /// Get the path to a block in the chunk store
    pub fn get_index_block_path(blocks_dir: &str, index_block_hash: &StacksBlockId) -> Result<String, Error> {
        let block_hash_bytes = index_block_hash.as_bytes();
        let mut block_path = PathBuf::from(blocks_dir);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));
        block_path.push(format!("{}", index_block_hash));

        let blocks_path_str = block_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(blocks_path_str)
    }
    
    /// Get the path to a block in the chunk store, given the burn header hash and block hash.
    pub fn get_block_path(blocks_dir: &str, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, block_hash);
        StacksChainState::get_index_block_path(blocks_dir, &index_block_hash)
    }
    
    /// Make a directory tree for storing this block to the chunk store, and return the block's path
    fn make_block_dir(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, block_hash);
        let block_hash_bytes = index_block_hash.as_bytes();
        let mut block_path = PathBuf::from(blocks_dir);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));

        let _ = StacksChainState::mkdirs(&block_path)?;

        block_path.push(format!("{}", to_hex(block_hash_bytes)));
        let blocks_path_str = block_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(blocks_path_str)
    }

    pub fn atomic_file_store<F>(path: &String, delete_on_error: bool, mut writer: F) -> Result<(), Error> 
    where
        F: FnMut(&mut fs::File) -> Result<(), Error>
    {
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
                            error!("Failed to open {:?}: {:?}", &path_tmp, &e);
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        writer(&mut fd).map_err(|e| {
            if delete_on_error {
                // abort
                let _ = fs::remove_file(&path_tmp);
            }
            e
        })?;

        fd.sync_all().map_err(|e| Error::DBError(db_error::IOError(e)))?;

        // atomically put this file in place
        // TODO: this is atomic but not crash-consistent!  need to fsync the dir as well
        trace!("Rename {:?} to {:?}", &path_tmp, &path);
        fs::rename(&path_tmp, &path).map_err(|e| Error::DBError(db_error::IOError(e)))?;

        Ok(())
    }

    pub fn atomic_file_write(path: &String, bytes: &Vec<u8>) -> Result<(), Error> {
        StacksChainState::atomic_file_store(path, false, |ref mut fd| {
            fd.write_all(bytes).map_err(|e| Error::DBError(db_error::IOError(e)))
        })
    }

    pub fn get_file_size(path: &String) -> Result<u64, Error> {
        let sz = match fs::metadata(path) {
            Ok(md) => {
                md.len()
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    return Err(Error::DBError(db_error::NotFoundError));
                }
                else {
                    error!("Failed to stat {:?}: {:?}", &path, &e);
                    return Err(Error::DBError(db_error::IOError(e)));
                }
            }
        };
        Ok(sz)
    }

    pub fn consensus_load<T: StacksMessageCodec>(path: &String) -> Result<T, Error> {
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        let mut bound_reader = BoundReader::from_reader(&mut fd, MAX_MESSAGE_LEN as u64);
        let inst = T::consensus_deserialize(&mut bound_reader).map_err(Error::NetError)?;
        Ok(inst)
    }
    
    /// Do we have a stored a block in the chunk store?
    pub fn has_block_indexed(blocks_dir: &String, index_block_hash: &StacksBlockId) -> Result<bool, Error> {
        let block_path = StacksChainState::get_index_block_path(blocks_dir, index_block_hash)?;
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

    /// Have we processed and stored a particular block?
    pub fn has_stored_block(blocks_db: &DBConn, blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        let staging_status = StacksChainState::has_staging_block(blocks_db, burn_header_hash, block_hash)?;
        if staging_status {
            // not committed yet 
            test_debug!("Block {}/{} is staging", burn_header_hash, block_hash);
            return Ok(false);
        }

        // only accepted if we stored it
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, block_hash);
        StacksChainState::has_block_indexed(blocks_dir, &index_block_hash)
    }

    /// Have we committed to and stored a microblock stream in the chunk store?
    /// The given burn_header_hash is the burnchain header hash of the snapshot that selected this
    /// stream's anchored block.
    pub fn has_stored_microblocks(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, first_header: &BlockHeaderHash) -> Result<bool, Error> {
        if *first_header == EMPTY_MICROBLOCK_PARENT_HASH {
            // empty
            Ok(true)
        }
        else {
            // only accepted if we stored it
            let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, first_header);
            StacksChainState::has_block_indexed(blocks_dir, &index_block_hash)
        }
    }

    /// Store a block to the chunk store, named by its hash
    pub fn store_block(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock) -> Result<(), Error> {
        let block_hash = block.block_hash();
        let block_path = StacksChainState::make_block_dir(blocks_dir, burn_header_hash, &block_hash)?;
        
        test_debug!("Store {}/{} to {}", burn_header_hash, &block_hash, &block_path);
        StacksChainState::atomic_file_store(&block_path, true, |ref mut fd| {
            block.consensus_serialize(fd).map_err(Error::NetError)
        })
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
    pub fn list_blocks(blocks_conn: &DBConn) -> Result<Vec<(BurnchainHeaderHash, BlockHeaderHash)>, Error> {
        let list_block_sql = "SELECT * FROM staging_blocks".to_string();
        let mut blocks = query_rows::<StagingBlock, _>(blocks_conn, &list_block_sql, NO_PARAMS)
            .map_err(Error::DBError)?;

        Ok(blocks.drain(..).map(|b| (b.burn_header_hash, b.anchored_block_hash)).collect())
    }

    /// Get a list of all microblocks' hashes, and their anchored blocks' hashes
    #[cfg(test)]
    pub fn list_microblocks(blocks_conn: &DBConn, blocks_dir: &String) -> Result<Vec<(BurnchainHeaderHash, BlockHeaderHash, Vec<BlockHeaderHash>)>, Error> {
        let mut blocks = StacksChainState::list_blocks(blocks_conn)?;
        let mut ret = vec![];
        
        for (burn_hash, block_hash) in blocks.drain(..) {
            let list_microblock_sql = "SELECT * FROM staging_microblocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 ORDER BY sequence".to_string();
            let list_microblock_args: [&dyn ToSql; 2] = [&block_hash, &burn_hash];
            let mut microblocks = query_rows::<StagingMicroblock, _>(blocks_conn, &list_microblock_sql, &list_microblock_args)
                .map_err(Error::DBError)?;

            let microblock_hashes = microblocks.drain(..).map(|mb| mb.microblock_hash).collect();
            ret.push((burn_hash, block_hash, microblock_hashes));
        }
        
        Ok(ret)
    }

    /// Load up a blocks' bytes from the chunk store.
    /// Returns Ok(Some(bytes)) on success, if found.
    /// Returns Ok(none) if this block was found, but is known to be invalid
    /// Returns Err(...) on not found or I/O error
    pub fn load_block_bytes(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<Vec<u8>>, Error> {
        let block_path = StacksChainState::get_block_path(blocks_dir, burn_header_hash, block_hash)?;
        let sz = StacksChainState::get_file_size(&block_path)?;
        if sz == 0 {
            debug!("Zero-sized block {}", block_hash);
            return Ok(None);
        }
        if sz > MAX_MESSAGE_LEN as u64 {
            debug!("Invalid block {}: too big", block_hash);
            return Ok(None);
        }

        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(&block_path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        let mut ret = vec![];
        fd.read_to_end(&mut ret).map_err(|e| Error::DBError(db_error::IOError(e)))?;
        Ok(Some(ret))
    }

    /// Load up a block from the chunk store (staging or confirmed)
    /// Returns Ok(Some(block)) if found.
    /// Returns Ok(None) if this block was found, but is known to be invalid 
    /// Returns Err(...) on not found or I/O error
    pub fn load_block(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlock>, Error> {
        let block_path = StacksChainState::get_block_path(blocks_dir, burn_header_hash, block_hash)?;
        let sz = StacksChainState::get_file_size(&block_path)?;
        if sz == 0 {
            debug!("Zero-sized block {}", &block_hash);
            return Ok(None);
        }

        let block : StacksBlock = StacksChainState::consensus_load(&block_path)?;
        Ok(Some(block))
    }

    /// Load up an anchored block header from the chunk store.
    /// Returns Ok(Some(blockheader)) if found.
    /// Returns Ok(None) if this block was found, but is known to be invalid 
    /// Returns Err(...) on not found or I/O error
    pub fn load_block_header(blocks_dir: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlockHeader>, Error> {
        let block_path = StacksChainState::get_block_path(blocks_dir, burn_header_hash, block_hash)?;
        let sz = StacksChainState::get_file_size(&block_path)?;
        if sz == 0 {
            debug!("Zero-sized block {}", &block_hash);
            return Ok(None);
        }

        let block_header : StacksBlockHeader = StacksChainState::consensus_load(&block_path)?;
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
    ///
    /// The file stored is a serialized Vec<StacksMicroblock> 
    pub fn store_microblock_stream(blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, microblocks: &Vec<StacksMicroblock>) -> Result<(), Error> {
        if microblocks.len() == 0 {
            StacksChainState::store_empty_block(blocks_path, burn_header_hash, &EMPTY_MICROBLOCK_PARENT_HASH)?;
            return Ok(())
        }

        let block_hash = microblocks[0].block_hash();
        let block_path = StacksChainState::make_block_dir(blocks_path, burn_header_hash, &block_hash)?;

        StacksChainState::atomic_file_store(&block_path, false, |ref mut fd| {
            microblocks.consensus_serialize(fd).map_err(Error::NetError)
        })
    }

    /// Load a stream of microblocks from the chunk store, given its first block's hash.
    /// The given burn_header_hash is the burnchain header hash of the snapshot that selected this
    /// stream's anchored block.
    /// Returns Ok(Some(microblocks)) if the data was found
    /// Returns Ok(None) if the microblocks stream was previously processed and is known to be invalid
    /// Returns Err(...) for not found, I/O error, etc.
    fn load_microblock_stream(blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, microblock_head_hash: &BlockHeaderHash) -> Result<Option<Vec<StacksMicroblock>>, Error> {
        let block_path = StacksChainState::get_block_path(blocks_path, burn_header_hash, microblock_head_hash)?;
        let sz = StacksChainState::get_file_size(&block_path)?;
        if sz == 0 {
            // known-invalid
            debug!("Zero-sized microblock stream {}", &microblock_head_hash);
            return Ok(None);
        }

        let microblocks : Vec<StacksMicroblock> = StacksChainState::consensus_load(&block_path)?;
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
        let args = [&block_hash];
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
    
    fn load_staging_microblock_bytes(block_conn: &DBConn, block_hash: &BlockHeaderHash) -> Result<Option<Vec<u8>>, Error> {
        StacksChainState::inner_load_staging_block_bytes(block_conn, "staging_microblocks_data", block_hash)
    }

    fn has_blocks_with_microblock_pubkh(block_conn: &DBConn, pubkey_hash: &Hash160, minimum_block_height: i64) -> bool {
        let sql = "SELECT 1 FROM staging_blocks WHERE microblock_pubkey_hash = ?1 AND height >= ?2";
        let args : &[&dyn ToSql] = &[pubkey_hash, &minimum_block_height];
        block_conn.query_row(sql, args, |_r| ()).optional().expect("DB CORRUPTION: block header DB corrupted!").is_some()
    }

    /// Load up a preprocessed (queued) but still unprocessed block.
    pub fn load_staging_block(block_conn: &DBConn, blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StagingBlock>, Error> {
        let sql = "SELECT * FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND orphaned = 0 AND processed = 0".to_string();
        let args: &[&dyn ToSql] = &[&block_hash, &burn_header_hash];
        let mut rows = query_rows::<StagingBlock, _>(block_conn, &sql, args).map_err(Error::DBError)?;
        let len = rows.len();
        match len {
            0 => {
                Ok(None)
            }
            1 => {
                let mut staging_block = rows.pop().unwrap();

                // load up associated block data 
                staging_block.block_data = StacksChainState::load_block_bytes(blocks_path, burn_header_hash, block_hash)?.unwrap_or(vec![]);
                Ok(Some(staging_block))
            },
            _ => {
                // should be impossible since this is the primary key
                panic!("Got two or more block rows with same burn and block hashes");
            }
        }
    }

    #[cfg(test)]
    fn load_staging_block_data(block_conn: &DBConn, blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<StacksBlock>, Error> {
        match StacksChainState::load_staging_block(block_conn, blocks_path, burn_header_hash, block_hash)? {
            Some(staging_block) => {
                if staging_block.block_data.len() == 0 {
                    return Ok(None);
                }

                match StacksBlock::consensus_deserialize(&mut &staging_block.block_data[..]) {
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
        let args: &[&dyn ToSql] = &[&block_hash, &burn_header_hash];
        let rows = query_rows::<StagingUserBurnSupport, _>(block_conn, &sql, args).map_err(Error::DBError)?;
        Ok(rows)
    }
    
    /// Load up a queued block's queued pubkey hash
    fn load_staging_block_pubkey_hash(block_conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<Hash160>, Error> {
        let sql = format!("SELECT microblock_pubkey_hash FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND processed = 0 AND orphaned = 0");
        let args: &[&dyn ToSql] = &[&block_hash, &burn_header_hash];
        let rows = query_row_columns::<Hash160, _>(block_conn, &sql, args, "microblock_pubkey_hash").map_err(Error::DBError)?;
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

    /// Load up a preprocessed microblock (processed or not)
    pub fn load_staging_microblock(blocks_conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<Option<StagingMicroblock>, Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND microblock_hash = ?3 AND orphaned = 0".to_string();
        let args: &[&dyn ToSql] = &[&burn_header_hash, &block_hash, &microblock_hash];
        let mut rows = query_rows::<StagingMicroblock, _>(blocks_conn, &sql, args).map_err(Error::DBError)?;
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
                    return Err(Error::NetError(net_error::DeserializeError(format!("Microblock {} does not have block data", staging_microblocks[i].microblock_hash))));
                }

                let microblock = StacksMicroblock::consensus_deserialize(&mut &staging_microblocks[i].block_data[..])
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
                        return Err(Error::NetError(net_error::DeserializeError(format!("Microblock {} does not have block data", staging_microblocks[i].microblock_hash))));
                    }

                    let microblock = StacksMicroblock::consensus_deserialize(&mut &staging_microblocks[i].block_data[..])
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
        let args: &[&dyn ToSql] = &[&anchored_block_hash, &burn_header_hash, &last_seq];
        let mut staging_microblocks = query_rows::<StagingMicroblock, _>(blocks_conn, &sql, args)
            .map_err(Error::DBError)?;

        if staging_microblocks.len() == 0 {
            // haven't seen any microblocks that descend from this block yet
            test_debug!("No microblocks built on {}/{} up to {}", &burn_header_hash, &anchored_block_hash, last_seq);
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

    pub fn get_parent_burn_header_hash(burn_ic: &BurnDBConn, parent_block_hash: &BlockHeaderHash,
                                       my_burn_header_hash: &BurnchainHeaderHash) -> Result<Option<BurnchainHeaderHash>, Error> {
        let my_burn_block_snapshot = match BurnDB::get_block_snapshot(burn_ic, my_burn_header_hash)? {
            Some(x) => x,
            None => return Ok(None)
        };

        // find all blocks that we have that could be this block's parent
        let sql = "SELECT * FROM snapshots WHERE winning_stacks_block_hash = ?1";
        let possible_parent_snapshots = query_rows::<BlockSnapshot, _>(burn_ic, &sql, &[parent_block_hash])?;
        for possible_parent in possible_parent_snapshots.into_iter() {
            let burn_ancestor = BurnDB::get_block_snapshot_in_fork(
                burn_ic, possible_parent.block_height, &my_burn_block_snapshot.burn_header_hash)?;
            if let Some(ancestor) = burn_ancestor {
                assert_eq!(ancestor.burn_header_hash, possible_parent.burn_header_hash);

                // found!
                return Ok(Some(possible_parent.burn_header_hash));
            }
        }
        return Ok(None)
    }

    /// Get an anchored block's parent block header.
    /// Doesn't matter if it's staging or not.
    pub fn load_parent_block_header<'a>(burn_ic: &BurnDBConn<'a>, blocks_conn: &DBConn, blocks_path: &String, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash) -> Result<Option<(StacksBlockHeader, BurnchainHeaderHash)>, Error> {
        let header = match StacksChainState::load_block_header(blocks_path, burn_header_hash, anchored_block_hash)? {
            Some(hdr) => hdr,
            None => {
                return Ok(None);
            }
        };
        
        // find block snapshot for this block
        let block_snapshot = BurnDB::get_block_snapshot(burn_ic, burn_header_hash).map_err(Error::DBError)?
            .expect(&format!("DB CORRUPTION: block {} has no burn snapshot", anchored_block_hash));

        // find all blocks that we have that could be this block's parent
        let sql = "SELECT * FROM staging_blocks WHERE anchored_block_hash = ?1".to_string();
        let args : &[&dyn ToSql] = &[&header.parent_block];
        let mut rows = query_rows::<StagingBlock, _>(&blocks_conn, &sql, args).map_err(Error::DBError)?;
        if rows.len() == 0 {
            // don't have any parents yet
            return Ok(None);
        }

        // find the parent block whose burn block is also an ancestor of this block's burn block
        for row in rows.drain(..) {
            let parent_block_snapshot = BurnDB::get_block_snapshot(burn_ic, &row.burn_header_hash).map_err(Error::DBError)?
                .expect(&format!("DB CORRUPTION: block {}/{} is missing its burn block in the burn database", &row.anchored_block_hash, &row.burn_header_hash));

            // is it in the same burnchain fork as the given block?
            let burn_ancestor = BurnDB::get_block_snapshot_in_fork(burn_ic, parent_block_snapshot.block_height, &block_snapshot.burn_header_hash).map_err(Error::DBError)?;
            if let Some(ancestor) = burn_ancestor {
                assert_eq!(ancestor.burn_header_hash, row.burn_header_hash);
                
                // found!
                let ret = match StacksChainState::load_block_header(blocks_path, &ancestor.burn_header_hash, &row.anchored_block_hash)? {
                    Some(header) => Ok(Some((header, ancestor.burn_header_hash))),
                    None => Ok(None)
                };
                return ret;
            }
        }

        Ok(None)
    }

    /// Store a preprocessed block, queuing it up for subsequent processing.
    /// The caller should at least verify that the block is attached to some fork in the burn
    /// chain.
    fn store_staging_block<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, burn_header_timestamp: u64, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash, commit_burn: u64, sortition_burn: u64) -> Result<(), Error> {
        debug!("Store anchored block {}/{}, parent in {}", burn_hash, block.block_hash(), parent_burn_header_hash);
        assert!(commit_burn < i64::max_value() as u64);
        assert!(sortition_burn < i64::max_value() as u64);
        assert!(burn_header_timestamp < i64::max_value() as u64);

        let block_hash = block.block_hash();
        let index_block_hash = StacksBlockHeader::make_index_block_hash(&burn_hash, &block_hash);

        let attachable = {
            // if this block has an unprocessed staging parent, then it's not attachable until its parent is.
            let has_parent_sql = "SELECT anchored_block_hash FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2 AND processed = 0 AND orphaned = 0 LIMIT 1".to_string();
            let has_parent_args: &[&dyn ToSql] = &[&block.header.parent_block, &parent_burn_header_hash];
            let rows = query_row_columns::<BlockHeaderHash, _>(&tx, &has_parent_sql, has_parent_args, "anchored_block_hash").map_err(Error::DBError)?;
            if rows.len() > 0 {
                // still have unprocessed parent -- this block is not attachable 
                debug!("Store non-attachable anchored block {}/{}", burn_hash, block.block_hash());
                0
            }
            else {
                // no unprocessed parents -- this block is potentially attachable
                1
            }
        };

        // store block metadata
        let sql = "INSERT OR REPLACE INTO staging_blocks \
                   (anchored_block_hash, \
                   parent_anchored_block_hash, \
                   burn_header_hash, \
                   burn_header_timestamp, \
                   parent_burn_header_hash, \
                   parent_microblock_hash, \
                   parent_microblock_seq, \
                   microblock_pubkey_hash, \
                   height, \
                   attachable, \
                   processed, \
                   orphaned, \
                   commit_burn, \
                   sortition_burn, \
                   index_block_hash) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)";
        let args: &[&dyn ToSql] = &[
            &block_hash,
            &block.header.parent_block,
            &burn_hash,
            &u64_to_sql(burn_header_timestamp)?,
            &parent_burn_header_hash,
            &block.header.parent_microblock,
            &block.header.parent_microblock_sequence,
            &block.header.microblock_pubkey_hash,
            &u64_to_sql(block.header.total_work.work)?,
            &attachable,
            &0,
            &0,
            &u64_to_sql(commit_burn)?,
            &u64_to_sql(sortition_burn)?,
            &index_block_hash];

        tx.execute(&sql, args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        StacksChainState::store_block(tx.get_blocks_path(), burn_hash, block)?;

        // mark all children of this new block as unattachable -- need to attach this block first!
        // this should be done across all burnchains.
        let children_sql = "UPDATE staging_blocks SET attachable = 0 WHERE parent_anchored_block_hash = ?1";
        let children_args = [&block_hash];

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
        test_debug!("Store staging microblock {}/{}-{}", burn_header_hash, anchored_block_hash, microblock.block_hash());

        let mut microblock_bytes = vec![];
        microblock.consensus_serialize(&mut microblock_bytes).map_err(Error::NetError)?;

        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, anchored_block_hash);

        // store microblock metadata
        let sql = "INSERT OR REPLACE INTO staging_microblocks (anchored_block_hash, burn_header_hash, index_block_hash, microblock_hash, sequence, processed, orphaned) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
        let args: &[&dyn ToSql] = &[&anchored_block_hash, &burn_header_hash, &index_block_hash, &microblock.block_hash(), &microblock.header.sequence, &0, &0];

        tx.execute(&sql, args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        // store microblock bytes
        let block_sql = "INSERT OR REPLACE INTO staging_microblocks_data \
                         (block_hash, block_data)
                         VALUES (?1, ?2)";
        let block_args: &[&dyn ToSql] = &[&microblock.block_hash(), &microblock_bytes];

        tx.execute(&block_sql, block_args)
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
            let args: &[&dyn ToSql] = &[&burn_hash, &block_hash, &burn_support.address.to_string(), &u64_to_sql(burn_support.burn_fee)?, &burn_support.vtxindex];

            tx.execute(&sql, args)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }

        Ok(())
    }

    /// Read all the i64 values from a query (possibly none).
    fn read_i64s(conn: &DBConn, query: &str, args: &[&dyn ToSql]) -> Result<Vec<i64>, Error> {
        let mut stmt = conn.prepare(query).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        let mut rows = stmt.query(args).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // gather 
        let mut row_data : Vec<i64> = vec![];
        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let val_opt : Option<i64> = row.get(0);
                    match val_opt {
                        Some(val) => {
                            row_data.push(val);
                        },
                        None => {}
                    }
                },
                Err(e) => {
                    return Err(Error::DBError(db_error::SqliteError(e)));
                }
            };
        }
        Ok(row_data)
    }

    /// Do we have a block queued up, and if so, is it being processed?.
    /// Return Some(processed) if the block is queued up -- true if processed, false if not
    /// Return None if the block is not queued up
    fn get_staging_block_status(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<bool>, Error> {
        StacksChainState::read_i64s(blocks_conn, "SELECT processed FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2", &[block_hash, burn_hash])
            .and_then(|processed| {
                if processed.len() == 0 {
                    Ok(None)
                }
                else if processed.len() == 1 {
                    Ok(Some(processed[0] != 0))
                }
                else {
                    Err(Error::DBError(db_error::Overflow))
                }
            })
    }
    
    /// Is a block orphaned?
    pub fn is_block_orphaned(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        StacksChainState::read_i64s(blocks_conn, "SELECT orphaned FROM staging_blocks WHERE anchored_block_hash = ?1 AND burn_header_hash = ?2", &[block_hash, burn_hash])
            .and_then(|orphaned| {
                if orphaned.len() == 0 {
                    Ok(false)
                }
                else if orphaned.len() == 1 {
                    Ok(orphaned[0] != 0)
                }
                else {
                    Err(Error::DBError(db_error::Overflow))
                }
            })
    }

    /// Do we have a microblock queued up, and if so, is it being processed?
    /// Return Some(processed) if the microblock is queued up
    /// Return None if the microblock is not queued up
    pub fn get_staging_microblock_status(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<Option<bool>, Error> {
        StacksChainState::read_i64s(blocks_conn, "SELECT processed FROM staging_microblocks WHERE anchored_block_hash = ?1 AND microblock_hash = ?2 AND burn_header_hash = ?3", &[block_hash, microblock_hash, burn_hash])
            .and_then(|processed| {
                if processed.len() == 0 {
                    Ok(None)
                }
                else if processed.len() == 1 {
                    Ok(Some(processed[0] != 0))
                }
                else {
                    Err(Error::DBError(db_error::Overflow))
                }
            })
    }
    
    /// Is a microblock orphaned?
    pub fn is_microblock_orphaned(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<bool, Error> {
        StacksChainState::read_i64s(blocks_conn, "SELECT orphaned FROM staging_microblocks WHERE anchored_block_hash = ?1 AND microblock_hash = ?2 AND burn_header_hash = ?3", &[block_hash, microblock_hash, burn_hash])
            .and_then(|orphaned| {
                if orphaned.len() == 0 {
                    Ok(false)
                }
                else if orphaned.len() == 1 {
                    Ok(orphaned[0] != 0)
                }
                else {
                    Err(Error::DBError(db_error::Overflow))
                }
            })
    }

    /// What's the first microblock hash in a stream?
    pub fn get_microblock_stream_head_hash(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, anchored_header_hash: &BlockHeaderHash) -> Result<Option<BlockHeaderHash>, Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND sequence = 0 AND orphaned = 0".to_string();
        let args: &[&dyn ToSql] = &[&burn_hash, &anchored_header_hash];
        let staging_microblocks = query_rows::<StagingMicroblock, _>(blocks_conn, &sql, args).map_err(Error::DBError)?;
        match staging_microblocks.len() {
            0 => Ok(None),
            1 => Ok(Some(staging_microblocks[0].microblock_hash.clone())),
            _ => Ok(None)       // leader equivocated
        }
    }

    /// Generate a blocks inventory message, given the output of
    /// BurnDB::get_stacks_header_hashes().  Note that header_hashes must be less than or equal to
    /// BLOCKS_INV_DATA_MAX_BITLEN in order to generate a valid BlocksInvData payload.
    pub fn get_blocks_inventory(&mut self, header_hashes: &[(BurnchainHeaderHash, Option<BlockHeaderHash>)]) -> Result<BlocksInvData, Error> {
        if header_hashes.len() > (BLOCKS_INV_DATA_MAX_BITLEN as usize) {
            return Err(Error::NetError(net_error::OverflowError("Resulting block inventory would be too big".to_string())));
        }

        let mut block_bits = vec![];
        let mut microblock_bits = vec![];

        for (burn_header_hash, stacks_header_hash_opt) in header_hashes.iter() {
            match stacks_header_hash_opt {
                None => {
                    test_debug!("Do not have any block in burn block {} in {}", &burn_header_hash, &self.blocks_path);
                    block_bits.push(false);
                    microblock_bits.push(false);
                },
                Some(ref stacks_header_hash) => {
                    let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, stacks_header_hash);
                    
                    // check block
                    if StacksChainState::has_block_indexed(&self.blocks_path, &index_block_hash)? {
                        // it had better _not_ be empty (empty indicates invalid)
                        let block_path = StacksChainState::get_index_block_path(&self.blocks_path, &index_block_hash)?;
                        let sz = StacksChainState::get_file_size(&block_path)?;
                        if sz > 0 {
                            test_debug!("Have anchored block {} in {}", &index_block_hash, &self.blocks_path);
                            block_bits.push(true);
                        }
                        else {
                            test_debug!("Anchored block {} is orphaned; not reporting in inventory", &index_block_hash);
                            block_bits.push(false);
                        }
                    }
                    else {
                        test_debug!("Do not have {} in {}", &index_block_hash, &self.blocks_path);
                        block_bits.push(false);
                        microblock_bits.push(false);
                        continue;
                    }

                    // check confirmed microblocks (only report them if we have the anchored block
                    // that produced them).
                    match self.get_confirmed_microblock_index_hash(&index_block_hash)? {
                        Some(microblock_index_hash) => {
                            if self.has_confirmed_microblocks_indexed(&microblock_index_hash)? {
                                let mblocks_path = StacksChainState::get_index_block_path(&self.blocks_path, &microblock_index_hash)?;
                                let sz = StacksChainState::get_file_size(&mblocks_path)?;
                                if sz > 0 {
                                    // state was not orphaned
                                    let num_mblocks = self.get_microblock_stream_length(&index_block_hash)?;
                                    if num_mblocks > 0 {
                                        // only report this stream as "present" if there are any blocks
                                        // in this stream.
                                        test_debug!("Have confirmed microblocks {} in {}", &microblock_index_hash, &self.blocks_path);
                                        microblock_bits.push(true);
                                    }
                                    else {
                                        test_debug!("Do not have confirmed microblocks {} in {} -- zero-length stream", &microblock_index_hash, &self.blocks_path);
                                        microblock_bits.push(false);
                                    }
                                }
                                else {
                                    // state was orphaned
                                    test_debug!("Microblock stream {} is orphaned; not reporting in inventory", &microblock_index_hash);
                                    microblock_bits.push(false);
                                }
                            }
                            else {
                                test_debug!("Do not have confirmed microblocks {} in {} -- file not found", &microblock_index_hash, &self.blocks_path);
                                microblock_bits.push(false);
                            }
                        },
                        None => {
                            test_debug!("Do not have confirmed microblocks off of anchored block {} -- no index hash", &index_block_hash);
                            microblock_bits.push(false);
                        }
                    }
                }
            }
        }

        assert_eq!(block_bits.len(), microblock_bits.len());

        let block_bitvec = BlocksInvData::compress_bools(&block_bits);
        let microblocks_bitvec = BlocksInvData::compress_bools(&microblock_bits);

        Ok(BlocksInvData {
            bitlen: block_bits.len() as u16,
            block_bitvec: block_bitvec,
            microblocks_bitvec: microblocks_bitvec
        })
    }

    /// Do we have a staging block?  Return true if the block is present and marked as unprocessed;
    /// false otherwise
    pub fn has_staging_block(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<bool, Error> {
        match StacksChainState::get_staging_block_status(blocks_conn, burn_hash, block_hash)? {
            Some(processed) => Ok(!processed),
            None => Ok(false)
        }
    }

    /// Do we have a staging microblock?  Return true if the microblock is present and marked as
    /// unprocesed; false otherwise
    pub fn has_staging_microblock(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<bool, Error> {
        match StacksChainState::get_staging_microblock_status(blocks_conn, burn_hash, block_hash, microblock_hash)? {
            Some(processed) => Ok(!processed),
            None => Ok(false)
        }
    }
    
    /// Do we have a confirmed, processed microblock? Return true if the microblock is present and marked as processed; false otherwise
    pub fn has_confirmed_microblock(blocks_conn: &DBConn, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, microblock_hash: &BlockHeaderHash) -> Result<bool, Error> {
        match StacksChainState::get_staging_microblock_status(blocks_conn, burn_hash, block_hash, microblock_hash)? {
            Some(processed) => Ok(processed),
            None => Ok(false)
        }
    }

    /// Delete a microblock's data from staging 
    fn delete_staging_microblock_data<'a>(tx: &mut BlocksDBTx<'a>, microblock_hash: &BlockHeaderHash) -> Result<(), Error> {
        // clear out the block data from staging
        let clear_sql = "DELETE FROM staging_microblocks_data WHERE block_hash = ?1".to_string();
        let clear_args = [&microblock_hash];

        tx.execute(&clear_sql, &clear_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    /// Mark an anchored block as orphaned and both orphan and delete its descendent microblock data.
    /// The blocks database will eventually delete all orphaned data.
    fn delete_orphaned_epoch_data<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        // This block is orphaned
        let update_block_sql = "UPDATE staging_blocks SET orphaned = 1, processed = 1, attachable = 0 WHERE anchored_block_hash = ?1".to_string();
        let update_block_args = [&anchored_block_hash];

        // All descendents of this processed block are never attachable.
        // Indicate this by marking all children as orphaned (but not procesed), across all burnchain forks.
        let update_children_sql = "UPDATE staging_blocks SET orphaned = 1, processed = 0, attachable = 0 WHERE parent_anchored_block_hash = ?1".to_string();
        let update_children_args = [&anchored_block_hash];
        
        // find all orphaned microblocks, and delete the block data
        let find_orphaned_microblocks_sql = "SELECT microblock_hash FROM staging_microblocks WHERE anchored_block_hash = ?1".to_string();
        let find_orphaned_microblocks_args = [&anchored_block_hash];
        let orphaned_microblock_hashes = query_row_columns::<BlockHeaderHash, _>(tx, &find_orphaned_microblocks_sql, &find_orphaned_microblocks_args, "microblock_hash")
            .map_err(Error::DBError)?;
        
        // drop microblocks (this processes them)
        let update_microblock_children_sql = "UPDATE staging_microblocks SET orphaned = 1, processed = 1 WHERE anchored_block_hash = ?1".to_string();
        let update_microblock_children_args = [&anchored_block_hash];

        tx.execute(&update_block_sql, &update_block_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        tx.execute(&update_children_sql, &update_children_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        tx.execute(&update_microblock_children_sql, &update_microblock_children_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        for mblock_hash in orphaned_microblock_hashes {
            StacksChainState::delete_staging_microblock_data(tx, &mblock_hash)?;
        }
        
        // mark the block as empty if we haven't already
        let block_path = StacksChainState::get_block_path(tx.get_blocks_path(), burn_hash, anchored_block_hash)?;
        match fs::metadata(&block_path) {
            Ok(_) => {
                StacksChainState::free_block(tx.get_blocks_path(), burn_hash, anchored_block_hash);
            },
            Err(_) => {
                StacksChainState::atomic_file_write(&block_path, &vec![])?;
            }
        }

        Ok(())
    }

    /// Clear out a staging block -- mark it as processed.
    /// Mark its children as attachable.
    /// Idempotent.
    fn set_block_processed<'a, 'b>(tx: &mut BlocksDBTx<'a>, mut burn_tx_opt: Option<&mut BurnDBTx<'b>>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, accept: bool) -> Result<(), Error> {
        let sql = "SELECT * FROM staging_blocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND orphaned = 0".to_string();
        let args: &[&dyn ToSql] = &[&burn_hash, &anchored_block_hash];
      
        let has_stored_block = StacksChainState::has_stored_block(tx, tx.get_blocks_path(), burn_hash, anchored_block_hash)?;
        let _block_path = StacksChainState::make_block_dir(tx.get_blocks_path(), burn_hash, anchored_block_hash)?;

        let rows = query_rows::<StagingBlock, _>(tx, &sql, args).map_err(Error::DBError)?;
        let block = match rows.len() {
            0 => {
                // not an error if this block was already orphaned
                let orphan_sql = "SELECT * FROM staging_blocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND orphaned = 1".to_string();
                let orphan_args: &[&dyn ToSql] = &[&burn_hash, &anchored_block_hash];
                let orphan_rows = query_rows::<StagingBlock, _>(tx, &orphan_sql, orphan_args).map_err(Error::DBError)?;
                if orphan_rows.len() == 1 {
                    return Ok(());
                }
                else {
                    test_debug!("No such block at {}/{}", burn_hash, anchored_block_hash);
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
                    debug!("Accept block {}/{} as {}", burn_hash, anchored_block_hash, StacksBlockHeader::make_index_block_hash(&burn_hash, &anchored_block_hash));
                }
                else {
                    debug!("Reject block {}/{}", burn_hash, anchored_block_hash);
                }
            }
            else {
                debug!("Already stored block {}/{} ({})", burn_hash, anchored_block_hash, StacksBlockHeader::make_index_block_hash(&burn_hash, &anchored_block_hash));
            }
        }
        else {
            debug!("Already processed block {}/{} ({})", burn_hash, anchored_block_hash, StacksBlockHeader::make_index_block_hash(&burn_hash, &anchored_block_hash));
        }

        let update_sql = "UPDATE staging_blocks SET processed = 1 WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2".to_string();
        let update_args: &[&dyn ToSql] = &[&burn_hash, &anchored_block_hash];

        tx.execute(&update_sql, update_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
       
        if accept {
            // if we accepted this block, then children of this processed block are now attachable.
            // Applies across all burnchain forks
            let update_children_sql = "UPDATE staging_blocks SET attachable = 1 WHERE parent_anchored_block_hash = ?1".to_string();
            let update_children_args = [&anchored_block_hash];

            tx.execute(&update_children_sql, &update_children_args)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

            // mark this block as processed in the burn db too
            match burn_tx_opt {
                Some(ref mut burn_tx) => {
                    BurnDB::set_stacks_block_accepted(burn_tx, burn_hash, &block.parent_anchored_block_hash, &block.anchored_block_hash, block.height)
                        .map_err(Error::DBError)?;
                }
                None => {
                    if !cfg!(test) {
                        // not allowed in production
                        panic!("No burn DB transaction given to block processor");
                    }
                }
            }
        }
        else {
            // Otherwise, all descendents of this processed block are never attachable.
            // Mark this block's children as orphans, blow away its data, and blow away its descendent microblocks.
            test_debug!("Orphan block {}/{}", burn_hash, anchored_block_hash);
            StacksChainState::delete_orphaned_epoch_data(tx, burn_hash, anchored_block_hash)?;
        }

        Ok(())
    }

    /// Drop a trail of staging microblocks.  Mark them as orphaned and delete their data.
    /// Also, orphan any anchored children blocks that build off of the now-orphaned microblocks.
    fn drop_staging_microblocks<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, invalid_block_hash: &BlockHeaderHash) -> Result<(), Error> {
        // find offending sequence
        let seq_sql = "SELECT sequence FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND microblock_hash = ?3 AND processed = 0 AND orphaned = 0".to_string();
        let seq_args: &[&dyn ToSql] = &[&burn_hash, &anchored_block_hash, &invalid_block_hash];
        let seq = match query_int::<_>(tx, &seq_sql, seq_args) {
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

        test_debug!("Drop staging microblocks {}/{} up to {} ({})", burn_hash, anchored_block_hash, invalid_block_hash, seq);

        // drop staging children at and beyond the invalid block
        let update_microblock_children_sql = "UPDATE staging_microblocks SET orphaned = 1, processed = 1 WHERE anchored_block_hash = ?1 AND sequence >= ?2".to_string();
        let update_microblock_children_args: &[&dyn ToSql] = &[&anchored_block_hash, &seq];

        tx.execute(&update_microblock_children_sql, update_microblock_children_args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // find all orphaned microblocks hashes, and delete the block data
        let find_orphaned_microblocks_sql = "SELECT microblock_hash FROM staging_microblocks WHERE anchored_block_hash = ?1 AND sequence >= ?2".to_string();
        let find_orphaned_microblocks_args: &[&dyn ToSql] = &[&anchored_block_hash, &seq];
        let orphaned_microblock_hashes = query_row_columns::<BlockHeaderHash, _>(tx, &find_orphaned_microblocks_sql, find_orphaned_microblocks_args, "microblock_hash")
            .map_err(Error::DBError)?;
            
        for mblock_hash in orphaned_microblock_hashes.iter() {
            StacksChainState::delete_staging_microblock_data(tx, &mblock_hash)?;
        }

        for mblock_hash in orphaned_microblock_hashes.iter() {
            // orphan any staging blocks that build on the now-invalid microblocks
            let update_block_children_sql = "UPDATE staging_blocks SET orphaned = 1, processed = 0, attachable = 0 WHERE parent_microblock_hash = ?1".to_string();
            let update_block_children_args = [&mblock_hash];
            
            tx.execute(&update_block_children_sql, &update_block_children_args)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

            // mark the block as empty if we haven't already
            let block_path = StacksChainState::get_block_path(tx.get_blocks_path(), burn_hash, anchored_block_hash)?;
            match fs::metadata(&block_path) {
                Ok(_) => {
                    StacksChainState::free_block(tx.get_blocks_path(), burn_hash, anchored_block_hash);
                },
                Err(_) => {
                    StacksChainState::atomic_file_write(&block_path, &vec![])?;
                }
            }
        }

        Ok(())
    }

    /// Mark a range of a stream of microblocks as confirmed -- move them to the chunk store if
    /// they're not there already.
    ///
    /// All the corresponding blocks must have been validated and proven contiguous.
    fn set_microblocks_confirmed<'a>(tx: &mut BlocksDBTx<'a>, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, last_seq: u16) -> Result<(), Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND sequence <= ?3 AND orphaned = 0 ORDER BY sequence ASC".to_string();
        let args: &[&dyn ToSql] = &[&burn_hash, &anchored_block_hash, &last_seq];
        let mut staging_microblocks = query_rows::<StagingMicroblock, _>(tx, &sql, args).map_err(Error::DBError)?;

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

        debug!("Accept microblock stream {}/{}({}) as {}", StacksBlockHeader::make_index_block_hash(burn_hash, anchored_block_hash), microblocks[0].block_hash(), last_seq, StacksBlockHeader::make_index_block_hash(burn_hash, &microblocks[0].block_hash()));
        StacksChainState::store_microblock_stream(tx.get_blocks_path(), burn_hash, &microblocks)?;

        // clear out of staging
        let sql = "UPDATE staging_microblocks SET processed = 1 WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2 AND sequence <= ?3".to_string();
        let args: &[&dyn ToSql] = &[&burn_hash, &anchored_block_hash, &last_seq];

        tx.execute(&sql, args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        for i in 0..microblocks.len() {
            StacksChainState::delete_staging_microblock_data(tx, &microblocks[i].block_hash())?;
        }

        Ok(())
    }
   
    /// Is a particular microblock in staging, given its _indexed anchored block hash_?
    pub fn has_staging_microblock_indexed(&mut self, index_anchor_block_hash: &StacksBlockId, seq: u16) -> Result<bool, Error> {
        StacksChainState::read_i64s(&self.blocks_db, "SELECT processed FROM staging_microblocks WHERE index_block_hash = ?1 AND sequence = ?2", &[&index_anchor_block_hash, &seq])
            .and_then(|processed| {
                if processed.len() == 0 {
                    Ok(false)
                }
                else if processed.len() == 1 {
                    Ok(processed[0] == 0)
                }
                else {
                    Err(Error::DBError(db_error::Overflow))
                }
            })
    }

    /// Do we have a particular microblock stream given it _indexed head microblock hash_?
    pub fn has_confirmed_microblocks_indexed(&mut self, index_microblock_hash: &StacksBlockId) -> Result<bool, Error> {
        StacksChainState::has_block_indexed(&self.blocks_path, index_microblock_hash)
    }

    /// How many microblocks are in a given stream?
    pub fn get_microblock_stream_length(&self, index_anchor_block_hash: &StacksBlockId) -> Result<u64, Error> {
        let sql = "SELECT COUNT(microblock_hash) FROM staging_microblocks WHERE index_block_hash = ?1 AND processed = 1 AND orphaned = 0".to_string();
        let args = [&index_anchor_block_hash as &dyn ToSql];
        let cnt = query_count(&self.blocks_db, &sql, &args).map_err(Error::DBError)?;
        Ok(cnt as u64)
    }

    /// Given an index anchor block hash, get the index microblock hash for a confirmed microblock stream.
    pub fn get_confirmed_microblock_index_hash(&mut self, index_anchor_block_hash: &StacksBlockId) -> Result<Option<StacksBlockId>, Error> {
        let sql = "SELECT microblock_hash,burn_header_hash FROM staging_microblocks WHERE index_block_hash = ?1 AND sequence = 0 AND processed = 1 AND orphaned = 0 LIMIT 1";
        let args = [&index_anchor_block_hash as &dyn ToSql];

        let row_data_opt = self.blocks_db.query_row(sql, &args,
            |row| {
                let microblock_hash = BlockHeaderHash::from_column(row, "microblock_hash")?;
                let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
                Ok((microblock_hash, burn_header_hash))
            })
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        match row_data_opt {
            Some(Ok((microblock_hash, burn_header_hash))) => {
                let index_microblock_hash = StacksBlockHeader::make_index_block_hash(&burn_header_hash, &microblock_hash);
                trace!("Index microblock hash of anchored block {} is {}", index_anchor_block_hash, &index_microblock_hash);
                Ok(Some(index_microblock_hash))
            },
            Some(Err(e)) => {
                Err(e)
            },
            None => {
                // doesn't exist
                trace!("No confirmed microblocks off of anchored block {}", index_anchor_block_hash);
                Ok(None)
            }
        }
    }
    
    /// Do we have any unconfirmed microblocks at or after the given sequence number?
    pub fn has_any_staging_microblock_indexed(&mut self, index_block_hash: &StacksBlockId, min_seq: u16) -> Result<bool, Error> {
        StacksChainState::read_i64s(&self.blocks_db, "SELECT processed FROM staging_microblocks WHERE index_block_hash = ?1 AND sequence >= ?2 LIMIT 1", &[&index_block_hash, &min_seq])
            .and_then(|processed| {
                if processed.len() == 0 {
                    Ok(false)
                }
                else if processed.len() == 1 {
                    Ok(processed[0] == 0)
                }
                else {
                    Err(Error::DBError(db_error::Overflow))
                }
            })
    }
    
    /// Do we have any microblock available to serve in any capacity, given its anchored block's
    /// index block hash?
    #[cfg(test)]
    fn has_microblocks_indexed(&mut self, index_block_hash: &StacksBlockId) -> Result<bool, Error> {
        StacksChainState::read_i64s(&self.blocks_db, "SELECT processed FROM staging_microblocks WHERE index_block_hash = ?1", &[&index_block_hash])
            .and_then(|processed| {
                Ok(processed.len() > 0)
            })
    }

    /// Given an index block hash, get the burn header hash and block hash
    pub fn get_block_header_hashes(&self, index_block_hash: &StacksBlockId) -> Result<Option<(BurnchainHeaderHash, BlockHeaderHash)>, Error> {
        let sql = "SELECT burn_header_hash,anchored_block_hash FROM staging_blocks WHERE index_block_hash = ?1";
        let args = [index_block_hash as &dyn ToSql];
        
        let row_data_opt = self.blocks_db.query_row(sql, &args,
            |row| {
                let anchored_block_hash = BlockHeaderHash::from_column(row, "anchored_block_hash")?;
                let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
                Ok((burn_header_hash, anchored_block_hash))
            })
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        match row_data_opt {
            Some(Ok(x)) => Ok(Some(x)),
            Some(Err(e)) => Err(e),
            None => Ok(None)
        }
    }

    /// Get the sqlite rowid for a staging microblock.
    /// Returns None if no such microblock.
    fn stream_microblock_get_rowid(blocks_conn: &DBConn, index_block_hash: &StacksBlockId, seq: u16) -> Result<Option<i64>, Error> {
        let sql = "SELECT staging_microblocks_data.rowid FROM \
                   staging_microblocks JOIN staging_microblocks_data \
                   ON staging_microblocks.microblock_hash = staging_microblocks_data.block_hash \
                   WHERE staging_microblocks.index_block_hash = ?1 AND staging_microblocks.sequence = ?2";
        let args = [&index_block_hash as &dyn ToSql, &seq as &dyn ToSql];
        query_row(blocks_conn, sql, &args).map_err(Error::DBError)
    }

    /// Load up the metadata on a microblock stream (but don't get the data itself)
    fn stream_microblock_get_info(blocks_conn: &DBConn, index_block_hash: &StacksBlockId) -> Result<Vec<StagingMicroblock>, Error> {
        let sql = "SELECT * FROM staging_microblocks WHERE index_block_hash = ?1 ORDER BY sequence".to_string();
        let args = [index_block_hash as &dyn ToSql];
        let microblock_info = query_rows::<StagingMicroblock, _>(blocks_conn, &sql, &args).map_err(Error::DBError)?;
        Ok(microblock_info)
    }

    /// Stream data from one Read to one Write
    fn stream_data<W: Write, R: Read + Seek>(fd: &mut W, stream: &mut BlockStreamData, input: &mut R, count: u64) -> Result<u64, Error> {
        input.seek(SeekFrom::Start(stream.offset)).map_err(Error::ReadError)?;

        let mut buf = vec![0u8; count as usize];
        let nr = input.read(&mut buf).map_err(Error::ReadError)?;
        fd.write_all(&buf[0..nr]).map_err(Error::WriteError)?;

        stream.offset += nr as u64;
        stream.total_bytes += nr as u64;

        Ok(nr as u64)
    }

    /// Find the next-smallest sequence in a set of unconfirmed microblocks for a particular index block hash and current sequence number
    fn stream_microblocks_find_next_sequence(blocks_conn: &DBConn, index_block_hash: &StacksBlockId, cur_seq: u16) -> Result<Option<u16>, Error> {
        let sql = "SELECT MIN(sequence) FROM staging_microblocks WHERE index_block_hash = ?1 AND sequence > ?2";
        let args = [&index_block_hash as &dyn ToSql, &cur_seq as &dyn ToSql];
        let next_seqs = StacksChainState::read_i64s(blocks_conn, sql, &args)?;
        match next_seqs.len() {
            0 => Ok(None),
            _ => {
                if next_seqs[0] > u16::max_value() as i64 {
                    Err(Error::DBError(db_error::ParseError))
                }
                else {
                    Ok(Some(next_seqs[0] as u16))
                }
            }
        }
    }

    /// Stream a single microblock's data from the staging database.
    /// If this method returns 0, it's because we're EOF on the blob.
    fn stream_one_microblock_from_staging<W: Write>(blocks_conn: &DBConn, fd: &mut W, stream: &mut BlockStreamData, count: u64) -> Result<u64, Error> {
        let rowid = match stream.rowid {
            None => {
                // need to get rowid
                match StacksChainState::stream_microblock_get_rowid(blocks_conn, &stream.block_hash, stream.seq)? {
                    Some(rid) => rid,
                    None => {
                        test_debug!("Microblock hash={:?} seq={} not in staging", &stream.block_hash, stream.seq);
                        return Err(Error::NoSuchBlockError);
                    }
                }
            },
            Some(rid) => rid
        };
        
        stream.rowid = Some(rowid);
        let mut blob = blocks_conn.blob_open(DatabaseName::Main, "staging_microblocks_data", "block_data", rowid, true)
            .map_err(|e| {
                match e {
                    sqlite_error::SqliteFailure(_, _) => {
                        // blob got moved out of staging
                        Error::NoSuchBlockError
                    },
                    _ => Error::DBError(db_error::SqliteError(e))
                }
            })?;

        StacksChainState::stream_data(fd, stream, &mut blob, count)
    }

    /// Stream multiple microblocks from staging, moving onto the next microblock in the stream.
    /// Returns total number of bytes written (will be equal to the number of bytes read).
    /// Returns 0 if we run out of microblocks in the staging db
    fn stream_microblocks_from_staging<W: Write>(blocks_conn: &DBConn, fd: &mut W, stream: &mut BlockStreamData, count: u64) -> Result<u64, Error> {
        let mut to_write = count;
        while to_write > 0 {
            let nw = StacksChainState::stream_one_microblock_from_staging(blocks_conn, fd, stream, to_write)?;
            if nw == 0 {
                // EOF on microblock blob; move to the next one
                let next_seq = match StacksChainState::stream_microblocks_find_next_sequence(blocks_conn, &stream.block_hash, stream.seq)? {
                    Some(seq) => seq,
                    None => {
                        // out of blocks
                        break;
                    }
                };

                let rowid = match StacksChainState::stream_microblock_get_rowid(blocks_conn, &stream.block_hash, next_seq)? {
                    Some(rid) => rid,
                    None => {
                        // end of staging microblock stream
                        break;
                    }
                };
               
                stream.seq = next_seq;
                stream.offset = 0;
                stream.rowid = Some(rowid);
            }
            else {
                to_write = to_write.checked_sub(nw).expect("BUG: wrote more data than called for");
            }
        }
        Ok(count - to_write)
    }

    /// Stream block data from the chunk store.
    /// Also works for a microblock stream.
    fn stream_data_from_chunk_store<W: Write>(blocks_path: &String, fd: &mut W, stream: &mut BlockStreamData, count: u64) -> Result<u64, Error> {
        let block_path = StacksChainState::get_index_block_path(blocks_path, &stream.block_hash)?;
        
        // The reason we open a file on each call to stream data is because we don't want to
        // exhaust the supply of file descriptors.  Maybe a future version of this code will do
        // something like cache the set of open files so we don't have to keep re-opening them.
        let mut file_fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .create(false)
                    .truncate(false)
                    .open(&block_path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", &block_path);
                            Error::NoSuchBlockError
                        }
                        else {
                            Error::ReadError(e)
                        }
                    })?;

        StacksChainState::stream_data(fd, stream, &mut file_fd, count)
    }

    /// Stream block data from the chain state.  Pull from either staging or the chunk store,
    /// wherever it happens to be located.
    /// Returns the number of bytes written, and updates `stream` to point to the next point to
    /// read.  Writes the bytes streamed to `fd`.
    pub fn stream_block<W: Write>(&mut self, fd: &mut W, stream: &mut BlockStreamData, count: u64) -> Result<u64, Error> {
        StacksChainState::stream_data_from_chunk_store(&self.blocks_path, fd, stream, count)
    }

    /// Stream confirmed microblocks from the chain state.  Pull from only the chunk store.
    /// Returns the number of bytes written, and updates `stream` to point to the next point to
    /// read.  Writes the bytes streamed to `fd`.
    pub fn stream_microblocks_confirmed<W: Write>(&mut self, fd: &mut W, stream: &mut BlockStreamData, count: u64) -> Result<u64, Error> {
        let mut to_write = count;
        while to_write > 0 {
            // reading from the chunk store.
            let nw = StacksChainState::stream_data_from_chunk_store(&self.blocks_path, fd, stream, count)?;
            to_write = to_write.checked_sub(nw).expect("BUG: streamed more data than called for");
 
            if nw == 0 {
                break;
            }
        }
        Ok(count - to_write)
    }

    /// Stream unconfirmed microblocks from the staging DB.  Pull only from the staging DB.
    /// Returns the number of bytes written, and updates `stream` to point to the next point to
    /// read.  Wrties the bytes streamed to `fd`.
    pub fn stream_microblocks_unconfirmed<W: Write>(&mut self, fd: &mut W, stream: &mut BlockStreamData, count: u64) -> Result<u64, Error> {
        // if this is the first-ever microblock we're going to read, then go and find its seq.
        // this will be true if we don't have a rowid yet.
        if stream.rowid.is_none() {
            let seq = 
                if self.has_staging_microblock_indexed(&stream.block_hash, stream.seq)? {
                    stream.seq
                }
                else {
                    // if we don't find any seq, then there are no staging microblocks
                    StacksChainState::stream_microblocks_find_next_sequence(&self.blocks_db, &stream.block_hash, stream.seq)?.ok_or(Error::NoSuchBlockError)?
                };

            stream.seq = seq;
        }

        let mut to_write = count;
        while to_write > 0 {
            // block is in staging.
            let nw = StacksChainState::stream_microblocks_from_staging(&self.blocks_db, fd, stream, to_write)?;
            if nw == 0 {
                break;
            }
            
            to_write = to_write.checked_sub(nw).expect("BUG: streamed more data than called for");
        }
        Ok(count - to_write)
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
    pub fn validate_parent_microblock_stream(parent_anchored_block_header: &StacksBlockHeader, anchored_block_header: &StacksBlockHeader, microblocks: &Vec<StacksMicroblock>, verify_signatures: bool) -> Option<(usize, Option<TransactionPayload>)> {
        if anchored_block_header.is_first_mined() {
            // there had better be zero microblocks
            if anchored_block_header.parent_microblock == EMPTY_MICROBLOCK_PARENT_HASH && anchored_block_header.parent_microblock_sequence == 0 {
                return Some((0, None));
            }
            else {
                warn!("Block {} has no ancestor, and should have no microblock parents", anchored_block_header.block_hash());
                return None;
            }
        }

        let signed_microblocks = 
            if verify_signatures {
                let mut signed_microblocks = vec![];
                for microblock in microblocks.iter() {
                    let mut dup = microblock.clone();
                    if dup.verify(&parent_anchored_block_header.microblock_pubkey_hash).is_err() {
                        warn!("Microblock {} not signed by {}", microblock.block_hash(), parent_anchored_block_header.microblock_pubkey_hash);
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
                debug!("No microblocks between {} and {}", parent_anchored_block_header.block_hash(), anchored_block_header.block_hash());
                return Some((0, None));
            }
            else {
                // did not expect empty
                warn!("Missing microblocks between {} and {}", parent_anchored_block_header.block_hash(), anchored_block_header.block_hash());
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
                debug!("Deliberate microblock fork: duplicate parent {}", signed_microblock.header.prev_block);
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
            debug!("Empty microblock stream between {} and {}", parent_anchored_block_header.block_hash(), anchored_block_header.block_hash());
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
            debug!("Discontiguous stream: block {} does not connect to tail", anchored_block_header.block_hash());
            return None;
        }

        return Some((end, None));
    }

    /// Get the block snapshot of the parent stacks block of the given stacks block
    /// TODO: refactor and dedup with validate_anchored_block_burnchain below
    pub fn get_block_snapshot_of_parent_stacks_block<'a>(burn_ic: &BurnDBConn<'a>, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<BlockSnapshot>, Error> {
        let block_commit = match BurnDB::get_block_commit_for_stacks_block(burn_ic, burn_header_hash, &block_hash).map_err(Error::DBError)? {
            Some(bc) => bc,
            None => {
                // unsoliciated
                debug!("No block commit for {}/{}", burn_header_hash, block_hash);
                return Ok(None);
            }
        };

        // get the stacks chain tip this block commit builds off of
        let stacks_chain_tip = 
            if block_commit.parent_block_ptr == 0 && block_commit.parent_vtxindex == 0 {
                // no parent -- this is the first-ever Stacks block in this fork
                test_debug!("Block {}/{} mines off of genesis", burn_header_hash, block_hash);
                BurnDB::get_first_block_snapshot(burn_ic).map_err(Error::DBError)?
            }
            else {
                let parent_commit = match BurnDB::get_block_commit_parent(burn_ic, block_commit.parent_block_ptr.into(), block_commit.parent_vtxindex.into(), burn_header_hash).map_err(Error::DBError)? {
                    Some(commit) => commit,
                    None => {
                        // unsolicited -- orphaned
                        warn!("Received unsolicited block, could not find parent: {}/{}, parent={}/{}",
                              burn_header_hash, block_hash,
                              block_commit.parent_block_ptr, burn_header_hash);
                        return Ok(None);
                    }
                };

                debug!("Block {}/{} mines off of parent {},{}", burn_header_hash, block_hash, parent_commit.block_height, parent_commit.vtxindex);
                BurnDB::get_block_snapshot(burn_ic, &parent_commit.burn_header_hash)
                    .map_err(Error::DBError)?
                    .expect("FATAL: burn DB does not have snapshot for parent block commit")
            };

        Ok(Some(stacks_chain_tip))
    }

    /// Validate an anchored block against the burn chain state.
    /// Returns Some(commit burn, total burn) if valid
    /// Returns None if not valid
    /// * burn_header_hash is the burnchain block header hash of the burnchain block whose sortition
    /// (ostensibly) selected this block for inclusion.
    pub fn validate_anchored_block_burnchain<'a>(burn_ic: &BurnDBConn<'a>, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock, mainnet: bool, chain_id: u32) -> Result<Option<(u64, u64)>, Error> {
        // sortition-winning block commit for this block?
        let block_hash = block.block_hash();
        let block_commit = match BurnDB::get_block_commit_for_stacks_block(burn_ic, burn_header_hash, &block_hash).map_err(Error::DBError)? {
            Some(bc) => bc,
            None => {
                // unsoliciated
                warn!("Received unsolicited block: {}/{}", burn_header_hash, block_hash);
                return Ok(None);
            }
        };

        // burn chain tip that selected this commit's block
        let burn_chain_tip = BurnDB::get_block_snapshot(burn_ic, &block_commit.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no block snapshot");
       
        // this is the penultimate burnchain snapshot with the VRF seed that this
        // block's miner had to prove on to generate the block-commit and block itself.
        let penultimate_sortition_snapshot = BurnDB::get_block_snapshot_in_fork(burn_ic, block_commit.block_height - 1, &block_commit.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no sortition snapshot");

        // key of the winning leader
        let leader_key = BurnDB::get_leader_key_at(burn_ic, block_commit.key_block_ptr as u64, block_commit.key_vtxindex as u32, &burn_chain_tip.burn_header_hash)
            .map_err(Error::DBError)?
            .expect("FATAL: have block commit but no leader key");

        // get the stacks chain tip this block commit builds off of
        let stacks_chain_tip = 
            if block_commit.parent_block_ptr == 0 && block_commit.parent_vtxindex == 0 {
                // no parent -- this is the first-ever Stacks block in this fork
                test_debug!("Block {}/{} mines off of genesis", burn_header_hash, block_hash);
                BurnDB::get_first_block_snapshot(burn_ic).map_err(Error::DBError)?
            }
            else {
                let parent_commit = match BurnDB::get_block_commit_parent(burn_ic, block_commit.parent_block_ptr.into(), block_commit.parent_vtxindex.into(), burn_header_hash).map_err(Error::DBError)? {
                    Some(commit) => commit,
                    None => {
                        // unsolicited -- orphaned
                        warn!("Received unsolicited block, could not find parent: {}/{}, parent={}/{}",
                              burn_header_hash, block_hash,
                              block_commit.parent_block_ptr, burn_header_hash);
                        return Ok(None);
                    }
                };

                debug!("Block {}/{} mines off of parent {},{}", burn_header_hash, block_hash, parent_commit.block_height, parent_commit.vtxindex);
                BurnDB::get_block_snapshot(burn_ic, &parent_commit.burn_header_hash)
                    .map_err(Error::DBError)?
                    .expect("FATAL: burn DB does not have snapshot for parent block commit")
            };

        // attaches to burn chain
        match block.header.validate_burnchain(&burn_chain_tip, &penultimate_sortition_snapshot, &leader_key, &block_commit, &stacks_chain_tip) {
            Ok(_) => {},
            Err(_) => {
                warn!("Invalid block, could not validate on burnchain: {}/{}",
                      burn_header_hash, block_hash);
                      
                return Ok(None);
            }
        };

        // static checks on transactions all pass
        let valid = block.validate_transactions_static(mainnet, chain_id);
        if !valid {
            warn!("Invalid block, transactions failed static checks: {}/{}",
                  burn_header_hash, block_hash);
            return Ok(None);
        }

        let sortition_burns = BurnDB::get_block_burn_amount(burn_ic, block_commit.block_height - 1, &block_commit.burn_header_hash)
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
    pub fn preprocess_anchored_block<'a>(&mut self, burn_ic: &BurnDBConn<'a>, burn_header_hash: &BurnchainHeaderHash, burn_header_timestamp: u64, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash) -> Result<bool, Error> {
        debug!("preprocess anchored block {}/{}", burn_header_hash, block.block_hash());

        // already in queue or already processed?
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, &block.block_hash());
        if StacksChainState::has_stored_block(&self.blocks_db, &self.blocks_path, burn_header_hash, &block.block_hash())? {
            debug!("Block already stored and processed: {}/{} ({})", burn_header_hash, &block.block_hash(), &index_block_hash);
            return Ok(false);
        }
        else if StacksChainState::has_staging_block(&self.blocks_db, burn_header_hash, &block.block_hash())? {
            debug!("Block already stored (but not processed): {}/{} ({})", burn_header_hash, &block.block_hash(), &index_block_hash);
            return Ok(false);
        }
        else if StacksChainState::has_block_indexed(&self.blocks_path, &index_block_hash)? {
            debug!("Block already stored to chunk store: {}/{} ({})", burn_header_hash, &block.block_hash(), &index_block_hash);
            return Ok(false);
        }
         
        // find all user burns that supported this block 
        let user_burns = BurnDB::get_winning_user_burns_by_block(burn_ic, burn_header_hash)
            .map_err(Error::DBError)?;

        let mainnet = self.mainnet;
        let chain_id = self.chain_id;
        let mut block_tx = self.blocks_tx_begin()?;

        // does this block match the burnchain state? skip if not
        let (commit_burn, sortition_burn) = match StacksChainState::validate_anchored_block_burnchain(burn_ic, burn_header_hash, block, mainnet, chain_id)? {
            Some((commit_burn, sortition_burn)) => (commit_burn, sortition_burn),
            None => { 
                let msg = format!("Invalid block {}: does not correspond to burn chain state", block.block_hash());
                warn!("{}", &msg);

                // orphan it
                StacksChainState::set_block_processed(&mut block_tx, None, burn_header_hash, &block.block_hash(), false)?;

                block_tx.commit().map_err(Error::DBError)?;
                return Err(Error::InvalidStacksBlock(msg));
            }
        };
     
        debug!("Storing staging block");

        // queue block up for processing
        StacksChainState::store_staging_block(&mut block_tx, burn_header_hash, burn_header_timestamp, &block, parent_burn_header_hash, commit_burn, sortition_burn)?;

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
        test_debug!("preprocess microblock {}/{}-{}", burn_header_hash, anchored_block_hash, microblock.block_hash());

        // already queued or already processed?
        if StacksChainState::has_staging_microblock(&self.blocks_db, burn_header_hash, anchored_block_hash, &microblock.block_hash())? || 
           StacksChainState::has_confirmed_microblock(&self.blocks_db, burn_header_hash, anchored_block_hash, &microblock.block_hash())? {
            test_debug!("Microblock already stored and/or processed: {}/{} {} {}", burn_header_hash, &anchored_block_hash, microblock.block_hash(), microblock.header.sequence);

            // try to process it nevertheless
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
            warn!("Invalid microblock {}: failed to verify signature with {}", microblock.block_hash(), pubkey_hash);
            return Ok(false);
        }

        // static checks on transactions all pass
        let valid = microblock.validate_transactions_static(mainnet, chain_id);
        if !valid {
            warn!("Invalid microblock {}: one or more transactions failed static tests", microblock.block_hash());
            return Ok(false);
        }

        // add to staging
        StacksChainState::store_staging_microblock(&mut blocks_tx, burn_header_hash, anchored_block_hash, microblock)?;
        
        blocks_tx.commit().map_err(Error::DBError)?;

        Ok(true)
    }

    /// Given a burnchain snapshot, a Stacks block and a microblock stream, preprocess them all.
    #[cfg(test)]
    pub fn preprocess_stacks_epoch<'a>(&mut self, burn_ic: &BurnDBConn<'a>, snapshot: &BlockSnapshot, block: &StacksBlock, microblocks: &Vec<StacksMicroblock>) -> Result<(), Error> {
        self.preprocess_anchored_block(burn_ic, &snapshot.burn_header_hash, snapshot.burn_header_timestamp, block, &snapshot.parent_burn_header_hash)?;
        let block_hash = block.block_hash();
        for mblock in microblocks.iter() {
            self.preprocess_streamed_microblock(&snapshot.burn_header_hash, &block_hash, mblock)?;
        }
        Ok(())
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
                debug!("No parent microblock stream for {}: expected {},{}", staging_block.anchored_block_hash, staging_block.parent_microblock_hash, staging_block.parent_microblock_seq);
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
            test_debug!("No orphans to remove");
            return Ok(false);
        }

        let orphan_block = rows.pop().unwrap();

        test_debug!("Delete orphaned block {}/{} and its microblocks, and orphan its children", &orphan_block.burn_header_hash, &orphan_block.anchored_block_hash);

        StacksChainState::delete_orphaned_epoch_data(blocks_tx, &orphan_block.burn_header_hash, &orphan_block.anchored_block_hash)?;
        Ok(true)
    }

    /// Is there at least one staging block that can be attached?
    pub fn has_attachable_staging_blocks(blocks_conn: &DBConn) -> Result<bool, Error> {
        // go through staging blocks and see if any of them match headers and are attachable.
        // pick randomly -- don't allow the network sender to choose the processing order!
        let sql = "SELECT 1 FROM staging_blocks WHERE processed = 0 AND attachable = 1 AND orphaned = 0 LIMIT 1".to_string();
        let available = blocks_conn.query_row(&sql, NO_PARAMS, |_row| ()).optional().map_err(|e| Error::DBError(db_error::SqliteError(e)))?.is_some();
        Ok(available)
    }

    /// Given access to the chain state (headers) and the staging blocks, find a staging block we
    /// can process, as well as its parent microblocks that it confirms
    /// Returns Some(microblocks, staging block) if we found a sequence of blocks to process.
    /// Returns None if not.
    fn find_next_staging_block(blocks_conn: &DBConn, blocks_path: &String, headers_conn: &DBConn) -> Result<Option<(Vec<StacksMicroblock>, StagingBlock)>, Error> {
        test_debug!("Find next staging block");

        // go through staging blocks and see if any of them match headers and are attachable.
        // pick randomly -- don't allow the network sender to choose the processing order!
        let sql = "SELECT * FROM staging_blocks WHERE processed = 0 AND attachable = 1 AND orphaned = 0 ORDER BY RANDOM()".to_string();
        
        let mut stmt = blocks_conn.prepare(&sql)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let mut rows = stmt.query(NO_PARAMS)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let candidate = StagingBlock::from_row(&row).map_err(Error::DBError)?;
                    
                    debug!("Consider block {}/{} whose parent is {}/{}", 
                           &candidate.burn_header_hash, &candidate.anchored_block_hash,
                           &candidate.parent_burn_header_hash, &candidate.parent_anchored_block_hash);
        
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
                            let hdr_args: &[&dyn ToSql] = &[&candidate.parent_anchored_block_hash, &candidate.parent_burn_header_hash];
                            let hdr_rows = query_rows::<StacksHeaderInfo, _>(headers_conn, &hdr_sql, hdr_args)
                                .map_err(Error::DBError)?;

                            match hdr_rows.len() {
                                0 => {
                                    // no parent processed for this block
                                    debug!("No such parent {}/{} for block, cannot process", &candidate.parent_burn_header_hash, &candidate.parent_anchored_block_hash);
                                    false
                                }
                                1 => {
                                    // can process this block 
                                    debug!("Have parent {}/{} for this block, will process", &candidate.parent_burn_header_hash, &candidate.parent_anchored_block_hash);
                                    true
                                },
                                _ => {
                                    // should be impossible -- stored the same block twice
                                    unreachable!("Stored the same block twice: {}/{}", &candidate.parent_anchored_block_hash, &candidate.parent_burn_header_hash);
                                }
                            }
                        }
                    };

                    if can_attach {
                        // try and load up this staging block and its microblocks
                        match StacksChainState::load_staging_block(blocks_conn, blocks_path, &candidate.burn_header_hash, &candidate.anchored_block_hash)? {
                            Some(staging_block) => {
                                // must be unprocessed -- must have a block
                                if staging_block.block_data.len() == 0 {
                                    return Err(Error::NetError(net_error::DeserializeError(format!("No block data for staging block {}", candidate.anchored_block_hash))));
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
    pub fn process_microblocks_transactions<'a>(clarity_tx: &mut ClarityTx<'a>, microblocks: &Vec<StacksMicroblock>) -> Result<(u128, u128, Vec<StacksTransactionReceipt>), (Error, BlockHeaderHash)> {
        let mut fees = 0u128;
        let mut burns = 0u128;
        let mut receipts = vec![];
        for microblock in microblocks.iter() {
            for tx in microblock.txs.iter() {
                let (tx_fee, tx_receipt) = StacksChainState::process_transaction(clarity_tx, tx)
                    .map_err(|e| (e, microblock.block_hash()))?;

                fees = fees.checked_add(tx_fee as u128).expect("Fee overflow");
                burns = burns.checked_add(tx_receipt.stx_burned as u128).expect("Burns overflow");
                receipts.push(tx_receipt);
            }
        }
        Ok((fees, burns, receipts))
    }

    /// Process a single anchored block.
    /// Return the fees and burns.
    fn process_block_transactions<'a>(clarity_tx: &mut ClarityTx<'a>, block: &StacksBlock) -> Result<(u128, u128, Vec<StacksTransactionReceipt>), Error> {
        let mut fees = 0u128;
        let mut burns = 0u128;
        let mut receipts = vec![];
        for tx in block.txs.iter() {
            let (tx_fee, tx_receipt) = StacksChainState::process_transaction(clarity_tx, tx)?;
            fees = fees.checked_add(tx_fee as u128).expect("Fee overflow");
            burns = burns.checked_add(tx_receipt.stx_burned as u128).expect("Burns overflow");
            receipts.push(tx_receipt);
        }
        Ok((fees, burns, receipts))
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
      
        clarity_tx.connection().as_transaction(|x| { x.with_clarity_db(|ref mut db| {
            // (+ reward (get available (default-to {available: 0, authorized: false} (map-get rewards ((miner))))))
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
        })}).map_err(Error::ClarityError)?;
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
                        chain_tip_burn_header_timestamp: u64,
                        block: &StacksBlock, 
                        microblocks: &Vec<StacksMicroblock>,  // parent microblocks 
                        burnchain_commit_burn: u64, 
                        burnchain_sortition_burn: u64, 
                        user_burns: &Vec<StagingUserBurnSupport>) -> Result<(StacksHeaderInfo, Vec<StacksTransactionReceipt>), Error>
    {

        debug!("Process block {:?} with {} transactions", &block.block_hash().to_hex(), block.txs.len());

        let mainnet = chainstate_tx.get_config().mainnet;
        let next_block_height = block.header.total_work.work;

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        let matured_miner_rewards_opt = {
            StacksChainState::find_mature_miner_rewards(&mut chainstate_tx.headers_tx, parent_chain_tip, Some(chainstate_tx.miner_payment_cache))?
        };

        let (scheduled_miner_reward, txs_receipts) = {
            let (parent_burn_header_hash, parent_block_hash) = 
                if block.is_first_mined() {
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

                    test_debug!("\n\nAppend {} microblocks {}/{}-{} off of {}/{}\n", num_mblocks, chain_tip_burn_header_hash, _first_mblock_hash, last_microblock_hash, parent_burn_header_hash, parent_block_hash);
                    (last_microblock_hash, last_microblock_seq)
                }
                else {
                    (EMPTY_MICROBLOCK_PARENT_HASH.clone(), 0)
                };

            if last_microblock_hash != block.header.parent_microblock || last_microblock_seq != block.header.parent_microblock_sequence {
                // the pre-processing step should prevent this from being reached
                panic!("BUG: received discontiguous headers for processing: {} (seq={}) does not connect to {} (microblock parent is {} (seq {}))",
                       last_microblock_hash, last_microblock_seq, block.block_hash(), block.header.parent_microblock, block.header.parent_microblock_sequence);
            }
            
            let mut clarity_tx = StacksChainState::chainstate_block_begin(chainstate_tx, clarity_instance, &parent_burn_header_hash, &parent_block_hash, &MINER_BLOCK_BURN_HEADER_HASH, &MINER_BLOCK_HEADER_HASH);

            // process microblock stream
            let (microblock_fees, microblock_burns, mut microblock_txs_receipts) = match StacksChainState::process_microblocks_transactions(&mut clarity_tx, &microblocks) {
                Err((e, offending_mblock_header_hash)) => {
                    let msg = format!("Invalid Stacks microblocks {},{} (offender {}): {:?}", block.header.parent_microblock, block.header.parent_microblock_sequence, offending_mblock_header_hash, &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksMicroblock(msg, offending_mblock_header_hash));
                },
                Ok((fees, burns, events)) => {
                    (fees, burns, events)
                }
            };
            
            test_debug!("\n\nAppend block {}/{} off of {}/{}\nStacks block height: {}, Total Burns: {}\nMicroblock parent: {} (seq {}) (count {})\n", 
                        chain_tip_burn_header_hash, block.block_hash(), parent_burn_header_hash, parent_block_hash,
                        block.header.total_work.work, block.header.total_work.burn,
                        last_microblock_hash, last_microblock_seq, microblocks.len());

            // process anchored block
            let (block_fees, block_burns, mut txs_receipts) = match StacksChainState::process_block_transactions(&mut clarity_tx, &block) {
                Err(e) => {
                    let msg = format!("Invalid Stacks block {}: {:?}", block.block_hash(), &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(Error::InvalidStacksBlock(msg));
                },
                Ok((block_fees, block_burns, txs_receipts)) => (block_fees, block_burns, txs_receipts)
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

            debug!("Reached state root {}", root_hash);
            
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
                                                                                       block_burns.checked_add(microblock_burns).expect("Overflow: Too many STX burnt"),
                                                                                       burnchain_commit_burn,
                                                                                       burnchain_sortition_burn,
                                                                                       0xffffffffffffffff)        // TODO: calculate total compute budget and scale up
                .expect("FATAL: parsed and processed a block without a coinbase");

            txs_receipts.append(&mut microblock_txs_receipts);

            (scheduled_miner_reward, txs_receipts)
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
                                                    chain_tip_burn_header_timestamp,
                                                    microblock_tail_opt,
                                                    &scheduled_miner_reward,
                                                    user_burns)
            .expect("FATAL: failed to advance chain tip");

        Ok((new_tip, txs_receipts))
    }

    /// Verify that a Stacks anchored block attaches to its parent anchored block.
    /// * checks .header.total_work.work
    /// * checks .header.parent_block
    fn check_block_attachment(parent_block_header: &StacksBlockHeader, block_header: &StacksBlockHeader) -> bool {
        // must have the right height
        if parent_block_header.total_work.work.checked_add(1).expect("Blockchain height overflow") != block_header.total_work.work {
            return false;
        }

        // must have right hash linkage
        if parent_block_header.block_hash() != block_header.parent_block {
            return false;
        }
        
        return true;
    }

    /// Find and process the next staging block.
    /// Return the next chain tip if we processed this block, or None if we couldn't.
    /// Return a poison microblock transaction payload if the microblock stream contains a
    /// deliberate miner fork.
    ///
    /// Occurs as a single, atomic transaction against the (marf'ed) headers database and
    /// (un-marf'ed) staging block database, as well as against the chunk store.
    fn process_next_staging_block<'a>(&mut self, burn_tx: &mut BurnDBTx<'a>) -> Result<(Option<(StacksHeaderInfo, Vec<StacksTransactionReceipt>)>, Option<TransactionPayload>), Error> {
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

        debug!("Process staging block {}/{}", next_staging_block.burn_header_hash, next_staging_block.anchored_block_hash);

        let parent_block_header_info = {
            let parent_block_header_info = match StacksChainState::get_anchored_block_header_info(&chainstate_tx.headers_tx, &next_staging_block.parent_burn_header_hash, &next_staging_block.parent_anchored_block_hash)? {
                Some(parent_info) => {
                    debug!("Found parent info {}/{}", next_staging_block.parent_burn_header_hash, next_staging_block.parent_anchored_block_hash);
                    parent_info
                },
                None => {
                    if next_staging_block.is_first_mined() {
                        // this is the first-ever mined block
                        debug!("This is the first-ever block in this fork.  Parent is 00000000..00000000/00000000..00000000");
                        StacksHeaderInfo::genesis_block_header_info(TrieHash([0u8; 32]))        // NOTE: we don't use or care about the index_root_hash field here
                    }
                    else {
                        // no parent stored
                        debug!("No parent block for {}/{} processed yet", next_staging_block.burn_header_hash, next_staging_block.anchored_block_hash);
                        return Ok((None, None));
                    }
                }
            };

            parent_block_header_info
        };

        let block = {
            StacksBlock::consensus_deserialize(&mut &next_staging_block.block_data[..])
                .map_err(Error::NetError)?
        };

        let block_hash = block.block_hash();
        if block_hash != next_staging_block.anchored_block_hash {
            // database corruption
            error!("Staging DB corruption: expected block {}, got {} from disk", next_staging_block.anchored_block_hash, block_hash);
            return Err(Error::DBError(db_error::Corruption));
        }

        // sanity check -- don't process this block again if we already did so
        if StacksChainState::has_stored_block(&chainstate_tx.blocks_tx, chainstate_tx.blocks_tx.get_blocks_path(), &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash)? {
            debug!("Block already processed: {}/{}", &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash);

            // clear out
            StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, Some(burn_tx), &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash, true)?; 
            chainstate_tx.commit()
                .map_err(Error::DBError)?;

            return Ok((None, None));
        }

        // validation check -- we can't have seen this block's microblock public key hash before in
        // this fork
        if StacksChainState::has_microblock_pubkey_hash(&mut chainstate_tx.headers_tx, &parent_block_header_info.burn_header_hash, &parent_block_header_info.anchored_header, &block.header.microblock_pubkey_hash)? {
            let msg = format!("Invalid stacks block {}/{} -- already used microblock pubkey hash {}", &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash, &block.header.microblock_pubkey_hash);
            warn!("{}", &msg);

            // clear out
            StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, None, &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash, false)?; 
            chainstate_tx.commit()
                .map_err(Error::DBError)?;

            return Err(Error::InvalidStacksBlock(msg));
        }

        // validation check -- the block must attach to its accepted parent
        if !StacksChainState::check_block_attachment(&parent_block_header_info.anchored_header, &block.header) {
            let msg = format!("Invalid stacks block {}/{} -- does not attach to parent {}/{}", &next_staging_block.burn_header_hash, block.block_hash(), parent_block_header_info.anchored_header.block_hash(), &parent_block_header_info.burn_header_hash);
            warn!("{}", &msg);
            
            // clear out
            StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, None, &next_staging_block.burn_header_hash, &next_staging_block.anchored_block_hash, false)?; 
            chainstate_tx.commit()
                .map_err(Error::DBError)?;

            return Err(Error::InvalidStacksBlock(msg));
        }

        // validate microblocks
        // NOTE: since we got the microblocks from staging, where their signatures were already
        // validated, we don't need to validate them again.
        let (microblock_terminus, poison_microblock_opt) = match StacksChainState::validate_parent_microblock_stream(&parent_block_header_info.anchored_header, &block.header, &next_microblocks, false) {
            Some((terminus, poison_opt)) => (terminus, poison_opt),
            None => {
                debug!("Stopping at block {}/{} -- discontiguous header stream", next_staging_block.burn_header_hash, block_hash);
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
                //
                // TODO: the node should orphan all of the equivocated microblocks.
                return Ok((None, Some(poison_microblock)));
            }
            None => {}
        }

        // do not consider trailing microblocks that this anchored block does _not_ confirm
        if microblock_terminus < next_microblocks.len() {
            debug!("Truncate microblock stream from parent {}/{} from {} to {} items", parent_block_header_info.burn_header_hash, parent_block_header_info.anchored_header.block_hash(), next_microblocks.len(), microblock_terminus);
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
        let (next_chain_tip, receipts) = match StacksChainState::append_block(&mut chainstate_tx, 
                                                                              clarity_instance, 
                                                                              &parent_block_header_info, 
                                                                              &next_staging_block.burn_header_hash, 
                                                                              next_staging_block.burn_header_timestamp,
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
                test_debug!("Failed to append {}/{}", &next_staging_block.burn_header_hash, &block.block_hash());
                StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, None, &next_staging_block.burn_header_hash, &block.header.block_hash(), false)?;
                StacksChainState::free_block_state(&blocks_path, &next_staging_block.burn_header_hash, &block.header);

                match e {
                    Error::InvalidStacksMicroblock(ref msg, ref header_hash) => {
                        // specifically, an ancestor microblock was invalid.  Drop any descendent microblocks --
                        // they're never going to be valid in _any_ fork, even if they have a clone
                        // in a neighboring burnchain fork.
                        error!("Parent microblock stream from {}/{} is invalid at microblock {}: {}", parent_block_header_info.burn_header_hash, parent_block_header_info.anchored_header.block_hash(), header_hash, msg);
                        StacksChainState::drop_staging_microblocks(&mut chainstate_tx.blocks_tx, &parent_block_header_info.burn_header_hash, &parent_block_header_info.anchored_header.block_hash(), header_hash)?;
                    },
                    _ => {
                        // block was invalid, but this means all the microblocks it confirmed are
                        // still (potentially) valid.  However, they are not confirmed yet, so
                        // leave them in the staging database.
                    }
                }

                chainstate_tx.commit()
                    .map_err(Error::DBError)?;

                return Err(e);
            }
        };

        assert_eq!(next_chain_tip.anchored_header.block_hash(), block.block_hash());
        assert_eq!(next_chain_tip.burn_header_hash, next_staging_block.burn_header_hash);
        assert_eq!(next_chain_tip.anchored_header.parent_microblock, last_microblock_hash);
        assert_eq!(next_chain_tip.anchored_header.parent_microblock_sequence, last_microblock_seq);

        debug!("Reached chain tip {}/{} from {}/{}", next_chain_tip.burn_header_hash, next_chain_tip.anchored_header.block_hash(), next_staging_block.parent_burn_header_hash, next_staging_block.parent_anchored_block_hash);

        if next_staging_block.parent_microblock_hash != EMPTY_MICROBLOCK_PARENT_HASH || next_staging_block.parent_microblock_seq != 0 {
            // confirmed one or more parent microblocks
            StacksChainState::set_microblocks_confirmed(&mut chainstate_tx.blocks_tx, &next_staging_block.parent_burn_header_hash, &next_staging_block.parent_anchored_block_hash, last_microblock_seq)?;
        }
        StacksChainState::set_block_processed(&mut chainstate_tx.blocks_tx, Some(burn_tx), &next_chain_tip.burn_header_hash, &next_chain_tip.anchored_header.block_hash(), true)?;
       
        chainstate_tx.commit()
            .map_err(Error::DBError)?;

        Ok((Some((next_chain_tip, receipts)), None))
    }

    /// Process some staging blocks, up to max_blocks.
    /// Return new chain tips, and optionally any poison microblock payloads for each chain tip
    /// found.
    pub fn process_blocks(&mut self, burndb: &mut BurnDB, max_blocks: usize) -> Result<Vec<(Option<(StacksHeaderInfo, Vec<StacksTransactionReceipt>)>, Option<TransactionPayload>)>, Error> {
        debug!("Process up to {} blocks", max_blocks);

        let mut ret = vec![];

        if max_blocks == 0 {
            // nothing to do
            return Ok(vec![]);
        }
        
        let mut tx = burndb.tx_begin()?;

        for i in 0..max_blocks {
            // process up to max_blocks pending blocks
            match self.process_next_staging_block(&mut tx) {
                Ok((next_tip_opt, next_microblock_poison_opt)) => match next_tip_opt {
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
                },
                Err(Error::InvalidStacksBlock(msg)) => {
                    warn!("Encountered invalid block: {}", &msg);
                    continue;
                },
                Err(Error::InvalidStacksMicroblock(msg, hash)) => {
                    warn!("Encountered invalid microblock {}: {}", hash, &msg);
                    continue;
                },
                Err(Error::NetError(net_error::DeserializeError(msg))) => {
                    // happens if we load a zero-sized block (i.e. an invalid block)
                    warn!("Encountered invalid block: {}", &msg);
                    continue;
                },
                Err(e) => {
                    error!("Unrecoverable error when processing blocks: {:?}", &e);
                    return Err(e);
                }
            }
        }

        tx.commit().map_err(Error::DBError)?;

        let mut block_tx = self.blocks_tx_begin()?;
        for _ in 0..max_blocks {
            // delete up to max_blocks blocks
            let deleted = StacksChainState::process_next_orphaned_staging_block(&mut block_tx)?;
            if !deleted {
                break;
            }
        }
        block_tx.commit()?;

        Ok(ret)
    }

    fn is_valid_address_version(mainnet: bool, version: u8) -> bool {
        if mainnet {
            version == C32_ADDRESS_VERSION_MAINNET_SINGLESIG ||
                version == C32_ADDRESS_VERSION_MAINNET_MULTISIG
        } else {
            version == C32_ADDRESS_VERSION_TESTNET_SINGLESIG ||
                version == C32_ADDRESS_VERSION_TESTNET_MULTISIG
        }
    }

    /// Get the highest processed block on the canonical burn chain.
    /// Break ties on lexigraphical ordering of the block hash
    /// (i.e. arbitrarily).  The staging block will be returned, but no block data will be filled
    /// in.
    pub fn get_stacks_chain_tip(&self, burndb: &BurnDB) -> Result<Option<StagingBlock>, Error> {
        let (burn_bhh, block_bhh) = BurnDB::get_canonical_stacks_chain_tip_hash(burndb.conn())?;
        let sql = "SELECT * FROM staging_blocks WHERE processed = 1 AND orphaned = 0 AND burn_header_hash = ?1 AND anchored_block_hash = ?2";
        let args : &[&dyn ToSql] = &[&burn_bhh, &block_bhh];
        query_row(&self.blocks_db, sql, args).map_err(Error::DBError)
    }

    /// Get the height of a staging block
    pub fn get_stacks_block_height(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<u64>, Error> {
        let sql = "SELECT height FROM staging_blocks WHERE burn_header_hash = ?1 AND anchored_block_hash = ?2";
        let args : &[&dyn ToSql] = &[burn_header_hash, block_hash];
        query_row(&self.blocks_db, sql, args).map_err(Error::DBError)
    }

    /// Check to see if a transaction can be (potentially) appended on top of a given chain tip.
    /// Note that this only checks the transaction against the _anchored chain tip_, not the
    /// unconfirmed microblock stream trailing off of it.
    pub fn will_admit_mempool_tx(&mut self, current_burn: &BurnchainHeaderHash, current_block: &BlockHeaderHash, tx: &StacksTransaction, tx_size: u64) -> Result<(), MemPoolRejection> {
        let conf = self.config();
        let staging_height = match self.get_stacks_block_height(current_burn, current_block) {
            Ok(Some(height)) => {
                height
            },
            Ok(None) => {
                if *current_burn == FIRST_BURNCHAIN_BLOCK_HASH {
                    0
                }
                else {
                    return Err(MemPoolRejection::NoSuchChainTip(current_burn.clone(), current_block.clone()));
                }
            },
            Err(_e) => {
                panic!("DB CORRUPTION: failed to query block height");
            }
        };

        let has_microblock_pubk = match tx.payload {
            TransactionPayload::PoisonMicroblock(ref microblock_header_1, _) => {
                let microblock_pkh_1 = microblock_header_1.check_recover_pubkey()
                    .map_err(|_e| MemPoolRejection::InvalidMicroblocks)?;

                StacksChainState::has_blocks_with_microblock_pubkh(&self.blocks_db, &microblock_pkh_1, staging_height as i64)
            },
            _ => false      // unused
        };
        
        self.with_read_only_clarity_tx(current_burn, current_block, |conn| {
            StacksChainState::can_include_tx(conn, &conf, has_microblock_pubk, tx, tx_size)
        })
    }

    /// Given an outstanding clarity connection, can we append the tx to the chain state?
    /// Used when mining transactions.
    pub fn can_include_tx<T: ClarityConnection>(clarity_connection: &mut T, chainstate_config: &DBConfig, has_microblock_pubkey: bool, tx: &StacksTransaction, tx_size: u64) -> Result<(), MemPoolRejection> {
        // 1: must parse (done)

        // 2: it must be validly signed.
        StacksChainState::process_transaction_precheck(&chainstate_config, &tx)
            .map_err(|e| MemPoolRejection::FailedToValidate(e))?;

        // 3: it must pay a tx fee
        let fee = tx.get_fee_rate();

        if fee < MINIMUM_TX_FEE || 
           fee / tx_size < MINIMUM_TX_FEE_RATE_PER_BYTE {
            return Err(MemPoolRejection::FeeTooLow(fee, cmp::max(MINIMUM_TX_FEE, tx_size * MINIMUM_TX_FEE_RATE_PER_BYTE)))
        }

        // 4: the account nonces must be correct
        let (origin, payer) = StacksChainState::check_transaction_nonces(clarity_connection, &tx)
            .map_err(|e| MemPoolRejection::BadNonces(e))?;

        if !StacksChainState::is_valid_address_version(chainstate_config.mainnet, origin.principal.version())
            || !StacksChainState::is_valid_address_version(chainstate_config.mainnet, payer.principal.version()) {
                return Err(MemPoolRejection::BadAddressVersionByte)
        }

        // 5: the paying account must have enough funds
        if fee as u128 > payer.stx_balance {
            match &tx.payload {
                TransactionPayload::TokenTransfer(..) => {
                    // pass: we'll return a total_spent failure below.
                },
                _ => {
                    return Err(MemPoolRejection::NotEnoughFunds(fee as u128, payer.stx_balance));
                }
            }
        }

        // 6: payload-specific checks
        match &tx.payload {
            TransactionPayload::TokenTransfer(addr, amount, _memo) => {
                // version byte matches?
                if !StacksChainState::is_valid_address_version(chainstate_config.mainnet, addr.version()) {
                    return Err(MemPoolRejection::BadAddressVersionByte);
                }

                // got the funds?
                let total_spent = (*amount as u128) +
                    if origin == payer {
                        fee as u128
                    } else {
                        0
                    };
                if total_spent > origin.stx_balance {
                    return Err(MemPoolRejection::NotEnoughFunds(total_spent, origin.stx_balance))
                }
            },
            TransactionPayload::ContractCall(TransactionContractCall {
                address, contract_name, function_name, function_args }) => {
                // version byte matches?
                if !StacksChainState::is_valid_address_version(chainstate_config.mainnet, address.version) {
                    return Err(MemPoolRejection::BadAddressVersionByte)
                }

                let contract_identifier = QualifiedContractIdentifier::new(address.clone().into(), contract_name.clone());

                let function_type = clarity_connection.with_analysis_db_readonly(|db| {
                        db.get_public_function_type(&contract_identifier, &function_name)
                    })
                    .map_err(|_e| MemPoolRejection::NoSuchContract)?
                    .ok_or_else(|| MemPoolRejection::NoSuchPublicFunction)?;

                let arg_types: Vec<_> = function_args.iter().map(|x| TypeSignature::type_of(x)).collect();
                function_type.check_args(&mut (), &arg_types)
                    .map_err(|e| MemPoolRejection::BadFunctionArgument(e))?;
            },
            TransactionPayload::SmartContract(TransactionSmartContract { name, code_body: _ }) => {
                let contract_identifier = QualifiedContractIdentifier::new(tx.origin_address().into(), name.clone());

                let exists = clarity_connection.with_analysis_db_readonly(|db| {
                        db.has_contract(&contract_identifier)
                    });

                if exists {
                    return Err(MemPoolRejection::ContractAlreadyExists(contract_identifier))
                }
            },
            TransactionPayload::PoisonMicroblock(microblock_header_1, microblock_header_2) => {
                if microblock_header_1.sequence != microblock_header_2.sequence ||
                    microblock_header_1.prev_block != microblock_header_2.prev_block ||
                    microblock_header_1.version != microblock_header_2.version {
                    return Err(MemPoolRejection::PoisonMicroblocksDoNotConflict)
                }

                let microblock_pkh_1 = microblock_header_1.check_recover_pubkey()
                    .map_err(|_e| MemPoolRejection::InvalidMicroblocks)?;
                let microblock_pkh_2 = microblock_header_2.check_recover_pubkey()
                    .map_err(|_e| MemPoolRejection::InvalidMicroblocks)?;

                if microblock_pkh_1 != microblock_pkh_2 {
                    return Err(MemPoolRejection::PoisonMicroblocksDoNotConflict)
                }

                if !has_microblock_pubkey {
                    return Err(MemPoolRejection::NoAnchorBlockWithPubkeyHash(microblock_pkh_1))
                }
            },
            TransactionPayload::Coinbase(_) => {
                return Err(MemPoolRejection::NoCoinbaseViaMempool)
            }
        };

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use chainstate::stacks::Error as chainstate_error;
    use chainstate::stacks::*;
    use chainstate::stacks::test::*;
    use chainstate::stacks::db::*;
    use chainstate::stacks::db::test::*;
        
    use burnchains::*;
    use chainstate::burn::*;
    use chainstate::burn::db::burndb::*;
    use util::db::Error as db_error;
    use util::db::*;
    use util::hash::*;
    use util::retry::*;
    use std::fs;

    pub fn make_empty_coinbase_block(mblock_key: &StacksPrivateKey) -> StacksBlock {
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

    pub fn make_sample_microblock_stream(privk: &StacksPrivateKey, anchored_block_hash: &BlockHeaderHash) -> Vec<StacksMicroblock> {
        let mut all_txs = vec![];
        let mut microblocks : Vec<StacksMicroblock> = vec![];

        for i in 0..49 {
            let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
            let tx_smart_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                           auth.clone(),
                                                           TransactionPayload::new_smart_contract(&"hello-microblock".to_string(), &format!("hello smart contract {}", i)).unwrap());
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
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap(), *block);
        assert_eq!(StacksChainState::get_staging_block_status(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), false);

        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header, &block.block_hash());
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_hash).unwrap());
    }

    fn assert_block_not_stored(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock) -> () {
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap());
        assert_eq!(StacksChainState::load_staging_block_pubkey_hash(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), block.header.microblock_pubkey_hash);
    }

    fn assert_block_stored_rejected(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock) -> () {
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_block_header(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_staging_block_pubkey_hash(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());

        assert_eq!(StacksChainState::get_staging_block_status(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), true);
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());

        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header, &block.block_hash());
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_hash).unwrap());
    }

    fn assert_block_stored_not_staging(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, block: &StacksBlock) -> () {
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_block(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap(), *block);
        assert_eq!(StacksChainState::load_block_header(&chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap(), block.header);
        assert!(StacksChainState::load_staging_block_pubkey_hash(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().is_none());

        assert_eq!(StacksChainState::get_staging_block_status(&chainstate.blocks_db, burn_header, &block.block_hash()).unwrap().unwrap(), true);
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
        
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header, &block.block_hash());
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_hash).unwrap());
    }

    pub fn store_staging_block(chainstate: &mut StacksChainState, burn_header: &BurnchainHeaderHash, burn_header_timestamp: u64, block: &StacksBlock, parent_burn_header: &BurnchainHeaderHash, commit_burn: u64, sortition_burn: u64) {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::store_staging_block(&mut tx, burn_header, burn_header_timestamp, block, parent_burn_header, commit_burn, sortition_burn).unwrap();
        tx.commit().unwrap();
        
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header, &block.block_hash());
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_hash).unwrap());
    }

    pub fn store_staging_microblock(chainstate: &mut StacksChainState, burn_header_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, microblock: &StacksMicroblock) {
        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::store_staging_microblock(&mut tx, burn_header_hash, anchored_block_hash, microblock).unwrap();
        tx.commit().unwrap();
        
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_header_hash, anchored_block_hash);
        assert!(chainstate.has_microblocks_indexed(&index_block_hash).unwrap());
    }
    
    pub fn set_block_processed(chainstate: &mut StacksChainState, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, accept: bool) {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_hash, anchored_block_hash);
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_hash).unwrap());

        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::set_block_processed(&mut tx, None, burn_hash, anchored_block_hash, accept).unwrap();
        tx.commit().unwrap();
        
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_hash).unwrap());
    }

    fn get_microblock_stream_head_hash(chainstate: &StacksChainState, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash) -> Option<BlockHeaderHash> {
        StacksChainState::get_microblock_stream_head_hash(&chainstate.blocks_db, burn_hash, anchored_block_hash).unwrap()
    }

    pub fn set_microblocks_confirmed(chainstate: &mut StacksChainState, burn_hash: &BurnchainHeaderHash, anchored_block_hash: &BlockHeaderHash, last_seq: u16) {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_hash, anchored_block_hash);
        assert!(chainstate.has_microblocks_indexed(&index_block_hash).unwrap());

        let stream_head_hash = get_microblock_stream_head_hash(chainstate, burn_hash, anchored_block_hash).unwrap();
        let index_microblock_hash = StacksBlockHeader::make_index_block_hash(burn_hash, &stream_head_hash);
        
        let mblock_anchored_hash_opt = chainstate.get_confirmed_microblock_index_hash(&index_block_hash).unwrap();
        
        // is there already a confirmed stream for this anchored block?
        if chainstate.has_confirmed_microblocks_indexed(&index_microblock_hash).unwrap() {
            // make sure we can get back the confirmed mciroblock index hash
            assert!(mblock_anchored_hash_opt.is_some());
        }
        else {
            assert!(mblock_anchored_hash_opt.is_none());
        }

        let mut tx = chainstate.blocks_tx_begin().unwrap();
        StacksChainState::set_microblocks_confirmed(&mut tx, burn_hash, anchored_block_hash, last_seq).unwrap();
        tx.commit().unwrap();
        
        assert!(chainstate.has_microblocks_indexed(&index_block_hash).unwrap());
        assert!(chainstate.has_confirmed_microblocks_indexed(&index_microblock_hash).unwrap());
   
        // now that the stream is confirmed, we can get its head hash by anchor block
        let mblock_anchored_hash_opt = chainstate.get_confirmed_microblock_index_hash(&index_block_hash).unwrap();
        assert!(mblock_anchored_hash_opt.is_some());
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
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap());

        StacksChainState::store_empty_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap();
        assert!(fs::metadata(&path).is_ok());
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([2u8; 32])).unwrap());
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
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());

        StacksChainState::store_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block).unwrap();
        assert!(fs::metadata(&path).is_ok());
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().unwrap(), block);
        assert_eq!(StacksChainState::load_block_header(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().unwrap(), block.header);

        StacksChainState::free_block_state(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.header);

        assert!(StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap());
        assert!(StacksChainState::load_block(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_none());
        assert!(StacksChainState::load_block_header(&chainstate.blocks_path, &BurnchainHeaderHash([1u8; 32]), &block.block_hash()).unwrap().is_none());
    }

    #[test]
    fn stacks_db_staging_block_load_store_accept() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
      
        let block = make_empty_coinbase_block(&privk);
        
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), get_epoch_time_secs(), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);

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
        
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &block.block_hash()).unwrap().is_none());

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), get_epoch_time_secs(), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);

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
        assert!(!StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).is_err());
        
        StacksChainState::store_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks).unwrap();

        assert!(fs::metadata(&path).is_ok());
        assert!(StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
        
        assert!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().is_some());
        assert_eq!(StacksChainState::load_microblock_stream(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap().unwrap(), microblocks);

        StacksChainState::free_block(&chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash());

        assert!(StacksChainState::has_stored_block(&chainstate.blocks_db, &chainstate.blocks_path, &BurnchainHeaderHash([2u8; 32]), &microblocks[0].block_hash()).unwrap());
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

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), get_epoch_time_secs(), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);
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

        store_staging_block(&mut chainstate, &BurnchainHeaderHash([2u8; 32]), get_epoch_time_secs(), &block, &BurnchainHeaderHash([1u8; 32]), 1, 2);
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
                                                                       TransactionPayload::new_smart_contract(&"name-contract".to_string(), &format!("conflicting smart contract {}", i)).unwrap());
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
    fn stacks_db_staging_block_load_store_accept_attachable() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_block_load_store_accept_attachable");
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
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, burn_header, get_epoch_time_secs(), block, parent_burn_header, 1, 2);
            assert_block_staging_not_processed(&mut chainstate, burn_header, block);
        }

        // first block is attachable, but all the rest are not
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[0], &block_1.block_hash()).unwrap().unwrap().attachable, true);

        for (block, burn_header) in blocks[1..].iter().zip(&burn_headers[1..]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap().attachable, false);
        }

        // process all blocks, and check that processing a parent makes the child attachable
        for (i, (block, burn_header)) in blocks.iter().zip(&burn_headers).enumerate() {
            // child block is not attachable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attachable, false);
            }

            // block not stored yet
            assert_block_not_stored(&mut chainstate, burn_header, block);

            set_block_processed(&mut chainstate, burn_header, &block.block_hash(), true);

            // block is now stored
            assert_block_stored_not_staging(&mut chainstate, burn_header, block);

            // child block is attachable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attachable, true);
            }
        }
    }

    #[test]
    fn stacks_db_staging_block_load_store_accept_attachable_reversed() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stx_db_staging_block_load_store_accept_attachable_r");
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
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, burn_header, get_epoch_time_secs(), block, parent_burn_header, 1, 2);
            assert_block_staging_not_processed(&mut chainstate, burn_header, block);
        }

        // first block is accepted, but all the rest are not
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[0], &block_1.block_hash()).unwrap().unwrap().attachable, true);

        for (block, burn_header) in blocks[1..].iter().zip(&burn_headers[1..]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap().attachable, false);
        }

        // process all blocks, and check that processing a parent makes the child attachable
        for (i, (block, burn_header)) in blocks.iter().zip(&burn_headers).enumerate() {
            // child block is not attachable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attachable, false);
            }

            // block not stored yet
            assert_block_not_stored(&mut chainstate, burn_header, block);

            set_block_processed(&mut chainstate, burn_header, &block.block_hash(), true);

            // block is now stored
            assert_block_stored_not_staging(&mut chainstate, burn_header, block);

            // child block is attachable
            if i + 1 < burn_headers.len() {
                let child_burn_header = &burn_headers[i + 1];
                let child_block = &blocks[i + 1];
                assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, child_burn_header, &child_block.block_hash()).unwrap().unwrap().attachable, true);
            }
        }
    }
    
    #[test]
    fn stacks_db_staging_block_load_store_accept_attachable_fork() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stx_db_staging_block_load_store_accept_attachable_f");
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
        // storing block_1 to staging renders block_2 and block_3 unattachable
        // processing and accepting block_1 renders both block_2 and block_3 attachable again

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
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, burn_header, get_epoch_time_secs(), block, parent_burn_header, 1, 2);
            assert_block_staging_not_processed(&mut chainstate, burn_header, block);
        }

        // block 4 is not attachable
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[3], &block_4.block_hash()).unwrap().unwrap().attachable, false);

        // blocks 2 and 3 are attachable
        for (block, burn_header) in [&block_2, &block_3].iter().zip(&[&burn_headers[1], &burn_headers[2]]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap().attachable, true);
        }

        // store block 1
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[0], &block_1.block_hash()).unwrap().is_none());
        store_staging_block(&mut chainstate, &burn_headers[0], get_epoch_time_secs(), &block_1, &parent_burn_headers[0], 1, 2);
        assert_block_staging_not_processed(&mut chainstate, &burn_headers[0], &block_1);
        
        // first block is attachable
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[0], &block_1.block_hash()).unwrap().unwrap().attachable, true);

        // blocks 2 and 3 are no longer attachable
        for (block, burn_header) in [&block_2, &block_3].iter().zip(&[&burn_headers[1], &burn_headers[2]]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap().attachable, false);
        }

        // process block 1, and confirm that it makes block 2 and 3 attachable
        assert_block_not_stored(&mut chainstate, &burn_headers[0], &block_1);
        set_block_processed(&mut chainstate, &burn_headers[0], &block_1.block_hash(), true);
        assert_block_stored_not_staging(&mut chainstate, &burn_headers[0], &block_1);
        
        // now block 2 and 3 are attachable
        for (block, burn_header) in blocks[1..3].iter().zip(&burn_headers[1..3]) {
            assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, burn_header, &block.block_hash()).unwrap().unwrap().attachable, true);
        }

        // and block 4 is still not
        assert_eq!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[3], &block_4.block_hash()).unwrap().unwrap().attachable, false);
    }

    #[test]
    fn stacks_db_staging_microblocks_multiple_descendents() {
        // multiple anchored blocks build off of different microblock parents 
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_microblocks_multiple_descendents");
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
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[0], &blocks[0].block_hash()).unwrap().is_none());
        store_staging_block(&mut chainstate, &burn_headers[0], get_epoch_time_secs(), &blocks[0], &parent_burn_headers[0], 1, 2);
        assert_block_staging_not_processed(&mut chainstate, &burn_headers[0], &blocks[0]);

        set_block_processed(&mut chainstate, &burn_headers[0], &blocks[0].block_hash(), true);
        assert_block_stored_not_staging(&mut chainstate, &burn_headers[0], &blocks[0]);

        // process and store blocks 1 and N, as well as microblocks in-between
        let len = blocks.len();
        for i in 1..len {
            // this is what happens at the end of append_block()
            // store block to staging and process it
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[i], &blocks[i].block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, &burn_headers[i], get_epoch_time_secs(), &blocks[i], &parent_burn_headers[i], 1, 2);
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
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_staging_blocks_orphaned");
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
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[i], &blocks[i].block_hash()).unwrap().is_none());
            store_staging_block(&mut chainstate, &burn_headers[i], get_epoch_time_secs(), &blocks[i], &parent_burn_headers[i], 1, 2);
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
                assert!(StacksChainState::load_staging_block(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[i+1], &blocks[i+1].block_hash()).unwrap().is_none());
                assert!(StacksChainState::load_block_bytes(&chainstate.blocks_path, &burn_headers[i+1], &blocks[i+1].block_hash()).unwrap().unwrap().len() > 0);
                
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
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_drop_staging_microblocks_1");
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
        assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &burn_header, &block.block_hash()).unwrap().is_none());
        store_staging_block(&mut chainstate, &burn_header, get_epoch_time_secs(), &block, &parent_burn_header, 1, 2);
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

    #[test]
    fn stacks_db_has_blocks_and_microblocks() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_has_blocks_and_microblocks");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
        
        let block = make_empty_coinbase_block(&privk);
        let mut mblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        mblocks.truncate(3);
        
        let burn_header = BurnchainHeaderHash([2u8; 32]);
        let parent_burn_header = BurnchainHeaderHash([1u8; 32]);

        let index_block_header = StacksBlockHeader::make_index_block_hash(&burn_header, &block.block_hash());
        assert!(!StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_header).unwrap());
        assert!(!chainstate.has_microblocks_indexed(&index_block_header).unwrap());
        
        assert_eq!(StacksChainState::stream_microblock_get_info(&chainstate.blocks_db, &index_block_header).unwrap().len(), 0);

        // store microblocks to staging
        for (i, mblock) in mblocks.iter().enumerate() {
            assert!(StacksChainState::stream_microblock_get_rowid(&chainstate.blocks_db, &index_block_header, mblock.header.sequence).unwrap().is_none());

            store_staging_microblock(&mut chainstate, &burn_header, &block.block_hash(), mblock);
            assert!(StacksChainState::load_staging_microblock(&chainstate.blocks_db, &burn_header, &block.block_hash(), &mblock.block_hash()).unwrap().is_some());
        
            assert!(chainstate.has_microblocks_indexed(&index_block_header).unwrap());
            assert!(StacksChainState::stream_microblock_get_rowid(&chainstate.blocks_db, &index_block_header, mblock.header.sequence).unwrap().is_some());

            assert!(!StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_header).unwrap());
            
            let mblock_info = StacksChainState::stream_microblock_get_info(&chainstate.blocks_db, &index_block_header).unwrap();
            assert_eq!(mblock_info.len(), i + 1);

            let last_mblock_info = mblock_info.last().unwrap();
            assert_eq!(last_mblock_info.burn_header_hash, burn_header);
            assert_eq!(last_mblock_info.anchored_block_hash, block.block_hash());
            assert_eq!(last_mblock_info.microblock_hash, mblock.block_hash());
            assert_eq!(last_mblock_info.sequence, mblock.header.sequence);
            assert!(!last_mblock_info.processed);
            assert!(!last_mblock_info.orphaned);
            assert_eq!(last_mblock_info.block_data.len(), 0);
        }
        
        // store block to staging
        store_staging_block(&mut chainstate, &burn_header, get_epoch_time_secs(), &block, &parent_burn_header, 1, 2);
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_header).unwrap());

        // accept it
        set_block_processed(&mut chainstate, &burn_header, &block.block_hash(), true);
        assert!(StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_header).unwrap());

        for i in 0..mblocks.len() {
            assert!(StacksChainState::stream_microblock_get_rowid(&chainstate.blocks_db, &index_block_header, mblocks[i].header.sequence).unwrap().is_some());

            // set different parts of this stream as confirmed
            set_microblocks_confirmed(&mut chainstate, &burn_header, &block.block_hash(), i as u16);
            assert!(chainstate.has_microblocks_indexed(&index_block_header).unwrap());
            assert!(StacksChainState::stream_microblock_get_rowid(&chainstate.blocks_db, &index_block_header, mblocks[i].header.sequence).unwrap().is_none());  // no longer in staging

            let mblock_info = StacksChainState::stream_microblock_get_info(&chainstate.blocks_db, &index_block_header).unwrap();
            assert_eq!(mblock_info.len(), mblocks.len());

            let this_mblock_info = &mblock_info[i];
            assert_eq!(this_mblock_info.burn_header_hash, burn_header);
            assert_eq!(this_mblock_info.anchored_block_hash, block.block_hash());
            assert_eq!(this_mblock_info.microblock_hash, mblocks[i].block_hash());
            assert_eq!(this_mblock_info.sequence, mblocks[i].header.sequence);
            assert!(this_mblock_info.processed);
            assert!(!this_mblock_info.orphaned);
            assert_eq!(this_mblock_info.block_data.len(), 0);
        }
    }

    fn stream_one_staging_microblock_to_vec(blocks_conn: &DBConn, stream: &mut BlockStreamData, count: u64) -> Result<Vec<u8>, chainstate_error> {
        let mut bytes = vec![];
        StacksChainState::stream_one_microblock_from_staging(blocks_conn, &mut bytes, stream, count)
            .map(|nr| {
                assert_eq!(bytes.len(), nr as usize);
                bytes
            })
    }

    fn stream_chunk_to_vec(blocks_path: &String, stream: &mut BlockStreamData, count: u64) -> Result<Vec<u8>, chainstate_error> {
        let mut bytes = vec![];
        StacksChainState::stream_data_from_chunk_store(blocks_path, &mut bytes, stream, count)
            .map(|nr| {
                assert_eq!(bytes.len(), nr as usize);
                bytes
            })
    }
    
    fn stream_unconfirmed_microblocks_to_vec(chainstate: &mut StacksChainState, stream: &mut BlockStreamData, count: u64) -> Result<Vec<u8>, chainstate_error> {
        let mut bytes = vec![];
        StacksChainState::stream_microblocks_unconfirmed(chainstate, &mut bytes, stream, count)
            .map(|nr| {
                assert_eq!(bytes.len(), nr as usize);
                bytes
            })
    }

    fn stream_confirmed_microblocks_to_vec(chainstate: &mut StacksChainState, stream: &mut BlockStreamData, count: u64) -> Result<Vec<u8>, chainstate_error> {
        let mut bytes = vec![];
        StacksChainState::stream_microblocks_confirmed(chainstate, &mut bytes, stream, count)
            .map(|nr| {
                assert_eq!(bytes.len(), nr as usize);
                bytes
            })
    }

    fn decode_microblock_stream(mblock_bytes: &Vec<u8>) -> Vec<StacksMicroblock> {
        // decode stream
        let mut mblock_ptr = mblock_bytes.as_slice();
        let mut mblocks = vec![];
        loop {
            test_debug!("decoded {}", mblocks.len());
            {
                let mut debug_reader = LogReader::from_reader(&mut mblock_ptr);
                let next_mblock = StacksMicroblock::consensus_deserialize(&mut debug_reader).map_err(|e| {
                    eprintln!("Failed to decode microblock {}: {:?}", mblocks.len(), &e);
                    eprintln!("Bytes consumed:");
                    for buf in debug_reader.log().iter() {
                        eprintln!("  {}", to_hex(buf));
                    }
                    assert!(false);
                    unreachable!();
                }).unwrap();
                mblocks.push(next_mblock);
            }
            if mblock_ptr.len() == 0 {
                break;
            }
        }
        mblocks
    }
    
    #[test]
    fn stacks_db_stream_blocks() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_stream_blocks");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
        
        let block = make_empty_coinbase_block(&privk);
        
        let burn_header = BurnchainHeaderHash([2u8; 32]);
        let parent_burn_header = BurnchainHeaderHash([1u8; 32]);
        let index_block_header = StacksBlockHeader::make_index_block_hash(&burn_header, &block.block_hash());

        // can't stream a non-existant block
        let mut stream = BlockStreamData::new_block(index_block_header.clone());
        assert!(stream_chunk_to_vec(&chainstate.blocks_path, &mut stream, 123).is_err());

        // stream unmodified
        let stream_2 = BlockStreamData::new_block(index_block_header.clone());
        assert_eq!(stream, stream_2);

        // store block to staging
        store_staging_block(&mut chainstate, &burn_header, get_epoch_time_secs(), &block, &parent_burn_header, 1, 2);

        // stream it back
        let mut all_block_bytes = vec![];
        loop {
            let mut next_bytes = stream_chunk_to_vec(&chainstate.blocks_path, &mut stream, 16).unwrap();
            if next_bytes.len() == 0 {
                break;
            }
            test_debug!("Got {} more bytes from staging; add to {} total", next_bytes.len(), all_block_bytes.len());
            all_block_bytes.append(&mut next_bytes);
        }

        // should decode back into the block
        let staging_block = StacksBlock::consensus_deserialize(&mut &all_block_bytes[..]).unwrap();
        assert_eq!(staging_block, block);

        // accept it
        set_block_processed(&mut chainstate, &burn_header, &block.block_hash(), true);

        // can still stream it
        let mut stream = BlockStreamData::new_block(index_block_header.clone());

        // stream from chunk store
        let mut all_block_bytes = vec![];
        loop {
            let mut next_bytes = stream_chunk_to_vec(&chainstate.blocks_path, &mut stream, 16).unwrap();
            if next_bytes.len() == 0 {
                break;
            }
            test_debug!("Got {} more bytes from chunkstore; add to {} total", next_bytes.len(), all_block_bytes.len());
            all_block_bytes.append(&mut next_bytes);
        }
        
        // should decode back into the block
        let staging_block = StacksBlock::consensus_deserialize(&mut &all_block_bytes[..]).unwrap();
        assert_eq!(staging_block, block);
    }

    #[test]
    fn stacks_db_stream_staging_microblocks() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_stream_staging_microblocks");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
        
        let block = make_empty_coinbase_block(&privk);
        let mut mblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        mblocks.truncate(15);
        
        let burn_header = BurnchainHeaderHash([2u8; 32]);
        let parent_burn_header = BurnchainHeaderHash([1u8; 32]);
        let index_block_header = StacksBlockHeader::make_index_block_hash(&burn_header, &block.block_hash());
        
        // can't stream a non-existant microblock
        let mut stream = BlockStreamData::new_block(index_block_header.clone());
        assert!(StacksChainState::stream_one_microblock_from_staging(&chainstate.blocks_db, &mut vec![], &mut stream, 123).is_err());
        assert!(stream.rowid.is_none());

        // store microblocks to staging and stream them back
        for (i, mblock) in mblocks.iter().enumerate() {
            store_staging_microblock(&mut chainstate, &burn_header, &block.block_hash(), mblock);

            // read back all the data we have so far, block-by-block
            let mut staging_mblocks = vec![];
            for j in 0..(i+1) {
                let mut next_mblock_bytes = vec![];
                let mut stream = BlockStreamData::new_microblock_unconfirmed(index_block_header.clone(), j as u16);
                loop {
                    let mut next_bytes = stream_one_staging_microblock_to_vec(&chainstate.blocks_db, &mut stream, 4096).unwrap();
                    if next_bytes.len() == 0 {
                        break;
                    }
                    test_debug!("Got {} more bytes from staging; add to {} total", next_bytes.len(), next_mblock_bytes.len());
                    next_mblock_bytes.append(&mut next_bytes);
                }
                // should deserialize to a microblock
                let staging_mblock = StacksMicroblock::consensus_deserialize(&mut &next_mblock_bytes[..]).unwrap();
                staging_mblocks.push(staging_mblock);
            }

            assert_eq!(staging_mblocks.len(), mblocks[0..(i+1)].len());
            for j in 0..(i+1) {
                test_debug!("check {}", j);
                assert_eq!(staging_mblocks[j], mblocks[j])
            }

            // can also read partial stream in one shot, from any seq
            for k in 0..(i+1) {
                test_debug!("start at seq {}", k);
                let mut staging_mblock_bytes = vec![];
                let mut stream = BlockStreamData::new_microblock_unconfirmed(index_block_header.clone(), k as u16);
                loop {
                    let mut next_bytes = stream_unconfirmed_microblocks_to_vec(&mut chainstate, &mut stream, 4096).unwrap();
                    if next_bytes.len() == 0 {
                        break;
                    }
                    test_debug!("Got {} more bytes from staging; add to {} total", next_bytes.len(), staging_mblock_bytes.len());
                    staging_mblock_bytes.append(&mut next_bytes);
                }

                // decode stream
                let staging_mblocks = decode_microblock_stream(&staging_mblock_bytes);
                
                assert_eq!(staging_mblocks.len(), mblocks[k..(i+1)].len());
                for j in 0..staging_mblocks.len() {
                    test_debug!("check {}", j);
                    assert_eq!(staging_mblocks[j], mblocks[k+j])
                }
            }
        }
    } 
    
    #[test]
    fn stacks_db_stream_confirmed_microblocks() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_stream_confirmed_microblocks");
        let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();
        
        let block = make_empty_coinbase_block(&privk);
        let mut mblocks = make_sample_microblock_stream(&privk, &block.block_hash());
        mblocks.truncate(5);
        
        let burn_header = BurnchainHeaderHash([2u8; 32]);
        let parent_burn_header = BurnchainHeaderHash([1u8; 32]);

        let index_block_header = StacksBlockHeader::make_index_block_hash(&burn_header, &block.block_hash());

        // store microblocks to staging
        for (i, mblock) in mblocks.iter().enumerate() {
            store_staging_microblock(&mut chainstate, &burn_header, &block.block_hash(), mblock);
        }
        
        // store block to staging
        store_staging_block(&mut chainstate, &burn_header, get_epoch_time_secs(), &block, &parent_burn_header, 1, 2);

        // accept it
        set_block_processed(&mut chainstate, &burn_header, &block.block_hash(), true);

        for i in 0..mblocks.len() {
            // set different parts of this stream as confirmed
            set_microblocks_confirmed(&mut chainstate, &burn_header, &block.block_hash(), i as u16);

            // verify that we can stream everything
            let microblock_index_header = StacksBlockHeader::make_index_block_hash(&burn_header, &mblocks[0].block_hash());
            let mut stream = BlockStreamData::new_microblock_confirmed(microblock_index_header.clone());

            let mut confirmed_mblock_bytes = vec![];
            loop {
                let mut next_bytes = stream_confirmed_microblocks_to_vec(&mut chainstate, &mut stream, 16).unwrap();
                if next_bytes.len() == 0 {
                    break;
                }
                test_debug!("Got {} more bytes from staging; add to {} total", next_bytes.len(), confirmed_mblock_bytes.len());
                confirmed_mblock_bytes.append(&mut next_bytes);
            }
            
            // decode stream (should be length-prefixed)
            let confirmed_mblocks = Vec::<StacksMicroblock>::consensus_deserialize(&mut &confirmed_mblock_bytes[..]).unwrap();

            assert_eq!(confirmed_mblocks.len(), mblocks[0..(i+1)].len());
            for j in 0..(i+1) {
                test_debug!("check {}", j);
                assert_eq!(confirmed_mblocks[j], mblocks[j])
            }
        }
    }
    
    #[test]
    fn stacks_db_get_blocks_inventory() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "stacks_db_get_blocks_inventory");
      
        let mut blocks = vec![];
        let mut privks = vec![];
        let mut microblocks = vec![];
        let mut burn_headers = vec![];
        let mut parent_burn_headers = vec![];

        for i in 0..(BLOCKS_INV_DATA_MAX_BITLEN as usize) {
            test_debug!("Making block {}", i);
            let privk = StacksPrivateKey::new();
            let block = make_empty_coinbase_block(&privk);

            blocks.push(block);
            privks.push(privk);

            let bhh = BurnchainHeaderHash([((i + 1) as u8); 32]);
            burn_headers.push(bhh);

            let parent_bhh = BurnchainHeaderHash([(i as u8); 32]);
            parent_burn_headers.push(parent_bhh);
        }

        for i in 0..blocks.len() {
            test_debug!("Making microblock stream {}", i);
            // make a sample microblock stream for block i
            let mut mblocks = make_sample_microblock_stream(&privks[i], &blocks[i].block_hash());
            mblocks.truncate(3);
        
            if i + 1 < blocks.len() {
                blocks[i+1].header.parent_block = blocks[i].block_hash();
                blocks[i+1].header.parent_microblock = mblocks[2].block_hash();
                blocks[i+1].header.parent_microblock_sequence = mblocks[2].header.sequence;
            }

            microblocks.push(mblocks);
        }

        let block_hashes : Vec<BlockHeaderHash> = blocks.iter().map(|ref b| b.block_hash()).collect();
        let header_hashes_all : Vec<(BurnchainHeaderHash, Option<BlockHeaderHash>)> = burn_headers.iter().zip(block_hashes.iter()).map(|(ref burn, ref block)| ((*burn).clone(), Some((*block).clone()))).collect();

        // nothing is stored, so our inventory should be empty 
        let block_inv_all = chainstate.get_blocks_inventory(&header_hashes_all).unwrap();

        assert_eq!(block_inv_all.bitlen as usize, block_hashes.len());
        for i in 0..blocks.len() {
            assert!(!block_inv_all.has_ith_block(i as u16));
            assert!(!block_inv_all.has_ith_microblock_stream(i as u16));
        }

        // store all microblocks to staging
        for (i, ((block, burn_header), mblocks)) in blocks.iter().zip(&burn_headers).zip(&microblocks).enumerate() {
            test_debug!("Store microblock stream {} to staging", i);
            for mblock in mblocks.iter() {
                store_staging_microblock(&mut chainstate, burn_header, &block.block_hash(), mblock);
            }
        }
        
        // no anchored blocks are stored, so our block inventory should _still_ be empty 
        let block_inv_all = chainstate.get_blocks_inventory(&header_hashes_all).unwrap();

        assert_eq!(block_inv_all.bitlen as usize, block_hashes.len());
        for i in 0..blocks.len() {
            assert!(!block_inv_all.has_ith_block(i as u16));
            assert!(!block_inv_all.has_ith_microblock_stream(i as u16));        // because anchord blocks are missing, microblocks won't be reported either
        }

        // store blocks to staging
        for i in 0..blocks.len() {
            test_debug!("Store block {} to staging", i);
            assert!(StacksChainState::load_staging_block_data(&chainstate.blocks_db, &chainstate.blocks_path, &burn_headers[i], &blocks[i].block_hash()).unwrap().is_none());

            store_staging_block(&mut chainstate, &burn_headers[i], get_epoch_time_secs(), &blocks[i], &parent_burn_headers[i], 1, 2);
            assert_block_staging_not_processed(&mut chainstate, &burn_headers[i], &blocks[i]);
        
            // some anchored blocks are stored (to staging)
            let block_inv_all = chainstate.get_blocks_inventory(&header_hashes_all).unwrap();
            assert_eq!(block_inv_all.bitlen as usize, block_hashes.len());
            for j in 0..(i+1) {
                assert!(block_inv_all.has_ith_block(j as u16), format!("Missing block {} from bitvec {}", j, to_hex(&block_inv_all.block_bitvec)));

                // microblocks not stored yet, so they should be marked absent
                assert!(!block_inv_all.has_ith_microblock_stream(j as u16), format!("Have microblock {} from bitvec {}", j, to_hex(&block_inv_all.microblocks_bitvec)));
            }
            for j in i+1..blocks.len() {
                assert!(!block_inv_all.has_ith_block(j as u16));
                assert!(!block_inv_all.has_ith_microblock_stream(j as u16));
            }
        }

        // confirm blocks and microblocks 
        for i in 0..blocks.len() {
            test_debug!("Confirm block {} and its microblock stream", i);
            set_block_processed(&mut chainstate, &burn_headers[i], &block_hashes[i], true);

            // have block, but stream is still empty
            let block_inv_all = chainstate.get_blocks_inventory(&header_hashes_all).unwrap();
            assert!(!block_inv_all.has_ith_microblock_stream(i as u16));

            for k in 0..2 {
                set_microblocks_confirmed(&mut chainstate, &burn_headers[i], &block_hashes[i], k);

                let block_inv_all = chainstate.get_blocks_inventory(&header_hashes_all).unwrap();
                for j in 0..blocks.len() {
                    // still have all the blocks
                    assert!(block_inv_all.has_ith_block(j as u16));

                    if j <= i {
                        assert!(block_inv_all.has_ith_microblock_stream(j as u16));
                    }
                    else {
                        assert!(!block_inv_all.has_ith_microblock_stream(j as u16));
                    }
                }
            }
        }

        // mark blocks as empty.  Should also orphan its descendent microblock stream
        for i in 0..blocks.len() {
            test_debug!("Mark block {} as invalid", i);
            StacksChainState::free_block(&chainstate.blocks_path, &burn_headers[i], &blocks[i].block_hash());
            
            // some anchored blocks are stored (to staging)
            let block_inv_all = chainstate.get_blocks_inventory(&header_hashes_all).unwrap();
            assert_eq!(block_inv_all.bitlen as usize, block_hashes.len());
            for j in 0..(i+1) {
                assert!(!block_inv_all.has_ith_block(j as u16), format!("Have orphaned block {} from bitvec {}", j, to_hex(&block_inv_all.block_bitvec)));
                assert!(block_inv_all.has_ith_microblock_stream(j as u16), format!("Missing microblock {} from bitvec {}", j, to_hex(&block_inv_all.microblocks_bitvec)));
            }
            for j in i+1..blocks.len() {
                assert!(block_inv_all.has_ith_block(j as u16));
                assert!(block_inv_all.has_ith_microblock_stream(j as u16));
            }
        }
        
        // mark microblocks as empty.  Should also orphan its descendent microblock stream
        for i in 0..blocks.len() {
            test_debug!("Mark block {} as invalid", i);
            let index_hash = StacksBlockHeader::make_index_block_hash(&burn_headers[i], &blocks[i].block_hash());
            let mblock_index_hash = chainstate.get_confirmed_microblock_index_hash(&index_hash).unwrap().unwrap();
            let mblock_path = StacksChainState::get_index_block_path(&chainstate.blocks_path, &mblock_index_hash).unwrap();
            
            fs::OpenOptions::new()
                .read(false)
                .write(true)
                .truncate(true)
                .open(&mblock_path)
                .expect(&format!("FATAL: Failed to mark block path '{}' as free", &mblock_path));
            
            // some anchored blocks are stored (to staging)
            let block_inv_all = chainstate.get_blocks_inventory(&header_hashes_all).unwrap();
            assert_eq!(block_inv_all.bitlen as usize, block_hashes.len());
            for j in 0..(i+1) {
                assert!(!block_inv_all.has_ith_block(j as u16), format!("Have orphaned block {} from bitvec {}", j, to_hex(&block_inv_all.block_bitvec)));
                assert!(!block_inv_all.has_ith_microblock_stream(j as u16), format!("Have orphaned microblock {} from bitvec {}", j, to_hex(&block_inv_all.microblocks_bitvec)));
            }
            for j in i+1..blocks.len() {
                assert!(!block_inv_all.has_ith_block(j as u16));
                assert!(block_inv_all.has_ith_microblock_stream(j as u16));
            }
        }
    }

   
    // TODO: test multiple anchored blocks confirming the same microblock stream (in the same
    // place, and different places, with/without orphans)
    // TODO: process_next_staging_block
    // TODO: test resource limits -- shouldn't be able to load microblock streams that are too big
}
