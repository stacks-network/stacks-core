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

pub mod accounts;
pub mod blocks;
pub mod contracts;
pub mod headers;
pub mod transactions;

use rusqlite::Transaction;
use rusqlite::Connection;
use rusqlite::NO_PARAMS;
use rusqlite::OpenFlags;
use rusqlite::types::ToSql;
use rusqlite::Row;

use std::io;
use std::io::prelude::*;
use std::fmt;
use std::fs;

use burnchains::BurnchainHeaderHash;

use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::index::TrieHash;
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::storage::TrieFileStorage;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    DBConn,
    DBTx,
    IndexDBTx,
    query_rows,
    query_count,
    RowOrder,
    FromRow,
    db_mkdirs,
};

use util::hash::to_hex;

use chainstate::burn::db::burndb::*;

use net::Error as net_error;

use vm::analysis::run_analysis;
use vm::analysis::analysis_db::AnalysisDatabase;
use vm::ast::build_ast;
use vm::contexts::OwnedEnvironment;
use vm::database::marf::sqlite_marf;
use vm::database::marf::MarfedKV;
use vm::database::SqliteConnection;
use vm::clarity::ClarityInstance;
use vm::clarity::ClarityBlockConnection;
use vm::clarity::Error as clarity_error;
use vm::representations::ClarityName;
use vm::representations::ContractName;

pub const STACKS_CHAINSTATE_VERSION: &'static str = "22.0.0.0";

pub struct StacksChainState {
    pub mainnet: bool,
    pub chain_id: u32,
    clarity_state: ClarityInstance,
    pub headers_db: DBConn,
    headers_index: MARF,
    pub blocks_path: String,
    db_path: String
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksAccount {
    pub principal: PrincipalData,
    pub nonce: u64,
    pub stx_balance: u128
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerPaymentSchedule {
    pub address: StacksAddress,
    pub block_hash: BlockHeaderHash,
    pub coinbase: u128,
    pub tx_fees_anchored: u128,
    pub tx_fees_streamed: u128,
    pub burns: u128,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksHeaderInfo {
    pub anchored_header: StacksBlockHeader,
    pub microblock_tail: Option<StacksMicroblockHeader>,
    pub block_height: u64,
    pub index_root: TrieHash,
    pub burn_block_hash: BurnchainHeaderHash
}

#[derive(Debug, Clone, PartialEq)]
pub struct DBConfig {
    pub version: String,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl StacksHeaderInfo {
    pub fn index_block_hash(&self) -> BlockHeaderHash {
        self.anchored_header.index_block_hash(&self.burn_block_hash)
    }
}

impl RowOrder for DBConfig {
    fn row_order() -> Vec<&'static str> {
        vec!["version", "mainnet", "chain_id"]
    }
}

impl FromRow<DBConfig> for DBConfig {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<DBConfig, db_error> {
        let version : String = row.get(index);
        let mainnet_i64 : i64 = row.get(index + 1);
        let chain_id_i64 : i64 = row.get(index + 2);

        let mainnet = mainnet_i64 != 0;
        let chain_id = chain_id_i64 as u32;

        Ok(DBConfig {
            version,
            mainnet,
            chain_id
        })
    }
}

impl RowOrder for StacksHeaderInfo {
    fn row_order() -> Vec<&'static str> {
        let mut header_rows = vec!["block_height", "index_root", "burn_block_hash"];
        header_rows.append(&mut StacksBlockHeader::row_order());
        header_rows
    }
}

impl FromRow<StacksHeaderInfo> for StacksHeaderInfo {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StacksHeaderInfo, db_error> {
        let block_height_i64 : i64 = row.get(index);
        let index_root = TrieHash::from_row(row, index+1)?;
        let burn_block_hash = BurnchainHeaderHash::from_row(row, index+2)?;
        let stacks_header = StacksBlockHeader::from_row(row, index+3)?;
        
        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        Ok(StacksHeaderInfo {
            anchored_header: stacks_header, 
            microblock_tail: None,
            block_height: block_height_i64 as u64,
            index_root: index_root,
            burn_block_hash: burn_block_hash
        })
    }
}

pub type StacksDBTx<'a> = IndexDBTx<'a, ()>;

pub struct ClarityTx<'a> {
    block: ClarityBlockConnection<'a>,
    pub config: DBConfig
}

impl<'a> ClarityTx<'a> {
    pub fn get_root_hash(&mut self) -> TrieHash {
        self.block.get_root_hash()
    }

    pub fn commit_block(self) -> () {
        self.block.commit_block()
    }

    pub fn rollback_block(self) -> () {
        self.block.rollback_block()
    }

    pub fn connection(&mut self) -> &mut ClarityBlockConnection<'a> {
        &mut self.block
    }
}

// TODO: need to index Stacks blocks by both burn block hash and block hash, since the same block
// can be mined on two different burn chain forks (and both must be processed).
// This affects this code here, as well as burndb.
const STACKS_CHAIN_STATE_SQL : &'static [&'static str]= &[
    "PRAGMA foreign_keys = ON;",
    r#"
    -- Stacks block headers
    CREATE TABLE block_headers(
        version INTEGER NOT NULL,
        total_burn TEXT NOT NULL,       -- converted to/from u64
        total_work TEXT NOT NULL,       -- converted to/from u64
        proof TEXT NOT NULL,
        parent_block TEXT NOT NULL,
        parent_microblock TEXT NOT NULL,
        tx_merkle_root TEXT NOT NULL,
        state_index_root TEXT NOT NULL,
        microblock_pubkey_hash TEXT NOT NULL,
        
        -- NOTE: this is derived from the above
        block_hash TEXT NOT NULL,                   -- NOTE: this is *not* unique, since two burn chain forks can commit to the same Stacks block.
        index_block_hash TEXT UNIQUE NOT NULL,      -- NOTE: this is the hash of the block hash and burn block hash, and is guaranteed to be unqiue.
                                                    -- index_block_hash is the block hash fed into the MARF index.

        -- internal use only
        block_height INTEGER NOT NULL,
        index_root TEXT NOT NULL,                   -- TODO: this might not actually be needed
        burn_block_hash TEXT UNIQUE NOT NULL,       -- all burn header hashes are guaranteed to be unique

        PRIMARY KEY(burn_block_hash,block_hash)
    );
    "#,
    r#"
    CREATE INDEX block_headers_hash_index ON block_headers(block_hash,block_height);
    CREATE INDEX block_index_hash_index ON block_headers(index_block_hash,burn_block_hash,block_hash);
    "#,
    r#"
    -- scheduled payments
    CREATE TABLE payments(
        address TEXT NOT NULL,
        block_hash TEXT NOT NULL,
        burn_block_hash TEXT NOT NULL,
        coinbase TEXT NOT NULL,             -- encodes u128
        tx_fees_anchored TEXT NOT NULL,     -- encodes u128
        tx_fees_streamed TEXT NOT NULL,     -- encodes u128
        burns TEXT NOT NULL,                -- encodes u128
        
        -- internal use
        index_root TEXT NOT NULL,           -- TODO: this might not actually be needed
        block_height INTEGER NOT NULL,

        PRIMARY KEY(address,block_hash,burn_block_hash),
        FOREIGN KEY(index_root,burn_block_hash,block_hash) REFERENCES block_headers(index_root,burn_block_hash,block_hash)
    );
    "#,
    r#"
    -- microblock headers
    CREATE TABLE microblock_headers(
        version INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        prev_block TEXT NOT NULL,
        tx_merkle_root TEXT NOT NULL,
        signature TEXT NOT NULL,

        -- NOTE: this is derived from the above
        microblock_hash TEXT NOT NULL,

        -- internal use only
        block_height INTEGER NOT NULL,
        parent_block_hash TEXT NOT NULL,        -- matches the parent anchored block (and by extension, snapshot and block commit) to which this stream is appended
        parent_burn_block_hash TEXT NOT NULL,   -- matches the parent anchored block
        
        PRIMARY KEY(microblock_hash,parent_block_hash,parent_burn_block_hash),
        FOREIGN KEY(parent_burn_block_hash,parent_block_hash) REFERENCES block_headers(burn_block_hash,block_hash)
    );
    "#,
    r#"
    CREATE INDEX microblock_headers_hash ON microblock_headers(microblock_hash,block_height,parent_block_hash);
    "#,
    r#"
    CREATE TABLE db_config(
        version TEXT NOT NULL,
        mainnet INTEGER NOT NULL,
        chain_id INTEGER NOT NULL
    )"#
];

impl StacksChainState {
    fn instantiate_headers_db(conn: &mut DBConn, mainnet: bool, chain_id: u32, marf_path: &str) -> Result<(), Error> {
        let tx = conn.transaction().map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        for cmd in STACKS_CHAIN_STATE_SQL {
            tx.execute(cmd, NO_PARAMS).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }

        tx.execute("INSERT INTO db_config (version,mainnet,chain_id) VALUES (?1,?2,?3)", &[&STACKS_CHAINSTATE_VERSION, &(if mainnet { 1 } else { 0 }) as &ToSql, &chain_id as &ToSql])
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let mut marf = StacksChainState::open_index(marf_path)?;
        let mut dbtx = StacksDBTx::new(tx, &mut marf, ());
        
        dbtx.instantiate_index().map_err(Error::DBError)?;
        dbtx.commit().map_err(Error::DBError)?;
        Ok(())
    }
    
    fn open_headers_db(mainnet: bool, chain_id: u32, headers_path: &str, index_path: &str) -> Result<DBConn, Error> {
        let mut create_flag = false;
        let open_flags =
            if fs::metadata(headers_path).is_err() {
                // need to create 
                create_flag = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            }
            else {
                // can just open 
                OpenFlags::SQLITE_OPEN_READ_WRITE
            };

        let mut conn = DBConn::open_with_flags(headers_path, open_flags).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        if create_flag {
            // instantiate!
            StacksChainState::instantiate_headers_db(&mut conn, mainnet, chain_id, index_path)?;
        }
        else {
            // sanity check
            let rows = query_rows::<DBConfig, _>(&conn, &format!("SELECT {} FROM db_config LIMIT 1", DBConfig::row_order().join(",")), NO_PARAMS)
                .map_err(Error::DBError)?;

            let db_config = rows[0].clone();

            if db_config.mainnet != mainnet {
                error!("Invalid chain state database: expected mainnet = {}, got {}", mainnet, db_config.mainnet);
                return Err(Error::InvalidChainstateDB);
            }
            
            if db_config.version != STACKS_CHAINSTATE_VERSION {
                error!("Invalid chain state database: expected version = {}, got {}", STACKS_CHAINSTATE_VERSION, db_config.version);
                return Err(Error::InvalidChainstateDB);
            }

            if db_config.chain_id != chain_id {
                error!("Invalid chain ID: expected {}, got {}", chain_id, db_config.chain_id);
                return Err(Error::InvalidChainstateDB);
            }
        }

        Ok(conn)
    }
    
    fn open_index(index_root: &str) -> Result<MARF, Error> {
        test_debug!("Open index at {}", index_root);
        let marf = MARF::from_path(index_root).map_err(|e| Error::DBError(db_error::IndexError(e)))?;
        Ok(marf)
    }
    
    fn mkdirs(path: &PathBuf) -> Result<String, Error> {
        match fs::metadata(path) {
            Ok(md) => {
                if !md.is_dir() {
                    error!("Not a directory: {:?}", path);
                    return Err(Error::DBError(db_error::ExistsError));
                }
            },
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::DBError(db_error::IOError(e)));
                }
                fs::create_dir_all(path).map_err(|e| Error::DBError(db_error::IOError(e)))?;
            }
        }

        let path_str = path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        Ok(path_str)
    }
    
    pub fn open(mainnet: bool, chain_id: u32, path_str: &str) -> Result<StacksChainState, Error> {
        let mut path = PathBuf::from(path_str);

        let chain_id_str = 
            if mainnet {
                format!("chain-{}-mainnet", &to_hex(&chain_id.to_le_bytes()))
            }
            else {
                format!("chain-{}-testnet", &to_hex(&chain_id.to_le_bytes()))
            };

        path.push(chain_id_str);
        let root_path_str = path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        let (db_path, index_path) = db_mkdirs(&root_path_str).map_err(Error::DBError)?;

        path.push("blocks");
        StacksChainState::mkdirs(&path)?;

        let blocks_path = path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();
        let headers_db = StacksChainState::open_headers_db(mainnet, chain_id, &db_path, &index_path)?;
        let index = StacksChainState::open_index(&index_path)?;

        let vm_state = sqlite_marf(path_str, None).map_err(Error::ClarityInterpreterError)?;
        let clarity_state = ClarityInstance::new(vm_state);
        
        Ok(StacksChainState {
            mainnet: mainnet,
            chain_id: chain_id,
            clarity_state: clarity_state,
            headers_db: headers_db,
            headers_index: index,
            blocks_path: blocks_path,
            db_path: path_str.to_string()
        })
    }

    pub fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            version: STACKS_CHAINSTATE_VERSION.to_string()
        }
    }
    
    /// Begin a transaction against the (indexed) stacks chainstate DB.
    pub fn tx_begin<'a>(&'a mut self) -> Result<StacksDBTx<'a>, Error> {
        let tx = self.headers_db.transaction().map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        Ok(StacksDBTx::new(tx, &mut self.headers_index, ()))
    }

    /// Begin a transaction against the Clarity VM.
    pub fn block_begin<'a>(&'a mut self, parent_burn_hash: &BurnchainHeaderHash, parent_block: &BlockHeaderHash, new_burn_hash: &BurnchainHeaderHash, new_block: &BlockHeaderHash) -> ClarityTx<'a> {
        let conf = self.config();

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it nos guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block = 
            if *parent_block == TrieFileStorage::block_sentinel() {
                // begin first-ever block
                parent_block.clone()
            }
            else {
                // subsequent block
                StacksBlockHeader::make_index_block_hash(parent_burn_hash, parent_block)
            };

        let new_index_block = StacksBlockHeader::make_index_block_hash(new_burn_hash, new_block);
        let clarity_tx = self.clarity_state.begin_block(&parent_index_block, &new_index_block);
        ClarityTx {
            block: clarity_tx,
            config: conf
        }
    }
    
    /// Add fork-indexed fields.
    /// Nothing special here; we only need to store the height <--> index-block-hash mapping.
    fn index_add_fork_info<'a>(tx: &mut StacksDBTx<'a>, parent_tip: &StacksBlockHeader, parent_burn_block: &BurnchainHeaderHash, new_tip: &StacksBlockHeader, new_burn_block: &BurnchainHeaderHash) -> Result<TrieHash, Error> {
        let parent_block_hash = parent_tip.index_block_hash(parent_burn_block);
        let new_block_hash = new_tip.index_block_hash(new_burn_block);

        tx.put_indexed_begin(&parent_block_hash, &new_block_hash).map_err(Error::DBError)?;
        let root_hash = tx.put_indexed_all(&vec![], &vec![]).map_err(Error::DBError)?;
        tx.indexed_commit().map_err(Error::DBError)?;
        Ok(root_hash)
    }

    /// Append a Stacks block to an existing Stacks block, and grant the miner the block reward.
    /// Return the new Stacks header info.
    pub fn advance_tip(&mut self, parent_tip: &StacksBlockHeader, parent_burn_block: &BurnchainHeaderHash, parent_block_height: u64, new_tip: &StacksBlockHeader, new_burn_block: &BurnchainHeaderHash, block_reward: &MinerPaymentSchedule) -> Result<StacksHeaderInfo, Error> {
        assert_eq!(new_tip.parent_block, parent_tip.block_hash());
        let new_tip_block_height = parent_block_height.checked_add(1).expect("Block height overflow");

        let mut tx = self.tx_begin()?;
        let root_hash = StacksChainState::index_add_fork_info(&mut tx, parent_tip, parent_burn_block, new_tip, new_burn_block)?;

        let new_tip_info = StacksHeaderInfo {
            anchored_header: new_tip.clone(),
            microblock_tail: None,
            index_root: root_hash,
            block_height: new_tip_block_height,
            burn_block_hash: new_burn_block.clone()
        };

        StacksChainState::insert_stacks_block_header(&mut tx, &new_tip_info)?;
        StacksChainState::insert_miner_payment_schedule(&mut tx, &new_tip_info, block_reward)?;

        tx.commit().map_err(Error::DBError)?;
        Ok(new_tip_info)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use std::fs;
    
    pub fn instantiate_chainstate(mainnet: bool, chain_id: u32, test_name: &str) -> StacksChainState {
        let path = format!("/tmp/blockstack-test-chainstate-{}", test_name);
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };

        StacksChainState::open(mainnet, chain_id, &path).unwrap()
    }

    #[test]
    fn test_instantiate_chainstate() {
        let _ = instantiate_chainstate(false, 0x80000000, "instantiate-chainstate");
    }
}

