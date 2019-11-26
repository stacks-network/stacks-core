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
use burnchains::Address;

use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::db::blocks::*;
use chainstate::stacks::index::{
    TrieHash,
    MARFValue
};
use chainstate::stacks::index::marf::{
    MARF,
    BLOCK_HASH_TO_HEIGHT_MAPPING_KEY,
    BLOCK_HEIGHT_TO_HASH_MAPPING_KEY
};

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
    pub blocks_db: DBConn,
    pub clarity_state_index: MARF,
    pub headers_state_index: MARF,
    pub blocks_path: String,
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
    pub burn_header_hash: BurnchainHeaderHash,
    pub parent_block_hash: BlockHeaderHash,
    pub parent_burn_header_hash: BurnchainHeaderHash,
    pub coinbase: u128,
    pub tx_fees_anchored: u128,
    pub tx_fees_streamed: u128,
    pub stx_burns: u128,
    pub burnchain_commit_burn: u64,
    pub burnchain_sortition_burn: u64,
    pub fill: u64,          // fixed-point fraction of how full this block is, scaled up between 0 and 2**64 - 1 (i.e. 0x8000000000000000 == 50% full)
    pub miner: bool,        // is this a schedule payment for the block's miner?
    pub stacks_block_height: u64,
    pub vtxindex: u32
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksHeaderInfo {
    pub anchored_header: StacksBlockHeader,
    pub microblock_tail: Option<StacksMicroblockHeader>,
    pub block_height: u64,
    pub index_root: TrieHash,
    pub burn_header_hash: BurnchainHeaderHash
}

#[derive(Debug, Clone, PartialEq)]
pub struct DBConfig {
    pub version: String,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl StacksHeaderInfo {
    pub fn index_block_hash(&self) -> BlockHeaderHash {
        self.anchored_header.index_block_hash(&self.burn_header_hash)
    }
    pub fn genesis() -> StacksHeaderInfo {
        StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis(),
            microblock_tail: None,
            block_height: 0,
            index_root: TrieHash([0u8; 32]),
            burn_header_hash: BurnchainHeaderHash([0u8; 32])
        }
    }
    pub fn is_genesis(&self) -> bool {
        self.anchored_header.is_genesis()
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
        let mut header_rows = vec!["block_height", "index_root", "burn_header_hash"];
        header_rows.append(&mut StacksBlockHeader::row_order());
        header_rows
    }
}

impl FromRow<StacksHeaderInfo> for StacksHeaderInfo {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StacksHeaderInfo, db_error> {
        let block_height_i64 : i64 = row.get(index);
        let index_root = TrieHash::from_row(row, index+1)?;
        let burn_header_hash = BurnchainHeaderHash::from_row(row, index+2)?;
        let stacks_header = StacksBlockHeader::from_row(row, index+3)?;
        
        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        Ok(StacksHeaderInfo {
            anchored_header: stacks_header, 
            microblock_tail: None,
            block_height: block_height_i64 as u64,
            index_root: index_root,
            burn_header_hash: burn_header_hash
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

    pub fn commit_to_block(self, height: u32, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> () {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_hash, block_hash);
        self.block.commit_to_block(&index_block_hash)
    }

    pub fn rollback_block(self) -> () {
        self.block.rollback_block()
    }

    pub fn connection(&mut self) -> &mut ClarityBlockConnection<'a> {
        &mut self.block
    }

    pub fn get_block_path(&mut self, burn_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> PathBuf {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(burn_hash, block_hash);
        self.block.get_marf().get_block_path(&index_block_hash)
    }
}

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
        parent_microblock_sequence INTEGER NOT NULL,
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
        burn_header_hash TEXT UNIQUE NOT NULL,       -- all burn header hashes are guaranteed to be unique

        PRIMARY KEY(burn_header_hash,block_hash)
    );
    "#,
    r#"
    CREATE INDEX block_headers_hash_index ON block_headers(block_hash,block_height);
    CREATE INDEX block_index_hash_index ON block_headers(index_block_hash,burn_header_hash,block_hash);
    "#,
    r#"
    -- scheduled payments
    -- no designated primary key since there can be duplicate entries
    CREATE TABLE payments(
        address TEXT NOT NULL,              -- miner that produced this block and microblock stream
        block_hash TEXT NOT NULL,
        burn_header_hash TEXT NOT NULL,
        parent_block_hash TEXT NOT NULL,
        parent_burn_header_hash TEXT NOT NULL,
        coinbase TEXT NOT NULL,             -- encodes u128
        tx_fees_anchored TEXT NOT NULL,     -- encodes u128
        tx_fees_streamed TEXT NOT NULL,     -- encodes u128
        stx_burns TEXT NOT NULL,            -- encodes u128
        burnchain_commit_burn INT NOT NULL,
        burnchain_sortition_burn INT NOT NULL,
        fill TEXT NOT NULL,                 -- encodes u64 
        miner INT NOT NULL,
        
        -- internal use
        stacks_block_height INTEGER NOT NULL,
        vtxindex INT NOT NULL               -- user burn support vtxindex
    );
    "#,
    r#"
    -- users who supported miners
    CREATE TABLE user_supporters(
        address TEXT NOT NULL,
        support_burn INT NOT NULL,
        block_hash TEXT NOT NULL,
        burn_header_hash TEXT NOT NULL,

        PRIMARY KEY(address,block_hash,burn_header_hash)
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
        parent_burn_header_hash TEXT NOT NULL,   -- matches the parent anchored block
        
        PRIMARY KEY(microblock_hash,parent_block_hash,parent_burn_header_hash),
        FOREIGN KEY(parent_burn_header_hash,parent_block_hash) REFERENCES block_headers(burn_header_hash,block_hash)
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

/// Built-in "system-level" smart contracts that are there from the beginning.
/// Includes BNS and the miner trust fund.
#[cfg(test)]
const STACKS_MINER_AUTH_KEY : &'static str = "a5879925788dcb3fe1f2737453e371ba04c4064e6609552ef59a126ac4fa598001";

#[cfg(test)]
const STACKS_BOOT_CODE : &'static [&'static str] = &[
    r#"
    (define-constant ERR-NO-PRINCIPAL 1)
    (define-constant ERR-NOT-AUTHORIZED 2)

    (define-constant AUTHORIZER 'ST3REJ5WQ42JGJZ6W77CX79JYMCVTKD73D6R6Z4R3)   ;; addr of STACKS_MINER_AUTH_KEY

    (define-map rewards
        ((participant principal))
        ((available uint) (authorized bool))
    )
    (define-private (get-participant-info (participant principal))
        (default-to (tuple (available u0) (authorized 'false)) (map-get rewards ((participant participant)))))

    (define-public (get-participant-reward (participant principal))
        (ok (get available (get-participant-info participant))))

    (define-public (is-participant-authorized? (participant principal))
        (ok (get authorized (get-participant-info participant))))

    ;; TODO: authorize STX withdrawals
    ;; TODO: withdraw STX
    "#
];


#[cfg(test)]
pub const STACKS_BOOT_CODE_CONTRACT_ADDRESS : &'static str = "ST000000000000000000002AMW42H";

#[cfg(test)]
const STACKS_BOOT_CODE_CONTRACT_NAMES : &'static [&'static str] = &[
    "miner-rewards"
];

pub const BOOT_CODE_MINER_CONTRACT_NAME : &'static str = "miner-rewards";
pub const BOOT_CODE_MINER_REWARDS_MAP : &'static str = "rewards";
pub const BOOT_CODE_MINER_REWARDS_PARTICIPANT : &'static str = "participant";
pub const BOOT_CODE_MINER_REWARDS_AVAILABLE : &'static str = "available";
pub const BOOT_CODE_MINER_REWARDS_AUTHORIZED : &'static str = "authorized";

#[cfg(test)]
pub const MINER_REWARD_MATURITY : u64 = 2;       // small for testing purposes

#[cfg(not(test))]
pub const MINER_REWARD_MATURITY : u64 = 100;

#[cfg(test)]
pub const MINER_REWARD_WINDOW : u64 = 5;       // small for testing purposes

#[cfg(not(test))]
pub const MINER_REWARD_WINDOW : u64 = 1008;

pub const MINER_FEE_MINIMUM_BLOCK_USAGE : u64 = 80;         // miner must share the first F% of the anchored block tx fees, and gets 100% - F% exclusively

pub const MINER_FEE_WINDOW : u64 = 24;                      // number of blocks (B) used to smooth over the fraction of tx fees they share from anchored blocks

#[cfg(not(test))]
pub const STACKS_BOOT_CODE_CONTRACT_ADDRESS : &'static str = "SP000000000000000000002Q6VF78";

// TODO
#[cfg(not(test))]
const STACKS_BOOT_CODE : &'static [&'static str] = &[
];

// TODO
#[cfg(not(test))]
const STACKS_BOOT_CODE_CONTRACT_NAMES : &'static [&'static str] = &[
];

impl StacksChainState {
    fn instantiate_headers_db(conn: &mut DBConn, mainnet: bool, chain_id: u32, marf_path: &str) -> Result<(), Error> {
        let tx = conn.transaction().map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        
        for cmd in STACKS_CHAIN_STATE_SQL {
            tx.execute(cmd, NO_PARAMS).map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }

        tx.execute("INSERT INTO db_config (version,mainnet,chain_id) VALUES (?1,?2,?3)", &[&STACKS_CHAINSTATE_VERSION, &(if mainnet { 1 } else { 0 }) as &dyn ToSql, &chain_id as &dyn ToSql])
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
    
    fn open_index(marf_path: &str) -> Result<MARF, Error> {
        test_debug!("Open MARF index at {}", marf_path);
        let marf = MARF::from_path(marf_path).map_err(|e| Error::DBError(db_error::IndexError(e)))?;
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

    /// Install the boot code into the chain history.
    /// TODO: instantiate all account balances as well.
    fn install_boot_code(chainstate: &mut StacksChainState, mainnet: bool, additional_boot_code_contract_names: &Vec<String>, additional_boot_code: &Vec<String>) -> Result<(), Error> {
        assert_eq!(STACKS_BOOT_CODE.len(), STACKS_BOOT_CODE_CONTRACT_NAMES.len());
        assert_eq!(additional_boot_code_contract_names.len(), additional_boot_code.len());
        
        let tx_version = 
            if mainnet {
                TransactionVersion::Mainnet
            }
            else {
                TransactionVersion::Testnet
            };

        let boot_code_address = StacksAddress::from_string(&STACKS_BOOT_CODE_CONTRACT_ADDRESS.to_string()).unwrap();
        let boot_code_auth = TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: boot_code_address.bytes.clone(),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            nonce: 0,
            signature: MessageSignature::empty()
        }));

        let mut boot_code_account = StacksAccount {
            principal: PrincipalData::Standard(StandardPrincipalData::from(boot_code_address.clone())),
            nonce: 0,
            stx_balance: 0
        };

        let mut clarity_tx = chainstate.block_begin(&BurnchainHeaderHash([0xff; 32]), &BlockHeaderHash([0xff; 32]), &BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]));
        for i in 0..STACKS_BOOT_CODE.len() {
            let smart_contract = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(STACKS_BOOT_CODE_CONTRACT_NAMES[i].to_string()).expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(&STACKS_BOOT_CODE[i].to_string()).expect("FATAL: invalid boot code body"),
                }
            );

            let boot_code_smart_contract = StacksTransaction::new(tx_version.clone(), boot_code_auth.clone(), smart_contract);
            StacksChainState::process_transaction_payload(&mut clarity_tx, &boot_code_smart_contract, &boot_code_account)?;

            boot_code_account.nonce += 1;
        }

        for i in 0..additional_boot_code.len() {
            let smart_contract = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(additional_boot_code_contract_names[i].clone()).expect("FATAL: invalid additional boot-code contract name"),
                    code_body: StacksString::from_str(&additional_boot_code[i]).expect("FATAL: invalid additional boot code body"),
                }
            );

            let boot_code_smart_contract = StacksTransaction::new(tx_version.clone(), boot_code_auth.clone(), smart_contract);
            StacksChainState::process_transaction_payload(&mut clarity_tx, &boot_code_smart_contract, &boot_code_account)?;
            
            boot_code_account.nonce += 1;
        }

        clarity_tx.commit_to_block(0, &BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]));
        Ok(())
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

        StacksChainState::mkdirs(&path)?;

        let mut blocks_path = path.clone();

        blocks_path.push("blocks");
        StacksChainState::mkdirs(&blocks_path)?;

        let blocks_path_root = blocks_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();

        blocks_path.push("staging.db");
        let blocks_db_path = blocks_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();

        let mut headers_path = path.clone();

        headers_path.push("vm");
        StacksChainState::mkdirs(&headers_path)?;

        headers_path.push("headers.db");
        let headers_db_path = headers_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();

        headers_path.pop();
        headers_path.push("clarity");
        let clarity_state_index_root = headers_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();

        headers_path.push("marf");
        let clarity_state_index_marf = headers_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();

        headers_path.pop();
        headers_path.pop();
        
        headers_path.push("index");
        let header_index_root = headers_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError))?.to_string();

        let index_exists = match fs::metadata(&clarity_state_index_marf) {
            Ok(_) => true,
            Err(_) => false
        };

        let headers_db = StacksChainState::open_headers_db(mainnet, chain_id, &headers_db_path, &clarity_state_index_marf)?;
        let blocks_db = StacksChainState::open_blocks_db(&blocks_db_path)?;

        let clarity_state_index = StacksChainState::open_index(&clarity_state_index_marf)?;
        let headers_state_index = StacksChainState::open_index(&header_index_root)?;

        let vm_state = sqlite_marf(&clarity_state_index_root, None).map_err(Error::ClarityInterpreterError)?;
        let clarity_state = ClarityInstance::new(vm_state);
        
        let mut chainstate = StacksChainState {
            mainnet: mainnet,
            chain_id: chain_id,
            clarity_state: clarity_state,
            headers_db: headers_db,
            blocks_db: blocks_db,
            clarity_state_index: clarity_state_index,
            headers_state_index: headers_state_index,
            blocks_path: blocks_path_root,
        };

        if !index_exists {
            StacksChainState::install_boot_code(&mut chainstate, mainnet, &vec![], &vec![])?;
        }

        Ok(chainstate)
    }

    pub fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            version: STACKS_CHAINSTATE_VERSION.to_string()
        }
    }
    
    /// Begin a transaction against the (indexed) stacks chainstate DB.
    pub fn headers_tx_begin<'a>(&'a mut self) -> Result<StacksDBTx<'a>, Error> {
        let tx = self.headers_db.transaction().map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        Ok(StacksDBTx::new(tx, &mut self.headers_state_index, ()))
    }
    
    /// Begin a transaction against our staging block index DB.
    pub fn blocks_tx_begin<'a>(&'a mut self) -> Result<StacksDBTx<'a>, Error> {
        let tx = self.blocks_db.transaction().map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        Ok(StacksDBTx::new(tx, &mut self.headers_state_index, ()))
    }

    /// Begin a transaction against the Clarity VM.
    pub fn block_begin<'a>(&'a mut self, parent_burn_hash: &BurnchainHeaderHash, parent_block: &BlockHeaderHash, new_burn_hash: &BurnchainHeaderHash, new_block: &BlockHeaderHash) -> ClarityTx<'a> {
        let conf = self.config();

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block = 
            if *parent_block == BlockHeaderHash([0xff; 32]) {
                // begin boot block
                test_debug!("Begin processing boot block");
                TrieFileStorage::block_sentinel()
            }
            else if *parent_block == BlockHeaderHash([0u8; 32]) {
                // begin first-ever block
                test_debug!("Begin processing first-ever block");
                StacksBlockHeader::make_index_block_hash(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]))
            }
            else {
                // subsequent block
                StacksBlockHeader::make_index_block_hash(parent_burn_hash, parent_block)
            };

        let new_index_block = StacksBlockHeader::make_index_block_hash(new_burn_hash, new_block);

        debug!("Begin processing Stacks block off of {}/{}", parent_burn_hash.to_hex(), parent_block.to_hex());
        test_debug!("Child MARF index root:  {} = {} + {}", new_index_block.to_hex(), new_burn_hash.to_hex(), new_block.to_hex());
        test_debug!("Parent MARF index root: {} = {} + {}", parent_index_block.to_hex(), parent_burn_hash.to_hex(), parent_block.to_hex());

        // NOTE: the miner uses the index hash block calculated from a burn header hash and
        // stacks header hash of all 0x01's for its next-block chain tip, so we'll need to do so as
        // well when validating this block.
        let miner_tip = StacksBlockHeader::make_index_block_hash(&BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));
        let clarity_tx = self.clarity_state.begin_block(&parent_index_block, &new_index_block, &miner_tip);

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: clarity_tx,
            config: conf
        }
    }
   
    /// Append a Stacks block to an existing Stacks block, and grant the miner the block reward.
    /// Return the new Stacks header info.
    pub fn advance_tip(&mut self, 
                       parent_tip: &StacksBlockHeader, 
                       parent_burn_block: &BurnchainHeaderHash, 
                       parent_block_height: u64, 
                       new_tip: &StacksBlockHeader, 
                       new_burn_block: &BurnchainHeaderHash, 
                       block_reward: &MinerPaymentSchedule,
                       user_burns: &Vec<StagingUserBurnSupport>) -> Result<StacksHeaderInfo, Error>
    {
        if new_tip.parent_block != BlockHeaderHash([0u8; 32]) {
            // not the first-ever block, so linkage must occur
            assert_eq!(new_tip.parent_block, parent_tip.block_hash());
        }
        let new_tip_block_height = parent_block_height.checked_add(1).expect("Block height overflow");

        let mut tx = self.headers_tx_begin()?;

        let parent_hash = 
            if parent_tip.is_genesis() {
                TrieFileStorage::block_sentinel()
            }
            else {
                parent_tip.index_block_hash(parent_burn_block)
            };

        // store each indexed field
        tx.put_indexed_begin(&parent_hash, &new_tip.index_block_hash(new_burn_block))
            .map_err(Error::DBError)?;
        let root_hash = tx.put_indexed_all(&vec![], &vec![])
            .map_err(Error::DBError)?;
        tx.indexed_commit()
            .map_err(Error::DBError)?;
        
        let new_tip_info = StacksHeaderInfo {
            anchored_header: new_tip.clone(),
            microblock_tail: None,
            index_root: root_hash,
            block_height: new_tip_block_height,
            burn_header_hash: new_burn_block.clone()
        };

        StacksChainState::insert_stacks_block_header(&mut tx, &new_tip_info)?;
        StacksChainState::insert_miner_payment_schedule(&mut tx, block_reward, user_burns)?;

        tx.commit().map_err(Error::DBError)?;
        
        debug!("Advanced to new tip! {}/{}", new_burn_block.to_hex(), new_tip.block_hash());
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

    pub fn open_chainstate(mainnet: bool, chain_id: u32, test_name: &str) -> StacksChainState {
        let path = format!("/tmp/blockstack-test-chainstate-{}", test_name);
        StacksChainState::open(mainnet, chain_id, &path).unwrap()
    }

    #[test]
    fn test_instantiate_chainstate() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "instantiate-chainstate");

        // verify that the boot code is there
        let mut conn = chainstate.block_begin(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]), &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let boot_code_address = StacksAddress::from_string(&STACKS_BOOT_CODE_CONTRACT_ADDRESS.to_string()).unwrap();
        for boot_contract_name in STACKS_BOOT_CODE_CONTRACT_NAMES.iter() {
            let boot_contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(boot_code_address.clone()), ContractName::try_from(boot_contract_name.to_string()).unwrap());
            let contract_res = StacksChainState::get_contract(&mut conn, &boot_contract_id).unwrap();
            assert!(contract_res.is_some());
        }
    }
}

