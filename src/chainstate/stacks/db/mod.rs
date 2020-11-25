// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

pub mod accounts;
pub mod blocks;
pub mod contracts;
pub mod headers;
pub mod transactions;
pub mod unconfirmed;

use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::OpenFlags;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::NO_PARAMS;

use std::fmt;
use std::fs;
use std::io;
use std::io::prelude::*;

use core::*;

use burnchains::{Address, Burnchain, BurnchainParameters};

use chainstate::burn::db::sortdb::{SortitionDB, SortitionDBConn};
use chainstate::burn::ConsensusHash;

use chainstate::stacks::db::accounts::*;
use chainstate::stacks::db::blocks::*;
use chainstate::stacks::events::*;
use chainstate::stacks::index::marf::{
    MarfConnection, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF,
};
use chainstate::stacks::index::{MARFValue, MarfTrieId, TrieHash};
use chainstate::stacks::Error;
use chainstate::stacks::*;

use chainstate::stacks::index::storage::TrieFileStorage;

use chainstate::burn::db::sortdb::BlockHeaderCache;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    db_mkdirs, query_count, query_row, tx_begin_immediate, tx_busy_handler, DBConn, DBTx,
    FromColumn, FromRow, IndexDBTx,
};

use util::hash::to_hex;

use chainstate::burn::db::sortdb::*;

use chainstate::stacks::boot::*;

use net::Error as net_error;

use vm::analysis::analysis_db::AnalysisDatabase;
use vm::analysis::run_analysis;
use vm::ast::build_ast;
use vm::clarity::{
    ClarityBlockConnection, ClarityConnection, ClarityInstance, ClarityReadOnlyConnection,
    Error as clarity_error,
};
use vm::contexts::OwnedEnvironment;
use vm::costs::ExecutionCost;
use vm::database::marf::MarfedKV;
use vm::database::{
    BurnStateDB, ClarityDatabase, HeadersDB, STXBalance, SqliteConnection, NULL_BURN_STATE_DB,
};
use vm::representations::ClarityName;
use vm::representations::ContractName;

use core::CHAINSTATE_VERSION;

use chainstate::stacks::db::unconfirmed::UnconfirmedState;

pub struct StacksChainState {
    pub mainnet: bool,
    pub chain_id: u32,
    clarity_state: ClarityInstance,
    pub blocks_db: DBConn,
    pub headers_state_index: MARF<StacksBlockId>,
    pub blocks_path: String,
    pub clarity_state_index_path: String, // path to clarity MARF
    pub clarity_state_index_root: String, // path to dir containing clarity MARF and side-store
    pub root_path: String,
    cached_miner_payments: MinerPaymentCache,
    pub block_limit: ExecutionCost,
    pub unconfirmed_state: Option<UnconfirmedState>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksAccount {
    pub principal: PrincipalData,
    pub nonce: u64,
    pub stx_balance: STXBalance,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerPaymentSchedule {
    pub address: StacksAddress,
    pub block_hash: BlockHeaderHash,
    pub consensus_hash: ConsensusHash,
    pub parent_block_hash: BlockHeaderHash,
    pub parent_consensus_hash: ConsensusHash,
    pub coinbase: u128,
    pub tx_fees_anchored: u128,
    pub tx_fees_streamed: u128,
    pub stx_burns: u128,
    pub burnchain_commit_burn: u64,
    pub burnchain_sortition_burn: u64,
    pub fill: u64, // fixed-point fraction of how full this block is, scaled up between 0 and 2**64 - 1 (i.e. 0x8000000000000000 == 50% full)
    pub miner: bool, // is this a schedule payment for the block's miner?
    pub stacks_block_height: u64,
    pub vtxindex: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksHeaderInfo {
    pub anchored_header: StacksBlockHeader,
    pub microblock_tail: Option<StacksMicroblockHeader>,
    pub block_height: u64,
    pub index_root: TrieHash,
    pub consensus_hash: ConsensusHash,
    pub burn_header_hash: BurnchainHeaderHash,
    pub burn_header_height: u32,
    pub burn_header_timestamp: u64,
    pub total_liquid_ustx: u128,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerRewardInfo {
    pub from_block_consensus_hash: ConsensusHash,
    pub from_stacks_block_hash: BlockHeaderHash,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksEpochReceipt {
    pub header: StacksHeaderInfo,
    pub tx_receipts: Vec<StacksTransactionReceipt>,
    pub matured_rewards: Vec<MinerReward>,
    pub matured_rewards_info: Option<MinerRewardInfo>,
    pub parent_microblocks_cost: ExecutionCost,
    pub anchored_block_cost: ExecutionCost,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DBConfig {
    pub version: String,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl StacksHeaderInfo {
    pub fn index_block_hash(&self) -> StacksBlockId {
        self.anchored_header.index_block_hash(&self.consensus_hash)
    }

    pub fn regtest_genesis(total_liquid_ustx: u128) -> StacksHeaderInfo {
        let burnchain_params = BurnchainParameters::bitcoin_regtest();
        StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis_block_header(),
            microblock_tail: None,
            block_height: 0,
            index_root: TrieHash([0u8; 32]),
            burn_header_hash: burnchain_params.first_block_hash.clone(),
            burn_header_height: burnchain_params.first_block_height as u32,
            consensus_hash: ConsensusHash::empty(),
            burn_header_timestamp: 0,
            total_liquid_ustx,
        }
    }

    pub fn genesis(
        root_hash: TrieHash,
        initial_liquid_ustx: u128,
        first_burnchain_block_hash: &BurnchainHeaderHash,
        first_burnchain_block_height: u32,
        first_burnchain_block_timestamp: u64,
    ) -> StacksHeaderInfo {
        StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis_block_header(),
            microblock_tail: None,
            block_height: 0,
            index_root: root_hash,
            burn_header_hash: first_burnchain_block_hash.clone(),
            burn_header_height: first_burnchain_block_height,
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            burn_header_timestamp: first_burnchain_block_timestamp,
            total_liquid_ustx: initial_liquid_ustx,
        }
    }

    pub fn is_first_mined(&self) -> bool {
        self.anchored_header.is_first_mined()
    }
}

impl FromRow<DBConfig> for DBConfig {
    fn from_row<'a>(row: &'a Row) -> Result<DBConfig, db_error> {
        let version: String = row.get("version");
        let mainnet_i64: i64 = row.get("mainnet");
        let chain_id_i64: i64 = row.get("chain_id");

        let mainnet = mainnet_i64 != 0;
        let chain_id = chain_id_i64 as u32;

        Ok(DBConfig {
            version,
            mainnet,
            chain_id,
        })
    }
}

impl FromRow<StacksHeaderInfo> for StacksHeaderInfo {
    fn from_row<'a>(row: &'a Row) -> Result<StacksHeaderInfo, db_error> {
        let block_height = u64::from_column(row, "block_height")?;
        let index_root = TrieHash::from_column(row, "index_root")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let burn_header_height = u64::from_column(row, "burn_header_height")? as u32;
        let burn_header_timestamp = u64::from_column(row, "burn_header_timestamp")?;
        let stacks_header = StacksBlockHeader::from_row(row)?;
        let total_liquid_ustx_str: String = row.get("total_liquid_ustx");
        let total_liquid_ustx = total_liquid_ustx_str
            .parse::<u128>()
            .map_err(|_| db_error::ParseError)?;

        if block_height != stacks_header.total_work.work {
            return Err(db_error::ParseError);
        }

        Ok(StacksHeaderInfo {
            anchored_header: stacks_header,
            microblock_tail: None,
            block_height: block_height,
            index_root: index_root,
            consensus_hash: consensus_hash,
            burn_header_hash: burn_header_hash,
            burn_header_height: burn_header_height,
            burn_header_timestamp: burn_header_timestamp,
            total_liquid_ustx: total_liquid_ustx,
        })
    }
}

pub type StacksDBTx<'a> = IndexDBTx<'a, (), StacksBlockId>;

pub struct BlocksDBTx<'a> {
    pub tx: DBTx<'a>,
    pub blocks_path: String,
}

impl<'a> Deref for BlocksDBTx<'a> {
    type Target = DBTx<'a>;
    fn deref(&self) -> &DBTx<'a> {
        &self.tx
    }
}

impl<'a> DerefMut for BlocksDBTx<'a> {
    fn deref_mut(&mut self) -> &mut DBTx<'a> {
        &mut self.tx
    }
}

impl<'a> BlocksDBTx<'a> {
    pub fn new(tx: DBTx, blocks_path: String) -> BlocksDBTx {
        BlocksDBTx { tx, blocks_path }
    }

    pub fn get_blocks_path(&self) -> &String {
        &self.blocks_path
    }

    pub fn commit(self) -> Result<(), db_error> {
        self.tx.commit().map_err(db_error::SqliteError)
    }
}

pub struct ClarityTx<'a> {
    block: ClarityBlockConnection<'a>,
    pub config: DBConfig,
}

impl ClarityConnection for ClarityTx<'_> {
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase),
    {
        ClarityConnection::with_clarity_db_readonly_owned(&mut self.block, to_do)
    }

    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R,
    {
        self.block.with_analysis_db_readonly(to_do)
    }
}

impl<'a> ClarityTx<'a> {
    pub fn get_root_hash(&mut self) -> TrieHash {
        self.block.get_root_hash()
    }

    pub fn cost_so_far(&self) -> ExecutionCost {
        self.block.cost_so_far()
    }

    #[cfg(test)]
    pub fn commit_block(self) -> () {
        self.block.commit_block();
    }

    pub fn commit_mined_block(self, block_hash: &StacksBlockId) -> ExecutionCost {
        self.block.commit_mined_block(block_hash).get_total()
    }

    pub fn commit_to_block(
        self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> () {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        self.block.commit_to_block(&index_block_hash);
    }

    pub fn commit_unconfirmed(self) -> () {
        self.block.commit_unconfirmed();
    }

    pub fn rollback_block(self) -> () {
        self.block.rollback_block()
    }

    pub fn rollback_unconfirmed(self) -> () {
        self.block.rollback_unconfirmed()
    }

    pub fn reset_cost(&mut self, cost: ExecutionCost) -> () {
        self.block.reset_block_cost(cost);
    }

    pub fn connection(&mut self) -> &mut ClarityBlockConnection<'a> {
        &mut self.block
    }
}

pub struct ChainstateTx<'a> {
    pub config: DBConfig,
    pub headers_tx: StacksDBTx<'a>,
    pub blocks_tx: BlocksDBTx<'a>,
    pub miner_payment_cache: &'a mut MinerPaymentCache,
}

impl<'a> ChainstateTx<'a> {
    pub fn get_config(&self) -> &DBConfig {
        &self.config
    }

    pub fn commit(self) -> Result<(), db_error> {
        self.headers_tx.commit()?;
        self.blocks_tx.commit()
    }

    #[cfg(feature = "tx_log")]
    pub fn log_transactions_processed(
        &self,
        block_id: &StacksBlockId,
        events: &[StacksTransactionReceipt],
    ) {
        let insert =
            "INSERT INTO transactions (txid, index_block_hash, tx_hex, result) VALUES (?, ?, ?, ?)";
        for tx_event in events.iter() {
            let txid = tx_event.transaction.txid();
            let tx_hex = to_hex(&tx_event.transaction.serialize_to_vec());
            let result = tx_event.result.to_string();
            let params: &[&dyn ToSql] = &[&txid, block_id, &tx_hex, &result];
            if let Err(e) = self.headers_tx.tx().execute(insert, params) {
                warn!("Failed to log TX: {}", e);
            }
        }
    }

    #[cfg(not(feature = "tx_log"))]
    pub fn log_transactions_processed(
        &self,
        _block_id: &StacksBlockId,
        _events: &[StacksTransactionReceipt],
    ) {
    }
}

/// Opaque structure for streaming block and microblock data from disk
#[derive(Debug, PartialEq, Clone)]
pub struct BlockStreamData {
    block_hash: StacksBlockId, // index block hash of the block or microblock stream head
    rowid: Option<i64>,        // used when reading a blob out of staging
    offset: u64, // offset into whatever is being read (the blob, or the file in the chunk store)
    total_bytes: u64, // total number of bytes read.

    // used only for microblocks
    is_microblock: bool,
    seq: u16,
    in_staging: bool,
}

// TODO: keep track of when microblock equivocations occur (maybe in the MARF?), so that once we
// process a PoisonMicroblock transaction, no further blocks may build off of any descendent fork.
const STACKS_CHAIN_STATE_SQL: &'static [&'static str] = &[
    "PRAGMA foreign_keys = ON;",
    r#"
    -- Anchored stacks block headers
    CREATE TABLE block_headers(
        version INTEGER NOT NULL,
        total_burn TEXT NOT NULL,       -- converted to/from u64
        total_work TEXT NOT NULL,       -- converted to/from u64 -- TODO: rename to total_length
        proof TEXT NOT NULL,
        parent_block TEXT NOT NULL,             -- hash of parent Stacks block
        parent_microblock TEXT NOT NULL,
        parent_microblock_sequence INTEGER NOT NULL,
        tx_merkle_root TEXT NOT NULL,
        state_index_root TEXT NOT NULL,
        microblock_pubkey_hash TEXT NOT NULL,
        
        block_hash TEXT NOT NULL,                   -- NOTE: this is *not* unique, since two burn chain forks can commit to the same Stacks block.
        index_block_hash TEXT UNIQUE NOT NULL,      -- NOTE: this is the hash of the block hash and consensus hash of the burn block that selected it, 
                                                    -- and is guaranteed to be globally unique (across all Stacks forks and across all PoX forks).
                                                    -- index_block_hash is the block hash fed into the MARF index.

        -- internal use only
        block_height INTEGER NOT NULL,
        index_root TEXT NOT NULL,                    -- root hash of the internal, not-consensus-critical MARF that allows us to track chainstate /fork metadata
        consensus_hash TEXT UNIQUE NOT NULL,         -- all consensus hashes are guaranteed to be unique
        burn_header_hash TEXT NOT NULL,              -- burn header hash corresponding to the consensus hash (NOT guaranteed to be unique, since we can have 2+ blocks per burn block if there's a PoX fork)
        burn_header_height INT NOT NULL,             -- height of the burnchain block header that generated this consensus hash
        burn_header_timestamp INT NOT NULL,          -- timestamp from burnchain block header that generated this consensus hash
        total_liquid_ustx TEXT NOT NULL,             -- string representation of the u128 that encodes the total number of liquid uSTX (i.e. that exist and aren't locked in the .lockup contract)
        parent_block_id TEXT NOT NULL,        -- NOTE: this is the parent index_block_hash

        cost TEXT NOT NULL,

        PRIMARY KEY(consensus_hash,block_hash)
    );
    "#,
    #[cfg(feature = "tx_log")]
    r#"
    CREATE TABLE transactions(
        id INTEGER PRIMARY KEY,
        txid TEXT NOT NULL,
        index_block_hash TEXT NOT NULL,
        tx_hex TEXT NOT NULL,
        result TEXT NOT NULL,
        UNIQUE (txid,index_block_hash)
    );
    CREATE INDEX txid_tx_index ON transactions(txid);
    CREATE INDEX index_block_hash_tx_index ON transactions(index_block_hash);
    "#,
    r#"
    CREATE INDEX block_headers_hash_index ON block_headers(block_hash,block_height);
    CREATE INDEX block_index_hash_index ON block_headers(index_block_hash,consensus_hash,block_hash);
    "#,
    r#"
    -- scheduled payments
    -- no designated primary key since there can be duplicate entries
    CREATE TABLE payments(
        address TEXT NOT NULL,              -- miner that produced this block and microblock stream
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        parent_block_hash TEXT NOT NULL,
        parent_consensus_hash TEXT NOT NULL,
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
        index_block_hash TEXT NOT NULL,     -- NOTE: can't enforce UNIQUE here, because there will be multiple entries per block
        vtxindex INT NOT NULL               -- user burn support vtxindex
    );
    "#,
    r#"
    -- users who supported miners
    CREATE TABLE user_supporters(
        address TEXT NOT NULL,
        support_burn INT NOT NULL,
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,

        PRIMARY KEY(address,block_hash,consensus_hash)
    );
    "#,
    r#"
    CREATE TABLE db_config(
        version TEXT NOT NULL,
        mainnet INTEGER NOT NULL,
        chain_id INTEGER NOT NULL
    )"#,
];

#[cfg(test)]
pub const MINER_REWARD_MATURITY: u64 = 2; // small for testing purposes

#[cfg(not(test))]
pub const MINER_REWARD_MATURITY: u64 = 100;

#[cfg(test)]
pub const MINER_REWARD_WINDOW: u64 = 5; // small for testing purposes

#[cfg(not(test))]
pub const MINER_REWARD_WINDOW: u64 = 16;

pub const MINER_FEE_MINIMUM_BLOCK_USAGE: u64 = 80; // miner must share the first F% of the anchored block tx fees, and gets 100% - F% exclusively

pub const MINER_FEE_WINDOW: u64 = 24; // number of blocks (B) used to smooth over the fraction of tx fees they share from anchored blocks

pub struct ChainStateBootData {
    pub first_burnchain_block_hash: BurnchainHeaderHash,
    pub first_burnchain_block_height: u32,
    pub first_burnchain_block_timestamp: u32,
    pub initial_balances: Vec<(PrincipalData, u64)>,
    pub post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx) -> ()>>,
}

impl ChainStateBootData {
    pub fn new(
        burnchain: &Burnchain,
        initial_balances: Vec<(PrincipalData, u64)>,
        post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx) -> ()>>,
    ) -> ChainStateBootData {
        ChainStateBootData {
            first_burnchain_block_hash: burnchain.first_block_hash.clone(),
            first_burnchain_block_height: burnchain.first_block_height as u32,
            first_burnchain_block_timestamp: burnchain.first_block_timestamp,
            initial_balances,
            post_flight_callback,
        }
    }
}

impl StacksChainState {
    fn instantiate_headers_db(
        mainnet: bool,
        chain_id: u32,
        marf_path: &str,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let mut marf = StacksChainState::open_index(marf_path)?;
        let mut dbtx = StacksDBTx::new(&mut marf, ());

        {
            let tx = dbtx.tx();

            for cmd in STACKS_CHAIN_STATE_SQL {
                tx.execute(cmd, NO_PARAMS)?;
            }

            tx.execute(
                "INSERT INTO db_config (version,mainnet,chain_id) VALUES (?1,?2,?3)",
                &[
                    &CHAINSTATE_VERSION,
                    &(if mainnet { 1 } else { 0 }) as &dyn ToSql,
                    &chain_id as &dyn ToSql,
                ],
            )?;
        }

        dbtx.instantiate_index()?;
        dbtx.commit()?;
        Ok(marf)
    }

    fn open_headers_db(
        mainnet: bool,
        chain_id: u32,
        index_path: &str,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let create_flag = fs::metadata(index_path).is_err();

        if create_flag {
            // instantiate!
            StacksChainState::instantiate_headers_db(mainnet, chain_id, index_path)
        } else {
            let marf = StacksChainState::open_index(index_path)?;
            // sanity check
            let db_config = query_row::<DBConfig, _>(
                marf.sqlite_conn(),
                &"SELECT * FROM db_config LIMIT 1".to_string(),
                NO_PARAMS,
            )?
            .expect("CORRUPTION: no db_config found");

            if db_config.mainnet != mainnet {
                error!(
                    "Invalid chain state database: expected mainnet = {}, got {}",
                    mainnet, db_config.mainnet
                );
                return Err(Error::InvalidChainstateDB);
            }

            if db_config.version != CHAINSTATE_VERSION {
                error!(
                    "Invalid chain state database: expected version = {}, got {}",
                    CHAINSTATE_VERSION, db_config.version
                );
                return Err(Error::InvalidChainstateDB);
            }

            if db_config.chain_id != chain_id {
                error!(
                    "Invalid chain ID: expected {}, got {}",
                    chain_id, db_config.chain_id
                );
                return Err(Error::InvalidChainstateDB);
            }

            Ok(marf)
        }
    }

    pub fn open_index(marf_path: &str) -> Result<MARF<StacksBlockId>, Error> {
        test_debug!("Open MARF index at {}", marf_path);
        let marf =
            MARF::from_path(marf_path).map_err(|e| Error::DBError(db_error::IndexError(e)))?;
        Ok(marf)
    }

    /// Idempotent `mkdir -p`
    fn mkdirs(path: &PathBuf) -> Result<String, Error> {
        match fs::metadata(path) {
            Ok(md) => {
                if !md.is_dir() {
                    error!("Not a directory: {:?}", path);
                    return Err(Error::DBError(db_error::ExistsError));
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::DBError(db_error::IOError(e)));
                }
                fs::create_dir_all(path).map_err(|e| Error::DBError(db_error::IOError(e)))?;
            }
        }

        let path_str = path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();
        Ok(path_str)
    }

    /// Install the boot code into the chain history.
    fn install_boot_code(
        chainstate: &mut StacksChainState,
        mainnet: bool,
        boot_data: &mut ChainStateBootData,
    ) -> Result<Vec<StacksTransactionReceipt>, Error> {
        debug!("Begin install boot code");

        let tx_version = if mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let boot_code_address = STACKS_BOOT_CODE_CONTRACT_ADDRESS.clone();
        let boot_code_auth = TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                signer: boot_code_address.bytes.clone(),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                nonce: 0,
                fee_rate: 0,
                signature: MessageSignature::empty(),
            },
        ));

        let mut boot_code_account = StacksAccount {
            principal: PrincipalData::Standard(boot_code_address.into()),
            nonce: 0,
            stx_balance: STXBalance::zero(),
        };

        let mut initial_liquid_ustx = 0u128;
        let mut receipts = vec![];

        {
            let mut clarity_tx = chainstate.block_begin(
                &NULL_BURN_STATE_DB,
                &BURNCHAIN_BOOT_CONSENSUS_HASH,
                &BOOT_BLOCK_HASH,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            let boot_code = if mainnet {
                *boot::STACKS_BOOT_CODE_MAINNET
            } else {
                *boot::STACKS_BOOT_CODE_TESTNET
            };
            for (boot_code_name, boot_code_contract) in boot_code.iter() {
                debug!(
                    "Instantiate boot code contract '{}.{}' ({} bytes)...",
                    &STACKS_BOOT_CODE_CONTRACT_ADDRESS_STR,
                    boot_code_name,
                    boot_code_contract.len()
                );

                let smart_contract = TransactionPayload::SmartContract(TransactionSmartContract {
                    name: ContractName::try_from(boot_code_name.to_string())
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(boot_code_contract)
                        .expect("FATAL: invalid boot code body"),
                });

                let boot_code_smart_contract = StacksTransaction::new(
                    tx_version.clone(),
                    boot_code_auth.clone(),
                    smart_contract,
                );

                let tx_receipt = clarity_tx.connection().as_transaction(|clarity| {
                    StacksChainState::process_transaction_payload(
                        clarity,
                        &boot_code_smart_contract,
                        &boot_code_account,
                    )
                })?;
                receipts.push(tx_receipt);

                boot_code_account.nonce += 1;
            }

            for (address, amount) in boot_data.initial_balances.iter() {
                clarity_tx.connection().as_transaction(|clarity| {
                    StacksChainState::account_genesis_credit(clarity, address, *amount)
                });
                initial_liquid_ustx = initial_liquid_ustx
                    .checked_add(*amount as u128)
                    .expect("FATAL: liquid STX overflow");
            }
            if let Some(callback) = boot_data.post_flight_callback.take() {
                callback(&mut clarity_tx);
            }

            clarity_tx.commit_to_block(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
        }

        {
            // add a block header entry for the boot code
            let mut headers_tx = chainstate.headers_tx_begin()?;
            let parent_hash = StacksBlockId::sentinel();
            let first_index_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );

            test_debug!(
                "Boot code headers index_put_begin {}-{}",
                &parent_hash,
                &first_index_hash
            );

            headers_tx.put_indexed_begin(&parent_hash, &first_index_hash)?;
            let first_root_hash = headers_tx.put_indexed_all(&vec![], &vec![])?;

            test_debug!(
                "Boot code headers index_commit {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_tip_info = StacksHeaderInfo::genesis(
                first_root_hash,
                initial_liquid_ustx,
                &boot_data.first_burnchain_block_hash,
                boot_data.first_burnchain_block_height,
                boot_data.first_burnchain_block_timestamp as u64,
            );

            StacksChainState::insert_stacks_block_header(
                &mut headers_tx,
                &parent_hash,
                &first_tip_info,
                &ExecutionCost::zero(),
            )?;
            headers_tx.commit()?;
        }

        debug!("Finish install boot code");
        Ok(receipts)
    }

    pub fn open(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        StacksChainState::open_and_exec(
            mainnet,
            chain_id,
            path_str,
            None,
            ExecutionCost::max_value(),
        )
    }

    /// Re-open the chainstate -- i.e. to get a new handle to it using an existing chain state's
    /// parameters
    pub fn reopen(&self) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        StacksChainState::open(self.mainnet, self.chain_id, &self.root_path)
    }

    /// Re-open the chainstate -- i.e. to get a new handle to it using an existing chain state's
    /// parameters, but with a block limit
    pub fn reopen_limited(
        &self,
        budget: ExecutionCost,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        StacksChainState::open_and_exec(self.mainnet, self.chain_id, &self.root_path, None, budget)
    }

    pub fn open_testnet<F>(
        chain_id: u32,
        path_str: &str,
        boot_data: Option<&mut ChainStateBootData>,
        block_limit: ExecutionCost,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        StacksChainState::open_and_exec(false, chain_id, path_str, boot_data, block_limit)
    }

    pub fn open_with_block_limit(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        block_limit: ExecutionCost,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        StacksChainState::open_and_exec(mainnet, chain_id, path_str, None, block_limit)
    }

    pub fn open_and_exec(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        boot_data: Option<&mut ChainStateBootData>,
        block_limit: ExecutionCost,
    ) -> Result<(StacksChainState, Vec<StacksTransactionReceipt>), Error> {
        let mut path = PathBuf::from(path_str);

        let chain_id_str = if mainnet {
            format!("chain-{}-mainnet", &to_hex(&chain_id.to_le_bytes()))
        } else {
            format!("chain-{}-testnet", &to_hex(&chain_id.to_le_bytes()))
        };

        path.push(chain_id_str);
        StacksChainState::mkdirs(&path)?;

        let mut blocks_path = path.clone();

        blocks_path.push("blocks");
        StacksChainState::mkdirs(&blocks_path)?;

        let blocks_path_root = blocks_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        blocks_path.push("staging.db");
        let blocks_db_path = blocks_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let mut headers_path = path.clone();

        headers_path.push("vm");
        StacksChainState::mkdirs(&headers_path)?;

        headers_path.push("clarity");
        let clarity_state_index_root = headers_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        headers_path.push("marf");
        let clarity_state_index_marf = headers_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        headers_path.pop();
        headers_path.pop();

        headers_path.push("index");
        let header_index_root = headers_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let init_required = match fs::metadata(&clarity_state_index_marf) {
            Ok(_) => false,
            Err(_) => true,
        };

        let headers_state_index =
            StacksChainState::open_headers_db(mainnet, chain_id, &header_index_root)?;
        let blocks_db = StacksChainState::open_blocks_db(&blocks_db_path)?;

        let vm_state = MarfedKV::open(
            &clarity_state_index_root,
            Some(&StacksBlockHeader::make_index_block_hash(
                &MINER_BLOCK_CONSENSUS_HASH,
                &MINER_BLOCK_HEADER_HASH,
            )),
        )
        .map_err(|e| Error::ClarityError(e.into()))?;

        let clarity_state = ClarityInstance::new(vm_state, block_limit.clone());

        let mut chainstate = StacksChainState {
            mainnet: mainnet,
            chain_id: chain_id,
            clarity_state: clarity_state,
            blocks_db: blocks_db,
            headers_state_index: headers_state_index,
            blocks_path: blocks_path_root,
            clarity_state_index_path: clarity_state_index_marf,
            clarity_state_index_root: clarity_state_index_root,
            root_path: path_str.to_string(),
            cached_miner_payments: MinerPaymentCache::new(),
            block_limit: block_limit,
            unconfirmed_state: None,
        };

        let mut receipts = vec![];
        match (init_required, boot_data) {
            (true, Some(boot_data)) => {
                let mut res =
                    StacksChainState::install_boot_code(&mut chainstate, mainnet, boot_data)?;
                receipts.append(&mut res);
            }
            (true, None) => {
                panic!(
                    "StacksChainState initialization is required, but boot_data was not passed."
                );
            }
            (false, _) => {}
        }

        Ok((chainstate, receipts))
    }

    pub fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            version: CHAINSTATE_VERSION.to_string(),
        }
    }

    /// Begin a transaction against the (indexed) stacks chainstate DB.
    pub fn headers_tx_begin<'a>(&'a mut self) -> Result<StacksDBTx<'a>, Error> {
        Ok(StacksDBTx::new(&mut self.headers_state_index, ()))
    }

    /// Begin a transaction against our staging block index DB.
    pub fn blocks_tx_begin<'a>(&'a mut self) -> Result<BlocksDBTx<'a>, Error> {
        let tx = tx_begin_immediate(&mut self.blocks_db)?;
        Ok(BlocksDBTx::new(tx, self.blocks_path.clone()))
    }

    /// Simultaneously begin a transaction against both the headers and blocks.
    /// Used when considering a new block to append the chain state.
    pub fn chainstate_tx_begin<'a>(
        &'a mut self,
    ) -> Result<(ChainstateTx<'a>, &'a mut ClarityInstance), Error> {
        let config = self.config();
        let blocks_inner_tx = tx_begin_immediate(&mut self.blocks_db)?;

        let blocks_path = self.blocks_path.clone();
        let clarity_instance = &mut self.clarity_state;
        let headers_tx = StacksDBTx::new(&mut self.headers_state_index, ());
        let blocks_tx = BlocksDBTx::new(blocks_inner_tx, blocks_path);

        let chainstate_tx = ChainstateTx {
            config: config,
            headers_tx: headers_tx,
            blocks_tx: blocks_tx,
            miner_payment_cache: &mut self.cached_miner_payments,
        };

        Ok((chainstate_tx, clarity_instance))
    }

    // NOTE: used for testing in the stacks testnet code.
    // DO NOT CALL FROM PRODUCTION
    pub fn clarity_eval_read_only(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Value {
        let result = self.clarity_state.eval_read_only(
            parent_id_bhh,
            self.headers_state_index.sqlite_conn(),
            burn_dbconn,
            contract,
            code,
        );
        result.unwrap()
    }

    pub fn clarity_eval_read_only_checked(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Result<Value, Error> {
        self.clarity_state
            .eval_read_only(
                parent_id_bhh,
                self.headers_state_index.sqlite_conn(),
                burn_dbconn,
                contract,
                code,
            )
            .map_err(Error::ClarityError)
    }

    pub fn headers_db(&self) -> &DBConn {
        self.headers_state_index.sqlite_conn()
    }

    /// Begin processing an epoch's transactions within the context of a chainstate transaction
    pub fn chainstate_block_begin<'a>(
        chainstate_tx: &'a ChainstateTx<'a>,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a> {
        let conf = chainstate_tx.config.clone();
        StacksChainState::inner_clarity_tx_begin(
            conf,
            chainstate_tx.headers_tx.deref().deref(),
            clarity_instance,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin a transaction against the Clarity VM, _outside of_ the context of a chainstate
    /// transaction.  Used by the miner for producing blocks.
    pub fn block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a> {
        let conf = self.config();
        StacksChainState::inner_clarity_tx_begin(
            conf,
            self.headers_state_index.sqlite_conn(),
            &mut self.clarity_state,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    pub fn with_clarity_marf<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut MARF<StacksBlockId>) -> R,
    {
        self.clarity_state.with_marf(f)
    }

    fn begin_read_only_clarity_tx<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        index_block: &StacksBlockId,
    ) -> ClarityReadOnlyConnection<'a> {
        self.clarity_state.read_only_connection(
            &index_block,
            self.headers_state_index.sqlite_conn(),
            burn_dbconn,
        )
    }

    /// Run to_do on the state of the Clarity VM at the given chain tip
    pub fn with_read_only_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &StacksBlockId,
        to_do: F,
    ) -> R
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        let mut conn = self.begin_read_only_clarity_tx(burn_dbconn, parent_tip);
        let result = to_do(&mut conn);
        conn.done();
        result
    }

    /// Run to_do on the unconfirmed Clarity VM state
    pub fn with_read_only_unconfirmed_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        to_do: F,
    ) -> Option<R>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        let mut unconfirmed_state_opt = self.unconfirmed_state.take();
        let res = if let Some(ref mut unconfirmed_state) = unconfirmed_state_opt {
            let mut conn = unconfirmed_state.clarity_inst.read_only_connection(
                &unconfirmed_state.unconfirmed_chain_tip,
                self.headers_db(),
                burn_dbconn,
            );
            let result = to_do(&mut conn);
            conn.done();
            Some(result)
        } else {
            None
        };
        self.unconfirmed_state = unconfirmed_state_opt;
        res
    }

    /// Run to_do on the unconfirmed Clarity VM state if the tip refers to the unconfirmed state;
    /// otherwise run to_do on the confirmed state of the Clarity VM.  If the tip doesn't exist,
    /// then return None.
    pub fn maybe_read_only_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &StacksBlockId,
        to_do: F,
    ) -> R
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        let unconfirmed = if let Some(ref unconfirmed_state) = self.unconfirmed_state {
            *parent_tip == unconfirmed_state.unconfirmed_chain_tip
        } else {
            false
        };

        if unconfirmed {
            self.with_read_only_unconfirmed_clarity_tx(burn_dbconn, to_do)
                .expect("BUG: both have and do not have unconfirmed chain state")
        } else {
            self.with_read_only_clarity_tx(burn_dbconn, parent_tip, to_do)
        }
    }

    fn get_parent_index_block(
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
    ) -> StacksBlockId {
        if *parent_block == BOOT_BLOCK_HASH {
            // begin boot block
            StacksBlockId::sentinel()
        } else if *parent_block == FIRST_STACKS_BLOCK_HASH {
            // begin first-ever block
            StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            // subsequent block
            StacksBlockHeader::make_index_block_hash(parent_consensus_hash, parent_block)
        }
    }

    /// Begin an unconfirmed VM transaction, if there's no other open transaction for it.
    pub fn begin_unconfirmed<'a>(
        conf: DBConfig,
        headers_db: &'a dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'a dyn BurnStateDB,
        tip: &StacksBlockId,
    ) -> ClarityTx<'a> {
        let inner_clarity_tx = clarity_instance.begin_unconfirmed(tip, headers_db, burn_dbconn);
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create a Clarity VM database transaction
    fn inner_clarity_tx_begin<'a>(
        conf: DBConfig,
        headers_db: &'a Connection,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a> {
        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            StacksChainState::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_block(
            &parent_index_block,
            &new_index_block,
            headers_db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Get the appropriate MARF index hash to use to identify a chain tip, given a block header
    pub fn get_index_hash(
        consensus_hash: &ConsensusHash,
        header: &StacksBlockHeader,
    ) -> StacksBlockId {
        if consensus_hash == &FIRST_BURNCHAIN_CONSENSUS_HASH {
            StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            header.index_block_hash(consensus_hash)
        }
    }

    /// See if a microblock public key hash was used in this fork already
    pub fn has_microblock_pubkey_hash<'a>(
        headers_tx: &mut StacksDBTx<'a>,
        tip_consensus_hash: &ConsensusHash,
        tip_header: &StacksBlockHeader,
        pubkey_hash: &Hash160,
    ) -> Result<bool, Error> {
        // we cannot have used this microblock public key hash before in this fork.
        // (this restriction is required to ensure that a poison microblock transaction can only apply to
        // a single epoch)
        let parent_hash = StacksChainState::get_index_hash(tip_consensus_hash, tip_header);
        match headers_tx
            .get_indexed(
                &parent_hash,
                &format!("chainstate::pubkey_hash::{}", pubkey_hash),
            )
            .map_err(Error::DBError)?
        {
            Some(_) => {
                // pubkey hash was seen before
                debug!(
                    "Public key hash {} already used (index hash {})",
                    pubkey_hash, &parent_hash
                );
                return Ok(true);
            }
            None => {
                // pubkey hash was never before seen
                return Ok(false);
            }
        }
    }

    /// Append a Stacks block to an existing Stacks block, and grant the miner the block reward.
    /// Return the new Stacks header info.
    pub fn advance_tip<'a>(
        headers_tx: &mut StacksDBTx<'a>,
        parent_tip: &StacksBlockHeader,
        parent_consensus_hash: &ConsensusHash,
        new_tip: &StacksBlockHeader,
        new_consensus_hash: &ConsensusHash,
        new_burn_header_hash: &BurnchainHeaderHash,
        new_burnchain_height: u32,
        new_burnchain_timestamp: u64,
        microblock_tail_opt: Option<StacksMicroblockHeader>,
        block_reward: &MinerPaymentSchedule,
        user_burns: &Vec<StagingUserBurnSupport>,
        total_liquid_ustx: u128,
        anchor_block_cost: &ExecutionCost,
    ) -> Result<StacksHeaderInfo, Error> {
        if new_tip.parent_block != FIRST_STACKS_BLOCK_HASH {
            // not the first-ever block, so linkage must occur
            assert_eq!(new_tip.parent_block, parent_tip.block_hash());
        }

        assert_eq!(
            parent_tip
                .total_work
                .work
                .checked_add(1)
                .expect("Block height overflow"),
            new_tip.total_work.work
        );

        let parent_hash = StacksChainState::get_index_hash(parent_consensus_hash, parent_tip);
        let indexed_keys = vec![format!(
            "chainstate::pubkey_hash::{}",
            new_tip.microblock_pubkey_hash
        )];

        let indexed_values = vec!["1".to_string()];

        // store each indexed field
        test_debug!(
            "Headers index_put_begin {}-{}",
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash)
        );
        headers_tx
            .put_indexed_begin(&parent_hash, &new_tip.index_block_hash(new_consensus_hash))?;
        let root_hash = headers_tx.put_indexed_all(&indexed_keys, &indexed_values)?;
        test_debug!(
            "Headers index_indexed_all finished {}-{}",
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash)
        );

        let new_tip_info = StacksHeaderInfo {
            anchored_header: new_tip.clone(),
            microblock_tail: microblock_tail_opt,
            index_root: root_hash,
            block_height: new_tip.total_work.work,
            consensus_hash: new_consensus_hash.clone(),
            burn_header_hash: new_burn_header_hash.clone(),
            burn_header_height: new_burnchain_height,
            burn_header_timestamp: new_burnchain_timestamp,
            total_liquid_ustx,
        };

        StacksChainState::insert_stacks_block_header(
            headers_tx,
            &parent_hash,
            &new_tip_info,
            anchor_block_cost,
        )?;
        StacksChainState::insert_miner_payment_schedule(headers_tx, block_reward, user_burns)?;

        debug!(
            "Advanced to new tip! {}/{}",
            new_consensus_hash,
            new_tip.block_hash()
        );
        Ok(new_tip_info)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use chainstate::stacks::db::*;
    use chainstate::stacks::*;
    use std::fs;

    use vm::database::NULL_BURN_STATE_DB;

    pub fn instantiate_chainstate(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
    ) -> StacksChainState {
        instantiate_chainstate_with_balances(mainnet, chain_id, test_name, vec![])
    }

    pub fn instantiate_chainstate_with_balances(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        balances: Vec<(StacksAddress, u64)>,
    ) -> StacksChainState {
        let path = chainstate_path(test_name);
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            }
            Err(_) => {}
        };

        let initial_balances = balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
        };

        StacksChainState::open_and_exec(
            mainnet,
            chain_id,
            &path,
            Some(&mut boot_data),
            ExecutionCost::max_value(),
        )
        .unwrap()
        .0
    }

    pub fn open_chainstate(mainnet: bool, chain_id: u32, test_name: &str) -> StacksChainState {
        let path = chainstate_path(test_name);
        StacksChainState::open(mainnet, chain_id, &path).unwrap().0
    }

    pub fn chainstate_path(test_name: &str) -> String {
        format!("/tmp/blockstack-test-chainstate-{}", test_name)
    }

    #[test]
    fn test_instantiate_chainstate() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "instantiate-chainstate");

        // verify that the boot code is there
        let mut conn = chainstate.block_begin(
            &NULL_BURN_STATE_DB,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        );

        for (boot_contract_name, _) in STACKS_BOOT_CODE_TESTNET.iter() {
            let boot_contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(STACKS_BOOT_CODE_CONTRACT_ADDRESS.clone()),
                ContractName::try_from(boot_contract_name.to_string()).unwrap(),
            );
            let contract_res =
                StacksChainState::get_contract(&mut conn, &boot_contract_id).unwrap();
            assert!(contract_res.is_some());
        }
    }
}
