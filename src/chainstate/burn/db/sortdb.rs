// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
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

use std::cmp::Ord;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::convert::{From, TryFrom, TryInto};
use std::io::{ErrorKind, Write};
use std::ops::Deref;
use std::ops::DerefMut;
use std::{cmp, fmt, fs, str::FromStr};

use rand;
use rand::RngCore;
use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::TransactionBehavior;
use rusqlite::{Connection, OpenFlags, OptionalExtension, NO_PARAMS};
use sha2::{Digest, Sha512Trunc256};
use vm::costs::ExecutionCost;

use address::AddressHashMode;
use burnchains::BitcoinNetworkType;
use burnchains::{Address, PublicKey, Txid};
use burnchains::{
    Burnchain, BurnchainBlockHeader, BurnchainRecipient, BurnchainStateTransition,
    BurnchainTransaction, BurnchainView, Error as BurnchainError, PoxConstants,
};
use chainstate::burn::operations::{
    leader_block_commit::{MissedBlockCommit, RewardSetInfo, OUTPUTS_PER_COMMIT},
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp, StackStxOp,
    TransferStxOp, UserBurnSupportOp,
};
use chainstate::burn::Opcodes;
use chainstate::burn::{BlockSnapshot, ConsensusHash, OpsHash, SortitionHash};
use chainstate::coordinator::{Error as CoordinatorError, PoxAnchorBlockStatus, RewardCycleInfo};
use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use chainstate::stacks::index::marf::MarfConnection;
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::storage::TrieFileStorage;
use chainstate::stacks::index::{Error as MARFError, MarfTrieId};
use chainstate::stacks::StacksPublicKey;
use chainstate::stacks::*;
use chainstate::ChainstateDB;
use core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use core::FIRST_STACKS_BLOCK_HASH;
use core::{StacksEpoch, StacksEpochId, STACKS_EPOCH_MAX};
use net::neighbors::MAX_NEIGHBOR_BLOCK_DELAY;
use net::{Error as NetError, Error};
use util::get_epoch_time_secs;
use util::hash::{hex_bytes, to_hex, Hash160, Sha512Trunc256Sum};
use util::log;
use util::secp256k1::MessageSignature;
use util::vrf::*;
use util_lib::db::tx_begin_immediate;
use util_lib::db::tx_busy_handler;
use util_lib::db::Error as db_error;
use util_lib::db::{
    db_mkdirs, query_count, query_row, query_row_columns, query_row_panic, query_rows, sql_pragma,
    u64_to_sql, DBConn, FromColumn, FromRow, IndexDBConn, IndexDBTx,
};
use vm::representations::{ClarityName, ContractName};
use vm::types::Value;

use chainstate::burn::ConsensusHashExtensions;
use chainstate::stacks::address::StacksAddressExtensions;
use chainstate::stacks::index::{ClarityMarfTrieId, MARFValue};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, VRFSeed,
};

const BLOCK_HEIGHT_MAX: u64 = ((1 as u64) << 63) - 1;

pub const REWARD_WINDOW_START: u64 = 144 * 15;
pub const REWARD_WINDOW_END: u64 = 144 * 90 + REWARD_WINDOW_START;

pub type BlockHeaderCache = HashMap<ConsensusHash, (Option<BlockHeaderHash>, ConsensusHash)>;

impl FromRow<SortitionId> for SortitionId {
    fn from_row<'a>(row: &'a Row) -> Result<SortitionId, db_error> {
        SortitionId::from_column(row, "sortition_id")
    }
}

impl FromRow<MissedBlockCommit> for MissedBlockCommit {
    fn from_row<'a>(row: &'a Row) -> Result<MissedBlockCommit, db_error> {
        let intended_sortition = SortitionId::from_column(row, "intended_sortition_id")?;
        let input_json: String = row.get_unwrap("input");
        let input =
            serde_json::from_str(&input_json).map_err(|e| db_error::SerializationError(e))?;
        let txid = Txid::from_column(row, "txid")?;

        Ok(MissedBlockCommit {
            input,
            txid,
            intended_sortition,
        })
    }
}

impl FromRow<BlockSnapshot> for BlockSnapshot {
    fn from_row<'a>(row: &'a Row) -> Result<BlockSnapshot, db_error> {
        let block_height = u64::from_column(row, "block_height")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let burn_header_timestamp = u64::from_column(row, "burn_header_timestamp")?;
        let parent_burn_header_hash =
            BurnchainHeaderHash::from_column(row, "parent_burn_header_hash")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let ops_hash = OpsHash::from_column(row, "ops_hash")?;
        let total_burn_str: String = row.get_unwrap("total_burn");
        let sortition: bool = row.get_unwrap("sortition");
        let sortition_hash = SortitionHash::from_column(row, "sortition_hash")?;
        let winning_block_txid = Txid::from_column(row, "winning_block_txid")?;
        let winning_stacks_block_hash =
            BlockHeaderHash::from_column(row, "winning_stacks_block_hash")?;
        let index_root = TrieHash::from_column(row, "index_root")?;
        let num_sortitions = u64::from_column(row, "num_sortitions")?;

        // information we learn about the stacks block this snapshot committedto
        let stacks_block_accepted: bool = row.get_unwrap("stacks_block_accepted");
        let stacks_block_height = u64::from_column(row, "stacks_block_height")?;
        let arrival_index = u64::from_column(row, "arrival_index")?;

        // information about what we have determined about the stacks chain tip.
        // This is memoized to a given canonical chain tip block.
        let canonical_stacks_tip_height = u64::from_column(row, "canonical_stacks_tip_height")?;
        let canonical_stacks_tip_hash =
            BlockHeaderHash::from_column(row, "canonical_stacks_tip_hash")?;
        let canonical_stacks_tip_consensus_hash =
            ConsensusHash::from_column(row, "canonical_stacks_tip_consensus_hash")?;

        // identifiers derived from PoX forking state
        let sortition_id = SortitionId::from_column(row, "sortition_id")?;
        let parent_sortition_id = SortitionId::from_column(row, "parent_sortition_id")?;
        let pox_valid = row.get_unwrap("pox_valid");

        let accumulated_coinbase_ustx_str: String = row.get_unwrap("accumulated_coinbase_ustx");
        let accumulated_coinbase_ustx = accumulated_coinbase_ustx_str
            .parse::<u128>()
            .expect("DB CORRUPTION: failed to parse stored value");

        let total_burn = total_burn_str
            .parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        let snapshot = BlockSnapshot {
            block_height: block_height,
            burn_header_timestamp: burn_header_timestamp,
            burn_header_hash,
            parent_burn_header_hash,
            consensus_hash: consensus_hash,
            ops_hash: ops_hash,
            total_burn: total_burn,
            sortition: sortition,
            sortition_hash: sortition_hash,
            winning_block_txid: winning_block_txid,
            winning_stacks_block_hash: winning_stacks_block_hash,
            index_root: index_root,
            num_sortitions: num_sortitions,

            stacks_block_accepted: stacks_block_accepted,
            stacks_block_height: stacks_block_height,
            arrival_index: arrival_index,

            canonical_stacks_tip_height: canonical_stacks_tip_height,
            canonical_stacks_tip_hash: canonical_stacks_tip_hash,
            canonical_stacks_tip_consensus_hash: canonical_stacks_tip_consensus_hash,

            sortition_id,
            parent_sortition_id,
            pox_valid,
            accumulated_coinbase_ustx,
        };
        Ok(snapshot)
    }
}

impl FromRow<LeaderBlockCommitOp> for LeaderBlockCommitOp {
    fn from_row<'a>(row: &'a Row) -> Result<LeaderBlockCommitOp, db_error> {
        let txid = Txid::from_column(row, "txid")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "l1_block_id")?;
        let block_header_hash = BlockHeaderHash::from_column(row, "committed_block_hash")?;

        let block_commit = LeaderBlockCommitOp {
            block_header_hash,
            txid,
            burn_header_hash,
        };
        Ok(block_commit)
    }
}

struct AcceptedStacksBlockHeader {
    pub tip_consensus_hash: ConsensusHash, // PoX tip
    pub consensus_hash: ConsensusHash,     // stacks block consensus hash
    pub block_hash: BlockHeaderHash,       // stacks block hash
    pub height: u64,                       // stacks block height
}

pub struct InitialMiningBonus {
    pub total_reward: u128,
    pub per_block: u128,
}

impl FromRow<AcceptedStacksBlockHeader> for AcceptedStacksBlockHeader {
    fn from_row<'a>(row: &'a Row) -> Result<AcceptedStacksBlockHeader, db_error> {
        let tip_consensus_hash = ConsensusHash::from_column(row, "tip_consensus_hash")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let block_hash = BlockHeaderHash::from_column(row, "stacks_block_hash")?;
        let height = u64::from_column(row, "block_height")?;

        Ok(AcceptedStacksBlockHeader {
            tip_consensus_hash,
            consensus_hash,
            block_hash,
            height,
        })
    }
}

impl FromRow<StacksEpoch> for StacksEpoch {
    fn from_row<'a>(row: &'a Row) -> Result<StacksEpoch, db_error> {
        let epoch_id_u32: u32 = row.get_unwrap("epoch_id");
        let epoch_id = StacksEpochId::try_from(epoch_id_u32).map_err(|_| db_error::ParseError)?;

        let start_height = u64::from_column(row, "start_block_height")?;
        let end_height = u64::from_column(row, "end_block_height")?;

        let network_epoch: u8 = row.get_unwrap("network_epoch");

        let block_limit = row.get_unwrap("block_limit");
        Ok(StacksEpoch {
            epoch_id,
            start_height,
            end_height,
            block_limit,
            network_epoch,
        })
    }
}

pub const SORTITION_DB_VERSION: &'static str = "2";

const SORTITION_DB_INITIAL_SCHEMA: &'static [&'static str] = &[
    r#"
    PRAGMA foreign_keys = ON;
    "#,
    r#"
    -- sortition snapshots -- snapshot of all transactions processed in a burn block
    -- organizes the set of forks in the burn chain as well.
    CREATE TABLE snapshots(
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,
        sortition_id TEXT UNIQUE NOT NULL,
        parent_sortition_id TEXT NOT NULL,
        burn_header_timestamp INT NOT NULL,
        parent_burn_header_hash TEXT NOT NULL,
        consensus_hash TEXT UNIQUE NOT NULL,
        ops_hash TEXT NOT NULL,
        total_burn TEXT NOT NULL,
        sortition INTEGER NOT NULL,
        sortition_hash TEXT NOT NULL,
        winning_block_txid TEXT NOT NULL,
        winning_stacks_block_hash TEXT NOT NULL,
        index_root TEXT UNIQUE NOT NULL,

        num_sortitions INTEGER NOT NULL,

        stacks_block_accepted INTEGER NOT NULL,        -- set to 1 if we fetched and processed this Stacks block
        stacks_block_height INTEGER NOT NULL,           -- set to the height of the stacks block, once it's processed
        arrival_index INTEGER NOT NULL,                 -- (global) order in which this Stacks block was processed

        canonical_stacks_tip_height INTEGER NOT NULL,   -- height of highest known Stacks fork in this burn chain fork
        canonical_stacks_tip_hash TEXT NOT NULL,        -- hash of highest known Stacks fork's tip block in this burn chain fork
        canonical_stacks_tip_consensus_hash TEXT NOT NULL,   -- burn hash of highest known Stacks fork's tip block in this burn chain fork

        pox_valid INTEGER NOT NULL,

        accumulated_coinbase_ustx TEXT NOT NULL,

        PRIMARY KEY(sortition_id)
    );"#,
    r#"
    CREATE TABLE snapshot_transition_ops(
      sortition_id TEXT PRIMARY KEY,
      accepted_ops TEXT NOT NULL
    );"#,
    r#"
    -- all leader keys registered in the blockchain.
    -- contains pointers to the burn block and fork in which they occur
    CREATE TABLE leader_keys(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,
        sortition_id TEXT NOT NULL,
        
        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        memo TEXT,
        address TEXT NOT NULL,

        PRIMARY KEY(txid,sortition_id),
        FOREIGN KEY(sortition_id) REFERENCES snapshots(sortition_id)
    );"#,
    r#"
    CREATE TABLE block_commits(
        txid TEXT NOT NULL,
        l1_block_id TEXT NOT NULL,
        committed_block_hash TEXT NOT NULL,
        sortition_id TEXT NOT NULL,

        PRIMARY KEY(txid,sortition_id),
        FOREIGN KEY(sortition_id) REFERENCES snapshots(sortition_id)
    );"#,
    r#"
    CREATE TABLE user_burn_support(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,
        sortition_id TEXT NOT NULL,

        address TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        key_block_ptr INTEGER NOT NULL,
        key_vtxindex INTEGER NOT NULL,
        block_header_hash_160 TEXT NOT NULL,

        burn_fee TEXT NOT NULL,

        PRIMARY KEY(txid,sortition_id),
        FOREIGN KEY(sortition_id) REFERENCES snapshots(sortition_id)
    );"#,
    r#"
    CREATE TABLE stack_stx (
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        sender_addr TEXT NOT NULL,
        reward_addr TEXT NOT NULL,
        stacked_ustx TEXT NOT NULL,
        num_cycles INTEGER NOT NULL,

        PRIMARY KEY(txid)
    );"#,
    r#"
    CREATE TABLE transfer_stx (
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        sender_addr TEXT NOT NULL,
        recipient_addr TEXT NOT NULL,
        transfered_ustx TEXT NOT NULL,
        memo TEXT NOT NULL,

        PRIMARY KEY(txid)
    );"#,
    r#"
    CREATE TABLE missed_commits (
        txid TEXT NOT NULL,
        input TEXT NOT NULL,
        intended_sortition_id TEXT NOT NULL,

        PRIMARY KEY(txid, intended_sortition_id)
    );"#,
    r#"
    CREATE TABLE canonical_accepted_stacks_blocks(
        tip_consensus_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        stacks_block_hash TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        PRIMARY KEY(consensus_hash, stacks_block_hash)
    );"#,
    "CREATE TABLE db_config(version TEXT PRIMARY KEY);",
];

const SORTITION_DB_SCHEMA_2: &'static [&'static str] = &[r#"
     CREATE TABLE epochs (
         start_block_height INTEGER NOT NULL,
         end_block_height INTEGER NOT NULL,
         epoch_id INTEGER NOT NULL,
         block_limit TEXT NOT NULL,
         network_epoch INTEGER NOT NULL,
         PRIMARY KEY(start_block_height,epoch_id)
     );"#];

const SORTITION_DB_INDEXES: &'static [&'static str] = &[
    "CREATE INDEX IF NOT EXISTS snapshots_block_hashes ON snapshots(block_height,index_root,winning_stacks_block_hash);",
    "CREATE INDEX IF NOT EXISTS snapshots_block_stacks_hashes ON snapshots(num_sortitions,index_root,winning_stacks_block_hash);",
    "CREATE INDEX IF NOT EXISTS snapshots_block_heights ON snapshots(burn_header_hash,block_height);",
    "CREATE INDEX IF NOT EXISTS snapshots_block_winning_hash ON snapshots(winning_stacks_block_hash);",
    "CREATE INDEX IF NOT EXISTS snapshots_canonical_chain_tip ON snapshots(pox_valid,block_height DESC,burn_header_hash ASC);",
    "CREATE INDEX IF NOT EXISTS block_arrivals ON snapshots(arrival_index,burn_header_hash);",
    "CREATE INDEX IF NOT EXISTS arrival_indexes ON snapshots(arrival_index);",
    "CREATE INDEX IF NOT EXISTS index_leader_keys_sortition_id_block_height_vtxindex ON leader_keys(sortition_id,block_height,vtxindex);",
    "CREATE INDEX IF NOT EXISTS index_user_burn_support_txid ON user_burn_support(txid);",
    "CREATE INDEX IF NOT EXISTS index_user_burn_support_sortition_id_vtxindex ON user_burn_support(sortition_id,vtxindex);",
    "CREATE INDEX IF NOT EXISTS index_user_burn_support_sortition_id_hash_160_key_vtxindex_key_block_ptr_vtxindex ON user_burn_support(sortition_id,block_header_hash_160,key_vtxindex,key_block_ptr,vtxindex ASC);",
    "CREATE INDEX IF NOT EXISTS index_stack_stx_burn_header_hash ON stack_stx(burn_header_hash);",
    "CREATE INDEX IF NOT EXISTS index_transfer_stx_burn_header_hash ON transfer_stx(burn_header_hash);",
    "CREATE INDEX IF NOT EXISTS index_missed_commits_intended_sortition_id ON missed_commits(intended_sortition_id);",
    "CREATE INDEX IF NOT EXISTS canonical_stacks_blocks ON canonical_accepted_stacks_blocks(tip_consensus_hash,stacks_block_hash);"
];

pub struct SortitionDB {
    pub readwrite: bool,
    pub marf: MARF<SortitionId>,
    pub first_block_height: u64,
    pub first_burn_header_hash: BurnchainHeaderHash,
}

#[derive(Clone)]
pub struct SortitionDBTxContext {
    pub first_block_height: u64,
}

#[derive(Clone)]
pub struct SortitionHandleContext {
    pub first_block_height: u64,
    pub chain_tip: SortitionId,
}

pub type SortitionDBConn<'a> = IndexDBConn<'a, SortitionDBTxContext, SortitionId>;
pub type SortitionDBTx<'a> = IndexDBTx<'a, SortitionDBTxContext, SortitionId>;

///
/// These structs are used to keep an open "handle" to the
///   sortition db -- this is just the db/marf connection
///   and a chain tip. This mostly just makes the job of callers
///   much simpler, because they don't have to worry about passing
///   around the open chain tip everywhere.
///
pub type SortitionHandleConn<'a> = IndexDBConn<'a, SortitionHandleContext, SortitionId>;
pub type SortitionHandleTx<'a> = IndexDBTx<'a, SortitionHandleContext, SortitionId>;

///
/// This trait is used for functions that
///  can accept either a SortitionHandleConn or a SortitionDBConn
///
pub trait SortitionContext: Clone {
    fn first_block_height(&self) -> u64;
}

impl SortitionContext for SortitionHandleContext {
    fn first_block_height(&self) -> u64 {
        self.first_block_height
    }
}

impl SortitionContext for SortitionDBTxContext {
    fn first_block_height(&self) -> u64 {
        self.first_block_height
    }
}

fn get_block_commit_by_txid(
    conn: &Connection,
    txid: &Txid,
) -> Result<Option<LeaderBlockCommitOp>, db_error> {
    let qry = "SELECT * FROM block_commits WHERE txid = ?1 LIMIT 1";
    query_row(conn, qry, &[&txid])
}

fn get_ancestor_sort_id<C: SortitionContext>(
    ic: &IndexDBConn<'_, C, SortitionId>,
    block_height: u64,
    tip_block_hash: &SortitionId,
) -> Result<Option<SortitionId>, db_error> {
    let adjusted_height = match get_adjusted_block_height(&ic.context, block_height) {
        Some(x) => x,
        None => return Ok(None),
    };

    ic.get_ancestor_block_hash(adjusted_height, &tip_block_hash)
}

fn get_ancestor_sort_id_tx<C: SortitionContext>(
    ic: &mut IndexDBTx<'_, C, SortitionId>,
    block_height: u64,
    tip_block_hash: &SortitionId,
) -> Result<Option<SortitionId>, db_error> {
    let adjusted_height = match get_adjusted_block_height(&ic.context, block_height) {
        Some(x) => x,
        None => return Ok(None),
    };

    ic.get_ancestor_block_hash(adjusted_height, &tip_block_hash)
}

fn get_adjusted_block_height<C: SortitionContext>(context: &C, block_height: u64) -> Option<u64> {
    let first_block_height = context.first_block_height();
    if block_height < first_block_height {
        return None;
    }

    Some(block_height - first_block_height)
}

pub struct db_keys;
impl db_keys {
    /// store an entry that maps from a PoX anchor's <stacks-block-header-hash> to <sortition-id of last block in prepare phase that chose it>
    pub fn pox_anchor_to_prepare_end(block_hash: &BlockHeaderHash) -> String {
        format!("sortition_db::pox_anchor_to_prepare_end::{}", block_hash)
    }

    pub fn pox_last_anchor() -> &'static str {
        "sortition_db::last_anchor_block"
    }

    pub fn pox_reward_set_size() -> &'static str {
        "sortition_db::reward_set::size"
    }

    pub fn pox_reward_set_entry(ix: u16) -> String {
        format!("sortition_db::reward_set::entry::{}", ix)
    }

    /// store an entry for retrieving the PoX identifier (i.e., the PoX bitvector) for this PoX fork
    pub fn pox_identifier() -> &'static str {
        "sortition_db::pox_identifier"
    }

    pub fn initial_mining_bonus_remaining() -> &'static str {
        "sortition_db::initial_mining::remaining"
    }

    pub fn initial_mining_bonus_per_block() -> &'static str {
        "sortition_db::initial_mining::per_block"
    }

    pub fn sortition_id_for_bhh(bhh: &BurnchainHeaderHash) -> String {
        format!("sortition_db::sortition_id_for_bhh::{}", bhh)
    }
    pub fn vrf_key_status(key: &VRFPublicKey) -> String {
        format!("sortition_db::vrf::{}", key.to_hex())
    }
    pub fn stacks_block_present(block_hash: &BlockHeaderHash) -> String {
        format!("sortition_db::sortition_block_hash::{}", block_hash)
    }
    pub fn last_sortition() -> &'static str {
        "sortition_db::last_sortition"
    }

    /// MARF index key for a processed stacks block.  Maps to its height.
    pub fn stacks_block_index(stacks_block_hash: &BlockHeaderHash) -> String {
        format!("sortition_db::stacks::block::{}", stacks_block_hash)
    }

    /// MARF index value for a processed stacks block
    fn stacks_block_index_value(height: u64) -> String {
        format!("{}", height)
    }

    /// MARF index key for the highest arrival index processed in a fork
    pub fn stacks_block_max_arrival_index() -> String {
        "sortition_db::stacks::block::max_arrival_index".to_string()
    }

    /// MARF index value for the highest arrival index processed in a fork
    fn stacks_block_max_arrival_index_value(index: u64) -> String {
        format!("{}", index)
    }

    pub fn reward_set_size_to_string(size: usize) -> String {
        to_hex(
            &u16::try_from(size)
                .expect("BUG: maximum reward set size should be u16")
                .to_le_bytes(),
        )
    }

    pub fn reward_set_size_from_string(size: &str) -> u16 {
        let bytes = hex_bytes(size).expect("CORRUPTION: bad format written for reward set size");
        let mut byte_buff = [0; 2];
        byte_buff.copy_from_slice(&bytes[0..2]);
        u16::from_le_bytes(byte_buff)
    }
}

impl<'a> SortitionHandleTx<'a> {
    /// begin a MARF transaction with this connection
    ///  this is used by _writing_ contexts
    pub fn begin(
        conn: &'a mut SortitionDB,
        parent_chain_tip: &SortitionId,
    ) -> Result<SortitionHandleTx<'a>, db_error> {
        if !conn.readwrite {
            return Err(db_error::ReadOnly);
        }

        let handle = SortitionHandleTx::new(
            &mut conn.marf,
            SortitionHandleContext {
                chain_tip: parent_chain_tip.clone(),
                first_block_height: conn.first_block_height,
            },
        );

        Ok(handle)
    }

    /// Uses the handle's current fork identifier to get a block snapshot by
    ///   burnchain block header
    /// If the burn header hash is _not_ in the current fork, then this will return Ok(None)
    pub fn get_block_snapshot(
        &mut self,
        burn_header_hash: &BurnchainHeaderHash,
        chain_tip: &SortitionId,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        let sortition_identifier_key = db_keys::sortition_id_for_bhh(burn_header_hash);
        let sortition_id = match self.get_indexed(&chain_tip, &sortition_identifier_key)? {
            None => return Ok(None),
            Some(x) => SortitionId::from_hex(&x).expect("FATAL: bad Sortition ID stored in DB"),
        };
        SortitionDB::get_block_snapshot(self.tx(), &sortition_id)
    }

    /// Get a leader key at a specific location in the burn chain's fork history, given the
    /// matching block commit's fork index root (block_height and vtxindex are the leader's
    /// calculated location in this fork).
    /// Returns None if there is no leader key at this location.
    pub fn get_leader_key_at(
        &mut self,
        _key_block_height: u64,
        _key_vtxindex: u32,
        _tip: &SortitionId,
    ) -> Result<Option<LeaderKeyRegisterOp>, db_error> {
        Ok(None)
    }

    /// Find the VRF public keys consumed by each block candidate in the given list.
    /// The burn DB should have a key for each candidate; otherwise the candidate would not have
    /// been accepted.
    pub fn get_consumed_leader_keys(
        &mut self,
        _parent_tip: &BlockSnapshot,
        _block_candidates: &Vec<LeaderBlockCommitOp>,
    ) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        Ok(vec![])
    }

    /// Get a block commit by its content-addressed location in a specific sortition.
    pub fn get_block_commit(
        &self,
        txid: &Txid,
        sortition_id: &SortitionId,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        SortitionDB::get_block_commit(self.tx(), txid, sortition_id)
    }

    pub fn get_consensus_at(
        &mut self,
        block_height: u64,
    ) -> Result<Option<ConsensusHash>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let chain_tip = self.context.chain_tip.clone();

        match SortitionDB::get_ancestor_snapshot_tx(self, block_height, &chain_tip)? {
            Some(sn) => Ok(Some(sn.consensus_hash)),
            None => Ok(None),
        }
    }

    /// Do we expect a stacks block in this particular fork?
    /// i.e. is this block hash part of the fork history identified by tip_block_hash?
    pub fn expects_stacks_block_in_fork(
        &mut self,
        block_hash: &BlockHeaderHash,
    ) -> Result<bool, db_error> {
        let chain_tip = self.context.chain_tip.clone();
        self.get_indexed(&chain_tip, &db_keys::stacks_block_present(block_hash))
            .map(|result| result.is_some())
    }

    /// Get the latest block snapshot on this fork where a sortition occured.
    /// Search snapshots up to (but excluding) the given block height.
    /// Will always return a snapshot -- even if it's the initial sentinel snapshot.
    pub fn get_last_snapshot_with_sortition(
        &mut self,
        burn_block_height: u64,
    ) -> Result<BlockSnapshot, db_error> {
        assert!(burn_block_height < BLOCK_HEIGHT_MAX);
        test_debug!(
            "Get snapshot at from sortition tip {}, expect height {}",
            &self.context.chain_tip,
            burn_block_height
        );
        let chain_tip = self.context.chain_tip.clone();

        let get_from = match get_ancestor_sort_id_tx(self, burn_block_height, &chain_tip)? {
            Some(sortition_id) => sortition_id,
            None => {
                error!(
                    "No blockheight {} ancestor at sortition identifier {}",
                    burn_block_height, &self.context.chain_tip
                );
                return Err(db_error::NotFoundError);
            }
        };

        let ancestor_hash = match self.get_indexed(&get_from, &db_keys::last_sortition())? {
            Some(hex_str) => BurnchainHeaderHash::from_hex(&hex_str).expect(&format!(
                "FATAL: corrupt database: failed to parse {} into a hex string",
                &hex_str
            )),
            None => {
                // no prior sortitions, so get the first
                return SortitionDB::get_first_block_snapshot(self.tx());
            }
        };

        self.get_block_snapshot(&ancestor_hash, &chain_tip)
            .map(|snapshot_opt| {
                snapshot_opt.expect(&format!(
                    "FATAL: corrupt index: no snapshot {}",
                    ancestor_hash
                ))
            })
    }

    /// Determine whether or not a leader key has been consumed by a subsequent block commitment in
    /// this fork's history.
    /// Will return false if the leader key does not exist.
    pub fn is_leader_key_consumed(
        &mut self,
        leader_key: &LeaderKeyRegisterOp,
    ) -> Result<bool, db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);
        let chain_tip = self.context.chain_tip.clone();

        let key_status =
            match self.get_indexed(&chain_tip, &db_keys::vrf_key_status(&leader_key.public_key))? {
                Some(status_str) => {
                    if status_str == "1" {
                        // key is still available
                        false
                    } else if status_str == "0" {
                        // key is consumed
                        true
                    } else {
                        panic!("Invalid key status string {}", status_str);
                    }
                }
                None => {
                    // never before seen
                    false
                }
            };

        Ok(key_status)
    }

    /// Get a parent block commit at a specific location in the burn chain on a particular fork.
    /// Returns None if there is no block commit at this location.
    pub fn get_block_commit_parent(
        &mut self,
        block_height: u64,
        vtxindex: u32,
        tip: &SortitionId,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_id = match get_ancestor_sort_id_tx(self, block_height, tip)? {
            Some(id) => id,
            None => {
                return Ok(None);
            }
        };

        SortitionDB::get_block_commit_of_sortition(self.tx(), &ancestor_id, block_height, vtxindex)
    }

    pub fn has_VRF_public_key(&mut self, key: &VRFPublicKey) -> Result<bool, db_error> {
        let chain_tip = self.context.chain_tip.clone();
        let key_status = self
            .get_indexed(&chain_tip, &db_keys::vrf_key_status(key))?
            .is_some();
        Ok(key_status)
    }

    fn check_fresh_consensus_hash<F>(
        &mut self,
        consensus_hash_lifetime: u64,
        check: F,
    ) -> Result<bool, db_error>
    where
        F: Fn(&ConsensusHash) -> bool,
    {
        let chain_tip = self.context.chain_tip.clone();
        let first_snapshot = SortitionDB::get_first_block_snapshot(self.tx())?;
        let mut last_snapshot =
            SortitionDB::get_block_snapshot(self.tx(), &self.context.chain_tip)?
                .ok_or_else(|| db_error::NotFoundError)?;
        let current_block_height = last_snapshot.block_height;

        let mut oldest_height = if current_block_height < consensus_hash_lifetime {
            0
        } else {
            current_block_height - consensus_hash_lifetime
        };

        if oldest_height < first_snapshot.block_height {
            oldest_height = first_snapshot.block_height;
        }

        if check(&last_snapshot.consensus_hash) {
            return Ok(true);
        }

        for _i in oldest_height..current_block_height {
            let ancestor_snapshot = self
                .get_block_snapshot(&last_snapshot.parent_burn_header_hash, &chain_tip)?
                .expect(&format!(
                    "Discontiguous index: missing block {}",
                    last_snapshot.parent_burn_header_hash
                ));
            if check(&ancestor_snapshot.consensus_hash) {
                return Ok(true);
            }
            last_snapshot = ancestor_snapshot;
        }

        return Ok(false);
    }

    /// Find out whether or not a given consensus hash is "recent" enough to be used in this fork.
    pub fn is_fresh_consensus_hash(
        &mut self,
        consensus_hash_lifetime: u64,
        consensus_hash: &ConsensusHash,
    ) -> Result<bool, db_error> {
        self.check_fresh_consensus_hash(consensus_hash_lifetime, |fresh_hash| {
            fresh_hash == consensus_hash
        })
    }

    /// Find out whether or not a given consensus hash is "recent" enough to be used in this fork.
    /// This function only checks the first 19 bytes
    pub fn is_fresh_consensus_hash_check_19b(
        &mut self,
        consensus_hash_lifetime: u64,
        consensus_hash: &ConsensusHash,
    ) -> Result<bool, db_error> {
        self.check_fresh_consensus_hash(consensus_hash_lifetime, |fresh_hash| {
            fresh_hash.as_bytes()[0..19] == consensus_hash.as_bytes()[0..19]
        })
    }
}

impl<'a> SortitionHandleTx<'a> {
    pub fn set_stacks_block_accepted(
        &mut self,
        consensus_hash: &ConsensusHash,
        parent_stacks_block_hash: &BlockHeaderHash,
        stacks_block_hash: &BlockHeaderHash,
        stacks_block_height: u64,
    ) -> Result<(), db_error> {
        // NOTE: chain_tip here is the tip of the PoX fork on the canonical burn chain fork.
        // consensus_hash refers to the consensus hash of the tip of the canonical Stacks fork
        // we're updating.
        let chain_tip = SortitionDB::get_block_snapshot(self, &self.context.chain_tip)?.expect(
            "FAIL: Setting stacks block accepted in canonical chain tip which cannot be found",
        );
        self.set_stacks_block_accepted_at_tip(
            &chain_tip,
            consensus_hash,
            parent_stacks_block_hash,
            stacks_block_hash,
            stacks_block_height,
        )
    }

    /// Get the expected PoX recipients (reward set) for the next sortition, either by querying information
    ///  from the current reward cycle, or if `next_pox_info` is provided, by querying information
    ///  for the next reward cycle.
    ///
    /// Returns None if:
    ///   * The reward cycle had an anchor block, but it isn't known by this node.
    ///   * The reward cycle did not have anchor block
    ///   * The block is in the prepare phase of a reward cycle, in which case miners must burn
    ///   * The Stacking recipient set is empty (either because this reward cycle has already exhausted the set of addresses or because no one ever Stacked).
    fn pick_recipients(
        &mut self,
        _burnchain: &Burnchain,
        _block_height: u64,
        _reward_set_vrf_seed: &SortitionHash,
        _next_pox_info: Option<&RewardCycleInfo>,
    ) -> Result<Option<RewardSetInfo>, BurnchainError> {
        Ok(None)
    }

    fn get_reward_set_entry(&mut self, entry_ix: u16) -> Result<StacksAddress, db_error> {
        let chain_tip = self.context.chain_tip.clone();
        let entry_str = self
            .get_indexed(&chain_tip, &db_keys::pox_reward_set_entry(entry_ix))?
            .expect(&format!(
                "CORRUPTION: expected reward set entry at index={}, but not found",
                entry_ix
            ));
        Ok(StacksAddress::from_string(&entry_str).expect(&format!(
            "CORRUPTION: bad address formatting in database: {}",
            &entry_str
        )))
    }

    fn get_reward_set_size(&mut self) -> Result<u16, db_error> {
        let chain_tip = self.context.chain_tip.clone();
        self.get_indexed(&chain_tip, db_keys::pox_reward_set_size())
            .map(|x| {
                db_keys::reward_set_size_from_string(
                    &x.expect("CORRUPTION: no current reward set size written"),
                )
            })
    }

    /// is the given block a descendant of `potential_ancestor`?
    ///  * block_at_burn_height: the burn height of the sortition that chose the stacks block to check
    ///  * potential_ancestor: the stacks block hash of the potential ancestor
    pub fn descended_from(
        &mut self,
        _block_at_burn_height: u64,
        _potential_ancestor: &BlockHeaderHash,
    ) -> Result<bool, db_error> {
        panic!("Not implemented")
    }

    pub fn get_block_snapshot_by_height(
        &mut self,
        block_height: u64,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let chain_tip = self.context.chain_tip.clone();
        SortitionDB::get_ancestor_snapshot_tx(self, block_height, &chain_tip)
    }

    pub fn get_last_anchor_block_hash(&mut self) -> Result<Option<BlockHeaderHash>, db_error> {
        let chain_tip = self.context.chain_tip.clone();
        let anchor_block_hash = SortitionDB::parse_last_anchor_block_hash(
            self.get_indexed(&chain_tip, &db_keys::pox_last_anchor())?,
        );
        Ok(anchor_block_hash)
    }

    /// Mark an existing snapshot's stacks block as accepted at a particular burn chain tip within a PoX fork (identified by the consensus hash),
    /// and calculate and store its arrival index.
    /// If this Stacks block extends the canonical stacks chain tip, then also update the memoized canonical
    /// stacks chain tip metadata on the burn chain tip.
    // TODO: this method's inner call to get_indexed() occurs within a MARF transaction, which
    // means it will clone() the underlying TrieRAM.  Until this is rectified, care should be taken
    // to ensure that no keys are inserted until after this method is called.  This should already
    // be the case, since the only time keys are inserted into the sortition DB MARF is when the
    // next snapshot is processed (whereas this method is called when a Stacks epoch is processed).
    fn set_stacks_block_accepted_at_tip(
        &mut self,
        burn_tip: &BlockSnapshot,
        consensus_hash: &ConsensusHash,
        parent_stacks_block_hash: &BlockHeaderHash,
        stacks_block_hash: &BlockHeaderHash,
        stacks_block_height: u64,
    ) -> Result<(), db_error> {
        let arrival_index = SortitionDB::get_max_arrival_index(self)?;
        let args: &[&dyn ToSql] = &[
            &u64_to_sql(stacks_block_height)?,
            &u64_to_sql(arrival_index + 1)?,
            consensus_hash,
            stacks_block_hash,
        ];

        self.execute("UPDATE snapshots SET stacks_block_accepted = 1, stacks_block_height = ?1, arrival_index = ?2 WHERE consensus_hash = ?3 AND winning_stacks_block_hash = ?4", args)?;

        let parent_key = db_keys::stacks_block_index(parent_stacks_block_hash);

        // update memoized canonical stacks chain tip on the canonical burn chain tip if this block
        // extends it.
        if burn_tip.canonical_stacks_tip_hash == *parent_stacks_block_hash {
            // This block builds off of the memoized canonical stacks chain tip information we
            // already have.
            // Memoize this tip to the canonical burn chain snapshot.
            if stacks_block_height > 0 {
                assert_eq!(
                    burn_tip.canonical_stacks_tip_height + 1,
                    stacks_block_height
                );
            } else {
                assert_eq!(stacks_block_hash, &FIRST_STACKS_BLOCK_HASH);
            }
            debug!(
                "Accepted Stacks block {}/{} builds on the memoized canonical chain tip ({})",
                consensus_hash, stacks_block_hash, &burn_tip.burn_header_hash
            );
            let args: &[&dyn ToSql] = &[
                consensus_hash,
                stacks_block_hash,
                &u64_to_sql(stacks_block_height)?,
                &burn_tip.sortition_id,
            ];
            self.execute("UPDATE snapshots SET canonical_stacks_tip_consensus_hash = ?1, canonical_stacks_tip_hash = ?2, canonical_stacks_tip_height = ?3
                        WHERE sortition_id = ?4", args)?;

            SortitionDB::insert_accepted_stacks_block_pointer(
                self,
                &burn_tip.consensus_hash,
                consensus_hash,
                stacks_block_hash,
                stacks_block_height,
            )?;
        } else {
            // see if this block builds off of a Stacks block mined on this burnchain fork
            let height_opt = match SortitionDB::get_accepted_stacks_block_pointer(
                self,
                &burn_tip.consensus_hash,
                parent_stacks_block_hash,
            )? {
                // this block builds on a block accepted _after_ this burn chain tip was processed?
                Some(accepted_header) => Some(accepted_header.height),
                None => {
                    match self.get_indexed(&burn_tip.sortition_id, &parent_key)? {
                        // this block builds on a block accepted _before_ this burn chain tip was processed?
                        Some(height_str) => Some(height_str.parse::<u64>().expect(&format!(
                            "BUG: MARF stacks block key '{}' does not map to a u64",
                            parent_key
                        ))),
                        None => None,
                    }
                }
            };
            match height_opt {
                Some(height) => {
                    if stacks_block_height > burn_tip.canonical_stacks_tip_height {
                        assert!(stacks_block_height > height, "BUG: DB corruption -- block height {} <= {} means we accepted a block out-of-order", stacks_block_height, height);
                        // This block builds off of a parent that is _concurrent_ with the memoized canonical stacks chain pointer.
                        // i.e. this block will reorg the Stacks chain on the canonical burnchain fork.
                        // Memoize this new stacks chain tip to the canonical burn chain snapshot.
                        // Note that we don't have to check continuity of accepted blocks -- we already
                        // are guaranteed by the Stacks chain state code that Stacks blocks in a given
                        // Stacks fork will be marked as accepted in sequential order (i.e. at height h, h+1,
                        // h+2, etc., without any gaps).
                        debug!("Accepted Stacks block {}/{} builds on a previous canonical Stacks tip on this burnchain fork ({})", consensus_hash, stacks_block_hash, &burn_tip.burn_header_hash);
                        let args: &[&dyn ToSql] = &[
                            consensus_hash,
                            stacks_block_hash,
                            &u64_to_sql(stacks_block_height)?,
                            &burn_tip.sortition_id,
                        ];
                        self.execute("UPDATE snapshots SET canonical_stacks_tip_consensus_hash = ?1, canonical_stacks_tip_hash = ?2, canonical_stacks_tip_height = ?3
                                    WHERE sortition_id = ?4", args)
                            .map_err(db_error::SqliteError)?;
                    } else {
                        // This block was mined on this fork, but it's acceptance doesn't overtake
                        // the current stacks chain tip.  Remember it so that we can process its children,
                        // which might do so later.
                        debug!("Accepted Stacks block {}/{} builds on a non-canonical Stacks tip in this burnchain fork ({})", consensus_hash, stacks_block_hash, &burn_tip.burn_header_hash);
                    }
                    SortitionDB::insert_accepted_stacks_block_pointer(
                        self,
                        &burn_tip.consensus_hash,
                        consensus_hash,
                        stacks_block_hash,
                        stacks_block_height,
                    )?;
                }
                None => {
                    debug!("Accepted Stacks block {}/{} does NOT build on a Stacks tip in this burnchain fork ({}) -- no parent {} in this fork", consensus_hash, stacks_block_hash, &burn_tip.burn_header_hash, parent_stacks_block_hash);
                }
            }
        }
        Ok(())
    }
}

impl<'a> SortitionHandleConn<'a> {
    /// open a reader handle from a consensus hash
    pub fn open_reader_consensus(
        connection: &'a SortitionDBConn<'a>,
        chain_tip: &ConsensusHash,
    ) -> Result<SortitionHandleConn<'a>, db_error> {
        let sn = match SortitionDB::get_block_snapshot_consensus(&connection.conn(), chain_tip)? {
            Some(sn) => {
                if !sn.pox_valid {
                    warn!(
                        "No such chain tip consensus hash {}: not on a valid PoX fork",
                        chain_tip
                    );
                    return Err(db_error::InvalidPoxSortition);
                }
                sn
            }
            None => {
                test_debug!("No such chain tip consensus hash {}", chain_tip);
                return Err(db_error::NotFoundError);
            }
        };

        SortitionHandleConn::open_reader(connection, &sn.sortition_id)
    }

    // TODO: delete this method once stable
    fn get_reward_set_size(&self) -> Result<u16, db_error> {
        Ok(0u16)
    }

    /// open a reader handle
    pub fn open_reader(
        connection: &'a SortitionDBConn<'a>,
        chain_tip: &SortitionId,
    ) -> Result<SortitionHandleConn<'a>, db_error> {
        Ok(SortitionHandleConn {
            context: SortitionHandleContext {
                chain_tip: chain_tip.clone(),
                first_block_height: connection.context.first_block_height,
            },
            index: &connection.index,
        })
    }

    fn get_tip_indexed(&self, key: &str) -> Result<Option<String>, db_error> {
        self.get_indexed(&self.context.chain_tip, key)
    }

    /// Return the sortition ID for the burn header hash if and only if it
    ///  that burn block is in the same fork as this db handle.
    fn get_sortition_id_for_bhh(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<SortitionId>, db_error> {
        let sortition_identifier_key = db_keys::sortition_id_for_bhh(burn_header_hash);
        let sortition_id = match self.get_tip_indexed(&sortition_identifier_key)? {
            None => return Ok(None),
            Some(x) => SortitionId::from_hex(&x).expect("FATAL: bad Sortition ID stored in DB"),
        };
        Ok(Some(sortition_id))
    }

    /// Uses the handle's current fork identifier to get a block snapshot by
    ///   burnchain block header
    /// If the burn header hash is _not_ in the current fork, then this will return Ok(None)
    pub fn get_block_snapshot(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        let sortition_id = match self.get_sortition_id_for_bhh(burn_header_hash)? {
            None => return Ok(None),
            Some(x) => x,
        };

        SortitionDB::get_block_snapshot(self.conn(), &sortition_id)
    }

    pub fn get_tip_snapshot(&self) -> Result<Option<BlockSnapshot>, db_error> {
        SortitionDB::get_block_snapshot(self.conn(), &self.context.chain_tip)
    }

    pub fn get_first_block_snapshot(&self) -> Result<BlockSnapshot, db_error> {
        SortitionDB::get_first_block_snapshot(self.conn())
    }

    /// Get consensus hash from a particular chain tip's history
    /// Returns None if the block height or block hash does not correspond to a
    /// known snapshot.
    pub fn get_consensus_at(&self, block_height: u64) -> Result<Option<ConsensusHash>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        match SortitionDB::get_ancestor_snapshot(self, block_height, &self.context.chain_tip)? {
            Some(sn) => Ok(Some(sn.consensus_hash)),
            None => Ok(None),
        }
    }

    pub fn get_block_snapshot_by_height(
        &self,
        block_height: u64,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        SortitionDB::get_ancestor_snapshot(self, block_height, &self.context.chain_tip)
    }

    /// Get all user burns that burned for the winning block in the chain_tip sortition
    /// Returns list of user burns in order by vtxindex.
    pub fn get_winning_user_burns_by_block(&self) -> Result<Vec<UserBurnSupportOp>, db_error> {
        Ok(vec![])
    }

    /// Get the latest block snapshot on this fork where a sortition occured.
    /// Search snapshots up to (but excluding) the given block height.
    /// Will always return a snapshot -- even if it's the initial sentinel snapshot.
    pub fn get_last_snapshot_with_sortition(
        &self,
        burn_block_height: u64,
    ) -> Result<BlockSnapshot, db_error> {
        assert!(burn_block_height < BLOCK_HEIGHT_MAX);
        test_debug!(
            "Get snapshot at from sortition tip {}, expect height {}",
            &self.context.chain_tip,
            burn_block_height
        );
        let get_from = match get_ancestor_sort_id(self, burn_block_height, &self.context.chain_tip)?
        {
            Some(sortition_id) => sortition_id,
            None => {
                error!(
                    "No blockheight {} ancestor at sortition identifier {}",
                    burn_block_height, &self.context.chain_tip
                );
                return Err(db_error::NotFoundError);
            }
        };

        let ancestor_hash = match self.get_indexed(&get_from, &db_keys::last_sortition())? {
            Some(hex_str) => BurnchainHeaderHash::from_hex(&hex_str).expect(&format!(
                "FATAL: corrupt database: failed to parse {} into a hex string",
                &hex_str
            )),
            None => {
                // no prior sortitions, so get the first
                return self.get_first_block_snapshot();
            }
        };

        self.get_block_snapshot(&ancestor_hash).map(|snapshot_opt| {
            snapshot_opt.expect(&format!(
                "FATAL: corrupt index: no snapshot {}",
                ancestor_hash
            ))
        })
    }

    pub fn get_block_commit_parent(
        &self,
        block_height: u64,
        vtxindex: u32,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        SortitionDB::get_block_commit_parent(self, block_height, vtxindex, &self.context.chain_tip)
    }

    /// Get a block commit by txid. In the event of a burnchain fork, this may not be unique.
    ///   this function simply returns one of those block commits: only use data that is
    ///   immutable across burnchain/pox forks, e.g., parent block ptr,  
    pub fn get_block_commit_by_txid(
        &self,
        txid: &Txid,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        get_block_commit_by_txid(self.conn(), txid)
    }

    /// Return a vec of sortition winner's burn header hash and stacks header hash, ordered by
    ///   increasing block height in the range (block_height_begin, block_height_end]
    fn get_sortition_winners_in_fork(
        &self,
        block_height_begin: u32,
        block_height_end: u32,
    ) -> Result<Vec<(Txid, u64)>, BurnchainError> {
        let mut result = vec![];
        for height in (block_height_begin + 1)..(block_height_end + 1) {
            debug!("Looking for winners at height = {}", height);
            let snapshot =
                SortitionDB::get_ancestor_snapshot(self, height as u64, &self.context.chain_tip)?
                    .ok_or_else(|| {
                    warn!("Missing parent"; "sortition_height" => %height);
                    BurnchainError::MissingParentBlock
                })?;
            if snapshot.sortition {
                result.push((snapshot.winning_block_txid, snapshot.block_height));
            }
        }
        Ok(result)
    }

    /// Return identifying information for a PoX anchor block for the reward cycle that
    ///   begins the block after `prepare_end_bhh`.
    /// If a PoX anchor block is chosen, this returns Some, if a PoX anchor block was not
    ///   selected, return `None`
    /// `prepare_end_bhh`: this is the burn block which is the last block in the prepare phase
    ///                 for the corresponding reward cycle
    pub fn get_chosen_pox_anchor(
        &self,
        prepare_end_bhh: &BurnchainHeaderHash,
        pox_consts: &PoxConstants,
    ) -> Result<Option<(ConsensusHash, BlockHeaderHash)>, CoordinatorError> {
        match self.get_chosen_pox_anchor_check_position(prepare_end_bhh, pox_consts, true) {
            Ok(Ok((c_hash, bh_hash, _))) => Ok(Some((c_hash, bh_hash))),
            Ok(Err(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_chosen_pox_anchor_check_position(
        &self,
        _prepare_end_bhh: &BurnchainHeaderHash,
        _pox_consts: &PoxConstants,
        _check_position: bool,
    ) -> Result<Result<(ConsensusHash, BlockHeaderHash, u32), u32>, CoordinatorError> {
        Ok(Err(0))
    }
}

// Connection methods
impl SortitionDB {
    /// Begin a transaction.
    pub fn tx_begin<'a>(&'a mut self) -> Result<SortitionDBTx<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let index_tx = SortitionDBTx::new(
            &mut self.marf,
            SortitionDBTxContext {
                first_block_height: self.first_block_height,
            },
        );
        Ok(index_tx)
    }

    /// Make an indexed connectino
    pub fn index_conn<'a>(&'a self) -> SortitionDBConn<'a> {
        SortitionDBConn::new(
            &self.marf,
            SortitionDBTxContext {
                first_block_height: self.first_block_height,
            },
        )
    }

    pub fn index_handle<'a>(&'a self, chain_tip: &SortitionId) -> SortitionHandleConn<'a> {
        SortitionHandleConn::new(
            &self.marf,
            SortitionHandleContext {
                first_block_height: self.first_block_height,
                chain_tip: chain_tip.clone(),
            },
        )
    }

    pub fn tx_handle_begin<'a>(
        &'a mut self,
        chain_tip: &SortitionId,
    ) -> Result<SortitionHandleTx<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        Ok(SortitionHandleTx::new(
            &mut self.marf,
            SortitionHandleContext {
                first_block_height: self.first_block_height,
                chain_tip: chain_tip.clone(),
            },
        ))
    }

    pub fn conn<'a>(&'a self) -> &'a Connection {
        self.marf.sqlite_conn()
    }

    fn open_index(index_path: &str) -> Result<MARF<SortitionId>, db_error> {
        test_debug!("Open index at {}", index_path);
        let marf = MARF::from_path(index_path).map_err(|_e| db_error::Corruption)?;
        sql_pragma(marf.sqlite_conn(), "foreign_keys", &true)?;
        Ok(marf)
    }

    /// Open the database on disk.  It must already exist and be instantiated.
    /// It's best not to call this if you are able to call connect().  If you must call this, do so
    /// after you call connect() somewhere else, since connect() performs additional validations.
    pub fn open(path: &str, readwrite: bool) -> Result<SortitionDB, db_error> {
        let index_path = db_mkdirs(path)?;
        debug!(
            "Open sortdb as '{}', with index as '{}'",
            if readwrite { "readwrite" } else { "readonly" },
            index_path
        );

        let marf = SortitionDB::open_index(&index_path)?;
        let first_snapshot = SortitionDB::get_first_block_snapshot(marf.sqlite_conn())?;

        let mut db = SortitionDB {
            marf,
            readwrite,
            first_block_height: first_snapshot.block_height,
            first_burn_header_hash: first_snapshot.burn_header_hash.clone(),
        };

        db.check_schema_version_or_error()?;
        Ok(db)
    }

    /// Open the burn database at the given path.  Open read-only or read/write.
    /// If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(
        path: &str,
        first_block_height: u64,
        first_burn_hash: &BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
        epochs: &[StacksEpoch],
        readwrite: bool,
    ) -> Result<SortitionDB, db_error> {
        let create_flag = match fs::metadata(path) {
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    // need to create
                    if readwrite {
                        true
                    } else {
                        return Err(db_error::NoDBError);
                    }
                } else {
                    return Err(db_error::IOError(e));
                }
            }
            Ok(_md) => false,
        };

        let index_path = db_mkdirs(path)?;
        info!(
            "Connect/Open {} sortdb as '{}', with index as '{}'",
            if create_flag { "(create)" } else { "" },
            if readwrite { "readwrite" } else { "readonly" },
            index_path
        );

        let marf = SortitionDB::open_index(&index_path)?;

        let mut db = SortitionDB {
            marf,
            readwrite,
            first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
        };

        if create_flag {
            // instantiate!
            db.instantiate(
                first_block_height,
                first_burn_hash,
                first_burn_header_timestamp,
                epochs,
            )?;
        } else {
            // validate -- must contain the given first block and first block hash
            let snapshot = SortitionDB::get_first_block_snapshot(db.conn())?;
            if !snapshot.is_initial()
                || snapshot.block_height != first_block_height
                || snapshot.burn_header_hash != *first_burn_hash
            {
                error!("Invalid genesis snapshot: sn.is_initial = {}, sn.block_height = {}, sn.burn_hash = {}, expect.block_height = {}, expect.burn_hash = {}",
                       snapshot.is_initial(), snapshot.block_height, &snapshot.burn_header_hash, first_block_height, first_burn_hash);
                return Err(db_error::Corruption);
            }
        }

        db.check_schema_version_and_update(epochs)?;
        if readwrite {
            db.add_indexes()?;
        }
        Ok(db)
    }

    /// Open a burn database at random tmp dir (used for testing)
    #[cfg(test)]
    pub fn connect_test(
        first_block_height: u64,
        first_burn_hash: &BurnchainHeaderHash,
    ) -> Result<SortitionDB, db_error> {
        use core::StacksEpochExtension;

        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let db_path_dir = format!(
            "/tmp/stacks-node-tests/unit-tests-sortdb/db-{}",
            to_hex(&buf)
        );

        SortitionDB::connect(
            &db_path_dir,
            first_block_height,
            first_burn_hash,
            get_epoch_time_secs(),
            &StacksEpoch::unit_test_pre_2_05(first_block_height),
            true,
        )
    }

    #[cfg(test)]
    pub fn connect_v1(
        path: &str,
        first_block_height: u64,
        first_burn_hash: &BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
        readwrite: bool,
    ) -> Result<SortitionDB, db_error> {
        let create_flag = match fs::metadata(path) {
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    // need to create
                    if readwrite {
                        true
                    } else {
                        return Err(db_error::NoDBError);
                    }
                } else {
                    return Err(db_error::IOError(e));
                }
            }
            Ok(_md) => false,
        };

        let index_path = db_mkdirs(path)?;
        debug!(
            "Connect/Open {} sortdb '{}' as '{}'",
            if create_flag { "(create)" } else { "" },
            index_path,
            if readwrite { "readwrite" } else { "readonly" }
        );

        let marf = SortitionDB::open_index(&index_path)?;

        let mut db = SortitionDB {
            marf,
            readwrite,
            first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
        };

        if create_flag {
            // instantiate!
            db.instantiate_v1(
                first_block_height,
                first_burn_hash,
                first_burn_header_timestamp,
            )?;
        } else {
            // validate -- must contain the given first block and first block hash
            let snapshot = SortitionDB::get_first_block_snapshot(db.conn())?;
            if !snapshot.is_initial()
                || snapshot.block_height != first_block_height
                || snapshot.burn_header_hash != *first_burn_hash
            {
                error!("Invalid genesis snapshot: sn.is_initial = {}, sn.block_height = {}, sn.burn_hash = {}, expect.block_height = {}, expect.burn_hash = {}",
                       snapshot.is_initial(), snapshot.block_height, &snapshot.burn_header_hash, first_block_height, first_burn_hash);
                return Err(db_error::Corruption);
            }
        }

        Ok(db)
    }

    /// Validate all Stacks Epochs. Since this is data that always comes from a static variable,
    /// any invalid StacksEpoch structuring should result in a runtime panic.
    fn validate_epochs(epochs_ref: &[StacksEpoch]) -> Vec<StacksEpoch> {
        // sanity check -- epochs must all be contiguous, each epoch must be unique,
        // and the range of epochs should span the whole non-negative i64 space.
        let mut epochs = epochs_ref.to_vec();
        let mut seen_epochs = HashSet::new();
        epochs.sort();

        let mut epoch_end_height = 0;
        for epoch in epochs.iter() {
            assert!(
                epoch.start_height <= epoch.end_height,
                "{} <= {} for {:?}",
                epoch.start_height,
                epoch.end_height,
                &epoch.epoch_id
            );

            if epoch_end_height == 0 {
                // first ever epoch must be defined for all of the prior chain history
                assert_eq!(epoch.start_height, 0);
                epoch_end_height = epoch.end_height;
            } else {
                assert_eq!(epoch_end_height, epoch.start_height);
                epoch_end_height = epoch.end_height;
            }
            if seen_epochs.contains(&epoch.epoch_id) {
                panic!("BUG: duplicate epoch");
            }

            seen_epochs.insert(epoch.epoch_id);
        }

        assert_eq!(epoch_end_height, STACKS_EPOCH_MAX);
        epochs
    }

    fn instantiate(
        &mut self,
        first_block_height: u64,
        first_burn_header_hash: &BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
        epochs_ref: &[StacksEpoch],
    ) -> Result<(), db_error> {
        debug!("Instantiate sortition DB");

        sql_pragma(self.conn(), "journal_mode", &"WAL")?;
        sql_pragma(self.conn(), "foreign_keys", &true)?;

        let mut db_tx = SortitionHandleTx::begin(self, &SortitionId::sentinel())?;

        // create first (sentinel) snapshot
        debug!("Make first snapshot");
        let mut first_snapshot = BlockSnapshot::initial(
            first_block_height,
            first_burn_header_hash,
            first_burn_header_timestamp,
        );

        assert!(first_snapshot.parent_burn_header_hash != first_snapshot.burn_header_hash);
        assert_eq!(
            first_snapshot.parent_burn_header_hash,
            BurnchainHeaderHash::sentinel()
        );

        for row_text in SORTITION_DB_INITIAL_SCHEMA {
            db_tx.execute_batch(row_text)?;
        }
        for row_text in SORTITION_DB_SCHEMA_2 {
            db_tx.execute_batch(row_text)?;
        }

        SortitionDB::validate_and_insert_epochs(&db_tx, epochs_ref)?;

        db_tx.execute(
            "INSERT OR REPLACE INTO db_config (version) VALUES (?1)",
            &[&SORTITION_DB_VERSION],
        )?;

        db_tx.instantiate_index()?;

        let mut first_sn = first_snapshot.clone();
        first_sn.sortition_id = SortitionId::sentinel();
        let index_root =
            db_tx.index_add_fork_info(&mut first_sn, &first_snapshot, &vec![], None)?;
        first_snapshot.index_root = index_root;

        db_tx.insert_block_snapshot(&first_snapshot)?;
        db_tx.store_transition_ops(
            &first_snapshot.sortition_id,
            &BurnchainStateTransition::noop(),
        )?;

        db_tx.commit()?;

        self.add_indexes()?;
        Ok(())
    }

    /// Validates given StacksEpochs (will runtime panic if there is any invalid StacksEpoch structuring) and
    ///  inserts them into the SortitionDB's epochs table.
    fn validate_and_insert_epochs(
        db_tx: &Transaction,
        epochs: &[StacksEpoch],
    ) -> Result<(), db_error> {
        let epochs = SortitionDB::validate_epochs(epochs);
        for epoch in epochs.into_iter() {
            let args: &[&dyn ToSql] = &[
                &(epoch.epoch_id as u32),
                &u64_to_sql(epoch.start_height)?,
                &u64_to_sql(epoch.end_height)?,
                &epoch.block_limit,
                &epoch.network_epoch,
            ];
            db_tx.execute(
                "INSERT INTO epochs (epoch_id,start_block_height,end_block_height,block_limit,network_epoch) VALUES (?1,?2,?3,?4,?5)",
                args
            )?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn instantiate_v1(
        &mut self,
        first_block_height: u64,
        first_burn_header_hash: &BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
    ) -> Result<(), db_error> {
        debug!("Instantiate SortDB");

        sql_pragma(self.conn(), "journal_mode", &"WAL")?;
        sql_pragma(self.conn(), "foreign_keys", &true)?;

        let mut db_tx = SortitionHandleTx::begin(self, &SortitionId::sentinel())?;

        // create first (sentinel) snapshot
        debug!("Make first snapshot");
        let mut first_snapshot = BlockSnapshot::initial(
            first_block_height,
            first_burn_header_hash,
            first_burn_header_timestamp,
        );

        assert!(first_snapshot.parent_burn_header_hash != first_snapshot.burn_header_hash);
        assert_eq!(
            first_snapshot.parent_burn_header_hash,
            BurnchainHeaderHash::sentinel()
        );

        for row_text in SORTITION_DB_INITIAL_SCHEMA {
            db_tx.execute_batch(row_text)?;
        }

        db_tx.execute(
            "INSERT OR REPLACE INTO db_config (version) VALUES (?1)",
            &[&"1"],
        )?;

        db_tx.instantiate_index()?;

        let mut first_sn = first_snapshot.clone();
        first_sn.sortition_id = SortitionId::sentinel();
        let index_root =
            db_tx.index_add_fork_info(&mut first_sn, &first_snapshot, &vec![], None)?;
        first_snapshot.index_root = index_root;

        db_tx.insert_block_snapshot(&first_snapshot)?;
        db_tx.store_transition_ops(
            &first_snapshot.sortition_id,
            &BurnchainStateTransition::noop(),
        )?;

        db_tx.commit()?;
        Ok(())
    }

    /// Get a block commit by its content-addressed location in a specific sortition.
    pub fn get_block_commit(
        conn: &Connection,
        txid: &Txid,
        sortition_id: &SortitionId,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        let qry = "SELECT * FROM block_commits WHERE txid = ?1 AND sortition_id = ?2";
        let args: [&dyn ToSql; 2] = [&txid, &sortition_id];
        query_row(conn, qry, &args)
    }

    /// Load up all snapshots, in ascending order by block height.  Great for testing!
    pub fn get_all_snapshots(&self) -> Result<Vec<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots ORDER BY block_height ASC";
        query_rows(self.conn(), qry, NO_PARAMS)
    }

    /// Get the schema version of a sortition DB, given the path to it.
    /// Returns the version string, if it exists
    pub fn get_db_version_from_path(path: &str) -> Result<Option<String>, db_error> {
        if fs::metadata(path).is_err() {
            return Err(db_error::NoDBError);
        }
        let index_path = db_mkdirs(path)?;
        let marf = SortitionDB::open_index(&index_path)?;
        SortitionDB::get_schema_version(marf.sqlite_conn())
    }

    /// Get the height of the highest burnchain block, given the DB path.
    /// Importantly, this will *not* apply any schema migrations.
    /// This is used to check if the DB is compatible with the current epoch.
    pub fn get_highest_block_height_from_path(path: &str) -> Result<u64, db_error> {
        if fs::metadata(path).is_err() {
            return Err(db_error::NoDBError);
        }
        let index_path = db_mkdirs(path)?;
        let marf = SortitionDB::open_index(&index_path)?;
        let sql = "SELECT MAX(block_height) FROM snapshots";
        Ok(query_rows(&marf.sqlite_conn(), sql, NO_PARAMS)?
            .pop()
            .expect("BUG: no snapshots in block_snapshots"))
    }

    /// Is a particular database version supported by a given epoch?
    pub fn is_db_version_supported_in_epoch(epoch: StacksEpochId, version: &str) -> bool {
        match epoch {
            StacksEpochId::Epoch10 => false,
            StacksEpochId::Epoch20 => (version == "1" || version == "2"),
            StacksEpochId::Epoch2_05 => version == "2",
        }
    }

    /// Get the database schema version, given a DB connection
    fn get_schema_version(conn: &Connection) -> Result<Option<String>, db_error> {
        let version = conn
            .query_row(
                "SELECT MAX(version) from db_config",
                rusqlite::NO_PARAMS,
                |row| row.get(0),
            )
            .optional()?;
        Ok(version)
    }

    fn apply_schema_2(tx: &SortitionDBTx, epochs: &[StacksEpoch]) -> Result<(), db_error> {
        for sql_exec in SORTITION_DB_SCHEMA_2 {
            tx.execute_batch(sql_exec)?;
        }

        SortitionDB::validate_and_insert_epochs(&tx, epochs)?;

        tx.execute(
            "INSERT OR REPLACE INTO db_config (version) VALUES (?1)",
            &["2"],
        )?;

        Ok(())
    }

    fn check_schema_version_or_error(&mut self) -> Result<(), db_error> {
        match SortitionDB::get_schema_version(self.conn()) {
            Ok(Some(version)) => {
                let expected_version = SORTITION_DB_VERSION.to_string();
                if version == expected_version {
                    Ok(())
                } else {
                    Err(db_error::Other(format!(
                        "The version of the sortition DB {} does not match the expected {} and cannot be updated from SortitionDB::open()",
                        version, expected_version
                    )))
                }
            }
            Ok(None) => panic!("The schema version of the sortition DB is not recorded."),
            Err(e) => panic!("Error obtaining the version of the sortition DB: {:?}", e),
        }
    }

    fn check_schema_version_and_update(&mut self, epochs: &[StacksEpoch]) -> Result<(), db_error> {
        let tx = self.tx_begin()?;
        match SortitionDB::get_schema_version(&tx) {
            Ok(Some(version)) => {
                let expected_version = SORTITION_DB_VERSION.to_string();
                if version == expected_version {
                    return Ok(());
                }
                if version == "1" {
                    SortitionDB::apply_schema_2(&tx, epochs)?;
                    tx.commit()?;
                    Ok(())
                } else {
                    panic!("The schema version of the sortition DB is invalid.")
                }
            }
            Ok(None) => panic!("The schema version of the sortition DB is not recorded."),
            Err(e) => panic!("Error obtaining the version of the sortition DB: {:?}", e),
        }
    }

    fn add_indexes(&mut self) -> Result<(), db_error> {
        let tx = self.tx_begin()?;
        for row_text in SORTITION_DB_INDEXES {
            tx.execute_batch(row_text)?;
        }
        tx.commit()?;
        Ok(())
    }
}

impl<'a> SortitionDBConn<'a> {
    pub fn as_handle<'b>(&'b self, chain_tip: &SortitionId) -> SortitionHandleConn<'b> {
        SortitionHandleConn {
            index: self.index,
            context: SortitionHandleContext {
                first_block_height: self.context.first_block_height.clone(),
                chain_tip: chain_tip.clone(),
            },
        }
    }

    /// Given a burnchain consensus hash,
    /// go get the last N Stacks block headers that won sortition
    /// leading up to the given header hash.  The ith slot in the vector will be Some(...) if there
    /// was a sortition, and None if not.
    /// Returns up to num_headers prior block header hashes.
    /// The list of hashes will be in ascending order -- the lowest-height block is item 0.
    /// The last hash will be the hash for the given consensus hash.
    pub fn get_stacks_header_hashes(
        &self,
        num_headers: u64,
        tip_consensus_hash: &ConsensusHash,
        cache: &BlockHeaderCache,
    ) -> Result<Vec<(ConsensusHash, Option<BlockHeaderHash>)>, db_error> {
        let mut ret = vec![];
        let tip_snapshot = SortitionDB::get_block_snapshot_consensus(self, tip_consensus_hash)?
            .ok_or_else(|| db_error::NotFoundError)?;

        if !tip_snapshot.pox_valid {
            warn!("Consensus hash {:?} corresponds to a sortition that is not on the canonical PoX fork", tip_consensus_hash);
            return Err(db_error::InvalidPoxSortition);
        }

        assert!(
            tip_snapshot.block_height >= self.context.first_block_height,
            "DB corruption: have snapshot with a smaller block height than the first block height"
        );

        let db_handle = self.as_handle(&tip_snapshot.sortition_id);

        let headers_count =
            if tip_snapshot.block_height - self.context.first_block_height < num_headers {
                tip_snapshot.block_height - self.context.first_block_height
            } else {
                num_headers
            };

        let mut ancestor_consensus_hash = tip_snapshot.consensus_hash;

        for _i in 0..headers_count {
            if let Some((header_hash_opt, prev_consensus_hash)) =
                cache.get(&ancestor_consensus_hash)
            {
                // cache hit
                ret.push((ancestor_consensus_hash, header_hash_opt.clone()));
                ancestor_consensus_hash = prev_consensus_hash.clone();
                continue;
            }

            // cache miss
            let ancestor_snapshot = SortitionDB::get_block_snapshot_consensus(
                db_handle.conn(),
                &ancestor_consensus_hash,
            )?
            .expect(&format!(
                "Discontiguous index: missing block for consensus hash {}",
                ancestor_consensus_hash
            ));

            // this can happen if this call is interleaved with a PoX invalidation transaction
            if !ancestor_snapshot.pox_valid {
                warn!("Consensus hash {:?} corresponds to a sortition that is not on the canonical PoX fork", ancestor_consensus_hash);
                return Err(db_error::InvalidPoxSortition);
            }

            let header_hash_opt = if ancestor_snapshot.sortition {
                Some(ancestor_snapshot.winning_stacks_block_hash.clone())
            } else {
                None
            };

            debug!(
                "CACHE MISS {} (height {}): {:?}",
                &ancestor_consensus_hash, ancestor_snapshot.block_height, &header_hash_opt
            );

            ret.push((ancestor_snapshot.consensus_hash, header_hash_opt.clone()));

            let ancestor_snapshot_parent = SortitionDB::get_block_snapshot(
                db_handle.conn(),
                &ancestor_snapshot.parent_sortition_id,
            )?
            .expect(&format!(
                "Discontiguous index: missing parent block of parent burn header hash {}",
                &ancestor_snapshot.parent_burn_header_hash
            ));

            ancestor_consensus_hash = ancestor_snapshot_parent.consensus_hash;
        }

        ret.reverse();
        Ok(ret)
    }

    /// Get the height of a burnchain block
    pub fn inner_get_burn_block_height(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, db_error> {
        let qry = "SELECT block_height FROM snapshots WHERE burn_header_hash = ?1 LIMIT 1";
        query_row(self.conn(), qry, &[burn_header_hash])
    }

    /// Get the burnchain hash given a height
    pub fn inner_get_burn_header_hash(
        &self,
        height: u32,
    ) -> Result<Option<BurnchainHeaderHash>, db_error> {
        let tip = SortitionDB::get_canonical_burn_chain_tip(self.conn())?;
        let ancestor_opt =
            SortitionDB::get_ancestor_snapshot(&self, height as u64, &tip.sortition_id)?
                .map(|snapshot| snapshot.burn_header_hash);
        Ok(ancestor_opt)
    }
}

// High-level functions used by ChainsCoordinator
impl SortitionDB {
    /// Get the sortition identifier corresponding to the provided
    ///  burnchain hash. In Hyperchains, because there is *no* PoX, this
    ///  is always just equal to the burnchain hash.
    pub fn get_sortition_id(
        &self,
        burnchain_header_hash: &BurnchainHeaderHash,
        _sortition_tip: &SortitionId,
    ) -> Result<Option<SortitionId>, BurnchainError> {
        Ok(Some(SortitionId(burnchain_header_hash.0.clone())))
    }

    pub fn is_sortition_processed(
        &self,
        burnchain_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<SortitionId>, BurnchainError> {
        let qry = "SELECT sortition_id FROM snapshots WHERE burn_header_hash = ? AND pox_valid = 1";
        query_row(self.conn(), qry, &[burnchain_header_hash]).map_err(BurnchainError::from)
    }

    fn get_block_height(
        conn: &Connection,
        sortition_id: &SortitionId,
    ) -> Result<Option<u32>, db_error> {
        let qry = "SELECT block_height FROM snapshots WHERE sortition_id = ? LIMIT 1";
        conn.query_row(qry, &[sortition_id], |row| row.get(0))
            .optional()
            .map_err(db_error::from)
    }

    /// Is the given block an expected PoX anchor in this sortition history?
    ///  if so, return the Stacks block hash
    pub fn is_stacks_block_pox_anchor(
        &mut self,
        block: &BlockHeaderHash,
        sortition_tip: &SortitionId,
    ) -> Result<Option<BlockHeaderHash>, BurnchainError> {
        let handle = self.index_handle(sortition_tip);
        let expects_block_as_anchor = handle
            .get_tip_indexed(&db_keys::pox_anchor_to_prepare_end(block))?
            .map(|_| block.clone());

        return Ok(expects_block_as_anchor);
    }

    fn parse_last_anchor_block_hash(s: Option<String>) -> Option<BlockHeaderHash> {
        s.map(|s| {
            if s == "" {
                None
            } else {
                Some(BlockHeaderHash::from_hex(&s).expect("BUG: Bad BlockHeaderHash stored in DB"))
            }
        })
        .flatten()
    }

    pub fn invalidate_descendants_of(
        &mut self,
        burn_block: &BurnchainHeaderHash,
    ) -> Result<(), BurnchainError> {
        let db_tx = self.tx_begin()?;
        let mut queue = vec![burn_block.clone()];

        while let Some(header) = queue.pop() {
            db_tx.tx().execute(
                "UPDATE snapshots SET pox_valid = 0 WHERE parent_burn_header_hash = ?",
                &[&header],
            )?;
            let mut stmt = db_tx.prepare(
                "SELECT DISTINCT burn_header_hash FROM snapshots WHERE parent_burn_header_hash = ?",
            )?;
            for next_header in stmt.query_map(&[&header], |row| row.get(0))? {
                queue.push(next_header?);
            }
        }

        db_tx.commit()?;
        Ok(())
    }

    /// Get the last sortition in the prepare phase that chose a particular Stacks block as the anchor,
    ///   or if the anchor is not expected, return None
    pub fn get_prepare_end_for(
        &mut self,
        sortition_tip: &SortitionId,
        anchor: &BlockHeaderHash,
    ) -> Result<Option<BlockSnapshot>, BurnchainError> {
        let handle = self.index_handle(sortition_tip);
        let prepare_end_sortid = match handle
            .get_tip_indexed(&db_keys::pox_anchor_to_prepare_end(anchor))?
        {
            Some(s) => SortitionId::from_hex(&s).expect("CORRUPTION: DB stored bad sortition ID"),
            None => return Ok(None),
        };
        let snapshot =
            SortitionDB::get_block_snapshot(self.conn(), &prepare_end_sortid)?.expect(&format!(
            "BUG: Sortition ID for prepare phase end is known, but no BlockSnapshot is stored: {}",
            &prepare_end_sortid
        ));
        Ok(Some(snapshot))
    }

    pub fn get_sortition_result(
        &self,
        id: &SortitionId,
    ) -> Result<Option<BlockSnapshot>, BurnchainError> {
        let snapshot = match SortitionDB::get_block_snapshot(self.conn(), id)? {
            Some(x) => x,
            None => return Ok(None),
        };

        Ok(Some(snapshot))
    }

    ///
    /// # Arguments
    /// * `burn_header` - the burnchain block header to process sortition for
    /// * `ops` - the parsed blockstack operations (will be validated in this function)
    /// * `burnchain` - a reference to the burnchain information struct
    /// * `from_tip` - tip of the "sortition chain" that is being built on
    /// * `next_pox_info` - iff this sortition is the first block in a reward cycle, this should be Some
    ///
    pub fn evaluate_sortition(
        &mut self,
        burn_header: &BurnchainBlockHeader,
        ops: Vec<BlockstackOperationType>,
        burnchain: &Burnchain,
        from_tip: &SortitionId,
        next_pox_info: Option<RewardCycleInfo>,
    ) -> Result<
        (
            BlockSnapshot,
            BurnchainStateTransition,
            Option<RewardSetInfo>,
        ),
        BurnchainError,
    > {
        let parent_sort_id = self
            .get_sortition_id(&burn_header.parent_block_hash, from_tip)?
            .ok_or_else(|| {
                warn!("Unknown block {:?}", burn_header.parent_block_hash);
                BurnchainError::MissingParentBlock
            })?;

        let mut sortition_db_handle = SortitionHandleTx::begin(self, &parent_sort_id)?;
        let parent_snapshot = sortition_db_handle
            .get_block_snapshot(&burn_header.parent_block_hash, &parent_sort_id)?
            .ok_or_else(|| {
                warn!("Missing block snapshot in sortition"; "burn_hash" => %burn_header.parent_block_hash, "sortition_id" => %parent_sort_id);
                BurnchainError::MissingParentBlock
            })?;

        let reward_set_vrf_hash = parent_snapshot
            .sortition_hash
            .mix_burn_header(&parent_snapshot.burn_header_hash);

        let reward_set_info = None;

        // Get any initial mining bonus which would be due to the winner of this block.
        let bonus_remaining =
            sortition_db_handle.get_initial_mining_bonus_remaining(&parent_sort_id)?;

        let initial_mining_bonus = if bonus_remaining > 0 {
            let mining_bonus_per_block = sortition_db_handle
                .get_initial_mining_bonus_per_block(&parent_sort_id)?
                .expect("BUG: initial mining bonus amount written, but not the per block amount.");
            cmp::min(bonus_remaining, mining_bonus_per_block)
        } else {
            0
        };

        let new_snapshot = sortition_db_handle.process_block_txs(
            &parent_snapshot,
            burn_header,
            burnchain,
            ops,
            next_pox_info,
            reward_set_info.as_ref(),
            initial_mining_bonus,
        )?;

        sortition_db_handle.store_transition_ops(&new_snapshot.0.sortition_id, &new_snapshot.1)?;

        // commit everything!
        sortition_db_handle.commit()?;
        Ok((new_snapshot.0, new_snapshot.1, reward_set_info))
    }

    #[cfg(test)]
    pub fn test_get_next_block_recipients(
        &mut self,
        burnchain: &Burnchain,
        next_pox_info: Option<&RewardCycleInfo>,
    ) -> Result<Option<RewardSetInfo>, BurnchainError> {
        let parent_snapshot = SortitionDB::get_canonical_burn_chain_tip(self.conn())?;
        self.get_next_block_recipients(burnchain, &parent_snapshot, next_pox_info)
    }

    /// There are never any block recipients. This comes from mainchain code.
    /// TODO: Delete this function once baseline subnet system is stable.
    pub fn get_next_block_recipients(
        &mut self,
        burnchain: &Burnchain,
        parent_snapshot: &BlockSnapshot,
        next_pox_info: Option<&RewardCycleInfo>,
    ) -> Result<Option<RewardSetInfo>, BurnchainError> {
        Ok(None)
    }

    pub fn is_stacks_block_in_sortition_set(
        &self,
        sortition_id: &SortitionId,
        block_to_check: &BlockHeaderHash,
    ) -> Result<bool, BurnchainError> {
        let result = self
            .index_handle(sortition_id)
            .get_tip_indexed(&db_keys::stacks_block_present(block_to_check))?;
        Ok(result.is_some())
    }

    pub fn latest_stacks_blocks_processed(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<u64, BurnchainError> {
        let db_handle = self.index_handle(sortition_id);
        SortitionDB::get_max_arrival_index(&db_handle).map_err(|e| BurnchainError::from(e))
    }

    /// Get a burn blockchain snapshot, given a burnchain configuration struct.
    /// Used mainly by the network code to determine what the chain tip currently looks like.
    pub fn get_burnchain_view(
        conn: &DBConn,
        burnchain: &Burnchain,
        chain_tip: &BlockSnapshot,
    ) -> Result<BurnchainView, db_error> {
        if chain_tip.block_height < burnchain.first_block_height {
            // should never happen, but don't panic since this is network-callable code
            error!(
                "Invalid block height from DB: {}: expected at least {}",
                chain_tip.block_height, burnchain.first_block_height
            );
            return Err(db_error::Corruption);
        }

        if chain_tip.block_height < burnchain.stable_confirmations as u64 {
            // should never happen, but don't panic since this is network-callable code
            error!(
                "Invalid block height from DB: {}: expected at least {}",
                chain_tip.block_height, burnchain.stable_confirmations
            );
            return Err(db_error::Corruption);
        }

        let stable_block_height = cmp::max(
            burnchain.first_block_height,
            chain_tip.block_height - (burnchain.stable_confirmations as u64),
        );

        // get all burn block hashes between the chain tip, and the stable height back
        // MAX_NEIGHBOR_BLOCK_DELAY
        let oldest_height = if stable_block_height < MAX_NEIGHBOR_BLOCK_DELAY {
            0
        } else {
            stable_block_height - MAX_NEIGHBOR_BLOCK_DELAY
        };

        let mut last_burn_block_hashes = HashMap::new();
        let tip_height = chain_tip.block_height;

        let mut cursor = chain_tip.clone();
        let mut cur_height = cursor.block_height;

        for _height in oldest_height..(tip_height + 1) {
            let (ancestor_hash, ancestor_height) =
                if cursor.block_height > burnchain.first_block_height {
                    match SortitionDB::get_block_snapshot(conn, &cursor.parent_sortition_id) {
                        Ok(Some(new_cursor)) => {
                            let ret = (cursor.burn_header_hash.clone(), cursor.block_height);

                            cursor = new_cursor;
                            assert_eq!(cursor.block_height + 1, cur_height);

                            cur_height = cursor.block_height;
                            ret
                        }
                        _ => {
                            cur_height = cur_height.saturating_sub(1);
                            (burnchain.first_block_hash.clone(), cur_height)
                        }
                    }
                } else {
                    cur_height = cur_height.saturating_sub(1);
                    (burnchain.first_block_hash.clone(), cur_height)
                };

            last_burn_block_hashes.insert(ancestor_height, ancestor_hash);
        }

        let burn_stable_block_hash = last_burn_block_hashes
            .get(&stable_block_height)
            .unwrap_or(&burnchain.first_block_hash)
            .clone();

        test_debug!(
            "Chain view: {},{}-{},{}",
            chain_tip.block_height,
            chain_tip.burn_header_hash,
            stable_block_height,
            &burn_stable_block_hash
        );
        Ok(BurnchainView {
            burn_block_height: chain_tip.block_height,
            burn_block_hash: chain_tip.burn_header_hash,
            burn_stable_block_height: stable_block_height,
            burn_stable_block_hash: burn_stable_block_hash,
            last_burn_block_hashes: last_burn_block_hashes,
        })
    }
}

// Querying methods
impl SortitionDB {
    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    pub fn get_canonical_burn_chain_tip(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let qry = "SELECT * FROM snapshots WHERE pox_valid = 1 ORDER BY block_height DESC, burn_header_hash ASC LIMIT 1";
        query_row(conn, qry, NO_PARAMS)
            .map(|opt| opt.expect("CORRUPTION: No canonical burnchain tip"))
    }

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    pub fn get_canonical_chain_tip_bhh(conn: &Connection) -> Result<BurnchainHeaderHash, db_error> {
        let qry = "SELECT burn_header_hash FROM snapshots WHERE pox_valid = 1 ORDER BY block_height DESC, burn_header_hash ASC LIMIT 1";
        match conn.query_row(qry, NO_PARAMS, |row| row.get(0)).optional() {
            Ok(opt) => Ok(opt.expect("CORRUPTION: No canonical burnchain tip")),
            Err(e) => Err(db_error::from(e)),
        }
    }

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    pub fn get_canonical_sortition_tip(conn: &Connection) -> Result<SortitionId, db_error> {
        let qry = "SELECT sortition_id FROM snapshots WHERE pox_valid = 1 ORDER BY block_height DESC, burn_header_hash ASC LIMIT 1";
        match conn.query_row(qry, NO_PARAMS, |row| row.get(0)).optional() {
            Ok(opt) => Ok(opt.expect("CORRUPTION: No canonical burnchain tip")),
            Err(e) => Err(db_error::from(e)),
        }
    }

    pub fn index_handle_at_tip<'a>(&'a self) -> SortitionHandleConn<'a> {
        let sortition_id = SortitionDB::get_canonical_sortition_tip(self.conn()).unwrap();
        self.index_handle(&sortition_id)
    }

    /// Open a tx handle at the burn chain tip
    pub fn tx_begin_at_tip<'a>(&'a mut self) -> SortitionHandleTx<'a> {
        let sortition_id = SortitionDB::get_canonical_sortition_tip(self.conn()).unwrap();
        self.tx_handle_begin(&sortition_id).unwrap()
    }

    /// Get the canonical Stacks chain tip -- this gets memoized on the canonical burn chain tip.
    pub fn get_canonical_stacks_chain_tip_hash(
        conn: &Connection,
    ) -> Result<(ConsensusHash, BlockHeaderHash), db_error> {
        let sn = SortitionDB::get_canonical_burn_chain_tip(conn)?;

        let stacks_block_hash = sn.canonical_stacks_tip_hash;
        let consensus_hash = sn.canonical_stacks_tip_consensus_hash;

        Ok((consensus_hash, stacks_block_hash))
    }

    /// Get an accepted stacks block header in a fork whose chain tip has not yet committed
    /// to it.
    fn get_accepted_stacks_block_pointer(
        conn: &Connection,
        tip_consensus_hash: &ConsensusHash,
        stacks_block_hash: &BlockHeaderHash,
    ) -> Result<Option<AcceptedStacksBlockHeader>, db_error> {
        let args: &[&dyn ToSql] = &[tip_consensus_hash, stacks_block_hash];
        query_row_panic(conn, "SELECT * FROM canonical_accepted_stacks_blocks WHERE tip_consensus_hash = ?1 AND stacks_block_hash = ?2", args,
                        || format!("BUG: the same Stacks block {} shows up twice or more in the same burn chain fork (whose tip is {})", stacks_block_hash, tip_consensus_hash))
    }

    /// Add an accepted Stacks block to the canonical accepted stacks header table, to indicate
    /// that it will be committed to by the next burn block added to the canonical chain tip.  Used
    /// to identify Stacks blocks that get accepted in the mean time, so we can ensure that the
    /// canonical burn chain tip always points to the canonical stacks chain tip.
    fn insert_accepted_stacks_block_pointer(
        tx: &Transaction,
        tip_consensus_hash: &ConsensusHash,
        consensus_hash: &ConsensusHash,
        stacks_block_hash: &BlockHeaderHash,
        stacks_block_height: u64,
    ) -> Result<(), db_error> {
        let args: &[&dyn ToSql] = &[
            tip_consensus_hash,
            consensus_hash,
            stacks_block_hash,
            &u64_to_sql(stacks_block_height)?,
        ];
        tx.execute("INSERT OR REPLACE INTO canonical_accepted_stacks_blocks (tip_consensus_hash, consensus_hash, stacks_block_hash, block_height) VALUES (?1, ?2, ?3, ?4)", args)
            .map_err(db_error::SqliteError)?;
        Ok(())
    }

    /// Get the maximum arrival index for any known snapshot.
    fn get_max_arrival_index(conn: &Connection) -> Result<u64, db_error> {
        match conn
            .query_row(
                "SELECT IFNULL(MAX(arrival_index), 0) FROM snapshots",
                NO_PARAMS,
                |row| Ok(u64::from_row(row).expect("Expected u64 in database")),
            )
            .optional()?
        {
            Some(arrival_index) => Ok(arrival_index),
            None => Ok(0),
        }
    }

    /// Get a snapshot with an arrived block (i.e. a block that was marked as processed)
    fn get_snapshot_by_arrival_index(
        conn: &Connection,
        arrival_index: u64,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        query_row_panic(
            conn,
            "SELECT * FROM snapshots WHERE arrival_index = ?1 AND stacks_block_accepted > 0 AND pox_valid = 1",
            &[&u64_to_sql(arrival_index)?],
            || "BUG: multiple snapshots have the same non-zero arrival index".to_string(),
        )
    }

    pub fn get_sortition_id_by_consensus(
        conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<SortitionId>, db_error> {
        let qry = "SELECT sortition_id FROM snapshots WHERE consensus_hash = ?1 AND pox_valid = 1 LIMIT 1";
        let args = [&consensus_hash];
        query_row_panic(conn, qry, &args, || {
            format!(
                "FATAL: multiple block snapshots for the same block with consensus hash {}",
                consensus_hash
            )
        })
    }

    /// Get a snapshot for an existing burn chain block given its consensus hash.
    /// The snapshot may not be valid.
    pub fn get_block_snapshot_consensus(
        conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE consensus_hash = ?1";
        let args = [&consensus_hash];
        query_row_panic(conn, qry, &args, || {
            format!(
                "FATAL: multiple block snapshots for the same block with consensus hash {}",
                consensus_hash
            )
        })
    }

    /// Get a snapshot for an processed sortition.
    /// The snapshot may not be valid
    pub fn get_block_snapshot(
        conn: &Connection,
        sortition_id: &SortitionId,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE sortition_id = ?1";
        let args = [&sortition_id];
        query_row_panic(conn, qry, &args, || {
            format!(
                "FATAL: multiple block snapshots for the same block {}",
                sortition_id
            )
        })
        .map(|x| {
            if x.is_none() {
                test_debug!("No snapshot with burn hash {}", sortition_id);
            }
            x
        })
    }

    /// Get the first snapshot
    pub fn get_first_block_snapshot(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let qry = "SELECT * FROM snapshots WHERE consensus_hash = ?1";
        let result = query_row_panic(conn, qry, &[&ConsensusHash::empty()], || {
            "FATAL: multiple first-block snapshots".into()
        })?;
        match result {
            None => {
                // should never happen
                panic!("FATAL: no first snapshot");
            }
            Some(snapshot) => Ok(snapshot),
        }
    }

    pub fn is_pox_active(
        &self,
        _burnchain: &Burnchain,
        _block: &BlockSnapshot,
    ) -> Result<bool, db_error> {
        Ok(false)
    }

    /// Find out how any burn tokens were destroyed in a given block on a given fork.
    pub fn get_block_burn_amount(
        _conn: &Connection,
        _block_snapshot: &BlockSnapshot,
    ) -> Result<u64, db_error> {
        Ok(0)
    }

    /// Get all block commitments registered in a block on the burn chain's history in this fork.
    /// Returns the list of block commits in order by vtxindex.
    pub fn get_block_commits_by_block(
        conn: &Connection,
        sortition: &SortitionId,
    ) -> Result<Vec<LeaderBlockCommitOp>, db_error> {
        let qry = "SELECT * FROM block_commits WHERE sortition_id = ?1";
        let args: &[&dyn ToSql] = &[sortition];

        query_rows(conn, qry, args)
    }

    pub fn get_block_winning_vtxindex(
        conn: &Connection,
        sortition: &SortitionId,
    ) -> Result<Option<u16>, db_error> {
        let qry = "SELECT vtxindex FROM block_commits WHERE sortition_id = ?1 
                    AND txid = (
                      SELECT winning_block_txid FROM snapshots WHERE sortition_id = ?2 LIMIT 1) LIMIT 1";
        let args: &[&dyn ToSql] = &[sortition, sortition];
        conn.query_row(qry, args, |row| row.get(0))
            .optional()
            .map_err(db_error::from)
    }

    /// Given the fork index hash of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork, find the snapshot of the block at that height.
    pub fn get_ancestor_snapshot<C: SortitionContext>(
        ic: &IndexDBConn<'_, C, SortitionId>,
        ancestor_block_height: u64,
        tip_block_hash: &SortitionId,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(ancestor_block_height < BLOCK_HEIGHT_MAX);

        let ancestor = match get_ancestor_sort_id(ic, ancestor_block_height, tip_block_hash)? {
            Some(id) => id,
            None => {
                debug!(
                    "No ancestor block {} from {} in index",
                    ancestor_block_height, tip_block_hash
                );
                return Ok(None);
            }
        };

        SortitionDB::get_block_snapshot(ic, &ancestor)
    }

    /// Given the fork index hash of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork, find the snapshot of the block at that height.
    pub fn get_ancestor_snapshot_tx<C: SortitionContext>(
        ic: &mut IndexDBTx<'_, C, SortitionId>,
        ancestor_block_height: u64,
        tip_block_hash: &SortitionId,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(ancestor_block_height < BLOCK_HEIGHT_MAX);

        let ancestor = match get_ancestor_sort_id_tx(ic, ancestor_block_height, tip_block_hash)? {
            Some(id) => id,
            None => {
                debug!(
                    "No ancestor block {} from {} in index",
                    ancestor_block_height, tip_block_hash
                );
                return Ok(None);
            }
        };

        SortitionDB::get_block_snapshot(ic.tx(), &ancestor)
    }

    /// Get a parent block commit at a specific location in the burn chain on a particular fork.
    /// Returns None if there is no block commit at this location.
    pub fn get_block_commit_parent<C: SortitionContext>(
        ic: &IndexDBConn<'_, C, SortitionId>,
        block_height: u64,
        vtxindex: u32,
        tip: &SortitionId,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_id = match get_ancestor_sort_id(ic, block_height, tip)? {
            Some(id) => id,
            None => {
                return Ok(None);
            }
        };

        SortitionDB::get_block_commit_of_sortition(ic, &ancestor_id, block_height, vtxindex)
    }

    fn get_block_commit_of_sortition(
        conn: &Connection,
        sortition: &SortitionId,
        block_height: u64,
        vtxindex: u32,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        let qry = "SELECT * FROM block_commits WHERE sortition_id = ?1 AND block_height = ?2 AND vtxindex = ?3 LIMIT 2";
        let args: &[&dyn ToSql] = &[sortition, &u64_to_sql(block_height)?, &vtxindex];
        query_row_panic(conn, qry, args, || {
            format!(
                "Multiple parent blocks at {},{} in {}",
                block_height, vtxindex, sortition
            )
        })
    }

    /// Get a block commit by its committed block
    pub fn get_block_commit_for_stacks_block(
        conn: &Connection,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        let (sortition_id, winning_txid) = match SortitionDB::get_block_snapshot_consensus(
            conn,
            consensus_hash,
        )? {
            Some(sn) => {
                if !sn.pox_valid {
                    warn!("Consensus hash {:?} corresponds to a sortition that is not on the canonical PoX fork", consensus_hash);
                    return Err(db_error::InvalidPoxSortition);
                }
                (sn.sortition_id, sn.winning_block_txid)
            }
            None => {
                return Ok(None);
            }
        };

        let qry = "SELECT * FROM block_commits WHERE sortition_id = ?1 AND committed_block_hash = ?2 AND txid = ?3";
        let args: [&dyn ToSql; 3] = [&sortition_id, &block_hash, &winning_txid];
        query_row_panic(conn, qry, &args, || {
            format!("FATAL: multiple block commits for {}", &block_hash)
        })
    }

    /// Get a block snapshot for a winning block hash in a given burn chain fork.
    pub fn get_block_snapshot_for_winning_stacks_block(
        ic: &SortitionDBConn,
        tip: &SortitionId,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<BlockSnapshot>, db_error> {
        match ic.get_indexed(tip, &db_keys::stacks_block_present(block_hash))? {
            Some(sortition_id_hex) => {
                let sortition_id = SortitionId::from_hex(&sortition_id_hex)
                    .expect("FATAL: DB stored non-parseable sortition id");
                SortitionDB::get_block_snapshot(ic, &sortition_id)
            }
            None => Ok(None),
        }
    }

    /// Merge the result of get_stacks_header_hashes() into a BlockHeaderCache
    pub fn merge_block_header_cache(
        cache: &mut BlockHeaderCache,
        header_data: &Vec<(ConsensusHash, Option<BlockHeaderHash>)>,
    ) -> () {
        if header_data.len() > 0 {
            let mut i = header_data.len() - 1;
            while i > 0 {
                let cur_consensus_hash = &header_data[i].0;
                let cur_block_opt = &header_data[i].1;

                if let Some((ref cached_block_opt, _)) = cache.get(cur_consensus_hash) {
                    assert_eq!(cached_block_opt, cur_block_opt);
                } else {
                    let prev_consensus_hash = header_data[i - 1].0.clone();
                    cache.insert(
                        (*cur_consensus_hash).clone(),
                        ((*cur_block_opt).clone(), prev_consensus_hash.clone()),
                    );
                }

                i -= 1;
            }
        }
        debug!("Block header cache has {} items", cache.len());
    }

    /// Get a blockstack burnchain operation by txid
    #[cfg(test)]
    pub fn get_burnchain_transaction(
        conn: &Connection,
        txid: &Txid,
    ) -> Result<Option<BlockstackOperationType>, db_error> {
        // block commit?
        let block_commit_sql = "SELECT * FROM block_commits WHERE txid = ?1 LIMIT 1";
        let args = [txid];

        let block_commit_res = query_row_panic(conn, &block_commit_sql, &args, || {
            "Multiple block commits with same txid".to_string()
        })?;
        if let Some(block_commit) = block_commit_res {
            return Ok(Some(BlockstackOperationType::LeaderBlockCommit(
                block_commit,
            )));
        }

        Ok(None)
    }

    /// Get the StacksEpoch for a given burn block height
    pub fn get_stacks_epoch(
        conn: &DBConn,
        burn_block_height: u64,
    ) -> Result<Option<StacksEpoch>, db_error> {
        let sql =
            "SELECT * FROM epochs WHERE start_block_height <= ?1 AND ?2 < end_block_height LIMIT 1";
        let args: &[&dyn ToSql] = &[
            &u64_to_sql(burn_block_height)?,
            &u64_to_sql(burn_block_height)?,
        ];
        query_row(conn, sql, args)
    }

    /// Get all StacksEpochs, in order by ascending start height
    pub fn get_stacks_epochs(conn: &DBConn) -> Result<Vec<StacksEpoch>, db_error> {
        let sql = "SELECT * FROM epochs ORDER BY start_block_height ASC";
        query_rows(conn, sql, NO_PARAMS)
    }

    pub fn get_stacks_epoch_by_epoch_id(
        conn: &DBConn,
        epoch_id: &StacksEpochId,
    ) -> Result<Option<StacksEpoch>, db_error> {
        let sql = "SELECT * FROM epochs WHERE epoch_id = ?1 LIMIT 1";
        let args: &[&dyn ToSql] = &[&(*epoch_id as u32)];
        query_row(conn, sql, args)
    }
}

impl<'a> SortitionHandleTx<'a> {
    /// Append a snapshot to a chain tip, and update various chain tip statistics.
    /// Returns the new state root of this fork.
    /// `initialize_bonus` - if Some(..), then this snapshot is the first mined snapshot,
    ///    and this method should initialize the `initial_mining_bonus` fields in the sortition db.
    pub fn append_chain_tip_snapshot(
        &mut self,
        parent_snapshot: &BlockSnapshot,
        snapshot: &BlockSnapshot,
        block_ops: &Vec<BlockstackOperationType>,
        _reward_info: Option<&RewardSetInfo>,
        initialize_bonus: Option<InitialMiningBonus>,
    ) -> Result<TrieHash, db_error> {
        assert_eq!(
            snapshot.parent_burn_header_hash,
            parent_snapshot.burn_header_hash
        );
        assert_eq!(snapshot.parent_sortition_id, parent_snapshot.sortition_id);
        assert_eq!(parent_snapshot.block_height + 1, snapshot.block_height);
        if snapshot.sortition {
            assert_eq!(parent_snapshot.num_sortitions + 1, snapshot.num_sortitions);
        } else {
            assert_eq!(parent_snapshot.num_sortitions, snapshot.num_sortitions);
        }

        let mut parent_sn = parent_snapshot.clone();
        let root_hash =
            self.index_add_fork_info(&mut parent_sn, snapshot, block_ops, initialize_bonus)?;

        let mut sn = snapshot.clone();
        sn.index_root = root_hash.clone();

        // preserve memoized stacks chain tip from this burn chain fork
        sn.canonical_stacks_tip_height = parent_sn.canonical_stacks_tip_height;
        sn.canonical_stacks_tip_hash = parent_sn.canonical_stacks_tip_hash;
        sn.canonical_stacks_tip_consensus_hash = parent_sn.canonical_stacks_tip_consensus_hash;

        self.insert_block_snapshot(&sn)?;

        for block_op in block_ops {
            self.store_burnchain_transaction(block_op, &sn.sortition_id)?;
        }

        Ok(root_hash)
    }

    pub fn get_initial_mining_bonus_remaining(
        &mut self,
        chain_tip: &SortitionId,
    ) -> Result<u128, db_error> {
        self.get_indexed(&chain_tip, db_keys::initial_mining_bonus_remaining())?
            .map(|s| Ok(s.parse().expect("BUG: bad mining bonus stored in DB")))
            .unwrap_or(Ok(0))
    }

    pub fn get_initial_mining_bonus_per_block(
        &mut self,
        chain_tip: &SortitionId,
    ) -> Result<Option<u128>, db_error> {
        Ok(self
            .get_indexed(&chain_tip, db_keys::initial_mining_bonus_per_block())?
            .map(|s| s.parse().expect("BUG: bad mining bonus stored in DB")))
    }

    fn store_burn_distribution(
        &mut self,
        _new_sortition: &SortitionId,
        _transition: &BurnchainStateTransition,
    ) {
    }

    fn store_transition_ops(
        &mut self,
        new_sortition: &SortitionId,
        transition: &BurnchainStateTransition,
    ) -> Result<(), db_error> {
        let sql = "INSERT INTO snapshot_transition_ops (sortition_id, accepted_ops) VALUES (?, ?)";
        let args: &[&dyn ToSql] = &[
            new_sortition,
            &serde_json::to_string(&transition.accepted_ops).unwrap(),
        ];
        self.execute(sql, args)?;
        self.store_burn_distribution(new_sortition, transition);
        Ok(())
    }

    /// Store a blockstack burnchain operation
    fn store_burnchain_transaction(
        &mut self,
        blockstack_op: &BlockstackOperationType,
        sort_id: &SortitionId,
    ) -> Result<(), db_error> {
        match blockstack_op {
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                info!(
                    "ACCEPTED burnchain operation";
                    "op" => "leader_block_commit",
                    "l1_stacks_block_id" => %op.burn_header_hash,
                    "txid" => %op.txid,
                    "commited_block_hash" => %op.block_header_hash,
                );
                self.insert_block_commit(op, sort_id)
            }
            BlockstackOperationType::DepositFt(ref op) => {
                info!(
                    "ACCEPTED burnchain operation";
                    "op" => "deposit_ft",
                    "l1_stacks_block_id" => %op.burn_header_hash,
                    "txid" => %op.txid,
                    "l1_contract_id" => %op.l1_contract_id,
                    "hc_contract_id" => %op.hc_contract_id,
                    "ft_name" => %op.ft_name,
                    "amount" => %op.amount,
                    "sender" => %op.sender,
                );

                // TODO(hyperchains) - store operation!
                Ok(())
            }
            BlockstackOperationType::DepositNft(ref op) => {
                info!(
                    "ACCEPTED burnchain operation";
                    "op" => "deposit_nft",
                    "l1_stacks_block_id" => %op.burn_header_hash,
                    "txid" => %op.txid,
                    "l1_contract_id" => %op.l1_contract_id,
                    "hc_contract_id" => %op.hc_contract_id,
                    "id" => %op.id,
                    "sender" => %op.sender,
                );

                // TODO(hyperchains) - store operation!
                Ok(())
            }
            BlockstackOperationType::WithdrawFt(ref op) => {
                info!(
                    "ACCEPTED burnchain operation";
                    "op" => "withdraw_ft",
                    "l1_stacks_block_id" => %op.burn_header_hash,
                    "txid" => %op.txid,
                    "l1_contract_id" => %op.l1_contract_id,
                    "hc_contract_id" => %op.hc_contract_id,
                    "ft_name" => %op.ft_name,
                    "amount" => %op.amount,
                    "recipient" => %op.recipient,
                );

                // TODO(hyperchains) - store operation!
                Ok(())
            }
            BlockstackOperationType::WithdrawNft(ref op) => {
                info!(
                    "ACCEPTED burnchain operation";
                    "op" => "withdraw_nft",
                    "l1_stacks_block_id" => %op.burn_header_hash,
                    "txid" => %op.txid,
                    "l1_contract_id" => %op.l1_contract_id,
                    "hc_contract_id" => %op.hc_contract_id,
                    "id" => %op.id,
                    "recipient" => %op.recipient,
                );

                // TODO(hyperchains) - store operation!
                Ok(())
            }
        }
    }

    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    fn insert_block_commit(
        &mut self,
        block_commit: &LeaderBlockCommitOp,
        sort_id: &SortitionId,
    ) -> Result<(), db_error> {
        let args: &[&dyn ToSql] = &[
            &block_commit.txid,
            &block_commit.burn_header_hash,
            &block_commit.block_header_hash,
            sort_id,
        ];

        self.execute(
            "INSERT INTO block_commits (txid, l1_block_id, committed_block_hash, sortition_id) \
                      VALUES (?1, ?2, ?3, ?4)",
            args,
        )?;

        Ok(())
    }

    /// Insert a snapshots row from a block's-worth of operations.
    /// Do not call directly -- use append_chain_tip_snapshot to preserve the fork table structure.
    fn insert_block_snapshot(&self, snapshot: &BlockSnapshot) -> Result<(), db_error> {
        assert!(snapshot.block_height < BLOCK_HEIGHT_MAX);
        assert!(snapshot.num_sortitions < BLOCK_HEIGHT_MAX);

        test_debug!(
            "Insert block snapshot state {} for block {} ({},{}) {}",
            snapshot.index_root,
            snapshot.block_height,
            snapshot.burn_header_hash,
            snapshot.parent_burn_header_hash,
            snapshot.num_sortitions
        );

        let args: &[&dyn ToSql] = &[
            &u64_to_sql(snapshot.block_height)?,
            &snapshot.burn_header_hash,
            &u64_to_sql(snapshot.burn_header_timestamp)?,
            &snapshot.parent_burn_header_hash,
            &snapshot.consensus_hash,
            &snapshot.ops_hash,
            &snapshot.total_burn.to_string(),
            &snapshot.sortition,
            &snapshot.sortition_hash,
            &snapshot.winning_block_txid,
            &snapshot.winning_stacks_block_hash,
            &snapshot.index_root,
            &u64_to_sql(snapshot.num_sortitions)?,
            &snapshot.stacks_block_accepted,
            &u64_to_sql(snapshot.stacks_block_height)?,
            &u64_to_sql(snapshot.arrival_index)?,
            &u64_to_sql(snapshot.canonical_stacks_tip_height)?,
            &snapshot.canonical_stacks_tip_hash,
            &snapshot.canonical_stacks_tip_consensus_hash,
            &snapshot.sortition_id,
            &snapshot.parent_sortition_id,
            &snapshot.pox_valid,
            &snapshot.accumulated_coinbase_ustx.to_string(),
        ];

        self.execute("INSERT INTO snapshots \
                      (block_height, burn_header_hash, burn_header_timestamp, parent_burn_header_hash, consensus_hash, ops_hash, total_burn, sortition, sortition_hash, winning_block_txid, winning_stacks_block_hash, index_root, num_sortitions, \
                      stacks_block_accepted, stacks_block_height, arrival_index, canonical_stacks_tip_height, canonical_stacks_tip_hash, canonical_stacks_tip_consensus_hash, sortition_id, parent_sortition_id, pox_valid, accumulated_coinbase_ustx) \
                      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)", args)
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Record fork information to the index and calculate the new fork index root hash.
    /// * sortdb::vrf::${VRF_PUBLIC_KEY} --> 0 or 1 (1 if available, 0 if consumed), for each VRF public key we process
    /// * sortdb::last_sortition --> $BURN_BLOCK_HASH, for each block that had a sortition
    /// * sortdb::sortition_block_hash::${STACKS_BLOCK_HASH} --> $BURN_BLOCK_HASH for each winning block sortition
    /// * sortdb::stacks::block::${STACKS_BLOCK_HASH} --> ${STACKS_BLOCK_HEIGHT} for each block that has been accepted so far
    /// * sortdb::stacks::block::max_arrival_index --> ${ARRIVAL_INDEX} to set the maximum arrival index processed in this fork
    /// * sortdb::pox_reward_set::${n} --> recipient Bitcoin address, to track the reward set as the permutation progresses
    ///
    /// `recipient_info` is used to pass information to this function about which reward set addresses were consumed
    ///   during this sortition. this object will be None in the following cases:
    ///    * The reward cycle had an anchor block, but it isn't known by this node.
    ///    * The reward cycle did not have anchor block
    ///    * The Stacking recipient set is empty (either because this reward cycle has already exhausted the set of addresses or because no one ever Stacked).
    ///
    /// NOTE: the resulting index root must be globally unique.  This is guaranteed because each
    /// burn block hash is unique, no matter what fork it's on (and this index uses burn block
    /// hashes as its index's block hash data).
    fn index_add_fork_info(
        &mut self,
        parent_snapshot: &mut BlockSnapshot,
        snapshot: &BlockSnapshot,
        _block_ops: &Vec<BlockstackOperationType>,
        initialize_bonus: Option<InitialMiningBonus>,
    ) -> Result<TrieHash, db_error> {
        if !snapshot.is_initial() {
            assert_eq!(
                snapshot.parent_burn_header_hash,
                parent_snapshot.burn_header_hash
            );
            assert_eq!(&parent_snapshot.sortition_id, &self.context.chain_tip);
        }

        // data we want to store
        let mut keys = vec![];
        let mut values = vec![];

        // map burnchain header hashes to sortition ids
        keys.push(db_keys::sortition_id_for_bhh(&snapshot.burn_header_hash));
        values.push(snapshot.sortition_id.to_hex());

        // if this commit has a sortition, record its burn block hash and stacks block hash
        if snapshot.sortition {
            keys.push(db_keys::last_sortition().to_string());
            values.push(snapshot.burn_header_hash.to_hex());

            keys.push(db_keys::stacks_block_present(
                &snapshot.winning_stacks_block_hash,
            ));
            values.push(snapshot.sortition_id.to_hex());
        }

        if let Some(initialize_bonus) = initialize_bonus {
            // first sortition with a winner, set the initial mining bonus fields
            keys.push(db_keys::initial_mining_bonus_per_block().into());
            values.push(initialize_bonus.per_block.to_string());

            let total_reward_remaining = initialize_bonus
                .total_reward
                .saturating_sub(initialize_bonus.per_block);
            keys.push(db_keys::initial_mining_bonus_remaining().into());
            values.push(total_reward_remaining.to_string());
        } else if parent_snapshot.total_burn > 0 {
            // mining has started, check if there's still any remaining bonus that this
            //  block consumed, and then decrement
            let prior_bonus_remaining =
                self.get_initial_mining_bonus_remaining(&parent_snapshot.sortition_id)?;
            if prior_bonus_remaining > 0 {
                let mining_bonus_per_block = self
                    .get_initial_mining_bonus_per_block(&parent_snapshot.sortition_id)?
                    .expect(
                        "BUG: initial mining bonus amount written, but not the per block amount.",
                    );
                let bonus_remaining = prior_bonus_remaining.saturating_sub(mining_bonus_per_block);
                keys.push(db_keys::initial_mining_bonus_remaining().into());
                values.push(bonus_remaining.to_string());
            }
        }

        // storing null PoX info
        keys.push(db_keys::pox_reward_set_size().to_string());
        values.push(db_keys::reward_set_size_to_string(0));
        keys.push(db_keys::pox_last_anchor().to_string());
        values.push("".to_string());

        // commit to all newly-arrived blocks
        let (mut block_arrival_keys, mut block_arrival_values) =
            self.process_new_block_arrivals(parent_snapshot)?;
        keys.append(&mut block_arrival_keys);
        values.append(&mut block_arrival_values);

        // store each indexed field
        //  -- marf tx _must_ have already began
        self.put_indexed_begin(&parent_snapshot.sortition_id, &snapshot.sortition_id)?;

        let root_hash = self.put_indexed_all(&keys, &values)?;
        self.context.chain_tip = snapshot.sortition_id.clone();
        Ok(root_hash)
    }

    /// Find all stacks blocks that were processed since parent_tip had been processed, and generate MARF
    /// key/value pairs for the subset that arrived on ancestor blocks of the parent.  Update the
    /// given parent chain tip to have the correct memoized canonical chain tip present in the fork
    /// it represents.
    fn process_new_block_arrivals(
        &mut self,
        parent_tip: &mut BlockSnapshot,
    ) -> Result<(Vec<String>, Vec<String>), db_error> {
        let mut keys = vec![];
        let mut values = vec![];

        let mut new_block_arrivals = vec![];

        let old_max_arrival_index = self
            .get_indexed(
                &parent_tip.sortition_id,
                &db_keys::stacks_block_max_arrival_index(),
            )?
            .unwrap_or("0".into())
            .parse::<u64>()
            .expect("BUG: max arrival index is not a u64");

        let max_arrival_index = SortitionDB::get_max_arrival_index(self.tx())?;

        // find all Stacks block hashes who arrived since this parent_tip was built.
        for ari in old_max_arrival_index..(max_arrival_index + 1) {
            test_debug!("Get block with arrival index {}", ari);
            let arrival_sn = match SortitionDB::get_snapshot_by_arrival_index(self.tx(), ari)? {
                Some(sn) => sn,
                None => {
                    continue;
                }
            };

            // must be an ancestor of this tip, or must be this tip
            if let Some(sn) =
                self.get_block_snapshot(&arrival_sn.burn_header_hash, &parent_tip.sortition_id)?
            {
                assert_eq!(sn, arrival_sn);

                info!(
                    "New Stacks anchored block arrived since {}: block {} ({}) ari={} tip={}",
                    parent_tip.burn_header_hash,
                    sn.stacks_block_height,
                    sn.winning_stacks_block_hash,
                    ari,
                    &sn.burn_header_hash
                );
                new_block_arrivals.push((
                    sn.consensus_hash,
                    sn.winning_stacks_block_hash,
                    sn.stacks_block_height,
                ));
            } else {
                // this block did not arrive on an ancestor block
                continue;
            }
        }

        let mut best_tip_block_bhh = parent_tip.canonical_stacks_tip_hash.clone();
        let mut best_tip_consensus_hash = parent_tip.canonical_stacks_tip_consensus_hash.clone();
        let mut best_tip_height = parent_tip.canonical_stacks_tip_height;

        // NOTE: new_block_arrivals is ordered by arrival index, which means it is partially
        // ordered by block height!
        for (consensus_hash, block_bhh, height) in new_block_arrivals.into_iter() {
            keys.push(db_keys::stacks_block_index(&block_bhh));
            values.push(db_keys::stacks_block_index_value(height));

            if height > best_tip_height {
                debug!(
                    "At tip {}: {}/{} (height {}) is superceded by {}/{} (height {})",
                    &parent_tip.burn_header_hash,
                    &best_tip_consensus_hash,
                    &best_tip_block_bhh,
                    best_tip_height,
                    consensus_hash,
                    block_bhh,
                    height
                );

                best_tip_block_bhh = block_bhh;
                best_tip_consensus_hash = consensus_hash;
                best_tip_height = height;
            }
        }

        // update parent tip
        parent_tip.canonical_stacks_tip_consensus_hash = best_tip_consensus_hash;
        parent_tip.canonical_stacks_tip_hash = best_tip_block_bhh;
        parent_tip.canonical_stacks_tip_height = best_tip_height;

        debug!(
            "Max arrival for child of {} (burn {}) is {}",
            &parent_tip.consensus_hash, &parent_tip.burn_header_hash, &max_arrival_index
        );
        keys.push(db_keys::stacks_block_max_arrival_index());
        values.push(db_keys::stacks_block_max_arrival_index_value(
            max_arrival_index,
        ));

        Ok((keys, values))
    }
}

impl ChainstateDB for SortitionDB {
    fn backup(_backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}
