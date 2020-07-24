/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

use rusqlite::{Connection, OpenFlags, NO_PARAMS, OptionalExtension};
use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::TransactionBehavior;

use rand;
use rand::RngCore;

use std::{io, fs, cmp};
use std::convert::From;
use std::ops::Deref;
use std::ops::DerefMut;

use util::db::{FromRow, FromColumn, u64_to_sql, query_rows, query_row, query_row_columns, query_count, IndexDBTx,
               IndexDBConn, db_mkdirs, query_row_panic};
use util::db::Error as db_error;
use util::db::tx_begin_immediate;
use util::get_epoch_time_secs;

use chainstate::ChainstateDB;

use chainstate::burn::Opcodes;
use chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash, OpsHash, BlockSnapshot, SortitionHash};

use core::CHAINSTATE_VERSION;

use chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    UserBurnSupportOp,
    BlockstackOperation,
    BlockstackOperationType
};

use burnchains::{Txid, BurnchainHeaderHash, PublicKey, Address};
use burnchains::BurnchainView;
use burnchains::Burnchain;

use burnchains::{
    BurnchainSigner,
    BurnchainRecipient,
    BurnchainTransaction,
    BurnchainBlockHeader,
    BurnchainStateTransition,
    Error as BurnchainError
};

use chainstate::stacks::StacksAddress;
use chainstate::stacks::StacksPublicKey;
use chainstate::stacks::*;
use chainstate::stacks::index::TrieHash;
use chainstate::stacks::index::MarfTrieId;
use chainstate::stacks::index::storage::TrieFileStorage;
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::MARFValue;
use chainstate::stacks::index::Error as MARFError;

use address::AddressHashMode;

use util::log;
use util::vrf::*;
use util::secp256k1::MessageSignature;
use util::hash::{to_hex, hex_bytes, Hash160, Sha512Trunc256Sum};
use sha2::{Sha512Trunc256, Digest};

use util::strings::StacksString;
use util::db::tx_busy_handler;

use net::neighbors::MAX_NEIGHBOR_BLOCK_DELAY;

use std::collections::HashMap;

use core::FIRST_STACKS_BLOCK_HASH;
use core::FIRST_BURNCHAIN_BLOCK_HASH;

use vm::types::Value;
use vm::representations::{ContractName, ClarityName};

const BLOCK_HEIGHT_MAX : u64 = ((1 as u64) << 63) - 1; 

pub const REWARD_WINDOW_START : u64 = 144 * 15;
pub const REWARD_WINDOW_END : u64 = 144 * 90 + REWARD_WINDOW_START;

pub type BlockHeaderCache = HashMap<BurnchainHeaderHash, (Option<BlockHeaderHash>, BurnchainHeaderHash)>;

// for using BurnchainHeaderHash values as block hashes in a MARF
impl From<BurnchainHeaderHash> for BlockHeaderHash {
    fn from(bhh: BurnchainHeaderHash) -> BlockHeaderHash {
        BlockHeaderHash(bhh.0)
    }
}

// for using BurnchainHeaderHash values as block hashes in a MARF
impl From<BlockHeaderHash> for BurnchainHeaderHash {
    fn from(bhh: BlockHeaderHash) -> BurnchainHeaderHash {
        BurnchainHeaderHash(bhh.0)
    }
}

impl FromRow<BlockSnapshot> for BlockSnapshot {
    fn from_row<'a>(row: &'a Row) -> Result<BlockSnapshot, db_error> {
        let block_height = u64::from_column(row, "block_height")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let burn_header_timestamp = u64::from_column(row, "burn_header_timestamp")?;
        let parent_burn_header_hash = BurnchainHeaderHash::from_column(row, "parent_burn_header_hash")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let ops_hash = OpsHash::from_column(row, "ops_hash")?;
        let total_burn_str : String = row.get("total_burn");
        let sortition : bool = row.get("sortition");
        let sortition_hash = SortitionHash::from_column(row, "sortition_hash")?;
        let winning_block_txid = Txid::from_column(row, "winning_block_txid")?;
        let winning_stacks_block_hash = BlockHeaderHash::from_column(row, "winning_stacks_block_hash")?;
        let index_root = TrieHash::from_column(row, "index_root")?;
        let num_sortitions = u64::from_column(row, "num_sortitions")?;

        // information we learn about the stacks block this snapshot committedto
        let stacks_block_accepted : bool = row.get("stacks_block_accepted");
        let stacks_block_height = u64::from_column(row, "stacks_block_height")?;
        let arrival_index = u64::from_column(row, "arrival_index")?;

        // information about what we have determined about the stacks chain tip.
        // This is memoized to a given canonical chain tip block.
        let canonical_stacks_tip_height = u64::from_column(row, "canonical_stacks_tip_height")?;
        let canonical_stacks_tip_hash = BlockHeaderHash::from_column(row, "canonical_stacks_tip_hash")?;
        let canonical_stacks_tip_burn_hash = BurnchainHeaderHash::from_column(row, "canonical_stacks_tip_burn_hash")?;


        // identifiers derived from PoX forking state
        let sortition_id = SortitionId::from_column(row, "sortition_id")?;
        let pox_id = PoxId::from_column(row, "pox_id")?;

        let total_burn = total_burn_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        let snapshot = BlockSnapshot {
            block_height: block_height,
            burn_header_timestamp: burn_header_timestamp,
            burn_header_hash: burn_header_hash,
            parent_burn_header_hash: parent_burn_header_hash,
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
            canonical_stacks_tip_burn_hash: canonical_stacks_tip_burn_hash,

            sortition_id,
            pox_id
        };
        Ok(snapshot)
    }
}

impl FromRow<LeaderKeyRegisterOp> for LeaderKeyRegisterOp {
    fn from_row<'a>(row: &'a Row) -> Result<LeaderKeyRegisterOp, db_error> {
        let txid = Txid::from_column(row, "txid")?;
        let vtxindex : u32 = row.get("vtxindex");
        let block_height = u64::from_column(row, "block_height")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let public_key = VRFPublicKey::from_column(row, "public_key")?;
        let memo_hex : String = row.get("memo");
        let address = StacksAddress::from_column(row, "address")?;
        
        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        let leader_key_row = LeaderKeyRegisterOp {
            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height,
            burn_header_hash: burn_header_hash,

            consensus_hash: consensus_hash,
            public_key: public_key,
            memo: memo, 
            address: address,
        };

        Ok(leader_key_row)
    }
}

impl FromRow<LeaderBlockCommitOp> for LeaderBlockCommitOp {
    fn from_row<'a>(row: &'a Row) -> Result<LeaderBlockCommitOp, db_error> {
        let txid = Txid::from_column(row, "txid")?;
        let vtxindex : u32 = row.get("vtxindex");
        let block_height = u64::from_column(row, "block_height")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let block_header_hash = BlockHeaderHash::from_column(row, "block_header_hash")?;
        let new_seed = VRFSeed::from_column(row, "new_seed")?;
        let parent_block_ptr : u32 = row.get("parent_block_ptr");
        let parent_vtxindex: u16 = row.get("parent_vtxindex");
        let key_block_ptr : u32 = row.get("key_block_ptr");
        let key_vtxindex : u16 = row.get("key_vtxindex");
        let memo_hex : String = row.get("memo");
        let burn_fee_str : String = row.get("burn_fee");
        let input_json : String = row.get("input");
        
        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        let input = serde_json::from_str::<BurnchainSigner>(&input_json)
            .map_err(|e| db_error::SerializationError(e))?;

        let burn_fee = burn_fee_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: block_header_hash,
            new_seed: new_seed,
            parent_block_ptr: parent_block_ptr,
            parent_vtxindex: parent_vtxindex,
            key_block_ptr: key_block_ptr,
            key_vtxindex: key_vtxindex,
            memo: memo,

            burn_fee: burn_fee,
            input: input,

            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height,
            burn_header_hash: burn_header_hash,
        };
        Ok(block_commit)
    }
}

impl FromRow<UserBurnSupportOp> for UserBurnSupportOp {
    fn from_row<'a>(row: &'a Row) -> Result<UserBurnSupportOp, db_error> {
        let txid = Txid::from_column(row, "txid")?;
        let vtxindex : u32 = row.get("vtxindex");
        let block_height = u64::from_column(row, "block_height")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;

        let address = StacksAddress::from_column(row, "address")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let public_key = VRFPublicKey::from_column(row, "public_key")?;
        let key_block_ptr: u32 = row.get("key_block_ptr");
        let key_vtxindex : u16 = row.get("key_vtxindex");
        let block_header_hash_160 = Hash160::from_column(row, "block_header_hash_160")?;

        let burn_fee_str : String = row.get("burn_fee");

        let burn_fee = burn_fee_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        let user_burn = UserBurnSupportOp {
            address: address,
            consensus_hash: consensus_hash,
            public_key: public_key,
            key_block_ptr: key_block_ptr,
            key_vtxindex: key_vtxindex,
            block_header_hash_160: block_header_hash_160,
            burn_fee: burn_fee,

            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height,
            burn_header_hash: burn_header_hash
        };
        Ok(user_burn)
    }
}

struct AcceptedStacksBlockHeader {
    pub tip_burn_header_hash: BurnchainHeaderHash,      // burn chain tip
    pub burn_header_hash: BurnchainHeaderHash,          // stacks block burn header hash
    pub block_hash: BlockHeaderHash,                    // stacks block hash
    pub height: u64                                     // stacks block height
}

impl FromRow<AcceptedStacksBlockHeader> for AcceptedStacksBlockHeader {
    fn from_row<'a>(row: &'a Row) -> Result<AcceptedStacksBlockHeader, db_error> {
        let tip_burn_header_hash = BurnchainHeaderHash::from_column(row, "tip_burn_block_hash")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_block_hash")?;
        let block_hash = BlockHeaderHash::from_column(row, "stacks_block_hash")?;
        let height = u64::from_column(row, "block_height")?;

        Ok(AcceptedStacksBlockHeader {
            tip_burn_header_hash,
            burn_header_hash,
            block_hash,
            height
        })
    }
}

const BURNDB_SETUP : &'static [&'static str]= &[
    r#"
    PRAGMA foreign_keys = ON;
    "#,
    r#"
    -- sortition snapshots -- snapshot of all transactions processed in a burn block
    -- organizes the set of forks in the burn chain as well.
    CREATE TABLE snapshots(
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT UNIQUE NOT NULL,
        sortition_id TEXT UNIQUE NOT NULL,
        pox_id TEXT NOT NULL,
        burn_header_timestamp INT NOT NULL,
        parent_burn_header_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
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
        canonical_stacks_tip_burn_hash TEXT NOT NULL,   -- burn hash of highest known Stacks fork's tip block in this burn chain fork

        PRIMARY KEY(sortition_id)
    );"#,
    r#"
    CREATE UNIQUE INDEX snapshots_block_hashes ON snapshots(block_height,index_root,winning_stacks_block_hash);
    CREATE UNIQUE INDEX snapshots_block_stacks_hashes ON snapshots(num_sortitions,index_root,winning_stacks_block_hash);
    CREATE INDEX block_arrivals ON snapshots(arrival_index,burn_header_hash);
    CREATE INDEX arrival_indexes ON snapshots(arrival_index);
    "#,
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
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,
        sortition_id TEXT NOT NULL,

        block_header_hash TEXT NOT NULL,
        new_seed TEXT NOT NULL,
        parent_block_ptr INTEGER NOT NULL,
        parent_vtxindex INTEGER NOT NULL,
        key_block_ptr INTEGER NOT NULL,
        key_vtxindex INTEGER NOT NULL,
        memo TEXT,
        
        burn_fee TEXT NOT NULL,     -- use text to encode really big numbers
        input TEXT NOT NULL,        -- must match `address` in leader_keys

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
    CREATE TABLE canonical_accepted_stacks_blocks(
        tip_burn_block_hash TEXT NOT NULL,
        burn_block_hash TEXT NOT NULL,
        stacks_block_hash TEXT NOT NULL,
        block_height INTEGER NOT NULL,
        PRIMARY KEY(burn_block_hash, stacks_block_hash)
    );
    CREATE INDEX canonical_stacks_blocks ON canonical_accepted_stacks_blocks(tip_burn_block_hash,stacks_block_hash);
    "#,
    r#"
    CREATE TABLE db_config(
        version TEXT NOT NULL
    );
    "#
];

pub struct SortitionDB {
    pub conn: Connection,
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
    pub chain_tip: SortitionId
}

pub type SortitionDBConn<'a> = IndexDBConn<'a, SortitionDBTxContext, SortitionId>;
pub type SortitionDBTx<'a> = IndexDBTx<'a, SortitionDBTxContext, SortitionId>;

///
/// These structs are used to keep an open "handle" to the
///   sortition db -- this is just the db/marf connection
///   + a chain tip. This mostly just makes the job of callers 
///   much simpler, because they don't have to worry about passing
///   around the open chain tip everywhere.
///
pub type SortitionHandleConn<'a> = IndexDBConn<'a, SortitionHandleContext, SortitionId>;
pub type SortitionHandleTx<'a> = IndexDBTx<'a, SortitionHandleContext, SortitionId>;

///
/// This trait is used for functions that
///  can accept either a SortitionHandleConn or a SortitionDBConn
///
pub trait SortitionContext {
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

fn get_ancestor_sort_id<C: SortitionContext>(ic: &IndexDBConn<'_, C, SortitionId>, block_height: u64, tip_block_hash: &SortitionId) -> Result<Option<SortitionId>, db_error> {
    let first_block_height = ic.context.first_block_height();
    if block_height < first_block_height {
        return Ok(None);
    }
 
    ic.get_ancestor_block_hash(block_height - first_block_height, &tip_block_hash)
}

/// Identifier used to identify "sortitions" in the
///  SortitionDB. A sortition is the collection of
///  valid burnchain operations (and any dependent
///  variables, e.g., the sortition winner, the
///  consensus hash, the next VRF key)
pub struct SortitionId(pub [u8; 32]);
impl_array_newtype!(SortitionId, u8, 32);
impl_array_hexstring_fmt!(SortitionId);
impl_byte_array_newtype!(SortitionId, u8, 32);
impl_byte_array_from_column!(SortitionId);
impl_byte_array_message_codec!(SortitionId, 32);

/// Identifier used to identify Proof-of-Transfer forks
///  (or Rewards Cycle forks). These identifiers are opaque
///  outside of the PoX DB, however, they are sufficient
///  to uniquely identify a "sortition" when paired with
///  a burn header hash
pub struct PoxId(pub [u8; 32]);
impl_array_newtype!(PoxId, u8, 32);
impl_array_hexstring_fmt!(PoxId);
impl_byte_array_newtype!(PoxId, u8, 32);
impl_byte_array_from_column!(PoxId);
impl_byte_array_message_codec!(PoxId, 32);

struct db_keys;
impl db_keys {
    pub fn sortition_id_for_bhh(bhh: &BurnchainHeaderHash) -> String {
        format!("sortition_db::sortition_id_for_bhh::{}", bhh)
    }
    pub fn vrf_key_status(key: &VRFPublicKey) -> String {
        format!("sortition_db::vrf::{}", key.to_hex())
    }
    pub fn stacks_block_present(block_hash: &BlockHeaderHash) -> String {
        format!("sortition_db::sortition_block_hash::{}", block_hash)
    }
    pub fn last_sortition() -> String {
        "sortition_db::last_sortition".into()
    }

    /// MARF index key for a processed stacks block.  Maps to its height.
    pub fn stacks_block_index(stacks_block_hash: &BlockHeaderHash) -> String {
        format!("sortition_db::stacks::block::{}", stacks_block_hash)
    }

    /// MARF index key for the highest arrival index processed in a fork
    pub fn stacks_block_max_arrival_index() -> String {
        "sortdb::stacks::block::max_arrival_index".to_string()
    }
}

impl <'a> SortitionHandleTx <'a> {
    /// begin a MARF transaction with this connection
    ///  this is used by _writing_ contexts
    pub fn begin(conn: &'a mut SortitionDB, parent_chain_tip: &SortitionId) -> Result<SortitionHandleTx<'a>, db_error> {
        if !conn.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = tx_begin_immediate(&mut conn.conn)?;
        let handle = SortitionHandleTx::new(
            tx, &mut conn.marf,
            SortitionHandleContext { chain_tip: parent_chain_tip.clone(),
                                     first_block_height: conn.first_block_height });

        Ok(handle)
    }

    pub fn conn_view<'b>(&'b self, view_sortition: &SortitionId) -> SortitionHandleConn<'b> {
        let mut conn_view = self.as_conn();
        conn_view.context.chain_tip = view_sortition.clone();
        conn_view
    }
}

impl <'a> SortitionDBTx <'a> { 
    // PoX todo: this acceptance tracking will need to change once the StacksChainView is integrated
    pub fn set_stacks_block_accepted_stubbed(&mut self, burn_header_hash: &BurnchainHeaderHash, parent_stacks_block_hash: &BlockHeaderHash,
                                             stacks_block_hash: &BlockHeaderHash, stacks_block_height: u64) -> Result<(), db_error> {
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(self)?;
        self.set_stacks_block_accepted_at_tip(&chain_tip, burn_header_hash, parent_stacks_block_hash, stacks_block_hash, stacks_block_height)
    }

    /// Mark an existing snapshot's stacks block as accepted at a particular burn chain tip, and calculate and store its arrival index.
    /// If this Stacks block extends the canonical stacks chain tip, then also update the memoized canonical
    /// stacks chain tip metadata on the burn chain tip.
    fn set_stacks_block_accepted_at_tip(&mut self, burn_tip: &BlockSnapshot, burn_header_hash: &BurnchainHeaderHash,
                                        parent_stacks_block_hash: &BlockHeaderHash, stacks_block_hash: &BlockHeaderHash, stacks_block_height: u64) -> Result<(), db_error> {
        let arrival_index = SortitionDB::get_max_arrival_index(self)?;
        let args : &[&dyn ToSql] = &[&u64_to_sql(stacks_block_height)?, &u64_to_sql(arrival_index + 1)?, burn_header_hash, stacks_block_hash];

        self.execute("UPDATE snapshots SET stacks_block_accepted = 1, stacks_block_height = ?1, arrival_index = ?2 WHERE burn_header_hash = ?3 AND winning_stacks_block_hash = ?4", args)?;

        let parent_key = db_keys::stacks_block_index(parent_stacks_block_hash);

        // update memoized canonical stacks chain tip on the canonical burn chain tip if this block
        // extends it.
        if burn_tip.canonical_stacks_tip_hash == *parent_stacks_block_hash {
            // This block builds off of the memoized canonical stacks chain tip information we
            // already have.
            // Memoize this tip to the canonical burn chain snapshot.
            if stacks_block_height > 0 {
                assert_eq!(burn_tip.canonical_stacks_tip_height + 1, stacks_block_height);
            }
            else {
                assert_eq!(stacks_block_hash, &FIRST_STACKS_BLOCK_HASH);
            }
            debug!("Accepted Stacks block {}/{} builds on the memoized canonical chain tip ({})", burn_header_hash, stacks_block_hash, &burn_tip.burn_header_hash);
            let args : &[&dyn ToSql] = &[burn_header_hash, stacks_block_hash, &u64_to_sql(stacks_block_height)?, &burn_tip.sortition_id];
            self.execute("UPDATE snapshots SET canonical_stacks_tip_burn_hash = ?1, canonical_stacks_tip_hash = ?2, canonical_stacks_tip_height = ?3
                        WHERE sortition_id = ?4", args)?;

            SortitionDB::insert_accepted_stacks_block_pointer(self, &burn_tip.burn_header_hash, burn_header_hash, stacks_block_hash, stacks_block_height)?;
        }
        else {
            // see if this block builds off of a Stacks block mined on this burnchain fork
            let height_opt = match SortitionDB::get_accepted_stacks_block_pointer(self, &burn_tip.burn_header_hash, parent_stacks_block_hash)? {
                // this block builds on a block accepted _after_ this burn chain tip was processed?
                Some(accepted_header) => Some(accepted_header.height),
                None =>
                    match self.get_indexed(&burn_tip.sortition_id, &parent_key)? {
                        // this block builds on a block accepted _before_ this burn chain tip was processed?
                        Some(height_str) => Some(height_str.parse::<u64>().expect(&format!("BUG: MARF stacks block key '{}' does not map to a u64", parent_key))),
                        None => None
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
                        debug!("Accepted Stacks block {}/{} builds on a previous canonical Stacks tip on this burnchain fork ({})", burn_header_hash, stacks_block_hash, &burn_tip.burn_header_hash);
                        let args : &[&dyn ToSql] = &[burn_header_hash, stacks_block_hash, &u64_to_sql(stacks_block_height)?, &burn_tip.burn_header_hash];
                        self.execute("UPDATE snapshots SET canonical_stacks_tip_burn_hash = ?1, canonical_stacks_tip_hash = ?2, canonical_stacks_tip_height = ?3
                                    WHERE burn_header_hash = ?4", args)
                            .map_err(db_error::SqliteError)?;
                    }
                    else {
                        // This block was mined on this fork, but it's acceptance doesn't overtake
                        // the current stacks chain tip.  Remember it so that we can process its children,
                        // which might do so later.
                        debug!("Accepted Stacks block {}/{} builds on a non-canonical Stacks tip in this burnchain fork ({})", burn_header_hash, stacks_block_hash, &burn_tip.burn_header_hash);
                    }
                    SortitionDB::insert_accepted_stacks_block_pointer(self, &burn_tip.burn_header_hash, burn_header_hash, stacks_block_hash, stacks_block_height)?;
                },
                None => {
                    debug!("Accepted Stacks block {}/{} does NOT build on a Stacks tip in this burnchain fork ({}) -- no parent {} in this fork", 
                           burn_header_hash, stacks_block_hash, &burn_tip.burn_header_hash, parent_stacks_block_hash);
                }
            }
        }
        Ok(())
    }

}

impl <'a> SortitionHandleConn <'a> {
    /// open a reader handle
    pub fn open_reader_stubbed(connection: &'a SortitionDBConn<'a>, chain_tip: &BurnchainHeaderHash) -> Result<SortitionHandleConn<'a>, db_error> {
        let chain_tip = SortitionId(chain_tip.0.clone());
        SortitionHandleConn::open_reader(connection, &chain_tip)
    }

    /// open a reader handle
    pub fn open_reader(connection: &'a SortitionDBConn<'a>, chain_tip: &SortitionId) -> Result<SortitionHandleConn<'a>, db_error> {
        Ok(SortitionHandleConn {
            conn: &connection.conn,
            context: SortitionHandleContext {
                chain_tip: chain_tip.clone(),
                first_block_height: connection.context.first_block_height
            },
            index: &connection.index,
        })
    }

    fn get_tip_indexed(&self, key: &str) -> Result<Option<String>, db_error> {
        self.get_indexed(&self.context.chain_tip, key)
    }

    /// Uses the handle's current fork identifier to get a block snapshot by
    ///   burnchain block header
    /// If the burn header hash is _not_ in the current fork, then this will return Ok(None)
    pub fn get_block_snapshot(&self, burn_header_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        let sortition_identifier_key = db_keys::sortition_id_for_bhh(burn_header_hash);
        let sortition_id = match self.get_tip_indexed(&sortition_identifier_key)? {
            None => return Ok(None),
            Some(x) => SortitionId::from_hex(&x).expect("FATAL: bad Sortition ID stored in DB")
        };

        SortitionDB::get_block_snapshot(&self.conn, &sortition_id)
    }

    pub fn get_tip_snapshot(&self) -> Result<Option<BlockSnapshot>, db_error> {
        SortitionDB::get_block_snapshot(&self.conn, &self.context.chain_tip)
    }

    pub fn has_VRF_public_key(&self, key: &VRFPublicKey) -> Result<bool, db_error> {
        let key_status = self.get_tip_indexed(&db_keys::vrf_key_status(key))?
            .is_some();
        Ok(key_status)
    }

    pub fn get_first_block_snapshot(&self) -> Result<BlockSnapshot, db_error> {
        SortitionDB::get_first_block_snapshot(&self.conn)
    }

    /// Do we expect a stacks block in this particular fork?
    /// i.e. is this block hash part of the fork history identified by tip_block_hash?
    pub fn expects_stacks_block_in_fork(&self, block_hash: &BlockHeaderHash) -> Result<bool, db_error> {
        self.get_tip_indexed(&db_keys::stacks_block_present(block_hash))
            .map(|result| result.is_some())
    }


    /// Get consensus hash from a particular chain tip's history
    /// Returns None if the block height or block hash does not correspond to a
    /// known snapshot.
    pub fn get_consensus_at(&self, block_height: u64) -> Result<Option<ConsensusHash>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        match SortitionDB::get_ancestor_snapshot(self, block_height, &self.context.chain_tip)? {
            Some(sn) => Ok(Some(sn.consensus_hash)),
            None => Ok(None)
        }
    }

    pub fn get_block_snapshot_by_height(&self, block_height: u64) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        SortitionDB::get_ancestor_snapshot(self, block_height, &self.context.chain_tip)
    }

    /// Get all user burns that burned for the winning block in the chain_tip sortition
    /// Returns list of user burns in order by vtxindex.
    pub fn get_winning_user_burns_by_block(&self) -> Result<Vec<UserBurnSupportOp>, db_error> {
        let snapshot = match self.get_tip_snapshot()? {
            Some(sn) => sn,
            None => {
                // no such snapshot, so no such users
                return Ok(vec![]);
            }
        };

        if !snapshot.sortition {
            // no winner
            return Ok(vec![]);
        }

        let winning_block_hash160 = Hash160::from_sha256(snapshot.winning_stacks_block_hash.as_bytes());

        let qry = "SELECT * FROM user_burn_support WHERE sortition_id = ?1 AND block_header_hash_160 = ?2 ORDER BY vtxindex ASC";
        let args: [&dyn ToSql; 2] = [&snapshot.sortition_id, &winning_block_hash160];

        query_rows(self, qry, &args)
    }

    /// Get the block snapshot of the parent stacks block of the given stacks block
    pub fn get_block_snapshot_of_parent_stacks_block(&self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<(LeaderBlockCommitOp, BlockSnapshot)>, db_error> {
        let block_commit = match SortitionDB::get_block_commit_for_stacks_block(&self.conn, burn_header_hash, &block_hash)? {
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
                self.get_first_block_snapshot()?
            }
            else {
                let parent_commit = match self.get_block_commit_parent(block_commit.parent_block_ptr.into(), block_commit.parent_vtxindex.into())? {
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
                self.get_block_snapshot(&parent_commit.burn_header_hash)?
                    .expect("FATAL: burn DB does not have snapshot for parent block commit")
            };

        Ok(Some((block_commit, stacks_chain_tip)))
    }

    /// Get the latest block snapshot on this fork where a sortition occured.
    /// Search snapshots up to (but excluding) the given block height.
    /// Will always return a snapshot -- even if it's the initial sentinel snapshot.
    pub fn get_last_snapshot_with_sortition(&self, burn_block_height: u64) -> Result<BlockSnapshot, db_error> {
        assert!(burn_block_height < BLOCK_HEIGHT_MAX);
        test_debug!("Get snapshot at from sortition tip {}, expect height {}", &self.context.chain_tip, burn_block_height);
        let get_from = match get_ancestor_sort_id(self, burn_block_height, &self.context.chain_tip)? {
            Some(sortition_id) => sortition_id,
            None => {
                error!("No blockheight {} ancestor at sortition identifier {}",
                       burn_block_height, &self.context.chain_tip);
                return Err(db_error::NotFoundError);
            }
        };

        let ancestor_hash = match self.get_indexed(&get_from, &db_keys::last_sortition())? {
            Some(hex_str) => {
                BurnchainHeaderHash::from_hex(&hex_str)
                    .expect(&format!("FATAL: corrupt database: failed to parse {} into a hex string", &hex_str))
            },
            None => {
                // no prior sortitions, so get the first
                return self.get_first_block_snapshot();
            }
        };
        
        self.get_block_snapshot(&ancestor_hash)
            .map(|snapshot_opt| {
                snapshot_opt
                    .expect(&format!("FATAL: corrupt index: no snapshot {}", ancestor_hash))
            })
    }

    fn check_fresh_consensus_hash<F>(&self, consensus_hash_lifetime: u64, check: F) -> Result<bool, db_error>
    where F: Fn(&ConsensusHash) -> bool {
        let first_snapshot = self.get_first_block_snapshot()?;
        let mut last_snapshot = self.get_tip_snapshot()?
            .ok_or_else(|| db_error::NotFoundError )?;
        let current_block_height = last_snapshot.block_height;

        let mut oldest_height = 
            if current_block_height < consensus_hash_lifetime {
                0
            }
            else {
                current_block_height - consensus_hash_lifetime
            };

        if oldest_height < first_snapshot.block_height {
            oldest_height = first_snapshot.block_height;
        }

        if check(&last_snapshot.consensus_hash) {
            return Ok(true)
        }

        for _i in oldest_height..current_block_height {
            let ancestor_snapshot = self.get_block_snapshot(&last_snapshot.parent_burn_header_hash)?
                .expect(&format!("Discontiguous index: missing block {}", last_snapshot.parent_burn_header_hash));
            if check(&ancestor_snapshot.consensus_hash) {
                return Ok(true)
            }
            last_snapshot = ancestor_snapshot;
        }

        return Ok(false)
    }

    /// Find out whether or not a given consensus hash is "recent" enough to be used in this fork.
    pub fn is_fresh_consensus_hash(&self, consensus_hash_lifetime: u64, consensus_hash: &ConsensusHash) -> Result<bool, db_error> {
        self.check_fresh_consensus_hash(consensus_hash_lifetime,
                                        |fresh_hash| { fresh_hash == consensus_hash })
    }

    /// Find out whether or not a given consensus hash is "recent" enough to be used in this fork.
    /// This function only checks the first 19 bytes
    pub fn is_fresh_consensus_hash_check_19b(&self, consensus_hash_lifetime: u64, consensus_hash: &ConsensusHash) -> Result<bool, db_error> {
        self.check_fresh_consensus_hash(consensus_hash_lifetime,
                                        |fresh_hash| { fresh_hash.as_bytes()[0..19] == consensus_hash.as_bytes()[0..19] })
    }

    pub fn get_leader_key_at(&self, key_block_height: u64, key_vtxindex: u32) -> Result<Option<LeaderKeyRegisterOp>, db_error> {
        SortitionDB::get_leader_key_at(self, key_block_height, key_vtxindex, &self.context.chain_tip)
    }

    pub fn get_block_commit_parent(&self, block_height: u64, vtxindex: u32) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        SortitionDB::get_block_commit_parent(self, block_height, vtxindex, &self.context.chain_tip)
    }

    /// Get a block commit by its content-addressed location.  Note that burn_header_hash is enough
    /// to identify the fork we're on, since block hashes are globally-unique (w.h.p.) by
    /// construction.
    pub fn get_block_commit(&self, txid: &Txid, burn_header_hash: &BurnchainHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        // PoX TODO: note -- block_commits table will index on burn_header_hash: if a block_commit is reprocessed due to a PoX fork,
        //                   it should be allowed to either overwrite the previous entry OR skip insertion (i.e., UNIQUE constraints
        //                   should not be allowed to cause a panic)
        let qry = "SELECT * FROM block_commits WHERE txid = ?1 AND burn_header_hash = ?2";
        let args: [&dyn ToSql; 2] = [&txid, &burn_header_hash];
        query_row_panic(&self.conn, qry, &args,
                        || format!("FATAL: multiple block commits for {},{}", &txid, &burn_header_hash))
    }

    /// Determine whether or not a leader key has been consumed by a subsequent block commitment in
    /// this fork's history.
    /// Will return false if the leader key does not exist.
    pub fn is_leader_key_consumed(&self, leader_key: &LeaderKeyRegisterOp) -> Result<bool, db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);

        let key_status = match self.get_tip_indexed(&db_keys::vrf_key_status(&leader_key.public_key))? {
            Some(status_str) => {
                if status_str == "1" {
                    // key is still available
                    false
                }
                else if status_str == "0" {
                    // key is consumed
                    true
                }
                else {
                    panic!("Invalid key status string {}", status_str);
                }
            },
            None => {
                // never before seen
                false
            }
        };

        Ok(key_status)
    }

}

impl PoxId {
    const BASE_FORK: PoxId = PoxId([0; 32]);

    pub fn stubbed() -> PoxId {
        PoxId::BASE_FORK.clone()
    }

    pub fn base_fork() -> &'static PoxId {
        &PoxId::BASE_FORK
    }
}

impl SortitionId {
    /// PoX Todo: any caller of this would need to instead
    ///  construct a sortition ID with a burn header hash + pox fork identifier
    pub fn stubbed(from: &BurnchainHeaderHash) -> SortitionId {
        SortitionId::new(from, PoxId::base_fork())
    }

    pub fn new(bhh: &BurnchainHeaderHash, pox: &PoxId) -> SortitionId {
        if pox == PoxId::base_fork() {
            SortitionId(bhh.0.clone())
        } else {
            let mut hasher = Sha512Trunc256::new();
            hasher.input(bhh);
            hasher.input(pox);
            let h = Sha512Trunc256Sum::from_hasher(hasher);
            SortitionId(h.0)
        }
    }
}

// Connection methods
impl SortitionDB {
    /// Begin a transaction.
    pub fn tx_begin<'a>(&'a mut self) -> Result<SortitionDBTx<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = tx_begin_immediate(&mut self.conn)?;
        let index_tx = SortitionDBTx::new(tx, &mut self.marf,
                                          SortitionDBTxContext { first_block_height: self.first_block_height });
        Ok(index_tx)
    }

    /// Make an indexed connectino
    pub fn index_conn<'a>(&'a self) -> SortitionDBConn<'a> {
        SortitionDBConn::new(&self.conn, &self.marf,
                             SortitionDBTxContext { first_block_height: self.first_block_height })
    }

    pub fn index_handle<'a>(&'a self, chain_tip: &SortitionId) -> SortitionHandleConn<'a> {
        SortitionHandleConn::new(&self.conn, &self.marf,
                                 SortitionHandleContext {
                                     first_block_height: self.first_block_height,
                                     chain_tip: chain_tip.clone() })
    }

    pub fn conn<'a>(&'a self) -> &'a Connection {
        &self.conn
    }

    fn open_index(index_path: &str) -> Result<MARF<SortitionId>, db_error> {
        test_debug!("Open index at {}", index_path);
        MARF::from_path(index_path).map_err(|_e| db_error::Corruption)
    }

    /// Open the database on disk.  It must already exist and be instantiated.
    /// It's best not to call this if you are able to call connect().  If you must call this, do so
    /// after you call connect() somewhere else, since connect() performs additional validations.
    pub fn open(path: &str, readwrite: bool) -> Result<SortitionDB, db_error> {
        let open_flags =
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            }
            else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            };

        let (db_path, index_path) = db_mkdirs(path)?;
        debug!("Open sortdb '{}' as '{}', with index as '{}'",
               db_path, if readwrite { "readwrite" } else { "readonly" }, index_path);
        
        let conn = Connection::open_with_flags(&db_path, open_flags)?;
        conn.busy_handler(Some(tx_busy_handler))?;

        let marf = SortitionDB::open_index(&index_path)?;
        let first_snapshot = SortitionDB::get_first_block_snapshot(&conn)?;

        let db = SortitionDB {
            conn, marf, readwrite,
            first_block_height: first_snapshot.block_height,
            first_burn_header_hash: first_snapshot.burn_header_hash.clone(),
        };
        Ok(db)
    }

    /// Open the burn database at the given path.  Open read-only or read/write.
    /// If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(path: &str, first_block_height: u64, first_burn_hash: &BurnchainHeaderHash, first_burn_header_timestamp: u64, readwrite: bool) -> Result<SortitionDB, db_error> {
        let mut create_flag = false;
        let open_flags = match fs::metadata(path) {
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    // need to create 
                    if readwrite {
                        create_flag = true;
                        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                    }
                    else {
                        return Err(db_error::NoDBError);
                    }
                }
                else {
                    return Err(db_error::IOError(e));
                }
            },
            Ok(_md) => {
                // can just open 
                if readwrite {
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                }
                else {
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                }
            }
        };

        let (db_path, index_path) = db_mkdirs(path)?;
        debug!("Connect/Open sortdb '{}' as '{}', with index as '{}'",
               db_path, if readwrite { "readwrite" } else { "readonly" }, index_path);

        let conn = Connection::open_with_flags(&db_path, open_flags)?;
        conn.busy_handler(Some(tx_busy_handler))?;

        let marf = SortitionDB::open_index(&index_path)?;

        let mut db = SortitionDB {
            conn, marf, readwrite, first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
        };

        if create_flag {
            // instantiate!
            db.instantiate(first_block_height, first_burn_hash, first_burn_header_timestamp)?;
        }
        else {
            // validate -- must contain the given first block and first block hash 
            let snapshot = SortitionDB::get_first_block_snapshot(&db.conn)?;
            if !snapshot.is_initial() || snapshot.block_height != first_block_height || snapshot.burn_header_hash != *first_burn_hash {
                error!("Invalid genesis snapshot at {}", first_block_height);
                return Err(db_error::Corruption);
            }
        }

        Ok(db)
    }

    /// Open a burn database at random tmp dir (used for testing)
    #[cfg(test)]
    pub fn connect_test(first_block_height: u64, first_burn_hash: &BurnchainHeaderHash) -> Result<SortitionDB, db_error> { 
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let db_path_dir = format!("/tmp/test-blockstack-sortdb-{}", to_hex(&buf));

        SortitionDB::connect(&db_path_dir, first_block_height, first_burn_hash,
                             get_epoch_time_secs(), true)
    }

    fn instantiate(&mut self, first_block_height: u64, first_burn_header_hash: &BurnchainHeaderHash, first_burn_header_timestamp: u64) -> Result<(), db_error> {
        let mut db_tx = SortitionHandleTx::begin(self, &SortitionId::sentinel())?;

        // create first (sentinel) snapshot
        let mut first_snapshot = BlockSnapshot::initial(first_block_height, first_burn_header_hash, first_burn_header_timestamp);
        
        assert!(first_snapshot.parent_burn_header_hash != first_snapshot.burn_header_hash);
        assert_eq!(first_snapshot.parent_burn_header_hash, BurnchainHeaderHash::sentinel());

        for row_text in BURNDB_SETUP {
            db_tx.execute(row_text, NO_PARAMS)?;
        }

        db_tx.execute("INSERT INTO db_config (version) VALUES (?1)", &[&CHAINSTATE_VERSION])?;

        db_tx.instantiate_index()?;

        let mut first_sn = first_snapshot.clone();
        first_sn.sortition_id = SortitionId::sentinel();
        let index_root = db_tx.index_add_fork_info(&mut first_sn, &first_snapshot, &vec![], &vec![])?;
        first_snapshot.index_root = index_root;

        db_tx.insert_block_snapshot(&first_snapshot)?;

        db_tx.commit()?;
        Ok(())
    }

    /// Load up all snapshots, in ascending order by block height.  Great for testing!
    pub fn get_all_snapshots(&self) -> Result<Vec<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots ORDER BY block_height ASC";
        query_rows(self.conn(), qry, NO_PARAMS)
    }
}

impl <'a> SortitionDBConn <'a> {
    pub fn as_handle <'b> (&'b self, chain_tip: &SortitionId) -> SortitionHandleConn <'b> {
        SortitionHandleConn {
            conn: self.conn,
            index: self.index,
            context: SortitionHandleContext {
                first_block_height: self.context.first_block_height.clone(),
                chain_tip: chain_tip.clone()
            }
        }
    }

    /// Given a burnchain consensus hash,
    ///    go get the last N Stacks block headers that won sortition
    /// leading up to the given header hash.  The ith slot in the vector will be Some(...) if there
    /// was a sortition, and None if not.
    /// Returns up to num_headers prior block header hashes.
    /// The list of hashes will be in ascending order -- the lowest-height block is item 0.
    /// The last hash will be the hash for the given consensus hash.
    pub fn get_stacks_header_hashes(&self, num_headers: u64, tip_consensus_hash: &ConsensusHash, cache: Option<&BlockHeaderCache>) -> Result<Vec<(BurnchainHeaderHash, Option<BlockHeaderHash>)>, db_error> {
        let mut ret = vec![];
        let tip_snapshot = SortitionDB::get_block_snapshot_consensus(self, tip_consensus_hash)?
            .ok_or_else(|| db_error::NotFoundError)?;

        assert!(tip_snapshot.block_height >= self.context.first_block_height, "DB corruption: have snapshot with a smaller block height than the first block height");

        let db_handle = self.as_handle(&tip_snapshot.sortition_id);

        let headers_count = 
            if tip_snapshot.block_height - self.context.first_block_height  < num_headers {
                tip_snapshot.block_height - self.context.first_block_height
            }
            else {
                num_headers
            };

        // PoX TODO: this BlockHeaderCache should use sortition_id's instead of burn_header_hashes.
        let mut ancestor_header_hash = tip_snapshot.burn_header_hash;
        for _i in 0..headers_count {
            if let Some(ref cached) = cache {
                if let Some((header_hash_opt, prev_block_hash)) = cached.get(&ancestor_header_hash) {
                    // cache hit
                    ret.push((ancestor_header_hash, header_hash_opt.clone()));

                    ancestor_header_hash = prev_block_hash.clone();
                    continue;
                }
            }

            // cache miss
            let ancestor_snapshot = db_handle.get_block_snapshot(&ancestor_header_hash)?
                .expect(&format!("Discontiguous index: missing block {}", ancestor_header_hash));
            let header_hash_opt = 
                if ancestor_snapshot.sortition {
                    Some(ancestor_snapshot.winning_stacks_block_hash.clone())
                }
                else {
                    None
                };

            debug!("CACHE MISS {}", &ancestor_header_hash);

            ret.push((ancestor_header_hash.clone(), header_hash_opt.clone()));

            ancestor_header_hash = ancestor_snapshot.parent_burn_header_hash.clone();
        }

        ret.reverse();
        Ok(ret)
    }

    /// Get a burn blockchain snapshot, given a burnchain configuration struct.
    /// Used mainly by the network code to determine what the chain tip currently looks like.
    pub fn get_burnchain_view(&self, burnchain: &Burnchain, chain_tip: &BlockSnapshot) -> Result<BurnchainView, db_error> {
        if chain_tip.block_height < burnchain.first_block_height {
            // should never happen, but don't panic since this is network-callable code
            error!("Invalid block height from DB: {}: expected at least {}", chain_tip.block_height, burnchain.first_block_height);
            return Err(db_error::Corruption);
        }

        if chain_tip.block_height < burnchain.stable_confirmations as u64 {
            // should never happen, but don't panic since this is network-callable code
            error!("Invalid block height from DB: {}: expected at least {}", chain_tip.block_height, burnchain.stable_confirmations);
            return Err(db_error::Corruption);
        }

        let stable_block_height = cmp::max(burnchain.first_block_height,
                                           chain_tip.block_height - (burnchain.stable_confirmations as u64));

        let db_handle = SortitionHandleConn::open_reader(self, &chain_tip.sortition_id)?;

        let stable_snapshot = db_handle.get_block_snapshot_by_height(stable_block_height)?
            .ok_or_else(|| {
                // shouldn't be possible, but don't panic since this is network-callable code
                error!("Failed to load snapshot for block {} from fork {}", stable_block_height, &chain_tip.burn_header_hash);
                db_error::Corruption
            })?;

        // get all consensus hashes between the chain tip, and the stable height back
        // MAX_NEIGHBOR_BLOCK_DELAY
        let oldest_height = 
            if stable_snapshot.block_height < MAX_NEIGHBOR_BLOCK_DELAY {
                0
            }
            else {
                stable_snapshot.block_height - MAX_NEIGHBOR_BLOCK_DELAY
            };

        let mut last_consensus_hashes = HashMap::new();
        for height in oldest_height..chain_tip.block_height {
            let ch = db_handle.get_consensus_at(height)?
                .unwrap_or(ConsensusHash::empty());
            last_consensus_hashes.insert(height, ch);
        }

        test_debug!("Chain view: {},{}-{},{}", chain_tip.block_height, chain_tip.consensus_hash, stable_block_height, stable_snapshot.consensus_hash);
        Ok(BurnchainView {
            burn_block_height: chain_tip.block_height, 
            burn_consensus_hash: chain_tip.consensus_hash,
            burn_stable_block_height: stable_block_height,
            burn_stable_consensus_hash: stable_snapshot.consensus_hash,
            last_consensus_hashes: last_consensus_hashes
        })
    }
}

pub struct PoxDB;

impl PoxDB {
    /// Get the canonical PoX identifier for a given burnchain header hash.
    ///   this result may change if a previously unknown PoX anchor is processed.
    pub fn get_canonical_pox_id(&self, _burnchain_header_hash: &BurnchainHeaderHash) -> Result<PoxId, ()> {
        Ok(PoxId::stubbed())
    }
    /// Get the parent PoX identifier for a given identifier.
    ///  If the PoX identifier does not have a parent (should only be true for the "base" PoX identifier)
    ///    return an error.
    pub fn get_parent_pox_id(&self, _pox_id: &PoxId) -> Result<PoxId, ()> {
        Err(())
    }
    /// does the given pox identifier describe a child fork of the parent pox identifier? this returns true if they
    ///   are equal or child is a descendant.
    pub fn is_pox_id_descendant(&self, parent: &PoxId, child: &PoxId) -> bool {
        return parent == child || self.get_parent_pox_id(child).as_ref() == Ok(parent)
    }
    pub fn stubbed() -> PoxDB {
        PoxDB
    }
}

// High-level functions used by ChainsCoordinator
impl SortitionDB {
    pub fn get_sortition_id(&self, burnchain_header_hash: &BurnchainHeaderHash, pox_id: &PoxId) -> Result<SortitionId, ()> {
        Ok(SortitionId::new(burnchain_header_hash, pox_id))
    }
    pub fn is_sortition_processed(&self, burnchain_header_hash: &BurnchainHeaderHash, pox_id: &PoxId) -> Result<bool, BurnchainError> {
        let sort_id = SortitionId::new(burnchain_header_hash, pox_id);

        match SortitionDB::get_block_snapshot(&self.conn, &sort_id) {
            Ok(opt_sn) => Ok(opt_sn.is_some()),
            Err(e) => Err(BurnchainError::from(e))
        }
    }

    pub fn evaluate_sortition(&mut self, burn_header: &BurnchainBlockHeader, ops: Vec<BlockstackOperationType>,
                              burnchain: &Burnchain, pox_id: &PoxId, pox_db: &PoxDB) -> Result<(BlockSnapshot, BurnchainStateTransition), BurnchainError> {
        let parent_pox = pox_db.get_canonical_pox_id(&burn_header.parent_block_hash)
            .map_err(|_e| BurnchainError::MissingParentBlock)?;
        let parent_sort_id = SortitionId::new(&burn_header.parent_block_hash, &parent_pox);

        if !pox_db.is_pox_id_descendant(&parent_pox, pox_id) {
            return Err(BurnchainError::NonCanonicalPoxId(parent_pox, pox_id.clone()));
        }

        let mut sortition_db_handle = SortitionHandleTx::begin(self, &parent_sort_id)?;
        let parent_snapshot = sortition_db_handle.as_conn().get_block_snapshot(&burn_header.parent_block_hash)?
            .ok_or_else(|| {
                warn!("Unknown block {:?}", burn_header.parent_block_hash);
                BurnchainError::MissingParentBlock
            })?;

        let new_snapshot = sortition_db_handle.process_block_txs(
            &parent_snapshot, burn_header, burnchain, ops)?;

        // commit everything!
        sortition_db_handle.commit()?;
        Ok(new_snapshot)
    }

    pub fn is_stacks_block_in_sortition_set(&self, sortition_id: &SortitionId, block_to_check: &BlockHeaderHash) -> Result<bool, BurnchainError> {
        self.index_handle(sortition_id)
            .expects_stacks_block_in_fork(block_to_check)
            .map_err(|e| BurnchainError::from(e))
    }

    pub fn latest_stacks_blocks_processed(&self, sortition_id: &SortitionId) -> Result<u64, BurnchainError> {
        let db_handle = self.index_handle(sortition_id);
        SortitionDB::get_max_arrival_index(&db_handle)
            .map_err(|e| BurnchainError::from(e))
    }
}

// Querying methods
impl SortitionDB {
    /// Get the last snapshot processed, in the provided PoX fork
    pub fn get_last_snapshot(conn: &Connection, pox_id: &PoxId, pox_db: &PoxDB) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE pox_id = ?1 ORDER BY block_height DESC, burn_header_hash ASC LIMIT 1";
        let opt_result = query_row(conn, qry, &[pox_id])?;
        if let None = opt_result {
            let parent_pox_id = match pox_db.get_parent_pox_id(pox_id).ok() {
                None => return Ok(None),
                Some(x) => x
            };
            query_row(conn, qry, &[&parent_pox_id])
        } else {
            Ok(opt_result)
        }
    }

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    // PoX TODO: this method should go away -- callers will need to call `get_last_snapshot` with a PoX identifier
    //            to obtain the last snapshot
    pub fn get_canonical_burn_chain_tip_stubbed(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let pox_db = PoxDB::stubbed();
        SortitionDB::get_last_snapshot(conn, &PoxId::stubbed(), &pox_db)
            .map(|opt| opt.expect("CORRUPTION: No canonical burnchain tip"))
    }

    /// Get the canonical Stacks chain tip -- this gets memoized on the canonical burn chain tip.
    pub fn get_canonical_stacks_chain_tip_hash_stubbed(conn: &Connection) -> Result<(BurnchainHeaderHash, BlockHeaderHash), db_error> {
        let sn = SortitionDB::get_canonical_burn_chain_tip_stubbed(conn)?;

        let stacks_block_hash = sn.canonical_stacks_tip_hash;
        let burn_block_hash = sn.canonical_stacks_tip_burn_hash;
        Ok((burn_block_hash, stacks_block_hash))
    }


    /// Get an accepted stacks block header in a fork whose chain tip has not yet committed
    /// to it.
    // PoX TODO: once we integrate with the StacksChainController, this logic will go away
    fn get_accepted_stacks_block_pointer(conn: &Connection, tip_burn_header_hash: &BurnchainHeaderHash, stacks_block_hash: &BlockHeaderHash) -> Result<Option<AcceptedStacksBlockHeader>, db_error> {
        let args : &[&dyn ToSql] = &[tip_burn_header_hash, stacks_block_hash];
        query_row_panic(conn, "SELECT * FROM canonical_accepted_stacks_blocks WHERE tip_burn_block_hash = ?1 AND stacks_block_hash = ?2", args,
                        || format!("BUG: the same Stacks block {} shows up twice or more in the same burn chain fork (whose tip is {})", stacks_block_hash, tip_burn_header_hash))
    }

    /// Add an accepted Stacks block to the canonical accepted stacks header table, to indicate
    /// that it will be committed to by the next burn block added to the canonical chain tip.  Used
    /// to identify Stacks blocks that get accepted in the mean time, so we can ensure that the
    /// canonical burn chain tip always points to the canonical stacks chain tip.
    // PoX TODO: once we integrate with the StacksChainController, this logic will go away 
    fn insert_accepted_stacks_block_pointer(tx: &Transaction, tip_burn_header_hash: &BurnchainHeaderHash, burn_header_hash: &BurnchainHeaderHash, stacks_block_hash: &BlockHeaderHash, stacks_block_height: u64) -> Result<(), db_error> {
        let args: &[&dyn ToSql] = &[tip_burn_header_hash, burn_header_hash, stacks_block_hash, &u64_to_sql(stacks_block_height)?];
        tx.execute("INSERT OR REPLACE INTO canonical_accepted_stacks_blocks (tip_burn_block_hash, burn_block_hash, stacks_block_hash, block_height) VALUES (?1, ?2, ?3, ?4)", args)
            .map_err(db_error::SqliteError)?;
        Ok(())
    }

    /// Get the maximum arrival index for any known snapshot.
    fn get_max_arrival_index(conn: &Connection) -> Result<u64, db_error> {
        match conn.query_row("SELECT IFNULL(MAX(arrival_index), 0) FROM snapshots", NO_PARAMS,
                             |row| u64::from_row(row))
            .optional()? {
            Some(arrival_index) => Ok(arrival_index?),
            None => Ok(0)
        }
    }

    /// Get a snapshot with an arrived block (i.e. a block that was marked as processed)
    fn get_snapshot_by_arrival_index(conn: &Connection, arrival_index: u64) -> Result<Option<BlockSnapshot>, db_error> {
        query_row_panic(conn, "SELECT * FROM snapshots WHERE arrival_index = ?1 AND stacks_block_accepted > 0",
                        &[&u64_to_sql(arrival_index)?],
                        || "BUG: multiple snapshots have the same non-zero arrival index".to_string())
    }

    /// Get a snapshot for an existing burn chain block given its consensus hash.
    pub fn get_block_snapshot_consensus(conn: &Connection, consensus_hash: &ConsensusHash) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE consensus_hash = ?1";
        let args = [&consensus_hash];
        query_row_panic(conn, qry, &args,
                        || format!("FATAL: multiple block snapshots for the same block with consensus hash {}", consensus_hash))
    }

    /// MARF index value for a processed stacks block
    fn stacks_block_index_value(height: u64) -> String {
        format!("{}", height)
    }

    /// MARF index value for the highest arrival index processed in a fork
    fn stacks_block_max_arrival_index_value(index: u64) -> String {
        format!("{}", index)
    }

    /// Get a snapshot for an processed sortition.
    pub fn get_block_snapshot(conn: &Connection, sortition_id: &SortitionId) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE sortition_id = ?1";
        let args = [&sortition_id];
        query_row_panic(conn, qry, &args,
                        || format!("FATAL: multiple block snapshots for the same block {}", sortition_id))
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
        let result = query_row_panic(conn, qry, &[&ConsensusHash::empty()],
                                     || "FATAL: multiple first-block snapshots".into())?;
        match result {
            None => {
                // should never happen
                panic!("FATAL: no first snapshot");
            },
            Some(snapshot) => {
                Ok(snapshot)
            }
        }
    }

    /// Find out how any burn tokens were destroyed in a given block on a given fork.
    pub fn get_block_burn_amount(conn: &Connection, block_snapshot: &BlockSnapshot) -> Result<u64, db_error> {
        let user_burns = SortitionDB::get_user_burns_by_block(conn, &block_snapshot.sortition_id)?;
        let block_commits = SortitionDB::get_block_commits_by_block(conn, &block_snapshot.sortition_id)?;
        let mut burn_total : u64 = 0;
        
        for i in 0..user_burns.len() {
            burn_total = burn_total.checked_add(user_burns[i].burn_fee).expect("Way too many tokens burned");
        }
        for i in 0..block_commits.len() {
            burn_total = burn_total.checked_add(block_commits[i].burn_fee).expect("Way too many tokens burned");
        }
        Ok(burn_total)
    }

    /// Get all user burns registered in a block on is fork.
    /// Returns list of user burns in order by vtxindex.
    pub fn get_user_burns_by_block(conn: &Connection, sortition: &SortitionId) -> Result<Vec<UserBurnSupportOp>, db_error> {
        let qry = "SELECT * FROM user_burn_support WHERE sortition_id = ?1 ORDER BY vtxindex ASC";
        let args: &[&dyn ToSql] = &[sortition];

        query_rows(conn, qry, args)
    }

    /// Get all block commitments registered in a block on the burn chain's history in this fork.
    /// Returns the list of block commits in order by vtxindex.
    pub fn get_block_commits_by_block(conn: &Connection, sortition: &SortitionId) -> Result<Vec<LeaderBlockCommitOp>, db_error> {
        let qry = "SELECT * FROM block_commits WHERE sortition_id = ?1 ORDER BY vtxindex ASC";
        let args: &[&dyn ToSql] = &[sortition];

        query_rows(conn, qry, args)
    }

    /// Get all leader keys registered in a block on the burn chain's history in this fork.
    /// Returns the list of leader keys in order by vtxindex.
    pub fn get_leader_keys_by_block(conn: &Connection, sortition: &SortitionId) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        let qry = "SELECT * FROM leader_keys WHERE sortition_id = ?1 ORDER BY vtxindex ASC";
        let args: &[&dyn ToSql] = &[sortition];

        query_rows(conn, qry, args)
    }

    pub fn get_block_winning_vtxindex(conn: &Connection, sortition: &SortitionId) -> Result<Option<u16>, db_error> {
        let qry = "SELECT vtxindex FROM block_commits WHERE sortition_id = ?1 
                    AND txid = (
                      SELECT winning_block_txid FROM snapshots WHERE sortition_id = ?2 LIMIT 1) LIMIT 1";
        let args: &[&dyn ToSql] = &[sortition, sortition];
        conn.query_row(qry, args, |row| row.get(0)).optional()
            .map_err(db_error::from)
    }


    /// Given the fork index hash of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork, find the snapshot of the block at that height.
    pub fn get_ancestor_snapshot<C: SortitionContext>(ic: &IndexDBConn<'_, C, SortitionId>, ancestor_block_height: u64, tip_block_hash: &SortitionId) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(ancestor_block_height < BLOCK_HEIGHT_MAX);

        let ancestor = match get_ancestor_sort_id(ic, ancestor_block_height, tip_block_hash)? {
            Some(id) => id,
            None => {
                debug!("No ancestor block {} from {} in index", ancestor_block_height, tip_block_hash);
                return Ok(None)
            }
        };

        SortitionDB::get_block_snapshot(ic, &ancestor)
    }

    /// Get a parent block commit at a specific location in the burn chain on a particular fork.
    /// Returns None if there is no block commit at this location.
    pub fn get_block_commit_parent<C: SortitionContext>(ic: &IndexDBConn<'_, C, SortitionId>, block_height: u64, vtxindex: u32, tip: &SortitionId) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match SortitionDB::get_ancestor_snapshot(ic, block_height, tip)? {
            Some(sn) => sn,
            None => {
                return Ok(None);
            }
        };

        let qry = "SELECT * FROM block_commits WHERE sortition_id = ?1 AND block_height = ?2 AND vtxindex = ?3 LIMIT 2";
        let args: &[&dyn ToSql] = &[&ancestor_snapshot.sortition_id, &u64_to_sql(block_height)?, &vtxindex];
        query_row_panic(ic, qry, args,
                        || format!("Multiple parent blocks at {},{} in {}", block_height, vtxindex, tip))
    }

    /// Get a leader key at a specific location in the burn chain's fork history, given the
    /// matching block commit's fork index root (block_height and vtxindex are the leader's
    /// calculated location in this fork).
    /// Returns None if there is no leader key at this location.
    pub fn get_leader_key_at<C: SortitionContext>(ic: &IndexDBConn<'_, C, SortitionId>, key_block_height: u64, key_vtxindex: u32, tip: &SortitionId) -> Result<Option<LeaderKeyRegisterOp>, db_error> {
        assert!(key_block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match SortitionDB::get_ancestor_snapshot(ic, key_block_height, tip)? {
            Some(sn) => sn,
            None => {
                return Ok(None);
            }
        };

        // PoX TODO: note -- leader_keys table will index on burn_header_hash: if a leader key is reprocessed due to a PoX fork,
        //                   it should be allowed to either overwrite the previous entry OR skip insertion (i.e., UNIQUE constraints
        //                   should not be allowed to cause a panic)
        let qry = "SELECT * FROM leader_keys WHERE burn_header_hash = ?1 AND block_height = ?2 AND vtxindex = ?3 LIMIT 2";
        let args : &[&dyn ToSql] = &[&ancestor_snapshot.burn_header_hash, &u64_to_sql(key_block_height)?, &key_vtxindex];
        query_row_panic(ic, qry, args,
                        || format!("Multiple keys at {},{} in {}", key_block_height, key_vtxindex, tip))
    }
    
    /// Find the VRF public keys consumed by each block candidate in the given list.
    /// The burn DB should have a key for each candidate; otherwise the candidate would not have
    /// been accepted.
    pub fn get_consumed_leader_keys<C: SortitionContext>(ic: &IndexDBConn<'_, C, SortitionId>, parent_tip: &BlockSnapshot, block_candidates: &Vec<LeaderBlockCommitOp>) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        // get the set of VRF keys consumed by these commits 
        let mut leader_keys = vec![];
        for i in 0..block_candidates.len() {
            let leader_key_block_height = block_candidates[i].key_block_ptr as u64;
            let leader_key_vtxindex = block_candidates[i].key_vtxindex as u32;
            let leader_key = SortitionDB::get_leader_key_at(ic, leader_key_block_height, leader_key_vtxindex, &parent_tip.sortition_id)?
                .expect(&format!("FATAL: no leader key for accepted block commit {} (at {},{})", &block_candidates[i].txid, leader_key_block_height, leader_key_vtxindex));

            leader_keys.push(leader_key);
        }

        Ok(leader_keys)
    }

    /// Get a block commit by its committed block
    pub fn get_block_commit_for_stacks_block(conn: &Connection, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        let qry = "SELECT * FROM block_commits WHERE burn_header_hash = ?1 AND block_header_hash = ?2";
        let args: [&dyn ToSql; 2] = [&burn_header_hash, &block_hash];
        query_row_panic(conn, qry, &args,
                        || format!("FATAL: multiple block commits for {}", &block_hash))
    }


    /// Get a block snapshot for a winning block hash in a given burn chain fork.
    #[cfg(test)]
    pub fn get_block_snapshot_for_winning_stacks_block(ic: &SortitionDBConn, tip: &SortitionId, block_hash: &BlockHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        match ic.get_indexed(tip, &db_keys::stacks_block_present(block_hash))? {
            Some(sortition_id_hex) => {
                let sortition_id = SortitionId::from_hex(&sortition_id_hex)
                    .expect("FATAL: DB stored non-parseable sortition id");
                SortitionDB::get_block_snapshot(ic, &sortition_id)
            },
            None => {
                Ok(None)
            }
        }
    }

    /// Merge the result of get_stacks_header_hashes() into a BlockHeaderCache
    pub fn merge_block_header_cache(cache: &mut BlockHeaderCache, header_data: &Vec<(BurnchainHeaderHash, Option<BlockHeaderHash>)>) -> () {
        let mut i = header_data.len() - 1;
        while i > 0 {

            let cur_block_hash = &header_data[i].0;
            let cur_block_opt = &header_data[i].1;

            if !cache.contains_key(cur_block_hash) {
                let prev_block_hash = header_data[i-1].0.clone();
                cache.insert((*cur_block_hash).clone(), ((*cur_block_opt).clone(), prev_block_hash.clone()));
            }
            
            i -= 1;
        }
        
        debug!("Block header cache has {} items", cache.len());
    }

    /// Get a blockstack burnchain operation by txid
    #[cfg(test)]
    pub fn get_burnchain_transaction(conn: &Connection, txid: &Txid) -> Result<Option<BlockstackOperationType>, db_error> {
        // leader key?
        let leader_key_sql = "SELECT * FROM leader_keys WHERE txid = ?1 LIMIT 1";
        let args = [&txid];

        let leader_key_res = query_row_panic(conn, &leader_key_sql, &args,
                                             || "Multiple leader keys with same txid".to_string())?;
        if let Some(leader_key) = leader_key_res {
            return Ok(Some(BlockstackOperationType::LeaderKeyRegister(leader_key)));
        }
        
        // block commit?
        let block_commit_sql = "SELECT * FROM block_commits WHERE txid = ?1 LIMIT 1";

        let block_commit_res = query_row_panic(conn, &block_commit_sql, &args,
                                             || "Multiple block commits with same txid".to_string())?;
        if let Some(block_commit) = block_commit_res {
            return Ok(Some(BlockstackOperationType::LeaderBlockCommit(block_commit)));
        }

        // user burn?
        let user_burn_sql = "SELECT * FROM user_burn_support WHERE txid = ?1 LIMIT 1".to_string();

        let user_burn_res = query_row_panic(conn, &user_burn_sql, &args,
                                            || "Multiple user burns with same txid".to_string())?;
        if let Some(user_burn) = user_burn_res {
            return Ok(Some(BlockstackOperationType::UserBurnSupport(user_burn)));
        }

        Ok(None)
    }

}

impl <'a> SortitionHandleTx <'a> {
    /// Append a snapshot to a chain tip, and update various chain tip statistics.
    /// Returns the new state root of this fork.
    pub fn append_chain_tip_snapshot(&mut self, parent_snapshot: &BlockSnapshot, snapshot: &BlockSnapshot, block_ops: &Vec<BlockstackOperationType>, consumed_leader_keys: &Vec<LeaderKeyRegisterOp>) -> Result<TrieHash, db_error> {
        assert_eq!(snapshot.parent_burn_header_hash, parent_snapshot.burn_header_hash);
        assert_eq!(parent_snapshot.block_height + 1, snapshot.block_height);
        if snapshot.sortition {
            assert_eq!(parent_snapshot.num_sortitions + 1, snapshot.num_sortitions);
        }
        else {
            assert_eq!(parent_snapshot.num_sortitions, snapshot.num_sortitions);
        }

        let mut parent_sn = parent_snapshot.clone();
        let root_hash = self.index_add_fork_info(&mut parent_sn, snapshot, block_ops, consumed_leader_keys)?;

        let mut sn = snapshot.clone();
        sn.index_root = root_hash.clone();

        // preserve memoized stacks chain tip from this burn chain fork
        sn.canonical_stacks_tip_height = parent_sn.canonical_stacks_tip_height;
        sn.canonical_stacks_tip_hash = parent_sn.canonical_stacks_tip_hash;
        sn.canonical_stacks_tip_burn_hash = parent_sn.canonical_stacks_tip_burn_hash;

        self.insert_block_snapshot(&sn)?;

        for block_op in block_ops {
            self.store_burnchain_transaction(block_op, &sn.sortition_id)?;
        }

        Ok(root_hash)
    }

    /// Store a blockstack burnchain operation
    fn store_burnchain_transaction(&mut self, blockstack_op: &BlockstackOperationType, sort_id: &SortitionId) -> Result<(), db_error> {
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                debug!("ACCEPTED({}) leader key register {} at {},{}", op.block_height, &op.txid, op.block_height, op.vtxindex);
                self.insert_leader_key(op, sort_id)
            },
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                debug!("ACCEPTED({}) leader block commit {} at {},{}", op.block_height, &op.txid, op.block_height, op.vtxindex);
                self.insert_block_commit(op, sort_id)
            },
            BlockstackOperationType::UserBurnSupport(ref op) => {
                debug!("ACCEPTED({}) user burn support {} at {},{}", op.block_height, &op.txid, op.block_height, op.vtxindex);
                self.insert_user_burn(op, sort_id)
            }
        }
    }

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    fn insert_leader_key(&mut self, leader_key: &LeaderKeyRegisterOp, sort_id: &SortitionId) -> Result<(), db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);

        let args : &[&dyn ToSql] = &[
            &leader_key.txid,
            &leader_key.vtxindex,
            &u64_to_sql(leader_key.block_height)?,
            &leader_key.burn_header_hash,
            &leader_key.consensus_hash,
            &leader_key.public_key.to_hex(),
            &to_hex(&leader_key.memo),
            &leader_key.address.to_string(),
            sort_id
        ];

        self.execute("INSERT INTO leader_keys (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, memo, address, sortition_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", args)?;

        Ok(())
    }
    
    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    fn insert_block_commit(&mut self, block_commit: &LeaderBlockCommitOp, sort_id: &SortitionId) -> Result<(), db_error> {
        assert!(block_commit.block_height < BLOCK_HEIGHT_MAX);

        // serialize tx input to JSON
        let tx_input_str = serde_json::to_string(&block_commit.input)
            .map_err(|e| db_error::SerializationError(e))?;

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", block_commit.burn_fee);

        let args : &[&dyn ToSql] = &[
            &block_commit.txid,
            &block_commit.vtxindex,
            &u64_to_sql(block_commit.block_height)?,
            &block_commit.burn_header_hash, 
            &block_commit.block_header_hash,
            &block_commit.new_seed,
            &block_commit.parent_block_ptr,
            &block_commit.parent_vtxindex,
            &block_commit.key_block_ptr,
            &block_commit.key_vtxindex,
            &to_hex(&block_commit.memo[..]),
            &burn_fee_str,
            &tx_input_str,
            sort_id
        ];

        self.execute("INSERT INTO block_commits (txid, vtxindex, block_height, burn_header_hash, block_header_hash, new_seed, parent_block_ptr, parent_vtxindex, key_block_ptr, key_vtxindex, memo, burn_fee, input, sortition_id) \
                      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)", args)?;

        Ok(())
    }

    /// Insert a user support burn.
    /// No validity checking will be done, beyond what is encoded in the user_burn_support table
    /// constraints.  That is, type mismatches and serialization errors will be caught, but nothing
    /// else.
    /// The corresponding snapshot must already be inserted
    fn insert_user_burn(&mut self, user_burn: &UserBurnSupportOp, sort_id: &SortitionId) -> Result<(), db_error> {
        assert!(user_burn.block_height < BLOCK_HEIGHT_MAX);

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", user_burn.burn_fee);

        let args : &[&dyn ToSql] = &[
            &user_burn.txid,
            &user_burn.vtxindex,
            &u64_to_sql(user_burn.block_height)?,
            &user_burn.burn_header_hash, 
            &user_burn.address.to_string(),
            &user_burn.consensus_hash,
            &user_burn.public_key.to_hex(),
            &user_burn.key_block_ptr,
            &user_burn.key_vtxindex,
            &user_burn.block_header_hash_160,
            &burn_fee_str,
            sort_id
        ];

        self.execute("INSERT INTO user_burn_support (txid, vtxindex, block_height, burn_header_hash, address, consensus_hash, public_key, key_block_ptr, key_vtxindex, block_header_hash_160, burn_fee, sortition_id) \
                      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)", args)?;

        Ok(())
    }

    /// Insert a snapshots row from a block's-worth of operations. 
    /// Do not call directly -- use append_chain_tip_snapshot to preserve the fork table structure.
    fn insert_block_snapshot(&self, snapshot: &BlockSnapshot) -> Result<(), db_error> {
        assert!(snapshot.block_height < BLOCK_HEIGHT_MAX);
        assert!(snapshot.num_sortitions < BLOCK_HEIGHT_MAX);

        test_debug!("Insert block snapshot state {} for block {} ({},{}) {}", snapshot.index_root, snapshot.block_height,
                    snapshot.burn_header_hash, snapshot.parent_burn_header_hash, snapshot.num_sortitions);

        let total_burn_str = format!("{}", snapshot.total_burn);

        let args : &[&dyn ToSql] = &[
            &u64_to_sql(snapshot.block_height)?,
            &snapshot.burn_header_hash,
            &u64_to_sql(snapshot.burn_header_timestamp)?,
            &snapshot.parent_burn_header_hash,
            &snapshot.consensus_hash,
            &snapshot.ops_hash,
            &total_burn_str,
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
            &snapshot.canonical_stacks_tip_burn_hash,
            &snapshot.sortition_id,
            &snapshot.pox_id
        ];

        self.execute("INSERT INTO snapshots \
                      (block_height, burn_header_hash, burn_header_timestamp, parent_burn_header_hash, consensus_hash, ops_hash, total_burn, sortition, sortition_hash, winning_block_txid, winning_stacks_block_hash, index_root, num_sortitions, \
                      stacks_block_accepted, stacks_block_height, arrival_index, canonical_stacks_tip_height, canonical_stacks_tip_hash, canonical_stacks_tip_burn_hash, sortition_id, pox_id) \
                      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)", args)
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Record fork information to the index and calculate the new fork index root hash.
    /// * sortdb::vrf::${VRF_PUBLIC_KEY} --> 0 or 1 (1 if available, 0 if consumed), for each VRF public key we process
    /// * sortdb::last_sortition --> $BURN_BLOCK_HASH, for each block that had a sortition
    /// * sortdb::sortition_block_hash::${STACKS_BLOCK_HASH} --> $BURN_BLOCK_HASH for each winning block sortition
    /// * sortdb::stacks::block::${STACKS_BLOCK_HASH} --> ${STACKS_BLOCK_HEIGHT} for each block that has been accepted so far
    /// * sortdb::stacks::block::max_arrival_index --> ${ARRIVAL_INDEX} to set the maximum arrival index processed in this fork
    /// NOTE: the resulting index root must be globally unique.  This is guaranteed because each
    /// burn block hash is unique, no matter what fork it's on (and this index uses burn block
    /// hashes as its index's block hash data).
    fn index_add_fork_info(&mut self, parent_snapshot: &mut BlockSnapshot, snapshot: &BlockSnapshot, block_ops: &Vec<BlockstackOperationType>, consumed_leader_keys: &Vec<LeaderKeyRegisterOp>) -> Result<TrieHash, db_error> {
        if !snapshot.is_initial() {
            assert_eq!(snapshot.parent_burn_header_hash, parent_snapshot.burn_header_hash);
        }

        // data we want to store
        let mut keys = vec![];
        let mut values = vec![];

        // record each new VRF key, and each consumed VRF key
        for block_op in block_ops {
            if let BlockstackOperationType::LeaderKeyRegister(ref data) = block_op {
                keys.push(db_keys::vrf_key_status(&data.public_key));
                values.push("1".to_string());       // indicates "available"
            }
        }

        // record each consumed VRF key as consumed
        for consumed_leader_key in consumed_leader_keys {
            keys.push(db_keys::vrf_key_status(&consumed_leader_key.public_key));
            values.push("0".to_string());
        }

        // map burnchain header hashes to sortition ids
        keys.push(db_keys::sortition_id_for_bhh(&snapshot.burn_header_hash));
        values.push(snapshot.sortition_id.to_hex());

        // if this commit has a sortition, record its burn block hash and stacks block hash
        if snapshot.sortition {
            keys.push(db_keys::last_sortition());
            values.push(snapshot.burn_header_hash.to_hex());

            keys.push(db_keys::stacks_block_present(&snapshot.winning_stacks_block_hash));
            values.push(snapshot.sortition_id.to_hex());
        }

        // commit to all newly-arrived blocks
        let (mut block_arrival_keys, mut block_arrival_values) = self.process_new_block_arrivals(parent_snapshot)?;
        keys.append(&mut block_arrival_keys);
        values.append(&mut block_arrival_values);

        // store each indexed field
        //  -- marf tx _must_ have already began
        self.put_indexed_begin(&parent_snapshot.sortition_id, &snapshot.sortition_id)?;

        let root_hash = self.put_indexed_all(&keys, &values)?;
        self.indexed_commit()?;
        self.context.chain_tip = snapshot.sortition_id.clone();
        Ok(root_hash)
    }

    /// Find all stacks blocks that were processed since parent_tip had been processed, and generate MARF
    /// key/value pairs for the subset that arrived on ancestor blocks of the parent.  Update the
    /// given parent chain tip to have the correct memoized canonical chain tip present in the fork
    /// it represents.
    fn process_new_block_arrivals(&self, parent_tip: &mut BlockSnapshot) -> Result<(Vec<String>, Vec<String>), db_error> {
        let mut keys = vec![];
        let mut values = vec![];

        let db_handle = self.conn_view(&parent_tip.sortition_id);

        let old_max_arrival_index = db_handle.get_tip_indexed(&db_keys::stacks_block_max_arrival_index())?
            .unwrap_or("0".into())
            .parse::<u64>().expect("BUG: max arrival index is not a u64");
        let max_arrival_index = SortitionDB::get_max_arrival_index(&db_handle)?;

        let mut new_block_arrivals = vec![];

        // find all Stacks block hashes who arrived since this parent_tip was built.
        for ari in old_max_arrival_index..(max_arrival_index+1) {
            let arrival_sn = match SortitionDB::get_snapshot_by_arrival_index(&db_handle, ari)? {
                Some(sn) => sn,
                None => {
                    continue;
                }
            };

            // must be an ancestor of this tip, or must be this tip
            if let Some(sn) = db_handle.get_block_snapshot(&arrival_sn.burn_header_hash)? {
                // this block arrived on an ancestor block
                assert_eq!(sn, arrival_sn);

                debug!("New Stacks anchored block arrived since {}: block {} ({}) ari={} tip={}", parent_tip.burn_header_hash, sn.stacks_block_height, sn.winning_stacks_block_hash, ari, &parent_tip.burn_header_hash);
                new_block_arrivals.push((sn.burn_header_hash, sn.winning_stacks_block_hash, sn.stacks_block_height));
            } else {
                // this block did not arrive on an ancestor block
                continue;
            }
        }

        let mut best_tip_block_bhh = parent_tip.canonical_stacks_tip_hash.clone();
        let mut best_tip_burn_bhh = parent_tip.canonical_stacks_tip_burn_hash.clone();
        let mut best_tip_height = parent_tip.canonical_stacks_tip_height;

        // NOTE: new_block_arrivals is ordered by arrival index, which means it is partially
        // ordered by block height!
        for (burn_bhh, block_bhh, height) in new_block_arrivals.into_iter() {
            keys.push(db_keys::stacks_block_index(&block_bhh));
            values.push(SortitionDB::stacks_block_index_value(height));

            if height > best_tip_height {
                debug!("At tip {}: {}/{} (height {}) is superceded by {}/{} (height {})", &parent_tip.burn_header_hash, &best_tip_burn_bhh, &best_tip_block_bhh, best_tip_height, burn_bhh, block_bhh, height);

                best_tip_block_bhh = block_bhh;
                best_tip_burn_bhh = burn_bhh;
                best_tip_height = height;
            }
        }

        // update parent tip
        parent_tip.canonical_stacks_tip_burn_hash = best_tip_burn_bhh;
        parent_tip.canonical_stacks_tip_hash = best_tip_block_bhh;
        parent_tip.canonical_stacks_tip_height = best_tip_height;

        debug!("Max arrival for child of {} is {}", &parent_tip.burn_header_hash, &max_arrival_index);
        keys.push(db_keys::stacks_block_max_arrival_index());
        values.push(SortitionDB::stacks_block_max_arrival_index_value(max_arrival_index));

        Ok((keys, values))
    }

}

impl ChainstateDB for SortitionDB {
    fn backup(_backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use util::db::Error as db_error;
    use util::get_epoch_time_secs;

    use chainstate::burn::operations::{
        LeaderBlockCommitOp,
        LeaderKeyRegisterOp,
        UserBurnSupportOp,
        BlockstackOperation,
        BlockstackOperationType
    };

    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::BitcoinNetworkType;

    use burnchains::{Txid, BurnchainHeaderHash};
    use chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash};
    use util::hash::{hex_bytes, Hash160};
    use util::vrf::*;

    use chainstate::stacks::StacksAddress;
    use chainstate::stacks::StacksPublicKey;
    use address::AddressHashMode;

    use core::*;

    #[test]
    fn test_instantiate() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let _db = SortitionDB::connect_test(123, &first_burn_hash).unwrap();
    }

    #[test]
    fn test_tx_begin_end() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut db = SortitionDB::connect_test(123, &first_burn_hash).unwrap();
        let tx = db.tx_begin().unwrap();
        tx.commit().unwrap();
    }

    fn test_append_snapshot(db: &mut SortitionDB, next_hash: BurnchainHeaderHash, block_ops: &Vec<BlockstackOperationType>, consumed_leader_keys: &Vec<LeaderKeyRegisterOp>) -> BlockSnapshot {
        let mut sn = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        let mut tx = SortitionHandleTx::begin(db, &sn.sortition_id).unwrap();

        let sn_parent = sn.clone();
        sn.parent_burn_header_hash = sn.burn_header_hash.clone();
        sn.burn_header_hash = next_hash;
        sn.block_height += 1;
        sn.num_sortitions += 1;
        sn.sortition_id = SortitionId::stubbed(&sn.burn_header_hash);

        let index_root = tx.append_chain_tip_snapshot(&sn_parent, &sn, block_ops, consumed_leader_keys).unwrap();
        sn.index_root = index_root;

        tx.commit().unwrap();

        sn
    }

    #[test]
    fn test_insert_leader_key() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let leader_key = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 1,
            burn_header_hash: BurnchainHeaderHash([0x01; 32])
        };

        let mut db = SortitionDB::connect_test(block_height, &first_burn_hash).unwrap();

        let snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x01; 32]),
                                            &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]);

        {
            let ic = db.index_conn();
            let leader_key_opt = SortitionDB::get_leader_key_at(&ic, block_height + 1, vtxindex, &snapshot.sortition_id).unwrap();
            assert!(leader_key_opt.is_some());
            assert_eq!(leader_key_opt.unwrap(), leader_key);
        }

        let new_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x02; 32]),
                                            &vec![], &vec![]);

        {
            let ic = db.index_conn();
            let leader_key_opt = SortitionDB::get_leader_key_at(&ic, block_height + 1, vtxindex, &new_snapshot.sortition_id).unwrap();
            assert!(leader_key_opt.is_some());
            assert_eq!(leader_key_opt.unwrap(), leader_key);
            
            let leader_key_none = SortitionDB::get_leader_key_at(&ic, block_height + 1, vtxindex+1, &new_snapshot.sortition_id).unwrap();
            assert!(leader_key_none.is_none());
        }
    }

    #[test]
    fn test_insert_block_commit() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let leader_key = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 1,
            burn_header_hash: BurnchainHeaderHash([0x01; 32])
        };

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_ptr: 0x43424140,
            parent_vtxindex: 0x5150,
            key_block_ptr: (block_height + 1) as u32,
            key_vtxindex: vtxindex as u16,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1, 
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 2,
            burn_header_hash: BurnchainHeaderHash([0x03; 32])
        };

        let mut db = SortitionDB::connect_test(block_height, &first_burn_hash).unwrap();

        let snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x01; 32]),
                                            &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]);

        // test get_consumed_leader_keys()
        {
            let ic = db.index_conn();
            let keys = SortitionDB::get_consumed_leader_keys(&ic, &snapshot, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);
        }

        // test is_leader_key_consumed()
        {
            let ic = db.index_handle(&snapshot.sortition_id);
            let is_consumed = ic.is_leader_key_consumed(&leader_key).unwrap();
            assert!(!is_consumed);
        }

        let snapshot_consumed = test_append_snapshot(&mut db, BurnchainHeaderHash([0x03; 32]),
                                                     &vec![BlockstackOperationType::LeaderBlockCommit(block_commit.clone())], &vec![leader_key.clone()]);

        {
            let res_block_commits = SortitionDB::get_block_commits_by_block(db.conn(), &snapshot_consumed.sortition_id).unwrap();
            assert_eq!(res_block_commits.len(), 1);
            assert_eq!(res_block_commits[0], block_commit);
        }
        
        // test is_leader_key_consumed() now that the commit exists
        {
            let ic = db.index_handle(&snapshot_consumed.sortition_id);
            let is_consumed = ic.is_leader_key_consumed(&leader_key).unwrap();
            assert!(is_consumed);
        }

        // advance and get parent
        let empty_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x05; 32]),
                                                  &vec![], &vec![]);

        // test get_block_commit_parent()
        {
            let ic = db.index_conn();
            let parent = SortitionDB::get_block_commit_parent(&ic, block_height + 2, block_commit.vtxindex, &empty_snapshot.sortition_id).unwrap();
            assert!(parent.is_some());
            assert_eq!(parent.unwrap(), block_commit);

            let parent = SortitionDB::get_block_commit_parent(&ic, block_height + 3, block_commit.vtxindex, &empty_snapshot.sortition_id).unwrap();
            assert!(parent.is_none());
            
            let parent = SortitionDB::get_block_commit_parent(&ic, block_height + 2, block_commit.vtxindex + 1, &empty_snapshot.sortition_id).unwrap();
            assert!(parent.is_none());
        }

        // test get_block_commit()
        {
            let handle = db.index_handle(&empty_snapshot.sortition_id);
            let commit = handle.get_block_commit(&block_commit.txid, &block_commit.burn_header_hash).unwrap();
            assert!(commit.is_some());
            assert_eq!(commit.unwrap(), block_commit);

            let bad_txid = Txid::from_bytes_be(&hex_bytes("4c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap();
            let commit = handle.get_block_commit(&bad_txid, &block_commit.burn_header_hash).unwrap();
            assert!(commit.is_none());
        }
        
        // test get_consumed_leader_keys() (should be doable at any subsequent index root)
        {
            let ic = db.index_conn();
            let keys = SortitionDB::get_consumed_leader_keys(&ic, &empty_snapshot, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);
        }
        
        // test is_leader_key_consumed() (should be duable at any subsequent index root)
        {
            let ic = db.index_handle(&empty_snapshot.sortition_id);
            let is_consumed = ic.is_leader_key_consumed(&leader_key).unwrap();
            assert!(is_consumed);
            

            let ic = db.index_handle(&snapshot.sortition_id);
            let is_consumed = ic.is_leader_key_consumed(&leader_key).unwrap();
            assert!(!is_consumed);
        }

        // make a fork between the leader key and block commit, and verify that the key is
        // unconsumed
        let fork_snapshot = {
            let mut sn = SortitionDB::get_block_snapshot(db.conn(), &snapshot.sortition_id).unwrap().unwrap();
            let next_hash = BurnchainHeaderHash([0x13; 32]);
            let mut tx = SortitionHandleTx::begin(&mut db, &sn.sortition_id).unwrap();

            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.sortition_id = SortitionId(next_hash.0.clone());
            sn.burn_header_hash = next_hash;
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = tx.append_chain_tip_snapshot(&sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();

            sn
        };

        // test get_consumed_leader_keys() and is_leader_key_consumed() against this new fork
        {
            let ic = db.index_conn();
            let keys = SortitionDB::get_consumed_leader_keys(&ic, &fork_snapshot, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);
        }
        
        // test is_leader_key_consumed() (should be duable at any subsequent index root)
        {
            let ic = db.index_handle(&fork_snapshot.sortition_id);
            let is_consumed = ic.is_leader_key_consumed(&leader_key).unwrap();
            assert!(!is_consumed);
        }
    }
    
    #[test]
    fn test_insert_user_burn() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let leader_key = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 1,
            burn_header_hash: BurnchainHeaderHash([0x01; 32])
        };

        let user_burn = UserBurnSupportOp {
            address: StacksAddress::new(1, Hash160([1u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            key_block_ptr: (block_height + 1) as u32,
            key_vtxindex: vtxindex as u16,
            burn_fee: 12345,

            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 2,
            burn_header_hash: BurnchainHeaderHash([0x03; 32])
        };

        let mut db = SortitionDB::connect_test(block_height, &first_burn_hash).unwrap();
        

        let snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x01; 32]),
                                            &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]);

        let user_burn_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x03; 32]),
                                                      &vec![BlockstackOperationType::UserBurnSupport(user_burn.clone())], &vec![]);

        {
            let res_user_burns = SortitionDB::get_user_burns_by_block(db.conn(), &user_burn_snapshot.sortition_id).unwrap();
            assert_eq!(res_user_burns.len(), 1);
            assert_eq!(res_user_burns[0], user_burn);

            let no_user_burns = SortitionDB::get_user_burns_by_block(db.conn(), &snapshot.sortition_id).unwrap();
            assert_eq!(no_user_burns.len(), 0);
        }
    }

    #[test]
    fn has_VRF_public_key() {
        let public_key = VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap();
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let leader_key = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: public_key.clone(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 2,
            burn_header_hash: BurnchainHeaderHash([0x03; 32])
        };

        let mut db = SortitionDB::connect_test(block_height, &first_burn_hash).unwrap();
        
        let no_key_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x01; 32]),
                                                   &vec![], &vec![]);

        let has_key_before = {
            let ic = db.index_handle(&no_key_snapshot.sortition_id);
            ic.has_VRF_public_key(&public_key).unwrap()
        };

        assert!(!has_key_before);

        let key_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x03; 32]),
                                                &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]);

        let has_key_after = {
            let ic = db.index_handle(&key_snapshot.sortition_id);
            ic.has_VRF_public_key(&public_key).unwrap()
        };

        assert!(has_key_after);
    }

    #[test]
    fn is_fresh_consensus_hash() {
        let consensus_hash_lifetime = 24;
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();
        {
            let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
            for i in 0..255 {
                let sortition_id = SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]);
                let parent_sortition_id = if i == 0 {
                    last_snapshot.sortition_id.clone()
                } else {
                    SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i-1 as u8])
                };

                let mut tx = SortitionHandleTx::begin(&mut db, &parent_sortition_id).unwrap();
                let snapshot_row = BlockSnapshot {
                    block_height: i as u64 +1,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    sortition_id,
                    pox_id: PoxId::stubbed(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[(if i == 0 { 0x10 } else { 0 }) as u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(i+1) as u8]).unwrap(),
                    ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    total_burn: i as u64,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: i as u64 + 1,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
                };
                let index_root = tx.append_chain_tip_snapshot(&last_snapshot, &snapshot_row,
                                                              &vec![], &vec![]).unwrap();
                last_snapshot = snapshot_row;
                last_snapshot.index_root = index_root;
                tx.commit().unwrap();
            }
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();

        let ch_fresh = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255]).unwrap();
        let ch_oldest_fresh = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(255 - consensus_hash_lifetime) as u8]).unwrap();
        let ch_newest_stale = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(255 - consensus_hash_lifetime - 1) as u8]).unwrap();
        let ch_missing = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,255]).unwrap();

        let ic = db.index_handle(&tip.sortition_id);
        let fresh_check = ic.is_fresh_consensus_hash(consensus_hash_lifetime, &ch_fresh).unwrap();

        assert!(fresh_check);

        let oldest_fresh_check = ic.is_fresh_consensus_hash(consensus_hash_lifetime, &ch_oldest_fresh).unwrap();

        assert!(oldest_fresh_check);

        let newest_stale_check = ic.is_fresh_consensus_hash(consensus_hash_lifetime, &ch_newest_stale).unwrap();

        assert!(!newest_stale_check);

            
        let missing_check = ic.is_fresh_consensus_hash(consensus_hash_lifetime, &ch_missing).unwrap();

        assert!(!missing_check);
    }

    #[test]
    fn get_consensus_at() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();
        {
            let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
            for i in 0..256u64 {
                let sortition_id = SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]);
                let parent_sortition_id = if i == 0 {
                    last_snapshot.sortition_id.clone()
                } else {
                    SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(i-1) as u8])
                };

                let mut tx = SortitionHandleTx::begin(&mut db, &parent_sortition_id).unwrap();
                let snapshot_row = BlockSnapshot {
                    block_height: i as u64 +1,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    sortition_id,
                    pox_id: PoxId::stubbed(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[(if i == 0 { 0x10 } else { 0 }) as u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(i+1) as u8]).unwrap(),
                    ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    total_burn: i as u64,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: i as u64 + 1,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
                };
                let index_root = tx.append_chain_tip_snapshot(&last_snapshot, &snapshot_row,
                                                              &vec![], &vec![]).unwrap();
                last_snapshot = snapshot_row;
                last_snapshot.index_root = index_root;
                // should succeed within the tx
                let ch = tx.as_conn().get_consensus_at(i as u64 + 1).unwrap().unwrap();
                assert_eq!(ch, last_snapshot.consensus_hash);

                tx.commit().unwrap();
            }
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();

        for i in 0..256 {
            // should succeed within the conn
            let ic = db.index_handle(&tip.sortition_id);
            let expected_ch = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap();
            let ch = ic.get_consensus_at(i).unwrap().unwrap();
            assert_eq!(ch, expected_ch);
        }
    }

    #[test]
    fn get_block_burn_amount() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let leader_key = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 1,
            burn_header_hash: BurnchainHeaderHash([0x01; 32])
        };

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_ptr: 0x43424140,
            parent_vtxindex: 0x4342,
            key_block_ptr: (block_height + 1) as u32,
            key_vtxindex: vtxindex as u16,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1, 
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height + 2,
            burn_header_hash: BurnchainHeaderHash([0x03; 32])
        };

        let user_burn = UserBurnSupportOp {
            address: StacksAddress::new(2, Hash160([2u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            key_block_ptr: (block_height + 1) as u32,
            key_vtxindex: vtxindex as u16,
            burn_fee: 12345,

            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
            vtxindex: vtxindex + 1,
            block_height: block_height + 2,
            burn_header_hash: BurnchainHeaderHash([0x03; 32])
        };

        let mut db = SortitionDB::connect_test(block_height, &first_burn_hash).unwrap();

        let key_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x01; 32]),
                                                &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]);

        let commit_snapshot = test_append_snapshot(&mut db, BurnchainHeaderHash([0x03; 32]),
                                                   &vec![BlockstackOperationType::LeaderBlockCommit(block_commit.clone()), BlockstackOperationType::UserBurnSupport(user_burn.clone())], &vec![leader_key.clone()]);
    
        {
            let burn_amt = SortitionDB::get_block_burn_amount(db.conn(), &commit_snapshot).unwrap();
            assert_eq!(burn_amt, block_commit.burn_fee + user_burn.burn_fee);

            let no_burn_amt = SortitionDB::get_block_burn_amount(db.conn(), &key_snapshot).unwrap();
            assert_eq!(no_burn_amt, 0);
        }
    }
   
    #[test]
    fn get_last_snapshot_with_sortition() {
        let block_height = 123;
        let total_burn_sortition = 100;
        let total_burn_no_sortition = 200;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let mut first_snapshot = BlockSnapshot {
            block_height: block_height - 2,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: first_burn_hash.clone(),
            sortition_id: SortitionId(first_burn_hash.0.clone()),
            parent_burn_header_hash: BurnchainHeaderHash([0xff; 32]),
            consensus_hash: ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
            ops_hash: OpsHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            total_burn: 0,
            sortition: true,
            sortition_hash: SortitionHash::initial(),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            index_root: TrieHash([0u8; 32]),
            num_sortitions: 0,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            pox_id: PoxId::stubbed(),
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
        };

        let mut snapshot_with_sortition = BlockSnapshot {
            block_height: block_height,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]).unwrap(),
            sortition_id: SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]),
            parent_burn_header_hash:  BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            total_burn: total_burn_sortition,
            sortition: true,
            sortition_hash: SortitionHash::initial(),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            index_root: TrieHash([1u8; 32]),
            num_sortitions: 1,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            pox_id: PoxId::stubbed(),
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
        };

        let snapshot_without_sortition = BlockSnapshot {
            block_height: block_height - 1,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            sortition_id: SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
            parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]).unwrap(),
            consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]).unwrap(),
            ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]).unwrap(),
            total_burn: total_burn_no_sortition,
            sortition: false,
            sortition_hash: SortitionHash::initial(),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
            index_root: TrieHash([2u8; 32]),
            num_sortitions: 0,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            pox_id: PoxId::stubbed(),
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
        };

        let mut db = SortitionDB::connect_test(block_height - 2, &first_burn_hash).unwrap();

        let chain_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();

        let initial_snapshot = {
            let ic = db.index_handle(&chain_tip.sortition_id);
            ic.get_last_snapshot_with_sortition(block_height - 2).unwrap()
        };

        first_snapshot.index_root = initial_snapshot.index_root.clone();
        first_snapshot.burn_header_timestamp = initial_snapshot.burn_header_timestamp;
        assert_eq!(initial_snapshot, first_snapshot);

        {
            let chain_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
            let mut tx = SortitionHandleTx::begin(&mut db, &chain_tip.sortition_id).unwrap();

            tx.append_chain_tip_snapshot(&chain_tip, &snapshot_without_sortition, &vec![], &vec![]).unwrap();
            tx.commit().unwrap();
        }
        
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();

        let mut next_snapshot = {
            let ic = db.index_handle(&chain_tip.sortition_id);
            ic.get_last_snapshot_with_sortition(block_height - 1).unwrap()
        };

        next_snapshot.index_root = initial_snapshot.index_root.clone();
        next_snapshot.burn_header_timestamp = initial_snapshot.burn_header_timestamp;
        assert_eq!(initial_snapshot, next_snapshot);

        {
            let chain_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
            let mut tx = SortitionHandleTx::begin(&mut db, &chain_tip.sortition_id).unwrap();

            tx.append_chain_tip_snapshot(&chain_tip, &snapshot_with_sortition, &vec![], &vec![]).unwrap();
            tx.commit().unwrap();
        }
        
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();

        let next_snapshot_2 = {
            let ic = db.index_handle(&chain_tip.sortition_id);
            ic.get_last_snapshot_with_sortition(block_height).unwrap()
        };

        snapshot_with_sortition.index_root = next_snapshot_2.index_root.clone();
        snapshot_with_sortition.burn_header_timestamp = next_snapshot_2.burn_header_timestamp;
        assert_eq!(snapshot_with_sortition, next_snapshot_2);
    }

    /// Verify that the snapshots in a fork are well-formed -- i.e. the block heights are
    /// sequential and the parent block hash of the ith block is equal to the block hash of the
    /// (i-1)th block.
    fn verify_fork_integrity(db: &mut SortitionDB, tip: &SortitionId) {
        let mut child = SortitionDB::get_block_snapshot(db.conn(), tip).unwrap().unwrap();

        let initial = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
       
        test_debug!("Verify from {},hash={},parent={} back to {},hash={},parent={}",
                    child.block_height, child.burn_header_hash, child.parent_burn_header_hash,
                    initial.block_height, initial.burn_header_hash, initial.parent_burn_header_hash);

        while child.block_height > initial.block_height {
            let parent = {
                let ic = db.index_conn();
                SortitionDB::get_ancestor_snapshot(&ic, child.block_height - 1, &child.sortition_id).unwrap().unwrap()
            };

            test_debug!("Verify {} == {} - 1 and hash={},parent_hash={} == parent={}",
                        parent.block_height, child.block_height,
                        child.burn_header_hash, parent.burn_header_hash, child.parent_burn_header_hash);

            assert_eq!(parent.block_height, child.block_height - 1);
            assert_eq!(parent.burn_header_hash, child.parent_burn_header_hash);

            child = parent.clone();
        }

        assert_eq!(child, initial);
    }

    #[test]
    fn test_chain_reorg() {
        // Create a set of forks that looks like this:
        // 0-1-2-3-4-5-6-7-8-9 (fork 0)
        //  \
        //   1-2-3-4-5-6-7-8-9 (fork 1)
        //    \
        //     2-3-4-5-6-7-8-9 (fork 2)
        //      \
        //       3-4-5-6-7-8-9 (fork 3)
        //
        //    ...etc...
        //
        // Then, append a block to fork 9, and confirm that it switches places with fork 0.
        // Append 2 blocks to fork 8, and confirm that it switches places with fork 0.
        // Append 3 blocks to fork 7, and confirm that it switches places with fork 0.
        // ... etc.
        //
        let first_burn_hash = BurnchainHeaderHash([0x00; 32]);
        let first_block_height = 100;

        let mut db = SortitionDB::connect_test(first_block_height, &first_burn_hash).unwrap();

        // make an initial fork
        let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();

        for i in 0..10 {
            let mut next_snapshot = last_snapshot.clone();

            next_snapshot.block_height += 1;
            next_snapshot.num_sortitions += 1;
            next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
            next_snapshot.burn_header_hash = BurnchainHeaderHash([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i + 1]);
            next_snapshot.sortition_id = SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i + 1]);
            next_snapshot.consensus_hash = ConsensusHash([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i + 1]);
            
            let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
            tx.append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
            tx.commit().unwrap();

            last_snapshot = next_snapshot.clone();
        }
        
        test_debug!("----- make forks -----");

        // make other forks
        for i in 0..9 { 
            let parent_block_hash =
                if i == 0 {
                    [0u8; 32]
                }
                else {
                    let mut tmp = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(i+1) as u8];
                    tmp[i-1] = 1;
                    tmp
                };
            
            let parent_block = SortitionId(parent_block_hash);
            test_debug!("----- build fork off of parent {} (i = {}) -----", &parent_block, i);

            let mut last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &parent_block).unwrap().unwrap();

            let initial_block_height = last_snapshot.block_height;
            let initial_num_sortitions = last_snapshot.num_sortitions;

            let mut next_snapshot = last_snapshot.clone();

            for j in (i+1)..10 {
            
                let mut block_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(j+1) as u8];
                block_hash[i] = (j - i) as u8;

                next_snapshot.block_height = initial_block_height + (j - i) as u64;
                next_snapshot.num_sortitions = initial_num_sortitions + (j - i) as u64;
                next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
                next_snapshot.sortition_id = SortitionId(block_hash.clone());
                next_snapshot.burn_header_hash = BurnchainHeaderHash(block_hash);
                next_snapshot.consensus_hash = ConsensusHash([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,j as u8,(i + 1) as u8]);

                let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
                let next_index_root = tx.append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
                tx.commit().unwrap();

                next_snapshot.index_root = next_index_root;
                last_snapshot = next_snapshot.clone();
            }
        
            test_debug!("----- made fork {} (i = {}) -----", &next_snapshot.burn_header_hash, i);
        }

        test_debug!("----- grow forks -----");

        let mut all_chain_tips = vec![];

        // grow each fork so it overtakes the currently-canonical fork
        for i in 0..9 {
            let mut last_block_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10];
            last_block_hash[i] = (9 - i) as u8;
            let last_block = SortitionId(last_block_hash);
            
            test_debug!("----- grow fork {} (i = {}) -----", &last_block, i);

            let mut last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &last_block).unwrap().unwrap();
           
            let initial_block_height = last_snapshot.block_height;
            let mut next_snapshot = last_snapshot.clone();

            // grow the fork up to the length of the previous fork
            for j in 0..((i+1) as u64) {
                next_snapshot = last_snapshot.clone();

                let mut next_block_hash_vec = last_snapshot.burn_header_hash.as_bytes().to_vec();
                next_block_hash_vec[0] += 1;
                let mut next_block_hash = [0u8; 32];
                next_block_hash.copy_from_slice(&next_block_hash_vec[..]);

                next_snapshot.block_height = last_snapshot.block_height + 1;
                next_snapshot.num_sortitions = last_snapshot.num_sortitions + 1;
                next_snapshot.parent_burn_header_hash = last_snapshot.burn_header_hash.clone();
                next_snapshot.sortition_id = SortitionId(next_block_hash.clone());
                next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);
                next_snapshot.consensus_hash = ConsensusHash([2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,j as u8,(i + 1) as u8]);

                let next_index_root = {
                    let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
                    let next_index_root = tx.append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
                    tx.commit().unwrap();
                    next_index_root
                };

                last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &next_snapshot.sortition_id).unwrap().unwrap();
            }

            // make the fork exceed the canonical chain tip 
            next_snapshot = last_snapshot.clone();

            let mut next_block_hash_vec = last_snapshot.burn_header_hash.as_bytes().to_vec();
            next_block_hash_vec[0] = 0xff;
            let mut next_block_hash = [0u8; 32];
            next_block_hash.copy_from_slice(&next_block_hash_vec[..]);

            next_snapshot.block_height += 1;
            next_snapshot.num_sortitions += 1;
            next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
            next_snapshot.sortition_id = SortitionId(next_block_hash.clone());
            next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);

            let next_index_root = {
                let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();
                let next_index_root = tx.append_chain_tip_snapshot(&last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
                tx.commit().unwrap();
                next_index_root
            };
            
            next_snapshot.index_root = next_index_root;

            let mut expected_tip = next_snapshot.clone();
            expected_tip.index_root = next_index_root;

            let canonical_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
            assert_eq!(canonical_tip, expected_tip);

            verify_fork_integrity(&mut db, &canonical_tip.sortition_id);
            all_chain_tips.push(canonical_tip.sortition_id.clone());
        }

        for tip_header_hash in all_chain_tips.iter() {
            verify_fork_integrity(&mut db, tip_header_hash);
        }
    }

    #[test]
    fn test_get_stacks_header_hashes() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();
        {
            let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
            let mut total_burn = 0;
            let mut total_sortitions = 0;
            for i in 0..256 {
                let snapshot_row = 
                    if i % 3 == 0 {
                        BlockSnapshot {
                            pox_id: PoxId::stubbed(),
                            block_height: i+1,
                            burn_header_timestamp: get_epoch_time_secs(),
                            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                            sortition_id: SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]),
                            parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[(if i == 0 { 0x10 } else { 0 }) as u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                            consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                            ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                            total_burn: total_burn,
                            sortition: false,
                            sortition_hash: SortitionHash([(i as u8); 32]),
                            winning_block_txid: Txid([(i as u8); 32]),
                            winning_stacks_block_hash: BlockHeaderHash([0u8; 32]),
                            index_root: TrieHash::from_empty_data(), 
                            num_sortitions: total_sortitions,
                            stacks_block_accepted: false,
                            stacks_block_height: 0,
                            arrival_index: 0,
                            canonical_stacks_tip_height: 0,
                            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
                        }
                    }
                    else {
                        total_burn += 1;
                        total_sortitions += 1;
                        BlockSnapshot {
                            pox_id: PoxId::stubbed(),
                            block_height: i+1,
                            burn_header_timestamp: get_epoch_time_secs(),
                            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                            sortition_id: SortitionId([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]),
                            parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[(if i == 0 { 0x10 } else { 0 }) as u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                            consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                            ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                            total_burn: total_burn,
                            sortition: true,
                            sortition_hash: SortitionHash([(i as u8); 32]),
                            winning_block_txid: Txid([(i as u8); 32]),
                            winning_stacks_block_hash: BlockHeaderHash([(i as u8); 32]),
                            index_root: TrieHash::from_empty_data(), 
                            num_sortitions: total_sortitions,
                            stacks_block_accepted: false,
                            stacks_block_height: 0,
                            arrival_index: 0,
                            canonical_stacks_tip_height: 0,
                            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
                        }
                    };

                // NOTE: we don't care about VRF keys or block commits here

                let mut tx = SortitionHandleTx::begin(&mut db, &last_snapshot.sortition_id).unwrap();

                let index_root = tx.append_chain_tip_snapshot(&last_snapshot, &snapshot_row, &vec![], &vec![]).unwrap();
                last_snapshot = snapshot_row;
                last_snapshot.index_root = index_root;

                // should succeed within the tx 
                let ch = tx.as_conn().get_consensus_at(i + 1).unwrap().unwrap_or(ConsensusHash::empty());
                assert_eq!(ch, last_snapshot.consensus_hash);

                tx.commit().unwrap();
            }
        }
        
        let canonical_tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        let mut cache = BlockHeaderCache::new();

        {
            let ic = db.index_conn();
            let hashes = ic.get_stacks_header_hashes(256, &canonical_tip.consensus_hash, Some(&cache)).unwrap();
            SortitionDB::merge_block_header_cache(&mut cache, &hashes);

            assert_eq!(hashes.len(), 256);
            for i in 0..256 {
                let (ref burn_hash, ref block_hash_opt) = &hashes[i];
                if i % 3 == 0 {
                    assert!(block_hash_opt.is_none());
                }
                else {
                    assert!(block_hash_opt.is_some());
                    let block_hash = block_hash_opt.unwrap();
                    assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
                }
                assert_eq!(*burn_hash, BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap());

                if i > 0 {
                    assert!(cache.contains_key(burn_hash));
                    assert_eq!(cache.get(burn_hash).unwrap().0, *block_hash_opt);
                }
            }
        }

        {
            let ic = db.index_conn();
            let hashes = ic.get_stacks_header_hashes(256, &canonical_tip.consensus_hash, None).unwrap();
            SortitionDB::merge_block_header_cache(&mut cache, &hashes);

            let cached_hashes = ic.get_stacks_header_hashes(256, &canonical_tip.consensus_hash, Some(&cache)).unwrap();

            assert_eq!(hashes.len(), 256);
            assert_eq!(cached_hashes.len(), 256);
            for i in 0..256 {
                assert_eq!(cached_hashes[i], hashes[i]);
                let (ref burn_hash, ref block_hash_opt) = &hashes[i];
                if i % 3 == 0 {
                    assert!(block_hash_opt.is_none());
                }
                else {
                    assert!(block_hash_opt.is_some());
                    let block_hash = block_hash_opt.unwrap();
                    assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
                }
                assert_eq!(*burn_hash, BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap());
                
                if i > 0 {
                    assert!(cache.contains_key(burn_hash));
                    assert_eq!(cache.get(burn_hash).unwrap().0, *block_hash_opt);
                }
            }
        }

        {
            let ic = db.index_conn();
            let hashes = ic.get_stacks_header_hashes(192, &canonical_tip.consensus_hash, None).unwrap();
            SortitionDB::merge_block_header_cache(&mut cache, &hashes);

            let cached_hashes = ic.get_stacks_header_hashes(192, &canonical_tip.consensus_hash, Some(&cache)).unwrap();

            assert_eq!(hashes.len(), 192);
            assert_eq!(cached_hashes.len(), 192);
            for i in 64..256 {
                assert_eq!(cached_hashes[i-64], hashes[i-64]);
                let (ref burn_hash, ref block_hash_opt) = &hashes[i - 64];
                if i % 3 == 0 {
                    assert!(block_hash_opt.is_none());
                }
                else {
                    assert!(block_hash_opt.is_some());
                    let block_hash = block_hash_opt.unwrap();
                    assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
                }
                assert_eq!(*burn_hash, BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap());
                
                assert!(cache.contains_key(burn_hash));
                assert_eq!(cache.get(burn_hash).unwrap().0, *block_hash_opt);
            }
        }
        
        {
            let ic = db.index_conn();
            let hashes = ic.get_stacks_header_hashes(257, &canonical_tip.consensus_hash, None).unwrap();
            SortitionDB::merge_block_header_cache(&mut cache, &hashes);

            let cached_hashes = ic.get_stacks_header_hashes(257, &canonical_tip.consensus_hash, Some(&cache)).unwrap();

            assert_eq!(hashes.len(), 256);
            assert_eq!(cached_hashes.len(), 256);
            for i in 0..256 {
                assert_eq!(cached_hashes[i], hashes[i]);
                let (ref burn_hash, ref block_hash_opt) = &hashes[i];
                if i % 3 == 0 {
                    assert!(block_hash_opt.is_none());
                }
                else {
                    assert!(block_hash_opt.is_some());
                    let block_hash = block_hash_opt.unwrap();
                    assert_eq!(block_hash, BlockHeaderHash([(i as u8); 32]));
                }
                assert_eq!(*burn_hash, BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap());
                
                if i > 0 {
                    assert!(cache.contains_key(burn_hash));
                    assert_eq!(cache.get(burn_hash).unwrap().0, *block_hash_opt);
                }
            }
        }
        
        {
            let ic = db.index_conn();
            let err = ic.get_stacks_header_hashes(256, &ConsensusHash([0x03; 20]), None).unwrap_err();
            match err {
                db_error::NotFoundError => {},
                _ => {
                    eprintln!("Got wrong error: {:?}", &err);
                    assert!(false);
                    unreachable!();
                }
            }
            
            let err = ic.get_stacks_header_hashes(256, &ConsensusHash([0x03; 20]), Some(&cache)).unwrap_err();
            match err {
                db_error::NotFoundError => {},
                _ => {
                    eprintln!("Got wrong error: {:?}", &err);
                    assert!(false);
                    unreachable!();
                }
            }
        }
    }

    fn make_fork_run(db: &mut SortitionDB, start_snapshot: &BlockSnapshot, length: u64, bit_pattern: u8) -> () {
        let mut last_snapshot = start_snapshot.clone();
        for i in last_snapshot.block_height..(last_snapshot.block_height + length) {
            let snapshot = BlockSnapshot {
                pox_id: PoxId::stubbed(),
                block_height: last_snapshot.block_height + 1,
                burn_header_timestamp: get_epoch_time_secs(),
                burn_header_hash: BurnchainHeaderHash([(i as u8) | bit_pattern; 32]),
                sortition_id: SortitionId([(i as u8) | bit_pattern; 32]),
                parent_burn_header_hash: last_snapshot.burn_header_hash.clone(),
                consensus_hash: ConsensusHash([(i as u8) | bit_pattern; 20]),
                ops_hash: OpsHash([(i as u8) | bit_pattern; 32]),
                total_burn: 0,
                sortition: true,
                sortition_hash: SortitionHash([(i as u8) | bit_pattern; 32]),
                winning_block_txid: Txid([(i as u8) | bit_pattern; 32]),
                winning_stacks_block_hash: BlockHeaderHash([(i as u8) | bit_pattern; 32]),
                index_root: TrieHash([0u8; 32]),
                num_sortitions: last_snapshot.num_sortitions + 1,
                stacks_block_accepted: false,
                stacks_block_height: 0,
                arrival_index: 0,
                canonical_stacks_tip_height: 0,
                canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
            };
            {
                let mut tx = SortitionHandleTx::begin(db, &last_snapshot.sortition_id).unwrap();
                let _index_root = tx.append_chain_tip_snapshot(&last_snapshot, &snapshot, &vec![], &vec![]).unwrap();
                tx.commit().unwrap();
            }
            last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &snapshot.sortition_id).unwrap().unwrap();
        }
    }

    #[test]
    fn test_set_stacks_block_accepted() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = SortitionDB::connect_test(0, &first_burn_hash).unwrap();

        let mut last_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();

        // seed a single fork
        make_fork_run(&mut db, &last_snapshot, 5, 0);

        // set some blocks as processed
        for i in 0..5 {
            let burn_header_hash = BurnchainHeaderHash([i as u8; 32]);
            let parent_stacks_block_hash = 
                if i == 0 {
                    FIRST_STACKS_BLOCK_HASH.clone()
                }
                else {
                    BlockHeaderHash([(i - 1) as u8; 32])
                };

            let stacks_block_hash = BlockHeaderHash([i as u8; 32]);
            let height = i;

            {
                let mut tx = db.tx_begin().unwrap();
                tx.set_stacks_block_accepted_stubbed(
                    &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, height).unwrap();
                tx.commit().unwrap();
            }

            // chain tip is memoized to the current burn chain tip
            let (burn_bhh, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash_stubbed(db.conn()).unwrap();
            assert_eq!(burn_bhh, burn_header_hash);
            assert_eq!(block_bhh, stacks_block_hash);
        }

        // materialize all block arrivals in the MARF
        last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x04; 32])).unwrap().unwrap();
        make_fork_run(&mut db, &last_snapshot, 1, 0);

        // verify that all Stacks block in this fork can be looked up from this chain tip
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        {
            let ic = db.index_conn();
            for i in 0..5 {
                let parent_stacks_block_hash = BlockHeaderHash([i as u8; 32]);
                let parent_key = db_keys::stacks_block_index(&parent_stacks_block_hash);

                test_debug!("Look up '{}' off of {}", &parent_key, &last_snapshot.burn_header_hash);
                let value_opt = ic.get_indexed(&last_snapshot.sortition_id, &parent_key).unwrap();
                assert!(value_opt.is_some());
                assert_eq!(value_opt.unwrap(), format!("{}", i));
            }
        }

        // make a burn fork off of the 5th block
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        make_fork_run(&mut db, &last_snapshot, 5, 0x80);

        // chain tip is _still_ memoized to the last materialized chain tip
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x8a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x04; 32]));

        // accept blocks 5 and 7 in one fork, and 6, 8, 9 in another.
        // Stacks fork 1,2,3,4,5,7 will be the longest fork.
        // Stacks fork 1,2,3,4 will overtake it when blocks 6,8,9 are processed.
        let mut parent_stacks_block_hash = BlockHeaderHash([0x04; 32]);
        for (i, height) in [5, 7].iter().zip([5, 6].iter()) {
            let burn_header_hash = BurnchainHeaderHash([(i | 0x80) as u8; 32]);
            let stacks_block_hash = BlockHeaderHash([(i | 0x80) as u8; 32]);
                
            {
                let mut tx = db.tx_begin().unwrap();
                tx.set_stacks_block_accepted_stubbed(
                    &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, *height).unwrap();
                tx.commit().unwrap();
            }

            // chain tip is memoized to the current burn chain tip, since it's the longest stacks fork
            let (burn_bhh, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash_stubbed(db.conn()).unwrap();
            assert_eq!(burn_bhh, burn_header_hash);
            assert_eq!(block_bhh, stacks_block_hash);

            parent_stacks_block_hash = stacks_block_hash;
        }

        // chain tip is _still_ memoized to the last materialized chain tip (i.e. stacks block 7)
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x8a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x87; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x87; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 6);
        
        // when the blocks for burn blocks 6 and 8 arrive, the canonical fork is still at stacks
        // block 7.  The two stacks forks will be:
        // * 1,2,3,4,5,7
        // * 1,2,3,4,6,8
        parent_stacks_block_hash = BlockHeaderHash([4u8; 32]);
        for (i, height) in [6, 8].iter().zip([5, 6].iter()) {
            let burn_header_hash = BurnchainHeaderHash([(i | 0x80) as u8; 32]);
            let stacks_block_hash = BlockHeaderHash([(i | 0x80) as u8; 32]);
                
            {
                let mut tx = db.tx_begin().unwrap();
                tx.set_stacks_block_accepted_stubbed(
                    &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, *height).unwrap();
                tx.commit().unwrap();
            }

            // chain tip is memoized to the current burn chain tip, since it's the longest stacks fork
            let (burn_bhh, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash_stubbed(db.conn()).unwrap();
            assert_eq!(burn_bhh, last_snapshot.canonical_stacks_tip_burn_hash);
            assert_eq!(block_bhh, last_snapshot.canonical_stacks_tip_hash);
            
            parent_stacks_block_hash = stacks_block_hash;
        }

        // when the block for burn block 9 arrives, the canonical stacks fork will be
        // 1,2,3,4,6,8,9.  It overtakes 1,2,3,4,5,7
        for (i, height) in [9].iter().zip([7].iter()) {
            let burn_header_hash = BurnchainHeaderHash([(i | 0x80) as u8; 32]);
            let stacks_block_hash = BlockHeaderHash([(i | 0x80) as u8; 32]);
                
            {
                let mut tx = db.tx_begin().unwrap();
                tx.set_stacks_block_accepted_stubbed(
                    &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, *height).unwrap();
                tx.commit().unwrap();
            }

            // we've overtaken the longest fork with a different longest fork on this burn chain fork
            let (burn_bhh, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash_stubbed(db.conn()).unwrap();
            assert_eq!(burn_bhh, burn_header_hash);
            assert_eq!(block_bhh, stacks_block_hash);
        }
        
        // canonical stacks chain tip is now stacks block 9
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x8a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x89; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x89; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 7);

        // fork the burn chain at 0x4, producing a longer burnchain fork.  There are now two
        // burnchain forks, where the first one has two stacks forks:
        // stx:      1,    2,    3,    4,          6,          8,    9
        // stx:      1,    2,    3,    4,    5,          7,
        // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
        //
        // stx:      1,    2,    3,    4
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
        last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x04; 32])).unwrap().unwrap();
        make_fork_run(&mut db, &last_snapshot, 7, 0x40);

        // canonical stacks chain tip is now stacks block 4, since the burn chain fork ending on
        // 0x4b has overtaken the burn chain fork ending on 0x8a
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 4);

        // set the stacks block at 0x4b as accepted as the 5th block
        {
            let mut tx = db.tx_begin().unwrap();
            tx.set_stacks_block_accepted_stubbed(
                &BurnchainHeaderHash([0x4b; 32]), &BlockHeaderHash([0x04; 32]), &BlockHeaderHash([0x4b; 32]), 5).unwrap();
            tx.commit().unwrap();
        }
        
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);

        // fork the burn chain at 0x48, producing a shorter burnchain fork.  There are now three
        // burnchain forks:
        // stx:      1,    2,    3,    4,          6,          8,    9
        // stx:      1,    2,    3,    4,    5,          7,
        // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
        //
        // stx:      1,    2,    3,    4,                                        5
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
        //
        // stx:      1,    2,    3,    4,
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a
        last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x48; 32])).unwrap().unwrap();
        make_fork_run(&mut db, &last_snapshot, 2, 0x20);

        last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x2a; 32])).unwrap().unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 4);
        
        // doesn't affect canonical chain tip
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);
        
        // set the stacks block at 0x29 and 0x2a as accepted as the 5th and 6th blocks
        {
            let mut tx = db.tx_begin().unwrap();
            let tip_snapshot = SortitionDB::get_block_snapshot(&tx, &SortitionId([0x2a; 32])).unwrap().unwrap();
            tx.set_stacks_block_accepted_at_tip(&tip_snapshot,
                &BurnchainHeaderHash([0x29; 32]), &BlockHeaderHash([0x04; 32]), &BlockHeaderHash([0x29; 32]), 5).unwrap();
            tx.set_stacks_block_accepted_at_tip(&tip_snapshot,
                &BurnchainHeaderHash([0x2a; 32]), &BlockHeaderHash([0x29; 32]), &BlockHeaderHash([0x2a; 32]), 6).unwrap();
            tx.commit().unwrap();
        }

        // new state of the world:
        // burnchain forks:
        // stx:      1,    2,    3,    4,          6,          8,    9
        // stx:      1,    2,    3,    4,    5,          7,
        // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
        //
        // stx:      1,    2,    3,    4,                                        5
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
        //
        // stx:      1,    2,    3,    4,                            5,    6
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a
        
        // canonical stacks chain off of non-canonical burn chain fork 0x2a should have been updated
        last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x2a; 32])).unwrap().unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 6);

        // insertion on the non-canonical tip doesn't affect canonical chain tip
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);

        // insert stacks blocks #6, #7, #8, #9 off of the burn chain tip starting at 0x4b (i.e. the
        // canonical burn chain tip), on blocks 0x45, 0x46, and 0x47
        {
            let mut tx = db.tx_begin().unwrap();
            tx.set_stacks_block_accepted_stubbed(
                &BurnchainHeaderHash([0x45; 32]), &BlockHeaderHash([0x04; 32]), &BlockHeaderHash([0x45; 32]), 5).unwrap();
            tx.set_stacks_block_accepted_stubbed(
                &BurnchainHeaderHash([0x46; 32]), &BlockHeaderHash([0x45; 32]), &BlockHeaderHash([0x46; 32]), 6).unwrap();
            tx.set_stacks_block_accepted_stubbed(
                &BurnchainHeaderHash([0x47; 32]), &BlockHeaderHash([0x46; 32]), &BlockHeaderHash([0x47; 32]), 7).unwrap();
            tx.set_stacks_block_accepted_stubbed(
                &BurnchainHeaderHash([0x48; 32]), &BlockHeaderHash([0x47; 32]), &BlockHeaderHash([0x48; 32]), 8).unwrap();
            tx.commit().unwrap();
        }
        
        // new state of the world:
        // burnchain forks:
        // stx:      1,    2,    3,    4,          6,          8,    9
        // stx:      1,    2,    3,    4,    5,          7,
        // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
        //
        // stx:      1,    2,    3,    4,    6,    7,    8,   9
        // stx:      1,    2,    3,    4,                                        5
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
        //
        // stx:      1,    2,    3,    4,                            5,    6
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a

        // new stacks tip is the 9th block added on burn chain tipped by 0x4b
        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 8);

        // LIMITATION: the burn chain tipped at 0x2a will _not_ be updated, since it is not the
        // canonical burn chain tip.
        last_snapshot = SortitionDB::get_block_snapshot(db.conn(), &SortitionId([0x2a; 32])).unwrap().unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 6);

        // BUT, when the burn chain tipped by 0x2a overtakes the one tipped by 0x4b, then all blocks
        // will show up.
        make_fork_run(&mut db, &last_snapshot, 2, 0x20);

        // new state of the world:
        // burnchain forks:
        // stx:      1,    2,    3,    4,          6,          8,    9
        // stx:      1,    2,    3,    4,    5,          7,
        // burn:  0x01, 0x02, 0x03, 0x04, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a
        //
        // stx:      1,    2,    3,    4,    6,    7,    8,    9
        // stx:      1,    2,    3,    4,                                        5
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b
        //
        // stx:      1,    2,    3,    4,    7,    8,    9,   10
        // stx:      1,    2,    3,    4,                            5,    6
        // burn:  0x01, 0x02, 0x03, 0x04, 0x45, 0x46, 0x47, 0x48, 0x29, 0x2a, 0x2b, 0x2c

        last_snapshot = SortitionDB::get_canonical_burn_chain_tip_stubbed(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x2c; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 8);
    }
}
