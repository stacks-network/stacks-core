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

use std::fs;
use std::io;
use std::convert::From;
use std::ops::Deref;
use std::ops::DerefMut;

use util::db::{FromRow, FromColumn, u64_to_sql, query_rows, query_row, query_row_columns, query_count, IndexDBTx, IndexDBConn, db_mkdirs};
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
    BurnchainTransaction
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
            canonical_stacks_tip_burn_hash: canonical_stacks_tip_burn_hash
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

        PRIMARY KEY(burn_header_hash)
    );"#,
    r#"
    CREATE UNIQUE INDEX snapshots_block_hashes ON snapshots(block_height,index_root,winning_stacks_block_hash);
    CREATE UNIQUE INDEX snapshots_block_stacks_hashes ON snapshots(num_sortitions,index_root,winning_stacks_block_hash);
    CREATE INDEX block_arrivals ON snapshots(arrival_index,burn_header_hash);
    "#,
    r#"
    -- all leader keys registered in the blockchain.
    -- contains pointers to the burn block and fork in which they occur
    CREATE TABLE leader_keys(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        memo TEXT,
        address TEXT NOT NULL,

        PRIMARY KEY(txid,burn_header_hash),
        FOREIGN KEY(burn_header_hash) REFERENCES snapshots(burn_header_hash)
    );"#,
    r#"
    CREATE TABLE block_commits(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        block_header_hash TEXT NOT NULL,
        new_seed TEXT NOT NULL,
        parent_block_ptr INTEGER NOT NULL,
        parent_vtxindex INTEGER NOT NULL,
        key_block_ptr INTEGER NOT NULL,
        key_vtxindex INTEGER NOT NULL,
        memo TEXT,
        
        burn_fee TEXT NOT NULL,     -- use text to encode really big numbers
        input TEXT NOT NULL,        -- must match `address` in leader_keys

        PRIMARY KEY(txid,burn_header_hash),
        FOREIGN KEY(burn_header_hash) REFERENCES snapshots(burn_header_hash)
    );"#,
    r#"
    CREATE TABLE user_burn_support(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        address TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        key_block_ptr INTEGER NOT NULL,
        key_vtxindex INTEGER NOT NULL,
        block_header_hash_160 TEXT NOT NULL,

        burn_fee TEXT NOT NULL,

        PRIMARY KEY(txid,burn_header_hash),
        FOREIGN KEY(burn_header_hash) REFERENCES snapshots(burn_header_hash)
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

pub struct BurnDB {
    pub conn: Connection,
    pub readwrite: bool,
    pub marf: MARF<BurnchainHeaderHash>,
    pub first_block_height: u64,
    pub first_burn_header_hash: BurnchainHeaderHash,
}

#[derive(Clone)]
pub struct BurnDBTxContext {
    pub first_block_height: u64,
}

pub type BurnDBTx<'a> = IndexDBTx<'a, BurnDBTxContext, BurnchainHeaderHash>;
pub type BurnDBConn<'a> = IndexDBConn<'a, BurnDBTxContext, BurnchainHeaderHash>;

fn burndb_get_ancestor_block_hash<'a>(iconn: &BurnDBConn<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<BurnchainHeaderHash>, db_error> {
    if block_height < iconn.context.first_block_height {
        return Ok(None);
    }
    
    let first_block_height = iconn.context.first_block_height;
    match iconn.get_ancestor_block_hash(block_height - first_block_height, &tip_block_hash)? {
        Some(bhh) => {
            Ok(Some(BurnchainHeaderHash::from(bhh)))
        },
        None => {
            Ok(None)
        }
    }
}

impl BurnDB {
    fn instantiate(conn: &mut Connection, index_path: &str, first_block_height: u64, first_burn_header_hash: &BurnchainHeaderHash, first_burn_header_timestamp: u64) -> Result<(), db_error> {
        let tx = tx_begin_immediate(conn)?;

        // create first (sentinel) snapshot
        let mut first_snapshot = BlockSnapshot::initial(first_block_height, first_burn_header_hash, first_burn_header_timestamp);
        
        assert!(first_snapshot.parent_burn_header_hash != first_snapshot.burn_header_hash);
        assert_eq!(first_snapshot.parent_burn_header_hash, BurnchainHeaderHash::sentinel());

        for row_text in BURNDB_SETUP {
            tx.execute(row_text, NO_PARAMS).map_err(db_error::SqliteError)?;
        }

        tx.execute("INSERT INTO db_config (version) VALUES (?1)", &[&CHAINSTATE_VERSION]).map_err(db_error::SqliteError)?;
        
        let mut marf = BurnDB::open_index(index_path)?;
        let mut burndbtx = BurnDBTx::new(tx, &mut marf, BurnDBTxContext { first_block_height: first_block_height });
        
        burndbtx.instantiate_index()?;

        let mut first_sn = first_snapshot.clone();
        let index_root = BurnDB::index_add_fork_info(&mut burndbtx, &mut first_sn, &first_snapshot, &vec![], &vec![])?;
        first_snapshot.index_root = index_root;

        let snapshot_args : &[&dyn ToSql] = &[
            &u64_to_sql(first_snapshot.block_height)?,
            &first_snapshot.burn_header_hash,
            &u64_to_sql(first_snapshot.burn_header_timestamp)?,
            &first_snapshot.parent_burn_header_hash,
            &first_snapshot.consensus_hash,
            &first_snapshot.ops_hash,
            &"0".to_string(),
            &first_snapshot.sortition,
            &first_snapshot.sortition_hash,
            &first_snapshot.winning_block_txid,
            &first_snapshot.winning_stacks_block_hash,
            &first_snapshot.index_root, 
            &u64_to_sql(first_snapshot.num_sortitions)?,
            &false,
            &0,
            &0,
            &0,
            &FIRST_STACKS_BLOCK_HASH,
            &FIRST_BURNCHAIN_BLOCK_HASH,
        ];

        burndbtx.tx_mut().execute("INSERT INTO snapshots (
                                block_height,
                                burn_header_hash,
                                burn_header_timestamp,
                                parent_burn_header_hash,
                                consensus_hash,
                                ops_hash,
                                total_burn,
                                sortition,
                                sortition_hash,
                                winning_block_txid,
                                winning_stacks_block_hash,
                                index_root,
                                num_sortitions,
                                stacks_block_accepted,
                                stacks_block_height,
                                arrival_index,
                                canonical_stacks_tip_height,
                                canonical_stacks_tip_hash,
                                canonical_stacks_tip_burn_hash
                    )
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                   snapshot_args)
            .map_err(db_error::SqliteError)?;
       
        burndbtx.commit()?;
        Ok(())
    }

    /// Open the burn database at the given path.  Open read-only or read/write.
    /// If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(path: &String, first_block_height: u64, first_burn_hash: &BurnchainHeaderHash, first_burn_header_timestamp: u64, readwrite: bool) -> Result<BurnDB, db_error> {
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
        debug!("Connect/Open burndb '{}' as '{}', with index as '{}'",
               db_path, if readwrite { "readwrite" } else { "readonly" }, index_path);

        let mut conn = Connection::open_with_flags(&db_path, open_flags).map_err(db_error::SqliteError)?;
        conn.busy_handler(Some(tx_busy_handler)).map_err(db_error::SqliteError)?;

        if create_flag {
            // instantiate!
            BurnDB::instantiate(&mut conn, &index_path, first_block_height, first_burn_hash, first_burn_header_timestamp)?;
        }
        else {
            // validate -- must contain the given first block and first block hash 
            let snapshot_opt = BurnDB::get_block_snapshot(&conn, first_burn_hash)?;
            match snapshot_opt {
                None => {
                    error!("No snapshot for block {}", first_block_height);
                    return Err(db_error::Corruption);
                },
                Some(snapshot) => {
                    if !snapshot.is_initial() || snapshot.block_height != first_block_height || snapshot.burn_header_hash != *first_burn_hash {
                       error!("Invalid genesis snapshot at {}", first_block_height);
                       return Err(db_error::Corruption);
                    }
                }
            };
        }

        let marf = BurnDB::open_index(&index_path)?;

        let db = BurnDB {
            conn: conn,
            marf: marf,
            readwrite: readwrite,
            first_block_height: first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
        };

        Ok(db)
    }

    /// Open a burn database in memory (used for testing)
    #[cfg(test)]
    pub fn connect_test(first_block_height: u64, first_burn_hash: &BurnchainHeaderHash) -> Result<BurnDB, db_error> { 
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let db_path_dir = format!("/tmp/test-blockstack-burndb-{}", to_hex(&buf));
        let (db_path, index_path) = db_mkdirs(&db_path_dir)?;

        debug!("Open {}", &db_path);
        let mut conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE).map_err(db_error::SqliteError)?;
        conn.busy_handler(Some(tx_busy_handler)).map_err(db_error::SqliteError)?;

        BurnDB::instantiate(&mut conn, &index_path, first_block_height, first_burn_hash, get_epoch_time_secs())?;

        let marf = BurnDB::open_index(&index_path)?;

        let db = BurnDB {
            conn: conn,
            marf: marf,
            readwrite: true,
            first_block_height: first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
        };
        
        Ok(db)
    }

    /// Open the database on disk.  It must already exist and be instantiated.
    /// It's best not to call this if you are able to call connect().  If you must call this, do so
    /// after you call connect() somewhere else, since connect() performs additional validations.
    pub fn open(path: &str, readwrite: bool) -> Result<BurnDB, db_error> {
        let open_flags =
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            }
            else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            };

        let (db_path, index_path) = db_mkdirs(path)?;
        debug!("Open burndb '{}' as '{}', with index as '{}'",
               db_path, if readwrite { "readwrite" } else { "readonly" }, index_path);
        
        let conn = Connection::open_with_flags(&db_path, open_flags).map_err(db_error::SqliteError)?;
        conn.busy_handler(Some(tx_busy_handler)).map_err(db_error::SqliteError)?;

        let marf = BurnDB::open_index(&index_path)?;
        let first_snapshot = BurnDB::get_first_block_snapshot(&conn)?;

        let db = BurnDB {
            conn: conn,
            marf: marf,
            readwrite: readwrite,
            first_block_height: first_snapshot.block_height,
            first_burn_header_hash: first_snapshot.burn_header_hash.clone(),
        };
        Ok(db)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn open_index(index_path: &str) -> Result<MARF<BurnchainHeaderHash>, db_error> {
        test_debug!("Open index at {}", index_path);
        let marf = MARF::from_path(index_path, None).map_err(|_e| db_error::Corruption)?;
        Ok(marf)
    }

    /// Insert a snapshots row from a block's-worth of operations. 
    /// Do not call directly -- use append_chain_tip_snapshot to preserve the fork table structure.
    fn insert_block_snapshot<'a>(tx: &mut BurnDBTx<'a>, snapshot: &BlockSnapshot) -> Result<(), db_error> {
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
        ];

        tx.execute("INSERT INTO snapshots \
                   (block_height, burn_header_hash, burn_header_timestamp, parent_burn_header_hash, consensus_hash, ops_hash, total_burn, sortition, sortition_hash, winning_block_txid, winning_stacks_block_hash, index_root, num_sortitions, \
                   stacks_block_accepted, stacks_block_height, arrival_index, canonical_stacks_tip_height, canonical_stacks_tip_hash, canonical_stacks_tip_burn_hash) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)", args)
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Get the current arrival index.
    fn get_arrival_index(conn: &Connection) -> Result<u64, db_error> {
        match query_row::<BlockSnapshot, _>(conn, "SELECT * FROM snapshots ORDER BY arrival_index DESC LIMIT 1", NO_PARAMS)? {
            Some(sn) => Ok(sn.arrival_index),
            None => Ok(0)
        }
    }

    /// MARF index key for a processed stacks block.  Maps to its height.
    fn make_stacks_block_index_key(stacks_block_hash: &BlockHeaderHash) -> String {
        format!("burndb::stacks::block::{}", stacks_block_hash)
    }

    /// MARF index value for a processed stacks block
    fn make_stacks_block_index_value(height: u64) -> String {
        format!("{}", height)
    }

    /// MARF index key for the highest arrival index processed in a fork
    fn make_stacks_block_max_arrival_index_key() -> String {
        "burndb::stacks::block::max_arrival_index".to_string()
    }

    /// MARF index value for the highest arrival index processed in a fork
    fn make_stacks_block_max_arrival_index_value(index: u64) -> String {
        format!("{}", index)
    }

    /// Add an accepted Stacks block to the canonical accepted stacks header table, to indicate
    /// that it will be committed to by the next burn block added to the canonical chain tip.  Used
    /// to identify Stacks blocks that get accepted in the mean time, so we can ensure that the
    /// canonical burn chain tip always points to the canonical stacks chain tip.
    fn insert_accepted_stacks_block_pointer<'a>(tx: &mut BurnDBTx<'a>, tip_burn_header_hash: &BurnchainHeaderHash, burn_header_hash: &BurnchainHeaderHash, stacks_block_hash: &BlockHeaderHash, stacks_block_height: u64) -> Result<(), db_error> {
        let args: &[&dyn ToSql] = &[tip_burn_header_hash, burn_header_hash, stacks_block_hash, &u64_to_sql(stacks_block_height)?];
        tx.execute("INSERT OR REPLACE INTO canonical_accepted_stacks_blocks (tip_burn_block_hash, burn_block_hash, stacks_block_hash, block_height) VALUES (?1, ?2, ?3, ?4)", args)
            .map_err(db_error::SqliteError)?;
        Ok(())
    }

    /// Get an accepted stacks block header in a fork whose chain tip has not yet committed
    /// to it.
    fn get_accepted_stacks_block_pointer(conn: &Connection, tip_burn_header_hash: &BurnchainHeaderHash, stacks_block_hash: &BlockHeaderHash) -> Result<Option<AcceptedStacksBlockHeader>, db_error> {
        let args : &[&dyn ToSql] = &[tip_burn_header_hash, stacks_block_hash];
        let mut rows = query_rows(conn, "SELECT * FROM canonical_accepted_stacks_blocks WHERE tip_burn_block_hash = ?1 AND stacks_block_hash = ?2", args)?;
        let len = rows.len();
        match len {
            0 => Ok(None),
            1 => Ok(rows.pop()),
            _ => {
                panic!("BUG: the same Stacks block {} shows up twice or more in the same burn chain fork (whose tip is {})", stacks_block_hash, tip_burn_header_hash);
            }
        }
    }

    /// Mark an existing snapshot's stacks block as accepted at a particular burn chain tip, and calculate and store its arrival index.
    /// If this Stacks block extends the canonical stacks chain tip, then also update the memoized canonical
    /// stacks chain tip metadata on the burn chain tip.
    fn set_stacks_block_accepted_at_tip<'a>(tx: &mut BurnDBTx<'a>, burn_tip: &BlockSnapshot, burn_header_hash: &BurnchainHeaderHash, parent_stacks_block_hash: &BlockHeaderHash, stacks_block_hash: &BlockHeaderHash, stacks_block_height: u64) -> Result<(), db_error> {
        let arrival_index = BurnDB::get_arrival_index(tx)?;
        let args : &[&dyn ToSql] = &[&u64_to_sql(stacks_block_height)?, &u64_to_sql(arrival_index + 1)?, burn_header_hash, stacks_block_hash];

        tx.execute("UPDATE snapshots SET stacks_block_accepted = 1, stacks_block_height = ?1, arrival_index = ?2 WHERE burn_header_hash = ?3 AND winning_stacks_block_hash = ?4", args)
            .map_err(db_error::SqliteError)?;

        let parent_key = BurnDB::make_stacks_block_index_key(parent_stacks_block_hash);

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
            let args : &[&dyn ToSql] = &[burn_header_hash, stacks_block_hash, &u64_to_sql(stacks_block_height)?, &burn_tip.burn_header_hash];
            tx.execute("UPDATE snapshots SET canonical_stacks_tip_burn_hash = ?1, canonical_stacks_tip_hash = ?2, canonical_stacks_tip_height = ?3
                        WHERE burn_header_hash = ?4", args)
                .map_err(db_error::SqliteError)?;
        
            BurnDB::insert_accepted_stacks_block_pointer(tx, &burn_tip.burn_header_hash, burn_header_hash, stacks_block_hash, stacks_block_height)?;
        }
        else {
            // see if this block builds off of a Stacks block mined on this burnchain fork
            let height_opt = match BurnDB::get_accepted_stacks_block_pointer(tx, &burn_tip.burn_header_hash, parent_stacks_block_hash)? {
                // this block builds on a block accepted _after_ this burn chain tip was processed?
                Some(accepted_header) => Some(accepted_header.height),
                None => match BurnDB::index_value_get(&tx.as_conn(), &burn_tip.burn_header_hash, &parent_key)? {
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
                        tx.execute("UPDATE snapshots SET canonical_stacks_tip_burn_hash = ?1, canonical_stacks_tip_hash = ?2, canonical_stacks_tip_height = ?3
                                    WHERE burn_header_hash = ?4", args)
                            .map_err(db_error::SqliteError)?;
                    }
                    else {
                        // This block was mined on this fork, but it's acceptance doesn't overtake
                        // the current stacks chain tip.  Remember it so that we can process its children,
                        // which might do so later.
                        debug!("Accepted Stacks block {}/{} builds on a non-canonical Stacks tip in this burnchain fork ({})", burn_header_hash, stacks_block_hash, &burn_tip.burn_header_hash);
                    }
                    BurnDB::insert_accepted_stacks_block_pointer(tx, &burn_tip.burn_header_hash, burn_header_hash, stacks_block_hash, stacks_block_height)?;
                },
                None => {
                    debug!("Accepted Stacks block {}/{} does NOT build on a Stacks tip in this burnchain fork ({}) -- no parent {} in this fork", 
                           burn_header_hash, stacks_block_hash, &burn_tip.burn_header_hash, parent_stacks_block_hash);
                }
            }
        }
        Ok(())
    }
    
    pub fn set_stacks_block_accepted<'a>(tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, parent_stacks_block_hash: &BlockHeaderHash, stacks_block_hash: &BlockHeaderHash, stacks_block_height: u64) -> Result<(), db_error> {
        let burn_tip = BurnDB::get_canonical_burn_chain_tip(tx)?;
        BurnDB::set_stacks_block_accepted_at_tip(tx, &burn_tip, burn_header_hash, parent_stacks_block_hash, stacks_block_hash, stacks_block_height)
    }

    /// Get an ancestor block snapshot if the given ancestor hash is indeed an ancestor.
    pub fn get_ancestor_snapshot_by_hash<'a>(ic: &BurnDBConn<'a>, ancestor_hash: &BurnchainHeaderHash, tip_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        let _ = BurnDB::get_block_snapshot(ic, tip_hash)?.ok_or(db_error::NotFoundError)?;
        let an_sn = match BurnDB::get_block_snapshot(ic, ancestor_hash)? {
            Some(sn) => sn,
            None => {
                return Ok(None);
            }
        };

        match burndb_get_ancestor_block_hash(ic, an_sn.block_height, tip_hash)? {
            Some(bhh) => {
                if bhh != an_sn.burn_header_hash {
                    return Ok(None);
                }
                else {
                    return Ok(Some(an_sn));
                }
            },
            None => {
                return Ok(None);
            }
        }
    }

    /// Get a snapshot with an arrived block (i.e. a block that was marked as processed)
    fn get_snapshot_by_arrival_index(conn: &Connection, arrival_index: u64) -> Result<Option<BlockSnapshot>, db_error> {
        let mut rows = query_rows(conn, "SELECT * FROM snapshots WHERE arrival_index = ?1 AND stacks_block_accepted > 0", &[&u64_to_sql(arrival_index)?])?;
        let len = rows.len();
        match len {
            0 => Ok(None),
            1 => Ok(rows.pop()),
            _ => {
                panic!("BUG: multiple snapshots have the same non-zero arrival index");
            }
        }
    }

    /// Find all stacks blocks that were processed since parent_tip had been processed, and generate MARF
    /// key/value pairs for the subset that arrived on ancestor blocks of the parent.  Update the
    /// given parent chain tip to have the correct memoized canonical chain tip present in the fork
    /// it represents.
    fn process_new_block_arrivals<'a>(tx: &mut BurnDBTx<'a>, parent_tip: &mut BlockSnapshot) -> Result<(Vec<String>, Vec<String>), db_error> {
        let mut keys = vec![];
        let mut values = vec![];

        let max_arrival_index_key = BurnDB::make_stacks_block_max_arrival_index_key();
        let old_max_arrival_index_str = BurnDB::index_value_get(&tx.as_conn(), &parent_tip.burn_header_hash, &max_arrival_index_key)?.unwrap_or("0".to_string());
        let old_max_arrival_index = old_max_arrival_index_str.parse::<u64>().expect("BUG: max arrival index is not a u64");
        let max_arrival_index = BurnDB::get_arrival_index(tx)?;

        let mut new_block_arrivals = vec![];

        // find all Stacks block hashes who arrived since this parent_tip was built.
        for ari in old_max_arrival_index..(max_arrival_index+1) {
            let arrival_sn = match BurnDB::get_snapshot_by_arrival_index(tx, ari)? {
                Some(sn) => sn,
                None => {
                    continue;
                }
            };

            // must be an ancestor of this tip, or must be this tip
            match BurnDB::get_ancestor_snapshot_by_hash(&tx.as_conn(), &arrival_sn.burn_header_hash, &parent_tip.burn_header_hash)? {
                Some(sn) => {
                    // this block arrived on an ancestor block
                    assert_eq!(sn, arrival_sn);

                    debug!("New Stacks anchored block arrived since {}: block {} ({}) ari={} tip={}", parent_tip.burn_header_hash, sn.stacks_block_height, sn.winning_stacks_block_hash, ari, &parent_tip.burn_header_hash);
                    new_block_arrivals.push((sn.burn_header_hash, sn.winning_stacks_block_hash, sn.stacks_block_height));
                }
                None => {
                    // this block did not arrive on an ancestor block
                    continue;
                }
            }
        }

        let mut best_tip_block_bhh = parent_tip.canonical_stacks_tip_hash.clone();
        let mut best_tip_burn_bhh = parent_tip.canonical_stacks_tip_burn_hash.clone();
        let mut best_tip_height = parent_tip.canonical_stacks_tip_height;

        // NOTE: new_block_arrivals is ordered by arrival index, which means it is partially
        // ordered by block height!
        for (burn_bhh, block_bhh, height) in new_block_arrivals.into_iter() {
            keys.push(BurnDB::make_stacks_block_index_key(&block_bhh));
            values.push(BurnDB::make_stacks_block_index_value(height));

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
        keys.push(BurnDB::make_stacks_block_max_arrival_index_key());
        values.push(BurnDB::make_stacks_block_max_arrival_index_value(max_arrival_index));

        Ok((keys, values))
    }

    /// Store a blockstack burnchain operation
    fn store_burnchain_transaction<'a>(tx: &mut BurnDBTx<'a>, blockstack_op: &BlockstackOperationType) -> Result<(), db_error> {
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                debug!("ACCEPTED({}) leader key register {} at {},{}", op.block_height, &op.txid, op.block_height, op.vtxindex);
                BurnDB::insert_leader_key(tx, op)?;
            },
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                debug!("ACCEPTED({}) leader block commit {} at {},{}", op.block_height, &op.txid, op.block_height, op.vtxindex);
                BurnDB::insert_block_commit(tx, op)?;
            },
            BlockstackOperationType::UserBurnSupport(ref op) => {
                debug!("ACCEPTED({}) user burn support {} at {},{}", op.block_height, &op.txid, op.block_height, op.vtxindex);
                BurnDB::insert_user_burn(tx, op)?;
            }
        }
        Ok(())
    }

    /// Get a blockstack burnchain operation by txid
    pub fn get_burnchain_transaction(conn: &Connection, txid: &Txid) -> Result<Option<BlockstackOperationType>, db_error> {
        // leader key?
        let leader_key_sql = "SELECT * FROM leader_keys WHERE txid = ?1 LIMIT 1".to_string();
        let args = [&txid];

        let leader_key_rows = query_rows::<LeaderKeyRegisterOp, _>(conn, &leader_key_sql, &args)?;
        match leader_key_rows.len() {
            0 => {},
            1 => {
                return Ok(Some(BlockstackOperationType::LeaderKeyRegister(leader_key_rows[0].clone())));
            },
            _ => {
                panic!("Multiple leader keys with same txid");
            }
        }
        
        // block commit?
        let block_commit_sql = "SELECT * FROM block_commits WHERE txid = ?1 LIMIT 1".to_string();

        let block_commit_rows = query_rows::<LeaderBlockCommitOp, _>(conn, &block_commit_sql, &args)?;
        match block_commit_rows.len() {
            0 => {},
            1 => {
                return Ok(Some(BlockstackOperationType::LeaderBlockCommit(block_commit_rows[0].clone())));
            },
            _ => {
                panic!("Multiple block commits with same txid");
            }
        }

        // user burn?
        let user_burn_sql = "SELECT * FROM user_burn_support WHERE txid = ?1 LIMIT 1".to_string();

        let user_burn_rows = query_rows::<UserBurnSupportOp, _>(conn, &user_burn_sql, &args)?;
        match user_burn_rows.len() {
            0 => {},
            1 => {
                return Ok(Some(BlockstackOperationType::UserBurnSupport(user_burn_rows[0].clone())));
            },
            _ => {
                panic!("Multiple user burns with the same txid");
            }
        }

        Ok(None)
    }

    /// Get a value from the fork index
    fn index_value_get<'a>(ic: &BurnDBConn<'a>, burn_header_hash: &BurnchainHeaderHash, key: &String) -> Result<Option<String>, db_error> {
        ic.get_indexed(burn_header_hash, key)
    }

    /// Record fork information to the index and calculate the new fork index root hash.
    /// * burndb::vrf::${VRF_PUBLIC_KEY} --> 0 or 1 (1 if available, 0 if consumed), for each VRF public key we process
    /// * burndb::last_sortition --> $BURN_BLOCK_HASH, for each block that had a sortition
    /// * burndb::sortition_block_hash::${STACKS_BLOCK_HASH} --> $BURN_BLOCK_HASH for each winning block sortition
    /// * burndb::stacks::block::${STACKS_BLOCK_HASH} --> ${STACKS_BLOCK_HEIGHT} for each block that has been accepted so far
    /// * burndb::stacks::block::max_arrival_index --> ${ARRIVAL_INDEX} to set the maximum arrival index processed in this fork
    /// NOTE: the resulting index root must be globally unique.  This is guaranteed because each
    /// burn block hash is unique, no matter what fork it's on (and this index uses burn block
    /// hashes as its index's block hash data).
    fn index_add_fork_info<'a>(tx: &mut BurnDBTx<'a>, parent_snapshot: &mut BlockSnapshot, snapshot: &BlockSnapshot, block_ops: &Vec<BlockstackOperationType>, consumed_leader_keys: &Vec<LeaderKeyRegisterOp>) -> Result<TrieHash, db_error> {
        if !snapshot.is_initial() {
            assert_eq!(snapshot.parent_burn_header_hash, parent_snapshot.burn_header_hash);
        }

        let parent_header = &snapshot.parent_burn_header_hash;
        let header = &snapshot.burn_header_hash;

        // data we want to store
        let mut keys = vec![];
        let mut values = vec![];

        // record each new VRF key, and each consumed VRF key
        for block_op in block_ops {
            match block_op {
                BlockstackOperationType::LeaderKeyRegister(ref data) => {
                    keys.push(format!("burndb::vrf::{}", &data.public_key.to_hex()));
                    values.push("1".to_string());       // indicates "available"
                },
                _ => {}
            }
        }

        // record each consumed VRF key as consumed
        for consumed_leader_key in consumed_leader_keys {
            keys.push(format!("burndb::vrf::{}", &consumed_leader_key.public_key.to_hex()));
            values.push("0".to_string());
        }

        // if this commit has a sortition, record its burn block hash and stacks block hash
        if snapshot.sortition {
            keys.push("burndb::last_sortition".to_string());
            values.push(snapshot.burn_header_hash.to_hex());

            keys.push(format!("burndb::sortition_block_hash::{}", snapshot.winning_stacks_block_hash));
            values.push(snapshot.burn_header_hash.to_hex());
        }

        // commit to all newly-arrived blocks
        let (mut block_arrival_keys, mut block_arrival_values) = BurnDB::process_new_block_arrivals(tx, parent_snapshot)?;
        keys.append(&mut block_arrival_keys);
        values.append(&mut block_arrival_values);

        // store each indexed field
        tx.put_indexed_begin(parent_header, header)?;
        let root_hash = tx.put_indexed_all(&keys, &values)?;
        tx.indexed_commit()?;
        Ok(root_hash)
    }

    /// Append a snapshot to a chain tip, and update various chain tip statistics.
    /// Returns the new state root of this fork.
    pub fn append_chain_tip_snapshot<'a>(tx: &mut BurnDBTx<'a>, parent_snapshot: &BlockSnapshot, snapshot: &BlockSnapshot, block_ops: &Vec<BlockstackOperationType>, consumed_leader_keys: &Vec<LeaderKeyRegisterOp>) -> Result<TrieHash, db_error> {
        assert_eq!(snapshot.parent_burn_header_hash, parent_snapshot.burn_header_hash);
        assert_eq!(parent_snapshot.block_height + 1, snapshot.block_height);
        if snapshot.sortition {
            assert_eq!(parent_snapshot.num_sortitions + 1, snapshot.num_sortitions);
        }
        else {
            assert_eq!(parent_snapshot.num_sortitions, snapshot.num_sortitions);
        }

        let mut parent_sn = parent_snapshot.clone();
        let root_hash = BurnDB::index_add_fork_info(tx, &mut parent_sn, snapshot, block_ops, consumed_leader_keys)?;
        
        let mut sn = snapshot.clone();
        sn.index_root = root_hash.clone();

        // preserve memoized stacks chain tip from this burn chain fork
        sn.canonical_stacks_tip_height = parent_sn.canonical_stacks_tip_height;
        sn.canonical_stacks_tip_hash = parent_sn.canonical_stacks_tip_hash;
        sn.canonical_stacks_tip_burn_hash = parent_sn.canonical_stacks_tip_burn_hash;
 
        BurnDB::insert_block_snapshot(tx, &sn)?;

        for block_op in block_ops {
            BurnDB::store_burnchain_transaction(tx, block_op)?;
        }

        Ok(root_hash)
    }

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    pub fn get_canonical_burn_chain_tip(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let qry = "SELECT * FROM snapshots ORDER BY block_height DESC, burn_header_hash ASC LIMIT 1";
        query_row(conn, qry, NO_PARAMS)
            .map(|opt| opt.expect("CORRUPTION: No canonical burnchain tip"))
    }

    /// Get the canonical Stacks chain tip -- this gets memoized on the canonical burn chain tip.
    pub fn get_canonical_stacks_chain_tip_hash(conn: &Connection) -> Result<(BurnchainHeaderHash, BlockHeaderHash), db_error> {
        let sn = BurnDB::get_canonical_burn_chain_tip(conn)?;

        let stacks_block_hash = sn.canonical_stacks_tip_hash;
        let burn_block_hash = sn.canonical_stacks_tip_burn_hash;
        Ok((burn_block_hash, stacks_block_hash))
    }

    /// Given the fork index hash of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork, find the snapshot of the block at that height.
    pub fn get_ancestor_snapshot<'a>(ic: &BurnDBConn<'a>, ancestor_block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(ancestor_block_height < BLOCK_HEIGHT_MAX);
        let ancestor_hash = match burndb_get_ancestor_block_hash(ic, ancestor_block_height, &tip_block_hash)? {
            Some(bhh) => {
                BurnchainHeaderHash::from(bhh)
            },
            None => {
                test_debug!("No ancestor block {} from {} in index", ancestor_block_height, tip_block_hash);
                return Ok(None);
            }
        };

        BurnDB::get_block_snapshot(ic, &ancestor_hash)
    }

    /// Get consensus hash from a particular chain tip's history
    /// Returns None if the block height or block hash does not correspond to a
    /// known snapshot.
    pub fn get_consensus_at<'a>(ic: &BurnDBConn<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<ConsensusHash>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        match BurnDB::get_ancestor_snapshot(ic, block_height, tip_block_hash)? {
            Some(sn) => Ok(Some(sn.consensus_hash.clone())),
            None => Ok(None)
        }
    }

    /// Begin a transaction.
    pub fn tx_begin<'a>(&'a mut self) -> Result<BurnDBTx<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = tx_begin_immediate(&mut self.conn)?;
        let index_tx = BurnDBTx::new(tx, &mut self.marf, BurnDBTxContext { first_block_height: self.first_block_height });
        Ok(index_tx)
    }

    /// Make an indexed connectino
    pub fn index_conn<'a>(&'a self) -> BurnDBConn<'a> {
        BurnDBConn::new(&self.conn, &self.marf, BurnDBTxContext { first_block_height: self.first_block_height })
    }

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    pub fn insert_leader_key<'a>(tx: &mut BurnDBTx<'a>, leader_key: &LeaderKeyRegisterOp) -> Result<(), db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);

        let args : &[&dyn ToSql] = &[
            &leader_key.txid,
            &leader_key.vtxindex,
            &u64_to_sql(leader_key.block_height)?,
            &leader_key.burn_header_hash,
            &leader_key.consensus_hash,
            &leader_key.public_key.to_hex(),
            &to_hex(&leader_key.memo),
            &leader_key.address.to_string()
        ];

        tx.execute("INSERT INTO leader_keys (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, memo, address) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", args)
            .map_err(db_error::SqliteError)?;

        Ok(())
    }
    
    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    pub fn insert_block_commit<'a>(tx: &mut BurnDBTx<'a>, block_commit: &LeaderBlockCommitOp) -> Result<(), db_error> {
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
            &tx_input_str];

        tx.execute("INSERT INTO block_commits (txid, vtxindex, block_height, burn_header_hash, block_header_hash, new_seed, parent_block_ptr, parent_vtxindex, key_block_ptr, key_vtxindex, memo, burn_fee, input) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)", args)
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Insert a user support burn.
    /// No validity checking will be done, beyond what is encoded in the user_burn_support table
    /// constraints.  That is, type mismatches and serialization errors will be caught, but nothing
    /// else.
    /// The corresponding snapshot must already be inserted
    pub fn insert_user_burn<'a>(tx: &mut BurnDBTx<'a>, user_burn: &UserBurnSupportOp) -> Result<(), db_error> {
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
            &burn_fee_str];

        tx.execute("INSERT INTO user_burn_support (txid, vtxindex, block_height, burn_header_hash, address, consensus_hash, public_key, key_block_ptr, key_vtxindex, block_header_hash_160, burn_fee) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)", args)
            .map_err(db_error::SqliteError)?;

        Ok(())
    }
    
    /// Get the first snapshot 
    pub fn get_first_block_snapshot(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let qry = "SELECT * FROM snapshots WHERE consensus_hash = ?1".to_string();
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &[&ConsensusHash::empty()])?;
        match rows.len() {
            0 => {
                // should never happen
                panic!("FATAL: no first snapshot");
            },
            1 => Ok(rows[0].clone()),
            _ => {
                // should never happen 
                panic!("FATAL: multiple first-block snapshots");
            }
        }
    }

    /// Get a snapshot for an existing block.
    pub fn get_block_snapshot(conn: &Connection, burn_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE burn_header_hash = ?1".to_string();
        let args = [&burn_hash];
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)?;
        match rows.len() {
            0 => {
                test_debug!("No snapshot with burn hash {}", burn_hash);
                Ok(None)
            },
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block {}", burn_hash);
            }
        }
    }
    
    /// Get a snapshot for an existing burn chain block given its consensus hash.
    pub fn get_block_snapshot_consensus(conn: &Connection, consensus_hash: &ConsensusHash) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE consensus_hash = ?1".to_string();
        let args = [&consensus_hash];
        let mut rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)?;
        let len = rows.len();
        match len {
            0 => {
                test_debug!("No snapshot with consensus hash {}", consensus_hash);
                Ok(None)
            },
            1 => Ok(rows.pop()),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block with consensus hash {}", consensus_hash);
            }
        }
    }
    
    /// Get a snapshot for an existing block given its state index
    pub fn get_block_snapshot_at(conn: &Connection, index_root: &TrieHash) -> Result<Option<BlockSnapshot>, db_error> {
        let qry = "SELECT * FROM snapshots WHERE index_root = ?1".to_string();
        let args = [&index_root];
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block {}", index_root);
            }
        }
    }
    
    /// Get a snapshot for an existing block in a particular fork, given its tip
    pub fn get_block_snapshot_in_fork<'a>(ic: &BurnDBConn<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(ic, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                return Ok(None);
            }
        };

        let qry = "SELECT * FROM snapshots WHERE burn_header_hash = ?1 AND block_height = ?2".to_string();
        let args : &[&dyn ToSql] = &[&ancestor_snapshot.burn_header_hash, &u64_to_sql(block_height)?];
        let rows = query_rows::<BlockSnapshot, _>(ic, &qry.to_string(), args)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block height and fork segment");
            }
        }
    }
    
    /// Get a leader key at a specific location in the burn chain's fork history, given the
    /// matching block commit's fork index root (block_height and vtxindex are the leader's
    /// calculated location in this fork).
    /// Returns None if there is no leader key at this location.
    pub fn get_leader_key_at<'a>(ic: &BurnDBConn<'a>, key_block_height: u64, key_vtxindex: u32, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<LeaderKeyRegisterOp>, db_error> {
        assert!(key_block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(ic, key_block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                test_debug!("No ancestor snapshot for height {} back from {}", key_block_height, tip_block_hash);
                return Ok(None);
            }
        };

        let qry = "SELECT * FROM leader_keys WHERE burn_header_hash = ?1 AND block_height = ?2 AND vtxindex = ?3 LIMIT 2".to_string();
        let args : &[&dyn ToSql] = &[&ancestor_snapshot.burn_header_hash, &u64_to_sql(key_block_height)?, &key_vtxindex];
        let rows = query_rows::<LeaderKeyRegisterOp, _>(ic, &qry, args)?;
        match rows.len() {
            0 => {
                test_debug!("No leader keys at {},{} in {}", key_block_height, key_vtxindex, &ancestor_snapshot.burn_header_hash);
                return Ok(None);
            },
            1 => {
                return Ok(Some(rows[0].clone()));
            },
            _ => {
                panic!("Multiple keys at {},{} in {}", key_block_height, key_vtxindex, tip_block_hash);
            }
        }
    }
    
    /// Find the VRF public keys consumed by each block candidate in the given list.
    /// The burn DB should have a key for each candidate; otherwise the candidate would not have
    /// been accepted.
    pub fn get_consumed_leader_keys<'a>(ic: &BurnDBConn<'a>, parent_tip_block_hash: &BurnchainHeaderHash, block_candidates: &Vec<LeaderBlockCommitOp>) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        // get the set of VRF keys consumed by these commits 
        let mut leader_keys = vec![];
        for i in 0..block_candidates.len() {
            let leader_key_block_height = block_candidates[i].key_block_ptr as u64;
            let leader_key_vtxindex = block_candidates[i].key_vtxindex as u32;
            let leader_key = BurnDB::get_leader_key_at(ic, leader_key_block_height, leader_key_vtxindex, parent_tip_block_hash)?
                .expect(&format!("FATAL: no leader key for accepted block commit {} (at {},{})", &block_candidates[i].txid, leader_key_block_height, leader_key_vtxindex));
                    
            leader_keys.push(leader_key);
        }

        Ok(leader_keys)
    }

    /// Get all leader keys registered in a block on the burn chain's history in this fork.
    /// Returns the list of leader keys in order by vtxindex.
    pub fn get_leader_keys_by_block<'a>(ic: &BurnDBConn<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(ic, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                error!("No ancestor snapshot at {} from {}", block_height, tip_block_hash);
                return Err(db_error::NotFoundError);
            }
        };

        let qry = "SELECT * FROM leader_keys WHERE burn_header_hash = ?1 AND block_height = ?2 ORDER BY vtxindex ASC".to_string();
        let args : &[&dyn ToSql] = &[&ancestor_snapshot.burn_header_hash, &u64_to_sql(block_height)?];

        query_rows::<LeaderKeyRegisterOp, _>(ic, &qry.to_string(), args)
    }

    /// Get all block commitments registered in a block on the burn chain's history in this fork.
    /// Returns the list of block commits in order by vtxindex.
    pub fn get_block_commits_by_block<'a>(ic: &BurnDBConn<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(ic, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                error!("No ancestor snapshot at {} from {}", block_height, tip_block_hash);
                return Err(db_error::NotFoundError);
            }
        };

        let qry = "SELECT * FROM block_commits WHERE burn_header_hash = ?1 AND block_height = ?2 ORDER BY vtxindex ASC".to_string();
        let args: &[&dyn ToSql] = &[&ancestor_snapshot.burn_header_hash, &u64_to_sql(block_height)?];

        query_rows::<LeaderBlockCommitOp, _>(ic, &qry.to_string(), args)
    }

    /// Get all user burns registered in a block on is fork.
    /// Returns list of user burns in order by vtxindex.
    pub fn get_user_burns_by_block<'a>(ic: &BurnDBConn<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<UserBurnSupportOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(ic, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                error!("No ancestor snapshot at {} from {}", block_height, tip_block_hash);
                return Err(db_error::NotFoundError);
            }
        };

        let qry = "SELECT * FROM user_burn_support WHERE burn_header_hash = ?1 AND block_height = ?2 ORDER BY vtxindex ASC".to_string();
        let args: &[&dyn ToSql] = &[&ancestor_snapshot.burn_header_hash, &u64_to_sql(block_height)?];

        query_rows::<UserBurnSupportOp, _>(ic, &qry.to_string(), args)
    }
    
    /// Get all user burns that burned for a particular block in a fork.
    /// Returns list of user burns in order by vtxindex.
    pub fn get_winning_user_burns_by_block(conn: &Connection, burn_header_hash: &BurnchainHeaderHash) -> Result<Vec<UserBurnSupportOp>, db_error> {
        let ancestor_snapshot = match BurnDB::get_block_snapshot(conn, burn_header_hash)? {
            Some(sn) => sn,
            None => {
                // no such snapshot, so no such users
                return Ok(vec![]);
            }
        };

        if !ancestor_snapshot.sortition {
            // no winner
            return Ok(vec![]);
        }

        let winning_block_hash160 = Hash160::from_sha256(ancestor_snapshot.winning_stacks_block_hash.as_bytes());

        let qry = "SELECT * FROM user_burn_support WHERE burn_header_hash = ?1 AND block_header_hash_160 = ?2 ORDER BY vtxindex ASC".to_string();
        let args: [&dyn ToSql; 2] = [&ancestor_snapshot.burn_header_hash, &winning_block_hash160];

        query_rows::<UserBurnSupportOp, _>(conn, &qry.to_string(), &args)
    }

    /// Find out how any burn tokens were destroyed in a given block on a given fork.
    pub fn get_block_burn_amount<'a>(ic: &BurnDBConn<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<u64, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        let user_burns = BurnDB::get_user_burns_by_block(ic, block_height, tip_block_hash)?;
        let block_commits = BurnDB::get_block_commits_by_block(ic, block_height, tip_block_hash)?;
        let mut burn_total : u64 = 0;
        
        for i in 0..user_burns.len() {
            burn_total = burn_total.checked_add(user_burns[i].burn_fee).expect("Way too many tokens burned");
        }
        for i in 0..block_commits.len() {
            burn_total = burn_total.checked_add(block_commits[i].burn_fee).expect("Way too many tokens burned");
        }
        Ok(burn_total)
    }

    pub fn get_block_winning_vtxindex(conn: &Connection, block_hash: &BurnchainHeaderHash) -> Result<Option<u16>, db_error> {
        let qry = "SELECT vtxindex FROM block_commits WHERE burn_header_hash = ?1 
                    AND txid = (
                      SELECT winning_block_txid FROM snapshots WHERE burn_header_hash = ?2 LIMIT 1) LIMIT 1";
        let args: &[&dyn ToSql] = &[block_hash, block_hash];
        conn.query_row(qry, args, |row| row.get(0)).optional()
            .map_err(db_error::from)
    }
    
    /// Get a parent block commit at a specific location in the burn chain on a particular fork.
    /// Returns None if there is no block commit at this location.
    pub fn get_block_commit_parent<'a>(ic: &BurnDBConn<'a>, block_height: u64, vtxindex: u32, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(ic, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                return Ok(None);
            }
        };

        let qry = "SELECT * FROM block_commits WHERE burn_header_hash = ?1 AND block_height = ?2 AND vtxindex = ?3 LIMIT 2".to_string();
        let args: &[&dyn ToSql] = &[&ancestor_snapshot.burn_header_hash, &u64_to_sql(block_height)?, &vtxindex];
        let rows = query_rows::<LeaderBlockCommitOp, _>(ic, &qry, args)?;

        match rows.len() {
            0 => {
                return Ok(None);
            },
            1 => {
                return Ok(Some(rows[0].clone()));
            },
            _ => {
                panic!("Multiple parent blocks at {},{} in {}", block_height, vtxindex, tip_block_hash);
            }
        }
    }

    /// Get a block commit by its content-addressed location.  Note that burn_header_hash is enough
    /// to identify the fork we're on, since block hashes are globally-unique (w.h.p.) by
    /// construction.
    pub fn get_block_commit(conn: &Connection, txid: &Txid, burn_header_hash: &BurnchainHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        let qry = "SELECT * FROM block_commits WHERE txid = ?1 AND burn_header_hash = ?2".to_string();
        let args: [&dyn ToSql; 2] = [&txid, &burn_header_hash];
        let rows = query_rows::<LeaderBlockCommitOp, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block commits for {},{}", &txid, &burn_header_hash);
            }
        }
    }

    /// Get a block commit by its committed block
    pub fn get_block_commit_for_stacks_block(conn: &Connection, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        let qry = "SELECT * FROM block_commits WHERE burn_header_hash = ?1 AND block_header_hash = ?2".to_string();
        let args: [&dyn ToSql; 2] = [&burn_header_hash, &block_hash];
        let rows = query_rows::<LeaderBlockCommitOp, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block commits for {}", &block_hash);
            }
        }
    }

    /// Get a block snapshot for a winning block hash in a given burn chain fork.
    pub fn get_block_snapshot_for_winning_stacks_block<'a>(ic: &BurnDBConn<'a>, tip_burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        match BurnDB::index_value_get(ic, tip_burn_header_hash, &format!("burndb::sortition_block_hash::{}", block_hash))? {
            Some(burn_header_hash_str) => {
                let bhh = BurnchainHeaderHash::from_hex(&burn_header_hash_str).expect(&format!("FATAL: corrupt database: failed to parse {} as a hex string", &burn_header_hash_str));
                BurnDB::get_block_snapshot(ic, &bhh)
            },
            None => {
                Ok(None)
            }
        }
    }

    /// Find out whether or not a particular VRF key was used before in this fork segment's history.
    pub fn has_VRF_public_key<'a>(ic: &BurnDBConn<'a>, key: &VRFPublicKey, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        let tip_snapshot = match BurnDB::get_block_snapshot(ic, tip_block_hash)? {
            None => {
                error!("No tip with index root {}", tip_block_hash);
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
        };

        let key_status = match BurnDB::index_value_get(ic, &tip_snapshot.burn_header_hash, &format!("burndb::vrf::{}", key.to_hex()))? {
            Some(_) => {
                // key was seen before
                true
            },
            None => {
                // never before seen
                false
            }
        };

        Ok(key_status)
    }
    
    /// Get all fresh consensus hashes in this fork.
    pub fn get_fresh_consensus_hashes<'a>(ic: &BurnDBConn<'a>, current_block_height: u64, consensus_hash_lifetime: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<ConsensusHash>, db_error> {
        assert!(current_block_height < BLOCK_HEIGHT_MAX);
        let first_snapshot = BurnDB::get_first_block_snapshot(ic)?;
        let mut last_snapshot = match BurnDB::get_block_snapshot(ic, tip_block_hash)? {
            None => {
                return Err(db_error::NotFoundError);
            }
            Some(sn) => sn
        };

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

        let mut fresh_chs = vec![last_snapshot.consensus_hash.clone()];
        for _i in oldest_height..current_block_height {
            let ancestor_snapshot = BurnDB::get_block_snapshot(ic, &last_snapshot.parent_burn_header_hash)?.expect(&format!("Discontiguous index: missing block {}", last_snapshot.parent_burn_header_hash));
            fresh_chs.push(ancestor_snapshot.consensus_hash);
            last_snapshot = ancestor_snapshot;
        }

        // first item is the _oldest_ consensus hash
        fresh_chs.reverse();
        return Ok(fresh_chs);
    }
    
    /// Given a burnchain header hash, go get the last N Stacks block headers that won sortition
    /// leading up to the given header hash.  The ith slot in the vector will be Some(...) if there
    /// was a sortition, and None if not.
    /// Returns up to num_headers prior block header hashes.
    /// The list of hashes will be in ascending order -- the lowest-height block is item 0.
    /// The last hash will be the hash for the given consensus hash.
    pub fn get_stacks_header_hashes<'a>(ic: &BurnDBConn<'a>, num_headers: u64, tip_consensus_hash: &ConsensusHash, cache: Option<&BlockHeaderCache>) -> Result<Vec<(BurnchainHeaderHash, Option<BlockHeaderHash>)>, db_error> {
        let mut ret = vec![];
        let tip_snapshot = match BurnDB::get_block_snapshot_consensus(ic, tip_consensus_hash)? {
            Some(sn) => sn,
            None => {
                return Err(db_error::NotFoundError);
            }
        };

        assert!(tip_snapshot.block_height >= ic.context.first_block_height, "DB corruption: have snapshot with a smaller block height than the first block height");

        let headers_count = 
            if tip_snapshot.block_height - ic.context.first_block_height  < num_headers {
                tip_snapshot.block_height - ic.context.first_block_height
            }
            else {
                num_headers
            };
        
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
            let ancestor_snapshot = BurnDB::get_block_snapshot(ic, &ancestor_header_hash)?.expect(&format!("Discontiguous index: missing block {}", ancestor_header_hash));
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

    /// Find out whether or not a given consensus hash is "recent" enough to be used in this fork.
    /// The fork must exist.
    pub fn is_fresh_consensus_hash<'a>(ic: &BurnDBConn<'a>, current_block_height: u64, consensus_hash_lifetime: u64, consensus_hash: &ConsensusHash, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        assert!(current_block_height < BLOCK_HEIGHT_MAX);
        let first_snapshot = BurnDB::get_first_block_snapshot(ic)?;
        match BurnDB::get_block_snapshot(ic, tip_block_hash)? {
            None => {
                return Err(db_error::NotFoundError);
            }
            Some(_) => {}
        };

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

        let mut last_snapshot = BurnDB::get_block_snapshot(ic, tip_block_hash)?
            .ok_or(db_error::NotFoundError)?;

        if last_snapshot.consensus_hash == *consensus_hash {
            return Ok(true);
        }

        for _i in oldest_height..current_block_height {
            // all of these values should exist
            let ancestor_snapshot = match BurnDB::get_block_snapshot(ic, &last_snapshot.parent_burn_header_hash)? {
                Some(sn) => {
                    sn
                },
                None => {
                    panic!("Discontiguous index: missing block {}", last_snapshot.parent_burn_header_hash);
                }
            };

            if ancestor_snapshot.consensus_hash == *consensus_hash {
                // found!
                return Ok(true);
            }

            last_snapshot = ancestor_snapshot;
        }

        return Ok(false);
    }

    /// Determine whether or not a leader key has been consumed by a subsequent block commitment in
    /// this fork's history.
    /// Will return false if the leader key does not exist.
    pub fn is_leader_key_consumed<'a>(ic: &BurnDBConn<'a>, leader_key: &LeaderKeyRegisterOp, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);
        
        let tip_snapshot = match BurnDB::get_block_snapshot(ic, tip_block_hash)? { 
            None => {
                error!("No tip with index root {}", tip_block_hash);
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
        };

        let key_status = match BurnDB::index_value_get(ic, &tip_snapshot.burn_header_hash, &format!("burndb::vrf::{}", leader_key.public_key.to_hex()))? {
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

    /// Get the latest block snapshot on this fork where a sortition occured.
    /// Search snapshots up to (but excluding) the given block height.
    /// Will always return a snapshot -- even if it's the initial sentinel snapshot.
    pub fn get_last_snapshot_with_sortition<'a>(ic: &BurnDBConn<'a>, burn_block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<BlockSnapshot, db_error> {
        assert!(burn_block_height < BLOCK_HEIGHT_MAX);
        test_debug!("Get snapshot at burn block {}, expect height {}", tip_block_hash, burn_block_height);
        let tip_snapshot = match BurnDB::get_block_snapshot(ic, tip_block_hash)? {
            None => {
                error!("No tip at burn block {}", tip_block_hash);
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
        };

        assert_eq!(tip_snapshot.block_height, burn_block_height);

        let ancestor_hash = match BurnDB::index_value_get(ic, &tip_snapshot.burn_header_hash, &"burndb::last_sortition".to_string())? {
            Some(hex_str) => {
                BurnchainHeaderHash::from_hex(&hex_str).expect(&format!("FATAL: corrupt database: failed to parse {} into a hex string", &hex_str))
            },
            None => {
                // no prior sortitions, so get the first
                return BurnDB::get_first_block_snapshot(ic);
            }
        };

        match BurnDB::get_block_snapshot(ic, &ancestor_hash) {
            Ok(snapshot_opt) => {
                Ok(snapshot_opt.expect(&format!("FATAL: corrupt index: no snapshot {}", ancestor_hash)))
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    /// Get a burn blockchain snapshot, given a burnchain configuration struct.
    /// Used mainly by the network code to determine what the chain tip currently looks like.
    pub fn get_burnchain_view<'a>(ic: &BurnDBConn<'a>, burnchain: &Burnchain) -> Result<BurnchainView, db_error> {
        let chain_tip = BurnDB::get_canonical_burn_chain_tip(ic)?;
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

        let stable_block_height = 
            if chain_tip.block_height - (burnchain.stable_confirmations as u64) < burnchain.first_block_height {
                burnchain.first_block_height
            }
            else {
                chain_tip.block_height - (burnchain.stable_confirmations as u64)
            };

        let stable_snapshot = match BurnDB::get_block_snapshot_in_fork(ic, stable_block_height, &chain_tip.burn_header_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                // shouldn't be possible, but don't panic since this is network-callable code
                error!("Failed to load snapshot for block {} from fork {}", stable_block_height, &chain_tip.burn_header_hash);
                return Err(db_error::Corruption);
            }
        };

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
            let ch = BurnDB::get_consensus_at(ic, height, &chain_tip.burn_header_hash)?.unwrap_or(ConsensusHash::empty());
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

    /// Do we expect a stacks block on some fork?  i.e. is there at least one winning block commit for it?
    pub fn expects_stacks_block(conn: &Connection, block_hash: &BlockHeaderHash) -> Result<bool, db_error> {
        let sql = "SELECT winning_stacks_block_hash FROM snapshots WHERE winning_stacks_block_hash = ?1".to_string();
        let rows = query_row_columns::<BlockHeaderHash, _>(conn, &sql, &[&block_hash], "winning_stacks_block_hash")?;
        match rows.len() {
            0 => Ok(false),
            _ => Ok(true)
        }
    }

    /// Do we expect a stacks block in this particular fork?
    /// i.e. is this block hash part of the fork history identified by tip_block_hash?
    pub fn expects_stacks_block_in_fork<'a>(ic: &BurnDBConn<'a>, block_hash: &BlockHeaderHash, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        match BurnDB::index_value_get(ic, tip_block_hash, &format!("burndb::sortition_block_hash::{}", block_hash))? {
            Some(_) => {
                Ok(true)
            },
            None => {
                Ok(false)
            }
        }
    }
}

impl ChainstateDB for BurnDB {
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
        let _db = BurnDB::connect_test(123, &first_burn_hash).unwrap();
    }

    #[test]
    fn test_tx_begin_end() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut db = BurnDB::connect_test(123, &first_burn_hash).unwrap();
        let tx = db.tx_begin().unwrap();
        tx.commit().unwrap();
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

        let mut db = BurnDB::connect_test(block_height, &first_burn_hash).unwrap();

        let snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();

            sn
        };

        {
            let ic = db.index_conn();
            let leader_key_opt = BurnDB::get_leader_key_at(&ic, block_height + 1, vtxindex, &snapshot.burn_header_hash).unwrap();
            assert!(leader_key_opt.is_some());
            assert_eq!(leader_key_opt.unwrap(), leader_key);
        }

        let new_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();

            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x02; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };

        {
            let ic = db.index_conn();
            let leader_key_opt = BurnDB::get_leader_key_at(&ic, block_height + 1, vtxindex, &new_snapshot.burn_header_hash).unwrap();
            assert!(leader_key_opt.is_some());
            assert_eq!(leader_key_opt.unwrap(), leader_key);
            
            let leader_key_none = BurnDB::get_leader_key_at(&ic, block_height + 1, vtxindex+1, &new_snapshot.burn_header_hash).unwrap();
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

        let mut db = BurnDB::connect_test(block_height, &first_burn_hash).unwrap();

        let snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };

        // test get_consumed_leader_keys()
        {
            let ic = db.index_conn();
            let keys = BurnDB::get_consumed_leader_keys(&ic, &snapshot.burn_header_hash, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);
        }

        // test is_leader_key_consumed()
        {
            let ic = db.index_conn();
            let is_consumed = BurnDB::is_leader_key_consumed(&ic, &leader_key, &snapshot.burn_header_hash).unwrap();
            assert!(!is_consumed);
        }
        
        let snapshot_consumed = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x03; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderBlockCommit(block_commit.clone())], &vec![leader_key.clone()]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();

            sn
        };

        {
            let ic = db.index_conn();
            let res_block_commits = BurnDB::get_block_commits_by_block(&ic, block_height+2, &snapshot_consumed.burn_header_hash).unwrap();
            assert_eq!(res_block_commits.len(), 1);
            assert_eq!(res_block_commits[0], block_commit);

            let no_block_commits = BurnDB::get_block_commits_by_block(&ic, block_height+1, &snapshot_consumed.burn_header_hash).unwrap();
            assert_eq!(no_block_commits.len(), 0);
        }
        
        // test is_leader_key_consumed() now that the commit exists
        {
            let ic = db.index_conn();
            let is_consumed = BurnDB::is_leader_key_consumed(&ic, &leader_key, &snapshot_consumed.burn_header_hash).unwrap();
            assert!(is_consumed);
        }

        // advance and get parent
        let empty_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x05; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();

            sn
        };
        
        // test get_block_commit_parent()
        {
            let ic = db.index_conn();
            let parent = BurnDB::get_block_commit_parent(&ic, block_height + 2, block_commit.vtxindex, &empty_snapshot.burn_header_hash).unwrap();
            assert!(parent.is_some());
            assert_eq!(parent.unwrap(), block_commit);

            let parent = BurnDB::get_block_commit_parent(&ic, block_height + 3, block_commit.vtxindex, &empty_snapshot.burn_header_hash).unwrap();
            assert!(parent.is_none());
            
            let parent = BurnDB::get_block_commit_parent(&ic, block_height + 2, block_commit.vtxindex + 1, &empty_snapshot.burn_header_hash).unwrap();
            assert!(parent.is_none());
        }

        // test get_block_commit()
        {
            let commit = BurnDB::get_block_commit(db.conn(), &block_commit.txid, &block_commit.burn_header_hash).unwrap();
            assert!(commit.is_some());
            assert_eq!(commit.unwrap(), block_commit);

            let bad_txid = Txid::from_bytes_be(&hex_bytes("4c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap();
            let commit = BurnDB::get_block_commit(db.conn(), &bad_txid, &block_commit.burn_header_hash).unwrap();
            assert!(commit.is_none());
        }
        
        // test get_consumed_leader_keys() (should be doable at any subsequent index root)
        {
            let ic = db.index_conn();
            let keys = BurnDB::get_consumed_leader_keys(&ic, &empty_snapshot.burn_header_hash, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);
        }
        
        // test is_leader_key_consumed() (should be duable at any subsequent index root)
        {
            let ic = db.index_conn();
            let is_consumed = BurnDB::is_leader_key_consumed(&ic, &leader_key, &empty_snapshot.burn_header_hash).unwrap();
            assert!(is_consumed);
            
            let is_consumed = BurnDB::is_leader_key_consumed(&ic, &leader_key, &snapshot.burn_header_hash).unwrap();
            assert!(!is_consumed);
        }

        // make a fork between the leader key and block commit, and verify that the key is
        // unconsumed
        let fork_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_block_snapshot(&tx, &BurnchainHeaderHash([0x01; 32])).unwrap().unwrap();

            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x13; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();

            sn
        };

        // test get_consumed_leader_keys() and is_leader_key_consumed() against this new fork
        {
            let ic = db.index_conn();
            let keys = BurnDB::get_consumed_leader_keys(&ic, &fork_snapshot.burn_header_hash, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);

            let is_consumed = BurnDB::is_leader_key_consumed(&ic, &leader_key, &fork_snapshot.burn_header_hash).unwrap();
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

        let mut db = BurnDB::connect_test(block_height, &first_burn_hash).unwrap();
        
        let snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };
        
        let user_burn_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x03; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::UserBurnSupport(user_burn.clone())], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };

        {
            let ic = db.index_conn();
            let res_user_burns = BurnDB::get_user_burns_by_block(&ic, block_height+2, &user_burn_snapshot.burn_header_hash).unwrap();
            assert_eq!(res_user_burns.len(), 1);
            assert_eq!(res_user_burns[0], user_burn);

            let no_user_burns = BurnDB::get_user_burns_by_block(&ic, block_height+1, &user_burn_snapshot.burn_header_hash).unwrap();
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

        let mut db = BurnDB::connect_test(block_height, &first_burn_hash).unwrap();
        
        let no_key_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();
            sn
        };

        let has_key_before = {
            let ic = db.index_conn();
            BurnDB::has_VRF_public_key(&ic, &public_key, &no_key_snapshot.burn_header_hash).unwrap()
        };

        assert!(!has_key_before);

        let key_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x03; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();
            sn
        };

        let has_key_after = {
            let ic = db.index_conn();
            BurnDB::has_VRF_public_key(&ic, &public_key, &key_snapshot.burn_header_hash).unwrap()
        };

        assert!(has_key_after);
    }

    #[test]
    fn is_fresh_consensus_hash() {
        let consensus_hash_lifetime = 24;
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = BurnDB::connect_test(0, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            let mut last_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
            for i in 0..255 {
                let snapshot_row = BlockSnapshot {
                    block_height: i+1,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[(if i == 0 { 0x10 } else { 0 }) as u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(i+1) as u8]).unwrap(),
                    ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    total_burn: i,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: i+1,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
                };
                let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &snapshot_row, &vec![], &vec![]).unwrap();
                last_snapshot = snapshot_row;
                last_snapshot.index_root = index_root;
            }

            tx.commit().unwrap();
        }

        let tip = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

        let ch_fresh = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255]).unwrap();
        let ch_oldest_fresh = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(255 - consensus_hash_lifetime) as u8]).unwrap();
        let ch_newest_stale = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(255 - consensus_hash_lifetime - 1) as u8]).unwrap();
        let ch_missing = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,255]).unwrap();

        let fresh_check = {
            let ic = db.index_conn();
            BurnDB::is_fresh_consensus_hash(&ic, 255, consensus_hash_lifetime, &ch_fresh, &tip.burn_header_hash).unwrap()
        };

        assert!(fresh_check);

        let oldest_fresh_check = {
            let ic = db.index_conn();
            BurnDB::is_fresh_consensus_hash(&ic, 255, consensus_hash_lifetime, &ch_oldest_fresh, &tip.burn_header_hash).unwrap()
        };

        assert!(oldest_fresh_check);

        let newest_stale_check = {
            let ic = db.index_conn();
            BurnDB::is_fresh_consensus_hash(&ic, 255, consensus_hash_lifetime, &ch_newest_stale, &tip.burn_header_hash).unwrap()
        };

        assert!(!newest_stale_check);

        let missing_check = {
            let ic = db.index_conn();
            BurnDB::is_fresh_consensus_hash(&ic, 255, consensus_hash_lifetime, &ch_missing, &tip.burn_header_hash).unwrap()
        };

        assert!(!missing_check);
    }

    #[test]
    fn get_consensus_at() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = BurnDB::connect_test(0, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            let mut last_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
            for i in 0..256 {
                let snapshot_row = BlockSnapshot {
                    block_height: i+1,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[(if i == 0 { 0x10 } else { 0 }) as u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    total_burn: i,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    index_root: TrieHash::from_empty_data(), 
                    num_sortitions: i+1,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
                };
                let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &snapshot_row, &vec![], &vec![]).unwrap();
                last_snapshot = snapshot_row;
                last_snapshot.index_root = index_root;

                // should succeed within the tx 
                let ch = BurnDB::get_consensus_at(&tx.as_conn(), i+1, &last_snapshot.burn_header_hash).unwrap().unwrap_or(ConsensusHash::empty());
                assert_eq!(ch, last_snapshot.consensus_hash);
            }

            tx.commit().unwrap();
        }

        let tip = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

        for i in 0..256 {
            // should succeed within the conn
            let ic = db.index_conn();
            let expected_ch = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap();
            let ch = BurnDB::get_consensus_at(&ic, i+1, &tip.burn_header_hash).unwrap().unwrap_or(ConsensusHash::empty());
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

        let mut db = BurnDB::connect_test(block_height, &first_burn_hash).unwrap();

        let key_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();
            sn
        };
        
        let commit_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x03; 32]);
            sn.block_height += 1;
            sn.num_sortitions += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderBlockCommit(block_commit.clone()), BlockstackOperationType::UserBurnSupport(user_burn.clone())], &vec![leader_key.clone()]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };
    
        {
            let ic = db.index_conn();
            let burn_amt = BurnDB::get_block_burn_amount(&ic, block_height + 2, &commit_snapshot.burn_header_hash).unwrap();
            assert_eq!(burn_amt, block_commit.burn_fee + user_burn.burn_fee);

            let no_burn_amt = BurnDB::get_block_burn_amount(&ic, block_height + 1, &commit_snapshot.burn_header_hash).unwrap();
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
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
        };

        let mut snapshot_with_sortition = BlockSnapshot {
            block_height: block_height,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]).unwrap(),
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
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
        };

        let snapshot_without_sortition = BlockSnapshot {
            block_height: block_height - 1,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
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
            canonical_stacks_tip_height: 0,
            canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
            canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
        };

        let mut db = BurnDB::connect_test(block_height - 2, &first_burn_hash).unwrap();

        let chain_tip = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap()
        };

        let initial_snapshot = {
            let ic = db.index_conn();
            BurnDB::get_last_snapshot_with_sortition(&ic, block_height - 2, &chain_tip.burn_header_hash).unwrap()
        };

        first_snapshot.index_root = initial_snapshot.index_root.clone();
        first_snapshot.burn_header_timestamp = initial_snapshot.burn_header_timestamp;
        assert_eq!(initial_snapshot, first_snapshot);

        {
            let mut tx = db.tx_begin().unwrap();
            let chain_tip = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            BurnDB::append_chain_tip_snapshot(&mut tx, &chain_tip, &snapshot_without_sortition, &vec![], &vec![]).unwrap();
            tx.commit().unwrap();
        }
        
        let chain_tip = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap()
        };

        let mut next_snapshot = {
            let ic = db.index_conn();
            BurnDB::get_last_snapshot_with_sortition(&ic, block_height - 1, &chain_tip.burn_header_hash).unwrap()
        };

        next_snapshot.index_root = initial_snapshot.index_root.clone();
        next_snapshot.burn_header_timestamp = initial_snapshot.burn_header_timestamp;
        assert_eq!(initial_snapshot, next_snapshot);

        {
            let mut tx = db.tx_begin().unwrap();
            let chain_tip = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            BurnDB::append_chain_tip_snapshot(&mut tx, &chain_tip, &snapshot_with_sortition, &vec![], &vec![]).unwrap();
            tx.commit().unwrap();
        }
        
        let chain_tip = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap()
        };

        let next_snapshot_2 = {
            let ic = db.index_conn();
            BurnDB::get_last_snapshot_with_sortition(&ic, block_height, &chain_tip.burn_header_hash).unwrap()
        };

        snapshot_with_sortition.index_root = next_snapshot_2.index_root.clone();
        snapshot_with_sortition.burn_header_timestamp = next_snapshot_2.burn_header_timestamp;
        assert_eq!(snapshot_with_sortition, next_snapshot_2);
    }

    /// Verify that the snapshots in a fork are well-formed -- i.e. the block heights are
    /// sequential and the parent block hash of the ith block is equal to the block hash of the
    /// (i-1)th block.
    fn verify_fork_integrity(db: &mut BurnDB, tip_header_hash: &BurnchainHeaderHash) {
        let mut child = {
            let ic = db.index_conn();
            BurnDB::get_block_snapshot(&ic, tip_header_hash).unwrap().unwrap()
        };

        let initial = BurnDB::get_first_block_snapshot(db.conn()).unwrap();
       
        test_debug!("Verify from {},hash={},parent={} back to {},hash={},parent={}",
                    child.block_height, child.burn_header_hash, child.parent_burn_header_hash,
                    initial.block_height, initial.burn_header_hash, initial.parent_burn_header_hash);

        while child.block_height > initial.block_height {
            let parent = {
                let ic = db.index_conn();
                BurnDB::get_block_snapshot_in_fork(&ic, child.block_height - 1, &child.burn_header_hash).unwrap().unwrap()
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

        let mut db = BurnDB::connect_test(first_block_height, &first_burn_hash).unwrap();

        // make an initial fork
        let mut last_snapshot = BurnDB::get_first_block_snapshot(db.conn()).unwrap();

        for i in 0..10 {
            let mut next_snapshot = last_snapshot.clone();

            next_snapshot.block_height += 1;
            next_snapshot.num_sortitions += 1;
            next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
            next_snapshot.burn_header_hash = BurnchainHeaderHash([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i + 1]);
            next_snapshot.consensus_hash = ConsensusHash([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i + 1]);
            
            let mut tx = db.tx_begin().unwrap();
            BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
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
            
            let parent_block = BurnchainHeaderHash(parent_block_hash);
            test_debug!("----- build fork off of parent {} (i = {}) -----", &parent_block, i);

            let mut last_snapshot = BurnDB::get_block_snapshot(db.conn(), &parent_block).unwrap().unwrap();

            let initial_block_height = last_snapshot.block_height;
            let initial_num_sortitions = last_snapshot.num_sortitions;

            let mut next_snapshot = last_snapshot.clone();

            for j in (i+1)..10 {
            
                let mut block_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(j+1) as u8];
                block_hash[i] = (j - i) as u8;

                next_snapshot.block_height = initial_block_height + (j - i) as u64;
                next_snapshot.num_sortitions = initial_num_sortitions + (j - i) as u64;
                next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
                next_snapshot.burn_header_hash = BurnchainHeaderHash(block_hash);
                next_snapshot.consensus_hash = ConsensusHash([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,j as u8,(i + 1) as u8]);

                let mut tx = db.tx_begin().unwrap();
                let next_index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
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
            let last_block = BurnchainHeaderHash(last_block_hash);
            
            test_debug!("----- grow fork {} (i = {}) -----", &last_block, i);

            let mut last_snapshot = BurnDB::get_block_snapshot(db.conn(), &last_block).unwrap().unwrap();
           
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
                next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);
                next_snapshot.consensus_hash = ConsensusHash([2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,j as u8,(i + 1) as u8]);

                let next_index_root = {
                    let mut tx = db.tx_begin().unwrap();
                    let next_index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
                    tx.commit().unwrap();
                    next_index_root
                };

                last_snapshot = BurnDB::get_block_snapshot(db.conn(), &next_snapshot.burn_header_hash).unwrap().unwrap();
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
            next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);

            let next_index_root = {
                let mut tx = db.tx_begin().unwrap();
                let next_index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
                tx.commit().unwrap();
                next_index_root
            };
            
            next_snapshot.index_root = next_index_root;

            let mut expected_tip = next_snapshot.clone();
            expected_tip.index_root = next_index_root;

            let canonical_tip = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
            assert_eq!(canonical_tip, expected_tip);

            verify_fork_integrity(&mut db, &canonical_tip.burn_header_hash);
            all_chain_tips.push(canonical_tip.burn_header_hash.clone());
        }

        for tip_header_hash in all_chain_tips.iter() {
            verify_fork_integrity(&mut db, tip_header_hash);
        }
    }

    #[test]
    fn test_get_stacks_header_hashes() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = BurnDB::connect_test(0, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            let mut last_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
            let mut total_burn = 0;
            let mut total_sortitions = 0;
            for i in 0..256 {
                let snapshot_row = 
                    if i % 3 == 0 {
                        BlockSnapshot {
                            block_height: i+1,
                            burn_header_timestamp: get_epoch_time_secs(),
                            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
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
                            block_height: i+1,
                            burn_header_timestamp: get_epoch_time_secs(),
                            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
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
                let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &snapshot_row, &vec![], &vec![]).unwrap();
                last_snapshot = snapshot_row;
                last_snapshot.index_root = index_root;

                // should succeed within the tx 
                let ch = BurnDB::get_consensus_at(&tx.as_conn(), i+1, &last_snapshot.burn_header_hash).unwrap().unwrap_or(ConsensusHash::empty());
                assert_eq!(ch, last_snapshot.consensus_hash);
            }

            tx.commit().unwrap();
        }
        
        let canonical_tip = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        let mut cache = BlockHeaderCache::new();

        {
            let ic = db.index_conn();
            let hashes = BurnDB::get_stacks_header_hashes(&ic, 256, &canonical_tip.consensus_hash, Some(&cache)).unwrap();
            BurnDB::merge_block_header_cache(&mut cache, &hashes);

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
            let hashes = BurnDB::get_stacks_header_hashes(&ic, 256, &canonical_tip.consensus_hash, None).unwrap();
            BurnDB::merge_block_header_cache(&mut cache, &hashes);

            let cached_hashes = BurnDB::get_stacks_header_hashes(&ic, 256, &canonical_tip.consensus_hash, Some(&cache)).unwrap();

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
            let hashes = BurnDB::get_stacks_header_hashes(&ic, 192, &canonical_tip.consensus_hash, None).unwrap();
            BurnDB::merge_block_header_cache(&mut cache, &hashes);

            let cached_hashes = BurnDB::get_stacks_header_hashes(&ic, 192, &canonical_tip.consensus_hash, Some(&cache)).unwrap();

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
            let hashes = BurnDB::get_stacks_header_hashes(&ic, 257, &canonical_tip.consensus_hash, None).unwrap();
            BurnDB::merge_block_header_cache(&mut cache, &hashes);

            let cached_hashes = BurnDB::get_stacks_header_hashes(&ic, 257, &canonical_tip.consensus_hash, Some(&cache)).unwrap();

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
            let err = BurnDB::get_stacks_header_hashes(&ic, 256, &ConsensusHash([0x03; 20]), None).unwrap_err();
            match err {
                db_error::NotFoundError => {},
                _ => {
                    eprintln!("Got wrong error: {:?}", &err);
                    assert!(false);
                    unreachable!();
                }
            }
            
            let err = BurnDB::get_stacks_header_hashes(&ic, 256, &ConsensusHash([0x03; 20]), Some(&cache)).unwrap_err();
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

    fn make_fork_run(db: &mut BurnDB, start_snapshot: &BlockSnapshot, length: u64, bit_pattern: u8) -> () {
        let mut last_snapshot = start_snapshot.clone();
        for i in last_snapshot.block_height..(last_snapshot.block_height + length) {
            let snapshot = BlockSnapshot {
                block_height: last_snapshot.block_height + 1,
                burn_header_timestamp: get_epoch_time_secs(),
                burn_header_hash: BurnchainHeaderHash([(i as u8) | bit_pattern; 32]),
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
                let mut tx = db.tx_begin().unwrap();
                BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &snapshot, &vec![], &vec![]).unwrap();
                tx.commit().unwrap();
            }
            last_snapshot = BurnDB::get_block_snapshot(db.conn(), &snapshot.burn_header_hash).unwrap().unwrap();
        }
    }

    #[test]
    fn test_set_stacks_block_accepted() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = BurnDB::connect_test(0, &first_burn_hash).unwrap();

        let mut last_snapshot = BurnDB::get_first_block_snapshot(db.conn()).unwrap();

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
                BurnDB::set_stacks_block_accepted(&mut tx, &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, height).unwrap();
                tx.commit().unwrap();
            }

            // chain tip is memoized to the current burn chain tip
            let (burn_bhh, block_bhh) = BurnDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
            assert_eq!(burn_bhh, burn_header_hash);
            assert_eq!(block_bhh, stacks_block_hash);
        }

        // materialize all block arrivals in the MARF
        last_snapshot = BurnDB::get_block_snapshot(db.conn(), &BurnchainHeaderHash([0x04; 32])).unwrap().unwrap();
        make_fork_run(&mut db, &last_snapshot, 1, 0);

        // verify that all Stacks block in this fork can be looked up from this chain tip
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        {
            let ic = db.index_conn();
            for i in 0..5 {
                let parent_stacks_block_hash = BlockHeaderHash([i as u8; 32]);
                let parent_key = BurnDB::make_stacks_block_index_key(&parent_stacks_block_hash);

                test_debug!("Look up '{}' off of {}", &parent_key, &last_snapshot.burn_header_hash);
                let value_opt = BurnDB::index_value_get(&ic, &last_snapshot.burn_header_hash, &parent_key).unwrap();
                assert!(value_opt.is_some());
                assert_eq!(value_opt.unwrap(), format!("{}", i));
            }
        }

        // make a burn fork off of the 5th block
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        make_fork_run(&mut db, &last_snapshot, 5, 0x80);

        // chain tip is _still_ memoized to the last materialized chain tip
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
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
                BurnDB::set_stacks_block_accepted(&mut tx, &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, *height).unwrap();
                tx.commit().unwrap();
            }

            // chain tip is memoized to the current burn chain tip, since it's the longest stacks fork
            let (burn_bhh, block_bhh) = BurnDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
            assert_eq!(burn_bhh, burn_header_hash);
            assert_eq!(block_bhh, stacks_block_hash);

            parent_stacks_block_hash = stacks_block_hash;
        }
        
        // chain tip is _still_ memoized to the last materialized chain tip (i.e. stacks block 7)
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
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
                BurnDB::set_stacks_block_accepted(&mut tx, &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, *height).unwrap();
                tx.commit().unwrap();
            }

            // chain tip is memoized to the current burn chain tip, since it's the longest stacks fork
            let (burn_bhh, block_bhh) = BurnDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
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
                BurnDB::set_stacks_block_accepted(&mut tx, &burn_header_hash, &parent_stacks_block_hash, &stacks_block_hash, *height).unwrap();
                tx.commit().unwrap();
            }

            // we've overtaken the longest fork with a different longest fork on this burn chain fork
            let (burn_bhh, block_bhh) = BurnDB::get_canonical_stacks_chain_tip_hash(db.conn()).unwrap();
            assert_eq!(burn_bhh, burn_header_hash);
            assert_eq!(block_bhh, stacks_block_hash);
        }
        
        // canonical stacks chain tip is now stacks block 9
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
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
        last_snapshot = BurnDB::get_block_snapshot(db.conn(), &BurnchainHeaderHash([0x04; 32])).unwrap().unwrap();
        make_fork_run(&mut db, &last_snapshot, 7, 0x40);

        // canonical stacks chain tip is now stacks block 4, since the burn chain fork ending on
        // 0x4b has overtaken the burn chain fork ending on 0x8a
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 4);

        // set the stacks block at 0x4b as accepted as the 5th block
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::set_stacks_block_accepted(&mut tx, &BurnchainHeaderHash([0x4b; 32]), &BlockHeaderHash([0x04; 32]), &BlockHeaderHash([0x4b; 32]), 5).unwrap();
            tx.commit().unwrap();
        }
        
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
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
        last_snapshot = BurnDB::get_block_snapshot(db.conn(), &BurnchainHeaderHash([0x48; 32])).unwrap().unwrap();
        make_fork_run(&mut db, &last_snapshot, 2, 0x20);

        last_snapshot = BurnDB::get_block_snapshot(db.conn(), &BurnchainHeaderHash([0x2a; 32])).unwrap().unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x04; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 4);
        
        // doesn't affect canonical chain tip
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);
        
        // set the stacks block at 0x29 and 0x2a as accepted as the 5th and 6th blocks
        {
            let mut tx = db.tx_begin().unwrap();
            let tip_snapshot = BurnDB::get_block_snapshot(&tx, &BurnchainHeaderHash([0x2a; 32])).unwrap().unwrap();
            BurnDB::set_stacks_block_accepted_at_tip(&mut tx, &tip_snapshot, &BurnchainHeaderHash([0x29; 32]), &BlockHeaderHash([0x04; 32]), &BlockHeaderHash([0x29; 32]), 5).unwrap();
            BurnDB::set_stacks_block_accepted_at_tip(&mut tx, &tip_snapshot, &BurnchainHeaderHash([0x2a; 32]), &BlockHeaderHash([0x29; 32]), &BlockHeaderHash([0x2a; 32]), 6).unwrap();
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
        last_snapshot = BurnDB::get_block_snapshot(db.conn(), &BurnchainHeaderHash([0x2a; 32])).unwrap().unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x2a; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 6);

        // insertion on the non-canonical tip doesn't affect canonical chain tip
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 5);

        // insert stacks blocks #6, #7, #8, #9 off of the burn chain tip starting at 0x4b (i.e. the
        // canonical burn chain tip), on blocks 0x45, 0x46, and 0x47
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::set_stacks_block_accepted(&mut tx, &BurnchainHeaderHash([0x45; 32]), &BlockHeaderHash([0x04; 32]), &BlockHeaderHash([0x45; 32]), 5).unwrap();
            BurnDB::set_stacks_block_accepted(&mut tx, &BurnchainHeaderHash([0x46; 32]), &BlockHeaderHash([0x45; 32]), &BlockHeaderHash([0x46; 32]), 6).unwrap();
            BurnDB::set_stacks_block_accepted(&mut tx, &BurnchainHeaderHash([0x47; 32]), &BlockHeaderHash([0x46; 32]), &BlockHeaderHash([0x47; 32]), 7).unwrap();
            BurnDB::set_stacks_block_accepted(&mut tx, &BurnchainHeaderHash([0x48; 32]), &BlockHeaderHash([0x47; 32]), &BlockHeaderHash([0x48; 32]), 8).unwrap();
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
        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x4b; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 8);

        // LIMITATION: the burn chain tipped at 0x2a will _not_ be updated, since it is not the
        // canonical burn chain tip.
        last_snapshot = BurnDB::get_block_snapshot(db.conn(), &BurnchainHeaderHash([0x2a; 32])).unwrap().unwrap();
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

        last_snapshot = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        assert_eq!(last_snapshot.burn_header_hash, BurnchainHeaderHash([0x2c; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_burn_hash, BurnchainHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_hash, BlockHeaderHash([0x48; 32]));
        assert_eq!(last_snapshot.canonical_stacks_tip_height, 8);
    }
}
