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

use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;

use rand;
use rand::RngCore;

use std::fs;
use std::io;
use std::convert::From;
use std::ops::Deref;
use std::ops::DerefMut;

use util::db::{FromRow, RowOrder, query_rows, query_count, IndexDBTx, db_mkdirs};
use util::db::Error as db_error;

use chainstate::ChainstateDB;

use chainstate::burn::Opcodes;
use chainstate::burn::CHAINSTATE_VERSION;
use chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash, OpsHash, BlockSnapshot, SortitionHash};

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

use net::neighbors::MAX_NEIGHBOR_BLOCK_DELAY;

use std::collections::HashMap;

use vm::types::Value;
use vm::representations::{ContractName, ClarityName};

const BLOCK_HEIGHT_MAX : u64 = ((1 as u64) << 63) - 1; 
const SQLITE_ERROR_MSG : &'static str = "FATAL: failed to exeucte Sqlite database operation.  Aborting...";

pub const REWARD_WINDOW_START : u64 = 144 * 15;
pub const REWARD_WINDOW_END : u64 = 144 * 90 + REWARD_WINDOW_START;

// for using BurnchainHeaderHash values as block hashes in a MARF
impl From<BurnchainHeaderHash> for BlockHeaderHash {
    fn from(bhh: BurnchainHeaderHash) -> BlockHeaderHash {
        let mut header_hash_bytes = [0u8; 32];
        header_hash_bytes.copy_from_slice(bhh.as_bytes());
        let header_hash = BlockHeaderHash(header_hash_bytes);
        header_hash
    }
}

// for using BurnchainHeaderHash values as block hashes in a MARF
impl From<BlockHeaderHash> for BurnchainHeaderHash {
    fn from(bhh: BlockHeaderHash) -> BurnchainHeaderHash {
        let mut header_hash_bytes = [0u8; 32];
        header_hash_bytes.copy_from_slice(bhh.as_bytes());
        let header_hash = BurnchainHeaderHash(header_hash_bytes);
        header_hash
    }
}

impl RowOrder for BlockSnapshot {
    fn row_order() -> Vec<&'static str> {
        vec!["block_height","burn_header_hash","parent_burn_header_hash","consensus_hash","ops_hash","total_burn","sortition","sortition_hash","winning_block_txid","winning_stacks_block_hash","index_root","stacks_block_height"]
    }
}

impl FromRow<BlockSnapshot> for BlockSnapshot {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<BlockSnapshot, db_error> {
        let block_height_i64 : i64 = row.get(0 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 1 + index)?;
        let parent_burn_header_hash = BurnchainHeaderHash::from_row(row, 2 + index)?;
        let consensus_hash = ConsensusHash::from_row(row, 3 + index)?;
        let ops_hash = OpsHash::from_row(row, 4 + index)?;
        let total_burn_str : String = row.get(5 + index);
        let sortition : bool = row.get(6 + index);
        let sortition_hash = SortitionHash::from_row(row, 7 + index)?;
        let winning_block_txid = Txid::from_row(row, 8 + index)?;
        let winning_stacks_block_hash = BlockHeaderHash::from_row(row, 9 + index)?;
        let index_root = TrieHash::from_row(row, 10 + index)?;
        let stacks_block_height_i64 : i64 = row.get(11);

        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        if stacks_block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let total_burn = total_burn_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        let snapshot = BlockSnapshot {
            block_height: block_height_i64 as u64,
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
            stacks_block_height: stacks_block_height_i64 as u64,
        };
        Ok(snapshot)
    }
}

impl RowOrder for LeaderKeyRegisterOp {
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","consensus_hash","public_key","memo","address"]
    }
}

impl FromRow<LeaderKeyRegisterOp> for LeaderKeyRegisterOp {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<LeaderKeyRegisterOp, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_height : i64 = row.get(2 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 3 + index)?;
        let consensus_hash = ConsensusHash::from_row(row, 4 + index)?;
        let public_key = VRFPublicKey::from_row(row, 5 + index)?;
        let memo_hex : String = row.get(6 + index);
        let address = StacksAddress::from_row(row, 7 + index)?;
        
        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        if block_height < 0 {
            return Err(db_error::ParseError);
        }

        let leader_key_row = LeaderKeyRegisterOp {
            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height as u64,
            burn_header_hash: burn_header_hash,

            consensus_hash: consensus_hash,
            public_key: public_key,
            memo: memo, 
            address: address,
        };

        Ok(leader_key_row)
    }
}

impl RowOrder for LeaderBlockCommitOp {
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","block_header_hash","new_seed",
             "parent_block_ptr","parent_vtxindex","key_block_ptr","key_vtxindex", "memo",
             "burn_fee","input"]
    }
}

impl FromRow<LeaderBlockCommitOp> for LeaderBlockCommitOp {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<LeaderBlockCommitOp, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_height: i64 = row.get(2 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 3 + index)?;
        let block_header_hash = BlockHeaderHash::from_row(row, 4 + index)?;
        let new_seed = VRFSeed::from_row(row, 5 + index)?;
        let parent_block_ptr : u32 = row.get(6 + index);
        let parent_vtxindex: u16 = row.get(7 + index);
        let key_block_ptr : u32 = row.get(8 + index);
        let key_vtxindex : u16 = row.get(9 + index);
        let memo_hex : String = row.get(10 + index);
        let burn_fee_str : String = row.get(11 + index);
        let input_json : String = row.get(12 + index);
        
        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        let input = serde_json::from_str::<BurnchainSigner>(&input_json)
            .map_err(|e| db_error::SerializationError(e))?;

        let burn_fee = burn_fee_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        if block_height < 0 {
            return Err(db_error::ParseError);
        }

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
            block_height: block_height as u64,
            burn_header_hash: burn_header_hash,
        };
        Ok(block_commit)
    }
}

impl RowOrder for UserBurnSupportOp {
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","consensus_hash","public_key","key_block_ptr","key_vtxindex","block_header_hash_160","burn_fee"]
    }
}

impl FromRow<UserBurnSupportOp> for UserBurnSupportOp {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<UserBurnSupportOp, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_height : i64 = row.get(2 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 3 + index)?;

        let consensus_hash = ConsensusHash::from_row(row, 4 + index)?;
        let public_key = VRFPublicKey::from_row(row, 5 + index)?;
        let key_block_ptr: u32 = row.get(6 + index);
        let key_vtxindex : u16 = row.get(7 + index);
        let block_header_hash_160 = Hash160::from_row(row, 8 + index)?;

        let burn_fee_str : String = row.get(9 + index);

        let burn_fee = burn_fee_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        if block_height < 0 {
            return Err(db_error::ParseError);
        }

        let user_burn = UserBurnSupportOp {
            consensus_hash: consensus_hash,
            public_key: public_key,
            key_block_ptr: key_block_ptr,
            key_vtxindex: key_vtxindex,
            block_header_hash_160: block_header_hash_160,
            burn_fee: burn_fee,

            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height as u64,
            burn_header_hash: burn_header_hash
        };
        Ok(user_burn)
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
        parent_burn_header_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        ops_hash TEXT NOT NULL,
        total_burn TEXT NOT NULL,
        sortition INTEGER NOT NULL,
        sortition_hash TEXT NOT NULL,
        winning_block_txid TEXT NOT NULL,
        winning_stacks_block_hash TEXT NOT NULL,
        index_root TEXT UNIQUE NOT NULL,

        stacks_block_height INTEGER NOT NULL,

        PRIMARY KEY(burn_header_hash)
    );"#,
    r#"
    CREATE UNIQUE INDEX snapshots_block_hashes ON snapshots(block_height,index_root,winning_stacks_block_hash);
    CREATE UNIQUE INDEX snapshots_block_stacks_hashes ON snapshots(stacks_block_height,index_root,winning_stacks_block_hash);
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
        public_key TEXT UNIQUE NOT NULL,
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
    CREATE TABLE db_config(
        version TEXT NOT NULL
    );
    "#
];

pub struct BurnDB {
    pub conn: Connection,
    pub readwrite: bool,
    pub marf: MARF,
    pub first_block_height: u64,
    pub first_burn_header_hash: BurnchainHeaderHash,
}

pub struct BurnDBTxContext {
    pub first_block_height: u64
}

pub type BurnDBTx<'a> = IndexDBTx<'a, BurnDBTxContext>;

fn burndb_get_ancestor_block_hash<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<BurnchainHeaderHash>, db_error> {
    if block_height < tx.context.first_block_height {
        return Ok(None);
    }
    
    let tip_bhh = BlockHeaderHash::from(tip_block_hash.clone());
    let first_block_height = tx.context.first_block_height;
    match tx.get_ancestor_block_hash(block_height - first_block_height, &tip_bhh)? {
        Some(bhh) => {
            Ok(Some(BurnchainHeaderHash::from(bhh)))
        },
        None => {
            Ok(None)
        }
    }
}

fn burndb_get_ancestor_block_height<'a>(tx: &mut BurnDBTx<'a>, ancestor_hash: &BurnchainHeaderHash, &tip_block_hash: &BurnchainHeaderHash) -> Result<Option<u64>, db_error> {
    let ancestor_bhh = BlockHeaderHash::from(ancestor_hash.clone());
    let tip_bhh = BlockHeaderHash::from(tip_block_hash.clone());
    match tx.get_ancestor_block_height(&ancestor_bhh, &tip_bhh)? {
        Some(height_u32) => {
            Ok(Some((height_u32 as u64) + tx.context.first_block_height))
        },
        None => {
            Ok(None)
        }
    }
}

impl BurnDB {
    fn instantiate(conn: &mut Connection, index_path: &str, first_block_height: u64, first_burn_header_hash: &BurnchainHeaderHash) -> Result<(), db_error> {
        let tx = conn.transaction().map_err(db_error::SqliteError)?;

        // create first (sentinel) snapshot
        let mut first_snapshot = BlockSnapshot::initial(first_block_height, first_burn_header_hash);
        
        assert!(first_snapshot.parent_burn_header_hash != first_snapshot.burn_header_hash);
        assert_eq!(first_snapshot.parent_burn_header_hash.as_bytes(), TrieFileStorage::block_sentinel().as_bytes());

        for row_text in BURNDB_SETUP {
            tx.execute(row_text, NO_PARAMS).map_err(db_error::SqliteError)?;
        }

        tx.execute("INSERT INTO db_config (version) VALUES (?1)", &[&CHAINSTATE_VERSION]).map_err(db_error::SqliteError)?;
        
        let mut marf = BurnDB::open_index(index_path)?;
        let mut burndbtx = BurnDBTx::new(tx, &mut marf, BurnDBTxContext { first_block_height: first_block_height });
        
        burndbtx.instantiate_index()?;

        let index_root = BurnDB::index_add_fork_info(&mut burndbtx, &first_snapshot, &first_snapshot, &vec![], &vec![])?;
        first_snapshot.index_root = index_root;

        burndbtx.tx.execute("INSERT INTO snapshots \
                   (block_height, burn_header_hash, parent_burn_header_hash, consensus_hash, ops_hash, total_burn, sortition, sortition_hash, winning_block_txid, winning_stacks_block_hash, index_root, stacks_block_height) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                   &[&(first_snapshot.block_height as i64) as &dyn ToSql, &first_snapshot.burn_header_hash.to_hex(), &first_snapshot.parent_burn_header_hash.to_hex(), &first_snapshot.consensus_hash.to_hex(), &first_snapshot.ops_hash.to_hex(), &"0".to_string(),
                     &first_snapshot.sortition as &dyn ToSql, &first_snapshot.sortition_hash.to_hex(), &first_snapshot.winning_block_txid.to_hex(), &first_snapshot.winning_stacks_block_hash.to_hex(), &first_snapshot.index_root.to_hex(), 
                     &(first_snapshot.stacks_block_height as i64) as &dyn ToSql])
            .map_err(db_error::SqliteError)?;
       
        burndbtx.commit()?;
        Ok(())
    }

    /// Open the burn database at the given path.  Open read-only or read/write.
    /// If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(path: &String, first_block_height: u64, first_burn_hash: &BurnchainHeaderHash, readwrite: bool) -> Result<BurnDB, db_error> {
        let mut create_flag = false;
        let open_flags =
            if fs::metadata(path).is_err() {
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
                // can just open 
                if readwrite {
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                }
                else {
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                }
            };

        let (db_path, index_path) = db_mkdirs(path)?;
        let mut conn = Connection::open_with_flags(&db_path, open_flags).map_err(db_error::SqliteError)?;

        if create_flag {
            // instantiate!
            BurnDB::instantiate(&mut conn, &index_path, first_block_height, first_burn_hash)?;
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
    pub fn connect_memory(first_block_height: u64, first_burn_hash: &BurnchainHeaderHash) -> Result<BurnDB, db_error> {
        let mut conn = Connection::open_in_memory().map_err(db_error::SqliteError)?;
        
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let db_path_dir = format!("/tmp/test-blockstack-burndb-{}", to_hex(&buf));
        let (db_path, index_path) = db_mkdirs(&db_path_dir)?;

        BurnDB::instantiate(&mut conn, &index_path, first_block_height, first_burn_hash)?;

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
    pub fn open(path: &String, readwrite: bool) -> Result<BurnDB, db_error> {
        let open_flags =
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            }
            else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            };

        let (db_path, index_path) = db_mkdirs(path)?;
        let conn = Connection::open_with_flags(&db_path, open_flags).map_err(db_error::SqliteError)?;
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

    pub fn open_index(index_path: &str) -> Result<MARF, db_error> {
        test_debug!("Open index at {}", index_path);
        let marf = MARF::from_path(index_path).map_err(|_e| db_error::Corruption)?;
        Ok(marf)
    }

    /// Get a particular chain tip's snapshot if the arguments here actually correspond to a chain
    /// tip.  If not, then return None.
    /// Insert a snapshots row from a block's-worth of operations. 
    /// Do not call directly -- use append_chain_tip_snapshot to preserve the fork table structure.
    fn insert_block_snapshot<'a>(tx: &mut BurnDBTx<'a>, snapshot: &BlockSnapshot) -> Result<(), db_error> {
        assert!(snapshot.block_height < BLOCK_HEIGHT_MAX);
        assert!(snapshot.stacks_block_height < BLOCK_HEIGHT_MAX);

        test_debug!("Insert block snapshot state {} for block {} ({},{}) {}", snapshot.index_root.to_hex(), snapshot.block_height,
                    snapshot.burn_header_hash.to_hex(), snapshot.parent_burn_header_hash.to_hex(), snapshot.stacks_block_height);

        let total_burn_str = format!("{}", snapshot.total_burn);

        tx.execute("INSERT INTO snapshots \
                   (block_height, burn_header_hash, parent_burn_header_hash, consensus_hash, ops_hash, total_burn, sortition, sortition_hash, winning_block_txid, winning_stacks_block_hash, index_root, stacks_block_height) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                   &[&(snapshot.block_height as i64) as &dyn ToSql, &snapshot.burn_header_hash.to_hex(), &snapshot.parent_burn_header_hash.to_hex(), &snapshot.consensus_hash.to_hex(), &snapshot.ops_hash.to_hex(), &total_burn_str,
                     &snapshot.sortition as &dyn ToSql, &snapshot.sortition_hash.to_hex(), &snapshot.winning_block_txid.to_hex(), &snapshot.winning_stacks_block_hash.to_hex(), &snapshot.index_root.to_hex(),
                     &(snapshot.stacks_block_height as i64) as &dyn ToSql])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Store a blockstack burnchain operation
    fn store_burnchain_transaction<'a>(tx: &mut BurnDBTx<'a>, blockstack_op: &BlockstackOperationType) -> Result<(), db_error> {
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                info!("ACCEPTED({}) leader key register {} at {},{}", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex);
                BurnDB::insert_leader_key(tx, op)
                    .expect("FATAL: failed to store leader key to Sqlite");
            },
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                info!("ACCEPTED({}) leader block commit {} at {},{}", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex);
                BurnDB::insert_block_commit(tx, op)
                    .expect("FATAL: failed to store leader block commit to Sqlite");
            },
            BlockstackOperationType::UserBurnSupport(ref op) => {
                info!("ACCEPTED({}) user burn support {} at {},{}", op.block_height, &op.txid.to_hex(), op.block_height, op.vtxindex);
                BurnDB::insert_user_burn(tx, op)
                    .expect("FATAL: failed to store user burn support to Sqlite");
            }
        }
        Ok(())
    }

    /// Get a blockstack burnchain operation by txid
    pub fn get_burnchain_transaction(conn: &Connection, txid: &Txid) -> Result<Option<BlockstackOperationType>, db_error> {
        // leader key?
        let leader_key_row_order = LeaderKeyRegisterOp::row_order().join(",");
        let leader_key_sql = format!("SELECT {} FROM leader_keys WHERE txid = ?1 LIMIT 1", leader_key_row_order);
        let args = [&txid.to_hex() as &dyn ToSql];

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
        let block_commit_row_order = LeaderBlockCommitOp::row_order().join(",");
        let block_commit_sql = format!("SELECT {} FROM block_commits WHERE txid = ?1 LIMIT 1", block_commit_row_order);

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
        let user_burn_row_order = UserBurnSupportOp::row_order().join(",");
        let user_burn_sql = format!("SELECT {} FROM user_burn_support WHERE txid = ?1 LIMIT 1", user_burn_row_order);

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
    fn index_value_get<'a>(tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, key: &String) -> Result<Option<String>, db_error> {
        let mut header_hash_bytes = [0u8; 32];
        header_hash_bytes.copy_from_slice(burn_header_hash.as_bytes());
        let header_hash = BlockHeaderHash(header_hash_bytes);
        tx.get_indexed(&header_hash, key)
    }

    /// Record fork information to the index and calculate the new fork index root hash.
    /// * burndb::vrf::${VRF_PUBLIC_KEY} --> 0 or 1 (1 if available, 0 if consumed), for each VRF public key we process
    /// * burndb::last_sortition --> $BURN_BLOCK_HASH, for each block that had a sortition
    /// * burndb::sortition_block_hash::${STACKS_BLOCK_HASH} --> $BURN_BLOCK_HASH for each winning block sortition
    /// NOTE: the resulting index root must be globally unique.  This is guaranteed because each
    /// burn block hash is unique, no matter what fork it's on (and this index uses burn block
    /// hashes as its index's block hash data).
    fn index_add_fork_info<'a>(tx: &mut BurnDBTx<'a>, parent_snapshot: &BlockSnapshot, snapshot: &BlockSnapshot, block_ops: &Vec<BlockstackOperationType>, consumed_leader_keys: &Vec<LeaderKeyRegisterOp>) -> Result<TrieHash, db_error> {
        if !snapshot.is_initial() {
            assert_eq!(snapshot.parent_burn_header_hash, parent_snapshot.burn_header_hash);
        }

        // convert from burn header hash to block header hash (it's safe since theyr'e both
        // 32-byte hashes)
        let parent_header = BlockHeaderHash::from(snapshot.parent_burn_header_hash.clone());
        let header = BlockHeaderHash::from(snapshot.burn_header_hash.clone());

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

            keys.push(format!("burndb::sortition_block_hash::{}", snapshot.winning_stacks_block_hash.to_hex()));
            values.push(snapshot.burn_header_hash.to_hex());
        }

        // store each indexed field
        tx.put_indexed_begin(&parent_header, &header)?;
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
            assert_eq!(parent_snapshot.stacks_block_height + 1, snapshot.stacks_block_height);
        }
        else {
            assert_eq!(parent_snapshot.stacks_block_height, snapshot.stacks_block_height);
        }

        let root_hash = BurnDB::index_add_fork_info(tx, parent_snapshot, snapshot, block_ops, consumed_leader_keys)?;
        
        let mut sn = snapshot.clone();
        sn.index_root = root_hash.clone();

        BurnDB::insert_block_snapshot(tx, &sn)?;

        for block_op in block_ops {
            BurnDB::store_burnchain_transaction(tx, block_op)?;
        }

        Ok(root_hash)
    }

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    pub fn get_canonical_burn_chain_tip(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots ORDER BY block_height DESC, burn_header_hash ASC LIMIT 1", row_order);
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry, NO_PARAMS)?;
        assert!(rows.len() > 0);
        Ok(rows[0].clone())
    }

    /// Get the canonical stacks chain tip -- the tip of the longest stacks chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    pub fn get_canonical_stacks_chain_tip(conn: &Connection) -> Result<Option<BlockSnapshot>, db_error> {
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots ORDER BY stacks_block_height DESC, burn_header_hash ASC LIMIT 1", row_order);
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry, NO_PARAMS)?;
        match rows.len() {
            0 => {
                Ok(None)
            },
            _ => {
                Ok(Some(rows[0].clone()))
            }
        }
    }

    /// Given the fork index hash of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork, find the snapshot of the block at that height.
    fn get_ancestor_snapshot<'a>(tx: &mut BurnDBTx<'a>, ancestor_block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(ancestor_block_height < BLOCK_HEIGHT_MAX);
        let ancestor_hash = match burndb_get_ancestor_block_hash(tx, ancestor_block_height, &tip_block_hash)? {
            Some(bhh) => {
                BurnchainHeaderHash::from(bhh)
            },
            None => {
                test_debug!("No ancestor block {} from {} in index", ancestor_block_height, tip_block_hash.to_hex());
                return Ok(None);
            }
        };

        BurnDB::get_block_snapshot(tx, &ancestor_hash)
    }

    /// Get consensus hash from a particular chain tip's history
    pub fn get_consensus_at<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<ConsensusHash, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        match BurnDB::get_ancestor_snapshot(tx, block_height, tip_block_hash)? {
            Some(sn) => Ok(sn.consensus_hash.clone()),
            None => Ok(ConsensusHash::empty())
        }
    }

    /// Begin a transaction.
    pub fn tx_begin<'a>(&'a mut self) -> Result<BurnDBTx<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = self.conn.transaction().map_err(db_error::SqliteError)?;
        let index_tx = BurnDBTx::new(tx, &mut self.marf, BurnDBTxContext { first_block_height: self.first_block_height });
        Ok(index_tx)
    }

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    pub fn insert_leader_key<'a>(tx: &mut BurnDBTx<'a>, leader_key: &LeaderKeyRegisterOp) -> Result<(), db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);

        tx.execute("INSERT INTO leader_keys (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, memo, address) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                   &[&leader_key.txid.to_hex(), &leader_key.vtxindex as &dyn ToSql, &(leader_key.block_height as i64) as &dyn ToSql, &leader_key.burn_header_hash.to_hex(),
                   &leader_key.consensus_hash.to_hex(), &leader_key.public_key.to_hex(), &to_hex(&leader_key.memo), &leader_key.address.to_string()])
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

        tx.execute("INSERT INTO block_commits (txid, vtxindex, block_height, burn_header_hash, block_header_hash, new_seed, parent_block_ptr, parent_vtxindex, key_block_ptr, key_vtxindex, memo, burn_fee, input) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    &[&block_commit.txid.to_hex(), &block_commit.vtxindex as &dyn ToSql, &(block_commit.block_height as i64) as &dyn ToSql, &block_commit.burn_header_hash.to_hex(), 
                    &block_commit.block_header_hash.to_hex(), &block_commit.new_seed.to_hex(), &block_commit.parent_block_ptr as &dyn ToSql, &block_commit.parent_vtxindex as &dyn ToSql,
                    &block_commit.key_block_ptr as &dyn ToSql, &block_commit.key_vtxindex as &dyn ToSql, &to_hex(&block_commit.memo[..]), &burn_fee_str as &dyn ToSql, &tx_input_str])
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

        tx.execute("INSERT INTO user_burn_support (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, key_block_ptr, key_vtxindex, block_header_hash_160, burn_fee) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                   &[&user_burn.txid.to_hex(), &user_burn.vtxindex as &dyn ToSql, &(user_burn.block_height as i64) as &dyn ToSql, &user_burn.burn_header_hash.to_hex(), &user_burn.consensus_hash.to_hex(),
                   &user_burn.public_key.to_hex(), &user_burn.key_block_ptr as &dyn ToSql, &user_burn.key_vtxindex as &dyn ToSql, &user_burn.block_header_hash_160.to_hex(), &burn_fee_str])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }
    
    /// Get the first snapshot 
    pub fn get_first_block_snapshot(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE consensus_hash = ?1", row_order);
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &[&ConsensusHash::empty().to_hex()])?;
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
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE burn_header_hash = ?1", row_order);
        let args = [&burn_hash.to_hex()];
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block {}", burn_hash.to_hex());
            }
        }
    }
    
    /// Get a snapshot for an existing block given its state index
    pub fn get_block_snapshot_at(conn: &Connection, index_root: &TrieHash) -> Result<Option<BlockSnapshot>, db_error> {
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE index_root = ?1", row_order);
        let args = [&index_root.to_hex()];
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block {}", index_root.to_hex());
            }
        }
    }
    
    /// Get a snapshot for an existing block in a particular fork segment
    pub fn get_block_snapshot_in_fork<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(tx, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                return Ok(None);
            }
        };

        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE burn_header_hash = ?1 AND block_height = ?2", row_order);
        let args = [&ancestor_snapshot.burn_header_hash.to_hex() as &dyn ToSql, &(block_height as i64) as &dyn ToSql];
        let rows = query_rows::<BlockSnapshot, _>(tx, &qry.to_string(), &args)?;
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
    pub fn get_leader_key_at<'a>(tx: &mut BurnDBTx<'a>, key_block_height: u64, key_vtxindex: u32, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<LeaderKeyRegisterOp>, db_error> {
        assert!(key_block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(tx, key_block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                test_debug!("No ancestor snapshot for height {} back from {}", key_block_height, tip_block_hash.to_hex());
                return Ok(None);
            }
        };

        let row_order = LeaderKeyRegisterOp::row_order().join(",");
        let qry = format!("SELECT {} FROM leader_keys WHERE burn_header_hash = ?1 AND block_height = ?2 AND vtxindex = ?3 LIMIT 2", row_order);
        let args = [&ancestor_snapshot.burn_header_hash.to_hex(), &(key_block_height as i64) as &dyn ToSql, &key_vtxindex as &dyn ToSql];
        let rows = query_rows::<LeaderKeyRegisterOp, _>(tx, &qry, &args)?;
        match rows.len() {
            0 => {
                test_debug!("No leader keys at {},{} in {}", key_block_height, key_vtxindex, &ancestor_snapshot.burn_header_hash.to_hex());
                return Ok(None);
            },
            1 => {
                return Ok(Some(rows[0].clone()));
            },
            _ => {
                panic!("Multiple keys at {},{} in {}", key_block_height, key_vtxindex, tip_block_hash.to_hex());
            }
        }
    }
    
    /// Find the VRF public keys consumed by each block candidate in the given list.
    /// The burn DB should have a key for each candidate; otherwise the candidate would not have
    /// been accepted.
    pub fn get_consumed_leader_keys<'a>(tx: &mut BurnDBTx<'a>, parent_tip_block_hash: &BurnchainHeaderHash, block_candidates: &Vec<LeaderBlockCommitOp>) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        // get the set of VRF keys consumed by these commits 
        let mut leader_keys = vec![];
        for i in 0..block_candidates.len() {
            let leader_key_block_height = block_candidates[i].key_block_ptr as u64;
            let leader_key_vtxindex = block_candidates[i].key_vtxindex as u32;
            let leader_key = BurnDB::get_leader_key_at(tx, leader_key_block_height, leader_key_vtxindex, parent_tip_block_hash)?
                .expect(&format!("FATAL: no leader key for accepted block commit {} (at {},{})", &block_candidates[i].txid.to_hex(), leader_key_block_height, leader_key_vtxindex));
                    
            leader_keys.push(leader_key);
        }

        Ok(leader_keys)
    }

    /// Get all leader keys registered in a block on the burn chain's history in this fork.
    /// Returns the list of leader keys in order by vtxindex.
    pub fn get_leader_keys_by_block<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(tx, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                error!("No ancestor snapshot at {} from {}", block_height, tip_block_hash.to_hex());
                return Err(db_error::NotFoundError);
            }
        };

        let row_order = LeaderKeyRegisterOp::row_order().join(",");

        let qry = format!("SELECT {} FROM leader_keys WHERE burn_header_hash = ?1 AND block_height = ?2 ORDER BY vtxindex ASC", row_order);
        let args = [&ancestor_snapshot.burn_header_hash.to_hex() as &dyn ToSql, &(block_height as i64) as &dyn ToSql];

        query_rows::<LeaderKeyRegisterOp, _>(tx, &qry.to_string(), &args)
    }

    /// Get all block commitments registered in a block on the burn chain's history in this fork.
    /// Returns the list of block commits in order by vtxindex.
    pub fn get_block_commits_by_block<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(tx, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                error!("No ancestor snapshot at {} from {}", block_height, tip_block_hash.to_hex());
                return Err(db_error::NotFoundError);
            }
        };

        let row_order = LeaderBlockCommitOp::row_order().join(",");

        let qry = format!("SELECT {} FROM block_commits WHERE burn_header_hash = ?1 AND block_height = ?2 ORDER BY vtxindex ASC", row_order);
        let args = [&ancestor_snapshot.burn_header_hash.to_hex() as &dyn ToSql, &(block_height as i64) as &dyn ToSql];

        query_rows::<LeaderBlockCommitOp, _>(tx, &qry.to_string(), &args)
    }

    /// Get all user burns registered in a block on is fork.
    /// Returns list of user burns in order by vtxindex.
    pub fn get_user_burns_by_block<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<UserBurnSupportOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(tx, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                error!("No ancestor snapshot at {} from {}", block_height, tip_block_hash.to_hex());
                return Err(db_error::NotFoundError);
            }
        };
        
        let row_order = UserBurnSupportOp::row_order().join(",");

        let qry = format!("SELECT {} FROM user_burn_support WHERE burn_header_hash = ?1 AND block_height = ?2 ORDER BY vtxindex ASC", row_order);
        let args = [&ancestor_snapshot.burn_header_hash.to_hex() as &dyn ToSql, &(block_height as i64) as &dyn ToSql];

        query_rows::<UserBurnSupportOp, _>(tx, &qry.to_string(), &args)
    }

    /// Find out how any burn tokens were destroyed in a given block on a given fork.
    pub fn get_block_burn_amount<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<u128, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        let user_burns = BurnDB::get_user_burns_by_block(tx, block_height, tip_block_hash)?;
        let block_commits = BurnDB::get_block_commits_by_block(tx, block_height, tip_block_hash)?;
        let mut burn_total : u128 = 0;
        
        for i in 0..user_burns.len() {
            burn_total = burn_total.checked_add(user_burns[i].burn_fee as u128).expect("Way too many tokens burned");
        }
        for i in 0..block_commits.len() {
            burn_total = burn_total.checked_add(block_commits[i].burn_fee as u128).expect("Way too many tokens burned");
        }
        Ok(burn_total)
    }
    
    /// Get a parent block commit at a specific location in the burn chain on a particular fork.
    /// Returns None if there is no block commit at this location.
    pub fn get_block_commit_parent<'a>(tx: &mut BurnDBTx<'a>, block_height: u64, vtxindex: u32, tip_block_hash: &BurnchainHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        let ancestor_snapshot = match BurnDB::get_ancestor_snapshot(tx, block_height, tip_block_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                return Ok(None);
            }
        };

        let row_order = LeaderBlockCommitOp::row_order().join(",");
        let qry = format!("SELECT {} FROM block_commits WHERE burn_header_hash = ?1 AND block_height = ?2 AND vtxindex = ?3 LIMIT 2", row_order);
        let args = [&ancestor_snapshot.burn_header_hash.to_hex(), &(block_height as i64) as &dyn ToSql, &vtxindex as &dyn ToSql];
        let rows = query_rows::<LeaderBlockCommitOp, _>(tx, &qry, &args)?;

        match rows.len() {
            0 => {
                return Ok(None);
            },
            1 => {
                return Ok(Some(rows[0].clone()));
            },
            _ => {
                panic!("Multiple parent blocks at {},{} in {}", block_height, vtxindex, tip_block_hash.to_hex());
            }
        }
    }

    /// Get a block commit by its content-addressed location.  Note that burn_header_hash is enough
    /// to identify the fork we're on, since block hashes are globally-unique (w.h.p.) by
    /// construction.
    pub fn get_block_commit(conn: &Connection, txid: &Txid, burn_header_hash: &BurnchainHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        let row_order_list : Vec<String> = LeaderBlockCommitOp::row_order().iter().map(|r| format!("block_commits.{}", r)).collect();
        let row_order = row_order_list.join(",");

        let qry = format!("SELECT {} FROM block_commits WHERE block_commits.txid = ?1 AND block_commits.burn_header_hash = ?2", row_order);
        let args = [&txid.to_hex(), &burn_header_hash.to_hex()];
        let rows = query_rows::<LeaderBlockCommitOp, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block commits for {},{}", &txid.to_hex(), &burn_header_hash.to_hex());
            }
        }
    }

    /// Get a block commit by its committed block
    pub fn get_block_commit_for_stacks_block(conn: &Connection, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        let row_order = LeaderBlockCommitOp::row_order().join(",");

        let qry = format!("SELECT {} FROM block_commits WHERE burn_header_hash = ?1 AND block_header_hash = ?2", row_order);
        let args = [&burn_header_hash.to_hex(), &block_hash.to_hex()];
        let rows = query_rows::<LeaderBlockCommitOp, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block commits for {}", &block_hash.to_hex());
            }
        }
    }

    /// Get a block snapshot for a winning block hash in a given burn chain fork.
    pub fn get_block_snapshot_for_winning_stacks_block<'a>(tx: &mut BurnDBTx<'a>, tip_burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        match BurnDB::index_value_get(tx, tip_burn_header_hash, &format!("burndb::sortition_block_hash::{}", block_hash.to_hex()))? {
            Some(burn_header_hash_str) => {
                let bhh = BurnchainHeaderHash::from_hex(&burn_header_hash_str).expect(&format!("FATAL: corrupt database: failed to parse {} as a hex string", &burn_header_hash_str));
                BurnDB::get_block_snapshot(tx, &bhh)
            },
            None => {
                Ok(None)
            }
        }
    }

    /// Find out whether or not a particular VRF key was used before in this fork segment's history.
    pub fn has_VRF_public_key<'a>(tx: &mut BurnDBTx<'a>, key: &VRFPublicKey, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        let tip_snapshot = match BurnDB::get_block_snapshot(tx, tip_block_hash)? {
            None => {
                error!("No tip with index root {}", tip_block_hash.to_hex());
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
        };

        let key_status = match BurnDB::index_value_get(tx, &tip_snapshot.burn_header_hash, &format!("burndb::vrf::{}", key.to_hex()))? {
            Some(status_str) => {
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
    pub fn get_fresh_consensus_hashes<'a>(tx: &mut BurnDBTx<'a>, current_block_height: u64, consensus_hash_lifetime: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<Vec<ConsensusHash>, db_error> {
        assert!(current_block_height < BLOCK_HEIGHT_MAX);
        let first_snapshot = BurnDB::get_first_block_snapshot(tx)?;
        let tip_snapshot = match BurnDB::get_block_snapshot(tx, tip_block_hash)? {
            None => {
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
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

        let mut fresh_chs = vec![];

        for i in oldest_height..current_block_height+1 {
            // all of these values should exist
            let block_hash = match burndb_get_ancestor_block_hash(tx, i, tip_block_hash)? {
                Some(bhh) => {
                    BurnchainHeaderHash::from(bhh)
                },
                None => {
                    panic!("Discontiguous index: missing block {}", i);
                }
            };

            let ancestor_snapshot = match BurnDB::get_block_snapshot(tx, &block_hash)? {
                Some(sn) => {
                    sn
                },
                None => {
                    panic!("Discontiguous index: missing block {}", block_hash.to_hex());
                }
            };

            fresh_chs.push(ancestor_snapshot.consensus_hash.clone());
        }

        return Ok(fresh_chs);
    }

    /// Find out whether or not a given consensus hash is "recent" enough to be used in this fork.
    /// The fork must exist.
    pub fn is_fresh_consensus_hash<'a>(tx: &mut BurnDBTx<'a>, current_block_height: u64, consensus_hash_lifetime: u64, consensus_hash: &ConsensusHash, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        assert!(current_block_height < BLOCK_HEIGHT_MAX);
        let first_snapshot = BurnDB::get_first_block_snapshot(tx)?;
        let tip_snapshot = match BurnDB::get_block_snapshot(tx, tip_block_hash)? {
            None => {
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
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

        for i in oldest_height..current_block_height+1 {
            // all of these values should exist
            let block_hash = match burndb_get_ancestor_block_hash(tx, i, tip_block_hash)? {
                Some(bhh) => {
                    BurnchainHeaderHash::from(bhh)
                },
                None => {
                    panic!("Discontiguous index: missing block {}", i);
                }
            };

            let ancestor_snapshot = match BurnDB::get_block_snapshot(tx, &block_hash)? {
                Some(sn) => {
                    sn
                },
                None => {
                    panic!("Discontiguous index: missing block {}", block_hash.to_hex());
                }
            };

            if ancestor_snapshot.consensus_hash == *consensus_hash {
                // found!
                return Ok(true);
            }
        }

        return Ok(false);
    }

    /// Determine whether or not a leader key has been consumed by a subsequent block commitment in
    /// this fork's history.
    /// Will return false if the leader key does not exist.
    pub fn is_leader_key_consumed<'a>(tx: &mut BurnDBTx<'a>, leader_key: &LeaderKeyRegisterOp, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);
        
        let tip_snapshot = match BurnDB::get_block_snapshot(tx, tip_block_hash)? { 
            None => {
                error!("No tip with index root {}", tip_block_hash.to_hex());
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
        };

        let key_status = match BurnDB::index_value_get(tx, &tip_snapshot.burn_header_hash, &format!("burndb::vrf::{}", leader_key.public_key.to_hex()))? {
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
    pub fn get_last_snapshot_with_sortition<'a>(tx: &mut BurnDBTx<'a>, burn_block_height: u64, tip_block_hash: &BurnchainHeaderHash) -> Result<BlockSnapshot, db_error> {
        assert!(burn_block_height < BLOCK_HEIGHT_MAX);
        test_debug!("Get snapshot at burn block {}, expect height {}", tip_block_hash.to_hex(), burn_block_height);
        let tip_snapshot = match BurnDB::get_block_snapshot(tx, tip_block_hash)? {
            None => {
                error!("No tip at burn block {}", tip_block_hash.to_hex());
                return Err(db_error::NotFoundError);
            }
            Some(sn) => {
                sn
            }
        };

        assert_eq!(tip_snapshot.block_height, burn_block_height);

        let ancestor_hash = match BurnDB::index_value_get(tx, &tip_snapshot.burn_header_hash, &"burndb::last_sortition".to_string())? {
            Some(hex_str) => {
                BurnchainHeaderHash::from_hex(&hex_str).expect(&format!("FATAL: corrupt database: failed to parse {} into a hex string", &hex_str))
            },
            None => {
                // no prior sortitions, so get the first
                return BurnDB::get_first_block_snapshot(tx);
            }
        };

        match BurnDB::get_block_snapshot(tx, &ancestor_hash) {
            Ok(snapshot_opt) => {
                Ok(snapshot_opt.expect(&format!("FATAL: corrupt index: no snapshot {}", ancestor_hash.to_hex())))
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    /// Get a burn blockchain snapshot, given a burnchain configuration struct.
    /// Used mainly by the network code to determine what the chain tip currently looks like.
    pub fn get_burnchain_view<'a>(tx: &mut BurnDBTx<'a>, burnchain: &Burnchain) -> Result<BurnchainView, db_error> {
        let chain_tip = BurnDB::get_canonical_burn_chain_tip(tx)?;
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

        let stable_snapshot = match BurnDB::get_block_snapshot_in_fork(tx, stable_block_height, &chain_tip.burn_header_hash)? {
            Some(sn) => {
                sn
            },
            None => {
                // shouldn't be possible, but don't panic since this is network-callable code
                error!("Failed to load snapshot for block {} from fork {}", stable_block_height, &chain_tip.burn_header_hash.to_hex());
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
            let ch = BurnDB::get_consensus_at(tx, height, &chain_tip.burn_header_hash)?;
            last_consensus_hashes.insert(height, ch);
        }

        test_debug!("Chain view: {},{}-{},{}", chain_tip.block_height, chain_tip.consensus_hash.to_hex(), stable_block_height, stable_snapshot.consensus_hash.to_hex());
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
        let rows = query_rows::<BlockHeaderHash, _>(conn, &sql, &[&block_hash.to_hex()])?;
        match rows.len() {
            0 => Ok(false),
            _ => Ok(true)
        }
    }

    /// Do we expect a stacks block in this particular fork?
    /// i.e. is this block hash part of the fork history identified by tip_block_hash?
    pub fn expects_stacks_block_in_fork<'a>(tx: &mut BurnDBTx<'a>, block_hash: &BlockHeaderHash, tip_block_hash: &BurnchainHeaderHash) -> Result<bool, db_error> {
        match BurnDB::index_value_get(tx, tip_block_hash, &format!("burndb::sortition_block_hash::{}", block_hash.to_hex()))? {
            Some(block_hash) => {
                Ok(true)
            },
            None => {
                Ok(false)
            }
        }
    }
}

impl ChainstateDB for BurnDB {
    fn backup(backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use util::db::Error as db_error;

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

    #[test]
    fn test_instantiate() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let _db = BurnDB::connect_memory(123, &first_burn_hash).unwrap();
    }

    #[test]
    fn test_tx_begin_end() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut db = BurnDB::connect_memory(123, &first_burn_hash).unwrap();
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

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();

        let snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();

            sn
        };

        {
            let mut tx = db.tx_begin().unwrap();
            let leader_key_opt = BurnDB::get_leader_key_at(&mut tx, block_height + 1, vtxindex, &snapshot.burn_header_hash).unwrap();
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
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };

        {
            let mut tx = db.tx_begin().unwrap();
            let leader_key_opt = BurnDB::get_leader_key_at(&mut tx, block_height + 1, vtxindex, &new_snapshot.burn_header_hash).unwrap();
            assert!(leader_key_opt.is_some());
            assert_eq!(leader_key_opt.unwrap(), leader_key);
            
            let leader_key_none = BurnDB::get_leader_key_at(&mut tx, block_height + 1, vtxindex+1, &new_snapshot.burn_header_hash).unwrap();
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

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();

        let snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };

        // test get_consumed_leader_keys()
        {
            let mut tx = db.tx_begin().unwrap();
            let keys = BurnDB::get_consumed_leader_keys(&mut tx, &snapshot.burn_header_hash, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);
        }

        // test is_leader_key_consumed()
        {
            let mut tx = db.tx_begin().unwrap();
            let is_consumed = BurnDB::is_leader_key_consumed(&mut tx, &leader_key, &snapshot.burn_header_hash).unwrap();
            assert!(!is_consumed);
        }
        
        let snapshot_consumed = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x03; 32]);
            sn.block_height += 1;
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderBlockCommit(block_commit.clone())], &vec![leader_key.clone()]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();

            sn
        };

        {
            let mut tx = db.tx_begin().unwrap();
            let res_block_commits = BurnDB::get_block_commits_by_block(&mut tx, block_height+2, &snapshot_consumed.burn_header_hash).unwrap();
            assert_eq!(res_block_commits.len(), 1);
            assert_eq!(res_block_commits[0], block_commit);

            let no_block_commits = BurnDB::get_block_commits_by_block(&mut tx, block_height+1, &snapshot_consumed.burn_header_hash).unwrap();
            assert_eq!(no_block_commits.len(), 0);
        }
        
        // test is_leader_key_consumed() now that the commit exists
        {
            let mut tx = db.tx_begin().unwrap();
            let is_consumed = BurnDB::is_leader_key_consumed(&mut tx, &leader_key, &snapshot_consumed.burn_header_hash).unwrap();
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
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();

            sn
        };
        
        // test get_block_commit_parent()
        {
            let mut tx = db.tx_begin().unwrap();
            let parent = BurnDB::get_block_commit_parent(&mut tx, block_height + 2, block_commit.vtxindex, &empty_snapshot.burn_header_hash).unwrap();
            assert!(parent.is_some());
            assert_eq!(parent.unwrap(), block_commit);

            let parent = BurnDB::get_block_commit_parent(&mut tx, block_height + 3, block_commit.vtxindex, &empty_snapshot.burn_header_hash).unwrap();
            assert!(parent.is_none());
            
            let parent = BurnDB::get_block_commit_parent(&mut tx, block_height + 2, block_commit.vtxindex + 1, &empty_snapshot.burn_header_hash).unwrap();
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
            let mut tx = db.tx_begin().unwrap();
            let keys = BurnDB::get_consumed_leader_keys(&mut tx, &empty_snapshot.burn_header_hash, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);
        }
        
        // test is_leader_key_consumed() (should be duable at any subsequent index root)
        {
            let mut tx = db.tx_begin().unwrap();
            let is_consumed = BurnDB::is_leader_key_consumed(&mut tx, &leader_key, &empty_snapshot.burn_header_hash).unwrap();
            assert!(is_consumed);
            
            let is_consumed = BurnDB::is_leader_key_consumed(&mut tx, &leader_key, &snapshot.burn_header_hash).unwrap();
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
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();

            sn
        };

        // test get_consumed_leader_keys() and is_leader_key_consumed() against this new fork
        {
            let mut tx = db.tx_begin().unwrap();
            let keys = BurnDB::get_consumed_leader_keys(&mut tx, &fork_snapshot.burn_header_hash, &vec![block_commit.clone()]).unwrap();
            assert_eq!(keys, vec![leader_key.clone()]);

            let is_consumed = BurnDB::is_leader_key_consumed(&mut tx, &leader_key, &fork_snapshot.burn_header_hash).unwrap();
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

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        
        let snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.stacks_block_height += 1;

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
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::UserBurnSupport(user_burn.clone())], &vec![]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };

        {
            let mut tx = db.tx_begin().unwrap();
            let res_user_burns = BurnDB::get_user_burns_by_block(&mut tx, block_height+2, &user_burn_snapshot.burn_header_hash).unwrap();
            assert_eq!(res_user_burns.len(), 1);
            assert_eq!(res_user_burns[0], user_burn);

            let no_user_burns = BurnDB::get_user_burns_by_block(&mut tx, block_height+1, &user_burn_snapshot.burn_header_hash).unwrap();
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

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        
        let no_key_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();
            sn
        };

        let has_key_before = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::has_VRF_public_key(&mut tx, &public_key, &no_key_snapshot.burn_header_hash).unwrap()
        };

        assert!(!has_key_before);

        let key_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x03; 32]);
            sn.block_height += 1;
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderKeyRegister(leader_key.clone())], &vec![]).unwrap();
            sn.index_root = index_root;
            
            tx.commit().unwrap();
            sn
        };

        let has_key_after = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::has_VRF_public_key(&mut tx, &public_key, &key_snapshot.burn_header_hash).unwrap()
        };

        assert!(has_key_after);
    }

    #[test]
    fn is_fresh_consensus_hash() {
        let consensus_hash_lifetime = 24;
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = BurnDB::connect_memory(0, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            let mut last_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
            for i in 0..255 {
                let snapshot_row = BlockSnapshot {
                    block_height: i+1,
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
                    stacks_block_height: i+1,
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
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 255, consensus_hash_lifetime, &ch_fresh, &tip.burn_header_hash).unwrap()
        };

        assert!(fresh_check);

        let oldest_fresh_check = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 255, consensus_hash_lifetime, &ch_oldest_fresh, &tip.burn_header_hash).unwrap()
        };

        assert!(oldest_fresh_check);

        let newest_stale_check = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 255, consensus_hash_lifetime, &ch_newest_stale, &tip.burn_header_hash).unwrap()
        };

        assert!(!newest_stale_check);

        let missing_check = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 255, consensus_hash_lifetime, &ch_missing, &tip.burn_header_hash).unwrap()
        };

        assert!(!missing_check);
    }

    #[test]
    fn get_consensus_at() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("10000000000000000000000000000000000000000000000000000000000000ff").unwrap();
        let mut db = BurnDB::connect_memory(0, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            let mut last_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
            for i in 0..256 {
                let snapshot_row = BlockSnapshot {
                    block_height: i+1,
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
                    stacks_block_height: i+1,
                };
                let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &snapshot_row, &vec![], &vec![]).unwrap();
                last_snapshot = snapshot_row;
                last_snapshot.index_root = index_root;

                // should succeed within the tx 
                let ch = BurnDB::get_consensus_at(&mut tx, i+1, &last_snapshot.burn_header_hash).unwrap();
                assert_eq!(ch, last_snapshot.consensus_hash);
            }

            tx.commit().unwrap();
        }

        let tip = BurnDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

        for i in 0..256 {
            // should succeed within the conn
            let mut tx = db.tx_begin().unwrap();
            let expected_ch = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap();
            let ch = BurnDB::get_consensus_at(&mut tx, i+1, &tip.burn_header_hash).unwrap();
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

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();

        let key_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            let mut sn = BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap();
            
            let sn_parent = sn.clone();
            sn.parent_burn_header_hash = sn.burn_header_hash.clone();
            sn.burn_header_hash = BurnchainHeaderHash([0x01; 32]);
            sn.block_height += 1;
            sn.stacks_block_height += 1;

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
            sn.stacks_block_height += 1;

            let index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &sn_parent, &sn, &vec![BlockstackOperationType::LeaderBlockCommit(block_commit.clone()), BlockstackOperationType::UserBurnSupport(user_burn.clone())], &vec![leader_key.clone()]).unwrap();
            sn.index_root = index_root;

            tx.commit().unwrap();
            sn
        };
    
        {
            let mut tx = db.tx_begin().unwrap();
            let burn_amt = BurnDB::get_block_burn_amount(&mut tx, block_height + 2, &commit_snapshot.burn_header_hash).unwrap();
            assert_eq!(burn_amt, (block_commit.burn_fee + user_burn.burn_fee) as u128);

            let no_burn_amt = BurnDB::get_block_burn_amount(&mut tx, block_height + 1, &commit_snapshot.burn_header_hash).unwrap();
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
            stacks_block_height: 0,
        };

        let mut snapshot_with_sortition = BlockSnapshot {
            block_height: block_height,
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
            stacks_block_height: 1,
        };

        let snapshot_without_sortition = BlockSnapshot {
            block_height: block_height - 1,
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
            stacks_block_height: 0
        };

        let mut db = BurnDB::connect_memory(block_height - 2, &first_burn_hash).unwrap();

        let chain_tip = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_canonical_burn_chain_tip(&mut tx).unwrap()
        };

        let initial_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_last_snapshot_with_sortition(&mut tx, block_height - 2, &chain_tip.burn_header_hash).unwrap()
        };

        first_snapshot.index_root = initial_snapshot.index_root.clone();
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
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_last_snapshot_with_sortition(&mut tx, block_height - 1, &chain_tip.burn_header_hash).unwrap()
        };

        next_snapshot.index_root = initial_snapshot.index_root.clone();
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
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_last_snapshot_with_sortition(&mut tx, block_height, &chain_tip.burn_header_hash).unwrap()
        };

        snapshot_with_sortition.index_root = next_snapshot_2.index_root.clone();
        assert_eq!(snapshot_with_sortition, next_snapshot_2);
    }

    /// Verify that the snapshots in a fork are well-formed -- i.e. the block heights are
    /// sequential and the parent block hash of the ith block is equal to the block hash of the
    /// (i-1)th block.
    fn verify_fork_integrity(db: &mut BurnDB, tip_header_hash: &BurnchainHeaderHash) {
        let mut child = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_block_snapshot(&mut tx, tip_header_hash).unwrap().unwrap()
        };

        let initial = BurnDB::get_first_block_snapshot(db.conn()).unwrap();
       
        test_debug!("Verify from {},hash={},parent={} back to {},hash={},parent={}",
                    child.block_height, child.burn_header_hash.to_hex(), child.parent_burn_header_hash.to_hex(),
                    initial.block_height, initial.burn_header_hash.to_hex(), initial.parent_burn_header_hash.to_hex());

        while child.block_height > initial.block_height {
            let parent = {
                let mut tx = db.tx_begin().unwrap();
                BurnDB::get_block_snapshot_in_fork(&mut tx, child.block_height - 1, &child.burn_header_hash).unwrap().unwrap()
            };

            test_debug!("Verify {} == {} - 1 and hash={},parent_hash={} == parent={}",
                        parent.block_height, child.block_height,
                        child.burn_header_hash.to_hex(), parent.burn_header_hash.to_hex(), child.parent_burn_header_hash.to_hex());

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

        let mut db = BurnDB::connect_memory(first_block_height, &first_burn_hash).unwrap();

        // make an initial fork
        let mut last_snapshot = BurnDB::get_first_block_snapshot(db.conn()).unwrap();

        for i in 0..10 {
            let mut next_snapshot = last_snapshot.clone();

            next_snapshot.block_height += 1;
            next_snapshot.stacks_block_height += 1;
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
            let mut parent_block_hash =
                if i == 0 {
                    [0u8; 32]
                }
                else {
                    let mut tmp = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(i+1) as u8];
                    tmp[i-1] = 1;
                    tmp
                };
            
            let parent_block = BurnchainHeaderHash(parent_block_hash);
            test_debug!("----- build fork off of parent {} (i = {}) -----", &parent_block.to_hex(), i);

            let mut last_snapshot = BurnDB::get_block_snapshot(db.conn(), &parent_block).unwrap().unwrap();

            let initial_block_height = last_snapshot.block_height;
            let initial_stacks_block_height = last_snapshot.stacks_block_height;

            let mut next_snapshot = last_snapshot.clone();

            for j in (i+1)..10 {
            
                let mut block_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(j+1) as u8];
                block_hash[i] = (j - i) as u8;

                next_snapshot.block_height = initial_block_height + (j - i) as u64;
                next_snapshot.stacks_block_height = initial_stacks_block_height + (j - i) as u64;
                next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
                next_snapshot.burn_header_hash = BurnchainHeaderHash(block_hash);
                next_snapshot.consensus_hash = ConsensusHash([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,j as u8,(i + 1) as u8]);

                let mut tx = db.tx_begin().unwrap();
                let next_index_root = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot, &vec![], &vec![]).unwrap();
                tx.commit().unwrap();

                next_snapshot.index_root = next_index_root;
                last_snapshot = next_snapshot.clone();
            }
        
            test_debug!("----- made fork {} (i = {}) -----", &next_snapshot.burn_header_hash.to_hex(), i);
        }

        test_debug!("----- grow forks -----");

        let mut all_chain_tips = vec![];

        // grow each fork so it overtakes the currently-canonical fork
        for i in 0..9 {
            let mut last_block_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10];
            last_block_hash[i] = (9 - i) as u8;
            let last_block = BurnchainHeaderHash(last_block_hash);
            
            test_debug!("----- grow fork {} (i = {}) -----", &last_block.to_hex(), i);

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
                next_snapshot.stacks_block_height = last_snapshot.stacks_block_height + 1;
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
            next_snapshot.stacks_block_height += 1;
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
}
