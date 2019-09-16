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

use std::fs;
use std::convert::From;

use util::db::{FromRow, RowOrder, query_rows, query_count};
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
use chainstate::stacks::StacksBlockHeader;
use chainstate::stacks::StacksMicroblockHeader;
use chainstate::stacks::index::TrieHash;

use address::AddressHashMode;

use util::log;
use util::vrf::*;
use util::hash::{to_hex, hex_bytes, Hash160};

const BLOCK_HEIGHT_MAX : u64 = ((1 as u64) << 63) - 1; 
const FORK_SEGMENT_ID_MAX : u64 = ((1 as u64) << 63) - 1;
const SQLITE_ERROR_MSG : &'static str = "FATAL: failed to exeucte Sqlite database operation.  Aborting...";

impl RowOrder for BlockSnapshot {
    fn row_order() -> Vec<&'static str> {
        vec!["block_height","burn_header_hash","parent_burn_header_hash","consensus_hash","ops_hash","total_burn","sortition","sortition_hash","winning_block_txid","winning_stacks_block_hash",
             "fork_segment_id","parent_fork_segment_id","fork_length","fork_segment_length"]
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
        let fork_segment_id_i64 : i64 = row.get(10 + index);
        let parent_fork_segment_id_i64 : i64 = row.get(11 + index);
        let fork_length_i64 : i64 = row.get(12 + index);
        let fork_segment_length_i64 : i64 = row.get(13 + index);

        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        if fork_segment_id_i64 < 0 {
            return Err(db_error::ParseError);
        }

        if fork_length_i64 < 0 {
            return Err(db_error::ParseError);
        }
        
        if fork_segment_length_i64 < 0 {
            return Err(db_error::ParseError);
        }

        if parent_fork_segment_id_i64 < 0 {
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
            fork_segment_id: fork_segment_id_i64 as u64,
            parent_fork_segment_id: parent_fork_segment_id_i64 as u64,
            fork_length: fork_length_i64 as u64,
            fork_segment_length: fork_segment_length_i64 as u64
        };
        Ok(snapshot)
    }
}

impl RowOrder for LeaderKeyRegisterOp {
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","consensus_hash","public_key","memo","address","fork_segment_id"]
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
        let fork_segment_id_i64 : i64 = row.get(8 + index);

        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        if block_height < 0 {
            return Err(db_error::ParseError);
        }

        if fork_segment_id_i64 < 0 {
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

            fork_segment_id: fork_segment_id_i64 as u64
        };

        Ok(leader_key_row)
    }
}

impl RowOrder for LeaderBlockCommitOp {
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","block_header_hash","new_seed",
             "parent_block_backptr","parent_vtxindex","key_block_backptr","key_vtxindex",
             "epoch_num","memo","burn_fee","input","fork_segment_id"]
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
        let parent_block_backptr : u16 = row.get(6 + index);
        let parent_vtxindex: u16 = row.get(7 + index);
        let key_block_backptr : u16 = row.get(8 + index);
        let key_vtxindex : u16 = row.get(9 + index);
        let epoch_num : u32 = row.get(10 + index);
        let memo_hex : String = row.get(11 + index);
        let burn_fee_str : String = row.get(12 + index);
        let input_json : String = row.get(13 + index);
        let fork_segment_id_i64 : i64 = row.get(14 + index);

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

        if fork_segment_id_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: block_header_hash,
            new_seed: new_seed,
            parent_block_backptr: parent_block_backptr,
            parent_vtxindex: parent_vtxindex,
            key_block_backptr: key_block_backptr,
            key_vtxindex: key_vtxindex,
            epoch_num: epoch_num,
            memo: memo,

            burn_fee: burn_fee,
            input: input,

            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height as u64,
            burn_header_hash: burn_header_hash,

            fork_segment_id: fork_segment_id_i64 as u64
        };
        Ok(block_commit)
    }
}

impl RowOrder for UserBurnSupportOp {
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","consensus_hash","public_key","key_block_backptr","key_vtxindex","block_header_hash_160","memo","burn_fee","fork_segment_id"]
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
        let key_block_backptr: u16 = row.get(6 + index);
        let key_vtxindex : u16 = row.get(7 + index);
        let block_header_hash_160 = Hash160::from_row(row, 8 + index)?;
        let memo_hex : String = row.get(9 + index);

        let burn_fee_str : String = row.get(10 + index);

        let fork_segment_id_i64 : i64 = row.get(11 + index);
        
        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        let burn_fee = burn_fee_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        if block_height < 0 {
            return Err(db_error::ParseError);
        }

        if fork_segment_id_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let user_burn = UserBurnSupportOp {
            consensus_hash: consensus_hash,
            public_key: public_key,
            key_block_backptr: key_block_backptr,
            key_vtxindex: key_vtxindex,
            block_header_hash_160: block_header_hash_160,
            memo: memo,
            burn_fee: burn_fee,

            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height as u64,
            burn_header_hash: burn_header_hash,

            fork_segment_id: fork_segment_id_i64 as u64
        };
        Ok(user_burn)
    }
}

impl RowOrder for StacksBlockHeader {
    fn row_order() -> Vec<&'static str> {
        vec!["version", "total_burn", "total_work", "proof", "parent_block", "parent_microblock", "parent_microblock_sequence", "tx_merkle_root", "state_index_root", "microblock_pubkey", "block_hash", "block_height", "fork_segment_id"]
    }
}

impl FromRow<StacksBlockHeader> for StacksBlockHeader {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StacksBlockHeader, db_error> {
        let version : u8 = row.get(0 + index);
        let total_burn_str : String = row.get(1 + index);
        let total_work_str : String = row.get(2 + index);
        let proof : VRFProof = VRFProof::from_row(row, 3 + index)?;
        let parent_block = BlockHeaderHash::from_row(row, 4 + index)?;
        let parent_microblock = BlockHeaderHash::from_row(row, 5 + index)?;
        let parent_microblock_sequence = BlockHeaderHash::from_row(row, 6 + index)?;
        let tx_merkle_root = Sha512_256::from_row(row, 7 + index)?;
        let state_index_root = TrieHash::from_row(row, 8 + index)?;
        let microblock_pubkey = StacksPublicKey::from_row(row, 9 + index)?;

        let block_hash = BlockHeaderHash::from_row(row, 10 + index)?;
        let block_height_i64 : i64 = row.get(11 + index);
        let fork_segment_id_i64 : i64 = row.get(12 + index);

        let total_burn = total_burn_str.parse::<u64>().map_err(|e| db_error::ParseError)?;
        let total_work = total_work_str.parse::<u64>().map_err(|e| db_error::ParseError)?;

        // checked but not used
        if fork_segment_id_i64 < 0 {
            return Err(db_error::ParseError);
        }

        // checked but not used
        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let header = StacksBlockHeader {
            version,
            total_work: StacksWorkScore { burn: total_burn, work: total_work },
            proof,
            parent_block,
            parent_microblock,
            parent_microblock_sequence,
            tx_merkle_root,
            state_index_root,
            microblock_pubkey
        };

        if header.block_hash() != block_hash {
            return Err(db_error::ParseError);
        }

        Ok(header)
    }
}

impl RowOrder for StacksMicroblockHeader {
    fn row_order() -> Vec<&'static str> {
        vec!["version", "sequence", "prev_block", "tx_merkle_root", "signature", "microblock_hash", "parent_block_hash", "block_height", "fork_segment_id"]
    }
}

impl FromRow<StacksMicroblockHeader> for StacksMicroblockHeader {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<StacksMicroblockHeader, db_error> {
        let version : u8 = row.get(0 + index);
        let sequence : u8 = row.get(1 + index);
        let prev_block = BlockHeaderHash::from_row(2 + index)?;
        let tx_merkle_root = Sha512_256::from_row(3 + index)?;
        let signature = MessageSignature::from_row(4 + index)?;

        let microblock_hash = BlockHeaderHash::from_row(5 + index)?;
        let parent_block_hash = BlockHeaderHash::from_row(6 + index)?;
        let block_height_i64 : i64 = row.get(7 + index);
        let fork_segment_id_i64 : i64 = row.get(8 + index);
        
        // checked but not used
        if fork_segment_id_i64 < 0 {
            return Err(db_error::ParseError);
        }

        // checked but not used
        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let microblock_header = StacksMicroblockHeader {
           version,
           sequence,
           prev_block,
           tx_merkle_root,
           signature
        };
        
        if microblock_hash != microblock_header.block_hash() {
            return Err(db_error::ParseError);
        }

        Ok(microblock_header)
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

        fork_segment_id INTEGER NOT NULL,
        parent_fork_segment_id INTEGER NOT NULL,
        fork_length INTEGER NOT NULL,           -- total fork length inductively calculated as more snapshots are appended
        fork_segment_length INTEGER NOT NULL,   -- length of this fork segment's "run", also calculated inductively
        PRIMARY KEY(block_height,fork_segment_id)
    );"#,
    r#"
    CREATE UNIQUE INDEX snapshots_block_hashes(block_height,fork_segment_id,winning_stacks_block_hash);
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

        fork_segment_id INTEGER NOT NULL,

        PRIMARY KEY(txid,burn_header_hash,fork_segment_id),

        -- deferred foreign key to snapshots so updating these values is efficient and fork table compression is possible
        FOREIGN KEY(block_height,fork_segment_id) REFERENCES snapshots(block_height,fork_segment_id) DEFERRABLE INITIALLY DEFERRED
    );"#,
    r#"
    CREATE TABLE block_commits(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        block_header_hash TEXT NOT NULL,
        new_seed TEXT NOT NULL,
        parent_block_backptr INTEGER NOT NULL,
        parent_vtxindex INTEGER NOT NULL,
        key_block_backptr INTEGER NOT NULL,
        key_vtxindex INTEGER NOT NULL,
        epoch_num INTEGER NOT NULL,
        memo TEXT,
        
        burn_fee TEXT NOT NULL,     -- use text to encode really big numbers
        input TEXT NOT NULL,        -- must match `address` in leader_keys

        fork_segment_id INTEGER NOT NULL,

        PRIMARY KEY(txid,burn_header_hash,fork_segment_id),
        
        -- deferred foreign key to snapshots so updating these values is efficient and fork table compression is possible
        FOREIGN KEY(block_height,fork_segment_id) REFERENCES snapshots(block_height,fork_segment_id) DEFERRABLE INITIALLY DEFERRED
    );"#,
    r#"
    CREATE TABLE user_burn_support(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        key_block_backptr INTEGER NOT NULL,
        key_vtxindex INTEGER NOT NULL,
        block_header_hash_160 TEXT NOT NULL,
        memo TEXT,

        burn_fee TEXT NOT NULL,

        fork_segment_id INTEGER NOT NULL,

        PRIMARY KEY(txid,burn_header_hash,fork_segment_id),
        
        -- deferred foreign key to snapshots so updating these values is efficient and fork table compression is possible
        FOREIGN KEY(block_height,fork_segment_id) REFERENCES snapshots(block_height,fork_segment_id) DEFERRABLE INITIALLY DEFERRED
    );"#,
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
        microblock_pubkey TEXT NOT NULL,
        
        -- NOTE: this is derived from the above
        block_hash TEXT NOT NULL,

        -- internal use only
        block_height INTEGER NOT NULL,
        fork_segment_id INTEGER NOT NULL,

        PRIMARY KEY(block_hash),

        -- deferred foreign key to snapshots so updating this value is efficient and fork table compression is possible
        FOREIGN KEY(block_height,fork_segment_id,block_hash) REFERENCES snapshots(block_height,fork_segment_id,winning_stacks_block_hash) DEFERRABLE INITIALLY DEFERRED
    );"#,
    r#"
    CREATE INDEX block_headers_hash_index on block_headers(block_hash,block_height,fork_segment_id);
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
        fork_segment_id INTEGER NOT NULL,
        parent_block_hash TEXT NOT NULL,    -- matches the block header (and by extension, snapshot and block commit) to which this stream is appended
        
        PRIMARY KEY(microblock_hash),
        
        -- deferred foreign key to snapshots so updating this value is efficient and fork table compression is possible
        FOREIGN KEY(block_height,fork_segment_id,parent_block_hash) REFERENCES snapshots(block_height,fork_segment_id,winning_stacks_block_hash) DEFERRABLE INITIALLY DEFERRED
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];

pub struct BurnDB {
    pub conn: Connection,
    pub readwrite: bool,
    pub first_block_height: u64,
    pub first_burn_header_hash: BurnchainHeaderHash,
}

impl BurnDB {
    fn instantiate(&mut self) -> Result<(), db_error> {
        // create first (sentinel) snapshot
        let first_snapshot = BlockSnapshot::initial(self.first_block_height, &self.first_burn_header_hash);
        let mut tx = self.tx_begin()?;

        for row_text in BURNDB_SETUP {
            tx.execute(row_text, NO_PARAMS)
                .expect(SQLITE_ERROR_MSG);
        }

        tx.execute("INSERT INTO db_version (version) VALUES (?1)", &[&CHAINSTATE_VERSION])
            .expect(SQLITE_ERROR_MSG);

        BurnDB::insert_block_snapshot(&mut tx, &first_snapshot)?;
        tx.commit()
            .expect(SQLITE_ERROR_MSG);

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

        let conn = Connection::open_with_flags(path, open_flags)
            .expect(SQLITE_ERROR_MSG);

        let mut db = BurnDB {
            conn: conn,
            readwrite: readwrite,
            first_block_height: first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
        };

        if create_flag {
            // instantiate!
            db.instantiate()?;
        }
        else {
            // validate -- must contain the given first block and first block hash 
            let snapshot_opt = BurnDB::get_block_snapshot(&db.conn, first_burn_hash)?;
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

        Ok(db)
    }

    /// Open a burn database in memory (used for testing)
    #[cfg(test)]
    pub fn connect_memory(first_block_height: u64, first_burn_hash: &BurnchainHeaderHash) -> Result<BurnDB, db_error> {
        let conn = Connection::open_in_memory()
            .expect(SQLITE_ERROR_MSG);

        let mut db = BurnDB {
            conn: conn,
            readwrite: true,
            first_block_height: first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
        };

        db.instantiate()?;
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

        let conn = Connection::open_with_flags(path, open_flags)
            .expect(SQLITE_ERROR_MSG);

        let first_snapshot = BurnDB::get_first_block_snapshot(&conn)?;

        let db = BurnDB {
            conn: conn,
            readwrite: readwrite,
            first_block_height: first_snapshot.block_height,
            first_burn_header_hash: first_snapshot.burn_header_hash.clone(),
        };
        Ok(db)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Get a particular chain tip's snapshot if the arguments here actually correspond to a chain
    /// tip.  If not, then return None.
    /// Insert a snapshots row from a block's-worth of operations. 
    /// Do not call directly -- use append_chain_tip_snapshot to preserve the fork table structure.
    fn insert_block_snapshot<'a>(tx: &mut Transaction<'a>, snapshot: &BlockSnapshot) -> Result<(), db_error> {
        assert!(snapshot.block_height < BLOCK_HEIGHT_MAX);
        assert!(snapshot.fork_segment_id < FORK_SEGMENT_ID_MAX);

        test_debug!("Insert block snapshot on fork segment {} parent {} for block {} ({},{})", snapshot.fork_segment_id, snapshot.parent_fork_segment_id, snapshot.block_height,
                    snapshot.burn_header_hash.to_hex(), snapshot.parent_burn_header_hash.to_hex());        

        let total_burn_str = format!("{}", snapshot.total_burn);

        tx.execute("INSERT INTO snapshots \
                   (block_height, burn_header_hash, parent_burn_header_hash, consensus_hash, ops_hash, total_burn, sortition, sortition_hash, winning_block_txid, winning_stacks_block_hash, fork_segment_id, parent_fork_segment_id, fork_length, fork_segment_length) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                   &[&(snapshot.block_height as i64) as &ToSql, &snapshot.burn_header_hash.to_hex(), &snapshot.parent_burn_header_hash.to_hex(), &snapshot.consensus_hash.to_hex(), &snapshot.ops_hash.to_hex(), &total_burn_str,
                     &snapshot.sortition as &ToSql, &snapshot.sortition_hash.to_hex(), &snapshot.winning_block_txid.to_hex(), &snapshot.winning_stacks_block_hash.to_hex(), &(snapshot.fork_segment_id as i64) as &ToSql,
                     &(snapshot.parent_fork_segment_id as i64) as &ToSql, &(snapshot.fork_length as i64) as &ToSql, &(snapshot.fork_segment_length as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        Ok(())
    }
    
    /// Get the list of children blocks from a given header hash
    fn get_block_children<'a>(tx: &mut Transaction<'a>, parent_header_hash: &BurnchainHeaderHash) -> Result<Vec<BlockSnapshot>, db_error> {
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE parent_burn_header_hash = ?1 ORDER BY fork_segment_id ASC", row_order);
        let rows = query_rows::<BlockSnapshot, _>(tx, &qry, &[&parent_header_hash.to_hex()])
            .expect(SQLITE_ERROR_MSG);

        Ok(rows)
    }

    /// Compactify the fork table after appending a block.
    /// Returns the fork segment it is ultimately assigned to
    fn compactify_fork_table<'a>(tx: &mut Transaction<'a>, appended_snapshot: &BlockSnapshot) -> Result<u64, db_error> {
        let mut snapshot = appended_snapshot.clone();

        loop {

            /*
            #[cfg(test)]
            {
                test_debug!("Before compaction:");
                let max_fork_id = BurnDB::next_unused_fork_segment_id(tx).expect(SQLITE_ERROR_MSG);
                for cur_fork_segment_id in 0..max_fork_id {
                    test_debug!("snapshots in fork {}:", cur_fork_segment_id);
                    let snapshots = BurnDB::get_block_snapshots_in_fork_segment(tx, cur_fork_segment_id).unwrap();
                    for sn in snapshots {
                        test_debug!("block {}: hash={},parent={}, fid: {}, pfid: {}", sn.block_height, sn.burn_header_hash.to_hex(), sn.parent_burn_header_hash.to_hex(), sn.fork_segment_id, sn.parent_fork_segment_id);
                    }
                }
            }
            */

            test_debug!("Find sibling-parent {} from {}", snapshot.parent_fork_segment_id, snapshot.fork_segment_id);

            // find sibling branch that descends from the parent
            let sibling_snapshot = BurnDB::get_fork_segment_tail(tx, snapshot.parent_fork_segment_id)
                .expect(SQLITE_ERROR_MSG)
                .expect("FATAL: no parent block snapshot");

            // has this fork segment outgrown its parent? if so, make it the parent, and make
            // the part of the parent that it conflicts with into its sibling segment.
            if sibling_snapshot.block_height < snapshot.block_height {
                let snapshot_head = BurnDB::get_fork_segment_head(tx, snapshot.fork_segment_id)
                    .expect(SQLITE_ERROR_MSG)
                    .expect("FATAL: no sibling head block snapshot");
                
                test_debug!("Exchange sibling-parent {} with {} starting at {} (fork segment head is {},{})",
                            snapshot.parent_fork_segment_id, snapshot.fork_segment_id, snapshot_head.block_height,
                            sibling_snapshot.burn_header_hash.to_hex(), sibling_snapshot.parent_burn_header_hash.to_hex());

                // switch the fork segment IDs and parent fork segment IDs of all descendents of the parent after this
                // snapshot's head.  The fork segment ID of the snapshot we're storing will
                // merge with its parent, and the sibling snapshots previously in the parent
                // segment will receive the old fork segment ID.
                // how it works:
                // notation:
                //              ${height}${hash}${parent}(${fid}${pfid})- ...
                //              where
                //                  ${height} == block height
                //                  ${hash}   == burn block header hash
                //                  ${parent} == parent burn block header hash
                //                  ${fid}    == fork segment ID
                //                  ${pfid}   == parent fork segment ID
                //
                //      example: 100ab(3,4)
                //                  height: 100
                //                  hash:   a
                //                  parent: b
                //                  fid:    3
                //                  pfid:   4
                //
                // Suppose we append to fork segment 2, below (block 112__(2,0))
                // before:
                // * the canonical fork is fork segment 2, which is connected to fork segment 0
                // goal:
                // * merge fork segments 0 and 2 so that fork segment 0 is canonical
                //
                //                                  103kh(3,2)-104lk(3,2)-105ml(3,2)-106__(3,2)-107__(3,2)-108__(3,2)-109__(3,2)
                //                                 /
                //                       102hb(2,0)-103ih(2,0)-104ji(2,0)-105__(2,0)-106__(2,0)-107__(2,0)-108__(2,0)-109__(2,0)-110__(2,0)-111__(2,0)-112__(2,0)
                //                      /
                // 100aa(0,0)-101ba(0,0)-102cb(0,0)-103dc(0,0)-104__(0,0)-105__(0,0)-106__(0,0)-107__(0,0)-108__(0,0)-109__(0,0)-110__(0,0)-111__(0,0)
                //           \
                //            101ea(1,0)-102fe(1,0)-103gf(1,0)-104__(1,0)-105__(1,0)-106__(1,0)-107__(1,0)-108__(1,0)-109__(1,0)-110__(1,0)
                //
                //
                // after fork_segment_rename 
                // - rename 0 to 10 after 102
                // - rename 2 to 0 after 102
                // - rename 10 to 2 after 102
                //
                //                                  103kh(3,2)-104lk(3,2)-105ml(3,2)-106__(3,2)-107__(3,2)-108__(3,2)-109__(3,2)
                //                                 /
                //                       102cb(2,0)-103dc(2,0)-104__(2,0)-105__(2,0)-106__(2,0)-107__(2,0)-108__(2,0)-109__(2,0)-110__(2,0)-111__(2,0)
                //                      /
                // 100aa(0,0)-101ba(0,0)-102hb(0,0)-103ih(0,0)-104ji(0,0)-105__(0,0)-106__(0,0)-107__(0,0)-108__(0,0)-109__(0,0)-110__(0,0)-111__(0,0)-112__(0,0)
                //           \
                //            101ea(1,0)-102fe(1,0)-103gf(1,0)-104__(1,0)-105__(1,0)-106__(1,0)-107__(1,0)-108__(1,0)-109__(1,0)-110__(1,0)
                //
                // after parent_fork_segment_rename 
                // - rename parent 0 to 10, ignoring if fork is 0 or 2 and only if the segment starts after 102
                // - rename parent 2 to 0   ignoring if fork is 0 or 2 and only if the segment starts after 102
                // - rename parent 10 to 2  ignoring if fork is 0 or 2 and only if the segment starts after 102
                //
                //                       102cb(2,0)-103dc(2,0)-104__(2,0)-105__(2,0)-106__(2,0)-107__(2,0)-108__(2,0)-109__(2,0)-110__(2,0)-111__(2,0)
                //                      /
                //                      |           103kh(3,0)-104lk(3,0)-105ml(3,0)-106__(3,0)-107__(3,0)-108__(3,0)-109__(3,0)
                //                      |          /
                // 100aa(0,0)-101ba(0,0)-102hb(0,0)-103ih(0,0)-104ji(0,0)-105__(0,0)-106__(0,0)-107__(0,0)-108__(0,0)-109__(0,0)-110__(0,0)-111__(0,0)-112__(0,0)
                //           \
                //            101ea(1,0)-102fe(1,0)-103gf(1,0)-104__(1,0)-105__(1,0)-106__(1,0)-107__(1,0)-108__(1,0)-109__(1,0)-110__(1,0)
                //
                // Now, fork segment 0 is the longest (canonical) fork, and the fork segments are
                // all well-formed again.

                let tmp_fork_segment_id = BurnDB::next_unused_fork_segment_id(tx).expect(SQLITE_ERROR_MSG);
                
                // sibling-in-parent --> tmp
                BurnDB::fork_segment_rename(tx, snapshot_head.block_height, sibling_snapshot.fork_segment_id, tmp_fork_segment_id, snapshot.fork_segment_id)
                    .expect(SQLITE_ERROR_MSG);
                
                // sibling --> sibling-in-parent
                BurnDB::fork_segment_rename(tx, snapshot_head.block_height, snapshot.fork_segment_id, sibling_snapshot.fork_segment_id, sibling_snapshot.parent_fork_segment_id)
                    .expect(SQLITE_ERROR_MSG);
                
                // tmp --> sibling
                BurnDB::fork_segment_rename(tx, snapshot_head.block_height, tmp_fork_segment_id, snapshot.fork_segment_id, snapshot.parent_fork_segment_id)
                    .expect(SQLITE_ERROR_MSG);

                // anyone that had the now-merged snapshot fork segment as its parent needs to be updated
                BurnDB::parent_fork_segment_rename(tx, snapshot_head.block_height, snapshot.fork_segment_id, sibling_snapshot.fork_segment_id, sibling_snapshot.fork_segment_id, tmp_fork_segment_id)
                    .expect(SQLITE_ERROR_MSG);

                BurnDB::parent_fork_segment_rename(tx, snapshot_head.block_height, snapshot.fork_segment_id, sibling_snapshot.fork_segment_id, snapshot.fork_segment_id, sibling_snapshot.fork_segment_id)
                    .expect(SQLITE_ERROR_MSG);

                BurnDB::parent_fork_segment_rename(tx, snapshot_head.block_height, snapshot.fork_segment_id, sibling_snapshot.fork_segment_id, tmp_fork_segment_id, snapshot.fork_segment_id)
                    .expect(SQLITE_ERROR_MSG);

                // compactify sibling
                snapshot = BurnDB::get_fork_segment_tail(tx, sibling_snapshot.fork_segment_id)
                    .expect(SQLITE_ERROR_MSG)
                    .expect("FATAL: no parent block snapshot");
                
                continue;
            }
            else {
                test_debug!("Fork segment {} is at least as long ({}) as its sibling-parent {} ({})", snapshot.fork_segment_id, snapshot.block_height, sibling_snapshot.fork_segment_id, sibling_snapshot.block_height);
                return Ok(snapshot.fork_segment_id);
            }
        }
    }

    /// Append a snapshot to a chain tip, and update various chain tip statistics.
    /// Returns the fork segment ID to which the snapshot was appended (post-compaction)
    pub fn append_chain_tip_snapshot<'a>(tx: &mut Transaction<'a>, parent_snapshot: &BlockSnapshot, snapshot: &BlockSnapshot) -> Result<u64, db_error> {
        let appended_fork_segment_id =
            if parent_snapshot.fork_segment_id == snapshot.fork_segment_id {
                // building onto an existing chain tip
                test_debug!("Append to existing chain fork segment {} at block {} (on parent block {})", snapshot.fork_segment_id, snapshot.block_height, parent_snapshot.block_height);

                assert_eq!(parent_snapshot.block_height + 1, snapshot.block_height);
                assert_eq!(parent_snapshot.fork_segment_length + 1, snapshot.fork_segment_length);
                assert_eq!(parent_snapshot.fork_length + 1, snapshot.fork_length);
                assert_eq!(parent_snapshot.burn_header_hash, snapshot.parent_burn_header_hash);

                BurnDB::insert_block_snapshot(tx, &snapshot).expect(SQLITE_ERROR_MSG);
                BurnDB::compactify_fork_table(tx, &snapshot).expect(SQLITE_ERROR_MSG)
            }
            else {
                // building a new chain tip
                test_debug!("Begin new chain fork segment {} at {} (parent fork segment {} height {})", snapshot.fork_segment_id, snapshot.block_height, parent_snapshot.fork_segment_id, parent_snapshot.block_height);
               
                assert_eq!(parent_snapshot.block_height + 1, snapshot.block_height);
                assert_eq!(snapshot.fork_segment_length, 1);
                assert_eq!(parent_snapshot.fork_length + 1, snapshot.fork_length);
                assert_eq!(parent_snapshot.burn_header_hash, snapshot.parent_burn_header_hash);
                
                BurnDB::insert_block_snapshot(tx, &snapshot).expect(SQLITE_ERROR_MSG);

                snapshot.fork_segment_id
            };

        Ok(appended_fork_segment_id)
    }

    /// Change the fork segment ID in some snapshots in fork segment, i.e. to handle reorgs.
    /// Updates the various blockstack ops tables as well due to foreign key constraint.
    fn fork_segment_rename<'a>(tx: &mut Transaction<'a>, block_height: u64, fork_segment_id: u64, new_fork_segment_id: u64, new_parent_fork_segment_id: u64) -> Result<(), db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);
        assert!(new_fork_segment_id < FORK_SEGMENT_ID_MAX);
        assert!(new_parent_fork_segment_id < FORK_SEGMENT_ID_MAX);

        test_debug!("Rename fork segment {} to {} (parent {}) starting at block {}", fork_segment_id, new_fork_segment_id, new_parent_fork_segment_id, block_height);

        let snapshot_qry = "UPDATE snapshots SET fork_segment_id = ?1, parent_fork_segment_id = ?2 WHERE fork_segment_id = ?3 AND block_height >= ?4";
        let snapshot_args = [&(new_fork_segment_id as i64) as &ToSql, &(new_parent_fork_segment_id as i64) as &ToSql, &(fork_segment_id as i64) as &ToSql, &(block_height as i64) as &ToSql];

        if fork_segment_id != new_fork_segment_id {
            let op_update_template = "UPDATE {} SET fork_segment_id = ?1 WHERE fork_segment_id = ?2 AND block_height >= ?3";
            let op_update_args = [&(new_fork_segment_id as i64) as &ToSql, &(fork_segment_id as i64) as &ToSql, &(block_height as i64) as &ToSql];

            tx.execute(&snapshot_qry.to_string(), &snapshot_args).expect(SQLITE_ERROR_MSG);
            tx.execute("UPDATE leader_keys SET fork_segment_id = ?1 WHERE fork_segment_id = ?2 AND block_height >= ?3", &op_update_args).expect(SQLITE_ERROR_MSG);
            tx.execute("UPDATE block_commits SET fork_segment_id = ?1 WHERE fork_segment_id = ?2 AND block_height >= ?3", &op_update_args).expect(SQLITE_ERROR_MSG);
            tx.execute("UPDATE user_burn_support SET fork_segment_id = ?1 WHERE fork_segment_id = ?2 AND block_height >= ?3", &op_update_args).expect(SQLITE_ERROR_MSG);
            tx.execute("UPDATE block_headers SET fork_segment_id = ?1 WHERE fork_segment_id = ?2 AND block_height >= ?3", &op_update_args).expect(SQLITE_ERROR_MSG);
            tx.execute("UPDATE microblock_headers SET fork_segment_id = ?1 WHERE fork_segment_id = ?2 AND block_height >= ?3", &op_update_args).expect(SQLITE_ERROR_MSG);
        }

        Ok(())
    }

    /// Rename a set of snapshots' parent fork IDs
    fn parent_fork_segment_rename<'a>(tx: &mut Transaction<'a>, head_block_height: u64, fork_segment_id: u64, sibling_fork_segment_id: u64, parent_fork_segment_id: u64, new_parent_fork_segment_id: u64) -> Result<(), db_error> {
        assert!(parent_fork_segment_id < FORK_SEGMENT_ID_MAX);
        assert!(new_parent_fork_segment_id < FORK_SEGMENT_ID_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);
        assert!(sibling_fork_segment_id < FORK_SEGMENT_ID_MAX);
        assert!(head_block_height < BLOCK_HEIGHT_MAX);

        test_debug!("Rename parent fork segment {} to {} if it joins at or after {}, ignoring {} and {}", parent_fork_segment_id, new_parent_fork_segment_id, head_block_height, fork_segment_id, sibling_fork_segment_id);

        let snapshot_qry = "UPDATE snapshots SET parent_fork_segment_id = ?1 WHERE parent_fork_segment_id = ?2 AND fork_segment_id != ?3 AND fork_segment_id != ?4 AND \
                           0 == (SELECT COUNT(*) FROM snapshots WHERE block_height <= ?5 AND parent_fork_segment_id = ?6)";
        let snapshot_args = [&(new_parent_fork_segment_id as i64) as &ToSql, &(parent_fork_segment_id as i64) as &ToSql, &(fork_segment_id as i64) as &ToSql, &(sibling_fork_segment_id as i64) as &ToSql,
                             &(head_block_height as i64) as &ToSql, &(parent_fork_segment_id as i64) as &ToSql];
        
        tx.execute(&snapshot_qry.to_string(), &snapshot_args).expect(SQLITE_ERROR_MSG);
        Ok(())
    }

    /// Get the canonical chain tips -- the longest chain tip we know about.
    pub fn get_canonical_chain_tip(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        // break ties in block height by building on the longer fork.
        // break ties in forks of the same length by building on the longer segment
        // break ties in forks of the same length and segment length arbitrarily -- i.e. by fork ID
        let row_order = BlockSnapshot::row_order().join(",");
        let sql_qry = format!("SELECT {} FROM snapshots ORDER BY block_height DESC, fork_length DESC, fork_segment_length DESC, fork_segment_id DESC LIMIT 1", row_order);
        let rows = query_rows::<BlockSnapshot, _>(conn, &sql_qry.to_string(), NO_PARAMS)
            .expect(SQLITE_ERROR_MSG);

        match rows.len() {
            1 => Ok(rows[0].clone()),
            _ => {
                // should never happen 
                panic!("FATAL: could not get a chain tip, or got duplicate chain tip");
            }
        }
    }

    /// Get the next unallocated fork segment ID
    pub fn next_unused_fork_segment_id<'a>(tx: &mut Transaction<'a>) -> Result<u64, db_error> {
        let qry = "SELECT MAX(fork_segment_id) FROM snapshots";
        let mut stmt = tx.prepare(qry).expect(SQLITE_ERROR_MSG);

        let m = stmt.query_row(NO_PARAMS,
            |row| {
                let res : i64 = row.get(0);
                res
            })
            .expect(SQLITE_ERROR_MSG);

        Ok((m as u64) + 1)
    }

    /// Get the fork segment ID that will contain the given a block with the given parent, if we
    /// were to insert a snapshot for it.
    pub fn get_next_fork_segment_id<'a>(tx: &mut Transaction<'a>, parent_snapshot: &BlockSnapshot) -> Result<Option<u64>, db_error> {
        let child_qry = "SELECT COUNT(*) FROM snapshots WHERE parent_burn_header_hash = ?1".to_string();
        let child_count = query_count(tx, &child_qry.to_string(), &[&parent_snapshot.burn_header_hash.to_hex() as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        if child_count == 0 || (child_count == 1 && parent_snapshot.is_initial()) {
            // this is the chain tip -- append to this parent
            test_debug!("Snapshot {} is the chain tip (fork segment {})", parent_snapshot.burn_header_hash.to_hex(), parent_snapshot.fork_segment_id);
            Ok(Some(parent_snapshot.fork_segment_id))
        }
        else {
            // this is not the chain tip.  Find the next fork segment
            test_debug!("Snapshot {} is NOT the chain tip -- has {} children", parent_snapshot.burn_header_hash.to_hex(), child_count);
            let fork_segment_id = BurnDB::next_unused_fork_segment_id(tx).expect(SQLITE_ERROR_MSG);
            Ok(Some(fork_segment_id))
        }
    }


    /// Get the sequence of fork segments that are parent/children of one another.
    /// The nth fork segment ID is the child of the n+1th.
    /// The last fork segment is the genesis block's segment.
    fn get_ancestor_fork_segments(conn: &Connection, fork_segment_id: u64) -> Result<Vec<u64>, db_error> {
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        // TODO: this information can be cached in RAM
        let qry = "SELECT parent_fork_segment_id FROM snapshots WHERE fork_segment_id = ?1 ORDER BY block_height ASC LIMIT 1";
        let mut ret = vec![];

        ret.push(fork_segment_id);

        let mut next_fork_segment_id = fork_segment_id;

        loop {
            let mut stmt = conn.prepare(qry).expect(SQLITE_ERROR_MSG);

            let mut rows = stmt.query(&[&(next_fork_segment_id as i64) as &ToSql])
                .expect(SQLITE_ERROR_MSG);
           
            // expect this array to be 0 or 1 items
            let mut parent_fork_ids = vec![];

            while let Some(row_res) = rows.next() {
                let row = row_res.expect(SQLITE_ERROR_MSG);
                if parent_fork_ids.len() > 1 {
                    panic!("FATAL: database inconsistent; multiple snapshots with same fork segment ID and parent fork segment ID");
                }
                let fid : i64 = row.get(0);
                if fid < 0 {
                    panic!("FATAL: database returned a negative fork segment ID");
                }
                parent_fork_ids.push(fid as u64);
            }

            if parent_fork_ids.len() == 0 || parent_fork_ids[0] == next_fork_segment_id {
                // finished
                break;
            }

            next_fork_segment_id = parent_fork_ids[0];
            ret.push(parent_fork_ids[0] as u64);
        }

        Ok(ret)
    }

    /// Given a fork segment ID of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork segment, find the fork segment ID that contains the block of that height.
    fn get_ancestor_snapshot<'a>(tx: &mut Transaction<'a>, ancestor_block_height: u64, tip_fork_segment_id: u64) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(ancestor_block_height < BLOCK_HEIGHT_MAX);
        assert!(tip_fork_segment_id < FORK_SEGMENT_ID_MAX);

        // Common case -- this ancestor is in this fork segment.
        // If tip_fork_segment_id is the canonical chain, this should always return Some(...)
        match BurnDB::get_block_snapshot_in_fork_segment(tx, ancestor_block_height, tip_fork_segment_id).expect(SQLITE_ERROR_MSG) {
            Some(snapshot) => {
                test_debug!("Snapshot for block {} is in the tip fork segment {}", ancestor_block_height, tip_fork_segment_id);
                return Ok(Some(snapshot));
            }
            None => {}
        }

        // Uncommon case -- the ancestor is in a different fork segment (tip_fork_segment_id is not
        // the canonical chain fork).
        // Continue to walk through fork segments until we find the one that contains the ancestor
        // block height.
        let mut cur_fork_segment_id = tip_fork_segment_id;
        loop {
            let ancestor_snapshot = match BurnDB::get_fork_segment_head(tx, cur_fork_segment_id).expect(SQLITE_ERROR_MSG) {
                Some(snapshot) => {
                    snapshot
                },
                None => {
                    // this ancestor block was not processed
                    test_debug!("No ancestor snapshot for block {} from tip fork segment {}", ancestor_block_height, tip_fork_segment_id);
                    return Ok(None);
                }
            };

            if ancestor_snapshot.block_height == ancestor_block_height {
                // lucky guess
                test_debug!("Ancestor snapshot at {} is in fork segment {}", ancestor_block_height, ancestor_snapshot.fork_segment_id);
                return Ok(Some(ancestor_snapshot));
            }
            else if ancestor_snapshot.block_height < ancestor_block_height {
                // this fork segment ought to contain this ancestor block
                match BurnDB::get_block_snapshot_in_fork_segment(tx, ancestor_block_height, ancestor_snapshot.fork_segment_id).expect(SQLITE_ERROR_MSG) {
                    Some(snapshot) => {
                        test_debug!("Ancestor snapshot at {} is in fork segment {}", ancestor_block_height, snapshot.fork_segment_id);
                        return Ok(Some(snapshot));
                    },
                    None => {
                        // implies discontinuity, or that this block is too far in the future
                        let ancestor_tail = BurnDB::get_fork_segment_tail(tx, cur_fork_segment_id)
                            .expect(SQLITE_ERROR_MSG)
                            .expect(&format!("FATAL: no fork segment tail for {}, but there is a head", cur_fork_segment_id));

                        if ancestor_tail.block_height < ancestor_block_height {
                            // too far in the future
                            test_debug!("Block {} is too far in the future", ancestor_block_height);
                            return Ok(None);
                        }

                        // should be unreachable
                        panic!("FATAL: burn DB is dicontinuous in fork segment {} between blocks {} and {}", ancestor_snapshot.fork_segment_id, ancestor_snapshot.block_height, ancestor_block_height);
                    }
                }
            }
            else {
                // keep walking back segments, while we can
                test_debug!("Walk back from fork segment {} to fork segment {}", cur_fork_segment_id, ancestor_snapshot.parent_fork_segment_id);
                if cur_fork_segment_id == 0 && ancestor_snapshot.parent_fork_segment_id == 0 {
                    // at the end
                    return Ok(None);
                }

                cur_fork_segment_id = ancestor_snapshot.parent_fork_segment_id;
                continue;
            }
        }
    }

    /// Get consensus hash from a particular chain tip's history
    pub fn get_consensus_at<'a>(tx: &mut Transaction<'a>, block_height: u64, tip_fork_segment_id: u64) -> Result<Option<ConsensusHash>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        match BurnDB::get_ancestor_snapshot(tx, block_height, tip_fork_segment_id).expect(SQLITE_ERROR_MSG) {
            Some(sn) => Ok(Some(sn.consensus_hash)),
            None => Ok(None)
        }
    }

    /// Begin a transaction.
    pub fn tx_begin<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = self.conn.transaction()
            .expect(SQLITE_ERROR_MSG);

        Ok(tx)
    }

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    pub fn insert_leader_key<'a>(tx: &mut Transaction<'a>, leader_key: &LeaderKeyRegisterOp) -> Result<(), db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);
        assert!(leader_key.fork_segment_id < FORK_SEGMENT_ID_MAX);

        tx.execute("INSERT INTO leader_keys (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, memo, address, fork_segment_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                   &[&leader_key.txid.to_hex(), &leader_key.vtxindex as &ToSql, &(leader_key.block_height as i64) as &ToSql, &leader_key.burn_header_hash.to_hex(),
                   &leader_key.consensus_hash.to_hex(), &leader_key.public_key.to_hex(), &to_hex(&leader_key.memo), &leader_key.address.to_string(), &(leader_key.fork_segment_id as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        Ok(())
    }
    
    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    pub fn insert_block_commit<'a>(tx: &mut Transaction<'a>, block_commit: &LeaderBlockCommitOp) -> Result<(), db_error> {
        assert!(block_commit.block_height < BLOCK_HEIGHT_MAX);
        assert!(block_commit.fork_segment_id < FORK_SEGMENT_ID_MAX);

        // serialize tx input to JSON
        let tx_input_str = serde_json::to_string(&block_commit.input)
            .map_err(|e| db_error::SerializationError(e))?;

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", block_commit.burn_fee);

        tx.execute("INSERT INTO block_commits (txid, vtxindex, block_height, burn_header_hash, block_header_hash, new_seed, parent_block_backptr, parent_vtxindex, key_block_backptr, key_vtxindex, epoch_num, memo, burn_fee, input, fork_segment_id) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    &[&block_commit.txid.to_hex(), &block_commit.vtxindex as &ToSql, &(block_commit.block_height as i64) as &ToSql, &block_commit.burn_header_hash.to_hex(), 
                    &block_commit.block_header_hash.to_hex(), &block_commit.new_seed.to_hex(), &block_commit.parent_block_backptr as &ToSql, &block_commit.parent_vtxindex as &ToSql,
                    &block_commit.key_block_backptr as &ToSql, &block_commit.key_vtxindex as &ToSql, &block_commit.epoch_num as &ToSql, &to_hex(&block_commit.memo[..]), 
                    &burn_fee_str, &tx_input_str, &(block_commit.fork_segment_id as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        Ok(())
    }

    /// Insert a user support burn.
    /// No validity checking will be done, beyond what is encoded in the user_burn_support table
    /// constraints.  That is, type mismatches and serialization errors will be caught, but nothing
    /// else.
    /// The corresponding snapshot must already be inserted
    pub fn insert_user_burn<'a>(tx: &mut Transaction<'a>, user_burn: &UserBurnSupportOp) -> Result<(), db_error> {
        assert!(user_burn.block_height < BLOCK_HEIGHT_MAX);
        assert!(user_burn.fork_segment_id < FORK_SEGMENT_ID_MAX);

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", user_burn.burn_fee);

        tx.execute("INSERT INTO user_burn_support (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, key_block_backptr, key_vtxindex, block_header_hash_160, memo, burn_fee, fork_segment_id) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                   &[&user_burn.txid.to_hex(), &user_burn.vtxindex as &ToSql, &(user_burn.block_height as i64) as &ToSql, &user_burn.burn_header_hash.to_hex(), &user_burn.consensus_hash.to_hex(),
                   &user_burn.public_key.to_hex(), &user_burn.key_block_backptr as &ToSql, &user_burn.key_vtxindex as &ToSql, &user_burn.block_header_hash_160.to_hex(), &to_hex(&user_burn.memo[..]),
                   &burn_fee_str, &(user_burn.fork_segment_id as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        Ok(())
    }
    
    /// Insert a block header that is paired with an already-existing block commit and snapshot
    pub fn insert_block_header<'a>(tx: &mut Transaction<'a>, header: &StacksBlockHeader, block_height: u64, fork_segment_id: u64) -> Result<(), db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let total_work_str = format!("{}", header.total_work.work);
        let total_burn_str = format!("{}", header.total_work.burn);
        let block_hash = header.block_hash();

        tx.execute("INSERT INTO block_headers \
                    (version, total_burn, total_work, proof, parent_block, parent_microblock, parent_microblock_sequence, tx_merkle_root, state_index_root, microblock_pubkey, block_hash, block_height, fork_segment_id) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    &[&header.version as &ToSql, &total_burn_str, &total_work_str, &header.proof.to_hex(), &header.parent_block.to_hex(), &header.parent_microblock.to_hex(), &header.parent_microblock_sequence, 
                      &header.tx_merkle_root.to_hex(), &header.microblock_pubkey.to_hex(), &block_hash.to_hex(), &(block_height as i64) as &ToSql, &(fork_segment_id as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        Ok(())
    }
   
    /// Insert a microblock header that is paired with an already-existing block header
    pub fn insert_microblock_header<'a>(tx: &mut Transaction<'a>, microblock_header: &StacksMicroblockHeader, parent_block_hash: &BlockHeaderHash, block_height: u64, fork_segment_id: u64) -> Result<(), db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let microblock_hash = microblock_header.block_hash();

        tx.execute("INSERT INTO microblock_headers \
                    (version, sequence, prev_block, tx_merkle_root, signature, microblock_hash, parent_block_hash, block_height, fork_segment_id) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    &[&header.version as &ToSql, &header.sequence as &ToSql, &microblock.prev_block.to_hex(), &microblock.tx_merkle_root.to_hex(), &microblock.signature.to_hex(), &microblock_hash.to_hex(),
                      parent_block_hash.to_hex(), &(block_height as i64) as &ToSql, &(fork_segment_id as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);
        Ok(())
    }

    /// Get the first snapshot 
    pub fn get_first_block_snapshot(conn: &Connection) -> Result<BlockSnapshot, db_error> {
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE fork_segment_id = 0 AND parent_fork_segment_id = 0 AND fork_length = 0 AND fork_segment_length = 0 ORDER BY block_height LIMIT 1", row_order);
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), NO_PARAMS)?;

        match rows.len() {
            1 => Ok(rows[0].clone()),
            _ => {
                // should never happen 
                panic!("FATAL: multiple first-block snapshots")
            }
        }
    }

    /// Get a snapshot for an existing block.
    pub fn get_block_snapshot(conn: &Connection, burn_hash: &BurnchainHeaderHash) -> Result<Option<BlockSnapshot>, db_error> {
        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE burn_header_hash = ?1", row_order);
        let args = [&burn_hash.to_hex()];
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)
            .expect(SQLITE_ERROR_MSG);

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block {}", burn_hash.to_hex());
            }
        }
    }
    
    /// Get a snapshot for an existing block in a particular fork segment
    pub fn get_block_snapshot_in_fork_segment(conn: &Connection, block_height: u64, fork_segment_id: u64) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE fork_segment_id = ?1 AND block_height = ?2", row_order);
        let args = [&(fork_segment_id as i64) as &ToSql, &(block_height as i64) as &ToSql];
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)
            .expect(SQLITE_ERROR_MSG);

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block snapshots for the same block height and fork segment");
            }
        }
    }
    
    /// Get all snapshots in a fork segment
    #[cfg(test)]
    fn get_block_snapshots_in_fork_segment(conn: &Connection, fork_segment_id: u64) -> Result<Vec<BlockSnapshot>, db_error> {
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE fork_segment_id = ?1 ORDER BY block_height ASC", row_order);
        let args = [&(fork_segment_id as i64) as &ToSql];
        let rows = query_rows::<BlockSnapshot, _>(conn, &qry.to_string(), &args)
            .expect(SQLITE_ERROR_MSG);

        Ok(rows)
    }

    /// Get the first snapshot in a fork segment
    fn get_fork_segment_head<'a>(tx: &mut Transaction<'a>, fork_segment_id: u64) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE fork_segment_id = ?1 ORDER BY block_height ASC LIMIT 1", row_order);
        let rows = query_rows::<BlockSnapshot, _>(tx, &qry, &[&(fork_segment_id as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        match rows.len() {
            0 => {
                Ok(None)
            },
            _ => {
                Ok(Some(rows[0].clone()))
            }
        }
    }

    /// Get the last snapshot in a fork segment
    pub fn get_fork_segment_tail<'a>(tx: &mut Transaction<'a>, fork_segment_id: u64) -> Result<Option<BlockSnapshot>, db_error> {
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE fork_segment_id = ?1 ORDER BY block_height DESC LIMIT 1", row_order);
        let rows = query_rows::<BlockSnapshot, _>(tx, &qry, &[&(fork_segment_id as i64) as &ToSql])
            .expect(SQLITE_ERROR_MSG);

        match rows.len() {
            0 => {
                Ok(None)
            },
            _ => {
                Ok(Some(rows[0].clone()))
            }
        }
    }
    
    /// Get a leader key at a specific location in the burn chain's fork history, given the
    /// matching block commit's fork segment ID (block_height and vtxindex are the leader's
    /// calculated location in this fork).
    /// Returns None if there is no leader key at this location.
    pub fn get_leader_key_at<'a>(tx: &mut Transaction<'a>, key_block_height: u64, key_vtxindex: u32, fork_segment_id: u64) -> Result<Option<LeaderKeyRegisterOp>, db_error> {
        assert!(key_block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let leader_snapshot = match BurnDB::get_ancestor_snapshot(tx, key_block_height, fork_segment_id).expect(SQLITE_ERROR_MSG) {
            Some(sn) => {
                sn
            },
            None => {
                // no such leader key
                return Ok(None);
            }
        };

        let row_order = LeaderKeyRegisterOp::row_order().join(",");

        let qry = format!("SELECT {} FROM leader_keys WHERE fork_segment_id = ?1 AND block_height = ?2 AND vtxindex = ?3", row_order);
        let args = [&(leader_snapshot.fork_segment_id as i64) as &ToSql, &(key_block_height as i64) as &ToSql, &key_vtxindex as &ToSql];
        let rows = query_rows::<LeaderKeyRegisterOp, _>(tx, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple leader keys at block {} vtxindex {}", key_block_height, key_vtxindex);
            }
        }
    }

    /// Get all leader keys registered in a block on the burn chain's history in this fork segment.
    /// Returns the list of block commits in order by vtxindex.
    pub fn get_leader_keys_by_block(conn: &Connection, block_height: u64, fork_segment_id: u64) -> Result<Vec<LeaderKeyRegisterOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = LeaderKeyRegisterOp::row_order().join(",");

        let qry = format!("SELECT {} FROM leader_keys WHERE fork_segment_id = ?1 AND block_height = ?2 ORDER BY vtxindex ASC", row_order);
        let args = [&(fork_segment_id as i64) as &ToSql, &(block_height as i64) as &ToSql];

        query_rows::<LeaderKeyRegisterOp, _>(conn, &qry.to_string(), &args)
    }

    /// Get all block commitments registered in a block on the burn chain's history in this fork segment.
    /// Returns the list of block commits in order by vtxindex.
    pub fn get_block_commits_by_block(conn: &Connection, block_height: u64, fork_segment_id: u64) -> Result<Vec<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = LeaderBlockCommitOp::row_order().join(",");

        let qry = format!("SELECT {} FROM block_commits WHERE fork_segment_id = ?1 AND block_height = ?2 ORDER BY vtxindex ASC", row_order);
        let args = [&(fork_segment_id as i64) as &ToSql, &(block_height as i64) as &ToSql];

        query_rows::<LeaderBlockCommitOp, _>(conn, &qry.to_string(), &args)
    }

    /// Get all user burns registered in a block on is fork segment.
    /// Returns list of user burns in order by vtxindex.
    pub fn get_user_burns_by_block(conn: &Connection, block_height: u64, fork_segment_id: u64) -> Result<Vec<UserBurnSupportOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = UserBurnSupportOp::row_order().join(",");

        let qry = format!("SELECT {} FROM user_burn_support WHERE fork_segment_id = ?1 AND block_height = ?2 ORDER BY vtxindex ASC", row_order);
        let args = [&(fork_segment_id as i64) as &ToSql, &(block_height as i64) as &ToSql];

        query_rows::<UserBurnSupportOp, _>(conn, &qry.to_string(), &args)
    }

    /// Find out how any burn tokens were destroyed in a given block and fork segment.
    pub fn get_block_burn_amount<'a>(tx: &mut Transaction<'a>, block_height: u64, fork_segment_id: u64) -> Result<u128, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let user_burns = BurnDB::get_user_burns_by_block(tx, block_height, fork_segment_id)?;
        let block_commits = BurnDB::get_block_commits_by_block(tx, block_height, fork_segment_id)?;
        let mut burn_total : u128 = 0;

        for i in 0..user_burns.len() {
            burn_total = burn_total.checked_add(user_burns[i].burn_fee as u128).expect("Way too many tokens burned");
        }
        for i in 0..block_commits.len() {
            burn_total = burn_total.checked_add(block_commits[i].burn_fee as u128).expect("Way too many tokens burned");
        }
        Ok(burn_total)
    }

    /// Get a block commit at a specific location in the burn chain on a particular fork segment.
    /// Returns None if there is no block commit at this location.
    pub fn get_block_commit_at(conn: &Connection, block_height: u64, vtxindex: u32, fork_segment_id: u64) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);
        
        let row_order_list : Vec<String> = LeaderBlockCommitOp::row_order().iter().map(|r| format!("block_commits.{}", r)).collect();
        let row_order = row_order_list.join(",");

        let qry = format!("SELECT {} FROM block_commits WHERE block_commits.fork_segment_id = ?1 AND block_commits.block_height = ?2 AND block_commits.vtxindex = ?3", row_order);
        let args = [&(fork_segment_id as i64) as &ToSql, &(block_height as i64) as &ToSql, &vtxindex as &ToSql];
        let rows = query_rows::<LeaderBlockCommitOp, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple block commits at block {} vtxindex {}", block_height, vtxindex);
            }
        }
    }

    /// Get a block commit by its content-addressed location in the given fork segment.
    /// Returns None if there is no block commit with this key that is on this fork 
    pub fn get_block_commit(conn: &Connection, txid: &Txid, burn_header_hash: &BurnchainHeaderHash, fork_segment_id: u64) -> Result<Option<LeaderBlockCommitOp>, db_error> {
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order_list : Vec<String> = LeaderBlockCommitOp::row_order().iter().map(|r| format!("block_commits.{}", r)).collect();
        let row_order = row_order_list.join(",");

        let qry = format!("SELECT {} FROM block_commits WHERE block_commits.fork_segment_id = ?1 AND block_commits.txid = ?2 AND block_commits.burn_header_hash = ?3", row_order);
        let args = [&(fork_segment_id as i64) as &ToSql, &txid.to_hex(), &burn_header_hash.to_hex()];
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

    /// Find out whether or not a particular VRF key was used before in this fork segment's history.
    pub fn has_VRF_public_key<'a>(tx: &mut Transaction<'a>, key: &VRFPublicKey, fork_segment_id: u64) -> Result<bool, db_error> {
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let qry = "SELECT COUNT(leader_keys.public_key) FROM leader_keys WHERE public_key = ?1 AND fork_segment_id = ?2".to_string();
        let ancestor_fork_segments = BurnDB::get_ancestor_fork_segments(tx, fork_segment_id).expect(SQLITE_ERROR_MSG);
        for ancestor_fork_id in ancestor_fork_segments {
            let args = [&key.to_hex(), &(ancestor_fork_id as i64) as &ToSql];
            let count = query_count(tx, &qry, &args).expect(SQLITE_ERROR_MSG);
            if count != 0 {
                return Ok(true)
            }
        }

        Ok(false)
    }

    /// Find out whether or not a given consensus hash is "recent" enough to be used in this fork
    pub fn is_fresh_consensus_hash<'a>(tx: &mut Transaction<'a>, current_block_height: u64, consensus_hash_lifetime: u64, consensus_hash: &ConsensusHash, fork_segment_id: u64) -> Result<bool, db_error> {
        assert!(current_block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let oldest_block_height =
            if current_block_height <= (consensus_hash_lifetime as u64) {
                0
            }
            else {
                current_block_height - (consensus_hash_lifetime as u64)
            };

        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE fork_segment_id = ?1 AND block_height >= ?2 AND block_height <= ?3 ORDER BY block_height DESC", row_order); 

        let ancestor_fork_segments = BurnDB::get_ancestor_fork_segments(tx, fork_segment_id).expect(SQLITE_ERROR_MSG);
        
        for fork_segment in ancestor_fork_segments {
            let args = [&(fork_segment as i64) as &ToSql, &(oldest_block_height as i64) as &ToSql, &(current_block_height as i64) as &ToSql];
            let rows = query_rows::<BlockSnapshot, _>(tx, &qry, &args).expect(SQLITE_ERROR_MSG);

            if rows.len() == 0 {
                break;
            }

            for row in rows {
                if row.consensus_hash == *consensus_hash {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Determine whether or not a leader key has been consumed by a subsequent block commitment in
    /// this fork's history.
    /// Will return false if the leader key does not exist.
    pub fn is_leader_key_consumed<'a>(tx: &mut Transaction<'a>, tip_block_height: u64, leader_key: &LeaderKeyRegisterOp, tip_fork_segment_id: u64) -> Result<bool, db_error> {
        assert!(leader_key.block_height < BLOCK_HEIGHT_MAX);
        assert!(leader_key.fork_segment_id < FORK_SEGMENT_ID_MAX);
        assert!(tip_block_height < BLOCK_HEIGHT_MAX);

        let qry = "SELECT COUNT(*) FROM block_commits WHERE fork_segment_id = ?1 AND block_height <= ?2 AND key_vtxindex = ?3 AND block_height - key_block_backptr = ?4".to_string();
        let ancestor_fork_segments = BurnDB::get_ancestor_fork_segments(tx, tip_fork_segment_id).expect(SQLITE_ERROR_MSG);
        for fork_segment in ancestor_fork_segments {
            let args = [&(fork_segment as i64) as &ToSql, &(tip_block_height as i64) as &ToSql, &leader_key.vtxindex as &ToSql, &(leader_key.block_height as i64) as &ToSql];
            let count = query_count(tx, &qry, &args).expect(SQLITE_ERROR_MSG);
            if count != 0 {
                // found
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get the latest block snapshot on this fork where a sortition occured.
    /// Search snapshots up to (but excluding) the given block height.
    /// Will always return a snapshot -- even if it's the initial sentinel snapshot.
    /// NOTE: the search will include burn_block_height.  burn_block_height and fork_segment_id
    /// identify the chain tip.
    pub fn get_last_snapshot_with_sortition<'a>(tx: &mut Transaction<'a>, burn_block_height: u64, fork_segment_id: u64) -> Result<BlockSnapshot, db_error> {
        assert!(burn_block_height < BLOCK_HEIGHT_MAX);
        assert!(fork_segment_id < FORK_SEGMENT_ID_MAX);

        let row_order = BlockSnapshot::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE snapshots.sortition = 1 AND snapshots.block_height <= ?1 AND fork_segment_id = ?2 ORDER BY snapshots.block_height DESC LIMIT 1", row_order);
        let ancestor_fork_segments = BurnDB::get_ancestor_fork_segments(tx, fork_segment_id).expect(SQLITE_ERROR_MSG);
        for fork_segment in ancestor_fork_segments {
            let args = [&(burn_block_height as i64) as &ToSql, &(fork_segment as i64) as &ToSql];
            let rows = query_rows::<BlockSnapshot, _>(tx, &qry, &args)?;

            if rows.len() == 0 {
                continue;
            }
            else if rows.len() == 1 {
                return Ok(rows[0].clone());
            }
            else {
                // should never happen -- there is always a last-block-with-sortition.  Even the sentinel initial snapshot has a sortition.
                panic!("Found more than one last canonical block snapshot with sortition");
            }
        }
        
        // should never happen -- implies discontinuity in the burn db
        panic!("No initial snapshot with sortition (disconnected block {} fork segment {})", burn_block_height, fork_segment_id);
    }

    /// Get a consensus hash at a particular block height, or if that block height is too far in the
    /// past or too far in the future, return None.
    /// Due to the way we construct the fork segments, the canonical fork is the longest fork, and we
    /// can avoid the expensive get_consensus_at() function in favor of select the snapshot on the
    /// canonical fork segment at the given block height.
    /// NOTE: not for use with consensus-critical code, hence not a transaction.
    pub fn get_canonical_consensus_hash(conn: &Connection, block_height: u64) -> Result<Option<ConsensusHash>, db_error> {
        assert!(block_height < BLOCK_HEIGHT_MAX);

        let chain_tip = BurnDB::get_canonical_chain_tip(conn)?;
        if chain_tip.block_height < block_height {
            return Ok(None);
        }

        let snapshot = match BurnDB::get_block_snapshot_in_fork_segment(conn, block_height, chain_tip.fork_segment_id).expect(SQLITE_ERROR_MSG) {
            Some(sn) => {
                sn
            },
            None => { 
                return Ok(None);
            }
        };

        Ok(Some(snapshot.consensus_hash))
    }

    /// Get a burn blockchain snapshot, given a burnchain configuration struct.
    /// Used mainly by the network code to determine what the chain tip currently looks like.
    pub fn get_burnchain_view<'a>(tx: &mut Transaction<'a>, burnchain: &Burnchain) -> Result<BurnchainView, db_error> {
        let chain_tip = BurnDB::get_canonical_chain_tip(tx)?;
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

        let stable_snapshot = match BurnDB::get_block_snapshot_in_fork_segment(tx, stable_block_height, chain_tip.fork_segment_id).expect(SQLITE_ERROR_MSG) {
            Some(sn) => {
                sn
            },
            None => {
                // shouldn't be possible, but don't panic since this is network-callable code
                error!("Failed to load snapshot for block {} from fork segment {}", stable_block_height, chain_tip.fork_segment_id);
                return Err(db_error::Corruption);
            }
        };

        test_debug!("Chain view: {},{}-{},{}", chain_tip.block_height, chain_tip.consensus_hash.to_hex(), stable_block_height, stable_snapshot.consensus_hash.to_hex());
        Ok(BurnchainView {
            burn_block_height: chain_tip.block_height, 
            burn_consensus_hash: chain_tip.consensus_hash,
            burn_stable_block_height: stable_block_height,
            burn_stable_consensus_hash: stable_snapshot.consensus_hash
        })
    }

    /// Get the header inventory information over a range.
    /// Returns at most 2000 entries, ending at the given chain tip.
    pub fn get_stacks_block_headers<'a>(tx: &mut Transaction<'a>, tip_block_height: u64, tip_fork_segment_id: u64) -> Result<Vec<(BlockHeaderHash, Option<StacksBlockHeader>)>, db_error> {
        assert!(tip_block_height < BLOCK_HEIGHT_MAX);
        assert!(tip_fork_segment_id < FORK_SEGMENT_ID_MAX);

        let count = 2000u64;

        let header_row_order = StacksBlockHeader::row_order().iter().map(|s| format!("block_header.{}", s)).collect().join(",");
        let snapshot_row_order = BlockSnapshot::row_order().iter().map(|s| format!("snapshots.{}", s)).collect().join(",");
        let header_row_offset = BlockSnapshot::row_order().len();

        let qry = format!("SELECT {},{} FROM snapshots LEFT JOIN block_headers \
                          ON block_headers.block_height = snapshots.block_height AND block_headers.fork_segment_id = snapshots.fork_segment_id AND block_headers.block_hash = snapshots.winning_stacks_block_hash \
                          WHERE fork_segment_id = ?1 AND block_height > ?2 AND block_height <= ?3 ORDER BY block_height DESC LIMIT {}", snapshots_row_order, header_row_order count);

        let mut block_inventory = Vec::with_capacity(count as usize);
        let mut cur_block_height = tip_block_height;

        // get as many as we can, up to $count
        let fork_segments = BurnDB::get_ancestor_fork_segments(tx, tip_fork_segment_id).expect(SQLITE_ERROR_MSG);
        for fork_segment in fork_segments {
            let next_block_height = 
                if cur_block_height < count {
                    0
                }
                else {
                    cur_block_height - count
                };
       
            let mut stmt = conn.prepare(qry).expect(SQLITE_ERROR_MSG);
            let mut rows = stmt.query(sql_args).expect(SQLITE_ERROR_MSG);
            while let Some(row_res) = rows.next() {
                let row = row_res.expect(SQLITE_ERROR_MSG);
                let next_snapshot = BlockSnapshot::from_row(&row, 0)?;
                let next_header_opt =
                    if next_snapshot.sortition {
                        let next_header = StacksBlockHeader::from_row(&row, header_row_offset)?;
                        Some(next_header)
                    }
                    else {
                        None
                    };

                block_inventory.push((next_snapshot, next_header_opt));
                if block_inventory.len() >= count as usize {
                    break;
                }
            }

            if block_inventory.len() >= count as usize {
                break;
            }

            if cur_block_height > 0 {
                cur_block_height -= 1;
            }
        }

        block_inventory.reverse();
        Ok(block_inventory)
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
            block_height: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            fork_segment_id: 0,
        };

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();

        {   // force the tx to go out of scope when we commit
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_leader_key(&mut tx, &leader_key).unwrap();
            tx.commit().unwrap();
        }

        let res_leader_keys = BurnDB::get_leader_keys_by_block(db.conn(), block_height, 0).unwrap();
        assert_eq!(res_leader_keys.len(), 1);
        assert_eq!(res_leader_keys[0], leader_key);

        let no_leader_keys = BurnDB::get_leader_keys_by_block(db.conn(), block_height+1, 0).unwrap();
        assert_eq!(no_leader_keys.len(), 0);

        let mut tx = db.tx_begin().unwrap();
        let leader_key_opt = BurnDB::get_leader_key_at(&mut tx, block_height, vtxindex, 0).unwrap();
        assert!(leader_key_opt.is_some());
        assert_eq!(leader_key_opt.unwrap(), leader_key);

        let leader_key_none = BurnDB::get_leader_key_at(&mut tx, block_height, vtxindex+1, 0).unwrap();
        assert!(leader_key_none.is_none());
    }

    #[test]
    fn test_insert_block_commit() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 0x4140,
            parent_vtxindex: 0x4342,
            key_block_backptr: 0x5150,
            key_vtxindex: 0x6160,
            epoch_num: 0x71706362,
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
            block_height: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            fork_segment_id: 0,
        };

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_commit(&mut tx, &block_commit).unwrap();
            tx.commit().unwrap();
        }

        let res_block_commits = BurnDB::get_block_commits_by_block(db.conn(), block_height, 0).unwrap();
        assert_eq!(res_block_commits.len(), 1);
        assert_eq!(res_block_commits[0], block_commit);

        let no_block_commits = BurnDB::get_leader_keys_by_block(db.conn(), block_height+1, 0).unwrap();
        assert_eq!(no_block_commits.len(), 0);
    }

    #[test]
    fn test_insert_user_burn() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let user_burn = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            key_block_backptr: 258,
            key_vtxindex: 772,
            memo: vec![0x05],
            burn_fee: 12345,

            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_height: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            fork_segment_id: 0,
        };

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_user_burn(&mut tx, &user_burn).unwrap();
            tx.commit().unwrap();
        }

        let res_user_burns = BurnDB::get_user_burns_by_block(db.conn(), block_height, 0).unwrap();
        assert_eq!(res_user_burns.len(), 1);
        assert_eq!(res_user_burns[0], user_burn);

        let no_user_burns = BurnDB::get_user_burns_by_block(db.conn(), block_height+1, 0).unwrap();
        assert_eq!(no_user_burns.len(), 0);
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
            block_height: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            fork_segment_id: 0,
        };

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        
        let has_key_before = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::has_VRF_public_key(&mut tx, &public_key, 0).unwrap()
        };

        assert!(!has_key_before);

        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_leader_key(&mut tx, &leader_key).unwrap();
            tx.commit().unwrap();
        }

        let has_key_after = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::has_VRF_public_key(&mut tx, &public_key, 0).unwrap()
        };

        assert!(has_key_after);
    }

    #[test]
    fn is_fresh_consensus_hash() {
        let consensus_hash_lifetime = 24;
        let first_burn_hash = BurnchainHeaderHash::from_hex("1000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut db = BurnDB::connect_memory(0, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            for i in 0..256 {
                let snapshot_row = BlockSnapshot {
                    block_height: i+1,
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    total_burn: i,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
                    fork_segment_id: 0,
                    parent_fork_segment_id: 0,
                    fork_segment_length: i+1,
                    fork_length: i+1
                };
                BurnDB::insert_block_snapshot(&mut tx, &snapshot_row).unwrap();
            }

            tx.commit().unwrap();
        }

        let ch_fresh = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,255]).unwrap();
        let ch_oldest_fresh = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(255 - consensus_hash_lifetime) as u8]).unwrap();
        let ch_newest_stale = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(255 - consensus_hash_lifetime - 1) as u8]).unwrap();
        let ch_missing = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,255]).unwrap();

        let fresh_check = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 256, consensus_hash_lifetime, &ch_fresh, 0).unwrap()
        };

        assert!(fresh_check);

        let oldest_fresh_check = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 256, consensus_hash_lifetime, &ch_oldest_fresh, 0).unwrap()
        };

        assert!(oldest_fresh_check);

        let newest_stale_check = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 256, consensus_hash_lifetime, &ch_newest_stale, 0).unwrap()
        };

        assert!(!newest_stale_check);

        let missing_check = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_fresh_consensus_hash(&mut tx, 256, consensus_hash_lifetime, &ch_missing, 0).unwrap()
        };

        assert!(!missing_check);
    }

    #[test]
    fn get_consensus_at() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("1000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut db = BurnDB::connect_memory(0, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            for i in 0..256 {
                let snapshot_row = BlockSnapshot {
                    block_height: i+1,
                    burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i == 0 { 0xff } else { i - 1 }) as u8]).unwrap(),
                    consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    total_burn: i,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    
                    fork_segment_id: 0,
                    parent_fork_segment_id: 0,
                    fork_segment_length: i+1,
                    fork_length: i+1
                };
                BurnDB::insert_block_snapshot(&mut tx, &snapshot_row).unwrap();

                // should succeed within the tx 
                let ch_opt = BurnDB::get_consensus_at(&mut tx, i+1, 0).unwrap();
                let ch = ch_opt.unwrap();
                assert_eq!(ch, snapshot_row.consensus_hash);
            }

            tx.commit().unwrap();
        }

        for i in 0..256 {
            // should succeed within the conn
            let mut tx = db.tx_begin().unwrap();
            let expected_ch = ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap();
            let ch_opt = BurnDB::get_consensus_at(&mut tx, i+1, 0).unwrap();
            let ch = ch_opt.unwrap();
            assert_eq!(ch, expected_ch);
        }
    }

    #[test]
    fn get_block_burn_amount() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let fork_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let block_height = 123;

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();

            // make a non-canonical snapshot
            let mut fork_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
            fork_snapshot.fork_segment_id = 1;
            fork_snapshot.burn_header_hash = fork_burn_hash;
            BurnDB::insert_block_snapshot(&mut tx, &fork_snapshot).unwrap();
        
            let block_commit = LeaderBlockCommitOp {
                block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                parent_block_backptr: 0x4140,
                parent_vtxindex: 0x4342,
                key_block_backptr: 0x5150,
                key_vtxindex: 0x6160,
                epoch_num: 0x71706362,
                memo: vec![0x80],

                burn_fee: 1,
                input: BurnchainSigner {
                    public_keys: vec![
                        StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                    ],
                    num_sigs: 1,
                    hash_mode: AddressHashMode::SerializeP2PKH
                },

                txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                vtxindex: 0,
                block_height: block_height,
                burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),

                fork_segment_id: 0,
            };
            
            let block_commit_noncanonical = LeaderBlockCommitOp {
                block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222223").unwrap()).unwrap(),
                new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                parent_block_backptr: 0x4140,
                parent_vtxindex: 0x4342,
                key_block_backptr: 0x5150,
                key_vtxindex: 0x6160,
                epoch_num: 0x71706362,
                memo: vec![0x80],

                burn_fee: 10,
                input: BurnchainSigner {
                    public_keys: vec![
                        StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                    ],
                    num_sigs: 1,
                    hash_mode: AddressHashMode::SerializeP2PKH
                },

                txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                vtxindex: 0,
                block_height: block_height,
                burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),

                fork_segment_id: 1
            };
        
            let user_burn = UserBurnSupportOp {
                consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
                block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
                key_block_backptr: 258,
                key_vtxindex: 772,
                memo: vec![0x05],
                burn_fee: 2,

                txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
                vtxindex: 1,
                block_height: block_height,
                burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),

                fork_segment_id: 0
            };
            
            let user_burn_noncanonical = UserBurnSupportOp {
                consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
                block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
                key_block_backptr: 258,
                key_vtxindex: 772,
                memo: vec![0x05],
                burn_fee: 20,

                txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
                vtxindex: 1,
                block_height: block_height,
                burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),

                fork_segment_id: 1
            };

            BurnDB::insert_block_commit(&mut tx, &block_commit_noncanonical).unwrap();
            BurnDB::insert_user_burn(&mut tx, &user_burn_noncanonical).unwrap();

            // TODO: repair this
           
            /*
            let burn_amount_noncanonical = BurnDB::get_block_burn_amount(&mut tx, block_height, 1).unwrap();
            assert_eq!(burn_amount_noncanonical, 30);
            
            assert_eq!(BurnDB::get_block_burn_amount(&mut tx, block_height - 1, 0).unwrap(), 0);
            assert_eq!(BurnDB::get_block_burn_amount(&mut tx, block_height + 1, 0).unwrap(), 0);

            let burn_amount_postreorg = BurnDB::get_block_burn_amount(&mut tx, block_height).unwrap();
            assert_eq!(burn_amount_postreorg, 0);
            
            assert_eq!(BurnDB::get_block_burn_amount(&mut tx, block_height - 1).unwrap(), 0);
            assert_eq!(BurnDB::get_block_burn_amount(&mut tx, block_height + 1).unwrap(), 0);

            BurnDB::insert_block_commit(&mut tx, &block_commit).unwrap();
            BurnDB::insert_user_burn(&mut tx, &user_burn).unwrap();
        
            // only the canonical ops should show up 
            let burn_amount = BurnDB::get_block_burn_amount(&mut tx, block_height).unwrap();
            assert_eq!(burn_amount, 3);
            
            assert_eq!(BurnDB::get_block_burn_amount(&mut tx, block_height - 1).unwrap(), 0);
            assert_eq!(BurnDB::get_block_burn_amount(&mut tx, block_height + 1).unwrap(), 0);

            tx.commit().unwrap();
            */
        }
    }

    #[test]
    fn get_block_commit_at() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 0x4140,
            parent_vtxindex: 0x4342,
            key_block_backptr: 0x5150,
            key_vtxindex: 0x6160,
            epoch_num: 0x71706362,
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
            block_height: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),

            fork_segment_id: 0,
        };

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        let block_commit_before = BurnDB::get_block_commit_at(db.conn(), block_height, vtxindex, 0).unwrap();
        assert!(block_commit_before.is_none());
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_commit(&mut tx, &block_commit).unwrap();
            tx.commit().unwrap();
        }

        let block_commit_after = BurnDB::get_block_commit_at(db.conn(), block_height, vtxindex, 0).unwrap();
        assert!(block_commit_after.unwrap() == block_commit);
    }

    #[test]
    fn get_block_commit() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let txid = Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap();
        let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 0x4140,
            parent_vtxindex: 0x4342,
            key_block_backptr: 0x5150,
            key_vtxindex: 0x6160,
            epoch_num: 0x71706362,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: txid.clone(),
            vtxindex: vtxindex,
            block_height: block_height,
            burn_header_hash: burn_header_hash.clone(),
            
            fork_segment_id: 0,
        };

        let mut db = BurnDB::connect_memory(block_height, &first_burn_hash).unwrap();
        let block_commit_before = BurnDB::get_block_commit(db.conn(), &txid, &burn_header_hash, 0).unwrap();
        assert!(block_commit_before.is_none());
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_commit(&mut tx, &block_commit).unwrap();
            tx.commit().unwrap();
        }

        let block_commit_after = BurnDB::get_block_commit(db.conn(), &txid, &burn_header_hash, 0).unwrap();
        assert!(block_commit_after.unwrap() == block_commit);
    }

    #[test]
    fn is_leader_key_consumed() {
        let first_block_height = 100;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let public_key = VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap();

        let leader_block_height = 100;
        let leader_vtxindex = 200;
        let leader_txid = Txid::from_bytes_be(&hex_bytes("5fb4ba1a651bae8057ec6b5cdafc93fa7e0b7d944d6f02a4b751de4e15464def").unwrap()).unwrap();
        let leader_burn_header_hash = Txid::from_bytes_be(&hex_bytes("9469d78e2a826a45f7adfae5437382fe7fd739d1b65faa8152eb7d4f0efc4d37").unwrap()).unwrap();

        let commit_block_height = 101;
        let commit_vtxindex = 456;
        let commit_vtxindex_2 = 457;
        let commit_txid = Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap();
        let commit_txid_2 = Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27d0").unwrap()).unwrap();
        let commit_burn_header_hash = BurnchainHeaderHash::from_hex("6bd41cec6aa0973a6b586934d870b1e9340918bf05d8fefcba337c8fecb3fdeb").unwrap();

        let leader_key = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: public_key,
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: leader_vtxindex,
            block_height: leader_block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            fork_segment_id: 0,
        };

        let nonmatching_block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 1,
            parent_vtxindex: 1,
            key_block_backptr: (commit_block_height - leader_block_height) as u16,
            key_vtxindex: (leader_vtxindex + 1) as u16,
            epoch_num: 50,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: commit_txid.clone(),
            vtxindex: commit_vtxindex,
            block_height: commit_block_height,
            burn_header_hash: commit_burn_header_hash.clone(),
            
            fork_segment_id: 0,
        };

        let matching_block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 1,
            parent_vtxindex: 1,
            key_block_backptr: (commit_block_height - leader_block_height) as u16,
            key_vtxindex: leader_vtxindex as u16,
            epoch_num: 50,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: commit_txid_2.clone(),
            vtxindex: commit_vtxindex_2,
            block_height: commit_block_height,
            burn_header_hash: commit_burn_header_hash.clone(),
            
            fork_segment_id: 0,
        };

        let mut db = BurnDB::connect_memory(first_block_height, &first_burn_hash).unwrap();

        // make snapshots
        {
            let mut tx = db.tx_begin().unwrap();
            let mut commit_snapshot = BurnDB::get_first_block_snapshot(&tx).unwrap();
            commit_snapshot.fork_segment_length += 1;
            commit_snapshot.fork_length += 1;
            commit_snapshot.block_height = commit_block_height;
            commit_snapshot.burn_header_hash = commit_burn_header_hash.clone();
            BurnDB::insert_block_snapshot(&mut tx, &commit_snapshot).unwrap();
            tx.commit().unwrap();
        }

        let is_consumed_before = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_leader_key_consumed(&mut tx, 102, &leader_key, 0).unwrap()
        };

        assert!(!is_consumed_before);      // doesn't exist in the DB yet, so not consumed

        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_leader_key(&mut tx, &leader_key).unwrap();
            tx.commit().unwrap();
        }

        let is_consumed_after_insert = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_leader_key_consumed(&mut tx, 102, &leader_key, 0).unwrap()
        };

        assert!(!is_consumed_after_insert);     // exists, but not consumed yet 

        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_commit(&mut tx, &nonmatching_block_commit).unwrap();
            tx.commit().unwrap();
        }

        let is_consumed_after_nonmatching = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_leader_key_consumed(&mut tx, 102, &leader_key, 0).unwrap()
        };

        assert!(!is_consumed_after_nonmatching);       // not consumed -- existing block commit doesn't match this leader key

        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_commit(&mut tx, &matching_block_commit).unwrap();
            tx.commit().unwrap();
        }

        let is_consumed = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_leader_key_consumed(&mut tx, 102, &leader_key, 0).unwrap()
        };

        assert!(is_consumed);       // consumed now that a matching block commit has been added 

        // try to reorg at the block commit height
        {
            let mut tx = db.tx_begin().unwrap();
            let commit_snapshot = BurnDB::get_block_snapshot(&tx, &commit_burn_header_hash).unwrap().unwrap();
            let mut last_snapshot = BurnDB::get_block_snapshot(&tx, &commit_snapshot.parent_burn_header_hash).unwrap().unwrap();

            let initial_block_height = last_snapshot.block_height;
            let initial_fork_length = last_snapshot.fork_length;
            let mut fork_segment_id = 1;

            for i in 0..3 {
                let mut next_snapshot = last_snapshot.clone();
               
                next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
                next_snapshot.burn_header_hash = BurnchainHeaderHash([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i + 100]);
                next_snapshot.fork_segment_id = fork_segment_id;
                next_snapshot.fork_segment_length = (i as u64) + 1; 
                next_snapshot.fork_length = initial_fork_length + (i as u64) + 1;
                next_snapshot.block_height = initial_block_height + (i as u64) + 1;
                next_snapshot.parent_fork_segment_id = 0;

                let next_fork_segment_id = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot).unwrap();
                if next_fork_segment_id != fork_segment_id {
                    // did a compactification
                    test_debug!("Switch fork segment from {} to {}", fork_segment_id, next_fork_segment_id);
                    fork_segment_id = next_fork_segment_id;
        
                    let canonical_chain_tip = BurnDB::get_canonical_chain_tip(&tx).unwrap();
                    assert_eq!(canonical_chain_tip.fork_segment_id, next_fork_segment_id);
                    assert_eq!(canonical_chain_tip.block_height, next_snapshot.block_height);

                    next_snapshot.fork_segment_id = next_fork_segment_id;
                }

                last_snapshot = next_snapshot;
            }
            
            tx.commit().unwrap();
        }

        let canonical_chain_tip = BurnDB::get_canonical_chain_tip(db.conn()).unwrap();
        assert_eq!(canonical_chain_tip.fork_segment_id, 0);
       
        // leader key is now available -- the block commit that consumed it is no longer on this
        // fork segment
        let is_consumed_after_reorg = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_leader_key_consumed(&mut tx, 105, &leader_key, 0).unwrap()
        };

        assert!(!is_consumed_after_reorg);
        
        let is_consumed_on_orphan_chain_tip = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::is_leader_key_consumed(&mut tx, 105, &leader_key, 1).unwrap()
        };

        assert!(is_consumed_on_orphan_chain_tip);
    }

    #[test]
    fn get_last_snapshot_with_sortition() {
        let block_height = 123;
        let total_burn_sortition = 100;
        let total_burn_no_sortition = 200;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let first_snapshot = BlockSnapshot {
            block_height: block_height - 2,
            burn_header_hash: first_burn_hash.clone(),
            parent_burn_header_hash: first_burn_hash.clone(),
            consensus_hash: ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
            ops_hash: OpsHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            total_burn: 0,
            sortition: true,
            sortition_hash: SortitionHash::initial(),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            fork_segment_id: 0,
            parent_fork_segment_id: 0,
            fork_segment_length: 0,
            fork_length: 0
        };

        let snapshot_with_sortition = BlockSnapshot {
            block_height: block_height,
            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            parent_burn_header_hash: first_burn_hash.clone(),
            consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            total_burn: total_burn_sortition,
            sortition: true,
            sortition_hash: SortitionHash::initial(),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            
            fork_segment_id: 0,
            parent_fork_segment_id: 0,
            fork_segment_length: 1,
            fork_length: 1
        };

        let snapshot_without_sortition = BlockSnapshot {
            block_height: block_height - 1,
            burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]).unwrap(),
            parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap(),
            consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]).unwrap(),
            ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]).unwrap(),
            total_burn: total_burn_no_sortition,
            sortition: false,
            sortition_hash: SortitionHash::initial(),
            winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
            winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
            
            fork_segment_id: 0,
            parent_fork_segment_id: 0,
            fork_segment_length: 2,
            fork_length: 2
        };

        let mut db = BurnDB::connect_memory(block_height - 2, &first_burn_hash).unwrap();

        let initial_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_last_snapshot_with_sortition(&mut tx, block_height, 0).unwrap()
        };

        assert_eq!(initial_snapshot, first_snapshot);

        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_snapshot(&mut tx, &snapshot_without_sortition).unwrap();
            tx.commit().unwrap();
        }

        let next_snapshot = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_last_snapshot_with_sortition(&mut tx, block_height, 0).unwrap()
        };

        assert_eq!(initial_snapshot, next_snapshot);

        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_snapshot(&mut tx, &snapshot_with_sortition).unwrap();
            tx.commit().unwrap();
        }

        let next_snapshot_2 = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_last_snapshot_with_sortition(&mut tx, block_height, 0).unwrap()
        };

        assert_eq!(snapshot_with_sortition, next_snapshot_2);

        // test inequality
        let next_snapshot_3 = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_last_snapshot_with_sortition(&mut tx, block_height + 1, 0).unwrap()
        };

        assert_eq!(snapshot_with_sortition, next_snapshot_3);
    }

    /// Verify that the snapshots in a fork segemnt are well-formed -- i.e. the block heights are
    /// sequential and the parent block hash of the ith block is equal to the block hash of the
    /// (i-1)th block.
    fn verify_fork_integrity(db: &mut BurnDB, fork_segment_id: u64) {
        let mut child = {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::get_fork_segment_tail(&mut tx, fork_segment_id).unwrap().unwrap()
        };

        let initial = BurnDB::get_first_block_snapshot(db.conn()).unwrap();

        for cur_fork_segment_id in 0..fork_segment_id+1 {
            test_debug!("snapshots in fork {}:", cur_fork_segment_id);
            let snapshots = BurnDB::get_block_snapshots_in_fork_segment(db.conn(), cur_fork_segment_id).unwrap();
            for sn in snapshots {
                test_debug!("block {}: hash={},parent={}", sn.block_height, sn.burn_header_hash.to_hex(), sn.parent_burn_header_hash.to_hex());
            }
        }
       
        test_debug!("Verify from {},hash={},parent={},fid={},pfid={} back to {},hash={},parent={},fid={},pfid={}",
                    child.block_height, child.burn_header_hash.to_hex(), child.parent_burn_header_hash.to_hex(), child.fork_segment_id, child.parent_fork_segment_id,
                    initial.block_height, initial.burn_header_hash.to_hex(), initial.parent_burn_header_hash.to_hex(), initial.fork_segment_id, initial.parent_fork_segment_id);

        while child.block_height > initial.block_height {
            let parent = {
                let mut tx = db.tx_begin().unwrap();
                let next_parent = match BurnDB::get_block_snapshot_in_fork_segment(&mut tx, child.block_height - 1, child.fork_segment_id).unwrap() {
                    Some(sn) => {
                        sn
                    },
                    None => {
                        match BurnDB::get_block_snapshot_in_fork_segment(&mut tx, child.block_height - 1, child.parent_fork_segment_id).unwrap() {
                            Some(sn) => {
                                sn
                            },
                            None => {
                                panic!("No snapshot {} in parent fork {} at height {}", child.parent_burn_header_hash.to_hex(), child.parent_fork_segment_id, child.block_height - 1);
                            }
                        }
                    }
                };
                next_parent
            };

            test_debug!("Verify for {},{}: {} == {} - 1 and hash={},parent_hash={} == parent={}",
                        parent.fork_segment_id, child.fork_segment_id,
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
        let first_burn_hash = BurnchainHeaderHash([0xff; 32]);
        let first_block_height = 100;

        let mut db = BurnDB::connect_memory(first_block_height, &first_burn_hash).unwrap();

        // make an initial fork
        let mut last_snapshot = BurnDB::get_first_block_snapshot(db.conn()).unwrap();

        for i in 0..10 {
            let mut next_snapshot = last_snapshot.clone();

            next_snapshot.fork_segment_length += 1;
            next_snapshot.fork_length += 1;
            next_snapshot.block_height += 1; 
            next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
            next_snapshot.burn_header_hash = BurnchainHeaderHash([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i]);
            
            let mut tx = db.tx_begin().unwrap();
            let next_fork_segment_id = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot).unwrap();
            tx.commit().unwrap();

            // no compactification should happen, yet
            assert_eq!(next_fork_segment_id, 0);

            last_snapshot = next_snapshot.clone();
        }
        
        test_debug!("----- make forks -----");

        // make other forks
        for i in 0..9 { 
            let mut parent_block_hash =
                if i == 0 {
                    [0xff; 32]
                }
                else {
                    let mut tmp = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8];
                    tmp[i-1] = 1;
                    tmp
                };
            
            let parent_block = BurnchainHeaderHash(parent_block_hash);
            test_debug!("----- build fork off of parent {} (i = {}) -----", &parent_block.to_hex(), i);

            let mut last_snapshot = BurnDB::get_block_snapshot(db.conn(), &parent_block).unwrap().unwrap();

            let initial_fork_length = last_snapshot.fork_length;
            let initial_block_height = last_snapshot.block_height;

            let mut next_snapshot = last_snapshot.clone();

            for j in (i+1)..10 {
            
                let mut block_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,j as u8];
                block_hash[i] = (j - i) as u8;

                next_snapshot.fork_segment_id = (i+1) as u64;
                next_snapshot.fork_segment_length = (j - i) as u64;
                next_snapshot.fork_length = initial_fork_length + (j - i) as u64;
                next_snapshot.block_height = initial_block_height + (j - i) as u64;
                next_snapshot.parent_fork_segment_id = i as u64;
                next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
                next_snapshot.burn_header_hash = BurnchainHeaderHash(block_hash);

                let mut tx = db.tx_begin().unwrap();
                let next_fork_segment_id = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot).unwrap();
                tx.commit().unwrap();

                // no compactification should happen (yet)
                assert_eq!(next_fork_segment_id, next_snapshot.fork_segment_id);

                last_snapshot = next_snapshot.clone();
            }
        
            test_debug!("----- made fork {} (i = {}) -----", &next_snapshot.burn_header_hash.to_hex(), i);

            let ancestor_fork_segments = BurnDB::get_ancestor_fork_segments(db.conn(), (i+1) as u64).unwrap();
            let mut expected_fork_segments : Vec<u64> = vec![];
            for j in 0..(i+1) {
                expected_fork_segments.push((i-j+1) as u64);
            }
            expected_fork_segments.push(0);
            assert_eq!(ancestor_fork_segments, expected_fork_segments);

            for fid in expected_fork_segments {
                verify_fork_integrity(&mut db, fid);
            }
        }

        test_debug!("----- grow forks -----");

        // grow each fork so it overtakes the currently-canonical fork
        for i in 0..9 {
            let mut last_block_hash = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9];
            last_block_hash[i] = (9 - i) as u8;
            let last_block = BurnchainHeaderHash(last_block_hash);
            
            test_debug!("----- grow fork {} (i = {}) -----", &last_block.to_hex(), i);

            let mut last_snapshot = BurnDB::get_block_snapshot(db.conn(), &last_block).unwrap().unwrap();
           
            let initial_fork_segment = last_snapshot.fork_segment_id;
            let initial_parent_fork_segment = last_snapshot.parent_fork_segment_id;
            let initial_fork_length = last_snapshot.fork_length;
            let initial_block_height = last_snapshot.block_height;
            let initial_fork_segment_length = last_snapshot.fork_segment_length;

            let mut next_snapshot = last_snapshot.clone();

            // grow the fork up to the length of the previous fork
            for j in 0..((i+1) as u64) {
                next_snapshot = last_snapshot.clone();

                let mut next_block_hash_vec = last_snapshot.burn_header_hash.as_bytes().to_vec();
                next_block_hash_vec[0] += 1;
                let mut next_block_hash = [0u8; 32];
                next_block_hash.copy_from_slice(&next_block_hash_vec[..]);

                next_snapshot.fork_length = last_snapshot.fork_length + 1;
                next_snapshot.block_height = last_snapshot.block_height + 1;
                next_snapshot.fork_segment_length = last_snapshot.fork_segment_length + 1;
                next_snapshot.parent_burn_header_hash = last_snapshot.burn_header_hash.clone();
                next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);

                {
                    let mut tx = db.tx_begin().unwrap();
                    let next_fork_segment_id = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot).unwrap();
                    tx.commit().unwrap();
                }

                last_snapshot = BurnDB::get_block_snapshot(db.conn(), &next_snapshot.burn_header_hash).unwrap().unwrap();
            }

            // make the fork exceed the canonical chain tip 
            next_snapshot = last_snapshot.clone();

            let mut next_block_hash_vec = last_snapshot.burn_header_hash.as_bytes().to_vec();
            next_block_hash_vec[0] = 0xff;
            let mut next_block_hash = [0u8; 32];
            next_block_hash.copy_from_slice(&next_block_hash_vec[..]);

            next_snapshot.fork_length += 1;
            next_snapshot.block_height += 1;
            next_snapshot.fork_segment_length += 1;
            next_snapshot.parent_burn_header_hash = next_snapshot.burn_header_hash.clone();
            next_snapshot.burn_header_hash = BurnchainHeaderHash(next_block_hash);

            let next_fork_segment_id = {
                let mut tx = db.tx_begin().unwrap();
                let next_fork_segment_id = BurnDB::append_chain_tip_snapshot(&mut tx, &last_snapshot, &next_snapshot).unwrap();
                tx.commit().unwrap();
                next_fork_segment_id
            };
            
            assert_eq!(next_fork_segment_id, 0);

            let mut expected_tip = next_snapshot.clone();
            expected_tip.fork_segment_id = 0;
            expected_tip.parent_fork_segment_id = 0;

            let canonical_tip = BurnDB::get_canonical_chain_tip(db.conn()).unwrap();
            assert_eq!(canonical_tip, expected_tip);

            let ancestor_fork_segments = BurnDB::get_ancestor_fork_segments(db.conn(), (i+1) as u64).unwrap();
            let mut expected_fork_segments = vec![];
            for j in 0..(i+1) {
                expected_fork_segments.push((i+1-j) as u64);
            }
            expected_fork_segments.push(0);

            // assert_eq!(expected_fork_segments, ancestor_fork_segments);
            
            for fid in 0..10 {
                verify_fork_integrity(&mut db, fid);
            }
        }
    }
}
