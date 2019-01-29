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
use rusqlite::DropBehavior;
use rusqlite::Transaction;

use std::fs;
use std::fmt;
use std::convert::From;
use std::marker::PhantomData;

use chainstate::burn::db::{FromRow, RowOrder};
use chainstate::burn::db::VRFPublicKey_from_row;
use chainstate::burn::db::ChainstateDB;
use chainstate::burn::db::Error as db_error;

use chainstate::burn::CHAINSTATE_VERSION;
use chainstate::burn::CONSENSUS_HASH_LIFETIME;
use chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash, OpsHash};

use chainstate::burn::operations::{BlockstackOperationType, BlockstackOperation};
use chainstate::burn::operations::leader_block_commit::LeaderBlockCommitOp;
use chainstate::burn::operations::leader_block_commit::OPCODE as LeaderBlockCommitOp_OPCODE;
use chainstate::burn::operations::leader_key_register::LeaderKeyRegisterOp;
use chainstate::burn::operations::leader_key_register::OPCODE as LeaderKeyRegisterOp_OPCODE;
use chainstate::burn::operations::user_burn_support::UserBurnSupportOp;
use chainstate::burn::operations::user_burn_support::OPCODE as UserBurnSupportOp_OPCODE;
use chainstate::burn::operations::Error as op_error;

use burnchains::BurnchainTxInput;
use burnchains::BurnchainTransaction;
use burnchains::BurnchainBlock;
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::address::BitcoinAddress;
use burnchains::{Txid, BurnchainHeaderHash, PublicKey, Address};

use util::vrf::ECVRF_public_key_to_hex;
use util::hash::{to_hex, hex_bytes, Hash160};
use util::pipeline::PipelineProcessor;

use ed25519_dalek::PublicKey as VRFPublicKey;

// a row in the "history" table
pub struct HistoryRow {
    pub txid: Txid,
    pub vtxindex: u32,
    pub block_height: u64,
    pub op: u8,
    pub burn_header_hash: BurnchainHeaderHash,
    pub canonical: bool
}

impl RowOrder for HistoryRow {
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","op","burn_header_hash","canonical"]
    }
}

impl FromRow<HistoryRow> for HistoryRow {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<HistoryRow, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_height_i64 : i64 = row.get(2 + index);
        let op : u8 = row.get(3 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 4 + index)?;
        let canonical : bool = row.get(5 + index);

        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let history_row = HistoryRow {
            txid: txid,
            vtxindex: vtxindex,
            block_height: block_height_i64 as u64,
            op: op,
            burn_header_hash: burn_header_hash,
            canonical: canonical
        };
        Ok(history_row)
    }
}

impl<A, K> From<&LeaderKeyRegisterOp<A, K>> for HistoryRow
where
    A: Address,
    K: PublicKey
{
    fn from(leader_key: &LeaderKeyRegisterOp<A, K>) -> HistoryRow {
        HistoryRow {
            txid: leader_key.txid.clone(),
            vtxindex: leader_key.vtxindex,
            block_height: leader_key.block_number,
            op: leader_key.op,
            burn_header_hash: leader_key.burn_header_hash.clone(),
            canonical: true
        }
    }
}

impl<A, K> From<&LeaderBlockCommitOp<A, K>> for HistoryRow 
where
    A: Address,
    K: PublicKey
{
    fn from(block_commit: &LeaderBlockCommitOp<A, K>) -> HistoryRow {
        HistoryRow {
            txid: block_commit.txid.clone(),
            vtxindex: block_commit.vtxindex,
            block_height: block_commit.block_number,
            op: block_commit.op,
            burn_header_hash: block_commit.burn_header_hash.clone(),
            canonical: true
        }
    }
}

impl<A, K> From<&UserBurnSupportOp<A, K>> for HistoryRow 
where
    A: Address,
    K: PublicKey
{
    fn from(user_support: &UserBurnSupportOp<A, K>) -> HistoryRow {
        HistoryRow {
            txid: user_support.txid.clone(),
            vtxindex: user_support.vtxindex,
            block_height: user_support.block_number,
            op: user_support.op,
            burn_header_hash: user_support.burn_header_hash.clone(),
            canonical: true
        }
    }
}

// a row in the "snapshots" table
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotRow {
    pub block_height: u64,
    pub burn_header_hash: BurnchainHeaderHash,
    pub consensus_hash: ConsensusHash,
    pub ops_hash: OpsHash,
    pub total_burn: u64,
    pub canonical: bool
}

impl RowOrder for SnapshotRow {
    fn row_order() -> Vec<&'static str> {
        vec!["block_height","burn_header_hash","consensus_hash","ops_hash","total_burn","canonical"]
    }
}

impl FromRow<SnapshotRow> for SnapshotRow {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<SnapshotRow, db_error> {
        let block_height_i64 : i64 = row.get(0 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 1 + index)?;
        let consensus_hash = ConsensusHash::from_row(row, 2 + index)?;
        let ops_hash = OpsHash::from_row(row, 3 + index)?;
        let total_burn_str : String = row.get(4 + index);
        let canonical : bool = row.get(5 + index);

        if block_height_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let total_burn = total_burn_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        let snapshot = SnapshotRow {
            block_height: block_height_i64 as u64,
            burn_header_hash: burn_header_hash,
            consensus_hash: consensus_hash,
            ops_hash: ops_hash,
            total_burn: total_burn,
            canonical: canonical
        };
        Ok(snapshot)
    }
}

impl<A, K> RowOrder for LeaderKeyRegisterOp<A, K>
where
    A: Address,
    K: PublicKey
{
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","consensus_hash","public_key","memo","address"]
    }
}

impl<A, K> FromRow<LeaderKeyRegisterOp<A, K>> for LeaderKeyRegisterOp<A, K>
where
    A: Address + FromRow<A>,
    K: PublicKey
{
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<LeaderKeyRegisterOp<A, K>, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_number : i64 = row.get(2 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 3 + index)?;
        let consensus_hash = ConsensusHash::from_row(row, 4 + index)?;
        let public_key = VRFPublicKey_from_row(row, 5 + index)?;
        let memo_hex : String = row.get(6 + index);
        let address = A::from_row(row, 7 + index)?;
            // BitcoinAddress::from_row(row, 7 + index)?;

        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        if block_number < 0 {
            return Err(db_error::ParseError);
        }

        let leader_key_row = LeaderKeyRegisterOp {
            txid: txid,
            vtxindex: vtxindex,
            block_number: block_number as u64,
            burn_header_hash: burn_header_hash,
            op: LeaderKeyRegisterOp_OPCODE,

            consensus_hash: consensus_hash,
            public_key: public_key,
            memo: memo, 
            address: address,
                    
            _phantom: PhantomData
        };

        Ok(leader_key_row)
    }
}

impl<A, K> RowOrder for LeaderBlockCommitOp<A, K>
where
    A: Address,
    K: PublicKey,
{
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","block_header_hash","new_seed",
             "parent_block_backptr","parent_vtxindex","key_block_backptr","key_vtxindex",
             "epoch_num","memo","burn_fee","input"]
    }
}

impl<A, K> FromRow<LeaderBlockCommitOp<A, K>> for LeaderBlockCommitOp<A, K>
where
    A: Address,
    K: PublicKey
{
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<LeaderBlockCommitOp<A, K>, db_error> {
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

        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        let input = serde_json::from_str::<BurnchainTxInput<K>>(&input_json)
            .map_err(|e| db_error::SerializationError(e))?;

        let burn_fee = burn_fee_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        if block_height < 0 {
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

            op: LeaderBlockCommitOp_OPCODE,
            txid: txid,
            vtxindex: vtxindex,
            block_number: block_height as u64,
            burn_header_hash: burn_header_hash,

            _phantom: PhantomData
        };
        Ok(block_commit)
    }
}

impl<A, K> RowOrder for UserBurnSupportOp<A, K> 
where
    A: Address,
    K: PublicKey
{
    fn row_order() -> Vec<&'static str> {
        vec!["txid","vtxindex","block_height","burn_header_hash","consensus_hash","public_key","block_header_hash_160","memo","burn_fee"]
    }
}

impl<A, K> FromRow<UserBurnSupportOp<A, K>> for UserBurnSupportOp<A, K>
where
    A: Address, 
    K: PublicKey
{
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<UserBurnSupportOp<A, K>, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_height : i64 = row.get(2 + index);
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 3 + index)?;

        let consensus_hash = ConsensusHash::from_row(row, 4 + index)?;
        let public_key = VRFPublicKey_from_row(row, 5 + index)?;
        let block_header_hash_160 = Hash160::from_row(row, 6 + index)?;
        let memo_hex : String = row.get(7 + index);

        let burn_fee_str : String = row.get(8 + index);
        
        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        let burn_fee = burn_fee_str.parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        if block_height < 0 {
            return Err(db_error::ParseError);
        }

        let user_burn = UserBurnSupportOp {
            consensus_hash: consensus_hash,
            public_key: public_key,
            block_header_hash_160: block_header_hash_160,
            memo: memo,
            burn_fee: burn_fee,

            op: UserBurnSupportOp_OPCODE,
            txid: txid,
            vtxindex: vtxindex,
            block_number: block_height as u64,
            burn_header_hash: burn_header_hash,

            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };
        Ok(user_burn)
    }
}

const BURNDB_SETUP : &'static [&'static str]= &[
    r#"
    CREATE TABLE history(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,
        op TEXT NOT NULL,
        canonical INTEGER NOT NULL,     -- whether or not this history item is on the canonical burn chain history
        PRIMARY KEY(txid,burn_header_hash)
    );"#,
    r#"
    CREATE INDEX block_history ON history(block_height, txid, burn_header_hash);
    "#,
    r#"
    CREATE TABLE snapshots(
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        ops_hash TEXT NOT NULL,
        total_burn TEXT NOT NULL,
        canonical INTEGER NOT NULL,     -- whether or not this history item is on the canonical burn chain history
        PRIMARY KEY(burn_header_hash)
    );"#,
    r#"
    CREATE INDEX snapshot_blocks ON snapshots(block_height, burn_header_hash);
    "#,
    r#"
    -- all leader keys registered in the blockchain
    -- note that we do not normalize -- the history entries are repeated to make reads faster
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
        FOREIGN KEY(txid,burn_header_hash) REFERENCES history(txid,burn_header_hash)
    );"#,
    r#"
    CREATE INDEX leader_key_blocks ON leader_keys(public_key, txid, burn_header_hash);
    "#,
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

        PRIMARY KEY(txid,burn_header_hash),
        FOREIGN KEY(txid,burn_header_hash) REFERENCES history(txid,burn_header_hash)
    );"#,
    r#"
    CREATE TABLE user_burn_support(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        block_header_hash_160 TEXT NOT NULL,
        memo TEXT,

        burn_fee TEXT NOT NULL,

        PRIMARY KEY(txid,burn_header_hash),
        FOREIGN KEY(txid,burn_header_hash) REFERENCES history(txid,burn_header_hash)
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];

pub struct BurnDB<A, K>
where
    A: Address,
    K: PublicKey
{
    pub conn: Connection,
    pub readwrite: bool,
    pub tx_active: bool,
    pub first_block_height: u64,
    pub first_burn_header_hash: BurnchainHeaderHash,

    // required to make the compiler behave
    _phantom_a: PhantomData<A>,
    _phantom_k: PhantomData<K>
}

impl<A, K> BurnDB<A, K>
where
    A: Address, 
    K: PublicKey
{
    fn instantiate(&mut self) -> Result<(), db_error> {

        // create first (sentinel) snapshot
        let first_snapshot = SnapshotRow {
            block_height: self.first_block_height,
            burn_header_hash: self.first_burn_header_hash.clone(),
            consensus_hash: ConsensusHash::from_hex("0000000000000000000000000000000000000000").unwrap(),
            ops_hash: OpsHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            total_burn: 0,
            canonical: true
        };

        let mut tx = self.tx_begin()?;

        for row_text in BURNDB_SETUP {
            tx.execute(row_text, NO_PARAMS)
                .map_err(|e| db_error::SqliteError(e))?;
        }

        tx.execute("INSERT INTO db_version (version) VALUES (?1)", &[&CHAINSTATE_VERSION])
            .map_err(|e| db_error::SqliteError(e))?;

        BurnDB::<A, K>::insert_snapshot_row(&mut tx, &first_snapshot)?;
        tx.commit();

        Ok(())
    }

    /// Open the burn database at the given path.  Open read-only or read/write.
    /// If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(path: &String, first_block_height: u64, first_burn_hash: &BurnchainHeaderHash, readwrite: bool) -> Result<BurnDB<A, K>, db_error> {
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
            .map_err(|e| db_error::SqliteError(e))?;

        let mut db = BurnDB {
            conn: conn,
            readwrite: readwrite,
            tx_active: false,
            first_block_height: first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };

        if create_flag {
            // instantiate!
            db.instantiate()?;
        }
        Ok(db)
    }

    /// Open a burn database in memory (used for testing)
    pub fn connect_memory(first_block_height: u64, first_burn_hash: &BurnchainHeaderHash) -> Result<BurnDB<A, K>, db_error> {
        let conn = Connection::open_in_memory()
            .map_err(|e| db_error::SqliteError(e))?;

        let mut db = BurnDB {
            conn: conn,
            readwrite: true,
            tx_active: false,
            first_block_height: first_block_height,
            first_burn_header_hash: first_burn_hash.clone(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };

        db.instantiate()?;
        Ok(db)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Get the previous consensus hashes that must be hashed to find
    /// the next consensus hash at a particular block.
    fn get_prev_consensus_hashes(conn: &Connection, block_height: u64, first_block_height: u64) -> Result<Vec<ConsensusHash>, db_error> {
        let mut i = 1;
        let mut prev_chs = vec![];
        while block_height - (((1 as u64) << i) - 1) >= first_block_height {
            let prev_block : u64 = block_height - (((1 as u64) << i) - 1);
            let prev_ch_opt = BurnDB::<A, K>::get_consensus_at(conn, prev_block)?;
            match prev_ch_opt {
                Some(prev_ch) => {
                    prev_chs.push(prev_ch.clone());
                    i += 1;
                }
                None => {
                    error!("Failed to read consensus hash for block height {}", prev_block);
                    return Err(db_error::Corruption);
                }
            };
        }
        Ok(prev_chs)
    }

    /// Make a new consensus hash, given the ops hash 
    fn make_consensus_hash(conn: &Connection, opshash: &OpsHash, block_height: u64, first_block_height: u64, total_burn: u64) -> Result<ConsensusHash, db_error> {
        let prev_consensus_hashes = BurnDB::<A, K>::get_prev_consensus_hashes(conn, block_height, first_block_height)?;
        Ok(ConsensusHash::from_ops(opshash, total_burn, &prev_consensus_hashes))
    }

    /// Find out how any burn tokens were destroyed in a given (canonical) block
    fn find_block_burn_amount<'a>(tx: &mut Transaction<'a>, block_height: u64) -> Result<u64, db_error>
    {
        let user_burns = BurnDB::<A, K>::get_user_burns_by_block(tx, block_height)?;
        let block_commits = BurnDB::<A, K>::get_block_commits_by_block(tx, block_height)?;
        let mut burn_total = 0;

        for i in (0..user_burns.len()) {
            if burn_total + user_burns[i].burn_fee < 0 {
                return Err(db_error::Overflow);
            }

            burn_total += user_burns[i].burn_fee;
        }
        for i in (0..block_commits.len()) {
            if burn_total + user_burns[i].burn_fee < 0 {
                return Err(db_error::Overflow);
            }

            burn_total += block_commits[i].burn_fee;
        }
        Ok(burn_total)
    }

    /// Make a block snapshot 
    fn make_snapshot_row(conn: &Connection, block_height: u64, burn_header_hash: &BurnchainHeaderHash, first_block_height: u64, txids: &Vec<Txid>, total_burn: u64) -> Result<SnapshotRow, db_error> {
        let ops_hash = OpsHash::from_txids(txids);
        let ch = BurnDB::<A, K>::make_consensus_hash(conn, &ops_hash, block_height, first_block_height, total_burn)?;
        
        Ok(SnapshotRow {
            block_height: block_height,
            burn_header_hash: burn_header_hash.clone(),
            consensus_hash: ch,
            ops_hash: ops_hash,
            total_burn: total_burn,
            canonical: true
        })
    }

    /// Process a burn chain reorganization -- given the height at which the reorg starts,
    /// invalidate all blocks and transactions processed since then.
    pub fn burnchain_history_reorg<'a>(tx: &mut Transaction<'a>, reorg_height: u64) -> Result<(), db_error> {
        if reorg_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        // de-canonicalize operations that have occurred at or after this block height.
        // we will need to reprocess them.
        let affected_tables = vec!["leader_keys", "block_commits", "user_support_burns", "history", "snapshots"];
        for i in 0..affected_tables.len() {
            let sql = format!("UPDATE {} SET canonical = 0 WHERE block_height >= ?1", &affected_tables[i]);
            tx.execute(&sql, &[&(reorg_height as i64) as &ToSql])
              .map_err(|e| db_error::SqliteError(e))?;
        }

        Ok(())
    }

    /// What is the height of our burn chain database?  only consider the sequence of snapshots
    /// that correspond to the canonical burn chain history.
    pub fn get_block_height(conn: &Connection) -> Result<u64, db_error> {
        let sql_qry = "SELECT MAX(block_height) FROM snapshots WHERE canonical = 1";
        let args = NO_PARAMS;
        let res = BurnDB::<A, K>::query_count(conn, &sql_qry.to_string(), args)?;
        Ok(res as u64)
    }

    /// Begin a transaction.  TODO: use immediate mode?
    pub fn tx_begin<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = self.conn.transaction()
            .map_err(|e| db_error::SqliteError(e))?;
        Ok(tx)
    }

    /// Insert a history row
    fn insert_history_row<'a>(tx: &mut Transaction<'a>, history_row: &HistoryRow) -> Result<(), db_error> {
        // make sure our u64 values fit into i64 space
        if history_row.block_height > ((1 as u64) << 63 - 1) {
            return Err(db_error::TypeError);
        }

        tx.execute("INSERT OR REPLACE INTO history (txid, vtxindex, block_height, burn_header_hash, op, canonical) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[&history_row.txid.to_hex(), &history_row.vtxindex as &ToSql, &(history_row.block_height as i64), &history_row.burn_header_hash.to_hex(), &history_row.op, &true as &ToSql])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }

    /// Insert a snapshots row from a block's-worth of operations. 
    fn insert_snapshot_row<'a>(tx: &mut Transaction<'a>, snapshot: &SnapshotRow) -> Result<(), db_error> {
        if snapshot.block_height > ((1 as u64) << 63 - 1) {
            return Err(db_error::TypeError);
        }

        let total_burn_str = format!("{}", snapshot.total_burn);
        tx.execute("INSERT OR REPLACE INTO snapshots (block_height, burn_header_hash, consensus_hash, ops_hash, total_burn, canonical) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                   &[&(snapshot.block_height as i64) as &ToSql, &snapshot.burn_header_hash.to_hex(), &snapshot.consensus_hash.to_hex(), &snapshot.ops_hash.to_hex(), &total_burn_str, &snapshot.canonical as &ToSql])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    pub fn insert_leader_key<'a>(tx: &mut Transaction<'a>, leader_key: &LeaderKeyRegisterOp<A, K>) -> Result<(), db_error> {
        let hist_row = HistoryRow::from(leader_key);
        BurnDB::<A, K>::insert_history_row(tx, &hist_row)?;

        tx.execute("INSERT OR REPLACE INTO leader_keys (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, memo, address) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                   &[&leader_key.txid.to_hex(), &leader_key.vtxindex as &ToSql, &(leader_key.block_number as i64) as &ToSql, &leader_key.burn_header_hash.to_hex(),
                   &leader_key.consensus_hash.to_hex(), &ECVRF_public_key_to_hex(&leader_key.public_key), &to_hex(&leader_key.memo), &leader_key.address.to_string()])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }
    
    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    pub fn insert_block_commit<'a>(tx: &mut Transaction<'a>, block_commit: &LeaderBlockCommitOp<A, K>) -> Result<(), db_error> {
        let hist_row = HistoryRow::from(block_commit);
        BurnDB::<A, K>::insert_history_row(tx, &hist_row)?;

        // serialize tx input to JSON
        let tx_input_str = serde_json::to_string(&block_commit.input)
            .map_err(|e| db_error::SerializationError(e))?;

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", block_commit.burn_fee);

        tx.execute("INSERT OR REPLACE INTO block_commits (txid, vtxindex, block_height, burn_header_hash, block_header_hash, new_seed, parent_block_backptr, parent_vtxindex, key_block_backptr, key_vtxindex, epoch_num, memo, burn_fee, input) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    &[&block_commit.txid.to_hex(), &block_commit.vtxindex as &ToSql, &(block_commit.block_number as i64) as &ToSql, &block_commit.burn_header_hash.to_hex(), 
                    &block_commit.block_header_hash.to_hex(), &block_commit.new_seed.to_hex(), &block_commit.parent_block_backptr as &ToSql, &block_commit.parent_vtxindex as &ToSql,
                    &block_commit.key_block_backptr as &ToSql, &block_commit.key_vtxindex as &ToSql, &block_commit.epoch_num as &ToSql, &to_hex(&block_commit.memo[..]), 
                    &burn_fee_str, &tx_input_str])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }

    /// Insert a user support burn.
    /// No validity checking will be done, beyond what is encoded in the user_burn_support table
    /// constraints.  That is, type mismatches and serialization errors will be caught, but nothing
    /// else.
    pub fn insert_user_burn<'a>(tx: &mut Transaction<'a>, user_burn: &UserBurnSupportOp<A, K>) -> Result<(), db_error> {
        let hist_row = HistoryRow::from(user_burn);
        BurnDB::<A, K>::insert_history_row(tx, &hist_row)?;

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", user_burn.burn_fee);

        tx.execute("INSERT OR REPLACE INTO user_burn_support (txid, vtxindex, block_height, burn_header_hash, consensus_hash, public_key, block_header_hash_160, memo, burn_fee) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                   &[&user_burn.txid.to_hex(), &user_burn.vtxindex as &ToSql, &(user_burn.block_number as i64) as &ToSql, &user_burn.burn_header_hash.to_hex(), &user_burn.consensus_hash.to_hex(),
                   &ECVRF_public_key_to_hex(&user_burn.public_key), &user_burn.block_header_hash_160.to_hex(), &to_hex(&user_burn.memo[..]), &burn_fee_str])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }

    /// boilerplate code for querying rows 
    fn query_rows<T, P>(conn: &Connection, sql_query: &String, sql_args: P) -> Result<Vec<T>, db_error>
    where
        P: IntoIterator,
        P::Item: ToSql,
        T: FromRow<T>
    {
        let mut stmt = conn.prepare(sql_query)
            .map_err(|e| db_error::SqliteError(e))?;

        let mut rows = stmt.query(sql_args)
            .map_err(|e| db_error::SqliteError(e))?;

        // gather 
        let mut row_data = vec![];
        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let next_row = T::from_row(&row, 0)?;
                    row_data.push(next_row);
                },
                Err(e) => {
                    return Err(db_error::SqliteError(e));
                }
            };
        }

        Ok(row_data)
    }

    /// boilerplate code for querying a count of something
    fn query_count<P>(conn: &Connection, sql_query: &String, sql_args: P) -> Result<i64, db_error>
    where
        P: IntoIterator,
        P::Item: ToSql
    {
        let mut stmt = conn.prepare(sql_query)
            .map_err(|e| db_error::SqliteError(e))?;

        stmt.query_row(sql_args,
            |row| {
                let res : i64 = row.get(0);
                res
            })
            .map_err(|e| db_error::SqliteError(e))
    }

    /// Get a canonical snapshot row 
    pub fn get_block_snapshot(conn: &Connection, block_height: u64) -> Result<Option<SnapshotRow>, db_error> {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        let row_order = SnapshotRow::row_order().join(",");
        let qry = format!("SELECT {} FROM snapshots WHERE canonical = 1 AND block_height = ?1", row_order);
        let args = [&(block_height as i64) as &ToSql];
        let rows = BurnDB::<A, K>::query_rows::<SnapshotRow, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple canonical block snapshots for {}", block_height);
            }
        }
    }

    /// Get all leader keys registered in a block on the canonical history.
    pub fn get_leader_keys_by_block(conn: &Connection, block_height: u64) -> Result<Vec<LeaderKeyRegisterOp<A, K>>, db_error>
    where
        LeaderKeyRegisterOp<A, K>: FromRow<LeaderKeyRegisterOp<A, K>> + RowOrder
    {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        let row_order_list : Vec<String> = LeaderKeyRegisterOp::row_order().iter().map(|r| format!("leader_keys.{}", r)).collect();
        let row_order = row_order_list.join(",");

        let qry = format!("SELECT {} FROM leader_keys JOIN history ON leader_keys.txid = history.txid WHERE history.canonical = 1 AND leader_keys.block_height = ?1 ORDER BY leader_keys.vtxindex ASC", row_order);
        let args = [&(block_height as i64) as &ToSql];
        BurnDB::<A, K>::query_rows::<LeaderKeyRegisterOp<A, K>, _>(conn, &qry.to_string(), &args)
    }

    /// Get a leader key at a specific location in the burn chain's canonical history.
    /// Returns None if there is no leader key at this location.
    pub fn get_leader_key(conn: &Connection, block_height: u64, vtxindex: u32) -> Result<Option<LeaderKeyRegisterOp<A, K>>, db_error>
    where
        LeaderKeyRegisterOp<A, K>: FromRow<LeaderKeyRegisterOp<A, K>> + RowOrder
    {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        let row_order_list : Vec<String> = LeaderKeyRegisterOp::row_order().iter().map(|r| format!("leader_keys.{}", r)).collect();
        let row_order = row_order_list.join(",");

        let qry = format!("SELECT {} FROM leader_keys JOIN history ON leader_keys.txid = history.txid WHERE history.canonical = 1 AND leader_keys.block_height = ?1 AND leader_keys.vtxindex = ?2 ORDER BY leader_keys.vtxindex ASC", row_order);
        let args = [&(block_height as i64) as &ToSql, &vtxindex as &ToSql];
        let rows = BurnDB::<A, K>::query_rows::<LeaderKeyRegisterOp<A, K>, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // should never happen 
                panic!("FATAL: multiple leader keys at block {} vtxindex {}", block_height, vtxindex);
            }
        }
    }

    /// Get all block commitments registered in a block on the burn chain's canonical history.
    pub fn get_block_commits_by_block(conn: &Connection, block_height: u64) -> Result<Vec<LeaderBlockCommitOp<A, K>>, db_error>
    where
        LeaderBlockCommitOp<A, K>: FromRow<LeaderBlockCommitOp<A, K>> + RowOrder
    {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        let row_order_list : Vec<String> = LeaderBlockCommitOp::row_order().iter().map(|r| format!("block_commits.{}", r)).collect();
        let row_order = row_order_list.join(",");

        let qry = format!("SELECT {} FROM block_commits JOIN history ON block_commits.txid = history.txid WHERE history.canonical = 1 AND block_commits.block_height = ?1 ORDER BY block_commits.vtxindex ASC", row_order);
        let args = [&(block_height as i64) as &ToSql];

        BurnDB::<A, K>::query_rows::<LeaderBlockCommitOp<A, K>, _>(conn, &qry.to_string(), &args)
    }
    
    /// Get all user burns registered in a block on the burn chain's canonical history
    pub fn get_user_burns_by_block(conn: &Connection, block_height: u64) -> Result<Vec<UserBurnSupportOp<A, K>>, db_error>
    where
        UserBurnSupportOp<A, K>: FromRow<UserBurnSupportOp<A, K>> + RowOrder
    {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        let row_order_list : Vec<String> = UserBurnSupportOp::row_order().iter().map(|r| format!("user_burn_support.{}", r)).collect();
        let row_order = row_order_list.join(",");

        let qry = format!("SELECT {} FROM user_burn_support JOIN history ON user_burn_support.txid = history.txid WHERE history.canonical = 1 AND user_burn_support.block_height = ?1 ORDER BY user_burn_support.vtxindex ASC", row_order);
        let args = [&(block_height as i64) as &ToSql];

        BurnDB::<A, K>::query_rows::<UserBurnSupportOp<A, K>, _>(conn, &qry.to_string(), &args)
    }

    /// Find out whether or not a particular VRF key was used before in the canonical burnchain history
    pub fn has_VRF_public_key(conn: &Connection, key: &VRFPublicKey) -> Result<bool, db_error> {
        let qry = "SELECT COUNT(leader_keys.public_key) FROM leader_keys JOIN history ON leader_keys.txid = history.txid WHERE history.canonical = 1 AND leader_keys.public_key = ?1 AND history.canonical = 1";
        let args = [&ECVRF_public_key_to_hex(&key)];
        let count = BurnDB::<A, K>::query_count(conn, &qry.to_string(), &args)?;
        Ok(count != 0)
    }

    /// Find out whether or not a given consensus hash is "recent" enough to be used in the
    /// canonical burnchain history
    pub fn is_fresh_consensus_hash(conn: &Connection, current_block_height: u64, consensus_hash: &ConsensusHash) -> Result<bool, db_error> {
        if current_block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        if current_block_height < (CONSENSUS_HASH_LIFETIME as u64) {
            return Err(db_error::TypeError);
        }

        let qry = "SELECT COUNT(consensus_hash) FROM snapshots WHERE canonical = 1 AND consensus_hash = ?1 AND block_height >= ?2 AND block_height <= ?3";
        let args = [&consensus_hash.to_hex(), &((current_block_height as u32) - CONSENSUS_HASH_LIFETIME) as &ToSql, &(current_block_height as u32) as &ToSql];
        let count = BurnDB::<A, K>::query_count(conn, &qry.to_string(), &args)?;
        Ok(count != 0)
    }

    /// Get a consensus hash at a particular block height 
    /// Returns None if there is no consensus hash at this given block height
    pub fn get_consensus_at(conn: &Connection, block_height: u64) -> Result<Option<ConsensusHash>, db_error> {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        let qry = "SELECT consensus_hash FROM snapshots WHERE canoncal = 1 AND block_height = ?1";
        let args = [&(block_height as i64) as &ToSql];

        let mut stmt = conn.prepare(qry)
            .map_err(|e| db_error::SqliteError(e))?;

        stmt.query_row(&args,
            |row| {
                match ConsensusHash::from_row(&row, 0) {
                    Ok(ch) => Some(ch),
                    Err(_e) => None
                }
            })
            .map_err(|e| db_error::SqliteError(e))
    }

    /// Classify a burnchain transaction as a burn database operation 
    pub fn classify_transaction(block_height: u64, block_hash: &BurnchainHeaderHash, burn_tx: &BurnchainTransaction<A, K>) -> Option<BlockstackOperationType<A, K>> {
        match burn_tx.opcode {
            LeaderKeyRegisterOp_OPCODE => {
                match LeaderKeyRegisterOp::from_tx(block_height, block_hash, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::LeaderKeyRegister(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse leader key register tx {} data {}: {:?}", &burn_tx.txid.to_hex(), &to_hex(&burn_tx.data[..]), e);
                        None
                    }
                }
            },
            LeaderBlockCommitOp_OPCODE => {
                match LeaderBlockCommitOp::from_tx(block_height, block_hash, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::LeaderBlockCommit(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse leader block commit tx {} data {}: {:?}", &burn_tx.txid.to_hex(), &to_hex(&burn_tx.data[..]), e);
                        None
                    }
                }
            },
            UserBurnSupportOp_OPCODE => {
                match UserBurnSupportOp::from_tx(block_height, block_hash, burn_tx) {
                    Ok(op) => {
                        Some(BlockstackOperationType::UserBurnSupport(op))
                    },
                    Err(e) => {
                        warn!("Failed to parse user burn support tx {} data {}: {:?}", &burn_tx.txid.to_hex(), &to_hex(&burn_tx.data[..]), e);
                        None
                    }
                }
            },
            _ => {
                None
            }
        }
    }

    /// Check a burnchain transaction to determine if it is valid -- i.e. that it can be committed 
    pub fn check_transaction(conn: &Connection, blockstack_op: &BlockstackOperationType<A, K>) -> Result<bool, op_error> { 
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                LeaderKeyRegisterOp::check(op, conn)
                  .and_then(|res| {
                      if res {
                          info!("ACCEPT leader key register {}", &op.txid.to_hex());
                      }
                      else {
                          warn!("REJECT leader key register {}", &op.txid.to_hex());
                      }
                      Ok(res)
                  })
            },
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                LeaderBlockCommitOp::check(op, conn)
                  .and_then(|res| {
                      if res {
                          info!("ACCEPT leader block commit {}", &op.txid.to_hex());
                      }
                      else {
                          warn!("REJECT leader block commit {}", &op.txid.to_hex());
                      }
                      Ok(res)
                  })
            },
            BlockstackOperationType::UserBurnSupport(ref op) => {
                UserBurnSupportOp::check(op, conn)
                  .and_then(|res| {
                      if res {
                          info!("ACCEPT user burn support {}", &op.txid.to_hex());
                      }
                      else {
                          warn!("REJECT user burn support {}", &op.txid.to_hex());
                      }
                      Ok(res)
                  })
            }
        }
    }

    /// commit a transaction 
    pub fn commit_transaction<'a>(tx: &mut Transaction<'a>, blockstack_op: &BlockstackOperationType<A, K>) -> Result<(), db_error> { 
        match blockstack_op {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                info!("COMMIT leader key register {}", &op.txid.to_hex());
                BurnDB::insert_leader_key(tx, op)
            },
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                info!("COMMIT leader block commit {}", &op.txid.to_hex());
                BurnDB::insert_block_commit(tx, op)
            },
            BlockstackOperationType::UserBurnSupport(ref op) => {
                info!("COMMIT user burn support {}", &op.txid.to_hex());
                BurnDB::insert_user_burn(tx, op)
            }
        }
    }

    /// Process a burnchain block from Bitcoin. Check each transaction and commit the valid ones.
    /// Panics if any database operation fails.
    pub fn process_block(&mut self, block: &BurnchainBlock<A, K>) -> Result<(), db_error>
    {
        let first_block_height = self.first_block_height;
        debug!("Process block {} {}", block.block_height, &block.block_hash.to_hex());
        
        let mut tx = self.tx_begin()?;

        // commit each transaction
        for i in 0..block.txs.len() {
            match BurnDB::classify_transaction(block.block_height, &block.block_hash, &block.txs[i]) {
                None => {
                    continue;
                },
                Some(ref blockstack_op) => {
                    match BurnDB::check_transaction(&tx, blockstack_op) {
                        Err(op_error) => {
                            panic!("FATAL ERROR when processing burnchain transaction {}", &block.txs[i].txid.to_hex());
                        },
                        Ok(res) => {
                            if res {
                                // accepted, so commit 
                                match BurnDB::commit_transaction(&mut tx, blockstack_op) {
                                    Err(db_error) => {
                                        panic!("FATAL ERROR when inserting burnchain transaction {}", &block.txs[i].txid.to_hex());
                                    }
                                    Ok(_) => {}
                                };
                            }
                            else {
                                // rejected
                                continue;
                            }
                        }
                    };
                }
            };
        }

        // snapshot
        let txids : Vec<Txid> = block.txs.iter()
                                         .map(|tx| tx.txid.clone())
                                         .collect();

        let block_burn_total = BurnDB::<A, K>::find_block_burn_amount(&mut tx, block.block_height)
            .map_err(|e| panic!("FATAL ERROR when trying to query burn amount for block {}", block.block_height))?;

        let last_block_snapshot_opt = BurnDB::<A, K>::get_block_snapshot(&mut tx, block.block_height - 1)
            .map_err(|e| panic!("FATAL ERROR when trying to get block snapshot for block {}", block.block_height))?;

        let chain_burn_total = 
            match last_block_snapshot_opt {
                Some(prev_snapshot) => prev_snapshot.total_burn,
                None => 0
            };
       
        if block_burn_total + chain_burn_total < 0 {
            panic!("FATAL ERROR burn total overflow ({} + {})", block_burn_total, chain_burn_total);
        }

        let snapshot = BurnDB::<A, K>::make_snapshot_row(&mut tx, block.block_height, &block.block_hash, first_block_height, &txids, block_burn_total + chain_burn_total)
            .map_err(|_e| panic!("FATAL ERROR when taking snapshot at block {} ({})", block.block_height, &block.block_hash.to_hex()))?;

        BurnDB::<A, K>::insert_snapshot_row(&mut tx, &snapshot)
            .map_err(|_e| panic!("FATAL ERROR when inserting snapshot for block {} ({})", block.block_height, &block.block_hash.to_hex()))?;
        
        info!("OPSHASH({}): {}", block.block_height, &snapshot.ops_hash.to_hex());
        info!("CONSENSUS({}): {}", block.block_height, &snapshot.consensus_hash.to_hex());

        // commit everything!
        tx.commit();
        Ok(())
    }
}

impl<A, K> ChainstateDB for BurnDB<A, K>
where
    A: Address,
    K: PublicKey
{
    fn backup(backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chainstate::burn::db::Error as db_error;

    use chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash};

    use chainstate::burn::operations::leader_block_commit::LeaderBlockCommitOp;
    use chainstate::burn::operations::leader_key_register::LeaderKeyRegisterOp;
    use chainstate::burn::operations::leader_key_register::OPCODE as LeaderKeyRegisterOp_OPCODE;
    use chainstate::burn::operations::user_burn_support::UserBurnSupportOp;
    use chainstate::burn::operations::user_burn_support::OPCODE as UserBurnSupportOp_OPCODE;

    use burnchains::BurnchainTxInput;
    use burnchains::BurnchainInputType;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::BitcoinAddress;

    use burnchains::{Txid, BurnchainHeaderHash};

    use util::hash::{hex_bytes, Hash160};

    use ed25519_dalek::PublicKey as VRFPublicKey;

    use burnchains::bitcoin::BitcoinNetworkType;

    #[test]
    fn test_instantiate() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let _db : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(123, &first_burn_hash).unwrap();
    }

    #[test]
    fn test_tx_begin_end() {
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut db : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(123, &first_burn_hash).unwrap();
        let tx = db.tx_begin().unwrap();
        tx.commit();
    }

    #[test]
    fn test_insert_leader_key() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let leader_key : LeaderKeyRegisterOp<BitcoinAddress, BitcoinPublicKey> = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap(),

            op: LeaderKeyRegisterOp_OPCODE,
            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_number: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            _phantom: PhantomData
        };

        let mut db : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(123, &first_burn_hash).unwrap();

        {   // force the tx to go out of scope when we commit
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_leader_key(&mut tx, &leader_key).unwrap();
            tx.commit();
        }

        let res_leader_keys = BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_leader_keys_by_block(db.conn(), block_height).unwrap();
        assert_eq!(res_leader_keys.len(), 1);
        assert_eq!(res_leader_keys[0], leader_key);

        let no_leader_keys = BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_leader_keys_by_block(db.conn(), block_height+1).unwrap();
        assert_eq!(no_leader_keys.len(), 0);

        let leader_key_opt = BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_leader_key(db.conn(), block_height, vtxindex).unwrap();
        assert!(leader_key_opt.is_some());
        assert_eq!(leader_key_opt.unwrap(), leader_key);

        let leader_key_none = BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_leader_key(db.conn(), block_height, vtxindex+1).unwrap();
        assert!(leader_key_none.is_none());

        // should fail -- block height too big 
        match BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_leader_keys_by_block(db.conn(), (1 as u64) << 63) {
            Err(db_error::TypeError) => {},
            _ => assert!(false)
        };

        match BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_leader_key(db.conn(), (1 as u64) << 63, vtxindex) {
            Err(db_error::TypeError) => {},
            _ => assert!(false)
        };
    }

    #[test]
    fn test_insert_block_commit() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let block_commit : LeaderBlockCommitOp<BitcoinAddress, BitcoinPublicKey> = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 0x4140,
            parent_vtxindex: 0x4342,
            key_block_backptr: 0x5150,
            key_vtxindex: 0x6160,
            epoch_num: 0x71706362,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainTxInput {
                keys: vec![
                    BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_required: 1, 
                in_type: BurnchainInputType::BitcoinInput,
            },

            op: 91,     // '[' in ascii
            txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_number: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),

            _phantom: PhantomData
        };

        let mut db : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(123, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_commit(&mut tx, &block_commit).unwrap();
            tx.commit();
        }

        let res_block_commits = BurnDB::get_block_commits_by_block(db.conn(), block_height).unwrap();
        assert_eq!(res_block_commits.len(), 1);
        assert_eq!(res_block_commits[0], block_commit);

        let no_block_commits = BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_leader_keys_by_block(db.conn(), block_height+1).unwrap();
        assert_eq!(no_block_commits.len(), 0);

        match BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_block_commits_by_block(db.conn(), (1 as u64) << 63) {
            Err(db_error::TypeError) => {},
            _ => assert!(false)
        };
    }

    #[test]
    fn test_insert_user_burn() {
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let user_burn : UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey> = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 12345,

            op: UserBurnSupportOp_OPCODE,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_number: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        };

        let mut db : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(123, &first_burn_hash).unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_user_burn(&mut tx, &user_burn).unwrap();
            tx.commit();
        }

        let res_user_burns = BurnDB::get_user_burns_by_block(db.conn(), block_height).unwrap();
        assert_eq!(res_user_burns.len(), 1);
        assert_eq!(res_user_burns[0], user_burn);

        let no_user_burns = BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_user_burns_by_block(db.conn(), block_height+1).unwrap();
        assert_eq!(no_user_burns.len(), 0);

        match BurnDB::<BitcoinAddress, BitcoinPublicKey>::get_user_burns_by_block(db.conn(), (1 as u64) << 63) {
            Err(db_error::TypeError) => {},
            _ => assert!(false)
        };
    }

    #[test]
    fn has_VRF_public_key() {
        let public_key = VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap();
        let block_height = 123;
        let vtxindex = 456;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let leader_key : LeaderKeyRegisterOp<BitcoinAddress, BitcoinPublicKey> = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: public_key,
            memo: vec![01, 02, 03, 04, 05],
            address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap(),

            op: LeaderKeyRegisterOp_OPCODE,
            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_number: block_height,
            burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            
            _phantom: PhantomData
        };

        let mut db : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(123, &first_burn_hash).unwrap();
        let has_key_before = BurnDB::<BitcoinAddress, BitcoinPublicKey>::has_VRF_public_key(db.conn(), &public_key).unwrap();
        assert!(!has_key_before);

        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_leader_key(&mut tx, &leader_key).unwrap();
            tx.commit();
        }

        let has_key_after = BurnDB::<BitcoinAddress, BitcoinPublicKey>::has_VRF_public_key(db.conn(), &public_key).unwrap();
        assert!(has_key_after);
    }
}
