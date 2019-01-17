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

use rusqlite::{Connection, Transaction, OpenFlags, NO_PARAMS};
use rusqlite::types::ToSql;
use rusqlite::Row;

use std::fs;
use std::convert::From;

use chainstate::db::FromRow;
use chainstate::db::VRFPublicKey_from_row;
use chainstate::db::ChainstateDB;
use chainstate::db::Error as db_error;

use chainstate::CHAINSTATE_VERSION;
use chainstate::{ConsensusHash, VRFSeed, BlockHeaderHash};

use chainstate::operations::leader_block_commit::LeaderBlockCommitOp;
use chainstate::operations::leader_block_commit::OPCODE as LeaderBlockCommitOp_OPCODE;
use chainstate::operations::leader_key_register::LeaderKeyRegisterOp;
use chainstate::operations::leader_key_register::OPCODE as LeaderKeyRegisterOp_OPCODE;
use chainstate::operations::user_burn_support::UserBurnSupportOp;
use chainstate::operations::user_burn_support::OPCODE as UserBurnSupportOp_OPCODE;

use burnchains::BurnchainTxInput;
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::address::BitcoinAddress;

use burnchains::{Txid, Hash160};

use util::vrf::ECVRF_public_key_to_hex;
use util::hash::{to_hex, hex_bytes};

use serde_json::json;

use ed25519_dalek::PublicKey as VRFPublicKey;

// a row in the "history" table
pub struct HistoryRow {
    pub txid: Txid,
    pub vtxindex: u32,
    pub block_height: u64,
    pub op: u8
}

impl HistoryRow {
    pub fn new(txid: &Txid, vtxindex: u32, block_height: u64, op: u8) -> HistoryRow {
        HistoryRow {
            txid: txid.clone(),
            vtxindex: vtxindex,
            block_height: block_height,
            op: op
        }
    }
}

impl From<&LeaderKeyRegisterOp<BitcoinAddress>> for HistoryRow {
    fn from(leader_key: &LeaderKeyRegisterOp<BitcoinAddress>) -> Self {
        HistoryRow {
            txid: leader_key.txid.clone(),
            vtxindex: leader_key.vtxindex,
            block_height: leader_key.block_number,
            op: leader_key.op
        }
    }
}

impl From<&LeaderBlockCommitOp<BitcoinPublicKey>> for HistoryRow {
    fn from(block_commit: &LeaderBlockCommitOp<BitcoinPublicKey>) -> Self {
        HistoryRow {
            txid: block_commit.txid.clone(),
            vtxindex: block_commit.vtxindex,
            block_height: block_commit.block_number,
            op: block_commit.op
        }
    }
}

impl From<&UserBurnSupportOp> for HistoryRow {
    fn from(user_support: &UserBurnSupportOp) -> Self {
        HistoryRow {
            txid: user_support.txid.clone(),
            vtxindex: user_support.vtxindex,
            block_height: user_support.block_number,
            op: user_support.op
        }
    }
}

impl FromRow<LeaderKeyRegisterOp<BitcoinAddress>> for LeaderKeyRegisterOp<BitcoinAddress> {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<LeaderKeyRegisterOp<BitcoinAddress>, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_number : i64 = row.get(2 + index);
        let consensus_hash = ConsensusHash::from_row(row, 3 + index)?;
        let public_key = VRFPublicKey_from_row(row, 4 + index)?;
        let memo_hex : String = row.get(5 + index);
        let address = BitcoinAddress::from_row(row, 6 + index)?;

        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        if block_number < 0 {
            return Err(db_error::ParseError);
        }

        let leader_key_row = LeaderKeyRegisterOp {
            txid: txid,
            vtxindex: vtxindex,
            block_number: block_number as u64,
            op: LeaderKeyRegisterOp_OPCODE,

            consensus_hash: consensus_hash,
            public_key: public_key,
            memo: memo, 
            address: address
        };

        Ok(leader_key_row)
    }
}

impl FromRow<LeaderBlockCommitOp<BitcoinPublicKey>> for LeaderBlockCommitOp<BitcoinPublicKey> {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<LeaderBlockCommitOp<BitcoinPublicKey>, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_height: i64 = row.get(2 + index);
        let block_header_hash = BlockHeaderHash::from_row(row, 3 + index)?;
        let new_seed = VRFSeed::from_row(row, 4 + index)?;
        let parent_block_backptr : u32 = row.get(5 + index);
        let parent_vtxindex: u16 = row.get(6 + index);
        let key_block_backptr : u32 = row.get(7 + index);
        let key_vtxindex : u16 = row.get(8 + index);
        let memo_hex : String = row.get(9 + index);
        let burn_fee_str : String = row.get(10 + index);
        let input_json : String = row.get(11 + index);

        let memo_bytes = hex_bytes(&memo_hex)
            .map_err(|_e| db_error::ParseError)?;

        let memo = memo_bytes.to_vec();

        let input = serde_json::from_str::<BurnchainTxInput<BitcoinPublicKey>>(&input_json)
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
            memo: memo,

            burn_fee: burn_fee,
            input: input,

            op: LeaderBlockCommitOp_OPCODE,
            txid: txid,
            vtxindex: vtxindex,
            block_number: block_height as u64
        };
        Ok(block_commit)
    }
}

impl FromRow<UserBurnSupportOp> for UserBurnSupportOp {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<UserBurnSupportOp, db_error> {
        let txid = Txid::from_row(row, 0 + index)?;
        let vtxindex : u32 = row.get(1 + index);
        let block_height : i64 = row.get(2 + index);

        let consensus_hash = ConsensusHash::from_row(row, 3 + index)?;
        let public_key = VRFPublicKey_from_row(row, 4 + index)?;
        let block_header_hash_160 = Hash160::from_row(row, 5 + index)?;
        let memo_hex : String = row.get(6 + index);
        let burn_fee_str : String = row.get(7 + index);
        
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
            block_number: block_height as u64
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
        op TEXT NOT NULL,
        PRIMARY KEY(txid)
    );"#,
    r#"
    CREATE INDEX block_history ON history(block_height, txid);
    "#,
    r#"
    -- all leader keys registered in the blockchain
    -- note that we do not normalize -- the history entries are repeated to make reads faster
    CREATE TABLE leader_keys(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        memo TEXT,
        address TEXT NOT NULL,

        PRIMARY KEY(public_key),
        FOREIGN KEY(txid) REFERENCES history(txid)
    );"#,
    r#"
    CREATE TABLE block_commits(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,

        block_header_hash TEXT NOT NULL,
        new_seed TEXT NOT NULL,
        parent_block_backptr INTEGER NOT NULL,
        parent_vtxindex INTEGER NOT NULL,
        key_block_backptr INTEGER NOT NULL,
        key_vtxindex INTEGER NOT NULL,
        memo TEXT,
        
        burn_fee TEXT NOT NULL,     -- use text to encode really big numbers
        input TEXT NOT NULL,        -- must match `address` in leader_keys

        PRIMARY KEY(txid),
        FOREIGN KEY(txid) REFERENCES history(txid)
    );"#,
    r#"
    CREATE TABLE user_burn_support(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        block_header_hash_160 TEXT NOT NULL,
        memo TEXT,

        burn_fee TEXT NOT NULL,

        PRIMARY KEY(txid),
        FOREIGN KEY(txid) REFERENCES history(txid)
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];

pub struct BurnDB {
    pub conn: Connection,
    pub readwrite: bool
}

impl BurnDB {
    fn instantiate(conn: &mut Connection) -> Result<(), db_error> {
        let tx = conn.transaction()
            .map_err(|e| db_error::SqliteError(e))?;

        for row_text in BURNDB_SETUP {
            tx.execute(row_text, NO_PARAMS)
                .map_err(|e| db_error::SqliteError(e))?;
        }

        tx.execute("INSERT INTO db_version (version) VALUES (?1)", &[&CHAINSTATE_VERSION])
            .map_err(|e| db_error::SqliteError(e))?;

        tx.commit();
        Ok(())
    }

    /// Open the burn database at the given path.  Open read-only or read/write.
    /// If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(path: &String, readwrite: bool) -> Result<BurnDB, db_error> {
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

        let mut conn = Connection::open_with_flags(path, open_flags)
            .map_err(|e| db_error::SqliteError(e))?;

        if create_flag {
            // instantiate!
            BurnDB::instantiate(&mut conn)?;
        }
        Ok(BurnDB {
            conn: conn,
            readwrite: readwrite
        })
    }

    /// Open a burn database in memory (used for testing)
    pub fn connect_memory() -> Result<BurnDB, db_error> {
        let mut conn = Connection::open_in_memory()
            .map_err(|e| db_error::SqliteError(e))?;

        BurnDB::instantiate(&mut conn)?;
        Ok(BurnDB {
            conn: conn,
            readwrite: true
        })
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

        tx.execute("INSERT INTO history (txid, vtxindex, block_height, op) VALUES (?1, ?2, ?3, ?4)",
                   &[&history_row.txid.to_hex(), &history_row.vtxindex as &ToSql, &(history_row.block_height as i64), &history_row.op])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    pub fn insert_leader_key<'a>(tx: &mut Transaction<'a>, leader_key: &LeaderKeyRegisterOp<BitcoinAddress>) -> Result<(), db_error> {
        let hist_row = HistoryRow::from(leader_key);
        BurnDB::insert_history_row(tx, &hist_row)?;

        tx.execute("INSERT INTO leader_keys (txid, vtxindex, block_height, consensus_hash, public_key, memo, address) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                   &[&leader_key.txid.to_hex(), &leader_key.vtxindex as &ToSql, &(leader_key.block_number as i64) as &ToSql, &leader_key.consensus_hash.to_hex(),
                   &ECVRF_public_key_to_hex(&leader_key.public_key), &to_hex(&leader_key.memo), &leader_key.address.to_b58()])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }
    
    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    pub fn insert_block_commit<'a>(tx: &mut Transaction<'a>, block_commit: &LeaderBlockCommitOp<BitcoinPublicKey>) -> Result<(), db_error> {
        let hist_row = HistoryRow::from(block_commit);
        BurnDB::insert_history_row(tx, &hist_row)?;

        // serialize tx input to JSON
        let tx_input_str = serde_json::to_string(&block_commit.input)
            .map_err(|e| db_error::SerializationError(e))?;

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", block_commit.burn_fee);

        tx.execute("INSERT INTO block_commits (txid, vtxindex, block_height, block_header_hash, new_seed, parent_block_backptr, parent_vtxindex, key_block_backptr, key_vtxindex, memo, burn_fee, input) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                   &[&block_commit.txid.to_hex(), &block_commit.vtxindex as &ToSql, &(block_commit.block_number as i64) as &ToSql, &block_commit.block_header_hash.to_hex(), &block_commit.new_seed.to_hex(), 
                   &block_commit.parent_block_backptr as &ToSql, &block_commit.parent_vtxindex as &ToSql, &block_commit.key_block_backptr as &ToSql, &block_commit.key_vtxindex as &ToSql,
                   &to_hex(&block_commit.memo[..]), &burn_fee_str, &tx_input_str])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }

    /// Insert a user support burn.
    /// No validity checking will be done, beyond what is encoded in the user_burn_support table
    /// constraints.  That is, type mismatches and serialization errors will be caught, but nothing
    /// else.
    pub fn insert_user_burn<'a>(tx: &mut Transaction<'a>, user_burn: &UserBurnSupportOp) -> Result<(), db_error> {
        let hist_row = HistoryRow::from(user_burn);
        BurnDB::insert_history_row(tx, &hist_row)?;

        // represent burn fee as TEXT 
        let burn_fee_str = format!("{}", user_burn.burn_fee);

        tx.execute("INSERT INTO user_burn_support (txid, vtxindex, block_height, consensus_hash, public_key, block_header_hash_160, memo, burn_fee) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                   &[&user_burn.txid.to_hex(), &user_burn.vtxindex as &ToSql, &(user_burn.block_number as i64) as &ToSql, &user_burn.consensus_hash.to_hex(),
                   &ECVRF_public_key_to_hex(&user_burn.public_key), &user_burn.block_header_hash_160.to_hex(), &to_hex(&user_burn.memo[..]), &burn_fee_str])
            .map_err(|e| db_error::SqliteError(e))?;

        Ok(())
    }

    /// boilerplate code for querying rows 
    fn query_rows<T, P>(&self, sql_query: &String, sql_args: P) -> Result<Vec<T>, db_error>
    where
        P: IntoIterator,
        P::Item: ToSql,
        T: FromRow<T>
    {
        let mut stmt = self.conn.prepare(sql_query)
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

    /// Get all leader keys registered in a block 
    pub fn get_leader_keys_by_block(&self, block_height: u64) -> Result<Vec<LeaderKeyRegisterOp<BitcoinAddress>>, db_error> {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        // NOTE: we must select the fields *in this order*
        let qry = "SELECT txid,vtxindex,block_height,consensus_hash,public_key,memo,address FROM leader_keys WHERE block_height = ?1 ORDER BY vtxindex ASC";
        let args = [&(block_height as i64) as &ToSql];
        self.query_rows::<LeaderKeyRegisterOp<BitcoinAddress>, _>(&qry.to_string(), &args)
    }

    /// Get all block commitments registered in a block 
    pub fn get_block_commits_by_block(&self, block_height: u64) -> Result<Vec<LeaderBlockCommitOp<BitcoinPublicKey>>, db_error> {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        // NOTE: we must select the fields *in this order*
        let qry = "SELECT txid,vtxindex,block_height,block_header_hash,new_seed,parent_block_backptr,parent_vtxindex,key_block_backptr,key_vtxindex,memo,burn_fee,input FROM block_commits WHERE block_height = ?1 ORDER BY vtxindex ASC";
        let args = [&(block_height as i64) as &ToSql];
        self.query_rows::<LeaderBlockCommitOp<BitcoinPublicKey>, _>(&qry.to_string(), &args)
    }
    
    /// Get all user burns registered in a block 
    pub fn get_user_burns_by_block(&self, block_height: u64) -> Result<Vec<UserBurnSupportOp>, db_error> {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::TypeError);
        }

        // NOTE: we must select the fields *in this order*
        let qry = "SELECT txid,vtxindex,block_height,consensus_hash,public_key,block_header_hash_160,memo,burn_fee FROM user_burn_support WHERE block_height = ?1 ORDER BY vtxindex ASC";
        let args = [&(block_height as i64) as &ToSql];
        self.query_rows::<UserBurnSupportOp, _>(&qry.to_string(), &args)
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

    use rusqlite::{Connection, Transaction, OpenFlags, NO_PARAMS};
    use rusqlite::types::ToSql;
    use rusqlite::Row;

    use std::fs;
    use std::convert::From;

    use chainstate::db::FromRow;
    use chainstate::db::VRFPublicKey_from_row;
    use chainstate::db::ChainstateDB;
    use chainstate::db::Error as db_error;

    use chainstate::CHAINSTATE_VERSION;
    use chainstate::{ConsensusHash, VRFSeed, BlockHeaderHash};

    use chainstate::operations::leader_block_commit::LeaderBlockCommitOp;
    use chainstate::operations::leader_block_commit::OPCODE as LeaderBlockCommitOp_OPCODE;
    use chainstate::operations::leader_key_register::LeaderKeyRegisterOp;
    use chainstate::operations::leader_key_register::OPCODE as LeaderKeyRegisterOp_OPCODE;
    use chainstate::operations::user_burn_support::UserBurnSupportOp;
    use chainstate::operations::user_burn_support::OPCODE as UserBurnSupportOp_OPCODE;

    use burnchains::BurnchainTxInput;
    use burnchains::BurnchainInputType;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::BitcoinAddress;

    use burnchains::{Txid, Hash160};

    use util::vrf::ECVRF_public_key_to_hex;
    use util::hash::{to_hex, hex_bytes};

    use serde_json::json;

    use ed25519_dalek::PublicKey as VRFPublicKey;

    use burnchains::bitcoin::BitcoinNetworkType;

    #[test]
    fn test_instantiate() {
        let db = BurnDB::connect_memory().unwrap();
    }

    #[test]
    fn test_tx_begin_end() {
        let mut db = BurnDB::connect_memory().unwrap();
        let tx = db.tx_begin().unwrap();
        tx.commit();
    }

    #[test]
    fn test_insert_leader_key() {
        let block_height = 123;
        let vtxindex = 456;

        let leader_key = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap(),

            op: LeaderKeyRegisterOp_OPCODE,
            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_number: block_height
        };

        let mut db = BurnDB::connect_memory().unwrap();
        {   // force the tx to go out of scope when we commit
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_leader_key(&mut tx, &leader_key);
            tx.commit();
        }

        let res_leader_keys = db.get_leader_keys_by_block(block_height).unwrap();
        assert_eq!(res_leader_keys.len(), 1);
        assert_eq!(res_leader_keys[0], leader_key);

        let no_leader_keys = db.get_leader_keys_by_block(block_height+1).unwrap();
        assert_eq!(no_leader_keys.len(), 0);
    }

    #[test]
    fn test_insert_block_commit() {
        let block_height = 123;
        let vtxindex = 456;

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_backptr: 1128415552,       // 0x40414243 (network byte order)
            parent_vtxindex: 20816,                 // 0x5051 (network byte order)
            key_block_backptr: 1667391840,          // 0x60616263 (network byte order)
            key_vtxindex: 29040,                    // 0x7071 (network byte order)
            memo: vec![128],                        // 0x80

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
            block_number: block_height
        };

        let mut db = BurnDB::connect_memory().unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_block_commit(&mut tx, &block_commit);
            tx.commit();
        }

        let res_block_commits = db.get_block_commits_by_block(block_height).unwrap();
        assert_eq!(res_block_commits.len(), 1);
        assert_eq!(res_block_commits[0], block_commit);

        let no_block_commits = db.get_leader_keys_by_block(block_height+1).unwrap();
        assert_eq!(no_block_commits.len(), 0);
    }

    #[test]
    fn test_insert_user_burn() {
        let block_height = 123;
        let vtxindex = 456;

        let user_burn = UserBurnSupportOp {
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            burn_fee: 12345,

            op: UserBurnSupportOp_OPCODE,
            txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
            vtxindex: vtxindex,
            block_number: block_height
        };

        let mut db = BurnDB::connect_memory().unwrap();
        {
            let mut tx = db.tx_begin().unwrap();
            BurnDB::insert_user_burn(&mut tx, &user_burn).unwrap();
            tx.commit();
        }

        let res_user_burns = db.get_user_burns_by_block(block_height).unwrap();
        assert_eq!(res_user_burns.len(), 1);
        assert_eq!(res_user_burns[0], user_burn);

        let no_user_burns = db.get_user_burns_by_block(block_height+1).unwrap();
        assert_eq!(no_user_burns.len(), 0);
    }
}
