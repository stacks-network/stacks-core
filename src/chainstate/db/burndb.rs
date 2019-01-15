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

use std::fs;
use std::convert::From;

use chainstate::db::ChainstateDB;
use chainstate::db::Error as db_error;

use chainstate::CHAINSTATE_VERSION;

use chainstate::operations::leader_block_commit::LeaderBlockCommitOp;
use chainstate::operations::leader_key_register::LeaderKeyRegisterOp;
use chainstate::operations::user_burn_support::UserBurnSupportOp;

use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::address::BitcoinAddress;

use burnchains::{Txid, Hash160};

use util::vrf::ECVRF_public_key_to_hex;
use util::hash::to_hex;

use serde_json::json;

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

const BURNDB_SETUP : &'static [&'static str]= &[
    r#"
    CREATE TABLE history(
        txid TEXT NOT NULL,
        vtxindex INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        op TEXT NOT NULL,
        PRIMARY KEY(txid),
    );"#,
    r#"
    CREATE INDEX block_history ON history(block_height, txid);
    "#,
    r#"
    CREATE TABLE leader_keys(
        txid TEXT NOT NULL,

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        memo TEXT,
        address TEXT NOT NULL,

        PRIMARY KEY(public_key),
        FOREIGN KEY(txid) REFERENCES history(txid)
    );"#,
    r#"
    CREATE INDEX address_leader_keys ON leader_keys(address, public_key);
    CREATE INDEX txid_leader_keys ON leader_keys(txid, public_key);
    CREATE INDEX block_height_leader_keys ON leader_keys(block_height, public_key);
    "#,
    r#"
    CREATE TABLE block_commits(
        txid TEXT NOT NULL,

        block_header_hash TEXT NOT NULL,
        new_seed TEXT NOT NULL,
        parent_block_backptr INTEGER NOT NULL,
        parent_block_vtxindex INTEGER NOT NULL,
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

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        block_header_hash TEXT NOT NULL,
        memo TEXT,

        PRIMARY KEY(txid),
        FOREIGN KEY(txid) REFERENCES history(txid)
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];

pub struct BurnDB<'a> {
    conn: Connection,
    tx: Option<Transaction<'a>>,
    readwrite: bool
}

impl<'a> BurnDB<'a> {
    fn instantiate(conn: &mut Connection) -> Result<(), db_error> {
        let tx = conn.transaction()
            .map_err(|e| db_error::SqliteError(e))?;

        for row_text in BURNDB_SETUP {
            debug!("{}", row_text);
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
            tx: None,
            readwrite: readwrite
        })
    }

    /// Begin a transaction.  TODO: use immediate mode?
    pub fn tx_begin(&'a mut self) -> Result<(), db_error> {
        match self.tx {
            Some(ref _tx) => {
                // already running a transaction
                Err(db_error::TransactionInProgress)
            },
            None => {
                let tx = self.conn.transaction()
                    .map_err(|e| db_error::SqliteError(e))?;

                self.tx = Some(tx);
                Ok(())
            }
        }
    }

    /// Insert a history row
    fn insert_history_row(&mut self, history_row: &HistoryRow) -> Result<(), db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        // make sure our u64 values fit into i64 space
        if history_row.block_height > ((1 as u64) << 63 - 1) {
            return Err(db_error::TypeError);
        }

        match self.tx {
            Some(ref tx) => {
                tx.execute("INSERT INTO history (txid, vtxindex, block_height, op) VALUES (?1, ?2, ?3, ?4)",
                           &[&history_row.txid.to_hex(), &history_row.vtxindex as &ToSql, &(history_row.block_height as i64), &history_row.op])
                    .map_err(|e| db_error::SqliteError(e))?;

                return Ok(());
            },
            None => {
                return Err(db_error::NoTransaction);
            }
        };
    }

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    pub fn insert_leader_key(&mut self, leader_key: &LeaderKeyRegisterOp<BitcoinAddress>) -> Result<(), db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }
        
        let hist_row = HistoryRow::from(leader_key);
        self.insert_history_row(&hist_row)?;

        match self.tx {
            Some(ref tx) => {
                tx.execute("INSERT INTO leader_keys (txid, consensus_hash, public_key, memo, address) VALUES (?1, ?2, ?3, ?4, ?5)",
                           &[&leader_key.txid.to_hex(), &leader_key.consensus_hash.to_hex(), &ECVRF_public_key_to_hex(&leader_key.public_key), &to_hex(&leader_key.memo), &leader_key.address.to_b58()])
                    .map_err(|e| db_error::SqliteError(e))?;

                return Ok(());
            },
            None => {
                return Err(db_error::NoTransaction);
            }
        };
    }
    
    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    pub fn insert_block_commitment(&mut self, block_commit: &LeaderBlockCommitOp<BitcoinPublicKey>) -> Result<(), db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let hist_row = HistoryRow::from(block_commit);
        self.insert_history_row(&hist_row)?;

        match self.tx {
            Some(ref tx) => {
                // serialize tx input to JSON
                let tx_input_str = serde_json::to_string(&block_commit.input)
                    .map_err(|e| db_error::SerializationError(e))?;

                // represent burn fee as TEXT 
                let burn_fee_str = format!("{}", block_commit.burn_fee);

                tx.execute("INSERT INTO block_commits (txid, block_header_hash, new_seed, parent_block_backptr, parent_block_vtxindex, key_block_backptr, key_vtxindex, memo, burn_fee, input) \
                            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                           &[&block_commit.txid.to_hex(), &block_commit.block_header_hash.to_hex(), &block_commit.new_seed.to_hex(), &block_commit.parent_block_backptr as &ToSql, &block_commit.parent_vtxindex as &ToSql,
                             &block_commit.key_block_backptr, &block_commit.key_vtxindex, &to_hex(&block_commit.memo[..]), &burn_fee_str, &tx_input_str])
                    .map_err(|e| db_error::SqliteError(e))?;

                return Ok(());
            },
            None => {
                return Err(db_error::NoTransaction);
            }
        };
    }

    /// Insert a user support burn.
    /// No validity checking will be done, beyond what is encoded in the user_burn_support table
    /// constraints.  That is, type mismatches and serialization errors will be caught, but nothing
    /// else.
    pub fn insert_user_burn(&mut self, user_burn: &UserBurnSupportOp) -> Result<(), db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let hist_row = HistoryRow::from(user_burn);
        self.insert_history_row(&hist_row)?;

        match self.tx {
            Some(ref tx) => {
                t.execute("INSERT INTO user_burn_support (txid, consensus_hash, public_key, block_header_hash, memo) VALUES (?1, ?2, ?3, ?4, ?5)",
                          &[&user_burn.txid.to_hex(), &user_burn.consensus_hash.to_hex(), &ECVRF_public_key_to_hex(&user_burn.public_key), &user_burn.block_header_hash.to_hex(), &to_hex(&user_burn.memo[..])])
                    .map_err(|e| db_error::SqliteError(e))?;

                return Ok(());
            },
            None => {
                return Err(db_error::NoTransaction);
            }
        };
    }

    /// 
}

impl<'a> ChainstateDB for BurnDB<'a> {
    fn backup(backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}


