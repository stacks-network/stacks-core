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

use std::fs;

use chainstate::db::ChainstateDB;
use chainstate::db::Error as db_error;

use chainstate::CHAINSTATE_VERSION;

use burnchains::{Txid, Hash160};

use ed25519_dalek::PublicKey;

// a row in the "history" table
pub struct HistoryRow {
    pub txid: Txid,
    pub vtxindex: u64,
    pub block_height: u64,
    pub op: u8
}

impl HistoryRow {
    pub fn new(txid: &Txid, vtxindex: u64, block_height: u64, op: u8) -> HistoryRow {
        HistoryRow {
            txid: txid.clone(),
            vtxindex: vtxindex,
            block_height: block_height,
            op: op
        }
    }
}

const BURNDB_SETUP : &'static [&'static str]= &[
    r#"
    CREATE TABLE history(
        txid TEXT NOT NULL,
        vtxindex INT NOT NULL,
        block_height INT NOT NULL,
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
        memo BLOB NOT NULL,
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
        parent_block_backptr INT NOT NULL,
        parent_vtxindex INT NOT NULL,
        key_block_backptr INT NOT NULL,
        key_vtxindex INT NOT NULL,
        memo BLOB,
        
        burn_fee INT NOT NULL,
        input TEXT NOT NULL,

        PRIMARY KEY(txid),
        FOREIGN KEY(txid) REFERENCES history(txid)
    );"#,
    r#"
    CREATE TABLE user_burn_support(
        txid TEXT NOT NULL,

        consensus_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        block_header_hash TEXT NOT NULL,
        memo BLOB,

        PRIMARY KEY(txid),
        FOREIGN KEY(txid) REFERENCES history(txid)
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];

pub struct BurnDB {
    conn: Connection
}

impl BurnDB {
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
            conn: conn
        })
    }
}

impl ChainstateDB for BurnDB {
    fn backup(backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}


