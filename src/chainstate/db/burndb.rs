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

use rusqlite::{Connection, Result, OpenFlags};

use std::fs;

use chainstate::db::ChainstateDB;
use chainstate::db::Error as db_error;

use chainstate::CHAINSTATE_VERSION;

use burnchains::{Txid, Hash160};

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
        PRIMARY KEY(txid)
    );"#,
    r#"
    CREATE INDEX block_history ON history(block_height, txid);
    "#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];


pub struct BurnDB {
    conn: Connection
}

/*
impl BurnDB {
    pub fn connect(path: &String, readwrite: bool) -> Result<BurnDB, db_error> {
        let open_flags =
            if fs::metadata(path).is_err() {
                // need to create 
                if readwrite {
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

        BurnDB {
            conn: conn
        }
    }
}

impl ChainstateDB for BurnDB {
    fn backup(backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}
*/
