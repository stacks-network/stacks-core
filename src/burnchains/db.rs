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

use std::collections::HashMap;
use std::{fs, io};

use rusqlite::{
    types::ToSql, Connection, OpenFlags, OptionalExtension, Row, Transaction, NO_PARAMS,
};
use serde_json;

use crate::burnchains::Txid;
use crate::burnchains::{Burnchain, BurnchainBlock, BurnchainBlockHeader, Error as BurnchainError};
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::util_lib::db::{
    query_row, query_rows, sql_pragma, sqlite_open, tx_begin_immediate, tx_busy_handler,
    u64_to_sql, Error as DBError, FromColumn, FromRow,
};

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use stacks_common::types::chainstate::BurnchainHeaderHash;

pub struct BurnchainDB {
    conn: Connection,
}

struct BurnchainDBTransaction<'a> {
    sql_tx: Transaction<'a>,
}

pub struct BurnchainBlockData {
    pub header: BurnchainBlockHeader,
    pub ops: Vec<BlockstackOperationType>,
}

/// Apply safety checks on extracted blockstack transactions
/// - put them in order by vtxindex
/// - make sure there are no vtxindex duplicates
fn apply_blockstack_txs_safety_checks(
    _block_height: u64,
    blockstack_txs: &mut Vec<BlockstackOperationType>,
) -> () {
    // safety -- make sure these are in order
    blockstack_txs.sort_by(|ref a, ref b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());
}

impl FromRow<BurnchainBlockHeader> for BurnchainBlockHeader {
    fn from_row(row: &Row) -> Result<BurnchainBlockHeader, DBError> {
        let block_height = u64::from_column(row, "block_height")?;
        let block_hash = BurnchainHeaderHash::from_column(row, "block_hash")?;
        let timestamp = u64::from_column(row, "timestamp")?;
        let num_txs = u64::from_column(row, "num_txs")?;
        let parent_block_hash = BurnchainHeaderHash::from_column(row, "parent_block_hash")?;

        Ok(BurnchainBlockHeader {
            block_height,
            block_hash,
            timestamp,
            num_txs,
            parent_block_hash,
        })
    }
}

impl FromRow<BlockstackOperationType> for BlockstackOperationType {
    fn from_row(row: &Row) -> Result<BlockstackOperationType, DBError> {
        let serialized = row.get_unwrap::<_, String>("op");
        let deserialized = serde_json::from_str(&serialized)
            .expect("CORRUPTION: db store un-deserializable block op");

        Ok(deserialized)
    }
}

pub const BURNCHAIN_DB_VERSION: &'static str = "1";

const BURNCHAIN_DB_INITIAL_SCHEMA: &'static str = "
CREATE TABLE burnchain_db_block_headers (
    block_height INTEGER NOT NULL,
    block_hash TEXT UNIQUE NOT NULL,
    parent_block_hash TEXT NOT NULL,
    num_txs INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,

    PRIMARY KEY(block_hash)
);

CREATE TABLE burnchain_db_block_ops (
    block_hash TEXT NOT NULL,
    op TEXT NOT NULL,
    txid TEXT NOT NULL,
    FOREIGN KEY(block_hash) REFERENCES burnchain_db_block_headers(block_hash)
);

CREATE TABLE db_config(version TEXT NOT NULL);";

const BURNCHAIN_DB_INDEXES: &'static [&'static str] = &[
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_headers_height_hash ON burnchain_db_block_headers(block_height DESC, block_hash ASC);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_hash ON burnchain_db_block_ops(block_hash);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_txid ON burnchain_db_block_ops(txid);",
];

impl<'a> BurnchainDBTransaction<'a> {
    fn store_burnchain_db_entry(
        &self,
        header: &BurnchainBlockHeader,
    ) -> Result<i64, BurnchainError> {
        let sql = "INSERT INTO burnchain_db_block_headers
                   (block_height, block_hash, parent_block_hash, num_txs, timestamp)
                   VALUES (?, ?, ?, ?, ?)";
        let args: &[&dyn ToSql] = &[
            &u64_to_sql(header.block_height)?,
            &header.block_hash,
            &header.parent_block_hash,
            &u64_to_sql(header.num_txs)?,
            &u64_to_sql(header.timestamp)?,
        ];

        match self.sql_tx.execute(sql, args) {
            Ok(_) => Ok(self.sql_tx.last_insert_rowid()),
            Err(e) => Err(BurnchainError::from(e)),
        }
    }

    fn store_blockstack_ops(
        &self,
        block_hash: &BurnchainHeaderHash,
        block_ops: &[BlockstackOperationType],
    ) -> Result<(), BurnchainError> {
        let sql = "INSERT INTO burnchain_db_block_ops
                   (block_hash, txid, op) VALUES (?, ?, ?)";
        let mut stmt = self.sql_tx.prepare(sql)?;
        for op in block_ops.iter() {
            let serialized_op =
                serde_json::to_string(op).expect("Failed to serialize parsed BlockstackOp");
            let args: &[&dyn ToSql] = &[block_hash, op.txid_ref(), &serialized_op];
            stmt.execute(args)?;
        }
        Ok(())
    }

    fn commit(self) -> Result<(), BurnchainError> {
        self.sql_tx.commit().map_err(BurnchainError::from)
    }
}

impl BurnchainDB {
    fn add_indexes(&mut self) -> Result<(), BurnchainError> {
        let db_tx = self.tx_begin()?;
        for index in BURNCHAIN_DB_INDEXES.iter() {
            db_tx.sql_tx.execute_batch(index)?;
        }
        db_tx.commit()?;
        Ok(())
    }

    pub fn connect(
        path: &str,
        first_block_height: u64,
        first_burn_header_hash: &BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
        readwrite: bool,
    ) -> Result<BurnchainDB, BurnchainError> {
        let mut create_flag = false;
        let open_flags = match fs::metadata(path) {
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    // need to create
                    if readwrite {
                        create_flag = true;
                        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                    } else {
                        return Err(BurnchainError::from(DBError::NoDBError));
                    }
                } else {
                    return Err(BurnchainError::from(DBError::IOError(e)));
                }
            }
            Ok(_md) => {
                // can just open
                if readwrite {
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                } else {
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                }
            }
        };

        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = BurnchainDB { conn };

        if create_flag {
            let db_tx = db.tx_begin()?;
            db_tx.sql_tx.execute_batch(BURNCHAIN_DB_INITIAL_SCHEMA)?;

            db_tx.sql_tx.execute(
                "INSERT INTO db_config (version) VALUES (?1)",
                &[&BURNCHAIN_DB_VERSION],
            )?;

            let first_block_header = BurnchainBlockHeader {
                block_height: first_block_height,
                block_hash: first_burn_header_hash.clone(),
                timestamp: first_burn_header_timestamp,
                num_txs: 0,
                parent_block_hash: BurnchainHeaderHash::sentinel(),
            };

            db_tx.store_burnchain_db_entry(&first_block_header)?;
            db_tx.commit()?;
        }

        if readwrite {
            db.add_indexes()?;
        }
        Ok(db)
    }

    pub fn open(path: &str, readwrite: bool) -> Result<BurnchainDB, BurnchainError> {
        let open_flags = if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = BurnchainDB { conn };

        if readwrite {
            db.add_indexes()?;
        }
        Ok(db)
    }

    fn tx_begin<'a>(&'a mut self) -> Result<BurnchainDBTransaction<'a>, BurnchainError> {
        let sql_tx = tx_begin_immediate(&mut self.conn)?;
        Ok(BurnchainDBTransaction { sql_tx: sql_tx })
    }

    pub fn get_canonical_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height DESC, block_hash ASC LIMIT 1";
        let opt = query_row(&self.conn, qry, NO_PARAMS)?;
        opt.ok_or(BurnchainError::MissingParentBlock)
    }

    pub fn get_burnchain_block(
        &self,
        block: &BurnchainHeaderHash,
    ) -> Result<BurnchainBlockData, BurnchainError> {
        let block_header_qry =
            "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ? LIMIT 1";
        let block_ops_qry = "SELECT * FROM burnchain_db_block_ops WHERE block_hash = ?";

        let block_header = query_row(&self.conn, block_header_qry, &[block])?
            .ok_or_else(|| BurnchainError::UnknownBlock(block.clone()))?;
        let block_ops = query_rows(&self.conn, block_ops_qry, &[block])?;

        Ok(BurnchainBlockData {
            header: block_header,
            ops: block_ops,
        })
    }

    pub fn get_burnchain_op(&self, txid: &Txid) -> Option<BlockstackOperationType> {
        let qry = "SELECT op FROM burnchain_db_block_ops WHERE txid = ?";

        match query_row(&self.conn, qry, &[txid]) {
            Ok(res) => res,
            Err(e) => {
                warn!(
                    "BurnchainDB Error finding burnchain op: {:?}. txid = {}",
                    e, txid
                );
                None
            }
        }
    }

    /// Filter out the burnchain block's transactions that could be blockstack transactions.
    /// Return the ordered list of blockstack operations by vtxindex
    fn get_blockstack_transactions(
        &self,
        burnchain: &Burnchain,
        block: &BurnchainBlock,
        block_header: &BurnchainBlockHeader,
    ) -> Vec<BlockstackOperationType> {
        debug!(
            "Extract Blockstack transactions from block {} {}",
            block.block_height(),
            &block.block_hash()
        );

        let mut ops = Vec::new();

        for tx in block.txs().iter() {
            let result = Burnchain::classify_transaction(burnchain, self, block_header, &tx);
            if let Some(classified_tx) = result {
                ops.push(classified_tx);
            }
        }

        ops.sort_by_key(|op| op.vtxindex());

        ops
    }

    pub fn store_new_burnchain_block(
        &mut self,
        burnchain: &Burnchain,
        block: &BurnchainBlock,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        let header = block.header();
        debug!("Storing new burnchain block";
              "burn_header_hash" => %header.block_hash.to_string());
        let mut blockstack_ops = self.get_blockstack_transactions(burnchain, block, &header);
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        let db_tx = self.tx_begin()?;

        db_tx.store_burnchain_db_entry(&header)?;
        db_tx.store_blockstack_ops(&header.block_hash, &blockstack_ops)?;

        db_tx.commit()?;

        Ok(blockstack_ops)
    }

    #[cfg(test)]
    pub fn raw_store_burnchain_block(
        &mut self,
        header: BurnchainBlockHeader,
        mut blockstack_ops: Vec<BlockstackOperationType>,
    ) -> Result<(), BurnchainError> {
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        let db_tx = self.tx_begin()?;

        db_tx.store_burnchain_db_entry(&header)?;
        db_tx.store_blockstack_ops(&header.block_hash, &blockstack_ops)?;

        db_tx.commit()?;

        Ok(())
    }
}
