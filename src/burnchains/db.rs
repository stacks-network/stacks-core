// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
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

use rusqlite::{
    types::ToSql, Connection, OpenFlags, OptionalExtension, Row, Transaction, NO_PARAMS,
};
use serde_json;
use std::{fs, io};

use burnchains::{
    Burnchain, BurnchainBlock, BurnchainBlockHeader, BurnchainHeaderHash, Error as BurnchainError,
};

use chainstate::burn::operations::BlockstackOperationType;

use chainstate::stacks::index::MarfTrieId;

use util::db::{
    query_row, query_rows, tx_begin_immediate, tx_busy_handler, u64_to_sql, Error as DBError,
    FromColumn, FromRow,
};

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
    block_height: u64,
    blockstack_txs: &mut Vec<BlockstackOperationType>,
) -> () {
    // safety -- make sure these are in order
    blockstack_txs.sort_by(|ref a, ref b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());

    // safety -- no duplicate vtxindex (shouldn't happen but crash if so)
    if blockstack_txs.len() > 1 {
        for i in 0..blockstack_txs.len() - 1 {
            if blockstack_txs[i].vtxindex() == blockstack_txs[i + 1].vtxindex() {
                panic!(
                    "FATAL: BUG: duplicate vtxindex {} in block {}",
                    blockstack_txs[i].vtxindex(),
                    blockstack_txs[i].block_height()
                );
            }
        }
    }

    // safety -- block heights all match
    for tx in blockstack_txs.iter() {
        if tx.block_height() != block_height {
            panic!(
                "FATAL: BUG: block height mismatch: {} != {}",
                tx.block_height(),
                block_height
            );
        }
    }
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
        let serialized = row.get::<_, String>("op");
        let deserialized = serde_json::from_str(&serialized)
            .expect("CORRUPTION: db store un-deserializable block op");

        Ok(deserialized)
    }
}

const BURNCHAIN_DB_SCHEMA: &'static str = "
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

    FOREIGN KEY(block_hash) REFERENCES burnchain_db_block_headers(block_hash)
);
";

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
                   (block_hash, op) VALUES (?, ?)";
        let mut stmt = self.sql_tx.prepare(sql)?;
        for op in block_ops.iter() {
            let serialized_op =
                serde_json::to_string(op).expect("Failed to serialize parsed BlockstackOp");
            let args: &[&dyn ToSql] = &[block_hash, &serialized_op];
            stmt.execute(args)?;
        }
        Ok(())
    }

    fn commit(self) -> Result<(), BurnchainError> {
        self.sql_tx.commit().map_err(BurnchainError::from)
    }
}

impl BurnchainDB {
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

        let conn = Connection::open_with_flags(path, open_flags)
            .expect(&format!("FAILED to open: {}", path));

        conn.busy_handler(Some(tx_busy_handler))?;

        let mut db = BurnchainDB { conn };

        if create_flag {
            let db_tx = db.tx_begin()?;
            db_tx.sql_tx.execute_batch(BURNCHAIN_DB_SCHEMA)?;

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

        Ok(db)
    }

    pub fn open(path: &str, readwrite: bool) -> Result<BurnchainDB, BurnchainError> {
        let open_flags = if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let conn = Connection::open_with_flags(path, open_flags)?;
        conn.busy_handler(Some(tx_busy_handler))?;

        Ok(BurnchainDB { conn })
    }

    fn tx_begin<'a>(&'a mut self) -> Result<BurnchainDBTransaction<'a>, BurnchainError> {
        let sql_tx = tx_begin_immediate(&mut self.conn)?;
        Ok(BurnchainDBTransaction { sql_tx: sql_tx })
    }

    pub fn get_canonical_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height DESC, block_hash ASC LIMIT 1";
        let opt = query_row(&self.conn, qry, NO_PARAMS)?;
        Ok(opt.expect("CORRUPTION: No canonical burnchain tip"))
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

    /// Filter out the burnchain block's transactions that could be blockstack transactions.
    /// Return the ordered list of blockstack operations by vtxindex
    fn get_blockstack_transactions(
        block: &BurnchainBlock,
        block_header: &BurnchainBlockHeader,
    ) -> Vec<BlockstackOperationType> {
        debug!(
            "Extract Blockstack transactions from block {} {}",
            block.block_height(),
            &block.block_hash()
        );
        block
            .txs()
            .iter()
            .filter_map(|tx| Burnchain::classify_transaction(block_header, &tx))
            .collect()
    }

    pub fn store_new_burnchain_block(
        &mut self,
        block: &BurnchainBlock,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        let header = block.header();
        let mut blockstack_ops = BurnchainDB::get_blockstack_transactions(block, &header);
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

#[cfg(test)]
mod tests {
    use super::*;
    use burnchains::bitcoin::blocks::*;
    use burnchains::bitcoin::*;
    use burnchains::BLOCKSTACK_MAGIC_MAINNET;
    use chainstate::burn::operations;
    use deps::bitcoin::blockdata::transaction::Transaction as BtcTx;
    use deps::bitcoin::network::serialize::deserialize;
    use std::convert::TryInto;
    use util::hash::{hex_bytes, to_hex};

    fn make_tx(hex_str: &str) -> BtcTx {
        let tx_bin = hex_bytes(hex_str).unwrap();
        deserialize(&tx_bin.to_vec()).unwrap()
    }

    #[test]
    fn test_store_and_fetch() {
        let first_bhh = BurnchainHeaderHash([0; 32]);
        let first_timestamp = 321;
        let first_height = 1;

        let mut burnchain_db =
            BurnchainDB::connect(":memory:", first_height, &first_bhh, first_timestamp, true)
                .unwrap();

        let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
        assert_eq!(&first_block_header.block_hash, &first_bhh);
        assert_eq!(&first_block_header.block_height, &first_height);
        assert_eq!(&first_block_header.timestamp, &first_timestamp);
        assert_eq!(
            &first_block_header.parent_block_hash,
            &BurnchainHeaderHash::sentinel()
        );

        let canon_hash = BurnchainHeaderHash([1; 32]);

        let canonical_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            500,
            &canon_hash,
            &first_bhh,
            &vec![],
            485,
        ));
        let ops = burnchain_db
            .store_new_burnchain_block(&canonical_block)
            .unwrap();
        assert_eq!(ops.len(), 0);

        let vtxindex = 1;
        let noncanon_block_height = 400;
        let non_canon_hash = BurnchainHeaderHash([2; 32]);

        let fixtures = operations::leader_key_register::tests::get_test_fixtures(
            vtxindex,
            noncanon_block_height,
            non_canon_hash,
        );

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);
        let mut broadcast_ops = vec![];
        let mut expected_ops = vec![];

        for (ix, tx_fixture) in fixtures.iter().enumerate() {
            let tx = make_tx(&tx_fixture.txstr);
            let burnchain_tx = parser.parse_tx(&tx, ix + 1).unwrap();
            if let Some(res) = &tx_fixture.result {
                let mut res = res.clone();
                res.vtxindex = (ix + 1).try_into().unwrap();
                expected_ops.push(res.clone());
            }
            broadcast_ops.push(burnchain_tx);
        }

        let non_canonical_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            400,
            &non_canon_hash,
            &first_bhh,
            &broadcast_ops,
            350,
        ));

        let ops = burnchain_db
            .store_new_burnchain_block(&non_canonical_block)
            .unwrap();
        assert_eq!(ops.len(), expected_ops.len());
        for op in ops.iter() {
            let expected_op = expected_ops
                .iter()
                .find(|candidate| candidate.txid == op.txid())
                .expect("FAILED to find parsed op in expected ops");
            if let BlockstackOperationType::LeaderKeyRegister(op) = op {
                assert_eq!(op, expected_op);
            } else {
                panic!("EXPECTED to parse a LeaderKeyRegister");
            }
        }

        let BurnchainBlockData { header, ops } =
            burnchain_db.get_burnchain_block(&non_canon_hash).unwrap();
        assert_eq!(ops.len(), expected_ops.len());
        for op in ops.iter() {
            let expected_op = expected_ops
                .iter()
                .find(|candidate| candidate.txid == op.txid())
                .expect("FAILED to find parsed op in expected ops");
            if let BlockstackOperationType::LeaderKeyRegister(op) = op {
                assert_eq!(op, expected_op);
            } else {
                panic!("EXPECTED to parse a LeaderKeyRegister");
            }
        }
        assert_eq!(&header, &non_canonical_block.header());

        let looked_up_canon = burnchain_db.get_canonical_chain_tip().unwrap();
        assert_eq!(&looked_up_canon, &canonical_block.header());

        let BurnchainBlockData { header, ops } =
            burnchain_db.get_burnchain_block(&canon_hash).unwrap();
        assert_eq!(ops.len(), 0);
        assert_eq!(&header, &looked_up_canon);
    }
}
