use serde_json;
use rusqlite::{
    Connection, Transaction, types::ToSql, NO_PARAMS,
    OptionalExtension, Row
};

use burnchains::{
    Burnchain,
    BurnchainBlock,
    BurnchainBlockHeader,
    BurnchainHeaderHash,
    Error as BurnchainError
};

use chainstate::burn::operations::{
    BlockstackOperationType
};

use util::db::{
    u64_to_sql, query_row, FromRow, FromColumn, Error as DBError
};

pub struct BurnchainDb {
    conn: Connection
}

struct BurnchainDbTransaction<'a> {
    sql_tx: Transaction<'a>
}


/// Apply safety checks on extracted blockstack transactions
/// - put them in order by vtxindex
/// - make sure there are no vtxindex duplicates
fn apply_blockstack_txs_safety_checks(block_height: u64, blockstack_txs: &mut Vec<BlockstackOperationType>) -> () {
    // safety -- make sure these are in order
    blockstack_txs.sort_by(|ref a, ref b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());

    // safety -- no duplicate vtxindex (shouldn't happen but crash if so)
    if blockstack_txs.len() > 1 {
        for i in 0..blockstack_txs.len() - 1 {
            if blockstack_txs[i].vtxindex() == blockstack_txs[i+1].vtxindex() {
                panic!("FATAL: BUG: duplicate vtxindex {} in block {}", blockstack_txs[i].vtxindex(), blockstack_txs[i].block_height());
            }
        }
    }

    // safety -- block heights all match
    for tx in blockstack_txs.iter() {
        if tx.block_height() != block_height {
            panic!("FATAL: BUG: block height mismatch: {} != {}", tx.block_height(), block_height);
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
            block_height, block_hash, timestamp, num_txs, parent_block_hash
        })
    }
}

impl <'a> BurnchainDbTransaction <'a> {
    fn store_burnchain_db_entry(&self, header: &BurnchainBlockHeader) -> Result<i64, BurnchainError> {
        let sql = "INSERT INTO burnchain_db_block_headers
                   (block_height, block_hash, parent_block_hash, num_txs, timestamp)
                   VALUES (?, ?, ?, ?, ?)";
        let args: &[&dyn ToSql] = &[ &u64_to_sql(header.block_height)?,
                                     &header.block_hash,
                                     &header.parent_block_hash,
                                     &u64_to_sql(header.num_txs)?,
                                     &u64_to_sql(header.timestamp)? ];
        match self.sql_tx.execute(sql, args) {
            Ok(_) => Ok(self.sql_tx.last_insert_rowid()),
            Err(e) => Err(BurnchainError::from(e))
        }
    }

    fn store_blockstack_ops(&self, header_identifier: i64, block_ops: &[BlockstackOperationType]) -> Result<(), BurnchainError> {
        let sql = "INSERT INTO burnchain_db_bock_ops
                   (burnchain_db_block_id, op) VALUES (?, ?)";
        let mut stmt = self.sql_tx.prepare(sql)?;
        for op in block_ops.iter() {
            let serialized_op = serde_json::to_string(op)
                .expect("Failed to serialize parsed BlockstackOp");
            let args: &[&dyn ToSql] = &[&header_identifier,
                                        &serialized_op];
            stmt.execute(args)?;
        }
        Ok(())
    }

    fn commit(self) -> Result<(), BurnchainError> {
        self.sql_tx.commit()
            .map_err(BurnchainError::from)
    }
}

impl BurnchainDb {
    pub fn connect(path: &str, readwrite: bool) -> Result<BurnchainDb, BurnchainError> {
        panic!("Not implemented: {} {}", path, readwrite);
    }

    pub fn open(path: &str, readwrite: bool) -> Result<BurnchainDb, BurnchainError> {
        panic!("Not implemented: {} {}", path, readwrite);
    }

    fn start_transaction<'a>(&'a mut self) -> Result<BurnchainDbTransaction<'a>, BurnchainError> {
        Ok(BurnchainDbTransaction { sql_tx: self.conn.transaction()? })
    }

    pub fn get_canonical_burn_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height DESC, block_hash ASC LIMIT 1";
        let opt = query_row(&self.conn, qry, NO_PARAMS)?;
        Ok(opt.expect("CORRUPTION: No canonical burnchain tip"))
    }

    /// Filter out the burnchain block's transactions that could be blockstack transactions.
    /// Return the ordered list of blockstack operations by vtxindex
    fn get_blockstack_transactions(block: &BurnchainBlock, block_header: &BurnchainBlockHeader) -> Vec<BlockstackOperationType> {
        debug!("Extract Blockstack transactions from block {} {}", block.block_height(), &block.block_hash());
        block.txs().iter().filter_map(|tx| Burnchain::classify_transaction(block_header, &tx)).collect()
    }

    pub fn store_new_burnchain_block(&mut self, block: &BurnchainBlock) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        let header = block.header();
        let mut blockstack_ops = BurnchainDb::get_blockstack_transactions(block, &header);
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        let db_tx = self.start_transaction()?;

        let header_identifier = db_tx.store_burnchain_db_entry(&header)?;
        db_tx.store_blockstack_ops(header_identifier, &blockstack_ops)?;

        db_tx.commit()?;

        Ok(blockstack_ops)
    }
}
