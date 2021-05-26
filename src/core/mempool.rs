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

use std::cmp;
use std::fs;
use std::io::Read;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};

use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::Error as SqliteError;
use rusqlite::OpenFlags;
use rusqlite::OptionalExtension;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::NO_PARAMS;

use burnchains::Txid;
use chainstate::burn::ConsensusHash;
use chainstate::stacks::TransactionPayload;
use chainstate::stacks::{
    db::blocks::MemPoolRejection, db::StacksChainState, index::Error as MarfError,
    Error as ChainstateError, StacksTransaction,
};
use core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use core::FIRST_STACKS_BLOCK_HASH;
use monitoring::increment_stx_mempool_gc;
use util::db::query_rows;
use util::db::tx_begin_immediate;
use util::db::tx_busy_handler;
use util::db::u64_to_sql;
use util::db::Error as db_error;
use util::db::FromColumn;
use util::db::{query_row, Error};
use util::db::{sql_pragma, DBConn, DBTx, FromRow};
use util::get_epoch_time_secs;
use vm::types::PrincipalData;

use crate::codec::StacksMessageCodec;
use crate::monitoring;
use crate::types::chainstate::{BlockHeaderHash, StacksAddress, StacksBlockHeader};

// maximum number of confirmations a transaction can have before it's garbage-collected
pub const MEMPOOL_MAX_TRANSACTION_AGE: u64 = 256;
pub const MAXIMUM_MEMPOOL_TX_CHAINING: u64 = 25;

pub struct MemPoolAdmitter {
    cur_block: BlockHeaderHash,
    cur_consensus_hash: ConsensusHash,
}

enum MemPoolWalkResult {
    Chainstate(ConsensusHash, BlockHeaderHash, u64, u64),
    NoneAtHeight(ConsensusHash, BlockHeaderHash, u64),
    Done,
}

impl MemPoolAdmitter {
    pub fn new(cur_block: BlockHeaderHash, cur_consensus_hash: ConsensusHash) -> MemPoolAdmitter {
        MemPoolAdmitter {
            cur_block,
            cur_consensus_hash,
        }
    }

    pub fn set_block(&mut self, cur_block: &BlockHeaderHash, cur_consensus_hash: ConsensusHash) {
        self.cur_consensus_hash = cur_consensus_hash.clone();
        self.cur_block = cur_block.clone();
    }
    pub fn will_admit_tx(
        &mut self,
        chainstate: &mut StacksChainState,
        tx: &StacksTransaction,
        tx_size: u64,
    ) -> Result<(), MemPoolRejection> {
        chainstate.will_admit_mempool_tx(&self.cur_consensus_hash, &self.cur_block, tx, tx_size)
    }
}

pub enum MemPoolDropReason {
    REPLACE_ACROSS_FORK,
    REPLACE_BY_FEE,
    STALE_COLLECT,
    TOO_EXPENSIVE,
}

impl std::fmt::Display for MemPoolDropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemPoolDropReason::STALE_COLLECT => write!(f, "StaleGarbageCollect"),
            MemPoolDropReason::TOO_EXPENSIVE => write!(f, "TooExpensive"),
            MemPoolDropReason::REPLACE_ACROSS_FORK => write!(f, "ReplaceAcrossFork"),
            MemPoolDropReason::REPLACE_BY_FEE => write!(f, "ReplaceByFee"),
        }
    }
}

pub trait MemPoolEventDispatcher {
    fn mempool_txs_dropped(&self, txids: Vec<Txid>, reason: MemPoolDropReason);
}

#[derive(Debug, PartialEq, Clone)]
pub struct MemPoolTxInfo {
    pub tx: StacksTransaction,
    pub metadata: MemPoolTxMetadata,
}

#[derive(Debug, PartialEq, Clone)]
pub struct MemPoolTxMetadata {
    pub txid: Txid,
    pub len: u64,
    pub tx_fee: u64,
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub block_height: u64,
    pub origin_address: StacksAddress,
    pub origin_nonce: u64,
    pub sponsor_address: StacksAddress,
    pub sponsor_nonce: u64,
    pub accept_time: u64,
}

impl FromRow<Txid> for Txid {
    fn from_row<'a>(row: &'a Row) -> Result<Txid, db_error> {
        row.get(0).map_err(db_error::SqliteError)
    }
}

impl FromRow<MemPoolTxMetadata> for MemPoolTxMetadata {
    fn from_row<'a>(row: &'a Row) -> Result<MemPoolTxMetadata, db_error> {
        let txid = Txid::from_column(row, "txid")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let block_header_hash = BlockHeaderHash::from_column(row, "block_header_hash")?;
        let tx_fee = u64::from_column(row, "tx_fee")?;
        let height = u64::from_column(row, "height")?;
        let len = u64::from_column(row, "length")?;
        let ts = u64::from_column(row, "accept_time")?;
        let origin_address = StacksAddress::from_column(row, "origin_address")?;
        let origin_nonce = u64::from_column(row, "origin_nonce")?;
        let sponsor_address = StacksAddress::from_column(row, "sponsor_address")?;
        let sponsor_nonce = u64::from_column(row, "sponsor_nonce")?;

        Ok(MemPoolTxMetadata {
            txid: txid,
            tx_fee: tx_fee,
            len: len,
            consensus_hash: consensus_hash,
            block_header_hash: block_header_hash,
            block_height: height,
            accept_time: ts,
            origin_address: origin_address,
            origin_nonce: origin_nonce,
            sponsor_address: sponsor_address,
            sponsor_nonce: sponsor_nonce,
        })
    }
}

impl FromRow<MemPoolTxInfo> for MemPoolTxInfo {
    fn from_row<'a>(row: &'a Row) -> Result<MemPoolTxInfo, db_error> {
        let md = MemPoolTxMetadata::from_row(row)?;
        let tx_bytes: Vec<u8> = row.get_unwrap("tx");
        let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..])
            .map_err(|_e| db_error::ParseError)?;

        if tx.txid() != md.txid {
            return Err(db_error::ParseError);
        }

        Ok(MemPoolTxInfo {
            tx: tx,
            metadata: md,
        })
    }
}

impl FromRow<(u64, u64)> for (u64, u64) {
    fn from_row<'a>(row: &'a Row) -> Result<(u64, u64), db_error> {
        let t1: i64 = row.get_unwrap(0);
        let t2: i64 = row.get_unwrap(1);
        if t1 < 0 || t2 < 0 {
            return Err(db_error::ParseError);
        }
        Ok((t1 as u64, t2 as u64))
    }
}

const MEMPOOL_INITIAL_SCHEMA: &'static [&'static str] = &[
    r#"
    CREATE TABLE mempool(
        txid TEXT NOT NULL,
        origin_address TEXT NOT NULL,
        origin_nonce INTEGER NOT NULL,
        sponsor_address TEXT NOT NULL,
        sponsor_nonce INTEGER NOT NULL,
        tx_fee INTEGER NOT NULL,
        length INTEGER NOT NULL,
        consensus_hash TEXT NOT NULL,
        block_header_hash TEXT NOT NULL,
        height INTEGER NOT NULL,    -- stacks block height
        accept_time INTEGER NOT NULL,
        tx BLOB NOT NULL,
        PRIMARY KEY (txid),
        UNIQUE (origin_address, origin_nonce),
        UNIQUE (sponsor_address,sponsor_nonce)
    );
    "#,
    "CREATE INDEX by_txid ON mempool(txid);",
    "CREATE INDEX by_sponsor ON mempool(sponsor_address, sponsor_nonce);",
    "CREATE INDEX by_origin ON mempool(origin_address, origin_nonce);",
    "CREATE INDEX by_timestamp ON mempool(accept_time);",
    "CREATE INDEX by_chaintip ON mempool(consensus_hash,block_header_hash);",
];

pub struct MemPoolDB {
    db: DBConn,
    path: String,
    admitter: MemPoolAdmitter,
}

pub struct MemPoolTx<'a> {
    tx: DBTx<'a>,
    admitter: &'a mut MemPoolAdmitter,
}

impl<'a> Deref for MemPoolTx<'a> {
    type Target = DBTx<'a>;
    fn deref(&self) -> &DBTx<'a> {
        &self.tx
    }
}

impl<'a> DerefMut for MemPoolTx<'a> {
    fn deref_mut(&mut self) -> &mut DBTx<'a> {
        &mut self.tx
    }
}

impl<'a> MemPoolTx<'a> {
    pub fn new(tx: DBTx<'a>, admitter: &'a mut MemPoolAdmitter) -> MemPoolTx<'a> {
        MemPoolTx { tx, admitter }
    }

    pub fn commit(self) -> Result<(), db_error> {
        self.tx.commit().map_err(db_error::SqliteError)
    }
}

impl MemPoolTxInfo {
    pub fn from_tx(
        tx: StacksTransaction,
        consensus_hash: ConsensusHash,
        block_header_hash: BlockHeaderHash,
        block_height: u64,
    ) -> MemPoolTxInfo {
        let txid = tx.txid();
        let mut tx_data = vec![];
        tx.consensus_serialize(&mut tx_data)
            .expect("BUG: failed to serialize to vector");

        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let (sponsor_address, sponsor_nonce) =
            if let (Some(addr), Some(nonce)) = (tx.sponsor_address(), tx.get_sponsor_nonce()) {
                (addr, nonce)
            } else {
                (origin_address.clone(), origin_nonce)
            };

        let metadata = MemPoolTxMetadata {
            txid: txid,
            len: tx_data.len() as u64,
            tx_fee: tx.get_tx_fee(),
            consensus_hash: consensus_hash,
            block_header_hash: block_header_hash,
            block_height: block_height,
            origin_address: origin_address,
            origin_nonce: origin_nonce,
            sponsor_address: sponsor_address,
            sponsor_nonce: sponsor_nonce,
            accept_time: get_epoch_time_secs(),
        };
        MemPoolTxInfo {
            tx: tx,
            metadata: metadata,
        }
    }
}

impl MemPoolDB {
    fn instantiate_mempool_db(conn: &mut DBConn) -> Result<(), db_error> {
        sql_pragma(conn, "PRAGMA journal_mode = WAL;")?;

        let tx = tx_begin_immediate(conn)?;

        for cmd in MEMPOOL_INITIAL_SCHEMA {
            tx.execute_batch(cmd).map_err(db_error::SqliteError)?;
        }

        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn db_path(chainstate_root_path: &str) -> Result<String, db_error> {
        let mut path = PathBuf::from(chainstate_root_path);

        path.push("mempool.sqlite");
        path.to_str()
            .ok_or_else(|| db_error::ParseError)
            .map(String::from)
    }

    /// Open the mempool db within the chainstate directory.
    /// The chainstate must be instantiated already.
    pub fn open(
        mainnet: bool,
        chain_id: u32,
        chainstate_path: &str,
    ) -> Result<MemPoolDB, db_error> {
        match fs::metadata(chainstate_path) {
            Ok(md) => {
                if !md.is_dir() {
                    return Err(db_error::NotFoundError);
                }
            }
            Err(_e) => {
                return Err(db_error::NotFoundError);
            }
        }

        let (chainstate, _) = StacksChainState::open(mainnet, chain_id, chainstate_path)
            .map_err(|e| db_error::Other(format!("Failed to open chainstate: {:?}", &e)))?;

        let admitter = MemPoolAdmitter::new(BlockHeaderHash([0u8; 32]), ConsensusHash([0u8; 20]));

        let db_path = MemPoolDB::db_path(&chainstate.root_path)?;

        let mut create_flag = false;
        let open_flags = if fs::metadata(&db_path).is_err() {
            // need to create
            create_flag = true;
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        } else {
            // can just open
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };

        let mut conn =
            DBConn::open_with_flags(&db_path, open_flags).map_err(db_error::SqliteError)?;
        conn.busy_handler(Some(tx_busy_handler))
            .map_err(db_error::SqliteError)?;

        if create_flag {
            // instantiate!
            MemPoolDB::instantiate_mempool_db(&mut conn)?;
        }

        Ok(MemPoolDB {
            db: conn,
            path: db_path,
            admitter: admitter,
        })
    }

    ///
    /// Iterate over candidates in the mempool
    ///  todo will be called once for each bundle of transactions at
    ///  each nonce, starting with the smallest nonce and going higher until there are
    ///  no more transactions to consider. Each batch of transactions
    ///  passed to todo will be sorted by sponsor_nonce.
    ///
    /// Consider transactions across all forks where the transactions have
    /// height >= max(0, tip_height - MEMPOOL_MAX_TRANSACTION_AGE) and height <= tip_height.
    pub fn iterate_candidates<F, E>(&self, tip_height: u64, mut todo: F) -> Result<(), E>
    where
        F: FnMut(Vec<MemPoolTxInfo>) -> Result<(), E>,
        E: From<db_error> + From<ChainstateError>,
    {
        // Want to consider transactions with
        // height > max(-1, tip_height - (MEMPOOL_MAX_TRANSACTION_AGE + 1))
        let min_height = tip_height.checked_sub(MEMPOOL_MAX_TRANSACTION_AGE + 1);
        let mut curr_page = 0;

        let mut next_nonce =
            match MemPoolDB::get_next_nonce(&self.db, min_height, tip_height, None)? {
                None => {
                    return Ok(());
                }
                Some(nonce) => nonce,
            };

        loop {
            let available_txs = MemPoolDB::get_txs_at_nonce_and_offset(
                &self.db, min_height, tip_height, next_nonce, curr_page,
            )?;
            debug!(
                "Have {} transactions at nonce={}",
                available_txs.len(),
                next_nonce,
            );

            if available_txs.len() > 0 {
                todo(available_txs)?;
                curr_page += 1;
            } else {
                curr_page = 0;
                next_nonce = match MemPoolDB::get_next_nonce(
                    &self.db,
                    min_height,
                    tip_height,
                    Some(next_nonce),
                )? {
                    None => {
                        return Ok(());
                    }
                    Some(nonce) => nonce,
                };
            }
        }
    }

    pub fn conn(&self) -> &DBConn {
        &self.db
    }

    pub fn tx_begin<'a>(&'a mut self) -> Result<MemPoolTx<'a>, db_error> {
        let tx = tx_begin_immediate(&mut self.db)?;
        Ok(MemPoolTx::new(tx, &mut self.admitter))
    }

    fn db_has_tx(conn: &DBConn, txid: &Txid) -> Result<bool, db_error> {
        query_row(
            conn,
            "SELECT 1 FROM mempool WHERE txid = ?1",
            &[txid as &dyn ToSql],
        )
        .and_then(|row_opt: Option<i64>| Ok(row_opt.is_some()))
    }

    pub fn get_tx(conn: &DBConn, txid: &Txid) -> Result<Option<MemPoolTxInfo>, db_error> {
        query_row(
            conn,
            "SELECT * FROM mempool WHERE txid = ?1",
            &[txid as &dyn ToSql],
        )
    }

    /// Get all transactions across all tips
    #[cfg(test)]
    pub fn get_all_txs(conn: &DBConn) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let sql = "SELECT * FROM mempool";
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, NO_PARAMS)?;
        Ok(rows)
    }

    /// Get all transactions at a specific block
    #[cfg(test)]
    pub fn get_num_tx_at_block(
        conn: &DBConn,
        consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
    ) -> Result<usize, db_error> {
        let sql = "SELECT * FROM mempool WHERE consensus_hash = ?1 AND block_header_hash = ?2";
        let args: &[&dyn ToSql] = &[consensus_hash, block_header_hash];
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, args)?;
        Ok(rows.len())
    }

    /// Get the next nonce/timestamp after this nonce that occurs in the height range.
    pub fn get_next_nonce(
        conn: &DBConn,
        min_height: Option<u64>,
        max_height: u64,
        nonce: Option<u64>,
    ) -> Result<Option<u64>, db_error> {
        let nonce = match nonce {
            None => -1,
            Some(n) => u64_to_sql(n)?,
        };
        let min_height_sql_arg = match min_height {
            None => -1,
            Some(h) => u64_to_sql(h)?,
        };
        let sql = "SELECT origin_nonce FROM mempool WHERE origin_nonce > ?1 AND \
        height > ?2 AND height <= ?3 ORDER BY origin_nonce, accept_time ASC LIMIT 1";

        let args: &[&dyn ToSql] = &[&nonce, &min_height_sql_arg, &u64_to_sql(max_height)?];
        query_row(conn, sql, args)
    }

    /// Get all transactions at a particular nonce and timestamp on a given chain tip.
    /// Order them by sponsor nonce.
    pub fn get_txs_at_nonce_and_offset(
        conn: &DBConn,
        min_height: Option<u64>,
        max_height: u64,
        nonce: u64,
        curr_page: u32,
    ) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let min_height_sql_arg = match min_height {
            None => -1,
            Some(h) => u64_to_sql(h)?,
        };
        let limit = 200;
        let offset = limit * curr_page;

        let sql = "SELECT * FROM mempool WHERE origin_nonce = ?1 AND \
        height > ?2 AND height <= ?3 ORDER BY sponsor_nonce ASC LIMIT ?4 OFFSET ?5";
        let args: &[&dyn ToSql] = &[
            &u64_to_sql(nonce)?,
            &min_height_sql_arg,
            &u64_to_sql(max_height)?,
            &limit,
            &offset,
        ];
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, args)?;
        Ok(rows)
    }

    /// Get all transactions at a particular timestamp on a given chain tip.
    /// Order them by origin nonce.
    pub fn get_txs_at(
        conn: &DBConn,
        consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
        timestamp: u64,
    ) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let sql = "SELECT * FROM mempool WHERE accept_time = ?1 AND consensus_hash = ?2 AND block_header_hash = ?3 ORDER BY origin_nonce ASC";
        let args: &[&dyn ToSql] = &[&u64_to_sql(timestamp)?, consensus_hash, block_header_hash];
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, args)?;
        Ok(rows)
    }

    /// Given a chain tip, find the highest block-height from _before_ this tip
    pub fn get_previous_block_height(conn: &DBConn, height: u64) -> Result<Option<u64>, db_error> {
        let sql = "SELECT height FROM mempool WHERE height < ?1 ORDER BY height DESC LIMIT 1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(height)?];
        query_row(conn, sql, args)
    }

    /// Get a number of transactions after a given timestamp on a given chain tip.
    pub fn get_txs_after(
        conn: &DBConn,
        consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
        timestamp: u64,
        count: u64,
    ) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let sql = "SELECT * FROM mempool WHERE accept_time >= ?1 AND consensus_hash = ?2 AND block_header_hash = ?3 ORDER BY tx_fee DESC LIMIT ?4";
        let args: &[&dyn ToSql] = &[
            &u64_to_sql(timestamp)?,
            consensus_hash,
            block_header_hash,
            &u64_to_sql(count)?,
        ];
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, args)?;
        Ok(rows)
    }

    /// Get a transaction's metadata, given address and nonce, and whether the address is used as a sponsor or an origin.
    /// Faster than getting the MemPoolTxInfo, since no deserialization will be needed.
    /// Used to see if there exists a transaction with this info, so as to implement replace-by-fee
    fn get_tx_metadata_by_address(
        conn: &DBConn,
        is_origin: bool,
        addr: &StacksAddress,
        nonce: u64,
    ) -> Result<Option<MemPoolTxMetadata>, db_error> {
        let sql = format!(
            "SELECT 
                          txid,
                          origin_address,
                          origin_nonce,
                          sponsor_address,
                          sponsor_nonce,
                          tx_fee,
                          length,
                          consensus_hash,
                          block_header_hash,
                          height,
                          accept_time
                          FROM mempool WHERE {0}_address = ?1 AND {0}_nonce = ?2",
            if is_origin { "origin" } else { "sponsor" }
        );
        let args: &[&dyn ToSql] = &[&addr.to_string(), &u64_to_sql(nonce)?];
        query_row(conn, &sql, args)
    }

    fn get_next_nonce_as_participant_type(
        conn: &DBConn,
        addr: &StacksAddress,
        as_origin: bool,
    ) -> Result<u64, db_error> {
        let sql = format!(
            "SELECT ifnull(max({0}_nonce + 1), 0) FROM mempool WHERE {0}_address = ?1",
            if as_origin { "origin" } else { "sponsor" }
        );
        match conn.query_row_and_then(&sql, &[addr.to_string()], |row| u64::from_row(row)) {
            Ok(max) => Ok(max),
            Err(db_error::SqliteError(SqliteError::QueryReturnedNoRows)) => Ok(0),
            otherwise => otherwise,
        }
    }

    pub fn get_next_nonce_for_address(
        conn: &DBConn,
        address: &StacksAddress,
    ) -> Result<u64, db_error> {
        let as_origin = MemPoolDB::get_next_nonce_as_participant_type(conn, address, true)?;
        let as_sponsor = MemPoolDB::get_next_nonce_as_participant_type(conn, address, false)?;
        Ok(cmp::max(as_origin, as_sponsor))
    }

    fn are_blocks_in_same_fork(
        chainstate: &mut StacksChainState,
        first_consensus_hash: &ConsensusHash,
        first_stacks_block: &BlockHeaderHash,
        second_consensus_hash: &ConsensusHash,
        second_stacks_block: &BlockHeaderHash,
    ) -> Result<bool, db_error> {
        let first_block =
            StacksBlockHeader::make_index_block_hash(first_consensus_hash, first_stacks_block);
        let second_block =
            StacksBlockHeader::make_index_block_hash(second_consensus_hash, second_stacks_block);
        // short circuit equality
        if second_block == first_block {
            return Ok(true);
        }

        let headers_conn = &chainstate
            .index_conn()
            .map_err(|_e| db_error::Other("ChainstateError".to_string()))?;
        let height_of_first_with_second_tip =
            headers_conn.get_ancestor_block_height(&second_block, &first_block)?;
        let height_of_second_with_first_tip =
            headers_conn.get_ancestor_block_height(&first_block, &second_block)?;

        match (
            height_of_first_with_second_tip,
            height_of_second_with_first_tip,
        ) {
            (None, None) => Ok(false),
            (_, _) => Ok(true),
        }
    }

    /// Add a transaction to the mempool.  If it already exists, then replace it if the given fee
    /// is higher than the one that's already there.
    /// Carry out the mempool admission test before adding.
    /// Don't call directly; use submit()
    fn try_add_tx(
        tx: &mut MemPoolTx,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
        txid: Txid,
        tx_bytes: Vec<u8>,
        tx_fee: u64,
        height: u64,
        origin_address: &StacksAddress,
        origin_nonce: u64,
        sponsor_address: &StacksAddress,
        sponsor_nonce: u64,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
    ) -> Result<(), MemPoolRejection> {
        let length = tx_bytes.len() as u64;

        // do we already have txs with either the same origin nonce or sponsor nonce ?
        let prior_tx = {
            match MemPoolDB::get_tx_metadata_by_address(tx, true, origin_address, origin_nonce)? {
                Some(prior_tx) => Some(prior_tx),
                None => MemPoolDB::get_tx_metadata_by_address(
                    tx,
                    false,
                    sponsor_address,
                    sponsor_nonce,
                )?,
            }
        };

        let mut replace_reason = MemPoolDropReason::REPLACE_BY_FEE;

        // if so, is this a replace-by-fee? or a replace-in-chain-tip?
        let add_tx = if let Some(ref prior_tx) = prior_tx {
            if tx_fee > prior_tx.tx_fee {
                // is this a replace-by-fee ?
                replace_reason = MemPoolDropReason::REPLACE_BY_FEE;
                true
            } else if !MemPoolDB::are_blocks_in_same_fork(
                chainstate,
                &prior_tx.consensus_hash,
                &prior_tx.block_header_hash,
                consensus_hash,
                block_header_hash,
            )? {
                // is this a replace-across-fork ?
                replace_reason = MemPoolDropReason::REPLACE_ACROSS_FORK;
                true
            } else {
                // there's a >= fee tx in this fork, cannot add
                info!("TX conflicts with sponsor/origin nonce in same fork with >= fee";
                      "new_txid" => %txid, 
                      "old_txid" => %prior_tx.txid,
                      "origin_addr" => %origin_address,
                      "origin_nonce" => origin_nonce,
                      "sponsor_addr" => %sponsor_address,
                      "sponsor_nonce" => sponsor_nonce,
                      "new_fee" => tx_fee,
                      "old_fee" => prior_tx.tx_fee);
                false
            }
        } else {
            // no conflicting TX with this origin/sponsor, go ahead and add
            true
        };

        if !add_tx {
            return Err(MemPoolRejection::ConflictingNonceInMempool);
        }

        let sql = "INSERT OR REPLACE INTO mempool (
            txid,
            origin_address,
            origin_nonce,
            sponsor_address,
            sponsor_nonce,
            tx_fee,
            length,
            consensus_hash,
            block_header_hash,
            height,
            accept_time,
            tx)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

        let args: &[&dyn ToSql] = &[
            &txid,
            &origin_address.to_string(),
            &u64_to_sql(origin_nonce)?,
            &sponsor_address.to_string(),
            &u64_to_sql(sponsor_nonce)?,
            &u64_to_sql(tx_fee)?,
            &u64_to_sql(length)?,
            consensus_hash,
            block_header_hash,
            &u64_to_sql(height)?,
            &u64_to_sql(get_epoch_time_secs())?,
            &tx_bytes,
        ];

        tx.execute(sql, args)
            .map_err(|e| MemPoolRejection::DBError(db_error::SqliteError(e)))?;

        // broadcast drop event if a tx is being replaced
        if let (Some(prior_tx), Some(event_observer)) = (prior_tx, event_observer) {
            event_observer.mempool_txs_dropped(vec![prior_tx.txid], replace_reason);
        };

        Ok(())
    }

    /// Garbage-collect the mempool.  Remove transactions that have a given number of
    /// confirmations.
    pub fn garbage_collect(
        tx: &mut MemPoolTx,
        min_height: u64,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
    ) -> Result<(), db_error> {
        let args: &[&dyn ToSql] = &[&u64_to_sql(min_height)?];

        if let Some(event_observer) = event_observer {
            let sql = "SELECT txid FROM mempool WHERE height < ?1";
            let txids = query_rows(tx, sql, args)?;
            event_observer.mempool_txs_dropped(txids, MemPoolDropReason::STALE_COLLECT);
        }

        let sql = "DELETE FROM mempool WHERE height < ?1";

        tx.execute(sql, args)?;
        increment_stx_mempool_gc();
        Ok(())
    }

    #[cfg(test)]
    pub fn clear_before_height(&mut self, min_height: u64) -> Result<(), db_error> {
        let mut tx = self.tx_begin()?;
        MemPoolDB::garbage_collect(&mut tx, min_height, None)?;
        tx.commit()?;
        Ok(())
    }

    /// Scan the chain tip for all available transactions (but do not remove them!)
    pub fn poll(
        &mut self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Vec<StacksTransaction> {
        test_debug!("Mempool poll at {}/{}", consensus_hash, block_hash);
        MemPoolDB::get_txs_after(
            &self.db,
            consensus_hash,
            block_hash,
            0,
            (i64::max_value() - 1) as u64,
        )
        .unwrap_or(vec![])
        .into_iter()
        .map(|tx_info| {
            test_debug!(
                "Mempool poll {} at {}/{}",
                &tx_info.tx.txid(),
                consensus_hash,
                block_hash
            );
            tx_info.tx
        })
        .collect()
    }

    /// Submit a transaction to the mempool at a particular chain tip.
    fn tx_submit(
        mempool_tx: &mut MemPoolTx,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx: &StacksTransaction,
        do_admission_checks: bool,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
    ) -> Result<(), MemPoolRejection> {
        test_debug!(
            "Mempool submit {} at {}/{}",
            tx.txid(),
            consensus_hash,
            block_hash
        );

        let height = match chainstate.get_stacks_block_height(consensus_hash, block_hash) {
            Ok(Some(h)) => h,
            Ok(None) => {
                if *consensus_hash == FIRST_BURNCHAIN_CONSENSUS_HASH {
                    0
                } else {
                    return Err(MemPoolRejection::NoSuchChainTip(
                        consensus_hash.clone(),
                        block_hash.clone(),
                    ));
                }
            }
            Err(e) => {
                return Err(MemPoolRejection::Other(format!(
                    "Failed to load chain tip: {:?}",
                    &e
                )));
            }
        };

        let txid = tx.txid();
        let mut tx_data = vec![];
        tx.consensus_serialize(&mut tx_data)
            .map_err(MemPoolRejection::SerializationFailure)?;

        let len = tx_data.len() as u64;
        let tx_fee = tx.get_tx_fee();
        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let (sponsor_address, sponsor_nonce) =
            if let (Some(addr), Some(nonce)) = (tx.sponsor_address(), tx.get_sponsor_nonce()) {
                (addr, nonce)
            } else {
                (origin_address.clone(), origin_nonce)
            };

        if do_admission_checks {
            mempool_tx
                .admitter
                .set_block(&block_hash, (*consensus_hash).clone());
            mempool_tx.admitter.will_admit_tx(chainstate, tx, len)?;
        }

        MemPoolDB::try_add_tx(
            mempool_tx,
            chainstate,
            &consensus_hash,
            &block_hash,
            txid.clone(),
            tx_data,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            event_observer,
        )?;

        if let Err(e) = monitoring::mempool_accepted(&txid, &chainstate.root_path) {
            warn!("Failed to monitor TX receive: {:?}", e; "txid" => %txid);
        }

        Ok(())
    }

    /// One-shot submit
    pub fn submit(
        &mut self,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx: &StacksTransaction,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
    ) -> Result<(), MemPoolRejection> {
        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;
        MemPoolDB::tx_submit(
            &mut mempool_tx,
            chainstate,
            consensus_hash,
            block_hash,
            tx,
            true,
            event_observer,
        )?;
        mempool_tx.commit().map_err(MemPoolRejection::DBError)?;
        Ok(())
    }

    /// Directly submit to the mempool, and don't do any admissions checks.
    pub fn submit_raw(
        &mut self,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx_bytes: Vec<u8>,
    ) -> Result<(), MemPoolRejection> {
        let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..])
            .map_err(MemPoolRejection::DeserializationFailure)?;

        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;
        MemPoolDB::tx_submit(
            &mut mempool_tx,
            chainstate,
            consensus_hash,
            block_hash,
            &tx,
            false,
            None,
        )?;
        mempool_tx.commit().map_err(MemPoolRejection::DBError)?;
        Ok(())
    }

    /// Drop transactions from the mempool
    pub fn drop_txs(&mut self, txids: &[Txid]) -> Result<(), db_error> {
        let mempool_tx = self.tx_begin()?;
        let sql = "DELETE FROM mempool WHERE txid = ?";
        for txid in txids.iter() {
            mempool_tx.execute(sql, &[txid])?;
        }
        mempool_tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn dump_txs(&self) {
        let sql = "SELECT * FROM mempool";
        let txs: Vec<MemPoolTxMetadata> = query_rows(&self.db, sql, NO_PARAMS).unwrap();

        eprintln!("{:#?}", txs);
    }

    /// Do we have a transaction?
    pub fn has_tx(&self, txid: &Txid) -> bool {
        match MemPoolDB::db_has_tx(self.conn(), txid) {
            Ok(b) => {
                if b {
                    test_debug!("Mempool tx already present: {}", txid);
                }
                b
            }
            Err(e) => {
                warn!("Failed to query txid: {:?}", &e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use address::AddressHashMode;
    use burnchains::Address;
    use chainstate::burn::ConsensusHash;
    use chainstate::stacks::db::test::chainstate_path;
    use chainstate::stacks::db::test::instantiate_chainstate;
    use chainstate::stacks::db::test::instantiate_chainstate_with_balances;
    use chainstate::stacks::test::codec_all_transactions;
    use chainstate::stacks::{
        db::blocks::MemPoolRejection, db::StacksChainState, index::MarfTrieId, CoinbasePayload,
        Error as ChainstateError, SinglesigHashMode, SinglesigSpendingCondition, StacksPrivateKey,
        StacksPublicKey, StacksTransaction, StacksTransactionSigner, TokenTransferMemo,
        TransactionAnchorMode, TransactionAuth, TransactionContractCall, TransactionPayload,
        TransactionPostConditionMode, TransactionPublicKeyEncoding, TransactionSmartContract,
        TransactionSpendingCondition, TransactionVersion,
    };
    use chainstate::stacks::{
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    };
    use core::FIRST_BURNCHAIN_CONSENSUS_HASH;
    use core::FIRST_STACKS_BLOCK_HASH;
    use net::Error as NetError;
    use util::db::{DBConn, FromRow};
    use util::hash::Hash160;
    use util::secp256k1::MessageSignature;
    use util::{hash::hex_bytes, hash::to_hex, hash::*, log, secp256k1::*, strings::StacksString};
    use vm::{
        database::HeadersDB,
        database::NULL_BURN_STATE_DB,
        errors::Error as ClarityError,
        errors::RuntimeErrorType,
        types::{PrincipalData, QualifiedContractIdentifier},
        ClarityName, ContractName, Value,
    };

    use crate::codec::StacksMessageCodec;
    use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};
    use crate::types::chainstate::{
        StacksAddress, StacksBlockHeader, StacksBlockId, StacksMicroblockHeader, StacksWorkScore,
        VRFSeed,
    };
    use crate::types::proof::TrieHash;
    use crate::{
        chainstate::stacks::db::StacksHeaderInfo, util::vrf::VRFProof, vm::costs::ExecutionCost,
    };

    use super::MemPoolDB;

    const FOO_CONTRACT: &'static str = "(define-public (foo) (ok 1))
                                        (define-public (bar (x uint)) (ok x))";
    const SK_1: &'static str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
    const SK_2: &'static str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
    const SK_3: &'static str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

    #[test]
    fn mempool_db_init() {
        let _chainstate = instantiate_chainstate(false, 0x80000000, "mempool_db_init");
        let chainstate_path = chainstate_path("mempool_db_init");
        let _mempool = MemPoolDB::open(false, 0x80000000, &chainstate_path).unwrap();
    }

    fn make_block(
        chainstate: &mut StacksChainState,
        block_consensus: ConsensusHash,
        parent: &(ConsensusHash, BlockHeaderHash),
        burn_height: u64,
        block_height: u64,
    ) -> (ConsensusHash, BlockHeaderHash) {
        let (mut chainstate_tx, clar_tx) = chainstate.chainstate_tx_begin().unwrap();

        let anchored_header = StacksBlockHeader {
            version: 1,
            total_work: StacksWorkScore {
                work: block_height,
                burn: 1,
            },
            proof: VRFProof::empty(),
            parent_block: parent.1.clone(),
            parent_microblock: BlockHeaderHash([0; 32]),
            parent_microblock_sequence: 0,
            tx_merkle_root: Sha512Trunc256Sum::empty(),
            state_index_root: TrieHash::from_empty_data(),
            microblock_pubkey_hash: Hash160([0; 20]),
        };

        let block_hash = anchored_header.block_hash();

        let c_tx = StacksChainState::chainstate_block_begin(
            &chainstate_tx,
            clar_tx,
            &NULL_BURN_STATE_DB,
            &parent.0,
            &parent.1,
            &block_consensus,
            &block_hash,
        );

        let new_tip_info = StacksHeaderInfo {
            anchored_header,
            microblock_tail: None,
            index_root: TrieHash::from_empty_data(),
            block_height,
            consensus_hash: block_consensus.clone(),
            burn_header_hash: BurnchainHeaderHash([0; 32]),
            burn_header_height: burn_height as u32,
            burn_header_timestamp: 0,
            anchored_block_size: 1,
        };

        c_tx.commit_block();

        let new_index_hash = StacksBlockId::new(&block_consensus, &block_hash);

        chainstate_tx
            .put_indexed_begin(&StacksBlockId::new(&parent.0, &parent.1), &new_index_hash)
            .unwrap();

        StacksChainState::insert_stacks_block_header(
            &mut chainstate_tx,
            &new_index_hash,
            &new_tip_info,
            &ExecutionCost::zero(),
        )
        .unwrap();

        chainstate_tx.commit().unwrap();

        (block_consensus, block_hash)
    }

    #[test]
    fn mempool_walk_over_fork() {
        let mut chainstate = instantiate_chainstate_with_balances(
            false,
            0x80000000,
            "mempool_walk_over_fork",
            vec![],
        );

        // genesis -> b_1* -> b_2*
        //               \-> b_3 -> b_4
        //
        // *'d blocks accept transactions,
        //   try to walk at b_4, we should be able to find
        //   the transaction at b_1

        let b_1 = make_block(
            &mut chainstate,
            ConsensusHash([0x1; 20]),
            &(
                FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                FIRST_STACKS_BLOCK_HASH.clone(),
            ),
            1,
            1,
        );
        let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);
        let b_5 = make_block(&mut chainstate, ConsensusHash([0x5; 20]), &b_2, 5, 3);
        let b_3 = make_block(&mut chainstate, ConsensusHash([0x3; 20]), &b_1, 3, 2);
        let b_4 = make_block(&mut chainstate, ConsensusHash([0x4; 20]), &b_3, 4, 3);

        let chainstate_path = chainstate_path("mempool_walk_over_fork");
        let mut mempool = MemPoolDB::open(false, 0x80000000, &chainstate_path).unwrap();

        let mut txs = codec_all_transactions(
            &TransactionVersion::Testnet,
            0x80000000,
            &TransactionAnchorMode::Any,
            &TransactionPostConditionMode::Allow,
        );

        let blocks_to_broadcast_in = [&b_1, &b_2, &b_4];
        let mut txs = [txs.pop().unwrap(), txs.pop().unwrap(), txs.pop().unwrap()];
        for tx in txs.iter_mut() {
            tx.set_tx_fee(123);
        }

        for ix in 0..3 {
            let mut mempool_tx = mempool.tx_begin().unwrap();

            let block = &blocks_to_broadcast_in[ix];
            let tx = &txs[ix];

            let origin_address = StacksAddress {
                version: 22,
                bytes: Hash160::from_data(&[0; 32]),
            };
            let sponsor_address = StacksAddress {
                version: 22,
                bytes: Hash160::from_data(&[1; 32]),
            };

            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let tx_fee = tx.get_tx_fee();

            let height = 1 + ix as u64;

            let origin_nonce = ix as u64;
            let sponsor_nonce = ix as u64;

            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &block.0,
                &block.1,
                txid,
                tx_bytes,
                tx_fee,
                height,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce,
                None,
            )
            .unwrap();

            assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            mempool_tx.commit().unwrap();
        }

        // genesis -> b_1* -> b_2* -> b_5
        //               \-> b_3 -> b_4
        //
        // *'d blocks accept transactions,
        //   try to walk at b_4, we should be able to find
        //   the transaction at b_1

        let mut count_txs = 0;
        mempool
            .iterate_candidates::<_, ChainstateError>(2, |available_txs| {
                count_txs += available_txs.len();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            count_txs, 2,
            "Mempool should find two transactions from b_2"
        );

        let mut count_txs = 0;
        mempool
            .iterate_candidates::<_, ChainstateError>(3, |available_txs| {
                count_txs += available_txs.len();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            count_txs, 3,
            "Mempool should find three transactions from b_5"
        );

        let mut count_txs = 0;
        mempool
            .iterate_candidates::<_, ChainstateError>(2, |available_txs| {
                count_txs += available_txs.len();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            count_txs, 2,
            "Mempool should find two transactions from b_3"
        );

        let mut count_txs = 0;
        mempool
            .iterate_candidates::<_, ChainstateError>(3, |available_txs| {
                count_txs += available_txs.len();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            count_txs, 3,
            "Mempool should find three transactions from b_4"
        );

        // let's test replace-across-fork while we're here.
        // first try to replace a tx in b_2 in b_1 - should fail because they are in the same fork
        let mut mempool_tx = mempool.tx_begin().unwrap();
        let block = &b_1;
        let tx = &txs[1];
        let origin_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[0; 32]),
        };
        let sponsor_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[1; 32]),
        };

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();

        let height = 3;
        let origin_nonce = 1;
        let sponsor_nonce = 1;

        // make sure that we already have the transaction we're testing for replace-across-fork
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        assert!(MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &block.0,
            &block.1,
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .is_err());

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
        mempool_tx.commit().unwrap();

        // now try replace-across-fork from b_2 to b_4
        // check that the number of transactions at b_2 and b_4 starts at 1 each
        assert_eq!(
            MemPoolDB::get_num_tx_at_block(&mempool.db, &b_4.0, &b_4.1).unwrap(),
            1
        );
        assert_eq!(
            MemPoolDB::get_num_tx_at_block(&mempool.db, &b_2.0, &b_2.1).unwrap(),
            1
        );
        let mut mempool_tx = mempool.tx_begin().unwrap();
        let block = &b_4;
        let tx = &txs[1];
        let origin_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[0; 32]),
        };
        let sponsor_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[1; 32]),
        };

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();

        let height = 3;
        let origin_nonce = 1;
        let sponsor_nonce = 1;

        // make sure that we already have the transaction we're testing for replace-across-fork
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &block.0,
            &block.1,
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        mempool_tx.commit().unwrap();

        // after replace-across-fork, tx[1] should have moved from the b_2->b_5 fork to b_4
        assert_eq!(
            MemPoolDB::get_num_tx_at_block(&mempool.db, &b_4.0, &b_4.1).unwrap(),
            2
        );
        assert_eq!(
            MemPoolDB::get_num_tx_at_block(&mempool.db, &b_2.0, &b_2.1).unwrap(),
            0
        );
    }

    #[test]
    fn mempool_do_not_replace_tx() {
        let mut chainstate = instantiate_chainstate_with_balances(
            false,
            0x80000000,
            "mempool_do_not_replace_tx",
            vec![],
        );

        // genesis -> b_1 -> b_2
        //      \-> b_3
        //
        let b_1 = make_block(
            &mut chainstate,
            ConsensusHash([0x1; 20]),
            &(
                FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                FIRST_STACKS_BLOCK_HASH.clone(),
            ),
            1,
            1,
        );
        let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);
        let b_3 = make_block(&mut chainstate, ConsensusHash([0x3; 20]), &b_1, 1, 1);

        let chainstate_path = chainstate_path("mempool_do_not_replace_tx");
        let mut mempool = MemPoolDB::open(false, 0x80000000, &chainstate_path).unwrap();

        let mut txs = codec_all_transactions(
            &TransactionVersion::Testnet,
            0x80000000,
            &TransactionAnchorMode::Any,
            &TransactionPostConditionMode::Allow,
        );
        let mut tx = txs.pop().unwrap();

        let mut mempool_tx = mempool.tx_begin().unwrap();

        // do an initial insert
        let origin_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[0; 32]),
        };
        let sponsor_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[1; 32]),
        };

        tx.set_tx_fee(123);

        // test insert
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();

        let tx_fee = tx.get_tx_fee();
        let height = 100;

        let origin_nonce = tx.get_origin_nonce();
        let sponsor_nonce = match tx.get_sponsor_nonce() {
            Some(n) => n,
            None => origin_nonce,
        };

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_1.0,
            &b_1.1,
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let prior_txid = txid.clone();

        // now, let's try inserting again, with a lower fee, but at a different block hash
        tx.set_tx_fee(100);
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();
        let height = 100;

        let err_resp = MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_2.0,
            &b_2.1,
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap_err();
        assert!(match err_resp {
            MemPoolRejection::ConflictingNonceInMempool => true,
            _ => false,
        });

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &prior_txid).unwrap());
        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
    }

    #[test]
    fn mempool_db_load_store_replace_tx() {
        let mut chainstate =
            instantiate_chainstate(false, 0x80000000, "mempool_db_load_store_replace_tx");
        let chainstate_path = chainstate_path("mempool_db_load_store_replace_tx");
        let mut mempool = MemPoolDB::open(false, 0x80000000, &chainstate_path).unwrap();

        let mut txs = codec_all_transactions(
            &TransactionVersion::Testnet,
            0x80000000,
            &TransactionAnchorMode::Any,
            &TransactionPostConditionMode::Allow,
        );
        let num_txs = txs.len() as u64;

        let mut mempool_tx = mempool.tx_begin().unwrap();

        eprintln!("add all txs");
        for (i, mut tx) in txs.drain(..).enumerate() {
            // make sure each address is unique per tx (not the case in codec_all_transactions)
            let origin_address = StacksAddress {
                version: 22,
                bytes: Hash160::from_data(&i.to_be_bytes()),
            };
            let sponsor_address = StacksAddress {
                version: 22,
                bytes: Hash160::from_data(&(i + 1).to_be_bytes()),
            };

            tx.set_tx_fee(123);

            // test insert

            let txid = tx.txid();
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            let expected_tx = tx.clone();

            let tx_fee = tx.get_tx_fee();
            let height = 100;
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_nonce = match tx.get_sponsor_nonce() {
                Some(n) => n,
                None => origin_nonce,
            };
            let len = tx_bytes.len() as u64;

            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1; 20]),
                &BlockHeaderHash([0x2; 32]),
                txid,
                tx_bytes,
                tx_fee,
                height,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce,
                None,
            )
            .unwrap();

            assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            // test retrieval
            let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
            let tx_info = tx_info_opt.unwrap();

            assert_eq!(tx_info.tx, expected_tx);
            assert_eq!(tx_info.metadata.len, len);
            assert_eq!(tx_info.metadata.tx_fee, 123);
            assert_eq!(tx_info.metadata.origin_address, origin_address);
            assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
            assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
            assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
            assert_eq!(tx_info.metadata.consensus_hash, ConsensusHash([0x1; 20]));
            assert_eq!(
                tx_info.metadata.block_header_hash,
                BlockHeaderHash([0x2; 32])
            );
            assert_eq!(tx_info.metadata.block_height, height);

            // test replace-by-fee with a higher fee
            let old_txid = txid;

            tx.set_tx_fee(124);
            assert!(txid != tx.txid());

            let txid = tx.txid();
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            let expected_tx = tx.clone();
            let tx_fee = tx.get_tx_fee();

            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            let tx_info_before = MemPoolDB::get_tx_metadata_by_address(
                &mempool_tx,
                true,
                &origin_address,
                origin_nonce,
            )
            .unwrap()
            .unwrap();
            assert_eq!(tx_info_before, tx_info.metadata);

            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1; 20]),
                &BlockHeaderHash([0x2; 32]),
                txid,
                tx_bytes,
                tx_fee,
                height,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce,
                None,
            )
            .unwrap();

            // was replaced
            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
            assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            let tx_info_after = MemPoolDB::get_tx_metadata_by_address(
                &mempool_tx,
                true,
                &origin_address,
                origin_nonce,
            )
            .unwrap()
            .unwrap();
            assert!(tx_info_after != tx_info.metadata);

            // test retrieval -- transaction should have been replaced because it has a higher
            // estimated fee
            let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();

            let tx_info = tx_info_opt.unwrap();
            assert_eq!(tx_info.metadata, tx_info_after);

            assert_eq!(tx_info.tx, expected_tx);
            assert_eq!(tx_info.metadata.len, len);
            assert_eq!(tx_info.metadata.tx_fee, 124);
            assert_eq!(tx_info.metadata.origin_address, origin_address);
            assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
            assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
            assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
            assert_eq!(tx_info.metadata.consensus_hash, ConsensusHash([0x1; 20]));
            assert_eq!(
                tx_info.metadata.block_header_hash,
                BlockHeaderHash([0x2; 32])
            );
            assert_eq!(tx_info.metadata.block_height, height);

            // test replace-by-fee with a lower fee
            let old_txid = txid;

            tx.set_tx_fee(122);
            assert!(txid != tx.txid());

            let txid = tx.txid();
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            let _expected_tx = tx.clone();
            let tx_fee = tx.get_tx_fee();

            assert!(match MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1; 20]),
                &BlockHeaderHash([0x2; 32]),
                txid,
                tx_bytes,
                tx_fee,
                height,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce,
                None,
            )
            .unwrap_err()
            {
                MemPoolRejection::ConflictingNonceInMempool => true,
                _ => false,
            });

            // was NOT replaced
            assert!(MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
        }
        mempool_tx.commit().unwrap();

        eprintln!("get all txs");
        let txs = MemPoolDB::get_txs_after(
            &mempool.db,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            0,
            num_txs,
        )
        .unwrap();
        assert_eq!(txs.len() as u64, num_txs);

        eprintln!("get empty txs");
        let txs = MemPoolDB::get_txs_after(
            &mempool.db,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x3; 32]),
            0,
            num_txs,
        )
        .unwrap();
        assert_eq!(txs.len(), 0);

        eprintln!("get empty txs");
        let txs = MemPoolDB::get_txs_after(
            &mempool.db,
            &ConsensusHash([0x2; 20]),
            &BlockHeaderHash([0x2; 32]),
            0,
            num_txs,
        )
        .unwrap();
        assert_eq!(txs.len(), 0);

        eprintln!("garbage-collect");
        let mut mempool_tx = mempool.tx_begin().unwrap();
        MemPoolDB::garbage_collect(&mut mempool_tx, 101, None).unwrap();
        mempool_tx.commit().unwrap();

        let txs = MemPoolDB::get_txs_after(
            &mempool.db,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            0,
            num_txs,
        )
        .unwrap();
        assert_eq!(txs.len(), 0);
    }

    #[test]
    fn mempool_db_test_rbf() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "mempool_db_test_rbf");
        let chainstate_path = chainstate_path("mempool_db_test_rbf");
        let mut mempool = MemPoolDB::open(false, 0x80000000, &chainstate_path).unwrap();

        // create initial transaction
        let mut mempool_tx = mempool.tx_begin().unwrap();
        let spending_condition =
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                nonce: 123,
                tx_fee: 456,
                signature: MessageSignature::from_raw(&vec![0xff; 65]),
            });
        let stx_address = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        };
        let payload = TransactionPayload::TokenTransfer(
            PrincipalData::from(QualifiedContractIdentifier {
                issuer: stx_address.into(),
                name: "hello-contract-name".into(),
            }),
            123,
            TokenTransferMemo([0u8; 34]),
        );
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::Standard(spending_condition.clone()),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: Vec::new(),
            payload,
        };

        let i: usize = 0;
        let origin_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&i.to_be_bytes()),
        };
        let sponsor_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&(i + 1).to_be_bytes()),
        };

        tx.set_tx_fee(123);
        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let expected_tx = tx.clone();
        let tx_fee = tx.get_tx_fee();
        let height = 100;
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_nonce = match tx.get_sponsor_nonce() {
            Some(n) => n,
            None => origin_nonce,
        };
        let first_len = tx_bytes.len() as u64;

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        // test retrieval of initial transaction
        let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
        let tx_info = tx_info_opt.unwrap();

        // test replace-by-fee with a higher fee, where the payload is smaller
        let old_txid = txid;
        let old_tx_fee = tx_fee;

        tx.set_tx_fee(124);
        tx.payload = TransactionPayload::TokenTransfer(
            stx_address.into(),
            123,
            TokenTransferMemo([0u8; 34]),
        );
        assert!(txid != tx.txid());
        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let expected_tx = tx.clone();
        let tx_fee = tx.get_tx_fee();
        let second_len = tx_bytes.len() as u64;

        // these asserts are to ensure we are using the fee directly, not the fee rate
        assert!(second_len < first_len);
        assert!(second_len * tx_fee < first_len * old_tx_fee);
        assert!(tx_fee > old_tx_fee);
        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let tx_info_before =
            MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
                .unwrap()
                .unwrap();
        assert_eq!(tx_info_before, tx_info.metadata);

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        // check that the transaction was replaced
        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let tx_info_after =
            MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
                .unwrap()
                .unwrap();
        assert!(tx_info_after != tx_info.metadata);

        // test retrieval -- transaction should have been replaced because it has a higher fee
        let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
        let tx_info = tx_info_opt.unwrap();
        assert_eq!(tx_info.metadata, tx_info_after);
        assert_eq!(tx_info.metadata.len, second_len);
        assert_eq!(tx_info.metadata.tx_fee, 124);
    }
}
