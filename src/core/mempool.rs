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

use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::OpenFlags;
use rusqlite::OptionalExtension;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::NO_PARAMS;

use std::cmp;
use std::ops::Deref;
use std::ops::DerefMut;

use burnchains::Txid;
use chainstate::burn::ConsensusHash;

use net::StacksMessageCodec;

use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::{
    db::blocks::MemPoolRejection, db::StacksChainState, index::Error as MarfError,
    Error as ChainstateError, StacksAddress, StacksBlockHeader, StacksTransaction,
};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use util::db::query_row;
use util::db::query_rows;
use util::db::tx_begin_immediate;
use util::db::tx_busy_handler;
use util::db::u64_to_sql;
use util::db::Error as db_error;
use util::db::FromColumn;
use util::db::{DBConn, DBTx, FromRow};
use util::get_epoch_time_secs;

use core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use core::FIRST_STACKS_BLOCK_HASH;

use rusqlite::Error as SqliteError;

// maximum number of confirmations a transaction can have before it's garbage-collected
pub const MEMPOOL_MAX_TRANSACTION_AGE: u64 = 256;
pub const MAXIMUM_MEMPOOL_TX_CHAINING: u64 = 25;

pub struct MemPoolAdmitter {
    cur_block: BlockHeaderHash,
    cur_consensus_hash: ConsensusHash,
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
    pub estimated_fee: u64, // upper bound on what the fee to pay will be
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub block_height: u64,
    pub origin_address: StacksAddress,
    pub origin_nonce: u64,
    pub sponsor_address: StacksAddress,
    pub sponsor_nonce: u64,
    pub accept_time: u64,
}

impl FromRow<MemPoolTxMetadata> for MemPoolTxMetadata {
    fn from_row<'a>(row: &'a Row) -> Result<MemPoolTxMetadata, db_error> {
        let txid = Txid::from_column(row, "txid")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let block_header_hash = BlockHeaderHash::from_column(row, "block_header_hash")?;
        let estimated_fee = u64::from_column(row, "estimated_fee")?;
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
            estimated_fee: estimated_fee,
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
        let tx_bytes: Vec<u8> = row.get("tx");
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

const MEMPOOL_SQL: &'static [&'static str] = &[
    r#"
    CREATE TABLE mempool(
        txid TEXT NOT NULL,
        origin_address TEXT NOT NULL,
        origin_nonce INTEGER NOT NULL,
        sponsor_address TEXT NOT NULL,
        sponsor_nonce INTEGER NOT NULL,
        estimated_fee INTEGER NOT NULL,
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
    r#"
    CREATE INDEX by_txid ON mempool(txid);
    CREATE INDEX by_sponsor ON mempool(sponsor_address, sponsor_nonce),
    CREATE INDEX by_origin ON mempool(origin_address, origin_nonce),
    CREATE INDEX by_timestamp ON mempool(accept_time);
    CREATE INDEX by_chaintip ON mempool(consensus_hash,block_header_hash);
    CREATE INDEX by_estimated_fee ON mempool(estimated_fee);
    "#,
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

    fn is_block_in_fork(
        &mut self,
        chainstate: &mut StacksChainState,
        check_consensus_hash: &ConsensusHash,
        check_stacks_block: &BlockHeaderHash,
        cur_consensus_hash: &ConsensusHash,
        cur_stacks_block: &BlockHeaderHash,
    ) -> Result<bool, db_error> {
        let admitter_block =
            StacksBlockHeader::make_index_block_hash(cur_consensus_hash, cur_stacks_block);
        let index_block =
            StacksBlockHeader::make_index_block_hash(check_consensus_hash, check_stacks_block);
        // short circuit equality
        if admitter_block == index_block {
            return Ok(true);
        }

        let height_result = chainstate
            .with_clarity_marf(|marf| marf.get_block_height_of(&index_block, &admitter_block));
        match height_result {
            Ok(x) => {
                eprintln!("{} from {} => {:?}", &index_block, &admitter_block, x);
                Ok(x.is_some())
            }
            Err(x) => Err(db_error::IndexError(x)),
        }
    }
}

impl MemPoolTxInfo {
    pub fn from_tx(
        tx: StacksTransaction,
        estimated_fee: u64,
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
            estimated_fee: estimated_fee,
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
        let tx = tx_begin_immediate(conn)?;

        for cmd in MEMPOOL_SQL {
            tx.execute(cmd, NO_PARAMS).map_err(db_error::SqliteError)?;
        }

        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
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

        let mut path = PathBuf::from(chainstate.root_path.clone());

        let admitter = MemPoolAdmitter::new(BlockHeaderHash([0u8; 32]), ConsensusHash([0u8; 20]));

        path.push("mempool.db");
        let db_path = path
            .to_str()
            .ok_or_else(|| db_error::ParseError)?
            .to_string();

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
            path: db_path.to_string(),
            admitter: admitter,
        })
    }

    fn walk(
        &self,
        chainstate: &mut StacksChainState,
        tip_consensus_hash: &ConsensusHash,
        tip_block_hash: &BlockHeaderHash,
        tip_height: u64,
    ) -> Result<Option<(ConsensusHash, BlockHeaderHash, u64, u64)>, ChainstateError> {
        // Walk back to the next-highest
        // ancestor of this tip, and see if we can include anything from there.
        let next_height = MemPoolDB::get_previous_block_height(&self.db, tip_height)?.unwrap_or(0);
        if next_height == 0 && tip_height == 0 {
            // we're done -- tried every tx
            debug!("Done scanning mempool -- at height 0");
            return Ok(None);
        }

        let mut next_tips = MemPoolDB::get_chain_tips_at_height(&self.db, next_height)?;
        if next_tips.len() == 0 {
            // we're done -- no more chain tips
            debug!(
                "Done scanning mempool -- no chain tips at height {}",
                next_height
            );
            return Ok(None);
        }

        let ancestor_tip = {
            let headers_conn = chainstate.index_conn()?;
            let index_block =
                StacksBlockHeader::make_index_block_hash(tip_consensus_hash, tip_block_hash);
            match StacksChainState::get_index_tip_ancestor_conn(
                &headers_conn,
                &index_block,
                next_height,
            )? {
                Some(tip_info) => tip_info,
                None => {
                    // no such ancestor.  We're done
                    debug!(
                        "Done scanning mempool -- no ancestor at height {} off of {}/{} ({})",
                        next_height,
                        tip_consensus_hash,
                        tip_block_hash,
                        StacksBlockHeader::make_index_block_hash(
                            tip_consensus_hash,
                            tip_block_hash
                        )
                    );
                    return Ok(None);
                }
            }
        };

        // find out which tip is the ancestor tip
        let mut found = false;
        let mut next_tip_consensus_hash = tip_consensus_hash.clone();
        let mut next_tip_block_hash = tip_block_hash.clone();

        for (consensus_hash, block_bhh) in next_tips.drain(..) {
            if ancestor_tip.consensus_hash == consensus_hash
                && ancestor_tip.anchored_header.block_hash() == block_bhh
            {
                found = true;
                next_tip_consensus_hash = consensus_hash;
                next_tip_block_hash = block_bhh;
                break;
            }
        }

        if !found {
            // no such ancestor.  We're done.
            debug!("Done scanning mempool -- none of the available prior chain tips at {} is an ancestor of {}/{}", next_height, tip_consensus_hash, tip_block_hash);
            return Ok(None);
        }

        let next_timestamp = match MemPoolDB::get_next_timestamp(
            &self.db,
            &next_tip_consensus_hash,
            &next_tip_block_hash,
            0,
        )? {
            Some(ts) => ts,
            None => {
                unreachable!("No transactions at a chain tip that exists");
            }
        };

        debug!(
            "Will start scaning mempool at {}/{} height={} ts={}",
            &next_tip_consensus_hash, &next_tip_block_hash, next_height, next_timestamp
        );
        Ok(Some((
            next_tip_consensus_hash,
            next_tip_block_hash,
            next_height,
            next_timestamp,
        )))
    }

    ///
    /// Iterate over candidates in the mempool
    ///  todo will be called once for each bundle of transactions at
    ///  each ancestor chain tip from the given one, starting with the
    ///  most recent chain tip and working backwards until there are
    ///  no more transactions to consider. Each batch of transactions
    ///  passed to todo will be sorted in nonce order.
    pub fn iterate_candidates<F, E>(
        &self,
        tip_consensus_hash: &ConsensusHash,
        tip_block_hash: &BlockHeaderHash,
        tip_height: u64,
        chainstate: &mut StacksChainState,
        mut todo: F,
    ) -> Result<(), E>
    where
        F: FnMut(Vec<MemPoolTxInfo>) -> Result<(), E>,
        E: From<db_error> + From<ChainstateError>,
    {
        let (mut tip_consensus_hash, mut tip_block_hash, mut tip_height) = (
            tip_consensus_hash.clone(),
            tip_block_hash.clone(),
            tip_height,
        );

        debug!(
            "Begin scanning transaction mempool at {}/{} height={}",
            &tip_consensus_hash, &tip_block_hash, tip_height
        );

        let mut next_timestamp =
            match MemPoolDB::get_next_timestamp(&self.db, &tip_consensus_hash, &tip_block_hash, 0)?
            {
                Some(ts) => ts,
                None => {
                    // walk back to where the first transaction we can mine can be found
                    match self.walk(chainstate, &tip_consensus_hash, &tip_block_hash, tip_height)? {
                        Some((
                            next_consensus_hash,
                            next_block_bhh,
                            next_height,
                            next_timestamp,
                        )) => {
                            tip_consensus_hash = next_consensus_hash;
                            tip_block_hash = next_block_bhh;
                            tip_height = next_height;
                            next_timestamp
                        }
                        None => {
                            return Ok(());
                        }
                    }
                }
            };

        loop {
            let available_txs = MemPoolDB::get_txs_at(
                &self.db,
                &tip_consensus_hash,
                &tip_block_hash,
                next_timestamp,
            )?;

            debug!(
                "Have {} transactions at {}/{} height={} at or after {}",
                available_txs.len(),
                &tip_consensus_hash,
                &tip_block_hash,
                tip_height,
                next_timestamp
            );

            todo(available_txs)?;
            next_timestamp = match MemPoolDB::get_next_timestamp(
                &self.db,
                &tip_consensus_hash,
                &tip_block_hash,
                next_timestamp,
            )? {
                Some(ts) => ts,
                None => {
                    // walk back
                    match self.walk(chainstate, &tip_consensus_hash, &tip_block_hash, tip_height)? {
                        Some((
                            next_consensus_hash,
                            next_block_bhh,
                            next_height,
                            next_timestamp,
                        )) => {
                            tip_consensus_hash = next_consensus_hash;
                            tip_block_hash = next_block_bhh;
                            tip_height = next_height;
                            next_timestamp
                        }
                        None => {
                            // no more transactions
                            return Ok(());
                        }
                    }
                }
            };
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

    fn get_tx_estimated_fee(conn: &DBConn, txid: &Txid) -> Result<Option<u64>, db_error> {
        query_row(
            conn,
            "SELECT estimated_fee FROM mempool WHERE txid = ?1",
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

    /// Get the next timestamp after this one that occurs in this chain tip.
    pub fn get_next_timestamp(
        conn: &DBConn,
        consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
        timestamp: u64,
    ) -> Result<Option<u64>, db_error> {
        let sql = "SELECT accept_time FROM mempool WHERE accept_time > ?1 AND consensus_hash = ?2 AND block_header_hash = ?3 ORDER BY accept_time ASC LIMIT 1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(timestamp)?, consensus_hash, block_header_hash];
        query_row(conn, sql, args)
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

    /// Get chain tip(s) at a given height that have transactions
    pub fn get_chain_tips_at_height(
        conn: &DBConn,
        height: u64,
    ) -> Result<Vec<(ConsensusHash, BlockHeaderHash)>, db_error> {
        let sql = "SELECT consensus_hash,block_header_hash FROM mempool WHERE height = ?1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(height)?];

        let mut stmt = conn.prepare(sql).map_err(db_error::SqliteError)?;

        let mut rows = stmt.query(args).map_err(db_error::SqliteError)?;

        // gather
        let mut tips = vec![];
        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let consensus_hash = ConsensusHash::from_column(&row, "consensus_hash")?;
                    let block_hash = BlockHeaderHash::from_column(&row, "block_header_hash")?;
                    tips.push((consensus_hash, block_hash));
                }
                Err(e) => {
                    return Err(db_error::SqliteError(e));
                }
            };
        }

        Ok(tips)
    }

    /// Get a number of transactions after a given timestamp on a given chain tip.
    pub fn get_txs_after(
        conn: &DBConn,
        consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
        timestamp: u64,
        count: u64,
    ) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let sql = "SELECT * FROM mempool WHERE accept_time >= ?1 AND consensus_hash = ?2 AND block_header_hash = ?3 ORDER BY estimated_fee DESC LIMIT ?4";
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
                          estimated_fee,
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

    /// Add a transaction to the mempool.  If it already exists, then replace it if the given fee
    /// is higher than the one that's already there.
    /// Carry out the mempool admission test before adding.
    /// Don't call directly; use submit()
    fn try_add_tx<'a>(
        tx: &mut MemPoolTx<'a>,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
        txid: Txid,
        tx_bytes: Vec<u8>,
        estimated_fee: u64,
        tx_fee: u64,
        height: u64,
        origin_address: &StacksAddress,
        origin_nonce: u64,
        sponsor_address: &StacksAddress,
        sponsor_nonce: u64,
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

        // if so, is this a replace-by-fee? or a replace-in-chain-tip?
        let add_tx = if let Some(prior_tx) = prior_tx {
            if estimated_fee > prior_tx.estimated_fee {
                // is this a replace-by-fee ?
                true
            } else if !tx.is_block_in_fork(
                chainstate,
                &prior_tx.consensus_hash,
                &prior_tx.block_header_hash,
                consensus_hash,
                block_header_hash,
            )? {
                // is this a replace-across-fork ?
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
                      "new_fee" => estimated_fee,
                      "old_fee" => prior_tx.estimated_fee);
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
            estimated_fee,
            tx_fee,
            length,
            consensus_hash,
            block_header_hash,
            height,
            accept_time,
            tx)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

        let args: &[&dyn ToSql] = &[
            &txid,
            &origin_address.to_string(),
            &u64_to_sql(origin_nonce)?,
            &sponsor_address.to_string(),
            &u64_to_sql(sponsor_nonce)?,
            &u64_to_sql(estimated_fee)?,
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
        Ok(())
    }

    /// Garbage-collect the mempool.  Remove transactions that have a given number of
    /// confirmations.
    pub fn garbage_collect<'a>(tx: &mut MemPoolTx<'a>, min_height: u64) -> Result<(), db_error> {
        let sql = "DELETE FROM mempool WHERE height < ?1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(min_height)?];

        tx.execute(sql, args).map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn clear_before_height(&mut self, min_height: u64) -> Result<(), db_error> {
        let mut tx = self.tx_begin()?;
        MemPoolDB::garbage_collect(&mut tx, min_height)?;
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
    pub fn tx_submit(
        mempool_tx: &mut MemPoolTx,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx: &StacksTransaction,
        do_admission_checks: bool,
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

        // TODO; estimate the true fee using Clarity analysis data.  For now, just do tx_fee
        let estimated_fee = tx_fee
            .checked_mul(len)
            .ok_or(MemPoolRejection::Other("Fee numeric overflow".to_string()))?;

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
            txid,
            tx_data,
            estimated_fee,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
        )?;

        Ok(())
    }

    /// One-shot submit
    pub fn submit(
        &mut self,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx: &StacksTransaction,
    ) -> Result<(), MemPoolRejection> {
        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;
        MemPoolDB::tx_submit(
            &mut mempool_tx,
            chainstate,
            consensus_hash,
            block_hash,
            tx,
            true,
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
        )?;
        mempool_tx.commit().map_err(MemPoolRejection::DBError)?;
        Ok(())
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
    use chainstate::burn::{BlockHeaderHash, VRFSeed};
    use net::{Error as NetError, StacksMessageCodec};
    use util::{hash::hex_bytes, hash::to_hex, hash::*, log, secp256k1::*, strings::StacksString};
    use vm::{
        database::HeadersDB,
        database::NULL_BURN_STATE_DB,
        errors::Error as ClarityError,
        errors::RuntimeErrorType,
        types::{PrincipalData, QualifiedContractIdentifier},
        ClarityName, ContractName, Value,
    };

    use chainstate::stacks::{
        db::blocks::MemPoolRejection, db::StacksChainState, index::MarfTrieId, CoinbasePayload,
        Error as ChainstateError, StacksAddress, StacksBlockHeader, StacksMicroblockHeader,
        StacksPrivateKey, StacksPublicKey, StacksTransaction, StacksTransactionSigner,
        TokenTransferMemo, TransactionAnchorMode, TransactionAuth, TransactionContractCall,
        TransactionPayload, TransactionPostConditionMode, TransactionSmartContract,
        TransactionSpendingCondition, TransactionVersion, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    };

    use super::MemPoolDB;
    use util::db::{DBConn, FromRow};

    use chainstate::burn::ConsensusHash;
    use chainstate::stacks::db::test::chainstate_path;
    use chainstate::stacks::db::test::instantiate_chainstate;
    use chainstate::stacks::db::test::instantiate_chainstate_with_balances;
    use chainstate::stacks::test::codec_all_transactions;
    use core::FIRST_BURNCHAIN_CONSENSUS_HASH;
    use core::FIRST_STACKS_BLOCK_HASH;

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

        let b_1 = (ConsensusHash([0x1; 20]), BlockHeaderHash([0x4; 32]));
        let b_2 = (ConsensusHash([0x2; 20]), BlockHeaderHash([0x5; 32]));
        let b_3 = (ConsensusHash([0x3; 20]), BlockHeaderHash([0x6; 32]));

        eprintln!(
            "b_1 => {}",
            &StacksBlockHeader::make_index_block_hash(&b_1.0, &b_1.1)
        );
        eprintln!(
            "b_2 => {}",
            &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1)
        );
        eprintln!(
            "b_3 => {}",
            &StacksBlockHeader::make_index_block_hash(&b_3.0, &b_3.1)
        );

        {
            let (chainstate_tx, clar_tx) = chainstate.chainstate_tx_begin().unwrap();
            let c_tx = StacksChainState::chainstate_block_begin(
                &chainstate_tx,
                clar_tx,
                &NULL_BURN_STATE_DB,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &b_1.0,
                &b_1.1,
            );
            c_tx.commit_block();
        }

        {
            let (chainstate_tx, clar_tx) = chainstate.chainstate_tx_begin().unwrap();
            let c_tx = StacksChainState::chainstate_block_begin(
                &chainstate_tx,
                clar_tx,
                &NULL_BURN_STATE_DB,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                &b_3.0,
                &b_3.1,
            );
            c_tx.commit_block();
        }

        {
            let (chainstate_tx, clar_tx) = chainstate.chainstate_tx_begin().unwrap();
            let c_tx = StacksChainState::chainstate_block_begin(
                &chainstate_tx,
                clar_tx,
                &NULL_BURN_STATE_DB,
                &b_1.0,
                &b_1.1,
                &b_2.0,
                &b_2.1,
            );
            c_tx.commit_block();
        }

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

        let len = tx_bytes.len() as u64;
        let estimated_fee = tx.get_tx_fee() * len; //TODO: use clarity analysis data to make this estimate
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
            estimated_fee,
            tx.get_tx_fee(),
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
        )
        .unwrap();

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let prior_txid = txid.clone();

        // now, let's try inserting again, with a lower fee, but at a different block hash
        tx.set_tx_fee(100);
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let len = tx_bytes.len() as u64;
        let estimated_fee = tx.get_tx_fee() * len; //TODO: use clarity analysis data to make this estimate
        let height = 100;

        let err_resp = MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_2.0,
            &b_2.1,
            txid,
            tx_bytes,
            estimated_fee,
            tx.get_tx_fee(),
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
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

            let len = tx_bytes.len() as u64;
            let estimated_fee = tx.get_tx_fee() * len; //TODO: use clarity analysis data to make this estimate
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
                &ConsensusHash([0x1; 20]),
                &BlockHeaderHash([0x2; 32]),
                txid,
                tx_bytes,
                estimated_fee,
                tx.get_tx_fee(),
                height,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce,
            )
            .unwrap();

            assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            // test retrieval
            let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
            let tx_info = tx_info_opt.unwrap();

            assert_eq!(tx_info.tx, expected_tx);
            assert_eq!(tx_info.metadata.len, len);
            assert_eq!(tx_info.metadata.estimated_fee, estimated_fee);
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
            let estimated_fee = tx.get_tx_fee() * len; // TODO: use clarity analysis data to make this estimate

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
                estimated_fee,
                tx.get_tx_fee(),
                height,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce,
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
            assert_eq!(tx_info.metadata.estimated_fee, estimated_fee);
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
            let estimated_fee = tx.get_tx_fee() * len; // TODO: use clarity analysis metadata to make this estimate

            assert!(match MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1; 20]),
                &BlockHeaderHash([0x2; 32]),
                txid,
                tx_bytes,
                estimated_fee,
                tx.get_tx_fee(),
                height,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce
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
        MemPoolDB::garbage_collect(&mut mempool_tx, 101).unwrap();
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
}
