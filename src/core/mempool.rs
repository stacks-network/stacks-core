/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

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

use rusqlite::Transaction;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::NO_PARAMS;
use rusqlite::OpenFlags;
use rusqlite::types::ToSql;
use rusqlite::Row;

use std::ops::Deref;
use std::ops::DerefMut;

use burnchains::BurnchainHeaderHash;
use burnchains::Txid;

use net::StacksMessageCodec;

use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::{
    StacksAddress,
    StacksTransaction,
    db::StacksChainState,
    db::blocks::MemPoolRejection
};
use std::io::Read;
use std::fs;
use std::path::{Path, PathBuf};

use util::db::u64_to_sql;
use util::db::{DBConn, DBTx, FromRow};
use util::db::FromColumn;
use util::db::query_rows;
use util::db::query_row;
use util::db::Error as db_error;
use util::get_epoch_time_secs;
use util::db::tx_begin_immediate;
use util::db::tx_busy_handler;

use core::FIRST_STACKS_BLOCK_HASH;
use core::FIRST_BURNCHAIN_BLOCK_HASH;

// maximum number of confirmations a transaction can have before it's garbage-collected
pub const MEMPOOL_MAX_TRANSACTION_AGE : u64 = 256;

pub struct MemPoolAdmitter {
    // mempool admission should have its own chain state view.
    //   the mempool admitter interacts with the chain state
    //   exclusively in read-only fashion, however, it should have
    //   its own instance of things like the MARF index, because otherwise
    //   mempool admission tests would block with chain processing.
    chainstate: StacksChainState,
    cur_block: BlockHeaderHash,
    cur_burn_block: BurnchainHeaderHash,
}

impl MemPoolAdmitter {
    pub fn new(chainstate: StacksChainState, cur_block: BlockHeaderHash, cur_burn_block: BurnchainHeaderHash) -> MemPoolAdmitter {
        MemPoolAdmitter { chainstate, cur_block, cur_burn_block }
    }

    pub fn set_block(&mut self, cur_block: &BlockHeaderHash, cur_burn_block: &BurnchainHeaderHash) {
        self.cur_burn_block = cur_burn_block.clone();
        self.cur_block = cur_block.clone();
    }

    pub fn will_admit_tx(&mut self, tx: &StacksTransaction, tx_size: u64) -> Result<(), MemPoolRejection> {
        self.chainstate.will_admit_mempool_tx(&self.cur_burn_block, &self.cur_block, tx, tx_size)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct MemPoolTxInfo {
    pub tx: StacksTransaction,
    pub metadata: MemPoolTxMetadata
}

#[derive(Debug, PartialEq, Clone)]
pub struct MemPoolTxMetadata {
    pub txid: Txid,
    pub len: u64,
    pub fee_rate: u64,
    pub estimated_fee: u64,     // upper bound on what the fee to pay will be
    pub burn_header_hash: BurnchainHeaderHash,
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
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let block_header_hash = BlockHeaderHash::from_column(row, "block_header_hash")?;
        let estimated_fee = u64::from_column(row, "estimated_fee")?;
        let fee_rate = u64::from_column(row, "fee_rate")?;
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
            fee_rate: fee_rate,
            len: len,
            burn_header_hash: burn_header_hash,
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
        let tx_bytes : Vec<u8> = row.get("tx");
        let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..])
            .map_err(|_e| db_error::ParseError)?;

        if tx.txid() != md.txid {
            return Err(db_error::ParseError);
        }

        Ok(MemPoolTxInfo {
            tx: tx,
            metadata: md
        })
    }
}


const MEMPOOL_SQL : &'static [&'static str] = &[
    r#"
    CREATE TABLE mempool(
        txid TEXT NOT NULL,
        origin_address TEXT NOT NULL,
        origin_nonce INTEGER NOT NULL,
        sponsor_address TEXT NOT NULL,
        sponsor_nonce INTEGER NOT NULL,
        estimated_fee INTEGER NOT NULL,
        fee_rate INTEGER NOT NULL,
        length INTEGER NOT NULL,
        burn_header_hash TEXT NOT NULL,
        block_header_hash TEXT NOT NULL,
        height INTEGER NOT NULL,    -- stacks block height
        accept_time INTEGER NOT NULL,
        tx BLOB NOT NULL,
        PRIMARY KEY(origin_address,origin_nonce,sponsor_address,sponsor_nonce)
    );
    "#,
    r#"
    CREATE INDEX by_txid ON mempool(txid);
    CREATE INDEX by_timestamp ON mempool(accept_time);
    CREATE INDEX by_chaintip ON mempool(burn_header_hash,block_header_hash);
    CREATE INDEX by_estimated_fee ON mempool(estimated_fee);
    "#
];

pub struct MemPoolDB {
    db: DBConn,
    path: String,
    admitter: MemPoolAdmitter,
}

pub struct MemPoolTx<'a> {
    tx: DBTx<'a>,
    admitter: &'a mut MemPoolAdmitter
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
        MemPoolTx {
            tx,
            admitter
        }
    }
    
    pub fn commit(self) -> Result<(), db_error> {
        self.tx.commit().map_err(db_error::SqliteError)
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
    pub fn open(mainnet: bool, chain_id: u32, chainstate_path: &str) -> Result<MemPoolDB, db_error> {
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

        let chainstate = StacksChainState::open(mainnet, chain_id, chainstate_path)
            .map_err(|e| db_error::Other(format!("Failed to open chainstate: {:?}", &e)))?;
        
        let mut path = PathBuf::from(chainstate.root_path.clone());

        let admitter = MemPoolAdmitter::new(chainstate, BlockHeaderHash([0u8; 32]), BurnchainHeaderHash([0u8; 32]));

        path.push("mempool.db");
        let db_path = path.to_str().ok_or_else(|| db_error::ParseError)?.to_string();

        let mut create_flag = false;
        let open_flags =
            if fs::metadata(&db_path).is_err() {
                // need to create 
                create_flag = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            }
            else {
                // can just open 
                OpenFlags::SQLITE_OPEN_READ_WRITE
            };

        let mut conn = DBConn::open_with_flags(&db_path, open_flags).map_err(db_error::SqliteError)?;
        conn.busy_handler(Some(tx_busy_handler)).map_err(db_error::SqliteError)?;

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

    pub fn conn(&self) -> &DBConn {
        &self.db
    }

    pub fn tx_begin<'a>(&'a mut self) -> Result<MemPoolTx<'a>, db_error> {
        let tx = tx_begin_immediate(&mut self.db)?;
        Ok(MemPoolTx::new(tx, &mut self.admitter))
    }

    fn db_has_tx(conn: &DBConn, txid: &Txid) -> Result<bool, db_error> {
        query_row(conn, "SELECT 1 FROM mempool WHERE txid = ?1", &[txid as &dyn ToSql])
            .and_then(|row_opt: Option<i64>| Ok(row_opt.is_some()))
    }

    pub fn get_tx(conn: &DBConn, txid: &Txid) -> Result<Option<MemPoolTxInfo>, db_error> {
        query_row(conn, "SELECT * FROM mempool WHERE txid = ?1", &[txid as &dyn ToSql])
    }
    
    fn get_tx_estimated_fee(conn: &DBConn, txid: &Txid) -> Result<Option<u64>, db_error> {
        query_row(conn, "SELECT estimated_fee FROM mempool WHERE txid = ?1", &[txid as &dyn ToSql])
    }

    /// Get all transactions across all tips
    #[cfg(test)]
    pub fn get_all_txs(conn: &DBConn) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let sql = "SELECT * FROM mempool";
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, NO_PARAMS)?;
        Ok(rows)
    }

    /// Get the next timestamp after this one that occurs in this chain tip.
    pub fn get_next_timestamp(conn: &DBConn, burnchain_header_hash: &BurnchainHeaderHash, block_header_hash: &BlockHeaderHash, timestamp: u64) -> Result<Option<u64>, db_error> {
        let sql = "SELECT accept_time FROM mempool WHERE accept_time > ?1 AND burn_header_hash = ?2 AND block_header_hash = ?3 ORDER BY accept_time LIMIT 1";
        let args : &[&dyn ToSql] = &[&u64_to_sql(timestamp)?, burnchain_header_hash, block_header_hash];
        query_row(conn, sql, args)
    }
    
    /// Get all transactions at a particular timestamp and chain tip
    pub fn get_txs_at(conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_header_hash: &BlockHeaderHash, timestamp: u64) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let sql = "SELECT * FROM mempool WHERE accept_time = ?1 AND burn_header_hash = ?2 AND block_header_hash = ?3 ORDER BY estimated_fee DESC";
        let args : &[&dyn ToSql] = &[&u64_to_sql(timestamp)?, burn_header_hash, block_header_hash];
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, args)?;
        Ok(rows)
    }

    /// Given a chain tip, find the highest block-height from _before_ this tip
    pub fn get_previous_block_height(conn: &DBConn, height: u64) -> Result<Option<u64>, db_error> {
        let sql = "SELECT height FROM mempool WHERE height < ?1 ORDER BY height DESC LIMIT 1";
        let args : &[&dyn ToSql] = &[&u64_to_sql(height)?];
        query_row(conn, sql, args)
    }

    /// Get chain tip(s) at a given height that have transactions
    pub fn get_chain_tips_at_height(conn: &DBConn, height: u64) -> Result<Vec<(BurnchainHeaderHash, BlockHeaderHash)>, db_error> {
        let sql = "SELECT burn_header_hash,block_header_hash FROM mempool WHERE height = ?1";
        let args : &[&dyn ToSql] = &[&u64_to_sql(height)?];
        
        let mut stmt = conn.prepare(sql)
            .map_err(db_error::SqliteError)?;

        let mut rows = stmt.query(args)
            .map_err(db_error::SqliteError)?;

        // gather 
        let mut tips = vec![];
        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let burn_header_hash = BurnchainHeaderHash::from_column(&row, "burn_header_hash")?;
                    let block_hash = BlockHeaderHash::from_column(&row, "block_header_hash")?;
                    tips.push((burn_header_hash, block_hash));
                },
                Err(e) => {
                    return Err(db_error::SqliteError(e));
                }
            };
        }

        Ok(tips)
    }

    /// Get a number of transactions after a given timestamp on a given chain tip.
    pub fn get_txs_after(conn: &DBConn, burn_header_hash: &BurnchainHeaderHash, block_header_hash: &BlockHeaderHash, timestamp: u64, count: u64) -> Result<Vec<MemPoolTxInfo>, db_error> {
        let sql = "SELECT * FROM mempool WHERE accept_time >= ?1 AND burn_header_hash = ?2 AND block_header_hash = ?3 ORDER BY estimated_fee DESC LIMIT ?4";
        let args : &[&dyn ToSql] = &[&u64_to_sql(timestamp)?, burn_header_hash, block_header_hash, &u64_to_sql(count)?];
        let rows = query_rows::<MemPoolTxInfo, _>(conn, &sql, args)?;
        Ok(rows)
    }

    /// Get a transaction's metadata in a chain tip, given its origin and sponsor metadata.
    /// Faster than getting the MemPoolTxInfo, since no deserialization will be needed.
    /// Used to see if there exists a transaction with this info, so as to implement replace-by-fee
    fn get_tx_metadata_by_addresses(conn: &DBConn,
                                    origin_address: &StacksAddress,
                                    origin_nonce: u64,
                                    sponsor_address: &StacksAddress,
                                    sponsor_nonce: u64,
                                    burn_header_hash: &BurnchainHeaderHash,
                                    block_header_hash: &BlockHeaderHash) -> Result<Option<MemPoolTxMetadata>, db_error> {
        let sql = "SELECT 
            txid,
            origin_address,
            origin_nonce,
            sponsor_address,
            sponsor_nonce,
            estimated_fee,
            fee_rate,
            length,
            burn_header_hash,
            block_header_hash,
            height,
            accept_time
            FROM mempool WHERE origin_address = ?1 AND origin_nonce = ?2 AND sponsor_address = ?3 AND sponsor_nonce = ?4 AND burn_header_hash = ?5 AND block_header_hash = ?6";
        let args : &[&dyn ToSql] = &[&origin_address.to_string(), &u64_to_sql(origin_nonce)?, &sponsor_address.to_string(), &u64_to_sql(sponsor_nonce)?, burn_header_hash, block_header_hash];
        query_row(conn, sql, args)
    }

    /// Add a transaction to the mempool.  If it already exists, then replace it if the given fee
    /// is higher than the one that's already there.
    /// Carry out the mempool admission test before adding.
    /// Don't call directly; use submit()
    fn try_add_tx<'a>(tx: &mut MemPoolTx<'a>, 
                      burn_header_hash: &BurnchainHeaderHash, 
                      block_header_hash: &BlockHeaderHash, 
                      txid: Txid, 
                      tx_bytes: Vec<u8>, 
                      estimated_fee: u64,
                      fee_rate: u64,
                      height: u64,
                      origin_address: &StacksAddress,
                      origin_nonce: u64,
                      sponsor_address: &StacksAddress,
                      sponsor_nonce: u64) -> Result<(), MemPoolRejection> {

        let length = tx_bytes.len() as u64;

        // replace-by-fee in this chain tip?
        if let Some(tx_metadata) = MemPoolDB::get_tx_metadata_by_addresses(tx, origin_address, origin_nonce, sponsor_address, sponsor_nonce, burn_header_hash, block_header_hash).map_err(MemPoolRejection::DBError)? {
            if estimated_fee < tx_metadata.estimated_fee {
                // we already have a tx from these accounts, and the tx we have has a higher fee
                debug!("Already have a tx from ({},{},{},{}) -- estimated fee {} < {}", origin_address, origin_nonce, sponsor_address, sponsor_nonce, estimated_fee, tx_metadata.estimated_fee);
                return Ok(());
            }
        }

        let sql = "INSERT OR REPLACE INTO mempool (
            txid,
            origin_address,
            origin_nonce,
            sponsor_address,
            sponsor_nonce,
            estimated_fee,
            fee_rate,
            length,
            burn_header_hash,
            block_header_hash,
            height,
            accept_time,
            tx)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

        let args : &[&dyn ToSql] = &[
            &txid, 
            &origin_address.to_string(),
            &u64_to_sql(origin_nonce)?,
            &sponsor_address.to_string(),
            &u64_to_sql(sponsor_nonce)?,
            &u64_to_sql(estimated_fee)?,
            &u64_to_sql(fee_rate)?,
            &u64_to_sql(length)?,
            burn_header_hash,
            block_header_hash,
            &u64_to_sql(height)?,
            &u64_to_sql(get_epoch_time_secs())?,
            &tx_bytes];

        tx.execute(sql, args).map_err(|e| MemPoolRejection::DBError(db_error::SqliteError(e)))?;
        Ok(())
    }

    /// Garbage-collect the mempool.  Remove transactions that have a given number of
    /// confirmations.
    pub fn garbage_collect<'a>(tx: &mut MemPoolTx<'a>, min_height: u64) -> Result<(), db_error> {
        let sql = "DELETE FROM mempool WHERE height < ?1";
        let args : &[&dyn ToSql] = &[&u64_to_sql(min_height)?];

        tx.execute(sql, args).map_err(db_error::SqliteError)?;
        Ok(())
    }

    /// Scan the chain tip for all available transactions (but do not remove them!)
    pub fn poll(&mut self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash) -> Vec<StacksTransaction> {
        test_debug!("Mempool poll at {}/{}", burn_header_hash, block_hash);
        MemPoolDB::get_txs_after(&self.db, burn_header_hash, block_hash, 0, (i64::max_value() - 1) as u64).unwrap_or(vec![])
            .into_iter()
            .map(|tx_info| {
                test_debug!("Mempool poll {} at {}/{}", &tx_info.tx.txid(), burn_header_hash, block_hash);
                tx_info.tx
            })
            .collect()
    }

    /// Submit a transaction to the mempool at a particular chain tip.
    pub fn tx_submit<'a>(mempool_tx: &mut MemPoolTx<'a>, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, tx: StacksTransaction, do_admission_checks: bool) -> Result<(), MemPoolRejection> {
        test_debug!("Mempool submit {} at {}/{}", tx.txid(), burn_header_hash, block_hash);

        let height = match mempool_tx.admitter.chainstate.get_stacks_block_height(burn_header_hash, block_hash) {
            Ok(Some(h)) => h,
            Ok(None) => {
                if *burn_header_hash == FIRST_BURNCHAIN_BLOCK_HASH {
                    0
                }
                else {
                    return Err(MemPoolRejection::NoSuchChainTip(burn_header_hash.clone(), block_hash.clone()));
                }
            },
            Err(e) => {
                return Err(MemPoolRejection::Other(format!("Failed to load chain tip: {:?}", &e)));
            }
        };

        let txid = tx.txid();
        let mut tx_data = vec![];
        tx.consensus_serialize(&mut tx_data).map_err(MemPoolRejection::SerializationFailure)?;

        let len = tx_data.len() as u64;
        let fee_rate = tx.get_fee_rate();
        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let (sponsor_address, sponsor_nonce) = 
            if let (Some(addr), Some(nonce)) = (tx.sponsor_address(), tx.get_sponsor_nonce()) {
                (addr, nonce)
            }
            else{
                (origin_address.clone(), origin_nonce)
            };
        
        // TODO; estimate the true fee using Clarity analysis data.  For now, just do fee_rate
        let estimated_fee = fee_rate.checked_mul(len)
            .ok_or(MemPoolRejection::Other("Fee numeric overflow".to_string()))?;

        if do_admission_checks {
            mempool_tx.admitter.set_block(&block_hash, &burn_header_hash);
            mempool_tx.admitter.will_admit_tx(&tx, len)?;
        }
        
        MemPoolDB::try_add_tx(mempool_tx, &burn_header_hash, &block_hash, txid, tx_data, estimated_fee, fee_rate, height, &origin_address, origin_nonce, &sponsor_address, sponsor_nonce)?;

        Ok(())
    }
   
    /// One-shot submit
    pub fn submit(&mut self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, tx: StacksTransaction) -> Result<(), MemPoolRejection> {
        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;
        MemPoolDB::tx_submit(&mut mempool_tx, burn_header_hash, block_hash, tx, true)?;
        mempool_tx.commit().map_err(MemPoolRejection::DBError)?;
        Ok(())
    }

    /// Directly submit to the mempool, and don't do any admissions checks.
    pub fn submit_raw(&mut self, burn_header_hash: &BurnchainHeaderHash, block_hash: &BlockHeaderHash, tx_bytes: Vec<u8>) -> Result<(), MemPoolRejection> {
        let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).map_err(MemPoolRejection::DeserializationFailure)?;
        
        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;
        MemPoolDB::tx_submit(&mut mempool_tx, burn_header_hash, block_hash, tx, false)?;
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
            },
            Err(e) => {
                warn!("Failed to query txid: {:?}", &e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use vm::{
        database::HeadersDB,
        types::{QualifiedContractIdentifier, PrincipalData},
        Value, ClarityName, ContractName, errors::RuntimeErrorType, errors::Error as ClarityError };
    use chainstate::burn::{VRFSeed, BlockHeaderHash};
    use burnchains::Address;
    use address::AddressHashMode;
    use net::{Error as NetError, StacksMessageCodec};
    use util::{log, secp256k1::*, strings::StacksString, hash::hex_bytes, hash::to_hex, hash::*};

    use chainstate::stacks::{
        StacksBlockHeader,
        Error as ChainstateError,
        db::blocks::MemPoolRejection, db::StacksChainState, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        StacksMicroblockHeader, StacksPrivateKey, TransactionSpendingCondition, TransactionAuth, TransactionVersion,
        StacksPublicKey, TransactionPayload, StacksTransactionSigner,
        TokenTransferMemo, CoinbasePayload, TransactionPostConditionMode, TransactionAnchorMode,
        StacksTransaction, TransactionSmartContract, TransactionContractCall, StacksAddress };

    use util::db::{DBConn, FromRow};
    use super::MemPoolDB;

    use burnchains::BurnchainHeaderHash;
    use chainstate::stacks::test::codec_all_transactions;
    use chainstate::stacks::db::test::chainstate_path;
    use chainstate::stacks::db::test::instantiate_chainstate;

    const FOO_CONTRACT: &'static str = "(define-public (foo) (ok 1))
                                        (define-public (bar (x uint)) (ok x))";
    const SK_1: &'static str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
    const SK_2: &'static str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
    const SK_3: &'static str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

    #[test]
    fn mempool_db_init() {
        let chainstate = instantiate_chainstate(false, 0x80000000, "mempool_db_init");
        let chainstate_path = chainstate_path("mempool_db_init");
        let mempool = MemPoolDB::open(false, 0x80000000, &chainstate_path).unwrap();
    }

    #[test]
    fn mempool_db_load_store_replace_tx() {
        let chainstate = instantiate_chainstate(false, 0x80000000, "mempool_db_load_store_replace_tx");
        let chainstate_path = chainstate_path("mempool_db_load_store_replace_tx");
        let mut mempool = MemPoolDB::open(false, 0x80000000, &chainstate_path).unwrap();

        let mut txs = codec_all_transactions(&TransactionVersion::Testnet, 0x80000000, &TransactionAnchorMode::Any, &TransactionPostConditionMode::Allow);
        let num_txs = txs.len() as u64;

        let mut mempool_tx = mempool.tx_begin().unwrap();

        eprintln!("add all txs");
        for (i, mut tx) in txs.drain(..).enumerate() {
            // make sure each address is unique per tx (not the case in codec_all_transactions)
            let origin_address = StacksAddress { version: 22, bytes: Hash160::from_data(&i.to_be_bytes()) };
            let sponsor_address = StacksAddress { version: 22, bytes: Hash160::from_data(&(i + 1).to_be_bytes()) };

            tx.set_fee_rate(123);

            // test insert
            let txid = tx.txid();
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            let expected_tx = tx.clone();

            let len = tx_bytes.len() as u64;
            let estimated_fee = tx.get_fee_rate() * len;        //TODO: use clarity analysis data to make this estimate
            let height = 100;

            let origin_nonce = tx.get_origin_nonce();
            let sponsor_nonce = match tx.get_sponsor_nonce() {
                Some(n) => n,
                None => origin_nonce
            };

            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            MemPoolDB::try_add_tx(&mut mempool_tx, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x2; 32]), txid, tx_bytes, estimated_fee, tx.get_fee_rate(), height, &origin_address, origin_nonce, &sponsor_address, sponsor_nonce).unwrap();
            
            assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            // test retrieval
            let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
            let tx_info = tx_info_opt.unwrap();

            assert_eq!(tx_info.tx, expected_tx);
            assert_eq!(tx_info.metadata.len, len);
            assert_eq!(tx_info.metadata.estimated_fee, estimated_fee);
            assert_eq!(tx_info.metadata.fee_rate, 123);
            assert_eq!(tx_info.metadata.origin_address, origin_address);
            assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
            assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
            assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
            assert_eq!(tx_info.metadata.burn_header_hash, BurnchainHeaderHash([0x1; 32]));
            assert_eq!(tx_info.metadata.block_header_hash, BlockHeaderHash([0x2; 32]));
            assert_eq!(tx_info.metadata.block_height, height);

            // test replace-by-fee with a higher fee
            let old_txid = txid;

            tx.set_fee_rate(124);
            assert!(txid != tx.txid());

            let txid = tx.txid();
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            let expected_tx = tx.clone();
            let estimated_fee = tx.get_fee_rate() * len;        // TODO: use clarity analysis data to make this estimate
    
            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

            let tx_info_before = MemPoolDB::get_tx_metadata_by_addresses(&mempool_tx, &origin_address, origin_nonce, &sponsor_address, sponsor_nonce, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x2; 32])).unwrap().unwrap();
            assert_eq!(tx_info_before, tx_info.metadata);

            MemPoolDB::try_add_tx(&mut mempool_tx, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x2; 32]), txid, tx_bytes, estimated_fee, tx.get_fee_rate(), height, &origin_address, origin_nonce, &sponsor_address, sponsor_nonce).unwrap();
            
            // was replaced
            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
            assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
            
            let tx_info_after = MemPoolDB::get_tx_metadata_by_addresses(&mempool_tx, &origin_address, origin_nonce, &sponsor_address, sponsor_nonce, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x2; 32])).unwrap().unwrap();
            assert!(tx_info_after != tx_info.metadata);

            // test retrieval -- transaction should have been replaced because it has a higher
            // estimated fee
            let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();

            let tx_info = tx_info_opt.unwrap();
            assert_eq!(tx_info.metadata, tx_info_after);

            assert_eq!(tx_info.tx, expected_tx);
            assert_eq!(tx_info.metadata.len, len);
            assert_eq!(tx_info.metadata.estimated_fee, estimated_fee);
            assert_eq!(tx_info.metadata.fee_rate, 124);
            assert_eq!(tx_info.metadata.origin_address, origin_address);
            assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
            assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
            assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
            assert_eq!(tx_info.metadata.burn_header_hash, BurnchainHeaderHash([0x1; 32]));
            assert_eq!(tx_info.metadata.block_header_hash, BlockHeaderHash([0x2; 32]));
            assert_eq!(tx_info.metadata.block_height, height);

            // test replace-by-fee with a lower fee
            let old_txid = txid;
            
            tx.set_fee_rate(122);
            assert!(txid != tx.txid());
            
            let txid = tx.txid();
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            let expected_tx = tx.clone();
            let estimated_fee = tx.get_fee_rate() * len;        // TODO: use clarity analysis metadata to make this estimate
    
            MemPoolDB::try_add_tx(&mut mempool_tx, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x2; 32]), txid, tx_bytes, estimated_fee, tx.get_fee_rate(), height, &origin_address, origin_nonce, &sponsor_address, sponsor_nonce).unwrap();
            
            // was NOT replaced
            assert!(MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
            assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
        }
        mempool_tx.commit().unwrap();

        eprintln!("get all txs");
        let txs = MemPoolDB::get_txs_after(&mempool.db, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x2; 32]), 0, num_txs).unwrap();
        assert_eq!(txs.len() as u64, num_txs);
        
        eprintln!("get empty txs");
        let txs = MemPoolDB::get_txs_after(&mempool.db, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x3; 32]), 0, num_txs).unwrap();
        assert_eq!(txs.len(), 0);
        
        eprintln!("get empty txs");
        let txs = MemPoolDB::get_txs_after(&mempool.db, &BurnchainHeaderHash([0x2; 32]), &BlockHeaderHash([0x2; 32]), 0, num_txs).unwrap();
        assert_eq!(txs.len(), 0);

        eprintln!("garbage-collect");
        let mut mempool_tx = mempool.tx_begin().unwrap();
        MemPoolDB::garbage_collect(&mut mempool_tx, 101).unwrap();
        mempool_tx.commit().unwrap();
        
        let txs = MemPoolDB::get_txs_after(&mempool.db, &BurnchainHeaderHash([0x1; 32]), &BlockHeaderHash([0x2; 32]), 0, num_txs).unwrap();
        assert_eq!(txs.len(), 0);
    }
}
