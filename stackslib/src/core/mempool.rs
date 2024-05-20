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

use std::cmp::{self, Ordering};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hasher;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Instant;
use std::{fs, io};

use clarity::vm::types::PrincipalData;
use rand::distributions::Uniform;
use rand::prelude::Distribution;
use rusqlite::types::ToSql;
use rusqlite::{
    Connection, Error as SqliteError, OpenFlags, OptionalExtension, Row, Rows, Transaction,
    NO_PARAMS,
};
use siphasher::sip::SipHasher; // this is SipHash-2-4
use stacks_common::codec::{
    read_next, write_next, Error as codec_error, StacksMessageCodec, MAX_MESSAGE_LEN,
};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksAddress, StacksBlockId};
use stacks_common::util::hash::{to_hex, Sha512Trunc256Sum};
use stacks_common::util::retry::{BoundReader, RetryReader};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};

use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::blocks::MemPoolRejection;
use crate::chainstate::stacks::db::{ClarityTx, StacksChainState};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::index::Error as MarfError;
use crate::chainstate::stacks::miner::TransactionEvent;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, StacksMicroblock, StacksTransaction, TransactionPayload,
};
use crate::clarity_vm::clarity::ClarityConnection;
use crate::core::{
    ExecutionCost, StacksEpochId, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use crate::cost_estimates::metrics::{CostMetric, UnitMetric};
use crate::cost_estimates::{CostEstimator, EstimatorError, UnitEstimator};
use crate::monitoring::increment_stx_mempool_gc;
use crate::net::api::postblock_proposal::{BlockValidateOk, BlockValidateReject};
use crate::net::Error as net_error;
use crate::util_lib::bloom::{BloomCounter, BloomFilter, BloomNodeHasher};
use crate::util_lib::db::{
    query_int, query_row, query_row_columns, query_rows, sql_pragma, sqlite_open, table_exists,
    tx_begin_immediate, tx_busy_handler, u64_to_sql, DBConn, DBTx, Error as db_error, Error,
    FromColumn, FromRow,
};
use crate::{cost_estimates, monitoring};

// maximum number of confirmations a transaction can have before it's garbage-collected
pub const MEMPOOL_MAX_TRANSACTION_AGE: u64 = 256;
pub const MAXIMUM_MEMPOOL_TX_CHAINING: u64 = 25;

// name of table for storing the counting bloom filter
pub const BLOOM_COUNTER_TABLE: &'static str = "txid_bloom_counter";

// bloom filter error rate
pub const BLOOM_COUNTER_ERROR_RATE: f64 = 0.001;

// expected number of txs in the bloom filter
pub const MAX_BLOOM_COUNTER_TXS: u32 = 8192;

// how far back in time (in Stacks blocks) does the bloom counter maintain tx records?
pub const BLOOM_COUNTER_DEPTH: usize = 2;

// how long will a transaction be blacklisted?
// about as long as it takes for it to be garbage-collected
pub const DEFAULT_BLACKLIST_TIMEOUT: u64 = 24 * 60 * 60 * 2;
pub const DEFAULT_BLACKLIST_MAX_SIZE: u64 = 134217728; // 2**27 -- the blacklist table can reach at most 4GB at 128 bytes per record

// maximum many tx tags we'll send before sending a bloom filter instead.
// The parameter choice here is due to performance -- calculating a tag set can be slower than just
// loading the bloom filter, even though the bloom filter is larger.
const DEFAULT_MAX_TX_TAGS: u32 = 2048;

/// A node-specific transaction tag -- the first 8 bytes of siphash(local-seed,txid)
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct TxTag(pub [u8; 8]);

impl TxTag {
    pub fn from(seed: &[u8], txid: &Txid) -> TxTag {
        let mut hasher = SipHasher::new();
        hasher.write(seed);
        hasher.write(&txid.0);

        let result_64 = hasher.finish();
        TxTag(result_64.to_be_bytes())
    }
}

impl std::fmt::Display for TxTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", &to_hex(&self.0))
    }
}

impl StacksMessageCodec for TxTag {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        fd.write_all(&self.0).map_err(codec_error::WriteError)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TxTag, codec_error> {
        let mut bytes = [0u8; 8];
        fd.read_exact(&mut bytes).map_err(codec_error::ReadError)?;
        Ok(TxTag(bytes))
    }
}

define_u8_enum!(MemPoolSyncDataID {
    BloomFilter = 0x01,
    TxTags = 0x02
});

#[derive(Debug, Clone, PartialEq)]
pub enum MemPoolSyncData {
    BloomFilter(BloomFilter<BloomNodeHasher>),
    TxTags([u8; 32], Vec<TxTag>),
}

impl StacksMessageCodec for MemPoolSyncData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            MemPoolSyncData::BloomFilter(ref bloom_filter) => {
                write_next(fd, &MemPoolSyncDataID::BloomFilter.to_u8())?;
                write_next(fd, bloom_filter)?;
            }
            MemPoolSyncData::TxTags(ref seed, ref tags) => {
                write_next(fd, &MemPoolSyncDataID::TxTags.to_u8())?;
                write_next(fd, seed)?;
                write_next(fd, tags)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<MemPoolSyncData, codec_error> {
        let data_id: u8 = read_next(fd)?;
        match MemPoolSyncDataID::from_u8(data_id).ok_or(codec_error::DeserializeError(format!(
            "Unrecognized MemPoolSyncDataID {}",
            &data_id
        )))? {
            MemPoolSyncDataID::BloomFilter => {
                let bloom_filter: BloomFilter<BloomNodeHasher> = read_next(fd)?;
                Ok(MemPoolSyncData::BloomFilter(bloom_filter))
            }
            MemPoolSyncDataID::TxTags => {
                let seed: [u8; 32] = read_next(fd)?;
                let txtags: Vec<TxTag> = read_next(fd)?;
                Ok(MemPoolSyncData::TxTags(seed, txtags))
            }
        }
    }
}

/// Read the trailing page ID from a transaction stream
fn parse_mempool_query_page_id<R: Read>(
    pos: usize,
    retry_reader: &mut RetryReader<'_, R>,
) -> Result<Option<Txid>, net_error> {
    // possibly end-of-transactions, in which case, the last 32 bytes should be
    // a page ID.  Expect end-of-stream after this.
    retry_reader.set_position(pos);
    let next_page: Txid = match read_next(retry_reader) {
        Ok(txid) => txid,
        Err(e) => match e {
            codec_error::ReadError(ref ioe) => match ioe.kind() {
                io::ErrorKind::UnexpectedEof => {
                    if pos == retry_reader.position() {
                        // this is fine -- the node didn't get another page
                        return Ok(None);
                    } else {
                        // partial data -- corrupt stream
                        test_debug!("Unexpected EOF: {} != {}", pos, retry_reader.position());
                        return Err(e.into());
                    }
                }
                _ => {
                    return Err(e.into());
                }
            },
            e => {
                return Err(e.into());
            }
        },
    };

    test_debug!("Read page_id {:?}", &next_page);
    Ok(Some(next_page))
}

/// Decode a transaction stream, returned from /v2/mempool/query.
/// The wire format is a list of transactions (no SIP-003 length prefix), followed by an
/// optional 32-byte page ID.  Obtain both the transactions and page ID, if it exists.
pub fn decode_tx_stream<R: Read>(
    fd: &mut R,
) -> Result<(Vec<StacksTransaction>, Option<Txid>), net_error> {
    // The wire format is `tx, tx, tx, tx, .., tx, txid`.
    // The last 32 bytes are the page ID for the next mempool query.
    // NOTE: there will be no length prefix on this.
    let mut txs: Vec<StacksTransaction> = vec![];
    let mut bound_reader = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
    let mut retry_reader = RetryReader::new(&mut bound_reader);
    let mut page_id = None;
    let mut expect_eof = false;

    loop {
        let pos = retry_reader.position();
        let next_msg: Result<StacksTransaction, _> = read_next(&mut retry_reader);
        match next_msg {
            Ok(tx) => {
                if expect_eof {
                    // this should have failed
                    test_debug!("Expected EOF; got transaction {}", tx.txid());
                    return Err(net_error::ExpectedEndOfStream);
                }

                test_debug!("Read transaction {}", tx.txid());
                txs.push(tx);
                Ok(())
            }
            Err(e) => match e {
                codec_error::ReadError(ref ioe) => match ioe.kind() {
                    io::ErrorKind::UnexpectedEof => {
                        if expect_eof {
                            if pos != retry_reader.position() {
                                // read partial data. The stream is corrupt.
                                test_debug!(
                                    "Expected EOF; stream advanced from {} to {}",
                                    pos,
                                    retry_reader.position()
                                );
                                return Err(net_error::ExpectedEndOfStream);
                            }
                        } else {
                            // couldn't read a full transaction.  This is possibly a page ID, whose
                            // 32 bytes decode to the prefix of a well-formed transaction.
                            test_debug!("Try to read page ID trailer after ReadError");
                            page_id = parse_mempool_query_page_id(pos, &mut retry_reader)?;
                        }
                        break;
                    }
                    _ => Err(e),
                },
                codec_error::DeserializeError(_msg) => {
                    if expect_eof {
                        // this should have failed due to EOF
                        test_debug!("Expected EOF; got DeserializeError '{}'", &_msg);
                        return Err(net_error::ExpectedEndOfStream);
                    }

                    // failed to parse a transaction.  This is possibly a page ID.
                    test_debug!("Try to read page ID trailer after ReadError");
                    page_id = parse_mempool_query_page_id(pos, &mut retry_reader)?;

                    // do one more pass to make sure we're actually end-of-stream.
                    // otherwise, the stream itself was corrupt, since any 32 bytes is a valid
                    // txid and the presence of more bytes means that we simply got a bad tx
                    // that we couldn't decode.
                    expect_eof = true;
                    Ok(())
                }
                _ => Err(e),
            },
        }?;
    }

    Ok((txs, page_id))
}

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
        sortdb: &SortitionDB,
        tx: &StacksTransaction,
        tx_size: u64,
    ) -> Result<(), MemPoolRejection> {
        chainstate.will_admit_mempool_tx(
            &sortdb.index_conn(),
            &self.cur_consensus_hash,
            &self.cur_block,
            tx,
            tx_size,
        )
    }
}

pub enum MemPoolDropReason {
    REPLACE_ACROSS_FORK,
    REPLACE_BY_FEE,
    STALE_COLLECT,
    TOO_EXPENSIVE,
    PROBLEMATIC,
}

pub struct ConsiderTransaction {
    /// Transaction to consider in block assembly
    pub tx: MemPoolTxInfo,
    /// If `update_estimator` is set, the iteration should update the estimator
    /// after considering the tx.
    pub update_estimate: bool,
}

enum ConsiderTransactionResult {
    NoTransactions,
    UpdateNonces(Vec<StacksAddress>),
    /// This transaction should be considered for inclusion in the block.
    Consider(ConsiderTransaction),
}

impl std::fmt::Display for MemPoolDropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemPoolDropReason::STALE_COLLECT => write!(f, "StaleGarbageCollect"),
            MemPoolDropReason::TOO_EXPENSIVE => write!(f, "TooExpensive"),
            MemPoolDropReason::REPLACE_ACROSS_FORK => write!(f, "ReplaceAcrossFork"),
            MemPoolDropReason::REPLACE_BY_FEE => write!(f, "ReplaceByFee"),
            MemPoolDropReason::PROBLEMATIC => write!(f, "Problematic"),
        }
    }
}

pub trait ProposalCallbackReceiver: Send {
    fn notify_proposal_result(&self, result: Result<BlockValidateOk, BlockValidateReject>);
}

pub trait MemPoolEventDispatcher {
    fn get_proposal_callback_receiver(&self) -> Option<Box<dyn ProposalCallbackReceiver>>;
    fn mempool_txs_dropped(&self, txids: Vec<Txid>, reason: MemPoolDropReason);
    fn mined_block_event(
        &self,
        target_burn_height: u64,
        block: &StacksBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        confirmed_microblock_cost: &ExecutionCost,
        tx_results: Vec<TransactionEvent>,
    );
    fn mined_microblock_event(
        &self,
        microblock: &StacksMicroblock,
        tx_results: Vec<TransactionEvent>,
        anchor_block_consensus_hash: ConsensusHash,
        anchor_block: BlockHeaderHash,
    );
    fn mined_nakamoto_block_event(
        &self,
        target_burn_height: u64,
        block: &NakamotoBlock,
        block_size_bytes: u64,
        consumed: &ExecutionCost,
        tx_results: Vec<TransactionEvent>,
    );
}

#[derive(Debug, PartialEq, Clone)]
pub struct MemPoolTxInfo {
    pub tx: StacksTransaction,
    pub metadata: MemPoolTxMetadata,
}

/// This class is a minimal version of `MemPoolTxInfo`. It contains
/// just enough information to 1) filter by nonce readiness, 2) sort by fee rate.
#[derive(Debug, Clone)]
pub struct MemPoolTxInfoPartial {
    pub txid: Txid,
    pub fee_rate: Option<f64>,
    pub origin_address: StacksAddress,
    pub origin_nonce: u64,
    pub sponsor_address: StacksAddress,
    pub sponsor_nonce: u64,
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
    pub last_known_origin_nonce: Option<u64>,
    pub last_known_sponsor_nonce: Option<u64>,
    pub accept_time: u64,
}

impl MemPoolTxMetadata {
    pub fn get_unknown_nonces(&self) -> Vec<StacksAddress> {
        let mut needs_nonces = vec![];
        if self.last_known_origin_nonce.is_none() {
            needs_nonces.push(self.origin_address);
        }
        if self.last_known_sponsor_nonce.is_none() {
            needs_nonces.push(self.sponsor_address);
        }
        needs_nonces
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemPoolWalkTxTypes {
    TokenTransfer,
    SmartContract,
    ContractCall,
}

impl FromStr for MemPoolWalkTxTypes {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TokenTransfer" => {
                return Ok(Self::TokenTransfer);
            }
            "SmartContract" => {
                return Ok(Self::SmartContract);
            }
            "ContractCall" => {
                return Ok(Self::ContractCall);
            }
            _ => {
                return Err("Unknown mempool tx walk type");
            }
        }
    }
}

impl MemPoolWalkTxTypes {
    pub fn all() -> HashSet<MemPoolWalkTxTypes> {
        [
            MemPoolWalkTxTypes::TokenTransfer,
            MemPoolWalkTxTypes::SmartContract,
            MemPoolWalkTxTypes::ContractCall,
        ]
        .into_iter()
        .collect()
    }

    pub fn only(selected: &[MemPoolWalkTxTypes]) -> HashSet<MemPoolWalkTxTypes> {
        selected.iter().map(|x| x.clone()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct MemPoolWalkSettings {
    /// Maximum amount of time a miner will spend walking through mempool transactions, in
    /// milliseconds.  This is a soft deadline.
    pub max_walk_time_ms: u64,
    /// Probability percentage to consider a transaction which has not received a cost estimate.
    /// That is, with x%, when picking the next transaction to include a block, select one that
    /// either failed to get a cost estimate or has not been estimated yet.
    pub consider_no_estimate_tx_prob: u8,
    /// Size of the nonce cache. This avoids MARF look-ups.
    pub nonce_cache_size: u64,
    /// Size of the candidate cache. These are the candidates that will be retried after each
    /// transaction is mined.
    pub candidate_retry_cache_size: u64,
    /// Types of transactions we'll consider
    pub txs_to_consider: HashSet<MemPoolWalkTxTypes>,
    /// Origins for transactions that we'll consider
    pub filter_origins: HashSet<StacksAddress>,
}

impl MemPoolWalkSettings {
    pub fn default() -> MemPoolWalkSettings {
        MemPoolWalkSettings {
            max_walk_time_ms: u64::MAX,
            consider_no_estimate_tx_prob: 5,
            nonce_cache_size: 1024 * 1024,
            candidate_retry_cache_size: 64 * 1024,
            txs_to_consider: [
                MemPoolWalkTxTypes::TokenTransfer,
                MemPoolWalkTxTypes::SmartContract,
                MemPoolWalkTxTypes::ContractCall,
            ]
            .into_iter()
            .collect(),
            filter_origins: HashSet::new(),
        }
    }
    pub fn zero() -> MemPoolWalkSettings {
        MemPoolWalkSettings {
            max_walk_time_ms: u64::MAX,
            consider_no_estimate_tx_prob: 5,
            nonce_cache_size: 1024 * 1024,
            candidate_retry_cache_size: 64 * 1024,
            txs_to_consider: [
                MemPoolWalkTxTypes::TokenTransfer,
                MemPoolWalkTxTypes::SmartContract,
                MemPoolWalkTxTypes::ContractCall,
            ]
            .into_iter()
            .collect(),
            filter_origins: HashSet::new(),
        }
    }
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
        let block_height = u64::from_column(row, "height")?;
        let len = u64::from_column(row, "length")?;
        let accept_time = u64::from_column(row, "accept_time")?;
        let origin_address = StacksAddress::from_column(row, "origin_address")?;
        let origin_nonce = u64::from_column(row, "origin_nonce")?;
        let sponsor_address = StacksAddress::from_column(row, "sponsor_address")?;
        let sponsor_nonce = u64::from_column(row, "sponsor_nonce")?;
        let last_known_sponsor_nonce = u64::from_column(row, "last_known_sponsor_nonce")?;
        let last_known_origin_nonce = u64::from_column(row, "last_known_origin_nonce")?;

        Ok(MemPoolTxMetadata {
            txid,
            len,
            tx_fee,
            consensus_hash,
            block_header_hash,
            block_height,
            origin_address,
            origin_nonce,
            sponsor_address,
            sponsor_nonce,
            last_known_origin_nonce,
            last_known_sponsor_nonce,
            accept_time,
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

impl FromRow<MemPoolTxInfoPartial> for MemPoolTxInfoPartial {
    fn from_row<'a>(row: &'a Row) -> Result<MemPoolTxInfoPartial, db_error> {
        let txid = Txid::from_column(row, "txid")?;
        let fee_rate: Option<f64> = match row.get("fee_rate") {
            Ok(rate) => Some(rate),
            Err(_) => None,
        };
        let origin_address = StacksAddress::from_column(row, "origin_address")?;
        let origin_nonce = u64::from_column(row, "origin_nonce")?;
        let sponsor_address = StacksAddress::from_column(row, "sponsor_address")?;
        let sponsor_nonce = u64::from_column(row, "sponsor_nonce")?;

        Ok(MemPoolTxInfoPartial {
            txid,
            fee_rate,
            origin_address,
            origin_nonce,
            sponsor_address,
            sponsor_nonce,
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

const MEMPOOL_INITIAL_SCHEMA: &'static [&'static str] = &[r#"
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
    "#];

const MEMPOOL_SCHEMA_2_COST_ESTIMATOR: &'static [&'static str] = &[
    r#"
    CREATE TABLE fee_estimates(
        txid TEXT NOT NULL,
        fee_rate NUMBER,
        PRIMARY KEY (txid),
        FOREIGN KEY (txid) REFERENCES mempool (txid) ON DELETE CASCADE ON UPDATE CASCADE
    );
    "#,
    // The `last_known_*_nonce` columns are no longer used, beginning in schema 6,
    // in favor of a separate `nonces` table and an in-memory cache.
    r#"
    ALTER TABLE mempool ADD COLUMN last_known_origin_nonce INTEGER;
    "#,
    r#"
    ALTER TABLE mempool ADD COLUMN last_known_sponsor_nonce INTEGER;
    "#,
    r#"
    CREATE TABLE schema_version (version NUMBER, PRIMARY KEY (version));
    "#,
    r#"
    INSERT INTO schema_version (version) VALUES (2)
    "#,
];

const MEMPOOL_SCHEMA_3_BLOOM_STATE: &'static [&'static str] = &[
    r#"
    CREATE TABLE IF NOT EXISTS removed_txids(
        txid TEXT PRIMARY KEY NOT NULL,
        FOREIGN KEY(txid) REFERENCES mempool(txid) ON DELETE CASCADE
    );
    "#,
    r#"
    -- mapping between hash(local-seed,txid) and txid, used for randomized but efficient
    -- paging when streaming transactions out of the mempool.
    CREATE TABLE IF NOT EXISTS randomized_txids(
        txid TEXT PRIMARY KEY NOT NULL,
        hashed_txid TEXT NOT NULL,
        FOREIGN KEY(txid) REFERENCES mempool(txid) ON DELETE CASCADE
    );
    "#,
    r#"
    INSERT INTO schema_version (version) VALUES (3)
    "#,
];

const MEMPOOL_SCHEMA_4_BLACKLIST: &'static [&'static str] = &[
    r#"
    -- List of transactions that will never be stored to the mempool again, for as long as the rows exist.
    -- `arrival_time` indicates when the entry was created. This is used to garbage-collect the list.
    -- A transaction that is blacklisted may still be served from the mempool, but it will never be (re)submitted.
    CREATE TABLE IF NOT EXISTS tx_blacklist(
        txid TEXT PRIMARY KEY NOT NULL,
        arrival_time INTEGER NOT NULL
    );
    "#,
    r#"
    -- Count the number of entries in the blacklist
    CREATE TABLE IF NOT EXISTS tx_blacklist_size(
        size INTEGER NOT NULL
    );
    "#,
    r#"
    -- Maintain a count of the size of the blacklist
    CREATE TRIGGER IF NOT EXISTS tx_blacklist_size_inc
    AFTER INSERT ON tx_blacklist
    BEGIN
        UPDATE tx_blacklist_size SET size = size + 1;
    END
    "#,
    r#"
    CREATE TRIGGER IF NOT EXISTS tx_blacklist_size_dec
    AFTER DELETE ON tx_blacklist
    BEGIN
        UPDATE tx_blacklist_size SET size = size - 1;
    END
    "#,
    r#"
    INSERT INTO tx_blacklist_size (size) VALUES (0)
    "#,
    r#"
    INSERT INTO schema_version (version) VALUES (4)
    "#,
];

const MEMPOOL_SCHEMA_5: &'static [&'static str] = &[
    r#"
    ALTER TABLE mempool ADD COLUMN fee_rate NUMBER;
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS by_fee_rate ON mempool(fee_rate);
    "#,
    r#"
    UPDATE mempool
    SET fee_rate = (SELECT f.fee_rate FROM fee_estimates as f WHERE f.txid = mempool.txid);
    "#,
    r#"
    INSERT INTO schema_version (version) VALUES (5)
    "#,
];

const MEMPOOL_SCHEMA_6_NONCES: &'static [&'static str] = &[
    r#"
    CREATE TABLE nonces(
        address TEXT PRIMARY KEY NOT NULL,
        nonce INTEGER NOT NULL
    );
    "#,
    r#"
    INSERT INTO schema_version (version) VALUES (6)
    "#,
];

const MEMPOOL_INDEXES: &'static [&'static str] = &[
    "CREATE INDEX IF NOT EXISTS by_txid ON mempool(txid);",
    "CREATE INDEX IF NOT EXISTS by_height ON mempool(height);",
    "CREATE INDEX IF NOT EXISTS by_txid_and_height ON mempool(txid,height);",
    "CREATE INDEX IF NOT EXISTS by_sponsor ON mempool(sponsor_address, sponsor_nonce);",
    "CREATE INDEX IF NOT EXISTS by_origin ON mempool(origin_address, origin_nonce);",
    "CREATE INDEX IF NOT EXISTS by_timestamp ON mempool(accept_time);",
    "CREATE INDEX IF NOT EXISTS by_chaintip ON mempool(consensus_hash,block_header_hash);",
    "CREATE INDEX IF NOT EXISTS fee_by_txid ON fee_estimates(txid);",
    "CREATE INDEX IF NOT EXISTS by_ordered_hashed_txid ON randomized_txids(hashed_txid ASC);",
    "CREATE INDEX IF NOT EXISTS by_hashed_txid ON randomized_txids(txid,hashed_txid);",
    "CREATE INDEX IF NOT EXISTS by_arrival_time_desc ON tx_blacklist(arrival_time DESC);",
];

pub struct MemPoolDB {
    pub db: DBConn,
    path: String,
    admitter: MemPoolAdmitter,
    bloom_counter: BloomCounter<BloomNodeHasher>,
    max_tx_tags: u32,
    cost_estimator: Box<dyn CostEstimator>,
    metric: Box<dyn CostMetric>,
    pub blacklist_timeout: u64,
    pub blacklist_max_size: u64,
}

pub struct MemPoolTx<'a> {
    tx: DBTx<'a>,
    admitter: &'a mut MemPoolAdmitter,
    bloom_counter: Option<&'a mut BloomCounter<BloomNodeHasher>>,
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
    pub fn new(
        tx: DBTx<'a>,
        admitter: &'a mut MemPoolAdmitter,
        bloom_counter: &'a mut BloomCounter<BloomNodeHasher>,
    ) -> MemPoolTx<'a> {
        MemPoolTx {
            tx,
            admitter,
            bloom_counter: Some(bloom_counter),
        }
    }

    pub fn with_bloom_state<F, R>(tx: &mut MemPoolTx<'a>, f: F) -> R
    where
        F: FnOnce(&mut DBTx<'a>, &mut BloomCounter<BloomNodeHasher>) -> R,
    {
        let mut bc = tx
            .bloom_counter
            .take()
            .expect("BUG: did not replace bloom filter");
        let res = f(&mut tx.tx, &mut bc);
        tx.bloom_counter.replace(bc);
        res
    }

    pub fn commit(self) -> Result<(), db_error> {
        self.tx.commit().map_err(db_error::SqliteError)
    }

    /// Remove all txids at the given height from the bloom counter.
    /// Used to clear out txids that are now outside the bloom counter's depth.
    fn prune_bloom_counter(&mut self, target_height: u64) -> Result<(), MemPoolRejection> {
        let sql = "SELECT a.txid FROM mempool AS a LEFT OUTER JOIN removed_txids AS b ON a.txid = b.txid WHERE b.txid IS NULL AND a.height = ?1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(target_height)?];
        let txids: Vec<Txid> = query_rows(&self.tx, sql, args)?;
        let _num_txs = txids.len();

        test_debug!("Prune bloom counter from height {}", target_height);

        // keep borrow-checker happy
        MemPoolTx::with_bloom_state(self, |ref mut dbtx, ref mut bloom_counter| {
            for txid in txids.into_iter() {
                bloom_counter.remove_raw(dbtx, &txid.0)?;

                let sql = "INSERT OR REPLACE INTO removed_txids (txid) VALUES (?1)";
                let args: &[&dyn ToSql] = &[&txid];
                dbtx.execute(sql, args).map_err(db_error::SqliteError)?;
            }
            // help the type inference out
            let res: Result<(), db_error> = Ok(());
            res
        })?;

        test_debug!(
            "Pruned bloom filter at height {}: removed {} txs",
            target_height,
            _num_txs
        );
        Ok(())
    }

    /// Add the txid to the bloom counter in the mempool DB, optionally replacing a prior
    /// transaction (identified by prior_txid) if the bloom counter is full.
    /// If this is the first txid at this block height, then also garbage-collect the bloom counter to remove no-longer-recent transactions.
    /// If the bloom counter is saturated -- i.e. it represents more than MAX_BLOOM_COUNTER_TXS
    /// transactions -- then pick another transaction to evict from the bloom filter and return its txid.
    /// (Note that no transactions are ever removed from the mempool; we just don't prioritize them
    /// in the bloom filter).
    fn update_bloom_counter(
        &mut self,
        height: u64,
        txid: &Txid,
        prior_txid: Option<Txid>,
    ) -> Result<Option<Txid>, MemPoolRejection> {
        // is this the first-ever txid at this height?
        let sql = "SELECT 1 FROM mempool WHERE height = ?1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(height)?];
        let present: Option<i64> = query_row(&self.tx, sql, args)?;
        if present.is_none() && height > (BLOOM_COUNTER_DEPTH as u64) {
            // this is the first-ever tx at this height.
            // which means, the bloom filter window has advanced.
            // which means, we need to remove all the txs that are now out of the window.
            self.prune_bloom_counter(height - (BLOOM_COUNTER_DEPTH as u64))?;
        }

        MemPoolTx::with_bloom_state(self, |ref mut dbtx, ref mut bloom_counter| {
            // remove replaced transaction
            if let Some(prior_txid) = prior_txid {
                bloom_counter.remove_raw(dbtx, &prior_txid.0)?;
            }

            // keep the bloom counter un-saturated -- remove at most one transaction from it to keep
            // the error rate at or below the target error rate
            let evict_txid = {
                let num_recents = MemPoolDB::get_num_recent_txs(&dbtx)?;
                if num_recents >= MAX_BLOOM_COUNTER_TXS.into() {
                    // remove lowest-fee tx (they're paying the least, so replication is
                    // deprioritized)
                    let sql = "SELECT a.txid FROM mempool AS a LEFT OUTER JOIN removed_txids AS b ON a.txid = b.txid WHERE b.txid IS NULL AND a.height > ?1 ORDER BY a.tx_fee ASC LIMIT 1";
                    let args: &[&dyn ToSql] = &[&u64_to_sql(
                        height.saturating_sub(BLOOM_COUNTER_DEPTH as u64),
                    )?];
                    let evict_txid: Option<Txid> = query_row(&dbtx, sql, args)?;
                    if let Some(evict_txid) = evict_txid {
                        bloom_counter.remove_raw(dbtx, &evict_txid.0)?;

                        let sql = "INSERT OR REPLACE INTO removed_txids (txid) VALUES (?1)";
                        let args: &[&dyn ToSql] = &[&evict_txid];
                        dbtx.execute(sql, args).map_err(db_error::SqliteError)?;

                        Some(evict_txid)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            // finally add the new transaction
            bloom_counter.insert_raw(dbtx, &txid.0)?;
            Ok(evict_txid)
        })
    }

    /// Add the txid to our randomized page order
    fn update_mempool_pager(&mut self, txid: &Txid) -> Result<(), MemPoolRejection> {
        let mut randomized_buff = self
            .bloom_counter
            .as_ref()
            .expect("BUG: did not instantiate bloom counter in mempool tx")
            .get_seed()
            .to_vec();
        randomized_buff.extend_from_slice(&txid.0);
        let hashed_txid = Txid(Sha512Trunc256Sum::from_data(&randomized_buff).0);

        let sql = "INSERT OR REPLACE INTO randomized_txids (txid,hashed_txid) VALUES (?1,?2)";
        let args: &[&dyn ToSql] = &[txid, &hashed_txid];

        self.execute(sql, args).map_err(db_error::SqliteError)?;

        Ok(())
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
            txid,
            len: tx_data.len() as u64,
            tx_fee: tx.get_tx_fee(),
            consensus_hash,
            block_header_hash,
            block_height,
            origin_address,
            origin_nonce,
            sponsor_address,
            sponsor_nonce,
            accept_time: get_epoch_time_secs(),
            last_known_origin_nonce: None,
            last_known_sponsor_nonce: None,
        };
        MemPoolTxInfo { tx, metadata }
    }
}

/// Used to locally cache nonces to avoid repeatedly looking them up in the nonce.
struct NonceCache {
    cache: HashMap<StacksAddress, u64>,
    /// The maximum size that this cache can be.
    max_cache_size: usize,
}

impl NonceCache {
    fn new(nonce_cache_size: u64) -> Self {
        let max_size: usize = nonce_cache_size
            .try_into()
            .expect("Could not cast `nonce_cache_size` as `usize`.");
        Self {
            cache: HashMap::new(),
            max_cache_size: max_size,
        }
    }

    /// Get a nonce from the cache.
    /// First, the RAM cache will be checked for this address.
    /// If absent, then the `nonces` table will be queried for this address.
    /// If absent, then the MARF will be queried for this address.
    ///
    /// If not in RAM, the nonce will be opportunistically stored to the `nonces` table.  If that
    /// fails due to lock contention, then the method will return `true` for its second tuple argument.
    ///
    /// Returns (nonce, should-try-store-again?)
    fn get<C>(
        &mut self,
        address: &StacksAddress,
        clarity_tx: &mut C,
        mempool_db: &DBConn,
    ) -> (u64, bool)
    where
        C: ClarityConnection,
    {
        #[cfg(test)]
        assert!(self.cache.len() <= self.max_cache_size);

        // Check in-memory cache
        match self.cache.get(address) {
            Some(nonce) => (*nonce, false),
            None => {
                // Check sqlite cache
                let opt_nonce = match db_get_nonce(mempool_db, address) {
                    Ok(opt_nonce) => opt_nonce,
                    Err(e) => {
                        warn!("error retrieving nonce from mempool db: {}", e);
                        None
                    }
                };
                match opt_nonce {
                    Some(nonce) => {
                        // Copy this into the in-memory cache if there is space
                        if self.cache.len() < self.max_cache_size {
                            self.cache.insert(address.clone(), nonce);
                        }
                        (nonce, false)
                    }
                    None => {
                        let nonce =
                            StacksChainState::get_nonce(clarity_tx, &address.clone().into());

                        let should_store_again = match db_set_nonce(mempool_db, address, nonce) {
                            Ok(_) => false,
                            Err(e) => {
                                debug!("error caching nonce to sqlite: {}", e);
                                true
                            }
                        };

                        if self.cache.len() < self.max_cache_size {
                            self.cache.insert(address.clone(), nonce);
                        }
                        (nonce, should_store_again)
                    }
                }
            }
        }
    }

    /// Store the (address, nonce) pair to the `nonces` table.
    /// If storage fails, return false.
    /// Otherwise return true.
    fn update(&mut self, address: StacksAddress, value: u64, mempool_db: &DBConn) -> bool {
        // Sqlite cache
        let success = match db_set_nonce(mempool_db, &address, value) {
            Ok(_) => true,
            Err(e) => {
                warn!("error caching nonce to sqlite: {}", e);
                false
            }
        };

        // In-memory cache
        match self.cache.get_mut(&address) {
            Some(nonce) => {
                *nonce = value;
            }
            None => (),
        }

        success
    }
}

fn db_set_nonce(conn: &DBConn, address: &StacksAddress, nonce: u64) -> Result<(), db_error> {
    let addr_str = address.to_string();
    let nonce_i64 = u64_to_sql(nonce)?;

    let sql = "INSERT OR REPLACE INTO nonces (address, nonce) VALUES (?1, ?2)";
    conn.execute(sql, rusqlite::params![&addr_str, nonce_i64])?;
    Ok(())
}

fn db_get_nonce(conn: &DBConn, address: &StacksAddress) -> Result<Option<u64>, db_error> {
    let addr_str = address.to_string();

    let sql = "SELECT nonce FROM nonces WHERE address = ?";
    query_row(conn, sql, rusqlite::params![&addr_str])
}

#[cfg(test)]
pub fn db_get_all_nonces(conn: &DBConn) -> Result<Vec<(StacksAddress, u64)>, db_error> {
    let sql = "SELECT * FROM nonces";
    let mut stmt = conn.prepare(&sql).map_err(|e| db_error::SqliteError(e))?;
    let mut iter = stmt
        .query(NO_PARAMS)
        .map_err(|e| db_error::SqliteError(e))?;
    let mut ret = vec![];
    while let Ok(Some(row)) = iter.next() {
        let addr = StacksAddress::from_column(row, "address")?;
        let nonce = u64::from_column(row, "nonce")?;
        ret.push((addr, nonce));
    }
    Ok(ret)
}

/// Cache potential candidate transactions for subsequent iterations.
/// While walking the mempool, transactions that have nonces that are too high
/// to process yet (but could be processed in the future) are added to `next`.
/// In the next pass, `next` is moved to `cache` and these transactions are
/// checked before reading more from the mempool DB.
struct CandidateCache {
    cache: VecDeque<MemPoolTxInfoPartial>,
    next: VecDeque<MemPoolTxInfoPartial>,
    /// The maximum size that this cache can be.
    max_cache_size: usize,
}

impl CandidateCache {
    fn new(candidate_retry_cache_size: u64) -> Self {
        let max_size: usize = candidate_retry_cache_size
            .try_into()
            .expect("Could not cast `candidate_retry_cache_size` as usize.");
        Self {
            cache: VecDeque::new(),
            next: VecDeque::new(),
            max_cache_size: max_size,
        }
    }

    /// Retrieve the next candidate transaction from the cache.
    fn next(&mut self) -> Option<MemPoolTxInfoPartial> {
        self.cache.pop_front()
    }

    /// Push a candidate to the cache for the next iteration.
    fn push(&mut self, tx: MemPoolTxInfoPartial) {
        if self.next.len() < self.max_cache_size {
            self.next.push_back(tx);
        }

        #[cfg(test)]
        assert!(self.cache.len() + self.next.len() <= self.max_cache_size);
    }

    /// Prepare for the next iteration, transferring transactions from `next` to `cache`.
    fn reset(&mut self) {
        // We do not need a size check here, because the cache can only grow in size
        // after `cache` is empty. New transactions are not walked until the entire
        // cache has been walked, so whenever we are adding brand new transactions to
        // the cache, `cache` must, by definition, be empty. The size of `next`
        // can grow beyond the previous iteration's cache, and that is limited inside
        // the `push` method.
        self.next.append(&mut self.cache);
        self.cache = std::mem::take(&mut self.next);

        #[cfg(test)]
        {
            assert!(self.cache.len() <= self.max_cache_size + 1);
            assert!(self.next.len() <= self.max_cache_size + 1);
        }
    }

    /// Total length of the cache.
    #[cfg_attr(test, mutants::skip)]
    fn len(&self) -> usize {
        self.cache.len() + self.next.len()
    }
}

/// Evaluates the pair of nonces, to determine an order
///
/// Returns:
///   `Equal` if both origin and sponsor nonces match expected
///   `Less` if the origin nonce is less than expected, or the origin matches expected and the
///          sponsor nonce is less than expected
///   `Greater` if the origin nonce is greater than expected, or the origin matches expected
///          and the sponsor nonce is greater than expected
fn order_nonces(
    origin_actual: u64,
    origin_expected: u64,
    sponsor_actual: u64,
    sponsor_expected: u64,
) -> Ordering {
    if origin_actual < origin_expected {
        return Ordering::Less;
    } else if origin_actual > origin_expected {
        return Ordering::Greater;
    }

    if sponsor_actual < sponsor_expected {
        return Ordering::Less;
    } else if sponsor_actual > sponsor_expected {
        return Ordering::Greater;
    }

    Ordering::Equal
}

impl MemPoolDB {
    fn instantiate_mempool_db(conn: &mut DBConn) -> Result<(), db_error> {
        let mut tx = tx_begin_immediate(conn)?;

        // create initial mempool tables
        for cmd in MEMPOOL_INITIAL_SCHEMA {
            tx.execute_batch(cmd).map_err(db_error::SqliteError)?;
        }

        // apply all migrations
        MemPoolDB::apply_schema_migrations(&mut tx)?;

        // add all indexes
        MemPoolDB::add_indexes(&mut tx)?;

        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    /// Load the schema version from the database, if it's new enough to have such a version.
    /// Returns Some(version) if a version can be loaded; None if not.
    fn get_schema_version(conn: &DBConn) -> Result<Option<i64>, db_error> {
        let is_versioned = table_exists(conn, "schema_version")?;
        if !is_versioned {
            return Ok(None);
        }

        let version = conn
            .query_row(
                "SELECT MAX(version) FROM schema_version",
                rusqlite::NO_PARAMS,
                |row| row.get(0),
            )
            .optional()?;

        Ok(version)
    }

    /// Apply all schema migrations up to the latest schema.
    fn apply_schema_migrations(tx: &mut DBTx) -> Result<(), db_error> {
        loop {
            let version = MemPoolDB::get_schema_version(&tx)?.unwrap_or(1);
            match version {
                1 => {
                    MemPoolDB::instantiate_cost_estimator(tx)?;
                }
                2 => {
                    MemPoolDB::instantiate_bloom_state(tx)?;
                }
                3 => {
                    MemPoolDB::instantiate_tx_blacklist(tx)?;
                }
                4 => {
                    MemPoolDB::denormalize_fee_rate(tx)?;
                }
                5 => {
                    MemPoolDB::instantiate_nonces(tx)?;
                }
                6 => {
                    break;
                }
                _ => {
                    panic!("Unknown schema version {}", version);
                }
            }
        }
        Ok(())
    }

    /// Add indexes
    #[cfg_attr(test, mutants::skip)]
    fn add_indexes(tx: &mut DBTx) -> Result<(), db_error> {
        for cmd in MEMPOOL_INDEXES {
            tx.execute_batch(cmd).map_err(db_error::SqliteError)?;
        }
        Ok(())
    }

    /// Instantiate the on-disk counting bloom filter
    #[cfg_attr(test, mutants::skip)]
    fn instantiate_bloom_state(tx: &mut DBTx) -> Result<(), db_error> {
        let node_hasher = BloomNodeHasher::new_random();
        let _ = BloomCounter::new(
            tx,
            BLOOM_COUNTER_TABLE,
            BLOOM_COUNTER_ERROR_RATE,
            MAX_BLOOM_COUNTER_TXS,
            node_hasher,
        )?;

        for cmd in MEMPOOL_SCHEMA_3_BLOOM_STATE {
            tx.execute_batch(cmd).map_err(db_error::SqliteError)?;
        }
        Ok(())
    }

    /// Instantiate the cost estimator schema
    #[cfg_attr(test, mutants::skip)]
    fn instantiate_cost_estimator(tx: &DBTx) -> Result<(), db_error> {
        for sql_exec in MEMPOOL_SCHEMA_2_COST_ESTIMATOR {
            tx.execute_batch(sql_exec)?;
        }

        Ok(())
    }

    /// Denormalize fee rate schema 5
    fn denormalize_fee_rate(tx: &DBTx) -> Result<(), db_error> {
        for sql_exec in MEMPOOL_SCHEMA_5 {
            tx.execute_batch(sql_exec)?;
        }

        Ok(())
    }

    /// Instantiate the tx blacklist schema
    #[cfg_attr(test, mutants::skip)]
    fn instantiate_tx_blacklist(tx: &DBTx) -> Result<(), db_error> {
        for sql_exec in MEMPOOL_SCHEMA_4_BLACKLIST {
            tx.execute_batch(sql_exec)?;
        }

        Ok(())
    }

    /// Add the nonce table
    #[cfg_attr(test, mutants::skip)]
    fn instantiate_nonces(tx: &DBTx) -> Result<(), db_error> {
        for sql_exec in MEMPOOL_SCHEMA_6_NONCES {
            tx.execute_batch(sql_exec)?;
        }

        Ok(())
    }

    #[cfg_attr(test, mutants::skip)]
    pub fn db_path(chainstate_root_path: &str) -> Result<String, db_error> {
        let mut path = PathBuf::from(chainstate_root_path);

        path.push("mempool.sqlite");
        path.to_str()
            .ok_or_else(|| db_error::ParseError)
            .map(String::from)
    }

    #[cfg(test)]
    pub fn open_test(
        mainnet: bool,
        chain_id: u32,
        chainstate_path: &str,
    ) -> Result<MemPoolDB, db_error> {
        let estimator = Box::new(UnitEstimator);
        let metric = Box::new(UnitMetric);
        MemPoolDB::open(mainnet, chain_id, chainstate_path, estimator, metric)
    }

    pub fn open_db(
        db_path: &str,
        cost_estimator: Box<dyn CostEstimator>,
        metric: Box<dyn CostMetric>,
    ) -> Result<MemPoolDB, db_error> {
        let admitter = MemPoolAdmitter::new(BlockHeaderHash([0u8; 32]), ConsensusHash([0u8; 20]));

        let mut create_flag = false;
        let open_flags = if fs::metadata(&db_path).is_err() {
            // need to create
            create_flag = true;
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        } else {
            // can just open
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };

        let mut conn = sqlite_open(&db_path, open_flags, true)?;
        if create_flag {
            // instantiate!
            MemPoolDB::instantiate_mempool_db(&mut conn)?;
        } else {
            let mut tx = tx_begin_immediate(&mut conn)?;
            MemPoolDB::apply_schema_migrations(&mut tx)?;
            MemPoolDB::add_indexes(&mut tx)?;
            tx.commit().map_err(db_error::SqliteError)?;
        }

        let bloom_counter = BloomCounter::<BloomNodeHasher>::try_load(&conn, BLOOM_COUNTER_TABLE)?
            .ok_or(db_error::Other(format!("Failed to load bloom counter")))?;

        Ok(MemPoolDB {
            db: conn,
            path: db_path.to_owned(),
            admitter,
            bloom_counter,
            max_tx_tags: DEFAULT_MAX_TX_TAGS,
            cost_estimator,
            metric,
            blacklist_timeout: DEFAULT_BLACKLIST_TIMEOUT,
            blacklist_max_size: DEFAULT_BLACKLIST_MAX_SIZE,
        })
    }

    pub fn reopen(&self, readwrite: bool) -> Result<DBConn, db_error> {
        if let Err(e) = fs::metadata(&self.path) {
            return Err(db_error::IOError(e));
        }

        let open_flags = if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };

        let conn = sqlite_open(&self.path, open_flags, true)?;
        Ok(conn)
    }

    /// Open the mempool db within the chainstate directory.
    /// The chainstate must be instantiated already.
    pub fn open(
        mainnet: bool,
        chain_id: u32,
        chainstate_path: &str,
        cost_estimator: Box<dyn CostEstimator>,
        metric: Box<dyn CostMetric>,
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

        let (chainstate, _) = StacksChainState::open(mainnet, chain_id, chainstate_path, None)
            .map_err(|e| db_error::Other(format!("Failed to open chainstate: {:?}", &e)))?;

        let db_path = MemPoolDB::db_path(&chainstate.root_path)?;

        MemPoolDB::open_db(&db_path, cost_estimator, metric)
    }

    #[cfg_attr(test, mutants::skip)]
    pub fn reset_nonce_cache(&mut self) -> Result<(), db_error> {
        debug!("reset nonce cache");
        let sql = "DELETE FROM nonces";
        self.db.execute(sql, rusqlite::NO_PARAMS)?;
        Ok(())
    }

    /// Find the origin addresses who have sent the highest-fee transactions
    fn find_origin_addresses_by_descending_fees(
        &self,
        start_height: i64,
        end_height: i64,
        min_fees: u64,
        offset: u32,
        count: u32,
    ) -> Result<Vec<StacksAddress>, db_error> {
        let sql = "SELECT DISTINCT origin_address FROM mempool WHERE height > ?1 AND height <= ?2 AND tx_fee >= ?3
                   ORDER BY tx_fee DESC LIMIT ?4 OFFSET ?5";
        let args: &[&dyn ToSql] = &[
            &start_height,
            &end_height,
            &u64_to_sql(min_fees)?,
            &count,
            &offset,
        ];
        query_row_columns(self.conn(), sql, args, "origin_address")
    }

    /// Add estimated fee rates to the mempool rate table using
    /// the mempool's configured `CostMetric` and `CostEstimator`. Will update
    /// at most `max_updates` entries in the database before returning.
    ///
    /// Returns `Ok(number_updated)` on success
    pub fn estimate_tx_rates(
        &mut self,
        max_updates: u32,
        block_limit: &ExecutionCost,
        stacks_epoch_id: &StacksEpochId,
    ) -> Result<u32, db_error> {
        let sql_tx = tx_begin_immediate(&mut self.db)?;
        let txs: Vec<MemPoolTxInfo> = query_rows(
            &sql_tx,
            "SELECT * FROM mempool as m WHERE m.fee_rate IS NULL LIMIT ?",
            &[max_updates],
        )?;
        let mut updated = 0;
        for tx_to_estimate in txs {
            let txid = tx_to_estimate.tx.txid();
            let estimator_result = cost_estimates::estimate_fee_rate(
                &tx_to_estimate.tx,
                self.cost_estimator.as_ref(),
                self.metric.as_ref(),
                block_limit,
                stacks_epoch_id,
            );
            let fee_rate_f64 = match estimator_result {
                Ok(x) => Some(x),
                Err(EstimatorError::NoEstimateAvailable) => continue,
                Err(e) => {
                    warn!("Error while estimating mempool tx rate";
                          "txid" => %txid,
                          "error" => ?e);
                    continue;
                }
            };

            sql_tx.execute(
                "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                rusqlite::params![fee_rate_f64, &txid],
            )?;
            updated += 1;
        }

        sql_tx.commit()?;

        Ok(updated)
    }

    /// Helper method to record nonces to a retry-buffer.
    /// This is needed for when we try to write-through a new (address, nonce) pair to the on-disk
    /// `nonces` cache, but the write fails due to lock contention from another thread.  The
    /// retry-buffer will be used to later store this data in a single transaction.
    fn save_nonce_for_retry(
        retry_store: &mut HashMap<StacksAddress, u64>,
        max_size: u64,
        addr: StacksAddress,
        new_nonce: u64,
    ) {
        if (retry_store.len() as u64) < max_size {
            if let Some(nonce) = retry_store.get_mut(&addr) {
                *nonce = cmp::max(new_nonce, *nonce);
            } else {
                retry_store.insert(addr, new_nonce);
            }
        }
    }

    /// Iterate over candidates in the mempool
    /// `todo` will be called once for each transaction that is a valid
    /// candidate for inclusion in the next block, meaning its origin and
    /// sponsor nonces are equal to the nonces of the corresponding accounts.
    /// Best effort will be made to process the transactions in fee-rate order.
    /// That is, transactions will be processed in fee-rate order until the
    /// candidate cache is full, at which point, transactions with a lower
    /// fee-rate may be considered before those with a higher fee-rate.
    /// When the candidate cache fills, a subsequent call to
    /// `iterate_candidates` will be needed to reconsider transactions which
    /// were skipped on the first pass, but become valid after some lower
    /// fee-rate transactions are considered.
    ///
    /// The size of the candidate cache and the nonce cache are configurable
    /// in the settings struct. This method is interruptable -- in the
    /// `settings` struct, the caller may choose how long to spend iterating
    /// before this method stops.
    ///
    /// `todo` returns an option to a `TransactionEvent` representing the
    /// outcome, or None to indicate that iteration through the mempool should
    /// be halted.
    ///
    /// `output_events` is modified in place, adding all substantive
    /// transaction events (success and error events, but not skipped) output
    /// by `todo`.
    pub fn iterate_candidates<F, E, C>(
        &mut self,
        clarity_tx: &mut C,
        output_events: &mut Vec<TransactionEvent>,
        _tip_height: u64,
        settings: MemPoolWalkSettings,
        mut todo: F,
    ) -> Result<u64, E>
    where
        C: ClarityConnection,
        F: FnMut(
            &mut C,
            &ConsiderTransaction,
            &mut dyn CostEstimator,
        ) -> Result<Option<TransactionEvent>, E>,
        E: From<db_error> + From<ChainstateError>,
    {
        let start_time = Instant::now();
        let mut total_considered = 0;

        debug!("Mempool walk for {}ms", settings.max_walk_time_ms,);

        let tx_consideration_sampler = Uniform::new(0, 100);
        let mut rng = rand::thread_rng();
        let mut candidate_cache = CandidateCache::new(settings.candidate_retry_cache_size);
        let mut nonce_cache = NonceCache::new(settings.nonce_cache_size);

        // set of (address, nonce) to store after the inner loop completes.  This will be done in a
        // single transaction.  This cannot grow to more than `settings.nonce_cache_size` entries.
        let mut retry_store = HashMap::new();

        let sql = "
             SELECT txid, origin_nonce, origin_address, sponsor_nonce, sponsor_address, fee_rate
             FROM mempool
             WHERE fee_rate IS NULL
             ";
        let mut query_stmt_null = self
            .db
            .prepare(&sql)
            .map_err(|err| Error::SqliteError(err))?;
        let mut null_iterator = query_stmt_null
            .query(NO_PARAMS)
            .map_err(|err| Error::SqliteError(err))?;

        let sql = "
            SELECT txid, origin_nonce, origin_address, sponsor_nonce, sponsor_address, fee_rate
            FROM mempool
            WHERE fee_rate IS NOT NULL
            ORDER BY fee_rate DESC
            ";
        let mut query_stmt_fee = self
            .db
            .prepare(&sql)
            .map_err(|err| Error::SqliteError(err))?;
        let mut fee_iterator = query_stmt_fee
            .query(NO_PARAMS)
            .map_err(|err| Error::SqliteError(err))?;

        loop {
            if start_time.elapsed().as_millis() > settings.max_walk_time_ms as u128 {
                debug!("Mempool iteration deadline exceeded";
                       "deadline_ms" => settings.max_walk_time_ms);
                break;
            }

            let start_with_no_estimate =
                tx_consideration_sampler.sample(&mut rng) < settings.consider_no_estimate_tx_prob;

            // First, try to read from the retry list
            let (candidate, update_estimate) = match candidate_cache.next() {
                Some(tx) => {
                    let update_estimate = tx.fee_rate.is_none();
                    (tx, update_estimate)
                }
                None => {
                    // When the retry list is empty, read from the mempool db,
                    // randomly selecting from either the null fee-rate transactions
                    // or those with fee-rate estimates.
                    let opt_tx = if start_with_no_estimate {
                        null_iterator
                            .next()
                            .map_err(|err| Error::SqliteError(err))?
                    } else {
                        fee_iterator.next().map_err(|err| Error::SqliteError(err))?
                    };
                    match opt_tx {
                        Some(row) => (MemPoolTxInfoPartial::from_row(row)?, start_with_no_estimate),
                        None => {
                            // If the selected iterator is empty, check the other
                            match if start_with_no_estimate {
                                fee_iterator.next().map_err(|err| Error::SqliteError(err))?
                            } else {
                                null_iterator
                                    .next()
                                    .map_err(|err| Error::SqliteError(err))?
                            } {
                                Some(row) => (
                                    MemPoolTxInfoPartial::from_row(row)?,
                                    !start_with_no_estimate,
                                ),
                                None => {
                                    debug!("No more transactions to consider in mempool");
                                    break;
                                }
                            }
                        }
                    }
                }
            };

            // Check the nonces.
            let (expected_origin_nonce, retry_store_origin_nonce) =
                nonce_cache.get(&candidate.origin_address, clarity_tx, self.conn());
            let (expected_sponsor_nonce, retry_store_sponsor_nonce) =
                nonce_cache.get(&candidate.sponsor_address, clarity_tx, self.conn());

            // Try storing these nonces later if we failed to do so here, e.g. due to some other
            // thread holding the write-lock on the mempool DB.
            if retry_store_origin_nonce {
                Self::save_nonce_for_retry(
                    &mut retry_store,
                    settings.nonce_cache_size,
                    candidate.origin_address.clone(),
                    expected_origin_nonce,
                );
            }
            if retry_store_sponsor_nonce {
                Self::save_nonce_for_retry(
                    &mut retry_store,
                    settings.nonce_cache_size,
                    candidate.sponsor_address.clone(),
                    expected_sponsor_nonce,
                );
            }

            match order_nonces(
                candidate.origin_nonce,
                expected_origin_nonce,
                candidate.sponsor_nonce,
                expected_sponsor_nonce,
            ) {
                Ordering::Less => {
                    debug!(
                        "Mempool: unexecutable: drop tx {}:{} ({})",
                        candidate.origin_address,
                        candidate.origin_nonce,
                        candidate.fee_rate.unwrap_or_default()
                    );
                    // This transaction cannot execute in this pass, just drop it
                    continue;
                }
                Ordering::Greater => {
                    debug!(
                        "Mempool: nonces too high, cached for later {}:{} ({})",
                        candidate.origin_address,
                        candidate.origin_nonce,
                        candidate.fee_rate.unwrap_or_default()
                    );
                    // This transaction could become runnable in this pass, save it for later
                    candidate_cache.push(candidate);
                    continue;
                }
                Ordering::Equal => {
                    // Candidate transaction: fall through
                }
            };

            // Read in and deserialize the transaction.
            let tx_info_option = MemPoolDB::get_tx(&self.conn(), &candidate.txid)?;
            let tx_info = match tx_info_option {
                Some(tx) => tx,
                None => {
                    // Note: Don't panic here because maybe the state has changed from garbage collection.
                    warn!("Miner: could not find a tx for id {:?}", &candidate.txid);
                    continue;
                }
            };

            let (tx_type, do_consider) = match &tx_info.tx.payload {
                TransactionPayload::TokenTransfer(..) => (
                    "TokenTransfer".to_string(),
                    settings
                        .txs_to_consider
                        .contains(&MemPoolWalkTxTypes::TokenTransfer),
                ),
                TransactionPayload::SmartContract(..) => (
                    "SmartContract".to_string(),
                    settings
                        .txs_to_consider
                        .contains(&MemPoolWalkTxTypes::SmartContract),
                ),
                TransactionPayload::ContractCall(..) => (
                    "ContractCall".to_string(),
                    settings
                        .txs_to_consider
                        .contains(&MemPoolWalkTxTypes::ContractCall),
                ),
                _ => ("".to_string(), true),
            };
            if !do_consider {
                debug!("Will skip mempool tx, since it does not have an acceptable type";
                       "txid" => %tx_info.tx.txid(),
                       "type" => %tx_type);
                continue;
            }

            let do_consider = if settings.filter_origins.len() > 0 {
                settings
                    .filter_origins
                    .contains(&tx_info.metadata.origin_address)
            } else {
                true
            };

            if !do_consider {
                debug!("Will skip mempool tx, since it does not have an allowed origin";
                       "txid" => %tx_info.tx.txid(),
                       "origin" => %tx_info.metadata.origin_address);
                continue;
            }

            let consider = ConsiderTransaction {
                tx: tx_info,
                update_estimate,
            };
            debug!("Consider mempool transaction";
                           "txid" => %consider.tx.tx.txid(),
                           "origin_addr" => %consider.tx.metadata.origin_address,
                           "origin_nonce" => candidate.origin_nonce,
                           "sponsor_addr" => %consider.tx.metadata.sponsor_address,
                           "sponsor_nonce" => candidate.sponsor_nonce,
                           "accept_time" => consider.tx.metadata.accept_time,
                           "tx_fee" => consider.tx.metadata.tx_fee,
                           "fee_rate" => candidate.fee_rate,
                           "size" => consider.tx.metadata.len);
            total_considered += 1;

            // Run `todo` on the transaction.
            match todo(clarity_tx, &consider, self.cost_estimator.as_mut())? {
                Some(tx_event) => {
                    match tx_event {
                        TransactionEvent::Success(_) => {
                            // Bump nonces in the cache for the executed transaction
                            let stored = nonce_cache.update(
                                consider.tx.metadata.origin_address,
                                expected_origin_nonce + 1,
                                self.conn(),
                            );
                            if !stored {
                                Self::save_nonce_for_retry(
                                    &mut retry_store,
                                    settings.nonce_cache_size,
                                    consider.tx.metadata.origin_address,
                                    expected_origin_nonce + 1,
                                );
                            }

                            if consider.tx.tx.auth.is_sponsored() {
                                let stored = nonce_cache.update(
                                    consider.tx.metadata.sponsor_address,
                                    expected_sponsor_nonce + 1,
                                    self.conn(),
                                );
                                if !stored {
                                    Self::save_nonce_for_retry(
                                        &mut retry_store,
                                        settings.nonce_cache_size,
                                        consider.tx.metadata.sponsor_address,
                                        expected_sponsor_nonce + 1,
                                    );
                                }
                            }
                            output_events.push(tx_event);
                        }
                        TransactionEvent::Skipped(_) => {
                            // don't push `Skipped` events to the observer
                        }
                        _ => {
                            output_events.push(tx_event);
                        }
                    }
                }
                None => {
                    debug!("Mempool iteration early exit from iterator");
                    break;
                }
            }

            // Reset for finding the next transaction to process
            debug!(
                "Mempool: reset: retry list has {} entries",
                candidate_cache.len()
            );
            candidate_cache.reset();
        }

        // drop these rusqlite statements and queries, since their existence as immutable borrows on the
        // connection prevents us from beginning a transaction below (which requires a mutable
        // borrow).
        drop(null_iterator);
        drop(fee_iterator);
        drop(query_stmt_null);
        drop(query_stmt_fee);

        if retry_store.len() > 0 {
            let tx = self.tx_begin()?;
            for (address, nonce) in retry_store.into_iter() {
                nonce_cache.update(address, nonce, &tx);
            }
            tx.commit()?;
        }

        debug!(
            "Mempool iteration finished";
            "considered_txs" => total_considered,
            "elapsed_ms" => start_time.elapsed().as_millis()
        );
        Ok(total_considered)
    }

    pub fn conn(&self) -> &DBConn {
        &self.db
    }

    pub fn tx_begin<'a>(&'a mut self) -> Result<MemPoolTx<'a>, db_error> {
        let tx = tx_begin_immediate(&mut self.db)?;
        Ok(MemPoolTx::new(
            tx,
            &mut self.admitter,
            &mut self.bloom_counter,
        ))
    }

    pub fn db_has_tx(conn: &DBConn, txid: &Txid) -> Result<bool, db_error> {
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
    pub fn get_tx_metadata_by_address(
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
                          accept_time,
                          last_known_sponsor_nonce,
                          last_known_origin_nonce
                          FROM mempool WHERE {0}_address = ?1 AND {0}_nonce = ?2",
            if is_origin { "origin" } else { "sponsor" }
        );
        let args: &[&dyn ToSql] = &[&addr.to_string(), &u64_to_sql(nonce)?];
        query_row(conn, &sql, args)
    }

    fn are_blocks_in_same_fork(
        chainstate: &mut StacksChainState,
        first_consensus_hash: &ConsensusHash,
        first_stacks_block: &BlockHeaderHash,
        second_consensus_hash: &ConsensusHash,
        second_stacks_block: &BlockHeaderHash,
    ) -> Result<bool, db_error> {
        let first_block = StacksBlockId::new(first_consensus_hash, first_stacks_block);
        let second_block = StacksBlockId::new(second_consensus_hash, second_stacks_block);
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
    /// Don't call directly; use submit().
    /// This is `pub` only for testing.
    pub fn try_add_tx(
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
                debug!(
                    "Can replace {} with {} for {},{} by fee ({} < {})",
                    &prior_tx.txid, &txid, origin_address, origin_nonce, &prior_tx.tx_fee, &tx_fee
                );
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
                debug!(
                    "Can replace {} with {} for {},{} across fork",
                    &prior_tx.txid, &txid, origin_address, origin_nonce
                );
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

        tx.update_bloom_counter(height, &txid, prior_tx.as_ref().map(|tx| tx.txid.clone()))?;

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

        tx.update_mempool_pager(&txid)?;

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
            (i64::MAX - 1) as u64,
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
        sortdb: &SortitionDB,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx: &StacksTransaction,
        do_admission_checks: bool,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
        fee_rate_estimate: Option<f64>,
    ) -> Result<(), MemPoolRejection> {
        test_debug!(
            "Mempool submit {} at {}/{}",
            tx.txid(),
            consensus_hash,
            block_hash
        );

        let block_id = StacksBlockId::new(consensus_hash, block_hash);
        let height = match NakamotoChainState::get_block_header(chainstate.db(), &block_id) {
            Ok(Some(header)) => header.stacks_block_height,
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
            mempool_tx
                .admitter
                .will_admit_tx(chainstate, sortdb, tx, len)?;
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

        mempool_tx
            .execute(
                "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                rusqlite::params![fee_rate_estimate, &txid],
            )
            .map_err(db_error::from)?;

        if let Err(e) = monitoring::mempool_accepted(&txid, &chainstate.root_path) {
            warn!("Failed to monitor TX receive: {:?}", e; "txid" => %txid);
        }

        Ok(())
    }

    /// One-shot submit
    pub fn submit(
        &mut self,
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx: &StacksTransaction,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
        block_limit: &ExecutionCost,
        stacks_epoch_id: &StacksEpochId,
    ) -> Result<(), MemPoolRejection> {
        if self.is_tx_blacklisted(&tx.txid())? {
            // don't re-store this transaction
            test_debug!("Transaction {} is temporarily blacklisted", &tx.txid());
            return Err(MemPoolRejection::TemporarilyBlacklisted);
        }

        let estimator_result = cost_estimates::estimate_fee_rate(
            tx,
            self.cost_estimator.as_ref(),
            self.metric.as_ref(),
            block_limit,
            stacks_epoch_id,
        );

        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;

        let fee_rate = match estimator_result {
            Ok(x) => Some(x),
            Err(EstimatorError::NoEstimateAvailable) => None,
            Err(e) => {
                warn!("Error while estimating mempool tx rate";
                      "txid" => %tx.txid(),
                      "error" => ?e);
                return Err(MemPoolRejection::EstimatorError(e));
            }
        };

        MemPoolDB::tx_submit(
            &mut mempool_tx,
            chainstate,
            sortdb,
            consensus_hash,
            block_hash,
            tx,
            true,
            event_observer,
            fee_rate,
        )?;
        mempool_tx.commit().map_err(MemPoolRejection::DBError)?;
        Ok(())
    }

    /// Miner-driven submit (e.g. for poison microblocks), where no checks are performed
    pub fn miner_submit(
        &mut self,
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx: &StacksTransaction,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
        miner_estimate: f64,
    ) -> Result<(), MemPoolRejection> {
        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;

        let fee_estimate = Some(miner_estimate);

        MemPoolDB::tx_submit(
            &mut mempool_tx,
            chainstate,
            sortdb,
            consensus_hash,
            block_hash,
            tx,
            false,
            event_observer,
            fee_estimate,
        )?;
        mempool_tx.commit().map_err(MemPoolRejection::DBError)?;
        Ok(())
    }

    /// Directly submit to the mempool, and don't do any admissions checks.
    /// This method is only used during testing, but because it is used by the
    ///  integration tests, it cannot be marked #[cfg(test)].
    pub fn submit_raw(
        &mut self,
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        tx_bytes: Vec<u8>,
        block_limit: &ExecutionCost,
        stacks_epoch_id: &StacksEpochId,
    ) -> Result<(), MemPoolRejection> {
        let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..])
            .map_err(MemPoolRejection::DeserializationFailure)?;

        if self.is_tx_blacklisted(&tx.txid())? {
            // don't re-store this transaction
            test_debug!("Transaction {} is temporarily blacklisted", &tx.txid());
            return Err(MemPoolRejection::TemporarilyBlacklisted);
        }

        let estimator_result = cost_estimates::estimate_fee_rate(
            &tx,
            self.cost_estimator.as_ref(),
            self.metric.as_ref(),
            block_limit,
            stacks_epoch_id,
        );

        let mut mempool_tx = self.tx_begin().map_err(MemPoolRejection::DBError)?;

        let fee_rate = match estimator_result {
            Ok(x) => Some(x),
            Err(EstimatorError::NoEstimateAvailable) => None,
            Err(e) => {
                warn!("Error while estimating mempool tx rate";
                      "txid" => %tx.txid(),
                      "error" => ?e);
                return Err(MemPoolRejection::Other(
                    "Failed to estimate mempool tx rate".into(),
                ));
            }
        };

        MemPoolDB::tx_submit(
            &mut mempool_tx,
            chainstate,
            sortdb,
            consensus_hash,
            block_hash,
            &tx,
            false,
            None,
            fee_rate,
        )?;
        mempool_tx.commit().map_err(MemPoolRejection::DBError)?;
        Ok(())
    }

    /// Blacklist transactions from the mempool
    /// Do not call directly; it's `pub` only for testing
    pub fn inner_blacklist_txs<'a>(
        tx: &DBTx<'a>,
        txids: &[Txid],
        now: u64,
    ) -> Result<(), db_error> {
        for txid in txids {
            let sql = "INSERT OR REPLACE INTO tx_blacklist (txid, arrival_time) VALUES (?1, ?2)";
            let args: &[&dyn ToSql] = &[&txid, &u64_to_sql(now)?];
            tx.execute(sql, args)?;
        }
        Ok(())
    }

    /// garbage-collect the tx blacklist -- delete any transactions whose blacklist timeout has
    /// been exceeded
    pub fn garbage_collect_tx_blacklist<'a>(
        tx: &DBTx<'a>,
        now: u64,
        timeout: u64,
        max_size: u64,
    ) -> Result<(), db_error> {
        let sql = "DELETE FROM tx_blacklist WHERE arrival_time + ?1 < ?2";
        let args: &[&dyn ToSql] = &[&u64_to_sql(timeout)?, &u64_to_sql(now)?];
        tx.execute(sql, args)?;

        // if we get too big, then drop some txs at random
        let sql = "SELECT size FROM tx_blacklist_size";
        let sz = query_int(tx, sql, NO_PARAMS)? as u64;
        if sz > max_size {
            let to_delete = sz - max_size;
            let txids: Vec<Txid> = query_rows(
                tx,
                "SELECT txid FROM tx_blacklist ORDER BY RANDOM() LIMIT ?1",
                &[&u64_to_sql(to_delete)? as &dyn ToSql],
            )?;
            for txid in txids.into_iter() {
                tx.execute(
                    "DELETE FROM tx_blacklist WHERE txid = ?1",
                    &[&txid as &dyn ToSql],
                )?;
            }
        }
        Ok(())
    }

    /// when was a tx blacklisted?
    fn get_blacklisted_tx_arrival_time(
        conn: &DBConn,
        txid: &Txid,
    ) -> Result<Option<u64>, db_error> {
        let sql = "SELECT arrival_time FROM tx_blacklist WHERE txid = ?1";
        let args: &[&dyn ToSql] = &[&txid];
        query_row(conn, sql, args)
    }

    /// is a tx blacklisted as of the given timestamp?
    fn inner_is_tx_blacklisted(
        conn: &DBConn,
        txid: &Txid,
        now: u64,
        timeout: u64,
    ) -> Result<bool, db_error> {
        match MemPoolDB::get_blacklisted_tx_arrival_time(conn, txid)? {
            None => Ok(false),
            Some(arrival_time) => Ok(now < arrival_time + timeout),
        }
    }

    /// is a tx blacklisted?
    pub fn is_tx_blacklisted(&self, txid: &Txid) -> Result<bool, db_error> {
        MemPoolDB::inner_is_tx_blacklisted(
            self.conn(),
            txid,
            get_epoch_time_secs(),
            self.blacklist_timeout,
        )
    }

    /// Inner code body for dropping transactions.
    /// Note that the bloom filter will *NOT* be updated.  That's the caller's job, if desired.
    fn inner_drop_txs<'a>(tx: &DBTx<'a>, txids: &[Txid]) -> Result<(), db_error> {
        let sql = "DELETE FROM mempool WHERE txid = ?";
        for txid in txids.iter() {
            tx.execute(sql, &[txid])?;
        }
        Ok(())
    }

    /// Drop transactions from the mempool.  Does not update the bloom filter, thereby ensuring that
    /// these transactions will still show up as present to the mempool sync logic.
    pub fn drop_txs(&mut self, txids: &[Txid]) -> Result<(), db_error> {
        let mempool_tx = self.tx_begin()?;
        MemPoolDB::inner_drop_txs(&mempool_tx, txids)?;
        mempool_tx.commit()?;
        Ok(())
    }

    /// Drop and blacklist transactions, so we don't re-broadcast them or re-fetch them.
    /// Do *NOT* remove them from the bloom filter.  This will cause them to continue to be
    /// reported as present, which is exactly what we want because we don't want these transactions
    /// to be seen again (so we don't want anyone accidentally "helpfully" pushing them to us, nor
    /// do we want the mempool sync logic to "helpfully" re-discover and re-download them).
    pub fn drop_and_blacklist_txs(&mut self, txids: &[Txid]) -> Result<(), db_error> {
        let now = get_epoch_time_secs();
        let blacklist_timeout = self.blacklist_timeout;
        let blacklist_max_size = self.blacklist_max_size;

        let mempool_tx = self.tx_begin()?;
        MemPoolDB::inner_drop_txs(&mempool_tx, txids)?;
        MemPoolDB::inner_blacklist_txs(&mempool_tx, txids, now)?;
        MemPoolDB::garbage_collect_tx_blacklist(
            &mempool_tx,
            now,
            blacklist_timeout,
            blacklist_max_size,
        )?;
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

    /// Get the bloom filter that represents the set of recent transactions we have
    pub fn get_txid_bloom_filter(&self) -> Result<BloomFilter<BloomNodeHasher>, db_error> {
        self.bloom_counter.to_bloom_filter(&self.conn())
    }

    /// Find maximum height represented in the mempool
    pub fn get_max_height(conn: &DBConn) -> Result<Option<u64>, db_error> {
        let sql = "SELECT 1 FROM mempool WHERE height >= 0";
        let count = query_rows::<i64, _>(conn, sql, NO_PARAMS)?.len();
        if count == 0 {
            Ok(None)
        } else {
            let sql = "SELECT MAX(height) FROM mempool";
            Ok(Some(query_int(conn, sql, NO_PARAMS)? as u64))
        }
    }

    /// Get the transaction ID list that represents the set of transactions that are represented in
    /// the bloom counter.
    pub fn get_bloom_txids(&self) -> Result<Vec<Txid>, db_error> {
        let max_height = match MemPoolDB::get_max_height(&self.conn())? {
            Some(h) => h,
            None => {
                // mempool is empty
                return Ok(vec![]);
            }
        };
        let min_height = max_height.saturating_sub(BLOOM_COUNTER_DEPTH as u64);
        let sql = "SELECT mempool.txid FROM mempool WHERE height > ?1 AND height <= ?2 AND NOT EXISTS (SELECT 1 FROM removed_txids WHERE txid = mempool.txid)";
        let args: &[&dyn ToSql] = &[&u64_to_sql(min_height)?, &u64_to_sql(max_height)?];
        query_rows(&self.conn(), sql, args)
    }

    /// Get the transaction tag list that represents the set of recent transactions we have.
    /// Generate them with our node-local seed so that our txtag list is different from anyone
    /// else's, with high probability.
    pub fn get_txtags(&self, seed: &[u8]) -> Result<Vec<TxTag>, db_error> {
        self.get_bloom_txids().map(|txid_list| {
            txid_list
                .iter()
                .map(|txid| TxTag::from(seed, txid))
                .collect()
        })
    }

    /// How many recent transactions are there -- i.e. within BLOOM_COUNTER_DEPTH block heights of
    /// the chain tip?
    pub fn get_num_recent_txs(conn: &DBConn) -> Result<u64, db_error> {
        let max_height = match MemPoolDB::get_max_height(conn)? {
            Some(h) => h,
            None => {
                // mempool is empty
                return Ok(0);
            }
        };
        let min_height = max_height.saturating_sub(BLOOM_COUNTER_DEPTH as u64);
        let sql = "SELECT COUNT(txid) FROM mempool WHERE height > ?1 AND height <= ?2";
        let args: &[&dyn ToSql] = &[&u64_to_sql(min_height)?, &u64_to_sql(max_height)?];
        query_int(conn, sql, args).map(|cnt| cnt as u64)
    }

    /// Make a mempool sync request.
    /// If sufficiently sparse, use a MemPoolSyncData::TxTags variant
    /// Otherwise, use a MemPoolSyncData::BloomFilter variant
    pub fn make_mempool_sync_data(&self) -> Result<MemPoolSyncData, db_error> {
        let num_tags = MemPoolDB::get_num_recent_txs(self.conn())?;
        if num_tags < self.max_tx_tags.into() {
            let seed = self.bloom_counter.get_seed().clone();
            let tags = self.get_txtags(&seed)?;
            Ok(MemPoolSyncData::TxTags(seed, tags))
        } else {
            Ok(MemPoolSyncData::BloomFilter(self.get_txid_bloom_filter()?))
        }
    }

    /// Get the hashed txid for a txid
    pub fn get_randomized_txid(&self, txid: &Txid) -> Result<Option<Txid>, db_error> {
        let sql = "SELECT hashed_txid FROM randomized_txids WHERE txid = ?1 LIMIT 1";
        let args: &[&dyn ToSql] = &[txid];
        query_row(&self.conn(), sql, args)
    }

    pub fn find_next_missing_transactions(
        &self,
        data: &MemPoolSyncData,
        height: u64,
        last_randomized_txid: &Txid,
        max_txs: u64,
        max_run: u64,
    ) -> Result<(Vec<StacksTransaction>, Option<Txid>, u64), db_error> {
        Self::static_find_next_missing_transactions(
            self.conn(),
            data,
            height,
            last_randomized_txid,
            max_txs,
            max_run,
        )
    }

    /// Get the next batch of transactions from our mempool that are *not* represented in the given
    /// MemPoolSyncData.  Transactions are ordered lexicographically by randomized_txids.hashed_txid, since this allows us
    /// to use the txid as a cursor while ensuring that each node returns txids in a deterministic random order
    /// (so if some nodes are configured to return fewer than MAX_BLOOM_COUNTER_TXS transactions,
    /// a requesting node will still have a good chance of getting something useful).
    /// Also, return the next value to pass for `last_randomized_txid` to load the next page.
    /// Also, return the number of rows considered.
    pub fn static_find_next_missing_transactions(
        conn: &DBConn,
        data: &MemPoolSyncData,
        height: u64,
        last_randomized_txid: &Txid,
        max_txs: u64,
        max_run: u64,
    ) -> Result<(Vec<StacksTransaction>, Option<Txid>, u64), db_error> {
        let mut ret = vec![];
        let sql = "SELECT mempool.txid AS txid, mempool.tx AS tx, randomized_txids.hashed_txid AS hashed_txid \
                   FROM mempool JOIN randomized_txids \
                   ON mempool.txid = randomized_txids.txid \
                   WHERE randomized_txids.hashed_txid > ?1 \
                   AND mempool.height > ?2 \
                   AND NOT EXISTS \
                        (SELECT 1 FROM removed_txids WHERE txid = mempool.txid) \
                   ORDER BY randomized_txids.hashed_txid ASC LIMIT ?3";

        let args: &[&dyn ToSql] = &[
            &last_randomized_txid,
            &u64_to_sql(height.saturating_sub(BLOOM_COUNTER_DEPTH as u64))?,
            &u64_to_sql(max_run)?,
        ];

        let mut tags_table = HashSet::new();
        if let MemPoolSyncData::TxTags(_, ref tags) = data {
            for tag in tags.iter() {
                tags_table.insert(tag.clone());
            }
        }

        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(args)?;
        let mut num_rows_visited = 0;
        let mut next_page = None;
        while let Some(row) = rows.next()? {
            if num_rows_visited >= max_run {
                break;
            }

            let txid = Txid::from_column(row, "txid")?;
            num_rows_visited += 1;

            let hashed_txid = Txid::from_column(row, "hashed_txid")?;
            test_debug!(
                "Consider txid {} ({}) at or after {}",
                &txid,
                &hashed_txid,
                last_randomized_txid
            );
            next_page = Some(hashed_txid);

            let contains = match data {
                MemPoolSyncData::BloomFilter(ref bf) => bf.contains_raw(&txid.0),
                MemPoolSyncData::TxTags(ref seed, ..) => {
                    tags_table.contains(&TxTag::from(seed, &txid))
                }
            };
            if contains {
                // remote peer already has this one
                continue;
            }

            let tx_bytes: Vec<u8> = row.get_unwrap("tx");
            let tx = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..])
                .map_err(|_e| db_error::ParseError)?;

            test_debug!("Returning txid {}", &txid);
            ret.push(tx);
            if (ret.len() as u64) >= max_txs {
                break;
            }
        }

        Ok((ret, next_page, num_rows_visited))
    }
}
