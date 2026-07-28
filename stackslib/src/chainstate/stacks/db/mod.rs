// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::prelude::*;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use clarity::vm::analysis::analysis_db::AnalysisDatabase;
use clarity::vm::clarity::TransactionConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::{
    BurnStateDB, ClarityDatabase, HeadersDB, STXBalance, NULL_BURN_STATE_DB,
};
use clarity::vm::errors::ClarityEvalError;
use clarity::vm::events::*;
use clarity::vm::representations::ContractName;
use clarity::vm::resource_limiter::ResourceBudget;
use clarity::vm::types::TupleData;
use clarity::vm::{SymbolicExpression, Value};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::de::Error as de_Error;
use serde::Deserialize;
use stacks_common::codec::{read_next, write_next, StacksMessageCodec};
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId, TrieHash};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::burnchains::bitcoin::address::LegacyBitcoinAddress;
use crate::burnchains::{Address, Burnchain, BurnchainParameters, PoxConstants};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::{
    DelegateStxOp, StackStxOp, TransferStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::burn::{ConsensusHash, ConsensusHashExtensions};
use crate::chainstate::nakamoto::{
    HeaderTypeNames, NakamotoBlockHeader, NakamotoChainState, NakamotoStagingBlocksConn,
    NAKAMOTO_CHAINSTATE_SCHEMA_1, NAKAMOTO_CHAINSTATE_SCHEMA_2, NAKAMOTO_CHAINSTATE_SCHEMA_3,
    NAKAMOTO_CHAINSTATE_SCHEMA_4, NAKAMOTO_CHAINSTATE_SCHEMA_5, NAKAMOTO_CHAINSTATE_SCHEMA_6,
    NAKAMOTO_CHAINSTATE_SCHEMA_7, NAKAMOTO_CHAINSTATE_SCHEMA_8, NAKAMOTO_CHAINSTATE_SCHEMA_9,
};
use crate::chainstate::stacks::address::StacksAddressExtensions;
use crate::chainstate::stacks::boot::*;
use crate::chainstate::stacks::db::accounts::*;
use crate::chainstate::stacks::db::blocks::*;
use crate::chainstate::stacks::db::unconfirmed::UnconfirmedState;
use crate::chainstate::stacks::events::*;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::miner::TransactionResourceBudgets;
use crate::chainstate::stacks::{
    Error, StacksBlockHeader, StacksMicroblockHeader, C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::clarity_vm::clarity::{
    ClarityBlockConnection, ClarityConnection, ClarityError, ClarityInstance,
    ClarityReadOnlyConnection, PreCommitClarityBlock,
};
use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::monitoring;
use crate::net::atlas::BNS_CHARS_REGEX;
use crate::util_lib::boot::{boot_code_acc, boot_code_addr, boot_code_id, boot_code_tx_auth};
use crate::util_lib::db::{
    DBConn, DBTx, Error as db_error, FromColumn, FromRow, IndexDBConn, IndexDBTx,
};

pub mod accounts;
pub mod backend;
pub mod blocks;
pub mod contracts;
pub mod headers;
pub mod snapshot;
pub mod transactions;
pub mod unconfirmed;

pub use self::accounts::{
    MinerRewardCalculator, MinerRewardsDb, StacksAccountReader, StacksAccountWriter,
};
pub use self::backend::*;
pub use self::blocks::{
    Epoch2BlockProcessor, Epoch2BlockValidator, Epoch2StagingBlocksDb, MempoolAdmissionPolicy,
    StacksBlockStore,
};
pub use self::contracts::ClarityStateRead;
pub use self::headers::StacksHeadersDb;
pub use self::transactions::{
    handle_poison_microblock, StacksTransactionBlock, StacksTransactionChecker,
    StacksTransactionExecution, StacksTransactionPrecheck,
};

/// Fault injection struct for various kinds of faults we'd like to introduce into the system
pub struct StacksChainStateFaults {
    // if true, then the envar STACKS_HIDE_BLOCKS_AT_HEIGHT will be consulted to get a list of
    // Stacks block heights to never propagate or announce.
    pub hide_blocks: bool,
}

impl StacksChainStateFaults {
    pub fn new() -> Self {
        Self { hide_blocks: false }
    }
}

pub struct StacksChainState<B: ChainStatePersistence> {
    pub mainnet: bool,
    pub chain_id: u32,
    pub clarity_state: ClarityInstance,
    pub nakamoto_staging_blocks_conn: NakamotoStagingBlocksConn,
    pub state_index: MARF<StacksBlockId>,
    pub blocks_path: String,
    pub clarity_state_index_path: String, // path to clarity MARF
    pub clarity_state_index_root: String, // path to dir containing clarity MARF and side-store
    pub root_path: String,
    pub unconfirmed_state: Option<UnconfirmedState>,
    pub fault_injection: StacksChainStateFaults,
    marf_opts: Option<MARFOpenOpts>,
    backend: B,
}

/// Handles PoX reward-cycle start bookkeeping and unlock transitions.
pub struct PoxCycleStartHandler;

/// Computes PoX reward set thresholds, reward slots, and signer sets.
pub struct PoxRewardSetCalculator;

#[derive(Debug, Clone, PartialEq)]
pub struct StacksAccount {
    pub principal: PrincipalData,
    pub nonce: u64,
    pub stx_balance: STXBalance,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MinerPaymentTxFees {
    Epoch2 { anchored: u128, streamed: u128 },
    Nakamoto { parent_fees: u128 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerPaymentSchedule {
    pub address: StacksAddress,
    pub recipient: PrincipalData,
    pub block_hash: BlockHeaderHash,
    pub consensus_hash: ConsensusHash,
    pub parent_block_hash: BlockHeaderHash,
    pub parent_consensus_hash: ConsensusHash,
    pub coinbase: u128,
    pub tx_fees: MinerPaymentTxFees,
    pub burnchain_commit_burn: u64,
    pub burnchain_sortition_burn: u64,
    pub miner: bool, // is this a schedule payment for the block's miner?
    pub stacks_block_height: u64,
    pub vtxindex: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StacksBlockHeaderTypes {
    Epoch2(StacksBlockHeader),
    Nakamoto(NakamotoBlockHeader),
}

impl From<StacksBlockHeader> for StacksBlockHeaderTypes {
    fn from(value: StacksBlockHeader) -> Self {
        Self::Epoch2(value)
    }
}

impl From<NakamotoBlockHeader> for StacksBlockHeaderTypes {
    fn from(value: NakamotoBlockHeader) -> Self {
        Self::Nakamoto(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksHeaderInfo {
    /// Stacks block header
    pub anchored_header: StacksBlockHeaderTypes,
    /// Last microblock header (Stacks 2.x only; this is None in Stacks 3.x)
    pub microblock_tail: Option<StacksMicroblockHeader>,
    /// Height of this Stacks block
    pub stacks_block_height: u64,
    /// MARF root hash of the headers DB (not consensus critical)
    pub index_root: TrieHash,
    /// consensus hash of the burnchain block in which this miner was selected to produce this block
    pub consensus_hash: ConsensusHash,
    /// Hash of the burnchain block in which this miner was selected to produce this block
    pub burn_header_hash: BurnchainHeaderHash,
    /// Height of the burnchain block
    pub burn_header_height: u32,
    /// Timestamp of the burnchain block
    pub burn_header_timestamp: u64,
    /// Size of the block corresponding to `anchored_header` in bytes
    pub anchored_block_size: u64,
    /// The burnchain tip that is passed to Clarity while processing this block.
    /// This should always be `Some()` for Nakamoto blocks and `None` for 2.x blocks
    pub burn_view: Option<ConsensusHash>,
    /// Total tenure size (reset at every tenure extend) in bytes
    /// Not consensus-critical (may differ between nodes)
    pub total_tenure_size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MinerRewardInfo {
    pub from_block_consensus_hash: ConsensusHash,
    pub from_stacks_block_hash: BlockHeaderHash,
    pub from_parent_block_consensus_hash: ConsensusHash,
    pub from_parent_stacks_block_hash: BlockHeaderHash,
}

/// This is the block receipt for a Stacks block
#[derive(Debug, Clone, PartialEq)]
pub struct StacksEpochReceipt {
    pub header: StacksHeaderInfo,
    pub tx_receipts: Vec<StacksTransactionReceipt>,
    pub matured_rewards: Vec<MinerReward>,
    pub matured_rewards_info: Option<MinerRewardInfo>,
    pub parent_microblocks_cost: ExecutionCost,
    pub anchored_block_cost: ExecutionCost,
    pub parent_burn_block_hash: BurnchainHeaderHash,
    pub parent_burn_block_height: u32,
    pub parent_burn_block_timestamp: u64,
    /// This is the Stacks epoch that the block was evaluated in,
    /// which is the Stacks epoch that this block's parent was elected
    /// in.
    pub evaluated_epoch: StacksEpochId,
    pub epoch_transition: bool,
    /// Was .signers updated during this block?
    pub signers_updated: bool,
    pub coinbase_height: u64,
}

/// Headers we serve over the network
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtendedStacksHeader {
    pub consensus_hash: ConsensusHash,
    #[serde(
        serialize_with = "ExtendedStacksHeader_StacksBlockHeader_serialize",
        deserialize_with = "ExtendedStacksHeader_StacksBlockHeader_deserialize"
    )]
    pub header: StacksBlockHeader,
    pub parent_block_id: StacksBlockId,
}

/// In ExtendedStacksHeader, encode the StacksBlockHeader as a hex string
fn ExtendedStacksHeader_StacksBlockHeader_serialize<S: serde::Serializer>(
    header: &StacksBlockHeader,
    s: S,
) -> Result<S::Ok, S::Error> {
    let bytes = header.serialize_to_vec();
    let header_hex = to_hex(&bytes);
    s.serialize_str(header_hex.as_str())
}

/// In ExtendedStacksHeader, encode the StacksBlockHeader as a hex string
fn ExtendedStacksHeader_StacksBlockHeader_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<StacksBlockHeader, D::Error> {
    let header_hex = String::deserialize(d)?;
    let header_bytes = hex_bytes(&header_hex).map_err(de_Error::custom)?;
    StacksBlockHeader::consensus_deserialize(&mut &header_bytes[..]).map_err(de_Error::custom)
}

impl StacksMessageCodec for ExtendedStacksHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.header)?;
        write_next(fd, &self.parent_block_id)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ExtendedStacksHeader, codec_error> {
        let ch = read_next(fd)?;
        let bh = read_next(fd)?;
        let pbid = read_next(fd)?;
        Ok(ExtendedStacksHeader {
            consensus_hash: ch,
            header: bh,
            parent_block_id: pbid,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DBConfig {
    pub version: String,
    pub mainnet: bool,
    pub chain_id: u32,
}

impl DBConfig {
    pub fn supports_epoch(&self, epoch_id: StacksEpochId) -> bool {
        let version_u32: u32 = self.version.parse().unwrap_or_else(|e| {
            error!("Failed to parse Stacks chainstate version as u32: {e}");
            0
        });
        if epoch_id >= StacksEpochId::Epoch21 {
            (3..=CHAINSTATE_VERSION_NUMBER).contains(&version_u32)
        } else if epoch_id == StacksEpochId::Epoch2_05 {
            (2..=CHAINSTATE_VERSION_NUMBER).contains(&version_u32)
        } else if epoch_id == StacksEpochId::Epoch20 {
            (1..=CHAINSTATE_VERSION_NUMBER).contains(&version_u32)
        } else {
            true
        }
    }
}

impl StacksBlockHeaderTypes {
    pub fn block_hash(&self) -> BlockHeaderHash {
        match &self {
            StacksBlockHeaderTypes::Epoch2(x) => x.block_hash(),
            StacksBlockHeaderTypes::Nakamoto(x) => x.block_hash(),
        }
    }

    pub fn is_first_mined(&self) -> bool {
        match self {
            StacksBlockHeaderTypes::Epoch2(x) => x.is_first_mined(),
            StacksBlockHeaderTypes::Nakamoto(x) => x.is_first_mined(),
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            StacksBlockHeaderTypes::Epoch2(x) => x.total_work.work,
            StacksBlockHeaderTypes::Nakamoto(x) => x.chain_length,
        }
    }

    /// Get the total spend by miners for this block
    pub fn total_burns(&self) -> u64 {
        match self {
            StacksBlockHeaderTypes::Epoch2(x) => x.total_work.burn,
            StacksBlockHeaderTypes::Nakamoto(x) => x.burn_spent,
        }
    }

    pub fn as_stacks_epoch2(&self) -> Option<&StacksBlockHeader> {
        match &self {
            StacksBlockHeaderTypes::Epoch2(ref x) => Some(x),
            _ => None,
        }
    }

    pub fn as_stacks_nakamoto(&self) -> Option<&NakamotoBlockHeader> {
        match &self {
            StacksBlockHeaderTypes::Nakamoto(ref x) => Some(x),
            _ => None,
        }
    }
}

impl StacksHeaderInfo {
    pub fn index_block_hash(&self) -> StacksBlockId {
        let block_hash = self.anchored_header.block_hash();
        StacksBlockId::new(&self.consensus_hash, &block_hash)
    }

    pub fn regtest_genesis() -> StacksHeaderInfo {
        let burnchain_params = BurnchainParameters::bitcoin_regtest();
        StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis_block_header().into(),
            microblock_tail: None,
            stacks_block_height: 0,
            index_root: TrieHash([0u8; 32]),
            burn_header_hash: burnchain_params.first_block_hash.clone(),
            burn_header_height: burnchain_params.first_block_height as u32,
            consensus_hash: ConsensusHash::empty(),
            burn_header_timestamp: 0,
            anchored_block_size: 0,
            burn_view: None,
            total_tenure_size: 0,
        }
    }

    pub fn genesis(
        root_hash: TrieHash,
        first_burnchain_block_hash: &BurnchainHeaderHash,
        first_burnchain_block_height: u32,
        first_burnchain_block_timestamp: u64,
    ) -> StacksHeaderInfo {
        StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis_block_header().into(),
            microblock_tail: None,
            stacks_block_height: 0,
            index_root: root_hash,
            burn_header_hash: first_burnchain_block_hash.clone(),
            burn_header_height: first_burnchain_block_height,
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            burn_header_timestamp: first_burnchain_block_timestamp,
            anchored_block_size: 0,
            burn_view: None,
            total_tenure_size: 0,
        }
    }

    pub fn is_first_mined(&self) -> bool {
        self.anchored_header.is_first_mined()
    }

    pub fn is_epoch_2_block(&self) -> bool {
        matches!(self.anchored_header, StacksBlockHeaderTypes::Epoch2(_))
    }

    pub fn is_nakamoto_block(&self) -> bool {
        matches!(self.anchored_header, StacksBlockHeaderTypes::Nakamoto(_))
    }

    pub fn header_type_name(&self) -> &str {
        match self.anchored_header {
            StacksBlockHeaderTypes::Epoch2(_) => "epoch2",
            StacksBlockHeaderTypes::Nakamoto(_) => "nakamoto",
        }
    }
}

impl FromRow<DBConfig> for DBConfig {
    fn from_row(row: &Row) -> Result<DBConfig, db_error> {
        let version: String = row.get_unwrap("version");
        let mainnet_i64: i64 = row.get_unwrap("mainnet");
        let chain_id_i64: i64 = row.get_unwrap("chain_id");

        let mainnet = mainnet_i64 != 0;
        let chain_id = chain_id_i64 as u32;

        Ok(DBConfig {
            version,
            mainnet,
            chain_id,
        })
    }
}

impl FromRow<StacksHeaderInfo> for StacksHeaderInfo {
    fn from_row(row: &Row) -> Result<StacksHeaderInfo, db_error> {
        let block_height: u64 = u64::from_column(row, "block_height")?;
        let index_root = TrieHash::from_column(row, "index_root")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let burn_header_hash = BurnchainHeaderHash::from_column(row, "burn_header_hash")?;
        let burn_header_height: u64 = u64::from_column(row, "burn_header_height")?;
        let burn_header_timestamp = u64::from_column(row, "burn_header_timestamp")?;
        let anchored_block_size_str: String = row.get_unwrap("block_size");
        let anchored_block_size = anchored_block_size_str
            .parse::<u64>()
            .map_err(|_| db_error::ParseError)?;

        let header_type: HeaderTypeNames =
            row.get("header_type").unwrap_or(HeaderTypeNames::Epoch2);
        let stacks_header: StacksBlockHeaderTypes = {
            match header_type {
                HeaderTypeNames::Epoch2 => StacksBlockHeader::from_row(row)?.into(),
                HeaderTypeNames::Nakamoto => NakamotoBlockHeader::from_row(row)?.into(),
            }
        };
        let burn_view = {
            match header_type {
                HeaderTypeNames::Epoch2 => None,
                HeaderTypeNames::Nakamoto => Some(ConsensusHash::from_column(row, "burn_view")?),
            }
        };

        if block_height != stacks_header.height() {
            return Err(db_error::ParseError);
        }

        let total_tenure_size = {
            match header_type {
                HeaderTypeNames::Epoch2 => 0,
                HeaderTypeNames::Nakamoto => u64::from_column(row, "total_tenure_size")?,
            }
        };

        Ok(StacksHeaderInfo {
            anchored_header: stacks_header,
            microblock_tail: None,
            stacks_block_height: block_height,
            index_root,
            consensus_hash,
            burn_header_hash,
            burn_header_height: burn_header_height as u32,
            burn_header_timestamp,
            anchored_block_size,
            burn_view,
            total_tenure_size,
        })
    }
}

pub type StacksDBTx<'a> = IndexDBTx<'a, (), StacksBlockId>;
pub type StacksDBConn<'a> = IndexDBConn<'a, (), StacksBlockId>;

pub struct ClarityTx<'a, 'b> {
    block: ClarityBlockConnection<'a, 'b>,
    pub config: DBConfig,
}

impl ClarityConnection for ClarityTx<'_, '_> {
    fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase),
    {
        ClarityConnection::with_clarity_db_readonly_owned(&mut self.block, to_do)
    }

    fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
    where
        F: FnOnce(&mut AnalysisDatabase) -> R,
    {
        self.block.with_analysis_db_readonly(to_do)
    }

    fn get_epoch(&self) -> StacksEpochId {
        self.block.get_epoch()
    }
}

impl<'a, 'b> ClarityTx<'a, 'b> {
    /// Wrap an externally-constructed [`ClarityBlockConnection`] into a `ClarityTx`.
    ///
    /// Public twin of the internal `ClarityTx { block, config }` construction used
    /// by `inner_clarity_tx_begin`. Paired with
    /// [`ClarityBlockConnection::from_writable_store`], it lets a caller run the
    /// whole consensus transaction engine (`process_transaction`, `finish_block`,
    /// `seal`, …) against a custom [`WritableMarfStore`] backend rather than the
    /// datastore owned by a `ClarityInstance`.
    ///
    /// `DBConfig` is derived from the block connection so mainnet/chain_id cannot
    /// disagree with the store being driven.
    pub fn from_block_connection(block: ClarityBlockConnection<'a, 'b>) -> ClarityTx<'a, 'b> {
        let config = DBConfig {
            mainnet: block.is_mainnet(),
            chain_id: block.chain_id(),
            version: CHAINSTATE_VERSION.to_string(),
        };
        ClarityTx { block, config }
    }

    pub fn cost_so_far(&self) -> ExecutionCost {
        self.block.cost_so_far()
    }

    pub fn get_epoch(&self) -> StacksEpochId {
        self.block.get_epoch()
    }

    /// Set the ClarityTx's cost tracker.
    /// Returns the replaced cost tracker.
    fn set_cost_tracker(&mut self, new_tracker: LimitedCostTracker) -> LimitedCostTracker {
        self.block.set_cost_tracker(new_tracker)
    }

    /// Returns the block limit for the block being created.
    pub fn block_limit(&self) -> Option<ExecutionCost> {
        self.block.block_limit()
    }

    /// Run `todo` in this ClarityTx with `new_tracker`.
    /// Returns the result of `todo` and the `new_tracker`
    pub fn with_temporary_cost_tracker<F, R>(
        &mut self,
        new_tracker: LimitedCostTracker,
        todo: F,
    ) -> (R, LimitedCostTracker)
    where
        F: FnOnce(&mut ClarityTx) -> R,
    {
        let original_tracker = self.set_cost_tracker(new_tracker);
        let result = todo(self);
        let new_tracker = self.set_cost_tracker(original_tracker);
        (result, new_tracker)
    }

    pub fn seal(&mut self) -> TrieHash {
        self.block.seal()
    }

    #[cfg(test)]
    pub fn commit_block(self) {
        self.block.commit_block();
    }

    pub fn commit_mined_block(
        self,
        block_hash: &StacksBlockId,
    ) -> Result<ExecutionCost, ClarityError> {
        Ok(self.block.commit_mined_block(block_hash)?.get_total())
    }

    pub fn commit_to_block(self, consensus_hash: &ConsensusHash, block_hash: &BlockHeaderHash) {
        let index_block_hash = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        self.block.commit_to_block(&index_block_hash);
    }

    pub fn precommit_to_block(
        self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> PreCommitClarityBlock<'a> {
        let index_block_hash = StacksBlockId::new(consensus_hash, block_hash);
        self.block.precommit_to_block(index_block_hash)
    }

    pub fn commit_unconfirmed(self) {
        self.block.commit_unconfirmed();
    }

    pub fn rollback_block(self) {
        self.block.rollback_block()
    }

    pub fn rollback_unconfirmed(self) {
        self.block.rollback_unconfirmed()
    }

    pub fn reset_cost(&mut self, cost: ExecutionCost) {
        self.block.reset_block_cost(cost);
    }

    pub fn connection(&mut self) -> &mut ClarityBlockConnection<'a, 'b> {
        &mut self.block
    }

    pub fn increment_ustx_liquid_supply(&mut self, incr_by: u128) {
        self.connection()
            .as_transaction(|tx| {
                tx.with_clarity_db(|db| {
                    db.increment_ustx_liquid_supply(incr_by)
                        .map_err(|e| e.into())
                })
            })
            .expect("FATAL: `ust-liquid-supply` overflowed");
    }
}

pub struct ChainstateTx<'a> {
    pub config: DBConfig,
    pub blocks_path: String,
    pub tx: StacksDBTx<'a>,
    pub root_path: String,
}

impl<'a> ChainstateTx<'a> {
    pub fn new(
        tx: StacksDBTx<'a>,
        blocks_path: String,
        root_path: String,
        config: DBConfig,
    ) -> ChainstateTx<'a> {
        ChainstateTx {
            config,
            blocks_path,
            tx,
            root_path,
        }
    }

    pub fn get_blocks_path(&self) -> &String {
        &self.blocks_path
    }

    pub fn commit(self) -> Result<(), db_error> {
        self.tx.commit()
    }

    pub fn get_config(&self) -> &DBConfig {
        &self.config
    }

    pub fn log_transactions_processed(&self, events: &[StacksTransactionReceipt]) {
        for tx_event in events.iter() {
            let txid = tx_event.transaction.txid();
            if let Err(e) = monitoring::log_transaction_processed(&txid, &self.root_path) {
                warn!("Failed to monitor TX processed: {:?}", e; "txid" => %txid);
            }
        }
    }
}

impl<'a> Deref for ChainstateTx<'a> {
    type Target = StacksDBTx<'a>;
    fn deref(&self) -> &StacksDBTx<'a> {
        &self.tx
    }
}

impl<'a> DerefMut for ChainstateTx<'a> {
    fn deref_mut(&mut self) -> &mut StacksDBTx<'a> {
        &mut self.tx
    }
}

pub const CHAINSTATE_VERSION: &str = "14";
pub const CHAINSTATE_VERSION_NUMBER: u32 = 14;

const CHAINSTATE_INITIAL_SCHEMA: &[&str] = &[
    "PRAGMA foreign_keys = ON;",
    r#"
    -- Anchored stacks block headers
    CREATE TABLE block_headers(
        version INTEGER NOT NULL,
        total_burn TEXT NOT NULL,       -- converted to/from u64
        total_work TEXT NOT NULL,       -- converted to/from u64
        proof TEXT NOT NULL,
        parent_block TEXT NOT NULL,             -- hash of parent Stacks block
        parent_microblock TEXT NOT NULL,
        parent_microblock_sequence INTEGER NOT NULL,
        tx_merkle_root TEXT NOT NULL,
        state_index_root TEXT NOT NULL,
        microblock_pubkey_hash TEXT NOT NULL,

        block_hash TEXT NOT NULL,                   -- NOTE: this is *not* unique, since two burn chain forks can commit to the same Stacks block.
        index_block_hash TEXT UNIQUE NOT NULL,      -- NOTE: this is the hash of the block hash and consensus hash of the burn block that selected it,
                                                    -- and is guaranteed to be globally unique (across all Stacks forks and across all PoX forks).
                                                    -- index_block_hash is the block hash fed into the MARF index.

        -- internal use only
        block_height INTEGER NOT NULL,
        index_root TEXT NOT NULL,                    -- root hash of the internal, not-consensus-critical MARF that allows us to track chainstate /fork metadata
        consensus_hash TEXT UNIQUE NOT NULL,         -- all consensus hashes are guaranteed to be unique
        burn_header_hash TEXT NOT NULL,              -- burn header hash corresponding to the consensus hash (NOT guaranteed to be unique, since we can have 2+ blocks per burn block if there's a PoX fork)
        burn_header_height INT NOT NULL,             -- height of the burnchain block header that generated this consensus hash
        burn_header_timestamp INT NOT NULL,          -- timestamp from burnchain block header that generated this consensus hash
        parent_block_id TEXT NOT NULL,               -- NOTE: this is the parent index_block_hash

        cost TEXT NOT NULL,
        block_size TEXT NOT NULL,       -- converted to/from u64
        affirmation_weight INTEGER NOT NULL,

        PRIMARY KEY(consensus_hash,block_hash)
    );"#,
    r#"
    -- scheduled payments
    -- no designated primary key since there can be duplicate entries
    CREATE TABLE payments(
        address TEXT NOT NULL,              -- miner that produced this block and microblock stream
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,
        parent_block_hash TEXT NOT NULL,
        parent_consensus_hash TEXT NOT NULL,
        coinbase TEXT NOT NULL,             -- encodes u128
        tx_fees_anchored TEXT NOT NULL,     -- encodes u128
        tx_fees_streamed TEXT NOT NULL,     -- encodes u128
        stx_burns TEXT NOT NULL,            -- encodes u128
        burnchain_commit_burn INT NOT NULL,
        burnchain_sortition_burn INT NOT NULL,
        miner INT NOT NULL,

        -- internal use
        stacks_block_height INTEGER NOT NULL,
        index_block_hash TEXT NOT NULL,     -- NOTE: can't enforce UNIQUE here, because there will be multiple entries per block
        vtxindex INT NOT NULL               -- user burn support vtxindex
    );"#,
    r#"
    -- users who supported miners
    CREATE TABLE user_supporters(
        address TEXT NOT NULL,
        support_burn INT NOT NULL,
        block_hash TEXT NOT NULL,
        consensus_hash TEXT NOT NULL,

        PRIMARY KEY(address,block_hash,consensus_hash)
    );"#,
    r#"
    CREATE TABLE db_config(
        version TEXT NOT NULL,
        mainnet INTEGER NOT NULL,
        chain_id INTEGER NOT NULL
    );"#,
    r#"
    -- Staging microblocks -- preprocessed microblocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_microblocks(anchored_block_hash TEXT NOT NULL,     -- this is the hash of the parent anchored block
                                     consensus_hash TEXT NOT NULL,          -- this is the hash of the burn chain block that holds the parent anchored block's block-commit
                                     index_block_hash TEXT NOT NULL,        -- this is the anchored block's index hash
                                     microblock_hash TEXT NOT NULL,
                                     parent_hash TEXT NOT NULL,             -- previous microblock
                                     index_microblock_hash TEXT NOT NULL,   -- this is the hash of consensus_hash and microblock_hash
                                     sequence INT NOT NULL,
                                     processed INT NOT NULL,
                                     orphaned INT NOT NULL,
                                     PRIMARY KEY(anchored_block_hash,consensus_hash,microblock_hash)
    );"#,
    r#"
    -- Staging microblocks data
    CREATE TABLE staging_microblocks_data(block_hash TEXT NOT NULL,
                                          block_data BLOB NOT NULL,
                                          PRIMARY KEY(block_hash)
    );"#,
    r#"
    -- Invalidated staging microblocks data
    CREATE TABLE invalidated_microblocks_data(block_hash TEXT NOT NULL,
                                              block_data BLOB NOT NULL,
                                              PRIMARY KEY(block_hash)
    );"#,
    r#"
    -- Staging blocks -- preprocessed blocks queued up for subsequent processing and inclusion in the chunk store.
    CREATE TABLE staging_blocks(anchored_block_hash TEXT NOT NULL,
                                parent_anchored_block_hash TEXT NOT NULL,
                                consensus_hash TEXT NOT NULL,
                                -- parent_consensus_hash is the consensus hash of the sortition that chose the parent Stacks block.
                                parent_consensus_hash TEXT NOT NULL,
                                parent_microblock_hash TEXT NOT NULL,
                                parent_microblock_seq INT NOT NULL,
                                microblock_pubkey_hash TEXT NOT NULL,
                                height INT NOT NULL,
                                attachable INT NOT NULL,            -- set to 1 if this block's parent is processed; 0 if not
                                orphaned INT NOT NULL,              -- set to 1 if this block can never be attached
                                processed INT NOT NULL,
                                commit_burn INT NOT NULL,
                                sortition_burn INT NOT NULL,
                                index_block_hash TEXT NOT NULL,           -- used internally; hash of consensus hash and anchored_block_hash
                                download_time INT NOT NULL,               -- how long the block was in-flight
                                arrival_time INT NOT NULL,                -- when this block was stored
                                processed_time INT NOT NULL,              -- when this block was processed
                                PRIMARY KEY(anchored_block_hash,consensus_hash)
    );"#,
    r#"
    CREATE TABLE transactions(
        id INTEGER PRIMARY KEY,
        txid TEXT NOT NULL,
        index_block_hash TEXT NOT NULL,
        tx_hex TEXT NOT NULL,
        result TEXT NOT NULL,
        UNIQUE (txid,index_block_hash)
    );"#,
];

const CHAINSTATE_SCHEMA_2: &[&str] = &[
    // new in epoch 2.05 (schema version 2)
    // table of blocks that applied an epoch transition
    r#"
    CREATE TABLE epoch_transitions(
        block_id TEXT PRIMARY KEY
    );"#,
    r#"
    UPDATE db_config SET version = "2";
    "#,
];

const CHAINSTATE_SCHEMA_3: &[&str] = &[
    // new in epoch 2.1 (schema version 3)
    // track mature miner rewards paid out, so we can report them in Clarity.
    r#"
    -- table for MinerRewards.
    -- For each block within in a fork, there will be exactly two miner records:
    -- * one that records the coinbase, anchored tx fee, and confirmed streamed tx fees, and
    -- * one that records only the produced streamed tx fees.
    -- The latter is determined once this block's stream gets subsequently confirmed.
    -- You query this table by passing both the parent and the child block hashes, since both the
    -- parent and child blocks determine the full reward for the parent block.
    CREATE TABLE matured_rewards(
        address TEXT NOT NULL,      -- address of the miner who produced the block
        recipient TEXT,             -- who received the reward (if different from the miner)
        vtxindex INTEGER NOT NULL,  -- will be 0 if this is the miner, >0 if this is a user burn support
        coinbase TEXT NOT NULL,
        tx_fees_anchored TEXT NOT NULL,
        tx_fees_streamed_confirmed TEXT NOT NULL,
        tx_fees_streamed_produced TEXT NOT NULL,

        -- fork identifier
        child_index_block_hash TEXT NOT NULL,
        parent_index_block_hash TEXT NOT NULL,

        -- there are two rewards records per (parent,child) pair. One will have a non-zero coinbase; the other will have a 0 coinbase.
        PRIMARY KEY(parent_index_block_hash,child_index_block_hash,coinbase)
    );"#,
    r#"
    -- Add a `recipient` column so that in Stacks 2.1, the block reward can be sent to someone besides the miner (e.g. a contract).
    -- If NULL, then the payment goes to the `address`.
    ALTER TABLE payments ADD COLUMN recipient TEXT;
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS index_matured_rewards_by_vtxindex ON matured_rewards(parent_index_block_hash,child_index_block_hash,vtxindex);
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS index_parent_block_id_by_block_id ON block_headers(index_block_hash,parent_block_id);
    "#,
    // table to map index block hashes to the txids of on-burnchain stacks operations that were
    // proessed
    r#"
    CREATE TABLE burnchain_txids(
        -- in epoch 2.x, this is the index block hash of the Stacks block.
        -- in epoch 3.x, this is the index block hash of the tenure-start block.
        index_block_hash TEXT PRIMARY KEY,
        -- this is a JSON-encoded list of txids
        txids TEXT NOT NULL
    );"#,
    r#"
    UPDATE db_config SET version = "3";
    "#,
];

const CHAINSTATE_SCHEMA_4: &[&str] = &[
    // schema change is JUST a new index, so just bump db_config.version
    //   and add the index to `CHAINSTATE_INDEXES` (which gets re-execed
    //   on every schema change)
    r#"
    UPDATE db_config SET version = "9";
    "#,
];

pub static CHAINSTATE_SCHEMA_5: &[&str] = &[
    // Schema change: drop the affirmation_weight column from pre_nakamoto block_headers and any indexes that reference it
    // but leave everything else the same
    r#"
    DROP INDEX IF EXISTS index_block_header_by_affirmation_weight;
    DROP INDEX IF EXISTS index_block_header_by_height_and_affirmation_weight;
    ALTER TABLE block_headers DROP COLUMN affirmation_weight;
    "#,
    r#"UPDATE db_config SET version = "11";"#,
];

const CHAINSTATE_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS index_block_hash_to_primary_key ON block_headers(index_block_hash,consensus_hash,block_hash);",
    "CREATE INDEX IF NOT EXISTS block_headers_hash_index ON block_headers(block_hash,block_height);",
    "CREATE INDEX IF NOT EXISTS block_index_hash_index ON block_headers(index_block_hash,consensus_hash,block_hash);",
    "CREATE INDEX IF NOT EXISTS block_headers_burn_header_height ON block_headers(burn_header_height);",
    "CREATE INDEX IF NOT EXISTS index_payments_block_hash_consensus_hash_vtxindex ON payments(block_hash,consensus_hash,vtxindex ASC);",
    "CREATE INDEX IF NOT EXISTS index_payments_index_block_hash_vtxindex ON payments(index_block_hash,vtxindex ASC);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_processed ON staging_microblocks(processed);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_orphaned ON staging_microblocks(orphaned);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash ON staging_microblocks(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash_processed ON staging_microblocks(index_block_hash,processed);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_index_hash_orphaned ON staging_microblocks(index_block_hash,orphaned);",
    "CREATE INDEX IF NOT EXISTS staging_microblocks_microblock_hash ON staging_microblocks(microblock_hash);",
    "CREATE INDEX IF NOT EXISTS processed_stacks_blocks ON staging_blocks(processed,anchored_block_hash,consensus_hash);",
    "CREATE INDEX IF NOT EXISTS orphaned_stacks_blocks ON staging_blocks(orphaned,anchored_block_hash,consensus_hash);",
    "CREATE INDEX IF NOT EXISTS parent_blocks ON staging_blocks(parent_anchored_block_hash);",
    "CREATE INDEX IF NOT EXISTS parent_consensus_hashes ON staging_blocks(parent_consensus_hash);",
    "CREATE INDEX IF NOT EXISTS index_block_hashes ON staging_blocks(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS height_stacks_blocks ON staging_blocks(height);",
    "CREATE INDEX IF NOT EXISTS txid_tx_index ON transactions(txid);",
    "CREATE INDEX IF NOT EXISTS index_block_hash_tx_index ON transactions(index_block_hash);",
    "CREATE INDEX IF NOT EXISTS index_headers_by_consensus_hash ON block_headers(consensus_hash);",
    "CREATE INDEX IF NOT EXISTS processable_block ON staging_blocks(processed, orphaned, attachable);",
];

pub use stacks_common::consts::MINER_REWARD_MATURITY;

// fraction (out of 100) of the coinbase a user will receive for reporting a microblock stream fork
pub const POISON_MICROBLOCK_COMMISSION_FRACTION: u128 = 5;

#[derive(Debug, Clone)]
pub struct ChainstateAccountBalance {
    pub address: String,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateAccountLockup {
    pub address: String,
    pub amount: u64,
    pub block_height: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateBNSNamespace {
    pub namespace_id: String,
    pub importer: String,
    pub buckets: String,
    pub base: u64,
    pub coeff: u64,
    pub nonalpha_discount: u64,
    pub no_vowel_discount: u64,
    pub lifetime: u64,
}

#[derive(Debug, Clone)]
pub struct ChainstateBNSName {
    pub fully_qualified_name: String,
    pub owner: String,
    pub zonefile_hash: String,
}

impl ChainstateAccountLockup {
    pub fn new(address: StacksAddress, amount: u64, block_height: u64) -> ChainstateAccountLockup {
        ChainstateAccountLockup {
            address: address.to_string(),
            amount,
            block_height,
        }
    }
}

pub struct ChainStateBootData {
    pub first_burnchain_block_hash: BurnchainHeaderHash,
    pub first_burnchain_block_height: u32,
    pub first_burnchain_block_timestamp: u32,
    pub initial_balances: Vec<(PrincipalData, u64)>,
    pub pox_constants: PoxConstants,
    pub post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx)>>,
    pub get_bulk_initial_lockups:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateAccountLockup>>>>,
    pub get_bulk_initial_balances:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateAccountBalance>>>>,
    pub get_bulk_initial_namespaces:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateBNSNamespace>>>>,
    pub get_bulk_initial_names:
        Option<Box<dyn FnOnce() -> Box<dyn Iterator<Item = ChainstateBNSName>>>>,
}

impl ChainStateBootData {
    pub fn new(
        burnchain: &Burnchain,
        initial_balances: Vec<(PrincipalData, u64)>,
        post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx)>>,
    ) -> ChainStateBootData {
        ChainStateBootData {
            first_burnchain_block_hash: burnchain.first_block_hash.clone(),
            first_burnchain_block_height: burnchain.first_block_height as u32,
            first_burnchain_block_timestamp: burnchain.first_block_timestamp,
            initial_balances,
            pox_constants: burnchain.pox_constants.clone(),
            post_flight_callback,
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_namespaces: None,
            get_bulk_initial_names: None,
        }
    }
}

/// Installs genesis boot contracts and imported genesis state.
pub struct ChainStateBootInstaller;

impl ChainStateBootInstaller {
    fn parse_genesis_address(addr: &str, mainnet: bool) -> PrincipalData {
        // Typical entries are BTC encoded addresses that need converted to STX
        let stacks_address = match LegacyBitcoinAddress::from_b58(addr) {
            Ok(addr) => StacksAddress::from_legacy_bitcoin_address(&addr),
            // A few addresses (from legacy placeholder accounts) are already STX addresses
            _ => match StacksAddress::from_string(addr) {
                Some(addr) => addr,
                None => panic!("Failed to parsed genesis address {addr}"),
            },
        };
        // Convert a given address to the currently running network mode (mainnet vs testnet).
        // All addresses from the Stacks 1.0 import data should be mainnet, but we'll handle either case.
        let converted_version = if mainnet {
            match stacks_address.version() {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                C32_ADDRESS_VERSION_TESTNET_MULTISIG => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                _ => stacks_address.version(),
            }
        } else {
            match stacks_address.version() {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                C32_ADDRESS_VERSION_MAINNET_MULTISIG => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
                _ => stacks_address.version(),
            }
        };

        let (_, bytes) = stacks_address.destruct();
        let principal: PrincipalData = StandardPrincipalData::new(converted_version, bytes.0)
            .expect("FATAL: infallible constant version byte is not valid")
            .into();

        return principal;
    }

    /// Instantiate the boot code and genesis state into a given [`ClarityTx`].
    ///
    /// This is the genesis (boot) block body: instantiate the boot contracts,
    /// import the Stacks 1.0 genesis balances/lockups/BNS state, set the PoX
    /// burnchain params, and credit the initial liquid uSTX — everything except the
    /// final `commit_to_block`. Extracted from [`Self::install_boot_code`] (which
    /// now calls it against a `MarfedKV`-backed tx) so the same boot can be run
    /// against *any* [`ClarityTx`] — e.g. one built over a custom
    /// [`WritableMarfStore`] via [`ClarityBlockConnection::from_writable_store_genesis`]
    /// — yielding a byte-identical genesis state root regardless of backend.
    ///
    /// Network mode (`mainnet` vs testnet) is taken from `clarity_tx.config` so it
    /// cannot disagree with the connection being written to.
    pub fn instantiate_boot_code(
        clarity_tx: &mut ClarityTx,
        boot_data: &mut ChainStateBootData,
    ) -> Result<Vec<StacksTransactionReceipt>, Error> {
        let mainnet = clarity_tx.config.mainnet;
        let tx_version = if mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let boot_code_address = boot_code_addr(mainnet);

        let boot_code_auth = boot_code_tx_auth(boot_code_address.clone());

        let mut boot_code_account = boot_code_acc(boot_code_address.clone(), 0);

        let mut initial_liquid_ustx = 0u128;
        let mut receipts = vec![];
        let boot_code = if mainnet {
            *boot::STACKS_BOOT_CODE_MAINNET
        } else {
            *boot::STACKS_BOOT_CODE_TESTNET
        };
        for (boot_code_name, boot_code_contract) in boot_code.iter() {
            debug!(
                "Instantiate boot code contract '{}' ({} bytes)...",
                boot_code_name,
                boot_code_contract.len()
            );

            let smart_contract = TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from(boot_code_name.to_string())
                        .expect("FATAL: invalid boot-code contract name"),
                    code_body: StacksString::from_str(boot_code_contract)
                        .expect("FATAL: invalid boot code body"),
                },
                None,
            );

            let boot_code_smart_contract =
                StacksTransaction::new(tx_version, boot_code_auth.clone(), smart_contract);

            let tx_receipt = clarity_tx.connection().as_transaction(|clarity| {
                clarity.process_transaction_payload(
                    &boot_code_smart_contract,
                    &boot_code_account,
                    &TransactionResourceBudgets::unlimited(),
                )
            })?;
            receipts.push(tx_receipt);

            boot_code_account.nonce += 1;
        }

        let mut allocation_events: Vec<StacksTransactionEvent> = vec![];
        if !boot_data.initial_balances.is_empty() {
            warn!(
                "Seeding {} balances coming from the config",
                boot_data.initial_balances.len()
            );
        }
        for (address, amount) in boot_data.initial_balances.iter() {
            clarity_tx.connection().as_transaction(|clarity| {
                clarity.account_genesis_credit(address, (*amount).into())
            });
            initial_liquid_ustx = initial_liquid_ustx
                .checked_add(*amount as u128)
                .expect("FATAL: liquid STX overflow");
            let mint_event =
                StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(STXMintEventData {
                    recipient: address.clone(),
                    amount: *amount as u128,
                }));
            allocation_events.push(mint_event);
        }

        clarity_tx.connection().as_transaction(|clarity| {
            // Balances
            if let Some(get_balances) = boot_data.get_bulk_initial_balances.take() {
                info!("Importing accounts from Stacks 1.0");
                let mut balances_count = 0;
                let initial_balances = get_balances();
                for balance in initial_balances {
                    balances_count += 1;
                    let stx_address = Self::parse_genesis_address(&balance.address, mainnet);
                    clarity.account_genesis_credit(&stx_address, balance.amount.into());
                    initial_liquid_ustx = initial_liquid_ustx
                        .checked_add(balance.amount as u128)
                        .expect("FATAL: liquid STX overflow");
                    let mint_event = StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(
                        STXMintEventData {
                            recipient: stx_address,
                            amount: balance.amount.into(),
                        },
                    ));
                    allocation_events.push(mint_event);
                }
                info!("Seeding {} balances coming from chain dump", balances_count);
            }

            // Lockups
            if let Some(get_schedules) = boot_data.get_bulk_initial_lockups.take() {
                info!("Initializing chain with lockups");
                let mut lockups_per_block: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
                let initial_lockups = get_schedules();
                for schedule in initial_lockups {
                    let stx_address = Self::parse_genesis_address(&schedule.address, mainnet);
                    let value = Value::Tuple(
                        TupleData::from_data(vec![
                            (
                                ClarityName::from_literal("recipient"),
                                Value::Principal(stx_address),
                            ),
                            (
                                ClarityName::from_literal("amount"),
                                Value::UInt(schedule.amount.into()),
                            ),
                        ])
                        .unwrap(),
                    );
                    match lockups_per_block.entry(schedule.block_height) {
                        Entry::Occupied(schedules) => {
                            schedules.into_mut().push(value);
                        }
                        Entry::Vacant(entry) => {
                            let schedules = vec![value];
                            entry.insert(schedules);
                        }
                    };
                }

                let lockup_contract_id = boot_code_id("lockup", mainnet);
                let epoch = clarity.get_epoch();
                clarity
                    .with_clarity_db(|db| {
                        for (block_height, schedule) in lockups_per_block.into_iter() {
                            let key = Value::UInt(block_height.into());
                            let value = Value::cons_list(schedule, &epoch).unwrap();
                            db.insert_entry_unknown_descriptor(
                                &lockup_contract_id,
                                "lockups",
                                key,
                                value,
                                &epoch,
                            )?;
                        }
                        Ok(())
                    })
                    .unwrap();
            }

            // BNS Namespace
            let bns_contract_id = boot_code_id("bns", mainnet);
            if let Some(get_namespaces) = boot_data.get_bulk_initial_namespaces.take() {
                info!("Initializing chain with namespaces");
                let epoch = clarity.get_epoch();
                clarity
                    .with_clarity_db(|db| {
                        let initial_namespaces = get_namespaces();
                        for entry in initial_namespaces {
                            let namespace = {
                                if !BNS_CHARS_REGEX.is_match(&entry.namespace_id) {
                                    panic!("Invalid namespace characters");
                                }
                                let buffer = entry.namespace_id.as_bytes();
                                Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                            };

                            let importer = {
                                let address = Self::parse_genesis_address(&entry.importer, mainnet);
                                Value::Principal(address)
                            };

                            let revealed_at = Value::UInt(0);
                            let launched_at = Value::UInt(0);
                            let lifetime = Value::UInt(entry.lifetime.into());
                            let price_function = {
                                let base = Value::UInt(entry.base.into());
                                let coeff = Value::UInt(entry.coeff.into());
                                let nonalpha_discount = Value::UInt(entry.nonalpha_discount.into());
                                let no_vowel_discount = Value::UInt(entry.no_vowel_discount.into());
                                let buckets: Vec<_> = entry
                                    .buckets
                                    .split(';')
                                    .map(|e| Value::UInt(e.parse::<u64>().unwrap().into()))
                                    .collect();
                                assert_eq!(buckets.len(), 16);

                                TupleData::from_data(vec![
                                    (
                                        ClarityName::from_literal("buckets"),
                                        Value::cons_list(buckets, &epoch).unwrap(),
                                    ),
                                    (ClarityName::from_literal("base"), base),
                                    (ClarityName::from_literal("coeff"), coeff),
                                    (
                                        ClarityName::from_literal("nonalpha-discount"),
                                        nonalpha_discount,
                                    ),
                                    (
                                        ClarityName::from_literal("no-vowel-discount"),
                                        no_vowel_discount,
                                    ),
                                ])
                                .unwrap()
                            };

                            let namespace_props = Value::Tuple(
                                TupleData::from_data(vec![
                                    (ClarityName::from_literal("revealed-at"), revealed_at),
                                    (
                                        ClarityName::from_literal("launched-at"),
                                        Value::some(launched_at).unwrap(),
                                    ),
                                    (ClarityName::from_literal("lifetime"), lifetime),
                                    (ClarityName::from_literal("namespace-import"), importer),
                                    (
                                        ClarityName::from_literal("can-update-price-function"),
                                        Value::Bool(true),
                                    ),
                                    (
                                        ClarityName::from_literal("price-function"),
                                        Value::Tuple(price_function),
                                    ),
                                ])
                                .unwrap(),
                            );

                            db.insert_entry_unknown_descriptor(
                                &bns_contract_id,
                                "namespaces",
                                namespace,
                                namespace_props,
                                &epoch,
                            )?;
                        }
                        Ok(())
                    })
                    .unwrap();
            }

            // BNS Names
            if let Some(get_names) = boot_data.get_bulk_initial_names.take() {
                info!("Initializing chain with names");
                let epoch = clarity.get_epoch();
                clarity
                    .with_clarity_db(|db| {
                        let initial_names = get_names();
                        for entry in initial_names {
                            let components: Vec<_> =
                                entry.fully_qualified_name.split('.').collect();
                            assert_eq!(components.len(), 2);

                            let namespace = {
                                let namespace_str = components.get(1).unwrap();
                                if !BNS_CHARS_REGEX.is_match(namespace_str) {
                                    panic!("Invalid namespace characters");
                                }
                                let buffer = namespace_str.as_bytes();
                                Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                            };

                            let name = {
                                let name_str = components.get(0).unwrap().to_string();
                                if !BNS_CHARS_REGEX.is_match(&name_str) {
                                    panic!("Invalid name characters");
                                }
                                let buffer = name_str.as_bytes();
                                Value::buff_from(buffer.to_vec()).expect("Invalid name")
                            };

                            let fqn = Value::Tuple(
                                TupleData::from_data(vec![
                                    (ClarityName::from_literal("namespace"), namespace),
                                    (ClarityName::from_literal("name"), name),
                                ])
                                .unwrap(),
                            );

                            let owner_address = Self::parse_genesis_address(&entry.owner, mainnet);

                            let zonefile_hash = {
                                if entry.zonefile_hash.is_empty() {
                                    Value::buff_from(vec![]).unwrap()
                                } else {
                                    let buffer = Hash160::from_hex(&entry.zonefile_hash)
                                        .expect("Invalid zonefile_hash");
                                    Value::buff_from(buffer.to_bytes().to_vec()).unwrap()
                                }
                            };

                            let expected_asset_type =
                                db.get_nft_key_type(&bns_contract_id, "names")?;
                            db.set_nft_owner(
                                &bns_contract_id,
                                "names",
                                &fqn,
                                &owner_address,
                                &expected_asset_type,
                                &epoch,
                            )?;

                            let registered_at = Value::UInt(0);
                            let name_props = Value::Tuple(
                                TupleData::from_data(vec![
                                    (
                                        ClarityName::from_literal("registered-at"),
                                        Value::some(registered_at).unwrap(),
                                    ),
                                    (ClarityName::from_literal("imported-at"), Value::none()),
                                    (ClarityName::from_literal("revoked-at"), Value::none()),
                                    (ClarityName::from_literal("zonefile-hash"), zonefile_hash),
                                ])
                                .unwrap(),
                            );

                            db.insert_entry_unknown_descriptor(
                                &bns_contract_id,
                                "name-properties",
                                fqn.clone(),
                                name_props,
                                &epoch,
                            )?;

                            db.insert_entry_unknown_descriptor(
                                &bns_contract_id,
                                "owner-name",
                                Value::Principal(owner_address),
                                fqn,
                                &epoch,
                            )?;
                        }
                        Ok(())
                    })
                    .unwrap();
            }
            info!("Saving Genesis block. This could take a while");
        });

        let allocations_tx = StacksTransaction::new(
            tx_version,
            boot_code_auth,
            TransactionPayload::TokenTransfer(
                PrincipalData::Standard(boot_code_address.into()),
                0,
                TokenTransferMemo([0u8; 34]),
            ),
        );
        let allocations_receipt = StacksTransactionReceipt::from_stx_transfer(
            allocations_tx,
            allocation_events,
            Value::okay_true(),
            ExecutionCost::ZERO,
        );
        receipts.push(allocations_receipt);

        if let Some(callback) = boot_data.post_flight_callback.take() {
            callback(&mut *clarity_tx);
        }

        // Setup burnchain parameters for pox contract
        let pox_constants = &boot_data.pox_constants;
        let contract = boot_code_id("pox", mainnet);
        let sender = PrincipalData::from(contract.clone());
        let params = vec![
            Value::UInt(boot_data.first_burnchain_block_height as u128),
            Value::UInt(pox_constants.prepare_length as u128),
            Value::UInt(pox_constants.reward_cycle_length as u128),
            Value::UInt(pox_constants.pox_rejection_fraction as u128),
        ];
        clarity_tx.connection().as_transaction(|conn| {
            conn.run_contract_call(
                &sender,
                None,
                &contract,
                "set-burnchain-parameters",
                &params,
                |_, _| None,
                &ResourceBudget::unlimited(),
            )
            .expect("Failed to set burnchain parameters in PoX contract");
        });

        clarity_tx
            .connection()
            .as_transaction(|tx| {
                tx.with_clarity_db(|db| {
                    db.increment_ustx_liquid_supply(initial_liquid_ustx)
                        .map_err(|e| e.into())
                })
            })
            .expect("FATAL: `ustx-liquid-supply` overflowed");
        Ok(receipts)
    }

    fn install_boot_code(
        chainstate: &mut StacksChainState<impl ChainStatePersistence>,
        boot_data: &mut ChainStateBootData,
    ) -> Result<Vec<StacksTransactionReceipt>, Error> {
        info!("Building genesis block");

        let receipts = {
            let mut clarity_tx = chainstate.genesis_block_begin(
                &NULL_BURN_STATE_DB,
                &BURNCHAIN_BOOT_CONSENSUS_HASH,
                &BOOT_BLOCK_HASH,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            let receipts = Self::instantiate_boot_code(&mut clarity_tx, boot_data)?;
            clarity_tx.commit_to_block(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
            receipts
        };

        // verify that genesis root hash is as expected
        {
            let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
                let index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &FIRST_BURNCHAIN_CONSENSUS_HASH,
                    &FIRST_STACKS_BLOCK_HASH,
                );
                marf.get_root_hash_at(&index_block_hash).unwrap()
            });

            info!("Computed Clarity state genesis"; "root_hash" => %genesis_root_hash);

            if chainstate.mainnet {
                assert_eq!(
                    &genesis_root_hash.to_string(),
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    "Incorrect root hash for genesis block computed. expected={} computed={}",
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    genesis_root_hash
                )
            }
        }

        {
            // add a block header entry for the boot code
            let mut tx = chainstate.index_tx_begin();
            let parent_hash = StacksBlockId::sentinel();
            let first_index_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );

            test_debug!(
                "Boot code headers index_put_begin {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_root_hash = tx.put_indexed_all(&parent_hash, &first_index_hash, &[], &[])?;

            test_debug!(
                "Boot code headers index_commit {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_tip_info = StacksHeaderInfo::genesis(
                first_root_hash,
                &boot_data.first_burnchain_block_hash,
                boot_data.first_burnchain_block_height,
                boot_data.first_burnchain_block_timestamp as u64,
            );

            StacksHeadersDb::insert_stacks_block_header(
                &tx,
                &parent_hash,
                &first_tip_info,
                &ExecutionCost::ZERO,
            )?;
            tx.commit()?;
        }

        debug!("Finish install boot code");
        Ok(receipts)
    }
}

impl StacksChainState<DiskChainStateBackend> {
    pub fn open(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(Self, Vec<StacksTransactionReceipt>), Error> {
        Self::open_and_exec(mainnet, chain_id, path_str, None, marf_opts)
    }
}

impl<B: ChainStatePersistence> StacksChainState<B> {
    /// Re-open the chainstate -- i.e. to get a new handle to it using an existing chain state's
    /// parameters
    pub fn reopen(&self) -> Result<(Self, Vec<StacksTransactionReceipt>), Error> {
        let config = ChainStateOpenConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            root_path: self.root_path.clone(),
            marf_opts: self.marf_opts.clone(),
        };
        let backend = self.backend.clone();
        let parts = backend.reopen_shared_parts(&config, self)?;
        Ok((
            Self::from_open_parts(self.mainnet, self.chain_id, backend, parts),
            vec![],
        ))
    }

    /// Open an independent handle suitable for constructing a mining candidate against this
    /// chainstate's current storage.
    pub fn open_mining_candidate(&self) -> Result<Self, Error> {
        let config = ChainStateOpenConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            root_path: self.root_path.clone(),
            marf_opts: self.marf_opts.clone(),
        };
        let backend = self.backend.clone();
        let parts = backend.open_mining_candidate_parts(&config, self)?;
        Ok(Self::from_open_parts(
            self.mainnet,
            self.chain_id,
            backend,
            parts,
        ))
    }

    /// Re-open the Nakamoto staging blocks DB through this chainstate's backend.
    pub fn reopen_nakamoto_staging_blocks(&self) -> Result<NakamotoStagingBlocksConn, Error> {
        let config = ChainStateOpenConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            root_path: self.root_path.clone(),
            marf_opts: self.marf_opts.clone(),
        };
        self.backend
            .reopen_nakamoto_staging_blocks(&config, &self.nakamoto_staging_blocks_conn)
    }

    /// Re-open the chainstate DB
    pub fn reopen_db(&self) -> Result<DBConn, Error> {
        #[cfg(any(test, feature = "testing"))]
        if DiskChainStateLayout::is_ephemeral_root_path(&self.root_path) {
            let state_index_path = self.state_index.get_db_path();
            if state_index_path != ":memory:"
                && crate::util_lib::db::is_sqlite_memory_path(state_index_path)
            {
                return crate::util_lib::db::sqlite_open(
                    state_index_path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
                    false,
                )
                .map_err(|e| Error::DBError(db_error::SqliteError(e)));
            }

            return Err(Error::DBError(db_error::Other(
                "ephemeral chainstate roots cannot be reopened from a filesystem path".into(),
            )));
        }

        let path = PathBuf::from(self.root_path.clone());
        let header_index_root_path = DiskChainStateLayout::header_index_root_path(path);
        let header_index_root = header_index_root_path
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();

        let state_index = DiskIndexDb::open_db(
            self.mainnet,
            self.chain_id,
            &header_index_root,
            self.marf_opts.clone(),
        )?;
        Ok(state_index.into_sqlite_conn())
    }
}

impl<B: ChainStatePersistence> StacksChainState<B> {
    fn from_open_parts(
        mainnet: bool,
        chain_id: u32,
        backend: B,
        parts: ChainStateOpenParts,
    ) -> Self {
        StacksChainState {
            mainnet,
            chain_id,
            clarity_state: parts.clarity_state,
            nakamoto_staging_blocks_conn: parts.nakamoto_staging_blocks_conn,
            state_index: parts.state_index,
            blocks_path: parts.blocks_path,
            clarity_state_index_path: parts.clarity_state_index_path,
            clarity_state_index_root: parts.clarity_state_index_root,
            root_path: parts.root_path,
            unconfirmed_state: None,
            fault_injection: StacksChainStateFaults::new(),
            marf_opts: parts.marf_opts,
            backend,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl StacksChainState<MemoryChainStateBackend> {
    #[cfg(any(test, feature = "testing"))]
    pub fn new_ephemeral(
        mainnet: bool,
        chain_id: u32,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(Self, Vec<StacksTransactionReceipt>), Error> {
        Self::new_ephemeral_with_backend(mainnet, chain_id, boot_data, marf_opts, |namespace| {
            MemoryChainStateBackend::for_namespace(namespace)
        })
    }
}

#[cfg(any(test, feature = "testing"))]
impl StacksChainState<SharedMemoryChainStateBackend> {
    #[cfg(any(test, feature = "testing"))]
    pub fn new_shared_ephemeral(
        mainnet: bool,
        chain_id: u32,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(Self, Vec<StacksTransactionReceipt>), Error> {
        Self::new_ephemeral_with_backend(mainnet, chain_id, boot_data, marf_opts, |namespace| {
            SharedMemoryChainStateBackend::for_namespace(namespace)
        })
    }

    /// Snapshot this chainstate into an isolated shared-memory backend.
    pub fn fork_shared_ephemeral(&self) -> Result<Self, Error> {
        let root_path = DiskChainStateLayout::ephemeral_root_path()?;
        let config = ChainStateOpenConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            root_path: root_path.clone(),
            marf_opts: self.marf_opts.clone(),
        };
        let backend = SharedMemoryChainStateBackend::for_namespace(&root_path);
        let parts = backend.snapshot_parts(&config, self)?;
        Ok(Self::from_open_parts(
            self.mainnet,
            self.chain_id,
            backend,
            parts,
        ))
    }
}

impl<B: ChainStatePersistence> StacksChainState<B> {
    #[cfg(any(test, feature = "testing"))]
    fn new_ephemeral_with_backend(
        mainnet: bool,
        chain_id: u32,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
        backend_for_namespace: impl FnOnce(&str) -> B,
    ) -> Result<(Self, Vec<StacksTransactionReceipt>), Error> {
        let marf_opts = marf_opts.map(|mut opts| {
            opts.external_blobs = false;
            opts
        });
        let root_path = DiskChainStateLayout::ephemeral_root_path()?;
        let config = ChainStateOpenConfig {
            mainnet,
            chain_id,
            root_path,
            marf_opts,
        };
        let backend = backend_for_namespace(&config.root_path);
        let parts = backend.open_parts(&config)?;
        let mut chainstate = Self::from_open_parts(mainnet, chain_id, backend, parts);

        let mut receipts = vec![];
        match boot_data {
            Some(boot_data) => {
                let mut res =
                    ChainStateBootInstaller::install_boot_code(&mut chainstate, boot_data)?;
                receipts.append(&mut res);
            }
            None => {
                panic!(
                    "StacksChainState initialization is required, but boot_data was not passed."
                );
            }
        }

        Ok((chainstate, receipts))
    }
}

impl StacksChainState<DiskChainStateBackend> {
    pub fn open_and_exec(
        mainnet: bool,
        chain_id: u32,
        path_str: &str,
        boot_data: Option<&mut ChainStateBootData>,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<(Self, Vec<StacksTransactionReceipt>), Error> {
        #[cfg(any(test, feature = "testing"))]
        if DiskChainStateLayout::is_ephemeral_root_path(path_str) {
            return Err(Error::DBError(db_error::Other(
                "ephemeral chainstate roots cannot be reopened from a filesystem path".into(),
            )));
        }

        DiskChainStateLayout::make_chainstate_dirs(path_str)?;
        let clarity_state_index_path =
            DiskChainStateLayout::vm_state_index_marf_path(PathBuf::from(path_str))
                .to_str()
                .ok_or_else(|| Error::DBError(db_error::ParseError))?
                .to_string();
        let init_required = fs::metadata(&clarity_state_index_path).is_err();
        let config = ChainStateOpenConfig {
            mainnet,
            chain_id,
            root_path: path_str.to_string(),
            marf_opts,
        };
        let backend = DiskChainStateBackend::for_root(path_str)?;
        let parts = backend.open_parts(&config)?;
        let mut chainstate = Self::from_open_parts(mainnet, chain_id, backend, parts);

        let mut receipts = vec![];
        match (init_required, boot_data) {
            (true, Some(boot_data)) => {
                let mut res =
                    ChainStateBootInstaller::install_boot_code(&mut chainstate, boot_data)?;
                receipts.append(&mut res);
            }
            (true, None) => {
                panic!(
                    "StacksChainState initialization is required, but boot_data was not passed."
                );
            }
            (false, _) => {}
        }

        Ok((chainstate, receipts))
    }
}

impl<B: ChainStatePersistence> StacksChainState<B> {
    pub fn config(&self) -> DBConfig {
        DBConfig {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            version: CHAINSTATE_VERSION.to_string(),
        }
    }

    /// Begin a transaction against the (indexed) stacks chainstate DB.
    /// Does not create a Clarity instance.
    pub fn index_tx_begin(&mut self) -> StacksDBTx<'_> {
        StacksDBTx::new(&mut self.state_index, ())
    }

    pub fn index_conn(&self) -> StacksDBConn<'_> {
        StacksDBConn::new(&self.state_index, ())
    }

    /// Begin a transaction against the underlying DB
    /// Does not create a Clarity instance, and does not affect the MARF.
    pub fn db_tx_begin(&mut self) -> Result<DBTx<'_>, Error> {
        self.state_index.storage_tx().map_err(Error::DBError)
    }

    /// Simultaneously begin a transaction against both the headers and blocks.
    /// Used when considering a new block to append the chain state.
    pub fn chainstate_tx_begin(&mut self) -> (ChainstateTx<'_>, &mut ClarityInstance) {
        let config = self.config();
        let blocks_path = self.blocks_path.clone();
        let clarity_instance = &mut self.clarity_state;
        let inner_tx = StacksDBTx::new(&mut self.state_index, ());

        let chainstate_tx =
            ChainstateTx::new(inner_tx, blocks_path, self.root_path.clone(), config);

        (chainstate_tx, clarity_instance)
    }

    // NOTE: used for testing in the stacks testnet code.
    // DO NOT CALL FROM PRODUCTION
    pub fn clarity_eval_read_only(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Value {
        let result = self.clarity_state.eval_read_only(
            parent_id_bhh,
            &HeadersDBConn(StacksDBConn::new(&self.state_index, ())),
            burn_dbconn,
            contract,
            code,
        );
        result.unwrap()
    }

    /// Checked eval-read-only
    pub fn eval_read_only(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        code: &str,
    ) -> Result<Value, ClarityError> {
        self.clarity_state.eval_read_only(
            parent_id_bhh,
            &HeadersDBConn(StacksDBConn::new(&self.state_index, ())),
            burn_dbconn,
            contract,
            code,
        )
    }

    /// Execute a public function in `contract` from a read-only DB context
    ///  Any mutations that occur will be rolled-back before returning, regardless of
    ///  an okay or error result.
    pub fn eval_fn_read_only(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_id_bhh: &StacksBlockId,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
    ) -> Result<Value, ClarityError> {
        let headers_db = HeadersDBConn(StacksDBConn::new(&self.state_index, ()));
        let mut conn = self.clarity_state.read_only_connection_checked(
            parent_id_bhh,
            &headers_db,
            burn_dbconn,
        )?;

        let args: Vec<_> = args
            .iter()
            .map(|x| SymbolicExpression::atom_value(x.clone()))
            .collect();

        let result = conn.with_readonly_clarity_env(
            self.mainnet,
            self.chain_id,
            contract.clone().into(),
            None,
            LimitedCostTracker::Free,
            |exec_state, invoke_ctx| {
                exec_state
                    .execute_contract(
                        invoke_ctx, contract, function, &args,
                        // read-only is set to `false` so that non-read-only functions
                        //  can be executed. any transformation is rolled back.
                        false,
                    )
                    .map_err(ClarityEvalError::from)
            },
        )?;

        Ok(result)
    }

    pub fn db(&self) -> &DBConn {
        self.state_index.sqlite_conn()
    }
}

/// Factory helpers for constructing Clarity block and unconfirmed transactions.
pub struct ClarityTxFactory;

impl ClarityTxFactory {
    /// Begin processing an epoch's transactions within the context of a chainstate transaction
    pub fn chainstate_block_begin<'a, 'b>(
        chainstate_tx: &'b ChainstateTx<'b>,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        let conf = chainstate_tx.config.clone();
        Self::inner_clarity_tx_begin(
            conf,
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin processing an epoch's transactions within the context of a chainstate transaction,
    /// but do so in a way that will not cause them to be persisted.  Used for replaying blocks.
    pub fn chainstate_ephemeral_block_begin<'a, 'b>(
        chainstate_tx: &'b ChainstateTx<'b>,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        let conf = chainstate_tx.config.clone();
        Self::inner_ephemeral_clarity_tx_begin(
            conf,
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }
}

impl<B: ChainStatePersistence> StacksChainState<B> {
    /// Begin a transaction against the Clarity VM, _outside of_ the context of a chainstate
    /// transaction.  Used by the miner for producing blocks.
    pub fn block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        ClarityTxFactory::inner_clarity_tx_begin(
            conf,
            &self.state_index,
            &mut self.clarity_state,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin an ephemeral transaction against the Clarity VM, _outside of_ the context of a chainstate
    /// transaction.  The block will not be stored to disk, even if it is committed.
    /// Used by code paths which need to replay blocks.
    pub fn ephemeral_block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        ClarityTxFactory::inner_ephemeral_clarity_tx_begin(
            conf,
            &self.state_index,
            &mut self.clarity_state,
            burn_dbconn,
            parent_consensus_hash,
            parent_block,
            new_consensus_hash,
            new_block,
        )
    }

    /// Begin a transaction against the Clarity VM for initiating the genesis block
    ///  the genesis block is special cased because it must be evaluated _before_ the
    ///  cost contract is loaded in the boot code.
    pub fn genesis_block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            ClarityTxFactory::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    pub fn with_clarity_marf<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut MARF<StacksBlockId>) -> R,
    {
        self.clarity_state.with_marf(f)
    }

    /// Run to_do on the state of the Clarity VM at the given chain tip.
    /// Returns Some(x: R) if the given parent_tip exists.
    /// Returns None if not
    pub fn with_read_only_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &StacksBlockId,
        to_do: F,
    ) -> Option<R>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        match NakamotoChainState::get_block_header(self.db(), parent_tip) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return None;
            }
            Err(e) => {
                warn!("Failed to query for {}: {:?}", parent_tip, &e);
                return None;
            }
        }
        let mut conn = match self.clarity_state.read_only_connection_checked(
            parent_tip,
            &self.state_index,
            burn_dbconn,
        ) {
            Ok(x) => Some(x),
            Err(e) => {
                warn!("Failed to load read only connection"; "err" => %e);
                None
            }
        }?;
        let result = to_do(&mut conn);
        Some(result)
    }

    /// Run to_do on the unconfirmed Clarity VM state
    pub fn with_read_only_unconfirmed_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        to_do: F,
    ) -> Result<Option<R>, Error>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        if let Some(unconfirmed) = self.unconfirmed_state.as_ref() {
            if !unconfirmed.is_readable() {
                return Ok(None);
            }
        }

        let mut unconfirmed_state_opt = self.unconfirmed_state.take();
        let res = if let Some(ref mut unconfirmed_state) = unconfirmed_state_opt {
            let mut conn = unconfirmed_state
                .clarity_inst
                .read_only_connection_checked(
                    &unconfirmed_state.unconfirmed_chain_tip,
                    &self.state_index,
                    burn_dbconn,
                )?;
            let result = to_do(&mut conn);
            Some(result)
        } else {
            None
        };
        self.unconfirmed_state = unconfirmed_state_opt;
        Ok(res)
    }

    /// Run to_do on the unconfirmed Clarity VM state if the tip refers to the unconfirmed state;
    /// otherwise run to_do on the confirmed state of the Clarity VM. If the tip doesn't exist,
    /// then return None.
    pub fn maybe_read_only_clarity_tx<F, R>(
        &mut self,
        burn_dbconn: &dyn BurnStateDB,
        parent_tip: &StacksBlockId,
        to_do: F,
    ) -> Result<Option<R>, Error>
    where
        F: FnOnce(&mut ClarityReadOnlyConnection) -> R,
    {
        let unconfirmed = if let Some(ref unconfirmed_state) = self.unconfirmed_state {
            *parent_tip == unconfirmed_state.unconfirmed_chain_tip
                && unconfirmed_state.is_readable()
        } else {
            false
        };

        if unconfirmed {
            self.with_read_only_unconfirmed_clarity_tx(burn_dbconn, to_do)
        } else {
            Ok(self.with_read_only_clarity_tx(burn_dbconn, parent_tip, to_do))
        }
    }
}

impl ClarityTxFactory {
    pub(crate) fn get_parent_index_block(
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
    ) -> StacksBlockId {
        if *parent_block == BOOT_BLOCK_HASH {
            // begin boot block
            StacksBlockId::sentinel()
        } else if *parent_block == FIRST_STACKS_BLOCK_HASH {
            // begin first-ever block
            StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            // subsequent block
            StacksBlockHeader::make_index_block_hash(parent_consensus_hash, parent_block)
        }
    }

    /// Begin an unconfirmed VM transaction, if there's no other open transaction for it.
    pub fn chainstate_begin_unconfirmed<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        tip: &StacksBlockId,
    ) -> ClarityTx<'a, 'b> {
        let inner_clarity_tx = clarity_instance.begin_unconfirmed(tip, headers_db, burn_dbconn);
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }
}

impl<B: ChainStatePersistence> StacksChainState<B> {
    /// Open a Clarity transaction against this chainstate's unconfirmed state, if it exists.
    pub fn begin_unconfirmed<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
    ) -> Option<ClarityTx<'a, 'a>> {
        let conf = self.config();
        if let Some(ref mut unconfirmed) = self.unconfirmed_state {
            if !unconfirmed.is_writable() {
                debug!("Unconfirmed state is not writable; cannot begin unconfirmed Clarity Tx");
                return None;
            }

            Some(ClarityTxFactory::chainstate_begin_unconfirmed(
                conf,
                &self.state_index,
                &mut unconfirmed.clarity_inst,
                burn_dbconn,
                &unconfirmed.confirmed_chain_tip,
            ))
        } else {
            debug!("Unconfirmed state is not instantiated; cannot begin unconfirmed Clarity Tx");
            None
        }
    }
}

impl ClarityTxFactory {
    /// Create a Clarity VM database transaction
    fn inner_clarity_tx_begin<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        // mix consensus hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the pair is)
        let parent_index_block =
            ClarityTxFactory::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_block(
            &parent_index_block,
            &new_index_block,
            headers_db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create an ephemeral Clarity VM database transaction.
    /// The child block, identified by `new_consensus_hash` and `new_block`, will be treated as
    /// ephemeral.
    fn inner_ephemeral_clarity_tx_begin<'a, 'b>(
        conf: DBConfig,
        headers_db: &'b dyn HeadersDB,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &'b dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'b> {
        // mix consensus hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the pair is)
        let parent_index_block =
            ClarityTxFactory::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing ephemeral Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child ephemeral MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent ephemeral MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_ephemeral(
            &parent_index_block,
            &new_index_block,
            headers_db,
            burn_dbconn,
        );

        test_debug!("Got ephemeral clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }
}

impl<B: ChainStatePersistence> StacksChainState<B> {
    /// Create a Clarity VM transaction connection for testing in 2.1
    #[cfg(test)]
    pub fn test_genesis_block_begin_2_1<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            ClarityTxFactory::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing test genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_test_genesis_block_2_1(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }

    /// Create a Clarity VM transaction connection for testing in 2.05
    #[cfg(test)]
    pub fn test_genesis_block_begin_2_05<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            ClarityTxFactory::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing test genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_test_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }
}

/// Chainstate metadata helpers over the MARF-backed SQL state.
pub struct ChainStateMetadataDb;

pub trait MicroblockPubkeyHashStore {
    /// Record the microblock public key hash for a block into the MARF'ed Clarity DB
    fn insert_microblock_pubkey_hash(
        &mut self,
        height: u32,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<(), Error>;

    /// Get the block height at which a microblock public key hash was used, if any
    fn has_microblock_pubkey_hash(
        &mut self,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<Option<u32>, Error>;
}

impl MicroblockPubkeyHashStore for ClarityTx<'_, '_> {
    fn insert_microblock_pubkey_hash(
        &mut self,
        height: u32,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<(), Error> {
        self.connection()
            .as_transaction(|tx| {
                tx.with_clarity_db(|ref mut db| {
                    db.insert_microblock_pubkey_hash_height(mblock_pubkey_hash, height)
                        .expect("FATAL: failed to store microblock public key hash to Clarity DB");
                    Ok(())
                })
            })
            .expect("FATAL: failed to store microblock public key hash");
        Ok(())
    }

    fn has_microblock_pubkey_hash(
        &mut self,
        mblock_pubkey_hash: &Hash160,
    ) -> Result<Option<u32>, Error> {
        let height_opt = self
            .connection()
            .with_clarity_db_readonly::<_, Result<_, ()>>(|ref mut db| {
                let height_opt = db
                    .get_microblock_pubkey_hash_height(mblock_pubkey_hash)
                    .expect("FATAL: failed to query microblock public key hash");
                Ok(height_opt)
            })
            .expect("FATAL: failed to query microblock public key hash");
        Ok(height_opt)
    }
}

impl ChainStateMetadataDb {
    /// Get the appropriate MARF index hash to use to identify a chain tip, given a block header
    pub fn get_index_hash(
        consensus_hash: &ConsensusHash,
        header_hash: &BlockHeaderHash,
    ) -> StacksBlockId {
        if consensus_hash == &FIRST_BURNCHAIN_CONSENSUS_HASH {
            StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        } else {
            StacksBlockId::new(consensus_hash, header_hash)
        }
    }

    /// Get the burnchain txids for a given index block hash
    pub(crate) fn get_burnchain_txids_for_block(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Vec<Txid>, Error> {
        let sql = "SELECT txids FROM burnchain_txids WHERE index_block_hash = ?1";
        let args = params![index_block_hash];

        let txids = conn
            .query_row(sql, args, |r| {
                let txids_json: String = r.get_unwrap(0);
                let txids: Vec<Txid> = serde_json::from_str(&txids_json)
                    .expect("FATAL: database corruption: could not parse TXID JSON");

                Ok(txids)
            })
            .optional()?
            .unwrap_or_default();

        Ok(txids)
    }

    /// Get the txids of the burnchain operations applied in the past N Stacks blocks.
    /// Only works for epoch 2.x
    pub fn get_burnchain_txids_in_ancestors(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
        count: u64,
    ) -> Result<HashSet<Txid>, Error> {
        let mut ret = HashSet::new();
        let ancestors = StacksHeadersDb::get_ancestor_index_hashes(conn, index_block_hash, count)?;
        for ancestor in ancestors.into_iter() {
            let txids = ChainStateMetadataDb::get_burnchain_txids_for_block(conn, &ancestor)?;
            for txid in txids.into_iter() {
                ret.insert(txid);
            }
        }
        Ok(ret)
    }

    /// Store all on-burnchain STX operations' txids by index block hash.
    /// `index_block_hash` is the tenure-start block.
    /// * For epoch 2.x, this is simply the block ID
    /// * for epoch 3.x and later, this is the first block in the tenure.
    pub fn store_burnchain_txids(
        tx: &DBTx,
        index_block_hash: &StacksBlockId,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
    ) -> Result<(), Error> {
        let mut txids: Vec<_> = burn_stack_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        let mut xfer_txids = burn_transfer_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        txids.append(&mut xfer_txids);

        let mut delegate_txids = burn_delegate_stx_ops
            .into_iter()
            .fold(vec![], |mut txids, op| {
                txids.push(op.txid);
                txids
            });

        txids.append(&mut delegate_txids);

        let mut vote_txids =
            burn_vote_for_aggregate_key_ops
                .into_iter()
                .fold(vec![], |mut txids, op| {
                    txids.push(op.txid);
                    txids
                });

        txids.append(&mut vote_txids);

        let txids_json =
            serde_json::to_string(&txids).expect("FATAL: could not serialize Vec<Txid>");
        let sql = "INSERT INTO burnchain_txids (index_block_hash, txids) VALUES (?1, ?2)";
        let args = params![index_block_hash, &txids_json];
        tx.execute(sql, args)?;
        Ok(())
    }

    /// Append a Stacks block to an existing Stacks block, and grant the miner the block reward.
    /// Return the new Stacks header info.
    pub fn advance_tip(
        headers_tx: &mut StacksDBTx<'_>,
        parent_tip: &StacksBlockHeader,
        parent_consensus_hash: &ConsensusHash,
        new_tip: &StacksBlockHeader,
        new_consensus_hash: &ConsensusHash,
        new_burn_header_hash: &BurnchainHeaderHash,
        new_burnchain_height: u32,
        new_burnchain_timestamp: u64,
        microblock_tail_opt: Option<StacksMicroblockHeader>,
        block_reward: &MinerPaymentSchedule,
        mature_miner_payouts: Option<(MinerReward, Vec<MinerReward>, MinerReward, MinerRewardInfo)>, // (miner, [users], parent, matured rewards)
        anchor_block_cost: &ExecutionCost,
        anchor_block_size: u64,
        applied_epoch_transition: bool,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
    ) -> Result<StacksHeaderInfo, Error> {
        if new_tip.parent_block != FIRST_STACKS_BLOCK_HASH {
            // not the first-ever block, so linkage must occur
            assert_eq!(new_tip.parent_block, parent_tip.block_hash());
        }

        assert_eq!(
            parent_tip
                .total_work
                .work
                .checked_add(1)
                .expect("Block height overflow"),
            new_tip.total_work.work
        );

        let parent_hash =
            ChainStateMetadataDb::get_index_hash(parent_consensus_hash, &parent_tip.block_hash());

        // store each indexed field
        test_debug!(
            "Headers index_put_begin {}-{}",
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash)
        );
        let root_hash = headers_tx.put_indexed_all(
            &parent_hash,
            &new_tip.index_block_hash(new_consensus_hash),
            &[],
            &[],
        )?;
        let index_block_hash = new_tip.index_block_hash(new_consensus_hash);
        test_debug!(
            "Headers index_indexed_all finished {}-{}",
            &parent_hash,
            &index_block_hash,
        );

        let new_tip_info = StacksHeaderInfo {
            anchored_header: new_tip.clone().into(),
            microblock_tail: microblock_tail_opt,
            index_root: root_hash,
            stacks_block_height: new_tip.total_work.work,
            consensus_hash: new_consensus_hash.clone(),
            burn_header_hash: new_burn_header_hash.clone(),
            burn_header_height: new_burnchain_height,
            burn_header_timestamp: new_burnchain_timestamp,
            anchored_block_size: anchor_block_size,
            burn_view: None,
            total_tenure_size: 0,
        };

        StacksHeadersDb::insert_stacks_block_header(
            headers_tx.deref_mut(),
            &parent_hash,
            &new_tip_info,
            anchor_block_cost,
        )?;
        MinerRewardsDb::insert_miner_payment_schedule(headers_tx.deref_mut(), block_reward)?;
        ChainStateMetadataDb::store_burnchain_txids(
            headers_tx.deref(),
            &index_block_hash,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
            burn_vote_for_aggregate_key_ops,
        )?;

        if let Some((miner_payout, user_payouts, parent_payout, reward_info)) = mature_miner_payouts
        {
            let rewarded_miner_block_id = StacksBlockHeader::make_index_block_hash(
                &reward_info.from_block_consensus_hash,
                &reward_info.from_stacks_block_hash,
            );
            let rewarded_parent_miner_block_id = StacksBlockHeader::make_index_block_hash(
                &reward_info.from_parent_block_consensus_hash,
                &reward_info.from_parent_stacks_block_hash,
            );

            MinerRewardsDb::insert_matured_child_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &miner_payout,
            )?;
            for user_payout in user_payouts.into_iter() {
                MinerRewardsDb::insert_matured_child_user_reward(
                    headers_tx.deref_mut(),
                    &rewarded_parent_miner_block_id,
                    &rewarded_miner_block_id,
                    &user_payout,
                )?;
            }
            MinerRewardsDb::insert_matured_parent_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &parent_payout,
            )?;
        }

        if applied_epoch_transition {
            debug!("Block {} applied an epoch transition", &index_block_hash);
            let sql = "INSERT INTO epoch_transitions (block_id) VALUES (?)";
            let args = params![&index_block_hash];
            headers_tx.deref_mut().execute(sql, args)?;
        }

        info!(
            "Advanced to new tip! {}/{}",
            new_consensus_hash,
            new_tip.block_hash()
        );
        Ok(new_tip_info)
    }
}

#[cfg(test)]
pub mod test {
    use std::{env, fs};

    use clarity::vm::test_util::TEST_BURN_STATE_DB;
    use stx_genesis::GenesisData;

    use super::*;
    use crate::chainstate::stacks::*;
    use crate::util_lib::boot::boot_code_test_addr;
    use crate::util_lib::db::query_row;

    pub fn instantiate_chainstate(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
    ) -> StacksChainState<DiskChainStateBackend> {
        instantiate_chainstate_with_balances(mainnet, chain_id, test_name, vec![])
    }

    pub fn instantiate_chainstate_with_balances(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        balances: Vec<(StacksAddress, u64)>,
    ) -> StacksChainState<DiskChainStateBackend> {
        let path = chainstate_path(test_name);
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let initial_balances = balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_names: None,
            get_bulk_initial_namespaces: None,
        };

        StacksChainState::open_and_exec(mainnet, chain_id, &path, Some(&mut boot_data), None)
            .unwrap()
            .0
    }

    pub fn open_chainstate(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
    ) -> StacksChainState<DiskChainStateBackend> {
        let path = chainstate_path(test_name);
        StacksChainState::open(mainnet, chain_id, &path, None)
            .unwrap()
            .0
    }

    pub fn chainstate_path(test_name: &str) -> String {
        format!("/tmp/stacks-node-tests/cs-{}", test_name)
    }

    #[test]
    fn test_instantiate_chainstate() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());

        // verify that the boot code is there
        let mut conn = chainstate.block_begin(
            &TEST_BURN_STATE_DB,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        );

        for (boot_contract_name, _) in STACKS_BOOT_CODE_TESTNET.iter() {
            let boot_contract_id = QualifiedContractIdentifier::new(
                boot_code_test_addr().into(),
                ContractName::try_from(boot_contract_name.to_string()).unwrap(),
            );
            let contract_res = conn.get_contract(&boot_contract_id).unwrap();
            assert!(contract_res.is_some());
        }
    }

    /// Drive genesis boot through the public pluggable-store path:
    /// `from_writable_store_genesis` → `ClarityTx::from_block_connection` →
    /// `instantiate_boot_code`. Config/mainnet are derived from the connection
    /// rather than passed in separately.
    #[test]
    fn test_pluggable_store_instantiate_boot_code() {
        use clarity::vm::database::NULL_HEADER_DB;
        use stacks_common::consts::CHAIN_ID_TESTNET;

        let mut marf = MarfedKV::temporary();
        let parent = StacksBlockId::sentinel();
        let genesis = StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        );
        let store = marf.begin(&parent, &genesis);
        let block = ClarityBlockConnection::from_writable_store_genesis(
            Box::new(store),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
            false,
            CHAIN_ID_TESTNET,
        );
        assert!(!block.is_mainnet());
        assert_eq!(block.chain_id(), CHAIN_ID_TESTNET);

        let mut clarity_tx = ClarityTx::from_block_connection(block);
        assert_eq!(
            clarity_tx.config,
            DBConfig {
                mainnet: false,
                chain_id: CHAIN_ID_TESTNET,
                version: CHAINSTATE_VERSION.to_string(),
            }
        );

        let mut boot_data = ChainStateBootData {
            initial_balances: vec![],
            post_flight_callback: None,
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_names: None,
            get_bulk_initial_namespaces: None,
        };

        let receipts =
            ChainStateBootInstaller::instantiate_boot_code(&mut clarity_tx, &mut boot_data)
                .unwrap();
        assert!(
            !receipts.is_empty(),
            "boot should produce at least the contract-deploy receipts"
        );

        // Boot contracts should be present on the open connection before commit.
        for (boot_contract_name, _) in STACKS_BOOT_CODE_TESTNET.iter() {
            let boot_contract_id = QualifiedContractIdentifier::new(
                boot_code_test_addr().into(),
                ContractName::try_from(boot_contract_name.to_string()).unwrap(),
            );
            let contract_res = clarity_tx.get_contract(&boot_contract_id).unwrap();
            assert!(
                contract_res.is_some(),
                "missing boot contract {boot_contract_name}"
            );
        }

        clarity_tx.commit_to_block(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
    }

    #[test]
    fn test_chainstate_sampled_genesis_consistency() {
        // Test root hash for the test chainstate data set
        let mut boot_data = ChainStateBootData {
            initial_balances: vec![],
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::testnet_default(),
            post_flight_callback: None,
            get_bulk_initial_lockups: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_lockups().map(|item| {
                    ChainstateAccountLockup {
                        address: item.address,
                        amount: item.amount,
                        block_height: item.block_height,
                    }
                }))
            })),
            get_bulk_initial_balances: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_balances().map(|item| {
                    ChainstateAccountBalance {
                        address: item.address,
                        amount: item.amount,
                    }
                }))
            })),
            get_bulk_initial_namespaces: Some(Box::new(|| {
                Box::new(GenesisData::new(true).read_namespaces().map(|item| {
                    ChainstateBNSNamespace {
                        namespace_id: item.namespace_id,
                        importer: item.importer,
                        buckets: item.buckets,
                        base: item.base as u64,
                        coeff: item.coeff as u64,
                        nonalpha_discount: item.nonalpha_discount as u64,
                        no_vowel_discount: item.no_vowel_discount as u64,
                        lifetime: item.lifetime as u64,
                    }
                }))
            })),
            get_bulk_initial_names: Some(Box::new(|| {
                Box::new(
                    GenesisData::new(true)
                        .read_names()
                        .map(|item| ChainstateBNSName {
                            fully_qualified_name: item.fully_qualified_name,
                            owner: item.owner,
                            zonefile_hash: item.zonefile_hash,
                        }),
                )
            })),
        };

        let path = chainstate_path(function_name!());
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let mut chainstate =
            StacksChainState::open_and_exec(false, 0x80000000, &path, Some(&mut boot_data), None)
                .unwrap()
                .0;

        let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
            let index_block_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash).unwrap()
        });

        // If the genesis data changed, then this test will fail.
        // Just update the expected value
        assert_eq!(
            genesis_root_hash.to_string(),
            "0eb3076f0635ccdfcdc048afb8dea9048c5180a2e2b2952874af1d18f06321e8"
        );
    }

    #[test]
    fn test_chainstate_full_genesis_consistency() {
        if env::var("CIRCLE_CI_TEST") != Ok("1".into()) {
            return;
        }

        // Test root hash for the final chainstate data set
        let mut boot_data = ChainStateBootData {
            initial_balances: vec![],
            first_burnchain_block_hash: BurnchainHeaderHash::from_hex(
                BITCOIN_MAINNET_FIRST_BLOCK_HASH,
            )
            .unwrap(),
            first_burnchain_block_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT as u32,
            first_burnchain_block_timestamp: BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP,
            pox_constants: PoxConstants::mainnet_default(),
            post_flight_callback: None,
            get_bulk_initial_lockups: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_lockups().map(|item| {
                    ChainstateAccountLockup {
                        address: item.address,
                        amount: item.amount,
                        block_height: item.block_height,
                    }
                }))
            })),
            get_bulk_initial_balances: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_balances().map(|item| {
                    ChainstateAccountBalance {
                        address: item.address,
                        amount: item.amount,
                    }
                }))
            })),
            get_bulk_initial_namespaces: Some(Box::new(|| {
                Box::new(GenesisData::new(false).read_namespaces().map(|item| {
                    ChainstateBNSNamespace {
                        namespace_id: item.namespace_id,
                        importer: item.importer,
                        buckets: item.buckets,
                        base: item.base as u64,
                        coeff: item.coeff as u64,
                        nonalpha_discount: item.nonalpha_discount as u64,
                        no_vowel_discount: item.no_vowel_discount as u64,
                        lifetime: item.lifetime as u64,
                    }
                }))
            })),
            get_bulk_initial_names: Some(Box::new(|| {
                Box::new(
                    GenesisData::new(false)
                        .read_names()
                        .map(|item| ChainstateBNSName {
                            fully_qualified_name: item.fully_qualified_name,
                            owner: item.owner,
                            zonefile_hash: item.zonefile_hash,
                        }),
                )
            })),
        };

        let path = chainstate_path(function_name!());
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let mut chainstate =
            StacksChainState::open_and_exec(true, 0x000000001, &path, Some(&mut boot_data), None)
                .unwrap()
                .0;

        let genesis_root_hash = chainstate.clarity_state.with_marf(|marf| {
            let index_block_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash).unwrap()
        });

        // If the genesis data changed, then this test will fail.
        // Just update the expected value
        assert_eq!(
            format!("{}", genesis_root_hash),
            MAINNET_2_0_GENESIS_ROOT_HASH
        );
    }

    #[test]
    fn latest_db_version_supports_latest_epoch() {
        let db = DBConfig {
            version: CHAINSTATE_VERSION.to_string(),
            mainnet: true,
            chain_id: CHAIN_ID_MAINNET,
        };
        assert!(db.supports_epoch(StacksEpochId::latest()));
    }

    #[test]
    fn test_sqlite_version() {
        let chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        assert_eq!(
            query_row(chainstate.db(), "SELECT sqlite_version()", NO_PARAMS).unwrap(),
            Some("3.45.0".to_string())
        );
    }

    pub fn tmp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!("chainstate-test-{}.sqlite", rand::random::<u64>()))
    }

    #[test]
    fn chainstate_migration_v10_to_v11() -> Result<(), Error> {
        let test_name = "test_chainstate_migration_v10_to_v11";
        // Create an in-memory database
        let tmp_path = tmp_db_path();
        let conn = Connection::open(tmp_path.clone())?;

        // Simulate schema version 10 by applying all schemas up to NAKAMOTO_CHAINSTATE_SCHEMA_6
        for schema in CHAINSTATE_INITIAL_SCHEMA.iter() {
            conn.execute_batch(schema)?;
        }
        // Manually insert a version since chainstate initial schema just creates but doesn't insert anything
        // required for subsequent "updates" to be successful
        conn.execute(
            "INSERT INTO db_config (version, mainnet, chain_id) VALUES (?, ?, ?)",
            params!["1", 1, 1], // initial version 1
        )?;
        for schema in CHAINSTATE_SCHEMA_2.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in CHAINSTATE_SCHEMA_3.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_1.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_2.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_3.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_4.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_5.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in CHAINSTATE_SCHEMA_4.iter() {
            conn.execute_batch(schema)?;
        }
        for schema in NAKAMOTO_CHAINSTATE_SCHEMA_6.iter() {
            conn.execute_batch(schema)?;
        }

        // Insert dummy data into pre-nakamoto block_headers
        let sample_block_hash = BlockHeaderHash([1u8; 32]);
        let sample_consensus_hash = ConsensusHash([2u8; 20]);
        let sample_burn_header_hash = BurnchainHeaderHash([3u8; 32]);
        let sample_parent_block_id = StacksBlockId([0u8; 32]);
        let sample_index_block_hash =
            StacksBlockId::new(&sample_consensus_hash, &sample_block_hash);
        conn.execute(
            "INSERT INTO block_headers (
                version, total_burn, total_work, proof, parent_block, parent_microblock,
                parent_microblock_sequence, tx_merkle_root, state_index_root, microblock_pubkey_hash,
                block_hash, index_block_hash, block_height, index_root, consensus_hash,
                burn_header_hash, burn_header_height, burn_header_timestamp, parent_block_id,
                cost, block_size, affirmation_weight
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                1,
                "1000",
                "1",
                to_hex(&[0u8; 48]),
                to_hex(&[0u8; 32]),
                to_hex(&[0u8; 32]),
                0,
                to_hex(&[0u8; 32]),
                to_hex(&[0u8; 32]),
                to_hex(&[0u8; 20]),
                &sample_block_hash,
                &sample_index_block_hash,
                1,
                to_hex(&[0u8; 32]),
                &sample_consensus_hash,
                &sample_burn_header_hash,
                100,
                1234567890,
                &sample_parent_block_id,
                serde_json::to_string(&ExecutionCost::ZERO).unwrap(),
                "1000",
                10
            ],
        )?;

        // Verify schema version is 10 before migration
        let version: String = query_row(&conn, "SELECT version FROM db_config", NO_PARAMS)?
            .expect("Expected db_config to have a version");
        assert_eq!(
            version, "10",
            "Database version should be 10 before migration"
        );

        // Apply the simplified CHAINSTATE_SCHEMA_5 migration
        for statement in CHAINSTATE_SCHEMA_5.iter() {
            conn.execute_batch(statement)?;
        }
        // Verify schema version is updated to 11
        let version: String = query_row(&conn, "SELECT version FROM db_config", NO_PARAMS)?
            .expect("Expected db_config to have a version");
        assert_eq!(
            version, "11",
            "Database version should be 11 after migration"
        );

        // Verify affirmation_weight column is dropped
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(block_headers)")?
            .query_map([], |row| row.get(1))?
            .collect::<Result<Vec<String>, _>>()?;
        assert!(
            !columns.contains(&"affirmation_weight".to_string()),
            "affirmation_weight column should be dropped"
        );

        // Verify indexes are dropped
        let indexes: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'block_headers'")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        assert!(
            !indexes.contains(&"index_block_header_by_affirmation_weight".to_string()),
            "index_block_header_by_affirmation_weight should be dropped"
        );
        assert!(
            !indexes.contains(&"index_block_header_by_height_and_affirmation_weight".to_string()),
            "index_block_header_by_height_and_affirmation_weight should be dropped"
        );

        // Verify data integrity
        let row: Option<(String, String, String)> = conn
            .query_row(
                "SELECT block_hash, consensus_hash, block_size
            FROM block_headers WHERE index_block_hash = ?",
                params![&sample_index_block_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        assert!(row.is_some(), "Sample data should remain after migration");

        let (block_hash, consensus_hash, block_size) = row.unwrap();
        assert_eq!(
            block_hash,
            sample_block_hash.to_string(),
            "Block hash should be preserved"
        );
        assert_eq!(
            consensus_hash,
            sample_consensus_hash.to_string(),
            "Consensus hash should be preserved"
        );
        assert_eq!(block_size, "1000", "Block size should be preserved");

        Ok(())
    }
}
