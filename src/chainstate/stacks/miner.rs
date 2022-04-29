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
use std::collections::HashSet;
use std::convert::From;
use std::fs;
use std::mem;

use crate::burnchains::PrivateKey;
use crate::burnchains::PublicKey;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionDBConn, SortitionHandleTx};
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::*;
use crate::chainstate::stacks::db::unconfirmed::UnconfirmedState;
use crate::chainstate::stacks::db::{
    blocks::MemPoolRejection, ChainstateTx, ClarityTx, MinerRewardInfo, StacksChainState,
    MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::events::{StacksTransactionEvent, StacksTransactionReceipt};
use crate::chainstate::stacks::Error;
use crate::chainstate::stacks::*;
use crate::clarity_vm::clarity::{ClarityConnection, ClarityInstance};
use crate::core::mempool::*;
use crate::core::*;
use crate::cost_estimates::metrics::CostMetric;
use crate::cost_estimates::CostEstimator;
use crate::net::Error as net_error;
use crate::types::StacksPublicKeyBuffer;
use clarity::vm::database::BurnStateDB;
use serde::Deserialize;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::MerkleTree;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};
use stacks_common::util::vrf::*;

use crate::chainstate::stacks::address::StacksAddressExtensions;
use crate::chainstate::stacks::db::blocks::SetupBlockResult;
use crate::chainstate::stacks::StacksBlockHeader;
use crate::chainstate::stacks::StacksMicroblockHeader;
use crate::codec::{read_next, write_next, StacksMessageCodec};
use crate::types::chainstate::BurnchainHeaderHash;
use crate::types::chainstate::StacksBlockId;
use crate::types::chainstate::TrieHash;
use crate::types::chainstate::{BlockHeaderHash, StacksAddress, StacksWorkScore};
use clarity::vm::clarity::TransactionConnection;

#[derive(Debug, Clone)]
pub struct BlockBuilderSettings {
    pub max_miner_time_ms: u64,
    pub mempool_settings: MemPoolWalkSettings,
}

impl BlockBuilderSettings {
    pub fn limited() -> BlockBuilderSettings {
        BlockBuilderSettings {
            max_miner_time_ms: u64::max_value(),
            mempool_settings: MemPoolWalkSettings::default(),
        }
    }

    pub fn max_value() -> BlockBuilderSettings {
        BlockBuilderSettings {
            max_miner_time_ms: u64::max_value(),
            mempool_settings: MemPoolWalkSettings::zero(),
        }
    }
}

#[derive(Clone)]
struct MicroblockMinerRuntime {
    bytes_so_far: u64,
    pub prev_microblock_header: Option<StacksMicroblockHeader>,
    considered: Option<HashSet<Txid>>,
    num_mined: u64,
    tip: StacksBlockId,

    // fault injection, inherited from unconfirmed
    disable_bytes_check: bool,
    disable_cost_check: bool,
}

/// The value of `BlockLimitFunction` holds the state of the size of the block being built.
/// As the value increases, the less we can add to blocks.
#[derive(PartialEq)]
enum BlockLimitFunction {
    /// The block size limit has not been hit, and there are no restrictions on what can be added to
    /// a block.
    NO_LIMIT_HIT,
    /// We have got a pretty full block, and so will not allow any more contract call or
    /// contract publish transactions to be added to this block.
    CONTRACT_LIMIT_HIT,
    /// We have a completely full block. No new transactions can be added to the block.
    LIMIT_REACHED,
}

pub struct MinerEpochInfo<'a> {
    pub chainstate_tx: ChainstateTx<'a>,
    pub clarity_instance: &'a mut ClarityInstance,
    pub burn_tip: BurnchainHeaderHash,
    pub burn_tip_height: u32,
    pub parent_microblocks: Vec<StacksMicroblock>,
    pub mainnet: bool,
}

impl From<&UnconfirmedState> for MicroblockMinerRuntime {
    fn from(unconfirmed: &UnconfirmedState) -> MicroblockMinerRuntime {
        let considered = unconfirmed
            .mined_txs
            .iter()
            .map(|(txid, _)| txid.clone())
            .collect();
        MicroblockMinerRuntime {
            bytes_so_far: unconfirmed.bytes_so_far,
            prev_microblock_header: unconfirmed.last_mblock.clone(),
            considered: Some(considered),
            num_mined: 0,
            tip: unconfirmed.confirmed_chain_tip.clone(),

            disable_bytes_check: unconfirmed.disable_bytes_check,
            disable_cost_check: unconfirmed.disable_cost_check,
        }
    }
}

/// Represents a successful transaction. This transaction should be added to the block.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionSuccess {
    pub tx: StacksTransaction,
    /// The fee that was charged to the user for doing this transaction.
    pub fee: u64,
    pub receipt: StacksTransactionReceipt,
}

/// Represents a failed transaction. Something went wrong when processing this transaction.
#[derive(Debug)]
pub struct TransactionError {
    pub tx: StacksTransaction,
    pub error: Error,
}

/// Represents a transaction that was skipped, but might succeed later.
#[derive(Debug)]
pub struct TransactionSkipped {
    pub tx: StacksTransaction,
    /// This error is the reason the transaction was skipped (ex: BlockTooBigError)
    pub error: Error,
}

/// Represents an event for a successful transaction. This transaction should be added to the block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionSuccessEvent {
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub txid: Txid,
    pub fee: u64,
    pub execution_cost: ExecutionCost,
    pub result: Value,
}

/// Represents an event for a failed transaction. Something went wrong when processing this transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionErrorEvent {
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub txid: Txid,
    pub error: String,
}

/// Represents an event for a transaction that was skipped, but might succeed later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionSkippedEvent {
    #[serde(deserialize_with = "hex_deserialize", serialize_with = "hex_serialize")]
    pub txid: Txid,
    pub error: String,
}

fn hex_serialize<S: serde::Serializer>(txid: &Txid, s: S) -> Result<S::Ok, S::Error> {
    let inst = txid.to_hex();
    s.serialize_str(inst.as_str())
}

fn hex_deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Txid, D::Error> {
    let inst_str = String::deserialize(d)?;
    Txid::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

/// `TransactionResult` represents the outcome of transaction processing.
/// We use this enum to involve the compiler in forcing us to always clearly
/// indicate the outcome of a transaction.
///
/// There are currently three outcomes for a transaction:
/// 1) succeed
/// 2) fail, may be tried again later
/// 3) be skipped for now, to be tried again later
#[derive(Debug)]
pub enum TransactionResult {
    /// Transaction has already succeeded.
    Success(TransactionSuccess),
    /// Transaction failed when processed.
    ProcessingError(TransactionError),
    /// Transaction wasn't ready to be be processed, but might succeed later.
    Skipped(TransactionSkipped),
}

/// This struct is used to transmit data about transaction results through either the `mined_block`
/// or `mined_microblock` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionEvent {
    /// Transaction has already succeeded.
    Success(TransactionSuccessEvent),
    /// Transaction failed. It may succeed later depending on the error.
    ProcessingError(TransactionErrorEvent),
    /// Transaction wasn't ready to be be processed, but might succeed later.
    /// The bool represents whether mempool propagation should halt or continue
    Skipped(TransactionSkippedEvent),
}

impl TransactionResult {
    /// Logs a queryable message for the case where `txid` has succeeded.
    pub fn log_transaction_success(tx: &StacksTransaction) {
        info!("Tx successfully processed.";
            "event_name" => %"transaction_result",
            "tx_id" => %tx.txid(),
            "event_type" => %"success",
        );
    }

    /// Logs a queryable message for the case where `txid` has failed
    /// with error `err`.
    pub fn log_transaction_error(tx: &StacksTransaction, err: &Error) {
        info!("Tx processing failed with error";
            "event_name" => "transaction_result",
            "reason" => %err,
            "tx_id" => %tx.txid(),
            "event_type" => "error",
        );
    }

    /// Logs a queryable message for the case where `tx` has been skipped
    /// for error `err`.
    pub fn log_transaction_skipped(tx: &StacksTransaction, err: &Error) {
        info!(
            "Tx processing skipped";
            "event_name" => "transaction_result",
            "tx_id" => %tx.txid(),
            "event_type" => "skip",
            "reason" => %err,
        );
    }

    /// Creates a `TransactionResult` backed by `TransactionSuccess`.
    /// This method logs "transaction success" as a side effect.
    pub fn success(
        transaction: &StacksTransaction,
        fee: u64,
        receipt: StacksTransactionReceipt,
    ) -> TransactionResult {
        Self::log_transaction_success(transaction);
        Self::Success(TransactionSuccess {
            tx: transaction.clone(),
            fee: fee,
            receipt: receipt,
        })
    }

    /// Creates a `TransactionResult` backed by `TransactionError`.
    /// This method logs "transaction error" as a side effect.
    pub fn error(transaction: &StacksTransaction, error: Error) -> TransactionResult {
        Self::log_transaction_error(transaction, &error);
        TransactionResult::ProcessingError(TransactionError {
            tx: transaction.clone(),
            error: error,
        })
    }

    /// Creates a `TransactionResult` backed by `TransactionSkipped`.
    /// This method logs "transaction skipped" as a side effect.
    /// Takes in a reason (String) and uses the default error type for
    /// skipped transactions, `StacksTransactionSkipped` for the associated error.
    pub fn skipped(transaction: &StacksTransaction, reason: String) -> TransactionResult {
        let error = Error::StacksTransactionSkipped(reason);
        Self::log_transaction_skipped(transaction, &error);
        TransactionResult::Skipped(TransactionSkipped {
            tx: transaction.clone(),
            error: error,
        })
    }

    /// Creates a `TransactionResult` backed by `TransactionSkipped`.
    /// This method logs "transaction skipped" as a side effect.
    pub fn skipped_due_to_error(
        transaction: &StacksTransaction,
        error: Error,
    ) -> TransactionResult {
        Self::log_transaction_skipped(transaction, &error);
        TransactionResult::Skipped(TransactionSkipped {
            tx: transaction.clone(),
            error: error,
        })
    }

    pub fn convert_to_event(&self) -> TransactionEvent {
        match &self {
            TransactionResult::Success(TransactionSuccess { tx, fee, receipt }) => {
                TransactionEvent::Success(TransactionSuccessEvent {
                    txid: tx.txid(),
                    fee: *fee,
                    execution_cost: receipt.execution_cost.clone(),
                    result: receipt.result.clone(),
                })
            }
            TransactionResult::ProcessingError(TransactionError { tx, error }) => {
                TransactionEvent::ProcessingError(TransactionErrorEvent {
                    txid: tx.txid(),
                    error: error.to_string(),
                })
            }
            TransactionResult::Skipped(TransactionSkipped { tx, error }) => {
                TransactionEvent::Skipped(TransactionSkippedEvent {
                    txid: tx.txid(),
                    error: error.to_string(),
                })
            }
        }
    }

    /// Returns true iff this enum is backed by `TransactionSuccess`.
    pub fn is_ok(&self) -> bool {
        match &self {
            TransactionResult::Success(_) => true,
            _ => false,
        }
    }

    /// Returns a TransactionSuccess result as a pair of 1) fee and 2) receipt.
    /// Otherwise crashes.
    pub fn unwrap(self) -> (u64, StacksTransactionReceipt) {
        match self {
            TransactionResult::Success(TransactionSuccess {
                tx: _,
                fee,
                receipt,
            }) => (fee, receipt),
            _ => panic!("Tried to `unwrap` a non-success result."),
        }
    }

    /// Returns true iff this enum is backed by `Error`.
    pub fn is_err(&self) -> bool {
        match &self {
            TransactionResult::ProcessingError(_) => true,
            _ => false,
        }
    }

    /// Returns an Error result as an Error.
    /// Otherwise crashes.
    pub fn unwrap_err(self) -> Error {
        match self {
            TransactionResult::ProcessingError(TransactionError { tx: _, error }) => error,
            _ => panic!("Tried to `unwrap_error` a non-error result."),
        }
    }
}

///
///    Independent structure for building microblocks:
///       StacksBlockBuilder cannot be used, since microblocks should only be broadcasted
///       once the anchored block is mined, won sortition, and a StacksBlockBuilder will
///       not survive that long.
///
///     StacksMicroblockBuilder holds a mutable reference to the provided chainstate in the
///       new function. This is required for the `clarity_tx` -- basically, to append transactions
///       as new microblocks, the builder _needs_ to be able to keep the current clarity_tx "open"
pub struct StacksMicroblockBuilder<'a> {
    anchor_block: BlockHeaderHash,
    anchor_block_consensus_hash: ConsensusHash,
    anchor_block_height: u64,
    header_reader: StacksChainState,
    clarity_tx: Option<ClarityTx<'a, 'a>>,
    unconfirmed: bool,
    runtime: MicroblockMinerRuntime,
    settings: BlockBuilderSettings,
}

impl<'a> StacksMicroblockBuilder<'a> {
    pub fn new(
        anchor_block: BlockHeaderHash,
        anchor_block_consensus_hash: ConsensusHash,
        chainstate: &'a mut StacksChainState,
        burn_dbconn: &'a dyn BurnStateDB,
        settings: BlockBuilderSettings,
    ) -> Result<StacksMicroblockBuilder<'a>, Error> {
        let runtime = if let Some(unconfirmed_state) = chainstate.unconfirmed_state.as_ref() {
            MicroblockMinerRuntime::from(unconfirmed_state)
        } else {
            warn!("No unconfirmed state instantiated; cannot mine microblocks");
            return Err(Error::NoSuchBlockError);
        };

        let (header_reader, _) = chainstate.reopen()?;
        let anchor_block_height = StacksChainState::get_anchored_block_header_info(
            header_reader.db(),
            &anchor_block_consensus_hash,
            &anchor_block,
        )?
        .ok_or_else(|| {
            warn!(
                "No such block: {}/{}",
                &anchor_block_consensus_hash, &anchor_block
            );
            Error::NoSuchBlockError
        })?
        .stacks_block_height;

        // when we drop the miner, the underlying clarity instance will be rolled back
        chainstate.set_unconfirmed_dirty(true);

        // find parent block's execution cost
        let parent_index_hash =
            StacksBlockHeader::make_index_block_hash(&anchor_block_consensus_hash, &anchor_block);
        let cost_so_far =
            StacksChainState::get_stacks_block_anchored_cost(chainstate.db(), &parent_index_hash)?
                .ok_or(Error::NoSuchBlockError)?;

        // We need to open the chainstate _after_ any possible errors could occur, otherwise, we'd have opened
        //  the chainstate, but will lose the reference to the clarity_tx before the Drop handler for StacksMicroblockBuilder
        //  could take over.
        let mut clarity_tx = chainstate.block_begin(
            burn_dbconn,
            &anchor_block_consensus_hash,
            &anchor_block,
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        );

        debug!(
            "Begin microblock mining from {} from unconfirmed state with cost {:?}",
            &StacksBlockHeader::make_index_block_hash(&anchor_block_consensus_hash, &anchor_block),
            &cost_so_far
        );
        clarity_tx.reset_cost(cost_so_far);

        Ok(StacksMicroblockBuilder {
            anchor_block,
            anchor_block_consensus_hash,
            anchor_block_height,
            runtime: runtime,
            clarity_tx: Some(clarity_tx),
            header_reader,
            unconfirmed: false,
            settings: settings,
        })
    }

    /// Create a microblock miner off of the _unconfirmed_ chaintip, i.e., resuming construction of
    /// a microblock stream.
    pub fn resume_unconfirmed(
        chainstate: &'a mut StacksChainState,
        burn_dbconn: &'a dyn BurnStateDB,
        cost_so_far: &ExecutionCost,
        settings: BlockBuilderSettings,
    ) -> Result<StacksMicroblockBuilder<'a>, Error> {
        let runtime = if let Some(unconfirmed_state) = chainstate.unconfirmed_state.as_ref() {
            MicroblockMinerRuntime::from(unconfirmed_state)
        } else {
            warn!("No unconfirmed state instantiated; cannot mine microblocks");
            return Err(Error::NoSuchBlockError);
        };

        let (header_reader, _) = chainstate.reopen()?;
        let (anchored_consensus_hash, anchored_block_hash, anchored_block_height) =
            if let Some(unconfirmed) = chainstate.unconfirmed_state.as_ref() {
                let header_info =
                    StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                        chainstate.db(),
                        &unconfirmed.confirmed_chain_tip,
                    )?
                    .ok_or_else(|| {
                        warn!(
                            "No such confirmed block {}",
                            &unconfirmed.confirmed_chain_tip
                        );
                        Error::NoSuchBlockError
                    })?;
                (
                    header_info.consensus_hash,
                    header_info.anchored_header.block_hash(),
                    header_info.stacks_block_height,
                )
            } else {
                // unconfirmed state needs to be initialized
                debug!("Unconfirmed chainstate not initialized");
                return Err(Error::NoSuchBlockError)?;
            };

        let mut clarity_tx = chainstate.begin_unconfirmed(burn_dbconn).ok_or_else(|| {
            warn!(
                "Failed to begin-unconfirmed on {}/{}",
                &anchored_consensus_hash, &anchored_block_hash
            );
            Error::NoSuchBlockError
        })?;

        debug!(
            "Resume microblock mining from {} from unconfirmed state with cost {:?}",
            &StacksBlockHeader::make_index_block_hash(
                &anchored_consensus_hash,
                &anchored_block_hash
            ),
            cost_so_far
        );
        clarity_tx.reset_cost(cost_so_far.clone());

        Ok(StacksMicroblockBuilder {
            anchor_block: anchored_block_hash,
            anchor_block_consensus_hash: anchored_consensus_hash,
            anchor_block_height: anchored_block_height,
            runtime: runtime,
            clarity_tx: Some(clarity_tx),
            header_reader,
            unconfirmed: true,
            settings: settings,
        })
    }

    /// Produce a microblock, given its parent.
    /// No accounting state will be updated.
    pub fn make_next_microblock_from_txs(
        txs: Vec<StacksTransaction>,
        miner_key: &Secp256k1PrivateKey,
        parent_anchor_block_hash: &BlockHeaderHash,
        prev_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> Result<StacksMicroblock, Error> {
        let miner_pubkey_hash =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(miner_key));
        if txs.len() == 0 {
            return Err(Error::NoTransactionsToMine);
        }

        let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        let mut next_microblock_header = if let Some(ref prev_microblock) = prev_microblock_header {
            StacksMicroblockHeader::from_parent_unsigned(prev_microblock, &tx_merkle_root)
                .ok_or(Error::MicroblockStreamTooLongError)?
        } else {
            // .prev_block is the hash of the parent anchored block
            StacksMicroblockHeader::first_unsigned(parent_anchor_block_hash, &tx_merkle_root)
        };

        next_microblock_header.sign(miner_key).unwrap();
        next_microblock_header.verify(&miner_pubkey_hash).unwrap();
        Ok(StacksMicroblock {
            header: next_microblock_header,
            txs: txs,
        })
    }

    /// Produce the next microblock in the stream, unconditionally, from the given txs.
    /// Inner accouting state, like runtime and space, will be updated.
    /// Otherwise, no validity checking will be done.
    pub fn make_next_microblock(
        &mut self,
        txs: Vec<StacksTransaction>,
        miner_key: &Secp256k1PrivateKey,
        tx_events: Vec<TransactionEvent>,
        event_dispatcher: Option<&dyn MemPoolEventDispatcher>,
    ) -> Result<StacksMicroblock, Error> {
        let microblock = StacksMicroblockBuilder::make_next_microblock_from_txs(
            txs,
            miner_key,
            &self.anchor_block,
            self.runtime.prev_microblock_header.as_ref(),
        )?;
        self.runtime.prev_microblock_header = Some(microblock.header.clone());

        if let Some(dispatcher) = event_dispatcher {
            dispatcher.mined_microblock_event(
                &microblock,
                tx_events,
                self.anchor_block_consensus_hash,
                self.anchor_block,
            )
        }

        info!(
            "Miner: Created microblock block {} (seq={}) off of {}/{}: {} transaction(s)",
            microblock.block_hash(),
            microblock.header.sequence,
            self.anchor_block_consensus_hash,
            self.anchor_block,
            microblock.txs.len()
        );
        Ok(microblock)
    }

    /// Mine the next transaction into a microblock.
    /// Returns Ok(TransactionResult::Success) if the transaction was mined into this microblock.
    /// Returns Ok(TransactionResult::Skipped) if the transaction was not mined, but can be mined later.
    /// Returns Ok(TransactionResult::Error) if the transaction was not mined due to an error.
    /// Returns Err(e) if an error occurs during the function.
    ///
    /// This calls `StacksChainState::process_transaction` and also checks certain pre-conditions
    /// and handles errors.
    ///
    /// # Pre-Checks
    /// - skip if the `anchor_mode` rules out micro-blocks
    /// - skip if 'tx.txid()` is already in `considered`
    /// - skip if adding the block would result in a block size bigger than `MAX_EPOCH_SIZE`
    ///
    /// # Error Handling
    /// - If the error when processing a tx is `CostOverflowError`, reset the cost of the block.
    fn mine_next_transaction(
        clarity_tx: &mut ClarityTx,
        tx: StacksTransaction,
        tx_len: u64,
        bytes_so_far: u64,
        limit_behavior: &BlockLimitFunction,
    ) -> Result<TransactionResult, Error> {
        if tx.anchor_mode != TransactionAnchorMode::OffChainOnly
            && tx.anchor_mode != TransactionAnchorMode::Any
        {
            return Ok(TransactionResult::skipped_due_to_error(
                &tx,
                Error::InvalidStacksTransaction(
                    "Invalid transaction anchor mode for streamed data".to_string(),
                    false,
                ),
            ));
        }

        if bytes_so_far + tx_len >= MAX_EPOCH_SIZE.into() {
            info!(
                "Adding microblock tx {} would exceed epoch data size",
                &tx.txid()
            );
            return Ok(TransactionResult::skipped_due_to_error(
                &tx,
                Error::BlockTooBigError,
            ));
        }
        match limit_behavior {
            BlockLimitFunction::CONTRACT_LIMIT_HIT => {
                match &tx.payload {
                    TransactionPayload::ContractCall(cc) => {
                        // once we've hit the runtime limit once, allow boot code contract calls, but do not try to eval
                        //   other contract calls
                        if !cc.address.is_boot_code_addr() {
                            return Ok(TransactionResult::skipped(
                                &tx,
                                "BlockLimitFunction::CONTRACT_LIMIT_HIT".to_string(),
                            ));
                        }
                    }
                    TransactionPayload::SmartContract(_) => {
                        return Ok(TransactionResult::skipped(
                            &tx,
                            "BlockLimitFunction::CONTRACT_LIMIT_HIT".to_string(),
                        ));
                    }
                    _ => {}
                }
            }
            BlockLimitFunction::LIMIT_REACHED => {
                return Ok(TransactionResult::skipped(
                    &tx,
                    "BlockLimitFunction::LIMIT_REACHED".to_string(),
                ))
            }
            BlockLimitFunction::NO_LIMIT_HIT => {}
        };

        let quiet = !cfg!(test);
        match StacksChainState::process_transaction(clarity_tx, &tx, quiet) {
            Ok((fee, receipt)) => Ok(TransactionResult::success(&tx, fee, receipt)),
            Err(e) => {
                match &e {
                    Error::CostOverflowError(cost_before, cost_after, total_budget) => {
                        // note: this path _does_ not perform the tx block budget % heuristic,
                        //  because this code path is not directly called with a mempool handle.
                        clarity_tx.reset_cost(cost_before.clone());
                        if total_budget.proportion_largest_dimension(&cost_before)
                            < TX_BLOCK_LIMIT_PROPORTION_HEURISTIC
                        {
                            warn!(
                                "Transaction {} consumed over {}% of block budget, marking as invalid; budget was {}",
                                tx.txid(),
                                100 - TX_BLOCK_LIMIT_PROPORTION_HEURISTIC,
                                &total_budget
                            );
                            return Ok(TransactionResult::error(
                                &tx,
                                Error::TransactionTooBigError,
                            ));
                        } else {
                            warn!(
                                "Transaction {} reached block cost {}; budget was {}",
                                tx.txid(),
                                &cost_after,
                                &total_budget
                            );
                            return Ok(TransactionResult::skipped_due_to_error(
                                &tx,
                                Error::BlockTooBigError,
                            ));
                        }
                    }
                    _ => Ok(TransactionResult::error(&tx, e)),
                }
            }
        }
    }

    /// NOTE: this is only used in integration tests.
    pub fn mine_next_microblock_from_txs(
        &mut self,
        txs_and_lens: Vec<(StacksTransaction, u64)>,
        miner_key: &Secp256k1PrivateKey,
    ) -> Result<StacksMicroblock, Error> {
        let mut txs_included = vec![];

        let mut clarity_tx = self
            .clarity_tx
            .take()
            .expect("Microblock already open and processing");

        let mut considered = self
            .runtime
            .considered
            .take()
            .expect("Microblock already open and processing");

        let mut bytes_so_far = self.runtime.bytes_so_far;
        let mut num_txs = self.runtime.num_mined;
        let mut tx_events = Vec::new();
        let mut block_limit_hit = BlockLimitFunction::NO_LIMIT_HIT;

        let mut result = Ok(());
        for (tx, tx_len) in txs_and_lens.into_iter() {
            if considered.contains(&tx.txid()) {
                continue;
            } else {
                considered.insert(tx.txid());
            }

            match StacksMicroblockBuilder::mine_next_transaction(
                &mut clarity_tx,
                tx.clone(),
                tx_len,
                bytes_so_far,
                &block_limit_hit,
            ) {
                Ok(tx_result) => {
                    tx_events.push(tx_result.convert_to_event());
                    match tx_result {
                        TransactionResult::Success(..) => {
                            test_debug!("Include tx {} in microblock", tx.txid());
                            bytes_so_far += tx_len;
                            num_txs += 1;
                            txs_included.push(tx);
                        }
                        TransactionResult::Skipped(TransactionSkipped { error, .. })
                        | TransactionResult::ProcessingError(TransactionError { error, .. }) => {
                            test_debug!("Exclude tx {} from microblock", tx.txid());
                            match &error {
                                Error::BlockTooBigError => {
                                    // done mining -- our execution budget is exceeded.
                                    // Make the block from the transactions we did manage to get
                                    test_debug!("Block budget exceeded on tx {}", &tx.txid());
                                    if block_limit_hit == BlockLimitFunction::NO_LIMIT_HIT {
                                        test_debug!("Switch to mining stx-transfers only");
                                        block_limit_hit = BlockLimitFunction::CONTRACT_LIMIT_HIT;
                                    } else if block_limit_hit
                                        == BlockLimitFunction::CONTRACT_LIMIT_HIT
                                    {
                                        test_debug!(
                                            "Stop mining microblock block due to limit exceeded"
                                        );
                                        break;
                                    }
                                }
                                _ => {}
                            }
                            continue;
                        }
                    }
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }

        // do fault injection
        if self.runtime.disable_bytes_check {
            warn!("Fault injection: disabling miner limit on microblock stream size");
            bytes_so_far = 0;
        }
        if self.runtime.disable_cost_check {
            warn!("Fault injection: disabling miner limit on microblock runtime cost");
            clarity_tx.reset_cost(ExecutionCost::zero());
        }

        self.runtime.bytes_so_far = bytes_so_far;
        self.clarity_tx.replace(clarity_tx);
        self.runtime.considered.replace(considered);
        self.runtime.num_mined = num_txs;

        match result {
            Err(e) => {
                warn!("Error producing microblock: {}", e);
                return Err(e);
            }
            _ => {}
        }

        return self.make_next_microblock(txs_included, miner_key, tx_events, None);
    }

    pub fn mine_next_microblock(
        &mut self,
        mem_pool: &mut MemPoolDB,
        miner_key: &Secp256k1PrivateKey,
        event_dispatcher: &dyn MemPoolEventDispatcher,
    ) -> Result<StacksMicroblock, Error> {
        let mut txs_included = vec![];
        let mempool_settings = self.settings.mempool_settings.clone();

        let mut clarity_tx = self
            .clarity_tx
            .take()
            .expect("Microblock already open and processing");

        let mut considered = self
            .runtime
            .considered
            .take()
            .expect("Microblock already open and processing");

        let mut invalidated_txs = vec![];

        let mut bytes_so_far = self.runtime.bytes_so_far;
        let mut num_txs = self.runtime.num_mined;
        let mut num_selected = 0;
        let mut tx_events = Vec::new();
        let deadline = get_epoch_time_ms() + (self.settings.max_miner_time_ms as u128);
        let mut block_limit_hit = BlockLimitFunction::NO_LIMIT_HIT;

        mem_pool.reset_last_known_nonces()?;
        let stacks_epoch_id = clarity_tx.get_epoch();
        let block_limit = clarity_tx
            .block_limit()
            .expect("No block limit found for clarity_tx.");
        mem_pool.estimate_tx_rates(100, &block_limit, &stacks_epoch_id)?;

        debug!(
            "Microblock transaction selection begins (child of {}), bytes so far: {}",
            &self.anchor_block, bytes_so_far
        );
        let result = {
            let mut intermediate_result;
            loop {
                let mut num_added = 0;
                intermediate_result = mem_pool.iterate_candidates(
                    &mut clarity_tx,
                    self.anchor_block_height,
                    mempool_settings.clone(),
                    |clarity_tx, to_consider, estimator| {
                        let mempool_tx = &to_consider.tx;
                        let update_estimator = to_consider.update_estimate;

                        if get_epoch_time_ms() >= deadline {
                            debug!(
                                "Microblock miner deadline exceeded ({} ms)",
                                self.settings.max_miner_time_ms
                            );
                            return Ok(false);
                        }

                        if considered.contains(&mempool_tx.tx.txid()) {
                            return Ok(true);
                        } else {
                            considered.insert(mempool_tx.tx.txid());
                        }

                        match StacksMicroblockBuilder::mine_next_transaction(
                            clarity_tx,
                            mempool_tx.tx.clone(),
                            mempool_tx.metadata.len,
                            bytes_so_far,
                            &block_limit_hit,
                        ) {
                            Ok(tx_result) => {
                                tx_events.push(tx_result.convert_to_event());
                                match tx_result {
                                    TransactionResult::Success(TransactionSuccess {
                                        receipt,
                                        ..
                                    }) => {
                                        bytes_so_far += mempool_tx.metadata.len;

                                        if update_estimator {
                                            if let Err(e) = estimator.notify_event(
                                                &mempool_tx.tx.payload,
                                                &receipt.execution_cost,
                                                &block_limit,
                                                &stacks_epoch_id,
                                            ) {
                                                warn!("Error updating estimator";
                                              "txid" => %mempool_tx.metadata.txid,
                                              "error" => ?e);
                                            }
                                        }

                                        debug!(
                                            "Include tx {} ({}) in microblock",
                                            mempool_tx.tx.txid(),
                                            mempool_tx.tx.payload.name()
                                        );
                                        txs_included.push(mempool_tx.tx.clone());
                                        num_txs += 1;
                                        num_added += 1;
                                        num_selected += 1;
                                        Ok(true)
                                    }
                                    TransactionResult::Skipped(TransactionSkipped {
                                        error,
                                        ..
                                    })
                                    | TransactionResult::ProcessingError(TransactionError {
                                        error,
                                        ..
                                    }) => {
                                        match &error {
                                            Error::BlockTooBigError => {
                                                // done mining -- our execution budget is exceeded.
                                                // Make the block from the transactions we did manage to get
                                                debug!("Block budget exceeded on tx {}", &mempool_tx.tx.txid());
                                                if block_limit_hit == BlockLimitFunction::NO_LIMIT_HIT {
                                                    debug!("Block budget exceeded while mining microblock"; 
                                                        "tx" => %mempool_tx.tx.txid(), "next_behavior" => "Switch to mining stx-transfers only");
                                                    block_limit_hit =
                                                        BlockLimitFunction::CONTRACT_LIMIT_HIT;
                                                } else if block_limit_hit
                                                    == BlockLimitFunction::CONTRACT_LIMIT_HIT
                                                {
                                                    debug!("Block budget exceeded while mining microblock"; 
                                                        "tx" => %mempool_tx.tx.txid(), "next_behavior" => "Stop mining microblock");
                                                    block_limit_hit = BlockLimitFunction::LIMIT_REACHED;
                                                    return Ok(false);
                                                }
                                            }
                                            Error::TransactionTooBigError => {
                                                invalidated_txs.push(mempool_tx.metadata.txid);
                                            }
                                            _ => {}
                                        }
                                        return Ok(true)
                                    }
                                }
                            }
                            Err(e) => Err(e),
                        }
                    },
                );

                if intermediate_result.is_err() {
                    break;
                }

                if num_added == 0 {
                    break;
                }
            }
            intermediate_result
        };
        debug!(
            "Microblock transaction selection finished (child of {}); {} transactions selected",
            &self.anchor_block, num_selected
        );

        // do fault injection
        if self.runtime.disable_bytes_check {
            warn!("Fault injection: disabling miner limit on microblock stream size");
            bytes_so_far = 0;
        }
        if self.runtime.disable_cost_check {
            warn!("Fault injection: disabling miner limit on microblock runtime cost");
            clarity_tx.reset_cost(ExecutionCost::zero());
        }

        self.runtime.bytes_so_far = bytes_so_far;
        self.clarity_tx.replace(clarity_tx);
        self.runtime.considered.replace(considered);
        self.runtime.num_mined = num_txs;

        mem_pool.drop_txs(&invalidated_txs)?;
        event_dispatcher.mempool_txs_dropped(invalidated_txs, MemPoolDropReason::TOO_EXPENSIVE);

        match result {
            Ok(_) => {}
            Err(e) => {
                warn!("Failure building microblock: {}", e);
                return Err(e);
            }
        }

        return self.make_next_microblock(
            txs_included,
            miner_key,
            tx_events,
            Some(event_dispatcher),
        );
    }

    pub fn get_bytes_so_far(&self) -> u64 {
        self.runtime.bytes_so_far
    }

    pub fn get_cost_so_far(&self) -> Option<ExecutionCost> {
        self.clarity_tx.as_ref().map(|tx| tx.cost_so_far())
    }
}

impl<'a> Drop for StacksMicroblockBuilder<'a> {
    fn drop(&mut self) {
        debug!(
            "Drop StacksMicroblockBuilder";
            "chain tip" => %&self.runtime.tip,
            "txs mined off tip" => &self.runtime.considered.as_ref().map(|x| x.len()).unwrap_or(0),
            "txs added" => self.runtime.num_mined,
            "bytes so far" => self.runtime.bytes_so_far,
            "cost so far" => &format!("{:?}", &self.get_cost_so_far())
        );
        self.clarity_tx
            .take()
            .expect("Attempted to reclose closed microblock builder")
            .rollback_block()
    }
}

impl StacksBlockBuilder {
    fn from_parent_pubkey_hash(
        miner_id: usize,
        parent_chain_tip: &StacksHeaderInfo,
        total_work: &StacksWorkScore,
        proof: &VRFProof,
        pubkh: Hash160,
    ) -> StacksBlockBuilder {
        let header = StacksBlockHeader::from_parent_empty(
            &parent_chain_tip.anchored_header,
            parent_chain_tip.microblock_tail.as_ref(),
            total_work,
            proof,
            &pubkh,
        );

        let mut header_bytes = vec![];
        header
            .consensus_serialize(&mut header_bytes)
            .expect("FATAL: failed to serialize to vec");
        let bytes_so_far = header_bytes.len() as u64;

        StacksBlockBuilder {
            chain_tip: parent_chain_tip.clone(),
            txs: vec![],
            micro_txs: vec![],
            total_anchored_fees: 0,
            total_confirmed_streamed_fees: 0,
            total_streamed_fees: 0,
            bytes_so_far: bytes_so_far,
            anchored_done: false,
            parent_consensus_hash: parent_chain_tip.consensus_hash.clone(),
            parent_header_hash: header.parent_block.clone(),
            header: header,
            parent_microblock_hash: parent_chain_tip
                .microblock_tail
                .as_ref()
                .map(|ref hdr| hdr.block_hash()),
            prev_microblock_header: StacksMicroblockHeader::first_unsigned(
                &EMPTY_MICROBLOCK_PARENT_HASH,
                &Sha512Trunc256Sum([0u8; 32]),
            ), // will be updated
            miner_privkey: StacksPrivateKey::new(), // caller should overwrite this, or refrain from mining microblocks
            miner_payouts: None,
            miner_id: miner_id,
        }
    }

    pub fn from_parent(
        miner_id: usize,
        parent_chain_tip: &StacksHeaderInfo,
        total_work: &StacksWorkScore,
        proof: &VRFProof,
        microblock_privkey: &StacksPrivateKey,
    ) -> StacksBlockBuilder {
        let mut pubk = StacksPublicKey::from_private(microblock_privkey);
        pubk.set_compressed(true);
        let pubkh = Hash160::from_node_public_key(&pubk);

        let mut builder = StacksBlockBuilder::from_parent_pubkey_hash(
            miner_id,
            parent_chain_tip,
            total_work,
            proof,
            pubkh,
        );
        builder.miner_privkey = microblock_privkey.clone();
        builder
    }

    fn first_pubkey_hash(
        miner_id: usize,
        genesis_consensus_hash: &ConsensusHash,
        genesis_burn_header_hash: &BurnchainHeaderHash,
        genesis_burn_header_height: u32,
        genesis_burn_header_timestamp: u64,
        proof: &VRFProof,
        pubkh: Hash160,
    ) -> StacksBlockBuilder {
        let genesis_chain_tip = StacksHeaderInfo {
            anchored_header: StacksBlockHeader::genesis_block_header(),
            microblock_tail: None,
            stacks_block_height: 0,
            index_root: TrieHash([0u8; 32]),
            consensus_hash: genesis_consensus_hash.clone(),
            burn_header_hash: genesis_burn_header_hash.clone(),
            burn_header_timestamp: genesis_burn_header_timestamp,
            burn_header_height: genesis_burn_header_height,
            anchored_block_size: 0,
        };

        let mut builder = StacksBlockBuilder::from_parent_pubkey_hash(
            miner_id,
            &genesis_chain_tip,
            &StacksWorkScore::initial(),
            proof,
            pubkh,
        );
        builder.header.parent_block = EMPTY_MICROBLOCK_PARENT_HASH.clone();
        builder
    }

    pub fn first(
        miner_id: usize,
        genesis_consensus_hash: &ConsensusHash,
        genesis_burn_header_hash: &BurnchainHeaderHash,
        genesis_burn_header_height: u32,
        genesis_burn_header_timestamp: u64,
        proof: &VRFProof,
        microblock_privkey: &StacksPrivateKey,
    ) -> StacksBlockBuilder {
        let mut pubk = StacksPublicKey::from_private(microblock_privkey);
        pubk.set_compressed(true);
        let pubkh = Hash160::from_node_public_key(&pubk);

        let mut builder = StacksBlockBuilder::first_pubkey_hash(
            miner_id,
            genesis_consensus_hash,
            genesis_burn_header_hash,
            genesis_burn_header_height,
            genesis_burn_header_timestamp,
            proof,
            pubkh,
        );
        builder.miner_privkey = microblock_privkey.clone();
        builder
    }

    /// Assign the block parent
    pub fn set_parent_block(&mut self, parent_block_hash: &BlockHeaderHash) -> () {
        self.header.parent_block = parent_block_hash.clone();
    }

    /// Assign the anchored block's parent microblock (used for testing orphaning)
    pub fn set_parent_microblock(
        &mut self,
        parent_mblock_hash: &BlockHeaderHash,
        parent_mblock_seq: u16,
    ) -> () {
        self.header.parent_microblock = parent_mblock_hash.clone();
        self.header.parent_microblock_sequence = parent_mblock_seq;
    }

    /// Set the block header's public key hash
    pub fn set_microblock_pubkey_hash(&mut self, pubkh: Hash160) -> bool {
        if self.anchored_done {
            // too late
            return false;
        }

        self.header.microblock_pubkey_hash = pubkh;
        return true;
    }

    /// Reset measured costs and fees
    pub fn reset_costs(&mut self) -> () {
        self.total_anchored_fees = 0;
        self.total_confirmed_streamed_fees = 0;
        self.total_streamed_fees = 0;
    }

    /// Append a transaction if doing so won't exceed the epoch data size.
    /// Errors out if we fail to mine the tx (exceed budget, or the transaction is invalid).
    pub fn try_mine_tx(
        &mut self,
        clarity_tx: &mut ClarityTx,
        tx: &StacksTransaction,
    ) -> Result<TransactionResult, Error> {
        let tx_len = tx.tx_len();
        match self.try_mine_tx_with_len(clarity_tx, tx, tx_len, &BlockLimitFunction::NO_LIMIT_HIT) {
            TransactionResult::Success(s) => Ok(TransactionResult::Success(s)),
            TransactionResult::Skipped(TransactionSkipped { error, .. })
            | TransactionResult::ProcessingError(TransactionError { error, .. }) => Err(error),
        }
    }

    /// Append a transaction if doing so won't exceed the epoch data size.
    /// Errors out if we exceed budget, or the transaction is invalid.
    fn try_mine_tx_with_len(
        &mut self,
        clarity_tx: &mut ClarityTx,
        tx: &StacksTransaction,
        tx_len: u64,
        limit_behavior: &BlockLimitFunction,
    ) -> TransactionResult {
        if self.bytes_so_far + tx_len >= MAX_EPOCH_SIZE.into() {
            return TransactionResult::skipped_due_to_error(&tx, Error::BlockTooBigError);
        }

        match limit_behavior {
            BlockLimitFunction::CONTRACT_LIMIT_HIT => {
                match &tx.payload {
                    TransactionPayload::ContractCall(cc) => {
                        // once we've hit the runtime limit once, allow boot code contract calls, but do not try to eval
                        //   other contract calls
                        if !cc.address.is_boot_code_addr() {
                            return TransactionResult::skipped(
                                &tx,
                                "BlockLimitFunction::CONTRACT_LIMIT_HIT".to_string(),
                            );
                        }
                    }
                    TransactionPayload::SmartContract(_) => {
                        return TransactionResult::skipped(
                            &tx,
                            "BlockLimitFunction::CONTRACT_LIMIT_HIT".to_string(),
                        );
                    }
                    _ => {}
                }
            }
            BlockLimitFunction::LIMIT_REACHED => {
                return TransactionResult::skipped(
                    &tx,
                    "BlockLimitFunction::LIMIT_REACHED".to_string(),
                )
            }
            BlockLimitFunction::NO_LIMIT_HIT => {}
        };

        let quiet = !cfg!(test);
        let result = if !self.anchored_done {
            // building up the anchored blocks
            if tx.anchor_mode != TransactionAnchorMode::OnChainOnly
                && tx.anchor_mode != TransactionAnchorMode::Any
            {
                return TransactionResult::skipped_due_to_error(
                    tx,
                    Error::InvalidStacksTransaction(
                        "Invalid transaction anchor mode for anchored data".to_string(),
                        false,
                    ),
                );
            }

            let (fee, receipt) = match StacksChainState::process_transaction(clarity_tx, tx, quiet)
            {
                Ok((fee, receipt)) => (fee, receipt),
                Err(e) => match e {
                    Error::CostOverflowError(cost_before, cost_after, total_budget) => {
                        clarity_tx.reset_cost(cost_before.clone());
                        if total_budget.proportion_largest_dimension(&cost_before)
                            < TX_BLOCK_LIMIT_PROPORTION_HEURISTIC
                        {
                            warn!(
                                    "Transaction {} consumed over {}% of block budget, marking as invalid; budget was {}",
                                    tx.txid(),
                                    100 - TX_BLOCK_LIMIT_PROPORTION_HEURISTIC,
                                    &total_budget
                                );
                            return TransactionResult::error(&tx, Error::TransactionTooBigError);
                        } else {
                            warn!(
                                "Transaction {} reached block cost {}; budget was {}",
                                tx.txid(),
                                &cost_after,
                                &total_budget
                            );
                            return TransactionResult::skipped_due_to_error(
                                &tx,
                                Error::BlockTooBigError,
                            );
                        }
                    }
                    _ => return TransactionResult::error(&tx, e),
                },
            };
            info!("Include tx";
                  "tx" => %tx.txid(),
                  "payload" => tx.payload.name(),
                  "origin" => %tx.origin_address());

            // save
            self.txs.push(tx.clone());
            self.total_anchored_fees += fee;

            TransactionResult::success(&tx, fee, receipt)
        } else {
            // building up the microblocks
            if tx.anchor_mode != TransactionAnchorMode::OffChainOnly
                && tx.anchor_mode != TransactionAnchorMode::Any
            {
                return TransactionResult::skipped_due_to_error(
                    tx,
                    Error::InvalidStacksTransaction(
                        "Invalid transaction anchor mode for streamed data".to_string(),
                        false,
                    ),
                );
            }

            let (fee, receipt) = match StacksChainState::process_transaction(clarity_tx, tx, quiet)
            {
                Ok((fee, receipt)) => (fee, receipt),
                Err(e) => match e {
                    Error::CostOverflowError(cost_before, cost_after, total_budget) => {
                        clarity_tx.reset_cost(cost_before.clone());
                        if total_budget.proportion_largest_dimension(&cost_before)
                            < TX_BLOCK_LIMIT_PROPORTION_HEURISTIC
                        {
                            warn!(
                                "Transaction {} consumed over {}% of block budget, marking as invalid; budget was {}",
                                tx.txid(),
                                100 - TX_BLOCK_LIMIT_PROPORTION_HEURISTIC,
                                &total_budget
                            );
                            return TransactionResult::error(&tx, Error::TransactionTooBigError);
                        } else {
                            warn!(
                                "Transaction {} reached block cost {}; budget was {}",
                                tx.txid(),
                                &cost_after,
                                &total_budget
                            );
                            return TransactionResult::skipped_due_to_error(
                                &tx,
                                Error::BlockTooBigError,
                            );
                        }
                    }
                    _ => return TransactionResult::error(&tx, e),
                },
            };
            debug!(
                "Include tx {} ({}) in microblock",
                tx.txid(),
                tx.payload.name()
            );

            // save
            self.micro_txs.push(tx.clone());
            self.total_streamed_fees += fee;

            TransactionResult::success(&tx, fee, receipt)
        };

        self.bytes_so_far += tx_len;
        result
    }

    /// Append a transaction if doing so won't exceed the epoch data size.
    /// Does not check for errors
    #[cfg(test)]
    pub fn force_mine_tx(
        &mut self,
        clarity_tx: &mut ClarityTx,
        tx: &StacksTransaction,
    ) -> Result<(), Error> {
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes)
            .map_err(Error::CodecError)?;
        let tx_len = tx_bytes.len() as u64;

        if self.bytes_so_far + tx_len >= MAX_EPOCH_SIZE.into() {
            warn!(
                "Epoch size is {} >= {}",
                self.bytes_so_far + tx_len,
                MAX_EPOCH_SIZE
            );
        }

        let quiet = !cfg!(test);
        if !self.anchored_done {
            // save
            match StacksChainState::process_transaction(clarity_tx, tx, quiet) {
                Ok((fee, receipt)) => {
                    self.total_anchored_fees += fee;
                }
                Err(e) => {
                    warn!("Invalid transaction {} in anchored block, but forcing inclusion (error: {:?})", &tx.txid(), &e);
                }
            }

            self.txs.push(tx.clone());
        } else {
            match StacksChainState::process_transaction(clarity_tx, tx, quiet) {
                Ok((fee, receipt)) => {
                    self.total_streamed_fees += fee;
                }
                Err(e) => {
                    warn!(
                        "Invalid transaction {} in microblock, but forcing inclusion (error: {:?})",
                        &tx.txid(),
                        &e
                    );
                }
            }

            self.micro_txs.push(tx.clone());
        }

        self.bytes_so_far += tx_len;
        Ok(())
    }

    pub fn finalize_block(&mut self, clarity_tx: &mut ClarityTx) -> StacksBlock {
        // done!  Calculate state root and tx merkle root
        let txid_vecs = self
            .txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        let state_root_hash = clarity_tx.seal();

        self.header.tx_merkle_root = tx_merkle_root;
        self.header.state_index_root = state_root_hash;

        let block = StacksBlock {
            header: self.header.clone(),
            txs: self.txs.clone(),
        };

        self.prev_microblock_header = StacksMicroblockHeader::first_unsigned(
            &block.block_hash(),
            &Sha512Trunc256Sum([0u8; 32]),
        );

        self.prev_microblock_header.prev_block = block.block_hash();
        self.anchored_done = true;

        test_debug!(
            "\n\nMiner {}: Mined anchored block {}, {} transactions, state root is {}\n",
            self.miner_id,
            block.block_hash(),
            block.txs.len(),
            state_root_hash
        );

        info!(
            "Miner: mined anchored block {} height {} with {} txs, parent block {}, parent microblock {} ({}), state root = {}",
            block.block_hash(),
            block.header.total_work.work,
            block.txs.len(),
            &self.header.parent_block,
            &self.header.parent_microblock,
            self.header.parent_microblock_sequence,
            state_root_hash
        );

        block
    }

    /// Finish building the anchored block.
    /// TODO: expand to deny mining a block whose anchored static checks fail (and allow the caller
    /// to disable this, in order to test mining invalid blocks)
    /// Returns: stacks block
    pub fn mine_anchored_block(&mut self, clarity_tx: &mut ClarityTx) -> StacksBlock {
        assert!(!self.anchored_done);
        StacksChainState::finish_block(
            clarity_tx,
            self.miner_payouts.clone(),
            self.header.total_work.work as u32,
            self.header.microblock_pubkey_hash,
        )
        .expect("FATAL: call to `finish_block` failed");
        self.finalize_block(clarity_tx)
    }

    /// Cut the next microblock.
    pub fn mine_next_microblock<'a>(&mut self) -> Result<StacksMicroblock, Error> {
        let txid_vecs = self
            .micro_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        let mut next_microblock_header =
            if self.prev_microblock_header.tx_merkle_root == Sha512Trunc256Sum([0u8; 32]) {
                // .prev_block is the hash of the parent anchored block
                StacksMicroblockHeader::first_unsigned(
                    &self.prev_microblock_header.prev_block,
                    &tx_merkle_root,
                )
            } else {
                StacksMicroblockHeader::from_parent_unsigned(
                    &self.prev_microblock_header,
                    &tx_merkle_root,
                )
                .ok_or(Error::MicroblockStreamTooLongError)?
            };

        test_debug!("Sign with {}", self.miner_privkey.to_hex());

        next_microblock_header.sign(&self.miner_privkey).unwrap();
        next_microblock_header
            .verify(&self.header.microblock_pubkey_hash)
            .unwrap();

        self.prev_microblock_header = next_microblock_header.clone();

        let microblock = StacksMicroblock {
            header: next_microblock_header,
            txs: self.micro_txs.clone(),
        };

        self.micro_txs.clear();

        test_debug!(
            "\n\nMiner {}: Mined microblock block {} (seq={}): {} transaction(s)\n",
            self.miner_id,
            microblock.block_hash(),
            microblock.header.sequence,
            microblock.txs.len()
        );
        Ok(microblock)
    }

    fn load_parent_microblocks(
        &mut self,
        chainstate: &mut StacksChainState,
        parent_consensus_hash: &ConsensusHash,
        parent_header_hash: &BlockHeaderHash,
        parent_index_hash: &StacksBlockId,
    ) -> Result<Vec<StacksMicroblock>, Error> {
        if let Some(microblock_parent_hash) = self.parent_microblock_hash.as_ref() {
            // load up a microblock fork
            let microblocks = StacksChainState::load_microblock_stream_fork(
                &chainstate.db(),
                &parent_consensus_hash,
                &parent_header_hash,
                &microblock_parent_hash,
            )?
            .ok_or(Error::NoSuchBlockError)?;

            Ok(microblocks)
        } else {
            // apply all known parent microblocks before beginning our tenure
            let (parent_microblocks, _) =
                match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                    &chainstate.db(),
                    &parent_index_hash,
                    0,
                    u16::MAX,
                )? {
                    Some(x) => x,
                    None => (vec![], None),
                };
            Ok(parent_microblocks)
        }
    }

    /// This function should be called before `epoch_begin`.
    /// It loads the parent microblock stream, sets the parent microblock, and returns
    /// data necessary for `epoch_begin`.
    /// Returns chainstate transaction, clarity instance, burnchain header hash
    /// of the burn tip, burn tip height + 1, the parent microblock stream,
    /// the parent consensus hash, the parent header hash, and a bool
    /// representing whether the network is mainnet or not.
    pub fn pre_epoch_begin<'a>(
        &mut self,
        chainstate: &'a mut StacksChainState,
        burn_dbconn: &'a SortitionDBConn,
    ) -> Result<MinerEpochInfo<'a>, Error> {
        debug!(
            "Miner epoch begin";
            "miner" => %self.miner_id,
            "chain_tip" => %format!("{}/{}", self.chain_tip.consensus_hash,
                                    self.header.parent_block)
        );

        if let Some((ref _miner_payout, ref _user_payouts, ref _parent_reward)) = self.miner_payouts
        {
            test_debug!(
                "Miner payout to process: {:?}; user payouts: {:?}; parent payout: {:?}",
                _miner_payout,
                _user_payouts,
                _parent_reward
            );
        }

        let parent_index_hash = StacksBlockHeader::make_index_block_hash(
            &self.parent_consensus_hash,
            &self.parent_header_hash,
        );

        let burn_tip = SortitionDB::get_canonical_chain_tip_bhh(burn_dbconn.conn())?;
        let burn_tip_height =
            SortitionDB::get_canonical_burn_chain_tip(burn_dbconn.conn())?.block_height as u32;

        let parent_microblocks = if StacksChainState::block_crosses_epoch_boundary(
            chainstate.db(),
            &self.parent_consensus_hash,
            &self.parent_header_hash,
        )? {
            info!("Descendant of {}/{} will NOT confirm any microblocks, since it will cross an epoch boundary", &self.parent_consensus_hash, &self.parent_header_hash);
            vec![]
        } else {
            match self.load_parent_microblocks(
                chainstate,
                &self.parent_consensus_hash.clone(),
                &self.parent_header_hash.clone(),
                &parent_index_hash,
            ) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Miner failed to load parent microblock, mining without parent microblock tail";
                              "parent_block_hash" => %self.parent_header_hash,
                              "parent_index_hash" => %parent_index_hash,
                              "parent_consensus_hash" => %self.parent_consensus_hash,
                              "parent_microblock_hash" => match self.parent_microblock_hash.as_ref() {
                                  Some(x) => format!("Some({})", x.to_string()),
                                  None => "None".to_string(),
                              },
                              "error" => ?e);
                    vec![]
                }
            }
        };

        debug!(
            "Descendant of {}/{} confirms {} microblock(s)",
            &self.parent_consensus_hash,
            &self.parent_header_hash,
            parent_microblocks.len()
        );

        if parent_microblocks.len() == 0 {
            self.set_parent_microblock(&EMPTY_MICROBLOCK_PARENT_HASH, 0);
        } else {
            let num_mblocks = parent_microblocks.len();
            let last_mblock_hdr = parent_microblocks[num_mblocks - 1].header.clone();
            self.set_parent_microblock(&last_mblock_hdr.block_hash(), last_mblock_hdr.sequence);
        };

        let mainnet = chainstate.config().mainnet;

        let (chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin()?;

        Ok(MinerEpochInfo {
            chainstate_tx,
            clarity_instance,
            burn_tip,
            burn_tip_height: burn_tip_height + 1,
            parent_microblocks,
            mainnet,
        })
    }

    /// Begin mining an epoch's transactions.
    /// Returns an open ClarityTx for mining the block, as well as the ExecutionCost of any confirmed
    ///  microblocks.
    /// NOTE: even though we don't yet know the block hash, the Clarity VM ensures that a
    /// transaction can't query information about the _current_ block (i.e. information that is not
    /// yet known).
    /// This function was separated from `pre_epoch_begin` because something "higher" than `epoch_begin`
    /// must own `ChainstateTx` and `ClarityInstance`, which are borrowed to construct the
    /// returned ClarityTx object.
    pub fn epoch_begin<'a, 'b>(
        &mut self,
        burn_dbconn: &'a SortitionDBConn,
        info: &'b mut MinerEpochInfo<'a>,
    ) -> Result<(ClarityTx<'b, 'b>, ExecutionCost), Error> {
        let SetupBlockResult {
            clarity_tx,
            microblock_execution_cost,
            microblock_fees,
            matured_miner_rewards_opt,
            ..
        } = StacksChainState::setup_block(
            &mut info.chainstate_tx,
            info.clarity_instance,
            burn_dbconn,
            burn_dbconn.conn(),
            &self.chain_tip,
            info.burn_tip,
            info.burn_tip_height,
            self.parent_consensus_hash,
            self.parent_header_hash,
            &info.parent_microblocks,
            info.mainnet,
            Some(self.miner_id),
        )?;
        self.miner_payouts =
            matured_miner_rewards_opt.map(|(miner, users, parent, _)| (miner, users, parent));
        self.total_confirmed_streamed_fees += microblock_fees as u64;

        Ok((clarity_tx, microblock_execution_cost))
    }

    /// Finish up mining an epoch's transactions
    pub fn epoch_finish(self, tx: ClarityTx) -> ExecutionCost {
        let new_consensus_hash = MINER_BLOCK_CONSENSUS_HASH.clone();
        let new_block_hash = MINER_BLOCK_HEADER_HASH.clone();

        let index_block_hash =
            StacksBlockHeader::make_index_block_hash(&new_consensus_hash, &new_block_hash);

        // clear out the block trie we just created, so the block validator logic doesn't step all
        // over it.
        //        let moved_name = format!("{}.mined", index_block_hash);

        // write out the trie...
        let consumed = tx.commit_mined_block(&index_block_hash);

        test_debug!(
            "\n\nMiner {}: Finished mining child of {}/{}. Trie is in mined_blocks table.\n",
            self.miner_id,
            self.chain_tip.consensus_hash,
            self.chain_tip.anchored_header.block_hash()
        );

        consumed
    }

    /// Unconditionally build an anchored block from a list of transactions.
    ///  Used in test cases
    #[cfg(test)]
    pub fn make_anchored_block_from_txs(
        mut builder: StacksBlockBuilder,
        chainstate_handle: &StacksChainState,
        burn_dbconn: &SortitionDBConn,
        mut txs: Vec<StacksTransaction>,
    ) -> Result<(StacksBlock, u64, ExecutionCost), Error> {
        debug!("Build anchored block from {} transactions", txs.len());
        let (mut chainstate, _) = chainstate_handle.reopen()?;
        let mut miner_epoch_info = builder.pre_epoch_begin(&mut chainstate, burn_dbconn)?;
        let (mut epoch_tx, _) = builder.epoch_begin(burn_dbconn, &mut miner_epoch_info)?;
        for tx in txs.drain(..) {
            match builder.try_mine_tx(&mut epoch_tx, &tx) {
                Ok(_) => {
                    debug!("Included {}", &tx.txid());
                }
                Err(Error::BlockTooBigError) => {
                    // done mining -- our execution budget is exceeded.
                    // Make the block from the transactions we did manage to get
                    debug!("Block budget exceeded on tx {}", &tx.txid());
                }
                Err(Error::InvalidStacksTransaction(_emsg, true)) => {
                    // if we have an invalid transaction that was quietly ignored, don't warn here either
                    test_debug!(
                        "Failed to apply tx {}: InvalidStacksTransaction '{:?}'",
                        &tx.txid(),
                        &_emsg
                    );
                    continue;
                }
                Err(e) => {
                    warn!("Failed to apply tx {}: {:?}", &tx.txid(), &e);
                    continue;
                }
            }
        }
        let block = builder.mine_anchored_block(&mut epoch_tx);
        let size = builder.bytes_so_far;
        let cost = builder.epoch_finish(epoch_tx);
        Ok((block, size, cost))
    }

    /// Create a block builder for mining
    pub fn make_block_builder(
        mainnet: bool,
        stacks_parent_header: &StacksHeaderInfo,
        proof: VRFProof,
        total_burn: u64,
        pubkey_hash: Hash160,
    ) -> Result<StacksBlockBuilder, Error> {
        let builder = if stacks_parent_header.consensus_hash == FIRST_BURNCHAIN_CONSENSUS_HASH {
            let (first_block_hash_hex, first_block_height, first_block_ts) = if mainnet {
                (
                    BITCOIN_MAINNET_FIRST_BLOCK_HASH,
                    BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
                    BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP,
                )
            } else {
                (
                    BITCOIN_TESTNET_FIRST_BLOCK_HASH,
                    BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT,
                    BITCOIN_TESTNET_FIRST_BLOCK_TIMESTAMP,
                )
            };
            let first_block_hash = BurnchainHeaderHash::from_hex(first_block_hash_hex).unwrap();
            StacksBlockBuilder::first_pubkey_hash(
                0,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &first_block_hash,
                first_block_height as u32,
                first_block_ts as u64,
                &proof,
                pubkey_hash,
            )
        } else {
            // building off an existing stacks block
            let new_work = StacksWorkScore {
                burn: total_burn,
                work: stacks_parent_header
                    .stacks_block_height
                    .checked_add(1)
                    .expect("FATAL: block height overflow"),
            };

            StacksBlockBuilder::from_parent_pubkey_hash(
                0,
                stacks_parent_header,
                &new_work,
                &proof,
                pubkey_hash,
            )
        };

        Ok(builder)
    }

    /// Create a block builder for regtest mining
    pub fn make_regtest_block_builder(
        stacks_parent_header: &StacksHeaderInfo,
        proof: VRFProof,
        total_burn: u64,
        pubkey_hash: Hash160,
    ) -> Result<StacksBlockBuilder, Error> {
        let builder = if stacks_parent_header.consensus_hash == FIRST_BURNCHAIN_CONSENSUS_HASH {
            let first_block_hash =
                BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
            StacksBlockBuilder::first_pubkey_hash(
                0,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &first_block_hash,
                BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT as u32,
                BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP as u64,
                &proof,
                pubkey_hash,
            )
        } else {
            // building off an existing stacks block
            let new_work = StacksWorkScore {
                burn: total_burn,
                work: stacks_parent_header
                    .stacks_block_height
                    .checked_add(1)
                    .expect("FATAL: block height overflow"),
            };

            StacksBlockBuilder::from_parent_pubkey_hash(
                0,
                stacks_parent_header,
                &new_work,
                &proof,
                pubkey_hash,
            )
        };
        Ok(builder)
    }

    /// Given access to the mempool, mine an anchored block with no more than the given execution cost.
    ///   returns the assembled block, and the consumed execution budget.
    pub fn build_anchored_block(
        chainstate_handle: &StacksChainState, // not directly used; used as a handle to open other chainstates
        burn_dbconn: &SortitionDBConn,
        mempool: &mut MemPoolDB,
        parent_stacks_header: &StacksHeaderInfo, // Stacks header we're building off of
        total_burn: u64, // the burn so far on the burnchain (i.e. from the last burnchain block)
        proof: VRFProof, // proof over the burnchain's last seed
        pubkey_hash: Hash160,
        coinbase_tx: &StacksTransaction,
        settings: BlockBuilderSettings,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
    ) -> Result<(StacksBlock, ExecutionCost, u64), Error> {
        let mempool_settings = settings.mempool_settings;
        let max_miner_time_ms = settings.max_miner_time_ms;

        if let TransactionPayload::Coinbase(..) = coinbase_tx.payload {
        } else {
            return Err(Error::MemPoolError(
                "Not a coinbase transaction".to_string(),
            ));
        }

        let (tip_consensus_hash, tip_block_hash, tip_height) = (
            parent_stacks_header.consensus_hash.clone(),
            parent_stacks_header.anchored_header.block_hash(),
            parent_stacks_header.stacks_block_height,
        );

        debug!(
            "Build anchored block off of {}/{} height {}",
            &tip_consensus_hash, &tip_block_hash, tip_height
        );

        let (mut chainstate, _) = chainstate_handle.reopen()?;

        let mut builder = StacksBlockBuilder::make_block_builder(
            chainstate.mainnet,
            parent_stacks_header,
            proof,
            total_burn,
            pubkey_hash,
        )?;

        let ts_start = get_epoch_time_ms();

        let mut miner_epoch_info = builder.pre_epoch_begin(&mut chainstate, burn_dbconn)?;
        let (mut epoch_tx, confirmed_mblock_cost) =
            builder.epoch_begin(burn_dbconn, &mut miner_epoch_info)?;
        let stacks_epoch_id = epoch_tx.get_epoch();
        let block_limit = epoch_tx
            .block_limit()
            .expect("Failed to obtain block limit from miner's block connection");

        let mut tx_events = Vec::new();
        tx_events.push(
            builder
                .try_mine_tx(&mut epoch_tx, coinbase_tx)?
                .convert_to_event(),
        );

        mempool.reset_last_known_nonces()?;

        mempool.estimate_tx_rates(100, &block_limit, &stacks_epoch_id)?;

        let mut considered = HashSet::new(); // txids of all transactions we looked at
        let mut mined_origin_nonces: HashMap<StacksAddress, u64> = HashMap::new(); // map addrs of mined transaction origins to the nonces we used
        let mut mined_sponsor_nonces: HashMap<StacksAddress, u64> = HashMap::new(); // map addrs of mined transaction sponsors to the nonces we used

        let mut invalidated_txs = vec![];

        let mut block_limit_hit = BlockLimitFunction::NO_LIMIT_HIT;
        let deadline = ts_start + (max_miner_time_ms as u128);
        let mut num_txs = 0;

        debug!(
            "Anchored block transaction selection begins (child of {})",
            &parent_stacks_header.anchored_header.block_hash()
        );
        let result = {
            let mut intermediate_result = Ok(0);
            while block_limit_hit != BlockLimitFunction::LIMIT_REACHED {
                let mut num_considered = 0;
                intermediate_result = mempool.iterate_candidates(
                    &mut epoch_tx,
                    tip_height,
                    mempool_settings.clone(),
                    |epoch_tx, to_consider, estimator| {
                        let txinfo = &to_consider.tx;
                        let update_estimator = to_consider.update_estimate;

                        if block_limit_hit == BlockLimitFunction::LIMIT_REACHED {
                            return Ok(false);
                        }
                        if get_epoch_time_ms() >= deadline {
                            debug!("Miner mining time exceeded ({} ms)", max_miner_time_ms);
                            return Ok(false);
                        }

                        // skip transactions early if we can
                        if considered.contains(&txinfo.tx.txid()) {
                            return Ok(true);
                        }

                        if let Some(nonce) = mined_origin_nonces.get(&txinfo.tx.origin_address()) {
                            if *nonce >= txinfo.tx.get_origin_nonce() {
                                return Ok(true);
                            }
                        }
                        if let Some(sponsor_addr) = txinfo.tx.sponsor_address() {
                            if let Some(nonce) = mined_sponsor_nonces.get(&sponsor_addr) {
                                if let Some(sponsor_nonce) = txinfo.tx.get_sponsor_nonce() {
                                    if *nonce >= sponsor_nonce {
                                        return Ok(true);
                                    }
                                }
                            }
                        }

                        considered.insert(txinfo.tx.txid());
                        num_considered += 1;

                        let tx_result = builder.try_mine_tx_with_len(
                            epoch_tx,
                            &txinfo.tx,
                            txinfo.metadata.len,
                            &block_limit_hit,
                        );
                        tx_events.push(tx_result.convert_to_event());

                        match tx_result {
                            TransactionResult::Success(TransactionSuccess { receipt, .. }) => {
                                num_txs += 1;
                                if update_estimator {
                                    if let Err(e) = estimator.notify_event(
                                        &txinfo.tx.payload,
                                        &receipt.execution_cost,
                                        &block_limit,
                                        &stacks_epoch_id,
                                    ) {
                                        warn!("Error updating estimator";
                                              "txid" => %txinfo.metadata.txid,
                                              "error" => ?e);
                                    }
                                }
                                mined_origin_nonces.insert(
                                    txinfo.tx.origin_address(),
                                    txinfo.tx.get_origin_nonce(),
                                );
                                if let (Some(sponsor_addr), Some(sponsor_nonce)) =
                                    (txinfo.tx.sponsor_address(), txinfo.tx.get_sponsor_nonce())
                                {
                                    mined_sponsor_nonces.insert(sponsor_addr, sponsor_nonce);
                                }
                            }
                            TransactionResult::Skipped(TransactionSkipped { error, .. })
                            | TransactionResult::ProcessingError(TransactionError {
                                error, ..
                            }) => {
                                match &error {
                                    Error::StacksTransactionSkipped(_) => {}
                                    Error::BlockTooBigError => {
                                        // done mining -- our execution budget is exceeded.
                                        // Make the block from the transactions we did manage to get
                                        debug!("Block budget exceeded on tx {}", &txinfo.tx.txid());
                                        if block_limit_hit == BlockLimitFunction::NO_LIMIT_HIT {
                                            debug!("Switch to mining stx-transfers only");
                                            block_limit_hit =
                                                BlockLimitFunction::CONTRACT_LIMIT_HIT;
                                        } else if block_limit_hit
                                            == BlockLimitFunction::CONTRACT_LIMIT_HIT
                                        {
                                            debug!(
                                                "Stop mining anchored block due to limit exceeded"
                                            );
                                            block_limit_hit = BlockLimitFunction::LIMIT_REACHED;
                                            return Ok(false);
                                        }
                                    }
                                    Error::TransactionTooBigError => {
                                        invalidated_txs.push(txinfo.metadata.txid);
                                    }
                                    Error::InvalidStacksTransaction(_, true) => {
                                        // if we have an invalid transaction that was quietly ignored, don't warn here either
                                    }
                                    e => {
                                        warn!("Failed to apply tx {}: {:?}", &txinfo.tx.txid(), &e);
                                        return Ok(true);
                                    }
                                }
                            }
                        }

                        Ok(true)
                    },
                );

                if intermediate_result.is_err() {
                    break;
                }

                if num_considered == 0 {
                    break;
                }
            }
            debug!("Anchored block transaction selection finished (child of {}): {} transactions selected ({} considered)", &parent_stacks_header.anchored_header.block_hash(), num_txs, considered.len());
            intermediate_result
        };

        mempool.drop_txs(&invalidated_txs)?;

        if let Some(observer) = event_observer {
            observer.mempool_txs_dropped(invalidated_txs, MemPoolDropReason::TOO_EXPENSIVE);
        }

        match result {
            Ok(_) => {}
            Err(e) => {
                warn!("Failure building block: {}", e);
                epoch_tx.rollback_block();
                return Err(e);
            }
        }

        // the prior do_rebuild logic wasn't necessary
        // a transaction that caused a budget exception is rolled back in process_transaction

        // save the block so we can build microblocks off of it
        let block = builder.mine_anchored_block(&mut epoch_tx);
        let size = builder.bytes_so_far;
        let consumed = builder.epoch_finish(epoch_tx);

        let ts_end = get_epoch_time_ms();

        if let Some(observer) = event_observer {
            observer.mined_block_event(
                SortitionDB::get_canonical_burn_chain_tip(burn_dbconn.conn())?.block_height + 1,
                &block,
                size,
                &consumed,
                &confirmed_mblock_cost,
                tx_events,
            );
        }

        debug!(
            "Miner: mined anchored block";
            "block_hash" => %block.block_hash(),
            "height" => block.header.total_work.work,
            "tx_count" => block.txs.len(),
            "parent_stacks_block_hash" => %block.header.parent_block,
            "parent_stacks_microblock" => %block.header.parent_microblock,
            "parent_stacks_microblock_seq" => block.header.parent_microblock_sequence,
            "block_size" => size,
            "execution_consumed" => %consumed,
            "assembly_time_ms" => ts_end.saturating_sub(ts_start),
            "tx_fees_microstacks" => block.txs.iter().fold(0, |agg: u64, tx| {
                agg.saturating_add(tx.get_tx_fee())
            })
        );

        Ok((block, consumed, size))
    }
}

#[cfg(test)]
pub mod test {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use rand::Rng;

    use crate::burnchains::tests::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::operations::{
        BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp, UserBurnSupportOp,
    };
    use crate::chainstate::burn::*;
    use crate::chainstate::coordinator::Error as CoordinatorError;
    use crate::chainstate::stacks::db::blocks::test::store_staging_block;
    use crate::chainstate::stacks::db::test::*;
    use crate::chainstate::stacks::db::*;
    use crate::chainstate::stacks::Error as ChainstateError;
    use crate::chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
    use crate::chainstate::stacks::*;
    use crate::net::test::*;
    use crate::util_lib::db::Error as db_error;
    use clarity::vm::types::*;
    use stacks_common::address::*;
    use stacks_common::util::sleep_ms;
    use stacks_common::util::vrf::VRFProof;

    use crate::cost_estimates::metrics::UnitMetric;
    use crate::cost_estimates::UnitEstimator;
    use crate::types::chainstate::SortitionId;
    use crate::util_lib::boot::boot_code_addr;

    use super::*;

    pub const COINBASE: u128 = 500 * 1_000_000;

    pub fn coinbase_total_at(stacks_height: u64) -> u128 {
        if stacks_height > MINER_REWARD_MATURITY {
            COINBASE * ((stacks_height - MINER_REWARD_MATURITY) as u128)
        } else {
            0
        }
    }

    pub fn path_join(dir: &str, path: &str) -> String {
        // force path to be relative
        let tail = if !path.starts_with("/") {
            path.to_string()
        } else {
            String::from_utf8(path.as_bytes()[1..].to_vec()).unwrap()
        };

        let p = PathBuf::from(dir);
        let res = p.join(PathBuf::from(tail));
        res.to_str().unwrap().to_string()
    }

    // copy src to dest
    pub fn copy_dir(src_dir: &str, dest_dir: &str) -> Result<(), io::Error> {
        eprintln!("Copy directory {} to {}", src_dir, dest_dir);

        let mut dir_queue = VecDeque::new();
        dir_queue.push_back("/".to_string());

        while dir_queue.len() > 0 {
            let next_dir = dir_queue.pop_front().unwrap();
            let next_src_dir = path_join(&src_dir, &next_dir);
            let next_dest_dir = path_join(&dest_dir, &next_dir);

            eprintln!("mkdir {}", &next_dest_dir);
            fs::create_dir_all(&next_dest_dir)?;

            for dirent_res in fs::read_dir(&next_src_dir)? {
                let dirent = dirent_res?;
                let path = dirent.path();
                let md = fs::metadata(&path)?;
                if md.is_dir() {
                    let frontier = path_join(&next_dir, &dirent.file_name().to_str().unwrap());
                    eprintln!("push {}", &frontier);
                    dir_queue.push_back(frontier);
                } else {
                    let dest_path =
                        path_join(&next_dest_dir, &dirent.file_name().to_str().unwrap());
                    eprintln!("copy {} to {}", &path.to_str().unwrap(), &dest_path);
                    fs::copy(path, dest_path)?;
                }
            }
        }
        Ok(())
    }

    // one point per round
    pub struct TestMinerTracePoint {
        pub fork_snapshots: HashMap<usize, BlockSnapshot>, // map miner ID to snapshot
        pub stacks_blocks: HashMap<usize, StacksBlock>,    // map miner ID to stacks block
        pub microblocks: HashMap<usize, Vec<StacksMicroblock>>, // map miner ID to microblocks
        pub block_commits: HashMap<usize, LeaderBlockCommitOp>, // map miner ID to block commit
        pub miner_node_map: HashMap<usize, String>,        // map miner ID to the node it worked on
    }

    impl TestMinerTracePoint {
        pub fn new() -> TestMinerTracePoint {
            TestMinerTracePoint {
                fork_snapshots: HashMap::new(),
                stacks_blocks: HashMap::new(),
                microblocks: HashMap::new(),
                block_commits: HashMap::new(),
                miner_node_map: HashMap::new(),
            }
        }

        pub fn add(
            &mut self,
            miner_id: usize,
            node_name: String,
            fork_snapshot: BlockSnapshot,
            stacks_block: StacksBlock,
            microblocks: Vec<StacksMicroblock>,
            block_commit: LeaderBlockCommitOp,
        ) -> () {
            self.fork_snapshots.insert(miner_id, fork_snapshot);
            self.stacks_blocks.insert(miner_id, stacks_block);
            self.microblocks.insert(miner_id, microblocks);
            self.block_commits.insert(miner_id, block_commit);
            self.miner_node_map.insert(miner_id, node_name);
        }

        pub fn get_block_snapshot(&self, miner_id: usize) -> Option<BlockSnapshot> {
            self.fork_snapshots.get(&miner_id).cloned()
        }

        pub fn get_stacks_block(&self, miner_id: usize) -> Option<StacksBlock> {
            self.stacks_blocks.get(&miner_id).cloned()
        }

        pub fn get_microblocks(&self, miner_id: usize) -> Option<Vec<StacksMicroblock>> {
            self.microblocks.get(&miner_id).cloned()
        }

        pub fn get_block_commit(&self, miner_id: usize) -> Option<LeaderBlockCommitOp> {
            self.block_commits.get(&miner_id).cloned()
        }

        pub fn get_node_name(&self, miner_id: usize) -> Option<String> {
            self.miner_node_map.get(&miner_id).cloned()
        }

        pub fn get_miner_ids(&self) -> Vec<usize> {
            let mut miner_ids = HashSet::new();
            for miner_id in self.fork_snapshots.keys() {
                miner_ids.insert(*miner_id);
            }
            for miner_id in self.stacks_blocks.keys() {
                miner_ids.insert(*miner_id);
            }
            for miner_id in self.microblocks.keys() {
                miner_ids.insert(*miner_id);
            }
            for miner_id in self.block_commits.keys() {
                miner_ids.insert(*miner_id);
            }
            let mut ret = vec![];
            for miner_id in miner_ids.iter() {
                ret.push(*miner_id);
            }
            ret
        }
    }

    pub struct TestMinerTrace {
        pub points: Vec<TestMinerTracePoint>,
        pub burn_node: TestBurnchainNode,
        pub miners: Vec<TestMiner>,
    }

    impl TestMinerTrace {
        pub fn new(
            burn_node: TestBurnchainNode,
            miners: Vec<TestMiner>,
            points: Vec<TestMinerTracePoint>,
        ) -> TestMinerTrace {
            TestMinerTrace {
                points: points,
                burn_node: burn_node,
                miners: miners,
            }
        }

        /// how many blocks represented here?
        pub fn get_num_blocks(&self) -> usize {
            let mut num_blocks = 0;
            for p in self.points.iter() {
                for miner_id in p.stacks_blocks.keys() {
                    if p.stacks_blocks.get(miner_id).is_some() {
                        num_blocks += 1;
                    }
                }
            }
            num_blocks
        }

        /// how many sortitions represented here?
        pub fn get_num_sortitions(&self) -> usize {
            let mut num_sortitions = 0;
            for p in self.points.iter() {
                for miner_id in p.fork_snapshots.keys() {
                    if p.fork_snapshots.get(miner_id).is_some() {
                        num_sortitions += 1;
                    }
                }
            }
            num_sortitions
        }

        /// how many rounds did this trace go for?
        pub fn rounds(&self) -> usize {
            self.points.len()
        }

        /// what are the chainstate directories?
        pub fn get_test_names(&self) -> Vec<String> {
            let mut all_test_names = HashSet::new();
            for p in self.points.iter() {
                for miner_id in p.miner_node_map.keys() {
                    if let Some(ref test_name) = p.miner_node_map.get(miner_id) {
                        if !all_test_names.contains(test_name) {
                            all_test_names.insert(test_name.clone());
                        }
                    }
                }
            }
            let mut ret = vec![];
            for name in all_test_names.drain() {
                ret.push(name.to_owned());
            }
            ret
        }
    }

    pub struct TestStacksNode {
        pub chainstate: StacksChainState,
        pub prev_keys: Vec<LeaderKeyRegisterOp>, // _all_ keys generated
        pub key_ops: HashMap<VRFPublicKey, usize>, // map VRF public keys to their locations in the prev_keys array
        pub anchored_blocks: Vec<StacksBlock>,
        pub microblocks: Vec<Vec<StacksMicroblock>>,
        pub commit_ops: HashMap<BlockHeaderHash, usize>,
        pub test_name: String,
        forkable: bool,
    }

    impl TestStacksNode {
        pub fn new(
            mainnet: bool,
            chain_id: u32,
            test_name: &str,
            mut initial_balance_recipients: Vec<StacksAddress>,
        ) -> TestStacksNode {
            initial_balance_recipients.sort();
            let initial_balances = initial_balance_recipients
                .into_iter()
                .map(|addr| (addr, 10_000_000_000))
                .collect();
            let chainstate = instantiate_chainstate_with_balances(
                mainnet,
                chain_id,
                test_name,
                initial_balances,
            );
            TestStacksNode {
                chainstate: chainstate,
                prev_keys: vec![],
                key_ops: HashMap::new(),
                anchored_blocks: vec![],
                microblocks: vec![],
                commit_ops: HashMap::new(),
                test_name: test_name.to_string(),
                forkable: true,
            }
        }

        pub fn open(mainnet: bool, chain_id: u32, test_name: &str) -> TestStacksNode {
            let chainstate = open_chainstate(mainnet, chain_id, test_name);
            TestStacksNode {
                chainstate: chainstate,
                prev_keys: vec![],
                key_ops: HashMap::new(),
                anchored_blocks: vec![],
                microblocks: vec![],
                commit_ops: HashMap::new(),
                test_name: test_name.to_string(),
                forkable: true,
            }
        }

        pub fn from_chainstate(chainstate: StacksChainState) -> TestStacksNode {
            TestStacksNode {
                chainstate: chainstate,
                prev_keys: vec![],
                key_ops: HashMap::new(),
                anchored_blocks: vec![],
                microblocks: vec![],
                commit_ops: HashMap::new(),
                test_name: "".to_string(),
                forkable: false,
            }
        }

        // NOTE: can't do this if instantiated via from_chainstate()
        pub fn fork(&self, new_test_name: &str) -> TestStacksNode {
            if !self.forkable {
                panic!("Tried to fork an unforkable chainstate instance");
            }

            match fs::metadata(&chainstate_path(new_test_name)) {
                Ok(_) => {
                    fs::remove_dir_all(&chainstate_path(new_test_name)).unwrap();
                }
                Err(_) => {}
            }

            copy_dir(
                &chainstate_path(&self.test_name),
                &chainstate_path(new_test_name),
            )
            .unwrap();
            let chainstate = open_chainstate(
                self.chainstate.mainnet,
                self.chainstate.chain_id,
                new_test_name,
            );
            TestStacksNode {
                chainstate: chainstate,
                prev_keys: self.prev_keys.clone(),
                key_ops: self.key_ops.clone(),
                anchored_blocks: self.anchored_blocks.clone(),
                microblocks: self.microblocks.clone(),
                commit_ops: self.commit_ops.clone(),
                test_name: new_test_name.to_string(),
                forkable: true,
            }
        }

        pub fn next_burn_block(
            sortdb: &mut SortitionDB,
            fork: &mut TestBurnchainFork,
        ) -> TestBurnchainBlock {
            let burn_block = {
                let ic = sortdb.index_conn();
                fork.next_block(&ic)
            };
            burn_block
        }

        pub fn add_key_register(
            &mut self,
            block: &mut TestBurnchainBlock,
            miner: &mut TestMiner,
        ) -> LeaderKeyRegisterOp {
            let key_register_op = block.add_leader_key_register(miner);
            self.prev_keys.push(key_register_op.clone());
            self.key_ops
                .insert(key_register_op.public_key.clone(), self.prev_keys.len() - 1);
            key_register_op
        }

        pub fn add_key_register_op(&mut self, op: &LeaderKeyRegisterOp) -> () {
            self.prev_keys.push(op.clone());
            self.key_ops
                .insert(op.public_key.clone(), self.prev_keys.len() - 1);
        }

        pub fn add_block_commit(
            sortdb: &SortitionDB,
            burn_block: &mut TestBurnchainBlock,
            miner: &mut TestMiner,
            block_hash: &BlockHeaderHash,
            burn_amount: u64,
            key_op: &LeaderKeyRegisterOp,
            parent_block_snapshot: Option<&BlockSnapshot>,
        ) -> LeaderBlockCommitOp {
            let block_commit_op = {
                let ic = sortdb.index_conn();
                let parent_snapshot = burn_block.parent_snapshot.clone();
                burn_block.add_leader_block_commit(
                    &ic,
                    miner,
                    block_hash,
                    burn_amount,
                    key_op,
                    Some(&parent_snapshot),
                    parent_block_snapshot,
                )
            };
            block_commit_op
        }

        pub fn get_last_key(&self, miner: &TestMiner) -> LeaderKeyRegisterOp {
            let last_vrf_pubkey = miner.last_VRF_public_key().unwrap();
            let idx = *self.key_ops.get(&last_vrf_pubkey).unwrap();
            self.prev_keys[idx].clone()
        }

        pub fn get_last_anchored_block(&self, miner: &TestMiner) -> Option<StacksBlock> {
            match miner.last_block_commit() {
                None => None,
                Some(block_commit_op) => {
                    match self.commit_ops.get(&block_commit_op.block_header_hash) {
                        None => None,
                        Some(idx) => Some(self.anchored_blocks[*idx].clone()),
                    }
                }
            }
        }

        pub fn get_last_accepted_anchored_block(
            &self,
            sortdb: &SortitionDB,
            miner: &TestMiner,
        ) -> Option<StacksBlock> {
            for bc in miner.block_commits.iter().rev() {
                let consensus_hash = match SortitionDB::get_block_snapshot(
                    sortdb.conn(),
                    &SortitionId::stubbed(&bc.burn_header_hash),
                )
                .unwrap()
                {
                    Some(sn) => sn.consensus_hash,
                    None => {
                        continue;
                    }
                };

                if StacksChainState::has_stored_block(
                    &self.chainstate.db(),
                    &self.chainstate.blocks_path,
                    &consensus_hash,
                    &bc.block_header_hash,
                )
                .unwrap()
                    && !StacksChainState::is_block_orphaned(
                        &self.chainstate.db(),
                        &consensus_hash,
                        &bc.block_header_hash,
                    )
                    .unwrap()
                {
                    match self.commit_ops.get(&bc.block_header_hash) {
                        None => {
                            continue;
                        }
                        Some(idx) => {
                            return Some(self.anchored_blocks[*idx].clone());
                        }
                    }
                }
            }
            return None;
        }

        pub fn get_microblock_stream(
            &self,
            miner: &TestMiner,
            block_hash: &BlockHeaderHash,
        ) -> Option<Vec<StacksMicroblock>> {
            match self.commit_ops.get(block_hash) {
                None => None,
                Some(idx) => Some(self.microblocks[*idx].clone()),
            }
        }

        pub fn get_anchored_block(&self, block_hash: &BlockHeaderHash) -> Option<StacksBlock> {
            match self.commit_ops.get(block_hash) {
                None => None,
                Some(idx) => Some(self.anchored_blocks[*idx].clone()),
            }
        }

        pub fn get_last_winning_snapshot(
            ic: &SortitionDBConn,
            fork_tip: &BlockSnapshot,
            miner: &TestMiner,
        ) -> Option<BlockSnapshot> {
            for commit_op in miner.block_commits.iter().rev() {
                match SortitionDB::get_block_snapshot_for_winning_stacks_block(
                    ic,
                    &fork_tip.sortition_id,
                    &commit_op.block_header_hash,
                )
                .unwrap()
                {
                    Some(sn) => {
                        return Some(sn);
                    }
                    None => {}
                }
            }
            return None;
        }

        pub fn get_miner_balance(clarity_tx: &mut ClarityTx, addr: &StacksAddress) -> u128 {
            clarity_tx.with_clarity_db_readonly(|db| {
                db.get_account_stx_balance(&StandardPrincipalData::from(addr.clone()).into())
                    .amount_unlocked()
            })
        }

        pub fn make_tenure_commitment(
            &mut self,
            sortdb: &SortitionDB,
            burn_block: &mut TestBurnchainBlock,
            miner: &mut TestMiner,
            stacks_block: &StacksBlock,
            microblocks: &Vec<StacksMicroblock>,
            burn_amount: u64,
            miner_key: &LeaderKeyRegisterOp,
            parent_block_snapshot_opt: Option<&BlockSnapshot>,
        ) -> LeaderBlockCommitOp {
            self.anchored_blocks.push(stacks_block.clone());
            self.microblocks.push(microblocks.clone());

            test_debug!(
                "Miner {}: Commit to stacks block {} (work {},{})",
                miner.id,
                stacks_block.block_hash(),
                stacks_block.header.total_work.burn,
                stacks_block.header.total_work.work
            );

            // send block commit for this block
            let block_commit_op = TestStacksNode::add_block_commit(
                sortdb,
                burn_block,
                miner,
                &stacks_block.block_hash(),
                burn_amount,
                miner_key,
                parent_block_snapshot_opt,
            );

            test_debug!(
                "Miner {}: Block commit transaction builds on {},{} (parent snapshot is {:?})",
                miner.id,
                block_commit_op.parent_block_ptr,
                block_commit_op.parent_vtxindex,
                &parent_block_snapshot_opt
            );
            self.commit_ops.insert(
                block_commit_op.block_header_hash.clone(),
                self.anchored_blocks.len() - 1,
            );
            block_commit_op
        }

        pub fn mine_stacks_block<F>(
            &mut self,
            sortdb: &SortitionDB,
            miner: &mut TestMiner,
            burn_block: &mut TestBurnchainBlock,
            miner_key: &LeaderKeyRegisterOp,
            parent_stacks_block: Option<&StacksBlock>,
            burn_amount: u64,
            block_assembler: F,
        ) -> (StacksBlock, Vec<StacksMicroblock>, LeaderBlockCommitOp)
        where
            F: FnOnce(
                StacksBlockBuilder,
                &mut TestMiner,
                &SortitionDB,
            ) -> (StacksBlock, Vec<StacksMicroblock>),
        {
            let proof = miner
                .make_proof(
                    &miner_key.public_key,
                    &burn_block.parent_snapshot.sortition_hash,
                )
                .expect(&format!(
                    "FATAL: no private key for {}",
                    miner_key.public_key.to_hex()
                ));

            let (builder, parent_block_snapshot_opt) = match parent_stacks_block {
                None => {
                    // first stacks block
                    let builder = StacksBlockBuilder::first(
                        miner.id,
                        &burn_block.parent_snapshot.consensus_hash,
                        &burn_block.parent_snapshot.burn_header_hash,
                        burn_block.parent_snapshot.block_height as u32,
                        burn_block.parent_snapshot.burn_header_timestamp,
                        &proof,
                        &miner.next_microblock_privkey(),
                    );
                    (builder, None)
                }
                Some(parent_stacks_block) => {
                    // building off an existing stacks block
                    let parent_stacks_block_snapshot = {
                        let ic = sortdb.index_conn();
                        let parent_stacks_block_snapshot =
                            SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                &ic,
                                &burn_block.parent_snapshot.sortition_id,
                                &parent_stacks_block.block_hash(),
                            )
                            .unwrap()
                            .unwrap();
                        let burned_last =
                            SortitionDB::get_block_burn_amount(&ic, &burn_block.parent_snapshot)
                                .unwrap();
                        parent_stacks_block_snapshot
                    };

                    let parent_chain_tip = StacksChainState::get_anchored_block_header_info(
                        self.chainstate.db(),
                        &parent_stacks_block_snapshot.consensus_hash,
                        &parent_stacks_block.header.block_hash(),
                    )
                    .unwrap()
                    .unwrap();

                    let new_work = StacksWorkScore {
                        burn: parent_stacks_block_snapshot.total_burn,
                        work: parent_stacks_block
                            .header
                            .total_work
                            .work
                            .checked_add(1)
                            .expect("FATAL: stacks block height overflow"),
                    };

                    test_debug!(
                        "Work in {} {}: {},{}",
                        burn_block.block_height,
                        burn_block.parent_snapshot.burn_header_hash,
                        new_work.burn,
                        new_work.work
                    );
                    let builder = StacksBlockBuilder::from_parent(
                        miner.id,
                        &parent_chain_tip,
                        &new_work,
                        &proof,
                        &miner.next_microblock_privkey(),
                    );
                    (builder, Some(parent_stacks_block_snapshot))
                }
            };

            test_debug!(
                "Miner {}: Assemble stacks block from {}",
                miner.id,
                miner.origin_address().unwrap().to_string()
            );

            let (stacks_block, microblocks) = block_assembler(builder, miner, sortdb);
            let block_commit_op = self.make_tenure_commitment(
                sortdb,
                burn_block,
                miner,
                &stacks_block,
                &microblocks,
                burn_amount,
                miner_key,
                parent_block_snapshot_opt.as_ref(),
            );

            (stacks_block, microblocks, block_commit_op)
        }
    }

    /// Return Some(bool) to indicate whether or not the anchored block was accepted into the queue.
    /// Return None if the block was not submitted at all.
    fn preprocess_stacks_block_data(
        node: &mut TestStacksNode,
        burn_node: &mut TestBurnchainNode,
        fork_snapshot: &BlockSnapshot,
        stacks_block: &StacksBlock,
        stacks_microblocks: &Vec<StacksMicroblock>,
        block_commit_op: &LeaderBlockCommitOp,
    ) -> Option<bool> {
        let block_hash = stacks_block.block_hash();

        let ic = burn_node.sortdb.index_conn();
        let ch_opt = SortitionDB::get_block_commit_parent(
            &ic,
            block_commit_op.parent_block_ptr.into(),
            block_commit_op.parent_vtxindex.into(),
            &fork_snapshot.sortition_id,
        )
        .unwrap();
        let parent_block_consensus_hash = match ch_opt {
            Some(parent_commit) => {
                let db_handle = SortitionHandleConn::open_reader(
                    &ic,
                    &SortitionId::stubbed(&block_commit_op.burn_header_hash),
                )
                .unwrap();
                let sn = db_handle
                    .get_block_snapshot(&parent_commit.burn_header_hash)
                    .unwrap()
                    .unwrap();
                sn.consensus_hash
            }
            None => {
                // only allowed if this is the first-ever block in the stacks fork
                assert_eq!(block_commit_op.parent_block_ptr, 0);
                assert_eq!(block_commit_op.parent_vtxindex, 0);
                assert!(stacks_block.header.is_first_mined());

                FIRST_BURNCHAIN_CONSENSUS_HASH.clone()
            }
        };

        let commit_snapshot = match SortitionDB::get_block_snapshot_for_winning_stacks_block(
            &ic,
            &fork_snapshot.sortition_id,
            &block_hash,
        )
        .unwrap()
        {
            Some(sn) => sn,
            None => {
                test_debug!("Block commit did not win sorition: {:?}", block_commit_op);
                return None;
            }
        };

        // "discover" this stacks block
        test_debug!(
            "\n\nPreprocess Stacks block {}/{} ({})",
            &commit_snapshot.consensus_hash,
            &block_hash,
            StacksBlockHeader::make_index_block_hash(&commit_snapshot.consensus_hash, &block_hash)
        );
        let block_res = node
            .chainstate
            .preprocess_anchored_block(
                &ic,
                &commit_snapshot.consensus_hash,
                &stacks_block,
                &parent_block_consensus_hash,
                5,
            )
            .unwrap();

        // "discover" this stacks microblock stream
        for mblock in stacks_microblocks.iter() {
            test_debug!(
                "Preprocess Stacks microblock {}-{} (seq {})",
                &block_hash,
                mblock.block_hash(),
                mblock.header.sequence
            );
            match node.chainstate.preprocess_streamed_microblock(
                &commit_snapshot.consensus_hash,
                &stacks_block.block_hash(),
                mblock,
            ) {
                Ok(_) => {}
                Err(_) => {
                    return Some(false);
                }
            }
        }

        Some(block_res)
    }

    /// Verify that the stacks block's state root matches the state root in the chain state
    fn check_block_state_index_root(
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        stacks_header: &StacksBlockHeader,
    ) -> bool {
        let index_block_hash =
            StacksBlockHeader::make_index_block_hash(consensus_hash, &stacks_header.block_hash());
        let mut state_root_index =
            StacksChainState::open_index(&chainstate.clarity_state_index_path).unwrap();
        let state_root = state_root_index
            .borrow_storage_backend()
            .read_block_root_hash(&index_block_hash)
            .unwrap();
        test_debug!(
            "checking {}/{} state root: expecting {}, got {}",
            consensus_hash,
            &stacks_header.block_hash(),
            &stacks_header.state_index_root,
            &state_root
        );
        state_root == stacks_header.state_index_root
    }

    /// Verify that the miner got the expected block reward
    fn check_mining_reward(
        clarity_tx: &mut ClarityTx,
        miner: &mut TestMiner,
        block_height: u64,
        prev_block_rewards: &Vec<Vec<MinerPaymentSchedule>>,
    ) -> bool {
        let mut block_rewards = HashMap::new();
        let mut stream_rewards = HashMap::new();
        let mut heights = HashMap::new();
        let mut confirmed = HashSet::new();
        for (i, reward_list) in prev_block_rewards.iter().enumerate() {
            for reward in reward_list.iter() {
                let ibh = StacksBlockHeader::make_index_block_hash(
                    &reward.consensus_hash,
                    &reward.block_hash,
                );
                if reward.coinbase > 0 {
                    block_rewards.insert(ibh.clone(), reward.clone());
                }
                if reward.tx_fees_streamed > 0 {
                    stream_rewards.insert(ibh.clone(), reward.clone());
                }
                heights.insert(ibh.clone(), i);
                confirmed.insert((
                    StacksBlockHeader::make_index_block_hash(
                        &reward.parent_consensus_hash,
                        &reward.parent_block_hash,
                    ),
                    i,
                ));
            }
        }

        // what was the miner's total spend?
        let miner_nonce = clarity_tx.with_clarity_db_readonly(|db| {
            db.get_account_nonce(
                &StandardPrincipalData::from(miner.origin_address().unwrap()).into(),
            )
        });

        let mut spent_total = 0;
        for (nonce, spent) in miner.spent_at_nonce.iter() {
            if *nonce < miner_nonce {
                spent_total += *spent;
            }
        }

        let mut total: u128 = 10_000_000_000 - spent_total;
        test_debug!(
            "Miner {} has spent {} in total so far",
            &miner.origin_address().unwrap(),
            spent_total
        );

        if block_height >= MINER_REWARD_MATURITY {
            for (i, prev_block_reward) in prev_block_rewards.iter().enumerate() {
                if i as u64 > block_height - MINER_REWARD_MATURITY {
                    break;
                }
                let mut found = false;
                for recipient in prev_block_reward {
                    if recipient.address == miner.origin_address().unwrap() {
                        let reward: u128 = recipient.coinbase
                            + recipient.tx_fees_anchored
                            + (3 * recipient.tx_fees_streamed / 5);

                        test_debug!(
                            "Miner {} received a reward {} = {} + {} + {} at block {}",
                            &recipient.address.to_string(),
                            reward,
                            recipient.coinbase,
                            recipient.tx_fees_anchored,
                            (3 * recipient.tx_fees_streamed / 5),
                            i
                        );
                        total += reward;
                        found = true;
                    }
                }
                if !found {
                    test_debug!(
                        "Miner {} received no reward at block {}",
                        miner.origin_address().unwrap(),
                        i
                    );
                }
            }

            for (parent_block, confirmed_block_height) in confirmed.into_iter() {
                if confirmed_block_height as u64 > block_height - MINER_REWARD_MATURITY {
                    continue;
                }
                if let Some(ref parent_reward) = stream_rewards.get(&parent_block) {
                    if parent_reward.address == miner.origin_address().unwrap() {
                        let parent_streamed = (2 * parent_reward.tx_fees_streamed) / 5;
                        let parent_ibh = StacksBlockHeader::make_index_block_hash(
                            &parent_reward.consensus_hash,
                            &parent_reward.block_hash,
                        );
                        test_debug!(
                            "Miner {} received a produced-stream reward {} from {} confirmed at {}",
                            miner.origin_address().unwrap().to_string(),
                            parent_streamed,
                            heights.get(&parent_ibh).unwrap(),
                            confirmed_block_height
                        );
                        total += parent_streamed;
                    }
                }
            }
        }

        let amount =
            TestStacksNode::get_miner_balance(clarity_tx, &miner.origin_address().unwrap());
        if amount == 0 {
            test_debug!(
                "Miner {} '{}' has no mature funds in this fork",
                miner.id,
                miner.origin_address().unwrap().to_string()
            );
            return total == 0;
        } else {
            if amount != total {
                test_debug!("Amount {} != {}", amount, total);
                return false;
            }
            return true;
        }
    }

    pub fn get_last_microblock_header(
        node: &TestStacksNode,
        miner: &TestMiner,
        parent_block_opt: Option<&StacksBlock>,
    ) -> Option<StacksMicroblockHeader> {
        let last_microblocks_opt = match parent_block_opt {
            Some(ref block) => node.get_microblock_stream(&miner, &block.block_hash()),
            None => None,
        };

        let last_microblock_header_opt = match last_microblocks_opt {
            Some(last_microblocks) => {
                if last_microblocks.len() == 0 {
                    None
                } else {
                    let l = last_microblocks.len() - 1;
                    Some(last_microblocks[l].header.clone())
                }
            }
            None => None,
        };

        last_microblock_header_opt
    }

    fn get_all_mining_rewards(
        chainstate: &mut StacksChainState,
        tip: &StacksHeaderInfo,
        block_height: u64,
    ) -> Vec<Vec<MinerPaymentSchedule>> {
        let mut ret = vec![];
        let mut tx = chainstate.index_tx_begin().unwrap();

        for i in 0..block_height {
            let block_rewards =
                StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, tip, i)
                    .unwrap();
            ret.push(block_rewards);
        }

        ret
    }

    /*
    // TODO: can't use this until we stop using get_simmed_block_height
    fn clarity_get_block_hash<'a>(clarity_tx: &mut ClarityTx<'a>, block_height: u64) -> Option<BlockHeaderHash> {
        let block_hash_value = clarity_tx.connection().clarity_eval_raw(&format!("(get-block-info? header-hash u{})", &block_height)).unwrap();

        match block_hash_value {
            Value::Buffer(block_hash_buff) => {
                assert_eq!(block_hash_buff.data.len(), 32);
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&block_hash_buff.data[0..32]);
                Some(BlockHeaderHash(buf))
            },
            _ => {
                None
            }
        }
    }
    */

    /// Simplest end-to-end test: create 1 fork of N Stacks epochs, mined on 1 burn chain fork,
    /// all from the same miner.
    fn mine_stacks_blocks_1_fork_1_miner_1_burnchain<F, G>(
        test_name: &String,
        rounds: usize,
        mut block_builder: F,
        mut check_oracle: G,
    ) -> TestMinerTrace
    where
        F: FnMut(
            &mut ClarityTx,
            &mut StacksBlockBuilder,
            &mut TestMiner,
            usize,
            Option<&StacksMicroblockHeader>,
        ) -> (StacksBlock, Vec<StacksMicroblock>),
        G: FnMut(&StacksBlock, &Vec<StacksMicroblock>) -> bool,
    {
        let full_test_name = format!("{}-1_fork_1_miner_1_burnchain", test_name);
        let mut burn_node = TestBurnchainNode::new();
        let mut miner_factory = TestMinerFactory::new();
        let mut miner =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

        let mut node = TestStacksNode::new(
            false,
            0x80000000,
            &full_test_name,
            vec![miner.origin_address().unwrap()],
        );

        let first_snapshot =
            SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
        let mut fork = TestBurnchainFork::new(
            first_snapshot.block_height,
            &first_snapshot.burn_header_hash,
            &first_snapshot.index_root,
            0,
        );

        let mut first_burn_block =
            TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork);

        // first, register a VRF key
        node.add_key_register(&mut first_burn_block, &mut miner);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork.append_block(first_burn_block);
        burn_node.mine_fork(&mut fork);

        let mut miner_trace = vec![];

        // next, build up some stacks blocks
        for i in 0..rounds {
            let mut burn_block = {
                let ic = burn_node.sortdb.index_conn();
                fork.next_block(&ic)
            };

            let last_key = node.get_last_key(&miner);
            let parent_block_opt = node.get_last_accepted_anchored_block(&burn_node.sortdb, &miner);
            let last_microblock_header =
                get_last_microblock_header(&node, &miner, parent_block_opt.as_ref());

            // next key
            node.add_key_register(&mut burn_block, &mut miner);

            let (stacks_block, microblocks, block_commit_op) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner,
                &mut burn_block,
                &last_key,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!("Produce anchored stacks block");

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = burn_node.mine_fork(&mut fork);

            // "discover" the stacks block and its microblocks
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block,
                &microblocks,
                &block_commit_op,
            );

            // process all blocks
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block.block_hash(),
                microblocks.len()
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 1)
                .unwrap();

            let expect_success = check_oracle(&stacks_block, &microblocks);
            if expect_success {
                // processed _this_ block
                assert_eq!(tip_info_list.len(), 1);
                let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

                assert!(chain_tip_opt.is_some());
                assert!(poison_opt.is_none());

                let chain_tip = chain_tip_opt.unwrap().header;

                assert_eq!(
                    chain_tip.anchored_header.block_hash(),
                    stacks_block.block_hash()
                );
                assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &chain_tip.anchored_header
                ));
            }

            let mut next_miner_trace = TestMinerTracePoint::new();
            next_miner_trace.add(
                miner.id,
                full_test_name.clone(),
                fork_snapshot,
                stacks_block,
                microblocks,
                block_commit_op,
            );
            miner_trace.push(next_miner_trace);
        }

        TestMinerTrace::new(burn_node, vec![miner], miner_trace)
    }

    /// one miner begins a chain, and another miner joins it in the same fork at rounds/2.
    fn mine_stacks_blocks_1_fork_2_miners_1_burnchain<F>(
        test_name: &String,
        rounds: usize,
        mut miner_1_block_builder: F,
        mut miner_2_block_builder: F,
    ) -> TestMinerTrace
    where
        F: FnMut(
            &mut ClarityTx,
            &mut StacksBlockBuilder,
            &mut TestMiner,
            usize,
            Option<&StacksMicroblockHeader>,
        ) -> (StacksBlock, Vec<StacksMicroblock>),
    {
        let full_test_name = format!("{}-1_fork_2_miners_1_burnchain", test_name);
        let mut burn_node = TestBurnchainNode::new();
        let mut miner_factory = TestMinerFactory::new();
        let mut miner_1 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
        let mut miner_2 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

        let mut node = TestStacksNode::new(
            false,
            0x80000000,
            &full_test_name,
            vec![
                miner_1.origin_address().unwrap(),
                miner_2.origin_address().unwrap(),
            ],
        );

        let mut sortition_winners = vec![];

        let first_snapshot =
            SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
        let mut fork = TestBurnchainFork::new(
            first_snapshot.block_height,
            &first_snapshot.burn_header_hash,
            &first_snapshot.index_root,
            0,
        );

        let mut first_burn_block =
            TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork);

        // first, register a VRF key
        node.add_key_register(&mut first_burn_block, &mut miner_1);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork.append_block(first_burn_block);
        burn_node.mine_fork(&mut fork);

        let mut miner_trace = vec![];

        // next, build up some stacks blocks
        for i in 0..rounds / 2 {
            let mut burn_block = {
                let ic = burn_node.sortdb.index_conn();
                fork.next_block(&ic)
            };

            let last_key = node.get_last_key(&miner_1);
            let parent_block_opt = node.get_last_anchored_block(&miner_1);
            let last_microblock_header_opt =
                get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref());

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block, microblocks, block_commit_op) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block,
                &last_key,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!("Produce anchored stacks block");

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = burn_node.mine_fork(&mut fork);

            // "discover" the stacks block and its microblocks
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block,
                &microblocks,
                &block_commit_op,
            );

            // process all blocks
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block.block_hash(),
                microblocks.len()
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 1)
                .unwrap();

            // processed _this_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap().header;

            assert_eq!(
                chain_tip.anchored_header.block_hash(),
                stacks_block.block_hash()
            );
            assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &chain_tip.anchored_header
            ));

            sortition_winners.push(miner_1.origin_address().unwrap());

            let mut next_miner_trace = TestMinerTracePoint::new();
            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot,
                stacks_block,
                microblocks,
                block_commit_op,
            );
            miner_trace.push(next_miner_trace);
        }

        // miner 2 begins mining
        for i in rounds / 2..rounds {
            let mut burn_block = {
                let ic = burn_node.sortdb.index_conn();
                fork.next_block(&ic)
            };

            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);

            let last_winning_snapshot = {
                let first_block_height = burn_node.sortdb.first_block_height;
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork.get_tip(&ic);
                ic.as_handle(&chain_tip.sortition_id)
                    .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                    .expect("FATAL: no prior snapshot with sortition")
            };

            let parent_block_opt = Some(
                node.get_anchored_block(&last_winning_snapshot.winning_stacks_block_hash)
                    .expect("FATAL: no prior block from last winning snapshot"),
            );

            let last_microblock_header_opt =
                match get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref()) {
                    Some(stream) => Some(stream),
                    None => get_last_microblock_header(&node, &miner_2, parent_block_opt.as_ref()),
                };

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block,
                &last_key_1,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 1 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_2,
                &mut burn_block,
                &last_key_2,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 2 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_2_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = burn_node.mine_fork(&mut fork);

            // "discover" the stacks blocks
            let res_1 = preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );
            let res_2 = preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );

            // exactly one stacks block will have been queued up, since sortition picks only one.
            match (res_1, res_2) {
                (Some(res), None) => {}
                (None, Some(res)) => {}
                (_, _) => assert!(false),
            }

            // process all blocks
            test_debug!(
                "Process Stacks block {}",
                &fork_snapshot.winning_stacks_block_hash
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();

            // processed exactly one block, but got back two tip-infos
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap().header;

            // selected block is the sortition-winning block
            assert_eq!(
                chain_tip.anchored_header.block_hash(),
                fork_snapshot.winning_stacks_block_hash
            );
            assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

            let mut next_miner_trace = TestMinerTracePoint::new();
            if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
                test_debug!(
                    "\n\nMiner 1 ({}) won sortition\n",
                    miner_1.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_1.header
                ));
                sortition_winners.push(miner_1.origin_address().unwrap());

                next_miner_trace.add(
                    miner_1.id,
                    full_test_name.clone(),
                    fork_snapshot,
                    stacks_block_1,
                    microblocks_1,
                    block_commit_op_1,
                );
            } else {
                test_debug!(
                    "\n\nMiner 2 ({}) won sortition\n",
                    miner_2.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_2.header
                ));
                sortition_winners.push(miner_2.origin_address().unwrap());

                next_miner_trace.add(
                    miner_2.id,
                    full_test_name.clone(),
                    fork_snapshot,
                    stacks_block_2,
                    microblocks_2,
                    block_commit_op_2,
                );
            }

            miner_trace.push(next_miner_trace);
        }

        TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
    }

    /// two miners begin working on the same stacks chain, and then the stacks chain forks
    /// (resulting in two chainstates).  The burnchain is unaffected.  One miner continues on one
    /// chainstate, and the other continues on the other chainstate.  Fork happens on rounds/2
    fn mine_stacks_blocks_2_forks_2_miners_1_burnchain<F>(
        test_name: &String,
        rounds: usize,
        miner_1_block_builder: F,
        miner_2_block_builder: F,
    ) -> TestMinerTrace
    where
        F: FnMut(
            &mut ClarityTx,
            &mut StacksBlockBuilder,
            &mut TestMiner,
            usize,
            Option<&StacksMicroblockHeader>,
        ) -> (StacksBlock, Vec<StacksMicroblock>),
    {
        mine_stacks_blocks_2_forks_at_height_2_miners_1_burnchain(
            test_name,
            rounds,
            rounds / 2,
            miner_1_block_builder,
            miner_2_block_builder,
        )
    }

    /// two miners begin working on the same stacks chain, and then the stacks chain forks
    /// (resulting in two chainstates).  The burnchain is unaffected.  One miner continues on one
    /// chainstate, and the other continues on the other chainstate.  Fork happens on fork_height
    fn mine_stacks_blocks_2_forks_at_height_2_miners_1_burnchain<F>(
        test_name: &String,
        rounds: usize,
        fork_height: usize,
        mut miner_1_block_builder: F,
        mut miner_2_block_builder: F,
    ) -> TestMinerTrace
    where
        F: FnMut(
            &mut ClarityTx,
            &mut StacksBlockBuilder,
            &mut TestMiner,
            usize,
            Option<&StacksMicroblockHeader>,
        ) -> (StacksBlock, Vec<StacksMicroblock>),
    {
        let full_test_name = format!("{}-2_forks_2_miners_1_burnchain", test_name);
        let mut burn_node = TestBurnchainNode::new();
        let mut miner_factory = TestMinerFactory::new();
        let mut miner_1 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
        let mut miner_2 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

        let mut node = TestStacksNode::new(
            false,
            0x80000000,
            &full_test_name,
            vec![
                miner_1.origin_address().unwrap(),
                miner_2.origin_address().unwrap(),
            ],
        );

        let mut sortition_winners = vec![];

        let first_snapshot =
            SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
        let mut fork = TestBurnchainFork::new(
            first_snapshot.block_height,
            &first_snapshot.burn_header_hash,
            &first_snapshot.index_root,
            0,
        );

        let mut first_burn_block =
            TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork);

        // first, register a VRF key
        node.add_key_register(&mut first_burn_block, &mut miner_1);
        node.add_key_register(&mut first_burn_block, &mut miner_2);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork.append_block(first_burn_block);
        burn_node.mine_fork(&mut fork);

        let mut miner_trace = vec![];

        // miner 1 and 2 cooperate to build a shared fork
        for i in 0..fork_height {
            let mut burn_block = {
                let ic = burn_node.sortdb.index_conn();
                fork.next_block(&ic)
            };

            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);

            let last_winning_snapshot = {
                let first_block_height = burn_node.sortdb.first_block_height;
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork.get_tip(&ic);
                ic.as_handle(&chain_tip.sortition_id)
                    .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                    .expect("FATAL: no prior snapshot with sortition")
            };

            let (parent_block_opt, last_microblock_header_opt) = if last_winning_snapshot
                .num_sortitions
                == 0
            {
                // this is the first block
                (None, None)
            } else {
                // this is a subsequent block
                let parent_block_opt = Some(
                    node.get_anchored_block(&last_winning_snapshot.winning_stacks_block_hash)
                        .expect("FATAL: no prior block from last winning snapshot"),
                );
                let last_microblock_header_opt =
                    match get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref()) {
                        Some(stream) => Some(stream),
                        None => {
                            get_last_microblock_header(&node, &miner_2, parent_block_opt.as_ref())
                        }
                    };
                (parent_block_opt, last_microblock_header_opt)
            };

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block,
                &last_key_1,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 1 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_2,
                &mut burn_block,
                &last_key_2,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 2 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_2_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = burn_node.mine_fork(&mut fork);

            // "discover" the stacks block and its microblocks
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );

            // process all blocks
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block_1.block_hash(),
                microblocks_1.len()
            );
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block_2.block_hash(),
                microblocks_2.len()
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();

            // processed _one_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap().header;

            let mut next_miner_trace = TestMinerTracePoint::new();
            if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
                test_debug!(
                    "\n\nMiner 1 ({}) won sortition\n",
                    miner_1.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_1.header
                ));
                sortition_winners.push(miner_1.origin_address().unwrap());
            } else {
                test_debug!(
                    "\n\nMiner 2 ({}) won sortition\n",
                    miner_2.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_2.header
                ));
                sortition_winners.push(miner_2.origin_address().unwrap());
            }

            // add both blocks to the miner trace, because in this test runner, there will be _two_
            // nodes that process _all_ blocks
            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot.clone(),
                stacks_block_1.clone(),
                microblocks_1.clone(),
                block_commit_op_1.clone(),
            );
            next_miner_trace.add(
                miner_2.id,
                full_test_name.clone(),
                fork_snapshot.clone(),
                stacks_block_2.clone(),
                microblocks_2.clone(),
                block_commit_op_2.clone(),
            );
            miner_trace.push(next_miner_trace);
        }

        test_debug!("\n\nMiner 1 and Miner 2 now separate\n\n");

        let mut sortition_winners_1 = sortition_winners.clone();
        let mut sortition_winners_2 = sortition_winners.clone();
        let snapshot_at_fork = {
            let ic = burn_node.sortdb.index_conn();
            let tip = fork.get_tip(&ic);
            tip
        };

        assert_eq!(snapshot_at_fork.num_sortitions, fork_height as u64);

        // give miner 2 its own chain state directory
        let full_test_name_2 = format!("{}.2", &full_test_name);
        let mut node_2 = node.fork(&full_test_name_2);

        // miner 1 begins working on its own fork.
        // miner 2 begins working on its own fork.
        for i in fork_height..rounds {
            let mut burn_block = {
                let ic = burn_node.sortdb.index_conn();
                fork.next_block(&ic)
            };

            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node_2.get_last_key(&miner_2);

            let mut last_winning_snapshot_1 = {
                let ic = burn_node.sortdb.index_conn();
                let tip = fork.get_tip(&ic);
                match TestStacksNode::get_last_winning_snapshot(&ic, &tip, &miner_1) {
                    Some(sn) => sn,
                    None => SortitionDB::get_first_block_snapshot(&ic).unwrap(),
                }
            };

            let mut last_winning_snapshot_2 = {
                let ic = burn_node.sortdb.index_conn();
                let tip = fork.get_tip(&ic);
                match TestStacksNode::get_last_winning_snapshot(&ic, &tip, &miner_2) {
                    Some(sn) => sn,
                    None => SortitionDB::get_first_block_snapshot(&ic).unwrap(),
                }
            };

            // build off of the point where the fork occurred, regardless of who won that sortition
            if last_winning_snapshot_1.num_sortitions < snapshot_at_fork.num_sortitions {
                last_winning_snapshot_1 = snapshot_at_fork.clone();
            }
            if last_winning_snapshot_2.num_sortitions < snapshot_at_fork.num_sortitions {
                last_winning_snapshot_2 = snapshot_at_fork.clone();
            }

            let parent_block_opt_1 =
                node.get_anchored_block(&last_winning_snapshot_1.winning_stacks_block_hash);
            let parent_block_opt_2 =
                node_2.get_anchored_block(&last_winning_snapshot_2.winning_stacks_block_hash);

            let last_microblock_header_opt_1 =
                get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
            let last_microblock_header_opt_2 =
                get_last_microblock_header(&node_2, &miner_2, parent_block_opt_2.as_ref());

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node_2.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block,
                &last_key_1,
                parent_block_opt_1.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Miner {}: Produce anchored stacks block in stacks fork 1 via {}",
                        miner.id,
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_1.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            let (stacks_block_2, microblocks_2, block_commit_op_2) = node_2.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_2,
                &mut burn_block,
                &last_key_2,
                parent_block_opt_2.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Miner {}: Produce anchored stacks block in stacks fork 2 via {}",
                        miner.id,
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate =
                        open_chainstate(false, 0x80000000, &full_test_name_2);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_2_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_2.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork.append_block(burn_block);
            let fork_snapshot = burn_node.mine_fork(&mut fork);

            // "discover" the stacks blocks
            let res_1 = preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );
            let res_2 = preprocess_stacks_block_data(
                &mut node_2,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );

            // exactly one stacks block will have been queued up, since sortition picks only one.
            match (res_1, res_2) {
                (Some(res), None) => assert!(res),
                (None, Some(res)) => assert!(res),
                (_, _) => assert!(false),
            }

            // process all blocks
            test_debug!(
                "Process Stacks block {}",
                &fork_snapshot.winning_stacks_block_hash
            );
            let mut tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();
            let mut tip_info_list_2 = node_2
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();

            tip_info_list.append(&mut tip_info_list_2);

            // processed exactly one block, but got back two tip-infos
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap().header;

            // selected block is the sortition-winning block
            assert_eq!(
                chain_tip.anchored_header.block_hash(),
                fork_snapshot.winning_stacks_block_hash
            );
            assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

            let mut next_miner_trace = TestMinerTracePoint::new();
            if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
                test_debug!(
                    "\n\nMiner 1 ({}) won sortition\n",
                    miner_1.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_1.header
                ));
                sortition_winners_1.push(miner_1.origin_address().unwrap());
            } else {
                test_debug!(
                    "\n\nMiner 2 ({}) won sortition\n",
                    miner_2.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node_2.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_2.header
                ));
                sortition_winners_2.push(miner_2.origin_address().unwrap());
            }

            // each miner produced a block; just one of them got accepted
            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot.clone(),
                stacks_block_1.clone(),
                microblocks_1.clone(),
                block_commit_op_1.clone(),
            );
            next_miner_trace.add(
                miner_2.id,
                full_test_name_2.clone(),
                fork_snapshot.clone(),
                stacks_block_2.clone(),
                microblocks_2.clone(),
                block_commit_op_2.clone(),
            );
            miner_trace.push(next_miner_trace);

            // keep chainstates in sync with one another -- each node discovers each other nodes'
            // block data.
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );
            preprocess_stacks_block_data(
                &mut node_2,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );
            let _ = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();
            let _ = node_2
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();
        }

        TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
    }

    /// two miners work on the same fork, and the burnchain splits them.
    /// the split happens at rounds/2
    fn mine_stacks_blocks_1_fork_2_miners_2_burnchains<F>(
        test_name: &String,
        rounds: usize,
        mut miner_1_block_builder: F,
        mut miner_2_block_builder: F,
    ) -> TestMinerTrace
    where
        F: FnMut(
            &mut ClarityTx,
            &mut StacksBlockBuilder,
            &mut TestMiner,
            usize,
            Option<&StacksMicroblockHeader>,
        ) -> (StacksBlock, Vec<StacksMicroblock>),
    {
        let full_test_name = format!("{}-1_fork_2_miners_2_burnchain", test_name);
        let mut burn_node = TestBurnchainNode::new();
        let mut miner_factory = TestMinerFactory::new();
        let mut miner_1 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
        let mut miner_2 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

        let mut node = TestStacksNode::new(
            false,
            0x80000000,
            &full_test_name,
            vec![
                miner_1.origin_address().unwrap(),
                miner_2.origin_address().unwrap(),
            ],
        );

        let first_snapshot =
            SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
        let mut fork_1 = TestBurnchainFork::new(
            first_snapshot.block_height,
            &first_snapshot.burn_header_hash,
            &first_snapshot.index_root,
            0,
        );

        let mut first_burn_block =
            TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork_1);

        // first, register a VRF key
        node.add_key_register(&mut first_burn_block, &mut miner_1);
        node.add_key_register(&mut first_burn_block, &mut miner_2);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork_1.append_block(first_burn_block);
        burn_node.mine_fork(&mut fork_1);

        let mut miner_trace = vec![];

        // next, build up some stacks blocks, cooperatively
        for i in 0..rounds / 2 {
            let mut burn_block = {
                let ic = burn_node.sortdb.index_conn();
                fork_1.next_block(&ic)
            };

            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);

            let last_winning_snapshot = {
                let first_block_height = burn_node.sortdb.first_block_height;
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork_1.get_tip(&ic);
                ic.as_handle(&chain_tip.sortition_id)
                    .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                    .expect("FATAL: no prior snapshot with sortition")
            };

            let (parent_block_opt, last_microblock_header_opt) = if last_winning_snapshot
                .num_sortitions
                == 0
            {
                // this is the first block
                (None, None)
            } else {
                // this is a subsequent block
                let parent_block_opt = Some(
                    node.get_anchored_block(&last_winning_snapshot.winning_stacks_block_hash)
                        .expect("FATAL: no prior block from last winning snapshot"),
                );
                let last_microblock_header_opt =
                    match get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref()) {
                        Some(stream) => Some(stream),
                        None => {
                            get_last_microblock_header(&node, &miner_2, parent_block_opt.as_ref())
                        }
                    };
                (parent_block_opt, last_microblock_header_opt)
            };

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block,
                &last_key_1,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!("Produce anchored stacks block from miner 1");

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_2,
                &mut burn_block,
                &last_key_2,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!("Produce anchored stacks block from miner 2");

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_2_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork_1.append_block(burn_block);
            let fork_snapshot = burn_node.mine_fork(&mut fork_1);

            // "discover" the stacks block
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );

            // process all blocks
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block_1.block_hash(),
                microblocks_1.len()
            );
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block_2.block_hash(),
                microblocks_2.len()
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();

            // processed _one_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap().header;

            // selected block is the sortition-winning block
            assert_eq!(
                chain_tip.anchored_header.block_hash(),
                fork_snapshot.winning_stacks_block_hash
            );
            assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

            let mut next_miner_trace = TestMinerTracePoint::new();
            if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
                test_debug!(
                    "\n\nMiner 1 ({}) won sortition\n",
                    miner_1.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_1.header
                ));
                next_miner_trace.add(
                    miner_1.id,
                    full_test_name.clone(),
                    fork_snapshot,
                    stacks_block_1,
                    microblocks_1,
                    block_commit_op_1,
                );
            } else {
                test_debug!(
                    "\n\nMiner 2 ({}) won sortition\n",
                    miner_2.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_2.header
                ));
                next_miner_trace.add(
                    miner_2.id,
                    full_test_name.clone(),
                    fork_snapshot,
                    stacks_block_2,
                    microblocks_2,
                    block_commit_op_2,
                );
            }
            miner_trace.push(next_miner_trace);
        }

        let mut fork_2 = fork_1.fork();

        test_debug!("\n\n\nbegin burnchain fork\n\n");

        // next, build up some stacks blocks on two separate burnchain forks.
        // send the same leader key register transactions to both forks.
        for i in rounds / 2..rounds {
            let mut burn_block_1 = {
                let ic = burn_node.sortdb.index_conn();
                fork_1.next_block(&ic)
            };
            let mut burn_block_2 = {
                let ic = burn_node.sortdb.index_conn();
                fork_2.next_block(&ic)
            };

            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);

            let block_1_snapshot = {
                let first_block_height = burn_node.sortdb.first_block_height;
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork_1.get_tip(&ic);
                ic.as_handle(&chain_tip.sortition_id)
                    .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                    .expect("FATAL: no prior snapshot with sortition")
            };

            let block_2_snapshot = {
                let first_block_height = burn_node.sortdb.first_block_height;
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork_2.get_tip(&ic);
                ic.as_handle(&chain_tip.sortition_id)
                    .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                    .expect("FATAL: no prior snapshot with sortition")
            };

            let parent_block_opt_1 =
                node.get_anchored_block(&block_1_snapshot.winning_stacks_block_hash);
            let parent_block_opt_2 =
                node.get_anchored_block(&block_2_snapshot.winning_stacks_block_hash);

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block_1, &mut miner_1);
            node.add_key_register(&mut burn_block_2, &mut miner_2);

            let last_microblock_header_opt_1 =
                get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
            let last_microblock_header_opt_2 =
                get_last_microblock_header(&node, &miner_2, parent_block_opt_2.as_ref());

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block_1,
                &last_key_1,
                parent_block_opt_1.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 1 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_1.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_2,
                &mut burn_block_2,
                &last_key_2,
                parent_block_opt_2.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 2 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_2_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_2.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork_1.append_block(burn_block_1);
            fork_2.append_block(burn_block_2);
            let fork_snapshot_1 = burn_node.mine_fork(&mut fork_1);
            let fork_snapshot_2 = burn_node.mine_fork(&mut fork_2);

            assert!(fork_snapshot_1.burn_header_hash != fork_snapshot_2.burn_header_hash);
            assert!(fork_snapshot_1.consensus_hash != fork_snapshot_2.consensus_hash);

            // "discover" the stacks block
            test_debug!("preprocess fork 1 {}", stacks_block_1.block_hash());
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot_1,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );

            test_debug!("preprocess fork 2 {}", stacks_block_1.block_hash());
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot_2,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );

            // process all blocks
            test_debug!(
                "Process all Stacks blocks: {}, {}",
                &stacks_block_1.block_hash(),
                &stacks_block_2.block_hash()
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();

            // processed all stacks blocks -- one on each burn chain fork
            assert_eq!(tip_info_list.len(), 2);

            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                assert!(chain_tip_opt.is_some());
                assert!(poison_opt.is_none());
            }

            // fork 1?
            let mut found_fork_1 = false;
            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                let chain_tip = chain_tip_opt.clone().unwrap().header;
                if chain_tip.consensus_hash == fork_snapshot_1.consensus_hash {
                    found_fork_1 = true;
                    assert_eq!(
                        chain_tip.anchored_header.block_hash(),
                        stacks_block_1.block_hash()
                    );

                    // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                    assert!(check_block_state_index_root(
                        &mut node.chainstate,
                        &fork_snapshot_1.consensus_hash,
                        &chain_tip.anchored_header
                    ));
                }
            }

            assert!(found_fork_1);

            let mut found_fork_2 = false;
            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                let chain_tip = chain_tip_opt.clone().unwrap().header;
                if chain_tip.consensus_hash == fork_snapshot_2.consensus_hash {
                    found_fork_2 = true;
                    assert_eq!(
                        chain_tip.anchored_header.block_hash(),
                        stacks_block_2.block_hash()
                    );

                    // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                    assert!(check_block_state_index_root(
                        &mut node.chainstate,
                        &fork_snapshot_2.consensus_hash,
                        &chain_tip.anchored_header
                    ));
                }
            }

            assert!(found_fork_2);

            let mut next_miner_trace = TestMinerTracePoint::new();
            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot_1,
                stacks_block_1,
                microblocks_1,
                block_commit_op_1,
            );
            next_miner_trace.add(
                miner_2.id,
                full_test_name.clone(),
                fork_snapshot_2,
                stacks_block_2,
                microblocks_2,
                block_commit_op_2,
            );
            miner_trace.push(next_miner_trace);
        }

        TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
    }

    /// two miners begin working on separate forks, and the burnchain splits out under them,
    /// putting each one on a different fork.
    /// split happens at rounds/2
    fn mine_stacks_blocks_2_forks_2_miners_2_burnchains<F>(
        test_name: &String,
        rounds: usize,
        mut miner_1_block_builder: F,
        mut miner_2_block_builder: F,
    ) -> TestMinerTrace
    where
        F: FnMut(
            &mut ClarityTx,
            &mut StacksBlockBuilder,
            &mut TestMiner,
            usize,
            Option<&StacksMicroblockHeader>,
        ) -> (StacksBlock, Vec<StacksMicroblock>),
    {
        let full_test_name = format!("{}-2_forks_2_miner_2_burnchains", test_name);
        let mut burn_node = TestBurnchainNode::new();
        let mut miner_factory = TestMinerFactory::new();
        let mut miner_1 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
        let mut miner_2 =
            miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

        let mut node = TestStacksNode::new(
            false,
            0x80000000,
            &full_test_name,
            vec![
                miner_1.origin_address().unwrap(),
                miner_2.origin_address().unwrap(),
            ],
        );

        let first_snapshot =
            SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
        let mut fork_1 = TestBurnchainFork::new(
            first_snapshot.block_height,
            &first_snapshot.burn_header_hash,
            &first_snapshot.index_root,
            0,
        );

        let mut first_burn_block =
            TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork_1);

        // first, register a VRF key
        node.add_key_register(&mut first_burn_block, &mut miner_1);
        node.add_key_register(&mut first_burn_block, &mut miner_2);

        test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

        fork_1.append_block(first_burn_block);
        burn_node.mine_fork(&mut fork_1);

        let mut miner_trace = vec![];

        // next, build up some stacks blocks. miners cooperate
        for i in 0..rounds / 2 {
            let mut burn_block = {
                let ic = burn_node.sortdb.index_conn();
                fork_1.next_block(&ic)
            };

            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);

            let (block_1_snapshot_opt, block_2_snapshot_opt) = {
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork_1.get_tip(&ic);
                let block_1_snapshot_opt =
                    TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_1);
                let block_2_snapshot_opt =
                    TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_2);
                (block_1_snapshot_opt, block_2_snapshot_opt)
            };

            let parent_block_opt_1 = match block_1_snapshot_opt {
                Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
                None => None,
            };

            let parent_block_opt_2 = match block_2_snapshot_opt {
                Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
                None => parent_block_opt_1.clone(),
            };

            let last_microblock_header_opt_1 =
                get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
            let last_microblock_header_opt_2 =
                get_last_microblock_header(&node, &miner_2, parent_block_opt_2.as_ref());

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block, &mut miner_1);
            node.add_key_register(&mut burn_block, &mut miner_2);

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block,
                &last_key_1,
                parent_block_opt_1.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!("Produce anchored stacks block");

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_1.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_2,
                &mut burn_block,
                &last_key_2,
                parent_block_opt_2.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!("Produce anchored stacks block");

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_2_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_2.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork_1.append_block(burn_block);
            let fork_snapshot = burn_node.mine_fork(&mut fork_1);

            // "discover" the stacks block
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );

            // process all blocks
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block_1.block_hash(),
                microblocks_1.len()
            );
            test_debug!(
                "Process Stacks block {} and {} microblocks",
                &stacks_block_2.block_hash(),
                microblocks_2.len()
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();

            // processed _one_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap().header;

            // selected block is the sortition-winning block
            assert_eq!(
                chain_tip.anchored_header.block_hash(),
                fork_snapshot.winning_stacks_block_hash
            );
            assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

            let mut next_miner_trace = TestMinerTracePoint::new();
            if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
                test_debug!(
                    "\n\nMiner 1 ({}) won sortition\n",
                    miner_1.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_1.header
                ));
                next_miner_trace.add(
                    miner_1.id,
                    full_test_name.clone(),
                    fork_snapshot.clone(),
                    stacks_block_1,
                    microblocks_1,
                    block_commit_op_1,
                );
            } else {
                test_debug!(
                    "\n\nMiner 2 ({}) won sortition\n",
                    miner_2.origin_address().unwrap().to_string()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot.consensus_hash,
                    &stacks_block_2.header
                ));
                next_miner_trace.add(
                    miner_2.id,
                    full_test_name.clone(),
                    fork_snapshot,
                    stacks_block_2,
                    microblocks_2,
                    block_commit_op_2,
                );
            }

            miner_trace.push(next_miner_trace);
        }

        let mut fork_2 = fork_1.fork();

        test_debug!("\n\n\nbegin burnchain fork\n\n");

        // next, build up some stacks blocks on two separate burnchain forks.
        // send the same leader key register transactions to both forks.
        // miner 1 works on fork 1
        // miner 2 works on fork 2
        for i in rounds / 2..rounds {
            let mut burn_block_1 = {
                let ic = burn_node.sortdb.index_conn();
                fork_1.next_block(&ic)
            };
            let mut burn_block_2 = {
                let ic = burn_node.sortdb.index_conn();
                fork_2.next_block(&ic)
            };

            let last_key_1 = node.get_last_key(&miner_1);
            let last_key_2 = node.get_last_key(&miner_2);
            let block_1_snapshot_opt = {
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork_1.get_tip(&ic);
                TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_1)
            };
            let block_2_snapshot_opt = {
                let ic = burn_node.sortdb.index_conn();
                let chain_tip = fork_2.get_tip(&ic);
                TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_2)
            };

            let parent_block_opt_1 = match block_1_snapshot_opt {
                Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
                None => None,
            };

            let parent_block_opt_2 = match block_2_snapshot_opt {
                Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
                None => parent_block_opt_1.clone(),
            };

            // send next key (key for block i+1)
            node.add_key_register(&mut burn_block_1, &mut miner_1);
            node.add_key_register(&mut burn_block_2, &mut miner_2);

            let last_microblock_header_opt_1 =
                get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
            let last_microblock_header_opt_2 =
                get_last_microblock_header(&node, &miner_2, parent_block_opt_2.as_ref());

            let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_1,
                &mut burn_block_1,
                &last_key_1,
                parent_block_opt_1.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 1 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_1_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_1.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
                &mut burn_node.sortdb,
                &mut miner_2,
                &mut burn_block_2,
                &last_key_2,
                parent_block_opt_2.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    test_debug!(
                        "Produce anchored stacks block in stacks fork 2 via {}",
                        miner.origin_address().unwrap().to_string()
                    );

                    let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                    let all_prev_mining_rewards = get_all_mining_rewards(
                        &mut miner_chainstate,
                        &builder.chain_tip,
                        builder.chain_tip.stacks_block_height,
                    );

                    let sort_iconn = sortdb.index_conn();
                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;
                    let (stacks_block, microblocks) = miner_2_block_builder(
                        &mut epoch,
                        &mut builder,
                        miner,
                        i,
                        last_microblock_header_opt_2.as_ref(),
                    );

                    assert!(check_mining_reward(
                        &mut epoch,
                        miner,
                        builder.chain_tip.stacks_block_height,
                        &all_prev_mining_rewards
                    ));

                    builder.epoch_finish(epoch);
                    (stacks_block, microblocks)
                },
            );

            // process burn chain
            fork_1.append_block(burn_block_1);
            fork_2.append_block(burn_block_2);
            let fork_snapshot_1 = burn_node.mine_fork(&mut fork_1);
            let fork_snapshot_2 = burn_node.mine_fork(&mut fork_2);

            assert!(fork_snapshot_1.burn_header_hash != fork_snapshot_2.burn_header_hash);
            assert!(fork_snapshot_1.consensus_hash != fork_snapshot_2.consensus_hash);

            // "discover" the stacks block
            test_debug!("preprocess fork 1 {}", stacks_block_1.block_hash());
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot_1,
                &stacks_block_1,
                &microblocks_1,
                &block_commit_op_1,
            );

            test_debug!("preprocess fork 2 {}", stacks_block_1.block_hash());
            preprocess_stacks_block_data(
                &mut node,
                &mut burn_node,
                &fork_snapshot_2,
                &stacks_block_2,
                &microblocks_2,
                &block_commit_op_2,
            );

            // process all blocks
            test_debug!(
                "Process all Stacks blocks: {}, {}",
                &stacks_block_1.block_hash(),
                &stacks_block_2.block_hash()
            );
            let tip_info_list = node
                .chainstate
                .process_blocks_at_tip(&mut burn_node.sortdb, 2)
                .unwrap();

            // processed all stacks blocks -- one on each burn chain fork
            assert_eq!(tip_info_list.len(), 2);

            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                assert!(chain_tip_opt.is_some());
                assert!(poison_opt.is_none());
            }

            // fork 1?
            let mut found_fork_1 = false;
            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                let chain_tip = chain_tip_opt.clone().unwrap().header;
                if chain_tip.consensus_hash == fork_snapshot_1.consensus_hash {
                    found_fork_1 = true;
                    assert_eq!(
                        chain_tip.anchored_header.block_hash(),
                        stacks_block_1.block_hash()
                    );

                    // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                    assert!(check_block_state_index_root(
                        &mut node.chainstate,
                        &fork_snapshot_1.consensus_hash,
                        &chain_tip.anchored_header
                    ));
                }
            }

            assert!(found_fork_1);

            let mut found_fork_2 = false;
            for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
                let chain_tip = chain_tip_opt.clone().unwrap().header;
                if chain_tip.consensus_hash == fork_snapshot_2.consensus_hash {
                    found_fork_2 = true;
                    assert_eq!(
                        chain_tip.anchored_header.block_hash(),
                        stacks_block_2.block_hash()
                    );

                    // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                    assert!(check_block_state_index_root(
                        &mut node.chainstate,
                        &fork_snapshot_2.consensus_hash,
                        &chain_tip.anchored_header
                    ));
                }
            }

            assert!(found_fork_2);

            let mut next_miner_trace = TestMinerTracePoint::new();
            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot_1,
                stacks_block_1,
                microblocks_1,
                block_commit_op_1,
            );
            next_miner_trace.add(
                miner_2.id,
                full_test_name.clone(),
                fork_snapshot_2,
                stacks_block_2,
                microblocks_2,
                block_commit_op_2,
            );
            miner_trace.push(next_miner_trace);
        }

        TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
    }

    /// compare two chainstates to see if they have exactly the same blocks and microblocks.
    fn assert_chainstate_blocks_eq(test_name_1: &str, test_name_2: &str) {
        let ch1 = open_chainstate(false, 0x80000000, test_name_1);
        let ch2 = open_chainstate(false, 0x80000000, test_name_2);

        // check presence of anchored blocks
        let mut all_blocks_1 = StacksChainState::list_blocks(&ch1.db()).unwrap();
        let mut all_blocks_2 = StacksChainState::list_blocks(&ch2.db()).unwrap();

        all_blocks_1.sort();
        all_blocks_2.sort();

        assert_eq!(all_blocks_1.len(), all_blocks_2.len());
        for i in 0..all_blocks_1.len() {
            assert_eq!(all_blocks_1[i], all_blocks_2[i]);
        }

        // check presence and ordering of microblocks
        let mut all_microblocks_1 =
            StacksChainState::list_microblocks(&ch1.db(), &ch1.blocks_path).unwrap();
        let mut all_microblocks_2 =
            StacksChainState::list_microblocks(&ch2.db(), &ch2.blocks_path).unwrap();

        all_microblocks_1.sort();
        all_microblocks_2.sort();

        assert_eq!(all_microblocks_1.len(), all_microblocks_2.len());
        for i in 0..all_microblocks_1.len() {
            assert_eq!(all_microblocks_1[i].0, all_microblocks_2[i].0);
            assert_eq!(all_microblocks_1[i].1, all_microblocks_2[i].1);

            assert_eq!(all_microblocks_1[i].2.len(), all_microblocks_2[i].2.len());
            for j in 0..all_microblocks_1[i].2.len() {
                assert_eq!(all_microblocks_1[i].2[j], all_microblocks_2[i].2[j]);
            }
        }

        // compare block status (staging vs confirmed) and contents
        for i in 0..all_blocks_1.len() {
            let staging_1_opt = StacksChainState::load_staging_block(
                &ch1.db(),
                &ch2.blocks_path,
                &all_blocks_1[i].0,
                &all_blocks_1[i].1,
            )
            .unwrap();
            let staging_2_opt = StacksChainState::load_staging_block(
                &ch2.db(),
                &ch2.blocks_path,
                &all_blocks_2[i].0,
                &all_blocks_2[i].1,
            )
            .unwrap();

            let chunk_1_opt = StacksChainState::load_block(
                &ch1.blocks_path,
                &all_blocks_1[i].0,
                &all_blocks_1[i].1,
            )
            .unwrap();
            let chunk_2_opt = StacksChainState::load_block(
                &ch2.blocks_path,
                &all_blocks_2[i].0,
                &all_blocks_2[i].1,
            )
            .unwrap();

            match (staging_1_opt, staging_2_opt) {
                (Some(staging_1), Some(staging_2)) => {
                    assert_eq!(staging_1.block_data, staging_2.block_data);
                }
                (None, None) => {}
                (_, _) => {
                    assert!(false);
                }
            }

            match (chunk_1_opt, chunk_2_opt) {
                (Some(block_1), Some(block_2)) => {
                    assert_eq!(block_1, block_2);
                }
                (None, None) => {}
                (_, _) => {
                    assert!(false);
                }
            }
        }

        for i in 0..all_microblocks_1.len() {
            if all_microblocks_1[i].2.len() == 0 {
                continue;
            }

            let chunk_1_opt = StacksChainState::load_descendant_staging_microblock_stream(
                &ch1.db(),
                &StacksBlockHeader::make_index_block_hash(
                    &all_microblocks_1[i].0,
                    &all_microblocks_1[i].1,
                ),
                0,
                u16::MAX,
            )
            .unwrap();
            let chunk_2_opt = StacksChainState::load_descendant_staging_microblock_stream(
                &ch1.db(),
                &StacksBlockHeader::make_index_block_hash(
                    &all_microblocks_2[i].0,
                    &all_microblocks_2[i].1,
                ),
                0,
                u16::MAX,
            )
            .unwrap();

            match (chunk_1_opt, chunk_2_opt) {
                (Some(chunk_1), Some(chunk_2)) => {
                    assert_eq!(chunk_1, chunk_2);
                }
                (None, None) => {}
                (_, _) => {
                    assert!(false);
                }
            }
            for j in 0..all_microblocks_1[i].2.len() {
                // staging status is the same
                let staging_1_opt = StacksChainState::load_staging_microblock(
                    &ch1.db(),
                    &all_microblocks_1[i].0,
                    &all_microblocks_1[i].1,
                    &all_microblocks_1[i].2[j],
                )
                .unwrap();
                let staging_2_opt = StacksChainState::load_staging_microblock(
                    &ch2.db(),
                    &all_microblocks_2[i].0,
                    &all_microblocks_2[i].1,
                    &all_microblocks_2[i].2[j],
                )
                .unwrap();

                match (staging_1_opt, staging_2_opt) {
                    (Some(staging_1), Some(staging_2)) => {
                        assert_eq!(staging_1.block_data, staging_2.block_data);
                    }
                    (None, None) => {}
                    (_, _) => {
                        assert!(false);
                    }
                }
            }
        }
    }

    /// produce all stacks blocks, but don't process them in order.  Instead, queue them all up and
    /// process them in randomized order.
    /// This works by running mine_stacks_blocks_1_fork_1_miner_1_burnchain, extracting the blocks,
    /// and then re-processing them in a different chainstate directory.
    fn miner_trace_replay_randomized(miner_trace: &mut TestMinerTrace) {
        test_debug!("\n\n");
        test_debug!("------------------------------------------------------------------------");
        test_debug!("                   Randomize and re-apply blocks");
        test_debug!("------------------------------------------------------------------------");
        test_debug!("\n\n");

        let rounds = miner_trace.rounds();
        let test_names = miner_trace.get_test_names();
        let mut nodes = HashMap::new();
        for (i, test_name) in test_names.iter().enumerate() {
            let rnd_test_name = format!("{}-replay_randomized", test_name);
            let next_node = TestStacksNode::new(
                false,
                0x80000000,
                &rnd_test_name,
                miner_trace
                    .miners
                    .iter()
                    .map(|ref miner| miner.origin_address().unwrap())
                    .collect(),
            );
            nodes.insert(test_name, next_node);
        }

        let expected_num_sortitions = miner_trace.get_num_sortitions();
        let expected_num_blocks = miner_trace.get_num_blocks();
        let mut num_processed = 0;

        let mut rng = thread_rng();
        miner_trace.points.as_mut_slice().shuffle(&mut rng);

        // "discover" blocks in random order
        for point in miner_trace.points.drain(..) {
            let mut miner_ids = point.get_miner_ids();
            miner_ids.as_mut_slice().shuffle(&mut rng);

            for miner_id in miner_ids {
                let fork_snapshot_opt = point.get_block_snapshot(miner_id);
                let stacks_block_opt = point.get_stacks_block(miner_id);
                let microblocks_opt = point.get_microblocks(miner_id);
                let block_commit_op_opt = point.get_block_commit(miner_id);

                if fork_snapshot_opt.is_none() || block_commit_op_opt.is_none() {
                    // no sortition by this miner at this point in time
                    continue;
                }

                let fork_snapshot = fork_snapshot_opt.unwrap();
                let block_commit_op = block_commit_op_opt.unwrap();

                match stacks_block_opt {
                    Some(stacks_block) => {
                        let mut microblocks = microblocks_opt.unwrap_or(vec![]);

                        // "discover" the stacks block and its microblocks in all nodes
                        // TODO: randomize microblock discovery order too
                        for (node_name, mut node) in nodes.iter_mut() {
                            microblocks.as_mut_slice().shuffle(&mut rng);

                            preprocess_stacks_block_data(
                                &mut node,
                                &mut miner_trace.burn_node,
                                &fork_snapshot,
                                &stacks_block,
                                &vec![],
                                &block_commit_op,
                            );

                            if microblocks.len() > 0 {
                                for mblock in microblocks.iter() {
                                    preprocess_stacks_block_data(
                                        &mut node,
                                        &mut miner_trace.burn_node,
                                        &fork_snapshot,
                                        &stacks_block,
                                        &vec![mblock.clone()],
                                        &block_commit_op,
                                    );

                                    // process all the blocks we can
                                    test_debug!(
                                        "Process Stacks block {} and microblock {} {}",
                                        &stacks_block.block_hash(),
                                        mblock.block_hash(),
                                        mblock.header.sequence
                                    );
                                    let tip_info_list = node
                                        .chainstate
                                        .process_blocks_at_tip(
                                            &mut miner_trace.burn_node.sortdb,
                                            expected_num_blocks,
                                        )
                                        .unwrap();

                                    num_processed += tip_info_list.len();
                                }
                            } else {
                                // process all the blocks we can
                                test_debug!(
                                    "Process Stacks block {} and {} microblocks in {}",
                                    &stacks_block.block_hash(),
                                    microblocks.len(),
                                    &node_name
                                );
                                let tip_info_list = node
                                    .chainstate
                                    .process_blocks_at_tip(
                                        &mut miner_trace.burn_node.sortdb,
                                        expected_num_blocks,
                                    )
                                    .unwrap();

                                num_processed += tip_info_list.len();
                            }
                        }
                    }
                    None => {
                        // no block announced at this point in time
                        test_debug!(
                            "Miner {} did not produce a Stacks block for {:?} (commit {:?})",
                            miner_id,
                            &fork_snapshot,
                            &block_commit_op
                        );
                        continue;
                    }
                }
            }
        }

        // must have processed the same number of blocks in all nodes
        assert_eq!(num_processed, expected_num_blocks);

        // must have processed all blocks the same way
        for test_name in test_names.iter() {
            let rnd_test_name = format!("{}-replay_randomized", test_name);
            assert_chainstate_blocks_eq(test_name, &rnd_test_name);
        }
    }

    pub fn make_coinbase(miner: &mut TestMiner, burnchain_height: usize) -> StacksTransaction {
        make_coinbase_with_nonce(miner, burnchain_height, miner.get_nonce())
    }

    pub fn make_coinbase_with_nonce(
        miner: &mut TestMiner,
        burnchain_height: usize,
        nonce: u64,
    ) -> StacksTransaction {
        // make a coinbase for this miner
        let mut tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            miner.as_transaction_auth().unwrap(),
            TransactionPayload::Coinbase(CoinbasePayload([(burnchain_height % 256) as u8; 32])),
        );
        tx_coinbase.chain_id = 0x80000000;
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        miner.sign_as_origin(&mut tx_signer);
        let tx_coinbase_signed = tx_signer.get_tx().unwrap();
        tx_coinbase_signed
    }

    pub fn mine_empty_anchored_block(
        clarity_tx: &mut ClarityTx,
        builder: &mut StacksBlockBuilder,
        miner: &mut TestMiner,
        burnchain_height: usize,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>) {
        let miner_account = StacksChainState::get_account(
            clarity_tx,
            &miner.origin_address().unwrap().to_account_principal(),
        );
        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);

        builder
            .try_mine_tx(clarity_tx, &tx_coinbase_signed)
            .unwrap();

        let stacks_block = builder.mine_anchored_block(clarity_tx);

        test_debug!(
            "Produce anchored stacks block at burnchain height {} stacks height {}",
            burnchain_height,
            stacks_block.header.total_work.work
        );
        (stacks_block, vec![])
    }

    pub fn mine_empty_anchored_block_with_burn_height_pubkh(
        clarity_tx: &mut ClarityTx,
        builder: &mut StacksBlockBuilder,
        miner: &mut TestMiner,
        burnchain_height: usize,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>) {
        let mut pubkh_bytes = [0u8; 20];
        pubkh_bytes[0..8].copy_from_slice(&burnchain_height.to_be_bytes());
        assert!(builder.set_microblock_pubkey_hash(Hash160(pubkh_bytes)));

        let miner_account = StacksChainState::get_account(
            clarity_tx,
            &miner.origin_address().unwrap().to_account_principal(),
        );

        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);

        builder
            .try_mine_tx(clarity_tx, &tx_coinbase_signed)
            .unwrap();

        let stacks_block = builder.mine_anchored_block(clarity_tx);

        test_debug!(
            "Produce anchored stacks block at burnchain height {} stacks height {} pubkeyhash {}",
            burnchain_height,
            stacks_block.header.total_work.work,
            &stacks_block.header.microblock_pubkey_hash
        );
        (stacks_block, vec![])
    }

    pub fn mine_empty_anchored_block_with_stacks_height_pubkh(
        clarity_tx: &mut ClarityTx,
        builder: &mut StacksBlockBuilder,
        miner: &mut TestMiner,
        burnchain_height: usize,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>) {
        let mut pubkh_bytes = [0u8; 20];
        pubkh_bytes[0..8].copy_from_slice(&burnchain_height.to_be_bytes());
        assert!(builder.set_microblock_pubkey_hash(Hash160(pubkh_bytes)));

        let miner_account = StacksChainState::get_account(
            clarity_tx,
            &miner.origin_address().unwrap().to_account_principal(),
        );
        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);

        builder
            .try_mine_tx(clarity_tx, &tx_coinbase_signed)
            .unwrap();

        let stacks_block = builder.mine_anchored_block(clarity_tx);

        test_debug!(
            "Produce anchored stacks block at burnchain height {} stacks height {} pubkeyhash {}",
            burnchain_height,
            stacks_block.header.total_work.work,
            &stacks_block.header.microblock_pubkey_hash
        );
        (stacks_block, vec![])
    }

    pub fn make_smart_contract(
        miner: &mut TestMiner,
        burnchain_height: usize,
        stacks_block_height: usize,
    ) -> StacksTransaction {
        // make a smart contract
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        test_debug!(
            "Make smart contract block at hello-world-{}-{}",
            burnchain_height,
            stacks_block_height
        );

        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            miner.as_transaction_auth().unwrap(),
            TransactionPayload::new_smart_contract(
                &format!("hello-world-{}-{}", burnchain_height, stacks_block_height),
                &contract.to_string(),
            )
            .unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.auth.set_origin_nonce(miner.get_nonce());

        if miner.test_with_tx_fees {
            tx_contract.set_tx_fee(123);
            miner.spent_at_nonce.insert(miner.get_nonce(), 123);
        } else {
            tx_contract.set_tx_fee(0);
        }

        let mut tx_signer = StacksTransactionSigner::new(&tx_contract);
        miner.sign_as_origin(&mut tx_signer);
        let tx_contract_signed = tx_signer.get_tx().unwrap();

        tx_contract_signed
    }

    /// paired with make_smart_contract
    pub fn make_contract_call(
        miner: &mut TestMiner,
        burnchain_height: usize,
        stacks_block_height: usize,
        arg1: i128,
        arg2: i128,
    ) -> StacksTransaction {
        let addr = miner.origin_address().unwrap();
        let mut tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            miner.as_transaction_auth().unwrap(),
            TransactionPayload::new_contract_call(
                addr.clone(),
                &format!("hello-world-{}-{}", burnchain_height, stacks_block_height),
                "set-bar",
                vec![Value::Int(arg1), Value::Int(arg2)],
            )
            .unwrap(),
        );

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.auth.set_origin_nonce(miner.get_nonce());

        if miner.test_with_tx_fees {
            tx_contract_call.set_tx_fee(456);
            miner.spent_at_nonce.insert(miner.get_nonce(), 456);
        } else {
            tx_contract_call.set_tx_fee(0);
        }

        let mut tx_signer = StacksTransactionSigner::new(&tx_contract_call);
        miner.sign_as_origin(&mut tx_signer);
        let tx_contract_call_signed = tx_signer.get_tx().unwrap();
        tx_contract_call_signed
    }

    /// make a token transfer
    pub fn make_token_transfer(
        miner: &mut TestMiner,
        burnchain_height: usize,
        nonce: Option<u64>,
        recipient: &StacksAddress,
        amount: u64,
        memo: &TokenTransferMemo,
    ) -> StacksTransaction {
        let addr = miner.origin_address().unwrap();
        let mut tx_stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            miner.as_transaction_auth().unwrap(),
            TransactionPayload::TokenTransfer((*recipient).clone().into(), amount, (*memo).clone()),
        );

        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer
            .auth
            .set_origin_nonce(nonce.unwrap_or(miner.get_nonce()));
        tx_stx_transfer.set_tx_fee(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_stx_transfer);
        miner.sign_as_origin(&mut tx_signer);
        let tx_stx_transfer_signed = tx_signer.get_tx().unwrap();
        tx_stx_transfer_signed
    }

    /// Mine invalid token transfers
    pub fn mine_invalid_token_transfers_block(
        clarity_tx: &mut ClarityTx,
        builder: &mut StacksBlockBuilder,
        miner: &mut TestMiner,
        burnchain_height: usize,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>) {
        let miner_account = StacksChainState::get_account(
            clarity_tx,
            &miner.origin_address().unwrap().to_account_principal(),
        );
        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
        builder
            .try_mine_tx(clarity_tx, &tx_coinbase_signed)
            .unwrap();

        let recipient =
            StacksAddress::new(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, Hash160([0xff; 20]));
        let tx1 = make_token_transfer(
            miner,
            burnchain_height,
            Some(1),
            &recipient,
            11111,
            &TokenTransferMemo([1u8; 34]),
        );
        builder.force_mine_tx(clarity_tx, &tx1).unwrap();

        if miner.spent_at_nonce.get(&1).is_none() {
            miner.spent_at_nonce.insert(1, 11111);
        }

        let tx2 = make_token_transfer(
            miner,
            burnchain_height,
            Some(2),
            &recipient,
            22222,
            &TokenTransferMemo([2u8; 34]),
        );
        builder.force_mine_tx(clarity_tx, &tx2).unwrap();

        if miner.spent_at_nonce.get(&2).is_none() {
            miner.spent_at_nonce.insert(2, 22222);
        }

        let tx3 = make_token_transfer(
            miner,
            burnchain_height,
            Some(1),
            &recipient,
            33333,
            &TokenTransferMemo([3u8; 34]),
        );
        builder.force_mine_tx(clarity_tx, &tx3).unwrap();

        let tx4 = make_token_transfer(
            miner,
            burnchain_height,
            Some(2),
            &recipient,
            44444,
            &TokenTransferMemo([4u8; 34]),
        );
        builder.force_mine_tx(clarity_tx, &tx4).unwrap();

        let stacks_block = builder.mine_anchored_block(clarity_tx);

        test_debug!("Produce anchored stacks block {} with invalid token transfers at burnchain height {} stacks height {}", stacks_block.block_hash(), burnchain_height, stacks_block.header.total_work.work);

        (stacks_block, vec![])
    }

    /// mine a smart contract in an anchored block, and mine a contract-call in the same anchored
    /// block
    pub fn mine_smart_contract_contract_call_block(
        clarity_tx: &mut ClarityTx,
        builder: &mut StacksBlockBuilder,
        miner: &mut TestMiner,
        burnchain_height: usize,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>) {
        let miner_account = StacksChainState::get_account(
            clarity_tx,
            &miner.origin_address().unwrap().to_account_principal(),
        );
        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
        builder
            .try_mine_tx(clarity_tx, &tx_coinbase_signed)
            .unwrap();

        // make a smart contract
        let tx_contract_signed = make_smart_contract(
            miner,
            burnchain_height,
            builder.header.total_work.work as usize,
        );
        builder
            .try_mine_tx(clarity_tx, &tx_contract_signed)
            .unwrap();

        // make a contract call
        let tx_contract_call_signed = make_contract_call(
            miner,
            burnchain_height,
            builder.header.total_work.work as usize,
            6,
            2,
        );
        builder
            .try_mine_tx(clarity_tx, &tx_contract_call_signed)
            .unwrap();

        let stacks_block = builder.mine_anchored_block(clarity_tx);

        // TODO: test value of 'bar' in last contract(s)

        test_debug!("Produce anchored stacks block {} with smart contract and contract call at burnchain height {} stacks height {}", stacks_block.block_hash(), burnchain_height, stacks_block.header.total_work.work);
        (stacks_block, vec![])
    }

    /// mine a smart contract in an anchored block, and mine some contract-calls to it in a microblock tail
    pub fn mine_smart_contract_block_contract_call_microblock(
        clarity_tx: &mut ClarityTx,
        builder: &mut StacksBlockBuilder,
        miner: &mut TestMiner,
        burnchain_height: usize,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>) {
        if burnchain_height > 0 && builder.chain_tip.anchored_header.total_work.work > 0 {
            // find previous contract in this fork
            for i in (0..burnchain_height).rev() {
                let prev_contract_id = QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(miner.origin_address().unwrap()),
                    ContractName::try_from(
                        format!(
                            "hello-world-{}-{}",
                            i, builder.chain_tip.anchored_header.total_work.work
                        )
                        .as_str(),
                    )
                    .unwrap(),
                );
                let contract =
                    StacksChainState::get_contract(clarity_tx, &prev_contract_id).unwrap();
                if contract.is_none() {
                    continue;
                }

                let prev_bar_value =
                    StacksChainState::get_data_var(clarity_tx, &prev_contract_id, "bar").unwrap();
                assert_eq!(prev_bar_value, Some(Value::Int(3)));
                break;
            }
        }

        let miner_account = StacksChainState::get_account(
            clarity_tx,
            &miner.origin_address().unwrap().to_account_principal(),
        );
        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
        builder
            .try_mine_tx(clarity_tx, &tx_coinbase_signed)
            .unwrap();

        // make a smart contract
        let tx_contract_signed = make_smart_contract(
            miner,
            burnchain_height,
            builder.header.total_work.work as usize,
        );
        builder
            .try_mine_tx(clarity_tx, &tx_contract_signed)
            .unwrap();

        let stacks_block = builder.mine_anchored_block(clarity_tx);
        let mut microblocks = vec![];

        for i in 0..3 {
            // make a contract call
            let tx_contract_call_signed = make_contract_call(
                miner,
                burnchain_height,
                builder.header.total_work.work as usize,
                6,
                2,
            );

            builder.micro_txs.clear();
            builder.micro_txs.push(tx_contract_call_signed);

            // put the contract-call into a microblock
            let microblock = builder.mine_next_microblock().unwrap();
            microblocks.push(microblock);
        }

        test_debug!("Produce anchored stacks block {} with smart contract and {} microblocks with contract call at burnchain height {} stacks height {}",
                    stacks_block.block_hash(), microblocks.len(), burnchain_height, stacks_block.header.total_work.work);

        (stacks_block, microblocks)
    }

    /// mine a smart contract in an anchored block, and mine a contract-call to it in a microblock.
    /// Make it so all microblocks throw a runtime exception, but confirm that they are still mined
    /// anyway.
    pub fn mine_smart_contract_block_contract_call_microblock_exception(
        clarity_tx: &mut ClarityTx,
        builder: &mut StacksBlockBuilder,
        miner: &mut TestMiner,
        burnchain_height: usize,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>) {
        if burnchain_height > 0 && builder.chain_tip.anchored_header.total_work.work > 0 {
            // find previous contract in this fork
            for i in (0..burnchain_height).rev() {
                let prev_contract_id = QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(miner.origin_address().unwrap()),
                    ContractName::try_from(
                        format!(
                            "hello-world-{}-{}",
                            i, builder.chain_tip.anchored_header.total_work.work
                        )
                        .as_str(),
                    )
                    .unwrap(),
                );
                let contract =
                    StacksChainState::get_contract(clarity_tx, &prev_contract_id).unwrap();
                if contract.is_none() {
                    continue;
                }

                test_debug!("Found contract {:?}", &prev_contract_id);
                let prev_bar_value =
                    StacksChainState::get_data_var(clarity_tx, &prev_contract_id, "bar").unwrap();
                assert_eq!(prev_bar_value, Some(Value::Int(0)));
                break;
            }
        }

        let miner_account = StacksChainState::get_account(
            clarity_tx,
            &miner.origin_address().unwrap().to_account_principal(),
        );
        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
        builder
            .try_mine_tx(clarity_tx, &tx_coinbase_signed)
            .unwrap();

        // make a smart contract
        let tx_contract_signed = make_smart_contract(
            miner,
            burnchain_height,
            builder.header.total_work.work as usize,
        );
        builder
            .try_mine_tx(clarity_tx, &tx_contract_signed)
            .unwrap();

        let stacks_block = builder.mine_anchored_block(clarity_tx);

        let mut microblocks = vec![];
        for i in 0..3 {
            // make a contract call (note: triggers a divide-by-zero runtime error)
            let tx_contract_call_signed = make_contract_call(
                miner,
                burnchain_height,
                builder.header.total_work.work as usize,
                6,
                0,
            );
            builder.micro_txs.clear();
            builder.micro_txs.push(tx_contract_call_signed);

            // put the contract-call into a microblock
            let microblock = builder.mine_next_microblock().unwrap();
            microblocks.push(microblock);
        }

        test_debug!("Produce anchored stacks block {} with smart contract and {} microblocks with contract call at burnchain height {} stacks height {}", 
                    stacks_block.block_hash(), microblocks.len(), burnchain_height, stacks_block.header.total_work.work);

        (stacks_block, microblocks)
    }

    /*
    // TODO: blocked on get-block-info's reliance on get_simmed_block_height

    /// In the first epoch, mine an anchored block followed by 100 microblocks.
    /// In all following epochs, build off of one of the microblocks.
    fn mine_smart_contract_block_contract_call_microblocks_same_stream<'a>(clarity_tx: &mut ClarityTx<'a>,
                                                                           builder: &mut StacksBlockBuilder,
                                                                           miner: &mut TestMiner,
                                                                           burnchain_height: usize,
                                                                           parent_microblock_header: Option<&StacksMicroblockHeader>) -> (StacksBlock, Vec<StacksMicroblock>) {

        let miner_account = StacksChainState::get_account(clarity_tx, &miner.origin_address().unwrap().to_account_principal());
        miner.set_nonce(miner_account.nonce);

        // make a coinbase for this miner
        let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
        builder.try_mine_tx(clarity_tx, &tx_coinbase_signed).unwrap();

        if burnchain_height == 0 {
            // make a smart contract
            let tx_contract_signed = make_smart_contract(miner, burnchain_height, builder.header.total_work.work as usize);
            builder.try_mine_tx(clarity_tx, &tx_contract_signed).unwrap();

            let stacks_block = builder.mine_anchored_block(clarity_tx);

            // create the initial 20 contract calls in microblocks
            let mut stacks_microblocks = vec![];
            for i in 0..20 {
                let tx_contract_call_signed = make_contract_call(miner, burnchain_height, builder.header.total_work.work, 6, 2);
                builder.try_mine_tx(clarity_tx, &tx_contract_call_signed).unwrap();

                let microblock = builder.mine_next_microblock().unwrap();
                stacks_microblocks.push(microblock);
            }

            (stacks_block, stacks_microblocks)
        }
        else {
            // set parent at block 1
            let first_block_hash = clarity_get_block_hash(clarity_tx, 1).unwrap();
            builder.set_parent_block(&first_block_hash);

            let mut stacks_block = builder.mine_anchored_block(clarity_tx);

            // re-create the initial 100 contract calls in microblocks
            let mut stacks_microblocks = vec![];
            for i in 0..20 {
                let tx_contract_call_signed = make_contract_call(miner, burnchain_height, builder.header.total_work.work, 6, 2);
                builder.try_mine_tx(clarity_tx, &tx_contract_call_signed).unwrap();

                let microblock = builder.mine_next_microblock().unwrap();
                stacks_microblocks.push(microblock);
            }

            // builder.set_parent_microblock(&stacks_microblocks[burnchain_height].block_hash(), stacks_microblocks[burnchain_height].header.sequence);
            stacks_block.header.parent_microblock = stacks_microblocks[burnchain_height].block_hash();
            stacks_block.header.parent_microblock_sequence = stacks_microblocks[burnchain_height].header.sequence;

            (stacks_block, vec![])
        }
    }
    */

    #[test]
    fn mine_anchored_empty_blocks_single() {
        mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"empty-anchored-blocks".to_string(),
            10,
            mine_empty_anchored_block,
            |_, _| true,
        );
    }

    #[test]
    fn mine_anchored_empty_blocks_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"empty-anchored-blocks-random".to_string(),
            10,
            mine_empty_anchored_block,
            |_, _| true,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_empty_blocks_multiple_miners() {
        mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"empty-anchored-blocks-multiple-miners".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
    }

    #[test]
    fn mine_anchored_empty_blocks_multiple_miners_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"empty-anchored-blocks-multiple-miners-random".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_empty_blocks_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"empty-anchored-blocks-stacks-fork".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
    }

    #[test]
    fn mine_anchored_empty_blocks_stacks_fork_random() {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"empty-anchored-blocks-stacks-fork-random".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_empty_blocks_burnchain_fork() {
        mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"empty-anchored-blocks-burnchain-fork".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
    }

    #[test]
    fn mine_anchored_empty_blocks_burnchain_fork_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"empty-anchored-blocks-burnchain-fork-random".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_empty_blocks_burnchain_fork_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"empty-anchored-blocks-burnchain-stacks-fork".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
    }

    #[test]
    fn mine_anchored_empty_blocks_burnchain_fork_stacks_fork_random() {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"empty-anchored-blocks-burnchain-stacks-fork-random".to_string(),
            10,
            mine_empty_anchored_block,
            mine_empty_anchored_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_single() {
        mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"smart-contract-contract-call-anchored-blocks".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            |_, _| true,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_single_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"smart-contract-contract-call-anchored-blocks-random".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            |_, _| true,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_multiple_miners() {
        mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"smart-contract-contract-call-anchored-blocks-multiple-miners".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_multiple_miners_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"smart-contract-contract-call-anchored-blocks-multiple-miners-random".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"smart-contract-contract-call-anchored-blocks-stacks-fork".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_stacks_fork_random() {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"smart-contract-contract-call-anchored-blocks-stacks-fork-random".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork() {
        mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"smart-contract-contract-call-anchored-blocks-burnchain-fork".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"smart-contract-contract-call-anchored-blocks-burnchain-fork-random".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"smart-contract-contract-call-anchored-blocks-burnchain-stacks-fork".to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork_stacks_fork_random() {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"smart-contract-contract-call-anchored-blocks-burnchain-stacks-fork-random"
                .to_string(),
            10,
            mine_smart_contract_contract_call_block,
            mine_smart_contract_contract_call_block,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_single() {
        mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"smart-contract-block-contract-call-microblock".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            |_, _| true,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_single_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"smart-contract-block-contract-call-microblock-random".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            |_, _| true,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_multiple_miners() {
        mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-multiple-miners".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_multiple_miners_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-multiple-miners-random".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-stacks-fork".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
    }

    #[test]
    #[ignore]
    fn mine_anchored_smart_contract_block_contract_call_microblock_stacks_fork_random() {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-stacks-fork-random".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork() {
        mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-burnchain-fork".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-burnchain-fork-random".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-burnchain-stacks-fork".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork_stacks_fork_random(
    ) {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-burnchain-stacks-fork-random"
                .to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock,
            mine_smart_contract_block_contract_call_microblock,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_single() {
        mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"smart-contract-block-contract-call-microblock-exception".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            |_, _| true,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_single_random() {
        let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"smart-contract-block-contract-call-microblock-exception-random".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            |_, _| true,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_multiple_miners() {
        mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-exception-multiple-miners".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_multiple_miners_random(
    ) {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-exception-multiple-miners-random"
                .to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-exception-stacks-fork".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
    }

    #[test]
    #[ignore]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_stacks_fork_random() {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"smart-contract-block-contract-call-microblock-exception-stacks-fork-random"
                .to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork() {
        mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-exception-burnchain-fork".to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork_random()
    {
        let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-exception-burnchain-fork-random"
                .to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork_stacks_fork(
    ) {
        mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-exception-burnchain-stacks-fork"
                .to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
    }

    #[test]
    fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork_stacks_fork_random(
    ) {
        let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
            &"smart-contract-block-contract-call-microblock-exception-burnchain-stacks-fork-random"
                .to_string(),
            10,
            mine_smart_contract_block_contract_call_microblock_exception,
            mine_smart_contract_block_contract_call_microblock_exception,
        );
        miner_trace_replay_randomized(&mut miner_trace);
    }

    #[test]
    fn mine_empty_anchored_block_deterministic_pubkeyhash_burnchain_fork() {
        mine_stacks_blocks_1_fork_2_miners_2_burnchains(
            &"mine_empty_anchored_block_deterministic_pubkeyhash_burnchain_fork".to_string(),
            10,
            mine_empty_anchored_block_with_burn_height_pubkh,
            mine_empty_anchored_block_with_burn_height_pubkh,
        );
    }

    #[test]
    fn mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork() {
        mine_stacks_blocks_2_forks_2_miners_1_burnchain(
            &"mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork".to_string(),
            10,
            mine_empty_anchored_block_with_stacks_height_pubkh,
            mine_empty_anchored_block_with_stacks_height_pubkh,
        );
    }

    #[test]
    fn mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork_at_genesis() {
        mine_stacks_blocks_2_forks_at_height_2_miners_1_burnchain(
            &"mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork_at_genesis"
                .to_string(),
            10,
            0,
            mine_empty_anchored_block_with_stacks_height_pubkh,
            mine_empty_anchored_block_with_stacks_height_pubkh,
        );
    }

    #[test]
    fn mine_anchored_invalid_token_transfer_blocks_single() {
        let miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
            &"invalid-token-transfers".to_string(),
            10,
            mine_invalid_token_transfers_block,
            |_, _| false,
        );

        let full_test_name = "invalid-token-transfers-1_fork_1_miner_1_burnchain";
        let chainstate = open_chainstate(false, 0x80000000, full_test_name);

        // each block must be orphaned
        for point in miner_trace.points.iter() {
            for (height, bc) in point.block_commits.iter() {
                // NOTE: this only works because there are no PoX forks in this test
                let sn = SortitionDB::get_block_snapshot(
                    miner_trace.burn_node.sortdb.conn(),
                    &SortitionId::stubbed(&bc.burn_header_hash),
                )
                .unwrap()
                .unwrap();
                assert!(StacksChainState::is_block_orphaned(
                    &chainstate.db(),
                    &sn.consensus_hash,
                    &bc.block_header_hash
                )
                .unwrap());
            }
        }
    }

    // TODO: merge with vm/tests/integrations.rs.
    // Distinct here because we use a different testnet ID
    pub fn make_user_contract_publish(
        sender: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
        contract_name: &str,
        contract_content: &str,
    ) -> StacksTransaction {
        let name = ContractName::from(contract_name);
        let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

        let payload = TransactionSmartContract { name, code_body };

        sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
    }

    pub fn make_user_stacks_transfer(
        sender: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
        recipient: &PrincipalData,
        amount: u64,
    ) -> StacksTransaction {
        let payload = TransactionPayload::TokenTransfer(
            recipient.clone(),
            amount,
            TokenTransferMemo([0; 34]),
        );
        sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
    }

    pub fn make_user_coinbase(
        sender: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
    ) -> StacksTransaction {
        let payload = TransactionPayload::Coinbase(CoinbasePayload([0; 32]));
        sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
    }

    pub fn make_user_poison_microblock(
        sender: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
        payload: TransactionPayload,
    ) -> StacksTransaction {
        sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
    }

    pub fn sign_standard_singlesig_tx(
        payload: TransactionPayload,
        sender: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
    ) -> StacksTransaction {
        let mut spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(sender),
        )
        .expect("Failed to create p2pkh spending condition from public key.");
        spending_condition.set_nonce(nonce);
        spending_condition.set_tx_fee(tx_fee);
        let auth = TransactionAuth::Standard(spending_condition);
        let mut unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);

        unsigned_tx.chain_id = 0x80000000;
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer.sign_origin(sender).unwrap();

        tx_signer.get_tx().unwrap()
    }

    #[test]
    fn test_build_anchored_blocks_empty() {
        let peer_config = TestPeerConfig::new("test_build_anchored_blocks_empty", 2000, 2001);
        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let num_blocks = 10;
        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let mut last_block: Option<StacksBlock> = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            assert_eq!(
                tip.block_height,
                first_stacks_block_height + (tenure_id as u64)
            );
            if let Some(block) = last_block {
                assert_eq!(tip.winning_stacks_block_hash, block.block_hash());
            }

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();
                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        }
    }

    #[test]
    fn test_build_anchored_blocks_stx_transfers_single() {
        let privk = StacksPrivateKey::from_hex(
            "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
        )
        .unwrap();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        let mut peer_config = TestPeerConfig::new(
            "test_build_anchored_blocks_stx_transfers_single",
            2002,
            2003,
        );
        peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let num_blocks = 10;
        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
        let mut sender_nonce = 0;

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    if tenure_id > 0 {
                        let stx_transfer = make_user_stacks_transfer(
                            &privk,
                            sender_nonce,
                            200,
                            &recipient.to_account_principal(),
                            1,
                        );
                        sender_nonce += 1;

                        mempool
                            .submit(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &stx_transfer,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();
                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            if tenure_id > 0 {
                // transaction was mined
                assert_eq!(stacks_block.txs.len(), 2);
                if let TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) =
                    stacks_block.txs[1].payload
                {
                    assert_eq!(*addr, recipient.to_account_principal());
                    assert_eq!(*amount, 1);
                } else {
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_build_anchored_blocks_empty_with_builder_timeout() {
        let privk = StacksPrivateKey::from_hex(
            "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
        )
        .unwrap();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        let mut peer_config = TestPeerConfig::new(
            "test_build_anchored_blocks_empty_with_builder_timeout",
            2022,
            2023,
        );
        peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let num_blocks = 10;
        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
        let mut sender_nonce = 0;

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    if tenure_id > 0 {
                        let stx_transfer = make_user_stacks_transfer(
                            &privk,
                            sender_nonce,
                            200,
                            &recipient.to_account_principal(),
                            1,
                        );
                        sender_nonce += 1;

                        mempool
                            .submit(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &stx_transfer,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        // no time to mine anything, so all blocks should be empty
                        BlockBuilderSettings {
                            max_miner_time_ms: 0,
                            ..BlockBuilderSettings::max_value()
                        },
                        None,
                    )
                    .unwrap();
                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            if tenure_id > 0 {
                // transaction was NOT mined due to timeout
                assert_eq!(stacks_block.txs.len(), 1);
            }
        }
    }

    #[test]
    fn test_build_anchored_blocks_stx_transfers_multi() {
        let mut privks = vec![];
        let mut balances = vec![];
        let num_blocks = 10;

        for _ in 0..num_blocks {
            let privk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();

            privks.push(privk);
            balances.push((addr.to_account_principal(), 100000000));
        }

        let mut peer_config =
            TestPeerConfig::new("test_build_anchored_blocks_stx_transfers_multi", 2004, 2005);
        peer_config.initial_balances = balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
        let mut sender_nonce = 0;

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    if tenure_id > 0 {
                        for i in 0..5 {
                            let stx_transfer = make_user_stacks_transfer(
                                &privks[i],
                                sender_nonce,
                                200,
                                &recipient.to_account_principal(),
                                1,
                            );
                            mempool
                                .submit(
                                    chainstate,
                                    &parent_consensus_hash,
                                    &parent_header_hash,
                                    &stx_transfer,
                                    None,
                                    &ExecutionCost::max_value(),
                                    &StacksEpochId::Epoch20,
                                )
                                .unwrap();
                        }

                        // test pagination by timestamp
                        test_debug!("Delay for 1.5s");
                        sleep_ms(1500);

                        for i in 5..10 {
                            let stx_transfer = make_user_stacks_transfer(
                                &privks[i],
                                sender_nonce,
                                200,
                                &recipient.to_account_principal(),
                                1,
                            );
                            mempool
                                .submit(
                                    chainstate,
                                    &parent_consensus_hash,
                                    &parent_header_hash,
                                    &stx_transfer,
                                    None,
                                    &ExecutionCost::max_value(),
                                    &StacksEpochId::Epoch20,
                                )
                                .unwrap();
                        }

                        sender_nonce += 1;
                    }

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();
                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            if tenure_id > 0 {
                // transaction was mined, even though they were staggerred by time
                assert_eq!(stacks_block.txs.len(), 11);
                for i in 1..11 {
                    if let TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) =
                        stacks_block.txs[i].payload
                    {
                        assert_eq!(*addr, recipient.to_account_principal());
                        assert_eq!(*amount, 1);
                    } else {
                        assert!(false);
                    }
                }
            }
        }
    }

    #[test]
    fn test_build_anchored_blocks_connected_by_microblocks_across_epoch() {
        let privk = StacksPrivateKey::from_hex(
            "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
        )
        .unwrap();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        let mut peer_config = TestPeerConfig::new(
            "test_build_anchored_blocks_connected_by_microblocks_across_epoch",
            2016,
            2017,
        );
        peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];

        let epochs = vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: 0,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 0,
                end_height: 30, // NOTE: the first 25 burnchain blocks have no sortition
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 30,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost {
                    write_length: 205205,
                    write_count: 205205,
                    read_length: 205205,
                    read_count: 205205,
                    runtime: 205205,
                },
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ];
        peer_config.epochs = Some(epochs);

        let num_blocks = 10;

        let mut mblock_privks = vec![];
        for _ in 0..num_blocks {
            let mblock_privk = StacksPrivateKey::new();
            mblock_privks.push(mblock_privk);
        }

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let acct = get_stacks_account(&mut peer, &addr.to_account_principal());

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let parent_index_hash = StacksBlockHeader::make_index_block_hash(
                        &parent_consensus_hash,
                        &parent_header_hash,
                    );

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let coinbase_tx = make_coinbase(miner, tenure_id);
                    let sort_ic = sortdb.index_conn();
                    let (parent_mblock_stream, mblock_pubkey_hash) = {
                        if tenure_id > 0 {
                            chainstate
                                .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                                .unwrap();

                            let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();
                            // produce the microblock stream for the parent, which this tenure's anchor
                            // block will confirm.
                            let mut microblock_builder = StacksMicroblockBuilder::new(
                                parent_header_hash.clone(),
                                parent_consensus_hash.clone(),
                                chainstate,
                                &sort_ic,
                                BlockBuilderSettings::max_value(),
                            )
                            .unwrap();

                            let mut microblocks = vec![];

                            let mblock_tx = make_user_stacks_transfer(
                                &privk,
                                acct.nonce,
                                200,
                                &recipient.to_account_principal(),
                                1,
                            );

                            let mblock_tx_len = {
                                let mut bytes = vec![];
                                mblock_tx.consensus_serialize(&mut bytes).unwrap();
                                bytes.len() as u64
                            };

                            test_debug!(
                                "Make microblock parent stream for block in tenure {}",
                                tenure_id
                            );
                            let mblock = microblock_builder
                                .mine_next_microblock_from_txs(
                                    vec![(mblock_tx, mblock_tx_len)],
                                    &parent_microblock_privkey,
                                )
                                .unwrap();
                            microblocks.push(mblock);

                            let microblock_privkey = mblock_privks[tenure_id].clone();
                            let mblock_pubkey_hash = Hash160::from_node_public_key(
                                &StacksPublicKey::from_private(&microblock_privkey),
                            );
                            (microblocks, mblock_pubkey_hash)
                        } else {
                            let parent_microblock_privkey = mblock_privks[tenure_id].clone();
                            let mblock_pubkey_hash = Hash160::from_node_public_key(
                                &StacksPublicKey::from_private(&parent_microblock_privkey),
                            );
                            (vec![], mblock_pubkey_hash)
                        }
                    };

                    test_debug!("Store parent microblocks for tenure {}", tenure_id);
                    for mblock in parent_mblock_stream.iter() {
                        let stored = chainstate
                            .preprocess_streamed_microblock(
                                &parent_consensus_hash,
                                &parent_header_hash,
                                mblock,
                            )
                            .unwrap();
                        assert!(stored);
                    }

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sort_ic,
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        mblock_pubkey_hash,
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();

                    if parent_mblock_stream.len() > 0 {
                        if tenure_id != 5 {
                            assert_eq!(
                                anchored_block.0.header.parent_microblock,
                                parent_mblock_stream.last().unwrap().block_hash()
                            );
                        } else {
                            // epoch change happened, so miner didn't confirm any microblocks
                            assert!(!anchored_block.0.has_microblock_parent());
                        }
                    }

                    (anchored_block.0, parent_mblock_stream)
                },
            );

            last_block = Some(stacks_block.clone());

            test_debug!("Process tenure {}", tenure_id);

            // should always succeed
            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip_checked(&stacks_block, &vec![])
                .unwrap();
        }

        let last_block = last_block.unwrap();
        assert_eq!(last_block.header.total_work.work, 10); // mined a chain successfully across the epoch boundary
    }

    #[test]
    #[should_panic(expected = "success")]
    fn test_build_anchored_blocks_connected_by_microblocks_across_epoch_invalid() {
        let privk = StacksPrivateKey::from_hex(
            "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
        )
        .unwrap();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        let mut peer_config = TestPeerConfig::new(
            "test_build_anchored_blocks_connected_by_microblocks_across_epoch_invalid",
            2018,
            2019,
        );
        peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];

        let epochs = vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: 0,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 0,
                end_height: 30, // NOTE: the first 25 burnchain blocks have no sortition
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 30,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost {
                    write_length: 205205,
                    write_count: 205205,
                    read_length: 205205,
                    read_count: 205205,
                    runtime: 205205,
                },
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ];
        peer_config.epochs = Some(epochs);

        let num_blocks = 10;

        let mut mblock_privks = vec![];
        for _ in 0..num_blocks {
            let mblock_privk = StacksPrivateKey::new();
            mblock_privks.push(mblock_privk);
        }

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

        let mut last_block: Option<StacksBlock> = None;
        let mut last_block_ch: Option<ConsensusHash> = None;

        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let acct = get_stacks_account(&mut peer, &addr.to_account_principal());

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();

                            if tenure_id < 6 {
                                let snapshot =
                                    SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                        &ic,
                                        &tip.sortition_id,
                                        &block.block_hash(),
                                    )
                                    .unwrap()
                                    .unwrap();

                                StacksChainState::get_anchored_block_header_info(
                                    chainstate.db(),
                                    &snapshot.consensus_hash,
                                    &snapshot.winning_stacks_block_hash,
                                )
                                .unwrap()
                                .unwrap()
                            } else {
                                // first block after the invalid block that had a microblock parent
                                // while straddling the epoch boundary.
                                // Verify that the last block was indeed marked as invalid, and abort.
                                let bhh = last_block.as_ref().unwrap().block_hash();
                                let ch = last_block_ch.as_ref().unwrap().clone();
                                assert!(StacksChainState::is_block_orphaned(
                                    chainstate.db(),
                                    &ch,
                                    &bhh
                                )
                                .unwrap());
                                panic!("success");
                            }
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let parent_index_hash = StacksBlockHeader::make_index_block_hash(
                        &parent_consensus_hash,
                        &parent_header_hash,
                    );

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let coinbase_tx = make_coinbase(miner, tenure_id);
                    let sort_ic = sortdb.index_conn();
                    let (parent_mblock_stream, mblock_pubkey_hash) = {
                        if tenure_id > 0 {
                            chainstate
                                .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                                .unwrap();

                            let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();

                            // produce the microblock stream for the parent, which this tenure's anchor
                            // block will confirm.
                            let mut microblock_builder = StacksMicroblockBuilder::new(
                                parent_header_hash.clone(),
                                parent_consensus_hash.clone(),
                                chainstate,
                                &sort_ic,
                                BlockBuilderSettings::max_value(),
                            )
                            .unwrap();

                            let mut microblocks = vec![];

                            let mblock_tx = make_user_stacks_transfer(
                                &privk,
                                acct.nonce,
                                (200 + tenure_id) as u64,
                                &recipient.to_account_principal(),
                                1,
                            );

                            let mblock_tx_len = {
                                let mut bytes = vec![];
                                mblock_tx.consensus_serialize(&mut bytes).unwrap();
                                bytes.len() as u64
                            };

                            test_debug!(
                                "Make microblock parent stream for block in tenure {}",
                                tenure_id
                            );
                            let mblock = microblock_builder
                                .mine_next_microblock_from_txs(
                                    vec![(mblock_tx, mblock_tx_len)],
                                    &parent_microblock_privkey,
                                )
                                .unwrap();
                            microblocks.push(mblock);

                            let microblock_privkey = mblock_privks[tenure_id].clone();
                            let mblock_pubkey_hash = Hash160::from_node_public_key(
                                &StacksPublicKey::from_private(&microblock_privkey),
                            );
                            (microblocks, mblock_pubkey_hash)
                        } else {
                            let parent_microblock_privkey = mblock_privks[tenure_id].clone();
                            let mblock_pubkey_hash = Hash160::from_node_public_key(
                                &StacksPublicKey::from_private(&parent_microblock_privkey),
                            );
                            (vec![], mblock_pubkey_hash)
                        }
                    };

                    test_debug!("Store parent microblocks for tenure {}", tenure_id);
                    for mblock in parent_mblock_stream.iter() {
                        let stored = chainstate
                            .preprocess_streamed_microblock(
                                &parent_consensus_hash,
                                &parent_header_hash,
                                mblock,
                            )
                            .unwrap();
                        assert!(stored);
                    }

                    let mut anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sort_ic,
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        mblock_pubkey_hash,
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();

                    if parent_mblock_stream.len() > 0 {
                        // force the block to confirm a microblock stream, even if it would result in
                        // an invalid block.
                        test_debug!(
                            "Force {} to have a microblock parent",
                            &anchored_block.0.block_hash()
                        );
                        anchored_block.0.header.parent_microblock =
                            parent_mblock_stream.last().unwrap().block_hash();
                        anchored_block.0.header.parent_microblock_sequence =
                            (parent_mblock_stream.len() as u16).saturating_sub(1);
                        assert_eq!(
                            anchored_block.0.header.parent_microblock,
                            parent_mblock_stream.last().unwrap().block_hash()
                        );
                        test_debug!("New block hash is {}", &anchored_block.0.block_hash());
                    } else {
                        assert_eq!(tenure_id, 0);
                    }

                    (anchored_block.0, parent_mblock_stream)
                },
            );

            last_block = Some(stacks_block.clone());

            test_debug!("Process tenure {}", tenure_id);
            let (_, _, block_ch) = peer.next_burnchain_block(burn_ops.clone());

            if tenure_id != 5 {
                // should always succeed
                peer.process_stacks_epoch_at_tip_checked(&stacks_block, &vec![])
                    .unwrap();
            } else {
                // should fail at first, since the block won't be available
                // (since validate_anchored_block_burnchain() will fail)
                if let Err(e) = peer.process_stacks_epoch_at_tip_checked(&stacks_block, &vec![]) {
                    match e {
                        CoordinatorError::ChainstateError(ChainstateError::DBError(
                            db_error::NotFoundError,
                        )) => {}
                        x => {
                            panic!("Unexpected error {:?}", &x);
                        }
                    }
                } else {
                    panic!("processed epoch successfully");
                }

                // the parent of this block crosses the epoch boundary
                let last_block_ch = last_block_ch.clone().unwrap();
                assert!(StacksChainState::block_crosses_epoch_boundary(
                    peer.chainstate().db(),
                    &last_block_ch,
                    &stacks_block.header.parent_block
                )
                .unwrap());

                // forcibly store the block
                store_staging_block(
                    peer.chainstate(),
                    &block_ch,
                    &stacks_block,
                    &last_block_ch,
                    stacks_block.header.total_work.burn,
                    stacks_block.header.total_work.burn,
                );

                // should run to completion, but the block should *not* be processed
                // (this tests append_block())
                peer.process_stacks_epoch_at_tip_checked(&stacks_block, &vec![])
                    .unwrap();
            }

            last_block_ch = Some(
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap()
                    .consensus_hash,
            );
        }

        let last_block = last_block.unwrap();
        assert_eq!(last_block.header.total_work.work, 10); // mined a chain successfully across the epoch boundary
    }

    #[test]
    /// This test covers two different behaviors added to the block assembly logic:
    /// (1) Ordering by estimated fee rate: the test peer uses the "unit" estimator
    /// for costs, but this estimator still uses the fee of the transaction to order
    /// the mempool. This leads to the behavior in this test where txs are included
    /// like 0 -> 1 -> 2 ... -> 25 -> next origin 0 -> 1 ...
    /// because the fee goes up with the nonce.
    /// (2) Discovery of nonce in the mempool iteration: this behavior allows the miner
    /// to consider an origin's "next" transaction immediately. Prior behavior would
    /// only do so after processing any other origin's transactions.
    fn test_build_anchored_blocks_incrementing_nonces() {
        let private_keys: Vec<_> = (0..10).map(|_| StacksPrivateKey::new()).collect();
        let addresses: Vec<_> = private_keys
            .iter()
            .map(|sk| {
                StacksAddress::from_public_keys(
                    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                    &AddressHashMode::SerializeP2PKH,
                    1,
                    &vec![StacksPublicKey::from_private(sk)],
                )
                .unwrap()
            })
            .collect();

        let initial_balances: Vec<_> = addresses
            .iter()
            .map(|addr| (addr.to_account_principal(), 100000000000))
            .collect();

        let mut peer_config = TestPeerConfig::new("build_anchored_incrementing_nonces", 2030, 2031);
        peer_config.initial_balances = initial_balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

        // during the tenure, let's push transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let coinbase_tx = make_coinbase(miner, 0);

                let txs: Vec<_> = private_keys
                    .iter()
                    .flat_map(|privk| {
                        let privk = privk.clone();
                        (0..25).map(move |tx_nonce| {
                            let contract = "(define-data-var bar int 0)";
                            make_user_contract_publish(
                                &privk,
                                tx_nonce,
                                200 * (tx_nonce + 1),
                                &format!("contract-{}", tx_nonce),
                                contract,
                            )
                        })
                    })
                    .collect();

                for tx in txs {
                    mempool
                        .submit(
                            chainstate,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &tx,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_conn(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([0 as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::limited(),
                    None,
                )
                .unwrap();
                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        // expensive transaction was not mined, but the two stx-transfers were
        assert_eq!(stacks_block.txs.len(), 251);

        // block should be ordered like coinbase, nonce 0, nonce 1, .. nonce 25, nonce 0, ..
        //  because the tx fee for each transaction increases with the nonce
        for (i, tx) in stacks_block.txs.iter().enumerate() {
            if i == 0 {
                let okay = if let TransactionPayload::Coinbase(..) = tx.payload {
                    true
                } else {
                    false
                };
                assert!(okay, "Coinbase should be first tx");
            } else {
                let expected_nonce = (i - 1) % 25;
                assert_eq!(
                    tx.get_origin_nonce(),
                    expected_nonce as u64,
                    "{}th transaction should have nonce = {}",
                    i,
                    expected_nonce
                );
            }
        }
    }

    #[test]
    fn test_build_anchored_blocks_skip_too_expensive() {
        let privk = StacksPrivateKey::from_hex(
            "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
        )
        .unwrap();
        let privk_extra = StacksPrivateKey::from_hex(
            "f67c7437f948ca1834602b28595c12ac744f287a4efaf70d437042a6afed81bc01",
        )
        .unwrap();
        let mut privks_expensive = vec![];
        let mut initial_balances = vec![];
        let num_blocks = 10;
        for i in 0..num_blocks {
            let pk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&pk)],
            )
            .unwrap()
            .to_account_principal();

            privks_expensive.push(pk);
            initial_balances.push((addr, 10000000000));
        }

        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();
        let addr_extra = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk_extra)],
        )
        .unwrap();

        initial_balances.push((addr.to_account_principal(), 100000000000));
        initial_balances.push((addr_extra.to_account_principal(), 200000000000));

        let mut peer_config =
            TestPeerConfig::new("test_build_anchored_blocks_skip_too_expensive", 2006, 2007);
        peer_config.initial_balances = initial_balances;
        peer_config.epochs = Some(vec![StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: i64::MAX as u64,
            // enough for the first stx-transfer, but not for the analysis of the smart
            // contract.
            block_limit: ExecutionCost {
                write_length: 100,
                write_count: 100,
                read_length: 100,
                read_count: 100,
                runtime: 3350,
            },
            network_epoch: PEER_VERSION_EPOCH_2_0,
        }]);

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
        let mut sender_nonce = 0;

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    if tenure_id > 0 {
                        let mut expensive_part = vec![];
                        for i in 0..100 {
                            expensive_part.push(format!("(define-data-var var-{} int 0)", i));
                        }
                        let contract = format!(
                            "{}
                    (define-data-var bar int 0)
                    (define-public (get-bar) (ok (var-get bar)))
                    (define-public (set-bar (x int) (y int))
                      (begin (var-set bar (/ x y)) (ok (var-get bar))))",
                            expensive_part.join("\n")
                        );

                        // fee high enough to get mined first
                        let stx_transfer = make_user_stacks_transfer(
                            &privk,
                            sender_nonce,
                            (4 * contract.len()) as u64,
                            &recipient.to_account_principal(),
                            1,
                        );
                        mempool
                            .submit(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &stx_transfer,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        // will never get mined
                        let contract_tx = make_user_contract_publish(
                            &privks_expensive[tenure_id],
                            0,
                            (2 * contract.len()) as u64,
                            &format!("hello-world-{}", tenure_id),
                            &contract,
                        );

                        mempool
                            .submit(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &contract_tx,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        // will get mined last
                        let stx_transfer = make_user_stacks_transfer(
                            &privk_extra,
                            sender_nonce,
                            300,
                            &recipient.to_account_principal(),
                            1,
                        );
                        mempool
                            .submit(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &stx_transfer,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        sender_nonce += 1;
                    }

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::limited(),
                        None,
                    )
                    .unwrap();
                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            if tenure_id > 0 {
                // expensive transaction was not mined, but the two stx-transfers were
                assert_eq!(stacks_block.txs.len(), 3);
                for tx in stacks_block.txs.iter() {
                    match tx.payload {
                        TransactionPayload::Coinbase(..) => {}
                        TransactionPayload::TokenTransfer(ref recipient, ref amount, ref memo) => {}
                        _ => {
                            assert!(false);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_build_anchored_blocks_multiple_chaintips() {
        let mut privks = vec![];
        let mut balances = vec![];
        let num_blocks = 10;

        for _ in 0..num_blocks {
            let privk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();

            privks.push(privk);
            balances.push((addr.to_account_principal(), 100000000));
        }

        let mut peer_config =
            TestPeerConfig::new("test_build_anchored_blocks_multiple_chaintips", 2008, 2009);
        peer_config.initial_balances = balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        // make a blank chainstate and mempool so we can mine empty blocks
        //  without punishing the correspondingly "too expensive" transactions
        let blank_chainstate = instantiate_chainstate(
            false,
            1,
            "test_build_anchored_blocks_multiple_chaintips_blank",
        );
        let mut blank_mempool =
            MemPoolDB::open_test(false, 1, &blank_chainstate.root_path).unwrap();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    if tenure_id > 0 {
                        let contract = "
                    (define-data-var bar int 0)
                    (define-public (get-bar) (ok (var-get bar)))
                    (define-public (set-bar (x int) (y int))
                      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            0,
                            (2 * contract.len()) as u64,
                            &format!("hello-world-{}", tenure_id),
                            &contract,
                        );
                        mempool
                            .submit(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &contract_tx,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }

                    let anchored_block = {
                        let mempool_to_use = if tenure_id < num_blocks - 1 {
                            &mut blank_mempool
                        } else {
                            &mut mempool
                        };

                        StacksBlockBuilder::build_anchored_block(
                            chainstate,
                            &sortdb.index_conn(),
                            mempool_to_use,
                            &parent_tip,
                            tip.total_burn,
                            vrf_proof,
                            Hash160([tenure_id as u8; 20]),
                            &coinbase_tx,
                            BlockBuilderSettings::limited(),
                            None,
                        )
                        .unwrap()
                    };
                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            if tenure_id < num_blocks - 1 {
                assert_eq!(stacks_block.txs.len(), 1);
            } else {
                assert_eq!(stacks_block.txs.len(), num_blocks);
            }
        }
    }

    #[test]
    fn test_build_anchored_blocks_empty_chaintips() {
        let mut privks = vec![];
        let mut balances = vec![];
        let num_blocks = 10;

        for _ in 0..num_blocks {
            let privk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();

            privks.push(privk);
            balances.push((addr.to_account_principal(), 100000000));
        }

        let mut peer_config =
            TestPeerConfig::new("test_build_anchored_blocks_empty_chaintips", 2010, 2011);
        peer_config.initial_balances = balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();

                    // submit a transaction for the _next_ block to pick up
                    if tenure_id > 0 {
                        let contract = "
                    (define-data-var bar int 0)
                    (define-public (get-bar) (ok (var-get bar)))
                    (define-public (set-bar (x int) (y int))
                      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            0,
                            2000,
                            &format!("hello-world-{}", tenure_id),
                            &contract,
                        );
                        mempool
                            .submit(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &contract_tx,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }

                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            test_debug!(
                "\n\ncheck tenure {}: {} transactions\n",
                tenure_id,
                stacks_block.txs.len()
            );

            if tenure_id > 1 {
                // two transactions after the first two tenures
                assert_eq!(stacks_block.txs.len(), 2);
            } else {
                assert_eq!(stacks_block.txs.len(), 1);
            }
        }
    }

    #[test]
    fn test_build_anchored_blocks_too_expensive_transactions() {
        let mut privks = vec![];
        let mut balances = vec![];
        let num_blocks = 3;

        for _ in 0..num_blocks {
            let privk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();

            privks.push(privk);
            balances.push((addr.to_account_principal(), 100000000));
        }

        let mut peer_config = TestPeerConfig::new(
            "test_build_anchored_blocks_too_expensive_transactions",
            2013,
            2014,
        );
        peer_config.initial_balances = balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    if tenure_id == 2 {
                        let contract = "
                    (define-data-var bar int 0)
                    (define-public (get-bar) (ok (var-get bar)))
                    (define-public (set-bar (x int) (y int))
                      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                        // should be mined once
                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            0,
                            100000000 / 2 + 1,
                            &format!("hello-world-{}", tenure_id),
                            &contract,
                        );
                        let mut contract_tx_bytes = vec![];
                        contract_tx
                            .consensus_serialize(&mut contract_tx_bytes)
                            .unwrap();
                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                contract_tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                        sleep_ms(2000);

                        // should never be mined
                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            1,
                            100000000 / 2,
                            &format!("hello-world-{}-2", tenure_id),
                            &contract,
                        );
                        let mut contract_tx_bytes = vec![];
                        contract_tx
                            .consensus_serialize(&mut contract_tx_bytes)
                            .unwrap();
                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                contract_tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                        sleep_ms(2000);
                    }

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();

                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            test_debug!(
                "\n\ncheck tenure {}: {} transactions\n",
                tenure_id,
                stacks_block.txs.len()
            );

            // assert_eq!(stacks_block.txs.len(), 1);
        }
    }

    #[test]
    fn test_build_anchored_blocks_invalid() {
        let peer_config = TestPeerConfig::new("test_build_anchored_blocks_invalid", 2014, 2015);
        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let num_blocks = 10;
        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let mut last_block: Option<StacksBlock> = None;
        let mut last_valid_block: Option<StacksBlock> = None;
        let mut last_tip: Option<BlockSnapshot> = None;
        let mut last_parent: Option<StacksBlock> = None;
        let mut last_parent_tip: Option<StacksHeaderInfo> = None;

        let bad_block_tenure = 6;
        let bad_block_ancestor_tenure = 3;
        let resume_parent_tenure = 5;

        let mut bad_block_tip: Option<BlockSnapshot> = None;
        let mut bad_block_parent: Option<StacksBlock> = None;
        let mut bad_block_parent_tip: Option<StacksHeaderInfo> = None;
        let mut bad_block_parent_commit: Option<LeaderBlockCommitOp> = None;

        let mut resume_tenure_parent_commit: Option<LeaderBlockCommitOp> = None;
        let mut resume_tip: Option<BlockSnapshot> = None;

        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let mut tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            if tenure_id == bad_block_ancestor_tenure {
                bad_block_tip = Some(tip.clone());
            } else if tenure_id == bad_block_tenure {
                tip = bad_block_tip.clone().unwrap();
            } else if tenure_id == resume_parent_tenure {
                resume_tip = Some(tip.clone());
            } else if tenure_id == bad_block_tenure + 1 {
                tip = resume_tip.clone().unwrap();
            }

            last_tip = Some(tip.clone());

            let (mut burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_opt =
                    if tenure_id != bad_block_tenure {
                        if let Some(p) = &last_parent {
                            assert!(tenure_id == bad_block_tenure + 1);
                            Some(p.clone())
                        }
                        else {
                            assert!(tenure_id != bad_block_tenure + 1);
                            match parent_opt {
                                Some(p) => Some((*p).clone()),
                                None => None
                            }
                        }
                    }
                    else {
                        bad_block_parent.clone()
                    };

                let parent_tip =
                    if tenure_id != bad_block_tenure {
                        if let Some(tip) = &last_parent_tip {
                            assert!(tenure_id == bad_block_tenure + 1);
                            tip.clone()
                        }
                        else {
                            assert!(tenure_id != bad_block_tenure + 1);
                            match parent_opt {
                                None => {
                                    StacksChainState::get_genesis_header_info(chainstate.db()).unwrap()
                                }
                                Some(ref block) => {
                                    let ic = sortdb.index_conn();
                                    let parent_block_hash =
                                        if let Some(ref block) = last_valid_block.as_ref() {
                                            block.block_hash()
                                        }
                                        else {
                                            block.block_hash()
                                        };

                                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(&ic, &tip.sortition_id, &parent_block_hash).unwrap().unwrap();      // succeeds because we don't fork
                                    StacksChainState::get_anchored_block_header_info(chainstate.db(), &snapshot.consensus_hash, &snapshot.winning_stacks_block_hash).unwrap().unwrap()
                                }
                            }
                        }
                    }
                    else {
                        bad_block_parent_tip.clone().unwrap()
                    };

                if tenure_id == resume_parent_tenure {
                    // resume here
                    last_parent = parent_opt.clone();
                    last_parent_tip = Some(parent_tip.clone());

                    eprintln!("\n\nat resume parent tenure:\nlast_parent: {:?}\nlast_parent_tip: {:?}\n\n", &last_parent, &last_parent_tip);
                }
                else if tenure_id >= bad_block_tenure + 1 {
                    last_parent = None;
                    last_parent_tip = None;
                }

                if tenure_id == bad_block_ancestor_tenure {
                    bad_block_parent_tip = Some(parent_tip.clone());
                    bad_block_parent = parent_opt.clone();

                    eprintln!("\n\nancestor of corrupt block: {:?}\n", &parent_tip);
                }

                if tenure_id == bad_block_tenure + 1 {
                    // prior block was invalid; reset nonce
                    miner.set_nonce(resume_parent_tenure as u64);
                }
                else if tenure_id == bad_block_tenure {
                    // building off of a long-gone snapshot
                    miner.set_nonce(miner.get_nonce() - ((bad_block_tenure - bad_block_ancestor_tenure) as u64));
                }

                let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let coinbase_tx = make_coinbase(miner, tenure_id as usize);

                let mut anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate, &sortdb.index_conn(), &mut mempool, &parent_tip, tip.total_burn, vrf_proof, Hash160([tenure_id as u8; 20]), &coinbase_tx, BlockBuilderSettings::max_value(), None,
                ).unwrap();

                if tenure_id == bad_block_tenure {
                    // corrupt the block
                    eprintln!("\n\ncorrupt block {:?}\nparent: {:?}\n", &anchored_block.0.header, &parent_tip.anchored_header);
                    anchored_block.0.header.state_index_root = TrieHash([0xff; 32]);
                }

                (anchored_block.0, vec![])
            });

            if tenure_id == bad_block_tenure + 1 {
                // adjust
                for i in 0..burn_ops.len() {
                    if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i]
                    {
                        opdata.parent_block_ptr =
                            (resume_tenure_parent_commit.as_ref().unwrap().block_height as u32) - 1;
                    }
                }
            } else if tenure_id == bad_block_tenure {
                // adjust
                for i in 0..burn_ops.len() {
                    if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i]
                    {
                        opdata.parent_block_ptr =
                            (bad_block_parent_commit.as_ref().unwrap().block_height as u32) - 1;
                        eprintln!("\n\ncorrupt block commit is now {:?}\n", opdata);
                    }
                }
            } else if tenure_id == bad_block_ancestor_tenure {
                // find
                for i in 0..burn_ops.len() {
                    if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i]
                    {
                        bad_block_parent_commit = Some(opdata.clone());
                    }
                }
            } else if tenure_id == resume_parent_tenure {
                // find
                for i in 0..burn_ops.len() {
                    if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i]
                    {
                        resume_tenure_parent_commit = Some(opdata.clone());
                    }
                }
            }

            if tenure_id != bad_block_tenure {
                last_block = Some(stacks_block.clone());
                last_valid_block = last_block.clone();
            } else {
                last_block = last_valid_block.clone();
            }

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch(&stacks_block, &consensus_hash, &microblocks);
        }
    }

    #[test]
    fn test_build_anchored_blocks_bad_nonces() {
        let mut privks = vec![];
        let mut balances = vec![];
        let num_blocks = 10;

        for _ in 0..num_blocks {
            let privk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();

            privks.push(privk);
            balances.push((addr.to_account_principal(), 100000000));
        }

        let mut peer_config = TestPeerConfig::new(
            "test_build_anchored_blocks_too_expensive_transactions",
            2012,
            2013,
        );
        peer_config.initial_balances = balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            eprintln!("Start tenure {:?}", tenure_id);
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_tip_ch = parent_tip.consensus_hash.clone();
                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let mut mempool =
                        MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    if tenure_id == 2 {
                        let contract = "
                    (define-data-var bar int 0)
                    (define-public (get-bar) (ok (var-get bar)))
                    (define-public (set-bar (x int) (y int))
                      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                        // should be mined once
                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            0,
                            10000,
                            &format!("hello-world-{}", tenure_id),
                            &contract,
                        );
                        let mut contract_tx_bytes = vec![];
                        contract_tx
                            .consensus_serialize(&mut contract_tx_bytes)
                            .unwrap();
                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_tip_ch,
                                &parent_header_hash,
                                contract_tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        eprintln!("first tx submitted");
                        // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                        sleep_ms(2000);

                        // should never be mined
                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            1,
                            10000,
                            &format!("hello-world-{}-2", tenure_id),
                            &contract,
                        );
                        let mut contract_tx_bytes = vec![];
                        contract_tx
                            .consensus_serialize(&mut contract_tx_bytes)
                            .unwrap();
                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_tip_ch,
                                &parent_header_hash,
                                contract_tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        eprintln!("second tx submitted");
                        // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                        sleep_ms(2000);
                    }

                    if tenure_id == 3 {
                        let contract = "
                    (define-data-var bar int 0)
                    (define-public (get-bar) (ok (var-get bar)))
                    (define-public (set-bar (x int) (y int))
                      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                        // should be mined once
                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            0,
                            10000,
                            &format!("hello-world-{}", tenure_id),
                            &contract,
                        );
                        let mut contract_tx_bytes = vec![];
                        contract_tx
                            .consensus_serialize(&mut contract_tx_bytes)
                            .unwrap();
                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_tip_ch,
                                &parent_header_hash,
                                contract_tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        eprintln!("third tx submitted");
                        // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                        sleep_ms(2000);

                        // should never be mined
                        let contract_tx = make_user_contract_publish(
                            &privks[tenure_id],
                            1,
                            10000,
                            &format!("hello-world-{}-2", tenure_id),
                            &contract,
                        );
                        let mut contract_tx_bytes = vec![];
                        contract_tx
                            .consensus_serialize(&mut contract_tx_bytes)
                            .unwrap();
                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_tip_ch,
                                &parent_header_hash,
                                contract_tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();

                        eprintln!("fourth tx submitted");
                        // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                        sleep_ms(2000);
                    }

                    let estimator = UnitEstimator;
                    let metric = UnitMetric;

                    let anchored_block = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();

                    (anchored_block.0, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            test_debug!(
                "\n\ncheck tenure {}: {} transactions\n",
                tenure_id,
                stacks_block.txs.len()
            );

            // assert_eq!(stacks_block.txs.len(), 1);
        }
    }

    fn get_stacks_account(peer: &mut TestPeer, addr: &PrincipalData) -> StacksAccount {
        let account = peer
            .with_db_state(|ref mut sortdb, ref mut chainstate, _, _| {
                let (consensus_hash, block_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
                let stacks_block_id =
                    StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
                let acct = chainstate
                    .with_read_only_clarity_tx(
                        &sortdb.index_conn(),
                        &stacks_block_id,
                        |clarity_tx| StacksChainState::get_account(clarity_tx, addr),
                    )
                    .unwrap();
                Ok(acct)
            })
            .unwrap();
        account
    }

    #[test]
    fn test_build_microblock_stream_forks() {
        let mut privks = vec![];
        let mut addrs = vec![];
        let mut mblock_privks = vec![];
        let mut balances = vec![];
        let num_blocks = 10;
        let initial_balance = 100000000;

        for _ in 0..num_blocks {
            let privk = StacksPrivateKey::new();
            let mblock_privk = StacksPrivateKey::new();

            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();

            addrs.push(addr.clone());
            privks.push(privk);
            mblock_privks.push(mblock_privk);
            balances.push((addr.to_account_principal(), initial_balance));
        }

        let mut peer_config = TestPeerConfig::new("test_build_microblock_stream_forks", 2014, 2015);
        peer_config.initial_balances = balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

        let mut last_block = None;
        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = match parent_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db())
                            .unwrap(),
                        Some(block) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap(); // succeeds because we don't fork
                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        }
                    };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let parent_index_hash = StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash);
                    let parent_size = parent_tip.anchored_block_size;

                    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let expected_parent_microblock_opt =
                        if tenure_id > 0 {
                            let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();

                            let parent_mblock_stream = {
                                let parent_cost = StacksChainState::get_stacks_block_anchored_cost(chainstate.db(), &StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash)).unwrap().unwrap();

                                // produce the microblock stream for the parent, which this tenure's anchor
                                // block will confirm.
                                let sort_ic = sortdb.index_conn();

                                chainstate
                                    .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                                    .unwrap();

                                let mut microblock_builder = StacksMicroblockBuilder::new(parent_header_hash.clone(), parent_consensus_hash.clone(), chainstate, &sort_ic, BlockBuilderSettings::max_value()).unwrap();

                                let mut microblocks = vec![];
                                for i in 0..5 {
                                    let mblock_tx = make_user_contract_publish(
                                        &privks[tenure_id - 1],
                                        i,
                                        0,
                                        &format!("hello-world-{}-{}", i, thread_rng().gen::<u64>()),
                                        &format!("(begin (print \"{}\"))", thread_rng().gen::<u64>())
                                    );
                                    let mblock_tx_len = {
                                        let mut bytes = vec![];
                                        mblock_tx.consensus_serialize(&mut bytes).unwrap();
                                        bytes.len() as u64
                                    };

                                    let mblock = microblock_builder.mine_next_microblock_from_txs(vec![(mblock_tx, mblock_tx_len)], &parent_microblock_privkey).unwrap();
                                    microblocks.push(mblock);
                                }
                                microblocks
                            };

                            // make a fork at seq 2
                            let mut forked_parent_microblock_stream = parent_mblock_stream.clone();
                            for i in 2..forked_parent_microblock_stream.len() {
                                let forked_mblock_tx = make_user_contract_publish(
                                    &privks[tenure_id - 1],
                                    i as u64,
                                    0,
                                    &format!("hello-world-fork-{}-{}", i, thread_rng().gen::<u64>()),
                                    &format!("(begin (print \"fork-{}\"))", thread_rng().gen::<u64>())
                                );

                                forked_parent_microblock_stream[i].txs[0] = forked_mblock_tx;

                                // re-calculate merkle root
                                let txid_vecs = forked_parent_microblock_stream[i].txs
                                    .iter()
                                    .map(|tx| tx.txid().as_bytes().to_vec())
                                    .collect();

                                let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
                                let tx_merkle_root = merkle_tree.root();

                                forked_parent_microblock_stream[i].header.tx_merkle_root = tx_merkle_root;
                                forked_parent_microblock_stream[i].header.prev_block = forked_parent_microblock_stream[i-1].block_hash();
                                forked_parent_microblock_stream[i].header.sign(&parent_microblock_privkey).unwrap();

                                test_debug!("parent of microblock {} is {}", &forked_parent_microblock_stream[i].block_hash(), &forked_parent_microblock_stream[i-1].block_hash());
                            }

                            let mut tail = None;

                            // store two forks, which diverge at seq 2
                            for mblock in parent_mblock_stream.into_iter() {
                                if mblock.header.sequence < 2 {
                                    tail = Some((mblock.block_hash(), mblock.header.sequence));
                                }
                                let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, &mblock).unwrap();
                                assert!(stored);
                            }
                            for mblock in forked_parent_microblock_stream[2..].iter() {
                                let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, mblock).unwrap();
                                assert!(stored);
                            }

                            // find the poison-microblock at seq 2
                            let (_, poison_opt) = match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                                &chainstate.db(),
                                &parent_index_hash,
                                0,
                                u16::MAX
                            ).unwrap() {
                                Some(x) => x,
                                None => (vec![], None)
                            };

                            if let Some(poison_payload) = poison_opt {
                                let mut tx_bytes = vec![];
                                let poison_microblock_tx = make_user_poison_microblock(
                                    &privks[tenure_id - 1],
                                    2,
                                    0,
                                    poison_payload
                                );

                                poison_microblock_tx
                                    .consensus_serialize(&mut tx_bytes)
                                    .unwrap();

                                mempool
                                    .submit_raw(
                                        chainstate,
                                        &parent_consensus_hash,
                                        &parent_header_hash,
                                        tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                                    )
                                    .unwrap();
                            }
                            // the miner will load a microblock stream up to the first detected
                            // fork (which is at sequence 2)
                            tail
                        }
                        else {
                            None
                        };

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let mblock_pubkey_hash = Hash160::from_node_public_key(&StacksPublicKey::from_private(&mblock_privks[tenure_id]));

                    let (anchored_block, block_size, block_execution_cost) = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        mblock_pubkey_hash,
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();

                    // miner should have picked up the preprocessed microblocks, but only up to the
                    // fork.
                    if let Some((mblock_tail_hash, mblock_tail_seq)) = expected_parent_microblock_opt {
                        assert_eq!(anchored_block.header.parent_microblock, mblock_tail_hash);
                        assert_eq!(anchored_block.header.parent_microblock_sequence, mblock_tail_seq);
                        assert_eq!(mblock_tail_seq, 1);
                    }

                    // block should contain at least one poison-microblock tx
                    if tenure_id > 0 {
                        let mut have_poison_microblock = false;
                        for tx in anchored_block.txs.iter() {
                            if let TransactionPayload::PoisonMicroblock(_, _) = &tx.payload {
                                have_poison_microblock = true;
                            }
                        }
                        assert!(have_poison_microblock, "Anchored block has no poison microblock: {:#?}", &anchored_block);
                    }

                    (anchored_block, vec![])
                },
            );

            last_block = Some(stacks_block.clone());

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        }

        for (i, addr) in addrs.iter().enumerate() {
            let account = get_stacks_account(&mut peer, &addr.to_account_principal());
            let expected_coinbase = 3_600_000_000;
            test_debug!(
                "Test {}: {}",
                &account.principal.to_string(),
                account.stx_balance.get_total_balance()
            );
            if (i as u64) < (num_blocks as u64) - MINER_REWARD_MATURITY - 1 {
                assert_eq!(
                    account.stx_balance.get_total_balance(),
                    (initial_balance as u128)
                        + (expected_coinbase * POISON_MICROBLOCK_COMMISSION_FRACTION) / 100
                );
            } else {
                assert_eq!(
                    account.stx_balance.get_total_balance(),
                    initial_balance as u128
                );
            }
        }
    }

    #[test]
    fn test_build_microblock_stream_forks_with_descendants() {
        // creates a chainstate that looks like this:
        //
        //                                                   [mblock] <- [mblock] <- [tenure-2] (Poison-at-2)
        //                                                 /
        //                                          (2)   /
        // [tenure-0] <- [mblock] <- [mblock] <- [mblock] <- [tenure-1] (Poison-at-2)
        //                                                \
        //                                                 \               (4)
        //                                                   [mblock] <- [mblock] <- [tenure-3] (Poison-at-4)
        //
        //  Tenures 1 and 2 can report PoisonMicroblocks for the same point in the mblock stream
        //  fork as long as they themselves are on different branches.
        //
        //  Tenure 3 can report a PoisonMicroblock for a lower point in the fork and have it mined
        //  (seq(4)), as long as the PoisonMicroblock at seq(2) doesn't find its way into its fork
        //  of the chain history.
        let mut privks = vec![];
        let mut addrs = vec![];
        let mut mblock_privks = vec![];
        let mut balances = vec![];
        let num_blocks = 4;
        let initial_balance = 100000000;

        for _ in 0..num_blocks {
            let privk = StacksPrivateKey::new();
            let mblock_privk = StacksPrivateKey::new();

            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();

            test_debug!("addr: {:?}", &addr);
            addrs.push(addr.clone());
            privks.push(privk);
            mblock_privks.push(mblock_privk);
            balances.push((addr.to_account_principal(), initial_balance));
        }

        let mut peer_config = TestPeerConfig::new(
            "test_build_microblock_stream_forks_with_descendants",
            2014,
            2015,
        );
        peer_config.initial_balances = balances;

        let mut peer = TestPeer::new(peer_config);

        let chainstate_path = peer.chainstate_path.clone();

        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
        let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

        let mut microblock_tail_1: Option<StacksMicroblockHeader> = None;
        let mut microblock_tail_2: Option<StacksMicroblockHeader> = None;

        let mut parent_tip_1 = None;

        let parent_block_ptrs = RefCell::new(HashMap::new());
        let discovered_poison_payload = RefCell::new(None);

        let mut reporters = vec![];

        for tenure_id in 0..num_blocks {
            // send transactions to the mempool
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (mut burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let mut parent_tip =
                        if tenure_id == 0 || tenure_id == 1 {
                            let tip = match parent_opt {
                                None => StacksChainState::get_genesis_header_info(chainstate.db())
                                    .unwrap(),
                                Some(block) => {
                                    let ic = sortdb.index_conn();
                                    let snapshot =
                                        SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                            &ic,
                                            &tip.sortition_id,
                                            &block.block_hash(),
                                        )
                                        .unwrap()
                                        .unwrap(); // succeeds because we don't fork
                                    StacksChainState::get_anchored_block_header_info(
                                        chainstate.db(),
                                        &snapshot.consensus_hash,
                                        &snapshot.winning_stacks_block_hash,
                                    )
                                    .unwrap()
                                    .unwrap()
                                }
                            };
                            if tenure_id == 1 {
                                // save this for later
                                parent_tip_1 = Some(tip.clone());
                            }
                            tip
                        }
                        else if tenure_id == 2 || tenure_id == 3 {
                            // tenures 2 and 3 build off of microblock forks, but they share the
                            // same parent anchored block.
                            parent_tip_1.clone().unwrap()
                        }
                        else {
                            unreachable!()
                        };

                    let parent_header_hash = parent_tip.anchored_header.block_hash();
                    let parent_consensus_hash = parent_tip.consensus_hash.clone();
                    let parent_index_hash = StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash);
                    let parent_size = parent_tip.anchored_block_size;

                    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                    let (expected_parent_microblock_opt, fork_1, fork_2) =
                        if tenure_id == 1 {
                            // make a microblock fork
                            let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();

                            let parent_mblock_stream = {
                                let parent_cost = StacksChainState::get_stacks_block_anchored_cost(chainstate.db(), &StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash)).unwrap().unwrap();

                                // produce the microblock stream for the parent, which this tenure's anchor
                                // block will confirm.
                                let sort_ic = sortdb.index_conn();

                                chainstate
                                    .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                                    .unwrap();

                                let mut microblock_builder = StacksMicroblockBuilder::new(parent_header_hash.clone(), parent_consensus_hash.clone(), chainstate, &sort_ic, BlockBuilderSettings::max_value()).unwrap();

                                let mut microblocks = vec![];
                                for i in 0..5 {
                                    let mblock_tx = make_user_contract_publish(
                                        &privks[tenure_id - 1],
                                        i,
                                        0,
                                        &format!("hello-world-{}-{}", i, thread_rng().gen::<u64>()),
                                        &format!("(begin (print \"{}\"))", thread_rng().gen::<u64>())
                                    );
                                    let mblock_tx_len = {
                                        let mut bytes = vec![];
                                        mblock_tx.consensus_serialize(&mut bytes).unwrap();
                                        bytes.len() as u64
                                    };

                                    let mblock = microblock_builder.mine_next_microblock_from_txs(vec![(mblock_tx, mblock_tx_len)], &parent_microblock_privkey).unwrap();
                                    microblocks.push(mblock);
                                }
                                microblocks
                            };

                            // make a fork at seq 2
                            let mut forked_parent_microblock_stream = parent_mblock_stream.clone();
                            for i in 2..parent_mblock_stream.len() {
                                let forked_mblock_tx = make_user_contract_publish(
                                    &privks[tenure_id - 1],
                                    i as u64,
                                    0,
                                    &format!("hello-world-fork-{}-{}", i, thread_rng().gen::<u64>()),
                                    &format!("(begin (print \"fork-{}\"))", thread_rng().gen::<u64>())
                                );

                                forked_parent_microblock_stream[i].txs[0] = forked_mblock_tx;

                                // re-calculate merkle root
                                let txid_vecs = forked_parent_microblock_stream[i].txs
                                    .iter()
                                    .map(|tx| tx.txid().as_bytes().to_vec())
                                    .collect();

                                let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
                                let tx_merkle_root = merkle_tree.root();

                                forked_parent_microblock_stream[i].header.tx_merkle_root = tx_merkle_root;
                                forked_parent_microblock_stream[i].header.prev_block = forked_parent_microblock_stream[i - 1].block_hash();
                                forked_parent_microblock_stream[i].header.sign(&parent_microblock_privkey).unwrap();

                                test_debug!("parent of microblock {} is {}", &forked_parent_microblock_stream[i].block_hash(), &forked_parent_microblock_stream[i-1].block_hash());
                            }

                            let mut tail = None;

                            // store two forks, which diverge at seq 2
                            for mblock in parent_mblock_stream.iter() {
                                if mblock.header.sequence < 2 {
                                    tail = Some((mblock.block_hash(), mblock.header.sequence));
                                }
                                let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, &mblock).unwrap();
                                assert!(stored);
                            }
                            for mblock in forked_parent_microblock_stream[2..].iter() {
                                let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, mblock).unwrap();
                                assert!(stored);
                            }

                            // find the poison-microblock at seq 2
                            let (_, poison_opt) = match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                                &chainstate.db(),
                                &parent_index_hash,
                                0,
                                u16::MAX
                            ).unwrap() {
                                Some(x) => x,
                                None => (vec![], None)
                            };

                            if let Some(poison_payload) = poison_opt {
                                *discovered_poison_payload.borrow_mut() = Some(poison_payload.clone());

                                let mut tx_bytes = vec![];
                                let poison_microblock_tx = make_user_poison_microblock(
                                    &privks[tenure_id - 1],
                                    2,
                                    0,
                                    poison_payload
                                );

                                poison_microblock_tx
                                    .consensus_serialize(&mut tx_bytes)
                                    .unwrap();

                                mempool
                                    .submit_raw(
                                        chainstate,
                                        &parent_consensus_hash,
                                        &parent_header_hash,
                                        tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                                    )
                                    .unwrap();
                            }

                            // the miner will load a microblock stream up to the first detected
                            // fork (which is at sequence 2 -- the highest common ancestor between
                            // microblock fork #1 and microblock fork #2)
                            (tail, Some(parent_mblock_stream), Some(forked_parent_microblock_stream))
                        }
                        else if tenure_id == 2 {
                            // build off of the end of microblock fork #1
                            (Some((microblock_tail_1.as_ref().unwrap().block_hash(), microblock_tail_1.as_ref().unwrap().sequence)), None, None)
                        }
                        else if tenure_id == 3 {
                            // builds off of the end of microblock fork #2
                            (Some((microblock_tail_2.as_ref().unwrap().block_hash(), microblock_tail_2.as_ref().unwrap().sequence)), None, None)
                        }
                        else {
                            (None, None, None)
                        };

                    if tenure_id == 1 {
                        // prep for tenure 2 and 3
                        microblock_tail_1 = Some(fork_1.as_ref().unwrap().last().clone().unwrap().header.clone());
                        microblock_tail_2 = Some(fork_2.as_ref().unwrap().last().clone().unwrap().header.clone());
                    }

                    let nonce =
                        if tenure_id == 0 || tenure_id == 1 {
                            tenure_id
                        }
                        else if tenure_id == 2 {
                            1
                        }
                        else if tenure_id == 3 {
                            1
                        }
                        else {
                            unreachable!()
                        };

                    let coinbase_tx = make_coinbase_with_nonce(miner, tenure_id, nonce as u64);

                    let mblock_pubkey_hash = Hash160::from_node_public_key(&StacksPublicKey::from_private(&mblock_privks[tenure_id]));

                    test_debug!("Produce tenure {} block off of {}/{}", tenure_id, &parent_consensus_hash, &parent_header_hash);

                    // force tenures 2 and 3 to mine off of forked siblings deeper than the
                    // detected fork
                    if tenure_id == 2 {
                        parent_tip.microblock_tail = microblock_tail_1.clone();

                        // submit the _same_ poison microblock transaction, but to a different
                        // fork.
                        let poison_payload = discovered_poison_payload.borrow().as_ref().unwrap().clone();
                        let poison_microblock_tx = make_user_poison_microblock(
                            &privks[tenure_id],
                            0,
                            0,
                            poison_payload
                        );

                        let mut tx_bytes = vec![];
                        poison_microblock_tx
                            .consensus_serialize(&mut tx_bytes)
                            .unwrap();

                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }
                    else if tenure_id == 3 {
                        parent_tip.microblock_tail = microblock_tail_2.clone();

                        // submit a different poison microblock transaction
                        let poison_payload = TransactionPayload::PoisonMicroblock(microblock_tail_1.as_ref().unwrap().clone(), microblock_tail_2.as_ref().unwrap().clone());
                        let poison_microblock_tx = make_user_poison_microblock(
                            &privks[tenure_id],
                            0,
                            0,
                            poison_payload
                        );

                        // erase any pending transactions -- this is a "worse" poison-microblock,
                        // and we want to avoid mining the "better" one
                        mempool.clear_before_height(10).unwrap();

                        let mut tx_bytes = vec![];
                        poison_microblock_tx
                            .consensus_serialize(&mut tx_bytes)
                            .unwrap();

                        mempool
                            .submit_raw(
                                chainstate,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                tx_bytes,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }

                    let (anchored_block, block_size, block_execution_cost) = StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_conn(),
                        &mut mempool,
                        &parent_tip,
                        parent_tip.anchored_header.total_work.burn + 1000,
                        vrf_proof,
                        mblock_pubkey_hash,
                        &coinbase_tx,
                        BlockBuilderSettings::max_value(),
                        None,
                    )
                    .unwrap();

                    // miner should have picked up the preprocessed microblocks, but only up to the
                    // fork tail reported.

                    // block should contain at least one poison-microblock tx
                    if tenure_id == 1 {
                        if let Some((mblock_tail_hash, mblock_tail_seq)) = expected_parent_microblock_opt {
                            assert_eq!(anchored_block.header.parent_microblock, mblock_tail_hash);
                            assert_eq!(anchored_block.header.parent_microblock_sequence, mblock_tail_seq);
                        }
                    }
                    if tenure_id > 0 {
                        let mut have_poison_microblock = false;
                        for tx in anchored_block.txs.iter() {
                            if let TransactionPayload::PoisonMicroblock(_, _) = &tx.payload {
                                have_poison_microblock = true;
                                test_debug!("Have PoisonMicroblock for {} reported by {:?}", &anchored_block.block_hash(), &tx.auth);
                            }
                        }
                        assert!(have_poison_microblock, "Anchored block has no poison microblock: {:#?}", &anchored_block);
                    }

                    // tenures 2 and 3 build off of 1, but build off of the deepest microblock fork
                    if tenure_id == 2 {
                        assert_eq!(anchored_block.header.parent_microblock, microblock_tail_1.as_ref().unwrap().block_hash());
                        assert_eq!(anchored_block.header.parent_microblock_sequence, 4);
                    }
                    if tenure_id == 3 {
                        assert_eq!(anchored_block.header.parent_microblock, microblock_tail_2.as_ref().unwrap().block_hash());
                        assert_eq!(anchored_block.header.parent_microblock_sequence, 4);
                    }

                    let mut parent_ptrs = parent_block_ptrs.borrow_mut();
                    parent_ptrs.insert(anchored_block.header.parent_block.clone(), parent_tip.burn_header_height);

                    (anchored_block, vec![])
                },
            );

            for burn_op in burn_ops.iter_mut() {
                if let BlockstackOperationType::LeaderBlockCommit(ref mut op) = burn_op {
                    // patch it up
                    op.parent_block_ptr = (*parent_block_ptrs
                        .borrow()
                        .get(&stacks_block.header.parent_block)
                        .unwrap()) as u32;
                }
            }

            let (_, burn_header_hash, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch(&stacks_block, &consensus_hash, &microblocks);

            if tenure_id >= 1 {
                let next_tip = StacksChainState::get_anchored_block_header_info(
                    peer.chainstate().db(),
                    &consensus_hash,
                    &stacks_block.block_hash(),
                )
                .unwrap()
                .unwrap();

                let new_tip_hash = StacksBlockHeader::make_index_block_hash(
                    &next_tip.consensus_hash,
                    &next_tip.anchored_header.block_hash(),
                );

                let reporter = if tenure_id == 1 {
                    addrs[0].clone()
                } else {
                    addrs[tenure_id].clone()
                };

                let seq = if tenure_id == 1 || tenure_id == 2 {
                    2
                } else {
                    4
                };

                // check descendant blocks for their poison-microblock commissions
                test_debug!(
                    "new tip at height {}: {}",
                    next_tip.stacks_block_height,
                    &new_tip_hash
                );
                reporters.push((reporter, new_tip_hash, seq));
            }
        }

        // verify that each submitted poison-microblock created a commission
        for (reporter_addr, chain_tip, seq) in reporters.into_iter() {
            test_debug!("Check {} in {} for report", &reporter_addr, &chain_tip);
            peer.with_db_state(|ref mut sortdb, ref mut chainstate, _, _| {
                chainstate
                    .with_read_only_clarity_tx(&sortdb.index_conn(), &chain_tip, |clarity_tx| {
                        // the key at height 1 should be reported as poisoned
                        let report = StacksChainState::get_poison_microblock_report(clarity_tx, 1)
                            .unwrap()
                            .unwrap();
                        assert_eq!(report.0, reporter_addr);
                        assert_eq!(report.1, seq);
                        Ok(())
                    })
                    .unwrap()
            })
            .unwrap();
        }
    }

    pub fn instantiate_and_exec(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        balances: Vec<(StacksAddress, u64)>,
        post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx) -> ()>>,
    ) -> StacksChainState {
        let path = chainstate_path(test_name);
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            }
            Err(_) => {}
        };

        let initial_balances = balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback,
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

    // TODO: invalid block with duplicate microblock public key hash (okay between forks, but not
    // within the same fork)
    // TODO; skipped blocks
    // TODO: missing blocks
    // TODO: no-sortition
    // TODO: burnchain forks, and we mine the same anchored stacks block in the beginnings of the two descendent
    // forks.  Verify all descendents are unique -- if A --> B and A --> C, and B --> D and C -->
    // E, and B == C, verify that it is never the case that D == E (but it is allowed that B == C
    // if the burnchain forks).
    // TODO: confirm that if A is accepted but B is rejected, then C must also be rejected even if
    // it's on a different burnchain fork.
    // TODO: confirm that we can process B and C separately, even though they're the same block
}
