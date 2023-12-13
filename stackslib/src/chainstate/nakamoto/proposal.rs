use std::collections::{HashMap, HashSet};
use std::convert::From;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::{cmp, fs, mem};

use clarity::vm::analysis::{CheckError, CheckErrors};
use clarity::vm::ast::errors::ParseErrors;
use clarity::vm::ast::ASTRules;
use clarity::vm::clarity::TransactionConnection;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::BurnStateDB;
use clarity::vm::errors::Error as InterpreterError;
use clarity::vm::types::TypeSignature;
use serde::Deserialize;
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_PAYLOAD_LEN,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, TrieHash,
};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::{Hash160, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};
use stacks_common::util::vrf::*;

use crate::burnchains::{PrivateKey, PublicKey};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionDBConn, SortitionHandleTx};
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::*;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, SetupBlockResult,
};
use crate::chainstate::stacks::address::StacksAddressExtensions;
use crate::chainstate::stacks::db::accounts::MinerReward;
use crate::chainstate::stacks::db::blocks::MemPoolRejection;
use crate::chainstate::stacks::db::transactions::{
    handle_clarity_runtime_error, ClarityRuntimeTxError,
};
use crate::chainstate::stacks::db::{
    ChainstateTx, ClarityTx, MinerRewardInfo, StacksChainState, StacksHeaderInfo,
    MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::events::{StacksTransactionEvent, StacksTransactionReceipt};
use crate::chainstate::stacks::miner::{
    BlockBuilder, BlockBuilderSettings, BlockLimitFunction, TransactionError,
    TransactionProblematic, TransactionResult, TransactionSkipped,
};
use crate::chainstate::stacks::{Error, StacksBlockHeader, *};
use crate::clarity_vm::clarity::{ClarityConnection, ClarityInstance, Error as clarity_error};
use crate::core::mempool::*;
use crate::core::*;
use crate::cost_estimates::metrics::CostMetric;
use crate::cost_estimates::CostEstimator;
use crate::monitoring::{
    set_last_mined_block_transaction_count, set_last_mined_execution_cost_observed,
};
use crate::net::relay::Relayer;
use crate::net::Error as net_error;
use crate::util_lib::db::Error as DBError;

/// This enum is used to supply a `reason_code` for validation
///  rejection responses. This is serialized as an enum with string
///  type (in jsonschema terminology).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidateRejectCode {
    BadBlockHash,
    BadTransaction,
    InvalidBlock,
    ChainstateError,
    UnknownParent,
}

/// A response for block proposal validation
///  that the stacks-node thinks should be rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockValidateReject {
    pub reason: String,
    pub reason_code: ValidateRejectCode,
}

/// A response for block proposal validation
///  that the stacks-node thinks is acceptable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockValidateOk {
    pub block: NakamotoBlock,
    pub cost: ExecutionCost,
    pub size: u64,
}

/// This enum is used for serializing the response to block
/// proposal validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "Result")]
pub enum BlockValidateResponse {
    Ok(BlockValidateOk),
    Reject(BlockValidateReject),
}

impl From<Result<BlockValidateOk, BlockValidateReject>> for BlockValidateResponse {
    fn from(value: Result<BlockValidateOk, BlockValidateReject>) -> Self {
        match value {
            Ok(o) => BlockValidateResponse::Ok(o),
            Err(e) => BlockValidateResponse::Reject(e),
        }
    }
}

impl From<Error> for BlockValidateReject {
    fn from(value: Error) -> Self {
        BlockValidateReject {
            reason: format!("Chainstate Error: {value}"),
            reason_code: ValidateRejectCode::ChainstateError,
        }
    }
}

impl From<DBError> for BlockValidateReject {
    fn from(value: DBError) -> Self {
        Error::from(value).into()
    }
}

/// Represents a block proposed to the `v2/block_proposal` endpoint for validation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoBlockProposal {
    /// Proposed block
    pub block: NakamotoBlock,
    // tenure ID -- this is the index block hash of the start block of the last tenure (i.e.
    // the data we committed to in the block-commit).  If this is an epoch 2.x parent, then
    // this is just the index block hash of the parent Stacks block.
    pub tenure_start_block: StacksBlockId,
    /// Most recent burnchain block hash
    pub burn_tip: BurnchainHeaderHash,
    /// This refers to the burn block that was the current tip
    ///  at the time this proposal was constructed. In most cases,
    ///  if this proposal is accepted, it will be "mined" in the next
    ///  burn block.
    pub burn_tip_height: u32,
    /// Identifies which chain block is for (Mainnet, Testnet, etc.)
    pub chain_id: u32,
    /// total BTC burn so far
    pub total_burn: u64,
}

impl StacksMessageCodec for NakamotoBlockProposal {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.block)?;
        write_next(fd, &self.tenure_start_block)?;
        write_next(fd, &self.burn_tip)?;
        write_next(fd, &self.burn_tip_height)?;
        write_next(fd, &self.chain_id)?;
        write_next(fd, &self.total_burn)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            block: read_next(fd)?,
            tenure_start_block: read_next(fd)?,
            burn_tip: read_next(fd)?,
            burn_tip_height: read_next(fd)?,
            chain_id: read_next(fd)?,
            total_burn: read_next(fd)?,
        })
    }
}

impl NakamotoBlockProposal {
    /// Test this block proposal against the current chain state and
    /// either accept or reject the proposal
    ///
    /// This is done in 2 steps:
    /// - Static validation of the block, which checks the following:
    ///   - Block is well-formed
    ///   - Transactions are well-formed
    ///   - Miner signature is valid
    /// - Validation of transactions by executing them agains current chainstate.
    ///   This is resource intensive, and therefore done only if previous checks pass
    pub fn validate(
        &self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState, // not directly used; used as a handle to open other chainstates
    ) -> Result<BlockValidateOk, BlockValidateReject> {
        // Time this function
        let ts_start = get_epoch_time_ms();

        let mainnet = self.chain_id == CHAIN_ID_MAINNET;
        if self.chain_id != chainstate.chain_id || mainnet != chainstate.mainnet {
            return Err(BlockValidateReject {
                reason_code: ValidateRejectCode::InvalidBlock,
                reason: "Wrong netowrk/chain_id".into(),
            });
        }

        let burn_dbconn = sortdb.index_conn();
        let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn())?;
        let mut db_handle = sortdb.index_handle(&sort_tip);
        // Is this safe?
        let mut _chainstate = chainstate.reopen()?.0;
        let (chainstate_tx, _clarity_instance) = _chainstate.chainstate_tx_begin()?;
        let expected_burn =
            NakamotoChainState::get_expected_burns(&mut db_handle, &chainstate_tx, &self.block)?;

        // Static validation checks
        NakamotoChainState::validate_nakamoto_block_burnchain(
            &db_handle,
            expected_burn,
            &self.block,
            mainnet,
            self.chain_id,
        )?;

        // Validate block txs against chainstate
        let parent_stacks_header = NakamotoChainState::get_block_header(
            &chainstate_tx,
            &self.block.header.parent_block_id,
        )?
        .ok_or_else(|| BlockValidateReject {
            reason_code: ValidateRejectCode::InvalidBlock,
            reason: "Invalid parent block".into(),
        })?;
        let tenure_change = self
            .block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::TenureChange(..)));
        let coinbase = self
            .block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::Coinbase(..)));
        let tenure_cause = tenure_change.and_then(|tx| match &tx.payload {
            TransactionPayload::TenureChange(tc) => Some(tc.cause),
            _ => None,
        });

        let mut builder = NakamotoBlockBuilder::new_from_parent(
            &self.tenure_start_block,
            &parent_stacks_header,
            &self.block.header.consensus_hash,
            self.total_burn,
            tenure_change,
            coinbase,
        )?;

        let mut miner_tenure_info =
            builder.load_tenure_info(chainstate, &burn_dbconn, tenure_cause)?;
        let mut tenure_tx = builder.tenure_begin(&burn_dbconn, &mut miner_tenure_info)?;

        for (i, tx) in self.block.txs.iter().enumerate() {
            let tx_len = tx.tx_len();
            let tx_result = builder.try_mine_tx_with_len(
                &mut tenure_tx,
                &tx,
                tx_len,
                &BlockLimitFunction::NO_LIMIT_HIT,
                ASTRules::PrecheckSize,
            );
            let err = match tx_result {
                TransactionResult::Success(_) => Ok(()),
                TransactionResult::Skipped(s) => Err(format!("tx {i} skipped: {}", s.error)),
                TransactionResult::ProcessingError(e) => {
                    Err(format!("Error processing tx {i}: {}", e.error))
                }
                TransactionResult::Problematic(p) => {
                    Err(format!("Problematic tx {i}: {}", p.error))
                }
            };
            if let Err(reason) = err {
                warn!(
                    "Rejected block proposal";
                    "reason" => %reason,
                    "tx" => ?tx,
                );
                return Err(BlockValidateReject {
                    reason,
                    reason_code: ValidateRejectCode::BadTransaction,
                });
            }
        }

        let mut block = builder.mine_nakamoto_block(&mut tenure_tx);
        let size = builder.get_bytes_so_far();
        let cost = builder.tenure_finish(tenure_tx);

        // Clone signatures from block proposal
        // These have already been validated by `validate_nakamoto_block_burnchain()``
        block.header.miner_signature = self.block.header.miner_signature.clone();
        block.header.signer_signature = self.block.header.signer_signature.clone();

        // Assuming `tx_nerkle_root` has been checked we don't need to hash the whole block
        let expected_block_header_hash = self.block.header.block_hash();
        let computed_block_header_hash = block.header.block_hash();

        if computed_block_header_hash != expected_block_header_hash {
            warn!(
                "Rejected block proposal";
                "reason" => "Block hash is not as expected",
                "expected_block_header_hash" => %expected_block_header_hash,
                "computed_block_header_hash" => %computed_block_header_hash,
            );
            return Err(BlockValidateReject {
                reason: "Block hash is not as expected".into(),
                reason_code: ValidateRejectCode::BadBlockHash,
            });
        }

        let ts_end = get_epoch_time_ms();

        info!(
            "Participant: validated anchored block";
            "block_header_hash" => %computed_block_header_hash,
            "height" => block.header.chain_length,
            "tx_count" => block.txs.len(),
            "parent_stacks_block_id" => %block.header.parent_block_id,
            "block_size" => size,
            "execution_cost" => %cost,
            "validation_time_ms" => ts_end.saturating_sub(ts_start),
            "tx_fees_microstacks" => block.txs.iter().fold(0, |agg: u64, tx| {
                agg.saturating_add(tx.get_tx_fee())
            })
        );

        Ok(BlockValidateOk { block, cost, size })
    }
}
