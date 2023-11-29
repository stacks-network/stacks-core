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
    /// Identify the stacks/burnchain fork we are on
    pub parent_consensus_hash: ConsensusHash,
    /// Most recent burnchain block hash
    pub burn_tip: BurnchainHeaderHash,
    /// This refers to the burn block that was the current tip
    ///  at the time this proposal was constructed. In most cases,
    ///  if this proposal is accepted, it will be "mined" in the next
    ///  burn block.
    pub burn_tip_height: u32,
    /// Identifies which chain block is for (Mainnet, Testnet, etc.)
    pub chain_id: u32,
}

impl StacksMessageCodec for NakamotoBlockProposal {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.block)?;
        write_next(fd, &self.parent_consensus_hash)?;
        write_next(fd, &self.burn_tip)?;
        write_next(fd, &self.burn_tip_height)?;
        write_next(fd, &self.chain_id)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            block: read_next(fd)?,
            parent_consensus_hash: read_next(fd)?,
            burn_tip: read_next(fd)?,
            burn_tip_height: read_next(fd)?,
            chain_id: read_next(fd)?,
        })
    }
}

impl NakamotoBlockProposal {
    /// Test this block proposal against the current chain state and
    /// either accept or reject the proposal.
    pub fn validate(
        &self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState, // not directly used; used as a handle to open other chainstates
    ) -> Result<BlockValidateOk, BlockValidateReject> {
        let mainnet = self.chain_id == CHAIN_ID_MAINNET;
        if self.chain_id != chainstate.chain_id || mainnet != chainstate.mainnet {
            return Err(BlockValidateReject {
                reason_code: ValidateRejectCode::InvalidBlock,
                reason: "Wrong netowrk/chain_id".into(),
            });
        }

        let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn())?;
        let mut db_handle = sortdb.index_handle(&sort_tip);
        let (chainstate_tx, _clarity_instance) = chainstate.chainstate_tx_begin()?;
        let expected_burn =
            NakamotoChainState::get_expected_burns(&mut db_handle, &chainstate_tx, &self.block)?;

        NakamotoChainState::validate_nakamoto_block_burnchain(
            &db_handle,
            expected_burn,
            &self.block,
            mainnet,
            self.chain_id,
        )?;

        // TODO: Validate block txs against chainstate

        Ok(BlockValidateOk {
            block: self.block.clone(),
            cost: ExecutionCost::zero(),
            size: 0, // TODO
        })
    }
}
