// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::ops::{Deref, DerefMut, Range};
use std::path::PathBuf;

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::{BurnStateDB, ClarityDatabase};
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::{PrincipalData, StacksAddressExtensions, TupleData};
use clarity::vm::{ClarityVersion, SymbolicExpression, Value};
use lazy_static::{__Deref, lazy_static};
use rusqlite::blob::Blob;
use rusqlite::types::{FromSql, FromSqlError};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, ToSql, NO_PARAMS};
use sha2::{Digest as Sha2Digest, Sha512_256};
use stacks_common::bitvec::BitVec;
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_MESSAGE_LEN,
    MAX_PAYLOAD_LEN,
};
use stacks_common::consts::{
    FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, MINER_REWARD_MATURITY,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId,
    StacksPrivateKey, StacksPublicKey, TrieHash, VRFSeed,
};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::hash::{to_hex, Hash160, MerkleHashFunc, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey, VRF};
use stacks_common::util::{get_epoch_time_secs, sleep_ms};
use wsts::curve::point::Point;

use self::signer_set::SignerCalculation;
use super::burn::db::sortdb::{
    get_ancestor_sort_id, get_ancestor_sort_id_tx, get_block_commit_by_txid, SortitionHandle,
    SortitionHandleConn, SortitionHandleTx,
};
use super::burn::operations::{DelegateStxOp, StackStxOp, TransferStxOp, VoteForAggregateKeyOp};
use super::stacks::boot::{
    PoxVersions, RawRewardSetEntry, RewardSet, RewardSetData, BOOT_TEST_POX_4_AGG_KEY_CONTRACT,
    BOOT_TEST_POX_4_AGG_KEY_FNAME, SIGNERS_MAX_LIST_SIZE, SIGNERS_NAME, SIGNERS_PK_LEN,
};
use super::stacks::db::accounts::MinerReward;
use super::stacks::db::{
    ChainstateTx, ClarityTx, MinerPaymentSchedule, MinerPaymentTxFees, MinerRewardInfo,
    StacksBlockHeaderTypes, StacksDBTx, StacksEpochReceipt, StacksHeaderInfo,
};
use super::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use super::stacks::{
    Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksMicroblock, StacksTransaction,
    TenureChangeError, TenureChangePayload, ThresholdSignature, TransactionPayload,
};
use crate::burnchains::{Burnchain, PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::{LeaderBlockCommitOp, LeaderKeyRegisterOp};
use crate::chainstate::burn::{BlockSnapshot, SortitionHash};
use crate::chainstate::coordinator::{BlockEventDispatcher, Error};
use crate::chainstate::nakamoto::signer_set::NakamotoSigners;
use crate::chainstate::nakamoto::tenure::NAKAMOTO_TENURES_SCHEMA;
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::{POX_4_NAME, SIGNERS_UPDATE_STATE};
use crate::chainstate::stacks::db::{DBConfig as ChainstateConfig, StacksChainState};
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::{
    TenureChangeCause, MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use crate::clarity::vm::clarity::{ClarityConnection, TransactionConnection};
use crate::clarity_vm::clarity::{
    ClarityInstance, ClarityTransactionConnection, Error as ClarityError, PreCommitClarityBlock,
};
use crate::clarity_vm::database::SortitionDBRef;
use crate::core::BOOT_BLOCK_HASH;
use crate::net::stackerdb::{StackerDBConfig, MINER_SLOT_COUNT};
use crate::net::Error as net_error;
use crate::util_lib::boot;
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::{
    query_int, query_row, query_row_panic, query_rows, sqlite_open, tx_begin_immediate, u64_to_sql,
    DBConn, Error as DBError, FromRow,
};
use crate::{chainstate, monitoring};

pub mod coordinator;
pub mod miner;
pub mod signer_set;
pub mod staging_blocks;
pub mod tenure;
pub mod test_signers;
#[cfg(test)]
pub mod tests;

pub use self::staging_blocks::{
    NakamotoStagingBlocksConn, NakamotoStagingBlocksConnRef, NakamotoStagingBlocksTx,
};

pub const NAKAMOTO_BLOCK_VERSION: u8 = 0;

define_named_enum!(HeaderTypeNames {
    Nakamoto("nakamoto"),
    Epoch2("epoch2"),
});

impl ToSql for HeaderTypeNames {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.get_name_str().to_sql()
    }
}

impl FromSql for HeaderTypeNames {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Self::lookup_by_name(value.as_str()?).ok_or_else(|| FromSqlError::InvalidType)
    }
}

lazy_static! {
    pub static ref FIRST_STACKS_BLOCK_ID: StacksBlockId = StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);

    pub static ref NAKAMOTO_CHAINSTATE_SCHEMA_1: Vec<String> = vec![
    r#"
    -- Table for storing calculated reward sets. This must be in the Chainstate DB because calculation occurs
    --   during block processing.
    CREATE TABLE nakamoto_reward_sets (
                     index_block_hash TEXT NOT NULL,
                     reward_set TEXT NOT NULL,
                     PRIMARY KEY (index_block_hash)
    );"#.into(),
    NAKAMOTO_TENURES_SCHEMA.into(),
    r#"
      -- Table for Nakamoto block headers
      CREATE TABLE nakamoto_block_headers (
          -- The following fields all correspond to entries in the StacksHeaderInfo struct
                     block_height INTEGER NOT NULL,
                     -- root hash of the internal, not-consensus-critical MARF that allows us to track chainstate/fork metadata
                     index_root TEXT NOT NULL,
                     -- burn header hash corresponding to the consensus hash (NOT guaranteed to be unique, since we can
                     --    have 2+ blocks per burn block if there's a PoX fork)
                     burn_header_hash TEXT NOT NULL,
                     -- height of the burnchain block header that generated this consensus hash
                     burn_header_height INT NOT NULL,
                     -- timestamp from burnchain block header that generated this consensus hash
                     burn_header_timestamp INT NOT NULL,
                     -- size of this block, in bytes.
                     -- encoded as TEXT for compatibility
                     block_size TEXT NOT NULL,
          -- The following fields all correspond to entries in the NakamotoBlockHeader struct
                     version INTEGER NOT NULL,
                     -- this field is the total number of blocks in the chain history (including this block)
                     chain_length INTEGER NOT NULL,
                     -- this field is the total amount of BTC spent in the chain history (including this block)
                     burn_spent INTEGER NOT NULL,
                     -- the consensus hash of the burnchain block that selected this block's miner's block-commit
                     consensus_hash TEXT NOT NULL,
                     -- the parent StacksBlockId
                     parent_block_id TEXT NOT NULL,
                     -- Merkle root of a Merkle tree constructed out of all the block's transactions
                     tx_merkle_root TEXT NOT NULL,
                     -- root hash of the Stacks chainstate MARF
                     state_index_root TEXT NOT NULL,
                     -- miner's signature over the block
                     miner_signature TEXT NOT NULL,
                     -- signers' signature over the block
                     signer_signature TEXT NOT NULL,
                     -- bitvec capturing stacker participation in signature
                     signer_bitvec TEXT NOT NULL,
          -- The following fields are not part of either the StacksHeaderInfo struct
          --   or its contained NakamotoBlockHeader struct, but are used for querying
                     -- what kind of header this is (nakamoto or stacks 2.x)
                     header_type TEXT NOT NULL,
                     -- hash of the block
                     block_hash TEXT NOT NULL,
                     -- index_block_hash is the hash of the block hash and consensus hash of the burn block that selected it,
                     -- and is guaranteed to be globally unique (across all Stacks forks and across all PoX forks).
                     -- index_block_hash is the block hash fed into the MARF index.
                     index_block_hash TEXT NOT NULL,
                     -- the ExecutionCost of the block
                     cost TEXT NOT NULL,
                     -- the total cost up to and including this block in the current tenure
                     total_tenure_cost TEXT NOT NULL,
                     -- this field is true if this is the first block of a new tenure
                     tenure_changed INTEGER NOT NULL,
                     -- this field tracks the total tx fees so far in this tenure. it is a text-serialized u128
                     tenure_tx_fees TEXT NOT NULL,
                     -- nakamoto block's VRF proof, if this is a tenure-start block
                     vrf_proof TEXT,

              PRIMARY KEY(consensus_hash,block_hash)
          );
          CREATE INDEX nakamoto_block_headers_by_consensus_hash ON nakamoto_block_headers(consensus_hash);
    "#.into(),
        format!(
            r#"ALTER TABLE payments
               ADD COLUMN schedule_type TEXT NOT NULL DEFAULT "{}";
            "#,
            HeaderTypeNames::Epoch2.get_name_str()),
        r#"
        UPDATE db_config SET version = "4";
        "#.into(),
    ];
}

/// Matured miner reward schedules
#[derive(Debug, Clone)]
pub struct MaturedMinerPaymentSchedules {
    /// miners whose rewards matured
    pub latest_miners: Vec<MinerPaymentSchedule>,
    /// parent to be paid (epoch2 only)
    pub parent_miner: MinerPaymentSchedule,
}

impl MaturedMinerPaymentSchedules {
    pub fn genesis(mainnet: bool) -> Self {
        Self {
            latest_miners: vec![],
            parent_miner: MinerPaymentSchedule::genesis(mainnet),
        }
    }
}

/// Calculated matured miner rewards, from scheduled rewards
#[derive(Debug, Clone)]
pub struct MaturedMinerRewards {
    /// this block's reward recipient
    /// NOTE: in epoch2, if a PoisonMicroblock report was successful, then the recipient is the
    /// reporter, not the miner.
    pub recipient: MinerReward,
    /// the parent block's reward.
    /// this is all of the fees they accumulated during their tenure.
    pub parent_reward: MinerReward,
    /// metadata about the block miner's reward
    pub reward_info: MinerRewardInfo,
}

impl MaturedMinerRewards {
    /// Get the list of miner rewards this struct represents
    pub fn consolidate(&self) -> Vec<MinerReward> {
        vec![self.recipient.clone(), self.parent_reward.clone()]
    }
}

/// Result of preparing to produce or validate a block
pub struct SetupBlockResult<'a, 'b> {
    /// Handle to the ClarityVM
    pub clarity_tx: ClarityTx<'a, 'b>,
    /// Transaction receipts from any Stacks-on-Bitcoin transactions and epoch transition events
    pub tx_receipts: Vec<StacksTransactionReceipt>,
    /// Miner rewards that can be paid now
    pub matured_miner_rewards_opt: Option<MaturedMinerRewards>,
    /// Epoch in which this block was set up
    pub evaluated_epoch: StacksEpochId,
    /// Whether or not we applied an epoch transition in this block
    pub applied_epoch_transition: bool,
    /// stack-stx Stacks-on-Bitcoin txs
    pub burn_stack_stx_ops: Vec<StackStxOp>,
    /// transfer-stx Stacks-on-Bitcoin txs
    pub burn_transfer_stx_ops: Vec<TransferStxOp>,
    /// delegate-stx Stacks-on-Bitcoin txs
    pub burn_delegate_stx_ops: Vec<DelegateStxOp>,
    /// STX auto-unlock events from PoX
    pub auto_unlock_events: Vec<StacksTransactionEvent>,
    /// Result of a signer set calculation if one occurred
    pub signer_set_calc: Option<SignerCalculation>,
    /// vote-for-aggregate-key Stacks-on-Bitcoin txs
    pub burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoBlockHeader {
    pub version: u8,
    /// The total number of StacksBlock and NakamotoBlocks preceding
    /// this block in this block's history.
    pub chain_length: u64,
    /// Total amount of BTC spent producing the sortition that
    /// selected this block's miner.
    pub burn_spent: u64,
    /// The consensus hash of the burnchain block that selected this tenure.  The consensus hash
    /// uniquely identifies this tenure, including across all Bitcoin forks.
    pub consensus_hash: ConsensusHash,
    /// The index block hash of the immediate parent of this block.
    /// This is the hash of the parent block's hash and consensus hash.
    pub parent_block_id: StacksBlockId,
    /// The root of a SHA512/256 merkle tree over all this block's
    /// contained transactions
    pub tx_merkle_root: Sha512Trunc256Sum,
    /// The MARF trie root hash after this block has been processed
    pub state_index_root: TrieHash,
    /// Recoverable ECDSA signature from the tenure's miner.
    pub miner_signature: MessageSignature,
    /// Schnorr signature over the block header from the signer set active during the tenure.
    pub signer_signature: ThresholdSignature,
    /// A bitvec which represents the signers that participated in this block signature.
    /// The maximum number of entries in the bitvec is 4000.
    pub signer_bitvec: BitVec<4000>,
}

impl FromRow<NakamotoBlockHeader> for NakamotoBlockHeader {
    fn from_row(row: &rusqlite::Row) -> Result<NakamotoBlockHeader, DBError> {
        let version = row.get("version")?;
        let chain_length_i64: i64 = row.get("chain_length")?;
        let chain_length = chain_length_i64
            .try_into()
            .map_err(|_| DBError::ParseError)?;
        let burn_spent_i64: i64 = row.get("burn_spent")?;
        let burn_spent = burn_spent_i64.try_into().map_err(|_| DBError::ParseError)?;
        let consensus_hash = row.get("consensus_hash")?;
        let parent_block_id = row.get("parent_block_id")?;
        let tx_merkle_root = row.get("tx_merkle_root")?;
        let state_index_root = row.get("state_index_root")?;
        let signer_signature = row.get("signer_signature")?;
        let miner_signature = row.get("miner_signature")?;
        let signer_bitvec = row.get("signer_bitvec")?;

        Ok(NakamotoBlockHeader {
            version,
            chain_length,
            burn_spent,
            consensus_hash,
            parent_block_id,
            tx_merkle_root,
            state_index_root,
            signer_signature,
            miner_signature,
            signer_bitvec,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// A vote across the signer set for a block
pub struct NakamotoBlockVote {
    pub signer_signature_hash: Sha512Trunc256Sum,
    pub rejected: bool,
}

impl StacksMessageCodec for NakamotoBlockVote {
    fn consensus_serialize<W: std::io::Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.signer_signature_hash)?;
        if self.rejected {
            write_next(fd, &1u8)?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: std::io::Read>(fd: &mut R) -> Result<Self, CodecError> {
        let signer_signature_hash = read_next(fd)?;
        let rejected_byte: Option<u8> = read_next(fd).ok();
        let rejected = rejected_byte.is_some();
        Ok(Self {
            signer_signature_hash,
            rejected,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoBlock {
    pub header: NakamotoBlockHeader,
    pub txs: Vec<StacksTransaction>,
}

pub struct NakamotoChainState;

impl StacksMessageCodec for NakamotoBlockHeader {
    fn consensus_serialize<W: std::io::Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.version)?;
        write_next(fd, &self.chain_length)?;
        write_next(fd, &self.burn_spent)?;
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.parent_block_id)?;
        write_next(fd, &self.tx_merkle_root)?;
        write_next(fd, &self.state_index_root)?;
        write_next(fd, &self.miner_signature)?;
        write_next(fd, &self.signer_signature)?;
        write_next(fd, &self.signer_bitvec)?;

        Ok(())
    }

    fn consensus_deserialize<R: std::io::Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(NakamotoBlockHeader {
            version: read_next(fd)?,
            chain_length: read_next(fd)?,
            burn_spent: read_next(fd)?,
            consensus_hash: read_next(fd)?,
            parent_block_id: read_next(fd)?,
            tx_merkle_root: read_next(fd)?,
            state_index_root: read_next(fd)?,
            miner_signature: read_next(fd)?,
            signer_signature: read_next(fd)?,
            signer_bitvec: read_next(fd)?,
        })
    }
}

impl NakamotoBlockHeader {
    /// Calculate the message digest for miners to sign.
    /// This includes all fields _except_ the signatures.
    pub fn miner_signature_hash(&self) -> Sha512Trunc256Sum {
        self.miner_signature_hash_inner()
            .expect("BUG: failed to calculate miner signature hash")
    }

    /// Calculate the message digest for signers to sign.
    /// This includes all fields _except_ the signer signature.
    pub fn signer_signature_hash(&self) -> Sha512Trunc256Sum {
        self.signer_signature_hash_inner()
            .expect("BUG: failed to calculate signer signature hash")
    }

    /// Inner calculation of the message digest for miners to sign.
    /// This includes all fields _except_ the signatures.
    fn miner_signature_hash_inner(&self) -> Result<Sha512Trunc256Sum, CodecError> {
        let mut hasher = Sha512_256::new();
        let fd = &mut hasher;
        write_next(fd, &self.version)?;
        write_next(fd, &self.chain_length)?;
        write_next(fd, &self.burn_spent)?;
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.parent_block_id)?;
        write_next(fd, &self.tx_merkle_root)?;
        write_next(fd, &self.state_index_root)?;
        Ok(Sha512Trunc256Sum::from_hasher(hasher))
    }

    /// Inner calculation of the message digest for stackers to sign.
    /// This includes all fields _except_ the stacker signature.
    fn signer_signature_hash_inner(&self) -> Result<Sha512Trunc256Sum, CodecError> {
        let mut hasher = Sha512_256::new();
        let fd = &mut hasher;
        write_next(fd, &self.version)?;
        write_next(fd, &self.chain_length)?;
        write_next(fd, &self.burn_spent)?;
        write_next(fd, &self.consensus_hash)?;
        write_next(fd, &self.parent_block_id)?;
        write_next(fd, &self.tx_merkle_root)?;
        write_next(fd, &self.state_index_root)?;
        write_next(fd, &self.miner_signature)?;
        write_next(fd, &self.signer_bitvec)?;
        Ok(Sha512Trunc256Sum::from_hasher(hasher))
    }

    pub fn recover_miner_pk(&self) -> Option<StacksPublicKey> {
        let signed_hash = self.miner_signature_hash();
        let recovered_pk =
            StacksPublicKey::recover_to_pubkey(signed_hash.bits(), &self.miner_signature).ok()?;

        Some(recovered_pk)
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        BlockHeaderHash::from_serializer(self)
            .expect("BUG: failed to serialize block header hash struct")
    }

    pub fn block_id(&self) -> StacksBlockId {
        StacksBlockId::new(&self.consensus_hash, &self.block_hash())
    }

    pub fn is_first_mined(&self) -> bool {
        self.parent_block_id == StacksBlockId::first_mined()
    }

    /// Sign the block header by the miner
    pub fn sign_miner(&mut self, privk: &StacksPrivateKey) -> Result<(), ChainstateError> {
        let sighash = self.miner_signature_hash().0;
        let sig = privk
            .sign(&sighash)
            .map_err(|se| net_error::SigningError(se.to_string()))?;
        self.miner_signature = sig;
        Ok(())
    }

    /// Verify the block header against an aggregate public key
    pub fn verify_signer(&self, signer_aggregate: &Point) -> bool {
        let schnorr_signature = &self.signer_signature.0;
        let message = self.signer_signature_hash().0;
        schnorr_signature.verify(signer_aggregate, &message)
    }

    /// Make an "empty" header whose block data needs to be filled in.
    /// This is used by the miner code.
    pub fn from_parent_empty(
        chain_length: u64,
        burn_spent: u64,
        consensus_hash: ConsensusHash,
        parent_block_id: StacksBlockId,
        bitvec_len: u16,
    ) -> NakamotoBlockHeader {
        NakamotoBlockHeader {
            version: NAKAMOTO_BLOCK_VERSION,
            chain_length,
            burn_spent,
            consensus_hash,
            parent_block_id,
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            state_index_root: TrieHash([0u8; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: ThresholdSignature::empty(),
            signer_bitvec: BitVec::ones(bitvec_len)
                .expect("BUG: bitvec of length-1 failed to construct"),
        }
    }

    /// Make a completely empty header
    pub fn empty() -> NakamotoBlockHeader {
        NakamotoBlockHeader {
            version: 0,
            chain_length: 0,
            burn_spent: 0,
            consensus_hash: ConsensusHash([0u8; 20]),
            parent_block_id: StacksBlockId([0u8; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            state_index_root: TrieHash([0u8; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: ThresholdSignature::empty(),
            signer_bitvec: BitVec::zeros(1).expect("BUG: bitvec of length-1 failed to construct"),
        }
    }

    /// Make a genesis header (testing only)
    pub fn genesis() -> NakamotoBlockHeader {
        NakamotoBlockHeader {
            version: 0,
            chain_length: 0,
            burn_spent: 0,
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            parent_block_id: StacksBlockId(BOOT_BLOCK_HASH.0.clone()),
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            state_index_root: TrieHash([0u8; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: ThresholdSignature::empty(),
            signer_bitvec: BitVec::zeros(1).expect("BUG: bitvec of length-1 failed to construct"),
        }
    }
}

impl NakamotoBlock {
    /// Find all positionally-valid tenure changes in this block.
    /// They must be the first transactions.
    /// Return their indexes into self.txs
    fn find_tenure_changes(&self) -> Vec<usize> {
        let mut ret = vec![];
        for (i, tx) in self.txs.iter().enumerate() {
            if let TransactionPayload::TenureChange(..) = &tx.payload {
                ret.push(i);
            } else {
                break;
            }
        }
        ret
    }

    pub fn is_first_mined(&self) -> bool {
        self.header.is_first_mined()
    }

    /// Get the tenure-change transaction in Nakamoto.
    /// If it's present, then it's the first transaction (i.e. tx 0).
    /// NOTE: this does _not_ return a tenure-extend transaction payload.
    pub fn get_tenure_change_tx_payload(&self) -> Option<&TenureChangePayload> {
        if self.is_wellformed_tenure_start_block() != Ok(true) {
            // no tenure-change, or invalid
            return None;
        }

        // if it exists, it's the first
        self.txs.get(0).and_then(|tx| {
            if let TransactionPayload::TenureChange(ref tc) = &tx.payload {
                Some(tc)
            } else {
                None
            }
        })
    }

    /// Get the tenure-extend transaction in Nakamoto.
    /// If it's present, then it's the first transaction (i.e. tx 0)
    /// NOTE: this does _not_ return a tenure-change transaction payload.
    pub fn get_tenure_extend_tx_payload(&self) -> Option<&TenureChangePayload> {
        if self.is_wellformed_tenure_extend_block() != Ok(true) {
            // no tenure-extend, or invalid
            return None;
        }

        // if it exists, it's the first
        self.txs.get(0).and_then(|tx| {
            if let TransactionPayload::TenureChange(ref tc) = &tx.payload {
                Some(tc)
            } else {
                None
            }
        })
    }

    /// Get the tenure-change or tenure-extend transaction in Nakamoto, if it exists.
    /// At most one will exist.
    pub fn get_tenure_tx_payload(&self) -> Option<&TenureChangePayload> {
        if let Some(payload) = self.get_tenure_change_tx_payload() {
            return Some(payload);
        }
        if let Some(payload) = self.get_tenure_extend_tx_payload() {
            return Some(payload);
        }
        return None;
    }

    /// Get the coinbase transaction in Nakamoto.
    /// It's the first non-TenureChange transaction (i.e. tx 1)
    pub fn get_coinbase_tx(&self) -> Option<&StacksTransaction> {
        if self.is_wellformed_tenure_start_block() != Ok(true) {
            // not a tenure-change block, or invalid
            return None;
        }

        // there is one coinbase.
        // go find it.
        self.txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::Coinbase(..)))
    }

    /// Get the VRF proof from this block.
    /// It's Some(..) only if there's a coinbase
    pub fn get_vrf_proof(&self) -> Option<&VRFProof> {
        self.get_coinbase_tx()
            .map(|coinbase_tx| {
                if let TransactionPayload::Coinbase(_, _, vrf_proof) = &coinbase_tx.payload {
                    vrf_proof.as_ref()
                } else {
                    // actually unreachable
                    None
                }
            })
            .flatten()
    }

    /// Try to get the first transaction in the block as a tenure-change
    /// Return Some(tenure-change-payload) if it's a tenure change
    /// Return None if not
    pub fn try_get_tenure_change_payload(&self) -> Option<&TenureChangePayload> {
        if self.txs.len() == 0 {
            return None;
        }
        if let TransactionPayload::TenureChange(ref tc) = &self.txs[0].payload {
            Some(tc)
        } else {
            None
        }
    }

    /// Determine if this is a well-formed tenure-extend block.
    /// * It has exactly one TenureChange, and it does _not_ require a sortiton (it's `cause` is
    /// `Extended`)
    /// * Its consensus hash and previous consensus hash values point to this block.
    /// * There is no coinbase
    /// * There are no other TenureChange transactions
    ///
    /// Returns Ok(true) if the above are true
    /// Returns Ok(false) if it is not a tenure-extend block
    /// Returns Err(()) if this block cannot be a valid block
    pub fn is_wellformed_tenure_extend_block(&self) -> Result<bool, ()> {
        // find coinbases
        let has_coinbase = self
            .txs
            .iter()
            .find(|tx| matches!(&tx.payload, TransactionPayload::Coinbase(..)))
            .is_some();

        if has_coinbase {
            // can't be
            return Ok(false);
        }

        // find all tenure changes, even if they're not sortition-induced
        let tenure_change_positions = self
            .txs
            .iter()
            .enumerate()
            .filter_map(|(i, tx)| {
                if let TransactionPayload::TenureChange(..) = &tx.payload {
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if tenure_change_positions.len() == 0 {
            return Ok(false);
        }

        if tenure_change_positions.len() > 1 {
            // invalid
            warn!(
                "Invalid block -- {} tenure txs",
                tenure_change_positions.len()
            );
            return Err(());
        }

        let Some(tc_payload) = self.try_get_tenure_change_payload() else {
            warn!("Invalid block -- tx at index 0 is not a tenure tx",);
            return Err(());
        };
        if tc_payload.cause != TenureChangeCause::Extended {
            // not a tenure-extend, and can't be valid since all other tenure-change types require
            // a coinbase (which is not present)
            warn!("Invalid block -- tenure tx cause is not an extension");
            return Err(());
        }

        if tc_payload.previous_tenure_end != self.header.parent_block_id {
            // discontinuous
            warn!(
                "Invalid block -- discontiguous";
                "previosu_tenure_end" => %tc_payload.previous_tenure_end,
                "parent_block_id" => %self.header.parent_block_id
            );
            return Err(());
        }

        if tc_payload.tenure_consensus_hash != self.header.consensus_hash
            || tc_payload.prev_tenure_consensus_hash != self.header.consensus_hash
        {
            // tenure-extends don't change the current miner
            warn!(
                "Invalid block -- tenure extend tx must have the same consensus hash and previous consensus hash as the block header";
                "tenure_consensus_hash" => %tc_payload.tenure_consensus_hash,
                "prev_tenure_consensus_hash" => %tc_payload.prev_tenure_consensus_hash,
                "consensus_hash" => %self.header.consensus_hash,
            );
            return Err(());
        }

        Ok(true)
    }

    /// Determine if this is a well-formed first block in a tenure.
    /// * It has exactly one TenureChange, and it requires a sortition and points to the parent of
    /// this block (this checks `cause` and `previous_tenure_end`)
    /// * It then has a Nakamoto coinbase
    /// * Coinbases and TenureChanges do not occur anywhere else
    ///
    /// Returns Ok(true) if the above are true
    /// Returns Ok(false) if this is not a tenure-start block
    /// Returns Err(()) if this block cannot be a valid block
    pub fn is_wellformed_tenure_start_block(&self) -> Result<bool, ()> {
        // sanity check -- this may contain no coinbases or tenure-changes
        let coinbase_positions = self
            .txs
            .iter()
            .enumerate()
            .filter_map(|(i, tx)| {
                if let TransactionPayload::Coinbase(..) = &tx.payload {
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // find all tenure changes, even if they're not sortition-induced
        let tenure_change_positions = self
            .txs
            .iter()
            .enumerate()
            .filter_map(|(i, tx)| {
                if let TransactionPayload::TenureChange(..) = &tx.payload {
                    Some(i)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if coinbase_positions.len() == 0 && tenure_change_positions.len() == 0 {
            // can't be a first block in a tenure
            return Ok(false);
        }

        if coinbase_positions.len() > 1 || tenure_change_positions.len() > 1 {
            // never valid to have more than one of each
            warn!(
                "Invalid block -- have {} coinbases and {} tenure txs",
                coinbase_positions.len(),
                tenure_change_positions.len()
            );
            return Err(());
        }

        if coinbase_positions.len() == 1 && tenure_change_positions.len() == 0 {
            // coinbase unaccompanied by a tenure change
            warn!("Invalid block -- have coinbase without tenure change");
            return Err(());
        }

        if coinbase_positions.len() == 0 && tenure_change_positions.len() == 1 {
            // this is possibly a block with a tenure-extend transaction.
            // It must be the first tx
            if tenure_change_positions[0] != 0 {
                // wrong position
                warn!(
                    "Invalid block -- tenure change positions = {:?}, expected [0]",
                    &tenure_change_positions,
                );
                return Err(());
            }

            // must be a non-sortition-triggered tenure change
            let TransactionPayload::TenureChange(tc_payload) = &self.txs[0].payload else {
                // this transaction is not a tenure change
                // (should be unreachable)
                warn!("Invalid block -- first transaction is not a tenure change");
                return Err(());
            };

            if tc_payload.cause.expects_sortition() {
                // not valid
                warn!("Invalid block -- no coinbase, but tenure change expects sortition");
                return Err(());
            }

            // not a tenure-start block, but syntactically valid w.r.t. tenure changes
            return Ok(false);
        }

        // have both a coinbase and a tenure-change
        let coinbase_idx = 1;
        let tc_idx = 0;
        if coinbase_positions[0] != coinbase_idx && tenure_change_positions[0] != tc_idx {
            // invalid -- expect exactly one sortition-induced tenure change and exactly one coinbase expected,
            // and the tenure change must be the first transaction and the coinbase must be the second transaction
            warn!("Invalid block -- coinbase and/or tenure change txs are in the wrong position -- ({:?}, {:?}) != [{}], [{}]", &coinbase_positions, &tenure_change_positions, coinbase_idx, tc_idx);
            return Err(());
        }
        let Some(tc_payload) = self.try_get_tenure_change_payload() else {
            warn!("Invalid block -- tx at index 0 is not a tenure tx",);
            return Err(());
        };
        if !tc_payload.cause.expects_sortition() {
            // the only tenure change allowed in a block with a coinbase is a sortition-triggered
            // tenure change
            warn!("Invalid block -- tenure change does not expect a sortition");
            return Err(());
        }
        if tc_payload.previous_tenure_end != self.header.parent_block_id {
            // discontinuous
            warn!(
                "Invalid block -- discontiguous -- {} != {}",
                &tc_payload.previous_tenure_end, &self.header.parent_block_id
            );
            return Err(());
        }

        // must be a Nakamoto coinbase
        let TransactionPayload::Coinbase(_, _, vrf_proof_opt) = &self.txs[coinbase_idx].payload
        else {
            // this transaction is not a coinbase (but this should be unreachable)
            warn!(
                "Invalid block -- tx index {} is not a coinbase",
                coinbase_idx
            );
            return Err(());
        };
        if vrf_proof_opt.is_none() {
            // not a Nakamoto coinbase
            warn!("Invalid block -- no VRF proof in coinbase");
            return Err(());
        }

        return Ok(true);
    }

    /// Verify that the VRF seed of this block's block-commit is the hash of the parent tenure's
    /// VRF seed.
    pub fn validate_vrf_seed(
        &self,
        sortdb_conn: &Connection,
        chainstate_conn: &Connection,
        block_commit: &LeaderBlockCommitOp,
    ) -> Result<(), ChainstateError> {
        // the block-commit from the miner who created this coinbase must have a VRF seed that
        // is the hash of the parent tenure's VRF proof.
        let parent_vrf_proof = NakamotoChainState::get_parent_vrf_proof(
            chainstate_conn,
            sortdb_conn,
            &self.header.consensus_hash,
            &block_commit.txid,
        )?;
        if !block_commit.new_seed.is_from_proof(&parent_vrf_proof) {
            warn!("Invalid Nakamoto block-commit: seed does not match parent VRF proof";
                  "block_id" => %self.block_id(),
                  "commit_seed" => %block_commit.new_seed,
                  "proof_seed" => %VRFSeed::from_proof(&parent_vrf_proof),
                  "parent_vrf_proof" => %parent_vrf_proof.to_hex(),
                  "block_commit" => format!("{:?}", &block_commit)
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: bad VRF proof".into(),
            ));
        }
        Ok(())
    }

    pub fn block_id(&self) -> StacksBlockId {
        self.header.block_id()
    }

    /// Get the miner's public key hash160 from this signature
    pub(crate) fn recover_miner_pubkh(&self) -> Result<Hash160, ChainstateError> {
        let recovered_miner_pubk = self.header.recover_miner_pk().ok_or_else(|| {
            warn!(
                "Nakamoto Stacks block downloaded with unrecoverable miner public key";
                "block_hash" => %self.header.block_hash(),
                "block_id" => %self.header.block_id(),
            );
            return ChainstateError::InvalidStacksBlock("Unrecoverable miner public key".into());
        })?;

        let recovered_miner_hash160 = Hash160::from_node_public_key(&recovered_miner_pubk);
        Ok(recovered_miner_hash160)
    }

    /// Verify the miner signature over this block.
    pub(crate) fn check_miner_signature(
        &self,
        miner_pubkey_hash160: &Hash160,
    ) -> Result<(), ChainstateError> {
        let recovered_miner_hash160 = self.recover_miner_pubkh()?;
        if &recovered_miner_hash160 != miner_pubkey_hash160 {
            warn!(
                "Nakamoto Stacks block signature mismatch: {recovered_miner_hash160} != {miner_pubkey_hash160} from leader-key";
                "block_hash" => %self.header.block_hash(),
                "block_id" => %self.header.block_id(),
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid miner signature".into(),
            ));
        }

        Ok(())
    }

    /// Verify that if this block has a tenure-change, that it is consistent with our header's
    /// consensus_hash and miner_signature.  If there is no tenure change tx in this block, then
    /// this is a no-op.
    ///
    /// This check applies to both tenure-changes and tenure-extends
    pub(crate) fn check_tenure_tx(&self) -> Result<(), ChainstateError> {
        // If this block has a tenure-change, then verify that the miner public key is the same as
        // the leader key.  This is required for all tenure-change causes.
        let Some(tc_payload) = self.get_tenure_tx_payload() else {
            return Ok(());
        };

        // in all cases, the miner public key must match that of the tenure change
        let recovered_miner_hash160 = self.recover_miner_pubkh()?;
        if tc_payload.pubkey_hash != recovered_miner_hash160 {
            warn!(
                "Invalid tenure-change transaction -- bad miner pubkey hash160";
                "block_hash" => %self.header.block_hash(),
                "block_id" => %self.header.block_id(),
                "pubkey_hash" => %tc_payload.pubkey_hash,
                "recovered_miner_hash160" => %recovered_miner_hash160
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid tenure change -- bad miner pubkey hash160".into(),
            ));
        }

        // in all cases, the tenure change's consensus hash must match the block's consensus
        // hash
        if tc_payload.tenure_consensus_hash != self.header.consensus_hash {
            warn!(
                "Invalid tenure-change transaction -- bad consensus hash";
                "block_hash" => %self.header.block_hash(),
                "block_id" => %self.header.block_id(),
                "consensus_hash" => %self.header.consensus_hash,
                "tc_payload.tenure_consensus_hash" => %tc_payload.tenure_consensus_hash
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid tenure change -- bad consensus hash".into(),
            ));
        }

        Ok(())
    }

    /// Verify that if this block has a coinbase, that its VRF proof is consistent with the leader
    /// public key's VRF key. If there is no coinbase tx, then this is a no-op.
    pub(crate) fn check_coinbase_tx(
        &self,
        leader_vrf_key: &VRFPublicKey,
        sortition_hash: &SortitionHash,
    ) -> Result<(), ChainstateError> {
        // If this block has a coinbase, then verify that its VRF proof was generated by this
        // block's miner.  We'll verify that the seed of this block-commit was generated from the
        // parnet tenure's VRF proof via the `validate_vrf_seed()` method, which requires that we
        // already have the parent block.
        if let Some(coinbase_tx) = self.get_coinbase_tx() {
            let (_, _, vrf_proof_opt) = coinbase_tx
                .try_as_coinbase()
                .expect("FATAL: `get_coinbase_tx()` did not return a coinbase");
            let vrf_proof = vrf_proof_opt.ok_or(ChainstateError::InvalidStacksBlock(
                "Nakamoto coinbase must have a VRF proof".into(),
            ))?;

            // this block's VRF proof must have ben generated from the last sortition's sortition
            // hash (which includes the last commit's VRF seed)
            let valid = match VRF::verify(leader_vrf_key, vrf_proof, sortition_hash.as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "Invalid Stacks block header {}: failed to verify VRF proof: {}",
                        self.header.block_hash(),
                        e
                    );
                    false
                }
            };

            if !valid {
                warn!("Invalid Nakamoto block: leader VRF key did not produce a valid proof";
                      "block_id" => %self.block_id(),
                      "leader_public_key" => %leader_vrf_key.to_hex(),
                      "sortition_hash" => %sortition_hash
                );
                return Err(ChainstateError::InvalidStacksBlock(
                    "Invalid Nakamoto block: leader VRF key did not produce a valid proof".into(),
                ));
            }
        }
        Ok(())
    }

    /// Validate this Nakamoto block header against burnchain state.
    /// Used to determine whether or not we'll keep a block around (even if we don't yet have its parent).
    ///
    /// Arguments
    /// -- `tenure_burn_chain_tip` is the BlockSnapshot containing the block-commit for this block's
    /// tenure.  It is not always the tip of the burnchain.
    /// -- `expected_burn` is the total number of burnchain tokens spent, if known.
    /// -- `leader_key` is the miner's leader key registration transaction
    ///
    /// Verifies the following:
    /// -- (self.header.consensus_hash) that this block falls into this block-commit's tenure
    /// -- (self.header.burn_spent) that this block's burn total matches `burn_tip`'s total burn
    /// -- (self.header.miner_signature) that this miner signed this block
    /// -- if this block has a tenure change, then it's consistent with the miner's public key and
    /// self.header.consensus_hash
    /// -- if this block has a coinbase, then that it's VRF proof was generated by this miner
    pub fn validate_against_burnchain(
        &self,
        tenure_burn_chain_tip: &BlockSnapshot,
        expected_burn: Option<u64>,
        leader_key: &LeaderKeyRegisterOp,
    ) -> Result<(), ChainstateError> {
        // this block's consensus hash must match the sortition that selected it
        if tenure_burn_chain_tip.consensus_hash != self.header.consensus_hash {
            warn!("Invalid Nakamoto block: consensus hash does not match sortition";
                  "consensus_hash" => %self.header.consensus_hash,
                  "sortition.consensus_hash" => %tenure_burn_chain_tip.consensus_hash
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: invalid consensus hash".into(),
            ));
        }

        // this block must commit to all of the work seen so far
        if let Some(expected_burn) = expected_burn {
            if self.header.burn_spent != expected_burn {
                warn!("Invalid Nakamoto block header: invalid total burns";
                      "header.burn_spent" => self.header.burn_spent,
                      "expected_burn" => expected_burn,
                );
                return Err(ChainstateError::InvalidStacksBlock(
                    "Invalid Nakamoto block: invalid total burns".into(),
                ));
            }
        }

        // miner must have signed this block
        let miner_pubkey_hash160 = leader_key
            .interpret_nakamoto_signing_key()
            .ok_or(ChainstateError::NoSuchBlockError)
            .map_err(|e| {
                warn!(
                    "Leader key did not contain a hash160 of the miner signing public key";
                    "leader_key" => ?leader_key,
                );
                e
            })?;

        self.check_miner_signature(&miner_pubkey_hash160)?;
        self.check_tenure_tx()?;
        self.check_coinbase_tx(
            &leader_key.public_key,
            &tenure_burn_chain_tip.sortition_hash,
        )?;

        // not verified by this method:
        // * chain_length       (need parent block header)
        // * parent_block_id    (need parent block header)
        // * block-commit seed  (need parent block)
        // * tx_merkle_root     (already verified; validated on deserialization)
        // * state_index_root   (validated on process_block())
        // * stacker signature  (validated on accept_block())
        Ok(())
    }

    /// Static sanity checks on transactions.
    /// Verifies:
    /// * the block is non-empty
    /// * that all txs are unique
    /// * that all txs use the given network
    /// * that all txs use the given chain ID
    /// * if this is a tenure-start tx, that:
    ///    * it has a well-formed coinbase
    ///    * it has a sortition-induced tenure change transaction
    /// * that only epoch-permitted transactions are present
    pub fn validate_transactions_static(
        &self,
        mainnet: bool,
        chain_id: u32,
        epoch_id: StacksEpochId,
    ) -> bool {
        if self.txs.is_empty() {
            return false;
        }
        if !StacksBlock::validate_transactions_unique(&self.txs) {
            return false;
        }
        if !StacksBlock::validate_transactions_network(&self.txs, mainnet) {
            return false;
        }
        if !StacksBlock::validate_transactions_chain_id(&self.txs, chain_id) {
            return false;
        }
        let valid_tenure_start = self.is_wellformed_tenure_start_block();
        if valid_tenure_start == Ok(true) {
            if self.get_coinbase_tx().is_none() {
                return false;
            }
            if self.get_tenure_change_tx_payload().is_none() {
                return false;
            }
        } else if valid_tenure_start.is_err() {
            // bad tenure change
            warn!("Not a well-formed tenure-start block");
            return false;
        }
        let valid_tenure_extend = self.is_wellformed_tenure_extend_block();
        if valid_tenure_extend == Ok(true) {
            if self.get_tenure_extend_tx_payload().is_none() {
                return false;
            }
        } else if valid_tenure_extend.is_err() {
            // bad tenure extend
            warn!("Not a well-formed tenure-extend block");
            return false;
        }
        if !StacksBlock::validate_transactions_static_epoch(&self.txs, epoch_id) {
            return false;
        }
        return true;
    }
}

impl NakamotoChainState {
    /// Infallibly set a block as processed.
    /// Does not return until it succeeds.
    fn infallible_set_block_processed(
        stacks_chain_state: &mut StacksChainState,
        block_id: &StacksBlockId,
    ) {
        loop {
            let Ok(staging_block_tx) = stacks_chain_state.staging_db_tx_begin().map_err(|e| {
                warn!("Failed to begin staging DB tx: {:?}", &e);
                e
            }) else {
                sleep_ms(1000);
                continue;
            };

            let Ok(_) = staging_block_tx.set_block_processed(block_id).map_err(|e| {
                warn!("Failed to mark {} as processed: {:?}", block_id, &e);
                e
            }) else {
                sleep_ms(1000);
                continue;
            };

            let Ok(_) = staging_block_tx.commit().map_err(|e| {
                warn!(
                    "Failed to commit staging block tx for {}: {:?}",
                    block_id, &e
                );
                e
            }) else {
                sleep_ms(1000);
                continue;
            };

            break;
        }
    }

    /// Infallibly set a block as orphaned.
    /// Does not return until it succeeds.
    fn infallible_set_block_orphaned(
        stacks_chain_state: &mut StacksChainState,
        block_id: &StacksBlockId,
    ) {
        loop {
            let Ok(staging_block_tx) = stacks_chain_state.staging_db_tx_begin().map_err(|e| {
                warn!("Failed to begin staging DB tx: {:?}", &e);
                e
            }) else {
                sleep_ms(1000);
                continue;
            };

            let Ok(_) = staging_block_tx.set_block_orphaned(&block_id).map_err(|e| {
                warn!("Failed to mark {} as orphaned: {:?}", &block_id, &e);
                e
            }) else {
                sleep_ms(1000);
                continue;
            };

            let Ok(_) = staging_block_tx.commit().map_err(|e| {
                warn!(
                    "Failed to commit staging block tx for {}: {:?}",
                    &block_id, &e
                );
                e
            }) else {
                sleep_ms(1000);
                continue;
            };

            break;
        }
    }

    /// Process the next ready block.
    /// If there exists a ready Nakamoto block, then this method returns Ok(Some(..)) with the
    /// receipt.  Otherwise, it returns Ok(None).
    ///
    /// It returns Err(..) on DB error, or if the child block does not connect to the parent.
    /// The caller should keep calling this until it gets Ok(None)
    pub fn process_next_nakamoto_block<'a, T: BlockEventDispatcher>(
        stacks_chain_state: &mut StacksChainState,
        sort_tx: &mut SortitionHandleTx,
        dispatcher_opt: Option<&'a T>,
    ) -> Result<Option<StacksEpochReceipt>, ChainstateError> {
        let nakamoto_blocks_db = stacks_chain_state.nakamoto_blocks_db();
        let Some((next_ready_block, block_size)) =
            nakamoto_blocks_db.next_ready_nakamoto_block(stacks_chain_state.db(), sort_tx)?
        else {
            // no more blocks
            test_debug!("No more Nakamoto blocks to process");
            return Ok(None);
        };

        let block_id = next_ready_block.block_id();

        // find corresponding snapshot
        let next_ready_block_snapshot = SortitionDB::get_block_snapshot_consensus(
            sort_tx,
            &next_ready_block.header.consensus_hash,
        )?
        .unwrap_or_else(|| {
            panic!(
                "CORRUPTION: staging Nakamoto block {}/{} does not correspond to a burn block",
                &next_ready_block.header.consensus_hash,
                &next_ready_block.header.block_hash()
            )
        });

        debug!("Process staging Nakamoto block";
               "consensus_hash" => %next_ready_block.header.consensus_hash,
               "block_hash" => %next_ready_block.header.block_hash(),
               "burn_block_hash" => %next_ready_block_snapshot.burn_header_hash
        );

        let (mut chainstate_tx, clarity_instance) = stacks_chain_state.chainstate_tx_begin()?;

        // find parent header
        let Some(parent_header_info) =
            Self::get_block_header(&chainstate_tx.tx, &next_ready_block.header.parent_block_id)?
        else {
            // no parent; cannot process yet
            debug!("Cannot process Nakamoto block: missing parent header";
                   "consensus_hash" => %next_ready_block.header.consensus_hash,
                   "block_hash" => %next_ready_block.header.block_hash(),
                   "parent_block_id" => %next_ready_block.header.parent_block_id
            );
            return Ok(None);
        };

        // sanity check -- must attach to parent
        let parent_block_id = StacksBlockId::new(
            &parent_header_info.consensus_hash,
            &parent_header_info.anchored_header.block_hash(),
        );
        if parent_block_id != next_ready_block.header.parent_block_id {
            drop(chainstate_tx);

            let msg = "Discontinuous Nakamoto Stacks block";
            warn!("{}", &msg;
                  "child parent_block_id" => %next_ready_block.header.parent_block_id,
                  "expected parent_block_id" => %parent_block_id
            );
            let staging_block_tx = stacks_chain_state.staging_db_tx_begin()?;
            staging_block_tx.set_block_orphaned(&block_id)?;
            staging_block_tx.commit()?;
            return Err(ChainstateError::InvalidStacksBlock(msg.into()));
        }

        // find commit and sortition burns if this is a tenure-start block
        let Ok(new_tenure) = next_ready_block.is_wellformed_tenure_start_block() else {
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: invalid tenure change tx(s)".into(),
            ));
        };

        let (commit_burn, sortition_burn) = if new_tenure {
            // find block-commit to get commit-burn
            let block_commit = sort_tx
                .get_block_commit(
                    &next_ready_block_snapshot.winning_block_txid,
                    &next_ready_block_snapshot.sortition_id,
                )?
                .expect("FATAL: no block-commit for tenure-start block");

            let sort_burn = SortitionDB::get_block_burn_amount(
                sort_tx.deref().deref(),
                &next_ready_block_snapshot,
            )?;
            (block_commit.burn_fee, sort_burn)
        } else {
            (0, 0)
        };

        // attach the block to the chain state and calculate the next chain tip.
        let pox_constants = sort_tx.context.pox_constants.clone();

        // NOTE: because block status is updated in a separate transaction, we need `chainstate_tx`
        // and `clarity_instance` to go out of scope before we can issue the it (since we need a
        // mutable reference to `stacks_chain_state` to start it).  This means ensuring that, in the
        // `Ok(..)` case, the `clarity_commit` gets dropped beforehand.  In order to do this, we first
        // run `::append_block()` here, and capture both the Ok(..) and Err(..) results as
        // Option<..>'s.  Then, if we errored, we can explicitly drop the `Ok(..)` option (even
        // though it will always be None), which gets the borrow-checker to believe that it's safe
        // to access `stacks_chain_state` again.  In the `Ok(..)` case, it's instead sufficient so
        // simply commit the block before beginning the second transaction to mark it processed.
        let (ok_opt, err_opt) = match NakamotoChainState::append_block(
            &mut chainstate_tx,
            clarity_instance,
            sort_tx,
            &pox_constants,
            &parent_header_info,
            &next_ready_block_snapshot.burn_header_hash,
            next_ready_block_snapshot
                .block_height
                .try_into()
                .expect("Failed to downcast u64 to u32"),
            next_ready_block_snapshot.burn_header_timestamp,
            &next_ready_block,
            block_size,
            commit_burn,
            sortition_burn,
        ) {
            Ok(next_chain_tip_info) => (Some(next_chain_tip_info), None),
            Err(e) => (None, Some(e)),
        };

        if let Some(e) = err_opt {
            // force rollback
            drop(ok_opt);
            drop(chainstate_tx);

            warn!(
                "Failed to append {}/{}: {:?}",
                &next_ready_block.header.consensus_hash,
                &next_ready_block.header.block_hash(),
                &e
            );

            // as a separate transaction, mark this block as processed and orphaned.
            // This is done separately so that the staging blocks DB, which receives writes
            // from the network to store blocks, will be available for writes while a block is
            // being processed. Therefore, it's *very important* that block-processing happens
            // within the same, single thread.  Also, it's *very important* that this update
            // succeeds, since *we have already processed* the block.
            Self::infallible_set_block_orphaned(stacks_chain_state, &block_id);
            return Err(e);
        };

        let (receipt, clarity_commit, reward_set_data) = ok_opt.expect("FATAL: unreachable");

        assert_eq!(
            receipt.header.anchored_header.block_hash(),
            next_ready_block.header.block_hash()
        );
        assert_eq!(
            receipt.header.consensus_hash,
            next_ready_block.header.consensus_hash
        );

        // set stacks block accepted
        sort_tx.set_stacks_block_accepted(
            &next_ready_block.header.consensus_hash,
            &next_ready_block.header.block_hash(),
            next_ready_block.header.chain_length,
        )?;

        // this will panic if the Clarity commit fails.
        clarity_commit.commit();
        chainstate_tx.commit()
            .unwrap_or_else(|e| {
                error!("Failed to commit chainstate transaction after committing Clarity block. The chainstate database is now corrupted.";
                       "error" => ?e);
                panic!()
            });

        // as a separate transaction, mark this block as processed.
        // This is done separately so that the staging blocks DB, which receives writes
        // from the network to store blocks, will be available for writes while a block is
        // being processed. Therefore, it's *very important* that block-processing happens
        // within the same, single thread.  Also, it's *very important* that this update
        // succeeds, since *we have already processed* the block.
        Self::infallible_set_block_processed(stacks_chain_state, &block_id);

        let signer_bitvec = (&next_ready_block).header.signer_bitvec.clone();

        // announce the block, if we're connected to an event dispatcher
        if let Some(dispatcher) = dispatcher_opt {
            let block_event = (
                next_ready_block,
                parent_header_info.anchored_header.block_hash(),
            )
                .into();
            dispatcher.announce_block(
                &block_event,
                &receipt.header.clone(),
                &receipt.tx_receipts,
                &parent_block_id,
                next_ready_block_snapshot.winning_block_txid,
                &receipt.matured_rewards,
                receipt.matured_rewards_info.as_ref(),
                receipt.parent_burn_block_hash,
                receipt.parent_burn_block_height,
                receipt.parent_burn_block_timestamp,
                &receipt.anchored_block_cost,
                &receipt.parent_microblocks_cost,
                &pox_constants,
                &reward_set_data,
                &Some(signer_bitvec),
            );
        }

        Ok(Some(receipt))
    }

    /// Get the expected total burnchain tokens spent so far for a given block.
    /// * if the block has a tenure-change tx, then this is the tx's sortition consensus hash's
    /// snapshot's burn total (since the miner will have produced this tenure-change tx in reaction
    /// to the arrival of this new sortition)
    /// * otherwise, it's the highest processed tenure's sortition consensus hash's snapshot's burn
    /// total.
    ///
    /// This function will return Ok(None) if the given block's parent is not yet processed.  This
    /// by itself is not necessarily an error, because a block can be stored for subsequent
    /// processing before its parent has been processed.  The `Self::append_block()` function,
    /// however, will flag a block as invalid in this case, because the parent must be available in
    /// order to process a block.
    pub(crate) fn get_expected_burns<SH: SortitionHandle>(
        sort_handle: &mut SH,
        chainstate_conn: &Connection,
        block: &NakamotoBlock,
    ) -> Result<Option<u64>, ChainstateError> {
        let burn_view_ch = if let Some(tenure_payload) = block.get_tenure_tx_payload() {
            tenure_payload.burn_view_consensus_hash
        } else {
            // if there's no new tenure for this block, the burn total should be the same as its parent
            let parent_burns_opt =
                Self::get_block_header(chainstate_conn, &block.header.parent_block_id)?
                    .map(|parent| parent.anchored_header.total_burns());
            return Ok(parent_burns_opt);
        };
        let burn_view_sn =
            SortitionDB::get_block_snapshot_consensus(sort_handle.sqlite(), &burn_view_ch)?
                .ok_or_else(|| {
                    warn!("Could not load expected burns -- no such burn view";
                          "burn_view_consensus_hash" => %burn_view_ch
                    );
                    ChainstateError::NoSuchBlockError
                })?;
        Ok(Some(burn_view_sn.total_burn))
    }

    /// Validate that a Nakamoto block attaches to the burn chain state.
    /// Called before inserting the block into the staging DB.
    /// Wraps `NakamotoBlock::validate_against_burnchain()`, and
    /// verifies that all transactions in the block are allowed in this epoch.
    pub fn validate_nakamoto_block_burnchain(
        db_handle: &SortitionHandleConn,
        expected_burn: Option<u64>,
        block: &NakamotoBlock,
        mainnet: bool,
        chain_id: u32,
    ) -> Result<(), ChainstateError> {
        // find the sortition-winning block commit for this block, as well as the block snapshot
        // containing the parent block-commit.  This is the snapshot that corresponds to when the
        // miner begain its tenure; it may not be the burnchain tip.
        let block_hash = block.header.block_hash();
        let consensus_hash = &block.header.consensus_hash;

        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(db_handle)?;

        // burn chain tip that selected this commit's block (the tenure sortition)
        let Some(tenure_burn_chain_tip) =
            SortitionDB::get_block_snapshot_consensus(db_handle, consensus_hash)?
        else {
            warn!("No sortition for {}", &consensus_hash);
            return Err(ChainstateError::InvalidStacksBlock(
                "No sortition for block's consensus hash".into(),
            ));
        };

        // tenure sortition is canonical
        let Some(ancestor_sort_id) = get_ancestor_sort_id(
            db_handle,
            tenure_burn_chain_tip.block_height,
            &sort_tip.sortition_id,
        )?
        else {
            // not canonical
            warn!("Invalid consensus hash: snapshot is not canonical"; "consensus_hash" => %consensus_hash);
            return Err(ChainstateError::InvalidStacksBlock(
                "No sortition for block's consensus hash -- not canonical".into(),
            ));
        };
        if ancestor_sort_id != tenure_burn_chain_tip.sortition_id {
            // not canonical
            warn!("Invalid consensus hash: snapshot is not canonical"; "consensus_hash" => %consensus_hash);
            return Err(ChainstateError::InvalidStacksBlock(
                "No sortition for block's consensus hash -- not canonical".into(),
            ));
        };

        // the block-commit itself
        let Some(block_commit) = db_handle.get_block_commit_by_txid(
            &tenure_burn_chain_tip.sortition_id,
            &tenure_burn_chain_tip.winning_block_txid,
        )?
        else {
            warn!(
                "No block commit for {} in sortition for {}",
                &tenure_burn_chain_tip.winning_block_txid, &consensus_hash
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "No block-commit in sortition for block's consensus hash".into(),
            ));
        };

        // key register of the winning miner
        let leader_key = db_handle
            .get_leader_key_at(
                u64::from(block_commit.key_block_ptr),
                u32::from(block_commit.key_vtxindex),
            )?
            .expect("FATAL: have block commit but no leader key");

        // attaches to burn chain
        if let Err(e) =
            block.validate_against_burnchain(&tenure_burn_chain_tip, expected_burn, &leader_key)
        {
            warn!(
                "Invalid Nakamoto block, could not validate on burnchain";
                "consensus_hash" => %consensus_hash,
                "block_hash" => %block_hash,
                "error" => ?e
            );

            return Err(e);
        }

        // check the _next_ block's tenure, since when Nakamoto's miner activates, the current chain tip
        // will be in epoch 2.5 (the next block will be epoch 3.0)
        let cur_epoch = SortitionDB::get_stacks_epoch(
            db_handle.deref(),
            tenure_burn_chain_tip.block_height + 1,
        )?
        .expect("FATAL: no epoch defined for current Stacks block");

        // static checks on transactions all pass
        let valid = block.validate_transactions_static(mainnet, chain_id, cur_epoch.epoch_id);
        if !valid {
            warn!(
                "Invalid Nakamoto block, transactions failed static checks: {}/{} (epoch {})",
                consensus_hash, block_hash, cur_epoch.epoch_id
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: failed static transaction checks".into(),
            ));
        }

        Ok(())
    }

    /// Insert a Nakamoto block into the staging blocks DB
    pub(crate) fn store_block(
        staging_db_tx: &NakamotoStagingBlocksTx,
        block: NakamotoBlock,
        burn_attachable: bool,
    ) -> Result<(), ChainstateError> {
        let block_id = block.block_id();
        let Ok(tenure_start) = block.is_wellformed_tenure_start_block() else {
            return Err(ChainstateError::InvalidStacksBlock(
                "Tried to store a tenure-start block that is not well-formed".into(),
            ));
        };

        staging_db_tx.execute(
            "INSERT INTO nakamoto_staging_blocks (
                     block_hash,
                     consensus_hash,
                     parent_block_id,
                     is_tenure_start,
                     burn_attachable,
                     orphaned,
                     processed,

                     height,
                     index_block_hash,
                     download_time,
                     arrival_time,
                     processed_time,
                     data
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                &block.header.block_hash(),
                &block.header.consensus_hash,
                &block.header.parent_block_id,
                &tenure_start,
                if burn_attachable { 1 } else { 0 },
                0,
                0,
                u64_to_sql(block.header.chain_length)?,
                &block_id,
                0,
                0,
                0,
                block.serialize_to_vec(),
            ],
        )?;
        if burn_attachable {
            staging_db_tx.set_burn_block_processed(&block.header.consensus_hash)?;
        }
        Ok(())
    }

    /// Accept a Nakamoto block into the staging blocks DB.
    /// Fails if:
    /// * the public key cannot be recovered from the miner's signature
    /// * the stackers during the tenure didn't sign it
    /// * a DB error occurs
    /// Does nothing if:
    /// * we already have the block
    /// Returns true if we stored the block; false if not.
    pub fn accept_block(
        config: &ChainstateConfig,
        block: NakamotoBlock,
        db_handle: &mut SortitionHandleConn,
        staging_db_tx: &NakamotoStagingBlocksTx,
        headers_conn: &Connection,
        aggregate_public_key: &Point,
    ) -> Result<bool, ChainstateError> {
        test_debug!("Consider Nakamoto block {}", &block.block_id());
        // do nothing if we already have this block
        if let Some(_) = Self::get_block_header(headers_conn, &block.header.block_id())? {
            debug!("Already have block {}", &block.header.block_id());
            return Ok(false);
        }

        // if this is the first tenure block, then make sure it's well-formed
        block.is_wellformed_tenure_start_block().map_err(|_| {
            warn!(
                "Block {} is not a well-formed first tenure block",
                &block.block_id()
            );
            ChainstateError::InvalidStacksBlock("Not a well-formed first-tenure block".into())
        })?;

        // if this is a tenure-extend block, then make sure it's well-formed
        block.is_wellformed_tenure_extend_block().map_err(|_| {
            warn!(
                "Block {} is not a well-formed tenure-extend block",
                &block.block_id()
            );
            ChainstateError::InvalidStacksBlock("Not a well-formed tenure-extend block".into())
        })?;

        // it's okay if this fails because we might not have the parent block yet.  It will be
        // checked on `::append_block()`
        let expected_burn_opt = Self::get_expected_burns(db_handle, headers_conn, &block)?;

        // this block must be consistent with its miner's leader-key and block-commit, and must
        // contain only transactions that are valid in this epoch.
        if let Err(e) = Self::validate_nakamoto_block_burnchain(
            db_handle,
            expected_burn_opt,
            &block,
            config.mainnet,
            config.chain_id,
        ) {
            warn!("Unacceptable Nakamoto block; will not store";
                  "block_id" => %block.block_id(),
                  "error" => ?e
            );
            return Ok(false);
        };

        let schnorr_signature = &block.header.signer_signature.0;
        if !db_handle.expects_signer_signature(
            &block.header.consensus_hash,
            schnorr_signature,
            &block.header.signer_signature_hash().0,
            aggregate_public_key,
        )? {
            let msg = format!(
                "Received block, but the signer signature does not match the active stacking cycle"
            );
            warn!("{}", msg; "aggregate_key" => %aggregate_public_key);
            return Err(ChainstateError::InvalidStacksBlock(msg));
        }

        // if we pass all the tests, then along the way, we will have verified (in
        // Self::validate_nakamoto_block_burnchain) that the consensus hash of this block is on the
        // same sortition history as `db_handle` (and thus it must be burn_attachable)
        let burn_attachable = true;

        let _block_id = block.block_id();
        Self::store_block(staging_db_tx, block, burn_attachable)?;
        test_debug!("Stored Nakamoto block {}", &_block_id);
        Ok(true)
    }

    /// Get the aggregate public key for the given block from the signers-voting contract
    pub(crate) fn load_aggregate_public_key<SH: SortitionHandle>(
        sortdb: &SortitionDB,
        sort_handle: &SH,
        chainstate: &mut StacksChainState,
        for_burn_block_height: u64,
        at_block_id: &StacksBlockId,
        warn_if_not_found: bool,
    ) -> Result<Point, ChainstateError> {
        // Get the current reward cycle
        let Some(rc) = sort_handle.pox_constants().block_height_to_reward_cycle(
            sort_handle.first_burn_block_height(),
            for_burn_block_height,
        ) else {
            // This should be unreachable, but we'll return an error just in case.
            let msg = format!(
                "BUG: Failed to determine reward cycle of burn block height: {}.",
                for_burn_block_height
            );
            warn!("{msg}");
            return Err(ChainstateError::InvalidStacksBlock(msg));
        };

        test_debug!(
            "get-approved-aggregate-key at block {}, cycle {}",
            at_block_id,
            rc
        );
        match chainstate.get_aggregate_public_key_pox_4(sortdb, at_block_id, rc)? {
            Some(key) => Ok(key),
            None => {
                // this can happen for a whole host of reasons
                if warn_if_not_found {
                    warn!(
                        "Failed to get aggregate public key";
                        "block_id" => %at_block_id,
                        "reward_cycle" => rc,
                    );
                }
                Err(ChainstateError::InvalidStacksBlock(
                    "Failed to get aggregate public key".into(),
                ))
            }
        }
    }

    /// Get the aggregate public key for a block.
    /// TODO: The block at which the aggregate public key is queried needs to be better defined.
    /// See https://github.com/stacks-network/stacks-core/issues/4109
    pub fn get_aggregate_public_key<SH: SortitionHandle>(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        sort_handle: &SH,
        block: &NakamotoBlock,
    ) -> Result<Point, ChainstateError> {
        let block_sn =
            SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &block.header.consensus_hash)?
                .ok_or(ChainstateError::DBError(DBError::NotFoundError))?;
        let aggregate_key_block_header =
            Self::get_canonical_block_header(chainstate.db(), sortdb)?.unwrap();
        let epoch_id = SortitionDB::get_stacks_epoch(sortdb.conn(), block_sn.block_height)?
            .ok_or(ChainstateError::InvalidStacksBlock(
                "Failed to get epoch ID".into(),
            ))?
            .epoch_id;

        let aggregate_public_key = Self::load_aggregate_public_key(
            sortdb,
            sort_handle,
            chainstate,
            block_sn.block_height,
            &aggregate_key_block_header.index_block_hash(),
            epoch_id >= StacksEpochId::Epoch30,
        )?;
        Ok(aggregate_public_key)
    }

    /// Return the total ExecutionCost consumed during the tenure up to and including
    ///  `block`
    pub fn get_total_tenure_cost_at(
        chainstate_conn: &Connection,
        block: &StacksBlockId,
    ) -> Result<Option<ExecutionCost>, ChainstateError> {
        let qry = "SELECT total_tenure_cost FROM nakamoto_block_headers WHERE index_block_hash = ?";
        chainstate_conn
            .query_row(qry, &[block], |row| row.get(0))
            .optional()
            .map_err(ChainstateError::from)
    }

    /// Return the total transactions fees during the tenure up to and including
    ///  `block`
    pub fn get_total_tenure_tx_fees_at(
        chainstate_conn: &Connection,
        block: &StacksBlockId,
    ) -> Result<Option<u128>, ChainstateError> {
        let qry = "SELECT tenure_tx_fees FROM nakamoto_block_headers WHERE index_block_hash = ?";
        let tx_fees_str: Option<String> = chainstate_conn
            .query_row(qry, &[block], |row| row.get(0))
            .optional()?;
        tx_fees_str
            .map(|x| x.parse())
            .transpose()
            .map_err(|_| ChainstateError::DBError(DBError::ParseError))
    }

    /// Return a Nakamoto StacksHeaderInfo at a given coinbase height in the fork identified by `tip_index_hash`.
    /// * For Stacks 2.x, this is the Stacks block's header
    /// * For Stacks 3.x (Nakamoto), this is the first block in the miner's tenure.
    pub fn get_header_by_coinbase_height(
        tx: &mut StacksDBTx,
        tip_index_hash: &StacksBlockId,
        coinbase_height: u64,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        // query for block header info at the tenure-height, then check if in fork
        let qry = "SELECT DISTINCT tenure_id_consensus_hash AS consensus_hash FROM nakamoto_tenures WHERE coinbase_height = ?1";

        let candidate_chs: Vec<ConsensusHash> =
            query_rows(tx.tx(), qry, &[u64_to_sql(coinbase_height)?])?;

        if candidate_chs.len() == 0 {
            // no nakamoto_tenures at that tenure height, check if there's a stack block header where
            //   block_height = coinbase_height
            let Some(ancestor_at_height) = tx
                .get_ancestor_block_hash(coinbase_height, tip_index_hash)?
                .map(|ancestor| Self::get_block_header(tx.tx(), &ancestor))
                .transpose()?
                .flatten()
            else {
                warn!("No such epoch2 ancestor";
                      "coinbase_height" => coinbase_height,
                      "tip_index_hash" => %tip_index_hash,
                );
                return Ok(None);
            };
            // only return if it is an epoch-2 block, because that's
            // the only case where block_height can be interpreted as
            // tenure height.
            if ancestor_at_height.is_epoch_2_block() {
                return Ok(Some(ancestor_at_height));
            } else {
                return Ok(None);
            }
        }

        for candidate_ch in candidate_chs.into_iter() {
            let Some(candidate) = Self::get_block_header_by_consensus_hash(tx, &candidate_ch)?
            else {
                continue;
            };
            let Ok(Some(ancestor_at_height)) =
                tx.get_ancestor_block_hash(candidate.stacks_block_height, tip_index_hash)
            else {
                // if there's an error or no result, this candidate doesn't match, so try next candidate
                continue;
            };
            if ancestor_at_height == candidate.index_block_hash() {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// Load a Nakamoto header
    pub fn get_block_header_nakamoto(
        chainstate_conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_block_headers WHERE index_block_hash = ?1";
        let result = query_row_panic(chainstate_conn, sql, &[&index_block_hash], || {
            "FATAL: multiple rows for the same block hash".to_string()
        })?;
        Ok(result)
    }

    /// Load an epoch2 header
    pub fn get_block_header_epoch2(
        chainstate_conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        let sql = "SELECT * FROM block_headers WHERE index_block_hash = ?1";
        let result = query_row_panic(chainstate_conn, sql, &[&index_block_hash], || {
            "FATAL: multiple rows for the same block hash".to_string()
        })?;

        Ok(result)
    }

    /// Load block header (either Epoch-2 rules or Nakamoto) by `index_block_hash`
    pub fn get_block_header(
        chainstate_conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        if let Some(header) = Self::get_block_header_nakamoto(chainstate_conn, index_block_hash)? {
            return Ok(Some(header));
        }

        Self::get_block_header_epoch2(chainstate_conn, index_block_hash)
    }

    /// Does a block header exist?
    /// Works for both Nakamoto and epoch2 blocks, as long as check_epoch2 is true
    pub fn has_block_header(
        chainstate_conn: &Connection,
        index_block_hash: &StacksBlockId,
        check_epoch2: bool,
    ) -> Result<bool, ChainstateError> {
        let sql = "SELECT 1 FROM nakamoto_block_headers WHERE index_block_hash = ?1";
        let result: Option<i64> =
            query_row_panic(chainstate_conn, sql, &[&index_block_hash], || {
                "FATAL: multiple rows for the same block hash".to_string()
            })?;
        if result.is_some() {
            return Ok(true);
        }

        if !check_epoch2 {
            return Ok(false);
        }

        // check epoch 2
        let sql = "SELECT 1 FROM block_headers WHERE index_block_hash = ?1";
        let result: Option<i64> =
            query_row_panic(chainstate_conn, sql, &[&index_block_hash], || {
                "FATAL: multiple rows for the same block hash".to_string()
            })?;

        Ok(result.is_some())
    }

    /// Load the canonical Stacks block header (either epoch-2 rules or Nakamoto)
    pub fn get_canonical_block_header(
        chainstate_conn: &Connection,
        sortdb: &SortitionDB,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        let (consensus_hash, block_hash) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())?;
        Self::get_block_header(
            chainstate_conn,
            &StacksBlockId::new(&consensus_hash, &block_hash),
        )
    }

    /// Get the tenure-start block header of a given consensus hash.
    /// It might be an epoch 2.x block header
    pub fn get_block_header_by_consensus_hash(
        chainstate_conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        let nakamoto_header_info =
            Self::get_nakamoto_tenure_start_block_header(chainstate_conn, consensus_hash)?;
        if nakamoto_header_info.is_some() {
            return Ok(nakamoto_header_info);
        }

        // parent might be epoch 2
        let epoch2_header_info = StacksChainState::get_stacks_block_header_info_by_consensus_hash(
            chainstate_conn,
            consensus_hash,
        )?;
        Ok(epoch2_header_info)
    }

    /// Get the VRF proof for a Stacks block.
    /// This works for either Nakamoto or epoch 2.x
    pub fn get_block_vrf_proof(
        chainstate_conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<VRFProof>, ChainstateError> {
        let Some(start_header) = NakamotoChainState::get_block_header_by_consensus_hash(
            chainstate_conn,
            consensus_hash,
        )?
        else {
            return Ok(None);
        };

        let vrf_proof = match start_header.anchored_header {
            StacksBlockHeaderTypes::Epoch2(epoch2_header) => Some(epoch2_header.proof),
            StacksBlockHeaderTypes::Nakamoto(..) => {
                NakamotoChainState::get_nakamoto_tenure_vrf_proof(chainstate_conn, consensus_hash)?
            }
        };

        Ok(vrf_proof)
    }

    /// Get the VRF proof of the parent tenure (either Nakamoto or epoch 2.x) of the block
    /// identified by the given consensus hash.
    /// The parent must already have been processed.
    ///
    /// `consensus_hash` identifies the child block.
    /// `block_commit_txid` identifies the child block's tenure's block-commit tx
    ///
    /// Returns the proof of this block's parent tenure on success.
    ///
    /// Returns InvalidStacksBlock if the sortition for `consensus_hash` does not exist, or if its
    /// parent sortition doesn't exist (i.e. the sortition DB is missing something)
    ///
    /// Returns NoSuchBlockError if the block header for `consensus_hash` does not exist, or if the
    /// parent block header info does not exist (i.e. the chainstate DB is missing something)
    pub fn get_parent_vrf_proof(
        chainstate_conn: &Connection,
        sortdb_conn: &Connection,
        consensus_hash: &ConsensusHash,
        block_commit_txid: &Txid,
    ) -> Result<VRFProof, ChainstateError> {
        let sn = SortitionDB::get_block_snapshot_consensus(sortdb_conn, consensus_hash)?.ok_or(
            ChainstateError::InvalidStacksBlock("No sortition for consensus hash".into()),
        )?;

        let parent_sortition_id = SortitionDB::get_block_commit_parent_sortition_id(
            sortdb_conn,
            &block_commit_txid,
            &sn.sortition_id,
        )?
        .ok_or(ChainstateError::InvalidStacksBlock(
            "Parent block-commit is not in this block's sortition history".into(),
        ))?;

        let parent_sn = SortitionDB::get_block_snapshot(sortdb_conn, &parent_sortition_id)?.ok_or(
            ChainstateError::InvalidStacksBlock(
                "Parent block-commit does not have a sortition".into(),
            ),
        )?;

        let parent_vrf_proof =
            Self::get_block_vrf_proof(chainstate_conn, &parent_sn.consensus_hash)?
                .ok_or(ChainstateError::NoSuchBlockError)
                .map_err(|e| {
                    warn!("Nakamoto block has no parent";
                      "block consensus_hash" => %consensus_hash);
                    e
                })?;

        Ok(parent_vrf_proof)
    }

    /// Get the status of a Nakamoto block.
    /// Returns Some(accepted?, orphaned?) on success
    /// Returns None if there's no such block
    /// Returns Err on DBError
    pub fn get_nakamoto_block_status(
        staging_blocks_conn: NakamotoStagingBlocksConnRef,
        headers_conn: &Connection,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<(bool, bool)>, ChainstateError> {
        let sql = "SELECT processed, orphaned FROM nakamoto_staging_blocks WHERE consensus_hash = ?1 AND block_hash = ?2";
        let args: &[&dyn ToSql] = &[consensus_hash, block_hash];
        let Some((processed, orphaned)) = query_row_panic(&staging_blocks_conn, sql, args, || {
            "FATAL: multiple rows for the same consensus hash and block hash".to_string()
        })
        .map_err(ChainstateError::DBError)?
        .map(|(processed, orphaned): (u32, u32)| (processed != 0, orphaned != 0)) else {
            // not present
            return Ok(None);
        };

        if processed || orphaned {
            return Ok(Some((processed, orphaned)));
        }

        // this can report a false negative since we set the `processed` and `orphaned` flags in a
        // separate transaction after processing a block, so handle that here
        // look for the block
        if Self::has_block_header(
            headers_conn,
            &StacksBlockId::new(consensus_hash, block_hash),
            false,
        )? {
            // was processed, but the staging DB has not yet been updated.
            return Ok(Some((true, false)));
        } else {
            // not processed yet, so return whatever was in the staging DB
            return Ok(Some((processed, orphaned)));
        }
    }

    /// Get the VRF proof for a Nakamoto block, if it exists.
    /// Returns None if the Nakamoto block's VRF proof is not found (e.g. because there is no
    /// Nakamoto block)
    pub fn get_nakamoto_tenure_vrf_proof(
        chainstate_conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<VRFProof>, ChainstateError> {
        let sql = "SELECT vrf_proof FROM nakamoto_block_headers WHERE consensus_hash = ?1 AND tenure_changed = 1";
        let args: &[&dyn ToSql] = &[consensus_hash];
        let proof_bytes: Option<String> = query_row(chainstate_conn, sql, args)?;
        if let Some(bytes) = proof_bytes {
            let proof = VRFProof::from_hex(&bytes)
                .ok_or(DBError::Corruption)
                .map_err(|e| {
                    warn!("Failed to load VRF proof: could not decode";
                          "vrf_proof" => %bytes,
                          "consensus_hash" => %consensus_hash
                    );
                    e
                })?;
            Ok(Some(proof))
        } else {
            Ok(None)
        }
    }

    /// Verify that a nakamoto block's block-commit's VRF seed is consistent with the VRF proof
    fn check_block_commit_vrf_seed(
        chainstate_conn: &Connection,
        sortdb_conn: &Connection,
        block: &NakamotoBlock,
    ) -> Result<(), ChainstateError> {
        // get the block-commit for this block
        let sn =
            SortitionDB::get_block_snapshot_consensus(sortdb_conn, &block.header.consensus_hash)?
                .ok_or(ChainstateError::NoSuchBlockError)
                .map_err(|e| {
                    warn!("No block-commit for block"; "block_id" => %block.block_id());
                    e
                })?;

        let block_commit =
            get_block_commit_by_txid(sortdb_conn, &sn.sortition_id, &sn.winning_block_txid)?
                .ok_or(ChainstateError::NoSuchBlockError)
                .map_err(|e| {
                    warn!("No block-commit for block"; "block_id" => %block.block_id());
                    e
                })?;

        block.validate_vrf_seed(sortdb_conn, chainstate_conn, &block_commit)
    }

    /// Insert a nakamoto block header that is paired with an
    /// already-existing block commit and snapshot
    ///
    /// `header` should be a pointer to the header in `tip_info`.
    pub(crate) fn insert_stacks_block_header(
        chainstate_tx: &Connection,
        tip_info: &StacksHeaderInfo,
        header: &NakamotoBlockHeader,
        vrf_proof: Option<&VRFProof>,
        block_cost: &ExecutionCost,
        total_tenure_cost: &ExecutionCost,
        tenure_changed: bool,
        tenure_tx_fees: u128,
    ) -> Result<(), ChainstateError> {
        assert_eq!(tip_info.stacks_block_height, header.chain_length,);
        assert!(tip_info.burn_header_timestamp < u64::try_from(i64::MAX).unwrap());

        let StacksHeaderInfo {
            index_root,
            consensus_hash,
            burn_header_hash,
            stacks_block_height,
            burn_header_height,
            burn_header_timestamp,
            ..
        } = tip_info;

        let block_size_str = format!("{}", tip_info.anchored_block_size);

        let block_hash = header.block_hash();

        let index_block_hash = StacksBlockId::new(&consensus_hash, &block_hash);

        assert!(*stacks_block_height < u64::try_from(i64::MAX).unwrap());

        let vrf_proof_bytes = vrf_proof.map(|proof| proof.to_hex());

        let args: &[&dyn ToSql] = &[
            &u64_to_sql(*stacks_block_height)?,
            &index_root,
            &consensus_hash,
            &burn_header_hash,
            &burn_header_height,
            &u64_to_sql(*burn_header_timestamp)?,
            &block_size_str,
            &HeaderTypeNames::Nakamoto,
            &header.version,
            &u64_to_sql(header.chain_length)?,
            &u64_to_sql(header.burn_spent)?,
            &header.miner_signature,
            &header.signer_signature,
            &header.tx_merkle_root,
            &header.state_index_root,
            &block_hash,
            &index_block_hash,
            block_cost,
            total_tenure_cost,
            &tenure_tx_fees.to_string(),
            &header.parent_block_id,
            if tenure_changed { &1i64 } else { &0i64 },
            &vrf_proof_bytes.as_ref(),
            &header.signer_bitvec,
        ];

        chainstate_tx.execute(
            "INSERT INTO nakamoto_block_headers
                    (block_height,  index_root, consensus_hash,
                     burn_header_hash, burn_header_height,
                     burn_header_timestamp, block_size,

                     header_type,
                     version, chain_length, burn_spent,
                     miner_signature, signer_signature, tx_merkle_root, state_index_root,

                     block_hash,
                     index_block_hash,
                     cost,
                     total_tenure_cost,
                     tenure_tx_fees,
                     parent_block_id,
                     tenure_changed,
                     vrf_proof,
                     signer_bitvec
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
            args
        )?;

        Ok(())
    }

    /// Append a Stacks block to an existing Stacks block, and grant the miner the block reward.
    /// Return the new Stacks header info.
    fn advance_tip(
        headers_tx: &mut StacksDBTx,
        parent_tip: &StacksBlockHeaderTypes,
        parent_consensus_hash: &ConsensusHash,
        new_tip: &NakamotoBlockHeader,
        new_vrf_proof: Option<&VRFProof>,
        new_burn_header_hash: &BurnchainHeaderHash,
        new_burnchain_height: u32,
        new_burnchain_timestamp: u64,
        block_reward: Option<&MinerPaymentSchedule>,
        mature_miner_payouts_opt: Option<MaturedMinerRewards>,
        anchor_block_cost: &ExecutionCost,
        total_tenure_cost: &ExecutionCost,
        block_size: u64,
        applied_epoch_transition: bool,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        burn_vote_for_aggregate_key_ops: Vec<VoteForAggregateKeyOp>,
        new_tenure: bool,
        block_fees: u128,
    ) -> Result<StacksHeaderInfo, ChainstateError> {
        if new_tip.parent_block_id
            != StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            // not the first-ever block, so linkage must occur
            match parent_tip {
                StacksBlockHeaderTypes::Epoch2(..) => {
                    assert_eq!(
                        new_tip.parent_block_id,
                        StacksBlockId::new(&parent_consensus_hash, &parent_tip.block_hash())
                    );
                }
                StacksBlockHeaderTypes::Nakamoto(nakamoto_header) => {
                    // nakamoto blocks link to their parent via index block hashes
                    assert_eq!(new_tip.parent_block_id, nakamoto_header.block_id());
                }
            }
        }

        assert_eq!(
            parent_tip
                .height()
                .checked_add(1)
                .expect("Block height overflow"),
            new_tip.chain_length
        );

        let parent_hash = new_tip.parent_block_id.clone();
        let new_block_hash = new_tip.block_hash();
        let index_block_hash = new_tip.block_id();

        // store each indexed field
        test_debug!("Headers index_put_begin {parent_hash}-{index_block_hash}");
        let root_hash =
            headers_tx.put_indexed_all(&parent_hash, &index_block_hash, &vec![], &vec![])?;
        test_debug!("Headers index_indexed_all finished {parent_hash}-{index_block_hash}");

        let new_tip_info = StacksHeaderInfo {
            anchored_header: new_tip.clone().into(),
            microblock_tail: None,
            index_root: root_hash,
            stacks_block_height: new_tip.chain_length,
            consensus_hash: new_tip.consensus_hash.clone(),
            burn_header_hash: new_burn_header_hash.clone(),
            burn_header_height: new_burnchain_height,
            burn_header_timestamp: new_burnchain_timestamp,
            anchored_block_size: block_size,
        };

        let tenure_fees = block_fees
            + if new_tenure {
                0
            } else {
                Self::get_total_tenure_tx_fees_at(&headers_tx, &parent_hash)?.ok_or_else(|| {
                    warn!(
                        "Failed to fetch parent block's total tx fees";
                        "parent_block_id" => %parent_hash,
                        "block_id" => %index_block_hash,
                    );
                    ChainstateError::NoSuchBlockError
                })?
            };

        Self::insert_stacks_block_header(
            headers_tx.deref_mut(),
            &new_tip_info,
            &new_tip,
            new_vrf_proof,
            anchor_block_cost,
            total_tenure_cost,
            new_tenure,
            tenure_fees,
        )?;
        if let Some(block_reward) = block_reward {
            StacksChainState::insert_miner_payment_schedule(headers_tx.deref_mut(), block_reward)?;
        }
        StacksChainState::store_burnchain_txids(
            headers_tx.deref(),
            &index_block_hash,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
            burn_vote_for_aggregate_key_ops,
        )?;

        if let Some(matured_miner_payouts) = mature_miner_payouts_opt {
            let rewarded_miner_block_id = StacksBlockId::new(
                &matured_miner_payouts.reward_info.from_block_consensus_hash,
                &matured_miner_payouts.reward_info.from_stacks_block_hash,
            );
            let rewarded_parent_miner_block_id = StacksBlockId::new(
                &matured_miner_payouts
                    .reward_info
                    .from_parent_block_consensus_hash,
                &matured_miner_payouts
                    .reward_info
                    .from_parent_stacks_block_hash,
            );

            StacksChainState::insert_matured_child_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &matured_miner_payouts.recipient,
            )?;
            StacksChainState::insert_matured_parent_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &matured_miner_payouts.parent_reward,
            )?;
        }

        if applied_epoch_transition {
            debug!("Block {} applied an epoch transition", &index_block_hash);
            let sql = "INSERT INTO epoch_transitions (block_id) VALUES (?)";
            let args: &[&dyn ToSql] = &[&index_block_hash];
            headers_tx.deref_mut().execute(sql, args)?;
        }

        debug!(
            "Advanced to new tip! {}/{}",
            &new_tip.consensus_hash, new_block_hash,
        );
        Ok(new_tip_info)
    }

    pub fn write_reward_set(
        tx: &mut ChainstateTx,
        block_id: &StacksBlockId,
        reward_set: &RewardSet,
    ) -> Result<(), ChainstateError> {
        let sql = "INSERT INTO nakamoto_reward_sets (index_block_hash, reward_set) VALUES (?, ?)";
        let args = rusqlite::params![block_id, &reward_set.metadata_serialize(),];
        tx.execute(sql, args)?;
        Ok(())
    }

    pub fn get_reward_set(
        chainstate_db: &Connection,
        block_id: &StacksBlockId,
    ) -> Result<Option<RewardSet>, ChainstateError> {
        let sql = "SELECT reward_set FROM nakamoto_reward_sets WHERE index_block_hash = ?";
        chainstate_db
            .query_row(sql, &[block_id], |row| {
                let reward_set: String = row.get(0)?;
                let reward_set = RewardSet::metadata_deserialize(&reward_set)
                    .map_err(|s| FromSqlError::Other(s.into()))?;
                Ok(reward_set)
            })
            .optional()
            .map_err(ChainstateError::from)
    }

    /// Begin block-processing and return all of the pre-processed state within a
    /// `SetupBlockResult`.
    ///
    /// * Find the matured miner rewards that must be applied in this block
    /// * Begin the Clarity transaction
    /// * Load up the tenure's execution cost thus far
    /// * Apply an epoch transition, if necessary
    /// * Handle auto-unlock for PoX
    /// * Process any new Stacks-on-Bitcoin transactions
    ///
    /// Called in both follower and miner block assembly paths.
    /// Arguments:
    /// * chainstate_tx: transaction against the chainstate MARF
    /// * clarity_instance: connection to the chainstate Clarity instance
    /// * sortition_dbconn: connection to the sortition DB MARF
    /// * pox_constants: PoX parameters
    /// * parent_consensus_hash, parent_header_hash, parent_stacks_height, parent_burn_height:
    /// pointer to the already-processed parent Stacks block
    /// * burn_header_hash, burn_header_height: pointer to the Bitcoin block that identifies the
    /// tenure of this block to be processed
    /// * new_tenure: whether or not this block is the start of a new tenure
    /// * coinbase_height: the number of tenures that this block confirms (including epoch2 blocks)
    ///   (this is equivalent to the number of coinbases)
    /// * tenure_extend: whether or not to reset the tenure's ongoing execution cost
    ///
    /// Returns clarity_tx, list of receipts, microblock execution cost,
    /// microblock fees, microblock burns, list of microblock tx receipts,
    /// miner rewards tuples, the stacks epoch id, and a boolean that
    /// represents whether the epoch transition has been applied.
    pub fn setup_block<'a, 'b>(
        chainstate_tx: &'b mut ChainstateTx,
        clarity_instance: &'a mut ClarityInstance,
        sortition_dbconn: &'b dyn SortitionDBRef,
        first_block_height: u64,
        pox_constants: &PoxConstants,
        parent_consensus_hash: ConsensusHash,
        parent_header_hash: BlockHeaderHash,
        _parent_stacks_height: u64,
        parent_burn_height: u32,
        burn_header_hash: BurnchainHeaderHash,
        burn_header_height: u32,
        new_tenure: bool,
        coinbase_height: u64,
        tenure_extend: bool,
    ) -> Result<SetupBlockResult<'a, 'b>, ChainstateError> {
        let parent_index_hash = StacksBlockId::new(&parent_consensus_hash, &parent_header_hash);
        let parent_sortition_id = sortition_dbconn
            .get_sortition_id_from_consensus_hash(&parent_consensus_hash)
            .expect("Failed to get parent SortitionID from ConsensusHash");
        let tip_index_hash = StacksBlockId::new(&parent_consensus_hash, &parent_header_hash);

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        let matured_rewards_schedule_opt = if new_tenure {
            Self::get_matured_miner_reward_schedules(
                chainstate_tx,
                &tip_index_hash,
                coinbase_height,
            )?
        } else {
            // no rewards if mid-tenure
            None
        };

        // TODO: only need to do this if this is a tenure-start block
        let (stacking_burn_ops, transfer_burn_ops, delegate_burn_ops, vote_for_agg_key_ops) =
            StacksChainState::get_stacking_and_transfer_and_delegate_burn_ops(
                chainstate_tx,
                &parent_index_hash,
                sortition_dbconn.sqlite_conn(),
                &burn_header_hash,
                burn_header_height.into(),
            )?;

        let mut clarity_tx = StacksChainState::chainstate_block_begin(
            chainstate_tx,
            clarity_instance,
            sortition_dbconn.as_burn_state_db(),
            &parent_consensus_hash,
            &parent_header_hash,
            &MINER_BLOCK_CONSENSUS_HASH,
            &MINER_BLOCK_HEADER_HASH,
        );

        // now that we have access to the ClarityVM, we can account for reward deductions from
        // PoisonMicroblocks if we have new rewards scheduled
        let matured_rewards_opt = matured_rewards_schedule_opt
            .map(|matured_rewards_schedule| {
                Self::calculate_matured_miner_rewards(
                    &mut clarity_tx,
                    sortition_dbconn.sqlite_conn(),
                    // coinbase_height + 1,
                    coinbase_height,
                    matured_rewards_schedule,
                )
            })
            .transpose()?
            .flatten();

        // Nakamoto must load block cost from parent if this block isn't a tenure change.
        // If this is a tenure-extend, then the execution cost is reset.
        let initial_cost = if new_tenure || tenure_extend {
            ExecutionCost::zero()
        } else {
            let parent_cost_total =
                Self::get_total_tenure_cost_at(&chainstate_tx.deref().deref(), &parent_index_hash)?
                    .ok_or_else(|| {
                        ChainstateError::InvalidStacksBlock(format!(
                    "Failed to load total tenure cost from parent. parent_stacks_block_id = {}",
                    &parent_index_hash
                ))
                    })?;
            parent_cost_total
        };

        clarity_tx.reset_cost(initial_cost);

        // is this stacks block the first of a new epoch?
        let (applied_epoch_transition, mut tx_receipts) =
            StacksChainState::process_epoch_transition(&mut clarity_tx, burn_header_height)?;

        debug!(
            "Setup block: Processed epoch transition";
            "parent_consensus_hash" => %parent_consensus_hash,
            "parent_header_hash" => %parent_header_hash,
        );

        if new_tenure {
            clarity_tx
                .connection()
                .as_free_transaction(|clarity_tx_conn| {
                    clarity_tx_conn.with_clarity_db(|db| {
                        db.set_tenure_height(
                            coinbase_height
                                .try_into()
                                .expect("Tenure height overflowed 32-bit range"),
                        )?;
                        Ok(())
                    })
                })
                .map_err(|e| {
                    error!("Failed to set tenure height during block setup";
                        "error" => ?e,
                    );
                    e
                })?;
        }

        let evaluated_epoch = clarity_tx.get_epoch();

        let auto_unlock_events = if evaluated_epoch >= StacksEpochId::Epoch21 {
            let unlock_events = StacksChainState::check_and_handle_reward_start(
                burn_header_height.into(),
                sortition_dbconn.as_burn_state_db(),
                sortition_dbconn,
                &mut clarity_tx,
                parent_burn_height,
                &parent_sortition_id,
            )?;
            debug!(
                "Setup block: Processed unlock events";
                "parent_consensus_hash" => %parent_consensus_hash,
                "parent_header_hash" => %parent_header_hash,
            );
            unlock_events
        } else {
            vec![]
        };

        let active_pox_contract = pox_constants.active_pox_contract(burn_header_height.into());

        // process stacking & transfer operations from burnchain ops
        tx_receipts.extend(StacksChainState::process_stacking_ops(
            &mut clarity_tx,
            stacking_burn_ops.clone(),
            active_pox_contract,
        ));
        tx_receipts.extend(StacksChainState::process_transfer_ops(
            &mut clarity_tx,
            transfer_burn_ops.clone(),
        ));
        debug!(
            "Setup block: Processed burnchain stacking and transfer ops";
            "parent_consensus_hash" => %parent_consensus_hash,
            "parent_header_hash" => %parent_header_hash,
        );

        // DelegateStx ops are allowed from epoch 2.1 onward.
        // The query for the delegate ops only returns anything in and after Epoch 2.1,
        // but we do a second check here just to be safe.
        if evaluated_epoch >= StacksEpochId::Epoch21 {
            tx_receipts.extend(StacksChainState::process_delegate_ops(
                &mut clarity_tx,
                delegate_burn_ops.clone(),
                active_pox_contract,
            ));
            debug!(
                "Setup block: Processed burnchain delegate ops";
                "parent_consensus_hash" => %parent_consensus_hash,
                "parent_header_hash" => %parent_header_hash,
            );
        }

        // Handle signer stackerdb updates
        let signer_set_calc;
        if evaluated_epoch >= StacksEpochId::Epoch25 {
            signer_set_calc = NakamotoSigners::check_and_handle_prepare_phase_start(
                &mut clarity_tx,
                first_block_height,
                &pox_constants,
                burn_header_height.into(),
                coinbase_height,
            )?;
            tx_receipts.extend(StacksChainState::process_vote_for_aggregate_key_ops(
                &mut clarity_tx,
                vote_for_agg_key_ops.clone(),
            ));
        } else {
            signer_set_calc = None;
        }

        debug!(
            "Setup block: completed setup";
            "parent_consensus_hash" => %parent_consensus_hash,
            "parent_header_hash" => %parent_header_hash,
        );

        Ok(SetupBlockResult {
            clarity_tx,
            tx_receipts,
            matured_miner_rewards_opt: matured_rewards_opt,
            evaluated_epoch,
            applied_epoch_transition,
            burn_stack_stx_ops: stacking_burn_ops,
            burn_transfer_stx_ops: transfer_burn_ops,
            auto_unlock_events,
            burn_delegate_stx_ops: delegate_burn_ops,
            signer_set_calc,
            burn_vote_for_aggregate_key_ops: vote_for_agg_key_ops,
        })
    }

    /// This function is called in both `append_block` in blocks.rs (follower) and
    /// `mine_anchored_block` in miner.rs.
    /// Processes matured miner rewards, alters liquid supply of ustx, processes
    /// stx lock events, and marks the microblock public key as used
    /// Returns stx lockup events.
    pub fn finish_block(
        clarity_tx: &mut ClarityTx,
        miner_payouts: Option<&MaturedMinerRewards>,
    ) -> Result<Vec<StacksTransactionEvent>, ChainstateError> {
        // add miner payments
        if let Some(ref rewards) = miner_payouts {
            // grant in order by miner, then users
            let matured_ustx = StacksChainState::process_matured_miner_rewards(
                clarity_tx,
                &rewards.recipient,
                &[],
                &rewards.parent_reward,
            )?;

            clarity_tx.increment_ustx_liquid_supply(matured_ustx);
        }

        // process unlocks
        let (new_unlocked_ustx, lockup_events) = StacksChainState::process_stx_unlocks(clarity_tx)?;

        clarity_tx.increment_ustx_liquid_supply(new_unlocked_ustx);

        Ok(lockup_events)
    }

    /// Append a Nakamoto Stacks block to the Stacks chain state.
    /// NOTE: This does _not_ set the block as processed!  The caller must do this.
    fn append_block<'a>(
        chainstate_tx: &mut ChainstateTx,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &mut SortitionHandleTx,
        pox_constants: &PoxConstants,
        parent_chain_tip: &StacksHeaderInfo,
        chain_tip_burn_header_hash: &BurnchainHeaderHash,
        chain_tip_burn_header_height: u32,
        chain_tip_burn_header_timestamp: u64,
        block: &NakamotoBlock,
        block_size: u64,
        burnchain_commit_burn: u64,
        burnchain_sortition_burn: u64,
    ) -> Result<
        (
            StacksEpochReceipt,
            PreCommitClarityBlock<'a>,
            Option<RewardSetData>,
        ),
        ChainstateError,
    > {
        debug!(
            "Process Nakamoto block {:?} with {} transactions",
            &block.header.block_hash().to_hex(),
            block.txs.len()
        );

        let ast_rules = ASTRules::PrecheckSize;
        let next_block_height = block.header.chain_length;
        let first_block_height = burn_dbconn.context.first_block_height;

        // check that this block attaches to the `parent_chain_tip`
        let (parent_ch, parent_block_hash) = if block.is_first_mined() {
            (
                FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                FIRST_STACKS_BLOCK_HASH.clone(),
            )
        } else {
            (
                parent_chain_tip.consensus_hash.clone(),
                parent_chain_tip.anchored_header.block_hash(),
            )
        };

        let parent_block_id = StacksBlockId::new(&parent_ch, &parent_block_hash);
        if parent_block_id != block.header.parent_block_id {
            warn!("Error processing nakamoto block: Parent consensus hash does not match db view";
                  "db.parent_block_id" => %parent_block_id,
                  "header.parent_block_id" => %block.header.parent_block_id);
            return Err(ChainstateError::InvalidStacksBlock(
                "Parent block does not match".into(),
            ));
        }

        // look up this block's sortition's burnchain block hash and height.
        // It must exist in the same Bitcoin fork as our `burn_dbconn`.
        let tenure_block_snapshot =
            Self::check_sortition_exists(burn_dbconn, &block.header.consensus_hash)?;
        let burn_header_hash = tenure_block_snapshot.burn_header_hash.clone();
        let burn_header_height = tenure_block_snapshot.block_height;
        let block_hash = block.header.block_hash();

        let new_tenure = match block.is_wellformed_tenure_start_block() {
            Ok(true) => true,
            Ok(false) => {
                // this block is mined in the ongoing tenure.
                if !Self::check_tenure_continuity(
                    chainstate_tx,
                    burn_dbconn.sqlite(),
                    &parent_ch,
                    &block.header,
                )? {
                    // this block is not part of the ongoing tenure; it's invalid
                    return Err(ChainstateError::ExpectedTenureChange);
                }
                false
            }
            Err(_) => {
                return Err(ChainstateError::InvalidStacksBlock(
                    "Invalid tenure changes in nakamoto block".into(),
                ));
            }
        };

        let tenure_extend = match block.is_wellformed_tenure_extend_block() {
            Ok(true) => {
                if new_tenure {
                    return Err(ChainstateError::InvalidStacksBlock(
                        "Both started and extended tenure".into(),
                    ));
                }
                true
            }
            Ok(false) => false,
            Err(_) => {
                return Err(ChainstateError::InvalidStacksBlock(
                    "Invalid tenure extend in nakamoto block".into(),
                ));
            }
        };

        let parent_coinbase_height = if block.is_first_mined() {
            0
        } else {
            Self::get_coinbase_height(chainstate_tx.deref(), &parent_block_id)?.ok_or_else(
                || {
                    warn!(
                        "Parent of Nakamoto block is not in block headers DB yet";
                        "block_hash" => %block.header.block_hash(),
                        "parent_block_hash" => %parent_block_hash,
                        "parent_block_id" => %parent_block_id
                    );
                    ChainstateError::NoSuchBlockError
                },
            )?
        };

        let expected_burn_opt = Self::get_expected_burns(burn_dbconn, chainstate_tx, block)
            .map_err(|e| {
                warn!("Unacceptable Nakamoto block: could not load expected burns (unable to find its paired sortition)";
                      "block_id" => %block.block_id(),
                      "parent_block_id" => %block.header.parent_block_id,
                      "error" => e.to_string(),
                );
                ChainstateError::InvalidStacksBlock("Invalid Nakamoto block: could not find sortition burns".into())
            })?;

        let Some(expected_burn) = expected_burn_opt else {
            warn!("Unacceptable Nakamoto block: unable to find parent block's burns";
                  "block_id" => %block.block_id(),
                  "parent_block_id" => %block.header.parent_block_id,
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: could not find sortition burns".into(),
            ));
        };

        // this block must commit to all of the burnchain spends seen so far
        if block.header.burn_spent != expected_burn {
            warn!("Invalid Nakamoto block header: invalid total burns";
                  "header.burn_spent" => block.header.burn_spent,
                  "expected_burn" => expected_burn,
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: invalid total burns".into(),
            ));
        }

        // this block's tenure's block-commit contains the hash of the parent tenure's tenure-start
        // block.
        // (note that we can't check this earlier, since we need the parent tenure to have been
        // processed)
        if new_tenure && parent_chain_tip.is_nakamoto_block() && !block.is_first_mined() {
            let tenure_block_commit = burn_dbconn
                .get_block_commit(
                    &tenure_block_snapshot.winning_block_txid,
                    &tenure_block_snapshot.sortition_id,
                )?
                .ok_or_else(|| {
                    warn!("Invalid Nakamoto block: has no block-commit in its sortition";
                          "block_id" => %block.header.block_id(),
                          "sortition_id" => %tenure_block_snapshot.sortition_id,
                          "block_commit_txid" => %tenure_block_snapshot.winning_block_txid);
                    ChainstateError::NoSuchBlockError
                })?;

            let parent_tenure_start_header =
                Self::get_nakamoto_tenure_start_block_header(chainstate_tx.tx(), &parent_ch)?
                    .ok_or_else(|| {
                        warn!("Invalid Nakamoto block: no start-tenure block for parent";
                          "parent_consensus_hash" => %parent_ch,
                          "block_id" => %block.header.block_id());

                        ChainstateError::NoSuchBlockError
                    })?;

            if parent_tenure_start_header.index_block_hash() != tenure_block_commit.last_tenure_id()
            {
                warn!("Invalid Nakamoto block: its tenure's block-commit's block ID hash does not match its parent tenure's start block";
                      "block_id" => %block.header.block_id(),
                      "parent_consensus_hash" => %parent_ch,
                      "parent_tenure_start_block_id" => %parent_tenure_start_header.index_block_hash(),
                      "block_commit.last_tenure_id" => %tenure_block_commit.last_tenure_id());

                return Err(ChainstateError::NoSuchBlockError);
            }
        }

        // verify VRF proof, if present
        // only need to do this once per tenure
        // get the resulting vrf proof bytes
        let vrf_proof_opt = if new_tenure {
            Self::check_block_commit_vrf_seed(chainstate_tx.deref(), burn_dbconn, block)?;
            Some(
                block
                    .get_vrf_proof()
                    .ok_or(ChainstateError::InvalidStacksBlock(
                        "Invalid Nakamoto block: has coinbase but no VRF proof".into(),
                    ))?,
            )
        } else {
            None
        };

        // process the tenure-change if it happened, so that when block-processing begins, it happens in whatever the
        // current tenure is
        let coinbase_height = Self::advance_nakamoto_tenure(
            chainstate_tx,
            burn_dbconn,
            block,
            parent_coinbase_height,
        )?;
        if new_tenure {
            // tenure height must have advanced
            if coinbase_height
                != parent_coinbase_height
                    .checked_add(1)
                    .expect("Too many tenures")
            {
                // this should be unreachable
                return Err(ChainstateError::InvalidStacksBlock(
                    "Could not advance tenure, even though tenure changed".into(),
                ));
            }
        } else {
            if coinbase_height != parent_coinbase_height {
                // this should be unreachable
                return Err(ChainstateError::InvalidStacksBlock(
                    "Advanced tenure even though a new tenure did not happen".into(),
                ));
            }
        }

        // begin processing this block
        let SetupBlockResult {
            mut clarity_tx,
            mut tx_receipts,
            matured_miner_rewards_opt,
            evaluated_epoch,
            applied_epoch_transition,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
            mut auto_unlock_events,
            signer_set_calc,
            burn_vote_for_aggregate_key_ops,
        } = Self::setup_block(
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
            first_block_height,
            pox_constants,
            parent_ch,
            parent_block_hash,
            parent_chain_tip.stacks_block_height,
            parent_chain_tip.burn_header_height,
            burn_header_hash,
            burn_header_height.try_into().map_err(|_| {
                ChainstateError::InvalidStacksBlock("Burn block height exceeded u32".into())
            })?,
            new_tenure,
            coinbase_height,
            tenure_extend,
        )?;

        let starting_cost = clarity_tx.cost_so_far();

        debug!(
            "Append nakamoto block";
            "block" => format!("{}/{block_hash}", block.header.consensus_hash),
            "block_id" => %block.header.block_id(),
            "parent_block" => %block.header.parent_block_id,
            "stacks_height" => next_block_height,
            "total_burns" => block.header.burn_spent,
            "evaluated_epoch" => %evaluated_epoch
        );

        // process anchored block
        let (block_fees, txs_receipts) = match StacksChainState::process_block_transactions(
            &mut clarity_tx,
            &block.txs,
            0,
            ast_rules,
        ) {
            Err(e) => {
                let msg = format!("Invalid Stacks block {}: {:?}", &block_hash, &e);
                warn!("{}", &msg);

                clarity_tx.rollback_block();
                return Err(ChainstateError::InvalidStacksBlock(msg));
            }
            Ok((block_fees, _block_burns, txs_receipts)) => (block_fees, txs_receipts),
        };

        tx_receipts.extend(txs_receipts.into_iter());

        let total_tenure_cost = clarity_tx.cost_so_far();
        let mut block_execution_cost = total_tenure_cost.clone();
        block_execution_cost.sub(&starting_cost).map_err(|_e| {
            ChainstateError::InvalidStacksBlock("Block execution cost was negative".into())
        })?;

        // obtain reward info for receipt -- consolidate miner, user, and parent rewards into a
        // single list, but keep the miner/user/parent/info tuple for advancing the chain tip
        let matured_rewards = matured_miner_rewards_opt
            .as_ref()
            .map(|matured_miner_rewards| matured_miner_rewards.consolidate())
            .unwrap_or(vec![]);

        let mut lockup_events =
            match Self::finish_block(&mut clarity_tx, matured_miner_rewards_opt.as_ref()) {
                Err(ChainstateError::InvalidStacksBlock(e)) => {
                    clarity_tx.rollback_block();
                    return Err(ChainstateError::InvalidStacksBlock(e));
                }
                Err(e) => return Err(e),
                Ok(lockup_events) => lockup_events,
            };

        // if any, append lockups events to the coinbase receipt
        if lockup_events.len() > 0 {
            // Receipts are appended in order, so the first receipt should be
            // the one of the coinbase transaction
            if let Some(receipt) = tx_receipts.get_mut(0) {
                if receipt.is_coinbase_tx() {
                    receipt.events.append(&mut lockup_events);
                }
            } else {
                warn!("Unable to attach lockups events, block's first transaction is not a coinbase transaction")
            }
        }
        // if any, append auto unlock events to the coinbase receipt
        if auto_unlock_events.len() > 0 {
            // Receipts are appended in order, so the first receipt should be
            // the one of the coinbase transaction
            if let Some(receipt) = tx_receipts.get_mut(0) {
                if receipt.is_coinbase_tx() {
                    receipt.events.append(&mut auto_unlock_events);
                }
            } else {
                warn!("Unable to attach auto unlock events, block's first transaction is not a coinbase transaction")
            }
        }

        // verify that the resulting chainstate matches the block's state root
        let root_hash = clarity_tx.seal();
        if root_hash != block.header.state_index_root {
            let msg = format!(
                "Block {} state root mismatch: expected {}, got {}",
                &block_hash, block.header.state_index_root, root_hash,
            );
            warn!("{}", &msg);

            clarity_tx.rollback_block();
            return Err(ChainstateError::InvalidStacksBlock(msg));
        }

        debug!("Reached state root {}", root_hash;
               "block_cost" => %block_execution_cost);

        // good to go!
        let block_limit = clarity_tx
            .block_limit()
            .ok_or_else(|| ChainstateError::InvalidChainstateDB)?;
        let clarity_commit =
            clarity_tx.precommit_to_block(&block.header.consensus_hash, &block_hash);

        // calculate the reward for this tenure
        let scheduled_miner_reward = if new_tenure {
            Some(Self::calculate_scheduled_tenure_reward(
                chainstate_tx,
                burn_dbconn,
                block,
                evaluated_epoch,
                parent_coinbase_height,
                chain_tip_burn_header_height.into(),
                burnchain_commit_burn,
                burnchain_sortition_burn,
            )?)
        } else {
            None
        };

        // extract matured rewards info -- we'll need it for the receipt
        let matured_rewards_info_opt = matured_miner_rewards_opt
            .as_ref()
            .map(|rewards| rewards.reward_info.clone());

        let new_tip = Self::advance_tip(
            &mut chainstate_tx.tx,
            &parent_chain_tip.anchored_header,
            &parent_chain_tip.consensus_hash,
            &block.header,
            vrf_proof_opt,
            chain_tip_burn_header_hash,
            chain_tip_burn_header_height,
            chain_tip_burn_header_timestamp,
            scheduled_miner_reward.as_ref(),
            matured_miner_rewards_opt,
            &block_execution_cost,
            &total_tenure_cost,
            block_size,
            applied_epoch_transition,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
            burn_vote_for_aggregate_key_ops,
            new_tenure,
            block_fees,
        )
        .expect("FATAL: failed to advance chain tip");

        let new_block_id = new_tip.index_block_hash();
        chainstate_tx.log_transactions_processed(&new_block_id, &tx_receipts);

        // store the reward set calculated during this block if it happened
        // NOTE: miner and proposal evaluation should not invoke this because
        //  it depends on knowing the StacksBlockId.
        let signers_updated = signer_set_calc.is_some();
        let mut reward_set_data = None;
        if let Some(signer_calculation) = signer_set_calc {
            Self::write_reward_set(chainstate_tx, &new_block_id, &signer_calculation.reward_set)?;

            let cycle_number = if let Some(cycle) = pox_constants.reward_cycle_of_prepare_phase(
                first_block_height.into(),
                chain_tip_burn_header_height.into(),
            ) {
                Some(cycle)
            } else {
                pox_constants
                    .block_height_to_reward_cycle(
                        first_block_height.into(),
                        chain_tip_burn_header_height.into(),
                    )
                    .map(|cycle| cycle + 1)
            };

            if let Some(cycle) = cycle_number {
                reward_set_data = Some(RewardSetData::new(
                    signer_calculation.reward_set.clone(),
                    cycle,
                ));
            }
        }

        monitoring::set_last_block_transaction_count(u64::try_from(block.txs.len()).unwrap());
        monitoring::set_last_execution_cost_observed(&block_execution_cost, &block_limit);

        // get burn block stats, for the transaction receipt
        let (parent_burn_block_hash, parent_burn_block_height, parent_burn_block_timestamp) =
            if block.is_first_mined() {
                (BurnchainHeaderHash([0; 32]), 0, 0)
            } else {
                let sn = SortitionDB::get_block_snapshot_consensus(burn_dbconn, &parent_ch)?
                    .ok_or_else(|| {
                        // shouldn't happen
                        warn!(
                            "CORRUPTION: {} does not correspond to a burn block",
                            &parent_ch
                        );
                        ChainstateError::InvalidStacksBlock("No parent consensus hash".into())
                    })?;
                (
                    sn.burn_header_hash,
                    sn.block_height,
                    sn.burn_header_timestamp,
                )
            };

        let epoch_receipt = StacksEpochReceipt {
            header: new_tip,
            tx_receipts,
            matured_rewards,
            matured_rewards_info: matured_rewards_info_opt,
            parent_microblocks_cost: ExecutionCost::zero(),
            anchored_block_cost: block_execution_cost,
            parent_burn_block_hash,
            parent_burn_block_height: u32::try_from(parent_burn_block_height).unwrap_or(0), // shouldn't be fatal
            parent_burn_block_timestamp,
            evaluated_epoch,
            epoch_transition: applied_epoch_transition,
            signers_updated,
        };

        Ok((epoch_receipt, clarity_commit, reward_set_data))
    }

    /// Create a StackerDB config for the .miners contract.
    /// It has two slots -- one for the past two sortition winners.
    pub fn make_miners_stackerdb_config(
        sortdb: &SortitionDB,
        tip: &BlockSnapshot,
    ) -> Result<StackerDBConfig, ChainstateError> {
        let ih = sortdb.index_handle(&tip.sortition_id);
        let last_winner_snapshot = ih.get_last_snapshot_with_sortition(tip.block_height)?;
        let parent_winner_snapshot = ih.get_last_snapshot_with_sortition(
            last_winner_snapshot.block_height.saturating_sub(1),
        )?;

        let mut miner_key_hash160s = vec![];

        // go get their corresponding leader keys, but preserve the miner's relative position in
        // the stackerdb signer list -- if a miner was in slot 0, then it should stay in slot 0
        // after a sortition (and vice versa for 1)
        let sns = if last_winner_snapshot.num_sortitions % 2 == 0 {
            [last_winner_snapshot, parent_winner_snapshot]
        } else {
            [parent_winner_snapshot, last_winner_snapshot]
        };

        for sn in sns {
            // find the commit
            let Some(block_commit) =
                ih.get_block_commit_by_txid(&sn.sortition_id, &sn.winning_block_txid)?
            else {
                warn!(
                    "No block commit for {} in sortition for {}",
                    &sn.winning_block_txid, &sn.consensus_hash
                );
                return Err(ChainstateError::InvalidStacksBlock(
                    "No block-commit in sortition for block's consensus hash".into(),
                ));
            };

            // key register of the winning miner
            let leader_key = ih
                .get_leader_key_at(
                    u64::from(block_commit.key_block_ptr),
                    u32::from(block_commit.key_vtxindex),
                )?
                .expect("FATAL: have block commit but no leader key");

            // the leader key should always be valid (i.e. the unwrap_or() should be unreachable),
            // but be defensive and just use the "null" address
            miner_key_hash160s.push(
                leader_key
                    .interpret_nakamoto_signing_key()
                    .unwrap_or(Hash160([0x00; 20])),
            );
        }

        let signers = miner_key_hash160s
            .into_iter()
            .map(|hash160|
                // each miner gets two slots
                (
                    StacksAddress {
                        version: 1, // NOTE: the version is ignored in stackerdb; we only care about the hashbytes
                        bytes: hash160
                    },
                    MINER_SLOT_COUNT,
                ))
            .collect();

        Ok(StackerDBConfig {
            chunk_size: MAX_PAYLOAD_LEN.into(),
            signers,
            write_freq: 5,
            max_writes: u32::MAX,  // no limit on number of writes
            max_neighbors: 200, // TODO: const -- just has to be equal to or greater than the number of signers
            hint_replicas: vec![], // TODO: is there a way to get the IP addresses of stackers' preferred nodes?
        })
    }

    /// Get the slot range for the given miner's public key.
    /// Returns Some(Range<u32>) if the miner is in the StackerDB config, where the range of slots for the miner is [start, end).
    ///   i.e., inclusive of `start`, exclusive of `end`.
    /// Returns None if the miner is not in the StackerDB config.
    /// Returns an error if the miner is in the StackerDB config but the slot number is invalid.
    pub fn get_miner_slot(
        sortdb: &SortitionDB,
        tip: &BlockSnapshot,
        miner_pubkey: &StacksPublicKey,
    ) -> Result<Option<Range<u32>>, ChainstateError> {
        let miner_hash160 = Hash160::from_node_public_key(&miner_pubkey);
        let stackerdb_config = Self::make_miners_stackerdb_config(sortdb, &tip)?;

        // find out which slot we're in
        let mut slot_index = 0;
        let mut slot_id_result = None;
        for (addr, slot_count) in stackerdb_config.signers.iter() {
            if addr.bytes == miner_hash160 {
                slot_id_result = Some(Range {
                    start: slot_index,
                    end: slot_index + slot_count,
                });
                break;
            }
            slot_index += slot_count;
        }

        let Some(slot_id_range) = slot_id_result else {
            // miner key does not match any slot
            warn!("Miner is not in the miners StackerDB config";
                  "miner" => %miner_hash160,
                  "stackerdb_slots" => format!("{:?}", &stackerdb_config.signers));

            return Ok(None);
        };
        Ok(Some(slot_id_range))
    }

    /// Boot code instantiation for the aggregate public key.
    /// TODO: This should be removed once it's possible for stackers to vote on the aggregate
    /// public key
    /// DO NOT USE IN MAINNET
    pub fn aggregate_public_key_bootcode(clarity_tx: &mut ClarityTx, apk: &Point) {
        let agg_pub_key = to_hex(&apk.compress().data);
        let contract_content = format!(
            "(define-read-only ({}) 0x{})",
            BOOT_TEST_POX_4_AGG_KEY_FNAME, agg_pub_key
        );
        // NOTE: this defaults to a testnet address to prevent it from ever working on
        // mainnet
        let contract_id = boot_code_id(BOOT_TEST_POX_4_AGG_KEY_CONTRACT, false);
        clarity_tx.connection().as_transaction(|clarity| {
            let (ast, analysis) = clarity
                .analyze_smart_contract(
                    &contract_id,
                    ClarityVersion::Clarity2,
                    &contract_content,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity
                .initialize_smart_contract(
                    &contract_id,
                    ClarityVersion::Clarity2,
                    &ast,
                    &contract_content,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity.save_analysis(&contract_id, &analysis).unwrap();
        })
    }
}

impl StacksMessageCodec for NakamotoBlock {
    fn consensus_serialize<W: std::io::Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.header)?;
        write_next(fd, &self.txs)
    }

    fn consensus_deserialize<R: std::io::Read>(fd: &mut R) -> Result<Self, CodecError> {
        let (header, txs) = {
            let mut bound_read = BoundReader::from_reader(fd, u64::from(MAX_MESSAGE_LEN));
            let header: NakamotoBlockHeader = read_next(&mut bound_read)?;
            let txs: Vec<_> = read_next(&mut bound_read)?;
            (header, txs)
        };

        // all transactions are unique
        if !StacksBlock::validate_transactions_unique(&txs) {
            warn!("Invalid block: Found duplicate transaction"; "block_hash" => header.block_hash());
            return Err(CodecError::DeserializeError(
                "Invalid block: found duplicate transaction".to_string(),
            ));
        }

        // header and transactions must be consistent
        let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

        let merkle_tree = MerkleTree::new(&txid_vecs);
        let tx_merkle_root: Sha512Trunc256Sum = merkle_tree.root();

        if tx_merkle_root != header.tx_merkle_root {
            warn!("Invalid block: Tx Merkle root mismatch"; "block_hash" => header.block_hash());
            return Err(CodecError::DeserializeError(
                "Invalid block: tx Merkle root mismatch".to_string(),
            ));
        }

        Ok(NakamotoBlock { header, txs })
    }
}
