// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::collections::HashSet;
use std::ops::DerefMut;

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::BurnStateDB;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::StacksAddressExtensions;
use lazy_static::{__Deref, lazy_static};
use rusqlite::types::{FromSql, FromSqlError};
use rusqlite::{params, Connection, OptionalExtension, ToSql, NO_PARAMS};
use sha2::{Digest as Sha2Digest, Sha512_256};
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_MESSAGE_LEN,
};
use stacks_common::consts::{
    FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, MINER_REWARD_MATURITY,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksBlockId, StacksPrivateKey,
    StacksPublicKey, TrieHash, VRFSeed,
};
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{to_hex, Hash160, MerkleHashFunc, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey, VRF};

use super::burn::db::sortdb::{
    get_ancestor_sort_id_tx, get_block_commit_by_txid, SortitionHandleConn, SortitionHandleTx,
};
use super::burn::operations::{DelegateStxOp, StackStxOp, TransferStxOp};
use super::stacks::db::accounts::MinerReward;
use super::stacks::db::blocks::StagingUserBurnSupport;
use super::stacks::db::{
    ChainstateTx, ClarityTx, MinerPaymentSchedule, MinerPaymentTxFees, MinerRewardInfo,
    StacksBlockHeaderTypes, StacksDBTx, StacksEpochReceipt, StacksHeaderInfo,
};
use super::stacks::events::StacksTransactionReceipt;
use super::stacks::{
    Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksMicroblock, StacksTransaction,
    TenureChangeCause, TenureChangePayload, TransactionPayload,
};
use crate::burnchains::{PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::{LeaderBlockCommitOp, LeaderKeyRegisterOp};
use crate::chainstate::burn::{BlockSnapshot, SortitionHash};
use crate::chainstate::coordinator::{BlockEventDispatcher, Error};
use crate::chainstate::stacks::db::{DBConfig as ChainstateConfig, StacksChainState};
use crate::chainstate::stacks::{MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH};
use crate::clarity_vm::clarity::{ClarityInstance, PreCommitClarityBlock};
use crate::clarity_vm::database::SortitionDBRef;
use crate::core::BOOT_BLOCK_HASH;
use crate::monitoring;
use crate::net::Error as net_error;
use crate::util_lib::db::{
    query_int, query_row, query_row_panic, query_rows, u64_to_sql, DBConn, Error as DBError,
    FromRow,
};

pub mod coordinator;
pub mod miner;

#[cfg(test)]
pub mod tests;

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
      -- Table for staging nakamoto blocks
      -- TODO: this goes into its own DB at some point
      CREATE TABLE nakamoto_staging_blocks (
                     -- SHA512/256 hash of this block
                     block_hash TEXT NOT NULL,
                     -- the consensus hash of the burnchain block that selected this block's miner's block-commit
                     consensus_hash TEXT NOT NULL,
                     -- the parent index_block_hash
                     parent_block_id TEXT NOT NULL,

                     -- has the burnchain block with this block's `consensus_hash` been processed?
                     burn_attachable INT NOT NULL,
                     -- has the parent Stacks block been processed?
                     stacks_attachable INT NOT NULL,
                     -- set to 1 if this block can never be attached
                     orphaned INT NOT NULL,
                     -- has this block been processed?
                     processed INT NOT NULL,

                     height INT NOT NULL,

                     -- used internally -- this is the StacksBlockId of this block's consensus hash and block hash
                     index_block_hash TEXT NOT NULL,
                     -- how long the block was in-flight
                     download_time INT NOT NULL,
                     -- when this block was stored
                     arrival_time INT NOT NULL,
                     -- when this block was processed
                     processed_time INT NOT NULL,

                     -- block data
                     data BLOB NOT NULL,
                    
                     PRIMARY KEY(block_hash,consensus_hash)
    );"#.into(),
    r#"
        -- Table for all processed tenures.
        -- This represents all BlockFound tenure changes, not extensions.
        -- Every time we insert a header which has `tenure_changed == 1`, we should insert a record into this table as well.
        -- Note that not every sortition is represented here.  If a tenure is extended, then no new tenure record is created
        -- for it.
        CREATE TABLE nakamoto_tenures (
            -- consensus hash of start-tenure block (i.e. the consensus hash of the sortition in which the miner's block-commit
            -- was mined)
            consensus_hash TEXT NOT NULL,
            -- consensus hash of the previous tenure's start-tenure block
            prev_consensus_hash TEXT NOT NULL,
            -- block hash of start-tenure block
            block_hash TEXT NOT NULL,
            -- block ID of this start block (this is the StacksBlockId of the above consensus_hash and block_hash)
            block_id TEXT NOT NULL,
            -- this field is the total number of *tenures* in the chain history (including this tenure),
            -- as of the _end_ of this block.  A block can contain multiple TenureChanges; if so, then this
            -- is the height of the _last_ TenureChange.
            tenure_height INTEGER NOT NULL,
            -- number of blocks this tenure confirms
            num_blocks_confirmed INTEGER NOT NULL,

            PRIMARY KEY(consensus_hash)
        );
        CREATE INDEX nakamoto_tenures_by_block_id ON nakamoto_tenures(block_id);
        CREATE INDEX nakamoto_tenures_by_block_and_consensus_hashes ON nakamoto_tenures(consensus_hash,block_hash);
    "#.into(),
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
                     -- stackers' signature over the block
                     stacker_signature TEXT NOT NULL,
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
              PRIMARY KEY(consensus_hash,block_hash),
              FOREIGN KEY(consensus_hash) REFERENCES nakamoto_tenures(consensus_hash)
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
        let mut ret = vec![];
        ret.push(self.recipient.clone());
        ret.push(self.parent_reward.clone());
        ret
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
}

#[derive(Debug, Clone, PartialEq)]
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
    /// Recoverable ECDSA signature from the stacker set active during the tenure.
    /// TODO: This is a placeholder
    pub stacker_signature: MessageSignature,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NakamotoBlock {
    pub header: NakamotoBlockHeader,
    pub txs: Vec<StacksTransaction>,
}

pub struct NakamotoChainState;

#[derive(Debug, Clone, PartialEq)]
pub struct NakamotoTenure {
    /// consensus hash of start-tenure block
    pub consensus_hash: ConsensusHash,
    /// consensus hash of parent tenure's start-tenure block
    pub prev_consensus_hash: ConsensusHash,
    /// block hash of start-tenure block
    pub block_hash: BlockHeaderHash,
    /// block ID of this start block
    pub block_id: StacksBlockId,
    /// number of tenures so far, including this one
    pub tenure_height: u64,
    /// number of blocks this tenure confirms
    pub num_blocks_confirmed: u32,
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
        let stacker_signature = row.get("stacker_signature")?;
        let miner_signature = row.get("miner_signature")?;

        Ok(NakamotoBlockHeader {
            version,
            chain_length,
            burn_spent,
            consensus_hash,
            parent_block_id,
            tx_merkle_root,
            state_index_root,
            stacker_signature,
            miner_signature,
        })
    }
}

impl FromRow<NakamotoTenure> for NakamotoTenure {
    fn from_row(row: &rusqlite::Row) -> Result<NakamotoTenure, DBError> {
        let consensus_hash = row.get("consensus_hash")?;
        let prev_consensus_hash = row.get("prev_consensus_hash")?;
        let block_hash = row.get("block_hash")?;
        let block_id = row.get("block_id")?;
        let tenure_height_i64: i64 = row.get("tenure_height")?;
        let tenure_height = tenure_height_i64
            .try_into()
            .map_err(|_| DBError::ParseError)?;
        let num_blocks_confirmed: u32 = row.get("num_blocks_confirmed")?;
        Ok(NakamotoTenure {
            consensus_hash,
            prev_consensus_hash,
            block_hash,
            block_id,
            tenure_height,
            num_blocks_confirmed,
        })
    }
}

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
        write_next(fd, &self.stacker_signature)?;

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
            stacker_signature: read_next(fd)?,
        })
    }
}

impl NakamotoBlockHeader {
    /// Calculate the message digest to sign.
    /// This includes all fields _except_ the signatures.
    pub fn signature_hash(&self) -> Result<Sha512Trunc256Sum, CodecError> {
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

    pub fn recover_miner_pk(&self) -> Option<StacksPublicKey> {
        let signed_hash = self.signature_hash().ok()?;
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
        let sighash = self.signature_hash()?.0;
        let sig = privk
            .sign(&sighash)
            .map_err(|se| net_error::SigningError(se.to_string()))?;
        self.miner_signature = sig;
        Ok(())
    }

    /// Make an "empty" header whose block data needs to be filled in.
    /// This is used by the miner code.
    pub fn from_parent_empty(
        chain_length: u64,
        burn_spent: u64,
        consensus_hash: ConsensusHash,
        parent_block_id: StacksBlockId,
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
            stacker_signature: MessageSignature::empty(),
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
            stacker_signature: MessageSignature::empty(),
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
            stacker_signature: MessageSignature::empty(),
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
    /// If it's present, then it's the first transaction (i.e. tx 0)
    pub fn get_tenure_change_tx(&self) -> Option<&StacksTransaction> {
        let wellformed = self.is_wellformed_tenure_start_block();
        if let Some(false) = wellformed {
            // block isn't well-formed
            return None;
        }

        // if it exists, it's the first
        self.txs.get(0).and_then(|tx| {
            if let TransactionPayload::TenureChange(..) = &tx.payload {
                Some(tx)
            } else {
                None
            }
        })
    }

    /// Get the coinbase transaction in Nakamoto.
    /// It's the first non-TenureChange transaction (i.e. tx 1)
    pub fn get_coinbase_tx(&self) -> Option<&StacksTransaction> {
        let wellformed = self.is_wellformed_tenure_start_block();
        if wellformed.is_none() {
            // block isn't a first-tenure block, so no coinbase
            return None;
        }
        if let Some(false) = wellformed {
            // block isn't well-formed
            return None;
        }

        // there is one coinbase.
        // go find it.
        self.txs.iter().find(|tx| {
            if let TransactionPayload::Coinbase(..) = &tx.payload {
                true
            } else {
                false
            }
        })
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

    /// Determine if this is a well-formed first block in a tenure.
    /// * It has exactly one TenureChange, and it requires a sortition and points to the parent of
    /// this block (this checks `cause` and `previous_tenure_end`)
    /// * It then has a Nakamoto coinbase
    /// * Coinbases and TenureChanges do not occur anywhere else
    ///
    /// Returns Some(true) if the above are true
    /// Returns Some(false) if this block has at least one coinbase or TenureChange tx, but one of
    /// the above checks are false
    /// Returns None if this block has no coinbase or TenureChange txs
    pub fn is_wellformed_tenure_start_block(&self) -> Option<bool> {
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
            return None;
        }

        if coinbase_positions.len() > 1 || tenure_change_positions.len() > 1 {
            // never valid to have more than one of each
            return Some(false);
        }

        if coinbase_positions.len() == 1 && tenure_change_positions.len() == 0 {
            // coinbase unaccompanied by a tenure change
            return Some(false);
        }

        if coinbase_positions.len() == 0 && tenure_change_positions.len() == 1 {
            // this is possibly a block with a tenure-extend transaction.
            // It must be the first tx
            if tenure_change_positions != vec![0] {
                // wrong position
                return Some(false);
            }

            // must be a non-sortition-triggered tenure change
            let TransactionPayload::TenureChange(tc_payload) = &self.txs[0].payload else {
                // this transaction is not a tenure change
                // (should be unreachable)
                return Some(false);
            };

            if tc_payload.cause.expects_sortition() {
                // not valid
                return Some(false);
            }

            // not a tenure-start block, but syntactically valid w.r.t. tenure changes
            return None;
        }

        // have both a coinbase and a tenure-change
        let tc_idx = 0;
        let coinbase_idx = 1;
        if coinbase_positions != vec![coinbase_idx] || tenure_change_positions != vec![tc_idx] {
            // invalid -- expect exactly one sortition-induced tenure change and exactly one coinbase expected,
            // and the tenure change must be the first transaction and the coinbase must be the second transaction
            return Some(false);
        }

        // must be a sortition-triggered tenure change that points to our parent block
        let TransactionPayload::TenureChange(tc_payload) = &self.txs[tc_idx].payload else {
            // this transaction is not a tenure change
            // (should be unreachable)
            return Some(false);
        };
        if !tc_payload.cause.expects_sortition() {
            // the only tenure change allowed in a block with a coinbase is a sortition-triggered
            // tenure change
            return Some(false);
        }
        if tc_payload.previous_tenure_end != self.header.parent_block_id {
            // discontinuous
            return Some(false);
        }

        // must be a Nakamoto coinbase
        let TransactionPayload::Coinbase(_, _, vrf_proof_opt) = &self.txs[coinbase_idx].payload
        else {
            // this transaction is not a coinbase (but this should be unreachable)
            return Some(false);
        };
        if vrf_proof_opt.is_none() {
            // not a Nakamoto coinbase
            return Some(false);
        }

        return Some(true);
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
    pub(crate) fn get_miner_pubkh(&self) -> Result<Hash160, ChainstateError> {
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
        let recovered_miner_hash160 = self.get_miner_pubkh()?;
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
    /// this is a no-op
    pub(crate) fn check_tenure_change_tx(&self) -> Result<(), ChainstateError> {
        // If this block has a tenure-change, then verify that the miner public key is the same as
        // the leader key.  This is required for all tenure-change causes.
        if let Some(tenure_change_tx) = self.get_tenure_change_tx() {
            // in all cases, the miner public key must match that of the tenure change
            let tc_payload = tenure_change_tx
                .try_as_tenure_change()
                .expect("FATAL: `get_tenure_change_tx()` did not return a tenure-change");
            let recovered_miner_hash160 = self.get_miner_pubkh()?;
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
            if tc_payload.consensus_hash != self.header.consensus_hash {
                warn!(
                    "Invalid tenure-change transaction -- bad consensus hash";
                    "block_hash" => %self.header.block_hash(),
                    "block_id" => %self.header.block_id(),
                    "consensus_hash" => %self.header.consensus_hash,
                    "tc_payload.consensus_hash" => %tc_payload.consensus_hash
                );
                return Err(ChainstateError::InvalidStacksBlock(
                    "Invalid tenure change -- bad consensus hash".into(),
                ));
            }
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
    /// -- `burn_chain_tip` is the BlockSnapshot containing the block-commit for this block's
    /// tenure
    /// -- `leader_key` is the miner's leader key registration transaction
    /// -- `bloc_commit` is the block-commit for this tenure
    ///
    /// Verifies the following:
    /// -- (self.header.consensus_hash) that this block falls into this block-commit's tenure
    /// -- (self.header.burn_spent) that this block's burn total matches `burn_chain_tip`'s total burn
    /// -- (self.header.miner_signature) that this miner signed this block
    /// -- if this block has a tenure change, then it's consistent with the miner's public key and
    /// self.header.consensus_hash
    /// -- if this block has a coinbase, then that it's VRF proof was generated by this miner
    pub fn validate_against_burnchain(
        &self,
        burn_chain_tip: &BlockSnapshot,
        leader_key: &LeaderKeyRegisterOp,
    ) -> Result<(), ChainstateError> {
        // this block's consensus hash must match the sortition that selected it
        if burn_chain_tip.consensus_hash != self.header.consensus_hash {
            warn!("Invalid Nakamoto block: consensus hash does not match sortition";
                  "consensus_hash" => %self.header.consensus_hash,
                  "sortition.consensus_hash" => %burn_chain_tip.consensus_hash
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: invalid consensus hash".into(),
            ));
        }

        // this block must commit to all of the work seen so far
        if self.header.burn_spent != burn_chain_tip.total_burn {
            warn!("Invalid Nakamoto block header: invalid total burns";
                  "header.burn_spent" => self.header.burn_spent,
                  "burn_chain_tip.total_burn" => burn_chain_tip.total_burn
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Invalid Nakamoto block: invalid total burns".into(),
            ));
        }

        // miner must have signed this block
        let miner_pubkey_hash160 = leader_key
            .interpret_nakamoto_signing_key()
            .ok_or(ChainstateError::NoSuchBlockError)
            .map_err(|e| {
                warn!(
                    "Leader key did not contain a hash160 of the miner signing public key";
                    "leader_key" => format!("{:?}", &leader_key),
                );
                e
            })?;

        self.check_miner_signature(&miner_pubkey_hash160)?;
        self.check_tenure_change_tx()?;
        self.check_coinbase_tx(&leader_key.public_key, &burn_chain_tip.sortition_hash)?;

        // not verified by this method:
        // * chain_length       (need parent block header)
        // * parent_block_id    (need parent block header)
        // * block-commit seed  (need parent block)
        // * tx_merkle_root     (already verified; validated on deserialization)
        // * state_index_root   (validated on process_block())
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
        if let Some(valid) = self.is_wellformed_tenure_start_block() {
            if !valid {
                // bad tenure change
                return false;
            }
            if self.get_coinbase_tx().is_none() {
                return false;
            }
            if self.get_tenure_change_tx().is_none() {
                return false;
            }
        }
        if !StacksBlock::validate_transactions_static_epoch(&self.txs, epoch_id) {
            return false;
        }
        return true;
    }
}

impl StacksChainState {
    /// Begin a transaction against the staging blocks DB.
    /// Note that this DB is (or will eventually be) in a separate database from the headers.
    pub fn staging_db_tx_begin<'a>(
        &'a mut self,
    ) -> Result<rusqlite::Transaction<'a>, ChainstateError> {
        // TODO: this should be against a separate DB!
        self.db_tx_begin()
    }
}

impl NakamotoChainState {
    /// Notify the staging database that a given stacks block has been processed.
    /// This will update the attachable status for children blocks, as well as marking the stacks
    ///  block itself as processed.
    pub fn set_block_processed(
        staging_db_tx: &rusqlite::Transaction,
        block: &StacksBlockId,
    ) -> Result<(), ChainstateError> {
        let update_dependents = "UPDATE nakamoto_staging_blocks SET stacks_attachable = 1
                                 WHERE parent_block_id = ?";
        staging_db_tx.execute(&update_dependents, &[&block])?;

        let clear_staged_block =
            "UPDATE nakamoto_staging_blocks SET processed = 1, processed_time = ?2
                                  WHERE index_block_hash = ?1";
        staging_db_tx.execute(
            &clear_staged_block,
            params![&block, &u64_to_sql(get_epoch_time_secs())?],
        )?;

        Ok(())
    }

    /// Modify the staging database that a given stacks block can never be processed.
    /// This will update the attachable status for children blocks, as well as marking the stacks
    ///  block itself as orphaned.
    pub fn set_block_orphaned(
        staging_db_tx: &rusqlite::Transaction,
        block: &StacksBlockId,
    ) -> Result<(), ChainstateError> {
        let update_dependents =
            "UPDATE nakamoto_staging_blocks SET stacks_attachable = 0, orphaned = 1
                                 WHERE parent_block_id = ?";
        staging_db_tx.execute(&update_dependents, &[&block])?;

        let clear_staged_block =
            "UPDATE nakamoto_staging_blocks SET processed = 1, processed_time = ?2, orphaned = 1
                                  WHERE index_block_hash = ?1";
        staging_db_tx.execute(
            &clear_staged_block,
            params![&block, &u64_to_sql(get_epoch_time_secs())?],
        )?;

        Ok(())
    }

    /// Notify the staging database that a given burn block has been processed.
    /// This is required for staged blocks to be eligible for processing.
    pub fn set_burn_block_processed(
        staging_db_tx: &rusqlite::Transaction,
        consensus_hash: &ConsensusHash,
    ) -> Result<(), ChainstateError> {
        let update_dependents = "UPDATE nakamoto_staging_blocks SET burn_attachable = 1
                                 WHERE consensus_hash = ?";
        staging_db_tx.execute(&update_dependents, &[consensus_hash])?;

        Ok(())
    }

    /// Find the next ready-to-process Nakamoto block, given a connection to the staging blocks DB.
    /// Returns (the block, the size of the block)
    pub fn next_ready_nakamoto_block(
        staging_db_conn: &Connection,
    ) -> Result<Option<(NakamotoBlock, u64)>, ChainstateError> {
        let query = "SELECT data FROM nakamoto_staging_blocks
                     WHERE burn_attachable = 1
                       AND stacks_attachable = 1
                       AND orphaned = 0
                       AND processed = 0
                     ORDER BY height ASC";
        staging_db_conn
            .query_row_and_then(query, NO_PARAMS, |row| {
                let data: Vec<u8> = row.get("data")?;
                let block = NakamotoBlock::consensus_deserialize(&mut data.as_slice())?;
                Ok(Some((
                    block,
                    u64::try_from(data.len()).expect("FATAL: block is bigger than a u64"),
                )))
            })
            .or_else(|e| {
                if let ChainstateError::DBError(DBError::SqliteError(
                    rusqlite::Error::QueryReturnedNoRows,
                )) = e
                {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
    }

    /// Extract and parse a nakamoto block from the DB, and verify its integrity.
    pub fn load_nakamoto_block(
        staging_db_conn: &Connection,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<NakamotoBlock>, ChainstateError> {
        let query = "SELECT data FROM nakamoto_staging_blocks WHERE consensus_hash = ?1 AND block_hash = ?2";
        staging_db_conn
            .query_row_and_then(
                query,
                rusqlite::params![consensus_hash, block_hash],
                |row| {
                    let data: Vec<u8> = row.get("data")?;
                    let block = NakamotoBlock::consensus_deserialize(&mut data.as_slice())
                        .map_err(|_| DBError::ParseError)?;
                    if &block.header.block_hash() != block_hash {
                        error!(
                            "Staging DB corruption: expected {}, got {}",
                            &block_hash,
                            &block.header.block_hash()
                        );
                        return Err(DBError::Corruption.into());
                    }
                    Ok(Some(block))
                },
            )
            .or_else(|e| {
                if let ChainstateError::DBError(DBError::SqliteError(
                    rusqlite::Error::QueryReturnedNoRows,
                )) = e
                {
                    Ok(None)
                } else {
                    Err(e.into())
                }
            })
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
        let (mut chainstate_tx, clarity_instance) = stacks_chain_state.chainstate_tx_begin()?;
        let Some((next_ready_block, block_size)) =
            Self::next_ready_nakamoto_block(&chainstate_tx.tx)?
        else {
            // no more blocks
            return Ok(None);
        };

        let block_id = next_ready_block.block_id();

        // find corresponding snapshot
        let next_ready_block_snapshot = SortitionDB::get_block_snapshot_consensus(
            sort_tx,
            &next_ready_block.header.consensus_hash,
        )?
        .expect(&format!(
            "CORRUPTION: staging Nakamoto block {}/{} does not correspond to a burn block",
            &next_ready_block.header.consensus_hash,
            &next_ready_block.header.block_hash()
        ));

        debug!("Process staging Nakamoto block";
               "consensus_hash" => %next_ready_block.header.consensus_hash,
               "block_hash" => %next_ready_block.header.block_hash(),
               "burn_block_hash" => %next_ready_block_snapshot.burn_header_hash
        );

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
            let msg = "Discontinuous Nakamoto Stacks block";
            warn!("{}", &msg;
                  "child parent_block_id" => %next_ready_block.header.parent_block_id,
                  "expected parent_block_id" => %parent_block_id
            );
            let _ = Self::set_block_orphaned(&chainstate_tx.tx, &block_id);
            chainstate_tx.commit()?;
            return Err(ChainstateError::InvalidStacksBlock(msg.into()));
        }

        // find commit and sortition burns if this is a tenure-start block
        let new_tenure =
            if let Some(tenure_valid) = next_ready_block.is_wellformed_tenure_start_block() {
                if !tenure_valid {
                    return Err(ChainstateError::InvalidStacksBlock(
                        "Invalid Nakamoto block: invalid tenure change tx(s)".into(),
                    ));
                }
                true
            } else {
                false
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
        let (receipt, clarity_commit) = match NakamotoChainState::append_block(
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
            Ok(next_chain_tip_info) => next_chain_tip_info,
            Err(e) => {
                test_debug!(
                    "Failed to append {}/{}: {:?}",
                    &next_ready_block.header.consensus_hash,
                    &next_ready_block.header.block_hash(),
                    &e
                );
                let _ = Self::set_block_orphaned(&chainstate_tx.tx, &block_id);
                chainstate_tx.commit()?;
                return Err(e);
            }
        };

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
            );
        }

        // this will panic if the Clarity commit fails.
        clarity_commit.commit();
        chainstate_tx.commit()
            .unwrap_or_else(|e| {
                error!("Failed to commit chainstate transaction after committing Clarity block. The chainstate database is now corrupted.";
                       "error" => ?e);
                panic!()
            });

        Ok(Some(receipt))
    }

    /// Validate that a Nakamoto block attaches to the burn chain state.
    /// Called before inserting the block into the staging DB.
    /// Wraps `NakamotoBlock::validate_against_burnchain()`, and
    /// verifies that all transactions in the block are allowed in this epoch.
    pub fn validate_nakamoto_block_burnchain(
        db_handle: &SortitionHandleConn,
        block: &NakamotoBlock,
        mainnet: bool,
        chain_id: u32,
    ) -> Result<(), ChainstateError> {
        // find the sortition-winning block commit for this block, as well as the block snapshot
        // containing the parent block-commit
        let block_hash = block.header.block_hash();
        let consensus_hash = &block.header.consensus_hash;

        // burn chain tip that selected this commit's block
        let Some(burn_chain_tip) =
            SortitionDB::get_block_snapshot_consensus(db_handle, &consensus_hash)?
        else {
            warn!("No sortition for {}", &consensus_hash);
            return Err(ChainstateError::InvalidStacksBlock(
                "No sortition for block's consensus hash".into(),
            ));
        };

        // the block-commit itself
        let Some(block_commit) = db_handle.get_block_commit_by_txid(
            &burn_chain_tip.sortition_id,
            &burn_chain_tip.winning_block_txid,
        )?
        else {
            warn!(
                "No block commit for {} in sortition for {}",
                &burn_chain_tip.winning_block_txid, &consensus_hash
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
        if let Err(e) = block.validate_against_burnchain(&burn_chain_tip, &leader_key) {
            warn!(
                "Invalid Nakamoto block, could not validate on burnchain";
                "consensus_hash" => %consensus_hash,
                "block_hash" => %block_hash,
                "error" => format!("{:?}", &e)
            );

            return Err(e);
        }

        // check the _next_ block's tenure, since when Nakamoto's miner activates, the current chain tip
        // will be in epoch 2.5 (the next block will be epoch 3.0)
        let cur_epoch =
            SortitionDB::get_stacks_epoch(db_handle.deref(), burn_chain_tip.block_height + 1)?
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
        staging_db_tx: &rusqlite::Transaction,
        block: NakamotoBlock,
        burn_attachable: bool,
        stacks_attachable: bool,
    ) -> Result<(), ChainstateError> {
        let block_id = block.block_id();
        staging_db_tx.execute(
            "INSERT INTO nakamoto_staging_blocks (
                     block_hash,
                     consensus_hash,
                     parent_block_id,
                     burn_attachable,
                     stacks_attachable,
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
                if burn_attachable { 1 } else { 0 },
                if stacks_attachable { 1 } else { 0 },
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
        sortdb: &SortitionHandleConn,
        staging_db_tx: &rusqlite::Transaction,
    ) -> Result<bool, ChainstateError> {
        test_debug!("Consider Nakamoto block {}", &block.block_id());
        // do nothing if we already have this block
        if let Some(_) = Self::get_block_header(&staging_db_tx, &block.header.block_id())? {
            debug!("Already have block {}", &block.header.block_id());
            return Ok(false);
        }

        // if this is the first tenure block, then make sure it's well-formed
        if let Some(false) = block.is_wellformed_tenure_start_block() {
            warn!(
                "Block {} is not a well-formed first tenure block",
                &block.block_id()
            );
            return Err(ChainstateError::InvalidStacksBlock(
                "Not a well-formed first block".into(),
            ));
        }

        // this block must be consistent with its miner's leader-key and block-commit, and must
        // contain only transactions that are valid in this epoch.
        if let Err(e) =
            Self::validate_nakamoto_block_burnchain(sortdb, &block, config.mainnet, config.chain_id)
        {
            warn!("Unacceptable Nakamoto block; will not store";
                  "block_id" => %block.block_id(),
                  "error" => format!("{:?}", &e)
            );
            return Ok(false);
        };

        if !sortdb.expects_stacker_signature(
            &block.header.consensus_hash,
            &block.header.stacker_signature,
        )? {
            let msg = format!("Received block, but the stacker signature does not match the active stacking cycle");
            warn!("{}", msg);
            return Err(ChainstateError::InvalidStacksBlock(msg));
        }

        // if the burnchain block of this Stacks block's tenure has been processed, then it
        // is ready to be processed from the perspective of the burnchain
        let burn_attachable = sortdb.processed_block(&block.header.consensus_hash)?;

        // check if the parent Stacks Block ID has been processed. if so, then this block is stacks_attachable
        let stacks_attachable =
            // block is the first-ever mined (test only)
            block.is_first_mined()
            // block attaches to a processed nakamoto block
            || staging_db_tx.query_row(
                "SELECT 1 FROM nakamoto_staging_blocks WHERE index_block_hash = ? AND processed = 1 AND orphaned = 0",
                rusqlite::params![&block.header.parent_block_id],
                |_row| Ok(())
            ).optional()?.is_some()
            // block attaches to a Stacks epoch 2.x block, and there are no nakamoto blocks at all
            || (
                staging_db_tx.query_row(
                    "SELECT 1 FROM block_headers WHERE index_block_hash = ?",
                    rusqlite::params![&block.header.parent_block_id],
                    |_row| Ok(())
                ).optional()?.is_some()
                && staging_db_tx.query_row(
                    "SELECT 1 FROM nakamoto_block_headers LIMIT 1",
                    rusqlite::NO_PARAMS,
                    |_row| Ok(())
                ).optional()?.is_none()
               );

        let block_id = block.block_id();
        Self::store_block(staging_db_tx, block, burn_attachable, stacks_attachable)?;
        test_debug!("Stored Nakamoto block {}", &block_id);
        Ok(true)
    }

    /// Create the block reward for a NakamotoBlock
    /// `coinbase_reward_ustx` is the total coinbase reward for this block, including any
    ///    accumulated rewards from missed sortitions or initial mining rewards.
    /// TODO: unit test
    pub fn make_scheduled_miner_reward(
        mainnet: bool,
        epoch_id: StacksEpochId,
        parent_block_hash: &BlockHeaderHash,
        parent_consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        block_consensus_hash: &ConsensusHash,
        block_height: u64,
        coinbase_tx: &StacksTransaction,
        parent_fees: u128,
        burnchain_commit_burn: u64,
        burnchain_sortition_burn: u64,
        coinbase_reward_ustx: u128,
    ) -> MinerPaymentSchedule {
        let miner_auth = coinbase_tx.get_origin();
        let miner_addr = miner_auth.get_address(mainnet);

        let recipient = if epoch_id >= StacksEpochId::Epoch21 {
            // pay to tx-designated recipient, or if there is none, pay to the origin
            match coinbase_tx.try_as_coinbase() {
                Some((_, recipient_opt, _)) => recipient_opt
                    .cloned()
                    .unwrap_or(miner_addr.to_account_principal()),
                None => miner_addr.to_account_principal(),
            }
        } else {
            // pre-2.1, always pay to the origin
            miner_addr.to_account_principal()
        };

        // N.B. a `MinerPaymentSchedule` that pays to a contract can never be created before 2.1,
        // per the above check (and moreover, a Stacks block with a pay-to-alt-recipient coinbase would
        // not become valid until after 2.1 activates).
        let miner_reward = MinerPaymentSchedule {
            address: miner_addr,
            recipient,
            block_hash: block_hash.clone(),
            consensus_hash: block_consensus_hash.clone(),
            parent_block_hash: parent_block_hash.clone(),
            parent_consensus_hash: parent_consensus_hash.clone(),
            coinbase: coinbase_reward_ustx,
            tx_fees: MinerPaymentTxFees::Nakamoto { parent_fees },
            burnchain_commit_burn,
            burnchain_sortition_burn,
            miner: true,
            stacks_block_height: block_height,
            vtxindex: 0,
        };

        miner_reward
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

    /// Return a Nakamoto StacksHeaderInfo at a given tenure height in the fork identified by `tip_index_hash`.
    /// * For Stacks 2.x, this is the Stacks block's header
    /// * For Stacks 3.x (Nakamoto), this is the first block in the miner's tenure.
    /// TODO: unit test
    pub fn get_header_by_tenure_height(
        tx: &mut StacksDBTx,
        tip_index_hash: &StacksBlockId,
        tenure_height: u64,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        // query for block header info at the tenure-height, then check if in fork
        let qry = "SELECT consensus_hash FROM nakamoto_tenures WHERE tenure_height = ?1";

        let candidate_chs: Vec<ConsensusHash> =
            query_rows(tx.tx(), qry, &[u64_to_sql(tenure_height)?])?;

        if candidate_chs.len() == 0 {
            // no nakamoto_tenures at that tenure height, check if there's a stack block header where
            //   block_height = tenure_height
            let Some(ancestor_at_height) = tx
                .get_ancestor_block_hash(tenure_height, tip_index_hash)?
                .map(|ancestor| Self::get_block_header(tx.tx(), &ancestor))
                .transpose()?
                .flatten()
            else {
                warn!("No such epoch2 ancestor";
                      "tenure_height" => tenure_height,
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

    /// Return the tenure height of `block` if it was a nakamoto block, or the
    ///  Stacks block height of `block` if it was an epoch-2 block
    ///
    /// In Stacks 2.x, the tenure height and block height are the
    /// same. A miner's tenure in Stacks 2.x is entirely encompassed
    /// in the single Bitcoin-anchored Stacks block they produce, as
    /// well as the microblock stream they append to it.
    pub fn get_tenure_height(
        chainstate_conn: &Connection,
        block: &StacksBlockId,
    ) -> Result<Option<u64>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_block_headers WHERE index_block_hash = ?1";
        let result: Option<NakamotoBlockHeader> =
            query_row_panic(chainstate_conn, sql, &[&block], || {
                "FATAL: multiple rows for the same block hash".to_string()
            })?;
        if let Some(nak_hdr) = result {
            let nak_qry = "SELECT tenure_height FROM nakamoto_tenures WHERE consensus_hash = ?1";
            let opt_height: Option<i64> = chainstate_conn
                .query_row(nak_qry, &[&nak_hdr.consensus_hash], |row| row.get(0))
                .optional()?;
            if let Some(height) = opt_height {
                return Ok(Some(
                    u64::try_from(height).map_err(|_| DBError::ParseError)?,
                ));
            } else {
                // should be unreachable
                return Err(DBError::NotFoundError.into());
            }
        }

        let epoch_2_qry = "SELECT block_height FROM block_headers WHERE index_block_hash = ?1";
        let opt_height: Option<i64> = chainstate_conn
            .query_row(epoch_2_qry, &[block], |row| row.get(0))
            .optional()?;
        opt_height
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ChainstateError::DBError(DBError::ParseError))
    }

    /// Load block header (either Epoch-2 rules or Nakamoto) by `index_block_hash`
    pub fn get_block_header(
        chainstate_conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_block_headers WHERE index_block_hash = ?1";
        let result = query_row_panic(chainstate_conn, sql, &[&index_block_hash], || {
            "FATAL: multiple rows for the same block hash".to_string()
        })?;
        if result.is_some() {
            return Ok(result);
        }

        let sql = "SELECT * FROM block_headers WHERE index_block_hash = ?1";
        let result = query_row_panic(chainstate_conn, sql, &[&index_block_hash], || {
            "FATAL: multiple rows for the same block hash".to_string()
        })?;

        Ok(result)
    }

    /// Load the canonical Stacks block header (either epoch-2 rules or Nakamoto)
    /// TODO: unit test
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
    ///
    /// TODO: unit test
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

    /// Get the first block header in a Nakamoto tenure
    pub fn get_nakamoto_tenure_start_block_header(
        chainstate_conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_block_headers WHERE consensus_hash = ?1 ORDER BY block_height ASC LIMIT 1";
        query_row_panic(chainstate_conn, sql, &[&consensus_hash], || {
            "FATAL: multiple rows for the same consensus hash".to_string()
        })
        .map_err(ChainstateError::DBError)
    }

    /// Get the last block header in a Nakamoto tenure
    pub fn get_nakamoto_tenure_finish_block_header(
        chainstate_conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_block_headers WHERE consensus_hash = ?1 ORDER BY block_height DESC LIMIT 1";
        query_row_panic(chainstate_conn, sql, &[&consensus_hash], || {
            "FATAL: multiple rows for the same consensus hash".to_string()
        })
        .map_err(ChainstateError::DBError)
    }

    /// Get the number of blocks in a tenure.
    /// Only works for Nakamoto blocks, not Stacks epoch2 blocks.
    /// Returns 0 if the consensus hash is not found.
    pub fn get_nakamoto_tenure_length(
        chainstate_conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<u32, ChainstateError> {
        let sql = "SELECT IFNULL(COUNT(block_hash),0) FROM nakamoto_block_headers WHERE consensus_hash = ?1";
        let count_i64 = query_int(chainstate_conn, sql, &[&consensus_hash])?;
        let count: u32 = count_i64
            .try_into()
            .expect("FATAL: too many blocks in tenure");
        Ok(count)
    }

    /// Get the status of a Nakamoto block.
    /// Returns Some(accepted?, orphaned?) on success
    /// Returns None if there's no such block
    /// Returns Err on DBError
    pub fn get_nakamoto_block_status(
        staging_blocks_conn: &Connection,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<(bool, bool)>, ChainstateError> {
        let sql = "SELECT processed, orphaned FROM nakamoto_staging_blocks WHERE consensus_hash = ?1 AND block_hash = ?2";
        let args: &[&dyn ToSql] = &[consensus_hash, block_hash];
        Ok(query_row_panic(staging_blocks_conn, sql, args, || {
            "FATAL: multiple rows for the same consensus hash and block hash".to_string()
        })
        .map_err(ChainstateError::DBError)?
        .map(|(processed, orphaned): (u32, u32)| (processed != 0, orphaned != 0)))
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
            &header.stacker_signature,
            &header.tx_merkle_root,
            &header.state_index_root,
            &block_hash,
            &index_block_hash,
            block_cost,
            total_tenure_cost,
            &tenure_tx_fees.to_string(),
            &header.parent_block_id,
            if tenure_changed { &1i64 } else { &0 },
            &vrf_proof_bytes.as_ref(),
        ];

        chainstate_tx.execute(
            "INSERT INTO nakamoto_block_headers
                    (block_height,  index_root, consensus_hash,
                     burn_header_hash, burn_header_height,
                     burn_header_timestamp, block_size,

                     header_type,
                     version, chain_length, burn_spent,
                     miner_signature, stacker_signature, tx_merkle_root, state_index_root,

                     block_hash,
                     index_block_hash,
                     cost,
                     total_tenure_cost,
                     tenure_tx_fees,
                     parent_block_id,
                     tenure_changed,
                     vrf_proof)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
            args
        )?;

        Ok(())
    }

    /// Insert a nakamoto tenure.
    /// No validation will be done.
    pub(crate) fn insert_nakamoto_tenure(
        tx: &Connection,
        block_header: &NakamotoBlockHeader,
        tenure_height: u64,
        tenure: &TenureChangePayload,
    ) -> Result<(), ChainstateError> {
        // NOTE: this is checked with check_nakamoto_tenure()
        assert_eq!(block_header.consensus_hash, tenure.consensus_hash);
        let args: &[&dyn ToSql] = &[
            &tenure.consensus_hash,
            &tenure.prev_consensus_hash,
            &block_header.block_hash(),
            &block_header.block_id(),
            &u64_to_sql(tenure_height)?,
            &tenure.previous_tenure_blocks,
        ];
        tx.execute(
            "INSERT INTO nakamoto_tenures
                (consensus_hash, prev_consensus_hash, block_hash, block_id,
                tenure_height, num_blocks_confirmed)
            VALUES
                (?1,?2,?3,?4,?5,?6)",
            args,
        )?;

        Ok(())
    }

    /// Get the highest tenure height processed.
    /// Returns Ok(Some(tenure_height)) if we have processed at least one tenure
    /// Returns Ok(None) if we have not yet processed a Nakamoto tenure
    /// Returns Err(..) on database errors
    pub fn get_highest_nakamoto_tenure_height(
        conn: &Connection,
    ) -> Result<Option<u64>, ChainstateError> {
        match conn
            .query_row(
                "SELECT IFNULL(MAX(tenure_height), 0) FROM nakamoto_tenures",
                NO_PARAMS,
                |row| Ok(u64::from_row(row).expect("Expected u64 in database")),
            )
            .optional()?
        {
            Some(height_i64) => {
                if height_i64 == 0 {
                    // this never happens, so it's None
                    Ok(None)
                } else {
                    Ok(Some(
                        height_i64.try_into().map_err(|_| DBError::ParseError)?,
                    ))
                }
            }
            None => Ok(None),
        }
    }

    /// Get the highest processed tenure on the canonical sortition history.
    /// TODO: unit test
    pub fn get_highest_nakamoto_tenure(
        conn: &Connection,
        sort_tx: &mut SortitionHandleTx,
    ) -> Result<Option<NakamotoTenure>, ChainstateError> {
        let Some(max_sort_height) = Self::get_highest_nakamoto_tenure_height(conn)? else {
            // no tenures yet
            return Ok(None);
        };

        let sql = "SELECT * FROM nakamoto_tenures WHERE tenure_height = ?1";
        let args: &[&dyn ToSql] = &[&u64_to_sql(max_sort_height)?];
        let tenures: Vec<NakamotoTenure> = query_rows(conn, sql, args)?;
        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_tx)?;

        // find the one that's in the canonical sortition history
        for tenure in tenures.into_iter() {
            let Some(sn) =
                SortitionDB::get_block_snapshot_consensus(sort_tx, &tenure.consensus_hash)?
            else {
                // not in sortition DB.
                // This is unreachable, but be defensive and just skip it.
                continue;
            };
            let Some(_ancestor_sort_id) =
                get_ancestor_sort_id_tx(sort_tx, sn.block_height, &tip.sortition_id)?
            else {
                // not canonical
                continue;
            };
            return Ok(Some(tenure));
        }
        // not found
        Ok(None)
    }

    /// Verify that a tenure change tx is a valid first-ever tenure change.  It must connect to an
    /// epoch2 block.
    /// TODO: unit test
    pub(crate) fn check_first_nakamoto_tenure_change(
        headers_conn: &Connection,
        tenure_payload: &TenureChangePayload,
    ) -> Result<bool, ChainstateError> {
        let Some(parent_header) =
            Self::get_block_header(headers_conn, &tenure_payload.previous_tenure_end)?
        else {
            warn!("Invalid tenure-change: no parent epoch2 header";
                  "consensus_hash" => %tenure_payload.consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(false);
        };
        if parent_header.anchored_header.as_stacks_epoch2().is_none() {
            warn!("Invalid tenure-change: parent header is not epoch2";
                  "consensus_hash" => %tenure_payload.consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(false);
        }
        if tenure_payload.previous_tenure_blocks != 1 {
            warn!("Invalid tenure-change: expected 1 previous tenure block";
                  "consensus_hash" => %tenure_payload.consensus_hash,
            );
            return Ok(false);
        }
        return Ok(true);
    }

    /// Check a Nakamoto tenure transaction's validity with respect to the last-processed tenure
    /// and the sortition DB.  This validates the following fields:
    /// * consensus_hash
    /// * prev_consensus_hash
    /// * previous_tenure_end
    /// * previous_tenure_blocks
    /// * cause
    ///
    /// Returns Ok(true) on success
    /// Returns Ok(false) if the tenure change is invalid
    /// Returns Err(..) on DB error
    /// TODO: unit test
    pub(crate) fn check_nakamoto_tenure(
        headers_conn: &Connection,
        sort_tx: &mut SortitionHandleTx,
        block_header: &NakamotoBlockHeader,
        tenure_payload: &TenureChangePayload,
    ) -> Result<bool, ChainstateError> {
        if !tenure_payload.cause.expects_sortition() {
            // not paired with a sortition
            return Ok(true);
        }

        // block header must match tenure
        if block_header.consensus_hash != tenure_payload.consensus_hash {
            warn!("Invalid tenure-change (or block) -- mismatched consensus hash";
                  "tenure_payload.consensus_hash" => %tenure_payload.consensus_hash,
                  "block_header.consensus_hash" => %block_header.consensus_hash
            );
            return Ok(false);
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_tx)?;

        // the target sortition must exist, and it must be on the canonical fork
        let Some(sn) =
            SortitionDB::get_block_snapshot_consensus(sort_tx, &tenure_payload.consensus_hash)?
        else {
            // no sortition
            warn!("Invalid tenure-change: no such snapshot"; "consensus_hash" => %tenure_payload.consensus_hash);
            return Ok(false);
        };
        let Some(_ancestor_sort_id) =
            get_ancestor_sort_id_tx(sort_tx, sn.block_height, &tip.sortition_id)?
        else {
            // not canonical
            warn!("Invalid tenure-change: snapshot is not canonical"; "consensus_hash" => %tenure_payload.consensus_hash);
            return Ok(false);
        };
        if tenure_payload.prev_consensus_hash != FIRST_BURNCHAIN_CONSENSUS_HASH {
            // the parent sortition must exist, must be canonical, and must be an ancestor of the
            // sortition for the given consensus hash.
            let Some(prev_sn) = SortitionDB::get_block_snapshot_consensus(
                sort_tx,
                &tenure_payload.prev_consensus_hash,
            )?
            else {
                // no parent sortition
                warn!("Invalid tenure-change: no such parent snapshot"; "prev_consensus_hash" => %tenure_payload.prev_consensus_hash);
                return Ok(false);
            };
            let Some(_ancestor_sort_id) =
                get_ancestor_sort_id_tx(sort_tx, sn.block_height, &tip.sortition_id)?
            else {
                // parent not canonical
                warn!("Invalid tenure-change: parent snapshot is not canonical"; "prev_consensus_hash" => %tenure_payload.prev_consensus_hash);
                return Ok(false);
            };
            if prev_sn.block_height >= sn.block_height {
                // parent comes after child
                warn!("Invalid tenure-change: parent snapshot comes after child"; "consensus_hash" => %tenure_payload.consensus_hash, "prev_consensus_hash" => %tenure_payload.prev_consensus_hash);
                return Ok(false);
            }
        }

        // validate cause
        match tenure_payload.cause {
            TenureChangeCause::BlockFound => {
                // there must have been a block-commit which one sortition
                if !sn.sortition {
                    warn!("Invalid tenure-change: no block found";
                          "consensus_hash" => %tenure_payload.consensus_hash
                    );
                    return Ok(false);
                }
            }
            TenureChangeCause::Extended => {}
        }

        let Some(highest_processed_tenure) =
            Self::get_highest_nakamoto_tenure(headers_conn, sort_tx)?
        else {
            // no previous tenures.  This is the first tenure change.  It should point to an epoch
            // 2.x block.
            return Self::check_first_nakamoto_tenure_change(headers_conn, tenure_payload);
        };

        let Some(last_tenure_finish_block_id) = Self::get_nakamoto_tenure_finish_block_header(
            headers_conn,
            &highest_processed_tenure.consensus_hash,
        )?
        .map(|hdr| hdr.index_block_hash()) else {
            // last tenure doesn't exist (should be unreachable)
            warn!("Invalid tenure-change: no blocks found for highest processed tenure";
                  "consensus_hash" => %highest_processed_tenure.consensus_hash,
            );
            return Ok(false);
        };

        if last_tenure_finish_block_id != tenure_payload.previous_tenure_end
            || highest_processed_tenure.consensus_hash != tenure_payload.prev_consensus_hash
        {
            // not continuous -- this tenure-change does not point to the end of the
            // last-processed tenure, or does not point to the last-processed tenure's sortition
            warn!("Invalid tenure-change: discontiguous";
                  "consensus_hash" => %tenure_payload.consensus_hash,
                  "prev_consensus_hash" => %tenure_payload.prev_consensus_hash,
                  "highest_processed_tenure.consensus_hash" => %highest_processed_tenure.consensus_hash,
                  "last_tenure_finish_block_id" => %last_tenure_finish_block_id,
                  "tenure_payload.previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(false);
        }

        let tenure_len = Self::get_nakamoto_tenure_length(
            headers_conn,
            &highest_processed_tenure.consensus_hash,
        )?;
        if tenure_len != tenure_payload.previous_tenure_blocks {
            // invalid -- does not report the correct number of blocks in the past tenure
            warn!("Invalid tenure-change: wrong number of blocks";
                  "consensus_hash" => %tenure_payload.consensus_hash,
                  "highest_processed_tenure.consensus_hash" => %highest_processed_tenure.consensus_hash,
                  "tenure_len" => tenure_len,
                  "tenure_payload.previous_tenure_blocks" => tenure_payload.previous_tenure_blocks
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Advance the tenures table with a validated block's tenure data.
    /// Only stores tenures that are paired with sortitions
    /// TODO: unit test
    pub(crate) fn advance_nakamoto_tenure(
        headers_tx: &mut StacksDBTx,
        sort_tx: &mut SortitionHandleTx,
        block: &NakamotoBlock,
        parent_tenure_height: u64,
    ) -> Result<u64, ChainstateError> {
        let tenure_height = parent_tenure_height
            .checked_add(1)
            .expect("FATAL: too many tenures");

        for tx in block.txs.iter() {
            let TransactionPayload::TenureChange(ref tenure_change_payload) = &tx.payload else {
                continue;
            };

            if !Self::check_nakamoto_tenure(
                headers_tx,
                sort_tx,
                &block.header,
                tenure_change_payload,
            )? {
                return Err(ChainstateError::InvalidStacksTransaction(
                    "Invalid tenure-change".into(),
                    false,
                ));
            }

            Self::insert_nakamoto_tenure(
                headers_tx,
                &block.header,
                tenure_height,
                tenure_change_payload,
            )?;
            return Ok(tenure_height);
        }
        // no new tenure
        return Ok(parent_tenure_height);
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
            StacksChainState::insert_miner_payment_schedule(
                headers_tx.deref_mut(),
                block_reward,
                &[],
            )?;
        }
        StacksChainState::store_burnchain_txids(
            headers_tx.deref(),
            &index_block_hash,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
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

    /// Get scheduled miner rewards that have matured when this tenure starts.
    /// Returns (list of miners to pay, any residual payments to the parent miner) on success.
    /// TODO: unit test
    pub(crate) fn get_matured_miner_reward_schedules(
        chainstate_tx: &mut ChainstateTx,
        tip_index_hash: &StacksBlockId,
        tenure_height: u64,
    ) -> Result<Option<MaturedMinerPaymentSchedules>, ChainstateError> {
        let mainnet = chainstate_tx.get_config().mainnet;

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        if tenure_height < MINER_REWARD_MATURITY {
            return Ok(Some(MaturedMinerPaymentSchedules::genesis(mainnet)));
        }

        let matured_tenure_height = tenure_height - MINER_REWARD_MATURITY;
        let matured_tenure_block_header = Self::get_header_by_tenure_height(
            chainstate_tx,
            &tip_index_hash,
            matured_tenure_height,
        )?
        .ok_or_else(|| {
            warn!("Matured tenure data not found");
            ChainstateError::NoSuchBlockError
        })?;

        let latest_miners = StacksChainState::get_scheduled_block_rewards_at_block(
            chainstate_tx.deref_mut(),
            &matured_tenure_block_header.index_block_hash(),
        )?;
        let parent_miner = StacksChainState::get_parent_matured_miner(
            chainstate_tx.deref_mut(),
            mainnet,
            &latest_miners,
        )?;
        Ok(Some(MaturedMinerPaymentSchedules {
            latest_miners,
            parent_miner,
        }))
    }

    /// Calculate the total matured rewards from the scheduled matured rewards.
    /// This takes a ClarityTx, so PoisonMicroblocks can be taken into account (which deduct
    /// STX from the block reward for offending miners).
    /// The recipient of the block reward may not be the miner, but may be a PoisonMicroblock
    /// reporter (both are captured as the sole `recipient` in the `MaturedMinerRewards` struct).
    ///
    /// Returns Ok(Some(rewards)) if we were able to calculate the rewards
    /// Returns Ok(None) if there are no matured rewards yet
    /// Returns Err(..) on DB error
    /// TODO: unit test
    pub(crate) fn calculate_matured_miner_rewards(
        clarity_tx: &mut ClarityTx,
        sortdb_conn: &Connection,
        parent_stacks_height: u64,
        matured_miner_schedule: MaturedMinerPaymentSchedules,
    ) -> Result<Option<MaturedMinerRewards>, ChainstateError> {
        let matured_miner_rewards_opt = match StacksChainState::find_mature_miner_rewards(
            clarity_tx,
            sortdb_conn,
            parent_stacks_height,
            matured_miner_schedule.latest_miners,
            matured_miner_schedule.parent_miner,
        ) {
            Ok(Some((recipient, _user_burns, parent, reward_info))) => Some(MaturedMinerRewards {
                recipient,
                parent_reward: parent,
                reward_info,
            }),
            Ok(None) => None,
            Err(e) => {
                let msg = format!("Failed to load miner rewards: {:?}", &e);
                warn!("{}", &msg);
                return Err(ChainstateError::InvalidStacksBlock(msg));
            }
        };
        Ok(matured_miner_rewards_opt)
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
    /// * tenure_height: the number of tenures that this block confirms (including epoch2 blocks)
    ///
    /// Returns clarity_tx, list of receipts, microblock execution cost,
    /// microblock fees, microblock burns, list of microblock tx receipts,
    /// miner rewards tuples, the stacks epoch id, and a boolean that
    /// represents whether the epoch transition has been applied.
    pub fn setup_block<'a, 'b>(
        chainstate_tx: &'b mut ChainstateTx,
        clarity_instance: &'a mut ClarityInstance,
        sortition_dbconn: &'b dyn SortitionDBRef,
        pox_constants: &PoxConstants,
        parent_consensus_hash: ConsensusHash,
        parent_header_hash: BlockHeaderHash,
        parent_stacks_height: u64,
        parent_burn_height: u32,
        burn_header_hash: BurnchainHeaderHash,
        burn_header_height: u32,
        new_tenure: bool,
        tenure_height: u64,
    ) -> Result<SetupBlockResult<'a, 'b>, ChainstateError> {
        let parent_index_hash = StacksBlockId::new(&parent_consensus_hash, &parent_header_hash);
        let parent_sortition_id = sortition_dbconn
            .get_sortition_id_from_consensus_hash(&parent_consensus_hash)
            .expect("Failed to get parent SortitionID from ConsensusHash");
        let tip_index_hash = StacksBlockId::new(&parent_consensus_hash, &parent_header_hash);

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        let matured_rewards_schedule_opt = if new_tenure {
            Self::get_matured_miner_reward_schedules(chainstate_tx, &tip_index_hash, tenure_height)?
        } else {
            // no rewards if mid-tenure
            None
        };

        // TODO: only need to do this if this is a tenure-start block
        let (stacking_burn_ops, transfer_burn_ops, delegate_burn_ops) =
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
                    parent_stacks_height,
                    matured_rewards_schedule,
                )
            })
            .transpose()?
            .flatten();

        // Nakamoto must load block cost from parent if this block isn't a tenure change
        let initial_cost = if new_tenure {
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

    /// Check that a given Nakamoto block's tenure's sortition exists and was processed.
    /// Return the sortition's burnchain block's hash and its burnchain height
    /// TODO: unit test
    pub(crate) fn check_sortition_exists(
        burn_dbconn: &mut SortitionHandleTx,
        block_consensus_hash: &ConsensusHash,
    ) -> Result<(BurnchainHeaderHash, u64), ChainstateError> {
        // check that the burnchain block that this block is associated with has been processed.
        // N.B. we must first get its hash, and then verify that it's in the same Bitcoin fork as
        // our `burn_dbconn` indicates.
        let burn_header_hash =
            SortitionDB::get_burnchain_header_hash_by_consensus(burn_dbconn, block_consensus_hash)?
                .ok_or_else(|| {
                    warn!(
                        "Unrecognized consensus hash";
                        "consensus_hash" => %block_consensus_hash,
                    );
                    ChainstateError::NoSuchBlockError
                })?;

        let sortition_tip = burn_dbconn.context.chain_tip.clone();
        let burn_header_height = burn_dbconn
            .get_block_snapshot(&burn_header_hash, &sortition_tip)?
            .ok_or_else(|| {
                warn!(
                    "Tried to process Nakamoto block before its burn view was processed";
                    "burn_header_hash" => %burn_header_hash,
                );
                ChainstateError::NoSuchBlockError
            })?
            .block_height;

        Ok((burn_header_hash, burn_header_height))
    }

    /// Check that this block is in the same tenure as its parent, and that this tenure is the
    /// highest-seen tenure.
    /// Returns Ok(bool) to indicate whether or not this block is in the same tenure as its parent.
    /// Returns Err(..) on DB error
    /// TODO: unit test
    pub(crate) fn check_tenure_continuity(
        headers_conn: &Connection,
        sort_tx: &mut SortitionHandleTx,
        parent_ch: &ConsensusHash,
        block_header: &NakamotoBlockHeader,
    ) -> Result<bool, ChainstateError> {
        // block must have the same consensus hash as its parent
        if block_header.is_first_mined() || parent_ch != &block_header.consensus_hash {
            return Ok(false);
        }

        // block must be in the same tenure as the highest-processed tenure
        let Some(highest_tenure) = Self::get_highest_nakamoto_tenure(headers_conn, sort_tx)? else {
            // no tenures yet, so definitely not continuous
            return Ok(false);
        };

        if &highest_tenure.consensus_hash != parent_ch {
            // this block is not in the highest-known tenure, so it can't be continuous
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate the scheduled block-reward for this tenure.
    /// - chainstate_tx: the transaction open against the chainstate
    /// - burn_dbconn: the sortition fork tx open against the sortition DB
    /// - block: the block being processed
    /// - parent_tenure_height: the number of tenures represented by the parent of this block
    /// - chain_tip_burn_header_height: the height of the burnchain block mined when this block was
    /// produced
    /// - burnchain_commit_burn: how many burnchain tokens were spent by this block's tenure's block-commit
    /// - burnchain_sortition_burn: total burnchain tokens spent by all miners for this block's
    /// tenure
    ///
    /// Returns the scheduled reward for this block's miner, subject to:
    /// - accumulated STX from missed sortitions
    /// - initial mining bonus, if any
    /// - the coinbase reward at this burnchain block height
    /// - the parent tenure's total fees
    ///
    /// TODO: unit test
    pub(crate) fn calculate_scheduled_tenure_reward(
        chainstate_tx: &mut ChainstateTx,
        burn_dbconn: &mut SortitionHandleTx,
        block: &NakamotoBlock,
        evaluated_epoch: StacksEpochId,
        parent_tenure_height: u64,
        chain_tip_burn_header_height: u64,
        burnchain_commit_burn: u64,
        burnchain_sortition_burn: u64,
    ) -> Result<MinerPaymentSchedule, ChainstateError> {
        let mainnet = chainstate_tx.get_config().mainnet;

        // figure out if there any accumulated rewards by
        //   getting the snapshot that elected this block.
        let accumulated_rewards = SortitionDB::get_block_snapshot_consensus(
            burn_dbconn.tx(),
            &block.header.consensus_hash,
        )?
        .expect("CORRUPTION: failed to load snapshot that elected processed block")
        .accumulated_coinbase_ustx;

        let coinbase_at_block = StacksChainState::get_coinbase_reward(
            chain_tip_burn_header_height,
            burn_dbconn.context.first_block_height,
        );

        let total_coinbase = coinbase_at_block.saturating_add(accumulated_rewards);
        let parent_tenure_start_header: StacksHeaderInfo = Self::get_header_by_tenure_height(
            chainstate_tx,
            &block.header.parent_block_id,
            parent_tenure_height,
        )?
        .ok_or_else(|| {
            warn!("While processing tenure change, failed to look up parent tenure";
                  "parent_tenure_height" => parent_tenure_height,
                  "parent_block_id" => %block.header.parent_block_id,
                  "block_hash" => %block.header.block_hash(),
                  "block_consensus_hash" => %block.header.consensus_hash);
            ChainstateError::NoSuchBlockError
        })?;
        // fetch the parent tenure fees by reading the total tx fees from this block's
        // *parent* (not parent_tenure_start_header), because `parent_block_id` is the last
        // block of that tenure, so contains a total fee accumulation for the whole tenure
        let parent_tenure_fees = if parent_tenure_start_header.is_nakamoto_block() {
            Self::get_total_tenure_tx_fees_at(
                chainstate_tx,
                &block.header.parent_block_id
            )?.ok_or_else(|| {
                warn!("While processing tenure change, failed to look up parent block's total tx fees";
                      "parent_block_id" => %block.header.parent_block_id,
                      "block_hash" => %block.header.block_hash(),
                      "block_consensus_hash" => %block.header.consensus_hash);
                ChainstateError::NoSuchBlockError
            })?
        } else {
            // if the parent tenure is an epoch-2 block, don't pay
            // any fees to them in this schedule: nakamoto blocks
            // cannot confirm microblock transactions, and
            // anchored transactions are scheduled
            // by the parent in epoch-2.
            0
        };

        Ok(Self::make_scheduled_miner_reward(
            mainnet,
            evaluated_epoch,
            &parent_tenure_start_header.anchored_header.block_hash(),
            &parent_tenure_start_header.consensus_hash,
            &block.header.block_hash(),
            &block.header.consensus_hash,
            block.header.chain_length,
            block
                .get_coinbase_tx()
                .ok_or(ChainstateError::InvalidStacksBlock(
                    "No coinbase transaction in tenure changing block".into(),
                ))?,
            parent_tenure_fees,
            burnchain_commit_burn,
            burnchain_sortition_burn,
            total_coinbase,
        ))
    }

    /// Get the burnchain block info of a given tenure's consensus hash.
    /// Used for the tx receipt.
    /// TODO: unit test
    pub(crate) fn get_tenure_burn_block_info(
        burn_dbconn: &Connection,
        first_mined: bool,
        ch: &ConsensusHash,
    ) -> Result<(BurnchainHeaderHash, u64, u64), ChainstateError> {
        // get burn block stats, for the transaction receipt
        let (burn_block_hash, burn_block_height, burn_block_timestamp) = if first_mined {
            (BurnchainHeaderHash([0; 32]), 0, 0)
        } else {
            match SortitionDB::get_block_snapshot_consensus(burn_dbconn, ch)? {
                Some(sn) => (
                    sn.burn_header_hash,
                    sn.block_height,
                    sn.burn_header_timestamp,
                ),
                None => {
                    // shouldn't happen
                    warn!("CORRUPTION: {} does not correspond to a burn block", ch,);
                    (BurnchainHeaderHash([0; 32]), 0, 0)
                }
            }
        };

        Ok((burn_block_hash, burn_block_height, burn_block_timestamp))
    }

    /// Append a Nakamoto Stacks block to the Stacks chain state.
    pub fn append_block<'a>(
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
    ) -> Result<(StacksEpochReceipt, PreCommitClarityBlock<'a>), ChainstateError> {
        debug!(
            "Process block {:?} with {} transactions",
            &block.header.block_hash().to_hex(),
            block.txs.len()
        );

        let ast_rules = ASTRules::PrecheckSize;
        let next_block_height = block.header.chain_length;

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
        let (burn_header_hash, burn_header_height) =
            Self::check_sortition_exists(burn_dbconn, &block.header.consensus_hash)?;
        let block_hash = block.header.block_hash();

        let new_tenure = if let Some(tenures_valid) = block.is_wellformed_tenure_start_block() {
            if !tenures_valid {
                return Err(ChainstateError::InvalidStacksBlock(
                    "Invalid tenure changes in nakamoto block".into(),
                ));
            }
            true
        } else {
            // this block is mined in the ongoing tenure.
            if !Self::check_tenure_continuity(
                chainstate_tx,
                burn_dbconn,
                &parent_ch,
                &block.header,
            )? {
                // this block is not part of the ongoing tenure; it's invalid
                return Err(ChainstateError::ExpectedTenureChange);
            }

            false
        };

        let parent_tenure_height = if block.is_first_mined() {
            0
        } else {
            Self::get_tenure_height(chainstate_tx.deref(), &parent_block_id)?.ok_or_else(|| {
                warn!(
                    "Parent of Nakamoto block in block headers DB yet";
                    "block_hash" => %block.header.block_hash(),
                    "parent_block_hash" => %parent_block_hash,
                    "parent_block_id" => %parent_block_id
                );
                ChainstateError::NoSuchBlockError
            })?
        };

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
        let tenure_height =
            Self::advance_nakamoto_tenure(chainstate_tx, burn_dbconn, block, parent_tenure_height)?;
        if new_tenure {
            // tenure height must have advanced
            if tenure_height
                != parent_tenure_height
                    .checked_add(1)
                    .expect("Too many tenures")
            {
                // this should be unreachable
                return Err(ChainstateError::InvalidStacksBlock(
                    "Could not advance tenure, even though tenure changed".into(),
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
        } = Self::setup_block(
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
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
            tenure_height,
        )?;

        let starting_cost = clarity_tx.cost_so_far();

        debug!(
            "Append nakamoto block";
            "block" => format!("{}/{block_hash}", block.header.consensus_hash),
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
                parent_tenure_height,
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
            new_tenure,
            block_fees,
        )
        .expect("FATAL: failed to advance chain tip");

        let new_block_id = new_tip.index_block_hash();
        chainstate_tx.log_transactions_processed(&new_block_id, &tx_receipts);

        monitoring::set_last_block_transaction_count(u64::try_from(block.txs.len()).unwrap());
        monitoring::set_last_execution_cost_observed(&block_execution_cost, &block_limit);

        // get previous burn block stats, for the transaction receipt
        let (parent_burn_block_hash, parent_burn_block_height, parent_burn_block_timestamp) =
            Self::get_tenure_burn_block_info(burn_dbconn, block.is_first_mined(), &parent_ch)?;
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
        };

        NakamotoChainState::set_block_processed(&chainstate_tx, &new_block_id)?;

        Ok((epoch_receipt, clarity_commit))
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
