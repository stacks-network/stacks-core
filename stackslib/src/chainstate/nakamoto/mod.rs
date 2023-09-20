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

use std::ops::DerefMut;

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::BurnStateDB;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::StacksAddressExtensions;
use lazy_static::__Deref;
use rand_chacha::rand_core::block;
use rusqlite::types::{FromSql, FromSqlError};
use rusqlite::{Connection, OptionalExtension, ToSql};
use stacks_common::codec::Error as CodecError;
use stacks_common::codec::{read_next, write_next, StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::consts::{
    FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, MINER_REWARD_MATURITY,
};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, ConsensusHash};
use stacks_common::types::StacksEpochId;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::{Hash160, MerkleHashFunc, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
use stacks_common::util::secp256k1::MessageSignature;

use super::burn::db::sortdb::SortitionHandleTx;
use super::burn::operations::{DelegateStxOp, StackStxOp, TransferStxOp};
use super::stacks::db::accounts::MinerReward;
use super::stacks::db::blocks::StagingUserBurnSupport;
use super::stacks::db::{
    ChainstateTx, ClarityTx, MinerPaymentSchedule, MinerRewardInfo, StacksBlockHeaderTypes,
    StacksDBTx, StacksHeaderInfo,
};
use super::stacks::db::{MinerPaymentTxFees, StacksEpochReceipt};
use super::stacks::events::StacksTransactionReceipt;
use super::stacks::Error as ChainstateError;
use super::stacks::StacksBlock;
use super::stacks::StacksTransaction;
use super::stacks::{StacksBlockHeader, StacksMicroblock, TransactionPayload};
use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH};
use crate::clarity_vm::clarity::{ClarityInstance, PreCommitClarityBlock};
use crate::clarity_vm::database::SortitionDBRef;
use crate::monitoring;
use crate::util_lib::db::{query_rows, u64_to_sql, Error as DBError, FromRow};

#[cfg(test)]
pub mod tests;

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
    pub static ref NAKAMOTO_CHAINSTATE_SCHEMA_1: Vec<String> = vec![
    r#"
      -- Table for Nakamoto Block Headers
      CREATE TABLE nakamoto_block_headers (
          -- The following fields all correspond to entries in the StacksHeaderInfo struct
                     block_height INTEGER NOT NULL,
                     -- root hash of the internal, not-consensus-critical MARF that allows us to track chainstate/fork metadata
                     index_root TEXT NOT NULL,
                     -- all consensus hashes are guaranteed to be unique
                     consensus_hash TEXT UNIQUE NOT NULL,
                     -- burn header hash corresponding to the consensus hash (NOT guaranteed to be unique, since we can 
                     --    have 2+ blocks per burn block if there's a PoX fork)
                     burn_header_hash TEXT NOT NULL,
                     -- height of the burnchain block header that generated this consensus hash
                     burn_header_height INT NOT NULL,
                     -- timestamp from burnchain block header that generated this consensus hash
                     burn_header_timestamp INT NOT NULL,
                     block_size TEXT NOT NULL,
          -- The following fields all correspond to entries in the NakamotoBlockHeader struct
                     version INTEGER NOT NULL,
                     -- this field is the total number of blocks in the chain history (including this block)
                     chain_length INTEGER NOT NULL,
                     -- this field is the total amount of BTC spent in the chain history (including this block)
                     burn_spent INTEGER NOT NULL,
                     -- the parent BlockHeaderHash
                     parent TEXT NOT NULL,
                     -- the latest bitcoin block whose data is viewable from this stacks block
                     burn_view TEXT NOT NULL,
                     -- stackers' signature over the block
                     signature TEXT NOT NULL,
                     tx_merkle_root TEXT NOT NULL,
                     state_index_root TEXT NOT NULL,

          -- The following fields are not part of either the StacksHeaderInfo struct
          --   or its contained NakamotoBlockHeader struct, but are used for querying
                     header_type TEXT NOT NULL,
                     block_hash TEXT NOT NULL,
                     -- index_block_hash is the hash of the block hash and consensus hash of the burn block that selected it, 
                     -- and is guaranteed to be globally unique (across all Stacks forks and across all PoX forks).
                     -- index_block_hash is the block hash fed into the MARF index.
                     index_block_hash TEXT NOT NULL,
                     -- the total cost of the block
                     cost TEXT NOT NULL,
                     -- the total cost up to and including this block in the current tenure
                     total_tenure_cost TEXT NOT NULL,
                     -- the parent index_block_hash
                     parent_block_id TEXT NOT NULL,
                     affirmation_weight INTEGER NOT NULL,
                     -- this field is the total number of *tenures* in the chain history (including this tenure)
                     tenure_height INTEGER NOT NULL,
                     -- this field is true if this is the first block of a new tenure
                     tenure_changed INTEGER NOT NULL,
                     -- this field tracks the total tx fees so far in this tenure. it is a text-serialized u128
                     tenure_tx_fees TEXT NOT NULL,
              PRIMARY KEY(consensus_hash,block_hash)
          );
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

pub struct SetupBlockResult<'a, 'b> {
    pub clarity_tx: ClarityTx<'a, 'b>,
    pub tx_receipts: Vec<StacksTransactionReceipt>,
    pub matured_miner_rewards_opt:
        Option<(MinerReward, Vec<MinerReward>, MinerReward, MinerRewardInfo)>,
    pub evaluated_epoch: StacksEpochId,
    pub applied_epoch_transition: bool,
    pub burn_stack_stx_ops: Vec<StackStxOp>,
    pub burn_transfer_stx_ops: Vec<TransferStxOp>,
    pub auto_unlock_events: Vec<StacksTransactionEvent>,
    pub burn_delegate_stx_ops: Vec<DelegateStxOp>,
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
    /// The block hash of the immediate parent of this block.
    pub parent: BlockHeaderHash,
    /// The bitcoin block whose data has been handled most recently by
    /// the Stacks chain as of this block.
    pub burn_view: BurnchainHeaderHash,
    /// The root of a SHA512/256 merkle tree over all this block's
    /// contained transactions
    pub tx_merkle_root: Sha512Trunc256Sum,
    /// The MARF trie root hash after this block has been processed
    pub state_index_root: TrieHash,
    /// Recoverable ECDSA signature from the tenure's miner.
    pub signature: MessageSignature,
}

pub struct NakamotoBlock {
    pub header: NakamotoBlockHeader,
    pub txs: Vec<StacksTransaction>,
}

pub struct NakamotoChainState;

impl FromRow<NakamotoBlockHeader> for NakamotoBlockHeader {
    fn from_row(row: &rusqlite::Row) -> Result<NakamotoBlockHeader, DBError> {
        let version = row.get("version")?;
        let chain_length_i64: i64 = row.get("chain_length")?;
        let chain_length = chain_length_i64.try_into().map_err(|_| DBError::Overflow)?;
        let burn_spent_i64: i64 = row.get("burn_spent")?;
        let burn_spent = burn_spent_i64.try_into().map_err(|_| DBError::Overflow)?;
        let parent = row.get("parent")?;
        let burn_view = row.get("burn_view")?;
        let signature = row.get("signature")?;
        let tx_merkle_root = row.get("tx_merkle_root")?;
        let state_index_root = row.get("state_index_root")?;

        Ok(NakamotoBlockHeader {
            version,
            chain_length,
            burn_spent,
            parent,
            burn_view,
            signature,
            tx_merkle_root,
            state_index_root,
        })
    }
}

impl StacksMessageCodec for NakamotoBlockHeader {
    fn consensus_serialize<W: std::io::Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.version)?;
        write_next(fd, &self.chain_length)?;
        write_next(fd, &self.burn_spent)?;
        write_next(fd, &self.parent)?;
        write_next(fd, &self.burn_view)?;
        write_next(fd, &self.tx_merkle_root)?;
        write_next(fd, &self.state_index_root)?;
        write_next(fd, &self.signature)?;

        Ok(())
    }

    fn consensus_deserialize<R: std::io::Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(NakamotoBlockHeader {
            version: read_next(fd)?,
            chain_length: read_next(fd)?,
            burn_spent: read_next(fd)?,
            parent: read_next(fd)?,
            burn_view: read_next(fd)?,
            tx_merkle_root: read_next(fd)?,
            state_index_root: read_next(fd)?,
            signature: read_next(fd)?,
        })
    }
}

impl NakamotoBlockHeader {
    pub fn block_hash(&self) -> BlockHeaderHash {
        BlockHeaderHash::from_serializer(self)
            .expect("BUG: failed to serialize block header hash struct")
    }
}

impl NakamotoBlock {
    /// Did the stacks tenure change on this nakamoto block? i.e., does this block
    ///  include a TenureChange transaction?
    pub fn tenure_changed(&self) -> bool {
        // TODO: when tenure change txs are implemented, this must be updated
        true
    }

    pub fn is_first_mined(&self) -> bool {
        StacksBlockHeader::is_first_block_hash(&self.header.parent)
    }

    pub fn get_coinbase_tx(&self) -> Option<&StacksTransaction> {
        match self.txs.get(0).map(|x| &x.payload) {
            Some(TransactionPayload::Coinbase(..)) => Some(&self.txs[0]),
            _ => None,
        }
    }
}

impl NakamotoChainState {
    /// Create the block reward for a NakamotoBlock
    /// `coinbase_reward_ustx` is the total coinbase reward for this block, including any
    ///    accumulated rewards from missed sortitions or initial mining rewards.
    pub fn make_scheduled_miner_reward(
        mainnet: bool,
        epoch_id: StacksEpochId,
        parent_block_hash: &BlockHeaderHash,
        parent_consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        coinbase_tx: &StacksTransaction,
        block_consensus_hash: &ConsensusHash,
        block_height: u64,
        parent_fees: u128,
        burnchain_commit_burn: u64,
        burnchain_sortition_burn: u64,
        coinbase_reward_ustx: u128,
    ) -> Result<MinerPaymentSchedule, ChainstateError> {
        let miner_auth = coinbase_tx.get_origin();
        let miner_addr = miner_auth.get_address(mainnet);

        let recipient = if epoch_id >= StacksEpochId::Epoch21 {
            // pay to tx-designated recipient, or if there is none, pay to the origin
            match coinbase_tx.try_as_coinbase() {
                Some((_, recipient_opt)) => recipient_opt
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

        Ok(miner_reward)
    }

    /// Return the total ExecutionCost consumed during the tenure up to and including
    ///  `block`
    pub fn get_total_tenure_cost_at(
        conn: &Connection,
        block: &StacksBlockId,
    ) -> Result<Option<ExecutionCost>, ChainstateError> {
        let qry = "SELECT total_tenure_cost FROM nakamoto_block_headers WHERE index_block_hash = ?";
        conn.query_row(qry, &[block], |row| row.get(0))
            .optional()
            .map_err(|e| ChainstateError::DBError(e.into()))
    }

    /// Return the total transactions fees during the tenure up to and including
    ///  `block`
    pub fn get_total_tenure_tx_fees_at(
        conn: &Connection,
        block: &StacksBlockId,
    ) -> Result<Option<u128>, ChainstateError> {
        let qry = "SELECT tenure_tx_fees FROM nakamoto_block_headers WHERE index_block_hash = ?";
        let tx_fees_str: Option<String> =
            conn.query_row(qry, &[block], |row| row.get(0)).optional()?;
        tx_fees_str
            .map(|x| x.parse())
            .transpose()
            .map_err(|_| ChainstateError::DBError(DBError::ParseError))
    }

    /// Return a Nakamoto StacksHeaderInfo at a given tenure height in the fork identified by `tip_index_hash`
    pub fn get_header_by_tenure_height(
        tx: &mut StacksDBTx,
        tip_index_hash: &StacksBlockId,
        tenure_height: u64,
    ) -> Result<Option<StacksHeaderInfo>, ChainstateError> {
        // query for block header info at the tenure-height, then check if in fork
        let qry =
            "SELECT * FROM nakamoto_block_headers WHERE tenure_changed = 1 AND tenure_height = ?";
        let candidate_headers: Vec<StacksHeaderInfo> =
            query_rows(tx.tx(), qry, &[u64_to_sql(tenure_height)?])?;

        if candidate_headers.len() == 0 {
            // no nakamoto_block_headers at that tenure height, check if there's a stack block header where
            //   block_height = tenure_height
            let ancestor_at_height = match StacksChainState::get_index_tip_ancestor(
                tx,
                tip_index_hash,
                tenure_height,
            )? {
                Some(x) => x,
                None => return Ok(None),
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

        for candidate in candidate_headers.into_iter() {
            let ancestor_at_height = match StacksChainState::get_index_tip_ancestor(
                tx,
                tip_index_hash,
                candidate.stacks_block_height,
            ) {
                Ok(Some(ancestor_at_height)) => ancestor_at_height,
                // if there's an error or no result, this candidate doesn't match, so try next candidate
                _ => continue,
            };
            if ancestor_at_height.index_block_hash() == candidate.index_block_hash() {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    /// Return the tenure height of `block` if it was a nakamoto block, or the
    ///  Stacks block height of `block` if it was an epoch-2 block
    pub fn get_tenure_height(
        conn: &Connection,
        block: &StacksBlockId,
    ) -> Result<Option<u64>, ChainstateError> {
        let nak_qry = "SELECT tenure_height FROM nakamoto_block_headers WHERE index_block_hash = ?";
        let opt_height: Option<i64> = conn
            .query_row(nak_qry, &[block], |row| row.get(0))
            .optional()?;
        if let Some(height) = opt_height {
            return Ok(Some(
                u64::try_from(height).map_err(|_| DBError::ParseError)?,
            ));
        }

        let epoch_2_qry = "SELECT block_height FROM block_headers WHERE index_block_hash = ?";
        let opt_height: Option<i64> = conn
            .query_row(epoch_2_qry, &[block], |row| row.get(0))
            .optional()?;
        opt_height
            .map(u64::try_from)
            .transpose()
            .map_err(|_| ChainstateError::DBError(DBError::ParseError))
    }

    /// Insert a nakamoto block header that is paired with an
    /// already-existing block commit and snapshot
    ///
    /// `header` should be a pointer to the header in `tip_info`.
    pub fn insert_stacks_block_header(
        tx: &Connection,
        parent_id: &StacksBlockId,
        tip_info: &StacksHeaderInfo,
        header: &NakamotoBlockHeader,
        anchored_block_cost: &ExecutionCost,
        total_tenure_cost: &ExecutionCost,
        affirmation_weight: u64,
        tenure_height: u64,
        tenure_changed: bool,
        tenure_tx_fees: u128,
    ) -> Result<(), ChainstateError> {
        assert_eq!(tip_info.stacks_block_height, header.chain_length,);
        assert!(tip_info.burn_header_timestamp < i64::MAX as u64);

        let index_root = &tip_info.index_root;
        let consensus_hash = &tip_info.consensus_hash;
        let burn_header_hash = &tip_info.burn_header_hash;
        let block_height = tip_info.stacks_block_height;
        let burn_header_height = tip_info.burn_header_height;
        let burn_header_timestamp = tip_info.burn_header_timestamp;

        let block_size_str = format!("{}", tip_info.anchored_block_size);

        let block_hash = header.block_hash();

        let index_block_hash =
            StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_hash);

        assert!(block_height < (i64::MAX as u64));

        let args: &[&dyn ToSql] = &[
            &u64_to_sql(block_height)?,
            &index_root,
            &consensus_hash,
            &burn_header_hash,
            &burn_header_height,
            &u64_to_sql(burn_header_timestamp)?,
            &block_size_str,
            &HeaderTypeNames::Nakamoto,
            &header.version,
            &u64_to_sql(header.chain_length)?,
            &u64_to_sql(header.burn_spent)?,
            &header.parent,
            &header.burn_view,
            &header.signature,
            &header.tx_merkle_root,
            &header.state_index_root,
            &block_hash,
            &index_block_hash,
            anchored_block_cost,
            total_tenure_cost,
            &tenure_tx_fees.to_string(),
            parent_id,
            &u64_to_sql(affirmation_weight)?,
            &u64_to_sql(tenure_height)?,
            if tenure_changed { &1i64 } else { &0 },
        ];

        tx.execute(
            "INSERT INTO nakamoto_block_headers
                    (block_height,  index_root, consensus_hash,
                     burn_header_hash, burn_header_height,
                     burn_header_timestamp, block_size,

                     header_type,
                     version, chain_length, burn_spent, parent,
                     burn_view, signature, tx_merkle_root, state_index_root,

                     block_hash,
                     index_block_hash,
                     cost,
                     total_tenure_cost,
                     tenure_tx_fees,
                     parent_block_id,
                     affirmation_weight,
                     tenure_height,
                     tenure_changed)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
            args
        )?;

        Ok(())
    }

    /// Append a Stacks block to an existing Stacks block, and grant the miner the block reward.
    /// Return the new Stacks header info.
    pub fn advance_tip(
        headers_tx: &mut StacksDBTx,
        parent_tip: &StacksBlockHeaderTypes,
        parent_consensus_hash: &ConsensusHash,
        new_tip: &NakamotoBlockHeader,
        new_consensus_hash: &ConsensusHash,
        new_burn_header_hash: &BurnchainHeaderHash,
        new_burnchain_height: u32,
        new_burnchain_timestamp: u64,
        block_reward: Option<&MinerPaymentSchedule>,
        mature_miner_payouts: Option<(MinerReward, Vec<MinerReward>, MinerReward, MinerRewardInfo)>, // (miner, [users], parent, matured rewards)
        anchor_block_cost: &ExecutionCost,
        total_tenure_cost: &ExecutionCost,
        anchor_block_size: u64,
        applied_epoch_transition: bool,
        burn_stack_stx_ops: Vec<StackStxOp>,
        burn_transfer_stx_ops: Vec<TransferStxOp>,
        burn_delegate_stx_ops: Vec<DelegateStxOp>,
        affirmation_weight: u64,
        tenure_height: u64,
        tenure_changed: bool,
        block_fees: u128,
    ) -> Result<StacksHeaderInfo, ChainstateError> {
        if new_tip.parent != FIRST_STACKS_BLOCK_HASH {
            // not the first-ever block, so linkage must occur
            assert_eq!(new_tip.parent, parent_tip.block_hash());
        }

        assert_eq!(
            parent_tip
                .height()
                .checked_add(1)
                .expect("Block height overflow"),
            new_tip.chain_length
        );

        let parent_hash =
            StacksChainState::get_index_hash(parent_consensus_hash, &parent_tip.block_hash());

        let new_block_hash = new_tip.block_hash();
        let index_block_hash = StacksBlockId::new(&new_consensus_hash, &new_block_hash);

        // store each indexed field
        test_debug!(
            "Headers index_put_begin {}-{}",
            &parent_hash,
            &index_block_hash,
        );
        let root_hash =
            headers_tx.put_indexed_all(&parent_hash, &index_block_hash, &vec![], &vec![])?;
        test_debug!(
            "Headers index_indexed_all finished {}-{}",
            &parent_hash,
            &index_block_hash,
        );

        let new_tip_info = StacksHeaderInfo {
            anchored_header: new_tip.clone().into(),
            microblock_tail: None,
            index_root: root_hash,
            stacks_block_height: new_tip.chain_length,
            consensus_hash: new_consensus_hash.clone(),
            burn_header_hash: new_burn_header_hash.clone(),
            burn_header_height: new_burnchain_height,
            burn_header_timestamp: new_burnchain_timestamp,
            anchored_block_size: anchor_block_size,
        };

        let tenure_fees = block_fees
            + if tenure_changed {
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
            &parent_hash,
            &new_tip_info,
            &new_tip,
            anchor_block_cost,
            total_tenure_cost,
            affirmation_weight,
            tenure_height,
            tenure_changed,
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

        if let Some((miner_payout, user_payouts, parent_payout, reward_info)) = mature_miner_payouts
        {
            let rewarded_miner_block_id = StacksBlockId::new(
                &reward_info.from_block_consensus_hash,
                &reward_info.from_stacks_block_hash,
            );
            let rewarded_parent_miner_block_id = StacksBlockId::new(
                &reward_info.from_parent_block_consensus_hash,
                &reward_info.from_parent_stacks_block_hash,
            );

            StacksChainState::insert_matured_child_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &miner_payout,
            )?;
            for user_payout in user_payouts.into_iter() {
                StacksChainState::insert_matured_child_user_reward(
                    headers_tx.deref_mut(),
                    &rewarded_parent_miner_block_id,
                    &rewarded_miner_block_id,
                    &user_payout,
                )?;
            }
            StacksChainState::insert_matured_parent_miner_reward(
                headers_tx.deref_mut(),
                &rewarded_parent_miner_block_id,
                &rewarded_miner_block_id,
                &parent_payout,
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
            new_consensus_hash, new_block_hash,
        );
        Ok(new_tip_info)
    }

    /// This function is called in both `append_block` in blocks.rs (follower) and
    /// `mine_anchored_block` in miner.rs.
    /// Processes matured miner rewards, alters liquid supply of ustx, processes
    /// stx lock events, and marks the microblock public key as used
    /// Returns stx lockup events.
    pub fn finish_block(
        clarity_tx: &mut ClarityTx,
        miner_payouts: Option<&(MinerReward, Vec<MinerReward>, MinerReward, MinerRewardInfo)>,
    ) -> Result<Vec<StacksTransactionEvent>, ChainstateError> {
        // add miner payments
        if let Some((ref miner_reward, ref user_rewards, ref parent_reward, _)) = miner_payouts {
            // grant in order by miner, then users
            let matured_ustx = StacksChainState::process_matured_miner_rewards(
                clarity_tx,
                miner_reward,
                user_rewards,
                parent_reward,
            )?;

            clarity_tx.increment_ustx_liquid_supply(matured_ustx);
        }

        // process unlocks
        let (new_unlocked_ustx, lockup_events) = StacksChainState::process_stx_unlocks(clarity_tx)?;

        clarity_tx.increment_ustx_liquid_supply(new_unlocked_ustx);

        Ok(lockup_events)
    }

    /// Called in both follower and miner block assembly paths.
    ///
    /// Returns clarity_tx, list of receipts, microblock execution cost,
    /// microblock fees, microblock burns, list of microblock tx receipts,
    /// miner rewards tuples, the stacks epoch id, and a boolean that
    /// represents whether the epoch transition has been applied.
    ///
    /// The `burn_dbconn`, `sortition_dbconn`, and `conn` arguments
    ///  all reference the same sortition database through different
    ///  interfaces. `burn_dbconn` and `sortition_dbconn` should
    ///  reference the same object. The reason to provide both is that
    ///  `SortitionDBRef` captures trait functions that Clarity does
    ///  not need, and Rust does not support trait upcasting (even
    ///  though it would theoretically be safe).
    pub fn setup_block<'a, 'b>(
        chainstate_tx: &'b mut ChainstateTx,
        clarity_instance: &'a mut ClarityInstance,
        sortition_dbconn: &'b dyn SortitionDBRef,
        pox_constants: &PoxConstants,
        chain_tip: &StacksHeaderInfo,
        burn_view: BurnchainHeaderHash,
        burn_view_height: u32,
        parent_consensus_hash: ConsensusHash,
        parent_header_hash: BlockHeaderHash,
        mainnet: bool,
        miner_id_opt: Option<usize>,
        tenure_changed: bool,
        tenure_height: u64,
    ) -> Result<SetupBlockResult<'a, 'b>, ChainstateError> {
        let parent_index_hash = StacksBlockId::new(&parent_consensus_hash, &parent_header_hash);
        let parent_sortition_id = sortition_dbconn
            .get_sortition_id_from_consensus_hash(&parent_consensus_hash)
            .expect("Failed to get parent SortitionID from ConsensusHash");
        let tip_index_hash = chain_tip.index_block_hash();

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        let matured_rewards_pair = if !tenure_changed {
            // only grant matured rewards at a tenure changing block
            None
        } else {
            if tenure_height < MINER_REWARD_MATURITY {
                Some((vec![], MinerPaymentSchedule::genesis(mainnet)))
            } else {
                let matured_tenure_height = tenure_height - MINER_REWARD_MATURITY;
                // for finding matured rewards at a tenure height, we identify the tenure
                //  by the consensus hash associated with that tenure's sortition.
                let matured_tenure_block_header = Self::get_header_by_tenure_height(
                    chainstate_tx,
                    &tip_index_hash,
                    matured_tenure_height,
                )?
                .ok_or_else(|| {
                    warn!("Matured tenure data not found");
                    ChainstateError::NoSuchBlockError
                })?;

                if matured_tenure_block_header.is_epoch_2_block() {
                    // is matured_tenure_height a epoch-2 rules block? if so, use StacksChainState block rewards methods
                    let latest_miners = StacksChainState::get_scheduled_block_rewards_at_block(
                        chainstate_tx.deref_mut(),
                        &matured_tenure_block_header.index_block_hash(),
                    )?;
                    let parent_miner = StacksChainState::get_parent_matured_miner(
                        chainstate_tx.deref_mut(),
                        mainnet,
                        &latest_miners,
                    )?;
                    Some((latest_miners, parent_miner))
                } else {
                    // otherwise, apply nakamoto rules for getting block rewards: fetch by the consensus hash
                    //   associated with the tenure, parent_miner is None.
                    let latest_miners = StacksChainState::get_scheduled_block_rewards_at_block(
                        chainstate_tx.deref_mut(),
                        &matured_tenure_block_header.index_block_hash(),
                    )?;
                    // find the parent of this tenure
                    let parent_miner = StacksChainState::get_parent_matured_miner(
                        chainstate_tx.deref_mut(),
                        mainnet,
                        &latest_miners,
                    )?;
                    Some((latest_miners, parent_miner))
                }
            }
        };

        let (stacking_burn_ops, transfer_burn_ops, delegate_burn_ops) =
            StacksChainState::get_stacking_and_transfer_and_delegate_burn_ops(
                chainstate_tx,
                &parent_index_hash,
                sortition_dbconn.sqlite_conn(),
                &burn_view,
                burn_view_height.into(),
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

        let matured_miner_rewards_result =
            matured_rewards_pair.map(|(latest_matured_miners, matured_miner_parent)| {
                StacksChainState::find_mature_miner_rewards(
                    &mut clarity_tx,
                    sortition_dbconn.sqlite_conn(),
                    &chain_tip,
                    latest_matured_miners,
                    matured_miner_parent,
                )
            });
        let matured_miner_rewards_opt = match matured_miner_rewards_result {
            Some(Ok(x)) => x,
            Some(Err(e)) => {
                if miner_id_opt.is_some() {
                    return Err(e);
                } else {
                    let msg = format!("Failed to load miner rewards: {:?}", &e);
                    warn!("{}", &msg);

                    clarity_tx.rollback_block();
                    return Err(ChainstateError::InvalidStacksBlock(msg));
                }
            }
            None => None,
        };

        // Nakamoto must load block cost from parent if this block isn't a tenure change
        let initial_cost = if tenure_changed {
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
            StacksChainState::process_epoch_transition(&mut clarity_tx, burn_view_height)?;

        debug!(
            "Setup block: Processed epoch transition at {}/{}",
            &chain_tip.consensus_hash,
            &chain_tip.anchored_header.block_hash()
        );

        let evaluated_epoch = clarity_tx.get_epoch();

        let auto_unlock_events = if evaluated_epoch >= StacksEpochId::Epoch21 {
            let unlock_events = StacksChainState::check_and_handle_reward_start(
                burn_view_height.into(),
                sortition_dbconn.as_burn_state_db(),
                sortition_dbconn,
                &mut clarity_tx,
                chain_tip,
                &parent_sortition_id,
            )?;
            debug!(
                "Setup block: Processed unlock events at {}/{}",
                &chain_tip.consensus_hash,
                &chain_tip.anchored_header.block_hash()
            );
            unlock_events
        } else {
            vec![]
        };

        let active_pox_contract = pox_constants.active_pox_contract(burn_view_height.into());

        // process stacking & transfer operations from burnchain ops
        tx_receipts.extend(StacksChainState::process_stacking_ops(
            &mut clarity_tx,
            stacking_burn_ops.clone(),
            active_pox_contract,
        ));
        debug!(
            "Setup block: Processed burnchain stacking ops for {}/{}",
            &chain_tip.consensus_hash,
            &chain_tip.anchored_header.block_hash()
        );
        tx_receipts.extend(StacksChainState::process_transfer_ops(
            &mut clarity_tx,
            transfer_burn_ops.clone(),
        ));
        debug!(
            "Setup block: Processed burnchain transfer ops for {}/{}",
            &chain_tip.consensus_hash,
            &chain_tip.anchored_header.block_hash()
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
                "Setup block: Processed burnchain delegate ops for {}/{}",
                &chain_tip.consensus_hash,
                &chain_tip.anchored_header.block_hash()
            );
        }

        debug!(
            "Setup block: ready to go for {}/{}",
            &chain_tip.consensus_hash,
            &chain_tip.anchored_header.block_hash()
        );
        Ok(SetupBlockResult {
            clarity_tx,
            tx_receipts,
            matured_miner_rewards_opt,
            evaluated_epoch,
            applied_epoch_transition,
            burn_stack_stx_ops: stacking_burn_ops,
            burn_transfer_stx_ops: transfer_burn_ops,
            auto_unlock_events,
            burn_delegate_stx_ops: delegate_burn_ops,
        })
    }

    fn append_block<'a>(
        chainstate_tx: &mut ChainstateTx,
        clarity_instance: &'a mut ClarityInstance,
        burn_dbconn: &mut SortitionHandleTx,
        pox_constants: &PoxConstants,
        parent_chain_tip: &StacksHeaderInfo,
        chain_tip_consensus_hash: &ConsensusHash,
        chain_tip_burn_header_hash: &BurnchainHeaderHash,
        chain_tip_burn_header_height: u32,
        chain_tip_burn_header_timestamp: u64,
        block: &NakamotoBlock,
        block_size: u64,
        burnchain_commit_burn: u64,
        burnchain_sortition_burn: u64,
        affirmation_weight: u64,
    ) -> Result<(StacksEpochReceipt, PreCommitClarityBlock<'a>), ChainstateError> {
        debug!(
            "Process block {:?} with {} transactions",
            &block.header.block_hash().to_hex(),
            block.txs.len()
        );

        let ast_rules = ASTRules::PrecheckSize;

        let mainnet = chainstate_tx.get_config().mainnet;
        let next_block_height = block.header.chain_length;

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

        // check that the burnchain block that this block is associated with has been processed
        let burn_view_hash = block.header.burn_view.clone();
        let sortition_tip = burn_dbconn.context.chain_tip.clone();
        let burn_view_height = burn_dbconn
            .get_block_snapshot(&burn_view_hash, &sortition_tip)?
            .ok_or_else(|| {
                warn!(
                    "Tried to process Nakamoto block before its burn view was processed";
                    "block_hash" => block.header.block_hash(),
                    "burn_view" => %burn_view_hash,
                );
                ChainstateError::NoSuchBlockError
            })?
            .block_height;

        let block_hash = block.header.block_hash();

        let tenure_changed = block.tenure_changed();

        let parent_block_id = StacksChainState::get_index_hash(&parent_ch, &parent_block_hash);

        let parent_tenure_height = if block.is_first_mined() {
            0
        } else {
            Self::get_tenure_height(&chainstate_tx.deref().deref(), &parent_block_id)?.ok_or_else(
                || {
                    warn!(
                        "Parent of Nakamoto block in block headers DB yet";
                        "block_hash" => %block.header.block_hash(),
                        "parent_block_hash" => %parent_block_hash,
                        "parent_block_id" => %parent_block_id
                    );
                    ChainstateError::NoSuchBlockError
                },
            )?
        };

        let tenure_height = if tenure_changed {
            parent_tenure_height + 1
        } else {
            parent_tenure_height
        };

        let SetupBlockResult {
            mut clarity_tx,
            mut tx_receipts,
            matured_miner_rewards_opt,
            evaluated_epoch,
            applied_epoch_transition,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            mut auto_unlock_events,
            burn_delegate_stx_ops,
        } = Self::setup_block(
            chainstate_tx,
            clarity_instance,
            burn_dbconn,
            pox_constants,
            &parent_chain_tip,
            burn_view_hash,
            burn_view_height.try_into().map_err(|_| {
                ChainstateError::InvalidStacksBlock("Burn block height exceeded u32".into())
            })?,
            parent_ch,
            parent_block_hash,
            mainnet,
            None,
            tenure_changed,
            tenure_height,
        )?;

        let starting_cost = clarity_tx.cost_so_far();

        debug!(
            "Append nakamoto block";
            "block" => format!("{}/{}", chain_tip_consensus_hash, block_hash),
            "parent_block" => format!("{}/{}", parent_ch, parent_block_hash),
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
        let (matured_rewards, miner_payouts_opt) = if let Some(matured_miner_rewards) =
            matured_miner_rewards_opt
        {
            let (miner_reward, mut user_rewards, parent_reward, reward_ptr) = matured_miner_rewards;

            let mut ret = vec![];
            ret.push(miner_reward.clone());
            ret.append(&mut user_rewards);
            ret.push(parent_reward.clone());
            (
                ret,
                Some((miner_reward, user_rewards, parent_reward, reward_ptr)),
            )
        } else {
            (vec![], None)
        };

        let mut lockup_events =
            match Self::finish_block(&mut clarity_tx, miner_payouts_opt.as_ref()) {
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
        let clarity_commit = clarity_tx.precommit_to_block(chain_tip_consensus_hash, &block_hash);

        // figure out if there any accumulated rewards by
        //   getting the snapshot that elected this block.
        let accumulated_rewards =
            SortitionDB::get_block_snapshot_consensus(burn_dbconn.tx(), chain_tip_consensus_hash)?
                .expect("CORRUPTION: failed to load snapshot that elected processed block")
                .accumulated_coinbase_ustx;

        let coinbase_at_block = StacksChainState::get_coinbase_reward(
            chain_tip_burn_header_height as u64,
            burn_dbconn.context.first_block_height,
        );

        let total_coinbase = coinbase_at_block.saturating_add(accumulated_rewards);

        let scheduled_miner_reward = if tenure_changed {
            let parent_tenure_header: StacksHeaderInfo = Self::get_header_by_tenure_height(
                chainstate_tx,
                &parent_block_id,
                parent_tenure_height,
            )?
            .ok_or_else(|| {
                warn!("While processing tenure change, failed to look up parent tenure";
                      "parent_tenure_height" => parent_tenure_height,
                      "block_hash" => %block_hash,
                      "block_consensus_hash" => %chain_tip_consensus_hash);
                ChainstateError::NoSuchBlockError
            })?;
            // fetch the parent tenure fees by reading the total tx fees from this block's
            // *parent* (not parent_tenure_header), because `parent_block_id` is the last
            // block of that tenure, so contains a total fee accumulation for the whole tenure
            let parent_tenure_fees = Self::get_total_tenure_tx_fees_at(
                chainstate_tx,
                &parent_block_id
            )?.ok_or_else(|| {
                warn!("While processing tenure change, failed to look up parent block's total tx fees";
                      "parent_block_id" => %parent_block_id,
                      "block_hash" => %block_hash,
                      "block_consensus_hash" => %chain_tip_consensus_hash);
                ChainstateError::NoSuchBlockError
            })?;

            Some(
                Self::make_scheduled_miner_reward(
                    mainnet,
                    evaluated_epoch,
                    &parent_tenure_header.anchored_header.block_hash(),
                    &parent_tenure_header.consensus_hash,
                    &block_hash,
                    block
                        .get_coinbase_tx()
                        .ok_or(ChainstateError::InvalidStacksBlock(
                            "No coinbase transaction in tenure changing block".into(),
                        ))?,
                    chain_tip_consensus_hash,
                    next_block_height,
                    parent_tenure_fees,
                    burnchain_commit_burn,
                    burnchain_sortition_burn,
                    total_coinbase,
                )
                .expect("FATAL: parsed and processed a block without a coinbase"),
            )
        } else {
            None
        };

        let matured_rewards_info = miner_payouts_opt
            .as_ref()
            .map(|(_, _, _, info)| info.clone());

        let new_tip = Self::advance_tip(
            &mut chainstate_tx.tx,
            &parent_chain_tip.anchored_header,
            &parent_chain_tip.consensus_hash,
            &block.header,
            chain_tip_consensus_hash,
            chain_tip_burn_header_hash,
            chain_tip_burn_header_height,
            chain_tip_burn_header_timestamp,
            scheduled_miner_reward.as_ref(),
            miner_payouts_opt,
            &block_execution_cost,
            &total_tenure_cost,
            block_size,
            applied_epoch_transition,
            burn_stack_stx_ops,
            burn_transfer_stx_ops,
            burn_delegate_stx_ops,
            affirmation_weight,
            tenure_height,
            tenure_changed,
            block_fees,
        )
        .expect("FATAL: failed to advance chain tip");

        chainstate_tx.log_transactions_processed(&new_tip.index_block_hash(), &tx_receipts);

        monitoring::set_last_block_transaction_count(block.txs.len() as u64);
        monitoring::set_last_execution_cost_observed(&block_execution_cost, &block_limit);

        // get previous burn block stats
        let (parent_burn_block_hash, parent_burn_block_height, parent_burn_block_timestamp) =
            if block.is_first_mined() {
                (BurnchainHeaderHash([0; 32]), 0, 0)
            } else {
                match SortitionDB::get_block_snapshot_consensus(burn_dbconn, &parent_ch)? {
                    Some(sn) => (
                        sn.burn_header_hash,
                        sn.block_height as u32,
                        sn.burn_header_timestamp,
                    ),
                    None => {
                        // shouldn't happen
                        warn!(
                            "CORRUPTION: block {}/{} does not correspond to a burn block",
                            &parent_ch, &parent_block_hash
                        );
                        (BurnchainHeaderHash([0; 32]), 0, 0)
                    }
                }
            };

        let epoch_receipt = StacksEpochReceipt {
            header: new_tip,
            tx_receipts,
            matured_rewards,
            matured_rewards_info,
            parent_microblocks_cost: ExecutionCost::zero(),
            anchored_block_cost: block_execution_cost,
            parent_burn_block_hash,
            parent_burn_block_height,
            parent_burn_block_timestamp,
            evaluated_epoch,
            epoch_transition: applied_epoch_transition,
        };

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
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
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
