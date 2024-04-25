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

//! This module is concerned with tracking all Nakamoto tenures.
//!
//! A _tenure_ is the sequence of blocks that a miner produces from a winning sortition.  A tenure
//! can last for the duration of one or more burnchain blocks, and may be extended by Stackers.  As
//! such, every tenure corresponds to exactly one cryptographic sortition with a winning miner.
//! The consensus hash of the winning miner's sortition serves as the _tenure ID_, and it is
//! guaranteed to be globally unique across all Stacks chain histories and burnchain histories.
//!
//! The tenures within one burnchain fork are well-ordered.  Each tenure has exactly one parent
//! tenure, such that the last block in the parent tenure is the parent of the first block in the
//! child tenure.  The first-ever Nakamoto tenure's parent block is the last epoch2 Stacks block.
//! Due to well-ordering, each burnchain fork has a highest tenure, which is used to validate
//! blocks before processing them.  Namely, a Nakamoto block must belong to the highest tenure in
//! order to be appended to the chain tip.
//!
//! Treating tenures as sequences of blocks mined by a winning miner allows us to cause coinbases
//! to mature based on tenure confirmations.  This is consistent with the epoch2 behavior.  It also
//! allows us to quickly identify whether or not a block belongs to a given tenure, and it allows a
//! booting miner to identify the set of all tenure IDs in a reward cycle using only burnchain
//! state (although some of these tenures may be empty).
//!
//! Tenures are created and extended via `TenureChange` transactions.  These come in two flavors:
//!
//! * A `BlockFound` tenure change, which is induced by a winning sortition.  This causes the new
//! miner to start producing blocks, and stops the current miner from producing more blocks.
//!
//! * An `Extended` tenure change, which is induced by Stackers. This resets the tenure's ongoing
//! execution budget, thereby allowing the miner to continue producing blocks.
//!
//! A tenure may be extended at any time by Stackers, and may span multiple Bitcoin blocks (such
//! as if there was no sortition winner, or the winning miner never comes online).
//!
//! `TenureChanges` contain three pointers to chainstate:
//! * The _tenure consensus hash_: this is the consensus hash of the sortition that chose the last
//! winning miner.  Note that due to the above, it may not be the highest sortition processed.
//! * The _previous tenure consensus hash_: this is the consensus hash of the sortition that chose
//! the miner who produced the parent tenure of the current ongoing tenure.
//! * The _sortition consensus hash: this is the tip of the sortition history that Stackers knew
//! about when they created the `TenureChange.
//!
//! The Nakamoto system uses this module to track the set of all tenures.  It does so within a
//! (derived-state) table called `nakamoto_tenures`.  Whenever a `TenureChange` transaction is
//! processed, a new row will be added to this table.
//!
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
use wsts::curve::point::Point;

use crate::burnchains::{PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle, SortitionHandleTx};
use crate::chainstate::burn::{BlockSnapshot, SortitionHash};
use crate::chainstate::coordinator::{BlockEventDispatcher, Error};
use crate::chainstate::nakamoto::{
    MaturedMinerPaymentSchedules, MaturedMinerRewards, NakamotoBlock, NakamotoBlockHeader,
    NakamotoChainState,
};
use crate::chainstate::stacks::db::accounts::MinerReward;
use crate::chainstate::stacks::db::{
    ChainstateTx, ClarityTx, DBConfig as ChainstateConfig, MinerPaymentSchedule,
    MinerPaymentTxFees, MinerRewardInfo, StacksBlockHeaderTypes, StacksChainState, StacksDBTx,
    StacksEpochReceipt, StacksHeaderInfo,
};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksMicroblock, StacksTransaction,
    TenureChangeCause, TenureChangeError, TenureChangePayload, ThresholdSignature,
    TransactionPayload, MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use crate::clarity_vm::clarity::{ClarityInstance, PreCommitClarityBlock};
use crate::clarity_vm::database::SortitionDBRef;
use crate::core::BOOT_BLOCK_HASH;
use crate::monitoring;
use crate::net::Error as net_error;
use crate::util_lib::db::{
    query_int, query_row, query_row_panic, query_rows, u64_to_sql, DBConn, Error as DBError,
    FromRow,
};

pub static NAKAMOTO_TENURES_SCHEMA: &'static str = r#"
    CREATE TABLE nakamoto_tenures (
        -- consensus hash of start-tenure block (i.e. the consensus hash of the sortition in which the miner's block-commit
        -- was mined)
        tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the previous tenure's start-tenure block
        prev_tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the last-processed sortition
        burn_view_consensus_hash TEXT NOT NULL,
        -- whether or not this tenure was triggered by a sortition (as opposed to a tenure-extension).
        -- this is equal to the `cause` field in a TenureChange
        cause INETGER NOT NULL,
        -- block hash of start-tenure block
        block_hash TEXT NOT NULL,
        -- block ID of this start block (this is the StacksBlockId of the above tenure_id_consensus_hash and block_hash)
        block_id TEXT NOT NULL,
        -- this field is the total number of _sortition-induced_ tenures in the chain history (including this tenure),
        -- as of the _end_ of this block.  A tenure can contain multiple TenureChanges; if so, then this
        -- is the height of the _sortition-induced_ TenureChange that created it.
        coinbase_height INTEGER NOT NULL,
        -- number of blocks this tenure.
        -- * for tenure-changes induced by sortitions, this is the number of blocks in the previous tenure
        -- * for tenure-changes induced by extension, this is the number of blocks in the current tenure so far.
        num_blocks_confirmed INTEGER NOT NULL,
        -- this is the ith tenure transaction in its respective Nakamoto chain history.
        tenure_index INTEGER NOT NULL,

        PRIMARY KEY(burn_view_consensus_hash,tenure_index)
    );
    CREATE INDEX nakamoto_tenures_by_block_id ON nakamoto_tenures(block_id);
    CREATE INDEX nakamoto_tenures_by_tenure_id ON nakamoto_tenures(tenure_id_consensus_hash);
    CREATE INDEX nakamoto_tenures_by_block_and_consensus_hashes ON nakamoto_tenures(tenure_id_consensus_hash,block_hash);
    CREATE INDEX nakamoto_tenures_by_burn_view_consensus_hash ON nakamoto_tenures(burn_view_consensus_hash);
    CREATE INDEX nakamoto_tenures_by_tenure_index ON nakamoto_tenures(tenure_index);
    CREATE INDEX nakamoto_tenures_by_parent ON nakamoto_tenures(tenure_id_consensus_hash,prev_tenure_id_consensus_hash);
"#;

#[derive(Debug, Clone, PartialEq)]
pub struct NakamotoTenure {
    /// consensus hash of start-tenure block
    pub tenure_id_consensus_hash: ConsensusHash,
    /// consensus hash of parent tenure's start-tenure block
    pub prev_tenure_id_consensus_hash: ConsensusHash,
    /// sortition tip consensus hash when this tenure was processed
    pub burn_view_consensus_hash: ConsensusHash,
    /// the cause of this tenure -- either a new miner was chosen, or the current miner's tenure
    /// was extended
    pub cause: TenureChangeCause,
    /// block hash of start-tenure block
    pub block_hash: BlockHeaderHash,
    /// block ID of this start block
    pub block_id: StacksBlockId,
    /// number of sortition-tenures so far, including this one.
    /// This is, equivalently, the number of coinbases emitted so far.
    pub coinbase_height: u64,
    /// number of tenure-change transactions so far, including this one
    pub tenure_index: u64,
    /// number of blocks this tenure confirms
    pub num_blocks_confirmed: u32,
}

impl FromRow<NakamotoTenure> for NakamotoTenure {
    fn from_row(row: &rusqlite::Row) -> Result<NakamotoTenure, DBError> {
        let tenure_id_consensus_hash = row.get("tenure_id_consensus_hash")?;
        let prev_tenure_id_consensus_hash = row.get("prev_tenure_id_consensus_hash")?;
        let burn_view_consensus_hash = row.get("burn_view_consensus_hash")?;
        let cause_u8: u8 = row.get("cause")?;
        let cause = TenureChangeCause::try_from(cause_u8).map_err(|_| DBError::ParseError)?;
        let block_hash = row.get("block_hash")?;
        let block_id = row.get("block_id")?;
        let coinbase_height_i64: i64 = row.get("coinbase_height")?;
        let coinbase_height = coinbase_height_i64
            .try_into()
            .map_err(|_| DBError::ParseError)?;
        let tenure_index_i64: i64 = row.get("tenure_index")?;
        let tenure_index = tenure_index_i64
            .try_into()
            .map_err(|_| DBError::ParseError)?;
        let num_blocks_confirmed: u32 = row.get("num_blocks_confirmed")?;
        Ok(NakamotoTenure {
            tenure_id_consensus_hash,
            prev_tenure_id_consensus_hash,
            burn_view_consensus_hash,
            cause,
            block_hash,
            block_id,
            coinbase_height,
            tenure_index,
            num_blocks_confirmed,
        })
    }
}

impl NakamotoChainState {
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

    /// Get scheduled miner rewards that have matured when this tenure starts.
    /// Returns (list of miners to pay, any residual payments to the parent miner) on success.
    pub(crate) fn get_matured_miner_reward_schedules(
        chainstate_tx: &mut ChainstateTx,
        tip_index_hash: &StacksBlockId,
        coinbase_height: u64,
    ) -> Result<Option<MaturedMinerPaymentSchedules>, ChainstateError> {
        let mainnet = chainstate_tx.get_config().mainnet;

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        if coinbase_height < MINER_REWARD_MATURITY {
            return Ok(Some(MaturedMinerPaymentSchedules::genesis(mainnet)));
        }

        let matured_coinbase_height = coinbase_height - MINER_REWARD_MATURITY;
        let matured_tenure_block_header = Self::get_header_by_coinbase_height(
            chainstate_tx,
            &tip_index_hash,
            matured_coinbase_height,
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

    /// Return the coinbase height of `block` if it was a nakamoto block, or the
    ///  Stacks block height of `block` if it was an epoch-2 block
    ///
    /// In Stacks 2.x, the coinbase height and block height are the
    /// same. A miner's tenure in Stacks 2.x is entirely encompassed
    /// in the single Bitcoin-anchored Stacks block they produce, as
    /// well as the microblock stream they append to it.  But in Nakamoto,
    /// the coinbase height and block height are decoupled.
    pub fn get_coinbase_height(
        chainstate_conn: &Connection,
        block: &StacksBlockId,
    ) -> Result<Option<u64>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_block_headers WHERE index_block_hash = ?1";
        let result: Option<NakamotoBlockHeader> =
            query_row_panic(chainstate_conn, sql, &[&block], || {
                "FATAL: multiple rows for the same block hash".to_string()
            })?;
        if let Some(nak_hdr) = result {
            let nak_qry = "SELECT coinbase_height FROM nakamoto_tenures WHERE tenure_id_consensus_hash = ?1 ORDER BY tenure_index DESC LIMIT 1";
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

    /// Determine if a tenure has been fully processed.
    pub fn has_processed_nakamoto_tenure(
        conn: &Connection,
        tenure_id_consensus_hash: &ConsensusHash,
    ) -> Result<bool, ChainstateError> {
        // a tenure will have been processed if any of its children have been processed
        let sql = "SELECT 1 FROM nakamoto_tenures WHERE prev_tenure_id_consensus_hash = ?1 LIMIT 1";
        let args: &[&dyn ToSql] = &[tenure_id_consensus_hash];
        let found: Option<i64> = query_row(conn, sql, args)?;
        Ok(found.is_some())
    }

    /// Insert a nakamoto tenure.
    /// No validation will be done.
    pub(crate) fn insert_nakamoto_tenure(
        tx: &Connection,
        block_header: &NakamotoBlockHeader,
        coinbase_height: u64,
        tenure_index: u64,
        tenure: &TenureChangePayload,
    ) -> Result<(), ChainstateError> {
        // NOTE: this is checked with check_nakamoto_tenure()
        assert_eq!(block_header.consensus_hash, tenure.tenure_consensus_hash);
        let args: &[&dyn ToSql] = &[
            &tenure.tenure_consensus_hash,
            &tenure.prev_tenure_consensus_hash,
            &tenure.burn_view_consensus_hash,
            &tenure.cause.as_u8(),
            &block_header.block_hash(),
            &block_header.block_id(),
            &u64_to_sql(coinbase_height)?,
            &u64_to_sql(tenure_index)?,
            &tenure.previous_tenure_blocks,
        ];
        tx.execute(
            "INSERT INTO nakamoto_tenures
                (tenure_id_consensus_hash, prev_tenure_id_consensus_hash, burn_view_consensus_hash, cause,
                block_hash, block_id, coinbase_height, tenure_index, num_blocks_confirmed)
            VALUES
                (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            args,
        )?;

        Ok(())
    }

    /// Drop a nakamoto tenure.
    /// Used for testing
    #[cfg(test)]
    pub(crate) fn delete_nakamoto_tenure(
        tx: &Connection,
        ch: &ConsensusHash,
    ) -> Result<(), ChainstateError> {
        tx.execute(
            "DELETE FROM nakamoto_tenures WHERE tenure_id_consensus_hash = ?1",
            &[ch],
        )?;
        Ok(())
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

    /// Get the consensus hash of the parent tenure
    /// Used by the p2p code.
    /// Don't use in consensus code.
    pub fn get_nakamoto_parent_tenure_id_consensus_hash(
        chainstate_conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<ConsensusHash>, ChainstateError> {
        let sql = "SELECT prev_tenure_id_consensus_hash AS consensus_hash FROM nakamoto_tenures WHERE tenure_id_consensus_hash = ?1 ORDER BY tenure_index DESC LIMIT 1";
        let args: &[&dyn ToSql] = &[consensus_hash];
        query_row(chainstate_conn, sql, args).map_err(ChainstateError::DBError)
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

    /// Get the highest coinbase height processed.
    /// Returns Ok(Some(coinbase_height)) if we have processed at least one tenure
    /// Returns Ok(None) if we have not yet processed a Nakamoto tenure
    /// Returns Err(..) on database errors
    pub fn get_highest_nakamoto_coinbase_height(
        conn: &Connection,
        max: u64,
    ) -> Result<Option<u64>, ChainstateError> {
        match conn
            .query_row(
                "SELECT IFNULL(MAX(coinbase_height), 0) FROM nakamoto_tenures WHERE coinbase_height < ?1",
                &[&u64_to_sql(max)?],
                |row| Ok(u64::from_row(row).expect("Expected u64 in database")),
            )
            .optional()?
        {
            Some(0) => {
                // this never happens, so it's None
                Ok(None)
            }
            Some(height_i64) => {
                Ok(Some(
                    height_i64.try_into().map_err(|_| DBError::ParseError)?,
                ))
            }
            None => Ok(None),
        }
    }

    /// Get the nakamoto tenure by id
    pub fn get_nakamoto_tenure_change_by_tenure_id(
        headers_conn: &Connection,
        tenure_consensus_hash: &ConsensusHash,
    ) -> Result<Option<NakamotoTenure>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_tenures WHERE tenure_id_consensus_hash = ?1 ORDER BY tenure_index DESC LIMIT 1";
        let args: &[&dyn ToSql] = &[&tenure_consensus_hash];
        let tenure_opt: Option<NakamotoTenure> = query_row(headers_conn, sql, args)?;
        Ok(tenure_opt)
    }

    /// Get a nakamoto tenure-change by its tenure ID consensus hash.
    /// Get the highest such record.  It will be the last-processed BlockFound tenure
    /// for the given sortition consensus hash.
    pub fn get_highest_nakamoto_tenure_change_by_tenure_id(
        headers_conn: &Connection,
        tenure_id_consensus_hash: &ConsensusHash,
    ) -> Result<Option<NakamotoTenure>, ChainstateError> {
        let sql = "SELECT * FROM nakamoto_tenures WHERE tenure_id_consensus_hash = ?1 AND cause = ?2 ORDER BY tenure_index DESC LIMIT 1";
        let args: &[&dyn ToSql] = &[
            tenure_id_consensus_hash,
            &TenureChangeCause::BlockFound.as_u8(),
        ];
        let tenure_opt: Option<NakamotoTenure> = query_row(headers_conn, sql, args)?;
        Ok(tenure_opt)
    }

    /// Get the highest non-empty processed tenure on the canonical sortition history.
    pub fn get_highest_nakamoto_tenure(
        headers_conn: &Connection,
        sortdb_conn: &Connection,
    ) -> Result<Option<NakamotoTenure>, ChainstateError> {
        // find the tenure for the Stacks chain tip
        let (tip_ch, tip_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb_conn)?;
        if tip_ch == FIRST_BURNCHAIN_CONSENSUS_HASH || tip_bhh == FIRST_STACKS_BLOCK_HASH {
            // no chain tip, so no tenure
            return Ok(None);
        }
        Self::get_nakamoto_tenure_change_by_tenure_id(headers_conn, &tip_ch)
    }

    /// Verify that a tenure change tx is a valid first-ever tenure change.  It must connect to an
    /// epoch2 block, and it must be sortition-induced.
    ///
    /// Returns Some(mocked-epoch2-tenure) on success
    /// Returns None on error
    pub(crate) fn check_first_nakamoto_tenure_change(
        headers_conn: &Connection,
        tenure_payload: &TenureChangePayload,
    ) -> Result<Option<NakamotoTenure>, ChainstateError> {
        // must be a tenure-change
        if !tenure_payload.cause.expects_sortition() {
            warn!("Invalid tenure-change: not a sortition-induced tenure-change";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(None);
        }

        let Some(parent_header) =
            Self::get_block_header(headers_conn, &tenure_payload.previous_tenure_end)?
        else {
            warn!("Invalid tenure-change: no parent epoch2 header";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(None);
        };
        if tenure_payload.previous_tenure_blocks != 1 {
            warn!("Invalid tenure-change: expected 1 previous tenure block";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_blocks" => %tenure_payload.previous_tenure_blocks
            );
            return Ok(None);
        }
        let Some(epoch2_header_info) = parent_header.anchored_header.as_stacks_epoch2() else {
            warn!("Invalid tenure-change: parent header is not epoch2";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(None);
        };

        // synthesize the "last epoch2" tenure info, so we can calculate the first nakamoto tenure
        let last_epoch2_tenure = NakamotoTenure {
            tenure_id_consensus_hash: parent_header.consensus_hash.clone(),
            prev_tenure_id_consensus_hash: ConsensusHash([0x00; 20]), // ignored,
            burn_view_consensus_hash: parent_header.consensus_hash.clone(),
            cause: TenureChangeCause::BlockFound,
            block_hash: epoch2_header_info.block_hash(),
            block_id: StacksBlockId::new(
                &parent_header.consensus_hash,
                &epoch2_header_info.block_hash(),
            ),
            coinbase_height: epoch2_header_info.total_work.work,
            // NOTE: first Nakamoto tenure and tenure index will have height 1
            tenure_index: 0,
            num_blocks_confirmed: 1,
        };
        Ok(Some(last_epoch2_tenure))
    }

    /// Check that a consensus hash is on the canonical burnchain fork
    /// Returns Some(corresponding snapshot) if so
    /// Returns None if it's not on the canonical fork
    pub(crate) fn check_valid_consensus_hash<SH: SortitionHandle>(
        sort_handle: &mut SH,
        ch: &ConsensusHash,
    ) -> Result<Option<BlockSnapshot>, ChainstateError> {
        // the target sortition must exist, and it must be on the canonical fork
        let Some(sn) = SortitionDB::get_block_snapshot_consensus(sort_handle.sqlite(), ch)? else {
            // no sortition
            warn!("Invalid consensus hash: no such snapshot"; "consensus_hash" => %ch);
            return Ok(None);
        };
        let Some(ancestor_sn) = sort_handle.get_block_snapshot_by_height(sn.block_height)? else {
            // not canonical
            warn!("Invalid consensus hash: snapshot is not canonical"; "consensus_hash" => %ch);
            return Ok(None);
        };
        if ancestor_sn.sortition_id != sn.sortition_id {
            // not canonical
            return Ok(None);
        }
        Ok(Some(sn))
    }

    /// Check a Nakamoto tenure transaction's validity with respect to the last-processed tenure
    /// and the sortition DB.  This validates the following fields:
    /// * tenure_consensus_hash
    /// * prev_tenure_consensus_hash
    /// * previous_tenure_end
    /// * previous_tenure_blocks
    /// * cause
    ///
    /// Returns Ok(Some(processed-tenure)) on success
    /// Returns Ok(None) if the tenure change is invalid
    /// Returns Err(..) on DB error
    pub(crate) fn check_nakamoto_tenure<SH: SortitionHandle>(
        headers_conn: &Connection,
        sort_handle: &mut SH,
        block_header: &NakamotoBlockHeader,
        tenure_payload: &TenureChangePayload,
    ) -> Result<Option<NakamotoTenure>, ChainstateError> {
        // block header must match this tenure
        if block_header.consensus_hash != tenure_payload.tenure_consensus_hash {
            warn!("Invalid tenure-change (or block) -- mismatched consensus hash";
                  "tenure_payload.tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "block_header.consensus_hash" => %block_header.consensus_hash
            );
            return Ok(None);
        }

        // all consensus hashes must be on the canonical fork, if they're not the first-ever
        let Some(tenure_sn) =
            Self::check_valid_consensus_hash(sort_handle, &tenure_payload.tenure_consensus_hash)?
        else {
            return Ok(None);
        };
        let Some(sortition_sn) = Self::check_valid_consensus_hash(
            sort_handle,
            &tenure_payload.burn_view_consensus_hash,
        )?
        else {
            return Ok(None);
        };

        // tenure_sn must be no more recent than sortition_sn
        if tenure_sn.block_height > sortition_sn.block_height {
            warn!("Invalid tenure-change: tenure snapshot comes sortition snapshot"; "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash, "burn_view_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
            return Ok(None);
        }

        if tenure_payload.prev_tenure_consensus_hash != FIRST_BURNCHAIN_CONSENSUS_HASH {
            // the parent sortition must exist, must be canonical, and must be an ancestor of the
            // sortition for the given consensus hash.
            let Some(prev_sn) = Self::check_valid_consensus_hash(
                sort_handle,
                &tenure_payload.prev_tenure_consensus_hash,
            )?
            else {
                return Ok(None);
            };
            match tenure_payload.cause {
                TenureChangeCause::BlockFound => {
                    if prev_sn.block_height >= tenure_sn.block_height {
                        // parent comes after child
                        warn!("Invalid tenure-change: parent snapshot comes at or after current tenure"; "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash, "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
                        return Ok(None);
                    }
                }
                TenureChangeCause::Extended => {
                    // prev and current tenure consensus hashes must be identical
                    if prev_sn.consensus_hash != tenure_sn.consensus_hash {
                        warn!("Invalid tenure-change extension: parent snapshot is not the same as the current tenure snapshot"; "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash, "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
                        return Ok(None);
                    }
                }
            }

            if prev_sn.block_height > sortition_sn.block_height {
                // parent comes after tip
                warn!("Invalid tenure-change: parent snapshot comes after current tip"; "burn_view_consensus_hash" => %tenure_payload.burn_view_consensus_hash, "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
                return Ok(None);
            }
            if !prev_sn.sortition {
                // parent wasn't a sortition-induced tenure change
                warn!("Invalid tenure-change: no block found";
                      "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash
                );
                return Ok(None);
            }
        }

        // the tenure must correspond to sortitions
        if !tenure_sn.sortition {
            warn!("Invalid tenure-change: no block found";
                  "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash
            );
            return Ok(None);
        }

        // Note in the extend case, this will actually return the current tenure, not the parent as prev_tenure_consensus_hash will be the same as tenure_consensus_hash
        let Some(tenure) = Self::get_nakamoto_tenure_change_by_tenure_id(
            headers_conn,
            &tenure_payload.prev_tenure_consensus_hash,
        )?
        else {
            // not building off of a previous Nakamoto tenure.  This is the first tenure change.  It should point to an epoch
            // 2.x block.
            return Self::check_first_nakamoto_tenure_change(headers_conn, tenure_payload);
        };

        // validate cause
        match tenure_payload.cause {
            TenureChangeCause::BlockFound => {}
            TenureChangeCause::Extended => {
                // tenure extensions don't begin a new tenure (since the miner isn't changing), so
                // the tenure consensus hash must be the same as the previous tenure consensus hash
                if tenure_payload.tenure_consensus_hash != tenure_payload.prev_tenure_consensus_hash
                {
                    warn!("Invalid tenure-change: tenure extension tries to start a new tenure";
                          "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash,
                          "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash,
                    );
                    return Ok(None);
                }
            }
        };

        // The tenure-change must report the number of blocks _so far_ in the previous tenure (note if this is a TenureChangeCause::Extended, then its parent tenure will be its own tenure).
        // If there is a succession of tenure-extensions for a given tenure, then the reported tenure
        // length must report the number of blocks since the last _sortition-induced_ tenure
        // change.
        let tenure_len = Self::get_nakamoto_tenure_length(
            headers_conn,
            &tenure_payload.prev_tenure_consensus_hash,
        )?;
        if tenure_len != tenure_payload.previous_tenure_blocks {
            // invalid -- does not report the correct number of blocks in the past tenure
            warn!("Invalid tenure-change: wrong number of blocks";
                  "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash,
                  "tenure_len" => tenure_len,
                  "tenure_payload.previous_tenure_blocks" => tenure_payload.previous_tenure_blocks
            );
            return Ok(None);
        }

        Ok(Some(tenure))
    }

    /// Advance the tenures table with a validated block's tenure data.
    /// This applies to both tenure-changes and tenure-extends.
    /// Returns the tenure-change height (this is parent_coinbase_height + 1 if there was a
    /// tenure-change tx, or just parent_coinbase_height if there was a tenure-extend tx or no tenure
    /// txs at all).
    /// TODO: unit test
    pub(crate) fn advance_nakamoto_tenure(
        headers_tx: &mut StacksDBTx,
        sort_tx: &mut SortitionHandleTx,
        block: &NakamotoBlock,
        parent_coinbase_height: u64,
    ) -> Result<u64, ChainstateError> {
        let Some(tenure_payload) = block.get_tenure_tx_payload() else {
            // no new tenure
            return Ok(parent_coinbase_height);
        };

        let coinbase_height = match tenure_payload.cause {
            TenureChangeCause::BlockFound => {
                // tenure height advances
                parent_coinbase_height
                    .checked_add(1)
                    .expect("FATAL: too many tenures")
            }
            TenureChangeCause::Extended => {
                // tenure height does not advance
                parent_coinbase_height
            }
        };

        let Some(processed_tenure) =
            Self::check_nakamoto_tenure(headers_tx, sort_tx, &block.header, tenure_payload)?
        else {
            return Err(ChainstateError::InvalidStacksTransaction(
                "Invalid tenure tx".into(),
                false,
            ));
        };

        Self::insert_nakamoto_tenure(
            headers_tx,
            &block.header,
            coinbase_height,
            processed_tenure
                .tenure_index
                .checked_add(1)
                .expect("too many tenure-changes"),
            tenure_payload,
        )?;
        return Ok(coinbase_height);
    }

    /// Check that this block is in the same tenure as its parent, and that this tenure is the
    /// highest-seen tenure.  Use this to check blocks that do _not_ have tenure-changes.
    ///
    /// Returns Ok(bool) to indicate whether or not this block is in the same tenure as its parent.
    /// Returns Err(..) on DB error
    pub(crate) fn check_tenure_continuity(
        headers_conn: &Connection,
        sortdb_conn: &Connection,
        parent_ch: &ConsensusHash,
        block_header: &NakamotoBlockHeader,
    ) -> Result<bool, ChainstateError> {
        // block must have the same consensus hash as its parent
        if block_header.is_first_mined() || parent_ch != &block_header.consensus_hash {
            return Ok(false);
        }

        // block must be in the same tenure as the highest-processed tenure.
        let Some(highest_tenure) = Self::get_highest_nakamoto_tenure(headers_conn, sortdb_conn)?
        else {
            // no tenures yet, so definitely not continuous
            return Ok(false);
        };

        if &highest_tenure.tenure_id_consensus_hash != parent_ch {
            // this block is not in the highest-known tenure, so it can't be continuous
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate the scheduled block-reward for this tenure.
    /// - chainstate_tx: the transaction open against the chainstate
    /// - burn_dbconn: the sortition fork tx open against the sortition DB
    /// - block: the block being processed
    /// - parent_coinbase_height: the number of tenures represented by the parent of this block
    /// (equivalent to the number of coinbases)
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
        parent_coinbase_height: u64,
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
        let parent_tenure_start_header: StacksHeaderInfo = Self::get_header_by_coinbase_height(
            chainstate_tx,
            &block.header.parent_block_id,
            parent_coinbase_height,
        )?
        .ok_or_else(|| {
            warn!("While processing tenure change, failed to look up parent tenure";
                  "parent_coinbase_height" => parent_coinbase_height,
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

    /// Check that a given Nakamoto block's tenure's sortition exists and was processed on this
    /// particular burnchain fork.
    /// Return the block snapshot if so.
    pub(crate) fn check_sortition_exists(
        burn_dbconn: &mut SortitionHandleTx,
        block_consensus_hash: &ConsensusHash,
    ) -> Result<BlockSnapshot, ChainstateError> {
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
        let snapshot = burn_dbconn
            .get_block_snapshot(&burn_header_hash, &sortition_tip)?
            .ok_or_else(|| {
                warn!(
                    "Tried to process Nakamoto block before its burn view was processed";
                    "burn_header_hash" => %burn_header_hash,
                );
                ChainstateError::NoSuchBlockError
            })?;

        Ok(snapshot)
    }
}
