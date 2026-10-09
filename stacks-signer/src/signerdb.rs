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

use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::{TenureChangeCause, TransactionPayload};
use blockstack_lib::util_lib::db::{
    query_row, query_rows, sqlite_open, table_exists, tx_begin_immediate, u64_to_sql, DBTx,
    Error as DBError, FromColumn, FromRow,
};
use clarity::types::chainstate::{BurnchainHeaderHash, StacksAddress, StacksPublicKey};
use clarity::types::Address;
use libsigner::v0::messages::{RejectReason, RejectReasonPrefix, StateMachineUpdate};
use libsigner::v0::signer_state::GlobalStateEvaluator;
use libsigner::BlockProposal;
use rusqlite::functions::FunctionFlags;
use rusqlite::{params, Connection, Error as SqliteError, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use stacks_common::codec::{read_next, write_next, Error as CodecError, StacksMessageCodec};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
#[cfg(test)]
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::{debug, define_u8_enum, error, warn};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// A vote across the signer set for a block
pub struct NakamotoBlockVote {
    /// Signer signature hash (i.e. block hash) of the Nakamoto block
    pub signer_signature_hash: Sha512Trunc256Sum,
    /// Whether or not the block was rejected
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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
/// Struct for storing information about a burn block
pub struct BurnBlockInfo {
    /// The hash of the burn block
    pub block_hash: BurnchainHeaderHash,
    /// The height of the burn block
    pub block_height: u64,
    /// The consensus hash of the burn block
    pub consensus_hash: ConsensusHash,
    /// The hash of the parent burn block
    pub parent_burn_block_hash: BurnchainHeaderHash,
}

impl FromRow<BurnBlockInfo> for BurnBlockInfo {
    fn from_row(row: &rusqlite::Row) -> Result<Self, DBError> {
        let block_hash: BurnchainHeaderHash = row.get(0)?;
        let block_height: u64 = row.get(1)?;
        let consensus_hash: ConsensusHash = row.get(2)?;
        let parent_burn_block_hash: BurnchainHeaderHash = row.get(3)?;
        Ok(BurnBlockInfo {
            block_hash,
            block_height,
            consensus_hash,
            parent_burn_block_hash,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
/// Store extra version-specific info in `BlockInfo`
pub enum ExtraBlockInfo {
    #[default]
    /// Don't know what version
    None,
    /// Extra data for Signer V0
    V0,
}

define_u8_enum!(
/// Block state relative to the signer's view of the stacks blockchain
BlockState {
    /// The block has not yet been processed by the signer
    Unprocessed = 0,
    /// The block is accepted by the signer but a threshold of signers has not yet signed it
    LocallyAccepted = 1,
    /// The block is rejected by the signer but a threshold of signers has not accepted/rejected it yet
    LocallyRejected = 2,
    /// A threshold number of signers have signed the block
    GloballyAccepted = 3,
    /// A threshold number of signers have rejected the block
    GloballyRejected = 4,
    /// The block is pre-committed by the signer, but not yet signed
    PreCommitted = 5
});

impl TryFrom<u8> for BlockState {
    type Error = String;
    fn try_from(value: u8) -> Result<BlockState, String> {
        let state = match value {
            0 => BlockState::Unprocessed,
            1 => BlockState::LocallyAccepted,
            2 => BlockState::LocallyRejected,
            3 => BlockState::GloballyAccepted,
            4 => BlockState::GloballyRejected,
            5 => BlockState::PreCommitted,
            _ => return Err("Invalid block state".into()),
        };
        Ok(state)
    }
}

impl Display for BlockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            BlockState::Unprocessed => "Unprocessed",
            BlockState::LocallyAccepted => "LocallyAccepted",
            BlockState::LocallyRejected => "LocallyRejected",
            BlockState::GloballyAccepted => "GloballyAccepted",
            BlockState::GloballyRejected => "GloballyRejected",
            BlockState::PreCommitted => "PreCommitted",
        };
        write!(f, "{state}")
    }
}

impl TryFrom<&str> for BlockState {
    type Error = String;
    fn try_from(value: &str) -> Result<BlockState, String> {
        let state = match value {
            "Unprocessed" => BlockState::Unprocessed,
            "LocallyAccepted" => BlockState::LocallyAccepted,
            "LocallyRejected" => BlockState::LocallyRejected,
            "GloballyAccepted" => BlockState::GloballyAccepted,
            "GloballyRejected" => BlockState::GloballyRejected,
            "PreCommitted" => BlockState::PreCommitted,
            _ => return Err("Unparsable block state".into()),
        };
        Ok(state)
    }
}

/// Pending responses for a block proposal we had not yet seen
#[derive(Debug, Clone)]
pub struct PendingBlockResponses {
    /// Pre-commit responses for this block signer_addr
    pub pre_commits: Vec<StacksAddress>,
    /// Signature responses for this block (signer_addr, signature)
    pub signatures: Vec<(StacksAddress, MessageSignature)>,
    /// Rejection responses for this block (signer_addr, reject_code)
    pub rejections: Vec<(StacksAddress, RejectReasonPrefix)>,
}

impl PendingBlockResponses {
    /// Create an empty PendingBlockResponses
    pub fn empty() -> Self {
        Self {
            pre_commits: Vec::new(),
            signatures: Vec::new(),
            rejections: Vec::new(),
        }
    }

    /// Check if this pending responses collection contains any entries
    pub fn is_empty(&self) -> bool {
        self.pre_commits.is_empty() && self.signatures.is_empty() && self.rejections.is_empty()
    }
}

/// Additional Info about a proposed block
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BlockInfo {
    /// The block we are considering
    pub block: NakamotoBlock,
    /// The burn block height at which the block was proposed
    pub burn_block_height: u64,
    /// The reward cycle the block belongs to
    pub reward_cycle: u64,
    /// Our vote on the block if we have one yet
    pub vote: Option<NakamotoBlockVote>,
    /// Whether the block contents are valid according to our local and node validation. None if not yet validated.
    pub valid: Option<bool>,
    /// Time at which the proposal was received by this signer (epoch time in seconds)
    pub proposed_time: u64,
    /// Time at which the proposal was pre-commited to by this signer (epoch time in seconds)
    pub approved_time: Option<u64>,
    /// Time at which the proposal was signed by this signer (epoch time in seconds)
    pub signed_self: Option<u64>,
    /// Time at which the proposal was signed by a threshold in the signer set (epoch time in seconds)
    pub signed_group: Option<u64>,
    /// The block state relative to the signer's view of the stacks blockchain
    pub state: BlockState,
    /// Consumed processing time in milliseconds to validate this block
    pub validation_time_ms: Option<u64>,
    /// Extra data specific to v0, v1, etc.
    pub ext: ExtraBlockInfo,
    /// If this signer rejected this block, what was the reason
    pub reject_reason: Option<RejectReason>,
}

impl From<BlockProposal> for BlockInfo {
    fn from(value: BlockProposal) -> Self {
        Self {
            block: value.block,
            burn_block_height: value.burn_height,
            reward_cycle: value.reward_cycle,
            vote: None,
            valid: None,
            proposed_time: get_epoch_time_secs(),
            approved_time: None,
            signed_self: None,
            signed_group: None,
            ext: ExtraBlockInfo::default(),
            state: BlockState::Unprocessed,
            validation_time_ms: None,
            reject_reason: None,
        }
    }
}
impl BlockInfo {
    /// Whether the block is a tenure extend/change block or not. Used only for schema migrations
    fn is_tenure_change(&self) -> bool {
        self.block
            .txs()
            .next()
            .map(|tx| matches!(tx.payload(), TransactionPayload::TenureChange(_)))
            .unwrap_or(false)
    }

    /// If the block has a tenure change tx, return the cause
    fn tenure_change_cause(&self) -> Option<TenureChangeCause> {
        let tx = self.block.txs().next()?;
        let TransactionPayload::TenureChange(ref tenure_change) = tx.payload() else {
            // if its not a tenure change payload at all, return None
            return None;
        };
        Some(tenure_change.cause)
    }

    /// Mark this block as valid, record the approved time timestamp if not already set and attempt to mark it as pre-committed.
    pub fn mark_pre_committed(&mut self) -> Result<(), String> {
        self.valid = Some(true);
        self.approved_time.get_or_insert(get_epoch_time_secs());
        self.move_to(BlockState::PreCommitted)
    }

    /// Mark this block as valid and the appropriate timestamps if they aren't already set, and attempt to mark it as locally accepted.
    pub fn mark_locally_accepted(&mut self, group_signed: bool) -> Result<(), String> {
        if group_signed {
            self.signed_group.get_or_insert(get_epoch_time_secs());
        } else {
            self.valid = Some(true);
            self.approved_time.get_or_insert(get_epoch_time_secs());
            self.signed_self.get_or_insert(get_epoch_time_secs());
        }
        self.move_to(BlockState::LocallyAccepted)
    }

    /// Mark this block's signed group time if not already set and attempt to mark it as globally accepted.
    pub fn mark_globally_accepted(&mut self) -> Result<(), String> {
        self.signed_group.get_or_insert(get_epoch_time_secs());
        self.move_to(BlockState::GloballyAccepted)
    }

    /// Mark this block as invalid and attempt to mark it as locally rejected
    pub fn mark_locally_rejected(&mut self) -> Result<(), String> {
        self.valid = Some(false);
        self.move_to(BlockState::LocallyRejected)
    }

    /// Attempt to mark the block as globally rejected
    pub fn mark_globally_rejected(&mut self) -> Result<(), String> {
        self.move_to(BlockState::GloballyRejected)
    }

    /// Return the block's signer signature hash
    pub fn signer_signature_hash(&self) -> Sha512Trunc256Sum {
        self.block.header.signer_signature_hash()
    }

    /// Check if the block state transition is valid
    fn check_state(&self, state: BlockState) -> bool {
        let prev_state = &self.state;
        if *prev_state == state {
            return true;
        }
        match state {
            BlockState::Unprocessed => false,
            BlockState::LocallyAccepted | BlockState::LocallyRejected => !matches!(
                prev_state,
                BlockState::GloballyRejected | BlockState::GloballyAccepted
            ),
            // A block only becomes globally accepted on evidence from the node that it is part
            // of the chain (a new block event, or the node reporting it as a tenure tip). That
            // overrides any other state, which is only inferred from signer messages: a block
            // can cross the rejection threshold on rejections that are later reconsidered and
            // still go on to reach the acceptance threshold.
            BlockState::GloballyAccepted => true,
            BlockState::GloballyRejected => !matches!(prev_state, BlockState::GloballyAccepted),
            BlockState::PreCommitted => matches!(prev_state, BlockState::Unprocessed),
        }
    }

    /// Attempt to transition the block state
    pub fn move_to(&mut self, state: BlockState) -> Result<(), String> {
        if !self.check_state(state) {
            return Err(format!(
                "Invalid state transition from {} to {state}",
                self.state
            ));
        }
        self.state = state;
        Ok(())
    }

    /// Check if the block is globally accepted or rejected
    pub fn has_reached_consensus(&self) -> bool {
        matches!(
            self.state,
            BlockState::GloballyAccepted | BlockState::GloballyRejected
        )
    }

    /// Check if the block is pre-committed, locally accepted or locally rejected
    pub fn is_locally_finalized(&self) -> bool {
        matches!(
            self.state,
            BlockState::PreCommitted | BlockState::LocallyAccepted | BlockState::LocallyRejected
        )
    }

    /// Check if the block is globally accepted and this signer has responded to it
    pub fn globally_approved_and_responded(&self) -> bool {
        matches!(self.state, BlockState::GloballyAccepted)
            && (self.signed_self.is_some() || self.valid == Some(false))
    }

    /// Perform static checks on the BlockInfo and determine if it is syntactically valid.
    /// Specifically, all integer values must be less than i64::MAX, since these values get stored
    /// in the sqlite DB via u64_to_sql()
    pub fn check_static_valid_block(&self) -> bool {
        let max_val = u64::try_from(i64::MAX).expect("infallible");
        if self.block.header.chain_length >= max_val {
            return false;
        }
        if self.burn_block_height >= max_val {
            return false;
        }
        if self.reward_cycle >= max_val {
            return false;
        }
        true
    }
}

/// How far below the burnchain tip, in burn blocks, a fork can still matter to the signer. It
/// bounds everything the signer database keeps by age.
/// Used as an input for pruning operations such as [`SignerDb::prune_superseded_tenures`] and
/// [`SignerDb::prune`].
/// NOTE: A fork deeper than this would cause much bigger problems than a stale conflict or
/// a missing local record.
pub const MAX_FORK_DEPTH: u64 = 100;

/// The parameters of one pruning pass (see [`SignerDb::prune`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneParams {
    /// The per-table limit of the pass: at most this many blocks, each together with its per-block
    /// rows, and at most this many rows per delete of each burn block keyed table. A large backlog
    /// drains over repeated passes.
    pub batch_size: u64,
    /// How far below the burn tip, in burn blocks, the fork horizon is placed. Everything the
    /// signer may still need for a fork up to that depth is kept.
    pub fork_depth: u64,
    /// How long records tied to a burn block this signer never recorded are kept, e.g. because it
    /// missed the burn block during an outage or started mid-tenure: the blocks and activity of
    /// such a tenure, and other signers' timestamps for such a burn block. Their age is not
    /// measured up to now but up to the arrival of the burn block of the tenure in charge at the
    /// fork horizon (see [`PruneTx`]), so it only advances as that horizon does.
    pub orphaned_update_max_age: Duration,
}

/// What a single [`SignerDb::prune`] pass removed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PruneStats {
    /// The block height below which whole tenures were eligible for removal, or `None` if the
    /// pass could not place the fork horizon and removed nothing.
    pub cutoff_height: Option<u64>,
    /// Rows removed from `blocks`
    pub blocks: u64,
    /// Rows removed from the per-block tables (signatures, pre-commits, rejections, pending
    /// validations) along with those blocks
    pub block_rows: u64,
    /// Rows removed from the burn block and reward cycle keyed tables
    pub other_rows: u64,
}

impl PruneStats {
    /// The result of a pass that could not place the fork horizon: nothing was removed.
    pub fn skipped() -> Self {
        Self::default()
    }

    /// Whether the pass removed any row. Once the database is up to date most passes remove
    /// nothing, since data crosses the fork horizon only about once per tenure.
    pub fn removed_any(&self) -> bool {
        self.blocks > 0 || self.block_rows > 0 || self.other_rows > 0
    }

    /// Whether the pass skipped the retention rule because it could not place the fork horizon
    /// from local data, e.g. on a new database or a signer that was offline. A skipped pass never
    /// removes anything, but a pass that removes nothing is usually not skipped.
    pub fn is_skipped(&self) -> bool {
        self.cutoff_height.is_none()
    }
}

/// Where a pruning pass places the fork horizon, and what it may remove behind it (see
/// [`SignerDb::prune`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneHorizon {
    /// The highest burn block recorded in the database
    pub burn_tip: u64,
    /// Burn height of the tenure in charge at the fork horizon
    pub in_charge_burn_height: u64,
    /// The lowest accepted Stacks height of the tenure in charge: blocks below it may be removed
    pub cutoff_height: u64,
    /// Records whose burn block was never recorded are removed once their last activity is
    /// before this time (epoch seconds)
    pub orphan_cutoff: u64,
}

impl PruneHorizon {
    /// Place the fork horizon `params.fork_depth` burn blocks below the burn tip, from local data
    /// only (see [`PruneTx`]). `None` if it cannot be placed. Only reads.
    fn place(conn: &Connection, params: &PruneParams) -> Result<Option<Self>, DBError> {
        let accepted = BlockState::GloballyAccepted.to_string();

        let tip: Option<(u64, u64)> = conn
            .query_row(
                "SELECT block_height, received_time FROM burn_blocks
                 ORDER BY block_height DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((burn_tip, tip_received_time)) = tip else {
            return Ok(None);
        };
        let Some(horizon) = burn_tip.checked_sub(params.fork_depth) else {
            return Ok(None);
        };

        // The tenure in charge at the horizon: the latest sortition at or below it whose tenure
        // has accepted blocks.
        let in_charge: Option<(String, u64, u64)> = conn
            .query_row(
                "SELECT bb.consensus_hash, bb.block_height, bb.received_time FROM burn_blocks bb
                 WHERE bb.block_height <= ?1 AND bb.block_height >= ?2
                   AND EXISTS (SELECT 1 FROM blocks b
                               WHERE b.consensus_hash = bb.consensus_hash AND b.state = ?3)
                 ORDER BY bb.block_height DESC LIMIT 1",
                params![
                    horizon,
                    horizon.saturating_sub(params.fork_depth),
                    &accepted
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((in_charge_tenure, in_charge_burn_height, in_charge_received_time)) = in_charge
        else {
            return Ok(None);
        };
        let cutoff_height: Option<u64> = conn.query_row(
            "SELECT MIN(stacks_height) FROM blocks WHERE consensus_hash = ?1 AND state = ?2",
            params![&in_charge_tenure, &accepted],
            |row| row.get(0),
        )?;
        let Some(cutoff_height) = cutoff_height else {
            return Ok(None);
        };
        let orphan_cutoff = in_charge_received_time
            .min(tip_received_time)
            .saturating_sub(params.orphaned_update_max_age.as_secs());

        Ok(Some(Self {
            burn_tip,
            in_charge_burn_height,
            cutoff_height,
            orphan_cutoff,
        }))
    }
}

/// One pruning pass over the signer db (run by [`SignerDb::prune`]), in a single `IMMEDIATE`
/// transaction: [`PruneTx::begin`] opens it and places the fork horizon (a [`PruneHorizon`]),
/// [`PruneTx::execute`] removes what lies behind it and [`PruneTx::commit`] keeps the result.
/// Dropping it before the commit rolls the whole pass back.
///
/// A pass removes what no fork can reach any more: every tenure elected before the one in charge
/// at the fork horizon ([`PruneParams::fork_depth`] burn blocks below the burn tip), together
/// with its per-block rows, and the burn block and reward cycle keyed records that go with it.
/// The reward cycle keyed signer state is small and is aged in full. Records tied to a burn block
/// this signer never recorded have no election height to compare, so they are removed by age
/// instead (see the orphan cutoff below).
///
/// The horizon is placed from data the signer trusts: burn blocks come from its own node, and
/// block heights only from [`BlockState::GloballyAccepted`] blocks. The burn height and reward
/// cycle a miner puts in a proposal are never used. If the tenure in charge at the horizon cannot
/// be found within a further [`PruneParams::fork_depth`] burn blocks (e.g. a fresh database or a
/// signer that was offline), the pass removes nothing.
///
/// A block is removed only if all of these rules hold:
/// 1. it is below the lowest accepted height of the tenure in charge at the horizon (the cutoff),
/// 2. no block of its tenure is at or above the cutoff: a tenure becomes removable only as a
///    whole, though its blocks may take several passes, oldest first, and an older tenure still
///    producing blocks (e.g. extended after a failover) is kept,
/// 3. its tenure is known to be elected before the tenure in charge (its burn block is recorded
///    below the burn block of the tenure in charge), or its election is unknown (no burn block
///    recorded, e.g. a database started mid-tenure) and its last activity is before the orphan
///    cutoff.
///
/// Rule 3 is what keeps recent tenures; the Stacks heights alone cannot. The tenure in charge is
/// not known to be canonical: after a Bitcoin reorg, a tenure of the orphaned branch keeps its
/// accepted blocks and may be the one found at the horizon, with a cutoff above the heights of
/// the replacement branch, up to its tip.
///
/// The orphan cutoff is [`PruneParams::orphaned_update_max_age`] before the arrival of the burn
/// block of the tenure in charge, capped at the arrival of the newest burn block. It applies to
/// every record whose burn block this signer never recorded: blocks and `tenure_activity` of an
/// unknown election, and other signers' burn block timestamps. Measured from the tenure in
/// charge, a tenure must lie behind the horizon by depth as well as by age, and a late burn block
/// moves the cutoff only once it reaches the horizon itself. The cap matters only when arrival
/// times are out of height order (e.g. a burn block event delivered again): the cutoff is then
/// never later than one measured from the newest burn block. An unknown election's activity is
/// the latest proposal, approval or signature time of its blocks, or its `tenure_activity`. This
/// is a retention policy, not proof of the election height: arrival times are local
/// observations, so delayed or replayed events and clock changes shift it.
struct PruneTx<'a> {
    tx: DBTx<'a>,
    /// The parameters of this pass
    params: PruneParams,
    /// The fork horizon of this pass
    horizon: PruneHorizon,
    /// What the pass has removed so far
    stats: PruneStats,
}

impl<'a> PruneTx<'a> {
    /// Open the transaction and place the fork horizon in it. `None` if it cannot be placed; the
    /// transaction is then dropped and nothing is written.
    fn begin(conn: &'a mut Connection, params: PruneParams) -> Result<Option<Self>, DBError> {
        let tx = tx_begin_immediate(conn)?;
        let Some(horizon) = PruneHorizon::place(&tx, &params)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            tx,
            params,
            horizon,
            stats: PruneStats::default(),
        }))
    }

    /// Run every step of the pass, in the order the rule needs. Run it once per pass: each step
    /// removes at most one batch.
    fn execute(&mut self) -> Result<(), DBError> {
        self.prune_blocks()?;
        // Burn block records are aged once nothing refers to them any more, so after the blocks.
        self.prune_burn_block_records()?;
        self.prune_reward_cycle_state()
    }

    /// Commit the pass and return what it removed
    fn commit(self) -> Result<PruneStats, DBError> {
        let Self {
            tx,
            horizon,
            mut stats,
            ..
        } = self;
        tx.commit()?;
        stats.cutoff_height = Some(horizon.cutoff_height);
        Ok(stats)
    }

    /// Rows removed by one statement, as a statistic
    fn count(removed: usize) -> u64 {
        u64::try_from(removed).unwrap_or(u64::MAX)
    }

    /// Remove at most one batch of blocks, each together with its per-block rows. See [`PruneTx`]
    /// for the three conditions a block must meet. Blocks of tenures with a known election go
    /// first; tenures with an unknown election take what is left of the batch. Either way, a
    /// tenure loses its oldest blocks first.
    fn prune_blocks(&mut self) -> Result<(), DBError> {
        let batch_size = usize::try_from(self.params.batch_size).unwrap_or(usize::MAX);
        let mut hashes = self.known_election_blocks()?;
        if hashes.len() < batch_size {
            for tenure in self.expired_unknown_elections()? {
                let remaining = batch_size - hashes.len();
                if remaining == 0 {
                    break;
                }
                hashes.extend(self.tenure_blocks(&tenure, remaining)?);
            }
        }
        for hash in &hashes {
            for table in [
                "block_signatures",
                "block_pre_commits",
                "block_rejection_signer_addrs",
                "block_validations_pending",
            ] {
                let removed = self.tx.execute(
                    &format!("DELETE FROM {table} WHERE signer_signature_hash = ?1"),
                    params![hash],
                )?;
                self.stats.block_rows = self.stats.block_rows.saturating_add(Self::count(removed));
            }
            let removed = self.tx.execute(
                "DELETE FROM blocks WHERE signer_signature_hash = ?1",
                params![hash],
            )?;
            self.stats.blocks = self.stats.blocks.saturating_add(Self::count(removed));
        }
        Ok(())
    }

    /// At most one batch of removable blocks of tenures with a known election: oldest election
    /// first, and within a tenure oldest block first.
    ///
    /// The scan walks the burn blocks below the tenure in charge, in height order, and stops once
    /// the batch is full. Blocks whose tenure has no recorded burn block are never visited, so
    /// they cost nothing here however many there are (e.g. blocks from before burn blocks were
    /// keyed by consensus hash, whose records a schema migration dropped). `CROSS JOIN` keeps
    /// `burn_blocks` as the outer loop: left to itself, SQLite walks every block below the cutoff
    /// instead. The whole-tenure check refers to the burn block only, so it runs once per tenure.
    /// Rule 1 is implied by rule 2, but narrows each tenure's blocks.
    fn known_election_blocks(&self) -> Result<Vec<String>, DBError> {
        let mut stmt = self.tx.prepare(
            "SELECT b.signer_signature_hash FROM burn_blocks bb
             CROSS JOIN blocks b
             WHERE b.consensus_hash = bb.consensus_hash
               AND bb.block_height < ?2
               AND b.stacks_height < ?1
               AND NOT EXISTS (SELECT 1 FROM blocks t
                               WHERE t.consensus_hash = bb.consensus_hash
                                 AND t.stacks_height >= ?1)
             ORDER BY bb.block_height ASC, b.stacks_height ASC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![
                self.horizon.cutoff_height,
                self.horizon.in_charge_burn_height,
                u64_to_sql(self.params.batch_size)?
            ],
            |row| row.get(0),
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The tenures with an unknown election that are removable: every block below the cutoff,
    /// no burn block recorded, and no activity at or after the orphan cutoff.
    ///
    /// Each tenure is checked once, not once per block. Candidates come from the blocks below the
    /// cutoff, which the scan reads from an index alone. Their blocks are fetched separately (see
    /// [`Self::tenure_blocks`]): selecting them in the same statement makes SQLite scan every
    /// block to test its tenure, even when no tenure has expired.
    ///
    /// At most one batch of tenures is returned, as each has at least one block; the others are
    /// found again by a later pass. The limit applies to tenures that passed the checks, never to
    /// the candidates, so a candidate that is kept cannot hide one behind it.
    ///
    /// NOTE: No index serves the `candidates` query directly, so SQLite reads every entry of
    /// `blocks_consensus_hash_state_height` (about 20 ms per million blocks). This runs only when
    /// tenures with a known election leave room in the batch, so not while a backlog of them
    /// drains, and by then the table is small. An index on `blocks (stacks_height,
    /// consensus_hash)` would save little, but would have to be built over the whole table of a
    /// large database when it upgrades, and updated on every block write.
    fn expired_unknown_elections(&self) -> Result<Vec<String>, DBError> {
        let mut stmt = self.tx.prepare(
            "WITH candidates AS MATERIALIZED (
                 SELECT DISTINCT consensus_hash FROM blocks WHERE stacks_height < ?1
             )
             SELECT c.consensus_hash FROM candidates c
             WHERE NOT EXISTS (SELECT 1 FROM burn_blocks bb
                               WHERE bb.consensus_hash = c.consensus_hash)
               AND NOT EXISTS (SELECT 1 FROM blocks t
                               WHERE t.consensus_hash = c.consensus_hash
                                 AND t.stacks_height >= ?1)
               AND NOT EXISTS (SELECT 1 FROM blocks t
                               WHERE t.consensus_hash = c.consensus_hash
                                 AND MAX(t.proposed_time,
                                         COALESCE(t.approved_time, 0),
                                         COALESCE(t.signed_self, 0),
                                         COALESCE(t.signed_group, 0)) >= ?2)
               AND NOT EXISTS (SELECT 1 FROM tenure_activity ta
                               WHERE ta.consensus_hash = c.consensus_hash
                                 AND ta.last_activity_time >= ?2)
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![
                self.horizon.cutoff_height,
                self.horizon.orphan_cutoff,
                u64_to_sql(self.params.batch_size)?
            ],
            |row| row.get(0),
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// At most `limit` blocks of `tenure`, oldest first
    fn tenure_blocks(&self, tenure: &str, limit: usize) -> Result<Vec<String>, DBError> {
        let mut stmt = self.tx.prepare(
            "SELECT signer_signature_hash FROM blocks WHERE consensus_hash = ?1
             ORDER BY stacks_height ASC LIMIT ?2",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt.query_map(params![tenure, limit], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Age the burn block keyed records of sortitions before the tenure in charge, oldest first.
    /// `burn_blocks` goes last: it is how the others are aged, and a record is kept while anything
    /// still refers to it.
    ///
    /// The `burn_blocks` delete only examines its `batch_size` oldest candidates, so its cost
    /// stays bounded however large a backlog is. Candidates exclude records still referred to by
    /// `blocks`, the only reference that can outlive the horizon (a kept tip tenure, or a tenure
    /// kept whole); the other references are aged oldest first just before, so the oldest
    /// candidates are always the next to become free.
    fn prune_burn_block_records(&mut self) -> Result<(), DBError> {
        let batch_size_sql = u64_to_sql(self.params.batch_size)?;
        let removed = self.tx.execute(
            "DELETE FROM burn_block_updates_received_times WHERE rowid IN (
                SELECT u.rowid FROM burn_block_updates_received_times u
                JOIN burn_blocks bb ON bb.consensus_hash = u.burn_block_consensus_hash
                WHERE bb.block_height < ?1
                ORDER BY bb.block_height LIMIT ?2)",
            params![self.horizon.in_charge_burn_height, batch_size_sql],
        )?;
        let removed_count = Self::count(removed);
        self.stats.other_rows = self.stats.other_rows.saturating_add(removed_count);

        // Timestamps for a burn block this signer never recorded cannot be aged by height. They
        // are kept while a peer's update may simply have arrived before our own burn block, and
        // removed once past the orphan cutoff, too old to belong to the current or last sortition,
        // the only ones they are read for. This runs only once the height-based aging above has
        // caught up, so the scan stays over a small table.
        if removed_count < self.params.batch_size {
            let removed = self.tx.execute(
                "DELETE FROM burn_block_updates_received_times WHERE rowid IN (
                    SELECT u.rowid FROM burn_block_updates_received_times u
                    WHERE u.received_time < ?1
                      AND NOT EXISTS (SELECT 1 FROM burn_blocks bb
                                      WHERE bb.consensus_hash = u.burn_block_consensus_hash)
                    ORDER BY u.received_time LIMIT ?2)",
                params![self.horizon.orphan_cutoff, batch_size_sql],
            )?;
            self.stats.other_rows = self.stats.other_rows.saturating_add(Self::count(removed));
        }

        let removed = self.tx.execute(
            "DELETE FROM tenure_activity WHERE rowid IN (
                SELECT ta.rowid FROM tenure_activity ta
                JOIN burn_blocks bb ON bb.consensus_hash = ta.consensus_hash
                WHERE bb.block_height < ?1
                  AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.consensus_hash = ta.consensus_hash)
                ORDER BY bb.block_height LIMIT ?2)",
            params![self.horizon.in_charge_burn_height, batch_size_sql],
        )?;
        let removed_count = Self::count(removed);
        self.stats.other_rows = self.stats.other_rows.saturating_add(removed_count);

        // Activity of a tenure whose burn block this signer never recorded, once its blocks are
        // gone (see `prune_blocks`) and it is past the orphan cutoff, with the rest of the batch.
        if removed_count < self.params.batch_size {
            let removed = self.tx.execute(
                "DELETE FROM tenure_activity WHERE rowid IN (
                    SELECT ta.rowid FROM tenure_activity ta
                    WHERE ta.last_activity_time < ?1
                      AND NOT EXISTS (SELECT 1 FROM burn_blocks bb
                                      WHERE bb.consensus_hash = ta.consensus_hash)
                      AND NOT EXISTS (SELECT 1 FROM blocks b
                                      WHERE b.consensus_hash = ta.consensus_hash)
                    ORDER BY ta.last_activity_time LIMIT ?2)",
                params![
                    self.horizon.orphan_cutoff,
                    u64_to_sql(self.params.batch_size - removed_count)?
                ],
            )?;
            self.stats.other_rows = self.stats.other_rows.saturating_add(Self::count(removed));
        }

        let removed = self.tx.execute(
            "DELETE FROM burn_blocks WHERE rowid IN (
                SELECT candidate.rowid FROM (
                    SELECT bb.rowid, bb.consensus_hash FROM burn_blocks bb
                    WHERE bb.block_height < ?1
                      AND NOT EXISTS (SELECT 1 FROM blocks b
                                      WHERE b.consensus_hash = bb.consensus_hash)
                    ORDER BY bb.block_height LIMIT ?2) candidate
                WHERE NOT EXISTS (SELECT 1 FROM tenure_activity ta
                                  WHERE ta.consensus_hash = candidate.consensus_hash)
                  AND NOT EXISTS (SELECT 1 FROM burn_block_updates_received_times u
                                  WHERE u.burn_block_consensus_hash = candidate.consensus_hash))",
            params![self.horizon.in_charge_burn_height, batch_size_sql],
        )?;
        self.stats.other_rows = self.stats.other_rows.saturating_add(Self::count(removed));
        Ok(())
    }

    /// Keep signer state for the latest reward cycle this signer has recorded and the one before
    /// it. These cycles come from the signer's own configuration, never from a miner.
    fn prune_reward_cycle_state(&mut self) -> Result<(), DBError> {
        for table in ["signer_state_machine_updates", "signer_states"] {
            let removed = self.tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE reward_cycle < (SELECT MAX(reward_cycle) - 1 FROM {table})"
                ),
                [],
            )?;
            self.stats.other_rows = self.stats.other_rows.saturating_add(Self::count(removed));
        }
        Ok(())
    }
}

/// This struct manages a SQLite database connection
/// for the signer.
#[derive(Debug)]
pub struct SignerDb {
    /// Connection to the SQLite database
    db: Connection,
}

static CREATE_BLOCKS_TABLE_1: &str = "
CREATE TABLE IF NOT EXISTS blocks (
    reward_cycle INTEGER NOT NULL,
    signer_signature_hash TEXT NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    signed_over INTEGER NOT NULL,
    stacks_height INTEGER NOT NULL,
    burn_block_height INTEGER NOT NULL,
    PRIMARY KEY (reward_cycle, signer_signature_hash)
) STRICT";

static CREATE_BLOCKS_TABLE_2: &str = "
CREATE TABLE IF NOT EXISTS blocks (
    reward_cycle INTEGER NOT NULL,
    signer_signature_hash TEXT NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    signed_over INTEGER NOT NULL,
    broadcasted INTEGER,
    stacks_height INTEGER NOT NULL,
    burn_block_height INTEGER NOT NULL,
    PRIMARY KEY (reward_cycle, signer_signature_hash)
) STRICT";

static CREATE_INDEXES_1: &str = "
CREATE INDEX IF NOT EXISTS blocks_signed_over ON blocks (signed_over);
CREATE INDEX IF NOT EXISTS blocks_consensus_hash ON blocks (consensus_hash);
CREATE INDEX IF NOT EXISTS blocks_valid ON blocks ((json_extract(block_info, '$.valid')));
CREATE INDEX IF NOT EXISTS burn_blocks_height ON burn_blocks (block_height);
";

static CREATE_INDEXES_2: &str = r#"
CREATE INDEX IF NOT EXISTS block_signatures_on_signer_signature_hash ON block_signatures(signer_signature_hash);
"#;

static CREATE_INDEXES_3: &str = r#"
CREATE INDEX IF NOT EXISTS block_rejection_signer_addrs_on_block_signature_hash ON block_rejection_signer_addrs(signer_signature_hash);
"#;

static CREATE_INDEXES_4: &str = r#"
CREATE INDEX IF NOT EXISTS blocks_state ON blocks ((json_extract(block_info, '$.state')));
CREATE INDEX IF NOT EXISTS blocks_signed_group ON blocks ((json_extract(block_info, '$.signed_group')));
"#;

static CREATE_INDEXES_5: &str = r#"
CREATE INDEX IF NOT EXISTS blocks_signed_over ON blocks (consensus_hash, signed_over);
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_state ON blocks (consensus_hash, state);
CREATE INDEX IF NOT EXISTS blocks_state ON blocks (state);
CREATE INDEX IF NOT EXISTS blocks_signed_group ON blocks (signed_group);
"#;

static CREATE_INDEXES_6: &str = r#"
CREATE INDEX IF NOT EXISTS block_validations_pending_on_added_time ON block_validations_pending(added_time ASC);
"#;

static CREATE_INDEXES_8: &str = r#"
-- Add new index for get_last_globally_accepted_block query
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_state_height ON blocks (consensus_hash, state, stacks_height DESC);

-- Add new index for get_canonical_tip query
CREATE INDEX IF NOT EXISTS blocks_state_height_signed_group ON blocks (state, stacks_height DESC, signed_group DESC);

-- Index for get_first_signed_block_in_tenure
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_status_height ON blocks (consensus_hash, signed_over, stacks_height ASC);

-- Index for has_unprocessed_blocks
CREATE INDEX IF NOT EXISTS blocks_reward_cycle_state on blocks (reward_cycle, state);
"#;

static CREATE_INDEXES_11: &str = r#"
CREATE INDEX IF NOT EXISTS signer_state_machine_updates_reward_cycle_received_time ON signer_state_machine_updates (reward_cycle, received_time ASC);
"#;

static CREATE_SIGNER_STATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS signer_states (
    reward_cycle INTEGER PRIMARY KEY,
    encrypted_state BLOB NOT NULL
) STRICT";

static CREATE_BURN_STATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS burn_blocks (
    block_hash TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    received_time INTEGER NOT NULL
) STRICT";

static CREATE_DB_CONFIG: &str = "
    CREATE TABLE db_config(
        version INTEGER NOT NULL
    ) STRICT
";

static DROP_SCHEMA_0: &str = "
   DROP TABLE IF EXISTS burn_blocks;
   DROP TABLE IF EXISTS signer_states;
   DROP TABLE IF EXISTS blocks;
   DROP TABLE IF EXISTS db_config;";

static DROP_SCHEMA_1: &str = "
   DROP TABLE IF EXISTS burn_blocks;
   DROP TABLE IF EXISTS signer_states;
   DROP TABLE IF EXISTS blocks;
   DROP TABLE IF EXISTS db_config;";

static DROP_SCHEMA_2: &str = "
    DROP TABLE IF EXISTS burn_blocks;
    DROP TABLE IF EXISTS signer_states;
    DROP TABLE IF EXISTS blocks;
    DROP TABLE IF EXISTS db_config;";

static CREATE_BLOCK_SIGNATURES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_signatures (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- signature itself
    signature TEXT NOT NULL,
    PRIMARY KEY (signature)
) STRICT;"#;

static CREATE_BLOCK_REJECTION_SIGNER_ADDRS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_rejection_signer_addrs (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- the signer address that rejected the block
    signer_addr TEXT NOT NULL,
    PRIMARY KEY (signer_addr)
) STRICT;"#;

// Migration logic necessary to move blocks from the old blocks table to the new blocks table
static MIGRATE_BLOCKS_TABLE_2_BLOCKS_TABLE_3: &str = r#"
CREATE TABLE IF NOT EXISTS temp_blocks (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL PRIMARY KEY,
    reward_cycle INTEGER NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    signed_over INTEGER NOT NULL,
    broadcasted INTEGER,
    stacks_height INTEGER NOT NULL,
    burn_block_height INTEGER NOT NULL,
    valid INTEGER,
    state TEXT NOT NULL,
    signed_group INTEGER,
    signed_self INTEGER,
    proposed_time INTEGER NOT NULL,
    validation_time_ms INTEGER,
    tenure_change INTEGER NOT NULL
) STRICT;

INSERT INTO temp_blocks (
    signer_signature_hash,
    reward_cycle,
    block_info,
    consensus_hash,
    signed_over,
    broadcasted,
    stacks_height,
    burn_block_height,
    valid,
    state,
    signed_group,
    signed_self,
    proposed_time,
    validation_time_ms,
    tenure_change
)
SELECT
    signer_signature_hash,
    reward_cycle,
    block_info,
    consensus_hash,
    signed_over,
    broadcasted,
    stacks_height,
    burn_block_height,
    json_extract(block_info, '$.valid') AS valid,
    json_extract(block_info, '$.state') AS state,
    json_extract(block_info, '$.signed_group') AS signed_group,
    json_extract(block_info, '$.signed_self') AS signed_self,
    json_extract(block_info, '$.proposed_time') AS proposed_time,
    json_extract(block_info, '$.validation_time_ms') AS validation_time_ms,
    is_tenure_change(block_info) AS tenure_change
FROM blocks;

DROP TABLE blocks;

ALTER TABLE temp_blocks RENAME TO blocks;"#;

// Migration logic necessary to move burn blocks from the old burn blocks table to the new burn blocks table
// with the correct primary key
static MIGRATE_BURN_STATE_TABLE_1_TO_TABLE_2: &str = r#"
CREATE TABLE IF NOT EXISTS temp_burn_blocks (
    block_hash TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    received_time INTEGER NOT NULL,
    consensus_hash TEXT PRIMARY KEY NOT NULL
) STRICT;

INSERT INTO temp_burn_blocks (block_hash, block_height, received_time, consensus_hash)
SELECT block_hash, block_height, received_time, consensus_hash
FROM (
    SELECT
        block_hash,
        block_height,
        received_time,
        consensus_hash,
        ROW_NUMBER() OVER (
            PARTITION BY consensus_hash
            ORDER BY received_time DESC
        ) AS rn
    FROM burn_blocks
    WHERE consensus_hash IS NOT NULL
      AND consensus_hash <> ''
) AS ordered
WHERE rn = 1;

DROP TABLE burn_blocks;
ALTER TABLE temp_burn_blocks RENAME TO burn_blocks;

CREATE INDEX IF NOT EXISTS idx_burn_blocks_block_hash ON burn_blocks(block_hash);
"#;

static CREATE_BLOCK_VALIDATION_PENDING_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_validations_pending (
    signer_signature_hash TEXT NOT NULL,
    -- the time at which the block was added to the pending table
    added_time INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash)
) STRICT;"#;

static CREATE_TENURE_ACTIVTY_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS tenure_activity (
    consensus_hash TEXT NOT NULL PRIMARY KEY,
    last_activity_time INTEGER NOT NULL
) STRICT;"#;

static ADD_REJECT_CODE: &str = r#"
ALTER TABLE block_rejection_signer_addrs
    ADD COLUMN reject_code INTEGER;
"#;

static ADD_CONSENSUS_HASH: &str = r#"
ALTER TABLE burn_blocks
    ADD COLUMN consensus_hash TEXT;
"#;

static ADD_CONSENSUS_HASH_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS burn_blocks_ch on burn_blocks (consensus_hash);
"#;

static CREATE_SIGNER_STATE_MACHINE_UPDATES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS signer_state_machine_updates (
    signer_addr TEXT NOT NULL,
    reward_cycle INTEGER NOT NULL,
    state_update TEXT NOT NULL,
    received_time INTEGER NOT NULL,
    PRIMARY KEY (signer_addr, reward_cycle)
) STRICT;"#;

static CREATE_BURN_BLOCK_UPDATES_RECEIVED_TIME_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS burn_block_updates_received_times (
    signer_addr TEXT NOT NULL,
    burn_block_consensus_hash TEXT NOT NULL,
    received_time INTEGER NOT NULL,
    PRIMARY KEY (signer_addr, burn_block_consensus_hash)
) STRICT;
"#;

static ADD_PARENT_BURN_BLOCK_HASH: &str = r#"
 ALTER TABLE burn_blocks
    ADD COLUMN parent_burn_block_hash TEXT;
"#;

static ADD_PARENT_BURN_BLOCK_HASH_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS burn_blocks_parent_burn_block_hash_idx on burn_blocks (parent_burn_block_hash);
"#;

/// Dead schema: transaction replay was removed and nothing reads or writes this table.
/// To be dropped with a proper bump of `SCHEMA_VERSION`.
static ADD_BLOCK_VALIDATED_BY_REPLAY_TXS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_validated_by_replay_txs (
    signer_signature_hash TEXT NOT NULL,
    replay_tx_hash TEXT NOT NULL,
    replay_tx_exhausted INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash, replay_tx_hash)
) STRICT;"#;

static CREATE_STACKERDB_TRACKING: &str = "
CREATE TABLE stackerdb_tracking(
   public_key TEXT NOT NULL,
   slot_id INTEGER NOT NULL,
   slot_version INTEGER NOT NULL,
   PRIMARY KEY (public_key, slot_id)
) STRICT;";

// Used by get_burn_block_received_time_from_signers
static ADD_BURN_BLOCK_RECEIVED_TIMES_CONSENSUS_HASH_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS burn_block_updates_received_times_consensus_hash ON burn_block_updates_received_times(burn_block_consensus_hash, received_time ASC);
"#;

// Used by get_last_globally_accepted_block_approved_time
static ADD_BLOCK_SIGNED_SELF_INDEX: &str = r#"
CREATE INDEX idx_blocks_query_opt ON blocks (consensus_hash, state, signed_self, burn_block_height DESC);
"#;

static DROP_BLOCK_SIGNATURES_TABLE: &str = r#"
DROP TABLE IF EXISTS block_signatures;
"#;

static CREATE_BLOCK_SIGNATURES_TABLE_V16: &str = r#"
CREATE TABLE IF NOT EXISTS block_signatures (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- the signer address that signed the block
    signer_addr TEXT NOT NULL,
    -- signature itself
    signature TEXT NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;"#;

static DROP_BLOCK_REJECTION_SIGNER_ADDRS: &str = r#"
DROP TABLE IF EXISTS block_rejection_signer_addrs;
"#;

static CREATE_BLOCK_REJECTION_SIGNER_ADDRS_V16: &str = r#"
CREATE TABLE IF NOT EXISTS block_rejection_signer_addrs (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- the signer address that rejected the block
    signer_addr TEXT NOT NULL,
    -- the reject reason code
    reject_code INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;"#;

static CREATE_BLOCK_PRE_COMMITS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_pre_commits (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- signer address committing to sign the block
    signer_addr TEXT NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;"#;

static ADD_TENURE_CAUSE: &str = r#"
ALTER TABLE blocks
    ADD COLUMN tenure_change_cause INTEGER;
"#;

static CREATE_SUPERSEDED_TENURES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS superseded_tenures (
    -- consensus hash of a tenure that a later tenure was permitted to reorg. Its sortition is
    -- still canonical -- unlike an orphaned tenure -- but the reorg rules
    -- (`first_proposal_burn_block_timing`) sanctioned replacing the blocks it built, so a
    -- signature we put over one of them must not stand in the way of that replacement.
    consensus_hash TEXT PRIMARY KEY,
    -- burn block height of the superseded tenure's sortition, used to age the record out
    burn_block_height INTEGER NOT NULL,
    -- consensus hash of the tenure that was permitted to do the reorg. The permit only means
    -- anything while this tenure's sortition is still canonical: if a burnchain fork orphans
    -- it, the reorg we sanctioned can no longer happen and the record stops excluding the
    -- superseded tenure's blocks from conflict checks.
    superseded_by_consensus_hash TEXT NOT NULL,
    -- burn block hash of the permitting tenure's sortition, used to ask the node whether that
    -- sortition is still canonical
    superseded_by_burn_block_hash TEXT NOT NULL,
    -- epoch seconds at which we permitted the reorg
    superseded_at INTEGER NOT NULL
) STRICT;"#;

// New tables for tracking per-signer untracked block proposal responses with auto-eviction
static CREATE_SIGNER_PENDING_PRE_COMMIT_RESPONSES: &str = r#"
CREATE TABLE IF NOT EXISTS signer_pending_pre_commit_responses (
    signer_signature_hash TEXT NOT NULL,
    signer_addr TEXT NOT NULL,
    received_time INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_signer_pre_commit_responses_by_addr_time
ON signer_pending_pre_commit_responses (signer_addr, received_time DESC);

CREATE INDEX IF NOT EXISTS idx_signer_pre_commit_responses_by_hash_time
ON signer_pending_pre_commit_responses (signer_signature_hash, received_time DESC);
"#;

static CREATE_SIGNER_PENDING_SIGNATURE_RESPONSES: &str = r#"
CREATE TABLE IF NOT EXISTS signer_pending_signature_responses (
    signer_signature_hash TEXT NOT NULL,
    signer_addr TEXT NOT NULL,
    signature TEXT NOT NULL,
    received_time INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_signer_signature_responses_by_addr_time
ON signer_pending_signature_responses (signer_addr, received_time DESC);

CREATE INDEX IF NOT EXISTS idx_signer_signature_responses_by_hash_time
ON signer_pending_signature_responses (signer_signature_hash, received_time DESC);
"#;

static CREATE_SIGNER_PENDING_REJECTION_RESPONSES: &str = r#"
CREATE TABLE IF NOT EXISTS signer_pending_rejection_responses (
    signer_signature_hash TEXT NOT NULL,
    signer_addr TEXT NOT NULL,
    reject_code INTEGER NOT NULL,
    received_time INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_signer_rejection_responses_by_addr_time
ON signer_pending_rejection_responses (signer_addr, received_time DESC);

CREATE INDEX IF NOT EXISTS idx_signer_rejection_responses_by_hash_time
ON signer_pending_rejection_responses (signer_signature_hash, received_time DESC);
"#;

// Triggers to auto-evict responses when a signer exceeds 3 entries
static CREATE_PENDING_PRE_COMMIT_RESPONSES_EVICTION_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS evict_old_pending_pre_commit_responses
AFTER INSERT ON signer_pending_pre_commit_responses
FOR EACH ROW
BEGIN
    DELETE FROM signer_pending_pre_commit_responses
    WHERE signer_addr = NEW.signer_addr
    AND (signer_signature_hash, received_time) IN (
        SELECT signer_signature_hash, received_time
        FROM signer_pending_pre_commit_responses
        WHERE signer_addr = NEW.signer_addr
        ORDER BY received_time DESC
        LIMIT -1 OFFSET 3
    );
END;
"#;

static CREATE_PENDING_SIGNATURE_RESPONSES_EVICTION_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS evict_old_pending_signature_responses
AFTER INSERT ON signer_pending_signature_responses
FOR EACH ROW
BEGIN
    DELETE FROM signer_pending_signature_responses
    WHERE signer_addr = NEW.signer_addr
    AND (signer_signature_hash, received_time) IN (
        SELECT signer_signature_hash, received_time
        FROM signer_pending_signature_responses
        WHERE signer_addr = NEW.signer_addr
        ORDER BY received_time DESC
        LIMIT -1 OFFSET 3
    );
END;
"#;

static CREATE_PENDING_REJECTION_RESPONSES_EVICTION_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS evict_old_pending_rejection_responses
AFTER INSERT ON signer_pending_rejection_responses
FOR EACH ROW
BEGIN
    DELETE FROM signer_pending_rejection_responses
    WHERE signer_addr = NEW.signer_addr
    AND (signer_signature_hash, received_time) IN (
        SELECT signer_signature_hash, received_time
        FROM signer_pending_rejection_responses
        WHERE signer_addr = NEW.signer_addr
        ORDER BY received_time DESC
        LIMIT -1 OFFSET 3
    );
END;
"#;

/// Migration logic to add approved_time and remove signed_over from the blocks table.
///
/// Uses the recreate-table approach instead of `ALTER TABLE DROP COLUMN` because
/// `DROP COLUMN` can leave the database in a half-migrated state if it fails
/// inside a transaction (the prior `ADD COLUMN` may not roll back cleanly,
/// making the migration non-idempotent on retry).
static MIGRATE_BLOCKS_DROP_SIGNED_OVER_ADD_APPROVED_TIME: &str = r#"
CREATE TABLE IF NOT EXISTS new_blocks (
    signer_signature_hash TEXT NOT NULL PRIMARY KEY,
    reward_cycle INTEGER NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    broadcasted INTEGER,
    stacks_height INTEGER NOT NULL,
    burn_block_height INTEGER NOT NULL,
    valid INTEGER,
    state TEXT NOT NULL,
    signed_group INTEGER,
    signed_self INTEGER,
    proposed_time INTEGER NOT NULL,
    validation_time_ms INTEGER,
    tenure_change INTEGER NOT NULL,
    tenure_change_cause INTEGER,
    approved_time INTEGER
) STRICT;

INSERT OR IGNORE INTO new_blocks (
    signer_signature_hash,
    reward_cycle,
    block_info,
    consensus_hash,
    broadcasted,
    stacks_height,
    burn_block_height,
    valid,
    state,
    signed_group,
    signed_self,
    proposed_time,
    validation_time_ms,
    tenure_change,
    tenure_change_cause,
    approved_time
)
SELECT
    signer_signature_hash,
    reward_cycle,
    block_info,
    consensus_hash,
    broadcasted,
    stacks_height,
    burn_block_height,
    valid,
    state,
    signed_group,
    signed_self,
    proposed_time,
    validation_time_ms,
    tenure_change,
    tenure_change_cause,
    signed_self
FROM blocks;

DROP TABLE blocks;
ALTER TABLE new_blocks RENAME TO blocks;
"#;

/// Recreate indexes on the blocks table after the table was rebuilt.
/// DROP TABLE removes all indexes, so we must recreate the surviving ones
/// from earlier migrations (INDEXES_5, INDEXES_8) plus the new ones for
/// migration 19. Indexes that referenced `signed_over` are intentionally
/// omitted since that column no longer exists.
static CREATE_INDEXES_19: &str = r#"
-- Surviving indexes from INDEXES_5
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_state ON blocks (consensus_hash, state);
CREATE INDEX IF NOT EXISTS blocks_state ON blocks (state);
CREATE INDEX IF NOT EXISTS blocks_signed_group ON blocks (signed_group);

-- Surviving indexes from INDEXES_8
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_state_height ON blocks (consensus_hash, state, stacks_height DESC);
CREATE INDEX IF NOT EXISTS blocks_state_height_signed_group ON blocks (state, stacks_height DESC, signed_group DESC);
CREATE INDEX IF NOT EXISTS blocks_reward_cycle_state ON blocks (reward_cycle, state);

-- New index replacing idx_blocks_query_opt (now uses approved_time instead of signed_self)
CREATE INDEX IF NOT EXISTS idx_blocks_get_last_globally_accepted_block_approved_time
ON blocks (
    consensus_hash,
    state,
    approved_time,
    burn_block_height DESC
);

-- New partial indexes for fast tenure-level queries
CREATE INDEX IF NOT EXISTS idx_blocks_tenure_self_signed
ON blocks (consensus_hash, stacks_height)
WHERE signed_self IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_blocks_tenure_group_signed
ON blocks (consensus_hash, stacks_height)
WHERE signed_group IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_blocks_tenure_approved
ON blocks (consensus_hash, stacks_height)
WHERE approved_time IS NOT NULL;
"#;

static SCHEMA_1: &[&str] = &[
    DROP_SCHEMA_0,
    CREATE_DB_CONFIG,
    CREATE_BURN_STATE_TABLE,
    CREATE_BLOCKS_TABLE_1,
    CREATE_SIGNER_STATE_TABLE,
    CREATE_INDEXES_1,
    "INSERT INTO db_config (version) VALUES (1);",
];

static SCHEMA_2: &[&str] = &[
    DROP_SCHEMA_1,
    CREATE_DB_CONFIG,
    CREATE_BURN_STATE_TABLE,
    CREATE_BLOCKS_TABLE_2,
    CREATE_SIGNER_STATE_TABLE,
    CREATE_BLOCK_SIGNATURES_TABLE,
    CREATE_INDEXES_1,
    CREATE_INDEXES_2,
    "INSERT INTO db_config (version) VALUES (2);",
];

static SCHEMA_3: &[&str] = &[
    DROP_SCHEMA_2,
    CREATE_DB_CONFIG,
    CREATE_BURN_STATE_TABLE,
    CREATE_BLOCKS_TABLE_2,
    CREATE_SIGNER_STATE_TABLE,
    CREATE_BLOCK_SIGNATURES_TABLE,
    CREATE_BLOCK_REJECTION_SIGNER_ADDRS_TABLE,
    CREATE_INDEXES_1,
    CREATE_INDEXES_2,
    CREATE_INDEXES_3,
    "INSERT INTO db_config (version) VALUES (3);",
];

static SCHEMA_4: &[&str] = &[
    CREATE_INDEXES_4,
    "INSERT OR REPLACE INTO db_config (version) VALUES (4);",
];

static SCHEMA_5: &[&str] = &[
    MIGRATE_BLOCKS_TABLE_2_BLOCKS_TABLE_3,
    CREATE_INDEXES_5,
    "DELETE FROM db_config;", // Be extra careful. Make sure there is only ever one row in the table.
    "INSERT INTO db_config (version) VALUES (5);",
];

static SCHEMA_6: &[&str] = &[
    CREATE_BLOCK_VALIDATION_PENDING_TABLE,
    CREATE_INDEXES_6,
    "INSERT OR REPLACE INTO db_config (version) VALUES (6);",
];

static SCHEMA_7: &[&str] = &[
    CREATE_TENURE_ACTIVTY_TABLE,
    "INSERT OR REPLACE INTO db_config (version) VALUES (7);",
];

static SCHEMA_8: &[&str] = &[
    CREATE_INDEXES_8,
    "INSERT INTO db_config (version) VALUES (8);",
];

static SCHEMA_9: &[&str] = &[
    ADD_REJECT_CODE,
    "INSERT INTO db_config (version) VALUES (9);",
];

static SCHEMA_10: &[&str] = &[
    ADD_CONSENSUS_HASH,
    ADD_CONSENSUS_HASH_INDEX,
    "INSERT INTO db_config (version) VALUES (10);",
];

static SCHEMA_11: &[&str] = &[
    CREATE_SIGNER_STATE_MACHINE_UPDATES_TABLE,
    CREATE_INDEXES_11,
    "INSERT INTO db_config (version) VALUES (11);",
];

static SCHEMA_12: &[&str] = &[
    MIGRATE_BURN_STATE_TABLE_1_TO_TABLE_2,
    "INSERT OR REPLACE INTO db_config (version) VALUES (12);",
];

static SCHEMA_13: &[&str] = &[
    ADD_PARENT_BURN_BLOCK_HASH,
    ADD_PARENT_BURN_BLOCK_HASH_INDEX,
    "INSERT INTO db_config (version) VALUES (13);",
];

static SCHEMA_14: &[&str] = &[
    CREATE_STACKERDB_TRACKING,
    "INSERT INTO db_config (version) VALUES (14);",
];

static SCHEMA_15: &[&str] = &[
    ADD_BLOCK_VALIDATED_BY_REPLAY_TXS_TABLE,
    "INSERT INTO db_config (version) VALUES (15);",
];

static SCHEMA_16: &[&str] = &[
    CREATE_BURN_BLOCK_UPDATES_RECEIVED_TIME_TABLE,
    ADD_BURN_BLOCK_RECEIVED_TIMES_CONSENSUS_HASH_INDEX,
    ADD_BLOCK_SIGNED_SELF_INDEX,
    DROP_BLOCK_SIGNATURES_TABLE,
    CREATE_BLOCK_SIGNATURES_TABLE_V16,
    DROP_BLOCK_REJECTION_SIGNER_ADDRS,
    CREATE_BLOCK_REJECTION_SIGNER_ADDRS_V16,
    "INSERT INTO db_config (version) VALUES (16);",
];

static SCHEMA_17: &[&str] = &[
    CREATE_BLOCK_PRE_COMMITS_TABLE,
    "INSERT INTO db_config (version) VALUES (17);",
];

static SCHEMA_18: &[&str] = &[
    ADD_TENURE_CAUSE,
    "INSERT INTO db_config (version) VALUES (18);",
];

static SCHEMA_19: &[&str] = &[
    MIGRATE_BLOCKS_DROP_SIGNED_OVER_ADD_APPROVED_TIME,
    CREATE_INDEXES_19,
    CREATE_SIGNER_PENDING_PRE_COMMIT_RESPONSES,
    CREATE_SIGNER_PENDING_SIGNATURE_RESPONSES,
    CREATE_SIGNER_PENDING_REJECTION_RESPONSES,
    CREATE_PENDING_PRE_COMMIT_RESPONSES_EVICTION_TRIGGER,
    CREATE_PENDING_SIGNATURE_RESPONSES_EVICTION_TRIGGER,
    CREATE_PENDING_REJECTION_RESPONSES_EVICTION_TRIGGER,
    "INSERT INTO db_config (version) VALUES (19);",
];

static SCHEMA_20: &[&str] = &[
    CREATE_SUPERSEDED_TENURES_TABLE,
    // `get_signed_conflicts` filters on a height range near the chain tip across all tenures;
    // a plain height index makes that a bounded range scan and serves its ORDER BY.
    "CREATE INDEX IF NOT EXISTS blocks_stacks_height ON blocks (stacks_height DESC);",
    "INSERT INTO db_config (version) VALUES (20);",
];

static SCHEMA_21: &[&str] = &[
    // `prune` operation looks up sortitions by burn height to place the fork horizon.
    "CREATE INDEX IF NOT EXISTS burn_blocks_height ON burn_blocks (block_height);",
    "INSERT INTO db_config (version) VALUES (21);",
];

struct Migration {
    version: SchemaVersion,
    statements: &'static [&'static str],
}

/// Enum representing each schema version. Adding a new schema version requires
/// adding a variant here, a corresponding entry in `MIGRATIONS`, and a test
/// case in `test_all_schema_migrations_have_tests` (which uses an exhaustive
/// match to guarantee compile-time coverage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
enum SchemaVersion {
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V7 = 7,
    V8 = 8,
    V9 = 9,
    V10 = 10,
    V11 = 11,
    V12 = 12,
    V13 = 13,
    V14 = 14,
    V15 = 15,
    V16 = 16,
    V17 = 17,
    V18 = 18,
    V19 = 19,
    V20 = 20,
    V21 = 21,
}

impl SchemaVersion {
    const fn as_u32(self) -> u32 {
        self as u32
    }
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: SchemaVersion::V1,
        statements: SCHEMA_1,
    },
    Migration {
        version: SchemaVersion::V2,
        statements: SCHEMA_2,
    },
    Migration {
        version: SchemaVersion::V3,
        statements: SCHEMA_3,
    },
    Migration {
        version: SchemaVersion::V4,
        statements: SCHEMA_4,
    },
    Migration {
        version: SchemaVersion::V5,
        statements: SCHEMA_5,
    },
    Migration {
        version: SchemaVersion::V6,
        statements: SCHEMA_6,
    },
    Migration {
        version: SchemaVersion::V7,
        statements: SCHEMA_7,
    },
    Migration {
        version: SchemaVersion::V8,
        statements: SCHEMA_8,
    },
    Migration {
        version: SchemaVersion::V9,
        statements: SCHEMA_9,
    },
    Migration {
        version: SchemaVersion::V10,
        statements: SCHEMA_10,
    },
    Migration {
        version: SchemaVersion::V11,
        statements: SCHEMA_11,
    },
    Migration {
        version: SchemaVersion::V12,
        statements: SCHEMA_12,
    },
    Migration {
        version: SchemaVersion::V13,
        statements: SCHEMA_13,
    },
    Migration {
        version: SchemaVersion::V14,
        statements: SCHEMA_14,
    },
    Migration {
        version: SchemaVersion::V15,
        statements: SCHEMA_15,
    },
    Migration {
        version: SchemaVersion::V16,
        statements: SCHEMA_16,
    },
    Migration {
        version: SchemaVersion::V17,
        statements: SCHEMA_17,
    },
    Migration {
        version: SchemaVersion::V18,
        statements: SCHEMA_18,
    },
    Migration {
        version: SchemaVersion::V19,
        statements: SCHEMA_19,
    },
    Migration {
        version: SchemaVersion::V20,
        statements: SCHEMA_20,
    },
    Migration {
        version: SchemaVersion::V21,
        statements: SCHEMA_21,
    },
];

impl SignerDb {
    /// The current schema version used in this build of the signer binary.
    pub const SCHEMA_VERSION: u32 = SchemaVersion::V21.as_u32();

    /// Create a new `SignerState` instance.
    /// This will create a new SQLite database at the given path
    /// or an in-memory database if the path is ":memory:"
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, DBError> {
        let connection = Self::connect(db_path)?;

        let mut signer_db = Self { db: connection };
        signer_db.create_or_migrate()?;

        Ok(signer_db)
    }

    /// Returns the schema version of the database
    fn get_schema_version(conn: &Connection) -> Result<u32, DBError> {
        if !table_exists(conn, "db_config")? {
            return Ok(0);
        }
        let result = conn
            .query_row("SELECT MAX(version) FROM db_config LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional();
        match result {
            Ok(x) => Ok(x.unwrap_or(0)),
            Err(e) => Err(DBError::from(e)),
        }
    }

    /// Register custom scalar functions used by the database
    fn register_scalar_functions(&self) -> Result<(), DBError> {
        // Register helper function for determining if a block is a tenure change transaction
        // Required only for data migration from Schema 4 to Schema 5
        self.db.create_scalar_function(
            "is_tenure_change",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let value = ctx.get::<String>(0)?;
                let block_info = serde_json::from_str::<BlockInfo>(&value)
                    .map_err(|e| SqliteError::UserFunctionError(e.into()))?;
                Ok(block_info.is_tenure_change())
            },
        )?;
        // Register helper function for extracting the burn_block from the state machine update content
        // Required only for data migration from Schema 14 to Schema 15
        self.db.create_scalar_function(
            "extract_burn_block_consensus_hash",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let json_str = ctx.get::<String>(0)?;
                Self::extract_burn_block_consensus_hash_from_json(&json_str)
            },
        )?;
        Ok(())
    }

    /// Drop registered scalar functions used only for data migrations
    fn remove_scalar_functions(&self) -> Result<(), DBError> {
        self.db.remove_function("is_tenure_change", 1)?;
        self.db
            .remove_function("extract_burn_block_consensus_hash", 1)?;
        Ok(())
    }

    /// Either instantiate a new database, or migrate an existing one
    fn create_or_migrate(&mut self) -> Result<(), DBError> {
        self.register_scalar_functions()?;
        let sql_tx = tx_begin_immediate(&mut self.db)?;

        let mut current_db_version = Self::get_schema_version(&sql_tx)?;
        debug!("Current SignerDB schema version: {}", current_db_version);

        for migration in MIGRATIONS.iter() {
            let version = migration.version.as_u32();
            if current_db_version >= version {
                // don't need this migration, continue to see if we need later migrations
                continue;
            }
            if current_db_version != version - 1 {
                // This implies a gap or out-of-order migration definition,
                // or the database is at a version X, and the next migration is X+2 instead of X+1.
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Migration step missing or out of order. Current DB version: {}, trying to apply migration for version: {}",
                    current_db_version, version
                )));
            }
            debug!("Applying SignerDB migration for schema version {}", version);
            for statement in migration.statements.iter() {
                sql_tx.execute_batch(statement)?;
            }

            // Verify that the migration script updated the version correctly
            let new_version_check = Self::get_schema_version(&sql_tx)?;
            if new_version_check != version {
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Migration to version {version} failed to update DB version. Expected {version}, got {new_version_check}."
                )));
            }
            current_db_version = new_version_check;
            debug!("Successfully migrated to schema version {current_db_version}");
        }

        match current_db_version.cmp(&Self::SCHEMA_VERSION) {
            std::cmp::Ordering::Less => {
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Database migration incomplete. Current version: {current_db_version}, SCHEMA_VERSION: {}",
                    Self::SCHEMA_VERSION
                )));
            }
            std::cmp::Ordering::Greater => {
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Database schema is newer than SCHEMA_VERSION. SCHEMA_VERSION = {}, Current version = {}. Did you forget to update SCHEMA_VERSION?",
                    Self::SCHEMA_VERSION, current_db_version
                )));
            }
            std::cmp::Ordering::Equal => {}
        }

        sql_tx.commit()?;
        self.remove_scalar_functions()?;
        Ok(())
    }

    fn connect(db_path: impl AsRef<Path>) -> Result<Connection, SqliteError> {
        sqlite_open(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            false,
        )
    }

    /// Extracts the `burn_block` string from a JSON state machine update payload
    fn extract_burn_block_consensus_hash_from_json(json_str: &str) -> rusqlite::Result<String> {
        let v: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| SqliteError::UserFunctionError(e.into()))?;

        let content = &v["content"];
        let content_obj = if let Some(v0) = content.get("V0") {
            v0
        } else if let Some(v1) = content.get("V1") {
            v1
        } else {
            return Err(SqliteError::UserFunctionError(
                "Invalid \"content\" struct: Expected one of \"V0\" or \"V1\"".into(),
            ));
        };

        let burn_block_hex = content_obj
            .get("burn_block")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SqliteError::UserFunctionError("Missing burn_block".into()))?;

        Ok(burn_block_hex.to_string())
    }

    /// Get the latest known version from the db for the given slot_id/pk pair
    pub fn get_latest_chunk_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
    ) -> Result<Option<u32>, DBError> {
        self.db
            .query_row(
                "SELECT slot_version FROM stackerdb_tracking WHERE public_key = ? AND slot_id = ?",
                params![pk.to_hex(), slot_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(DBError::from)
    }

    /// Set the latest known version for the given slot_id/pk pair
    pub fn set_latest_chunk_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
        slot_version: u32,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO stackerdb_tracking (public_key, slot_id, slot_version) VALUES (?, ?, ?)",
            params![pk.to_hex(), slot_id, slot_version],
        )?;
        Ok(())
    }

    /// Get the signer state for the provided reward cycle if it exists in the database
    pub fn get_encrypted_signer_state(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<Vec<u8>>, DBError> {
        query_row(
            &self.db,
            "SELECT encrypted_state FROM signer_states WHERE reward_cycle = ?",
            [u64_to_sql(reward_cycle)?],
        )
    }

    /// Insert the given state in the `signer_states` table for the given reward cycle
    pub fn insert_encrypted_signer_state(
        &self,
        reward_cycle: u64,
        encrypted_signer_state: &[u8],
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO signer_states (reward_cycle, encrypted_state) VALUES (?1, ?2)",
            params![u64_to_sql(reward_cycle)?, encrypted_signer_state],
        )?;
        Ok(())
    }

    /// Fetch a block from the database using the block's
    /// `signer_signature_hash`
    pub fn block_lookup(&self, hash: &Sha512Trunc256Sum) -> Result<Option<BlockInfo>, DBError> {
        let result: Option<String> = query_row(
            &self.db,
            "SELECT block_info FROM blocks WHERE signer_signature_hash = ?",
            params![hash.to_string()],
        )?;

        try_deserialize(result)
    }

    /// Return whether there was an approved/signed block in a tenure (identified by its consensus hash)
    ///
    /// Note: this includes blocks that were only pre-committed (because `mark_pre_committed`
    /// records an `approved_time`). It is therefore NOT a test of whether this signer put a
    /// signature over a block in the tenure -- use [`SignerDb::has_signed_block_in_tenure`] for
    /// that (which is why production code no longer uses this; it is kept for tests pinning
    /// down the approved-vs-signed distinction).
    #[cfg(any(test, feature = "testing"))]
    pub fn has_approved_block_in_tenure(&self, tenure: &ConsensusHash) -> Result<bool, DBError> {
        let query = "SELECT 1 FROM blocks WHERE consensus_hash = ? AND (signed_self IS NOT NULL OR signed_group IS NOT NULL OR approved_time IS NOT NULL) LIMIT 1;";
        let result: Option<u64> = query_row(&self.db, query, [tenure])?;

        Ok(result.is_some())
    }

    /// Return whether this signer has signed a block, or observed the signer set sign a block,
    /// in a tenure (identified by its consensus hash). Used by `is_timed_out` to keep a tenure
    /// we are committed to from being timed out.
    ///
    /// Unlike [`SignerDb::has_approved_block_in_tenure`] this excludes blocks that were only
    /// pre-committed. A pre-commit does not put a signature over the block, so it does not
    /// represent a commitment that would be violated by abandoning the tenure.
    ///
    /// Rejection, even global rejection, does NOT clear the commitment. A rejection is a
    /// revocable opinion; a signature is a bearer instrument. Once ours is public, anyone can
    /// aggregate it toward the 70% threshold should enough rejecting signers change their
    /// minds, so a block we signed binds us to its tenure no matter what state it later fell
    /// to. This is deliberately a different predicate from
    /// [`SignerDb::get_last_signed_block`], which answers a tip question rather than a
    /// commitment question (see there).
    pub fn has_signed_block_in_tenure(&self, tenure: &ConsensusHash) -> Result<bool, DBError> {
        let query = "SELECT 1 FROM blocks WHERE consensus_hash = ? AND (signed_self IS NOT NULL OR signed_group IS NOT NULL) LIMIT 1;";
        let result: Option<u64> = query_row(&self.db, query, [tenure])?;

        Ok(result.is_some())
    }

    /// Return the first approved/signed block in a tenure (identified by its consensus hash)
    pub fn get_first_approved_block_in_tenure(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ? AND (signed_self IS NOT NULL OR signed_group IS NOT NULL OR approved_time IS NOT NULL) ORDER BY stacks_height ASC LIMIT 1";
        let result: Option<String> = query_row(&self.db, query, [tenure])?;

        try_deserialize(result)
    }

    /// Return the count of globally accepted blocks in a tenure (identified by its consensus hash)
    pub fn get_globally_accepted_block_count_in_tenure(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<u64, DBError> {
        let query = "SELECT COALESCE((MAX(stacks_height) - MIN(stacks_height) + 1), 0) AS block_count FROM blocks WHERE consensus_hash = ?1 AND state = ?2";
        let args = params![tenure, &BlockState::GloballyAccepted.to_string()];
        let block_count_opt: Option<u64> = query_row(&self.db, query, args)?;
        match block_count_opt {
            Some(block_count) => Ok(block_count),
            None => Ok(0),
        }
    }

    /// Return the last accepted block in a tenure (identified by its consensus hash).
    ///
    /// Note: this includes blocks that were only pre-committed. A pre-commit does not put a
    /// signature over the block, so this must NOT be used to determine the tenure's tip for
    /// validation purposes -- use [`SignerDb::get_last_signed_block`] for that.
    pub fn get_last_accepted_block(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND state IN (?2, ?3, ?4) ORDER BY stacks_height DESC LIMIT 1";
        let args = params![
            tenure,
            &BlockState::GloballyAccepted.to_string(),
            &BlockState::LocallyAccepted.to_string(),
            &BlockState::PreCommitted.to_string(),
        ];
        let result: Option<String> = query_row(&self.db, query, args)?;

        try_deserialize(result)
    }

    /// Return the last signed block in a tenure (identified by its consensus hash).
    /// A block is considered signed if it is locally or globally accepted. Blocks that
    /// have only been pre-committed are excluded, because a pre-commit does not put a
    /// signature over the block and may be safely superseded by a competing proposal.
    ///
    /// `excluded_signer_signature_hash` leaves one block out of the query, so that another
    /// accepted sibling at the same height can be the block returned. The exclusion is part of
    /// the query rather than a filter on its result: a filter after `LIMIT 1` could drop the
    /// only row returned and hide the sibling.
    ///
    /// This answers "what is the tenure's signed tip?", a different question from
    /// [`SignerDb::has_signed_block_in_tenure`]'s "does a signature bind us to this tenure?",
    /// which is why the predicates deliberately differ on rejected blocks (see there).
    pub fn get_last_signed_block(
        &self,
        tenure: &ConsensusHash,
        excluded_signer_signature_hash: Option<&Sha512Trunc256Sum>,
    ) -> Result<Option<BlockInfo>, DBError> {
        let accepted = [
            BlockState::GloballyAccepted.to_string(),
            BlockState::LocallyAccepted.to_string(),
        ];
        let result: Option<String> = match excluded_signer_signature_hash {
            None => query_row(
                &self.db,
                "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND state IN (?2, ?3) ORDER BY stacks_height DESC LIMIT 1",
                params![tenure, &accepted[0], &accepted[1]],
            )?,
            Some(excluded) => query_row(
                &self.db,
                "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND state IN (?2, ?3) AND signer_signature_hash != ?4 ORDER BY stacks_height DESC LIMIT 1",
                params![tenure, &accepted[0], &accepted[1], excluded.to_string()],
            )?,
        };

        try_deserialize(result)
    }

    /// Return every signed block at or above the given Stacks height, in ANY tenure, excluding
    /// the block with the given signer signature hash, ordered by height (highest first). A
    /// block is considered signed if a signature was ever put over it, ours (`signed_self`)
    /// or the observed group's (`signed_group`). Blocks that were only pre-committed carry no
    /// signature and are never returned. Each row carries the most recent endorsement time
    /// (`signed_self`/`signed_group`, whichever is later) so the caller can judge freshness per
    /// conflict.
    ///
    /// The search deliberately spans all tenures: two blocks at the same height are siblings
    /// no matter which tenure they belong to (e.g. a tenure-start block conflicts with the
    /// previous tenure's block at the same height), so a signature over either may conflict
    /// with a fresh signature over the other.
    ///
    /// Blocks in tenures whose reorg we sanctioned under the reorg-timing rules (see
    /// [`SignerDb::mark_tenure_superseded`]) are still returned, but annotated with the
    /// permitting tenure (`superseded_by_*`). Whether that permit excuses the conflict is the
    /// caller's to decide per evaluation (see `Signer::reorg_permit_stands`): it only covers a
    /// block in the permitting tenure, and only while that tenure's sortition is canonical --
    /// like every other question about whether a conflict is still *live*
    /// (`Signer::conflict_still_blocks`), it is not recorded.
    pub fn get_signed_conflicts(
        &self,
        height: u64,
        excluded_signer_signature_hash: &Sha512Trunc256Sum,
    ) -> Result<Vec<SignedConflictInfo>, DBError> {
        let query = "SELECT b.consensus_hash, b.signer_signature_hash, b.stacks_height, b.state,
                MAX(COALESCE(b.signed_self, 0), COALESCE(b.signed_group, 0)) AS last_endorsed,
                st.superseded_by_consensus_hash, st.superseded_by_burn_block_hash
            FROM blocks b
            LEFT JOIN superseded_tenures st ON st.consensus_hash = b.consensus_hash
            WHERE (b.signed_self IS NOT NULL OR b.signed_group IS NOT NULL)
                AND b.stacks_height >= ?1
                AND b.signer_signature_hash != ?2
            ORDER BY b.stacks_height DESC";
        let args = params![
            u64_to_sql(height)?,
            excluded_signer_signature_hash.to_string(),
        ];
        query_rows(&self.db, query, args)
    }

    /// Record that we permitted the tenure identified by `superseded_by_*` to reorg this one
    /// under the reorg-timing rules (`first_proposal_burn_block_timing`).
    ///
    /// Having sanctioned the replacement, our own signature over what this tenure built must not
    /// then block it: its blocks stop counting as conflicts against a block in
    /// `superseded_by_consensus_hash` (see [`SignerDb::get_signed_conflicts`]). Recorded when
    /// the reorg is permitted rather than derived at signing time, because by the time a
    /// replacement reaches the pre-commit threshold the sortition view that sanctioned the
    /// reorg may be long gone.
    ///
    /// Two things bound the permit when it is applied, both re-derived rather than recorded.
    /// It covers only the branch it sanctioned -- blocks in the permitting tenure, and blocks
    /// of a tenure built on top of it -- since only those continue the replacement: a block in
    /// this tenure alongside one we already signed is equivocation, not a reorg. And it is only
    /// honored while the permitting tenure's sortition is still canonical: if a burnchain fork
    /// orphans it, the reorg we sanctioned can no longer happen, so the record must not keep
    /// suppressing this tenure's conflicts. A re-permit by a different tenure replaces the
    /// record, so the latest permitting sortition is the one checked. Records age out via
    /// [`SignerDb::prune_superseded_tenures`].
    pub fn mark_tenure_superseded(
        &mut self,
        consensus_hash: &ConsensusHash,
        burn_block_height: u64,
        superseded_by_consensus_hash: &ConsensusHash,
        superseded_by_burn_block_hash: &BurnchainHeaderHash,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO superseded_tenures (consensus_hash, burn_block_height, superseded_by_consensus_hash, superseded_by_burn_block_hash, superseded_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                consensus_hash,
                u64_to_sql(burn_block_height)?,
                superseded_by_consensus_hash,
                superseded_by_burn_block_hash,
                u64_to_sql(get_epoch_time_secs())?
            ],
        )?;
        Ok(())
    }

    /// Whether we permitted a later tenure to reorg this one
    #[cfg(any(test, feature = "testing"))]
    pub fn is_tenure_superseded(&self, consensus_hash: &ConsensusHash) -> Result<bool, DBError> {
        let query = "SELECT 1 FROM superseded_tenures WHERE consensus_hash = ?1";
        Ok(query_row::<i64, _>(&self.db, query, params![consensus_hash])?.is_some())
    }

    /// Whether we recorded the permit described by `permit`: that
    /// [`ReorgPermit::reorging_tenure`] may reorg [`ReorgPermit::reorged_tenure`] (see
    /// [`SignerDb::mark_tenure_superseded`]). Only the most recent permitting tenure is
    /// recorded per reorged tenure, so a permit replaced by a later one reads as absent.
    pub fn has_reorg_permit(&self, permit: ReorgPermit<'_>) -> Result<bool, DBError> {
        let query = "SELECT 1 FROM superseded_tenures WHERE consensus_hash = ?1 AND superseded_by_consensus_hash = ?2";
        let args = params![permit.reorged_tenure, permit.reorging_tenure];
        Ok(query_row::<i64, _>(&self.db, query, args)?.is_some())
    }

    /// Drop superseded-tenure records for sortitions below `burn_block_height`. A tenure that
    /// old cannot conflict with a proposal anywhere near the chain tip, so the record has no
    /// further use.
    pub fn prune_superseded_tenures(&mut self, burn_block_height: u64) -> Result<(), DBError> {
        self.db.execute(
            "DELETE FROM superseded_tenures WHERE burn_block_height < ?1",
            params![u64_to_sql(burn_block_height)?],
        )?;
        Ok(())
    }

    /// Run one pruning pass (a `PruneTx`) with the given [`PruneParams`], removing what no fork can
    /// reach any more. A large backlog drains over repeated calls.
    ///
    /// Returns what the pass removed; [`PruneStats::is_skipped`] tells whether the fork horizon
    /// could not be placed.
    pub fn prune(&mut self, params: &PruneParams) -> Result<PruneStats, DBError> {
        let Some(mut prune_tx) = PruneTx::begin(&mut self.db, *params)? else {
            return Ok(PruneStats::skipped());
        };
        prune_tx.execute()?;
        prune_tx.commit()
    }

    /// Return the last globally accepted block in a tenure (identified by its consensus hash).
    pub fn get_last_globally_accepted_block(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND state = ?2 ORDER BY stacks_height DESC LIMIT 1";
        let args = params![tenure, &BlockState::GloballyAccepted.to_string()];
        let result: Option<String> = query_row(&self.db, query, args)?;

        try_deserialize(result)
    }

    /// Return the last globally accepted block approved_time in a given tenure (identified by its consensus hash).
    pub fn get_last_globally_accepted_approved_time(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<SystemTime>, DBError> {
        let query = r#"
            SELECT approved_time
            FROM blocks
            WHERE consensus_hash = ?1
            AND state = ?2
            AND approved_time IS NOT NULL
            ORDER BY burn_block_height DESC
            LIMIT 1;
        "#;
        let args = params![tenure, &BlockState::GloballyAccepted.to_string()];
        let result: Option<u64> = query_row(&self.db, query, args)?;
        Ok(result.map(|approved_time| UNIX_EPOCH + Duration::from_secs(approved_time)))
    }

    /// Return the canonical tip -- the last globally accepted block.
    pub fn get_canonical_tip(&self) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE state = ?1 ORDER BY stacks_height DESC, signed_group DESC LIMIT 1";
        let args = params![&BlockState::GloballyAccepted.to_string()];
        let result: Option<String> = query_row(&self.db, query, args)?;

        try_deserialize(result)
    }

    /// Insert or replace a burn block into the database
    pub fn insert_burn_block(
        &mut self,
        burn_hash: &BurnchainHeaderHash,
        consensus_hash: &ConsensusHash,
        burn_height: u64,
        received_time: &SystemTime,
        parent_burn_block_hash: &BurnchainHeaderHash,
    ) -> Result<(), DBError> {
        let received_ts = received_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DBError::Other(format!("Bad system time: {e}")))?
            .as_secs();
        debug!("Inserting burn block info";
            "burn_block_height" => burn_height,
            "burn_hash" => %burn_hash,
            "received" => received_ts,
            "ch" => %consensus_hash,
            "parent_burn_block_hash" => %parent_burn_block_hash
        );
        self.db.execute(
            "INSERT OR REPLACE INTO burn_blocks (block_hash, consensus_hash, block_height, received_time, parent_burn_block_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                burn_hash,
                consensus_hash,
                u64_to_sql(burn_height)?,
                u64_to_sql(received_ts)?,
                parent_burn_block_hash,
            ],
        )?;
        Ok(())
    }

    /// Get timestamp (epoch seconds) at which a burn block was received over the event dispatcher by this signer
    /// if that burn block has been received.
    pub fn get_burn_block_receive_time(
        &self,
        burn_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError> {
        let query = "SELECT received_time FROM burn_blocks WHERE block_hash = ? LIMIT 1";
        let Some(receive_time_i64) = query_row::<i64, _>(&self.db, query, &[burn_hash])? else {
            return Ok(None);
        };
        let receive_time = u64::try_from(receive_time_i64).map_err(|e| {
            error!("Failed to parse db received_time as u64: {e}");
            DBError::Corruption
        })?;
        Ok(Some(receive_time))
    }

    /// Get timestamp (epoch seconds) at which a burn block was received over the event dispatcher by this signer
    /// if that burn block has been received.
    pub fn get_burn_block_receive_time_ch(
        &self,
        ch: &ConsensusHash,
    ) -> Result<Option<u64>, DBError> {
        let query = "SELECT received_time FROM burn_blocks WHERE consensus_hash = ? LIMIT 1";
        let Some(receive_time_i64) = query_row::<i64, _>(&self.db, query, &[ch])? else {
            return Ok(None);
        };
        let receive_time = u64::try_from(receive_time_i64).map_err(|e| {
            error!("Failed to parse db received_time as u64: {e}");
            DBError::Corruption
        })?;
        Ok(Some(receive_time))
    }

    /// Lookup the burn block for a given burn block hash.
    pub fn get_burn_block_by_hash(
        &self,
        burn_block_hash: &BurnchainHeaderHash,
    ) -> Result<BurnBlockInfo, DBError> {
        let query =
            "SELECT block_hash, block_height, consensus_hash, parent_burn_block_hash FROM burn_blocks WHERE block_hash = ?";
        let args = params![burn_block_hash];

        query_row(&self.db, query, args)?.ok_or(DBError::NotFoundError)
    }

    /// Lookup the burn block for a given consensus hash.
    pub fn get_burn_block_by_ch(&self, ch: &ConsensusHash) -> Result<BurnBlockInfo, DBError> {
        let query = "SELECT block_hash, block_height, consensus_hash, parent_burn_block_hash FROM burn_blocks WHERE consensus_hash = ?";
        let args = params![ch];

        query_row(&self.db, query, args)?.ok_or(DBError::NotFoundError)
    }

    /// Insert or replace a block into the database.
    /// Preserves the `broadcast` column if replacing an existing block.
    pub fn insert_block(&mut self, block_info: &BlockInfo) -> Result<(), DBError> {
        let block_json =
            serde_json::to_string(&block_info).expect("Unable to serialize block info");
        let hash = &block_info.signer_signature_hash();
        let block_id = &block_info.block.block_id();
        let vote = block_info
            .vote
            .as_ref()
            .map(|v| if v.rejected { "REJECT" } else { "ACCEPT" });
        let broadcasted = self.get_block_broadcasted(hash)?;
        debug!("Inserting block_info.";
            "reward_cycle" => %block_info.reward_cycle,
            "burn_block_height" => %block_info.burn_block_height,
            "signer_signature_hash" => %hash,
            "block_id" => %block_id,
            "broadcasted" => ?broadcasted,
            "vote" => vote
        );
        self.db.execute(
            "INSERT OR REPLACE INTO blocks
              (reward_cycle, burn_block_height, signer_signature_hash, block_info,
               broadcasted, stacks_height, consensus_hash, valid, state, signed_group, signed_self, approved_time,
               proposed_time, validation_time_ms, tenure_change, tenure_change_cause)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                u64_to_sql(block_info.reward_cycle)?,
                u64_to_sql(block_info.burn_block_height)?,
                hash.to_string(),
                block_json,
                &broadcasted,
                u64_to_sql(block_info.block.header.chain_length)?,
                block_info.block.header.consensus_hash.to_hex(),
                &block_info.valid,
                &block_info.state.to_string(),
                &block_info.signed_group,
                &block_info.signed_self,
                &block_info.approved_time,
                &block_info.proposed_time,
                &block_info.validation_time_ms,
                &block_info.is_tenure_change(),
                &block_info.tenure_change_cause().map(|x| x.as_u8()),
            ],
        )?;
        Ok(())
    }

    /// Determine if there are any unprocessed blocks
    pub fn has_unprocessed_blocks(&self, reward_cycle: u64) -> Result<bool, DBError> {
        let query = "SELECT block_info FROM blocks WHERE reward_cycle = ?1 AND state = ?2 LIMIT 1";
        let result: Option<String> = query_row(
            &self.db,
            query,
            params!(
                &u64_to_sql(reward_cycle)?,
                &BlockState::Unprocessed.to_string()
            ),
        )?;

        Ok(result.is_some())
    }

    /// Record an observed block signature
    pub fn add_block_signature(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        signer_addr: &StacksAddress,
        signature: &MessageSignature,
    ) -> Result<bool, DBError> {
        // Remove any block rejection entry for this signer and block hash
        let del_qry = "DELETE FROM block_rejection_signer_addrs WHERE signer_signature_hash = ?1 AND signer_addr = ?2";
        let del_args = params![block_sighash, signer_addr.to_string()];
        self.db.execute(del_qry, del_args)?;

        // Insert the block signature
        let qry = "INSERT OR IGNORE INTO block_signatures (signer_signature_hash, signer_addr, signature) VALUES (?1, ?2, ?3);";
        let args = params![
            block_sighash,
            signer_addr.to_string(),
            serde_json::to_string(signature).map_err(DBError::SerializationError)?
        ];
        let rows_added = self.db.execute(qry, args)?;

        let is_new_signature = rows_added > 0;
        if is_new_signature {
            debug!("Added block signature.";
                "signer_signature_hash" => %block_sighash,
                "signer_address" => %signer_addr,
                "signature" => %signature
            );
        } else {
            debug!("Duplicate block signature.";
                "signer_signature_hash" => %block_sighash,
                "signer_address" => %signer_addr,
                "signature" => %signature
            );
        }
        Ok(is_new_signature)
    }

    /// Get all signatures for a block
    pub fn get_block_signatures(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<MessageSignature>, DBError> {
        let qry = "SELECT signature FROM block_signatures WHERE signer_signature_hash = ?1";
        let args = params![block_sighash];
        let sigs_txt: Vec<String> = query_rows(&self.db, qry, args)?;
        sigs_txt
            .into_iter()
            .map(|sig_txt| serde_json::from_str(&sig_txt).map_err(|_| DBError::ParseError))
            .collect()
    }

    /// Record an observed block rejection_signature
    pub fn add_block_rejection_signer_addr(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        addr: &StacksAddress,
        reject_reason: RejectReasonPrefix,
    ) -> Result<bool, DBError> {
        // If this signer/block already has a signature, do not allow a rejection
        let sig_qry = "SELECT EXISTS(SELECT 1 FROM block_signatures WHERE signer_signature_hash = ?1 AND signer_addr = ?2)";
        let sig_args = params![block_sighash, addr.to_string()];
        let exists = self.db.query_row(sig_qry, sig_args, |row| row.get(0))?;
        if exists {
            warn!("Cannot add block rejection because a signature already exists.";
                "signer_signature_hash" => %block_sighash,
                "signer_address" => %addr,
                "reject_reason" => ?reject_reason
            );
            return Ok(false);
        }

        // Check if a row exists for this sighash/signer combo
        let qry = "SELECT reject_code FROM block_rejection_signer_addrs WHERE signer_signature_hash = ?1 AND signer_addr = ?2 LIMIT 1";
        let args = params![block_sighash, addr.to_string()];
        let existing_code: Option<i64> =
            self.db.query_row(qry, args, |row| row.get(0)).optional()?;

        let reject_code = reject_reason as i64;

        match existing_code {
            Some(code) if code == reject_code => {
                // Row exists with same reject_reason, do nothing
                debug!("Duplicate block rejection.";
                    "signer_signature_hash" => %block_sighash,
                    "signer_address" => %addr,
                    "reject_reason" => ?reject_reason
                );
                Ok(false)
            }
            Some(_) => {
                // Row exists but with different reject_reason, update it
                let update_qry = "UPDATE block_rejection_signer_addrs SET reject_code = ?1 WHERE signer_signature_hash = ?2 AND signer_addr = ?3";
                let update_args = params![reject_code, block_sighash, addr.to_string()];
                self.db.execute(update_qry, update_args)?;
                debug!("Updated block rejection reason.";
                    "signer_signature_hash" => %block_sighash,
                    "signer_address" => %addr,
                    "reject_reason" => ?reject_reason
                );
                Ok(true)
            }
            None => {
                // Row does not exist, insert it
                let insert_qry = "INSERT INTO block_rejection_signer_addrs (signer_signature_hash, signer_addr, reject_code) VALUES (?1, ?2, ?3)";
                let insert_args = params![block_sighash, addr.to_string(), reject_code];
                self.db.execute(insert_qry, insert_args)?;
                debug!("Inserted block rejection.";
                    "signer_signature_hash" => %block_sighash,
                    "signer_address" => %addr,
                    "reject_reason" => ?reject_reason
                );
                Ok(true)
            }
        }
    }

    /// Get all signer addresses that rejected the block (and their reject codes)
    pub fn get_block_rejection_signer_addrs(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<(StacksAddress, RejectReasonPrefix)>, DBError> {
        let qry =
            "SELECT signer_addr, reject_code FROM block_rejection_signer_addrs WHERE signer_signature_hash = ?1";
        let args = params![block_sighash];
        let mut stmt = self.db.prepare(qry)?;

        let rows = stmt.query_map(args, |row| {
            let addr: String = row.get(0)?;
            let addr = StacksAddress::from_string(&addr).ok_or(SqliteError::InvalidColumnType(
                0,
                "signer_addr".into(),
                rusqlite::types::Type::Text,
            ))?;
            let reject_code: i64 = row.get(1)?;

            let reject_code = u8::try_from(reject_code)
                .map_err(|_| {
                    SqliteError::InvalidColumnType(
                        1,
                        "reject_code".into(),
                        rusqlite::types::Type::Integer,
                    )
                })
                .map(RejectReasonPrefix::from)?;

            Ok((addr, reject_code))
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.into())
    }

    /// Mark a block as having been broadcasted and therefore GloballyAccepted
    pub fn set_block_broadcasted(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        ts: u64,
    ) -> Result<(), DBError> {
        let qry = "UPDATE blocks SET broadcasted = ?1 WHERE signer_signature_hash = ?2";
        let args = params![u64_to_sql(ts)?, block_sighash];

        debug!("Marking block {block_sighash} as broadcasted at {ts}");
        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Get the timestamp at which the block was broadcasted.
    pub fn get_block_broadcasted(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Option<u64>, DBError> {
        let qry =
            "SELECT IFNULL(broadcasted,0) AS broadcasted FROM blocks WHERE signer_signature_hash = ?";
        let args = params![block_sighash];

        let Some(broadcasted): Option<u64> = query_row(&self.db, qry, args)? else {
            return Ok(None);
        };
        if broadcasted == 0 {
            return Ok(None);
        }
        Ok(Some(broadcasted))
    }

    /// Get a pending block validation, sorted by the time at which it was added to the pending table.
    /// If found, remove it from the pending table.
    pub fn get_and_remove_pending_block_validation(
        &self,
    ) -> Result<Option<(Sha512Trunc256Sum, u64)>, DBError> {
        let qry = "DELETE FROM block_validations_pending WHERE signer_signature_hash = (SELECT signer_signature_hash FROM block_validations_pending ORDER BY added_time ASC LIMIT 1) RETURNING signer_signature_hash, added_time";
        let args = params![];
        let mut stmt = self.db.prepare(qry)?;
        let result: Option<(String, i64)> = stmt
            .query_row(args, |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        Ok(result.and_then(|(sighash, ts_i64)| {
            let signer_sighash = Sha512Trunc256Sum::from_hex(&sighash).ok()?;
            let ts = u64::try_from(ts_i64).ok()?;
            Some((signer_sighash, ts))
        }))
    }

    /// Remove a pending block validation
    pub fn remove_pending_block_validation(
        &self,
        sighash: &Sha512Trunc256Sum,
    ) -> Result<(), DBError> {
        self.db.execute(
            "DELETE FROM block_validations_pending WHERE signer_signature_hash = ?1",
            params![sighash.to_string()],
        )?;
        Ok(())
    }

    /// Insert a pending block validation
    pub fn insert_pending_block_validation(
        &self,
        sighash: &Sha512Trunc256Sum,
        ts: u64,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT INTO block_validations_pending (signer_signature_hash, added_time) VALUES (?1, ?2)",
            params![sighash.to_string(), u64_to_sql(ts)?],
        )?;
        Ok(())
    }

    /// Check if a pending block validation exists for the given sighash
    pub fn has_pending_block_validation(
        &self,
        sighash: &Sha512Trunc256Sum,
    ) -> Result<bool, DBError> {
        let qry = "SELECT signer_signature_hash FROM block_validations_pending WHERE signer_signature_hash = ?1";
        let args = params![sighash.to_string()];
        let sighash_opt: Option<String> = query_row(&self.db, qry, args)?;
        Ok(sighash_opt.is_some())
    }

    /// Returns:
    /// * the time (epoch time in seconds) of the last tenure change during the tenure identified by `tenure`
    ///   where the change cause matches `cause_match`
    /// * the processing time in milliseconds of the blocks since that time
    fn get_tenure_times<F>(
        &self,
        tenure: &ConsensusHash,
        cause_match: F,
    ) -> Result<(u64, u64), DBError>
    where
        F: Fn(TenureChangeCause) -> bool,
    {
        let query = "SELECT tenure_change_cause, proposed_time, validation_time_ms FROM blocks WHERE consensus_hash = ?1 AND state = ?2 ORDER BY stacks_height DESC";
        let args = params![tenure, BlockState::GloballyAccepted.to_string()];
        let mut stmt = self.db.prepare(query)?;
        let rows = stmt.query_map(args, |row| {
            let tenure_change_cause: Option<u8> = row.get(0)?;
            let tenure_change_cause = tenure_change_cause
                .and_then(|cause_byte| TenureChangeCause::try_from(cause_byte).ok());
            let proposed_time: u64 = row.get(1)?;
            let validation_time_ms: Option<u64> = row.get(2)?;
            Ok((tenure_change_cause, proposed_time, validation_time_ms))
        })?;
        let mut tenure_processing_time_ms = 0_u64;
        let mut tenure_start_time = None;
        let mut nmb_rows = 0;
        for (i, row) in rows.enumerate() {
            nmb_rows += 1;
            let (tenure_change_cause, proposed_time, validation_time_ms) = row?;
            tenure_processing_time_ms =
                tenure_processing_time_ms.saturating_add(validation_time_ms.unwrap_or(0));
            tenure_start_time = Some(proposed_time);
            if let Some(tenure_change_cause) = tenure_change_cause {
                if cause_match(tenure_change_cause) {
                    debug!("Found matching tenure change block {i} blocks ago in tenure {tenure}");
                    break;
                }
            }
        }
        debug!("Calculated tenure extend timestamp from {nmb_rows} blocks in tenure {tenure}");
        Ok((
            tenure_start_time.unwrap_or(get_epoch_time_secs()),
            tenure_processing_time_ms,
        ))
    }

    /// Calculate the timestamp for the next read count tenure extend.
    ///
    /// If determining the timestamp for a block rejection, check_tenure_extend should be set to false to avoid recalculating
    /// the tenure extend timestamp for a tenure extend block.
    #[allow(unused)]
    pub fn calculate_read_count_extend_timestamp(
        &self,
        tenure_idle_timeout: Duration,
        block: &NakamotoBlock,
        check_tenure_extend: bool,
    ) -> u64 {
        self.calculate_tenure_extend_timestamp(
            tenure_idle_timeout,
            block,
            check_tenure_extend,
            |change_cause| {
                matches!(
                    change_cause,
                    // Note: we want to "reset" our timestamp whenever the read-count dimension is extended. This means
                    //  that "full" extends should also reset our timestamp
                    TenureChangeCause::BlockFound
                        | TenureChangeCause::Extended
                        | TenureChangeCause::ExtendedReadCount
                )
            },
        )
    }

    /// Calculate the (full) tenure extend timestamp.
    ///
    /// If determining the timestamp for a block rejection, check_tenure_extend should be set to false to avoid recalculating
    /// the tenure extend timestamp for a tenure extend block.
    pub fn calculate_full_extend_timestamp(
        &self,
        tenure_idle_timeout: Duration,
        block: &NakamotoBlock,
        check_tenure_extend: bool,
    ) -> u64 {
        self.calculate_tenure_extend_timestamp(
            tenure_idle_timeout,
            block,
            check_tenure_extend,
            |change_cause| {
                matches!(
                    change_cause,
                    TenureChangeCause::BlockFound | TenureChangeCause::Extended
                )
            },
        )
    }

    fn calculate_tenure_extend_timestamp<F>(
        &self,
        tenure_idle_timeout: Duration,
        block: &NakamotoBlock,
        check_tenure_extend: bool,
        tenure_change_match: F,
    ) -> u64
    where
        F: Fn(TenureChangeCause) -> bool,
    {
        if check_tenure_extend {
            if let Some(tenure_change) = block.get_tenure_tx_payload() {
                if tenure_change_match(tenure_change.cause) {
                    let tenure_extend_timestamp =
                        get_epoch_time_secs().wrapping_add(tenure_idle_timeout.as_secs());
                    debug!("Calculated tenure extend timestamp for a tenure extend block. Rolling over timestamp: {tenure_extend_timestamp}");
                    return tenure_extend_timestamp;
                }
            }
        }
        let tenure_idle_timeout_secs = tenure_idle_timeout.as_secs();
        let (tenure_start_time, tenure_process_time_ms) = self.get_tenure_times(
            &block.header.consensus_hash,
            tenure_change_match,
        ).unwrap_or_else(|e| {
            error!("Error occurred calculating tenure extend timestamp: {e:?}. Defaulting to {tenure_idle_timeout_secs} from now.");
            (get_epoch_time_secs(), 0)
        });
        // Plus (ms + 999)/1000 to round up to the nearest second
        let tenure_extend_timestamp = tenure_start_time
            .saturating_add(tenure_idle_timeout_secs)
            .saturating_add(tenure_process_time_ms.div_ceil(1000));
        debug!("Calculated tenure extend timestamp";
            "tenure_extend_timestamp" => tenure_extend_timestamp,
            "tenure_start_time" => tenure_start_time,
            "tenure_process_time_ms" => tenure_process_time_ms,
            "tenure_idle_timeout_secs" => tenure_idle_timeout_secs,
            "tenure_extend_in" => tenure_extend_timestamp.saturating_sub(get_epoch_time_secs()),
            "consensus_hash" => %block.header.consensus_hash,
        );
        tenure_extend_timestamp
    }

    /// Update the tenure (identified by consensus_hash) last activity timestamp
    pub fn update_last_activity_time(
        &mut self,
        tenure: &ConsensusHash,
        last_activity_time: u64,
    ) -> Result<(), DBError> {
        debug!("Updating last activity for tenure"; "consensus_hash" => %tenure, "last_activity_time" => last_activity_time);
        self.db.execute("INSERT OR REPLACE INTO tenure_activity (consensus_hash, last_activity_time) VALUES (?1, ?2)", params![tenure, u64_to_sql(last_activity_time)?])?;
        Ok(())
    }

    /// Get the last activity timestamp for a tenure (identified by consensus_hash)
    pub fn get_last_activity_time(&self, tenure: &ConsensusHash) -> Result<Option<u64>, DBError> {
        let query =
            "SELECT last_activity_time FROM tenure_activity WHERE consensus_hash = ? LIMIT 1";
        let Some(last_activity_time_i64) = query_row::<i64, _>(&self.db, query, &[tenure])? else {
            return Ok(None);
        };
        let last_activity_time = u64::try_from(last_activity_time_i64).map_err(|e| {
            error!("Failed to parse db last_activity_time as u64: {e}");
            DBError::Corruption
        })?;
        Ok(Some(last_activity_time))
    }

    /// Insert the signer state machine update
    pub fn insert_state_machine_update(
        &mut self,
        reward_cycle: u64,
        address: &StacksAddress,
        update: &StateMachineUpdate,
        received_time: &SystemTime,
    ) -> Result<(), DBError> {
        let received_ts = received_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DBError::Other(format!("Bad system time: {e}")))?
            .as_secs();
        let update_str =
            serde_json::to_string(&update).expect("Unable to serialize state machine update");
        debug!("Inserting update.";
            "reward_cycle" => reward_cycle,
            "address" => %address,
            "active_signer_protocol_version" => update.active_signer_protocol_version,
            "local_supported_signer_protocol_version" => update.local_supported_signer_protocol_version
        );
        self.db.execute("INSERT OR REPLACE INTO signer_state_machine_updates (signer_addr, reward_cycle, state_update, received_time) VALUES (?1, ?2, ?3, ?4)", params![
            address.to_string(),
            u64_to_sql(reward_cycle)?,
            update_str,
            u64_to_sql(received_ts)?,
        ])?;

        // Conditionally insert into burn_block_updates_received_times only if missing for (signer_addr, burn_block_consensus_hash)
        let burn_block_consensus_hash = update.content.burn_block_view().0;
        self.db.execute(
            "INSERT OR IGNORE INTO burn_block_updates_received_times
            (signer_addr, burn_block_consensus_hash, received_time)
            VALUES (?1, ?2, ?3)",
            params![
                address.to_string(),
                burn_block_consensus_hash,
                u64_to_sql(received_ts)?,
            ],
        )?;
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    /// Clear out signer state machine updates for testing purposes ONLY.
    pub fn clear_state_machine_updates(&mut self) -> Result<(), DBError> {
        debug!("Clearing all updates.");
        self.db
            .execute("DELETE FROM signer_state_machine_updates", params![])?;
        Ok(())
    }

    /// Get the most recent signer states from the signer state machine for the given reward cycle
    pub fn get_signer_state_machine_updates(
        &mut self,
        reward_cycle: u64,
    ) -> Result<HashMap<StacksAddress, StateMachineUpdate>, DBError> {
        let query = r#"
            SELECT signer_addr, state_update
            FROM signer_state_machine_updates
            WHERE reward_cycle = ?1;
        "#;
        let args = params![u64_to_sql(reward_cycle)?];
        let mut stmt = self.db.prepare(query)?;
        let rows = stmt.query_map(args, |row| {
            let address_str: String = row.get(0)?;
            let update_str: String = row.get(1)?;
            Ok((address_str, update_str))
        })?;
        let mut result = HashMap::new();
        for row in rows {
            let (address_str, update_str) = row?;
            let address = StacksAddress::from_string(&address_str).ok_or(DBError::Corruption)?;
            let update: StateMachineUpdate = serde_json::from_str(&update_str)?;
            result.insert(address, update);
        }
        Ok(result)
    }

    /// Get the earliest received time at which the signer state update achieved
    /// a global burn view identified by the provided ConsensusHash
    pub fn get_burn_block_received_time_from_signers(
        &self,
        eval: &GlobalStateEvaluator,
        ch: &ConsensusHash,
        local_address: &StacksAddress,
    ) -> Result<Option<u64>, DBError> {
        let mut entries = Vec::new();

        // Add our own vote if we received this consensus hash
        if let Some(local_received_time) = self.get_burn_block_receive_time_ch(ch)? {
            entries.push((local_address.clone(), local_received_time));
        }

        // Query other signer received times from the DB
        let query = r#"
            SELECT signer_addr, received_time
            FROM burn_block_updates_received_times
            WHERE burn_block_consensus_hash = ?1
        "#;

        let mut stmt = self.db.prepare(query)?;
        let rows = stmt.query_map(params![ch], |row| {
            let signer_addr: String = row.get(0)?;
            let received_time: i64 = row.get(1)?;
            Ok((signer_addr, received_time))
        })?;
        for row in rows {
            let (signer_addr_str, received_time_i64) = row?;
            let address =
                StacksAddress::from_string(&signer_addr_str).ok_or(DBError::Corruption)?;

            let received_time = u64::try_from(received_time_i64).map_err(|e| {
                error!("Failed to convert received_time to u64: {e}");
                DBError::Corruption
            })?;

            entries.push((address, received_time));
        }

        // Sort by received_time ascending
        entries.sort_by_key(|(_, time)| *time);

        // Accumulate vote weight and stop when threshold is reached
        let mut vote_weight: u32 = 0;
        for (address, received_time) in entries {
            let weight = eval.address_weights.get(&address).copied().unwrap_or(0);
            vote_weight = vote_weight.saturating_add(weight);

            if eval.reached_agreement(vote_weight) {
                return Ok(Some(received_time));
            }
        }

        Ok(None)
    }

    /// Record an observed block pre-commit
    pub fn add_block_pre_commit(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        address: &StacksAddress,
    ) -> Result<(), DBError> {
        let qry = "INSERT OR REPLACE INTO block_pre_commits (signer_signature_hash, signer_addr) VALUES (?1, ?2);";
        let args = params![block_sighash, address.to_string()];

        debug!("Inserting block pre-commit.";
            "signer_signature_hash" => %block_sighash,
            "signer_addr" => %address);

        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Check if the given address has already committed to sign the block identified by block_sighash
    pub fn has_committed(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        address: &StacksAddress,
    ) -> Result<bool, DBError> {
        let qry_check = "
            SELECT 1 FROM block_pre_commits
            WHERE signer_signature_hash = ?1 AND signer_addr = ?2
            LIMIT 1;";

        let exists: Option<u8> = self
            .db
            .query_row(
                qry_check,
                params![block_sighash, address.to_string()],
                |row| row.get(0),
            )
            .optional()?;

        Ok(exists.is_some())
    }

    /// Get all pre-committers for a block
    pub fn get_block_pre_committers(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<StacksAddress>, DBError> {
        let qry = "SELECT signer_addr FROM block_pre_commits WHERE signer_signature_hash = ?1";
        let args = params![block_sighash];
        let addrs_txt: Vec<String> = query_rows(&self.db, qry, args)?;

        let res: Result<Vec<_>, _> = addrs_txt
            .into_iter()
            .map(|addr| StacksAddress::from_string(&addr).ok_or(DBError::Corruption))
            .collect();
        res
    }
    /// Record a pending block pre-commit response for an untracked block proposal
    /// Automatically evicts oldest entries if this signer has more than 3 entries
    pub fn add_pending_block_pre_commit_response(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        signer_addr: &StacksAddress,
    ) -> Result<(), DBError> {
        let received_time = get_epoch_time_secs();
        let qry = "INSERT OR REPLACE INTO signer_pending_pre_commit_responses (signer_signature_hash, signer_addr, received_time) VALUES (?1, ?2, ?3);";
        let args = params![
            block_sighash.to_string(),
            signer_addr.to_string(),
            u64_to_sql(received_time)?
        ];

        debug!("Recording pending pre-commit response for untracked block.";
            "signer_signature_hash" => %block_sighash,
            "signer_addr" => %signer_addr,
            "received_time" => received_time);

        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Record a pending block signature response for an untracked block proposal
    /// Automatically evicts oldest entries if this signer has more than 3 entries
    pub fn add_pending_block_signature_response(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        signer_addr: &StacksAddress,
        signature: &MessageSignature,
    ) -> Result<(), DBError> {
        let received_time = get_epoch_time_secs();
        let qry = "INSERT OR REPLACE INTO signer_pending_signature_responses (signer_signature_hash, signer_addr, signature, received_time) VALUES (?1, ?2, ?3, ?4);";
        let args = params![
            block_sighash.to_string(),
            signer_addr.to_string(),
            serde_json::to_string(signature).map_err(DBError::SerializationError)?,
            u64_to_sql(received_time)?
        ];

        debug!("Recording pending signature response for untracked block.";
            "signer_signature_hash" => %block_sighash,
            "signer_addr" => %signer_addr,
            "received_time" => received_time);

        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Record a pending block rejection response for an untracked block proposal
    /// Automatically evicts oldest entries if this signer has more than 3 entries
    pub fn add_pending_block_rejection_response(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        signer_addr: &StacksAddress,
        reject_reason: RejectReasonPrefix,
    ) -> Result<(), DBError> {
        let received_time = get_epoch_time_secs();
        let reject_code = reject_reason as i64;
        let qry = "INSERT OR REPLACE INTO signer_pending_rejection_responses (signer_signature_hash, signer_addr, reject_code, received_time) VALUES (?1, ?2, ?3, ?4);";
        let args = params![
            block_sighash.to_string(),
            signer_addr.to_string(),
            reject_code,
            u64_to_sql(received_time)?
        ];

        debug!("Recording pending rejection response for untracked block.";
            "signer_signature_hash" => %block_sighash,
            "signer_addr" => %signer_addr,
            "reject_code" => reject_code,
            "received_time" => received_time);

        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Retrieve and clear all pending block response entries matching the given block signer_signature_hash
    /// Returns PendingBlockResponses containing all matching pre-commits, approval signatures, and rejections
    pub fn drain_pending_block_responses(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<PendingBlockResponses, DBError> {
        let hash_str = block_sighash.to_string();

        // Delete and return pre-commits in one operation
        let pre_commits_qry = "DELETE FROM signer_pending_pre_commit_responses WHERE signer_signature_hash = ?1 RETURNING signer_addr";
        let mut stmt = self.db.prepare(pre_commits_qry)?;
        let pre_commits_rows = stmt.query_map(params![&hash_str], |row| {
            let addr_str: String = row.get(0)?;
            let addr = StacksAddress::from_string(&addr_str).ok_or(
                SqliteError::InvalidColumnType(0, addr_str.clone(), rusqlite::types::Type::Text),
            )?;
            Ok(addr)
        })?;
        let pre_commits: Vec<_> = pre_commits_rows.collect::<Result<Vec<_>, _>>()?;

        // Delete and return signatures in one operation
        let signatures_qry = "DELETE FROM signer_pending_signature_responses WHERE signer_signature_hash = ?1 RETURNING signer_addr, signature";
        let mut stmt = self.db.prepare(signatures_qry)?;
        let signatures_rows = stmt.query_map(params![&hash_str], |row| {
            let addr_str: String = row.get(0)?;
            let sig_str: String = row.get(1)?;
            let addr = StacksAddress::from_string(&addr_str).ok_or(
                SqliteError::InvalidColumnType(0, addr_str.clone(), rusqlite::types::Type::Text),
            )?;
            let signature: MessageSignature = serde_json::from_str(&sig_str).map_err(|_| {
                SqliteError::InvalidColumnType(1, sig_str.clone(), rusqlite::types::Type::Text)
            })?;
            Ok((addr, signature))
        })?;
        let signatures: Vec<_> = signatures_rows.collect::<Result<Vec<_>, _>>()?;

        // Delete and return rejections in one operation
        let rejections_qry = "DELETE FROM signer_pending_rejection_responses WHERE signer_signature_hash = ?1 RETURNING signer_addr, reject_code";
        let mut stmt = self.db.prepare(rejections_qry)?;
        let rejections_rows = stmt.query_map(params![&hash_str], |row| {
            let addr_str: String = row.get(0)?;
            let reject_code: u8 = row.get(1)?;
            let addr = StacksAddress::from_string(&addr_str).ok_or(
                SqliteError::InvalidColumnType(0, addr_str.clone(), rusqlite::types::Type::Text),
            )?;
            let reject_reason = RejectReasonPrefix::from(reject_code);
            Ok((addr, reject_reason))
        })?;
        let rejections: Vec<_> = rejections_rows.collect::<Result<Vec<_>, _>>()?;

        let pending_block_responses = PendingBlockResponses {
            pre_commits,
            signatures,
            rejections,
        };
        if !pending_block_responses.is_empty() {
            debug!("Drained pending block responses for block {block_sighash}";
                "pre_commits_count" => pending_block_responses.pre_commits.len(),
                "signatures_count" => pending_block_responses.signatures.len(),
                "rejections_count" => pending_block_responses.rejections.len());
        }
        Ok(pending_block_responses)
    }
}

fn try_deserialize<T>(s: Option<String>) -> Result<Option<T>, DBError>
where
    T: serde::de::DeserializeOwned,
{
    s.as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(DBError::SerializationError)
}

/// The identifying details of a signed block that conflicts with a block proposal, as
/// returned by [`SignerDb::get_signed_conflicts`].
#[derive(Debug)]
pub struct SignedConflictInfo {
    /// The consensus hash of the tenure containing the conflicting block
    pub consensus_hash: ConsensusHash,
    /// The signer signature hash of the conflicting block
    pub signer_signature_hash: Sha512Trunc256Sum,
    /// The Stacks height of the conflicting block
    pub stacks_height: u64,
    /// The most recent time (epoch seconds) at which we signed the block or observed the
    /// signer set accept it (0 if neither was recorded)
    pub last_endorsed: u64,
    /// Whether the block reached global acceptance, which is what decides if the node ever had
    /// it: a locally accepted block is not handed to the node until the whole signer set has
    /// signed it, so the node not having one says nothing about whether it is still live.
    pub globally_accepted: bool,
    /// The sortition of the tenure we permitted to reorg this block's tenure, if we recorded
    /// such a permit (see [`SignerDb::mark_tenure_superseded`]). The permit excludes this
    /// conflict only for a proposal on the branch it sanctioned, and only while that sortition
    /// is still canonical, both of which the caller must derive.
    pub superseded_by: Option<SupersededBy>,
}

/// The two tenures of a reorg permit, as queried by [`SignerDb::has_reorg_permit`]. The two
/// hashes are named rather than positional because both sides of a reorg are a
/// [`ConsensusHash`], and swapping them asks a different question that silently answers
/// `false`.
#[derive(Debug)]
pub struct ReorgPermit<'a> {
    /// The tenure whose blocks we permitted to be replaced
    pub reorged_tenure: &'a ConsensusHash,
    /// The tenure we permitted to replace them
    pub reorging_tenure: &'a ConsensusHash,
}

/// The sortition of a tenure we permitted to reorg another tenure, as carried by
/// [`SignedConflictInfo::superseded_by`].
#[derive(Debug)]
pub struct SupersededBy {
    /// The consensus hash of the permitting tenure
    pub consensus_hash: ConsensusHash,
    /// The burn block hash of the permitting tenure's sortition, used to ask the node whether
    /// that sortition is still canonical
    pub burn_block_hash: BurnchainHeaderHash,
}

impl FromRow<SignedConflictInfo> for SignedConflictInfo {
    fn from_row(row: &rusqlite::Row) -> Result<Self, DBError> {
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let signer_signature_hash = Sha512Trunc256Sum::from_column(row, "signer_signature_hash")?;
        let stacks_height = u64::from_column(row, "stacks_height")?;
        let last_endorsed = u64::from_column(row, "last_endorsed")?;
        let state: String = row.get("state")?;
        let superseded_by_ch: Option<ConsensusHash> = row.get("superseded_by_consensus_hash")?;
        let superseded_by_bbh: Option<BurnchainHeaderHash> =
            row.get("superseded_by_burn_block_hash")?;
        let superseded_by = match (superseded_by_ch, superseded_by_bbh) {
            (Some(consensus_hash), Some(burn_block_hash)) => Some(SupersededBy {
                consensus_hash,
                burn_block_hash,
            }),
            _ => None,
        };
        Ok(SignedConflictInfo {
            consensus_hash,
            signer_signature_hash,
            stacks_height,
            last_endorsed,
            globally_accepted: state == BlockState::GloballyAccepted.to_string(),
            superseded_by,
        })
    }
}

/// For tests, a struct to represent a pending block validation
#[cfg(any(test, feature = "testing"))]
pub struct PendingBlockValidation {
    /// The signer signature hash of the block
    pub signer_signature_hash: Sha512Trunc256Sum,
    /// The time at which the block was added to the pending table
    pub added_time: u64,
}

#[cfg(any(test, feature = "testing"))]
impl FromRow<PendingBlockValidation> for PendingBlockValidation {
    fn from_row(row: &rusqlite::Row) -> Result<Self, DBError> {
        let signer_signature_hash = Sha512Trunc256Sum::from_column(row, "signer_signature_hash")?;
        let added_time = row.get_unwrap(1);
        Ok(PendingBlockValidation {
            signer_signature_hash,
            added_time,
        })
    }
}

#[cfg(any(test, feature = "testing"))]
impl SignerDb {
    /// For tests, fetch all pending block validations
    pub fn get_all_pending_block_validations(
        &self,
    ) -> Result<Vec<PendingBlockValidation>, DBError> {
        let qry = "SELECT signer_signature_hash, added_time FROM block_validations_pending ORDER BY added_time ASC";
        query_rows(&self.db, qry, params![])
    }
}

/// Tests for SignerDb
#[cfg(test)]
pub mod tests {
    use std::fs;
    use std::path::PathBuf;

    use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use blockstack_lib::chainstate::stacks::{
        StacksTransaction, TenureChangeCause, TenureChangePayload, TransactionAuth,
        TransactionVersion,
    };
    use clarity::types::chainstate::{StacksBlockId, StacksPrivateKey, StacksPublicKey};
    use clarity::types::PrivateKey;
    use clarity::util::hash::Hash160;
    use clarity::util::secp256k1::MessageSignature;
    use libsigner::v0::messages::{StateMachineUpdateContent, StateMachineUpdateMinerState};
    use libsigner::{BlockProposal, BlockProposalData};

    use super::*;
    use crate::signerdb::NakamotoBlockVote;

    fn _wipe_db(db_path: &PathBuf) {
        if fs::metadata(db_path).is_ok() {
            fs::remove_file(db_path).unwrap();
        }
    }

    /// Override the creation of a block from a block proposal with the provided function
    pub fn create_block_override(
        overrides: impl FnOnce(&mut BlockProposal),
    ) -> (BlockInfo, BlockProposal) {
        let header = NakamotoBlockHeader::empty();
        let block = NakamotoBlock::new(header, vec![]);
        let mut block_proposal = BlockProposal {
            block,
            burn_height: 7,
            reward_cycle: 42,
            block_proposal_data: BlockProposalData::empty(),
        };
        overrides(&mut block_proposal);
        (BlockInfo::from(block_proposal.clone()), block_proposal)
    }

    fn create_block() -> (BlockInfo, BlockProposal) {
        create_block_override(|_| {})
    }

    fn get_pending_pre_commit_responses(
        db: &SignerDb,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<StacksAddress>, DBError> {
        let qry = "SELECT signer_addr FROM signer_pending_pre_commit_responses WHERE signer_signature_hash = ?1 ORDER BY received_time DESC";
        let args = params![block_sighash.to_string()];

        let mut stmt = db.db.prepare(qry)?;
        let rows = stmt.query_map(args, |row| {
            let addr_str: String = row.get(0)?;
            let addr = StacksAddress::from_string(&addr_str).ok_or(
                SqliteError::InvalidColumnType(0, addr_str.clone(), rusqlite::types::Type::Text),
            )?;
            Ok(addr)
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(DBError::from)
    }

    fn get_pending_signature_responses(
        db: &SignerDb,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<MessageSignature>, DBError> {
        let qry = "SELECT signature FROM signer_pending_signature_responses WHERE signer_signature_hash = ?1 ORDER BY received_time DESC";
        let args = params![block_sighash.to_string()];

        let mut stmt = db.db.prepare(qry)?;
        let rows = stmt.query_map(args, |row| {
            let sig_str: String = row.get(0)?;
            let signature: MessageSignature = serde_json::from_str(&sig_str).map_err(|_| {
                SqliteError::InvalidColumnType(0, sig_str.clone(), rusqlite::types::Type::Text)
            })?;
            Ok(signature)
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(DBError::from)
    }

    fn get_pending_rejection_responses(
        db: &SignerDb,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<(StacksAddress, RejectReasonPrefix)>, DBError> {
        let qry = "SELECT signer_addr, reject_code FROM signer_pending_rejection_responses WHERE signer_signature_hash = ?1 ORDER BY received_time DESC";
        let args = params![block_sighash.to_string()];

        let mut stmt = db.db.prepare(qry)?;
        let rows = stmt.query_map(args, |row| {
            let addr_str: String = row.get(0)?;
            let reject_code: u8 = row.get(1)?;
            let addr = StacksAddress::from_string(&addr_str).ok_or(
                SqliteError::InvalidColumnType(0, addr_str.clone(), rusqlite::types::Type::Text),
            )?;
            let reject_reason = RejectReasonPrefix::from(reject_code);
            Ok((addr, reject_reason))
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(DBError::from)
    }

    /// Consensus hash of the test sortition at `burn_height`
    fn prune_test_ch(burn_height: u64) -> ConsensusHash {
        let mut bytes = [0u8; 20];
        bytes[..8].copy_from_slice(&burn_height.to_be_bytes());
        ConsensusHash(bytes)
    }

    /// Record a sortition at `burn_height` in `burn_blocks`
    fn prune_test_insert_burn_block(db: &mut SignerDb, burn_height: u64) {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&burn_height.to_be_bytes());
        let mut parent = [0u8; 32];
        parent[..8].copy_from_slice(&burn_height.saturating_sub(1).to_be_bytes());
        db.insert_burn_block(
            &BurnchainHeaderHash(hash),
            &prune_test_ch(burn_height),
            burn_height,
            &SystemTime::now(),
            &BurnchainHeaderHash(parent),
        )
        .unwrap();
    }

    /// Store a block of the tenure elected at `sortition` with the given height and state,
    /// with one signature row, and return its signer signature hash
    fn prune_test_insert_stx_block(
        db: &mut SignerDb,
        sortition: u64,
        stacks_height: u64,
        state: BlockState,
    ) -> Sha512Trunc256Sum {
        let (mut block_info, _) = create_block_override(|b| {
            b.block.header.consensus_hash = prune_test_ch(sortition);
            b.block.header.chain_length = stacks_height;
            // a miner-controlled value that pruning must ignore
            b.burn_height = u64::MAX / 4;
        });
        block_info.state = state;
        db.insert_block(&block_info).unwrap();
        let hash = block_info.signer_signature_hash();
        let signer = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );
        db.add_block_signature(&hash, &signer, &MessageSignature::empty())
            .unwrap();
        hash
    }

    /// The parameters of a test pruning pass. The seed data is built around a fork depth of
    /// `MAX_FORK_DEPTH` (burn tip 300, horizon 200, search down to 100).
    fn prune_test_params(batch_size: u64) -> PruneParams {
        PruneParams {
            batch_size,
            fork_depth: MAX_FORK_DEPTH,
            orphaned_update_max_age: Duration::from_secs(2 * MAX_FORK_DEPTH * 600),
        }
    }

    /// Number of rows in `table`
    pub fn prune_test_table_count(db: &SignerDb, table: &str) -> i64 {
        db.db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    /// Burn blocks 1..=300 (tip 300, horizon 200, search down to 100) and four tenures:
    /// A elected at 50, B at 150, C at 190 (the tenure in charge at the horizon), D at 250 (tip).
    pub fn prune_test_seed_data(db: &mut SignerDb) -> [Sha512Trunc256Sum; 8] {
        for burn_height in 1..=300 {
            prune_test_insert_burn_block(db, burn_height);
        }
        let accepted = BlockState::GloballyAccepted;
        [
            prune_test_insert_stx_block(db, 50, 1, accepted),
            prune_test_insert_stx_block(db, 50, 2, accepted),
            prune_test_insert_stx_block(db, 150, 3, accepted),
            prune_test_insert_stx_block(db, 150, 4, accepted),
            prune_test_insert_stx_block(db, 190, 5, accepted),
            prune_test_insert_stx_block(db, 190, 6, accepted),
            prune_test_insert_stx_block(db, 250, 7, accepted),
            prune_test_insert_stx_block(db, 250, 8, accepted),
        ]
    }

    #[test]
    fn test_prune_removes_tenures_elected_before_the_tenure_in_charge() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        let hashes = prune_test_seed_data(&mut db);

        let stats = db.prune(&prune_test_params(100)).unwrap();
        assert_eq!(stats.cutoff_height, Some(5));
        assert_eq!(stats.blocks, 4);
        // one signature per removed block
        assert_eq!(stats.block_rows, 4);

        // A and B are gone, with their signatures; C (in charge at the horizon) and D (tip) stay
        for hash in &hashes[..4] {
            assert!(db.block_lookup(hash).unwrap().is_none());
            assert!(db.get_block_signatures(hash).unwrap().is_empty());
        }
        for hash in &hashes[4..] {
            assert!(db.block_lookup(hash).unwrap().is_some());
            assert_eq!(db.get_block_signatures(hash).unwrap().len(), 1);
        }

        // burn blocks below the tenure in charge are aged out too, at most a batch per pass
        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
        assert!(db.get_burn_block_by_ch(&prune_test_ch(50)).is_err());
        assert!(db.get_burn_block_by_ch(&prune_test_ch(189)).is_err());
        assert!(db.get_burn_block_by_ch(&prune_test_ch(190)).is_ok());
        assert_eq!(prune_test_table_count(&db, "burn_blocks"), 111);

        // once drained, a pass still places the horizon and has nothing left to do
        let stats = db.prune(&prune_test_params(100)).unwrap();
        assert_eq!(stats.cutoff_height, Some(5));
        assert!(!stats.removed_any());
        assert!(!stats.is_skipped());
    }

    #[test]
    fn test_prune_keeps_tenures_elected_inside_the_horizon_whatever_their_height() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        // A tenure elected at 260 that built on an old parent: its block sits below the cutoff
        let reorging = prune_test_insert_stx_block(&mut db, 260, 2, BlockState::LocallyAccepted);
        // An unvalidated proposal claiming a low height in the tip's tenure
        let low_claim = prune_test_insert_stx_block(&mut db, 250, 1, BlockState::Unprocessed);

        let stats = db.prune(&prune_test_params(100)).unwrap();
        assert_eq!(stats.blocks, 4);
        assert!(db.block_lookup(&reorging).unwrap().is_some());
        assert!(db.block_lookup(&low_claim).unwrap().is_some());
    }

    #[test]
    fn test_prune_keeps_recent_tenures_after_a_bitcoin_reorg() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        for burn_height in 1..=300 {
            prune_test_insert_burn_block(&mut db, burn_height);
        }
        // A sortition of a Bitcoin branch orphaned by a two-block reorg: its burn block and its
        // accepted blocks stay in the database
        let orphaned_ch = |burn_height: u64| {
            let mut bytes = [0xffu8; 20];
            bytes[..8].copy_from_slice(&burn_height.to_be_bytes());
            ConsensusHash(bytes)
        };
        for burn_height in [199u64, 200] {
            let mut hash = [0xffu8; 32];
            hash[..8].copy_from_slice(&burn_height.to_be_bytes());
            db.insert_burn_block(
                &BurnchainHeaderHash(hash),
                &orphaned_ch(burn_height),
                burn_height,
                &SystemTime::now(),
                &BurnchainHeaderHash([0u8; 32]),
            )
            .unwrap();
        }
        let insert = |db: &mut SignerDb, ch: ConsensusHash, stacks_height: u64| {
            let (mut block_info, _) = create_block_override(|b| {
                b.block.header.consensus_hash = ch;
                b.block.header.chain_length = stacks_height;
            });
            block_info.state = BlockState::GloballyAccepted;
            db.insert_block(&block_info).unwrap();
            block_info.signer_signature_hash()
        };
        // Common parent: the tenure elected at 198, up to block 40
        insert(&mut db, prune_test_ch(198), 40);
        // The orphaned branch produced blocks 41..=100 in tenures 199' and 200'
        insert(&mut db, orphaned_ch(199), 41);
        insert(&mut db, orphaned_ch(199), 99);
        insert(&mut db, orphaned_ch(200), 100);
        // The replacement branch: 199 builds block 41 on the common parent, 200 produces nothing,
        // and the chain then moves slowly up to the tip at 61 in the tenure elected at 260
        insert(&mut db, prune_test_ch(199), 41);
        let recent = insert(&mut db, prune_test_ch(250), 42);
        let recent_last = insert(&mut db, prune_test_ch(250), 60);
        let tip = insert(&mut db, prune_test_ch(260), 61);

        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}

        // The tenures elected inside the horizon stay, including the tip's
        for hash in [&recent, &recent_last, &tip] {
            assert!(db.block_lookup(hash).unwrap().is_some());
        }
    }

    #[test]
    fn test_prune_keeps_tenures_with_an_unknown_election() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        // A tenure whose burn block this signer never recorded (e.g. a database started
        // mid-tenure), with a block below the cutoff
        let missed = prune_test_ch(10_000);
        assert!(db.get_burn_block_by_ch(&missed).is_err());
        let unknown = prune_test_insert_stx_block(&mut db, 10_000, 3, BlockState::GloballyAccepted);

        // Nothing shows it was elected before the tenure in charge, and it is recently active, so
        // it is kept
        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
        assert!(db.block_lookup(&unknown).unwrap().is_some());
        // while the tenures elected before the tenure in charge still go
        assert_eq!(prune_test_table_count(&db, "blocks"), 5);
    }

    /// Set the arrival time of every recorded burn block
    fn prune_test_set_burn_block_times(db: &SignerDb, received_time: u64) {
        db.db
            .execute(
                "UPDATE burn_blocks SET received_time = ?1",
                params![u64_to_sql(received_time).unwrap()],
            )
            .unwrap();
    }

    /// Set every local activity time of a stored block to `time`
    fn prune_test_set_old_activity(db: &mut SignerDb, hash: &Sha512Trunc256Sum, time: u64) {
        let mut block = db.block_lookup(hash).unwrap().unwrap();
        block.proposed_time = time;
        block.approved_time = None;
        block.signed_self = None;
        block.signed_group = None;
        db.insert_block(&block).unwrap();
    }

    #[test]
    fn test_prune_drains_unknown_elections_and_their_rows_by_age() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        prune_test_set_burn_block_times(&db, anchor);
        let old = anchor - prune_test_params(1).orphaned_update_max_age.as_secs() - 1;
        let mut hashes = Vec::new();
        for height in [2, 3] {
            let hash =
                prune_test_insert_stx_block(&mut db, 10_000, height, BlockState::GloballyAccepted);
            prune_test_set_old_activity(&mut db, &hash, old);
            let signer = StacksAddress::p2pkh(
                false,
                &StacksPublicKey::from_private(&StacksPrivateKey::random()),
            );
            db.add_block_pre_commit(&hash, &signer).unwrap();
            db.add_block_rejection_signer_addr(&hash, &signer, RejectReasonPrefix::InvalidMiner)
                .unwrap();
            db.insert_pending_block_validation(&hash, old).unwrap();
            hashes.push(hash);
        }
        db.update_last_activity_time(&prune_test_ch(10_000), old)
            .unwrap();

        // One block per pass: the tenure drains oldest first, then its activity goes
        while db.prune(&prune_test_params(1)).unwrap().removed_any() {}
        for hash in hashes {
            assert!(db.block_lookup(&hash).unwrap().is_none());
            for table in [
                "block_signatures",
                "block_pre_commits",
                "block_rejection_signer_addrs",
                "block_validations_pending",
            ] {
                let count: i64 = db
                    .db
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE signer_signature_hash = ?1"),
                        params![hash.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "{table}");
            }
        }
        assert!(db
            .get_last_activity_time(&prune_test_ch(10_000))
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_prune_keeps_unknown_elections_with_any_recent_activity() {
        // Each source of activity keeps the tenure on its own, even exactly at the cutoff
        for activity in 0..5 {
            let mut db = SignerDb::new(tmp_db_path()).unwrap();
            prune_test_seed_data(&mut db);
            let anchor = 1_000_000u64;
            prune_test_set_burn_block_times(&db, anchor);
            let orphan_cutoff = anchor - prune_test_params(100).orphaned_update_max_age.as_secs();
            let hash =
                prune_test_insert_stx_block(&mut db, 10_000, 3, BlockState::GloballyAccepted);
            prune_test_set_old_activity(&mut db, &hash, orphan_cutoff - 1);
            let sibling =
                prune_test_insert_stx_block(&mut db, 10_000, 2, BlockState::GloballyAccepted);
            prune_test_set_old_activity(&mut db, &sibling, orphan_cutoff - 1);
            let mut block = db.block_lookup(&hash).unwrap().unwrap();
            match activity {
                0 => block.proposed_time = orphan_cutoff,
                1 => block.approved_time = Some(orphan_cutoff),
                2 => block.signed_self = Some(orphan_cutoff),
                3 => block.signed_group = Some(orphan_cutoff),
                _ => db
                    .update_last_activity_time(&prune_test_ch(10_000), orphan_cutoff)
                    .unwrap(),
            }
            db.insert_block(&block).unwrap();

            while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
            assert!(
                db.block_lookup(&hash).unwrap().is_some(),
                "activity {activity}"
            );
            assert!(
                db.block_lookup(&sibling).unwrap().is_some(),
                "sibling with activity {activity}"
            );
        }
    }

    #[test]
    fn test_prune_gives_unknown_elections_the_rest_of_the_batch() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        // A and B (4 blocks) are removable for their election
        let seeded = prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        prune_test_set_burn_block_times(&db, anchor);
        let old = anchor - prune_test_params(5).orphaned_update_max_age.as_secs() - 1;
        // An inactive unknown election with three blocks, older than A by height
        let unknown: Vec<_> = (2..=4)
            .map(|height| {
                let hash = prune_test_insert_stx_block(
                    &mut db,
                    10_000,
                    height,
                    BlockState::GloballyAccepted,
                );
                prune_test_set_old_activity(&mut db, &hash, old);
                hash
            })
            .collect();

        // Known elections go first, the unknown election gets the last slot, oldest first
        let stats = db.prune(&prune_test_params(5)).unwrap();
        assert_eq!(stats.blocks, 5);
        for hash in &seeded[..4] {
            assert!(db.block_lookup(hash).unwrap().is_none());
        }
        assert!(db.block_lookup(&unknown[0]).unwrap().is_none());
        assert!(db.block_lookup(&unknown[1]).unwrap().is_some());

        // The rest of the unknown election follows in the next pass
        let stats = db.prune(&prune_test_params(5)).unwrap();
        assert_eq!(stats.blocks, 2);
        assert!(db.block_lookup(&unknown[2]).unwrap().is_none());
    }

    #[test]
    fn test_prune_drains_many_expired_unknown_elections_past_kept_ones() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        prune_test_set_burn_block_times(&db, anchor);
        let old = anchor - prune_test_params(1).orphaned_update_max_age.as_secs() - 1;
        // Recently active unknown elections, which are kept, and expired ones among them
        let mut kept = Vec::new();
        let mut expired = Vec::new();
        for tenure in 10_000..10_010 {
            let hash = prune_test_insert_stx_block(&mut db, tenure, 3, BlockState::Unprocessed);
            if tenure % 2 == 0 {
                prune_test_set_old_activity(&mut db, &hash, anchor);
                kept.push(hash);
            } else {
                prune_test_set_old_activity(&mut db, &hash, old);
                expired.push(hash);
            }
        }

        // One block per pass: every expired election goes in turn, the kept ones never block it
        while db.prune(&prune_test_params(1)).unwrap().removed_any() {}
        for hash in &expired {
            assert!(db.block_lookup(hash).unwrap().is_none());
        }
        for hash in &kept {
            assert!(db.block_lookup(hash).unwrap().is_some());
        }
    }

    #[test]
    fn test_prune_keeps_a_large_unknown_election_active_at_its_last_block() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        prune_test_set_burn_block_times(&db, anchor);
        let old = anchor - prune_test_params(100).orphaned_update_max_age.as_secs() - 1;
        // Many blocks below the cutoff (competing proposals at the same heights), all inactive but
        // the last one
        let mut hashes = Vec::new();
        for i in 0..300u64 {
            let (mut block_info, _) = create_block_override(|b| {
                b.block.header.consensus_hash = prune_test_ch(10_000);
                b.block.header.chain_length = 1 + i % 4;
                b.block.header.timestamp = i;
            });
            block_info.state = BlockState::Unprocessed;
            block_info.proposed_time = old;
            db.insert_block(&block_info).unwrap();
            hashes.push(block_info.signer_signature_hash());
        }
        let last = hashes.last().unwrap();
        prune_test_set_old_activity(&mut db, last, anchor);

        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
        // The whole tenure stays, while the removable tenures still go
        for hash in &hashes {
            assert!(db.block_lookup(hash).unwrap().is_some());
        }
        assert_eq!(prune_test_table_count(&db, "blocks"), 4 + 300);
    }

    #[test]
    fn test_prune_keeps_old_unknown_elections_whole() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        prune_test_set_burn_block_times(&db, anchor);
        let old = anchor - prune_test_params(100).orphaned_update_max_age.as_secs() - 1;
        // An inactive unknown election with a block at the cutoff (5)
        let low = prune_test_insert_stx_block(&mut db, 10_000, 3, BlockState::GloballyAccepted);
        let high = prune_test_insert_stx_block(&mut db, 10_000, 5, BlockState::LocallyAccepted);
        for hash in [&low, &high] {
            prune_test_set_old_activity(&mut db, hash, old);
        }

        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
        assert!(db.block_lookup(&low).unwrap().is_some());
        assert!(db.block_lookup(&high).unwrap().is_some());
    }

    #[test]
    fn test_prune_ages_unknown_elections_from_the_tenure_in_charge() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        let max_age = prune_test_params(100).orphaned_update_max_age.as_secs();
        prune_test_set_burn_block_times(&db, anchor);
        let unknown = prune_test_insert_stx_block(&mut db, 10_000, 3, BlockState::GloballyAccepted);
        prune_test_set_old_activity(&mut db, &unknown, anchor - 60);

        // A late tip does not move the cutoff
        db.db
            .execute(
                "UPDATE burn_blocks SET received_time = ?1 WHERE block_height = 300",
                params![u64_to_sql(anchor + max_age + 60).unwrap()],
            )
            .unwrap();
        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
        assert!(db.block_lookup(&unknown).unwrap().is_some());

        // Nor does an arrival time too early to subtract the maximum age from
        prune_test_set_burn_block_times(&db, max_age - 1);
        prune_test_set_old_activity(&mut db, &unknown, 0);
        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
        assert!(db.block_lookup(&unknown).unwrap().is_some());

        // Once the tenure in charge arrived long enough after the activity, it goes
        prune_test_set_burn_block_times(&db, anchor + max_age + 60);
        prune_test_set_old_activity(&mut db, &unknown, anchor - 60);
        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}
        assert!(db.block_lookup(&unknown).unwrap().is_none());
    }

    #[test]
    fn test_prune_ages_tenure_activity_of_unknown_elections() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        prune_test_set_burn_block_times(&db, anchor);
        let orphan_cutoff = anchor - prune_test_params(100).orphaned_update_max_age.as_secs();
        db.update_last_activity_time(&prune_test_ch(10_001), orphan_cutoff - 1)
            .unwrap();
        db.update_last_activity_time(&prune_test_ch(10_002), orphan_cutoff)
            .unwrap();
        // Old activity of an unknown election that still has a block at the cutoff
        prune_test_insert_stx_block(&mut db, 10_003, 5, BlockState::LocallyAccepted);
        db.update_last_activity_time(&prune_test_ch(10_003), orphan_cutoff - 1)
            .unwrap();

        while db.prune(&prune_test_params(1)).unwrap().removed_any() {}
        assert!(db
            .get_last_activity_time(&prune_test_ch(10_001))
            .unwrap()
            .is_none());
        assert_eq!(
            db.get_last_activity_time(&prune_test_ch(10_002)).unwrap(),
            Some(orphan_cutoff)
        );
        assert!(db
            .get_last_activity_time(&prune_test_ch(10_003))
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_prune_keeps_tenures_whole() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        // A tenure elected at 100 that is still producing blocks above the cutoff
        let old_part = prune_test_insert_stx_block(&mut db, 100, 2, BlockState::GloballyAccepted);
        let new_part = prune_test_insert_stx_block(&mut db, 100, 9, BlockState::LocallyAccepted);

        db.prune(&prune_test_params(100)).unwrap();
        assert!(db.block_lookup(&old_part).unwrap().is_some());
        assert!(db.block_lookup(&new_part).unwrap().is_some());
    }

    #[test]
    fn test_prune_drains_a_tenure_larger_than_a_batch_oldest_first() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        for burn_height in 1..=300 {
            prune_test_insert_burn_block(&mut db, burn_height);
        }
        let accepted = BlockState::GloballyAccepted;
        // A removable tenure elected at 150 with more blocks than a batch, then the tenure in
        // charge at the horizon (190) and the tip's tenure (250)
        let large: Vec<_> = (1..=5)
            .map(|height| prune_test_insert_stx_block(&mut db, 150, height, accepted))
            .collect();
        prune_test_insert_stx_block(&mut db, 190, 6, accepted);
        prune_test_insert_stx_block(&mut db, 250, 7, accepted);

        // Each pass removes the oldest blocks left, so its newest block is the last to go
        for (removed_so_far, removed_in_pass) in [(2, 2), (4, 2), (5, 1)] {
            let stats = db.prune(&prune_test_params(2)).unwrap();
            assert_eq!(stats.blocks, removed_in_pass);
            for (i, hash) in large.iter().enumerate() {
                assert_eq!(db.block_lookup(hash).unwrap().is_none(), i < removed_so_far);
            }
        }
        assert_eq!(prune_test_table_count(&db, "blocks"), 2);
    }

    #[test]
    fn test_prune_skips_when_the_horizon_cannot_be_placed() {
        // Fresh database
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        let stats = db.prune(&prune_test_params(100)).unwrap();
        assert!(stats.is_skipped());
        assert_eq!(stats, PruneStats::skipped());

        // Burn tip too low to have a horizon
        prune_test_insert_burn_block(&mut db, 50);
        prune_test_insert_stx_block(&mut db, 50, 1, BlockState::GloballyAccepted);
        let stats = db.prune(&prune_test_params(100)).unwrap();
        assert!(stats.is_skipped());
        assert_eq!(stats, PruneStats::skipped());

        // No accepted tenure elected in the search range below the horizon (a long Stacks stall,
        // or a signer that was offline): tip 500, horizon 400, search down to 300, last tenure at 50
        for burn_height in 51..=500 {
            prune_test_insert_burn_block(&mut db, burn_height);
        }
        let stats = db.prune(&prune_test_params(100)).unwrap();
        assert!(stats.is_skipped());
        assert_eq!(stats, PruneStats::skipped());
        assert_eq!(prune_test_table_count(&db, "blocks"), 1);
        // heights 50..=500: nothing was removed
        assert_eq!(prune_test_table_count(&db, "burn_blocks"), 451);
    }

    #[test]
    fn test_prune_respects_the_batch_size() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);

        let stats = db.prune(&prune_test_params(1)).unwrap();
        assert_eq!(stats.blocks, 1);
        assert_eq!(prune_test_table_count(&db, "blocks"), 7);

        let mut passes = 1;
        while db.prune(&prune_test_params(1)).unwrap().removed_any() {
            passes += 1;
        }
        assert_eq!(prune_test_table_count(&db, "blocks"), 4);
        // 4 blocks and 189 burn block rows, at most one of each per pass
        assert!(passes >= 189, "passes: {passes}");
    }

    /// Rows the unbounded form of the `burn_blocks` delete would still remove below `height`
    fn prune_test_unbounded_burn_block_candidates(db: &SignerDb, height: u64) -> i64 {
        db.db
            .query_row(
                "SELECT COUNT(*) FROM burn_blocks bb
                 WHERE bb.block_height < ?1
                   AND NOT EXISTS (SELECT 1 FROM blocks b WHERE b.consensus_hash = bb.consensus_hash)
                   AND NOT EXISTS (SELECT 1 FROM tenure_activity ta
                                   WHERE ta.consensus_hash = bb.consensus_hash)
                   AND NOT EXISTS (SELECT 1 FROM burn_block_updates_received_times u
                                   WHERE u.burn_block_consensus_hash = bb.consensus_hash)",
                params![u64_to_sql(height).unwrap()],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn test_prune_bounded_burn_block_aging_reaches_the_unbounded_end_state() {
        for batch_size in [1, 3, 100] {
            let mut db = SignerDb::new(tmp_db_path()).unwrap();
            prune_test_seed_data(&mut db);
            // Tenures elected before the tenure in charge that are kept, pinning their burn block
            // records at the very bottom of the window: one kept whole (it still has a block at
            // or above the cutoff) and one elected at the lowest height.
            prune_test_insert_stx_block(&mut db, 1, 2, BlockState::GloballyAccepted);
            prune_test_insert_stx_block(&mut db, 1, 9, BlockState::LocallyAccepted);
            prune_test_insert_stx_block(&mut db, 2, 3, BlockState::GloballyAccepted);
            prune_test_insert_stx_block(&mut db, 2, 10, BlockState::LocallyAccepted);
            db.update_last_activity_time(&prune_test_ch(3), 1).unwrap();

            while db
                .prune(&prune_test_params(batch_size))
                .unwrap()
                .removed_any()
            {}

            // Nothing the unbounded rule would remove is left, whatever the batch size
            assert_eq!(
                prune_test_unbounded_burn_block_candidates(&db, 190),
                0,
                "batch size {batch_size}"
            );
            // The pinned records stay; everything else below the tenure in charge is gone
            assert!(db.get_burn_block_by_ch(&prune_test_ch(1)).is_ok());
            assert!(db.get_burn_block_by_ch(&prune_test_ch(2)).is_ok());
            assert!(db.get_burn_block_by_ch(&prune_test_ch(3)).is_err());
            assert!(db.get_burn_block_by_ch(&prune_test_ch(189)).is_err());
            assert_eq!(prune_test_table_count(&db, "burn_blocks"), 111 + 2);
        }
    }

    #[test]
    fn test_prune_ages_burn_block_keyed_and_reward_cycle_tables() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        db.update_last_activity_time(&prune_test_ch(50), 1).unwrap();
        db.update_last_activity_time(&prune_test_ch(190), 1)
            .unwrap();
        db.update_last_activity_time(&prune_test_ch(250), 1)
            .unwrap();
        for reward_cycle in 1..=5 {
            db.insert_encrypted_signer_state(reward_cycle, &[0u8; 4])
                .unwrap();
        }

        db.prune(&prune_test_params(100)).unwrap();

        assert!(db
            .get_last_activity_time(&prune_test_ch(50))
            .unwrap()
            .is_none());
        assert!(db
            .get_last_activity_time(&prune_test_ch(190))
            .unwrap()
            .is_some());
        assert!(db
            .get_last_activity_time(&prune_test_ch(250))
            .unwrap()
            .is_some());
        // the latest recorded reward cycle and the one before it are kept
        assert!(db.get_encrypted_signer_state(3).unwrap().is_none());
        assert!(db.get_encrypted_signer_state(4).unwrap().is_some());
        assert!(db.get_encrypted_signer_state(5).unwrap().is_some());
    }

    #[test]
    fn test_prune_ages_orphaned_burn_block_timestamps_by_age() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        let max_age = prune_test_params(1).orphaned_update_max_age.as_secs();
        let insert = |db: &SignerDb, signer: &str, ch: &ConsensusHash, received_time: u64| {
            db.db
                .execute(
                    "INSERT INTO burn_block_updates_received_times
                     (signer_addr, burn_block_consensus_hash, received_time) VALUES (?1, ?2, ?3)",
                    params![signer, ch, u64_to_sql(received_time).unwrap()],
                )
                .unwrap();
        };
        let count = |db: &SignerDb, ch: &ConsensusHash| -> i64 {
            db.db
                .query_row(
                    "SELECT COUNT(*) FROM burn_block_updates_received_times
                     WHERE burn_block_consensus_hash = ?1",
                    params![ch],
                    |row| row.get(0),
                )
                .unwrap()
        };
        // Every burn block arrived at `anchor`, so the orphan cutoff is `anchor - max_age`
        prune_test_set_burn_block_times(&db, anchor);
        let orphan_cutoff = anchor - max_age;
        // Burn blocks this signer never recorded (no `burn_blocks` row)
        let missed = prune_test_ch(10_000);
        let at_cutoff = prune_test_ch(10_001);
        let not_yet_recorded = prune_test_ch(10_002);
        for signer in ["a", "b", "c"] {
            // missed long ago (e.g. during an outage): can no longer be the current sortition
            insert(&db, signer, &missed, orphan_cutoff - 60);
            insert(&db, signer, &at_cutoff, orphan_cutoff);
            // a peer's update that arrived before our own burn block
            insert(&db, signer, &not_yet_recorded, anchor - 60);
            // recorded burn blocks: one below the tenure in charge, one kept (the tip's tenure)
            insert(&db, signer, &prune_test_ch(50), anchor);
            insert(&db, signer, &prune_test_ch(250), orphan_cutoff - 60);
        }

        // While the height-based aging still has a full batch to do, orphans are left alone
        db.prune(&prune_test_params(1)).unwrap();
        assert_eq!(count(&db, &missed), 3);
        assert_eq!(count(&db, &prune_test_ch(50)), 2);

        // A late tip, long after the others: the cutoff is measured from the tenure in charge, so
        // it does not move
        db.db
            .execute(
                "UPDATE burn_blocks SET received_time = ?1 WHERE block_height = 300",
                params![u64_to_sql(anchor + 10 * max_age).unwrap()],
            )
            .unwrap();
        while db.prune(&prune_test_params(1)).unwrap().removed_any() {}

        // Only the orphans past the cutoff are gone
        assert_eq!(count(&db, &missed), 0);
        assert_eq!(count(&db, &at_cutoff), 3);
        assert_eq!(count(&db, &not_yet_recorded), 3);
        // Timestamps of recorded burn blocks are aged by height only, whatever their age
        assert_eq!(count(&db, &prune_test_ch(50)), 0);
        assert_eq!(count(&db, &prune_test_ch(250)), 3);
    }

    #[test]
    fn test_prune_orphan_cutoff_is_capped_at_the_newest_burn_block() {
        let mut db = SignerDb::new(tmp_db_path()).unwrap();
        prune_test_seed_data(&mut db);
        let anchor = 1_000_000u64;
        let max_age = prune_test_params(100).orphaned_update_max_age.as_secs();
        prune_test_set_burn_block_times(&db, anchor);
        // The burn block of the tenure in charge (190) was delivered again, long after the tip
        db.db
            .execute(
                "UPDATE burn_blocks SET received_time = ?1 WHERE block_height = 190",
                params![u64_to_sql(anchor + 10 * max_age).unwrap()],
            )
            .unwrap();
        let insert = |db: &SignerDb, ch: &ConsensusHash, received_time: u64| {
            db.db
                .execute(
                    "INSERT INTO burn_block_updates_received_times
                     (signer_addr, burn_block_consensus_hash, received_time) VALUES ('a', ?1, ?2)",
                    params![ch, u64_to_sql(received_time).unwrap()],
                )
                .unwrap();
        };
        let old = prune_test_ch(10_000);
        let kept_by_the_cap = prune_test_ch(10_001);
        insert(&db, &old, anchor - max_age - 1);
        insert(&db, &kept_by_the_cap, anchor - max_age + 60);
        let unknown = prune_test_insert_stx_block(&mut db, 10_002, 3, BlockState::GloballyAccepted);
        prune_test_set_old_activity(&mut db, &unknown, anchor - max_age + 60);

        while db.prune(&prune_test_params(100)).unwrap().removed_any() {}

        // The cutoff is measured from the tip's arrival, the earlier of the two
        let remaining: i64 = db
            .db
            .query_row(
                "SELECT COUNT(*) FROM burn_block_updates_received_times
                 WHERE burn_block_consensus_hash = ?1",
                params![&old],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
        let remaining: i64 = db
            .db
            .query_row(
                "SELECT COUNT(*) FROM burn_block_updates_received_times
                 WHERE burn_block_consensus_hash = ?1",
                params![&kept_by_the_cap],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
        assert!(db.block_lookup(&unknown).unwrap().is_some());
    }

    /// Create a temporary db path for testing purposes
    pub fn tmp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "stacks-signer-test-{}.sqlite",
            rand::random::<u64>()
        ))
    }

    fn test_basic_signer_db_with_path(db_path: impl AsRef<Path>) {
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info_1, block_proposal_1) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x01; 20]);
        });
        let (block_info_2, block_proposal_2) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x02; 20]);
        });
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        let block_info = db
            .block_lookup(&block_proposal_1.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal_1), block_info);

        // Test looking up a block with an unknown hash
        let block_info = db
            .block_lookup(&block_proposal_2.block.header.signer_signature_hash())
            .unwrap();
        assert!(block_info.is_none());

        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");
        let block_info = db
            .block_lookup(&block_proposal_2.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal_2), block_info);
    }

    #[test]
    fn test_basic_signer_db() {
        let db_path = tmp_db_path();
        eprintln!("db path is {}", db_path.display());
        test_basic_signer_db_with_path(db_path)
    }

    #[test]
    fn test_basic_signer_db_in_memory() {
        test_basic_signer_db_with_path(":memory:")
    }

    #[test]
    fn test_update_block() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info, block_proposal) = create_block();
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(&block_proposal.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal.clone()), block_info);

        let old_block_info = block_info;
        let old_block_proposal = block_proposal;

        let (mut block_info, block_proposal) = create_block_override(|b| {
            b.block.header.signer_signature =
                old_block_proposal.block.header.signer_signature.clone();
        });
        assert_eq!(
            block_info.signer_signature_hash(),
            old_block_info.signer_signature_hash()
        );
        let vote = NakamotoBlockVote {
            signer_signature_hash: Sha512Trunc256Sum([0x01; 32]),
            rejected: false,
        };
        block_info.vote = Some(vote.clone());
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(&block_proposal.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_ne!(old_block_info, block_info);
        assert_eq!(block_info.vote, Some(vote));
    }

    #[test]
    fn get_first_signed_block() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, block_proposal) = create_block();
        db.insert_block(&block_info).unwrap();

        assert!(db
            .get_first_approved_block_in_tenure(&block_proposal.block.header.consensus_hash)
            .unwrap()
            .is_none());

        block_info
            .mark_locally_accepted(false)
            .expect("Failed to mark block as locally accepted");
        db.insert_block(&block_info).unwrap();

        let fetched_info = db
            .get_first_approved_block_in_tenure(&block_proposal.block.header.consensus_hash)
            .unwrap()
            .unwrap();
        assert_eq!(fetched_info, block_info);
    }

    #[test]
    fn insert_burn_block_get_time() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let test_burn_hash = BurnchainHeaderHash([10; 32]);
        let test_consensus_hash = ConsensusHash([13; 20]);
        let stime = SystemTime::now();
        let time_to_epoch = stime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        db.insert_burn_block(
            &test_burn_hash,
            &test_consensus_hash,
            10,
            &stime,
            &test_burn_hash,
        )
        .unwrap();

        let stored_time = db
            .get_burn_block_receive_time(&test_burn_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored_time, time_to_epoch);
    }

    #[test]
    fn test_write_signer_state() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        let state_0 = vec![0];
        let state_1 = vec![1; 1024];

        db.insert_encrypted_signer_state(10, &state_0)
            .expect("Failed to insert signer state");

        db.insert_encrypted_signer_state(11, &state_1)
            .expect("Failed to insert signer state");

        assert_eq!(
            db.get_encrypted_signer_state(10)
                .expect("Failed to get signer state")
                .unwrap(),
            state_0
        );
        assert_eq!(
            db.get_encrypted_signer_state(11)
                .expect("Failed to get signer state")
                .unwrap(),
            state_1
        );
        assert!(db
            .get_encrypted_signer_state(12)
            .expect("Failed to get signer state")
            .is_none());
        assert!(db
            .get_encrypted_signer_state(9)
            .expect("Failed to get signer state")
            .is_none());
    }

    #[test]
    fn test_has_unprocessed_blocks() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.burn_height = 1;
        });
        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.burn_height = 2;
        });

        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");

        assert!(db
            .has_unprocessed_blocks(block_info_1.reward_cycle)
            .unwrap());

        block_info_1.state = BlockState::LocallyRejected;

        db.insert_block(&block_info_1)
            .expect("Unable to update block in db");

        assert!(db
            .has_unprocessed_blocks(block_info_1.reward_cycle)
            .unwrap());

        block_info_2.state = BlockState::LocallyAccepted;

        db.insert_block(&block_info_2)
            .expect("Unable to update block in db");

        assert!(!db
            .has_unprocessed_blocks(block_info_1.reward_cycle)
            .unwrap());
    }

    #[test]
    fn test_sqlite_version() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        assert_eq!(
            query_row(&db.db, "SELECT sqlite_version()", []).unwrap(),
            Some("3.45.0".to_string())
        );
    }

    #[test]
    fn add_and_get_block_signatures() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address1 = StacksAddress::burn_address(false);
        let address2 = StacksAddress::burn_address(true);
        let sig1 = MessageSignature([0x11; 65]);
        let sig2 = MessageSignature([0x22; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        db.add_block_signature(&block_id, &address1, &sig1).unwrap();
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![sig1.clone()]
        );

        db.add_block_signature(&block_id, &address2, &sig2).unwrap();
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![sig2, sig1]
        );
    }

    #[test]
    fn duplicate_block_signatures() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);
        let sig1 = MessageSignature([0x11; 65]);
        let sig2 = MessageSignature([0x22; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        assert!(db.add_block_signature(&block_id, &address, &sig1).unwrap());
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![sig1.clone()]
        );

        assert!(!db.add_block_signature(&block_id, &address, &sig2).unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);
    }

    #[test]
    fn add_and_get_block_rejections() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address1 = StacksAddress::burn_address(false);
        let address2 = StacksAddress::burn_address(true);

        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![]
        );

        assert!(db
            .add_block_rejection_signer_addr(
                &block_id,
                &address1,
                RejectReasonPrefix::DuplicateBlockFound,
            )
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address1.clone(), RejectReasonPrefix::DuplicateBlockFound)]
        );

        assert!(db
            .add_block_rejection_signer_addr(
                &block_id,
                &address2,
                RejectReasonPrefix::InvalidParentBlock,
            )
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![
                (address2, RejectReasonPrefix::InvalidParentBlock),
                (address1, RejectReasonPrefix::DuplicateBlockFound),
            ]
        );
    }

    #[test]
    fn duplicate_block_rejections() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);

        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![]
        );

        assert!(db
            .add_block_rejection_signer_addr(
                &block_id,
                &address,
                RejectReasonPrefix::InvalidParentBlock
            )
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address.clone(), RejectReasonPrefix::InvalidParentBlock)]
        );

        assert!(db
            .add_block_rejection_signer_addr(&block_id, &address, RejectReasonPrefix::InvalidMiner)
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address.clone(), RejectReasonPrefix::InvalidMiner)]
        );

        assert!(!db
            .add_block_rejection_signer_addr(&block_id, &address, RejectReasonPrefix::InvalidMiner)
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address, RejectReasonPrefix::InvalidMiner)]
        );
    }

    #[test]
    fn reject_then_accept() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);
        let sig1 = MessageSignature([0x11; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        assert!(db
            .add_block_rejection_signer_addr(
                &block_id,
                &address,
                RejectReasonPrefix::InvalidParentBlock
            )
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address.clone(), RejectReasonPrefix::InvalidParentBlock)]
        );

        assert!(db.add_block_signature(&block_id, &address, &sig1).unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);
        assert!(db
            .get_block_rejection_signer_addrs(&block_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn accept_then_reject() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);
        let sig1 = MessageSignature([0x11; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        assert!(db.add_block_signature(&block_id, &address, &sig1).unwrap());
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![sig1.clone()]
        );
        assert!(db
            .get_block_rejection_signer_addrs(&block_id)
            .unwrap()
            .is_empty());

        assert!(!db
            .add_block_rejection_signer_addr(
                &block_id,
                &address,
                RejectReasonPrefix::InvalidParentBlock
            )
            .unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);
        assert!(db
            .get_block_rejection_signer_addrs(&block_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn add_and_get_block_signatures_with_multiple_secp256k1_nonces() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());

        let private_key1 = Secp256k1PrivateKey::from_slice(&[0x99u8; 32]).unwrap();
        let private_key2 = Secp256k1PrivateKey::from_slice(&[0xAAu8; 32]).unwrap();

        let public_key1 = StacksPublicKey::from_private(&private_key1);
        let public_key2 = StacksPublicKey::from_private(&private_key2);

        let address1 = StacksAddress::p2pkh(false, &public_key1);
        let address2 = StacksAddress::p2pkh(false, &public_key2);

        let nonce1 = [0x11u8; 32];
        let signature1 = private_key1
            .sign_with_noncedata(&block_id.0, &nonce1)
            .unwrap();

        let nonce2 = [0x22u8; 32];
        let signature2 = private_key1
            .sign_with_noncedata(&block_id.0, &nonce2)
            .unwrap();

        let nonce3 = [0x33u8; 32];
        let signature3 = private_key1
            .sign_with_noncedata(&block_id.0, &nonce3)
            .unwrap();

        let nonce4 = [0x44u8; 32];
        let signature4 = private_key2
            .sign_with_noncedata(&block_id.0, &nonce4)
            .unwrap();

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        db.add_block_signature(&block_id, &address1, &signature1)
            .unwrap();
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![signature1.clone()]
        );

        db.add_block_signature(&block_id, &address1, &signature2)
            .unwrap();
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![signature1.clone()]
        );

        db.add_block_signature(&block_id, &address1, &signature3)
            .unwrap();
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![signature1.clone()]
        );

        db.add_block_signature(&block_id, &address2, &signature4)
            .unwrap();
        // sort them as ordering is not enforced in get_block_signatures
        let mut block_signatures = db.get_block_signatures(&block_id).unwrap();
        block_signatures.sort();
        let mut signatures = [signature1, signature4];
        signatures.sort();
        assert_eq!(block_signatures, signatures);
    }

    #[test]
    fn test_and_set_block_broadcasted() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let (block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.burn_height = 1;
        });

        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");

        assert!(db
            .get_block_broadcasted(&block_info_1.signer_signature_hash())
            .unwrap()
            .is_none());
        assert_eq!(
            db.block_lookup(&block_info_1.signer_signature_hash())
                .expect("Unable to get block from db")
                .expect("Unable to get block from db")
                .state,
            BlockState::Unprocessed
        );
        assert!(db
            .get_last_globally_accepted_block(&block_info_1.block.header.consensus_hash)
            .unwrap()
            .is_none());
        db.set_block_broadcasted(&block_info_1.signer_signature_hash(), 12345)
            .unwrap();
        assert_eq!(
            db.block_lookup(&block_info_1.signer_signature_hash())
                .expect("Unable to get block from db")
                .expect("Unable to get block from db")
                .state,
            BlockState::Unprocessed
        );
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db a second time");

        assert_eq!(
            db.get_block_broadcasted(&block_info_1.signer_signature_hash())
                .unwrap()
                .unwrap(),
            12345
        );
    }

    #[test]
    fn last_signed_block_excluding_returns_the_same_height_sibling() {
        // Two accepted siblings at one height: excluding either must return the other, which a
        // filter applied after `LIMIT 1` cannot guarantee.
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let tenure = ConsensusHash([7; 20]);
        let (mut a, _) = create_block_override(|b| {
            b.block.header.consensus_hash = tenure.clone();
            b.block.header.chain_length = 10;
            b.block.header.timestamp = 1;
        });
        let (mut b, _) = create_block_override(|b| {
            b.block.header.consensus_hash = tenure.clone();
            b.block.header.chain_length = 10;
            b.block.header.timestamp = 2;
        });
        a.mark_locally_accepted(false).unwrap();
        b.mark_locally_accepted(true).unwrap();
        db.insert_block(&a).unwrap();
        db.insert_block(&b).unwrap();
        let (hash_a, hash_b) = (a.signer_signature_hash(), b.signer_signature_hash());
        assert_ne!(hash_a, hash_b);
        let excluding = |h: &Sha512Trunc256Sum| {
            db.get_last_signed_block(&tenure, Some(h))
                .unwrap()
                .expect("the other sibling must be returned")
                .signer_signature_hash()
        };
        assert_eq!(excluding(&hash_a), hash_b);
        assert_eq!(excluding(&hash_b), hash_a);
        assert!(db.get_last_signed_block(&tenure, None).unwrap().is_some());
    }

    #[test]
    fn pre_committed_then_globally_rejected_keeps_valid_without_signature() {
        // The row shape the re-proposal guard must not trust: validated, never signed, and
        // terminal. `valid` is a local verdict and survives the global rejection.
        let (mut block, _) = create_block();
        block.mark_pre_committed().unwrap();
        block.mark_globally_rejected().unwrap();
        assert_eq!(block.state, BlockState::GloballyRejected);
        assert_eq!(block.valid, Some(true));
        assert!(block.signed_self.is_none());
        assert!(block.signed_group.is_none());
    }

    #[test]
    fn state_machine() {
        let (mut block, _) = create_block();
        assert_eq!(block.state, BlockState::Unprocessed);
        assert!(block.check_state(BlockState::Unprocessed));
        assert!(block.check_state(BlockState::LocallyAccepted));
        assert!(block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::LocallyAccepted).unwrap();
        assert_eq!(block.state, BlockState::LocallyAccepted);
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(block.check_state(BlockState::LocallyAccepted));
        assert!(block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::LocallyRejected).unwrap();
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(block.check_state(BlockState::LocallyAccepted));
        assert!(block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::GloballyAccepted).unwrap();
        assert_eq!(block.state, BlockState::GloballyAccepted);
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(!block.check_state(BlockState::LocallyAccepted));
        assert!(!block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(!block.check_state(BlockState::GloballyRejected));

        // Must manually override as will not be able to move from GloballyAccepted to GloballyRejected
        block.state = BlockState::GloballyRejected;
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(!block.check_state(BlockState::LocallyAccepted));
        assert!(!block.check_state(BlockState::LocallyRejected));
        // The node accepting the block overrides a global rejection
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));
    }

    #[test]
    fn globally_rejected_then_accepted_counts_toward_tenure_times() {
        // A block can cross the rejection threshold and still be accepted by the chain. Once the
        // node confirms it, it must count toward the tenure's extend timing; otherwise the tenure
        // has no globally accepted blocks and the extend timestamp keeps rolling forward from now.
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let mut block_info = generate_tenure_blocks().remove(0);
        let consensus_hash = block_info.block.header.consensus_hash.clone();
        let change_match = |change_cause| {
            matches!(
                change_cause,
                TenureChangeCause::BlockFound | TenureChangeCause::Extended
            )
        };

        block_info.state = BlockState::Unprocessed;
        block_info.mark_globally_rejected().unwrap();
        db.insert_block(&block_info).unwrap();
        let (start_time, _) = db.get_tenure_times(&consensus_hash, change_match).unwrap();
        assert!(
            start_time < block_info.proposed_time,
            "A globally rejected block should not count toward the tenure times"
        );

        block_info.mark_globally_accepted().unwrap();
        db.insert_block(&block_info).unwrap();
        assert_eq!(
            db.block_lookup(&block_info.signer_signature_hash())
                .unwrap()
                .unwrap()
                .state,
            BlockState::GloballyAccepted
        );
        let (start_time, _) = db.get_tenure_times(&consensus_hash, change_match).unwrap();
        assert_eq!(start_time, block_info.proposed_time);
    }

    #[test]
    fn test_get_canonical_tip() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let (mut block_info_1, _block_proposal_1) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });

        let (mut block_info_2, _block_proposal_2) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });

        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");

        assert!(db.get_canonical_tip().unwrap().is_none());

        block_info_1
            .mark_globally_accepted()
            .expect("Failed to mark block as globally accepted");
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");

        assert_eq!(db.get_canonical_tip().unwrap().unwrap(), block_info_1);

        block_info_2
            .mark_globally_accepted()
            .expect("Failed to mark block as globally accepted");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");

        assert_eq!(db.get_canonical_tip().unwrap().unwrap(), block_info_2);
    }

    #[test]
    fn get_accepted_blocks() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let consensus_hash_3 = ConsensusHash([0x03; 20]);
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });
        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });
        let (mut block_info_3, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 3;
        });
        let (mut block_info_4, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2.clone();
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 4;
        });
        let (mut block_info_5, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x04; 65]);
            b.block.header.chain_length = 4;
            b.burn_height = 3;
        });
        // Give blocks 2, 3, and 4 distinct signing times so the freshest conflict is unambiguous
        // (`mark_locally_accepted` and `mark_globally_accepted` preserve already-set timestamps).
        block_info_2.signed_self = Some(100);
        block_info_3.signed_self = Some(50);
        block_info_4.signed_group = Some(60);
        block_info_1.mark_globally_accepted().unwrap();
        block_info_2.mark_locally_accepted(false).unwrap();
        block_info_3.mark_locally_accepted(false).unwrap();
        block_info_4.mark_globally_accepted().unwrap();
        block_info_5.mark_pre_committed().unwrap();

        db.insert_block(&block_info_1).unwrap();
        db.insert_block(&block_info_2).unwrap();
        db.insert_block(&block_info_3).unwrap();
        db.insert_block(&block_info_4).unwrap();
        db.insert_block(&block_info_5).unwrap();

        // Verify tenure consensus_hash_1
        let block_info = db
            .get_last_accepted_block(&consensus_hash_1)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_5);
        let block_info = db
            .get_last_signed_block(&consensus_hash_1, None)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_3);
        let block_info = db
            .get_last_globally_accepted_block(&consensus_hash_1)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_1);

        // Verify tenure consensus_hash_2
        let block_info = db
            .get_last_accepted_block(&consensus_hash_2)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_4);
        let block_info = db
            .get_last_signed_block(&consensus_hash_2, None)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_4);
        let block_info = db
            .get_last_globally_accepted_block(&consensus_hash_2)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_4);

        // Verify tenure consensus_hash_3
        assert!(db
            .get_last_accepted_block(&consensus_hash_3)
            .unwrap()
            .is_none());
        assert!(db
            .get_last_signed_block(&consensus_hash_3, None)
            .unwrap()
            .is_none());
        assert!(db
            .get_last_globally_accepted_block(&consensus_hash_3)
            .unwrap()
            .is_none());

        // Verify the signed-conflict query. It searches across ALL tenures and returns every
        // signed conflict, highest first, with its endorsement time. Blocks 2 and 3 (tenure 1,
        // heights 2 and 3) were signed at times 100 and 50, block 4 (tenure 2, height 3) at
        // time 60; block_info_5 (height 4) is only pre-committed, so it must never be
        // considered.
        let unrelated_hash = Sha512Trunc256Sum([0xff; 32]);
        let conflicts = db.get_signed_conflicts(2, &unrelated_hash).unwrap();
        assert_eq!(conflicts.len(), 3);
        // Heights descending; block 3 and block 4 tie at height 3, then block 2 at height 2.
        assert_eq!(conflicts[0].stacks_height, 3);
        assert_eq!(conflicts[1].stacks_height, 3);
        assert_eq!(conflicts[2].stacks_height, 2);
        let tenure_2_conflict = conflicts
            .iter()
            .find(|c| c.consensus_hash == consensus_hash_2)
            .unwrap();
        assert_eq!(
            tenure_2_conflict.signer_signature_hash,
            block_info_4.block.header.signer_signature_hash()
        );
        assert_eq!(tenure_2_conflict.stacks_height, 3);
        assert_eq!(tenure_2_conflict.last_endorsed, 60);
        assert_eq!(conflicts[2].consensus_hash, consensus_hash_1);
        assert_eq!(
            conflicts[2].signer_signature_hash,
            block_info_2.block.header.signer_signature_hash()
        );
        assert_eq!(conflicts[2].last_endorsed, 100);
        // Height is a lower bound: at height 3, block 2 no longer conflicts.
        let conflicts = db.get_signed_conflicts(3, &unrelated_hash).unwrap();
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.iter().all(|c| c.stacks_height == 3));
        // The excluded (proposed) block is never its own conflict.
        let conflicts = db
            .get_signed_conflicts(3, &block_info_4.block.header.signer_signature_hash())
            .unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0].signer_signature_hash,
            block_info_3.block.header.signer_signature_hash()
        );
        assert_eq!(conflicts[0].consensus_hash, consensus_hash_1);
        assert_eq!(conflicts[0].last_endorsed, 50);
        // Above every signed block in every tenure (only the pre-committed block 5 is at
        // height 4): no conflict.
        assert!(db
            .get_signed_conflicts(4, &unrelated_hash)
            .unwrap()
            .is_empty());

        // A tenure whose reorg we permitted under the reorg-timing rules stays in the results
        // but carries the permitting tenure's sortition, so the caller can honor the permit
        // only while that sortition is still canonical. Superseding tenure 1 annotates blocks
        // 2 and 3; block 4 (tenure 2) stays unannotated.
        let permitting_ch = ConsensusHash([0x77; 20]);
        let permitting_bbh = BurnchainHeaderHash([0x88; 32]);
        assert!(!db.is_tenure_superseded(&consensus_hash_1).unwrap());
        db.mark_tenure_superseded(&consensus_hash_1, 42, &permitting_ch, &permitting_bbh)
            .unwrap();
        assert!(db.is_tenure_superseded(&consensus_hash_1).unwrap());
        assert!(db
            .has_reorg_permit(ReorgPermit {
                reorged_tenure: &consensus_hash_1,
                reorging_tenure: &permitting_ch,
            })
            .unwrap());
        // The permit names the tenure it was granted to, and no other.
        assert!(!db
            .has_reorg_permit(ReorgPermit {
                reorged_tenure: &consensus_hash_1,
                reorging_tenure: &consensus_hash_2,
            })
            .unwrap());
        assert!(!db
            .has_reorg_permit(ReorgPermit {
                reorged_tenure: &consensus_hash_2,
                reorging_tenure: &permitting_ch,
            })
            .unwrap());
        let conflicts = db.get_signed_conflicts(2, &unrelated_hash).unwrap();
        assert_eq!(conflicts.len(), 3);
        for conflict in &conflicts {
            if conflict.consensus_hash == consensus_hash_1 {
                let superseded_by = conflict.superseded_by.as_ref().unwrap();
                assert_eq!(superseded_by.consensus_hash, permitting_ch);
                assert_eq!(superseded_by.burn_block_hash, permitting_bbh);
            } else {
                assert!(conflict.superseded_by.is_none());
            }
        }

        // A re-permit by a different tenure replaces the record, so the latest permitting
        // sortition is the one carried.
        let repermitting_ch = ConsensusHash([0x79; 20]);
        let repermitting_bbh = BurnchainHeaderHash([0x8a; 32]);
        db.mark_tenure_superseded(&consensus_hash_1, 42, &repermitting_ch, &repermitting_bbh)
            .unwrap();
        let conflicts = db.get_signed_conflicts(2, &unrelated_hash).unwrap();
        let annotated = conflicts
            .iter()
            .find(|c| c.consensus_hash == consensus_hash_1)
            .unwrap();
        let superseded_by = annotated.superseded_by.as_ref().unwrap();
        assert_eq!(superseded_by.consensus_hash, repermitting_ch);
        assert_eq!(superseded_by.burn_block_hash, repermitting_bbh);
        assert!(db
            .has_reorg_permit(ReorgPermit {
                reorged_tenure: &consensus_hash_1,
                reorging_tenure: &repermitting_ch,
            })
            .unwrap());
        assert!(!db
            .has_reorg_permit(ReorgPermit {
                reorged_tenure: &consensus_hash_1,
                reorging_tenure: &permitting_ch,
            })
            .unwrap());

        db.mark_tenure_superseded(&consensus_hash_2, 43, &permitting_ch, &permitting_bbh)
            .unwrap();
        assert!(db
            .get_signed_conflicts(2, &unrelated_hash)
            .unwrap()
            .iter()
            .all(|c| c.superseded_by.is_some()));

        // Pruning only drops records for sortitions below the cutoff: tenure 1 (burn 42) goes,
        // tenure 2 (burn 43) stays, so tenure 1's blocks lose their annotation.
        db.prune_superseded_tenures(43).unwrap();
        assert!(!db.is_tenure_superseded(&consensus_hash_1).unwrap());
        assert!(!db
            .has_reorg_permit(ReorgPermit {
                reorged_tenure: &consensus_hash_1,
                reorging_tenure: &repermitting_ch,
            })
            .unwrap());
        assert!(db.is_tenure_superseded(&consensus_hash_2).unwrap());
        let conflicts = db.get_signed_conflicts(2, &unrelated_hash).unwrap();
        assert_eq!(conflicts.len(), 3);
        for conflict in &conflicts {
            assert_eq!(
                conflict.superseded_by.is_some(),
                conflict.consensus_hash == consensus_hash_2
            );
        }

        // Rejection does not clear a conflict: the signature over block 3 is public and can
        // still be aggregated toward the 70% threshold if rejecting signers change their
        // minds, so it keeps conflicting even once globally rejected. The tip question is
        // different: a rejected block is no longer the tenure's signed tip.
        block_info_3.mark_globally_rejected().unwrap();
        db.insert_block(&block_info_3).unwrap();
        let conflicts = db.get_signed_conflicts(2, &unrelated_hash).unwrap();
        assert_eq!(conflicts.len(), 3);
        assert!(conflicts.iter().any(|c| {
            c.signer_signature_hash == block_info_3.block.header.signer_signature_hash()
                && !c.globally_accepted
        }));
        let tip = db
            .get_last_signed_block(&consensus_hash_1, None)
            .unwrap()
            .unwrap();
        assert_eq!(tip, block_info_2);
    }

    fn generate_tenure_blocks() -> Vec<BlockInfo> {
        let tenure_change_payload = TenureChangePayload {
            tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
            prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
            burn_view_consensus_hash: ConsensusHash([0x04; 20]),
            previous_tenure_end: StacksBlockId([0x03; 32]),
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160::from_node_public_key(&StacksPublicKey::from_private(
                &StacksPrivateKey::random(),
            )),
        };
        let tenure_change_tx_payload = TransactionPayload::TenureChange(tenure_change_payload);
        let tenure_change_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&StacksPrivateKey::random()).unwrap(),
            tenure_change_tx_payload,
        );

        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });
        block_info_1.state = BlockState::GloballyAccepted;
        block_info_1
            .block
            .executed_and_skipped_txs_mut()
            .push(tenure_change_tx.clone());
        block_info_1.validation_time_ms = Some(1000);
        block_info_1.proposed_time = get_epoch_time_secs() + 500;

        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });
        block_info_2.state = BlockState::GloballyAccepted;
        block_info_2.validation_time_ms = Some(2000);
        block_info_2.proposed_time = block_info_1.proposed_time + 5;

        let (mut block_info_3, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 2;
        });
        block_info_3.state = BlockState::GloballyAccepted;
        block_info_3
            .block
            .executed_and_skipped_txs_mut()
            .push(tenure_change_tx);
        block_info_3.validation_time_ms = Some(5000);
        block_info_3.proposed_time = block_info_1.proposed_time + 10;

        // This should have no effect on the time calculations as its not a globally accepted block
        let (mut block_info_4, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x04; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 2;
        });
        block_info_4.state = BlockState::LocallyAccepted;
        block_info_4.validation_time_ms = Some(9000);
        block_info_4.proposed_time = block_info_1.proposed_time + 15;

        let (mut block_info_5, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2.clone();
            b.block.header.miner_signature = MessageSignature([0x05; 65]);
            b.block.header.chain_length = 4;
            b.burn_height = 3;
        });
        block_info_5.state = BlockState::GloballyAccepted;
        block_info_5.validation_time_ms = Some(20000);
        block_info_5.proposed_time = block_info_1.proposed_time + 20;

        // This should have no effect on the time calculations as its not a globally accepted block
        let (mut block_info_6, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2;
            b.block.header.miner_signature = MessageSignature([0x06; 65]);
            b.block.header.chain_length = 5;
            b.burn_height = 3;
        });
        block_info_6.state = BlockState::LocallyAccepted;
        block_info_6.validation_time_ms = Some(40000);
        block_info_6.proposed_time = block_info_1.proposed_time + 25;

        vec![
            block_info_1,
            block_info_2,
            block_info_3,
            block_info_4,
            block_info_5,
            block_info_6,
        ]
    }

    #[test]
    fn tenure_times() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let block_infos = generate_tenure_blocks();
        let consensus_hash_1 = &block_infos[0].block.header.consensus_hash;
        let consensus_hash_2 = &block_infos.last().unwrap().block.header.consensus_hash;
        let consensus_hash_3 = ConsensusHash([0x03; 20]);

        db.insert_block(&block_infos[0]).unwrap();
        db.insert_block(&block_infos[1]).unwrap();

        let change_match = |change_cause| {
            matches!(
                change_cause,
                TenureChangeCause::BlockFound | TenureChangeCause::Extended
            )
        };

        // Verify tenure consensus_hash_1
        let (start_time, processing_time) =
            db.get_tenure_times(consensus_hash_1, change_match).unwrap();
        assert_eq!(start_time, block_infos[0].proposed_time);
        assert_eq!(processing_time, 3000);

        db.insert_block(&block_infos[2]).unwrap();
        db.insert_block(&block_infos[3]).unwrap();

        let (start_time, processing_time) =
            db.get_tenure_times(consensus_hash_1, change_match).unwrap();
        assert_eq!(start_time, block_infos[2].proposed_time);
        assert_eq!(processing_time, 5000);

        db.insert_block(&block_infos[4]).unwrap();
        db.insert_block(&block_infos[5]).unwrap();

        // Verify tenure consensus_hash_2
        let (start_time, processing_time) =
            db.get_tenure_times(consensus_hash_2, change_match).unwrap();
        assert_eq!(start_time, block_infos[4].proposed_time);
        assert_eq!(processing_time, 20000);

        // Verify tenure consensus_hash_3 (unknown hash)
        let (start_time, validation_time) = db
            .get_tenure_times(&consensus_hash_3, change_match)
            .unwrap();
        assert!(start_time < block_infos[0].proposed_time, "Should have been generated from get_epoch_time_secs() making it much older than our artificially late proposal times");
        assert_eq!(validation_time, 0);
    }

    #[test]
    fn tenure_extend_timestamp() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_infos = generate_tenure_blocks();
        let mut unknown_block = block_infos[0].block.clone();
        unknown_block.header.consensus_hash = ConsensusHash([0x03; 20]);

        db.insert_block(&block_infos[0]).unwrap();
        db.insert_block(&block_infos[1]).unwrap();

        let tenure_idle_timeout = Duration::from_secs(10);
        // Verify tenure consensus_hash_1
        let timestamp_hash_1_before =
            db.calculate_full_extend_timestamp(tenure_idle_timeout, &block_infos[0].block, true);
        assert_eq!(
            timestamp_hash_1_before,
            block_infos[0]
                .proposed_time
                .saturating_add(tenure_idle_timeout.as_secs())
                .saturating_add(3)
        );

        db.insert_block(&block_infos[2]).unwrap();
        db.insert_block(&block_infos[3]).unwrap();

        let timestamp_hash_1_after =
            db.calculate_full_extend_timestamp(tenure_idle_timeout, &block_infos[0].block, true);

        assert_eq!(
            timestamp_hash_1_after,
            block_infos[2]
                .proposed_time
                .saturating_add(tenure_idle_timeout.as_secs())
                .saturating_add(5)
        );

        db.insert_block(&block_infos[4]).unwrap();
        db.insert_block(&block_infos[5]).unwrap();

        // Verify tenure consensus_hash_2
        let timestamp_hash_2 = db.calculate_full_extend_timestamp(
            tenure_idle_timeout,
            &block_infos.last().unwrap().block,
            true,
        );
        assert_eq!(
            timestamp_hash_2,
            block_infos[4]
                .proposed_time
                .saturating_add(tenure_idle_timeout.as_secs())
                .saturating_add(20)
        );

        let now = get_epoch_time_secs().saturating_add(tenure_idle_timeout.as_secs());
        let timestamp_hash_2_no_tenure_extend =
            db.calculate_full_extend_timestamp(tenure_idle_timeout, &block_infos[0].block, false);
        assert_ne!(timestamp_hash_2, timestamp_hash_2_no_tenure_extend);
        assert!(now < timestamp_hash_2_no_tenure_extend);

        // Verify tenure consensus_hash_3 (unknown hash)
        let timestamp_hash_3 =
            db.calculate_full_extend_timestamp(tenure_idle_timeout, &unknown_block, true);
        assert!(
            timestamp_hash_3.saturating_add(tenure_idle_timeout.as_secs())
                < block_infos[0].proposed_time
        );

        // Tenure extend blocks (an Extended* tenure change with no coinbase) must roll the
        // timestamp over to now + idle timeout instead of deriving it from the globally
        // accepted blocks in the tenure, which at this point only reach the previous extend
        let consensus_hash_1 = block_infos[0].block.header.consensus_hash.clone();
        let extend_block = |cause| {
            let parent_block_id = StacksBlockId([0x05; 32]);
            let payload = TenureChangePayload {
                tenure_consensus_hash: consensus_hash_1.clone(),
                prev_tenure_consensus_hash: consensus_hash_1.clone(),
                burn_view_consensus_hash: consensus_hash_1.clone(),
                previous_tenure_end: parent_block_id.clone(),
                previous_tenure_blocks: 1,
                cause,
                pubkey_hash: Hash160([0x06; 20]),
            };
            let tx = StacksTransaction::new(
                TransactionVersion::Testnet,
                TransactionAuth::from_p2pkh(&StacksPrivateKey::random()).unwrap(),
                TransactionPayload::TenureChange(payload),
            );
            let (mut block_info, _block_proposal) = create_block_override(|b| {
                b.block.header.consensus_hash = consensus_hash_1.clone();
                b.block.header.parent_block_id = parent_block_id;
            });
            block_info.block.executed_and_skipped_txs_mut().push(tx);
            block_info.block
        };
        let assert_rolled_over = |timestamp: u64, before: u64| {
            let after = get_epoch_time_secs();
            assert!(
                timestamp >= before.saturating_add(tenure_idle_timeout.as_secs())
                    && timestamp <= after.saturating_add(tenure_idle_timeout.as_secs()),
                "Expected timestamp {timestamp} to be rolled over to now + idle timeout"
            );
        };

        let full_extend_block = extend_block(TenureChangeCause::Extended);
        let before = get_epoch_time_secs();
        assert_rolled_over(
            db.calculate_full_extend_timestamp(tenure_idle_timeout, &full_extend_block, true),
            before,
        );
        assert_rolled_over(
            db.calculate_read_count_extend_timestamp(tenure_idle_timeout, &full_extend_block, true),
            before,
        );
        // Rejections must not roll over, even for an extend block
        assert_eq!(
            db.calculate_full_extend_timestamp(tenure_idle_timeout, &full_extend_block, false),
            timestamp_hash_1_after
        );

        // A read count extend rolls over the read count timestamp only
        let read_count_extend_block = extend_block(TenureChangeCause::ExtendedReadCount);
        let before = get_epoch_time_secs();
        assert_rolled_over(
            db.calculate_read_count_extend_timestamp(
                tenure_idle_timeout,
                &read_count_extend_block,
                true,
            ),
            before,
        );
        assert_eq!(
            db.calculate_full_extend_timestamp(tenure_idle_timeout, &read_count_extend_block, true),
            timestamp_hash_1_after
        );
    }

    #[test]
    fn test_get_and_remove_pending_block_validation() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let pending_hash = db.get_and_remove_pending_block_validation().unwrap();
        assert!(pending_hash.is_none());

        db.insert_pending_block_validation(&Sha512Trunc256Sum([0x01; 32]), 1000)
            .unwrap();
        db.insert_pending_block_validation(&Sha512Trunc256Sum([0x02; 32]), 2000)
            .unwrap();
        db.insert_pending_block_validation(&Sha512Trunc256Sum([0x03; 32]), 3000)
            .unwrap();

        let (pending_hash, _) = db
            .get_and_remove_pending_block_validation()
            .unwrap()
            .unwrap();
        assert_eq!(pending_hash, Sha512Trunc256Sum([0x01; 32]));

        let pendings = db.get_all_pending_block_validations().unwrap();
        assert_eq!(pendings.len(), 2);

        let (pending_hash, _) = db
            .get_and_remove_pending_block_validation()
            .unwrap()
            .unwrap();
        assert_eq!(pending_hash, Sha512Trunc256Sum([0x02; 32]));

        let pendings = db.get_all_pending_block_validations().unwrap();
        assert_eq!(pendings.len(), 1);

        let (pending_hash, _) = db
            .get_and_remove_pending_block_validation()
            .unwrap()
            .unwrap();
        assert_eq!(pending_hash, Sha512Trunc256Sum([0x03; 32]));

        let pendings = db.get_all_pending_block_validations().unwrap();
        assert!(pendings.is_empty());
    }

    #[test]
    fn check_globally_signed_block_count() {
        let db_path = tmp_db_path();
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, _) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
        });

        assert!(matches!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            0
        ));

        // locally accepted still returns 0
        block_info.mark_locally_accepted(false).unwrap();
        block_info.block.header.chain_length = 1;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            0
        );

        block_info.mark_globally_accepted().unwrap();
        block_info.block.header.chain_length = 2;
        db.insert_block(&block_info).unwrap();

        block_info.block.header.chain_length = 3;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            2
        );

        // add an unsigned block
        block_info.signed_group = None;
        block_info.block.header.chain_length = 4;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            3
        );

        // add a locally signed block
        block_info.state = BlockState::LocallyAccepted;
        block_info.block.header.chain_length = 5;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            3
        );
    }

    #[test]
    fn has_approved_block() {
        let db_path = tmp_db_path();
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, _) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.chain_length = 1;
        });

        assert!(!db.has_approved_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_approved_block_in_tenure(&consensus_hash_2).unwrap());

        block_info.mark_pre_committed().unwrap();
        db.insert_block(&block_info).unwrap();

        assert!(db.has_approved_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_approved_block_in_tenure(&consensus_hash_2).unwrap());

        block_info.block.header.consensus_hash = consensus_hash_2.clone();
        block_info.block.header.chain_length = 2;
        block_info.approved_time = None;

        db.insert_block(&block_info).unwrap();

        assert!(db.has_approved_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_approved_block_in_tenure(&consensus_hash_2).unwrap());

        block_info.signed_self = Some(get_epoch_time_secs());

        db.insert_block(&block_info).unwrap();

        assert!(db.has_approved_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(db.has_approved_block_in_tenure(&consensus_hash_2).unwrap());
    }

    #[test]
    fn has_signed_block() {
        let db_path = tmp_db_path();
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, _) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.chain_length = 1;
        });

        assert!(!db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        // A pre-commit sets `approved_time` but puts no signature over the block, so it must
        // not count as a signed block. This is the regression: treating it as signed suppressed
        // the miner inactivity timeout and stalled the tenure.
        block_info.mark_pre_committed().unwrap();
        db.insert_block(&block_info).unwrap();

        assert!(db.has_approved_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        // Signing it locally does count.
        block_info.mark_locally_accepted(false).unwrap();
        db.insert_block(&block_info).unwrap();

        assert!(db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        // A block signed by the group in another tenure counts for that tenure only.
        block_info.block.header.consensus_hash = consensus_hash_2.clone();
        block_info.block.header.chain_length = 2;
        block_info.signed_self = None;
        block_info.signed_group = None;
        block_info.approved_time = None;
        db.insert_block(&block_info).unwrap();

        assert!(!db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        block_info.signed_group = Some(get_epoch_time_secs());
        db.insert_block(&block_info).unwrap();

        assert!(db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        // Global rejection does not clear the commitment: a rejection is a revocable opinion,
        // while the signature is public and can still be aggregated toward the 70% threshold
        // if enough rejecting signers change their minds. The block must keep counting.
        block_info.mark_globally_rejected().unwrap();
        db.insert_block(&block_info).unwrap();

        assert!(db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());
    }

    #[test]
    fn update_last_activity() {
        let db_path = tmp_db_path();
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        assert!(db
            .get_last_activity_time(&consensus_hash_1)
            .unwrap()
            .is_none());
        assert!(db
            .get_last_activity_time(&consensus_hash_2)
            .unwrap()
            .is_none());

        let time = get_epoch_time_secs();
        db.update_last_activity_time(&consensus_hash_1, time)
            .unwrap();
        let retrieved_time = db
            .get_last_activity_time(&consensus_hash_1)
            .unwrap()
            .unwrap();
        assert_eq!(time, retrieved_time);
        assert!(db
            .get_last_activity_time(&consensus_hash_2)
            .unwrap()
            .is_none());
    }

    /// BlockInfo without the `reject_reason` or `approved_time` field for backwards compatibility testing
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct BlockInfoPrev {
        /// The block we are considering
        pub block: NakamotoBlock,
        /// The burn block height at which the block was proposed
        pub burn_block_height: u64,
        /// The reward cycle the block belongs to
        pub reward_cycle: u64,
        /// Our vote on the block if we have one yet
        pub vote: Option<NakamotoBlockVote>,
        /// Whether the block contents are valid
        pub valid: Option<bool>,
        /// Whether this block is already being signed over
        pub signed_over: bool,
        /// Time at which the proposal was received by this signer (epoch time in seconds)
        pub proposed_time: u64,
        /// Time at which the proposal was signed by this signer (epoch time in seconds)
        pub signed_self: Option<u64>,
        /// Time at which the proposal was signed by a threshold in the signer set (epoch time in seconds)
        pub signed_group: Option<u64>,
        /// The block state relative to the signer's view of the stacks blockchain
        pub state: BlockState,
        /// Consumed processing time in milliseconds to validate this block
        pub validation_time_ms: Option<u64>,
        /// Extra data specific to v0, v1, etc.
        pub ext: ExtraBlockInfo,
    }

    /// Verify that we can deserialize the old BlockInfo struct into the new version
    #[test]
    fn deserialize_old_block_info() {
        let block_info_prev = BlockInfoPrev {
            block: NakamotoBlock::new(NakamotoBlockHeader::genesis(), vec![]),
            burn_block_height: 2,
            reward_cycle: 3,
            vote: None,
            valid: None,
            signed_over: true,
            proposed_time: 4,
            signed_self: None,
            signed_group: None,
            state: BlockState::Unprocessed,
            validation_time_ms: Some(5),
            ext: ExtraBlockInfo::default(),
        };

        let block_info: BlockInfo =
            serde_json::from_value(serde_json::to_value(&block_info_prev).unwrap()).unwrap();
        assert_eq!(block_info.block, block_info_prev.block);
        assert_eq!(
            block_info.burn_block_height,
            block_info_prev.burn_block_height
        );
        assert_eq!(block_info.reward_cycle, block_info_prev.reward_cycle);
        assert_eq!(block_info.vote, block_info_prev.vote);
        assert_eq!(block_info.valid, block_info_prev.valid);
        assert_eq!(block_info.proposed_time, block_info_prev.proposed_time);
        assert_eq!(block_info.approved_time, block_info_prev.signed_self);
        assert_eq!(block_info.signed_self, block_info_prev.signed_self);
        assert_eq!(block_info.signed_group, block_info_prev.signed_group);
        assert_eq!(block_info.state, block_info_prev.state);
        assert_eq!(
            block_info.validation_time_ms,
            block_info_prev.validation_time_ms
        );
        assert_eq!(block_info.ext, block_info_prev.ext);
        assert!(block_info.reject_reason.is_none());
    }

    #[test]
    fn insert_and_get_state_machine_updates() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let reward_cycle_1 = 1;
        let address_1 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_1 = StateMachineUpdate::new(
            0,
            3,
            StateMachineUpdateContent::V0 {
                burn_block: ConsensusHash([0x55; 20]),
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::ActiveMiner {
                    current_miner_pkh: Hash160([0xab; 20]),
                    tenure_id: ConsensusHash([0x44; 20]),
                    parent_tenure_id: ConsensusHash([0x22; 20]),
                    parent_tenure_last_block: StacksBlockId([0x33; 32]),
                    parent_tenure_last_block_height: 1,
                },
            },
        )
        .unwrap();

        let address_2 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_2 = StateMachineUpdate::new(
            0,
            4,
            StateMachineUpdateContent::V0 {
                burn_block: ConsensusHash([0x55; 20]),
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        let address_3 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_3 = StateMachineUpdate::new(
            0,
            2,
            StateMachineUpdateContent::V0 {
                burn_block: ConsensusHash([0x66; 20]),
                burn_block_height: 101,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        assert!(
            db.get_signer_state_machine_updates(reward_cycle_1)
                .unwrap()
                .is_empty(),
            "The database should be empty for reward_cycle {reward_cycle_1}"
        );

        db.insert_state_machine_update(reward_cycle_1, &address_1, &update_1, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(reward_cycle_1, &address_2, &update_2, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(
            reward_cycle_1 + 1,
            &address_3,
            &update_3,
            &SystemTime::now(),
        )
        .expect("Unable to insert block into db");

        let updates = db.get_signer_state_machine_updates(reward_cycle_1).unwrap();
        assert_eq!(updates.len(), 2);

        assert_eq!(updates.get(&address_1), Some(&update_1));
        assert_eq!(updates.get(&address_2), Some(&update_2));
        assert_eq!(updates.get(&address_3), None);

        db.insert_state_machine_update(reward_cycle_1, &address_2, &update_3, &SystemTime::now())
            .expect("Unable to insert block into db");
        let updates = db.get_signer_state_machine_updates(reward_cycle_1).unwrap();
        assert_eq!(updates.len(), 2);

        assert_eq!(updates.get(&address_1), Some(&update_1));
        assert_eq!(updates.get(&address_2), Some(&update_3));
        assert_eq!(updates.get(&address_3), None);

        let updates = db
            .get_signer_state_machine_updates(reward_cycle_1 + 1)
            .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates.get(&address_1), None);
        assert_eq!(updates.get(&address_2), None);
        assert_eq!(updates.get(&address_3), Some(&update_3));
    }

    #[test]
    fn burn_state_migration_consensus_hash_primary_key() {
        // Construct the old table
        let conn = rusqlite::Connection::open_in_memory().expect("Failed to create in mem db");
        conn.execute_batch(CREATE_BURN_STATE_TABLE)
            .expect("Failed to create old table");
        conn.execute_batch(ADD_CONSENSUS_HASH)
            .expect("Failed to add consensus hash to old table");
        conn.execute_batch(ADD_CONSENSUS_HASH_INDEX)
            .expect("Failed to add consensus hash index to old table");

        let consensus_hash = ConsensusHash([0; 20]);
        let total_nmb_rows = 5;
        // Fill with old data with conflicting consensus hashes
        for i in 0..=total_nmb_rows {
            let now = SystemTime::now();
            let received_ts = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let burn_hash = BurnchainHeaderHash([i; 32]);
            let burn_height = i;
            if i % 2 == 0 {
                // Make sure we have some one empty consensus hash options that will get dropped
                conn.execute(
                    "INSERT OR REPLACE INTO burn_blocks (block_hash, block_height, received_time) VALUES (?1, ?2, ?3)",
                    params![
                        burn_hash,
                        u64_to_sql(burn_height.into()).unwrap(),
                        u64_to_sql(received_ts + i as u64).unwrap(), // Ensure increasing received_time
                    ]
                ).unwrap();
            } else {
                conn.execute(
                    "INSERT OR REPLACE INTO burn_blocks (block_hash, consensus_hash, block_height, received_time) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        burn_hash,
                        consensus_hash,
                        u64_to_sql(burn_height.into()).unwrap(),
                        u64_to_sql(received_ts + i as u64).unwrap(), // Ensure increasing received_time
                    ]
                ).unwrap();
            };
        }

        // Migrate the data and make sure that the primary key conflict is resolved by using the last received time
        // and that the block height and consensus hash of the surviving row is as expected
        conn.execute_batch(MIGRATE_BURN_STATE_TABLE_1_TO_TABLE_2)
            .expect("Failed to migrate data");
        let migrated_count: u64 = conn
            .query_row("SELECT COUNT(*) FROM burn_blocks;", [], |row| row.get(0))
            .expect("Failed to get row count");

        assert_eq!(
            migrated_count, 1,
            "Expected exactly one row after migration"
        );

        let (block_height, hex_hash): (u64, String) = conn
            .query_row(
                "SELECT block_height, consensus_hash FROM burn_blocks;",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("Failed to get block_height and consensus_hash");

        assert_eq!(
            block_height, total_nmb_rows as u64,
            "Expected block_height {total_nmb_rows} to be retained (has the latest received time)"
        );

        assert_eq!(
            hex_hash,
            consensus_hash.to_hex(),
            "Expected the surviving row to have the correct consensus_hash"
        );
    }

    #[test]
    fn check_burn_block_received_time_from_signers() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let reward_cycle_1 = 1;
        let local_address = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let address_1 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let burn_block_1 = ConsensusHash([0x55; 20]);
        let burn_block_2 = ConsensusHash([0x66; 20]);
        let update_1 = StateMachineUpdate::new(
            0,
            3,
            StateMachineUpdateContent::V0 {
                burn_block: burn_block_1.clone(),
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::ActiveMiner {
                    current_miner_pkh: Hash160([0xab; 20]),
                    tenure_id: ConsensusHash([0x44; 20]),
                    parent_tenure_id: ConsensusHash([0x22; 20]),
                    parent_tenure_last_block: StacksBlockId([0x33; 32]),
                    parent_tenure_last_block_height: 1,
                },
            },
        )
        .unwrap();

        let address_2 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_2 = StateMachineUpdate::new(
            0,
            4,
            StateMachineUpdateContent::V0 {
                burn_block: burn_block_1.clone(),
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        let address_3 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_3 = StateMachineUpdate::new(
            0,
            2,
            StateMachineUpdateContent::V0 {
                burn_block: burn_block_2.clone(),
                burn_block_height: 101,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        let mut address_weights = HashMap::new();
        address_weights.insert(local_address.clone(), 10);
        address_weights.insert(address_1.clone(), 10);
        address_weights.insert(address_2.clone(), 10);
        address_weights.insert(address_3.clone(), 10);
        let eval = GlobalStateEvaluator::new(HashMap::new(), address_weights);

        assert!(db
            .get_burn_block_received_time_from_signers(&eval, &burn_block_1, &local_address)
            .unwrap()
            .is_none());

        db.insert_state_machine_update(reward_cycle_1, &address_1, &update_1, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(reward_cycle_1, &address_2, &update_2, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(reward_cycle_1, &address_3, &update_3, &SystemTime::now())
            .expect("Unable to insert block into db");
        assert!(db
            .get_burn_block_received_time_from_signers(&eval, &burn_block_1, &local_address)
            .unwrap()
            .is_none());

        let burn_hash = BurnchainHeaderHash([10; 32]);
        let stime = SystemTime::now() + Duration::from_secs(30);
        let time_to_epoch = stime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        db.insert_burn_block(
            &burn_hash,
            &burn_block_1,
            101,
            &stime,
            &BurnchainHeaderHash([11; 32]),
        )
        .unwrap();
        assert_eq!(
            time_to_epoch,
            db.get_burn_block_received_time_from_signers(&eval, &burn_block_1, &local_address)
                .unwrap()
                .unwrap()
        );
        assert!(db
            .get_burn_block_received_time_from_signers(&eval, &burn_block_2, &local_address)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_get_last_globally_accepted_block_approved_time() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);

        // Create blocks with different burn heights and approved_time (seconds since epoch)
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });
        block_info_1.mark_pre_committed().unwrap();
        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1.clone();
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });
        block_info_2.mark_locally_accepted(false).unwrap();
        let (mut block_info_3, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2.clone();
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 3;
        });
        block_info_3.mark_locally_accepted(false).unwrap();

        // Mark only one of the blocks as globally accepted
        block_info_1.mark_globally_accepted().unwrap();

        // Insert into db
        db.insert_block(&block_info_1).unwrap();
        db.insert_block(&block_info_2).unwrap();
        db.insert_block(&block_info_3).unwrap();

        // Query for consensus_hash_1 should return approved_time of block_info_2 (highest burn_height)
        db.get_last_globally_accepted_approved_time(&consensus_hash_1)
            .unwrap()
            .expect("Expected a approved_time timestamp");

        // Query for consensus_hash_2 should return none since we only contributed to a locally signed block
        let result_2 = db
            .get_last_globally_accepted_approved_time(&consensus_hash_2)
            .unwrap();

        assert!(result_2.is_none());

        // Query for a consensus hash with no blocks should return None
        let consensus_hash_3 = ConsensusHash([0x03; 20]);
        let result_3 = db
            .get_last_globally_accepted_approved_time(&consensus_hash_3)
            .unwrap();

        assert!(result_3.is_none());
    }

    #[test]
    fn insert_and_get_state_block_pre_commits() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        let block_sighash1 = Sha512Trunc256Sum([1u8; 32]);
        let address1 = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );
        let block_sighash2 = Sha512Trunc256Sum([2u8; 32]);
        let address2 = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );
        let address3 = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );
        assert!(db
            .get_block_pre_committers(&block_sighash1)
            .unwrap()
            .is_empty());

        db.add_block_pre_commit(&block_sighash1, &address1).unwrap();
        assert_eq!(
            db.get_block_pre_committers(&block_sighash1).unwrap(),
            vec![address1.clone()]
        );

        db.add_block_pre_commit(&block_sighash1, &address2).unwrap();
        let commits = db.get_block_pre_committers(&block_sighash1).unwrap();
        assert_eq!(commits.len(), 2);
        assert!(commits.contains(&address2));
        assert!(commits.contains(&address1));

        db.add_block_pre_commit(&block_sighash2, &address3).unwrap();
        let commits = db.get_block_pre_committers(&block_sighash1).unwrap();
        assert_eq!(commits.len(), 2);
        assert!(commits.contains(&address2));
        assert!(commits.contains(&address1));
        let commits = db.get_block_pre_committers(&block_sighash2).unwrap();
        assert_eq!(commits.len(), 1);
        assert!(commits.contains(&address3));

        assert!(db.has_committed(&block_sighash1, &address1).unwrap());
        assert!(db.has_committed(&block_sighash1, &address2).unwrap());
        assert!(!db.has_committed(&block_sighash1, &address3).unwrap());
        assert!(!db.has_committed(&block_sighash2, &address1).unwrap());
        assert!(!db.has_committed(&block_sighash2, &address2).unwrap());
        assert!(db.has_committed(&block_sighash2, &address3).unwrap());
    }

    #[test]
    fn test_signer_pre_commit_responses_eviction() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let signer = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );

        // Create 5 different block hashes
        let blocks: Vec<Sha512Trunc256Sum> =
            (0..5).map(|i| Sha512Trunc256Sum([i as u8; 32])).collect();

        // Add first 3 pre-commits from same signer for different blocks
        for block in blocks.iter().take(3) {
            db.add_pending_block_pre_commit_response(block, &signer)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // Check block 0 has the signer
        let responses = get_pending_pre_commit_responses(&db, &blocks[0]).unwrap();
        assert_eq!(responses.len(), 1, "Should have 1 signer for block 0");
        assert!(responses.contains(&signer));

        // Add 4th pre-commit from same signer to a different block - should evict oldest
        db.add_pending_block_pre_commit_response(&blocks[3], &signer)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Block 0 should now be evicted (oldest per signer)
        let responses = get_pending_pre_commit_responses(&db, &blocks[0]).unwrap();
        assert_eq!(
            responses.len(),
            0,
            "Block 0 should be evicted (oldest per signer)"
        );

        // Blocks 1, 2, 3 should still have the signer
        let responses = get_pending_pre_commit_responses(&db, &blocks[1]).unwrap();
        assert_eq!(responses.len(), 1, "Block 1 should have the signer");
        assert!(responses.contains(&signer));

        let responses = get_pending_pre_commit_responses(&db, &blocks[2]).unwrap();
        assert_eq!(responses.len(), 1, "Block 2 should have the signer");

        let responses = get_pending_pre_commit_responses(&db, &blocks[3]).unwrap();
        assert_eq!(responses.len(), 1, "Block 3 should have the signer");

        // Add 5th pre-commit - should evict block 1 now
        db.add_pending_block_pre_commit_response(&blocks[4], &signer)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Block 1 should now be evicted
        let responses = get_pending_pre_commit_responses(&db, &blocks[1]).unwrap();
        assert_eq!(responses.len(), 0, "Block 1 should be evicted");

        // Blocks 2, 3, 4 should still have the signer
        let responses = get_pending_pre_commit_responses(&db, &blocks[2]).unwrap();
        assert_eq!(responses.len(), 1, "Block 2 should have the signer");

        let responses = get_pending_pre_commit_responses(&db, &blocks[3]).unwrap();
        assert_eq!(responses.len(), 1, "Block 3 should have the signer");

        let responses = get_pending_pre_commit_responses(&db, &blocks[4]).unwrap();
        assert_eq!(responses.len(), 1, "Block 4 should have the signer");
    }

    #[test]
    fn test_signer_signature_responses_eviction() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let signer_key = StacksPrivateKey::random();
        let signer_addr = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(&signer_key));

        // Create 5 different block hashes
        let blocks: Vec<Sha512Trunc256Sum> =
            (0..5).map(|i| Sha512Trunc256Sum([i as u8; 32])).collect();

        // Create valid signatures by signing each block hash
        let signatures: Vec<MessageSignature> = blocks
            .iter()
            .map(|hash| signer_key.sign(&hash.0).unwrap())
            .collect();

        // Add first 3 signatures from same signer for different blocks
        for (block, sig) in blocks.iter().take(3).zip(signatures.iter().take(3)) {
            db.add_pending_block_signature_response(block, &signer_addr, sig)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // Check block 0 has the signature
        let responses = get_pending_signature_responses(&db, &blocks[0]).unwrap();
        assert_eq!(responses.len(), 1, "Should have 1 signature for block 0");
        assert!(responses.contains(&signatures[0]));

        // Add 4th signature from same signer to a different block - should evict oldest
        db.add_pending_block_signature_response(&blocks[3], &signer_addr, &signatures[3])
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Block 0 should now be evicted (oldest per signer)
        let responses = get_pending_signature_responses(&db, &blocks[0]).unwrap();
        assert_eq!(
            responses.len(),
            0,
            "Block 0 should be evicted (oldest per signer)"
        );

        // Blocks 1, 2, 3 should still have the signature
        let responses = get_pending_signature_responses(&db, &blocks[1]).unwrap();
        assert_eq!(responses.len(), 1, "Block 1 should have the signature");
        assert!(responses.contains(&signatures[1]));

        // Add 5th signature - should evict block 1 now
        db.add_pending_block_signature_response(&blocks[4], &signer_addr, &signatures[4])
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Block 1 should now be evicted
        let responses = get_pending_signature_responses(&db, &blocks[1]).unwrap();
        assert_eq!(responses.len(), 0, "Block 1 should be evicted");

        // Blocks 2, 3, 4 should still have the signatures
        let responses = get_pending_signature_responses(&db, &blocks[2]).unwrap();
        assert_eq!(responses.len(), 1, "Block 2 should have the signature");

        let responses = get_pending_signature_responses(&db, &blocks[3]).unwrap();
        assert_eq!(responses.len(), 1, "Block 3 should have the signature");

        let responses = get_pending_signature_responses(&db, &blocks[4]).unwrap();
        assert_eq!(responses.len(), 1, "Block 4 should have the signature");
    }

    #[test]
    fn test_signer_rejection_responses_eviction() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let signer_addr = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );

        // Create 5 different block hashes
        let blocks: Vec<Sha512Trunc256Sum> =
            (0..5).map(|i| Sha512Trunc256Sum([i as u8; 32])).collect();

        // Add first 3 rejections from the same signer to different blocks
        for (i, block) in blocks.iter().enumerate().take(3) {
            db.add_pending_block_rejection_response(
                block,
                &signer_addr,
                RejectReasonPrefix::from(i as u8),
            )
            .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // Query block 0 - should have rejection from this signer
        let responses = get_pending_rejection_responses(&db, &blocks[0]).unwrap();
        assert_eq!(
            responses.len(),
            1,
            "Should have 1 rejection entry for block 0"
        );
        assert_eq!(responses[0].0, signer_addr);

        // Add 4th rejection from same signer to a different block - should trigger eviction
        db.add_pending_block_rejection_response(
            &blocks[3],
            &signer_addr,
            RejectReasonPrefix::from(3),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Query block 0 - should now be evicted (oldest)
        let responses = get_pending_rejection_responses(&db, &blocks[0]).unwrap();
        assert_eq!(
            responses.len(),
            0,
            "Block 0 rejection should be evicted (oldest per signer)"
        );

        // Query block 1 - should still exist
        let responses = get_pending_rejection_responses(&db, &blocks[1]).unwrap();
        assert_eq!(responses.len(), 1, "Block 1 rejection should still exist");

        // Query block 3 - should exist (newest)
        let responses = get_pending_rejection_responses(&db, &blocks[3]).unwrap();
        assert_eq!(responses.len(), 1, "Block 3 rejection should exist");

        // Add 5th rejection from same signer - should evict block 1 now
        db.add_pending_block_rejection_response(
            &blocks[4],
            &signer_addr,
            RejectReasonPrefix::from(4),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Query block 1 - should now be evicted
        let responses = get_pending_rejection_responses(&db, &blocks[1]).unwrap();
        assert_eq!(responses.len(), 0, "Block 1 rejection should be evicted");

        // Query block 2, 3, 4 - should still exist
        let responses = get_pending_rejection_responses(&db, &blocks[2]).unwrap();
        assert_eq!(responses.len(), 1, "Block 2 rejection should exist");

        let responses = get_pending_rejection_responses(&db, &blocks[3]).unwrap();
        assert_eq!(responses.len(), 1, "Block 3 rejection should exist");

        let responses = get_pending_rejection_responses(&db, &blocks[4]).unwrap();
        assert_eq!(responses.len(), 1, "Block 4 rejection should exist");
    }

    #[test]
    fn test_multiple_signers_independent_eviction() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        // Create 2 different signers
        let signer1 = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );
        let signer2 = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );

        // Create 5 different blocks
        let blocks: Vec<Sha512Trunc256Sum> =
            (0..5).map(|i| Sha512Trunc256Sum([i as u8; 32])).collect();

        // Signer1: Add 4 pre-commits for different blocks
        for block in blocks.iter().take(4) {
            db.add_pending_block_pre_commit_response(block, &signer1)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // Signer2: Add 2 pre-commits for different blocks
        for block in blocks.iter().take(2) {
            db.add_pending_block_pre_commit_response(block, &signer2)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // Signer1 should have evicted block 0 (oldest of 4)
        let responses = get_pending_pre_commit_responses(&db, &blocks[0]).unwrap();
        assert!(
            !responses.contains(&signer1),
            "Signer1 should be evicted from block 0 (oldest per signer)"
        );
        assert!(
            responses.contains(&signer2),
            "Signer2 should still be in block 0"
        );

        // Block 1 should have both signers
        let responses = get_pending_pre_commit_responses(&db, &blocks[1]).unwrap();
        assert!(responses.contains(&signer1), "Signer1 should be in block 1");
        assert!(responses.contains(&signer2), "Signer2 should be in block 1");

        // Signer2 should still have 2 entries (no eviction)
        let responses = get_pending_pre_commit_responses(&db, &blocks[2]).unwrap();
        assert!(responses.contains(&signer1), "Signer1 should be in block 2");
        assert!(
            !responses.contains(&signer2),
            "Signer2 should not be in block 2 (only added to blocks 0, 1)"
        );
    }

    /// Run migrations up to (and including) the given version on a raw connection.
    /// Caller must register scalar functions beforehand if running early migrations.
    /// Insert a block into the schema-5 blocks table using raw SQL.
    /// Builds a real `BlockInfo` so the `block_info` JSON is valid for
    /// deserialization after migration. Returns the `Sha512Trunc256Sum`
    /// so callers can use `block_lookup` to verify data post-migration.
    fn insert_schema5_block(
        conn: &Connection,
        consensus_hash: ConsensusHash,
        chain_length: u64,
        signed_self: Option<u64>,
    ) -> Sha512Trunc256Sum {
        let (mut block_info, _) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash;
            b.block.header.chain_length = chain_length;
        });
        block_info.valid = Some(true);
        block_info.state = BlockState::GloballyAccepted;
        block_info.signed_self = signed_self;

        let sighash = block_info.signer_signature_hash();
        let block_json =
            serde_json::to_string(&block_info).expect("Unable to serialize block info");

        conn.execute(
            "INSERT INTO blocks (
                signer_signature_hash, reward_cycle, block_info, consensus_hash,
                signed_over, broadcasted, stacks_height, burn_block_height,
                valid, state, signed_group, signed_self,
                proposed_time, validation_time_ms, tenure_change
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                sighash.to_string(),
                u64_to_sql(block_info.reward_cycle).unwrap(),
                block_json,
                block_info.block.header.consensus_hash.to_hex(),
                1i64,        // signed_over
                None::<i64>, // broadcasted
                u64_to_sql(block_info.block.header.chain_length).unwrap(),
                u64_to_sql(block_info.burn_block_height).unwrap(),
                &block_info.valid,
                &block_info.state.to_string(),
                &block_info.signed_group,
                &block_info.signed_self,
                u64_to_sql(block_info.proposed_time).unwrap(),
                &block_info.validation_time_ms,
                &block_info.is_tenure_change(),
            ],
        )
        .unwrap();

        sighash
    }

    /// Progressively applies every migration one at a time, running
    /// per-version validations at each step. The exhaustive `match` means
    /// adding a new `SchemaVersion` variant without handling it here will
    /// cause a compile error.
    ///
    /// When adding a new migration:
    /// 1. Add the `SchemaVersion` variant
    /// 2. Add the `Migration` entry in `MIGRATIONS`
    /// 3. Add the variant to the match below with version-specific checks
    #[test]
    fn test_all_schema_migrations() {
        let db_path = tmp_db_path();
        let mut signer_db = SignerDb {
            db: SignerDb::connect(&db_path).unwrap(),
        };
        signer_db.register_scalar_functions().unwrap();

        let mut hash_signed = Sha512Trunc256Sum([0; 32]);
        let mut hash_unsigned = Sha512Trunc256Sum([0; 32]);

        for migration in MIGRATIONS {
            // Apply this single migration
            let tx = tx_begin_immediate(&mut signer_db.db).unwrap();
            for statement in migration.statements {
                tx.execute_batch(statement).unwrap();
            }
            tx.commit().unwrap();

            let version = migration.version.as_u32();
            assert_eq!(
                SignerDb::get_schema_version(&signer_db.db).unwrap(),
                version,
                "Migration to version {version} did not set the correct schema version"
            );

            // Exhaustive match: per-version setup and validation.
            // Adding a new SchemaVersion variant without a branch here
            // will fail to compile.
            match migration.version {
                SchemaVersion::V1 | SchemaVersion::V2 | SchemaVersion::V3 | SchemaVersion::V4 => {}
                SchemaVersion::V5 => {
                    // Schema 5 is the first restructured blocks table.
                    // Insert test data that must survive all subsequent migrations.
                    hash_signed = insert_schema5_block(
                        &signer_db.db,
                        ConsensusHash([0x01; 20]),
                        100,
                        Some(1000),
                    );
                    hash_unsigned =
                        insert_schema5_block(&signer_db.db, ConsensusHash([0x02; 20]), 101, None);
                }
                SchemaVersion::V6
                | SchemaVersion::V7
                | SchemaVersion::V8
                | SchemaVersion::V9
                | SchemaVersion::V10
                | SchemaVersion::V11
                | SchemaVersion::V12
                | SchemaVersion::V13
                | SchemaVersion::V14
                | SchemaVersion::V15
                | SchemaVersion::V16
                | SchemaVersion::V17 => {}
                SchemaVersion::V18 => {
                    // signed_over column should still exist before V19 removes it
                    let signed_over: i64 = signer_db
                        .db
                        .query_row(
                            &format!(
                                "SELECT signed_over FROM blocks WHERE signer_signature_hash = '{hash_signed}'"
                            ),
                            [],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert_eq!(signed_over, 1);
                }
                SchemaVersion::V19 => {
                    // signed_over column should be removed
                    assert!(
                        signer_db
                            .db
                            .execute("SELECT signed_over FROM blocks LIMIT 1", [])
                            .is_err(),
                        "signed_over column should not exist after V19"
                    );

                    // approved_time backfilled from signed_self
                    let approved_time: Option<i64> = signer_db.db.query_row(
                        &format!("SELECT approved_time FROM blocks WHERE signer_signature_hash = '{hash_signed}'"),
                        [], |row| row.get(0),
                    ).unwrap();
                    assert_eq!(approved_time, Some(1000));

                    let approved_time: Option<i64> = signer_db.db.query_row(
                        &format!("SELECT approved_time FROM blocks WHERE signer_signature_hash = '{hash_unsigned}'"),
                        [], |row| row.get(0),
                    ).unwrap();
                    assert!(approved_time.is_none());

                    // Verify indexes survived the table rebuild
                    let index_names: Vec<String> = signer_db
                        .db
                        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'blocks'")
                        .unwrap()
                        .query_map([], |row| row.get(0))
                        .unwrap()
                        .collect::<Result<_, _>>()
                        .unwrap();
                    for expected in &[
                        "blocks_consensus_hash_state",
                        "blocks_state",
                        "blocks_signed_group",
                        "blocks_consensus_hash_state_height",
                        "blocks_state_height_signed_group",
                        "blocks_reward_cycle_state",
                        "idx_blocks_get_last_globally_accepted_block_approved_time",
                        "idx_blocks_tenure_self_signed",
                        "idx_blocks_tenure_group_signed",
                        "idx_blocks_tenure_approved",
                    ] {
                        assert!(
                            index_names.contains(&expected.to_string()),
                            "Missing index: {expected}"
                        );
                    }
                    for removed in &[
                        "blocks_signed_over",
                        "blocks_consensus_hash_status_height",
                        "idx_blocks_query_opt",
                    ] {
                        assert!(
                            !index_names.contains(&removed.to_string()),
                            "Index should not exist: {removed}"
                        );
                    }
                }
                SchemaVersion::V20 => {
                    // The superseded tenures table exists and starts empty
                    let superseded: i64 = signer_db
                        .db
                        .query_row("SELECT COUNT(*) FROM superseded_tenures", [], |row| {
                            row.get(0)
                        })
                        .expect("superseded_tenures table should exist after V20");
                    assert_eq!(superseded, 0);
                }
                SchemaVersion::V21 => {
                    // The burn block height index used by `prune` exists
                    let index: Option<String> = signer_db
                        .db
                        .query_row(
                            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'burn_blocks_height'",
                            [],
                            |row| row.get(0),
                        )
                        .optional()
                        .unwrap();
                    assert_eq!(index.as_deref(), Some("burn_blocks_height"));
                }
            }
        }

        // Verify data survived all migrations
        let block_signed = signer_db
            .block_lookup(&hash_signed)
            .unwrap()
            .expect("Block with signed_self should exist after all migrations");
        assert_eq!(block_signed.block.header.chain_length, 100);
        assert_eq!(block_signed.signed_self, Some(1000));
        assert_eq!(block_signed.state, BlockState::GloballyAccepted);

        let block_unsigned = signer_db
            .block_lookup(&hash_unsigned)
            .unwrap()
            .expect("Block without signed_self should exist after all migrations");
        assert_eq!(block_unsigned.block.header.chain_length, 101);
        assert!(block_unsigned.signed_self.is_none());

        // Database is usable: insert and read back a new block
        let (block_info, block_proposal) = create_block();
        signer_db.insert_block(&block_info).unwrap();
        let retrieved = signer_db
            .block_lookup(&block_proposal.block.header.signer_signature_hash())
            .unwrap()
            .expect("Should retrieve inserted block");
        assert_eq!(BlockInfo::from(block_proposal), retrieved);

        // Reopening is idempotent
        signer_db.remove_scalar_functions().unwrap();
        drop(signer_db);
        let db = SignerDb::new(&db_path).expect("Re-opening should succeed");
        assert_eq!(
            SignerDb::get_schema_version(&db.db).unwrap(),
            SignerDb::SCHEMA_VERSION
        );

        assert_eq!(
            MIGRATIONS.last().unwrap().version.as_u32(),
            SignerDb::SCHEMA_VERSION,
            "Last migration version must match SCHEMA_VERSION"
        );
    }
}
