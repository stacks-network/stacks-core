pub mod utils;
pub mod test_helpers;

use std::{ops::Deref, path::PathBuf};

use clarity::vm::ast::ASTRules;
use stacks_common::types::{chainstate::{BurnchainHeaderHash, SortitionId, ConsensusHash, BlockHeaderHash, PoxId, TrieHash}, StacksEpochId};

use crate::{
    burnchains::{
        PoxConstants, Txid, affirmation::AffirmationMap, Error as BurnchainError, BurnchainStateTransitionOps, BurnchainBlockHeader, Burnchain, BurnchainStateTransition, BurnchainView
    }, 
    core::StacksEpoch, 
    chainstate::{
        burn::{operations::{LeaderBlockCommitOp, leader_block_commit::{RewardSetInfo, MissedBlockCommit}, BlockstackOperationType, StackStxOp, DelegateStxOp, PegInOp, PegOutRequestOp, PegOutFulfillOp, TransferStxOp, UserBurnSupportOp, LeaderKeyRegisterOp}, BlockSnapshot}, 
        coordinator::RewardCycleInfo, stacks::{address::PoxAddress, index::trie_db::TrieDb}
    }
};

use super::sortdb::{BlockHeaderCache, InitialMiningBonus};

#[derive(Debug)]
pub enum SortitionError {
    Burnchain(BurnchainError)
}

impl From<BurnchainError> for SortitionError {
    fn from(e: BurnchainError) -> Self {
        SortitionError::Burnchain(e)
    }
}

impl From<SortitionError> for crate::util_lib::db::Error {
    fn from(e: SortitionError) -> Self {
        crate::util_lib::db::Error::Other(format!("{:?}", e))
    }
}

pub type Result<T> = std::result::Result<T, SortitionError>;

pub trait SortitionDb 
where
    Self: TrieDb + Sized
{
    type TxType<'a, State>: SortitionDbTransaction<Self, State> + Sized 
    where 
        Self: 'a;

    fn connect(
        path: &str,
        first_block_height: u64,
        first_burn_hash: &BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
        epochs: &[StacksEpoch],
        pox_constants: PoxConstants,
        readwrite: bool,
    ) -> Result<Self>
    where
        Self: Sized;

    fn transaction(
        &mut self
    ) -> Result<&Self::TxType<'_, ()>> 
    where 
        Self: Sized;

    fn transaction_with_state<State>(
        &mut self, 
        state: State
    ) -> Result<&Self::TxType<'_, State>> 
    where 
        Self: Sized;

    /// Get a block commit by its content-addressed location in a specific sortition.
    fn get_block_commit(
        &self,
        txid: &Txid,
        sortition_id: &SortitionId,
    ) -> Result<Option<LeaderBlockCommitOp>>;

    /// Get the Sortition ID for the burnchain block containing `txid`'s parent.
    /// `txid` is the burnchain txid of a block-commit.
    fn get_block_commit_parent_sortition_id(
        &self,
        txid: &Txid,
        sortition_id: &SortitionId,
    ) -> Result<Option<SortitionId>>;

    /// Load up all snapshots, in ascending order by block height.  Great for testing!
    fn get_all_snapshots(
        &self
    ) -> Result<Vec<BlockSnapshot>>;

    /// Get all snapshots for a burn block hash, even if they're not on the canonical PoX fork.
    fn get_all_snapshots_for_burn_block(
        &self,
        bhh: &BurnchainHeaderHash,
    ) -> Result<Vec<BlockSnapshot>>;

    /// Get the height of a consensus hash, even if it's not on the canonical PoX fork.
    fn get_consensus_hash_height(&self, ch: &ConsensusHash) -> Result<Option<u64>>;

    /// Get the height of the highest burnchain block, given the DB path.
    /// Importantly, this will *not* apply any schema migrations.
    /// This is used to check if the DB is compatible with the current epoch.
    fn get_highest_block_height_from_path(
        &self, 
        path: &str
    ) -> Result<u64>;

    /// What's the default AST rules at the given block height?
    fn get_ast_rules(
        &self, 
        height: u64
    ) -> Result<ASTRules>;

    /// Get a pre-processed reawrd set.
    /// `sortition_id` is the first sortition ID of the prepare phase.
    fn get_preprocessed_reward_set(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<Option<RewardCycleInfo>>;

    fn find_sortition_tip_affirmation_map(
        &self,
        chain_tip: &SortitionId,
    ) -> Result<AffirmationMap>;

    /// Given a burnchain consensus hash,
    /// go get the last N Stacks block headers that won sortition
    /// leading up to the given header hash.  The ith slot in the vector will be Some(...) if there
    /// was a sortition, and None if not.
    /// Returns up to num_headers prior block header hashes.
    /// The list of hashes will be in ascending order -- the lowest-height block is item 0.
    /// The last hash will be the hash for the given consensus hash.
    fn get_stacks_header_hashes(
        &self,
        num_headers: u64,
        tip_consensus_hash: &ConsensusHash,
        cache: &BlockHeaderCache,
    ) -> Result<Vec<(ConsensusHash, Option<BlockHeaderHash>)>>;

    fn find_parent_snapshot_for_stacks_block(
        &self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<BlockSnapshot>>;

    fn get_reward_set_size_at(
        &self, 
        sortition_id: &SortitionId
    ) -> Result<u16>;

    fn get_reward_set_entry_at(
        &self,
        sortition_id: &SortitionId,
        entry_ix: u16,
    ) -> Result<PoxAddress>;

    fn get_reward_set_payouts_at(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<(Vec<PoxAddress>, u128)>;

    fn get_sortition_id(
        &self,
        burnchain_header_hash: &BurnchainHeaderHash,
        sortition_tip: &SortitionId,
    ) -> Result<Option<SortitionId>>;

    fn is_sortition_processed(
        &self,
        burnchain_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<SortitionId>>;

    fn get_block_height(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<Option<u32>>;

    /// Is the given block an expected PoX anchor in this sortition history?
    ///  if so, return the Stacks block hash
    fn is_stacks_block_pox_anchor(
        &self,
        block: &BlockHeaderHash,
        sortition_tip: &SortitionId,
    ) -> Result<Option<BlockHeaderHash>>;

    fn find_snapshots_with_dirty_canonical_block_pointers(
        &self,
        canonical_stacks_height: u64,
    ) -> Result<Vec<SortitionId>>;

    fn get_prepare_end_for(
        &self,
        sortition_tip: &SortitionId,
        anchor: &BlockHeaderHash,
    ) -> Result<Option<BlockSnapshot>>;

    fn get_pox_id(
        &self, 
        sortition_tip: &SortitionId
    ) -> Result<PoxId>;

    fn get_sortition_result(
        &self,
        id: &SortitionId,
    ) -> Result<Option<(BlockSnapshot, BurnchainStateTransitionOps)>>;

    fn get_next_block_recipients(
        &mut self,
        burnchain: &Burnchain,
        parent_snapshot: &BlockSnapshot,
        next_pox_info: Option<&RewardCycleInfo>,
    ) -> Result<Option<RewardSetInfo>>;

    fn is_stacks_block_in_sortition_set(
        &self,
        sortition_id: &SortitionId,
        block_to_check: &BlockHeaderHash,
    ) -> Result<bool>;

    fn latest_stacks_blocks_processed(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<u64>;

    /// Get a burn blockchain snapshot, given a burnchain configuration struct.
    /// Used mainly by the network code to determine what the chain tip currently looks like.
    fn get_burnchain_view(
        &self,
        burnchain: &Burnchain,
        chain_tip: &BlockSnapshot,
    ) -> Result<BurnchainView>;

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    fn get_canonical_burn_chain_tip(
        &self
    ) -> Result<BlockSnapshot>;

    /// Get the highest burn chain tip even if it's not PoX-valid.
    /// Break ties deterministically by ordering on burnchain block hash.
    fn get_highest_known_burn_chain_tip(
        &self
    ) -> Result<BlockSnapshot>;

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    fn get_canonical_chain_tip_bhh(
        &self
    ) -> Result<BurnchainHeaderHash>;

    /// Get the canonical burn chain tip -- the tip of the longest burn chain we know about.
    /// Break ties deterministically by ordering on burnchain block hash.
    ///
    /// Returns Err if the underlying SQLite call fails.
    fn get_canonical_sortition_tip(
        &self
    ) -> Result<SortitionId>;

    /// Get the list of Stack-STX operations processed in a given burnchain block.
    /// This will be the same list in each PoX fork; it's up to the Stacks block-processing logic
    /// to reject them.
    fn get_stack_stx_ops(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<StackStxOp>>;

    /// Get the list of Delegate-STX operations processed in a given burnchain block.
    /// This will be the same list in each PoX fork; it's up to the Stacks block-processing logic
    /// to reject them.
    fn get_delegate_stx_ops(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<DelegateStxOp>>;

    /// Get the list of Peg-In operations processed in a given burnchain block.
    /// This will be the same list in each PoX fork; it's up to the Stacks block-processing logic
    /// to reject them.
    fn get_peg_in_ops(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<PegInOp>>;

    /// Get the list of Peg-Out Request operations processed in a given burnchain block.
    /// This will be the same list in each PoX fork; it's up to the Stacks block-processing logic
    /// to reject them.
    fn get_peg_out_request_ops(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<PegOutRequestOp>>;

    /// Get the list of Peg-Out Fulfill operations processed in a given burnchain block.
    /// This will be the same list in each PoX fork; it's up to the Stacks block-processing logic
    /// to reject them.
    fn get_peg_out_fulfill_ops(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<PegOutFulfillOp>>;

    /// Get the list of Transfer-STX operations processed in a given burnchain block.
    /// This will be the same list in each PoX fork; it's up to the Stacks block-processing logic
    /// to reject them.
    fn get_transfer_stx_ops(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<TransferStxOp>>;

    /// Get the parent burnchain header hash of a given burnchain header hash
    fn get_parent_burnchain_header_hash(
        &self,
        burnchain_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<BurnchainHeaderHash>>;

    /// Get the last N ancestor burnchain header hashes, given a burnchain header hash.
    /// This is done without regards to PoX forks.
    ///
    /// The returned list will be formatted as follows:
    ///
    /// * burn_header_hash
    /// * 1st ancestor of burn_header_hash
    /// * 2nd ancestor of burn_header_hash
    /// ...
    /// * Nth ancestor of burn_header_hash
    ///
    /// That is, the resulting list will have up to N+1 items.
    ///
    /// If an ancestor is not found, then return early.
    /// The returned list always starts with `burn_header_hash`.
    fn get_ancestor_burnchain_header_hashes(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
        count: u64,
    ) -> Result<Vec<BurnchainHeaderHash>>;

    fn get_canonical_stacks_chain_tip_hash(
        &self
    ) -> Result<(ConsensusHash, BlockHeaderHash)>;

    /// Get the maximum arrival index for any known snapshot.
    fn get_max_arrival_index(
        &self
    ) -> Result<u64>;

    /// Get a snapshot with an arrived block (i.e. a block that was marked as processed)
    fn get_snapshot_by_arrival_index(
        &self,
        arrival_index: u64,
    ) -> Result<Option<BlockSnapshot>>;

    fn get_burnchain_header_hash_by_consensus(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<BurnchainHeaderHash>>;

    fn get_sortition_id_by_consensus(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<SortitionId>>;

    /// Get a snapshot for an existing burn chain block given its consensus hash.
    /// The snapshot may not be valid.
    fn get_block_snapshot_consensus(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<BlockSnapshot>>;

    /// Get a snapshot for an processed sortition.
    /// The snapshot may not be valid
    fn get_block_snapshot(
        &self,
        sortition_id: &SortitionId,
    ) -> Result<Option<BlockSnapshot>>;

    /// Get the first snapshot
    fn get_first_block_snapshot(
        &self
    ) -> Result<BlockSnapshot>;

    fn is_pox_active(
        &self,
        burnchain: &Burnchain,
        block: &BlockSnapshot,
    ) -> Result<bool>;

    /// Find out how any burn tokens were destroyed in a given block on a given fork.
    fn get_block_burn_amount(
        &self,
        block_snapshot: &BlockSnapshot,
    ) -> Result<u64>;

    /// Get all user burns registered in a block on is fork.
    /// Returns list of user burns in order by vtxindex.
    fn get_user_burns_by_block(
        &self,
        sortition: &SortitionId,
    ) -> Result<Vec<UserBurnSupportOp>>;

    /// Get all block commitments registered in a block on the burn chain's history in this fork.
    /// Returns the list of block commits in order by vtxindex.
    fn get_block_commits_by_block(
        &self,
        sortition: &SortitionId,
    ) -> Result<Vec<LeaderBlockCommitOp>>;

    /// Get all the missed block commits that were intended to be included in the given
    ///  block but were not
    fn get_missed_commits_by_intended(
        &self,
        sortition: &SortitionId,
    ) -> Result<Vec<MissedBlockCommit>>;

    /// Get all leader keys registered in a block on the burn chain's history in this fork.
    /// Returns the list of leader keys in order by vtxindex.
    fn get_leader_keys_by_block(
        &self,
        sortition: &SortitionId,
    ) -> Result<Vec<LeaderKeyRegisterOp>>;

    /// Get the vtxindex of the winning sortition.
    /// The sortition may not be valid.
    fn get_block_winning_vtxindex(
        &self,
        sortition: &SortitionId,
    ) -> Result<Option<u16>>;

    /// Given the fork index hash of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork, find the snapshot of the block at that height.
    ///
    /// Returns None if there is no ancestor at this height.
    fn get_ancestor_snapshot(
        &self,
        ancestor_block_height: u64,
        tip_block_hash: &SortitionId,
    ) -> Result<Option<BlockSnapshot>>;

    /// Given the fork index hash of a chain tip, and a block height that is an ancestor of the last
    /// block in this fork, find the snapshot of the block at that height.
    fn get_ancestor_snapshot_tx(
        &self,
        ancestor_block_height: u64,
        tip_block_hash: &SortitionId,
    ) -> Result<Option<BlockSnapshot>>;

    /// Get a parent block commit at a specific location in the burn chain on a particular fork.
    /// Returns None if there is no block commit at this location.
    fn get_block_commit_parent(
        &self,
        block_height: u64,
        vtxindex: u32,
        tip: &SortitionId,
    ) -> Result<Option<LeaderBlockCommitOp>>;

    fn get_block_commit_of_sortition(
        &self,
        sortition: &SortitionId,
        block_height: u64,
        vtxindex: u32,
    ) -> Result<Option<LeaderBlockCommitOp>>;

    /// Get a leader key at a specific location in the burn chain's fork history, given the
    /// matching block commit's fork index root (block_height and vtxindex are the leader's
    /// calculated location in this fork).
    /// Returns None if there is no leader key at this location.
     fn get_leader_key_at(
        &self,
        key_block_height: u64,
        key_vtxindex: u32,
        tip: &SortitionId,
    ) -> Result<Option<LeaderKeyRegisterOp>>;

    /// Get a block commit by its committed block.
    /// For Stacks 2.x, `block_hash` is just the hash of the block
    /// For Nakamoto, `block_hash` is the StacksBlockId of the last tenure's first block
    fn get_block_commit_for_stacks_block(
        &self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<LeaderBlockCommitOp>>;

    /// Get a block snapshot for a winning block hash in a given burn chain fork.
    fn get_block_snapshot_for_winning_stacks_block(
        &self,
        tip: &SortitionId,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<BlockSnapshot>>;

    /// Get the StacksEpoch for a given burn block height
    fn get_stacks_epoch(
        &self,
        burn_block_height: u64,
    ) -> Result<Option<StacksEpoch>>;

    /// Get all sortition IDs at the given burnchain block height (including ones that aren't on
    /// the canonical PoX fork)
    fn get_sortition_ids_at_height(
        &self,
        height: u64,
    ) -> Result<Vec<SortitionId>>;

    /// Get all StacksEpochs, in order by ascending start height
    fn get_stacks_epochs(
        &self
    ) -> Result<Vec<StacksEpoch>>;

    fn get_stacks_epoch_by_epoch_id(
        &self,
        epoch_id: &StacksEpochId,
    ) -> Result<Option<StacksEpoch>>;

    /// Get the last reward cycle in epoch 2.05
    fn get_last_epoch_2_05_reward_cycle(
        &self
    ) -> Result<u64>;

    /// Get the latest block snapshot on this fork where a sortition occured.
    /// Search snapshots up to (but excluding) the given block height.
    /// Will always return a snapshot -- even if it's the initial sentinel snapshot.
    fn get_last_snapshot_with_sortition_tx(
        &self,
        burn_block_height: u64,
        chain_tip: &SortitionId,
    ) -> Result<BlockSnapshot>;

    fn get_initial_mining_bonus_remaining(
        &self,
        chain_tip: &SortitionId,
    ) -> Result<u128>;

    fn get_initial_mining_bonus_per_block(
        &self,
        chain_tip: &SortitionId,
    ) -> Result<Option<u128>>;

    fn get_num_pox_payouts(
        &self, 
        burn_block_height: u64
    ) -> Result<usize>;

    /// Given all of a snapshot's block ops, calculate how many burnchain tokens were sent to each
    /// PoX payout.  Note that this value is *per payout*:
    /// * in a reward phase, multiply this by OUTPUTS_PER_COMMIT to get the total amount of tokens
    /// sent across all miners.
    /// * in a prepare phase, where there is only one output, this value is the total amount of
    /// tokens sent across all miners.
    fn get_pox_payout_per_output(
        &self, 
        block_ops: &[BlockstackOperationType]
    ) -> Result<u128>;

    /// Find the new Stacks block arrivals as of the given tip `tip`, and return the highest chain
    /// tip discovered.
    ///
    /// Used in conjunction with update_new_block_arrivals().
    ///
    /// Returns Ok((
    ///     stacks tip consensus hash,
    ///     stacks tip block header hash,
    ///     stacks tip height,
    /// ))
    fn find_new_block_arrivals(
        &self,
        tip: &BlockSnapshot,
    ) -> Result<(ConsensusHash, BlockHeaderHash, u64)>;

    fn get_consensus_at(
        &self,
        block_height: u64,
    ) -> Result<Option<ConsensusHash>>;

    /// Get the latest block snapshot on this fork where a sortition occured.
    /// Search snapshots up to (but excluding) the given block height.
    /// Will always return a snapshot -- even if it's the initial sentinel snapshot.
    fn get_last_snapshot_with_sortition(
        &self,
        burn_block_height: u64,
    ) -> Result<BlockSnapshot>;
}

pub trait SortitionDbTransaction<SortDB, State = ()>
where
    SortDB: SortitionDb,
    Self: Deref<Target = SortDB>,
{
    fn commit() -> Result<()>;
    fn rollback() -> Result<()>;

    fn get_chain_tip(&self) -> Result<SortitionId>;

    fn get_state(&self) -> &State;

    /// Get the ancestor block hash of a block of a given height, given a descendent block hash.
    fn get_ancestor_block_hash(
        &mut self,
        block_height: u64,
        tip_block_hash: &SortitionId,
    ) -> Result<Option<SortitionId>>;

    /// is the given block a descendant of `potential_ancestor`?
    ///  * block_at_burn_height: the burn height of the sortition that chose the stacks block to check
    ///  * potential_ancestor: the stacks block hash of the potential ancestor
    fn descended_from(
        &mut self,
        block_at_burn_height: u64,
        potential_ancestor: &BlockHeaderHash,
    ) -> Result<bool>;

    /// Do we expect a stacks block in this particular fork?
    /// i.e. is this block hash part of the fork history identified by tip_block_hash?
    fn expects_stacks_block_in_fork<Conn>(
        &mut self,
        block_hash: &BlockHeaderHash,
    ) -> Result<bool>;

    /// Store a pre-processed reward set.
    /// `sortition_id` is the first sortition ID of the prepare phase
    fn store_preprocessed_reward_set(
        &self,
        sortition_id: &SortitionId,
        rc_info: &RewardCycleInfo,
    ) -> Result<()>;

    /// Mark a Stacks block snapshot as valid again, but update its memoized canonical Stacks tip
    /// height and block-accepted flag.
    fn revalidate_snapshot_with_block(
        &self,
        sortition_id: &SortitionId,
        canonical_stacks_ch: &ConsensusHash,
        canonical_stacks_bhh: &BlockHeaderHash,
        canonical_stacks_height: u64,
        stacks_block_accepted: Option<bool>,
    ) -> Result<()>;

    /// Invalidate all block snapshots that descend from the given burnchain block, and for each
    /// invalidated snapshot, apply `cls` to it with the given sortition DB transaction, the
    /// current burnchain block being considered, and the list of burnchain blocks still to be
    /// considered.  That last argument will have length 0 on the last call to `cls`.
    ///
    /// Run `after` with the sorition handle tx right before committing.
    fn invalidate_descendants_with_closures<F, G>(
        &self,
        burn_block: &BurnchainHeaderHash,
        cls: F,
        after: G,
    ) -> Result<()>
    where
        Self: Sized,
        F: FnMut(&mut Self, &BurnchainHeaderHash, &Vec<BurnchainHeaderHash>) -> (),
        G: FnMut(&mut Self) -> ();

    fn invalidate_descendants_of(
        &self,
        burn_block: &BurnchainHeaderHash,
    ) -> Result<()>;

    /// Evaluate the sortition (SIP-001 miner block election) in the burnchain block defined by
    /// `burn_header`. Returns the new snapshot and burnchain state
    /// transition.
    ///
    /// # Arguments
    /// * `burn_header` - the burnchain block header to process sortition for
    /// * `ops` - the parsed blockstack operations (will be validated in this function)
    /// * `burnchain` - a reference to the burnchain information struct
    /// * `from_tip` - tip of the "sortition chain" that is being built on
    /// * `next_pox_info` - iff this sortition is the first block in a reward cycle, this should be Some
    /// * `announce_to` - a function that will be invoked with the calculated reward set before this method
    ///                   commits its results. This is used to post the calculated reward set to an event observer.
    fn evaluate_sortition<F: FnOnce(Option<RewardSetInfo>) -> ()>(
        &self,
        burn_header: &BurnchainBlockHeader,
        ops: Vec<BlockstackOperationType>,
        burnchain: &Burnchain,
        from_tip: &SortitionId,
        next_pox_info: Option<RewardCycleInfo>,
        announce_to: F,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition)>;

    /// Append a snapshot to a chain tip, and update various chain tip statistics.
    /// Returns the new state root of this fork.
    /// `initialize_bonus` - if Some(..), then this snapshot is the first mined snapshot,
    ///    and this method should initialize the `initial_mining_bonus` fields in the sortition db.
    fn append_chain_tip_snapshot(
        &self,
        parent_snapshot: &BlockSnapshot,
        snapshot: &BlockSnapshot,
        block_ops: &Vec<BlockstackOperationType>,
        missed_commits: &Vec<MissedBlockCommit>,
        next_pox_info: Option<RewardCycleInfo>,
        reward_info: Option<&RewardSetInfo>,
        initialize_bonus: Option<InitialMiningBonus>,
    ) -> Result<TrieHash>;

    fn store_transition_ops(
        &self,
        new_sortition: &SortitionId,
        transition: &BurnchainStateTransition,
    ) -> Result<()>;

    /// Store a blockstack burnchain operation
    fn store_burnchain_transaction(
        &self,
        blockstack_op: &BlockstackOperationType,
        sort_id: &SortitionId,
    ) -> Result<()>;

    /// Insert a leader key registration.
    /// No validity checking will be done, beyond what is encoded in the leader_keys table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    fn insert_leader_key(
        &self,
        leader_key: &LeaderKeyRegisterOp,
        sort_id: &SortitionId,
    ) -> Result<()>;

    fn insert_stack_stx(
        &self, 
        op: &StackStxOp
    ) -> Result<()>;

    /// Insert a delegate-stx op
    fn insert_delegate_stx(
        &self, 
        op: &DelegateStxOp
    ) -> Result<()>;

    /// Insert a peg-in op
    fn insert_peg_in_sbtc(
        &self, 
        op: &PegInOp
    ) -> Result<()>;

    /// Insert a peg-out request op
    fn insert_sbtc_peg_out_request(
        &self, 
        op: &PegOutRequestOp
    ) -> Result<()>;

    /// Insert a peg-out fulfillment op
    fn insert_sbtc_peg_out_fulfill(
        &self, 
        op: &PegOutFulfillOp
    ) -> Result<()>;

    /// Insert a transfer-stx op
    fn insert_transfer_stx(
        &self, 
        op: &TransferStxOp
    ) -> Result<()>;

    /// Insert a leader block commitment.
    /// No validity checking will be done, beyond what is encoded in the block_commits table
    /// constraints.  That is, type mismatches and serialization issues will be caught, but nothing else.
    /// The corresponding snapshot must already be inserted
    fn insert_block_commit(
        &self,
        block_commit: &LeaderBlockCommitOp,
        sort_id: &SortitionId,
    ) -> Result<()>;

    /// Insert a user support burn.
    /// No validity checking will be done, beyond what is encoded in the user_burn_support table
    /// constraints.  That is, type mismatches and serialization errors will be caught, but nothing
    /// else.
    /// The corresponding snapshot must already be inserted
    fn insert_user_burn(
        &self,
        user_burn: &UserBurnSupportOp,
        sort_id: &SortitionId,
    ) -> Result<()>;

    /// Insert a missed block commit
    fn insert_missed_block_commit(
        &self, 
        op: &MissedBlockCommit
    ) -> Result<()>;

    /// Insert a snapshots row from a block's-worth of operations.
    /// Do not call directly -- use append_chain_tip_snapshot to preserve the fork table structure.
    fn insert_block_snapshot(
        &self,
        snapshot: &BlockSnapshot,
        total_pox_payouts: (Vec<PoxAddress>, u128),
    ) -> Result<()>;

    /// Record fork information to the index and calculate the new fork index root hash.
    /// * sortdb::vrf::${VRF_PUBLIC_KEY} --> 0 or 1 (1 if available, 0 if consumed), for each VRF public key we process
    /// * sortdb::last_sortition --> $BURN_BLOCK_HASH, for each block that had a sortition
    /// * sortdb::sortition_block_hash::${STACKS_BLOCK_HASH} --> $BURN_BLOCK_HASH for each winning block sortition
    /// * sortdb::stacks::block::${STACKS_BLOCK_HASH} --> ${STACKS_BLOCK_HEIGHT} for each block that has been accepted so far
    /// * sortdb::stacks::block::max_arrival_index --> ${ARRIVAL_INDEX} to set the maximum arrival index processed in this fork
    /// * sortdb::pox_reward_set::${n} --> recipient Bitcoin address, to track the reward set as the permutation progresses
    ///
    /// `recipient_info` is used to pass information to this function about which reward set addresses were consumed
    ///   during this sortition. this object will be None in the following cases:
    ///    * The reward cycle had an anchor block, but it isn't known by this node.
    ///    * The reward cycle did not have anchor block
    ///    * The Stacking recipient set is empty (either because this reward cycle has already exhausted the set of addresses or because no one ever Stacked).
    ///
    /// NOTE: the resulting index root must be globally unique.  This is guaranteed because each
    /// burn block hash is unique, no matter what fork it's on (and this index uses burn block
    /// hashes as its index's block hash data).
    fn index_add_fork_info(
        &self,
        parent_snapshot: &mut BlockSnapshot,
        snapshot: &BlockSnapshot,
        block_ops: &[BlockstackOperationType],
        next_pox_info: Option<RewardCycleInfo>,
        recipient_info: Option<&RewardSetInfo>,
        initialize_bonus: Option<InitialMiningBonus>,
    ) -> Result<(TrieHash, (Vec<PoxAddress>, u128))>;

    /// Update the given tip's canonical Stacks block pointer.
    /// Does so on all sortitions of the same height as tip.
    /// Only used in Stacks 2.x
    fn update_new_block_arrivals(
        &self,
        tip: &BlockSnapshot,
        best_chh: ConsensusHash,
        best_bhh: BlockHeaderHash,
        best_height: u64,
    ) -> Result<()>;

    /// Find all stacks blocks that were processed since parent_tip had been processed, and generate MARF
    /// key/value pairs for the subset that arrived on ancestor blocks of the parent.  Update the
    /// given parent chain tip to have the correct memoized canonical chain tip present in the fork
    /// it represents.
    fn process_new_block_arrivals(
        &self,
        parent_tip: &mut BlockSnapshot,
    ) -> Result<(Vec<String>, Vec<String>)>;

    /// Process all block's checked transactions
    /// * make the burn distribution
    /// * insert the ones that went into the burn distribution
    /// * snapshot the block and run the sortition
    /// * return the snapshot (and sortition results)
    fn process_checked_block_ops(
        &self,
        burnchain: &Burnchain,
        parent_snapshot: &BlockSnapshot,
        block_header: &BurnchainBlockHeader,
        this_block_ops: &Vec<BlockstackOperationType>,
        missed_commits: &Vec<MissedBlockCommit>,
        next_pox_info: Option<RewardCycleInfo>,
        parent_pox: PoxId,
        reward_info: Option<&RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition)>;

    /// Check and then commit all blockstack operations to our chainstate.
    /// * pull out all the transactions that are blockstack ops
    /// * select the ones that are _valid_
    /// * do a cryptographic sortition to select the next Stacks block
    /// * commit all valid transactions
    /// * commit the results of the sortition
    /// Returns the BlockSnapshot created from this block.
    fn process_block_ops(
        &self,
        burnchain: &Burnchain,
        parent_snapshot: &BlockSnapshot,
        block_header: &BurnchainBlockHeader,
        blockstack_txs: Vec<BlockstackOperationType>,
        next_pox_info: Option<RewardCycleInfo>,
        parent_pox: PoxId,
        reward_set_info: Option<&RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition)>;

    /// Given the extracted txs, and a block header, go process them into the next
    /// snapshot.  Unlike process_block_ops, this method applies safety checks against the given
    /// list of blockstack transactions.
    fn process_block_txs(
        &mut self,
        parent_snapshot: &BlockSnapshot,
        this_block_header: &BurnchainBlockHeader,
        burnchain: &Burnchain,
        blockstack_txs: Vec<BlockstackOperationType>,
        next_pox_info: Option<RewardCycleInfo>,
        parent_pox: PoxId,
        reward_set_info: Option<&RewardSetInfo>,
        initial_mining_bonus_ustx: u128,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition)>;

}