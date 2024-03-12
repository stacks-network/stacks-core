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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use clarity::vm::database::BurnStateDB;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksBlockId,
};
use stacks_common::types::{StacksEpoch, StacksEpochId};

use crate::burnchains::db::{BurnchainBlockData, BurnchainDB, BurnchainHeaderReader};
use crate::burnchains::{Burnchain, BurnchainBlockHeader};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::leader_block_commit::RewardSetInfo;
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::coordinator::comm::{
    CoordinatorChannels, CoordinatorCommunication, CoordinatorEvents, CoordinatorNotices,
    CoordinatorReceivers,
};
use crate::chainstate::coordinator::{
    calculate_paid_rewards, dispatcher_announce_burn_ops, BlockEventDispatcher, ChainsCoordinator,
    Error, OnChainRewardSetProvider, PaidRewards, PoxAnchorBlockStatus, RewardCycleInfo,
    RewardSetProvider,
};
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::boot::RewardSet;
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState};
use crate::chainstate::stacks::miner::{signal_mining_blocked, signal_mining_ready, MinerStatus};
use crate::chainstate::stacks::Error as ChainstateError;
use crate::cost_estimates::{CostEstimator, FeeEstimator};
use crate::monitoring::increment_stx_blocks_processed_counter;
use crate::net::Error as NetError;
use crate::util_lib::db::Error as DBError;

#[cfg(test)]
pub mod tests;

impl OnChainRewardSetProvider {
    pub fn get_reward_set_nakamoto(
        &self,
        // NOTE: this value is the first burnchain block in the prepare phase which has a Stacks
        // block (unlike in Stacks 2.x, where this is the first block of the reward phase)
        current_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<RewardSet, Error> {
        let cycle = burnchain
            .block_height_to_reward_cycle(current_burn_height)
            .expect("FATAL: no reward cycle for burn height")
            + 1;

        let registered_addrs =
            chainstate.get_reward_addresses_in_cycle(burnchain, sortdb, cycle, block_id)?;

        let liquid_ustx = chainstate.get_liquid_ustx(block_id);

        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            &burnchain.pox_constants,
            &registered_addrs[..],
            liquid_ustx,
        );

        let cur_epoch =
            SortitionDB::get_stacks_epoch(sortdb.conn(), current_burn_height)?.expect(&format!(
                "FATAL: no epoch defined for burn height {}",
                current_burn_height
            ));

        if cur_epoch.epoch_id >= StacksEpochId::Epoch30 && participation == 0 {
            // no one is stacking
            error!("No PoX participation");
            return Err(Error::PoXAnchorBlockRequired);
        }

        info!("PoX reward cycle threshold computed";
              "burn_height" => current_burn_height,
              "threshold" => threshold,
              "participation" => participation,
              "liquid_ustx" => liquid_ustx,
              "registered_addrs" => registered_addrs.len());

        Ok(StacksChainState::make_reward_set(
            threshold,
            registered_addrs,
            cur_epoch.epoch_id,
        ))
    }
}

/// Find the ordered sequence of sortitions from a given burnchain block back to the start of
/// the burnchain block's reward cycle's prepare phase.  If the burnchain block is not in a prepare
/// phase, then the returned list is empty.  If the burnchain block is in a prepare phase, then all
/// consensus hashes back to the first block in the prepare phase are loaded and returned in
/// ascending height order.
fn find_prepare_phase_sortitions(
    sort_db: &SortitionDB,
    burnchain: &Burnchain,
    sortition_tip: &SortitionId,
) -> Result<Vec<BlockSnapshot>, Error> {
    let mut prepare_phase_sn = SortitionDB::get_block_snapshot(sort_db.conn(), sortition_tip)?
        .ok_or(DBError::NotFoundError)?;

    let mut height = prepare_phase_sn.block_height;
    let mut sns = vec![];

    while burnchain.is_in_prepare_phase(height) && height > 0 {
        let parent_sortition_id = prepare_phase_sn.parent_sortition_id;
        sns.push(prepare_phase_sn);
        let Some(sn) = SortitionDB::get_block_snapshot(sort_db.conn(), &parent_sortition_id)?
        else {
            break;
        };
        prepare_phase_sn = sn;
        height = height.saturating_sub(1);
    }

    sns.reverse();
    Ok(sns)
}

/// Try to get the reward cycle information for a Nakamoto reward cycle.
/// In Nakamoto, the PoX anchor block for reward cycle _R_ is the _first_ Stacks block mined in the
/// _last_ tenure of _R - 1_'s reward phase phase (i.e. which takes place toward the end of reward cycle).
/// The reason it must be this way is because its hash will be in the block-commit for the first
/// prepare-phase tenure of cycle _R_ (which is required for the PoX ancestry query in the
/// block-commit validation logic).
///
/// If this method returns None, the caller should try again when there are more Stacks blocks.  In
/// Nakamoto, every reward cycle _must_ have a PoX anchor block; otherwise, the chain halts.
///
/// N.B. this method assumes that the prepare phase is comprised _solely_ of Nakamoto tenures.  It
/// will not work if any of the prepare-phase tenures are from epoch 2.x.
///
/// Returns Ok(Some(reward-cycle-info)) if we found the first sortition in the prepare phase.
/// Returns Ok(None) if we're still waiting for the PoX anchor block sortition
/// Returns Err(Error::NotInPreparePhase) if `burn_height` is not in the prepare phase
/// Returns Err(Error::RewardCycleAlreadyProcessed) if the reward set for this reward cycle has
/// already been processed.
pub fn get_nakamoto_reward_cycle_info<U: RewardSetProvider>(
    burn_height: u64,
    sortition_tip: &SortitionId,
    burnchain: &Burnchain,
    chain_state: &mut StacksChainState,
    sort_db: &mut SortitionDB,
    provider: &U,
) -> Result<Option<RewardCycleInfo>, Error> {
    let epoch_at_height = SortitionDB::get_stacks_epoch(sort_db.conn(), burn_height)?
        .expect(&format!(
            "FATAL: no epoch defined for burn height {}",
            burn_height
        ))
        .epoch_id;

    assert!(
        epoch_at_height >= StacksEpochId::Epoch30,
        "FATAL: called a nakamoto function outside of epoch 3"
    );

    if !burnchain.is_in_prepare_phase(burn_height) {
        return Err(Error::NotInPreparePhase);
    }

    // calculating the reward set for the _next_ reward cycle
    let reward_cycle = burnchain
        .block_height_to_reward_cycle(burn_height)
        .expect("FATAL: no reward cycle for burn height")
        + 1;

    debug!("Processing reward set for Nakamoto reward cycle";
          "burn_height" => burn_height,
          "reward_cycle" => reward_cycle,
          "reward_cycle_length" => burnchain.pox_constants.reward_cycle_length,
          "prepare_phase_length" => burnchain.pox_constants.prepare_length);

    // find the last tenure-start Stacks block processed in the preceeding prepare phase
    // (i.e. the first block in the tenure of the parent of the first Stacks block processed in the prepare phase).
    // Note that we may not have processed it yet.  But, if we do find it, then it's
    // unique (and since Nakamoto Stacks blocks are processed in order, the anchor block
    // cannot change later).
    let prepare_phase_sortitions =
        find_prepare_phase_sortitions(sort_db, burnchain, sortition_tip)?;

    // did we already calculate the reward cycle info?  If so, then return it.
    let first_sortition_id = if let Some(first_sn) = prepare_phase_sortitions.first() {
        if let Some(persisted_reward_cycle_info) =
            SortitionDB::get_preprocessed_reward_set(sort_db.conn(), &first_sn.sortition_id)?
        {
            return Ok(Some(persisted_reward_cycle_info));
        }
        first_sn.sortition_id.clone()
    } else {
        // can't do anything
        return Ok(None);
    };

    for sn in prepare_phase_sortitions.into_iter() {
        if !sn.sortition {
            continue;
        }

        // find the first Stacks block processed in the prepare phase
        let Some(prepare_start_block_header) =
            NakamotoChainState::get_nakamoto_tenure_start_block_header(
                chain_state.db(),
                &sn.consensus_hash,
            )?
        else {
            // no header for this snapshot (possibly invalid)
            continue;
        };

        let parent_block_id = &prepare_start_block_header
            .anchored_header
            .as_stacks_nakamoto()
            .expect("FATAL: queried non-Nakamoto tenure start header")
            .parent_block_id;

        // find the tenure-start block of the tenure of the parent of this Stacks block.
        // in epoch 2, this is the preceding anchor block
        // in nakamoto, this is the tenure-start block of the preceding tenure
        let parent_block_header =
            NakamotoChainState::get_block_header(chain_state.db(), &parent_block_id)?
                .expect("FATAL: no parent for processed Stacks block in prepare phase");

        let anchor_block_header = match &parent_block_header.anchored_header {
            StacksBlockHeaderTypes::Epoch2(..) => parent_block_header,
            StacksBlockHeaderTypes::Nakamoto(..) => {
                NakamotoChainState::get_nakamoto_tenure_start_block_header(
                    chain_state.db(),
                    &parent_block_header.consensus_hash,
                )?
                .expect("FATAL: no parent for processed Stacks block in prepare phase")
            }
        };

        let anchor_block_sn = SortitionDB::get_block_snapshot_consensus(
            sort_db.conn(),
            &anchor_block_header.consensus_hash,
        )?
        .expect("FATAL: no snapshot for winning PoX anchor block");

        // make sure the `anchor_block` field is the same as whatever goes into the block-commit,
        // or PoX ancestry queries won't work
        let (block_id, stacks_block_hash) = match anchor_block_header.anchored_header {
            StacksBlockHeaderTypes::Epoch2(header) => (
                StacksBlockId::new(&anchor_block_header.consensus_hash, &header.block_hash()),
                header.block_hash(),
            ),
            StacksBlockHeaderTypes::Nakamoto(header) => {
                (header.block_id(), BlockHeaderHash(header.block_id().0))
            }
        };

        let txid = anchor_block_sn.winning_block_txid;

        info!(
            "Anchor block selected for cycle {}: (ch {}) {}",
            reward_cycle, &anchor_block_header.consensus_hash, &block_id
        );

        let reward_set =
            provider.get_reward_set(burn_height, chain_state, burnchain, sort_db, &block_id)?;
        debug!(
            "Stacks anchor block (ch {}) {} cycle {} is processed",
            &anchor_block_header.consensus_hash, &block_id, reward_cycle
        );
        let anchor_status =
            PoxAnchorBlockStatus::SelectedAndKnown(stacks_block_hash, txid, reward_set);

        let rc_info = RewardCycleInfo {
            reward_cycle,
            anchor_status,
        };

        // persist this
        let mut tx = sort_db.tx_begin()?;
        SortitionDB::store_preprocessed_reward_set(&mut tx, &first_sortition_id, &rc_info)?;
        tx.commit()?;

        return Ok(Some(rc_info));
    }

    // no stacks block known yet
    info!("No PoX anchor block known yet for cycle {}", reward_cycle);
    return Ok(None);
}

/// Get the next PoX recipients in the Nakamoto epoch.
/// This is a little different than epoch 2.x:
/// * we're guaranteed to have an anchor block
/// * we pre-compute the reward set at the start of the prepare phase, so we only need to load it
/// up here at the start of the reward phase.
pub fn get_nakamoto_next_recipients(
    sortition_tip: &BlockSnapshot,
    sort_db: &mut SortitionDB,
    burnchain: &Burnchain,
) -> Result<Option<RewardSetInfo>, Error> {
    let reward_cycle_info = if burnchain.is_reward_cycle_start(sortition_tip.block_height + 1) {
        // load up new reward cycle info so we can start using *that*
        let prepare_phase_sortitions =
            find_prepare_phase_sortitions(sort_db, burnchain, &sortition_tip.parent_sortition_id)?;

        // NOTE: this must panic because Nakamoto's first reward cycle has stackers
        let first_sn = prepare_phase_sortitions
            .first()
            .expect("FATAL: unreachable: no prepare-phase sortitions at start of reward cycle");

        debug!("Get pre-processed reward set";
               "sortition_id" => %first_sn.sortition_id);

        // NOTE: if we don't panic here, we'll panic later in a more obscure way
        Some(
            SortitionDB::get_preprocessed_reward_set(sort_db.conn(), &first_sn.sortition_id)?
                .expect(&format!(
                    "No reward set for start of reward cycle beginning with block {}",
                    &sortition_tip.block_height
                )),
        )
    } else {
        None
    };
    sort_db
        .get_next_block_recipients(burnchain, sortition_tip, reward_cycle_info.as_ref())
        .map_err(Error::from)
}

impl<
        'a,
        T: BlockEventDispatcher,
        N: CoordinatorNotices,
        U: RewardSetProvider,
        CE: CostEstimator + ?Sized,
        FE: FeeEstimator + ?Sized,
        B: BurnchainHeaderReader,
    > ChainsCoordinator<'a, T, N, U, CE, FE, B>
{
    /// Check to see if we're in the last of the 2.x epochs, and we have the first PoX anchor block
    /// for epoch 3.
    /// NOTE: the first block in epoch3 must be after the first block in the reward phase, so as
    /// to ensure that the PoX stackers have been selected for this cycle.  This means that we
    /// don't proceed to process Nakamoto blocks until the reward cycle has begun.  Also, the last
    /// reward cycle of epoch2 _must_ be PoX so we have stackers who can sign.
    ///
    /// TODO: how do signers register their initial keys?  Can we just deploy a pre-registration
    /// contract?
    pub fn can_process_nakamoto(&mut self) -> Result<bool, Error> {
        let canonical_sortition_tip = self
            .canonical_sortition_tip
            .clone()
            .expect("FAIL: checking epoch status, but we don't have a canonical sortition tip");

        let canonical_sn =
            SortitionDB::get_block_snapshot(self.sortition_db.conn(), &canonical_sortition_tip)?
                .expect("FATAL: canonical sortition tip has no sortition");

        // what epoch are we in?
        let cur_epoch =
            SortitionDB::get_stacks_epoch(self.sortition_db.conn(), canonical_sn.block_height)?
                .expect(&format!(
                    "BUG: no epoch defined at height {}",
                    canonical_sn.block_height
                ));

        if cur_epoch.epoch_id < StacksEpochId::Epoch30 {
            return Ok(false);
        }

        // in epoch3
        let all_epochs = SortitionDB::get_stacks_epochs(self.sortition_db.conn())?;
        let epoch_3_idx = StacksEpoch::find_epoch_by_id(&all_epochs, StacksEpochId::Epoch30)
            .expect("FATAL: epoch3 not defined");

        let epoch3 = &all_epochs[epoch_3_idx];
        let first_epoch3_reward_cycle = self
            .burnchain
            .block_height_to_reward_cycle(epoch3.start_height)
            .expect("FATAL: epoch3 block height has no reward cycle");

        // only proceed if we have processed the _anchor block_ for this reward cycle
        let handle_conn = self.sortition_db.index_handle(&canonical_sortition_tip);
        let last_processed_rc = handle_conn.get_last_processed_reward_cycle()?;
        Ok(last_processed_rc >= first_epoch3_reward_cycle)
    }

    /// This is the main loop body for the coordinator in epoch 3.
    /// Returns true if the coordinator is still running.
    /// Returns false otherwise.
    pub fn handle_comms_nakamoto(
        &mut self,
        comms: &CoordinatorReceivers,
        miner_status: Arc<Mutex<MinerStatus>>,
    ) -> bool {
        // timeout so that we handle Ctrl-C a little gracefully
        let bits = comms.wait_on();
        if (bits & (CoordinatorEvents::NEW_STACKS_BLOCK as u8)) != 0 {
            signal_mining_blocked(miner_status.clone());
            debug!("Received new Nakamoto stacks block notice");
            match self.handle_new_nakamoto_stacks_block() {
                Ok(new_anchor_block_opt) => {
                    if let Some(bhh) = new_anchor_block_opt {
                        debug!(
                            "Found next PoX anchor block, waiting for reward cycle processing";
                            "pox_anchor_block_hash" => %bhh
                        );
                    }
                }
                Err(e) => {
                    warn!("Error processing new stacks block: {:?}", e);
                }
            }

            signal_mining_ready(miner_status.clone());
        }
        if (bits & (CoordinatorEvents::NEW_BURN_BLOCK as u8)) != 0 {
            signal_mining_blocked(miner_status.clone());
            debug!("Received new burn block notice");
            match self.handle_new_nakamoto_burnchain_block() {
                Ok(can_proceed) => {
                    if !can_proceed {
                        error!("Missing canonical anchor block",);
                    }
                }
                Err(e) => {
                    warn!("Error processing new burn block: {:?}", e);
                }
            }
            signal_mining_ready(miner_status.clone());
        }
        if (bits & (CoordinatorEvents::STOP as u8)) != 0 {
            signal_mining_blocked(miner_status.clone());
            debug!("Received stop notice");
            return false;
        }

        true
    }

    /// Handle one or more new Nakamoto Stacks blocks.
    /// If we process a PoX anchor block, then return its block hash.  This unblocks processing the
    /// next reward cycle's burnchain blocks.  Subsequent calls to this function will terminate
    /// with Some(pox-anchor-block-hash) until the reward cycle info is processed in the sortition
    /// DB.
    pub fn handle_new_nakamoto_stacks_block(&mut self) -> Result<Option<BlockHeaderHash>, Error> {
        let canonical_sortition_tip = self.canonical_sortition_tip.clone().expect(
            "FAIL: processing a new Stacks block, but don't have a canonical sortition tip",
        );

        loop {
            // process at most one block per loop pass
            let mut sortdb_handle = self
                .sortition_db
                .tx_handle_begin(&canonical_sortition_tip)?;

            let mut processed_block_receipt = match NakamotoChainState::process_next_nakamoto_block(
                &mut self.chain_state_db,
                &mut sortdb_handle,
                self.dispatcher,
            ) {
                Ok(receipt_opt) => receipt_opt,
                Err(ChainstateError::InvalidStacksBlock(msg)) => {
                    warn!("Encountered invalid block: {}", &msg);

                    // try again
                    self.notifier.notify_stacks_block_processed();
                    increment_stx_blocks_processed_counter();
                    continue;
                }
                Err(ChainstateError::NetError(NetError::DeserializeError(msg))) => {
                    // happens if we load a zero-sized block (i.e. an invalid block)
                    warn!("Encountered invalid block (codec error): {}", &msg);

                    // try again
                    self.notifier.notify_stacks_block_processed();
                    increment_stx_blocks_processed_counter();
                    continue;
                }
                Err(e) => {
                    // something else happened
                    return Err(e.into());
                }
            };

            sortdb_handle.commit()?;

            let Some(block_receipt) = processed_block_receipt.take() else {
                // out of blocks
                debug!("No more blocks to process (no receipts)");
                break;
            };

            let block_hash = block_receipt.header.anchored_header.block_hash();
            let (
                canonical_stacks_block_id,
                canonical_stacks_block_height,
                canonical_stacks_consensus_hash,
            ) = {
                let nakamoto_header = block_receipt
                    .header
                    .anchored_header
                    .as_stacks_nakamoto()
                    .expect("FATAL: unreachable: processed a non-Nakamoto block");

                (
                    nakamoto_header.block_id(),
                    nakamoto_header.chain_length,
                    nakamoto_header.consensus_hash.clone(),
                )
            };

            debug!("Bump blocks processed ({})", &canonical_stacks_block_id);

            self.notifier.notify_stacks_block_processed();
            increment_stx_blocks_processed_counter();

            // process Atlas events
            Self::process_atlas_attachment_events(
                self.atlas_db.as_mut(),
                &self.atlas_config,
                &block_receipt,
                canonical_stacks_block_height,
            );

            // update cost estimator
            if let Some(ref mut estimator) = self.cost_estimator {
                let stacks_epoch = self
                    .sortition_db
                    .index_conn()
                    .get_stacks_epoch_by_epoch_id(&block_receipt.evaluated_epoch)
                    .expect("Could not find a stacks epoch.");
                estimator.notify_block(
                    &block_receipt.tx_receipts,
                    &stacks_epoch.block_limit,
                    &stacks_epoch.epoch_id,
                );
            }

            // update fee estimator
            if let Some(ref mut estimator) = self.fee_estimator {
                let stacks_epoch = self
                    .sortition_db
                    .index_conn()
                    .get_stacks_epoch_by_epoch_id(&block_receipt.evaluated_epoch)
                    .expect("Could not find a stacks epoch.");
                if let Err(e) = estimator.notify_block(&block_receipt, &stacks_epoch.block_limit) {
                    warn!("FeeEstimator failed to process block receipt";
                          "stacks_block" => %block_hash,
                          "stacks_height" => %block_receipt.header.stacks_block_height,
                          "error" => %e);
                }
            }

            let stacks_sn = SortitionDB::get_block_snapshot_consensus(
                &self.sortition_db.conn(),
                &canonical_stacks_consensus_hash,
            )?
            .expect(&format!(
                "FATAL: unreachable: consensus hash {} has no snapshot",
                &canonical_stacks_consensus_hash
            ));

            // are we in the prepare phase?
            if !self.burnchain.is_in_prepare_phase(stacks_sn.block_height) {
                // next ready stacks block
                continue;
            }

            // is the upcoming reward cycle processed yet?
            let current_reward_cycle = self
                .burnchain
                .block_height_to_reward_cycle(stacks_sn.block_height)
                .expect(&format!(
                    "FATAL: unreachable: burnchain block height has no reward cycle"
                ));

            let last_processed_reward_cycle = {
                let ic = self.sortition_db.index_handle(&canonical_sortition_tip);
                ic.get_last_processed_reward_cycle()?
            };

            if last_processed_reward_cycle > current_reward_cycle {
                // already processed upcoming reward cycle
                continue;
            }

            // This is the first Stacks block in the prepare phase for the next reward cycle.
            // Pause here and process the next sortitions
            debug!("Process next reward cycle's sortitions");
            self.handle_new_nakamoto_burnchain_block()?;
            debug!("Processed next reward cycle's sortitions");
        }

        // no PoX anchor block found
        Ok(None)
    }

    /// Given a burnchain header, find the PoX reward cycle info
    fn get_nakamoto_reward_cycle_info(
        &mut self,
        block_height: u64,
    ) -> Result<Option<RewardCycleInfo>, Error> {
        let sortition_tip_id = self
            .canonical_sortition_tip
            .as_ref()
            .expect("FATAL: Processing anchor block, but no known sortition tip");

        get_nakamoto_reward_cycle_info(
            block_height,
            sortition_tip_id,
            &self.burnchain,
            &mut self.chain_state_db,
            &mut self.sortition_db,
            &self.reward_set_provider,
        )
    }

    /// Find sortitions to process.
    /// Returns the last processed ancestor of `cursor`, and any unprocessed burnchain blocks
    fn find_sortitions_to_process(
        &self,
        mut cursor: BurnchainHeaderHash,
    ) -> Result<(SortitionId, VecDeque<BurnchainBlockData>), Error> {
        let mut sortitions_to_process = VecDeque::new();
        let last_processed_ancestor = loop {
            if let Some(found_sortition) = self.sortition_db.is_sortition_processed(&cursor)? {
                debug!(
                    "Ancestor sortition {} of block {} is processed",
                    &found_sortition, &cursor
                );
                break found_sortition;
            }

            let current_block =
                BurnchainDB::get_burnchain_block(&self.burnchain_blocks_db.conn(), &cursor)
                    .map_err(|e| {
                        warn!(
                            "ChainsCoordinator: could not retrieve block burnhash={}",
                            &cursor
                        );
                        Error::NonContiguousBurnchainBlock(e)
                    })?;

            debug!(
                "Unprocessed block: ({}, {})",
                &current_block.header.block_hash.to_string(),
                current_block.header.block_height
            );

            let parent = current_block.header.parent_block_hash.clone();
            sortitions_to_process.push_front(current_block);
            cursor = parent;
        };
        Ok((last_processed_ancestor, sortitions_to_process))
    }

    /// Process the next-available burnchain block, if possible.
    /// Burnchain blocks can only be processed for the last-known PoX reward set, which is to say,
    /// burnchain block processing can be blocked on the unavailability of the next PoX anchor
    /// block.  If the next PoX anchor block is not available, then no burnchain block processing
    /// happens, and this function returns false.  It returns true otherwise.
    ///
    /// Returns Err(..) if an error occurred while processing (i.e. a DB error).
    pub fn handle_new_nakamoto_burnchain_block(&mut self) -> Result<bool, Error> {
        // highest burnchain block we've downloaded
        let canonical_burnchain_tip = self.burnchain_blocks_db.get_canonical_chain_tip()?;

        debug!("Handle new canonical burnchain tip";
               "height" => %canonical_burnchain_tip.block_height,
               "block_hash" => %canonical_burnchain_tip.block_hash.to_string());

        // Retrieve all the direct ancestors of this block with an unprocessed sortition
        let (mut last_processed_ancestor, sortitions_to_process) =
            self.find_sortitions_to_process(canonical_burnchain_tip.block_hash.clone())?;
        let dbg_burn_header_hashes: Vec<_> = sortitions_to_process
            .iter()
            .map(|block| {
                format!(
                    "({}, {})",
                    &block.header.block_hash.to_string(),
                    block.header.block_height
                )
            })
            .collect();

        debug!(
            "Unprocessed burn chain blocks: {:?}",
            &dbg_burn_header_hashes
        );

        // Unlike in Stacks 2.x, there can be neither chain reorgs nor PoX reorgs unless Bitcoin itself
        // reorgs.  But if this happens, then we will have already found the set of
        // (newly-canonical) burnchain blocks which lack sortitions -- they'll be in
        // `sortitions_to_process`.  So, we can proceed to process all outstanding sortitions until
        // we come across a PoX anchor block that we don't have yet.
        for unprocessed_block in sortitions_to_process.into_iter() {
            let BurnchainBlockData { header, ops } = unprocessed_block;
            let reward_cycle = self
                .burnchain
                .block_height_to_reward_cycle(header.block_height)
                .unwrap_or(u64::MAX);

            debug!(
                "Process burn block {} reward cycle {} in {}",
                header.block_height, reward_cycle, &self.burnchain.working_dir,
            );

            info!(
                "Process burn block {} reward cycle {} in {}",
                header.block_height, reward_cycle, &self.burnchain.working_dir;
                "in_prepare_phase" => self.burnchain.is_in_prepare_phase(header.block_height),
                "is_rc_start" => self.burnchain.is_reward_cycle_start(header.block_height),
                "is_prior_in_prepare_phase" => self.burnchain.is_in_prepare_phase(header.block_height.saturating_sub(2)),
            );

            // calculate paid rewards during this burnchain block if we announce
            //  to an events dispatcher
            let paid_rewards = if self.dispatcher.is_some() {
                calculate_paid_rewards(&ops)
            } else {
                PaidRewards {
                    pox: vec![],
                    burns: 0,
                }
            };

            if self.burnchain.is_in_prepare_phase(header.block_height) {
                // try to eagerly load up the reward cycle information, so we can persist it and
                // make it available to signers.  If we're at the _end_ of the prepare phase, then
                // we have no choice but to block.
                let reward_cycle_info = self.get_nakamoto_reward_cycle_info(header.block_height)?;
                if let Some(rc_info) = reward_cycle_info {
                    // in nakamoto, if we have any reward cycle info at all, it will be known.
                    assert!(
                        rc_info.known_selected_anchor_block().is_some(),
                        "FATAL: unknown PoX anchor block in Nakamoto"
                    );
                }
            }

            let reward_cycle_info = if self.burnchain.is_reward_cycle_start(header.block_height) {
                // we're at the end of the prepare phase, so we'd better have obtained the reward
                // cycle info of we must block.
                // N.B. it's `- 2` because `is_reward_cycle_start` implies that `block_height % reward_cycle_length == 1`,
                // but this call needs `block_height % reward_cycle_length == reward_cycle_length - 1` -- i.e. `block_height`
                // must be the last block height in the last reward cycle.
                let reward_cycle_info =
                    self.get_nakamoto_reward_cycle_info(header.block_height - 2)?;
                if let Some(rc_info) = reward_cycle_info.as_ref() {
                    // in nakamoto, if we have any reward cycle info at all, it will be known.
                    assert!(
                        rc_info.known_selected_anchor_block().is_some(),
                        "FATAL: unknown PoX anchor block in Nakamoto"
                    );
                } else {
                    // have to block -- we don't have the reward cycle information
                    debug!("Do not yet have PoX anchor block for next reward cycle -- no anchor block found";
                           "next_reward_cycle" => self.burnchain.block_height_to_reward_cycle(header.block_height),
                           "reward_cycle_end" => header.block_height - 2
                    );
                    return Ok(false);
                }
                reward_cycle_info
            } else {
                // not starting a reward cycle anyway
                None
            };

            // process next sortition
            let dispatcher_ref = &self.dispatcher;
            let (next_snapshot, _) = self
                .sortition_db
                .evaluate_sortition(
                    &header,
                    ops,
                    &self.burnchain,
                    &last_processed_ancestor,
                    reward_cycle_info,
                    |reward_set_info| {
                        if let Some(dispatcher) = dispatcher_ref {
                            dispatcher_announce_burn_ops(
                                *dispatcher,
                                &header,
                                paid_rewards,
                                reward_set_info,
                            );
                        }
                    },
                )
                .map_err(|e| {
                    error!("ChainsCoordinator: unable to evaluate sortition: {:?}", e);
                    Error::FailedToProcessSortition(e)
                })?;

            // mark this burn block as processed in the nakamoto chainstate
            let tx = self.chain_state_db.staging_db_tx_begin()?;
            NakamotoChainState::set_burn_block_processed(&tx, &next_snapshot.consensus_hash)?;
            tx.commit().map_err(DBError::SqliteError)?;

            let sortition_id = next_snapshot.sortition_id;

            self.notifier.notify_sortition_processed();

            debug!(
                "Sortition processed";
                "sortition_id" => &sortition_id.to_string(),
                "burn_header_hash" => &next_snapshot.burn_header_hash.to_string(),
                "burn_height" => next_snapshot.block_height
            );

            // always bump canonical sortition tip:
            //   if this code path is invoked, the canonical burnchain tip
            //   has moved, so we should move our canonical sortition tip as well.
            self.canonical_sortition_tip = Some(sortition_id.clone());
            last_processed_ancestor = sortition_id;
        }

        Ok(true)
    }
}
