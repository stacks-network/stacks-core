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

use std::collections::HashMap;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::net::{Error as NetError, NakamotoInvData};
use crate::util_lib::db::Error as DBError;

/// Cached data for a sortition in the sortition DB.
/// Caching this allows us to avoid calls to `SortitionDB::get_block_snapshot_consensus()`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InvSortitionInfo {
    parent_consensus_hash: ConsensusHash,
    block_height: u64,
}

impl InvSortitionInfo {
    /// Load up cacheable sortition state for a given consensus hash
    pub fn load(
        sortdb: &SortitionDB,
        consensus_hash: &ConsensusHash,
    ) -> Result<InvSortitionInfo, NetError> {
        let sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), consensus_hash)?
            .ok_or(DBError::NotFoundError)?;

        let parent_sn = SortitionDB::get_block_snapshot(sortdb.conn(), &sn.parent_sortition_id)?
            .ok_or(DBError::NotFoundError)?;

        Ok(Self {
            parent_consensus_hash: parent_sn.consensus_hash,
            block_height: sn.block_height,
        })
    }
}

/// Cached data for a TenureChange transaction caused by a BlockFound event.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InvTenureInfo {
    /// This tenure's start-block consensus hash
    tenure_id_consensus_hash: ConsensusHash,
    /// This tenure's parent's start-block consensus hash
    parent_tenure_id_consensus_hash: ConsensusHash,
}

impl InvTenureInfo {
    /// Load up cacheable tenure state for a given tenure-ID consensus hash.
    /// This only returns Ok(Some(..)) if there was a tenure-change tx for this consensus hash.
    pub fn load(
        chainstate: &StacksChainState,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<InvTenureInfo>, NetError> {
        Ok(
            NakamotoChainState::get_highest_nakamoto_tenure_change_by_tenure_id(
                chainstate.db(),
                consensus_hash,
            )?
            .map(|tenure| Self {
                tenure_id_consensus_hash: tenure.tenure_id_consensus_hash,
                parent_tenure_id_consensus_hash: tenure.prev_tenure_id_consensus_hash,
            }),
        )
    }
}

/// This struct represents cached inventory data loaded from Nakamoto headers.
/// It is of the utmost importance that inventory message generation is _fast_, and incurs as
/// little I/O overhead as possible, given how essential these messages are to nodes trying to keep
/// in sync.  By caching (immutable) tenure data in this struct, we can enusre that this happens
/// all the time except for during node bootup.
pub struct InvGenerator {
    processed_tenures: HashMap<ConsensusHash, Option<InvTenureInfo>>,
    sortitions: HashMap<ConsensusHash, InvSortitionInfo>,
}

impl InvGenerator {
    pub fn new() -> Self {
        Self {
            processed_tenures: HashMap::new(),
            sortitions: HashMap::new(),
        }
    }

    /// Get a processed tenure. If it's not cached, then load it.
    /// Returns Some(..) if there existed a tenure-change tx for this given consensus hash
    fn get_processed_tenure(
        &mut self,
        chainstate: &StacksChainState,
        tenure_id_consensus_hash: &ConsensusHash,
    ) -> Result<Option<InvTenureInfo>, NetError> {
        if let Some(info_opt) = self.processed_tenures.get(&tenure_id_consensus_hash) {
            return Ok((*info_opt).clone());
        };
        // not cached so go load it
        let loaded_info_opt = InvTenureInfo::load(chainstate, &tenure_id_consensus_hash)?;
        self.processed_tenures
            .insert(tenure_id_consensus_hash.clone(), loaded_info_opt.clone());
        Ok(loaded_info_opt)
    }

    /// Generate an block inventory bit vector for a reward cycle.
    /// The bit vector is "big-endian" -- the first bit is the oldest sortition, and the last bit is
    /// the newest sortition.  It is structured as follows:
    /// * Bit 0 is the sortition at the start of the given reward cycle
    /// * Bit i is 1 if there was a tenure-start for the ith sortition in the reward cycle, and 0
    /// if not.
    ///
    /// Populate the cached data lazily.
    ///
    /// * `tip` is the canonical sortition tip
    /// * `chainstate` is a handle to the chainstate DB
    /// * `reward_cycle` is the reward cycle for which to generate the inventory
    ///
    /// The resulting bitvector will be truncated if `reward_cycle` is the current reward cycle.
    pub fn make_tenure_bitvector(
        &mut self,
        tip: &BlockSnapshot,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        reward_cycle: u64,
    ) -> Result<Vec<bool>, NetError> {
        let ih = sortdb.index_handle(&tip.sortition_id);
        let reward_cycle_end_height = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, reward_cycle + 1)
            - 2;
        let reward_cycle_end_tip = if tip.block_height <= reward_cycle_end_height {
            tip.clone()
        } else {
            ih.get_block_snapshot_by_height(reward_cycle_end_height)?
                .ok_or(NetError::NotFoundError)?
        };

        let mut tenure_status = vec![];
        let mut cur_height = reward_cycle_end_tip.block_height;
        let mut cur_consensus_hash = reward_cycle_end_tip.consensus_hash;

        let mut cur_tenure_opt = self.get_processed_tenure(chainstate, &cur_consensus_hash)?;

        // loop variables and invariants:
        //
        // * `cur_height` is a "cursor" that gets used to populate the bitmap. It corresponds
        // to a burnchain block height (since inventory bitvectors correspond to sortitions).
        // It gets decremented once per loop pass.  The loop terminates once the reward cycle
        // for `cur_height` is less than the given `reward_cycle`.
        //
        // * `cur_consensus_hash` refers to the consensus hash of the sortition at `cur_height`. It
        // is updated once per loop pass.
        //
        // * `tenure_status` is the bit vector itself.  On each pass of this loop, `true` or
        // `false` is pushed to it.  When the loop exits, `tenure_status` will have a `true` or
        // `false` value for each sortition in the given reward cycle.
        //
        // `cur_tenure_opt` refers to the tenure that is active as of `cur_height`, if there is one.
        // If there is an active tenure in `cur_height`, then if the sortition at `cur_height`
        // matches the `tenure_id_consensus_hash` of `cur_tenure_opt`, `cur_tenure_opt` is
        // set to its parent tenure, and we push `true` to `tenure_status`.  This is the only
        // time we do this, since since `cur_tenure_opt`'s `tenure_id_consensus_hash` only
        // ever matches `cur_consensus_hash` if a tenure began at `cur_height`.  If a tenure did _not_
        // begin at `cur_height`, or if there is no active tenure at `cur_height`, then `tenure_status`.
        // will have `false` for `cur_height`'s bit.
        loop {
            let cur_reward_cycle = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, cur_height)
                .ok_or(NetError::ChainstateError(
                    "block height comes before system start".into(),
                ))?;
            if cur_reward_cycle < reward_cycle {
                // done scanning this reward cycle
                break;
            }
            let cur_sortition_info = if let Some(info) = self.sortitions.get(&cur_consensus_hash) {
                info
            } else {
                let loaded_info = InvSortitionInfo::load(sortdb, &cur_consensus_hash)?;
                self.sortitions
                    .insert(cur_consensus_hash.clone(), loaded_info);
                self.sortitions
                    .get(&cur_consensus_hash)
                    .expect("infallible: just inserted this data".into())
            };
            let parent_sortition_consensus_hash = cur_sortition_info.parent_consensus_hash.clone();

            test_debug!("Get sortition and tenure info for height {}. cur_consensus_hash = {}, cur_tenure_info = {:?}, cur_sortition_info = {:?}", cur_height, &cur_consensus_hash, &cur_tenure_opt, cur_sortition_info);

            if let Some(cur_tenure_info) = cur_tenure_opt.as_ref() {
                // a tenure was active when this sortition happened...
                if cur_tenure_info.tenure_id_consensus_hash == cur_consensus_hash {
                    // ...and this tenure started in this sortition
                    tenure_status.push(true);
                    cur_tenure_opt = self.get_processed_tenure(
                        chainstate,
                        &cur_tenure_info.parent_tenure_id_consensus_hash,
                    )?;
                } else {
                    // ...but this tenure did not start in this sortition
                    tenure_status.push(false);
                }
            } else {
                // no active tenure during this sortition. Check the parent sortition to see if a
                // tenure begain there.
                tenure_status.push(false);
                cur_tenure_opt =
                    self.get_processed_tenure(chainstate, &parent_sortition_consensus_hash)?;
            }

            // next sortition
            cur_consensus_hash = parent_sortition_consensus_hash;
            if cur_height == 0 {
                break;
            }
            cur_height = cur_height.saturating_sub(1);
        }

        tenure_status.reverse();
        Ok(tenure_status)
    }
}
