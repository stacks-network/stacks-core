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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, PoxId, SortitionId, StacksBlockId,
};
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, log};
use wsts::curve::point::Point;

use crate::burnchains::{Burnchain, BurnchainView, PoxConstants};
use crate::chainstate::burn::db::sortdb::{
    BlockHeaderCache, SortitionDB, SortitionDBConn, SortitionHandleConn,
};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, NakamotoStagingBlocksConnRef,
};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    Error as chainstate_error, StacksBlockHeader, TenureChangePayload,
};
use crate::core::{
    EMPTY_MICROBLOCK_PARENT_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::chat::ConversationP2P;
use crate::net::db::{LocalPeer, PeerDB};
use crate::net::download::nakamoto::{
    AvailableTenures, NakamotoTenureDownloader, NakamotoTenureDownloaderSet,
    NakamotoUnconfirmedTenureDownloader, TenureStartEnd, WantedTenure,
};
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{StacksHttpRequest, StacksHttpResponse};
use crate::net::inv::epoch2x::InvState;
use crate::net::inv::nakamoto::{NakamotoInvStateMachine, NakamotoTenureInv};
use crate::net::neighbors::rpc::NeighborRPC;
use crate::net::neighbors::NeighborComms;
use crate::net::p2p::PeerNetwork;
use crate::net::server::HttpPeer;
use crate::net::{Error as NetError, Neighbor, NeighborAddress, NeighborKey};
use crate::util_lib::db::{DBConn, Error as DBError};

/// The overall downloader can operate in one of two states:
/// * it's doing IBD, in which case it's downloading tenures using neighbor inventories and
/// the start/end block ID hashes obtained from block-commits.  This works up until the last two
/// tenures.
/// * it's in steady-state, in which case it's downloading the last two tenures from its neighbors.
#[derive(Debug, Clone, PartialEq)]
pub enum NakamotoDownloadState {
    /// confirmed tenure download (IBD)
    Confirmed,
    /// unconfirmed tenure download (steady-state)
    Unconfirmed,
}

impl fmt::Display for NakamotoDownloadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The top-level block download state machine
pub struct NakamotoDownloadStateMachine {
    /// What's the start burn block height for Nakamoto?
    nakamoto_start_height: u64,
    /// What's the current reward cycle we're tracking?
    pub(crate) reward_cycle: u64,
    /// List of (possible) tenures in the current reward cycle
    pub(crate) wanted_tenures: Vec<WantedTenure>,
    /// List of (possible) tenures in the previous reward cycle. Will be None in the first reward
    /// cycle of Nakamoto
    pub(crate) prev_wanted_tenures: Option<Vec<WantedTenure>>,
    /// Last burnchain tip we've seen
    last_sort_tip: Option<BlockSnapshot>,
    /// Download behavior we're in
    state: NakamotoDownloadState,
    /// Map a tenure ID to its tenure start-block and end-block for each of our neighbors' invs
    tenure_block_ids: HashMap<NeighborAddress, AvailableTenures>,
    /// Who can serve a given tenure
    pub(crate) available_tenures: HashMap<ConsensusHash, Vec<NeighborAddress>>,
    /// Confirmed tenure download schedule
    pub(crate) tenure_download_schedule: VecDeque<ConsensusHash>,
    /// Unconfirmed tenure download schedule
    unconfirmed_tenure_download_schedule: VecDeque<NeighborAddress>,
    /// Ongoing unconfirmed tenure downloads, prioritized in who announces the latest block
    unconfirmed_tenure_downloads: HashMap<NeighborAddress, NakamotoUnconfirmedTenureDownloader>,
    /// Ongoing confirmed tenure downloads for when we know the start and end block hashes.
    tenure_downloads: NakamotoTenureDownloaderSet,
    /// resolved tenure-start blocks
    tenure_start_blocks: HashMap<StacksBlockId, NakamotoBlock>,
    /// comms to remote neighbors
    pub(super) neighbor_rpc: NeighborRPC,
}

impl NakamotoDownloadStateMachine {
    pub fn new(nakamoto_start_height: u64) -> Self {
        Self {
            nakamoto_start_height,
            reward_cycle: 0, // will be calculated at runtime
            wanted_tenures: vec![],
            prev_wanted_tenures: None,
            last_sort_tip: None,
            state: NakamotoDownloadState::Confirmed,
            tenure_block_ids: HashMap::new(),
            available_tenures: HashMap::new(),
            tenure_download_schedule: VecDeque::new(),
            unconfirmed_tenure_download_schedule: VecDeque::new(),
            tenure_downloads: NakamotoTenureDownloaderSet::new(),
            unconfirmed_tenure_downloads: HashMap::new(),
            tenure_start_blocks: HashMap::new(),
            neighbor_rpc: NeighborRPC::new(),
        }
    }

    /// Get a range of wanted tenures between two burnchain blocks.
    /// Each wanted tenure's .processed flag will be set to false.
    ///
    /// Returns the tenures from first_block_height (inclusive) to last_block_height (exclusive) on
    /// success.
    ///
    /// Returns Err(..) on DB error, or if one or both of these heights do not correspond to a
    /// sortition.
    pub(crate) fn load_wanted_tenures(
        ih: &SortitionHandleConn,
        first_block_height: u64,
        last_block_height: u64,
    ) -> Result<Vec<WantedTenure>, NetError> {
        let mut wanted_tenures = Vec::with_capacity(
            usize::try_from(last_block_height.saturating_sub(first_block_height))
                .expect("FATAL: infallible: usize can't old a reward cycle"),
        );
        let mut cursor = ih
            .get_block_snapshot_by_height(last_block_height.saturating_sub(1))?
            .ok_or(DBError::NotFoundError)?;
        while cursor.block_height >= first_block_height {
            test_debug!(
                "Load sortition {}/{} burn height {}",
                &cursor.consensus_hash,
                &cursor.winning_stacks_block_hash,
                cursor.block_height
            );
            wanted_tenures.push(WantedTenure::new(
                cursor.consensus_hash,
                StacksBlockId(cursor.winning_stacks_block_hash.0),
                cursor.block_height,
            ));
            cursor = SortitionDB::get_block_snapshot(&ih, &cursor.parent_sortition_id)?
                .ok_or(DBError::NotFoundError)?;
        }
        wanted_tenures.reverse();
        Ok(wanted_tenures)
    }

    /// Update a given list of wanted tenures (`wanted_tenures`), which may already have wanted
    /// tenures.  Appends new tenures for the given reward cycle (`cur_rc`) to `wanted_tenures`.
    ///
    /// Returns Ok(()) on sucess, and appends new tenures in the given reward cycle (`cur_rc`) to
    /// `wanted_tenures`.
    /// Returns Err(..) on DB errors.
    pub(crate) fn update_wanted_tenures_for_reward_cycle(
        cur_rc: u64,
        tip: &BlockSnapshot,
        sortdb: &SortitionDB,
        wanted_tenures: &mut Vec<WantedTenure>,
    ) -> Result<(), NetError> {
        let highest_tenure_height = wanted_tenures.last().map(|wt| wt.burn_height).unwrap_or(0);

        // careful -- need .saturating_sub(1) since this calculation puts the reward cycle start at
        // block height 1 mod reward cycle len, but we really want 0 mod reward cycle len
        let first_block_height = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, cur_rc)
            .saturating_sub(1)
            .max(highest_tenure_height.saturating_add(1));

        let last_block_height = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, cur_rc.saturating_add(1))
            .saturating_sub(1)
            .min(tip.block_height.saturating_add(1));

        if highest_tenure_height > last_block_height {
            test_debug!(
                "Will NOT update wanted tenures for reward cycle {}: {} > {}",
                cur_rc,
                highest_tenure_height,
                last_block_height
            );
            return Ok(());
        }

        test_debug!(
            "Update reward cycle sortitions between {} and {} (rc is {})",
            first_block_height,
            last_block_height,
            cur_rc
        );

        // find all sortitions in this reward cycle
        let ih = sortdb.index_handle(&tip.sortition_id);
        let mut new_tenures =
            Self::load_wanted_tenures(&ih, first_block_height, last_block_height)?;
        wanted_tenures.append(&mut new_tenures);
        Ok(())
    }

    /// Given the last-considered sortition tip and the current sortition tip, and a list of wanted
    /// tenures loaded so far, load up any new wanted tenure data _in the same reward cycle_.  Used
    /// during steady-state to load up new tenures after the sorittion DB advances.
    ///
    /// It may return zero tenures.
    ///
    /// Returns Ok(new-tenures) on success.
    /// Returns Err(..) on error.
    pub(crate) fn load_wanted_tenures_at_tip(
        last_tip: Option<&BlockSnapshot>,
        tip: &BlockSnapshot,
        sortdb: &SortitionDB,
        loaded_so_far: &[WantedTenure],
    ) -> Result<Vec<WantedTenure>, NetError> {
        let tip_rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap_or(0);

        let first_block_height = if let Some(highest_wanted_tenure) = loaded_so_far.last() {
            highest_wanted_tenure.burn_height.saturating_add(1)
        } else if let Some(last_tip) = last_tip.as_ref() {
            last_tip.block_height.saturating_add(1)
        } else {
            // careful -- need .saturating_sub(1) since this calculation puts the reward cycle start at
            // block height 1 mod reward cycle len, but we really want 0 mod reward cycle len.
            sortdb
                .pox_constants
                .reward_cycle_to_block_height(sortdb.first_block_height, tip_rc)
                .saturating_sub(1)
        };

        // be extra careful with last_block_height -- we not only account for the above, but also
        // we need to account for the fact that `load_wanted_tenures` does not load the sortition
        // of the last block height (but we want this!)
        let last_block_height = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, tip_rc.saturating_add(1))
            .saturating_sub(1)
            .min(tip.block_height)
            .saturating_add(1);

        test_debug!(
            "Load tip sortitions between {} and {} (loaded_so_far = {})",
            first_block_height,
            last_block_height,
            loaded_so_far.len()
        );
        if last_block_height < first_block_height {
            return Ok(vec![]);
        }

        let ih = sortdb.index_handle(&tip.sortition_id);
        let wanted_tenures = Self::load_wanted_tenures(&ih, first_block_height, last_block_height)?;

        test_debug!(
            "Loaded tip sortitions between {} and {} (loaded_so_far = {}): {:?}",
            first_block_height,
            last_block_height,
            loaded_so_far.len(),
            &wanted_tenures
        );
        Ok(wanted_tenures)
    }

    /// Update the .processed state for each given wanted tenure.
    /// Set it to true if any of the following are true:
    /// * the tenure is before the nakamoto start height
    /// * we have processed the entire tenure
    ///
    /// This function exists as a static function for ease of testing.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(..) on DB error
    pub(crate) fn inner_update_processed_wanted_tenures(
        nakamoto_start: u64,
        wanted_tenures: &mut [WantedTenure],
        chainstate: &StacksChainState,
    ) -> Result<(), NetError> {
        for wt in wanted_tenures.iter_mut() {
            test_debug!("update_processed_wanted_tenures: consider {:?}", &wt);
            if wt.processed {
                continue;
            }
            if wt.burn_height < nakamoto_start {
                // not our problem
                wt.processed = true;
                continue;
            }
            if NakamotoChainState::has_processed_nakamoto_tenure(
                chainstate.db(),
                &wt.tenure_id_consensus_hash,
            )? {
                test_debug!("Tenure {} is now processed", &wt.tenure_id_consensus_hash);
                wt.processed = true;
                continue;
            }
        }
        Ok(())
    }

    /// Update the .processed state for each wanted tenure in the `prev_wanted_tenures` and
    /// `wanted_tenures` lists.
    ///
    /// Returns Ok(()) on success
    /// Returns Err(..) on DB error
    pub(crate) fn update_processed_tenures(
        &mut self,
        chainstate: &StacksChainState,
    ) -> Result<(), NetError> {
        if let Some(prev_wanted_tenures) = self.prev_wanted_tenures.as_mut() {
            test_debug!("update_processed_wanted_tenures: update prev_tenures");
            Self::inner_update_processed_wanted_tenures(
                self.nakamoto_start_height,
                prev_wanted_tenures,
                chainstate,
            )?;
        }
        test_debug!("update_processed_wanted_tenures: update wanted_tenures");
        Self::inner_update_processed_wanted_tenures(
            self.nakamoto_start_height,
            &mut self.wanted_tenures,
            chainstate,
        )
    }

    /// Find all stored (but not necessarily processed) tenure-start blocks for a list
    /// of wanted tenures that this node has locally.  NOTE: these tenure-start blocks
    /// do not correspond to the tenure; they correspond to the _parent_ tenure (since a
    /// `WantedTenure` captures the tenure-start block hash of the parent tenure; the same data
    /// captured by a sortition).
    ///
    /// This method is static to ease testing.
    ///
    /// Returns Ok(()) on success and fills in newly-discovered blocks into `tenure_start_blocks`.
    /// Returns Err(..) on DB error.
    pub(crate) fn load_tenure_start_blocks(
        wanted_tenures: &[WantedTenure],
        chainstate: &StacksChainState,
        tenure_start_blocks: &mut HashMap<StacksBlockId, NakamotoBlock>,
    ) -> Result<(), NetError> {
        for wt in wanted_tenures {
            let Some(tenure_start_block) = chainstate
                .nakamoto_blocks_db()
                .get_nakamoto_tenure_start_block(&wt.tenure_id_consensus_hash)?
            else {
                test_debug!("No tenure-start block for {}", &wt.tenure_id_consensus_hash);
                continue;
            };
            tenure_start_blocks.insert(tenure_start_block.block_id(), tenure_start_block);
        }
        Ok(())
    }

    /// Update our local tenure start block data
    fn update_tenure_start_blocks(
        &mut self,
        chainstate: &StacksChainState,
    ) -> Result<(), NetError> {
        Self::load_tenure_start_blocks(
            &self.wanted_tenures,
            chainstate,
            &mut self.tenure_start_blocks,
        )
    }

    /// Update `self.wanted_tenures` and `self.prev_wanted_tenures` with newly-discovered sortition
    /// data.  These lists are extended in three possible ways, depending on the sortition tip:
    ///
    /// * If the sortition tip is in the same reward cycle that the block downloader is tracking,
    /// then any newly-available sortitions are loaded via `load_wanted_tenures_at_tip()` and appended
    /// to `self.wanted_tenures`.  This is what happens most of the time in steady-state.
    ///
    /// * Otherwise, if the sortition tip is different (i.e. ahead) of the block downloader's
    /// tracked reward cycle, _and_ if it's safe to do so (discussed below), then the next reward
    /// cycle's sortitions are loaded.  `self.prev_wanted_tenures` is populated with all of the
    /// wanted tenures from the prior reward cycle, and `self.wanted_tenures` is populated with all
    /// of the wanted tenures from the current reward cycle.
    ///
    /// Due to the way the chains coordinator works, the sortition DB will never be more than one
    /// reward cycle ahead of the block downloader.  This is because sortitions cannot be processed
    /// (and will not be processed) until their corresponding PoX anchor block has been processed.
    /// As such, the second case above only occurs at a reward cycle boundary -- specifically, the
    /// sortition DB is in the process of being updated by the chains coordinator with the next
    /// reward cycle's sortitions.
    ///
    /// Naturally, processing a new reward cycle is disruptive to the download state machine, which
    /// can be in the process of finishing up downloading the prepare phase for a reward cycle at
    /// the same time as the sortition DB processing the next reward cycle.  To ensure that the
    /// downloader doesn't miss anything, this code checks (via `have_unprocessed_tenures()`) that
    /// all wanted tenures for which we have inventory data have been downloaded before advancing
    /// `self.wanted_tenures` and `self.prev_wanted_tenures.`
    fn extend_wanted_tenures(
        &mut self,
        network: &PeerNetwork,
        sortdb: &SortitionDB,
    ) -> Result<(), NetError> {
        let sort_tip = &network.burnchain_tip;
        let Some(invs) = network.inv_state_nakamoto.as_ref() else {
            // nothing to do
            test_debug!("No network inventories");
            return Err(NetError::PeerNotConnected);
        };

        let last_sort_height_opt = self.last_sort_tip.as_ref().map(|sn| sn.block_height);
        let last_sort_height = last_sort_height_opt.unwrap_or(sort_tip.block_height);
        let sort_rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, last_sort_height)
            .expect("FATAL: burnchain tip is before system start");

        let mut new_wanted_tenures = Self::load_wanted_tenures_at_tip(
            self.last_sort_tip.as_ref(),
            sort_tip,
            sortdb,
            &self.wanted_tenures,
        )?;

        let can_advance_wanted_tenures =
            if let Some(prev_wanted_tenures) = self.prev_wanted_tenures.as_ref() {
                !Self::have_unprocessed_tenures(
                    sortdb
                        .pox_constants
                        .block_height_to_reward_cycle(
                            sortdb.first_block_height,
                            self.nakamoto_start_height,
                        )
                        .expect("FATAL: first nakamoto block from before system start"),
                    &self.tenure_downloads.completed_tenures,
                    prev_wanted_tenures,
                    &self.tenure_block_ids,
                    &sortdb.pox_constants,
                    sortdb.first_block_height,
                    invs.inventories.values(),
                )
            } else {
                test_debug!("No prev_wanted_tenures yet");
                true
            };

        if can_advance_wanted_tenures && self.reward_cycle != sort_rc {
            let mut prev_wanted_tenures = vec![];
            let mut cur_wanted_tenures = vec![];
            let prev_wts = self.prev_wanted_tenures.take().unwrap_or(vec![]);
            let cur_wts = std::mem::replace(&mut self.wanted_tenures, vec![]);

            for wt in new_wanted_tenures
                .into_iter()
                .chain(prev_wts.into_iter())
                .chain(cur_wts.into_iter())
            {
                test_debug!("Consider wanted tenure: {:?}", &wt);
                let wt_rc = sortdb
                    .pox_constants
                    .block_height_to_reward_cycle(sortdb.first_block_height, wt.burn_height)
                    .expect("FATAL: height before system start");
                if wt_rc + 1 == sort_rc {
                    prev_wanted_tenures.push(wt);
                } else if wt_rc == sort_rc {
                    cur_wanted_tenures.push(wt);
                } else {
                    test_debug!("Drop wanted tenure: {:?}", &wt);
                }
            }

            prev_wanted_tenures.sort_unstable_by_key(|wt| wt.burn_height);
            cur_wanted_tenures.sort_unstable_by_key(|wt| wt.burn_height);

            test_debug!("prev_wanted_tenures is now {:?}", &prev_wanted_tenures);
            test_debug!("wanted_tenures is now {:?}", &cur_wanted_tenures);

            self.prev_wanted_tenures = if prev_wanted_tenures.is_empty() {
                None
            } else {
                Some(prev_wanted_tenures)
            };
            self.wanted_tenures = cur_wanted_tenures;
            self.reward_cycle = sort_rc;
        } else {
            test_debug!(
                "Append {} wanted tenures: {:?}",
                new_wanted_tenures.len(),
                &new_wanted_tenures
            );
            self.wanted_tenures.append(&mut new_wanted_tenures);
            test_debug!("wanted_tenures is now {:?}", &self.wanted_tenures);
        }

        Ok(())
    }

    /// Initialize `self.wanted_tenures` and `self.prev_wanted_tenures` for the first time, if they
    /// are not set up yet.  At all times, `self.prev_wanted_tenures` ought to be initialized to the last
    /// full reward cycle's tenures, and `self.wanted_tenures` ought to be initialized to the
    /// ongoing reward cycle's tenures.
    pub(crate) fn initialize_wanted_tenures(
        &mut self,
        sort_tip: &BlockSnapshot,
        sortdb: &SortitionDB,
    ) -> Result<(), NetError> {
        // check for reorgs
        let reorg = PeerNetwork::is_reorg(self.last_sort_tip.as_ref(), sort_tip, sortdb);
        if reorg {
            // force a reload
            test_debug!("Detected reorg! Refreshing wanted tenures");
            self.prev_wanted_tenures = None;
            self.wanted_tenures.clear();
        }

        if self
            .prev_wanted_tenures
            .as_ref()
            .map(|pwts| pwts.len())
            .unwrap_or(0)
            < usize::try_from(sortdb.pox_constants.reward_cycle_length)
                .expect("FATAL: usize cannot support reward cycle length")
        {
            // this is the first-ever pass, so load up the last full reward cycle
            let sort_rc = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, sort_tip.block_height)
                .expect("FATAL: burnchain tip is before system start")
                .saturating_sub(1);

            let mut prev_wanted_tenures = vec![];
            Self::update_wanted_tenures_for_reward_cycle(
                sort_rc,
                sort_tip,
                sortdb,
                &mut prev_wanted_tenures,
            )?;

            test_debug!(
                "initial prev_wanted_tenures (rc {}): {:?}",
                sort_rc,
                &prev_wanted_tenures
            );
            self.prev_wanted_tenures = Some(prev_wanted_tenures);
        }
        if self.wanted_tenures.is_empty() {
            // this is the first-ever pass, so load up the current reward cycle
            let sort_rc = sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, sort_tip.block_height)
                .expect("FATAL: burnchain tip is before system start");

            let mut wanted_tenures = vec![];
            Self::update_wanted_tenures_for_reward_cycle(
                sort_rc,
                sort_tip,
                sortdb,
                &mut wanted_tenures,
            )?;

            test_debug!(
                "initial wanted_tenures (rc {}): {:?}",
                sort_rc,
                &wanted_tenures
            );
            self.wanted_tenures = wanted_tenures;
            self.reward_cycle = sort_rc;
        }
        Ok(())
    }

    /// Determine if the set of `TenureStartEnd`s represents available but unfetched data.  Used to
    /// determine whether or not to update the set of wanted tenures -- we don't want to skip
    /// fetching wanted tenures if they're still available!
    pub(crate) fn have_unprocessed_tenures<'a>(
        first_nakamoto_rc: u64,
        completed_tenures: &HashSet<ConsensusHash>,
        prev_wanted_tenures: &[WantedTenure],
        tenure_block_ids: &HashMap<NeighborAddress, AvailableTenures>,
        pox_constants: &PoxConstants,
        first_burn_height: u64,
        inventory_iter: impl Iterator<Item = &'a NakamotoTenureInv>,
    ) -> bool {
        if prev_wanted_tenures.is_empty() {
            return true;
        }

        // the anchor block for prev_wanted_tenures must not only be processed, but also we have to
        // have seen an inventory message from the subsequent reward cycle.  If we can see
        // inventory messages for the reward cycle after `prev_wanted_rc`, then the former will be
        // true
        let prev_wanted_rc = prev_wanted_tenures
            .first()
            .map(|wt| {
                pox_constants
                    .block_height_to_reward_cycle(first_burn_height, wt.burn_height)
                    .expect("FATAL: wanted tenure before system start")
            })
            .unwrap_or(u64::MAX);

        let cur_wanted_rc = prev_wanted_rc.saturating_add(1);

        let mut has_prev_inv = false;
        let mut has_cur_inv = false;
        for inv in inventory_iter {
            if prev_wanted_rc < first_nakamoto_rc {
                // assume the epoch 2.x inventory has this
                has_prev_inv = true;
            } else if inv.tenures_inv.get(&prev_wanted_rc).is_some() {
                has_prev_inv = true;
            }

            if cur_wanted_rc < first_nakamoto_rc {
                // assume the epoch 2.x inventory has this
                has_cur_inv = true;
            } else if inv.tenures_inv.get(&cur_wanted_rc).is_some() {
                has_cur_inv = true;
            }
        }

        if !has_prev_inv || !has_cur_inv {
            debug!("No peer has an inventory for either the previous ({}: available = {}) or current ({}: available = {}) wanted tenures", prev_wanted_rc, has_prev_inv, cur_wanted_rc, has_cur_inv);
            return true;
        }

        // the state machine updates `tenure_block_ids` _after_ `wanted_tenures`, so verify that
        // this isn't a stale `tenure_block_ids` by checking that it contains at least one block in
        // the prev_wanted_rc and at least one in the cur_wanted_rc
        let mut has_prev_rc_block = false;
        let mut has_cur_rc_block = false;
        for (_naddr, available) in tenure_block_ids.iter() {
            for (_ch, tenure_info) in available.iter() {
                if tenure_info.start_reward_cycle == prev_wanted_rc
                    || tenure_info.end_reward_cycle == prev_wanted_rc
                {
                    has_prev_rc_block = true;
                }
                if tenure_info.start_reward_cycle == cur_wanted_rc
                    || tenure_info.end_reward_cycle == cur_wanted_rc
                {
                    has_cur_rc_block = true;
                }
            }
        }

        if (prev_wanted_rc >= first_nakamoto_rc && !has_prev_rc_block)
            || (cur_wanted_rc >= first_nakamoto_rc && !has_cur_rc_block)
        {
            debug!(
                "tenure_block_ids stale: missing representation in reward cycles {} ({}) and {} ({})",
                prev_wanted_rc,
                has_prev_rc_block,
                cur_wanted_rc,
                has_cur_rc_block,
            );
            return true;
        }

        let mut ret = false;
        for (_naddr, available) in tenure_block_ids.iter() {
            for wt in prev_wanted_tenures.iter() {
                let Some(tenure_info) = available.get(&wt.tenure_id_consensus_hash) else {
                    continue;
                };
                if completed_tenures.contains(&tenure_info.tenure_id_consensus_hash) {
                    // this check is necessary because the check for .processed requires that a
                    // child tenure block has been processed, which isn't guaranteed at a reward
                    // cycle boundary
                    test_debug!("Tenure {:?} has been fully downloaded", &tenure_info);
                    continue;
                }
                if !tenure_info.processed {
                    test_debug!(
                        "Tenure {:?} is available from {} but not processed",
                        &tenure_info,
                        &_naddr
                    );
                    ret = true;
                }
            }
        }
        ret
    }

    /// Update the state machine's wanted tenures and processed tenures, if it's time to do so.
    /// This will only happen when the sortition DB has finished processing a reward cycle of
    /// tenures when in IBD mode, _OR_ when the sortition tip advances when in steady-state mode.
    /// This is the top-level method for managing `self.wanted_tenures` and
    /// `self.prev_wanted_tenures`.
    ///
    /// In the first case, this function will load up the whole list of wanted
    /// tenures for this reward cycle, and proceed to download them.  This happens only on reward
    /// cycle boundaries, where the sortition DB is about to begin processing a new reward cycle.
    /// The list of wanted tenures for the current reward cycle will be saved as
    /// `self.prev_wanted_tenures`, and the set of wanted tenures for the next reward cycle
    /// will be stored to `self.wanted_tenures`.  It will only update these two lists if it is safe
    /// to do so, as determined by `have_unprocessed_tenures()`.
    ///
    /// In the second case (i.e. not a reward cycle boundary), this function will load up _new_
    /// wanted tenure data and append it to `self.wanted_tenures` via
    /// `self.extend_wanted_tenures()` above.  If it turns out that the downloader's tracked reward
    /// cycle is behind the sortition DB tip's reward cycle, then this will update
    /// `self.wnated_tenures` and `self.prev_wanted_tenures` if it is safe to do so.
    pub(crate) fn update_wanted_tenures(
        &mut self,
        network: &PeerNetwork,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
    ) -> Result<(), NetError> {
        let sort_tip = &network.burnchain_tip;
        let Some(invs) = network.inv_state_nakamoto.as_ref() else {
            // nothing to do
            test_debug!("No network inventories");
            return Err(NetError::PeerNotConnected);
        };

        self.initialize_wanted_tenures(sort_tip, sortdb)?;
        let last_sort_height_opt = self.last_sort_tip.as_ref().map(|sn| sn.block_height);
        let last_sort_height = last_sort_height_opt.unwrap_or(sort_tip.block_height);
        let sort_rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, last_sort_height)
            .expect("FATAL: burnchain tip is before system start");

        let next_sort_rc = if last_sort_height == sort_tip.block_height {
            sortdb
                .pox_constants
                .block_height_to_reward_cycle(
                    sortdb.first_block_height,
                    sort_tip.block_height.saturating_add(1),
                )
                .expect("FATAL: burnchain tip is before system start")
        } else {
            sortdb
                .pox_constants
                .block_height_to_reward_cycle(sortdb.first_block_height, sort_tip.block_height)
                .expect("FATAL: burnchain tip is before system start")
        };

        test_debug!(
            "last_sort_height = {}, sort_rc = {}, next_sort_rc = {}, self.reward_cycle = {}, sort_tip.block_height = {}",
            last_sort_height,
            sort_rc,
            next_sort_rc,
            self.reward_cycle,
            sort_tip.block_height,
        );

        if sort_rc == next_sort_rc {
            // not at a reward cycle boundary, os just extend self.wanted_tenures
            test_debug!("Extend wanted tenures since no sort_rc change and we have tenure data");
            self.extend_wanted_tenures(network, sortdb)?;
            self.update_tenure_start_blocks(chainstate)?;
            return Ok(());
        }

        let can_advance_wanted_tenures =
            if let Some(prev_wanted_tenures) = self.prev_wanted_tenures.as_ref() {
                !Self::have_unprocessed_tenures(
                    sortdb
                        .pox_constants
                        .block_height_to_reward_cycle(
                            sortdb.first_block_height,
                            self.nakamoto_start_height,
                        )
                        .expect("FATAL: nakamoto starts before system start"),
                    &self.tenure_downloads.completed_tenures,
                    prev_wanted_tenures,
                    &self.tenure_block_ids,
                    &sortdb.pox_constants,
                    sortdb.first_block_height,
                    invs.inventories.values(),
                )
            } else {
                test_debug!("No prev_wanted_tenures yet");
                true
            };
        if !can_advance_wanted_tenures {
            return Ok(());
        }

        // crossed reward cycle boundary
        let mut new_wanted_tenures = vec![];
        Self::update_wanted_tenures_for_reward_cycle(
            sort_rc + 1,
            sort_tip,
            sortdb,
            &mut new_wanted_tenures,
        )?;

        let mut new_prev_wanted_tenures = vec![];
        Self::update_wanted_tenures_for_reward_cycle(
            sort_rc,
            sort_tip,
            sortdb,
            &mut new_prev_wanted_tenures,
        )?;

        test_debug!("new_wanted_tenures is now {:?}", &new_wanted_tenures);
        test_debug!(
            "new_prev_wanted_tenures is now {:?}",
            &new_prev_wanted_tenures
        );

        self.prev_wanted_tenures = if new_prev_wanted_tenures.is_empty() {
            None
        } else {
            Some(new_prev_wanted_tenures)
        };
        self.wanted_tenures = new_wanted_tenures;
        self.reward_cycle = sort_rc;

        self.update_tenure_start_blocks(chainstate)?;
        Ok(())
    }

    /// Given a set of inventory bit vectors for the current reward cycle, find out which neighbors
    /// can serve each tenure (identified by the tenure ID consensus hash).
    /// Every tenure ID consensus hash in `wanted_tenures` will be mapped to the returned hash
    /// table, but the list of addresses may be empty if no neighbor reports having that tenure.
    pub(crate) fn find_available_tenures<'a>(
        reward_cycle: u64,
        wanted_tenures: &[WantedTenure],
        mut inventory_iter: impl Iterator<Item = (&'a NeighborAddress, &'a NakamotoTenureInv)>,
    ) -> HashMap<ConsensusHash, Vec<NeighborAddress>> {
        let mut available: HashMap<ConsensusHash, Vec<NeighborAddress>> = HashMap::new();
        for wt in wanted_tenures.iter() {
            available.insert(wt.tenure_id_consensus_hash.clone(), vec![]);
        }

        while let Some((naddr, inv)) = inventory_iter.next() {
            let Some(rc_inv) = inv.tenures_inv.get(&reward_cycle) else {
                // this peer has no inventory data for this reward cycle
                debug!(
                    "Peer {} has no inventory for reward cycle {}",
                    naddr, reward_cycle
                );
                continue;
            };
            for (i, wt) in wanted_tenures.iter().enumerate() {
                if wt.processed {
                    continue;
                }

                let (ch, ibh) = (&wt.tenure_id_consensus_hash, &wt.winning_block_id);
                if ibh == &StacksBlockId([0x00; 32]) {
                    continue;
                }

                let bit = u16::try_from(i).expect("FATAL: more sortitions than u16::MAX");
                if !rc_inv.get(bit).unwrap_or(false) {
                    // this neighbor does not have this tenure
                    test_debug!(
                        "Peer {} does not have sortition #{} in reward cycle {} (wt {:?})",
                        naddr,
                        bit,
                        reward_cycle,
                        &wt
                    );
                    continue;
                }

                if let Some(neighbor_list) = available.get_mut(ch) {
                    neighbor_list.push(naddr.clone());
                } else {
                    available.insert(ch.clone(), vec![naddr.clone()]);
                }
            }
        }
        available
    }

    /// Find each peer's mapping between tenure ID consensus hashes for the tenures it claims to
    /// have in its inventory vector, and its tenure start block ID.
    ///
    /// This is a static method to facilitate testing.
    pub(crate) fn find_tenure_block_ids<'a>(
        rc: u64,
        wanted_tenures: &[WantedTenure],
        next_wanted_tenures: Option<&[WantedTenure]>,
        pox_constants: &PoxConstants,
        first_burn_height: u64,
        mut inventory_iter: impl Iterator<Item = (&'a NeighborAddress, &'a NakamotoTenureInv)>,
    ) -> HashMap<NeighborAddress, AvailableTenures> {
        let mut tenure_block_ids = HashMap::new();
        while let Some((naddr, tenure_inv)) = inventory_iter.next() {
            let Some(peer_tenure_block_ids) = TenureStartEnd::from_inventory(
                rc,
                wanted_tenures,
                next_wanted_tenures,
                pox_constants,
                first_burn_height,
                tenure_inv,
            ) else {
                // this peer doesn't know about this reward cycle
                continue;
            };
            tenure_block_ids.insert(naddr.clone(), peer_tenure_block_ids);
        }
        tenure_block_ids
    }

    /// Produce a download schedule for IBD mode.  Tenures will be downloaded in sortition order.
    /// The first item will be fetched first.
    pub(crate) fn make_ibd_download_schedule(
        nakamoto_start: u64,
        wanted_tenures: &[WantedTenure],
        available: &HashMap<ConsensusHash, Vec<NeighborAddress>>,
    ) -> VecDeque<ConsensusHash> {
        let mut schedule = VecDeque::new();
        for wt in wanted_tenures.iter() {
            if wt.processed {
                continue;
            }
            if wt.burn_height < nakamoto_start {
                continue;
            }
            if !available.contains_key(&wt.tenure_id_consensus_hash) {
                continue;
            }
            schedule.push_back(wt.tenure_id_consensus_hash.clone());
        }
        schedule
    }

    /// Produce a download schedule for steady-state mode.  Tenures will be downloaded in
    /// rarest-first order.
    /// The first item will be fetched first.
    pub(crate) fn make_rarest_first_download_schedule(
        nakamoto_start: u64,
        wanted_tenures: &[WantedTenure],
        available: &HashMap<ConsensusHash, Vec<NeighborAddress>>,
    ) -> VecDeque<ConsensusHash> {
        let mut schedule = Vec::with_capacity(available.len());
        for wt in wanted_tenures.iter() {
            if wt.processed {
                continue;
            }
            if wt.burn_height < nakamoto_start {
                continue;
            }
            let Some(neighbors) = available.get(&wt.tenure_id_consensus_hash) else {
                continue;
            };
            schedule.push((neighbors.len(), wt.tenure_id_consensus_hash.clone()));
        }

        // order by fewest neighbors first
        schedule.sort_by(|a, b| a.0.cmp(&b.0));
        schedule.into_iter().map(|(_count, ch)| ch).collect()
    }

    /// How many neighbors can we contact still, given the map of tenures to neighbors which can
    /// serve it?
    fn count_available_tenure_neighbors(
        available: &HashMap<ConsensusHash, Vec<NeighborAddress>>,
    ) -> usize {
        available
            .iter()
            .fold(0, |count, (_ch, naddrs)| count.saturating_add(naddrs.len()))
    }

    /// This function examines the contents of `self.wanted_tenures` and
    /// `self.prev_wanted_tenures`, and calculates the following:
    ///
    /// * The set of `TenureStartEnd`s for both `self.wanted_tenures` and
    /// `self.prev_wanted_tenures`, given the peers' inventory vectors.
    ///
    /// * The set of which tenures are available from which neighbors
    ///
    /// * The order in which to fetch tenure data, based on whether or not we're in IBD or
    /// steady-state.
    ///
    /// This function should be called immediately after `update_wanted_tenures()`.
    pub(crate) fn update_available_tenures(
        &mut self,
        inventories: &HashMap<NeighborAddress, NakamotoTenureInv>,
        pox_constants: &PoxConstants,
        first_burn_height: u64,
        ibd: bool,
    ) {
        if self.tenure_download_schedule.is_empty() {
            // try again
            self.available_tenures.clear();
            self.tenure_block_ids.clear();
        }
        if Self::count_available_tenure_neighbors(&self.available_tenures) > 0 {
            // still have requests to try, so don't bother computing a new set of available tenures
            test_debug!("Still have requests to try");
            return;
        }
        if self.wanted_tenures.is_empty() {
            // nothing to do
            return;
        }
        if inventories.is_empty() {
            // nothing to do
            test_debug!("No inventories available");
            return;
        }

        // calculate self.available
        // get available tenures for both the current and previous reward cycles
        let prev_available = self
            .prev_wanted_tenures
            .as_ref()
            .map(|prev_wanted_tenures| {
                test_debug!(
                    "Load availability for prev_wanted_tenures ({}) at rc {}",
                    prev_wanted_tenures.len(),
                    self.reward_cycle.saturating_sub(1)
                );
                Self::find_available_tenures(
                    self.reward_cycle.saturating_sub(1),
                    prev_wanted_tenures,
                    inventories.iter(),
                )
            })
            .unwrap_or(HashMap::new());

        let mut available = Self::find_available_tenures(
            self.reward_cycle,
            &self.wanted_tenures,
            inventories.iter(),
        );
        available.extend(prev_available.into_iter());

        // calculate self.tenure_block_ids
        let prev_tenure_block_ids = self.prev_wanted_tenures
            .as_ref()
            .map(|prev_wanted_tenures| {
                // have both self.prev_wanted_tenures and self.wanted_tenures
                test_debug!("Load tenure block IDs for prev_wanted_tenures ({}) and wanted_tenures ({}) at rc {}", prev_wanted_tenures.len(), self.wanted_tenures.len(), self.reward_cycle.saturating_sub(1));
                Self::find_tenure_block_ids(
                    self.reward_cycle.saturating_sub(1),
                    prev_wanted_tenures,
                    Some(&self.wanted_tenures),
                    pox_constants,
                    first_burn_height,
                    inventories.iter(),
                )
            })
            .unwrap_or(HashMap::new());

        let mut tenure_block_ids = {
            test_debug!(
                "Load tenure block IDs for wanted_tenures ({}) at rc {}",
                self.wanted_tenures.len(),
                self.reward_cycle
            );
            Self::find_tenure_block_ids(
                self.reward_cycle,
                &self.wanted_tenures,
                None,
                pox_constants,
                first_burn_height,
                inventories.iter(),
            )
        };

        // merge tenure block IDs
        for (naddr, prev_available) in prev_tenure_block_ids.into_iter() {
            if let Some(available) = tenure_block_ids.get_mut(&naddr) {
                available.extend(prev_available.into_iter());
            } else {
                tenure_block_ids.insert(naddr, prev_available);
            }
        }

        // create download schedules for unprocessed blocks
        let schedule = if ibd {
            let mut prev_schedule = self
                .prev_wanted_tenures
                .as_ref()
                .map(|prev_wanted_tenures| {
                    Self::make_ibd_download_schedule(
                        self.nakamoto_start_height,
                        prev_wanted_tenures,
                        &available,
                    )
                })
                .unwrap_or(VecDeque::new());

            let schedule = Self::make_ibd_download_schedule(
                self.nakamoto_start_height,
                &self.wanted_tenures,
                &available,
            );

            prev_schedule.extend(schedule.into_iter());
            prev_schedule
        } else {
            let mut prev_schedule = self
                .prev_wanted_tenures
                .as_ref()
                .map(|prev_wanted_tenures| {
                    Self::make_rarest_first_download_schedule(
                        self.nakamoto_start_height,
                        prev_wanted_tenures,
                        &available,
                    )
                })
                .unwrap_or(VecDeque::new());

            let schedule = Self::make_rarest_first_download_schedule(
                self.nakamoto_start_height,
                &self.wanted_tenures,
                &available,
            );

            prev_schedule.extend(schedule.into_iter());
            prev_schedule
        };

        test_debug!("new schedule: {:?}", schedule);
        test_debug!("new available: {:?}", &available);
        test_debug!("new tenure_block_ids: {:?}", &tenure_block_ids);

        self.tenure_download_schedule = schedule;
        self.tenure_block_ids = tenure_block_ids;
        self.available_tenures = available;
    }

    /// Update our tenure download state machines, given our download schedule, our peers' tenure
    /// availabilities, and our computed `TenureStartEnd`s
    fn update_tenure_downloaders(
        &mut self,
        count: usize,
        agg_public_keys: &BTreeMap<u64, Option<Point>>,
    ) {
        self.tenure_downloads.make_tenure_downloaders(
            &mut self.tenure_download_schedule,
            &mut self.available_tenures,
            &mut self.tenure_block_ids,
            count,
            agg_public_keys,
        )
    }

    /// Determine whether or not we can start downloading the highest complete tenure and the
    /// unconfirmed tenure.  Only do this if (1) the sortition DB is at the burnchain tip and (2)
    /// all of our wanted tenures are marked as either downloaded or complete.
    ///
    /// To fully determine if it's appropriate to download unconfirmed tenures, the caller should
    /// additionally ensure that there are no in-flight confirmed tenure downloads.
    ///
    /// This method is static to facilitate testing.
    pub(crate) fn need_unconfirmed_tenures<'a>(
        nakamoto_start_block: u64,
        burnchain_height: u64,
        sort_tip: &BlockSnapshot,
        completed_tenures: &HashSet<ConsensusHash>,
        wanted_tenures: &[WantedTenure],
        prev_wanted_tenures: &[WantedTenure],
        tenure_block_ids: &HashMap<NeighborAddress, AvailableTenures>,
        pox_constants: &PoxConstants,
        first_burn_height: u64,
        inventory_iter: impl Iterator<Item = &'a NakamotoTenureInv>,
        blocks_db: NakamotoStagingBlocksConnRef,
    ) -> bool {
        if sort_tip.block_height < burnchain_height {
            test_debug!(
                "sort_tip {} < burn tip {}",
                sort_tip.block_height,
                burnchain_height
            );
            return false;
        }

        if wanted_tenures.is_empty() {
            test_debug!("No wanted tenures");
            return false;
        }

        if prev_wanted_tenures.is_empty() {
            test_debug!("No prev wanted tenures");
            return false;
        }

        // there are still confirmed tenures we have to go and get
        if Self::have_unprocessed_tenures(
            pox_constants
                .block_height_to_reward_cycle(first_burn_height, nakamoto_start_block)
                .expect("FATAL: nakamoto starts before system start"),
            completed_tenures,
            prev_wanted_tenures,
            tenure_block_ids,
            pox_constants,
            first_burn_height,
            inventory_iter,
        ) {
            test_debug!("Still have unprocessed tenures, so we don't need unconfirmed tenures");
            return false;
        }

        // see if we need any tenures still
        for wt in wanted_tenures.iter() {
            if completed_tenures.contains(&wt.tenure_id_consensus_hash) {
                continue;
            }
            let is_available = tenure_block_ids
                .iter()
                .any(|(_, available)| available.contains_key(&wt.tenure_id_consensus_hash));

            if is_available && !wt.processed {
                return false;
            }
        }

        // there are still tenures that have to be processed
        if blocks_db
            .has_any_unprocessed_nakamoto_block()
            .map_err(|e| {
                warn!(
                    "Failed to determine if there are unprocessed Nakamoto blocks: {:?}",
                    &e
                );
                e
            })
            .unwrap_or(true)
        {
            test_debug!("Still have stored but unprocessed Nakamoto blocks");
            return false;
        }

        true
    }

    /// Select neighbors to query for unconfirmed tenures, given this node's view of the burnchain
    /// and an iterator over the set of ongoing p2p conversations.
    /// Only select neighbors that has the same burnchain view as us, and have authenticated to us
    /// and are outbound from us (meaning, they're not NAT'ed relative to us).
    pub(crate) fn make_unconfirmed_tenure_download_schedule<'a>(
        chain_view: &BurnchainView,
        peers_iter: impl Iterator<Item = (&'a usize, &'a ConversationP2P)>,
    ) -> VecDeque<NeighborAddress> {
        let mut schedule = VecDeque::new();
        for (_, convo) in peers_iter {
            if chain_view.burn_block_hash != convo.burnchain_tip_burn_header_hash {
                continue;
            }
            if chain_view.burn_block_height != convo.burnchain_tip_height {
                continue;
            }
            if !convo.is_authenticated() {
                continue;
            }
            if !convo.is_outbound() {
                continue;
            }
            schedule.push_back(convo.to_neighbor_address());
        }
        schedule
    }

    /// Create up to `count` unconfirmed tenure downloaders.  Add them to `downloaders`, and remove
    /// the remote peer's address from `schedule`.
    ///
    /// The caller will need to ensure that no request to the ongoing unconfirmed tenure
    /// downloaders gets created, lest it replace the unconfirmed tenure request.
    ///
    /// This method removes items from `schedule` and adds unconfirmed downloaders to
    /// `downloaders`.
    ///
    /// This method is static to facilitate testing.
    pub(crate) fn make_unconfirmed_tenure_downloaders(
        schedule: &mut VecDeque<NeighborAddress>,
        count: usize,
        downloaders: &mut HashMap<NeighborAddress, NakamotoUnconfirmedTenureDownloader>,
        highest_processed_block_id: Option<StacksBlockId>,
    ) {
        while downloaders.len() < count {
            let Some(naddr) = schedule.front() else {
                break;
            };
            if downloaders.contains_key(naddr) {
                continue;
            }
            let unconfirmed_tenure_download = NakamotoUnconfirmedTenureDownloader::new(
                naddr.clone(),
                highest_processed_block_id.clone(),
            );

            test_debug!("Request unconfirmed tenure state from neighbor {}", &naddr);
            downloaders.insert(naddr.clone(), unconfirmed_tenure_download);
            schedule.pop_front();
        }
    }

    /// Update our unconfirmed tenure download state machines
    fn update_unconfirmed_tenure_downloaders(
        &mut self,
        count: usize,
        highest_processed_block_id: Option<StacksBlockId>,
    ) {
        Self::make_unconfirmed_tenure_downloaders(
            &mut self.unconfirmed_tenure_download_schedule,
            count,
            &mut self.unconfirmed_tenure_downloads,
            highest_processed_block_id,
        );
    }

    /// Run unconfirmed tenure download state machines.
    /// * Update the highest-processed block in each downloader to our highest-processed block
    /// * Send any HTTP requests that the downloaders indicate are needed (if they are not blocked
    /// waiting for a response)
    /// * Obtain any HTTP responses and pass them into the downloaders, thereby advancing their
    /// states
    /// * Obtain downloaded blocks, and create new confirmed tenure downloaders for the
    /// highest-complete tenure downloader.
    /// * Clear out downloader state for peers who have disconnected or have finished processing
    /// their machines.
    ///
    /// As the local node processes blocks, update each downloader's view of the highest-processed
    /// block so it can cancel itself early if it finds that we've already got the blocks, or if
    /// another peer indicates that it has a higher block.
    ///
    /// This method guarantees that the highest confirmed tenure downloaders instantiated here can
    /// be safely run without clobbering ongoing conversations with other neighbors, _provided
    /// that_ the download state machine is currently concerned with running unconfirmed tenure
    /// downloaders (i.e. it's not in IBD).
    ///
    /// This method is static to facilitate testing.
    ///
    /// Returns the map from neighbors to the unconfirmed blocks they serve, as well as a map from
    /// neighbors to the instantiated confirmed tenure downloaders for their highest completed
    /// tenures (this information cannot be determined from sortition history and block inventories
    /// alone, since we need to know the tenure-start block from the ongoing tenure).
    pub(crate) fn run_unconfirmed_downloaders(
        downloaders: &mut HashMap<NeighborAddress, NakamotoUnconfirmedTenureDownloader>,
        network: &mut PeerNetwork,
        neighbor_rpc: &mut NeighborRPC,
        sortdb: &SortitionDB,
        sort_tip: &BlockSnapshot,
        chainstate: &StacksChainState,
        highest_complete_tenure: &WantedTenure,
        unconfirmed_tenure: &WantedTenure,
    ) -> (
        HashMap<NeighborAddress, Vec<NakamotoBlock>>,
        HashMap<NeighborAddress, NakamotoTenureDownloader>,
    ) {
        let addrs: Vec<_> = downloaders.keys().map(|addr| addr.clone()).collect();
        let mut finished = vec![];
        let mut unconfirmed_blocks = HashMap::new();
        let mut highest_completed_tenure_downloaders = HashMap::new();

        // find the highest-processed block, and update all ongoing state-machines.
        // Then, as faster state-machines linked to more up-to-date peers download newer blocks,
        // other state-machines will automatically terminate once they reach the highest block this
        // peer has now processed.
        let highest_processed_block_id =
            StacksBlockId::new(&network.stacks_tip.0, &network.stacks_tip.1);
        let highest_processed_block_height = network.stacks_tip.2;

        for (_, downloader) in downloaders.iter_mut() {
            downloader.set_highest_processed_block(
                highest_processed_block_id.clone(),
                highest_processed_block_height,
            );
        }

        // send requests
        for (naddr, downloader) in downloaders.iter_mut() {
            if downloader.is_done() {
                finished.push(naddr.clone());
                continue;
            }
            if neighbor_rpc.has_inflight(&naddr) {
                continue;
            }

            test_debug!(
                "Send request to {} for tenure {:?} (state {})",
                &naddr,
                &downloader.unconfirmed_tenure_id(),
                &downloader.state
            );
            if let Err(e) = downloader.send_next_download_request(network, neighbor_rpc) {
                debug!(
                    "Downloader for {} failed; this peer is dead: {:?}",
                    &naddr, &e
                );
                neighbor_rpc.add_dead(network, naddr);
                continue;
            };
        }

        // clear dead, broken, and done
        for naddr in addrs.iter() {
            if neighbor_rpc.is_dead_or_broken(network, naddr) {
                downloaders.remove(naddr);
            }
        }
        for done_naddr in finished.drain(..) {
            downloaders.remove(&done_naddr);
        }

        // handle responses
        for (naddr, response) in neighbor_rpc.collect_replies(network) {
            let Some(downloader) = downloaders.get_mut(&naddr) else {
                test_debug!("Got rogue response from {}", &naddr);
                continue;
            };

            test_debug!("Got response from {}", &naddr);
            let Ok(blocks_opt) = downloader.handle_next_download_response(
                response,
                sortdb,
                sort_tip,
                chainstate,
                &network.aggregate_public_keys,
            ) else {
                neighbor_rpc.add_dead(network, &naddr);
                continue;
            };

            let Some(blocks) = blocks_opt else {
                continue;
            };

            if let Some(highest_complete_tenure_downloader) = downloader
                .make_highest_complete_tenure_downloader(
                    highest_complete_tenure,
                    unconfirmed_tenure,
                )
                .map_err(|e| {
                    warn!(
                        "Failed to make highest complete tenure downloader for {:?}: {:?}",
                        &downloader.unconfirmed_tenure_id(),
                        &e
                    );
                    e
                })
                .ok()
            {
                // don't start this unless the downloader is actually done (this should always be
                // the case, but don't tempt fate with an assert!)
                if downloader.is_done() {
                    highest_completed_tenure_downloaders
                        .insert(naddr.clone(), highest_complete_tenure_downloader);
                }
            }

            unconfirmed_blocks.insert(naddr.clone(), blocks);
            if downloader.is_done() {
                finished.push(naddr);
                continue;
            }
        }

        // clear dead, broken, and done
        for naddr in addrs.iter() {
            if neighbor_rpc.is_dead_or_broken(network, naddr) {
                downloaders.remove(naddr);
            }
        }
        for done_naddr in finished.iter() {
            downloaders.remove(done_naddr);
        }

        (unconfirmed_blocks, highest_completed_tenure_downloaders)
    }

    /// Run and process all confirmed tenure downloaders, and do the necessary bookkeeping to deal
    /// with failed peer connections.
    ///
    /// At most `max_count` downloaders will be instantiated at once.
    ///
    /// Returns the set of downloaded confirmed tenures obtained.
    fn download_confirmed_tenures(
        &mut self,
        network: &mut PeerNetwork,
        max_count: usize,
    ) -> HashMap<ConsensusHash, Vec<NakamotoBlock>> {
        // queue up more downloaders
        self.update_tenure_downloaders(max_count, &network.aggregate_public_keys);

        // run all downloaders
        let new_blocks = self.tenure_downloads.run(network, &mut self.neighbor_rpc);

        // give blocked downloaders their tenure-end blocks from other downloaders that have
        // obtained their tenure-start blocks
        let new_tenure_starts = self.tenure_downloads.find_new_tenure_start_blocks();
        self.tenure_start_blocks
            .extend(new_tenure_starts.into_iter());

        let dead = self
            .tenure_downloads
            .handle_tenure_end_blocks(&self.tenure_start_blocks);

        // bookkeeping
        for naddr in dead.into_iter() {
            self.neighbor_rpc.add_dead(network, &naddr);
        }

        new_blocks
    }

    /// Run and process all unconfirmed tenure downloads, and highest complete tenure downloads.
    /// Do the needful bookkeeping to remove dead peers.
    fn download_unconfirmed_tenures(
        &mut self,
        network: &mut PeerNetwork,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        highest_processed_block_id: Option<StacksBlockId>,
    ) -> HashMap<ConsensusHash, Vec<NakamotoBlock>> {
        // queue up more downloaders
        self.update_unconfirmed_tenure_downloaders(
            usize::try_from(network.get_connection_opts().max_inflight_blocks)
                .expect("FATAL: max_inflight_blocks exceeds usize::MAX"),
            highest_processed_block_id,
        );

        // run all unconfirmed downloaders, and start confirmed downloaders for the
        // highest complete tenure
        let burnchain_tip = network.burnchain_tip.clone();
        let Some(unconfirmed_tenure) = self
            .wanted_tenures
            .last()
            .map(|wt| Some(wt.clone()))
            .unwrap_or_else(|| {
                // unconfirmed tenure is the last tenure in prev_wanted_tenures if
                // wanted_tenures.len() is 0
                let prev_wanted_tenures = self.prev_wanted_tenures.as_ref()?;
                let wt = prev_wanted_tenures.last()?;
                Some(wt.clone())
            })
        else {
            // not initialized yet (technically unrachable)
            return HashMap::new();
        };

        // Get the highest WantedTenure.  This will be the WantedTenure whose winning block hash is
        // the start block hash of the highest complete tenure, and whose consensus hash is the
        // tenure ID of the ongoing tenure.  It corresponds to the highest sortition for which
        // there exists a tenure.
        //
        // There are three possibilities for obtaining this, based on what we know about tenures
        // from the sortition DB and the peers' inventories:
        //
        // Case 1: There are no sortitions yet in the current reward cycle, so this is the
        // second-to-last WantedTenure in the last reward cycle's WantedTenure list.
        //
        // Case 2: There is one sortition in the current reward cycle, so this is the last
        // WantedTenure in the last reward cycle's WantedTenure list
        //
        // Case 3: There are two or more sortitions in the current reward cycle, so this is the
        // second-to-last WantedTenure in the current reward cycle's WantedTenure list.
        let highest_wanted_tenure = if self.wanted_tenures.is_empty() {
            // highest complete wanted tenure is the second-to-last tenure in prev_wanted_tenures
            let Some(prev_wanted_tenures) = self.prev_wanted_tenures.as_ref() else {
                // not initialized yet (technically unrachable)
                return HashMap::new();
            };
            if prev_wanted_tenures.len() < 2 {
                return HashMap::new();
            };
            let Some(wt) = prev_wanted_tenures.get(prev_wanted_tenures.len().saturating_sub(2))
            else {
                return HashMap::new();
            };
            wt.clone()
        } else if self.wanted_tenures.len() == 1 {
            // highest complete tenure is the last tenure in prev_wanted_tenures
            let Some(prev_wanted_tenures) = self.prev_wanted_tenures.as_ref() else {
                return HashMap::new();
            };
            let Some(wt) = prev_wanted_tenures.last() else {
                return HashMap::new();
            };
            wt.clone()
        } else {
            // highest complete tenure is the second-to-last tenure in wanted_tenures
            let Some(wt) = self
                .wanted_tenures
                .get(self.wanted_tenures.len().saturating_sub(2))
            else {
                return HashMap::new();
            };
            wt.clone()
        };

        // Run the confirmed downloader state machine set, since we could already be processing the
        // highest complete tenure download.  NOTE: due to the way that we call this method, we're
        // guaranteed that if the `tenure_downloads` downloader set has any downloads at all, they
        // will only be for the highest complete tenure (i.e. we only call this method if we've
        // already downloaded all confirmed tenures), so there's no risk of clobberring any other
        // in-flight requests.
        let new_confirmed_blocks = if self.tenure_downloads.inflight() > 0 {
            self.download_confirmed_tenures(network, 0)
        } else {
            HashMap::new()
        };

        // Only run unconfirmed downloaders if we're _not_ busy obtaining the highest confirmed
        // tenure.  The behavior here ensures that we first obtain the highest complete tenure, and
        // then poll for new unconfirmed tenure blocks.
        let (new_unconfirmed_blocks, new_highest_confirmed_downloaders) =
            if self.tenure_downloads.inflight() > 0 {
                (HashMap::new(), HashMap::new())
            } else {
                Self::run_unconfirmed_downloaders(
                    &mut self.unconfirmed_tenure_downloads,
                    network,
                    &mut self.neighbor_rpc,
                    sortdb,
                    &burnchain_tip,
                    chainstate,
                    &highest_wanted_tenure,
                    &unconfirmed_tenure,
                )
            };

        // schedule downloaders for the highest-confirmed tenure, if we generated any
        self.tenure_downloads
            .add_downloaders(new_highest_confirmed_downloaders.into_iter());

        // coalesce blocks -- maps consensus hash to map of block id to block
        let mut coalesced_blocks: HashMap<ConsensusHash, HashMap<StacksBlockId, NakamotoBlock>> =
            HashMap::new();
        for blocks in new_unconfirmed_blocks
            .into_values()
            .chain(new_confirmed_blocks.into_values())
        {
            for block in blocks.into_iter() {
                let block_id = block.header.block_id();
                if let Some(block_map) = coalesced_blocks.get_mut(&block.header.consensus_hash) {
                    block_map.insert(block_id, block);
                } else {
                    let mut block_map = HashMap::new();
                    let ch = block.header.consensus_hash.clone();
                    block_map.insert(block_id, block);
                    coalesced_blocks.insert(ch, block_map);
                }
            }
        }

        coalesced_blocks
            .into_iter()
            .map(|(consensus_hash, block_map)| {
                let mut block_list: Vec<_> =
                    block_map.into_iter().map(|(_, block)| block).collect();
                block_list.sort_unstable_by_key(|blk| blk.header.chain_length);
                (consensus_hash, block_list)
            })
            .collect()
    }

    /// Top-level download state machine execution.
    ///
    /// The downloader transitions between two states in perpetuity: obtaining confirmed tenures,
    /// and obtaining the unconfirmed tenure and the highest complete tenure.
    ///
    /// The system starts out in the "confirmed" mode, since the node must first download all
    /// confirmed tenures before it can process the chain tip.  But once all confirmed tenures have
    /// been downloaded, the system transitions to "unconfirmed" mode whereby it attempts to
    /// download the highest complete tenure and any new unconfirmed tenure blocks.  It stays in
    /// "unconfirmed" mode until there are new confirmed tenures to fetch (which shouldn't happen
    /// unless this node misses a few sortitions, such as due to a restart).
    fn run_downloads(
        &mut self,
        burnchain_height: u64,
        network: &mut PeerNetwork,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        ibd: bool,
    ) -> HashMap<ConsensusHash, Vec<NakamotoBlock>> {
        debug!("NakamotoDownloadStateMachine in state {}", &self.state);
        let Some(invs) = network.inv_state_nakamoto.as_ref() else {
            // nothing to do
            test_debug!("No network inventories");
            return HashMap::new();
        };
        test_debug!(
            "run_downloads: burnchain_height={}, network.burnchain_tip.block_height={}",
            burnchain_height,
            network.burnchain_tip.block_height
        );
        self.update_available_tenures(
            &invs.inventories,
            &sortdb.pox_constants,
            sortdb.first_block_height,
            ibd,
        );

        match self.state {
            NakamotoDownloadState::Confirmed => {
                let new_blocks = self.download_confirmed_tenures(
                    network,
                    usize::try_from(network.get_connection_opts().max_inflight_blocks)
                        .expect("FATAL: max_inflight_blocks exceeds usize::MAX"),
                );

                // keep borrow-checker happy by instantiang this ref again, now that `network` is
                // no longer mutably borrowed.
                let Some(invs) = network.inv_state_nakamoto.as_ref() else {
                    // nothing to do
                    test_debug!("No network inventories");
                    return HashMap::new();
                };

                debug!(
                    "tenure_downloads.is_empty: {}",
                    self.tenure_downloads.is_empty()
                );
                if self.tenure_downloads.is_empty()
                    && Self::need_unconfirmed_tenures(
                        self.nakamoto_start_height,
                        burnchain_height,
                        &network.burnchain_tip,
                        &self.tenure_downloads.completed_tenures,
                        &self.wanted_tenures,
                        self.prev_wanted_tenures.as_ref().unwrap_or(&vec![]),
                        &self.tenure_block_ids,
                        &sortdb.pox_constants,
                        sortdb.first_block_height,
                        invs.inventories.values(),
                        chainstate.nakamoto_blocks_db(),
                    )
                {
                    debug!(
                        "Transition from {} to {}",
                        &self.state,
                        NakamotoDownloadState::Unconfirmed
                    );

                    self.unconfirmed_tenure_download_schedule =
                        Self::make_unconfirmed_tenure_download_schedule(
                            &network.chain_view,
                            network.iter_peer_convos(),
                        );
                    self.state = NakamotoDownloadState::Unconfirmed;
                }

                return new_blocks;
            }
            NakamotoDownloadState::Unconfirmed => {
                let highest_processed_block_id =
                    StacksBlockId::new(&network.stacks_tip.0, &network.stacks_tip.1);

                let new_blocks = self.download_unconfirmed_tenures(
                    network,
                    sortdb,
                    chainstate,
                    Some(highest_processed_block_id),
                );

                // keep borrow-checker happy by instantiang this ref again, now that `network` is
                // no longer mutably borrowed.
                let Some(invs) = network.inv_state_nakamoto.as_ref() else {
                    // nothing to do
                    test_debug!("No network inventories");
                    return HashMap::new();
                };

                if self.tenure_downloads.is_empty()
                    && self.unconfirmed_tenure_downloads.is_empty()
                    && self.unconfirmed_tenure_download_schedule.is_empty()
                {
                    if Self::need_unconfirmed_tenures(
                        self.nakamoto_start_height,
                        burnchain_height,
                        &network.burnchain_tip,
                        &self.tenure_downloads.completed_tenures,
                        &self.wanted_tenures,
                        self.prev_wanted_tenures.as_ref().unwrap_or(&vec![]),
                        &self.tenure_block_ids,
                        &sortdb.pox_constants,
                        sortdb.first_block_height,
                        invs.inventories.values(),
                        chainstate.nakamoto_blocks_db(),
                    ) {
                        // do this again
                        self.unconfirmed_tenure_download_schedule =
                            Self::make_unconfirmed_tenure_download_schedule(
                                &network.chain_view,
                                network.iter_peer_convos(),
                            );
                        debug!(
                            "Transition from {} to {}",
                            &self.state,
                            NakamotoDownloadState::Unconfirmed
                        );
                        self.state = NakamotoDownloadState::Unconfirmed;
                    } else {
                        debug!(
                            "Transition from {} to {}",
                            &self.state,
                            NakamotoDownloadState::Confirmed
                        );
                        self.state = NakamotoDownloadState::Confirmed;
                    }
                }

                return new_blocks;
            }
        }
    }

    /// Go and get tenures. Returns list of blocks per tenure, identified by consensus hash.
    /// The blocks will be sorted by height, but may not be contiguous.
    pub fn run(
        &mut self,
        burnchain_height: u64,
        network: &mut PeerNetwork,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        ibd: bool,
    ) -> Result<HashMap<ConsensusHash, Vec<NakamotoBlock>>, NetError> {
        self.update_wanted_tenures(&network, sortdb, chainstate)?;
        self.update_processed_tenures(chainstate)?;
        let new_blocks = self.run_downloads(burnchain_height, network, sortdb, chainstate, ibd);
        self.last_sort_tip = Some(network.burnchain_tip.clone());
        Ok(new_blocks)
    }
}
