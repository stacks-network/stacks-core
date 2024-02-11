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
use std::collections::BTreeMap;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::net::{Error as NetError, NakamotoInvData};
use crate::net::NeighborComms;
use crate::util_lib::db::Error as DBError;
use crate::net::StacksMessageType;
use crate::net::GetNakamotoInvData;
use crate::net::NakamotoInvData;

use stacks_common::util::get_epoch_time_secs();

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

#[derive(Debug, PartialEq, Clone)]
pub struct NakamotoTenureInv {
    /// Bitmap of which tenures a peer has.
    /// Maps reward cycle to bitmap.
    pub tenures_inv: BTreeMap<u64, Vec<u8>>,
    /// Highest sortition this peer has seen
    pub highest_sortition: u64,
    /// Time of last update, in seconds
    pub last_updated_at: u64,
    /// Burn block height of first sortition
    pub first_block_height: u64,
    /// Length of reward cycle
    pub reward_cycle_len: u64,

    /// The fields below are used for synchronizing this particular peer's inventories.
    /// Currently tracked reward cycle
    pub cur_reward_cycle: u64,
    /// Status of this node.
    /// True if we should keep talking to it; false if not
    pub online: bool,
    /// Last time we began talking to this peer
    pub start_sync_time: u64,
}

impl NakamotoTenureInv {
    pub fn new(first_block_height: u64, reward_cycle_len: u64) -> Self {
        Self {
            tenures_inv: vec![],
            highest_sortition: 0,
            last_updated_at: 0,
            first_block_height,
            reward_cycle_len,
            cur_reward_cycle: 0,
            online: true,
            start_sync_time: 0,
        }
    }

    /// Does this remote neighbor have the ith tenure data for the given (absolute) burn block height?
    /// (note that block_height is the _absolute_ block height)
    pub fn has_ith_tenure(&self, burn_block_height: u64) -> bool {
        if burn_block_height < self.first_block_height {
            return false;
        }

        let Some(reward_cycle) = PoxConstants::static_block_height_to_reward_cycle(burn_block_height, self.first_block_height, self.reward_cycle_len) else {
            return false;
        };

        let rc_idx = usize::try_from(reward_cycle).expect("FATAL: reward cycle exceeds usize");
        let Some(rc_tenures) = self.tenures_inv.get(rc_idx) else {
            return false;
        };

        let sortition_height = burn_block_height - self.first_block_height;
        let rc_height = sortition_height % self.reward_cycle_len;

        let idx = usize::try_from(rc_height / 8).expect("FATAL: reward cycle length exceeds host usize");
        let bit = rc_height % 8;

        rc_tenures
            .get(idx)
            .map(|bits| bits & (1 << bit) != 0)
            .unwrap_or(false)
    }

    /// How many reward cycles of data do we have for this peer?
    pub fn num_reward_cycles(&self) -> u64 {
        let Some((highest_rc, _)) = self.tenures_inv.last_key_value() else {
            return 0;
        };
        *highest_rc
    }

    /// Add in a newly-discovered inventory.
    /// NOTE: inventories are supposed to be aligned to the reward cycle
    pub fn merge_tenure_inv(&mut self, tenure_inv: Vec<u8>, tenure_bitlen: u16, reward_cycle: u64) {
        // populate the tenures bitmap to we can fit this tenures inv
        let rc_idx = usize::try_from(reward_cycle).expect("FATAL: reward_cycle exceeds usize");

        self.highest_sortition = self.num_reward_cycles() * self.reward_cycle_len + u64::from(tenure_bitlen);
        self.tenures_inv[rc_idx] = tenure_inv;
        self.last_updated_at = get_epoch_time_secs();
    }

    /// Adjust the next reward cycle to query.
    /// Returns the reward cycle to query.
    pub fn next_reward_cycle(&mut self) -> u64 {
        let query_rc = self.cur_reward_cycle;
        self.cur_reward_cycle += 1;
        query_rc
    }

    /// Reset synchronization state for this peer.  Don't remove inventory data; just make it so we
    /// can talk to the peer again
    pub fn try_reset_comms(&mut self, inv_sync_interval: u64, start_rc: u64) {
        let now = get_epoch_time_secs();
        if self.start_sync_time + inv_sync_interval <= now {
            self.online = true;
            self.start_sync_time = now;
            self.cur_reward_cycle = start_rc;
        }
    }

    /// Get the reward cycle we're sync'ing for
    pub fn reward_cycle(&self) -> u64 {
        self.cur_reward_cycle
    }

    /// Get online status
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Set online status.  We don't talk to offline peers
    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NakamotoInvState {
    GetNakamotoInvBegin,
    GetNakamotoInvFinish,
    Done
}

/// Nakamoto inventory state machine
pub struct NakamotoInvStateMachine<NC: NeighborComms> {
    /// What state is the machine in?
    pub(crate) state: NakamotoInvState,
    /// Communications links 
    pub(crate) comms: NC,
    /// Nakamoto inventories we have
    inventories: HashMap<NeighborAddress, NakamotoTenureInv>,
    /// Reward cycle consensus hashes
    reward_cycle_consensus_hashes: BTreeMap<u64, ConsensusHash>,
    /// What reward cycle are we in?
    cur_reward_cycle: u64,
}

impl<NC: NeighborComms> NakamotoInvStateMachine<NC> {
    pub fn new(comms: NC) -> Self {
        Self {
            state: NakamotoInvstate::GetNakamotoInvBegin,
            comms: NC,
            inventories: HashMap::new(),
            reward_cycle_consensus_hashes: BTreeMap::new(),
            cur_reward_cycle: 0,
        }
    }

    pub fn reset(&mut self) {
        self.comms.reset();
        self.inventories.clear();
        self.state = NakamotoInvState::GetNakamotoInvBegin;
    }

    /// Get the consensus hash for the first sortition in the given reward cycle
    fn load_consensus_hash_for_reward_cycle(sortdb: &SortitionDB, reward_cycle: u64) -> Result<Option<ConsensusHash>, NetError> {
        let consensus_hash = {
            let reward_cycle_start_height = sortdb
                .pox_constants
                .reward_cycle_to_block_height(sortdb.first_block_height, reward_cycle);
            let sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;
            let ih = sortdb.index_handle(sn.sortition_id);
            let Some(rc_start_sn) = ih
                .get_block_snapshot_by_height(reward_cycle_start_height)?
            else {
                return None;
            };
            rc_start_sn.consensus_hash
        };
        Ok(Some(consensus_hash))
    }

    /// Populate the reward_cycle_consensus_hash mapping.  Idempotent.
    /// Returns the current reward cycle.
    fn update_reward_cycle_consensus_hashes(&mut self, sortdb: &SortitionDB) -> Result<u64, NetError> {
        let highest_rc = if let Some((highest_rc, _)) = self.reward_cycle_consensus_hashes.last_key_value() {
            *highest_rc
        }
        else {
            0
        };

        let sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;
        let tip_rc = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, sn.block_height);

        for rc in highest_rc..=tip_rc {
            if self.reward_cycle_consnsus_hashes.contains_key(&rc) {
                continue;
            }
            let Some(ch) = Self::load_consensus_hash_for_reward_cycle(sortdb, rc)? else {
                continue;
            };
            self.reward_cycle_consensus_hashes.insert(rc, ch);
        }
        Ok(tip_rc)
    }

    /// Make a getnakamotoinv message
    fn make_getnakamotoinv(&self, reward_cycle: u64) -> Option<StacksMessageType> {
        let Some(ch) = self.reward_cycle_consensus_hashes.get(&reward_cycle) else {
            return None;
        };
        Some(StacksMessageType::GetNakamotoInv(GetNakamotoInvData {
            consensus_hash: ch.clone()
        }))
    }

    /// Proceed to ask neighbors for their nakamoto tenure inventories.
    /// If we're in initial block download (ibd), then only ask our bootstrap peers.
    /// Otherwise, ask everyone.
    /// Returns Ok(true) if we completed this step of the state machine
    /// Returns Ok(false) if not (currently this never happens)
    /// Returns Err(..) on I/O errors
    pub fn getnakamotoinv_begin(&mut self, network: &mut PeerNetwork, sortdb: &SortitionDB, ibd: bool) -> Result<bool, NetError> {
        // make sure we know all consensus hashes for all reward cycles.
        let current_reward_cycle = self.update_reward_cycle_consensus_hashes(sortdb)?;
        self.cur_reward_cycle = current_reward_cycle;

        // we're updating inventories, so preserve the state we have
        let mut new_inventories = BTreeMap::new();
        for event_id in network.peer_iter_event_ids() {
            let Some(convo) = network.get_p2p_convo(*event_id) else {
                continue;
            };
            if ibd {
                // in IBD, only connect to initial peers
                let is_initial = PeerDB::is_initial_peer(
                    &network.peerdb_conn(),
                    convo.peer_network_id,
                    &convo.peer_addrbytes,
                    convo.peer_port
                ).unwrap_or(false);
                if !is_initial {
                    continue;
                }
            }

            let naddr = convo.to_neighbor_address();

            let mut inv = self.inventories
                .get(&naddr)
                .clone()
                .unwrap_or(NakamotoTenureInv::new(
                    network.get_burnchain().first_block_height,
                    network.get_burnchain().pox_constants.reward_cycle_len,
                ));

            // possibly reset communications with this peer, if it's time to do so.
            inv.try_reset_comms(network.get_connection_opts().inv_sync_interval, current_reward_cycle.saturating_sub(network.get_connection_opts().inv_reward_cycles));
            if !inv.is_online() {
                // don't talk to this peer
                continue;
            }

            if inv.reward_cycle() > current_reward_cycle {
                // we've fully sync'ed with this peer
                continue;
            }

            // ask this neighbor for its inventory
            if let Some(getnakamotoinv) = self.make_getnakamotoinv(inv.reward_cycle()) {
                if let Err(e) = self.comms.neighbor_send(network, &naddr, getnakamotoinv) {
                    warn!("{:?}: failed to send GetNakamotoInv", network.get_local_peer();
                          "message" => ?getnakamotoinv,
                          "peer" => ?naddr,
                          "error" => ?e
                    );
                }
                else {
                    // keep this connection open
                    self.comms.pin_connection(*event_id);
                }
            }

            new_inventories.insert(naddr, inv);
        }

        self.inventories = new_inventories;
        Ok(true);
    }

    /// Finish asking for inventories, and update inventory state.
    pub fn getnakamotoinv_try_finish(&mut self, network: &mut PeerNetwork) -> Result<bool, NetError> {
        let mut inv_replies = vec![];
        let mut nack_replies = vec![];
        for (naddr, reply) in self.comms.collect_replies(network) {
            match reply {
                StacksMessageType::NakamotoInv(inv_data) => {
                    inv_replies.push((naddr, inv_data));
                }
                StacksMessageType::Nack(nack_data) => {
                    nack_replies.push((naddr, nack_data));
                }
            }
        }

        // process NACKs
        for (naddr, nack_data) in nack_replies.into_iter() {
            info!("{:?}: remote peer NACKed our GetNakamotoInv", network.get_local_peer();
                  "error_code" => nack_data.error_code);

            let Some(inv) = self.inventories.get_mut(&naddr) else {
                continue;
            };

            // stop talking to this peer
            inv.set_online(false);
        }

        // process NakamotoInvs
        for (naddr, inv_data) in inv_replies.into_iter() {
            let Some(inv) = self.inventories.get_mut(&naddr) else {
                info!("{:?}: Drop unsolicited NakamotoInv from {:?}", &network.get_local_peer(), &naddr);
                continue;
            };
            inv.merge_tenure_inv(&inv_data.tenures, inv_data.bitlen, inv.reward_cycle());
            inv.next_reward_cycle();
        }

        Ok(self.comms.count_inflight() == 0)
    }

    pub fn run(&mut self, network: &mut PeerNetwork) -> bool {
        false
    }
}
