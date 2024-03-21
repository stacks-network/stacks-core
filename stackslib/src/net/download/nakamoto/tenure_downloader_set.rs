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
    AvailableTenures, NakamotoTenureDownloadState, NakamotoTenureDownloader,
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

/// A set of confirmed downloader state machines assigned to one or more neighbors.  The block
/// downloader runs tenure-downloaders in parallel, since the downloader for the N+1'st tenure
/// needs to feed data into the Nth tenure.  This struct is responsible for scheduling peer
/// connections to downloader state machines, such that each peer is assigned to at most one
/// downloader.  A peer is assigned a downloader for the duration of at most one RPC request, at
/// which point, it will be re-assigned a (possibly different) downloader.  As such, each machine
/// can make progress even if there is only one available peer (in which case, that peer will get
/// scheduled across multiple machines to drive their progress in the right sequence such that
/// tenures will be incrementally fetched and yielded by the p2p state machine to the relayer).
pub struct NakamotoTenureDownloaderSet {
    /// A list of instantiated downloaders that are in progress
    pub(crate) downloaders: Vec<Option<NakamotoTenureDownloader>>,
    /// An assignment of peers to downloader machines in the `downloaders` list.
    pub(crate) peers: HashMap<NeighborAddress, usize>,
    /// The set of tenures that have been successfully downloaded (but possibly not yet stored or
    /// processed)
    pub(crate) completed_tenures: HashSet<ConsensusHash>,
}

impl NakamotoTenureDownloaderSet {
    pub fn new() -> Self {
        Self {
            downloaders: vec![],
            peers: HashMap::new(),
            completed_tenures: HashSet::new(),
        }
    }

    /// Assign the given peer to the given downloader state machine.  Allocate a slot for it if
    /// needed.
    fn add_downloader(&mut self, naddr: NeighborAddress, downloader: NakamotoTenureDownloader) {
        test_debug!(
            "Add downloader for tenure {} driven by {}",
            &downloader.tenure_id_consensus_hash,
            &naddr
        );
        if let Some(idx) = self.peers.get(&naddr) {
            self.downloaders[*idx] = Some(downloader);
        } else {
            self.downloaders.push(Some(downloader));
            self.peers.insert(naddr, self.downloaders.len() - 1);
        }
    }

    /// Does the given neighbor have an assigned downloader state machine?
    pub(crate) fn has_downloader(&self, naddr: &NeighborAddress) -> bool {
        let Some(idx) = self.peers.get(naddr) else {
            return false;
        };
        let Some(downloader_opt) = self.downloaders.get(*idx) else {
            return false;
        };
        downloader_opt.is_some()
    }

    /// Drop the downloader associated with the given neighbor, if any.
    pub fn clear_downloader(&mut self, naddr: &NeighborAddress) {
        let Some(index) = self.peers.remove(naddr) else {
            return;
        };
        self.downloaders[index] = None;
    }

    /// How many downloaders are there?
    pub fn num_downloaders(&self) -> usize {
        self.downloaders
            .iter()
            .fold(0, |acc, dl| if dl.is_some() { acc + 1 } else { acc })
    }

    /// How many downloaders are there, which are scheduled?
    pub fn num_scheduled_downloaders(&self) -> usize {
        let mut cnt = 0;
        for (_, idx) in self.peers.iter() {
            if let Some(Some(_)) = self.downloaders.get(*idx) {
                cnt += 1;
            }
        }
        cnt
    }

    /// Add a sequence of (address, downloader) pairs to this downloader set.
    pub(crate) fn add_downloaders(
        &mut self,
        iter: impl IntoIterator<Item = (NeighborAddress, NakamotoTenureDownloader)>,
    ) {
        for (naddr, downloader) in iter {
            if self.has_downloader(&naddr) {
                test_debug!("Already have downloader for {}", &naddr);
                continue;
            }
            self.add_downloader(naddr, downloader);
        }
    }

    /// Count up the number of in-flight messages, based on the states of each instantiated
    /// downloader.
    pub fn inflight(&self) -> usize {
        let mut cnt = 0;
        for downloader_opt in self.downloaders.iter() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if downloader.idle {
                continue;
            }
            if downloader.is_waiting() {
                continue;
            }
            if downloader.is_done() {
                continue;
            }
            cnt += 1;
        }
        cnt
    }

    /// Determine whether or not there exists a downloader for the given tenure, identified by its
    /// consensus hash.
    pub fn is_tenure_inflight(&self, ch: &ConsensusHash) -> bool {
        self.downloaders
            .iter()
            .find(|d| d.as_ref().map(|x| &x.tenure_id_consensus_hash) == Some(ch))
            .is_some()
    }

    /// Determine if this downloader set is empty -- i.e. there's no in-flight requests.
    pub fn is_empty(&self) -> bool {
        self.inflight() == 0
    }

    /// Try to resume processing a download state machine with a given peer.  Since a peer is
    /// detached from the machine after a single RPC call, this call is needed to re-attach it to a
    /// (potentially different, unblocked) machine for the next RPC call to this peer.
    ///
    /// Returns true if the peer gets scheduled.
    /// Returns false if not.
    pub fn try_resume_peer(&mut self, naddr: NeighborAddress) -> bool {
        if let Some(idx) = self.peers.get(&naddr) {
            let Some(Some(_downloader)) = self.downloaders.get(*idx) else {
                return false;
            };

            test_debug!(
                "Peer {} already bound to downloader for {}",
                &naddr,
                &_downloader.tenure_id_consensus_hash
            );
            return true;
        }
        for (i, downloader_opt) in self.downloaders.iter_mut().enumerate() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if !downloader.idle {
                continue;
            }
            if downloader.is_waiting() {
                continue;
            }
            if downloader.naddr != naddr {
                continue;
            }
            test_debug!(
                "Assign peer {} to work on downloader for {} in state {}",
                &naddr,
                &downloader.tenure_id_consensus_hash,
                &downloader.state
            );
            self.peers.insert(naddr, i);
            return true;
        }
        return false;
    }

    /// Deschedule peers that are bound to downloader slots that are either vacant or correspond to
    /// blocked downloaders.
    pub fn clear_available_peers(&mut self) {
        let mut idled: Vec<NeighborAddress> = vec![];
        for (naddr, i) in self.peers.iter() {
            let Some(downloader_opt) = self.downloaders.get(*i) else {
                // should be unreachable
                idled.push(naddr.clone());
                continue;
            };
            let Some(downloader) = downloader_opt else {
                test_debug!("Remove peer {} for null download {}", &naddr, i);
                idled.push(naddr.clone());
                continue;
            };
            if downloader.idle || downloader.is_waiting() {
                test_debug!(
                    "Remove idled peer {} for tenure download {}",
                    &naddr,
                    &downloader.tenure_id_consensus_hash
                );
                idled.push(naddr.clone());
            }
        }
        for naddr in idled.into_iter() {
            self.peers.remove(&naddr);
        }
    }

    /// Clear out downloaders (but not their peers) that have finished.  The caller should follow
    /// this up with a call to `clear_available_peers()`.
    pub fn clear_finished_downloaders(&mut self) {
        for downloader_opt in self.downloaders.iter_mut() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if downloader.is_done() {
                *downloader_opt = None;
            }
        }
    }

    /// Find the downloaders that have obtained their tenure-start blocks, and extract them.  These
    /// will be fed into other downloaders which are blocked on needing their tenure-end blocks.
    pub(crate) fn find_new_tenure_start_blocks(&self) -> HashMap<StacksBlockId, NakamotoBlock> {
        let mut ret = HashMap::new();
        for downloader_opt in self.downloaders.iter() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            let Some(block) = downloader.tenure_start_block.as_ref() else {
                continue;
            };
            ret.insert(block.block_id(), block.clone());
        }
        ret
    }

    /// Given a set of tenure-start blocks, pass them into downloaders that are waiting for their
    /// tenure-end blocks.
    /// Return a list of peers driving downloaders with failing `tenure_start_blocks`
    pub(crate) fn handle_tenure_end_blocks(
        &mut self,
        tenure_start_blocks: &HashMap<StacksBlockId, NakamotoBlock>,
    ) -> Vec<NeighborAddress> {
        test_debug!(
            "handle tenure-end blocks: {:?}",
            &tenure_start_blocks.keys().collect::<Vec<_>>()
        );
        let mut dead = vec![];
        for downloader_opt in self.downloaders.iter_mut() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            let NakamotoTenureDownloadState::WaitForTenureEndBlock(end_block_id, ..) =
                &downloader.state
            else {
                continue;
            };
            let Some(end_block) = tenure_start_blocks.get(end_block_id) else {
                continue;
            };
            if let Err(e) = downloader.try_accept_tenure_end_block(end_block) {
                warn!(
                    "Failed to accept tenure end-block {} for tenure {}: {:?}",
                    &end_block.block_id(),
                    &downloader.tenure_id_consensus_hash,
                    &e
                );
                dead.push(downloader.naddr.clone());
            }
        }
        dead
    }

    /// Does there exist a downloader (possibly unscheduled) for the given tenure?
    pub(crate) fn has_downloader_for_tenure(&self, tenure_id: &ConsensusHash) -> bool {
        for downloader_opt in self.downloaders.iter() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if &downloader.tenure_id_consensus_hash == tenure_id {
                test_debug!(
                    "Have downloader for tenure {} already (idle={}, waiting={}, state={})",
                    tenure_id,
                    downloader.idle,
                    downloader.is_waiting(),
                    &downloader.state
                );
                return true;
            }
        }
        false
    }

    /// In the event that the last confirmed tenure in a reward cycle contains the PoX anchor
    /// block, we need to go and directly fetch its end block instead of waiting for another
    /// NakamotoTenureDownloader to provide it as its tenure-start block.  Naively, this method
    /// just unconditionally sets the highest available tenure downloader to fetch its tenure end block.
    pub(crate) fn try_transition_fetch_tenure_end_blocks(
        &mut self,
        tenure_block_ids: &HashMap<NeighborAddress, AvailableTenures>,
    ) {
        for downloader_opt in self.downloaders.iter_mut() {
            let Some(downloader) = downloader_opt.as_mut() else {
                continue;
            };
            downloader.transition_to_fetch_end_block_on_timeout();
        }

        // find tenures in which we need to fetch the tenure-end block directly.
        let mut last_available_tenures: HashSet<StacksBlockId> = HashSet::new();
        for (_, all_available) in tenure_block_ids.iter() {
            for (_, available) in all_available.iter() {
                if available.fetch_end_block {
                    last_available_tenures.insert(available.end_block_id.clone());
                }
            }
        }

        // is anyone downloading this tenure, and if so, are they waiting?  If so, then flip to
        // fetching
        for downloader_opt in self.downloaders.iter_mut() {
            let Some(downloader) = downloader_opt.as_mut() else {
                continue;
            };
            if !downloader.idle {
                continue;
            }
            if !downloader.is_waiting() {
                continue;
            }
            if !last_available_tenures.contains(&downloader.tenure_end_block_id) {
                continue;
            }
            test_debug!(
                "Transition downloader for {} from waiting to fetching",
                &downloader.tenure_id_consensus_hash
            );
            if let Err(e) = downloader.transition_to_fetch_end_block() {
                warn!(
                    "Downloader for {} failed to transition to fetch end block: {:?}",
                    &downloader.tenure_id_consensus_hash, &e
                );
            }
        }
    }

    /// Create a given number of downloads from a schedule and availability set.
    /// Removes items from the schedule, and neighbors from the availability set.
    /// A neighbor will be issued at most one request.
    pub(crate) fn make_tenure_downloaders(
        &mut self,
        schedule: &mut VecDeque<ConsensusHash>,
        available: &mut HashMap<ConsensusHash, Vec<NeighborAddress>>,
        tenure_block_ids: &HashMap<NeighborAddress, AvailableTenures>,
        count: usize,
        agg_public_keys: &BTreeMap<u64, Option<Point>>,
    ) {
        test_debug!("schedule: {:?}", schedule);
        test_debug!("available: {:?}", &available);
        test_debug!("tenure_block_ids: {:?}", &tenure_block_ids);
        test_debug!("inflight: {}", self.inflight());
        test_debug!(
            "count: {}, running: {}, scheduled: {}",
            count,
            self.num_downloaders(),
            self.num_scheduled_downloaders()
        );

        self.clear_available_peers();
        self.clear_finished_downloaders();
        self.try_transition_fetch_tenure_end_blocks(tenure_block_ids);
        while self.inflight() < count {
            let Some(ch) = schedule.front() else {
                break;
            };
            if self.completed_tenures.contains(&ch) {
                test_debug!("Already successfully downloaded tenure {}", &ch);
                schedule.pop_front();
                continue;
            }
            let Some(neighbors) = available.get_mut(ch) else {
                // not found on any neighbors, so stop trying this tenure
                test_debug!("No neighbors have tenure {}", ch);
                schedule.pop_front();
                continue;
            };
            if neighbors.is_empty() {
                // no more neighbors to try
                test_debug!("No more neighbors can serve tenure {}", ch);
                schedule.pop_front();
                continue;
            }
            let Some(naddr) = neighbors.pop() else {
                test_debug!("No more neighbors can serve tenure {}", ch);
                schedule.pop_front();
                continue;
            };
            if self.try_resume_peer(naddr.clone()) {
                continue;
            };
            if self.has_downloader_for_tenure(&ch) {
                schedule.pop_front();
                continue;
            }

            let Some(available_tenures) = tenure_block_ids.get(&naddr) else {
                // this peer doesn't have any known tenures, so try the others
                test_debug!("No tenures available from {}", &naddr);
                continue;
            };
            let Some(tenure_info) = available_tenures.get(ch) else {
                // this peer does not have a tenure start/end block for this tenure, so try the
                // others.
                test_debug!("Neighbor {} does not serve tenure {}", &naddr, ch);
                continue;
            };
            let Some(Some(start_agg_pubkey)) = agg_public_keys.get(&tenure_info.start_reward_cycle)
            else {
                test_debug!(
                    "Cannot fetch tenure-start block due to no known aggregate public key: {:?}",
                    &tenure_info
                );
                schedule.pop_front();
                continue;
            };
            let Some(Some(end_agg_pubkey)) = agg_public_keys.get(&tenure_info.end_reward_cycle)
            else {
                test_debug!(
                    "Cannot fetch tenure-end block due to no known aggregate public key: {:?}",
                    &tenure_info
                );
                schedule.pop_front();
                continue;
            };

            test_debug!(
                "Download tenure {} (start={}, end={}) with aggregate keys {}, {} (rc {},{})",
                &ch,
                &tenure_info.start_block_id,
                &tenure_info.end_block_id,
                &start_agg_pubkey,
                &end_agg_pubkey,
                tenure_info.start_reward_cycle,
                tenure_info.end_reward_cycle
            );
            let tenure_download = NakamotoTenureDownloader::new(
                ch.clone(),
                tenure_info.start_block_id.clone(),
                tenure_info.end_block_id.clone(),
                naddr.clone(),
                start_agg_pubkey.clone(),
                end_agg_pubkey.clone(),
            );

            test_debug!("Request tenure {} from neighbor {}", ch, &naddr);
            self.add_downloader(naddr, tenure_download);
            schedule.pop_front();
        }
    }

    /// Run all confirmed downloaders.
    /// * Identify neighbors for which we do not have an inflight request
    /// * Get each such neighbor's downloader, and generate its next HTTP reqeust. Send that
    /// request to the neighbor and begin driving the underlying socket I/O.
    /// * Get each HTTP reply, and pass it into the corresponding downloader's handler to advance
    /// its state.
    /// * Identify and remove misbehaving neighbors and neighbors whose connections have broken.
    ///
    /// Returns the set of downloaded blocks obtained for completed downloaders.  These will be
    /// full confirmed tenures.
    pub fn run(
        &mut self,
        network: &mut PeerNetwork,
        neighbor_rpc: &mut NeighborRPC,
    ) -> HashMap<ConsensusHash, Vec<NakamotoBlock>> {
        let addrs: Vec<_> = self.peers.keys().cloned().collect();
        let mut finished = vec![];
        let mut finished_tenures = vec![];
        let mut new_blocks = HashMap::new();

        // send requests
        for (naddr, index) in self.peers.iter() {
            if neighbor_rpc.has_inflight(&naddr) {
                test_debug!("Peer {} has an inflight request", &naddr);
                continue;
            }
            let Some(Some(downloader)) = self.downloaders.get_mut(*index) else {
                test_debug!("No downloader for {}", &naddr);
                continue;
            };
            if downloader.is_done() {
                test_debug!("Downloader for {} is done", &naddr);
                finished.push(naddr.clone());
                finished_tenures.push(downloader.tenure_id_consensus_hash.clone());
                continue;
            }
            test_debug!(
                "Send request to {} for tenure {} (state {})",
                &naddr,
                &downloader.tenure_id_consensus_hash,
                &downloader.state
            );
            let Ok(sent) = downloader.send_next_download_request(network, neighbor_rpc) else {
                test_debug!("Downloader for {} failed; this peer is dead", &naddr);
                neighbor_rpc.add_dead(network, naddr);
                continue;
            };
            if !sent {
                // this downloader is dead or broken
                finished.push(naddr.clone());
                continue;
            }
        }

        // clear dead, broken, and done
        for naddr in addrs.iter() {
            if neighbor_rpc.is_dead_or_broken(network, naddr) {
                test_debug!("Remove dead/broken downloader for {}", &naddr);
                self.clear_downloader(&naddr);
            }
        }
        for done_naddr in finished.drain(..) {
            test_debug!("Remove finished downloader for {}", &done_naddr);
            self.clear_downloader(&done_naddr);
        }
        for done_tenure in finished_tenures.drain(..) {
            self.completed_tenures.insert(done_tenure);
        }

        // handle responses
        for (naddr, response) in neighbor_rpc.collect_replies(network) {
            let Some(index) = self.peers.get(&naddr) else {
                test_debug!("No downloader for {}", &naddr);
                continue;
            };
            let Some(Some(downloader)) = self.downloaders.get_mut(*index) else {
                test_debug!("No downloader for {}", &naddr);
                continue;
            };
            test_debug!("Got response from {}", &naddr);

            let Ok(blocks_opt) = downloader.handle_next_download_response(response) else {
                test_debug!("Failed to handle download response from {}", &naddr);
                neighbor_rpc.add_dead(network, &naddr);
                continue;
            };

            let Some(blocks) = blocks_opt else {
                continue;
            };

            test_debug!(
                "Got {} blocks for tenure {}",
                blocks.len(),
                &downloader.tenure_id_consensus_hash
            );
            new_blocks.insert(downloader.tenure_id_consensus_hash.clone(), blocks);
            if downloader.is_done() {
                finished.push(naddr.clone());
                finished_tenures.push(downloader.tenure_id_consensus_hash.clone());
                continue;
            }
        }

        // clear dead, broken, and done
        for naddr in addrs.iter() {
            if neighbor_rpc.is_dead_or_broken(network, naddr) {
                test_debug!("Remove dead/broken downloader for {}", &naddr);
                self.clear_downloader(naddr);
            }
        }
        for done_naddr in finished.drain(..) {
            test_debug!("Remove finished downloader for {}", &done_naddr);
            self.clear_downloader(&done_naddr);
        }
        for done_tenure in finished_tenures.drain(..) {
            self.completed_tenures.insert(done_tenure);
        }

        new_blocks
    }
}
