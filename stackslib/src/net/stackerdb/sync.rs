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

use std::collections::{HashMap, HashSet};
use std::mem;

use crate::net::stackerdb::{
    StackerDBConfig, StackerDBSync, StackerDBSyncResult, StackerDBSyncState, StackerDBs,
};

use crate::net::db::PeerDB;

use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Hash160;

use crate::net::chat::ConversationP2P;
use crate::net::connection::ReplyHandleP2P;
use crate::net::p2p::PeerNetwork;
use crate::net::Error as net_error;
use crate::net::{
    NackData, Neighbor, NeighborAddress, NeighborKey, StackerDBChunkData, StackerDBChunkInvData,
    StackerDBGetChunkData, StackerDBGetChunkInvData, StackerDBPushChunkData, StacksMessageType,
};

use crate::net::neighbors::NeighborComms;

use clarity::vm::types::QualifiedContractIdentifier;

use rand::prelude::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;

const MAX_CHUNKS_IN_FLIGHT: usize = 6;
const MAX_DB_NEIGHBORS: usize = 32;

impl<NC: NeighborComms> StackerDBSync<NC> {
    /// TODO: replace `stackerdbs` with a type parameter
    pub fn new(
        smart_contract: QualifiedContractIdentifier,
        config: &StackerDBConfig,
        comms: NC,
        stackerdbs: StackerDBs,
    ) -> Result<StackerDBSync<NC>, net_error> {
        let mut dbsync = StackerDBSync {
            state: StackerDBSyncState::ConnectBegin,
            smart_contract_id: smart_contract,
            num_slots: config.num_slots() as usize,
            write_freq: config.write_freq,
            chunk_invs: HashMap::new(),
            chunk_fetch_priorities: vec![],
            chunk_push_priorities: vec![],
            chunk_push_receipts: HashMap::new(),
            next_chunk_fetch_priority: 0,
            next_chunk_push_priority: 0,
            expected_versions: vec![],
            downloaded_chunks: HashMap::new(),
            replicas: HashSet::new(),
            connected_replicas: HashSet::new(),
            comms,
            stackerdbs,
            request_capacity: MAX_CHUNKS_IN_FLIGHT,
            max_neighbors: MAX_DB_NEIGHBORS,
            total_stored: 0,
            total_pushed: 0,
            last_run_ts: 0,
            need_resync: false,
        };
        dbsync.reset(None, config)?;
        Ok(dbsync)
    }

    /// Calculate the new set of replicas to contact.
    /// This is the same as the set that was connected on the last sync, plus any
    /// config hints and discovered nodes from the DB.
    fn find_new_replicas(
        &self,
        mut connected_replicas: HashSet<NeighborAddress>,
        network: Option<&PeerNetwork>,
        config: &StackerDBConfig,
    ) -> Result<HashSet<NeighborAddress>, net_error> {
        // keep all connected replicas, and replenish from config hints and the DB as needed
        let mut peers = config.hint_replicas.clone();
        if let Some(network) = network {
            let extra_peers: Vec<_> = PeerDB::find_stacker_db_replicas(
                network.peerdb_conn(),
                network.get_local_peer().network_id,
                &self.smart_contract_id,
                self.max_neighbors,
            )?
            .into_iter()
            .map(|neighbor| NeighborAddress::from_neighbor(&neighbor))
            .collect();
            peers.extend(extra_peers);
        }

        for peer in peers {
            if connected_replicas.len() >= config.max_neighbors {
                break;
            }
            connected_replicas.insert(peer);
        }
        Ok(connected_replicas)
    }

    /// Reset this state machine, and get the StackerDBSyncResult with newly-obtained chunk data
    /// and newly-learned information about broken and dead peers.
    pub fn reset(
        &mut self,
        network: Option<&PeerNetwork>,
        config: &StackerDBConfig,
    ) -> Result<StackerDBSyncResult, net_error> {
        let mut chunks = vec![];
        let downloaded_chunks = mem::replace(&mut self.downloaded_chunks, HashMap::new());
        for (_, mut data) in downloaded_chunks.into_iter() {
            chunks.append(&mut data);
        }

        let chunk_invs = mem::replace(&mut self.chunk_invs, HashMap::new());
        let result = StackerDBSyncResult {
            contract_id: self.smart_contract_id.clone(),
            chunk_invs,
            chunks_to_store: chunks,
            dead: self.comms.take_dead_neighbors(),
            broken: self.comms.take_broken_neighbors(),
        };

        // keep all connected replicas, and replenish from config hints and the DB as needed
        let connected_replicas = mem::replace(&mut self.connected_replicas, HashSet::new());
        let next_connected_replicas =
            self.find_new_replicas(connected_replicas, network, config)?;
        self.replicas = next_connected_replicas;

        self.chunk_fetch_priorities.clear();
        self.chunk_push_priorities.clear();
        self.next_chunk_fetch_priority = 0;
        self.next_chunk_push_priority = 0;
        self.chunk_push_receipts.clear();
        self.expected_versions.clear();
        self.downloaded_chunks.clear();

        // reset comms, but keep all replicas pinned
        self.comms.reset();

        // reload from config
        self.num_slots = config.num_slots() as usize;
        self.write_freq = config.write_freq;

        self.need_resync = false;

        Ok(result)
    }

    /// Get the set of connection IDs in use
    pub fn get_pinned_connections(&self) -> &HashSet<usize> {
        self.comms.get_pinned_connections()
    }

    /// Make a chunk inv request
    pub fn make_getchunkinv(&self, rc_consensus_hash: &ConsensusHash) -> StacksMessageType {
        StacksMessageType::StackerDBGetChunkInv(StackerDBGetChunkInvData {
            contract_id: self.smart_contract_id.clone(),
            rc_consensus_hash: rc_consensus_hash.clone(),
        })
    }

    /// Given the downloaded set of chunk inventories, identify:
    /// * which chunks we need to fetch, because they're newer than ours.
    /// * what order to fetch chunks in, in rarest-first order
    /// Returns a list of (chunk requests, list of neighbors that can service them), which is
    /// ordered from rarest chunk to most-common chunk.
    pub fn make_chunk_request_schedule(
        &self,
        network: &PeerNetwork,
        local_slot_versions_opt: Option<Vec<u32>>,
    ) -> Result<Vec<(StackerDBGetChunkData, Vec<NeighborAddress>)>, net_error> {
        let rc_consensus_hash = network.get_chain_view().rc_consensus_hash.clone();
        let local_slot_versions = if let Some(local_slot_versions) = local_slot_versions_opt {
            local_slot_versions
        } else {
            self.stackerdbs.get_slot_versions(&self.smart_contract_id)?
        };

        let local_write_timestamps = self
            .stackerdbs
            .get_slot_write_timestamps(&self.smart_contract_id)?;
        assert_eq!(local_slot_versions.len(), local_write_timestamps.len());

        let mut need_chunks: HashMap<usize, (StackerDBGetChunkData, Vec<NeighborAddress>)> =
            HashMap::new();
        let now = get_epoch_time_secs();

        // who has data we need?
        for (i, local_version) in local_slot_versions.iter().enumerate() {
            let write_ts = local_write_timestamps[i];
            if write_ts + self.write_freq > now {
                test_debug!(
                    "{:?}: Chunk {} was written too frequently ({} + {} >= {}), so will not fetch chunk",
                    network.get_local_peer(),
                    i,
                    write_ts,
                    self.write_freq,
                    now
                );
                continue;
            }

            for (naddr, chunk_inv) in self.chunk_invs.iter() {
                assert_eq!(
                    chunk_inv.slot_versions.len(),
                    local_slot_versions.len(),
                    "FATAL: did not validate StackerDBChunkInvData"
                );

                if *local_version >= chunk_inv.slot_versions[i] {
                    // remote peer has same view as local peer, or stale
                    continue;
                }

                let (request, available) = if let Some(x) = need_chunks.get_mut(&i) {
                    // someone has this chunk already
                    x
                } else {
                    // haven't seen anyone with this data yet.
                    // Add a record for it
                    need_chunks.insert(
                        i,
                        (
                            StackerDBGetChunkData {
                                contract_id: self.smart_contract_id.clone(),
                                rc_consensus_hash,
                                slot_id: i as u32,
                                slot_version: chunk_inv.slot_versions[i],
                            },
                            vec![naddr.clone()],
                        ),
                    );
                    continue;
                };

                if request.slot_version < chunk_inv.slot_versions[i] {
                    // this peer has a newer view
                    available.clear();
                    available.push(naddr.clone());
                    *request = StackerDBGetChunkData {
                        contract_id: self.smart_contract_id.clone(),
                        rc_consensus_hash,
                        slot_id: i as u32,
                        slot_version: chunk_inv.slot_versions[i],
                    };
                } else if request.slot_version == chunk_inv.slot_versions[i] {
                    // this peer has the same view as a prior peer.
                    // just track how many times we see this
                    available.push(naddr.clone());
                }
            }
        }

        // prioritize requests by rarest-chunk-first order, but choose neighbors in random order
        let mut schedule: Vec<_> = need_chunks
            .into_iter()
            .map(|(_, (stackerdb_getchunkdata, mut neighbors))| {
                neighbors.shuffle(&mut thread_rng());
                (stackerdb_getchunkdata, neighbors)
            })
            .collect();

        schedule.sort_by(|item_1, item_2| item_1.1.len().cmp(&item_2.1.len()));
        schedule.reverse();

        test_debug!(
            "{:?}: Will request up to {} chunks for {}",
            network.get_local_peer(),
            &schedule.len(),
            &self.smart_contract_id,
        );
        Ok(schedule)
    }

    /// Given the downloaded set of chunk inventories, identify:
    /// * which chunks we need to push, because we have them and the neighbor does not
    /// * what order to push them in, in rarest-first order
    pub fn make_chunk_push_schedule(
        &self,
        network: &PeerNetwork,
    ) -> Result<Vec<(StackerDBPushChunkData, Vec<NeighborAddress>)>, net_error> {
        let rc_consensus_hash = network.get_chain_view().rc_consensus_hash.clone();
        let local_slot_versions = self.stackerdbs.get_slot_versions(&self.smart_contract_id)?;

        let mut need_chunks: HashMap<usize, (StackerDBPushChunkData, Vec<NeighborAddress>)> =
            HashMap::new();

        // who needs data we can serve?
        for (i, local_version) in local_slot_versions.iter().enumerate() {
            let mut local_chunk = None;
            for (naddr, chunk_inv) in self.chunk_invs.iter() {
                assert_eq!(
                    chunk_inv.slot_versions.len(),
                    local_slot_versions.len(),
                    "FATAL: did not validate StackerDBChunkData"
                );

                if *local_version <= chunk_inv.slot_versions[i] {
                    // remote peer has same or newer view than local peer
                    continue;
                }

                if local_chunk.is_none() {
                    let chunk_data = if let Some(chunk_data) = self.stackerdbs.get_chunk(
                        &self.smart_contract_id,
                        i as u32,
                        *local_version,
                    )? {
                        chunk_data
                    } else {
                        // we don't have this chunk
                        break;
                    };
                    local_chunk = Some(StackerDBPushChunkData {
                        contract_id: self.smart_contract_id.clone(),
                        rc_consensus_hash: rc_consensus_hash.clone(),
                        chunk_data,
                    });
                }

                let our_chunk = if let Some(chunk) = local_chunk.as_ref() {
                    chunk
                } else {
                    // we don't have this chunk
                    break;
                };

                // replicate with probability 1/num-outbound-replicas
                let do_replicate = if chunk_inv.num_outbound_replicas == 0 {
                    true
                } else {
                    thread_rng().gen::<u32>() % chunk_inv.num_outbound_replicas == 0
                };

                if !do_replicate {
                    continue;
                }

                if let Some((_, receivers)) = need_chunks.get_mut(&i) {
                    // someone needs this chunk already
                    receivers.push(naddr.clone());
                } else {
                    // haven't seen anyone that needs this data yet.
                    // Add a record for it.
                    need_chunks.insert(i, (our_chunk.clone(), vec![naddr.clone()]));
                };
            }
        }

        // prioritize requests by rarest-chunk-first order.
        // no need to randomize; we'll pick recipients at random
        let mut schedule: Vec<_> = need_chunks
            .into_iter()
            .map(|(_, (stackerdb_chunkdata, neighbors))| (stackerdb_chunkdata, neighbors))
            .collect();

        schedule.sort_by(|item_1, item_2| item_1.1.len().cmp(&item_2.1.len()));
        test_debug!(
            "{:?}: Will push up to {} chunks for {}",
            network.get_local_peer(),
            &schedule.len(),
            &self.smart_contract_id,
        );
        Ok(schedule)
    }

    /// Validate a downloaded chunk
    pub fn validate_downloaded_chunk(
        &self,
        network: &PeerNetwork,
        config: &StackerDBConfig,
        data: &StackerDBChunkData,
    ) -> Result<bool, net_error> {
        // validate -- must be a valid chunk
        if !network.validate_received_chunk(
            &self.smart_contract_id,
            &config,
            data,
            &self.expected_versions,
        )? {
            return Ok(false);
        }

        // no need to validate the timestamp, because we already skipped requesting it if it was
        // written too recently.

        Ok(true)
    }

    /// Store a downloaded chunk to RAM, and update bookkeeping
    pub fn add_downloaded_chunk(&mut self, naddr: NeighborAddress, data: StackerDBChunkData) {
        let slot_id = data.slot_id;
        let _slot_version = data.slot_version;

        if let Some(data_list) = self.downloaded_chunks.get_mut(&naddr) {
            data_list.push(data);
        } else {
            self.downloaded_chunks.insert(naddr.clone(), vec![data]);
        }

        self.chunk_fetch_priorities
            .retain(|(chunk, ..)| chunk.slot_id != slot_id);

        if self.chunk_fetch_priorities.len() > 0 {
            let next_chunk_fetch_priority =
                self.next_chunk_fetch_priority % self.chunk_fetch_priorities.len();
            self.next_chunk_fetch_priority = next_chunk_fetch_priority;
        }

        self.total_stored += 1;
    }

    /// Update bookkeeping about which chunks we have pushed.
    /// Stores the new chunk inventory to RAM.
    /// Returns true if the inventory changed (indicating that we need to resync)
    /// Returns false otherwise
    pub fn add_pushed_chunk(
        &mut self,
        network: &PeerNetwork,
        naddr: NeighborAddress,
        new_inv: StackerDBChunkInvData,
        slot_id: u32,
    ) -> bool {
        // safety (should already be checked) -- don't accept if the size is wrong
        if new_inv.slot_versions.len() != self.num_slots {
            return false;
        }

        let need_resync = if let Some(old_inv) = self.chunk_invs.get(&naddr) {
            let mut resync = false;
            for (old_slot_id, old_version) in old_inv.slot_versions.iter().enumerate() {
                if *old_version < new_inv.slot_versions[old_slot_id] {
                    // remote peer indicated that it has a newer version of this chunk.
                    test_debug!(
                        "{:?}: peer {:?} has a newer version of slot {} ({} < {})",
                        network.get_local_peer(),
                        &naddr,
                        old_slot_id,
                        old_version,
                        new_inv.slot_versions[old_slot_id]
                    );
                    resync = true;
                    break;
                }
            }
            resync
        } else {
            false
        };

        self.chunk_invs.insert(naddr.clone(), new_inv);

        self.chunk_push_priorities
            .retain(|(chunk, ..)| chunk.chunk_data.slot_id != slot_id);

        if self.chunk_push_priorities.len() > 0 {
            let next_chunk_push_priority =
                self.next_chunk_push_priority % self.chunk_push_priorities.len();
            self.next_chunk_push_priority = next_chunk_push_priority;
        }

        self.total_pushed += 1;
        need_resync
    }

    /// Ask inbound neighbors who replicate this DB for their chunk inventories.
    /// Don't send them a message if they're also outbound.
    /// Logs errors but does not return them.
    fn send_getchunkinv_to_inbound_neighbors(
        &mut self,
        network: &mut PeerNetwork,
        already_sent: &[NeighborAddress],
    ) {
        let sent_naddr_set: HashSet<_> = already_sent.iter().collect();
        let mut to_send = vec![];
        for event_id in network.iter_peer_event_ids() {
            let convo = if let Some(c) = network.get_p2p_convo(*event_id) {
                c
            } else {
                continue;
            };

            // only want inbound peers that replicate this DB
            if convo.is_outbound() {
                continue;
            }
            if !convo.replicates_stackerdb(&self.smart_contract_id) {
                continue;
            }

            let naddr = convo.to_neighbor_address();
            let has_reciprocal_outbound = network
                .get_pubkey_events(&naddr.public_key_hash)
                .iter()
                .find(|event_id| {
                    if let Some(convo) = network.get_p2p_convo(**event_id) {
                        if !convo.is_outbound() {
                            return false;
                        }
                        let other_naddr = convo.to_neighbor_address();
                        if sent_naddr_set.contains(&other_naddr) {
                            return true;
                        }
                    }
                    return false;
                })
                .is_some();

            if has_reciprocal_outbound {
                // this inbound neighbor is also connected to us as an outbound neighbor, and we
                // already sent it a getchunkinv request
                continue;
            }

            let chunks_req = self.make_getchunkinv(&network.get_chain_view().rc_consensus_hash);
            to_send.push((naddr, chunks_req));
        }

        for (naddr, chunks_req) in to_send.into_iter() {
            test_debug!("{:?}: send_getchunksinv_to_inbound_neighbors: Send StackerDBGetChunkInv to inbound {:?}", network.get_local_peer(), &naddr);
            if let Err(_e) = self.comms.neighbor_send(network, &naddr, chunks_req) {
                info!(
                    "{:?}: Failed to send StackerDBGetChunkInv to inbound {:?}: {:?}",
                    network.get_local_peer(),
                    &naddr,
                    &_e
                );
            }
        }
    }

    /// Establish sessions with remote replicas.
    /// We might not be connected to any yet.
    /// Clears self.replicas, and fills in self.connected_replicas with already-connected neighbors
    /// Returns Ok(true) if we can proceed to sync
    /// Returns Ok(false) if we have no known peers
    /// Returns Err(..) on DB query error
    pub fn connect_begin(&mut self, network: &mut PeerNetwork) -> Result<bool, net_error> {
        if self.replicas.len() == 0 {
            // find some from the peer Db
            let replicas = PeerDB::find_stacker_db_replicas(
                network.peerdb_conn(),
                network.get_local_peer().network_id,
                &self.smart_contract_id,
                self.max_neighbors,
            )?
            .into_iter()
            .map(|neighbor| NeighborAddress::from_neighbor(&neighbor))
            .collect();
            self.replicas = replicas;
        }
        test_debug!(
            "{:?}: connect_begin: establish StackerDB sessions to {} neighbors",
            network.get_local_peer(),
            self.replicas.len()
        );
        if self.replicas.len() == 0 {
            // nothing to do
            return Ok(false);
        }

        let naddrs = mem::replace(&mut self.replicas, HashSet::new());
        for naddr in naddrs.into_iter() {
            if self.comms.has_neighbor_session(network, &naddr) {
                test_debug!(
                    "{:?}: connect_begin: already connected to StackerDB peer {:?}",
                    network.get_local_peer(),
                    &naddr
                );
                self.connected_replicas.insert(naddr);
                continue;
            }

            test_debug!(
                "{:?}: connect_begin: Send Handshake to StackerDB peer {:?}",
                network.get_local_peer(),
                &naddr
            );
            match self.comms.neighbor_session_begin(network, &naddr) {
                Ok(true) => {
                    // connected!
                    test_debug!(
                        "{:?}: connect_begin: connected to StackerDB peer {:?}",
                        network.get_local_peer(),
                        &naddr
                    );
                }
                Ok(false) => {
                    // need to retry
                    self.replicas.insert(naddr);
                }
                Err(_e) => {
                    info!("Failed to begin session with {:?}: {:?}", &naddr, &_e);
                }
            }
        }
        Ok(self.replicas.len() == 0)
    }

    /// Finish up connecting to our replicas.
    /// Fills in self.connected_replicas based on receipt of a handshake accept.
    /// Returns true if we've received all pending messages
    /// Returns false otherwise
    pub fn connect_try_finish(&mut self, network: &mut PeerNetwork) -> Result<bool, net_error> {
        for (naddr, message) in self.comms.collect_replies(network).into_iter() {
            let data = match message.payload {
                StacksMessageType::StackerDBHandshakeAccept(_, db_data) => {
                    if network.get_chain_view().rc_consensus_hash != db_data.rc_consensus_hash {
                        // stale or inconsistent view. Do not proceed
                        debug!(
                            "{:?}: remote peer {:?} has stale view ({} != {})",
                            network.get_local_peer(),
                            &naddr,
                            &network.get_chain_view().rc_consensus_hash,
                            &db_data.rc_consensus_hash
                        );
                        continue;
                    }
                    db_data
                }
                StacksMessageType::Nack(data) => {
                    debug!(
                        "{:?}: remote peer {:?} NACK'ed us with code {}",
                        &network.get_local_peer(),
                        &naddr,
                        data.error_code
                    );
                    continue;
                }
                x => {
                    info!("Received unexpected message {:?}", &x);
                    continue;
                }
            };

            if data
                .smart_contracts
                .iter()
                .find(|db_id| *db_id == &self.smart_contract_id)
                .is_none()
            {
                debug!(
                    "{:?}: remote peer does not replicate {}",
                    network.get_local_peer(),
                    &self.smart_contract_id
                );

                // disconnect
                self.comms.add_dead(network, &naddr);
                continue;
            }

            test_debug!(
                "{:?}: connect_try_finish: Received StackerDBHandshakeAccept from {:?} for {:?}",
                network.get_local_peer(),
                &naddr,
                &data
            );

            // this neighbor is good
            self.connected_replicas.insert(naddr);
        }

        if self.comms.count_inflight() > 0 {
            // still blocked
            return Ok(false);
        }

        if self.connected_replicas.len() == 0 {
            // no one to talk to
            test_debug!(
                "{:?}: connect_try_finish: no valid replicas",
                network.get_local_peer()
            );
            return Err(net_error::PeerNotConnected);
        }

        Ok(true)
    }

    /// Ask each replica for its chunk inventories.
    /// Also ask each inbound neighbor.
    /// Clears self.connected_replicas.
    /// StackerDBGetChunksInv
    /// Always succeeds; does not block.
    pub fn getchunksinv_begin(&mut self, network: &mut PeerNetwork) {
        let naddrs = mem::replace(&mut self.connected_replicas, HashSet::new());
        let mut already_sent = vec![];
        test_debug!(
            "{:?}: getchunksinv_begin: Send StackerDBGetChunksInv to {} replicas",
            network.get_local_peer(),
            naddrs.len()
        );
        for naddr in naddrs.into_iter() {
            test_debug!(
                "{:?}: getchunksinv_begin: Send StackerDBGetChunksInv to {:?}",
                network.get_local_peer(),
                &naddr
            );
            let chunks_req = self.make_getchunkinv(&network.get_chain_view().rc_consensus_hash);
            if let Err(e) = self.comms.neighbor_send(network, &naddr, chunks_req) {
                info!(
                    "{:?}: failed to send StackerDBGetChunkInv to {:?}: {:?}",
                    network.get_local_peer(),
                    &naddr,
                    &e
                );
                continue;
            }
            already_sent.push(naddr);
        }
        self.send_getchunkinv_to_inbound_neighbors(network, &already_sent);
    }

    /// Collect each chunk inventory request.
    /// Restores self.connected_replicas based on messages received.
    /// Return Ok(true) if we've received all pending messages
    /// Return Ok(false) if not
    pub fn getchunksinv_try_finish(
        &mut self,
        network: &mut PeerNetwork,
    ) -> Result<bool, net_error> {
        for (naddr, message) in self.comms.collect_replies(network).into_iter() {
            let chunk_inv = match message.payload {
                StacksMessageType::StackerDBChunkInv(data) => {
                    if data.slot_versions.len() != self.num_slots {
                        info!("{:?}: Received malformed StackerDBChunkInv from {:?}: expected {} chunks, got {}", network.get_local_peer(), &naddr, self.num_slots, data.slot_versions.len());
                        self.comms.add_broken(network, &naddr);
                        continue;
                    }
                    data
                }
                StacksMessageType::Nack(data) => {
                    debug!(
                        "{:?}: remote peer {:?} NACK'ed us with code {}",
                        &network.get_local_peer(),
                        &naddr,
                        data.error_code
                    );
                    continue;
                }
                x => {
                    info!("Received unexpected message {:?}", &x);
                    continue;
                }
            };
            test_debug!(
                "{:?}: getchunksinv_try_finish: Received StackerDBChunkInv from {:?}",
                network.get_local_peer(),
                &naddr
            );
            self.chunk_invs.insert(naddr.clone(), chunk_inv);
            self.connected_replicas.insert(naddr);
        }
        if self.comms.count_inflight() > 0 {
            // not done yet, so blocked
            return Ok(false);
        }

        // got everything. Calculate download priority
        let priorities = self.make_chunk_request_schedule(&network, None)?;
        let expected_versions = self.stackerdbs.get_slot_versions(&self.smart_contract_id)?;

        self.chunk_fetch_priorities = priorities;
        self.expected_versions = expected_versions;
        Ok(true)
    }

    /// Ask each prioritized replica for some chunks we need.
    /// Return Ok(true) if we processed all requested chunks
    /// Return Ok(false) if there are still some requests to make
    pub fn getchunks_begin(&mut self, network: &mut PeerNetwork) -> bool {
        if self.chunk_fetch_priorities.len() == 0 {
            // done
            return true;
        }

        let mut cur_priority = self.next_chunk_fetch_priority % self.chunk_fetch_priorities.len();

        test_debug!(
            "{:?}: getchunks_begin: Issue up to {} StackerDBGetChunk requests",
            &network.get_local_peer(),
            self.request_capacity
        );

        // fill up our comms with $capacity requests
        for _i in 0..self.request_capacity {
            if self.comms.count_inflight() >= self.request_capacity {
                break;
            }

            let chunk_request = self.chunk_fetch_priorities[cur_priority].0.clone();
            let selected_neighbor_opt = self.chunk_fetch_priorities[cur_priority]
                .1
                .iter()
                .enumerate()
                .find(|(_i, naddr)| !self.comms.has_inflight(naddr));

            let (idx, selected_neighbor) = if let Some(x) = selected_neighbor_opt {
                x
            } else {
                continue;
            };

            test_debug!(
                "{:?}: getchunks_begin: Send StackerDBGetChunk(db={},id={},ver={}) to {}",
                &network.get_local_peer(),
                &self.smart_contract_id,
                chunk_request.slot_id,
                chunk_request.slot_version,
                &selected_neighbor
            );

            if let Err(e) = self.comms.neighbor_send(
                network,
                &selected_neighbor,
                StacksMessageType::StackerDBGetChunk(chunk_request.clone()),
            ) {
                info!(
                    "{:?}: Failed to request chunk {} of {} from {:?}: {:?}",
                    network.get_local_peer(),
                    chunk_request.slot_id,
                    &self.smart_contract_id,
                    &selected_neighbor,
                    &e
                );
                self.connected_replicas.remove(&selected_neighbor);
                continue;
            }

            // don't ask this neighbor again
            self.chunk_fetch_priorities[cur_priority].1.remove(idx);

            // next-prioritized chunk
            cur_priority = (cur_priority + 1) % self.chunk_fetch_priorities.len();
        }
        self.next_chunk_fetch_priority = cur_priority;

        self.chunk_fetch_priorities.len() == 0
    }

    /// Collect chunk replies from neighbors
    /// Returns Ok(true) if all inflight messages have been received (or dealt with)
    /// Returns Ok(false) otherwise
    pub fn getchunks_try_finish(
        &mut self,
        network: &mut PeerNetwork,
        config: &StackerDBConfig,
    ) -> Result<bool, net_error> {
        for (naddr, message) in self.comms.collect_replies(network).into_iter() {
            let data = match message.payload {
                StacksMessageType::StackerDBChunk(data) => data,
                StacksMessageType::Nack(data) => {
                    debug!(
                        "{:?}: remote peer {:?} NACK'ed our StackerDBGetChunk with code {}",
                        network.get_local_peer(),
                        &naddr,
                        data.error_code
                    );
                    self.connected_replicas.remove(&naddr);
                    continue;
                }
                x => {
                    info!("Received unexpected message {:?}", &x);
                    continue;
                }
            };

            // validate
            if !self.validate_downloaded_chunk(network, config, &data)? {
                info!(
                    "Remote neighbor {:?} served an invalid chunk for ID {}",
                    &naddr, data.slot_id
                );
                self.comms.add_broken(network, &naddr);
                self.connected_replicas.remove(&naddr);
                continue;
            }

            // update bookkeeping
            test_debug!(
                "{:?}: getchunks_try_finish: Received StackerDBChunk from {:?}",
                network.get_local_peer(),
                &naddr
            );
            self.add_downloaded_chunk(naddr, data);
        }

        Ok(self.comms.count_inflight() == 0)
    }

    /// Push out chunks to peers
    /// Returns true if there are no more chunks to push.
    /// Returns false if there are
    pub fn pushchunks_begin(&mut self, network: &mut PeerNetwork) -> Result<bool, net_error> {
        if self.chunk_push_priorities.len() == 0 {
            let priorities = self.make_chunk_push_schedule(&network)?;
            self.chunk_push_priorities = priorities;
        }
        if self.chunk_push_priorities.len() == 0 {
            // done
            return Ok(true);
        }

        let mut cur_priority = self.next_chunk_push_priority % self.chunk_push_priorities.len();

        test_debug!(
            "{:?}: pushchunks_begin: Send up to {} StackerDBChunk pushes",
            &network.get_local_peer(),
            self.chunk_push_priorities.len()
        );

        // fill up our comms with $capacity requests
        for _i in 0..self.request_capacity {
            if self.comms.count_inflight() >= self.request_capacity {
                break;
            }

            let chunk_push = self.chunk_push_priorities[cur_priority].0.clone();
            let selected_neighbor_opt = self.chunk_push_priorities[cur_priority]
                .1
                .iter()
                .enumerate()
                .find(|(_i, naddr)| !self.comms.has_inflight(naddr));

            let (idx, selected_neighbor) = if let Some(x) = selected_neighbor_opt {
                x
            } else {
                test_debug!("{:?}: pushchunks_begin: no available neighbor to send StackerDBChunk(db={},id={},ver={}) to",
                    &network.get_local_peer(),
                    &self.smart_contract_id,
                    chunk_push.chunk_data.slot_id,
                    chunk_push.chunk_data.slot_version,
                );
                continue;
            };

            test_debug!(
                "{:?}: pushchunks_begin: Send StackerDBChunk(db={},id={},ver={}) to {}",
                &network.get_local_peer(),
                &self.smart_contract_id,
                chunk_push.chunk_data.slot_id,
                chunk_push.chunk_data.slot_version,
                &selected_neighbor
            );

            let slot_id = chunk_push.chunk_data.slot_id;
            let slot_version = chunk_push.chunk_data.slot_version;
            if let Err(e) = self.comms.neighbor_send(
                network,
                &selected_neighbor,
                StacksMessageType::StackerDBPushChunk(chunk_push),
            ) {
                info!(
                    "{:?}: Failed to send chunk {} of {} from {:?}: {:?}",
                    network.get_local_peer(),
                    slot_id,
                    &self.smart_contract_id,
                    &selected_neighbor,
                    &e
                );
                self.connected_replicas.remove(&selected_neighbor);
                continue;
            }

            // record what we just sent
            self.chunk_push_receipts
                .insert(selected_neighbor.clone(), (slot_id, slot_version));

            // don't send to this neighbor again
            self.chunk_push_priorities[cur_priority].1.remove(idx);

            // next-prioritized chunk
            cur_priority = (cur_priority + 1) % self.chunk_push_priorities.len();
        }
        self.next_chunk_push_priority = cur_priority;
        Ok(self.chunk_push_priorities.len() == 0)
    }

    /// Collect push-chunk replies from neighbors.
    /// If a remote neighbor replies with a chunk-inv for a pushed chunk which contains newer data
    /// than we have, then set `self.need_resync` to true.
    /// Returns true if all inflight messages have been received (or dealt with)
    /// Returns false otherwise
    pub fn pushchunks_try_finish(&mut self, network: &mut PeerNetwork) -> bool {
        for (naddr, message) in self.comms.collect_replies(network).into_iter() {
            let new_chunk_inv = match message.payload {
                StacksMessageType::StackerDBChunkInv(data) => data,
                StacksMessageType::Nack(data) => {
                    debug!(
                        "{:?}: remote peer {:?} NACK'ed our StackerDBChunk with code {}",
                        network.get_local_peer(),
                        &naddr,
                        data.error_code
                    );
                    self.connected_replicas.remove(&naddr);
                    continue;
                }
                x => {
                    info!("Received unexpected message {:?}", &x);
                    continue;
                }
            };

            // must be well-formed
            if new_chunk_inv.slot_versions.len() != self.num_slots {
                info!("{:?}: Received malformed StackerDBChunkInv from {:?}: expected {} chunks, got {}", network.get_local_peer(), &naddr, self.num_slots, new_chunk_inv.slot_versions.len());
                self.comms.add_broken(network, &naddr);
                continue;
            }

            // update bookkeeping
            test_debug!(
                "{:?}: pushchunks_try_finish: Received StackerDBChunkInv from {:?}",
                network.get_local_peer(),
                &naddr
            );

            if let Some((slot_id, _)) = self.chunk_push_receipts.get(&naddr) {
                self.need_resync = self.need_resync
                    || self.add_pushed_chunk(network, naddr, new_chunk_inv, *slot_id);
            }
        }

        self.comms.count_inflight() == 0
    }

    /// Recalculate the download schedule based on chunkinvs received on push
    pub fn recalculate_chunk_request_schedule(
        &mut self,
        network: &PeerNetwork,
    ) -> Result<(), net_error> {
        // figure out the new expected versions
        let mut expected_versions = vec![0u32; self.num_slots as usize];
        for (_, chunk_inv) in self.chunk_invs.iter() {
            for (slot_id, slot_version) in chunk_inv.slot_versions.iter().enumerate() {
                expected_versions[slot_id] = (*slot_version).max(expected_versions[slot_id]);
            }
        }

        let priorities =
            self.make_chunk_request_schedule(&network, Some(expected_versions.clone()))?;

        self.chunk_fetch_priorities = priorities;
        self.expected_versions = expected_versions;
        Ok(())
    }

    /// Forcibly wake up the state machine if it is throttled
    pub fn wakeup(&mut self) {
        test_debug!("wake up StackerDB sync for {}", &self.smart_contract_id);
        self.last_run_ts = 0;
    }

    /// Run the state machine.
    /// If we run to completion, then reset and return the sync result.
    /// Otherwise, if there's still more work to do, then return None
    pub fn run(
        &mut self,
        network: &mut PeerNetwork,
        config: &StackerDBConfig,
    ) -> Result<Option<StackerDBSyncResult>, net_error> {
        // throttle to write_freq
        if self.last_run_ts + config.write_freq > get_epoch_time_secs() {
            test_debug!(
                "{:?}: stacker DB sync for {} is throttled until {}",
                network.get_local_peer(),
                &self.smart_contract_id,
                self.last_run_ts + config.write_freq
            );
            return Ok(None);
        }

        loop {
            test_debug!(
                "{:?}: stacker DB sync state is {:?}",
                network.get_local_peer(),
                &self.state
            );
            let mut blocked = true;
            match self.state {
                StackerDBSyncState::ConnectBegin => {
                    let done = self.connect_begin(network)?;
                    if done {
                        self.state = StackerDBSyncState::ConnectFinish;
                        blocked = false;
                    }
                }
                StackerDBSyncState::ConnectFinish => {
                    let done = self.connect_try_finish(network)?;
                    if done {
                        self.state = StackerDBSyncState::GetChunksInvBegin;
                        blocked = false;
                    }
                }
                StackerDBSyncState::GetChunksInvBegin => {
                    // does not block
                    self.getchunksinv_begin(network);
                    self.state = StackerDBSyncState::GetChunksInvFinish;
                    blocked = false;
                }
                StackerDBSyncState::GetChunksInvFinish => {
                    let done = self.getchunksinv_try_finish(network)?;
                    if done {
                        self.state = StackerDBSyncState::GetChunks;
                        blocked = false;
                    }
                }
                StackerDBSyncState::GetChunks => {
                    if network.get_connection_opts().disable_stackerdb_get_chunks {
                        // fault injection -- force the system to rely exclusively on push-chunk
                        // behavior
                        self.state = StackerDBSyncState::PushChunks;
                        continue;
                    }

                    let requests_finished = self.getchunks_begin(network);
                    let inflight_finished = self.getchunks_try_finish(network, config)?;
                    let done = requests_finished && inflight_finished;
                    if done {
                        self.state = StackerDBSyncState::PushChunks;
                        blocked = false;
                    }
                }
                StackerDBSyncState::PushChunks => {
                    let pushes_finished = self.pushchunks_begin(network)?;
                    let inflight_finished = self.pushchunks_try_finish(network);
                    let done = pushes_finished && inflight_finished;
                    if done {
                        if self.need_resync
                            && !network.get_connection_opts().disable_stackerdb_get_chunks
                        {
                            // someone pushed newer chunk data to us, and getting chunks is
                            // enabled, so immediately go request them
                            self.recalculate_chunk_request_schedule(network)?;
                            self.state = StackerDBSyncState::GetChunks;
                        } else {
                            // done syncing
                            self.state = StackerDBSyncState::Finished;
                        }
                        self.need_resync = false;
                        blocked = false;
                    }
                }
                StackerDBSyncState::Finished => {
                    let result = self.reset(Some(network), config)?;
                    self.state = StackerDBSyncState::ConnectBegin;
                    self.last_run_ts = get_epoch_time_secs();
                    return Ok(Some(result));
                }
            };

            if blocked {
                return Ok(None);
            }
        }
    }
}
