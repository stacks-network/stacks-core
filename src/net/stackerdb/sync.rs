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

use crate::net::neighbors::NeighborSet;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::net::stackerdb::{
    StackerDB, StackerDBConfig, StackerDBPeerSet, StackerDBSync, StackerDBSyncResult,
    StackerDBSyncState,
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
    ContractId, NackData, Neighbor, NeighborKey, StackerDBChunkData, StackerDBChunkInvData,
    StackerDBGetChunkData, StackerDBGetChunkInvData, StacksMessageType,
};

use rand::prelude::SliceRandom;
use rand::thread_rng;
use rand::RngCore;

const MAX_CHUNKS_IN_FLIGHT: usize = 6;

impl NeighborSet for StackerDBPeerSet {
    fn add_connecting(&mut self, nk: &NeighborKey, event_id: usize) {
        self.connecting.insert(nk.clone(), event_id);
        self.pin_connection(event_id);
    }
    fn get_connecting(&self, nk: &NeighborKey) -> Option<usize> {
        self.connecting.get(nk).copied()
    }
    fn remove_connecting(&mut self, nk: &NeighborKey) {
        self.connecting.remove(nk);
    }
    fn add_dead(&mut self, nk: &NeighborKey) {
        self.dead.insert(nk.clone());
    }
    fn pin_connection(&mut self, event_id: usize) {
        self.peers.insert(event_id);
    }
    fn unpin_connection(&mut self, event_id: usize) {
        self.peers.remove(&event_id);
    }
    fn is_pinned(&self, event_id: usize) -> bool {
        self.peers.contains(&event_id)
    }
}

impl StackerDBPeerSet {
    pub fn new(smart_contract: ContractId, num_chunks: usize, write_freq: u64) -> StackerDBPeerSet {
        StackerDBPeerSet {
            smart_contract_id: smart_contract,
            num_chunks,
            write_freq,
            peers: HashSet::new(),
            connecting: HashMap::new(),
            dead: HashSet::new(),
            requests: HashMap::new(),
            next_requests: HashMap::new(),
            chunk_invs: HashMap::new(),
            chunk_priorities: vec![],
            next_chunk_priority: 0,
            expected_versions: vec![],
            downloaded_chunks: HashMap::new(),
        }
    }

    /// Declare a neighbor dead and unpin its connection
    pub fn add_dead_and_unpin(&mut self, nk: &NeighborKey, event_id: usize) {
        self.add_dead(nk);
        self.unpin_connection(event_id);
    }

    /// Advance to the next state.
    /// Move all next_requests into requests.
    pub fn advance(&mut self) {
        self.requests.clear();
        let next_requests = std::mem::replace(&mut self.next_requests, HashMap::new());
        self.requests = next_requests;
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
    pub fn make_chunk_request_schedule(
        &self,
        stackerdb: &StackerDB,
        rc_consensus_hash: &ConsensusHash,
    ) -> Result<Vec<(StackerDBGetChunkData, Vec<NeighborKey>)>, net_error> {
        let local_chunk_versions =
            stackerdb.get_chunk_versions(&self.smart_contract_id, rc_consensus_hash)?;
        let local_write_timestamps =
            stackerdb.get_chunk_write_timestamps(&self.smart_contract_id, rc_consensus_hash)?;
        assert_eq!(local_chunk_versions.len(), local_write_timestamps.len());

        let mut need_chunks: HashMap<usize, (StackerDBGetChunkData, Vec<NeighborKey>)> =
            HashMap::new();
        let now = get_epoch_time_secs();

        // who has data we need?
        for (i, local_version) in local_chunk_versions.iter().enumerate() {
            let write_ts = local_write_timestamps[i];
            if write_ts + self.write_freq >= now {
                test_debug!(
                    "Chunk {} was written too freuently ({} + {} >= {}), so will not fetch chunk",
                    local_chunk_versions[i],
                    write_ts,
                    self.write_freq,
                    now
                );
                continue;
            }

            for (nk, chunk_inv) in self.chunk_invs.iter() {
                assert_eq!(
                    chunk_inv.chunk_versions.len(),
                    local_chunk_versions.len(),
                    "FATAL: did not validate StackerDBChunkInvData"
                );

                if *local_version >= chunk_inv.chunk_versions[i] {
                    // remote peer has same view as local peer, or stale
                    continue;
                }

                if let Some((ref mut request, ref mut available)) = need_chunks.get_mut(&i) {
                    if request.chunk_version < chunk_inv.chunk_versions[i] {
                        // this peer has a newer view
                        available.clear();
                        available.push(nk.clone());
                        *request = StackerDBGetChunkData {
                            contract_id: self.smart_contract_id.clone(),
                            rc_consensus_hash: rc_consensus_hash.clone(),
                            chunk_id: i as u32,
                            chunk_version: chunk_inv.chunk_versions[i],
                        };
                    } else if request.chunk_version == chunk_inv.chunk_versions[i] {
                        // this peer has the same view as a prior peer.
                        // just track how many times we see this
                        available.push(nk.clone());
                    } else {
                        // this peer has an older view than the prior peer.
                        continue;
                    }
                } else {
                    // haven't seen anyone with this data yet
                    need_chunks.insert(
                        i,
                        (
                            StackerDBGetChunkData {
                                contract_id: self.smart_contract_id.clone(),
                                rc_consensus_hash: rc_consensus_hash.clone(),
                                chunk_id: i as u32,
                                chunk_version: chunk_inv.chunk_versions[i],
                            },
                            vec![nk.clone()],
                        ),
                    );
                }
            }
        }

        // prioritize requests by rarest-chunk-first order, but choose neighbors in random order
        let mut request_priority = BTreeMap::new();
        for (_i, (stacker_db_getchunkdata, mut neighbors)) in need_chunks.into_iter() {
            neighbors.shuffle(&mut thread_rng());
            request_priority.insert(
                (neighbors.len(), stacker_db_getchunkdata.chunk_id),
                (stacker_db_getchunkdata, neighbors),
            );
        }

        let mut ret = vec![];

        debug!(
            "Will request up to {} chunks from {}",
            &request_priority.len(),
            &self.smart_contract_id,
        );
        for (_, (stacker_db_getchunkdata, neighbors)) in request_priority.into_iter() {
            debug!(
                "Will request chunk {}/{}.{} from {:?}",
                &stacker_db_getchunkdata.contract_id,
                &stacker_db_getchunkdata.chunk_id,
                &stacker_db_getchunkdata.chunk_version,
                &neighbors
            );
            ret.push((stacker_db_getchunkdata, neighbors));
        }

        Ok(ret)
    }

    /// Validate a downloaded chunk
    pub fn validate_downloaded_chunk(
        &self,
        rc_consensus_hash: &ConsensusHash,
        data: &StackerDBChunkData,
        stacker_db: &StackerDB,
    ) -> Result<bool, net_error> {
        // validate -- must be a valid chunk
        if data.chunk_id >= (self.expected_versions.len() as u32) {
            info!(
                "Received StackerDBChunk ID {}, which is too big ({})",
                data.chunk_id,
                self.expected_versions.len()
            );
            return Ok(false);
        }

        // validate -- must be signed by the expected author
        let addr = match stacker_db.get_chunk_signer(
            &self.smart_contract_id,
            rc_consensus_hash,
            data.chunk_id,
        )? {
            Some(addr) => addr,
            None => {
                return Ok(false);
            }
        };

        let chunk_metadata = data.get_chunk_metadata(rc_consensus_hash.clone());
        if !chunk_metadata.verify(&addr)? {
            info!(
                "StackerDBChunk ID {} is not signed by {}",
                data.chunk_id, &addr
            );
            return Ok(false);
        }

        // validate -- must be the current or newer version
        let chunk_idx = data.chunk_id as usize;
        if data.chunk_version < self.expected_versions[chunk_idx] {
            info!(
                "Received StackerDBChunk ID {} version {}, which is stale (expected {})",
                data.chunk_id, data.chunk_version, self.expected_versions[chunk_idx]
            );
            return Ok(false);
        }

        // no need to validate the timestamp, because we already skipped requesting it if it was
        // written too recently.

        Ok(true)
    }

    /// Store a downloaded chunk to RAM, and update bookkeeping
    pub fn add_downloaded_chunk(&mut self, nk: NeighborKey, data: StackerDBChunkData) {
        let chunk_id = data.chunk_id;
        let _chunk_version = data.chunk_version;

        if let Some(data_list) = self.downloaded_chunks.get_mut(&nk) {
            data_list.push(data);
        } else {
            self.downloaded_chunks.insert(nk.clone(), vec![data]);
        }

        // yes, this is a linear scan. But because the number of chunks in the DB is a small O(1)
        // enforced by the protocol, this isn't a big deal.
        // This loop is only expected to run once, but is in place for defensive purposes.
        loop {
            let mut remove_idx = None;
            for (i, (chunk, ..)) in self.chunk_priorities.iter().enumerate() {
                if chunk.chunk_id == chunk_id {
                    remove_idx = Some(i);
                    break;
                }
            }
            if let Some(remove_idx) = remove_idx {
                test_debug!(
                    "Downloaded chunk {}.{} from {:?}",
                    chunk_id,
                    _chunk_version,
                    &nk
                );
                self.chunk_priorities.remove(remove_idx);
            } else {
                break;
            }
        }
        if self.chunk_priorities.len() > 0 {
            let next_chunk_priority = self.next_chunk_priority % self.chunk_priorities.len();
            self.next_chunk_priority = next_chunk_priority;
        }
    }

    /// Make download requests -- keep our `requests` table full.
    /// Returns the (number of new requests created, number of requests in flight)
    fn send_getchunks_requests(&mut self, network: &mut PeerNetwork) -> (usize, usize) {
        if self.chunk_priorities.len() == 0 {
            return (0, self.requests.len());
        }

        let capacity = MAX_CHUNKS_IN_FLIGHT.saturating_sub(self.requests.len());
        let mut cur_priority = self.next_chunk_priority % self.chunk_priorities.len();
        let mut num_new_requests = 0;

        test_debug!(
            "{:?}: Issue up to {} StackerDBGetChunk requests",
            &network.local_peer,
            capacity
        );
        for _i in 0..capacity {
            let chunk_request = self.chunk_priorities[cur_priority].0.clone();

            let mut selected_neighbor = None;
            for (j, nk) in self.chunk_priorities[cur_priority].1.iter().enumerate() {
                if self.requests.get(&nk).is_some() {
                    // already talking to this neighbor
                    continue;
                }

                selected_neighbor = Some((j, nk.clone()));
                break;
            }

            if let Some((idx, nk)) = selected_neighbor {
                let handle = match Self::neighbor_send(
                    network,
                    &nk,
                    StacksMessageType::StackerDBGetChunk(chunk_request.clone()),
                ) {
                    Ok(h) => h,
                    Err(e) => {
                        info!(
                            "Failed to request chunk {} of {} from {:?}: {:?}",
                            chunk_request.chunk_id, &self.smart_contract_id, &nk, &e
                        );
                        continue;
                    }
                };

                debug!(
                    "{:?}: Send StackerDBGetChunk(db={},id={},ver={}) to {}",
                    &network.local_peer,
                    &self.smart_contract_id,
                    chunk_request.chunk_id,
                    chunk_request.chunk_version,
                    &nk
                );
                self.requests.insert(nk, handle);

                num_new_requests += 1;
                self.chunk_priorities[cur_priority].1.remove(idx);
            }

            cur_priority = (cur_priority + 1) % self.chunk_priorities.len();
            if cur_priority == self.next_chunk_priority {
                // looped around
                break;
            }
        }
        test_debug!(
            "{:?}: Issued {} StackerDBGetChunk requests; {} in-flight",
            &network.local_peer,
            num_new_requests,
            self.requests.len()
        );
        self.next_chunk_priority = cur_priority;
        (num_new_requests, self.requests.len())
    }

    /// Convert ourselves into the result to store.
    pub fn into_stacker_db_sync_result(self) -> StackerDBSyncResult {
        let mut chunks = vec![];
        for (_, mut data) in self.downloaded_chunks.into_iter() {
            chunks.append(&mut data);
        }
        StackerDBSyncResult {
            contract_id: self.smart_contract_id,
            chunks_to_store: chunks,
            dead: self.dead,
        }
    }
}

impl StackerDBSyncState {
    /// Initialize the state machine for replicating a DB.
    /// Finds some initial peers.
    /// Returns NoSuchNeighbor if there aren't any known replicas.
    pub fn new(
        smart_contract: ContractId,
        num_chunks: usize,
        write_freq: u64,
        peerdb: &PeerDB,
        max_neighbors: usize,
        start_time: u64,
    ) -> Result<StackerDBSyncState, net_error> {
        let local_peer = PeerDB::get_local_peer(peerdb.conn())?;
        let peers = PeerDB::find_stacker_db_replicas(
            peerdb.conn(),
            local_peer.network_id,
            &smart_contract,
            max_neighbors,
        )?;
        if peers.len() == 0 {
            debug!("No available peers to replicate {}", &smart_contract);
        }
        Ok(StackerDBSyncState::ConnectBegin(
            peers,
            StackerDBPeerSet::new(smart_contract.clone(), num_chunks, write_freq),
            start_time,
        ))
    }

    /// Ask inbound neighbors who replicate this DB for their chunks.
    /// Returns the map of reply handles.
    /// TODO: limit the number
    fn send_getchunkinv_to_inbound_neighbors(
        network: &mut PeerNetwork,
        neighbor_set: &StackerDBPeerSet,
    ) -> HashMap<NeighborKey, ReplyHandleP2P> {
        let mut ret = HashMap::new();
        let mut to_send = vec![];
        for (_, convo) in network.peers.iter() {
            if !ConversationP2P::supports_stackerdb(convo.peer_services) {
                continue;
            }
            if convo.is_outbound() {
                continue;
            }
            if !convo.replicates_stackerdb(&neighbor_set.smart_contract_id) {
                continue;
            }
            let nk = convo.to_neighbor_key();
            let chunks_req = neighbor_set.make_getchunkinv(&network.chain_view.rc_consensus_hash);
            to_send.push((nk, chunks_req));
        }

        for (nk, chunks_req) in to_send.into_iter() {
            match StackerDBPeerSet::neighbor_send(network, &nk, chunks_req) {
                Ok(handle) => {
                    ret.insert(nk, handle);
                }
                Err(e) => {
                    warn!("Failed to send GetChunkInv to {:?}: {:?}", &nk, &e);
                }
            }
        }
        ret
    }

    /// Establish sessions with remote replicas.
    /// We might not be connected to any yet.
    fn run_connect_begin(
        network: &mut PeerNetwork,
        neighbors: Vec<Neighbor>,
        mut neighbor_set: StackerDBPeerSet,
        start_time: u64,
    ) -> Result<StackerDBSyncState, net_error> {
        test_debug!(
            "{:?}: StackerDBSyncState run_connect_begin",
            &network.local_peer
        );
        if get_epoch_time_secs() < start_time {
            return Ok(StackerDBSyncState::ConnectBegin(
                neighbors,
                neighbor_set,
                start_time,
            ));
        }

        let mut retry_requests = vec![];
        for neighbor in neighbors.into_iter() {
            if network.can_register_peer(&neighbor.addr, true).is_ok() {
                // neighbor is not yet connected
                match neighbor_set.neighbor_session_begin(
                    network,
                    &neighbor.addr,
                    &Hash160::from_node_public_key(&neighbor.public_key),
                ) {
                    Ok(Some(handle)) => {
                        neighbor_set.next_requests.insert(neighbor.addr, handle);
                    }
                    Ok(None) => {
                        retry_requests.push(neighbor);
                    }
                    Err(e) => {
                        info!("Failed to connect to {:?}: {:?}", &neighbor.addr, &e);
                        continue;
                    }
                }
            } else {
                debug!(
                    "{:?}: already connected to {}",
                    &network.local_peer, &neighbor.addr
                );

                // proceed to ask for a chunk inventory
                let chunks_req =
                    neighbor_set.make_getchunkinv(&network.chain_view.rc_consensus_hash);
                let handle = StackerDBPeerSet::neighbor_send(network, &neighbor.addr, chunks_req)?;
                neighbor_set.next_requests.insert(neighbor.addr, handle);
            }
        }
        if retry_requests.len() == 0 {
            // *also* ask any *existing* neighbors who have this DB for their chunk invs
            let mut existing_neighbor_requests =
                Self::send_getchunkinv_to_inbound_neighbors(network, &neighbor_set);
            for (nk, rh) in existing_neighbor_requests.drain() {
                neighbor_set.next_requests.insert(nk, rh);
            }

            // attempted all connections
            neighbor_set.advance();
            return Ok(StackerDBSyncState::ConnectFinish(neighbor_set));
        } else {
            // still must attempt more
            return Ok(StackerDBSyncState::ConnectBegin(
                retry_requests,
                neighbor_set,
                start_time,
            ));
        }
    }

    /// Finish establishing all connections, and if we asked for a chunk inventory, handle that as
    /// well.
    fn run_connect_finish(
        network: &mut PeerNetwork,
        mut neighbor_set: StackerDBPeerSet,
    ) -> Result<StackerDBSyncState, net_error> {
        debug!(
            "{:?}: StackerDBSyncState run_connect_finish",
            &network.local_peer
        );
        let mut requests = std::mem::replace(&mut neighbor_set.requests, HashMap::new());
        let mut retry_requests = HashMap::new();
        for (nk, rh) in requests.drain() {
            let event_id = rh.get_event_id();
            match neighbor_set.neighbor_try_recv(network, &nk, rh) {
                Ok(message) => {
                    match message.payload {
                        StacksMessageType::StackerDBHandshakeAccept(_, db_data) => {
                            if network.chain_view.rc_consensus_hash != db_data.rc_consensus_hash {
                                // stale or inconsistent view. Do not proceed
                                debug!(
                                    "{:?}: remote peer {:?} has stale view ({} != {})",
                                    &network.local_peer,
                                    &nk,
                                    &network.chain_view.rc_consensus_hash,
                                    &db_data.rc_consensus_hash
                                );
                                neighbor_set.unpin_connection(event_id);
                                continue;
                            }

                            // ask for chunk inv
                            let chunks_req =
                                neighbor_set.make_getchunkinv(&db_data.rc_consensus_hash);
                            let handle = StackerDBPeerSet::neighbor_send(network, &nk, chunks_req)?;
                            neighbor_set.next_requests.insert(nk, handle);
                        }
                        StacksMessageType::StackerDBChunkInv(data) => {
                            // got a chunk inv, because this neighbor was already connected and we
                            // didn't need to handshake.  Proceed to store if well-formed.
                            if data.chunk_versions.len() != neighbor_set.num_chunks {
                                info!("Received malformed StackerDBChunkInv from {:?}: expected {} chunks, got {}", &nk, neighbor_set.num_chunks, data.chunk_versions.len());
                                continue;
                            }

                            neighbor_set.chunk_invs.insert(nk, data);
                        }
                        StacksMessageType::Nack(data) => {
                            debug!(
                                "{:?}: remote peer {:?} NACK'ed us with code {}",
                                &network.local_peer, &nk, data.error_code
                            );
                            neighbor_set.unpin_connection(event_id);
                            continue;
                        }
                        x => {
                            info!("Received unexpected message {:?}", &x);
                            neighbor_set.add_dead_and_unpin(&nk, event_id);
                            continue;
                        }
                    }
                }
                Err(Ok(retry)) => {
                    retry_requests.insert(nk, retry);
                }
                Err(Err(e)) => {
                    info!("Failed to finish connecting to {:?}: {:?}", &nk, &e);
                    neighbor_set.add_dead_and_unpin(&nk, event_id);
                    continue;
                }
            }
        }
        neighbor_set.requests = retry_requests;

        if neighbor_set.requests.len() == 0 {
            // no more requests to complete. Can advance.
            neighbor_set.advance();
            return Ok(StackerDBSyncState::GetChunkInv(neighbor_set));
        } else {
            // must keep trying
            return Ok(StackerDBSyncState::ConnectFinish(neighbor_set));
        }
    }

    /// Finish fetching chunk invs, and when we do, schedule and kick off chunk requests.
    fn run_getchunkinv(
        network: &mut PeerNetwork,
        stackerdb: &StackerDB,
        mut neighbor_set: StackerDBPeerSet,
    ) -> Result<StackerDBSyncState, net_error> {
        debug!(
            "{:?}: StackerDBSyncState run_getchunkinv",
            &network.local_peer
        );
        let mut requests = std::mem::replace(&mut neighbor_set.requests, HashMap::new());
        let mut retry_requests = HashMap::new();
        for (nk, rh) in requests.drain() {
            let event_id = rh.get_event_id();
            match neighbor_set.neighbor_try_recv(network, &nk, rh) {
                Ok(message) => {
                    debug!(
                        "{:?}: got {} from {:?}",
                        &network.local_peer,
                        &message.payload.get_message_description(),
                        &nk
                    );
                    match message.payload {
                        StacksMessageType::StackerDBChunkInv(data) => {
                            // must be well-formed
                            if data.chunk_versions.len() != neighbor_set.num_chunks {
                                info!("Received malformed StackerDBChunkInv from {:?}: expected {} chunks, got {}", &nk, neighbor_set.num_chunks, data.chunk_versions.len());
                                continue;
                            }

                            neighbor_set.chunk_invs.insert(nk, data);
                        }
                        StacksMessageType::Nack(data) => {
                            debug!("{:?}: remote peer {:?} NACK'ed our StackerDBGetChunkInv with code {}", &network.local_peer, &nk, data.error_code);
                            neighbor_set.unpin_connection(event_id);
                            continue;
                        }
                        x => {
                            info!("Received unexpected message {:?}", &x);
                            neighbor_set.add_dead_and_unpin(&nk, event_id);
                            continue;
                        }
                    }
                }
                Err(Ok(retry)) => {
                    retry_requests.insert(nk, retry);
                }
                Err(Err(e)) => {
                    info!(
                        "Failed to finish getting chunk inv from {:?}: {:?}",
                        &nk, &e
                    );
                    neighbor_set.add_dead_and_unpin(&nk, event_id);
                    continue;
                }
            }
        }
        neighbor_set.requests = retry_requests;
        if neighbor_set.requests.len() == 0 {
            // no more requests to complete. Can advance
            neighbor_set.advance();

            // schedule downloads
            let priorities = neighbor_set
                .make_chunk_request_schedule(stackerdb, &network.chain_view.rc_consensus_hash)?;
            let expected_versions = stackerdb.get_chunk_versions(
                &neighbor_set.smart_contract_id,
                &network.chain_view.rc_consensus_hash,
            )?;
            neighbor_set.chunk_priorities = priorities;
            neighbor_set.expected_versions = expected_versions;

            // begin requests
            neighbor_set.send_getchunks_requests(network);
            return Ok(StackerDBSyncState::GetChunks(neighbor_set));
        } else {
            // must keep trying
            return Ok(StackerDBSyncState::GetChunkInv(neighbor_set));
        }
    }

    /// Go get chunks.
    fn run_getchunks(
        network: &mut PeerNetwork,
        stackerdb: &StackerDB,
        mut neighbor_set: StackerDBPeerSet,
    ) -> Result<StackerDBSyncState, net_error> {
        debug!(
            "{:?}: StackerDBSyncState run_getchunks",
            &network.local_peer
        );
        let mut requests = std::mem::replace(&mut neighbor_set.requests, HashMap::new());
        let mut retry_requests = HashMap::new();
        for (nk, rh) in requests.drain() {
            let event_id = rh.get_event_id();
            match neighbor_set.neighbor_try_recv(network, &nk, rh) {
                Ok(message) => {
                    debug!(
                        "{:?}: got {} from {:?}",
                        &network.local_peer,
                        &message.payload.get_message_description(),
                        &nk
                    );
                    match message.payload {
                        StacksMessageType::StackerDBChunk(data) => {
                            // validate
                            if !neighbor_set.validate_downloaded_chunk(
                                &network.chain_view.rc_consensus_hash,
                                &data,
                                stackerdb,
                            )? {
                                info!(
                                    "Remote neighbor {:?} served an invalid chunk for ID {}",
                                    &nk, data.chunk_id
                                );
                                neighbor_set.add_dead_and_unpin(&nk, event_id);
                                continue;
                            }

                            // update bookkeeping
                            neighbor_set.add_downloaded_chunk(nk, data);
                        }
                        StacksMessageType::Nack(data) => {
                            debug!(
                                "{:?}: remote peer {:?} NACK'ed our StackerDBGetChunk with code {}",
                                &network.local_peer, &nk, data.error_code
                            );
                            neighbor_set.unpin_connection(event_id);
                            continue;
                        }
                        x => {
                            info!("Received unexpected message {:?}", &x);
                            neighbor_set.add_dead_and_unpin(&nk, event_id);
                            continue;
                        }
                    }
                }
                Err(Ok(retry)) => {
                    retry_requests.insert(nk, retry);
                }
                Err(Err(e)) => {
                    info!("Failed to finish getting chunk from {:?}: {:?}", &nk, &e);
                    neighbor_set.add_dead_and_unpin(&nk, event_id);
                    continue;
                }
            }
        }
        neighbor_set.requests = retry_requests;

        // keep the pipe full
        let (num_added, num_inflight) = neighbor_set.send_getchunks_requests(network);
        if num_added == 0 && num_inflight == 0 {
            // all requests terminated
            return Ok(StackerDBSyncState::Final(
                neighbor_set.into_stacker_db_sync_result(),
            ));
        } else {
            // some requests still in-flight
            return Ok(StackerDBSyncState::GetChunks(neighbor_set));
        }
    }

    /// Run the state-machine
    pub fn next_state(
        self,
        network: &mut PeerNetwork,
        stackerdb: &StackerDB,
    ) -> Result<StackerDBSyncState, net_error> {
        match self {
            StackerDBSyncState::ConnectBegin(neighbors, neighbor_set, start_time) => {
                Self::run_connect_begin(network, neighbors, neighbor_set, start_time)
            }
            StackerDBSyncState::ConnectFinish(neighbor_set) => {
                Self::run_connect_finish(network, neighbor_set)
            }
            StackerDBSyncState::GetChunkInv(neighbor_set) => {
                Self::run_getchunkinv(network, stackerdb, neighbor_set)
            }
            StackerDBSyncState::GetChunks(neighbor_set) => {
                Self::run_getchunks(network, stackerdb, neighbor_set)
            }
            StackerDBSyncState::Final(result) => Ok(StackerDBSyncState::Final(result)),
        }
    }

    /// Get a ref to the neighbor set
    pub fn neighbor_set(&self) -> Option<&StackerDBPeerSet> {
        match self {
            StackerDBSyncState::ConnectBegin(ref _neighbors, ref neighbor_set, _) => {
                Some(neighbor_set)
            }
            StackerDBSyncState::ConnectFinish(ref neighbor_set) => Some(neighbor_set),
            StackerDBSyncState::GetChunkInv(ref neighbor_set) => Some(neighbor_set),
            StackerDBSyncState::GetChunks(ref neighbor_set) => Some(neighbor_set),
            StackerDBSyncState::Final(_) => None,
        }
    }
}

impl StackerDBSync {
    pub fn new(
        peerdb: &PeerDB,
        smart_contract: ContractId,
        stackerdb_config: &StackerDBConfig,
        db_path: &str,
    ) -> Result<StackerDBSync, net_error> {
        if stackerdb_config.num_chunks > (usize::MAX as u64) {
            return Err(net_error::OverflowError(
                "StackerDB num_chunks exceeds usize::MAX".to_string(),
            ));
        }
        let num_neighbors = stackerdb_config.num_neighbors;
        let num_chunks = stackerdb_config.num_chunks as usize;
        let write_freq = stackerdb_config.write_freq;
        let stacker_db = StackerDB::connect(db_path, true)?;
        Ok(StackerDBSync {
            smart_contract_id: smart_contract.clone(),
            stacker_db,
            total_stored: 0,
            state: Some(StackerDBSyncState::new(
                smart_contract,
                num_chunks,
                write_freq,
                peerdb,
                num_neighbors,
                0,
            )?),
        })
    }

    /// Reset the state machine
    pub fn reset(
        &mut self,
        peerdb: &PeerDB,
        stackerdb_config: &StackerDBConfig,
    ) -> Result<(), net_error> {
        debug!("Reset StackerDBSync({})", &self.smart_contract_id,);
        let sc = self.smart_contract_id.clone();
        self.state = Some(StackerDBSyncState::new(
            sc,
            stackerdb_config.num_chunks as usize,
            stackerdb_config.write_freq,
            peerdb,
            stackerdb_config.num_neighbors,
            stackerdb_config.write_freq + get_epoch_time_secs(),
        )?);
        Ok(())
    }

    /// Run one state-machine pass.
    /// If the state machine
    pub fn run(
        &mut self,
        network: &mut PeerNetwork,
        stackerdb_config: &StackerDBConfig,
    ) -> Result<Option<StackerDBSyncResult>, net_error> {
        let state = self.state.take();
        if let Some(state) = state {
            let new_state = match state.next_state(network, &self.stacker_db) {
                Ok(state) => state,
                Err(e) => {
                    info!("Failed state transition: {:?}", &e);
                    self.reset(&network.peerdb, stackerdb_config)?;
                    return Ok(None);
                }
            };
            if let StackerDBSyncState::Final(result) = new_state {
                self.total_stored += result.chunks_to_store.len() as u64;
                self.reset(&network.peerdb, stackerdb_config)?;
                Ok(Some(result))
            } else {
                self.state = Some(new_state);
                Ok(None)
            }
        } else {
            self.reset(&network.peerdb, stackerdb_config)?;
            Ok(None)
        }
    }

    /// Get a ref to the neighbor set, if we're running
    pub fn neighbor_set(&self) -> Option<&StackerDBPeerSet> {
        if let Some(state) = self.state.as_ref() {
            state.neighbor_set()
        } else {
            None
        }
    }
}

impl PeerNetwork {
    /// Run all stacker DB sync state-machines
    pub fn run_stacker_db_sync(&mut self) -> Result<Vec<StackerDBSyncResult>, net_error> {
        let mut results = vec![];
        let mut stacker_db_syncs = self
            .stacker_db_syncs
            .take()
            .expect("FATAL: did not replace stacker dbs");
        let stacker_db_configs = self.stacker_db_configs.clone();

        for (sc, stacker_db_sync) in stacker_db_syncs.iter_mut() {
            if let Some(config) = stacker_db_configs.get(sc) {
                match stacker_db_sync.run(self, config) {
                    Ok(Some(result)) => {
                        // clear dead nodes
                        for dead in result.dead.iter() {
                            self.deregister_neighbor(dead);
                        }
                        results.push(result);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        info!(
                            "Failed to run StackerDB state machine for {}: {:?}",
                            &sc, &e
                        );
                    }
                }
            } else {
                info!("No stacker DB config for {}", &sc);
            }
        }
        self.stacker_db_syncs = Some(stacker_db_syncs);
        Ok(results)
    }
}
