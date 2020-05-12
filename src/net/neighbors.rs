/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/


use core::PEER_VERSION;

use net::PeerAddress;
use net::Neighbor;
use net::NeighborKey;
use net::Error as net_error;
use net::db::PeerDB;
use net::asn::ASEntry4;

use net::*;
use net::codec::*;

use net::connection::ConnectionOptions;
use net::connection::ReplyHandleP2P;

use net::db::LocalPeer;

use net::p2p::*;

use util::db::Error as db_error;
use util::db::DBConn;

use util::secp256k1::Secp256k1PublicKey;

use std::mem;
use std::net::SocketAddr;
use std::cmp;

use std::collections::HashMap;
use std::collections::HashSet;

use burnchains::Address;
use burnchains::PublicKey;
use burnchains::Burnchain;
use burnchains::BurnchainView;

use util::log;
use util::get_epoch_time_secs;
use util::hash::*;

use rand::prelude::*;
use rand::thread_rng;

use rusqlite::Transaction;

#[cfg(test)] pub const NEIGHBOR_MINIMUM_CONTACT_INTERVAL : u64 = 0;
#[cfg(not(test))] pub const NEIGHBOR_MINIMUM_CONTACT_INTERVAL : u64 = 600;      // don't reach out to a frontier neighbor more than once every 10 minutes

pub const NEIGHBOR_REQUEST_TIMEOUT : u64 = 10;

pub const NUM_INITIAL_WALKS : u64 = 10;     // how many unthrottled walks should we do when this peer starts up
#[cfg(test)] pub const PRUNE_FREQUENCY : u64 = 0;             // how often we should consider pruning neighbors
#[cfg(not(test))] pub const PRUNE_FREQUENCY : u64 = 43200;     // how often we should consider pruning neighbors (twice a day)
pub const MAX_NEIGHBOR_BLOCK_DELAY : u64 = 288;     // maximum delta between our current block height and the neighbor's that we will treat this neighbor as fresh

#[cfg(test)] pub const NEIGHBOR_WALK_INTERVAL : u64 = 0;
#[cfg(not(test))] pub const NEIGHBOR_WALK_INTERVAL : u64 = 120;     // seconds

impl Neighbor {
    pub fn empty(key: &NeighborKey, pubk: &Secp256k1PublicKey, expire_block: u64) -> Neighbor {
        Neighbor {
            addr: key.clone(),
            public_key: pubk.clone(),
            expire_block: expire_block,
            last_contact_time: 0,
            whitelisted: 0,
            blacklisted: 0,
            asn: 0,
            org: 0,
            in_degree: 1,
            out_degree: 1
        }
    }

    /// Update this peer in the DB.
    /// If there's no DB entry for this peer, then do nothing.
    pub fn save_update<'a>(&self, tx: &mut Transaction<'a>) -> Result<(), net_error> {
        PeerDB::update_peer(tx, &self)
            .map_err(net_error::DBError)
    }

    /// Save to the peer DB, inserting it if it isn't already there.
    /// Return true if saved.
    /// Return false if not saved -- i.e. the frontier is full and we should try evicting neighbors.
    pub fn save<'a>(&self, tx: &mut Transaction<'a>) -> Result<bool, net_error> {
        PeerDB::try_insert_peer(tx, &self)
            .map_err(net_error::DBError)
    }

    /// Attempt to load a neighbor from our peer DB, given its NeighborAddress reported by another
    /// peer.  Returns a neighbor in the peer DB if it matches the neighbor address and has a fresh public key
    /// (where "fresh" means "the public key hash matches the neighbor address")
    pub fn from_neighbor_address(conn: &DBConn, network_id: u32, block_height: u64, neighbor_address: &NeighborAddress) -> Result<Option<Neighbor>, net_error> {
        let peer_opt = PeerDB::get_peer(conn, network_id, &neighbor_address.addrbytes, neighbor_address.port)
            .map_err(net_error::DBError)?;

        match peer_opt {
            None => {
                Ok(None)       // unkonwn
            },
            Some(peer) => {
                // expired public key?
                if peer.expire_block < block_height {
                    Ok(None)
                }
                else {
                    let pubkey_160 = Hash160::from_data(&peer.public_key.to_bytes_compressed()[..]);
                    if pubkey_160 == neighbor_address.public_key_hash {
                        // we know this neighbor's key
                        Ok(Some(peer))
                    }
                    else {
                        // this neighbor's key may be stale
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Weighted _undirected_ degree estimate.
    /// If this were an undirected peer graph, the lower bound of a peer's degree would be
    /// min(in-degree, out-degree), and the upper bound would be max(in-degree, out-degree).
    /// Considering that "P1 points to P2" is just as likely as "P2 points to P1", this means that
    /// Pr["P1 points to P2" | "P2 points to P1"] == Pr["P2 points to P1" | "P1 points to P2"].
    /// So, we can estimate the undirected degree as being a random value between the lower and
    /// upper bound.
    pub fn degree(&self) -> u64 {
        let mut rng = thread_rng();
        let res = rng.gen_range(self.in_degree, self.out_degree+1) as u64;
        if res == 0 {
            1
        }
        else {
            res
        }
    }
}

/// Struct for capturing the results of a walk.
/// -- reports newly-connected neighbors
/// -- reports neighbors we had trouble talking to.
/// The peer network will use this struct to clean out dead neighbors, and to keep the number of
/// _outgoing_ connections limited to NUM_NEIGHBORS.
#[derive(Clone)]
pub struct NeighborWalkResult {
    pub new_connections: HashSet<NeighborKey>,
    pub dead_connections: HashSet<NeighborKey>,
    pub broken_connections: HashSet<NeighborKey>,
    pub replaced_neighbors: HashSet<NeighborKey>,
    pub burn_chain_tips: HashMap<NeighborKey, (u64, ConsensusHash)>,
    pub stable_burn_chain_tips: HashMap<NeighborKey, (u64, ConsensusHash)>,
    pub do_prune: bool
}

impl NeighborWalkResult {
    pub fn new() -> NeighborWalkResult {
        NeighborWalkResult {
            new_connections: HashSet::new(),
            dead_connections: HashSet::new(),
            broken_connections: HashSet::new(),
            replaced_neighbors: HashSet::new(),
            burn_chain_tips: HashMap::new(),
            stable_burn_chain_tips: HashMap::new(),
            do_prune: false
        }
    }

    pub fn add_new(&mut self, nk: NeighborKey) -> () {
        self.new_connections.insert(nk);
    }

    pub fn add_broken(&mut self, nk: NeighborKey) -> () {
        self.broken_connections.insert(nk);
    }
    
    pub fn add_dead(&mut self, nk: NeighborKey) -> () {
        self.dead_connections.insert(nk);
    }

    pub fn add_replaced(&mut self, nk: NeighborKey) -> () {
        self.replaced_neighbors.insert(nk);
    }

    pub fn add_chain_tip(&mut self, nk: NeighborKey, tip_height: u64, tip: ConsensusHash, stable_tip_height: u64, stable_tip: ConsensusHash) -> () {
        self.burn_chain_tips.insert(nk.clone(), (tip_height, tip));
        self.stable_burn_chain_tips.insert(nk, (stable_tip_height, stable_tip));
    }

    pub fn clear(&mut self) -> () {
        self.new_connections.clear();
        self.dead_connections.clear();
        self.broken_connections.clear();
        self.replaced_neighbors.clear();
        self.burn_chain_tips.clear();
        self.stable_burn_chain_tips.clear();
        self.do_prune = false;
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NeighborWalkState {
    HandshakeBegin,
    HandshakeFinish,
    GetNeighborsBegin,
    GetNeighborsFinish,
    GetHandshakesBegin,
    GetHandshakesFinish,
    GetNeighborsNeighborsBegin,
    GetNeighborsNeighborsFinish,
    NeighborsPingBegin,
    NeighborsPingFinish,
    Finished
}

pub struct NeighborWalk {
    pub state: NeighborWalkState,
    pub events: HashSet<usize>,

    local_peer: LocalPeer,
    chain_view: BurnchainView,

    connecting: HashMap<NeighborKey, usize>,

    // handshakes we've successfully made while waiting for others to complete 
    // (used in HandshakeBegin/HandshakeFinish and GetHandshakesBegin/GetHandshakesFinish)
    pending_handshakes: HashMap<NeighborAddress, ReplyHandleP2P>,

    // Addresses of neighbors resolved by GetNeighborsBegin/GetNeighborsFinish
    pending_neighbor_addrs: Option<Vec<NeighborAddress>>,

    prev_neighbor: Option<Neighbor>,
    cur_neighbor: Neighbor,
    next_neighbor: Option<Neighbor>,

    pub frontier: HashMap<NeighborKey, Neighbor>,
    new_frontier: HashMap<NeighborKey, Neighbor>,

    // pending request to cur_neighbor to handshake 
    handshake_request: Option<ReplyHandleP2P>,

    // pending request to cur_neighbor to get _its_ neighbors
    getneighbors_request: Option<ReplyHandleP2P>,

    // outstanding requests to handshake with our cur_neighbor's neighbors.
    resolved_handshake_neighbors: HashMap<NeighborAddress, Neighbor>,
    unresolved_handshake_neighbors: HashMap<NeighborAddress, ReplyHandleP2P>,

    // outstanding requests to get the neighbors of our cur_neighbor's neighbors
    resolved_getneighbors_neighbors: HashMap<NeighborKey, Vec<NeighborAddress>>,
    unresolved_getneighbors_neighbors: HashMap<NeighborKey, ReplyHandleP2P>,

    // outstanding requests to ping existing neighbors to be replaced in the frontier
    neighbor_replacements: HashMap<NeighborKey, Neighbor>,
    replaced_neighbors: HashMap<NeighborKey, u32>,
    unresolved_neighbor_pings: HashMap<NeighborKey, ReplyHandleP2P>,

    // neighbor walk result we build up incrementally 
    result: NeighborWalkResult,

    // time that we started/finished the last walk 
    walk_start_time: u64,
    walk_end_time: u64,

    // walk random-restart parameters
    walk_step_count: u64,           // how many times we've taken a step
    walk_min_duration: u64,         // minimum steps we have to take before reset
    walk_max_duration: u64,         // maximum steps we have to take before reset
    walk_reset_prob: f64            // probability that we do a reset once the minimum duration is met
}

impl NeighborWalk {
    pub fn new(local_peer: LocalPeer, chain_view: BurnchainView, neighbor: &Neighbor) -> NeighborWalk {
        NeighborWalk {
            local_peer: local_peer,
            chain_view: chain_view,

            state: NeighborWalkState::HandshakeBegin,
            events: HashSet::new(),

            connecting: HashMap::new(),
            pending_handshakes: HashMap::new(),
            pending_neighbor_addrs: None,

            prev_neighbor: None,
            cur_neighbor: neighbor.clone(),
            next_neighbor: None,
            
            frontier: HashMap::new(),
            new_frontier: HashMap::new(),
            
            handshake_request: None,
            getneighbors_request: None,

            resolved_handshake_neighbors: HashMap::new(),
            unresolved_handshake_neighbors: HashMap::new(),

            resolved_getneighbors_neighbors: HashMap::new(),
            unresolved_getneighbors_neighbors: HashMap::new(),

            neighbor_replacements: HashMap::new(),
            replaced_neighbors: HashMap::new(),
            unresolved_neighbor_pings: HashMap::new(),

            result: NeighborWalkResult::new(),

            walk_start_time: 0,
            walk_end_time: 0,
            
            walk_step_count: 0,
            walk_min_duration: 20,
            walk_max_duration: 40,
            walk_reset_prob: 0.05,
        }
    }

    /// Reset the walk with a new neighbor.
    /// Give back a report of the walk.
    /// Resets neighbor pointer.
    /// Clears out connections, but preserves state (frontier, result, etc.).
    pub fn reset(&mut self, next_neighbor: &Neighbor) -> NeighborWalkResult {
        debug!("Walk reset");
        self.state = NeighborWalkState::HandshakeBegin;

        self.prev_neighbor = Some(self.cur_neighbor.clone());
        self.cur_neighbor = next_neighbor.clone();
        self.next_neighbor = None;

        self.clear_connections();
        self.new_frontier.clear();

        let result = self.result.clone();

        self.walk_end_time = get_epoch_time_secs();

        // leave self.frontier and self.result alone until the next walk.
        // (makes it so that at the end of the walk, we can query the result and frontier)
        result
    }

    /// Clear the walk's intermittent state
    pub fn clear_state(&mut self) -> () {
        debug!("Walk clear state");
        self.new_frontier.clear();
        self.frontier.clear();
        self.result.clear();
    }

    /// Clear the walk's connection state
    pub fn clear_connections(&mut self) -> () {
        test_debug!("Walk clear connections");
        self.events.clear();
        self.connecting.clear();
        self.pending_handshakes.clear();
        self.pending_neighbor_addrs = None;

        self.handshake_request = None;
        self.getneighbors_request = None;

        self.resolved_handshake_neighbors.clear();
        self.unresolved_handshake_neighbors.clear();
        
        self.resolved_getneighbors_neighbors.clear();
        self.unresolved_getneighbors_neighbors.clear();

        self.neighbor_replacements.clear();
        self.replaced_neighbors.clear();
        self.unresolved_neighbor_pings.clear();
    }

    /// Update the state of the walk 
    /// (as a separate method for debugging purposes)
    fn set_state(&mut self, new_state: NeighborWalkState) -> () {
        test_debug!("{:?}: Advance walk state: {:?} --> {:?}", &self.local_peer, &self.state, &new_state);
        self.state = new_state;
    }

    /// Begin handshaking with our current neighbor 
    pub fn handshake_begin(&mut self, req: Option<ReplyHandleP2P>) -> () {
        assert!(self.state == NeighborWalkState::HandshakeBegin);

        self.handshake_request = req;

        // next state!
        self.set_state(NeighborWalkState::HandshakeFinish);
    }

    /// Finish handshaking with our current neighbor, thereby ensuring that it is connected 
    pub fn handshake_try_finish(&mut self, network: &mut PeerNetwork, burn_stable_block_height: u64) -> Result<Option<Neighbor>, net_error> {
        assert!(self.state == NeighborWalkState::HandshakeFinish);

        let req_opt = self.handshake_request.take();
        if req_opt.is_none() {
            return Ok(None);
        }

        let mut req = req_opt.unwrap();
        if let Err(e) = network.saturate_p2p_socket(req.get_event_id(), &mut req) {
            self.result.add_dead(self.cur_neighbor.addr.clone());
            return Err(e);
        }

        let handshake_reply_res = req.try_send_recv();
        match handshake_reply_res {
            Ok(message) => {
                // only consider this neighbor if it's _not_ bootstrapping
                if message.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY < burn_stable_block_height {
                    debug!("{:?}: neighbor {:?} is still bootstrapping (on block {})", &self.local_peer, self.cur_neighbor.addr.clone(), message.preamble.burn_stable_block_height);
                    Err(net_error::StaleNeighbor)
                }
                else {
                    match message.payload {
                        StacksMessageType::HandshakeAccept(ref data) => {
                            // accepted! can proceed to ask for neighbors
                            // save knowledge to the peer DB (NOTE: the neighbor should already be in
                            // the DB, since it's cur_neighbor)
                            debug!("{:?}: received HandshakeAccept from {:?}: {:?}", &self.local_peer, &message.to_neighbor_key(&data.handshake.addrbytes, data.handshake.port), &data.handshake);

                            let mut tx = network.peerdb.tx_begin()?;
                            let neighbor_from_handshake = Neighbor::from_handshake(&mut tx, message.preamble.peer_version, message.preamble.network_id, &data.handshake)?;
                            let res = 
                                if neighbor_from_handshake.addr != self.cur_neighbor.addr {
                                    // somehow, got a handshake from someone that _isn't_ cur_neighbor
                                    debug!("{:?}: got unsolicited HandshakeAccept from {:?} (expected {:?})", &self.local_peer, &neighbor_from_handshake.addr, &self.cur_neighbor.addr);
                                    Err(net_error::PeerNotConnected)
                                }
                                else {
                                    // this is indeed cur_neighbor
                                    self.cur_neighbor.handshake_update(&mut tx, &data.handshake)?;
                                    self.cur_neighbor.save_update(&mut tx)?;
                                   
                                    debug!("Connected with {:?}", &self.cur_neighbor.addr);
                                    self.new_frontier.insert(self.cur_neighbor.addr.clone(), self.cur_neighbor.clone());

                                    // remember the tip this peer reported
                                    self.result.add_chain_tip(self.cur_neighbor.addr.clone(), message.preamble.burn_block_height, message.preamble.burn_consensus_hash.clone(), message.preamble.burn_stable_block_height, message.preamble.burn_stable_consensus_hash.clone());

                                    // advance state!
                                    self.set_state(NeighborWalkState::GetNeighborsBegin);
                                    Ok(Some(self.cur_neighbor.clone()))
                                };
                            tx.commit()?;
                            res
                        },
                        StacksMessageType::HandshakeReject => {
                            // told to bugger off 
                            Err(net_error::PeerNotConnected)
                        },
                        StacksMessageType::Nack(_) => {
                            // something's wrong on our end (we're using a new key that they don't yet
                            // know about, or something)
                            Err(net_error::PeerNotConnected)
                        },
                        _ => {
                            // invalid message
                            debug!("{:?}: Got out-of-sequence message from {:?}", &self.local_peer, &self.cur_neighbor.addr);
                            self.result.add_broken(self.cur_neighbor.addr.clone());
                            Err(net_error::InvalidMessage)
                        }
                    }
                }
            },
            Err(req_res) => {
                match req_res {
                    Ok(same_req) => {
                        // try again
                        self.handshake_request = Some(same_req);
                        Ok(None)
                    },
                    Err(e) => {
                        // disconnected 
                        debug!("Failed to get Handshake reply from {:?}: {:?}", &self.cur_neighbor.addr, &e);
                        self.result.add_dead(self.cur_neighbor.addr.clone());
                        Err(e)
                    }
                }
            }
        }
    }

    /// Begin refreshing our knowledge of peer in/out degrees
    pub fn getneighbors_begin(&mut self, req: Option<ReplyHandleP2P>) -> () {
        assert!(self.state == NeighborWalkState::GetNeighborsBegin);
        
        self.resolved_handshake_neighbors.clear();
        self.unresolved_handshake_neighbors.clear();
        
        self.getneighbors_request = req;

        // next state!
        self.set_state(NeighborWalkState::GetNeighborsFinish);
    }

    /// Find the neighbor addresses that we need to resolve to neighbors,
    /// and find out the neighbor addresses that we already have fresh neighbor data for.
    /// If we know of a neighbor, and contacted it recently, then consider it resolved _even if_
    /// the reported NeighborAddress public key hash doesn't match our records.
    fn lookup_stale_neighbors(dbconn: &DBConn, network_id: u32, block_height: u64, addrs: &Vec<NeighborAddress>) -> Result<(HashMap<NeighborAddress, Neighbor>, Vec<NeighborAddress>), net_error> {
        let mut to_resolve = vec![];
        let mut resolved : HashMap<NeighborAddress, Neighbor> = HashMap::new();
        for naddr in addrs {
            let neighbor_opt = Neighbor::from_neighbor_address(dbconn, network_id, block_height, naddr)?;
            match neighbor_opt {
                None => {
                    // need to resolve this one, but don't talk to it if we did so recently (even
                    // if we have stale information for it -- the remote node could be trying to trick
                    // us into DDoS'ing this node).
                    let peer_opt = PeerDB::get_peer(dbconn, network_id, &naddr.addrbytes, naddr.port)
                        .map_err(net_error::DBError)?;

                    match peer_opt {
                        None => {
                            // okay, we really don't know about this neighbor
                            to_resolve.push((*naddr).clone());
                        },
                        Some(n) => {
                            // we know about this neighbor, but its key didn't match the
                            // neighboraddress.  Only try to re-connect with it if we haven't done
                            // so recently, so a rogue neighbor can't force us to DDoS another
                            // peer.
                            if n.last_contact_time + NEIGHBOR_MINIMUM_CONTACT_INTERVAL < get_epoch_time_secs() {
                                to_resolve.push((*naddr).clone());
                            }
                            else {
                                // recently contacted
                                resolved.insert(naddr.clone(), n);
                            }
                        }
                    }
                }
                Some(neighbor) => {
                    if neighbor.last_contact_time + NEIGHBOR_MINIMUM_CONTACT_INTERVAL < get_epoch_time_secs() {
                        // stale 
                        to_resolve.push((*naddr).clone());
                    }
                    else {
                        // our copy is still fresh 
                        resolved.insert(naddr.clone(), neighbor);
                    }
                }
            }
        }
        Ok((resolved, to_resolve))
    }

    /// Try to finish the getneighbors request to cur_neighbor
    /// Returns the list of neighbors we need to resolve
    /// Return None if we're not done yet, or haven't started yet.
    pub fn getneighbors_try_finish(&mut self, network: &mut PeerNetwork, block_height: u64) -> Result<Option<Vec<NeighborAddress>>, net_error> {
        assert!(self.state == NeighborWalkState::GetNeighborsFinish);

        let req_opt = self.getneighbors_request.take();
        if req_opt.is_none() {
            return Ok(None);
        }

        let mut req = req_opt.unwrap();
        if let Err(e) = network.saturate_p2p_socket(req.get_event_id(), &mut req) {
            self.result.add_dead(self.cur_neighbor.addr.clone());
            return Err(e);
        }

        let neighbors_reply_res = req.try_send_recv();
        match neighbors_reply_res {
            Ok(message) => {
                // only consider this neighbor if it's _not_ bootstrapping
                if message.preamble.burn_block_height + MAX_NEIGHBOR_BLOCK_DELAY < block_height {
                    test_debug!("{:?}: neighbor {:?} is still bootstrapping (on block {})", &self.local_peer, &self.cur_neighbor.addr, message.preamble.burn_block_height);
                    return Err(net_error::StaleNeighbor);
                }
                match message.payload {
                    StacksMessageType::Neighbors(ref data) => {
                        let (mut found, to_resolve) = NeighborWalk::lookup_stale_neighbors(network.peerdb.conn(), message.preamble.network_id, block_height, &data.neighbors)?;

                        for (naddr, neighbor) in found.drain() {
                            debug!("New neighbor {:?}", &neighbor.addr);
                            self.new_frontier.insert(neighbor.addr.clone(), neighbor.clone());
                            self.resolved_handshake_neighbors.insert(naddr, neighbor);
                        }

                        Ok(Some(to_resolve))
                    },
                    StacksMessageType::Nack(ref data) => {
                        debug!("Neighbor {:?} NACK'ed GetNeighbors with code {:?}", &self.cur_neighbor.addr, data.error_code);
                        self.result.add_broken(self.cur_neighbor.addr.clone());
                        Err(net_error::ConnectionBroken)
                    },
                    _ => {
                        // invalid message
                        debug!("Got out-of-sequence message from {:?}", &self.cur_neighbor.addr);
                        self.result.add_broken(self.cur_neighbor.addr.clone());
                        Err(net_error::InvalidMessage)
                    }
                }
            },
            Err(req_res) => {
                match req_res {
                    Ok(same_req) => {
                        // try again
                        self.getneighbors_request = Some(same_req);
                        Ok(None)
                    },
                    Err(e) => {
                        // disconnected 
                        debug!("Failed to get GetNeighbors reply from {:?}: {:?}", &self.cur_neighbor.addr, &e);
                        self.result.add_dead(self.cur_neighbor.addr.clone());
                        Err(e)
                    }
                }
            }
        }
    }

    /// Begin getting the neighors of cur_neighbor's neighbors.
    /// ReplyHandleP2Ps should be reply handles for Handshake requests.
    pub fn neighbor_handshakes_begin(&mut self, handshake_handles: HashMap<NeighborAddress, ReplyHandleP2P>) -> () {
        assert!(self.state == NeighborWalkState::GetHandshakesBegin);

        // advance state!
        self.unresolved_handshake_neighbors = handshake_handles;
        self.set_state(NeighborWalkState::GetHandshakesFinish);
    }

    /// Given a neighbor we tried to insert into the peer database, find one of the existing
    /// neighbors it collided with.  Return its slot in the peer db.
    fn find_replaced_neighbor_slot(conn: &DBConn, nk: &NeighborKey) -> Result<Option<u32>, net_error> {
        let mut slots = PeerDB::peer_slots(conn, nk.network_id, &nk.addrbytes, nk.port)
            .map_err(net_error::DBError)?;

        if slots.len() == 0 {
            // not present
            return Ok(None);
        }

        let mut rng = thread_rng();
        slots.shuffle(&mut rng);
        
        for slot in slots {
            let peer_opt = PeerDB::get_peer_at(conn, nk.network_id, slot)
                .map_err(net_error::DBError)?;

            match peer_opt {
                None => {
                    continue;
                }
                Some(_) => {
                    return Ok(Some(slot));
                }
            }
        }

        Ok(None)
    }

    /// Try to finish getting handshakes from cur_neighbors' neighbors.
    /// Once all handles resolve, return the list of neighbors that we can contact.
    /// As a side-effect of handshaking with all these peers, our PeerDB instance will be expanded
    /// with the addresses, public keys, public key expiries of these neighbors -- i.e. this method grows
    /// our frontier.
    pub fn neighbor_handshakes_try_finish(&mut self, network: &mut PeerNetwork, block_height: u64, stable_block_height: u64) -> Result<Option<Vec<NeighborKey>>, net_error> {
        assert!(self.state == NeighborWalkState::GetHandshakesFinish);

        // see if we got any replies 
        let mut new_unresolved_handshakes = HashMap::new();
        for (naddr, mut rh) in self.unresolved_handshake_neighbors.drain() {
            if let Err(_e) = network.saturate_p2p_socket(rh.get_event_id(), &mut rh) {
                self.result.add_dead(NeighborKey::from_neighbor_address(PEER_VERSION, self.local_peer.network_id, &naddr));
                continue;
            }

            let res = rh.try_send_recv();
            let rh_naddr = naddr.clone();       // used below
            let new_rh = match res {
                Ok(message) => {
                    // if the neighbor is still bootstrapping, we're doone
                    if message.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY < stable_block_height {
                        debug!("Remote neighbor {:?} is still bootstrapping (at block {})", &rh_naddr, message.preamble.burn_stable_block_height);
                    }
                    else {
                        match message.payload {
                            StacksMessageType::HandshakeAccept(ref data) => {
                                // success! do we know about this peer already?
                                let mut tx = network.peerdb.tx_begin()?;
                                let neighbor_from_handshake = Neighbor::from_handshake(&mut tx, message.preamble.peer_version, message.preamble.network_id, &data.handshake)?;
                                let neighbor_opt = Neighbor::from_neighbor_address(&mut tx, message.preamble.network_id, block_height, &naddr)?;
                                match neighbor_opt {
                                    Some(neighbor) => {
                                        debug!("{:?}: already know about {:?}", &self.local_peer, &neighbor.addr);

                                        // knew about this neighbor already
                                        self.resolved_handshake_neighbors.insert(naddr, neighbor.clone());
                                
                                        // remember the tip this peer saw
                                        self.result.add_chain_tip(neighbor.addr.clone(), message.preamble.burn_block_height, message.preamble.burn_consensus_hash.clone(), message.preamble.burn_stable_block_height, message.preamble.burn_stable_consensus_hash.clone());

                                        // update our frontier as well
                                        self.new_frontier.insert(neighbor.addr.clone(), neighbor);
                                        neighbor_from_handshake.save_update(&mut tx)?;
                                    },
                                    None => {
                                        debug!("{:?}: new neighbor {:?}", &self.local_peer, &neighbor_from_handshake.addr);

                                        // didn't know about this neighbor yet. Try to add it.
                                        let added = neighbor_from_handshake.save(&mut tx)?;
                                        if !added {
                                            // no more room in the db.  See if we can add it by
                                            // evicting an existing neighbor once we're done with this
                                            // walk.
                                            let replaced_neighbor_slot_opt = NeighborWalk::find_replaced_neighbor_slot(&mut tx, &neighbor_from_handshake.addr)?;

                                            match replaced_neighbor_slot_opt {
                                                Some(slot) => {
                                                    // if this peer isn't whitelisted, then consider
                                                    // replacing
                                                    if neighbor_from_handshake.whitelisted > 0 && (neighbor_from_handshake.whitelisted as u64) < get_epoch_time_secs() {
                                                        self.neighbor_replacements.insert(neighbor_from_handshake.addr.clone(), neighbor_from_handshake.clone());
                                                        self.replaced_neighbors.insert(neighbor_from_handshake.addr.clone(), slot);
                                                    }
                                                },
                                                None => {
                                                    // shouldn't happen 
                                                }
                                            };
                                        }
                                        self.new_frontier.insert(neighbor_from_handshake.addr.clone(), neighbor_from_handshake);
                                    }
                                };
                                tx.commit()?;
                            },
                            StacksMessageType::HandshakeReject => {
                                // remote peer doesn't want to talk to us 
                                debug!("Neighbor {:?} rejected our handshake", &naddr);
                                self.result.add_dead(NeighborKey::from_neighbor_address(message.preamble.peer_version, message.preamble.network_id, &naddr));
                            },
                            StacksMessageType::Nack(ref data) => {
                                // remote peer nope'd us
                                debug!("Neighbor {:?} NACK'ed our handshake with error code {:?}", &naddr, data.error_code);
                                self.result.add_dead(NeighborKey::from_neighbor_address(message.preamble.peer_version, message.preamble.network_id, &naddr));
                            }
                            _ => {
                                // protocol violation
                                debug!("Neighbor {:?} replied an out-of-sequence message", &naddr);
                                self.result.add_broken(NeighborKey::from_neighbor_address(message.preamble.peer_version, message.preamble.network_id, &naddr));
                            }
                        };
                    }
                    None
                },
                Err(req_res) => {
                    match req_res {
                        Ok(same_req) => {
                            // try again 
                            Some(same_req)
                        },
                        Err(e) => {
                            // connection broken.
                            // Don't try to contact this node again.
                            debug!("Failed to handshake with {:?}: {:?}", naddr, &e);
                            self.result.add_dead(NeighborKey::from_neighbor_address(PEER_VERSION, self.local_peer.network_id, &naddr));
                            None
                        }
                    }
                }
            };
            match new_rh {
                Some(rh) => {
                    new_unresolved_handshakes.insert(rh_naddr, rh);
                },
                None => {}
            };
        }

        // save unresolved handshakes for next time 
        for (naddr, rh) in new_unresolved_handshakes.drain() {
            self.unresolved_handshake_neighbors.insert(naddr, rh);
        }

        if self.unresolved_handshake_neighbors.len() == 0 {
            // finished handshaking!  find neighbors that accepted
            let mut neighbor_keys = vec![];
            
            // update our frontier knowledge
            for (nkey, new_neighbor) in self.new_frontier.drain() {
                debug!("{:?}: Add to frontier: {:?}", &self.local_peer, &nkey);
                self.frontier.insert(nkey.clone(), new_neighbor);

                if nkey.addrbytes != self.cur_neighbor.addr.addrbytes || nkey.port != self.cur_neighbor.addr.port {
                    neighbor_keys.push(nkey.clone());
                }
            }

            self.new_frontier.clear();

            // advance state!
            self.set_state(NeighborWalkState::GetNeighborsNeighborsBegin);
            Ok(Some(neighbor_keys))
        }
        else {
            // still handshaking 
            Ok(None)
        }
    }

    /// Begin asking remote neighbors for their neighbors in order to estimate cur_neighbor's
    /// in-degree. 
    pub fn getneighbors_neighbors_begin(&mut self, getneighbors_handles: HashMap<NeighborKey, ReplyHandleP2P>) -> () {
        assert!(self.state == NeighborWalkState::GetNeighborsNeighborsBegin);

        // advance state!
        self.unresolved_getneighbors_neighbors = getneighbors_handles;
        self.set_state(NeighborWalkState::GetNeighborsNeighborsFinish);
    }

    /// Try to finish getting the neighbors from cur_neighbors' neighbors 
    /// Once all handles resolve, return the list of new neighbors.
    pub fn getneighbors_neighbors_try_finish(&mut self, network: &mut PeerNetwork, burn_stable_block_height: u64) -> Result<Option<Neighbor>, net_error> {
        assert!(self.state == NeighborWalkState::GetNeighborsNeighborsFinish);

        // see if we got any replies 
        let mut new_unresolved_neighbors = HashMap::new();
        for (nkey, mut rh) in self.unresolved_getneighbors_neighbors.drain() {
            let rh_nkey = nkey.clone();     // used below
            if let Err(_e) = network.saturate_p2p_socket(rh.get_event_id(), &mut rh) {
                self.result.add_dead(rh_nkey);
                continue;
            }

            let res = rh.try_send_recv();
            let new_rh = match res {
                Ok(message) => {
                    // only consider this neighbor if it's _not_ bootstrapping
                    if message.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY >= burn_stable_block_height {
                        match message.payload {
                            StacksMessageType::Neighbors(ref data) => {
                                self.resolved_getneighbors_neighbors.insert(nkey, data.neighbors.clone());
                            },
                            StacksMessageType::Nack(ref data) => {
                                // not broken; likely because it hasn't gotten to processing our
                                // handshake yet.  We'll just ignore it.
                                debug!("Neighbor {:?} NACKed with code {:?}", &nkey, data.error_code);
                            },
                            _ => {
                                // unexpected reply
                                debug!("Neighbor {:?} replied an out-of-sequence message (type {}); assuming broken", &nkey, message.get_message_name());
                                self.result.add_broken(nkey);
                            }
                        }
                    }
                    None
                },
                Err(req_res) => {
                    match req_res {
                        Ok(nrh) => {
                            // try again 
                            Some(nrh)
                        }
                        Err(e) => {
                            // disconnected from peer 
                            debug!("Failed to get neighbors from {:?} ({})", &nkey, e);
                            self.result.add_dead(nkey);
                            None
                        }
                    }
                }
            };
            match new_rh {
                Some(rh) => {
                    new_unresolved_neighbors.insert(rh_nkey, rh);
                },
                None => {}
            };
        }

        // try these again 
        for (nkey, rh) in new_unresolved_neighbors.drain() {
            test_debug!("{:?}: still waiting for Neighbors reply from {:?}", &self.local_peer, &nkey);
            self.unresolved_getneighbors_neighbors.insert(nkey, rh);
        }

        if self.unresolved_getneighbors_neighbors.len() == 0 {
            // finished!  build up frontier's in-degree estimation, plus ourselves
            self.cur_neighbor.in_degree = 1;
            self.cur_neighbor.out_degree = self.frontier.len() as u32;

            for (_, neighbor_list) in self.resolved_getneighbors_neighbors.iter() {
                for na in neighbor_list {
                    if na.addrbytes == self.cur_neighbor.addr.addrbytes && na.port == self.cur_neighbor.addr.port {
                        self.cur_neighbor.in_degree += 1;
                    }
                }
            }

            // remember this peer's in/out degree estimates
            test_debug!("{:?}: In/Out degree of {:?} is {}/{}", &self.local_peer, &self.cur_neighbor.addr, self.cur_neighbor.in_degree, self.cur_neighbor.out_degree);
            let mut tx = network.peerdb.tx_begin()?;
            self.cur_neighbor.save_update(&mut tx)?;
            tx.commit()?;

            // advance state!
            self.set_state(NeighborWalkState::NeighborsPingBegin);
            Ok(Some(self.cur_neighbor.clone()))
        }
        else {
            // still working
            Ok(None)
        }
    }

    /// Pick a random neighbor from the frontier, excluding an optional given neighbor 
    fn pick_random_neighbor(frontier: &HashMap<NeighborKey, Neighbor>, exclude: Option<&Neighbor>) -> Option<Neighbor> {
        let mut rnd = thread_rng();

        let sample = rnd.gen_range(0, frontier.len());
        let mut count = 0;

        for (nk, n) in frontier.iter() {
            count += match exclude {
                None => 1,
                Some(ref e) => if (*e).addr == *nk { 0 } else { 1 }
            };
            if count >= sample {
                return Some(n.clone());
            }
        }
        return None;
    }
    
    /// Calculate the "degree ratio" between two neighbors, used to determine the probability of
    /// stepping to a neighbor in MHRWDA.  We estimate each neighbor's undirected degree, and then
    /// measure how represented each neighbor's AS is in the peer graph.  We *bias* the sample so
    /// that peers in under-represented ASs are more likely to be walked to than they otherwise
    /// would be if considering only neighbor degrees.
    fn degree_ratio(peerdb_conn: &DBConn, n1: &Neighbor, n2: &Neighbor) -> f64 {
        let d1 = n1.degree() as f64;
        let d2 = n2.degree() as f64;
        let as_d1 = PeerDB::asn_count(peerdb_conn, n1.asn).unwrap_or(1) as f64;
        let as_d2 = PeerDB::asn_count(peerdb_conn, n2.asn).unwrap_or(1) as f64;
        (d1 * as_d2) / (d2 * as_d1)
    }

    /// Do the MHRWDA step -- try to step from our cur_neighbor to an immediate neighbor, if there
    /// is any neighbor to step to.  Return the new cur_neighbor, if we were able to step.
    /// The caller should call reset() after this, optionally with a newly-selected frontier
    /// neighbor if we were unable to take a step.
    ///
    /// This is a slightly modified MHRWDA algorithm.  The following differences are described:
    /// * The Stacks peer network is a _directed_ graph, whereas MHRWDA is desigend to operate
    /// on _undirected_ graphs.  As such, we calculate a separate peer graph with undirected edges
    /// with the same peers.  We estimate a peer's undirected degree with Neighbor::degree().
    /// * The probability of transitioning to a new peer is proportional not only to the ratio of
    /// the current peer's degree to the new peer's degree, but also to the ratio of the new
    /// peer's AS's node count to the current peer's AS's node count.
    pub fn step(&mut self, peerdb_conn: &DBConn) -> Option<Neighbor> {
        let mut rnd = thread_rng();

        // step to a node in cur_neighbor's frontier, per MHRWDA
        let next_neighbor_opt = 
            if self.frontier.len() == 0 {
                // just started the walk, so stay here for now -- we don't yet know the neighbor's
                // frontier.
                Some(self.cur_neighbor.clone())
            }
            else {
                let next_neighbor = NeighborWalk::pick_random_neighbor(&self.frontier, None).unwrap();     // won't panic since self.frontier.len() > 0
                let walk_prob : f64 = rnd.gen();
                if walk_prob < fmin!(1.0, NeighborWalk::degree_ratio(peerdb_conn, &self.cur_neighbor, &next_neighbor)) {
                    match self.prev_neighbor {
                        Some(ref prev_neighbor) => {
                            // will take a step
                            if prev_neighbor.addr == next_neighbor.addr {
                                // oops, backtracked.  Try to pick a different neighbor, if possible.
                                if self.frontier.len() == 1 {
                                    // no other choices. will need to reset this walk.
                                    None
                                }
                                else {
                                    // have alternative choices, so instead of backtracking, we'll delay
                                    // acceptance by probabilistically deciding to step to an alternative
                                    // instead of backtracking.
                                    let alt_next_neighbor = NeighborWalk::pick_random_neighbor(&self.frontier, Some(&prev_neighbor)).unwrap();
                                    let alt_prob : f64 = rnd.gen();

                                    let cur_to_alt = NeighborWalk::degree_ratio(peerdb_conn, &self.cur_neighbor, &alt_next_neighbor);
                                    let prev_to_cur = NeighborWalk::degree_ratio(peerdb_conn, &prev_neighbor, &self.cur_neighbor);
                                    let trans_prob = fmin!(
                                                        fmin!(1.0, cur_to_alt * cur_to_alt),
                                                        fmax!(1.0, prev_to_cur * prev_to_cur)
                                                     );

                                    if alt_prob < fmin!(1.0, trans_prob) {
                                        // go to alt peer instead
                                        Some(alt_next_neighbor)
                                    }
                                    else {
                                        // backtrack.
                                        Some(next_neighbor)
                                    }
                                }
                            }
                            else {
                                // not backtracking.  Take a step.
                                Some(next_neighbor)
                            }
                        },
                        None => {
                            // not backtracking.  Take a step.
                            Some(next_neighbor)
                        }
                    }
                }
                else {
                    // will not take a step
                    Some(self.cur_neighbor.clone())
                }
            };

        self.next_neighbor = next_neighbor_opt.clone();
        next_neighbor_opt
    }

    // proceed to ping _existing_ neighbors that would be replaced by the discovery of a new
    // neighbor
    pub fn ping_existing_neighbors_begin(&mut self, network_handles: HashMap<NeighborKey, ReplyHandleP2P>) -> () {
        assert!(self.state == NeighborWalkState::NeighborsPingBegin);

        self.unresolved_neighbor_pings = network_handles;
        
        // advance state!
        self.set_state(NeighborWalkState::NeighborsPingFinish);
    }

    // try to finish pinging/handshaking all exisitng neighbors.
    // if the remote neighbor does _not_ respond to our ping, then replace it.
    // Return the list of _evicted_ neighbors.
    pub fn ping_existing_neighbors_try_finish(&mut self, network: &mut PeerNetwork) -> Result<Option<HashSet<NeighborKey>>, net_error> {
        assert!(self.state == NeighborWalkState::NeighborsPingFinish);

        let mut new_unresolved_neighbor_pings = HashMap::new();
        
        for (nkey, mut rh) in self.unresolved_neighbor_pings.drain() {
            let rh_nkey = nkey.clone();     // used below
            if let Err(_e) = network.saturate_p2p_socket(rh.get_event_id(), &mut rh) {
                self.result.add_dead(rh_nkey);
                continue;
            }
            let res = rh.try_send_recv();
            let new_rh = match res {
                Ok(message) => {
                    match message.payload {
                        StacksMessageType::HandshakeAccept(ref data) => {
                            // this peer is still alive -- will not replace it 
                            // save knowledge to the peer DB (NOTE: the neighbor should already be in
                            // the DB, since it's cur_neighbor)
                            test_debug!("{:?}: received HandshakeAccept from {:?}", &self.local_peer, &message.to_neighbor_key(&data.handshake.addrbytes, data.handshake.port));

                            let mut tx = network.peerdb.tx_begin()?;
                            let neighbor_from_handshake = Neighbor::from_handshake(&mut tx, message.preamble.peer_version, message.preamble.network_id, &data.handshake)?;
                            neighbor_from_handshake.save_update(&mut tx)?;
                            tx.commit()?;

                            // not going to replace
                            if self.replaced_neighbors.contains_key(&neighbor_from_handshake.addr) {
                                test_debug!("{:?}: will NOT replace {:?}", &self.local_peer, &neighbor_from_handshake.addr);
                                self.replaced_neighbors.remove(&neighbor_from_handshake.addr);
                            }
                            
                            // remember the tip this neighbor saw 
                            self.result.add_chain_tip(nkey.clone(), message.preamble.burn_block_height, message.preamble.burn_consensus_hash.clone(), message.preamble.burn_stable_block_height, message.preamble.burn_stable_consensus_hash.clone());
                        },
                        StacksMessageType::Nack(ref data) => {
                            // evict
                            debug!("Neighbor {:?} NACK'ed Handshake with code {:?}; will evict", nkey, data.error_code);
                            self.result.add_broken(nkey.clone());
                        },
                        _ => {
                            // unexpected reply -- this peer is misbehaving and should be replaced
                            debug!("Neighbor {:?} replied an out-of-sequence message (type {}); will replace", &nkey, message.get_message_name());
                            self.result.add_broken(nkey);
                        }
                    };
                    None
                },
                Err(req_res) => {
                    match req_res {
                        Ok(nrh) => {
                            // try again 
                            Some(nrh)
                        }
                        Err(_) => {
                            // disconnected from peer already -- we can replace it
                            debug!("Neighbor {:?} could not be pinged; will replace", &nkey);
                            self.result.add_dead(nkey);
                            None
                        }
                    }
                }
            };
            match new_rh {
                Some(rh) => {
                    // try again next time
                    new_unresolved_neighbor_pings.insert(rh_nkey, rh);
                },
                None => {}
            };
        }

        if new_unresolved_neighbor_pings.len() == 0 {
            // done getting pings.  do our replacements
            let mut tx = network.peerdb.tx_begin()?;
            for (replaceable_key, slot) in self.replaced_neighbors.iter() {
                let replacement = match self.neighbor_replacements.get(replaceable_key) {
                    Some(n) => n.clone(),
                    None => {
                        continue;
                    }
                };

                let replaced_opt = PeerDB::get_peer_at(&mut tx, self.local_peer.network_id, *slot)?;
                match replaced_opt {
                    Some(replaced) => {
                        debug!("Replace {:?} with {:?}", &replaced.addr, &replacement.addr);

                        PeerDB::insert_or_replace_peer(&mut tx, &replacement, *slot)?;
                        self.result.add_replaced(replaced.addr.clone());
                    },
                    None => {}
                }
            }
            tx.commit()?;

            // advance state!
            self.set_state(NeighborWalkState::Finished);
            Ok(Some(self.result.replaced_neighbors.clone()))
        }
        else {
            // still have more work to do
            self.unresolved_neighbor_pings = new_unresolved_neighbor_pings;
            Ok(None)
        }
    }
}

impl PeerNetwork {
    /// Get some initial fresh random neighbor(s) to crawl
    pub fn get_random_neighbors(&self, num_neighbors: u64, block_height: u64) -> Result<Vec<Neighbor>, net_error> {
        let neighbors = PeerDB::get_random_walk_neighbors(&self.peerdb.conn(), self.local_peer.network_id, num_neighbors as u32, block_height)
            .map_err(net_error::DBError)?;

        if neighbors.len() == 0 {
            debug!("{:?}: No neighbors available!  Will not begin neighbor walk", &self.local_peer);
            return Err(net_error::NoSuchNeighbor);
        }
        Ok(neighbors)
    }

    /// Connect to a remote peer and begin to handshake with it.
    fn connect_and_handshake(&mut self, walk: &mut NeighborWalk, nk: &NeighborKey) -> Result<Option<ReplyHandleP2P>, net_error> {
        if !self.is_registered(nk) {
            if !walk.connecting.contains_key(nk) {
                let con_res = self.connect_peer(nk);
                match con_res {
                    Ok(event_id) => {
                        // remember this in the walk result
                        walk.result.add_new(nk.clone());
                        walk.connecting.insert(nk.clone(), event_id);

                        // stop the pruner from removing this connection
                        walk.events.insert(event_id);
                        
                        // force the caller to try again -- we're not registered yet
                        debug!("{:?}: Walk is connecting to {:?} (event {})", &self.local_peer, &nk, event_id);
                        return Ok(None);
                    },
                    Err(_e) => {
                        debug!("{:?}: Failed to connect to {:?}: {:?}", &self.local_peer, nk, &_e);
                        return Err(net_error::PeerNotConnected);
                    }
                }
            }
            else {
                let event_id = walk.connecting.get(nk).unwrap();
                
                // is the peer network still working?
                if !self.is_connecting(*event_id) {
                    debug!("{:?}: Failed to connect to {:?} (no longer connecting; assumed timed out)", &self.local_peer, nk);
                    walk.connecting.remove(&nk);
                    return Err(net_error::PeerNotConnected);
                }

                // still connecting
                debug!("{:?}: walk still connecting to {:?} (event {})", &self.local_peer, nk, event_id);
                return Ok(None);
            }
        }
        else {
            test_debug!("{:?}: already connected to {:?} as event {}", &self.local_peer, &nk, self.get_event_id(nk).unwrap());
        }
        
        // so far so good.
        // send handshake.
        let handshake_data = HandshakeData::from_local_peer(&self.local_peer);
        
        debug!("{:?}: send Handshake to {:?}", &self.local_peer, &nk);

        let msg = self.sign_for_peer(nk, StacksMessageType::Handshake(handshake_data))?;
        let req_res = self.send_message(nk, msg, self.connection_opts.timeout);
        match req_res {
            Ok(handle) => {
                Ok(Some(handle))
            },
            Err(e) => {
                debug!("Not connected: {:?} ({:?})", nk, &e);
                walk.result.add_dead(nk.clone());
                Err(net_error::PeerNotConnected)
            }
        }
    }

    /// Instantiate the neighbor walk 
    fn instantiate_walk(&mut self) -> Result<(), net_error> {
        // pick a random neighbor as a walking point 
        let next_neighbors = self.get_random_neighbors(1, self.chain_view.burn_block_height)
            .map_err(|e| {
                debug!("Failed to load initial walk neighbors: {:?}", &e);
                e
            })?;

        let mut w = NeighborWalk::new(self.local_peer.clone(), self.chain_view.clone(), &next_neighbors[0]);
        w.walk_start_time = get_epoch_time_secs();

        self.walk = Some(w);
        Ok(())
    }

    pub fn with_walk_state<F, R>(network: &mut PeerNetwork, handler: F) -> Result<R, net_error>
    where
        F: FnOnce(&mut PeerNetwork, &mut NeighborWalk) -> Result<R, net_error>
    {
        let mut walk = network.walk.take();
        let res = match walk {
            None => {
                test_debug!("{:?}: not connected", &network.local_peer);
                Err(net_error::NotConnected)
            },
            Some(ref mut walk) => handler(network, walk)
        };
        network.walk = walk;
        res
    }

    /// Begin walking the peer graph by reaching out to a neighbor and handshaking with it.
    /// Return true/false to indicate if we connected or not.
    /// Return an error to reset the walk.
    pub fn walk_handshake_begin(&mut self) -> Result<bool, net_error> {
        if self.walk.is_none() {
            self.instantiate_walk()?;
        }
       
        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            match walk.handshake_request {
                Some(_) => {
                    // in progress already
                    Ok(true)
                },
                None => {
                    // if cur_neighbor is _us_, then grab a different neighbor and try again
                    if walk.cur_neighbor.public_key == Secp256k1PublicKey::from_private(&network.local_peer.private_key) {
                        debug!("Walk stepped to ourselves.  Will reset instead.");
                        return Err(net_error::NoSuchNeighbor);
                    }

                    let my_addr = walk.cur_neighbor.addr.clone();
                    walk.clear_state();

                    let handle_opt = network.connect_and_handshake(walk, &my_addr)?;
                    if handle_opt.is_some() {
                        walk.handshake_begin(handle_opt);
                        debug!("Handshake sent to {:?}", &my_addr);
                        Ok(true)
                    }
                    else {
                        debug!("No Handshake sent (dest was {:?})", &my_addr);
                        Ok(false)
                    }
                }
            }
        })
    }

    /// Try to finish handshaking with our current neighbor
    pub fn walk_handshake_try_finish(&mut self) -> Result<Option<Neighbor>, net_error> {
        let burn_stable_block_height = self.chain_view.burn_stable_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            walk.handshake_try_finish(network, burn_stable_block_height)
        })
    }

    /// Begin walking the peer graph by reaching out to a neighbor, connecting to _it's_ neighbors,
    /// asking for their neighbor-sets (in order to get the neighbor's in/out-degree estimates),
    /// and then stepping to one of the neighbor's neighbors.
    /// Return an error to reset the walk.
    pub fn walk_getneighbors_begin(&mut self) -> Result<(), net_error> {
        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            match walk.getneighbors_request {
                Some(_) => {
                    Ok(())
                },
                None => {
                    test_debug!("{:?}: send GetNeighbors to {:?}", &walk.local_peer, &walk.cur_neighbor);

                    let msg = network.sign_for_peer(&walk.cur_neighbor.addr, StacksMessageType::GetNeighbors)?;
                    let req_res = network.send_message(&walk.cur_neighbor.addr, msg, get_epoch_time_secs() + network.connection_opts.timeout);
                    match req_res {
                        Ok(handle) => {
                            walk.getneighbors_begin(Some(handle));
                            Ok(())
                        },
                        Err(e) => {
                            debug!("Not connected: {:?} ({:?}", &walk.cur_neighbor.addr, &e);
                            Err(e)
                        }
                    }
                }
            }
        })
    }

    /// Make progress completing the pending getneighbor request, and if it completes,
    /// proceed to handshake with all its neighbors that we don't know about.
    /// Return an error to reset the walk.
    pub fn walk_getneighbors_try_finish(&mut self) -> Result<bool, net_error> {
        let burn_block_height = self.chain_view.burn_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let my_pubkey_hash = Hash160::from_data(&Secp256k1PublicKey::from_private(&walk.local_peer.private_key).to_bytes()[..]);
            let cur_neighbor_pubkey_hash = Hash160::from_data(&walk.cur_neighbor.public_key.to_bytes_compressed()[..]);

            if walk.pending_neighbor_addrs.is_none() {
                // keep trying to finish getting neighbor addresses.  Stop trying once we get something.
                let neighbor_addrs_opt = walk.getneighbors_try_finish(network, burn_block_height)?;
                walk.pending_neighbor_addrs = neighbor_addrs_opt;

                if walk.pending_neighbor_addrs.is_some() {
                    // proceed to connect-and-handshake
                    walk.connecting.clear();
                    walk.pending_handshakes.clear();
                }
            }

            let pending_neighbor_addrs = walk.pending_neighbor_addrs.take();
            let res = match pending_neighbor_addrs {
                None => {
                    // nothing to do -- not done yet
                    Ok(false)
                },
                Some(ref neighbor_addrs) => {
                    // got neighbors -- proceed to ask each one for *its* neighbors so we can
                    // estimate cur_neighbor's in-degree and grow our frontier.
                    let mut pending = false;
                    for na in neighbor_addrs {
                        // don't talk to myself if we're listed as a neighbor of this
                        // remote peer.
                        if na.public_key_hash == my_pubkey_hash {
                            continue;
                        }

                        // don't handshake with cur_neighbor, if for some reason it gets listed
                        // in the neighbors reply
                        if na.public_key_hash == cur_neighbor_pubkey_hash {
                            continue;
                        }
                        
                        let nk = NeighborKey::from_neighbor_address(network.peer_version, network.local_peer.network_id, &na);
                        
                        // already trying to connect to this neighbor?
                        if walk.connecting.contains_key(&nk) {
                            continue;
                        }

                        // already sent a handshake to this neighbor?
                        if walk.pending_handshakes.contains_key(na) {
                            continue;
                        }

                        match network.connect_and_handshake(walk, &nk) {
                            Ok(Some(handle)) => {
                                walk.pending_handshakes.insert(na.clone(), handle);
                            }
                            Ok(None) => {
                                pending = true;

                                // try again
                                continue;
                            }
                            Err(e) => {
                                info!("Failed to connect to {:?}: {:?}", &nk, &e);
                                continue;
                            }
                        }
                    }

                    if !pending {
                        // everybody connected
                        let pending_handshakes = mem::replace(&mut walk.pending_handshakes, HashMap::new());
                        walk.connecting.clear();
                        
                        walk.set_state(NeighborWalkState::GetHandshakesBegin);
                        walk.neighbor_handshakes_begin(pending_handshakes);
                        Ok(true)
                    }
                    else {
                        Ok(false)
                    }
                }
            };

            walk.pending_neighbor_addrs = pending_neighbor_addrs;
            res
        })
    }

    /// Make progress on completing handshakes with all our neighbors.  If we finish, proceed to
    /// ask them for their neighbors in order to estimate cur_neighbor's in/out degrees.
    /// Return an error to reset the walk.
    pub fn walk_neighbor_handshakes_try_finish(&mut self) -> Result<(), net_error> {
        let burn_block_height = self.chain_view.burn_block_height;
        let burn_stable_block_height = self.chain_view.burn_stable_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let neighbor_keys_opt = walk.neighbor_handshakes_try_finish(network, burn_block_height, burn_stable_block_height)?;
            match neighbor_keys_opt {
                None => {
                    // nothing to do -- still working 
                    Ok(())
                },
                Some(neighbor_keys) => {
                    // finished handshaking.  Proceed to estimate cur_neighbor's in-degree
                    let mut pending_getneighbors = HashMap::new();
                    let now = get_epoch_time_secs();

                    for nk in neighbor_keys {
                        if !network.is_registered(&nk) {
                            // not connected to this neighbor -- can't ask for neighbors 
                            warn!("Not connected to {:?}", &nk);
                            continue;
                        }

                        test_debug!("{:?}: send GetNeighbors to {:?}", &walk.local_peer, &nk);

                        let msg = network.sign_for_peer(&nk, StacksMessageType::GetNeighbors)?;
                        let rh_res = network.send_message(&nk, msg, now + network.connection_opts.timeout);
                        match rh_res {
                            Ok(rh) => {
                                pending_getneighbors.insert(nk, rh);
                            }
                            Err(e) => {
                                // failed to begin getneighbors 
                                debug!("Not connected to {:?}: {:?}", &nk, &e);
                                continue;
                            }
                        }
                    }

                    walk.getneighbors_neighbors_begin(pending_getneighbors);
                    Ok(())
                }
            }
        })
    }

    /// Make progress on completing getneighbors requests to all of cur_neighbor's neighbors.  If
    /// we finish, proceed to update our knowledge of these neighbors and take a step in the peer
    /// graph.
    pub fn walk_getneighbors_neighbors_try_finish(&mut self) -> Result<Option<Neighbor>, net_error> {
        let burn_stable_block_height = self.chain_view.burn_stable_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let neighbor_opt = walk.getneighbors_neighbors_try_finish(network, burn_stable_block_height)?;
            match neighbor_opt {
                None => {
                    // not done yet 
                    Ok(None)
                },
                Some(_neighbor) => {
                    // finished calculating this neighbor's in/out degree.
                    // walk to the next neighbor.
                    let next_neighbor_opt = walk.step(network.peerdb.conn());
                    let mut ping_handles = HashMap::new();

                    // proceed to ping/handshake neighbors we need to replace
                    for (nk, _) in walk.replaced_neighbors.iter() {
                        test_debug!("{:?}: send Handshake to replaceable neighbor {:?}", &walk.local_peer, nk);

                        let handshake_data = HandshakeData::from_local_peer(&walk.local_peer);
                        let msg = network.sign_for_peer(nk, StacksMessageType::Handshake(handshake_data))?;
                        let req_res = network.send_message(nk, msg, get_epoch_time_secs() + network.connection_opts.timeout);
                        match req_res {
                            Ok(handle) => {
                                ping_handles.insert((*nk).clone(), handle);
                            }
                            Err(e) => {
                                debug!("Not connected to {:?}: ({:?}", nk, &e);
                            }
                        };
                    }

                    walk.ping_existing_neighbors_begin(ping_handles);
                    Ok(next_neighbor_opt)
                }
            }
        })
    }

    /// Make progress on completing pings to existing neighbors we'd like to replace.  If we
    /// finish, proceed to update our peer database.
    /// Return the result of the peer walk, and reset the walk state.
    pub fn walk_ping_existing_neighbors_try_finish(&mut self) -> Result<Option<NeighborWalkResult>, net_error> {
        let burn_block_height = self.chain_view.burn_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let replaced_opt = walk.ping_existing_neighbors_try_finish(network)?;
            match replaced_opt {
                None => {
                    // still working
                    Ok(None)
                },
                Some(_) => {
                    // finished!
                    // extract the walk result
                    let neighbor_walk_result = {
                        let mut next_neighbor_opt = walk.next_neighbor.take();
                        match next_neighbor_opt {
                            Some(ref mut next_neighbor) => {
                                test_debug!("Stepped to {:?}", &next_neighbor.addr);
                                walk.reset(&next_neighbor.clone())
                            }
                            None => {
                                // need to select a random new neighbor 
                                let next_neighbors = network.get_random_neighbors(1, burn_block_height)?;
                                test_debug!("Did not step to any neighbor; resetting walk to {:?}", &next_neighbors[0].addr);
                                walk.reset(&next_neighbors[0])
                            }
                        }
                    };

                    Ok(Some(neighbor_walk_result))
                }
            }
        })
    }

    /// Get the walk state
    fn get_walk_state(&self) -> NeighborWalkState {
        match self.walk {
            None => {
                NeighborWalkState::HandshakeBegin
            },
            Some(ref walk) => {
                walk.state
            }
        }
    }

    /// Update the state of our peer graph walk.
    /// If we complete a walk, give back a walk result.
    /// Mask errors by restarting the graph walk.
    /// Returns the walk result, and a true/false flag to indicate whether or not the work for the
    /// walk was finished (i.e. we either completed the walk, or we reset the walk)
    pub fn walk_peer_graph(&mut self) -> (bool, Option<NeighborWalkResult>) {
        if self.walk.is_none() {
            // time to do a walk yet?
            if self.walk_count > NUM_INITIAL_WALKS && self.walk_deadline > get_epoch_time_secs() {
                // we've done enough walks for an initial mixing,
                // so throttle ourselves down until the walk deadline passes.
                debug!("{:?}: Throttle walk until {} to walk again", &self.local_peer, self.walk_deadline);
                return (true, None);
            }
        }

        // take as many steps as we can
        let mut walk_state = self.get_walk_state();

        let mut did_cycle = false;
        let res = loop {
            let last_walk_state = walk_state;

            debug!("{:?}: walk state is {:?}", &self.local_peer, walk_state);
            let res = match walk_state {
                NeighborWalkState::HandshakeBegin => {
                    self.walk_handshake_begin()
                        .and_then(|_| Ok(None))
                },
                NeighborWalkState::HandshakeFinish => {
                    self.walk_handshake_try_finish()
                        .and_then(|_| Ok(None))
                },
                NeighborWalkState::GetNeighborsBegin => {
                    self.walk_getneighbors_begin()
                        .and_then(|_| Ok(None))
                },
                NeighborWalkState::GetNeighborsFinish => {
                    self.walk_getneighbors_try_finish()
                        .and_then(|_| Ok(None))
                },
                NeighborWalkState::GetHandshakesFinish => {
                    self.walk_neighbor_handshakes_try_finish()
                        .and_then(|_| Ok(None))
                },
                NeighborWalkState::GetNeighborsNeighborsFinish => {
                    self.walk_getneighbors_neighbors_try_finish()
                        .and_then(|_| Ok(None))
                },
                NeighborWalkState::NeighborsPingFinish => {
                    did_cycle = true;
                    test_debug!("{:?}: finish walk {}", &self.local_peer, self.walk_count);
                    self.walk_ping_existing_neighbors_try_finish()
                }
                _ => {
                    panic!("Reached invalid walk state {:?}", walk_state);
                }
            };

            if did_cycle || res.is_err() {
                break res;
            }

            walk_state = self.get_walk_state();
            if walk_state == last_walk_state {
                break res;
            }
        };

        match res {
            Ok(mut walk_opt) => {
                // did something
                self.walk_total_step_count += 1;

                let mut done = false;

                match walk_opt {
                    Some(ref mut walk_result) => {
                        // finished a walk completely
                        done = true;
                        self.walk_count += 1;
                        self.walk_deadline = self.connection_opts.walk_interval + get_epoch_time_secs();

                        if self.walk_count > NUM_INITIAL_WALKS && self.prune_deadline < get_epoch_time_secs() {
                            // clean up 
                            walk_result.do_prune = true;
                            self.prune_deadline = get_epoch_time_secs() + PRUNE_FREQUENCY;
                        }
                    },
                    None => {}
                }

                // Randomly restart it if we have done enough walks
                let reset = match self.walk {
                    Some(ref mut walk) => {
                        // finished a walk step.
                        walk.walk_step_count += 1;
                        debug!("{:?}: walk has taken {} steps (total of {} walks)", &self.local_peer, walk.walk_step_count, self.walk_count);

                        if walk_opt.is_some() && self.walk_count > NUM_INITIAL_WALKS && walk.walk_step_count >= walk.walk_min_duration {
                            // consider re-setting the walk state, now that we completed a walk
                            let mut rng = thread_rng();
                            let sample : f64 = rng.gen();
                            if walk.walk_step_count >= walk.walk_max_duration || sample < walk.walk_reset_prob {
                                true
                            }
                            else {
                                false
                            }
                        }
                        else {
                            false
                        }
                    },
                    None => false
                };

                if reset {
                    debug!("{:?}: random walk restart", &self.local_peer);
                    self.walk = None;
                    done = true;        // move onto the next p2p work item
                }

                #[cfg(test)]
                {
                    if done {
                        let (mut inbound, mut outbound) = self.dump_peer_table();

                        inbound.sort();
                        outbound.sort();

                        debug!("Walk finished ===================");
                        debug!("{:?}: Peers outbound ({}): {}", &self.local_peer, outbound.len(), outbound.join(", "));
                        debug!("{:?}: Peers inbound ({}):  {}", &self.local_peer, inbound.len(), inbound.join(", "));
                        debug!("Walk finished ===================");

                        match PeerDB::get_frontier_size(self.peerdb.conn()) {
                            Ok(count) => {
                                debug!("{:?}: Frontier size: {}", &self.local_peer, count);
                            },
                            Err(_) => {}
                        };
                    }
                }
                
                (done, walk_opt)
            },
            Err(_e) => {
                test_debug!("{:?}: Restarting neighbor with new random neighbors: {:?} => {:?}", &self.local_peer, walk_state, &_e);
                self.walk = None;
                (true, None)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use net::asn::*;
    use net::chat::*;
    use net::db::*;
    use net::test::*;
    use util::hash::*;
    use util::sleep_ms;

    const TEST_IN_OUT_DEGREES : u64 = 0x1;

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_plain() {
        let mut peer_1_config = TestPeerConfig::from_port(31990);
        let peer_2_config = TestPeerConfig::from_port(31992);

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(peer_1_dbconn, neighbor_2.addr.network_id, &neighbor_2.addr.addrbytes, neighbor_2.addr.port).unwrap() {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            },
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }
    }
    
    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_heartbeat_ping() {
        let mut peer_1_config = TestPeerConfig::from_port(31992);
        let mut peer_2_config = TestPeerConfig::from_port(31994);

        peer_1_config.connection_opts.heartbeat = 10;
        peer_2_config.connection_opts.heartbeat = 10;

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        info!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(peer_1_dbconn, neighbor_2.addr.network_id, &neighbor_2.addr.addrbytes, neighbor_2.addr.port).unwrap() {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            },
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        assert_eq!(peer_1.network.relay_handles.len(), 0);
        assert_eq!(peer_2.network.relay_handles.len(), 0);

        info!("Wait {} seconds for ping timeout", peer_1.config.connection_opts.timeout);
        sleep_ms(1000 * peer_1.config.connection_opts.timeout);

        peer_1.network.queue_ping_heartbeats();
        peer_2.network.queue_ping_heartbeats();

        // pings queued
        assert_eq!(peer_1.network.relay_handles.len(), 1);
        assert_eq!(peer_2.network.relay_handles.len(), 0);
    }
    
    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_bootstrapping() {
        let mut peer_1_config = TestPeerConfig::from_port(32100);
        let peer_2_config = TestPeerConfig::from_port(32102);

        // peer 1 crawls peer 2, but peer 1 doesn't add peer 2 to its frontier becuase peer 2 is
        // too far behind.
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // advance peer 1
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY+1 {
            peer_1.add_empty_burnchain_block();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        
        let neighbor_2 = peer_2.to_neighbor();
        
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();
            
            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                   
                    // peer 2 never gets added to peer 1's frontier
                    assert!(w.frontier.get(&neighbor_2.addr).is_none());
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    }
   
    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_behind() {
        let mut peer_1_config = TestPeerConfig::from_port(32200);
        let peer_2_config = TestPeerConfig::from_port(32202);

        // peer 1 crawls peer 2, and peer 1 adds peer 2 to its frontier even though peer 2 does
        // not, because peer 2 is too far ahead
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // advance peer 2
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY+1 {
            peer_2.add_empty_burnchain_block();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();
        
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();
            
            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                    
                    // peer 1 never gets added to peer 2's frontier
                    assert!(w.frontier.get(&neighbor_1.addr).is_none());
                }
                None => {}
            };

            i += 1;
        }
        
        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 was added to the peer DB of peer 1, even though peer 1 is very behind peer 2
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(peer_1_dbconn, neighbor_2.addr.network_id, &neighbor_2.addr.addrbytes, neighbor_2.addr.port).unwrap() {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            },
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }
    }

    #[test]
    #[ignore]
    fn test_step_walk_10_neighbors_of_neighbor_plain() {
        // peer 1 has peer 2 as its neighbor.
        // peer 2 has 10 other neighbors.
        // Goal: peer 1 learns about the 10 other neighbors.
        let mut peer_1_config = TestPeerConfig::from_port(32300);
        let mut peer_2_config = TestPeerConfig::from_port(32302);

        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let mut peer_2_neighbors = vec![];
        for i in 0..10 {
            let mut n = TestPeerConfig::from_port(2*i + 4 + 32300);
            
            // turn off features we don't use
            n.connection_opts.disable_inv_sync = true;
            n.connection_opts.disable_block_download = true;
            
            peer_2_config.add_neighbor(&n.to_neighbor());

            let p = TestPeer::new(n);
            peer_2_neighbors.push(p);
        }

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);
        
        // next, make peer 1 discover peer 2's neighbors and peer 2's in/out degree.
        // Do two full walks
        let mut i = 0;
        let mut did_connect = false;
        while !did_connect {
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            while walk_1_count < 20 && walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                for j in 0..10 {
                    let _ = peer_2_neighbors[j].step();
                }
                
                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);
                
                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.dead_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.dead_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;
            }

            // peer 1 must have handshaked with all of peer 2's neighbors if this test will pass
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            let mut num_handshakes = 0;
            for peer in &peer_2_neighbors {
                let n = peer.to_neighbor();
                let p_opt = PeerDB::get_peer(peer_1_dbconn, n.addr.network_id, &n.addr.addrbytes, n.addr.port).unwrap();
                match p_opt {
                    None => {
                        test_debug!("no such peer: {:?}", &n.addr);
                    },
                    Some(p) => {
                        assert_eq!(p.public_key, n.public_key);
                        assert_eq!(p.expire_block, n.expire_block);
                        num_handshakes += 1;
                    }
                }
            }

            if num_handshakes < 10 {
                continue;
            }
            
            // peer 1 learned that peer 2 has an out-degree of 10 (10 neighbors) and an in-degree of 1 if this test will pass
            let n2 = peer_2.to_neighbor();
            let p2_opt = PeerDB::get_peer(peer_1_dbconn, n2.addr.network_id, &n2.addr.addrbytes, n2.addr.port).unwrap();
            match p2_opt {
                None => {
                    test_debug!("no peer 2");
                },
                Some(p2) => {
                    if p2.out_degree >= 11 && p2.in_degree >= 1 {
                        assert_eq!(p2.out_degree, 11);
                        did_connect = true;
                    }
                }
            }
        }
        
        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    }
    
    #[test]
    #[ignore]
    fn test_step_walk_10_neighbors_of_neighbor_bootstrapping() {
        // peer 1 has peer 2 as its neighbor.
        // peer 2 has 10 other neighbors, 5 of which are too far behind peer 1.
        // Goal: peer 1 learns about the 5 fresher neighbors.
        let mut peer_1_config = TestPeerConfig::from_port(32400);
        let mut peer_2_config = TestPeerConfig::from_port(32402);
        
        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let mut peer_2_neighbors = vec![];
        for i in 0..10 {
            let mut n = TestPeerConfig::from_port(2*i + 4 + 32400);
            
            // turn off features we don't use
            n.connection_opts.disable_inv_sync = true;
            n.connection_opts.disable_block_download = true;
            
            peer_2_config.add_neighbor(&n.to_neighbor());

            let p = TestPeer::new(n);
            peer_2_neighbors.push(p);
        }

        // peer 1 crawls peer 2
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // advance peer 1 and peer 2, and some of peer 2's neighbors
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY+1 {
            peer_1.add_empty_burnchain_block();
            peer_2.add_empty_burnchain_block();
            for j in 0..5 {
                peer_2_neighbors[j].add_empty_burnchain_block();
            }
        }
        
        // next, make peer 1 discover peer 2's neighbors and peer 2's in/out degree.
        // Do two full walks
        let mut i = 0;
        let mut did_handshakes = false;
        while !did_handshakes {
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            while walk_1_count < 20 && walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();
                
                for j in 0..10 {
                    let _ = peer_2_neighbors[j].step();
                }
                
                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.dead_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.dead_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };
                
                i += 1;
            }
        
            peer_1.dump_frontier();
            peer_2.dump_frontier();

            // check if peer 1 handshaked with all of peer 2's _fresh_ neighbors
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            let mut num_contacted = 0;      // should be 5 when test finishes
            for i in 0..5 {
                let peer = &peer_2_neighbors[i];
                let n = peer.to_neighbor();
                let p_opt = PeerDB::get_peer(peer_1_dbconn, n.addr.network_id, &n.addr.addrbytes, n.addr.port).unwrap();
                match p_opt {
                    None => {
                        test_debug!("no such peer: {:?}", &n.addr);
                    },
                    Some(p) => {
                        assert_eq!(p.public_key, n.public_key);
                        assert_eq!(p.expire_block, n.expire_block);
                        num_contacted += 1;
                    }
                }
                
                let stale_peer = &peer_2_neighbors[i+5];
                let stale_n = stale_peer.to_neighbor();
                let stale_peer_opt = PeerDB::get_peer(peer_1_dbconn, stale_n.addr.network_id, &stale_n.addr.addrbytes, stale_n.addr.port).unwrap();
                match stale_peer_opt {
                    None => {},
                    Some(_) => {
                        test_debug!("stale peer contacted: {:?}", &stale_n.addr);
                        assert!(false);
                    }
                }
            }

            if num_contacted < 5 {
                continue;
            }
            
            // peer 1 learned that peer 2 has an out-degree of 6 (peer_1 + 5 fresh neighbors) and an in-degree of 1 
            let n2 = peer_2.to_neighbor();
            let p2_opt = PeerDB::get_peer(peer_1_dbconn, n2.addr.network_id, &n2.addr.addrbytes, n2.addr.port).unwrap();
            match p2_opt {
                None => {
                    test_debug!("no peer 2");
                },
                Some(p2) => {
                    if p2.out_degree >= 6 && p2.in_degree >= 1 {
                        assert_eq!(p2.out_degree, 6);
                        did_handshakes = true;
                    }
                }
            }
        }        

        debug!("Completed walk round {} step(s)", i);
        
        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    }

    #[test]
    fn test_step_walk_2_neighbors_plain() {
        let mut peer_1_config = TestPeerConfig::from_port(32500);
        let mut peer_2_config = TestPeerConfig::from_port(32502);

        peer_1_config.whitelisted = -1;
        peer_2_config.whitelisted = -1;

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();
            
            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
        
        // peer 2 contacted peer 1
        let stats_2 = peer_2.network.get_neighbor_stats(&peer_1.to_neighbor().addr).unwrap();
        assert!(stats_2.last_contact_time > 0);
        assert!(stats_2.last_handshake_time > 0);
        assert!(stats_2.last_send_time > 0);
        assert!(stats_2.last_recv_time > 0);
        assert!(stats_2.bytes_rx > 0);
        assert!(stats_2.bytes_tx > 0);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 was added to the peer DB of peer 1
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(peer_1_dbconn, neighbor_2.addr.network_id, &neighbor_2.addr.addrbytes, neighbor_2.addr.port).unwrap() {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            },
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }
        
        // peer 1 was added to the peer DB of peer 2
        let peer_2_dbconn = peer_2.get_peerdb_conn();
        match PeerDB::get_peer(peer_2_dbconn, neighbor_1.addr.network_id, &neighbor_1.addr.addrbytes, neighbor_1.addr.port).unwrap() {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_1.addr);
                assert!(false);
            },
            Some(p) => {
                assert_eq!(p.public_key, neighbor_1.public_key);
                assert_eq!(p.expire_block, neighbor_1.expire_block);
            }
        }
    }

    #[test]
    fn test_step_walk_2_neighbors_rekey() {
        let mut peer_1_config = TestPeerConfig::from_port(32600);
        let mut peer_2_config = TestPeerConfig::from_port(32602);

        peer_1_config.whitelisted = -1;
        peer_2_config.whitelisted = -1;
            
        // turn off features we don't use
        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;
        
        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;
        
        let first_block_height = peer_1_config.current_block + 1;

        // make keys expire soon
        peer_1_config.private_key_expire = first_block_height + 3;
        peer_2_config.private_key_expire = first_block_height + 4;

        peer_1_config.connection_opts.private_key_lifetime = 5;
        peer_2_config.connection_opts.private_key_lifetime = 5;

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let initial_public_key_1 = peer_1.get_public_key();
        let initial_public_key_2 = peer_2.get_public_key();

        // walk for a bit
        for i in 0..10 {
            for j in 0..5 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        // assert_eq!(w.result.dead_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        // assert_eq!(w.result.dead_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };
            }

            peer_1.add_empty_burnchain_block();
            peer_2.add_empty_burnchain_block();
        }

        // peer 1 contacted peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr).unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
        
        // peer 2 contacted peer 1
        let stats_2 = peer_2.network.get_neighbor_stats(&peer_1.to_neighbor().addr).unwrap();
        assert!(stats_2.last_contact_time > 0);
        assert!(stats_2.last_handshake_time > 0);
        assert!(stats_2.last_send_time > 0);
        assert!(stats_2.last_recv_time > 0);
        assert!(stats_2.bytes_rx > 0);
        assert!(stats_2.bytes_tx > 0);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 1 was added to the peer DB of peer 2
        assert!(PeerDB::get_peer(peer_1.network.peerdb.conn(), neighbor_2.addr.network_id, &neighbor_2.addr.addrbytes, neighbor_2.addr.port).unwrap().is_some());
        
        // peer 2 was added to the peer DB of peer 1
        assert!(PeerDB::get_peer(peer_2.network.peerdb.conn(), neighbor_1.addr.network_id, &neighbor_1.addr.addrbytes, neighbor_1.addr.port).unwrap().is_some());
        
        // new keys
        assert!(peer_1.get_public_key() != initial_public_key_1);
        assert!(peer_2.get_public_key() != initial_public_key_2);
    }
    
    #[test]
    fn test_step_walk_2_neighbors_different_networks() {
        // peer 1 and 2 try to handshake but never succeed since they have different network IDs
        let mut peer_1_config = TestPeerConfig::from_port(32700);
        let mut peer_2_config = TestPeerConfig::from_port(32702);

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        
        // peer 2 thinks peer 1 has the same network ID that it does
        peer_1_config.network_id = peer_1_config.network_id + 1;
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());
        peer_1_config.network_id = peer_1_config.network_id - 1;
        
        // different network IDs
        peer_2_config.network_id = peer_1_config.network_id + 1;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut i = 0;
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!("peer 1 took {} walk steps; peer 2 took {} walk steps", walk_1_count, walk_2_count);

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                },
                None => {}
            };
            
            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                },
                None => {}
            };

            i += 1;
        }
        
        debug!("Completed walk round {} step(s)", i);

        // peer 1 did NOT contact peer 2
        let stats_1 = peer_1.network.get_neighbor_stats(&peer_2.to_neighbor().addr);
        assert!(stats_1.is_none());
        
        // peer 2 did NOT contact peer 1
        let stats_2 = peer_2.network.get_neighbor_stats(&peer_1.to_neighbor().addr);
        assert!(stats_2.is_none());

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 1 was NOT added to the peer DB of peer 2
        assert!(PeerDB::get_peer(peer_1.network.peerdb.conn(), neighbor_2.addr.network_id, &neighbor_2.addr.addrbytes, neighbor_2.addr.port).unwrap().is_none());
        
        // peer 2 was NOT added to the peer DB of peer 1
        assert!(PeerDB::get_peer(peer_2.network.peerdb.conn(), neighbor_1.addr.network_id, &neighbor_1.addr.addrbytes, neighbor_1.addr.port).unwrap().is_none());
    }
    
    fn setup_peer_config(i: usize, port_base: u16, neighbor_count: usize, peer_count: usize) -> TestPeerConfig {
        let mut conf = TestPeerConfig::from_port(port_base + (2*i as u16));
        conf.connection_opts.num_neighbors = neighbor_count as u64;
        conf.connection_opts.soft_num_neighbors = neighbor_count as u64;

        conf.connection_opts.num_clients = 256;
        conf.connection_opts.soft_num_clients = 128;

        conf.connection_opts.max_clients_per_host = MAX_NEIGHBORS_DATA_LEN as u64;
        conf.connection_opts.soft_max_clients_per_host = peer_count as u64;

        conf.connection_opts.max_neighbors_per_host = MAX_NEIGHBORS_DATA_LEN as u64;
        conf.connection_opts.soft_max_neighbors_per_host = (neighbor_count/2) as u64;
        conf.connection_opts.soft_max_neighbors_per_org = (neighbor_count/2) as u64;

        conf.connection_opts.walk_interval = 0;

        conf.connection_opts.disable_inv_sync = true;
        conf.connection_opts.disable_block_download = true;

        let j = i as u32;
        conf.burnchain.peer_version = PEER_VERSION | (j << 16) | (j << 8) | j;     // different non-major versions for each peer
        conf
    }

    #[test]
    #[ignore]
    fn test_walk_ring_whitelist_20() {
        // all initial peers are whitelisted
        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 32800, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = -1;      // always whitelisted
            conf.blacklisted = 0;

            peer_configs.push(conf);
        }

        test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);
    }
    
    #[test]
    #[ignore]
    fn test_walk_ring_20_plain() {
        // initial peers are neither white- nor blacklisted
        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 32900, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = 0;
            conf.blacklisted = 0;

            peer_configs.push(conf);
        }

        test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);
    }

    #[test]
    #[ignore]
    fn test_walk_ring_20_org_biased() {
        // one outlier peer has a different org than the others.
        use std::env;

        // ::33000 is in AS 1
        env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33000", "1");

        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33000, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = 0;
            conf.blacklisted = 0;
            if i == 0 {
                conf.asn = 1;
                conf.org = 1;
            }
            else {
                conf.asn = 0;
                conf.org = 0;
            }

            peer_configs.push(conf);
        }

        let peers = test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);

        // all peers see peer ::33000 as having ASN and Org ID 1
        let peer_0 = peer_configs[0].to_neighbor();
        for i in 1..PEER_COUNT {
            match PeerDB::get_peer(peers[i].network.peerdb.conn(), peer_0.addr.network_id, &peer_0.addr.addrbytes, peer_0.addr.port).unwrap() {
                Some(p) => {
                    assert_eq!(p.asn, 1);
                    assert_eq!(p.org, 1);
                },
                None => {}
            }
        }

        // no peer pruned peer ::33000
        for i in 1..PEER_COUNT {
            match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                None => {},
                Some(count) => {
                    assert_eq!(*count, 0);
                }
            }
        }
    }

    fn test_walk_ring(peer_configs: &mut Vec<TestPeerConfig>, neighbor_count: usize) -> Vec<TestPeer> {
        // arrange neighbors into a "ring" topology, where
        // neighbor N is connected to neighbor (N-1)%NUM_NEIGHBORS and (N+1)%NUM_NEIGHBORS.
        let mut peers = vec![];

        let PEER_COUNT = peer_configs.len();
        let NEIGHBOR_COUNT = neighbor_count;

        for i in 0..PEER_COUNT {
            let n = (i + 1) % PEER_COUNT;
            let neighbor = peer_configs[n].to_neighbor();
            peer_configs[i].add_neighbor(&neighbor);
        }
        for i in 1..PEER_COUNT+1 {
            let p = i - 1;
            let neighbor = peer_configs[p].to_neighbor();
            peer_configs[i % PEER_COUNT].add_neighbor(&neighbor);
        }

        for i in 0..PEER_COUNT {
            let p = TestPeer::new(peer_configs[i].clone());
            peers.push(p);
        }

        run_topology_test(&mut peers, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);

        // no nacks or handshake-rejects
        for i in 0..PEER_COUNT {
            for (_, convo) in peers[i].network.peers.iter() {
                assert!(*convo.stats.msg_rx_counts.get(&StacksMessageID::Nack).unwrap_or(&0) == 0);
                assert!(*convo.stats.msg_rx_counts.get(&StacksMessageID::HandshakeReject).unwrap_or(&0) == 0);
            }
        }

        peers
    }
    
    #[test]
    #[ignore]
    fn test_walk_line_whitelisted_20() {
        // initial peers are neither white- nor blacklisted
        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33100, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = -1;
            conf.blacklisted = 0;

            peer_configs.push(conf);
        }

        test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
    }
    
    #[test]
    #[ignore]
    fn test_walk_line_20_plain() {
        // initial peers are neither white- nor blacklisted
        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;

        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33200, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = 0;
            conf.blacklisted = 0;

            peer_configs.push(conf);
        }

        test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
    }

    #[test]
    #[ignore]
    fn test_walk_line_20_org_biased() {
        // one outlier peer has a different org than the others.
        use std::env;

        // ::33300 is in AS 1
        env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33300", "1");

        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;     // make this a little bigger to speed this test up
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33300, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = 0;
            conf.blacklisted = 0;
            if i == 0 {
                conf.asn = 1;
                conf.org = 1;
            }
            else {
                conf.asn = 0;
                conf.org = 0;
            }

            peer_configs.push(conf);
        }

        let peers = test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, 0);

        // all peers see peer ::33300 as having ASN and Org ID 1
        let peer_0 = peer_configs[0].to_neighbor();
        for i in 1..PEER_COUNT {
            match PeerDB::get_peer(peers[i].network.peerdb.conn(), peer_0.addr.network_id, &peer_0.addr.addrbytes, peer_0.addr.port).unwrap() {
                Some(p) => {
                    assert_eq!(p.asn, 1);
                    assert_eq!(p.org, 1);
                },
                None => {}
            }
        }

        // no peer pruned peer ::33300
        for i in 1..PEER_COUNT {
            match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                None => {},
                Some(count) => {
                    assert_eq!(*count, 0);
                }
            }
        }
    }

    fn test_walk_line(peer_configs: &mut Vec<TestPeerConfig>, neighbor_count: usize, tests: u64) -> Vec<TestPeer> {
        // arrange neighbors into a "line" topology, where
        // neighbor N is connected to neighbor (N-1)%NUM_NEIGHBORS and (N+1)%NUM_NEIGHBORS
        // except for neighbors 0 and 19 (which each only have one neighbor).
        // all initial peers are whitelisted
        let mut peers = vec![];

        let PEER_COUNT = peer_configs.len();
        let NEIGHBOR_COUNT = neighbor_count;
        for i in 0..PEER_COUNT-1 {
            let n = i + 1;
            let neighbor = peer_configs[n].to_neighbor();
            peer_configs[i].add_neighbor(&neighbor);
        }
        for i in 1..PEER_COUNT {
            let p = i - 1;
            let neighbor = peer_configs[p].to_neighbor();
            peer_configs[i].add_neighbor(&neighbor);
        }

        for i in 0..PEER_COUNT {
            let p = TestPeer::new(peer_configs[i].clone());
            peers.push(p);
        }

        run_topology_test(&mut peers, NEIGHBOR_COUNT, tests);

        // no nacks or handshake-rejects
        for i in 0..PEER_COUNT {
            for (_, convo) in peers[i].network.peers.iter() {
                assert!(*convo.stats.msg_rx_counts.get(&StacksMessageID::Nack).unwrap_or(&0) == 0);
                assert!(*convo.stats.msg_rx_counts.get(&StacksMessageID::HandshakeReject).unwrap_or(&0) == 0);
            }
        }

        peers
    }

    #[test]
    #[ignore]
    fn test_walk_star_whitelisted_20() {
        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33400, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = -1;      // always whitelisted
            conf.blacklisted = 0;

            peer_configs.push(conf);
        }

        test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);
    }
    
    #[test]
    #[ignore]
    fn test_walk_star_20_plain() {
        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33500, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = 0;
            conf.blacklisted = 0;

            peer_configs.push(conf);
        }

        test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);
    }
    
    #[test]
    #[ignore]
    fn test_walk_star_20_org_biased() {
        // one outlier peer has a different org than the others.
        use std::env;

        // ::33600 is in AS 1
        env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33600", "1");

        let mut peer_configs = vec![];
        let PEER_COUNT : usize = 20;
        let NEIGHBOR_COUNT : usize = 5;
        for i in 0..PEER_COUNT {
            let mut conf = setup_peer_config(i, 33600, NEIGHBOR_COUNT, PEER_COUNT);

            conf.whitelisted = 0;
            conf.blacklisted = 0;
            if i == 0 {
                conf.asn = 1;
                conf.org = 1;
            }
            else {
                conf.asn = 0;
                conf.org = 0;
            }

            peer_configs.push(conf);
        }

        let peers = test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);

        // all peers see peer ::33600 as having ASN and Org ID 1
        let peer_0 = peer_configs[0].to_neighbor();
        for i in 1..PEER_COUNT {
            match PeerDB::get_peer(peers[i].network.peerdb.conn(), peer_0.addr.network_id, &peer_0.addr.addrbytes, peer_0.addr.port).unwrap() {
                Some(p) => {
                    assert_eq!(p.asn, 1);
                    assert_eq!(p.org, 1);
                },
                None => {}
            }
        }

        // no peer pruned peer ::33600
        for i in 1..PEER_COUNT {
            match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                None => {},
                Some(count) => {
                    assert_eq!(*count, 0);
                }
            }
        }
    }

    fn test_walk_star(peer_configs: &mut Vec<TestPeerConfig>, neighbor_count: usize) -> Vec<TestPeer> {
        // arrange neighbors into a "star" topology, where
        // neighbor 0 is connected to all neighbors N > 0.
        // all initial peers are whitelisted.
        let mut peers = vec![];
        let PEER_COUNT = peer_configs.len();
        let NEIGHBOR_COUNT = neighbor_count;

        for i in 1..PEER_COUNT {
            let neighbor = peer_configs[i].to_neighbor();
            let hub = peer_configs[0].to_neighbor();
            peer_configs[0].add_neighbor(&neighbor);
            peer_configs[i].add_neighbor(&hub);
        }

        for i in 0..PEER_COUNT {
            let p = TestPeer::new(peer_configs[i].clone());
            peers.push(p);
        }

        run_topology_test(&mut peers, NEIGHBOR_COUNT, 0);

        // no nacks or handshake-rejects
        for i in 0..PEER_COUNT {
            for (_, convo) in peers[i].network.peers.iter() {
                assert!(*convo.stats.msg_rx_counts.get(&StacksMessageID::Nack).unwrap_or(&0) == 0);
                assert!(*convo.stats.msg_rx_counts.get(&StacksMessageID::HandshakeReject).unwrap_or(&0) == 0);
            }
        }

        peers
    }
    
    fn dump_peers(peers: &Vec<TestPeer>) -> () {
        test_debug!("\n=== PEER DUMP ===");
        for i in 0..peers.len() {
            let mut neighbor_index = vec![];
            let mut outbound_neighbor_index = vec![];
            for j in 0..peers.len() {
                let stats_opt = peers[i].network.get_neighbor_stats(&peers[j].to_neighbor().addr);
                match stats_opt {
                    Some(stats) => {
                        neighbor_index.push(j);
                        if stats.outbound {
                            outbound_neighbor_index.push(j);
                        }
                    },
                    None => {}
                }
            }

            let all_neighbors = PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
            let num_whitelisted = all_neighbors.iter().fold(0, |mut sum, ref n2| {sum += if n2.whitelisted < 0 { 1 } else { 0 }; sum});
            test_debug!("Neighbor {} (all={}, outbound={}) (total neighbors = {}, total whitelisted = {}): outbound={:?} all={:?}", i, neighbor_index.len(), outbound_neighbor_index.len(), all_neighbors.len(), num_whitelisted, &outbound_neighbor_index, &neighbor_index);
        }
        test_debug!("\n");
    }

    fn dump_peer_histograms(peers: &Vec<TestPeer>) -> () {
        let mut outbound_hist : HashMap<usize, usize> = HashMap::new();
        let mut inbound_hist : HashMap<usize, usize> = HashMap::new();
        let mut all_hist : HashMap<usize, usize> = HashMap::new();
        for i in 0..peers.len() {
            let mut neighbor_index = vec![];
            let mut inbound_neighbor_index = vec![];
            let mut outbound_neighbor_index = vec![];
            for j in 0..peers.len() {
                let stats_opt = peers[i].network.get_neighbor_stats(&peers[j].to_neighbor().addr);
                match stats_opt {
                    Some(stats) => {
                        neighbor_index.push(j);
                        if stats.outbound {
                            outbound_neighbor_index.push(j);
                        }
                        else {
                            inbound_neighbor_index.push(j);
                        }
                    },
                    None => {}
                }
            }
            for inbound in inbound_neighbor_index.iter() {
                if inbound_hist.contains_key(inbound) {
                    let c = inbound_hist.get(inbound).unwrap().to_owned();
                    inbound_hist.insert(*inbound, c + 1);
                }
                else {
                    inbound_hist.insert(*inbound, 1);
                }
            }
            for outbound in outbound_neighbor_index.iter() {
                if outbound_hist.contains_key(outbound) {
                    let c = outbound_hist.get(outbound).unwrap().to_owned();
                    outbound_hist.insert(*outbound, c + 1);
                }
                else {
                    outbound_hist.insert(*outbound, 1);
                }
            }
            for n in neighbor_index.iter() {
                if all_hist.contains_key(n) {
                    let c = all_hist.get(n).unwrap().to_owned();
                    all_hist.insert(*n, c + 1);
                }
                else {
                    all_hist.insert(*n, 1);
                }
            }
        }

        test_debug!("=== PEER HISTOGRAM ===");
        for i in 0..peers.len() {
            test_debug!("Neighbor {}: #in={} #out={} #all={}", i, inbound_hist.get(&i).unwrap_or(&0), outbound_hist.get(&i).unwrap_or(&0), all_hist.get(&i).unwrap_or(&0));
        }
        test_debug!("\n");
    }

    fn run_topology_test(peers: &mut Vec<TestPeer>, neighbor_count: usize, test_bits: u64) -> () {
        let PEER_COUNT = peers.len();

        let mut initial_whitelisted : HashMap<NeighborKey, Vec<NeighborKey>> = HashMap::new();
        let mut initial_blacklisted : HashMap<NeighborKey, Vec<NeighborKey>> = HashMap::new();

        for i in 0..PEER_COUNT {
            // turn off components we don't need
            peers[i].config.connection_opts.disable_inv_sync = true;
            peers[i].config.connection_opts.disable_block_download = true;
            let nk = peers[i].config.to_neighbor().addr.clone();
            for j in 0..peers[i].config.initial_neighbors.len() {
                let initial = &peers[i].config.initial_neighbors[j];
                if initial.whitelisted < 0 {
                    if !initial_whitelisted.contains_key(&nk) {
                        initial_whitelisted.insert(nk.clone(), vec![]);
                    }
                    initial_whitelisted.get_mut(&nk).unwrap().push(initial.addr.clone());
                }
                if initial.blacklisted < 0 {
                    if !initial_blacklisted.contains_key(&nk) {
                        initial_blacklisted.insert(nk.clone(), vec![]);
                    }
                    initial_blacklisted.get_mut(&nk).unwrap().push(initial.addr.clone());
                }
            }
        }

        for i in 0..PEER_COUNT {
            peers[i].connect_initial().unwrap();
        }

        // go until each neighbor knows about each other neighbor 
        let mut finished = false;
        let mut count = 0;
        while !finished {
            finished = true;
            let mut peer_counts = 0;
            for i in 0..PEER_COUNT {
                let _ = peers[i].step();
                let nk = peers[i].config.to_neighbor().addr;
                
                // whitelisted peers are still connected 
                match initial_whitelisted.get(&nk) {
                    Some(ref peer_list) => {
                        for pnk in peer_list.iter() {
                            if !peers[i].network.events.contains_key(&pnk.clone()) {
                                error!("{:?}: Perma-whitelisted peer {:?} not connected anymore", &nk, &pnk);
                                assert!(false);
                            }
                        }
                    },
                    None => {}
                };

                // blacklisted peers are never connected 
                match initial_blacklisted.get(&nk) {
                    Some(ref peer_list) => {
                        for pnk in peer_list.iter() {
                            if peers[i].network.events.contains_key(&pnk.clone()) {
                                error!("{:?}: Perma-blacklisted peer {:?} connected", &nk, &pnk);
                                assert!(false);
                            }
                        }
                    }
                    None => {}
                };

                // all ports are unique in the p2p socket table
                let mut ports : HashSet<u16> = HashSet::new();
                for k in peers[i].network.events.keys() {
                    if ports.contains(&k.port) {
                        error!("duplicate port {} from {:?}", k.port, k);
                        assert!(false);
                    }
                    ports.insert(k.port);
                }

                // done?
                let all_neighbors = PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
                peer_counts += all_neighbors.len();
                if (all_neighbors.len() as u64) < ((PEER_COUNT - 1) as u64) {
                    let nk = peers[i].config.to_neighbor().addr;
                    test_debug!("waiting for {:?} to fill up its frontier: {}", &nk, all_neighbors.len());
                    finished = false;
                }
            }
            
            count += 1;

            test_debug!("Network convergence rate: {}%", (100.0 * (peer_counts as f64)) / ((PEER_COUNT * PEER_COUNT) as f64));

            if finished {
                break;
            }
 
            test_debug!("Finished walking the network {} times", count);
            dump_peers(&peers);
            dump_peer_histograms(&peers);
        }

        test_debug!("Converged after {} calls to network.run()", count);
        dump_peers(&peers);
        dump_peer_histograms(&peers);
    }
}
