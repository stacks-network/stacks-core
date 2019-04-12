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


use net::PeerAddress;
use net::Neighbor;
use net::NeighborKey;
use net::Error as net_error;
use net::db::PeerDB;
use net::asn::ASEntry4;

use net::*;
use net::codec::*;

use net::connection::Connection;
use net::connection::ConnectionOptions;
use net::connection::NetworkReplyHandle;

use net::db::LocalPeer;

use net::p2p::*;

use util::db::Error as db_error;
use util::db::DBConn;

use util::secp256k1::Secp256k1PublicKey;

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
use util::hash::Hash160;

use rand::prelude::*;
use rand::thread_rng;

use rusqlite::Transaction;

pub const NEIGHBOR_MINIMUM_CONTACT_INTERVAL : u64 = 600;      // don't reach out to a frontier neighbor more than once every 10 minutes

pub const NEIGHBOR_REQUEST_TIMEOUT : u64 = 60;

impl NeighborKey {
    pub fn from_neighbor_address(peer_version: u32, network_id: u32, na: &NeighborAddress) -> NeighborKey {
        NeighborKey {
            peer_version: peer_version,
            network_id: network_id,
            addrbytes: na.addrbytes.clone(),
            port: na.port
        }
    }

    pub fn to_normalized(&self) -> NeighborKey {
        NeighborKey {
            peer_version: 0,
            network_id: 0,
            addrbytes: self.addrbytes.clone(),
            port: self.port
        }
    }
}

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
            .map_err(|_e| net_error::DBError)
    }

    /// Save to the peer DB, inserting it if it isn't already there.
    /// Return true if saved.
    /// Return false if not saved -- i.e. the frontier is full and we should try evicting neighbors.
    pub fn save<'a>(&self, tx: &mut Transaction<'a>) -> Result<bool, net_error> {
        PeerDB::try_insert_peer(tx, &self)
            .map_err(|_e| net_error::DBError)
    }

    /// Attempt to load a neighbor from our peer DB, given its NeighborAddress reported by another
    /// peer.  Returns a neighbor in the peer DB if it matches the neighbor address and has a fresh public key
    /// (where "fresh" means "the public key hash matches the neighbor address")
    pub fn from_neighbor_address(conn: &DBConn, peer_version: u32, network_id: u32, block_height: u64, neighbor_address: &NeighborAddress) -> Result<Option<Neighbor>, net_error> {
        let peer_opt = PeerDB::get_peer(conn, network_id, &neighbor_address.addrbytes, neighbor_address.port)
            .map_err(|_e| net_error::DBError)?;

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
                    let pubkey_160 = Hash160::from_data(&peer.public_key.to_bytes()[..]);
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
}

/// Struct for capturing the results of a walk.
/// -- reports newly-connected neighbors
/// -- reports neighbors we had trouble talking to.
/// The peer network will use this struct to clean out dead neighbors, and to keep the number of
/// _outgoing_ connections limited to NUM_NEIGHBORS.
#[derive(Clone)]
pub struct NeighborWalkResult {
    pub new_connections: HashSet<NeighborKey>,
    pub broken_connections: HashSet<NeighborKey>,
    pub replaced_neighbors: HashSet<NeighborKey>
}

impl NeighborWalkResult {
    pub fn new() -> NeighborWalkResult {
        NeighborWalkResult {
            new_connections: HashSet::new(),
            broken_connections: HashSet::new(),
            replaced_neighbors: HashSet::new()
        }
    }

    pub fn add_new(&mut self, nk: NeighborKey) -> () {
        self.new_connections.insert(nk);
    }

    pub fn add_broken(&mut self, nk: NeighborKey) -> () {
        self.broken_connections.insert(nk);
    }

    pub fn add_replaced(&mut self, nk: NeighborKey) -> () {
        self.replaced_neighbors.insert(nk);
    }

    pub fn clear(&mut self) -> () {
        self.new_connections.clear();
        self.broken_connections.clear();
        self.replaced_neighbors.clear();
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum NeighborWalkState {
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

    prev_neighbor: Option<Neighbor>,
    cur_neighbor: Neighbor,
    next_neighbor: Option<Neighbor>,

    pub frontier: HashMap<NeighborKey, Neighbor>,
    new_frontier: HashMap<NeighborKey, Neighbor>,

    // pending request to cur_neighbor to get _its_ neighbors
    getneighbors_request: Option<NetworkReplyHandle>,

    // outstanding requests to handshake with our cur_neighbor's neighbors.
    resolved_handshake_neighbors: HashMap<NeighborAddress, Neighbor>,
    unresolved_handshake_neighbors: HashMap<NeighborAddress, NetworkReplyHandle>,

    // outstanding requests to get the neighbors of our cur_neighbor's neighbors
    resolved_getneighbors_neighbors: HashMap<NeighborKey, Vec<NeighborAddress>>,
    unresolved_getneighbors_neighbors: HashMap<NeighborKey, NetworkReplyHandle>,

    // outstanding requests to ping existing neighbors to be replaced in the frontier
    neighbor_replacements: HashMap<NeighborKey, Neighbor>,
    replaced_neighbors: HashMap<NeighborKey, u32>,
    unresolved_neighbor_pings: HashMap<NeighborKey, NetworkReplyHandle>,

    // neighbor walk result we build up incrementally 
    result: NeighborWalkResult,
}

impl NeighborWalk {
    pub fn new(neighbor: &Neighbor) -> NeighborWalk {
        NeighborWalk {
            state: NeighborWalkState::GetNeighborsBegin,

            prev_neighbor: None,
            cur_neighbor: neighbor.clone(),
            next_neighbor: None,
            
            frontier: HashMap::new(),
            new_frontier: HashMap::new(),
            
            getneighbors_request: None,

            resolved_handshake_neighbors: HashMap::new(),
            unresolved_handshake_neighbors: HashMap::new(),

            resolved_getneighbors_neighbors: HashMap::new(),
            unresolved_getneighbors_neighbors: HashMap::new(),

            neighbor_replacements: HashMap::new(),
            replaced_neighbors: HashMap::new(),
            unresolved_neighbor_pings: HashMap::new(),

            result: NeighborWalkResult::new(),
        }
    }

    /// Reset the walk with a new neighbor.
    /// Give back a report of the walk
    pub fn reset(&mut self, next_neighbor: &Neighbor) -> NeighborWalkResult {
        self.state = NeighborWalkState::GetNeighborsBegin;
        self.prev_neighbor = Some(self.cur_neighbor.clone());
        self.cur_neighbor = next_neighbor.clone();
        self.next_neighbor = None;

        self.frontier.clear();
        for (k, v) in self.new_frontier.drain() {
            self.frontier.insert(k, v);
        }

        self.getneighbors_request = None;

        self.resolved_handshake_neighbors.clear();
        self.unresolved_handshake_neighbors.clear();
        
        self.resolved_getneighbors_neighbors.clear();
        self.unresolved_getneighbors_neighbors.clear();

        self.neighbor_replacements.clear();
        self.replaced_neighbors.clear();
        self.unresolved_neighbor_pings.clear();

        let result = self.result.clone();
        self.result.clear();

        result
    }

    /// Begin refreshing our knowledge of peer in/out degrees
    pub fn getneighbors_begin(&mut self, req: Option<NetworkReplyHandle>) -> () {
        assert!(self.state == NeighborWalkState::GetNeighborsBegin);
        
        self.resolved_handshake_neighbors.clear();
        self.unresolved_handshake_neighbors.clear();
        
        self.getneighbors_request = req;

        // next state!
        self.state = NeighborWalkState::GetNeighborsFinish;
    }

    /// Find the neighbor addresses that we need to resolve to neighbors,
    /// and find out the neighbor addresses that we already have fresh neighbor data for.
    /// If we know of a neighbor, and contacted it recently, then consider it resolved _even if_
    /// the reported NeighborAddress public key hash doesn't match our records.
    fn lookup_stale_neighbors(dbconn: &DBConn, peer_version: u32, network_id: u32, block_height: u64, addrs: &Vec<NeighborAddress>) -> Result<(HashMap<NeighborAddress, Neighbor>, Vec<NeighborAddress>), net_error> {
        let mut to_resolve = vec![];
        let mut resolved = HashMap::<NeighborAddress, Neighbor>::new();
        for naddr in addrs {
            let neighbor_opt = Neighbor::from_neighbor_address(dbconn, peer_version, network_id, block_height, naddr)?;
            match neighbor_opt {
                None => {
                    // need to resolve this one, but don't talk to it if we did so recently (even
                    // if we have stale information for it -- the remote node could be trying to trick
                    // us into DDoS'ing this node).
                    let peer_opt = PeerDB::get_peer(dbconn, network_id, &naddr.addrbytes, naddr.port)
                        .map_err(|_e| net_error::DBError)?;

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
                    // our copy is still fresh 
                    resolved.insert(naddr.clone(), neighbor);
                }
            }
        }
        Ok((resolved, to_resolve))
    }

    /// Try to finish the getneighbors request to cur_neighbor
    /// Returns the list of neighbors we need to resolve
    /// Return None if we're not done yet, or haven't started yet.
    pub fn getneighbors_try_finish(&mut self, dbconn: &DBConn, peer_version: u32, network_id: u32, block_height: u64) -> Result<Option<Vec<NeighborAddress>>, net_error> {
        assert!(self.state == NeighborWalkState::GetNeighborsFinish);

        let req_opt = self.getneighbors_request.take();
        if req_opt.is_none() {
            return Ok(None);
        }

        let req = req_opt.unwrap();
        let neighbors_reply_res = req.try_recv();
        match neighbors_reply_res {
            Ok(message) => {
                match message.payload {
                    StacksMessageType::Neighbors(ref data) => {
                        let (mut found, to_resolve) = NeighborWalk::lookup_stale_neighbors(dbconn, peer_version, network_id, block_height, &data.neighbors)?;

                        for (naddr, neighbor) in found.drain() {
                            self.resolved_handshake_neighbors.insert(naddr, neighbor);
                        }

                        self.state = NeighborWalkState::GetHandshakesBegin;
                        Ok(Some(to_resolve))
                    },
                    StacksMessageType::Nack(ref data) => {
                        info!("Neighbor {:?} NACK'ed GetNeighbors with code {:?}", &self.cur_neighbor.addr, data.error_code);
                        self.result.add_broken(self.cur_neighbor.addr.clone());
                        Err(net_error::ConnectionBroken)
                    },
                    _ => {
                        // invalid message
                        info!("Got non-sequitor message from {:?}", &self.cur_neighbor.addr);
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
                        self.result.add_broken(self.cur_neighbor.addr.clone());
                        Err(e)
                    }
                }
            }
        }
    }

    /// Begin getting the neighors of cur_neighbor's neighbors.
    /// NetworkReplyHandles should be reply handles for Handshake requests.
    pub fn handshakes_begin(&mut self, mut handshake_handles: HashMap<NeighborAddress, NetworkReplyHandle>) -> () {
        assert!(self.state == NeighborWalkState::GetHandshakesBegin);

        // advance state!
        self.unresolved_handshake_neighbors.clear();
        for (naddr, nh) in handshake_handles.drain() {
            self.unresolved_handshake_neighbors.insert(naddr, nh);
        }

        self.state = NeighborWalkState::GetHandshakesFinish;
    }

    /// Given a neighbor we tried to insert into the peer database, find one of the existing
    /// neighbors it collided with.  Return its slot in the peer db.
    fn find_replaced_neighbor_slot(conn: &DBConn, nk: &NeighborKey) -> Result<Option<u32>, net_error> {
        let mut slots = PeerDB::peer_slots(conn, nk.network_id, &nk.addrbytes, nk.port)
            .map_err(|_e| net_error::DBError)?;

        if slots.len() == 0 {
            // not present
            return Ok(None);
        }

        let mut rng = thread_rng();
        slots.shuffle(&mut rng);
        
        for slot in slots {
            let peer_opt = PeerDB::get_peer_at(conn, nk.network_id, slot)
                .map_err(|_e| net_error::DBError)?;

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
    pub fn handshakes_try_finish<'a>(&mut self, tx: &mut Transaction<'a>, peer_version: u32, network_id: u32, block_height: u64) -> Result<Option<Vec<NeighborKey>>, net_error> {
        assert!(self.state == NeighborWalkState::GetHandshakesFinish);

        // see if we got any replies 
        let mut new_unresolved_handshakes = HashMap::new();
        for (naddr, rh) in self.unresolved_handshake_neighbors.drain() {
            let res = rh.try_recv();
            let rh_naddr = naddr.clone();       // used below
            let new_rh = match res {
                Ok(message) => {
                    match message.payload {
                        StacksMessageType::HandshakeAccept(ref data) => {
                            // success! do we know about this peer already?
                            let neighbor_from_handshake = Neighbor::from_handshake(tx, peer_version, network_id, &data.handshake)?;
                            let mut neighbor_opt = Neighbor::from_neighbor_address(tx, peer_version, network_id, block_height, &naddr)?;
                            match neighbor_opt {
                                Some(neighbor) => {
                                    // knew about this neighbor already
                                    self.resolved_handshake_neighbors.insert(naddr, neighbor.clone());

                                    // update our frontier as well
                                    self.new_frontier.insert(neighbor.addr.clone(), neighbor);
                                    neighbor_from_handshake.save_update(tx)?;
                                },
                                None => {
                                    // didn't know about this neighbor yet. Try to add it.
                                    let added = neighbor_from_handshake.save(tx)?;
                                    if !added {
                                        // no more room in the db.  See if we can add it by
                                        // evicting an existing neighbor once we're done with this
                                        // walk.
                                        let replaced_neighbor_slot_opt = NeighborWalk::find_replaced_neighbor_slot(tx, &neighbor_from_handshake.addr)?;

                                        match replaced_neighbor_slot_opt {
                                            Some(slot) => {
                                                self.neighbor_replacements.insert(neighbor_from_handshake.addr.clone(), neighbor_from_handshake.clone());
                                                self.replaced_neighbors.insert(neighbor_from_handshake.addr.clone(), slot);
                                            },
                                            None => {
                                                // shouldn't happen 
                                            }
                                        };
                                    }
                                    self.new_frontier.insert(neighbor_from_handshake.addr.clone(), neighbor_from_handshake);
                                }
                            };
                        },
                        StacksMessageType::HandshakeReject => {
                            // remote peer doesn't want to talk to us 
                            info!("Neighbor {:?} rejected our handshake", &naddr);
                            self.result.add_broken(NeighborKey::from_neighbor_address(peer_version, network_id, &naddr));
                        },
                        StacksMessageType::Nack(ref data) => {
                            // remote peer nope'd us
                            info!("Neighbor {:?} NACK'ed our handshake with error code {:?}", &naddr, data.error_code);
                            self.result.add_broken(NeighborKey::from_neighbor_address(peer_version, network_id, &naddr));
                        }
                        _ => {
                            // remote peer doesn't want to talk to us
                            info!("Neighbor {:?} replied a non-sequitor message", &naddr);
                            self.result.add_broken(NeighborKey::from_neighbor_address(peer_version, network_id, &naddr));
                        }
                    };
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
                            info!("Failed to handshake with {:?}", naddr);
                            self.result.add_broken(NeighborKey::from_neighbor_address(peer_version, network_id, &naddr));
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
            for (_, neighbor) in self.resolved_handshake_neighbors.iter() {
                neighbor_keys.push(neighbor.addr.clone());
            }

            // update our frontier knowledge
            for (nkey, new_neighbor) in self.new_frontier.drain() {
                self.frontier.insert(nkey, new_neighbor);
            }

            // advance state!
            self.state = NeighborWalkState::GetNeighborsNeighborsBegin;
            Ok(Some(neighbor_keys))
        }
        else {
            // still handshaking 
            Ok(None)
        }
    }

    /// Begin asking remote neighbors for their neighbors in order to estimate cur_neighbor's
    /// in-degree. 
    pub fn getneighbors_neighbors_begin(&mut self, mut getneighbors_handles: HashMap<NeighborKey, NetworkReplyHandle>) -> () {
        assert!(self.state == NeighborWalkState::GetNeighborsNeighborsBegin);

        // advance state!
        self.unresolved_getneighbors_neighbors.clear();
        for (naddr, nh) in getneighbors_handles.drain() {
            self.unresolved_getneighbors_neighbors.insert(naddr, nh);
        }

        self.state = NeighborWalkState::GetNeighborsNeighborsFinish;
    }

    /// Try to finish getting the neighbors from cur_neighbors' neighbors 
    /// Once all handles resolve, return the list of new neighbors.
    pub fn getneighbors_neighbors_try_finish<'a>(&mut self, tx: &mut Transaction<'a>, peer_version: u32, network_id: u32) -> Result<Option<Neighbor>, net_error> {
        assert!(self.state == NeighborWalkState::GetNeighborsNeighborsFinish);

        // see if we got any replies 
        let mut new_unresolved_neighbors = HashMap::new();
        for (nkey, rh) in self.unresolved_getneighbors_neighbors.drain() {
            let rh_nkey = nkey.clone();     // used below
            let res = rh.try_recv();
            let new_rh = match res {
                Ok(message) => {
                    match message.payload {
                        StacksMessageType::Neighbors(ref data) => {
                            self.resolved_getneighbors_neighbors.insert(nkey, data.neighbors.clone());
                        },
                        _ => {
                            // unexpected reply
                            info!("Neighbor {:?} replied a non-sequitor message (type {}); assuming broken", &nkey, message_type_to_id(&message.payload));
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
                        Err(e) => {
                            // disconnected from peer 
                            info!("Failed to get neighbors from {:?}", &nkey);
                            self.result.add_broken(nkey);
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
            self.unresolved_getneighbors_neighbors.insert(nkey, rh);
        }

        if self.unresolved_getneighbors_neighbors.len() == 0 {
            // finished!  build up frontier's in-degree estimation
            self.cur_neighbor.in_degree = 1;
            self.cur_neighbor.out_degree = self.resolved_getneighbors_neighbors.len() as u32;

            for (nkey, neighbor_list) in self.resolved_getneighbors_neighbors.iter() {
                for na in neighbor_list {
                    if na.addrbytes == self.cur_neighbor.addr.addrbytes && na.port == self.cur_neighbor.addr.port {
                        self.cur_neighbor.in_degree += 1;
                    }
                }
            }

            // remember this peer's in/out degree estimates
            self.cur_neighbor.save_update(tx)
                .map_err(|e| net_error::DBError)?;

            // advance state!
            self.state = NeighborWalkState::NeighborsPingBegin;
            Ok(Some(self.cur_neighbor.clone()))
        }
        else {
            // still working
            Ok(None)
        }
    }

    /// Pick a random neighbor from the frontier 
    /// TODO: find a cheaper way to do this
    fn pick_random_neighbor(frontier: &HashMap<NeighborKey, Neighbor>) -> Option<Neighbor> {
        let mut rnd = thread_rng();
        let sample = rnd.gen_range(0, frontier.len());
        let mut count = 0;

        for (nk, n) in frontier.iter() {
            count += 1;
            if count >= sample {
                return Some(n.clone());
            }
        }
        return None;
    }
        
        
    /// Do the MHRWDA step -- try to step from our cur_neighbor to an immediate neighbor, if there
    /// is any neighbor to step to.  Return the new cur_neighbor, if we were able to step.
    /// The caller should call reset() after this, optionally with a newly-selected frontier
    /// neighbor if we were unable to take a step.
    pub fn step(&mut self) -> Option<Neighbor> {
        let mut rnd = thread_rng();

        // step to a node in cur_neighbor's frontier, per MHRWDA
        let next_neighbor_opt = 
            if self.frontier.len() == 0 {
                // just started the walk, so stay here for now -- we don't yet know the neighbor's
                // frontier.
                Some(self.cur_neighbor.clone())
            }
            else {
                let next_neighbor = NeighborWalk::pick_random_neighbor(&self.frontier).unwrap();     // won't panic since self.frontier.len() > 0
                
                let walk_prob : f64 = rnd.gen();
                if walk_prob < fmin!(1.0, (self.cur_neighbor.in_degree as f64) / (next_neighbor.in_degree as f64)) {
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
                                    let alt_next_neighbor;
                                    loop {
                                        let candidate = NeighborWalk::pick_random_neighbor(&self.frontier).unwrap();
                                        if candidate.addr != prev_neighbor.addr {
                                            alt_next_neighbor = candidate.clone();
                                            break;
                                        }
                                    }

                                    let alt_prob : f64 = rnd.gen();
                                    let trans_prob = fmin!(
                                                        fmin!(1.0, (self.cur_neighbor.in_degree as f64) / ((alt_next_neighbor.in_degree * alt_next_neighbor.in_degree) as f64)), 
                                                        fmax!(1.0, (prev_neighbor.in_degree as f64) / ((self.cur_neighbor.in_degree * self.cur_neighbor.in_degree) as f64))
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

    // proceed to ping _existing_ neighbors that would be replaced
    pub fn ping_existing_neighbors_begin(&mut self, mut network_handles: HashMap<NeighborKey, NetworkReplyHandle>) -> () {
        assert!(self.state == NeighborWalkState::NeighborsPingBegin);

        self.unresolved_neighbor_pings.clear();

        for (neighbor_key, ping_handle) in network_handles.drain() {
            self.unresolved_neighbor_pings.insert(neighbor_key, ping_handle);
        }

        // advance state!
        self.state = NeighborWalkState::NeighborsPingFinish;
    }

    // try to finish pinging all exisitng neighbors.
    // if the remote neighbor does _not_ respond to our ping, then replace it.
    // Return the list of _evicted_ neighbors.
    pub fn ping_existing_neighbors_try_finish<'a>(&mut self, tx: &mut Transaction<'a>, network_id: u32) -> Result<Option<HashSet<NeighborKey>>, net_error> {
        assert!(self.state == NeighborWalkState::NeighborsPingFinish);

        let mut new_unresolved_neighbor_pings = HashMap::new();
        
        for (nkey, rh) in self.unresolved_neighbor_pings.drain() {
            let rh_nkey = nkey.clone();     // used below
            let res = rh.try_recv();
            let new_rh = match res {
                Ok(message) => {
                    match message.payload {
                        StacksMessageType::Pong(_) => {
                            // this peer is still alive -- will not replace it
                            continue;
                        },
                        _ => {
                            // unexpected reply -- this peer is misbehaving and should be replaced
                            info!("Neighbor {:?} replied a non-sequitor message (type {}); will replace", &nkey, message_type_to_id(&message.payload));
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
                        Err(e) => {
                            // disconnected from peer already -- we can replace it
                            info!("Neighbor {:?} could not be pinged; will replace", &nkey);
                            self.result.add_broken(nkey);
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
            for (replaceable_key, slot) in self.replaced_neighbors.iter() {
                let replacement = match self.neighbor_replacements.get(replaceable_key) {
                    Some(n) => n.clone(),
                    None => {
                        continue;
                    }
                };

                let replaced_opt = PeerDB::get_peer_at(tx, network_id, *slot)
                    .map_err(|_e| net_error::DBError)?;

                match replaced_opt {
                    Some(replaced) => {
                        info!("Replace {:?}:{:?} with {:?}:{:?}", &replaced.addr.addrbytes, replaced.addr.port, &replacement.addr.addrbytes, replaced.addr.port);

                        PeerDB::insert_or_replace_peer(tx, &replacement, *slot)
                            .map_err(|_e| net_error::DBError)?;

                        self.result.add_replaced(replaced.addr.clone());
                    },
                    None => {}
                }
            }

            // advance state!
            self.state = NeighborWalkState::Finished;
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
        let neighbors = PeerDB::get_random_walk_neighbors(&self.peerdb.conn(), self.burnchain.network_id, num_neighbors as u32, block_height)
            .map_err(|_e| net_error::DBError)?;

        Ok(neighbors)
    }

    /// Begin walking the peer graph by reaching out to a neighbor, connecting to _it's_ neighbors,
    /// asking for their neighbor-sets (in order to get the neighbor's in/out-degree estimates),
    /// and then stepping to one of the neighbor's neighbors.
    /// Return an error to reset the walk.
    pub fn walk_getneighbors_begin(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView) -> Result<(), net_error> {
        if self.walk.is_none() {
            // pick a random neighbor as a walking point 
            let next_neighbors = self.get_random_neighbors(1, chain_view.burn_block_height)?;
            if next_neighbors.len() == 0 {
                // can't do anything 
                return Err(net_error::NoSuchNeighbor);
            }

            self.walk = Some(NeighborWalk::new(&next_neighbors[0]));
        }
        let mut getneighbors_request = None;
        let mut my_walk = self.walk.take();

        match my_walk {
            None => {},     // won't happen 
            Some(ref mut walk) => {
                match walk.getneighbors_request {
                    Some(_) => {},   // in-progress
                    None => {
                        let msg = self.sign_for_peer(local_peer, chain_view, &walk.cur_neighbor.addr, StacksMessageType::GetNeighbors)?;
                        let req_res = self.dispatch_send_message(&walk.cur_neighbor.addr, msg, NEIGHBOR_REQUEST_TIMEOUT);
                        match req_res {
                            Ok(handle) => {
                                getneighbors_request = Some(handle);
                                walk.getneighbors_begin(getneighbors_request);
                            },
                            Err(e) => {
                                info!("Not connected: {:?} ({:?}", &walk.cur_neighbor.addr, &e);
                            }
                        };
                    }
                };
            }
        };

        self.walk = my_walk;

        Ok(())
    }

    /// Make progress completing the pending getneighbor request, and if it completes,
    /// proceed to handshake with all its neighbors that we don't know about.
    /// Return an error to reset the walk.
    pub fn walk_getneighbors_try_finish(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView) -> Result<(), net_error> {
        let mut my_walk = self.walk.take();

        let res = match my_walk {
            None => {
                panic!("Invalid neighbor-walk state reached -- cannot finish getting neighbors when the walk state is not instantiated");
            },
            Some(ref mut walk) => {
                let neighbor_addrs_opt = walk.getneighbors_try_finish(self.peerdb.conn(), self.burnchain.peer_version, self.burnchain.network_id, chain_view.burn_block_height)?;
                match neighbor_addrs_opt {
                    None => {
                        // nothing to do -- not done yet
                        Ok(())
                    },
                    Some(neighbor_addrs) => {
                        // got neighbors -- proceed to ask each one for *its* neighbors so we can
                        // estimate cur_neighbor's in-degree and grow our frontier.
                        let mut pending_handshakes = HashMap::new();
                        let handshake_data = HandshakeData::from_local_peer(local_peer);
                        let now = get_epoch_time_secs();

                        for na in neighbor_addrs {
                            let nk = NeighborKey::from_neighbor_address(self.burnchain.peer_version, self.burnchain.network_id, &na);

                            if !self.is_registered(&nk) {
                                // not connected yet
                                let con_res = self.dispatch_connect_peer(&local_peer, chain_view, &nk);
                                match con_res {
                                    Ok(_) => {
                                        // remember this in the walk result
                                        walk.result.new_connections.insert(nk.clone());
                                    },
                                    Err(e) => {
                                        info!("Failed to connect to {:?}: {:?}", &nk, &e);
                                        walk.result.add_broken(nk.clone());
                                        continue;
                                    }
                                }
                            }

                            let payload = StacksMessageType::Handshake(handshake_data.clone());
                            let msg = self.sign_for_peer(local_peer, chain_view, &nk, payload)?;

                            let rh_res = self.dispatch_send_message(&nk, msg, now + NEIGHBOR_REQUEST_TIMEOUT);
                            match rh_res {
                                Ok(rh) => {
                                    pending_handshakes.insert(na, rh);
                                }
                                Err(e) => {
                                    // not connected to this peer 
                                    info!("Not connected to {:?}: {:?}", &nk, &e);
                                    continue;
                                }
                            }
                        }

                        walk.handshakes_begin(pending_handshakes);
                        Ok(())
                    }
                }
            }
        };

        self.walk = my_walk;
        res
    }

    /// Make progress on completing handshakes with all our neighbors.  If we finish, proceed to
    /// ask them for their neighbors in order to estimate cur_neighbor's in/out degrees.
    /// Return an error to reset the walk.
    pub fn walk_handshakes_try_finish(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView) -> Result<(), net_error> {
        let mut my_walk = self.walk.take();

        let res = match my_walk {
            None => {
                panic!("Invalid neighbor-walk state reached -- cannot finish handshaking with neighbor's frontier when the walk state is not instantiated");
            },
            Some(ref mut walk) => {
                let neighbor_keys_opt = {
                    let mut tx = self.peerdb.tx_begin()
                        .map_err(|_e| net_error::DBError)?;

                    let res = walk.handshakes_try_finish(&mut tx, self.burnchain.peer_version, self.burnchain.network_id, chain_view.burn_block_height)?;
                    tx.commit()
                        .map_err(|_e| net_error::DBError)?;
                    res
                };

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
                            if !self.is_registered(&nk) {
                                // not connected -- can't ask for neighbors 
                                info!("Not connected to {:?}", &nk);
                                continue;
                            }

                            let msg = self.sign_for_peer(local_peer, chain_view, &nk, StacksMessageType::GetNeighbors)?;
                            let rh_res = self.dispatch_send_message(&nk, msg, now + NEIGHBOR_REQUEST_TIMEOUT);
                            match rh_res {
                                Ok(rh) => {
                                    pending_getneighbors.insert(nk, rh);
                                }
                                Err(e) => {
                                    // failed to begin getneighbors 
                                    info!("Not connected to {:?}: {:?}", &nk, &e);
                                    continue;
                                }
                            }
                        }

                        walk.getneighbors_neighbors_begin(pending_getneighbors);
                        Ok(())
                    }
                }
            }
        };

        self.walk = my_walk;
        res
    }

    /// Make progress on completing getneighbors requests to all of cur_neighbor's neighbors.  If
    /// we finish, proceed to update our knowledge of these neighbors and take a step in the peer
    /// graph.
    pub fn walk_getneighbors_neighbors_try_finish(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView) -> Result<Option<Neighbor>, net_error> {
        let mut my_walk = self.walk.take();
        let res = match my_walk {
            None => {
                panic!("Invalid neighbor-walk state reached -- cannot finish gathering neighbor's frontier's GetNeighbors replies when the walk state is not instantiated");
            },
            Some(ref mut walk) => {
                let neighbor_opt = {
                    let mut tx = self.peerdb.tx_begin()
                        .map_err(|_e| net_error::DBError)?;
                    
                    let neighbor_opt = walk.getneighbors_neighbors_try_finish(&mut tx, self.burnchain.peer_version, self.burnchain.network_id)?;
                    tx.commit()
                        .map_err(|_e| net_error::DBError)?;

                    neighbor_opt
                };

                match neighbor_opt {
                    None => {
                        // not done yet 
                        Ok(None)
                    },
                    Some(_neighbor) => {
                        // finished calculating this neighbor's in/out degree.
                        // walk to the next neighbor.
                        let next_neighbor_opt = walk.step();
                        let mut ping_handles = HashMap::new();

                        // proceed to ping neighbors we need to replace
                        for (naddr, slot) in walk.replaced_neighbors.iter() {
                            let ping = StacksMessageType::Ping(PingData::new());
                            let msg = self.sign_for_peer(local_peer, chain_view, naddr, ping.clone())?;
                            let req_res = self.dispatch_send_message(naddr, msg, NEIGHBOR_REQUEST_TIMEOUT);
                            match req_res {
                                Ok(handle) => {
                                    ping_handles.insert((*naddr).clone(), handle);
                                }
                                Err(e) => {
                                    info!("Not connected to {:?}:{:?}: ({:?}", &naddr.addrbytes, naddr.port, &e);
                                }
                            };
                        }

                        walk.ping_existing_neighbors_begin(ping_handles);
                        Ok(next_neighbor_opt)
                    }
                }
            }
        };

        self.walk = my_walk;
        res
    }

    /// Make progress on completing pings to existing neighbors we'd like to replace.  If we
    /// finish, proceed to update our peer database.
    /// Return the result of the peer walk, and reset the walk state.
    pub fn walk_ping_existing_neighbors_try_finish(&mut self, chain_view: &BurnchainView) -> Result<Option<NeighborWalkResult>, net_error> {
        let mut my_walk = self.walk.take();
        let res = match my_walk {
            None => {
                panic!("Invalid neighbor-walk state reached -- cannot finish pinging stale neighbors when walk state is not instantiated");
            },
            Some(ref mut walk) => {
                let replaced_opt = {
                    let mut tx = self.peerdb.tx_begin()
                        .map_err(|_e| net_error::DBError)?;

                    let res = walk.ping_existing_neighbors_try_finish(&mut tx, self.burnchain.network_id)?;
                    tx.commit()
                        .map_err(|_e| net_error::DBError)?;

                    res
                };

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
                                    info!("Stepped to {:?}", &next_neighbor.addr);
                                    walk.reset(&next_neighbor.clone())
                                }
                                None => {
                                    // need to select a random new neighbor 
                                    let next_neighbors = self.get_random_neighbors(1, chain_view.burn_block_height)?;

                                    info!("Did not step to any neighbor; resetting walk to {:?}", &next_neighbors[0].addr);
                                    walk.reset(&next_neighbors[0])
                                }
                            }
                        };

                        Ok(Some(neighbor_walk_result))
                    }
                }
            }
        };
        self.walk = my_walk;
        res
    }

    /// Update the state of our peer graph walk.
    /// If we complete a walk, give back a walk result.
    /// Mask errors by restarting the graph walk.
    pub fn walk_peer_graph(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView) -> Option<NeighborWalkResult> {
        let walk_state =
            match self.walk {
                None => {
                    NeighborWalkState::GetNeighborsBegin
                },
                Some(ref walk) => {
                    walk.state.clone()
                }
            };

        let res = match walk_state {
            NeighborWalkState::GetNeighborsBegin => {
                self.walk_getneighbors_begin(local_peer, chain_view)
                    .and_then(|_r| Ok(None))
            },
            NeighborWalkState::GetNeighborsFinish => {
                self.walk_getneighbors_try_finish(local_peer, chain_view)
                    .and_then(|_r| Ok(None))
            },
            NeighborWalkState::GetHandshakesFinish => {
                self.walk_handshakes_try_finish(local_peer, chain_view)
                    .and_then(|r| Ok(None))
            },
            NeighborWalkState::GetNeighborsNeighborsFinish => {
                self.walk_getneighbors_neighbors_try_finish(local_peer, chain_view)
                    .and_then(|r| Ok(None))
            },
            NeighborWalkState::NeighborsPingFinish => {
                self.walk_ping_existing_neighbors_try_finish(chain_view)
            }
            _ => {
                panic!("Reached invalid walk state {:?}", walk_state);
            }
        };
        
        match res {
            Ok(walk_opt) => {
                walk_opt
            },
            Err(e) => {
                info!("Restarting neighbor walk with new random neighbors: {:?} => {:?}", walk_state, &e);
                self.walk = None;
                None
            }
        }
    }
}
