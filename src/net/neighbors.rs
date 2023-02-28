// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::cmp;
use std::collections::HashMap;
use std::collections::HashSet;
use std::mem;
use std::net::SocketAddr;

use rand::prelude::*;
use rand::thread_rng;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::*;
use stacks_common::util::log;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use crate::burnchains::Address;
use crate::burnchains::Burnchain;
use crate::burnchains::BurnchainView;
use crate::burnchains::PublicKey;
use crate::core::PEER_VERSION_TESTNET;
use crate::net::asn::ASEntry4;
use crate::net::codec::*;
use crate::net::connection::ConnectionOptions;
use crate::net::connection::ReplyHandleP2P;
use crate::net::db::LocalPeer;
use crate::net::db::PeerDB;
use crate::net::p2p::*;
use crate::net::Error as net_error;
use crate::net::Neighbor;
use crate::net::NeighborKey;
use crate::net::PeerAddress;
use crate::net::*;
use crate::util_lib::db::DBConn;
use crate::util_lib::db::DBTx;
use crate::util_lib::db::Error as db_error;

#[cfg(test)]
pub const NEIGHBOR_MINIMUM_CONTACT_INTERVAL: u64 = 0;
#[cfg(not(test))]
pub const NEIGHBOR_MINIMUM_CONTACT_INTERVAL: u64 = 600; // don't reach out to a frontier neighbor more than once every 10 minutes

pub const NEIGHBOR_REQUEST_TIMEOUT: u64 = 30; // default number of seconds an outstanding request for neighbors can take

pub const NUM_INITIAL_WALKS: u64 = 10; // how many unthrottled walks should we do when this peer starts up
pub const WALK_RETRY_COUNT: u64 = 10; // how many unthrottled walks should we attempt when the peer starts up
pub const WALK_MIN_DURATION: u64 = 20; // minimum number of steps a walk will take before we consider a reset
pub const WALK_MAX_DURATION: u64 = 40; // maximum number of steps a walk will take before we do a hard reset
pub const WALK_RESET_PROB: f64 = 0.05; // probability of a walk reset in-between the minimum and maximum duration
pub const WALK_STATE_TIMEOUT: u64 = 60; // how long the walk can remain in a single state before being reset

#[cfg(test)]
pub const WALK_RESET_INTERVAL: u64 = 60; // how long a walk can last
#[cfg(not(test))]
pub const WALK_RESET_INTERVAL: u64 = 600;

#[cfg(test)]
pub const PRUNE_FREQUENCY: u64 = 0; // how often we should consider pruning neighbors
#[cfg(not(test))]
pub const PRUNE_FREQUENCY: u64 = 43200; // how often we should consider pruning neighbors (twice a day)

#[cfg(test)]
pub const MAX_NEIGHBOR_BLOCK_DELAY: u64 = 25; // maximum delta between our current block height and the neighbor's that we will treat this neighbor as fresh
#[cfg(not(test))]
pub const MAX_NEIGHBOR_BLOCK_DELAY: u64 = 288; // maximum delta between our current block height and the neighbor's that we will treat this neighbor as fresh (prod)

#[cfg(test)]
pub const NEIGHBOR_WALK_INTERVAL: u64 = 0;
#[cfg(not(test))]
pub const NEIGHBOR_WALK_INTERVAL: u64 = 120; // seconds

#[derive(Debug, PartialEq, Clone)]
pub struct NeighborPingback {
    pub ts: u64,                 // when we discovered this neighbor to ping back
    pub peer_version: u32,       // peer version of neighbor to ping back
    pub network_id: u32,         // network ID of neighbor to ping back
    pub pubkey: StacksPublicKey, // public key of neighbor to ping back
}

impl Neighbor {
    pub fn empty(key: &NeighborKey, pubk: &Secp256k1PublicKey, expire_block: u64) -> Neighbor {
        Neighbor {
            addr: key.clone(),
            public_key: pubk.clone(),
            expire_block: expire_block,
            last_contact_time: 0,
            allowed: 0,
            denied: 0,
            asn: 0,
            org: 0,
            in_degree: 1,
            out_degree: 1,
        }
    }

    /// Update this peer in the DB.
    /// If there's no DB entry for this peer, then do nothing.
    /// Updates last-contact-time to now, since this is only called when we get back a Handshake
    pub fn save_update<'a>(&mut self, tx: &mut DBTx<'a>) -> Result<(), net_error> {
        self.last_contact_time = get_epoch_time_secs();
        PeerDB::update_peer(tx, &self).map_err(net_error::DBError)
    }

    /// Save to the peer DB, inserting it if it isn't already there.
    /// Updates last-contact-time to now, since this is only called when we get back a Handshake
    /// Return true if saved.
    /// Return false if not saved -- i.e. the frontier is full and we should try evicting neighbors.
    pub fn save<'a>(&mut self, tx: &mut DBTx<'a>) -> Result<bool, net_error> {
        self.last_contact_time = get_epoch_time_secs();
        PeerDB::try_insert_peer(tx, &self).map_err(net_error::DBError)
    }

    /// Attempt to load a neighbor from our peer DB, given its NeighborAddress reported by another
    /// peer.  Returns a neighbor in the peer DB if it matches the neighbor address and has a fresh public key
    /// (where "fresh" means "the public key hash matches the neighbor address")
    pub fn from_neighbor_address(
        conn: &DBConn,
        network_id: u32,
        block_height: u64,
        neighbor_address: &NeighborAddress,
    ) -> Result<Option<Neighbor>, net_error> {
        let peer_opt = PeerDB::get_peer(
            conn,
            network_id,
            &neighbor_address.addrbytes,
            neighbor_address.port,
        )
        .map_err(net_error::DBError)?;

        match peer_opt {
            None => {
                Ok(None) // unkonwn
            }
            Some(peer) => {
                // expired public key?
                if peer.expire_block < block_height {
                    Ok(None)
                } else {
                    let pubkey_160 = Hash160::from_node_public_key(&peer.public_key);
                    if pubkey_160 == neighbor_address.public_key_hash {
                        // we know this neighbor's key
                        Ok(Some(peer))
                    } else {
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
        let min = cmp::min(self.in_degree, self.out_degree);
        let max = cmp::max(self.in_degree, self.out_degree);
        let res = rng.gen_range(min, max + 1) as u64;
        if res == 0 {
            1
        } else {
            res
        }
    }
}

/// Struct for capturing the results of a walk.
/// -- reports newly-connected neighbors
/// -- reports neighbors we had trouble talking to.
/// The peer network will use this struct to clean out dead neighbors, and to keep the number of
/// _outgoing_ connections limited to NUM_NEIGHBORS.
#[derive(Clone, Debug)]
pub struct NeighborWalkResult {
    pub new_connections: HashSet<NeighborKey>,
    pub dead_connections: HashSet<NeighborKey>,
    pub broken_connections: HashSet<NeighborKey>,
    pub replaced_neighbors: HashSet<NeighborKey>,
    pub do_prune: bool,
}

impl NeighborWalkResult {
    pub fn new() -> NeighborWalkResult {
        NeighborWalkResult {
            new_connections: HashSet::new(),
            dead_connections: HashSet::new(),
            broken_connections: HashSet::new(),
            replaced_neighbors: HashSet::new(),
            do_prune: false,
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

    pub fn clear(&mut self) -> () {
        self.new_connections.clear();
        self.dead_connections.clear();
        self.broken_connections.clear();
        self.replaced_neighbors.clear();
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
    PingbackHandshakesBegin,
    PingbackHandshakesFinish,
    ReplacedNeighborsPingBegin,
    ReplacedNeighborsPingFinish,
    Finished,
}

#[derive(Debug)]
pub struct NeighborWalk {
    pub state: NeighborWalkState,
    pub events: HashSet<usize>,

    local_peer: LocalPeer, // gets instantiated as a copy from PeerNetwork
    chain_view: BurnchainView,

    connecting: HashMap<NeighborKey, usize>,

    // Addresses of neighbors resolved by GetNeighborsBegin/GetNeighborsFinish
    pending_neighbor_addrs: Option<Vec<NeighborAddress>>,

    // neighbor we're crawling, as well as its predecessor and successor
    prev_neighbor: Option<Neighbor>,
    cur_neighbor: Neighbor,
    next_neighbor: Option<Neighbor>,
    next_walk_outbound: bool,
    walk_outbound: bool, // whether or not we have an outbound connection to cur_neighbor
    neighbor_from_handshake: NeighborKey,

    // current neighbor's frontier
    pub frontier: HashMap<NeighborKey, Neighbor>,
    new_frontier: HashMap<NeighborKey, Neighbor>,

    // HandshakeBegin / HandshakeFinish: pending request to cur_neighbor to handshake
    handshake_request: Option<ReplyHandleP2P>,

    // GetNeighborsBegin / GetNeighborsFinish: pending request to cur_neighbor to get _its_ neighbors
    getneighbors_request: Option<ReplyHandleP2P>,

    // GetHandshakesBegin / GetHandshakesFinish: outstanding requests to handshake with our cur_neighbor's neighbors.
    resolved_handshake_neighbors: HashMap<NeighborAddress, Neighbor>,
    unresolved_handshake_neighbors: HashMap<NeighborAddress, ReplyHandleP2P>,
    handshake_neighbor_keys: Vec<NeighborKey>,

    // GetNeighborsNeighborsBegin / GetNeighborsNeighborsFinish:
    // outstanding requests to get the neighbors of our cur_neighbor's neighbors
    resolved_getneighbors_neighbors: HashMap<NeighborKey, Vec<NeighborAddress>>,
    unresolved_getneighbors_neighbors: HashMap<NeighborKey, ReplyHandleP2P>,

    // ReplacedNeighborsPingBegin / ReplacedNeighborsPingFinish:
    // outstanding requests to ping existing neighbors to be replaced in the frontier
    neighbor_replacements: HashMap<NeighborKey, Neighbor>,
    replaced_neighbors: HashMap<NeighborKey, u32>,
    unresolved_neighbor_pings: HashMap<NeighborKey, ReplyHandleP2P>,

    // PingbackHandshakesBegin / PingbackHandshakesFinish:
    // outstanding requests to new inbound peers
    network_pingbacks: HashMap<NeighborAddress, NeighborPingback>, // taken from the network at instantiation.  Maps address to (peer version, network ID, timestamp)
    pending_pingback_handshakes: HashMap<NeighborAddress, ReplyHandleP2P>,

    // neighbor walk result we build up incrementally
    result: NeighborWalkResult,

    // time that we started/finished the last walk
    walk_start_time: u64,
    walk_end_time: u64,

    // walk random-restart parameters
    walk_step_count: u64,   // how many times we've taken a step
    walk_min_duration: u64, // minimum steps we have to take before reset
    walk_max_duration: u64, // maximum steps we have to take before reset
    walk_reset_prob: f64,   // probability that we do a reset once the minimum duration is met
    walk_instantiation_time: u64,
    walk_reset_interval: u64, // how long a walk can last, in wall-clock time
    walk_state_time: u64,     // when the walk entered this state
    walk_state_timeout: u64,  // how long the walk can remain in this state
}

impl NeighborWalk {
    pub fn new(
        local_peer: LocalPeer,
        chain_view: BurnchainView,
        neighbor: &Neighbor,
        outbound: bool,
        pingbacks: HashMap<NeighborAddress, NeighborPingback>,
        connection_opts: &ConnectionOptions,
    ) -> NeighborWalk {
        NeighborWalk {
            local_peer: local_peer,
            chain_view: chain_view,

            state: NeighborWalkState::HandshakeBegin,
            events: HashSet::new(),

            connecting: HashMap::new(),
            pending_neighbor_addrs: None,

            prev_neighbor: None,
            cur_neighbor: neighbor.clone(),
            next_neighbor: None,
            next_walk_outbound: true,
            walk_outbound: outbound,
            neighbor_from_handshake: NeighborKey::empty(),

            frontier: HashMap::new(),
            new_frontier: HashMap::new(),

            handshake_request: None,
            getneighbors_request: None,

            resolved_handshake_neighbors: HashMap::new(),
            unresolved_handshake_neighbors: HashMap::new(),
            handshake_neighbor_keys: vec![],

            resolved_getneighbors_neighbors: HashMap::new(),
            unresolved_getneighbors_neighbors: HashMap::new(),

            neighbor_replacements: HashMap::new(),
            replaced_neighbors: HashMap::new(),
            unresolved_neighbor_pings: HashMap::new(),

            network_pingbacks: pingbacks,
            pending_pingback_handshakes: HashMap::new(),

            result: NeighborWalkResult::new(),

            walk_start_time: get_epoch_time_secs(),
            walk_end_time: 0,

            walk_step_count: 0,
            walk_min_duration: connection_opts.walk_min_duration,
            walk_max_duration: connection_opts.walk_max_duration,
            walk_reset_prob: connection_opts.walk_reset_prob,
            walk_instantiation_time: get_epoch_time_secs(),
            walk_reset_interval: connection_opts.walk_reset_interval,
            walk_state_time: get_epoch_time_secs(),
            walk_state_timeout: connection_opts.walk_state_timeout,
        }
    }

    /// Reset the walk with a new neighbor.
    /// Give back a report of the walk.
    /// Resets neighbor pointer.
    /// Clears out connections, but preserves state (frontier, result, etc.).
    pub fn reset(
        &mut self,
        next_neighbor: Neighbor,
        next_neighbor_outbound: bool,
    ) -> NeighborWalkResult {
        debug!(
            "{:?}: Walk reset to {} neighbor {:?}",
            &self.local_peer,
            if self.next_walk_outbound {
                "outbound"
            } else {
                "inbound"
            },
            &next_neighbor.addr
        );
        self.state = NeighborWalkState::HandshakeBegin;
        self.walk_state_time = get_epoch_time_secs();

        if self.cur_neighbor != next_neighbor {
            // moving on -- clear frontier
            self.frontier.clear();
        }

        self.prev_neighbor = Some(self.cur_neighbor.clone());
        self.cur_neighbor = next_neighbor;
        self.walk_outbound = next_neighbor_outbound;
        self.next_neighbor = None;

        self.clear_connections();
        self.new_frontier.clear();

        let result = self.result.clone();

        self.walk_end_time = get_epoch_time_secs();

        // leave self.frontier and self.result alone until the next walk.
        // (makes it so that at the end of the walk, we can query the result and frontier, which
        // get built up over successive passes of the state-machine)
        result
    }

    /// Clear the walk's intermittent walk state that gets repopulated on each pass through the
    /// state-machine.
    pub fn clear_state(&mut self) -> () {
        debug!("{:?}: Walk clear state", &self.local_peer);
        self.new_frontier.clear();
        self.result.clear();
    }

    /// Clear the walk's connection state
    pub fn clear_connections(&mut self) -> () {
        test_debug!("{:?}: Walk clear connections", &self.local_peer);
        self.events.clear();
        self.connecting.clear();
        self.pending_neighbor_addrs = None;

        self.handshake_request = None;
        self.getneighbors_request = None;

        self.resolved_handshake_neighbors.clear();
        self.unresolved_handshake_neighbors.clear();
        self.handshake_neighbor_keys.clear();

        self.resolved_getneighbors_neighbors.clear();
        self.unresolved_getneighbors_neighbors.clear();

        self.neighbor_replacements.clear();
        self.replaced_neighbors.clear();
        self.unresolved_neighbor_pings.clear();

        self.network_pingbacks.clear();
        self.pending_pingback_handshakes.clear();
    }

    /// Update the state of the walk
    /// (as a separate method for debugging purposes)
    fn set_state(&mut self, new_state: NeighborWalkState) -> () {
        test_debug!(
            "{:?}: Advance walk state: {:?} --> {:?} (after {} seconds)",
            &self.local_peer,
            &self.state,
            &new_state,
            get_epoch_time_secs().saturating_sub(self.walk_state_time)
        );
        self.state = new_state;
        self.connecting.clear();
        self.walk_state_time = get_epoch_time_secs()
    }

    /// Begin handshaking with our current neighbor
    pub fn handshake_begin(&mut self, req: ReplyHandleP2P) -> () {
        assert!(self.state == NeighborWalkState::HandshakeBegin);

        self.handshake_request = Some(req);

        // next state!
        self.set_state(NeighborWalkState::HandshakeFinish);
    }

    /// Finish handshaking with our current neighbor, thereby ensuring that it is connected
    pub fn handshake_try_finish(
        &mut self,
        network: &mut PeerNetwork,
        burn_stable_block_height: u64,
    ) -> Result<Option<Neighbor>, net_error> {
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
                if message.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY
                    < burn_stable_block_height
                {
                    debug!(
                        "{:?}: neighbor {:?} is still bootstrapping (on block {})",
                        &self.local_peer,
                        self.cur_neighbor.addr.clone(),
                        message.preamble.burn_stable_block_height
                    );
                    Err(net_error::StaleNeighbor)
                } else {
                    match message.payload {
                        StacksMessageType::HandshakeAccept(ref data) => {
                            // accepted! can proceed to ask for neighbors
                            // save knowledge to the peer DB if it was outbound
                            // (NOTE: an outbound neighbor should already be in
                            // the DB, since it's cur_neighbor)
                            debug!(
                                "{:?}: received HandshakeAccept from {} {:?}: {:?}",
                                &self.local_peer,
                                if self.walk_outbound {
                                    "outbound"
                                } else {
                                    "inbound"
                                },
                                &message.to_neighbor_key(
                                    &data.handshake.addrbytes,
                                    data.handshake.port
                                ),
                                &data.handshake
                            );

                            if self.walk_outbound {
                                // connected to a routable neighbor, so update its entry in the DB.
                                let mut tx = network.peerdb.tx_begin()?;
                                let mut neighbor_from_handshake = Neighbor::from_handshake(
                                    &mut tx,
                                    message.preamble.peer_version,
                                    message.preamble.network_id,
                                    &data.handshake,
                                )?;

                                // if the neighbor accidentally gave us a private IP address, then
                                // just use the one we used to contact it.  This can happen if the
                                // node is behind a load-balancer, or is doing port-forwarding,
                                // etc.
                                if neighbor_from_handshake.addr.addrbytes.is_in_private_range() {
                                    debug!("{:?}: outbound neighbor gave private IP address {:?}; assuming it meant {:?}", &self.local_peer, &neighbor_from_handshake.addr, &self.cur_neighbor.addr);
                                    neighbor_from_handshake.addr.addrbytes =
                                        self.cur_neighbor.addr.addrbytes.clone();
                                    neighbor_from_handshake.addr.port = self.cur_neighbor.addr.port;
                                }

                                let res = if neighbor_from_handshake.addr != self.cur_neighbor.addr
                                {
                                    // somehow, got a handshake from someone that _isn't_ cur_neighbor
                                    debug!("{:?}: got unsolicited (or bootstrapping) HandshakeAccept from outbound {:?} (expected {:?})", 
                                               &self.local_peer,
                                               &neighbor_from_handshake.addr,
                                               &self.cur_neighbor.addr);

                                    Err(net_error::PeerNotConnected)
                                } else {
                                    // this is indeed cur_neighbor
                                    self.cur_neighbor
                                        .handshake_update(&mut tx, &data.handshake)?;
                                    self.cur_neighbor.save_update(&mut tx)?;

                                    debug!(
                                        "{:?}: Connected with {:?}",
                                        &self.local_peer, &self.cur_neighbor.addr
                                    );
                                    self.new_frontier.insert(
                                        self.cur_neighbor.addr.clone(),
                                        self.cur_neighbor.clone(),
                                    );

                                    // advance state!
                                    self.set_state(NeighborWalkState::GetNeighborsBegin);
                                    Ok(Some(self.cur_neighbor.clone()))
                                };
                                tx.commit()?;

                                self.neighbor_from_handshake = neighbor_from_handshake.addr;
                                res
                            } else {
                                // connected to an unroutable neighbor, so
                                // don't save to DB (but do update frontier)
                                let neighbor_from_handshake = Neighbor::from_handshake(
                                    &network.peerdb.conn(),
                                    message.preamble.peer_version,
                                    message.preamble.network_id,
                                    &data.handshake,
                                )?;
                                debug!(
                                    "{:?}: Connected with inbound non-frontier neighbor {:?}: {:?}",
                                    &self.local_peer,
                                    &self.cur_neighbor.addr,
                                    &neighbor_from_handshake.addr
                                );

                                self.neighbor_from_handshake = neighbor_from_handshake.addr;

                                // advance state!
                                self.set_state(NeighborWalkState::GetNeighborsBegin);
                                Ok(Some(self.cur_neighbor.clone()))
                            }
                        }
                        StacksMessageType::HandshakeReject => {
                            // told to bugger off
                            Err(net_error::PeerNotConnected)
                        }
                        StacksMessageType::Nack(_) => {
                            // something's wrong on our end (we're using a new key that they don't yet
                            // know about, or something)
                            Err(net_error::PeerNotConnected)
                        }
                        _ => {
                            // invalid message
                            debug!(
                                "{:?}: Got out-of-sequence message from {:?}",
                                &self.local_peer, &self.cur_neighbor.addr
                            );
                            self.result.add_broken(self.cur_neighbor.addr.clone());
                            Err(net_error::InvalidMessage)
                        }
                    }
                }
            }
            Err(req_res) => {
                match req_res {
                    Ok(same_req) => {
                        // try again
                        self.handshake_request = Some(same_req);
                        Ok(None)
                    }
                    Err(e) => {
                        // disconnected
                        debug!(
                            "{:?}: Failed to get Handshake reply from {:?}: {:?}",
                            &self.local_peer, &self.cur_neighbor.addr, &e
                        );
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
    fn lookup_stale_neighbors(
        dbconn: &DBConn,
        network_id: u32,
        block_height: u64,
        addrs: &Vec<NeighborAddress>,
    ) -> Result<(HashMap<NeighborAddress, Neighbor>, Vec<NeighborAddress>), net_error> {
        let mut to_resolve = vec![];
        let mut resolved: HashMap<NeighborAddress, Neighbor> = HashMap::new();
        for naddr in addrs {
            let neighbor_opt =
                Neighbor::from_neighbor_address(dbconn, network_id, block_height, naddr)?;
            match neighbor_opt {
                None => {
                    // need to resolve this one, but don't talk to it if we did so recently (even
                    // if we have stale information for it -- the remote node could be trying to trick
                    // us into DDoS'ing this node).
                    let peer_opt =
                        PeerDB::get_peer(dbconn, network_id, &naddr.addrbytes, naddr.port)
                            .map_err(net_error::DBError)?;

                    match peer_opt {
                        None => {
                            // okay, we really don't know about this neighbor
                            to_resolve.push((*naddr).clone());
                        }
                        Some(n) => {
                            // we know about this neighbor, but its key didn't match the
                            // neighboraddress.  Only try to re-connect with it if we haven't done
                            // so recently, so a rogue neighbor can't force us to DDoS another
                            // peer.
                            if n.last_contact_time + NEIGHBOR_MINIMUM_CONTACT_INTERVAL
                                < get_epoch_time_secs()
                            {
                                to_resolve.push((*naddr).clone());
                            } else {
                                // recently contacted
                                resolved.insert(naddr.clone(), n);
                            }
                        }
                    }
                }
                Some(neighbor) => {
                    if neighbor.last_contact_time + NEIGHBOR_MINIMUM_CONTACT_INTERVAL
                        < get_epoch_time_secs()
                    {
                        // stale
                        to_resolve.push((*naddr).clone());
                    } else {
                        // our copy is still fresh
                        resolved.insert(naddr.clone(), neighbor);
                    }
                }
            }
        }
        Ok((resolved, to_resolve))
    }

    /// Select neighbors that are routable, and ignore ones that are not.
    /// TODO: expand if we ever want to filter by unroutable network class or something
    fn filter_sensible_neighbors(neighbors: Vec<NeighborAddress>) -> Vec<NeighborAddress> {
        let mut ret = vec![];
        for neighbor in neighbors.into_iter() {
            if neighbor.addrbytes.is_anynet() {
                continue;
            }
            ret.push(neighbor);
        }
        ret
    }

    /// Try to finish the getneighbors request to cur_neighbor
    /// Returns the list of neighbors we need to resolve
    /// Return None if we're not done yet, or haven't started yet.
    pub fn getneighbors_try_finish(
        &mut self,
        network: &mut PeerNetwork,
        block_height: u64,
    ) -> Result<Option<Vec<NeighborAddress>>, net_error> {
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
                    test_debug!(
                        "{:?}: neighbor {:?} is still bootstrapping (on block {})",
                        &self.local_peer,
                        &self.cur_neighbor.addr,
                        message.preamble.burn_block_height
                    );
                    return Err(net_error::StaleNeighbor);
                }
                match message.payload {
                    StacksMessageType::Neighbors(ref data) => {
                        debug!(
                            "{:?}: Got Neighbors from {:?}: {:?}",
                            &self.local_peer, &self.cur_neighbor.addr, data.neighbors
                        );
                        let neighbors =
                            NeighborWalk::filter_sensible_neighbors(data.neighbors.clone());
                        let (mut found, to_resolve) = NeighborWalk::lookup_stale_neighbors(
                            network.peerdb.conn(),
                            message.preamble.network_id,
                            block_height,
                            &neighbors,
                        )?;

                        for (_naddr, neighbor) in found.drain() {
                            self.new_frontier
                                .insert(neighbor.addr.clone(), neighbor.clone());
                            self.frontier
                                .insert(neighbor.addr.clone(), neighbor.clone());
                        }

                        Ok(Some(to_resolve))
                    }
                    StacksMessageType::Nack(ref data) => {
                        debug!(
                            "{:?}: Neighbor {:?} NACK'ed GetNeighbors with code {:?}",
                            &self.local_peer, &self.cur_neighbor.addr, data.error_code
                        );
                        self.result.add_broken(self.cur_neighbor.addr.clone());
                        Err(net_error::ConnectionBroken)
                    }
                    _ => {
                        // invalid message
                        debug!(
                            "{:?}: Got out-of-sequence message from {:?}",
                            &self.local_peer, &self.cur_neighbor.addr
                        );
                        self.result.add_broken(self.cur_neighbor.addr.clone());
                        Err(net_error::InvalidMessage)
                    }
                }
            }
            Err(req_res) => {
                match req_res {
                    Ok(same_req) => {
                        // try again
                        self.getneighbors_request = Some(same_req);
                        Ok(None)
                    }
                    Err(e) => {
                        // disconnected
                        debug!(
                            "{:?}: Failed to get GetNeighbors reply from {:?}: {:?}",
                            &self.local_peer, &self.cur_neighbor.addr, &e
                        );
                        self.result.add_dead(self.cur_neighbor.addr.clone());
                        Err(e)
                    }
                }
            }
        }
    }

    /// Begin getting the neighors of cur_neighbor's neighbors.
    /// ReplyHandleP2Ps should be reply handles for Handshake requests.
    pub fn neighbor_handshakes_begin(&mut self) -> () {
        assert!(self.state == NeighborWalkState::GetHandshakesBegin);

        // advance state!
        self.set_state(NeighborWalkState::GetHandshakesFinish);
    }

    /// Given a neighbor we tried to insert into the peer database, find one of the existing
    /// neighbors it collided with.  Return its slot in the peer db.
    fn find_replaced_neighbor_slot(
        conn: &DBConn,
        nk: &NeighborKey,
    ) -> Result<Option<u32>, net_error> {
        let mut slots = PeerDB::peer_slots(conn, nk.network_id, &nk.addrbytes, nk.port)
            .map_err(net_error::DBError)?;

        if slots.len() == 0 {
            // not present
            return Ok(None);
        }

        let mut rng = thread_rng();
        slots.shuffle(&mut rng);

        for slot in slots {
            let peer_opt =
                PeerDB::get_peer_at(conn, nk.network_id, slot).map_err(net_error::DBError)?;

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

    /// Add a neighbor or schedule it to be pinged since it's up for replacement.
    /// Returns (was-new?, neighbor)
    fn add_or_schedule_replace_neighbor<'a>(
        &mut self,
        tx: &mut DBTx<'a>,
        block_height: u64,
        naddr: &NeighborAddress,
        peer_version: u32,
        network_id: u32,
        handshake: &HandshakeData,
    ) -> Result<(bool, Neighbor), net_error> {
        let mut neighbor_from_handshake =
            Neighbor::from_handshake(tx, peer_version, network_id, handshake)?;
        let neighbor_opt = Neighbor::from_neighbor_address(tx, network_id, block_height, naddr)?;
        match neighbor_opt {
            Some(neighbor) => {
                debug!(
                    "{:?}: already know about {:?}",
                    &self.local_peer, &neighbor.addr
                );
                neighbor_from_handshake.save_update(tx)?;

                // seen this neighbor before
                Ok((false, neighbor_from_handshake))
            }
            None => {
                debug!(
                    "{:?}: new neighbor {:?}",
                    &self.local_peer, &neighbor_from_handshake.addr
                );

                // didn't know about this neighbor yet. Try to add it.
                let added = neighbor_from_handshake.save(tx)?;
                if !added {
                    // no more room in the db.  See if we can add it by
                    // evicting an existing neighbor once we're done with this
                    // walk.
                    let replaced_neighbor_slot_opt = NeighborWalk::find_replaced_neighbor_slot(
                        tx,
                        &neighbor_from_handshake.addr,
                    )?;
                    match replaced_neighbor_slot_opt {
                        Some(slot) => {
                            // if this peer isn't allowed or denied, then consider
                            // replacing.  Otherwise, keep the local configuration's preference.
                            if !neighbor_from_handshake.is_denied()
                                && !neighbor_from_handshake.is_allowed()
                            {
                                self.neighbor_replacements.insert(
                                    neighbor_from_handshake.addr.clone(),
                                    neighbor_from_handshake.clone(),
                                );
                                self.replaced_neighbors
                                    .insert(neighbor_from_handshake.addr.clone(), slot);
                            }
                        }
                        None => {
                            // shouldn't happen
                        }
                    };
                }

                // neighbor was new
                Ok((true, neighbor_from_handshake))
            }
        }
    }

    /// Try to finish getting handshakes from cur_neighbors' neighbors.
    /// Once all handles resolve, return the list of neighbors that we can contact.
    /// As a side-effect of handshaking with all these peers, our PeerDB instance will be expanded
    /// with the addresses, public keys, public key expiries of these neighbors -- i.e. this method grows
    /// our frontier.
    pub fn neighbor_handshakes_try_finish(
        &mut self,
        network: &mut PeerNetwork,
        block_height: u64,
        stable_block_height: u64,
    ) -> Result<Option<Vec<NeighborKey>>, net_error> {
        assert!(self.state == NeighborWalkState::GetHandshakesFinish);

        // see if we got any replies
        let mut new_unresolved_handshakes = HashMap::new();
        let mut unresolved_handshake_neighbors =
            mem::replace(&mut self.unresolved_handshake_neighbors, HashMap::new());

        test_debug!(
            "{:?}: Try to finish {} in-flight handshakes with neighbors-of-neighbor {:?}",
            &self.local_peer,
            unresolved_handshake_neighbors.len(),
            &self.cur_neighbor.addr
        );
        for (naddr, mut rh) in unresolved_handshake_neighbors.drain() {
            if let Err(_e) = network.saturate_p2p_socket(rh.get_event_id(), &mut rh) {
                self.result.add_dead(NeighborKey::from_neighbor_address(
                    network.peer_version,
                    self.local_peer.network_id,
                    &naddr,
                ));
                continue;
            }

            let res = rh.try_send_recv();
            let rh_naddr = naddr.clone(); // used below
            let new_rh = match res {
                Ok(message) => {
                    // if the neighbor is still bootstrapping, we're done
                    if message.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY
                        < stable_block_height
                    {
                        debug!(
                            "{:?}: Remote neighbor {:?} is still bootstrapping (at block {})",
                            &self.local_peer, &rh_naddr, message.preamble.burn_stable_block_height
                        );
                    } else {
                        match message.payload {
                            StacksMessageType::HandshakeAccept(ref data) => {
                                debug!(
                                    "{:?}: Got HandshakeAccept from {:?}",
                                    &self.local_peer, &naddr
                                );

                                // NOTE: even if cur_neighbor is an inbound neighbor, the neighbors
                                // of cur_neighbor that we could handshake with are necessarily
                                // outbound connections.  So, save them all.
                                // Do we know about this peer already?
                                let mut tx = network.peerdb.tx_begin()?;
                                let (new, neighbor) = self.add_or_schedule_replace_neighbor(
                                    &mut tx,
                                    block_height,
                                    &naddr,
                                    message.preamble.peer_version,
                                    message.preamble.network_id,
                                    &data.handshake,
                                )?;
                                if new {
                                    // neighbor was new
                                    self.new_frontier
                                        .insert(neighbor.addr.clone(), neighbor.clone());
                                } else {
                                    // frontier maintenance
                                    self.frontier
                                        .insert(neighbor.addr.clone(), neighbor.clone());
                                }

                                self.resolved_handshake_neighbors.insert(naddr, neighbor);
                                tx.commit()?;
                            }
                            StacksMessageType::HandshakeReject => {
                                // remote peer doesn't want to talk to us
                                debug!(
                                    "{:?}: Neighbor {:?} rejected our handshake",
                                    &self.local_peer, &naddr
                                );
                                self.result.add_dead(NeighborKey::from_neighbor_address(
                                    message.preamble.peer_version,
                                    message.preamble.network_id,
                                    &naddr,
                                ));
                            }
                            StacksMessageType::Nack(ref data) => {
                                // remote peer nope'd us
                                debug!("{:?}: Neighbor {:?} NACK'ed our handshake with error code {:?}", &self.local_peer, &naddr, data.error_code);
                                self.result.add_dead(NeighborKey::from_neighbor_address(
                                    message.preamble.peer_version,
                                    message.preamble.network_id,
                                    &naddr,
                                ));
                            }
                            _ => {
                                // protocol violation
                                debug!(
                                    "{:?}: Neighbor {:?} replied an out-of-sequence message",
                                    &self.local_peer, &naddr
                                );
                                self.result.add_broken(NeighborKey::from_neighbor_address(
                                    message.preamble.peer_version,
                                    message.preamble.network_id,
                                    &naddr,
                                ));
                            }
                        };
                    }
                    None
                }
                Err(req_res) => {
                    match req_res {
                        Ok(same_req) => {
                            // try again
                            Some(same_req)
                        }
                        Err(e) => {
                            // connection broken.
                            // Don't try to contact this node again.
                            debug!(
                                "{:?}: Failed to handshake with {:?}: {:?}",
                                &self.local_peer, naddr, &e
                            );
                            self.result.add_dead(NeighborKey::from_neighbor_address(
                                network.peer_version,
                                self.local_peer.network_id,
                                &naddr,
                            ));
                            None
                        }
                    }
                }
            };
            match new_rh {
                Some(rh) => {
                    new_unresolved_handshakes.insert(rh_naddr, rh);
                }
                None => {
                    debug!(
                        "{:?}: Finished handshaking with neighbor-of-neighbor {:?}",
                        &self.local_peer, &rh_naddr
                    );
                }
            };
        }

        // save unresolved handshakes for next time
        self.unresolved_handshake_neighbors = new_unresolved_handshakes;
        if self.unresolved_handshake_neighbors.len() == 0 {
            // finished handshaking!  find neighbors that accepted
            let mut neighbor_keys = vec![];

            // update our frontier knowledge
            for (nkey, new_neighbor) in self.new_frontier.drain() {
                debug!(
                    "{:?}: Add to frontier of {:?}: {:?}",
                    &self.local_peer, &self.cur_neighbor.addr, &nkey
                );
                self.frontier.insert(nkey.clone(), new_neighbor);

                if nkey.addrbytes != self.cur_neighbor.addr.addrbytes
                    || nkey.port != self.cur_neighbor.addr.port
                {
                    neighbor_keys.push(nkey.clone());
                }
            }

            self.new_frontier.clear();

            // advance state!
            self.set_state(NeighborWalkState::GetNeighborsNeighborsBegin);
            Ok(Some(neighbor_keys))
        } else {
            // still handshaking
            Ok(None)
        }
    }

    /// Begin asking remote neighbors for their neighbors in order to estimate cur_neighbor's
    /// in-degree.
    pub fn getneighbors_neighbors_begin(&mut self) -> () {
        assert!(self.state == NeighborWalkState::GetNeighborsNeighborsBegin);

        // advance state!
        self.set_state(NeighborWalkState::GetNeighborsNeighborsFinish);
    }

    /// Try to finish getting the neighbors from cur_neighbors' neighbors
    /// Once all handles resolve, return the current neighbor.
    pub fn getneighbors_neighbors_try_finish(
        &mut self,
        network: &mut PeerNetwork,
        burn_stable_block_height: u64,
    ) -> Result<Option<Neighbor>, net_error> {
        assert!(self.state == NeighborWalkState::GetNeighborsNeighborsFinish);

        // see if we got any replies
        let mut new_unresolved_neighbors = HashMap::new();
        for (nkey, mut rh) in self.unresolved_getneighbors_neighbors.drain() {
            let rh_nkey = nkey.clone(); // used below
            if let Err(_e) = network.saturate_p2p_socket(rh.get_event_id(), &mut rh) {
                self.result.add_dead(rh_nkey);
                continue;
            }

            let res = rh.try_send_recv();
            let new_rh = match res {
                Ok(message) => {
                    // only consider this neighbor if it's _not_ bootstrapping
                    if message.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY
                        >= burn_stable_block_height
                    {
                        match message.payload {
                            StacksMessageType::Neighbors(ref data) => {
                                debug!(
                                    "{:?}: Got Neighbors from {:?}: {:?}",
                                    &self.local_peer, &nkey, &data.neighbors
                                );
                                let neighbors =
                                    NeighborWalk::filter_sensible_neighbors(data.neighbors.clone());
                                self.resolved_getneighbors_neighbors.insert(nkey, neighbors);
                            }
                            StacksMessageType::Nack(ref data) => {
                                // not broken; likely because it hasn't gotten to processing our
                                // handshake yet.  We'll just ignore it.
                                debug!(
                                    "{:?}: Neighbor {:?} NACKed with code {:?}",
                                    &self.local_peer, &nkey, data.error_code
                                );
                            }
                            _ => {
                                // unexpected reply
                                debug!("{:?}: Neighbor {:?} replied an out-of-sequence message (type {}); assuming broken", &self.local_peer, &nkey, message.get_message_name());
                                self.result.add_broken(nkey);
                            }
                        }
                    }
                    None
                }
                Err(req_res) => {
                    match req_res {
                        Ok(nrh) => {
                            // try again
                            Some(nrh)
                        }
                        Err(e) => {
                            // disconnected from peer
                            debug!(
                                "{:?}: Failed to get neighbors from {:?} ({})",
                                &self.local_peer, &nkey, e
                            );
                            self.result.add_dead(nkey);
                            None
                        }
                    }
                }
            };
            match new_rh {
                Some(rh) => {
                    new_unresolved_neighbors.insert(rh_nkey, rh);
                }
                None => {}
            };
        }

        // try these again
        self.unresolved_getneighbors_neighbors = new_unresolved_neighbors;

        if self.unresolved_getneighbors_neighbors.len() == 0 {
            // finished!  build up frontier's in-degree estimation, plus ourselves
            self.cur_neighbor.in_degree = 1;
            self.cur_neighbor.out_degree = self.frontier.len() as u32;

            for (_, neighbor_list) in self.resolved_getneighbors_neighbors.iter() {
                for na in neighbor_list {
                    if na.addrbytes == self.cur_neighbor.addr.addrbytes
                        && na.port == self.cur_neighbor.addr.port
                    {
                        self.cur_neighbor.in_degree += 1;
                    }
                }
            }

            // only save if the neighbor is routable from us
            if self.walk_outbound {
                // remember this peer's in/out degree estimates
                debug!(
                    "{:?}: In/Out degree of current neighbor {:?} is {}/{}",
                    &self.local_peer,
                    &self.cur_neighbor.addr,
                    self.cur_neighbor.in_degree,
                    self.cur_neighbor.out_degree
                );

                let mut tx = network.peerdb.tx_begin()?;
                self.cur_neighbor.save_update(&mut tx)?;
                tx.commit()?;
            }

            // advance state!
            self.set_state(NeighborWalkState::PingbackHandshakesBegin);
            Ok(Some(self.cur_neighbor.clone()))
        } else {
            // still working
            debug!(
                "{:?}: still waiting for {} Neighbors replies",
                &self.local_peer,
                self.unresolved_getneighbors_neighbors.len()
            );
            Ok(None)
        }
    }

    /// Pick a random neighbor from the frontier, excluding an optional given neighbor
    fn pick_random_neighbor(
        frontier: &HashMap<NeighborKey, Neighbor>,
        exclude: Option<&Neighbor>,
    ) -> Option<Neighbor> {
        let mut rnd = thread_rng();

        let sample = rnd.gen_range(0, frontier.len());
        let mut count = 0;

        for (nk, n) in frontier.iter() {
            count += match exclude {
                None => 1,
                Some(ref e) => {
                    if (*e).addr == *nk {
                        0
                    } else {
                        1
                    }
                }
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
    ///
    /// This method updates self.next_neighbor with a new neighbor to step to, or None to restart.
    pub fn step(&mut self, peerdb_conn: &DBConn) -> () {
        test_debug!(
            "{:?}: execute neighbor step from {:?}",
            &self.local_peer,
            &self.cur_neighbor.addr
        );

        let mut rnd = thread_rng();

        // step to a node in cur_neighbor's frontier, per MHRWDA
        let next_neighbor_opt = if self.frontier.len() == 0 {
            // just started the walk, so stay here for now -- we don't yet know the neighbor's
            // frontier.
            if self.walk_outbound {
                Some(self.cur_neighbor.clone())
            } else {
                // inbound; reset
                None
            }
        } else {
            let next_neighbor = NeighborWalk::pick_random_neighbor(&self.frontier, None)
                .expect("BUG: empty frontier size"); // won't panic since self.frontier.len() > 0
            let walk_prob: f64 = rnd.gen();
            if walk_prob
                < fmin!(
                    1.0,
                    NeighborWalk::degree_ratio(peerdb_conn, &self.cur_neighbor, &next_neighbor)
                )
            {
                match self.prev_neighbor {
                    Some(ref prev_neighbor) => {
                        // will take a step
                        if prev_neighbor.addr == next_neighbor.addr {
                            // oops, backtracked.  Try to pick a different neighbor, if possible.
                            if self.frontier.len() == 1 {
                                // no other choices. will need to reset this walk.
                                None
                            } else {
                                // have alternative choices, so instead of backtracking, we'll delay
                                // acceptance by probabilistically deciding to step to an alternative
                                // instead of backtracking.
                                let alt_next_neighbor = NeighborWalk::pick_random_neighbor(
                                    &self.frontier,
                                    Some(&prev_neighbor),
                                )
                                .expect("BUG: empty frontier size");
                                let alt_prob: f64 = rnd.gen();

                                let cur_to_alt = NeighborWalk::degree_ratio(
                                    peerdb_conn,
                                    &self.cur_neighbor,
                                    &alt_next_neighbor,
                                );
                                let prev_to_cur = NeighborWalk::degree_ratio(
                                    peerdb_conn,
                                    &prev_neighbor,
                                    &self.cur_neighbor,
                                );
                                let trans_prob = fmin!(
                                    fmin!(1.0, cur_to_alt * cur_to_alt),
                                    fmax!(1.0, prev_to_cur * prev_to_cur)
                                );

                                if alt_prob < fmin!(1.0, trans_prob) {
                                    // go to alt peer instead
                                    Some(alt_next_neighbor)
                                } else {
                                    // backtrack.
                                    Some(next_neighbor)
                                }
                            }
                        } else {
                            // not backtracking.  Take a step.
                            Some(next_neighbor)
                        }
                    }
                    None => {
                        // not backtracking.  Take a step.
                        Some(next_neighbor)
                    }
                }
            } else {
                // will not take a step
                Some(self.cur_neighbor.clone())
            }
        };

        if let Some(ref neighbor) = next_neighbor_opt {
            debug!("{:?}: Walk steps to {:?}", &self.local_peer, &neighbor.addr);
        } else {
            debug!(
                "{:?}: Walk will not step to a new neighbor",
                &self.local_peer
            );
        }

        self.next_neighbor = next_neighbor_opt;
        if let Some(ref next_neighbor) = self.next_neighbor {
            if *next_neighbor == self.cur_neighbor {
                self.next_walk_outbound = self.walk_outbound;
            } else {
                // can only step to outbound neighbors
                self.next_walk_outbound = true;
            }
        }
    }

    /// Start to connect to newly-discovered inbound peers
    pub fn pingback_handshakes_begin(&mut self) -> () {
        // caller will have already populated the pending_pingback_handshakes hashmap
        assert!(self.state == NeighborWalkState::PingbackHandshakesBegin);

        self.set_state(NeighborWalkState::PingbackHandshakesFinish);
    }

    /// Finish up connecting to newly-discovered inbound peers
    pub fn pingback_handshakes_try_finish(
        &mut self,
        network: &mut PeerNetwork,
        block_height: u64,
        stable_block_height: u64,
    ) -> Result<bool, net_error> {
        assert!(self.state == NeighborWalkState::PingbackHandshakesFinish);

        // see if we got any replies
        let mut new_pingback_handshakes = HashMap::new();
        let mut pending_pingback_handshakes =
            mem::replace(&mut self.pending_pingback_handshakes, HashMap::new());
        for (naddr, mut rh) in pending_pingback_handshakes.drain() {
            if let Err(_e) = network.saturate_p2p_socket(rh.get_event_id(), &mut rh) {
                continue;
            }

            let rh_naddr = naddr.clone();
            let res = rh.try_send_recv();
            let new_rh = match res {
                Ok(message) => {
                    if message.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY
                        < stable_block_height
                    {
                        debug!("{:?}: Remote pingback'ed neighbor {:?} is still bootstrapping (at block {})", &self.local_peer, &rh_naddr, message.preamble.burn_stable_block_height);
                    } else {
                        // if we got back a HandshakeAccept, and it's on the same chain as us, we're good!
                        match message.payload {
                            StacksMessageType::HandshakeAccept(ref data) => {
                                debug!("{:?}: received HandshakeAccept from peer {:?}; now known to be routable from us", &self.local_peer, &message.to_neighbor_key(&data.handshake.addrbytes, data.handshake.port));

                                // must have the same key; otherwise don't add
                                let neighbor_pubkey_hash = Hash160::from_node_public_key_buffer(
                                    &data.handshake.node_public_key,
                                );
                                if neighbor_pubkey_hash != naddr.public_key_hash {
                                    debug!("{:?}: Neighbor {:?} had an unexpected pubkey hash: expected {:?} != {:?}",
                                           &self.local_peer, &message.to_neighbor_key(&data.handshake.addrbytes, data.handshake.port), &naddr.public_key_hash, &neighbor_pubkey_hash);
                                    continue;
                                }

                                let mut tx = network.peerdb.tx_begin()?;
                                self.add_or_schedule_replace_neighbor(
                                    &mut tx,
                                    block_height,
                                    &naddr,
                                    message.preamble.peer_version,
                                    message.preamble.network_id,
                                    &data.handshake,
                                )?;
                                tx.commit()?;
                            }
                            _ => {
                                debug!("{:?}: Neighbor {:?} replied {:?} instead of pingback handshake", &self.local_peer, &rh_naddr, &message.get_message_name());
                            }
                        }
                    }
                    None
                }
                Err(req_res) => {
                    match req_res {
                        Ok(nrh) => {
                            // try again
                            Some(nrh)
                        }
                        Err(e) => {
                            // disconnected from peer
                            debug!(
                                "{:?}: Failed to connect to {:?} ({})",
                                &self.local_peer, &rh_naddr, &e
                            );
                            None
                        }
                    }
                }
            };
            match new_rh {
                Some(rh) => {
                    new_pingback_handshakes.insert(rh_naddr, rh);
                }
                None => {}
            };
        }

        self.pending_pingback_handshakes = new_pingback_handshakes;
        if self.pending_pingback_handshakes.len() == 0 {
            // done!
            self.set_state(NeighborWalkState::ReplacedNeighborsPingBegin);
            Ok(true)
        } else {
            // not done!
            Ok(false)
        }
    }

    /// Ping existing neighbors that would be replaced by the discovery of new neighbors (i.e.
    /// through getting the neighbors of our neighbor, or though pingbacks)
    pub fn ping_existing_neighbors_begin(
        &mut self,
        network_handles: HashMap<NeighborKey, ReplyHandleP2P>,
    ) -> () {
        assert!(self.state == NeighborWalkState::ReplacedNeighborsPingBegin);

        self.unresolved_neighbor_pings = network_handles;

        // advance state!
        self.set_state(NeighborWalkState::ReplacedNeighborsPingFinish);
    }

    // try to finish pinging/handshaking all exisitng neighbors.
    // if the remote neighbor does _not_ respond to our ping, then replace it.
    // Return the list of _evicted_ neighbors.
    pub fn ping_existing_neighbors_try_finish(
        &mut self,
        network: &mut PeerNetwork,
    ) -> Result<Option<HashSet<NeighborKey>>, net_error> {
        assert!(self.state == NeighborWalkState::ReplacedNeighborsPingFinish);

        let mut new_unresolved_neighbor_pings = HashMap::new();

        for (nkey, mut rh) in self.unresolved_neighbor_pings.drain() {
            let rh_nkey = nkey.clone(); // used below
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
                            test_debug!(
                                "{:?}: received HandshakeAccept from {:?}",
                                &self.local_peer,
                                &message.to_neighbor_key(
                                    &data.handshake.addrbytes,
                                    data.handshake.port
                                )
                            );

                            let mut tx = network.peerdb.tx_begin()?;
                            let mut neighbor_from_handshake = Neighbor::from_handshake(
                                &mut tx,
                                message.preamble.peer_version,
                                message.preamble.network_id,
                                &data.handshake,
                            )?;
                            neighbor_from_handshake.save_update(&mut tx)?;
                            tx.commit()?;

                            // not going to replace
                            if self
                                .replaced_neighbors
                                .contains_key(&neighbor_from_handshake.addr)
                            {
                                test_debug!(
                                    "{:?}: will NOT replace {:?}",
                                    &self.local_peer,
                                    &neighbor_from_handshake.addr
                                );
                                self.replaced_neighbors
                                    .remove(&neighbor_from_handshake.addr);
                            }
                        }
                        StacksMessageType::Nack(ref data) => {
                            // evict
                            debug!(
                                "{:?}: Neighbor {:?} NACK'ed Handshake with code {:?}; will evict",
                                &self.local_peer, nkey, data.error_code
                            );
                            self.result.add_broken(nkey.clone());
                        }
                        _ => {
                            // unexpected reply -- this peer is misbehaving and should be replaced
                            debug!("{:?}: Neighbor {:?} replied an out-of-sequence message (type {}); will replace", &self.local_peer, &nkey, message.get_message_name());
                            self.result.add_broken(nkey);
                        }
                    };
                    None
                }
                Err(req_res) => {
                    match req_res {
                        Ok(nrh) => {
                            // try again
                            Some(nrh)
                        }
                        Err(_) => {
                            // disconnected from peer already -- we can replace it
                            debug!(
                                "{:?}: Neighbor {:?} could not be pinged; will replace",
                                &self.local_peer, &nkey
                            );
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
                }
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
                        if PeerDB::is_address_denied(&mut tx, &replacement.addr.addrbytes)? {
                            debug!(
                                "{:?}: Will not replace {:?} with {:?} -- is denied",
                                &self.local_peer, &replaced.addr, &replacement.addr
                            );
                        } else {
                            debug!(
                                "{:?}: Replace {:?} with {:?}",
                                &self.local_peer, &replaced.addr, &replacement.addr
                            );

                            PeerDB::insert_or_replace_peer(&mut tx, &replacement, *slot)?;
                            self.result.add_replaced(replaced.addr.clone());
                        }
                    }
                    None => {}
                }
            }
            tx.commit()?;

            // advance state!
            self.set_state(NeighborWalkState::Finished);
            Ok(Some(self.result.replaced_neighbors.clone()))
        } else {
            // still have more work to do
            self.unresolved_neighbor_pings = new_unresolved_neighbor_pings;
            Ok(None)
        }
    }
}

impl PeerNetwork {
    /// Get some initial fresh random neighbor(s) to crawl,
    /// given the number of neighbors and current burn block height
    pub fn walk_get_random_neighbors(
        &self,
        num_neighbors: u64,
        block_height: u64,
    ) -> Result<Vec<Neighbor>, net_error> {
        let cur_epoch = self.get_current_epoch();
        let neighbors = PeerDB::get_random_walk_neighbors(
            &self.peerdb.conn(),
            self.local_peer.network_id,
            cur_epoch.network_epoch,
            num_neighbors as u32,
            block_height,
        )
        .map_err(net_error::DBError)?;

        if neighbors.len() == 0 {
            debug!(
                "{:?}: No neighbors available in the peer DB!",
                &self.local_peer
            );
            return Err(net_error::NoSuchNeighbor);
        }
        Ok(neighbors)
    }

    /// Send off a handshake to a remote peer
    fn walk_handshake(
        &mut self,
        walk: &mut NeighborWalk,
        nk: &NeighborKey,
    ) -> Result<ReplyHandleP2P, net_error> {
        // send handshake.
        let handshake_data = HandshakeData::from_local_peer(&self.local_peer);

        debug!("{:?}: send Handshake to {:?}", &self.local_peer, &nk);
        walk.connecting.remove(nk);

        let msg = match self.sign_for_peer(nk, StacksMessageType::Handshake(handshake_data)) {
            Ok(msg) => msg,
            Err(e) => {
                info!("{:?}: Failed to sign for peer {:?}", &self.local_peer, &nk);
                walk.result.add_dead(nk.clone());
                return Err(e);
            }
        };

        let req_res = self.send_message(nk, msg, self.connection_opts.timeout);

        // we tried this neighbor
        match req_res {
            Ok(handle) => Ok(handle),
            Err(e) => {
                debug!("{:?}: Not connected: {:?} ({:?})", &self.local_peer, nk, &e);
                walk.result.add_dead(nk.clone());
                Err(net_error::PeerNotConnected)
            }
        }
    }

    /// Connect to a remote peer and begin to handshake with it.
    /// Returns Ok(None) if the connection is in progress.
    /// Returns Ok(Some(handle)) if the connection succeeded and we sent the handshake
    /// Returns Err(..) if there was a problem
    fn walk_connect_and_handshake(
        &mut self,
        walk: &mut NeighborWalk,
        nk: &NeighborKey,
    ) -> Result<Option<ReplyHandleP2P>, net_error> {
        match self.can_register_peer(nk, true) {
            Ok(_) => {
                if !walk.connecting.contains_key(nk) {
                    let con_res = self.connect_peer(nk);
                    match con_res {
                        Ok(event_id) => {
                            // remember this in the walk result
                            walk.connecting.insert(nk.clone(), event_id);

                            // stop the pruner from removing this connection
                            walk.events.insert(event_id);

                            // force the caller to try again -- we're not registered yet
                            debug!(
                                "{:?}: Walk is connecting to {:?} (event {})",
                                &self.local_peer, &nk, event_id
                            );
                            return Ok(None);
                        }
                        Err(_e) => {
                            debug!(
                                "{:?}: Failed to connect to {:?}: {:?}",
                                &self.local_peer, nk, &_e
                            );
                            return Err(net_error::PeerNotConnected);
                        }
                    }
                } else {
                    let event_id = walk.connecting.get(nk).unwrap();

                    // is the peer network still working?
                    if !self.is_connecting(*event_id) {
                        debug!("{:?}: Failed to connect to {:?} (event {} no longer connecting; assumed timed out)", &self.local_peer, *event_id, nk);
                        return Err(net_error::PeerNotConnected);
                    }

                    // still connecting
                    debug!(
                        "{:?}: walk still connecting to {:?} (event {})",
                        &self.local_peer, nk, event_id
                    );
                    return Ok(None);
                }
            }
            Err(net_error::AlreadyConnected(_event_id, _nk)) => {
                test_debug!(
                    "{:?}: already connected to {:?} as event {}",
                    &self.local_peer,
                    &nk,
                    _event_id
                );
            }
            Err(e) => {
                info!(
                    "{:?}: could not connect to {:?}: {:?}",
                    &self.local_peer, &nk, &e
                );
                return Err(e);
            }
        }

        self.walk_handshake(walk, nk)
            .and_then(|handle| Ok(Some(handle)))
    }

    /// Instantiate the neighbor walk from a neighbor routable from us.
    fn instantiate_walk(&mut self) -> Result<(), net_error> {
        // pick a random neighbor as a walking point
        let next_neighbors = self
            .walk_get_random_neighbors(1, self.chain_view.burn_block_height)
            .map_err(|e| {
                debug!(
                    "{:?}: Failed to load initial walk neighbors: {:?}",
                    &self.local_peer, &e
                );
                e
            })?;

        let w = NeighborWalk::new(
            self.local_peer.clone(),
            self.chain_view.clone(),
            &next_neighbors[0],
            true,
            self.walk_pingbacks.clone(),
            &self.connection_opts,
        );

        debug!(
            "{:?}: instantiated neighbor walk to outbound peer {:?}",
            &self.local_peer, &next_neighbors[0].addr
        );

        self.walk = Some(w);
        Ok(())
    }

    /// Is the network connected to always-allowed peers?
    /// Returns (count, total)
    fn count_connected_always_allowed_peers(&self) -> Result<(u64, u64), net_error> {
        let allowed_peers =
            PeerDB::get_always_allowed_peers(self.peerdb.conn(), self.local_peer.network_id)?;
        let num_allowed_peers = allowed_peers.len();
        let mut count = 0;
        for allowed in allowed_peers {
            if self.events.contains_key(&allowed.addr) {
                count += 1;
            }
        }
        Ok((count, num_allowed_peers as u64))
    }

    /// Instantiate the neighbor walk to an always-allowed node.
    /// If we're in the initial block download, then this must also be a *bootstrap* peer.
    fn instantiate_walk_to_always_allowed(&mut self, ibd: bool) -> Result<(), net_error> {
        let allowed_peers = if ibd {
            // only get bootstrap peers
            PeerDB::get_bootstrap_peers(&self.peerdb.conn(), self.local_peer.network_id)?
        } else {
            // can be any peer marked 'always-allowed'
            PeerDB::get_always_allowed_peers(self.peerdb.conn(), self.local_peer.network_id)?
        };

        let mut count = 0;
        for allowed in allowed_peers.iter() {
            if self.events.contains_key(&allowed.addr) {
                count += 1;
            }
        }

        if count == 0 {
            // must connect to always-allowed
            for allowed in allowed_peers {
                if !self.events.contains_key(&allowed.addr) {
                    debug!(
                        "Will (re-)connect to always-allowed peer {:?}",
                        &allowed.addr
                    );
                    let w = NeighborWalk::new(
                        self.local_peer.clone(),
                        self.chain_view.clone(),
                        &allowed,
                        true,
                        self.walk_pingbacks.clone(),
                        &self.connection_opts,
                    );

                    debug!(
                        "{:?}: instantiated neighbor walk to always-allowed peer {:?}",
                        &self.local_peer, &allowed
                    );
                    self.walk = Some(w);
                    return Ok(());
                }
            }
        }

        // try a different walk strategy
        return Err(net_error::NotFoundError);
    }

    /// Instantiate a neighbor walk, but use an inbound neighbor instead of a neighbor from our
    /// peer DB.  This helps a public node discover other public nodes, by asking a private node
    /// for its neighbors (which can include other public nodes).
    fn instantiate_walk_from_inbound(&mut self) -> Result<(), net_error> {
        if self.peers.len() == 0 {
            debug!(
                "{:?}: failed to begin inbound neighbor walk: no one's connected to us",
                &self.local_peer
            );
            return Err(net_error::NoSuchNeighbor);
        }

        // pick a random inbound conversation
        let mut idx = thread_rng().gen::<usize>() % self.peers.len();

        test_debug!(
            "{:?}: try inbound neighbors -- sample out of {}. idx = {}",
            &self.local_peer,
            self.peers.len(),
            idx
        );

        for _ in 0..self.walk_pingbacks.len() + 1 {
            let event_id = match self.peers.keys().skip(idx).next() {
                Some(eid) => *eid,
                None => {
                    idx = 0;
                    continue;
                }
            };
            idx = (idx + 1) % self.peers.len();

            let convo = self
                .peers
                .get(&event_id)
                .expect("BUG: no conversation for event ID key");

            if convo.is_outbound() || !convo.is_authenticated() {
                test_debug!(
                    "{:?}: skip outbound and/or unauthenticated neighbor {}",
                    &self.local_peer,
                    &convo.to_neighbor_key()
                );
                continue;
            }

            let pubkey = convo
                .get_public_key()
                .expect("BUG: authenticated conversation without public key");

            // found!
            let nk = convo.to_neighbor_key();
            let empty_neighbor = Neighbor::empty(&nk, &pubkey, 0);
            let w = NeighborWalk::new(
                self.local_peer.clone(),
                self.chain_view.clone(),
                &empty_neighbor,
                false,
                self.walk_pingbacks.clone(),
                &self.connection_opts,
            );

            debug!(
                "{:?}: instantiated neighbor walk to inbound peer {}",
                &self.local_peer, &nk
            );

            self.walk = Some(w);
            return Ok(());
        }

        return Err(net_error::NoSuchNeighbor);
    }

    /// Instantiate a neighbor walk, but go straight to the pingback logic (i.e. we don't have any
    /// immediate neighbors)
    fn instantiate_walk_from_pingback(&mut self) -> Result<(), net_error> {
        if self.walk_pingbacks.len() == 0 {
            return Err(net_error::NoSuchNeighbor);
        }

        let idx = thread_rng().gen::<usize>() % self.walk_pingbacks.len();

        test_debug!(
            "{:?}: try pingback candidates -- sample out of {}. idx = {}",
            &self.local_peer,
            self.walk_pingbacks.len(),
            idx
        );

        let addr = match self.walk_pingbacks.keys().skip(idx).next() {
            Some(ref addr) => (*addr).clone(),
            None => {
                return Err(net_error::NoSuchNeighbor);
            }
        };

        let pb = self.walk_pingbacks.get(&addr).unwrap().clone();
        let nk = NeighborKey::from_neighbor_address(pb.peer_version, pb.network_id, &addr);

        // don't proceed if denied
        if PeerDB::is_peer_denied(&self.peerdb.conn(), nk.network_id, &nk.addrbytes, nk.port)? {
            debug!(
                "{:?}: pingback neighbor {:?} is denied",
                &self.local_peer, &nk
            );
            return Err(net_error::Denied);
        }

        // (this will be ignored by the neighbor walk)
        let empty_neighbor = Neighbor::empty(&nk, &pb.pubkey, 0);

        let mut w = NeighborWalk::new(
            self.local_peer.clone(),
            self.chain_view.clone(),
            &empty_neighbor,
            false,
            self.walk_pingbacks.clone(),
            &self.connection_opts,
        );

        debug!(
            "{:?}: instantiated neighbor walk to {} for pingback only",
            &self.local_peer, &nk
        );

        w.set_state(NeighborWalkState::PingbackHandshakesBegin);
        self.walk = Some(w);
        return Ok(());
    }

    pub fn with_walk_state<F, R>(network: &mut PeerNetwork, handler: F) -> Result<R, net_error>
    where
        F: FnOnce(&mut PeerNetwork, &mut NeighborWalk) -> Result<R, net_error>,
    {
        let mut walk = network.walk.take();
        let res = match walk {
            None => {
                test_debug!("{:?}: not connected", &network.local_peer);
                Err(net_error::NotConnected)
            }
            Some(ref mut walk) => handler(network, walk),
        };
        network.walk = walk;
        res
    }

    /// Begin walking the peer graph by reaching out to a neighbor and handshaking with it.
    /// Return true/false to indicate if we connected or not.
    /// Return an error to reset the walk.
    pub fn walk_handshake_begin(&mut self) -> Result<bool, net_error> {
        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            match walk.handshake_request {
                Some(_) => {
                    // in progress already
                    Ok(true)
                }
                None => {
                    // if cur_neighbor is _us_, then grab a different neighbor and try again
                    if Hash160::from_node_public_key(&walk.cur_neighbor.public_key)
                        == Hash160::from_node_public_key(&Secp256k1PublicKey::from_private(
                            &network.local_peer.private_key,
                        ))
                    {
                        debug!(
                            "{:?}: Walk stepped to ourselves.  Will reset instead.",
                            &walk.local_peer
                        );
                        return Err(net_error::NoSuchNeighbor);
                    }

                    // if cur_neighbor is our bind address, then grab a different neighbor and try
                    // again
                    if network.is_bound(&walk.cur_neighbor.addr) {
                        debug!(
                            "{:?}: Walk stepped to our bind address ({:?}).  Will reset instead.",
                            &walk.local_peer, &walk.cur_neighbor.addr
                        );
                        return Err(net_error::NoSuchNeighbor);
                    }

                    // if cur_neighbor is an anynet address, then grab a different neighbor and try
                    // again
                    if walk.cur_neighbor.addr.addrbytes.is_anynet() {
                        debug!(
                            "{:?}: Walk stepped to an any-network address ({:?}).  Will reset instead.",
                            &walk.local_peer, &walk.cur_neighbor.addr
                        );
                        return Err(net_error::NoSuchNeighbor);
                    }

                    let cur_addr = walk.cur_neighbor.addr.clone();
                    walk.clear_state();

                    let cur_pubkh = Hash160::from_node_public_key(&walk.cur_neighbor.public_key);
                    let res = match network
                        .can_register_peer_with_pubkey(&cur_addr, true, &cur_pubkh)
                    {
                        Ok(_) => network.walk_connect_and_handshake(walk, &cur_addr)?,
                        Err(net_error::AlreadyConnected(event_id, handshake_nk)) => {
                            // already connected, but on a possibly-different address.
                            // If the already-connected handle is inbound, and we're _not_ doing an
                            // inbound neighbor walk, try to connect to this address anyway in
                            // order to maximize our outbound connections we have.
                            if let Some(convo) = network.peers.get(&event_id) {
                                if !convo.is_outbound() {
                                    debug!("{:?}: Already connected to {:?} on inbound event {} (address {:?}). Try to establish outbound connection to {:?} {:?}.",
                                           &network.local_peer, &cur_addr, &event_id, &handshake_nk, &cur_pubkh, &cur_addr);
                                    network.walk_connect_and_handshake(walk, &cur_addr)?
                                } else {
                                    debug!(
                                        "{:?}: Already connected to {:?} on event {} (address: {:?})",
                                        &network.local_peer, &cur_addr, &event_id, &handshake_nk
                                    );
                                    network
                                        .walk_handshake(walk, &handshake_nk)
                                        .and_then(|handle| Ok(Some(handle)))?
                                }
                            } else {
                                // should never be reachable
                                unreachable!(
                                    "AlreadyConnected error on event {} has no conversation",
                                    event_id
                                );
                            }
                        }
                        Err(e) => {
                            debug!(
                                "{:?}: Failed to check connection to {:?}: {:?}. No handshake sent.",
                                &network.local_peer, &cur_addr, &e
                            );
                            return Ok(false);
                        }
                    };

                    match res {
                        Some(handle) => {
                            debug!("{:?}: Handshake sent to {:?}", &walk.local_peer, &cur_addr);
                            walk.handshake_begin(handle);
                            Ok(true)
                        }
                        None => {
                            debug!(
                                "{:?}: No Handshake sent (dest was {:?})",
                                &walk.local_peer, &cur_addr
                            );
                            Ok(false)
                        }
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
                Some(_) => Ok(()),
                None => {
                    debug!(
                        "{:?}: send GetNeighbors to {:?}",
                        &walk.local_peer, &walk.cur_neighbor.addr
                    );

                    let msg = network
                        .sign_for_peer(&walk.cur_neighbor.addr, StacksMessageType::GetNeighbors)?;
                    let req_res = network.send_message(
                        &walk.cur_neighbor.addr,
                        msg,
                        network.connection_opts.timeout,
                    );
                    match req_res {
                        Ok(handle) => {
                            walk.getneighbors_begin(Some(handle));
                            Ok(())
                        }
                        Err(e) => {
                            debug!(
                                "{:?}: Not connected: {:?} ({:?}",
                                &walk.local_peer, &walk.cur_neighbor.addr, &e
                            );
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
            if walk.pending_neighbor_addrs.is_none() {
                // keep trying to finish getting neighbor addresses.  Stop trying once we get something.
                let neighbor_addrs_opt =
                    walk.getneighbors_try_finish(network, burn_block_height)?;
                walk.pending_neighbor_addrs = neighbor_addrs_opt;
            }

            if walk.pending_neighbor_addrs.is_some() {
                // proceed to handshake with them.
                // If this is an inbound neighbor, then try also to handshake with its advertized
                // IP address.
                if !walk.walk_outbound {
                    if let Some(ref mut naddrs) = walk.pending_neighbor_addrs {
                        test_debug!("{:?}: will try to handshake with inbound neighbor {:?}'s advertized address {:?} as well", &walk.local_peer, &walk.cur_neighbor.addr, &walk.neighbor_from_handshake);
                        let cur_neighbor_pubkey_hash =
                            Hash160::from_node_public_key(&walk.cur_neighbor.public_key);
                        naddrs.push(NeighborAddress::from_neighbor_key(
                            walk.neighbor_from_handshake.clone(),
                            cur_neighbor_pubkey_hash,
                        ));
                    }
                }

                // prune this down to size
                let pending_neighbor_list =
                    if let Some(mut pending_neighbor_addrs) = walk.pending_neighbor_addrs.take() {
                        if pending_neighbor_addrs.len() as u64
                            > network.connection_opts.max_neighbors_of_neighbor
                        {
                            debug!(
                                "{:?}: will handshake with {} neighbors out of {} reported by {:?}",
                                &walk.local_peer,
                                &network.connection_opts.max_neighbors_of_neighbor,
                                pending_neighbor_addrs.len(),
                                &walk.cur_neighbor.addr
                            );
                            pending_neighbor_addrs.shuffle(&mut thread_rng());
                            pending_neighbor_addrs
                                [0..(network.connection_opts.max_neighbors_of_neighbor as usize)]
                                .to_vec()
                        } else {
                            pending_neighbor_addrs
                        }
                    } else {
                        vec![]
                    };

                walk.pending_neighbor_addrs = Some(pending_neighbor_list);

                test_debug!(
                    "{:?}: received Neighbors from {} {:?}: {:?}",
                    &walk.local_peer,
                    if walk.walk_outbound {
                        "outbound"
                    } else {
                        "inbound"
                    },
                    &walk.cur_neighbor.addr,
                    &walk.pending_neighbor_addrs.as_ref().unwrap()
                );
                walk.set_state(NeighborWalkState::GetHandshakesBegin);
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    /// Start handshaking with our neighbors' neighbors.
    pub fn walk_neighbor_handshakes_begin(&mut self) -> Result<bool, net_error> {
        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let my_pubkey_hash = Hash160::from_node_public_key(&Secp256k1PublicKey::from_private(
                &walk.local_peer.private_key,
            ));
            debug!(
                "{:?}: my public key hash is {}",
                &walk.local_peer, &my_pubkey_hash
            );
            let pending_neighbor_addrs = walk.pending_neighbor_addrs.take();

            let res = match pending_neighbor_addrs {
                None => {
                    unreachable!("BUG: no result from GetNeighbors");
                }
                Some(ref neighbor_addrs) => {
                    // got neighbors -- proceed to ask each one for *its* neighbors so we can
                    // estimate cur_neighbor's in-degree and grow our frontier.
                    debug!(
                        "{:?}: will try to connect to {} neighbors of {:?}",
                        &network.local_peer,
                        neighbor_addrs.len(),
                        &walk.cur_neighbor.addr
                    );

                    let mut pending = false;
                    for na in neighbor_addrs {
                        // don't talk to myself if we're listed as a neighbor of this
                        // remote peer.
                        if na.public_key_hash == my_pubkey_hash {
                            test_debug!("{:?}: skip handshaking with myself", &network.local_peer);
                            continue;
                        }

                        // don't handshake with cur_neighbor if we already know its public IP
                        // address (we may not know this if the neighbor is inbound)
                        if na.addrbytes == walk.cur_neighbor.addr.addrbytes
                            && na.port == walk.cur_neighbor.addr.port
                        {
                            test_debug!(
                                "{:?}: skip handshaking with cur_neighbor {:?}",
                                &network.local_peer,
                                &walk.cur_neighbor.addr
                            );
                            continue;
                        }

                        // already sent a handshake to this neighbor?
                        if walk.unresolved_handshake_neighbors.contains_key(na) {
                            test_debug!(
                                "{:?}: already connected to {:?}",
                                &network.local_peer,
                                &na
                            );
                            continue;
                        }

                        let nk = NeighborKey::from_neighbor_address(
                            network.peer_version,
                            network.local_peer.network_id,
                            &na,
                        );

                        // don't talk to a neighbor if it's unroutable anyway
                        if network.is_bound(&nk) || nk.addrbytes.is_anynet() {
                            test_debug!(
                                "{:?}: will not connect to bind / anynet address {:?}",
                                &network.local_peer,
                                &nk
                            );
                            continue;
                        }

                        match network.can_register_peer_with_pubkey(&nk, true, &na.public_key_hash)
                        {
                            Ok(_) => {
                                // not connected; try and do so
                                test_debug!(
                                    "{:?}: try to connect to {:?} ({:?})",
                                    &network.local_peer,
                                    &nk,
                                    &na
                                );

                                match network.walk_connect_and_handshake(walk, &nk) {
                                    Ok(Some(handle)) => {
                                        debug!(
                                            "{:?}: will Handshake with neighbor-of-neighbor {:?} ({})",
                                            &network.local_peer, &nk, &na.public_key_hash
                                        );
                                        walk.unresolved_handshake_neighbors
                                            .insert(na.clone(), handle);
                                    }
                                    Ok(None) => {
                                        test_debug!(
                                            "{:?}: already connecting to {:?}",
                                            &network.local_peer,
                                            &nk
                                        );
                                        pending = true;

                                        // try again
                                        continue;
                                    }
                                    Err(e) => {
                                        debug!(
                                            "{:?}: Failed to connect to {:?}: {:?}",
                                            &network.local_peer, &nk, &e
                                        );
                                        continue;
                                    }
                                }
                            }
                            Err(net_error::AlreadyConnected(_event_id, handshake_nk)) => {
                                // connected already -- just proceed to send handshake
                                match network.walk_handshake(walk, &handshake_nk) {
                                    Ok(handle) => {
                                        debug!("{:?}: will Handshake with neighbor-of-neighbor {:?} {:?} (connected as {:?})", &network.local_peer, &na.public_key_hash, &nk, &handshake_nk);
                                        walk.unresolved_handshake_neighbors
                                            .insert(na.clone(), handle);
                                    }
                                    Err(e) => {
                                        info!("{:?}: failed to send Handshake to neighbor-of-neighbor {:?} ({:?}): {:?}", &network.local_peer, &handshake_nk, &nk, &e);
                                        continue;
                                    }
                                }
                            }
                            Err(_e) => {
                                debug!(
                                    "{:?}: cannot handshake with neighbor peer {:?}: {:?}",
                                    &network.local_peer, &nk, &_e
                                );
                                continue;
                            }
                        }
                    }

                    if !pending {
                        // everybody connected
                        test_debug!(
                            "{:?}: connected to {} neighbors-of-neighbors of {:?}",
                            &network.local_peer,
                            walk.unresolved_handshake_neighbors.len(),
                            &walk.cur_neighbor.addr
                        );
                        walk.neighbor_handshakes_begin();
                        Ok(true)
                    } else {
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
    pub fn walk_neighbor_handshakes_try_finish(&mut self) -> Result<bool, net_error> {
        let burn_block_height = self.chain_view.burn_block_height;
        let burn_stable_block_height = self.chain_view.burn_stable_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            match walk.neighbor_handshakes_try_finish(
                network,
                burn_block_height,
                burn_stable_block_height,
            )? {
                Some(mut neighbor_keys) => {
                    walk.handshake_neighbor_keys.clear();
                    walk.handshake_neighbor_keys.append(&mut neighbor_keys);
                    Ok(true)
                }
                None => Ok(false),
            }
        })
    }

    /// Get our neighbors' neighbors
    pub fn walk_getneighbors_neighbors_begin(&mut self) -> Result<(), net_error> {
        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            walk.unresolved_getneighbors_neighbors.clear();
            for nk in walk.handshake_neighbor_keys.drain(..) {
                if !network.is_registered(&nk) {
                    // not connected to this neighbor -- can't ask for neighbors
                    debug!("{:?}: Not connected to {:?}", &network.local_peer, &nk);
                    continue;
                }

                debug!("{:?}: send GetNeighbors to {:?}", &walk.local_peer, &nk);

                let msg = network.sign_for_peer(&nk, StacksMessageType::GetNeighbors)?;
                let rh_res = network.send_message(&nk, msg, network.connection_opts.timeout);
                match rh_res {
                    Ok(rh) => {
                        walk.unresolved_getneighbors_neighbors.insert(nk, rh);
                    }
                    Err(e) => {
                        // failed to begin getneighbors
                        debug!(
                            "{:?}: Could not send to {:?}: {:?}",
                            &walk.local_peer, &nk, &e
                        );
                        continue;
                    }
                }
            }

            walk.getneighbors_neighbors_begin();
            Ok(())
        })
    }

    /// Make progress on completing getneighbors requests to all of cur_neighbor's neighbors.  If
    /// we finish, proceed to update our knowledge of these neighbors and take a step in the peer
    /// graph.
    pub fn walk_getneighbors_neighbors_try_finish(&mut self) -> Result<bool, net_error> {
        let burn_stable_block_height = self.chain_view.burn_stable_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            match walk.getneighbors_neighbors_try_finish(network, burn_stable_block_height)? {
                None => {
                    // not done yet
                    Ok(false)
                }
                Some(_neighbor) => {
                    // finished calculating this neighbor's in/out degree.
                    // walk to the next neighbor.
                    walk.step(network.peerdb.conn());
                    Ok(true)
                }
            }
        })
    }

    /// Begin handshaking with peers that reached out to us
    pub fn walk_pingback_handshakes_begin(&mut self) -> Result<bool, net_error> {
        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let mut pending = false;
            let mut network_pingbacks = mem::replace(&mut walk.network_pingbacks, HashMap::new());
            let mut new_network_pingbacks = HashMap::new();

            for (naddr, pingback) in network_pingbacks.drain() {
                // already connected?
                if walk.pending_pingback_handshakes.contains_key(&naddr) {
                    continue;
                }

                // pingback hint is stale? (or we tried to connect and timed out?)
                if pingback.ts + network.connection_opts.pingback_timeout < get_epoch_time_secs() {
                    continue;
                }

                let nk = NeighborKey::from_neighbor_address(
                    pingback.peer_version,
                    pingback.network_id,
                    &naddr,
                );

                // already trying to connect to this neighbor?
                if walk.connecting.contains_key(&nk) {
                    continue;
                }

                match network.can_register_peer_with_pubkey(&nk, true, &naddr.public_key_hash) {
                    Ok(_) => {
                        // not connected yet
                        // still have to connect
                        pending = true;
                        match network.walk_connect_and_handshake(walk, &nk)? {
                            Some(handle) => {
                                debug!(
                                    "{:?}: Sent pingback handshake to {:?}",
                                    &network.local_peer, &nk
                                );
                                walk.pending_pingback_handshakes
                                    .insert(naddr.clone(), handle);
                            }
                            None => {
                                debug!(
                                    "{:?}: No pingback handshake sent to {:?}",
                                    &network.local_peer, &nk
                                );

                                // try again
                                new_network_pingbacks.insert(naddr, pingback);
                            }
                        }
                    }
                    Err(net_error::AlreadyConnected(_event_id, handshake_nk)) => {
                        // use preferred address
                        // already connected; just send
                        match network.walk_handshake(walk, &handshake_nk) {
                            Ok(handle) => {
                                debug!(
                                    "{:?}: Sent pingback handshake to {:?}",
                                    &network.local_peer, &handshake_nk
                                );
                                walk.pending_pingback_handshakes
                                    .insert(naddr.clone(), handle);
                            }
                            Err(e) => {
                                info!(
                                    "{:?}: Failed to send pingback handshake to {:?}: {:?}",
                                    &network.local_peer, &handshake_nk, &e
                                );
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            "{:?}: Failed to connect to pingback {:?}: {:?}",
                            &network.local_peer, &nk, &e
                        );
                        continue;
                    }
                }
            }

            // restore
            walk.network_pingbacks = new_network_pingbacks;

            if !pending {
                // all handshakes sent
                walk.pingback_handshakes_begin();
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    /// Finish handshaking with peers that reached out to us
    pub fn walk_pingback_handshakes_try_finish(&mut self) -> Result<bool, net_error> {
        let burn_block_height = self.chain_view.burn_block_height;
        let burn_stable_block_height = self.chain_view.burn_stable_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            walk.pingback_handshakes_try_finish(
                network,
                burn_block_height,
                burn_stable_block_height,
            )
        })
    }

    /// Begin pinging existing neighbors up for replacement
    pub fn walk_ping_existing_neighbors_begin(&mut self) -> Result<(), net_error> {
        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let mut ping_handles = HashMap::new();

            // proceed to ping/handshake neighbors we need to replace
            for (nk, _) in walk.replaced_neighbors.iter() {
                test_debug!(
                    "{:?}: send Handshake to replaceable neighbor {:?}",
                    &walk.local_peer,
                    nk
                );

                let handshake_data = HandshakeData::from_local_peer(&walk.local_peer);
                let msg =
                    network.sign_for_peer(nk, StacksMessageType::Handshake(handshake_data))?;
                let req_res = network.send_message(nk, msg, network.connection_opts.timeout);
                match req_res {
                    Ok(handle) => {
                        ping_handles.insert((*nk).clone(), handle);
                    }
                    Err(e) => {
                        debug!(
                            "{:?}: Not connected to {:?}: ({:?}",
                            &walk.local_peer, nk, &e
                        );
                    }
                };
            }

            walk.ping_existing_neighbors_begin(ping_handles);
            Ok(())
        })
    }

    /// Make progress on completing pings to existing neighbors we'd like to replace.  If we
    /// finish, proceed to update our peer database.
    /// Return the result of the peer walk, and reset the walk state.
    pub fn walk_ping_existing_neighbors_try_finish(
        &mut self,
    ) -> Result<Option<NeighborWalkResult>, net_error> {
        let burn_block_height = self.chain_view.burn_block_height;

        PeerNetwork::with_walk_state(self, |ref mut network, ref mut walk| {
            let replaced_opt = walk.ping_existing_neighbors_try_finish(network)?;
            match replaced_opt {
                None => {
                    // still working
                    Ok(None)
                }
                Some(_) => {
                    // finished!
                    // extract the walk result
                    let neighbor_walk_result = {
                        let next_neighbor_opt = walk.next_neighbor.take();
                        match next_neighbor_opt {
                            Some(next_neighbor) => {
                                debug!(
                                    "{:?}: Stepped to {:?}",
                                    &walk.local_peer, &next_neighbor.addr
                                );

                                walk.reset(next_neighbor, false)
                            }
                            None => {
                                // need to select a random new neighbor (will be outbound)
                                // NOTE: this will fail if this peer only has inbound neighbors,
                                // and force the walk to restart.
                                let next_neighbor = network
                                    .walk_get_random_neighbors(1, burn_block_height)?
                                    .pop()
                                    .expect(
                                        "BUG: get_random_neighbors returned an undersized array",
                                    );
                                test_debug!(
                                    "{:?}: Did not step to any neighbor; resetting walk to {:?}",
                                    &walk.local_peer,
                                    &next_neighbor.addr
                                );
                                walk.reset(next_neighbor, true)
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
            None => NeighborWalkState::HandshakeBegin,
            Some(ref walk) => walk.state,
        }
    }

    /// Update the state of our peer graph walk.
    /// If we complete a walk, give back a walk result.
    /// Mask errors by restarting the graph walk.
    /// Returns the walk result, and a true/false flag to indicate whether or not the work for the
    /// walk was finished (i.e. we either completed the walk, or we reset the walk)
    pub fn walk_peer_graph(&mut self, ibd: bool) -> (bool, Option<NeighborWalkResult>) {
        if self.walk.is_none() {
            // time to do a walk yet?
            if (self.walk_count > self.connection_opts.num_initial_walks
                || self.walk_retries > self.connection_opts.walk_retry_count)
                && self.walk_deadline > get_epoch_time_secs()
            {
                // we've done enough walks for an initial mixing, or we can't connect to anyone,
                // so throttle ourselves down until the walk deadline passes.
                debug!(
                    "{:?}: Throttle walk until {} to walk again (walk count: {}, walk retries: {})",
                    &self.local_peer, self.walk_deadline, self.walk_count, self.walk_retries
                );
                return (true, None);
            }
        }

        let (num_always_connected, total_always_connected) = self
            .count_connected_always_allowed_peers()
            .unwrap_or((0, 0));
        if num_always_connected == 0 && total_always_connected > 0 {
            // force a reset
            debug!("{:?}: not connected to any always-allowed peers; forcing a walk reset to try and fix this", &self.local_peer);
            self.walk = None;
        }

        if self.walk.is_none() {
            // alternate between starting walks from inbound and outbound neighbors.
            // fall back to pingbacks-only walks if no options exist.
            debug!(
                "{:?}: Begin walk attempt {}",
                &self.local_peer, self.walk_attempts
            );

            // always ensure we're connected to always-allowed outbound peers
            let walk_res = if ibd {
                // always connect to bootstrap peers if in IBD
                self.instantiate_walk_to_always_allowed(ibd)
            } else {
                // if not in IBD, then we're not required to use the always-allowed neighbors
                // all the time (since they may be offline, and we have all the blocks anyway).
                // Alternate between picking random neighbors, and picking always-allowed
                // neighbors.
                if self.walk_attempts % (self.connection_opts.walk_inbound_ratio + 1) == 0 {
                    self.instantiate_walk()
                } else {
                    self.instantiate_walk_to_always_allowed(ibd)
                }
            };

            let walk_res = match walk_res {
                Ok(x) => Ok(x),
                Err(net_error::NotFoundError) => {
                    // failed to create a walk, so either connect to any known neighbor or connect
                    // to an inbound peer.
                    if self.walk_attempts % (self.connection_opts.walk_inbound_ratio + 1) == 0 {
                        self.instantiate_walk()
                    } else {
                        if self.connection_opts.disable_inbound_walks {
                            debug!(
                                "{:?}: disabled inbound neighbor walks for testing",
                                &self.local_peer
                            );
                            self.instantiate_walk()
                        } else {
                            self.instantiate_walk_from_inbound()
                        }
                    }
                }
                Err(e) => Err(e),
            };

            self.walk_attempts += 1;

            match walk_res {
                Ok(_) => {}
                Err(Error::NoSuchNeighbor) => match self.instantiate_walk_from_pingback() {
                    Ok(_) => {}
                    Err(e) => {
                        debug!(
                            "{:?}: Failed to begin neighbor walk from pingback: {:?}",
                            &self.local_peer, &e
                        );
                        self.walk_retries += 1;
                        self.walk_deadline =
                            self.connection_opts.walk_interval + get_epoch_time_secs();
                        return (true, None);
                    }
                },
                Err(e) => {
                    debug!(
                        "{:?}: Failed to begin neighbor walk from peer database: {:?}",
                        &self.local_peer, &e
                    );
                    self.walk_retries += 1;
                    self.walk_deadline = self.connection_opts.walk_interval + get_epoch_time_secs();
                    return (true, None);
                }
            }
        }

        // synchronize local peer state, in case we learn e.g. the public IP address in the mean
        // time
        match self.walk {
            Some(ref mut walk) => {
                walk.local_peer = self.local_peer.clone();
            }
            None => {}
        }

        // take as many steps as we can
        let mut walk_state = self.get_walk_state();
        let mut walk_state_timeout = false;
        let mut did_cycle = false;
        let res = loop {
            if let Some(ref walk) = self.walk.as_ref() {
                // a walk times out if it stays in one state for too long
                walk_state_timeout =
                    walk.walk_state_time + walk.walk_state_timeout < get_epoch_time_secs();

                if walk_state_timeout {
                    debug!(
                        "{:?}: walk has timed out: stayed in state {:?} for more than {} seconds",
                        &self.local_peer, &walk.state, walk.walk_state_timeout
                    );
                    break Ok(None);
                }
            }

            // advance to next state
            let last_walk_state = walk_state;
            debug!("{:?}: walk state is {:?}", &self.local_peer, walk_state);
            let res = match walk_state {
                NeighborWalkState::HandshakeBegin => {
                    self.walk_handshake_begin().and_then(|_| Ok(None))
                }
                NeighborWalkState::HandshakeFinish => {
                    self.walk_handshake_try_finish().and_then(|_| Ok(None))
                }
                NeighborWalkState::GetNeighborsBegin => {
                    self.walk_getneighbors_begin().and_then(|_| Ok(None))
                }
                NeighborWalkState::GetNeighborsFinish => {
                    self.walk_getneighbors_try_finish().and_then(|_| Ok(None))
                }
                NeighborWalkState::GetHandshakesBegin => {
                    self.walk_neighbor_handshakes_begin().and_then(|_| Ok(None))
                }
                NeighborWalkState::GetHandshakesFinish => self
                    .walk_neighbor_handshakes_try_finish()
                    .and_then(|_| Ok(None)),
                NeighborWalkState::GetNeighborsNeighborsBegin => self
                    .walk_getneighbors_neighbors_begin()
                    .and_then(|_| Ok(None)),
                NeighborWalkState::GetNeighborsNeighborsFinish => self
                    .walk_getneighbors_neighbors_try_finish()
                    .and_then(|_| Ok(None)),
                NeighborWalkState::PingbackHandshakesBegin => {
                    self.walk_pingback_handshakes_begin().and_then(|_| Ok(None))
                }
                NeighborWalkState::PingbackHandshakesFinish => self
                    .walk_pingback_handshakes_try_finish()
                    .and_then(|_| Ok(None)),
                NeighborWalkState::ReplacedNeighborsPingBegin => self
                    .walk_ping_existing_neighbors_begin()
                    .and_then(|_| Ok(None)),
                NeighborWalkState::ReplacedNeighborsPingFinish => {
                    match self.walk_ping_existing_neighbors_try_finish() {
                        Ok(Some(x)) => {
                            debug!("{:?}: finished walk {}", &self.local_peer, self.walk_count);
                            did_cycle = true;
                            Ok(Some(x))
                        }
                        x => x,
                    }
                }
                NeighborWalkState::Finished => {
                    panic!("Walk should never reach the Finished state");
                }
            };

            if did_cycle || res.is_err() {
                // reached the end of the state-machine
                break res;
            }

            walk_state = self.get_walk_state();
            if walk_state == last_walk_state {
                // blocked
                break res;
            }
        };

        match res {
            Ok(mut walk_opt) => {
                // did something
                self.walk_total_step_count += 1;
                self.walk_retries = 0;

                let mut done = false;

                match walk_opt {
                    Some(ref mut walk_result) => {
                        // finished a walk completely
                        done = true;
                        self.walk_count += 1;
                        self.walk_deadline =
                            self.connection_opts.walk_interval + get_epoch_time_secs();

                        debug!(
                            "{:?}: walk has completed in {} steps ({} walks total)",
                            &self.local_peer,
                            self.walk.as_ref().map(|w| w.walk_step_count).unwrap_or(0),
                            self.walk_count
                        );

                        walk_result.do_prune = true;
                    }
                    None => {}
                }

                // Randomly restart it if we have done enough walks, or if the current walk has
                // taken enough steps, or if a timeout has passed
                let reset = match self.walk {
                    Some(ref mut walk) => {
                        if did_cycle {
                            // finished a walk pass
                            walk.walk_step_count += 1;
                        }

                        debug!(
                            "{:?}: current walk has taken {} steps (total of {} walks)",
                            &self.local_peer, walk.walk_step_count, self.walk_count
                        );

                        // a walk times out if it takes too many steps, or if a deadline passes
                        let walk_timed_out = walk.walk_step_count >= walk.walk_max_duration
                            || walk.walk_instantiation_time + walk.walk_reset_interval
                                < get_epoch_time_secs();

                        if walk_timed_out {
                            debug!(
                                "{:?}: walk has timed out: steps = {}, reset deadline = {} < {}",
                                &self.local_peer,
                                walk.walk_step_count,
                                walk.walk_instantiation_time + walk.walk_reset_interval,
                                get_epoch_time_secs()
                            );
                        }

                        if (walk_opt.is_some()
                            && self.walk_count > self.connection_opts.num_initial_walks
                            && walk.walk_step_count >= walk.walk_min_duration)
                            || walk_timed_out
                            || walk_state_timeout
                        {
                            // consider re-setting the walk state, now that we completed a walk.
                            let mut rng = thread_rng();
                            let sample: f64 = rng.gen();
                            if walk_timed_out || walk_state_timeout || sample < walk.walk_reset_prob
                            {
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    None => false,
                };

                if reset {
                    debug!("{:?}: random walk restart", &self.local_peer);
                    self.walk = None;
                    self.walk_resets += 1;
                    done = true; // move onto the next p2p work item
                }

                #[cfg(test)]
                {
                    if done {
                        let (mut inbound, mut outbound) = self.dump_peer_table();

                        inbound.sort();
                        outbound.sort();

                        debug!(
                            "{:?}: Walk finished (reset: {}) ===================",
                            &self.local_peer, reset
                        );
                        debug!(
                            "{:?}: Peers outbound ({}): {}",
                            &self.local_peer,
                            outbound.len(),
                            outbound.join(", ")
                        );
                        debug!(
                            "{:?}: Peers inbound ({}):  {}",
                            &self.local_peer,
                            inbound.len(),
                            inbound.join(", ")
                        );

                        match PeerDB::get_frontier_size(self.peerdb.conn()) {
                            Ok(count) => {
                                debug!("{:?}: Frontier table size: {}", &self.local_peer, count);
                            }
                            Err(_) => {}
                        };
                        debug!("{:?}: Walk finished ===================", &self.local_peer);
                    }
                }

                (done, walk_opt)
            }
            Err(_e) => {
                debug!(
                    "{:?}: Restarting neighbor walk with new random neighbors: {:?} => {:?}",
                    &self.local_peer, walk_state, &_e
                );
                self.walk = None;
                self.walk_resets += 1;
                (true, None)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use stacks_common::util::hash::*;
    use stacks_common::util::sleep_ms;

    use super::*;
    use crate::core::{
        StacksEpoch, StacksEpochId, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
        STACKS_EPOCH_MAX,
    };
    use crate::net::asn::*;
    use crate::net::chat::*;
    use crate::net::db::*;
    use crate::net::test::*;
    use crate::util_lib::test::*;

    const TEST_IN_OUT_DEGREES: u64 = 0x1;

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_plain() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(31890);
            let peer_2_config = TestPeerConfig::from_port(31892);

            // peer 1 crawls peer 2, but not vice versa
            // (so only peer 1 will learn its public IP)
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            let mut i = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;

            while (walk_1_count < 20 || walk_2_count < 20)
                || (!peer_1.network.public_ip_confirmed)
                || peer_1
                    .network
                    .get_neighbor_stats(&peer_2.to_neighbor().addr)
                    .is_none()
            {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
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
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);

            let neighbor_2 = peer_2.to_neighbor();

            // peer 2 is in peer 1's frontier DB
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            match PeerDB::get_peer(
                peer_1_dbconn,
                neighbor_2.addr.network_id,
                &neighbor_2.addr.addrbytes,
                neighbor_2.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_2.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_2.public_key);
                    assert_eq!(p.expire_block, neighbor_2.expire_block);
                }
            }

            // peer 1 learned and confirmed its public IP address from peer 2
            assert!(peer_1.network.local_peer.public_ip_address.is_some());
            assert_eq!(
                peer_1.network.local_peer.public_ip_address.clone().unwrap(),
                (
                    PeerAddress::from_socketaddr(
                        &format!("127.0.0.1:1").parse::<SocketAddr>().unwrap()
                    ),
                    31890
                )
            );
            assert!(peer_1.network.public_ip_learned);
            assert!(peer_1.network.public_ip_confirmed);

            // peer 2 learned nothing, despite trying
            assert!(peer_2.network.local_peer.public_ip_address.is_none());
            assert!(peer_2.network.public_ip_learned);
            assert!(!peer_2.network.public_ip_confirmed);
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_plain_no_natpunch() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(31980);
            let mut peer_2_config = TestPeerConfig::from_port(31982);

            // simulate peer 2 not knowing how to handle a natpunch request
            peer_2_config.connection_opts.disable_natpunch = true;

            // peer 1 crawls peer 2
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            let mut i = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;

            let mut stats_1 = None;

            while (walk_1_count < 20 || walk_2_count < 20) || stats_1.is_none() {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

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

                if let Some(s) = peer_1
                    .network
                    .get_neighbor_stats(&peer_2.to_neighbor().addr)
                {
                    stats_1 = Some(s);
                }

                i += 1;
            }

            debug!("Completed walk round {} step(s)", i);

            peer_1.dump_frontier();
            peer_2.dump_frontier();

            // peer 1 contacted peer 2
            let stats_1 = stats_1.unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);

            let neighbor_2 = peer_2.to_neighbor();

            // peer 2 is in peer 1's frontier DB
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            match PeerDB::get_peer(
                peer_1_dbconn,
                neighbor_2.addr.network_id,
                &neighbor_2.addr.addrbytes,
                neighbor_2.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_2.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_2.public_key);
                    assert_eq!(p.expire_block, neighbor_2.expire_block);
                }
            }

            // peer 1 did not learn IP address
            assert!(peer_1.network.local_peer.public_ip_address.is_none());
            assert!(!peer_1.network.public_ip_confirmed);

            // peer 2 did not learn IP address
            assert!(peer_2.network.local_peer.public_ip_address.is_none());
            assert!(!peer_2.network.public_ip_confirmed);
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_denied() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(31994);
            let mut peer_2_config = TestPeerConfig::from_port(31996);

            // peer 1 crawls peer 2, but peer 1 has denied peer 2
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

            peer_1_config.connection_opts.walk_retry_count = 10;
            peer_2_config.connection_opts.walk_retry_count = 10;
            peer_1_config.connection_opts.walk_interval = 1;
            peer_2_config.connection_opts.walk_interval = 1;

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            {
                let mut tx = peer_1.network.peerdb.tx_begin().unwrap();
                PeerDB::add_deny_cidr(&mut tx, &PeerAddress::from_ipv4(127, 0, 0, 1), 128).unwrap();
                tx.commit().unwrap();
            }

            let mut i = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            let mut walk_1_retries = 0;
            let mut walk_2_retries = 0;
            let mut walk_1_total = 0;
            let mut walk_2_total = 0;

            // walks just don't start.
            // neither peer learns their public IP addresses.
            while walk_1_retries < 20 && walk_2_retries < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                walk_1_total = peer_1.network.walk_count;
                walk_2_total = peer_2.network.walk_count;

                assert_eq!(walk_1_total, 0);
                assert_eq!(walk_2_total, 0);

                walk_1_retries = peer_1.network.walk_retries;
                walk_2_retries = peer_2.network.walk_retries;

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;
            }

            assert!(peer_1.network.public_ip_learned);
            assert!(!peer_1.network.public_ip_confirmed);
            assert!(peer_1.network.local_peer.public_ip_address.is_none());

            assert!(peer_2.network.public_ip_learned);
            assert!(!peer_2.network.public_ip_confirmed);
            assert!(peer_2.network.local_peer.public_ip_address.is_none());
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_bad_epoch() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(31998);
            let mut peer_2_config = TestPeerConfig::from_port(31990);

            peer_1_config.connection_opts.walk_retry_count = 10;
            peer_2_config.connection_opts.walk_retry_count = 10;
            peer_1_config.connection_opts.walk_interval = 1;
            peer_2_config.connection_opts.walk_interval = 1;

            // peer 1 thinks its always epoch 2.0
            peer_1_config.peer_version = 0x18000000;
            peer_1_config.epochs = Some(vec![StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 0,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            }]);

            // peer 2 thinks its always epoch 2.05
            peer_2_config.peer_version = 0x18000005;
            peer_2_config.epochs = Some(vec![StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 0,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            }]);

            // peers know about each other, but peer 2 never talks to peer 1 since it believes that
            // it's in a wholly different epoch
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
            peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            let mut i = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            let mut walk_1_retries = 0;
            let mut walk_2_retries = 0;
            let mut walk_1_total = 0;
            let mut walk_2_total = 0;

            // walks just don't start.
            // neither peer learns their public IP addresses.
            while walk_1_retries < 20 && walk_2_retries < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                walk_1_total = peer_1.network.walk_count;
                walk_2_total = peer_2.network.walk_count;

                assert_eq!(walk_1_total, 0);
                assert_eq!(walk_2_total, 0);

                walk_1_retries = peer_1.network.walk_attempts;
                walk_2_retries = peer_2.network.walk_attempts;

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;

                debug!("attempts: {},{}", walk_1_retries, walk_2_retries);
            }

            assert!(peer_1.network.public_ip_learned);
            assert!(!peer_1.network.public_ip_confirmed);
            assert!(peer_1.network.local_peer.public_ip_address.is_none());

            assert!(peer_2.network.public_ip_learned);
            assert!(!peer_2.network.public_ip_confirmed);
            assert!(peer_2.network.local_peer.public_ip_address.is_none());
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_heartbeat_ping() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32992);
            let mut peer_2_config = TestPeerConfig::from_port(32994);

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

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
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
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);

            let neighbor_2 = peer_2.to_neighbor();

            // peer 2 is in peer 1's frontier DB
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            match PeerDB::get_peer(
                peer_1_dbconn,
                neighbor_2.addr.network_id,
                &neighbor_2.addr.addrbytes,
                neighbor_2.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_2.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_2.public_key);
                    assert_eq!(p.expire_block, neighbor_2.expire_block);
                }
            }

            assert_eq!(peer_1.network.relay_handles.len(), 0);
            assert_eq!(peer_2.network.relay_handles.len(), 0);

            info!("Wait 60 seconds for ping timeout");
            sleep_ms(60000);

            peer_1.network.queue_ping_heartbeats();
            peer_2.network.queue_ping_heartbeats();

            // pings queued
            assert_eq!(peer_1.network.relay_handles.len(), 1);
            assert_eq!(peer_2.network.relay_handles.len(), 1);
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_bootstrapping() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32100);
            let peer_2_config = TestPeerConfig::from_port(32102);

            // peer 1 crawls peer 2, but peer 1 doesn't add peer 2 to its frontier becuase peer 2 is
            // too far behind.
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            // advance peer 1
            for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
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

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);

                        // peer 2 never gets added to peer 1's frontier
                        assert!(w.frontier.get(&neighbor_2.addr).is_none());
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;
            }

            debug!("Completed walk round {} step(s)", i);

            // peer 1 contacted peer 2
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_1_neighbor_behind() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32200);
            let mut peer_2_config = TestPeerConfig::from_port(32202);

            peer_1_config.connection_opts.disable_natpunch = true;
            peer_2_config.connection_opts.disable_natpunch = true;

            // peer 1 crawls peer 2, and peer 1 adds peer 2 to its frontier even though peer 2 does
            // not, because peer 2 is too far ahead
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            // advance peer 2
            for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
                peer_2.add_empty_burnchain_block();
            }

            let mut i = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;

            let neighbor_1 = peer_1.to_neighbor();
            let neighbor_2 = peer_2.to_neighbor();

            while (walk_1_count < 20 && walk_2_count < 20)
                || peer_1
                    .network
                    .get_neighbor_stats(&peer_2.to_neighbor().addr)
                    .is_none()
            {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);

                        // peer 1 never gets added to peer 2's frontier
                        assert!(w.frontier.get(&neighbor_1.addr).is_none());
                    }
                    None => {}
                };

                i += 1;

                debug!("Peer 1 begin neighbor stats:");
                for (nk, _) in peer_1.network.events.iter() {
                    match peer_1.network.get_neighbor_stats(nk) {
                        Some(ns) => {
                            debug!("   have stats for {:?}", &nk);
                        }
                        None => {
                            debug!("   (no stats for {:?})", &nk);
                        }
                    }
                }
                debug!("Peer 1 end neighbor stats");
            }

            debug!("Completed walk round {} step(s)", i);

            // peer 1 contacted peer 2
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);

            let neighbor_2 = peer_2.to_neighbor();

            // peer 2 was added to the peer DB of peer 1, even though peer 1 is very behind peer 2
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            match PeerDB::get_peer(
                peer_1_dbconn,
                neighbor_2.addr.network_id,
                &neighbor_2.addr.addrbytes,
                neighbor_2.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_2.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_2.public_key);
                    assert_eq!(p.expire_block, neighbor_2.expire_block);
                }
            }
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_10_neighbors_of_neighbor_plain() {
        with_timeout(600, || {
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
                let mut n = TestPeerConfig::from_port(2 * i + 4 + 32300);

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

                    test_debug!(
                        "peer 1 took {} walk steps; peer 2 took {} walk steps",
                        walk_1_count,
                        walk_2_count
                    );

                    match peer_1.network.walk {
                        Some(ref w) => {
                            assert_eq!(w.result.broken_connections.len(), 0);
                            assert_eq!(w.result.replaced_neighbors.len(), 0);
                        }
                        None => {}
                    };

                    match peer_2.network.walk {
                        Some(ref w) => {
                            assert_eq!(w.result.broken_connections.len(), 0);
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
                    let p_opt = PeerDB::get_peer(
                        peer_1_dbconn,
                        n.addr.network_id,
                        &n.addr.addrbytes,
                        n.addr.port,
                    )
                    .unwrap();
                    match p_opt {
                        None => {
                            test_debug!("no such peer: {:?}", &n.addr);
                        }
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
                let p2_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    n2.addr.network_id,
                    &n2.addr.addrbytes,
                    n2.addr.port,
                )
                .unwrap();
                match p2_opt {
                    None => {
                        test_debug!("no peer 2");
                    }
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
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_10_neighbors_of_neighbor_bootstrapping() {
        with_timeout(600, || {
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
                let mut n = TestPeerConfig::from_port(2 * i + 4 + 32400);

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
            for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
                peer_1.add_empty_burnchain_block();
                peer_2.add_empty_burnchain_block();
                for j in 0..5 {
                    peer_2_neighbors[j].add_empty_burnchain_block();
                }
            }

            // next, make peer 1 discover peer 2's neighbors and peer 2's in/out degree.
            let mut steps = 0;
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

                    test_debug!(
                        "peer 1 took {} walk steps; peer 2 took {} walk steps",
                        walk_1_count,
                        walk_2_count
                    );

                    match peer_1.network.walk {
                        Some(ref w) => {
                            assert_eq!(w.result.broken_connections.len(), 0);
                            assert_eq!(w.result.replaced_neighbors.len(), 0);
                        }
                        None => {}
                    };

                    match peer_2.network.walk {
                        Some(ref w) => {
                            assert_eq!(w.result.broken_connections.len(), 0);
                            assert_eq!(w.result.replaced_neighbors.len(), 0);
                        }
                        None => {}
                    };

                    steps += 1;
                }

                peer_1.dump_frontier();
                peer_2.dump_frontier();

                // check if peer 1 handshaked with all of peer 2's _fresh_ neighbors
                let peer_1_dbconn = peer_1.get_peerdb_conn();
                let mut num_contacted = 0; // should be 5 when test finishes
                for i in 0..5 {
                    let peer = &peer_2_neighbors[i];
                    let n = peer.to_neighbor();
                    let p_opt = PeerDB::get_peer(
                        peer_1_dbconn,
                        n.addr.network_id,
                        &n.addr.addrbytes,
                        n.addr.port,
                    )
                    .unwrap();
                    match p_opt {
                        None => {
                            test_debug!("no such peer: {:?}", &n.addr);
                        }
                        Some(p) => {
                            assert_eq!(p.public_key, n.public_key);
                            assert_eq!(p.expire_block, n.expire_block);
                            num_contacted += 1;
                        }
                    }

                    let stale_peer = &peer_2_neighbors[i + 5];
                    let stale_n = stale_peer.to_neighbor();
                    let stale_peer_opt = PeerDB::get_peer(
                        peer_1_dbconn,
                        stale_n.addr.network_id,
                        &stale_n.addr.addrbytes,
                        stale_n.addr.port,
                    )
                    .unwrap();
                    match stale_peer_opt {
                        None => {}
                        Some(_) => {
                            test_debug!("stale peer contacted: {:?}", &stale_n.addr);
                            assert!(false);
                        }
                    }
                }

                test_debug!(
                    "Peer 1 has contactd {} of Peer 2's neighbors",
                    num_contacted
                );

                if num_contacted < 5 {
                    continue;
                }

                // peer 1 learned that peer 2 has an out-degree of 6 (peer_1 + 5 fresh neighbors) and an in-degree of 1
                let n2 = peer_2.to_neighbor();
                let p2_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    n2.addr.network_id,
                    &n2.addr.addrbytes,
                    n2.addr.port,
                )
                .unwrap();
                match p2_opt {
                    None => {
                        test_debug!("no peer 2");
                    }
                    Some(p2) => {
                        if p2.out_degree >= 6 && p2.in_degree >= 1 {
                            assert_eq!(p2.out_degree, 6);
                            did_handshakes = true;
                        }
                    }
                }
            }

            debug!("Completed walk round {} step(s)", steps);

            // peer 1 contacted peer 2
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);
        })
    }

    #[test]
    fn test_step_walk_2_neighbors_plain() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32500);
            let mut peer_2_config = TestPeerConfig::from_port(32502);

            peer_1_config.allowed = -1;
            peer_2_config.allowed = -1;

            // short-lived walks...
            peer_1_config.connection_opts.walk_max_duration = 10;
            peer_2_config.connection_opts.walk_max_duration = 10;

            // peer 1 crawls peer 2, and peer 2 crawls peer 1
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
            peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            let mut i = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;

            // NOTE: 2x the max walk duration
            while walk_1_count < 20 || walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;
            }

            debug!("Completed walk round {} step(s)", i);

            // peer 1 contacted peer 2
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);

            // peer 2 contacted peer 1
            let stats_2 = peer_2
                .network
                .get_neighbor_stats(&peer_1.to_neighbor().addr)
                .unwrap();
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
            match PeerDB::get_peer(
                peer_1_dbconn,
                neighbor_2.addr.network_id,
                &neighbor_2.addr.addrbytes,
                neighbor_2.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_2.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_2.public_key);
                    assert_eq!(p.expire_block, neighbor_2.expire_block);
                }
            }

            // peer 1 was added to the peer DB of peer 2
            let peer_2_dbconn = peer_2.get_peerdb_conn();
            match PeerDB::get_peer(
                peer_2_dbconn,
                neighbor_1.addr.network_id,
                &neighbor_1.addr.addrbytes,
                neighbor_1.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_1.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_1.public_key);
                    assert_eq!(p.expire_block, neighbor_1.expire_block);
                }
            }

            // walks were reset at least once
            assert!(peer_1.network.walk_count > 0);
            assert!(peer_2.network.walk_count > 0);
        })
    }

    #[test]
    fn test_step_walk_2_neighbors_state_timeout() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32504);
            let mut peer_2_config = TestPeerConfig::from_port(32506);

            peer_1_config.allowed = -1;
            peer_2_config.allowed = -1;

            // short-lived walks...
            peer_1_config.connection_opts.walk_max_duration = 10;
            peer_2_config.connection_opts.walk_max_duration = 10;

            peer_1_config.connection_opts.walk_state_timeout = 1;
            peer_2_config.connection_opts.walk_state_timeout = 1;

            // peer 1 crawls peer 2, and peer 2 crawls peer 1
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
            peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            for _i in 0..10 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                let walk_1_count = peer_1.network.walk_total_step_count;
                let walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                sleep_ms(3_000);
            }

            // state resets trigger walk resets
            assert!(peer_1.network.walk_resets > 0);
            assert!(peer_2.network.walk_resets > 0);
        })
    }

    #[test]
    fn test_step_walk_2_neighbors_walk_timeout() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32508);
            let mut peer_2_config = TestPeerConfig::from_port(32510);

            peer_1_config.allowed = -1;
            peer_2_config.allowed = -1;

            // short-lived walks...
            peer_1_config.connection_opts.walk_max_duration = 10;
            peer_2_config.connection_opts.walk_max_duration = 10;

            peer_1_config.connection_opts.walk_state_timeout = 20;
            peer_2_config.connection_opts.walk_state_timeout = 20;

            peer_1_config.connection_opts.walk_reset_interval = 10;
            peer_2_config.connection_opts.walk_reset_interval = 10;

            // peer 1 crawls peer 2, and peer 2 crawls peer 1
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
            peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);

            let mut i = 0;
            let mut walk_1_step_count = 0;
            let mut walk_2_step_count = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;

            while walk_1_step_count < 20 || walk_2_step_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_step_count = peer_1.network.walk_total_step_count;
                walk_2_step_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_step_count,
                    walk_2_step_count
                );

                if walk_1_count < peer_1.network.walk_count
                    || walk_2_count < peer_2.network.walk_count
                {
                    // force walk to time out
                    sleep_ms(11_000);
                }

                walk_1_count = peer_1
                    .network
                    .walk
                    .as_ref()
                    .map(|w| w.walk_step_count)
                    .unwrap_or(0);
                walk_2_count = peer_1
                    .network
                    .walk
                    .as_ref()
                    .map(|w| w.walk_step_count)
                    .unwrap_or(0);

                i += 1;
            }

            // walk timeouts trigger walk resets
            assert!(peer_1.network.walk_resets > 0);
            assert!(peer_2.network.walk_resets > 0);
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_3_neighbors_inbound() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32520);
            let mut peer_2_config = TestPeerConfig::from_port(32522);
            let mut peer_3_config = TestPeerConfig::from_port(32524);

            peer_1_config.allowed = -1;
            peer_2_config.allowed = -1;
            peer_3_config.allowed = -1;

            peer_1_config.connection_opts.disable_pingbacks = true;
            peer_2_config.connection_opts.disable_pingbacks = true;
            peer_3_config.connection_opts.disable_pingbacks = true;

            peer_1_config.connection_opts.disable_inv_sync = true;
            peer_2_config.connection_opts.disable_inv_sync = true;
            peer_3_config.connection_opts.disable_inv_sync = true;

            peer_1_config.connection_opts.disable_block_download = true;
            peer_2_config.connection_opts.disable_block_download = true;
            peer_3_config.connection_opts.disable_block_download = true;

            // Peer 2 and peer 3 are public nodes that don't know about each other, but peer 1 lists
            // both of them as outbound neighbors.  Goal is for peer 2 to learn about peer 3, and vice
            // versa, by crawling peer 1 through an inbound neighbor walk.
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
            peer_1_config.add_neighbor(&peer_3_config.to_neighbor());

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);
            let mut peer_3 = TestPeer::new(peer_3_config);

            let mut i = 0;
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            let mut walk_3_count = 0;
            let mut peer_1_frontier_size = 0;
            let mut peer_2_frontier_size = 0;
            let mut peer_3_frontier_size = 0;
            while peer_2_frontier_size < 2 || peer_3_frontier_size < 2 {
                let _ = peer_1.step();
                let _ = peer_2.step();
                let _ = peer_3.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;
                walk_3_count = peer_3.network.walk_total_step_count;

                test_debug!("========");
                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps; peer 3 took {} steps",
                    walk_1_count,
                    walk_2_count,
                    walk_3_count
                );
                test_debug!(
                    "peer 1 frontier size: {}, peer 2 frontier size: {}, peer 3 frontier size: {}",
                    peer_1_frontier_size,
                    peer_2_frontier_size,
                    peer_3_frontier_size
                );
                test_debug!("========");

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_3.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                for (i, peer) in [&peer_1, &peer_2, &peer_3].iter().enumerate() {
                    let db = peer.get_peerdb_conn();
                    let neighbors = PeerDB::get_all_peers(db).unwrap();
                    test_debug!("Begin neighbor dump from {:?}", &peer.to_neighbor().addr);
                    for n in neighbors {
                        test_debug!("   {:?}", &n.addr);
                    }
                    test_debug!("End neighbor dump from {:?}", &peer.to_neighbor().addr);
                }

                peer_1_frontier_size = PeerDB::get_all_peers(peer_1.get_peerdb_conn())
                    .unwrap()
                    .len();
                peer_2_frontier_size = PeerDB::get_all_peers(peer_2.get_peerdb_conn())
                    .unwrap()
                    .len();
                peer_3_frontier_size = PeerDB::get_all_peers(peer_3.get_peerdb_conn())
                    .unwrap()
                    .len();

                i += 1;
            }

            debug!("Completed walk round {} step(s)", i);

            let neighbor_1 = peer_1.to_neighbor();
            let neighbor_2 = peer_2.to_neighbor();
            let neighbor_3 = peer_3.to_neighbor();

            // peer 2 was added to the peer DB of peer 1
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            match PeerDB::get_peer_by_port(
                peer_1_dbconn,
                neighbor_2.addr.network_id,
                neighbor_2.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_2.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_2.public_key);
                    assert_eq!(p.expire_block, neighbor_2.expire_block);
                }
            }

            // peer 3 was added to the peer DB of peer 1
            match PeerDB::get_peer_by_port(
                peer_1_dbconn,
                neighbor_3.addr.network_id,
                neighbor_3.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_3.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_3.public_key);
                    assert_eq!(p.expire_block, neighbor_3.expire_block);
                }
            }

            // peer 2 was added to the peer DB of peer 3
            let peer_2_dbconn = peer_2.get_peerdb_conn();
            match PeerDB::get_peer_by_port(
                peer_2_dbconn,
                neighbor_3.addr.network_id,
                neighbor_3.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_3.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_3.public_key);
                    assert_eq!(p.expire_block, neighbor_3.expire_block);
                }
            }

            // peer 3 was added to the peer DB of peer 2
            let peer_3_dbconn = peer_3.get_peerdb_conn();
            match PeerDB::get_peer_by_port(
                peer_3_dbconn,
                neighbor_2.addr.network_id,
                neighbor_2.addr.port,
            )
            .unwrap()
            {
                None => {
                    test_debug!("no such peer: {:?}", &neighbor_2.addr);
                    assert!(false);
                }
                Some(p) => {
                    assert_eq!(p.public_key, neighbor_2.public_key);
                    assert_eq!(p.expire_block, neighbor_2.expire_block);
                }
            }
        })
    }

    #[test]
    #[ignore]
    fn test_step_walk_2_neighbors_rekey() {
        with_timeout(600, || {
            let mut peer_1_config = TestPeerConfig::from_port(32600);
            let mut peer_2_config = TestPeerConfig::from_port(32602);

            peer_1_config.allowed = -1;
            peer_2_config.allowed = -1;

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
                            assert_eq!(w.result.replaced_neighbors.len(), 0);
                        }
                        None => {}
                    };

                    match peer_2.network.walk {
                        Some(ref w) => {
                            assert_eq!(w.result.broken_connections.len(), 0);
                            assert_eq!(w.result.replaced_neighbors.len(), 0);
                        }
                        None => {}
                    };
                }

                peer_1.add_empty_burnchain_block();
                peer_2.add_empty_burnchain_block();
            }

            // peer 1 contacted peer 2
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .unwrap();
            assert!(stats_1.last_contact_time > 0);
            assert!(stats_1.last_handshake_time > 0);
            assert!(stats_1.last_send_time > 0);
            assert!(stats_1.last_recv_time > 0);
            assert!(stats_1.bytes_rx > 0);
            assert!(stats_1.bytes_tx > 0);

            // peer 2 contacted peer 1
            let stats_2 = peer_2
                .network
                .get_neighbor_stats(&peer_1.to_neighbor().addr)
                .unwrap();
            assert!(stats_2.last_contact_time > 0);
            assert!(stats_2.last_handshake_time > 0);
            assert!(stats_2.last_send_time > 0);
            assert!(stats_2.last_recv_time > 0);
            assert!(stats_2.bytes_rx > 0);
            assert!(stats_2.bytes_tx > 0);

            let neighbor_1 = peer_1.to_neighbor();
            let neighbor_2 = peer_2.to_neighbor();

            // peer 1 was added to the peer DB of peer 2
            assert!(PeerDB::get_peer(
                peer_1.network.peerdb.conn(),
                neighbor_2.addr.network_id,
                &neighbor_2.addr.addrbytes,
                neighbor_2.addr.port
            )
            .unwrap()
            .is_some());

            // peer 2 was added to the peer DB of peer 1
            assert!(PeerDB::get_peer(
                peer_2.network.peerdb.conn(),
                neighbor_1.addr.network_id,
                &neighbor_1.addr.addrbytes,
                neighbor_1.addr.port
            )
            .unwrap()
            .is_some());

            // new keys
            assert!(peer_1.get_public_key() != initial_public_key_1);
            assert!(peer_2.get_public_key() != initial_public_key_2);
        })
    }

    #[test]
    fn test_step_walk_2_neighbors_different_networks() {
        with_timeout(600, || {
            // peer 1 and 2 try to handshake but never succeed since they have different network IDs
            let mut peer_1_config = TestPeerConfig::from_port(32700);
            let mut peer_2_config = TestPeerConfig::from_port(32702);

            // peer 1 crawls peer 2, and peer 2 crawls peer 1
            peer_1_config.add_neighbor(&peer_2_config.to_neighbor());

            // peer 2 thinks peer 1 has the same network ID that it does
            println!("1 ~~~ {}", peer_1_config.network_id);
            println!("2 ~~~ {}", peer_2_config.network_id);

            peer_1_config.network_id = peer_1_config.network_id + 1;
            peer_2_config.add_neighbor(&peer_1_config.to_neighbor());
            peer_1_config.network_id = peer_1_config.network_id - 1;

            // different network IDs
            peer_2_config.network_id = peer_1_config.network_id + 1;

            println!("3 ~~~ {}", peer_1_config.network_id);
            println!("4 ~~~ {}", peer_2_config.network_id);

            let mut peer_1 = TestPeer::new(peer_1_config);
            let mut peer_2 = TestPeer::new(peer_2_config);
            println!("5 ~~~");

            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            let mut i = 0;
            while walk_1_count < 20 && walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;
            }

            debug!("Completed walk round {} step(s)", i);

            // peer 1 did NOT contact peer 2
            let stats_1 = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr);
            assert!(stats_1.is_none());

            // peer 2 did NOT contact peer 1
            let stats_2 = peer_2
                .network
                .get_neighbor_stats(&peer_1.to_neighbor().addr);
            assert!(stats_2.is_none());

            let neighbor_1 = peer_1.to_neighbor();
            let neighbor_2 = peer_2.to_neighbor();

            // peer 1 was NOT added to the peer DB of peer 2
            assert!(PeerDB::get_peer(
                peer_1.network.peerdb.conn(),
                neighbor_2.addr.network_id,
                &neighbor_2.addr.addrbytes,
                neighbor_2.addr.port
            )
            .unwrap()
            .is_none());

            // peer 2 was NOT added to the peer DB of peer 1
            assert!(PeerDB::get_peer(
                peer_2.network.peerdb.conn(),
                neighbor_1.addr.network_id,
                &neighbor_1.addr.addrbytes,
                neighbor_1.addr.port
            )
            .unwrap()
            .is_none());
        })
    }

    fn setup_peer_config(
        i: usize,
        port_base: u16,
        neighbor_count: usize,
        peer_count: usize,
    ) -> TestPeerConfig {
        let mut conf = TestPeerConfig::from_port(port_base + (2 * i as u16));
        conf.connection_opts.num_neighbors = neighbor_count as u64;
        conf.connection_opts.soft_num_neighbors = neighbor_count as u64;

        conf.connection_opts.num_clients = 256;
        conf.connection_opts.soft_num_clients = 128;

        conf.connection_opts.max_http_clients = 1000;
        conf.connection_opts.max_neighbors_of_neighbor = 256;

        conf.connection_opts.max_clients_per_host = MAX_NEIGHBORS_DATA_LEN as u64;
        conf.connection_opts.soft_max_clients_per_host = peer_count as u64;

        conf.connection_opts.max_neighbors_per_host = MAX_NEIGHBORS_DATA_LEN as u64;
        conf.connection_opts.soft_max_neighbors_per_host = (neighbor_count / 2) as u64;
        conf.connection_opts.soft_max_neighbors_per_org = (neighbor_count / 2) as u64;

        conf.connection_opts.walk_interval = 0;

        conf.connection_opts.disable_inv_sync = true;
        conf.connection_opts.disable_block_download = true;

        let j = i as u32;
        conf.burnchain.peer_version = PEER_VERSION_TESTNET | (j << 16) | (j << 8) | j; // different non-major versions for each peer
        conf
    }

    #[test]
    #[ignore]
    fn test_walk_ring_allow_15() {
        with_timeout(600, || {
            // all initial peers are allowed
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 32800, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = -1; // always allowed
                conf.denied = 0;

                conf.connection_opts.timeout = 100000;
                conf.connection_opts.handshake_timeout = 100000;
                conf.connection_opts.disable_natpunch = true; // breaks allow checks

                peer_configs.push(conf);
            }

            test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_ring_15_plain() {
        with_timeout(600, || {
            // initial peers are neither white- nor denied
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 32900, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;

                peer_configs.push(conf);
            }

            test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_ring_15_pingback() {
        with_timeout(600, || {
            // initial peers are neither white- nor denied
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 32950, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;
                conf.connection_opts.disable_pingbacks = true;
                conf.connection_opts.disable_inbound_walks = false;

                peer_configs.push(conf);
            }

            test_walk_ring_pingback(&mut peer_configs, NEIGHBOR_COUNT);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_ring_15_org_biased() {
        with_timeout(600, || {
            // one outlier peer has a different org than the others.
            use std::env;

            // ::33000 is in AS 1
            env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33000", "1");

            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33000, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;
                if i == 0 {
                    conf.asn = 1;
                    conf.org = 1;
                } else {
                    conf.asn = 0;
                    conf.org = 0;
                }

                peer_configs.push(conf);
            }

            // all peers see peer ::33000 as having ASN and Org ID 1
            let peer_0 = peer_configs[0].to_neighbor();

            let peers = test_walk_ring(&mut peer_configs, NEIGHBOR_COUNT);

            for i in 1..PEER_COUNT {
                match PeerDB::get_peer(
                    peers[i].network.peerdb.conn(),
                    peer_0.addr.network_id,
                    &peer_0.addr.addrbytes,
                    peer_0.addr.port,
                )
                .unwrap()
                {
                    Some(p) => {
                        assert_eq!(p.asn, 1);
                        assert_eq!(p.org, 1);
                    }
                    None => {}
                }
            }

            // no peer pruned peer ::33000
            for i in 1..PEER_COUNT {
                match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                    None => {}
                    Some(count) => {
                        assert_eq!(*count, 0);
                    }
                }
            }
        })
    }

    fn test_walk_ring_ex(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
        test_pingback: bool,
    ) -> Vec<TestPeer> {
        // arrange neighbors into a "ring" topology, where
        // neighbor N is connected to neighbor (N-1)%NUM_NEIGHBORS and (N+1)%NUM_NEIGHBORS.
        // If test_pingback is true, then neighbor N is only connected to (N+1)%NUM_NEIGHBORS
        let mut peers = vec![];

        let PEER_COUNT = peer_configs.len();
        let NEIGHBOR_COUNT = neighbor_count;

        for i in 0..PEER_COUNT {
            let n = (i + 1) % PEER_COUNT;
            let neighbor = peer_configs[n].to_neighbor();
            peer_configs[i].add_neighbor(&neighbor);
        }

        if !test_pingback {
            for i in 1..PEER_COUNT + 1 {
                let p = i - 1;
                let neighbor = peer_configs[p].to_neighbor();
                peer_configs[i % PEER_COUNT].add_neighbor(&neighbor);
            }
        }

        for i in 0..PEER_COUNT {
            let p = TestPeer::new(peer_configs[i].clone());
            peers.push(p);
        }

        run_topology_test(&mut peers, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);

        // no nacks or handshake-rejects
        for i in 0..PEER_COUNT {
            for (_, convo) in peers[i].network.peers.iter() {
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::Nack)
                        .unwrap_or(&0)
                        == 0
                );
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::HandshakeReject)
                        .unwrap_or(&0)
                        == 0
                );
            }
        }

        peers
    }

    fn test_walk_ring(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
    ) -> Vec<TestPeer> {
        test_walk_ring_ex(peer_configs, neighbor_count, false)
    }

    fn test_walk_ring_pingback(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
    ) -> Vec<TestPeer> {
        test_walk_ring_ex(peer_configs, neighbor_count, true)
    }

    #[test]
    #[ignore]
    fn test_walk_line_allowed_15() {
        with_timeout(600, || {
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33100, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = -1;
                conf.denied = 0;

                conf.connection_opts.timeout = 100000;
                conf.connection_opts.handshake_timeout = 100000;
                conf.connection_opts.disable_natpunch = true; // breaks allow checks

                peer_configs.push(conf);
            }

            test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_line_15_plain() {
        with_timeout(600, || {
            // initial peers are neither white- nor denied
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33200, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;

                peer_configs.push(conf);
            }

            test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_line_15_org_biased() {
        with_timeout(600, || {
            // one outlier peer has a different org than the others.
            use std::env;

            // ::33300 is in AS 1
            env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33300", "1");

            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3; // make this a little bigger to speed this test up
            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33300, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;
                if i == 0 {
                    conf.asn = 1;
                    conf.org = 1;
                } else {
                    conf.asn = 0;
                    conf.org = 0;
                }

                peer_configs.push(conf);
            }
            // all peers see peer ::33300 as having ASN and Org ID 1
            let peer_0 = peer_configs[0].to_neighbor();

            let peers = test_walk_line(&mut peer_configs, NEIGHBOR_COUNT, 0);

            for i in 1..PEER_COUNT {
                match PeerDB::get_peer(
                    peers[i].network.peerdb.conn(),
                    peer_0.addr.network_id,
                    &peer_0.addr.addrbytes,
                    peer_0.addr.port,
                )
                .unwrap()
                {
                    Some(p) => {
                        assert_eq!(p.asn, 1);
                        assert_eq!(p.org, 1);
                    }
                    None => {}
                }
            }

            // no peer pruned peer ::33300
            for i in 1..PEER_COUNT {
                match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                    None => {}
                    Some(count) => {
                        assert_eq!(*count, 0);
                    }
                }
            }
        })
    }

    #[test]
    #[ignore]
    fn test_walk_line_15_pingback() {
        with_timeout(600, || {
            // initial peers are neither white- nor denied
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33350, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;
                conf.connection_opts.disable_pingbacks = false;
                conf.connection_opts.disable_inbound_walks = true;

                peer_configs.push(conf);
            }

            test_walk_line_pingback(&mut peer_configs, NEIGHBOR_COUNT, TEST_IN_OUT_DEGREES);
        })
    }

    fn test_walk_line(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
        tests: u64,
    ) -> Vec<TestPeer> {
        test_walk_line_ex(peer_configs, neighbor_count, tests, false)
    }

    fn test_walk_line_pingback(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
        tests: u64,
    ) -> Vec<TestPeer> {
        test_walk_line_ex(peer_configs, neighbor_count, tests, true)
    }

    fn test_walk_line_ex(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
        tests: u64,
        pingback_test: bool,
    ) -> Vec<TestPeer> {
        // arrange neighbors into a "line" topology.
        // If pingback_test is true, then the topology is unidirectional:
        //
        // 0 ---> 1 ---> 2 ---> ... ---> NEIGHBOR_COUNT
        //
        // If pingback_test is false, then the topology is bidirectional
        //
        // 0 <--> 1 <--> 2 <--> ... <--> NEIGHBOR_COUNT
        //
        // all initial peers are allowed
        let mut peers = vec![];

        let PEER_COUNT = peer_configs.len();
        let NEIGHBOR_COUNT = neighbor_count;
        for i in 0..PEER_COUNT - 1 {
            let n = i + 1;
            let neighbor = peer_configs[n].to_neighbor();
            peer_configs[i].add_neighbor(&neighbor);
        }

        if !pingback_test {
            for i in 1..PEER_COUNT {
                let p = i - 1;
                let neighbor = peer_configs[p].to_neighbor();
                peer_configs[i].add_neighbor(&neighbor);
            }
        }

        for i in 0..PEER_COUNT {
            let p = TestPeer::new(peer_configs[i].clone());
            peers.push(p);
        }

        run_topology_test(&mut peers, NEIGHBOR_COUNT, tests);

        // no nacks or handshake-rejects
        for i in 0..PEER_COUNT {
            for (_, convo) in peers[i].network.peers.iter() {
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::Nack)
                        .unwrap_or(&0)
                        == 0
                );
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::HandshakeReject)
                        .unwrap_or(&0)
                        == 0
                );
            }
        }

        peers
    }

    #[test]
    #[ignore]
    fn test_walk_star_allowed_15() {
        with_timeout(600, || {
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;
            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33400, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = -1; // always allowed
                conf.denied = 0;

                conf.connection_opts.timeout = 100000;
                conf.connection_opts.handshake_timeout = 100000;
                conf.connection_opts.disable_natpunch = true; // breaks allow checks

                peer_configs.push(conf);
            }

            test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_star_15_plain() {
        with_timeout(600, || {
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;
            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33500, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;

                peer_configs.push(conf);
            }

            test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_star_15_pingback() {
        with_timeout(600, || {
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;
            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33550, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;
                conf.connection_opts.disable_pingbacks = false;
                conf.connection_opts.disable_inbound_walks = true;
                conf.connection_opts.soft_max_neighbors_per_org = PEER_COUNT as u64;

                peer_configs.push(conf);
            }

            test_walk_star_pingback(&mut peer_configs, NEIGHBOR_COUNT);
        })
    }

    #[test]
    #[ignore]
    fn test_walk_star_15_org_biased() {
        with_timeout(600, || {
            // one outlier peer has a different org than the others.
            use std::env;

            // ::33600 is in AS 1
            env::set_var("BLOCKSTACK_NEIGHBOR_TEST_33600", "1");

            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 3;
            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33600, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;
                if i == 0 {
                    conf.asn = 1;
                    conf.org = 1;
                } else {
                    conf.asn = 0;
                    conf.org = 0;
                }

                peer_configs.push(conf);
            }
            // all peers see peer ::33600 as having ASN and Org ID 1
            let peer_0 = peer_configs[0].to_neighbor();

            let peers = test_walk_star(&mut peer_configs, NEIGHBOR_COUNT);

            for i in 1..PEER_COUNT {
                match PeerDB::get_peer(
                    peers[i].network.peerdb.conn(),
                    peer_0.addr.network_id,
                    &peer_0.addr.addrbytes,
                    peer_0.addr.port,
                )
                .unwrap()
                {
                    Some(p) => {
                        assert_eq!(p.asn, 1);
                        assert_eq!(p.org, 1);
                    }
                    None => {}
                }
            }

            // no peer pruned peer ::33600
            for i in 1..PEER_COUNT {
                match peers[i].network.prune_inbound_counts.get(&peer_0.addr) {
                    None => {}
                    Some(count) => {
                        assert_eq!(*count, 0);
                    }
                }
            }
        })
    }

    fn test_walk_star(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
    ) -> Vec<TestPeer> {
        test_walk_star_ex(peer_configs, neighbor_count, false)
    }

    fn test_walk_star_pingback(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
    ) -> Vec<TestPeer> {
        test_walk_star_ex(peer_configs, neighbor_count, true)
    }

    fn test_walk_star_ex(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
        pingback_test: bool,
    ) -> Vec<TestPeer> {
        // arrange neighbors into a "star" topology.
        // If pingback_test is true, then initial connections are unidirectional -- each neighbor (except
        // for 0) only knows about 0.  Neighbor 0 knows about no one.
        // If pingback_test is false, then initial connections are bidirectional.

        let mut peers = vec![];
        let PEER_COUNT = peer_configs.len();
        let NEIGHBOR_COUNT = neighbor_count;

        for i in 1..PEER_COUNT {
            let neighbor = peer_configs[i].to_neighbor();
            let hub = peer_configs[0].to_neighbor();
            if !pingback_test {
                peer_configs[0].add_neighbor(&neighbor);
            }

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
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::Nack)
                        .unwrap_or(&0)
                        == 0
                );
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::HandshakeReject)
                        .unwrap_or(&0)
                        == 0
                );
            }
        }

        peers
    }

    fn test_walk_inbound_line(
        peer_configs: &mut Vec<TestPeerConfig>,
        neighbor_count: usize,
    ) -> Vec<TestPeer> {
        // arrange neighbors into a two-tiered "line" topology, where even-numbered neighbors are
        // "NAT'ed" but connected to both the predecessor and successor odd neighbors.  Odd
        // numbered neighbors are not connected to anyone.  The first and last even-numbered
        // neighbor is only connected to its successor and predecessor, respectively.
        //
        //    1     3     5
        //   ^ ^   ^ ^   ^ ^
        //  /   \ /   \ /   \   ... etc ...
        // 0     2     4     6
        //
        // The goal of this test is that odd-numbered neighbors all learn about each other

        let mut peers = vec![];
        let PEER_COUNT = peer_configs.len();
        let NEIGHBOR_COUNT = neighbor_count;

        for i in 0..PEER_COUNT {
            if i % 2 == 0 {
                if i > 0 {
                    let predecessor = peer_configs[i - 1].to_neighbor();
                    peer_configs[i].add_neighbor(&predecessor);
                }
                if i + 1 < PEER_COUNT {
                    let successor = peer_configs[i + 1].to_neighbor();
                    peer_configs[i].add_neighbor(&successor);
                }
            }
        }

        for i in 0..PEER_COUNT {
            let p = TestPeer::new(peer_configs[i].clone());
            peers.push(p);
        }

        run_topology_test_ex(
            &mut peers,
            NEIGHBOR_COUNT,
            0,
            |peers: &Vec<TestPeer>| {
                let mut done = true;
                for i in 0..PEER_COUNT {
                    // only check "public" peers
                    if i % 2 != 0 {
                        let all_neighbors =
                            PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
                        if (all_neighbors.len() as u64) < ((PEER_COUNT / 2 - 1) as u64) {
                            let nk = peers[i].config.to_neighbor().addr;
                            test_debug!(
                                "waiting for public peer {:?} to fill up its frontier: {}",
                                &nk,
                                all_neighbors.len()
                            );
                            done = false;
                        }
                    }
                }
                done
            },
            true,
        );

        // no nacks or handshake-rejects
        for i in 0..PEER_COUNT {
            for (_, convo) in peers[i].network.peers.iter() {
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::Nack)
                        .unwrap_or(&0)
                        == 0
                );
                assert!(
                    *convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::HandshakeReject)
                        .unwrap_or(&0)
                        == 0
                );
            }
        }

        peers
    }

    #[test]
    #[ignore]
    fn test_walk_inbound_line_15() {
        with_timeout(600, || {
            let mut peer_configs = vec![];
            let PEER_COUNT: usize = 15;
            let NEIGHBOR_COUNT: usize = 15; // make this test go faster

            for i in 0..PEER_COUNT {
                let mut conf = setup_peer_config(i, 33250, NEIGHBOR_COUNT, PEER_COUNT);

                conf.allowed = 0;
                conf.denied = 0;
                conf.connection_opts.disable_pingbacks = true;
                conf.connection_opts.disable_inbound_walks = false;
                conf.connection_opts.walk_inbound_ratio = 2;
                // basically, don't timeout (so public nodes can ask non-public inbound nodes about
                // neighbors indefinitely)
                conf.connection_opts.connect_timeout = 60000;
                conf.connection_opts.timeout = 60000;
                conf.connection_opts.handshake_timeout = 60000;
                conf.connection_opts.soft_max_neighbors_per_org = (NEIGHBOR_COUNT + 1) as u64;
                conf.connection_opts.soft_max_neighbors_per_host = (NEIGHBOR_COUNT + 1) as u64;

                peer_configs.push(conf);
            }

            test_walk_inbound_line(&mut peer_configs, NEIGHBOR_COUNT);
        })
    }

    fn dump_peers(peers: &Vec<TestPeer>) -> () {
        test_debug!("\n=== PEER DUMP ===");
        for i in 0..peers.len() {
            let mut neighbor_index = vec![];
            let mut outbound_neighbor_index = vec![];
            for j in 0..peers.len() {
                let stats_opt = peers[i]
                    .network
                    .get_neighbor_stats(&peers[j].to_neighbor().addr);
                match stats_opt {
                    Some(stats) => {
                        neighbor_index.push(j);
                        if stats.outbound {
                            outbound_neighbor_index.push(j);
                        }
                    }
                    None => {}
                }
            }

            let all_neighbors = PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
            let num_allowed = all_neighbors.iter().fold(0, |mut sum, ref n2| {
                sum += if n2.allowed < 0 { 1 } else { 0 };
                sum
            });
            test_debug!("Neighbor {} (all={}, outbound={}) (total neighbors = {}, total allowed = {}): outbound={:?} all={:?}", i, neighbor_index.len(), outbound_neighbor_index.len(), all_neighbors.len(), num_allowed, &outbound_neighbor_index, &neighbor_index);
        }
        test_debug!("\n");
    }

    fn dump_peer_histograms(peers: &Vec<TestPeer>) -> () {
        let mut outbound_hist: HashMap<usize, usize> = HashMap::new();
        let mut inbound_hist: HashMap<usize, usize> = HashMap::new();
        let mut all_hist: HashMap<usize, usize> = HashMap::new();
        for i in 0..peers.len() {
            let mut neighbor_index = vec![];
            let mut inbound_neighbor_index = vec![];
            let mut outbound_neighbor_index = vec![];
            for j in 0..peers.len() {
                let stats_opt = peers[i]
                    .network
                    .get_neighbor_stats(&peers[j].to_neighbor().addr);
                match stats_opt {
                    Some(stats) => {
                        neighbor_index.push(j);
                        if stats.outbound {
                            outbound_neighbor_index.push(j);
                        } else {
                            inbound_neighbor_index.push(j);
                        }
                    }
                    None => {}
                }
            }
            for inbound in inbound_neighbor_index.iter() {
                if inbound_hist.contains_key(inbound) {
                    let c = inbound_hist.get(inbound).unwrap().to_owned();
                    inbound_hist.insert(*inbound, c + 1);
                } else {
                    inbound_hist.insert(*inbound, 1);
                }
            }
            for outbound in outbound_neighbor_index.iter() {
                if outbound_hist.contains_key(outbound) {
                    let c = outbound_hist.get(outbound).unwrap().to_owned();
                    outbound_hist.insert(*outbound, c + 1);
                } else {
                    outbound_hist.insert(*outbound, 1);
                }
            }
            for n in neighbor_index.iter() {
                if all_hist.contains_key(n) {
                    let c = all_hist.get(n).unwrap().to_owned();
                    all_hist.insert(*n, c + 1);
                } else {
                    all_hist.insert(*n, 1);
                }
            }
        }

        test_debug!("=== PEER HISTOGRAM ===");
        for i in 0..peers.len() {
            test_debug!(
                "Neighbor {}: #in={} #out={} #all={}",
                i,
                inbound_hist.get(&i).unwrap_or(&0),
                outbound_hist.get(&i).unwrap_or(&0),
                all_hist.get(&i).unwrap_or(&0)
            );
        }
        test_debug!("\n");
    }

    fn run_topology_test(peers: &mut Vec<TestPeer>, neighbor_count: usize, test_bits: u64) -> () {
        run_topology_test_ex(peers, neighbor_count, test_bits, |_| false, false)
    }

    fn run_topology_test_ex<F>(
        peers: &mut Vec<TestPeer>,
        neighbor_count: usize,
        test_bits: u64,
        mut finished_check: F,
        use_finished_check: bool,
    ) -> ()
    where
        F: FnMut(&Vec<TestPeer>) -> bool,
    {
        let PEER_COUNT = peers.len();

        let mut initial_allowed: HashMap<NeighborKey, Vec<NeighborKey>> = HashMap::new();
        let mut initial_denied: HashMap<NeighborKey, Vec<NeighborKey>> = HashMap::new();

        for i in 0..PEER_COUNT {
            // turn off components we don't need
            peers[i].config.connection_opts.disable_inv_sync = true;
            peers[i].config.connection_opts.disable_block_download = true;
            let nk = peers[i].config.to_neighbor().addr.clone();
            for j in 0..peers[i].config.initial_neighbors.len() {
                let initial = &peers[i].config.initial_neighbors[j];
                if initial.allowed < 0 {
                    if !initial_allowed.contains_key(&nk) {
                        initial_allowed.insert(nk.clone(), vec![]);
                    }
                    initial_allowed
                        .get_mut(&nk)
                        .unwrap()
                        .push(initial.addr.clone());
                }
                if initial.denied < 0 {
                    if !initial_denied.contains_key(&nk) {
                        initial_denied.insert(nk.clone(), vec![]);
                    }
                    initial_denied
                        .get_mut(&nk)
                        .unwrap()
                        .push(initial.addr.clone());
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
            let mut random_order = vec![0usize; PEER_COUNT];
            for i in 0..PEER_COUNT {
                random_order[i] = i;
            }
            let mut rng = thread_rng();
            let _ = &mut &random_order.shuffle(&mut rng);

            for i in random_order.into_iter() {
                let _ = peers[i].step();
                let nk = peers[i].config.to_neighbor().addr;

                // allowed peers are still connected
                match initial_allowed.get(&nk) {
                    Some(ref peer_list) => {
                        for pnk in peer_list.iter() {
                            if !peers[i].network.events.contains_key(&pnk.clone()) {
                                error!(
                                    "{:?}: Perma-allowed peer {:?} not connected anymore",
                                    &nk, &pnk
                                );
                                assert!(false);
                            }
                        }
                    }
                    None => {}
                };

                // denied peers are never connected
                match initial_denied.get(&nk) {
                    Some(ref peer_list) => {
                        for pnk in peer_list.iter() {
                            if peers[i].network.events.contains_key(&pnk.clone()) {
                                error!("{:?}: Perma-denied peer {:?} connected", &nk, &pnk);
                                assert!(false);
                            }
                        }
                    }
                    None => {}
                };

                // all ports are unique in the p2p socket table
                let mut ports: HashSet<u16> = HashSet::new();
                for k in peers[i].network.events.keys() {
                    if ports.contains(&k.port) {
                        error!("duplicate port {} from {:?}", k.port, k);
                        assert!(false);
                    }
                    ports.insert(k.port);
                }

                // done?
                finished = if use_finished_check {
                    finished_check(&peers)
                } else {
                    let mut done = true;
                    let all_neighbors =
                        PeerDB::get_all_peers(peers[i].network.peerdb.conn()).unwrap();
                    peer_counts += all_neighbors.len();
                    if (all_neighbors.len() as u64) < ((PEER_COUNT - 1) as u64) {
                        let nk = peers[i].config.to_neighbor().addr;
                        test_debug!(
                            "waiting for {:?} to fill up its frontier: {}",
                            &nk,
                            all_neighbors.len()
                        );
                        done = false;
                    }
                    done
                };
            }

            count += 1;

            test_debug!(
                "Network convergence rate: {}%",
                (100.0 * (peer_counts as f64)) / ((PEER_COUNT * PEER_COUNT) as f64)
            );

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
