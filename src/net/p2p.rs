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

use net::connection::Connection;
use net::connection::ConnectionOptions;
use net::connection::NetworkReplyHandle;

use net::chat::Conversation;
use net::chat::NeighborStats;

use net::poll::NetworkState;
use net::poll::NetworkPollState;

use net::db::LocalPeer;

use net::neighbors::*;

use util::db::Error as db_error;
use util::db::DBConn;

use util::secp256k1::Secp256k1PublicKey;

use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SendError;
use std::sync::mpsc::RecvError;
use std::sync::mpsc::TryRecvError;

use std::net::SocketAddr;

use std::collections::VecDeque;
use std::collections::HashMap;
use std::collections::HashSet;

use burnchains::Address;
use burnchains::PublicKey;
use burnchains::Burnchain;
use burnchains::BurnchainView;

use chainstate::burn::db::burndb;

use util::log;
use util::get_epoch_time_secs;

use rand::prelude::*;
use rand::thread_rng;

use mio;
use mio::net as mio_net;

/// inter-thread request to send a message from another thread in this program.
pub struct NetworkRequest {
    neighbors: Vec<NeighborKey>,
    message: Option<StacksMessage>,
    expect_reply: bool,
    ttl: u64,
    connect: bool,                      // if true, then only connect to the neighbor.
}

/// Handle for other threads to use to issue network requests.
/// The "main loop" for sending/receiving data is a select/poll loop, and runs outside of other
/// threads that need a synchronous RPC or a multi-RPC interface.  This object gives those threads
/// a way to issue commands and hear back replies from them.
pub struct NetworkHandle {
    chan_in: SyncSender<NetworkRequest>,
    chan_out: Receiver<Result<Option<NetworkReplyHandle>, net_error>>
}

/// Internal handle for receiving requests from a NetworkHandle.
/// This is the 'other end' of a NetworkHandle inside the peer network struct.
struct NetworkHandleServer {
    chan_in: Receiver<NetworkRequest>,
    chan_out: SyncSender<Result<Option<NetworkReplyHandle>, net_error>>
}

impl NetworkHandle {
    pub fn new(chan_in: SyncSender<NetworkRequest>, chan_out: Receiver<Result<Option<NetworkReplyHandle>, net_error>>) -> NetworkHandle {
        NetworkHandle {
            chan_in: chan_in,
            chan_out: chan_out
        }
    }

    /// Connect to a remote peer 
    pub fn connect_peer(&mut self, neighbor_key: &NeighborKey) -> Result<(), net_error> {
        let req = NetworkRequest {
            neighbors: vec![(*neighbor_key).clone()],
            message: None,
            expect_reply: false,
            ttl: 0,
            connect: true,
        };
        self.chan_in.send(req).map_err(|_e| net_error::InvalidHandle)?;
        let res = self.chan_out.recv().map_err(|_e| net_error::InvalidHandle)?;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    /// Disconnect a remote peer 
    pub fn disconnect_peer(&mut self, neighbor_key: &NeighborKey) -> Result<(), net_error> {
        let req = NetworkRequest {
            neighbors: vec![(*neighbor_key).clone()],
            message: None,
            expect_reply: false,
            ttl: 0,
            connect: false,
        };
        self.chan_in.send(req).map_err(|_e| net_error::InvalidHandle)?;
        let res = self.chan_out.recv().map_err(|_e| net_error::InvalidHandle)?;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    /// Sends the message to the p2p network thread and gets back a reply handle the calling thread
    /// can wait on.
    pub fn send_signed_message(&mut self, neighbor_key: &NeighborKey, msg: StacksMessage, ttl: u64) -> Result<NetworkReplyHandle, net_error> {
        let req = NetworkRequest {
            neighbors: vec![(*neighbor_key).clone()],
            message: Some(msg),
            expect_reply: true,
            ttl: ttl,
            connect: false,
        };
        self.chan_in.send(req).map_err(|_e| net_error::InvalidHandle)?;
        let reply = self.chan_out.recv().map_err(|_e| net_error::InvalidHandle)?;
        match reply {
            Ok(handle_opt) => {
                match handle_opt {
                    Some(handle) => Ok(handle),
                    None => panic!("Did not receive a NetworkReplyHandle as expected")
                }
            },
            Err(e) => Err(e)
        }
    }

    /// Relay a message to a peer via the p2p network thread, expecting no reply.
    pub fn relay_signed_message(&mut self, neighbor_key: &NeighborKey, msg: StacksMessage) -> Result<(), net_error> {
        let req = NetworkRequest {
            neighbors: vec![(*neighbor_key).clone()],
            message: Some(msg),
            expect_reply: false,
            ttl: 0,
            connect: false,
        };
        self.chan_in.send(req).map_err(|_e| net_error::InvalidHandle)?;
        let res = self.chan_out.recv().map_err(|_e| net_error::InvalidHandle)?;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    /// Broadcast a message to our neighbors via the p2p network thread.
    pub fn broadcast_signed_message(&mut self, neighbors: &Vec<NeighborKey>, msg: StacksMessage) -> Result<(), net_error> {
        let req = NetworkRequest {
            neighbors: neighbors.clone(),
            message: Some(msg),
            expect_reply: false,
            ttl: 0,
            connect: false,
        };
        self.chan_in.send(req).map_err(|_e| net_error::InvalidHandle)?;
        let res = self.chan_out.recv().map_err(|_e| net_error::InvalidHandle)?;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }
}

impl NetworkHandleServer {
    pub fn new(chan_in: Receiver<NetworkRequest>, chan_out: SyncSender<Result<Option<NetworkReplyHandle>, net_error>>) -> NetworkHandleServer {
        NetworkHandleServer {
            chan_in: chan_in,
            chan_out: chan_out
        }
    }

    pub fn pair() -> (NetworkHandleServer, NetworkHandle) {
        let (msg_send, msg_recv) = sync_channel(1);
        let (handle_send, handle_recv) = sync_channel(1);
        let server = NetworkHandleServer::new(msg_recv, handle_send);
        let client = NetworkHandle::new(msg_send, handle_recv);
        (server, client)
    }
}

pub struct PeerNetwork {
    pub peerdb: PeerDB,

    // ongoing conversations (either they reached out to us, or we to them)
    peers: HashMap<usize, Conversation>,
    sockets: HashMap<usize, mio_net::TcpStream>,
    events: HashMap<NeighborKey, usize>,

    // handles for other threads to send/receive data to peers
    handles: VecDeque<NetworkHandleServer>,

    // network I/O
    network: Option<NetworkState>,

    // info on the burn chain we're tracking 
    pub burnchain: Burnchain,

    // connection options
    pub connection_opts: ConnectionOptions,

    // neighbor walk state 
    pub walk: Option<NeighborWalk>,
    pub frontier: HashSet<NeighborKey>
}

impl PeerNetwork {
    pub fn new(peerdb: PeerDB, burnchain: &Burnchain, connection_opts: &ConnectionOptions) -> PeerNetwork {
        PeerNetwork {
            peerdb: peerdb,
            peers: HashMap::new(),
            sockets: HashMap::new(),
            events: HashMap::new(),

            handles: VecDeque::new(),
            network: None,

            burnchain: burnchain.clone(),
            connection_opts: connection_opts.clone(),
            walk: None,
            frontier: HashSet::new()
        }
    }

    pub fn init(peerdb_path: &String, block_height: u64, burnchain: &Burnchain, connection_opts: &ConnectionOptions, asn4_path: &Option<String>) -> Result<PeerNetwork, net_error> {
        let peerdb = PeerDB::connect(peerdb_path, true, block_height + connection_opts.private_key_lifetime, asn4_path, None)
            .map_err(|_e| net_error::DBError)?;

        Ok(PeerNetwork::new(peerdb, burnchain, connection_opts))
    }

    /// start serving
    pub fn bind(&mut self, my_addr: &SocketAddr) -> Result<(), net_error> {
        let net = NetworkState::bind(my_addr, 1000)?;
        self.network = Some(net);
        Ok(())
    }
    
    /// Create a network handle for another thread to use to communicate with remote peers
    pub fn new_handle(&mut self) -> NetworkHandle {
        let (server, client) = NetworkHandleServer::pair();
        self.handles.push_back(server);
        client
    }

    /// Send a message at the request of another thread 
    pub fn dispatch_send_message(&mut self, neighbor_key: &NeighborKey, message: StacksMessage, ttl: u64) -> Result<NetworkReplyHandle, net_error> {
        let neighbor = neighbor_key.to_normalized();

        let event_id_opt = self.events.get(&neighbor);
        if event_id_opt.is_none() {
            warn!("Not connected to {:?}", &neighbor);
            return Err(net_error::NoSuchNeighbor);
        }

        let event_id = event_id_opt.unwrap();
        let convo_opt = self.peers.get_mut(event_id);
        if convo_opt.is_none() {
            warn!("No ongoing conversation with {:?}", &neighbor);
            return Err(net_error::PeerNotConnected);
        }

        let convo = convo_opt.unwrap();
        convo.send_signed_message(message, ttl)
    }

    /// Relay a message at the request of another thread 
    pub fn dispatch_relay_message(&mut self, neighbor_key: &NeighborKey, message: StacksMessage) -> Result<(), net_error> {
        let neighbor = neighbor_key.to_normalized();

        let event_id_opt = self.events.get(&neighbor);
        if event_id_opt.is_none() {
            warn!("Not connected to {:?}", &neighbor);
            return Err(net_error::NoSuchNeighbor);
        }

        let event_id = event_id_opt.unwrap();
        let convo_opt = self.peers.get_mut(event_id);
        if convo_opt.is_none() {
            warn!("No ongoing conversation with {:?}", &neighbor);
            return Err(net_error::PeerNotConnected);
        }

        let convo = convo_opt.unwrap();
        convo.relay_signed_message(message)
    }

    /// Broadcast a message at the request of another thread 
    pub fn dispatch_broadcast_message(&mut self, neighbor_keys: &Vec<NeighborKey>, message: StacksMessage) -> () {
        for neighbor_key in neighbor_keys {
            let neighbor = neighbor_key.to_normalized();

            let res = self.dispatch_relay_message(&neighbor, message.clone());
            match res {
                Ok(_) => {},
                Err(e) => {
                    warn!("Failed to broadcast message to {:?}: {:?}", &neighbor, &e);
                }
            };
        }
    }

    /// Connect to a peer at the request of another thread 
    pub fn dispatch_connect_peer(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, neighbor: &NeighborKey) -> Result<(), net_error> {
        let (sock, next_event_id) = match self.network {
            None => {
                return Err(net_error::NotConnected);
            },
            Some(ref mut network) => {
                let sock = network.connect(&neighbor.addrbytes.to_socketaddr(neighbor.port))?;
                let next_event_id = network.next_event_id();
                (sock, next_event_id)
            }
        };
        self.register(local_peer, chain_view, next_event_id, sock)
    }

    /// Disconnect from a peer at the request of another thread
    pub fn dispatch_disconnect_peer(&mut self, neighbor_key: &NeighborKey) -> () {
        let neighbor = neighbor_key.to_normalized();

        let event_id = {
            let event_id_opt = self.events.get(&neighbor);
            if event_id_opt.is_none() {
                return;
            }
            *(event_id_opt.unwrap())
        };
        self.deregister(event_id)
    }

    /// Dispatch a single request from another thread.
    /// Returns an option for a reply handle if the caller expects the peer to reply.
    fn dispatch_request(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, request: NetworkRequest) -> Result<Option<NetworkReplyHandle>, net_error> {
        let mut reply_handle = None;
        let mut send_error = None;

        match request.neighbors.len() {
            0 => {
                send_error = Some(net_error::InvalidHandle);
            }
            1 => {
                let neighbor = &request.neighbors[0];
                match request.message {
                    None => {
                        if request.connect {
                            // connect to neighbor
                            let res = self.dispatch_connect_peer(local_peer, chain_view, neighbor);
                            if res.is_err() {
                                send_error = Some(res.unwrap_err());
                            }
                        }
                        else {
                            // disconnect from neighbor
                            self.dispatch_disconnect_peer(neighbor);
                        }
                    },
                    Some(message) => {
                        // send a message to a specific neighbor, and expect a reply 
                        if request.expect_reply {
                            let rh_res = self.dispatch_send_message(neighbor, message, request.ttl);
                            match rh_res {
                                Ok(rh) => reply_handle = Some(rh),
                                Err(e) => send_error = Some(e)
                            };
                        }
                        else {
                            let rh_res = self.dispatch_relay_message(neighbor, message);
                            match rh_res {
                                Ok(_) => {},
                                Err(e) => send_error = Some(e)
                            };
                        }
                    }
                }
            },
            _ => {
                match request.message {
                    Some(message) => {
                        // broadcast message to all neighbors 
                        self.dispatch_broadcast_message(&request.neighbors, message);
                    },
                    None => {
                        // no message and no neighbor
                        send_error = Some(net_error::InvalidHandle);
                    }
                }
            }
        };

        if send_error.is_none() {
            return Ok(reply_handle);
        }
        else {
            return Err(send_error.unwrap());
        }
    }

    /// Process any handle requests from other threads.
    /// Returns the number of requests dispatched.
    fn dispatch_requests(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView) -> usize {
        let mut to_remove = vec![];
        let mut messages = vec![];
        let mut responses = vec![];
        let mut num_dispatched = 0;

        // receive all in-bound requests
        for i in 0..self.handles.len() {
            let handle_opt = self.handles.get(i);
            if handle_opt.is_none() {
                break;
            }
            let handle = handle_opt.unwrap();

            let inbound_request_res = handle.chan_in.try_recv();
            match inbound_request_res {
                Ok(inbound_request) => {
                    messages.push((i, inbound_request));
                },
                Err(TryRecvError::Empty) => {
                    // nothing to do
                },
                Err(TryRecvError::Disconnected) => {
                    // dead; remove
                    to_remove.push(i);
                }
            };
        }

        // dispatch all in-bound requests from waiting threads
        for (i, inbound_request) in messages {
            let dispatch_res = self.dispatch_request(local_peer, chain_view, inbound_request);
            responses.push((i, dispatch_res));
        }

        // send back all out-bound reply handles to waiting threads, causing them to wake up
        for (i, dispatch_res) in responses {
            let handle_opt = self.handles.get(i);
            if handle_opt.is_none() {
                continue;
            }
            let handle = handle_opt.unwrap();
            let send_res = handle.chan_out.send(dispatch_res);
            match send_res {
                Ok(_) => {
                    num_dispatched += 1;
                }
                Err(_e) => {
                    // channel disconnected; remove
                    to_remove.push(i);
                }
            };
        }

        // clear out dead handles
        to_remove.reverse();
        for i in to_remove {
            self.handles.remove(i);
        }

        num_dispatched
    }

    /// Get the stored, non-expired public key for a remote peer (if we know of it)
    fn lookup_peer(&self, cur_block_height: u64, peer_addr: &SocketAddr) -> Result<Option<Neighbor>, net_error> {
        let conn = self.peerdb.conn();
        let addrbytes = PeerAddress::from_socketaddr(peer_addr);
        let neighbor_opt = PeerDB::get_peer(conn, self.burnchain.network_id, &addrbytes, peer_addr.port())
            .map_err(|e| net_error::DBError)?;

        match neighbor_opt {
            None => Ok(None),
            Some(neighbor) => {
                if neighbor.expire_block < cur_block_height {
                    Ok(Some(neighbor))
                }
                else {
                    Ok(None)
                }
            }
        }
    }

    /// Get number of inbound connections we're servicing
    pub fn num_peers(&self) -> usize {
        self.sockets.len()
    }
    
    /// Register a socket/event pair.
    fn register(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, event_id: usize, socket: mio_net::TcpStream) -> Result<(), net_error> {
        let client_addr = socket.peer_addr()
            .map_err(|e| {
                warn!("Failed to get peer address of {:?}: {:?}", &socket, &e);
                net_error::SocketError
            })?;

        let neighbor_opt = self.lookup_peer(chain_view.burn_block_height, &client_addr)?;
        let (pubkey_opt, neighbor_key) = match neighbor_opt {
            Some(neighbor) => (Some(neighbor.public_key.clone()), neighbor.addr.clone()),
            None => (None, NeighborKey::from_socketaddr(0, 0, &client_addr))
        };

        let convo = match self.network {
            None => {
                return Err(net_error::NotConnected);
            },
            Some(ref mut network) => {
                network.register(event_id, &socket)?;
                Conversation::new(&self.burnchain, &client_addr, &self.connection_opts)
            }
        };

        self.sockets.insert(event_id, socket);
        self.peers.insert(event_id, convo);
        self.events.insert(neighbor_key.clone(), event_id);
        Ok(())
    }

    /// Are we connected to a neighbor?
    pub fn is_registered(&self, neighbor_key: &NeighborKey) -> bool {
        let neighbor = neighbor_key.to_normalized();
        self.events.contains_key(&neighbor)
    }

    /// Deregister a socket/event pair 
    fn deregister(&mut self, event_id: usize) -> () {
        if self.peers.contains_key(&event_id) {
            self.peers.remove(&event_id);
        }
        let mut to_remove = vec![];
        for (neighbor_key, ev_id) in self.events.iter() {
            if *ev_id == event_id {
                to_remove.push(neighbor_key.clone());
            }
        }
        for nk in to_remove {
            self.events.remove(&nk);
        }

        let mut to_remove = vec![];
        match self.network {
            None => {},
            Some(ref mut network) => {
                match self.sockets.get_mut(&event_id) {
                    None => {},
                    Some(ref sock) => {
                        let res = network.deregister(sock);
                        match res {
                            Ok(_) => {},
                            Err(e) => {
                                warn!("Failed to deregister {:?}: {:?}", &sock, &e);
                            }
                        };

                        to_remove.push(event_id);
                    }
                }
            }
        }

        for event_id in to_remove {
            self.sockets.remove(&event_id);
        }
    }

    /// Deregister by neighbor key 
    fn deregister_neighbor(&mut self, neighbor_key: &NeighborKey) -> () {
        let neighbor = neighbor_key.to_normalized();
        let event_id = match self.events.get(&neighbor) {
            None => {
                return;
            }
            Some(eid) => *eid
        };
        self.deregister(event_id)
    }

    /// Sign a message to be sent to a particular peer we're having a conversation with
    pub fn sign_for_peer(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, peer_key: &NeighborKey, message_payload: StacksMessageType) -> Result<StacksMessage, net_error> {
        match self.events.get(peer_key) {
            None => {
                // not connected 
                Err(net_error::PeerNotConnected)
            },
            Some(event_id) => {
                match self.peers.get_mut(&event_id) {
                    None => {
                        Err(net_error::PeerNotConnected)
                    },
                    Some(ref mut convo) => {
                        convo.sign_message(chain_view, &local_peer.private_key, message_payload)
                    }
                }
            }
        }
    }
    
    /// Process new TCP connections we just accepted.
    /// Returns the event IDs of sockets we need to register
    fn process_new_sockets(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, poll_state: &mut NetworkPollState) -> Vec<usize> {
        let mut registered = vec![];

        for (event_id, client_sock) in poll_state.new.drain() {
            // event ID already used?
            if self.peers.contains_key(&event_id) {
                continue;
            }
            let res = self.register(local_peer, chain_view, event_id, client_sock);
            match res {
                Err(e) => {
                    continue;
                }
                Ok(_) => {
                    registered.push(event_id);
                }
            }
        }
    
        registered
    }

    /// Process sockets that are ready.
    /// Advance the state of all conversations ongoing with remote peers.
    /// Return the list of events that correspond to failed conversations, as well as the set of
    /// unsolicited messages grouped by event_id.
    fn process_ready_sockets(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, burndb_conn: &DBConn, poll_state: &mut NetworkPollState) -> (Vec<usize>, HashMap<usize, Vec<StacksMessage>>) {
        let mut to_remove = vec![];
        let mut unsolicited = HashMap::new();
        for event_id in &poll_state.ready {
            if !self.sockets.contains_key(&event_id) {
                warn!("Rogue socket event {}", event_id);
                to_remove.push(*event_id);
                continue;
            }

            let client_sock_opt = self.sockets.get_mut(&event_id);
            if client_sock_opt.is_none() {
                warn!("No such socket event {}", event_id);
                to_remove.push(*event_id);
                continue;
            }
            let client_sock = client_sock_opt.unwrap();

            if !self.peers.contains_key(&event_id) {
                // not sure what to do with this 
                warn!("Rogue socket event {} on {:?}: no ongoing conversation", event_id, &client_sock);
                to_remove.push(*event_id);
                continue;
            }
            let mut convo = self.peers.get_mut(&event_id).unwrap();

            // get incoming bytes and update the state of this conversation.
            let recv_res = convo.recv(client_sock);
            match recv_res {
                Err(e) => {
                    info!("Failed to receive data on event {} (socket {:?}): {:?}", event_id, &client_sock, &e);
                    to_remove.push(*event_id);
                    continue;
                },
                Ok(_) => {}
            }

            // react to inbound messages -- do we need to send something out?
            let mut chat_res = convo.chat(local_peer, burndb_conn, chain_view);
            match chat_res {
                Err(e) => {
                    info!("Failed to converse with event {} (socket {:?}): {:?}", event_id, &client_sock, &e);
                    to_remove.push(*event_id);
                    continue;
                },
                Ok(ref mut u) => {
                    if !unsolicited.contains_key(event_id) {
                        unsolicited.insert(*event_id, vec![]);
                    }

                    unsolicited.get_mut(event_id).unwrap().append(u);
                }
            }

            // send out data in this conversation
            let send_res = convo.send(client_sock);
            match send_res {
                Err(e) => {
                    info!("Failed to send data to event {} (socket {:?}): {:?}", event_id, &client_sock, &e);
                    to_remove.push(*event_id);
                    continue;
                },
                Ok(_) => {}
            }
        }

        (to_remove, unsolicited)
    }

    /// Queue a reply to a GetNeighbors
    fn handle_getneighbors(dbconn: &DBConn, burnchain: &Burnchain, local_peer: &LocalPeer, chain_view: &BurnchainView, convo: &mut Conversation, getneighbors_msg: &StacksMessage) -> Result<(), net_error> {
        // get neighbors at random as long as they're fresh
        let neighbors = PeerDB::get_random_neighbors(dbconn, burnchain.network_id, MAX_NEIGHBORS_DATA_LEN, chain_view.burn_block_height, false)
            .map_err(|e| net_error::DBError)?;

        let neighbor_addrs = neighbors
            .iter()
            .map(|n| NeighborAddress::from_neighbor(n))
            .collect();
        
        let payload = StacksMessageType::Neighbors( NeighborsData { neighbors: neighbor_addrs } );
        let reply = convo.sign_reply(chain_view, &local_peer.private_key, payload, getneighbors_msg.preamble.seq)?;
        convo.relay_signed_message(reply)
            .map_err(|e| {
                info!("Outbox to {:?}:{:?} is full; cannot reply to GetNeighbors", &convo.peer_addrbytes, convo.peer_port);
                e
            })
    }

    /// Reply to requests for information
    /// Return messages that we could not handle in this module
    fn handle_data_requests(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, mut unsolicited_messages: HashMap<usize, Vec<StacksMessage>>) -> HashMap<usize, Vec<StacksMessage>> {
        let mut unhandled_messages = HashMap::new();
        for (event_id, mut msgs) in unsolicited_messages.drain() {
            match self.peers.get_mut(&event_id) {
                None => {
                    continue;
                },
                Some(ref mut convo) => {
                    for msg in msgs.drain(0..) {
                        match msg.payload {
                            StacksMessageType::GetNeighbors => {
                                let res = PeerNetwork::handle_getneighbors(self.peerdb.conn(), &self.burnchain, local_peer, chain_view, convo, &msg);
                                match res {
                                    Ok(()) => {},
                                    Err(e) => {
                                        info!("Failed to handle GetNeighbors from {:?}:{:?}: {:?}", &convo.peer_addrbytes, convo.peer_port, &e);
                                        if unhandled_messages.contains_key(&event_id) {
                                            unhandled_messages.insert(event_id, vec![]);
                                        }

                                        unhandled_messages.get_mut(&event_id).unwrap().push(msg);
                                    }
                                };
                            },
                            /* TODO: handle blocks and transactions */
                            _ => {
                                if unhandled_messages.contains_key(&event_id) {
                                    unhandled_messages.insert(event_id, vec![]);
                                }

                                unhandled_messages.get_mut(&event_id).unwrap().push(msg);
                            }
                        }
                    }
                }
            }
        }

        unhandled_messages
    }

    /// Get stats for a neighbor 
    pub fn get_neighbor_stats(&self, nk: &NeighborKey) -> Option<NeighborStats> {
        let neighbor = nk.to_normalized();
        match self.events.get(&neighbor) {
            None => {
                None
            }
            Some(eid) => {
                match self.peers.get(&eid) {
                    None => {
                        None
                    },
                    Some(ref convo) => {
                        Some(convo.stats.clone())
                    }
                }
            }
        }
    }

    /// Get a neighbor from the peer DB
    pub fn get_neighbor(&self, dbconn: &DBConn, nk: &NeighborKey) -> Result<Option<Neighbor>, net_error> {
        let neighbor = nk.to_normalized();
        match self.events.get(&neighbor) {
            None => {
                Ok(None)
            }
            Some(eid) => {
                match self.peers.get(&eid) {
                    None => {
                        Ok(None)
                    },
                    Some(ref convo) => {
                        Neighbor::from_conversation(dbconn, convo)
                    }
                }
            }
        }
    }

    /// Sample a drop probability 
    fn sample_drop_probability(point: f64, drop_prob: &HashMap<NeighborKey, f64>) -> NeighborKey {
        let mut normalized_dist = vec![];
        let mut sum = 0.0;
        let mut off = 0.0;
        for (_, v) in drop_prob.iter() {
            sum += v;
        }

        for (k, v) in drop_prob.iter() {
            normalized_dist.push((k.clone(), v / sum + off));
            off += v / sum;
        }

        for (nk, p) in normalized_dist.iter() {
            if point >= *p {
                return nk.clone();
            }
        }
        return normalized_dist[normalized_dist.len()-1].0.clone();
    }

    /// Prune our frontier
    /// -- If we have too many outbound connections, then prune them based on how fresh they are
    /// and how diverse pruning them will leave the network.
    ///
    /// TODO: consider removing/reworking this method.  We want network diversity, and we want to
    /// avoid putting too much favor on new peers.  But, do we want hard limits?
    fn prune_frontier(&mut self) -> () {
        // assign each node in our frontier a drop probability,
        // based on how recently it was discovered and how redundant it is
        // regarding peer diversity.
        let mut rng = thread_rng();
        while self.events.len() > NUM_NEIGHBORS { 
            let mut node_stats : HashMap<NeighborKey, NeighborStats> = HashMap::new();
            let mut neighbors : HashMap<NeighborKey, Neighbor> = HashMap::new();
            let mut drop_uptime_probs : HashMap<NeighborKey, f64> = HashMap::new();
            let mut drop_diversity_probs : HashMap<NeighborKey, f64> = HashMap::new();
            let mut asn_counts : HashMap<u32, u64> = HashMap::new();
            let mut dead = vec![];
            
            for (nk, _) in self.events.iter() {
                let stats_opt = self.get_neighbor_stats(nk);
                match stats_opt {
                    None => {
                        // dead 
                        dead.push(nk.clone());
                    }
                    Some(stats) => {
                        node_stats.insert(nk.clone(), stats);
                    }
                }

                let neighbor_opt = match self.get_neighbor(self.peerdb.conn(), nk) {
                    Ok(nopt) => nopt,
                    Err(_e) => None
                };

                match neighbor_opt {
                    None => {
                        // dead 
                        dead.push(nk.clone());
                    }
                    Some(neighbor) => {
                        neighbors.insert(nk.clone(), neighbor);
                    }
                }
            }

            let mut oldest_first_contact = get_epoch_time_secs() as u64;
            for (nk, stats) in node_stats.iter() {
                if stats.first_contact_time < oldest_first_contact {
                    oldest_first_contact = stats.first_contact_time;
                }
            }

            for (nk, neighbor) in neighbors.iter() {
                let asn_count = match asn_counts.get(&neighbor.asn) {
                    Some(c) => c + 1,
                    None => 0
                };
                asn_counts.insert(neighbor.asn, asn_count);
            }

            for (nk, stats) in node_stats.iter() {
                // Pr[online now] ~ uptime
                // Pr[drop] ~ 1/uptime
                let drop_uptime_prob = 1.0 / ((oldest_first_contact - stats.first_contact_time) as f64);
                drop_uptime_probs.insert(nk.clone(), drop_uptime_prob);
            }

            for (nk, neighbor) in neighbors.iter() {
                // Pr[drop] ~ #(AS's this neighbor represents) / #(AS's total)
                let drop_diversity_prob = (*(asn_counts.get(&neighbor.asn).unwrap_or(&1)) as f64) / (asn_counts.len() as f64);
                drop_diversity_probs.insert(nk.clone(), drop_diversity_prob);
            }

            // flip a coin.
            // If heads, use uptime drop probability.
            // If tails, use ASN diversity probability.
            let coin : f64 = rng.gen();
            let selection : f64 = rng.gen();
            let drop_probs = if coin <= 0.5 { &drop_uptime_probs } else { &drop_diversity_probs };
            let drop = PeerNetwork::sample_drop_probability(selection, drop_probs);

            info!("Prune {:?}", &drop);
            self.deregister_neighbor(&drop);
        }
    }

    /// Update peer connections as a result of a peer graph walk.
    /// -- Drop broken connections.
    /// -- Update our frontier.
    /// -- Prune our frontier if it gets too big.
    fn process_neighbor_walk(&mut self, walk_result: NeighborWalkResult) -> () {
        for broken in walk_result.broken_connections {
            self.deregister_neighbor(&broken);
        }

        for replaced in walk_result.replaced_neighbors {
            self.deregister_neighbor(&replaced);
        }

        // if our frontier gets too big, then we need to prune it 
        self.prune_frontier();
    }

    /// Send pings to everyone we haven't spoken to in a while to let them know that we're still
    /// alive.
    fn send_heartbeats(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView) -> () {
        let now = get_epoch_time_secs();
        for (event_id, convo) in self.peers.iter_mut() {
            if convo.stats.last_send_time + (convo.peer_heartbeat as u64) + NEIGHBOR_REQUEST_TIMEOUT < now {
                // haven't talked to this neighbor in a while
                let payload = StacksMessageType::Ping(PingData::new());
                let ping_res = convo.sign_message(chain_view, &local_peer.private_key, payload);

                match ping_res {
                    Ok(ping) => {
                        // NOTE: use "relay" here because we don't intend to wait for a reply
                        // (the conversational logic will update our measure of this node's uptime)
                        match convo.relay_signed_message(ping) {
                            Ok(_) => {},
                            Err(_e) => {
                                info!("Outbox to {:?}:{:?} is full; cannot ping", &convo.peer_addrbytes, convo.peer_port);
                            }
                        };
                    },
                    Err(e) => {
                        info!("Unable to create ping message for {:?}:{:?}: {:?}", &convo.peer_addrbytes, convo.peer_port, &e);
                    }
                };
            }
        }
    }

    /// Remove unresponsive peers
    fn disconnect_unresponsive(&mut self) -> () {
        let now = get_epoch_time_secs();
        let mut to_remove = vec![];
        for (event_id, convo) in self.peers.iter() {
            if convo.stats.last_recv_time + (convo.heartbeat as u64) + NEIGHBOR_REQUEST_TIMEOUT < now {
                // haven't heard from this peer in too long a time 
                info!("Disconnect unresponsive peer {:?}:{:?}", &convo.peer_addrbytes, convo.peer_port);
                to_remove.push(*event_id);
            }
        }

        for event_id in to_remove.drain(0..) {
            self.deregister(event_id);
        }
    }

    /// Update networking state.
    /// -- accept new connections
    /// -- send data on ready sockets
    /// -- receive data on ready sockets
    /// -- clear out timed-out requests
    /// Returns the list of unsolicited peer messages
    fn dispatch_network(&mut self, burndb_conn: &DBConn, mut poll_state: NetworkPollState) -> Result<HashMap<usize, Vec<StacksMessage>>, net_error> {
        if self.network.is_none() {
            return Err(net_error::NotConnected);
        }
        
        let local_peer = PeerDB::get_local_peer(self.peerdb.conn())
            .map_err(|e| net_error::DBError)?;

        let chain_view = burndb::get_burnchain_view(burndb_conn, &self.burnchain)
            .map_err(|e| net_error::DBError)?;

        // set up new conversations
        self.process_new_sockets(&local_peer, &chain_view, &mut poll_state);

        // run existing conversations, clear out broken ones, and get back messages forwarded to us
        let (dead_events, unsolicited_messages) = self.process_ready_sockets(&local_peer, &chain_view, burndb_conn, &mut poll_state);
        for dead_event in dead_events {
            self.deregister(dead_event);
        }

        // reply to any data requests
        let unhandled_messages = self.handle_data_requests(&local_peer, &chain_view, unsolicited_messages);

        // handle network I/O requests from other threads, and get back reply handles to them
        self.dispatch_requests(&local_peer, &chain_view);

        // walk the peer graph and deal with new/dropped connections
        let walk_result_opt = self.walk_peer_graph(&local_peer, &chain_view);
        match walk_result_opt {
            None => {},
            Some(walk_result) => {
                self.process_neighbor_walk(walk_result);
            }
        }

        // remove timed-out requests from other threads 
        for (_, convo) in self.peers.iter_mut() {
            convo.connection.drain_timeouts();
        }
        
        // ping neighbors we haven't spoken to in a while
        self.send_heartbeats(&local_peer, &chain_view);
        
        // clear out peers that we haven't heard from in our heartbeat interval
        self.disconnect_unresponsive();

        Ok(unhandled_messages)
    }

    /// Top-level main-loop circuit to take.
    /// -- polls the peer network state to get new sockets and detect ready sockets
    /// -- carries out network conversations
    /// -- receives and dispatches requests from other threads
    /// Returns the list of unsolicited network messages to be acted upon.
    pub fn run(&mut self, burndb_conn: &DBConn) -> Result<HashMap<usize, Vec<StacksMessage>>, net_error> {
        let poll_state = match self.network {
            None => {
                Err(net_error::NotConnected)
            },
            Some(ref mut network) => {
                network.poll(1000)
            }
        }?;

        let unsolicited_messages = self.dispatch_network(burndb_conn, poll_state)?;
        Ok(unsolicited_messages)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use net::*;
    use net::db::*;
    use net::codec::*;
    use std::thread;
    use std::time;
    use util::log;
    use burnchains::*;
    use burnchains::burnchain::*;

    #[test]
    fn dispatch_requests_relay() {
        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef0,
                addrbytes: PeerAddress([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x7f,0x00,0x00,0x01]),
                port: 32100,
            },
            public_key: Secp256k1PublicKey::from_hex("02fa66b66f8971a8cd4d20ffded09674e030f0f33883f337f34b95ad4935bac0e3").unwrap(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            whitelisted: -1,
            blacklisted: -1,
            asn: 34567,
            org: 45678,
            in_degree: 1,
            out_degree: 1
        };

        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;

        let burnchain = Burnchain {
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: get_burn_quota_config(&"bitcoin".to_string()).unwrap(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7
        };

        let burnchain_view = BurnchainView {
            burn_block_height: 12345,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12339,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
        };

        let ping = StacksMessage::new(0x9abcdef0,
                                      burnchain_view.burn_block_height,
                                      &burnchain_view.burn_consensus_hash,
                                      burnchain_view.burn_stable_block_height,
                                      &burnchain_view.burn_stable_consensus_hash,
                                      StacksMessageType::Ping(PingData::new()));

        let db = PeerDB::connect_memory(12345, &vec![], &vec![neighbor.clone()]).unwrap();
        let thread_local_peer = PeerDB::get_local_peer(db.conn()).unwrap();

        let mut p2p = PeerNetwork::new(db, &burnchain, &conn_opts);

        let mut h = p2p.new_handle();

        let thread_burnchain_view = burnchain_view.clone();

        // start fake endpoint, which will accept once and wait 5 seconds
        let endpoint_thread = thread::spawn(move || {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:32100").unwrap();
            let (sock, addr) = listener.accept().unwrap();
            test_debug!("Accepted {:?}", &addr);
            thread::sleep(time::Duration::from_millis(5000));
        });

        // start dispatcher
        let p2p_thread = thread::spawn(move || {
            p2p.bind(&"127.0.0.1:32000".parse().unwrap()).unwrap();
            for i in 0..3 {
                test_debug!("dispatch batch {}", i);
                let dispatch_count = p2p.dispatch_requests(&thread_local_peer, &thread_burnchain_view);
                if dispatch_count >= 1 {
                    test_debug!("Dispatched {} requests", dispatch_count);
                }
                thread::sleep(time::Duration::from_millis(1000));
            }
        });

        h.connect_peer(&neighbor.addr.clone()).unwrap();
        h.relay_signed_message(&neighbor.addr.clone(), ping.clone()).unwrap();

        // should be unable to relay to a nonexistent neighbor
        let nonexistent_neighbor = NeighborKey {
            peer_version: 0x12345678,
            network_id: 0x9abcdef0,
            addrbytes: PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]),
            port: 12346,
        };

        let res = h.relay_signed_message(&nonexistent_neighbor, ping.clone());
        assert_eq!(res, Err(net_error::NoSuchNeighbor));

        p2p_thread.join().unwrap();
        test_debug!("dispatcher thread joined");

        endpoint_thread.join().unwrap();
        test_debug!("fake endpoint thread joined");
    }
}
