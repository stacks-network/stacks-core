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

use net::StacksMessage;

use net::connection::Connection;
use net::connection::ConnectionOptions;
use net::connection::NetworkReplyHandle;

use util::db::Error as db_error;
use util::db::DBConn;

use util::secp256k1::Secp256k1PublicKey;

use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SendError;
use std::sync::mpsc::RecvError;
use std::sync::mpsc::TryRecvError;

use std::collections::VecDeque;
use std::collections::HashMap;

use util::log;

pub const NUM_NEIGHBORS : u32 = 32;

/// state of a neighbor
struct NeighborState {
    neighbor: Neighbor,     // used for analytics
    connection: Connection
}

pub struct NetworkRequest {
    neighbor: Option<NeighborKey>,     // if None, then broadcast
    message: StacksMessage,
    expect_reply: bool
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

impl NeighborState {
    pub fn new(neighbor: &Neighbor, con_opts: &ConnectionOptions) -> NeighborState {
        NeighborState {
            neighbor: neighbor.clone(),
            connection: Connection::new(neighbor, con_opts)
        }
    }
}   

impl NetworkHandle {
    pub fn new(chan_in: SyncSender<NetworkRequest>, chan_out: Receiver<Result<Option<NetworkReplyHandle>, net_error>>) -> NetworkHandle {
        NetworkHandle {
            chan_in: chan_in,
            chan_out: chan_out
        }
    }

    /// Send a message and expect a reply.
    /// Get back a reply handle that can be used to wait for the reply.
    pub fn send_signed_message(&mut self, neighbor_key: &NeighborKey, msg: StacksMessage) -> Result<NetworkReplyHandle, net_error> {
        let req = NetworkRequest {
            neighbor: Some((*neighbor_key).clone()),
            message: msg,
            expect_reply: true
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

    /// Relay a message to a peer, expecting no reply.
    pub fn relay_signed_message(&mut self, neighbor_key: &NeighborKey, msg: StacksMessage) -> Result<(), net_error> {
        let req = NetworkRequest {
            neighbor: Some((*neighbor_key).clone()),
            message: msg,
            expect_reply: false
        };
        self.chan_in.send(req).map_err(|_e| net_error::InvalidHandle)?;
        let res = self.chan_out.recv().map_err(|_e| net_error::InvalidHandle)?;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }

    /// Broadcast a message to our neighbors.
    pub fn broadcast_signed_message(&mut self, msg: StacksMessage) -> Result<(), net_error> {
        let req = NetworkRequest {
            neighbor: None,
            message: msg,
            expect_reply: false
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
    neighbors: HashMap<NeighborKey, NeighborState>,
    db: PeerDB,

    cur_neighbor: Option<Neighbor>,
    cur_neighbor_frontier: Option<Vec<Neighbor>>,

    // handles for other threads to send/receive data to neighbors
    handles: VecDeque<NetworkHandleServer>
}

impl PeerNetwork {
    pub fn new(db: PeerDB, initial_neighbors: &Vec<Neighbor>, connection_opts: &ConnectionOptions) -> PeerNetwork {
        let mut neighbor_statemap = HashMap::new();
        for neighbor in initial_neighbors {
            let neighbor_key = neighbor.addr.clone();
            let neighbor_state = NeighborState::new(neighbor, connection_opts);

            neighbor_statemap.insert(neighbor_key, neighbor_state);
        }

        PeerNetwork {
            db: db,
            neighbors: neighbor_statemap,

            cur_neighbor: None,
            cur_neighbor_frontier: None,

            handles: VecDeque::new(),
        }
    }

    pub fn init(db_path: &String, network_id: u32, block_height: u64, connection_opts: &ConnectionOptions, asn4_path: &Option<String>, initial_neighbors: &Option<Vec<Neighbor>>) -> Result<PeerNetwork, net_error> {
        let db = PeerDB::connect(db_path, true, asn4_path, initial_neighbors)
            .map_err(|_e| net_error::DBError)?;

        let initial_neighbors = PeerDB::get_initial_neighbors(db.conn(), network_id, NUM_NEIGHBORS, block_height)
            .map_err(|_e| net_error::DBError)?;

        Ok(PeerNetwork::new(db, &initial_neighbors, connection_opts))
    }
    
    /// Create a network handle for another thread to use to send/receive peer messages
    pub fn new_handle(&mut self) -> NetworkHandle {
        let (server, client) = NetworkHandleServer::pair();
        self.handles.push_back(server);
        client
    }

    /// Dispatch a single request from another thread.
    /// Returns an option for a reply handle if the caller expects the peer to reply.
    fn dispatch_request(&mut self, request: NetworkRequest) -> Result<Option<NetworkReplyHandle>, net_error> {
        let mut reply_handle = None;
        let mut send_error = None;

        match request.neighbor {
            Some(neighbor) => {
                // send to a specific neighbor
                let mut neighbor_state_opt = self.neighbors.get_mut(&neighbor);
                match neighbor_state_opt {
                    Some(ref mut neighbor_state) => {
                        // connected to this neighbor.
                        let mut conn = &mut neighbor_state.connection;
                        if request.expect_reply {
                            test_debug!("Send signed message to {:?}", neighbor);
                            let rh_res = conn.send_signed_message(request.message);
                            match rh_res {
                                Ok(rh) => reply_handle = Some(rh),
                                Err(e) => send_error = Some(e)
                            };
                        }
                        else {
                            test_debug!("Relay signed message to {:?}", neighbor);
                            let relay_res = conn.relay_signed_message(request.message);
                            match relay_res {
                                Ok(_) => {},
                                Err(e) => send_error = Some(e)
                            };
                        }
                    },
                    None => {
                        // not connected to this neighbor anymore
                        test_debug!("No such neighbor: {:?}", neighbor);
                        send_error = Some(net_error::NoSuchNeighbor);
                    }
                }
            },
            None => {
                // broadcast to all neighbors 
                test_debug!("Broadcast signed message to {} neighbors", self.neighbors.len());
                for neighbor_state in self.neighbors.values_mut() {
                    let relay_res = (*neighbor_state).connection.relay_signed_message(request.message.clone());
                    match relay_res {
                        Ok(_) => {},
                        Err(e) => send_error = Some(e)
                    };
                }
            }
        }

        if send_error.is_none() {
            return Ok(reply_handle);
        }
        else {
            return Err(send_error.unwrap());
        }
    }

    /// Process any handle requests from other threads.
    pub fn dispatch_requests(&mut self) -> usize {
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

        // dispatch all in-bound requests
        for (i, inbound_request) in messages {
            let dispatch_res = self.dispatch_request(inbound_request);
            responses.push((i, dispatch_res));
        }

        // send back all out-bound replies
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

    #[test]
    fn relay_signed_message() {
        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef01,
                addrbytes: PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]),
                port: 12345,
            },
            public_key: Secp256k1PublicKey::from_hex("02fa66b66f8971a8cd4d20ffded09674e030f0f33883f337f34b95ad4935bac0e3").unwrap(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            whitelisted: -1,
            blacklisted: -1,
            asn: 34567,
            org: 45678,
            in_degree: 0,
            out_degree: 0
        };

        let conn_opts = ConnectionOptions {
            keepalive: 60,
            nodelay: true,
            inbox_maxlen: 5,
            outbox_maxlen: 5
        };

        let mut ping = StacksMessage::new(0x9abcdef01,
                                          12345,
                                          &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                          12339,
                                          &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                          StacksMessageType::Ping);

        let db = PeerDB::connect_memory(&vec![], &vec![neighbor.clone()]).unwrap();
        let mut p2p = PeerNetwork::new(db, &vec![neighbor.clone()], &conn_opts);

        let mut h = p2p.new_handle();

        // start dispatcher
        let p2p_thread = thread::spawn(move || {
            for i in 0..3 {
                test_debug!("dispatch batch {}", i);
                let dispatch_count = p2p.dispatch_requests();
                if dispatch_count >= 1 {
                    test_debug!("Dispatched {} requests", dispatch_count);
                }
                thread::sleep(time::Duration::from_millis(1000));
            }
        });
       
        h.relay_signed_message(&neighbor.addr.clone(), ping.clone()).unwrap();

        // should be unable to relay to a nonexistent neighbor
        let nonexistent_neighbor = NeighborKey {
            peer_version: 0x12345678,
            network_id: 0x9abcdef01,
            addrbytes: PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]),
            port: 12346,
        };

        let res = h.relay_signed_message(&nonexistent_neighbor, ping.clone());
        assert_eq!(res, Err(net_error::NoSuchNeighbor));

        p2p_thread.join().unwrap();
    }
}
