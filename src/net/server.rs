/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

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

use std::io::{Read, Write};
use std::io::Error as io_error;
use std::io::ErrorKind;

use std::collections::HashMap;
use std::collections::VecDeque;

use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SendError;
use std::sync::mpsc::RecvError;
use std::sync::mpsc::TryRecvError;

use net::Error as net_error;
use net::*;
use net::connection::*;
use net::db::*;
use net::poll::*;
use net::rpc::*;
use net::http::*;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::stacks::db::StacksChainState;

use burnchains::Burnchain;
use burnchains::BurnchainView;

use mio::net as mio_net;

use util::get_epoch_time_secs;

pub struct HttpPeer {
    pub network_id: u32,
    pub chain_view: BurnchainView,

    // ongoing http conversations (either they reached out to us, or we to them)
    pub peers: HashMap<usize, ConversationHttp>,
    pub sockets: HashMap<usize, mio_net::TcpStream>,

    // outbound connections that are pending connection 
    pub connecting: HashMap<usize, (mio_net::TcpStream, Option<UrlString>, Option<HttpRequestType>)>,

    // network I/O
    network: Option<NetworkState>,

    // info on the burn chain we're tracking 
    pub burnchain: Burnchain,

    // connection options
    pub connection_opts: ConnectionOptions,
}

impl HttpPeer {
    pub fn new(network_id: u32, burnchain: Burnchain, chain_view: BurnchainView, conn_opts: ConnectionOptions) -> HttpPeer {
        HttpPeer {
            network_id: network_id,
            chain_view: chain_view,
            peers: HashMap::new(),
            sockets: HashMap::new(),

            connecting: HashMap::new(),

            network: None,

            burnchain: burnchain,
            connection_opts: conn_opts
        }
    }

    /// start serving
    pub fn bind(&mut self, my_addr: &SocketAddr, max_sockets: usize) -> Result<(), net_error> {
        let net = NetworkState::bind(my_addr, max_sockets)?;
        self.network = Some(net);
        Ok(())
    }

    /// Is there a HTTP conversation open to this data_url that is not in progress?
    pub fn find_free_conversation(&self, data_url: &UrlString) -> Option<usize> {
        for (event_id, convo) in self.peers.iter() {
            if let Some(ref url) = convo.get_url() {
                if *url == data_url && !convo.is_request_inflight() {
                    return Some(*event_id);
                }
            }
        }
        None
    }

    /// Get a mut ref to a conversation
    pub fn get_conversation(&mut self, event_id: usize) -> Option<&mut ConversationHttp> {
        self.peers.get_mut(&event_id)
    }

    /// Connect to a new remote HTTP endpoint, given the data URL and a (resolved) socket address to
    /// its origin.  Once connected, optionally send the given request.
    /// Idempotent -- will not re-connect if already connected and there is a free conversation channel open 
    /// (will return Error::AlreadyConnected with the event ID)
    pub fn connect_http(&mut self, data_url: UrlString, addr: SocketAddr, request: Option<HttpRequestType>) -> Result<usize, net_error> {
        if let Some(event_id) = self.find_free_conversation(&data_url) {
            return Err(net_error::AlreadyConnected(event_id));
        }

        let (sock, next_event_id) = match self.network {
            None => {
                test_debug!("HTTP not connected");
                return Err(net_error::NotConnected);
            },
            Some(ref mut network) => {
                let sock = network.connect(&addr)?;
                let next_event_id = network.next_event_id();
                network.register(next_event_id, &sock)?;
                (sock, next_event_id)
            }
        };

        self.connecting.insert(next_event_id, (sock, Some(data_url), request));
        Ok(next_event_id)
    }

    /// How many conversations are connected from this IP address?
    fn count_inbound_ip_addrs(&self, peer_addr: &SocketAddr) -> u64 {
        let mut count = 0;
        for (_, convo) in self.peers.iter() {
            if convo.get_url().is_none() && convo.get_peer_addr().ip() == peer_addr.ip() {
                count += 1;
            }
        }
        count
    }

    /// Can we register this socket?
    fn can_register_http(&self, peer_addr: &SocketAddr, outbound_url: Option<&UrlString>) -> Result<(), net_error> {
        if outbound_url.is_none() && (self.peers.len() as u64) + 1 > self.connection_opts.num_clients {
            // inbound
            debug!("HTTP: too many inbound peers total");
            return Err(net_error::TooManyPeers);
        }

        // how many other conversations are connected?
        if self.count_inbound_ip_addrs(peer_addr) > self.connection_opts.max_clients_per_host {
            // too many 
            debug!("HTTP: too many inbound peers from {:?}", peer_addr);
            return Err(net_error::TooManyPeers);
        }

        test_debug!("HTTP: Have {} peers now (max {}) inbound={}", self.peers.len(), self.connection_opts.num_clients, outbound_url.is_none());
        Ok(())
    }

    /// remove a socket from our poller
    fn deregister_socket(&mut self, socket: mio_net::TcpStream) -> () {
        match self.network {
            Some(ref mut network) => {
                let _ = network.deregister(&socket);
            }
            None => {}
        }
    }

    /// Low-level method to register a socket/event pair on the p2p network interface.
    /// Call only once the socket is connected (called once the socket triggers ready).
    /// Will destroy the socket if we can't register for whatever reason.
    fn register_http(&mut self, event_id: usize, socket: mio_net::TcpStream, outbound_url: Option<UrlString>, initial_request: Option<HttpRequestType>) -> Result<(), net_error> {
        let client_addr = match socket.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Failed to get peer address of {:?}: {:?}", &socket, &e);
                return Err(net_error::SocketError);
            }
        };

        match self.can_register_http(&client_addr, outbound_url.as_ref()) {
            Ok(_) => {},
            Err(e) => {
                self.deregister_socket(socket);
                return Err(e);
            }
        }
        
        let peer_host = match outbound_url {
            Some(ref url_str) => PeerHost::try_from_url(url_str).unwrap_or(PeerHost::from_socketaddr(&client_addr)),
            None => PeerHost::from_socketaddr(&client_addr)
        };

        let mut new_convo = ConversationHttp::new(self.network_id, &self.burnchain, client_addr.clone(), outbound_url.clone(), peer_host, &self.connection_opts, event_id);
        
        test_debug!("Registered HTTP {} as event {} (outbound={:?})", &client_addr, event_id, &outbound_url);

        if let Some(request) = initial_request {
            test_debug!("Sending initial HTTP request to {}", &client_addr);
            match new_convo.send_request(request) {
                Ok(_) => {},
                Err(e) => {
                    self.deregister_socket(socket);
                    return Err(e);
                }
            }
        }

        self.sockets.insert(event_id, socket);
        self.peers.insert(event_id, new_convo);
        Ok(())
    }
    
    /// Deregister a socket/event pair
    pub fn deregister_http(&mut self, event_id: usize) -> () {
        if self.peers.contains_key(&event_id) {
            // kill the conversation
            self.peers.remove(&event_id);
        }

        let mut to_remove : Vec<usize> = vec![];
        match self.network {
            None => {},
            Some(ref mut network) => {
                match self.sockets.get_mut(&event_id) {
                    None => {},
                    Some(ref sock) => {
                        let _ = network.deregister(sock);
                        to_remove.push(event_id);   // force it to close anyway
                    }
                }
            }
        }

        for event_id in to_remove {
            // remove socket
            self.sockets.remove(&event_id);
            self.connecting.remove(&event_id);
        }
    }
    
    /// Remove slow/unresponsive peers
    fn disconnect_unresponsive(&mut self) -> () {
        let now = get_epoch_time_secs();
        let mut to_remove = vec![];
        for (event_id, convo) in self.peers.iter() {
            let mut last_request_time = convo.get_last_request_time();
            if last_request_time == 0 {
                // never got a request
                last_request_time = convo.get_connection_time();
            }

            let mut last_response_time = convo.get_last_response_time();
            if last_response_time == 0 {
                // never sent a response
                last_response_time = convo.get_connection_time();
            }
            
            if last_request_time + self.connection_opts.idle_timeout < now && last_response_time + self.connection_opts.idle_timeout < now {
                // it's been too long
                test_debug!("Removing idle HTTP conversation {:?}", convo);
                to_remove.push(*event_id);
            }
        }

        for event_id in to_remove.drain(0..) {
            self.deregister_http(event_id);
        }
    }
    
    /// Process new inbound HTTP connections we just accepted.
    /// Returns the event IDs of sockets we need to register
    fn process_new_sockets(&mut self, poll_state: &mut NetworkPollState) -> Result<Vec<usize>, net_error> {
        let mut registered = vec![];

        for (event_id, client_sock) in poll_state.new.drain() {
            // event ID already used?
            if self.peers.contains_key(&event_id) {
                continue;
            }

            match self.network {
                Some(ref mut network) => {
                    if let Err(_e) = network.register(event_id, &client_sock) {
                        continue;
                    }
                },
                None => {
                    test_debug!("HTTP not connected");
                    return Err(net_error::NotConnected);
                }
            }
            if let Err(_e) = self.register_http(event_id, client_sock, None, None) {
                continue;
            }
            registered.push(event_id);
        }
    
        Ok(registered)
    }

    /// Process network traffic on a HTTP conversation.
    /// Returns whether or not the convo is still alive.
    fn process_http_conversation(chain_view: &BurnchainView, burndb: &mut BurnDB, peerdb: &mut PeerDB, chainstate: &mut StacksChainState, event_id: usize, client_sock: &mut mio_net::TcpStream, convo: &mut ConversationHttp) -> Result<bool, net_error> {
        // get incoming bytes and update the state of this conversation.
        let mut convo_dead = false;
        let recv_res = convo.recv(client_sock);
        match recv_res {
            Err(e) => {
                match e {
                    net_error::PermanentlyDrained => {
                        // socket got closed, but we might still have pending unsolicited messages
                        debug!("Remote peer disconnected event {} (socket {:?})", event_id, &client_sock);
                    },
                    _ => {
                        debug!("Failed to receive data on event {} (socket {:?}): {:?}", event_id, &client_sock, &e);
                    }
                }
                convo_dead = true;
            },
            Ok(_) => {}
        }
    
        // react to inbound messages -- do we need to send something out, or fulfill requests
        // to other threads?  Try to chat even if the recv() failed, since we'll want to at
        // least drain the conversation inbox.
        match convo.chat(chain_view, burndb, peerdb, chainstate) {
            Ok(_) => {},
            Err(e) => {
                debug!("Failed to converse on event {} (socket {:?}): {:?}", event_id, &client_sock, &e);
                convo_dead = true;
            }
        }

        if !convo_dead {
            // (continue) sending out data in this conversation, if the conversation is still
            // ongoing
            match convo.send(client_sock) {
                Ok(_) => {},
                Err(e) => {
                    debug!("Failed to send data to event {} (socket {:?}): {:?}", event_id, &client_sock, &e);
                    convo_dead = true;
                }
            }
        }

        Ok(!convo_dead)
    }

    /// Process sockets that are ready, but specifically inbound or outbound only.
    /// Advance the state of all such conversations with remote peers.
    /// Return the list of events that correspond to failed conversations
    fn process_ready_sockets(&mut self, poll_state: &mut NetworkPollState, burndb: &mut BurnDB, peerdb: &mut PeerDB, chainstate: &mut StacksChainState) -> Vec<usize> {
        let mut to_remove = vec![];
        for event_id in &poll_state.ready {
            if self.connecting.contains_key(event_id) {
                let (socket, data_url, initial_request_opt) = self.connecting.remove(event_id).unwrap();
                debug!("Event {} connected ({:?})", event_id, &data_url);

                if let Err(_e) = self.register_http(*event_id, socket, data_url.clone(), initial_request_opt) {
                    debug!("Failed to register HTTP connection ({}, {:?})", event_id, data_url);
                    to_remove.push(*event_id);
                    continue;
                }
            }

            if !self.sockets.contains_key(&event_id) {
                test_debug!("Rogue socket event {}", event_id);
                to_remove.push(*event_id);
                continue;
            }

            let client_sock_opt = self.sockets.get_mut(&event_id);
            if client_sock_opt.is_none() {
                test_debug!("No such socket event {}", event_id);
                to_remove.push(*event_id);
                continue;
            }
            let client_sock = client_sock_opt.unwrap();

            match self.peers.get_mut(event_id) {
                Some(ref mut convo) => {
                    // activity on a http socket
                    test_debug!("Process HTTP data from {:?}", convo);
                    match HttpPeer::process_http_conversation(&self.chain_view, burndb, peerdb, chainstate, *event_id, client_sock, convo) {
                        Ok(alive) => {
                            if !alive {
                                to_remove.push(*event_id);
                            }
                        },
                        Err(_e) => {
                            to_remove.push(*event_id);
                            continue;
                        }
                    };
                },
                None => {
                    warn!("Rogue event {} for socket {:?}", event_id, &client_sock);
                    to_remove.push(*event_id);
                }
            }
        }

        to_remove
    }

    /// Make progress on sending any/all new outbound messages we have.
    /// Meant to prime sockets so we wake up on the next loop pass immediately to finish sending.
    fn send_outbound_messages(&mut self) -> Vec<usize> {
        let mut to_remove = vec![];
        for (event_id, convo) in self.peers.iter_mut() {
            if !self.sockets.contains_key(&event_id) {
                test_debug!("Rogue socket event {}", event_id);
                to_remove.push(*event_id);
                continue;
            }

            let client_sock_opt = self.sockets.get_mut(&event_id);
            if client_sock_opt.is_none() {
                test_debug!("No such socket event {}", event_id);
                to_remove.push(*event_id);
                continue;
            }
            let client_sock = client_sock_opt.unwrap();
            let send_res = convo.send(client_sock);
            match send_res {
                Err(e) => {
                    debug!("Failed to send data to event {} (socket {:?}): {:?}", event_id, &client_sock, &e);
                    to_remove.push(*event_id);
                    continue;
                },
                Ok(_) => {}
            }
        }
        to_remove
    }
    
    /// Flush outgoing replies, but don't block.
    /// Drop broken handles.
    /// Return the list of conversation event IDs to close (i.e. they're broken, or the request is done)
    fn flush_conversations(&mut self, chainstate: &mut StacksChainState) -> Vec<usize> {
        let mut close = vec![];

        // flush each outgoing conversation 
        for (event_id, ref mut convo) in self.peers.iter_mut() {
            match convo.try_flush(chainstate) {
                Ok(_) => {},
                Err(_e) => {
                    info!("Broken connection {:?}: {:?}", convo, &_e);
                    close.push(*event_id);
                }
            }

            if convo.is_drained() && !convo.is_keep_alive() {
                // did some work, but nothing more to do and we're not keep-alive
                test_debug!("Close drained connection {:?}", convo);
                close.push(*event_id);
            }
        }

        close
    }
    
    /// Update HTTP server state
    /// -- accept new connections
    /// -- send data on ready sockets
    /// -- receive data on ready sockets
    /// -- clear out timed-out requests
    fn dispatch_network(&mut self, new_chain_view: BurnchainView, burndb: &mut BurnDB, peerdb: &mut PeerDB, chainstate: &mut StacksChainState, mut poll_state: NetworkPollState) -> Result<(), net_error> {
        if self.network.is_none() {
            test_debug!("HTTP not connected");
            return Err(net_error::NotConnected);
        }

        // update burnchain snapshot
        self.chain_view = new_chain_view;

        // set up new inbound conversations
        self.process_new_sockets(&mut poll_state)?;

        // run existing conversations, clear out broken ones, and get back messages forwarded to us
        let error_events = self.process_ready_sockets(&mut poll_state, burndb, peerdb, chainstate);
        for error_event in error_events {
            debug!("Failed HTTP connection on event {}", error_event);
            self.deregister_http(error_event);
        }

        // move conversations along
        let close_events = self.flush_conversations(chainstate);
        for close_event in close_events {
            debug!("Close HTTP connection on event {}", close_event);
            self.deregister_http(close_event);
        }

        // remove timed-out requests 
        for (_, convo) in self.peers.iter_mut() {
            convo.clear_timeouts();
        }
        
        // clear out slow or non-responsive peers
        self.disconnect_unresponsive();

        // send out any queued messages.
        // this has the intentional side-effect of activating some sockets as writeable.
        let error_outbound_events = self.send_outbound_messages();
        for error_event in error_outbound_events {
            debug!("Failed HTTP connection on event {}", error_event);
            self.deregister_http(error_event);
        }
     
        Ok(())
    }

    /// Top-level main-loop circuit to take for http server and clients.
    /// -- polls the http server state to get new sockets and detect ready sockets
    /// -- carries out http network conversations
    pub fn run(&mut self, new_chain_view: BurnchainView, burndb: &mut BurnDB, peerdb: &mut PeerDB, chainstate: &mut StacksChainState, poll_timeout: u64) -> Result<(), net_error> {
        let poll_state = match self.network {
            None => {
                test_debug!("HTTP not connected");
                Err(net_error::NotConnected)
            },
            Some(ref mut network) => {
                network.poll(poll_timeout)
            }
        }?;

        self.dispatch_network(new_chain_view, burndb, peerdb, chainstate, poll_state)
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use super::*;
    use net::*;
    use net::codec::*;
    use net::test::*;
    use net::http::*;
    use net::rpc::*;
    
    use burnchains::Burnchain;
    use burnchains::BurnchainView;
    use burnchains::BurnchainHeaderHash;

    use chainstate::burn::db::burndb::BurnDB;
    use chainstate::burn::BlockHeaderHash;
    use chainstate::stacks::*;
    use chainstate::stacks::test::*;
    use chainstate::stacks::db::StacksChainState;
    use chainstate::stacks::db::BlockStreamData;
    use chainstate::stacks::db::blocks::test::*;
    use chainstate::stacks::Error as chain_error;
    use chainstate::stacks::*;
    use burnchains::*;

    use std::sync::mpsc::SyncSender;
    use std::sync::mpsc::Receiver;
    use std::sync::mpsc::sync_channel;
    use std::sync::mpsc::SendError;
    use std::sync::mpsc::RecvError;
    use std::sync::mpsc::TryRecvError;
    
    use std::thread;

    use std::net::SocketAddr;
    use std::net::TcpStream;
   
    use util::pipe::*;
    use util::get_epoch_time_secs;
    use util::sleep_ms;
    
    use vm::contracts::Contract;
    use vm::types::*;
    use vm::representations::ContractName;
    use vm::representations::ClarityName;

    fn test_http_server<F, C>(test_name: &str, peer_p2p: u16, peer_http: u16, conn_opts: ConnectionOptions, num_clients: usize, client_sleep: u64, mut make_request: F, check_result: C) -> ()
    where
        F: FnMut(usize, &mut TestPeer) -> Vec<u8>,
        C: Fn(usize, Result<Vec<u8>, net_error>) -> bool
    {
        let peer_config = TestPeerConfig::new(test_name, peer_p2p, peer_http);
        let mut peer = TestPeer::new(peer_config);
        let view = peer.get_burnchain_view().unwrap();

        let mut http_server = HttpPeer::new(0x9abcdef, peer.config.burnchain.clone(), view.clone(), conn_opts);
        http_server.bind(&format!("0.0.0.0:{}", peer_http).parse::<SocketAddr>().unwrap(), 1000).unwrap();

        let (http_sx, http_rx) = sync_channel(1);

        let mut client_requests = vec![];
        let mut client_threads = vec![];
        let mut client_handles = vec![];
        for i in 0..num_clients {
            let request = make_request(i, &mut peer);
            client_requests.push(request);
        }

        let http_thread = thread::spawn(move || {
            let view = peer.get_burnchain_view().unwrap();
            loop {
                test_debug!("http wakeup");

                let mut burndb = peer.burndb.take().unwrap();
                let mut stacks_node = peer.stacks_node.take().unwrap();
                http_server.run(view.clone(), &mut burndb, &mut peer.network.peerdb, &mut stacks_node.chainstate, 100).unwrap();
                peer.burndb = Some(burndb);
                peer.stacks_node = Some(stacks_node);

                // asked to yield?
                match http_rx.try_recv() {
                    Ok(_) => {
                        break;
                    },
                    Err(_) => {}
                }
            }

            test_debug!("http server joined");
        });

        for (i, request) in client_requests.drain(..).enumerate() {
            let (client_sx, client_rx) = sync_channel(1);
            let client = thread::spawn(move || {
                let mut sock = TcpStream::connect(&format!("127.0.0.1:{}", peer_http).parse::<SocketAddr>().unwrap()).unwrap();

                if client_sleep > 0 {
                    sleep_ms(client_sleep * 1000);
                }

                match sock.write_all(&request) {
                    Ok(_) => {},
                    Err(e) => {
                        test_debug!("Client {} failed to write: {:?}", i, &e);
                        client_sx.send(Err(net_error::WriteError(e))).unwrap();
                        return;
                    }
                }

                let mut resp = vec![];
                match sock.read_to_end(&mut resp) {
                    Ok(_) => {},
                    Err(e) => {
                        test_debug!("Client {} failed to read: {:?}", i, &e);
                        client_sx.send(Err(net_error::ReadError(e))).unwrap();
                        return;
                    }
                }

                test_debug!("Client {} received {} bytes", i, resp.len());
                client_sx.send(Ok(resp)).unwrap();
            });
            client_threads.push(client);
            client_handles.push(client_rx);
        }

        for (i, client_thread) in client_threads.drain(..).enumerate() {
            test_debug!("Client join {}", i);
            client_thread.join().unwrap();
            let resp = client_handles[i].recv().unwrap();
            assert!(check_result(i, resp));
        }

        http_sx.send(true).unwrap();
        http_thread.join().unwrap();
    }

    #[test]
    fn test_http_getinfo() {
        test_http_server("test_http_getinfo", 51000, 51001, ConnectionOptions::default(), 1, 0,
                        |client_id, _| {
                            let mut request = HttpRequestType::GetInfo(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51001)));
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            // should be a PeerInfo
                            let http_response_bytes = http_response_bytes_res.unwrap();
                            let response = StacksHttp::parse_response("/v2/info", &http_response_bytes).unwrap();
                            true
                        });
    }
    
    #[test]
    fn test_http_10_threads_getinfo() {
        test_http_server("test_http_10_threads_getinfo", 51010, 51011, ConnectionOptions::default(), 10, 0,
                        |client_id, _| {
                            let mut request = HttpRequestType::GetInfo(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51011)));
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            // should be a PeerInfo
                            let http_response_bytes = http_response_bytes_res.unwrap();
                            let response = StacksHttp::parse_response("/v2/info", &http_response_bytes).unwrap();
                            true
                        });
    }

    #[test]
    fn test_http_getblock() {
        test_http_server("test_http_getblock", 51020, 51021, ConnectionOptions::default(), 1, 0,
                        |client_id, ref mut peer_server| {
                            let peer_server_block = make_codec_test_block(25);
                            let peer_server_burn_block_hash = BurnchainHeaderHash([(client_id+1) as u8; 32]);
                            let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block.block_hash());

                            test_debug!("Store peer server index block {:?}", &index_block_hash);
                            store_staging_block(peer_server.chainstate(), &peer_server_burn_block_hash, get_epoch_time_secs(), &peer_server_block, &BurnchainHeaderHash([client_id as u8; 32]), 456, 123);

                            let mut request = HttpRequestType::GetBlock(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51021)), index_block_hash);
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            // should be a Block
                            let http_response_bytes = http_response_bytes_res.unwrap();

                            let peer_server_block = make_codec_test_block(25);
                            let peer_server_burn_block_hash = BurnchainHeaderHash([(client_id+1) as u8; 32]);
                            let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block.block_hash());

                            let request_path = format!("/v2/blocks/{}", &index_block_hash);
                            let response = StacksHttp::parse_response(&request_path, &http_response_bytes).unwrap();
                            match response {
                                StacksHttpMessage::Response(HttpResponseType::Block(md, block_data)) => block_data == peer_server_block,
                                _ => false
                            }
                        });
    }
    
    #[test]
    fn test_http_10_threads_getblock() {
        test_http_server("test_http_getblock", 51030, 51031, ConnectionOptions::default(), 10, 0,
                        |client_id, ref mut peer_server| {
                            let peer_server_block = make_codec_test_block(25);
                            let peer_server_burn_block_hash = BurnchainHeaderHash([(client_id+1) as u8; 32]);
                            let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block.block_hash());

                            test_debug!("Store peer server index block {:?}", &index_block_hash);
                            store_staging_block(peer_server.chainstate(), &peer_server_burn_block_hash, get_epoch_time_secs(), &peer_server_block, &BurnchainHeaderHash([client_id as u8; 32]), 456, 123);

                            let mut request = HttpRequestType::GetBlock(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51031)), index_block_hash);
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            // should be a Block
                            let http_response_bytes = http_response_bytes_res.unwrap();

                            let peer_server_block = make_codec_test_block(25);
                            let peer_server_burn_block_hash = BurnchainHeaderHash([(client_id+1) as u8; 32]);
                            let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block.block_hash());

                            let request_path = format!("/v2/blocks/{}", &index_block_hash);
                            let response = StacksHttp::parse_response(&request_path, &http_response_bytes).unwrap();
                            match response {
                                StacksHttpMessage::Response(HttpResponseType::Block(md, block_data)) => block_data == peer_server_block,
                                _ => false
                            }
                        });
    }
    
    #[test]
    fn test_http_too_many_clients() {
        let mut conn_opts = ConnectionOptions::default();
        conn_opts.num_clients = 1;

        let have_success = RefCell::new(false);
        let have_error = RefCell::new(false);

        test_http_server("test_http_too_many_clients", 51040, 51041, conn_opts, 2, 0,
                        |client_id, _| {
                            let mut request = HttpRequestType::GetInfo(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51041)));
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            match http_response_bytes_res {
                                Ok(http_response_bytes) => {
                                    // should be a PeerInfo
                                    let response = match StacksHttp::parse_response("/v2/info", &http_response_bytes) {
                                        Ok(res) => res,
                                        Err(e) => {
                                            eprintln!("Failed to parse /v2/info response from:\n{:?}\n{:?}", &http_response_bytes, &e);
                                            assert!(false);
                                            unreachable!();
                                        }
                                    };
                                    *have_success.borrow_mut() = true;
                                    true
                                }
                                Err(err) => {
                                    // should have failed
                                    eprintln!("{:?}", &err);
                                    *have_error.borrow_mut() = true;
                                    true
                                }
                            }
                        });

        assert!(*have_success.borrow());
        assert!(*have_error.borrow());
    }

    #[test]
    fn test_http_slow_client() {
        let mut conn_opts = ConnectionOptions::default();
        conn_opts.timeout = 3;      // kill a connection after 3 seconds of idling
        
        test_http_server("test_http_slow_client", 51050, 51051, conn_opts, 1, 30,
                        |client_id, _| {
                            let mut request = HttpRequestType::GetInfo(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51051)));
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            match http_response_bytes_res {
                                Ok(bytes) => bytes.len() == 0,      // should not have gotten any data
                                Err(err) => {
                                    // should have failed
                                    eprintln!("{:?}", &err);
                                    false
                                }
                            }
                        });
    }
    
    #[test]
    fn test_http_endless_data_client() {
        let conn_opts = ConnectionOptions::default();
        test_http_server("test_http_endless_data_client", 51060, 51061, conn_opts, 1, 0,
                        |client_id, ref mut peer| {
                            // make a gigantic transaction
                            let mut big_contract_parts = vec![];
                            let mut total_len = 0;
                            while total_len < MAX_MESSAGE_LEN {
                                let next_line = format!("(define-constant meaningless-data-{} {})\n", total_len, total_len);
                                total_len += next_line.len() as u32;
                                big_contract_parts.push(next_line);
                            }

                            let big_contract = big_contract_parts.join("");

                            let privk_origin = StacksPrivateKey::from_hex("027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01").unwrap();
                            let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
                            let mut tx_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                                         auth_origin.clone(),
                                                                         TransactionPayload::new_smart_contract(&"hello-world".to_string(), &big_contract.to_string()).unwrap());

                            tx_contract.chain_id = peer.config.network_id; 
                            tx_contract.set_fee_rate(0);

                            let mut signer = StacksTransactionSigner::new(&tx_contract);
                            signer.sign_origin(&privk_origin).unwrap();
                            
                            let signed_contract_tx = signer.get_tx().unwrap();

                            let mut request = HttpRequestType::PostTransaction(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51061)), signed_contract_tx);
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            match http_response_bytes_res {
                                Ok(bytes) => false,
                                Err(err) => {
                                    // should have failed
                                    eprintln!("{:?}", &err);
                                    true
                                }
                            }
                        });
    }
    
    #[test]
    fn test_http_noop() {
        if std::env::var("BLOCKSTACK_HTTP_TEST") != Ok("1".to_string()) {
            eprintln!("Set BLOCKSTACK_HTTP_TEST=1 to use this test.");
            eprintln!("To test, run `curl http://localhost:51071/v2/blocks/a3b82874a8bf02b91613f61bff41580dab439ecc14f5e71c7288d89623499dfa` to download a block");
            return;
        }

        // doesn't do anything; just runs a server for 10 minutes
        let conn_opts = ConnectionOptions::default();
        test_http_server("test_http_noop", 51070, 51071, conn_opts, 1, 600,
                        |client_id, ref mut peer_server| {
                            let peer_server_block = make_codec_test_block(25);
                            let peer_server_burn_block_hash = BurnchainHeaderHash([(client_id+1) as u8; 32]);
                            let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block.block_hash());

                            test_debug!("Store peer server index block {:?}", &index_block_hash);
                            store_staging_block(peer_server.chainstate(), &peer_server_burn_block_hash, get_epoch_time_secs(), &peer_server_block, &BurnchainHeaderHash([client_id as u8; 32]), 456, 123);

                            let mut request = HttpRequestType::GetBlock(HttpRequestMetadata::from_host(PeerHost::from_host_port("127.0.0.1".to_string(), 51071)), index_block_hash);
                            request.metadata_mut().keep_alive = false;
                            
                            let request_bytes = StacksHttp::serialize_request(&request).unwrap();
                            request_bytes
                        },
                        |client_id, http_response_bytes_res| {
                            true
                        });
    }
}
