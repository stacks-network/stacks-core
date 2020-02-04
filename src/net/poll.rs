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

use util::db::Error as db_error;
use util::db::DBConn;

use std::net::SocketAddr;
use std::collections::HashMap;
use std::time::Duration;
use std::io::Read;
use std::io::Write;
use std::io::Error as io_error;
use std::io::ErrorKind;

use util::log;

use mio;
use mio::net as mio_net;
use mio::Ready;
use mio::Token;
use mio::PollOpt;

use std::net::Shutdown;

pub const NUM_NEIGHBORS : u32 = 32;

const SERVER : Token = mio::Token(0);

pub struct NetworkPollState {
    pub new: HashMap<usize, mio_net::TcpStream>,
    pub ready: Vec<usize>
}

impl NetworkPollState {
    pub fn new() -> NetworkPollState {
        NetworkPollState {
            new: HashMap::new(),
            ready: vec![]
        }
    }
}

pub struct NetworkState {
    addr: SocketAddr,
    poll: mio::Poll,
    server: mio_net::TcpListener,
    events: mio::Events,
    count: usize,
}

impl NetworkState {
    pub fn bind(addr: &SocketAddr, capacity: usize) -> Result<NetworkState, net_error> {
        let server = mio_net::TcpListener::bind(addr)
            .map_err(|e| {
                error!("Failed to bind to {:?}: {:?}", addr, e);
                net_error::BindError
            })?;

        let poll = mio::Poll::new()
            .map_err(|e| {
                error!("Failed to initialize poller: {:?}", e);
                net_error::BindError
            })?;

        let events = mio::Events::with_capacity(capacity);

        poll.register(&server, SERVER, mio::Ready::readable(), mio::PollOpt::edge())
            .map_err(|e| {
                error!("Failed to register server socket: {:?}", &e);
                net_error::BindError
            })?;

        Ok(NetworkState {
            addr: addr.clone(),
            poll: poll,
            server: server,
            events: events,
            count: 1
        })
    }

    /// next event ID
    pub fn next_event_id(&mut self) -> usize {
        let ret = self.count;
        self.count += 1;
        ret
    }

    /// Register a socket for read/write notifications with this poller
    pub fn register(&mut self, event_id: usize, sock: &mio_net::TcpStream) -> Result<(), net_error> {
        self.poll.register(sock, mio::Token(event_id), Ready::all(), PollOpt::edge())
            .map_err(|e| {
                error!("Failed to register socket: {:?}", &e);
                net_error::RegisterError
            })
    }

    /// Deregister a socket event
    pub fn deregister(&mut self, sock: &mio_net::TcpStream) -> Result<(), net_error> {
        self.poll.deregister(sock)
            .map_err(|e| {
                error!("Failed to deregister socket: {:?}", &e);
                net_error::RegisterError
            })?;

        sock.shutdown(Shutdown::Both)
            .map_err(|_e| net_error::SocketError)?;

        test_debug!("Socket deregisterd: {:?}", sock);
        Ok(())
    }

    /// Connect to a remote peer, but don't register it with the poll handle.
    pub fn connect(&mut self, addr: &SocketAddr) -> Result<mio_net::TcpStream, net_error> {
        let stream = std::net::TcpStream::connect_timeout(
            addr, std::time::Duration::from_millis(5000))
            .map_err(|e| {
                test_debug!("failed to connect to {:?}: {:?}", addr, &e);
                net_error::ConnectionError
            })?;

        let stream = mio_net::TcpStream::from_stream(stream)
            .map_err(|e| {
                test_debug!("failed to connect to {:?}: {:?}", addr, &e);
                net_error::ConnectionError
            })?;

        test_debug!("New socket connected to {:?}: {:?}", addr, &stream);
        Ok(stream)
    }

    /// Poll socket states
    pub fn poll(&mut self, timeout: u64) -> Result<NetworkPollState, net_error> {
        self.poll.poll(&mut self.events, Some(Duration::from_millis(timeout)))
            .map_err(|e| {
                error!("Failed to poll: {:?}", &e);
                net_error::PollError
            })?;
       
        let mut poll_state = NetworkPollState::new();
        for event in &self.events {
            match event.token() {
                SERVER => {
                    // new inbound connection(s)
                    loop {
                        let (client_sock, client_addr) = match self.server.accept() {
                            Ok((client_sock, client_addr)) => (client_sock, client_addr),
                            Err(e) => {
                                match e.kind() {
                                    ErrorKind::WouldBlock => {
                                        break;
                                    },
                                    _ => {
                                        return Err(net_error::AcceptError);
                                    }
                                }
                            }
                        };

                        test_debug!("New socket accepted from {:?} (event {}): {:?}", &client_addr, self.count, &client_sock);
                        poll_state.new.insert(self.count, client_sock);
                        self.count += 1;
                    }
                },
                mio::Token(event_id) => {
                    // I/O available 
                    poll_state.ready.push(event_id);
                }
            }
        }

        Ok(poll_state)
    }
}
