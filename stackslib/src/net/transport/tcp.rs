// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::collections::HashMap;
use std::net::SocketAddr;

use mio::net as mio_net;

use crate::net::connection::ConnectionOptions;
use crate::net::poll::{NetworkPollState, NetworkState};
use crate::net::transport::{LentStream, PeerTransport, TransportEvents};
use crate::net::Error as net_error;

/// Plain TCP sockets, registered with the node's `mio` poller.
#[derive(Debug)]
pub struct TcpTransport {
    /// The poller handle of our listening socket, once bound.
    server_handle: Option<usize>,
    /// Open sockets, both connecting and connected, by connection ID.
    /// Boxed so that lending one out with `take_stream()` doesn't allocate.
    sockets: HashMap<usize, Box<mio_net::TcpStream>>,
    /// Connections whose socket is lent out, and whether `close()` was called on them since.
    lent: HashMap<usize, bool>,
    /// Sockets closed while they were lent out, to deregister on the next `process_poll()`.
    closing: Vec<(usize, Box<mio_net::TcpStream>)>,
    socket_send_buffer_size: u32,
    socket_recv_buffer_size: u32,
}

impl TcpTransport {
    pub fn new(connection_opts: &ConnectionOptions) -> Self {
        Self {
            server_handle: None,
            sockets: HashMap::new(),
            lent: HashMap::new(),
            closing: vec![],
            socket_send_buffer_size: connection_opts.socket_send_buffer_size,
            socket_recv_buffer_size: connection_opts.socket_recv_buffer_size,
        }
    }

    fn server_handle(&self) -> Result<usize, net_error> {
        self.server_handle.ok_or(net_error::NotConnected)
    }
}

impl PeerTransport for TcpTransport {
    fn bind(
        &mut self,
        poller: &mut NetworkState,
        addr: &SocketAddr,
    ) -> Result<SocketAddr, net_error> {
        let (handle, bound_addr) = poller.bind(addr)?;
        self.server_handle = Some(handle);
        Ok(bound_addr)
    }

    fn connect(
        &mut self,
        poller: &mut NetworkState,
        addr: &SocketAddr,
    ) -> Result<usize, net_error> {
        let server_handle = self.server_handle()?;
        let sock = NetworkState::connect(
            addr,
            self.socket_send_buffer_size,
            self.socket_recv_buffer_size,
        )?;
        let hint_event_id = poller.next_event_id()?;
        let event_id = poller.register(server_handle, hint_event_id, &sock)?;
        self.sockets.insert(event_id, Box::new(sock));
        Ok(event_id)
    }

    fn process_poll(
        &mut self,
        poller: &mut NetworkState,
        poll_states: &mut HashMap<usize, NetworkPollState>,
    ) -> TransportEvents {
        let server_handle = self
            .server_handle
            .expect("BUG: polled the p2p transport before binding it");

        // finish closing the sockets that were closed while lent out
        for (event_id, sock) in self.closing.drain(..) {
            let _ = poller.deregister(event_id, &sock);
        }

        let mut poll_state = poll_states
            .remove(&server_handle)
            .expect("BUG: no poll state for p2p network handle");

        let mut accepted = vec![];
        for (hint_event_id, client_sock) in poll_state.new.drain() {
            // add to poller
            let event_id = match poller.register(server_handle, hint_event_id, &client_sock) {
                Ok(event_id) => event_id,
                Err(e) => {
                    warn!("Failed to register {:?}: {:?}", &client_sock, &e);
                    continue;
                }
            };

            // event ID already used?
            if self.sockets.contains_key(&event_id) || self.lent.contains_key(&event_id) {
                warn!("Already have an event {event_id}");
                let _ = poller.deregister(event_id, &client_sock);
                continue;
            }

            self.sockets.insert(event_id, Box::new(client_sock));
            accepted.push(event_id);
        }

        TransportEvents {
            accepted,
            ready: poll_state.ready,
        }
    }

    fn peer_addr(&self, id: usize) -> Result<SocketAddr, net_error> {
        let sock = self
            .sockets
            .get(&id)
            .ok_or_else(|| net_error::PeerNotConnected(format!("No socket for event {id}")))?;
        sock.peer_addr().map_err(|e| {
            debug!("Failed to get peer address of {sock:?}: {e:?}");
            net_error::SocketError
        })
    }

    fn take_stream(&mut self, id: usize) -> Option<LentStream> {
        let sock = self.sockets.remove(&id)?;
        self.lent.insert(id, false);
        Some(LentStream::new(id, sock))
    }

    fn restore_stream(&mut self, stream: LentStream) {
        let (id, stream) = stream.into_parts();
        let closed = self
            .lent
            .remove(&id)
            .expect("BUG: restored a stream that the TCP transport did not lend out");
        let sock = stream
            .into_any()
            .downcast::<mio_net::TcpStream>()
            .expect("BUG: restored a stream that the TCP transport did not create");
        if closed {
            self.closing.push((id, sock));
        } else {
            self.sockets.insert(id, sock);
        }
    }

    fn close(&mut self, poller: &mut NetworkState, id: usize) {
        if let Some(sock) = self.sockets.remove(&id) {
            let _ = poller.deregister(id, &sock);
        } else if let Some(closed) = self.lent.get_mut(&id) {
            *closed = true;
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{ErrorKind, Read, Write};

    use super::*;

    /// Poll until the transport accepts an inbound connection, and return its ID.
    fn poll_until_accepted(poller: &mut NetworkState, transport: &mut TcpTransport) -> usize {
        for _ in 0..100 {
            let mut poll_states = poller.poll(100).unwrap();
            let events = transport.process_poll(poller, &mut poll_states);
            if let Some(event_id) = events.accepted.first() {
                return *event_id;
            }
        }
        panic!("transport never accepted the connection");
    }

    #[test]
    fn test_connect_before_bind() {
        let mut poller = NetworkState::new(10).unwrap();
        let mut transport = TcpTransport::new(&ConnectionOptions::default());
        let addr = "127.0.0.1:1".parse().unwrap();
        assert!(matches!(
            transport.connect(&mut poller, &addr),
            Err(net_error::NotConnected)
        ));
    }

    #[test]
    fn test_connect_accept_send_close() {
        let mut poller = NetworkState::new(10).unwrap();
        let mut transport = TcpTransport::new(&ConnectionOptions::default());
        let addr = transport
            .bind(&mut poller, &"127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert_ne!(addr.port(), 0);

        let outbound = transport.connect(&mut poller, &addr).unwrap();
        let inbound = poll_until_accepted(&mut poller, &mut transport);
        assert_ne!(inbound, outbound);
        assert_eq!(transport.peer_addr(outbound).unwrap(), addr);
        assert_eq!(poller.num_events(), 3);

        // a lent-out stream can't be lent out twice
        let mut sender = transport.take_stream(outbound).unwrap();
        assert!(transport.take_stream(outbound).is_none());
        let mut receiver = transport.take_stream(inbound).unwrap();

        // the sockets are non-blocking, so retry until the bytes get through
        let msg = b"hello";
        let mut sent = 0;
        let mut received = vec![];
        let mut buf = [0u8; 16];
        for _ in 0..1000 {
            if sent < msg.len() {
                match sender.write(&msg[sent..]) {
                    Ok(n) => sent += n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == ErrorKind::NotConnected => {}
                    Err(e) => panic!("write failed: {e:?}"),
                }
            }
            match receiver.read(&mut buf) {
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("read failed: {e:?}"),
            }
            if received.len() == msg.len() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(received, msg);

        transport.restore_stream(sender);
        transport.restore_stream(receiver);

        transport.close(&mut poller, outbound);
        transport.close(&mut poller, inbound);
        assert!(transport.peer_addr(outbound).is_err());
        assert!(transport.take_stream(inbound).is_none());

        // only the server socket is left registered
        assert_eq!(poller.num_events(), 1);

        // closing an unknown connection is a no-op
        transport.close(&mut poller, outbound);
    }

    #[test]
    fn test_close_while_lent() {
        let mut poller = NetworkState::new(10).unwrap();
        let mut transport = TcpTransport::new(&ConnectionOptions::default());
        let addr = transport
            .bind(&mut poller, &"127.0.0.1:0".parse().unwrap())
            .unwrap();
        let outbound = transport.connect(&mut poller, &addr).unwrap();
        let inbound = poll_until_accepted(&mut poller, &mut transport);
        assert_eq!(poller.num_events(), 3);

        // closing a connection whose stream is lent out doesn't close it yet
        let stream = transport.take_stream(outbound).unwrap();
        assert_eq!(stream.id(), outbound);
        transport.close(&mut poller, outbound);
        assert_eq!(poller.num_events(), 3);

        // once the stream is handed back, the connection is gone, and its ID is released by the
        // next poll
        transport.restore_stream(stream);
        assert!(transport.take_stream(outbound).is_none());
        assert!(transport.peer_addr(outbound).is_err());
        let mut poll_states = poller.poll(0).unwrap();
        transport.process_poll(&mut poller, &mut poll_states);
        assert_eq!(poller.num_events(), 2);

        // the other connection is unaffected
        let stream = transport.take_stream(inbound).unwrap();
        transport.restore_stream(stream);
        assert!(transport.peer_addr(inbound).is_ok());
    }
}
