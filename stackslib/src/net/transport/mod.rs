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

//! The transport layer underneath the p2p network.
//!
//! A [`PeerTransport`] accepts and opens connections to remote peers, and hands out a
//! non-blocking byte stream ([`PeerStream`]) for each one.  Everything above it -- the
//! handshake, message framing and signing in `ConversationP2P`, and the protocol state machines
//! in `PeerNetwork` -- only sees connection IDs and byte streams, so it does not depend on how
//! the bytes get to the remote peer.
//!
//! Connection IDs share the event ID space of the node's poller ([`NetworkState`]), which the
//! p2p network and the HTTP server use together.  A transport registers its connections with
//! that poller so a single `poll()` wakes up on either kind of traffic.
//!
//! [`TcpTransport`] carries traffic over plain TCP sockets driven by `mio`, the way the p2p
//! network always has.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;

use crate::net::poll::{NetworkPollState, NetworkState};
use crate::net::Error as net_error;

pub mod tcp;

pub use self::tcp::TcpTransport;

/// A non-blocking, bidirectional byte stream to a remote peer.
///
/// Reads and writes must not block: when no data can be moved, they fail with
/// `io::ErrorKind::WouldBlock`, and the transport reports the connection as ready again once
/// they can make progress.  Readiness is edge-triggered: a connection is reported once per
/// change, so the p2p network reads and writes until it gets `WouldBlock`.  A read returns
/// `Ok(0)` once the remote peer has closed the stream.
pub trait PeerStream: Read + Write + fmt::Debug + Send {
    /// Convert back into a concrete stream, so the transport that created it can recover it.
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send>;
}

impl<T: Read + Write + fmt::Debug + Send + 'static> PeerStream for T {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

/// A connection's stream, lent out by [`PeerTransport::take_stream`].  It reads and writes like
/// the stream itself, and must be handed back with [`PeerTransport::restore_stream`].
///
/// Only transports can create one or unwrap it, so the stream a transport gets back is always
/// the one it lent out, for the connection it lent it out for.
#[must_use = "a lent stream must be handed back with `PeerTransport::restore_stream`"]
#[derive(Debug)]
pub struct LentStream {
    id: usize,
    stream: Box<dyn PeerStream>,
}

impl LentStream {
    /// Lend out connection `id`'s stream.
    fn new(id: usize, stream: Box<dyn PeerStream>) -> Self {
        Self { id, stream }
    }

    /// Take back the connection ID and the stream.
    fn into_parts(self) -> (usize, Box<dyn PeerStream>) {
        (self.id, self.stream)
    }

    /// The ID of the connection this stream belongs to.
    pub fn id(&self) -> usize {
        self.id
    }
}

impl Read for LentStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for LentStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// What happened to a transport's connections during one poll.
#[derive(Debug, Default)]
pub struct TransportEvents {
    /// Inbound connections accepted since the last poll.  Their streams are open.
    pub accepted: Vec<usize>,
    /// Connections that may be able to make progress: they have data to read, room to write, or
    /// finished connecting (successfully or not).  A connection in `accepted` shows up here once
    /// it has I/O to do, which may not be until a later poll.
    pub ready: Vec<usize>,
}

/// The transport the p2p network runs on.
///
/// A connection's ID is assigned when it is accepted or opened, and stays valid until the
/// connection is closed with [`PeerTransport::close`].  Outbound connections are opened
/// asynchronously: [`PeerTransport::connect`] returns right away, and the connection is reported
/// in [`TransportEvents::ready`] once it is established or has failed.  A failure shows up as an
/// I/O error on the stream.
pub trait PeerTransport: Send {
    /// Start accepting inbound connections on `addr`.  Returns the address actually bound,
    /// which differs from `addr` when its port is 0.
    fn bind(
        &mut self,
        poller: &mut NetworkState,
        addr: &SocketAddr,
    ) -> Result<SocketAddr, net_error>;

    /// Start opening a connection to `addr`, without waiting for it to complete.
    /// Returns the new connection's ID.
    fn connect(&mut self, poller: &mut NetworkState, addr: &SocketAddr)
        -> Result<usize, net_error>;

    /// Take this transport's share of the poller's results and turn them into connection events.
    /// Called once per poll, after `poller.poll()`, and only after a successful `bind()`.
    fn process_poll(
        &mut self,
        poller: &mut NetworkState,
        poll_states: &mut HashMap<usize, NetworkPollState>,
    ) -> TransportEvents;

    /// The remote address of an open connection.
    fn peer_addr(&self, id: usize) -> Result<SocketAddr, net_error>;

    /// Lend out a connection's stream, so it can be used while the transport is borrowed
    /// elsewhere.  The caller must hand it back with [`PeerTransport::restore_stream`].
    /// Returns `None` if there is no such connection, or its stream is already lent out.
    fn take_stream(&mut self, id: usize) -> Option<LentStream>;

    /// Hand back a stream that [`PeerTransport::take_stream`] lent out.
    fn restore_stream(&mut self, stream: LentStream);

    /// Close a connection and release its ID.  Does nothing if there is no such connection.
    /// If the connection's stream is lent out, it is closed once the stream is handed back,
    /// and its ID is released by the next [`PeerTransport::process_poll`].
    fn close(&mut self, poller: &mut NetworkState, id: usize);
}
