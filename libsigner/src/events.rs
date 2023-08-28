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

use std::sync::mpsc::Sender;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;

use std::io::Read;

use clarity::vm::types::QualifiedContractIdentifier;
use libstackerdb::StackerDBChunkData;

use serde::{Deserialize, Serialize};

use crate::http::{decode_http_body, decode_http_request};
use crate::EventError;

/// Event structure for newly-arrived StackerDB data
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StackerDBChunksEvent {
    pub contract_id: QualifiedContractIdentifier,
    pub modified_slots: Vec<StackerDBChunkData>,
}

/// Trait to implement a stop-signaler for the event receiver thread.
/// The caller calls `send()` and the event receiver loop (which lives in a separate thread) will
/// terminate.
pub trait EventStopSignaler {
    fn send(&mut self);
}

/// Trait to implement to handle StackerDB events sent by the Stacks node
pub trait EventReceiver {
    /// The implementation of ST will ensure that a call to ST::send() will cause
    /// the call to `is_stopped()` below to return true.
    type ST: EventStopSignaler + Send + Sync;

    /// Open a server socket to the given socket address.
    fn bind(&mut self, listener: SocketAddr) -> Result<SocketAddr, EventError>;
    /// Return the next event
    fn next_event(&mut self) -> Result<StackerDBChunksEvent, EventError>;
    /// Add a downstream event consumer
    fn add_consumer(&mut self, event_out: Sender<StackerDBChunksEvent>);
    /// Forward the event to downstream consumers
    fn forward_event(&mut self, ev: StackerDBChunksEvent) -> bool;
    /// Determine if the receiver should hang up
    fn is_stopped(&self) -> bool;
    /// Get a stop signal instance that, when sent, will cause this receiver to stop accepting new
    /// events.  Called after `bind()`.
    fn get_stop_signaler(&mut self) -> Result<Self::ST, EventError>;

    /// Main loop for the receiver.
    /// Typically, this is started in a separate thread.
    fn main_loop(&mut self) {
        loop {
            if self.is_stopped() {
                info!("Event receiver stopped");
                break;
            }
            let next_event = match self.next_event() {
                Ok(event) => event,
                Err(EventError::UnrecognizedEvent(..)) => {
                    // got an event that we don't care about (not a problem)
                    continue;
                }
                Err(EventError::Terminated) => {
                    // we're done
                    info!("Caught termination signal");
                    break;
                }
                Err(e) => {
                    warn!("Failed to receive next event: {:?}", &e);
                    continue;
                }
            };
            if !self.forward_event(next_event) {
                info!("Failed to forward event");
                break;
            }
        }
        info!("Event receiver main loop exit");
    }
}

pub struct StackerDBEventReceiver {
    /// contracts we're listening for
    pub stackerdb_contract_ids: Vec<QualifiedContractIdentifier>,
    /// Address we bind to
    local_addr: Option<SocketAddr>,
    /// server socket that listens for HTTP POSTs from the node
    sock: Option<TcpListener>,
    /// channel into which to write newly-discovered data
    out_channels: Vec<Sender<StackerDBChunksEvent>>,
    /// inter-thread stop variable -- if set to true, then the `main_loop` will exit
    stop_signal: Arc<AtomicBool>,
}

impl StackerDBEventReceiver {
    /// Make a new StackerDB event receiver, and return both the receiver and the read end of a
    /// channel into which node-received data can be obtained.
    pub fn new(contract_ids: Vec<QualifiedContractIdentifier>) -> StackerDBEventReceiver {
        let stackerdb_receiver = StackerDBEventReceiver {
            stackerdb_contract_ids: contract_ids,
            sock: None,
            local_addr: None,
            out_channels: vec![],
            stop_signal: Arc::new(AtomicBool::new(false)),
        };
        stackerdb_receiver
    }

    /// Do something with the socket
    pub fn with_socket<F, R>(&mut self, todo: F) -> Result<R, EventError>
    where
        F: FnOnce(&mut StackerDBEventReceiver, &mut TcpListener) -> R,
    {
        let mut sock = if let Some(s) = self.sock.take() {
            s
        } else {
            return Err(EventError::NotBound);
        };

        let res = todo(self, &mut sock);

        self.sock = Some(sock);
        Ok(res)
    }
}

/// Stop signaler implementation
pub struct StackerDBStopSignaler {
    stop_signal: Arc<AtomicBool>,
    local_addr: SocketAddr,
}

impl StackerDBStopSignaler {
    pub fn new(sig: Arc<AtomicBool>, local_addr: SocketAddr) -> StackerDBStopSignaler {
        StackerDBStopSignaler {
            stop_signal: sig,
            local_addr,
        }
    }
}

impl EventStopSignaler for StackerDBStopSignaler {
    fn send(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);

        // wake up the thread so the atomicbool can be checked
        let _ = TcpStream::connect(&self.local_addr);
    }
}

impl EventReceiver for StackerDBEventReceiver {
    type ST = StackerDBStopSignaler;

    /// Start listening on the given socket address.
    /// Returns the address that was bound.
    /// Errors out if bind(2) fails
    fn bind(&mut self, listener: SocketAddr) -> Result<SocketAddr, EventError> {
        let srv = TcpListener::bind(listener)?;
        let bound_addr = srv.local_addr()?;
        self.sock = Some(srv);
        self.local_addr = Some(bound_addr.clone());
        Ok(bound_addr)
    }

    /// Wait for the node to post something, and then return it.
    /// Errors are recoverable -- the caller should call this method again even if it returns an
    /// error.
    fn next_event(&mut self) -> Result<StackerDBChunksEvent, EventError> {
        self.with_socket(|event_receiver, server_sock| {
            let (mut node_sock, _) = server_sock.accept()?;

            // were we asked to terminate?
            if event_receiver.is_stopped() {
                return Err(EventError::Terminated);
            }

            let mut buf = vec![];
            node_sock.read_to_end(&mut buf)?;

            let (verb, path, headers, body_offset) = decode_http_request(&buf)?;
            if verb != "POST" {
                return Err(EventError::MalformedRequest(format!(
                    "Unrecognized verb '{}'",
                    &verb
                )));
            }
            if path != "/stackerdb_chunks" {
                return Err(EventError::UnrecognizedEvent(path));
            }

            let body = decode_http_body(&headers, &buf[body_offset..])?;
            let event: StackerDBChunksEvent = serde_json::from_slice(&body).map_err(|e| {
                EventError::Deserialize(format!("Could not decode body to JSON: {:?}", &e))
            })?;
            Ok(event)
        })?
    }

    /// Determine if the receiver is hung up
    fn is_stopped(&self) -> bool {
        self.stop_signal.load(Ordering::SeqCst)
    }

    /// Forward an event
    /// Return true on success; false on error.
    /// Returning false terminates the event receiver.
    fn forward_event(&mut self, ev: StackerDBChunksEvent) -> bool {
        if self.out_channels.len() == 0 {
            // nothing to do
            error!("No channels connected to event receiver");
            return false;
        } else if self.out_channels.len() == 1 {
            // avoid a clone
            if let Err(e) = self.out_channels[0].send(ev) {
                error!("Failed to send to signer runloop: {:?}", &e);
                return false;
            }
            return true;
        } else {
            for (i, out_channel) in self.out_channels.iter().enumerate() {
                if let Err(e) = out_channel.send(ev.clone()) {
                    error!("Failed to send to signer runloop #{}: {:?}", i, &e);
                    return false;
                }
            }
            return true;
        }
    }

    /// Add an event consumer.  A received event will be forwarded to this Sender.
    fn add_consumer(&mut self, out_channel: Sender<StackerDBChunksEvent>) {
        self.out_channels.push(out_channel);
    }

    /// Get a stopped signaler.  The caller can then use it to terminate the event receiver loop,
    /// even if it's in a different thread.
    fn get_stop_signaler(&mut self) -> Result<StackerDBStopSignaler, EventError> {
        if let Some(local_addr) = self.local_addr.as_ref() {
            Ok(StackerDBStopSignaler::new(
                self.stop_signal.clone(),
                local_addr.clone(),
            ))
        } else {
            Err(EventError::NotBound)
        }
    }
}
