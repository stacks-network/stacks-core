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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::boot::{MINERS_NAME, SIGNERS_NAME};
use blockstack_lib::chainstate::stacks::events::StackerDBChunksEvent;
use blockstack_lib::chainstate::stacks::{StacksTransaction, ThresholdSignature};
use blockstack_lib::net::api::postblock_proposal::{
    BlockValidateReject, BlockValidateResponse, ValidateRejectCode,
};
use blockstack_lib::util_lib::boot::boot_code_id;
use clarity::vm::types::serialization::SerializationError;
use clarity::vm::types::QualifiedContractIdentifier;
use serde::{Deserialize, Serialize};
use stacks_common::codec::{
    read_next, read_next_at_most, read_next_exact, write_next, Error as CodecError,
    StacksMessageCodec,
};
use stacks_common::util::hash::Sha512Trunc256Sum;
use tiny_http::{
    Method as HttpMethod, Request as HttpRequest, Response as HttpResponse, Server as HttpServer,
};
use wsts::common::Signature;
use wsts::net::{
    DkgBegin, DkgEnd, DkgEndBegin, DkgPrivateBegin, DkgPrivateShares, DkgPublicShares, DkgStatus,
    Message, NonceRequest, NonceResponse, Packet, SignatureShareRequest, SignatureShareResponse,
};
use wsts::state_machine::signer;

use crate::http::{decode_http_body, decode_http_request};
use crate::{EventError, SignerMessage};

/// Event enum for newly-arrived signer subscribed events
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SignerEvent {
    /// The miner proposed blocks for signers to observe and sign
    ProposedBlocks(Vec<NakamotoBlock>),
    /// The signer messages for other signers and miners to observe
    SignerMessages(Vec<SignerMessage>),
    /// A new block proposal validation response from the node
    BlockValidationResponse(BlockValidateResponse),
    /// Status endpoint request
    StatusCheck,
}

/// Trait to implement a stop-signaler for the event receiver thread.
/// The caller calls `send()` and the event receiver loop (which lives in a separate thread) will
/// terminate.
pub trait EventStopSignaler {
    /// Send the stop signal
    fn send(&mut self);
}

/// Trait to implement to handle signer specific events sent by the Stacks node
pub trait EventReceiver {
    /// The implementation of ST will ensure that a call to ST::send() will cause
    /// the call to `is_stopped()` below to return true.
    type ST: EventStopSignaler + Send + Sync;

    /// Open a server socket to the given socket address.
    fn bind(&mut self, listener: SocketAddr) -> Result<SocketAddr, EventError>;
    /// Return the next event
    fn next_event(&mut self) -> Result<SignerEvent, EventError>;
    /// Add a downstream event consumer
    fn add_consumer(&mut self, event_out: Sender<SignerEvent>);
    /// Forward the event to downstream consumers
    fn forward_event(&mut self, ev: SignerEvent) -> bool;
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

/// Event receiver for Signer events
pub struct SignerEventReceiver {
    /// stacker db contracts we're listening for
    pub stackerdb_contract_ids: Vec<QualifiedContractIdentifier>,
    /// Address we bind to
    local_addr: Option<SocketAddr>,
    /// server socket that listens for HTTP POSTs from the node
    http_server: Option<HttpServer>,
    /// channel into which to write newly-discovered data
    out_channels: Vec<Sender<SignerEvent>>,
    /// inter-thread stop variable -- if set to true, then the `main_loop` will exit
    stop_signal: Arc<AtomicBool>,
    /// Whether the receiver is running on mainnet
    is_mainnet: bool,
}

impl SignerEventReceiver {
    /// Make a new Signer event receiver, and return both the receiver and the read end of a
    /// channel into which node-received data can be obtained.
    pub fn new(
        contract_ids: Vec<QualifiedContractIdentifier>,
        is_mainnet: bool,
    ) -> SignerEventReceiver {
        SignerEventReceiver {
            stackerdb_contract_ids: contract_ids,
            http_server: None,
            local_addr: None,
            out_channels: vec![],
            stop_signal: Arc::new(AtomicBool::new(false)),
            is_mainnet,
        }
    }

    /// Do something with the socket
    pub fn with_server<F, R>(&mut self, todo: F) -> Result<R, EventError>
    where
        F: FnOnce(&SignerEventReceiver, &mut HttpServer, bool) -> R,
    {
        let mut server = if let Some(s) = self.http_server.take() {
            s
        } else {
            return Err(EventError::NotBound);
        };

        let res = todo(self, &mut server, self.is_mainnet);

        self.http_server = Some(server);
        Ok(res)
    }
}

/// Stop signaler implementation
pub struct SignerStopSignaler {
    stop_signal: Arc<AtomicBool>,
    local_addr: SocketAddr,
}

impl SignerStopSignaler {
    /// Make a new stop signaler
    pub fn new(sig: Arc<AtomicBool>, local_addr: SocketAddr) -> SignerStopSignaler {
        SignerStopSignaler {
            stop_signal: sig,
            local_addr,
        }
    }
}

impl EventStopSignaler for SignerStopSignaler {
    fn send(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        // wake up the thread so the atomicbool can be checked
        // This makes me sad...but for now...it works.
        if let Ok(mut stream) = TcpStream::connect(self.local_addr) {
            // We need to send actual data to trigger the event receiver
            let body = "Yo. Shut this shit down!".to_string();
            let req = format!(
                "POST /shutdown HTTP/1.0\r\nContent-Length: {}\r\n\r\n{}",
                &body.len(),
                body
            );
            stream.write_all(req.as_bytes()).unwrap();
        }
    }
}

impl EventReceiver for SignerEventReceiver {
    type ST = SignerStopSignaler;

    /// Start listening on the given socket address.
    /// Returns the address that was bound.
    /// Errors out if bind(2) fails
    fn bind(&mut self, listener: SocketAddr) -> Result<SocketAddr, EventError> {
        self.http_server = Some(HttpServer::http(listener).expect("failed to start HttpServer"));
        self.local_addr = Some(listener);
        Ok(listener)
    }

    /// Wait for the node to post something, and then return it.
    /// Errors are recoverable -- the caller should call this method again even if it returns an
    /// error.
    fn next_event(&mut self) -> Result<SignerEvent, EventError> {
        self.with_server(|event_receiver, http_server, is_mainnet| {
            // were we asked to terminate?
            if event_receiver.is_stopped() {
                return Err(EventError::Terminated);
            }
            let request = http_server.recv()?;

            if request.url() == "/status" {
                request
                .respond(HttpResponse::from_string("OK"))
                .expect("response failed");
                return Ok(SignerEvent::StatusCheck);
            }

            if request.method() != &HttpMethod::Post {
                return Err(EventError::MalformedRequest(format!(
                    "Unrecognized method '{}'",
                    &request.method(),
                )));
            }
            if request.url() == "/stackerdb_chunks" {
                process_stackerdb_event(event_receiver.local_addr, request, is_mainnet)
            } else if request.url() == "/proposal_response" {
                process_proposal_response(request)
            } else {
                let url = request.url().to_string();

                info!(
                    "[{:?}] next_event got request with unexpected url {}, return OK so other side doesn't keep sending this",
                    event_receiver.local_addr,
                    request.url()
                );

                if let Err(e) = request.respond(HttpResponse::empty(200u16)) {
                    error!("Failed to respond to request: {:?}", &e);
                }
                Err(EventError::UnrecognizedEvent(url))
            }
        })?
    }

    /// Determine if the receiver is hung up
    fn is_stopped(&self) -> bool {
        self.stop_signal.load(Ordering::SeqCst)
    }

    /// Forward an event
    /// Return true on success; false on error.
    /// Returning false terminates the event receiver.
    fn forward_event(&mut self, ev: SignerEvent) -> bool {
        if self.out_channels.is_empty() {
            // nothing to do
            error!("No channels connected to event receiver");
            false
        } else if self.out_channels.len() == 1 {
            // avoid a clone
            if let Err(e) = self.out_channels[0].send(ev) {
                error!("Failed to send to signer runloop: {:?}", &e);
                return false;
            }
            true
        } else {
            for (i, out_channel) in self.out_channels.iter().enumerate() {
                if let Err(e) = out_channel.send(ev.clone()) {
                    error!("Failed to send to signer runloop #{}: {:?}", i, &e);
                    return false;
                }
            }
            true
        }
    }

    /// Add an event consumer.  A received event will be forwarded to this Sender.
    fn add_consumer(&mut self, out_channel: Sender<SignerEvent>) {
        self.out_channels.push(out_channel);
    }

    /// Get a stopped signaler.  The caller can then use it to terminate the event receiver loop,
    /// even if it's in a different thread.
    fn get_stop_signaler(&mut self) -> Result<SignerStopSignaler, EventError> {
        if let Some(local_addr) = self.local_addr {
            Ok(SignerStopSignaler::new(
                self.stop_signal.clone(),
                local_addr,
            ))
        } else {
            Err(EventError::NotBound)
        }
    }
}

/// Process a stackerdb event from the node
fn process_stackerdb_event(
    local_addr: Option<SocketAddr>,
    mut request: HttpRequest,
    is_mainnet: bool,
) -> Result<SignerEvent, EventError> {
    debug!("Got stackerdb_chunks event");
    let mut body = String::new();
    if let Err(e) = request.as_reader().read_to_string(&mut body) {
        error!("Failed to read body: {:?}", &e);

        if let Err(e) = request.respond(HttpResponse::empty(200u16)) {
            error!("Failed to respond to request: {:?}", &e);
        };
        return Err(EventError::MalformedRequest(format!(
            "Failed to read body: {:?}",
            &e
        )));
    }

    let event: StackerDBChunksEvent = serde_json::from_slice(body.as_bytes())
        .map_err(|e| EventError::Deserialize(format!("Could not decode body to JSON: {:?}", &e)))?;

    let signer_event = if event.contract_id == boot_code_id(MINERS_NAME, is_mainnet) {
        let blocks: Vec<NakamotoBlock> = event
            .modified_slots
            .iter()
            .filter_map(|chunk| read_next::<NakamotoBlock, _>(&mut &chunk.data[..]).ok())
            .collect();
        SignerEvent::ProposedBlocks(blocks)
    } else if event.contract_id.name.to_string() == SIGNERS_NAME {
        // TODO: fix this to be against boot_code_id(SIGNERS_NAME, is_mainnet) when .signers is deployed
        let signer_messages: Vec<SignerMessage> = event
            .modified_slots
            .iter()
            .filter_map(|chunk| read_next::<SignerMessage, _>(&mut &chunk.data[..]).ok())
            .collect();
        SignerEvent::SignerMessages(signer_messages)
    } else {
        info!(
            "[{:?}] next_event got event from an unexpected contract id {}, return OK so other side doesn't keep sending this",
            local_addr,
            event.contract_id
        );
        if let Err(e) = request.respond(HttpResponse::empty(200u16)) {
            error!("Failed to respond to request: {:?}", &e);
        }
        return Err(EventError::UnrecognizedStackerDBContract(event.contract_id));
    };

    if let Err(e) = request.respond(HttpResponse::empty(200u16)) {
        error!("Failed to respond to request: {:?}", &e);
    }

    Ok(signer_event)
}

/// Process a proposal response from the node
fn process_proposal_response(mut request: HttpRequest) -> Result<SignerEvent, EventError> {
    debug!("Got proposal_response event");
    let mut body = String::new();
    if let Err(e) = request.as_reader().read_to_string(&mut body) {
        error!("Failed to read body: {:?}", &e);

        if let Err(e) = request.respond(HttpResponse::empty(200u16)) {
            error!("Failed to respond to request: {:?}", &e);
        }
        return Err(EventError::MalformedRequest(format!(
            "Failed to read body: {:?}",
            &e
        )));
    }

    let event: BlockValidateResponse = serde_json::from_slice(body.as_bytes())
        .map_err(|e| EventError::Deserialize(format!("Could not decode body to JSON: {:?}", &e)))?;

    if let Err(e) = request.respond(HttpResponse::empty(200u16)) {
        error!("Failed to respond to request: {:?}", &e);
    }

    Ok(SignerEvent::BlockValidationResponse(event))
}
