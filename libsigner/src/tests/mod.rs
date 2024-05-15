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

mod http;

use std::fmt::Debug;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use std::{mem, thread};

use blockstack_lib::chainstate::nakamoto::signer_set::NakamotoSigners;
use blockstack_lib::chainstate::stacks::boot::SIGNERS_NAME;
use blockstack_lib::chainstate::stacks::events::StackerDBChunksEvent;
use blockstack_lib::util_lib::boot::boot_code_id;
use clarity::vm::types::QualifiedContractIdentifier;
use libstackerdb::StackerDBChunkData;
use stacks_common::codec::{
    read_next, read_next_at_most, read_next_exact, write_next, Error as CodecError,
    StacksMessageCodec,
};
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::sleep_ms;
use wsts::net::{DkgBegin, Packet};

use crate::events::{SignerEvent, SignerEventTrait};
use crate::v1::messages::SignerMessage;
use crate::{Signer, SignerEventReceiver, SignerRunLoop};

/// Simple runloop implementation.  It receives `max_events` events and returns `events` from the
/// last call to `run_one_pass` as its final state.
struct SimpleRunLoop<T: SignerEventTrait> {
    poll_timeout: Duration,
    events: Vec<SignerEvent<T>>,
    max_events: usize,
}

impl<T: SignerEventTrait> SimpleRunLoop<T> {
    pub fn new(max_events: usize) -> SimpleRunLoop<T> {
        SimpleRunLoop {
            poll_timeout: Duration::from_millis(100),
            events: vec![],
            max_events,
        }
    }
}

enum Command {
    Empty,
}

impl<T: SignerEventTrait> SignerRunLoop<Vec<SignerEvent<T>>, Command, T> for SimpleRunLoop<T> {
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.poll_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.poll_timeout
    }

    fn run_one_pass(
        &mut self,
        event: Option<SignerEvent<T>>,
        _cmd: Option<Command>,
        _res: Sender<Vec<SignerEvent<T>>>,
    ) -> Option<Vec<SignerEvent<T>>> {
        debug!("Got event: {:?}", &event);
        if let Some(event) = event {
            self.events.push(event);
        }

        if self.events.len() >= self.max_events {
            Some(mem::take(&mut self.events))
        } else {
            None
        }
    }
}

/// Set up a simple event listener thread and signer runloop thread, and verify that a mocked node
/// can feed the event listener events, which in turn get fed into the signer runloop for
/// processing.  Verify that the event stop signaler can be used to terminate both the event loop
/// and the signer runloop.
#[test]
fn test_simple_signer() {
    let contract_id = NakamotoSigners::make_signers_db_contract_id(0, 0, false);
    let ev = SignerEventReceiver::new(false);
    let (_cmd_send, cmd_recv) = channel();
    let (res_send, _res_recv) = channel();
    let max_events = 5;
    let mut signer = Signer::new(SimpleRunLoop::new(max_events), ev, cmd_recv, res_send);
    let endpoint: SocketAddr = "127.0.0.1:30000".parse().unwrap();
    let mut chunks = vec![];
    for i in 0..max_events {
        let privk = Secp256k1PrivateKey::new();
        let msg = wsts::net::Message::DkgBegin(DkgBegin { dkg_id: 0 });
        let message = SignerMessage::Packet(Packet { msg, sig: vec![] });
        let message_bytes = message.serialize_to_vec();
        let mut chunk = StackerDBChunkData::new(i as u32, 1, message_bytes);
        chunk.sign(&privk).unwrap();

        let chunk_event = StackerDBChunksEvent {
            contract_id: contract_id.clone(),
            modified_slots: vec![chunk],
        };
        chunks.push(chunk_event);
    }

    let thread_chunks = chunks.clone();

    // simulate a node that's trying to push data
    let mock_stacks_node = thread::spawn(move || {
        let mut num_sent = 0;
        while num_sent < thread_chunks.len() {
            let mut sock = match TcpStream::connect(endpoint) {
                Ok(sock) => sock,
                Err(..) => {
                    sleep_ms(100);
                    continue;
                }
            };

            let ev = &thread_chunks[num_sent];
            let body = serde_json::to_string(ev).unwrap();
            let req = format!(
                "POST /stackerdb_chunks HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                endpoint,
                &body.len(),
                body
            );
            debug!("Send:\n{}", &req);

            sock.write_all(req.as_bytes()).unwrap();
            sock.flush().unwrap();

            num_sent += 1;
        }
    });

    let running_signer = signer.spawn(endpoint).unwrap();
    sleep_ms(5000);
    let accepted_events = running_signer.stop().unwrap();

    chunks.sort_by(|ev1, ev2| {
        ev1.modified_slots[0]
            .slot_id
            .partial_cmp(&ev2.modified_slots[0].slot_id)
            .unwrap()
    });

    let sent_events: Vec<SignerEvent<SignerMessage>> = chunks
        .iter()
        .map(|chunk| {
            let msg = chunk.modified_slots[0].data.clone();
            let signer_message = read_next::<SignerMessage, _>(&mut &msg[..]).unwrap();
            SignerEvent::SignerMessages(0, vec![signer_message])
        })
        .collect();

    assert_eq!(sent_events, accepted_events);
    mock_stacks_node.join().unwrap();
}

#[test]
fn test_status_endpoint() {
    let ev = SignerEventReceiver::new(false);
    let (_cmd_send, cmd_recv) = channel();
    let (res_send, _res_recv) = channel();
    let max_events = 1;
    let mut signer = Signer::new(SimpleRunLoop::new(max_events), ev, cmd_recv, res_send);
    let endpoint: SocketAddr = "127.0.0.1:31000".parse().unwrap();

    // simulate a node that's trying to push data
    let mock_stacks_node = thread::spawn(move || {
        let mut sock = match TcpStream::connect(endpoint) {
            Ok(sock) => sock,
            Err(e) => {
                eprint!("Error connecting to {}: {}", endpoint, e);
                sleep_ms(100);
                return;
            }
        };
        let req = format!(
            "GET /status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            endpoint
        );

        sock.write_all(req.as_bytes()).unwrap();
        let mut buf = [0; 128];
        let _ = sock.read(&mut buf).unwrap();
        let res_str = std::str::from_utf8(&buf).unwrap();
        let expected_status_res = "HTTP/1.1 200 OK\r\n";
        assert_eq!(expected_status_res, &res_str[..expected_status_res.len()]);
        sock.flush().unwrap();
    });

    let running_signer = signer.spawn(endpoint).unwrap();
    sleep_ms(3000);
    let accepted_events = running_signer.stop().unwrap();

    let sent_events: Vec<SignerEvent<SignerMessage>> = vec![SignerEvent::StatusCheck];

    assert_eq!(sent_events, accepted_events);
    mock_stacks_node.join().unwrap();
}
