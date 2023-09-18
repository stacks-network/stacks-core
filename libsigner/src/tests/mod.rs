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

use std::io::Write;
use std::mem;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Duration;

use serde_json;

use crate::{Signer, SignerRunLoop, StackerDBChunksEvent, StackerDBEventReceiver};

use clarity::vm::types::QualifiedContractIdentifier;

use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::sleep_ms;

use libstackerdb::StackerDBChunkData;

/// Simple runloop implementation.  It receives `max_events` events and returns `events` from the
/// last call to `run_one_pass` as its final state.
struct SimpleRunLoop {
    poll_timeout: Duration,
    events: Vec<StackerDBChunksEvent>,
    max_events: usize,
}

impl SimpleRunLoop {
    pub fn new(max_events: usize) -> SimpleRunLoop {
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

impl SignerRunLoop<Vec<StackerDBChunksEvent>, Command> for SimpleRunLoop {
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.poll_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.poll_timeout.clone()
    }

    fn run_one_pass(
        &mut self,
        event: Option<StackerDBChunksEvent>,
        _cmd: Option<Command>,
    ) -> Option<Vec<StackerDBChunksEvent>> {
        debug!("Got event: {:?}", &event);
        if let Some(event) = event {
            self.events.push(event);
        }

        if self.events.len() >= self.max_events {
            return Some(mem::replace(&mut self.events, vec![]));
        } else {
            return None;
        }
    }
}

/// Set up a simple event listener thread and signer runloop thread, and verify that a mocked node
/// can feed the event listener events, which in turn get fed into the signer runloop for
/// processing.  Verify that the event stop signaler can be used to terminate both the event loop
/// and the signer runloop.
#[test]
fn test_simple_signer() {
    let ev = StackerDBEventReceiver::new(vec![QualifiedContractIdentifier::parse(
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world",
    )
    .unwrap()]);
    let (_cmd_send, cmd_recv) = channel();
    let mut signer = Signer::new(SimpleRunLoop::new(5), ev, cmd_recv);
    let endpoint: SocketAddr = "127.0.0.1:30000".parse().unwrap();
    let thread_endpoint = endpoint.clone();

    let mut chunks = vec![];
    for i in 0..5 {
        let privk = Secp256k1PrivateKey::new();
        let mut chunk = StackerDBChunkData::new(i as u32, 1, "hello world".as_bytes().to_vec());
        chunk.sign(&privk).unwrap();

        let chunk_event = StackerDBChunksEvent {
            contract_id: QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world",
            )
            .unwrap(),
            modified_slots: vec![chunk],
        };
        chunks.push(chunk_event);
    }

    let thread_chunks = chunks.clone();

    // simulate a node that's trying to push data
    let mock_stacks_node = thread::spawn(move || {
        let mut num_sent = 0;
        while num_sent < thread_chunks.len() {
            let mut sock = match TcpStream::connect(&thread_endpoint) {
                Ok(sock) => sock,
                Err(..) => {
                    sleep_ms(100);
                    continue;
                }
            };

            let body = serde_json::to_string(&thread_chunks[num_sent]).unwrap();
            let req = format!("POST /stackerdb_chunks HTTP/1.0\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", &body.len(), body);
            debug!("Send:\n{}", &req);

            sock.write_all(req.as_bytes()).unwrap();
            sock.flush().unwrap();

            num_sent += 1;
        }
    });

    let running_signer = signer.spawn(endpoint).unwrap();
    sleep_ms(5000);
    let mut accepted_events = running_signer.stop().unwrap();

    chunks.sort_by(|ev1, ev2| {
        ev1.modified_slots[0]
            .slot_id
            .partial_cmp(&ev2.modified_slots[0].slot_id)
            .unwrap()
    });
    accepted_events.sort_by(|ev1, ev2| {
        ev1.modified_slots[0]
            .slot_id
            .partial_cmp(&ev2.modified_slots[0].slot_id)
            .unwrap()
    });

    // runloop got the event that the mocked stacks node sent
    assert_eq!(accepted_events, chunks);
    mock_stacks_node.join().unwrap();
}
