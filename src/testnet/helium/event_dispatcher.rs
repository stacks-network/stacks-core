use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::thread::spawn;
use std::net::{SocketAddr};
use mio::tcp::TcpStream;
use serde_json::json;
use serde::Serialize;

use vm::types::{Value, QualifiedContractIdentifier};
use chainstate::stacks::StacksTransactionEvent;
use chainstate::stacks::db::StacksHeaderInfo;
use super::config::{EventObserverConfig};

#[derive(Debug)]
struct EventObserver {
    stream: TcpStream
}

impl EventObserver {

    pub fn new(address: &str, port: u16) -> EventObserver {
        let sock_addr = SocketAddr::new(address.parse().unwrap(), port);
        let stream = TcpStream::connect(&sock_addr).unwrap();
        EventObserver { stream }
    }

    pub fn send(&mut self, events: Vec<&StacksTransactionEvent>, header_info: &StacksHeaderInfo) {
        // Serialize events to JSON
        let events_payload: Vec<serde_json::Value> = events.iter().map(|event| 
            match event {
                StacksTransactionEvent::SmartContractEvent(event_data) => json!({
                    "type": "contract_event",
                    "contract_event_data": {
                        "contract_identifier": event_data.key.0.to_string(),
                        "topic": event_data.key.1,
                        "value": event_data.value,
                    }
                }),
                StacksTransactionEvent::StacksTransfer(event_data) => json!({
                    "type": "transfer_event",
                    "transfer_event_data": {
                        "sender": event_data.sender.to_string(),
                        "recipient": event_data.recipient,
                        "amount": event_data.amount,
                        "asset_id": "STX",
                    }
                }),
            }).collect();

        // Wrap events
        let payload = json!({
            "index_block_hash": format!("{:?}", header_info.index_block_hash()),
            "parent_block_hash": format!("{:?}", header_info.anchored_header.parent_block),
            "burn_header_hash": format!("{:?}", header_info.burn_header_hash),
            "burn_header_timestamp": header_info.burn_header_timestamp,
            "block_height": header_info.block_height,
            "events": events_payload
        }).to_string();


        // Send payload
        let _res = self.stream.write_bufs(&vec![payload.as_bytes().into()]);

        // todo(ludo): if res = error, we should probably discard the observer
    }
}

pub struct EventDispatcher {
    registered_observers: Vec<EventObserver>,
    watched_events_lookup: HashMap<(QualifiedContractIdentifier, String), HashSet<u16>>,
}

impl EventDispatcher {

    pub fn new() -> EventDispatcher {
        EventDispatcher {
            registered_observers: vec![],
            watched_events_lookup: HashMap::new(),
        }
    }

    pub fn dispatch_events(&mut self, events: Vec<StacksTransactionEvent>, header_info: &StacksHeaderInfo) {
        let mut dispatch_matrix: Vec<Vec<usize>> = self.registered_observers.iter().map(|_| vec![]).collect();
        for (i, event) in events.iter().enumerate() {
            match event {
                StacksTransactionEvent::SmartContractEvent(event_data) => {
                    match self.watched_events_lookup.get(&event_data.key) {
                        Some(observer_indexes) => {
                            for o_i in observer_indexes {
                                dispatch_matrix[*o_i as usize].push(i);
                            }
                         },
                        None => {},
                    };
                },
                StacksTransactionEvent::StacksTransfer(event_data) => {
                    // todo(ludo): to implement
                }
            }
        }

        for (observer_id, filtered_events_ids) in dispatch_matrix.iter().enumerate() {
            if filtered_events_ids.len() == 0 {
                continue;
            }

            let mut filtered_events: Vec<&StacksTransactionEvent> = vec![];
            for event_id in filtered_events_ids {
                filtered_events.push(&events[*event_id]);
            }
            self.registered_observers[observer_id].send(filtered_events, header_info);
        }
    }

    pub fn register_observer(&mut self, conf: &EventObserverConfig) {
        let event_observer = EventObserver::new(&conf.address, conf.port);
        
        let observer_index = self.registered_observers.len() as u16;

        for event_key in conf.watched_event_keys.iter() {
            match self.watched_events_lookup.entry(event_key.clone()) {
                Entry::Occupied(observer_indexes) => {
                    observer_indexes.into_mut().insert(observer_index);
                },
                Entry::Vacant(v) => {
                    let mut observer_indexes = HashSet::new();
                    observer_indexes.insert(observer_index);
                    v.insert(observer_indexes);
                }
            };
        }

        self.registered_observers.push(event_observer);
    }
}
