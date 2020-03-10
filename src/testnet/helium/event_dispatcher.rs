use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::thread::spawn;
use std::net::{SocketAddr};
use mio::tcp::TcpStream;
use serde_json::json;
use serde::Serialize;

use vm::types::{Value, QualifiedContractIdentifier};
use chainstate::stacks::events::{StacksTransactionEvent, STXEventType, FTEventType, NFTEventType};
use chainstate::stacks::db::StacksHeaderInfo;
use super::config::{EventObserverConfig};

#[derive(Debug)]
struct EventObserver {
    sock_addr: SocketAddr
}

impl EventObserver {

    pub fn new(address: &str, port: u16) -> EventObserver {
        let sock_addr = SocketAddr::new(address.parse().unwrap(), port);
        EventObserver { sock_addr }
    }

    pub fn send(&mut self, events: Vec<&StacksTransactionEvent>, header_info: &StacksHeaderInfo) {
        // Initiate a tcp socket
        let stream = TcpStream::connect(&self.sock_addr).unwrap();
        
        // Serialize events to JSON
        let events_payload: Vec<serde_json::Value> = events.iter().map(|event| 
            match event {
                StacksTransactionEvent::SmartContractEvent(event_data) => json!({
                    "type": "contract_event",
                    "contract_event": {
                        "contract_identifier": event_data.key.0.to_string(),
                        "topic": event_data.key.1,
                        "value": event_data.value,
                    }
                }),
                StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(event_data)) => json!({
                    "type": "stx_transfer_event",
                    "stx_transfer_event": event_data
                }),
                StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(event_data)) => json!({
                    "type": "stx_mint_event",
                    "stx_mint_event": event_data
                }),
                StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(event_data)) => json!({
                    "type": "stx_burn_event",
                    "stx_burn_event": event_data
                }),
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(event_data)) => json!({
                    "type": "nft_transfer_event",
                    "nft_transfer_event": event_data
                }),
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data)) => json!({
                    "type": "nft_mint_event",
                    "nft_mint_event": event_data
                }),
                StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data)) => json!({
                    "type": "ft_transfer_event",
                    "ft_transfer_event": event_data
                }),
                StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data)) => json!({
                    "type": "ft_mint_event",
                    "ft_mint_event": event_data
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
        let _res = stream.write_bufs(&vec![payload.as_bytes().into()]);

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

    pub fn dispatch_events(&mut self, events: &Vec<StacksTransactionEvent>, header_info: &StacksHeaderInfo) {
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
                StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(event_data)) => {},
                StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(event_data)) => {},
                StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(event_data)) => {},
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(event_data)) => {},
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data)) => {},
                StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data)) => {},
                StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data)) => {},
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
