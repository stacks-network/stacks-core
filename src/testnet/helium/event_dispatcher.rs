use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::thread::spawn;
use std::net::{SocketAddr};
use mio::tcp::TcpStream;
use serde_json::json;
use serde::Serialize;

use vm::types::{Value, QualifiedContractIdentifier, AssetIdentifier};
use net::StacksMessageCodec;
use chainstate::stacks::{StacksBlock};
use chainstate::stacks::events::{StacksTransactionEvent, STXEventType, FTEventType, NFTEventType};
use chainstate::stacks::db::StacksHeaderInfo;
use super::config::{EventObserverConfig, EventKeyType};

#[derive(Debug)]
struct EventObserver {
    sock_addr: SocketAddr
}

impl EventObserver {

    pub fn new(address: &str, port: u16) -> EventObserver {
        let sock_addr = SocketAddr::new(address.parse().unwrap(), port);
        EventObserver { sock_addr }
    }

    pub fn send(&mut self, events: Vec<&StacksTransactionEvent>, chain_tip: &StacksBlock, chain_tip_info: &StacksHeaderInfo) {
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

        let serialized_txs: Vec<String> = chain_tip.txs.iter().map(|t| {
            let mut unsigned_tx_bytes = vec![];
            t.consensus_serialize(&mut unsigned_tx_bytes).unwrap();
            let formatted_bytes: Vec<String> = unsigned_tx_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            format!("0x{}", formatted_bytes.join(""))
        }).collect();
        
        // Wrap events
        let payload = json!({
            "block_hash": format!("0x{:?}", chain_tip.block_hash()),
            "index_block_hash": format!("0x{:?}", chain_tip_info.index_block_hash()),
            "parent_block_hash": format!("0x{:?}", chain_tip.header.parent_block),
            "parent_microblock": format!("0x{:?}", chain_tip.header.parent_microblock),
            "events": events_payload,
            "transactions": serialized_txs,
        }).to_string();

        // Send payload
        let _res = stream.write_bufs(&vec![payload.as_bytes().into()]);
        match _res { 
            Err(err) => {
                eprintln!("Failed to write events to socket {}: {}", &self.sock_addr, err);
            },
            _ => ()
        };
    }
}

pub struct EventDispatcher {
    registered_observers: Vec<EventObserver>,
    contract_events_observers_lookup: HashMap<(QualifiedContractIdentifier, String), HashSet<u16>>,
    any_contract_events_observers_lookups: HashSet<u16>,
    assets_observers_lookup: HashMap<AssetIdentifier, HashSet<u16>>,
    any_asset_observers_lookup: HashSet<u16>,
    stx_observers_lookup: HashSet<u16>,
}

impl EventDispatcher {

    pub fn new() -> EventDispatcher {
        EventDispatcher {
            registered_observers: vec![],
            contract_events_observers_lookup: HashMap::new(),
            any_contract_events_observers_lookups: HashSet::new(),
            assets_observers_lookup: HashMap::new(),
            any_asset_observers_lookup: HashSet::new(),
            stx_observers_lookup: HashSet::new(),
        }
    }

    pub fn dispatch_events(&mut self, events: &Vec<StacksTransactionEvent>, chain_tip: &StacksBlock, chain_tip_info: &StacksHeaderInfo) {
        let mut dispatch_matrix: Vec<Vec<usize>> = self.registered_observers.iter().map(|_| vec![]).collect();
        for (i, event) in events.iter().enumerate() {
            match event {
                StacksTransactionEvent::SmartContractEvent(event_data) => {
                    if let Some(observer_indexes) = self.contract_events_observers_lookup.get(&event_data.key) {
                        for o_i in observer_indexes {
                            dispatch_matrix[*o_i as usize].push(i);
                        }
                    }
                    for o_i in &self.any_contract_events_observers_lookups {
                        dispatch_matrix[*o_i as usize].push(i);
                    }
                },
                StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(_)) |
                StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(_)) |
                StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(_)) => {
                    for o_i in &self.stx_observers_lookup {
                        dispatch_matrix[*o_i as usize].push(i);
                    }
                },
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(event_data)) => {
                    self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    for o_i in &self.any_asset_observers_lookup {
                        dispatch_matrix[*o_i as usize].push(i);
                    }
                },
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data)) => {
                    self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    for o_i in &self.any_asset_observers_lookup {
                        dispatch_matrix[*o_i as usize].push(i);
                    }
                },
                StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data)) => {
                    self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    for o_i in &self.any_asset_observers_lookup {
                        dispatch_matrix[*o_i as usize].push(i);
                    }
                },
                StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data)) => {
                    self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    for o_i in &self.any_asset_observers_lookup {
                        dispatch_matrix[*o_i as usize].push(i);
                    }
                },
            }
        }

        for (observer_id, filtered_events_ids) in dispatch_matrix.iter().enumerate() {
            let mut filtered_events: Vec<&StacksTransactionEvent> = vec![];
            for event_id in filtered_events_ids {
                filtered_events.push(&events[*event_id]);
            }
            self.registered_observers[observer_id].send(filtered_events, chain_tip, chain_tip_info);
        }
    }

    fn update_dispatch_matrix_if_observer_subscribed(&self, asset_identifier: &AssetIdentifier, event_index: usize, dispatch_matrix: &mut Vec<Vec<usize>>) {
        if let Some(observer_indexes) = self.assets_observers_lookup.get(asset_identifier) {
            for o_i in observer_indexes {
                dispatch_matrix[*o_i as usize].push(event_index);
            }
        }
    }

    pub fn register_observer(&mut self, conf: &EventObserverConfig) {
        let event_observer = EventObserver::new(&conf.address, conf.port);
        
        let observer_index = self.registered_observers.len() as u16;

        for event_key_type in conf.events_keys.iter() {
            match event_key_type {
                EventKeyType::SmartContractEvent(event_key) => {
                    match self.contract_events_observers_lookup.entry(event_key.clone()) {
                        Entry::Occupied(observer_indexes) => {
                            observer_indexes.into_mut().insert(observer_index);
                        },
                        Entry::Vacant(v) => {
                            let mut observer_indexes = HashSet::new();
                            observer_indexes.insert(observer_index);
                            v.insert(observer_indexes);
                        }
                    };
                },
                EventKeyType::AnySmartContractEvent => {
                    self.any_contract_events_observers_lookups.insert(observer_index);
                },
                EventKeyType::STXEvent => {
                    self.stx_observers_lookup.insert(observer_index);
                },
                EventKeyType::AnyAssetEvent => {
                    self.any_asset_observers_lookup.insert(observer_index);
                },
                EventKeyType::AssetEvent(event_key) => {
                    match self.assets_observers_lookup.entry(event_key.clone()) {
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
            }

        }

        self.registered_observers.push(event_observer);
    }
}
