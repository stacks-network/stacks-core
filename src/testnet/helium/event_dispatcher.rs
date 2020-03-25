use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::thread::spawn;
use std::net::{SocketAddr};
use mio::tcp::TcpStream;
use serde_json::json;
use serde::Serialize;

use vm::types::{Value, QualifiedContractIdentifier, AssetIdentifier};
use burnchains::Txid;
use chainstate::stacks::StacksBlock;
use chainstate::stacks::events::{StacksTransactionReceipt, StacksTransactionEvent, STXEventType, FTEventType, NFTEventType};
use chainstate::stacks::db::StacksHeaderInfo;
use net::StacksMessageCodec;

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

    pub fn send(&mut self, filtered_events: Vec<&(Txid, &StacksTransactionEvent)>, chain_tip: &StacksBlock, chain_tip_info: &StacksHeaderInfo, receipts: &Vec<StacksTransactionReceipt>) {
        // Initiate a tcp socket
        let stream = TcpStream::connect(&self.sock_addr).unwrap();
        
        // Serialize events to JSON
        let serialized_events: Vec<serde_json::Value> = filtered_events.iter().map(|(txid, event)|
            event.json_serialize(txid)
        ).collect();

        let serialized_txs: Vec<serde_json::Value> = receipts.iter().map(|artifact| {
            let tx = &artifact.transaction;

            let (success, result) = match &artifact.result {
                Value::Response(response_data) => {
                    (response_data.committed, response_data.data.clone())
                },
                _ => unreachable!(), // Transaction results should always be a Value::Response type
            };

            let raw_tx = {
                let mut bytes = vec![];
                tx.consensus_serialize(&mut bytes).unwrap();
                let formatted_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                formatted_bytes
            };
            
            let raw_result = {
                let mut bytes = vec![];
                result.consensus_serialize(&mut bytes).unwrap();
                let formatted_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                formatted_bytes
            };

            json!({
                "txid": format!("0x{}", tx.txid()),
                "success": success,
                "raw_result": format!("0x{}", raw_result.join("")),
                "raw_tx": format!("0x{}", raw_tx.join("")),
            })
        }).collect();
        
        // Wrap events
        let payload = json!({
            "block_hash": format!("0x{:?}", chain_tip.block_hash()),
            "block_height": chain_tip_info.block_height,
            "index_block_hash": format!("0x{:?}", chain_tip_info.index_block_hash()),
            "parent_block_hash": format!("0x{:?}", chain_tip.header.parent_block),
            "parent_microblock": format!("0x{:?}", chain_tip.header.parent_microblock),
            "events": serialized_events,
            "transactions": serialized_txs,
        }).to_string();

        // Send payload
        let res = stream.write_bufs(&vec![payload.as_bytes().into()]);
        if let Err(err) = res {
            error!("Event dispatcher failed sending buffer: {:?}", err);
        }
    }
}

pub struct EventDispatcher {
    registered_observers: Vec<EventObserver>,
    contract_events_observers_lookup: HashMap<(QualifiedContractIdentifier, String), HashSet<u16>>,
    assets_observers_lookup: HashMap<AssetIdentifier, HashSet<u16>>,
    stx_observers_lookup: HashSet<u16>,
    any_event_observers_lookup: HashSet<u16>,
}

impl EventDispatcher {

    pub fn new() -> EventDispatcher {
        EventDispatcher {
            registered_observers: vec![],
            contract_events_observers_lookup: HashMap::new(),
            assets_observers_lookup: HashMap::new(),
            stx_observers_lookup: HashSet::new(),
            any_event_observers_lookup: HashSet::new(),
        }
    }

    pub fn process_receipts(&mut self, receipts: &Vec<StacksTransactionReceipt>, chain_tip: &StacksBlock, chain_tip_info: &StacksHeaderInfo) {
        let mut dispatch_matrix: Vec<HashSet<usize>> = self.registered_observers.iter().map(|_| HashSet::new()).collect();
        let mut events: Vec<(Txid, &StacksTransactionEvent)> = vec![];
        let mut i: usize = 0;
        for artifact in receipts.iter() {
            let tx_hash = artifact.transaction.txid();
            for event in artifact.events.iter() {
                match event {
                    StacksTransactionEvent::SmartContractEvent(event_data) => {
                        if let Some(observer_indexes) = self.contract_events_observers_lookup.get(&event_data.key) {
                            for o_i in observer_indexes {
                                dispatch_matrix[*o_i as usize].insert(i);
                            }
                        }
                    },
                    StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(_)) |
                    StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(_)) |
                    StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(_)) => {
                        for o_i in &self.stx_observers_lookup {
                            dispatch_matrix[*o_i as usize].insert(i);
                        }
                    },
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    },
                    StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    },
                    StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    },
                    StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(event_data)) => {
                        self.update_dispatch_matrix_if_observer_subscribed(&event_data.asset_identifier, i, &mut dispatch_matrix);
                    },
                }
                events.push((tx_hash, event));
                for o_i in &self.any_event_observers_lookup {
                    dispatch_matrix[*o_i as usize].insert(i);
                }
                i += 1;
            }
        }


        for (observer_id, filtered_events_ids) in dispatch_matrix.iter().enumerate() {
            let mut filtered_events: Vec<&(Txid, &StacksTransactionEvent)> = vec![];
            for event_id in filtered_events_ids {
                filtered_events.push(&events[*event_id]);
            }
            self.registered_observers[observer_id].send(filtered_events, chain_tip, chain_tip_info, receipts);
        }
    }

    fn update_dispatch_matrix_if_observer_subscribed(&self, asset_identifier: &AssetIdentifier, event_index: usize, dispatch_matrix: &mut Vec<HashSet<usize>>) {
        if let Some(observer_indexes) = self.assets_observers_lookup.get(asset_identifier) {
            for o_i in observer_indexes {
                dispatch_matrix[*o_i as usize].insert(event_index);
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
                EventKeyType::STXEvent => {
                    self.stx_observers_lookup.insert(observer_index);
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
                },
                EventKeyType::AnyEvent => {
                    self.any_event_observers_lookup.insert(observer_index);
                },
            }

        }

        self.registered_observers.push(event_observer);
    }
}
