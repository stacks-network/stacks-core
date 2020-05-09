use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::thread::sleep;

use rand::{Rng, thread_rng};
use reqwest::blocking::Client;
use serde_json::json;

use stacks::burnchains::Txid;
use stacks::chainstate::stacks::events::{StacksTransactionEvent, STXEventType, FTEventType, NFTEventType};
use stacks::net::StacksMessageCodec;
use stacks::vm::types::{Value, QualifiedContractIdentifier, AssetIdentifier};
use stacks::vm::analysis::{contract_interface_builder::build_contract_interface};

use super::config::{EventObserverConfig, EventKeyType};
use super::node::{ChainTip};

#[derive(Debug)]
struct EventObserver {
    endpoint: String,
}

impl EventObserver {

    pub fn send(&mut self, filtered_events: Vec<&(Txid, &StacksTransactionEvent)>, chain_tip: &ChainTip) {
        // Serialize events to JSON
        let serialized_events: Vec<serde_json::Value> = filtered_events.iter().map(|(txid, event)|
            event.json_serialize(txid)
        ).collect();

        let mut tx_index: u32 = 0;
        let serialized_txs: Vec<serde_json::Value> = chain_tip.receipts.iter().map(|receipt| {
            let tx = &receipt.transaction;

            let (success, result) = match &receipt.result {
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
            let contract_interface_json = {
                match &receipt.contract_analysis {
                    Some(analysis) => json!(build_contract_interface(analysis)),
                    None => json!(null)
                }
            };
            let val = json!({
                "txid": format!("0x{}", tx.txid()),
                "tx_index": tx_index,
                "success": success,
                "raw_result": format!("0x{}", raw_result.join("")),
                "raw_tx": format!("0x{}", raw_tx.join("")),
                "contract_abi": contract_interface_json,
            });
            tx_index += 1;
            val
        }).collect();
        
        // Wrap events
        let payload = json!({
            "block_hash": format!("0x{:?}", chain_tip.block.block_hash()),
            "block_height": chain_tip.metadata.block_height,
            "burn_block_time": chain_tip.metadata.burn_header_timestamp,
            "index_block_hash": format!("0x{:?}", chain_tip.metadata.index_block_hash()),
            "parent_block_hash": format!("0x{:?}", chain_tip.block.header.parent_block),
            "parent_microblock": format!("0x{:?}", chain_tip.block.header.parent_microblock),
            "events": serialized_events,
            "transactions": serialized_txs,
        });

        // Send payload
        let mut backoff: f64 = 1.0;
        let mut rng = thread_rng();
        loop {
            let response = Client::new()
                .post(&self.endpoint)
                .json(&payload)
                .send();

            match response {
                Ok(response) => {
                    if response.status().is_success() {
                        break;
                    }
                    error!("Event dispatcher: POST {:?} failed with error {:?}", self.endpoint, response);
                },
                Err(e) => {
                    error!("Event dispatcher: POST {:?} failed with error {:?}", self.endpoint, e);
                }
            };

            backoff = (2.0 * backoff + (backoff * rng.gen_range(0.0, 1.0))).min(60.0);
            let duration = Duration::from_millis((backoff * 1_000.0) as u64);
            info!("Event dispatcher will retry posting in {:?}", duration);
            sleep(duration);
        };
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

    pub fn process_chain_tip(&mut self, chain_tip: &ChainTip) {

        let mut dispatch_matrix: Vec<HashSet<usize>> = self.registered_observers.iter().map(|_| HashSet::new()).collect();
        let mut events: Vec<(Txid, &StacksTransactionEvent)> = vec![];
        let mut i: usize = 0;
        for receipt in chain_tip.receipts.iter() {
            let tx_hash = receipt.transaction.txid();
            for event in receipt.events.iter() {
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
            self.registered_observers[observer_id].send(filtered_events, chain_tip);
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
        // let event_observer = EventObserver::new(&conf.address, conf.port);
        info!("Registering event observer at: {}", conf.endpoint);
        let event_observer = EventObserver { 
            endpoint: conf.endpoint.clone(),
        };

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
