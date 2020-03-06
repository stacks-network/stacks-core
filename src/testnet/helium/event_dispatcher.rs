use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::thread::spawn;

use vm::types::{Value, QualifiedContractIdentifier};
use super::config::{EventObserverConfig};

#[derive(Debug)]
struct ContractEvent {
    key: (QualifiedContractIdentifier, String),
    value: Value,
}

#[derive(Debug)]
struct EventObserver {
    pub address: String,
    pub port: u16,
}

impl EventObserver {

    pub fn write(&mut self, events: Vec<&ContractEvent>) {
        // serialize events in JSON, write to socket
    }
}

struct EventDispatcher {
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

    pub fn dispatch_events(&mut self, events: Vec<ContractEvent>) {
        let mut dispatch_grid: Vec<Vec<u16>> = self.registered_observers.iter().map(|_| vec![]).collect();
        for (i, ContractEvent { key, value: _ }) in events.iter().enumerate() {
            match self.watched_events_lookup.get(key) {
                Some(observer_indexes) => {
                    for o_i in observer_indexes {
                        // todo(ludo): should we move the interior vector to hashset?
                        dispatch_grid[*o_i as usize].push(i as u16);
                    }
                 },
                None => {},
            };
        }

        for (observer_id, filtered_events) in dispatch_grid.iter().enumerate() {
            // let events: Vec<&ContractEvent> = events.iter().enumerate().filter(|&(i, _)| i == 3 )
            // self.registered_observers[observer_id].write()
            println!("Dispatching {:?} to {:?}", self.registered_observers[observer_id], filtered_events);
        }
    }

    pub fn register_observer(&mut self, conf: &EventObserverConfig) {
        let event_observer = EventObserver {
            address: conf.address.clone(),
            port: conf.port,
        };
        
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
