use vm::types::{Value, ContractIdentifier} ;

struct ContractEvent {
    contract_identifier: ContractIdentifier,
    name: String,
    value: Value,
}

struct Sidecar {
    pub address: String,
    pub port: u16,
    pub watched_events: Vec<ContractEvent>,
}

struct EventDispatcher {
    registered_sidecars: Vec<Sidecar>,
}

impl EventDispatcher {

    pub fn new() -> EventDispatcher {
        EventDispatcher {}
    }

    pub fn dispatch_events(&mut self, events: Vec<ContractEvent>) {
        
    }

    pub fn register_sidecar(&mut self, sidecar: &Sidecar) {

    }
}
