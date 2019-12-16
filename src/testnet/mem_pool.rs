use std::thread;
use std::time;
use std::fs;

use burnchains::{Txid};

pub trait MemPool <'a> {
    fn start(&mut self);
    fn stop(&mut self);
    fn reset(&mut self);
    fn handle_incoming_tx(&mut self, tx: Txid);
    fn archive_tx(&mut self, tx: Txid);
    fn register_observer(&mut self, observer: &'a mut MemPoolObserver);
    fn unregister_observer(&mut self, observer: &'a mut MemPoolObserver);
}

pub trait MemPoolObserver {
    fn handle_received_tx(&mut self, tx: Txid);
    fn handle_archived_tx(&mut self, tx: Txid);
}

pub struct MemPoolFS <'a> {
    path: String,
    pending_txs: Vec<Txid>,
    archived_txs: Vec<Txid>,
    observers: Vec<&'a mut MemPoolObserver>
}

impl <'a> MemPoolFS <'a> {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            pending_txs: vec![],
            archived_txs: vec![],
            observers: vec![],
        }
    }
}

impl <'a> MemPool <'a> for MemPoolFS <'a> {
    fn start(&mut self) {
        loop {
            let block_time = time::Duration::from_millis(10000);
            let now = time::Instant::now();
            thread::sleep(block_time);
            println!("Tick");

            let mempool = fs::read_dir(self.path.clone()).unwrap();
            for tx in mempool {
                // De-serialize tx
                let txid = Txid([0u8; 32]);
                self.handle_incoming_tx(txid);
            }
        }
    }

    fn stop(&mut self) {

    }

    fn reset(&mut self) {

    }

    fn handle_incoming_tx(&mut self, tx: Txid) {
        for observer in self.observers.iter_mut() {
            observer.handle_received_tx(tx);
        }
    }

    fn archive_tx(&mut self, tx: Txid) {
        // Remove tx from pending_txs
        // Add tx to archived_txs
    }

    fn register_observer(&mut self, observer: &'a mut MemPoolObserver) {
        self.observers.push(observer);
    }

    fn unregister_observer(&mut self, observer: &'a mut MemPoolObserver) {
        // Remove observer from observers
    }
}