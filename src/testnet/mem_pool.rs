use std::thread;
use std::time;
use std::fs;

use burnchains::{Txid};

pub trait MemPool {
    fn start(&mut self);
    fn stop(&mut self);
    fn reset(&mut self);
    fn handle_incoming_tx(&mut self, tx: Txid);
    fn archive_tx(&mut self, tx: Txid);
}

pub struct MemPoolFS {
    path: String,
    pending_txs: Vec<Txid>,
    archived_txs: Vec<Txid>,
}

impl MemPoolFS {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            pending_txs: vec![],
            archived_txs: vec![]
        }
    }
}

impl MemPool for MemPoolFS {
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
    }

    fn archive_tx(&mut self, tx: Txid) {
        // Remove tx from pending_txs
        // Add tx to archived_txs
    }
}