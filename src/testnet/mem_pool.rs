use std::thread;
use std::time;
use std::fs;
use std::io::Read;

use burnchains::{Txid};
use chainstate::stacks::{StacksTransaction};
use net::StacksMessageCodec;

pub trait MemPool {
    fn poll(&mut self) -> Vec<StacksTransaction>;
    fn start(&mut self);
    fn stop(&mut self);
    fn handle_incoming_tx(&mut self, tx: Txid);
    fn archive_tx(&mut self, tx: Txid);
}

#[derive(Clone)]
pub struct MemPoolFS {
    path: String,
    pending_txs: Vec<StacksTransaction>,
    archived_txs: Vec<StacksTransaction>,
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

    fn poll(&mut self) -> Vec<StacksTransaction> {
        let txs_paths = fs::read_dir(self.path.clone()).unwrap();
        let mut decoded_txs = vec![];

        for tx in txs_paths {
            if let Ok(tx) = tx {
                let path = tx.path();
                if path.is_dir() {
                    continue;
                }
                
                let mut file = fs::File::open(path).unwrap();
                let mut encoded_tx = vec![];
                file.read(&mut encoded_tx[..]).unwrap();

                let mut index = 0;
                let tx = StacksTransaction::deserialize(&encoded_tx, &mut index, encoded_tx.len() as u32).map_err(|_e| {
                    eprintln!("Failed to decode transaction");
                    panic!();
                }).unwrap();
                
                decoded_txs.push(tx)
            }
        }
        decoded_txs
    }

    fn start(&mut self) {
    }

    fn stop(&mut self) {
    }

    fn handle_incoming_tx(&mut self, tx: Txid) {
    }

    fn archive_tx(&mut self, tx: Txid) {
        // Remove tx from pending_txs
        // Add tx to archived_txs
    }
}