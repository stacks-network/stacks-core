use std::thread;
use std::time;
use std::fs;
use std::io::Read;
use std::io::BufReader;
use std::io::prelude::*;
use rand::RngCore;
use util::hash::{to_hex};

use burnchains::{Txid};
use chainstate::stacks::{StacksTransaction};
use net::StacksMessageCodec;

pub trait MemPool {
    fn poll(&mut self) -> Vec<StacksTransaction>;
    fn start(&mut self);
    fn stop(&mut self);
    fn handle_incoming_tx(&mut self, tx: StacksTransaction);
    fn submit(&self, tx: Vec<u8>);
    fn archive_tx(&mut self, tx: StacksTransaction);
}

#[derive(Clone)]
pub struct MemPoolFS {
    path: String,
}

impl MemPoolFS {
    pub fn new(path: &str) -> Self {
        match fs::create_dir_all(path) {
            Ok(_) => {},
            Err(_) => panic!("Error while creating dir at path {}", path)
        };

        Self {
            path: path.to_string(),
        }
    }
}

impl MemPool for MemPoolFS {

    fn poll(&mut self) -> Vec<StacksTransaction> {
        let txs_paths = fs::read_dir(&self.path).unwrap();
        let mut decoded_txs = vec![];

        for tx in txs_paths {
            if let Ok(tx) = tx {
                let path = tx.path();
                if path.is_dir() {
                    continue;
                }

                let file = fs::File::open(path.clone()).unwrap();
                let mut reader = BufReader::new(file);
                assert!(reader.buffer().is_empty());
                reader.fill_buf().unwrap();
                let encoded_tx: Vec<u8> = reader.buffer().to_vec();
                let mut index = 0;
                match StacksTransaction::deserialize(&encoded_tx, &mut index, encoded_tx.len() as u32) {
                    Ok(tx) => decoded_txs.push(tx),
                    Err(e) => warn!("Failed to decode transaction {:?}", e)
                };

                fs::remove_file(path).unwrap();
            }
        }
        decoded_txs
    }

    fn submit(&self, tx: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        let tx_file = format!("{}/{}.tx", self.path, to_hex(&buf));
    
        let mut file = fs::File::create(tx_file).unwrap();
        file.write_all(&tx).unwrap();    
    }

    fn start(&mut self) {
        // no op - irrelevant in the case of MemPoolFS
    }

    fn stop(&mut self) {
        // no op - irrelevant in the case of MemPoolFS
    }

    fn handle_incoming_tx(&mut self, tx: StacksTransaction) {
        // no op - irrelevant in the case of MemPoolFS
    }

    fn archive_tx(&mut self, tx: StacksTransaction) {
        // no op - irrelevant in the case of MemPoolFS
    }
}