use super::{MemPoolObserver, MemPool};
use std::fs;
use std::env;
use std::process;
use net::StacksMessageCodec;
use chainstate::stacks::*;
use util::hash::hex_bytes;

use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::{StacksBlock, StacksMicroblock, CoinbasePayload};
use chainstate::burn::db::burndb::{BurnDB};
use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey};
use chainstate::stacks::{StacksPrivateKey};
use chainstate::burn::operations::{LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::SortitionHash;
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::Sha256Sum;
use std::collections::HashMap;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rand::RngCore;
use util::hash::{to_hex};
use std::{thread, time};


pub struct MemPoolFS {
    path: String,
    pending_txs: Vec<Txid>,
    archived_txs: Vec<Txid>,
}

impl MemPoolFS {
    pub fn new(path: String) -> Self {
        Self {
            path,
            pending_txs: vec![],
            archived_txs: vec![],
        }
    }
}

impl MemPoolFS {
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