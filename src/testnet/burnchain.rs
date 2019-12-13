use std::sync::mpsc;
use std::thread;
use std::time;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey, BurnchainBlock};
use chainstate::burn::db::burndb::{BurnDB};
use burnchains::bitcoin::BitcoinBlock;
use util::hash::Sha256Sum;
use chainstate::burn::{SortitionHash, BlockSnapshot, VRFSeed};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use std::sync::{Arc, Mutex};

pub struct BurnchainSimulator {
    mem_pool: Arc<Mutex<Vec<BlockstackOperationType>>>,
}

impl BurnchainSimulator {

    pub fn new() -> BurnchainSimulator {
        Self {
            mem_pool: Arc::new(Mutex::new(vec![]))
        }
    }
    
    pub fn start(&mut self, block_time: time::Duration, path: String, name: String) -> mpsc::Receiver<BlockSnapshot> {
        let (tx, rx) = mpsc::channel();
        
        let builder = thread::Builder::new();

        let mem_pool = Arc::clone(&self.mem_pool);

        let handler = builder.spawn(move || {

            let chain = Burnchain::new(&path, &"bitcoin".to_string(), &name).unwrap();
    
            let mut db = BurnDB::connect(&path, 0, &BurnchainHeaderHash([0u8; 32]), true).unwrap();
    
            let mut chain_tip = BurnDB::get_first_block_snapshot(db.conn()).unwrap();
            
            loop {
                thread::sleep(block_time);

                // Simulating mining
                let next_block_header = {
                    // block.hash = hash(block.parent.hash)
                    let curr_hash = &chain_tip.burn_header_hash.to_bytes()[..];
                    let next_hash = Sha256Sum::from_data(&curr_hash);

                    let block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
                        chain_tip.block_height + 1,
                        &BurnchainHeaderHash::from_bytes(next_hash.as_bytes()).unwrap(), 
                        &chain_tip.burn_header_hash, 
                        &vec![]));
                    block.header(&chain_tip)
                };

                // Updating ops properties before including them in the new block
                let mut ops_to_include = vec![];
                {
                    let mut ops = mem_pool.lock().unwrap();
                    for op in ops.iter_mut() {
                        match op {
                            BlockstackOperationType::LeaderKeyRegister(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                            },
                            BlockstackOperationType::LeaderBlockCommit(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                            },
                            BlockstackOperationType::UserBurnSupport(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                            }
                        }
                        ops_to_include.push(op.clone());
                    }
                    ops.clear();
                };
                
                // Include txs in a
                let mut burn_tx = db.tx_begin().unwrap();
                let new_chain_tip = Burnchain::process_block_ops(
                    &mut burn_tx, 
                    &chain, 
                    &chain_tip, 
                    &next_block_header, 
                    &ops_to_include).unwrap();
                burn_tx.commit().unwrap();
        
                chain_tip = new_chain_tip;

                tx.send(chain_tip.clone()).unwrap();    
            };
        }).unwrap();
        
        rx
    }

    pub fn submit_ops(&mut self, ops: &mut Vec<BlockstackOperationType>) {
        let mut mem_pool = self.mem_pool.lock().unwrap();
        mem_pool.append(ops);
    }
}