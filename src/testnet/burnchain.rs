use std::sync::mpsc;
use std::thread;
use std::time;
use std::sync::{Arc, Mutex};

use super::{Config};

use burnchains::{Burnchain, BurnchainBlockHeader, BurnchainHeaderHash, BurnchainBlock, Txid};
use burnchains::bitcoin::BitcoinBlock;
use chainstate::burn::db::burndb::{BurnDB};
use chainstate::burn::{BlockSnapshot};
use chainstate::burn::operations::{BlockstackOperationType};
use util::hash::Sha256Sum;

pub struct BurnchainSimulator {
    mem_pool: Arc<Mutex<Vec<BlockstackOperationType>>>,
}

impl BurnchainSimulator {

    pub fn new() -> Self {
        Self {
            mem_pool: Arc::new(Mutex::new(vec![]))
        }
    }
    
    pub fn start(&mut self, config: &Config) -> (mpsc::Receiver<(BlockSnapshot, Vec<BlockstackOperationType>)>, mpsc::Sender<BlockstackOperationType>) {
        let (block_tx, block_rx) = mpsc::channel();
        
        let path = config.burchain_path.clone();
        let chain = config.chain.clone();
        let name = config.testnet_name.clone();
        let block_time = time::Duration::from_millis(config.burchain_block_time);

        let ops_dequeuing = Arc::clone(&self.mem_pool);
        let mut vtxindex = 1;

        thread::spawn(move || {

            let chain = Burnchain::new(&path, &chain, &name).unwrap();
    
            let mut db = BurnDB::connect(&path, 0, &BurnchainHeaderHash([0u8; 32]), true).unwrap();
    
            let mut chain_tip = BurnDB::get_first_block_snapshot(db.conn()).unwrap();
            
            loop {
                thread::sleep(block_time);

                // Simulating mining
                let next_block_header = BurnchainSimulator::build_next_block_header(&chain_tip);

                // Updating ops properties before including them in the new block
                let mut ops_to_include = vec![];
                {
                    let mut ops = ops_dequeuing.lock().unwrap();
                    for op in ops.iter_mut() {
                        match op {
                            BlockstackOperationType::LeaderKeyRegister(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                                op.vtxindex = vtxindex;
                                op.txid = Txid(Sha256Sum::from_data(format!("{}", vtxindex).as_bytes()).0);
                            },
                            BlockstackOperationType::LeaderBlockCommit(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                                op.vtxindex = vtxindex;
                                op.txid = Txid(Sha256Sum::from_data(format!("{}", vtxindex).as_bytes()).0);
                            },
                            BlockstackOperationType::UserBurnSupport(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                                op.vtxindex = vtxindex;
                                op.txid = Txid(Sha256Sum::from_data(format!("{}", vtxindex).as_bytes()).0);
                            }
                        }
                        ops_to_include.push(op.clone());
                        vtxindex += 1;
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

                block_tx.send((chain_tip.clone(), ops_to_include)).unwrap();    
            };
        });
        
        let (op_tx, op_rx) = mpsc::channel();
        
        let ops_enqueuing = Arc::clone(&self.mem_pool);

        thread::spawn(move || {
            loop {
                // Handling incoming operations
                let op = op_rx.recv().unwrap();
                let mut ops = ops_enqueuing.lock().unwrap();
                ops.push(op);
            }
        });

        (block_rx, op_tx)
    }

    fn build_next_block_header(current_block: &BlockSnapshot) -> BurnchainBlockHeader {
        let curr_hash = &current_block.burn_header_hash.to_bytes()[..];
        let next_hash = Sha256Sum::from_data(&curr_hash);

        let block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            current_block.block_height + 1,
            &BurnchainHeaderHash::from_bytes(next_hash.as_bytes()).unwrap(), 
            &current_block.burn_header_hash, 
            &vec![]));
        block.header(&current_block)
    }
}