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

/// BurnchainSimulator is simulating a simplistic burnchain.
/// 
/// When calling start(), a thread is being detached, looping, sleeping and firing some events, and a tuple (tx, rx) 
/// is being returned so that the caller can be receiving new blocks, and transmitting ops in a simulated mem_pool.
pub struct BurnchainSimulator {
    mem_pool: Arc<Mutex<Vec<BlockstackOperationType>>>,
    db: Option<Arc<Mutex<BurnDB>>>,
}

pub struct BurnchainState {
    pub chain_tip: BlockSnapshot,
    pub ops: Vec<BlockstackOperationType>,
    pub db: Arc<Mutex<BurnDB>>,
}

impl BurnchainSimulator {

    pub fn new() -> Self {
        Self {
            mem_pool: Arc::new(Mutex::new(vec![])),
            db: None,
        }
    }
    
    pub fn start(&mut self, config: &Config) -> (mpsc::Receiver<BurnchainState>, mpsc::Sender<BlockstackOperationType>) {
        let (block_tx, block_rx) = mpsc::channel();
        
        let path = config.burnchain_path.clone();
        let chain = config.chain.clone();
        let name = config.testnet_name.clone();
        let block_time = time::Duration::from_millis(config.burnchain_block_time);

        let ops_dequeuing = Arc::clone(&self.mem_pool);

        let db = match BurnDB::connect(&path, 0, &BurnchainHeaderHash([0u8; 32]), true) {
            Ok(db) => Arc::new(Mutex::new(db)),
            Err(_) => panic!("Error while connecting to burnchain db")
        };

        let burn_db = Arc::clone(&db);
        self.db = Some(db);

        thread::spawn(move || {

            let chain = match Burnchain::new(&path, &chain, &name) {
                Ok(res) => res,
                Err(_) => panic!("Error while instantiating burnchain")
            };

            let mut chain_tip = {
                let db = burn_db.lock().unwrap();
                match BurnDB::get_first_block_snapshot(db.conn()) {
                    Ok(res) => res,
                    Err(_) => panic!("Error while getting genesis block")
                }
            };

            // Transmit genesis state
            let genesis_state = BurnchainState {
                chain_tip: chain_tip.clone(),
                ops: vec![],
                db: Arc::clone(&burn_db)
            };
            block_tx.send(genesis_state).unwrap();    
                
            loop {
                thread::sleep(block_time);

                // Simulating mining
                let next_block_header = BurnchainSimulator::build_next_block_header(&chain_tip);
                let mut vtxindex = 1;

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
                                op.txid = Txid(Sha256Sum::from_data(format!("{}::{}", op.block_height, vtxindex).as_bytes()).0);
                            },
                            BlockstackOperationType::LeaderBlockCommit(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                                op.vtxindex = vtxindex;
                                op.txid = Txid(Sha256Sum::from_data(format!("{}::{}", op.block_height, vtxindex).as_bytes()).0);
                            },
                            BlockstackOperationType::UserBurnSupport(ref mut op) => {
                                op.block_height = next_block_header.block_height;
                                op.burn_header_hash = next_block_header.block_hash;
                                op.vtxindex = vtxindex;
                                op.txid = Txid(Sha256Sum::from_data(format!("{}::{}", op.block_height, vtxindex).as_bytes()).0);
                            }
                        }
                        ops_to_include.push(op.clone());
                        vtxindex += 1;
                    }
                    ops.clear();
                };
                
                // Include txs in a new block   
                chain_tip = {
                    let mut db = burn_db.lock().unwrap();
                    let mut burn_tx = db.tx_begin().unwrap();
                    let new_chain_tip = Burnchain::process_block_ops(
                        &mut burn_tx, 
                        &chain, 
                        &chain_tip, 
                        &next_block_header, 
                        &ops_to_include).unwrap();
                    burn_tx.commit().unwrap();
                    new_chain_tip
                };
        
                // Transmit the new state
                let new_state = BurnchainState {
                    chain_tip: chain_tip.clone(),
                    ops: ops_to_include,
                    db: Arc::clone(&burn_db)
                };
                block_tx.send(new_state).unwrap();    
            };
        });
        
        let (op_tx, op_rx) = mpsc::channel();
        
        let ops_enqueuing = Arc::clone(&self.mem_pool);

        thread::spawn(move || {
            loop {
                // Handling incoming operations
                if let Ok(op) = op_rx.recv() {
                    let mut ops = ops_enqueuing.lock().unwrap();
                    ops.push(op);    
                } else {
                    debug!("Burnchain stopped handling ops");
                    break;
                }
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