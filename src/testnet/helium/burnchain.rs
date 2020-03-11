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
use util::get_epoch_time_secs;

/// BurnchainSimulator is simulating a simplistic burnchain.
pub struct BurnchainSimulator {
    config: Config,
    burnchain: Burnchain,
    // mem_pool: Arc<Mutex<Vec<BlockstackOperationType>>>,
    // db: Option<Arc<Mutex<BurnDB>>>,
    db: Option<BurnDB>
}

pub struct BurnchainState {
    pub chain_tip: BlockSnapshot,
    pub ops: Vec<BlockstackOperationType>,
    // pub db: Arc<Mutex<BurnDB>>,
}

impl BurnchainSimulator {

    pub fn new(config: Config) -> Self {
        let burnchain = Burnchain::new(&config.get_burn_db_path(), &config.burnchain.chain, &config.burnchain.mode)
            .expect("Error while instantiating burnchain");

        Self {
            config: config,
            burnchain: burnchain,
            db: None,
        }
    }

    pub fn burndb_mut(&mut self) -> &mut BurnDB {
        match self.db {
            Some(ref mut burndb) => burndb,
            None => {
                unreachable!();
            }
        }
    }
    
    fn get_chain_tip(&mut self) -> BlockSnapshot {
        match self.db {
            Some(ref mut db) => {
                BurnDB::get_canonical_burn_chain_tip(db.conn())
                    .expect("FATAL: failed to get canonical chain tip")
            },
            None => {
                unreachable!();
            }
        }
    }
   
    pub fn make_genesis_block(&mut self) -> BurnchainState {
        let db = match BurnDB::connect(&self.config.get_burn_db_path(), 0, &BurnchainHeaderHash([0u8; 32]), get_epoch_time_secs(), true) {
            Ok(db) => db,
            Err(_) => panic!("Error while connecting to burnchain db")
        };

        self.db = Some(db);

        let genesis_state = BurnchainState {
            chain_tip: self.get_chain_tip(),
            ops: vec![],
        };

        genesis_state
    }

    pub fn make_next_block(&mut self, mut ops: Vec<BlockstackOperationType>) -> BurnchainState {
        let chain_tip = self.get_chain_tip();

        // Simulating mining
        let next_block_header = BurnchainSimulator::build_next_block_header(&chain_tip);
        let mut vtxindex = 1;

        // Updating ops properties before including them in the new block
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
            vtxindex += 1;
        }
        
        // Include txs in a new block   
        let new_chain_tip = {
            match self.db {
                None => {
                    unreachable!();
                },
                Some(ref mut burn_db) => {
                    let mut burn_tx = burn_db.tx_begin().unwrap();
                    let new_chain_tip = Burnchain::process_block_ops(
                        &mut burn_tx, 
                        &self.burnchain, 
                        &chain_tip, 
                        &next_block_header, 
                        &ops).unwrap();
                    burn_tx.commit().unwrap();
                    new_chain_tip
                }
            }
        };

        // Transmit the new state
        let new_state = BurnchainState {
            chain_tip: new_chain_tip,
            ops: ops
        };

        new_state
    }

    fn build_next_block_header(current_block: &BlockSnapshot) -> BurnchainBlockHeader {
        let curr_hash = &current_block.burn_header_hash.to_bytes()[..];
        let next_hash = Sha256Sum::from_data(&curr_hash);

        let block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            current_block.block_height + 1,
            &BurnchainHeaderHash::from_bytes(next_hash.as_bytes()).unwrap(), 
            &current_block.burn_header_hash, 
            &vec![],
            get_epoch_time_secs()));
        block.header(&current_block)
    }
}
