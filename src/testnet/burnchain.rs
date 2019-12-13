use std::sync::mpsc;
use std::thread;
use std::time;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey, BurnchainBlock};
use chainstate::burn::db::burndb::{BurnDB};
use burnchains::bitcoin::BitcoinBlock;
use util::hash::Sha256Sum;
use chainstate::burn::{SortitionHash, BlockSnapshot, VRFSeed};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};

pub struct BurnchainSimulator {
    block_time: time::Duration,
    chain: Burnchain,
    db: BurnDB,
    pub chain_tip: BlockSnapshot,
    sender: Option<mpsc::Sender<BlockSnapshot>>,
    buffered_ops: Vec<BlockstackOperationType>,
}

impl BurnchainSimulator {

    pub fn new(path: String, name: String) -> Self {
        let chain = Burnchain::new(&path, &"bitcoin".to_string(), &name).unwrap();

        let first_block_height = 0;

        let first_block_hash = BurnchainHeaderHash([0u8; 32]);

        let db = BurnDB::connect(&path, first_block_height, &first_block_hash, true).unwrap();

        let genesis_block = BurnDB::get_first_block_snapshot(db.conn()).unwrap();

        Self {
            block_time: time::Duration::from_millis(20000),
            chain,
            db,
            chain_tip: genesis_block,
            buffered_ops: vec![],
            sender: None
        }
    }

    pub fn tear_up(&mut self) -> mpsc::Receiver<BlockSnapshot> {
        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx);
        rx
    }
    
    pub fn start(&mut self) {        
        loop {
            thread::sleep(self.block_time);
            // Simulating mining
            let sim_block_hash = {
                let curr_hash = &self.chain_tip.burn_header_hash.to_bytes()[..];
                let next_hash = Sha256Sum::from_data(&curr_hash);
                BurnchainHeaderHash::from_bytes(next_hash.as_bytes()).unwrap()
            };

            let next_block_header = {
                let block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
                    self.chain_tip.block_height + 1,
                    &sim_block_hash, 
                    &self.chain_tip.burn_header_hash, 
                    &vec![]));
                block.header(&self.chain_tip)
            };

            // Updating ops properties
            for op in self.buffered_ops.iter_mut() {
                match op {
                    BlockstackOperationType::LeaderKeyRegister(ref op) => {
                        op.block_height = next_block_header.block_height;
                    },
                    BlockstackOperationType::LeaderBlockCommit(ref op) => {
                        op.block_height = next_block_header.block_height;
                    },
                    BlockstackOperationType::UserBurnSupport(ref op) => {
                        op.block_height = next_block_header.block_height;
                    }
                }
            }
            
            let mut burn_tx = self.db.tx_begin().unwrap();
            let new_chain_tip = Burnchain::process_block_ops(
                &mut burn_tx, 
                &self.chain, 
                &self.chain_tip, 
                &next_block_header, 
                &self.buffered_ops).unwrap();
            burn_tx.commit().unwrap();
    
            self.buffered_ops.clear();
            self.chain_tip = new_chain_tip;
            
            self.sender.unwrap().send(self.chain_tip.clone()).unwrap();    
        };
    }

    pub fn submit_ops(&mut self, ops: &mut Vec<BlockstackOperationType>) {
        self.buffered_ops.append(ops);
    }
}