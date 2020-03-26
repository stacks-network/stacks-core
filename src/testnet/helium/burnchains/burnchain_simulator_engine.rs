use std::sync::mpsc;
use std::thread;
use std::time;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

use super::super::{Config};
use super::{BurnchainEngine, BurnchainOperationType, BurnchainState, BurnchainOperationSigningDelegate};

use burnchains::{Burnchain, BurnchainBlockHeader, BurnchainHeaderHash, BurnchainBlock, Txid};
use burnchains::bitcoin::BitcoinBlock;
use chainstate::burn::db::burndb::{BurnDB};
use chainstate::burn::{BlockSnapshot};
use chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    UserBurnSupportOp,
    BlockstackOperationType,
};
use util::hash::Sha256Sum;
use util::get_epoch_time_secs;

/// BurnchainSimulatorEngine is simulating a simplistic burnchain.
pub struct BurnchainSimulatorEngine {
    config: Config,
    burnchain: Burnchain,
    db: Option<BurnDB>,
    queued_operations: VecDeque<BurnchainOperationType>,
}

impl BurnchainSimulatorEngine {
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

impl BurnchainEngine for BurnchainSimulatorEngine {

    fn new(config: Config) -> Self {
        let burnchain = Burnchain::new(&config.get_burn_db_path(), &config.burnchain.chain, &config.burnchain.mode)
            .expect("Error while instantiating burnchain");

        Self {
            config: config,
            burnchain: burnchain,
            db: None,
            queued_operations: VecDeque::new()
        }
    }

    fn burndb_mut(&mut self) -> &mut BurnDB {
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
   
    fn start(&mut self) -> BurnchainState {
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

    fn submit_operation<T: BurnchainOperationSigningDelegate>(&mut self, operation: BurnchainOperationType, signer: &mut T) {
        self.queued_operations.push_back(operation);
    }

    fn sync(&mut self) -> BurnchainState {
        let chain_tip = self.get_chain_tip();

        // Simulating mining
        let next_block_header = BurnchainSimulatorEngine::build_next_block_header(&chain_tip);
        let mut vtxindex = 1;
        let mut ops = vec![];

        while let Some(payload) = self.queued_operations.pop_front() {
            let txid = Txid(Sha256Sum::from_data(format!("{}::{}", next_block_header.block_height, vtxindex).as_bytes()).0);
            let op = match payload {
                BurnchainOperationType::LeaderKeyRegister(payload) => {
                    BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
                        consensus_hash: payload.consensus_hash,
                        public_key: payload.public_key,
                        memo: payload.memo,
                        address: payload.address,
                        txid,
                        vtxindex: vtxindex,
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                    })
                },
                BurnchainOperationType::LeaderBlockCommit(payload) => {
                    BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
                        block_header_hash: payload.block_header_hash,
                        new_seed: payload.new_seed,
                        parent_block_ptr: payload.parent_block_ptr,
                        parent_vtxindex: payload.parent_vtxindex,
                        key_block_ptr: payload.key_block_ptr,
                        key_vtxindex: payload.key_vtxindex,
                        memo: payload.memo,
                        burn_fee: payload.burn_fee,
                        input: payload.input,
                        txid,
                        vtxindex: vtxindex,
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                    })
                },
                BurnchainOperationType::UserBurnSupport(payload) => {
                    BlockstackOperationType::UserBurnSupport(UserBurnSupportOp {
                        address: payload.address,
                        consensus_hash: payload.consensus_hash,
                        public_key: payload.public_key,
                        key_block_ptr: payload.key_block_ptr,
                        key_vtxindex: payload.key_vtxindex,
                        block_header_hash_160: payload.block_header_hash_160,
                        burn_fee: payload.burn_fee,
                        txid,
                        vtxindex: vtxindex,
                        block_height: next_block_header.block_height,
                        burn_header_hash: next_block_header.block_hash,
                    })
                }
            };
            ops.push(op);
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
}

