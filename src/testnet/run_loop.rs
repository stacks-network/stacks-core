use super::{MemPool, MemPoolFS, Config, Leader, Keychain, TestnetNode, TestnetBurnchainNode, TestnetMiner, BurnchainSimulator, MemPoolObserver};

use std::fs;
use std::env;
use std::process;
use net::StacksMessageCodec;
use chainstate::stacks::*;
use util::hash::hex_bytes;

use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use chainstate::stacks::{StacksBlock, StacksTransactionSigner, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAuth};
use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey, BurnchainBlock};
use chainstate::stacks::{StacksPrivateKey};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::{ConsensusHash, SortitionHash, BlockSnapshot, VRFSeed};
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::Sha256Sum;
use std::collections::HashMap;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rand::RngCore;
use util::hash::{to_hex};
use std::{thread, time};

pub struct RunLoop<'a> {
    config: Config,
    vtxindex: u16,
    leaders: Vec<Leader<'a>>,
}

impl <'a> RunLoop <'a> {

    pub fn new(config: Config) -> RunLoop<'a> {
        
        let mut leaders = vec![]; 
        let mut confs = config.leader_config.clone();
        for conf in confs.drain(..) {
            leaders.push(Leader::new(conf, config.burchain_block_time));
        }

        Self {
            config,
            leaders: leaders,
            vtxindex: 0,
        }
    }

    pub fn tear_down(&self) {
    }

    pub fn start(&mut self) {

        let mut burnchain = BurnchainSimulator::new();
    
        let block_time = time::Duration::from_millis(self.config.burchain_block_time);

        let (block_rx, op_tx) = burnchain.start(
            block_time, 
            self.config.burchain_path.to_string(), 
            self.config.testnet_name.to_string());

        for leader in self.leaders.iter_mut() {
            leader.tear_up(op_tx.clone(), ConsensusHash::empty());
        }

        // The goal of this run loop is too: 
        // 1) Handle incoming blocks from the burnchain 
        // 2) Pump and exaust the mempool (detached thread)

        loop {
            // Handling incoming blocks
            let burnchain_block = block_rx.recv().unwrap();

            println!("Incoming block - {:?}", burnchain_block);

            if burnchain_block.sortition == false {
                continue;
            }

            let sortition_hash = burnchain_block.sortition_hash;

            // Mark registered keys as approved, if any.

            // When receiving a new block from the burnchain, if there's a block commit op,
            // we should be:
            // 1) Get the sortition hash
            // 2) Start a new tenure

            for leader in self.leaders.iter_mut() {
                // leader.initiate_new_tenure(sortition_hash.clone()) tear_up(op_tx.clone(), ConsensusHash::empty());
            }
        }

        // loop {
        //     // Pump and exaust the mempool
        //     let j = rx.recv().unwrap();
        //     println!("====================================================");
        //     println!("====================================================");
        //     println!("{:?}", self.burnchain.chain_tip);
        //     println!("====================================================");
        //     println!("====================================================");

        //     let mut tenure = self.initiate_new_tenure(vrf_pk);

        //     // A tenure should end when
        //     // 1 - blocktime is about to expire

        //     let mut ops = vec![];

        //     let burnchain_tip = self.burnchain.chain_tip.clone();

        //     // Prepare commit block operation
        //     let commit_block_op = self.generate_block_commitment_op(tenure, burn_fee);
        //     ops.push(commit_block_op);
            
        //     self.commit_block_height = burnchain_tip.block_height as u16;
        //     self.commit_vtxindex = self.vtxindex;        
            
        //     // Register a new vrf
        //     vrf_pk = self.keychain.rotate_vrf_keypair();
        //     let reg_key_op = self.generate_leader_key_register_op(vrf_pk.clone());
        //     ops.push(reg_key_op);

        //     self.key_block_height = burnchain_tip.block_height as u16;
        //     self.key_vtxindex = self.vtxindex;        

        //     self.burnchain.submit_ops(&mut ops);

        //     self.chain_tip = Some(StacksHeaderInfo::genesis());

        //     let block_time = time::Duration::from_millis(20000);
        //     let now = time::Instant::now();

        //     burn_fee += 1;

        //     thread::sleep(block_time);
        // }
    }
}
