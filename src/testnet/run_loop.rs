use super::{MemPool, MemPoolFS, Config, Keychain, TestnetNode, TestnetBurnchainNode, TestnetMiner, BurnchainSimulator, MemPoolObserver};

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
use chainstate::burn::{SortitionHash, BlockSnapshot, VRFSeed};
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::Sha256Sum;
use std::collections::HashMap;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rand::RngCore;
use util::hash::{to_hex};
use std::{thread, time};

// struct Miner {
//     previous_tenures: Vec<LeaderTenure>,
//     ongoing_tenure: Option<LeaderTenure>,
//     ongoing_registered_key: Option<RegisteredKey>,
//     keychain: Keychain,
// }

// impl Miner {

//     // todo(ludo): revisit constructor
//     pub fn new(keychain: Keychain) -> Self {
//         Self {
//             previous_tenures: vec![],
//             ongoing_tenure: None,
//             ongoing_registered_key: None,
//             keychain
//         }
//     }

//     pub fn tear_up(burnchain_tip: ) {

//     }

//     pub fn start_new_tenure() -> Tenure {
//         // Should check if there's something ongoing.

//     }
// }


// struct RegisteredKey {
//     vrf_proof: VRFProof,
//     block_height: u64,
//     vtxindex: u32
// }

struct LeaderTenure {
    started_at: std::time::Instant,
    block_builder: StacksBlockBuilder,
    vrf_seed: VRFSeed,
    // registered_key: RegisteredKey,
}

impl LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, vrf_proof: VRFProof, microblock_secret_key: StacksPrivateKey) -> LeaderTenure {
        let now = time::Instant::now();
        
        let ratio = StacksWorkScore {
            burn: 1, // todo(ludo): get burn from burnchain_tip.
            work: 0
        };

        let block_builder = StacksBlockBuilder::from_parent(&parent_block, &ratio, &vrf_proof, &microblock_secret_key);

        Self {
            started_at: now,
            block_builder,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    pub fn handle_txs(&mut self, txs: Vec<StacksTransaction>) {
        
    }
}

pub struct RunLoop {
    burnchain: BurnchainSimulator,
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    config: Config,
    keychain: Keychain,
    mem_pool: MemPoolFS,
    previous_tenures: Vec<LeaderTenure>,
    vtxindex: u16,
    key_block_height: u16,
    key_vtxindex: u16,
    commit_block_height: u16,
    commit_vtxindex: u16
}

impl RunLoop {

    pub fn new(config: Config, keychain: Keychain, mem_pool: MemPoolFS) -> RunLoop {

        let burnchain = BurnchainSimulator::new(config.db_path.to_string(), config.name);

        let chain_state = StacksChainState::open(false, 0x80000000, &config.name).unwrap();

        Self {
            config,
            mem_pool,
            previous_tenures: vec![],
            chain_state,
            burnchain,
            chain_tip: None,
            keychain,
            vtxindex: 0,
            key_block_height: 0,
            key_vtxindex: 0,
            commit_block_height: 0,
            commit_vtxindex: 0,
        }
    }

    pub fn tear_up(&mut self, vrf_public_key: VRFPublicKey) {

        // On a local "testnet", a miner constantly registers a new vrf and start its tenure immediately,
        // since there's only one miner. 

        let key_reg_op = self.generate_leader_key_register_op(vrf_public_key);

        self.key_block_height = 0;
        self.key_vtxindex = self.vtxindex;        

        self.commit_block_height = 0;
        self.commit_vtxindex = 0;
    
        let ops = vec![key_reg_op];

        self.burnchain.submit_ops(&mut ops);

        // todo(ludo): Genesis should probably attached to a block in the burnchain.
        self.chain_tip = Some(StacksHeaderInfo::genesis());
    }

    pub fn tear_down(&self) {
    }

    fn generate_leader_key_register_op(&mut self, vrf_public_key: VRFPublicKey) -> BlockstackOperationType {
        self.vtxindex += 1;

        let consensus_hash = self.burnchain.chain_tip.consensus_hash;

        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            address: self.keychain.get_address(),
            consensus_hash,
            vtxindex: self.vtxindex as u32,

            // to be filled in 
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    fn generate_block_commitment_op(&mut self, tenure: LeaderTenure, burn_fee: u64) -> BlockstackOperationType {
        self.vtxindex += 1;

        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            new_seed: tenure.vrf_seed,
            key_block_ptr: self.key_block_height as u32,
            key_vtxindex: self.key_vtxindex as u16,
            parent_block_ptr: self.commit_block_height as u32, //block_height as u32 - 1,
            parent_vtxindex: self.commit_vtxindex as u16,
            memo: vec![],
            burn_fee,
            input: self.keychain.get_burnchain_signer(),
            block_header_hash: tenure.block_builder.header.block_hash(),
            vtxindex: self.vtxindex as u32,

            // to be filled in 
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    fn initiate_new_tenure(&mut self, vrf_public_key: VRFPublicKey) -> LeaderTenure {

        // todo(ludo): chain tip does not necessarly have a sortition hash
        let sortition_hash = self.burnchain.chain_tip.sortition_hash;

        let chain_tip = match self.chain_tip {
            Some(ref b) => b.clone(),
            _ => panic!()
        };

        let vrf_proof = self.keychain.generate_proof(vrf_public_key, sortition_hash.as_bytes()).unwrap();

        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        let mut tenure = LeaderTenure::new(chain_tip, vrf_proof, microblock_secret_key);

        let coinbase_tx = {
            let tx_auth = self.keychain.get_transaction_auth().unwrap();

            let mut tx = StacksTransaction::new(
                TransactionVersion::Testnet, 
                tx_auth, 
                TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
            tx.chain_id = 0x80000000;
            tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
            let mut tx_signer = StacksTransactionSigner::new(&tx);
            self.keychain.sign_as_origin(&mut tx_signer);
            tx_signer.get_tx().unwrap()
        };

        tenure.handle_txs(vec![coinbase_tx]);

        tenure
    }

    pub fn start(&mut self) {
        let mut vrf_pk = self.keychain.rotate_vrf_keypair();
        self.tear_up(vrf_pk.clone());
        let mut burn_fee = 1;

        let rx = self.burnchain.tear_up();

        // The goal of this run loop is too: 
        // 1) Handle incoming blocks from the burnchain 
        // 2) Pump and exaust the mempool

        thread::spawn(move|| {
            self.burnchain.start();
        });
    
        thread::spawn(move|| {
            loop {
                // Handling incoming blocks
                let j = rx.recv().unwrap();
            }
        });
    
        loop {
            // Pump and exaust the mempool
            let j = rx.recv().unwrap();
            println!("====================================================");
            println!("====================================================");
            println!("{:?}", self.burnchain.chain_tip);
            println!("====================================================");
            println!("====================================================");

            let mut tenure = self.initiate_new_tenure(vrf_pk);

            // A tenure should end when
            // 1 - blocktime is about to expire

            let mut ops = vec![];

            let burnchain_tip = self.burnchain.chain_tip.clone();

            // Prepare commit block operation
            let commit_block_op = self.generate_block_commitment_op(tenure, burn_fee);
            ops.push(commit_block_op);
            
            self.commit_block_height = burnchain_tip.block_height as u16;
            self.commit_vtxindex = self.vtxindex;        
            
            // Register a new vrf
            vrf_pk = self.keychain.rotate_vrf_keypair();
            let reg_key_op = self.generate_leader_key_register_op(vrf_pk.clone());
            ops.push(reg_key_op);

            self.key_block_height = burnchain_tip.block_height as u16;
            self.key_vtxindex = self.vtxindex;        

            self.burnchain.submit_ops(&mut ops);

            self.chain_tip = Some(StacksHeaderInfo::genesis());

            let block_time = time::Duration::from_millis(20000);
            let now = time::Instant::now();

            burn_fee += 1;

            thread::sleep(block_time);
        }
    }
}
