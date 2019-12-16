use super::{Keychain, MemPoolFS, LeaderConfig};

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::thread;
use std::time;

use rand::RngCore;

use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid};
use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use chainstate::stacks::{StacksPrivateKey, StacksBlock, TransactionPayload, StacksWorkScore, StacksAddress, StacksTransactionSigner, StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAnchorMode};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::{ConsensusHash, SortitionHash, BlockSnapshot, VRFSeed};
use util::hash::Sha256Sum;
use util::vrf::{VRFProof, VRFPublicKey};

#[derive(Clone)]
struct RegisteredKey {
    vrf_public_key: VRFPublicKey,
    key_block_height: u16,
    key_vtxindex: u16,
}

pub struct Leader <'a> {
    active_registered_key: Option<RegisteredKey>,
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    mem_pool: MemPoolFS<'a>,
    keychain: Keychain,
    commit_block_height: u16,
    commit_vtxindex: u16,
    block_time: u64,
    burchain_ops_tx: Option<Sender<BlockstackOperationType>>,
}

impl <'a> Leader <'a> {

    pub fn new(config: LeaderConfig, block_time: u64) -> Leader<'a> {
        
        let keychain = Keychain::default();

        let chain_state = StacksChainState::open(false, 0x80000000, &config.name).unwrap();

        let mem_pool = MemPoolFS::new(&config.mem_pool_path);

        Self {
            active_registered_key: None,
            chain_state,
            chain_tip: Some(StacksHeaderInfo::genesis()),
            keychain,
            mem_pool,
            commit_block_height: 0,
            commit_vtxindex: 0,
            block_time,
            burchain_ops_tx: None
        }
    }
    
    pub fn get_address(&self) -> StacksAddress {
        self.keychain.get_address()
    }

    pub fn tear_up(&mut self, burchain_ops_tx: Sender<BlockstackOperationType>, consensus_hash: ConsensusHash) {
        
        let vrf_pk = self.keychain.rotate_vrf_keypair();

        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, consensus_hash);
        burchain_ops_tx.send(key_reg_op).unwrap();
        self.burchain_ops_tx = Some(burchain_ops_tx);
    }

    fn generate_leader_key_register_op(&mut self, vrf_public_key: VRFPublicKey, consensus_hash: ConsensusHash) -> BlockstackOperationType {

        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            address: self.keychain.get_address(),
            consensus_hash,

            // to be filled in 
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    fn generate_block_commitment_op(&mut self, tenure: LeaderTenure, burn_fee: u64) -> BlockstackOperationType {

        let active_key = self.active_registered_key.clone().unwrap();

        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            new_seed: tenure.vrf_seed,
            key_block_ptr: active_key.key_block_height as u32,
            key_vtxindex: active_key.key_vtxindex as u16,
            parent_block_ptr: self.commit_block_height as u32,
            parent_vtxindex: self.commit_vtxindex as u16,
            memo: vec![],
            burn_fee,
            input: self.keychain.get_burnchain_signer(),
            block_header_hash: tenure.block_builder.header.block_hash(),

            // to be filled in 
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    pub fn notify_key_registration(&mut self, vrf_public_key: VRFPublicKey, key_block_height: u16, key_vtxindex: u16) {
        self.active_registered_key = Some(RegisteredKey { vrf_public_key, key_block_height, key_vtxindex });
    }

    // pub fn notify_key_invalidation(&mut self, vrf_public_key: VRFPublicKey, key_block_height: u16, key_vtxindex: u16) {
    //     self.active_registered_key = Some(RegisteredKey { vrf_public_key, key_block_height, key_vtxindex });
    // }

    pub fn handle_burnchain_block(&mut self, block: BlockSnapshot) {

        // has key?
        // Y: start new tenure
        // let mut tenure = leader.start_new_tenure(sortition_hash.clone());
        // thread::spawn(move || {
        //     tenure.start();
        // });


        // N: is block containing a key?
        // Y: update key
        // N: register a new key

    }

    pub fn initiate_new_tenure(&mut self, sortition_hash: SortitionHash) -> LeaderTenure {

        if self.active_registered_key.is_none() {
            panic!();
        }
        let vrf_public_key = self.active_registered_key.clone().unwrap().vrf_public_key;
        
        let chain_tip = self.chain_tip.clone().unwrap();

        // let chain_tip = match self.chain_tip {
        //     Some(ref b) => b.clone(),
        //     _ => panic!()
        // };

        let vrf_proof = self.keychain.generate_proof(vrf_public_key, sortition_hash.as_bytes()).unwrap();

        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        let mut tenure = LeaderTenure::new(chain_tip, vrf_proof, microblock_secret_key, self.block_time);

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
}

pub struct LeaderTenure {
    started_at: std::time::Instant,
    block_builder: StacksBlockBuilder,
    vrf_seed: VRFSeed,
    block_time: u64,
    // registered_key: RegisteredKey,
}

impl LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, vrf_proof: VRFProof, microblock_secret_key: StacksPrivateKey, block_time: u64) -> LeaderTenure {
        let now = time::Instant::now();
        
        let ratio = StacksWorkScore {
            burn: 1, // todo(ludo): get burn from burnchain_tip.
            work: 0
        };

        let block_builder = StacksBlockBuilder::from_parent(&parent_block, &ratio, &vrf_proof, &microblock_secret_key);

        Self {
            started_at: now,
            block_time,
            block_builder,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    pub fn handle_txs(&mut self, txs: Vec<StacksTransaction>) {
        
    }

    pub fn start(&mut self) {

        let mempool_poll_interval = time::Duration::from_millis(500);
        let tenure_duration = time::Duration::from_millis(self.block_time * 3 / 4);
        let should_commit_block_at = self.started_at.checked_add(tenure_duration).unwrap();

        while time::Instant::now() < should_commit_block_at {
            println!("Fetching mempool");

            thread::sleep(mempool_poll_interval);
        }
    
        println!("Committing block");

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