use super::{Keychain, MemPool, MemPoolFS, LeaderConfig};

use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use std::time;
use rand::RngCore;

use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, BurnchainSigner};
use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo, ClarityTx};
use chainstate::stacks::{StacksPrivateKey, StacksBlock, TransactionPayload, StacksWorkScore, StacksAddress, StacksTransactionSigner, StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAnchorMode};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::{ConsensusHash, SortitionHash, BlockSnapshot, VRFSeed, BlockHeaderHash};
use net::StacksMessageType;
use util::hash::Sha256Sum;
use util::vrf::{VRFProof, VRFPublicKey};

#[derive(Clone)]
pub struct RegisteredKey {
    vrf_public_key: VRFPublicKey,
    block_height: u16,
    op_vtxindex: u16,
}

#[derive(Clone)]
pub struct SortitionedBlock {
    sortition_hash: SortitionHash,
    block_height: u16,
    op_vtxindex: u16,
    op_txid: Txid,
}

impl SortitionedBlock {
    pub fn genesis() -> Self {
        Self {
            sortition_hash: SortitionHash::initial(),
            block_height: 0,
            op_vtxindex: 0,
            op_txid: Txid([0u8; 32]),    
        }
    }
}

pub struct Leader {
    active_registered_key: Option<RegisteredKey>,
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    last_sortitioned_block: Option<SortitionedBlock>,
    mem_pool: MemPoolFS,
    keychain: Keychain,
    block_time: u64,
    burchain_ops_tx: Option<Sender<BlockstackOperationType>>,
    rx: Receiver<StacksMessageType>,

    pub tx: Sender<StacksMessageType>,
}

impl Leader {

    pub fn new(config: LeaderConfig, block_time: u64) -> Self {
        
        let keychain = Keychain::default();

        let chain_state = StacksChainState::open(false, 0x80000000, &config.name).unwrap();

        let mem_pool = MemPoolFS::new(&config.mem_pool_path);

        let (tx, rx) = channel();

        Self {
            active_registered_key: None,
            chain_state,
            chain_tip: Some(StacksHeaderInfo::genesis()),
            keychain,
            last_sortitioned_block: None,
            mem_pool,
            block_time,
            burchain_ops_tx: None,
            tx,
            rx,
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

    pub fn process_burnchain_block(&mut self, block: &BlockSnapshot, ops: &Vec<BlockstackOperationType>) -> Option<SortitionedBlock> {

        let mut new_key = None;
        let mut last_sortitioned_block = None; 

        for op in ops {
            match op {
                BlockstackOperationType::LeaderKeyRegister(ref op) => {
                    if op.address == self.keychain.get_address() {
                        // Registered key has been mined
                        new_key = Some(RegisteredKey {
                            vrf_public_key: op.public_key.clone(),
                            block_height: op.block_height as u16,
                            op_vtxindex: op.vtxindex as u16,
                        });
                    }
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    if op.txid == block.winning_block_txid {
                        last_sortitioned_block = Some(SortitionedBlock {
                            block_height: block.block_height as u16,
                            op_vtxindex: op.vtxindex as u16,
                            op_txid: op.txid,
                            sortition_hash: block.sortition_hash,
                        });

                        // De-register key if leader won the sortition
                        // This will trigger a new registration
                        if op.input == self.keychain.get_burnchain_signer() {
                            self.active_registered_key = None;
                        }    
                    }
                },
                _ => {
                    // todo(ludo): ¯\_(ツ)_/¯
                }
            }
        }

        if new_key.is_some() {
            self.active_registered_key = new_key;
        }

        if last_sortitioned_block.is_some() {
            self.last_sortitioned_block = last_sortitioned_block;
        }

        if self.active_registered_key.is_none() {                                    
            // Register a new key
            let vrf_pk = self.keychain.rotate_vrf_keypair();
            let key_reg_op = self.generate_leader_key_register_op(vrf_pk, block.consensus_hash);
            let ops_tx = self.burchain_ops_tx.take().unwrap();
            ops_tx.send(key_reg_op).unwrap();
            self.burchain_ops_tx = Some(ops_tx);
            return None;
        }

        if self.last_sortitioned_block.is_none() {
            return None;
        }

        self.last_sortitioned_block.clone()
    }

    pub fn initiate_new_tenure(&mut self, sortitioned_block: SortitionedBlock) -> LeaderTenure {

        let chain_tip = self.chain_tip.clone().unwrap();

        let registered_key = self.active_registered_key.clone().unwrap();

        let vrf_proof = self.keychain.generate_proof(&registered_key.vrf_public_key, sortitioned_block.sortition_hash.as_bytes()).unwrap();

        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        let clarity_tx = self.chain_state.block_begin(
            &BurnchainHeaderHash([0u8; 32]), // &chain_tip.burn_header_hash, 
            &BlockHeaderHash([0u8; 32]),     // &chain_tip.anchored_header, 
            &BurnchainHeaderHash([1u8; 32]), 
            &BlockHeaderHash([1u8; 32]));

        let mut tenure = LeaderTenure::new(
            chain_tip, 
            self.block_time,
            self.burchain_ops_tx.clone().unwrap(),
            self.keychain.get_burnchain_signer().clone(),
            clarity_tx,
            self.mem_pool.clone(),
            microblock_secret_key, 
            sortitioned_block,
            registered_key,
            vrf_proof);

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

pub struct LeaderTenure <'a> {
// pub struct LeaderTenure {
    average_block_time: u64,
    block_builder: StacksBlockBuilder,
    burn_fee: u64,
    burnchain_ops_tx: Sender<BlockstackOperationType>,
    burnchain_signer: Option<BurnchainSigner>,
    clarity_tx: ClarityTx<'a>,
    last_sortitioned_block: SortitionedBlock,
    mem_pool: MemPoolFS,
    registered_key: RegisteredKey,
    started_at: std::time::Instant,
    vrf_seed: VRFSeed,
}

impl <'a> LeaderTenure <'a> {
// impl LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, 
               average_block_time: u64,
               burnchain_ops_tx: Sender<BlockstackOperationType>,
               burnchain_signer: BurnchainSigner,
               clarity_tx: ClarityTx<'a>,
               mem_pool: MemPoolFS,
               microblock_secret_key: StacksPrivateKey,  
               last_sortitioned_block: SortitionedBlock,
               registered_key: RegisteredKey,
            //    vrf_proof: VRFProof) -> LeaderTenure {
               vrf_proof: VRFProof) -> LeaderTenure <'a> {

        let now = time::Instant::now();
        
        let ratio = StacksWorkScore {
            burn: 1, // todo(ludo): get burn from burnchain_tip.
            work: 0
        };

        let block_builder = StacksBlockBuilder::from_parent(&parent_block, &ratio, &vrf_proof, &microblock_secret_key);

        Self {
            average_block_time,
            block_builder,
            burn_fee: 0,
            burnchain_ops_tx,
            burnchain_signer: Some(burnchain_signer),
            clarity_tx,
            last_sortitioned_block,
            mem_pool,
            registered_key,
            started_at: now,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    pub fn handle_txs(&mut self, txs: Vec<StacksTransaction>) {
    }

    pub fn run(&mut self) {

        let mempool_poll_interval = time::Duration::from_millis(500);
        let tenure_duration = time::Duration::from_millis(self.average_block_time * 3 / 4);
        let should_commit_block_at = self.started_at.checked_add(tenure_duration).unwrap();
        self.burn_fee = 1;

        while time::Instant::now() < should_commit_block_at {
            let txs = self.mem_pool.poll();

            for tx in txs {
                self.block_builder.try_mine_tx(&mut self.clarity_tx, &tx).unwrap();
            }
            thread::sleep(mempool_poll_interval);
        }

        self.commit();

        // // "discover" this stacks block
        // let res = node.chainstate.preprocess_anchored_block(&mut tx, &commit_snapshot.burn_header_hash, &stacks_block, &parent_block_burn_header_hash).unwrap();
        // if !res {
        //     return Some(res)
        // }

        // // "discover" this stacks microblock stream
        // for mblock in stacks_microblocks.iter() {
        //     let res = node.chainstate.preprocess_streamed_microblock(&mut tx, &commit_snapshot.burn_header_hash, &stacks_block.block_hash(), mblock).unwrap();
        //     if !res {
        //         return Some(res)
        //     }
        // }

        // Should broadcast artefacts
    }

    fn commit(&mut self) {
        // Build LeaderBlockCommit operation
        let op = BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            new_seed: self.vrf_seed,
            key_block_ptr: self.registered_key.block_height as u32,
            key_vtxindex: self.registered_key.op_vtxindex as u16,
            parent_block_ptr: self.last_sortitioned_block.block_height as u32,
            parent_vtxindex: self.last_sortitioned_block.op_vtxindex as u16,
            memo: vec![],
            burn_fee: self.burn_fee,
            input: self.burnchain_signer.take().unwrap(),
            block_header_hash: self.block_builder.header.block_hash(),

            // to be filled in 
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        });

        // Send op to the burnchain
        self.burnchain_ops_tx.send(op).unwrap();
    }
}