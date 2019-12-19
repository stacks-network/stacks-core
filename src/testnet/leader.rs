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

#[derive(Clone, Debug)]
pub struct SortitionedBlock {
    sortition_hash: SortitionHash,
    burn_header_hash: BurnchainHeaderHash,
    parent_burn_header_hash: BurnchainHeaderHash,
    block_height: u16,
    op_vtxindex: u16,
    op_txid: Txid,
    total_burn: u64,
}

impl SortitionedBlock {
    pub fn genesis() -> Self {
        Self {
            sortition_hash: SortitionHash::initial(),
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
            parent_burn_header_hash: BurnchainHeaderHash([0u8; 32]),
            block_height: 1,
            op_vtxindex: 0,
            op_txid: Txid([0u8; 32]),
            total_burn: 0
        }
    }

}

pub struct Leader {
    active_registered_key: Option<RegisteredKey>,
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    pub last_sortitioned_block: Option<SortitionedBlock>,
    // last_mined_block_including_a_sortition: Option<SortitionedBlock>,
    // last_mined_block_including_a_sortition_and_need_artefacts_from_: Option<SortitionedBlock>,
    burnchain_tip: Option<BlockSnapshot>,
    mem_pool: MemPoolFS,
    keychain: Keychain,
    block_time: u64,
    burnchain_ops_tx: Option<Sender<BlockstackOperationType>>,
    rx: Receiver<StacksMessageType>,

    pub tx: Sender<StacksMessageType>,
}

impl Leader {

    pub fn new(config: LeaderConfig, block_time: u64) -> Self {
        
        let keychain = Keychain::default();

        let chain_state = StacksChainState::open(false, 0x80000000, &config.path).unwrap();

        let mem_pool = MemPoolFS::new(&config.mem_pool_path);

        let (tx, rx) = channel();

        Self {
            active_registered_key: None,
            chain_state,
            chain_tip: None, //Some(StacksHeaderInfo::genesis()),
            keychain,
            last_sortitioned_block: None,
            mem_pool,
            block_time,
            burnchain_ops_tx: None,
            burnchain_tip: None,
            tx,
            rx,
        }
    }
    
    pub fn get_address(&self) -> StacksAddress {
        self.keychain.get_address()
    }

    pub fn tear_up(&mut self, burnchain_ops_tx: Sender<BlockstackOperationType>, consensus_hash: ConsensusHash) {
        
        let vrf_pk = self.keychain.rotate_vrf_keypair();

        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, consensus_hash);
        burnchain_ops_tx.send(key_reg_op).unwrap();
        self.burnchain_ops_tx = Some(burnchain_ops_tx);
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

    fn generate_block_commit_op(&mut self, 
                                block_header_hash: BlockHeaderHash,
                                burn_fee: u64, 
                                key: &RegisteredKey,
                                parent_block: &SortitionedBlock,
                                vrf_seed: VRFSeed) -> BlockstackOperationType {

        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            block_header_hash,
            burn_fee,
            input: self.keychain.get_burnchain_signer(),
            key_block_ptr: key.block_height as u32,
            key_vtxindex: key.op_vtxindex as u16,
            memo: vec![],
            new_seed: vrf_seed,
            parent_block_ptr: parent_block.block_height as u32,
            parent_vtxindex: parent_block.op_vtxindex as u16,

            // to be filled in 
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    pub fn process_burnchain_block(&mut self, block: &BlockSnapshot, ops: &Vec<BlockstackOperationType>) -> bool {
        println!("=======================================================");
        println!("NEW EPOCH");
        println!("BURNCHAIN: {:?} {:?} {:?}", block.block_height, block.burn_header_hash, block.parent_burn_header_hash);
        if self.last_sortitioned_block.is_some() {
            println!("LAST_SORT: {:?} {:?}", self.last_sortitioned_block.clone().unwrap().block_height, self.last_sortitioned_block.clone().unwrap().burn_header_hash);
        }
        if self.chain_tip.is_some() {
            println!("CHAIN_TIP: {:?} {:?}", self.chain_tip.clone().unwrap().block_height, self.chain_tip.clone().unwrap().anchored_header.block_hash());
        }
        println!("=======================================================");

        let mut new_key = None;
        let mut last_sortitioned_block = None; 
        let mut won_sortition = false;

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
                        println!("Found key");
                    }
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    if op.txid == block.winning_block_txid {
                        last_sortitioned_block = Some(SortitionedBlock {
                            block_height: block.block_height as u16,
                            op_vtxindex: op.vtxindex as u16,
                            op_txid: op.txid,
                            sortition_hash: block.sortition_hash,
                            total_burn: block.total_burn,
                            burn_header_hash: block.burn_header_hash,
                            parent_burn_header_hash: block.parent_burn_header_hash,
                        });

                        // De-register key if leader won the sortition
                        // This will trigger a new registration
                        if op.input == self.keychain.get_burnchain_signer() {
                            self.active_registered_key = None;
                            won_sortition = true;
                        }    
                    }
                },
                _ => {
                    // todo(ludo): ¯\_(ツ)_/¯
                }
            }
        }

        if new_key.is_some() {
            println!("Keeping key");
            self.active_registered_key = new_key;
        }

        if last_sortitioned_block.is_some() {
            self.last_sortitioned_block = last_sortitioned_block;
            println!("Found sortition: {:?}", self.last_sortitioned_block);
        }

        self.burnchain_tip = Some(block.clone());

        won_sortition
    }

    pub fn process_tenure(&mut self, anchored_block: Option<StacksBlock>, microblocks: Vec<StacksMicroblock>) {
        println!("process_tenure: {:?}", anchored_block);

        // todo(ludo): verify that the block is attached to some fork in the burn chain.
        if let Some(anchored_block) = anchored_block {
            let parent_block = match self.last_sortitioned_block {
                None => SortitionedBlock::genesis(),
                Some(ref parent_block) => parent_block.clone()
            };

            self.chain_state.store_staging_block(
                &parent_block.burn_header_hash, 
                &anchored_block, 
                &parent_block.parent_burn_header_hash, 
                1, 
                parent_block.total_burn).unwrap();

            // todo(ludo): verify that this block was signed by the miner of the ancestor
            // anchored block that this microblock builds off of, + ordering?
            for microblock in microblocks.iter() {
                self.chain_state.store_staging_microblock(
                    &parent_block.burn_header_hash, 
                    &anchored_block.block_hash(),
                    &microblock).unwrap();    
            }

            let current_chain_tip = match self.chain_tip {
                Some(ref chain_tip) => chain_tip.clone(),
                None => StacksHeaderInfo::genesis(),
            };

            // chain_tip_burn_header_hash: &BurnchainHeaderHash, 

            let new_chain_tip = self.chain_state.append_block( 
                &current_chain_tip, 
                &parent_block.burn_header_hash, 
                &anchored_block, 
                &microblocks, 
                1, 
                parent_block.total_burn, 
                &vec![]).unwrap();

            println!("----------------------------------------------");
            println!("Updating chain_tip");
            println!("{:?}", current_chain_tip);
            println!("{:?}", new_chain_tip);
            self.chain_tip = Some(new_chain_tip);
            println!("----------------------------------------------");

        }

        // Update self.chain_tip = Some(...);
    }

    pub fn maintain_leadership_eligibility(&mut self) {
        println!("maintain_leadership_eligibility");

        let ops_tx = self.burnchain_ops_tx.take().unwrap();

        let burnchain_tip = self.burnchain_tip.clone().unwrap();
        
        // Naive implementation: we keep registering new keys
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let op = self.generate_leader_key_register_op(vrf_pk, burnchain_tip.consensus_hash); // todo(ludo): should we use the consensus hash from the burnchain tip, or last sortitioned block?
        ops_tx.send(op).unwrap();

        if self.active_registered_key.is_none() {                                    
            // Trigger register_key op
        } else {
            if self.last_sortitioned_block.is_some() {
                println!("generate_block_commit_op");

                // Trigger block_commit op
                let registered_key = self.active_registered_key.clone().unwrap();
                let sortitioned_block = self.last_sortitioned_block.clone().unwrap();
                let chain_tip = self.chain_tip.clone().unwrap();

                let vrf_proof = self.keychain.generate_proof(&registered_key.vrf_public_key, sortitioned_block.sortition_hash.as_bytes()).unwrap();

                let op = self.generate_block_commit_op(
                    chain_tip.anchored_header.block_hash(),
                    1, // todo(ludo): fix
                    &registered_key, 
                    &sortitioned_block,
                    VRFSeed::from_proof(&vrf_proof));
                ops_tx.send(op).unwrap();
            } else {
                let chain_tip = self.chain_tip.clone().unwrap();
                if chain_tip.is_genesis() {
                    
                    // Trigger block_commit op
                    let key = self.active_registered_key.clone().unwrap();

                    let vrf_proof = self.keychain.generate_proof(&key.vrf_public_key, &SortitionHash::initial().0).unwrap();

                    let op = BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
                        block_header_hash: chain_tip.anchored_header.block_hash(),
                        burn_fee: 1,
                        input: self.keychain.get_burnchain_signer(),
                        key_block_ptr: key.block_height as u32,
                        key_vtxindex: key.op_vtxindex as u16,
                        memo: vec![],
                        new_seed: VRFSeed::from_proof(&vrf_proof),
                        parent_block_ptr: 0,
                        parent_vtxindex: 0,
            
                        // to be filled in 
                        vtxindex: 0,
                        txid: Txid([0u8; 32]),
                        block_height: 0,
                        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
                    });
                                
                    ops_tx.send(op).unwrap();
                }
            }
        }
        self.burnchain_ops_tx = Some(ops_tx);
    }

    pub fn initiate_new_tenure(&mut self, sortitioned_block: SortitionedBlock) -> LeaderTenure {

        let registered_key = self.active_registered_key.clone().unwrap();

        let vrf_proof = self.keychain.generate_proof(&registered_key.vrf_public_key, sortitioned_block.sortition_hash.as_bytes()).unwrap();

        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        let (chain_tip, clarity_tx) = match self.chain_tip {
            Some(ref chain_tip) => {
                println!("1: {:?}", sortitioned_block.parent_burn_header_hash);
                println!("2: {:?}", sortitioned_block.burn_header_hash);
                println!("3: {:?}", chain_tip.index_block_hash());
                println!("4: {:?}", chain_tip.anchored_header.block_hash());
                (chain_tip.clone(), self.chain_state.block_begin(
                    &sortitioned_block.parent_burn_header_hash, 
                    &BlockHeaderHash([0u8; 32]), 
                    &sortitioned_block.burn_header_hash, 
                    &chain_tip.anchored_header.block_hash()))
            },
            None => 
                (StacksHeaderInfo::genesis(), self.chain_state.block_begin(
                    &BurnchainHeaderHash([0u8; 32]),
                    &BlockHeaderHash([0u8; 32]),
                    &BurnchainHeaderHash([1u8; 32]), 
                    &BlockHeaderHash([1u8; 32])))
        };

        let mut tenure = LeaderTenure::new(
            chain_tip, 
            self.block_time,
            self.burnchain_ops_tx.clone().unwrap(),
            self.mem_pool.clone(),
            microblock_secret_key, 
            sortitioned_block,
            vrf_proof);

        // let res = tenure.block_builder.epoch_begin(&mut self.chain_state, &coinbase_tx);
        // let clarity_tx = res.unwrap();
        tenure.tear_up(clarity_tx);

        let coinbase_tx = {
            let tx_auth = self.keychain.get_transaction_auth().unwrap();

            let mut tx = StacksTransaction::new(
                TransactionVersion::Testnet, 
                tx_auth, 
                TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
            tx.chain_id = 0x80000000; // todo(ludo): fix?
            tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
            let mut tx_signer = StacksTransactionSigner::new(&tx);
            self.keychain.sign_as_origin(&mut tx_signer);
            tx_signer.get_tx().unwrap()
        };
        tenure.handle_txs(vec![coinbase_tx]);

        // tenure.tear_up(&mut self.chain_state, &coinbase_tx);

        tenure
    }
}

pub struct LeaderTenure <'a> {
// pub struct LeaderTenure {
    average_block_time: u64,
    pub block_builder: StacksBlockBuilder,
    burnchain_ops_tx: Sender<BlockstackOperationType>,
    clarity_tx: Option<ClarityTx<'a>>,
    last_sortitioned_block: SortitionedBlock,
    mem_pool: MemPoolFS,
    started_at: std::time::Instant,
    vrf_seed: VRFSeed,
}

impl <'a> LeaderTenure <'a> {
// impl LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, 
               average_block_time: u64,
               burnchain_ops_tx: Sender<BlockstackOperationType>,
               mem_pool: MemPoolFS,
               microblock_secret_key: StacksPrivateKey,  
               last_sortitioned_block: SortitionedBlock,
               vrf_proof: VRFProof) -> LeaderTenure <'a> {

        let now = time::Instant::now();
        
        let ratio = StacksWorkScore {
            burn: 0, // todo(ludo): get burn from burnchain_tip.
            work: 1
        };


        // last_sortitioned_block.sortition_hash.to_uint256() == 0

        println!("Initializing new tenure {:?}", last_sortitioned_block);

        let block_builder = match last_sortitioned_block.block_height {
            1 => StacksBlockBuilder::first(&parent_block.burn_header_hash, &vrf_proof, &microblock_secret_key),
            _ => StacksBlockBuilder::from_parent(&parent_block, &ratio, &vrf_proof, &microblock_secret_key)
        };

        Self {
            average_block_time,
            block_builder,
            burnchain_ops_tx,
            clarity_tx: None,
            last_sortitioned_block,
            mem_pool,
            started_at: now,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    // pub fn tear_up(&mut self, chain_state: &mut StacksChainState, coinbase: &StacksTransaction) {
    //     let res = self.block_builder.epoch_begin(&mut chain_state, coinbase);
    //     let mut clarity_tx = res.unwrap();
    //     self.clarity_tx = Some(clarity_tx);
    // }

    pub fn tear_up(&mut self, clarity_tx: ClarityTx<'a>) {
        self.clarity_tx = Some(clarity_tx);
    }

    pub fn handle_txs(&mut self, txs: Vec<StacksTransaction>) {
        let mut clarity_tx = self.clarity_tx.take().unwrap();
        for tx in txs {
            self.block_builder.try_mine_tx(&mut clarity_tx, &tx).unwrap();
        }
        self.clarity_tx = Some(clarity_tx);
    }

    pub fn run(&mut self) -> (Option<StacksBlock>, Vec<StacksMicroblock>) {

        println!("Running tenure");
        let mempool_poll_interval = time::Duration::from_millis(250);
        let tenure_duration = time::Duration::from_millis(self.average_block_time * 1 / 2);
        let should_commit_block_at = self.started_at.checked_add(tenure_duration).unwrap();

        while time::Instant::now() < should_commit_block_at {
            let txs = self.mem_pool.poll();
            self.handle_txs(txs);
            thread::sleep(mempool_poll_interval);
        }

        let mut clarity_tx = self.clarity_tx.take().unwrap();
        let anchored_block = self.block_builder.mine_anchored_block(&mut clarity_tx);
        // self.block_builder.epoch_finish(clarity_tx);
        clarity_tx.rollback_block();

        // (anchored_block, vec![])
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

        // let mut clarity_tx = self.clarity_tx.take().unwrap();

        println!("End tenure");

        (Some(anchored_block), vec![])
    }
}