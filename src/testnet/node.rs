use super::{Keychain, MemPool, MemPoolFS, NodeConfig};

use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::{Arc, Mutex};

use std::fmt;
use std::thread;
use std::time;
use rand::RngCore;

use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, BurnchainSigner};
use chainstate::burn::db::burndb::{BurnDB};
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
    consensus_hash: ConsensusHash,
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
            consensus_hash: ConsensusHash::empty(),
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
            parent_burn_header_hash: BurnchainHeaderHash([0u8; 32]),
            block_height: 1,
            op_vtxindex: 0,
            op_txid: Txid([0u8; 32]),
            total_burn: 0
        }
    }

}

pub struct Node {
    active_registered_key: Option<RegisteredKey>,
    average_block_time: u64,
    bootstraping_chain: bool,
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    config: NodeConfig,
    pub last_sortitioned_block: Option<SortitionedBlock>,
    // last_mined_block_including_a_sortition: Option<SortitionedBlock>,
    // last_mined_block_including_a_sortition_and_need_artefacts_from_: Option<SortitionedBlock>,
    burnchain_tip: Option<BlockSnapshot>,
    mem_pool: MemPoolFS,
    keychain: Keychain,
    burnchain_ops_tx: Option<Sender<BlockstackOperationType>>,
    rx: Receiver<StacksMessageType>,
    nonce: u64,
    pub tx: Sender<StacksMessageType>,
}

impl Node {

    pub fn new(config: NodeConfig, average_block_time: u64) -> Self {
        
        let keychain = Keychain::default();

        let chain_state = StacksChainState::open(false, 0x80000000, &config.path).unwrap();

        let mem_pool = MemPoolFS::new(&config.mem_pool_path);

        let (tx, rx) = channel();

        Self {
            active_registered_key: None,
            bootstraping_chain: false,
            chain_state,
            chain_tip: None, //Some(StacksHeaderInfo::genesis()),
            config,
            keychain,
            last_sortitioned_block: None,
            mem_pool,
            average_block_time,
            burnchain_ops_tx: None,
            burnchain_tip: None,
            tx,
            rx,
            nonce: 0,
        }
    }
    
    pub fn tear_up(&mut self, burnchain_ops_tx: Sender<BlockstackOperationType>, consensus_hash: ConsensusHash) {
        // Register a new key
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, consensus_hash);
        burnchain_ops_tx.send(key_reg_op).unwrap();

        // Keep the burnchain_ops_tx for subsequent ops submissions
        self.burnchain_ops_tx = Some(burnchain_ops_tx);
    }

    pub fn process_burnchain_block(&mut self, block: &BlockSnapshot, ops: &Vec<BlockstackOperationType>) -> (Option<SortitionedBlock>, bool) {
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
                    }
                },
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    if op.txid == block.winning_block_txid {
                        last_sortitioned_block = Some(SortitionedBlock {
                            block_height: block.block_height as u16,
                            op_vtxindex: op.vtxindex as u16,
                            op_txid: op.txid,
                            sortition_hash: block.sortition_hash,
                            consensus_hash: block.consensus_hash,
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
            self.active_registered_key = new_key;
        }

        if last_sortitioned_block.is_some() {
            self.last_sortitioned_block = last_sortitioned_block;
        }

        self.burnchain_tip = Some(block.clone());

        (self.last_sortitioned_block.clone(), won_sortition)
    }

    // BLock coming from burnchain.
    // Block has a registered key
    // Node should act as if it won sortition,
    // and start a tenure:
    // An anchored block must be produced, attached to block we just received.
    // Parent block of this is 0000000...0

    pub fn initiate_genesis_tenure(&mut self, block: &BlockSnapshot) -> Option<LeaderTenure> {
        // Node can't bootstap the chain without a registered key.
        let key = match &self.active_registered_key {
            None => return None,
            Some(key) => key.clone()
        };

        self.bootstraping_chain = true;

        let block = SortitionedBlock {
            block_height: block.block_height as u16,
            op_vtxindex: 0,
            op_txid: Txid([0u8; 32]),
            sortition_hash: SortitionHash::initial(),
            consensus_hash: block.consensus_hash,
            total_burn: 0,
            burn_header_hash: block.burn_header_hash,
            parent_burn_header_hash: block.parent_burn_header_hash,
        };

        let tenure = self.initiate_new_tenure(&block);

        self.last_sortitioned_block = Some(block);

        tenure
    }

    pub fn initiate_new_tenure(&mut self, sortitioned_block: &SortitionedBlock) -> Option<LeaderTenure> {
        println!("initiate_new_tenure()");

        let registered_key = match &self.active_registered_key {
            None => {

                println!("Registering new key");

                // let ops_tx = self.burnchain_ops_tx.take().unwrap();
                // let vrf_pk = self.keychain.rotate_vrf_keypair();
                // let op = self.generate_leader_key_register_op(
                //     vrf_pk, 
                //     self.burnchain_tip.as_ref().unwrap().consensus_hash.clone()); // todo(ludo): should we use the consensus hash from the burnchain tip, or last sortitioned block?
                // ops_tx.send(op).unwrap();

                // self.burnchain_ops_tx = Some(ops_tx);
                return None;
            },
            Some(registered_key) => registered_key.clone(),
        };

        let vrf_proof = self.keychain.generate_proof(&registered_key.vrf_public_key, sortitioned_block.sortition_hash.as_bytes()).unwrap();

        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        let chain_tip = match self.bootstraping_chain {
            true => StacksHeaderInfo::genesis(),
            false => match &self.chain_tip {
                Some(chain_tip) => chain_tip.clone(),
                None => unreachable!()
            }
        };

        println!("INITIATING TENURE WITH ~~~~> {:?} {:?}", chain_tip, chain_tip.anchored_header.block_hash());


        let coinbase_tx = {
            let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
            tx_auth.set_origin_nonce(self.nonce); // todo(ludo): fix nonce management

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

        let mut tenure = LeaderTenure::new(
            chain_tip, 
            self.average_block_time,
            self.burnchain_ops_tx.clone().unwrap(),
            coinbase_tx,
            self.config.clone(),
            self.mem_pool.clone(),
            microblock_secret_key, 
            sortitioned_block.clone(),
            vrf_proof);

        self.nonce += 1;
        Some(tenure)
    }


    pub fn process_tenure(&mut self, anchored_block: StacksBlock, parent_block: SortitionedBlock, microblocks: Vec<StacksMicroblock>, burn_db: Arc<Mutex<BurnDB>>) {

        // todo(ludo): verify that the block is attached to some fork in the burn chain.

        let chain_tip = match self.bootstraping_chain {
            true => StacksHeaderInfo::genesis(),
            false => match &self.chain_tip {
                Some(chain_tip) => chain_tip.clone(),
                _ => unreachable!()
            }
        };
        println!("process_tenure: {:?} - {:?}", anchored_block, chain_tip);

        println!("SORTITIONED BLOCK: {:?}", parent_block);

        // self.chain_state.store_staging_block(
        //     &parent_block.burn_header_hash, 
        //     &anchored_block, 
        //     &parent_block.parent_burn_header_hash, 
        //     1, 
        //     parent_block.total_burn).unwrap();

            // todo(ludo): verify that this block was signed by the miner of the ancestor
            // anchored block that this microblock builds off of, + ordering?
            // for microblock in microblocks.iter() {
            //     self.chain_state.store_staging_microblock(
            //         &parent_block.burn_header_hash, 
            //         &anchored_block.block_hash(),
            //         &microblock).unwrap();    
            // }

            // let current_chain_tip = match self.chain_tip {
            //     Some(ref chain_tip) => chain_tip.clone(),
            //     None => StacksHeaderInfo::genesis(),
            // };

            // chain_tip_burn_header_hash: &BurnchainHeaderHash, 

    /// Process the next pre-processed staging block.
    /// We've already processed parent_chain_tip.  chain_tip refers to a block we have _not_
    /// processed yet.
    /// Returns a StacksHeaderInfo with the microblock stream and chain state index root hash filled in, corresponding to the next block to process.
    /// Returns None if we're out of blocks to process.
    // pub fn append_block(&mut self, 
    //     parent_chain_tip: &StacksHeaderInfo, 
    //     chain_tip_burn_header_hash: &BurnchainHeaderHash, 
    //     block: &StacksBlock, 
    //     microblocks: &Vec<StacksMicroblock>, 
    //     burnchain_commit_burn: u64, 
    //     burnchain_sortition_burn: u64, 
    //     user_burns: &Vec<StagingUserBurnSupport>) -> Result<StacksHeaderInfo, Error>


//     #[derive(Debug, Clone, PartialEq)]
// pub struct StacksBlockHeader {
//     pub version: u8,
//     pub total_work: StacksWorkScore,            // NOTE: this is the work done on the chain tip this block builds on (i.e. take this from the parent)
//     pub proof: VRFProof,
//     pub parent_block: BlockHeaderHash,          // NOTE: even though this is also present in the burn chain, we need this here for super-light clients that don't even have burn chain headers
//     pub parent_microblock: BlockHeaderHash,
//     pub parent_microblock_sequence: u16,
//     pub tx_merkle_root: Sha512Trunc256Sum,
//     pub state_index_root: TrieHash,
//     pub microblock_pubkey_hash: Hash160,        // we'll get the public key back from the first signature (note that this is the Hash160 of the _compressed_ public key)
// }

// /// A block that contains blockchain-anchored data 
// /// (corresponding to a LeaderBlockCommitOp)
// #[derive(Debug, Clone, PartialEq)]
// pub struct StacksBlock {
//     pub header: StacksBlockHeader,
//     pub txs: Vec<StacksTransaction>
// }


        // let header = StacksHeaderInfo {
        //     anchored_header: anchored_block.header,
        //     microblock_tail: None,
        //     block_height: anchored_block.header.,
        //     index_root: anchored_block.header.state_index_root,
        //     burn_header_hash: BurnchainHeaderHash
        // };
    
        // pub fn process_blocks(&mut self, burndb_conn: &DBConn, max_blocks: usize) -> Result<Vec<(Option<StacksHeaderInfo>, Option<TransactionPayload>)>, Error> {

            // pub fn preprocess_anchored_block<'a>(&mut self, burn_tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash) -> Result<bool, Error> {

                // pub fn preprocess_anchored_block<'a>(&mut self, burn_tx: &mut BurnDBTx<'a>, burn_header_hash: &BurnchainHeaderHash, block: &StacksBlock, parent_burn_header_hash: &BurnchainHeaderHash) -> Result<bool, Error> {
                //     // already in queue or already processed?
                //     if self.has_stored_block(burn_header_hash, &block.block_hash())? || self.has_staging_block(burn_header_hash, &block.block_hash())? {
                //         return Ok(false);
                //     }


            {
                let mut db = burn_db.lock().unwrap();

                let mut tx = db.tx_begin().unwrap();

                let res = self.chain_state.preprocess_anchored_block(
                    &mut tx, 
                    &parent_block.burn_header_hash,
                    &anchored_block, 
                    &parent_block.parent_burn_header_hash).unwrap();
            }

        // // "discover" this stacks microblock stream
        // for mblock in stacks_microblocks.iter() {
        //     test_debug!("Preprocess Stacks microblock {}-{} (seq {})", &block_hash.to_hex(), mblock.block_hash().to_hex(), mblock.header.sequence);
        //     let res = node.chainstate.preprocess_streamed_microblock(&mut tx, &commit_snapshot.burn_header_hash, &stacks_block.block_hash(), mblock).unwrap();
        //     if !res {
        //         return Some(res)
        //     }
        // }
        

        // self.chain_state.store_staging_block(
        //     &parent_block.burn_header_hash, 
        //     &anchored_block, 
        //     &parent_block.parent_burn_header_hash, 
        //     1, 
        //     parent_block.total_burn).unwrap();



        // let (next_tip_opt, next_microblock_poison_opt) = self.chain_state.process_next_staging_block(&best_chain_tips)?;
            let new_chain_tip = {
                let db = burn_db.lock().unwrap();
                let res = self.chain_state.process_blocks(db.conn(), 1).unwrap();
                println!("~~~~> {:?}", res);
                res.first().unwrap().0.as_ref().unwrap().clone()
            };
            // let new_chain_tip = self.chain_state.append_block( 
            //     &current_chain_tip, 
            //     &parent_block.burn_header_hash, 
            //     &anchored_block, 
            //     &microblocks, 
            //     1, 
            //     parent_block.total_burn, 
            //     &vec![]).unwrap();


            println!("----------------------------------------------");
            println!("Updating chain_tip");
            println!("{:?}", chain_tip);
            println!("{:?}", new_chain_tip);
            println!("~~~~> {:?}", new_chain_tip.anchored_header.block_hash());

            self.chain_tip = Some(new_chain_tip);
            println!("----------------------------------------------");

            self.bootstraping_chain = false;
        
        // Update self.chain_tip = Some(...);
    }

    // pub fn process_tenure(&mut self, anchored_block: StacksBlock, microblocks: Vec<StacksMicroblock>, burn_db: Arc<Mutex<BurnDB>>) {

    pub fn receive_tenure_artefacts(&mut self, anchored_block_from_ongoing_tenure: StacksBlock, parent_block: SortitionedBlock) {
        println!("receive_tenure_artefacts");

        let ops_tx = self.burnchain_ops_tx.take().unwrap();

        // let burnchain_tip = self.burnchain_tip.clone().unwrap();
        // let parent_block = self.last_sortitioned_block.clone().unwrap();

        if self.active_registered_key.is_some() {
            let registered_key = self.active_registered_key.clone().unwrap();
            // let sortitioned_block = self.last_sortitioned_block.clone().unwrap();

            // let previous_seed = VRFSeed::from_proof(&anchored_block_from_ongoing_tenure.header.proof);
            // let new_proof = previous_seed
            // let vrf_proof = self.keychain.generate_proof(&registered_key.vrf_public_key, previous_seed.as_bytes()).unwrap();
            let vrf_proof = self.keychain.generate_proof(&registered_key.vrf_public_key, parent_block.sortition_hash.as_bytes()).unwrap();

            let op = self.generate_block_commit_op(
                anchored_block_from_ongoing_tenure.header.block_hash(),
                1, // todo(ludo): fix
                &registered_key, 
                &parent_block.clone(),
                VRFSeed::from_proof(&vrf_proof));
            println!("SUBMITTING OP: {:?}", op);
            ops_tx.send(op).unwrap();
        }

        // Naive implementation: we keep registering new keys
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let op = self.generate_leader_key_register_op(vrf_pk, parent_block.consensus_hash); // todo(ludo): should we use the consensus hash from the burnchain tip, or last sortitioned block?
        ops_tx.send(op).unwrap();

        self.burnchain_ops_tx = Some(ops_tx);
    }


    pub fn maintain_leadership_eligibility(&mut self) {
        println!("maintain_leadership_eligibility");

        let ops_tx = self.burnchain_ops_tx.take().unwrap();

        let burnchain_tip = self.burnchain_tip.clone().unwrap();
        
        // Naive implementation: we keep registering new keys
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let op = self.generate_leader_key_register_op(vrf_pk, burnchain_tip.consensus_hash); // todo(ludo): should we use the consensus hash from the burnchain tip, or last sortitioned block?
        ops_tx.send(op).unwrap();

        if self.active_registered_key.is_some() && self.last_sortitioned_block.is_some() {
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
            println!("SUBMITTING OP: {:?}", op);
            ops_tx.send(op).unwrap();

            self.bootstraping_chain = false;
        }

        self.burnchain_ops_tx = Some(ops_tx);
    }


    pub fn get_address(&self) -> StacksAddress {
        self.keychain.get_address()
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
        
        let (parent_block_ptr, parent_vtxindex) = match self.bootstraping_chain {
            true => (0, 0),
            false => (parent_block.block_height as u32, parent_block.op_vtxindex as u16)
        };

        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            block_header_hash,
            burn_fee,
            input: self.keychain.get_burnchain_signer(),
            key_block_ptr: key.block_height as u32,
            key_vtxindex: key.op_vtxindex as u16,
            memo: vec![],
            new_seed: vrf_seed,
            parent_block_ptr,
            parent_vtxindex,

            // to be filled in 
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

}

pub struct LeaderTenure {
// pub struct LeaderTenure {
    average_block_time: u64,
    pub block_builder: StacksBlockBuilder,
    burnchain_ops_tx: Sender<BlockstackOperationType>,
    coinbase_tx: StacksTransaction,
    config: NodeConfig,
    pub last_sortitioned_block: SortitionedBlock,
    mem_pool: MemPoolFS,
    pub parent_block: StacksHeaderInfo,
    started_at: std::time::Instant,
    vrf_seed: VRFSeed,
}

impl fmt::Display for LeaderTenure {

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tenure ( height: {}, burn_header_hash: {:?}, parent_hash: {} )", self.parent_block.block_height, self.last_sortitioned_block.burn_header_hash, self.parent_block.anchored_header.block_hash())
    }
}

impl <'a> LeaderTenure {
// impl LeaderTenure {

    pub fn new(parent_block: StacksHeaderInfo, 
               average_block_time: u64,
               burnchain_ops_tx: Sender<BlockstackOperationType>,
               coinbase_tx: StacksTransaction,
               config: NodeConfig,
               mem_pool: MemPoolFS,
               microblock_secret_key: StacksPrivateKey,  
               last_sortitioned_block: SortitionedBlock,
               vrf_proof: VRFProof) -> LeaderTenure {

        let now = time::Instant::now();

        let ratio = StacksWorkScore {
            burn: parent_block.anchored_header.total_work.burn + 1, // todo(ludo): get burn from burnchain_tip.
            work: parent_block.anchored_header.total_work.work + 1,
        };

        // last_sortitioned_block.sortition_hash.to_uint256() == 0

        println!("Initializing new tenure {:?}", last_sortitioned_block);

        let block_builder = match last_sortitioned_block.block_height {
            0 => StacksBlockBuilder::first(1, &parent_block.burn_header_hash, &vrf_proof, &microblock_secret_key),
            _ => StacksBlockBuilder::from_parent(1, &parent_block, &ratio, &vrf_proof, &microblock_secret_key)
        };

        Self {
            average_block_time,
            block_builder,
            burnchain_ops_tx,
            coinbase_tx,
            config,
            last_sortitioned_block,
            mem_pool,
            parent_block,
            started_at: now,
            vrf_seed: VRFSeed::from_proof(&vrf_proof),
        }
    }

    pub fn handle_txs(&mut self, clarity_tx: &mut ClarityTx<'a>, txs: Vec<StacksTransaction>) {
        for tx in txs {
            // println!("#### PRE-TX: {:?}", clarity_tx.get_root_hash());

            self.block_builder.try_mine_tx(clarity_tx, &tx).unwrap();
    
            // println!("#### POST-TX: {:?}", clarity_tx.get_root_hash());    
        }
    }

    pub fn run(&mut self) -> (Option<StacksBlock>, Vec<StacksMicroblock>, SortitionedBlock) {

        let mut chain_state = StacksChainState::open(false, 0x80000000, &self.config.path).unwrap();

        // let mut clarity_tx = if self.last_sortitioned_block.block_height == 1 {
        //     chain_state.block_begin(
        //             &self.last_sortitioned_block.parent_burn_header_hash, 
        //             &self.parent_block.anchored_header.parent_block, 
        //             // &BurnchainHeaderHash([1u8; 32]), 
        //             // &BlockHeaderHash([1u8; 32])))
        //             &self.last_sortitioned_block.burn_header_hash, 
        //             &self.parent_block.anchored_header.block_hash())
        //     } else {
        //         chain_state.block_begin(
        //             &BurnchainHeaderHash([0u8; 32]),
        //             &BlockHeaderHash([0u8; 32]),
        //             &BurnchainHeaderHash([1u8; 32]), 
        //             &BlockHeaderHash([1u8; 32]))
        //     };

        println!("BOOTSTRAPING TENURE {}", self.last_sortitioned_block.block_height);

        let mut clarity_tx = match self.last_sortitioned_block.block_height {
            0 => {
                println!("HERE");
                chain_state.block_begin(
                &BurnchainHeaderHash([0u8; 32]),
                &BlockHeaderHash([0u8; 32]),
                &BurnchainHeaderHash([1u8; 32]), 
                &BlockHeaderHash([1u8; 32]))
            },
            _ => chain_state.block_begin(
                &self.last_sortitioned_block.burn_header_hash, 
                &self.parent_block.anchored_header.block_hash(), 
                &BurnchainHeaderHash([1u8; 32]), 
                &BlockHeaderHash([1u8; 32])),
                // &self.last_sortitioned_block.burn_header_hash, 
                // &self.parent_block.anchored_header.block_hash()),
        };

        println!("Running tenure");
        let mempool_poll_interval = time::Duration::from_millis(250);
        let tenure_duration = time::Duration::from_millis(self.average_block_time * 1 / 2);
        let should_commit_block_at = self.started_at.checked_add(tenure_duration).unwrap();

        self.handle_txs(&mut clarity_tx, vec![self.coinbase_tx.clone()]);

        while time::Instant::now() < should_commit_block_at {
            let txs = self.mem_pool.poll();
            self.handle_txs(&mut clarity_tx, txs);
            thread::sleep(mempool_poll_interval);
        }

        // println!("#### OUTER BEFORE COMMIT: {:?}", clarity_tx.get_root_hash());

        let mut b = self.block_builder.clone();
        let anchored_block = self.block_builder.mine_anchored_block(&mut clarity_tx);

        // let res = StacksChainState::process_block_transactions(&mut clarity_tx, &anchored_block);
        // println!("===> {:?}", res);
        // b.epoch_finish(clarity_tx);

        // println!("#### OUTER AFTER COMMIT: {}", clarity_tx.get_root_hash());

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

        println!("End tenure -> {:?}", anchored_block);

        (Some(anchored_block), vec![], self.last_sortitioned_block.clone())
    }
}