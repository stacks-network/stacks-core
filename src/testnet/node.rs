use super::{Keychain, MemPool, MemPoolFS, NodeConfig, LeaderTenure};

use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::{Arc, Mutex};

use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid};
use chainstate::burn::db::burndb::{BurnDB};
use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo, ClarityTx};
use chainstate::stacks::{StacksPrivateKey, StacksBlock, TransactionPayload, StacksWorkScore, StacksAddress, StacksTransactionSigner, StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAnchorMode};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::{ConsensusHash, SortitionHash, BlockSnapshot, VRFSeed, BlockHeaderHash};
use net::StacksMessageType;
use util::hash::Sha256Sum;
use util::vrf::{VRFProof, VRFPublicKey};

#[derive(Clone)]
struct RegisteredKey {
    block_height: u16,
    op_vtxindex: u16,
    vrf_public_key: VRFPublicKey,
}

#[derive(Clone, Debug)]
pub struct SortitionedBlock {
    pub block_height: u16,
    pub burn_header_hash: BurnchainHeaderHash,
    consensus_hash: ConsensusHash,
    op_vtxindex: u16,
    op_txid: Txid,
    parent_burn_header_hash: BurnchainHeaderHash,
    sortition_hash: SortitionHash,
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

/// 
pub struct Node {
    active_registered_key: Option<RegisteredKey>,
    average_block_time: u64,
    bootstraping_chain: bool,
    burnchain_ops_tx: Option<Sender<BlockstackOperationType>>,
    burnchain_tip: Option<BlockSnapshot>,
    chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    config: NodeConfig,
    keychain: Keychain,
    last_sortitioned_block: Option<SortitionedBlock>,
    mem_pool: MemPoolFS,
    nonce: u64,
    pub rx: Receiver<StacksMessageType>,
    pub tx: Sender<StacksMessageType>,
}

impl Node {

    /// 
    pub fn new(config: NodeConfig, average_block_time: u64) -> Self {
        
        let keychain = Keychain::default();

        let chain_state = StacksChainState::open(false, 0x80000000, &config.path).unwrap();

        let mem_pool = MemPoolFS::new(&config.mem_pool_path);

        let (tx, rx) = channel();

        Self {
            active_registered_key: None,
            bootstraping_chain: false,
            chain_state,
            chain_tip: None,
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
    
    /// 
    pub fn tear_up(&mut self, burnchain_ops_tx: Sender<BlockstackOperationType>, consensus_hash: ConsensusHash) {
        // Register a new key
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, consensus_hash);
        burnchain_ops_tx.send(key_reg_op).unwrap();

        // Keep the burnchain_ops_tx for subsequent ops submissions
        self.burnchain_ops_tx = Some(burnchain_ops_tx);
    }

    /// 
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
                BlockstackOperationType::UserBurnSupport(_) => {
                    // no-op, UserBurnSupport ops are not supported / produced at this point.
                }
            }
        }

        // Update the active key so we use the latest registered key.
        if new_key.is_some() {
            self.active_registered_key = new_key;
        }

        // Update last_sortitioned_block so we keep a reference to the latest
        // block including a sortition.
        if last_sortitioned_block.is_some() {
            self.last_sortitioned_block = last_sortitioned_block;
        }

        // Keep a pointer of the burnchain's chain tip.
        self.burnchain_tip = Some(block.clone());

        (self.last_sortitioned_block.clone(), won_sortition)
    }

    /// Prepares the node to run a tenure consisting in bootstraping the chain.
    /// 
    /// Will internally call initiate_new_tenure().
    pub fn initiate_genesis_tenure(&mut self, block: &BlockSnapshot) -> Option<LeaderTenure> {
        // Set the `bootstraping_chain` flag, that will be unset once the 
        // bootstraping tenure ran successfully (process_tenure).
        self.bootstraping_chain = true;

        // Mock a block, including the expected initial sortition.
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

        self.last_sortitioned_block = Some(block.clone());

        self.initiate_new_tenure(&block)
    }

    /// Constructs and returns an instance of LeaderTenure, that can be run
    /// on an isolated thread and discarded or canceled without corrupting the
    /// chain state of the node.
    pub fn initiate_new_tenure(&mut self, sortitioned_block: &SortitionedBlock) -> Option<LeaderTenure> {
        // Get the latest registered key
        let registered_key = match &self.active_registered_key {
            None => {
                // We're continuously registering new keys, as such, this branch
                // should be unreachable.
                unreachable!()
            },
            Some(ref key) => key,
        };

        // Generates a proof out of the sortition hash provided in the params.
        let vrf_proof = self.keychain.generate_proof(
            &registered_key.vrf_public_key, 
            sortitioned_block.sortition_hash.as_bytes()).unwrap();

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        // Get the stack's chain tip
        let chain_tip = match self.bootstraping_chain {
            true => StacksHeaderInfo::genesis(),
            false => match &self.chain_tip {
                Some(chain_tip) => chain_tip.clone(),
                None => unreachable!()
            }
        };

        // Constructs the coinbase transaction - 1st txn that should be handled and included in 
        // the upcoming tenure.
        let coinbase_tx = {
            let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
            tx_auth.set_origin_nonce(self.nonce);

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

        // Construct the upcoming tenure
        let tenure = LeaderTenure::new(
            chain_tip, 
            self.average_block_time,
            coinbase_tx,
            self.config.clone(),
            self.mem_pool.clone(),
            microblock_secret_key, 
            sortitioned_block.clone(),
            vrf_proof);
        
        // Increment nonce
        self.nonce += 1;

        Some(tenure)
    }

    /// Handles artefacts coming from an ongoing tenure.
    /// At this point, we're not updating the chainstate, we're simply having the node
    /// candidating for the next tenure.
    pub fn receive_tenure_artefacts(&mut self, anchored_block_from_ongoing_tenure: &StacksBlock, parent_block: &SortitionedBlock) {
        let ops_tx = self.burnchain_ops_tx.take().unwrap();

        if self.active_registered_key.is_some() {
            let registered_key = self.active_registered_key.clone().unwrap();

            let vrf_proof = self.keychain.generate_proof(
                &registered_key.vrf_public_key, 
                parent_block.sortition_hash.as_bytes()).unwrap();

            let op = self.generate_block_commit_op(
                anchored_block_from_ongoing_tenure.header.block_hash(),
                1, // todo(ludo): fix
                &registered_key, 
                &parent_block,
                VRFSeed::from_proof(&vrf_proof));

            ops_tx.send(op).unwrap();
        }

        // Naive implementation: we keep registering new keys
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let op = self.generate_leader_key_register_op(vrf_pk, parent_block.consensus_hash); // todo(ludo): should we use the consensus hash from the burnchain tip, or last sortitioned block?
        ops_tx.send(op).unwrap();

        self.burnchain_ops_tx = Some(ops_tx);
    }

    /// Process artefacts from the tenure.
    /// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
    pub fn process_tenure(&mut self, anchored_block: &StacksBlock, parent_block: &SortitionedBlock, microblocks: Vec<StacksMicroblock>, burn_db: Arc<Mutex<BurnDB>>) {

        {
            let mut db = burn_db.lock().unwrap();

            let mut tx = db.tx_begin().unwrap();

            let res = self.chain_state.preprocess_anchored_block(
                &mut tx, 
                &parent_block.burn_header_hash,
                &anchored_block, 
                &parent_block.parent_burn_header_hash).unwrap();
        }

        let new_chain_tip = {
            let db = burn_db.lock().unwrap();
            let res = self.chain_state.process_blocks(db.conn(), 1).unwrap();
            res.first().unwrap().0.as_ref().unwrap().clone() // todo(ludo): yikes
        };

        self.chain_tip = Some(new_chain_tip);

        // Unset the `bootstraping_chain` flag.
        if self.bootstraping_chain {
            self.bootstraping_chain = false;
        }
    }

    /// Returns the Stacks address of the node
    pub fn get_address(&self) -> StacksAddress {
        self.keychain.get_address()
    }

    /// Constructs and returns a LeaderKeyRegisterOp out of the provided params
    fn generate_leader_key_register_op(&mut self, vrf_public_key: VRFPublicKey, consensus_hash: ConsensusHash) -> BlockstackOperationType {

        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            address: self.keychain.get_address(),
            consensus_hash,

            // Props that will be set by the burnchain simulator
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    /// Constructs and returns a LeaderBlockCommitOp out of the provided params
    fn generate_block_commit_op(&mut self, 
                                block_header_hash: BlockHeaderHash,
                                burn_fee: u64, 
                                key: &RegisteredKey,
                                parent_block: &SortitionedBlock,
                                vrf_seed: VRFSeed) -> BlockstackOperationType {
        
        let (parent_block_ptr, parent_vtxindex) = match self.bootstraping_chain {
            true => (0, 0), // Expected references when mocking the initial sortition
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

            // Props that will be set by the burnchain simulator
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }
}
