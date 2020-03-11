use super::{Keychain, MemPool, MemPoolFS, Config, LeaderTenure, BurnchainState, EventDispatcher};

use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender, Receiver};
use std::sync::{Arc, Mutex};

use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid};
use chainstate::burn::db::burndb::{BurnDB};
use chainstate::stacks::db::{StacksChainState, StacksHeaderInfo, ClarityTx};
use chainstate::stacks::events::StacksTransactionEvent;
use chainstate::stacks::{StacksPrivateKey, StacksBlock, TransactionPayload, StacksWorkScore, StacksAddress, StacksTransactionSigner, StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload, StacksBlockBuilder, TransactionAnchorMode};
use chainstate::burn::operations::{BlockstackOperationType, LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::{ConsensusHash, SortitionHash, BlockSnapshot, VRFSeed, BlockHeaderHash};
use net::{StacksMessageType, StacksMessageCodec};

use util::hash::Sha256Sum;
use util::vrf::{VRFProof, VRFPublicKey};
use util::get_epoch_time_secs;
use vm::types::PrincipalData;

pub const TESTNET_CHAIN_ID: u32 = 0x00000000;

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
    pub parent_burn_header_hash: BurnchainHeaderHash,
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

/// Node is a structure modelising an active node working on the stacks chain.
pub struct Node {
    active_registered_key: Option<RegisteredKey>,
    average_block_time: u64,
    bootstraping_chain: bool,
    burnchain_tip: Option<BlockSnapshot>,
    pub chain_state: StacksChainState,
    chain_tip: Option<StacksHeaderInfo>,
    config: Config,
    keychain: Keychain,
    last_sortitioned_block: Option<SortitionedBlock>,
    mem_pool: MemPoolFS,
    event_dispatcher: EventDispatcher,
    nonce: u64,
}

impl Node {

    /// Instantiate and initialize a new node, given a config
    pub fn new(config: Config) -> Self {
        
        let seed = Sha256Sum::from_data(format!("{}", config.node.name).as_bytes());
        let keychain = Keychain::default(seed.as_bytes().to_vec());

        let initial_balances = config.initial_balances.iter().map(|e| (e.address.clone(), e.amount)).collect();

        let chain_state = match StacksChainState::open_testnet(
            TESTNET_CHAIN_ID, 
            &config.get_chainstate_path(), 
            Some(initial_balances)) {
            Ok(res) => res,
            Err(_) => panic!("Error while opening chain state at path {:?}", config.get_chainstate_path())
        };

        let mem_pool = MemPoolFS::new(&config.mempool.path);

        let mut event_dispatcher = EventDispatcher::new();

        for observer in &config.events_observers {
            event_dispatcher.register_observer(observer);
        }

        Self {
            active_registered_key: None,
            bootstraping_chain: false,
            chain_state,
            chain_tip: None,
            keychain,
            last_sortitioned_block: None,
            mem_pool,
            average_block_time: config.burnchain.block_time,
            config,
            burnchain_tip: None,
            nonce: 0,
            event_dispatcher,
        }
    }
    
    pub fn setup(&mut self) -> BlockstackOperationType {
        // Register a new key
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let consensus_hash = ConsensusHash::empty();
        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, &consensus_hash);
        key_reg_op
    }

    /// Process an state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    pub fn process_burnchain_state(&mut self, state: &BurnchainState) -> (Option<SortitionedBlock>, bool) {
        let mut new_key = None;
        let mut last_sortitioned_block = None; 
        let mut won_sortition = false;
        let chain_tip = state.chain_tip.clone();

        for op in state.ops.iter() {
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
                    if op.txid == chain_tip.winning_block_txid {
                        last_sortitioned_block = Some(SortitionedBlock {
                            block_height: chain_tip.block_height as u16,
                            op_vtxindex: op.vtxindex as u16,
                            op_txid: op.txid,
                            sortition_hash: chain_tip.sortition_hash,
                            consensus_hash: chain_tip.consensus_hash,
                            total_burn: chain_tip.total_burn,
                            burn_header_hash: chain_tip.burn_header_hash,
                            parent_burn_header_hash: chain_tip.parent_burn_header_hash,
                        });

                        // Release current registered key if leader won the sortition
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
        self.burnchain_tip = Some(chain_tip);

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
            sortition_hash: block.sortition_hash,
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
        let coinbase_tx = self.generate_coinbase_tx();

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

        Some(tenure)
    }

    pub fn receive_tenure_artifacts(&mut self, anchored_block_from_ongoing_tenure: &StacksBlock, parent_block: &SortitionedBlock) -> Vec<BlockstackOperationType> {
        let mut ops = vec![];
        if self.active_registered_key.is_some() {
            let registered_key = self.active_registered_key.clone().unwrap();

            let vrf_proof = self.keychain.generate_proof(
                &registered_key.vrf_public_key, 
                parent_block.sortition_hash.as_bytes()).unwrap();

            let burn_fee = 1;
            let op = self.generate_block_commit_op(
                anchored_block_from_ongoing_tenure.header.block_hash(),
                burn_fee,
                &registered_key, 
                &parent_block,
                VRFSeed::from_proof(&vrf_proof));

            ops.push(op);
        }
        
        // Naive implementation: we keep registering new keys
        let vrf_pk = self.keychain.rotate_vrf_keypair();
        let burnchain_tip_consensus_hash = self.burnchain_tip.as_ref().unwrap().consensus_hash;
        let op = self.generate_leader_key_register_op(vrf_pk, &burnchain_tip_consensus_hash);

        ops.push(op);
        ops
    }

    /// Process artifacts from the tenure.
    /// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
    pub fn process_tenure(
        &mut self, 
        anchored_block: &StacksBlock, 
        burn_header_hash: &BurnchainHeaderHash, 
        parent_burn_header_hash: &BurnchainHeaderHash, 
        microblocks: Vec<StacksMicroblock>, 
        db: &mut BurnDB) -> (StacksBlock, StacksHeaderInfo, Vec<StacksTransactionEvent>) {

        {
            // let mut db = burn_db.lock().unwrap();
            let mut tx = db.tx_begin().unwrap();

            // Preprocess the anchored block
            self.chain_state.preprocess_anchored_block(
                &mut tx,
                &burn_header_hash,
                get_epoch_time_secs(),
                &anchored_block, 
                &parent_burn_header_hash).unwrap();

            // Preprocess the microblocks
            for microblock in microblocks.iter() {
                let res = self.chain_state.preprocess_streamed_microblock(
                    &burn_header_hash, 
                    &anchored_block.block_hash(), 
                    microblock).unwrap();
                if !res {
                    warn!("Unhandled error while pre-processing microblock {}", microblock.header.block_hash());
                }
            }
        }

        let mut processed_blocks = vec![];
        loop {
            match self.chain_state.process_blocks(1) {
                Err(e) => panic!("Error while processing block - {:?}", e),
                Ok(ref mut blocks) => {
                    if blocks.len() == 0 {
                        break;
                    } else {
                        processed_blocks.append(blocks);
                    }
                }
            }
        }

        // todo(ludo): yikes but good enough in the context of helium:
        // we only expect 1 block.
        let processed_block = processed_blocks[0].clone().0.unwrap();
        
        // Handle events
        let events = processed_block.1;
        let chain_tip_info = processed_block.0;
        let chain_tip = {
            let block_path = StacksChainState::get_block_path(
                &self.chain_state.blocks_path, 
                &chain_tip_info.burn_header_hash, 
                &chain_tip_info.anchored_header.block_hash()).unwrap();
            StacksChainState::consensus_load(&block_path).unwrap()
        };

        self.event_dispatcher.dispatch_events(&events, &chain_tip, &chain_tip_info);

        self.chain_tip = Some(chain_tip_info.clone());

        // Unset the `bootstraping_chain` flag.
        if self.bootstraping_chain {
            self.bootstraping_chain = false;
        }

        (chain_tip, chain_tip_info, events)
    }

    /// Returns the Stacks address of the node
    pub fn get_address(&self) -> StacksAddress {
        self.keychain.get_address()
    }

    /// Constructs and returns a LeaderKeyRegisterOp out of the provided params
    fn generate_leader_key_register_op(&mut self, vrf_public_key: VRFPublicKey, consensus_hash: &ConsensusHash) -> BlockstackOperationType {

        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            address: self.keychain.get_address(),
            consensus_hash: consensus_hash.clone(),

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

    // Constructs a coinbase transaction
    fn generate_coinbase_tx(&mut self) -> StacksTransaction {
        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(self.nonce);

        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet, 
            tx_auth, 
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
        tx.chain_id = TESTNET_CHAIN_ID;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);
     
        // Increment nonce
        self.nonce += 1;

        tx_signer.get_tx().unwrap()                       
    }
}
