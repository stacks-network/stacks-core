use super::{Keychain, Config, Tenure, BurnchainController, BurnchainTip, EventDispatcher};

use std::convert::TryFrom;
use std::{thread, time, thread::JoinHandle};
use std::net::SocketAddr;

use stacks::burnchains::{Burnchain, BurnchainHeaderHash, Txid};
use stacks::chainstate::burn::db::burndb::{BurnDB};
use stacks::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo, ClarityTx};
use stacks::chainstate::stacks::events::StacksTransactionReceipt;
use stacks::chainstate::stacks::{ StacksBlock, TransactionPayload, StacksAddress, StacksTransactionSigner, StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload, TransactionAnchorMode};
use stacks::chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash};
use stacks::chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    BlockstackOperationType,
};
use stacks::core::mempool::MemPoolDB;
use stacks::net::{ p2p::PeerNetwork, Error as NetError, db::{ PeerDB, LocalPeer }, relay::Relayer };
use stacks::net::dns::DNSResolver;
use stacks::util::vrf::VRFPublicKey;
use stacks::util::get_epoch_time_secs;
use stacks::util::strings::UrlString;
use stacks::net::NetworkResult;

use std::sync::mpsc::{channel, Sender, Receiver};

pub const TESTNET_CHAIN_ID: u32 = 0x00000000;
pub const TESTNET_PEER_VERSION: u32 = 0xdead1010;

#[derive(Debug, Clone)]
pub struct ChainTip {
    pub metadata: StacksHeaderInfo,
    pub block: StacksBlock,
    pub receipts: Vec<StacksTransactionReceipt>,
}

impl ChainTip {

    pub fn genesis() -> ChainTip {
        ChainTip {
            metadata: StacksHeaderInfo::genesis(),
            block: StacksBlock::genesis(),
            receipts: vec![]
        }
    }
}

#[derive(Clone)]
struct RegisteredKey {
    block_height: u16,
    op_vtxindex: u16,
    vrf_public_key: VRFPublicKey,
}

enum RelayerDirective {
    HandleNetResult(NetworkResult),
    ProcessTenure(StacksBlock, Vec<StacksMicroblock>, BurnchainHeaderHash, BurnchainHeaderHash)
}

/// Node is a structure modelising an active node working on the stacks chain.
pub struct Node {
    pub chain_state: StacksChainState,
    pub config: Config,
    active_registered_key: Option<RegisteredKey>,
    bootstraping_chain: bool,
    pub burnchain_tip: Option<BurnchainTip>,
    pub chain_tip: Option<ChainTip>,
    keychain: Keychain,
    last_sortitioned_block: Option<BurnchainTip>,
    nonce: u64,

    // refactoring this struct and the run_loops so that this doesn't
    // need to be an option, but is rather initialized on instantiation
    // would be a good idea.
    relay_channel: Option<Sender<RelayerDirective>>,
    dispatcher_channel: Sender<(StacksHeaderInfo, Vec<StacksTransactionReceipt>)>,
}

fn spawn_peer(mut this: PeerNetwork, p2p_sock: &SocketAddr, rpc_sock: &SocketAddr,
              burn_db_path: String, stacks_chainstate_path: String, 
              poll_timeout: u64, relay_channel: Sender<RelayerDirective>) -> Result<JoinHandle<()>, NetError> {
    this.bind(p2p_sock, rpc_sock).unwrap();
    let (mut dns_resolver, mut dns_client) = DNSResolver::new(5);
    let mut burndb = BurnDB::open(&burn_db_path, true)
        .map_err(NetError::DBError)?;

    let mut chainstate = StacksChainState::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(|e| NetError::ChainstateError(e.to_string()))?;
    
    let mut mem_pool = MemPoolDB::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(NetError::DBError)?;

    let server_thread = thread::spawn(move || {
        loop {
            let network_result = this.run(&mut burndb, &mut chainstate, &mut mem_pool, None, poll_timeout)
                .unwrap();

            if let Err(e) = relay_channel.send(RelayerDirective::HandleNetResult(network_result)) {
                info!("Relayer hang up with p2p channel: {}", e);
                break;
            }
        }
    });

    let jh = thread::spawn(move || {
        dns_resolver.thread_main();
    });

    Ok(server_thread)
}

fn spawn_miner_relayer(mut relayer: Relayer, local_peer: LocalPeer,
                       burn_db_path: String, stacks_chainstate_path: String, 
                       relay_channel: Receiver<RelayerDirective>, dispatcher_channel: Sender<(StacksHeaderInfo, Vec<StacksTransactionReceipt>)>) -> Result<(), NetError> {
    // Note: the relayer is *the* block processor, it is responsible for writes to the chainstate --
    //   no other codepaths should be writing once this is spawned.
    //
    // the relayer _should not_ be modifying the burndb,
    //   however, it needs a mut reference to create read TXs.
    //   should address via #1449
    let mut burndb = BurnDB::open(&burn_db_path, true)
        .map_err(NetError::DBError)?;

    let mut chainstate = StacksChainState::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(|e| NetError::ChainstateError(e.to_string()))?;
    
    let mut mem_pool = MemPoolDB::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(NetError::DBError)?;

    let relayer_thread = thread::spawn(move || {
        while let Ok(mut directive) = relay_channel.recv() {
            match directive {
                RelayerDirective::HandleNetResult(ref mut net_result) => {
                    let block_receipts = relayer.process_network_result(&local_peer, net_result,
                                                                        &mut burndb, &mut chainstate, &mut mem_pool)
                        .expect("BUG: failure processing network results");

                    for (stacks_header, tx_receipts) in block_receipts {
                        if let Err(e) = dispatcher_channel.send((stacks_header, tx_receipts)) {
                            info!("Event dispatcher hang up with p2p channel: {}", e);
                            break;
                        }
                    }
                },
                RelayerDirective::ProcessTenure(anchored_block, microblocks, burn_header, parent_burn_header) => {
                    let (stacks_header, _) = 
                        Node::inner_process_tenure(&anchored_block, &burn_header, &parent_burn_header, microblocks,
                                                   &mut burndb, &mut chainstate, &dispatcher_channel);
                    let blocks_available = Relayer::load_blocks_available_data(&mut burndb, vec![stacks_header.burn_header_hash])
                        .expect("Failed to obtain block information for a block we mined.");
                    if let Err(e) = relayer.advertize_blocks(blocks_available) {
                        warn!("Failed to advertise new block: {}", e);
                    }
                },
            }
        }
    });

    Ok(())
}

fn spawn_dispatcher(blocks_path: String, mut event_dispatcher: EventDispatcher,
                    dispatcher_channel: Receiver<(StacksHeaderInfo, Vec<StacksTransactionReceipt>)>) {
    thread::spawn(move || {
        while let Ok((metadata, receipts)) = dispatcher_channel.recv() {
            let block = {
                let block_path = StacksChainState::get_block_path(
                    &blocks_path, 
                    &metadata.burn_header_hash, 
                    &metadata.anchored_header.block_hash()).unwrap();
                StacksChainState::consensus_load(&block_path).unwrap()
            };

            let chain_tip = ChainTip {
                metadata,
                block,
                receipts
            };

            event_dispatcher.process_chain_tip(&chain_tip);
        }
    });
}

impl Node {

    /// Instantiate and initialize a new node, given a config
    pub fn new<F>(config: Config, boot_block_exec: F) -> Self
    where F: FnOnce(&mut ClarityTx) -> () {

        let keychain = Keychain::default(config.node.seed.clone());

        let initial_balances = config.initial_balances.iter().map(|e| (e.address.clone(), e.amount)).collect();

        let chain_state = match StacksChainState::open_and_exec(
            false, 
            TESTNET_CHAIN_ID, 
            &config.get_chainstate_path(), 
            Some(initial_balances), 
            boot_block_exec) {
            Ok(res) => res,
            Err(err) => panic!("Error while opening chain state at path {}: {:?}", config.get_chainstate_path(), err)
        };

        let (dispatcher_channel, dispatch_recv) = channel();
        let mut event_dispatcher = EventDispatcher::new();
        for observer in config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }
        let blocks_path = chain_state.blocks_path.clone();
        spawn_dispatcher(blocks_path, event_dispatcher, dispatch_recv);

        Self {
            active_registered_key: None,
            bootstraping_chain: false,
            chain_state,
            chain_tip: None,
            keychain,
            last_sortitioned_block: None,
            config,
            burnchain_tip: None,
            nonce: 0,
            relay_channel: None,
            dispatcher_channel,
        }
    }

    pub fn init_and_sync(config: Config, burnchain_controller: &mut Box<dyn BurnchainController>) -> Node {
        
        let burnchain_tip = burnchain_controller.get_chain_tip();

        let keychain = Keychain::default(config.node.seed.clone());

        let chainstate_path = config.get_chainstate_path();

        let chain_state = match StacksChainState::open(
            false, 
            TESTNET_CHAIN_ID, 
            &chainstate_path) {
            Ok(x) => x,
            Err(_e) => {
                panic!()
            },
        };

        let (dispatcher_channel, dispatch_recv) = channel();
        let mut event_dispatcher = EventDispatcher::new();
        for observer in config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }
        let blocks_path = chain_state.blocks_path.clone();
        spawn_dispatcher(blocks_path, event_dispatcher, dispatch_recv);

        let mut node = Node {
            active_registered_key: None,
            bootstraping_chain: false,
            chain_state,
            chain_tip: None,
            keychain,
            last_sortitioned_block: None,
            config,
            burnchain_tip: None,
            nonce: 0,
            relay_channel: None,
            dispatcher_channel,
        };

        node.spawn_node_threads();

        loop {
            if let Ok(Some(ref chain_tip)) = node.chain_state.get_stacks_chain_tip() {
                if chain_tip.burn_header_hash == burnchain_tip.block_snapshot.burn_header_hash {
                    info!("Syncing Stacks blocks - completed");
                    break;
                } else {
                    info!("Syncing Stacks blocks - received block #{}", chain_tip.height);
                }
            } else {
                info!("Syncing Stacks blocks - unable to progress");
            }
            thread::sleep(time::Duration::from_secs(5));
        }
        node
    }

    pub fn spawn_node_threads(&mut self) {
        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let mut burndb = BurnDB::open(&self.config.get_burn_db_file_path(), true)
            .expect("Error while instantiating burnchain db");

        let burnchain = Burnchain::new(
            &self.config.get_burn_db_path(),
            &self.config.burnchain.chain,
            "regtest").expect("Error while instantiating burnchain");

        let view = {
            let mut tx = burndb.tx_begin().unwrap();
            BurnDB::get_burnchain_view(&mut tx, &burnchain).unwrap()
        };

        // create a new peerdb
        let data_url = UrlString::try_from(format!("http://{}", self.config.node.rpc_bind)).unwrap();

        let mut initial_neighbors = vec![];
        if let Some(ref bootstrap_node) = self.config.node.bootstrap_node {
            initial_neighbors.push(bootstrap_node.clone());
        }

        println!("BOOTSTRAP WITH {:?}", initial_neighbors);

        let p2p_sock: SocketAddr = self.config.node.p2p_bind.parse()
            .expect(&format!("Failed to parse socket: {}", &self.config.node.p2p_bind));
        let rpc_sock = self.config.node.rpc_bind.parse()
            .expect(&format!("Failed to parse socket: {}", &self.config.node.rpc_bind));

        let peerdb = PeerDB::connect(
            &self.config.get_peer_db_path(), 
            true, 
            TESTNET_CHAIN_ID, 
            burnchain.network_id, 
            self.config.connection_options.private_key_lifetime.clone(),
            p2p_sock.port(),
            data_url.clone(),
            &vec![], 
            Some(&initial_neighbors)).unwrap();

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer")
        };

        let blocks_paths = self.chain_state.blocks_path.clone();

        // now we're ready to instantiate a p2p network object, the relayer, and the event dispatcher

        let mut p2p_net = PeerNetwork::new(peerdb, local_peer.clone(), TESTNET_PEER_VERSION, burnchain, view,
                                           self.config.connection_options.clone());
        let relayer = Relayer::from_p2p(&mut p2p_net);

        // we need to set up our communication channels.

        let (relay_send, relay_recv) = channel();

        self.relay_channel = Some(relay_send.clone());

        spawn_peer(
            p2p_net, 
            &p2p_sock, 
            &rpc_sock, 
            self.config.get_burn_db_file_path(),
            self.config.get_chainstate_path(), 
            5000, relay_send).unwrap();

        spawn_miner_relayer(relayer, local_peer,
                            self.config.get_burn_db_file_path(),
                            self.config.get_chainstate_path(),
                            relay_recv, self.dispatcher_channel.clone());

        info!("Bound HTTP server on: {}", &self.config.node.rpc_bind);
        info!("Bound P2P server on: {}", &self.config.node.p2p_bind);
    }
    
    pub fn setup(&mut self, burnchain_controller: &mut Box<dyn BurnchainController>) {
        // Register a new key
        let burnchain_tip = burnchain_controller.get_chain_tip();
        let vrf_pk = self.keychain.rotate_vrf_keypair(burnchain_tip.block_snapshot.block_height);
        let consensus_hash = burnchain_tip.block_snapshot.consensus_hash; 
        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, &consensus_hash);
        let mut op_signer = self.keychain.generate_op_signer();
        burnchain_controller.submit_operation(key_reg_op, &mut op_signer);
    }

    /// Process an state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    pub fn process_burnchain_state(&mut self, burnchain_tip: &BurnchainTip) -> (Option<BurnchainTip>, bool) {
        let mut new_key = None;
        let mut last_sortitioned_block = None; 
        let mut won_sortition = false;
        let ops = &burnchain_tip.state_transition.accepted_ops;
        
        for op in ops.iter() {
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
                    if op.txid == burnchain_tip.block_snapshot.winning_block_txid {
                        last_sortitioned_block = Some(burnchain_tip.clone());

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
        self.burnchain_tip = Some(burnchain_tip.clone());

        (self.last_sortitioned_block.clone(), won_sortition)
    }

    /// Prepares the node to run a tenure consisting in bootstraping the chain.
    /// 
    /// Will internally call initiate_new_tenure().
    pub fn initiate_genesis_tenure(&mut self, burnchain_tip: &BurnchainTip) -> Option<Tenure> {
        // Set the `bootstraping_chain` flag, that will be unset once the 
        // bootstraping tenure ran successfully (process_tenure).
        self.bootstraping_chain = true;

        self.last_sortitioned_block = Some(burnchain_tip.clone());

        self.initiate_new_tenure()
    }

    /// Constructs and returns an instance of Tenure, that can be run
    /// on an isolated thread and discarded or canceled without corrupting the
    /// chain state of the node.
    pub fn initiate_new_tenure(&mut self) -> Option<Tenure> {
        // Get the latest registered key
        let registered_key = match &self.active_registered_key {
            None => {
                // We're continuously registering new keys, as such, this branch
                // should be unreachable.
                return None;
            },
            Some(ref key) => key,
        };

        let block_to_build_upon = match &self.last_sortitioned_block {
            None => unreachable!(),
            Some(block) => block.clone()
        };

        // Generates a proof out of the sortition hash provided in the params.
        let vrf_proof = self.keychain.generate_proof(
            &registered_key.vrf_public_key, 
            block_to_build_upon.block_snapshot.sortition_hash.as_bytes()).unwrap();

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        // Get the stack's chain tip
        let chain_tip = match self.bootstraping_chain {
            true => ChainTip::genesis(),
            false => match &self.chain_tip {
                Some(chain_tip) => chain_tip.clone(),
                None => unreachable!()
            }
        };

        let mem_pool = MemPoolDB::open(false, TESTNET_CHAIN_ID, &self.chain_state.root_path).expect("FATAL: failed to open mempool");

        // Construct the coinbase transaction - 1st txn that should be handled and included in 
        // the upcoming tenure.
        let coinbase_tx = self.generate_coinbase_tx();

        let burn_fee_cap = self.config.burnchain.burn_fee_cap;

        // Construct the upcoming tenure
        let tenure = Tenure::new(
            chain_tip, 
            coinbase_tx,
            self.config.clone(),
            mem_pool,
            microblock_secret_key, 
            block_to_build_upon,
            vrf_proof,
            burn_fee_cap);

        Some(tenure)
    }

    pub fn commit_artifacts(
        &mut self, 
        anchored_block_from_ongoing_tenure: &StacksBlock, 
        burnchain_tip: &BurnchainTip,
        burnchain_controller: &mut Box<dyn BurnchainController>,
        burn_fee: u64) 
    {
        if self.active_registered_key.is_some() {
            let registered_key = self.active_registered_key.clone().unwrap();

            let vrf_proof = self.keychain.generate_proof(
                &registered_key.vrf_public_key, 
                burnchain_tip.block_snapshot.sortition_hash.as_bytes()).unwrap();

            let op = self.generate_block_commit_op(
                anchored_block_from_ongoing_tenure.header.block_hash(),
                burn_fee,
                &registered_key, 
                &burnchain_tip,
                VRFSeed::from_proof(&vrf_proof));

                let mut op_signer = self.keychain.generate_op_signer();
                burnchain_controller.submit_operation(op, &mut op_signer);
        }
        
        // Naive implementation: we keep registering new keys
        let burnchain_tip = burnchain_controller.get_chain_tip();
        let vrf_pk = self.keychain.rotate_vrf_keypair(burnchain_tip.block_snapshot.block_height);
        let burnchain_tip_consensus_hash = self.burnchain_tip.as_ref().unwrap().block_snapshot.consensus_hash;
        let op = self.generate_leader_key_register_op(vrf_pk, &burnchain_tip_consensus_hash);

        let mut one_off_signer = self.keychain.generate_op_signer();
        burnchain_controller.submit_operation(op, &mut one_off_signer);
    }


    /// returns _false_ if the relayer hung up the channel.
    pub fn relayer_process_tenure(&self,
        anchored_block: StacksBlock,
        burn_header_hash: BurnchainHeaderHash,
        parent_burn_header_hash: BurnchainHeaderHash,
        microblocks: Vec<StacksMicroblock>) -> bool {

        self.relay_channel.as_ref().expect("Tried to process a tenure before Relay/Miner thread spawned")
            .send(RelayerDirective::ProcessTenure(
                anchored_block, microblocks, burn_header_hash, parent_burn_header_hash))
            .is_ok()
    }

    pub fn process_tenure(&mut self, 
        anchored_block: &StacksBlock, 
        burn_header_hash: &BurnchainHeaderHash, 
        parent_burn_header_hash: &BurnchainHeaderHash, 
        microblocks: Vec<StacksMicroblock>, 
        burn_db: &mut BurnDB) -> ChainTip {
        let (metadata, receipts) = 
            Node::inner_process_tenure(anchored_block, burn_header_hash, parent_burn_header_hash,
                                       microblocks, burn_db, &mut self.chain_state,
                                       &self.dispatcher_channel);

        let block = {
            let block_path = StacksChainState::get_block_path(
                &self.chain_state.blocks_path, 
                &metadata.burn_header_hash, 
                &metadata.anchored_header.block_hash()).unwrap();
            StacksChainState::consensus_load(&block_path).unwrap()
        };

        let chain_tip = ChainTip {
            metadata,
            block,
            receipts
        };

        self.chain_tip = Some(chain_tip.clone());

        // Unset the `bootstraping_chain` flag.
        if self.bootstraping_chain {
            self.bootstraping_chain = false;
        }

        chain_tip
    }

    /// Process artifacts from the tenure.
    /// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
    fn inner_process_tenure(
        anchored_block: &StacksBlock, 
        burn_header_hash: &BurnchainHeaderHash, 
        parent_burn_header_hash: &BurnchainHeaderHash, 
        microblocks: Vec<StacksMicroblock>, 
        burn_db: &mut BurnDB,
        chain_state: &mut StacksChainState,
        dispatcher_channel: &Sender<(StacksHeaderInfo, Vec<StacksTransactionReceipt>)>) -> (StacksHeaderInfo, Vec<StacksTransactionReceipt>) {
        {
            let mut tx = burn_db.tx_begin().unwrap();

            // Preprocess the anchored block
            chain_state.preprocess_anchored_block(
                &mut tx,
                &burn_header_hash,
                get_epoch_time_secs(),
                &anchored_block, 
                &parent_burn_header_hash).unwrap();

            // Preprocess the microblocks
            for microblock in microblocks.iter() {
                let res = chain_state.preprocess_streamed_microblock(
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
            match chain_state.process_blocks(1) {
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
        let receipts = processed_block.1;
        let metadata = processed_block.0;

        dispatcher_channel.send((metadata.clone(), receipts.clone()));
        (metadata, receipts)
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
                                burnchain_tip: &BurnchainTip,
                                vrf_seed: VRFSeed) -> BlockstackOperationType {

        let winning_tx_vtindex = match (burnchain_tip.get_winning_tx_index(), burnchain_tip.block_snapshot.total_burn) {
            (Some(winning_tx_id), _) => winning_tx_id,
            (None, 0) => 0,
            _ => unreachable!()
        };

        let (parent_block_ptr, parent_vtxindex) = match self.bootstraping_chain {
            true => (0, 0), // parent_block_ptr and parent_vtxindex should both be 0 on block #1
            false => (burnchain_tip.block_snapshot.block_height as u32, winning_tx_vtindex as u16)
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
