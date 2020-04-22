use super::{Keychain, Config, Tenure, BurnchainController, BurnchainTip, EventDispatcher};
use crate::config::HELIUM_BLOCK_LIMIT;

use std::convert::TryFrom;
use std::{thread, thread::JoinHandle};
use std::net::SocketAddr;

use stacks::burnchains::{Burnchain, BurnchainHeaderHash, Txid, PublicKey};
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
use stacks::chainstate::stacks::{StacksBlockBuilder};
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::stacks::{Error as ChainstateError};
use stacks::chainstate::stacks::StacksPublicKey;

use stacks::core::mempool::MemPoolDB;
use stacks::net::{ p2p::PeerNetwork, Error as NetError, db::{ PeerDB, LocalPeer }, relay::Relayer };
use stacks::net::dns::DNSResolver;
use stacks::util::vrf::VRFPublicKey;
use stacks::util::get_epoch_time_secs;
use stacks::util::strings::UrlString;
use stacks::util::hash::Hash160;
use stacks::net::NetworkResult;
use std::sync::mpsc::{sync_channel, TrySendError, SyncSender, Receiver};
use crate::burnchains::bitcoin_regtest_controller::BitcoinRegtestController;
use crate::ChainTip;

use stacks::burnchains::BurnchainSigner;

pub const TESTNET_CHAIN_ID: u32 = 0x00000000;
pub const TESTNET_PEER_VERSION: u32 = 0xdead1010;
pub const RELAYER_MAX_BUFFER: usize = 100;

#[derive(Clone)]
struct RegisteredKey {
    block_height: u16,
    op_vtxindex: u16,
    vrf_public_key: VRFPublicKey,
}

enum RelayerDirective {
    HandleNetResult(NetworkResult),
    ProcessTenure(BurnchainHeaderHash, BurnchainHeaderHash, BlockHeaderHash),
    RunTenure(RegisteredKey, (BlockSnapshot, u32)),
}


pub struct InitializedNeonNode {
    relay_channel: SyncSender<RelayerDirective>,
    active_registered_key: Option<RegisteredKey>,
    burnchain_signer: BurnchainSigner,
    // TODO: what about handling blocks _without_ sortitions?
    // store the last sortitioned block, and it's winner vtx
    last_sortitioned_block: Option<(BlockSnapshot, u32)>,
}

pub struct NeonGenesisNode {
    pub chain_state: StacksChainState,
    pub config: Config,
    active_registered_key: Option<RegisteredKey>,
    pub burnchain_tip: Option<BurnchainTip>,
    keychain: Keychain,
    event_dispatcher: EventDispatcher,
    last_sortitioned_block: Option<BurnchainTip>,
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
    dispatcher: &mut EventDispatcher) -> Result<(StacksHeaderInfo, Vec<StacksTransactionReceipt>), ChainstateError> {
    {
        let mut tx = burn_db.tx_begin().unwrap();

        // Preprocess the anchored block
        chain_state.preprocess_anchored_block(
            &mut tx,
            &burn_header_hash,
            get_epoch_time_secs(),
            &anchored_block, 
            &parent_burn_header_hash)?;

        // Preprocess the microblocks
        for microblock in microblocks.iter() {
            let res = chain_state.preprocess_streamed_microblock(
                &burn_header_hash, 
                &anchored_block.block_hash(), 
                microblock)?;
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

    dispatcher_announce(&chain_state.blocks_path, dispatcher, metadata.clone(), receipts.clone());
    Ok((metadata, receipts))
}

fn inner_generate_coinbase_tx(keychain: &mut Keychain, nonce: u64) -> StacksTransaction {
    let mut tx_auth = keychain.get_transaction_auth().unwrap();
    tx_auth.set_origin_nonce(nonce);

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet, 
        tx_auth, 
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
    tx.chain_id = TESTNET_CHAIN_ID;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    keychain.sign_as_origin(&mut tx_signer);

    tx_signer.get_tx().unwrap()                       
}

/// Constructs and returns a LeaderKeyRegisterOp out of the provided params
fn inner_generate_leader_key_register_op(address: StacksAddress, vrf_public_key: VRFPublicKey, consensus_hash: &ConsensusHash) -> BlockstackOperationType {
    BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
        public_key: vrf_public_key,
        memo: vec![],
        address,
        consensus_hash: consensus_hash.clone(),
        vtxindex: 0,
        txid: Txid([0u8; 32]),
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),        
    })
}

/// Constructs and returns a LeaderBlockCommitOp out of the provided params
fn inner_generate_block_commit_op(
    input: BurnchainSigner,
    block_header_hash: BlockHeaderHash,
    burn_fee: u64, 
    key: &RegisteredKey,
    burnchain_tip: &BlockSnapshot,
    winning_vtx_index: Option<u32>,
    vrf_seed: VRFSeed,
    is_bootstrap_commit: bool) -> BlockstackOperationType {

    let (parent_block_ptr, parent_vtxindex) =
        if is_bootstrap_commit {
            (0, 0)
        } else {
            let winning_tx_vtindex = match (winning_vtx_index, burnchain_tip.total_burn) {
                (Some(winning_tx_id), _) => winning_tx_id,
                (None, 0) => 0,
                _ => unreachable!()
            };

            (burnchain_tip.block_height as u32, winning_tx_vtindex as u16)
        };
    BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
        block_header_hash,
        burn_fee,
        input,
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

fn spawn_peer(mut this: PeerNetwork, p2p_sock: &SocketAddr, rpc_sock: &SocketAddr,
              config: Config,
              poll_timeout: u64, relay_channel: SyncSender<RelayerDirective>) -> Result<JoinHandle<()>, NetError> {

    let burn_db_path = config.get_burn_db_file_path();
    let stacks_chainstate_path = config.get_chainstate_path();
    let block_limit = config.block_limit;

    this.bind(p2p_sock, rpc_sock).unwrap();
    let (mut dns_resolver, mut dns_client) = DNSResolver::new(5);
    let mut burndb = BurnDB::open(&burn_db_path, true)
        .map_err(NetError::DBError)?;

    let mut chainstate = StacksChainState::open_with_block_limit(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path, block_limit)
        .map_err(|e| NetError::ChainstateError(e.to_string()))?;
    
    let mut mem_pool = MemPoolDB::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(NetError::DBError)?;

    let server_thread = thread::spawn(move || {
        loop {
            let network_result = this.run(&mut burndb, &mut chainstate, &mut mem_pool, Some(&mut dns_client), poll_timeout)
                .unwrap();

            if let Err(e) = relay_channel.try_send(RelayerDirective::HandleNetResult(network_result)) {
                match e {
                    TrySendError::Full(_) => {
                        warn!("Relayer buffer is full, dropping NetworkHandle");
                    }
                    TrySendError::Disconnected(_) => {
                        info!("Relayer hang up with p2p channel");
                        break;
                    }
                }
            }
        }
    });

    let _jh = thread::spawn(move || {
        dns_resolver.thread_main();
    });

    Ok(server_thread)
}

fn spawn_miner_relayer(mut relayer: Relayer, local_peer: LocalPeer,
                       config: Config, mut keychain: Keychain,
                       burn_db_path: String, stacks_chainstate_path: String, 
                       relay_channel: Receiver<RelayerDirective>,
                       mut event_dispatcher: EventDispatcher) -> Result<(), NetError> {
    // Note: the relayer is *the* block processor, it is responsible for writes to the chainstate --
    //   no other codepaths should be writing once this is spawned.
    //
    // the relayer _should not_ be modifying the burndb,
    //   however, it needs a mut reference to create read TXs.
    //   should address via #1449
    let mut burndb = BurnDB::open(&burn_db_path, true)
        .map_err(NetError::DBError)?;

    let mut chainstate = StacksChainState::open_with_block_limit(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path, config.block_limit.clone())
        .map_err(|e| NetError::ChainstateError(e.to_string()))?;
    
    let mut mem_pool = MemPoolDB::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(NetError::DBError)?;

    let mut last_mined_block: Option<(BurnchainHeaderHash, StacksBlock)> = None;
    let burn_fee_cap = config.burnchain.burn_fee_cap;
    let mut bitcoin_controller = BitcoinRegtestController::new_dummy(config);


    let blocks_path = chainstate.blocks_path.clone();

    let _relayer_handle = thread::spawn(move || {
        while let Ok(mut directive) = relay_channel.recv() {
            match directive {
                RelayerDirective::HandleNetResult(ref mut net_result) => {
                    let block_receipts = relayer.process_network_result(&local_peer, net_result,
                                                                        &mut burndb, &mut chainstate, &mut mem_pool)
                        .expect("BUG: failure processing network results");

                    for (stacks_header, tx_receipts) in block_receipts {
                        dispatcher_announce(&blocks_path, &mut event_dispatcher, stacks_header, tx_receipts);
                    }
                },
                RelayerDirective::ProcessTenure(burn_header_hash, parent_burn_header_hash, block_header_hash) => {
                    if let Some((mined_burn_hh, mined_block)) = last_mined_block.take() {
                        if mined_block.block_hash() == block_header_hash && parent_burn_header_hash == mined_burn_hh {
                            // we won!
                            info!("Won sortition! stacks_header={}, burn_header={}",
                                  block_header_hash,
                                  mined_burn_hh);

                            let (stacks_header, _) = 
                                match inner_process_tenure(&mined_block, &burn_header_hash, &parent_burn_header_hash,
                                                           vec![], // no microblocks for now...
                                                           &mut burndb, &mut chainstate, &mut event_dispatcher) {
                                    Ok(x) => x,
                                    Err(e) => {
                                        warn!("Error processing my tenure, bad block produced: {}", e);
                                        continue;
                                    }
                                };


                            let blocks_available = Relayer::load_blocks_available_data(&mut burndb, vec![stacks_header.burn_header_hash])
                                .expect("Failed to obtain block information for a block we mined.");
                            if let Err(e) = relayer.advertize_blocks(blocks_available) {
                                warn!("Failed to advertise new block: {}", e);
                            }
                        } else {
                            warn!("Did not win sortition, my blocks [burn_hash= {}, block_hash= {}], their blocks [par_burn_hash= {}, burn_hash= {}, block_hash ={}]",
                                  mined_burn_hh, mined_block.block_hash(), parent_burn_header_hash, burn_header_hash, block_header_hash);
                        }
                    }
                },
                RelayerDirective::RunTenure(registered_key, (last_sortitioned_block, winning_vtx)) => {
                    last_mined_block = InitializedNeonNode::relayer_run_tenure(
                        registered_key, &mut chainstate, last_sortitioned_block, winning_vtx,
                        &mut keychain, &mut mem_pool, burn_fee_cap, &mut bitcoin_controller)
                },
            }
        }
    });

    Ok(())
}

fn dispatcher_announce(blocks_path: &str, event_dispatcher: &mut EventDispatcher,
                       metadata: StacksHeaderInfo, receipts: Vec<StacksTransactionReceipt>) {
    let block = {
        let block_path = StacksChainState::get_block_path(
            blocks_path, 
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

impl InitializedNeonNode {
    fn new(config: Config, keychain: Keychain, event_dispatcher: EventDispatcher,
           last_sortitioned_block: Option<BurnchainTip>, registered_key: Option<RegisteredKey>) -> InitializedNeonNode {
        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let mut burndb = BurnDB::open(&config.get_burn_db_file_path(), true)
            .expect("Error while instantiating burnchain db");

        let burnchain = Burnchain::new(
            &config.get_burn_db_path(),
            &config.burnchain.chain,
            "regtest").expect("Error while instantiating burnchain");

        let view = {
            let mut tx = burndb.tx_begin().unwrap();
            BurnDB::get_burnchain_view(&mut tx, &burnchain).unwrap()
        };

        // create a new peerdb
        let data_url = UrlString::try_from(format!("{}", &config.node.data_url)).unwrap();

        let mut initial_neighbors = vec![];
        if let Some(ref bootstrap_node) = &config.node.bootstrap_node {
            initial_neighbors.push(bootstrap_node.clone());
        }

        println!("BOOTSTRAP WITH {:?}", initial_neighbors);

        let p2p_sock: SocketAddr = config.node.p2p_bind.parse()
            .expect(&format!("Failed to parse socket: {}", &config.node.p2p_bind));
        let rpc_sock = config.node.rpc_bind.parse()
            .expect(&format!("Failed to parse socket: {}", &config.node.rpc_bind));

        let peerdb = PeerDB::connect(
            &config.get_peer_db_path(), 
            true, 
            TESTNET_CHAIN_ID, 
            burnchain.network_id, 
            config.connection_options.private_key_lifetime.clone(),
            p2p_sock.port(),
            data_url.clone(),
            config.node.local_peer_seed.clone(),
            &vec![], 
            Some(&initial_neighbors)).unwrap();

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer")
        };

        // now we're ready to instantiate a p2p network object, the relayer, and the event dispatcher
        let mut p2p_net = PeerNetwork::new(peerdb, local_peer.clone(), TESTNET_PEER_VERSION, burnchain, view,
                                           config.connection_options.clone());

        // setup the relayer channel
        let (relay_send, relay_recv) = sync_channel(RELAYER_MAX_BUFFER);

        let burnchain_signer = keychain.get_burnchain_signer();
        let relayer = Relayer::from_p2p(&mut p2p_net);

        spawn_miner_relayer(relayer, local_peer,
                            config.clone(), keychain,
                            config.get_burn_db_file_path(),
                            config.get_chainstate_path(),
                            relay_recv, event_dispatcher)
            .expect("Failed to initialize mine/relay thread");

        spawn_peer(p2p_net, &p2p_sock, &rpc_sock,
                   config.clone(), 5000, relay_send.clone())
            .expect("Failed to initialize mine/relay thread");


        info!("Bound HTTP server on: {}", &config.node.rpc_bind);
        info!("Bound P2P server on: {}", &config.node.p2p_bind);

        let last_sortitioned_block = last_sortitioned_block.map(
            |block| {
                let vtx = block.get_winning_tx_index().unwrap();
                (block.block_snapshot, vtx)
            });

        InitializedNeonNode {
            relay_channel: relay_send,
            last_sortitioned_block,
            burnchain_signer,
            active_registered_key: registered_key,
        }
    }


    /// Tell the relayer to fire off a tenure and a block commit op.
    pub fn relayer_issue_tenure(&self) -> bool {
        if let Some(key) = self.active_registered_key.clone() {
            if let Some(burnchain_tip) = self.last_sortitioned_block.clone() {
            self.relay_channel
                .send(RelayerDirective::RunTenure(key, burnchain_tip))
                .is_ok()
            } else {
                warn!("Skipped tenure because did not know the last sortition block. Seems bad.");
                true
            }
        } else {
            warn!("Skipped tenure because no active VRF key");
            true
        }
    }

    /// Notify the relayer of a sortition, telling it to process the block
    ///  and advertize it if it was mined by the node.
    /// returns _false_ if the relayer hung up the channel.
    pub fn relayer_sortition_notify(&self) -> bool {
        if let Some((ref snapshot, _)) = &self.last_sortitioned_block {
            self.relay_channel
                .send(RelayerDirective::ProcessTenure(
                    snapshot.burn_header_hash.clone(), 
                    snapshot.parent_burn_header_hash.clone(),
                    snapshot.winning_stacks_block_hash.clone()))
                .is_ok()
        } else {
            true
        }
    }


    fn relayer_run_tenure(registered_key: RegisteredKey,
                          chain_state: &mut StacksChainState,
                          burn_block: BlockSnapshot,
                          burn_block_winner_vtx: u32,
                          keychain: &mut Keychain,
                          mem_pool: &mut MemPoolDB,
                          burn_fee_cap: u64,
                          bitcoin_controller: &mut BitcoinRegtestController) -> Option<(BurnchainHeaderHash, StacksBlock)> {

        let stacks_tip = match chain_state.get_stacks_chain_tip().unwrap() {
            Some(x) => x,
            None => {
                warn!("Could not mine new tenure, since no chain tip known.");
                return None
            }
        };

        let stacks_tip_header = match StacksChainState::get_anchored_block_header_info(
            &chain_state.headers_db, &stacks_tip.burn_header_hash, &stacks_tip.anchored_block_hash).unwrap() {
            Some(x) => x,
            None => {
                warn!("Could not mine new tenure, since could not find header for known chain tip.");
                return None
            }
        };

        debug!("Mining tenure on burn_block: {}, stacks tip burn_header_hash: {}",
              &burn_block.burn_header_hash,
              &stacks_tip.burn_header_hash);

        // Generates a proof out of the sortition hash provided in the params.
        let vrf_proof = keychain.generate_proof(
            &registered_key.vrf_public_key, 
            burn_block.sortition_hash.as_bytes()).unwrap();

        debug!("Generated VRF Proof: {} over {} with key {}",
              vrf_proof.to_hex(),
              &burn_block.sortition_hash,
              &registered_key.vrf_public_key.to_hex());

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_secret_key = keychain.rotate_microblock_keypair();
        let mblock_pubkey_hash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_secret_key).to_bytes());
        
        // make a coinbase
        let principal = keychain.origin_address().unwrap().into();
        let nonce = {
            let account = chain_state.with_read_only_clarity_tx(&stacks_tip.burn_header_hash, &stacks_tip.anchored_block_hash, |conn| {
                StacksChainState::get_account(conn, &principal)
            });
            account.nonce
        };
        
        let coinbase_tx = inner_generate_coinbase_tx(keychain, nonce);

        let anchored_block = StacksBlockBuilder::build_anchored_block(
            chain_state, mem_pool, &stacks_tip_header, burn_block.total_burn,
            vrf_proof.clone(), mblock_pubkey_hash, &coinbase_tx, HELIUM_BLOCK_LIMIT.clone()).unwrap();

        info!("Finish tenure: {}", anchored_block.block_hash());

        // let's commit
        let op = inner_generate_block_commit_op(
            keychain.get_burnchain_signer(),
            anchored_block.block_hash(),
            burn_fee_cap,
            &registered_key, 
            &burn_block,
            Some(burn_block_winner_vtx),
            VRFSeed::from_proof(&vrf_proof),
            false);
        let mut op_signer = keychain.generate_op_signer();
        bitcoin_controller.submit_operation(op, &mut op_signer);

        let vrf_pk = keychain.rotate_vrf_keypair(burn_block.block_height);
        let burnchain_tip_consensus_hash = burn_block.consensus_hash;
        let op = inner_generate_leader_key_register_op(keychain.get_address(), vrf_pk, &burnchain_tip_consensus_hash);

        let mut one_off_signer = keychain.generate_op_signer();
        bitcoin_controller.submit_operation(op, &mut one_off_signer);

        Some((burn_block.burn_header_hash, anchored_block))
    }

    /// Process an state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    pub fn process_burnchain_state(&mut self, burndb: &mut BurnDB, burn_hash: &BurnchainHeaderHash) -> (Option<BlockSnapshot>, bool) {
        let mut new_key = None;
        let mut last_sortitioned_block = None; 
        let mut won_sortition = false;

        let mut burn_tx = burndb.tx_begin()
            .unwrap();

        let block_snapshot = BurnDB::get_block_snapshot(&burn_tx, burn_hash)
            .expect("Failed to obtain block snapshot for processed burn block.")
            .expect("Failed to obtain block snapshot for processed burn block.");
        let block_height = block_snapshot.block_height;

        let block_commits = BurnDB::get_block_commits_by_block(&mut burn_tx, block_height, burn_hash)
            .expect("Unexpected BurnDB error fetching block commits");
        for op in block_commits.into_iter() {
            if op.txid == block_snapshot.winning_block_txid {
                last_sortitioned_block = Some((block_snapshot.clone(), op.vtxindex));
                // Release current registered key if leader won the sortition
                // This will trigger a new registration
                if op.input == self.burnchain_signer {
                    self.active_registered_key = None;
                    won_sortition = true;
                }    
            }            
        }

        let key_registers = BurnDB::get_leader_keys_by_block(&mut burn_tx, block_height, burn_hash)
            .expect("Unexpected BurnDB error fetching key registers");
        for op in key_registers.into_iter() {
            if op.address == Keychain::address_from_burnchain_signer(&self.burnchain_signer) {
                // Registered key has been mined
                new_key = Some(RegisteredKey {
                    vrf_public_key: op.public_key,
                    block_height: op.block_height as u16,
                    op_vtxindex: op.vtxindex as u16,
                });
            }
        }

        // no-op on UserBurnSupport ops are not supported / produced at this point.

        // Update the active key so we use the latest registered key.
        if new_key.is_some() {
            self.active_registered_key = new_key;
        }

        // Keep a pointer of the burnchain's chain tip.
        if last_sortitioned_block.is_none() {
            info!("No sortition in the block {}", burn_hash);
        } else {
            info!("Found sortition in the block {}", burn_hash);
            self.last_sortitioned_block = last_sortitioned_block.clone();
        }

        (last_sortitioned_block.map(|x| x.0), won_sortition)
    }

}

impl NeonGenesisNode {

    /// Instantiate and initialize a new node, given a config
    pub fn new<F>(config: Config, boot_block_exec: F) -> Self
    where F: FnOnce(&mut ClarityTx) -> () {

        let keychain = Keychain::default(config.node.seed.clone());

        info!("Begining Neon genesis node: miner address: {}", keychain.origin_address().unwrap());
        let initial_balances = config.initial_balances.iter().map(|e| (e.address.clone(), e.amount)).collect();

        let chain_state = match StacksChainState::open_and_exec(
            false, 
            TESTNET_CHAIN_ID, 
            &config.get_chainstate_path(), 
            Some(initial_balances), 
            boot_block_exec,
            config.block_limit.clone()) {
            Ok(res) => res,
            Err(err) => panic!("Error while opening chain state at path {}: {:?}", config.get_chainstate_path(), err)
        };

        let mut event_dispatcher = EventDispatcher::new();
        for observer in config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }

        Self {
            last_sortitioned_block: None,
            active_registered_key: None,
            chain_state,
            keychain,
            config,
            event_dispatcher,
            burnchain_tip: None,
        }
    }

    pub fn submit_vrf_key_operation(&mut self, burnchain_controller: &mut Box<dyn BurnchainController>) -> bool {
        // Register a new key
        let burnchain_tip = burnchain_controller.get_chain_tip();
        let vrf_pk = self.keychain.rotate_vrf_keypair(burnchain_tip.block_snapshot.block_height);
        let consensus_hash = burnchain_tip.block_snapshot.consensus_hash; 
        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, &consensus_hash);
        let mut op_signer = self.keychain.generate_op_signer();
        info!("Trying to submit VRF key registration");
        burnchain_controller.submit_operation(key_reg_op, &mut op_signer)
    }

    /// initiate the first tenure.
    /// Constructs and returns an instance of Tenure, that can be run
    /// on an isolated thread and discarded or canceled without corrupting the
    /// chain state of the node.
    pub fn initiate_genesis_tenure(&mut self, block_to_build_upon: &BurnchainTip) -> Option<Tenure> {
        let block_to_build_upon = block_to_build_upon.clone();
        // Get the latest registered key
        let registered_key = match &self.active_registered_key {
            None => {
                // We're continuously registering new keys, as such, this branch
                // should be unreachable.
                panic!("Failed to register initial VRF key");
            },
            Some(ref key) => key,
        };

        // Generates a proof out of the sortition hash provided in the params.
        let vrf_proof = self.keychain.generate_proof(
            &registered_key.vrf_public_key, 
            block_to_build_upon.block_snapshot.sortition_hash.as_bytes()).unwrap();

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_secret_key = self.keychain.rotate_microblock_keypair();

        // Get the stack's chain tip
        let chain_tip = ChainTip::genesis();

        let mem_pool = MemPoolDB::open(false, TESTNET_CHAIN_ID,
                                       &self.chain_state.root_path).expect("FATAL: failed to open mempool");

        // Construct the coinbase transaction - 1st txn that should be handled and included in 
        // the upcoming tenure.
        let coinbase_tx = inner_generate_coinbase_tx(&mut self.keychain, 0);

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

            let op = inner_generate_block_commit_op(
                self.keychain.get_burnchain_signer(),
                anchored_block_from_ongoing_tenure.header.block_hash(),
                burn_fee,
                &registered_key,
                &burnchain_tip.block_snapshot,
                None,
                VRFSeed::from_proof(&vrf_proof),
                true);

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

    pub fn process_tenure(&mut self, 
        anchored_block: &StacksBlock, 
        burn_header_hash: &BurnchainHeaderHash, 
        parent_burn_header_hash: &BurnchainHeaderHash, 
        microblocks: Vec<StacksMicroblock>, 
        burn_db: &mut BurnDB) -> ChainTip {
        let (metadata, receipts) = 
            inner_process_tenure(anchored_block, burn_header_hash, parent_burn_header_hash,
                                 microblocks, burn_db, &mut self.chain_state,
                                 &mut self.event_dispatcher)
            .expect("Failed to process tenure during genesis initialization");

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

        chain_tip
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

        // Keep a pointer of the burnchain's chain tip.
        self.burnchain_tip = Some(burnchain_tip.clone());
        self.last_sortitioned_block = last_sortitioned_block.clone();

        (last_sortitioned_block, won_sortition)
    }

    /// Prepares the node to run a tenure consisting in bootstraping the chain.
    /// 
    /// Will internally call initiate_new_tenure().

    /// Returns the Stacks address of the node
    pub fn get_address(&self) -> StacksAddress {
        self.keychain.get_address()
    }

    fn generate_leader_key_register_op(&mut self, vrf_public_key: VRFPublicKey, consensus_hash: &ConsensusHash) -> BlockstackOperationType {
        inner_generate_leader_key_register_op(self.keychain.get_address(), vrf_public_key, consensus_hash)
    }

    pub fn into_initialized_leader_node(self) -> InitializedNeonNode {
        let config = self.config;
        let keychain = self.keychain;
        let event_dispatcher = self.event_dispatcher;
        let last_sortitioned_block = self.last_sortitioned_block
            .expect("Expected a sortitioned block to have occurred before initialization completed");
        let registered_key = self.active_registered_key
            .expect("Expected a burnchain block to have occurred before initialization completed");

        InitializedNeonNode::new(config, keychain, event_dispatcher, Some(last_sortitioned_block),
                                 Some(registered_key))
    }

    pub fn into_initialized_node(self) -> InitializedNeonNode {
        let config = self.config;
        let keychain = self.keychain;
        let event_dispatcher = self.event_dispatcher;
        let last_sortitioned_block = self.last_sortitioned_block;
        let registered_key = self.active_registered_key;

        InitializedNeonNode::new(config, keychain, event_dispatcher, last_sortitioned_block,
                                 registered_key)
    }
}
