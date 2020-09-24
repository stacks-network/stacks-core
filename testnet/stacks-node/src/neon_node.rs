use super::{Keychain, Config, BurnchainController, BurnchainTip, EventDispatcher};
use crate::config::HELIUM_BLOCK_LIMIT;
use crate::run_loop::RegisteredKey;

use std::convert::{ TryFrom, TryInto };
use std::{thread, thread::JoinHandle};
use std::net::SocketAddr;
use std::collections::VecDeque;
use std::default::Default;

use stacks::burnchains::{Burnchain, BurnchainHeaderHash, Txid, PublicKey};
use stacks::chainstate::burn::db::sortdb::{SortitionDB, SortitionId};
use stacks::chainstate::stacks::db::{StacksChainState, ClarityTx};
use stacks::chainstate::stacks::{
    StacksBlock, TransactionPayload, StacksAddress, StacksTransactionSigner,
    StacksTransaction, TransactionVersion, StacksMicroblock, CoinbasePayload,
    TransactionAnchorMode, StacksBlockHeader };
use stacks::chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash};
use stacks::chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    BlockstackOperationType,
    leader_block_commit::RewardSetInfo,
};
use stacks::chainstate::stacks::{StacksBlockBuilder, miner::StacksMicroblockBuilder};
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::stacks::{Error as ChainstateError};
use stacks::chainstate::stacks::StacksPublicKey;
use stacks::chainstate::stacks::StacksBlockId;
use stacks::core::mempool::MemPoolDB;
use stacks::util::vrf::VRFPublicKey;
use stacks::util::strings::UrlString;
use stacks::util::hash::{
    Hash160, Sha256Sum, to_hex
};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks::net::{
    db::{ PeerDB, LocalPeer }, relay::Relayer,
    dns::DNSResolver, p2p::PeerNetwork,
    Error as NetError, PeerAddress, StacksMessageCodec,
    NetworkResult, rpc::RPCHandlerArgs
};
use std::sync::mpsc::{sync_channel, TrySendError, SyncSender, Receiver};

use crate::burnchains::bitcoin_regtest_controller::BitcoinRegtestController;
use crate::ChainTip;
use stacks::burnchains::BurnchainSigner;
use stacks::core::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks::vm::costs::ExecutionCost;

use stacks::vm::database::BurnStateDB;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::coordinator::{get_next_recipients, OnChainRewardSetProvider};

use stacks::monitoring::{
    increment_stx_blocks_mined_counter,
    update_active_miners_count_gauge,
};

pub const TESTNET_CHAIN_ID: u32 = 0x80000000;
pub const TESTNET_PEER_VERSION: u32 = 0xfacade01;
pub const RELAYER_MAX_BUFFER: usize = 100;

struct AssembledAnchorBlock {
    parent_consensus_hash: ConsensusHash,
    my_burn_hash: BurnchainHeaderHash,
    anchored_block: StacksBlock,
    consumed_execution: ExecutionCost,
    bytes_so_far: u64
}

enum RelayerDirective {
    HandleNetResult(NetworkResult),
    ProcessTenure(ConsensusHash, BurnchainHeaderHash, BlockHeaderHash),
    RunTenure(RegisteredKey, BlockSnapshot),
    RegisterKey(BlockSnapshot),
}


pub struct InitializedNeonNode {
    relay_channel: SyncSender<RelayerDirective>,
    burnchain_signer: BurnchainSigner,
    last_burn_block: Option<BlockSnapshot>,
    active_keys: Vec<RegisteredKey>,
    sleep_before_tenure: u64,
    is_miner: bool,
}

pub struct NeonGenesisNode {
    pub config: Config,
    keychain: Keychain,
    event_dispatcher: EventDispatcher,
}

#[cfg(test)]
type BlocksProcessedCounter = std::sync::Arc<std::sync::atomic::AtomicU64>;

#[cfg(not(test))]
type BlocksProcessedCounter = ();

#[cfg(test)]
fn bump_processed_counter(blocks_processed: &BlocksProcessedCounter) {
    blocks_processed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(not(test))]
fn bump_processed_counter(_blocks_processed: &BlocksProcessedCounter) {
}

/// Process artifacts from the tenure.
/// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
fn inner_process_tenure(
    anchored_block: &StacksBlock, 
    consensus_hash: &ConsensusHash,
    parent_consensus_hash: &ConsensusHash,
    burn_db: &mut SortitionDB,
    chain_state: &mut StacksChainState,
    coord_comms: &CoordinatorChannels) -> Result<bool, ChainstateError> {

    let stacks_blocks_processed = coord_comms.get_stacks_blocks_processed();

    {
        let ic = burn_db.index_conn();

        // Preprocess the anchored block
        chain_state.preprocess_anchored_block(
            &ic,
            consensus_hash,
            &anchored_block,
            &parent_consensus_hash)?;
    }

    if !coord_comms.announce_new_stacks_block() {
        return Ok(false)
    }
    if !coord_comms.wait_for_stacks_blocks_processed(stacks_blocks_processed, 15000) {
        warn!("ChainsCoordinator timed out while waiting for new stacks block to be processed");
    }

    let (canonical_consensus_hash, canonical_block_hash) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(burn_db.conn())?;

    let canonical_tip = StacksBlockId::new(&canonical_consensus_hash, &canonical_block_hash);
    debug!("Reload unconfirmed state");
    chain_state.reload_unconfirmed_state(&burn_db.index_conn(), canonical_tip)?;

    Ok(true)
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

fn rotate_vrf_and_register(keychain: &mut Keychain, burn_block: &BlockSnapshot, btc_controller: &mut BitcoinRegtestController) {
    let vrf_pk = keychain.rotate_vrf_keypair(burn_block.block_height);
    let burnchain_tip_consensus_hash = &burn_block.consensus_hash;
    let op = inner_generate_leader_key_register_op(keychain.get_address(), vrf_pk, burnchain_tip_consensus_hash);

    let mut one_off_signer = keychain.generate_op_signer();
    btc_controller.submit_operation(op, &mut one_off_signer);
}

/// Constructs and returns a LeaderBlockCommitOp out of the provided params
fn inner_generate_block_commit_op(
    input: BurnchainSigner,
    block_header_hash: BlockHeaderHash,
    burn_fee: u64, 
    key: &RegisteredKey,
    parent_burnchain_height: u32,
    parent_winning_vtx: u16,
    vrf_seed: VRFSeed,
    recipients: Option<RewardSetInfo>) -> BlockstackOperationType {

    let (parent_block_ptr, parent_vtxindex) =
        (parent_burnchain_height, parent_winning_vtx);

    let commit_outs = if let Some(recipient_set) = recipients {
        let (addr, _) = recipient_set.recipient;
        vec![addr]
    } else {
        vec![]
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
        commit_outs,
    })
}

fn spawn_peer(mut this: PeerNetwork, p2p_sock: &SocketAddr, rpc_sock: &SocketAddr,
              config: Config,
              poll_timeout: u64, relay_channel: SyncSender<RelayerDirective>) -> Result<JoinHandle<()>, NetError> {

    let burn_db_path = config.get_burn_db_file_path();
    let stacks_chainstate_path = config.get_chainstate_path();
    let block_limit = config.block_limit;
    let exit_at_block_height = config.burnchain.process_exit_at_block_height;

    this.bind(p2p_sock, rpc_sock).unwrap();
    let (mut dns_resolver, mut dns_client) = DNSResolver::new(10);
    let sortdb = SortitionDB::open(&burn_db_path, false)
        .map_err(NetError::DBError)?;

    let (mut chainstate, _) = StacksChainState::open_with_block_limit(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path, block_limit)
        .map_err(|e| NetError::ChainstateError(e.to_string()))?;
    
    let mut mem_pool = MemPoolDB::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(NetError::DBError)?;

    // buffer up blocks to store without stalling the p2p thread
    let mut results_with_data = VecDeque::new();

    let server_thread = thread::spawn(move || {
        let handler_args = RPCHandlerArgs { exit_at_block_height: exit_at_block_height.as_ref(),
                                            .. RPCHandlerArgs::default() };

        let mut disconnected = false;
        while !disconnected {
            let download_backpressure = results_with_data.len() > 0;
            let poll_ms = 
                if !download_backpressure && this.has_more_downloads() {
                    // keep getting those blocks -- drive the downloader state-machine
                    debug!("P2P: backpressure: {}, more downloads: {}", download_backpressure, this.has_more_downloads());
                    100
                }
                else {
                    poll_timeout
                };

            // update p2p's read-only view of the unconfirmed state
            let (canonical_consensus_tip, canonical_block_tip) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())
                .expect("Failed to read canonical stacks chain tip");
            let canonical_tip = StacksBlockHeader::make_index_block_hash(&canonical_consensus_tip, &canonical_block_tip);
            chainstate.refresh_unconfirmed_state_readonly(canonical_tip)
                .expect("Failed to open unconfirmed Clarity state");

            let network_result = match this.run(&sortdb, &mut chainstate, &mut mem_pool, Some(&mut dns_client),
                                                 download_backpressure, poll_ms, &handler_args) {
                Ok(res) => res,
                Err(e) => {
                    error!("P2P: Failed to process network dispatch: {:?}", &e);
                    panic!();
                }
            };

            if network_result.has_data_to_store() {
                results_with_data.push_back(RelayerDirective::HandleNetResult(network_result));
            }

            while let Some(next_result) = results_with_data.pop_front() {
                // have blocks, microblocks, and/or transactions (don't care about anything else),
                if let Err(e) = relay_channel.try_send(next_result) {
                    debug!("P2P: {:?}: download backpressure detected", &this.local_peer);
                    match e {
                        TrySendError::Full(directive) => {
                            // don't lose this data -- just try it again
                            results_with_data.push_front(directive);
                            break;
                        },
                        TrySendError::Disconnected(_) => {
                            info!("P2P: Relayer hang up with p2p channel");
                            disconnected = true;
                            break;
                        }
                    }
                }
                else {
                    debug!("P2P: Dispatched result to Relayer!");
                }
            }
        }
        debug!("P2P thread exit!");
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
                       event_dispatcher: EventDispatcher,
                       blocks_processed: BlocksProcessedCounter,
                       burnchain: Burnchain,
                       coord_comms: CoordinatorChannels) -> Result<(), NetError> {
    // Note: the relayer is *the* block processor, it is responsible for writes to the chainstate --
    //   no other codepaths should be writing once this is spawned.
    //
    // the relayer _should not_ be modifying the sortdb,
    //   however, it needs a mut reference to create read TXs.
    //   should address via #1449
    let mut sortdb = SortitionDB::open(&burn_db_path, true)
        .map_err(NetError::DBError)?;

    let (mut chainstate, _) = StacksChainState::open_with_block_limit(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path, config.block_limit.clone())
        .map_err(|e| NetError::ChainstateError(e.to_string()))?;
    
    let mut mem_pool = MemPoolDB::open(
        false, TESTNET_CHAIN_ID, &stacks_chainstate_path)
        .map_err(NetError::DBError)?;

    let mut last_mined_block: Option<AssembledAnchorBlock> = None;
    let burn_fee_cap = config.burnchain.burn_fee_cap;
    let mine_microblocks = config.node.mine_microblocks;

    let mut bitcoin_controller = BitcoinRegtestController::new_dummy(config.clone());

    let _relayer_handle = thread::spawn(move || {
        while let Ok(mut directive) = relay_channel.recv() {
            match directive {
                RelayerDirective::HandleNetResult(ref mut net_result) => {
                    debug!("Relayer: Handle network result");
                    let net_receipts = relayer.process_network_result(&local_peer, net_result,
                                                                      &mut sortdb, &mut chainstate, &mut mem_pool,
                                                                      Some(&coord_comms))
                        .expect("BUG: failure processing network results");

                    let mempool_txs_added = net_receipts.mempool_txs_added.len();
                    if mempool_txs_added > 0 {
                        event_dispatcher.process_new_mempool_txs(net_receipts.mempool_txs_added);
                    }
                },
                RelayerDirective::ProcessTenure(consensus_hash, burn_hash, block_header_hash) => {
                    debug!("Relayer: Process tenure");
                    if let Some(my_mined) = last_mined_block.take() {
                        let AssembledAnchorBlock {
                            parent_consensus_hash,
                            anchored_block: mined_block,
                            my_burn_hash: mined_burn_hash,
                            consumed_execution,
                            bytes_so_far } = my_mined;
                        if mined_block.block_hash() == block_header_hash && burn_hash == mined_burn_hash {
                            // we won!
                            info!("Won sortition! stacks_header={}, burn_hash={}",
                                  block_header_hash,
                                  mined_burn_hash);

                            increment_stx_blocks_mined_counter();

                            match inner_process_tenure(&mined_block, &consensus_hash, &parent_consensus_hash,
                                                       &mut sortdb, &mut chainstate, &coord_comms) {
                                Ok(coordinator_running) => if !coordinator_running {
                                    warn!("Coordinator stopped, stopping relayer thread...");
                                    return;
                                },
                                Err(e) => {
                                    warn!("Error processing my tenure, bad block produced: {}", e);
                                    warn!("Bad block stacks_header={}, data={}",
                                          block_header_hash, to_hex(&mined_block.serialize_to_vec()));
                                    continue;
                                }
                            };

                            // advertize _and_ push blocks for now
                            let blocks_available = Relayer::load_blocks_available_data(&sortdb, vec![consensus_hash.clone()])
                                .expect("Failed to obtain block information for a block we mined.");
                            if let Err(e) = relayer.advertize_blocks(blocks_available) {
                                warn!("Failed to advertise new block: {}", e);
                            }

                            let snapshot = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &consensus_hash)
                                .expect("Failed to obtain snapshot for block")
                                .expect("Failed to obtain snapshot for block");

                            if !snapshot.pox_valid {
                                warn!("Snapshot for {} is no longer valid; discarding {}...", &consensus_hash, &mined_block.block_hash());
                            }
                            else {
                                if let Err(e) = relayer.broadcast_block(snapshot.consensus_hash, mined_block) {
                                    warn!("Failed to push new block: {}", e);
                                }
                                else {
                                    // should we broadcast microblocks?
                                    if mine_microblocks {
                                        let mint_result = InitializedNeonNode::relayer_mint_microblocks(
                                            &consensus_hash, &block_header_hash, &mut chainstate, &sortdb.index_conn(), &keychain,
                                            consumed_execution, bytes_so_far, &mem_pool);
                                        let mined_microblock = match mint_result {
                                            Ok(mined_microblock) => mined_microblock,
                                            Err(e) => {
                                                warn!("Failed to mine microblock: {}", e);
                                                continue;
                                            }
                                        };
                                        // preprocess the microblock locally
                                        match chainstate.preprocess_streamed_microblock(&consensus_hash, &block_header_hash, &mined_microblock) {
                                            Ok(res) => {
                                                if !res {
                                                    warn!("Unhandled error while pre-processing microblock {}",
                                                          mined_microblock.header.block_hash());
                                                    continue
                                                }
                                            },
                                            Err(e) => {
                                                error!("Error while pre-processing microblock {}: {}",
                                                       mined_microblock.header.block_hash(), e);
                                                continue
                                            },
                                        }
                                        // update unconfirmed state
                                        if let Err(e) = chainstate.refresh_unconfirmed_state(&sortdb.index_conn()) {
                                            warn!("Failed to refresh unconfirmed state after processing microblock {}/{}-{}: {:?}", &mined_burn_hash, &block_header_hash, mined_microblock.block_hash(), &e);
                                        }
                                        // broadcast to peers
                                        let microblock_hash = mined_microblock.header.block_hash();
                                        if let Err(e) = relayer.broadcast_microblock(&consensus_hash, &block_header_hash, mined_microblock) {
                                            error!("Failure trying to broadcast microblock {}: {}",
                                                   microblock_hash, e);
                                        }
                                    }
                                }
                            }
                        } else {
                            warn!("Did not win sortition, my blocks [burn_hash= {}, block_hash= {}], their blocks [parent_consenus_hash= {}, burn_hash= {}, block_hash ={}]",
                                  mined_burn_hash, mined_block.block_hash(), parent_consensus_hash, burn_hash, block_header_hash);
                        }
                    }
                },
                RelayerDirective::RunTenure(registered_key, last_burn_block) => {
                    debug!("Relayer: Run tenure");
                    last_mined_block = InitializedNeonNode::relayer_run_tenure(
                        &config, registered_key, &mut chainstate, &mut sortdb, &burnchain, last_burn_block,
                        &mut keychain, &mut mem_pool, burn_fee_cap, &mut bitcoin_controller);
                    bump_processed_counter(&blocks_processed);
                },
                RelayerDirective::RegisterKey(ref last_burn_block) => {
                    debug!("Relayer: Register key");
                    rotate_vrf_and_register(&mut keychain, last_burn_block, &mut bitcoin_controller);
                    bump_processed_counter(&blocks_processed);
                }
            }
        }
        debug!("Relayer exit!");
    });

    Ok(())
}

impl InitializedNeonNode {
    fn new(config: Config, keychain: Keychain, event_dispatcher: EventDispatcher,
           last_burn_block: Option<BurnchainTip>,
           miner: bool, blocks_processed: BlocksProcessedCounter, coord_comms: CoordinatorChannels) -> InitializedNeonNode {
        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let sortdb = SortitionDB::open(&config.get_burn_db_file_path(), false)
            .expect("Error while instantiating sortition db");

        let burnchain = Burnchain::new(
            &config.get_burn_db_path(),
            &config.burnchain.chain,
            "regtest").expect("Error while instantiating burnchain");

        let view = {
            let ic = sortdb.index_conn();
            let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(&ic)
                .expect("Failed to get sortition tip");
            ic.get_burnchain_view(&burnchain, &sortition_tip).unwrap()
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
        let p2p_addr: SocketAddr = config.node.p2p_address.parse()
            .expect(&format!("Failed to parse socket: {}", &config.node.p2p_address));
        let node_privkey = {
            let mut re_hashed_seed = config.node.local_peer_seed.clone();
            let my_private_key = loop {
                match Secp256k1PrivateKey::from_slice(&re_hashed_seed[..]) {
                    Ok(sk) => break sk,
                    Err(_) => re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..]).as_bytes().to_vec()
                }
            };
            my_private_key
        };

        let peerdb = PeerDB::connect(
            &config.get_peer_db_path(), 
            true, 
            TESTNET_CHAIN_ID, 
            burnchain.network_id, 
            Some(node_privkey),
            config.connection_options.private_key_lifetime.clone(),
            PeerAddress::from_socketaddr(&p2p_addr), 
            p2p_sock.port(),
            data_url.clone(),
            &vec![], 
            Some(&initial_neighbors)).unwrap();

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer")
        };

        // now we're ready to instantiate a p2p network object, the relayer, and the event dispatcher
        let mut p2p_net = PeerNetwork::new(peerdb, local_peer.clone(), TESTNET_PEER_VERSION, burnchain.clone(), view,
                                           config.connection_options.clone());

        // setup the relayer channel
        let (relay_send, relay_recv) = sync_channel(RELAYER_MAX_BUFFER);

        let burnchain_signer = keychain.get_burnchain_signer();
        let relayer = Relayer::from_p2p(&mut p2p_net);

        let sleep_before_tenure = config.node.wait_time_for_microblocks;

        spawn_miner_relayer(relayer, local_peer,
                            config.clone(), keychain,
                            config.get_burn_db_file_path(),
                            config.get_chainstate_path(),
                            relay_recv, event_dispatcher,
                            blocks_processed.clone(),
                            burnchain,
                            coord_comms)
            .expect("Failed to initialize mine/relay thread");

        spawn_peer(p2p_net, &p2p_sock, &rpc_sock,
                   config.clone(), 5000, relay_send.clone())
            .expect("Failed to initialize mine/relay thread");


        info!("Bound HTTP server on: {}", &config.node.rpc_bind);
        info!("Bound P2P server on: {}", &config.node.p2p_bind);

        let last_burn_block = last_burn_block.map(|x| x.block_snapshot);

        let is_miner = miner;

        let active_keys = vec![];

        InitializedNeonNode {
            relay_channel: relay_send,
            last_burn_block,
            burnchain_signer,
            is_miner,
            sleep_before_tenure,
            active_keys,
        }
    }


    /// Tell the relayer to fire off a tenure and a block commit op.
    pub fn relayer_issue_tenure(&mut self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to issue a tenure
            return true;
        }

        if let Some(burnchain_tip) = self.last_burn_block.clone() {
            if let Some(key) = self.active_keys.first() {
                debug!("Using key {:?}", &key.vrf_public_key);
                // sleep a little before building the anchor block, to give any broadcasted 
                //   microblocks time to propagate.
                info!("Sleeping {} before issuing tenure", self.sleep_before_tenure);
                thread::sleep(std::time::Duration::from_millis(self.sleep_before_tenure));
                self.relay_channel
                    .send(RelayerDirective::RunTenure(key.clone(), burnchain_tip))
                    .is_ok()
            } else {
                warn!("Skipped tenure because no active VRF key. Trying to register one.");
                self.relay_channel
                    .send(RelayerDirective::RegisterKey(burnchain_tip))
                    .is_ok()
            }
        } else {
            warn!("Do not know the last burn block. As a miner, this is bad.");
            true
        }
    }

    /// Notify the relayer of a sortition, telling it to process the block
    ///  and advertize it if it was mined by the node.
    /// returns _false_ if the relayer hung up the channel.
    pub fn relayer_sortition_notify(&self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to process my own tenure.
            return true;
        }

        if let Some(ref snapshot) = &self.last_burn_block {
            if snapshot.sortition {
                return self.relay_channel
                    .send(RelayerDirective::ProcessTenure(
                        snapshot.consensus_hash.clone(),
                        snapshot.parent_burn_header_hash.clone(),
                        snapshot.winning_stacks_block_hash.clone()))
                    .is_ok();
            }
        }
        true
    }

    fn relayer_mint_microblocks(mined_block_consensus_hash: &ConsensusHash,
                                mined_block_shh: &BlockHeaderHash,
                                chain_state: &mut StacksChainState,
                                burn_dbconn: &dyn BurnStateDB,
                                keychain: &Keychain,
                                consumed_execution: ExecutionCost,
                                bytes_so_far: u64,
                                mem_pool: &MemPoolDB) -> Result<StacksMicroblock, ChainstateError> {
        let mut microblock_miner = StacksMicroblockBuilder::new(mined_block_shh.clone(),
                                                                mined_block_consensus_hash.clone(),
                                                                chain_state,
                                                                burn_dbconn,
                                                                consumed_execution,
                                                                bytes_so_far)?;
        let mblock_key = keychain.get_microblock_key()
            .expect("Miner attempt to mine microblocks without a microblock key");

        let mblock = microblock_miner.mine_next_microblock(mem_pool, &mblock_key)?;

        info!("Minted microblock with {} transactions", mblock.txs.len());

        Ok(mblock)
    }

    // return stack's parent's burn header hash,
    //        the anchored block,
    //        the burn header hash of the burnchain tip
    fn relayer_run_tenure(config: &Config,
                          registered_key: RegisteredKey,
                          chain_state: &mut StacksChainState,
                          burn_db: &mut SortitionDB,
                          burnchain: &Burnchain,
                          burn_block: BlockSnapshot,
                          keychain: &mut Keychain,
                          mem_pool: &mut MemPoolDB,
                          burn_fee_cap: u64,
                          bitcoin_controller: &mut BitcoinRegtestController) -> Option<AssembledAnchorBlock> {
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

        let (stacks_parent_header, parent_consensus_hash, parent_block_burn_height, parent_block_total_burn, parent_winning_vtxindex, coinbase_nonce) =
            if let Some(stacks_tip) = chain_state.get_stacks_chain_tip(burn_db).unwrap() {
                let stacks_tip_header = match StacksChainState::get_anchored_block_header_info(chain_state.headers_db(), &stacks_tip.consensus_hash, &stacks_tip.anchored_block_hash).unwrap() {
                    Some(x) => x,
                    None => {
                        error!("Could not mine new tenure, since could not find header for known chain tip.");
                        return None
                    }
                };

                // the consensus hash of my Stacks block parent
                let parent_consensus_hash = stacks_tip.consensus_hash.clone();

                // the stacks block I'm mining off of's burn header hash and vtx index:
                let parent_snapshot = SortitionDB::get_block_snapshot_consensus(burn_db.conn(), &stacks_tip.consensus_hash)
                    .expect("Failed to look up block's parent snapshot")
                    .expect("Failed to look up block's parent snapshot");

                let parent_sortition_id = &parent_snapshot.sortition_id;
                let parent_winning_vtxindex =
                    match SortitionDB::get_block_winning_vtxindex(burn_db.conn(), parent_sortition_id)
                    .expect("SortitionDB failure.") {
                        Some(x) => x,
                        None => {
                            warn!("Failed to find winning vtx index for the parent sortition {}",
                                  parent_sortition_id);
                            return None
                        }
                    };

                let parent_block = match SortitionDB::get_block_snapshot(burn_db.conn(), parent_sortition_id)
                    .expect("SortitionDB failure.") {
                        Some(x) => x,
                        None => {
                            warn!("Failed to find block snapshot for the parent sortition {}",
                                  parent_sortition_id);
                            return None
                        }
                    };

                debug!("Mining tenure's last consensus hash: {}, stacks tip consensus hash: {}",
                       &burn_block.consensus_hash,
                       &stacks_tip.consensus_hash);

                let coinbase_nonce = {
                    let principal = keychain.origin_address().unwrap().into();
                    let account = chain_state.with_read_only_clarity_tx(&burn_db.index_conn(), &StacksBlockHeader::make_index_block_hash(&stacks_tip.consensus_hash, &stacks_tip.anchored_block_hash), |conn| {
                        StacksChainState::get_account(conn, &principal)
                    });
                    account.nonce
                };

                (stacks_tip_header, parent_consensus_hash, parent_block.block_height, parent_block.total_burn, parent_winning_vtxindex, coinbase_nonce)
            } else {
                warn!("No Stacks chain tip known, attempting to mine a genesis block");
                let chain_tip = ChainTip::genesis(config.get_initial_liquid_ustx());

                (chain_tip.metadata, FIRST_BURNCHAIN_CONSENSUS_HASH.clone(), 0, 0, 0, 0)
            };
        
        let coinbase_tx = inner_generate_coinbase_tx(keychain, coinbase_nonce);

        let (anchored_block, consumed_execution, bytes_so_far) = match StacksBlockBuilder::build_anchored_block(
            chain_state, &burn_db.index_conn(), mem_pool, &stacks_parent_header, parent_block_total_burn,
            vrf_proof.clone(), mblock_pubkey_hash, &coinbase_tx, HELIUM_BLOCK_LIMIT.clone()) {
            Ok(block) => block,
            Err(e) => {
                error!("Failure mining anchored block: {}", e);
                return None
            }
        };

        info!("{} block assembled: {}, with {} txs",
              if parent_block_total_burn == 0 { "Genesis" } else { "Stacks" },
              anchored_block.block_hash(), anchored_block.txs.len() );

        // let's figure out the recipient set!
        let recipients = match get_next_recipients(&burn_block, chain_state, burn_db,
                                                   burnchain, &OnChainRewardSetProvider()) {
            Ok(x) => x,
            Err(e) => {
                error!("Failure fetching recipient set: {:?}", e);
                return None
            },
        };
        // let's commit
        let op = inner_generate_block_commit_op(
            keychain.get_burnchain_signer(),
            anchored_block.block_hash(),
            burn_fee_cap,
            &registered_key,
            parent_block_burn_height.try_into()
                .expect("Could not convert parent block height into u32"),
            parent_winning_vtxindex,
            VRFSeed::from_proof(&vrf_proof),
            recipients);
        let mut op_signer = keychain.generate_op_signer();
        bitcoin_controller.submit_operation(op, &mut op_signer);

        Some(AssembledAnchorBlock {
            parent_consensus_hash: parent_consensus_hash,
            my_burn_hash: burn_block.burn_header_hash,
            consumed_execution,
            anchored_block,
            bytes_so_far
        })
    }

    /// Process a state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    pub fn process_burnchain_state(&mut self, sortdb: &SortitionDB, sort_id: &SortitionId) -> (Option<BlockSnapshot>, bool) {
        let mut last_sortitioned_block = None; 
        let mut won_sortition = false;

        let ic = sortdb.index_conn();

        let block_snapshot = SortitionDB::get_block_snapshot(&ic, sort_id)
            .expect("Failed to obtain block snapshot for processed burn block.")
            .expect("Failed to obtain block snapshot for processed burn block.");
        let block_height = block_snapshot.block_height;

        let block_commits = SortitionDB::get_block_commits_by_block(&ic, &block_snapshot.sortition_id)
            .expect("Unexpected SortitionDB error fetching block commits");

        update_active_miners_count_gauge(block_commits.len() as i64);

        for op in block_commits.into_iter() {
            if op.txid == block_snapshot.winning_block_txid {
                info!("Received burnchain block #{} including block_commit_op (winning) - {}", block_height, op.input.to_testnet_address());
                last_sortitioned_block = Some((block_snapshot.clone(), op.vtxindex));
                // Release current registered key if leader won the sortition
                // This will trigger a new registration
                if op.input == self.burnchain_signer {
                    won_sortition = true;
                }    
            } else {
                if self.is_miner {
                    info!("Received burnchain block #{} including block_commit_op - {}", block_height, op.input.to_testnet_address());
                }
            }
        }

        let key_registers = SortitionDB::get_leader_keys_by_block(&ic, &block_snapshot.sortition_id)
            .expect("Unexpected SortitionDB error fetching key registers");
        for op in key_registers.into_iter() {
            if self.is_miner {
                info!("Received burnchain block #{} including key_register_op - {}", block_height, op.address);
            }
            if op.address == Keychain::address_from_burnchain_signer(&self.burnchain_signer) {
                // Registered key has been mined
                self.active_keys.push(
                    RegisteredKey {
                        vrf_public_key: op.public_key,
                        block_height: op.block_height as u64,
                        op_vtxindex: op.vtxindex as u32,
                    });
            }
        }

        // no-op on UserBurnSupport ops are not supported / produced at this point.
        self.last_burn_block = Some(block_snapshot);

        (last_sortitioned_block.map(|x| x.0), won_sortition)
    }
}

impl NeonGenesisNode {

    /// Instantiate and initialize a new node, given a config
    pub fn new<F>(config: Config, mut event_dispatcher: EventDispatcher, boot_block_exec: F) -> Self
    where F: FnOnce(&mut ClarityTx) -> () {

        let keychain = Keychain::default(config.node.seed.clone());
        let initial_balances = config.initial_balances.iter().map(|e| (e.address.clone(), e.amount)).collect();

        // do the initial open!
        let (_chain_state, receipts) = match StacksChainState::open_and_exec(
            false, 
            TESTNET_CHAIN_ID, 
            &config.get_chainstate_path(), 
            Some(initial_balances), 
            boot_block_exec,
            config.block_limit.clone()) {
            Ok(res) => res,
            Err(err) => panic!("Error while opening chain state at path {}: {:?}", config.get_chainstate_path(), err)
        };

        event_dispatcher.process_boot_receipts(receipts);

        Self {
            keychain,
            config,
            event_dispatcher,
        }
    }

    pub fn into_initialized_leader_node(self, burnchain_tip: BurnchainTip, blocks_processed: BlocksProcessedCounter, coord_comms: CoordinatorChannels) -> InitializedNeonNode {
        let config = self.config;
        let keychain = self.keychain;
        let event_dispatcher = self.event_dispatcher;

        InitializedNeonNode::new(config, keychain, event_dispatcher, Some(burnchain_tip),
                                 true, blocks_processed, coord_comms)
    }

    pub fn into_initialized_node(self, burnchain_tip: BurnchainTip, blocks_processed: BlocksProcessedCounter, coord_comms: CoordinatorChannels) -> InitializedNeonNode {
        let config = self.config;
        let keychain = self.keychain;
        let event_dispatcher = self.event_dispatcher;

        InitializedNeonNode::new(config, keychain, event_dispatcher, Some(burnchain_tip),
                                 false, blocks_processed, coord_comms)
    }
}
