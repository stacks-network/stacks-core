use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::thread::JoinHandle;
use std::{env, thread, time};

use clarity::vm::database::BurnStateDB;
use rand::RngCore;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::db::BurnchainDB;
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::leader_block_commit::{
    RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS,
};
use stacks::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::db::{
    ChainStateBootData, ChainstateAccountBalance, ChainstateAccountLockup, ChainstateBNSName,
    ChainstateBNSNamespace, ClarityTx, StacksChainState, StacksEpochReceipt, StacksHeaderInfo,
};
use stacks::chainstate::stacks::events::{
    StacksTransactionEvent, StacksTransactionReceipt, TransactionOrigin,
};
use stacks::chainstate::stacks::{
    CoinbasePayload, StacksBlock, StacksMicroblock, StacksTransaction, StacksTransactionSigner,
    TransactionAnchorMode, TransactionPayload, TransactionVersion,
};
use stacks::core::mempool::MemPoolDB;
use stacks::core::STACKS_EPOCH_2_1_MARKER;
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::net::atlas::{AtlasConfig, AtlasDB, AttachmentInstance};
use stacks::net::db::PeerDB;
use stacks::net::p2p::PeerNetwork;
use stacks::net::stackerdb::StackerDBs;
use stacks::net::{Error as NetError, RPCHandlerArgs};
use stacks::util_lib::strings::UrlString;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, TrieHash, VRFSeed};
use stacks_common::types::net::PeerAddress;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha256Sum;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::vrf::VRFPublicKey;

use super::{BurnchainController, BurnchainTip, Config, EventDispatcher, Keychain, Tenure};
use crate::burnchains::make_bitcoin_indexer;
use crate::genesis_data::USE_TEST_GENESIS_CHAINSTATE;
use crate::run_loop;
use crate::run_loop::RegisteredKey;

#[derive(Debug, Clone)]
pub struct ChainTip {
    pub metadata: StacksHeaderInfo,
    pub block: StacksBlock,
    pub receipts: Vec<StacksTransactionReceipt>,
}

impl ChainTip {
    pub fn genesis(
        first_burnchain_block_hash: &BurnchainHeaderHash,
        first_burnchain_block_height: u64,
        first_burnchain_block_timestamp: u64,
    ) -> ChainTip {
        ChainTip {
            metadata: StacksHeaderInfo::genesis(
                TrieHash([0u8; 32]),
                first_burnchain_block_hash,
                first_burnchain_block_height as u32,
                first_burnchain_block_timestamp,
            ),
            block: StacksBlock::genesis_block(),
            receipts: vec![],
        }
    }
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
    event_dispatcher: EventDispatcher,
    nonce: u64,
    leader_key_registers: HashSet<Txid>,
    block_commits: HashSet<Txid>,
}

pub fn get_account_lockups(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountLockup>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_lockups()
            .map(|item| ChainstateAccountLockup {
                address: item.address,
                amount: item.amount,
                block_height: item.block_height,
            }),
    )
}

pub fn get_account_balances(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountBalance>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_balances()
            .map(|item| ChainstateAccountBalance {
                address: item.address,
                amount: item.amount,
            }),
    )
}

pub fn get_namespaces(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateBNSNamespace>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_namespaces()
            .map(|item| ChainstateBNSNamespace {
                namespace_id: item.namespace_id,
                importer: item.importer,
                buckets: item.buckets,
                base: item.base as u64,
                coeff: item.coeff as u64,
                nonalpha_discount: item.nonalpha_discount as u64,
                no_vowel_discount: item.no_vowel_discount as u64,
                lifetime: item.lifetime as u64,
            }),
    )
}

pub fn get_names(use_test_chainstate_data: bool) -> Box<dyn Iterator<Item = ChainstateBNSName>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_names()
            .map(|item| ChainstateBNSName {
                fully_qualified_name: item.fully_qualified_name,
                owner: item.owner,
                zonefile_hash: item.zonefile_hash,
            }),
    )
}

// This function is called for helium and mocknet.
fn spawn_peer(
    is_mainnet: bool,
    chain_id: u32,
    mut this: PeerNetwork,
    p2p_sock: &SocketAddr,
    rpc_sock: &SocketAddr,
    burn_db_path: String,
    stacks_chainstate_path: String,
    pox_consts: PoxConstants,
    event_dispatcher: EventDispatcher,
    exit_at_block_height: Option<u64>,
    genesis_chainstate_hash: Sha256Sum,
    poll_timeout: u64,
    config: Config,
) -> Result<JoinHandle<()>, NetError> {
    this.bind(p2p_sock, rpc_sock).unwrap();
    let server_thread = thread::spawn(move || {
        // create estimators, metric instances for RPC handler
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));
        let fee_estimator = config.make_fee_estimator();

        let handler_args = RPCHandlerArgs {
            exit_at_block_height: exit_at_block_height.clone(),
            cost_estimator: Some(cost_estimator.as_ref()),
            cost_metric: Some(metric.as_ref()),
            fee_estimator: fee_estimator.as_ref().map(|x| x.as_ref()),
            genesis_chainstate_hash,
            ..RPCHandlerArgs::default()
        };

        loop {
            let sortdb = match SortitionDB::open(&burn_db_path, false, pox_consts.clone()) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Error while connecting burnchain db in peer loop: {}", e);
                    thread::sleep(time::Duration::from_secs(1));
                    continue;
                }
            };
            let (mut chainstate, _) = match StacksChainState::open(
                is_mainnet,
                chain_id,
                &stacks_chainstate_path,
                Some(config.node.get_marf_opts()),
            ) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Error while connecting chainstate db in peer loop: {}", e);
                    thread::sleep(time::Duration::from_secs(1));
                    continue;
                }
            };

            let estimator = Box::new(UnitEstimator);
            let metric = Box::new(UnitMetric);

            let mut mem_pool = match MemPoolDB::open(
                is_mainnet,
                chain_id,
                &stacks_chainstate_path,
                estimator,
                metric,
            ) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Error while connecting to mempool db in peer loop: {}", e);
                    thread::sleep(time::Duration::from_secs(1));
                    continue;
                }
            };

            let indexer = make_bitcoin_indexer(&config, None);

            let net_result = this
                .run(
                    &indexer,
                    &sortdb,
                    &mut chainstate,
                    &mut mem_pool,
                    None,
                    false,
                    false,
                    poll_timeout,
                    &handler_args,
                )
                .unwrap();
            if net_result.has_transactions() {
                event_dispatcher.process_new_mempool_txs(net_result.transactions())
            }
            // Dispatch retrieved attachments, if any.
            if net_result.has_attachments() {
                event_dispatcher.process_new_attachments(&net_result.attachments);
            }
        }
    });
    Ok(server_thread)
}

// Check if the small test genesis chainstate data should be used.
// First check env var, then config file, then use default.
pub fn use_test_genesis_chainstate(config: &Config) -> bool {
    if env::var("BLOCKSTACK_USE_TEST_GENESIS_CHAINSTATE") == Ok("1".to_string()) {
        true
    } else if let Some(use_test_genesis_chainstate) = config.node.use_test_genesis_chainstate {
        use_test_genesis_chainstate
    } else {
        USE_TEST_GENESIS_CHAINSTATE
    }
}

impl Node {
    /// Instantiate and initialize a new node, given a config
    pub fn new(config: Config, boot_block_exec: Box<dyn FnOnce(&mut ClarityTx) -> ()>) -> Self {
        let use_test_genesis_data = if config.burnchain.mode == "mocknet" {
            use_test_genesis_chainstate(&config)
        } else {
            USE_TEST_GENESIS_CHAINSTATE
        };

        let keychain = Keychain::default(config.node.seed.clone());

        let initial_balances = config
            .initial_balances
            .iter()
            .map(|e| (e.address.clone(), e.amount))
            .collect();
        let pox_constants = match config.burnchain.get_bitcoin_network() {
            (_, BitcoinNetworkType::Mainnet) => PoxConstants::mainnet_default(),
            (_, BitcoinNetworkType::Testnet) => PoxConstants::testnet_default(),
            (_, BitcoinNetworkType::Regtest) => PoxConstants::regtest_default(),
        };

        let mut boot_data = ChainStateBootData {
            initial_balances,
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants,
            post_flight_callback: Some(boot_block_exec),
            get_bulk_initial_lockups: Some(Box::new(move || {
                get_account_lockups(use_test_genesis_data)
            })),
            get_bulk_initial_balances: Some(Box::new(move || {
                get_account_balances(use_test_genesis_data)
            })),
            get_bulk_initial_namespaces: Some(Box::new(move || {
                get_namespaces(use_test_genesis_data)
            })),
            get_bulk_initial_names: Some(Box::new(move || get_names(use_test_genesis_data))),
        };

        let chain_state_result = StacksChainState::open_and_exec(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            Some(&mut boot_data),
            Some(config.node.get_marf_opts()),
        );

        let (chain_state, receipts) = match chain_state_result {
            Ok(res) => res,
            Err(err) => panic!(
                "Error while opening chain state at path {}: {:?}",
                config.get_chainstate_path_str(),
                err
            ),
        };

        let estimator = Box::new(UnitEstimator);
        let metric = Box::new(UnitMetric);

        // avoid race to create condition on mempool db
        let _mem_pool = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &chain_state.root_path,
            estimator,
            metric,
        )
        .expect("FATAL: failed to initiate mempool");

        let mut event_dispatcher = EventDispatcher::new();

        for observer in &config.events_observers {
            event_dispatcher.register_observer(observer);
        }

        let burnchain_config = config.get_burnchain();

        // instantiate DBs
        let _burnchain_db = BurnchainDB::connect(
            &burnchain_config.get_burnchaindb_path(),
            &burnchain_config,
            true,
        )
        .expect("FATAL: failed to connect to burnchain DB");

        run_loop::announce_boot_receipts(
            &mut event_dispatcher,
            &chain_state,
            &burnchain_config.pox_constants,
            &receipts,
        );

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
            event_dispatcher,
            leader_key_registers: HashSet::new(),
            block_commits: HashSet::new(),
        }
    }

    fn make_atlas_config() -> AtlasConfig {
        AtlasConfig::new(false)
    }

    pub fn make_atlas_db(&self) -> AtlasDB {
        AtlasDB::connect(
            Self::make_atlas_config(),
            &self.config.get_atlas_db_file_path(),
            true,
        )
        .unwrap()
    }

    // This function is used for helium and mocknet.
    pub fn spawn_peer_server(&mut self) {
        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let burnchain = self.config.get_burnchain();
        let sortdb = SortitionDB::open(
            &self.config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating burnchain db");

        let epochs = SortitionDB::get_stacks_epochs(sortdb.conn())
            .expect("Error while loading stacks epochs");

        Config::assert_valid_epoch_settings(&burnchain, &epochs);

        let view = {
            let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn())
                .expect("Failed to get sortition tip");
            SortitionDB::get_burnchain_view(&sortdb.index_conn(), &burnchain, &sortition_tip)
                .unwrap()
        };

        // create a new peerdb
        let data_url = UrlString::try_from(format!("{}", self.config.node.data_url)).unwrap();

        let initial_neighbors = self.config.node.bootstrap_node.clone();

        println!("BOOTSTRAP WITH {:?}", initial_neighbors);

        let rpc_sock: SocketAddr =
            self.config.node.rpc_bind.parse().unwrap_or_else(|_| {
                panic!("Failed to parse socket: {}", &self.config.node.rpc_bind)
            });
        let p2p_sock: SocketAddr =
            self.config.node.p2p_bind.parse().unwrap_or_else(|_| {
                panic!("Failed to parse socket: {}", &self.config.node.p2p_bind)
            });
        let p2p_addr: SocketAddr = self.config.node.p2p_address.parse().unwrap_or_else(|_| {
            panic!("Failed to parse socket: {}", &self.config.node.p2p_address)
        });
        let node_privkey = {
            let mut re_hashed_seed = self.config.node.local_peer_seed.clone();
            let my_private_key = loop {
                match Secp256k1PrivateKey::from_slice(&re_hashed_seed[..]) {
                    Ok(sk) => break sk,
                    Err(_) => {
                        re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                            .as_bytes()
                            .to_vec()
                    }
                }
            };
            my_private_key
        };

        let mut peerdb = PeerDB::connect(
            &self.config.get_peer_db_file_path(),
            true,
            self.config.burnchain.chain_id,
            burnchain.network_id,
            Some(node_privkey),
            self.config.connection_options.private_key_lifetime.clone(),
            PeerAddress::from_socketaddr(&p2p_addr),
            p2p_sock.port(),
            data_url,
            &[],
            Some(&initial_neighbors),
            &[],
        )
        .unwrap();

        println!("DENY NEIGHBORS {:?}", &self.config.node.deny_nodes);
        {
            let mut tx = peerdb.tx_begin().unwrap();
            for denied in self.config.node.deny_nodes.iter() {
                PeerDB::set_deny_peer(
                    &mut tx,
                    denied.addr.network_id,
                    &denied.addr.addrbytes,
                    denied.addr.port,
                    get_epoch_time_secs() + 24 * 365 * 3600,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let atlasdb = self.make_atlas_db();

        let stackerdbs =
            StackerDBs::connect(&self.config.get_stacker_db_file_path(), true).unwrap();

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer"),
        };

        let event_dispatcher = self.event_dispatcher.clone();
        let exit_at_block_height = self.config.burnchain.process_exit_at_block_height.clone();

        let p2p_net = PeerNetwork::new(
            peerdb,
            atlasdb,
            stackerdbs,
            local_peer,
            self.config.burnchain.peer_version,
            burnchain.clone(),
            view,
            self.config.connection_options.clone(),
            HashMap::new(),
            epochs,
        );
        let _join_handle = spawn_peer(
            self.config.is_mainnet(),
            self.config.burnchain.chain_id,
            p2p_net,
            &p2p_sock,
            &rpc_sock,
            self.config.get_burn_db_file_path(),
            self.config.get_chainstate_path_str(),
            burnchain.pox_constants,
            event_dispatcher,
            exit_at_block_height,
            Sha256Sum::from_hex(stx_genesis::GENESIS_CHAINSTATE_HASH).unwrap(),
            1000,
            self.config.clone(),
        )
        .unwrap();

        info!("Start HTTP server on: {}", &self.config.node.rpc_bind);
        info!("Start P2P server on: {}", &self.config.node.p2p_bind);
    }

    pub fn setup(&mut self, burnchain_controller: &mut Box<dyn BurnchainController>) {
        // Register a new key
        let burnchain_tip = burnchain_controller.get_chain_tip();
        let (vrf_pk, _) = self
            .keychain
            .make_vrf_keypair(burnchain_tip.block_snapshot.block_height);
        let consensus_hash = burnchain_tip.block_snapshot.consensus_hash;

        let burnchain = self.config.get_burnchain();

        let sortdb = SortitionDB::open(
            &self.config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while opening sortition db");

        let epochs = SortitionDB::get_stacks_epochs(sortdb.conn())
            .expect("FATAL: failed to read sortition DB");

        Config::assert_valid_epoch_settings(&burnchain, &epochs);

        let cur_epoch =
            SortitionDB::get_stacks_epoch(sortdb.conn(), burnchain_tip.block_snapshot.block_height)
                .expect("FATAL: failed to read sortition DB")
                .expect("FATAL: no epoch defined");

        let key_reg_op = self.generate_leader_key_register_op(vrf_pk, &consensus_hash);
        let mut op_signer = self.keychain.generate_op_signer();
        let key_txid = burnchain_controller
            .submit_operation(cur_epoch.epoch_id, key_reg_op, &mut op_signer, 1)
            .expect("FATAL: failed to submit leader key register operation");

        self.leader_key_registers.insert(key_txid);
    }

    /// Process an state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    pub fn process_burnchain_state(
        &mut self,
        burnchain_tip: &BurnchainTip,
    ) -> (Option<BurnchainTip>, bool) {
        let mut new_key = None;
        let mut last_sortitioned_block = None;
        let mut won_sortition = false;
        let ops = &burnchain_tip.state_transition.accepted_ops;

        for op in ops.iter() {
            match op {
                BlockstackOperationType::LeaderKeyRegister(ref op) => {
                    if self.leader_key_registers.contains(&op.txid) {
                        // Registered key has been mined
                        new_key = Some(RegisteredKey {
                            vrf_public_key: op.public_key.clone(),
                            block_height: op.block_height as u64,
                            op_vtxindex: op.vtxindex as u32,
                            target_block_height: (op.block_height as u64) - 1,
                        });
                    }
                }
                BlockstackOperationType::LeaderBlockCommit(ref op) => {
                    if op.txid == burnchain_tip.block_snapshot.winning_block_txid {
                        last_sortitioned_block = Some(burnchain_tip.clone());
                        if self.block_commits.contains(&op.txid) {
                            won_sortition = true;
                        }
                    }
                }
                _ => {
                    // no-op, ops are not supported / produced at this point.
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
                unreachable!()
            }
            Some(ref key) => key,
        };

        let burnchain = self.config.get_burnchain();
        let sortdb = SortitionDB::open(
            &self.config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants,
        )
        .expect("Error while opening sortition db");
        let tip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn())
            .expect("FATAL: failed to query canonical burn chain tip");

        // Generates a proof out of the sortition hash provided in the params.
        let vrf_proof = self.keychain.generate_proof(
            registered_key.target_block_height,
            tip.sortition_hash.as_bytes(),
        );

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_secret_key = self.keychain.get_microblock_key(tip.block_height);

        // Get the stack's chain tip
        let chain_tip = match self.bootstraping_chain {
            true => ChainTip::genesis(&BurnchainHeaderHash::zero(), 0, 0),
            false => match &self.chain_tip {
                Some(chain_tip) => chain_tip.clone(),
                None => unreachable!(),
            },
        };

        let estimator = self
            .config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = self
            .config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mem_pool = MemPoolDB::open(
            self.config.is_mainnet(),
            self.config.burnchain.chain_id,
            &self.chain_state.root_path,
            estimator,
            metric,
        )
        .expect("FATAL: failed to open mempool");

        // Construct the coinbase transaction - 1st txn that should be handled and included in
        // the upcoming tenure.
        let coinbase_tx = self.generate_coinbase_tx(self.config.is_mainnet());

        let burn_fee_cap = self.config.burnchain.burn_fee_cap;

        let block_to_build_upon = match &self.last_sortitioned_block {
            None => unreachable!(),
            Some(block) => block.clone(),
        };

        // Construct the upcoming tenure
        let tenure = Tenure::new(
            chain_tip,
            coinbase_tx,
            self.config.clone(),
            mem_pool,
            microblock_secret_key,
            block_to_build_upon,
            vrf_proof,
            burn_fee_cap,
        );

        Some(tenure)
    }

    pub fn commit_artifacts(
        &mut self,
        anchored_block_from_ongoing_tenure: &StacksBlock,
        burnchain_tip: &BurnchainTip,
        burnchain_controller: &mut Box<dyn BurnchainController>,
        burn_fee: u64,
    ) {
        if self.active_registered_key.is_some() {
            let registered_key = self.active_registered_key.clone().unwrap();

            let vrf_proof = self.keychain.generate_proof(
                registered_key.target_block_height,
                burnchain_tip.block_snapshot.sortition_hash.as_bytes(),
            );

            let op = self.generate_block_commit_op(
                anchored_block_from_ongoing_tenure.header.block_hash(),
                burn_fee,
                &registered_key,
                &burnchain_tip,
                VRFSeed::from_proof(&vrf_proof),
            );

            let burnchain = self.config.get_burnchain();
            let sortdb = SortitionDB::open(
                &self.config.get_burn_db_file_path(),
                true,
                burnchain.pox_constants,
            )
            .expect("Error while opening sortition db");

            let cur_epoch = SortitionDB::get_stacks_epoch(
                sortdb.conn(),
                burnchain_tip.block_snapshot.block_height,
            )
            .expect("FATAL: failed to read sortition DB")
            .expect("FATAL: no epoch defined");

            let mut op_signer = self.keychain.generate_op_signer();
            let txid = burnchain_controller
                .submit_operation(cur_epoch.epoch_id, op, &mut op_signer, 1)
                .expect("FATAL: failed to submit block-commit");

            self.block_commits.insert(txid);
        } else {
            warn!("No leader key active!");
        }
    }

    /// Process artifacts from the tenure.
    /// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
    pub fn process_tenure(
        &mut self,
        anchored_block: &StacksBlock,
        consensus_hash: &ConsensusHash,
        microblocks: Vec<StacksMicroblock>,
        db: &mut SortitionDB,
        atlas_db: &mut AtlasDB,
    ) -> ChainTip {
        let _parent_consensus_hash = {
            // look up parent consensus hash
            let ic = db.index_conn();
            let parent_consensus_hash = StacksChainState::get_parent_consensus_hash(
                &ic,
                &anchored_block.header.parent_block,
                consensus_hash,
            )
            .unwrap_or_else(|_| {
                panic!(
                    "BUG: could not query chainstate to find parent consensus hash of {}/{}",
                    consensus_hash,
                    &anchored_block.block_hash()
                )
            })
            .unwrap_or_else(|| {
                panic!(
                    "BUG: no such parent of block {}/{}",
                    consensus_hash,
                    &anchored_block.block_hash()
                )
            });

            // Preprocess the anchored block
            self.chain_state
                .preprocess_anchored_block(
                    &ic,
                    consensus_hash,
                    &anchored_block,
                    &parent_consensus_hash,
                    0,
                )
                .unwrap();

            // Preprocess the microblocks
            for microblock in microblocks.iter() {
                let res = self
                    .chain_state
                    .preprocess_streamed_microblock(
                        &consensus_hash,
                        &anchored_block.block_hash(),
                        microblock,
                    )
                    .unwrap();
                if !res {
                    warn!(
                        "Unhandled error while pre-processing microblock {}",
                        microblock.header.block_hash()
                    );
                }
            }

            parent_consensus_hash
        };

        let burnchain = self.config.get_burnchain();
        let burnchain_db =
            BurnchainDB::connect(&burnchain.get_burnchaindb_path(), &burnchain, true)
                .expect("FATAL: failed to connect to burnchain DB");

        let atlas_config = Self::make_atlas_config();
        let mut processed_blocks = vec![];
        loop {
            let mut process_blocks_at_tip = {
                let tx = db.tx_begin_at_tip();
                self.chain_state.process_blocks(
                    burnchain_db.conn(),
                    tx,
                    1,
                    Some(&self.event_dispatcher),
                )
            };
            match process_blocks_at_tip {
                Err(e) => panic!("Error while processing block - {:?}", e),
                Ok(ref mut blocks) => {
                    if blocks.len() == 0 {
                        break;
                    } else {
                        for block in blocks.iter() {
                            match block {
                                (Some(epoch_receipt), _) => {
                                    let attachments_instances =
                                        self.get_attachment_instances(epoch_receipt, &atlas_config);
                                    if !attachments_instances.is_empty() {
                                        for new_attachment in attachments_instances.into_iter() {
                                            if let Err(e) =
                                                atlas_db.queue_attachment_instance(&new_attachment)
                                            {
                                                warn!(
                                                    "Atlas: Error writing attachment instance to DB";
                                                    "err" => ?e,
                                                    "index_block_hash" => %new_attachment.index_block_hash,
                                                    "contract_id" => %new_attachment.contract_id,
                                                    "attachment_index" => %new_attachment.attachment_index,
                                                );
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        processed_blocks.append(blocks);
                    }
                }
            }
        }

        // todo(ludo): yikes but good enough in the context of helium:
        // we only expect 1 block.
        let processed_block = processed_blocks[0].clone().0.unwrap();

        let mut cost_estimator = self.config.make_cost_estimator();
        let mut fee_estimator = self.config.make_fee_estimator();

        let stacks_epoch = db
            .index_conn()
            .get_stacks_epoch_by_epoch_id(&processed_block.evaluated_epoch)
            .expect("Could not find a stacks epoch.");
        if let Some(estimator) = cost_estimator.as_mut() {
            estimator.notify_block(
                &processed_block.tx_receipts,
                &stacks_epoch.block_limit,
                &stacks_epoch.epoch_id,
            );
        }

        if let Some(estimator) = fee_estimator.as_mut() {
            if let Err(e) = estimator.notify_block(&processed_block, &stacks_epoch.block_limit) {
                warn!("FeeEstimator failed to process block receipt";
                      "stacks_block" => %processed_block.header.anchored_header.block_hash(),
                      "stacks_height" => %processed_block.header.stacks_block_height,
                      "error" => %e);
            }
        }

        // Handle events
        let receipts = processed_block.tx_receipts;
        let metadata = processed_block.header;
        let block: StacksBlock = {
            let block_path = StacksChainState::get_block_path(
                &self.chain_state.blocks_path,
                &metadata.consensus_hash,
                &metadata.anchored_header.block_hash(),
            )
            .unwrap();
            StacksChainState::consensus_load(&block_path).unwrap()
        };

        let chain_tip = ChainTip {
            metadata,
            block,
            receipts,
        };
        self.chain_tip = Some(chain_tip.clone());

        // Unset the `bootstraping_chain` flag.
        if self.bootstraping_chain {
            self.bootstraping_chain = false;
        }

        chain_tip
    }

    pub fn get_attachment_instances(
        &self,
        epoch_receipt: &StacksEpochReceipt,
        atlas_config: &AtlasConfig,
    ) -> HashSet<AttachmentInstance> {
        let mut attachments_instances = HashSet::new();
        for receipt in epoch_receipt.tx_receipts.iter() {
            if let TransactionOrigin::Stacks(ref transaction) = receipt.transaction {
                if let TransactionPayload::ContractCall(ref contract_call) = transaction.payload {
                    let contract_id = contract_call.to_clarity_contract_id();
                    if atlas_config.contracts.contains(&contract_id) {
                        for event in receipt.events.iter() {
                            if let StacksTransactionEvent::SmartContractEvent(ref event_data) =
                                event
                            {
                                let res = AttachmentInstance::try_new_from_value(
                                    &event_data.value,
                                    &contract_id,
                                    epoch_receipt.header.index_block_hash(),
                                    epoch_receipt.header.stacks_block_height,
                                    receipt.transaction.txid(),
                                    self.chain_tip
                                        .as_ref()
                                        .map(|t| t.metadata.stacks_block_height),
                                );
                                if let Some(attachment_instance) = res {
                                    attachments_instances.insert(attachment_instance);
                                }
                            }
                        }
                    }
                }
            }
        }
        attachments_instances
    }

    /// Constructs and returns a LeaderKeyRegisterOp out of the provided params
    fn generate_leader_key_register_op(
        &mut self,
        vrf_public_key: VRFPublicKey,
        consensus_hash: &ConsensusHash,
    ) -> BlockstackOperationType {
        let mut txid_bytes = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut txid_bytes);
        let txid = Txid(txid_bytes);

        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            consensus_hash: consensus_hash.clone(),
            vtxindex: 1,
            txid,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        })
    }

    /// Constructs and returns a LeaderBlockCommitOp out of the provided params
    fn generate_block_commit_op(
        &mut self,
        block_header_hash: BlockHeaderHash,
        burn_fee: u64,
        key: &RegisteredKey,
        burnchain_tip: &BurnchainTip,
        vrf_seed: VRFSeed,
    ) -> BlockstackOperationType {
        let winning_tx_vtindex = burnchain_tip.get_winning_tx_index().unwrap_or(0);

        let (parent_block_ptr, parent_vtxindex) = match self.bootstraping_chain {
            true => (0, 0), // parent_block_ptr and parent_vtxindex should both be 0 on block #1
            false => (
                burnchain_tip.block_snapshot.block_height as u32,
                winning_tx_vtindex as u16,
            ),
        };

        let burnchain = self.config.get_burnchain();
        let commit_outs = if burnchain_tip.block_snapshot.block_height + 1
            < burnchain.pox_constants.sunset_end
            && !burnchain.is_in_prepare_phase(burnchain_tip.block_snapshot.block_height + 1)
        {
            RewardSetInfo::into_commit_outs(None, self.config.is_mainnet())
        } else {
            vec![PoxAddress::standard_burn_address(self.config.is_mainnet())]
        };

        let burn_parent_modulus =
            (burnchain_tip.block_snapshot.block_height % BURN_BLOCK_MINED_AT_MODULUS) as u8;

        let mut txid_bytes = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut txid_bytes);
        let txid = Txid(txid_bytes);

        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash,
            burn_fee,
            input: (Txid([0; 32]), 0),
            apparent_sender: self.keychain.get_burnchain_signer(),
            key_block_ptr: key.block_height as u32,
            key_vtxindex: key.op_vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_1_MARKER],
            new_seed: vrf_seed,
            parent_block_ptr,
            parent_vtxindex,
            vtxindex: 2,
            txid,
            commit_outs,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
            burn_parent_modulus,
        })
    }

    // Constructs a coinbase transaction
    fn generate_coinbase_tx(&mut self, is_mainnet: bool) -> StacksTransaction {
        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(self.nonce);

        let version = if is_mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };
        let mut tx = StacksTransaction::new(
            version,
            tx_auth,
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
        );
        tx.chain_id = self.config.burnchain.chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        // Increment nonce
        self.nonce += 1;

        tx_signer.get_tx().unwrap()
    }
}
