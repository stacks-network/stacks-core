use std::cell::{Cell, RefCell};
use std::cmp;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
use std::sync::atomic::AtomicU64;

use std::sync::mpsc::sync_channel;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;

use std::collections::HashSet;

use stacks::deps::ctrlc as termination;
use stacks::deps::ctrlc::SignalId;

use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::burnchains::bitcoin::address::BitcoinAddressType;
use stacks::burnchains::{Address, Burnchain};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::coordinator::comm::{CoordinatorChannels, CoordinatorReceivers};
use stacks::chainstate::coordinator::{
    migrate_chainstate_dbs, BlockEventDispatcher, ChainsCoordinator, CoordinatorCommunication,
    Error as coord_error,
};
use stacks::chainstate::stacks::db::{ChainStateBootData, StacksChainState};
use stacks::net::atlas::{AtlasConfig, Attachment, AttachmentInstance, ATTACHMENTS_CHANNEL_SIZE};
use stacks::util_lib::db::Error as db_error;
use stx_genesis::GenesisData;

use crate::monitoring::start_serving_monitoring_metrics;
use crate::neon_node::StacksNode;
use crate::node::use_test_genesis_chainstate;
use crate::syncctl::{PoxSyncWatchdog, PoxSyncWatchdogComms};
use crate::{
    node::{get_account_balances, get_account_lockups, get_names, get_namespaces},
    BitcoinRegtestController, BurnchainController, Config, EventDispatcher, Keychain,
};

use super::RunLoopCallbacks;
use crate::config::DynConfig;
use libc;

pub const STDERR: i32 = 2;

#[cfg(test)]
pub type RunLoopCounter = Arc<AtomicU64>;

#[cfg(not(test))]
pub type RunLoopCounter = ();

#[derive(Clone)]
pub struct Counters {
    pub blocks_processed: RunLoopCounter,
    pub microblocks_processed: RunLoopCounter,
    pub missed_tenures: RunLoopCounter,
    pub missed_microblock_tenures: RunLoopCounter,
    pub cancelled_commits: RunLoopCounter,
}

impl Counters {
    #[cfg(test)]
    pub fn new() -> Counters {
        Counters {
            blocks_processed: RunLoopCounter::new(AtomicU64::new(0)),
            microblocks_processed: RunLoopCounter::new(AtomicU64::new(0)),
            missed_tenures: RunLoopCounter::new(AtomicU64::new(0)),
            missed_microblock_tenures: RunLoopCounter::new(AtomicU64::new(0)),
            cancelled_commits: RunLoopCounter::new(AtomicU64::new(0)),
        }
    }

    #[cfg(not(test))]
    pub fn new() -> Counters {
        Counters {
            blocks_processed: (),
            microblocks_processed: (),
            missed_tenures: (),
            missed_microblock_tenures: (),
            cancelled_commits: (),
        }
    }

    #[cfg(test)]
    fn inc(ctr: &RunLoopCounter) {
        ctr.fetch_add(1, Ordering::SeqCst);
    }

    #[cfg(not(test))]
    fn inc(_ctr: &RunLoopCounter) {}

    #[cfg(test)]
    fn set(ctr: &RunLoopCounter, value: u64) {
        ctr.store(value, Ordering::SeqCst);
    }

    #[cfg(not(test))]
    fn set(_ctr: &RunLoopCounter, _value: u64) {}

    pub fn bump_blocks_processed(&self) {
        Counters::inc(&self.blocks_processed);
    }

    pub fn bump_microblocks_processed(&self) {
        Counters::inc(&self.microblocks_processed);
    }

    pub fn bump_missed_tenures(&self) {
        Counters::inc(&self.missed_tenures);
    }

    pub fn bump_missed_microblock_tenures(&self) {
        Counters::inc(&self.missed_microblock_tenures);
    }

    pub fn bump_cancelled_commits(&self) {
        Counters::inc(&self.cancelled_commits);
    }

    pub fn set_microblocks_processed(&self, value: u64) {
        Counters::set(&self.microblocks_processed, value)
    }
}

/// Coordinating a node running in neon mode.
pub struct RunLoop {
    config: Config,
    dyn_config: DynConfig,
    pub callbacks: RunLoopCallbacks,
    counters: Counters,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>,
    should_keep_running: Arc<AtomicBool>,
    event_dispatcher: EventDispatcher,
    pox_watchdog: Option<PoxSyncWatchdog>, // can't be instantiated until .start() is called
    is_miner: Option<bool>,                // not known until .start() is called
    burnchain: Option<Burnchain>,          // not known until .start() is called
    pox_watchdog_comms: PoxSyncWatchdogComms,
}

/// Write to stderr in an async-safe manner.
/// See signal-safety(7)
fn async_safe_write_stderr(msg: &str) {
    #[cfg(windows)]
    unsafe {
        // write(2) inexplicably has a different ABI only on Windows.
        libc::write(
            STDERR,
            msg.as_ptr() as *const libc::c_void,
            msg.len() as u32,
        );
    }
    #[cfg(not(windows))]
    unsafe {
        libc::write(STDERR, msg.as_ptr() as *const libc::c_void, msg.len());
    }
}

impl RunLoop {
    /// Sets up a runloop and node, given a config.
    pub fn new(config: Config) -> Self {
        let channels = CoordinatorCommunication::instantiate();
        let should_keep_running = Arc::new(AtomicBool::new(true));
        let pox_watchdog_comms = PoxSyncWatchdogComms::new(should_keep_running.clone());

        let mut event_dispatcher = EventDispatcher::new();
        for observer in config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }

        let dyn_config = DynConfig::new(config.clone());
        Self {
            config,
            dyn_config,
            coordinator_channels: Some(channels),
            callbacks: RunLoopCallbacks::new(),
            counters: Counters::new(),
            should_keep_running: should_keep_running,
            event_dispatcher,
            pox_watchdog: None,
            is_miner: None,
            burnchain: None,
            pox_watchdog_comms,
        }
    }

    pub fn get_coordinator_channel(&self) -> Option<CoordinatorChannels> {
        self.coordinator_channels.as_ref().map(|x| x.1.clone())
    }

    pub fn get_blocks_processed_arc(&self) -> RunLoopCounter {
        self.counters.blocks_processed.clone()
    }

    pub fn get_microblocks_processed_arc(&self) -> RunLoopCounter {
        self.counters.microblocks_processed.clone()
    }

    pub fn get_missed_tenures_arc(&self) -> RunLoopCounter {
        self.counters.missed_tenures.clone()
    }

    pub fn get_missed_microblock_tenures_arc(&self) -> RunLoopCounter {
        self.counters.missed_microblock_tenures.clone()
    }

    pub fn get_cancelled_commits_arc(&self) -> RunLoopCounter {
        self.counters.cancelled_commits.clone()
    }

    pub fn get_counters(&self) -> Counters {
        self.counters.clone()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn dyn_config(&self) -> &DynConfig {
        &self.dyn_config
    }

    pub fn get_event_dispatcher(&self) -> EventDispatcher {
        self.event_dispatcher.clone()
    }

    pub fn is_miner(&self) -> bool {
        self.is_miner.unwrap_or(false)
    }

    pub fn get_pox_sync_comms(&self) -> PoxSyncWatchdogComms {
        self.pox_watchdog_comms.clone()
    }

    pub fn get_termination_switch(&self) -> Arc<AtomicBool> {
        self.should_keep_running.clone()
    }

    pub fn get_burnchain(&self) -> Burnchain {
        self.burnchain
            .clone()
            .expect("FATAL: tried to get runloop burnchain before calling .start()")
    }

    pub fn get_pox_watchdog(&mut self) -> &mut PoxSyncWatchdog {
        self.pox_watchdog
            .as_mut()
            .expect("FATAL: tried to get PoX watchdog before calling .start()")
    }

    /// Set up termination handler.  Have a signal set the `should_keep_running` atomic bool to
    /// false.  Panics of called more than once.
    fn setup_termination_handler(&self) {
        let keep_running_writer = self.should_keep_running.clone();
        let install = termination::set_handler(move |sig_id| match sig_id {
            SignalId::Bus => {
                let msg = "Caught SIGBUS; crashing immediately and dumping core\n";
                async_safe_write_stderr(msg);
                unsafe {
                    libc::abort();
                }
            }
            _ => {
                let msg = format!("Graceful termination request received (signal `{}`), will complete the ongoing runloop cycles and terminate\n", sig_id);
                async_safe_write_stderr(&msg);
                keep_running_writer.store(false, Ordering::SeqCst);
            }
        });

        if let Err(e) = install {
            // integration tests can do this
            if cfg!(test) {
            } else {
                panic!("FATAL: error setting termination handler - {}", e);
            }
        }
    }

    /// Determine if we're the miner.
    /// If there's a network error, then assume that we're not a miner.
    fn check_is_miner(&mut self, burnchain: &mut BitcoinRegtestController) -> bool {
        if self.config.node.miner {
            let keychain = Keychain::default(self.config.node.seed.clone());
            let node_address = Keychain::address_from_burnchain_signer(
                &keychain.get_burnchain_signer(),
                self.config.is_mainnet(),
            );
            let btc_addr = BitcoinAddress::from_bytes(
                self.config.burnchain.get_bitcoin_network().1,
                BitcoinAddressType::PublicKeyHash,
                &node_address.to_bytes(),
            )
            .expect("FATAL: unable to determine Bitcoin address for miner");
            info!("Miner node: checking UTXOs at address: {}", btc_addr);

            match burnchain.create_wallet_if_dne() {
                Err(e) => warn!("Error when creating wallet: {:?}", e),
                _ => {}
            }

            let utxos =
                burnchain.get_utxos(&keychain.generate_op_signer().get_public_key(), 1, None, 0);
            if utxos.is_none() {
                if self.config.node.mock_mining {
                    info!("No UTXOs found, but configured to mock mine");
                    true
                } else {
                    error!("UTXOs not found - switching off mining, will run as a Follower node. If this is unexpected, please ensure that your bitcoind instance is indexing transactions for the address {} (importaddress)", btc_addr);
                    false
                }
            } else {
                info!("UTXOs found - will run as a Miner node");
                true
            }
        } else {
            info!("Will run as a Follower node");
            false
        }
    }

    /// Instantiate the burnchain client and databases.
    /// Fetches headers and instantiates the burnchain.
    /// Panics on failure.
    fn instantiate_burnchain_state(
        &mut self,
        burnchain_opt: Option<Burnchain>,
        coordinator_senders: CoordinatorChannels,
    ) -> BitcoinRegtestController {
        // Initialize and start the burnchain.
        let mut burnchain_controller = BitcoinRegtestController::with_burnchain(
            self.config.clone(),
            self.dyn_config.clone(),
            Some(coordinator_senders),
            burnchain_opt,
            Some(self.should_keep_running.clone()),
        );

        // Upgrade chainstate databases if they exist already
        let epochs = burnchain_controller.get_stacks_epochs();
        match migrate_chainstate_dbs(
            &epochs,
            &self.config.get_burn_db_file_path(),
            &self.config.get_chainstate_path_str(),
            Some(self.config.node.get_marf_opts()),
        ) {
            Ok(_) => {}
            Err(coord_error::DBError(db_error::TooOldForEpoch)) => {
                error!(
                    "FATAL: chainstate database(s) are not compatible with the current system epoch"
                );
                panic!();
            }
            Err(e) => {
                panic!("FATAL: unable to query filesystem or databases: {:?}", &e);
            }
        }

        info!("Start syncing Bitcoin headers, feel free to grab a cup of coffee, this can take a while");

        let burnchain_config = burnchain_controller.get_burnchain();
        let target_burnchain_block_height = match burnchain_config
            .get_highest_burnchain_block()
            .expect("FATAL: failed to access burnchain database")
        {
            Some(burnchain_tip) => {
                // database exists already, and has blocks -- just sync to its tip.
                let target_height = burnchain_tip.block_height + 1;
                debug!("Burnchain DB exists and has blocks up to {}; synchronizing from where it left off up to {}", burnchain_tip.block_height, target_height);
                target_height
            }
            None => {
                // database does not exist yet
                let target_height = 1.max(burnchain_config.first_block_height + 1);
                debug!("Burnchain DB does not exist or does not have blocks; synchronizing to first burnchain block height {}", target_height);
                target_height
            }
        };

        match burnchain_controller.start(Some(target_burnchain_block_height)) {
            Ok(_) => {}
            Err(e) => {
                error!("Burnchain controller stopped: {}", e);
                panic!();
            }
        };

        // if the chainstate DBs don't exist, this will instantiate them
        if let Err(e) = burnchain_controller.connect_dbs() {
            error!("Failed to connect to burnchain databases: {}", e);
            panic!();
        };

        // TODO (hack) instantiate the sortdb in the burnchain
        let _ = burnchain_controller.sortdb_mut();
        burnchain_controller
    }

    /// Instantiate the Stacks chain state and start the chains coordinator thread.
    /// Returns the coordinator thread handle, and the receiving end of the coordinator's atlas
    /// attachment channel.
    fn spawn_chains_coordinator(
        &mut self,
        burnchain_config: &Burnchain,
        coordinator_receivers: CoordinatorReceivers,
    ) -> (JoinHandle<()>, Receiver<HashSet<AttachmentInstance>>) {
        let use_test_genesis_data = use_test_genesis_chainstate(&self.config);

        // load up genesis balances
        let initial_balances = self
            .config
            .initial_balances
            .iter()
            .map(|e| (e.address.clone(), e.amount))
            .collect();

        // load up genesis Atlas attachments
        let mut atlas_config = AtlasConfig::default(self.config.is_mainnet());
        let genesis_attachments = GenesisData::new(use_test_genesis_data)
            .read_name_zonefiles()
            .into_iter()
            .map(|z| Attachment::new(z.zonefile_content.as_bytes().to_vec()))
            .collect();
        atlas_config.genesis_attachments = Some(genesis_attachments);

        // instantiate chainstate
        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash: burnchain_config.first_block_hash,
            first_burnchain_block_height: burnchain_config.first_block_height as u32,
            first_burnchain_block_timestamp: burnchain_config.first_block_timestamp,
            pox_constants: burnchain_config.pox_constants.clone(),
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

        let (chain_state_db, receipts) = StacksChainState::open_and_exec(
            self.config.is_mainnet(),
            self.config.burnchain.chain_id,
            &self.config.get_chainstate_path_str(),
            Some(&mut boot_data),
            Some(self.config.node.get_marf_opts()),
        )
        .unwrap();
        self.event_dispatcher.dispatch_boot_receipts(receipts);

        // NOTE: re-instantiate AtlasConfig so we don't have to keep the genesis attachments around
        let moved_atlas_config = AtlasConfig::default(self.config.is_mainnet());
        let moved_config = self.config.clone();
        let moved_burnchain_config = burnchain_config.clone();
        let mut coordinator_dispatcher = self.event_dispatcher.clone();
        let (attachments_tx, attachments_rx) = sync_channel(ATTACHMENTS_CHANNEL_SIZE);

        let coordinator_thread_handle = thread::Builder::new()
            .name("chains-coordinator".to_string())
            .spawn(move || {
                let mut cost_estimator = moved_config.make_cost_estimator();
                let mut fee_estimator = moved_config.make_fee_estimator();

                ChainsCoordinator::run(
                    chain_state_db,
                    moved_burnchain_config,
                    attachments_tx,
                    &mut coordinator_dispatcher,
                    coordinator_receivers,
                    moved_atlas_config,
                    cost_estimator.as_deref_mut(),
                    fee_estimator.as_deref_mut(),
                );
            })
            .expect("FATAL: failed to start chains coordinator thread");

        (coordinator_thread_handle, attachments_rx)
    }

    /// Instantiate the PoX watchdog
    fn instantiate_pox_watchdog(&mut self) {
        let pox_watchdog = PoxSyncWatchdog::new(&self.config, self.pox_watchdog_comms.clone())
            .expect("FATAL: failed to instantiate PoX sync watchdog");
        self.pox_watchdog = Some(pox_watchdog);
    }

    /// Start Prometheus logging
    fn start_prometheus(&mut self) {
        let prometheus_bind = self.config.node.prometheus_bind.clone();
        if let Some(prometheus_bind) = prometheus_bind {
            thread::Builder::new()
                .name("prometheus".to_string())
                .spawn(move || {
                    start_serving_monitoring_metrics(prometheus_bind);
                })
                .unwrap();
        }
    }

    /// Get the sortition DB's highest block height, aligned to a reward cycle boundary, and the
    /// highest sortition.
    /// Returns (height at rc start, sortition)
    fn get_reward_cycle_sortition_db_height(
        sortdb: &SortitionDB,
        burnchain_config: &Burnchain,
    ) -> (u64, BlockSnapshot) {
        let (stacks_ch, _) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())
            .expect("BUG: failed to load canonical stacks chain tip hash");

        let sn = match SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &stacks_ch)
            .expect("BUG: failed to query sortition DB")
        {
            Some(sn) => sn,
            None => {
                debug!("No canonical stacks chain tip hash present");
                let sn = SortitionDB::get_first_block_snapshot(&sortdb.conn())
                    .expect("BUG: failed to get first-ever block snapshot");
                sn
            }
        };

        (
            burnchain_config.reward_cycle_to_block_height(
                burnchain_config
                    .block_height_to_reward_cycle(sn.block_height)
                    .expect("BUG: snapshot preceeds first reward cycle"),
            ),
            sn,
        )
    }

    /// Starts the node runloop.
    ///
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self, burnchain_opt: Option<Burnchain>, mut mine_start: u64) {
        let (coordinator_receivers, coordinator_senders) = self
            .coordinator_channels
            .take()
            .expect("Run loop already started, can only start once after initialization.");

        self.setup_termination_handler();
        let mut burnchain =
            self.instantiate_burnchain_state(burnchain_opt, coordinator_senders.clone());

        let burnchain_config = burnchain.get_burnchain();
        self.burnchain = Some(burnchain_config.clone());

        let is_miner = self.check_is_miner(&mut burnchain);
        self.is_miner = Some(is_miner);

        // have headers; boot up the chains coordinator and instantiate the chain state
        let (coordinator_thread_handle, attachments_rx) =
            self.spawn_chains_coordinator(&burnchain_config, coordinator_receivers);
        self.instantiate_pox_watchdog();
        self.start_prometheus();

        // We announce a new burn block so that the chains coordinator
        // can resume prior work and handle eventual unprocessed sortitions
        // stored during a previous session.
        coordinator_senders.announce_new_burn_block();

        // Make sure at least one sortition has happened
        let sortdb = burnchain.sortdb_mut();
        let (rc_aligned_height, sn) =
            RunLoop::get_reward_cycle_sortition_db_height(&sortdb, &burnchain_config);

        let burnchain_tip_snapshot = if sn.block_height == burnchain_config.first_block_height {
            // need at least one sortition to happen.
            burnchain
                .wait_for_sortitions(Some(sn.block_height + 1))
                .expect("Unable to get burnchain tip")
                .block_snapshot
        } else {
            sn
        };

        // Boot up the p2p network and relayer, and figure out how many sortitions we have so far
        // (it could be non-zero if the node is resuming from chainstate)
        let mut node = StacksNode::spawn(
            self,
            Some(burnchain_tip_snapshot),
            coordinator_senders.clone(),
            attachments_rx,
        );

        // Wait for all pending sortitions to process
        let mut burnchain_tip = burnchain
            .wait_for_sortitions(None)
            .expect("Unable to get burnchain tip");

        // Start the runloop
        debug!("Begin run loop");
        self.counters.bump_blocks_processed();

        let mut sortition_db_height = rc_aligned_height;
        let mut burnchain_height = sortition_db_height;
        let mut num_sortitions_in_last_cycle = 1;

        // prepare to fetch the first reward cycle!
        let mut target_burnchain_block_height = burnchain_config.reward_cycle_to_block_height(
            burnchain_config
                .block_height_to_reward_cycle(burnchain_height)
                .expect("BUG: block height is not in a reward cycle")
                + 1,
        );

        debug!(
            "Begin main runloop starting a burnchain block {}",
            sortition_db_height
        );

        let mut last_tenure_sortition_height = 0;
        loop {
            if !self.should_keep_running.load(Ordering::SeqCst) {
                // The p2p thread relies on the same atomic_bool, it will
                // discontinue its execution after completing its ongoing runloop epoch.
                info!("Terminating p2p process");
                info!("Terminating relayer");
                info!("Terminating chains-coordinator");

                coordinator_senders.stop_chains_coordinator();
                coordinator_thread_handle.join().unwrap();
                node.join();

                info!("Exiting stacks-node");
                break;
            }

            let remote_chain_height = burnchain.get_headers_height();

            // wait for the p2p state-machine to do at least one pass
            debug!("Wait until Stacks block downloads reach a quiescent state before processing more burnchain blocks"; "remote_chain_height" => remote_chain_height, "local_chain_height" => burnchain_height);

            // wait until it's okay to process the next reward cycle's sortitions
            let ibd = match self.get_pox_watchdog().pox_sync_wait(
                &burnchain_config,
                &burnchain_tip,
                Some(remote_chain_height),
                num_sortitions_in_last_cycle,
            ) {
                Ok(ibd) => ibd,
                Err(e) => {
                    debug!("PoX sync wait routine aborted: {:?}", e);
                    continue;
                }
            };

            // will recalculate this in the following loop
            num_sortitions_in_last_cycle = 0;

            // Download each burnchain block and process their sortitions.  This, in turn, will
            // cause the node's p2p and relayer threads to go fetch and download Stacks blocks and
            // process them.  This loop runs for one reward cycle, so that the next pass of the
            // runloop will cause the PoX sync watchdog to wait until it believes that the node has
            // obtained all the Stacks blocks it can.
            while burnchain_height <= target_burnchain_block_height {
                if !self.should_keep_running.load(Ordering::SeqCst) {
                    break;
                }

                let (next_burnchain_tip, tip_burnchain_height) =
                    match burnchain.sync(Some(burnchain_height + 1)) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!("Burnchain controller stopped: {}", e);
                            continue;
                        }
                    };

                // *now* we know the burnchain height
                burnchain_tip = next_burnchain_tip;
                burnchain_height = cmp::min(burnchain_height + 1, tip_burnchain_height);

                let sortition_tip = &burnchain_tip.block_snapshot.sortition_id;
                let next_sortition_height = burnchain_tip.block_snapshot.block_height;

                if next_sortition_height != last_tenure_sortition_height {
                    info!(
                        "Downloaded burnchain blocks up to height {}; target height is {}; next_sortition_height = {}, sortition_db_height = {}",
                        burnchain_height, target_burnchain_block_height, next_sortition_height, sortition_db_height
                    );
                }

                if next_sortition_height > sortition_db_height {
                    debug!(
                        "New burnchain block height {} > {}",
                        next_sortition_height, sortition_db_height
                    );

                    let mut sort_count = 0;

                    // first, let's process all blocks in (sortition_db_height, next_sortition_height]
                    for block_to_process in (sortition_db_height + 1)..(next_sortition_height + 1) {
                        let block = {
                            let ic = burnchain.sortdb_ref().index_conn();
                            SortitionDB::get_ancestor_snapshot(&ic, block_to_process, sortition_tip)
                                .unwrap()
                                .expect(
                                    "Failed to find block in fork processed by burnchain indexer",
                                )
                        };
                        if block.sortition {
                            sort_count += 1;
                        }

                        let sortition_id = &block.sortition_id;

                        // Have the node process the new block, that can include, or not, a sortition.
                        node.process_burnchain_state(burnchain.sortdb_mut(), sortition_id, ibd);

                        // Now, tell the relayer to check if it won a sortition during this block,
                        // and, if so, to process and advertize the block.  This is basically a
                        // no-op during boot-up.
                        //
                        // _this will block if the relayer's buffer is full_
                        if !node.relayer_sortition_notify() {
                            // relayer hung up, exit.
                            error!("Block relayer and miner hung up, exiting.");
                            return;
                        }
                    }

                    num_sortitions_in_last_cycle = sort_count;
                    debug!(
                        "Synchronized burnchain up to block height {} from {} (chain tip height is {}); {} sortitions",
                        next_sortition_height, sortition_db_height, burnchain_height, num_sortitions_in_last_cycle;
                    );

                    sortition_db_height = next_sortition_height;
                } else if ibd {
                    // drive block processing after we reach the burnchain tip.
                    // we may have downloaded all the blocks already,
                    // so we can't rely on the relayer alone to
                    // drive it.
                    coordinator_senders.announce_new_stacks_block();
                }

                if burnchain_height == target_burnchain_block_height
                    || burnchain_height == tip_burnchain_height
                {
                    break;
                }
            }

            target_burnchain_block_height = burnchain_config.reward_cycle_to_block_height(
                burnchain_config
                    .block_height_to_reward_cycle(burnchain_height)
                    .expect("BUG: block height is not in a reward cycle")
                    + 1,
            );

            if sortition_db_height >= burnchain_height && !ibd {
                let canonical_stacks_tip_height =
                    SortitionDB::get_canonical_burn_chain_tip(burnchain.sortdb_ref().conn())
                        .map(|snapshot| snapshot.canonical_stacks_tip_height)
                        .unwrap_or(0);
                if canonical_stacks_tip_height < mine_start {
                    info!(
                        "Synchronized full burnchain, but stacks tip height is {}, and we are trying to boot to {}, not mining until reaching chain tip",
                        canonical_stacks_tip_height,
                        mine_start
                    );
                } else {
                    // once we've synced to the chain tip once, don't apply this check again.
                    //  this prevents a possible corner case in the event of a PoX fork.
                    mine_start = 0;

                    // at tip, and not downloading. proceed to mine.
                    if last_tenure_sortition_height != sortition_db_height {
                        info!(
                            "Synchronized full burnchain up to height {}. Proceeding to mine blocks",
                            sortition_db_height
                        );
                        last_tenure_sortition_height = sortition_db_height;
                    }
                    if !node.relayer_issue_tenure() {
                        // relayer hung up, exit.
                        error!("Block relayer and miner hung up, exiting.");
                        continue;
                    }
                }
            }
        }
    }
}
