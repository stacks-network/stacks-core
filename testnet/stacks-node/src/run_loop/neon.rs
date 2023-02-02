use std::cmp;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
use std::sync::atomic::AtomicU64;

use std::sync::mpsc::sync_channel;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::thread::JoinHandle;

use std::collections::HashSet;

use stacks::deps::ctrlc as termination;
use stacks::deps::ctrlc::SignalId;

use stacks::burnchains::bitcoin::address::{BitcoinAddress, LegacyBitcoinAddressType};
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::coordinator::comm::{CoordinatorChannels, CoordinatorReceivers};
use stacks::chainstate::coordinator::{
    migrate_chainstate_dbs, static_get_canonical_affirmation_map,
    static_get_heaviest_affirmation_map, static_get_stacks_tip_affirmation_map, ChainsCoordinator,
    ChainsCoordinatorConfig, CoordinatorCommunication, Error as coord_error,
};
use stacks::chainstate::stacks::db::{ChainStateBootData, StacksChainState};
use stacks::core::StacksEpochId;
use stacks::net::atlas::{AtlasConfig, Attachment, AttachmentInstance, ATTACHMENTS_CHANNEL_SIZE};
use stacks::util_lib::db::Error as db_error;
use stx_genesis::GenesisData;

use super::RunLoopCallbacks;
use crate::burnchains::make_bitcoin_indexer;
use crate::monitoring::start_serving_monitoring_metrics;
use crate::neon_node::Globals;
use crate::neon_node::StacksNode;
use crate::neon_node::BLOCK_PROCESSOR_STACK_SIZE;
use crate::neon_node::RELAYER_MAX_BUFFER;
use crate::node::use_test_genesis_chainstate;
use crate::syncctl::{PoxSyncWatchdog, PoxSyncWatchdogComms};
use crate::{
    node::{get_account_balances, get_account_lockups, get_names, get_namespaces},
    run_loop, BitcoinRegtestController, BurnchainController, Config, EventDispatcher, Keychain,
};
use stacks::chainstate::stacks::miner::{signal_mining_blocked, signal_mining_ready, MinerStatus};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::sleep_ms;

use libc;
use stacks::util::hash::Hash160;
use stacks_common::types::PublicKey;
pub const STDERR: i32 = 2;

#[cfg(test)]
pub type RunLoopCounter = Arc<AtomicU64>;

#[cfg(not(test))]
pub type RunLoopCounter = ();

#[cfg(test)]
const UNCONDITIONAL_CHAIN_LIVENESS_CHECK: u64 = 30;

#[cfg(not(test))]
const UNCONDITIONAL_CHAIN_LIVENESS_CHECK: u64 = 300;

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
    pub callbacks: RunLoopCallbacks,
    globals: Option<Globals>,
    counters: Counters,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>,
    should_keep_running: Arc<AtomicBool>,
    event_dispatcher: EventDispatcher,
    pox_watchdog: Option<PoxSyncWatchdog>, // can't be instantiated until .start() is called
    is_miner: Option<bool>,                // not known until .start() is called
    burnchain: Option<Burnchain>,          // not known until .start() is called
    pox_watchdog_comms: PoxSyncWatchdogComms,
    /// NOTE: this is duplicated in self.globals, but it needs to be accessible before globals is
    /// instantiated (namely, so the test framework can access it).
    miner_status: Arc<Mutex<MinerStatus>>,
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
        let miner_status = Arc::new(Mutex::new(MinerStatus::make_ready(
            config.burnchain.burn_fee_cap,
        )));

        let mut event_dispatcher = EventDispatcher::new();
        for observer in config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }

        Self {
            config,
            globals: None,
            coordinator_channels: Some(channels),
            callbacks: RunLoopCallbacks::new(),
            counters: Counters::new(),
            should_keep_running: should_keep_running,
            event_dispatcher,
            pox_watchdog: None,
            is_miner: None,
            burnchain: None,
            pox_watchdog_comms,
            miner_status,
        }
    }

    pub fn get_globals(&self) -> Globals {
        self.globals
            .clone()
            .expect("FATAL: globals not instantiated")
    }

    fn set_globals(&mut self, globals: Globals) {
        self.globals = Some(globals);
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
        self.get_globals().should_keep_running.clone()
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

    pub fn get_miner_status(&self) -> Arc<Mutex<MinerStatus>> {
        self.miner_status.clone()
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
            let mut op_signer = keychain.generate_op_signer();
            match burnchain.create_wallet_if_dne() {
                Err(e) => warn!("Error when creating wallet: {:?}", e),
                _ => {}
            }
            let mut btc_addrs = vec![(
                StacksEpochId::Epoch2_05,
                // legacy
                BitcoinAddress::from_bytes_legacy(
                    self.config.burnchain.get_bitcoin_network().1,
                    LegacyBitcoinAddressType::PublicKeyHash,
                    &Hash160::from_data(&op_signer.get_public_key().to_bytes()).0,
                )
                .expect("FATAL: failed to construct legacy bitcoin address"),
            )];
            if self.config.miner.segwit {
                btc_addrs.push((
                    StacksEpochId::Epoch21,
                    // segwit p2wpkh
                    BitcoinAddress::from_bytes_segwit_p2wpkh(
                        self.config.burnchain.get_bitcoin_network().1,
                        &Hash160::from_data(&op_signer.get_public_key().to_bytes_compressed()).0,
                    )
                    .expect("FATAL: failed to construct segwit p2wpkh address"),
                ));
            }

            for (epoch_id, btc_addr) in btc_addrs.into_iter() {
                info!("Miner node: checking UTXOs at address: {}", &btc_addr);
                let utxos = burnchain.get_utxos(epoch_id, &op_signer.get_public_key(), 1, None, 0);
                if utxos.is_none() {
                    warn!("UTXOs not found for {}. If this is unexpected, please ensure that your bitcoind instance is indexing transactions for the address {} (importaddress)", btc_addr, btc_addr);
                } else {
                    info!("UTXOs found - will run as a Miner node");
                    return true;
                }
            }
            if self.config.node.mock_mining {
                info!("No UTXOs found, but configured to mock mine");
                return true;
            } else {
                return false;
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
            Some(coordinator_senders),
            burnchain_opt,
            Some(self.should_keep_running.clone()),
        );

        let burnchain = burnchain_controller.get_burnchain();
        let epochs = burnchain_controller.get_stacks_epochs();

        // sanity check -- epoch data must be valid
        Config::assert_valid_epoch_settings(&burnchain, &epochs);

        // Upgrade chainstate databases if they exist already
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

    /// Boot up the stacks chainstate.
    /// Instantiate the chainstate and push out the boot receipts to observers
    /// This is only public so we can test it.
    pub fn boot_chainstate(&mut self, burnchain_config: &Burnchain) -> StacksChainState {
        let use_test_genesis_data = use_test_genesis_chainstate(&self.config);

        // load up genesis balances
        let initial_balances = self
            .config
            .initial_balances
            .iter()
            .map(|e| (e.address.clone(), e.amount))
            .collect();

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
        run_loop::announce_boot_receipts(
            &mut self.event_dispatcher,
            &chain_state_db,
            &burnchain_config.pox_constants,
            &receipts,
        );
        chain_state_db
    }

    /// Instantiate the Stacks chain state and start the chains coordinator thread.
    /// Returns the coordinator thread handle, and the receiving end of the coordinator's atlas
    /// attachment channel.
    fn spawn_chains_coordinator(
        &mut self,
        burnchain_config: &Burnchain,
        coordinator_receivers: CoordinatorReceivers,
        miner_status: Arc<Mutex<MinerStatus>>,
    ) -> (JoinHandle<()>, Receiver<HashSet<AttachmentInstance>>) {
        let use_test_genesis_data = use_test_genesis_chainstate(&self.config);

        // load up genesis Atlas attachments
        let mut atlas_config = AtlasConfig::default(self.config.is_mainnet());
        let genesis_attachments = GenesisData::new(use_test_genesis_data)
            .read_name_zonefiles()
            .into_iter()
            .map(|z| Attachment::new(z.zonefile_content.as_bytes().to_vec()))
            .collect();
        atlas_config.genesis_attachments = Some(genesis_attachments);

        let chain_state_db = self.boot_chainstate(burnchain_config);

        // NOTE: re-instantiate AtlasConfig so we don't have to keep the genesis attachments around
        let moved_atlas_config = AtlasConfig::default(self.config.is_mainnet());
        let moved_config = self.config.clone();
        let moved_burnchain_config = burnchain_config.clone();
        let mut coordinator_dispatcher = self.event_dispatcher.clone();
        let (attachments_tx, attachments_rx) = sync_channel(ATTACHMENTS_CHANNEL_SIZE);
        let coordinator_indexer = make_bitcoin_indexer(&self.config);

        let coordinator_thread_handle = thread::Builder::new()
            .name(format!(
                "chains-coordinator-{}",
                &moved_config.node.rpc_bind
            ))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                debug!(
                    "chains-coordinator thread ID is {:?}",
                    thread::current().id()
                );
                let mut cost_estimator = moved_config.make_cost_estimator();
                let mut fee_estimator = moved_config.make_fee_estimator();

                let coord_config = ChainsCoordinatorConfig {
                    always_use_affirmation_maps: moved_config.node.always_use_affirmation_maps,
                    require_affirmed_anchor_blocks: moved_config
                        .node
                        .require_affirmed_anchor_blocks,
                    ..ChainsCoordinatorConfig::new()
                };
                ChainsCoordinator::run(
                    coord_config,
                    chain_state_db,
                    moved_burnchain_config,
                    attachments_tx,
                    &mut coordinator_dispatcher,
                    coordinator_receivers,
                    moved_atlas_config,
                    cost_estimator.as_deref_mut(),
                    fee_estimator.as_deref_mut(),
                    miner_status,
                    coordinator_indexer,
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
                    debug!("prometheus thread ID is {:?}", thread::current().id());
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

    /// Wake up and drive stacks block processing if there's been a PoX reorg.
    /// Be careful not to saturate calls to announce new stacks blocks, because that will disable
    /// mining (which would prevent a miner attempting to fix a hidden PoX anchor block from making
    /// progress).
    fn drive_pox_reorg_stacks_block_processing(
        globals: &Globals,
        config: &Config,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        last_stacks_pox_reorg_recover_time: &mut u128,
    ) {
        let delay = cmp::max(
            1,
            cmp::max(
                config.miner.first_attempt_time_ms,
                config.miner.subsequent_attempt_time_ms,
            ) / 1000,
        );

        if *last_stacks_pox_reorg_recover_time + (delay as u128) >= get_epoch_time_secs().into() {
            // too soon
            return;
        }

        // compare stacks and heaviest AMs
        let burnchain_db = burnchain
            .open_burnchain_db(false)
            .expect("FATAL: failed to open burnchain DB");

        let sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: could not read sortition DB");

        let indexer = make_bitcoin_indexer(config);

        let heaviest_affirmation_map = match static_get_heaviest_affirmation_map(
            &burnchain,
            &indexer,
            &burnchain_db,
            sortdb,
            &sn.sortition_id,
        ) {
            Ok(am) => am,
            Err(e) => {
                warn!("Failed to find heaviest affirmation map: {:?}", &e);
                return;
            }
        };

        let highest_sn = SortitionDB::get_highest_known_burn_chain_tip(sortdb.conn())
            .expect("FATAL: could not read sortition DB");

        let canonical_burnchain_tip = burnchain_db
            .get_canonical_chain_tip()
            .expect("FATAL: could not read burnchain DB");

        let sortition_tip_affirmation_map =
            match SortitionDB::find_sortition_tip_affirmation_map(sortdb, &sn.sortition_id) {
                Ok(am) => am,
                Err(e) => {
                    warn!("Failed to find sortition affirmation map: {:?}", &e);
                    return;
                }
            };

        let stacks_tip_affirmation_map = static_get_stacks_tip_affirmation_map(
            &burnchain_db,
            sortdb,
            &sn.sortition_id,
            &sn.canonical_stacks_tip_consensus_hash,
            &sn.canonical_stacks_tip_hash,
        )
        .expect("FATAL: could not query stacks DB");

        if stacks_tip_affirmation_map.len() < heaviest_affirmation_map.len()
            || stacks_tip_affirmation_map
                .find_divergence(&heaviest_affirmation_map)
                .is_some()
        {
            // the sortition affirmation map might also be inconsistent, so we'll need to fix that
            // (i.e. the underlying sortitions) before we can fix the stacks fork
            if sortition_tip_affirmation_map.len() < heaviest_affirmation_map.len()
                || sortition_tip_affirmation_map
                    .find_divergence(&heaviest_affirmation_map)
                    .is_some()
            {
                debug!("Drive burn block processing: possible PoX reorg (sortition tip: {}, heaviest: {})", &sortition_tip_affirmation_map, &heaviest_affirmation_map);
                globals.coord().announce_new_burn_block();
            } else if highest_sn.block_height == sn.block_height
                && sn.block_height == canonical_burnchain_tip.block_height
            {
                // need to force an affirmation reorg because there will be no more burn block
                // announcements.
                debug!("Drive burn block processing: possible PoX reorg (sortition tip: {}, heaviest: {}, burn height {})", &sortition_tip_affirmation_map, &heaviest_affirmation_map, sn.block_height);
                globals.coord().announce_new_burn_block();
            }

            debug!(
                "Drive stacks block processing: possible PoX reorg (stacks tip: {}, heaviest: {})",
                &stacks_tip_affirmation_map, &heaviest_affirmation_map
            );
            globals.coord().announce_new_stacks_block();
        } else {
            debug!(
                "Drive stacks block processing: no need (stacks tip: {}, heaviest: {})",
                &stacks_tip_affirmation_map, &heaviest_affirmation_map
            );

            // do it anyway since it's harmless
            globals.coord().announce_new_stacks_block();
        }

        *last_stacks_pox_reorg_recover_time = get_epoch_time_secs().into();
    }

    /// Wake up and drive sortition processing if there's been a PoX reorg.
    /// Be careful not to saturate calls to announce new burn blocks, because that will disable
    /// mining (which would prevent a miner attempting to fix a hidden PoX anchor block from making
    /// progress).
    ///
    /// only call if no in ibd
    fn drive_pox_reorg_burn_block_processing(
        globals: &Globals,
        config: &Config,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chain_state_db: &StacksChainState,
        last_burn_pox_reorg_recover_time: &mut u128,
        last_announce_time: &mut u128,
    ) {
        let delay = cmp::max(
            1,
            cmp::max(
                config.miner.first_attempt_time_ms,
                config.miner.subsequent_attempt_time_ms,
            ) / 1000,
        );

        if *last_burn_pox_reorg_recover_time + (delay as u128) >= get_epoch_time_secs().into() {
            // too soon
            return;
        }

        // compare sortition and heaviest AMs
        let burnchain_db = burnchain
            .open_burnchain_db(false)
            .expect("FATAL: failed to open burnchain DB");

        let highest_sn = SortitionDB::get_highest_known_burn_chain_tip(sortdb.conn())
            .expect("FATAL: could not read sortition DB");

        let canonical_burnchain_tip = burnchain_db
            .get_canonical_chain_tip()
            .expect("FATAL: could not read burnchain DB");

        if canonical_burnchain_tip.block_height > highest_sn.block_height {
            // still processing sortitions
            test_debug!(
                "Drive burn block processing: still processing sortitions ({} > {})",
                canonical_burnchain_tip.block_height,
                highest_sn.block_height
            );
            return;
        }

        // NOTE: this could be lower than the highest_sn
        let sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: could not read sortition DB");

        let sortition_tip_affirmation_map =
            match SortitionDB::find_sortition_tip_affirmation_map(sortdb, &sn.sortition_id) {
                Ok(am) => am,
                Err(e) => {
                    warn!("Failed to find sortition affirmation map: {:?}", &e);
                    return;
                }
            };

        let indexer = make_bitcoin_indexer(config);

        let heaviest_affirmation_map = match static_get_heaviest_affirmation_map(
            &burnchain,
            &indexer,
            &burnchain_db,
            sortdb,
            &sn.sortition_id,
        ) {
            Ok(am) => am,
            Err(e) => {
                warn!("Failed to find heaviest affirmation map: {:?}", &e);
                return;
            }
        };

        let canonical_affirmation_map = match static_get_canonical_affirmation_map(
            &burnchain,
            &indexer,
            &burnchain_db,
            sortdb,
            &chain_state_db,
            &sn.sortition_id,
        ) {
            Ok(am) => am,
            Err(e) => {
                warn!("Failed to find canonical affirmation map: {:?}", &e);
                return;
            }
        };

        if sortition_tip_affirmation_map.len() < heaviest_affirmation_map.len()
            || sortition_tip_affirmation_map
                .find_divergence(&heaviest_affirmation_map)
                .is_some()
            || sn.block_height < highest_sn.block_height
        {
            debug!("Drive burn block processing: possible PoX reorg (sortition tip: {}, heaviest: {}, {} <? {})", &sortition_tip_affirmation_map, &heaviest_affirmation_map, sn.block_height, highest_sn.block_height);
            globals.coord().announce_new_burn_block();
            globals.coord().announce_new_stacks_block();
            *last_announce_time = get_epoch_time_secs().into();
        } else if sortition_tip_affirmation_map.len() >= heaviest_affirmation_map.len()
            && sortition_tip_affirmation_map.len() <= canonical_affirmation_map.len()
        {
            if let Some(divergence_rc) =
                canonical_affirmation_map.find_divergence(&sortition_tip_affirmation_map)
            {
                if divergence_rc + 1 >= (heaviest_affirmation_map.len() as u64) {
                    // we have unaffirmed PoX anchor blocks that are not yet processed in the sortition history
                    debug!("Drive burnchain processing: possible PoX reorg from unprocessed anchor block(s) (sortition tip: {}, heaviest: {}, canonical: {})", &sortition_tip_affirmation_map, &heaviest_affirmation_map, &canonical_affirmation_map);
                    globals.coord().announce_new_burn_block();
                    globals.coord().announce_new_stacks_block();
                    *last_announce_time = get_epoch_time_secs().into();
                }
            }
        } else {
            debug!(
                "Drive burn block processing: no need (sortition tip: {}, heaviest: {}, {} </ {})",
                &sortition_tip_affirmation_map,
                &heaviest_affirmation_map,
                sn.block_height,
                highest_sn.block_height
            );
        }

        *last_burn_pox_reorg_recover_time = get_epoch_time_secs().into();

        // unconditionally bump every 5 minutes, just in case.
        // this can get the node un-stuck if we're short on sortition processing but are unable to
        // sync with the remote node because it keeps NACK'ing us, leading to a runloop stall.
        if *last_announce_time + (UNCONDITIONAL_CHAIN_LIVENESS_CHECK as u128)
            < get_epoch_time_secs().into()
        {
            debug!("Drive burnchain processing: unconditional bump");
            globals.coord().announce_new_burn_block();
            globals.coord().announce_new_stacks_block();
            *last_announce_time = get_epoch_time_secs().into();
        }
    }

    /// In a separate thread, periodically drive coordinator liveness by checking to see if there's
    /// a pending reorg and if so, waking up the coordinator to go and process new blocks
    fn drive_chain_liveness(
        globals: Globals,
        config: Config,
        burnchain: Burnchain,
        sortdb: SortitionDB,
        chain_state_db: StacksChainState,
    ) {
        let mut last_burn_pox_reorg_recover_time = 0;
        let mut last_stacks_pox_reorg_recover_time = 0;
        let mut last_burn_announce_time = 0;

        debug!("Chain-liveness thread start!");

        while globals.keep_running() {
            debug!("Chain-liveness checkup");
            Self::drive_pox_reorg_burn_block_processing(
                &globals,
                &config,
                &burnchain,
                &sortdb,
                &chain_state_db,
                &mut last_burn_pox_reorg_recover_time,
                &mut last_burn_announce_time,
            );
            Self::drive_pox_reorg_stacks_block_processing(
                &globals,
                &config,
                &burnchain,
                &sortdb,
                &mut last_stacks_pox_reorg_recover_time,
            );

            sleep_ms(3000);
        }

        debug!("Chain-liveness thread exit!");
    }

    /// Spawn a thread to drive chain liveness
    fn spawn_chain_liveness_thread(&self, globals: Globals) -> JoinHandle<()> {
        let config = self.config.clone();
        let burnchain = self.get_burnchain();
        let sortdb = burnchain
            .open_sortition_db(true)
            .expect("FATAL: could not open sortition DB");

        let (chain_state_db, _) = StacksChainState::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            Some(config.node.get_marf_opts()),
        )
        .unwrap();

        let liveness_thread_handle = thread::Builder::new()
            .name(format!("chain-liveness-{}", config.node.rpc_bind))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                Self::drive_chain_liveness(globals, config, burnchain, sortdb, chain_state_db)
            })
            .expect("FATAL: failed to spawn chain liveness thread");

        liveness_thread_handle
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

        // can we mine?
        let is_miner = self.check_is_miner(&mut burnchain);
        self.is_miner = Some(is_miner);

        // relayer linkup
        let (relay_send, relay_recv) = sync_channel(RELAYER_MAX_BUFFER);

        // set up globals so other subsystems can instantiate off of the runloop state.
        let globals = Globals::new(
            coordinator_senders,
            self.get_miner_status(),
            relay_send,
            self.counters.clone(),
            self.pox_watchdog_comms.clone(),
            self.should_keep_running.clone(),
        );
        self.set_globals(globals.clone());

        // have headers; boot up the chains coordinator and instantiate the chain state
        let (coordinator_thread_handle, attachments_rx) = self.spawn_chains_coordinator(
            &burnchain_config,
            coordinator_receivers,
            globals.get_miner_status(),
        );
        self.instantiate_pox_watchdog();
        self.start_prometheus();

        // We announce a new burn block so that the chains coordinator
        // can resume prior work and handle eventual unprocessed sortitions
        // stored during a previous session.
        globals.coord().announce_new_burn_block();

        // Make sure at least one sortition has happened, and make sure it's globally available
        let sortdb = burnchain.sortdb_mut();
        let (rc_aligned_height, sn) =
            RunLoop::get_reward_cycle_sortition_db_height(&sortdb, &burnchain_config);

        let burnchain_tip_snapshot = if sn.block_height == burnchain_config.first_block_height {
            // need at least one sortition to happen.
            burnchain
                .wait_for_sortitions(globals.coord().clone(), sn.block_height + 1)
                .expect("Unable to get burnchain tip")
                .block_snapshot
        } else {
            sn
        };

        globals.set_last_sortition(burnchain_tip_snapshot.clone());

        // Boot up the p2p network and relayer, and figure out how many sortitions we have so far
        // (it could be non-zero if the node is resuming from chainstate)
        let mut node = StacksNode::spawn(self, globals.clone(), relay_recv, attachments_rx);
        let liveness_thread = self.spawn_chain_liveness_thread(globals.clone());

        // Wait for all pending sortitions to process
        let burnchain_db = burnchain_config
            .open_burnchain_db(false)
            .expect("FATAL: failed to open burnchain DB");
        let burnchain_db_tip = burnchain_db
            .get_canonical_chain_tip()
            .expect("FATAL: failed to query burnchain DB");
        let mut burnchain_tip = burnchain
            .wait_for_sortitions(globals.coord().clone(), burnchain_db_tip.block_height)
            .expect("Unable to get burnchain tip");

        // Start the runloop
        debug!("Runloop: Begin run loop");
        self.counters.bump_blocks_processed();

        let mut sortition_db_height = rc_aligned_height;
        let mut burnchain_height = sortition_db_height;
        let mut num_sortitions_in_last_cycle = 1;

        // prepare to fetch the first reward cycle!
        let mut target_burnchain_block_height = cmp::min(
            burnchain_config.reward_cycle_to_block_height(
                burnchain_config
                    .block_height_to_reward_cycle(burnchain_height)
                    .expect("BUG: block height is not in a reward cycle")
                    + 1,
            ),
            burnchain.get_headers_height() - 1,
        );

        debug!(
            "Runloop: Begin main runloop starting a burnchain block {}",
            sortition_db_height
        );

        let mut last_tenure_sortition_height = 0;

        loop {
            if !globals.keep_running() {
                // The p2p thread relies on the same atomic_bool, it will
                // discontinue its execution after completing its ongoing runloop epoch.
                info!("Terminating p2p process");
                info!("Terminating relayer");
                info!("Terminating chains-coordinator");

                globals.coord().stop_chains_coordinator();
                coordinator_thread_handle.join().unwrap();
                node.join();
                liveness_thread.join().unwrap();

                info!("Exiting stacks-node");
                break;
            }

            let remote_chain_height = burnchain.get_headers_height() - 1;

            // wait for the p2p state-machine to do at least one pass
            debug!("Runloop: Wait until Stacks block downloads reach a quiescent state before processing more burnchain blocks"; "remote_chain_height" => remote_chain_height, "local_chain_height" => burnchain_height);

            // wait until it's okay to process the next reward cycle's sortitions
            let ibd = match self.get_pox_watchdog().pox_sync_wait(
                &burnchain_config,
                &burnchain_tip,
                Some(remote_chain_height),
                num_sortitions_in_last_cycle,
            ) {
                Ok(ibd) => ibd,
                Err(e) => {
                    debug!("Runloop: PoX sync wait routine aborted: {:?}", e);
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
            debug!(
                "Runloop: Download burnchain blocks up to reward cycle #{} (height {})",
                burnchain_config
                    .block_height_to_reward_cycle(target_burnchain_block_height)
                    .expect("FATAL: target burnchain block height does not have a reward cycle"),
                target_burnchain_block_height,
            );

            loop {
                if !globals.keep_running() {
                    break;
                }

                let (next_burnchain_tip, tip_burnchain_height) =
                    match burnchain.sync(Some(target_burnchain_block_height)) {
                        Ok(x) => x,
                        Err(e) => {
                            warn!("Runloop: Burnchain controller stopped: {}", e);
                            continue;
                        }
                    };

                // *now* we know the burnchain height
                burnchain_tip = next_burnchain_tip;
                burnchain_height = tip_burnchain_height;

                let sortition_tip = &burnchain_tip.block_snapshot.sortition_id;
                let next_sortition_height = burnchain_tip.block_snapshot.block_height;

                if next_sortition_height != last_tenure_sortition_height {
                    info!(
                        "Runloop: Downloaded burnchain blocks up to height {}; target height is {}; remote_chain_height = {} next_sortition_height = {}, sortition_db_height = {}",
                        burnchain_height, target_burnchain_block_height, remote_chain_height, next_sortition_height, sortition_db_height
                    );
                }

                if next_sortition_height > sortition_db_height {
                    debug!(
                        "Runloop: New burnchain block height {} > {}",
                        next_sortition_height, sortition_db_height
                    );

                    let mut sort_count = 0;

                    debug!("Runloop: block mining until we process all sortitions");
                    signal_mining_blocked(globals.get_miner_status());

                    // first, let's process all blocks in (sortition_db_height, next_sortition_height]
                    for block_to_process in (sortition_db_height + 1)..(next_sortition_height + 1) {
                        // stop mining so we can advance the sortition DB and so our
                        // ProcessTenure() directive (sent by relayer_sortition_notify() below)
                        // will be unblocked.

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
                            error!("Runloop: Block relayer and miner hung up, exiting.");
                            return;
                        }
                    }

                    debug!("Runloop: enable miner after processing sortitions");
                    signal_mining_ready(globals.get_miner_status());

                    num_sortitions_in_last_cycle = sort_count;
                    debug!(
                        "Runloop: Synchronized sortitions up to block height {} from {} (chain tip height is {}); {} sortitions",
                        next_sortition_height, sortition_db_height, burnchain_height, num_sortitions_in_last_cycle;
                    );

                    sortition_db_height = next_sortition_height;
                } else if ibd {
                    // drive block processing after we reach the burnchain tip.
                    // we may have downloaded all the blocks already,
                    // so we can't rely on the relayer alone to
                    // drive it.
                    globals.coord().announce_new_stacks_block();
                }

                if burnchain_height >= target_burnchain_block_height
                    || burnchain_height >= remote_chain_height
                {
                    break;
                }
            }

            // advance one reward cycle at a time.
            // If we're still downloading, then this is simply target_burnchain_block_height + reward_cycle_len.
            // Otherwise, this is burnchain_tip + reward_cycle_len
            let next_target_burnchain_block_height = cmp::min(
                burnchain_config.reward_cycle_to_block_height(
                    burnchain_config
                        .block_height_to_reward_cycle(target_burnchain_block_height)
                        .expect("FATAL: burnchain height before system start")
                        + 1,
                ),
                remote_chain_height,
            );

            debug!("Runloop: Advance target burnchain block height from {} to {} (sortition height {})", target_burnchain_block_height, next_target_burnchain_block_height, sortition_db_height);
            target_burnchain_block_height = next_target_burnchain_block_height;

            if sortition_db_height >= burnchain_height && !ibd {
                let canonical_stacks_tip_height =
                    SortitionDB::get_canonical_burn_chain_tip(burnchain.sortdb_ref().conn())
                        .map(|snapshot| snapshot.canonical_stacks_tip_height)
                        .unwrap_or(0);
                if canonical_stacks_tip_height < mine_start {
                    info!(
                        "Runloop: Synchronized full burnchain, but stacks tip height is {}, and we are trying to boot to {}, not mining until reaching chain tip",
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
                            "Runloop: Synchronized full burnchain up to height {}. Proceeding to mine blocks",
                            sortition_db_height
                        );
                        last_tenure_sortition_height = sortition_db_height;
                    }

                    if !node.relayer_issue_tenure(ibd) {
                        // relayer hung up, exit.
                        error!("Runloop: Block relayer and miner hung up, exiting.");
                        break;
                    }
                }
            }
        }
    }
}
