use std::cmp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::thread;

use stacks::deps::ctrlc as termination;
use stacks::deps::ctrlc::SignalId;

use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::coordinator::comm::{CoordinatorChannels, CoordinatorReceivers};
use stacks::chainstate::coordinator::{
    check_chainstate_db_versions, BlockEventDispatcher, ChainsCoordinator, CoordinatorCommunication,
};
use stacks::chainstate::stacks::db::{ChainStateBootData, StacksChainState};
use stacks::net::atlas::{AtlasConfig, Attachment};
use stx_genesis::GenesisData;

use crate::appchain::make_burnchain_client;
use crate::monitoring::start_serving_monitoring_metrics;
use crate::node::{
    get_account_balances, get_account_lockups, get_names, get_namespaces,
    use_test_genesis_chainstate,
};
use crate::syncctl::PoxSyncWatchdog;
use crate::{Config, EventDispatcher, NeonGenesisNode};

use super::RunLoopCallbacks;
use libc;
pub const STDERR: i32 = 2;

/// Coordinating a node running in neon mode.
#[cfg(test)]
pub struct RunLoop {
    config: Config,
    pub callbacks: RunLoopCallbacks,
    blocks_processed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    microblocks_processed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>,
}

#[cfg(not(test))]
pub struct RunLoop {
    config: Config,
    pub callbacks: RunLoopCallbacks,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>,
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
    #[cfg(not(test))]
    pub fn new(config: Config) -> Self {
        let channels = CoordinatorCommunication::instantiate();
        Self {
            config,
            coordinator_channels: Some(channels),
            callbacks: RunLoopCallbacks::new(),
        }
    }

    #[cfg(test)]
    pub fn new(config: Config) -> Self {
        let channels = CoordinatorCommunication::instantiate();
        Self {
            config,
            coordinator_channels: Some(channels),
            callbacks: RunLoopCallbacks::new(),
            blocks_processed: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            microblocks_processed: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn get_coordinator_channel(&self) -> Option<CoordinatorChannels> {
        self.coordinator_channels.as_ref().map(|x| x.1.clone())
    }

    #[cfg(test)]
    pub fn get_blocks_processed_arc(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.blocks_processed.clone()
    }

    #[cfg(not(test))]
    fn get_blocks_processed_arc(&self) {}

    #[cfg(test)]
    pub fn get_microblocks_processed_arc(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.microblocks_processed.clone()
    }

    #[cfg(not(test))]
    fn get_microblocks_processed_arc(&self) {}

    #[cfg(test)]
    fn bump_blocks_processed(&self) {
        self.blocks_processed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(not(test))]
    fn bump_blocks_processed(&self) {}

    /// Starts the testnet runloop.
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

        let should_keep_running = Arc::new(AtomicBool::new(true));
        let keep_running_writer = should_keep_running.clone();

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

        // Initialize and start the burnchain client.
        let mut burnchain_client = make_burnchain_client(
            self.config.clone(),
            burnchain_opt,
            coordinator_senders.clone(),
            should_keep_running.clone(),
        );

        let burnchain_config = burnchain_client.get_burnchain();
        let pox_constants = burnchain_config.pox_constants.clone();
        let epochs = burnchain_client.get_stacks_epochs();
        if !check_chainstate_db_versions(
            &epochs,
            &self.config.get_burn_db_file_path(),
            &self.config.get_chainstate_path_str(),
        )
        .expect("FATAL: unable to query filesystem or databases for version information")
        {
            panic!(
                "FATAL: chainstate database(s) are not compatible with the current system epoch"
            );
        }

        let is_miner = if self.config.node.miner {
            burnchain_client.can_mine()
        } else {
            info!("Will run as a Follower node");
            false
        };

        let mut target_burnchain_block_height = 1.max(burnchain_config.first_block_height);

        info!("Start syncing burnchain headers up to height {}, feel free to grab a cup of coffee, this can take a while", target_burnchain_block_height);
        match burnchain_client.start(Some(target_burnchain_block_height)) {
            Ok(_) => {}
            Err(e) => {
                error!("Burnchain controller stopped: {}", e);
                return;
            }
        };
        debug!("Header sync finished");

        // Invoke connect_dbs() to perform any db instantiation early
        if let Err(e) = burnchain_client.connect_dbs() {
            error!("Failed to connect to burnchain databases: {}", e);
            return;
        };

        let mainnet = self.config.is_mainnet();
        let chainid = self.config.burnchain.chain_id;
        let is_appchain = self.config.describes_appchain();
        let initial_balances = self
            .config
            .initial_balances
            .iter()
            .map(|e| (e.address.clone(), e.amount))
            .collect();

        // setup dispatcher
        let mut event_dispatcher = EventDispatcher::new();
        for observer in self.config.events_observers.iter() {
            event_dispatcher.register_observer(observer, should_keep_running.clone());
        }

        let use_test_genesis_data = use_test_genesis_chainstate(&self.config);

        let mut atlas_config = AtlasConfig::default(false);
        let genesis_attachments = GenesisData::new(use_test_genesis_data)
            .read_name_zonefiles()
            .into_iter()
            .map(|z| Attachment::new(z.zonefile_content.as_bytes().to_vec()))
            .collect();
        atlas_config.genesis_attachments = Some(genesis_attachments);

        let mut coordinator_dispatcher = event_dispatcher.clone();

        let chainstate_path = self.config.get_chainstate_path_str();
        let coordinator_burnchain_config = burnchain_config.clone();

        let (attachments_tx, attachments_rx) = sync_channel(1);

        let mut boot_data =
            if let Some(appchain_runtime) = self.config.burnchain.appchain_runtime.as_ref() {
                // appchain mode
                debug!(
                    "Instantiate appchain {} state at {:?}",
                    chainid, &chainstate_path
                );
                ChainStateBootData::new_appchain(
                    mainnet,
                    &coordinator_burnchain_config,
                    initial_balances,
                    appchain_runtime.boot_code.clone(),
                    appchain_runtime.config.genesis_hash(),
                )
            } else {
                // mainchain node
                debug!(
                    "Instantiate Stacks mainchain state at {:?}",
                    &chainstate_path
                );
                let mut boot_data =
                    ChainStateBootData::new(&coordinator_burnchain_config, initial_balances, None);
                boot_data.get_bulk_initial_lockups =
                    Some(Box::new(move || get_account_lockups(use_test_genesis_data)));
                boot_data.get_bulk_initial_balances = Some(Box::new(move || {
                    get_account_balances(use_test_genesis_data)
                }));
                boot_data.get_bulk_initial_namespaces =
                    Some(Box::new(move || get_namespaces(use_test_genesis_data)));
                boot_data.get_bulk_initial_names =
                    Some(Box::new(move || get_names(use_test_genesis_data)));
                boot_data
            };

        let (chain_state_db, receipts) = StacksChainState::open_and_exec(
            mainnet,
            chainid,
            &chainstate_path,
            Some(&mut boot_data),
        )
        .unwrap();
        coordinator_dispatcher.dispatch_boot_receipts(receipts);

        let atlas_config = AtlasConfig::default(mainnet);
        let moved_atlas_config = atlas_config.clone();
        let moved_config = self.config.clone();

        let coordinator_thread_handle = thread::Builder::new()
            .name(format!(
                "chains-coordinator{}",
                if is_appchain { "-appchain" } else { "" }
            ))
            .spawn(move || {
                let mut cost_estimator = moved_config.make_cost_estimator();
                let mut fee_estimator = moved_config.make_fee_estimator();

                ChainsCoordinator::run(
                    chain_state_db,
                    coordinator_burnchain_config,
                    attachments_tx,
                    &mut coordinator_dispatcher,
                    coordinator_receivers,
                    moved_atlas_config,
                    cost_estimator.as_deref_mut(),
                    fee_estimator.as_deref_mut(),
                );
            })
            .unwrap();

        // We announce a new burn block so that the chains coordinator
        // can resume prior work and handle eventual unprocessed sortitions
        // stored during a previous session.
        coordinator_senders.announce_new_burn_block();

        let mut burnchain_tip = burnchain_client
            .wait_for_sortitions(None)
            .expect("Unable to get burnchain tip");

        let chainstate_path = self.config.get_chainstate_path_str();
        let mut pox_watchdog = PoxSyncWatchdog::new(
            mainnet,
            chainid,
            chainstate_path,
            self.config.burnchain.poll_time_secs,
            self.config.connection_options.timeout,
            self.config.node.pox_sync_sample_secs,
            self.config.node.pox_sync_sample_secs == 0,
            should_keep_running.clone(),
        )
        .unwrap();

        // TODO (hack) instantiate the sortdb in the burnchain
        let sortdb = burnchain_client.sortdb_mut();

        // setup genesis
        let node = NeonGenesisNode::new(
            self.config.clone(),
            event_dispatcher,
            burnchain_config.clone(),
            Box::new(|_| vec![]),
        );
        let mut node = if is_miner {
            node.into_initialized_leader_node(
                burnchain_tip.clone(),
                self.get_blocks_processed_arc(),
                self.get_microblocks_processed_arc(),
                coordinator_senders.clone(),
                pox_watchdog.make_comms_handle(),
                attachments_rx,
                atlas_config,
                should_keep_running.clone(),
            )
        } else {
            node.into_initialized_node(
                burnchain_tip.clone(),
                self.get_blocks_processed_arc(),
                self.get_microblocks_processed_arc(),
                coordinator_senders.clone(),
                pox_watchdog.make_comms_handle(),
                attachments_rx,
                atlas_config,
                should_keep_running.clone(),
            )
        };

        let mut block_height = {
            let (stacks_ch, _) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())
                .expect("BUG: failed to load canonical stacks chain tip hash");

            match SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &stacks_ch)
                .expect("BUG: failed to query sortition DB")
            {
                Some(sn) => burnchain_config.reward_cycle_to_block_height(
                    burnchain_config
                        .block_height_to_reward_cycle(sn.block_height)
                        .expect("BUG: snapshot preceeds first reward cycle"),
                ),
                None => {
                    let sn = SortitionDB::get_first_block_snapshot(&sortdb.conn())
                        .expect("BUG: failed to get first-ever block snapshot");

                    sn.block_height
                }
            }
        };

        // Start the runloop
        trace!("Begin run loop");
        self.bump_blocks_processed();

        let prometheus_bind = self.config.node.prometheus_bind.clone();
        if let Some(prometheus_bind) = prometheus_bind {
            thread::Builder::new()
                .name("prometheus".to_string())
                .spawn(move || {
                    start_serving_monitoring_metrics(prometheus_bind);
                })
                .unwrap();
        }

        let mut burnchain_height = block_height;
        let mut num_sortitions_in_last_cycle = 1;
        let mut learned_burnchain_height = false;

        // prepare to fetch the first reward cycle!
        target_burnchain_block_height = burnchain_height + pox_constants.reward_cycle_length as u64;

        debug!(
            "Begin main runloop starting a burnchain block {}",
            block_height
        );

        let mut last_block_height = 0;
        loop {
            // Orchestrating graceful termination
            if !should_keep_running.load(Ordering::SeqCst) {
                // The p2p thread relies on the same atomic_bool, it will
                // discontinue its execution after completing its ongoing runloop epoch.
                info!("Terminating p2p process");
                info!("Terminating relayer");
                info!("Terminating chains-coordinator");
                coordinator_senders.stop_chains_coordinator();

                coordinator_thread_handle.join().unwrap();
                node.relayer_thread_handle.join().unwrap();
                node.p2p_thread_handle.join().unwrap();

                info!("Exiting stacks-node");
                break;
            }

            // wait for the p2p state-machine to do at least one pass
            debug!("Wait until we reach steady-state before processing more burnchain blocks...");

            // wait until it's okay to process the next sortitions
            let ibd = match pox_watchdog.pox_sync_wait(
                &burnchain_config,
                &burnchain_tip,
                if learned_burnchain_height {
                    Some(burnchain_height)
                } else {
                    None
                },
                num_sortitions_in_last_cycle,
            ) {
                Ok(ibd) => ibd,
                Err(e) => {
                    debug!("Pox sync wait routine aborted: {:?}", e);
                    continue;
                }
            };

            // will recalculate this
            num_sortitions_in_last_cycle = 0;

            let (next_burnchain_tip, next_burnchain_height) =
                match burnchain_client.sync(Some(target_burnchain_block_height)) {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("Burnchain controller stopped: {}", e);
                        continue;
                    }
                };

            target_burnchain_block_height = cmp::min(
                next_burnchain_height,
                target_burnchain_block_height + pox_constants.reward_cycle_length as u64,
            );

            // *now* we know the burnchain height
            learned_burnchain_height = true;
            burnchain_tip = next_burnchain_tip;
            burnchain_height = next_burnchain_height;

            let sortition_tip = &burnchain_tip.block_snapshot.sortition_id;
            let next_height = burnchain_tip.block_snapshot.block_height;

            if next_height != last_block_height {
                info!(
                    "Downloaded burnchain blocks up to height {}; new target height is {}; next_height = {}, block_height = {}",
                    next_burnchain_height, target_burnchain_block_height, next_height, block_height
                );
            }

            if next_height > block_height {
                debug!(
                    "New burnchain block height {} > {}",
                    next_height, block_height
                );

                let mut sort_count = 0;

                // first, let's process all blocks in (block_height, next_height]
                for block_to_process in (block_height + 1)..(next_height + 1) {
                    let block = {
                        let ic = burnchain_client.sortdb_ref().index_conn();
                        SortitionDB::get_ancestor_snapshot(&ic, block_to_process, sortition_tip)
                            .unwrap()
                            .expect("Failed to find block in fork processed by burnchain indexer")
                    };
                    if block.sortition {
                        sort_count += 1;
                    }

                    let sortition_id = &block.sortition_id;

                    // Have the node process the new block, that can include, or not, a sortition.
                    node.process_burnchain_state(burnchain_client.sortdb_mut(), sortition_id, ibd);

                    // Now, tell the relayer to check if it won a sortition during this block,
                    //   and, if so, to process and advertize the block
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
                    next_height, block_height, burnchain_height, num_sortitions_in_last_cycle;
                );

                block_height = next_height;
            } else if ibd {
                // drive block processing after we reach the burnchain tip.
                // we may have downloaded all the blocks already,
                // so we can't rely on the relayer alone to
                // drive it.
                coordinator_senders.announce_new_stacks_block();
            }

            if block_height >= burnchain_height && !ibd {
                let canonical_stacks_tip_height =
                    SortitionDB::get_canonical_burn_chain_tip(burnchain_client.sortdb_ref().conn())
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
                    if last_block_height != block_height {
                        info!(
                            "Synchronized full burnchain up to height {}. Proceeding to mine blocks",
                            block_height
                        );
                        last_block_height = block_height;
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
