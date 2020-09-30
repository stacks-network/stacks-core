use std::thread;
use std::collections::VecDeque;

use crate::{Config, NeonGenesisNode, BurnchainController, EventDispatcher,
            BitcoinRegtestController, Keychain, neon_node};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::burnchains::{Address, Burnchain};
use stacks::burnchains::bitcoin::{address::{BitcoinAddressType}};
use stacks::chainstate::coordinator::{ChainsCoordinator, CoordinatorCommunication};
use stacks::chainstate::coordinator::comm::{CoordinatorChannels, CoordinatorReceivers};
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::util::sleep_ms;
use stacks::util::get_epoch_time_secs;

use super::RunLoopCallbacks;

use crate::monitoring::start_serving_monitoring_metrics;
use crate::burnchains::BurnchainTip;

/// Coordinating a node running in neon mode.
#[cfg(test)]
pub struct RunLoop {
    config: Config,
    pub callbacks: RunLoopCallbacks,
    blocks_processed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>
}

#[cfg(not(test))]
pub struct RunLoop {
    config: Config,
    pub callbacks: RunLoopCallbacks,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>
}

/// Monitor the state of the Stacks blockchain as the peer network and relay threads download and
/// proces Stacks blocks.  Don't allow the node to process the next PoX reward cycle's sortitions
/// unless it's reasonably sure that it has processed all Stacks blocks for this reward cycle.
/// This struct monitors the Stacks chainstate to make this determination.
pub struct PoxSyncWatchdog {
    /// number of attachable but unprocessed staging blocks over time
    new_attachable_blocks: VecDeque<i64>,
    /// number of newly-processed staging blocks over time
    new_processed_blocks: VecDeque<i64>,
    /// last time we asked for attachable blocks
    last_attachable_query: u64,
    /// last time we asked for processed blocks
    last_processed_query: u64,
    /// number of samples to take
    max_samples: u64,
    /// maximum number of blocks to count per query (affects performance!)
    max_staging: u64,
    /// when did we first start watching?
    watch_start_ts: u64,
    /// when did we first see a flatline in block-processing rate?
    last_block_processed_ts: u64,
    /// estimated time for a block to get downloaded.  Used to infer how long to wait for the first
    /// blocks to show up when waiting for this reward cycle.
    estimated_block_download_time: f64,
    /// estimated time for a block to get processed -- from when it shows up as attachable to when
    /// it shows up as processed.  Used to infer how long to wait for the last block to get
    /// processed before unblocking burnchain sync for the next reward cycle.
    estimated_block_process_time: f64,
    /// time between burnchain syncs in stead state
    steady_state_burnchain_sync_interval: u64,
    /// when to re-sync under steady state
    steady_state_resync_ts: u64,
    /// chainstate handle
    chainstate: StacksChainState,
}

impl PoxSyncWatchdog {
    pub fn new(mainnet: bool, chain_id: u32, chainstate_path: String, burnchain_poll_time: u64, download_timeout: u64) -> Result<PoxSyncWatchdog, String> {
        let (chainstate, _) = match StacksChainState::open(mainnet, chain_id, &chainstate_path) {
            Ok(cs) => cs,
            Err(e) => {
                return Err(format!("Failed to open chainstate at '{}': {:?}", &chainstate_path, &e));
            },
        };

        Ok(PoxSyncWatchdog {
            new_attachable_blocks: VecDeque::new(),
            new_processed_blocks: VecDeque::new(),
            last_attachable_query: 0,
            last_processed_query: 0,
            max_samples: download_timeout,      // sample once per second for however long we expect a timeout to be
            max_staging: 10,
            watch_start_ts: 0,
            last_block_processed_ts: 0,
            estimated_block_download_time: download_timeout as f64,
            estimated_block_process_time: 5.0,
            steady_state_burnchain_sync_interval: burnchain_poll_time,
            steady_state_resync_ts: 0,
            chainstate: chainstate,
        })
    }

    /// How many recently-added Stacks blocks are in an attachable state, up to $max_staging?
    fn count_attachable_stacks_blocks(&mut self) -> Result<u64, String> {
        // number of staging blocks that have arrived since the last sortition
        let cnt = StacksChainState::count_attachable_staging_blocks(&self.chainstate.blocks_db, self.max_staging, self.last_attachable_query)
            .map_err(|e| format!("Failed to count attachable staging blocks: {:?}", &e))?;

        self.last_attachable_query = get_epoch_time_secs();
        Ok(cnt)
    }
    
    /// How many recently-processed Stacks blocks are there, up to $max_staging?
    /// ($max_staging is necessary to limit the runtime of this method, since the underlying SQL
    /// uses COUNT(*), which in Sqlite is a _O(n)_ operation for _n_ rows)
    fn count_processed_stacks_blocks(&mut self) -> Result<u64, String> {
        // number of staging blocks that have arrived since the last sortition
        let cnt = StacksChainState::count_processed_staging_blocks(&self.chainstate.blocks_db, self.max_staging, self.last_processed_query)
            .map_err(|e| format!("Failed to count attachable staging blocks: {:?}", &e))?;

        self.last_processed_query = get_epoch_time_secs();
        Ok(cnt)
    }

    /// Are we still in the initial block download?  Infer this by checking to see how many reward
    /// cycles have been processed, compared to how many reward cycles exist.  If they're equal,
    /// then we're ready to start mining
    pub fn infer_initial_block_download(burnchain_tip: &BurnchainTip, burnchain_height: u64) -> bool {
        burnchain_tip.block_snapshot.block_height + 5 < burnchain_height
    }

    /// Calculate the first derivative of a list of points
    fn derivative(sample_list: &VecDeque<i64>) -> Vec<i64> {
        let mut deltas = vec![];
        let mut prev = 0;
        for (i, sample) in sample_list.iter().enumerate() {
            if i == 0 {
                prev = *sample;
                continue;
            }
            let delta = *sample - prev;
            prev = *sample;
            deltas.push(delta);
        }
        deltas
    }

    /// Is a derivative approximately flat, with a maximum absolute deviation from 0?
    /// Return whether or not the sample is mostly flat, and how many points were over the given
    /// error bar in either direction.
    fn is_mostly_flat(deriv: &Vec<i64>, error: i64) -> (bool, usize) {
        let mut total_deviates = 0;
        let mut ret = true;
        for d in deriv.iter() {
            if d.abs() > error {
                total_deviates += 1;
                ret = false;
            }
        }
        (ret, total_deviates)
    }

    /// low and high pass filter average -- take average without the smallest and largest values
    fn hilo_filter_avg(samples: &Vec<i64>) -> f64 {
        // take average with low and high pass 
        let mut min = i64::max_value();
        let mut max = i64::min_value();
        for s in samples.iter() {
            if *s < 0 {
                // nonsensical result (e.g. due to clock drift?)
                continue;
            }
            if *s < min {
                min = *s;
            }
            if *s > max {
                max = *s;
            }
        }

        let mut count = 0;
        let mut sum = 0;
        for s in samples.iter() {
            if *s < 0 {
                // nonsensical result
                continue;
            }
            if *s == min {
                continue;
            }
            if *s == max {
                continue;
            }
            count += 1;
            sum += *s;
        }

        if count == 0 {
            // no viable samples
            1.0
        }
        else {
            (sum as f64) / (count as f64)
        }
    }

    /// estimate how long a block remains in an unprocessed state
    fn estimate_block_process_time(chainstate: &StacksChainState, burnchain: &Burnchain, tip_height: u64) -> f64 {
        let this_reward_cycle = burnchain.block_height_to_reward_cycle(tip_height).expect(&format!("BUG: no reward cycle for {}", tip_height));
        let prev_reward_cycle = this_reward_cycle.saturating_sub(1);

        let start_height = burnchain.reward_cycle_to_block_height(prev_reward_cycle);
        let end_height = burnchain.reward_cycle_to_block_height(this_reward_cycle);

        if this_reward_cycle > 0 {
            assert!(start_height < end_height);
        }
        else {
            // no samples yet
            return 1.0;
        }

        let block_wait_times = StacksChainState::measure_block_wait_time(&chainstate.blocks_db, start_height, end_height)
            .expect("BUG: failed to query chainstate block-processing times");

        PoxSyncWatchdog::hilo_filter_avg(&block_wait_times)
    }
    
    /// estimate how long a block takes to download
    fn estimate_block_download_time(chainstate: &StacksChainState, burnchain: &Burnchain, tip_height: u64) -> f64 {
        let this_reward_cycle = burnchain.block_height_to_reward_cycle(tip_height).expect(&format!("BUG: no reward cycle for {}", tip_height));
        let prev_reward_cycle = this_reward_cycle.saturating_sub(1);

        let start_height = burnchain.reward_cycle_to_block_height(prev_reward_cycle);
        let end_height = burnchain.reward_cycle_to_block_height(this_reward_cycle);

        if this_reward_cycle > 0 {
            assert!(start_height < end_height);
        }
        else {
            // no samples yet
            return 1.0;
        }

        let block_download_times = StacksChainState::measure_block_download_time(&chainstate.blocks_db, start_height, end_height)
            .expect("BUG: failed to query chainstate block-download times");
        
        PoxSyncWatchdog::hilo_filter_avg(&block_download_times)
    }

    /// Reset internal state.  Performed when it's okay to begin syncing the burnchain.
    /// Updates estimate for block-processing time and block-downloading time.
    fn reset(&mut self, burnchain: &Burnchain, tip_height: u64) {
        // find the average (with low/high pass filter) time a block spends in the DB without being
        // processed, during this reward cycle
        self.estimated_block_process_time = PoxSyncWatchdog::estimate_block_process_time(&self.chainstate, burnchain, tip_height);

        // find the average (with low/high pass filter) time a block spends downloading
        self.estimated_block_download_time = PoxSyncWatchdog::estimate_block_download_time(&self.chainstate, burnchain, tip_height);
        
        debug!("Estimated block download time: {}s. Estimated block processing time: {}s", self.estimated_block_download_time, self.estimated_block_process_time);

        self.new_attachable_blocks.clear();
        self.new_processed_blocks.clear();
        self.last_block_processed_ts = 0;
        self.watch_start_ts = 0;
        self.steady_state_resync_ts = 0;
    }

    /// Wait until all of the Stacks blocks for the given reward cycle are seemingly downloaded and
    /// processed.  Do so by watching the _rate_ at which attachable Stacks blocks arrive and get
    /// processed.
    /// Returns whether or not we're still in the initial block download
    pub fn pox_sync_wait(&mut self, burnchain: &Burnchain, burnchain_tip: &BurnchainTip, burnchain_height: u64) -> bool {
        if self.watch_start_ts == 0 {
            self.watch_start_ts = get_epoch_time_secs();
        }
        if self.steady_state_resync_ts == 0 {
            self.steady_state_resync_ts = get_epoch_time_secs() + self.steady_state_burnchain_sync_interval;
        }

        // unconditionally download the first reward cycle
        if burnchain_tip.block_snapshot.block_height < burnchain.first_block_height + (burnchain.pox_constants.reward_cycle_length as u64) {
            debug!("PoX watchdog in first reward cycle -- sync immediately");
            return PoxSyncWatchdog::infer_initial_block_download(burnchain_tip, burnchain_height);
        }

        let mut steady_state = false;

        let ibd = loop {
            let ibd = PoxSyncWatchdog::infer_initial_block_download(burnchain_tip, burnchain_height);

            let expected_first_block_deadline = self.watch_start_ts + (self.estimated_block_download_time as u64);
            let expected_last_block_deadline = self.last_block_processed_ts + (self.estimated_block_download_time as u64) + (self.estimated_block_process_time as u64);

            match (self.count_attachable_stacks_blocks(), self.count_processed_stacks_blocks()) {
                (Ok(num_available), Ok(num_processed)) => {
                    self.new_attachable_blocks.push_back(num_available as i64);
                    self.new_processed_blocks.push_back(num_processed as i64);

                    if (self.new_attachable_blocks.len() as u64) > self.max_samples {
                        self.new_attachable_blocks.pop_front();
                    }
                    if (self.new_processed_blocks.len() as u64) > self.max_samples {
                        self.new_processed_blocks.pop_front();
                    }

                    if (self.new_attachable_blocks.len() as u64) < self.max_samples || (self.new_processed_blocks.len() as u64) < self.max_samples {
                        // still getting initial samples
                        if self.new_processed_blocks.len() % 10 == 0 {
                            debug!("PoX watchdog: Still warming up: {} out of {} samples...", &self.new_attachable_blocks.len(), &self.max_samples);
                        }
                        sleep_ms(1000);
                        continue;
                    }

                    if self.watch_start_ts > 0 && get_epoch_time_secs() < expected_first_block_deadline {
                        // still waiting for that first block in this reward cycle
                        debug!("PoX watchdog: Still warming up: waiting until {}s for first Stacks block download (estimated download time: {}s)...", expected_first_block_deadline, self.estimated_block_download_time);
                        sleep_ms(1000);
                        continue;
                    }
                     
                    // take first derivative of samples -- see if the download and processing rate has gone to 0
                    let attachable_delta = PoxSyncWatchdog::derivative(&self.new_attachable_blocks);
                    let processed_delta = PoxSyncWatchdog::derivative(&self.new_processed_blocks);

                    let (flat_attachable, attachable_deviants) = PoxSyncWatchdog::is_mostly_flat(&attachable_delta, 0);
                    let (flat_processed, processed_deviants) = PoxSyncWatchdog::is_mostly_flat(&processed_delta, 0);

                    debug!("PoX watchdog: flat-attachable?: {}, flat-processed?: {}, estimated block-download time: {}s, estimated block-processing time: {}s",
                           flat_attachable, flat_processed, self.estimated_block_download_time, self.estimated_block_process_time);

                    if flat_attachable && flat_processed && self.last_block_processed_ts == 0 {
                        // we're flat-lining -- this may be the end of this cycle
                        self.last_block_processed_ts = get_epoch_time_secs();
                    }

                    if self.last_block_processed_ts > 0 && get_epoch_time_secs() < expected_last_block_deadline {
                        debug!("PoX watchdog: Still processing blocks; waiting until at least min({},{})s before burnchain synchronization (estimated block-processing time: {}s)", 
                               get_epoch_time_secs() + 1, expected_last_block_deadline, self.estimated_block_process_time);
                        sleep_ms(1000);
                        continue;
                    }

                    if ibd {
                        // doing initial block download right now.
                        // only proceed to fetch the next reward cycle's burnchain blocks if we're neither downloading nor
                        // attaching blocks recently
                        debug!("PoX watchdog: In initial block download: flat-attachable = {}, flat-processed = {}, min-attachable: {}, min-processed: {}",
                               flat_attachable, flat_processed, &attachable_deviants, &processed_deviants);

                        if !flat_attachable || !flat_processed {
                            sleep_ms(1000);
                            continue;
                        }
                    }
                    else {
                        let now = get_epoch_time_secs();
                        if now < self.steady_state_resync_ts {
                            // steady state
                            if !steady_state {
                                debug!("PoX watchdog: In steady-state; waiting until at least {} before burnchain synchronization", self.steady_state_resync_ts);
                                steady_state = true;
                            }
                            sleep_ms(1000);
                            continue;
                        }
                    }
                },
                (err_attach, err_processed) => {
                    // can only happen on DB query failure
                    error!("PoX watchdog: Failed to count recently attached ('{:?}') and/or processed ('{:?}') staging blocks", &err_attach, &err_processed);
                    panic!();
                }
            };
            
            self.reset(burnchain, burnchain_tip.block_snapshot.block_height);
            break ibd;
        };
        ibd
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
    fn get_blocks_processed_arc(&self) {
    }

    #[cfg(test)]
    fn bump_blocks_processed(&self) {
        self.blocks_processed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(not(test))]
    fn bump_blocks_processed(&self) {
    }

    /// Starts the testnet runloop.
    /// 
    /// This function will block by looping infinitely.
    /// It will start the burnchain (separate thread), set-up a channel in
    /// charge of coordinating the new blocks coming from the burnchain and 
    /// the nodes, taking turns on tenures.  
    pub fn start(&mut self, _expected_num_rounds: u64) {

        let (coordinator_receivers, coordinator_senders) = self.coordinator_channels.take()
            .expect("Run loop already started, can only start once after initialization.");

        // Initialize and start the burnchain.
        let mut burnchain = BitcoinRegtestController::new(self.config.clone(), Some(coordinator_senders.clone()));
        let pox_constants = burnchain.get_pox_constants();

        let is_miner = if self.config.node.miner {
            let keychain = Keychain::default(self.config.node.seed.clone());
            let btc_addr = BitcoinAddress::from_bytes(
                self.config.burnchain.get_bitcoin_network().1,
                BitcoinAddressType::PublicKeyHash,
                &Keychain::address_from_burnchain_signer(&keychain.get_burnchain_signer()).to_bytes())
                .unwrap();
            info!("Miner node: checking UTXOs at address: {}", btc_addr);

            let utxos = burnchain.get_utxos(
                &keychain.generate_op_signer().get_public_key(), 1);
            if utxos.is_none() {
                error!("Miner node: UTXOs not found. Switching to Follower node. Restart node when you get some UTXOs.");
                false
            } else {
                info!("Miner node: starting up, UTXOs found.");
                true
            }
        } else {
            info!("Follower node: starting up");
            false
        };

        let mut target_burnchain_block_height = 1;
        match burnchain.start(Some(target_burnchain_block_height)) {
            Ok(_) => {},
            Err(e) => {
                warn!("Burnchain controller stopped: {}", e);
                return;
            }
        };

        let mainnet = false;
        let chainid = neon_node::TESTNET_CHAIN_ID;
        let block_limit = self.config.block_limit.clone();
        let initial_balances = self.config.initial_balances.iter().map(|e| (e.address.clone(), e.amount)).collect();
        let burnchain_poll_time = 30;       // TODO: this is testnet-specific

        // setup dispatcher
        let mut event_dispatcher = EventDispatcher::new();
        for observer in self.config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }

        let mut coordinator_dispatcher = event_dispatcher.clone();
        let burnchain_config = match Burnchain::new(&self.config.get_burn_db_path(), &self.config.burnchain.chain, "regtest") {
            Ok(burnchain) => burnchain,
            Err(e) => {
                error!("Failed to instantiate burnchain: {}", e);
                panic!()
            }
        };
        let chainstate_path = self.config.get_chainstate_path();
        let coordinator_burnchain_config = burnchain_config.clone();

        thread::spawn(move || {
            ChainsCoordinator::run(&chainstate_path, coordinator_burnchain_config, mainnet, chainid,
                                   Some(initial_balances),
                                   block_limit, &mut coordinator_dispatcher,
                                   coordinator_receivers, |_| {});
        });        
        
        let mut burnchain_tip = burnchain.wait_for_sortitions(None);

        let mut block_height = burnchain_tip.block_snapshot.block_height;

        // setup genesis
        let node = NeonGenesisNode::new(self.config.clone(), event_dispatcher, |_| {});
        let mut node = if is_miner {
            node.into_initialized_leader_node(burnchain_tip.clone(), self.get_blocks_processed_arc(), coordinator_senders)
        } else {
            node.into_initialized_node(burnchain_tip.clone(), self.get_blocks_processed_arc(), coordinator_senders)
        };

        // TODO (hack) instantiate the sortdb in the burnchain
        let _ = burnchain.sortdb_mut();

        // Start the runloop
        info!("Begin run loop");
        self.bump_blocks_processed();
        
        let prometheus_bind = self.config.node.prometheus_bind.clone();
        if let Some(prometheus_bind) = prometheus_bind {
            thread::spawn(move || {
                start_serving_monitoring_metrics(prometheus_bind);
            });
        }
        
        let chainstate_path = self.config.get_chainstate_path();
        let mut pox_watchdog = PoxSyncWatchdog::new(mainnet, chainid, chainstate_path, burnchain_poll_time, self.config.connection_options.timeout).unwrap();
        let mut burnchain_height = 1;

        // prepare to fetch the first reward cycle!
        target_burnchain_block_height = pox_constants.reward_cycle_length as u64;

        loop {
            // wait until it's okay to process the next sortitions
            let ibd = pox_watchdog.pox_sync_wait(&burnchain_config, &burnchain_tip, burnchain_height); 

            let (next_burnchain_tip, next_burnchain_height) = match burnchain.sync(Some(target_burnchain_block_height)) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Burnchain controller stopped: {}", e);
                    return;
                }
            };

            target_burnchain_block_height += pox_constants.reward_cycle_length as u64;
            burnchain_tip = next_burnchain_tip;
            burnchain_height = next_burnchain_height;

            let sortition_tip = &burnchain_tip.block_snapshot.sortition_id;
            let next_height = burnchain_tip.block_snapshot.block_height;
            if next_height <= block_height {
                warn!("burnchain.sync() did not progress block height");
                continue;
            }

            // first, let's process all blocks in (block_height, next_height]
            for block_to_process in (block_height+1)..(next_height+1) {
                let block = {
                    let ic = burnchain.sortdb_ref().index_conn();
                    SortitionDB::get_ancestor_snapshot(&ic, block_to_process, sortition_tip)
                        .unwrap()
                        .expect("Failed to find block in fork processed by bitcoin indexer")
                };
                let sortition_id = &block.sortition_id;

                // Have the node process the new block, that can include, or not, a sortition.
                node.process_burnchain_state(burnchain.sortdb_mut(), 
                                             sortition_id,
                                             ibd);
                // Now, tell the relayer to check if it won a sortition during this block,
                //   and, if so, to process and advertize the block
                //
                // _this will block if the relayer's buffer is full_
                if !node.relayer_sortition_notify() {
                    // relayer hung up, exit.
                    error!("Block relayer and miner hung up, exiting.");
                    return
                }
            }

            block_height = next_height;
            debug!("Synchronized up to block height {} (chain tip height is {})", block_height, burnchain_height);

            if block_height >= burnchain_height {
                // at tip. proceed to mine.
                debug!("Synchronized full burnchain. Proceeding to mine blocks");
                if !node.relayer_issue_tenure() {
                    // relayer hung up, exit.
                    error!("Block relayer and miner hung up, exiting.");
                    return
                }
            }
        }
    }
}
