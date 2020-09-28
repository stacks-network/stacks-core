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
use crate::neon_node::TESTNET_CHAIN_ID;
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
    chainstate_path: String,
    unprocessed_block_samples: VecDeque<i64>,
    max_samples: u64,
    max_staging: u64,
    delay_heuristic: u64,
    sync_frequency: u64,
    sync_deadline: u64,
    initial_block_download: bool,
}

impl PoxSyncWatchdog {
    pub fn new(chainstate_path: String) -> PoxSyncWatchdog {
        PoxSyncWatchdog {
            chainstate_path: chainstate_path,
            unprocessed_block_samples: VecDeque::new(),
            max_samples: 30,
            max_staging: 10,
            delay_heuristic: 60_000,        // 1 minute,
            sync_frequency: 10,
            sync_deadline: 0,
            initial_block_download: true
        }
    }

    /// How many recently-added Stacks blocks are in an attachable state, up to $max_staging, and
    /// no more recent than $now - $delay_heuristic seconds?
    /// ($max_staging is necessary to limit the runtime of this method, since the underlying SQL
    /// uses COUNT(*), which in Sqlite is a _O(n)_ operation for _n_ rows)
    fn count_attachable_stacks_blocks(&self) -> Result<u64, String> {
        let chainstate = match StacksChainState::open(false, TESTNET_CHAIN_ID, &self.chainstate_path) {
            Ok(cs) => cs,
            Err(e) => {
                return Err(format!("Failed to open chainstate at '{}': {:?}", &self.chainstate_path, &e));
            },
        };

        let cnt = StacksChainState::count_attachable_staging_blocks(&chainstate.blocks_db, self.max_staging, get_epoch_time_secs() - (self.delay_heuristic / 1000))
            .map_err(|e| format!("Failed to count attachable staging blocks: {:?}", &e))?;

        Ok(cnt)
    }

    /// Are we still in the initial block download?  Infer this by checking to see how many reward
    /// cycles have been processed, compared to how many reward cycles exist.  If they're equal,
    /// then we're ready to start mining
    pub fn infer_initial_block_download(&mut self, burnchain_ctl: &BitcoinRegtestController, burnchain_tip: &BurnchainTip, burnchain_height: u64) -> bool {
        let highest_reward_cycle = match burnchain_ctl.get_burnchain().block_height_to_reward_cycle(burnchain_height) {
            Some(x) => x,
            None => {
                return false;
            }
        };

        let highest_available_reward_cycle = match burnchain_ctl.get_burnchain().block_height_to_reward_cycle(burnchain_tip.block_snapshot.block_height) {
            Some(x) => x,
            None => {
                return false;
            }
        };

        self.initial_block_download = highest_available_reward_cycle <= highest_reward_cycle;
        self.initial_block_download
    }

    /// Wait until all of the Stacks blocks for the given reward cycle are seemingly downloaded and
    /// processed.  Do so by watching the _rate_ at which attachable Stacks blocks arrive.  If the
    /// rate goes to 0, and the number goes to 0 over $delay_heuristic milliseconds, then infer
    /// that all Stacks blocks have been downloaded.
    pub fn pox_sync_wait(&mut self, burnchain_ctl: &BitcoinRegtestController, burnchain_tip: &BurnchainTip, burnchain_height: u64) {
        self.infer_initial_block_download(burnchain_ctl, burnchain_tip, burnchain_height);
        loop {
            let mut total_blocks_seen = 0;
            let mut total_recent_changes = 0;
            let do_sync = match self.count_attachable_stacks_blocks() {
                Ok(num_available) => {
                    self.unprocessed_block_samples.push_back(num_available as i64);
                    if (self.unprocessed_block_samples.len() as u64) > self.max_samples {
                        self.unprocessed_block_samples.pop_front();
                    }

                    if num_available > 0 || (self.unprocessed_block_samples.len() as u64) < self.max_samples {
                        // wait for a bit before asking again (up to a minute total)
                        sleep_ms((self.delay_heuristic / self.max_samples) as u64);
                    }

                    // take first derivative of samples
                    let mut deltas = vec![];
                    let mut prev = *self.unprocessed_block_samples.front().unwrap_or(&(self.max_staging as i64));
                    for (i, sample) in self.unprocessed_block_samples.iter().enumerate() {
                        total_blocks_seen += sample;
                        if i == 0 {
                            continue;
                        }
                        let delta = sample - prev;
                        prev = *sample;
                        deltas.push(delta);
                    }

                    // if first-derivative is `y = 0` for the last $delay_heuristic millis, then we can infer
                    // that we've processed all of the burnchain blocks -- no more are likely to
                    // arrive late (but we can recover via the PoX unhappy path if that happens)
                    let mut flatlined = true;
                    for d in deltas.iter() {
                        if *d != 0 {
                            total_recent_changes += 1;
                            flatlined = false;
                        }
                    }

                    flatlined == 0
                },
                Err(msg) => {
                    warn!("{}", msg);
                    false
                }
            };

            if !do_sync {
                // still working on blocks
                debug!("Still downloading Stacks blocks; will not sync burnchain yet (total blocks seen in sample: {}; total number of changes in sample: {})", total_blocks_seen, total_recent_changes);
                sleep_ms((self.delay_heuristic / self.max_samples) as u64);
                continue;
            }

            let now = get_epoch_time_secs();
            if now < self.sync_deadline {
                debug!("Wait until {} to sync with the burnchain", self.sync_deadline);
                sleep_ms((self.sync_deadline - now) * 1000);
            }

            self.sync_deadline = get_epoch_time_secs() + self.sync_frequency;
            break;
        }
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

        thread::spawn(move || {
            ChainsCoordinator::run(&chainstate_path, burnchain_config, mainnet, chainid,
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
        let mut pox_watchdog = PoxSyncWatchdog::new(chainstate_path);
        let mut burnchain_height = 1;

        // prepare to fetch the first reward cycle!
        target_burnchain_block_height = pox_constants.reward_cycle_length as u64;

        loop {
            // wait until it's okay to process the next sortitions
            pox_watchdog.pox_sync_wait(&burnchain, &burnchain_tip, burnchain_height); 

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
                                             sortition_id);
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
                if !node.relayer_issue_tenure() {
                    // relayer hung up, exit.
                    error!("Block relayer and miner hung up, exiting.");
                    return
                }
            }
        }
    }
}
