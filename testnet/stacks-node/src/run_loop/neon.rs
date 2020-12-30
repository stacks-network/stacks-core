use crate::{
    genesis_data::USE_TEST_GENESIS_CHAINSTATE,
    node::{get_account_balances, get_account_lockups, get_names, get_namespaces},
    BitcoinRegtestController, BurnchainController, Config, EventDispatcher, Keychain,
    NeonGenesisNode,
};
use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::burnchains::bitcoin::address::BitcoinAddressType;
use stacks::burnchains::{Address, Burnchain};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::coordinator::comm::{CoordinatorChannels, CoordinatorReceivers};
use stacks::chainstate::coordinator::{
    BlockEventDispatcher, ChainsCoordinator, CoordinatorCommunication,
};
use stacks::chainstate::stacks::boot::STACKS_BOOT_CODE_CONTRACT_ADDRESS_STR;
use stacks::chainstate::stacks::db::{ChainStateBootData, ClarityTx, StacksChainState};
use stacks::net::atlas::AtlasConfig;
use stacks::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};
use std::cmp;
use std::sync::mpsc::sync_channel;
use std::thread;

use super::RunLoopCallbacks;

use crate::monitoring::start_serving_monitoring_metrics;

use crate::syncctl::PoxSyncWatchdog;

/// Coordinating a node running in neon mode.
#[cfg(test)]
pub struct RunLoop {
    config: Config,
    pub callbacks: RunLoopCallbacks,
    blocks_processed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>,
}

#[cfg(not(test))]
pub struct RunLoop {
    config: Config,
    pub callbacks: RunLoopCallbacks,
    coordinator_channels: Option<(CoordinatorReceivers, CoordinatorChannels)>,
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
    fn get_blocks_processed_arc(&self) {}

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
    pub fn start(&mut self, _expected_num_rounds: u64, burnchain_opt: Option<Burnchain>) {
        let (coordinator_receivers, coordinator_senders) = self
            .coordinator_channels
            .take()
            .expect("Run loop already started, can only start once after initialization.");

        // Initialize and start the burnchain.
        let mut burnchain = BitcoinRegtestController::with_burnchain(
            self.config.clone(),
            Some(coordinator_senders.clone()),
            burnchain_opt.clone(),
        );
        let pox_constants = burnchain.get_pox_constants();

        let is_miner = if self.config.node.miner {
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
            .unwrap();
            info!("Miner node: checking UTXOs at address: {}", btc_addr);

            let utxos = burnchain.get_utxos(&keychain.generate_op_signer().get_public_key(), 1);
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

        let burnchain_config = burnchain.get_burnchain();
        let mut target_burnchain_block_height = 1.max(burnchain_config.first_block_height);

        match burnchain.start(Some(target_burnchain_block_height)) {
            Ok(_) => {}
            Err(e) => {
                warn!("Burnchain controller stopped: {}", e);
                return;
            }
        };

        let mainnet = self.config.is_mainnet();
        let chainid = self.config.burnchain.chain_id;
        let block_limit = self.config.block_limit.clone();
        let initial_balances = self
            .config
            .initial_balances
            .iter()
            .map(|e| (e.address.clone(), e.amount))
            .collect();

        // setup dispatcher
        let mut event_dispatcher = EventDispatcher::new();
        for observer in self.config.events_observers.iter() {
            event_dispatcher.register_observer(observer);
        }

        let mut coordinator_dispatcher = event_dispatcher.clone();

        let chainstate_path = self.config.get_chainstate_path();
        let coordinator_burnchain_config = burnchain_config.clone();

        let (attachments_tx, attachments_rx) = sync_channel(1);
        let first_block_height = burnchain_config.first_block_height as u128;
        let pox_prepare_length = burnchain_config.pox_constants.prepare_length as u128;
        let pox_reward_cycle_length = burnchain_config.pox_constants.reward_cycle_length as u128;
        let pox_rejection_fraction = burnchain_config.pox_constants.pox_rejection_fraction as u128;

        let boot_block = Box::new(move |clarity_tx: &mut ClarityTx| {
            let contract = QualifiedContractIdentifier::parse(&format!(
                "{}.pox",
                STACKS_BOOT_CODE_CONTRACT_ADDRESS_STR
            ))
            .expect("Failed to construct boot code contract address");
            let sender = PrincipalData::from(contract.clone());
            let params = vec![
                Value::UInt(first_block_height),
                Value::UInt(pox_prepare_length),
                Value::UInt(pox_reward_cycle_length),
                Value::UInt(pox_rejection_fraction),
            ];

            clarity_tx.connection().as_transaction(|conn| {
                conn.run_contract_call(
                    &sender,
                    &contract,
                    "set-burnchain-parameters",
                    &params,
                    |_, _| false,
                )
                .expect("Failed to set burnchain parameters in PoX contract");
            });
        });
        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: Some(boot_block),
            first_burnchain_block_hash: coordinator_burnchain_config.first_block_hash,
            first_burnchain_block_height: coordinator_burnchain_config.first_block_height as u32,
            first_burnchain_block_timestamp: coordinator_burnchain_config.first_block_timestamp,
            get_bulk_initial_lockups: Some(Box::new(|| {
                get_account_lockups(USE_TEST_GENESIS_CHAINSTATE)
            })),
            get_bulk_initial_balances: Some(Box::new(|| {
                get_account_balances(USE_TEST_GENESIS_CHAINSTATE)
            })),
            get_bulk_initial_namespaces: Some(Box::new(|| {
                get_namespaces(USE_TEST_GENESIS_CHAINSTATE)
            })),
            get_bulk_initial_names: Some(Box::new(|| get_names(USE_TEST_GENESIS_CHAINSTATE))),
        };

        let (chain_state_db, receipts) = StacksChainState::open_and_exec(
            mainnet,
            chainid,
            &chainstate_path,
            Some(&mut boot_data),
            block_limit,
        )
        .unwrap();
        coordinator_dispatcher.dispatch_boot_receipts(receipts);

        let atlas_config = AtlasConfig::default();
        let moved_atlas_config = atlas_config.clone();

        thread::spawn(move || {
            ChainsCoordinator::run(
                chain_state_db,
                coordinator_burnchain_config,
                attachments_tx,
                &mut coordinator_dispatcher,
                coordinator_receivers,
                moved_atlas_config,
            );
        });

        let mut burnchain_tip = burnchain.wait_for_sortitions(None);

        let chainstate_path = self.config.get_chainstate_path();
        let mut pox_watchdog = PoxSyncWatchdog::new(
            mainnet,
            chainid,
            chainstate_path,
            self.config.burnchain.poll_time_secs,
            self.config.connection_options.timeout,
            self.config.node.pox_sync_sample_secs,
        )
        .unwrap();

        // setup genesis
        let node = NeonGenesisNode::new(
            self.config.clone(),
            event_dispatcher,
            burnchain_config.clone(),
            Box::new(|_| {}),
        );
        let mut node = if is_miner {
            node.into_initialized_leader_node(
                burnchain_tip.clone(),
                self.get_blocks_processed_arc(),
                coordinator_senders,
                pox_watchdog.make_comms_handle(),
                attachments_rx,
                atlas_config,
            )
        } else {
            node.into_initialized_node(
                burnchain_tip.clone(),
                self.get_blocks_processed_arc(),
                coordinator_senders,
                pox_watchdog.make_comms_handle(),
                attachments_rx,
                atlas_config,
            )
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

        let mut block_height = 1.max(burnchain_config.first_block_height);

        let mut burnchain_height = block_height;

        // prepare to fetch the first reward cycle!
        target_burnchain_block_height = burnchain_height + pox_constants.reward_cycle_length as u64;

        loop {
            // wait for the p2p state-machine to do at least one pass
            debug!("Wait until we reach steady-state before processing more burnchain blocks...");
            // wait until it's okay to process the next sortitions
            let ibd =
                pox_watchdog.pox_sync_wait(&burnchain_config, &burnchain_tip, burnchain_height);

            let (next_burnchain_tip, next_burnchain_height) =
                match burnchain.sync(Some(target_burnchain_block_height)) {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("Burnchain controller stopped: {}", e);
                        return;
                    }
                };

            target_burnchain_block_height = cmp::min(
                next_burnchain_height,
                target_burnchain_block_height + pox_constants.reward_cycle_length as u64,
            );
            debug!(
                "Downloaded burnchain blocks up to height {}; new target height is {}",
                next_burnchain_height, target_burnchain_block_height
            );

            burnchain_tip = next_burnchain_tip;
            burnchain_height = next_burnchain_height;

            let sortition_tip = &burnchain_tip.block_snapshot.sortition_id;
            let next_height = burnchain_tip.block_snapshot.block_height;

            if next_height > block_height {
                // first, let's process all blocks in (block_height, next_height]
                for block_to_process in (block_height + 1)..(next_height + 1) {
                    let block = {
                        let ic = burnchain.sortdb_ref().index_conn();
                        SortitionDB::get_ancestor_snapshot(&ic, block_to_process, sortition_tip)
                            .unwrap()
                            .expect("Failed to find block in fork processed by bitcoin indexer")
                    };
                    let sortition_id = &block.sortition_id;

                    // Have the node process the new block, that can include, or not, a sortition.
                    node.process_burnchain_state(burnchain.sortdb_mut(), sortition_id, ibd);

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

                block_height = next_height;
                debug!(
                    "Synchronized burnchain up to block height {} (chain tip height is {})",
                    block_height, burnchain_height
                );
            }

            if block_height >= burnchain_height && !ibd {
                // at tip, and not downloading. proceed to mine.
                debug!(
                    "Synchronized full burnchain up to height {}. Proceeding to mine blocks",
                    block_height
                );
                if !node.relayer_issue_tenure() {
                    // relayer hung up, exit.
                    error!("Block relayer and miner hung up, exiting.");
                    return;
                }
            }
        }
    }
}
