// Copyright (C) 2020-2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
mod v0;
mod v1;

// Copyright (C) 2020-2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clarity::boot_util::boot_code_id;
use libsigner::{SignerEntries, SignerEventTrait};
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::nakamoto::signer_set::NakamotoSigners;
use stacks::chainstate::stacks::boot::{NakamotoSignerEntry, SIGNERS_NAME};
use stacks::chainstate::stacks::{StacksPrivateKey, ThresholdSignature};
use stacks::core::StacksEpoch;
use stacks::net::api::postblock_proposal::BlockValidateResponse;
use stacks::util::secp256k1::MessageSignature;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{hex_bytes, Sha512Trunc256Sum};
use stacks_signer::client::{SignerSlotID, StacksClient};
use stacks_signer::config::{build_signer_config_tomls, GlobalConfig as SignerConfig, Network};
use stacks_signer::runloop::{SignerResult, State};
use stacks_signer::{Signer, SpawnedSigner};
use wsts::curve::point::Point;
use wsts::state_machine::PublicKeys;

use crate::config::{Config as NeonConfig, EventKeyType, EventObserverConfig, InitialBalance};
use crate::event_dispatcher::MinedNakamotoBlockEvent;
use crate::neon::Counters;
use crate::run_loop::boot_nakamoto;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::nakamoto_integrations::{
    naka_neon_integration_conf, next_block_and_mine_commit, POX_4_DEFAULT_STACKER_BALANCE,
};
use crate::tests::neon_integrations::{
    next_block_and_wait, run_until_burnchain_height, test_observer, wait_for_runloop,
};
use crate::tests::to_addr;
use crate::{BitcoinRegtestController, BurnchainController};

// Helper struct for holding the btc and stx neon nodes
#[allow(dead_code)]
pub struct RunningNodes {
    pub btc_regtest_controller: BitcoinRegtestController,
    pub btcd_controller: BitcoinCoreController,
    pub run_loop_thread: thread::JoinHandle<()>,
    pub run_loop_stopper: Arc<AtomicBool>,
    pub vrfs_submitted: Arc<AtomicU64>,
    pub commits_submitted: Arc<AtomicU64>,
    pub blocks_processed: Arc<AtomicU64>,
    pub coord_channel: Arc<Mutex<CoordinatorChannels>>,
    pub conf: NeonConfig,
}

/// A test harness for running a v0 or v1 signer integration test
pub struct SignerTest<S> {
    // The stx and bitcoin nodes and their run loops
    pub running_nodes: RunningNodes,
    // The spawned signers and their threads
    pub spawned_signers: Vec<S>,
    // the private keys of the signers
    pub signer_stacks_private_keys: Vec<StacksPrivateKey>,
    // link to the stacks node
    pub stacks_client: StacksClient,
    // Unique number used to isolate files created during the test
    pub run_stamp: u16,
}

impl<S: Signer<T> + Send + 'static, T: SignerEventTrait + 'static> SignerTest<SpawnedSigner<S, T>> {
    fn new(num_signers: usize) -> Self {
        // Generate Signer Data
        let signer_stacks_private_keys = (0..num_signers)
            .map(|_| StacksPrivateKey::new())
            .collect::<Vec<StacksPrivateKey>>();

        let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
        // So the combination is... one, two, three, four, five? That's the stupidest combination I've ever heard in my life!
        // That's the kind of thing an idiot would have on his luggage!
        let password = "12345";
        naka_conf.connection_options.block_proposal_token = Some(password.to_string());

        let run_stamp = rand::random();

        // Setup the signer and coordinator configurations
        let signer_configs = build_signer_config_tomls(
            &signer_stacks_private_keys,
            &naka_conf.node.rpc_bind,
            Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
            &Network::Testnet,
            password,
            run_stamp,
            3000,
            Some(100_000),
            None,
            Some(9000),
        );

        let spawned_signers: Vec<_> = (0..num_signers)
            .into_iter()
            .map(|i| {
                info!("spawning signer");
                let signer_config =
                    SignerConfig::load_from_str(&signer_configs[i as usize]).unwrap();
                SpawnedSigner::new(signer_config)
            })
            .collect();

        // Setup the nodes and deploy the contract to it
        let node = setup_stx_btc_node(naka_conf, &signer_stacks_private_keys, &signer_configs);
        let config = SignerConfig::load_from_str(&signer_configs[0]).unwrap();
        let stacks_client = StacksClient::from(&config);

        Self {
            running_nodes: node,
            spawned_signers,
            signer_stacks_private_keys,
            stacks_client,
            run_stamp,
        }
    }

    fn send_status_request(&self) {
        for port in 3000..3000 + self.spawned_signers.len() {
            let endpoint = format!("http://localhost:{}", port);
            let path = format!("{endpoint}/status");
            let client = reqwest::blocking::Client::new();
            let response = client
                .get(path)
                .send()
                .expect("Failed to send status request");
            assert!(response.status().is_success())
        }
    }

    /// Wait for the signers to respond to a status check
    fn wait_for_states(&mut self, timeout: Duration) -> Vec<State> {
        debug!("Waiting for Status...");
        let now = std::time::Instant::now();
        let mut states = Vec::with_capacity(self.spawned_signers.len());
        for signer in self.spawned_signers.iter() {
            let old_len = states.len();
            loop {
                assert!(
                    now.elapsed() < timeout,
                    "Timed out waiting for state checks"
                );
                let results = signer
                    .res_recv
                    .recv_timeout(timeout)
                    .expect("failed to recv state results");
                for result in results {
                    match result {
                        SignerResult::OperationResult(_operation) => {
                            panic!("Recieved an operation result.");
                        }
                        SignerResult::StatusCheck(state) => {
                            states.push(state);
                        }
                    }
                }
                if states.len() > old_len {
                    break;
                }
            }
        }
        debug!("Finished waiting for state checks!");
        states
    }

    fn nmb_blocks_to_reward_set_calculation(&mut self) -> u64 {
        let prepare_phase_len = self
            .running_nodes
            .conf
            .get_burnchain()
            .pox_constants
            .prepare_length as u64;
        let current_block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height()
            .saturating_sub(1); // Must subtract 1 since get_headers_height returns current block height + 1
        let curr_reward_cycle = self.get_current_reward_cycle();
        let next_reward_cycle = curr_reward_cycle.saturating_add(1);
        let next_reward_cycle_height = self
            .running_nodes
            .btc_regtest_controller
            .get_burnchain()
            .reward_cycle_to_block_height(next_reward_cycle);
        let next_reward_cycle_reward_set_calculation = next_reward_cycle_height
            .saturating_sub(prepare_phase_len)
            .saturating_add(1); // +1 as the reward calculation occurs in the SECOND block of the prepare phase/

        next_reward_cycle_reward_set_calculation.saturating_sub(current_block_height)
    }

    fn nmb_blocks_to_reward_cycle_boundary(&mut self, reward_cycle: u64) -> u64 {
        let current_block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height()
            .saturating_sub(1); // Must subtract 1 since get_headers_height returns current block height + 1
        let reward_cycle_height = self
            .running_nodes
            .btc_regtest_controller
            .get_burnchain()
            .reward_cycle_to_block_height(reward_cycle);
        reward_cycle_height.saturating_sub(current_block_height)
    }

    fn mine_and_verify_confirmed_naka_block(
        &mut self,
        agg_key: &Point,
        timeout: Duration,
    ) -> MinedNakamotoBlockEvent {
        let new_block = self.mine_nakamoto_block(timeout);
        let signer_sighash = new_block.signer_signature_hash.clone();
        let signature = self.wait_for_confirmed_block_v1(&signer_sighash, timeout);
        assert!(signature.0.verify(&agg_key, signer_sighash.as_bytes()));
        new_block
    }

    fn mine_nakamoto_block(&mut self, timeout: Duration) -> MinedNakamotoBlockEvent {
        let commits_submitted = self.running_nodes.commits_submitted.clone();
        let mined_block_time = Instant::now();
        next_block_and_mine_commit(
            &mut self.running_nodes.btc_regtest_controller,
            timeout.as_secs(),
            &self.running_nodes.coord_channel,
            &commits_submitted,
        )
        .unwrap();

        let t_start = Instant::now();
        while test_observer::get_mined_nakamoto_blocks().is_empty() {
            assert!(
                t_start.elapsed() < timeout,
                "Timed out while waiting for mined nakamoto block event"
            );
            thread::sleep(Duration::from_secs(1));
        }
        let mined_block_elapsed_time = mined_block_time.elapsed();
        info!(
            "Nakamoto block mine time elapsed: {:?}",
            mined_block_elapsed_time
        );
        test_observer::get_mined_nakamoto_blocks().pop().unwrap()
    }

    fn wait_for_confirmed_block_v1(
        &mut self,
        block_signer_sighash: &Sha512Trunc256Sum,
        timeout: Duration,
    ) -> ThresholdSignature {
        let block_obj = self.wait_for_confirmed_block_with_hash(block_signer_sighash, timeout);
        let signer_signature_hex = block_obj.get("signer_signature").unwrap().as_str().unwrap();
        let signer_signature_bytes = hex_bytes(&signer_signature_hex[2..]).unwrap();
        let signer_signature =
            ThresholdSignature::consensus_deserialize(&mut signer_signature_bytes.as_slice())
                .unwrap();
        signer_signature
    }

    /// Wait for a confirmed block and return a list of individual
    /// signer signatures
    fn wait_for_confirmed_block_v0(
        &mut self,
        block_signer_sighash: &Sha512Trunc256Sum,
        timeout: Duration,
    ) -> Vec<MessageSignature> {
        let block_obj = self.wait_for_confirmed_block_with_hash(block_signer_sighash, timeout);
        block_obj
            .get("signer_signature")
            .unwrap()
            .as_array()
            .expect("Expected signer_signature to be an array")
            .iter()
            .cloned()
            .map(serde_json::from_value::<MessageSignature>)
            .collect::<Result<Vec<_>, _>>()
            .expect("Unable to deserialize array of MessageSignature")
    }

    /// Wait for a confirmed block and return a list of individual
    /// signer signatures
    fn wait_for_confirmed_block_with_hash(
        &mut self,
        block_signer_sighash: &Sha512Trunc256Sum,
        timeout: Duration,
    ) -> serde_json::Map<String, serde_json::Value> {
        let t_start = Instant::now();
        while t_start.elapsed() <= timeout {
            let blocks = test_observer::get_blocks();
            if let Some(block) = blocks.iter().find_map(|block_json| {
                let block_obj = block_json.as_object().unwrap();
                let sighash = block_obj
                    // use the try operator because non-nakamoto blocks
                    // do not supply this field
                    .get("signer_signature_hash")?
                    .as_str()
                    .unwrap();
                if sighash != &format!("0x{block_signer_sighash}") {
                    return None;
                }
                Some(block_obj.clone())
            }) {
                return block;
            }
            thread::sleep(Duration::from_millis(500));
        }
        panic!("Timed out while waiting for confirmation of block with signer sighash = {block_signer_sighash}")
    }

    fn wait_for_block_validate_response(&mut self, timeout: Duration) -> BlockValidateResponse {
        // Wait for the block to show up in the test observer
        let t_start = Instant::now();
        while test_observer::get_proposal_responses().is_empty() {
            assert!(
                t_start.elapsed() < timeout,
                "Timed out while waiting for block proposal response event"
            );
            thread::sleep(Duration::from_secs(1));
        }
        test_observer::get_proposal_responses()
            .pop()
            .expect("No block proposal")
    }

    fn wait_for_validate_ok_response(&mut self, timeout: Duration) -> Sha512Trunc256Sum {
        let validate_response = self.wait_for_block_validate_response(timeout);
        match validate_response {
            BlockValidateResponse::Ok(block_validated) => block_validated.signer_signature_hash,
            _ => panic!("Unexpected response"),
        }
    }

    fn wait_for_validate_reject_response(&mut self, timeout: Duration) -> Sha512Trunc256Sum {
        // Wait for the block to show up in the test observer
        let validate_response = self.wait_for_block_validate_response(timeout);
        match validate_response {
            BlockValidateResponse::Reject(block_rejection) => block_rejection.signer_signature_hash,
            _ => panic!("Unexpected response"),
        }
    }

    // Must be called AFTER booting the chainstate
    fn run_until_epoch_3_boundary(&mut self) {
        let epochs = self.running_nodes.conf.burnchain.epochs.clone().unwrap();
        let epoch_3 =
            &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap()];

        let epoch_30_boundary = epoch_3.start_height - 1;
        // advance to epoch 3.0 and trigger a sign round (cannot vote on blocks in pre epoch 3.0)
        run_until_burnchain_height(
            &mut self.running_nodes.btc_regtest_controller,
            &self.running_nodes.blocks_processed,
            epoch_30_boundary,
            &self.running_nodes.conf,
        );
        info!("Advanced to Nakamoto epoch 3.0 boundary {epoch_30_boundary}! Ready to Sign Blocks!");
    }

    fn get_current_reward_cycle(&self) -> u64 {
        let block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        self.running_nodes
            .btc_regtest_controller
            .get_burnchain()
            .block_height_to_reward_cycle(block_height)
            .unwrap()
    }

    fn get_signer_index(&self, reward_cycle: u64) -> SignerSlotID {
        let valid_signer_set =
            u32::try_from(reward_cycle % 2).expect("FATAL: reward_cycle % 2 exceeds u32::MAX");
        let signer_stackerdb_contract_id = boot_code_id(SIGNERS_NAME, false);

        self.stacks_client
            .get_stackerdb_signer_slots(&signer_stackerdb_contract_id, valid_signer_set)
            .expect("FATAL: failed to get signer slots from stackerdb")
            .iter()
            .position(|(address, _)| address == self.stacks_client.get_signer_address())
            .map(|pos| {
                SignerSlotID(u32::try_from(pos).expect("FATAL: number of signers exceeds u32::MAX"))
            })
            .expect("FATAL: signer not registered")
    }

    fn get_signer_indices(&self, reward_cycle: u64) -> Vec<SignerSlotID> {
        let valid_signer_set =
            u32::try_from(reward_cycle % 2).expect("FATAL: reward_cycle % 2 exceeds u32::MAX");
        let signer_stackerdb_contract_id = boot_code_id(SIGNERS_NAME, false);

        self.stacks_client
            .get_stackerdb_signer_slots(&signer_stackerdb_contract_id, valid_signer_set)
            .expect("FATAL: failed to get signer slots from stackerdb")
            .iter()
            .enumerate()
            .map(|(pos, _)| {
                SignerSlotID(u32::try_from(pos).expect("FATAL: number of signers exceeds u32::MAX"))
            })
            .collect()
    }

    /// Get the wsts public keys for the given reward cycle
    fn get_signer_public_keys(&self, reward_cycle: u64) -> PublicKeys {
        let entries = self.get_reward_set_signers(reward_cycle);
        let entries = SignerEntries::parse(false, &entries).unwrap();
        entries.public_keys
    }

    /// Get the signers for the given reward cycle
    pub fn get_reward_set_signers(&self, reward_cycle: u64) -> Vec<NakamotoSignerEntry> {
        self.stacks_client
            .get_reward_set_signers(reward_cycle)
            .unwrap()
            .unwrap()
    }

    #[allow(dead_code)]
    fn get_signer_metrics(&self) -> String {
        #[cfg(feature = "monitoring_prom")]
        {
            let client = reqwest::blocking::Client::new();
            let res = client
                .get("http://localhost:9000/metrics")
                .send()
                .unwrap()
                .text()
                .unwrap();

            return res;
        }
        #[cfg(not(feature = "monitoring_prom"))]
        return String::new();
    }

    /// Kills the signer runloop at index `signer_idx`
    ///  and returns the private key of the killed signer.
    ///
    /// # Panics
    /// Panics if `signer_idx` is out of bounds
    pub fn stop_signer(&mut self, signer_idx: usize) -> StacksPrivateKey {
        let spawned_signer = self.spawned_signers.remove(signer_idx);
        let signer_key = self.signer_stacks_private_keys.remove(signer_idx);

        spawned_signer.stop();
        signer_key
    }

    /// (Re)starts a new signer runloop with the given private key
    pub fn restart_signer(&mut self, signer_idx: usize, signer_private_key: StacksPrivateKey) {
        let signer_config = build_signer_config_tomls(
            &[signer_private_key],
            &self.running_nodes.conf.node.rpc_bind,
            Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
            &Network::Testnet,
            "12345", // It worked sir, we have the combination! -Great, what's the combination?
            self.run_stamp,
            3000 + signer_idx,
            Some(100_000),
            None,
            Some(9000 + signer_idx),
        )
        .pop()
        .unwrap();

        info!("Restarting signer");
        let config = SignerConfig::load_from_str(&signer_config).unwrap();
        let signer = SpawnedSigner::new(config);
        self.spawned_signers.insert(signer_idx, signer);
    }

    pub fn shutdown(self) {
        self.running_nodes
            .coord_channel
            .lock()
            .expect("Mutex poisoned")
            .stop_chains_coordinator();

        self.running_nodes
            .run_loop_stopper
            .store(false, Ordering::SeqCst);
        // Stop the signers before the node to prevent hanging
        for signer in self.spawned_signers {
            assert!(signer.stop().is_none());
        }
        self.running_nodes.run_loop_thread.join().unwrap();
    }
}

fn setup_stx_btc_node(
    mut naka_conf: NeonConfig,
    signer_stacks_private_keys: &[StacksPrivateKey],
    signer_config_tomls: &[String],
) -> RunningNodes {
    // Spawn the endpoints for observing signers
    for toml in signer_config_tomls {
        let signer_config = SignerConfig::load_from_str(toml).unwrap();

        naka_conf.events_observers.insert(EventObserverConfig {
            endpoint: format!("{}", signer_config.endpoint),
            events_keys: vec![
                EventKeyType::StackerDBChunks,
                EventKeyType::BlockProposal,
                EventKeyType::BurnchainBlocks,
            ],
        });
    }

    // Spawn a test observer for verification purposes
    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![
            EventKeyType::StackerDBChunks,
            EventKeyType::BlockProposal,
            EventKeyType::MinedBlocks,
        ],
    });

    // The signers need some initial balances in order to pay for epoch 2.5 transaction votes
    let mut initial_balances = Vec::new();

    // TODO: separate keys for stacking and signing (because they'll be different in prod)
    for key in signer_stacks_private_keys {
        initial_balances.push(InitialBalance {
            address: to_addr(key).into(),
            amount: POX_4_DEFAULT_STACKER_BALANCE,
        });
    }
    naka_conf.initial_balances.append(&mut initial_balances);
    naka_conf.node.stacker = true;
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1000);

    for signer_set in 0..2 {
        for message_id in 0..SIGNER_SLOTS_PER_USER {
            let contract_id =
                NakamotoSigners::make_signers_db_contract_id(signer_set, message_id, false);
            if !naka_conf.node.stacker_dbs.contains(&contract_id) {
                debug!("A miner/stacker must subscribe to the {contract_id} stacker db contract. Forcibly subscribing...");
                naka_conf.node.stacker_dbs.push(contract_id);
            }
        }
    }
    info!("Make new BitcoinCoreController");
    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    info!("Make new BitcoinRegtestController");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);

    info!("Bootstraping...");
    btc_regtest_controller.bootstrap_chain(201);

    info!("Chain bootstrapped...");

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();
    let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));

    // Give the run loop some time to start up!
    info!("Wait for runloop...");
    wait_for_runloop(&blocks_processed);

    // First block wakes up the run loop.
    info!("Mine first block...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // Second block will hold our VRF registration.
    info!("Mine second block...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // Third block will be the first mined Stacks block.
    info!("Mine third block...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    RunningNodes {
        btcd_controller,
        btc_regtest_controller,
        run_loop_thread,
        run_loop_stopper,
        vrfs_submitted: vrfs_submitted.0,
        commits_submitted: commits_submitted.0,
        blocks_processed: blocks_processed.0,
        coord_channel,
        conf: naka_conf,
    }
}
