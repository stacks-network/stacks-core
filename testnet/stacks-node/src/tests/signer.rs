use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, thread};

use clarity::boot_util::boot_code_id;
use libsigner::{
    BlockResponse, RejectCode, RunningSigner, Signer, SignerEventReceiver, SignerMessage,
    BLOCK_MSG_ID,
};
use stacks::burnchains::Txid;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::nakamoto::signer_set::NakamotoSigners;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoBlockVote};
use stacks::chainstate::stacks::boot::SIGNERS_NAME;
use stacks::chainstate::stacks::miner::TransactionEvent;
use stacks::chainstate::stacks::{StacksPrivateKey, StacksTransaction, ThresholdSignature};
use stacks::core::StacksEpoch;
use stacks::net::api::postblock_proposal::BlockValidateResponse;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_signer::client::{StackerDB, StacksClient};
use stacks_signer::config::{build_signer_config_tomls, GlobalConfig as SignerConfig, Network};
use stacks_signer::runloop::RunLoopCommand;
use stacks_signer::signer::Command as SignerCommand;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use wsts::common::Signature;
use wsts::compute::tweaked_public_key;
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;
use wsts::state_machine::OperationResult;
use wsts::taproot::SchnorrProof;

use crate::config::{Config as NeonConfig, EventKeyType, EventObserverConfig, InitialBalance};
use crate::event_dispatcher::MinedNakamotoBlockEvent;
use crate::neon::Counters;
use crate::run_loop::boot_nakamoto;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::nakamoto_integrations::{
    boot_to_epoch_3_reward_set, naka_neon_integration_conf, next_block_and,
    next_block_and_mine_commit, POX_4_DEFAULT_STACKER_BALANCE,
};
use crate::tests::neon_integrations::{
    next_block_and_wait, run_until_burnchain_height, test_observer, wait_for_runloop,
};
use crate::tests::to_addr;
use crate::{BitcoinRegtestController, BurnchainController};

// Helper struct for holding the btc and stx neon nodes
#[allow(dead_code)]
struct RunningNodes {
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

struct SignerTest {
    // The stx and bitcoin nodes and their run loops
    pub running_nodes: RunningNodes,
    // The channels for sending commands to the signers
    pub signer_cmd_senders: Vec<Sender<RunLoopCommand>>,
    // The channels for receiving results from the signers
    pub result_receivers: Vec<Receiver<Vec<OperationResult>>>,
    // The running signer and its threads
    pub running_signers: Vec<RunningSigner<SignerEventReceiver, Vec<OperationResult>>>,
    // the private keys of the signers
    pub signer_stacks_private_keys: Vec<StacksPrivateKey>,
    // link to the stacks node
    pub stacks_client: StacksClient,
}

impl SignerTest {
    fn new(num_signers: usize) -> Self {
        // Generate Signer Data
        let signer_stacks_private_keys = (0..num_signers)
            .map(|_| StacksPrivateKey::new())
            .collect::<Vec<StacksPrivateKey>>();

        let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
        naka_conf.miner.self_signing_key = None;

        // Setup the signer and coordinator configurations
        let signer_configs = build_signer_config_tomls(
            &signer_stacks_private_keys,
            &naka_conf.node.rpc_bind,
            Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
            &Network::Testnet,
        );

        let mut running_signers = Vec::new();
        let mut signer_cmd_senders = Vec::new();
        let mut result_receivers = Vec::new();
        for i in 0..num_signers {
            let (cmd_send, cmd_recv) = channel();
            let (res_send, res_recv) = channel();
            info!("spawn signer");
            running_signers.push(spawn_signer(
                &signer_configs[i as usize],
                cmd_recv,
                res_send,
            ));
            signer_cmd_senders.push(cmd_send);
            result_receivers.push(res_recv);
        }

        // Setup the nodes and deploy the contract to it
        let node = setup_stx_btc_node(naka_conf, &signer_stacks_private_keys, &signer_configs);
        let config = SignerConfig::load_from_str(&signer_configs[0]).unwrap();
        let stacks_client = StacksClient::from(&config);

        Self {
            running_nodes: node,
            result_receivers,
            signer_cmd_senders,
            running_signers,
            signer_stacks_private_keys,
            stacks_client,
        }
    }

    fn boot_to_epoch_3(&mut self, timeout: Duration) -> Point {
        boot_to_epoch_3_reward_set(
            &self.running_nodes.conf,
            &self.running_nodes.blocks_processed,
            &self.signer_stacks_private_keys,
            &self.signer_stacks_private_keys,
            &mut self.running_nodes.btc_regtest_controller,
        );
        let dkg_vote = self.wait_for_dkg(timeout);

        // Advance and mine the DKG key block
        self.run_until_epoch_3_boundary();

        let reward_cycle = self.get_current_reward_cycle();
        let set_dkg = self
            .stacks_client
            .get_approved_aggregate_key(reward_cycle)
            .expect("Failed to get approved aggregate key")
            .expect("No approved aggregate key found");
        assert_eq!(set_dkg, dkg_vote);

        let (vrfs_submitted, commits_submitted) = (
            self.running_nodes.vrfs_submitted.clone(),
            self.running_nodes.commits_submitted.clone(),
        );
        // first block wakes up the run loop, wait until a key registration has been submitted.
        next_block_and(&mut self.running_nodes.btc_regtest_controller, 60, || {
            let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
            Ok(vrf_count >= 1)
        })
        .unwrap();

        info!("Successfully triggered first block to wake up the miner runloop.");
        // second block should confirm the VRF register, wait until a block commit is submitted
        next_block_and(&mut self.running_nodes.btc_regtest_controller, 60, || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count >= 1)
        })
        .unwrap();
        info!("Ready to mine Nakamoto blocks!");
        set_dkg
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
            .get_headers_height();
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
            .get_headers_height();
        let reward_cycle_height = self
            .running_nodes
            .btc_regtest_controller
            .get_burnchain()
            .reward_cycle_to_block_height(reward_cycle);
        reward_cycle_height
            .saturating_sub(current_block_height)
            .saturating_sub(1)
    }

    // Only call after already past the epoch 3.0 boundary
    fn run_to_dkg(&mut self, timeout: Duration) -> Option<Point> {
        let curr_reward_cycle = self.get_current_reward_cycle();
        let set_dkg = self
            .stacks_client
            .get_approved_aggregate_key(curr_reward_cycle)
            .expect("Failed to get approved aggregate key")
            .expect("No approved aggregate key found");
        let nmb_blocks_to_mine_to_dkg = self.nmb_blocks_to_reward_set_calculation();
        let end_block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height()
            .saturating_add(nmb_blocks_to_mine_to_dkg);
        info!("Mining {nmb_blocks_to_mine_to_dkg} Nakamoto block(s) to reach DKG calculation at block height {end_block_height}");
        for i in 1..=nmb_blocks_to_mine_to_dkg {
            info!("Mining Nakamoto block #{i} of {nmb_blocks_to_mine_to_dkg}");
            self.mine_nakamoto_block(timeout);
            let hash = self.wait_for_validate_ok_response(timeout);
            let signatures = self.wait_for_frost_signatures(timeout);
            // Verify the signers accepted the proposed block and are using the new DKG to sign it
            for signature in &signatures {
                assert!(signature.verify(&set_dkg, hash.0.as_slice()));
            }
        }
        if nmb_blocks_to_mine_to_dkg == 0 {
            None
        } else {
            Some(self.wait_for_dkg(timeout))
        }
    }

    // Only call after already past the epoch 3.0 boundary
    fn run_until_burnchain_height_nakamoto(
        &mut self,
        timeout: Duration,
        burnchain_height: u64,
    ) -> Vec<Point> {
        let mut points = vec![];
        let current_block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        let mut total_nmb_blocks_to_mine = burnchain_height.saturating_sub(current_block_height);
        debug!("Mining {total_nmb_blocks_to_mine} Nakamoto block(s) to reach burnchain height {burnchain_height}");
        let mut nmb_blocks_to_reward_cycle = 0;
        let mut blocks_to_dkg = self.nmb_blocks_to_reward_set_calculation();
        while total_nmb_blocks_to_mine > 0 && blocks_to_dkg > 0 {
            if blocks_to_dkg > 0 && total_nmb_blocks_to_mine >= blocks_to_dkg {
                let dkg = self.run_to_dkg(timeout);
                total_nmb_blocks_to_mine -= blocks_to_dkg;
                if dkg.is_some() {
                    points.push(dkg.unwrap());
                }
                blocks_to_dkg = 0;
                nmb_blocks_to_reward_cycle = self.nmb_blocks_to_reward_cycle_boundary(
                    self.get_current_reward_cycle().saturating_add(1),
                )
            }
            if total_nmb_blocks_to_mine >= nmb_blocks_to_reward_cycle {
                debug!("Mining {nmb_blocks_to_reward_cycle} Nakamoto block(s) to reach the next reward cycle boundary.");
                for i in 1..=nmb_blocks_to_reward_cycle {
                    debug!("Mining Nakamoto block #{i} of {nmb_blocks_to_reward_cycle}");
                    let curr_reward_cycle = self.get_current_reward_cycle();
                    let set_dkg = self
                        .stacks_client
                        .get_approved_aggregate_key(curr_reward_cycle)
                        .expect("Failed to get approved aggregate key")
                        .expect("No approved aggregate key found");
                    self.mine_nakamoto_block(timeout);
                    let hash = self.wait_for_validate_ok_response(timeout);
                    let signatures = self.wait_for_frost_signatures(timeout);
                    // Verify the signers accepted the proposed block and are using the new DKG to sign it
                    for signature in &signatures {
                        assert!(signature.verify(&set_dkg, hash.0.as_slice()));
                    }
                }
                total_nmb_blocks_to_mine -= nmb_blocks_to_reward_cycle;
                nmb_blocks_to_reward_cycle = 0;
                blocks_to_dkg = self.nmb_blocks_to_reward_set_calculation();
            }
        }
        for _ in 1..=total_nmb_blocks_to_mine {
            let curr_reward_cycle = self.get_current_reward_cycle();
            let set_dkg = self
                .stacks_client
                .get_approved_aggregate_key(curr_reward_cycle)
                .expect("Failed to get approved aggregate key")
                .expect("No approved aggregate key found");
            self.mine_nakamoto_block(timeout);
            let hash = self.wait_for_validate_ok_response(timeout);
            let signatures = self.wait_for_frost_signatures(timeout);
            // Verify the signers accepted the proposed block and are using the new DKG to sign it
            for signature in &signatures {
                assert!(signature.verify(&set_dkg, hash.0.as_slice()));
            }
        }
        points
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

    fn wait_for_validate_ok_response(&mut self, timeout: Duration) -> Sha512Trunc256Sum {
        // Wait for the block to show up in the test observer (Don't have to wait long as if we have received a mined block already,
        // we know that the signers have already received their block proposal events via their event observers)
        let t_start = Instant::now();
        while test_observer::get_proposal_responses().is_empty() {
            assert!(
                t_start.elapsed() < timeout,
                "Timed out while waiting for block proposal event"
            );
            thread::sleep(Duration::from_secs(1));
        }
        let validate_response = test_observer::get_proposal_responses()
            .pop()
            .expect("No block proposal");
        match validate_response {
            BlockValidateResponse::Ok(block_validated) => block_validated.signer_signature_hash,
            _ => panic!("Unexpected response"),
        }
    }

    fn wait_for_dkg(&mut self, timeout: Duration) -> Point {
        debug!("Waiting for DKG...");
        let mut key = Point::default();
        let dkg_now = Instant::now();
        for recv in self.result_receivers.iter() {
            let mut aggregate_public_key = None;
            loop {
                let results = recv
                    .recv_timeout(timeout)
                    .expect("failed to recv dkg results");
                for result in results {
                    match result {
                        OperationResult::Sign(sig) => {
                            panic!("Received Signature ({},{})", &sig.R, &sig.z);
                        }
                        OperationResult::SignTaproot(proof) => {
                            panic!("Received SchnorrProof ({},{})", &proof.r, &proof.s);
                        }
                        OperationResult::DkgError(dkg_error) => {
                            panic!("Received DkgError {:?}", dkg_error);
                        }
                        OperationResult::SignError(sign_error) => {
                            panic!("Received SignError {}", sign_error);
                        }
                        OperationResult::Dkg(point) => {
                            info!("Received aggregate_group_key {point}");
                            aggregate_public_key = Some(point);
                        }
                    }
                }
                if aggregate_public_key.is_some() || dkg_now.elapsed() > timeout {
                    break;
                }
            }
            key = aggregate_public_key.expect(&format!(
                "Failed to get aggregate public key within {timeout:?}"
            ));
        }
        debug!("Finished waiting for DKG!");
        key
    }

    fn wait_for_frost_signatures(&mut self, timeout: Duration) -> Vec<Signature> {
        debug!("Waiting for frost signatures...");
        let mut results = Vec::new();
        let sign_now = Instant::now();
        for recv in self.result_receivers.iter() {
            let mut frost_signature = None;
            loop {
                let results = recv
                    .recv_timeout(timeout)
                    .expect("failed to recv signature results");
                for result in results {
                    match result {
                        OperationResult::Sign(sig) => {
                            info!("Received Signature ({},{})", &sig.R, &sig.z);
                            frost_signature = Some(sig);
                        }
                        OperationResult::SignTaproot(proof) => {
                            panic!("Received SchnorrProof ({},{})", &proof.r, &proof.s);
                        }
                        OperationResult::DkgError(dkg_error) => {
                            panic!("Received DkgError {:?}", dkg_error);
                        }
                        OperationResult::SignError(sign_error) => {
                            panic!("Received SignError {}", sign_error);
                        }
                        OperationResult::Dkg(point) => {
                            panic!("Received aggregate_group_key {point}");
                        }
                    }
                }
                if frost_signature.is_some() || sign_now.elapsed() > timeout {
                    break;
                }
            }

            let frost_signature = frost_signature
                .expect(&format!("Failed to get frost signature within {timeout:?}"));
            results.push(frost_signature);
        }
        debug!("Finished waiting for frost signatures!");
        results
    }

    fn wait_for_taproot_signatures(&mut self, timeout: Duration) -> Vec<SchnorrProof> {
        debug!("Waiting for taproot signatures...");
        let mut results = vec![];
        let sign_now = Instant::now();
        for recv in self.result_receivers.iter() {
            let mut schnorr_proof = None;
            loop {
                let results = recv
                    .recv_timeout(timeout)
                    .expect("failed to recv signature results");
                for result in results {
                    match result {
                        OperationResult::Sign(sig) => {
                            panic!("Received Signature ({},{})", &sig.R, &sig.z);
                        }
                        OperationResult::SignTaproot(proof) => {
                            info!("Received SchnorrProof ({},{})", &proof.r, &proof.s);
                            schnorr_proof = Some(proof);
                        }
                        OperationResult::DkgError(dkg_error) => {
                            panic!("Received DkgError {:?}", dkg_error);
                        }
                        OperationResult::SignError(sign_error) => {
                            panic!("Received SignError {}", sign_error);
                        }
                        OperationResult::Dkg(point) => {
                            panic!("Received aggregate_group_key {point}");
                        }
                    }
                }
                if schnorr_proof.is_some() || sign_now.elapsed() > timeout {
                    break;
                }
            }
            let schnorr_proof = schnorr_proof.expect(&format!(
                "Failed to get schnorr proof signature within {timeout:?}"
            ));
            results.push(schnorr_proof);
        }
        debug!("Finished waiting for taproot signatures!");
        results
    }

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

    fn get_signer_index(&self, reward_cycle: u64) -> u32 {
        let valid_signer_set =
            u32::try_from(reward_cycle % 2).expect("FATAL: reward_cycle % 2 exceeds u32::MAX");
        let signer_stackerdb_contract_id = boot_code_id(SIGNERS_NAME, false);

        self.stacks_client
            .get_stackerdb_signer_slots(&signer_stackerdb_contract_id, valid_signer_set)
            .expect("FATAL: failed to get signer slots from stackerdb")
            .iter()
            .position(|(address, _)| address == self.stacks_client.get_signer_address())
            .map(|pos| u32::try_from(pos).expect("FATAL: number of signers exceeds u32::MAX"))
            .expect("FATAL: signer not registered")
    }

    fn generate_invalid_transactions(&self) -> Vec<StacksTransaction> {
        let host = self
            .running_nodes
            .conf
            .node
            .rpc_bind
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        // Get the signer indices
        let reward_cycle = self.get_current_reward_cycle();
        let valid_signer_index = self.get_signer_index(reward_cycle);
        let round = self
            .stacks_client
            .get_last_round(reward_cycle)
            .expect("FATAL: failed to get round")
            .unwrap_or(0)
            .saturating_add(1);
        let point = Point::from(Scalar::random(&mut rand::thread_rng()));
        let invalid_nonce_tx = self
            .stacks_client
            .build_vote_for_aggregate_public_key(
                valid_signer_index,
                round,
                point,
                reward_cycle,
                None,
                0, // Old nonce
            )
            .expect("FATAL: failed to build vote for aggregate public key");
        let invalid_stacks_client = StacksClient::new(StacksPrivateKey::new(), host, false);
        let invalid_signer_tx = invalid_stacks_client
            .build_vote_for_aggregate_public_key(
                valid_signer_index,
                round,
                point,
                reward_cycle,
                None,
                0,
            )
            .expect("FATAL: failed to build vote for aggregate public key");
        // TODO: add invalid contract calls (one with non 'vote-for-aggregate-public-key' function call and one with invalid function args)
        vec![invalid_nonce_tx, invalid_signer_tx]
    }

    fn shutdown(self) {
        self.running_nodes
            .coord_channel
            .lock()
            .expect("Mutex poisoned")
            .stop_chains_coordinator();

        self.running_nodes
            .run_loop_stopper
            .store(false, Ordering::SeqCst);
        // Stop the signers before the node to prevent hanging
        for signer in self.running_signers {
            assert!(signer.stop().is_none());
        }
        self.running_nodes.run_loop_thread.join().unwrap();
    }
}

fn spawn_signer(
    data: &str,
    receiver: Receiver<RunLoopCommand>,
    sender: Sender<Vec<OperationResult>>,
) -> RunningSigner<SignerEventReceiver, Vec<OperationResult>> {
    let config = SignerConfig::load_from_str(data).unwrap();
    let ev = SignerEventReceiver::new(config.network.is_mainnet());
    let endpoint = config.endpoint;
    let runloop: stacks_signer::runloop::RunLoop = stacks_signer::runloop::RunLoop::from(config);
    let mut signer: Signer<
        RunLoopCommand,
        Vec<OperationResult>,
        stacks_signer::runloop::RunLoop,
        SignerEventReceiver,
    > = Signer::new(runloop, ev, receiver, sender);
    info!("Spawning signer on endpoint {}", endpoint);
    signer.spawn(endpoint).unwrap()
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
            events_keys: vec![EventKeyType::StackerDBChunks, EventKeyType::BlockProposal],
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
        vrfs_submitted,
        commits_submitted,
        blocks_processed,
        coord_channel,
        conf: naka_conf,
    }
}

#[test]
#[ignore]
/// Test the signer can respond to external commands to perform DKG
fn stackerdb_dkg() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let timeout = Duration::from_secs(200);
    let mut signer_test = SignerTest::new(10);
    info!("Boot to epoch 3.0 reward calculation...");
    boot_to_epoch_3_reward_set(
        &signer_test.running_nodes.conf,
        &signer_test.running_nodes.blocks_processed,
        &signer_test.signer_stacks_private_keys,
        &signer_test.signer_stacks_private_keys,
        &mut signer_test.running_nodes.btc_regtest_controller,
    );

    info!("Pox 4 activated and at epoch 3.0 reward set calculation (2nd block of its prepare phase)! Ready for signers to perform DKG and Sign!");
    // First wait for the automatically triggered DKG to complete
    let key = signer_test.wait_for_dkg(timeout);

    info!("------------------------- Test DKG -------------------------");
    let reward_cycle = signer_test.get_current_reward_cycle().saturating_add(1);

    // Determine the coordinator of the current node height
    info!("signer_runloop: spawn send commands to do dkg");
    let dkg_now = Instant::now();
    for sender in signer_test.signer_cmd_senders.iter() {
        sender
            .send(RunLoopCommand {
                reward_cycle,
                command: SignerCommand::Dkg,
            })
            .expect("failed to send DKG command");
    }
    let new_key = signer_test.wait_for_dkg(timeout);
    let dkg_elapsed = dkg_now.elapsed();
    assert_ne!(new_key, key);

    info!("DKG Time Elapsed: {:.2?}", dkg_elapsed);
}

#[test]
#[ignore]
/// Test the signer can respond to external commands to perform DKG
fn stackerdb_sign() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");

    info!("Creating an invalid block to sign...");
    let header = NakamotoBlockHeader {
        version: 1,
        chain_length: 2,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::empty(),
        signer_bitvec: BitVec::zeros(1).unwrap(),
    };
    let mut block = NakamotoBlock {
        header,
        txs: vec![],
    };
    let tx_merkle_root = {
        let txid_vecs = block
            .txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };
    block.header.tx_merkle_root = tx_merkle_root;

    // The block is invalid so the signers should return a signature across a rejection
    let block_vote = NakamotoBlockVote {
        signer_signature_hash: block.header.signer_signature_hash(),
        rejected: true,
    };
    let msg = block_vote.serialize_to_vec();

    let timeout = Duration::from_secs(200);
    let mut signer_test = SignerTest::new(10);
    let key = signer_test.boot_to_epoch_3(timeout);

    info!("------------------------- Test Sign -------------------------");
    let reward_cycle = signer_test.get_current_reward_cycle();
    // Determine the coordinator of the current node height
    info!("signer_runloop: spawn send commands to do sign");
    let sign_now = Instant::now();
    let sign_command = RunLoopCommand {
        reward_cycle,
        command: SignerCommand::Sign {
            block: block.clone(),
            is_taproot: false,
            merkle_root: None,
        },
    };
    let sign_taproot_command = RunLoopCommand {
        reward_cycle,
        command: SignerCommand::Sign {
            block: block.clone(),
            is_taproot: true,
            merkle_root: None,
        },
    };
    for sender in signer_test.signer_cmd_senders.iter() {
        sender
            .send(sign_command.clone())
            .expect("failed to send sign command");
        sender
            .send(sign_taproot_command.clone())
            .expect("failed to send sign taproot command");
    }
    let frost_signatures = signer_test.wait_for_frost_signatures(timeout);
    let schnorr_proofs = signer_test.wait_for_taproot_signatures(timeout);

    for frost_signature in frost_signatures {
        assert!(frost_signature.verify(&key, &msg));
    }
    for schnorr_proof in schnorr_proofs {
        let tweaked_key = tweaked_public_key(&key, None);
        assert!(
            schnorr_proof.verify(&tweaked_key.x(), &msg),
            "Schnorr proof verification failed"
        );
    }
    let sign_elapsed = sign_now.elapsed();

    info!("------------------------- Test Block Accepted -------------------------");

    // Verify the signers rejected the proposed block
    let t_start = Instant::now();
    let mut chunk = None;
    while chunk.is_none() {
        assert!(
            t_start.elapsed() < Duration::from_secs(30),
            "Timed out while waiting for signers block response stacker db event"
        );

        let nakamoto_blocks = test_observer::get_stackerdb_chunks();
        for event in nakamoto_blocks {
            // Only care about the miners block slot
            if event.contract_id.name == format!("signers-1-{}", BLOCK_MSG_ID).as_str().into()
                || event.contract_id.name == format!("signers-0-{}", BLOCK_MSG_ID).as_str().into()
            {
                for slot in event.modified_slots {
                    chunk = Some(slot.data);
                    break;
                }
                if chunk.is_some() {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    let chunk = chunk.unwrap();
    let signer_message = read_next::<SignerMessage, _>(&mut &chunk[..]).unwrap();
    if let SignerMessage::BlockResponse(BlockResponse::Rejected(rejection)) = signer_message {
        assert!(matches!(
            rejection.reason_code,
            RejectCode::ValidationFailed(_)
        ));
    } else {
        panic!("Received unexpected message: {:?}", &signer_message);
    }
    info!("Sign Time Elapsed: {:.2?}", sign_elapsed);
}

#[test]
#[ignore]
/// Test that a signer can respond to a miners request for a signature on a block proposal
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is advanced to epoch 2.5. forcibly triggering DKG to set the key correctly
/// The stacks node is next advanced to epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node attempts to mine a Nakamoto block, sending a block to the observing signers via the
/// .miners stacker db instance. The signers submit the block to the stacks node for verification.
/// Upon receiving a Block Validation response approving the block, the signers perform a signing
/// round across its signature hash and return it back to the miner.
///
/// Test Assertion:
/// Signers return an operation result containing a valid signature across the miner's Nakamoto block's signature hash.
/// Signers broadcasted a signature across the miner's proposed block back to the respective .signers-XXX-YYY contract.
/// Miner appends the signature to the block and finishes mininig it.
fn stackerdb_block_proposal() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let mut signer_test = SignerTest::new(5);
    let timeout = Duration::from_secs(200);
    let short_timeout = Duration::from_secs(30);

    let key = signer_test.boot_to_epoch_3(timeout);
    signer_test.mine_nakamoto_block(timeout);

    info!("------------------------- Test Block Proposal -------------------------");
    // Verify that the signers accepted the proposed block, sending back a validate ok response
    let proposed_signer_signature_hash = signer_test.wait_for_validate_ok_response(short_timeout);

    info!("------------------------- Test Block Signed -------------------------");
    // Verify that the signers signed the proposed block
    let frost_signatures = signer_test.wait_for_frost_signatures(short_timeout);
    for signature in &frost_signatures {
        assert!(
            signature.verify(&key, proposed_signer_signature_hash.0.as_slice()),
            "Signature verification failed"
        );
    }
    info!("------------------------- Test Signers Broadcast Block -------------------------");
    // Verify that the signers broadcasted a signed NakamotoBlock back to the .signers contract
    let t_start = Instant::now();
    let mut chunk = None;
    while chunk.is_none() {
        assert!(
            t_start.elapsed() < short_timeout,
            "Timed out while waiting for signers block response stacker db event"
        );

        let nakamoto_blocks = test_observer::get_stackerdb_chunks();
        for event in nakamoto_blocks {
            if event.contract_id.name == format!("signers-1-{}", BLOCK_MSG_ID).as_str().into()
                || event.contract_id.name == format!("signers-0-{}", BLOCK_MSG_ID).as_str().into()
            {
                for slot in event.modified_slots {
                    chunk = Some(slot.data);
                    break;
                }
                if chunk.is_some() {
                    break;
                }
            }
            if chunk.is_some() {
                break;
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    let chunk = chunk.unwrap();
    let signer_message = read_next::<SignerMessage, _>(&mut &chunk[..]).unwrap();
    if let SignerMessage::BlockResponse(BlockResponse::Accepted((
        block_signer_signature_hash,
        block_signature,
    ))) = signer_message
    {
        assert_eq!(block_signer_signature_hash, proposed_signer_signature_hash);
        assert_eq!(
            block_signature,
            ThresholdSignature(frost_signatures.first().expect("No signature").clone())
        );
    } else {
        panic!("Received unexpected message");
    }
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers can handle a transition between Nakamoto reward cycles
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is advanced to epoch 2.5, triggering a DKG round. The stacks node is then advanced
/// to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 2 full Nakamoto reward cycles, sending blocks to observing signers to sign and return.
///
/// Test Assertion:
/// Signers can perform DKG and sign blocks across Nakamoto reward cycles.
fn stackerdb_mine_2_nakamoto_reward_cycles() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let nmb_reward_cycles = 2;
    let mut signer_test = SignerTest::new(5);
    let timeout = Duration::from_secs(200);
    let first_dkg = signer_test.boot_to_epoch_3(timeout);
    let curr_reward_cycle = signer_test.get_current_reward_cycle();
    // Mine 2 full Nakamoto reward cycles (epoch 3 starts in the middle of one, hence the + 1)
    let next_reward_cycle = curr_reward_cycle.saturating_add(1);
    let final_reward_cycle = next_reward_cycle.saturating_add(nmb_reward_cycles);
    let final_reward_cycle_height_boundary = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .reward_cycle_to_block_height(final_reward_cycle)
        .saturating_sub(1);

    info!("------------------------- Test Mine 2 Nakamoto Reward Cycles -------------------------");
    let dkgs = signer_test
        .run_until_burnchain_height_nakamoto(timeout, final_reward_cycle_height_boundary);
    assert_eq!(dkgs.len() as u64, nmb_reward_cycles.saturating_add(1)); // We will have mined the DKG vote for the following reward cycle
    let last_dkg = dkgs
        .last()
        .expect(&format!(
            "Failed to reach DKG for reward cycle {final_reward_cycle_height_boundary}"
        ))
        .clone();
    assert_ne!(first_dkg, last_dkg);

    let set_dkg = signer_test
        .stacks_client
        .get_approved_aggregate_key(final_reward_cycle)
        .expect("Failed to get approved aggregate key")
        .expect("No approved aggregate key found");
    assert_eq!(set_dkg, last_dkg);

    let current_burnchain_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    assert_eq!(current_burnchain_height, final_reward_cycle_height_boundary);
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers will accept a miners block proposal and sign it if it contains all expected transactions,
/// filtering invalid transactions from the block requirements
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is advanced to epoch 2.5, triggering a DKG round. The stacks node is then advanced
/// to Epoch 3.0 boundary to allow block signing. It then advances to the prepare phase of the next reward cycle
/// to enable Nakamoto signers to look at the next signer transactions to compare against a proposed block.
///
/// Test Execution:
/// The node attempts to mine a Nakamoto tenure, sending a block to the observing signers via the
/// .miners stacker db instance. The signers submit the block to the stacks node for verification.
/// Upon receiving a Block Validation response approving the block, the signers verify that it contains
/// all of the NEXT signers' expected transactions, being sure to filter out any invalid transactions
/// from stackerDB as well.
///
/// Test Assertion:
/// Miner proposes a block to the signers containing all expected transactions.
/// Signers broadcast block approval with a signature back to the waiting miner.
/// Miner includes the signers' signature in the block and finishes mining it.
fn stackerdb_filter_bad_transactions() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    // Advance to the prepare phase of a post epoch 3.0 reward cycle to force signers to look at the next signer transactions to compare against a proposed block
    let mut signer_test = SignerTest::new(5);
    let timeout = Duration::from_secs(200);
    let current_signers_dkg = signer_test.boot_to_epoch_3(timeout);
    let next_signers_dkg = signer_test
        .run_to_dkg(timeout)
        .expect("Failed to run to DKG");
    assert_ne!(current_signers_dkg, next_signers_dkg);

    info!("------------------------- Submit Invalid Transactions -------------------------");
    let host = signer_test
        .running_nodes
        .conf
        .node
        .rpc_bind
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let signer_private_key = signer_test
        .signer_stacks_private_keys
        .iter()
        .find(|pk| {
            let addr = to_addr(pk);
            addr == *signer_test.stacks_client.get_signer_address()
        })
        .cloned()
        .expect("Cannot find signer private key for signer id 1");
    let next_reward_cycle = signer_test.get_current_reward_cycle().saturating_add(1);
    // Must submit to the NEXT reward cycle slots as they are the ones looked at by the CURRENT miners
    let signer_index = signer_test.get_signer_index(next_reward_cycle);
    let mut stackerdb = StackerDB::new(
        host,
        signer_private_key,
        false,
        next_reward_cycle,
        signer_index,
    );

    debug!(
        "Signer address is {}",
        &signer_test.stacks_client.get_signer_address()
    );

    let invalid_txs = signer_test.generate_invalid_transactions();
    let invalid_txids: HashSet<Txid> = invalid_txs.iter().map(|tx| tx.txid()).collect();

    // Submit transactions to stackerdb for the signers and miners to pick up during block verification
    stackerdb
        .send_message_with_retry(SignerMessage::Transactions(invalid_txs))
        .expect("Failed to write expected transactions to stackerdb");

    info!("------------------------- Verify Nakamoto Block Mined -------------------------");
    let mined_block_event = signer_test.mine_nakamoto_block(timeout);
    let hash = signer_test.wait_for_validate_ok_response(timeout);
    let signatures = signer_test.wait_for_frost_signatures(timeout);
    // Verify the signers accepted the proposed block and are using the previously determined dkg to sign it
    for signature in &signatures {
        assert!(signature.verify(&current_signers_dkg, hash.0.as_slice()));
    }
    for tx_event in &mined_block_event.tx_events {
        let TransactionEvent::Success(tx_success) = tx_event else {
            panic!("Received unexpected transaction event");
        };
        // Since we never broadcast the "invalid" transaction to the mempool and the transaction did not come from a signer or had an invalid nonce
        // the miner should never construct a block that contains them and signers should still approve it
        assert!(
            !invalid_txids.contains(&tx_success.txid),
            "Miner included an invalid transaction in the block"
        );
    }
    signer_test.shutdown();
}
