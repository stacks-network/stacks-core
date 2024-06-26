use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, thread};

use clarity::boot_util::boot_code_id;
use clarity::vm::Value;
use libsigner::v1::messages::{BlockResponse, MessageSlotID, RejectCode, SignerMessage};
use libsigner::{BlockProposal, SignerEntries};
use rand::thread_rng;
use rand_core::RngCore;
use stacks::burnchains::Txid;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::nakamoto::signer_set::NakamotoSigners;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use stacks::chainstate::stacks::boot::{
    SIGNERS_NAME, SIGNERS_VOTING_FUNCTION_NAME, SIGNERS_VOTING_NAME,
};
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::miner::TransactionEvent;
use stacks::chainstate::stacks::{
    StacksPrivateKey, StacksTransaction, ThresholdSignature, TransactionAnchorMode,
    TransactionAuth, TransactionPayload, TransactionPostConditionMode, TransactionSmartContract,
    TransactionVersion,
};
use stacks::core::StacksEpoch;
use stacks::net::api::postblock_proposal::BlockValidateResponse;
use stacks::util_lib::strings::StacksString;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::{CHAIN_ID_TESTNET, SIGNER_SLOTS_PER_USER};
use stacks_common::types::chainstate::{
    ConsensusHash, StacksAddress, StacksBlockId, StacksPublicKey, TrieHash,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{hex_bytes, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_signer::client::{SignerSlotID, StackerDB, StacksClient};
use stacks_signer::config::{build_signer_config_tomls, GlobalConfig as SignerConfig, Network};
use stacks_signer::runloop::{RunLoopCommand, SignerCommand};
use stacks_signer::v1::coordinator::CoordinatorSelector;
use stacks_signer::v1::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;
use wsts::net::Message;
use wsts::state_machine::{OperationResult, PublicKeys};

use crate::config::{Config as NeonConfig, EventKeyType, EventObserverConfig, InitialBalance};
use crate::event_dispatcher::MinedNakamotoBlockEvent;
use crate::neon::Counters;
use crate::run_loop::boot_nakamoto;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::nakamoto_integrations::{
    boot_to_epoch_3_reward_set, boot_to_epoch_3_reward_set_calculation_boundary,
    naka_neon_integration_conf, next_block_and, next_block_and_mine_commit,
    POX_4_DEFAULT_STACKER_BALANCE,
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
    // The spawned signers and their threads
    pub spawned_signers: Vec<SpawnedSigner>,
    // the private keys of the signers
    pub signer_stacks_private_keys: Vec<StacksPrivateKey>,
    // link to the stacks node
    pub stacks_client: StacksClient,
    // Unique number used to isolate files created during the test
    pub run_stamp: u16,
}

impl SignerTest {
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
                SpawnedSigner::from(signer_config)
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
            .saturating_sub(1) // Must subtract 1 since get_headers_height returns current block height + 1
            .saturating_add(nmb_blocks_to_mine_to_dkg);
        info!("Mining {nmb_blocks_to_mine_to_dkg} bitcoin block(s) to reach DKG calculation at bitcoin height {end_block_height}");
        for i in 1..=nmb_blocks_to_mine_to_dkg {
            info!("Mining bitcoin block #{i} and nakamoto tenure of {nmb_blocks_to_mine_to_dkg}");
            self.mine_and_verify_confirmed_naka_block(&set_dkg, timeout);
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
                let end_block_height = self
                    .running_nodes
                    .btc_regtest_controller
                    .get_headers_height()
                    .saturating_sub(1) // Must subtract 1 since get_headers_height returns current block height + 1
                    .saturating_add(nmb_blocks_to_reward_cycle);
                debug!("Mining {nmb_blocks_to_reward_cycle} Nakamoto block(s) to reach the next reward cycle boundary at {end_block_height}.");
                for i in 1..=nmb_blocks_to_reward_cycle {
                    debug!("Mining Nakamoto block #{i} of {nmb_blocks_to_reward_cycle}");
                    let curr_reward_cycle = self.get_current_reward_cycle();
                    let set_dkg = self
                        .stacks_client
                        .get_approved_aggregate_key(curr_reward_cycle)
                        .expect("Failed to get approved aggregate key")
                        .expect("No approved aggregate key found");
                    self.mine_and_verify_confirmed_naka_block(&set_dkg, timeout);
                }
                total_nmb_blocks_to_mine -= nmb_blocks_to_reward_cycle;
                nmb_blocks_to_reward_cycle = 0;
                blocks_to_dkg = self.nmb_blocks_to_reward_set_calculation();
            }
        }
        for i in 1..=total_nmb_blocks_to_mine {
            info!("Mining Nakamoto block #{i} of {total_nmb_blocks_to_mine} to reach {burnchain_height}");
            let curr_reward_cycle = self.get_current_reward_cycle();
            let set_dkg = self
                .stacks_client
                .get_approved_aggregate_key(curr_reward_cycle)
                .expect("Failed to get approved aggregate key")
                .expect("No approved aggregate key found");
            self.mine_and_verify_confirmed_naka_block(&set_dkg, timeout);
        }
        points
    }

    fn mine_and_verify_confirmed_naka_block(
        &mut self,
        agg_key: &Point,
        timeout: Duration,
    ) -> MinedNakamotoBlockEvent {
        let new_block = self.mine_nakamoto_block(timeout);
        let signer_sighash = new_block.signer_signature_hash.clone();
        let signature = self.wait_for_confirmed_block(&signer_sighash, timeout);
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

    fn wait_for_confirmed_block(
        &mut self,
        block_signer_sighash: &Sha512Trunc256Sum,
        timeout: Duration,
    ) -> ThresholdSignature {
        let t_start = Instant::now();
        while t_start.elapsed() <= timeout {
            let blocks = test_observer::get_blocks();
            if let Some(signature) = blocks.iter().find_map(|block_json| {
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
                let signer_signature_hex =
                    block_obj.get("signer_signature").unwrap().as_str().unwrap();
                let signer_signature_bytes = hex_bytes(&signer_signature_hex[2..]).unwrap();
                let signer_signature = ThresholdSignature::consensus_deserialize(
                    &mut signer_signature_bytes.as_slice(),
                )
                .unwrap();
                Some(signer_signature)
            }) {
                return signature;
            }
            thread::sleep(Duration::from_millis(500));
        }
        panic!("Timed out while waiting for confirmation of block with signer sighash = {block_signer_sighash}")
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
        for signer in self.spawned_signers.iter() {
            let mut aggregate_public_key = None;
            loop {
                let results = signer
                    .res_recv
                    .recv_timeout(timeout)
                    .expect("failed to recv dkg results");
                for result in results {
                    match result {
                        OperationResult::Dkg(point) => {
                            info!("Received aggregate_group_key {point}");
                            aggregate_public_key = Some(point);
                        }
                        other => panic!("{}", operation_panic_message(&other)),
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

    fn get_signer_public_keys(&self, reward_cycle: u64) -> PublicKeys {
        let entries = self
            .stacks_client
            .get_reward_set_signers(reward_cycle)
            .unwrap()
            .unwrap();
        let entries = SignerEntries::parse(false, &entries).unwrap();
        entries.public_keys
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

        let signer_private_key = self.signer_stacks_private_keys[0];

        let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, false);
        let contract_addr = vote_contract_id.issuer.into();
        let contract_name = vote_contract_id.name.clone();

        let signer_index = thread_rng().next_u64();
        let signer_index_arg = Value::UInt(signer_index as u128);

        let point = Point::from(Scalar::random(&mut thread_rng()));
        let point_arg =
            Value::buff_from(point.compress().data.to_vec()).expect("Failed to create buff");

        let round = thread_rng().next_u64();
        let round_arg = Value::UInt(round as u128);

        let reward_cycle_arg = Value::UInt(reward_cycle as u128);
        let valid_function_args = vec![
            signer_index_arg.clone(),
            point_arg.clone(),
            round_arg.clone(),
            reward_cycle_arg.clone(),
        ];

        // Create a invalid transaction that is not a contract call
        let invalid_not_contract_call = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: CHAIN_ID_TESTNET,
            auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "test-contract".into(),
                    code_body: StacksString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };
        let invalid_contract_address = StacksClient::build_unsigned_contract_call_transaction(
            &StacksAddress::p2pkh(false, &StacksPublicKey::from_private(&signer_private_key)),
            contract_name.clone(),
            SIGNERS_VOTING_FUNCTION_NAME.into(),
            &valid_function_args,
            &signer_private_key,
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            1,
        )
        .unwrap();

        let invalid_contract_name = StacksClient::build_unsigned_contract_call_transaction(
            &contract_addr,
            "bad-signers-contract-name".into(),
            SIGNERS_VOTING_FUNCTION_NAME.into(),
            &valid_function_args,
            &signer_private_key,
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            1,
        )
        .unwrap();

        let invalid_signers_vote_function = StacksClient::build_unsigned_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            "some-other-function".into(),
            &valid_function_args,
            &signer_private_key,
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            1,
        )
        .unwrap();

        let invalid_function_arg_signer_index =
            StacksClient::build_unsigned_contract_call_transaction(
                &contract_addr,
                contract_name.clone(),
                SIGNERS_VOTING_FUNCTION_NAME.into(),
                &[
                    point_arg.clone(),
                    point_arg.clone(),
                    round_arg.clone(),
                    reward_cycle_arg.clone(),
                ],
                &signer_private_key,
                TransactionVersion::Testnet,
                CHAIN_ID_TESTNET,
                1,
            )
            .unwrap();

        let invalid_function_arg_key = StacksClient::build_unsigned_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            SIGNERS_VOTING_FUNCTION_NAME.into(),
            &[
                signer_index_arg.clone(),
                signer_index_arg.clone(),
                round_arg.clone(),
                reward_cycle_arg.clone(),
            ],
            &signer_private_key,
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            1,
        )
        .unwrap();

        let invalid_function_arg_round = StacksClient::build_unsigned_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            SIGNERS_VOTING_FUNCTION_NAME.into(),
            &[
                signer_index_arg.clone(),
                point_arg.clone(),
                point_arg.clone(),
                reward_cycle_arg.clone(),
            ],
            &signer_private_key,
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            1,
        )
        .unwrap();

        let invalid_function_arg_reward_cycle =
            StacksClient::build_unsigned_contract_call_transaction(
                &contract_addr,
                contract_name.clone(),
                SIGNERS_VOTING_FUNCTION_NAME.into(),
                &[
                    signer_index_arg.clone(),
                    point_arg.clone(),
                    round_arg.clone(),
                    point_arg.clone(),
                ],
                &signer_private_key,
                TransactionVersion::Testnet,
                CHAIN_ID_TESTNET,
                1,
            )
            .unwrap();

        let invalid_nonce = StacksClient::build_unsigned_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            SIGNERS_VOTING_FUNCTION_NAME.into(),
            &valid_function_args,
            &signer_private_key,
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            0, // Old nonce
        )
        .unwrap();

        let invalid_stacks_client = StacksClient::new(
            StacksPrivateKey::new(),
            host,
            "12345".to_string(), // That's amazing. I've got the same combination on my luggage!
            false,
        );
        let invalid_signer_tx = invalid_stacks_client
            .build_unsigned_vote_for_aggregate_public_key(0, round, point, reward_cycle, 0)
            .expect("FATAL: failed to build vote for aggregate public key");

        let unsigned_txs = vec![
            invalid_nonce,
            invalid_not_contract_call,
            invalid_contract_name,
            invalid_contract_address,
            invalid_signers_vote_function,
            invalid_function_arg_key,
            invalid_function_arg_reward_cycle,
            invalid_function_arg_round,
            invalid_function_arg_signer_index,
            invalid_signer_tx,
        ];
        unsigned_txs
            .into_iter()
            .map(|unsigned| {
                invalid_stacks_client
                    .sign_transaction(unsigned)
                    .expect("Failed to sign transaction")
            })
            .collect()
    }

    /// Kills the signer runloop at index `signer_idx`
    ///  and returns the private key of the killed signer.
    ///
    /// # Panics
    /// Panics if `signer_idx` is out of bounds
    fn stop_signer(&mut self, signer_idx: usize) -> StacksPrivateKey {
        let spawned_signer = self.spawned_signers.remove(signer_idx);
        let signer_key = self.signer_stacks_private_keys.remove(signer_idx);

        spawned_signer.stop();
        signer_key
    }

    /// (Re)starts a new signer runloop with the given private key
    fn restart_signer(&mut self, signer_idx: usize, signer_private_key: StacksPrivateKey) {
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
        let signer = SpawnedSigner::from(config);
        self.spawned_signers.insert(signer_idx, signer);
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

fn operation_panic_message(result: &OperationResult) -> String {
    match result {
        OperationResult::Sign(sig) => {
            format!("Received Signature ({},{})", sig.R, sig.z)
        }
        OperationResult::SignTaproot(proof) => {
            format!("Received SchnorrProof ({},{})", proof.r, proof.s)
        }
        OperationResult::DkgError(dkg_error) => {
            format!("Received DkgError {:?}", dkg_error)
        }
        OperationResult::SignError(sign_error) => {
            format!("Received SignError {}", sign_error)
        }
        OperationResult::Dkg(point) => {
            format!("Received aggregate_group_key {point}")
        }
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
    for signer in signer_test.spawned_signers.iter() {
        signer
            .cmd_send
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
/// Test the signer rejects requests to sign that do not come from a miner
fn stackerdb_sign_request_rejected() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");

    info!("Creating invalid blocks to sign...");
    let header1 = NakamotoBlockHeader {
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
    let mut block1 = NakamotoBlock {
        header: header1,
        txs: vec![],
    };
    let tx_merkle_root1 = {
        let txid_vecs = block1
            .txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };
    block1.header.tx_merkle_root = tx_merkle_root1;

    let header2 = NakamotoBlockHeader {
        version: 1,
        chain_length: 3,
        burn_spent: 4,
        consensus_hash: ConsensusHash([0x05; 20]),
        parent_block_id: StacksBlockId([0x06; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x07; 32]),
        state_index_root: TrieHash([0x08; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::empty(),
        signer_bitvec: BitVec::zeros(1).unwrap(),
    };
    let mut block2 = NakamotoBlock {
        header: header2,
        txs: vec![],
    };
    let tx_merkle_root2 = {
        let txid_vecs = block2
            .txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };
    block2.header.tx_merkle_root = tx_merkle_root2;

    let timeout = Duration::from_secs(200);
    let mut signer_test = SignerTest::new(10);
    let _key = signer_test.boot_to_epoch_3(timeout);

    info!("------------------------- Test Sign -------------------------");
    let reward_cycle = signer_test.get_current_reward_cycle();
    let block_proposal_1 = BlockProposal {
        block: block1.clone(),
        burn_height: 0,
        reward_cycle,
    };
    let block_proposal_2 = BlockProposal {
        block: block2.clone(),
        burn_height: 0,
        reward_cycle,
    };
    // Determine the coordinator of the current node height
    info!("signer_runloop: spawn send commands to do sign");
    let sign_now = Instant::now();
    let sign_command = RunLoopCommand {
        reward_cycle,
        command: SignerCommand::Sign {
            block_proposal: block_proposal_1,
            is_taproot: false,
            merkle_root: None,
        },
    };
    let sign_taproot_command = RunLoopCommand {
        reward_cycle,
        command: SignerCommand::Sign {
            block_proposal: block_proposal_2,
            is_taproot: true,
            merkle_root: None,
        },
    };
    for signer in signer_test.spawned_signers.iter() {
        signer
            .cmd_send
            .send(sign_command.clone())
            .expect("failed to send sign command");
        signer
            .cmd_send
            .send(sign_taproot_command.clone())
            .expect("failed to send sign taproot command");
    }

    // Don't wait for signatures. Because the block miner is acting as
    //  the coordinator, signers won't directly sign commands issued by someone
    //  other than the miner. Rather, they'll just broadcast their rejections.

    let sign_elapsed = sign_now.elapsed();

    info!("------------------------- Test Block Rejected -------------------------");

    // Verify the signers rejected the proposed block
    let t_start = Instant::now();
    let signer_message = loop {
        assert!(
            t_start.elapsed() < Duration::from_secs(30),
            "Timed out while waiting for signers block response stacker db event"
        );

        let nakamoto_blocks = test_observer::get_stackerdb_chunks();
        if let Some(message) = find_block_response(nakamoto_blocks) {
            break message;
        }
        thread::sleep(Duration::from_secs(1));
    };
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
/// Test that a signer can be offline when a DKG round has commenced and
/// can rejoin the DKG round after it has restarted
fn stackerdb_delayed_dkg() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let timeout = Duration::from_secs(200);
    let num_signers = 3;
    let mut signer_test = SignerTest::new(num_signers);
    boot_to_epoch_3_reward_set_calculation_boundary(
        &signer_test.running_nodes.conf,
        &signer_test.running_nodes.blocks_processed,
        &signer_test.signer_stacks_private_keys,
        &signer_test.signer_stacks_private_keys,
        &mut signer_test.running_nodes.btc_regtest_controller,
    );
    let reward_cycle = signer_test.get_current_reward_cycle().saturating_add(1);
    let public_keys = signer_test.get_signer_public_keys(reward_cycle);
    let coordinator_selector = CoordinatorSelector::from(public_keys);
    let (_, coordinator_public_key) = coordinator_selector.get_coordinator();
    let coordinator_public_key =
        StacksPublicKey::from_slice(coordinator_public_key.to_bytes().as_slice()).unwrap();
    let signer_slot_ids: Vec<_> = (0..num_signers)
        .into_iter()
        .map(|i| SignerSlotID(i as u32))
        .collect();
    let mut stackerdbs: Vec<_> = signer_slot_ids
        .iter()
        .map(|i| {
            StackerDB::new(
                &signer_test.running_nodes.conf.node.rpc_bind,
                StacksPrivateKey::new(), // Doesn't matter what key we use. We are just reading, not writing
                false,
                reward_cycle,
                *i,
            )
        })
        .collect();
    info!("------------------------- Stop Signers -------------------------");
    let mut to_stop = None;
    for (idx, key) in signer_test.signer_stacks_private_keys.iter().enumerate() {
        let public_key = StacksPublicKey::from_private(key);
        if public_key == coordinator_public_key {
            // Do not stop the coordinator. We want coordinator to start a DKG round
            continue;
        }
        // Only stop one signer
        to_stop = Some(idx);
        break;
    }
    let signer_idx = to_stop.expect("Failed to find a signer to stop");
    let signer_key = signer_test.stop_signer(signer_idx);
    debug!(
        "Removed signer {signer_idx} with key: {:?}, {}",
        signer_key,
        signer_key.to_hex()
    );
    info!("------------------------- Start DKG -------------------------");
    info!("Waiting for DKG to start...");
    // Advance one more to trigger DKG
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        timeout.as_secs(),
        || Ok(true),
    )
    .expect("Failed to mine bitcoin block");
    // Do not proceed until we guarantee that DKG was triggered
    let start_time = Instant::now();
    loop {
        let stackerdb = stackerdbs.first_mut().unwrap();
        let dkg_packets: Vec<_> = stackerdb
            .get_dkg_packets(&signer_slot_ids)
            .expect("Failed to get dkg packets");
        let begin_packets: Vec<_> = dkg_packets
            .iter()
            .filter_map(|packet| {
                if matches!(packet.msg, Message::DkgBegin(_)) {
                    Some(packet)
                } else {
                    None
                }
            })
            .collect();
        if !begin_packets.is_empty() {
            break;
        }
        assert!(
            start_time.elapsed() < Duration::from_secs(30),
            "Timed out waiting for DKG to be triggered"
        );
    }

    info!("------------------------- Restart Stopped Signer -------------------------");

    signer_test.restart_signer(signer_idx, signer_key);

    info!("------------------------- Wait for DKG -------------------------");
    let key = signer_test.wait_for_dkg(timeout);
    let mut transactions = HashSet::with_capacity(num_signers);
    let start_time = Instant::now();
    while transactions.len() < num_signers {
        for stackerdb in stackerdbs.iter_mut() {
            let current_transactions = stackerdb
                .get_current_transactions()
                .expect("Failed getting current transactions for signer slot id");
            for tx in current_transactions {
                transactions.insert(tx.txid());
            }
        }
        assert!(
            start_time.elapsed() < Duration::from_secs(30),
            "Failed to retrieve pending vote transactions within timeout"
        );
    }

    // Make sure transactions get mined
    let start_time = Instant::now();
    while !transactions.is_empty() {
        assert!(
            start_time.elapsed() < Duration::from_secs(30),
            "Failed to mine transactions within timeout"
        );
        next_block_and_wait(
            &mut signer_test.running_nodes.btc_regtest_controller,
            &signer_test.running_nodes.blocks_processed,
        );
        let blocks = test_observer::get_blocks();
        for block in blocks.iter() {
            let txs = block.get("transactions").unwrap().as_array().unwrap();
            for tx in txs.iter() {
                let raw_tx = tx.get("raw_tx").unwrap().as_str().unwrap();
                if raw_tx == "0x00" {
                    continue;
                }
                let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
                let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
                transactions.remove(&parsed.txid());
            }
        }
    }

    // Make sure DKG did get set
    assert_eq!(
        key,
        signer_test
            .stacks_client
            .get_approved_aggregate_key(reward_cycle)
            .expect("Failed to get approved aggregate key")
            .expect("No approved aggregate key found")
    );
}

pub fn find_block_response(chunk_events: Vec<StackerDBChunksEvent>) -> Option<SignerMessage> {
    for event in chunk_events.into_iter() {
        if event.contract_id.name.as_str()
            == &format!("signers-1-{}", MessageSlotID::BlockResponse.to_u8())
            || event.contract_id.name.as_str()
                == &format!("signers-0-{}", MessageSlotID::BlockResponse.to_u8())
        {
            let Some(data) = event.modified_slots.first() else {
                continue;
            };
            let msg = SignerMessage::consensus_deserialize(&mut data.data.as_slice()).unwrap();
            return Some(msg);
        }
    }
    None
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
    let num_signers = 5;
    let mut signer_test = SignerTest::new(num_signers);
    let timeout = Duration::from_secs(200);
    let short_timeout = Duration::from_secs(30);

    let key = signer_test.boot_to_epoch_3(timeout);
    signer_test.mine_nakamoto_block(timeout);

    info!("------------------------- Test Block Proposal -------------------------");
    // Verify that the signers accepted the proposed block, sending back a validate ok response
    let proposed_signer_signature_hash = signer_test.wait_for_validate_ok_response(short_timeout);

    info!("------------------------- Test Block Signed -------------------------");
    // Verify that the signers signed the proposed block
    let signature = signer_test.wait_for_confirmed_block(&proposed_signer_signature_hash, timeout);
    assert!(signature
        .0
        .verify(&key, proposed_signer_signature_hash.as_bytes()));

    // Test prometheus metrics response
    #[cfg(feature = "monitoring_prom")]
    {
        let metrics_response = signer_test.get_signer_metrics();

        // Because 5 signers are running in the same process, the prometheus metrics
        // are incremented once for every signer. This is why we expect the metric to be
        // `5`, even though there is only one block proposed.
        let expected_result = format!("stacks_signer_block_proposals_received {}", num_signers);
        assert!(metrics_response.contains(&expected_result));
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
        &signer_test.running_nodes.conf.node.rpc_bind,
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
    let mined_block_event =
        signer_test.mine_and_verify_confirmed_naka_block(&current_signers_dkg, timeout);
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

#[test]
#[ignore]
/// Test that signers will be able to continue their operations even if one signer is restarted.
///
/// Test Setup:
/// The test spins up three stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is advanced to epoch 2.5, triggering a DKG round. The stacks node is then advanced
/// to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The signers sign one block as usual.
/// Then, one of the signers is restarted.
/// Finally, the signers sign another block with the restarted signer.
///
/// Test Assertion:
/// The signers are able to produce a valid signature after one of them is restarted.
fn stackerdb_sign_after_signer_reboot() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 3;
    let mut signer_test = SignerTest::new(num_signers);
    let timeout = Duration::from_secs(200);
    let short_timeout = Duration::from_secs(30);

    let key = signer_test.boot_to_epoch_3(timeout);

    info!("------------------------- Test Mine Block -------------------------");

    signer_test.mine_nakamoto_block(timeout);
    let proposed_signer_signature_hash = signer_test.wait_for_validate_ok_response(short_timeout);
    let signature =
        signer_test.wait_for_confirmed_block(&proposed_signer_signature_hash, short_timeout);

    assert!(
        signature.verify(&key, proposed_signer_signature_hash.0.as_slice()),
        "Signature verification failed"
    );

    info!("------------------------- Restart one Signer -------------------------");
    let signer_key = signer_test.stop_signer(2);
    debug!(
        "Removed signer 2 with key: {:?}, {}",
        signer_key,
        signer_key.to_hex()
    );
    signer_test.restart_signer(2, signer_key);

    info!("------------------------- Test Mine Block after restart -------------------------");

    let last_block = signer_test.mine_nakamoto_block(timeout);
    let proposed_signer_signature_hash = signer_test.wait_for_validate_ok_response(short_timeout);
    let frost_signature =
        signer_test.wait_for_confirmed_block(&proposed_signer_signature_hash, short_timeout);

    // Check that the latest block's bitvec is all 1's
    assert_eq!(
        last_block.signer_bitvec,
        serde_json::to_value(BitVec::<4000>::ones(num_signers as u16).unwrap())
            .expect("Failed to serialize BitVec")
            .as_str()
            .expect("Failed to serialize BitVec")
    );

    assert!(
        frost_signature.verify(&key, proposed_signer_signature_hash.0.as_slice()),
        "Signature verification failed"
    );

    signer_test.shutdown();
}
