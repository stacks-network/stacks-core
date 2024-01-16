use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, thread};

use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{RunningSigner, Signer, SignerEventReceiver};
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::stacks::boot::MINERS_NAME;
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks::net::api::postblock_proposal::BlockValidateResponse;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks_signer::client::SIGNER_SLOTS_PER_USER;
use stacks_signer::config::{Config as SignerConfig, Network};
use stacks_signer::runloop::RunLoopCommand;
use stacks_signer::utils::{build_signer_config_tomls, build_stackerdb_contract};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::OperationResult;
use wsts::v2;

use crate::config::{Config as NeonConfig, EventKeyType, EventObserverConfig, InitialBalance};
use crate::neon::Counters;
use crate::run_loop::boot_nakamoto;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::nakamoto_integrations::{
    boot_to_epoch_3, naka_neon_integration_conf, next_block_and, next_block_and_mine_commit,
    setup_stacker,
};
use crate::tests::neon_integrations::{
    next_block_and_wait, submit_tx, test_observer, wait_for_runloop,
};
use crate::tests::{make_contract_publish, to_addr};
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
    // The channel for sending commands to the coordinator
    pub coordinator_cmd_sender: Sender<RunLoopCommand>,
    // The channels for sending commands to the signers
    pub _signer_cmd_senders: Vec<Sender<RunLoopCommand>>,
    // The channels for receiving results from both the coordinator and the signers
    pub result_receivers: Vec<Receiver<Vec<OperationResult>>>,
    // The running coordinator and its threads
    pub running_coordinator: RunningSigner<SignerEventReceiver, Vec<OperationResult>>,
    // The running signer and its threads
    pub running_signers: Vec<RunningSigner<SignerEventReceiver, Vec<OperationResult>>>,
}

impl SignerTest {
    fn new(num_signers: u32, num_keys: u32) -> Self {
        // Generate Signer Data
        let publisher_private_key = StacksPrivateKey::new();
        let signer_stacks_private_keys = (0..num_signers)
            .map(|_| StacksPrivateKey::new())
            .collect::<Vec<StacksPrivateKey>>();
        let signer_stacks_addresses = signer_stacks_private_keys
            .iter()
            .map(to_addr)
            .collect::<Vec<StacksAddress>>();

        // Build the stackerdb signers contract
        // TODO: Remove this once it is a boot contract
        let signers_stackerdb_contract =
            build_stackerdb_contract(&signer_stacks_addresses, SIGNER_SLOTS_PER_USER);
        let signers_stacker_db_contract_id = QualifiedContractIdentifier::new(
            to_addr(&publisher_private_key).into(),
            "signers".into(),
        );

        let (naka_conf, _miner_account) = naka_neon_integration_conf(None);

        // Setup the signer and coordinator configurations
        let signer_configs = build_signer_config_tomls(
            &signer_stacks_private_keys,
            num_keys,
            &naka_conf.node.rpc_bind,
            &signers_stacker_db_contract_id.to_string(),
            Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
        );

        let mut running_signers = vec![];
        let mut _signer_cmd_senders = vec![];
        // Spawn all the signers first to listen to the coordinator request for dkg
        let mut result_receivers = Vec::new();
        for i in (1..num_signers).rev() {
            let (cmd_send, cmd_recv) = channel();
            let (res_send, res_recv) = channel();
            info!("spawn signer");
            let running_signer = spawn_signer(&signer_configs[i as usize], cmd_recv, res_send);
            running_signers.push(running_signer);
            _signer_cmd_senders.push(cmd_send);
            result_receivers.push(res_recv);
        }
        // Spawn coordinator second
        let (coordinator_cmd_sender, coordinator_cmd_recv) = channel();
        let (coordinator_res_send, coordinator_res_receiver) = channel();
        info!("spawn coordinator");
        let running_coordinator = spawn_signer(
            &signer_configs[0],
            coordinator_cmd_recv,
            coordinator_res_send,
        );

        result_receivers.push(coordinator_res_receiver);

        // Setup the nodes and deploy the contract to it
        let node = setup_stx_btc_node(
            naka_conf,
            num_signers,
            &signer_stacks_private_keys,
            &publisher_private_key,
            &signers_stackerdb_contract,
            &signers_stacker_db_contract_id,
            &signer_configs,
        );

        Self {
            running_nodes: node,
            result_receivers,
            _signer_cmd_senders,
            coordinator_cmd_sender,
            running_coordinator,
            running_signers,
        }
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

        self.running_nodes.run_loop_thread.join().unwrap();
        // Stop the signers
        for signer in self.running_signers {
            assert!(signer.stop().is_none());
        }
        // Stop the coordinator
        assert!(self.running_coordinator.stop().is_none());
    }
}

fn spawn_signer(
    data: &str,
    receiver: Receiver<RunLoopCommand>,
    sender: Sender<Vec<OperationResult>>,
) -> RunningSigner<SignerEventReceiver, Vec<OperationResult>> {
    let config = stacks_signer::config::Config::load_from_str(data).unwrap();
    let ev = SignerEventReceiver::new(vec![
        boot_code_id(MINERS_NAME, config.network == Network::Mainnet),
        config.stackerdb_contract_id.clone(),
    ]);
    let runloop: stacks_signer::runloop::RunLoop<FireCoordinator<v2::Aggregator>> =
        stacks_signer::runloop::RunLoop::from(&config);
    let mut signer: Signer<
        RunLoopCommand,
        Vec<OperationResult>,
        stacks_signer::runloop::RunLoop<FireCoordinator<v2::Aggregator>>,
        SignerEventReceiver,
    > = Signer::new(runloop, ev, receiver, sender);
    let endpoint = config.endpoint;
    info!(
        "Spawning signer {} on endpoint {}",
        config.signer_id, endpoint
    );
    signer.spawn(endpoint).unwrap()
}

fn setup_stx_btc_node(
    mut naka_conf: NeonConfig,
    num_signers: u32,
    signer_stacks_private_keys: &[StacksPrivateKey],
    publisher_private_key: &StacksPrivateKey,
    stackerdb_contract: &str,
    stackerdb_contract_id: &QualifiedContractIdentifier,
    signer_config_tomls: &Vec<String>,
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
        events_keys: vec![EventKeyType::StackerDBChunks, EventKeyType::BlockProposal],
    });

    // The signers need some initial balances in order to pay for epoch 2.5 transaction votes
    let mut initial_balances = Vec::new();

    initial_balances.push(InitialBalance {
        address: to_addr(publisher_private_key).into(),
        amount: 10_000_000_000_000,
    });

    for i in 0..num_signers {
        initial_balances.push(InitialBalance {
            address: to_addr(&signer_stacks_private_keys[i as usize]).into(),
            amount: 10_000_000_000_000,
        });
    }
    naka_conf.initial_balances.append(&mut initial_balances);
    naka_conf
        .node
        .stacker_dbs
        .push(stackerdb_contract_id.clone());
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1000);

    let stacker_sk = setup_stacker(&mut naka_conf);

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

    info!("Send signers stacker-db contract-publish...");
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);

    let tx_fee = 100_000;
    let tx = make_contract_publish(
        publisher_private_key,
        0,
        tx_fee,
        &stackerdb_contract_id.name,
        stackerdb_contract,
    );
    submit_tx(&http_origin, &tx);
    // mine it
    info!("Mining the signers stackerdb contract: {stackerdb_contract_id}");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    info!("Boot to epoch 3.0 to activate pox-4...");
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        stacker_sk,
        StacksPublicKey::new(),
        &mut btc_regtest_controller,
    );

    info!("Pox 4 activated and ready for signers to perform DKG and sign!");
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
fn stackerdb_dkg_sign() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let signer_test = SignerTest::new(10, 400);
    info!("------------------------- Test DKG and Sign -------------------------");
    let now = std::time::Instant::now();
    info!("signer_runloop: spawn send commands to do dkg and then sign");
    signer_test
        .coordinator_cmd_sender
        .send(RunLoopCommand::Dkg)
        .expect("failed to send Dkg command");
    signer_test
        .coordinator_cmd_sender
        .send(RunLoopCommand::Sign {
            message: vec![1, 2, 3, 4, 5],
            is_taproot: false,
            merkle_root: None,
        })
        .expect("failed to send non taproot Sign command");
    signer_test
        .coordinator_cmd_sender
        .send(RunLoopCommand::Sign {
            message: vec![1, 2, 3, 4, 5],
            is_taproot: true,
            merkle_root: None,
        })
        .expect("failed to send taproot Sign command");
    for recv in signer_test.result_receivers.iter() {
        let mut aggregate_group_key = None;
        let mut frost_signature = None;
        let mut schnorr_proof = None;
        loop {
            let results = recv.recv().expect("failed to recv results");
            for result in results {
                match result {
                    OperationResult::Dkg(point) => {
                        info!("Received aggregate_group_key {point}");
                        aggregate_group_key = Some(point);
                    }
                    OperationResult::Sign(sig) => {
                        info!("Received Signature ({},{})", &sig.R, &sig.z);
                        frost_signature = Some(sig);
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
                }
            }
            if aggregate_group_key.is_some() && frost_signature.is_some() && schnorr_proof.is_some()
            {
                break;
            }
        }
    }
    let elapsed = now.elapsed();
    info!("DKG and Sign Time Elapsed: {:.2?}", elapsed);
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that a signer can respond to a miners request for a signature on a block proposal
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is advanced to epoch 3.0. and signers perform a DKG round (this should be removed
/// once we have proper casting of the vote during epoch 2.5).
///
/// Test Execution:
/// The node attempts to mine a Nakamoto tenure, sending a block to the observing signers via the
/// .miners stacker db instance. The signers submit the block to the stacks node for verification.
/// Upon receiving a Block Validation response approving the block, the signers perform a signing
/// round across its signature hash.
///
/// Test Assertion:
/// Signers return an operation result containing a valid signature across the miner's Nakamoto block's signature hash.
/// TODO: update this test to assert that the signers broadcast a Nakamoto block response back to the miners
fn stackerdb_block_proposal() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let mut signer_test = SignerTest::new(5, 5);

    // First run DKG in order to sign the block that arrives from the miners following a nakamoto block production
    // TODO: remove this forcibly running DKG once we have casting of the vote automagically happening during epoch 2.5
    info!("signer_runloop: spawn send commands to do dkg");
    signer_test
        .coordinator_cmd_sender
        .send(RunLoopCommand::Dkg)
        .expect("failed to send Dkg command");
    let mut aggregate_public_key = None;
    let recv = signer_test
        .result_receivers
        .last()
        .expect("Failed to get coordinator recv");
    let results = recv.recv().expect("failed to recv results");
    for result in results {
        match result {
            OperationResult::Dkg(point) => {
                info!("Received aggregate_group_key {point}");
                aggregate_public_key = Some(point);
                break;
            }
            _ => {
                panic!("Received Unexpected result");
            }
        }
    }
    let aggregate_public_key = aggregate_public_key.expect("Failed to get aggregate public key");

    let (vrfs_submitted, commits_submitted) = (
        signer_test.running_nodes.vrfs_submitted.clone(),
        signer_test.running_nodes.commits_submitted.clone(),
    );

    info!("Mining a Nakamoto tenure...");

    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
            Ok(vrf_count >= 1)
        },
    )
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count >= 1)
        },
    )
    .unwrap();

    // Mine 1 nakamoto tenure
    next_block_and_mine_commit(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
        &commits_submitted,
    )
    .unwrap();

    info!("------------------------- Test Block Processed -------------------------");
    let recv = signer_test
        .result_receivers
        .last()
        .expect("Failed to retreive coordinator recv");
    let results = recv.recv().expect("failed to recv results");
    let mut signature = None;
    for result in results {
        match result {
            OperationResult::Sign(sig) => {
                info!("Received Signature ({},{})", &sig.R, &sig.z);
                signature = Some(sig);
                break;
            }
            _ => {
                panic!("Unexpected operation result");
            }
        }
    }
    let signature = signature.expect("Failed to get signature");
    // Wait for the block to show up in the test observer (Don't have to wait long as if we have received a signature,
    // we know that the signers have already received their block proposal events via their event observers)
    let t_start = std::time::Instant::now();
    while test_observer::get_proposal_responses().is_empty() {
        assert!(
            t_start.elapsed() < Duration::from_secs(30),
            "Timed out while waiting for block proposal event"
        );
        thread::sleep(Duration::from_secs(1));
    }
    let validate_responses = test_observer::get_proposal_responses();
    let proposed_block = match validate_responses.first().expect("No block proposal") {
        BlockValidateResponse::Ok(block_validated) => block_validated.block.clone(),
        _ => panic!("Unexpected response"),
    };
    let signature_hash = proposed_block
        .header
        .signature_hash()
        .expect("Unable to retrieve signature hash from proposed block");
    assert!(
        signature.verify(&aggregate_public_key, signature_hash.0.as_slice()),
        "Signature verification failed"
    );
    signer_test.shutdown();
}
