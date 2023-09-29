use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;
use std::{env, thread};

use crate::{
    config::{Config as NeonConfig, EventKeyType, EventObserverConfig, InitialBalance},
    neon,
    tests::{
        bitcoin_regtest::BitcoinCoreController,
        make_contract_publish,
        neon_integrations::{
            neon_integration_test_conf, next_block_and_wait, submit_tx, wait_for_runloop,
        },
        to_addr,
    },
    BitcoinRegtestController, BurnchainController,
};
use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{RunningSigner, Signer, StackerDBEventReceiver};
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks_common::types::chainstate::StacksAddress;
use stacks_signer::{
    config::Config as SignerConfig,
    runloop::RunLoopCommand,
    utils::{build_signer_config_tomls, build_stackerdb_contract},
};
use wsts::{
    state_machine::{coordinator::Coordinator as FrostCoordinator, OperationResult},
    v1,
};

// Helper struct for holding the btc and stx neon nodes
#[allow(dead_code)]
struct RunningNodes {
    pub btc_regtest_controller: BitcoinRegtestController,
    pub btcd_controller: BitcoinCoreController,
    pub join_handle: thread::JoinHandle<()>,
    pub conf: NeonConfig,
}

fn spawn_signer(
    data: &str,
    receiver: Receiver<RunLoopCommand>,
    sender: Sender<Vec<OperationResult>>,
) -> RunningSigner<StackerDBEventReceiver, Vec<OperationResult>> {
    let config = stacks_signer::config::Config::load_from_str(data).unwrap();
    let ev = StackerDBEventReceiver::new(vec![config.stackerdb_contract_id.clone()]);
    let runloop: stacks_signer::runloop::RunLoop<FrostCoordinator<v1::Aggregator>> =
        stacks_signer::runloop::RunLoop::from(&config);
    let mut signer: Signer<
        RunLoopCommand,
        Vec<OperationResult>,
        stacks_signer::runloop::RunLoop<FrostCoordinator<v1::Aggregator>>,
        StackerDBEventReceiver,
    > = Signer::new(runloop, ev, receiver, sender);
    let endpoint = config.endpoint;
    info!(
        "Spawning signer {} on endpoint {}",
        config.signer_id, endpoint
    );
    signer.spawn(endpoint).unwrap()
}

fn setup_stx_btc_node(
    conf: &mut NeonConfig,
    num_signers: u32,
    signer_stacks_private_keys: &[StacksPrivateKey],
    stackerdb_contract: &str,
    signer_config_tomls: &Vec<String>,
) -> RunningNodes {
    for toml in signer_config_tomls {
        let signer_config = SignerConfig::load_from_str(toml).unwrap();

        conf.events_observers.push(EventObserverConfig {
            endpoint: format!("{}", signer_config.endpoint),
            events_keys: vec![EventKeyType::StackerDBChunks],
        });
    }

    let mut initial_balances = Vec::new();
    for i in 0..num_signers {
        initial_balances.push(InitialBalance {
            address: to_addr(&signer_stacks_private_keys[i as usize]).into(),
            amount: 10_000_000_000_000,
        });
    }

    conf.initial_balances.append(&mut initial_balances);
    conf.node.stacker_dbs.push(QualifiedContractIdentifier::new(
        to_addr(&signer_stacks_private_keys[0]).into(),
        "hello-world".into(),
    ));

    info!("Make new BitcoinCoreController");
    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    info!("Make new BitcoinRegtestController");
    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);

    info!("Bootstraping...");
    btc_regtest_controller.bootstrap_chain(201);

    info!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let join_handle = thread::spawn(move || run_loop.start(None, 0));

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

    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    info!("Send contract-publish...");
    let tx = make_contract_publish(
        &signer_stacks_private_keys[0],
        0,
        10_000,
        "hello-world",
        stackerdb_contract,
    );
    submit_tx(&http_origin, &tx);

    // mine it
    info!("Mine it...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    RunningNodes {
        btcd_controller,
        btc_regtest_controller,
        join_handle,
        conf: conf.clone(),
    }
}

#[test]
fn test_stackerdb_dkg() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    // Generate Signer Data
    let num_signers: u32 = 5;
    let num_keys: u32 = 20;
    let signer_stacks_private_keys = (0..num_signers)
        .map(|_| StacksPrivateKey::new())
        .collect::<Vec<StacksPrivateKey>>();
    let signer_stacks_addresses = signer_stacks_private_keys
        .iter()
        .map(|key| to_addr(key).into())
        .collect::<Vec<StacksAddress>>();

    // Setup the neon node
    let (mut conf, _) = neon_integration_test_conf();

    // Build the stackerdb contract
    let stackerdb_contract = build_stackerdb_contract(&signer_stacks_addresses);
    let contract_id =
        QualifiedContractIdentifier::new(signer_stacks_addresses[0].into(), "hello-world".into());

    // Setup the signer and coordinator configurations
    let signer_configs = build_signer_config_tomls(
        &signer_stacks_private_keys,
        num_keys,
        &conf.node.rpc_bind,
        &contract_id.to_string(),
        Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
    );

    // The test starts here
    let mut running_signers = vec![];
    // Spawn all the signers first to listen to the coordinator request for dkg
    let mut signer_cmd_senders = Vec::new();
    let mut signer_res_receivers = Vec::new();
    for i in (1..num_signers).rev() {
        let (cmd_send, cmd_recv) = channel();
        let (res_send, res_recv) = channel();
        info!("spawn signer");
        let running_signer = spawn_signer(&signer_configs[i as usize], cmd_recv, res_send);
        running_signers.push(running_signer);
        signer_cmd_senders.push(cmd_send);
        signer_res_receivers.push(res_recv);
    }
    // Spawn coordinator second
    let (coordinator_cmd_send, coordinator_cmd_recv) = channel();
    let (coordinator_res_send, coordinator_res_recv) = channel();
    info!("spawn coordinator");
    let running_coordinator = spawn_signer(
        &signer_configs[0],
        coordinator_cmd_recv,
        coordinator_res_send,
    );

    // Let's wrap the node in a lifetime to ensure stopping the signers doesn't cause issues.
    {
        // Setup the nodes and deploy the contract to it
        let _node = setup_stx_btc_node(
            &mut conf,
            num_signers,
            &signer_stacks_private_keys,
            &stackerdb_contract,
            &signer_configs,
        );

        let now = std::time::Instant::now();
        info!("signer_runloop: spawn send commands to do dkg and then sign");
        coordinator_cmd_send
            .send(RunLoopCommand::Dkg)
            .expect("failed to send DKG command");
        coordinator_cmd_send
            .send(RunLoopCommand::Sign {
                message: vec![1, 2, 3, 4, 5],
                is_taproot: false,
                merkle_root: None,
            })
            .expect("failed to send Sign command");
        coordinator_cmd_send
            .send(RunLoopCommand::Sign {
                message: vec![1, 2, 3, 4, 5],
                is_taproot: true,
                merkle_root: None,
            })
            .expect("failed to send Sign command");

        let mut aggregate_group_key = None;
        let mut frost_signature = None;
        let mut schnorr_proof = None;

        loop {
            let results = coordinator_res_recv.recv().expect("failed to recv results");
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
                }
            }
            if aggregate_group_key.is_some() && frost_signature.is_some() && schnorr_proof.is_some()
            {
                break;
            }
        }
        let elapsed = now.elapsed();
        info!("DKG and Sign Time Elapsed: {:.2?}", elapsed);
    }
    // Stop the signers
    for signer in running_signers {
        assert!(signer.stop().is_none());
    }
    // Stop the coordinator
    assert!(running_coordinator.stop().is_none());
}
