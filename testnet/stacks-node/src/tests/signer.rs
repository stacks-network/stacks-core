use std::sync::mpsc::{channel, Receiver};
use std::thread::sleep;
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
use p256k1::point::Point;
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks_common::types::chainstate::StacksAddress;
use stacks_signer::runloop::RunLoopCommand;
use stacks_signer::utils::{build_signer_config_tomls, build_stackerdb_contract};

// Helper struct for holding the btc and stx neon nodes
#[allow(dead_code)]
struct RunningNodes {
    pub btc_regtest_controller: BitcoinRegtestController,
    pub btcd_controller: BitcoinCoreController,
    pub join_handle: thread::JoinHandle<()>,
    pub conf: NeonConfig,
}

fn spawn_running_signer(
    data: &str,
    command: RunLoopCommand,
    receiver: Receiver<RunLoopCommand>,
) -> RunningSigner<StackerDBEventReceiver, Vec<Point>> {
    let config = stacks_signer::config::Config::load_from_str(data).unwrap();
    let ev = StackerDBEventReceiver::new(vec![config.stackerdb_contract_id.clone()]);
    let runloop: stacks_signer::runloop::RunLoop<stacks_signer::crypto::frost::Coordinator> =
        stacks_signer::runloop::RunLoop::new(&config, command);
    let mut signer: Signer<
        RunLoopCommand,
        Vec<Point>,
        stacks_signer::runloop::RunLoop<stacks_signer::crypto::frost::Coordinator>,
        StackerDBEventReceiver,
    > = Signer::new(runloop, ev, receiver);
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
        let signer_config = stacks_signer::config::Config::load_from_str(toml).unwrap();

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
    for i in (1..num_signers).rev() {
        let (cmd_send, cmd_recv) = channel();
        info!("spawn signer");
        let running_signer =
            spawn_running_signer(&signer_configs[i as usize], RunLoopCommand::Run, cmd_recv);
        //sleep(Duration::from_secs(1));
        running_signers.push(running_signer);
        signer_cmd_senders.push(cmd_send);
    }
    // Spawn coordinator second
    let (coordinator_cmd_send, coordinator_cmd_recv) = channel();
    //let running_coordinator = spawn_running_signer(&signer_configs[0],
    info!("spawn coordinator");
    let running_coordinator = spawn_running_signer(
        &signer_configs[0],
        RunLoopCommand::Wait,
        coordinator_cmd_recv,
    );

    info!("setup node, sleep first to make sure signers are running");
    sleep(Duration::from_secs(10));

    // Setup the nodes and deploy the contract to it
    let _node = setup_stx_btc_node(
        &mut conf,
        num_signers,
        &signer_stacks_private_keys,
        &stackerdb_contract,
        &signer_configs,
    );

    sleep(Duration::from_secs(5));

    info!("signer_runloop: spawn send dkg-sign command");
    coordinator_cmd_send
        .send(RunLoopCommand::DkgSign {
            message: vec![1, 2, 3, 4, 5],
        })
        .expect("failed to send command");

    sleep(Duration::from_secs(60));

    let result = running_coordinator.stop().unwrap();
    assert_eq!(result.len(), 1);
    assert_ne!(result[0], Point::default());
}
