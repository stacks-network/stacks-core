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
            neon_integration_test_conf, next_block_and_wait, submit_tx, test_observer,
            wait_for_runloop,
        },
        to_addr,
    },
    BitcoinRegtestController, BurnchainController,
};
use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{RunningSigner, Signer, StackerDBEventReceiver};
use p256k1::{ecdsa, point::Point, scalar::Scalar};
use rand_core::OsRng;
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks_signer::runloop::RunLoopCommand;

const SLOTS_PER_USER: u32 = 16;

// Helper struct for holding the btc and stx neon nodes
#[allow(dead_code)]
struct RunningNodes {
    pub btc_regtest_controller: BitcoinRegtestController,
    pub btcd_controller: BitcoinCoreController,
    pub join_handle: thread::JoinHandle<()>,
    pub conf: NeonConfig,
}

fn build_contract(num_signers: u32, signer_stacks_private_keys: &[StacksPrivateKey]) -> String {
    let mut stackerdb_contract = String::new(); // "
    stackerdb_contract += "        ;; stacker DB\n";
    stackerdb_contract += "        (define-read-only (stackerdb-get-signer-slots)\n";
    stackerdb_contract += "            (ok (list\n";
    for i in 0..num_signers {
        stackerdb_contract += "                {\n";
        stackerdb_contract += format!(
            "                    signer: '{},\n",
            to_addr(&signer_stacks_private_keys[i as usize])
        )
        .as_str();
        stackerdb_contract +=
            format!("                    num-slots: u{}\n", SLOTS_PER_USER).as_str();
        stackerdb_contract += "                }\n";
    }
    stackerdb_contract += "                )))\n";
    stackerdb_contract += "\n";
    stackerdb_contract += "        (define-read-only (stackerdb-get-config)\n";
    stackerdb_contract += "            (ok {\n";
    stackerdb_contract += "                chunk-size: u4096,\n";
    stackerdb_contract += "                write-freq: u0,\n";
    stackerdb_contract += "                max-writes: u4096,\n";
    stackerdb_contract += "                max-neighbors: u32,\n";
    stackerdb_contract += "                hint-replicas: (list )\n";
    stackerdb_contract += "            }))\n";
    stackerdb_contract += "    ";

    info!("stackerdb_contract:\n{}\n", &stackerdb_contract);
    stackerdb_contract
}

fn build_signer_config_tomls(
    num_signers: u32,
    signer_stacks_private_keys: &[StacksPrivateKey],
    node_host: &str,
    contract_id: String,
) -> Vec<String> {
    let mut rng = OsRng::default();
    let num_keys: u32 = 20;
    let keys_per_signer = num_keys / num_signers;
    let mut key_id: u32 = 1;
    let mut key_ids = Vec::new();
    for _ in 0..num_signers {
        let mut ids = Vec::new();
        for _ in 0..keys_per_signer {
            ids.push(format!("{key_id}"));
            key_id += 1;
        }
        key_ids.push(ids.join(", "));
    }
    let signer_ecdsa_private_keys = (0..num_signers)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<Scalar>>();

    let mut signer_config_tomls = vec![];
    let mut signers_array = String::new();
    signers_array += "signers = [";
    for (i, private_key) in signer_ecdsa_private_keys.iter().enumerate() {
        let ecdsa_public_key = ecdsa::PublicKey::new(private_key).unwrap().to_string();
        let ids = key_ids[i].clone();
        signers_array += &format!(
            r#"
            {{public_key = "{ecdsa_public_key}", key_ids = [{ids}]}}
        "#
        );
        if i != signer_ecdsa_private_keys.len() - 1 {
            signers_array += ",";
        }
    }
    signers_array += "]";
    let mut port = 30000;
    for (i, stacks_private_key) in signer_stacks_private_keys.iter().enumerate() {
        let endpoint = format!("localhost:{}", port);
        port += 1;
        let id = i;
        let message_private_key = signer_ecdsa_private_keys[i].to_string();
        let stacks_private_key = stacks_private_key.to_hex();
        let signer_config_toml = format!(
            r#"
message_private_key = "{message_private_key}"
stacks_private_key = "{stacks_private_key}"
node_host = "{node_host}"
endpoint = "{endpoint}"
network = "testnet"
stackerdb_contract_id = "{contract_id}"
signer_id = {id}
{signers_array}
"#
        );
        signer_config_tomls.push(signer_config_toml);
    }
    signer_config_tomls
}

fn spawn_running_signer(
    data: &str,
    command: RunLoopCommand,
) -> RunningSigner<StackerDBEventReceiver, Vec<Point>> {
    let config = stacks_signer::config::Config::load_from_str(data).unwrap();
    let ev = StackerDBEventReceiver::new(vec![config.stackerdb_contract_id.clone()]);
    let runloop: stacks_signer::runloop::RunLoop<stacks_signer::crypto::frost::Coordinator> =
        stacks_signer::runloop::RunLoop::new(&config, command);
    let mut signer: Signer<
        Vec<Point>,
        stacks_signer::runloop::RunLoop<stacks_signer::crypto::frost::Coordinator>,
        StackerDBEventReceiver,
    > = Signer::new(runloop, ev);
    let endpoint = config.endpoint;
    info!(
        "Spawning signer {} on endpoint {}",
        config.signer_id, endpoint
    );
    signer.spawn(endpoint).unwrap()
}

fn setup_stx_btc_node(
    num_signers: u32,
    signer_stacks_private_keys: &[StacksPrivateKey],
    stackerdb_contract: &str,
) -> RunningNodes {
    let (mut conf, _) = neon_integration_test_conf();
    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::StackerDBChunks],
    });

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

    test_observer::spawn();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let join_handle = thread::spawn(move || run_loop.start(None, 0));

    // Give the run loop some time to start up!
    eprintln!("Wait for runloop...");
    wait_for_runloop(&blocks_processed);

    // First block wakes up the run loop.
    eprintln!("Mine first block...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // Second block will hold our VRF registration.
    eprintln!("Mine second block...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // Third block will be the first mined Stacks block.
    eprintln!("Mine third block...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    eprintln!("Send contract-publish...");
    let tx = make_contract_publish(
        &signer_stacks_private_keys[0],
        0,
        10_000,
        "hello-world",
        stackerdb_contract,
    );
    submit_tx(&http_origin, &tx);

    // mine it
    eprintln!("Mine it...");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    RunningNodes {
        btcd_controller,
        btc_regtest_controller,
        join_handle,
        conf,
    }
}

#[test]
fn test_stackerdb_dkg() {
    let num_signers: u32 = 5;
    let signer_stacks_private_keys = (0..num_signers)
        .map(|_| StacksPrivateKey::new())
        .collect::<Vec<StacksPrivateKey>>();

    // Setup the neon node
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    // Build the stackerdb contract
    let stackerdb_contract = build_contract(num_signers, &signer_stacks_private_keys);
    // Setup the nodes and deploy the contract to it
    let node = setup_stx_btc_node(
        num_signers,
        &signer_stacks_private_keys,
        &stackerdb_contract,
    );

    // Setup the signer and coordinator configurations
    let contract_id = node.conf.node.stacker_dbs[0].clone();
    let signer_configs = build_signer_config_tomls(
        num_signers,
        &signer_stacks_private_keys,
        &node.conf.node.rpc_bind,
        contract_id.to_string(),
    );

    // The test starts here
    let mut running_signers = vec![];
    // Spawn all the signers first to listen to the coordinator request for dkg
    for i in 1..num_signers {
        let running_signer = spawn_running_signer(&signer_configs[i as usize], RunLoopCommand::Run);
        //sleep(Duration::from_secs(1));
        running_signers.push(running_signer);
    }
    // Spawn coordinator second
    let running_coordinator = spawn_running_signer(&signer_configs[0], RunLoopCommand::Dkg);

    sleep(Duration::from_secs(60));
    let result = running_coordinator.stop().unwrap();
    assert_eq!(result.len(), 1);
    assert_ne!(result[0], Point::default());
}
