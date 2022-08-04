use std;
use std::thread;

use crate::burnchains::commitment::MultiMinerParticipant;
use crate::config::CommitStrategy;
use crate::tests::l1_observer_test::wait_for_target_l1_block;
use crate::tests::make_contract_publish;
use crate::tests::neon_integrations::get_account;
use crate::Config;

use crate::neon;
use crate::tests::l1_observer_test::{
    publish_hc_contracts_to_l1, wait_for_next_stacks_block, StacksL1Controller,
    MOCKNET_PRIVATE_KEY_1, MOCKNET_PRIVATE_KEY_2, MOCKNET_PRIVATE_KEY_3,
};
use crate::tests::neon_integrations::submit_tx;
use crate::tests::to_addr;
use stacks::core::LAYER_1_CHAIN_ID_TESTNET;

use stacks::burnchains::Burnchain;

use stacks::vm::types::PrincipalData;
use stacks::vm::types::QualifiedContractIdentifier;
use stacks::vm::types::StandardPrincipalData;
use std::env;
use std::sync::atomic::Ordering;

use std::time::Duration;

/// This is the height to wait for the L1 mocknet node to reach the 2.1 epoch
pub const MOCKNET_EPOCH_2_1: u64 = 4;

/// Uses MOCKNET_PRIVATE_KEY_1 to publish the hyperchains contract and supporting
///  trait contracts
pub fn publish_multiparty_contract_to_l1(
    mut l1_nonce: u64,
    config: &Config,
    miners: &[PrincipalData],
) -> u64 {
    let (required_signers, contract) = match &config.burnchain.commit_strategy {
        CommitStrategy::MultiMiner {
            required_signers,
            contract,
            ..
        } => (*required_signers, contract.clone()),
        _ => panic!("Expected to be configured to use multi-party mining contract"),
    };

    let miners_str: Vec<_> = miners.iter().map(|x| format!("'{}", x)).collect();
    let miners_list_str = format!("(list {})", miners_str.join(" "));

    // Publish the multi-miner control contract on the L1 chain
    let contract_content = include_str!("../../../../core-contracts/contracts/multi-miner.clar")
        .replace(
            "(define-constant signers-required u2)",
            &format!("(define-constant signers-required u{})", required_signers),
        )
        .replace(
            "(define-data-var miners (optional (list 10 principal)) none)",
            &format!(
                "(define-data-var miners (optional (list 10 principal)) (some {}))",
                miners_list_str
            ),
        );
    let l1_rpc_origin = config.burnchain.get_rpc_url();

    assert_eq!(
        &StandardPrincipalData::from(to_addr(&MOCKNET_PRIVATE_KEY_1)),
        &contract.issuer,
        "Incorrectly configured mining contract: issuer should be MOCKNET_PRIVATE_KEY_1"
    );

    let miner_publish = make_contract_publish(
        &MOCKNET_PRIVATE_KEY_1,
        LAYER_1_CHAIN_ID_TESTNET,
        l1_nonce,
        1_000_000,
        &contract.name.to_string(),
        &contract_content,
    );
    l1_nonce += 1;

    submit_tx(&l1_rpc_origin, &miner_publish);

    println!("Submitted multi-party contract!");

    l1_nonce
}

#[test]
fn l1_multiparty_1_of_n_integration_test() {
    // running locally:
    // STACKS_BASE_DIR=~/devel/stacks-blockchain/target/release/stacks-node STACKS_NODE_TEST=1 cargo test --workspace l1_integration_test
    if env::var("STACKS_NODE_TEST") != Ok("1".into()) {
        return;
    }

    // Start Stacks L1.
    let l1_toml_file = "../../contrib/conf/stacks-l1-mocknet.toml";

    // Start the L2 run loop.
    let mut config = super::new_l1_test_conf(&*MOCKNET_PRIVATE_KEY_2, &*MOCKNET_PRIVATE_KEY_1);
    let miner_account = to_addr(&MOCKNET_PRIVATE_KEY_2);
    let l2_rpc_origin = format!("http://{}", &config.node.rpc_bind);

    let multi_party_contract = QualifiedContractIdentifier::new(
        to_addr(&MOCKNET_PRIVATE_KEY_1).into(),
        "hc-multiparty-miner".into(),
    );

    config.burnchain.commit_strategy = CommitStrategy::MultiMiner {
        required_signers: 1,
        contract: multi_party_contract.clone(),
        other_participants: vec![],
        leader: true,
    };

    let mut run_loop = neon::RunLoop::new(config.clone());
    let termination_switch = run_loop.get_termination_switch();
    let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));

    // Give the run loop time to start.
    thread::sleep(Duration::from_millis(2_000));

    let burnchain = Burnchain::new(&config.get_burn_db_path(), &config.burnchain.chain).unwrap();
    let (sortition_db, burndb) = burnchain.open_db(true).unwrap();

    let mut stacks_l1_controller = StacksL1Controller::new(l1_toml_file.to_string(), true);
    let _stacks_res = stacks_l1_controller
        .start_process()
        .expect("stacks l1 controller didn't start");

    // Sleep to give the L1 chain time to start
    thread::sleep(Duration::from_millis(10_000));

    wait_for_target_l1_block(&sortition_db, MOCKNET_EPOCH_2_1);

    let l1_nonce = publish_hc_contracts_to_l1(0, &config, multi_party_contract.clone().into());
    publish_multiparty_contract_to_l1(l1_nonce, &config, &[miner_account.clone().into()]);

    // Wait for exactly two stacks blocks.
    wait_for_next_stacks_block(&sortition_db);
    wait_for_next_stacks_block(&sortition_db);

    // The burnchain should have registered what the listener recorded.
    let tip = burndb
        .get_canonical_chain_tip()
        .expect("couldn't get chain tip");
    info!("burnblock chain tip is {:?}", &tip);

    // Ensure that the tip height has moved beyond height 0.
    // We check that we have moved past 3 just to establish we are reliably getting blocks.
    assert!(tip.block_height > 3);

    eprintln!("Miner account: {}", miner_account);

    // test the miner's nonce has incremented: this shows that L2 blocks have
    //  been mined (because the coinbase transactions bump the miner's nonce)
    let account = get_account(&l2_rpc_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert!(
        account.nonce >= 2,
        "Miner should have produced at least 2 coinbase transactions"
    );

    termination_switch.store(false, Ordering::SeqCst);
    stacks_l1_controller.kill_process();
    run_loop_thread.join().expect("Failed to join run loop.");
}

#[test]
// Test that a 2-of-2 multiparty mining setup can make
//  simple progress.
fn l1_multiparty_2_of_2_integration_test() {
    // running locally:
    // STACKS_BASE_DIR=~/devel/stacks-blockchain/target/release/stacks-node STACKS_NODE_TEST=1 cargo test --workspace l1_integration_test
    if env::var("STACKS_NODE_TEST") != Ok("1".into()) {
        return;
    }

    // Start Stacks L1.
    let l1_toml_file = "../../contrib/conf/stacks-l1-mocknet-double.toml";

    // Start the L2 run loop.
    let mut leader_config =
        super::new_l1_test_conf(&*MOCKNET_PRIVATE_KEY_2, &*MOCKNET_PRIVATE_KEY_1);
    let miner_account = to_addr(&MOCKNET_PRIVATE_KEY_2);
    let l2_rpc_origin = format!("http://{}", &leader_config.node.rpc_bind);

    let multi_party_contract = QualifiedContractIdentifier::new(
        to_addr(&MOCKNET_PRIVATE_KEY_1).into(),
        "hc-multiparty-miner".into(),
    );

    let mut follower_config =
        super::new_l1_test_conf(&*MOCKNET_PRIVATE_KEY_3, &*MOCKNET_PRIVATE_KEY_1);
    follower_config.node.chain_id = leader_config.node.chain_id;

    let follower_account = to_addr(&MOCKNET_PRIVATE_KEY_3);
    follower_config.connection_options.hyperchain_validator =
        follower_config.node.mining_key.clone();
    follower_config.node.rpc_bind = "127.0.0.1:30643".into();
    follower_config.node.data_url = "http://127.0.0.1:30643".into();
    follower_config.node.p2p_bind = "127.0.0.1:30644".into();
    follower_config.burnchain.observer_port = 52303;
    follower_config.events_observers = vec![];
    follower_config.node.miner = false;
    follower_config.node.local_peer_seed = vec![20; 32];

    follower_config.burnchain.commit_strategy = CommitStrategy::MultiMiner {
        required_signers: 2,
        contract: multi_party_contract.clone(),
        other_participants: vec![MultiMinerParticipant {
            rpc_server: l2_rpc_origin.clone(),
            public_key: [0; 33],
        }],
        leader: false,
    };

    follower_config
        .connection_options
        .hyperchain_signing_contract = Some(multi_party_contract.clone());

    follower_config.add_bootstrap_node(
        "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766@127.0.0.1:30444",
    );

    let follower_rpc_origin = format!("http://{}", &follower_config.node.rpc_bind);

    leader_config.burnchain.commit_strategy = CommitStrategy::MultiMiner {
        required_signers: 2,
        contract: multi_party_contract.clone(),
        other_participants: vec![MultiMinerParticipant {
            rpc_server: follower_rpc_origin.clone(),
            public_key: [0; 33],
        }],
        leader: true,
    };

    let mut leader_run_loop = neon::RunLoop::new(leader_config.clone());
    let leader_termination_switch = leader_run_loop.get_termination_switch();
    let leader_run_loop_thread = thread::spawn(move || leader_run_loop.start(None, 0));

    let mut follower_run_loop = neon::RunLoop::new(follower_config.clone());
    let follower_termination_switch = follower_run_loop.get_termination_switch();
    let follower_run_loop_thread = thread::spawn(move || follower_run_loop.start(None, 0));

    // Give the run loop time to start.
    thread::sleep(Duration::from_millis(2_000));

    let burnchain = Burnchain::new(
        &leader_config.get_burn_db_path(),
        &leader_config.burnchain.chain,
    )
    .unwrap();
    let (sortition_db, burndb) = burnchain.open_db(true).unwrap();

    let mut stacks_l1_controller = StacksL1Controller::new(l1_toml_file.to_string(), false);
    let _stacks_res = stacks_l1_controller
        .start_process()
        .expect("stacks l1 controller didn't start");

    // Sleep to give the L1 chain time to start
    thread::sleep(Duration::from_millis(10_000));
    wait_for_target_l1_block(&sortition_db, MOCKNET_EPOCH_2_1);

    let l1_nonce =
        publish_hc_contracts_to_l1(0, &leader_config, multi_party_contract.clone().into());
    publish_multiparty_contract_to_l1(
        l1_nonce,
        &leader_config,
        &[
            miner_account.clone().into(),
            follower_account.clone().into(),
        ],
    );

    // Wait for exactly two stacks blocks.
    wait_for_next_stacks_block(&sortition_db);
    wait_for_next_stacks_block(&sortition_db);

    // The burnchain should have registered what the listener recorded.
    let tip = burndb
        .get_canonical_chain_tip()
        .expect("couldn't get chain tip");
    info!("burnblock chain tip is {:?}", &tip);

    // Ensure that the tip height has moved beyond height 0.
    // We check that we have moved past 3 just to establish we are reliably getting blocks.
    assert!(tip.block_height > 3);

    eprintln!("Miner account: {}", miner_account);

    // test the miner's nonce has incremented: this shows that L2 blocks have
    //  been mined (because the coinbase transactions bump the miner's nonce)
    let account = get_account(&l2_rpc_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert!(
        account.nonce >= 2,
        "Miner should have produced at least 2 coinbase transactions"
    );

    leader_termination_switch.store(false, Ordering::SeqCst);
    follower_termination_switch.store(false, Ordering::SeqCst);
    stacks_l1_controller.kill_process();
    leader_run_loop_thread
        .join()
        .expect("Failed to join run loop.");
    follower_run_loop_thread
        .join()
        .expect("Failed to join run loop.");
}
