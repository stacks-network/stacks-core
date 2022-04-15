use std;
use std::thread;

use crate::burnchains::db_indexer::DBBurnchainIndexer;
use crate::neon;
use crate::stacks::burnchains::indexer::BurnchainIndexer;
use crate::tests::neon_integrations::{get_account, submit_tx};
use crate::tests::StacksL1Controller;
use crate::tests::{make_contract_publish, to_addr};
use clarity::util::hash::to_hex;
use rand::RngCore;
use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks::util::sleep_ms;
use stacks::vm::types::QualifiedContractIdentifier;
use std::env;
use std::time::Duration;

fn random_sortdb_test_dir() -> String {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    format!("/tmp/stacks-node-tests/sortdb/test-{}", to_hex(&buf))
}

lazy_static! {
    pub static ref MOCKNET_PRIVATE_KEY_1: StacksPrivateKey = StacksPrivateKey::from_hex(
        "aaf57b4730f713cf942bc63f0801c4a62abe5a6ac8e3da10389f9ca3420b0dc701"
    )
    .unwrap();
    pub static ref MOCKNET_PRIVATE_KEY_2: StacksPrivateKey = StacksPrivateKey::from_hex(
        "0916e2eb04b5702e0e946081829cee67d3bb76e1792af506646843db9252ff4101"
    )
    .unwrap();
}

/// This test brings up the Stacks-L1 chain in "mocknet" mode, and ensures that our listener can hear and record burn blocks
/// from the Stacks-L1 chain.
#[test]
fn l1_basic_listener_test() {
    if env::var("STACKS_NODE_TEST") != Ok("1".into()) {
        return;
    }

    // Start Stacks L1.
    let l1_toml_file = "../../contrib/conf/stacks-l1-mocknet.toml";
    let l1_rpc_origin = "http://127.0.0.1:20443";
    let nft_trait_name = "nft-trait-standard";
    let ft_trait_name = "ft-trait-standard";

    // Start the L2 run loop.
    let mut config = super::new_test_conf();
    config.node.mining_key = Some(MOCKNET_PRIVATE_KEY_2.clone());
    let miner_account = to_addr(&MOCKNET_PRIVATE_KEY_2);

    let db_path_dir = random_sortdb_test_dir();
    config.burnchain.indexer_base_db_path = db_path_dir;
    config.burnchain.first_burn_header_hash =
    // "a7578f11a428bb953e7bbced9858525b6eec0d24d5d9d77285a7d7d891f68561".to_string();
    "9946c68526249c259231f1660be4c72e915ebe1f25a8c8400095812b487eb279".to_string();
    config.burnchain.first_burn_header_height = 1;
    config.burnchain.chain = "stacks_layer_1".to_string();
    config.burnchain.mode = "hyperchain".to_string();
    config.burnchain.rpc_ssl = false;
    config.burnchain.rpc_port = 20443;
    config.burnchain.peer_host = "127.0.0.1".into();
    config.node.wait_time_for_microblocks = 10_000;
    config.node.rpc_bind = "127.0.0.1:30443".into();
    config.node.p2p_bind = "127.0.0.1:30444".into();
    let l2_rpc_origin = format!("http://{}", &config.node.rpc_bind);

    config.burnchain.contract_identifier = QualifiedContractIdentifier::new(
        to_addr(&MOCKNET_PRIVATE_KEY_1).into(),
        "hyperchain-controller".into(),
    );

    config.node.miner = true;

    let mut run_loop = neon::RunLoop::new(config.clone());
    let channel = run_loop.get_coordinator_channel().unwrap();
    thread::spawn(move || run_loop.start(None, 0));

    // Start Stacks L1.
    let l1_toml_file = "../../contrib/conf/stacks-l1-mocknet.toml";
    let mut stacks_l1_controller = StacksL1Controller::new(l1_toml_file.to_string(), true);
    let _stacks_res = stacks_l1_controller
        .start_process()
        .expect("stacks l1 controller didn't start");

    // Sleep to give the run loop time to listen to blocks.
    thread::sleep(Duration::from_millis(45000));

    let indexer = DBBurnchainIndexer::new(config.burnchain.clone(), false)
        .expect("Should be able to create DBBurnchainIndexer.");
    let tip_height = indexer
        .get_highest_header_height()
        .expect("Should have a highest block.");

    // Ensure that the tip height has moved beyond height 0.
    // We check that we have moved past 3 just to establish we are reliably getting blocks.
    assert!(tip_height > 3);

    channel.stop_chains_coordinator();
    stacks_l1_controller.kill_process();
}

#[test]
fn l1_integration_test() {
    // running locally:
    // STACKS_BASE_DIR=~/devel/stacks-blockchain/target/release/stacks-node STACKS_NODE_TEST=1 cargo test --workspace l1_integration_test
    if env::var("STACKS_NODE_TEST") != Ok("1".into()) {
        return;
    }

    // Start Stacks L1.
    let l1_toml_file = "../../contrib/conf/stacks-l1-mocknet.toml";
    let l1_rpc_origin = "http://127.0.0.1:20443";
    let nft_trait_name = "nft-trait-standard";
    let ft_trait_name = "ft-trait-standard";

    // Start the L2 run loop.
    let mut config = super::new_test_conf();
    config.node.mining_key = Some(MOCKNET_PRIVATE_KEY_2.clone());
    let miner_account = to_addr(&MOCKNET_PRIVATE_KEY_2);

    let db_path_dir = random_sortdb_test_dir();
    config.burnchain.indexer_base_db_path = db_path_dir;
    config.burnchain.first_burn_header_hash =
    // "a7578f11a428bb953e7bbced9858525b6eec0d24d5d9d77285a7d7d891f68561".to_string();
    "9946c68526249c259231f1660be4c72e915ebe1f25a8c8400095812b487eb279".to_string();
    config.burnchain.first_burn_header_height = 1;
    config.burnchain.chain = "stacks_layer_1".to_string();
    config.burnchain.mode = "hyperchain".to_string();
    config.burnchain.rpc_ssl = false;
    config.burnchain.rpc_port = 20443;
    config.burnchain.peer_host = "127.0.0.1".into();
    config.node.wait_time_for_microblocks = 10_000;
    config.node.rpc_bind = "127.0.0.1:30443".into();
    config.node.p2p_bind = "127.0.0.1:30444".into();
    let l2_rpc_origin = format!("http://{}", &config.node.rpc_bind);

    config.burnchain.contract_identifier = QualifiedContractIdentifier::new(
        to_addr(&MOCKNET_PRIVATE_KEY_1).into(),
        "hyperchain-controller".into(),
    );

    config.node.miner = true;

    let mut run_loop = neon::RunLoop::new(config.clone());
    let channel = run_loop.get_coordinator_channel().unwrap();
    thread::spawn(move || run_loop.start(None, 0));

    // Give the run loop time to start.
    thread::sleep(Duration::from_millis(2_000));

    // let account = get_account(&l2_rpc_origin, &miner_account);
    // assert_eq!(account.balance, 0);
    // assert!(
    //     account.nonce >= 2,
    //     "Miner should have produced at least 2 coinbase transactions"
    // );

    let mut stacks_l1_controller = StacksL1Controller::new(l1_toml_file.to_string(), true);
    let _stacks_res = stacks_l1_controller
        .start_process()
        .expect("stacks l1 controller didn't start");

    // Sleep to give the L1 chain time to start
    thread::sleep(Duration::from_millis(10_000));

    // Publish the NFT/FT traits
    let ft_trait_content =
        include_str!("../../../../core-contracts/contracts/helper/ft-trait-standard.clar");
    let ft_trait_publish = make_contract_publish(
        &MOCKNET_PRIVATE_KEY_1,
        0,
        1_000_000,
        &ft_trait_name,
        &ft_trait_content,
    );
    let nft_trait_content =
        include_str!("../../../../core-contracts/contracts/helper/nft-trait-standard.clar");
    let nft_trait_publish = make_contract_publish(
        &MOCKNET_PRIVATE_KEY_1,
        1,
        1_000_000,
        &nft_trait_name,
        &nft_trait_content,
    );

    // Publish the default hyperchains contract on the L1 chain
    let contract_content = include_str!("../../../../core-contracts/contracts/hyperchains.clar");
    let hc_contract_publish = make_contract_publish(
        &MOCKNET_PRIVATE_KEY_1,
        2,
        1_000_000,
        config.burnchain.contract_identifier.name.as_str(),
        &contract_content,
    );

    submit_tx(l1_rpc_origin, &ft_trait_publish);
    submit_tx(l1_rpc_origin, &nft_trait_publish);
    // Because the nonce ensures that the FT contract and NFT contract
    // are published before the HC contract, we can broadcast them
    // all at once, even though the HC contract depends on those
    // contracts.
    submit_tx(l1_rpc_origin, &hc_contract_publish);

    println!("Submitted FT, NFT, and Hyperchain contracts!");

    // Sleep to give the run loop time to listen to blocks,
    //  and start mining L2 blocks
    thread::sleep(Duration::from_secs(60));

    let indexer = DBBurnchainIndexer::new(config.burnchain.clone(), false)
        .expect("Should be able to create DBBurnchainIndexer.");
    let tip_height = indexer
        .get_highest_header_height()
        .expect("Should have a highest block.");

    // Ensure that the tip height has moved beyond height 0.
    // We check that we have moved past 3 just to establish we are reliably getting blocks.
    assert!(tip_height > 3);

    eprintln!("Miner account: {}", miner_account);

    // test the miner's nonce has incremented: this shows that L2 blocks have
    //  been mined (because the coinbase transactions bump the miner's nonce)
    let account = get_account(&l2_rpc_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert!(
        account.nonce >= 2,
        "Miner should have produced at least 2 coinbase transactions"
    );

    thread::sleep(Duration::from_secs(6));

    channel.stop_chains_coordinator();
    stacks_l1_controller.kill_process();
}
