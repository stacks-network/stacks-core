use stacks::util::hash::hex_bytes;

use stacks::net::PeerAddress;

use crate::{ neon, Config, Keychain, BitcoinRegtestController, BurnchainController };
use super::bitcoin_regtest::BitcoinCoreController;
use std::{thread, env};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, Duration};

const INITIAL_BLOCK_COUNT: u64 = 300;
const PHASE1_BLOCK_COUNT: u64 = 5;
const PHASE2_BLOCK_COUNT: u64 = 15;

fn master_miner_test_conf_master() -> Config {
    let mut conf = super::new_test_conf();

    conf.node.miner = true;
    conf.node.rpc_bind = "127.0.0.1:20543".into();
    conf.node.p2p_bind = "127.0.0.1:20544".into();
    conf.node.p2p_address = "127.0.0.1:20544".into();
    conf.node.data_url = "http://127.0.0.1:20543".into();
    conf.node.wait_time_for_microblocks = 0;
    conf.node.wait_time_for_stacks_block = 20_000;
    conf.node.run_tenure_with_missing_block = true;

    conf.connection_options.download_interval = 5;  // TODO(psq): is this too low?
    conf.connection_options.inv_sync_interval = 5;

    let keychain = Keychain::default(conf.node.seed.clone());

    conf.burnchain.mode = "neon".into(); 
    conf.burnchain.username = Some("neon-tester".into());
    conf.burnchain.password = Some("neon-tester-pass".into());
    conf.burnchain.peer_host = "127.0.0.1".into();
    conf.burnchain.local_mining_public_key = Some(keychain.generate_op_signer().get_public_key().to_hex());
    conf.burnchain.commit_anchor_block_within = 0;
    conf.burnchain.miner_exit_at_block_height = Some(INITIAL_BLOCK_COUNT + PHASE1_BLOCK_COUNT + PHASE2_BLOCK_COUNT);

    conf.connection_options.public_ip_address = Some((PeerAddress::from_ipv4(127, 0, 0, 1), 20544));

    println!("\nmaster node configuration {:?}", conf.node);
    println!("\nmaster connection_options configuration {:?}", conf.connection_options);
    conf
}

fn master_miner_test_conf_miner() -> Config {
    let mut conf = super::new_test_conf();

    conf.node.miner = true;
    conf.node.rpc_bind = "127.0.0.1:20743".into();
    conf.node.p2p_bind = "127.0.0.1:20744".into();
    conf.node.p2p_address = "127.0.0.1:20744".into();
    conf.node.data_url = "http://127.0.0.1:20743".into();
    conf.node.set_bootstrap_node(Some("047464c40a958bed5db5053fb79c331b8b430acd495dffe09ba43373bc9303604b84f26a305e1d9260de96f3b63e51d2d2213ae782be38992b3084cf01ad76a242@127.0.0.1:20544".to_string()));
    conf.node.seed = hex_bytes("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    conf.node.wait_time_for_microblocks = 0;
    conf.node.wait_time_for_stacks_block = 20_000;
    conf.node.run_tenure_with_missing_block = true;

    // conf.connection_options.max_inflight_blocks = 1; // TODO(psq): slow down as much as possible???
    // conf.connection_options.download_interval = 30;  // TODO(psq): 30 seconds is the default, but does this have any effect?
    // conf.connection_options.inv_sync_interval = 45;  // TODO(psq): would that help maybe delaying starting the block download, default is 45 seconds

    conf.connection_options.download_interval = 5;  // TODO(psq): is this too low?
    conf.connection_options.inv_sync_interval = 5;

    let keychain = Keychain::default(conf.node.seed.clone());

    conf.burnchain.mode = "neon".into();
    conf.burnchain.username = Some("neon-tester".into());
    conf.burnchain.password = Some("neon-tester-pass".into());
    conf.burnchain.peer_host = "127.0.0.1".into();
    conf.burnchain.local_mining_public_key = Some(keychain.generate_op_signer().get_public_key().to_hex());
    conf.burnchain.commit_anchor_block_within = 0;
    conf.burnchain.miner_exit_at_block_height = Some(INITIAL_BLOCK_COUNT + PHASE1_BLOCK_COUNT + PHASE2_BLOCK_COUNT);

    conf.connection_options.public_ip_address = Some((PeerAddress::from_ipv4(127, 0, 0, 1), 20744));

    println!("\nminer node configuration {:?}", conf.node);
    println!("\nminer connection_options configuration {:?}", conf.connection_options);

    conf
}


const PANIC_TIMEOUT_SECS: u64 = 600;
fn next_block_and_wait(btc_controller: &mut BitcoinRegtestController, blocks_processed: &Arc<AtomicU64>) {
    let current = blocks_processed.load(Ordering::SeqCst);
    println!("Issuing block, waiting for bump [{:?}] {:?}", thread::current().id(), current);
    btc_controller.build_next_block(1);
    println!("Issued block [{:?}]", thread::current().id());
    let start = Instant::now();
    while blocks_processed.load(Ordering::SeqCst) <= current {
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for block to process");
        }
        thread::sleep(Duration::from_millis(100));
    }
    println!("Got block [{:?}] {:?}", thread::current().id(), current);
}

fn next_block_and_sleep(btc_controller: &mut BitcoinRegtestController, sleep_duration: u64) {
    println!("Issuing block, sleeping [{:?}] {:?}", thread::current().id(), sleep_duration);
    btc_controller.build_next_block(1);
    println!("Issued block [{:?}]", thread::current().id());
    thread::sleep(Duration::from_millis(sleep_duration));
}

fn wait_for_runloop(blocks_processed: &Arc<AtomicU64>) {
    let start = Instant::now();
    while blocks_processed.load(Ordering::SeqCst) == 0 {
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            panic!("Timed out waiting for run loop to start");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore]
fn master_miner_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return
    }

    let conf_master = master_miner_test_conf_master();
    let conf_miner = master_miner_test_conf_miner();

    let mut btcd_controller = BitcoinCoreController::new(conf_master.clone());
    btcd_controller.start_bitcoind().map_err(|_e| ()).expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf_master.clone(), None);

    btc_regtest_controller.bootstrap_chain(201);
    if let Some(follower_pub_key) = &conf_miner.burnchain.local_mining_public_key {
        btc_regtest_controller.generate_to_address(follower_pub_key, 100);
    }

    eprintln!("Chain bootstrapped...");

    let mut run_loop_master = neon::RunLoop::new(conf_master);
    let blocks_processed_master = run_loop_master.get_blocks_processed_arc();
    let channel_master = run_loop_master.get_coordinator_channel().unwrap();
    let master_thread = thread::spawn(move || {
        run_loop_master.start(0)
    });

    // give the master run loop some time to start up!
    wait_for_runloop(&blocks_processed_master);

    // TODO(psq): need to consider much higher value to force block download to take more than 1 burn block
    // to verify miner will not start too early, or throttle block download (in flight value?  other configuration value?)
    let mut block_count = PHASE1_BLOCK_COUNT;
    while block_count > 0 {
        println!("block_count-1 [{:?}], {:?}", thread::current().id(), block_count);
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed_master);
        block_count -= 1;
    }

    println!("====> start second miner [{:?}]", thread::current().id());
    // start the miner, with some catching up to do
    let mut run_loop_miner = neon::RunLoop::new(conf_miner);
    let channel_miner = run_loop_miner.get_coordinator_channel().unwrap();
    let miner_thread = thread::spawn(move || {
        run_loop_miner.start(0)
    });

    // mine another 50 blocks
    let mut block_count = PHASE2_BLOCK_COUNT;
    while block_count > 0 {
        println!("block_count-2 [{:?}] {:?}", thread::current().id(), block_count);
        next_block_and_sleep(&mut btc_regtest_controller, 30_000);
        block_count -= 1;
    }

    println!("done generating blocks, stopping");
    master_thread.join().expect("failure during master thread run");
    miner_thread.join().expect("failure during miner thread run");

    // TODO(psq): test that both miners got all blocks
    // TODO(psq): test that everything was mined to a single branch
    // TODO(psq): test that both miners mined some blocks (yes, this could lead to spurious failures in about .1% of the cases)

    channel_master.stop_chains_coordinator();
    channel_miner.stop_chains_coordinator();
}



