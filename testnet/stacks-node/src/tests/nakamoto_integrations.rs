use clarity::vm::types::PrincipalData;
use stacks::burnchains::MagicBytes;
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::core::{
    StacksEpoch, StacksEpochId, BLOCK_LIMIT_MAINNET_10, HELIUM_BLOCK_LIMIT_20,
    PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2, PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4,
    PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0,
};
use stacks_common::address::AddressHashMode;
use stacks_common::consts::STACKS_EPOCH_MAX;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{env, thread};

use super::bitcoin_regtest::BitcoinCoreController;
use crate::mockamoto::signer::SelfSigner;
use crate::run_loop::nakamoto;
use crate::tests::neon_integrations::{
    next_block_and_wait, run_until_burnchain_height, submit_tx, wait_for_runloop,
};
use crate::{
    neon, tests, BitcoinRegtestController, BurnchainController, Config, ConfigFile, Keychain,
};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref NAKAMOTO_INTEGRATION_EPOCHS: [StacksEpoch; 9] = [
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: BLOCK_LIMIT_MAINNET_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 1,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 1,
            end_height: 2,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 2,
            end_height: 3,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_1
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: 3,
            end_height: 4,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_2
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: 4,
            end_height: 5,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_3
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: 5,
            end_height: 6,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_4
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: 6,
            end_height: 220,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_5
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: 220,
            end_height: STACKS_EPOCH_MAX,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_0
        },
    ];
}

/// Return a working nakamoto-neon config and the miner's bitcoin address to fund
pub fn naka_neon_integration_conf(seed: Option<&[u8]>) -> (Config, StacksAddress) {
    let mut conf = super::new_test_conf();
    conf.burnchain.mode = "nakamoto-neon".into();

    // tests can override this, but these tests run with epoch 2.05 by default
    conf.burnchain.epochs = Some(NAKAMOTO_INTEGRATION_EPOCHS.to_vec());

    if let Some(seed) = seed {
        conf.node.seed = seed.to_vec();
    }

    // instantiate the keychain so we can fund the bitcoin op signer
    let keychain = Keychain::default(conf.node.seed.clone());

    let mining_key = Secp256k1PrivateKey::from_seed(&[1]);
    conf.miner.mining_key = Some(mining_key);
    conf.miner.self_signing_key = Some(SelfSigner::single_signer());

    conf.node.miner = true;
    conf.node.wait_time_for_microblocks = 500;
    conf.burnchain.burn_fee_cap = 20000;

    conf.burnchain.username = Some("neon-tester".into());
    conf.burnchain.password = Some("neon-tester-pass".into());
    conf.burnchain.peer_host = "127.0.0.1".into();
    conf.burnchain.local_mining_public_key =
        Some(keychain.generate_op_signer().get_public_key().to_hex());
    conf.burnchain.commit_anchor_block_within = 0;

    // test to make sure config file parsing is correct
    let mut cfile = ConfigFile::xenon();
    cfile.node.as_mut().map(|node| node.bootstrap_node.take());

    if let Some(burnchain) = cfile.burnchain.as_mut() {
        burnchain.peer_host = Some("127.0.0.1".to_string());
    }

    conf.burnchain.magic_bytes = MagicBytes::from(['T' as u8, '3' as u8].as_ref());
    conf.burnchain.poll_time_secs = 1;
    conf.node.pox_sync_sample_secs = 0;

    conf.miner.min_tx_fee = 1;
    conf.miner.first_attempt_time_ms = i64::max_value() as u64;
    conf.miner.subsequent_attempt_time_ms = i64::max_value() as u64;

    // if there's just one node, then this must be true for tests to pass
    conf.miner.wait_for_block_download = false;

    conf.node.mine_microblocks = false;
    conf.miner.microblock_attempt_time_ms = 10;
    conf.node.microblock_frequency = 0;
    conf.node.wait_time_for_blocks = 200;

    let miner_account = keychain.origin_address(conf.is_mainnet()).unwrap();

    conf.burnchain.pox_prepare_length = Some(5);
    conf.burnchain.pox_reward_length = Some(20);

    (conf, miner_account)
}

pub fn next_block_and<F>(
    btc_controller: &mut BitcoinRegtestController,
    timeout_secs: u64,
    mut check: F,
) -> Result<(), String>
where
    F: FnMut() -> Result<bool, String>,
{
    eprintln!("Issuing bitcoin block");
    btc_controller.build_next_block(1);
    let start = Instant::now();
    while !check()? {
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            error!("Timed out waiting for block to process, trying to continue test");
            return Err("Timed out".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

#[test]
#[ignore]
fn simple_neon_integration() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    let stacker_sk = Secp256k1PrivateKey::new();
    let stacker_address = tests::to_addr(&stacker_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(stacker_address.clone()).to_string(),
        100_000_000_000_000,
    );

    let epoch_2_conf = naka_conf.clone();

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    btc_regtest_controller.bootstrap_chain(201);

    info!("Chain bootstrapped to bitcoin block 201, starting a epoch-2x miner");

    let mut run_loop = neon::RunLoop::new(epoch_2_conf.clone());

    let epoch_2_stopper = run_loop.get_termination_switch();
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let epoch_2_thread = thread::spawn(move || run_loop.start(None, 0));
    wait_for_runloop(&blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // first mined stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    // stack enough to activate pox-4
    let pox_addr_tuple = clarity::vm::tests::execute(&format!(
        "{{ hashbytes: 0x{}, version: 0x{:02x} }}",
        to_hex(&[0; 20]),
        AddressHashMode::SerializeP2PKH as u8,
    ));

    let stacking_tx = tests::make_contract_call(
        &stacker_sk,
        0,
        1000,
        &StacksAddress::burn_address(false),
        "pox-4",
        "stack-stx",
        &[
            clarity::vm::Value::UInt(99_000_000_000_000),
            pox_addr_tuple,
            clarity::vm::Value::UInt(205),
            clarity::vm::Value::UInt(12),
        ],
    );

    submit_tx(&http_origin, &stacking_tx);

    run_until_burnchain_height(
        &mut btc_regtest_controller,
        &blocks_processed,
        219,
        &epoch_2_conf,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");
    epoch_2_stopper.store(false, Ordering::SeqCst);

    epoch_2_thread.join().unwrap();

    let mut run_loop = nakamoto::RunLoop::new(naka_conf.clone());
    let epoch_3_stopper = run_loop.get_termination_switch();
    let blocks_processed = run_loop.get_blocks_processed_arc();
    let vrfs_submitted = run_loop.submitted_vrfs();
    let commits_submitted = run_loop.submitted_commits();
    let blocks_mined = run_loop.submitted_commits();
    let coord_channel = run_loop.get_coordinator_channel().unwrap();

    let epoch_3_thread = thread::spawn(move || run_loop.start(None, 0));

    wait_for_runloop(&blocks_processed);
    info!("Nakamoto miner started...");
    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    let blocks_processed_before_mining = coord_channel.get_stacks_blocks_processed();

    // this block should perform the sortition, wait until a block is mined
    next_block_and(&mut btc_regtest_controller, 60, || {
        let mined_count = blocks_mined.load(Ordering::SeqCst);
        Ok(mined_count >= 1)
    })
    .unwrap();

    // wait until the coordinator has processed the new block(s)
    while coord_channel.get_stacks_blocks_processed() <= blocks_processed_before_mining {
        thread::sleep(Duration::from_secs(1));
    }

    // load the chain tip, and assert that it is a nakamoto block

    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    info!(
        "Latest tip";
        "is_nakamoto" => tip.anchored_header.as_stacks_nakamoto().is_some(),
    );

    assert!(tip.anchored_header.as_stacks_nakamoto().is_some());

    coord_channel.stop_chains_coordinator();

    epoch_3_stopper.store(false, Ordering::SeqCst);
    epoch_3_thread.join().unwrap();
}
