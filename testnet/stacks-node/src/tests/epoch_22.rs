use std::env;
use std::thread;

use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::StacksBlockHeader;

use crate::config::Config;
use crate::config::EventKeyType;
use crate::config::EventObserverConfig;
use crate::config::InitialBalance;
use crate::neon;
use crate::neon::RunLoopCounter;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::neon_integrations::*;
use crate::tests::*;
use crate::BitcoinRegtestController;
use crate::BurnchainController;
use stacks::core;

use stacks::chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::operations::LeaderBlockCommitOp;

use stacks::chainstate::stacks::address::PoxAddress;

use stacks::burnchains::PoxConstants;
use stacks::burnchains::Txid;

use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::VRFSeed;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use stacks::chainstate::coordinator::comm::CoordinatorChannels;

use clarity::vm::types::PrincipalData;

use crate::Keychain;

const MINER_BURN_PUBLIC_KEY: &'static str =
    "03dc62fe0b8964d01fc9ca9a5eec0e22e557a12cc656919e648f04e0b26fea5faa";

#[allow(dead_code)]
fn advance_to_2_2(
    mut initial_balances: Vec<InitialBalance>,
    block_reward_recipient: Option<PrincipalData>,
    pox_constants: Option<PoxConstants>,
    segwit: bool,
) -> (
    Config,
    BitcoinCoreController,
    BitcoinRegtestController,
    RunLoopCounter,
    CoordinatorChannels,
) {
    let epoch_2_05 = 210;
    let epoch_2_1 = 215;
    let epoch_2_2 = 220;

    test_observer::spawn();

    let (mut conf, miner_account) = neon_integration_test_conf();

    conf.burnchain.peer_host = "localhost".to_string();
    conf.initial_balances.append(&mut initial_balances);
    conf.miner.block_reward_recipient = block_reward_recipient;

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;
    epochs[3].end_height = epoch_2_2;
    epochs[4].start_height = epoch_2_2;

    conf.burnchain.epochs = Some(epochs);

    conf.miner.segwit = segwit;

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let reward_cycle_len = 2000;
    let prepare_phase_len = 100;
    let pox_constants = pox_constants.unwrap_or(PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        u64::max_value() - 2,
        u64::max_value() - 1,
        u32::max_value(),
    ));
    burnchain_config.pox_constants = pox_constants.clone();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
        conf.clone(),
        None,
        Some(burnchain_config.clone()),
        None,
    );
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    // give one coinbase to the miner, and then burn the rest
    // if segwit is supported, then give one coinbase to the segwit address as well as the legacy
    // address. This is needed to allow the miner to boot up into 2.1 through epochs 2.0 and 2.05.
    let mining_pubkey = if conf.miner.segwit {
        btc_regtest_controller.set_use_segwit(false);
        btc_regtest_controller.bootstrap_chain(1);

        btc_regtest_controller.set_use_segwit(conf.miner.segwit);
        btc_regtest_controller.bootstrap_chain(1);

        let mining_pubkey = btc_regtest_controller.get_mining_pubkey().unwrap();
        debug!("Mining pubkey is {}", &mining_pubkey);
        btc_regtest_controller.set_mining_pubkey(MINER_BURN_PUBLIC_KEY.to_string());

        mining_pubkey
    } else {
        btc_regtest_controller.bootstrap_chain(1);

        let mining_pubkey = btc_regtest_controller.get_mining_pubkey().unwrap();
        debug!("Mining pubkey is {}", &mining_pubkey);
        btc_regtest_controller.set_mining_pubkey(MINER_BURN_PUBLIC_KEY.to_string());

        btc_regtest_controller.bootstrap_chain(1);

        mining_pubkey
    };

    // bitcoin chain starts at epoch 2.05 boundary, minus 5 blocks to go
    btc_regtest_controller.bootstrap_chain(epoch_2_05 - 7);

    // only one UTXO for our mining pubkey (which is uncompressed, btw)
    // NOTE: if we're using segwit, then the mining pubkey will be compressed for the segwit UTXO
    // generation (i.e. it'll be treated as different from the uncompressed public key).
    let utxos = btc_regtest_controller
        .get_all_utxos(&Secp256k1PublicKey::from_hex(&mining_pubkey).unwrap());

    eprintln!(
        "UTXOs for {} (segwit={}): {:?}",
        &mining_pubkey, conf.miner.segwit, &utxos
    );
    assert_eq!(utxos.len(), 1);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    let runloop_burnchain = burnchain_config.clone();
    thread::spawn(move || run_loop.start(Some(runloop_burnchain), 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_05 - 4);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // cross the epoch 2.05 boundary
    for _i in 0..3 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_05 + 1);

    // these should all succeed across the epoch 2.1, then 2.2 boundaries
    for _i in 0..10 {
        let tip_info = get_chain_info(&conf);

        // this block is the epoch transition?
        let (chainstate, _) = StacksChainState::open(
            false,
            conf.burnchain.chain_id,
            &conf.get_chainstate_path_str(),
            None,
        )
        .unwrap();
        let res = StacksChainState::block_crosses_epoch_boundary(
            &chainstate.db(),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
        )
        .unwrap();
        debug!(
            "Epoch transition at {} ({}/{}) height {}: {}",
            &StacksBlockHeader::make_index_block_hash(
                &tip_info.stacks_tip_consensus_hash,
                &tip_info.stacks_tip
            ),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
            tip_info.burn_block_height,
            res
        );

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_1 + 1);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.nonce, 9);

    eprintln!("Begin Stacks 2.2");
    return (
        conf,
        btcd_controller,
        btc_regtest_controller,
        blocks_processed,
        channel,
    );
}

#[test]
#[ignore]
fn transition_empty_blocks() {
    // very simple test to verify that the miner will keep making valid (empty) blocks after the
    // transition.  Really tests that the block-commits are well-formed before and after the epoch
    // transition.
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let epoch_2_05 = 210;
    let epoch_2_1 = 215;
    let epoch_2_2 = 220;

    let (mut conf, miner_account) = neon_integration_test_conf();

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;
    epochs[3].end_height = epoch_2_2;
    epochs[4].start_height = epoch_2_2;

    conf.node.mine_microblocks = false;
    conf.burnchain.max_rbf = 1000000;
    conf.miner.first_attempt_time_ms = 5_000;
    conf.miner.subsequent_attempt_time_ms = 10_000;
    conf.node.wait_time_for_blocks = 0;

    conf.burnchain.epochs = Some(epochs);

    test_observer::spawn();

    conf.events_observers.push(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let keychain = Keychain::default(conf.node.seed.clone());
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let reward_cycle_len = 10;
    let prepare_phase_len = 3;
    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        u64::max_value() - 2,
        u64::max_value() - 1,
        (epoch_2_1 + 1) as u32,
    );
    burnchain_config.pox_constants = pox_constants.clone();

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::with_burnchain(
        conf.clone(),
        None,
        Some(burnchain_config.clone()),
        None,
    );

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    let runloop_burnchain_config = burnchain_config.clone();
    thread::spawn(move || run_loop.start(Some(runloop_burnchain_config), 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let tip_info = get_chain_info(&conf);
    let key_block_ptr = tip_info.burn_block_height as u32;
    let key_vtxindex = 1; // nothing else here but the coinbase

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let burnchain = Burnchain::regtest(&conf.get_burn_db_path());
    let mut bitcoin_controller = BitcoinRegtestController::new_dummy(conf.clone());

    let mut crossed_22_boundary = false;

    // these should all succeed across the epoch boundary
    for _i in 0..35 {
        // also, make *huge* block-commits with invalid marker bytes once we reach the new
        // epoch, and verify that it fails.
        let tip_info = get_chain_info(&conf);
        let pox_info = get_pox_info(&http_origin);

        eprintln!(
            "\nPoX info at {}\n{:?}\n\n",
            tip_info.burn_block_height, &pox_info
        );

        // this block is the epoch transition?
        let (chainstate, _) = StacksChainState::open(
            false,
            conf.burnchain.chain_id,
            &conf.get_chainstate_path_str(),
            None,
        )
        .unwrap();
        let res = StacksChainState::block_crosses_epoch_boundary(
            &chainstate.db(),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
        )
        .unwrap();
        debug!(
            "Epoch transition at {} ({}/{}) height {}: {}",
            &StacksBlockHeader::make_index_block_hash(
                &tip_info.stacks_tip_consensus_hash,
                &tip_info.stacks_tip
            ),
            &tip_info.stacks_tip_consensus_hash,
            &tip_info.stacks_tip,
            tip_info.burn_block_height,
            res
        );

        if tip_info.burn_block_height == epoch_2_05
            || tip_info.burn_block_height == epoch_2_1
            || tip_info.burn_block_height == epoch_2_2
        {
            assert!(res);
            if tip_info.burn_block_height == epoch_2_2 {
                crossed_22_boundary = true;
            }
        } else {
            assert!(!res);
        }

        if tip_info.burn_block_height + 1 >= epoch_2_1 {
            let burn_fee_cap = 100000000; // 1 BTC
            let commit_outs = if !burnchain.is_in_prepare_phase(tip_info.burn_block_height + 1) {
                vec![
                    PoxAddress::standard_burn_address(conf.is_mainnet()),
                    PoxAddress::standard_burn_address(conf.is_mainnet()),
                ]
            } else {
                vec![PoxAddress::standard_burn_address(conf.is_mainnet())]
            };

            // let's commit
            let burn_parent_modulus =
                ((tip_info.burn_block_height + 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8;
            let op = BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
                sunset_burn: 0,
                block_header_hash: BlockHeaderHash([0xff; 32]),
                burn_fee: burn_fee_cap,
                input: (Txid([0; 32]), 0),
                apparent_sender: keychain.get_burnchain_signer(),
                key_block_ptr,
                key_vtxindex,
                memo: vec![0], // bad epoch marker
                new_seed: VRFSeed([0x11; 32]),
                parent_block_ptr: 0,
                parent_vtxindex: 0,
                // to be filled in
                vtxindex: 0,
                txid: Txid([0u8; 32]),
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash::zero(),
                burn_parent_modulus,
                commit_outs,
            });
            let mut op_signer = keychain.generate_op_signer();
            let res =
                bitcoin_controller.submit_operation(StacksEpochId::Epoch21, op, &mut op_signer, 1);
            assert!(res.is_some(), "Failed to submit block-commit");
        }

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let account = get_account(&http_origin, &miner_account);
    assert!(crossed_22_boundary);
    assert!(account.nonce >= 31);

    channel.stop_chains_coordinator();
}
