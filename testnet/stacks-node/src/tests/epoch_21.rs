use std::env;
use std::thread;

use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::StacksBlockHeader;
use stacks::types::chainstate::StacksAddress;

use crate::neon;
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::neon_integrations::*;
use crate::BitcoinRegtestController;
use crate::BurnchainController;
use stacks::core;

use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::distribution::BurnSamplePoint;

use stacks::burnchains::PoxConstants;

use crate::stacks_common::types::Address;

use stacks_common::util::secp256k1::Secp256k1PublicKey;

#[test]
#[ignore]
fn transition_fixes_utxo_chaining() {
    // very simple test to verify that the miner will keep making valid (empty) blocks after the
    // transition.  Really tests that the block-commits are well-formed before and after the epoch
    // transition.
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let epoch_2_05 = 210;
    let epoch_2_1 = 215;

    let (mut conf, miner_account) = neon_integration_test_conf();

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;

    conf.burnchain.epochs = Some(epochs);

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let reward_cycle_len = 2000;
    let prepare_phase_len = 100;
    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        (16 * reward_cycle_len - 1).into(),
        (17 * reward_cycle_len).into(),
        u32::max_value(),
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
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    // give one coinbase to the miner, and then burn the rest
    btc_regtest_controller.bootstrap_chain(1);

    let mining_pubkey = btc_regtest_controller.get_mining_pubkey().unwrap();
    btc_regtest_controller.set_mining_pubkey(
        "03dc62fe0b8964d01fc9ca9a5eec0e22e557a12cc656919e648f04e0b26fea5faa".to_string(),
    );

    // bitcoin chain starts at epoch 2.05 boundary, minus 5 blocks to go
    btc_regtest_controller.bootstrap_chain(epoch_2_05 - 6);

    // only one UTXO for our mining pubkey
    let utxos = btc_regtest_controller
        .get_all_utxos(&Secp256k1PublicKey::from_hex(&mining_pubkey).unwrap());
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

    // these should all succeed across the epoch 2.1 boundary
    for _i in 0..5 {
        // also, make *huge* block-commits with invalid marker bytes once we reach the new
        // epoch, and verify that it fails.
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

        if tip_info.burn_block_height >= epoch_2_1 {
            if tip_info.burn_block_height == epoch_2_1 {
                assert!(res);
            }

            // pox-2 should be initialized now
            let _ = get_contract_src(
                &http_origin,
                StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
                "pox-2".to_string(),
                true,
            )
            .unwrap();
        } else {
            assert!(!res);

            // pox-2 should NOT be initialized
            let e = get_contract_src(
                &http_origin,
                StacksAddress::from_string("ST000000000000000000002AMW42H").unwrap(),
                "pox-2".to_string(),
                true,
            )
            .unwrap_err();
            eprintln!("No pox-2: {}", &e);
        }

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let tip_info = get_chain_info(&conf);
    assert_eq!(tip_info.burn_block_height, epoch_2_1 + 1);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.nonce, 9);

    eprintln!("Begin epoch 2.1");

    // post epoch 2.1 -- UTXO chaining should be fixed
    for i in 0..10 {
        let tip_info = get_chain_info(&conf);

        if i % 2 == 1 {
            std::env::set_var(
                "STX_TEST_LATE_BLOCK_COMMIT",
                format!("{}", tip_info.burn_block_height + 1),
            );
        }

        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    let sortdb = btc_regtest_controller.sortdb_mut();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let burn_sample: Vec<BurnSamplePoint> = sortdb
        .conn()
        .query_row(
            "SELECT data FROM snapshot_burn_distributions WHERE sortition_id = ?",
            &[tip.sortition_id],
            |row| {
                let data_str: String = row.get_unwrap(0);
                Ok(serde_json::from_str(&data_str).unwrap())
            },
        )
        .unwrap();

    // if UTXO linking is fixed, then our median burn will be int((20,000 + 1) / 2).
    // Otherwise, it will be 1.
    assert_eq!(burn_sample.len(), 1);
    assert_eq!(burn_sample[0].burns, 10_000);

    channel.stop_chains_coordinator();
}
