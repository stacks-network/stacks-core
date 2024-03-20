// Copyright (C) 2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::{env, thread};

use clarity::vm::types::PrincipalData;
use stacks::burnchains::{Burnchain, PoxConstants};
use stacks::core;
use stacks_common::consts::STACKS_EPOCH_MAX;
use stacks_common::types::chainstate::StacksPrivateKey;

use crate::config::{EventKeyType, EventObserverConfig, InitialBalance};
use crate::tests::bitcoin_regtest::BitcoinCoreController;
use crate::tests::neon_integrations::{
    get_account, get_chain_info, neon_integration_test_conf, next_block_and_wait, submit_tx,
    test_observer, wait_for_runloop,
};
use crate::tests::{make_stacks_transfer_mblock_only, to_addr};
use crate::{neon, BitcoinRegtestController, BurnchainController};

#[test]
#[ignore]
fn microblocks_disabled() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let reward_cycle_len = 10;
    let prepare_phase_len = 3;
    let epoch_2_05 = 1;
    let epoch_2_1 = 2;
    let v1_unlock_height = epoch_2_1 + 1;
    let epoch_2_2 = 3; // two blocks before next prepare phase.
    let epoch_2_3 = 4;
    let epoch_2_4 = 5;
    let pox_3_activation_height = epoch_2_4;
    let epoch_2_5 = 210;

    let spender_1_bal = 10_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let spender_2_bal = 10_000_000 * (core::MICROSTACKS_PER_STACKS as u64);

    let spender_1_sk = StacksPrivateKey::new();
    let spender_1_addr: PrincipalData = to_addr(&spender_1_sk).into();

    let spender_2_sk = StacksPrivateKey::new();
    let spender_2_addr: PrincipalData = to_addr(&spender_2_sk).into();

    let mut initial_balances = vec![];

    initial_balances.push(InitialBalance {
        address: spender_1_addr.clone(),
        amount: spender_1_bal,
    });

    initial_balances.push(InitialBalance {
        address: spender_2_addr.clone(),
        amount: spender_2_bal,
    });

    let (mut conf, miner_account) = neon_integration_test_conf();

    conf.node.mine_microblocks = true;
    conf.burnchain.max_rbf = 1000000;
    conf.node.wait_time_for_microblocks = 0;
    conf.node.microblock_frequency = 1_000;
    conf.node.wait_time_for_blocks = 2_000;
    conf.miner.wait_for_block_download = false;

    conf.miner.first_attempt_time_ms = i64::max_value() as u64;
    conf.miner.subsequent_attempt_time_ms = i64::max_value() as u64;

    test_observer::spawn();

    conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{}", test_observer::EVENT_OBSERVER_PORT),
        events_keys: vec![EventKeyType::AnyEvent],
    });
    conf.initial_balances.append(&mut initial_balances);

    let mut epochs = core::STACKS_EPOCHS_REGTEST.to_vec();
    epochs[1].end_height = epoch_2_05;
    epochs[2].start_height = epoch_2_05;
    epochs[2].end_height = epoch_2_1;
    epochs[3].start_height = epoch_2_1;
    epochs[3].end_height = epoch_2_2;
    epochs[4].start_height = epoch_2_2;
    epochs[4].end_height = epoch_2_3;
    epochs[5].start_height = epoch_2_3;
    epochs[5].end_height = epoch_2_4;
    epochs[6].start_height = epoch_2_4;
    epochs[6].end_height = epoch_2_5;
    epochs[7].start_height = epoch_2_5;
    epochs[7].end_height = STACKS_EPOCH_MAX;
    epochs.truncate(8);
    conf.burnchain.epochs = Some(epochs);

    let mut burnchain_config = Burnchain::regtest(&conf.get_burn_db_path());

    let pox_constants = PoxConstants::new(
        reward_cycle_len,
        prepare_phase_len,
        4 * prepare_phase_len / 5,
        5,
        15,
        u64::max_value() - 2,
        u64::max_value() - 1,
        v1_unlock_height as u32,
        epoch_2_2 as u32 + 1,
        u32::MAX,
        pox_3_activation_height as u32,
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

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let runloop_burnchain = burnchain_config.clone();

    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(Some(runloop_burnchain), 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // push us to block 205
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let tx = make_stacks_transfer_mblock_only(&spender_1_sk, 0, 500, &spender_2_addr, 500);
    submit_tx(&http_origin, &tx);

    // wait until just before epoch 2.5
    loop {
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height >= epoch_2_5 - 2 {
            break;
        }
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    }

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    info!("Test passed processing 2.5");
    let account = get_account(&http_origin, &spender_1_addr);
    assert_eq!(
        u64::try_from(account.balance).unwrap(),
        spender_1_bal - 1_000
    );
    assert_eq!(account.nonce, 1);

    let tx = make_stacks_transfer_mblock_only(&spender_1_sk, 1, 500, &spender_2_addr, 500);
    submit_tx(&http_origin, &tx);

    let mut last_block_height = get_chain_info(&conf).burn_block_height;
    for _i in 0..5 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height > last_block_height {
            last_block_height = tip_info.burn_block_height;
        } else {
            panic!("FATAL: failed to mine");
        }
    }

    // second transaction should not have been processed!
    let account = get_account(&http_origin, &spender_1_addr);
    assert_eq!(
        u64::try_from(account.balance).unwrap(),
        spender_1_bal - 1_000
    );
    assert_eq!(account.nonce, 1);

    info!(
        "Microblocks assembled: {}",
        test_observer::get_microblocks().len()
    );
    assert_eq!(test_observer::get_microblocks().len(), 1);

    let miner_nonce_before_microblock_assembly = get_account(&http_origin, &miner_account).nonce;

    // Now, lets tell the miner to try to mine microblocks, but don't try to confirm them!
    env::set_var("STACKS_TEST_FORCE_MICROBLOCKS_POST_25", "1");

    let mut last_block_height = get_chain_info(&conf).burn_block_height;
    for _i in 0..2 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height > last_block_height {
            last_block_height = tip_info.burn_block_height;
        } else {
            panic!("FATAL: failed to mine");
        }
    }

    let miner_nonce_after_microblock_assembly = get_account(&http_origin, &miner_account).nonce;

    // second transaction should not have been processed -- even though we should have
    //  produced microblocks, they should not get accepted to the chain state
    let account = get_account(&http_origin, &spender_1_addr);
    assert_eq!(
        u64::try_from(account.balance).unwrap(),
        spender_1_bal - 1_000
    );
    assert_eq!(account.nonce, 1);

    // but we should have assembled and announced at least 1 to the observer
    assert!(test_observer::get_microblocks().len() >= 2);
    info!(
        "Microblocks assembled: {}",
        test_observer::get_microblocks().len()
    );

    // and our miner should have gotten some blocks accepted
    assert!(
        miner_nonce_after_microblock_assembly > miner_nonce_before_microblock_assembly,
        "Mined before started microblock assembly: {miner_nonce_before_microblock_assembly}, Mined after started microblock assembly: {miner_nonce_after_microblock_assembly}"
    );

    // Now, tell the miner to try to confirm microblocks as well.
    //  This should test that the block gets rejected by append block
    env::set_var("STACKS_TEST_CONFIRM_MICROBLOCKS_POST_25", "1");

    let mut last_block_height = get_chain_info(&conf).burn_block_height;
    for _i in 0..2 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let tip_info = get_chain_info(&conf);
        if tip_info.burn_block_height > last_block_height {
            last_block_height = tip_info.burn_block_height;
        } else {
            panic!("FATAL: failed to mine");
        }
    }

    let miner_nonce_after_microblock_confirmation = get_account(&http_origin, &miner_account).nonce;

    // and our miner should have gotten at most one more block accepted
    //  (because they may have had 1 block confirmation in the bitcoin mempool which didn't confirm a microblock
    //   before we flipped the flag)
    assert!(
        miner_nonce_after_microblock_confirmation <= miner_nonce_after_microblock_assembly + 1,
        "Mined after started microblock confimration: {miner_nonce_after_microblock_confirmation}",
    );

    // second transaction should not have been processed -- even though we should have
    //  produced microblocks, they should not get accepted to the chain state
    let account = get_account(&http_origin, &spender_1_addr);
    assert_eq!(
        u64::try_from(account.balance).unwrap(),
        spender_1_bal - 1_000
    );
    assert_eq!(account.nonce, 1);

    test_observer::clear();
    channel.stop_chains_coordinator();
}
