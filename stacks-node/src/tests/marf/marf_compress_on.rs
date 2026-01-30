// Copyright (C) 2025 Stacks Open Internet Foundation
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

//! MARF integration tests exercising behavior with compression always enabled.

use crate::tests::marf::marf_compress_dyn;

pub mod utils {
    use std::sync::atomic::Ordering;
    use std::{env, thread};

    use clarity::vm::types::PrincipalData;
    use stacks::chainstate::nakamoto::test_signers::TestSigners;
    use stacks::util::secp256k1::Secp256k1PrivateKey;

    use crate::burnchains::bitcoin::core_controller::BitcoinCoreController;
    use crate::neon::Counters;
    use crate::run_loop::boot_nakamoto;
    use crate::tests::nakamoto_integrations::{
        blind_signer, boot_to_epoch_3, naka_neon_integration_conf, setup_stacker,
        wait_for_first_naka_block_commit,
    };
    use crate::tests::neon_integrations::{get_chain_tip_height, test_observer, wait_for_runloop};
    use crate::tests::{self};
    use crate::{BitcoinRegtestController, BurnchainController};

    /// Just boot chain to epoch 3 using marf compress as node configuration
    pub fn boot_chain_with_marf_compress_cfg(compress: bool) {
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let mut signers = TestSigners::default();
        let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
        naka_conf.node.marf_compress = compress;

        let http_origin = naka_conf.node.data_url.clone();
        let sender_signer_sk = Secp256k1PrivateKey::random();
        let sender_signer_addr = tests::to_addr(&sender_signer_sk);
        naka_conf.add_initial_balance(
            PrincipalData::from(sender_signer_addr.clone()).to_string(),
            100000,
        );
        let stacker_sk = setup_stacker(&mut naka_conf);

        test_observer::spawn();
        test_observer::register_any(&mut naka_conf);

        let mut btcd_controller = BitcoinCoreController::from_stx_config(&naka_conf);
        btcd_controller
            .start_bitcoind()
            .expect("Failed starting bitcoind");
        let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
        btc_regtest_controller.bootstrap_chain(201);

        let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
        let run_loop_stopper = run_loop.get_termination_switch();
        let Counters {
            blocks_processed,
            naka_submitted_commits: commits_submitted,
            ..
        } = run_loop.counters();
        let counters = run_loop.counters();

        let coord_channel = run_loop.coordinator_channels();

        let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));
        wait_for_runloop(&blocks_processed);
        boot_to_epoch_3(
            &naka_conf,
            &blocks_processed,
            &[stacker_sk.clone()],
            &[sender_signer_sk],
            &mut Some(&mut signers),
            &mut btc_regtest_controller,
        );

        info!("Nakamoto miner started...");
        blind_signer(&naka_conf, &signers, &counters);

        wait_for_first_naka_block_commit(60, &commits_submitted);

        let stacks_height = get_chain_tip_height(&http_origin);
        assert_eq!(27, stacks_height);

        coord_channel
            .lock()
            .expect("Mutex poisoned")
            .stop_chains_coordinator();
        run_loop_stopper.store(false, Ordering::SeqCst);

        run_loop_thread.join().unwrap();
    }
}

/// Test copied from `stacks-node::tests::signer::large_mempool_original_constant_fee`
/// Interesting because with full MARF compression produces patch nodes with 256 diffs (max diff allowed)
///
/// In this scenario, MARF compression is always enabled.
#[test]
#[ignore]
fn large_mempool_with_marf_compression() {
    marf_compress_dyn::utils::large_mempool_base(true, true);
}

/// Boots the chain to epoch 3 using a node configuration where MARF compression is enabled.
#[test]
#[ignore]
fn test_boot_chain_with_node_marf_compress_enabled() {
    utils::boot_chain_with_marf_compress_cfg(true);
}
