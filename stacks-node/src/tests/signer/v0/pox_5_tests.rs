// Copyright (C) 2026 Stacks Open Internet Foundation
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
use std::env;
use std::time::Duration;

use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::RejectCode;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::TenureChangeCause;
use stacks::core::test_util::{make_stacks_transfer_serialized, to_addr};
use stacks::core::StacksEpochId;
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::{
    TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_REJECT_ALL_BLOCK_PROPOSAL,
    TEST_SIGNERS_INSERT_BLOCK_PROPOSAL_WITHOUT_PROCESSING,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::nakamoto_node::stackerdb_listener::TEST_IGNORE_SIGNERS;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, submit_tx, test_observer};
use crate::tests::signer::v0::{
    wait_for_block_acceptance_from_signers, wait_for_block_global_acceptance_from_signers,
    wait_for_block_pre_commits_from_signers, wait_for_block_proposal, wait_for_block_pushed,
    wait_for_block_pushed_by_miner_key, wait_for_block_rejections_from_signers, MultipleMinerTest,
};
use crate::tests::signer::SignerTest;
use crate::tests::{self};

#[test]
#[ignore]
fn test_pox_5_activation() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 10)],
            |_| {},
            |_| {},
            None,
            None,
            Some(function_name!()),
        );

    info!("---- Bootstrap Snapshot ----");
    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = &signer_test.running_nodes.conf;
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let epochs = conf.burnchain.epochs.clone().unwrap();
    let epoch_35_start = epochs[StacksEpochId::Epoch35].start_height;
    let mut bh = get_chain_info(conf).burn_block_height;
    info!("---- Starting test ----";
        "epoch_3_5" => epoch_35_start,
        "start_burn_block_height" => bh,
    );

    // quickly mine to 3.1 start
    let block_diff = epochs[StacksEpochId::Epoch31].start_height - bh;
    btc_controller.build_next_block(block_diff);
    wait_for(30, || {
        Ok(get_chain_info(conf).burn_block_height >= epochs[StacksEpochId::Epoch31].start_height)
    })
    .expect("Timed out waiting for burn block height to increase");
    bh = get_chain_info(conf).burn_block_height;
    info!("---- Mined to 3.1 start ----";
        "burn_block_height" => bh,
    );

    // quickly mine to 3.2 start
    let block_diff = epochs[StacksEpochId::Epoch32].start_height - bh;
    btc_controller.build_next_block(block_diff);
    wait_for(30, || {
        Ok(get_chain_info(conf).burn_block_height >= epochs[StacksEpochId::Epoch32].start_height)
    })
    .expect("Timed out waiting for burn block height to increase");
    bh = get_chain_info(conf).burn_block_height;
    info!("---- Mined to 3.2 start ----";
        "burn_block_height" => bh,
    );

    while bh < epoch_35_start {
        signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
        wait_for(30, || Ok(get_chain_info(conf).burn_block_height > bh))
            .expect("Timed out waiting for burn block height to increase");
        bh = get_chain_info(conf).burn_block_height;
        info!("---- Mined block ----";
            "burn_block_height" => bh,
        );
    }

    info!("---- Mined up to epoch 3.5 ----";
        "burn_block_height" => bh,
    );

    let tip = signer_test.get_peer_info();
    info!("---- Tip ----";
        "stacks_tip_height" => tip.stacks_tip_height,
        "burn_block_height" => tip.burn_block_height,
    );

    let source = tests::neon_integrations::get_contract_src(
        &signer_test.running_nodes.rpc_origin(),
        StacksAddress::burn_address(false),
        "pox-5".to_string(),
        true,
    )
    .expect("Failed to get contract source");

    info!("---- Contract source ----";
        "source" => source,
    );

    info!("---- Shutdown ----");
    signer_test.shutdown();
}
