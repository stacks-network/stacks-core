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

use stacks::address::AddressHashMode;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::core::test_util::make_contract_call;
use stacks::core::{StacksEpochId, CHAIN_ID_TESTNET};
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks::util_lib::boot::boot_code_id;
use stacks::util_lib::signed_structured_data::pox4::{
    make_pox_4_signer_key_signature, Pox4SignatureTopic,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_account, get_chain_info, submit_tx};
use crate::tests::signer::SignerTest;
use crate::tests::{self};
use crate::BurnchainController;

/// Submit `stake` transactions to pox-5 for each signer
fn stake_pox_5(signer_test: &SignerTest<SpawnedSigner>) {
    let block_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    let reward_cycle = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let lock_period = 12;
    for stacker_sk in signer_test.signer_stacks_private_keys.iter() {
        let stacker_addr = tests::to_addr(stacker_sk);
        let pox_addr = PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            stacker_addr.bytes().clone(),
        );
        let pox_addr_tuple: clarity::vm::Value =
            pox_addr.clone().as_clarity_tuple().unwrap().into();
        // TODO: update to use pox-5 signature
        let signature = make_pox_4_signer_key_signature(
            &pox_addr,
            stacker_sk,
            reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            lock_period,
            u128::MAX,
            1,
        )
        .unwrap()
        .to_rsv();

        let signer_pk = StacksPublicKey::from_private(stacker_sk);
        let nonce = get_account(&signer_test.running_nodes.rpc_origin(), &stacker_addr).nonce;
        info!("---- Submitting pox-5 stake ----";
            "stacker_addr" => %stacker_addr,
        );
        let stacking_tx = make_contract_call(
            stacker_sk,
            nonce,
            1000,
            signer_test.running_nodes.conf.burnchain.chain_id,
            &StacksAddress::burn_address(false),
            "pox-5",
            "stake",
            &[
                // TODO: use a real amount once we have unlocking from pox-4
                clarity::vm::Value::UInt(1000),
                pox_addr_tuple.clone(),
                clarity::vm::Value::UInt(block_height as u128),
                clarity::vm::Value::some(clarity::vm::Value::buff_from(signature).unwrap())
                    .unwrap(),
                clarity::vm::Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
                clarity::vm::Value::UInt(u128::MAX),
                clarity::vm::Value::UInt(1),
                clarity::vm::Value::UInt(lock_period),
                clarity::vm::Value::buff_from(vec![]).unwrap(),
            ],
        );
        submit_tx(&signer_test.running_nodes.rpc_origin(), &stacking_tx);
    }
}

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

    let conf = &signer_test.running_nodes.conf;
    let epochs = conf.burnchain.epochs.clone().unwrap();
    let epoch_35_start = epochs[StacksEpochId::Epoch35].start_height;

    info!("---- Bootstrap Snapshot ----");
    if signer_test.bootstrap_snapshot_to_height(Some(epoch_35_start - 2)) {
        signer_test.shutdown_and_snapshot();
        return;
    }
    let mut bh = get_chain_info(conf).burn_block_height;
    info!("---- Starting test ----";
        "epoch_3_5" => epoch_35_start,
        "start_burn_block_height" => bh,
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

    info!("---- Got contract source ----";
        "source" => source.split('\n').collect::<Vec<&str>>()[0..3].join("\n"),
    );

    info!("---- Staking in pox-5 ----");

    let signer_addr = tests::to_addr(&signer_test.signer_stacks_private_keys[0]);
    let nonce = get_account(&signer_test.running_nodes.rpc_origin(), &signer_addr).nonce;
    stake_pox_5(&signer_test);
    signer_test
        .wait_for_nonce_increase(&signer_addr, nonce)
        .unwrap();

    let staker_info = signer_test
        .eval_read_only(
            &boot_code_id("pox-5", false),
            &format!("(get-staker-info '{})", signer_addr),
        )
        .expect("Failed to call read-only function get-staker-info")
        .expect_optional()
        .expect("Fatal: expected optional result")
        .expect("Expected Some result from get-staker-info, got None")
        .expect_tuple()
        .expect("Expected tuple type from get-staker-info");

    info!("---- Staker info ----";
        "staker_info" => ?staker_info,
    );

    info!("---- Shutdown ----");
    signer_test.shutdown();
}
