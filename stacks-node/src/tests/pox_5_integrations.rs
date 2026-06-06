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

//! End-to-end integration tests for pox-5.
//!
//! Covers the basic stake/unstake lifecycle, the `register-for-bond` flow
//! (both the sBTC branch and the L1 Bitcoin lockup branch, including the
//! OP_IF timelock-matured and OP_ELSE early-exit witness paths), and the
//! `with-stacking` allowances that gate calls from contract callers.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::{env, thread};

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, Value};
use stacks::chainstate::nakamoto::test_signers::TestSigners;
use stacks::core::test_util::make_contract_call;
use stacks::core::StacksEpochId;
use stacks::util::hash::hex_bytes;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

use crate::burnchains::bitcoin::core_controller::BitcoinCoreController;
use crate::burnchains::BurnchainController;
use crate::neon::Counters;
use crate::operations::BurnchainOpSigner;
use crate::run_loop::boot_nakamoto;
use crate::tests::nakamoto_integrations::{
    boot_to_epoch_4_0, enable_epoch_4_0, get_tx_result_by_id, naka_neon_integration_conf,
    next_block_and_mine_commit, next_block_and_process_new_stacks_block, setup_stacker, wait_for,
    POX_DEFAULT_STACKER_STX_AMT,
};
use crate::tests::neon_integrations::{
    call_read_only, get_account, get_chain_info_result, submit_tx, test_observer, wait_for_runloop,
};
use crate::tests::signer::v0::pox5_signer_manager_source;
use crate::tests::{make_contract_publish, to_addr};
use crate::{tests, BitcoinRegtestController, Config, Keychain};

#[test]
#[ignore]
/// Verify the pox-5 stake lifecycle end-to-end on a regtest network:
/// register a signer, lock STX via `stake`, extend / increase via
/// `stake-update`, and finally schedule the unlock via `unstake`. Each
/// pox-5 entrypoint is invoked directly from a wallet (no `restrict-assets?`
/// wrapping) and we assert the resulting STX lock state on the staker's
/// account after every step.
fn check_pox_5_stake_lifecycle() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    enable_epoch_4_0(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.burnchain.chain_id = CHAIN_ID_TESTNET + 1;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_signer_sk = Secp256k1PrivateKey::random();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);

    let signer_sk = signers.signer_keys[0].clone();
    let signer_pk = StacksPublicKey::from_private(&signer_sk);

    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 3000;
    let call_fee = 400;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        deploy_fee + call_fee * 10,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // sBTC stubs - pox-5 boot needs both stubs deployed before the epoch 4.0
    // transition for static analysis to find the referenced contracts.
    let sbtc_deployer_sk = Secp256k1PrivateKey::random();
    let sbtc_deployer_addr = tests::to_addr(&sbtc_deployer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sbtc_deployer_addr.clone()).to_string(),
        2 * deploy_fee,
    );
    let sbtc_token_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-token").unwrap(),
    );
    let sbtc_registry_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-registry").unwrap(),
    );
    naka_conf.node.pox_5_sbtc_contract = Some(sbtc_token_id.clone());
    naka_conf.node.pox_5_sbtc_registry_contract = Some(sbtc_registry_id.clone());

    let stacker_sk = setup_stacker(&mut naka_conf);
    let staker_sk = setup_stacker(&mut naka_conf);
    let staker_addr = tests::to_addr(&staker_sk);

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
        blocks_processed, ..
    } = run_loop.counters();
    let counters = run_loop.counters();
    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let pubkey_bytes: [u8; 33] = signer_pk
        .to_bytes_compressed()
        .try_into()
        .expect("compressed secp256k1 pubkey should be 33 bytes");
    boot_to_epoch_4_0(
        &naka_conf,
        &blocks_processed,
        &counters,
        &coord_channel,
        &[stacker_sk.clone()],
        &[sender_signer_sk],
        &[signer_sk.clone()],
        &sbtc_deployer_sk,
        Some(&pubkey_bytes),
        deploy_fee,
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );

    let mut sender_nonce = 0;

    // Deploy the signer-manager contract.
    let signer_contract = pox5_signer_manager_source();
    let signer_deploy_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "test-signer",
        signer_contract,
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &signer_deploy_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for test-signer deploy");

    next_block_and_mine_commit(&mut btc_regtest_controller, 60, &naka_conf, &counters).unwrap();

    let test_signer_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from("test-signer").unwrap(),
    ));
    let auth_id: u128 = 1;
    let signer_grant_sig =
        stacks::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature(
            &test_signer_principal,
            auth_id,
            naka_conf.burnchain.chain_id,
            &signer_sk,
        )
        .expect("Failed to generate signer grant signature");
    let register_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "register-self",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            Value::UInt(auth_id),
            Value::buff_from(signer_grant_sig.to_rsv()).unwrap(),
        ],
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &register_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for register-self");

    // 1) `stake` — locks STX directly through pox-5 (no wrapper contract).
    let pox_5_id = boot_code_id("pox-5", false);
    let pox_5_addr: StacksAddress = pox_5_id.issuer.clone().into();
    let stake_amount = POX_DEFAULT_STACKER_STX_AMT;
    let staker_balance_before = get_account(&http_origin, &staker_addr).balance;
    assert!(staker_balance_before >= stake_amount + call_fee as u128 * 3);

    let stake_tx = make_contract_call(
        &staker_sk,
        0,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "stake",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(stake_amount),
            Value::UInt(12),
            Value::UInt(get_chain_info_result(&naka_conf).unwrap().burn_block_height as u128),
            Value::none(),
        ],
    );
    let stake_txid = submit_tx(&http_origin, &stake_tx);
    info!("Submitted pox-5 stake txid: {stake_txid}");
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 1),
    )
    .expect("Timed out waiting for stake");

    let after_stake = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_stake.locked, stake_amount,
        "stake should have locked exactly {stake_amount} ustx"
    );

    // 2) `stake-update` — extend by 1 cycle and increase by `extra`.
    next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 30, &coord_channel)
        .unwrap();
    let extra = 1_000_000u128;
    let update_tx = make_contract_call(
        &staker_sk,
        1,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "stake-update",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(1),
            Value::UInt(extra),
            Value::none(),
        ],
    );
    let update_txid = submit_tx(&http_origin, &update_tx);
    info!("Submitted pox-5 stake-update txid: {update_txid}");
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 2),
    )
    .expect("Timed out waiting for stake-update");

    let after_update = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_update.locked,
        stake_amount + extra,
        "stake-update should have locked an additional {extra} ustx"
    );
    let unlock_height_before_unstake = after_update.unlock_height;

    // 3) `unstake` — pox-5 forbids unstaking during the prepare phase.
    // Mine forward until we observe a contract-call result that isn't
    // `ERR_UNSTAKE_IN_PREPARE_PHASE` (u9). With `naka_neon_integration_conf`'s
    // defaults (reward 20 / prepare 5), prepare covers the last 5 burn
    // blocks of every 20-block cycle, so a handful of attempts always
    // land outside it.
    let pre_unstake_nonce = get_account(&http_origin, &staker_addr).nonce;
    let mut unstake_nonce = pre_unstake_nonce;
    let mut unstake_succeeded = false;
    let mut unstake_unlock_height: Option<u64> = None;
    for attempt in 0..6 {
        next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 30, &coord_channel)
            .unwrap();

        test_observer::clear();
        let unstake_tx = make_contract_call(
            &staker_sk,
            unstake_nonce,
            call_fee,
            naka_conf.burnchain.chain_id,
            &pox_5_addr,
            "pox-5",
            "unstake",
            &[Value::Principal(test_signer_principal.clone())],
        );
        let unstake_txid = submit_tx(&http_origin, &unstake_tx);
        info!("Submitted pox-5 unstake txid: {unstake_txid} (attempt {attempt})");
        let target_nonce = unstake_nonce + 1;
        wait_for(60, || {
            Ok(get_account(&http_origin, &staker_addr).nonce == target_nonce)
        })
        .expect("Timed out waiting for unstake to confirm");
        unstake_nonce = target_nonce;

        let parsed = get_tx_result_by_id(&unstake_txid)
            .expect("Did not observe unstake txid in test_observer");
        let response = parsed
            .clone()
            .expect_result()
            .expect("unstake response should be a clarity response");
        if let Ok(ok_value) = response {
            // Pull `unlock-burn-height` out of the unstake response tuple
            // so we can assert pox-locking actually applied the rescheduled
            // unlock to the staker's STX.
            let tuple = ok_value
                .expect_tuple()
                .expect("unstake ok payload should be a tuple");
            let unlock_height = tuple
                .get("unlock-burn-height")
                .expect("unstake response missing unlock-burn-height")
                .clone()
                .expect_u128()
                .expect("unlock-burn-height should be a uint")
                as u64;
            unstake_unlock_height = Some(unlock_height);
            unstake_succeeded = true;
        } else {
            info!("unstake attempt {attempt} returned: {parsed:?}");
        }

        if unstake_succeeded {
            break;
        }
    }
    assert!(
        unstake_succeeded,
        "pox-5 unstake never succeeded after 6 burn-block attempts"
    );
    let unstake_unlock_height =
        unstake_unlock_height.expect("unstake_succeeded but no unlock-burn-height captured");

    // pox-5 unstake schedules an unlock at `(+ u1 current-cycle)` — the STX
    // remain locked, but at the new (earlier) unlock burn height. pox-locking
    // is responsible for translating the contract response into a database
    // mutation; assert both the locked amount and the rescheduled unlock
    // height are reflected on the account.
    let after_unstake = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_unstake.locked,
        stake_amount + extra,
        "unstake schedules unlock for next cycle; STX should still be locked now"
    );
    assert!(
        unstake_unlock_height < unlock_height_before_unstake,
        "unstake should move the unlock height earlier (was {unlock_height_before_unstake}, now {unstake_unlock_height})"
    );
    assert_eq!(
        after_unstake.unlock_height, unstake_unlock_height,
        "pox-locking should have applied the rescheduled unlock-burn-height"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);
    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// Verify the pox-5 bond lifecycle end-to-end on a regtest network: the
/// configured bond admin sets up bond-index 0, the staker mints sBTC and
/// locks STX directly through `register-for-bond`, and a second
/// `register-for-bond` from the same staker is rejected with
/// `ERR_ALREADY_REGISTERED`. Each pox-5 entrypoint is invoked directly
/// from a wallet (no `restrict-assets?` wrapping) and we assert the
/// resulting STX lock state and the rescheduled `unlock-burn-height` on
/// the staker's account.
fn check_pox_5_register_for_bond_lifecycle() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    enable_epoch_4_0(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.burnchain.chain_id = CHAIN_ID_TESTNET + 1;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_signer_sk = Secp256k1PrivateKey::random();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);

    let signer_sk = signers.signer_keys[0].clone();
    let signer_pk = StacksPublicKey::from_private(&signer_sk);

    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 3000;
    let call_fee = 400;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        deploy_fee + call_fee * 10,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // sBTC stubs - pox-5 boot needs both stubs deployed before the epoch 4.0
    // transition for static analysis to find the referenced contracts.
    let sbtc_deployer_sk = Secp256k1PrivateKey::random();
    let sbtc_deployer_addr = tests::to_addr(&sbtc_deployer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sbtc_deployer_addr.clone()).to_string(),
        2 * deploy_fee,
    );
    let sbtc_token_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-token").unwrap(),
    );
    let sbtc_registry_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-registry").unwrap(),
    );
    naka_conf.node.pox_5_sbtc_contract = Some(sbtc_token_id.clone());
    naka_conf.node.pox_5_sbtc_registry_contract = Some(sbtc_registry_id.clone());

    // The pox-5 boot contract initializes its `bond-admin` data var to
    // `tx-sender`, which at boot deploy time is the unsignable boot
    // principal. Override it to a key we control so that `setup-bond` is
    // callable from the test (forbidden on mainnet).
    let bond_admin_sk = Secp256k1PrivateKey::random();
    let bond_admin_addr = tests::to_addr(&bond_admin_sk);
    // setup-bond carries a 683-byte buffer and a 1-entry allowlist; the
    // node prices it well above the small `call_fee` used for ordinary
    // contract calls.
    let setup_bond_fee = 5000u64;
    naka_conf.add_initial_balance(
        PrincipalData::from(bond_admin_addr.clone()).to_string(),
        setup_bond_fee + 1000,
    );
    naka_conf.node.pox_5_bond_admin = Some(PrincipalData::from(bond_admin_addr.clone()));

    let stacker_sk = setup_stacker(&mut naka_conf);
    let staker_sk = setup_stacker(&mut naka_conf);
    let staker_addr = tests::to_addr(&staker_sk);

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
        blocks_processed, ..
    } = run_loop.counters();
    let counters = run_loop.counters();
    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let pubkey_bytes: [u8; 33] = signer_pk
        .to_bytes_compressed()
        .try_into()
        .expect("compressed secp256k1 pubkey should be 33 bytes");
    boot_to_epoch_4_0(
        &naka_conf,
        &blocks_processed,
        &counters,
        &coord_channel,
        &[stacker_sk.clone()],
        &[sender_signer_sk],
        &[signer_sk.clone()],
        &sbtc_deployer_sk,
        Some(&pubkey_bytes),
        deploy_fee,
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );
    info!("Reached Epoch-4.0 boundary, deploying signer-manager and registering signer");

    let mut sender_nonce = 0;

    // Deploy the signer-manager contract.
    let signer_contract = pox5_signer_manager_source();
    let signer_deploy_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "test-signer",
        signer_contract,
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &signer_deploy_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for test-signer deploy");

    next_block_and_mine_commit(&mut btc_regtest_controller, 60, &naka_conf, &counters).unwrap();

    let test_signer_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from("test-signer").unwrap(),
    ));
    let auth_id: u128 = 1;
    let signer_grant_sig =
        stacks::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature(
            &test_signer_principal,
            auth_id,
            naka_conf.burnchain.chain_id,
            &signer_sk,
        )
        .expect("Failed to generate signer grant signature");
    let register_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "register-self",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            Value::UInt(auth_id),
            Value::buff_from(signer_grant_sig.to_rsv()).unwrap(),
        ],
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &register_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for register-self");

    let pox_5_id = boot_code_id("pox-5", false);
    let pox_5_addr: StacksAddress = pox_5_id.issuer.clone().into();

    // 1) `setup-bond` from the configured bond admin. Allowlist the staker
    // for `SBTC_AMT` sats. With `stx-value-ratio = 100` and
    // `min-ustx-ratio = 10000` (== 100% in basis points),
    // `min-ustx-for-sats-amount(SBTC_AMT, 100, 10000) = SBTC_AMT` ustx, so
    // any `amount-ustx >= SBTC_AMT` clears the bond's STX floor.
    const SBTC_AMT: u128 = 1_000_000;
    let allowlist_entry = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("staker").unwrap(),
                Value::Principal(staker_addr.clone().into()),
            ),
            (
                ClarityName::try_from("max-sats").unwrap(),
                Value::UInt(SBTC_AMT),
            ),
        ])
        .unwrap(),
    );
    let allowlist_value = Value::cons_list_unsanitized(vec![allowlist_entry]).unwrap();
    let setup_bond_tx = make_contract_call(
        &bond_admin_sk,
        0,
        setup_bond_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "setup-bond",
        &[
            Value::UInt(0),
            Value::UInt(1000),
            Value::UInt(100),
            Value::UInt(10000),
            Value::buff_from(vec![0u8; 683]).unwrap(),
            Value::Principal(bond_admin_addr.clone().into()),
            allowlist_value,
        ],
    );
    let setup_bond_txid = submit_tx(&http_origin, &setup_bond_tx);
    info!("Submitted pox-5 setup-bond txid: {setup_bond_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &bond_admin_addr).nonce == 1)
    })
    .expect("Timed out waiting for setup-bond");

    // 2) Mint `2 * SBTC_AMT` sBTC to the staker so `register-for-bond`'s sBTC
    // branch (`(err sbtc-amount)`) can pull `SBTC_AMT` sats from `tx-sender`
    // into pox-5. Only `SBTC_AMT` is actually consumed — the duplicate
    // `register-for-bond` in step (4) now fails on the membership gate
    // *before* `roll-sbtc` runs, so no second transfer is attempted. We
    // keep the 2× headroom for safety. The sBTC stub's `mint` has no
    // caller restriction.
    let mint_tx = make_contract_call(
        &staker_sk,
        0,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sbtc_deployer_addr,
        "sbtc-token",
        "mint",
        &[
            Value::UInt(SBTC_AMT * 2),
            Value::Principal(staker_addr.clone().into()),
        ],
    );
    submit_tx(&http_origin, &mint_tx);
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 1),
    )
    .expect("Timed out waiting for sbtc mint");

    // 3) `register-for-bond`. The `(err sbtc-amount)` branch selects the sBTC lockup path.
    let bond_amount = POX_DEFAULT_STACKER_STX_AMT;
    let staker_balance_before = get_account(&http_origin, &staker_addr).balance;
    assert!(staker_balance_before >= bond_amount + call_fee as u128 * 2);

    test_observer::clear();
    let register_tx = make_contract_call(
        &staker_sk,
        1,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            Value::error(Value::UInt(SBTC_AMT)).unwrap(),
            Value::none(),
        ],
    );
    let register_txid = submit_tx(&http_origin, &register_tx);
    info!("Submitted pox-5 register-for-bond txid: {register_txid}");
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 2),
    )
    .expect("Timed out waiting for register-for-bond");

    // Pull `unlock-burn-height` out of the register-for-bond response so
    // we can assert pox-locking applied the expected unlock to the
    // staker's STX.
    let parsed = get_tx_result_by_id(&register_txid)
        .expect("did not observe register-for-bond txid in test_observer");
    let response = parsed
        .expect_result()
        .expect("register-for-bond response should be a clarity response");
    let ok_value = response.expect("register-for-bond should have returned ok");
    let tuple = ok_value
        .expect_tuple()
        .expect("register-for-bond ok payload should be a tuple");
    let register_unlock_height = tuple
        .get("unlock-burn-height")
        .expect("register-for-bond response missing unlock-burn-height")
        .clone()
        .expect_u128()
        .expect("unlock-burn-height should be a uint") as u64;

    let after_register = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_register.locked, bond_amount,
        "register-for-bond should have locked exactly {bond_amount} ustx"
    );
    assert_eq!(
        after_register.unlock_height, register_unlock_height,
        "pox-locking should have applied the bond's unlock-burn-height"
    );

    // 4) A second `register-for-bond` from the same staker must fail with
    // `ERR_ALREADY_REGISTERED` (u9). Submit it and assert the response.
    test_observer::clear();
    let dup_tx = make_contract_call(
        &staker_sk,
        2,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            Value::error(Value::UInt(SBTC_AMT)).unwrap(),
            Value::none(),
        ],
    );
    let dup_txid = submit_tx(&http_origin, &dup_tx);
    info!("Submitted duplicate pox-5 register-for-bond txid: {dup_txid}");
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 3),
    )
    .expect("Timed out waiting for duplicate register-for-bond");

    let parsed = get_tx_result_by_id(&dup_txid)
        .expect("Did not observe duplicate register-for-bond txid in test_observer");
    assert_eq!(
        parsed,
        Value::error(Value::UInt(9)).unwrap(),
        "duplicate register-for-bond should fail with ERR_ALREADY_REGISTERED (u9)"
    );

    // The duplicate failure must not have disturbed the existing lock.
    let after_dup = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_dup.locked, bond_amount,
        "failed duplicate register-for-bond must not change locked balance"
    );
    assert_eq!(
        after_dup.unlock_height, register_unlock_height,
        "failed duplicate register-for-bond must not change unlock-burn-height"
    );

    // 5) `unstake` from a bond holder must fail with `ERR_NOT_STAKING` (u27)
    test_observer::clear();
    let unstake_tx = make_contract_call(
        &staker_sk,
        3,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "unstake",
        &[Value::Principal(test_signer_principal.clone())],
    );
    let unstake_txid = submit_tx(&http_origin, &unstake_tx);
    info!("Submitted pox-5 unstake (bond holder) txid: {unstake_txid}");
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 4),
    )
    .expect("Timed out waiting for unstake from bond holder");

    let parsed = get_tx_result_by_id(&unstake_txid)
        .expect("Did not observe bond-holder unstake txid in test_observer");
    assert_eq!(
        parsed,
        Value::error(Value::UInt(27)).unwrap(),
        "unstake from a bond holder should fail with ERR_NOT_STAKING (u27)"
    );

    // The failed unstake must not have disturbed the existing bond lock.
    let after_unstake = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_unstake.locked, bond_amount,
        "failed bond-holder unstake must not change locked balance"
    );
    assert_eq!(
        after_unstake.unlock_height, register_unlock_height,
        "failed bond-holder unstake must not change unlock-burn-height"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);
    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// Verify a pox-5 staker can roll directly from bond index 0 into bond index 6
/// (the next contiguous bond — bond 6 starts the exact cycle bond 0 ends) with
/// no gap in the STX lock and no gap in signer participation. The second
/// `register-for-bond` happens during bond 0's tail gap window, so the
/// contract gate must permit the non-overlapping later bond and the node-side
/// `pox-locking` handler must carry the STX lock forward (extend) rather than
/// reject it as `PoxAlreadyLocked`. The sBTC is rolled forward via the new
/// netting path: with equal new/old amounts no FT transfer fires and
/// `total-sbtc-staked` is unchanged.
fn check_pox_5_register_for_second_bond_no_downtime() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    enable_epoch_4_0(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.burnchain.chain_id = CHAIN_ID_TESTNET + 1;
    let sender_sk = Secp256k1PrivateKey::random();
    let signer_sk = signers.signer_keys[0].clone();
    let signer_pk = StacksPublicKey::from_private(&signer_sk);
    let sender_signer_sk = signer_sk.clone();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);

    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 3000;
    let call_fee = 400;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        deploy_fee + call_fee * 10,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // sBTC stubs — both must be deployed before the epoch 4.0 transition so
    // pox-5's static analysis at boot finds the referenced contracts.
    let sbtc_deployer_sk = Secp256k1PrivateKey::random();
    let sbtc_deployer_addr = tests::to_addr(&sbtc_deployer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sbtc_deployer_addr.clone()).to_string(),
        2 * deploy_fee,
    );
    let sbtc_token_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-token").unwrap(),
    );
    let sbtc_registry_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-registry").unwrap(),
    );
    naka_conf.node.pox_5_sbtc_contract = Some(sbtc_token_id.clone());
    naka_conf.node.pox_5_sbtc_registry_contract = Some(sbtc_registry_id.clone());

    // Override the bond-admin so `setup-bond` is callable from the test.
    let bond_admin_sk = Secp256k1PrivateKey::random();
    let bond_admin_addr = tests::to_addr(&bond_admin_sk);
    // Two `setup-bond` calls (bond 0 and bond 6) each carry a 683-byte buffer
    // and a 1-entry allowlist; price each accordingly.
    let setup_bond_fee = 5000u64;
    naka_conf.add_initial_balance(
        PrincipalData::from(bond_admin_addr.clone()).to_string(),
        2 * setup_bond_fee + 1000,
    );
    naka_conf.node.pox_5_bond_admin = Some(PrincipalData::from(bond_admin_addr.clone()));

    let stacker_sk = setup_stacker(&mut naka_conf);
    let staker_sk = setup_stacker(&mut naka_conf);
    let staker_addr = tests::to_addr(&staker_sk);

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
        blocks_processed, ..
    } = run_loop.counters();
    let counters = run_loop.counters();
    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let pubkey_bytes: [u8; 33] = signer_pk
        .to_bytes_compressed()
        .try_into()
        .expect("compressed secp256k1 pubkey should be 33 bytes");
    boot_to_epoch_4_0(
        &naka_conf,
        &blocks_processed,
        &counters,
        &coord_channel,
        &[stacker_sk.clone()],
        &[sender_signer_sk],
        &[signer_sk.clone()],
        &sbtc_deployer_sk,
        Some(&pubkey_bytes),
        deploy_fee,
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );
    info!("Reached Epoch-4.0 boundary, deploying signer-manager and registering signer");

    let mut sender_nonce = 0;

    // Deploy the signer-manager contract.
    let signer_contract = pox5_signer_manager_source();
    let signer_deploy_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "test-signer",
        signer_contract,
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &signer_deploy_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for test-signer deploy");

    next_block_and_mine_commit(&mut btc_regtest_controller, 60, &naka_conf, &counters).unwrap();

    let test_signer_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from("test-signer").unwrap(),
    ));
    let auth_id: u128 = 1;
    let signer_grant_sig =
        stacks::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature(
            &test_signer_principal,
            auth_id,
            naka_conf.burnchain.chain_id,
            &signer_sk,
        )
        .expect("Failed to generate signer grant signature");
    let register_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "register-self",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            Value::UInt(auth_id),
            Value::buff_from(signer_grant_sig.to_rsv()).unwrap(),
        ],
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &register_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for register-self");

    let pox_5_id = boot_code_id("pox-5", false);
    let pox_5_addr: StacksAddress = pox_5_id.issuer.clone().into();

    // 1) `setup-bond(0)` from the configured bond admin. The staker's allowlist
    // entry sets the max sats they can register with.
    const SBTC_AMT: u128 = 1_000_000;
    let allowlist_entry = |staker: &StacksAddress, max_sats: u128| -> Value {
        Value::Tuple(
            clarity::vm::types::TupleData::from_data(vec![
                (
                    ClarityName::try_from("staker").unwrap(),
                    Value::Principal(staker.clone().into()),
                ),
                (
                    ClarityName::try_from("max-sats").unwrap(),
                    Value::UInt(max_sats),
                ),
            ])
            .unwrap(),
        )
    };
    let allowlist_value_bond0 =
        Value::cons_list_unsanitized(vec![allowlist_entry(&staker_addr, SBTC_AMT)]).unwrap();
    let setup_bond0_tx = make_contract_call(
        &bond_admin_sk,
        0,
        setup_bond_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "setup-bond",
        &[
            Value::UInt(0),
            Value::UInt(1000),
            Value::UInt(100),
            Value::UInt(10000),
            Value::buff_from(vec![0u8; 683]).unwrap(),
            Value::Principal(bond_admin_addr.clone().into()),
            allowlist_value_bond0,
        ],
    );
    submit_tx(&http_origin, &setup_bond0_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &bond_admin_addr).nonce == 1)
    })
    .expect("Timed out waiting for setup-bond(0)");

    // 2) Mint exactly `SBTC_AMT` sBTC: the rollover into bond 6 nets against
    // bond 0's custodied sBTC, so equal amounts means zero additional sBTC is
    // pulled from the staker.
    let mint_tx = make_contract_call(
        &staker_sk,
        0,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sbtc_deployer_addr,
        "sbtc-token",
        "mint",
        &[
            Value::UInt(SBTC_AMT),
            Value::Principal(staker_addr.clone().into()),
        ],
    );
    submit_tx(&http_origin, &mint_tx);
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 1),
    )
    .expect("Timed out waiting for sbtc mint");

    // 3) `register-for-bond(0)` via the sBTC path.
    let bond_amount = POX_DEFAULT_STACKER_STX_AMT;
    let staker_balance_before = get_account(&http_origin, &staker_addr).balance;
    assert!(staker_balance_before >= bond_amount + call_fee as u128 * 2);

    test_observer::clear();
    let register0_tx = make_contract_call(
        &staker_sk,
        1,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            Value::error(Value::UInt(SBTC_AMT)).unwrap(),
            Value::none(),
        ],
    );
    let register0_txid = submit_tx(&http_origin, &register0_tx);
    info!("Submitted pox-5 register-for-bond(0) txid: {register0_txid}");
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 2),
    )
    .expect("Timed out waiting for register-for-bond(0)");

    let parsed = get_tx_result_by_id(&register0_txid)
        .expect("did not observe register-for-bond(0) txid in test_observer");
    let response = parsed
        .expect_result()
        .expect("register-for-bond(0) response should be a clarity response");
    let ok_value = response.expect("register-for-bond(0) should have returned ok");
    let tuple = ok_value
        .expect_tuple()
        .expect("register-for-bond(0) ok payload should be a tuple");
    let bond0_unlock_height = tuple
        .get("unlock-burn-height")
        .expect("response missing unlock-burn-height")
        .clone()
        .expect_u128()
        .expect("unlock-burn-height should be a uint") as u64;

    let after_register0 = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_register0.locked, bond_amount,
        "register-for-bond(0) should have locked exactly {bond_amount} ustx"
    );
    assert_eq!(
        after_register0.unlock_height, bond0_unlock_height,
        "pox-locking should have applied bond 0's unlock-burn-height"
    );

    // Read the actual burn heights for bond 0 and bond 6 from the contract so
    // the test stays correct regardless of the boot-time cycle math.
    let read_bond_burn_height = |bond_index: u128| -> u64 {
        let resp = call_read_only(
            &naka_conf,
            &pox_5_addr,
            "pox-5",
            "bond-period-to-burn-height",
            vec![&Value::UInt(bond_index)],
        );
        resp.result()
            .expect("bond-period-to-burn-height read-only failed")
            .expect_u128()
            .expect("bond-period-to-burn-height should return a uint") as u64
    };
    let bond0_start = read_bond_burn_height(0);
    let bond6_start = read_bond_burn_height(6);
    let bond12_start = read_bond_burn_height(12);
    assert_eq!(
        bond0_unlock_height, bond6_start,
        "bond 0's STX unlock height should equal bond 6's start (the contiguous next bond)"
    );

    // Read bond 0's L1 unlock height: with the new rollover-window gate the
    // staker can't register for bond 6 until `burn >= get-bond-l1-unlock-height(0)`,
    // matching the window an L1 bond holder has to redirect their BTC.
    let bond0_l1_unlock = {
        let resp = call_read_only(
            &naka_conf,
            &pox_5_addr,
            "pox-5",
            "get-bond-l1-unlock-height",
            vec![&Value::UInt(0)],
        );
        resp.result()
            .expect("get-bond-l1-unlock-height read-only failed")
            .expect_u128()
            .expect("get-bond-l1-unlock-height returns uint") as u64
    };
    assert!(
        bond0_l1_unlock < bond6_start,
        "L1 unlock must precede bond 6's start so a window exists"
    );

    // 4) Mine forward into bond 6's gap window AND past bond 0's L1 unlock.
    // The STX lock must stay live throughout — every block's `locked` reads
    // `bond_amount`.
    let target_register_height = bond0_l1_unlock;
    info!(
        "Mining from bond0_start={bond0_start} to bond0_l1_unlock={bond0_l1_unlock} (rollover window opens; bond6_start={bond6_start})"
    );
    loop {
        let blocks_before = test_observer::get_blocks().len();
        next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 60, &coord_channel)
            .unwrap();
        wait_for(30, || Ok(test_observer::get_blocks().len() > blocks_before))
            .expect("Timed out waiting for observer to process new block");
        let mid_account = get_account(&http_origin, &staker_addr);
        assert_eq!(
            mid_account.locked, bond_amount,
            "STX lock must remain in place through bond 0's full term (no unlock before rollover)"
        );
        let last_block = test_observer::get_blocks();
        let burn_height = last_block
            .last()
            .unwrap()
            .get("burn_block_height")
            .unwrap()
            .as_u64()
            .unwrap();
        if burn_height >= target_register_height {
            assert!(
                burn_height < bond6_start,
                "must register for bond 6 before bond 6 starts (burn={burn_height}, bond6_start={bond6_start})"
            );
            break;
        }
    }

    // 5) `setup-bond(6)` from the admin, then `register-for-bond(6)`. Same
    // sBTC amount: `roll-sbtc` should be a no-op (no FT transfer), and the
    // STX lock should be carried forward to bond 6's unlock height.
    let allowlist_value_bond6 =
        Value::cons_list_unsanitized(vec![allowlist_entry(&staker_addr, SBTC_AMT)]).unwrap();
    let setup_bond6_tx = make_contract_call(
        &bond_admin_sk,
        1,
        setup_bond_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "setup-bond",
        &[
            Value::UInt(6),
            Value::UInt(1000),
            Value::UInt(100),
            Value::UInt(10000),
            Value::buff_from(vec![0u8; 683]).unwrap(),
            Value::Principal(bond_admin_addr.clone().into()),
            allowlist_value_bond6,
        ],
    );
    submit_tx(&http_origin, &setup_bond6_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &bond_admin_addr).nonce == 2)
    })
    .expect("Timed out waiting for setup-bond(6)");

    let sbtc_staked_before_roll = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-total-sbtc-staked",
        vec![],
    )
    .result()
    .expect("get-total-sbtc-staked failed")
    .expect_u128()
    .expect("get-total-sbtc-staked returns uint");
    assert_eq!(
        sbtc_staked_before_roll, SBTC_AMT,
        "bond 0's sBTC should be the only custodied sBTC before the roll"
    );

    test_observer::clear();
    let register6_tx = make_contract_call(
        &staker_sk,
        2,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(6),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            Value::error(Value::UInt(SBTC_AMT)).unwrap(),
            Value::none(),
        ],
    );
    let register6_txid = submit_tx(&http_origin, &register6_tx);
    info!("Submitted pox-5 register-for-bond(6) txid: {register6_txid}");
    wait_for(
        60,
        || Ok(get_account(&http_origin, &staker_addr).nonce == 3),
    )
    .expect("Timed out waiting for register-for-bond(6)");

    let parsed = get_tx_result_by_id(&register6_txid)
        .expect("did not observe register-for-bond(6) txid in test_observer");
    let response = parsed
        .expect_result()
        .expect("register-for-bond(6) response should be a clarity response");
    let ok_value = response.expect("register-for-bond(6) should have returned ok");
    let tuple = ok_value
        .expect_tuple()
        .expect("register-for-bond(6) ok payload should be a tuple");
    let bond6_unlock_height = tuple
        .get("unlock-burn-height")
        .expect("response missing unlock-burn-height")
        .clone()
        .expect_u128()
        .expect("unlock-burn-height should be a uint") as u64;
    assert_eq!(
        bond6_unlock_height, bond12_start,
        "bond 6's STX unlock height should equal bond 12's start"
    );

    let after_register6 = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_register6.locked, bond_amount,
        "register-for-bond(6) must keep the STX locked (no release during rollover)"
    );
    assert_eq!(
        after_register6.unlock_height, bond6_unlock_height,
        "pox-locking should have extended the lock to bond 6's unlock height"
    );

    // sBTC: equal amounts → no net transfer; `total-sbtc-staked` unchanged.
    let sbtc_staked_after_roll = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-total-sbtc-staked",
        vec![],
    )
    .result()
    .expect("get-total-sbtc-staked failed")
    .expect_u128()
    .expect("get-total-sbtc-staked returns uint");
    assert_eq!(
        sbtc_staked_after_roll, SBTC_AMT,
        "equal-amount rollover must not change total-sbtc-staked"
    );
    let staker_sbtc_after = call_read_only(
        &naka_conf,
        &sbtc_deployer_addr,
        "sbtc-token",
        "get-balance",
        vec![&Value::Principal(staker_addr.clone().into())],
    )
    .result()
    .expect("sbtc get-balance failed")
    .expect_result_ok()
    .expect("sbtc get-balance should be (ok uint)")
    .expect_u128()
    .expect("sbtc get-balance returns uint");
    assert_eq!(
        staker_sbtc_after, 0,
        "equal-amount rollover should leave the staker's sBTC balance unchanged at 0"
    );

    // Membership is now bond 6.
    let membership_value = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-bond-membership",
        vec![&Value::Principal(staker_addr.clone().into())],
    )
    .result()
    .expect("get-bond-membership failed")
    .expect_optional()
    .expect("get-bond-membership returns optional")
    .expect("membership should be Some after registration");
    let membership_tuple = membership_value
        .expect_tuple()
        .expect("membership should be a tuple");
    let current_bond_index = membership_tuple
        .get("bond-index")
        .expect("missing bond-index")
        .clone()
        .expect_u128()
        .expect("bond-index uint");
    assert_eq!(
        current_bond_index, 6,
        "post-rollover membership should point at bond 6"
    );

    // Bond 0's reward shares are preserved (the staker still earns through
    // bond 0's term).
    let bond0_shares = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-staker-shares-staked-for-cycle",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::Bool(true),
            &Value::UInt(0),
            &Value::Principal(test_signer_principal.clone()),
        ],
    )
    .result()
    .expect("get-staker-shares-staked-for-cycle failed")
    .expect_u128()
    .expect("shares uint");
    assert_eq!(
        bond0_shares, SBTC_AMT,
        "bond 0's reward shares must be preserved through the roll-over"
    );

    // Continuous signer participation across the bond boundary: the staker is
    // in the signer set for cycles C+11 (last of bond 0) and C+12 (first of
    // bond 6).
    let bond6_first_cycle = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "bond-period-to-reward-cycle",
        vec![&Value::UInt(6)],
    )
    .result()
    .expect("bond-period-to-reward-cycle failed")
    .expect_u128()
    .expect("cycle uint");
    let last_bond0_cycle = bond6_first_cycle - 1;
    for cycle in [last_bond0_cycle, bond6_first_cycle] {
        let cycle_member = call_read_only(
            &naka_conf,
            &pox_5_addr,
            "pox-5",
            "get-signer-cycle-membership",
            vec![
                &Value::Principal(staker_addr.clone().into()),
                &Value::UInt(cycle),
            ],
        )
        .result()
        .expect("get-signer-cycle-membership failed")
        .expect_optional()
        .expect("get-signer-cycle-membership returns optional");
        assert!(
            cycle_member.is_some(),
            "staker must be a signer-set member in cycle {cycle} (no participation gap)"
        );
    }

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);
    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// Verify the pox-5 bond lifecycle end-to-end using the L1 BTC lockup path.
///
/// The test broadcasts a *real* Bitcoin transaction that locks
/// `BTC_LOCKUP_SATS` sats into the canonical timelock P2WSH and then
/// calls `register-for-bond` with those lockup details.
///
/// The test:
///   1. Stands up a side wallet `pox5-l1-bondholder` with private
///      keys enabled, then funds it from the miner.
///   2. Computes the expected P2WSH by calling pox-5's own
///      `construct-lockup-output-script` as a read-only, derives the
///      bech32 regtest address, and `bondholder_rpc.send_to_address`s
///      the lockup payment from the bondholder wallet.
///   3. Calls `generateblock(coinbase, &[our_txid])` so the resulting
///      block has exactly `[coinbase, lockup_tx]` — `tx_count=2`,
///      `tx_index=1`, and `siblings=[coinbase_txid_internal]` make the
///      merkle proof trivial to assemble.
///   4. Pulls the actual 80-byte header and the canonical txid order
///      back out of bitcoind and feeds the lockup tuple into
///      `register-for-bond`.
///
/// Assertions:
/// - submitting the same lockup outpoint three times in the L1 proof list
///   is rejected with `ERR_DUPLICATE_LOCKUP_OUTPOINT` (u46) — the per-output
///   dedup inside `validate-l1-lockup` trips before the post-fold sum check,
///   and the failure leaves the staker with no bond membership and no STX lock
/// - the honest single-output proof still registers (guards against
///   too-aggressive dedup)
/// - STX is locked, with unlock height set to the bond's unlock-burn-height
/// - the bond membership records `is-l1-lock: true` (the membership reads
///   `(is-ok btc-lockup)`)
/// - the staker's sBTC balance is unchanged (no sBTC `ft-transfer?` runs
///   on the L1 path)
/// - a second `register-for-bond` from the same staker fails with
///   `ERR_ALREADY_REGISTERED` (u9) and does not perturb the existing lock
/// - after the on-chain timelock matures, the locked BTC is spendable
///   *only* by the owner
fn check_pox_5_register_for_bond_l1_lockup_lifecycle() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    enable_epoch_4_0(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.burnchain.chain_id = CHAIN_ID_TESTNET + 1;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_signer_sk = Secp256k1PrivateKey::random();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);

    let signer_sk = signers.signer_keys[0].clone();
    let signer_pk = StacksPublicKey::from_private(&signer_sk);

    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 3000;
    let call_fee = 400;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        deploy_fee + call_fee * 10,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // sBTC stub — pox-5 boot needs the stub deployed before the epoch 4.0
    // transition for static analysis to find the referenced contract.
    // Even on the L1 path we deploy it so the boot succeeds; we just never
    // mint to the staker, and the test asserts the staker's sBTC balance
    // never changes.
    let sbtc_deployer_sk = Secp256k1PrivateKey::random();
    let sbtc_deployer_addr = tests::to_addr(&sbtc_deployer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sbtc_deployer_addr.clone()).to_string(),
        deploy_fee,
    );
    let sbtc_token_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-token").unwrap(),
    );
    naka_conf.node.pox_5_sbtc_contract = Some(sbtc_token_id.clone());

    // The pox-5 boot contract initializes its `bond-admin` data var to
    // `tx-sender`, which at boot deploy time is the unsignable boot
    // principal. Override it to a key we control so that `setup-bond` is
    // callable from the test (forbidden on mainnet).
    let bond_admin_sk = Secp256k1PrivateKey::random();
    let bond_admin_addr = tests::to_addr(&bond_admin_sk);
    let setup_bond_fee = 5000u64;
    naka_conf.add_initial_balance(
        PrincipalData::from(bond_admin_addr.clone()).to_string(),
        setup_bond_fee + 1000,
    );
    naka_conf.node.pox_5_bond_admin = Some(PrincipalData::from(bond_admin_addr.clone()));

    let stacker_sk = setup_stacker(&mut naka_conf);
    let staker_sk = setup_stacker(&mut naka_conf);
    let staker_addr = tests::to_addr(&staker_sk);

    test_observer::spawn();
    test_observer::register_any(&mut naka_conf);

    let mut btcd_controller = BitcoinCoreController::from_stx_config(&naka_conf);
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    // The L1 lockup tx is broadcast by a separate bondholder wallet, which
    // needs its own spendable Bitcoin. We seed that wallet now by paying it
    // from the miner, then mining one block to confirm.
    const BONDHOLDER_WALLET: &str = "pox5-l1-bondholder";
    let bondholder_rpc =
        crate::burnchains::rpc::bitcoin_rpc_client::BitcoinRpcClient::from_stx_config(&naka_conf)
            .expect("failed to construct bondholder RPC client");
    bondholder_rpc
        .create_wallet(BONDHOLDER_WALLET, Some(false))
        .expect("create bondholder wallet");
    let bondholder_addr = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress on bondholder wallet");
    // 2_000_000 sats = 0.02 BTC: comfortably covers the 1_000_000-sat
    // P2WSH lockup plus the fee for the subsequent `send_to_address`.
    const BONDHOLDER_FUNDING_SATS: u64 = 2_000_000;
    let miner_keychain = Keychain::default(naka_conf.node.seed.clone());
    let mut miner_op_signer = miner_keychain.generate_op_signer();
    btc_regtest_controller
        .send_btc(
            StacksEpochId::Epoch21,
            &mut miner_op_signer,
            &bondholder_addr,
            BONDHOLDER_FUNDING_SATS,
        )
        .expect("send_btc miner → bondholder");
    btc_regtest_controller.build_next_block(1);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed, ..
    } = run_loop.counters();
    let counters = run_loop.counters();
    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    boot_to_epoch_4_0(
        &naka_conf,
        &blocks_processed,
        &counters,
        &coord_channel,
        &[stacker_sk.clone()],
        &[sender_signer_sk],
        &[signer_sk.clone()],
        &sbtc_deployer_sk,
        None,
        deploy_fee,
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );
    info!("Reached Epoch-4.0 boundary, deploying signer-manager and registering signer");

    let mut sender_nonce = 0;

    // Deploy the signer-manager contract.
    let signer_contract = pox5_signer_manager_source();
    let signer_deploy_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "test-signer",
        signer_contract,
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &signer_deploy_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for test-signer deploy");

    next_block_and_mine_commit(&mut btc_regtest_controller, 60, &naka_conf, &counters).unwrap();

    let test_signer_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from("test-signer").unwrap(),
    ));
    let auth_id: u128 = 1;
    let signer_grant_sig =
        stacks::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature(
            &test_signer_principal,
            auth_id,
            naka_conf.burnchain.chain_id,
            &signer_sk,
        )
        .expect("Failed to generate signer grant signature");
    let register_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "register-self",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            Value::UInt(auth_id),
            Value::buff_from(signer_grant_sig.to_rsv()).unwrap(),
        ],
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &register_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for register-self");

    let pox_5_id = boot_code_id("pox-5", false);
    let pox_5_addr: StacksAddress = pox_5_id.issuer.clone().into();

    // 1) `setup-bond` from the configured bond admin. Allowlist the staker
    // for `BTC_LOCKUP_SATS` sats. With `stx-value-ratio = 100` and
    // `min-ustx-ratio = 10000` (== 100% in basis points),
    // `min-ustx-for-sats-amount(BTC_LOCKUP_SATS, 100, 10000) = BTC_LOCKUP_SATS`
    // ustx, so any `amount-ustx >= BTC_LOCKUP_SATS` clears the bond's STX
    // floor.
    //
    // For `early-unlock-bytes` we use 32 bytes of `0x61` (OP_NOP),
    // which parse cleanly as no-ops. The OP_ELSE branch they end up in
    // isn't exercised by this test, so their runtime semantics don't
    // matter — they only contribute to the P2WSH hash.
    const BTC_LOCKUP_SATS: u128 = 1_000_000;
    let early_unlock_bytes = vec![0x61u8; 32];
    let allowlist_entry = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("staker").unwrap(),
                Value::Principal(staker_addr.clone().into()),
            ),
            (
                ClarityName::try_from("max-sats").unwrap(),
                Value::UInt(BTC_LOCKUP_SATS),
            ),
        ])
        .unwrap(),
    );
    let allowlist_value = Value::cons_list_unsanitized(vec![allowlist_entry]).unwrap();
    let setup_bond_tx = make_contract_call(
        &bond_admin_sk,
        0,
        setup_bond_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "setup-bond",
        &[
            Value::UInt(0),
            Value::UInt(1000),
            Value::UInt(100),
            Value::UInt(10000),
            Value::buff_from(early_unlock_bytes.clone()).unwrap(),
            Value::Principal(bond_admin_addr.clone().into()),
            allowlist_value,
        ],
    );
    let setup_bond_txid = submit_tx(&http_origin, &setup_bond_tx);
    info!("Submitted pox-5 setup-bond (L1 test) txid: {setup_bond_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &bond_admin_addr).nonce == 1)
    })
    .expect("Timed out waiting for setup-bond");

    // 2) Build a real L1 lockup proof for `register-for-bond`'s
    // `(ok { outputs, staker-unlock-bytes })` branch.
    //
    // `staker-unlock-bytes` is the Bitcoin Script subscript the OP_IF
    // (timelock-matured) branch of `construct-lockup-script` executes
    // after CLTV. We make it a `<pubkey> OP_CHECKSIG` fragment so the
    // spend is gated on a real signature from `staker_unlock_sk`. The
    // encoding is `<push 33> <compressed pubkey> <OP_CHECKSIG>` =
    // `[0x21, …33 bytes…, 0xac]`, 35 bytes total.
    let staker_unlock_sk = Secp256k1PrivateKey::random();
    let staker_unlock_pk = Secp256k1PublicKey::from_private(&staker_unlock_sk);
    let staker_unlock_pk_bytes = staker_unlock_pk.to_bytes_compressed();
    assert_eq!(
        staker_unlock_pk_bytes.len(),
        33,
        "compressed secp pubkey should be 33 bytes"
    );
    let mut lockup_unlock_bytes = Vec::with_capacity(1 + 33 + 1);
    lockup_unlock_bytes.push(0x21); // OP_PUSHBYTES_33
    lockup_unlock_bytes.extend_from_slice(&staker_unlock_pk_bytes);
    lockup_unlock_bytes.push(0xac); // OP_CHECKSIG

    // (a) Compute the expected P2WSH script-pubkey by calling pox-5's own
    //     read-only `construct-lockup-output-script` — this returns the
    //     34-byte `0x0020 || sha256(timelock_script)` that the burn-chain
    //     output must pay to. We hand the same arguments the contract will
    //     reconstruct internally during `verify-l1-lockups`.
    let bond_index = 0u128;
    let unlock_burn_height = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-bond-l1-unlock-height",
        vec![&Value::UInt(bond_index)],
    )
    .result()
    .expect("get-bond-l1-unlock-height failed")
    .expect_u128()
    .expect("get-bond-l1-unlock-height should return a uint");
    let expected_script_buff = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "construct-lockup-output-script",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::UInt(unlock_burn_height),
            &Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            &Value::buff_from(early_unlock_bytes.clone()).unwrap(),
        ],
    )
    .result()
    .expect("construct-lockup-output-script failed")
    .expect_buff(34)
    .expect("construct-lockup-output-script should return (buff 34)");
    assert_eq!(
        &expected_script_buff[0..2],
        &[0x00, 0x20],
        "lockup output script is supposed to be a SegWit V0 P2WSH push (0x00 0x20 || hash)"
    );
    let mut witness_script_hash = [0u8; 32];
    witness_script_hash.copy_from_slice(&expected_script_buff[2..]);

    let p2wsh_addr = stacks::burnchains::bitcoin::address::BitcoinAddress::Segwit(
        stacks::burnchains::bitcoin::address::SegwitBitcoinAddress::P2WSH(
            stacks::burnchains::bitcoin::BitcoinNetworkType::Regtest,
            witness_script_hash,
        ),
    );
    info!(
        "Lockup P2WSH derived from construct-lockup-output-script: {}",
        &p2wsh_addr
    );

    // (b) Broadcast a tx from the bondholder wallet to the P2WSH address.
    //     This puts the tx into bitcoind's mempool; we then ask
    //     `generateblock` to mine a block whose non-coinbase txs are
    //     exactly `[our_txid]`, so the resulting block has a fully-known
    //     shape: coinbase at index 0, our P2WSH tx at index 1,
    //     tx_count = 2.
    let lockup_btc_amount = 0.01_f64; // 1_000_000 sats
    let p2wsh_txid = bondholder_rpc
        .send_to_address(BONDHOLDER_WALLET, &p2wsh_addr, lockup_btc_amount)
        .expect("send_to_address into lockup P2WSH");
    info!("Sent {lockup_btc_amount} BTC to lockup P2WSH; txid={p2wsh_txid}");

    let coinbase_recipient = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress for generateblock coinbase");
    let pre_register_burn_height = get_chain_info_result(&naka_conf).unwrap().burn_block_height;
    let lockup_block_hash = bondholder_rpc
        .generate_block(&coinbase_recipient, &[&p2wsh_txid.to_hex()])
        .expect("generateblock with lockup tx");
    info!("Mined lockup tx into block {lockup_block_hash}");

    // (c) Wait for the Stacks node to ingest the new burn block so that
    //     `get-burn-block-info? header-hash <height>` will return Some.
    wait_for(60, || {
        Ok(get_chain_info_result(&naka_conf).unwrap().burn_block_height > pre_register_burn_height)
    })
    .expect("Stacks node did not ingest the lockup burn block");
    let lockup_burn_height = get_chain_info_result(&naka_conf).unwrap().burn_block_height;
    info!("Stacks node observed lockup burn block; burn_block_height = {lockup_burn_height}");

    // (d) Reconstruct the raw tx, pinpoint the P2WSH output index, and
    //     read out the actual lockup amount the contract will check against
    //     `(get amount lockup)`.
    let lockup_tx_struct = bondholder_rpc
        .get_raw_transaction(&p2wsh_txid)
        .expect("getrawtransaction for lockup tx");
    let lockup_tx_hex =
        stacks_common::deps_common::bitcoin::network::serialize::serialize_hex(&lockup_tx_struct)
            .expect("serialize_hex(lockup_tx)");
    let lockup_tx_bytes = hex_bytes(&lockup_tx_hex).expect("decode lockup_tx hex");
    let (lockup_output_index, lockup_output_amount) = lockup_tx_struct
        .output
        .iter()
        .enumerate()
        .find_map(|(idx, out)| {
            let script = out.script_pubkey.as_bytes();
            if script.len() == 34
                && script[..2] == [0x00, 0x20]
                && script[2..] == witness_script_hash
            {
                Some((idx, out.value))
            } else {
                None
            }
        })
        .expect("lockup tx must contain a P2WSH output matching the expected script");
    info!(
        "Lockup tx output index {lockup_output_index} (= {lockup_output_amount} sats) is the timelock P2WSH"
    );
    assert_eq!(
        lockup_output_amount,
        u64::try_from(BTC_LOCKUP_SATS).unwrap(),
        "send_to_address moved exactly {BTC_LOCKUP_SATS} sats into the P2WSH"
    );

    // (e) Pull the actual 80-byte block header and the txid ordering so we
    //     can build a real merkle proof. `verify-merkle-proof` consumes
    //     internal-byte-order hashes; bitcoind's getblock returns
    //     display-order, so reverse.
    let header_hex = bondholder_rpc
        .get_block_header_hex(&lockup_block_hash)
        .expect("getblockheader for lockup block");
    let lockup_header_bytes = hex_bytes(&header_hex).expect("decode header hex");
    assert_eq!(
        lockup_header_bytes.len(),
        80,
        "Bitcoin block header is always 80 bytes"
    );
    let block_txids_display = bondholder_rpc
        .get_block_txids(&lockup_block_hash)
        .expect("getblock for lockup block txids");
    assert_eq!(
        block_txids_display.len(),
        2,
        "lockup block should contain exactly coinbase + lockup tx; got {} txs",
        block_txids_display.len()
    );
    // bitcoind always orders the coinbase first.
    let mut coinbase_txid_internal: [u8; 32] = block_txids_display[0].as_bytes().clone();
    coinbase_txid_internal.reverse();
    let mut lockup_txid_display: [u8; 32] = block_txids_display[1].as_bytes().clone();
    assert_eq!(
        block_txids_display[1].to_hex(),
        p2wsh_txid.to_hex(),
        "lockup tx must be the non-coinbase entry in the generated block",
    );
    lockup_txid_display.reverse(); // unused beyond the sanity check, but keeps intent obvious

    // (f) Assemble the lockup tuple.
    let lockup_output = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("height").unwrap(),
                Value::UInt(lockup_burn_height as u128),
            ),
            (
                ClarityName::try_from("tx").unwrap(),
                Value::buff_from(lockup_tx_bytes).unwrap(),
            ),
            (
                ClarityName::try_from("output-index").unwrap(),
                Value::UInt(lockup_output_index as u128),
            ),
            (
                ClarityName::try_from("header").unwrap(),
                Value::buff_from(lockup_header_bytes).unwrap(),
            ),
            (
                ClarityName::try_from("leaf-hashes").unwrap(),
                Value::cons_list_unsanitized(vec![Value::buff_from(
                    coinbase_txid_internal.to_vec(),
                )
                .unwrap()])
                .unwrap(),
            ),
            (ClarityName::try_from("tx-count").unwrap(), Value::UInt(2)),
            (ClarityName::try_from("tx-index").unwrap(), Value::UInt(1)),
            (
                ClarityName::try_from("amount").unwrap(),
                Value::UInt(u128::from(lockup_output_amount)),
            ),
        ])
        .unwrap(),
    );
    let lockup_tuple = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("outputs").unwrap(),
                Value::cons_list_unsanitized(vec![lockup_output.clone()]).unwrap(),
            ),
            (
                ClarityName::try_from("staker-unlock-bytes").unwrap(),
                Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            ),
        ])
        .unwrap(),
    );
    let l1_lockup_arg = Value::okay(lockup_tuple).expect("failed to wrap lockup tuple in (ok ...)");

    let register_fee = 2000u64;
    let bond_amount = POX_DEFAULT_STACKER_STX_AMT;
    let staker_balance_before = get_account(&http_origin, &staker_addr).balance;
    // 3 register attempts: dup-outpoint rejection, happy path, ERR_ALREADY_REGISTERED.
    assert!(staker_balance_before >= bond_amount + register_fee as u128 * 3);

    let sbtc_balance_before = sbtc_balance(&naka_conf, &sbtc_deployer_addr, &staker_addr);

    // 3) Submitting the same lockup outpoint multiple times in the L1 proof
    //    list must be rejected by `validate-l1-lockup`'s per-output dedup
    //    with `ERR_DUPLICATE_LOCKUP_OUTPOINT` (u46). The dedup check sits
    //    *inside* the fold, so it trips before the post-fold sum check
    //    would otherwise notice that 3 * BTC_LOCKUP_SATS exceeds the
    //    allowlist's `max-sats`. Asserting `u46` (not the sum error `u10`)
    //    proves the dedup is what caught the attack.
    let dup_lockup_tuple = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("outputs").unwrap(),
                Value::cons_list_unsanitized(vec![
                    lockup_output.clone(),
                    lockup_output.clone(),
                    lockup_output,
                ])
                .unwrap(),
            ),
            (
                ClarityName::try_from("staker-unlock-bytes").unwrap(),
                Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            ),
        ])
        .unwrap(),
    );
    let l1_dup_lockup_arg =
        Value::okay(dup_lockup_tuple).expect("failed to wrap dup lockup tuple in (ok ...)");

    test_observer::clear();
    let dup_outpoint_tx = make_contract_call(
        &staker_sk,
        0,
        register_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            l1_dup_lockup_arg,
            Value::none(),
        ],
    );
    let dup_outpoint_txid = submit_tx(&http_origin, &dup_outpoint_tx);
    info!("Submitted triplicate-outpoint pox-5 register-for-bond (L1) txid: {dup_outpoint_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &staker_addr).nonce == 1
            && get_tx_result_by_id(&dup_outpoint_txid).is_some())
    })
    .expect("Timed out waiting for triplicate-outpoint register-for-bond (L1)");

    let parsed = get_tx_result_by_id(&dup_outpoint_txid)
        .expect("Did not observe triplicate-outpoint register-for-bond txid in test_observer");
    assert_eq!(
        parsed,
        Value::error(Value::UInt(46)).unwrap(),
        "triplicate-outpoint register-for-bond (L1) should fail with \
         ERR_DUPLICATE_LOCKUP_OUTPOINT (u46), not the post-fold sum error",
    );

    // The failed call must not have produced any bond state: no membership
    // row, no STX lock.
    let no_membership = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-bond-membership",
        vec![&Value::Principal(staker_addr.clone().into())],
    )
    .result()
    .expect("get-bond-membership read failed")
    .expect_optional()
    .expect("get-bond-membership response should be (optional ...)");
    assert!(
        no_membership.is_none(),
        "triplicate-outpoint failure must not create a bond membership; got {no_membership:?}"
    );
    let after_dup_outpoint = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_dup_outpoint.locked, 0,
        "triplicate-outpoint failure must not lock staker STX"
    );

    // 4) `register-for-bond` via the L1 lockup branch — the honest
    //    single-output proof must still succeed. This guards against a
    //    too-aggressive dedup that would also break the happy path.
    test_observer::clear();
    let register_tx = make_contract_call(
        &staker_sk,
        1,
        register_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            l1_lockup_arg.clone(),
            Value::none(),
        ],
    );
    let register_txid = submit_tx(&http_origin, &register_tx);
    info!("Submitted pox-5 register-for-bond (L1 lockup) txid: {register_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &staker_addr).nonce == 2
            && get_tx_result_by_id(&register_txid).is_some())
    })
    .expect("Timed out waiting for register-for-bond (L1)");

    // Pull `unlock-burn-height` out of the register-for-bond response so
    // we can assert pox-locking applied the expected unlock to the
    // staker's STX.
    let parsed = get_tx_result_by_id(&register_txid)
        .expect("did not observe register-for-bond txid in test_observer");
    let response = parsed
        .expect_result()
        .expect("register-for-bond response should be a clarity response");
    let ok_value = response.expect("register-for-bond (L1) should have returned ok");
    let tuple = ok_value
        .expect_tuple()
        .expect("register-for-bond ok payload should be a tuple");
    let register_unlock_height = tuple
        .get("unlock-burn-height")
        .expect("register-for-bond response missing unlock-burn-height")
        .clone()
        .expect_u128()
        .expect("unlock-burn-height should be a uint") as u64;

    let after_register = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_register.locked, bond_amount,
        "register-for-bond (L1) should have locked exactly {bond_amount} ustx"
    );
    assert_eq!(
        after_register.unlock_height, register_unlock_height,
        "pox-locking should have applied the bond's unlock-burn-height"
    );

    // L1 path must not move sBTC; we never minted to the staker, but assert
    // explicitly to catch a regression where the contract takes the wrong
    // branch and silently runs `lock-sbtc`.
    let sbtc_balance_after = sbtc_balance(&naka_conf, &sbtc_deployer_addr, &staker_addr);
    assert_eq!(
        sbtc_balance_after, sbtc_balance_before,
        "L1 lockup branch must not change the staker's sBTC balance \
         (before={sbtc_balance_before}, after={sbtc_balance_after})",
    );

    // The bond membership row must record `is-l1-lock: true` so future
    // `announce-l1-early-exit` calls dispatch correctly.
    let membership = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-bond-membership",
        vec![&Value::Principal(staker_addr.clone().into())],
    )
    .result()
    .expect("get-bond-membership read failed");
    let is_l1_lock = membership
        .expect_optional()
        .expect("get-bond-membership response should be (optional ...)")
        .expect("staker should have a bond membership after register-for-bond")
        .expect_tuple()
        .expect("bond membership should be a tuple")
        .get("is-l1-lock")
        .expect("bond membership missing `is-l1-lock` field")
        .clone()
        .expect_bool()
        .expect("`is-l1-lock` should be a bool");
    assert!(
        is_l1_lock,
        "bond membership must record `is-l1-lock: true` for the L1 lockup branch",
    );

    // 5) A second `register-for-bond` from the same staker via the L1 path
    // must still fail with `ERR_ALREADY_REGISTERED` (u9) — the duplicate
    // check sits after `verify-l1-lockups` runs.
    test_observer::clear();
    let dup_tx = make_contract_call(
        &staker_sk,
        2,
        register_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            l1_lockup_arg,
            Value::none(),
        ],
    );
    let dup_txid = submit_tx(&http_origin, &dup_tx);
    info!("Submitted duplicate pox-5 register-for-bond (L1) txid: {dup_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &staker_addr).nonce == 3
            && get_tx_result_by_id(&dup_txid).is_some())
    })
    .expect("Timed out waiting for duplicate register-for-bond (L1)");

    let parsed = get_tx_result_by_id(&dup_txid)
        .expect("Did not observe duplicate register-for-bond txid in test_observer");
    assert_eq!(
        parsed,
        Value::error(Value::UInt(9)).unwrap(),
        "duplicate register-for-bond (L1) should fail with ERR_ALREADY_REGISTERED (u9)"
    );

    // The duplicate failure must not have disturbed the existing lock.
    let after_dup = get_account(&http_origin, &staker_addr);
    assert_eq!(
        after_dup.locked, bond_amount,
        "failed duplicate register-for-bond must not change locked balance"
    );
    assert_eq!(
        after_dup.unlock_height, register_unlock_height,
        "failed duplicate register-for-bond must not change unlock-burn-height"
    );

    // 6) Spend the L1 lockup once the on-chain timelock matures.
    //
    // The previous steps put `BTC_LOCKUP_SATS` into the canonical
    // timelock P2WSH whose witness program is
    // `sha256(construct-lockup-script(staker, unlock_burn_height,
    // lockup_unlock_bytes, early_unlock_bytes))`. Bitcoin will accept
    // a spend of that UTXO once:
    //   - the tx's `nLockTime >= unlock_burn_height` (so the
    //     `OP_CHECKLOCKTIMEVERIFY` in the OP_IF branch passes),
    //   - the spending block's height is also `>= nLockTime` (mempool's
    //     non-final-tx check), AND
    //   - the shared-tail `<staker_unlock_pk> OP_CHECKSIG` (the
    //     `staker-unlock-bytes` subscript that runs after the OP_IF branch's
    //     CLTV leaves its value for the shared OP_VERIFY) accepts a
    //     witness signature for the spend's BIP-143 sighash.
    //
    // We test both halves of that owner check:
    //   (a) an *interloper* signs the spend with a fresh, random key
    //       and tries to broadcast — Bitcoin must reject, because
    //       OP_CHECKSIG on `staker_unlock_pk` won't accept their sig.
    //   (b) the *owner* (the entity holding `staker_unlock_sk`) signs
    //       and broadcasts — Bitcoin accepts; the UTXO drains into a
    //       bondholder-controlled address.

    // Fetch the canonical script bytes from pox-5 itself so the
    // sha256(witness_last) we hand bitcoind matches exactly what pox-5
    // derived the P2WSH from.
    let timelock_script = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "construct-lockup-script",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::UInt(unlock_burn_height),
            &Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            &Value::buff_from(early_unlock_bytes.clone()).unwrap(),
        ],
    )
    .result()
    .expect("construct-lockup-script failed")
    .expect_buff(usize::MAX)
    .expect("construct-lockup-script should return a buff");

    // Stop the Stacks side: the rest of this test only drives bitcoind
    // directly to advance the burn chain past the timelock, and we don't
    // want the Stacks miner trying to keep pace with that.
    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);
    run_loop_thread.join().unwrap();

    // The sweep tx pays its output to a freshly generated bondholder
    // address (so the wallet recognises the output as its own and we
    // can assert the sweep landed via `gettransaction`).
    let sweep_dest_addr = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress for sweep destination");
    let sweep_dest_hash20 = match &sweep_dest_addr {
        stacks::burnchains::bitcoin::address::BitcoinAddress::Segwit(
            stacks::burnchains::bitcoin::address::SegwitBitcoinAddress::P2WPKH(_, h),
        ) => *h,
        other => panic!("expected P2WPKH bech32 sweep address, got {other:?}"),
    };

    // Mine empty Bitcoin blocks until the chain is past `unlock_burn_height`.
    // The +1 makes sure the block that *includes* our sweep also lands at
    // height >= nLockTime, which mempool requires for non-final txs.
    let pre_sweep_btc_height = bondholder_rpc
        .get_blockchain_info()
        .expect("getblockchaininfo")
        .blocks;
    let filler_addr = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress for filler coinbase");
    let unlock_burn_height_u64 =
        u64::try_from(unlock_burn_height).expect("unlock_burn_height fits in u64");
    let blocks_to_mine = (unlock_burn_height_u64 + 1).saturating_sub(pre_sweep_btc_height);
    if blocks_to_mine > 0 {
        bondholder_rpc
            .generate_to_address(blocks_to_mine, &filler_addr)
            .expect("advance bitcoin past unlock_burn_height");
    }
    info!(
        "Bitcoin chain advanced past L1 unlock height; mined {blocks_to_mine} \
         filler blocks (pre={pre_sweep_btc_height}, unlock={unlock_burn_height_u64})"
    );

    // Build a (signed) sweep tx for an arbitrary signer.
    const SWEEP_FEE_SATS: u64 = 1_000;
    assert!(
        lockup_output_amount > SWEEP_FEE_SATS,
        "lockup output {lockup_output_amount} sats must cover SWEEP_FEE_SATS={SWEEP_FEE_SATS}",
    );
    let sweep_value = lockup_output_amount - SWEEP_FEE_SATS;
    let build_signed_sweep = |signer_sk: &Secp256k1PrivateKey| -> stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction {
        let mut tx = stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: u32::try_from(unlock_burn_height).expect("unlock_burn_height fits in u32"),
            input: vec![
                stacks_common::deps_common::bitcoin::blockdata::transaction::TxIn {
                    previous_output:
                        stacks_common::deps_common::bitcoin::blockdata::transaction::OutPoint {
                            txid: lockup_tx_struct.txid(),
                            vout: u32::try_from(lockup_output_index)
                                .expect("lockup_output_index fits in u32"),
                        },
                    script_sig:
                        stacks_common::deps_common::bitcoin::blockdata::script::Script::new(),
                    // `0xfffffffe` < `0xffffffff` so the spend is
                    // treated as non-final and CLTV actually runs.
                    sequence: 0xffff_fffe,
                    witness: vec![], // filled in below
                },
            ],
            output: vec![
                stacks::burnchains::bitcoin::address::SegwitBitcoinAddress::to_p2wpkh_tx_out(
                    &sweep_dest_hash20,
                    sweep_value,
                ),
            ],
        };

        // BIP-143 sighash over the BIP-143 preimage, with `script_code`
        // set to the full witness script (no OP_CODESEPARATOR handling
        // needed here).
        let script_code = stacks_common::deps_common::bitcoin::blockdata::script::Script::from(
            timelock_script.clone(),
        );
        let sig_hash_all: u32 = 0x01;
        let sig_hash =
            tx.segwit_signature_hash(0, &script_code, lockup_output_amount, sig_hash_all);

        // `BurnchainOpSigner` is the existing helper that takes a
        // Secp256k1PrivateKey and produces compact recoverable signatures;
        // we convert to a standard DER signature for OP_CHECKSIG.
        let mut signer = BurnchainOpSigner::new(signer_sk.clone());
        let sig_der_serialized = signer
            .sign_message(sig_hash.as_bytes())
            .expect("sign sweep sighash")
            .to_secp256k1_recoverable()
            .expect("recoverable sig")
            .to_standard()
            .serialize_der();
        // `serialize_der()` returns `SerializedSignature`, which is a
        // fixed-capacity buffer view over the DER bytes; expand it into
        // an owned Vec so we can append the SIGHASH_ALL byte.
        let mut sig_with_sighash_flag: Vec<u8> = sig_der_serialized.to_vec();
        sig_with_sighash_flag.push(sig_hash_all as u8);

        tx.input[0].witness = vec![
            // The signature for OP_CHECKSIG to verify against
            // `staker_unlock_pk`. (Position 0 on the witness stack —
            // i.e. *under* the branch flag — because P2WSH execution
            // pushes witness items in order, so the *first* witness
            // item ends up at the *bottom* of the stack.)
            sig_with_sighash_flag,
            // Selects the OP_IF (timelock-matured) branch of
            // `construct-lockup-script`.
            vec![0x01],
            // The P2WSH witness program preimage — bitcoind checks
            // sha256(this) == witness_program before executing it.
            timelock_script.clone(),
        ];

        tx
    };

    // (a) Interloper attempt — random key, signature doesn't match
    //     `staker_unlock_pk`. Mempool must reject.
    let interloper_sk = Secp256k1PrivateKey::random();
    let interloper_sweep_tx = build_signed_sweep(&interloper_sk);
    let interloper_result =
        bondholder_rpc.send_raw_transaction(&interloper_sweep_tx, Some(0.0), Some(1_000_000));
    let interloper_err = interloper_result
        .err()
        .expect("interloper sweep must be rejected: the script's OP_CHECKSIG should fail");
    info!(
        "Interloper sweep rejected as expected (no valid signature for staker_unlock_pk): \
         {interloper_err:?}"
    );

    // (b) Owner sweep — signed with the matching staker_unlock_sk.
    let owner_sweep_tx = build_signed_sweep(&staker_unlock_sk);
    let sweep_txid = bondholder_rpc
        .send_raw_transaction(&owner_sweep_tx, Some(0.0), Some(1_000_000))
        .expect("send_raw_transaction(owner sweep)");
    info!("Broadcast L1 owner sweep tx after timelock: txid={sweep_txid}");

    // Mine one more block to confirm the sweep, then assert from the
    // bondholder wallet that it sees the incoming sweep.
    bondholder_rpc
        .generate_to_address(1, &filler_addr)
        .expect("mine confirmation block for owner sweep tx");
    let sweep_info = bondholder_rpc
        .get_transaction(BONDHOLDER_WALLET, &sweep_txid)
        .expect("gettransaction for owner sweep");
    assert!(
        sweep_info.confirmations >= 1,
        "owner sweep tx should have at least one confirmation; got {}",
        sweep_info.confirmations
    );
    info!(
        "L1 lockup unlock-sweep confirmed: {sweep_value} sats moved out of the timelock P2WSH \
         into a bondholder-controlled output ({} confirmation(s))",
        sweep_info.confirmations
    );
}

/// Read the `sbtc-token` stub's `get-balance` for `who`. Used by L1 lockup
/// tests to assert that the L1 path does *not* move sBTC, in contrast to
/// the sBTC branch of `register-for-bond`.
fn sbtc_balance(conf: &Config, deployer: &StacksAddress, who: &StacksAddress) -> u128 {
    let value = call_read_only(
        conf,
        deployer,
        "sbtc-token",
        "get-balance",
        vec![&Value::Principal(who.clone().into())],
    )
    .result()
    .expect("get-balance read failed");
    value
        .expect_result_ok()
        .expect("get-balance should return (ok uint)")
        .expect_u128()
        .expect("get-balance ok payload should be a uint")
}

#[test]
#[ignore]
/// Verify the OP_ELSE (early-exit) branch of pox-5's L1 lockup script is
/// only spendable when the caller reveals the staker-principal preimage and
/// supplies valid early-unlock and staker signatures.
///
/// `construct-lockup-script`'s OP_ELSE branch is
/// `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <early-unlock-bytes>`,
/// followed (after OP_ENDIF) by the shared `OP_VERIFY <staker-unlock-bytes>` tail.
/// `<H>` is `sha256(sha256(to-consensus-buff? staker))`, so spending the
/// early-exit branch requires revealing the 32-byte
/// `sha256(to-consensus-buff? staker)` preimage.
///
/// This test demonstrates the realistic script shapes:
///
///   - `staker-unlock-bytes = <unlock_pk> OP_CHECKSIG` (35 bytes, ends 0xac)
///   - `early-unlock-bytes  = <early_pk>  OP_CHECKSIG` (35 bytes, ends 0xac)
///   - Lock 1_000_000 sats into the canonical timelock P2WSH and
///     `register-for-bond` with the lockup tuple.
///
/// The test also accrues rewards, announces the early exit, claims signer
/// rewards, then asserts that `announce-l1-early-exit` did not erase the
/// staker's already accrued rewards.
///
/// All five sweep attempts run *before* `unlock-burn-height`, so the
/// OP_IF branch is unavailable (its CLTV would fail) and the only path
/// the BTC can move is the OP_ELSE branch:
///
///   1. Both sigs from random keys (correct preimage) → mempool rejects
///      (the early-unlock CHECKSIG's OP_VERIFY or the closing CHECKSIG
///      returns false).
///   2. Only the owner sig (early sig from a random key, correct preimage)
///      → rejects: the early-unlock CHECKSIG result fails the shared
///      OP_VERIFY.
///   3. Only the early sig (owner sig from a random key, correct preimage)
///      → rejects: the closing OP_CHECKSIG returns false.
///   4. Both sigs correct, but a wrong (still 32-byte) principal preimage
///      → rejects: `OP_SHA256 <H> OP_EQUALVERIFY` fails before the
///      CHECKSIGs run.
///   5. Both sigs from the correct keys, correct preimage, branch flag
///      empty (selects OP_ELSE) → confirms; the BTC moves to a
///      bondholder-controlled address before the timelock matures.
fn check_pox_5_register_for_bond_l1_early_unlock_lifecycle() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    enable_epoch_4_0(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.burnchain.chain_id = CHAIN_ID_TESTNET + 1;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_signer_sk = Secp256k1PrivateKey::random();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);

    let signer_sk = signers.signer_keys[0].clone();
    let signer_pk = StacksPublicKey::from_private(&signer_sk);

    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 3000;
    let call_fee = 400;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        deploy_fee + call_fee * 20 + 10_000,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // sBTC stub — pox-5 boot needs it deployed before the epoch 4.0
    // transition so static analysis resolves the reference.
    let sbtc_deployer_sk = Secp256k1PrivateKey::random();
    let sbtc_deployer_addr = tests::to_addr(&sbtc_deployer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sbtc_deployer_addr.clone()).to_string(),
        deploy_fee * 2,
    );
    let sbtc_token_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-token").unwrap(),
    );
    let sbtc_registry_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-registry").unwrap(),
    );
    naka_conf.node.pox_5_sbtc_contract = Some(sbtc_token_id.clone());
    naka_conf.node.pox_5_sbtc_registry_contract = Some(sbtc_registry_id.clone());

    let bond_admin_sk = Secp256k1PrivateKey::random();
    let bond_admin_addr = tests::to_addr(&bond_admin_sk);
    let setup_bond_fee = 5000u64;
    naka_conf.add_initial_balance(
        PrincipalData::from(bond_admin_addr.clone()).to_string(),
        setup_bond_fee + call_fee + 1000,
    );
    naka_conf.node.pox_5_bond_admin = Some(PrincipalData::from(bond_admin_addr.clone()));

    let stacker_sk = setup_stacker(&mut naka_conf);
    let staker_sk = setup_stacker(&mut naka_conf);
    let staker_addr = tests::to_addr(&staker_sk);

    test_observer::spawn();
    test_observer::register_any(&mut naka_conf);

    let mut btcd_controller = BitcoinCoreController::from_stx_config(&naka_conf);
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    // Side wallet that owns the lockup tx's funding UTXOs. Seeded by
    // `send_btc` from the miner so the wallet has spendable BTC.
    const BONDHOLDER_WALLET: &str = "pox5-l1-early-unlock-bondholder";
    let bondholder_rpc =
        crate::burnchains::rpc::bitcoin_rpc_client::BitcoinRpcClient::from_stx_config(&naka_conf)
            .expect("failed to construct bondholder RPC client");
    bondholder_rpc
        .create_wallet(BONDHOLDER_WALLET, Some(false))
        .expect("create bondholder wallet");
    let bondholder_addr = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress on bondholder wallet");
    const BONDHOLDER_FUNDING_SATS: u64 = 2_000_000;
    let miner_keychain = Keychain::default(naka_conf.node.seed.clone());
    let mut miner_op_signer = miner_keychain.generate_op_signer();
    btc_regtest_controller
        .send_btc(
            StacksEpochId::Epoch21,
            &mut miner_op_signer,
            &bondholder_addr,
            BONDHOLDER_FUNDING_SATS,
        )
        .expect("send_btc miner -> bondholder");
    btc_regtest_controller.build_next_block(1);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed, ..
    } = run_loop.counters();
    let counters = run_loop.counters();
    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let pubkey_bytes: [u8; 33] = signer_pk
        .to_bytes_compressed()
        .try_into()
        .expect("compressed secp256k1 pubkey should be 33 bytes");
    boot_to_epoch_4_0(
        &naka_conf,
        &blocks_processed,
        &counters,
        &coord_channel,
        &[stacker_sk.clone()],
        &[sender_signer_sk],
        &[signer_sk.clone()],
        &sbtc_deployer_sk,
        Some(&pubkey_bytes),
        deploy_fee,
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );
    info!(
        "Reached Epoch-4.0 boundary, deploying signer-manager and registering signer \
         (early-unlock test)"
    );

    let mut sender_nonce = 0;

    let signer_contract = pox5_signer_manager_source();
    let signer_deploy_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "test-signer",
        signer_contract,
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &signer_deploy_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for test-signer deploy");

    next_block_and_mine_commit(&mut btc_regtest_controller, 60, &naka_conf, &counters).unwrap();

    let test_signer_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from("test-signer").unwrap(),
    ));
    let auth_id: u128 = 1;
    let signer_grant_sig =
        stacks::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature(
            &test_signer_principal,
            auth_id,
            naka_conf.burnchain.chain_id,
            &signer_sk,
        )
        .expect("Failed to generate signer grant signature");
    let register_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "register-self",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            Value::UInt(auth_id),
            Value::buff_from(signer_grant_sig.to_rsv()).unwrap(),
        ],
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &register_tx);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for register-self");

    let pox_5_id = boot_code_id("pox-5", false);
    let pox_5_addr: StacksAddress = pox_5_id.issuer.clone().into();

    // Two keypairs gate the lockup:
    //   - `staker_unlock_sk` (owner) closes the shared tail of the witness
    //     script via `<unlock_pk> OP_CHECKSIG`; it is required on both
    //     branches.
    //   - `early_unlock_sk` is the early-exit signer; its sig is
    //     consumed by `<early_pk> OP_CHECKSIG` inside the OP_ELSE
    //     branch.
    let staker_unlock_sk = Secp256k1PrivateKey::random();
    let staker_unlock_pk = Secp256k1PublicKey::from_private(&staker_unlock_sk);
    let staker_unlock_pk_bytes = staker_unlock_pk.to_bytes_compressed();
    assert_eq!(
        staker_unlock_pk_bytes.len(),
        33,
        "compressed secp pubkey should be 33 bytes"
    );
    let early_unlock_sk = Secp256k1PrivateKey::random();
    let early_unlock_pk = Secp256k1PublicKey::from_private(&early_unlock_sk);
    let early_unlock_pk_bytes = early_unlock_pk.to_bytes_compressed();
    assert_eq!(
        early_unlock_pk_bytes.len(),
        33,
        "compressed secp pubkey should be 33 bytes"
    );

    // `staker-unlock-bytes` = `<unlock_pk> OP_CHECKSIG` (shared tail).
    let mut lockup_unlock_bytes = Vec::with_capacity(1 + 33 + 1);
    lockup_unlock_bytes.push(0x21); // OP_PUSHBYTES_33
    lockup_unlock_bytes.extend_from_slice(&staker_unlock_pk_bytes);
    lockup_unlock_bytes.push(0xac); // OP_CHECKSIG

    // `early-unlock-bytes` = `<early_pk> OP_CHECKSIG`. It guards the OP_ELSE
    // branch and MUST leave a boolean (it is consumed by the shared
    // OP_VERIFY), so it ends in OP_CHECKSIG (0xac), not OP_CHECKSIGVERIFY.
    let mut early_unlock_bytes = Vec::with_capacity(1 + 33 + 1);
    early_unlock_bytes.push(0x21); // OP_PUSHBYTES_33
    early_unlock_bytes.extend_from_slice(&early_unlock_pk_bytes);
    early_unlock_bytes.push(0xac); // OP_CHECKSIG

    // The OP_ELSE branch requires revealing the 32-byte
    // `sha256(to-consensus-buff? staker)` preimage of the committed hash
    // `<H> = sha256(sha256(to-consensus-buff? staker))`. Compute it here so
    // the early-exit witness can present it. `serialize_to_vec` produces the
    // exact bytes `to-consensus-buff?` does.
    let staker_principal_consensus_buff = Value::Principal(staker_addr.clone().into())
        .serialize_to_vec()
        .expect("serialize staker principal to consensus buff");
    let staker_principal_preimage =
        stacks_common::util::hash::Sha256Sum::from_data(&staker_principal_consensus_buff)
            .0
            .to_vec();

    // 1) `setup-bond` from the configured bond admin, with the
    // CHECKSIG-terminated early-unlock subscript.
    const BTC_LOCKUP_SATS: u128 = 1_000_000;
    const BOND_TARGET_RATE: u128 = 1_000;
    let allowlist_entry = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("staker").unwrap(),
                Value::Principal(staker_addr.clone().into()),
            ),
            (
                ClarityName::try_from("max-sats").unwrap(),
                Value::UInt(BTC_LOCKUP_SATS),
            ),
        ])
        .unwrap(),
    );
    let allowlist_value = Value::cons_list_unsanitized(vec![allowlist_entry]).unwrap();
    let setup_bond_tx = make_contract_call(
        &bond_admin_sk,
        0,
        setup_bond_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "setup-bond",
        &[
            Value::UInt(0),
            Value::UInt(BOND_TARGET_RATE),
            Value::UInt(100),
            Value::UInt(10000),
            Value::buff_from(early_unlock_bytes.clone()).unwrap(),
            Value::Principal(bond_admin_addr.clone().into()),
            allowlist_value,
        ],
    );
    let setup_bond_txid = submit_tx(&http_origin, &setup_bond_tx);
    info!("Submitted pox-5 setup-bond (early-unlock test) txid: {setup_bond_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &bond_admin_addr).nonce == 1)
    })
    .expect("Timed out waiting for setup-bond");

    // 2) Derive the P2WSH from pox-5, lock 1M sats into it, and prove
    //    the lockup to `register-for-bond`.
    let bond_index = 0u128;
    let unlock_burn_height = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-bond-l1-unlock-height",
        vec![&Value::UInt(bond_index)],
    )
    .result()
    .expect("get-bond-l1-unlock-height failed")
    .expect_u128()
    .expect("get-bond-l1-unlock-height should return a uint");
    let expected_script_buff = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "construct-lockup-output-script",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::UInt(unlock_burn_height),
            &Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            &Value::buff_from(early_unlock_bytes.clone()).unwrap(),
        ],
    )
    .result()
    .expect("construct-lockup-output-script failed")
    .expect_buff(34)
    .expect("construct-lockup-output-script should return (buff 34)");
    assert_eq!(
        &expected_script_buff[0..2],
        &[0x00, 0x20],
        "lockup output script is supposed to be a SegWit V0 P2WSH push (0x00 0x20 || hash)"
    );
    let mut witness_script_hash = [0u8; 32];
    witness_script_hash.copy_from_slice(&expected_script_buff[2..]);

    let p2wsh_addr = stacks::burnchains::bitcoin::address::BitcoinAddress::Segwit(
        stacks::burnchains::bitcoin::address::SegwitBitcoinAddress::P2WSH(
            stacks::burnchains::bitcoin::BitcoinNetworkType::Regtest,
            witness_script_hash,
        ),
    );
    info!(
        "Lockup P2WSH (early-unlock test) derived from construct-lockup-output-script: {}",
        &p2wsh_addr
    );

    let lockup_btc_amount = 0.01_f64; // 1_000_000 sats
    let p2wsh_txid = bondholder_rpc
        .send_to_address(BONDHOLDER_WALLET, &p2wsh_addr, lockup_btc_amount)
        .expect("send_to_address into lockup P2WSH");
    info!("Sent {lockup_btc_amount} BTC to lockup P2WSH; txid={p2wsh_txid}");

    let coinbase_recipient = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress for generateblock coinbase");
    let pre_register_burn_height = get_chain_info_result(&naka_conf).unwrap().burn_block_height;
    let lockup_block_hash = bondholder_rpc
        .generate_block(&coinbase_recipient, &[&p2wsh_txid.to_hex()])
        .expect("generateblock with lockup tx");
    info!("Mined lockup tx into block {lockup_block_hash}");

    wait_for(60, || {
        Ok(get_chain_info_result(&naka_conf).unwrap().burn_block_height > pre_register_burn_height)
    })
    .expect("Stacks node did not ingest the lockup burn block");
    let lockup_burn_height = get_chain_info_result(&naka_conf).unwrap().burn_block_height;
    info!("Stacks node observed lockup burn block; burn_block_height = {lockup_burn_height}");

    let lockup_tx_struct = bondholder_rpc
        .get_raw_transaction(&p2wsh_txid)
        .expect("getrawtransaction for lockup tx");
    let lockup_tx_hex =
        stacks_common::deps_common::bitcoin::network::serialize::serialize_hex(&lockup_tx_struct)
            .expect("serialize_hex(lockup_tx)");
    let lockup_tx_bytes = hex_bytes(&lockup_tx_hex).expect("decode lockup_tx hex");
    let (lockup_output_index, lockup_output_amount) = lockup_tx_struct
        .output
        .iter()
        .enumerate()
        .find_map(|(idx, out)| {
            let script = out.script_pubkey.as_bytes();
            if script.len() == 34
                && script[..2] == [0x00, 0x20]
                && script[2..] == witness_script_hash
            {
                Some((idx, out.value))
            } else {
                None
            }
        })
        .expect("lockup tx must contain a P2WSH output matching the expected script");
    assert_eq!(
        lockup_output_amount,
        u64::try_from(BTC_LOCKUP_SATS).unwrap(),
        "send_to_address moved exactly {BTC_LOCKUP_SATS} sats into the P2WSH"
    );

    let header_hex = bondholder_rpc
        .get_block_header_hex(&lockup_block_hash)
        .expect("getblockheader for lockup block");
    let lockup_header_bytes = hex_bytes(&header_hex).expect("decode header hex");
    assert_eq!(
        lockup_header_bytes.len(),
        80,
        "Bitcoin block header is always 80 bytes"
    );
    let block_txids_display = bondholder_rpc
        .get_block_txids(&lockup_block_hash)
        .expect("getblock for lockup block txids");
    assert_eq!(
        block_txids_display.len(),
        2,
        "lockup block should contain exactly coinbase + lockup tx; got {} txs",
        block_txids_display.len()
    );
    let mut coinbase_txid_internal: [u8; 32] = block_txids_display[0].as_bytes().clone();
    coinbase_txid_internal.reverse();
    assert_eq!(
        block_txids_display[1].to_hex(),
        p2wsh_txid.to_hex(),
        "lockup tx must be the non-coinbase entry in the generated block",
    );

    let lockup_output = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("height").unwrap(),
                Value::UInt(lockup_burn_height as u128),
            ),
            (
                ClarityName::try_from("tx").unwrap(),
                Value::buff_from(lockup_tx_bytes).unwrap(),
            ),
            (
                ClarityName::try_from("output-index").unwrap(),
                Value::UInt(lockup_output_index as u128),
            ),
            (
                ClarityName::try_from("header").unwrap(),
                Value::buff_from(lockup_header_bytes).unwrap(),
            ),
            (
                ClarityName::try_from("leaf-hashes").unwrap(),
                Value::cons_list_unsanitized(vec![Value::buff_from(
                    coinbase_txid_internal.to_vec(),
                )
                .unwrap()])
                .unwrap(),
            ),
            (ClarityName::try_from("tx-count").unwrap(), Value::UInt(2)),
            (ClarityName::try_from("tx-index").unwrap(), Value::UInt(1)),
            (
                ClarityName::try_from("amount").unwrap(),
                Value::UInt(u128::from(lockup_output_amount)),
            ),
        ])
        .unwrap(),
    );
    let lockup_tuple = clarity::vm::Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("outputs").unwrap(),
                Value::cons_list_unsanitized(vec![lockup_output]).unwrap(),
            ),
            (
                ClarityName::try_from("staker-unlock-bytes").unwrap(),
                Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            ),
        ])
        .unwrap(),
    );
    let l1_lockup_arg = Value::okay(lockup_tuple).expect("failed to wrap lockup tuple in (ok ...)");

    // 3) `register-for-bond` via the L1 path. This isn't strictly
    // required for the Bitcoin-script assertions below — the early-exit
    // branch is a property of the witness script alone — but it
    // documents the realistic end-to-end flow.
    let register_fee = 2000u64;
    let bond_amount = POX_DEFAULT_STACKER_STX_AMT;
    let register_tx = make_contract_call(
        &staker_sk,
        0,
        register_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "register-for-bond",
        &[
            Value::UInt(0),
            Value::Principal(test_signer_principal.clone()),
            Value::UInt(bond_amount),
            l1_lockup_arg,
            Value::none(),
        ],
    );
    let register_txid = submit_tx(&http_origin, &register_tx);
    info!("Submitted pox-5 register-for-bond (L1 early-unlock test) txid: {register_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &staker_addr).nonce == 1
            && get_tx_result_by_id(&register_txid).is_some())
    })
    .expect("Timed out waiting for register-for-bond (L1 early-unlock test)");

    // Accrue one bond reward distribution before the early-exit announcement.
    // `announce-l1-early-exit` settles staker rewards before zeroing L1 bond
    // shares; after that, claim signer rewards and check the staker's already
    // accrued rewards survived that state transition.
    let reward_mint = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sbtc_deployer_addr,
        "sbtc-token",
        "mint",
        &[
            Value::UInt(2_000),
            Value::Principal(PrincipalData::Contract(pox_5_id.clone())),
        ],
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &reward_mint);
    wait_for(60, || {
        Ok(get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce)
    })
    .expect("Timed out waiting for reward mint");

    let bond_start_cycle = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "bond-period-to-reward-cycle",
        vec![&Value::UInt(bond_index)],
    )
    .result()
    .expect("bond-period-to-reward-cycle failed")
    .expect_u128()
    .expect("bond-period-to-reward-cycle should return a uint");
    let reward_cycle = bond_start_cycle + 1;
    let reward_cycle_start = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "reward-cycle-to-burn-height",
        vec![&Value::UInt(reward_cycle)],
    )
    .result()
    .expect("reward-cycle-to-burn-height failed")
    .expect_u128()
    .expect("reward-cycle-to-burn-height should return a uint");
    let next_reward_cycle_start = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "reward-cycle-to-burn-height",
        vec![&Value::UInt(reward_cycle + 1)],
    )
    .result()
    .expect("reward-cycle-to-burn-height failed")
    .expect_u128()
    .expect("reward-cycle-to-burn-height should return a uint");
    let reward_calculation_burn_height =
        reward_cycle_start + ((next_reward_cycle_start - reward_cycle_start) / 2);
    while u128::from(get_chain_info_result(&naka_conf).unwrap().burn_block_height)
        < reward_calculation_burn_height
    {
        next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 30, &coord_channel)
            .unwrap();
    }

    test_observer::clear();
    let calculate_rewards_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        2_000,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "calculate-rewards",
        &[Value::cons_list_unsanitized(vec![Value::UInt(bond_index)]).unwrap()],
    );
    sender_nonce += 1;
    let calculate_rewards_txid = submit_tx(&http_origin, &calculate_rewards_tx);
    wait_for(60, || {
        Ok(
            get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce
                && get_tx_result_by_id(&calculate_rewards_txid).is_some(),
        )
    })
    .expect("Timed out waiting for calculate-rewards");
    assert!(
        get_tx_result_by_id(&calculate_rewards_txid)
            .expect("missing calculate-rewards result")
            .expect_result()
            .expect("calculate-rewards should return a response")
            .is_ok(),
        "calculate-rewards should succeed"
    );

    let expected_staker_rewards = ((BTC_LOCKUP_SATS * BOND_TARGET_RATE) / 10_000) / 50;

    // 4) Sweep the lockup via the OP_ELSE (early-exit) branch *before*
    //    `unlock-burn-height`. OP_IF's CLTV will reject any spend
    //    attempt at this height; the only path the BTC can move is
    //    OP_ELSE.
    let timelock_script = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "construct-lockup-script",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::UInt(unlock_burn_height),
            &Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            &Value::buff_from(early_unlock_bytes.clone()).unwrap(),
        ],
    )
    .result()
    .expect("construct-lockup-script failed")
    .expect_buff(usize::MAX)
    .expect("construct-lockup-script should return a buff");

    // Sanity check: we must still be well before the timelock so OP_IF
    // is unavailable when our sweeps land.
    let current_btc_height = bondholder_rpc
        .get_blockchain_info()
        .expect("getblockchaininfo")
        .blocks;
    assert!(
        (current_btc_height as u128) < unlock_burn_height,
        "test setup drifted past the L1 unlock height ({current_btc_height} >= {unlock_burn_height}); \
         OP_ELSE-only assertions would be undermined by OP_IF becoming spendable"
    );

    let sweep_dest_addr = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress for sweep destination");
    let sweep_dest_hash20 = match &sweep_dest_addr {
        stacks::burnchains::bitcoin::address::BitcoinAddress::Segwit(
            stacks::burnchains::bitcoin::address::SegwitBitcoinAddress::P2WPKH(_, h),
        ) => *h,
        other => panic!("expected P2WPKH bech32 sweep address, got {other:?}"),
    };
    let filler_addr = bondholder_rpc
        .get_new_address(
            BONDHOLDER_WALLET,
            None,
            Some(crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType::Bech32),
        )
        .expect("getnewaddress for filler coinbase");

    const SWEEP_FEE_SATS: u64 = 1_000;
    assert!(
        lockup_output_amount > SWEEP_FEE_SATS,
        "lockup output {lockup_output_amount} sats must cover SWEEP_FEE_SATS={SWEEP_FEE_SATS}",
    );
    let sweep_value = lockup_output_amount - SWEEP_FEE_SATS;

    // Build a sweep tx signed by two arbitrary keys, configured for the
    // OP_ELSE branch. The witness stack is laid out (bottom-to-top) as
    // `[sig_owner, sig_early, principal_preimage, <empty branch flag>]`
    // so the OP_ELSE body
    // `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
    //  <early_pk> OP_CHECKSIG` (then `OP_ENDIF OP_VERIFY
    //  <unlock_pk> OP_CHECKSIG`) sees what it needs:
    //   - witness items are pushed left-to-right; the first item ends
    //     up at the *bottom* of the stack;
    //   - after OP_IF pops the (empty) branch flag, the stack is
    //     [sig_owner, sig_early, principal_preimage];
    //   - OP_SIZE/OP_EQUALVERIFY checks the preimage is 32 bytes;
    //   - OP_SHA256/<H>/OP_EQUALVERIFY checks sha256(preimage) == H, leaving
    //     [sig_owner, sig_early];
    //   - `<early_pk> OP_CHECKSIG` pops `sig_early`, pushes a bool;
    //   - OP_ENDIF, then OP_VERIFY consumes that bool, leaving [sig_owner];
    //   - `<unlock_pk> OP_CHECKSIG` pops `sig_owner`, pushes 1 — the final
    //     result.
    let build_joint_sweep =
        |owner_sk: &Secp256k1PrivateKey,
         early_sk: &Secp256k1PrivateKey,
         preimage: &[u8]|
         -> stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction {
            let mut tx = stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction {
                version: 2,
                // OP_ELSE never runs CHECKLOCKTIMEVERIFY, so nLockTime can
                // be 0 and the tx is unconditionally final regardless of
                // the input's sequence.
                lock_time: 0,
                input: vec![
                    stacks_common::deps_common::bitcoin::blockdata::transaction::TxIn {
                        previous_output:
                            stacks_common::deps_common::bitcoin::blockdata::transaction::OutPoint {
                                txid: lockup_tx_struct.txid(),
                                vout: u32::try_from(lockup_output_index)
                                    .expect("lockup_output_index fits in u32"),
                            },
                        script_sig:
                            stacks_common::deps_common::bitcoin::blockdata::script::Script::new(),
                        sequence: 0xffff_fffe,
                        witness: vec![], // filled in below
                    },
                ],
                output: vec![
                    stacks::burnchains::bitcoin::address::SegwitBitcoinAddress::to_p2wpkh_tx_out(
                        &sweep_dest_hash20,
                        sweep_value,
                    ),
                ],
            };

            let script_code = stacks_common::deps_common::bitcoin::blockdata::script::Script::from(
                timelock_script.clone(),
            );
            let sig_hash_all: u32 = 0x01;
            let sig_hash =
                tx.segwit_signature_hash(0, &script_code, lockup_output_amount, sig_hash_all);

            let sign_with = |sk: &Secp256k1PrivateKey| -> Vec<u8> {
                let mut signer = BurnchainOpSigner::new(sk.clone());
                let sig_der_serialized = signer
                    .sign_message(sig_hash.as_bytes())
                    .expect("sign sweep sighash")
                    .to_secp256k1_recoverable()
                    .expect("recoverable sig")
                    .to_standard()
                    .serialize_der();
                let mut v: Vec<u8> = sig_der_serialized.to_vec();
                v.push(sig_hash_all as u8);
                v
            };

            let sig_owner = sign_with(owner_sk);
            let sig_early = sign_with(early_sk);

            tx.input[0].witness = vec![
                // First witness item -> bottom of stack: the sig the closing
                // `<unlock_pk> OP_CHECKSIG` (shared tail) will consume.
                sig_owner,
                // Above it: the sig that the OP_ELSE `<early_pk>
                // OP_CHECKSIG` consumes.
                sig_early,
                // Above that: the 32-byte sha256(to-consensus-buff? staker)
                // preimage that OP_SIZE/OP_SHA256 in the OP_ELSE branch
                // consume.
                preimage.to_vec(),
                // Empty buffer = false (MINIMALIF-compliant): OP_IF takes
                // the OP_ELSE branch.
                vec![],
                // P2WSH preimage; bitcoind checks sha256(this) ==
                // witness_program before executing.
                timelock_script.clone(),
            ];

            tx
        };

    // (a) Both sigs from random keys (correct preimage).
    let tx_both_wrong = build_joint_sweep(
        &Secp256k1PrivateKey::random(),
        &Secp256k1PrivateKey::random(),
        &staker_principal_preimage,
    );
    let res_both_wrong =
        bondholder_rpc.send_raw_transaction(&tx_both_wrong, Some(0.0), Some(1_000_000));
    let err_both_wrong = res_both_wrong
        .err()
        .expect("both-wrong-sigs early-exit sweep must be rejected by the script's CHECKSIGs");
    info!("Both-wrong-sigs early-exit sweep rejected as expected: {err_both_wrong:?}");

    // (b) Owner sig correct, early sig from a random key (correct preimage).
    let tx_no_early = build_joint_sweep(
        &staker_unlock_sk,
        &Secp256k1PrivateKey::random(),
        &staker_principal_preimage,
    );
    let res_no_early =
        bondholder_rpc.send_raw_transaction(&tx_no_early, Some(0.0), Some(1_000_000));
    let err_no_early = res_no_early
        .err()
        .expect("missing-early-sig sweep must be rejected: early-unlock CHECKSIG fails OP_VERIFY");
    info!(
        "Owner-only early-exit sweep rejected (early-unlock CHECKSIG fails the shared OP_VERIFY): \
         {err_no_early:?}"
    );

    // (c) Early sig correct, owner sig from a random key (correct preimage).
    let tx_no_owner = build_joint_sweep(
        &Secp256k1PrivateKey::random(),
        &early_unlock_sk,
        &staker_principal_preimage,
    );
    let res_no_owner =
        bondholder_rpc.send_raw_transaction(&tx_no_owner, Some(0.0), Some(1_000_000));
    let err_no_owner = res_no_owner
        .err()
        .expect("missing-owner-sig sweep must be rejected by the closing OP_CHECKSIG");
    info!(
        "Early-only early-exit sweep rejected (closing CHECKSIG on the owner sig fails): \
         {err_no_owner:?}"
    );

    // (d) Both sigs correct, but a wrong (still 32-byte) principal preimage.
    // OP_SIZE passes, but `OP_SHA256 <H> OP_EQUALVERIFY` fails because
    // sha256(wrong_preimage) != H, so the OP_ELSE branch aborts before the
    // CHECKSIGs ever run.
    let mut wrong_preimage = staker_principal_preimage.clone();
    wrong_preimage[0] ^= 0xff;
    let tx_wrong_preimage = build_joint_sweep(&staker_unlock_sk, &early_unlock_sk, &wrong_preimage);
    let res_wrong_preimage =
        bondholder_rpc.send_raw_transaction(&tx_wrong_preimage, Some(0.0), Some(1_000_000));
    let err_wrong_preimage = res_wrong_preimage
        .err()
        .expect("wrong-preimage sweep must be rejected by OP_SHA256 <H> OP_EQUALVERIFY");
    info!(
        "Wrong-preimage early-exit sweep rejected (sha256(preimage) != H fails OP_EQUALVERIFY): \
         {err_wrong_preimage:?}"
    );

    // (e) Both sigs from the correct keys, correct preimage -> confirms.
    let joint_sweep_tx = build_joint_sweep(
        &staker_unlock_sk,
        &early_unlock_sk,
        &staker_principal_preimage,
    );
    let sweep_txid = bondholder_rpc
        .send_raw_transaction(&joint_sweep_tx, Some(0.0), Some(1_000_000))
        .expect("send_raw_transaction(joint early-exit sweep)");
    info!("Broadcast joint-sig early-exit sweep before timelock: txid={sweep_txid}");

    bondholder_rpc
        .generate_to_address(1, &filler_addr)
        .expect("mine confirmation block for joint early-exit sweep");
    let sweep_info = bondholder_rpc
        .get_transaction(BONDHOLDER_WALLET, &sweep_txid)
        .expect("gettransaction for joint early-exit sweep");
    assert!(
        sweep_info.confirmations >= 1,
        "joint early-exit sweep tx should have at least one confirmation; got {}",
        sweep_info.confirmations
    );
    info!(
        "L1 early-exit sweep confirmed: {sweep_value} sats moved out of the timelock P2WSH \
         BEFORE unlock-burn-height ({} confirmation(s))",
        sweep_info.confirmations
    );

    // Final guard: prove the confirmed sweep took the OP_ELSE branch by
    // confirming the chain never crossed the OP_IF (timelock) gate.
    let final_btc_height = bondholder_rpc
        .get_blockchain_info()
        .expect("getblockchaininfo")
        .blocks;
    assert!(
        (final_btc_height as u128) < unlock_burn_height,
        "test drifted past unlock-burn-height ({final_btc_height} >= {unlock_burn_height}); \
         the confirmed sweep may have taken the OP_IF (timelock) branch instead of OP_ELSE"
    );

    // Call `announce-l1-early-exit` to ensure the contract accepts the proof
    // of the early exit as expected.
    let pre_announce_shares = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-staker-shares-staked-for-cycle",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::Bool(true),
            &Value::UInt(bond_index),
            &Value::Principal(test_signer_principal.clone()),
        ],
    )
    .result()
    .expect("get-staker-shares-staked-for-cycle failed")
    .expect_u128()
    .expect("get-staker-shares-staked-for-cycle should return a uint");
    assert_eq!(
        pre_announce_shares, BTC_LOCKUP_SATS,
        "staker should have {BTC_LOCKUP_SATS} bond shares from the L1 lockup before announce-l1-early-exit"
    );

    test_observer::clear();
    let announce_tx = make_contract_call(
        &bond_admin_sk,
        1,
        call_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_addr,
        "pox-5",
        "announce-l1-early-exit",
        &[
            Value::Principal(staker_addr.clone().into()),
            Value::Principal(test_signer_principal.clone()),
        ],
    );
    let announce_txid = submit_tx(&http_origin, &announce_tx);
    info!("Submitted pox-5 announce-l1-early-exit txid: {announce_txid}");

    wait_for(60, || {
        Ok(get_account(&http_origin, &bond_admin_addr).nonce == 2
            && get_tx_result_by_id(&announce_txid).is_some())
    })
    .expect("Timed out waiting for announce-l1-early-exit");

    let announce_result = get_tx_result_by_id(&announce_txid)
        .expect("did not observe announce-l1-early-exit txid in test_observer");
    let expected_announce_result = Value::okay(Value::Tuple(
        clarity::vm::types::TupleData::from_data(vec![
            (
                ClarityName::try_from("amount-sats-released").unwrap(),
                Value::UInt(BTC_LOCKUP_SATS),
            ),
            (
                ClarityName::try_from("bond-index").unwrap(),
                Value::UInt(bond_index),
            ),
            (
                ClarityName::try_from("signer").unwrap(),
                Value::Principal(test_signer_principal.clone()),
            ),
            (
                ClarityName::try_from("staker").unwrap(),
                Value::Principal(staker_addr.clone().into()),
            ),
        ])
        .unwrap(),
    ))
    .unwrap();
    assert_eq!(
        announce_result, expected_announce_result,
        "announce-l1-early-exit should return (ok {{ released bond details }}) when called by the early-unlock admin with the matching signer-manager"
    );

    let claim_rewards_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "claim-rewards",
        &[
            Value::cons_list_unsanitized(vec![Value::UInt(bond_index)]).unwrap(),
            Value::UInt(reward_cycle),
        ],
    );
    sender_nonce += 1;
    let claim_rewards_txid = submit_tx(&http_origin, &claim_rewards_tx);
    wait_for(60, || {
        Ok(
            get_account(&http_origin, &to_addr(&sender_sk)).nonce == sender_nonce
                && get_tx_result_by_id(&claim_rewards_txid).is_some(),
        )
    })
    .expect("Timed out waiting for claim-rewards");
    assert!(
        get_tx_result_by_id(&claim_rewards_txid)
            .expect("missing claim-rewards result")
            .expect_result()
            .expect("claim-rewards should return a response")
            .is_ok(),
        "claim-rewards should succeed"
    );

    let staker_rewards_after_announce = call_read_only(
        &naka_conf,
        &sender_addr,
        "test-signer",
        "get-earned-staker-rewards",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::Bool(true),
            &Value::UInt(bond_index),
        ],
    )
    .result()
    .expect("get-earned-staker-rewards failed")
    .expect_u128()
    .expect("get-earned-staker-rewards should return a uint");
    assert_eq!(
        staker_rewards_after_announce, expected_staker_rewards,
        "announce-l1-early-exit must not erase already accrued staker rewards"
    );

    let post_announce_shares = call_read_only(
        &naka_conf,
        &pox_5_addr,
        "pox-5",
        "get-staker-shares-staked-for-cycle",
        vec![
            &Value::Principal(staker_addr.clone().into()),
            &Value::Bool(true),
            &Value::UInt(bond_index),
            &Value::Principal(test_signer_principal.clone()),
        ],
    )
    .result()
    .expect("get-staker-shares-staked-for-cycle failed")
    .expect_u128()
    .expect("get-staker-shares-staked-for-cycle should return a uint");
    assert_eq!(
        post_announce_shares, 0,
        "announce-l1-early-exit should zero out the staker's bond shares"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// Verify the `with-stacking` allowances work as expected when staking STX
fn check_with_stacking_allowances_stake() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    enable_epoch_4_0(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.burnchain.chain_id = CHAIN_ID_TESTNET + 1;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_signer_sk = Secp256k1PrivateKey::random();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);

    let signer_sk = signers.signer_keys[0].clone();
    let signer_pk = StacksPublicKey::from_private(&signer_sk);

    // setup sender + recipient for some test stx transfers
    // these are necessary for the interim blocks to get mined at all
    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 3000;
    let call_fee = 400;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        deploy_fee + call_fee * 30,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // Set the sBTC token and registry contracts, which we will deploy before
    // epoch 4.0
    let sbtc_deployer_sk = Secp256k1PrivateKey::random();
    let sbtc_deployer_addr = tests::to_addr(&sbtc_deployer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sbtc_deployer_addr.clone()).to_string(),
        2 * deploy_fee,
    );
    let sbtc_token_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-token").unwrap(),
    );
    let sbtc_registry_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-registry").unwrap(),
    );
    naka_conf.node.pox_5_sbtc_contract = Some(sbtc_token_id.clone());
    naka_conf.node.pox_5_sbtc_registry_contract = Some(sbtc_registry_id.clone());

    // Default stacker used for bootstrapping
    let stacker_sk = setup_stacker(&mut naka_conf);

    // Stackers used for testing
    let stackers: Vec<_> = (0..3).map(|_| setup_stacker(&mut naka_conf)).collect();

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
        blocks_processed, ..
    } = run_loop.counters();
    let counters = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let pubkey_bytes: [u8; 33] = signer_pk
        .to_bytes_compressed()
        .try_into()
        .expect("compressed secp256k1 pubkey should be 33 bytes");
    boot_to_epoch_4_0(
        &naka_conf,
        &blocks_processed,
        &counters,
        &coord_channel,
        &[stacker_sk.clone()],
        &[sender_signer_sk],
        &[],
        &sbtc_deployer_sk,
        Some(&pubkey_bytes),
        deploy_fee,
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );

    let mut sender_nonce = 0;

    // Deploy the signer contract
    let signer_contract = pox5_signer_manager_source();
    let contract_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "test-signer",
        signer_contract,
    );
    sender_nonce += 1;
    let deploy_txid = submit_tx(&http_origin, &contract_tx);
    info!("Submitted signer contract deploy txid: {deploy_txid}");

    wait_for(60, || {
        let cur_sender_nonce = get_account(&http_origin, &to_addr(&sender_sk)).nonce;
        Ok(cur_sender_nonce == sender_nonce)
    })
    .expect("Timed out waiting for signer contract deploy");

    let info = get_chain_info_result(&naka_conf).unwrap();
    let last_stacks_block_height = info.stacks_tip_height as u128;

    next_block_and_mine_commit(&mut btc_regtest_controller, 60, &naka_conf, &counters).unwrap();

    let signer_key_hex = Value::buff_from(signer_pk.to_bytes_compressed()).unwrap();
    let contract_name = "test-contract";
    let contract = format!(
        r#"
(define-constant signer-key {signer_key_hex})
(define-public (stake (amount uint) (allowed uint))
  (restrict-assets? tx-sender ((with-stacking allowed))
    (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 stake
      .test-signer amount u12 burn-block-height none
    ))
    true
  )
)
(define-public (stake-2-allowances (amount uint) (allowed-1 uint) (allowed-2 uint))
  (restrict-assets? tx-sender ((with-stacking allowed-1) (with-stacking allowed-2))
    (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 stake
      .test-signer amount u12 burn-block-height none
    ))
    true
  )
)
(define-public (stake-no-allowance (amount uint))
  (restrict-assets? tx-sender ()
    (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 stake
      .test-signer amount u12 burn-block-height none
    ))
    true
  )
)
(define-public (stake-all (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender current-contract))
    (as-contract? ((with-all-assets-unsafe))
      (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 stake
        .test-signer amount u12 burn-block-height none
      ))
      true
    )
  )
)
"#
    );

    let contract_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        contract_name,
        &contract,
    );
    sender_nonce += 1;
    let deploy_txid = submit_tx(&http_origin, &contract_tx);
    info!("Submitted deploy txid: {deploy_txid}");

    let mut stacks_block_height = 0;
    wait_for(60, || {
        let cur_sender_nonce = get_account(&http_origin, &to_addr(&sender_sk)).nonce;
        let info = get_chain_info_result(&naka_conf).unwrap();
        stacks_block_height = info.stacks_tip_height as u128;
        Ok(stacks_block_height > last_stacks_block_height && cur_sender_nonce == sender_nonce)
    })
    .expect("Timed out waiting for contracts to publish");

    next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 30, &coord_channel)
        .unwrap();

    // pox-5's `stake` requires the signer-manager contract to have been
    // registered in advance via `register-signer`, which itself requires
    // a signer-key grant signed by the signer key. Build that signature
    // and call `test-signer.register-self` so the staking calls below
    // can find a signer record.
    let test_signer_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from("test-signer").unwrap(),
    ));
    let auth_id: u128 = 1;
    let signer_grant_sig =
        stacks::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature(
            &test_signer_principal,
            auth_id,
            naka_conf.burnchain.chain_id,
            &signer_sk,
        )
        .expect("Failed to generate signer grant signature");
    let register_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "register-self",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            Value::UInt(auth_id),
            Value::buff_from(signer_grant_sig.to_rsv()).unwrap(),
        ],
    );
    sender_nonce += 1;
    let register_txid = submit_tx(&http_origin, &register_tx);
    info!("Submitted register-self txid: {register_txid}");
    wait_for(60, || {
        let cur_sender_nonce = get_account(&http_origin, &to_addr(&sender_sk)).nonce;
        Ok(cur_sender_nonce == sender_nonce)
    })
    .expect("Timed out waiting for register-self to confirm");

    // Each stacker calls `pox-5.stake` indirectly through the test
    // contract, so they must first authorize the test contract as an
    // allowed contract-caller. Otherwise pox-5's `check-caller-allowed`
    // returns `ERR_UNAUTHORIZED_CALLER` (u22).
    let pox_5_id = boot_code_id("pox-5", false);
    let test_contract_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from(contract_name).unwrap(),
    ));
    let mut allow_nonces = HashMap::new();
    for stacker in stackers.iter() {
        let stacker_addr = tests::to_addr(stacker);
        let allow_tx = make_contract_call(
            stacker,
            0,
            call_fee,
            naka_conf.burnchain.chain_id,
            &pox_5_id.issuer.clone().into(),
            "pox-5",
            "allow-contract-caller",
            &[
                Value::Principal(test_contract_principal.clone()),
                Value::none(),
            ],
        );
        let txid = submit_tx(&http_origin, &allow_tx);
        info!("Submitted allow-contract-caller txid: {txid} for {stacker_addr}");
        allow_nonces.insert(stacker_addr, 1);
    }
    wait_for(60, || {
        for (addr, expected_nonce) in &allow_nonces {
            if get_account(&http_origin, addr).nonce != *expected_nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for allow-contract-caller");

    test_observer::clear();

    // Amount to stack
    let amount = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);

    // Map txid to expected result, `true` for ok, `false` for error
    let mut expected_results = HashMap::new();
    let mut wait_for_nonce = HashMap::new();

    // ***** Successfully stack with stackers[0]
    let stacker = &stackers[0];
    let stacker_addr = tests::to_addr(stacker);
    // stackers[0] consumed nonce 0 for allow-contract-caller above.
    let mut stacker_nonce = 1;

    let stack_ok_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake",
        &[amount.clone(), amount.clone()],
    );
    stacker_nonce += 1;
    let stack_ok_txid = submit_tx(&http_origin, &stack_ok_tx);
    info!("Submitted stake_ok txid: {stack_ok_txid}");
    expected_results.insert(stack_ok_txid, Value::okay_true());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Fail to stack with stackers[1]
    let stacker = &stackers[1];
    let stacker_addr = tests::to_addr(stacker);
    let mut stacker_nonce = 1;

    let allowed = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 1);
    let stack_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake",
        &[amount.clone(), allowed],
    );
    stacker_nonce += 1;
    let stack_err_txid = submit_tx(&http_origin, &stack_err_tx);
    info!("Submitted stake_err txid: {stack_err_txid}");
    expected_results.insert(stack_err_txid, Value::error(Value::UInt(0)).unwrap());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Stack successfully with stackers[1] with two allowances
    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT + 100);
    let stack_2_ok_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let stack_2_ok_txid = submit_tx(&http_origin, &stack_2_ok_tx);
    info!("Submitted stake_2_ok_txid txid: {stack_2_ok_txid}");
    expected_results.insert(stack_2_ok_txid, Value::okay_true());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Fail to stack with stackers[2] with two allowances (both too small)
    let stacker = &stackers[2];
    let stacker_addr = tests::to_addr(stacker);
    let mut stacker_nonce = 1;

    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 100);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 1000);
    let stack_2_both_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let stack_2_both_err_txid = submit_tx(&http_origin, &stack_2_both_err_tx);
    info!("Submitted stake_2_both_err txid: {stack_2_both_err_txid}");
    expected_results.insert(stack_2_both_err_txid, Value::error(Value::UInt(0)).unwrap());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Fail to stack with stackers[2] with two allowances (first too small)
    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 100);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);

    let stack_2_first_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let stack_2_first_err_txid = submit_tx(&http_origin, &stack_2_first_err_tx);
    info!("Submitted stake_2_first_err txid: {stack_2_first_err_txid}");
    expected_results.insert(
        stack_2_first_err_txid,
        Value::error(Value::UInt(0)).unwrap(),
    );
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Fail to stack with stackers[2] with two allowances (second too small)
    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 100);

    let stack_2_second_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let stack_2_second_err_txid = submit_tx(&http_origin, &stack_2_second_err_tx);
    info!("Submitted stake_2_second_err txid: {stack_2_second_err_txid}");
    expected_results.insert(
        stack_2_second_err_txid,
        Value::error(Value::UInt(1)).unwrap(),
    );
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Fail to stack with stackers[2] with no allowance
    let stack_no_allowance_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake-no-allowance",
        &[amount.clone()],
    );
    stacker_nonce += 1;
    let stack_no_allowance_err_txid = submit_tx(&http_origin, &stack_no_allowance_err_tx);
    info!("Submitted stake_no_allowance_err txid: {stack_no_allowance_err_txid}");
    expected_results.insert(
        stack_no_allowance_err_txid,
        Value::error(Value::UInt(128)).unwrap(),
    );
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Stack successfully with stackers[2] with with-all-assets-unsafe
    let stack_all_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "stake-all",
        &[amount.clone()],
    );
    stacker_nonce += 1;
    let stack_all_txid = submit_tx(&http_origin, &stack_all_tx);
    info!("Submitted stack_all txid: {stack_all_txid}");
    expected_results.insert(stack_all_txid, Value::okay_true());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    wait_for(60, || {
        for (addr, expected_nonce) in &wait_for_nonce {
            let cur_nonce = get_account(&http_origin, addr).nonce;
            if cur_nonce != *expected_nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for contract calls");

    let blocks = test_observer::get_blocks();
    let mut found = 0;
    for block in blocks.iter() {
        for tx in block.get("transactions").unwrap().as_array().unwrap() {
            let txid = tx
                .get("txid")
                .unwrap()
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap();
            if let Some(expected) = expected_results.get(txid) {
                let raw_result = tx.get("raw_result").unwrap().as_str().unwrap();
                let parsed = Value::try_deserialize_hex_untyped(&raw_result[2..]).unwrap();
                found += 1;
                assert_eq!(&parsed, expected, "Txid {txid} should have expected result");
            } else {
                // If there are any txids we don't expect, panic, because it probably means
                // there is an error in the test itself.
                panic!("Found unexpected txid: {txid}");
            }
        }
    }

    assert_eq!(
        found,
        expected_results.len(),
        "Should have found all expected txs"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// Verify the `with-stacking` allowances work as expected when calling
/// `register-for-bond` on pox-5. Mirrors `check_with_stacking_allowances_stake`
/// but locks STX through the bond path (with sBTC sats supplied via the
/// `(err sbtc-amount)` branch of `btc-lockup`) instead of the STX-only
/// `stake` entrypoint.
fn check_with_stacking_allowances_register_for_bond() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let mut signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    enable_epoch_4_0(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.burnchain.chain_id = CHAIN_ID_TESTNET + 1;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_signer_sk = Secp256k1PrivateKey::random();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);

    let signer_sk = signers.signer_keys[0].clone();
    let signer_pk = StacksPublicKey::from_private(&signer_sk);

    // setup sender + recipient for some test stx transfers
    // these are necessary for the interim blocks to get mined at all
    let sender_addr = tests::to_addr(&sender_sk);
    let deploy_fee = 3000;
    let call_fee = 400;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        deploy_fee + call_fee * 30,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // Set the sBTC token and registry contracts, which we will deploy before
    // epoch 4.0
    let sbtc_deployer_sk = Secp256k1PrivateKey::random();
    let sbtc_deployer_addr = tests::to_addr(&sbtc_deployer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sbtc_deployer_addr.clone()).to_string(),
        2 * deploy_fee,
    );
    let sbtc_token_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-token").unwrap(),
    );
    let sbtc_registry_id = QualifiedContractIdentifier::new(
        sbtc_deployer_addr.clone().into(),
        clarity::vm::ContractName::try_from("sbtc-registry").unwrap(),
    );
    naka_conf.node.pox_5_sbtc_contract = Some(sbtc_token_id.clone());
    naka_conf.node.pox_5_sbtc_registry_contract = Some(sbtc_registry_id.clone());

    // The pox-5 boot contract initializes its `bond-admin` data var to
    // `tx-sender`, which at boot deploy time is the unsignable boot
    // principal. Override it to a key we control so that `setup-bond` is
    // callable from the test (forbidden on mainnet).
    let bond_admin_sk = Secp256k1PrivateKey::random();
    let bond_admin_addr = tests::to_addr(&bond_admin_sk);
    // setup-bond carries a 683-byte buffer and a 3-entry allowlist, so the
    // node prices it well above the small `call_fee` used for ordinary
    // contract calls (observed expected ~1099). Pay it generously.
    let setup_bond_fee = 5000u64;
    naka_conf.add_initial_balance(
        PrincipalData::from(bond_admin_addr.clone()).to_string(),
        setup_bond_fee + 1000,
    );
    naka_conf.node.pox_5_bond_admin = Some(PrincipalData::from(bond_admin_addr.clone()));

    // Default stacker used for bootstrapping
    let stacker_sk = setup_stacker(&mut naka_conf);

    // Stackers used for testing
    let stackers: Vec<_> = (0..3).map(|_| setup_stacker(&mut naka_conf)).collect();

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
        blocks_processed, ..
    } = run_loop.counters();
    let counters = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let pubkey_bytes: [u8; 33] = signer_pk
        .to_bytes_compressed()
        .try_into()
        .expect("compressed secp256k1 pubkey should be 33 bytes");
    boot_to_epoch_4_0(
        &naka_conf,
        &blocks_processed,
        &counters,
        &coord_channel,
        &[stacker_sk.clone()],
        &[sender_signer_sk],
        &[],
        &sbtc_deployer_sk,
        Some(&pubkey_bytes),
        deploy_fee,
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );

    let mut sender_nonce = 0;

    // Deploy the signer contract — same shape as `check_with_stacking_allowances_stake`.
    let signer_contract = pox5_signer_manager_source();
    let contract_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        "test-signer",
        signer_contract,
    );
    sender_nonce += 1;
    let deploy_txid = submit_tx(&http_origin, &contract_tx);
    info!("Submitted signer contract deploy txid: {deploy_txid}");

    wait_for(60, || {
        let cur_sender_nonce = get_account(&http_origin, &to_addr(&sender_sk)).nonce;
        Ok(cur_sender_nonce == sender_nonce)
    })
    .expect("Timed out waiting for signer contract deploy");

    let info = get_chain_info_result(&naka_conf).unwrap();
    let last_stacks_block_height = info.stacks_tip_height as u128;

    next_block_and_mine_commit(&mut btc_regtest_controller, 60, &naka_conf, &counters).unwrap();

    // Test contract: each entry-point calls `pox-5.register-for-bond` from
    // inside a different `restrict-assets?` shape. The bond is set up at
    // `bond-index = 0`, every staker is allowlisted for `SBTC_AMT` sats,
    // and `(err sbtc-amount)` selects the sBTC lockup branch in pox-5.
    // `with-stacking` allowances cover `amount-ustx`; the `(with-ft …)`
    // entry covers the sBTC transfer pox-5 makes via `lock-sbtc`.
    //
    // The `register-for-bond-all` variant uses `as-contract? + with-all-assets-unsafe`,
    // which is the only place the unsafe allowance is permitted. Inside it
    // the contract becomes the staker, so we add the contract to the bond
    // allowlist below and have it pull the staker's sBTC into itself
    // before the inner call.
    let signer_key_hex = Value::buff_from(signer_pk.to_bytes_compressed()).unwrap();
    let contract_name = "test-contract";
    const SBTC_AMT: u128 = 1_000_000;
    let sbtc_token_principal = sbtc_token_id.to_string();
    let contract = format!(
        r#"
(define-constant signer-key {signer_key_hex})
(define-constant sbtc-amount u{SBTC_AMT})
(define-constant sbtc-contract '{sbtc_token_principal})
(define-public (register-for-bond (amount uint) (allowed uint))
  (restrict-assets? tx-sender ((with-stacking allowed) (with-ft sbtc-contract "sbtc-token" sbtc-amount))
    (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-for-bond
      u0 .test-signer amount (err sbtc-amount) none
    ))
    true
  )
)
(define-public (register-for-bond-2-allowances (amount uint) (allowed-1 uint) (allowed-2 uint))
  (restrict-assets? tx-sender ((with-stacking allowed-1) (with-stacking allowed-2) (with-ft sbtc-contract "sbtc-token" sbtc-amount))
    (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-for-bond
      u0 .test-signer amount (err sbtc-amount) none
    ))
    true
  )
)
(define-public (register-for-bond-no-allowance (amount uint))
  (restrict-assets? tx-sender ()
    (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-for-bond
      u0 .test-signer amount (err sbtc-amount) none
    ))
    true
  )
)
(define-public (register-for-bond-all (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender current-contract))
    (try! (contract-call? '{sbtc_token_principal} transfer
      sbtc-amount tx-sender current-contract none
    ))
    (as-contract? ((with-all-assets-unsafe))
      (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-for-bond
        u0 .test-signer amount (err sbtc-amount) none
      ))
      true
    )
  )
)
"#
    );

    let contract_tx = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        naka_conf.burnchain.chain_id,
        contract_name,
        &contract,
    );
    sender_nonce += 1;
    let deploy_txid = submit_tx(&http_origin, &contract_tx);
    info!("Submitted deploy txid: {deploy_txid}");

    let mut stacks_block_height = 0;
    wait_for(60, || {
        let cur_sender_nonce = get_account(&http_origin, &to_addr(&sender_sk)).nonce;
        let info = get_chain_info_result(&naka_conf).unwrap();
        stacks_block_height = info.stacks_tip_height as u128;
        Ok(stacks_block_height > last_stacks_block_height && cur_sender_nonce == sender_nonce)
    })
    .expect("Timed out waiting for contracts to publish");

    next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 30, &coord_channel)
        .unwrap();

    // Register the signer (same flow as the stake test).
    let test_signer_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from("test-signer").unwrap(),
    ));
    let auth_id: u128 = 1;
    let signer_grant_sig =
        stacks::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature(
            &test_signer_principal,
            auth_id,
            naka_conf.burnchain.chain_id,
            &signer_sk,
        )
        .expect("Failed to generate signer grant signature");
    let register_tx = make_contract_call(
        &sender_sk,
        sender_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        "test-signer",
        "register-self",
        &[
            Value::Principal(test_signer_principal.clone()),
            Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            Value::UInt(auth_id),
            Value::buff_from(signer_grant_sig.to_rsv()).unwrap(),
        ],
    );
    sender_nonce += 1;
    let register_txid = submit_tx(&http_origin, &register_tx);
    info!("Submitted register-self txid: {register_txid}");
    wait_for(60, || {
        let cur_sender_nonce = get_account(&http_origin, &to_addr(&sender_sk)).nonce;
        Ok(cur_sender_nonce == sender_nonce)
    })
    .expect("Timed out waiting for register-self to confirm");

    let pox_5_id = boot_code_id("pox-5", false);

    // Setup bond 0 from the configured bond admin. Allowlist all three
    // stackers for `SBTC_AMT` sats each, plus the test contract — under
    // `register-for-bond-all`, `as-contract?` switches tx-sender to the
    // contract, so it must also be in the allowlist. With
    // `stx-value-ratio = 100` and `min-ustx-ratio = 10000`
    // (== 100% in basis points),
    // `min-ustx-for-sats-amount(SBTC_AMT, 100, 10000) = SBTC_AMT` ustx — so
    // any `amount-ustx >= SBTC_AMT` satisfies the bond's STX floor.
    let test_contract_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender_addr.clone().into(),
        clarity::vm::ContractName::try_from(contract_name).unwrap(),
    ));
    let allowlist_entry = |principal: PrincipalData| {
        clarity::vm::Value::Tuple(
            clarity::vm::types::TupleData::from_data(vec![
                (
                    ClarityName::try_from("staker").unwrap(),
                    Value::Principal(principal),
                ),
                (
                    ClarityName::try_from("max-sats").unwrap(),
                    Value::UInt(SBTC_AMT),
                ),
            ])
            .unwrap(),
        )
    };
    let mut allowlist_entries: Vec<Value> = stackers
        .iter()
        .map(|sk| allowlist_entry(tests::to_addr(sk).into()))
        .collect();
    allowlist_entries.push(allowlist_entry(test_contract_principal.clone()));
    let allowlist_value = Value::cons_list_unsanitized(allowlist_entries).unwrap();
    let setup_bond_tx = make_contract_call(
        &bond_admin_sk,
        0,
        setup_bond_fee,
        naka_conf.burnchain.chain_id,
        &pox_5_id.issuer.clone().into(),
        "pox-5",
        "setup-bond",
        &[
            Value::UInt(0),
            Value::UInt(1000),
            Value::UInt(100),
            Value::UInt(10000),
            Value::buff_from(vec![0u8; 683]).unwrap(),
            Value::Principal(bond_admin_addr.clone().into()),
            allowlist_value,
        ],
    );
    let setup_bond_txid = submit_tx(&http_origin, &setup_bond_tx);
    info!("Submitted setup-bond txid: {setup_bond_txid}");
    wait_for(60, || {
        let cur_nonce = get_account(&http_origin, &bond_admin_addr).nonce;
        Ok(cur_nonce == 1)
    })
    .expect("Timed out waiting for setup-bond");

    // Mint sBTC to each stacker so their `register-for-bond` can lock
    // `SBTC_AMT` sats via the sBTC branch. The sBTC stub's `mint` has no
    // caller restriction, so each stacker mints to themselves at nonce 0.
    // pox-5 then transfers from `tx-sender` (the staker) into pox-5.
    for stacker in stackers.iter() {
        let stacker_addr = tests::to_addr(stacker);
        let mint_tx = make_contract_call(
            stacker,
            0,
            call_fee,
            naka_conf.burnchain.chain_id,
            &sbtc_deployer_addr,
            "sbtc-token",
            "mint",
            &[
                Value::UInt(SBTC_AMT),
                Value::Principal(stacker_addr.clone().into()),
            ],
        );
        let mint_txid = submit_tx(&http_origin, &mint_tx);
        info!("Submitted sbtc mint txid: {mint_txid} for {stacker_addr}");
    }
    wait_for(60, || {
        for stacker in stackers.iter() {
            let stacker_addr = tests::to_addr(stacker);
            if get_account(&http_origin, &stacker_addr).nonce != 1 {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for sbtc mints");

    // Each stacker calls pox-5 indirectly through the test contract, so
    // they must first authorize the test contract as an allowed
    // contract-caller. Otherwise pox-5's `check-caller-allowed` returns
    // `ERR_UNAUTHORIZED_CALLER` (u22).
    let mut allow_nonces = HashMap::new();
    for stacker in stackers.iter() {
        let stacker_addr = tests::to_addr(stacker);
        let allow_tx = make_contract_call(
            stacker,
            1,
            call_fee,
            naka_conf.burnchain.chain_id,
            &pox_5_id.issuer.clone().into(),
            "pox-5",
            "allow-contract-caller",
            &[
                Value::Principal(test_contract_principal.clone()),
                Value::none(),
            ],
        );
        let txid = submit_tx(&http_origin, &allow_tx);
        info!("Submitted allow-contract-caller txid: {txid} for {stacker_addr}");
        allow_nonces.insert(stacker_addr, 2);
    }
    wait_for(60, || {
        for (addr, expected_nonce) in &allow_nonces {
            if get_account(&http_origin, addr).nonce != *expected_nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for allow-contract-caller");

    test_observer::clear();

    // amount-ustx is what gets locked under `with-stacking`. Match the
    // pattern from `check_with_stacking_allowances_stake` and use
    // POX_DEFAULT_STACKER_STX_AMT — well above the bond's `SBTC_AMT` ustx
    // floor and well below the stacker's STX balance.
    let amount = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);

    // Map txid to expected result.
    let mut expected_results = HashMap::new();
    let mut wait_for_nonce = HashMap::new();

    // ***** Successfully register-for-bond with stackers[0]
    let stacker = &stackers[0];
    let stacker_addr = tests::to_addr(stacker);
    // nonces 0 (mint), 1 (allow-contract-caller) consumed above.
    let mut stacker_nonce = 2;

    let ok_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond",
        &[amount.clone(), amount.clone()],
    );
    stacker_nonce += 1;
    let ok_txid = submit_tx(&http_origin, &ok_tx);
    info!("Submitted register-for-bond ok txid: {ok_txid}");
    expected_results.insert(ok_txid, Value::okay_true());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Fail to register-for-bond with stackers[1] — single allowance too small
    let stacker = &stackers[1];
    let stacker_addr = tests::to_addr(stacker);
    let mut stacker_nonce = 2;

    let allowed = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 1);
    let err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond",
        &[amount.clone(), allowed],
    );
    stacker_nonce += 1;
    let err_txid = submit_tx(&http_origin, &err_tx);
    info!("Submitted register-for-bond err txid: {err_txid}");
    expected_results.insert(err_txid, Value::error(Value::UInt(0)).unwrap());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** Successfully register-for-bond with stackers[1] — two allowances
    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT + 100);
    let two_ok_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let two_ok_txid = submit_tx(&http_origin, &two_ok_tx);
    info!("Submitted register-for-bond-2-allowances ok txid: {two_ok_txid}");
    expected_results.insert(two_ok_txid, Value::okay_true());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** stackers[2] — both allowances too small
    let stacker = &stackers[2];
    let stacker_addr = tests::to_addr(stacker);
    let mut stacker_nonce = 2;

    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 100);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 1000);
    let two_both_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let two_both_err_txid = submit_tx(&http_origin, &two_both_err_tx);
    info!("Submitted register-for-bond-2-allowances both err txid: {two_both_err_txid}");
    expected_results.insert(two_both_err_txid, Value::error(Value::UInt(0)).unwrap());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** stackers[2] — first allowance too small
    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 100);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);
    let two_first_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let two_first_err_txid = submit_tx(&http_origin, &two_first_err_tx);
    info!("Submitted register-for-bond-2-allowances first err txid: {two_first_err_txid}");
    expected_results.insert(two_first_err_txid, Value::error(Value::UInt(0)).unwrap());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** stackers[2] — second allowance too small
    let allowed1 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT);
    let allowed2 = Value::UInt(POX_DEFAULT_STACKER_STX_AMT - 100);
    let two_second_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond-2-allowances",
        &[amount.clone(), allowed1, allowed2],
    );
    stacker_nonce += 1;
    let two_second_err_txid = submit_tx(&http_origin, &two_second_err_tx);
    info!("Submitted register-for-bond-2-allowances second err txid: {two_second_err_txid}");
    expected_results.insert(two_second_err_txid, Value::error(Value::UInt(1)).unwrap());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** stackers[2] — empty restrict-assets allowances
    let no_allowance_err_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond-no-allowance",
        &[amount.clone()],
    );
    stacker_nonce += 1;
    let no_allowance_err_txid = submit_tx(&http_origin, &no_allowance_err_tx);
    info!("Submitted register-for-bond-no-allowance err txid: {no_allowance_err_txid}");
    expected_results.insert(
        no_allowance_err_txid,
        Value::error(Value::UInt(128)).unwrap(),
    );
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    // ***** stackers[2] — `with-all-assets-unsafe` succeeds
    let all_tx = make_contract_call(
        stacker,
        stacker_nonce,
        call_fee,
        naka_conf.burnchain.chain_id,
        &sender_addr,
        contract_name,
        "register-for-bond-all",
        &[amount.clone()],
    );
    stacker_nonce += 1;
    let all_txid = submit_tx(&http_origin, &all_tx);
    info!("Submitted register-for-bond-all txid: {all_txid}");
    expected_results.insert(all_txid, Value::okay_true());
    wait_for_nonce.insert(stacker_addr.clone(), stacker_nonce);

    wait_for(60, || {
        for (addr, expected_nonce) in &wait_for_nonce {
            let cur_nonce = get_account(&http_origin, addr).nonce;
            if cur_nonce != *expected_nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for contract calls");

    let blocks = test_observer::get_blocks();
    let mut found = 0;
    for block in blocks.iter() {
        for tx in block.get("transactions").unwrap().as_array().unwrap() {
            let txid = tx
                .get("txid")
                .unwrap()
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap();
            if let Some(expected) = expected_results.get(txid) {
                let raw_result = tx.get("raw_result").unwrap().as_str().unwrap();
                let parsed = Value::try_deserialize_hex_untyped(&raw_result[2..]).unwrap();
                found += 1;
                assert_eq!(&parsed, expected, "Txid {txid} should have expected result");
            } else {
                panic!("Found unexpected txid: {txid}");
            }
        }
    }

    assert_eq!(
        found,
        expected_results.len(),
        "Should have found all expected txs"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}
