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

//! End-to-end integration tests for the pox-5 L1 (Bitcoin) bond-lockup
//! lifecycle.
//!
//! These tests exercise the L1 branch of `register-for-bond`: locking real
//! sats into the canonical timelock P2WSH derived from
//! `construct-lockup-output-script`, proving the lockup to the contract, and
//! later sweeping the BTC via either the OP_IF (timelock-matured) or OP_ELSE
//! (early-exit) branch of `construct-lockup-script`.

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
    next_block_and_mine_commit, setup_stacker, wait_for, POX_DEFAULT_STACKER_STX_AMT,
};
use crate::tests::neon_integrations::{
    call_read_only, get_account, get_chain_info_result, submit_tx, test_observer, wait_for_runloop,
};
use crate::tests::signer::v0::pox5_signer_manager_source;
use crate::tests::{make_contract_publish, to_addr};
use crate::{tests, BitcoinRegtestController, Config, Keychain};

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
    // `(ok { outputs, unlock-bytes })` branch.
    //
    // `unlock-bytes` is the Bitcoin Script subscript the OP_IF
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
                Value::cons_list_unsanitized(vec![lockup_output]).unwrap(),
            ),
            (
                ClarityName::try_from("unlock-bytes").unwrap(),
                Value::buff_from(lockup_unlock_bytes.clone()).unwrap(),
            ),
        ])
        .unwrap(),
    );
    let l1_lockup_arg = Value::okay(lockup_tuple).expect("failed to wrap lockup tuple in (ok ...)");

    // 3) `register-for-bond` via the L1 lockup branch.
    let register_fee = 2000u64;
    let bond_amount = POX_DEFAULT_STACKER_STX_AMT;
    let staker_balance_before = get_account(&http_origin, &staker_addr).balance;
    assert!(staker_balance_before >= bond_amount + register_fee as u128 * 2);

    let sbtc_balance_before = sbtc_balance(&naka_conf, &sbtc_deployer_addr, &staker_addr);

    test_observer::clear();
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
            l1_lockup_arg.clone(),
            Value::none(),
        ],
    );
    let register_txid = submit_tx(&http_origin, &register_tx);
    info!("Submitted pox-5 register-for-bond (L1 lockup) txid: {register_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &staker_addr).nonce == 1
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

    // 4) A second `register-for-bond` from the same staker via the L1 path
    // must still fail with `ERR_ALREADY_REGISTERED` (u9) — the duplicate
    // check sits after `verify-l1-lockups` runs.
    test_observer::clear();
    let dup_tx = make_contract_call(
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
            l1_lockup_arg,
            Value::none(),
        ],
    );
    let dup_txid = submit_tx(&http_origin, &dup_tx);
    info!("Submitted duplicate pox-5 register-for-bond (L1) txid: {dup_txid}");
    wait_for(60, || {
        Ok(get_account(&http_origin, &staker_addr).nonce == 2
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

    // 5) Spend the L1 lockup once the on-chain timelock matures.
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
    //   - the OP_IF branch's `<staker_unlock_pk> OP_CHECKSIG` (the
    //     inlined `unlock_bytes`) accepts a witness signature for the
    //     spend's BIP-143 sighash.
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
/// only spendable when the caller supplies a properly shaped
/// `unlock-bytes` and `early-unlock-bytes` subscripts.
///
/// `construct-lockup-script`'s OP_ELSE branch concatenates
/// `<early-unlock-bytes> <unlock-bytes>` and ends with OP_ENDIF.
///
/// This test demonstrates the realistic script shapes:
///
///   - `unlock-bytes  = <unlock_pk>  OP_CHECKSIG` (35 bytes, ends 0xac)
///   - `early-unlock-bytes = <early_pk> OP_CHECKSIGVERIFY` (35 bytes, ends 0xad)
///   - Lock 1_000_000 sats into the canonical timelock P2WSH and
///     `register-for-bond` with the lockup tuple.
///
/// All four sweep attempts run *before* `unlock-burn-height`, so the
/// OP_IF branch is unavailable (its CLTV would fail) and the only path
/// the BTC can move is the OP_ELSE branch:
///
///   1. Both sigs from random keys → mempool rejects (one of the
///      CHECKSIG/CHECKSIGVERIFY opcodes returns false).
///   2. Only the owner sig (early sig from a random key) → rejects:
///      OP_CHECKSIGVERIFY fails the script outright.
///   3. Only the early sig (owner sig from a random key) → rejects:
///      the closing OP_CHECKSIG returns false.
///   4. Both sigs from the correct keys, branch flag empty (selects
///      OP_ELSE) → confirms; the BTC moves to a bondholder-controlled
///      address before the timelock matures.
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
        deploy_fee + call_fee * 10,
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
    //   - `staker_unlock_sk` (owner) closes both branches of the witness
    //     script via `<unlock_pk> OP_CHECKSIG`.
    //   - `early_unlock_sk` is the early-exit signer; its sig is
    //     consumed by OP_CHECKSIGVERIFY at the head of the OP_ELSE
    //     branch (subscript ending `0xad`).
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

    // `unlock-bytes` = `<unlock_pk> OP_CHECKSIG`
    let mut lockup_unlock_bytes = Vec::with_capacity(1 + 33 + 1);
    lockup_unlock_bytes.push(0x21); // OP_PUSHBYTES_33
    lockup_unlock_bytes.extend_from_slice(&staker_unlock_pk_bytes);
    lockup_unlock_bytes.push(0xac); // OP_CHECKSIG

    // `early-unlock-bytes` = `<early_pk> OP_CHECKSIGVERIFY`
    // The OP_ELSE branch is `<early-unlock-bytes> <unlock-bytes>`
    let mut early_unlock_bytes = Vec::with_capacity(1 + 33 + 1);
    early_unlock_bytes.push(0x21); // OP_PUSHBYTES_33
    early_unlock_bytes.extend_from_slice(&early_unlock_pk_bytes);
    early_unlock_bytes.push(0xad); // OP_CHECKSIGVERIFY

    // 1) `setup-bond` from the configured bond admin, with the
    // CHECKSIGVERIFY-terminated early-unlock subscript.
    const BTC_LOCKUP_SATS: u128 = 1_000_000;
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
                ClarityName::try_from("unlock-bytes").unwrap(),
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
    // OP_ELSE branch. The witness stack is laid out so OP_ELSE's
    // `<early_pk> OP_CHECKSIGVERIFY  <unlock_pk> OP_CHECKSIG` sees
    // `sig_early` on top of `sig_owner`:
    //   - witness items are pushed left-to-right; the first item ends
    //     up at the *bottom* of the stack;
    //   - after OP_IF pops the (empty) branch flag, the stack is
    //     [sig_owner, sig_early];
    //   - CHECKSIGVERIFY pops `<early_pk>` and `sig_early`, fails the
    //     script if invalid, leaves [sig_owner];
    //   - CHECKSIG pops `<unlock_pk>` and `sig_owner`, pushes 1;
    //   - final stack: [1] — one item, OP_ENDIF, script succeeds.
    let build_joint_sweep =
        |owner_sk: &Secp256k1PrivateKey,
         early_sk: &Secp256k1PrivateKey|
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
                // OP_CHECKSIG will consume.
                sig_owner,
                // Above it: the sig that OP_CHECKSIGVERIFY consumes first.
                sig_early,
                // Empty buffer = false (MINIMALIF-compliant): OP_IF takes
                // the OP_ELSE branch.
                vec![],
                // P2WSH preimage; bitcoind checks sha256(this) ==
                // witness_program before executing.
                timelock_script.clone(),
            ];

            tx
        };

    // (a) Both sigs from random keys.
    let tx_both_wrong = build_joint_sweep(
        &Secp256k1PrivateKey::random(),
        &Secp256k1PrivateKey::random(),
    );
    let res_both_wrong =
        bondholder_rpc.send_raw_transaction(&tx_both_wrong, Some(0.0), Some(1_000_000));
    let err_both_wrong = res_both_wrong
        .err()
        .expect("both-wrong-sigs early-exit sweep must be rejected by the script's CHECKSIGs");
    info!("Both-wrong-sigs early-exit sweep rejected as expected: {err_both_wrong:?}");

    // (b) Owner sig correct, early sig from a random key.
    let tx_no_early = build_joint_sweep(&staker_unlock_sk, &Secp256k1PrivateKey::random());
    let res_no_early =
        bondholder_rpc.send_raw_transaction(&tx_no_early, Some(0.0), Some(1_000_000));
    let err_no_early = res_no_early
        .err()
        .expect("missing-early-sig sweep must be rejected by OP_CHECKSIGVERIFY");
    info!(
        "Owner-only early-exit sweep rejected (CHECKSIGVERIFY on the early sig fails): \
         {err_no_early:?}"
    );

    // (c) Early sig correct, owner sig from a random key.
    let tx_no_owner = build_joint_sweep(&Secp256k1PrivateKey::random(), &early_unlock_sk);
    let res_no_owner =
        bondholder_rpc.send_raw_transaction(&tx_no_owner, Some(0.0), Some(1_000_000));
    let err_no_owner = res_no_owner
        .err()
        .expect("missing-owner-sig sweep must be rejected by the closing OP_CHECKSIG");
    info!(
        "Early-only early-exit sweep rejected (closing CHECKSIG on the owner sig fails): \
         {err_no_owner:?}"
    );

    // (d) Both sigs from the correct keys -> confirms.
    let joint_sweep_tx = build_joint_sweep(&staker_unlock_sk, &early_unlock_sk);
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
    assert_eq!(
        announce_result,
        Value::okay_true(),
        "announce-l1-early-exit should return (ok true) when called by the early-unlock admin with the matching signer-manager"
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
