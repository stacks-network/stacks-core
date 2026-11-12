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

//! Integration tests covering the Epoch 4.0 transition to PoX-5 / sBTC
//! "waterfall" leader block commits, and the Epoch 4.1 switch of the
//! waterfall recipient from the sBTC v1 (aggregate-key) deposit to the v2
//! (Taproot multisig) deposit.
//!
//! Signer registration is driven through real pox-5 stake calls via
//! `SignerTest::boot_to_epoch_4_with_pox5_lockups`; no test-only signer-set
//! override is used. PoX-5 activation is wired through
//! `PoxConstants::pox_5_activation_height`, which `Config::apply_test_settings`
//! aligns to `epochs[Epoch40].start_height`.

use std::env;
use std::time::Duration;

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::ContractName;
use stacks::burnchains::Txid;
use stacks::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
use stacks::chainstate::stacks::boot::POX_5_NAME;
use stacks::chainstate::stacks::sbtc::{
    sbtc_pox5_deposit_taproot_output_key, sbtc_pox5_v2_deposit_taproot_output_key, SbtcSignerKeySet,
};
use stacks::core::POX_5_SBTC_DEPOSIT_MAX_FEE_SATS;
use stacks::types::chainstate::StacksPrivateKey;
use stacks::types::StacksEpochId;
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use stacks_common::util::hash::hex_bytes;
use stacks_signer::v0::SpawnedSigner;

use super::{SignerTest, SBTC_REGISTRY_STUB_SIGNATURE_THRESHOLD, SBTC_REGISTRY_STUB_SIGNER_KEYS};
use crate::tests::nakamoto_integrations::{enable_epoch_4_0, enable_epoch_4_1, wait_for};
use crate::tests::neon_integrations::{get_chain_info, next_block_and_wait};
use crate::tests::to_addr;
use crate::BitcoinRegtestController;

/// Compute the expected Epoch 4.0 sBTC PoxAddress recipient: the v1 deposit
/// locked by the registry stub's aggregate pubkey.
fn make_sbtc_recipient_fixture(pubkey: &[u8; 33], is_mainnet: bool) -> PoxAddress {
    let recipient = PrincipalData::Contract(boot_code_id(POX_5_NAME, is_mainnet));
    let output_key =
        sbtc_pox5_deposit_taproot_output_key(pubkey, &recipient, POX_5_SBTC_DEPOSIT_MAX_FEE_SATS)
            .expect("sBTC P2TR derivation failed for fixture");
    PoxAddress::Addr32(is_mainnet, PoxAddressType32::P2TR, output_key)
}

/// Compute the expected Epoch 4.1+ sBTC PoxAddress recipient: the v2 Taproot
/// multisig deposit locked by the registry stub's `get-current-signer-data`
/// signer set.
fn make_sbtc_v2_recipient_fixture(is_mainnet: bool) -> PoxAddress {
    let signer_keys: Vec<[u8; 33]> = SBTC_REGISTRY_STUB_SIGNER_KEYS
        .iter()
        .map(|key| {
            hex_bytes(key)
                .expect("stub signer key is hex")
                .try_into()
                .expect("stub signer key is 33 bytes")
        })
        .collect();
    let key_set =
        SbtcSignerKeySet::from_registry(&signer_keys, SBTC_REGISTRY_STUB_SIGNATURE_THRESHOLD)
            .expect("stub signer set is a valid v2 key set");
    let recipient = PrincipalData::Contract(boot_code_id(POX_5_NAME, is_mainnet));
    let output_key = sbtc_pox5_v2_deposit_taproot_output_key(
        &key_set,
        &recipient,
        POX_5_SBTC_DEPOSIT_MAX_FEE_SATS,
    )
    .expect("sBTC v2 P2TR derivation failed for fixture");
    PoxAddress::Addr32(is_mainnet, PoxAddressType32::P2TR, output_key)
}

/// Which sBTC recipient a block commit's first PoX output pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SbtcCommitOutput {
    /// Epoch 4.0 aggregate-key deposit.
    V1,
    /// Epoch 4.1+ Taproot multisig deposit.
    V2,
}

/// Get the most recent unconfirmed block-commit bitcoin transaction, if one
/// is in the mempool.
fn get_unconfirmed_commit_tx(
    btc_controller: &BitcoinRegtestController,
    miner_pk: &Secp256k1PublicKey,
) -> Option<BitcoinTransaction> {
    let unconfirmed_utxo = btc_controller
        .get_all_utxos(miner_pk)
        .into_iter()
        .find(|utxo| utxo.confirmations == 0)?;
    let unconfirmed_txid = Txid::from_bitcoin_tx_hash(&unconfirmed_utxo.txid);
    Some(btc_controller.get_raw_transaction(&unconfirmed_txid))
}

/// Returns the miner's bitcoin pubkey for the test node.
fn get_miner_pubkey<Z: super::SpawnedSignerTrait>(
    signer_test: &SignerTest<Z>,
) -> Secp256k1PublicKey {
    signer_test
        .running_nodes
        .btc_regtest_controller
        .get_mining_pubkey()
        .as_deref()
        .map(Secp256k1PublicKey::from_hex)
        .expect("mining pubkey configured")
        .expect("mining pubkey decodes")
}

/// After the Epoch 4.0 boundary, miners produce leader block commits
/// with a single PoX output paying to the configured sBTC recipient, and
/// blocks continue to assemble.
#[test]
#[ignore]
fn epoch_4_0_block_commit_uses_single_sbtc_output() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let stake_amount: u128 = 100_000_000_000;
    let lock_cycles: u128 = 12;

    let agg_pubkey: [u8; 33] =
        Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(b"epoch-4-0-waterfall-agg"))
            .to_bytes_compressed()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes");

    let spender_sk = StacksPrivateKey::from_seed(b"epoch-4-0-waterfall-publisher");
    let spender_addr = to_addr(&spender_sk);
    let token_contract_name = "sbtc-token-stub";
    let registry_contract_name = "sbtc-registry-stub";
    let token_contract_id = QualifiedContractIdentifier::new(
        spender_addr.clone().into(),
        ContractName::try_from(token_contract_name.to_string()).expect("valid contract name"),
    );
    let registry_contract_id = QualifiedContractIdentifier::new(
        spender_addr.clone().into(),
        ContractName::try_from(registry_contract_name.to_string()).expect("valid contract name"),
    );

    let initial_balances = vec![(spender_addr, 1_000_000)];

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            initial_balances,
            |_| {},
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.node.pox_5_sbtc_contract = Some(token_contract_id.clone());
                node_config.node.pox_5_sbtc_registry_contract = Some(registry_contract_id.clone());
                enable_epoch_4_0(node_config);
            },
            None,
            None,
            Some(function_name!()),
        );
    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = signer_test.running_nodes.conf.clone();
    let miner_pk = get_miner_pubkey(&signer_test);
    let sbtc_recipient = make_sbtc_recipient_fixture(&agg_pubkey, conf.is_mainnet());
    let sbtc_script_pubkey = sbtc_recipient.clone().to_bitcoin_tx_out(0).script_pubkey;

    signer_test.boot_to_epoch_4_with_pox5_lockups(
        &spender_sk,
        0,
        token_contract_name,
        registry_contract_name,
        &agg_pubkey,
        stake_amount,
        lock_cycles,
    );
    info!("------------------------- Reached Epoch 4.0 -------------------------");

    // Mine until we observe a block-commit whose first PoX output equals the
    // configured sBTC recipient.
    let max_tenures = 30;
    let mut waterfall_observed = false;
    for i in 0..max_tenures {
        let burn_height = get_chain_info(&conf).burn_block_height;
        info!("Mining tenure {} (burn_height={burn_height})", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(60), true);
        signer_test.check_signer_states_normal();
        let Some(tx) =
            get_unconfirmed_commit_tx(&signer_test.running_nodes.btc_regtest_controller, &miner_pk)
        else {
            continue;
        };
        if tx.output.len() >= 2 && tx.output[1].script_pubkey == sbtc_script_pubkey {
            assert_eq!(
                tx.output.len(),
                3,
                "waterfall commit must have exactly 3 outputs (op_return + sbtc + change), got {}",
                tx.output.len()
            );
            waterfall_observed = true;
            info!(
                "------------------------- Observed waterfall block commit at burn_height={burn_height} -------------------------"
            );
            break;
        }
    }

    assert!(
        waterfall_observed,
        "no waterfall block commit (paying to the configured sBTC recipient) observed in \
         {max_tenures} tenures"
    );

    // Mine more bitcoin blocks and confirm the chain keeps producing waterfall
    // block commits to the sBTC recipient.
    //
    // Make sure to span a full reward cycle past the first waterfall
    // observation to ensure we cover the prepare-phase blocks of the
    // first waterfall cycle and the mod-0 transition into the next
    // cycle.
    let blocks_processed = signer_test.running_nodes.counters.blocks_processed.clone();
    let target_steady_state_waterfalls = 30;
    let mut steady_state_waterfalls = 0;
    let mut last_stacks_tip = get_chain_info(&conf).stacks_tip_height;
    for i in 0..(target_steady_state_waterfalls * 4) {
        if steady_state_waterfalls >= target_steady_state_waterfalls {
            break;
        }
        info!(
            "Steady-state bitcoin block {} (waterfalls observed {}/{})",
            i + 1,
            steady_state_waterfalls,
            target_steady_state_waterfalls
        );
        next_block_and_wait(
            &signer_test.running_nodes.btc_regtest_controller,
            &blocks_processed,
        );
        // Require Stacks tip advancement: miners emit waterfall-shaped
        // commits even when signers reject every proposal, so without this
        // the waterfall counter ticks while the chain is dead.
        wait_for(30, || {
            Ok(get_chain_info(&conf).stacks_tip_height > last_stacks_tip)
        })
        .unwrap_or_else(|e| {
            panic!(
                "Stacks chain did not advance after bitcoin block (last_stacks_tip={last_stacks_tip}, \
                 burn_height={}): {e}",
                get_chain_info(&conf).burn_block_height,
            )
        });
        last_stacks_tip = get_chain_info(&conf).stacks_tip_height;
        let Some(tx) =
            get_unconfirmed_commit_tx(&signer_test.running_nodes.btc_regtest_controller, &miner_pk)
        else {
            continue;
        };
        if tx.output.len() >= 2 && tx.output[1].script_pubkey == sbtc_script_pubkey {
            steady_state_waterfalls += 1;
            info!(
                "Steady-state waterfall block commit #{steady_state_waterfalls} observed at burn_height={}",
                get_chain_info(&conf).burn_block_height
            );
        }
    }

    assert!(
        steady_state_waterfalls >= target_steady_state_waterfalls,
        "expected {target_steady_state_waterfalls} steady-state waterfall block commits, only \
         observed {steady_state_waterfalls}"
    );

    signer_test.shutdown();
}

/// Across the Epoch 4.1 boundary, miners keep paying the v1 (aggregate-key)
/// sBTC recipient until the first reward cycle whose reward set was computed
/// in Epoch 4.1, then pay the v2 (Taproot multisig) recipient and never the
/// v1 recipient again. With `enable_epoch_4_1` placing the boundary inside a
/// reward cycle, the switch lands on the following cycle.
#[test]
#[ignore]
fn epoch_4_1_block_commit_switches_to_sbtc_v2_output() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let stake_amount: u128 = 100_000_000_000;
    let lock_cycles: u128 = 12;

    let agg_pubkey: [u8; 33] =
        Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(b"epoch-4-1-waterfall-agg"))
            .to_bytes_compressed()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes");

    let spender_sk = StacksPrivateKey::from_seed(b"epoch-4-1-waterfall-publisher");
    let spender_addr = to_addr(&spender_sk);
    let token_contract_name = "sbtc-token-stub";
    let registry_contract_name = "sbtc-registry-stub";
    let token_contract_id = QualifiedContractIdentifier::new(
        spender_addr.clone().into(),
        ContractName::try_from(token_contract_name.to_string()).expect("valid contract name"),
    );
    let registry_contract_id = QualifiedContractIdentifier::new(
        spender_addr.clone().into(),
        ContractName::try_from(registry_contract_name.to_string()).expect("valid contract name"),
    );

    let initial_balances = vec![(spender_addr, 1_000_000)];

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            initial_balances,
            |_| {},
            |node_config| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.node.pox_5_sbtc_contract = Some(token_contract_id.clone());
                node_config.node.pox_5_sbtc_registry_contract = Some(registry_contract_id.clone());
                enable_epoch_4_0(node_config);
                enable_epoch_4_1(node_config);
            },
            None,
            None,
            Some(function_name!()),
        );
    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = signer_test.running_nodes.conf.clone();
    let miner_pk = get_miner_pubkey(&signer_test);
    let v1_script_pubkey = make_sbtc_recipient_fixture(&agg_pubkey, conf.is_mainnet())
        .to_bitcoin_tx_out(0)
        .script_pubkey;
    let v2_script_pubkey = make_sbtc_v2_recipient_fixture(conf.is_mainnet())
        .to_bitcoin_tx_out(0)
        .script_pubkey;
    assert_ne!(v1_script_pubkey, v2_script_pubkey);
    let classify = |tx: &BitcoinTransaction| -> Option<SbtcCommitOutput> {
        let output = tx.output.get(1)?;
        if output.script_pubkey == v1_script_pubkey {
            Some(SbtcCommitOutput::V1)
        } else if output.script_pubkey == v2_script_pubkey {
            Some(SbtcCommitOutput::V2)
        } else {
            None
        }
    };

    let epoch_41_start = conf
        .burnchain
        .epochs
        .as_ref()
        .and_then(|epochs| epochs.get(StacksEpochId::Epoch41))
        .map(|epoch| epoch.start_height)
        .expect("Epoch 4.1 configured");

    signer_test.boot_to_epoch_4_with_pox5_lockups(
        &spender_sk,
        0,
        token_contract_name,
        registry_contract_name,
        &agg_pubkey,
        stake_amount,
        lock_cycles,
    );
    info!("------------------------- Reached Epoch 4.0 -------------------------");

    // Phase 1: reach the first (v1) waterfall block commit, still in Epoch 4.0.
    let max_tenures = 30;
    let mut waterfall_observed = false;
    for i in 0..max_tenures {
        let burn_height = get_chain_info(&conf).burn_block_height;
        info!("Mining tenure {} (burn_height={burn_height})", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(60), true);
        signer_test.check_signer_states_normal();
        let Some(tx) =
            get_unconfirmed_commit_tx(&signer_test.running_nodes.btc_regtest_controller, &miner_pk)
        else {
            continue;
        };
        match classify(&tx) {
            Some(SbtcCommitOutput::V1) => {
                assert_eq!(
                    tx.output.len(),
                    3,
                    "waterfall commit must have exactly 3 outputs (op_return + sbtc + change), got {}",
                    tx.output.len()
                );
                waterfall_observed = true;
                info!(
                    "------------------------- Observed v1 waterfall block commit at burn_height={burn_height} -------------------------"
                );
                break;
            }
            Some(SbtcCommitOutput::V2) => {
                panic!("v2 sBTC output at burn_height={burn_height}, before Epoch 4.1 ({epoch_41_start})")
            }
            None => {}
        }
    }
    assert!(
        waterfall_observed,
        "no v1 waterfall block commit observed in {max_tenures} tenures"
    );
    let burn_height = get_chain_info(&conf).burn_block_height;
    assert!(
        burn_height < epoch_41_start,
        "the first waterfall commit must be observed before Epoch 4.1 ({epoch_41_start}) for \
         this test to exercise the switch; burn_height={burn_height}"
    );

    // The reward set for cycle N is computed in the prepare phase that ends
    // cycle N-1, and the epoch of that computation selects the deposit
    // format. So the first v2 commit lands on the first block of the first
    // cycle whose preceding prepare phase starts in Epoch 4.1. Like the
    // waterfall start itself, that is the Nakamoto (mod 0) cycle start.
    let burnchain = conf.get_burnchain();
    let pox_constants = &burnchain.pox_constants;
    let first_burn_height = burnchain.first_block_height;
    let mut switch_cycle = pox_constants
        .block_height_to_reward_cycle(first_burn_height, epoch_41_start)
        .expect("Epoch 4.1 starts after the first burn block");
    while pox_constants.prepare_phase_start(first_burn_height, switch_cycle - 1) < epoch_41_start {
        switch_cycle += 1;
    }
    let expected_switch_height =
        pox_constants.nakamoto_first_block_of_cycle(first_burn_height, switch_cycle);
    assert!(
        expected_switch_height > epoch_41_start,
        "test geometry must place Epoch 4.1 ({epoch_41_start}) strictly before the v2 switch \
         ({expected_switch_height}) so the v1 recipient is still paid inside Epoch 4.1"
    );
    // Each block mined below is followed by the commit for the next block, so
    // the first commit observed in this phase targets `burn_height + 2`.
    assert!(
        burn_height + 2 <= epoch_41_start,
        "phase 2 must observe the commit for every block from Epoch 4.1 ({epoch_41_start}) \
         onward; burn_height={burn_height}"
    );
    info!(
        "------------------------- Expecting v2 switch at burn height {expected_switch_height} (cycle {switch_cycle}) -------------------------"
    );

    // Phase 2: mine bitcoin blocks through the Epoch 4.1 boundary and check the
    // recipient of the block commit for every block.
    let blocks_processed = signer_test.running_nodes.counters.blocks_processed.clone();
    let target_v2_commits = 10;
    let mut v2_commits = 0;
    let mut v1_commits_in_epoch_41 = 0;
    let mut last_stacks_tip = get_chain_info(&conf).stacks_tip_height;
    while v2_commits < target_v2_commits {
        next_block_and_wait(
            &signer_test.running_nodes.btc_regtest_controller,
            &blocks_processed,
        );
        // Require Stacks tip advancement so the counters below only tick
        // while the chain is live (see the Epoch 4.0 test).
        wait_for(30, || {
            Ok(get_chain_info(&conf).stacks_tip_height > last_stacks_tip)
        })
        .unwrap_or_else(|e| {
            panic!(
                "Stacks chain did not advance after bitcoin block (last_stacks_tip={last_stacks_tip}, \
                 burn_height={}): {e}",
                get_chain_info(&conf).burn_block_height,
            )
        });
        last_stacks_tip = get_chain_info(&conf).stacks_tip_height;
        let burn_height = get_chain_info(&conf).burn_block_height;
        // The unconfirmed commit at tip `burn_height` targets the next block.
        let target_height = burn_height + 1;
        let mut commit = None;
        wait_for(30, || {
            commit = get_unconfirmed_commit_tx(
                &signer_test.running_nodes.btc_regtest_controller,
                &miner_pk,
            );
            Ok(commit.is_some())
        })
        .unwrap_or_else(|e| {
            panic!("no block commit submitted for burn height {target_height}: {e}")
        });
        let tx = commit.expect("wait_for returned once a commit was found");
        let output = classify(&tx).unwrap_or_else(|| {
            panic!(
                "block commit for burn height {target_height} pays neither the v1 nor the v2 \
                 sBTC recipient: {tx:?}"
            )
        });
        assert_eq!(
            tx.output.len(),
            3,
            "waterfall commit must have exactly 3 outputs (op_return + sbtc + change), got {}",
            tx.output.len()
        );
        let expected_output = if target_height < expected_switch_height {
            SbtcCommitOutput::V1
        } else {
            SbtcCommitOutput::V2
        };
        assert_eq!(
            output, expected_output,
            "wrong sBTC recipient for the commit targeting burn height {target_height} (Epoch 4.1 \
             starts at {epoch_41_start}, v2 switch expected at {expected_switch_height})"
        );
        info!(
            "Block commit targeting burn height {target_height} pays {output:?}";
            "v2_commits" => v2_commits,
            "target_v2_commits" => target_v2_commits,
        );
        match output {
            SbtcCommitOutput::V1 if target_height >= epoch_41_start => v1_commits_in_epoch_41 += 1,
            SbtcCommitOutput::V1 => {}
            SbtcCommitOutput::V2 => v2_commits += 1,
        }
    }

    assert_eq!(
        v1_commits_in_epoch_41,
        expected_switch_height - epoch_41_start,
        "every block from Epoch 4.1 activation up to the v2 switch must pay the v1 recipient"
    );

    signer_test.shutdown();
}
