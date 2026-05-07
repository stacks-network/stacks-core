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
//! "waterfall" leader block commits.
//!
//! The aggregate-pubkey contract is published by `boot_to_epoch_4`.
//!
//! This uses two test overrides so that the integration test can run
//!  without PoX-5 being in place yet:
//!
//! * `TEST_FORCE_POX_5_ACTIVE` makes the PoX-5 dispatch arm reachable as soon
//!   as `epoch >= Epoch40`. (Without it `PoxConstants::active_pox_contract`
//!   never returns `pox-5`.)
//! * `TEST_WATERFALL_SIGNER_SET_OVERRIDE` short-circuits the read against the
//!   (placeholder) PoX-5 contract body and supplies a hardcoded signer set.
//!
//! These override SHOULD BE REMOVED when PoX-5 initial versions land

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::ContractName;
use pinny::tag;
use stacks::burnchains::Txid;
use stacks::chainstate::nakamoto::signer_set::{
    TEST_FORCE_POX_5_ACTIVE, TEST_WATERFALL_SIGNER_SET_OVERRIDE,
};
use stacks::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
use stacks::chainstate::stacks::boot::POX_5_NAME;
use stacks::chainstate::stacks::sbtc::sbtc_deposit_taproot_output_key;
use stacks::core::POX_5_SBTC_DEPOSIT_MAX_FEE_SATS;
use stacks::types::chainstate::StacksPrivateKey;
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use stacks_signer::v0::SpawnedSigner;

use super::SignerTest;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, next_block_and_wait};
use crate::tests::to_addr;
use crate::BitcoinRegtestController;

/// Compute the expected sBTC PoxAddress recipient
fn make_sbtc_recipient_fixture(pubkey: &[u8; 33], is_mainnet: bool) -> PoxAddress {
    let recipient = PrincipalData::Contract(boot_code_id(POX_5_NAME, is_mainnet));
    let output_key =
        sbtc_deposit_taproot_output_key(pubkey, &recipient, POX_5_SBTC_DEPOSIT_MAX_FEE_SATS)
            .expect("sBTC P2TR derivation failed for fixture");
    PoxAddress::Addr32(is_mainnet, PoxAddressType32::P2TR, output_key)
}

/// Derive `(signer_key, amount_ustx)` pairs from the test's signer private keys
/// for use as a hardcoded signer-set fixture.
fn signer_pairs_from_keys(keys: &[StacksPrivateKey]) -> Vec<([u8; 33], u128)> {
    keys.iter()
        .map(|sk| {
            let signer_key: [u8; 33] = Secp256k1PublicKey::from_private(sk)
                .to_bytes_compressed()
                .try_into()
                .expect("compressed secp256k1 pubkey is 33 bytes");
            (signer_key, 100_000_000_000_u128)
        })
        .collect()
}

/// Populate the override map for a wide span of reward cycles
fn override_map_all_cycles(pairs: Vec<([u8; 33], u128)>) -> HashMap<u64, Vec<([u8; 33], u128)>> {
    let mut map = HashMap::new();
    for cycle in 0..1_000 {
        map.insert(cycle, pairs.clone());
    }
    map
}

/// Pre-generate signer keys deterministically so the override can be derived
/// before `SignerTest` is constructed.
fn pre_generate_signer_keys(num_signers: usize, seed_tag: &str) -> Vec<StacksPrivateKey> {
    (0..num_signers)
        .map(|i| StacksPrivateKey::from_seed(format!("signer_{i}_{seed_tag}").as_bytes()))
        .collect()
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
#[tag(slow, bitcoind)]
#[test]
#[ignore]
fn epoch_4_0_block_commit_uses_single_sbtc_output() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let signer_keys = pre_generate_signer_keys(num_signers, "epoch_4_0_basic");
    let signer_pairs = signer_pairs_from_keys(&signer_keys);

    let agg_pubkey: [u8; 33] =
        Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(b"epoch-4-0-waterfall-agg"))
            .to_bytes_compressed()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes");

    // Spender that publishes the contract.
    let spender_sk = StacksPrivateKey::from_seed(b"epoch-4-0-waterfall-publisher");
    let spender_addr = to_addr(&spender_sk);
    let contract_name = "agg-pubkey-stub";
    let contract_id = QualifiedContractIdentifier::new(
        spender_addr.clone().into(),
        ContractName::try_from(contract_name.to_string()).expect("valid contract name"),
    );

    // Install signer-set override and PoX-5 routing fault-injection BEFORE
    // constructing the test harness so any burnchain activity that triggers
    // the PoX-5 path picks them up.
    TEST_WATERFALL_SIGNER_SET_OVERRIDE.set(override_map_all_cycles(signer_pairs));
    TEST_FORCE_POX_5_ACTIVE.set(true);

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(spender_addr, 1_000_000)],
        |_| {},
        |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.node.pox_5_sbtc_contract = Some(contract_id.clone());
        },
        None,
        Some(signer_keys),
    );

    let conf = signer_test.running_nodes.conf.clone();
    let miner_pk = get_miner_pubkey(&signer_test);
    let sbtc_recipient = make_sbtc_recipient_fixture(&agg_pubkey, conf.is_mainnet());
    let sbtc_script_pubkey = sbtc_recipient.clone().to_bitcoin_tx_out(0).script_pubkey;

    signer_test.boot_to_epoch_4(&spender_sk, 0, contract_name, &agg_pubkey);
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
    let blocks_processed = signer_test.running_nodes.counters.blocks_processed.clone();
    let target_steady_state_waterfalls = 3;
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
        // Best-effort wait for a Stacks block in the (possibly new) tenure;
        // tolerate timeouts caused by missed sortitions.
        let _ = wait_for(30, || {
            Ok(get_chain_info(&conf).stacks_tip_height > last_stacks_tip)
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
