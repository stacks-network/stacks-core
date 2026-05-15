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
//! Signer registration is driven through real pox-5 stake calls via
//! `SignerTest::boot_to_epoch_4_with_pox5_lockups`; no test-only signer-set
//! override is used. PoX-5 activation is wired through
//! `PoxConstants::pox_5_activation_height`, which `Config::apply_test_settings`
//! aligns to `epochs[Epoch40].start_height`.

use std::env;
use std::time::Duration;

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::ContractName;
use pinny::tag;
use stacks::burnchains::Txid;
use stacks::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
use stacks::chainstate::stacks::boot::POX_5_NAME;
use stacks::chainstate::stacks::sbtc::sbtc_pox5_deposit_taproot_output_key;
use stacks::core::POX_5_SBTC_DEPOSIT_MAX_FEE_SATS;
use stacks::types::chainstate::StacksPrivateKey;
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use stacks_signer::v0::SpawnedSigner;

use super::{pox5_staker_initial_balances, pox5_staker_keys, SignerTest};
use crate::tests::nakamoto_integrations::{enable_epoch_4_0, wait_for};
use crate::tests::neon_integrations::{get_chain_info, next_block_and_wait};
use crate::tests::to_addr;
use crate::BitcoinRegtestController;

/// Compute the expected sBTC PoxAddress recipient
fn make_sbtc_recipient_fixture(pubkey: &[u8; 33], is_mainnet: bool) -> PoxAddress {
    let recipient = PrincipalData::Contract(boot_code_id(POX_5_NAME, is_mainnet));
    let output_key =
        sbtc_pox5_deposit_taproot_output_key(pubkey, &recipient, POX_5_SBTC_DEPOSIT_MAX_FEE_SATS)
            .expect("sBTC P2TR derivation failed for fixture");
    PoxAddress::Addr32(is_mainnet, PoxAddressType32::P2TR, output_key)
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
    let seed = "epoch_4_0_basic";
    let stake_amount: u128 = 100_000_000_000;
    let lock_cycles: u128 = 12;
    let stakers = pox5_staker_keys(num_signers, seed);
    let per_staker_balance: u64 = u64::try_from(stake_amount).unwrap() + 1_000_000;

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

    let mut initial_balances = vec![(spender_addr, 1_000_000)];
    initial_balances.extend(pox5_staker_initial_balances(
        num_signers,
        seed,
        per_staker_balance,
    ));

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
        &stakers,
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
