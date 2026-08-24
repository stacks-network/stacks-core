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
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::leader_block_commit::{
    RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS,
};
use stacks::chainstate::burn::operations::LeaderBlockCommitOp;
use stacks::chainstate::nakamoto::coordinator::get_nakamoto_next_recipients;
use stacks::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
use stacks::chainstate::stacks::boot::POX_5_NAME;
use stacks::chainstate::stacks::db::{DiskChainStateBackend, StacksChainState};
use stacks::chainstate::stacks::sbtc::sbtc_pox5_deposit_taproot_output_key;
use stacks::config::Config;
use stacks::core::{StacksEpochId, POX_5_SBTC_DEPOSIT_MAX_FEE_SATS};
use stacks::types::chainstate::{StacksBlockId, StacksPrivateKey};
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use stacks_signer::v0::SpawnedSigner;

use super::SignerTest;
use crate::tests::nakamoto_integrations::{naka_neon_integration_conf, wait_for};
use crate::tests::neon_integrations::{get_chain_info, next_block_and_wait_with_timeout};
use crate::tests::to_addr;
use crate::BitcoinRegtestController;

/// Configure a compact Epoch 3.x runway and ten-block PoX cycles.
/// The Epoch 3.0 reward-set calculation still has four burn blocks after the
/// initial stacking transactions, while Epoch 4.0 leaves a full cycle for the
/// sBTC stubs and PoX-5 registrations before the waterfall boundary.
pub(super) fn enable_compact_epoch_4_0(node_config: &mut Config) {
    const EPOCH_30_START: u64 = 212;
    const EPOCH_31_START: u64 = 215;
    const EPOCH_32_START: u64 = 216;
    const EPOCH_33_START: u64 = 217;
    const EPOCH_34_START: u64 = 218;
    const EPOCH_40_START: u64 = 222;

    node_config.burnchain.pox_reward_length = Some(10);
    let epochs = node_config
        .burnchain
        .epochs
        .as_mut()
        .expect("test requires configured epochs");
    epochs[StacksEpochId::Epoch25].end_height = EPOCH_30_START;
    epochs[StacksEpochId::Epoch30].start_height = EPOCH_30_START;
    epochs[StacksEpochId::Epoch30].end_height = EPOCH_31_START;
    epochs[StacksEpochId::Epoch31].start_height = EPOCH_31_START;
    epochs[StacksEpochId::Epoch31].end_height = EPOCH_32_START;
    epochs[StacksEpochId::Epoch32].start_height = EPOCH_32_START;
    epochs[StacksEpochId::Epoch32].end_height = EPOCH_33_START;
    epochs[StacksEpochId::Epoch33].start_height = EPOCH_33_START;
    epochs[StacksEpochId::Epoch33].end_height = EPOCH_34_START;
    epochs[StacksEpochId::Epoch34].start_height = EPOCH_34_START;
    epochs[StacksEpochId::Epoch34].end_height = EPOCH_40_START;
    epochs[StacksEpochId::Epoch40].start_height = EPOCH_40_START;
}

#[test]
fn compact_epoch_4_0_schedule_is_valid() {
    let (mut config, _) = naka_neon_integration_conf(None);
    enable_compact_epoch_4_0(&mut config);

    let burnchain = config.get_burnchain();
    assert_eq!(
        burnchain
            .pox_constants
            .first_pox_waterfall_block(burnchain.first_block_height),
        Some(230),
    );
}

/// Compute the expected sBTC PoxAddress recipient
pub fn make_sbtc_recipient_fixture(pubkey: &[u8; 33], is_mainnet: bool) -> PoxAddress {
    let recipient = PrincipalData::Contract(boot_code_id(POX_5_NAME, is_mainnet));
    let output_key =
        sbtc_pox5_deposit_taproot_output_key(pubkey, &recipient, POX_5_SBTC_DEPOSIT_MAX_FEE_SATS)
            .expect("sBTC P2TR derivation failed for fixture");
    PoxAddress::Addr32(is_mainnet, PoxAddressType32::P2TR, output_key)
}

/// Get a waterfall commit that targets a child of `burn_parent_height`.
pub fn get_unconfirmed_waterfall_commit_for_burn_parent(
    btc_controller: &BitcoinRegtestController,
    miner_pk: &Secp256k1PublicKey,
    burn_parent_height: u64,
    sbtc_script_pubkey: &[u8],
) -> Option<BitcoinTransaction> {
    let expected_modulus = u8::try_from(burn_parent_height % BURN_BLOCK_MINED_AT_MODULUS)
        .expect("burn-parent modulus fits in a byte");

    btc_controller
        .get_all_utxos(miner_pk)
        .into_iter()
        .filter(|utxo| utxo.confirmations == 0)
        .find_map(|utxo| {
            let txid = Txid::from_bitcoin_tx_hash(&utxo.txid);
            // A listed mempool UTXO can disappear before getrawtransaction if
            // the miner RBF-replaces its commit. Continue polling the current
            // mempool rather than turning that expected race into a retry.
            let tx = btc_controller.try_get_raw_transaction(&txid).ok()?;
            let op_return = tx.output.first()?.script_pubkey.as_bytes();
            let payload_start = op_return.len().checked_sub(77)?;
            let payload = LeaderBlockCommitOp::parse_data(op_return.get(payload_start..)?)?;
            (payload.burn_parent_modulus == expected_modulus
                && tx.output.len() == 3
                && tx.output[1].script_pubkey.as_bytes() == sbtc_script_pubkey)
                .then_some(tx)
        })
}

/// Wait until every node view resolves the expected PoX-5 waterfall recipient.
pub(super) fn wait_for_waterfall_commit_recipients(
    configs: &[&Config],
    expected_sbtc_address: &PoxAddress,
    timeout_secs: u64,
) -> Result<(), String> {
    let mut views = Vec::with_capacity(configs.len());
    for conf in configs {
        let burnchain = conf.get_burnchain();
        let sortdb = burnchain
            .open_sortition_db(true)
            .map_err(|error| format!("open sortition DB: {error}"))?;
        let (chainstate, _) = StacksChainState::<DiskChainStateBackend>::open(
            conf.is_mainnet(),
            conf.burnchain.chain_id,
            &conf.get_chainstate_path_str(),
            None,
        )
        .map_err(|error| format!("open chainstate: {error}"))?;
        views.push((burnchain, sortdb, chainstate));
    }

    wait_for(timeout_secs, || {
        for (burnchain, sortdb, chainstate) in &mut views {
            let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
                .map_err(|error| format!("load canonical burn tip: {error}"))?;
            let (consensus_hash, block_hash) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())
                    .map_err(|error| format!("load canonical stacks tip: {error}"))?;
            let stacks_tip = StacksBlockId::new(&consensus_hash, &block_hash);
            let Ok(Some(RewardSetInfo::Waterfall(waterfall))) = get_nakamoto_next_recipients(
                &sortition_tip,
                sortdb,
                chainstate,
                &stacks_tip,
                burnchain,
            ) else {
                return Ok(false);
            };
            if &waterfall.sbtc_address != expected_sbtc_address {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .map_err(|error| {
        format!("node views did not resolve the expected waterfall recipient: {error}")
    })
}

/// Wait for a waterfall commit targeting a child of `burn_parent_height`.
fn wait_for_unconfirmed_waterfall_commit_for_burn_parent<Z: super::SpawnedSignerTrait>(
    signer_test: &SignerTest<Z>,
    miner_pk: &Secp256k1PublicKey,
    burn_parent_height: u64,
    sbtc_script_pubkey: &[u8],
    timeout_secs: u64,
) -> BitcoinTransaction {
    let counters = &signer_test.running_nodes.counters;
    let btc_controller = &signer_test.running_nodes.btc_regtest_controller;
    let mut commit_tx = None;
    wait_for(timeout_secs, || {
        if counters.naka_submitted_commit_last_burn_height.get() < burn_parent_height {
            return Ok(false);
        }
        commit_tx = get_unconfirmed_waterfall_commit_for_burn_parent(
            btc_controller,
            miner_pk,
            burn_parent_height,
            sbtc_script_pubkey,
        );
        Ok(commit_tx.is_some())
    })
    .unwrap_or_else(|error| {
        panic!(
            "timed out waiting for an unconfirmed waterfall commit for burn parent \
             {burn_parent_height}; last submitted commit used burn parent {}: {error}",
            counters.naka_submitted_commit_last_burn_height.get()
        )
    });
    commit_tx.expect("unconfirmed block commit disappeared after it was observed")
}

/// Assert that a block commit uses the PoX-5 waterfall output layout.
fn assert_waterfall_commit(tx: &BitcoinTransaction, sbtc_script_pubkey: &[u8]) {
    assert_eq!(
        tx.output.len(),
        3,
        "waterfall commit must have exactly 3 outputs (op_return + sbtc + change), got {}",
        tx.output.len()
    );
    assert_eq!(
        tx.output[1].script_pubkey.as_bytes(),
        sbtc_script_pubkey,
        "waterfall commit did not pay its PoX output to the configured sBTC recipient"
    );
}

/// Advance through non-critical burn blocks and return the commit targeting
/// `target_block`.
fn advance_to_commit_for_block<Z: super::SpawnedSignerTrait>(
    signer_test: &SignerTest<Z>,
    miner_pk: &Secp256k1PublicKey,
    target_block: u64,
    sbtc_script_pubkey: &[u8],
    timeout_secs: u64,
) -> BitcoinTransaction {
    let target_parent = target_block
        .checked_sub(1)
        .expect("target burn block has a parent");
    while get_chain_info(&signer_test.running_nodes.conf).burn_block_height < target_parent {
        assert!(
            next_block_and_wait_with_timeout(
                &signer_test.running_nodes.btc_regtest_controller,
                &signer_test.running_nodes.counters.blocks_processed,
                timeout_secs,
            ),
            "timed out advancing toward burn block {target_block}"
        );
    }

    let info = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(
        info.burn_block_height, target_parent,
        "advanced past target burn block {target_block}"
    );

    wait_for_unconfirmed_waterfall_commit_for_burn_parent(
        signer_test,
        miner_pk,
        target_parent,
        sbtc_script_pubkey,
        timeout_secs,
    )
}

/// Cross the first waterfall transition only after the miner can resolve its
/// PoX-5 recipient, then return the refreshed commit for the boundary block.
fn advance_to_first_waterfall_commit<Z: super::SpawnedSignerTrait>(
    signer_test: &SignerTest<Z>,
    miner_pk: &Secp256k1PublicKey,
    target_block: u64,
    expected_sbtc_address: &PoxAddress,
    sbtc_script_pubkey: &[u8],
    timeout_secs: u64,
) -> BitcoinTransaction {
    let transition_parent = target_block
        .checked_sub(2)
        .expect("waterfall boundary has a preceding burn block");
    while get_chain_info(&signer_test.running_nodes.conf).burn_block_height < transition_parent {
        assert!(
            next_block_and_wait_with_timeout(
                &signer_test.running_nodes.btc_regtest_controller,
                &signer_test.running_nodes.counters.blocks_processed,
                timeout_secs,
            ),
            "timed out advancing toward the first waterfall block {target_block}"
        );
    }

    let conf = &signer_test.running_nodes.conf;
    assert_eq!(
        get_chain_info(conf).burn_block_height,
        transition_parent,
        "advanced past the first waterfall transition"
    );

    let skip_commit_op = &signer_test.running_nodes.counters.skip_commit_op;
    skip_commit_op.set(true);
    let transition_result = if next_block_and_wait_with_timeout(
        &signer_test.running_nodes.btc_regtest_controller,
        &signer_test.running_nodes.counters.blocks_processed,
        timeout_secs,
    ) {
        wait_for_waterfall_commit_recipients(&[conf], expected_sbtc_address, timeout_secs)
    } else {
        Err(format!(
            "timed out mining the parent of waterfall block {target_block}"
        ))
    };
    skip_commit_op.set(false);
    transition_result.unwrap_or_else(|error| {
        panic!("failed to settle the first waterfall reward-set transition: {error}")
    });

    wait_for_unconfirmed_waterfall_commit_for_burn_parent(
        signer_test,
        miner_pk,
        target_block - 1,
        sbtc_script_pubkey,
        timeout_secs,
    )
}

/// Mine a waterfall boundary and verify the commit for its successor.
fn mine_boundary_and_assert_next_waterfall_commit<Z: super::SpawnedSignerTrait>(
    signer_test: &SignerTest<Z>,
    miner_pk: &Secp256k1PublicKey,
    expected_burn_block: u64,
    sbtc_script_pubkey: &[u8],
    timeout: Duration,
) {
    assert!(
        next_block_and_wait_with_timeout(
            &signer_test.running_nodes.btc_regtest_controller,
            &signer_test.running_nodes.counters.blocks_processed,
            timeout.as_secs(),
        ),
        "timed out mining waterfall boundary {expected_burn_block}"
    );
    let info = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(
        info.burn_block_height, expected_burn_block,
        "mined an unexpected burn block at a waterfall boundary"
    );
    let tx = wait_for_unconfirmed_waterfall_commit_for_burn_parent(
        signer_test,
        miner_pk,
        expected_burn_block,
        sbtc_script_pubkey,
        timeout.as_secs(),
    );
    assert_waterfall_commit(&tx, sbtc_script_pubkey);
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
    const TENURE_TIMEOUT: Duration = Duration::from_secs(60);

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
                enable_compact_epoch_4_0(node_config);
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

    let burnchain = conf.get_burnchain();
    let first_waterfall_block = burnchain
        .pox_constants
        .first_pox_waterfall_block(burnchain.first_block_height)
        .expect("PoX-5 activation follows the burnchain's first block");
    let waterfall_cycle = burnchain
        .block_height_to_reward_cycle(first_waterfall_block)
        .expect("first waterfall block belongs to a reward cycle");
    let next_cycle_start = burnchain.nakamoto_first_block_of_cycle(waterfall_cycle + 1);
    let first_prepare_block = next_cycle_start
        .checked_sub(u64::from(burnchain.pox_constants.prepare_length).saturating_sub(1))
        .expect("prepare phase starts before the next reward cycle");
    assert!(
        burnchain.is_in_naka_prepare_phase(first_prepare_block),
        "derived prepare-phase boundary is not in the prepare phase"
    );
    assert!(
        !burnchain.is_in_naka_prepare_phase(first_prepare_block - 1),
        "derived prepare-phase boundary does not start the prepare phase"
    );

    let initial_stacks_tip = get_chain_info(&conf).stacks_tip_height;

    // Commits target the next burn block. Check both sides of each meaningful
    // transition while fast-forwarding the intervening reward-phase blocks.
    let tx = advance_to_first_waterfall_commit(
        &signer_test,
        &miner_pk,
        first_waterfall_block,
        &sbtc_recipient,
        sbtc_script_pubkey.as_bytes(),
        TENURE_TIMEOUT.as_secs(),
    );
    assert_waterfall_commit(&tx, sbtc_script_pubkey.as_bytes());
    info!(
        "------------------------- Observed commit for first waterfall block {first_waterfall_block} -------------------------"
    );
    mine_boundary_and_assert_next_waterfall_commit(
        &signer_test,
        &miner_pk,
        first_waterfall_block,
        sbtc_script_pubkey.as_bytes(),
        TENURE_TIMEOUT,
    );

    let tx = advance_to_commit_for_block(
        &signer_test,
        &miner_pk,
        first_prepare_block,
        sbtc_script_pubkey.as_bytes(),
        TENURE_TIMEOUT.as_secs(),
    );
    assert_waterfall_commit(&tx, sbtc_script_pubkey.as_bytes());
    let reward_phase_tip = get_chain_info(&conf).stacks_tip_height;
    assert!(
        reward_phase_tip > initial_stacks_tip,
        "Stacks chain did not advance during the waterfall reward phase"
    );
    mine_boundary_and_assert_next_waterfall_commit(
        &signer_test,
        &miner_pk,
        first_prepare_block,
        sbtc_script_pubkey.as_bytes(),
        TENURE_TIMEOUT,
    );

    let tx = advance_to_commit_for_block(
        &signer_test,
        &miner_pk,
        next_cycle_start,
        sbtc_script_pubkey.as_bytes(),
        TENURE_TIMEOUT.as_secs(),
    );
    assert_waterfall_commit(&tx, sbtc_script_pubkey.as_bytes());
    let prepare_phase_tip = get_chain_info(&conf).stacks_tip_height;
    assert!(
        prepare_phase_tip > reward_phase_tip,
        "Stacks chain did not advance during the waterfall prepare phase"
    );
    mine_boundary_and_assert_next_waterfall_commit(
        &signer_test,
        &miner_pk,
        next_cycle_start,
        sbtc_script_pubkey.as_bytes(),
        TENURE_TIMEOUT,
    );

    let final_info = get_chain_info(&conf);
    assert!(
        final_info.stacks_tip_height > initial_stacks_tip,
        "Stacks chain did not advance while traversing the waterfall reward cycle"
    );
    assert!(
        final_info.burn_block_height == next_cycle_start,
        "did not stop at the next waterfall reward-cycle boundary"
    );

    signer_test.shutdown();
}
