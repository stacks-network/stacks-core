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

//! Two-miner integration test for the burn-distribution / commit-windowing
//! path across the Epoch 4.0 boundary.
//!
//! With a single miner, dropped commits in the burn distribution don't
//! manifest as observable failures (the lone miner wins every sortition
//! regardless of effective burn). Two miners with deterministic asymmetric
//! fees give the math something to actually decide between, so a windowing
//! bug at the boundary surfaces as a failure mode the test can catch.
//!
//! Three deterministic assertions, all per-tenure:
//!
//! * Per-tenure burn distribution: `LATEST_BURN_DISTRIBUTION` (test hook in
//!   `make_min_median_distribution`) exposes the actual
//!   `Vec<BurnSamplePoint>` the chain computed for each sortition. We
//!   assert two samples (one chain per miner) and that the sorted `burns`
//!   values match `[MINER_1_FEE, MINER_2_FEE]`. Catches chaining failures
//!   that drop enough entries to shift the median for either miner, or
//!   that fail to construct one of the two chains entirely.
//! * Per-block commit count: every post-boundary burn block that has any
//!   commits has exactly two `pox_transactions` entries. Catches a
//!   parse-side regression that silently drops one miner's commit.
//! * Total commit fee invariant: sum of `reward_recipients` amounts equals
//!   the configured fee total per block. Catches dropped commits or a
//!   classification flip between burn-output and PoX-recipient paths.
//!
//! Signer registration is driven through real pox-5 stake calls via
//! `MultipleMinerTest::boot_to_epoch_4_with_pox5_lockups`; no test-only
//! signer-set override is used.

use std::env;
use std::time::Duration;

use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ContractName;
use pinny::tag;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::distribution::LATEST_BURN_DISTRIBUTION;
use stacks::chainstate::burn::operations::leader_block_commit::RewardSetInfo;
use stacks::chainstate::nakamoto::coordinator::get_nakamoto_next_recipients;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::db::{DiskChainStateBackend, StacksChainState};
use stacks::chainstate::stacks::events::BurnBlockEvent;
use stacks::core::{StacksEpochId, STACKS_EPOCH_MAX};
use stacks::types::chainstate::{StacksBlockId, StacksPrivateKey};
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks_common::types::MINING_COMMITMENT_WINDOW;

use super::{epoch_4_0_waterfall, MultipleMinerTest};
use crate::tests::nakamoto_integrations::{enable_epoch_4_0, wait_for};
use crate::tests::neon_integrations::test_observer;
use crate::tests::to_addr;

/// Per-miner deterministic burn fee (satoshis). Asymmetric so the burn
/// distribution actually has something to decide between.
const MINER_1_FEE: u64 = 5_000;
const MINER_2_FEE: u64 = 10_000;

/// Mine a complete commit window after the transition so every classic-PoX
/// commit has aged out of the burn-distribution calculation.
const POST_WATERFALL_TENURES: u64 = MINING_COMMITMENT_WINDOW as u64;

/// Allow a temporarily split signer view to converge without restarting the
/// entire multi-minute test.
const TENURE_SETTLE_TIMEOUT_SECS: u64 = 120;

/// Filter burn-block events to those at or after the Epoch 4.0 start height.
fn post_boundary_burn_blocks(epoch_40_start: u64) -> Vec<BurnBlockEvent> {
    test_observer::get_burn_blocks()
        .into_iter()
        .filter(|ev| ev.burn_block_height >= epoch_40_start)
        .collect()
}

/// Wait until both miners have valid waterfall commits for the next burn block.
fn wait_for_valid_waterfall_commits(
    miners: &MultipleMinerTest,
    miner_pks: [&Secp256k1PublicKey; 2],
    sbtc_script_pubkey: &[u8],
    timeout_secs: u64,
) -> Result<(), String> {
    let burn_parent_height = miners.get_peer_info().burn_block_height;
    wait_for(timeout_secs, || {
        Ok(miner_pks.iter().all(|miner_pk| {
            epoch_4_0_waterfall::get_unconfirmed_waterfall_commit_for_burn_parent(
                miners.btc_regtest_controller(),
                miner_pk,
                burn_parent_height,
                sbtc_script_pubkey,
            )
            .is_some()
        }))
    })
    .map_err(|error| {
        format!(
            "valid waterfall commits for burn parent {burn_parent_height} were not observed: {error}"
        )
    })
}

/// Wait until both miners' chainstate/sortition views resolve the expected
/// recipient through the same path used to build a block commit.
fn wait_for_waterfall_commit_recipients(
    miners: &MultipleMinerTest,
    expected_sbtc_address: &PoxAddress,
    timeout_secs: u64,
) -> Result<(), String> {
    let (conf_1, conf_2) = miners.get_node_configs();
    let mut views = Vec::with_capacity(2);
    for conf in [&conf_1, &conf_2] {
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
        format!("both miner views did not resolve the expected waterfall recipient: {error}")
    })
}

/// Two miners with asymmetric burn fees mine across the Epoch 4.0 boundary.
/// After the boundary, the burn distribution computed for each sortition
/// must contain both miners' chains with their configured fees as the
/// effective burn, and every burn block (with commits) must contain both
/// miners' commits with the fee sum invariant intact.
#[tag(slow, bitcoind)]
#[test]
#[ignore]
fn epoch_4_0_burn_distribution_chains_across_boundary() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let stake_amount: u128 = 100_000_000_000;
    let lock_cycles: u128 = 12;

    let agg_pubkey: [u8; 33] = Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(
        b"epoch-4-0-multi-miner-agg",
    ))
    .to_bytes_compressed()
    .try_into()
    .expect("compressed secp256k1 pubkey is 33 bytes");

    let publisher_sk = StacksPrivateKey::from_seed(b"epoch-4-0-multi-miner-publisher");
    let publisher_addr = to_addr(&publisher_sk);
    let token_contract_name = "sbtc-token-stub";
    let registry_contract_name = "sbtc-registry-stub";
    let token_contract_id = QualifiedContractIdentifier::new(
        publisher_addr.clone().into(),
        ContractName::try_from(token_contract_name.to_string()).expect("valid contract name"),
    );
    let registry_contract_id = QualifiedContractIdentifier::new(
        publisher_addr.clone().into(),
        ContractName::try_from(registry_contract_name.to_string()).expect("valid contract name"),
    );

    let publisher_addr_str = publisher_addr.to_string();
    let token_contract_id_modifier = token_contract_id.clone();
    let registry_contract_id_modifier = registry_contract_id.clone();

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |_| {},
        move |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.burnchain.burn_fee_cap = MINER_1_FEE;
            node_config.node.pox_5_sbtc_contract = Some(token_contract_id_modifier.clone());
            node_config.node.pox_5_sbtc_registry_contract =
                Some(registry_contract_id_modifier.clone());
            node_config.add_initial_balance(publisher_addr_str.clone(), 1_000_000);
            enable_epoch_4_0(node_config);
        },
        |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.burnchain.burn_fee_cap = MINER_2_FEE;
            enable_epoch_4_0(node_config);
        },
    );

    let (conf_1, conf_2) = miners.get_node_configs();
    let bitcoin_miner_pks = [&conf_1, &conf_2].map(|conf| {
        conf.burnchain
            .local_mining_public_key
            .as_deref()
            .map(Secp256k1PublicKey::from_hex)
            .transpose()
            .expect("configured Bitcoin mining public key must decode")
            .expect("Bitcoin mining public key must be configured")
    });
    let sbtc_recipient =
        epoch_4_0_waterfall::make_sbtc_recipient_fixture(&agg_pubkey, conf_1.is_mainnet());
    let sbtc_script_pubkey = sbtc_recipient.clone().to_bitcoin_tx_out(0).script_pubkey;
    let burnchain = conf_1.get_burnchain();
    let first_waterfall_block = burnchain
        .pox_constants
        .first_pox_waterfall_block(burnchain.first_block_height)
        .expect("PoX-5 waterfall boundary is configured");

    let epoch_40_start = conf_1
        .burnchain
        .epochs
        .as_ref()
        .and_then(|e| e.get(StacksEpochId::Epoch40))
        .map(|epoch| epoch.start_height)
        .filter(|h| *h < STACKS_EPOCH_MAX)
        .expect("test requires Epoch 4.0 configured");

    miners.boot_to_epoch_4_with_pox5_lockups(
        &publisher_sk,
        0,
        token_contract_name,
        registry_contract_name,
        &agg_pubkey,
        stake_amount,
        lock_cycles,
    );
    info!("------------------------- Reached Epoch 4.0 (multi-miner) -------------------------");

    // Mine N tenures past the boundary.
    //
    // After each BTC block, wait for both nodes and miners to settle on the
    // resulting tenure. Then read the captured
    // `LATEST_BURN_DISTRIBUTION` and assert per-tenure invariants on the
    // computed `Vec<BurnSamplePoint>`.
    let expected_burns = {
        let mut v = vec![MINER_1_FEE as u128, MINER_2_FEE as u128];
        v.sort();
        v
    };
    let final_burn_height = first_waterfall_block + POST_WATERFALL_TENURES;
    let mut i = 0;
    while miners.get_peer_info().burn_block_height < final_burn_height {
        let burn_height = miners.get_peer_info().burn_block_height;

        // The miners can observe parent(first_waterfall_block) before the
        // coordinator has made its PoX-5 reward set readable. If they submit
        // in that interval, the burn-address transaction remains their last
        // commit and no state change forces an RBF. Pause before processing
        // the boundary's parent, wait for both reward-set views, then resume;
        // the new burn view makes each miner issue a fresh waterfall commit.
        if burn_height == first_waterfall_block.saturating_sub(2) {
            miners.pause_commits_miner_1();
            miners.pause_commits_miner_2();
            let transition_result = miners
                .mine_bitcoin_block_and_wait_for_both_nodes(TENURE_SETTLE_TIMEOUT_SECS)
                .map(|_| ())
                .and_then(|_| {
                    wait_for_waterfall_commit_recipients(
                        &miners,
                        &sbtc_recipient,
                        TENURE_SETTLE_TIMEOUT_SECS,
                    )
                });
            miners.unpause_commits_miner_1();
            miners.unpause_commits_miner_2();
            transition_result.unwrap_or_else(|e| {
                panic!("failed to settle the waterfall reward-set transition: {e}")
            });
            miners
                .wait_for_both_miners_committed_to_current_tenure(TENURE_SETTLE_TIMEOUT_SECS)
                .unwrap_or_else(|e| panic!("failed to refresh waterfall commits: {e}"));
            continue;
        }

        let next_burn_height = burn_height.saturating_add(1);
        if next_burn_height >= first_waterfall_block {
            wait_for_valid_waterfall_commits(
                &miners,
                [&bitcoin_miner_pks[0], &bitcoin_miner_pks[1]],
                sbtc_script_pubkey.as_bytes(),
                TENURE_SETTLE_TIMEOUT_SECS,
            )
            .unwrap_or_else(|e| panic!("post-boundary tenure {i} has invalid commits: {e}"));
        }

        miners
            .mine_bitcoin_block_and_wait_for_both_miners(TENURE_SETTLE_TIMEOUT_SECS)
            .unwrap_or_else(|e| panic!("post-boundary tenure {i} failed: {e}"));

        let dist = LATEST_BURN_DISTRIBUTION
            .get_opt()
            .unwrap_or_else(|| panic!("tenure {i}: no burn distribution captured"));

        // Two miners both committing every block
        assert_eq!(
            dist.len(),
            2,
            "tenure {i}: expected 2 BurnSamplePoints (one per miner chain), got {}",
            dist.len(),
        );

        // With constant per-miner fees and an intact UTXO chain, each chain's
        // post-median effective burn equals the miner's configured fee.
        let mut burns: Vec<u128> = dist.iter().map(|s| s.burns).collect();
        burns.sort();
        assert_eq!(
            burns, expected_burns,
            "tenure {i}: burns mismatch (got {:?}, expected {:?})",
            burns, expected_burns,
        );
        i += 1;
    }

    // Per-block commit count + fee-sum invariant on burn events.
    let expected_fee_sum = MINER_1_FEE + MINER_2_FEE;
    let post_boundary = post_boundary_burn_blocks(epoch_40_start);
    for ev in post_boundary.iter() {
        let commit_count = ev.pox_transactions.len();
        if commit_count == 0 {
            continue;
        }

        assert_eq!(
            commit_count, 2,
            "burn_block_height={} had {} commits (expected 2, one from each miner)",
            ev.burn_block_height, commit_count,
        );

        let recipient_sum: u64 = ev.reward_recipients.iter().map(|r| r.amt).sum();
        assert_eq!(
            recipient_sum, expected_fee_sum,
            "burn_block_height={} reward_recipients summed to {recipient_sum} (expected \
             {expected_fee_sum} = MINER_1_FEE + MINER_2_FEE).",
            ev.burn_block_height,
        );
    }

    miners.shutdown();
}
