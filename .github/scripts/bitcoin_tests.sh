#!/usr/bin/env bash
# Generate a balanced test matrix for the Bitcoin integration test workflow.
#
# Discovers all ignored tests in the stacks-node binary via cargo nextest,
# removes a hardcoded exclude list, isolates slow tests into single-item batches,
# and chunks remaining tests into grouped batches.
#
# Optional env vars:
#   BATCH_SIZE       - Number of regular tests grouped into a single runner batch (default: 50)
#   NEXTEST_ARCHIVE  - Nextest archive to use (default: ./test_archive.tar.zst)
#   TEST_TAG_CI_SKIP - Tag name used to exclude tests from CI (default: ci_skip)
#
# Outputs:
#   GITHUB_OUTPUT  - Path to the GitHub Actions output file (set by runner)
set -euo pipefail

# Load logging functions from logging.sh for color and standardized output
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## --- Configuration ----------------------------------------------------------
batch_size="${BATCH_SIZE:-50}"
nextest_archive="${NEXTEST_ARCHIVE:-./test_archive.tar.zst}"
nextest_archive="${nextest_archive/#\~/$HOME}"
ci_skip_tag="${TEST_TAG_CI_SKIP:-ci_skip}"

## ── Require bash 5+ ─────────────────────────────────────────────────────────
if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    error "Bash version 5 or higher is required (found ${BASH_VERSION})"
    exit 1
fi

## ── Check for required binaries ─────────────────────────────────────────────
missing=0
for cmd in cargo comm grep jq sort wc; do
    if ! command -v "${cmd}" > /dev/null 2>&1; then
        error "Missing required command: $(hl "${cmd}")"
        missing=1
    fi
done
[[ "${missing}" -eq 1 ]] && exit 1

## --- List all ignored tests via nextest -------------------------------------
info "Listing ignored tests from nextest archive..."
cargo nextest list --archive-file "${nextest_archive}" -Tjson > nextest_output.json || {
    error "Error listing tests in $(hl ${nextest_archive})"
    exit 1
}

jq -c '
    .["rust-suites"]["stacks-node::bin/stacks-node"]["testcases"]
    | [to_entries[] | select(.value.ignored) | .key]
' nextest_output.json > ignored_tests.json

info "Ignored tests count: $(hl $(jq 'length' ignored_tests.json))"

## ── Build list of excluded tests ────────────────────────────────────────────
info "Building exclude list..."
cat << 'EOF' > raw_exclude.txt
# The following tests are excluded from CI runs.
tests::nakamoto_integrations::consensus_hash_event_dispatcher
tests::neon_integrations::atlas_integration_test
tests::neon_integrations::atlas_stress_integration_test
tests::neon_integrations::bitcoind_resubmission_test
tests::neon_integrations::block_replay_integration_test
tests::neon_integrations::deep_contract
tests::neon_integrations::filter_txs_by_origin
tests::neon_integrations::filter_txs_by_type
tests::neon_integrations::lockup_integration
tests::neon_integrations::most_recent_utxo_integration_test
tests::neon_integrations::run_with_custom_wallet
tests::neon_integrations::test_competing_miners_build_anchor_blocks_on_same_chain_without_rbf
tests::neon_integrations::test_one_miner_build_anchor_blocks_on_same_chain_without_rbf
tests::signer::v0::tenure_extend::tenure_extend_after_2_bad_commits
tests::epoch_205::test_cost_limit_switch_version205
tests::epoch_205::test_dynamic_db_method_costs
tests::epoch_205::test_exact_block_costs
tests::epoch_205::transition_empty_blocks
tests::epoch_21::test_sortition_divergence_pre_21
tests::epoch_21::test_v1_unlock_height_with_current_stackers
tests::epoch_21::test_v1_unlock_height_with_delay_and_current_stackers
tests::epoch_21::trait_invocation_cross_epoch
tests::epoch_21::transition_adds_burn_block_height
tests::epoch_21::transition_adds_get_pox_addr_recipients
tests::epoch_21::transition_adds_mining_from_segwit
tests::epoch_21::transition_adds_pay_to_alt_recipient_contract
tests::epoch_21::transition_adds_pay_to_alt_recipient_principal
tests::epoch_21::transition_empty_blocks
tests::epoch_21::transition_fixes_bitcoin_rigidity
tests::epoch_21::transition_removes_pox_sunset
tests::epoch_22::disable_pox
tests::epoch_22::pox_2_unlock_all
tests::epoch_23::trait_invocation_behavior
tests::epoch_24::fix_to_pox_contract
tests::epoch_24::verify_auto_unlock_behavior
tests::nakamoto_integrations::flash_blocks_on_epoch_3_FLAKY
tests::nakamoto_integrations::large_mempool_original_constant_fee
tests::nakamoto_integrations::large_mempool_original_random_fee
tests::nakamoto_integrations::large_mempool_next_constant_fee
tests::nakamoto_integrations::large_mempool_next_random_fee
tests::nakamoto_integrations::larger_mempool
tests::nakamoto_integrations::check_block_info_rewards
tests::signer::v0::larger_mempool
tests::pox_5_integrations::check_pox_5_register_for_second_bond_no_downtime
EOF

ci_skip_regex=":t::(?:.*::)?${ci_skip_tag}::"
info "Excluding tests matching tag: $(hl "${ci_skip_tag}") (regex: $(hl "${ci_skip_regex}"))"
jq -r '.[]' ignored_tests.json | grep -P "${ci_skip_regex}" >> raw_exclude.txt || true

grep -v '^\s*$' raw_exclude.txt | grep -v '^\s*#' > clean_exclude.txt
jq -R . clean_exclude.txt | jq -s . > exclude.json
info "Excluded tests count: $(hl $(jq length exclude.json))"

## ── Build list of slow tests ────────────────────────────────────────────────
info "Building slow tests list..."
cat << 'EOF' > raw_slow.txt
# Add tests here that should be executed individually in their own runner job because they are slow
bitvec::test::vectors
event_dispatcher::tests::test_http_delivery_non_blocking
tests::marf::marf_compress_off::large_mempool_with_marf_compression
tests::nakamoto_integrations::check_block_heights
tests::nakamoto_integrations::clarity_burn_state
tests::nakamoto_integrations::clarity_cost_spend_down
tests::nakamoto_integrations::follower_bootup_across_multiple_cycles
tests::nakamoto_integrations::follower_bootup_custom_chain_id
tests::nakamoto_integrations::follower_bootup_simple
tests::nakamoto_integrations::mine_multiple_per_tenure_integration
tests::nakamoto_integrations::multiple_miners
tests::nakamoto_integrations::nakamoto_attempt_time
tests::nakamoto_integrations::sip029_coinbase_change
tests::nakamoto_integrations::skip_mining_long_tx
tests::nakamoto_integrations::test_sip_031_last_phase
tests::neon_integrations::antientropy_integration_test
tests::neon_integrations::bitcoin_reorg_flap_with_follower
tests::pox_5_integrations::check_pox_5_register_for_bond_l1_early_unlock_lifecycle
tests::pox_5_integrations::check_with_pox_allowances
tests::pox_5_integrations::check_with_stacking_allowances_register_for_bond
tests::signer::v0::epoch_4_0_multi_miner_distribution::epoch_4_0_burn_distribution_chains_across_boundary::t::slow::bitcoind::t
tests::signer::v0::epoch_4_0_reorg::bitcoin_reorg_of_epoch_4_0_activation_block::t::slow::bitcoind::t
tests::signer::v0::epoch_4_0_waterfall::epoch_4_0_block_commit_uses_single_sbtc_output::t::slow::bitcoind::t
tests::signer::v0::large_mempool_next_random_fee
tests::signer::v0::min_gap_between_blocks
tests::signer::v0::mine_2_nakamoto_reward_cycles
tests::signer::v0::miner_stackerdb_version_rollover
tests::signer::v0::multiple_miners
tests::signer::v0::multiple_miners_mock_sign_epoch_25
tests::signer::v0::multiple_miners_with_custom_chain_id
tests::signer::v0::multiple_miners_with_nakamoto_blocks
tests::signer::v0::problematic_txs::signers_reject_blocks_with_problematic_txs::t::bitcoind::t
tests::signer::v0::reorg::bitcoind_forking_test
tests::signer::v0::reorg::disallow_reorg_within_first_proposal_burn_block_timing_secs_but_more_than_one_block
tests::signer::v0::reorg::miner_rejection_by_contract_publish_execution_time_expired
tests::signer::v0::reorg::no_reorg_due_to_successive_block_validation_ok
tests::signer::v0::reorg::reorg_locally_accepted_blocks_across_tenures_fails
tests::signer::v0::reorg::reorging_signers_capitulate_to_nonreorging_signers_during_tenure_fork
tests::signer::v0::signer_multinode_rollover
tests::signer::v0::tenure_extend::multiple_miners_empty_sortition
tests::signer::v0::tenure_extend::non_blocking_minority_configured_to_favour_incoming_miner
tests::signer::v0::test_vtxindex_zero_acceptance
tests::signer::v0::test_vtxindex_zero_two_miners
tests::signer::v0::tx_replay::tx_replay_budget_exceeded_tenure_extend
EOF

grep -v '^\s*$' raw_slow.txt | grep -v '^\s*#' > clean_slow.txt || true
jq -R . clean_slow.txt | jq -s . > slow.json
info "Configured slow tests count: $(hl $(jq length slow.json))"

## ── Filter out excluded tests -----------------------------------------------
info "Filtering excluded tests..."
jq -e 'type == "array"' ignored_tests.json > /dev/null
jq -e 'type == "array"' exclude.json > /dev/null

jq -r '.[]' ignored_tests.json | sort > ignored_sorted.txt
jq -r '.[]' exclude.json        | sort > exclude_sorted.txt

comm -23 ignored_sorted.txt exclude_sorted.txt > filtered.txt

## ── Separate regular tests and slow tests ───────────────────────────────────
jq -r '.[]' slow.json | sort > slow_sorted.txt

# Extract slow tests that exist in the non-excluded test set
comm -12 filtered.txt slow_sorted.txt > slow_filtered.txt

# Extract non-slow tests for normal batching
comm -23 filtered.txt slow_sorted.txt > normal_filtered.txt

normal_total=$(wc -l < normal_filtered.txt)
slow_total=$(wc -l < slow_filtered.txt)
info "Regular tests: $(hl ${normal_total}) | Slow tests (1 per job): $(hl ${slow_total})"

## ── Build dynamic matrix batches ───────────────────────────────────────────
batches_json="[]"
idx=1

# 1. Chunk normal tests into batches of size $batch_size
if [[ "${normal_total}" -gt 0 ]]; then
    info "Grouping $(hl ${normal_total}) regular tests into batches of size $(hl ${batch_size})...."
    mapfile -t normal_tests < normal_filtered.txt

    for (( j = 0; j < normal_total; j += batch_size )); do
        chunk=("${normal_tests[@]:j:batch_size}")
        
        old_ifs="$IFS"
        IFS=','
        csv_chunk="${chunk[*]}"
        IFS="$old_ifs"
        
        batches_json=$(echo "$batches_json" | jq --argjson idx "$idx" --arg csv "$csv_chunk" '. += [{"index": $idx, "csv": $csv}]')
        ((idx++))
    done
fi

# 2. Add each slow test as a single-item batch (1 test per runner job)
if [[ "${slow_total}" -gt 0 ]]; then
    info "Adding $(hl ${slow_total}) slow tests as individual matrix runner jobs..."
    mapfile -t slow_tests < slow_filtered.txt

    for test_name in "${slow_tests[@]}"; do
        [[ -z "${test_name}" ]] && continue
        batches_json=$(echo "$batches_json" | jq --argjson idx "$idx" --arg csv "$test_name" '. += [{"index": $idx, "csv": $csv}]')
        ((idx++))
    done
fi

info "Generated $(hl $(jq 'length' <<< "$batches_json")) total dynamic matrix batches."

# Export to GitHub Actions or stdout
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "batches=$(jq -c . <<< "$batches_json")" >> "${GITHUB_OUTPUT}"
else
    jq -c . <<< "$batches_json"
fi