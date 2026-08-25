#!/usr/bin/env bash
#
# Generates dynamic single-test matrices for the Bitcoin integration test workflow.
# Every test runs in its own job and partitions output into
# multiple matrix outputs (batches_1, batches_2, etc.) to bypass the GitHub Actions 256 matrix limit.
#
# Optional env vars:
#   MAX_CHUNKS       - Max chunks to process
#   MAX_PER_CHUNK    - Max tests per matrix output chunk (default: 256)
#   NEXTEST_ARCHIVE  - Nextest archive to use (default: ./test_archive.tar.zst)
#   TEST_TAG_CI_SKIP - Tag name used to exclude tests from CI (default: ci_skip)

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## --- Configuration ----------------------------------------------------------
max_chunks="${MAX_CHUNKS:-4}"
max_per_chunk="${MAX_PER_CHUNK:-256}"
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

## ── Build list of excluded tests --------------------------------------------
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
# Epoch tests are covered by the epoch-tests CI workflow, and don't need to run on every PR (for older epochs)
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
# Disable this flaky test. We don't need continue testing Epoch 2 -> 3 transition
tests::nakamoto_integrations::flash_blocks_on_epoch_3_FLAKY
# These mempool tests take a long time to run, and are meant to be run manually
tests::nakamoto_integrations::large_mempool_original_constant_fee
tests::nakamoto_integrations::large_mempool_original_random_fee
tests::nakamoto_integrations::large_mempool_next_constant_fee
tests::nakamoto_integrations::large_mempool_next_random_fee
tests::nakamoto_integrations::larger_mempool
tests::nakamoto_integrations::check_block_info_rewards
tests::signer::v0::larger_mempool
# This test takes too long run in CI
tests::pox_5_integrations::check_pox_5_register_for_second_bond_no_downtime
EOF

ci_skip_regex=":t::(?:.*::)?${ci_skip_tag}::"
jq -r '.[]' ignored_tests.json | grep -P "${ci_skip_regex}" >> raw_exclude.txt || true

grep -v '^\s*$' raw_exclude.txt | grep -v '^\s*#' > clean_exclude.txt
jq -R . clean_exclude.txt | jq -s . > exclude.json

## ── Filter excluded tests --------------------------------------------------
jq -r '.[]' ignored_tests.json | sort > ignored_sorted.txt
jq -r '.[]' exclude.json        | sort > exclude_sorted.txt

comm -23 ignored_sorted.txt exclude_sorted.txt > filtered.txt

mapfile -t tests < filtered.txt
total=${#tests[@]}
info "Total tests to run individually: $(hl ${total})"

## ── Validate Matrix Capacity Limits ─────────────────────────────────────────
max_capacity=$(( max_chunks * max_per_chunk ))
if (( total > max_capacity )); then
    error "Total tests ($(hl "${total}")) exceeds maximum total capacity of $(hl "${max_capacity}") (${max_chunks} chunks × ${max_per_chunk} limit per matrix)."
    error "Increase MAX_CHUNKS or reduce the test count to prevent matrix truncation."
    exit 1
fi

## ── Create Single-Test Batches ──────────────────────────────────────────────
all_batches="[]"
idx=1
all_batches=$(jq -R 'select(length > 0)' filtered.txt \
      | jq -s -c 'to_entries | map({index: (.key + 1), csv: .value})')

## ── Partition Single-Test Batches into Dynamic Chunks ────────────────────────
# Output chunks: batches_1, batches_2, etc. based on `max_chunks`
for (( c=1; c<=max_chunks; c++ )); do
    start_offset=$(( (c - 1) * max_per_chunk ))
    
    chunk_json=$(echo "$all_batches" | jq -c ".[${start_offset}:${start_offset}+${max_per_chunk}]")
    
    if [[ "$chunk_json" == "null" ]] || [[ -z "$chunk_json" ]]; then
        chunk_json="[]"
    fi

    chunk_length=$(echo "$chunk_json" | jq 'length')
    info "Chunk ${c} (batches_${c}): $(hl "${chunk_length}") single-test jobs"

    # Export to GitHub Actions or stdout
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "batches_${c}=${chunk_json}" >> "${GITHUB_OUTPUT}"
    else
        jq -c . <<< "$batches_json"
    fi
done
