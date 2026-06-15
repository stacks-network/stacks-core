#!/usr/bin/env bash
# Generate a balanced test matrix for the Bitcoin integration test workflow.
#
# Discovers all ignored tests in the stacks-node binary via cargo nextest,
# removes a hardcoded exclude list, then chunks them into batches.
#
# Optional env vars:
#   BATCH_SIZE       - Number of tests grouped into a single runner batch (default: 50)
#   NEXTEST_ARCHIVE  - Nextest archive to use (default: ~/test_archive.tar.zst)
#   TEST_TAG_CI_SKIP - Tag name used to exclude tests from CI (default: ci_skip)
#
# Outputs:
#   GITHUB_OUTPUT  - Path to the GitHub Actions output file (set by runner)
set -euo pipefail

# Load logging functions from logging.sh for color and standardized output
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## --- Configuration ----------------------------------------------------------
# Set batch size for test grouping. default is 50
batch_size="${BATCH_SIZE:-50}"
# Set the nextest archive to use
nextest_archive="${NEXTEST_ARCHIVE:-${HOME}/test_archive.tar.zst}"
# Safely replace a leading ~ with the actual absolute $HOME path if provided in the env var
nextest_archive="${nextest_archive/#\~/$HOME}"
# Exclude tests tagged with a skip tag
ci_skip_tag="${TEST_TAG_CI_SKIP:-ci_skip}"

## ── Require bash 5+ (mapfile with -t flag behaviour) ────────────────────────
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

## ── Build list of excluded tests --------------------------------------------
info "Building exclude list..."
cat << 'EOF' > raw_exclude.txt
# The following tests are excluded from CI runs. Some of these may be worth investigating adding back into the CI
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
EOF

## ── Append tests tagged with ci_skip to the exclude list ────────────────────
ci_skip_regex=":t::(?:.*::)?${ci_skip_tag}::"
info "Excluding tests matching tag: $(hl "${ci_skip_tag}") (regex: $(hl "${ci_skip_regex}"))"
jq -r '.[]' ignored_tests.json | grep -P "${ci_skip_regex}" >> raw_exclude.txt || true

## ── Strip blank lines and comments, then convert to JSON array ──────────────
grep -v '^\s*$' raw_exclude.txt | grep -v '^\s*#' > clean_exclude.txt
jq -R . clean_exclude.txt | jq -s . > exclude.json
info "Excluded tests count: $(hl $(jq length exclude.json))"

## ── Filter out excluded tests -----------------------------------------------
info "Filtering excluded tests..."
jq -e 'type == "array"' ignored_tests.json > /dev/null
jq -e 'type == "array"' exclude.json > /dev/null

jq -r '.[]' ignored_tests.json | sort > ignored_sorted.txt
jq -r '.[]' exclude.json        | sort > exclude_sorted.txt

comm -23 ignored_sorted.txt exclude_sorted.txt > filtered.txt

total=$(wc -l < filtered.txt)
info "Final test count: $(hl ${total})"

## ── Chunk all tests into batches ──────────────────────────────────────────
info "Grouping $(hl ${total}) tests into batches of size $(hl ${batch_size})...."
mapfile -t tests < filtered.txt

batches_json="[]"
idx=1

for (( j = 0; j < total; j += batch_size )); do
    chunk=("${tests[@]:j:batch_size}")
    
    # Safely join array elements using a comma character
    old_ifs="$IFS"
    IFS=','
    csv_chunk="${chunk[*]}"
    IFS="$old_ifs"
    
    # Append an object containing both the index and the raw CSV string to the master JSON array
    batches_json=$(echo "$batches_json" | jq --argjson idx "$idx" --arg csv "$csv_chunk" '. += [{"index": $idx, "csv": $csv}]')
    
    ((idx++))
done

info "Generated $(hl $(jq 'length' <<< "$batches_json")) dynamic matrix batches."

# Export to GitHub Actions or stdout
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "batches=$(jq -c . <<< "$batches_json")" >> "${GITHUB_OUTPUT}"
else
    jq -c . <<< "$batches_json"
fi