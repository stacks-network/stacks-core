#!/usr/bin/env bash
# Generate a balanced test matrix for the Bitcoin integration test workflow.
#
# Discovers all ignored tests in the stacks-node binary via cargo nextest,
# removes a hardcoded exclude list, then balances them into batches using
# historical JUnit timings.
#
# Optional env vars:
#   BATCH_SIZE       - Number of tests grouped into a single runner batch (default: 50)
#   NEXTEST_ARCHIVE  - Nextest archive to use (default: ./test_archive.tar.zst)
#   NEXTEST_LIST_FILE - Pre-generated nextest JSON test manifest. When set,
#                       the archive and cargo-nextest are not needed.
#   TEST_TAG_CI_SKIP - Tag name used to exclude tests from CI (default: ci_skip)
#   TEST_TIMINGS_FILE - Historical timing data used to balance batches
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
# Historical durations used by the longest-processing-time scheduler.
timings_file="${TEST_TIMINGS_FILE:-.github/test-timings/bitcoin-integration.json}"
# Set the nextest archive to use
nextest_archive="${NEXTEST_ARCHIVE:-./test_archive.tar.zst}"
# Safely replace a leading ~ with the actual absolute $HOME path if provided in the env var
nextest_archive="${nextest_archive/#\~/$HOME}"
# Reuse the manifest produced while creating the archive when available.
nextest_list_file="${NEXTEST_LIST_FILE:-}"
# Exclude tests tagged with a skip tag
ci_skip_tag="${TEST_TAG_CI_SKIP:-ci_skip}"

## ── Require bash 5+ (mapfile with -t flag behaviour) ────────────────────────
if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    error "Bash version 5 or higher is required (found ${BASH_VERSION})"
    exit 1
fi

## ── Check for required binaries ─────────────────────────────────────────────
required_commands=(comm grep jq sort wc)
if [[ -z "${nextest_list_file}" ]]; then
    required_commands+=(cargo)
fi

missing=0
for cmd in "${required_commands[@]}"; do
    if ! command -v "${cmd}" > /dev/null 2>&1; then
        error "Missing required command: $(hl "${cmd}")"
        missing=1
    fi
done
[[ "${missing}" -eq 1 ]] && exit 1

if ! [[ "${batch_size}" =~ ^[1-9][0-9]*$ ]]; then
    error "BATCH_SIZE must be a positive integer (found $(hl "${batch_size}"))"
    exit 1
fi

if [[ ! -f "${timings_file}" ]]; then
    error "Test timings file not found: $(hl "${timings_file}")"
    exit 1
fi

jq -e '
    (.default_seconds | type == "number" and . > 0) and
    (.tests | type == "object")
' "${timings_file}" > /dev/null || {
    error "Invalid test timings file: $(hl "${timings_file}")"
    exit 1
}

## --- List all ignored tests via nextest -------------------------------------
if [[ -n "${nextest_list_file}" ]]; then
    if [[ ! -f "${nextest_list_file}" ]]; then
        error "Nextest test manifest not found: $(hl "${nextest_list_file}")"
        exit 1
    fi
    nextest_output="${nextest_list_file}"
    info "Reading ignored tests from nextest manifest $(hl "${nextest_output}")..."
else
    nextest_output="nextest_output.json"
    info "Listing ignored tests from nextest archive..."
    cargo nextest list --archive-file "${nextest_archive}" -Tjson > "${nextest_output}" || {
        error "Error listing tests in $(hl "${nextest_archive}")"
        exit 1
    }
fi

jq -c '
    .["rust-suites"]["stacks-node::bin/stacks-node"]["testcases"]
    | [to_entries[] | select(.value.ignored) | .key]
' "${nextest_output}" > ignored_tests.json

ignored_count=$(jq 'length' ignored_tests.json)
info "Ignored tests count: $(hl "${ignored_count}")"

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
# This test takes too long run in CI
tests::pox_5_integrations::check_pox_5_register_for_second_bond_no_downtime
EOF

## ── Append tests tagged with ci_skip to the exclude list ────────────────────
ci_skip_regex=":t::(?:.*::)?${ci_skip_tag}::"
info "Excluding tests matching tag: $(hl "${ci_skip_tag}") (regex: $(hl "${ci_skip_regex}"))"
jq -r --arg regex "${ci_skip_regex}" '.[] | select(test($regex))' \
    ignored_tests.json >> raw_exclude.txt

## ── Strip blank lines and comments, then convert to JSON array ──────────────
grep -v '^\s*$' raw_exclude.txt | grep -v '^\s*#' > clean_exclude.txt
jq -R . clean_exclude.txt | jq -s . > exclude.json
excluded_count=$(jq length exclude.json)
info "Excluded tests count: $(hl "${excluded_count}")"

## ── Filter out excluded tests -----------------------------------------------
info "Filtering excluded tests..."
jq -e 'type == "array"' ignored_tests.json > /dev/null
jq -e 'type == "array"' exclude.json > /dev/null

jq -r '.[]' ignored_tests.json | sort > ignored_sorted.txt
jq -r '.[]' exclude.json        | sort > exclude_sorted.txt

comm -23 ignored_sorted.txt exclude_sorted.txt > filtered.txt

total=$(wc -l < filtered.txt)
info "Final test count: $(hl "${total}")"

## ── Runtime-balance tests into batches ─────────────────────────────────────
batch_count=$(( (total + batch_size - 1) / batch_size ))
info "Balancing $(hl "${total}") tests across $(hl "${batch_count}") batches of at most $(hl "${batch_size}") tests..."

if (( total == 0 )); then
    batches_json='[]'
else
    balancer="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/runtime_balance_tests.sh"
    balanced_batches=$(
        TEST_LIST_FILE=filtered.txt \
        TEST_TIMINGS_FILE="${timings_file}" \
        BATCH_COUNT="${batch_count}" \
        MAX_BATCH_SIZE="${batch_size}" \
            bash "${balancer}"
    )

    # The workflow action accepts each batch as a comma-separated list.
    batches_json=$(jq '[.[] | {
        index,
        estimated_seconds,
        csv: (.tests | join(","))
    }]' <<< "${balanced_batches}")
fi

generated_batch_count=$(jq 'length' <<< "$batches_json")
info "Generated $(hl "${generated_batch_count}") dynamic matrix batches."

# Export to GitHub Actions or stdout
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "batches=$(jq -c . <<< "$batches_json")" >> "${GITHUB_OUTPUT}"
else
    jq -c . <<< "$batches_json"
fi
