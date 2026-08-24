#!/usr/bin/env bash
# Generate a balanced test matrix for the Bitcoin integration test workflow.
#
# Discovers all ignored tests in the stacks-node binary via nextest,
# removes a hardcoded exclude list, then balances them into batches using
# historical JUnit timings.
#
# Optional env vars:
#   BATCH_SIZE       - Maximum tests grouped into a single runner batch (default: 50)
#   BITCOIN_BATCH_COUNT - Number of runner batches. Defaults to the minimum
#                         required by BATCH_SIZE.
#   NEXTEST_ARCHIVE  - Nextest archive to use (default: ./test_archive.tar.zst)
#   NEXTEST_LIST_FILE - Pre-generated nextest JSON test manifest. When set,
#                       the archive and cargo-nextest are not needed.
#   TEST_TAG_CI_SKIP - Tag name used to exclude tests from CI (default: ci_skip)
#   TEST_TIMINGS_FILE - Historical timing data used to balance batches
#   BITCOIN_TEST_THREADS - Nextest execution slots available to each batch (default: 2)
#   SIGNER_TEST_THREADS_REQUIRED - Slots reserved by an ordinary signer test (default: 1)
#   BITCOIN_ISOLATED_TESTS - Comma-separated tests assigned dedicated workflow jobs
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
# Optional runner-count override. This permits runtime-balanced batches to
# contain different test counts without weakening the per-runner safety cap.
batch_count_override="${BITCOIN_BATCH_COUNT:-}"
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
# Resource weights used by the corresponding nextest profile. Exclusive tests
# reserve every slot; ordinary signer tests reserve the configured subset.
test_threads="${BITCOIN_TEST_THREADS:-2}"
signer_test_threads_required="${SIGNER_TEST_THREADS_REQUIRED:-1}"
isolated_tests_csv="${BITCOIN_ISOLATED_TESTS:-}"

## ── Require bash 5+ (mapfile with -t flag behaviour) ────────────────────────
if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    error "Bash version 5 or higher is required (found ${BASH_VERSION})"
    exit 1
fi

## ── Check for required binaries ─────────────────────────────────────────────
required_commands=(comm grep jq python3 sort wc)
if [[ -z "${nextest_list_file}" ]]; then
    required_commands+=(cargo-nextest)
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

if [[ -n "${batch_count_override}" ]] &&
    ! [[ "${batch_count_override}" =~ ^[1-9][0-9]*$ ]]; then
    error "BITCOIN_BATCH_COUNT must be a positive integer (found $(hl "${batch_count_override}"))"
    exit 1
fi

if ! [[ "${test_threads}" =~ ^[1-9][0-9]*$ ]]; then
    error "BITCOIN_TEST_THREADS must be a positive integer (found $(hl "${test_threads}"))"
    exit 1
fi

if ! [[ "${signer_test_threads_required}" =~ ^[1-9][0-9]*$ ]] ||
    (( signer_test_threads_required > test_threads )); then
    error "SIGNER_TEST_THREADS_REQUIRED must be between 1 and BITCOIN_TEST_THREADS"
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
    cargo-nextest nextest list --archive-file "${nextest_archive}" -Tjson > "${nextest_output}" || {
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
# Exclude these tests from the generated matrix. Some may warrant future re-entry.
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

if [[ -n "${isolated_tests_csv}" ]]; then
    IFS=',' read -r -a isolated_tests <<< "${isolated_tests_csv}"
    for test_name in "${isolated_tests[@]}"; do
        test_name="${test_name//[[:space:]]/}"
        if ! jq -e --arg name "${test_name}" 'index($name) != null' \
            ignored_tests.json > /dev/null; then
            error "Isolated test is not present in the ignored-test manifest: $(hl "${test_name}")"
            exit 1
        fi
        printf '%s\n' "${test_name}" >> raw_exclude.txt
    done
fi

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
minimum_batch_count=$(( (total + batch_size - 1) / batch_size ))
batch_count="${batch_count_override:-$minimum_batch_count}"
if (( batch_count < minimum_batch_count )); then
    error "BITCOIN_BATCH_COUNT must be at least ${minimum_batch_count} for ${total} tests with BATCH_SIZE=${batch_size}"
    exit 1
fi
if (( total > 0 && batch_count > total )); then
    error "BITCOIN_BATCH_COUNT cannot exceed the test count (${total})"
    exit 1
fi
info "Balancing $(hl "${total}") tests across $(hl "${batch_count}") batches of at most $(hl "${batch_size}") tests..."

if (( total == 0 )); then
    batches_json='[]'
else
    scheduling_timings_file=$(mktemp)
    trap 'rm -f "${scheduling_timings_file}"' EXIT

    # Record both runtime and slot requirements. The resource-aware scheduler
    # models exclusive tests as a serial segment and ordinary tests on the two
    # concurrent execution lanes.
    jq -Rn \
        --slurpfile timings "${timings_file}" \
        --argjson test_threads "${test_threads}" \
        --argjson signer_threads "${signer_test_threads_required}" '
        ($timings[0]) as $timings
        | reduce inputs as $name (
            {
              default_seconds: $timings.default_seconds,
              test_threads: $test_threads,
              tests: {}
            };
            ($timings.tests[$name] // $timings.default_seconds) as $seconds
            | (
                if ($name == "tests::signer::v0::block_validation_check_rejection_timeout_heuristic"
                    or $name == "tests::signer::v0::signers_do_not_commit_unless_threshold_precommitted"
                    or $name == "tests::signer::v0::signer_multinode_rollover"
                    or $name == "tests::signer::v0::multiple_miners_with_nakamoto_blocks"
                    or $name == "tests::signer::v0::tenure_extend::tenure_extend_after_idle_miner"
                    or $name == "tests::signer::v0::reorg::no_reorg_due_to_successive_block_validation_ok"
                    or $name == "tests::signer::v0::signers_wait_for_validation::signer_waits_for_validation_before_signing"
                    or $name == "tests::signer::v0::tx_replay::tx_replay_forking_test"
                    or $name == "tests::signer::v0::tx_replay::tx_replay_with_fork_middle_replay_while_tenure_extending_and_new_tx_submitted"
                    or $name == "tests::signer::v0::epoch_4_0_multi_miner_distribution::epoch_4_0_burn_distribution_chains_across_boundary::t::slow::bitcoind::t")
                    or ($name | test("^tests::(?:signer::v0::large_mempool|marf::.*::large_mempool)"))
                then $test_threads
                elif ($name | startswith("tests::signer::"))
                then $signer_threads
                else 1
                end
              ) as $slots
            | .tests[$name] = {seconds: $seconds, slots: $slots}
          )
    ' < filtered.txt > "${scheduling_timings_file}"

    resource_balancer="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/balance_resource_tests.py"
    balanced_batches=$(
        python3 "${resource_balancer}" \
            --test-list filtered.txt \
            --weights "${scheduling_timings_file}" \
            --batch-count "${batch_count}" \
            --max-batch-size "${batch_size}"
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
