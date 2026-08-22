#!/usr/bin/env bash
# Select one runtime-balanced unit-test partition from a nextest archive.
#
# Required env vars:
#   NEXTEST_ARCHIVE   - Nextest archive containing the workspace tests
#   TEST_TIMINGS_FILE - Historical timing data for known slow tests
#   PARTITION         - 1-based partition to select
#   TOTAL_PARTITIONS  - Total number of runtime-balanced partitions
#   TEST_LIST_OUTPUT  - Destination for the selected newline-delimited tests
#
# Optional env vars:
#   EXCLUDED_TEST_NAMES_CSV - Tests run separately from these partitions
set -euo pipefail

nextest_archive="${NEXTEST_ARCHIVE:?NEXTEST_ARCHIVE is required}"
timings_file="${TEST_TIMINGS_FILE:?TEST_TIMINGS_FILE is required}"
partition="${PARTITION:?PARTITION is required}"
total_partitions="${TOTAL_PARTITIONS:?TOTAL_PARTITIONS is required}"
test_list_output="${TEST_LIST_OUTPUT:?TEST_LIST_OUTPUT is required}"
excluded_test_names_csv="${EXCLUDED_TEST_NAMES_CSV:-}"

if ! [[ "${partition}" =~ ^[1-9][0-9]*$ ]] ||
    ! [[ "${total_partitions}" =~ ^[1-9][0-9]*$ ]] ||
    (( partition > total_partitions )); then
    echo "Invalid partition ${partition}/${total_partitions}" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
nextest_output=$(mktemp)
discovered_tests=$(mktemp)
all_tests=$(mktemp)
excluded_tests=$(mktemp)
balanced_batches=$(mktemp)
trap 'rm -f "${nextest_output}" "${discovered_tests}" "${all_tests}" "${excluded_tests}" "${balanced_batches}"' EXIT

cargo-nextest nextest list \
    --config-file ./.github/nextest/ci-nextest.toml \
    --archive-file "${nextest_archive}" \
    -Tjson > "${nextest_output}"

# Test names are unique across the workspace except for one small configuration
# test. Deduplicating that name keeps both matching binaries in the same batch
# when nextest applies the exact-name filters.
jq -r '
    [
        .["rust-suites"][]
        | .testcases
        | to_entries[]
        | select(.value.ignored | not)
        | .key
    ]
    | unique[]
' "${nextest_output}" > "${discovered_tests}"

jq -Rnr --arg test_names "${excluded_test_names_csv}" '
    $test_names
    | split(",")
    | map(gsub("^[[:space:]]+|[[:space:]]+$"; ""))
    | map(select(length > 0))
    | unique[]
' > "${excluded_tests}"

missing_exclusions=$(comm -23 "${excluded_tests}" "${discovered_tests}")
if [[ -n "${missing_exclusions}" ]]; then
    echo "Excluded unit tests were not discovered:" >&2
    echo "${missing_exclusions}" >&2
    exit 1
fi

comm -23 "${discovered_tests}" "${excluded_tests}" > "${all_tests}"

TEST_LIST_FILE="${all_tests}" \
TEST_TIMINGS_FILE="${timings_file}" \
BATCH_COUNT="${total_partitions}" \
    bash "${script_dir}/runtime_balance_tests.sh" > "${balanced_batches}"

jq -r --argjson partition "${partition}" '
    .[]
    | select(.index == $partition)
    | .tests[]
' "${balanced_batches}" > "${test_list_output}"

selected_count=$(wc -l < "${test_list_output}")
selected_count=${selected_count//[[:space:]]/}
expected_count=$(jq -r --argjson partition "${partition}" '
    .[]
    | select(.index == $partition)
    | (.tests | length)
' "${balanced_batches}")

if [[ -z "${expected_count}" ]] || (( selected_count != expected_count )); then
    echo \
        "Selected ${selected_count} of ${expected_count:-0} expected tests for partition ${partition}" \
        >&2
    exit 1
fi

estimated_seconds=$(jq -r --argjson partition "${partition}" '
    .[]
    | select(.index == $partition)
    | .estimated_seconds
' "${balanced_batches}")

echo \
    "Selected ${selected_count} tests for partition ${partition}/${total_partitions}" \
    "(estimated ${estimated_seconds}s)"
