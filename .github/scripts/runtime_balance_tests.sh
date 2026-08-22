#!/usr/bin/env bash
# Balance a newline-delimited test list using historical runtimes.
#
# Required env vars:
#   TEST_LIST_FILE     - Newline-delimited test names
#   TEST_TIMINGS_FILE  - JSON containing default_seconds and a tests map
#   BATCH_COUNT        - Number of batches to generate
#
# Optional env vars:
#   MAX_BATCH_SIZE     - Maximum tests per batch; 0 means unlimited (default: 0)
#
# Outputs a JSON array of batches to stdout. Each batch contains its 1-based
# index, estimated_seconds, and tests array.
set -euo pipefail

test_list_file="${TEST_LIST_FILE:?TEST_LIST_FILE is required}"
timings_file="${TEST_TIMINGS_FILE:?TEST_TIMINGS_FILE is required}"
batch_count="${BATCH_COUNT:?BATCH_COUNT is required}"
max_batch_size="${MAX_BATCH_SIZE:-0}"

if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    echo "Bash 5 or higher is required: ${BASH_VERSION}" >&2
    exit 1
fi

if ! command -v jq > /dev/null 2>&1; then
    echo "Missing required command: jq" >&2
    exit 1
fi

if [[ ! -f "${test_list_file}" ]]; then
    echo "Test list file not found: ${test_list_file}" >&2
    exit 1
fi

if [[ ! -f "${timings_file}" ]]; then
    echo "Test timings file not found: ${timings_file}" >&2
    exit 1
fi

if ! [[ "${batch_count}" =~ ^[1-9][0-9]*$ ]]; then
    echo "BATCH_COUNT must be a positive integer: ${batch_count}" >&2
    exit 1
fi

if ! [[ "${max_batch_size}" =~ ^[0-9]+$ ]]; then
    echo "MAX_BATCH_SIZE must be a non-negative integer: ${max_batch_size}" >&2
    exit 1
fi

jq -e '
    (.default_seconds | type == "number" and . > 0) and
    (.tests | type == "object") and
    all(.tests[]; type == "number" and . >= 0)
' "${timings_file}" > /dev/null || {
    echo "Invalid test timings file: ${timings_file}" >&2
    exit 1
}

# Longest-processing-time scheduling greedily puts each remaining test in the
# eligible batch with the lowest estimated runtime.
mapfile -t weighted_tests < <(
    jq -Rnr --slurpfile timings "${timings_file}" '
        ($timings[0]) as $timings
        | [
            inputs
            | select(length > 0)
            | {
                name: .,
                weight: ($timings.tests[.] // $timings.default_seconds)
              }
          ]
        | sort_by([(-.weight), .name])
        | .[]
        | [((.weight * 1000) | round | tostring), .name]
        | @tsv
    ' < "${test_list_file}"
)

test_count=${#weighted_tests[@]}
if (( test_count == 0 )); then
    echo "Test list is empty: ${test_list_file}" >&2
    exit 1
fi

if (( batch_count > test_count )); then
    echo "BATCH_COUNT (${batch_count}) exceeds test count (${test_count})" >&2
    exit 1
fi

if (( max_batch_size > 0 && batch_count * max_batch_size < test_count )); then
    echo "${batch_count} batches of ${max_batch_size} cannot hold ${test_count} tests" >&2
    exit 1
fi

declare -a batch_weights_ms=()
declare -a batch_test_counts=()
declare -a batch_tests=()

for (( i = 0; i < batch_count; i++ )); do
    batch_weights_ms[i]=0
    batch_test_counts[i]=0
    batch_tests[i]=""
done

for weighted_test in "${weighted_tests[@]}"; do
    IFS=$'\t' read -r weight_ms test_name <<< "${weighted_test}"
    best_batch=-1

    for (( i = 0; i < batch_count; i++ )); do
        if (( max_batch_size > 0 && batch_test_counts[i] >= max_batch_size )); then
            continue
        fi

        if (( best_batch == -1 )) ||
            (( batch_weights_ms[i] < batch_weights_ms[best_batch] )) ||
            { (( batch_weights_ms[i] == batch_weights_ms[best_batch] )) &&
              (( batch_test_counts[i] < batch_test_counts[best_batch] )); }; then
            best_batch=${i}
        fi
    done

    if (( best_batch == -1 )); then
        echo "Unable to assign test to a batch: ${test_name}" >&2
        exit 1
    fi

    batch_weights_ms[best_batch]=$(( batch_weights_ms[best_batch] + weight_ms ))
    batch_test_counts[best_batch]=$(( batch_test_counts[best_batch] + 1 ))
    batch_tests[best_batch]+="${test_name}"$'\n'
done

result=$(
    for (( i = 0; i < batch_count; i++ )); do
        while IFS= read -r test_name; do
            [[ -n "${test_name}" ]] || continue
            printf '%d\t%d\t%s\n' "$((i + 1))" "${batch_weights_ms[i]}" "${test_name}"
        done <<< "${batch_tests[i]}"
    done | jq -Rs '
        [
            split("\n")[]
            | select(length > 0)
            | split("\t")
            | {
                index: (.[0] | tonumber),
                weight_ms: (.[1] | tonumber),
                name: .[2]
              }
        ]
        | group_by(.index)
        | map({
            index: .[0].index,
            estimated_seconds: (.[0].weight_ms / 1000),
            tests: map(.name)
          })
    '
)

emitted_count=$(jq '[.[].tests[]] | length' <<< "${result}")
if (( emitted_count != test_count )); then
    echo "Balancer emitted ${emitted_count} of ${test_count} tests" >&2
    exit 1
fi

# Compare the complete multisets, not only their counts, so a duplicate cannot
# conceal a dropped test.
if ! jq -e --rawfile expected "${test_list_file}" '
    ([$expected | split("\n")[] | select(length > 0)] | sort) ==
    ([.[].tests[]] | sort)
' <<< "${result}" > /dev/null; then
    echo "Balancer output does not exactly cover the input test list" >&2
    exit 1
fi

printf '%s\n' "${result}"
