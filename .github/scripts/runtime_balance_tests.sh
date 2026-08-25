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
#   TEST_THREADS       - Concurrent nextest slots per batch (default: 1)
#   SERIAL_GROUP_REGEX - Tests matching this regex share a concurrency limit
#   SERIAL_GROUP_MAX_THREADS - Concurrent tests allowed from that group (default: 1)
#
# Outputs a JSON array of batches to stdout. Each batch contains its 1-based
# index, estimated_seconds, and tests array.
set -euo pipefail

test_list_file="${TEST_LIST_FILE:?TEST_LIST_FILE is required}"
timings_file="${TEST_TIMINGS_FILE:?TEST_TIMINGS_FILE is required}"
batch_count="${BATCH_COUNT:?BATCH_COUNT is required}"
max_batch_size="${MAX_BATCH_SIZE:-0}"
test_threads="${TEST_THREADS:-1}"
serial_group_regex="${SERIAL_GROUP_REGEX:-}"
serial_group_max_threads="${SERIAL_GROUP_MAX_THREADS:-1}"

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

if ! [[ "${test_threads}" =~ ^[1-9][0-9]*$ ]]; then
    echo "TEST_THREADS must be a positive integer: ${test_threads}" >&2
    exit 1
fi

if ! [[ "${serial_group_max_threads}" =~ ^[1-9][0-9]*$ ]] ||
    (( serial_group_max_threads > test_threads )); then
    echo \
        "SERIAL_GROUP_MAX_THREADS must be between 1 and TEST_THREADS: ${serial_group_max_threads}" \
        >&2
    exit 1
fi

if [[ -n "${serial_group_regex}" ]] &&
    ! jq -n --arg regex "${serial_group_regex}" \
        'try ("" | test($regex)) catch halt_error(1)' > /dev/null; then
    echo "Invalid SERIAL_GROUP_REGEX: ${serial_group_regex}" >&2
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
# eligible batch with the lowest estimated makespan. The estimate accounts for
# both the runner-wide slot count and one optional nextest test-group limit.
mapfile -t weighted_tests < <(
    jq -Rnr \
        --slurpfile timings "${timings_file}" \
        --arg group_regex "${serial_group_regex}" \
        --argjson test_threads "${test_threads}" \
        --argjson group_threads "${serial_group_max_threads}" '
        ($timings[0]) as $timings
        | [
            inputs
            | select(length > 0)
            | . as $name
            | ($timings.tests[$name] // $timings.default_seconds) as $weight
            | ($group_regex != "" and ($name | test($group_regex))) as $is_group
            | {
                name: $name,
                weight: $weight,
                is_group: $is_group,
                priority: (
                  if $is_group
                  then $weight * $test_threads / $group_threads
                  else $weight
                  end
                )
              }
          ]
        | sort_by([(-.priority), (-.weight), .name])
        | .[]
        | [
            ((.weight * 1000) | round | tostring),
            (if .is_group then "1" else "0" end),
            .name
          ]
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

declare -a batch_work_ms=()
declare -a batch_group_ms=()
declare -a batch_max_test_ms=()
declare -a batch_estimated_ms=()
declare -a batch_test_counts=()
declare -a batch_tests=()

for (( i = 0; i < batch_count; i++ )); do
    batch_work_ms[i]=0
    batch_group_ms[i]=0
    batch_max_test_ms[i]=0
    batch_estimated_ms[i]=0
    batch_test_counts[i]=0
    batch_tests[i]=""
done

for weighted_test in "${weighted_tests[@]}"; do
    IFS=$'\t' read -r weight_ms is_group test_name <<< "${weighted_test}"
    best_batch=-1
    best_estimated_ms=-1

    for (( i = 0; i < batch_count; i++ )); do
        if (( max_batch_size > 0 && batch_test_counts[i] >= max_batch_size )); then
            continue
        fi

        candidate_work_ms=$(( batch_work_ms[i] + weight_ms ))
        candidate_group_ms=${batch_group_ms[i]}
        if (( is_group == 1 )); then
            candidate_group_ms=$(( candidate_group_ms + weight_ms ))
        fi
        candidate_max_test_ms=${batch_max_test_ms[i]}
        if (( weight_ms > candidate_max_test_ms )); then
            candidate_max_test_ms=${weight_ms}
        fi

        candidate_estimated_ms=$((
            (candidate_work_ms + test_threads - 1) / test_threads
        ))
        if [[ -n "${serial_group_regex}" ]]; then
            candidate_group_estimated_ms=$((
                (candidate_group_ms + serial_group_max_threads - 1) /
                    serial_group_max_threads
            ))
            if (( candidate_group_estimated_ms > candidate_estimated_ms )); then
                candidate_estimated_ms=${candidate_group_estimated_ms}
            fi
        fi
        if (( candidate_max_test_ms > candidate_estimated_ms )); then
            candidate_estimated_ms=${candidate_max_test_ms}
        fi

        if (( best_batch == -1 )) ||
            (( candidate_estimated_ms < best_estimated_ms )) ||
            { (( candidate_estimated_ms == best_estimated_ms )) &&
              (( batch_work_ms[i] < batch_work_ms[best_batch] )); } ||
            { (( candidate_estimated_ms == best_estimated_ms )) &&
              (( batch_work_ms[i] == batch_work_ms[best_batch] )) &&
              (( batch_test_counts[i] < batch_test_counts[best_batch] )); }; then
            best_batch=${i}
            best_estimated_ms=${candidate_estimated_ms}
        fi
    done

    if (( best_batch == -1 )); then
        echo "Unable to assign test to a batch: ${test_name}" >&2
        exit 1
    fi

    batch_work_ms[best_batch]=$(( batch_work_ms[best_batch] + weight_ms ))
    if (( is_group == 1 )); then
        batch_group_ms[best_batch]=$(( batch_group_ms[best_batch] + weight_ms ))
    fi
    if (( weight_ms > batch_max_test_ms[best_batch] )); then
        batch_max_test_ms[best_batch]=${weight_ms}
    fi
    batch_estimated_ms[best_batch]=${best_estimated_ms}
    batch_test_counts[best_batch]=$(( batch_test_counts[best_batch] + 1 ))
    batch_tests[best_batch]+="${test_name}"$'\n'
done

result=$(
    for (( i = 0; i < batch_count; i++ )); do
        while IFS= read -r test_name; do
            [[ -n "${test_name}" ]] || continue
            printf '%d\t%d\t%s\n' "$((i + 1))" "${batch_estimated_ms[i]}" "${test_name}"
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
