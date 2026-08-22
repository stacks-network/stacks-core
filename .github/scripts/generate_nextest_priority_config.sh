#!/usr/bin/env bash
# Add longest-first test priorities to a nextest profile.
#
# Required env vars:
#   TEST_NAMES_CSV    - Comma-separated literal test names
#   TEST_TIMINGS_FILE - JSON containing default_seconds and a tests map
#   BASE_CONFIG_FILE  - Existing nextest configuration
#   OUTPUT_CONFIG_FILE - Generated nextest configuration
#
# Optional env vars:
#   NEXTEST_PROFILE   - Profile receiving the overrides (default: ci-sequential)
set -euo pipefail

test_names_csv="${TEST_NAMES_CSV:?TEST_NAMES_CSV is required}"
timings_file="${TEST_TIMINGS_FILE:?TEST_TIMINGS_FILE is required}"
base_config_file="${BASE_CONFIG_FILE:?BASE_CONFIG_FILE is required}"
output_config_file="${OUTPUT_CONFIG_FILE:?OUTPUT_CONFIG_FILE is required}"
nextest_profile="${NEXTEST_PROFILE:-ci-sequential}"

if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    echo "Bash 5 or higher is required: ${BASH_VERSION}" >&2
    exit 1
fi
if ! command -v jq > /dev/null 2>&1; then
    echo "Missing required command: jq" >&2
    exit 1
fi
if ! [[ "${nextest_profile}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Invalid nextest profile: ${nextest_profile}" >&2
    exit 1
fi

for required_file in "${timings_file}" "${base_config_file}"; do
    if [[ ! -f "${required_file}" ]]; then
        echo "Required file not found: ${required_file}" >&2
        exit 1
    fi
done

jq -e '
    (.default_seconds | type == "number" and . > 0) and
    (.tests | type == "object")
' "${timings_file}" > /dev/null || {
    echo "Invalid test timings file: ${timings_file}" >&2
    exit 1
}

mapfile -t ordered_tests < <(
    jq -Rnr \
        --arg test_names "${test_names_csv}" \
        --slurpfile timings "${timings_file}" '
        ($timings[0]) as $timings
        | $test_names
        | split(",")
        | map(gsub("^[[:space:]]+|[[:space:]]+$"; ""))
        | map(select(length > 0))
        | unique
        | map({
            name: .,
            weight: ($timings.tests[.] // $timings.default_seconds)
          })
        | sort_by([(-.weight), .name])
        | .[].name
    '
)

test_count=${#ordered_tests[@]}
if (( test_count == 0 )); then
    echo "TEST_NAMES_CSV contains no test names" >&2
    exit 1
fi
if (( test_count > 201 )); then
    echo "Nextest supports only 201 distinct priority levels; received ${test_count} tests" >&2
    exit 1
fi

cp "${base_config_file}" "${output_config_file}"

priority=100
for test_name in "${ordered_tests[@]}"; do
    quoted_filter=$(jq -Rn --arg filter "test(=${test_name})" '$filter')
    {
        printf '\n[[profile.%s.overrides]]\n' "${nextest_profile}"
        printf 'filter = %s\n' "${quoted_filter}"
        printf 'priority = %d\n' "${priority}"
    } >> "${output_config_file}"
    priority=$((priority - 1))
done
