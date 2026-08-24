#!/usr/bin/env bash
# Add longest-first test priorities to a nextest profile.
#
# Required env vars:
#   TEST_TIMINGS_FILE - JSON containing default_seconds and a tests map
#   BASE_CONFIG_FILE  - Existing nextest configuration
#   OUTPUT_CONFIG_FILE - Generated nextest configuration
#
# Exactly one test-name input is required:
#   TEST_NAMES_CSV    - Comma-separated literal test names
#   TEST_NAMES_FILE   - Newline-delimited literal test names
#
# Optional env vars:
#   NEXTEST_PROFILE   - Profile receiving the overrides (default: ci-sequential)
#   RECORDED_TESTS_ONLY - Prioritize only tests present in the timings (default: false)
set -euo pipefail

test_names_csv="${TEST_NAMES_CSV:-}"
test_names_file="${TEST_NAMES_FILE:-}"
timings_file="${TEST_TIMINGS_FILE:?TEST_TIMINGS_FILE is required}"
base_config_file="${BASE_CONFIG_FILE:?BASE_CONFIG_FILE is required}"
output_config_file="${OUTPUT_CONFIG_FILE:?OUTPUT_CONFIG_FILE is required}"
nextest_profile="${NEXTEST_PROFILE:-ci-sequential}"
recorded_tests_only="${RECORDED_TESTS_ONLY:-false}"

if { [[ -z "${test_names_csv}" ]] && [[ -z "${test_names_file}" ]]; } ||
    { [[ -n "${test_names_csv}" ]] && [[ -n "${test_names_file}" ]]; }; then
    echo "Provide exactly one of TEST_NAMES_CSV or TEST_NAMES_FILE" >&2
    exit 1
fi
if [[ -n "${test_names_file}" && ! -f "${test_names_file}" ]]; then
    echo "Test names file not found: ${test_names_file}" >&2
    exit 1
fi
if [[ "${recorded_tests_only}" != "true" && "${recorded_tests_only}" != "false" ]]; then
    echo "RECORDED_TESTS_ONLY must be true or false: ${recorded_tests_only}" >&2
    exit 1
fi

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

normalized_names_file="${test_names_file}"
if [[ -n "${test_names_csv}" ]]; then
    normalized_names_file=$(mktemp)
    trap 'rm -f "${normalized_names_file}"' EXIT
    jq -Rnr --arg test_names "${test_names_csv}" '
        $test_names
        | split(",")[]
        | gsub("^[[:space:]]+|[[:space:]]+$"; "")
        | select(length > 0)
    ' > "${normalized_names_file}"
fi

mapfile -t ordered_tests < <(
    jq -Rnr \
        --slurpfile timings "${timings_file}" \
        --arg recorded_tests_only "${recorded_tests_only}" '
        ($timings[0]) as $timings
        | [inputs | select(length > 0)]
        | unique
        | map({
            name: .,
            weight: ($timings.tests[.] // $timings.default_seconds)
          })
        | map(. as $test | select(
            $recorded_tests_only == "false" or ($timings.tests | has($test.name))
          ))
        | sort_by([(-.weight), .name])
        | .[].name
    ' < "${normalized_names_file}"
)

test_count=${#ordered_tests[@]}
if (( test_count == 0 )); then
    if [[ "${recorded_tests_only}" == "true" ]]; then
        cp "${base_config_file}" "${output_config_file}"
        exit 0
    fi
    echo "The test-name input contains no test names" >&2
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
