#!/usr/bin/env bash
#
# Reports the outcome of every test in a flakiness scan run.
#
# Reads the nextest JUnit reports produced by the test jobs and records what
# happened to each test that ran. The workflow runs the `flaky-scan` profile with
# `retries = 0`, so every failure here is a single-attempt failure against the
# default branch - a flake candidate, not a retry artifact and not caused by a
# pull request's changes.
#
# Required env vars:
#   JUNIT_DIR           - Directory holding the downloaded junit_*.xml reports
#   OBSERVED_TESTS_FILE - JSONL to write, one object per test that ran, sorted
#                         by name:
#                           {"name": ..., "status": "pass"|"fail",
#                            "duration": <seconds>, "excerpt": ...}
#                         `excerpt` is empty for passing tests. Skipped tests are
#                         omitted: they never reached a verdict.
#
# Outputs:
#   - the file above, read by the issue steps in this same job
#   - a markdown summary appended to $GITHUB_STEP_SUMMARY when set
##
# Exit behavior:
#   Exits 0 when report can be produced, whether or not any test failed.
#
#   Exits 1 when a precondition is missing, or when the reports cannot be parsed. This
#   is a failure of the scan itself, not of any test.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

## Load logging functions
source "${script_dir}/lib/logging.sh"

## ── Main ────────────────────────────────────────────────────────────────────
main() {
    initialize

    local -a reports
    local report_count report observed_count failed_count
    local failed_names name status duration failure_text excerpt_text record

    ## Collect the reports
    mapfile -t reports < <(find "${CFG_JUNIT_DIR}" -type f -name '*.xml' 2> /dev/null | sort)
    report_count="${#reports[@]}"

    : > "${CFG_OBSERVED_TESTS_FILE}"

    # A run that produced no reports failed before the tests executed. That is a
    # very different thing from "no test failed", so never let it read as success.
    if [[ "${report_count}" -eq 0 ]]; then
        warn "No JUnit reports found under $(hl "${CFG_JUNIT_DIR}")"
        summary "## Flaky test scan"
        summary ""
        summary "**No test results were parsed.** Check the archive and test jobs."
        summary ""
        return 0
    fi

    info "Parsing $(hl "${report_count}") JUnit report(s) from $(hl "${CFG_JUNIT_DIR}")..."

    ## Record every test that ran
    for report in "${reports[@]}"; do
        # Gather failed tests names per report
        failed_names=$(test_names "${report}" '//testcase[failure or error]/@name')

        while read -r name; do
            [[ -z "${name}" ]] && continue

            # Fetch values by name rather than by position, so they cannot be
            # mismatched across separate queries. Rust test names contain no
            # quotes, so embedding one in the XPath is safe.
            duration=$(xpath "string(//testcase[@name='${name}']/@time)" "${report}" \
                | awk '{printf "%.0f", $1}')

            if grep -qxF "${name}" <<< "${failed_names}"; then
                status="fail"
                # string() gives the element's decoded string value. 
                failure_text=$(xpath "string(//testcase[@name='${name}']/*[self::failure or self::error])" "${report}")

                # nextest repeats the first line of the body in @message, so prefer
                # the body and fall back to @message only when the body is empty -
                # which is what happens when the test process aborts.
                if [[ -z "${failure_text//[[:space:]]/}" ]]; then
                    failure_text=$(xpath "string(//testcase[@name='${name}']/*[self::failure or self::error]/@message)" "${report}")
                fi
                excerpt_text="$(excerpt "${failure_text}")"
            else
                status="pass"
                excerpt_text=""
            fi

            jq -nc \
                --arg name "${name}" \
                --arg status "${status}" \
                --arg excerpt "${excerpt_text}" \
                --argjson duration "${duration:-0}" \
                '{name: $name, status: $status, duration: $duration, excerpt: $excerpt}' \
                >> "${CFG_OBSERVED_TESTS_FILE}"
        done < <(test_names "${report}" '//testcase/@name')
    done

    # Sort by test name
    if [[ -s "${CFG_OBSERVED_TESTS_FILE}" ]]; then
        jq -s -c 'sort_by(.name)[]' "${CFG_OBSERVED_TESTS_FILE}" > "${CFG_OBSERVED_TESTS_FILE}.sorted"
        mv "${CFG_OBSERVED_TESTS_FILE}.sorted" "${CFG_OBSERVED_TESTS_FILE}"
    fi

    observed_count=$(grep -c '' "${CFG_OBSERVED_TESTS_FILE}" || true)
    failed_count=$(jq -s '[.[] | select(.status == "fail")] | length' "${CFG_OBSERVED_TESTS_FILE}")

    ## Report
    summary "## Flaky test scan"
    summary ""
    summary "| | |"
    summary "| --- | --- |"
    summary "| JUnit reports parsed | ${report_count} |"
    summary "| Tests observed | ${observed_count} |"
    summary "| Failed | ${failed_count} |"
    summary ""

    if [[ "${failed_count}" -eq 0 ]]; then
        summary "No failures. Every test passed on a single attempt."
        summary ""
    else
        summary "### Failed tests"
        summary ""
        summary "| Test | Duration |"
        summary "| --- | --- |"
        while IFS=$'\t' read -r name duration; do
            summary "| \`${name}\` | ${duration}s |"
        done < <(jq -r 'select(.status == "fail") | [.name, .duration] | @tsv' "${CFG_OBSERVED_TESTS_FILE}")
        summary ""

        # The failing records, collapsed so they do not dominate the summary.
        # Filtered to failures: printing every observed test would be hundreds of
        # lines on a full-width run.
        summary "<details>"
        summary "<summary>Raw results for failures (<code>${CFG_OBSERVED_TESTS_FILE}</code>)</summary>"
        summary ""
        summary '```json'
        while IFS= read -r record; do
            summary "${record}"
        done < <(jq -c 'select(.status == "fail")' "${CFG_OBSERVED_TESTS_FILE}")
        summary '```'
        summary ""
        summary "</details>"
    fi

    info "Wrote $(hl "${observed_count}") observed test(s), $(hl "${failed_count}") failing, to $(hl "${CFG_OBSERVED_TESTS_FILE}")"
}

## ── Helpers ─────────────────────────────────────────────────────────────────

# Initialize the script, checking preconditions and loading configuration. 
# Exits on failure.
initialize() {
    ## Preconditions: tools
    local missing_cmds=() cmd
    for cmd in awk find grep jq sort xmllint; do
        command -v "${cmd}" > /dev/null 2>&1 || missing_cmds+=("${cmd}")
    done
    if (( ${#missing_cmds[@]} > 0 )); then
        error "Missing required command(s): $(hl "${missing_cmds[*]}")"
        # Named only when it is the one missing: it is the only non-obvious package.
        if [[ " ${missing_cmds[*]} " == *" xmllint "* ]]; then
            error "xmllint comes from the $(hl "libxml2-utils") package"
        fi
        exit 1
    fi

    ## Preconditions: inputs
    # Checked before binding, so the bindings below can be plain expansions.
    info "Checking required env vars..."
    require_vars \
        JUNIT_DIR \
        OBSERVED_TESTS_FILE

    ## Configuration
    CFG_JUNIT_DIR="${JUNIT_DIR}"
    CFG_OBSERVED_TESTS_FILE="${OBSERVED_TESTS_FILE}"

    # Enough of the output to recognize the failure, without pasting a whole
    # backtrace into an issue body later. Read by excerpt() below.
    CFG_EXCERPT_LINES=10
}

# Exit unless every named variable is set and non-empty.
# Reports all the misses at once.
require_vars() {
    local missing=() var

    for var in "$@"; do
        [[ -n "${!var:-}" ]] || missing+=("${var}")
    done

    if (( ${#missing[@]} > 0 )); then
        error "Missing required var(s): $(hl "${missing[*]}")"
        exit 1
    fi
}

# Run an XPath query, treating "no match" as empty rather than an error.
# xmllint exits non-zero and prints "XPath set is empty" when nothing matches.
xpath() {
    local expression="$1" file="$2"
    xmllint --xpath "${expression}" "${file}" 2> /dev/null || true
}

# Test names from an XPath selecting @name attributes. Querying attributes
# returns ` name="..."` pairs, so pull the values back out.
test_names() {
    local file="$1" expression="$2"
    xpath "${expression}" "${file}" \
        | grep -o 'name="[^"]*"' \
        | sed 's/^name="//; s/"$//' || true
}

# The part of the captured output that says why the test failed. Prefers the
# panic line and what follows; otherwise keeps the tail, which is where nextest
# prints the reason.
excerpt() {
    local text="$1"

    # An empty failure element carries no diagnostic at all: nextest emits
    # a bare <failure type="test failure"/> in some versions when output
    # storage is disabled. Handle it explicitly - otherwise the greps below
    # match nothing, exit 1, and pipefail plus set -e abort the whole script,
    # losing the entire report.
    if [[ -z "${text//[[:space:]]/}" ]]; then
        printf '%s' '(no failure detail in the JUnit report; see the job log)'
        return 0
    fi

    if grep -qi 'panicked at' <<< "${text}"; then
        grep -i -A"$(( CFG_EXCERPT_LINES - 1 ))" 'panicked at' <<< "${text}" \
            | sed '/[Ss]tack backtrace:/Q' \
            | head -n "${CFG_EXCERPT_LINES}"
    else
        grep -v '^[[:space:]]*$' <<< "${text}" | tail -n 15
    # A trailing `|| true` because this helper is best-effort by design: no
    # shape of failure output should be able to fail the run.
    fi | sed 's/[[:space:]]*$//' || true
}


## ── Entry point ─────────────────────────────────────────────────────────────
# Guarded so a this file can be sourced and exercise the helpers above
# in isolation without running the whole thing.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
