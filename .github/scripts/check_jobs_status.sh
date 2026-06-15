#!/usr/bin/env bash
# Checks whether all required jobs in a GitHub Actions workflow have succeeded.
#
# Required env vars (set by the calling workflow step):
#   JOBS          - JSON object of job results
#
# Optional env vars:
#   SUMMARY_PRINT - "true" to append a failure summary to $GITHUB_STEP_SUMMARY; defaults to "false"
#
# Exit behaviour:
#   - All jobs succeeded  → exits 0
#   - Any job failed      → prints failing job names, writes summary, exits 1
#   - JOBS is invalid JSON → writes error to $GITHUB_STEP_SUMMARY, exits 1
set -euo pipefail

## Load logging functions
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## ── Check for required binaries ─────────────────────────────────────────────
missing=0
for cmd in jq; do
    if ! command -v "${cmd}" > /dev/null 2>&1; then
        error "Missing required command: $(hl "${cmd}")"
        missing=1
    fi
done
[[ "${missing}" -eq 1 ]] && exit 1

## ── Validate required inputs ────────────────────────────────────────────────
: "${JOBS:?JOBS env var is required}"
SUMMARY_PRINT="${SUMMARY_PRINT:-false}"

## ── Validate JOBS is parseable JSON ─────────────────────────────────────────
if ! jq -e type <<< "${JOBS}" > /dev/null 2>&1; then
    error "JOBS env var is not valid JSON. Received: $(hl "${JOBS}")"
    exit 1
fi

## ── Collect all jobs whose result is not "success" ──────────────────────────
failing_jobs=()
while IFS= read -r job_name; do
    [[ -n "${job_name}" ]] && failing_jobs+=("${job_name}")
done < <(jq -r 'to_entries[] | select(.value.result != "success") | .key' <<< "${JOBS}")

## ── All jobs passed ─────────────────────────────────────────────────────────
if [[ ${#failing_jobs[@]} -eq 0 ]]; then
    info "All jobs were successful"
    exit 0
fi

## ── Report failing jobs ─────────────────────────────────────────────────────
error "The following required jobs did not succeed:"
for job in "${failing_jobs[@]}"; do
    echo "  - $(hl "${job}")" >&2
done

## ── Optionally append summary ───────────────────────────────────────────────
if [[ "${SUMMARY_PRINT}" == "true" ]]; then
    {
        echo "### Jobs Status"
        echo ""
        echo "The following required jobs did not succeed:"
        echo ""
        for job in "${failing_jobs[@]}"; do
            echo "- \`${job}\`"
        done
    } >> "${GITHUB_STEP_SUMMARY}"
fi

exit 1
