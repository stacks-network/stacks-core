#!/usr/bin/env bash
# Discovers available `bitcoin/bitcoin` Docker Hub tags and returns a JSON payload.
#
# Usage:
#   docker_bitcoin_majors.sh [START_MAJOR]
#
# Arguments:
#   START_MAJOR  Optional integer major version to start discovery from (default: 25)
#
# Output:
#   {
#     "start_major": <number>,
#     "major_versions": [<major>, ...],
#     "versions": [<resolved_tag>, ...]
#   }
#
# Resolution rules:
#   - Includes tags matching `X` and `X.Y` only.
#   - For each major X, prefers highest discovered minor (`X.Y`) over bare `X`.
#   - Validates discovered majors are contiguous from START_MAJOR to latest.
#
# Exit behaviour:
#   - Invalid input, API/read failure, no matching tags, or non-contiguous majors → exits 1
set -euo pipefail

# Load logging functions
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## ── Require bash 5+ ---------------------------------------------------------
if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    error "bash 5 or higher is required (found ${BASH_VERSION})"
    exit 1
fi

## ── Check for required binaries ─────────────────────────────────────────────
missing=0
for cmd in curl jq sort; do
    if ! command -v "${cmd}" > /dev/null 2>&1; then
        error "Missing required command: $(hl "${cmd}")"
        missing=1
    fi
done
[[ "${missing}" -eq 1 ]] && exit 1

main() {
    local start_major="${1:-25}"
    local -A resolved_tags

    ## ── Validate input ──────────────────────────────────────────────────────
    if ! [[ "$start_major" =~ ^[0-9]+$ ]]; then
        error "START_MAJOR must be an integer (got: $(hl "${start_major}"))"
        exit 1
    fi

    ## ── Retrieve and resolve tags ───────────────────────────────────────────
    local next_url="https://hub.docker.com/v2/repositories/bitcoin/bitcoin/tags?page_size=100"
    while [[ -n "$next_url" && "$next_url" != "null" ]]; do
        local response_json
        response_json="$(curl -fsSL --connect-timeout 10 --max-time 30 "$next_url")"

        mapfile -t tags < <(jq -r '.results[].name' <<< "$response_json")

        for tag in "${tags[@]}"; do
            if [[ "$tag" =~ ^([0-9]+)(\.([0-9]+))?$ ]]; then
                local major="${BASH_REMATCH[1]}"
                local minor="${BASH_REMATCH[3]}"

                if (( major >= start_major )); then
                    set_resolved_tag resolved_tags "$major" "$minor"
                fi
            fi
        done

        next_url="$(jq -r '.next' <<< "$response_json")"
    done

    if (( ${#resolved_tags[@]} == 0 )); then
        error "No bitcoind major tags found from version $(hl "${start_major}") upward"
        exit 1
    fi

    mapfile -t sorted_majors < <(printf '%s\n' "${!resolved_tags[@]}" | sort -n)

    ## ── Validate majors ─────────────────────────────────────────────────────
    if [[ "${sorted_majors[0]}" != "$start_major" ]]; then
        error "Expected start_major=$(hl "${start_major}") to be present, but first discovered major is $(hl "${sorted_majors[0]}")"
        exit 1
    fi

    local expected_major="$start_major"
    for major in "${sorted_majors[@]}"; do
        if (( major != expected_major )); then
            error "Major versions are not contiguous: expected $(hl "${expected_major}") but found $(hl "${major}")"
            exit 1
        fi
        expected_major=$((expected_major + 1))
    done

    ## ── Build JSON result ───────────────────────────────────────────────────
    local major_versions_json
    major_versions_json="$(printf '%s\n' "${sorted_majors[@]}" | jq -R . | jq -s -c .)"

    local full_versions_json
    full_versions_json="$({
        for major in "${sorted_majors[@]}"; do
            printf '%s\n' "${resolved_tags[$major]}"
        done
    } | jq -R . | jq -s -c .)"

    if [[ -z "${full_versions_json}" ]]; then
        error "Unable to parse versions JSON from resolved tags"
        exit 1
    fi

    info "start_major:    $(hl "${start_major}")"
    info "major_versions: $(hl "${major_versions_json}")"
    info "versions:       $(hl "${full_versions_json}")"

    ## ── Output ──────────────────────────────────────────────────────────────
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "versions=${full_versions_json}" >> "${GITHUB_OUTPUT}"
        info "versions written to GITHUB_OUTPUT"
    else
        info "versions=${full_versions_json}"
    fi
}

set_resolved_tag() {
    local map_name="$1"
    local major="$2"
    local minor="${3:-}"
    declare -n resolved_tags_ref="$map_name"

    if [[ ! -v resolved_tags_ref[$major] ]]; then
        resolved_tags_ref["$major"]="$major"
    fi

    local current="${resolved_tags_ref[$major]}"

    if [[ -z "$minor" ]]; then
        return
    fi

    local candidate="${major}.${minor}"

    if [[ "$current" == "$major" ]]; then
        resolved_tags_ref["$major"]="$candidate"
        return
    fi

    local current_minor="${current#*.}"
    if (( minor > current_minor )); then
        resolved_tags_ref["$major"]="$candidate"
    fi
}

main "$@"
