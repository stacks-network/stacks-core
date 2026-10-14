#!/usr/bin/env bash
#
# Requirement checks. Each helper takes a list of what the script needs,
# reports every one that is missing, and exits 1 - so a caller states its
# requirements once and can then assume they hold.

# Include guard
[[ -n "${_LIB_REQUIRE:-}" ]] && return 0
_LIB_REQUIRE=1

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

# Exit unless every named command is on PATH,
# reporting all the misses at once.
require_cmds() {
    local missing=() cmd

    for cmd in "$@"; do
        command -v "${cmd}" > /dev/null 2>&1 || missing+=("${cmd}")
    done

    if (( ${#missing[@]} > 0 )); then
        error "Missing required command(s): $(hl "${missing[*]}")"
        exit 1
    fi
}

# Exit unless every named variable is set and non-empty, 
# reporting all the misses at once.
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
