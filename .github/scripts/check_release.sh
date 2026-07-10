#!/usr/bin/env bash

# Checks whether the current branch name matches the release pattern and, if so,
# derives the release tag and validates it against versions.toml.
#
# The node and signer share a single version (see versions.toml) and are
# released together: a single `release/x.x.x` branch produces one combined
# GitHub release containing both the stacks-core and stacks-signer
# artifacts/images at that version.
#
# Required env vars:
#   BRANCH  - branch name from github.ref_name (e.g. release/4.0.0)
#
# Exit behaviour:
#   - Branch matches the release pattern → validates versions.toml, writes outputs, exits 0
#   - Branch does not match              → exits 0 (all outputs empty/false; downstream
#                                          jobs guard themselves with is_release checks)
# Outputs:
#   GITHUB_OUTPUT  - Path to the GitHub Actions output file (set by runner); prints to stderr if unset (via logging.sh)
#   tag         - release tag (e.g. 4.0.0)
#   is_release  - "true" if this is a release branch
set -euo pipefail

# Load logging functions from logging.sh for color and standardized output
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## ── Validate required inputs ────────────────────────────────────────────────
: "${BRANCH:?BRANCH is required}"

## ── Release branch pattern ──────────────────────────────────────────────────
# Release: release/x.x.x   (3-part version, major.minor.revision, optional -rcN suffix)
versions_file="versions.toml"
version_key="stacks_node_version"

version_regex="([0-9]+\.){2}[0-9]+(-rc[0-9]+)?"

release_prefix="release/"
release_regex="^${release_prefix}${version_regex}$"

## ── Initialise output variables ─────────────────────────────────────────────
tag=""
is_release=false

## ── Match branch against the release pattern ────────────────────────────────
if [[ "${BRANCH}" =~ ${release_regex} ]]; then
    tag=$(echo "${BRANCH}" | sed "s|^${release_prefix}||")
    is_release=true
else
    # Not a release branch — write empty/false outputs and exit cleanly so that
    # downstream jobs can evaluate their own is_release conditions.
    warn "Branch $(hl "${BRANCH}") does not match a release pattern. Skipping."
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        {
            echo "tag="
            echo "is_release=false"
        } >> "${GITHUB_OUTPUT}"
    else
        info "tag="
        info "is_release=false"
    fi
    exit 0
fi

## ── Validate versions.toml ──────────────────────────────────────────────────
if [[ ! -f "${versions_file}" ]]; then
    error "$(hl "${versions_file}") not found"
    exit 1
fi

version=$(grep "^${version_key}" "${versions_file}" | sed -E 's/.*=[[:space:]]*"([^"]+)"/\1/')

if [[ -z "${version}" ]]; then
    error "$(hl "${version_key}") not found in $(hl "${versions_file}")"
    exit 1
fi

if [[ "${version}" != "${tag}" ]]; then
    error "version in $(hl "${versions_file}") ($(hl "${version}")) does not match branch tag ($(hl "${tag}"))"
    exit 1
fi

info "Version:     $(hl "${version}")"
info "Is release:  $(hl "${is_release}")"

## ── Write outputs ───────────────────────────────────────────────────────────
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        echo "tag=${tag}"
        echo "is_release=${is_release}"
    } >> "${GITHUB_OUTPUT}"
else
    info "tag=${tag}"
    info "is_release=${is_release}"
fi
