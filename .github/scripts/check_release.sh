#!/usr/bin/env bash

# Checks whether the current branch name matches a release pattern and, if so,
# derives the release tags and validates them against versions.toml.
#
# Required env vars:
#   BRANCH  - branch name from github.ref_name (e.g. release/1.0.0.0.0)
#
# Exit behaviour:
#   - Branch matches a release pattern  → validates versions.toml, writes outputs, exits 0
#   - Branch does not match             → exits 0 (all outputs empty/false; downstream
#                                         jobs guard themselves with is_node/signer_release checks)
# Outputs:
#   GITHUB_OUTPUT  - Path to the GitHub Actions output file (set by runner); prints to stderr if unset (via logging.sh)
#   node_tag          - node release tag       (e.g. 1.0.0.0.0)         empty for signer-only releases
#   signer_tag        - signer release tag     (e.g. signer-1.0.0.0.0.0)
#   is_node_release   - "true" if this is a node release branch
#   is_signer_release - "true" if this is a signer release branch
set -euo pipefail

# Load logging functions from logging.sh for color and standardized output
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## ── Validate required inputs ────────────────────────────────────────────────
: "${BRANCH:?BRANCH is required}"

## ── Release branch patterns ─────────────────────────────────────────────────
# Node release:   release/x.x.x.x.x   (5-part version, optional -rcN suffix)
# Signer release: release/signer-x.x.x.x.x.x  (6-part version, optional -rcN suffix)
versions_file="versions.toml"
node_key="stacks_node_version"
signer_key="stacks_signer_version"

node_version_regex="([0-9]+\.){4}[0-9]+(-rc[0-9]+)?"
signer_version_regex="([0-9]+\.){5}[0-9]+(-rc[0-9]+)?"

release_prefix="release/"
signer_prefix="release/signer-"

node_release_regex="^${release_prefix}${node_version_regex}$"
signer_release_regex="^${signer_prefix}${signer_version_regex}$"

## ── Initialise output variables ─────────────────────────────────────────────
node_tag=""
signer_tag=""
is_node_release=false
is_signer_release=false

## ── Match branch against release patterns -----------------------------------
# Signer must be tested first — its prefix (release/signer-) is a superset of
# the node prefix (release/), so a signer branch would also match the node regex.
if [[ "${BRANCH}" =~ ${signer_release_regex} ]]; then
    signer_tag=$(echo "${BRANCH}" | sed "s|^${signer_prefix}||")
    is_signer_release=true
elif [[ "${BRANCH}" =~ ${node_release_regex} ]]; then
    node_tag=$(echo "${BRANCH}" | sed "s|^${release_prefix}||")
    ## Derive the signer tag by appending an extra .0 version component
    signer_tag=$(echo "${node_tag}" | sed 's/\(-[^-]*\)*$/.0\1/')
    is_node_release=true
    is_signer_release=true
else
    # Not a release branch — write empty/false outputs and exit cleanly so that
    # downstream jobs can evaluate their own is_node/signer_release conditions.
    warn "Branch $(hl "${BRANCH}") does not match a release pattern. Skipping."
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        {
            echo "node_tag="
            echo "signer_tag="
            echo "is_node_release=false"
            echo "is_signer_release=false"
        } >> "${GITHUB_OUTPUT}"
    else
        info "node_tag="
        info "signer_tag="
        info "is_node_release=false"
        info "is_signer_release=false"
    fi
    exit 0
fi

## ── Validate versions.toml ──────────────────────────────────────────────────
if [[ ! -f "${versions_file}" ]]; then
    error "$(hl "${versions_file}") not found"
    exit 1
fi

node_version=$(grep "^${node_key}" "${versions_file}" | sed -E 's/.*=[[:space:]]*"([^"]+)"/\1/')
signer_version=$(grep "^${signer_key}" "${versions_file}" | sed -E 's/.*=[[:space:]]*"([^"]+)"/\1/')

if [[ -z "${node_version}" ]]; then
    error "$(hl "${node_key}") not found in $(hl "${versions_file}")"
    exit 1
fi

if [[ -z "${signer_version}" ]]; then
    error "$(hl "${signer_key}") not found in $(hl "${versions_file}")"
    exit 1
fi

if [[ "${is_node_release}" == "true" && "${node_version}" != "${node_tag}" ]]; then
    error "node version in $(hl "${versions_file}") ($(hl "${node_version}")) does not match branch tag ($(hl "${node_tag}"))"
    exit 1
fi

if [[ "${signer_version}" != "${signer_tag}" ]]; then
    error "signer version in $(hl "${versions_file}") ($(hl "${signer_version}")) does not match branch tag ($(hl "${signer_tag}"))"
    exit 1
fi

info "Node version:     $(hl "${node_version}")"
info "Signer version:   $(hl "${signer_version}")"
info "Is node release:  $(hl "${is_node_release}")"
info "Is signer release:$(hl "${is_signer_release}")"

## ── Write outputs ───────────────────────────────────────────────────────────
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        echo "node_tag=${node_tag}"
        echo "signer_tag=${signer_tag}"
        echo "is_node_release=${is_node_release}"
        echo "is_signer_release=${is_signer_release}"
    } >> "${GITHUB_OUTPUT}"
else
    info "node_tag=${node_tag}"
    info "signer_tag=${signer_tag}"
    info "is_node_release=${is_node_release}"
    info "is_signer_release=${is_signer_release}"
fi
