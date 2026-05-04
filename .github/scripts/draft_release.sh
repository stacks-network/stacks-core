#!/usr/bin/env bash
# Generates a GitHub release body by expanding a template with release variables.
#
# Required env vars:
#   VERSION      - Bare release version (no 'signer-' prefix)
#                  e.g. 3.4.0.0.0 for stacks-node, 3.4.0.0.0.1 for stacks-signer
#   CHANGELOG    - Path to the CHANGELOG.md file
#   TEMPLATE     - Path to the release body template
#   RELEASE_TYPE - one of: stacks-core, stacks-signer
#
# Template variables substituted:
#   ${node_tag}         - 5-part node version  (e.g. 3.4.0.0.0)
#   ${signer_tag}       - 6-part signer version (e.g. 3.4.0.0.0.0)
#   ${node_epoch}       - epoch compatibility tag (e.g. 3.4.x.x.x)
#   ${companion_line}   - cross-release compatibility line (differs by RELEASE_TYPE)
#   ${changelog_content}- extracted changelog block (may be empty for signer releases)
#
# Outputs:
#   GITHUB_OUTPUT  - Path to the GitHub Actions output file (set by runner); prints to stderr if unset (via logging.sh)
set -euo pipefail

# Load logging functions
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## ── Validate required inputs ────────────────────────────────────────────────
: "${VERSION:?VERSION is required}"
: "${CHANGELOG:?CHANGELOG is required}"
: "${TEMPLATE:?TEMPLATE is required}"
: "${RELEASE_TYPE:?RELEASE_TYPE is required}"
: "${REPO:?REPO is required}"

if [[ ! -f "${TEMPLATE}" ]]; then
    error "template not found: $(hl "${TEMPLATE}")"
    exit 1
fi

if [[ ! -f "${CHANGELOG}" ]]; then
    error "changelog not found: $(hl "${CHANGELOG}")"
    exit 1
fi

## ── Derive node_tag, signer_tag, node_epoch, companion_line ─────────────────
if [[ "${RELEASE_TYPE}" == "stacks-signer" ]]; then
    signer_tag="${VERSION}"
    node_tag="$(echo "${signer_tag}" | cut -d. -f1-5)"
    companion_line="The version of stacks-node compatible with this release is ${node_tag}, available here: https://github.com/${REPO}/releases/tag/${node_tag}."
else
    node_tag="${VERSION}"
    signer_tag="${node_tag}.0"
    companion_line="The version of stacks-signer compatible with this release is ${signer_tag}, available at: https://github.com/${REPO}/releases/tag/signer-${signer_tag}."
fi

node_epoch="$(echo "${node_tag}" | cut -d. -f1-2).x.x.x"
repo="${REPO}"
repo_owner="${REPO%%/*}"

## ── Extract changelog content (empty is acceptable) ─────────────────────────
changelog_content=$(awk -v ver="## [${VERSION}]" '
    { sub(/[[:space:]]*$/, "") }
    $0 == ver       { found=1; next }
    found && /^## / { exit }
    found
' "${CHANGELOG}")

## ── Build changelog section (omitted entirely when content is empty) ────────
if [[ "${RELEASE_TYPE}" == "stacks-signer" ]]; then
    changelog_link="https://github.com/${REPO}/blob/${signer_tag}/stacks-signer/CHANGELOG.md"
else
    changelog_link="https://github.com/${REPO}/blob/${node_tag}/CHANGELOG.md"
fi

if [[ -n "${changelog_content}" ]]; then
    changelog_section="This release includes the following changes:
${changelog_link}

${changelog_content}"
else
    changelog_section=""
fi

## ── Log derived values ──────────────────────────────────────────────────────
info "RELEASE_TYPE:      $(hl "${RELEASE_TYPE}")"
info "node_tag:          $(hl "${node_tag}")"
info "signer_tag:        $(hl "${signer_tag}")"
info "node_epoch:        $(hl "${node_epoch}")"
info "changelog_link:    $(hl "${changelog_link}")"
changelog_lines=0
[[ -n "${changelog_content}" ]] && changelog_lines=$(printf '%s\n' "${changelog_content}" | wc -l | tr -d '[:space:]')
info "changelog_content: $(hl "${CHANGELOG}") (${changelog_lines} lines)"

## ── Expand template ─────────────────────────────────────────────────────────
export node_tag signer_tag node_epoch companion_line changelog_section repo repo_owner
# shellcheck disable=SC2016
body=$(envsubst '${node_tag}${signer_tag}${node_epoch}${companion_line}${changelog_section}${repo}${repo_owner}' < "${TEMPLATE}")

## ── Output ──────────────────────────────────────────────────────────────────
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    # Use a randomised delimiter to avoid collision with body content
    delimiter="RELEASE_BODY_$(set +o pipefail; LC_ALL=C tr -dc 'A-F0-9' < /dev/urandom 2>/dev/null | head -c 16)"
    {
        printf 'release_body<<%s\n' "${delimiter}"
        printf '%s\n' "${body}"
        printf '%s\n' "${delimiter}"
    } >> "${GITHUB_OUTPUT}"
    info "release_body written to GITHUB_OUTPUT"
else
    printf '%s\n' "${body}"
fi
