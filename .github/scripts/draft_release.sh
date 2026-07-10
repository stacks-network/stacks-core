#!/usr/bin/env bash
# Generates a GitHub release body by expanding a template with release variables.
# Notes:
#   - the node and signer share a single version and ship in one combined release
#   - the release body lists all docker images (stacks-core and stacks-signer)
#     with a sha256 (if available)
#   - the release body includes the node changelog section and, when present,
#     the signer changelog section
#   - rc releases follow the same rules
#
# Required env vars:
#   VERSION      - Release version (e.g. 4.0.0)
#   CHANGELOG    - Path to the node CHANGELOG.md file
#   TEMPLATE     - Path to the release body template
#   REPO         - repository to create release for
#
# Optional env vars:
#   SIGNER_CHANGELOG - Path to the signer CHANGELOG.md file (its section is
#       omitted from the body when unset or when it has no entry for VERSION)
#   DIGEST_MANIFEST  - json file containing sha256 for image variants and package IDs
#       Example manifest:
#       {
#         "stacks-core": {
#           "glibc": {
#             "digest": "sha256:83ff367380258dd2479843142f9214d84205a42b08b5f54bac40fb96ccede0de",
#             "package_id": "849093729"
#           },
#           "musl": {
#             "digest": "sha256:bd95c526a82b987d7a8bb2f2719b7ad7f4001b1449394ea276ee4637718bda95",
#             "package_id": "849093807"
#           }
#         },
#         "stacks-signer": {
#           "glibc": {
#             "digest": "sha256:8e34904e922c025289537f9c34844845c8de9d09d011b24b7bffe9de8b6efaf3",
#             "package_id": "849092426"
#           },
#           "musl": {
#             "digest": "sha256:cc28fb33521c766502d5f3b63198730285b9706280ddb23145e0926e79a542f6",
#             "package_id": "849092517"
#           }
#         }
#       }
#
# Template variables substituted:
#   ${tag}                      - release version (e.g. 4.0.0)
#   ${node_epoch}               - epoch compatibility tag (e.g. 4.0.x)
#   ${changelog_section}        - extracted node changelog block (may be empty)
#   ${signer_changelog_section} - extracted signer changelog block (may be empty)
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
: "${REPO:?REPO is required}"

SIGNER_CHANGELOG="${SIGNER_CHANGELOG:-}"
DIGEST_MANIFEST="${DIGEST_MANIFEST:-}"

if [[ ! -f "${TEMPLATE}" ]]; then
    error "template not found: $(hl "${TEMPLATE}")"
    exit 1
fi

if [[ ! -f "${CHANGELOG}" ]]; then
    error "changelog not found: $(hl "${CHANGELOG}")"
    exit 1
fi

## ── Derive tag, node_epoch ───────────────────────────────────────────────────
tag="${VERSION}"
node_epoch="$(echo "${tag}" | cut -d. -f1-2).x"
repo_owner="${REPO%%/*}"

## ── Format docker pull commands with digests (if manifest provided) ─────────
format_docker_pulls() {
    local manifest_file="$1"
    local tag="$2"
    local repo_owner="$3"

    # Print a single image variant with or without digest
    print_image() {
        local image_name="$1"
        local variant="$2"
        local tag="$3"
        local digest="$4"
        local package_id="$5"
        local dist os_name

        case "${variant}" in
            glibc)
                dist="";
                os_name="Debian (glibc)"
                ;;
            musl)
                dist="-alpine";
                os_name="Alpine (musl)"
                ;;
        esac
        if [[ -n "${package_id}" ]]; then
            printf "* %s: https://github.com/%s/%s/pkgs/container/%s/%s?tag=%s%s\n" \
                "${os_name}" "${repo_owner}" "${image_name}" "${image_name}" "${package_id}" "${tag}" "${dist}"
        else
            printf "* %s: https://github.com/%s/%s/pkgs/container/%s\n" \
                "${os_name}" "${repo_owner}" "${image_name}" "${image_name}"
        fi

        local digest_suffix=""
        [[ -n "${digest}" ]] && digest_suffix="@${digest}"

        printf '```sh\n'
        printf "docker pull ghcr.io/%s/%s:%s%s%s\n" "${repo_owner}" "${image_name}" "${tag}" "${dist}" "${digest_suffix}"
        printf '```\n'
        printf "\n"
    }

    # Validate JSON manifest
    if ! jq empty "${manifest_file}" 2>/dev/null; then
        warn "invalid JSON in digest manifest: $(hl "${manifest_file}"), falling back to simple docker pulls"
        info "manifest file contents:"
        cat "${manifest_file}" >&2
        return 1
    fi

    # Read digests and package IDs from JSON manifest
    local core_glibc core_glibc_id core_musl core_musl_id signer_glibc signer_glibc_id signer_musl signer_musl_id
    core_glibc=$(jq -r '.["stacks-core"].glibc.digest // empty' "${manifest_file}" 2>/dev/null) || return 1
    core_glibc_id=$(jq -r '.["stacks-core"].glibc.package_id // empty' "${manifest_file}" 2>/dev/null) || return 1
    core_musl=$(jq -r '.["stacks-core"].musl.digest // empty' "${manifest_file}" 2>/dev/null) || return 1
    core_musl_id=$(jq -r '.["stacks-core"].musl.package_id // empty' "${manifest_file}" 2>/dev/null) || return 1
    signer_glibc=$(jq -r '.["stacks-signer"].glibc.digest // empty' "${manifest_file}" 2>/dev/null) || return 1
    signer_glibc_id=$(jq -r '.["stacks-signer"].glibc.package_id // empty' "${manifest_file}" 2>/dev/null) || return 1
    signer_musl=$(jq -r '.["stacks-signer"].musl.digest // empty' "${manifest_file}" 2>/dev/null) || return 1
    signer_musl_id=$(jq -r '.["stacks-signer"].musl.package_id // empty' "${manifest_file}" 2>/dev/null) || return 1

    {
        printf "### Docker images have been published to GitHub Container Registry:\n\n"
        printf "#### **stacks-core**\n"
        print_image "stacks-core" "glibc" "${tag}" "${core_glibc}" "${core_glibc_id}"
        print_image "stacks-core" "musl" "${tag}" "${core_musl}" "${core_musl_id}"

        printf "#### **stacks-signer**\n"
        print_image "stacks-signer" "glibc" "${tag}" "${signer_glibc}" "${signer_glibc_id}"
        print_image "stacks-signer" "musl" "${tag}" "${signer_musl}" "${signer_musl_id}"
    }
}

## ── Generate docker pull section with or without digests ───────────────────
if [[ -n "${DIGEST_MANIFEST}" ]] && [[ -f "${DIGEST_MANIFEST}" ]]; then
    info "docker_pulls: using digest manifest from ${DIGEST_MANIFEST}"
    if ! docker_pulls_with_digests=$(format_docker_pulls "${DIGEST_MANIFEST}" "${tag}" "${repo_owner}"); then
        # Fallback if manifest processing fails
        info "docker_pulls: manifest processing failed, using fallback"
        docker_pulls_with_digests=""
    fi
fi
if [[ -z "${docker_pulls_with_digests:-}" ]]; then
    # Fallback to simple docker pull commands without digests (with generic link to ghcr)
    info "docker_pulls: digest manifest not found, using fallback"
    docker_pulls_with_digests=$(cat <<-EOF
	### Docker images have been published to GitHub Container Registry:

	#### **stacks-core**: https://github.com/${REPO}/pkgs/container/stacks-core
	* Debian (glibc):
	\`\`\`sh
	docker pull ghcr.io/${repo_owner}/stacks-core:${tag}
	\`\`\`

	#### **stacks-signer**: https://github.com/${REPO}/pkgs/container/stacks-signer
	* Debian (glibc):
	\`\`\`sh
	docker pull ghcr.io/${repo_owner}/stacks-signer:${tag}
	\`\`\`
	EOF
    )
fi

## ── Extract changelog content (empty is acceptable) ─────────────────────────
# Extract the changelog section for this release: from "## [VERSION]" until the next "## " header
extract_changelog() {
    local changelog_file="$1"
    awk -v ver="## [${VERSION}]" '
        { sub(/[[:space:]]*$/, "") }
        $0 == ver       { found=1; next }
        found && /^## / { exit }
        found
    ' "${changelog_file}"
}

changelog_content=$(extract_changelog "${CHANGELOG}")

signer_changelog_content=""
if [[ -n "${SIGNER_CHANGELOG}" ]] && [[ -f "${SIGNER_CHANGELOG}" ]]; then
    signer_changelog_content=$(extract_changelog "${SIGNER_CHANGELOG}")
fi

## ── Build changelog sections (omitted entirely when content is empty) ───────
changelog_link="https://github.com/${REPO}/blob/${tag}/CHANGELOG.md"
signer_changelog_link="https://github.com/${REPO}/blob/${tag}/stacks-signer/CHANGELOG.md"

if [[ -n "${changelog_content}" ]]; then
    changelog_section="This release includes the following changes:
${changelog_link}

${changelog_content}"
else
    changelog_section=""
fi

if [[ -n "${signer_changelog_content}" ]]; then
    signer_changelog_section="This release includes the following stacks-signer changes:
${signer_changelog_link}

${signer_changelog_content}"
else
    signer_changelog_section=""
fi

## ── Log derived values ──────────────────────────────────────────────────────
info "tag:               $(hl "${tag}")"
info "node_epoch:        $(hl "${node_epoch}")"
info "changelog_link:    $(hl "${changelog_link}")"
info "DIGEST_MANIFEST:   $(hl "${DIGEST_MANIFEST}")"

changelog_lines=0
[[ -n "${changelog_content}" ]] && changelog_lines=$(printf '%s\n' "${changelog_content}" | wc -l | tr -d '[:space:]')
info "changelog_content: $(hl "${CHANGELOG}") (${changelog_lines} lines)"

signer_changelog_lines=0
[[ -n "${signer_changelog_content}" ]] && signer_changelog_lines=$(printf '%s\n' "${signer_changelog_content}" | wc -l | tr -d '[:space:]')
info "signer_changelog_content: $(hl "${SIGNER_CHANGELOG:-<unset>}") (${signer_changelog_lines} lines)"

## ── Expand template ─────────────────────────────────────────────────────────
export tag node_epoch changelog_section signer_changelog_section repo_owner docker_pulls_with_digests

# shellcheck disable=SC2016
if ! body=$(envsubst '${tag}${node_epoch}${changelog_section}${signer_changelog_section}${repo_owner}${docker_pulls_with_digests}' < "${TEMPLATE}" 2>/dev/null); then
    error "failed to expand template with envsubst"
    exit 1
fi

## ── Output ──────────────────────────────────────────────────────────────────
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    # Use a delimiter to avoid collision with body content
    # GitHub Actions requires multiline variable delimiter format
    delimiter="RELEASE_BODY_END_$$_$(date +%s%N)"
    {
        printf 'release_body<<%s\n' "${delimiter}"
        printf '%s\n' "${body}"
        printf '%s\n' "${delimiter}"
    } >> "${GITHUB_OUTPUT}"
    info "release_body written to GITHUB_OUTPUT (${#body} bytes)"
else
    printf '%s\n' "${body}"
fi
