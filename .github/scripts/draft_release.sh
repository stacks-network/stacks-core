#!/usr/bin/env bash
# Generates a GitHub release body by expanding a template with release variables.
# Notes:
#   - stacks-core releases will output all docker images with a sha256 (if available), including stacks-signer images
#   - stacks-core releases will link to a companion stacks-signer release (e.g. stacks-core release 1.2.3.4.5 will link to stacks-signer 1.2.3.4.5.0)
#   - stacks-signer releases will *only* output images for the stacks-signer release (for stacks-core, a release link is provided for those images)
#   - stacks-signer point releases will link to the stacks-core release for that version (e.g. stacks-signer 1.2.3.4.5.1 will link to stacks-core 1.2.3.4.5)
#   - rc releases will respect the same above rules
#     - if there is an rc signer release, e.g. 1.2.3.4.5.1-rc1, it will link to stacks-core 1.2.3.4.5-rc1
#
# Required env vars:
#   VERSION      - Bare release version (no 'signer-' prefix)
#   CHANGELOG    - Path to the CHANGELOG.md file
#   TEMPLATE     - Path to the release body template
#   RELEASE_TYPE - one of: stacks-core, stacks-signer
#   REPO         - repository to create release for
#
# Optional env var:
#   DIGEST_MANIFEST - json file containing sha256 for image variants and package IDs
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


# Template variables substituted:
#   ${node_tag}          - 5-part node version  (e.g. 1.2.3.4.5)
#   ${signer_tag}        - 6-part signer version (e.g. 1.2.3.4.5.0)
#   ${node_epoch}        - epoch compatibility tag (e.g. 1.2.x.x.x)
#   ${companion_line}    - line to reference companion release (differs by RELEASE_TYPE, stacks-core mentions stacks-signer and vice-versa)
#   ${changelog_content} - extracted changelog block (may be empty for signer releases)
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

DIGEST_MANIFEST="${DIGEST_MANIFEST:-}"

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
    # Extract first 5 dot-separated parts and preserve any suffix (like -rc1)
    node_tag=$(echo "${signer_tag}" | sed 's/^\([^.]*\.[^.]*\.[^.]*\.[^.]*\.[^.]*\)\.[0-9]*\(.*\)$/\1\2/')
    companion_line="The version of stacks-node compatible with this release is ${node_tag}, available here: https://github.com/${REPO}/releases/tag/${node_tag}."
else
    node_tag="${VERSION}"
    signer_tag=$(sed 's/\(-[^-]*\)*$/.0\1/' <<<"${node_tag}")
    companion_line="The version of stacks-signer compatible with this release is ${signer_tag}, available at: https://github.com/${REPO}/releases/tag/signer-${signer_tag}."
fi

node_epoch="$(echo "${node_tag}" | cut -d. -f1-2).x.x.x"
repo_owner="${REPO%%/*}"

## ── Format docker pull commands with digests (if manifest provided) ─────────
format_docker_pulls() {
    local manifest_file="$1"
    local node_tag="$2"
    local signer_tag="$3"
    local repo_owner="$4"

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
        # if RELEASE_TYPE is stacks-core, show all images. if stacks-signer, only show signer images
        if [[ "${RELEASE_TYPE}" != "stacks-signer" ]]; then
            printf "#### **stacks-core**\n"
            print_image "stacks-core" "glibc" "${node_tag}" "${core_glibc}" "${core_glibc_id}"
            print_image "stacks-core" "musl" "${node_tag}" "${core_musl}" "${core_musl_id}"

            printf "#### **stacks-signer**\n"
        else
            printf "#### **stacks-signer**\n"
        fi
        print_image "stacks-signer" "glibc" "${signer_tag}" "${signer_glibc}" "${signer_glibc_id}"
        print_image "stacks-signer" "musl" "${signer_tag}" "${signer_musl}" "${signer_musl_id}"
    }
}

## ── Generate docker pull section with or without digests ───────────────────
if [[ -n "${DIGEST_MANIFEST}" ]] && [[ -f "${DIGEST_MANIFEST}" ]]; then
    info "docker_pulls: using digest manifest from ${DIGEST_MANIFEST}"
    if ! docker_pulls_with_digests=$(format_docker_pulls "${DIGEST_MANIFEST}" "${node_tag}" "${signer_tag}" "${repo_owner}"); then
        # Fallback if manifest processing fails
        info "docker_pulls: manifest processing failed, using fallback"
        docker_pulls_with_digests=$(cat <<-EOF
		### Docker images have been published to GitHub Container Registry:

		#### **stacks-core**: https://github.com/${REPO}/pkgs/container/stacks-core
		* Debian (glibc):
		\`\`\`sh
		docker pull ghcr.io/${repo_owner}/stacks-core:${node_tag}
		\`\`\`

		#### **stacks-signer**: https://github.com/${REPO}/pkgs/container/stacks-signer
		* Debian (glibc):
		\`\`\`sh
		docker pull ghcr.io/${repo_owner}/stacks-signer:${signer_tag}
		\`\`\`
		EOF
        )
    fi
else
    # Fallback to simple docker pull commands without digests (with generic link to ghcr)
    info "docker_pulls: digest manifest not found, using fallback"
    docker_pulls_with_digests=$(cat <<-EOF
	### Docker images have been published to GitHub Container Registry:

	#### **stacks-core**: https://github.com/${REPO}/pkgs/container/stacks-core
	* Debian (glibc):
	\`\`\`sh
	docker pull ghcr.io/${repo_owner}/stacks-core:${node_tag}
	\`\`\`

	#### **stacks-signer**: https://github.com/${REPO}/pkgs/container/stacks-signer
	* Debian (glibc):
	\`\`\`sh
	docker pull ghcr.io/${repo_owner}/stacks-signer:${signer_tag}
	\`\`\`
	EOF
    )
fi

## ── Extract changelog content (empty is acceptable) ─────────────────────────
# Extract the changelog section for this release: from "## [VERSION]" until the next "## " header
changelog_content=$(awk -v ver="## [${VERSION}]" '
    { sub(/[[:space:]]*$/, "") }
    $0 == ver       { found=1; next }
    found && /^## / { exit }
    found
' "${CHANGELOG}")

## ── Build changelog section (omitted entirely when content is empty) ────────
if [[ "${RELEASE_TYPE}" == "stacks-signer" ]]; then
    changelog_link="https://github.com/${REPO}/blob/signer-${signer_tag}/stacks-signer/CHANGELOG.md"
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
info "DIGEST_MANIFEST:   $(hl "${DIGEST_MANIFEST}")"

changelog_lines=0
[[ -n "${changelog_content}" ]] && changelog_lines=$(printf '%s\n' "${changelog_content}" | wc -l | tr -d '[:space:]')
info "changelog_content: $(hl "${CHANGELOG}") (${changelog_lines} lines)"

## ── Expand template ─────────────────────────────────────────────────────────
export node_tag signer_tag node_epoch companion_line changelog_section repo_owner docker_pulls_with_digests

# shellcheck disable=SC2016
if ! body=$(envsubst '${node_tag}${signer_tag}${node_epoch}${companion_line}${changelog_section}${repo_owner}${docker_pulls_with_digests}' < "${TEMPLATE}" 2>/dev/null); then
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
