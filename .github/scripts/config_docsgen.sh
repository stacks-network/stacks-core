#!/usr/bin/env bash
# Generate, validate, and summarise Stacks Core configuration documentation.
#
# Required env vars (set by the calling workflow step):
#   OUTPUT_FILE   - Path for the generated markdown file (e.g. ./node-parameters.md)
#   MIN_DOC_SIZE  - Minimum acceptable file size in bytes; generation is considered
#                   failed if the output is smaller than this value
#
# Optional env vars:
#   PROJECT_ROOT          - Workspace root; defaults to $GITHUB_WORKSPACE
#   RUST_NIGHTLY_VERSION  - Nightly toolchain used (informational — written to job summary)
#   ARTIFACT_NAME         - Artifact name (informational — written to job summary)
#   RETENTION_DAYS        - Retention period in days (informational — written to job summary)
set -euo pipefail

# Load logging functions
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

# --- Configuration -----------------------------------------------------------
: "${OUTPUT_FILE:?OUTPUT_FILE is required}"
: "${MIN_DOC_SIZE:?MIN_DOC_SIZE is required}"
PROJECT_ROOT="${PROJECT_ROOT:-${GITHUB_WORKSPACE}}"
rust_nightly_version="${RUST_NIGHTLY_VERSION:-}"
artifact_name="${ARTIFACT_NAME:-}"
retention_days="${RETENTION_DAYS:-}"

# ── Check for required binaries ----------------------------------------------
missing=0
for cmd in numfmt wc; do
    if ! command -v "${cmd}" > /dev/null 2>&1; then
        error "Missing required command: $(hl "${cmd}")"
        missing=1
    fi
done
[[ "${missing}" -eq 1 ]] && exit 1


# ── Generate configuration documentation -------------------------------------
info "Generating configuration documentation → $(hl "${OUTPUT_FILE}")..."
bash contrib/tools/config-docs-generator/generate-config-docs.sh || {
    error "config-docs-generator script failed"
    exit 1
}

if [[ ! -f "${OUTPUT_FILE}" ]]; then
    error "Output file $(hl "${OUTPUT_FILE}") was not created by the generator"
    exit 1
fi
info "Documentation generated at $(hl "${OUTPUT_FILE}")"

# ── Validate generated documentation -----------------------------------------
info "Validating $(hl "${OUTPUT_FILE}")..."

file_size="$(wc -c < "${OUTPUT_FILE}")"
word_count="$(wc -w < "${OUTPUT_FILE}")"
line_count="$(wc -l < "${OUTPUT_FILE}")"

if [[ "${file_size}" -lt "${MIN_DOC_SIZE}" ]]; then
    error "Documentation is too small: $(hl "${file_size} bytes") (minimum $(hl "${MIN_DOC_SIZE} bytes")) — this likely indicates a generation failure"
    exit 1
fi

info "Validation results for $(hl "${OUTPUT_FILE}"):"
info "  File size : $(hl "${file_size} bytes")"
info "  Word count: $(hl "${word_count} words")"
info "  Line count: $(hl "${line_count} lines")"
info "Documentation passed validation"

# ── Write job summary --------------------------------------------------------
formatted_size="$(numfmt --to=iec-i --suffix=B "${file_size}")"
formatted_words="$(printf "%'d" "${word_count}")"

{
    echo "## Configuration Documentation Generated"
    echo ""
    echo "Stacks Core configuration documentation has been generated and uploaded as an artifact."
    echo ""
    echo -n "**File Size**: ${formatted_size}"
    echo -n " | **Words**: ${formatted_words}"
    [[ -n "${rust_nightly_version}" ]] && echo -n " | **Toolchain**: \`${rust_nightly_version}\`"
    echo ""
    echo ""
    [[ -n "${artifact_name}" && -n "${RETENTION_DAYS}" ]] && \
        echo "**Artifact**: \`${artifact_name}\` (retained for ${retention_days} days)"
} >> "${GITHUB_STEP_SUMMARY}"
