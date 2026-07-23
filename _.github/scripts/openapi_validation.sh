#!/usr/bin/env bash
# Validate and generate OpenAPI documentation using Redocly CLI.
#
# Required env vars (set by the calling workflow step):
#   INPUT_FILE      - OpenAPI spec file to process (e.g. ./open-api.yml)
#   OUTPUT_FILE     - Output HTML documentation file (e.g. ./open-api-docs.html)
#   REDOCLY_VERSION - Version of Redocly CLI to install (e.g. "latest", "1.25.0")
#
# Optional env vars:
#   VALIDATE    - "true" to validate the spec before generating docs; defaults to "true"
#   CONFIG_FILE - Path to a Redocly config file for linting; omit to use no config
set -euo pipefail


# Load logging functions
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## ── Validate required inputs ────────────────────────────────────────────────
: "${INPUT_FILE:?INPUT_FILE is required}"
: "${OUTPUT_FILE:?OUTPUT_FILE is required}"
: "${REDOCLY_VERSION:?REDOCLY_VERSION is required}"
VALIDATE="${VALIDATE:-true}"
CONFIG_FILE="${CONFIG_FILE:-}"

## ── Install Redocly CLI ─────────────────────────────────────────────────────
info "Installing Redocly CLI $(hl "@${REDOCLY_VERSION}")..."
npm install -g "@redocly/cli@${REDOCLY_VERSION}" || {
    error "Failed to install Redocly CLI $(hl "@${REDOCLY_VERSION}")"
    exit 1
}
info "Redocly CLI ready: $(hl "$(redocly --version)")"

## ── Build optional --config argument ────────────────────────────────────────
config_arg=""
if [[ -n "${CONFIG_FILE}" ]]; then
    config_arg="--config ${CONFIG_FILE}"
fi

## ── Validate OpenAPI spec ───────────────────────────────────────────────────
if [[ "${VALIDATE}" == "true" ]]; then
    info "Validating OpenAPI spec $(hl "${INPUT_FILE}")..."
    # shellcheck disable=SC2086
    redocly lint "${INPUT_FILE}" ${config_arg} || {
        error "OpenAPI spec validation failed for $(hl "${INPUT_FILE}")"
        exit 1
    }
    info "OpenAPI spec $(hl "${INPUT_FILE}") passed validation"
else
    warn "Skipping validation (VALIDATE=$(hl "${VALIDATE}"))"
fi

## ── Generate OpenAPI docs ───────────────────────────────────────────────────
info "Generating documentation: $(hl "${INPUT_FILE}") → $(hl "${OUTPUT_FILE}")..."
# shellcheck disable=SC2086
redocly build-docs "${INPUT_FILE}" --output "${OUTPUT_FILE}" ${config_arg} || {
    error "Failed to generate documentation for $(hl "${INPUT_FILE}")"
    exit 1
}
info "Documentation generated at $(hl "${OUTPUT_FILE}")"

## ── Verify output ───────────────────────────────────────────────────────────
info "Verifying output file $(hl "${OUTPUT_FILE}")..."
if [[ ! -f "${OUTPUT_FILE}" ]]; then
    error "Output file $(hl "${OUTPUT_FILE}") was not created by redocly build-docs"
    exit 1
fi
filesize="$(du -h "${OUTPUT_FILE}" | cut -f1)"
info "Output file $(hl "${OUTPUT_FILE}") verified ($(hl "${filesize}"))"
