#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration - Allow environment variable overrides
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../../../" && pwd)}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
OUTPUT_FILE="${OUTPUT_FILE:-$CARGO_TARGET_DIR/generated-docs/node-parameters.md}"
TEMP_DIR="${TEMP_DIR:-$CARGO_TARGET_DIR/doc-generation}"

# Binary paths - allow override via environment
EXTRACT_DOCS_BIN="${EXTRACT_DOCS_BIN:-$CARGO_TARGET_DIR/release/extract-docs}"
GENERATE_MARKDOWN_BIN="${GENERATE_MARKDOWN_BIN:-$CARGO_TARGET_DIR/release/generate-markdown}"

# Template and mappings paths - allow override via environment
TEMPLATE_PATH="${TEMPLATE_PATH:-$SCRIPT_DIR/templates/reference_template.md}"
SECTION_MAPPINGS_PATH="${SECTION_MAPPINGS_PATH:-$SCRIPT_DIR/section_name_mappings.json}"

# Check if binaries are pre-built (skip build step)
SKIP_BUILD="${SKIP_BUILD:-false}"

export CARGO_TARGET_DIR

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

main() {
    log_info "Starting config documentation generation..."

    # Create necessary directories
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    mkdir -p "$TEMP_DIR"

    # Move to the script's directory to build `config-docs-generator`
    cd "$SCRIPT_DIR"

    # Step 1: Build the documentation generation tools
    if [[ "$SKIP_BUILD" != "true" ]]; then
        log_info "Building documentation generation tools..."
        cargo build --package config-docs-generator --release
    fi

    # Step 2: Extract documentation from source code using rustdoc
    log_info "Extracting configuration documentation using rustdoc..."
    EXTRACTED_JSON="$TEMP_DIR/extracted-config-docs.json"

    # Determine the list of structs to document from section_name_mappings.json
    # If the caller sets $TARGET_STRUCTS explicitly we honour that override.
    if [[ -z "${TARGET_STRUCTS:-}" ]]; then
        TARGET_STRUCTS="$(jq -r 'keys | join(",")' "$SECTION_MAPPINGS_PATH")"
    fi
    log_info "Structs to be documented: $TARGET_STRUCTS"

    # Move to the project's workspace root to run the extract-docs binary
    cd "$PROJECT_ROOT"

    "$EXTRACT_DOCS_BIN" \
        --package stackslib \
        --structs "$TARGET_STRUCTS" \
        --output "$EXTRACTED_JSON"

    # Step 3: Generate Markdown
    log_info "Generating Markdown documentation..."

    # Call the command
    "$GENERATE_MARKDOWN_BIN" --input "$EXTRACTED_JSON" --output "$OUTPUT_FILE" --template "$TEMPLATE_PATH" --section-name-mappings "$SECTION_MAPPINGS_PATH"

    log_info "Documentation generation complete!"
    log_info "Generated files:"
    log_info "  - Configuration reference: $OUTPUT_FILE"
    log_info "  - Intermediate JSON: $EXTRACTED_JSON"

    # Verify output
    if [[ -f "$OUTPUT_FILE" ]]; then
        WORD_COUNT=$(wc -w < "$OUTPUT_FILE")
        log_info "Generated Markdown contains $WORD_COUNT words"
    else
        log_error "Expected output file not found: $OUTPUT_FILE"
        exit 1
    fi
}

# Help function
show_help() {
    cat << EOF
generate-config-docs.sh - Generate configuration documentation for Stacks node

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -h, --help      Show this help message

DESCRIPTION:
    This script generates comprehensive Markdown documentation for all TOML
    configuration options available in the Stacks node. The documentation is
    automatically extracted from Rust source code comments.

    The process involves:
    1. Building the documentation generation tools
    2. Extracting configuration struct documentation from source code
    3. Converting to Markdown format

    Source file: stackslib/src/config/mod.rs

OUTPUT:
    docs/generated/node-parameters.md

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

main "$@"
