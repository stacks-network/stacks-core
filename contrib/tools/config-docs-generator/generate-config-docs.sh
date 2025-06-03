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
BUILD_ROOT="${BUILD_ROOT:-$PROJECT_ROOT}"
OUTPUT_DIR="$PROJECT_ROOT/docs/generated"
TEMP_DIR="$PROJECT_ROOT/target/doc-generation"
CONFIG_SOURCE_FILE="$PROJECT_ROOT/stackslib/src/config/mod.rs"

# Paths to binaries - allow override via environment
EXTRACT_DOCS_BIN="${EXTRACT_DOCS_BIN:-$BUILD_ROOT/target/release/extract-docs}"
GENERATE_MARKDOWN_BIN="${GENERATE_MARKDOWN_BIN:-$BUILD_ROOT/target/release/generate-markdown}"

# Check if binaries are pre-built (skip build step)
SKIP_BUILD="${SKIP_BUILD:-false}"
if [[ -f "$EXTRACT_DOCS_BIN" && -f "$GENERATE_MARKDOWN_BIN" ]]; then
    SKIP_BUILD=true
fi

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
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$TEMP_DIR"

    cd "$PROJECT_ROOT"

    # Verify source file exists
    if [[ ! -f "$CONFIG_SOURCE_FILE" ]]; then
        log_error "Config source file not found: $CONFIG_SOURCE_FILE"
        exit 1
    fi

    # Step 1: Build the documentation generation tools (skip if pre-built)
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "Using pre-built documentation generation tools..."
    else
        log_info "Building documentation generation tools..."
        cargo build --package config-docs-generator --release
    fi

    # Step 2: Extract documentation from source code using rustdoc
    log_info "Extracting configuration documentation using rustdoc..."
    EXTRACTED_JSON="$TEMP_DIR/extracted-config-docs.json"
    # List of specific Rust struct names to be documented
    # NOTE: This variable must be manually updated if this list changes
    # (e.g., new config structs are added or removed from the project)
    TARGET_STRUCTS="BurnchainConfig,NodeConfig,MinerConfig,ConnectionOptionsFile,FeeEstimationConfigFile,EventObserverConfigFile,InitialBalanceFile"
    "$EXTRACT_DOCS_BIN" \
        --package stackslib \
        --structs "$TARGET_STRUCTS" \
        --output "$EXTRACTED_JSON"

    # Step 3: Generate Markdown
    log_info "Generating Markdown documentation..."
    MARKDOWN_OUTPUT="$OUTPUT_DIR/configuration-reference.md"
    "$GENERATE_MARKDOWN_BIN" \
        --input "$EXTRACTED_JSON" \
        --output "$MARKDOWN_OUTPUT"

    log_info "Documentation generation complete!"
    log_info "Generated files:"
    log_info "  - Configuration reference: $MARKDOWN_OUTPUT"
    log_info "  - Intermediate JSON: $EXTRACTED_JSON"

    # Verify output
    if [[ -f "$MARKDOWN_OUTPUT" ]]; then
        WORD_COUNT=$(wc -w < "$MARKDOWN_OUTPUT")
        log_info "Generated Markdown contains $WORD_COUNT words"
    else
        log_error "Expected output file not found: $MARKDOWN_OUTPUT"
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
    docs/generated/configuration-reference.md

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
done

main "$@"
