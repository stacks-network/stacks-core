#!/usr/bin/env bash
# Refresh every Cargo.lock affected by workspace.package.version.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

ROOT_MANIFEST="${REPO_ROOT}/Cargo.toml"
FUZZ_MANIFESTS=(
    "${REPO_ROOT}/clarity/fuzz/Cargo.toml"
    "${REPO_ROOT}/stackslib/fuzz/Cargo.toml"
)

echo "Updating lockfile for Cargo.toml"
cargo update --manifest-path "${ROOT_MANIFEST}" --workspace

for manifest in "${FUZZ_MANIFESTS[@]}"; do
    relative_manifest="${manifest#"${REPO_ROOT}/"}"
    echo "Updating lockfile for ${relative_manifest}"
    cargo update \
        --manifest-path "${manifest}" \
        --package stacks-common
done

echo "Release lockfiles are up to date."
