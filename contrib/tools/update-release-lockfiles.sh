#!/usr/bin/env bash
# Refresh every Cargo.lock affected by workspace.package.version.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

MANIFESTS=(
    "${REPO_ROOT}/Cargo.toml"
    "${REPO_ROOT}/clarity/fuzz/Cargo.toml"
    "${REPO_ROOT}/stackslib/fuzz/Cargo.toml"
)

# Each fuzz crate is its own workspace. Cargo still reconciles changes to its
# local path dependencies (including clarity, stackslib, and stacks-common),
# while --workspace avoids updating registry packages.
for manifest in "${MANIFESTS[@]}"; do
    relative_manifest="${manifest#"${REPO_ROOT}/"}"
    echo "Updating lockfile for ${relative_manifest}"
    cargo update \
        --manifest-path "${manifest}" \
        --workspace
done

echo "Release lockfiles are up to date."
