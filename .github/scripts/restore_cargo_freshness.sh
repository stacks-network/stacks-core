#!/usr/bin/env bash
# Make source changes newer than restored Cargo artifacts without invalidating
# unchanged workspace crates.
set -euo pipefail

readonly source_index="${1:-target/.ci-workspace-source-index}"

if [[ ! -s "${source_index}" ]]; then
    echo "Cargo cache has no workspace source index; using Cargo's normal freshness checks"
    exit 0
fi

declare -A cached_entries=()
while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"
    cached_entries["${path}"]="${metadata}"
done < "${source_index}"

changed_count=0
while IFS= read -r -d '' entry; do
    metadata="${entry%%$'\t'*}"
    path="${entry#*$'\t'}"

    if [[ "${cached_entries[${path}]-}" != "${metadata}" ]]; then
        touch -c -- "${path}"
        touch -c -- "$(dirname -- "${path}")"
        changed_count=$((changed_count + 1))
    fi
    unset 'cached_entries[$path]'
done < <(git ls-files -s -z)

# A removed file cannot be touched, but its parent directory may be watched by
# a build script. Cargo itself detects missing files recorded in dep-info.
for path in "${!cached_entries[@]}"; do
    touch -c -- "$(dirname -- "${path}")"
    changed_count=$((changed_count + 1))
done

echo "Refreshed Cargo freshness for ${changed_count} changed tracked files"
