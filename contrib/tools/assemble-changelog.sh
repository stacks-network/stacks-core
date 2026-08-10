#!/usr/bin/env bash
#
# Assemble changelog fragments into CHANGELOG.md for both stacks-node
# and stacks-signer.
#
# Usage:
#   ./contrib/tools/assemble-changelog.sh <version>
#
# The node and signer are released together and share a single version, so both
# changelogs receive the same `## [<version>]` heading. `.github/scripts/draft_release.sh`
# looks up that exact heading in each CHANGELOG.md when it drafts the release body,
# so the two must stay in sync.
#
# The new version section is inserted before the first existing ## version
# header in each CHANGELOG.md. Fragment files are deleted after assembly.
# If a changelog directory has no fragments, it is skipped.
#
# Fragments are grouped by their file extension into sections, in this order:
#   .breaking -> "### ⚠️ Breaking Changes"  (first, so it can't be missed)
#   .added    -> "### Added"
#   .changed  -> "### Changed"
#   .fixed    -> "### Fixed"
#   .removed  -> "### Removed"
#
# Example:
#   ./contrib/tools/assemble-changelog.sh 4.1.0    # node [4.1.0] + signer [4.1.0]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>" >&2
    exit 1
fi

VERSION="$1"

shopt -s nullglob

# Fragment file extensions, in the order their sections are emitted.
# `breaking` is emitted first so that breaking changes are the first thing a
# reader (or release-notes reader) sees for a version.
CATEGORIES=(breaking added changed fixed removed)

# assemble_changelog <fragment_dir> <changelog_file> <version>
assemble_changelog() {
    local fragment_dir="$1"
    local changelog="$2"
    local version="$3"

    # --- Collect fragments by category ---
    local -a BREAKING=()
    local -a ADDED=()
    local -a CHANGED=()
    local -a FIXED=()
    local -a REMOVED=()
    local found_any=false

    for ext in "${CATEGORIES[@]}"; do
        for f in "$fragment_dir"/*."$ext"; do
            [ -f "$f" ] || continue
            found_any=true
            while IFS= read -r line || [ -n "$line" ]; do
                [ -z "$line" ] && continue
                # Normalise to * bullets (- triggers GPG dash-escaping)
                if [[ "$line" == "- "* ]]; then
                    line="* ${line#- }"
                elif [[ "$line" != "* "* ]]; then
                    line="* $line"
                fi
                case "$ext" in
                    breaking) BREAKING+=("$line") ;;
                    added)    ADDED+=("$line") ;;
                    changed)  CHANGED+=("$line") ;;
                    fixed)    FIXED+=("$line") ;;
                    removed)  REMOVED+=("$line") ;;
                esac
            done < "$f"
        done
    done

    if [ "$found_any" = false ]; then
        echo "  No fragments found in $fragment_dir — skipping."
        return
    fi

    # --- Build the new section ---
    local new_section="## [$version]"

    for category in "${CATEGORIES[@]}"; do
        local -a entries=()
        local heading=""
        case "$category" in
            breaking) entries=("${BREAKING[@]+"${BREAKING[@]}"}"); heading="⚠️ Breaking Changes" ;;
            added)    entries=("${ADDED[@]+"${ADDED[@]}"}");    heading="Added" ;;
            changed)  entries=("${CHANGED[@]+"${CHANGED[@]}"}");  heading="Changed" ;;
            fixed)    entries=("${FIXED[@]+"${FIXED[@]}"}");    heading="Fixed" ;;
            removed)  entries=("${REMOVED[@]+"${REMOVED[@]}"}");  heading="Removed" ;;
        esac

        if [ ${#entries[@]} -gt 0 ] && [ -n "${entries[0]}" ]; then
            new_section+=$'\n\n'"### $heading"$'\n'
            for entry in "${entries[@]}"; do
                new_section+=$'\n'"$entry"
            done
        fi
    done

    # --- Insert into CHANGELOG.md ---
    local section_file
    section_file=$(mktemp)
    printf '%s\n' "$new_section" > "$section_file"

    local tmpfile
    tmpfile=$(mktemp)

    awk -v sfile="$section_file" '
        !inserted && /^## \[/ {
            while ((getline sline < sfile) > 0) print sline
            close(sfile)
            print ""
            inserted = 1
        }
        { print }
    ' "$changelog" > "$tmpfile"

    mv "$tmpfile" "$changelog"
    rm -f "$section_file"

    # --- Delete assembled fragments ---
    for ext in "${CATEGORIES[@]}"; do
        for f in "$fragment_dir"/*."$ext"; do
            [ -f "$f" ] || continue
            rm "$f"
        done
    done

    echo "  Assembled [$version] into $changelog"
}

echo "Assembling stacks-node changelog..."
assemble_changelog "$REPO_ROOT/changelog.d" "$REPO_ROOT/CHANGELOG.md" "$VERSION"

echo "Assembling stacks-signer changelog..."
assemble_changelog "$REPO_ROOT/stacks-signer/changelog.d" "$REPO_ROOT/stacks-signer/CHANGELOG.md" "$VERSION"

echo "Done."
