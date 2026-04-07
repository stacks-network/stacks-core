#!/usr/bin/env bash
#
# Assemble changelog fragments into CHANGELOG.md for both stacks-node
# and stacks-signer.
#
# Usage:
#   ./contrib/tools/assemble-changelog.sh <version>           # both node and signer
#   ./contrib/tools/assemble-changelog.sh <version> --signer  # signer only
#
# By default, assembles both changelogs. The signer version is derived by
# appending ".0" to the node version (e.g., 3.3.0.0.7 -> 3.3.0.0.7.0).
# Use --signer for signer-only releases (version is used as-is for signer).
#
# The new version section is inserted before the first existing ## version
# header in each CHANGELOG.md. Fragment files are deleted after assembly.
# If a changelog directory has no fragments, it is skipped.
#
# Examples:
#   ./contrib/tools/assemble-changelog.sh 3.3.0.0.7           # node [3.3.0.0.7] + signer [3.3.0.0.7.0]
#   ./contrib/tools/assemble-changelog.sh 3.3.0.0.7.1 --signer  # signer [3.3.0.0.7.1] only

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <version> [--signer]" >&2
    exit 1
fi

VERSION="$1"
shift

SIGNER_ONLY=false
while [ $# -gt 0 ]; do
    case "$1" in
        --signer) SIGNER_ONLY=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

shopt -s nullglob

# assemble_changelog <fragment_dir> <changelog_file> <version>
assemble_changelog() {
    local fragment_dir="$1"
    local changelog="$2"
    local version="$3"

    # --- Collect fragments by category ---
    local -a ADDED=()
    local -a CHANGED=()
    local -a FIXED=()
    local -a REMOVED=()
    local found_any=false

    for ext in added changed fixed removed; do
        for f in "$fragment_dir"/*."$ext"; do
            [ -f "$f" ] || continue
            found_any=true
            while IFS= read -r line || [ -n "$line" ]; do
                [ -z "$line" ] && continue
                if [[ "$line" != "- "* ]]; then
                    line="- $line"
                fi
                case "$ext" in
                    added)   ADDED+=("$line") ;;
                    changed) CHANGED+=("$line") ;;
                    fixed)   FIXED+=("$line") ;;
                    removed) REMOVED+=("$line") ;;
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

    for category_name in Added Changed Fixed Removed; do
        local -a entries=()
        case "$category_name" in
            Added)   entries=("${ADDED[@]+"${ADDED[@]}"}") ;;
            Changed) entries=("${CHANGED[@]+"${CHANGED[@]}"}") ;;
            Fixed)   entries=("${FIXED[@]+"${FIXED[@]}"}") ;;
            Removed) entries=("${REMOVED[@]+"${REMOVED[@]}"}") ;;
        esac

        if [ ${#entries[@]} -gt 0 ] && [ -n "${entries[0]}" ]; then
            new_section+=$'\n\n'"### $category_name"$'\n'
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
    for ext in added changed fixed removed; do
        for f in "$fragment_dir"/*."$ext"; do
            [ -f "$f" ] || continue
            rm "$f"
        done
    done

    echo "  Assembled [$version] into $changelog"
}

if [ "$SIGNER_ONLY" = true ]; then
    echo "Assembling stacks-signer changelog..."
    assemble_changelog "$REPO_ROOT/stacks-signer/changelog.d" "$REPO_ROOT/stacks-signer/CHANGELOG.md" "$VERSION"
else
    echo "Assembling stacks-node changelog..."
    assemble_changelog "$REPO_ROOT/changelog.d" "$REPO_ROOT/CHANGELOG.md" "$VERSION"

    echo "Assembling stacks-signer changelog..."
    assemble_changelog "$REPO_ROOT/stacks-signer/changelog.d" "$REPO_ROOT/stacks-signer/CHANGELOG.md" "${VERSION}.0"
fi

echo "Done."
