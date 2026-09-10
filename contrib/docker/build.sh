#!/usr/bin/env bash
# Build node and signer images using the repository's Rust and workspace versions.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# Read one double-quoted scalar from a named TOML table; fail on missing/duplicate keys.
read_version() {
    awk -v section="$2" -v key="$3" '
        /^[[:space:]]*\[/ {
            table = $0
            sub(/^[[:space:]]*\[/, "", table)
            sub(/\][[:space:]]*(#.*)?$/, "", table)
            next
        }
        table == section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            value = $0
            sub("^[[:space:]]*" key "[[:space:]]*=[[:space:]]*", "", value)
            if (value !~ /^"[^"]+"[[:space:]]*(#.*)?$/) exit 1
            sub(/^"/, "", value)
            sub(/"[[:space:]]*(#.*)?$/, "", value)
            print value
            found++
        }
        END { if (found != 1) exit 1 }
    ' "$1" || {
        echo "Expected one quoted $3 in [$2] of $1" >&2
        return 1
    }
}

rust_version=$(read_version "$repo_root/rust-toolchain.toml" toolchain channel)
stacks_version=$(read_version "$repo_root/Cargo.toml" workspace.package version)
if [[ ! "$rust_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "rust-toolchain.toml must specify a numeric Rust release" >&2
    exit 1
fi
if [[ ! "$stacks_version" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ || ${#stacks_version} -gt 128 ]]; then
    echo "Workspace version is not a valid Docker tag: $stacks_version" >&2
    exit 1
fi

git_commit=$(git -C "$repo_root" rev-parse --verify HEAD 2>/dev/null || echo unknown)
git_branch=$(git -C "$repo_root" branch --show-current 2>/dev/null || echo unknown)
git_tree_clean='?'
if git_status=$(git -C "$repo_root" status --porcelain --untracked-files=normal 2>/dev/null); then
    git_tree_clean=''
    if [[ -n "$git_status" ]]; then git_tree_clean='+'; fi
fi

for target in node signer; do
    image=stacks-core
    if [[ "$target" == signer ]]; then image=stacks-signer; fi
    echo "Building $image:$stacks_version with Rust $rust_version"
    docker build "$@" \
        --file "$repo_root/contrib/docker/Dockerfile" \
        --build-arg "RUST_VERSION=$rust_version" \
        --build-arg "STACKS_VERSION=$stacks_version" \
        --build-arg "GIT_COMMIT=$git_commit" \
        --build-arg "GIT_BRANCH=${git_branch:-unknown}" \
        --build-arg "GIT_TREE_CLEAN=$git_tree_clean" \
        --target "$target" \
        --tag "$image:$stacks_version" \
        "$repo_root"
done
