#!/usr/bin/env bash
# Runs cargo fmt --check and reports formatting errors to stderr and $GITHUB_STEP_SUMMARY.
#
# Required env vars (set by the calling workflow step):
#   FMT_ALIAS         - cargo alias to use for fmt (e.g. fmt-stacks); defaults to "fmt-stacks"
#   FMT_MANIFEST_PATH - path to the Cargo.toml manifest; defaults to ./Cargo.toml
#
# Exit behaviour:
#   - Code is formatted correctly             → writes success summary, exits 0
#   - Formatting errors found                 → writes diff summary, exits with cargo's exit code
#   - Invalid alias or missing config file    → writes error to $GITHUB_STEP_SUMMARY, exits 1
set -euo pipefail


# Load logging functions
# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/logging.sh"

## ── Validate required inputs ────────────────────────────────────────────────
# Uppercase: these are env var inputs supplied by the calling workflow step.
FMT_ALIAS="${FMT_ALIAS:-fmt-stacks}"
FMT_MANIFEST_PATH="${FMT_MANIFEST_PATH:-./Cargo.toml}"

## ── Locate Cargo config file ────────────────────────────────────────────────
# Lowercase: script-local variables not exported or shared outside this script.
config_file_locations=(".cargo/config.toml" ".cargo/config")
config_file=""
for file in "${config_file_locations[@]}"; do
    if [[ -f "${file}" ]]; then
        config_file="${file}"
        break
    fi
done

if [[ -z "${config_file}" ]]; then
    error "No Cargo config file found in $(hl ".cargo/config.toml") or $(hl ".cargo/config")"
    exit 1
fi

## ── Extract and split alias command options ─────────────────────────────────
# 'alias' is a bash builtin — use fmt_cmd to avoid shadowing it.
fmt_cmd=$(grep -e "${FMT_ALIAS}.*=" "${config_file}" | tr -d '"' | awk -v key="${FMT_ALIAS}" '$0 ~ ("^" key "[[:space:]]*=") {sub(/^[^=]*=[[:space:]]*/,""); print; exit}')

before_empty_dashes=""
after_empty_dashes=""
reached_empty_dashes=false

IFS=' '
read -ra args <<< "${fmt_cmd}"

if [[ "${args[0]}" != "fmt" && "${FMT_ALIAS}" != "fmt" ]]; then
    error "The provided alias $(hl "${FMT_ALIAS}") is invalid"
    exit 1
fi

for arg in "${args[@]}"; do
    if [[ "${arg}" == "--" ]]; then
        reached_empty_dashes=true
        continue
    fi
    if ${reached_empty_dashes}; then
        after_empty_dashes="${after_empty_dashes} ${arg}"
    else
        before_empty_dashes="${before_empty_dashes} ${arg}"
    fi
done

## ── Run cargo fmt --check ───────────────────────────────────────────────────
cargo_status=0
# shellcheck disable=SC2086
cargo_output=$(cargo ${before_empty_dashes:-fmt} --all --manifest-path="${FMT_MANIFEST_PATH}" -- ${after_empty_dashes} --color=always --check 2>/dev/null) || cargo_status=$?

## ── Write step summary and exit ─────────────────────────────────────────────
if [[ "${cargo_status}" -eq 0 ]]; then
    info "Code is formatted correctly"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        cat >> "${GITHUB_STEP_SUMMARY}" <<'MARKDOWN'
## `rustfmt` Results

The code is formatted correctly
MARKDOWN
    fi
else
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        cat >> "${GITHUB_STEP_SUMMARY}" <<'MARKDOWN'
## `rustfmt` Results

`cargo fmt` reported formatting errors in the following locations.
You can fix them by executing the following command and committing the changes.
```bash
cargo fmt --all
```
MARKDOWN

        # Append a collapsible diff per file to the summary.
        # Strip ANSI/cursor codes using portable $'\033' form (not \x1B which BSD sed rejects),
        # then wrap each location block in a <details> element.
        printf '%s' "${cargo_output}" \
            | sed $'s/\033\\[[0-9;]*[A-Za-z]//g' \
            | sed $'s/\033.[A-G]//g' \
            | tr "\n" "\r" \
            | sed -E 's#Diff in ([^\r]*?) at line ([[:digit:]]+):\r((:?[ +-][^\r]*\r)+)#<details>\n<summary>\1:\2</summary>\n\n```diff\n\3```\n\n</details>\n\n#g' \
            | tr "\r" "\n" >> "${GITHUB_STEP_SUMMARY}"
    fi
fi

# Print the original cargo output to the terminal in case of fmt failures
[[ -n "${cargo_output}" ]] && info "${cargo_output}"

exit "${cargo_status}"
