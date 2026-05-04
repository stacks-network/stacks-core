#!/usr/bin/env bash
set -euo pipefail


## ── ANSI color codes and logging helpers ────────────────────────────────────
COLRED=$'\033[31m'    # Red
COLGREEN=$'\033[32m'  # Green
COLYELLOW=$'\033[33m' # Yellow
COLRESET=$'\033[0m'   # Reset color/formatting

# strip ansi color codes for GITHUB_STEP_SUMMARY
strip_ansi() {
    printf '%s' "$*" | sed $'s/\033\\[[0-9;]*m//g';
}
# highlight an inline value
hl() {
    printf '%s' "${COLYELLOW}$*${COLRESET}";
}
# Info logging to stderr
info() {
    echo "${COLGREEN}INFO:${COLRESET}    $*" >&2
}
# Warn log to stderr
warn() {
    echo "${COLYELLOW}WARN:${COLRESET}    $*" >&2
}
# Error log to stderr (do not exit here, let the calling script determine how to handle an error)
error() {
    echo "${COLRED}ERROR:${COLRESET}   $*" >&2
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "$(strip_ansi "$*")" >> "${GITHUB_STEP_SUMMARY}"
    fi
}
