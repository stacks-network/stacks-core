#!/usr/bin/env bash
set -euo pipefail


## ── ANSI color codes and logging helpers ────────────────────────────────────
COLRED=$'\033[31m'    # Red
COLGREEN=$'\033[32m'  # Green
COLYELLOW=$'\033[33m' # Yellow
COLRESET=$'\033[0m'   # Reset color/formatting

strip_ansi() { printf '%s' "$*" | sed $'s/\033\\[[0-9;]*m//g'; }
info()  { echo "${COLGREEN}INFO:${COLRESET}    $*"; }
warn()  { echo "${COLYELLOW}WARN:${COLRESET}    $*"; }
error() { echo "${COLRED}ERROR:${COLRESET}   $*" >&2; [[ -n "${GITHUB_STEP_SUMMARY:-}" ]] && echo "**ERROR:** $(strip_ansi "$*")" >> "${GITHUB_STEP_SUMMARY}"; }
hl()    { printf '%s' "${COLYELLOW}$*${COLRESET}"; }  # highlight an inline value
