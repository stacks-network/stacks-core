#!/usr/bin/env bash
# Run a reproducible, multi-worker cargo-fuzz campaign for one repository target.
#
# CI should set SECONDS_TOTAL explicitly, cache <target-dir>/fuzz/campaigns/<target>/corpus for
# continuity, and upload the corresponding runs directory when logs or failure artifacts must be
# retained. 
#
# Generated corpora remain disposable: periodically minimize them with `cargo fuzz cmin` and promote
# only selected regression or coverage-distinct inputs into the target's tracked seed_corpus
# directory.
set -euo pipefail

usage() {
    printf 'Usage: %s [--target-dir DIR] <TARGET>\n' "$0"
    printf '\n'
    printf 'Options:\n'
    printf '  --target-dir DIR  Generated-output root (default: repository target/)\n'
    printf '\n'
    printf 'Environment variables:\n'
    printf '  WORKERS         Parallel workers (default: 75%% of logical CPUs)\n'
    printf '  SECONDS_TOTAL   Run time per worker; set explicitly in CI (default: 3600)\n'
    printf '  MIN_EXECUTIONS  Optional aggregate execution floor\n'
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
readonly REPO_ROOT
readonly CALLER_DIR=$PWD

TARGET=""
TARGET_DIR_ARGUMENT=""
while [ "$#" -gt 0 ]; do
    case $1 in
        --target-dir)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf 'error: --target-dir requires a directory\n' >&2
                exit 64
            fi
            TARGET_DIR_ARGUMENT=$2
            shift 2
            ;;
        --target-dir=*)
            TARGET_DIR_ARGUMENT=${1#*=}
            if [ -z "$TARGET_DIR_ARGUMENT" ]; then
                printf 'error: --target-dir requires a directory\n' >&2
                exit 64
            fi
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*)
            printf 'error: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 64
            ;;
        *)
            if [ -n "$TARGET" ]; then
                printf 'error: expected one fuzz target, got: %s and %s\n' "$TARGET" "$1" >&2
                exit 64
            fi
            TARGET=$1
            shift
            ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage >&2
    exit 64
fi

readonly TARGET
if [[ ! "$TARGET" =~ ^[A-Za-z0-9_-]+$ ]]; then
    printf 'error: invalid fuzz target name: %s\n' "$TARGET" >&2
    exit 64
fi

OUTPUT_TARGET_DIR=${TARGET_DIR_ARGUMENT:-$REPO_ROOT/target}
if [[ "$OUTPUT_TARGET_DIR" != /* ]]; then
    OUTPUT_TARGET_DIR="$CALLER_DIR/$OUTPUT_TARGET_DIR"
fi
readonly OUTPUT_TARGET_DIR

# Target names are the public interface. Locate the owning fuzz crate so callers do not need to
# know its repository path, while rejecting ambiguous names rather than choosing silently.
TARGET_FILES=()
while IFS= read -r -d '' target_file; do
    TARGET_FILES+=("$target_file")
done < <(
    find "$REPO_ROOT" \
        \( -name .git -o -name target -o -name corpus -o -name artifacts \) -prune \
        -o -type f -path "*/fuzz/fuzz_targets/$TARGET.rs" -print0
)

case ${#TARGET_FILES[@]} in
    0)
        printf 'error: fuzz target not found: %s\n' "$TARGET" >&2
        exit 66
        ;;
    1) ;;
    *)
        printf 'error: fuzz target name is ambiguous: %s\n' "$TARGET" >&2
        printf 'matches:\n' >&2
        printf '  %s\n' "${TARGET_FILES[@]}" >&2
        exit 65
        ;;
esac

readonly TARGET_FILE=${TARGET_FILES[0]}
FUZZ_DIR=$(cd -- "$(dirname -- "$TARGET_FILE")/.." && pwd)
readonly FUZZ_DIR

if [ ! -f "$FUZZ_DIR/Cargo.toml" ]; then
    printf 'error: fuzz crate has no Cargo.toml: %s\n' "$FUZZ_DIR" >&2
    exit 66
fi

detect_logical_cpus() {
    local count=""
    if command -v nproc >/dev/null 2>&1; then
        count=$(nproc 2>/dev/null || true)
    fi
    if [[ ! "$count" =~ ^[1-9][0-9]*$ ]] && command -v getconf >/dev/null 2>&1; then
        count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    fi
    if [[ ! "$count" =~ ^[1-9][0-9]*$ ]] && command -v sysctl >/dev/null 2>&1; then
        count=$(sysctl -n hw.logicalcpu 2>/dev/null || true)
    fi
    if [[ ! "$count" =~ ^[1-9][0-9]*$ ]]; then
        count=1
    fi
    printf '%s\n' "$count"
}

require_positive_integer() {
    local name=$1
    local value=$2
    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf 'error: %s must be a positive integer, got: %s\n' "$name" "$value" >&2
        exit 64
    fi
}

# Leave capacity for normal host or CI activity unless the caller chooses an explicit worker count.
LOGICAL_CPUS=$(detect_logical_cpus)
readonly LOGICAL_CPUS
DEFAULT_WORKERS=$((LOGICAL_CPUS * 3 / 4))
if [ "$DEFAULT_WORKERS" -lt 1 ]; then
    DEFAULT_WORKERS=1
fi
readonly DEFAULT_WORKERS

readonly WORKER_COUNT=${WORKERS:-$DEFAULT_WORKERS}
readonly CAMPAIGN_SECONDS=${SECONDS_TOTAL:-3600}
# Execution throughput varies by target and machine, so only target-specific qualification runs
# should opt into an aggregate floor.
readonly EXECUTION_FLOOR=${MIN_EXECUTIONS:-}

require_positive_integer WORKERS "$WORKER_COUNT"
require_positive_integer SECONDS_TOTAL "$CAMPAIGN_SECONDS"
if [ -n "$EXECUTION_FLOOR" ]; then
    require_positive_integer MIN_EXECUTIONS "$EXECUTION_FLOOR"
fi

cd "$FUZZ_DIR"
export RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER=""

# Fail before creating campaign output when the local fuzz toolchain is unavailable.
if ! command -v cargo >/dev/null 2>&1; then
    printf 'error: cargo is required to run fuzz campaigns\n' >&2
    exit 69
fi
if ! cargo +nightly --version >/dev/null 2>&1; then
    printf 'error: the Rust nightly toolchain is required to run fuzz campaigns\n' >&2
    printf 'hint: run: rustup toolchain install nightly\n' >&2
    exit 69
fi
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    printf 'error: cargo-fuzz is required to run fuzz campaigns\n' >&2
    printf 'hint: run: cargo +nightly install cargo-fuzz\n' >&2
    exit 69
fi

AVAILABLE_TARGETS=$(cargo +nightly fuzz list)
if ! grep -Fxq "$TARGET" <<<"$AVAILABLE_TARGETS"; then
    printf 'error: %s is not registered as a cargo-fuzz target in %s\n' \
        "$TARGET" "$FUZZ_DIR/Cargo.toml" >&2
    exit 66
fi

readonly SEEDS="$FUZZ_DIR/seed_corpus/$TARGET"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly RUN_ID
# Keep all generated fuzz data beneath one caller-selectable cleanup boundary.
readonly FUZZ_OUTPUT_ROOT="$OUTPUT_TARGET_DIR/fuzz"
readonly FUZZ_BUILD_DIR="$FUZZ_OUTPUT_ROOT/build"
readonly TARGET_OUTPUT_DIR="$FUZZ_OUTPUT_ROOT/campaigns/$TARGET"
readonly CORPUS="$TARGET_OUTPUT_DIR/corpus"
readonly RUN_DIR="$TARGET_OUTPUT_DIR/runs/$RUN_ID"
readonly CRASH_DIR="$RUN_DIR/crashes"
readonly LOG_DIR="$RUN_DIR/logs"

mkdir -p "$CORPUS" "$CRASH_DIR" "$LOG_DIR"
for stale_log in fuzz-*.log; do
    [ -f "$stale_log" ] || continue
    printf 'error: refusing to overwrite unarchived worker log: %s/%s\n' \
        "$FUZZ_DIR" "$stale_log" >&2
    exit 1
done

# Generated corpora are disposable locally and cacheable in CI. Targets may promote selected,
# minimized witnesses into a tracked seed_corpus directory for permanent, reviewable coverage.
if [ -d "$SEEDS" ]; then
    for seed in "$SEEDS"/*; do
        [ -f "$seed" ] || continue
        cp "$seed" "$CORPUS/seed-$(basename "$seed")"
    done
fi

printf 'campaign start: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'target: %s\n' "$TARGET"
printf 'fuzz crate: %s\n' "$FUZZ_DIR"
printf 'workers: %s (detected logical CPUs: %s)\n' "$WORKER_COUNT" "$LOGICAL_CPUS"
printf 'seconds per worker: %s\n' "$CAMPAIGN_SECONDS"
printf 'run directory: %s\n' "$RUN_DIR"

if cargo +nightly fuzz run --target-dir "$FUZZ_BUILD_DIR" "$TARGET" "$CORPUS" -- \
    -max_total_time="$CAMPAIGN_SECONDS" \
    -workers="$WORKER_COUNT" \
    -jobs="$WORKER_COUNT" \
    -timeout=25 \
    -rss_limit_mb=4096 \
    -artifact_prefix="$CRASH_DIR/" \
    -print_final_stats=1
then
    STATUS=0
else
    STATUS=$?
fi

printf 'campaign end: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'cargo-fuzz exit status: %s\n' "$STATUS"

# cargo-fuzz leaves per-worker logs in the fuzz crate; archive them with this campaign's artifacts.
for log in fuzz-*.log; do
    [ -f "$log" ] || continue
    mv "$log" "$LOG_DIR"/
done

printf '=== per-worker totals ===\n'
TOTAL_EXECUTIONS=0
WORKER_LOGS=0
MIN_WORKER_SECONDS=""
# Read libFuzzer's final summaries to verify that every requested worker completed its campaign.
for log in "$LOG_DIR"/fuzz-*.log; do
    [ -f "$log" ] || continue
    WORKER_LOGS=$((WORKER_LOGS + 1))
    summary=$(grep -E '^Done [0-9]+ runs in [0-9]+ second' "$log" | tail -1 || true)
    if [ -n "$summary" ]; then
        runs=$(awk '{print $2}' <<<"$summary")
        worker_seconds=$(awk '{print $5}' <<<"$summary")
    else
        runs=$(grep -oE '^#[0-9]+' "$log" | tr -d '#' | tail -1 || true)
        runs=${runs:-0}
        worker_seconds=0
    fi
    if [ -z "$MIN_WORKER_SECONDS" ] || [ "$worker_seconds" -lt "$MIN_WORKER_SECONDS" ]; then
        MIN_WORKER_SECONDS=$worker_seconds
    fi
    printf '%s: %s runs in %s seconds\n' "$log" "$runs" "$worker_seconds"
    TOTAL_EXECUTIONS=$((TOTAL_EXECUTIONS + runs))
done
MIN_WORKER_SECONDS=${MIN_WORKER_SECONDS:-0}
printf 'WORKER_LOGS=%s\n' "$WORKER_LOGS"
printf 'MIN_WORKER_SECONDS=%s\n' "$MIN_WORKER_SECONDS"
printf 'TOTAL_EXECUTIONS=%s\n' "$TOTAL_EXECUTIONS"

ARTIFACT_COUNT=0
for artifact in "$CRASH_DIR"/*; do
    [ -f "$artifact" ] || continue
    printf 'failure artifact: %s\n' "$artifact"
    ARTIFACT_COUNT=$((ARTIFACT_COUNT + 1))
done

FAILURE_LOGS=$(grep -lE 'ERROR: libFuzzer|SUMMARY: |panicked at|deadly signal' \
    "$LOG_DIR"/fuzz-*.log 2>/dev/null || true)

FAILED=0
if [ "$STATUS" -ne 0 ]; then
    printf 'error: cargo-fuzz exited with status %s\n' "$STATUS" >&2
    FAILED=1
fi
if [ "$WORKER_LOGS" -ne "$WORKER_COUNT" ]; then
    printf 'error: campaign produced %s worker logs; expected %s\n' \
        "$WORKER_LOGS" "$WORKER_COUNT" >&2
    FAILED=1
fi
if [ "$MIN_WORKER_SECONDS" -lt "$CAMPAIGN_SECONDS" ]; then
    printf 'error: shortest worker ran for %s seconds; required %s\n' \
        "$MIN_WORKER_SECONDS" "$CAMPAIGN_SECONDS" >&2
    FAILED=1
fi
if [ -n "$EXECUTION_FLOOR" ] && [ "$TOTAL_EXECUTIONS" -lt "$EXECUTION_FLOOR" ]; then
    printf 'error: campaign executed %s inputs; required %s\n' \
        "$TOTAL_EXECUTIONS" "$EXECUTION_FLOOR" >&2
    FAILED=1
fi
if [ "$ARTIFACT_COUNT" -ne 0 ]; then
    printf 'error: campaign produced %s failure artifact(s)\n' "$ARTIFACT_COUNT" >&2
    FAILED=1
fi
if [ -n "$FAILURE_LOGS" ]; then
    printf 'error: campaign logs contain failure markers:\n%s\n' "$FAILURE_LOGS" >&2
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi
printf 'fuzz campaign completed successfully: %s\n' "$RUN_DIR"
