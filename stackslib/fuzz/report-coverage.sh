#!/usr/bin/env bash
set -euo pipefail

# Require a target name argument. Optional "text" shows a console summary.
[ $# -ge 1 ] || { printf 'Usage: %s <TARGET> [text]\n' "$0"; exit 64; }

target=$1
show_text=0
[ "${2:-}" = "text" ] && show_text=1

# Resolve paths. Script lives in the fuzz dir.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fuzz_dir=$script_dir
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null \
  || cd "$script_dir/.." && pwd)

# Toolchain and LLVM tools.
# Rust host triple identifies platform (e.g. x86_64-unknown-linux-gnu).
host=$(rustc -vV | sed -n 's/^host: //p')
toolchain=${TOOLCHAIN:-nightly-"$host"}

# Check toolchain exists before using it.
if ! rustup run "$toolchain" rustc -V >/dev/null 2>&1; then
  rustup toolchain install "$toolchain"
fi

# Check llvm-tools component exists (handle old/new names).
if ! rustup component list --toolchain "$toolchain" \
  | grep -Eq '^llvm-tools( |-preview ).*\(installed\)'; then
  rustup component add --toolchain "$toolchain" llvm-tools \
    || rustup component add --toolchain "$toolchain" llvm-tools-preview
fi

# Resolve tool paths via rustc sysroot. Never guess top-level bin/.
sysroot=$(rustup run "$toolchain" rustc --print sysroot)
llvm_bin=$sysroot/lib/rustlib/$host/bin
llvm_cov=$llvm_bin/llvm-cov
llvm_profdata=$llvm_bin/llvm-profdata

[ -x "$llvm_cov" ] || { printf 'error: llvm-cov missing.\n' 1>&2; exit 1; }
[ -x "$llvm_profdata" ] || {
  printf 'error: llvm-profdata missing.\n' 1>&2; exit 1; }

# Path to collected profile data.
profdata=$fuzz_dir/coverage/$target/coverage.profdata

# Helper: Locate coverage-built binary.
find_cov_bin() {
  find "$fuzz_dir/target" -type f -perm -111 -name "$target" \
    -path "*/coverage/*/release/*" -print -quit 2>/dev/null
}

bin=$(find_cov_bin || true)

# Generate coverage data if missing.
if [ ! -f "$profdata" ] || [ -z "${bin:-}" ]; then
  if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    cargo +nightly install cargo-fuzz
  fi
  printf 'Generating coverage data with cargo-fuzz...\n'
  cargo +nightly fuzz coverage "$target"
  bin=$(find_cov_bin || true)
fi

# Abort if binary still not found.
if [ -z "${bin:-}" ] || [ ! -f "$bin" ]; then
  printf 'Error: Coverage binary not found.\n' 1>&2
  printf 'Hint: find ./target -type f -name %s -path */coverage/*/release/*\n' \
    "$target" 1>&2
  exit 1
fi

printf 'Using coverage binary: %s\n' "$bin"

# Ignore paths from Rust internals and Cargo registry.
ignore_rgx='^(/rustc/|.*/\.cargo/registry/)'

# Use rustfilt if available to demangle Rust symbols.
demangler=()
if command -v rustfilt >/dev/null 2>&1; then
  demangler=(-Xdemangler=rustfilt)
fi

# Optional text report if user asks.
if [ "$show_text" -eq 1 ]; then
  printf '\n==== LLVM-COV Report (summary) ====\n'
  "$llvm_cov" report "$bin" -instr-profile="$profdata" \
    -ignore-filename-regex="$ignore_rgx" "${demangler[@]:-}"
fi

# HTML report.
html_out=$fuzz_dir/coverage/$target/html
mkdir -p "$html_out"
printf '\nGenerating fuzz target coverage: %s\n' "$html_out"
"$llvm_cov" show "$bin" -instr-profile="$profdata" \
  -format=html -output-dir="$html_out" -show-line-counts-or-regions \
  -ignore-filename-regex="$ignore_rgx" "${demangler[@]:-}"

# Final output location.
printf '\n%s/index.html\n\n' "$html_out"
