#!/bin/bash

### This is intended to run within the rust-stretch docker image (or a debian-like system with required dependencies).

cd "$(dirname "$(dirname "$0")")"

apt-get update
apt-get update && apt-get install -y --no-install-recommends \
  gcc-aarch64-linux-gnu \
  libc6-dev-arm64-cross

rustup target add aarch64-unknown-linux-gnu

CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo build --target aarch64-unknown-linux-gnu --release --features "aarch64" --no-default-features