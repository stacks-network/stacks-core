#!/bin/bash

### This is intended to run within the rust-stretch docker image (or a debian-like system with required dependencies).

cd "$(dirname "$(dirname "$0")")"

apt-get update
apt-get install -qq gcc-arm-linux-gnueabihf

rustup target add armv7-unknown-linux-gnueabihf

CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc \
CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
cargo build --target armv7-unknown-linux-gnueabihf --release --features "aarch64" --no-default-features