#!/bin/bash

### This is intended to run within the rust-stretch docker image (or a debian-like system with required dependencies).

cd "$(dirname "$(dirname "$0")")"

apt-get update
apt-get install -y gcc-mingw-w64-x86-64

rustup target add x86_64-pc-windows-gnu

CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
cargo build --target x86_64-pc-windows-gnu --release
