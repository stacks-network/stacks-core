#!/bin/bash

### This is intended to run within the rust-stretch docker image (or a debian-like system with required dependencies).

cd "$(dirname "$(dirname "$0")")"

rustup target add x86_64-unknown-linux-gnu
cargo build --target x86_64-unknown-linux-gnu --release

