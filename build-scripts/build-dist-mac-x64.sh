#!/bin/bash

### This is intended to run within the rust-stretch docker image (or a debian-like system with required dependencies).

### This script uses osxcross [https://github.com/tpoechtrager/osxcross] to cross-compile from linux to MacOS.

cd "$(dirname "$(dirname "$0")")"

apt-get update
apt-get install -y clang

git clone https://github.com/tpoechtrager/osxcross.git --depth=1

### Download a pre-bundled osx-sdk. The official method requires downloading and extracting the 
### sdk from a 5.2GB Xcode_7.x.dmg file, which requires an Apple ID to download. 
wget -nc https://github.com/phracker/MacOSX-SDKs/releases/download/10.13/MacOSX10.11.sdk.tar.xz --directory-prefix=osxcross/tarballs/

UNATTENDED=yes OSX_VERSION_MIN=10.7 ./osxcross/build.sh

rustup target add x86_64-apple-darwin

PATH="$(pwd)/osxcross/target/bin:$PATH" \
CC=o64-clang \
CXX=o64-clang++ \
LIBZ_SYS_STATIC=1 \
CC_x86_64_apple_darwin=x86_64-apple-darwin15-clang \
CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER=x86_64-apple-darwin15-clang \
CARGO_TARGET_X86_64_APPLE_DARWIN_AR=x86_64-apple-darwin15-ar \
cargo build --target x86_64-apple-darwin --release
