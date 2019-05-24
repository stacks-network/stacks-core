#!/bin/bash

### This is intended to run within the rust-stretch docker image (or a debian-like system with required dependencies).

script_path="$(dirname "$0")"
src_dir="$(dirname "$script_path")"
cd "$src_dir"


dist_dir="$src_dir/dist"
mkdir -p "$dist_dir"


### Build and package for Linux-x64 (GNU)
build_linux_x64 () {
  "$script_path/build-dist-linux-x64.sh"
  dist_archive_linux="$dist_dir/blockstack-core-linux-x64.tar.bz2"
  rm -f "$dist_archive_linux"
  tar cfvj "$dist_archive_linux" -C "$src_dir/target/x86_64-unknown-linux-gnu/release" blockstack-core clarity
}


### Build and package for Linux-musl-x64
build_linux_musl_x64 () {
  "$script_path/build-dist-linux-musl-x64.sh"
  dist_archive_linux_musl="$dist_dir/blockstack-core-linux-musl-x64.tar.bz2"
  rm -f "$dist_archive_linux_musl"
  tar cfvj "$dist_archive_linux_musl" -C "$src_dir/target/x86_64-unknown-linux-musl/release" blockstack-core clarity
}


### Build and package for MacOS-x64
build_mac_x64 () {
  "$script_path/build-dist-mac-x64.sh"
  dist_archive_mac="$dist_dir/blockstack-core-mac-x64.tar.bz2"
  rm -f "$dist_archive_mac"
  tar cfvj "$dist_archive_mac" -C "$src_dir/target/x86_64-apple-darwin/release" blockstack-core clarity
}


### Build and package for Windows-x64 (GNU/mingw)
build_win_x64 () {
  "$script_path/build-dist-win-x64.sh"
  dist_archive_win="$dist_dir/blockstack-core-win-x64.zip"
  rm -f "$dist_archive_win"
  apt-get update && apt-get install -y zip
  zip -j "$dist_archive_win" \
    "$src_dir/target/x86_64-pc-windows-gnu/release/blockstack-core.exe" \
    "$src_dir/target/x86_64-pc-windows-gnu/release/clarity.exe"
}

case $DIST_TARGET_FILTER in
  (*[![:blank:]]*)
    case $DIST_TARGET_FILTER in
      linux_x64) build_linux_x64 ;;
      linux_musl_x64) build_linux_musl_x64 ;;
      win_x64) build_win_x64 ;;
      mac_x64) build_mac_x64 ;;
      *)
        echo "Invalid dist target filter '$DIST_TARGET_FILTER'"
        exit 1
        ;;
    esac
    ;;
  (*)
    build_linux_x64
    build_linux_musl_x64
    build_win_x64
    build_mac_x64
    ;;
esac