#!/bin/bash

set -e

script_path="$(dirname "$0")"
src_dir="$(dirname "$script_path")"
cd "$src_dir"

build_linux_x64 () {
  dist_archive="dist/stacks-blockchain-linux-x64.tar.bz2"
  rm -rf $dist_archive dist/linux-x64
  DOCKER_BUILDKIT=1 docker build -o dist/linux-x64 -f ./build-scripts/Dockerfile.linux-x64 .
  tar cfvj $dist_archive -C dist/linux-x64 blockstack-core blockstack-cli clarity-cli stacks-node
  rm -rf dist/linux-x64
}

build_linux_musl_x64 () {
  dist_archive="dist/stacks-blockchain-linux-musl-x64.tar.bz2"
  rm -rf $dist_archive dist/linux-musl-x64
  DOCKER_BUILDKIT=1 docker build -o dist/linux-musl-x64 -f ./build-scripts/Dockerfile.linux-musl-x64 .
  tar cfvj $dist_archive -C dist/linux-musl-x64 blockstack-core blockstack-cli clarity-cli stacks-node
  rm -rf dist/linux-musl-x64
}

build_linux_armv7 () {
  dist_archive="dist/stacks-blockchain-linux-armv7.tar.bz2"
  rm -rf $dist_archive dist/linux-armv7
  DOCKER_BUILDKIT=1 docker build -o dist/linux-armv7 -f ./build-scripts/Dockerfile.linux-armv7 .
  tar cfvj $dist_archive -C dist/linux-armv7 blockstack-core blockstack-cli clarity-cli stacks-node
  rm -rf dist/linux-armv7
}

build_linux_arm64 () {
  dist_archive="dist/stacks-blockchain-linux-arm64.tar.bz2"
  rm -rf $dist_archive dist/linux-arm64
  DOCKER_BUILDKIT=1 docker build -o dist/linux-arm64 -f ./build-scripts/Dockerfile.linux-arm64 .
  tar cfvj $dist_archive -C dist/linux-arm64 blockstack-core blockstack-cli clarity-cli stacks-node
  rm -rf dist/linux-arm64
}

build_macos_x64 () {
  dist_archive="dist/stacks-blockchain-macos-x64.tar.bz2"
  rm -rf $dist_archive dist/macos-x64
  DOCKER_BUILDKIT=1 docker build -o dist/macos-x64 -f ./build-scripts/Dockerfile.macos-x64 .
  tar cfvj $dist_archive -C dist/macos-x64 blockstack-core blockstack-cli clarity-cli stacks-node
  rm -rf dist/macos-x64
}

build_windows_x64 () {
  dist_archive="dist/stacks-blockchain-windows-x64.tar.bz2"
  rm -rf $dist_archive dist/windows-x64
  DOCKER_BUILDKIT=1 docker build -o dist/windows-x64 -f ./build-scripts/Dockerfile.windows-x64 .
  tar cfvj $dist_archive -C dist/windows-x64 blockstack-core.exe blockstack-cli.exe clarity-cli.exe stacks-node.exe
  rm -rf dist/windows-x64
}

case $DIST_TARGET_FILTER in
  (*[![:blank:]]*)
    case $DIST_TARGET_FILTER in
      linux_x64) build_linux_x64 ;;
      linux_musl_x64) build_linux_musl_x64 ;;
      linux_armv7) build_linux_armv7 ;;
      linux_arm64) build_linux_arm64 ;;
      windows_x64) build_windows_x64 ;;
      macos_x64) build_macos_x64 ;;
      *)
        echo "Invalid dist target filter '$DIST_TARGET_FILTER'"
        exit 1
        ;;
    esac
    ;;
  (*)
    echo "Building distrubtions for all targets."
    build_linux_x64
    build_linux_musl_x64
    build_linux_armv7
    build_linux_arm64
    build_windows_x64
    build_macos_x64
    ;;
esac