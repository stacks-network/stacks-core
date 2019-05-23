#!/bin/bash

script_path="$(dirname "$0")"
src_dir="$(dirname "$script_path")"
cd "$src_dir"

rust_image="rust:1.34-stretch"

docker run \
  --volume `pwd`:/build \
  --workdir /build \
  --tty \
  --env "DIST_TARGET_FILTER=$DIST_TARGET_FILTER" \
  $rust_image \
  bash "$script_path/start-builds.sh"
