#!/bin/bash

cd "$(dirname "$(realpath "$0")")"

DOCKER_BUILDKIT=1 BUILDKIT_PROGRESS=plain docker build .