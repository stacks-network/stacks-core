#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

DOCKER_BUILDKIT=1 BUILDKIT_PROGRESS=plain docker build .