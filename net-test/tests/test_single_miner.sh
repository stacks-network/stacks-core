#!/bin/bash

# This test creates a simple network with one miner.

source ./config.sh
PROCESS_EXIT_AT_BLOCK_HEIGHT=450

source "$__BIN/start.sh"
source ./testlib.sh

set -uo pipefail

NAME="test-single-miner"

with_master() {
   master_config "master-$NAME" "127.0.0.1" "true"
}

with_master
    start_node &
    MASTER_PID=$!
    wait_node || exit_error "Master node failed to boot up"

    wait_until_burn_block 300 || exit_error "Master node failed to reach block 300"

wait_pids $MASTER_PID

with_master
    check_chain_quality 90 90 100
    if [ $? -ne 0 ]; then
       exit_error "Chain quality check failed"
    fi
    exit 0

