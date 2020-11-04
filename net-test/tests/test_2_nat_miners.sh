#!/bin/bash

# This test creates a network that looks like this:
#
# Miner (NAT'ed) <-----> Non-mining Master (public) <-----> Miner (NAT'ed)
#
# NAT'ing is emulated by having each miner ban all other miners, so they never talk to each other.

source ./config.sh
PROCESS_EXIT_AT_BLOCK_HEIGHT=450

source "$__BIN/start.sh"
source ./testlib.sh

set -uo pipefail

NAME="test-2-nat-miners"

with_master() {
   master_config "master-$NAME" "127.0.0.1" "false"
}

with_miner_1() {
   miner_config "miner-1-$NAME" "21443" "21444"
}

with_miner_2() {
   miner_config "miner-2-$NAME" "22443" "22444"
}

with_master
    set_inbound_walks "false"
    start_node &
    MASTER_PID=$!
    wait_node || exit_error "Master node failed to boot up"

with_miner_1
    ban_peer "127.0.0.1" "22444"
    set_nat "true"
    start_node &
    MINER_1_PID=$!

with_miner_2
    ban_peer "127.0.0.1" "21444"
    set_nat "true"
    start_node &
    MINER_2_PID=$!

with_miner_1
    wait_node || exit_error "Miner node 1 failed to boot up"

with_miner_2
    wait_node || exit_error "Miner node 2 failed to boot up"

with_master
    wait_until_burn_block 300 || exit_error "Master node failed to reach block 300"

with_miner_1
    wait_until_burn_block 300 || exit_error "Miner 1 failed to reach block 300"

with_miner_2
    wait_until_burn_block 300 || exit_error "Miner 2 failed to reach block 300"

wait_pids $MASTER_PID $MINER_1_PID $MINER_2_PID

with_master
    check_chain_quality 90 90 100
    if [ $? -ne 0 ]; then
       exit_error "Chain quality check failed"
    fi
    exit 0

