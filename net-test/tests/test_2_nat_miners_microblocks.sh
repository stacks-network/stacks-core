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

NAME="test-2-nat-miners-microblocks"

# this private key is pre-allocated some STX in the config file
STX_PRIVKEY="9aef533e754663a453984b69d36f109be817e9940519cc84979419e2be00864801"
STX_DEST_ADDR="ST2V6S2KBYH7Q2BHPTXTC73MPYGPP0G4B31EXCBMG"

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

with_miner_1
    RC=0
    for i in $(seq 1 50); do
       DONE=0
       while true; do
          wait_for_confirmations 1 "http://localhost:21443"
          RC=$?
          if [ $RC -ne 0 ]; then 
             logln "Failed to wait for next block tip: rc $RC"
             DONE=1
             break
          fi

          TX="$(easy_token_transfer "http://localhost:21443" "$STX_PRIVKEY" "$STX_DEST_ADDR" 1  "--microblock-only")"
          RC=$?
          if [ $RC -ne 0 ]; then
             logln "Failed to make a token transfer to $STX_DEST_ADDR at attempt $i: rc $RC"

             # keep trying
             continue
          fi

          TXID="$(echo "$TX" | send_tx "http://localhost:21443")"
          RC=$?
          if [ $RC -ne 0 ]; then
             logln "Failed to send a token transfer to $STX_DEST_ADDR at attempt $i: rc $RC"
             logln "Failed transaction: $TX"

             # keep trying
             continue
          else
             logln "$TXID ($i)"
          fi

          # sent one!
          break
       done
       if [[ $DONE = 1 ]]; then
          break
       fi
    done

wait_pids $MASTER_PID $MINER_1_PID $MINER_2_PID

with_master
    #  at least 100 blocks mined; at least 90% are on the same fork
    check_chain_quality 90 90 100
    if [ $? -ne 0 ]; then
       exit_error "Chain quality check failed"
    fi

    # all microblock-only transactions are mined
    NONCE="$(get_account_nonce "http://localhost:21443" "ST31HHVBKYCYQQJ5AQ25ZHA6W2A548ZADDQ6S16GP")"
    if [ $? -ne 0 ]; then
       exit_error "Failed to query account nonce for spending key"
    fi

    if (( $NONCE < 50 )); then
       exit_error "Not all microblock transactions mined in canonical chain tip: nonce is only $NONCE"
    fi

    exit 0

