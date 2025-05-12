#!/usr/bin/env bash

exit_error() {
   printf "$1" >&2
   exit 1
}

if [ $(echo ${BASH_VERSION} | cut -d '.' -f 1) -lt 4 ]; then
   exit_error "This script requires Bash 4.x or higher"
fi

log() {
   printf "%s" "$1" >&2
}

logln() {
   printf "%s\n" "$1" >&2
}

is_sourced() {
   if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
     return 0
   else
     return 1
   fi
}

start_bitcoind() {
   logln "[$$] Setting up bitcoind..."
   test -f "$BITCOIN_CONF".in || exit_error "No such file or directory: $BITCOIN_CONF"
   mkdir -p "$BITCOIN_DATA_DIR" || exit_error "Failed to create bitcoin data directory $BITCOIN_DATA_DIR"

   log "[$$]  Generating bitcoind config file..."
   sed -r \
     -e "s!@@BITCOIN_DATA_DIR@@!$BITCOIN_DATA_DIR!g" \
     "$BITCOIN_CONF".in \
     > "$BITCOIN_CONF"
   logln "ok"
   
   log "[$$] Starting bitcoind..."
   bitcoind -fallbackfee=0.0002 -conf="$BITCOIN_CONF" >"$BITCOIN_LOGFILE" 2>&1 &
   local BITCOIN_PID=$!
   logln "PID $BITCOIN_PID"

   while true; do 
      bitcoin-cli -regtest -conf="$BITCOIN_CONF" ping >/dev/null 2>&1
      if [ $? -eq 0 ]; then
         break
      fi
      sleep 1
   done

   echo "$BITCOIN_PID"
   return 0
}

start_bitcoind_controller() {
   logln "[$$] Setting up bitcoind controller..."
   test -f "$BITCOIN_CONTROLLER_CONF".in || exit_error "No such file or directory: $BITCOIN_CONTROLLER_CONF.in"

   log "[$$]  Generating bitcoind controller config file..."
   local NOW="$(date +%s)"
   sed -r \
    -e "s/@@BITCOIN_NEON_CONTROLLER_GENESIS_TIMESTAMP@@/$NOW/g" \
    "$BITCOIN_CONTROLLER_CONF".in \
    > "$BITCOIN_CONTROLLER_CONF"
   logln "ok"

   log "[$$] Starting bitcoind controller..."
   puppet-chain "$BITCOIN_CONTROLLER_CONF" >"$BITCOIN_CONTROLLER_LOGFILE" 2>&1 &
   local RC=$?
   local BITCOIN_NEON_CONTROLLER_PID=$!

   if [ $RC -ne 0 ]; then 
      logln "FAILED"
      return 1
   fi

   logln "PID $BITCOIN_NEON_CONTROLLER_PID"

   echo "$BITCOIN_NEON_CONTROLLER_PID"
   return 0
}

start_faucet() {
   logln "[$$] Setting up bitcoin faucet..."
   test -f "$BITCOIN_CONTROLLER_CONF" || exit_error "No such file or directory: $BITCOIN_CONTROLLER_CONF"
   test -f "$BITCOIN_CONF" || exit_error "No such file or directory: $BITCOIN_CONF"

   local PRIVKEY="$(cat "$BITCOIN_CONTROLLER_CONF" | grep "# WIF" | cut -d ' ' -f 3)"

   log "[$$]  Importing faucet private key..."
   bitcoin-cli -conf="$BITCOIN_CONF" importprivkey "$PRIVKEY" >"$FAUCET_LOGFILE" 2>&1
   local RC=$?
   if [ $RC -ne 0 ]; then
      logln "FAILED!"
      return 1
   fi
   logln "ok"

   local MINER_ADDR="$(cat "$BITCOIN_CONTROLLER_CONF" | grep "miner_address =" | cut -d ' ' -f 3 | sed -r 's/"//g')"

   log "[$$]  Importing miner address $MINER_ADDR..."
   
   echo "Try importing miner address $MINER_ADDR" >>"$FAUCET_LOGFILE"
   bitcoin-cli -conf="$BITCOIN_CONF" importaddress "$MINER_ADDR" >>"$FAUCET_LOGFILE" 2>&1
   RC=$?
   if [ $RC -ne 0 ]; then 
      logln "FAILED!"
      return 1
   fi

   logln "ok"

   log "[$$] Starting bitcoin faucet..."
   faucet.sh "$FAUCET_PORT" "$BITCOIN_CONF" "$STACKS_MASTER_CHAINSTATE_DIR" >"$FAUCET_LOGFILE" 2>&1 &
   local FAUCET_PID=$!
   logln "PID $FAUCET_PID"

   echo "$FAUCET_PID"
   return 0
}

start_stacks_master_node() {
   test -d "$STACKS_MASTER_CHAINSTATE_DIR" && exit_error "Cannot start Stacks master node: Directory exists: $STACKS_MASTER_CHAINSTATE_DIR"

   logln "[$$] Setting up Stacks master node..."
   test -f "$STACKS_MASTER_CONF_IN" || exit_error "No such file or directory: $STACKS_MASTER_CONF_IN"

   log "[$$]  Generating Stacks master config file..."
   sed -r \
      -e "s!@@STACKS_CHAINSTATE_DIR@@!$STACKS_MASTER_CHAINSTATE_DIR!g" \
      -e "s!@@STACKS_PUBLIC_IP@@!$STACKS_MASTER_PUBLIC_IP!g" \
      -e "s!@@STACKS_MASTER_IS_MINER@@!$STACKS_MASTER_IS_MINER!g" \
      -e "s/@@PROCESS_EXIT_AT_BLOCK_HEIGHT@@/$PROCESS_EXIT_AT_BLOCK_HEIGHT/g" \
      -e "s/@@STACKS_DENY_NODES@@/$STACKS_MASTER_DENY_NODES/g" \
      -e "s/@@DISABLE_INBOUND_HANDSHAKES@@/$STACKS_MASTER_DISABLE_INBOUND_HANDSHAKES/g" \
      -e "s/@@DISABLE_INBOUND_WALKS@@/$STACKS_MASTER_DISABLE_INBOUND_WALKS/g" \
      -e "s/@@STACKS_MASTER_MINE_MICROBLOCKS@@/$STACKS_MASTER_MINE_MICROBLOCKS/g" \
      -e "s/@@STACKS_MASTER_MICROBLOCK_FREQUENCY@@/$STACKS_MASTER_MICROBLOCK_FREQUENCY/g" \
      -e "s/@@STACKS_MASTER_MAX_MICROBLOCKS@@/$STACKS_MASTER_MAX_MICROBLOCKS/g" \
      -e "s/@@STACKS_MASTER_WAIT_FOR_MICROBLOCKS@@/$STACKS_MASTER_WAIT_FOR_MICROBLOCKS/g" \
      "$STACKS_MASTER_CONF_IN" \
      > "$STACKS_MASTER_CONF"
   logln "ok"

   log "[$$] Starting Stacks master node..."
   BLOCKSTACK_DEBUG=1 RUST_BACKTRACE=full stacks-node start --config "$STACKS_MASTER_CONF" >"$STACKS_MASTER_LOGFILE" 2>&1 &
   local STACKS_PID=$!
   logln "PID $STACKS_PID"

   echo "$STACKS_PID"
   return 0
}

start_stacks_miner_node() {
   test -d "$STACKS_MINER_CHAINSTATE_DIR" && exit_error "Cannot start Stacks miner node: Directory exists: $STACKS_MASTER_CHAINSTATE_DIR"

   logln "[$$] Setting up Stacks miner node ($STACKS_MINER_CONF)..."
   test -f "$STACKS_MINER_CONF_IN" || exit_error "No such file or directory: $STACKS_MINER_CONF_IN"

   log "[$$]  Generating Stacks miner config file..."
   local STACKS_MINER_SEED="$(blockstack-cli generate-sk | jq -r '.secretKey')"

   sed -r \
      -e "s/@@STACKS_BOOTSTRAP_IP@@/$STACKS_MINER_BOOTSTRAP_IP/g" \
      -e "s/@@STACKS_BOOTSTRAP_PORT@@/$STACKS_MINER_BOOTSTRAP_PORT/g" \
      -e "s/@@STACKS_DENY_NODES@@/$STACKS_MINER_DENY_NODES/g" \
      -e "s/@@BITCOIN_IP@@/$BITCOIN_PUBLIC_IP/g" \
      -e "s!@@STACKS_PUBLIC_IP@@!$STACKS_MINER_PUBLIC_IP!g" \
      -e "s/@@STACKS_MINER_SEED@@/$STACKS_MINER_SEED/g" \
      -e "s!@@STACKS_CHAINSTATE_DIR@@!$STACKS_MINER_CHAINSTATE_DIR!g" \
      -e "s!@@STACKS_MINER_P2P_PORT@@!$STACKS_MINER_P2P_PORT!g" \
      -e "s!@@STACKS_MINER_RPC_PORT@@!$STACKS_MINER_RPC_PORT!g" \
      -e "s/@@PROCESS_EXIT_AT_BLOCK_HEIGHT@@/$PROCESS_EXIT_AT_BLOCK_HEIGHT/g" \
      -e "s/@@DISABLE_INBOUND_HANDSHAKES@@/$STACKS_MINER_DISABLE_INBOUND_HANDSHAKES/g" \
      -e "s/@@DISABLE_INBOUND_WALKS@@/$STACKS_MINER_DISABLE_INBOUND_WALKS/g" \
      -e "s/@@STACKS_MINER_MINE_MICROBLOCKS@@/$STACKS_MINER_MINE_MICROBLOCKS/g" \
      -e "s/@@STACKS_MINER_MICROBLOCK_FREQUENCY@@/$STACKS_MINER_MICROBLOCK_FREQUENCY/g" \
      -e "s/@@STACKS_MINER_MAX_MICROBLOCKS@@/$STACKS_MINER_MAX_MICROBLOCKS/g" \
      -e "s/@@STACKS_MINER_WAIT_FOR_MICROBLOCKS@@/$STACKS_MINER_WAIT_FOR_MICROBLOCKS/g" \
      "$STACKS_MINER_CONF_IN" \
      > "$STACKS_MINER_CONF"
   logln "ok"

   local BTCADDR="$(blockstack-cli --testnet addresses "$STACKS_MINER_SEED" | jq -r '.BTC')"
   local TIMEOUT=2
   local TXID=""
   local CONFIRMATIONS=0

   log "[$$]  Fetching BTC from the faucet for this miner ($BTCADDR)..."
   for i in $(seq 1 10); do
       TXID="$(curl -sf -X POST -d $BTCADDR$'\n' -H "content-type: text/plain" "$FAUCET_URL"/bitcoin/fund)"
       local RC=$?
       if [ $RC -ne 0 ]; then 
          # curl failed, or we didn't get 200.  Try again
          logln "FAILED!  Try again in $TIMEOUT seconds..."
          sleep $TIMEOUT

          TIMEOUT=$((TIMEOUT + $RANDOM % TIMEOUT))
          continue
       fi
       break
   done
   logln "txid $TXID"

   log "[$$]  Waiting for BTC to get confirmed..."
   TIMEOUT=2
   for i in $(seq 1 20); do
       CONFIRMATIONS="$(curl -sf "$FAUCET_URL"/bitcoin/confirmations/"$TXID")"
       local RC=$?
       if [ $RC -ne 0 ]; then 
          logln "FAILED!  Try again (attempt $i)..."
          sleep $TIMEOUT

          TIMEOUT=$((TIMEOUT + $RANDOM % TIMEOUT))
          continue
       fi
       if (( $CONFIRMATIONS > 0 )); then 
          break
       else
          log ".wait $TIMEOUT."
          sleep $TIMEOUT

          TIMEOUT=$((TIMEOUT + $RANDOM % TIMEOUT))
       fi
   done

   if (( $CONFIRMATIONS == 0 )); then 
      logln "FAILED"
      return 1
   fi
   logln "ok"
   
   log "[$$] Starting Stacks miner node..."
   BLOCKSTACK_DEBUG=1 RUST_BACKTRACE=full stacks-node start --config "$STACKS_MINER_CONF" >"$STACKS_MINER_LOGFILE" 2>&1 &
   local STACKS_PID=$!
   logln "PID $STACKS_PID"
   
   echo "$STACKS_PID"
   return 0
}

start_stacks_follower_node() {
   test -d "$STACKS_FOLLOWER_CHAINSTATE_DIR" && exit_error "Cannot start Stacks miner node: Directory exists: $STACKS_MASTER_CHAINSTATE_DIR"

   logln "[$$] Setting up Stacks follower node ($STACKS_FOLLOWER_CONF)..."
   test -f "$STACKS_FOLLOWER_CONF_IN" || exit_error "No such file or directory: $STACKS_FOLLOWER_CONF_IN"

   log "[$$]  Generating Stacks follower config file..."
   sed -r \
      -e "s/@@STACKS_BOOTSTRAP_IP@@/$STACKS_FOLLOWER_BOOTSTRAP_IP/g" \
      -e "s/@@STACKS_BOOTSTRAP_PORT@@/$STACKS_FOLLOWER_BOOTSTRAP_PORT/g" \
      -e "s/@@BITCOIN_IP@@/$BITCOIN_PUBLIC_IP/g" \
      -e "s!@@STACKS_PUBLIC_IP@@!$STACKS_FOLLOWER_PUBLIC_IP!g" \
      -e "s/@@STACKS_DENY_NODES@@/$STACKS_FOLLOWER_DENY_NODES/g" \
      -e "s!@@STACKS_CHAINSTATE_DIR@@!$STACKS_FOLLOWER_CHAINSTATE_DIR!g" \
      -e "s!@@STACKS_FOLLOWER_P2P_PORT@@!$STACKS_FOLLOWER_P2P_PORT!g" \
      -e "s!@@STACKS_FOLLOWER_RPC_PORT@@!$STACKS_FOLLOWER_RPC_PORT!g" \
      -e "s/@@PROCESS_EXIT_AT_BLOCK_HEIGHT@@/$PROCESS_EXIT_AT_BLOCK_HEIGHT/g" \
      -e "s/@@DISABLE_INBOUND_HANDSHAKES@@/$STACKS_FOLLOWER_DISABLE_INBOUND_HANDSHAKES/g" \
      -e "s/@@DISABLE_INBOUND_WALKS@@/$STACKS_FOLLOWER_DISABLE_INBOUND_WALKS/g" \
      "$STACKS_FOLLOWER_CONF_IN" \
      > "$STACKS_FOLLOWER_CONF"
   logln "ok"
   
   log "[$$] Starting Stacks follower node..."
   BLOCKSTACK_DEBUG=1 RUST_BACKTRACE=full stacks-node start --config "$STACKS_FOLLOWER_CONF" >"$STACKS_FOLLOWER_LOGFILE" 2>&1 &
   local STACKS_PID=$!
   logln "PID $STACKS_PID"

   echo "$STACKS_PID"
   return 0
}

check_if_running() {
   local PID=$1
   if [ $PID -gt 0 ]; then 
       kill -s 0 "$PID" 2>/dev/null
       return $?
   else
       return 0
   fi
}

kill_if_running() {
   local SIG="$1"
   local PID=$2

   if [ $PID -gt 0 ]; then
      check_if_running $PID
      if [ $? -eq 0 ]; then
         logln "[$$] Send $SIG to PID $PID"
         kill -s "$SIG" "$PID" 2>/dev/null || true
      fi
   fi
}

BITCOIN_PID=0
BITCOIN_NEON_CONTROLLER_PID=0
STACKS_NODE_PID=0
FAUCET_PID=0

wait_pids() {
   while true; do
      wait
      sleep 5

      local ALL_GOOD=0
      local PID=0
      for PID in $@; do
         check_if_running $PID
         if [ $? -ne 0 ]; then
            ALL_GOOD=1
            break
         fi
      done

      if [ $ALL_GOOD -ne 0 ]; then
         break
      fi
   done
   return 0
}

shutdown() {
   echo "[$$] Sending SIGTERM to all processes"
   for PID in $BITCOIN_PID $BITCOIN_NEON_CONTROLLER_PID $STACKS_NODE_PID $FAUCET_PID; do
       kill_if_running SIGTERM $PID
   done

   sleep 5
   echo "[$$] Sending SIGKILL to all processes"
   for PID in $BITCOIN_PID $BITCOIN_NEON_CONTROLLER_PID $STACKS_NODE_PID $FAUCET_PID; do
       kill_if_running SIGKILL $PID
   done

   exit 0
}

usage() {
   exit_error "Usage: $0 [master|miner|follower]"
}

start_node() {
   local MODE="$CONFIG_MODE"
   if [ $# -gt 0 ]; then
      MODE="$1"
   fi
   if [ -z "$MODE" ]; then
      usage
   fi

   set -uo pipefail
   trap 'shutdown' INT

   case "$MODE" in
      master)
         BITCOIN_PID="$(start_bitcoind)"

         sleep 5
         BITCOIN_NEON_CONTROLLER_PID="$(start_bitcoind_controller)"

         sleep 5
         FAUCET_PID="$(start_faucet)"

         sleep 5
         STACKS_NODE_PID="$(start_stacks_master_node)"
         ;;

      miner)
         STACKS_NODE_PID="$(start_stacks_miner_node)"
         ;;

      follower)
         STACKS_NODE_PID="$(start_stacks_follower_node)"
         ;;
      *)
         usage
         ;;
   esac

   echo >&2 "[$$] Running!"

   # reap children
   wait_pids $BITCOIN_PID $BITCOIN_NEON_CONTROLLER_PID $STACKS_NODE_PID $FAUCET_PID

   echo >&2 "[$$] Shutting down"
   shutdown
}

wait_node() {
   local MODE="$CONFIG_MODE"
   if [ $# -gt 0 ]; then
       MODE="$1"
   fi
   local RPC_HOST=""
   local RPC_PORT=""
   case "$MODE" in
      master)
         RPC_HOST="$STACKS_MASTER_PUBLIC_IP"
         RPC_PORT="20443"
         ;;
      miner)
         RPC_HOST="$STACKS_MINER_PUBLIC_IP"
         RPC_PORT="$STACKS_MINER_RPC_PORT"
         ;;
      follower)
         RPC_HOST="$STACKS_FOLLOWER_PUBLIC_IP"
         RPC_PORT="$STACKS_FOLLOWER_RPC_PORT"
         ;;
      *)
         return 1
         ;;
   esac
   local CNT=0
   for CNT in $(seq 1 360); do
      curl -sLf "http://$RPC_HOST:$RPC_PORT/v2/info" >/dev/null 2>&1
      if [ $? -eq 0 ]; then
         return 0
      fi
      sleep 5
   done
   return 1
}

wait_until_burn_block() {
   local RPC_HOST=""
   local RPC_PORT=""
   local BURN_BLOCK_HEIGHT="$1"
   local MODE="$CONFIG_MODE"
   if [ $# -gt 1 ]; then
      MODE="$2"
   fi

   case "$MODE" in
      master)
         RPC_HOST="$STACKS_MASTER_PUBLIC_IP"
         RPC_PORT="20443"
         ;;
      miner)
         RPC_HOST="$STACKS_MINER_PUBLIC_IP"
         RPC_PORT="$STACKS_MINER_RPC_PORT"
         ;;
      follower)
         RPC_HOST="$STACKS_FOLLOWER_PUBLIC_IP"
         RPC_PORT="$STACKS_FOLLOWER_RPC_PORT"
         ;;
      *)
         return 1
         ;;
   esac
   local INFO_URL="http://$RPC_HOST:$RPC_PORT/v2/info"
   while true; do
      curl -sLf "$INFO_URL" >/dev/null 2>&1
      if [ $? -ne 0 ]; then
         sleep 5
         continue
      fi

      local BURN_HEIGHT="$(curl -sLf "$INFO_URL" | jq -r '.burn_block_height')"
      if (( $BURN_HEIGHT >= $BURN_BLOCK_HEIGHT )); then
         break
      fi
      sleep 5
   done
}

stop_node() {
   local PID="$1"
   kill -s SIGINT "$PID"
   return $?
}

report() {
   local REPORT_NAME="$1"
   local CHAINSTATE_DIR=""
   case "$CONFIG_MODE" in
      master)
         CHAINSTATE_DIR="$STACKS_MASTER_CHAINSTATE_DIR"
         ;;
      miner)
         CHAINSTATE_DIR="$STACKS_MINER_CHAINSTATE_DIR"
         ;;
      follower)
         CHAINSTATE_DIR="$STACKS_FOLLOWER_CHAINSTATE_DIR"
         ;;
      *)
         return 1
         ;;
   esac
   faucet.sh report "$BITCOIN_CONF" "$CHAINSTATE_DIR" "$REPORT_NAME"
}

is_sourced
if [ $? -ne 0 ]; then 
   for cmd in bitcoind bitcoin-cli puppet-chain stacks-node blockstack-cli date jq grep sed kill cat curl faucet.sh seq; do
      which $cmd 2>&1 >/dev/null || exit_error "Missing \"$cmd\""
   done

   CONF_FILE=""
   if [ -n "$CONFIG" ]; then
      CONF_FILE="$CONFIG"
   fi
   if [ -z "$CONF_FILE" ]; then
      exit_error "$CONFIG environ not set"
   fi
   if ! [ -f "$CONF_FILE" ]; then
      exit_error "No such file or directory: $CONF_FILE"
   fi
   source "$CONF_FILE"
   start_node $@
fi

