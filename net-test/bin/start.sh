#!/usr/bin/env bash

BITCOIN_LOGFILE="/mnt/bitcoin.log"
BITCOIN_NEON_CONTROLLER_LOGFILE="/mnt/bitcoin-neon-controller.log"
STACKS_MASTER_LOGFILE="/mnt/stacks-node-master.log"
STACKS_MINER_LOGFILE="/mnt/stacks-node-miner.log"
STACKS_FOLLOWER_LOGFILE="/mnt/stacks-node-follower.log"
FAUCET_LOGFILE="/mnt/faucet.log"

BITCOIN_CONF="/etc/bitcoin.conf"
BITCOIN_CONTROLLER_CONF="/etc/bitcoin-neon-controller.toml"
STACKS_MASTER_CONF="/etc/stacks-master.toml"
STACKS_MINER_CONF="/etc/stacks-miner.toml"
STACKS_FOLLOWER_CONF="/etc/stacks-follower.toml"

STACKS_CHAINSTATE_DIR="/mnt/stacks-chainstate"
BITCOIN_DATA_DIR="/mnt/bitcoin"

STACKS_MASTER_PUBLIC_IP="127.0.0.1"

FAUCET_PORT=8080

exit_error() {
   printf "$1" >&2
   exit 1
}

for cmd in bitcoind bitcoin-cli bitcoin-neon-controller stacks-node blockstack-cli date jq grep sed kill cat curl faucet.sh seq; do
   which $cmd 2>&1 >/dev/null || exit_error "Missing \"$cmd\""
done

if [ $(echo ${BASH_VERSION} | cut -d '.' -f 1) -lt 4 ]; then
   exit_error "This script requires Bash 4.x or higher"
fi

MODE="$1"
set -uo pipefail

if [ -f "./config.sh" ]; then
   source ./config.sh
fi

function log() {
   printf "%s" "$1" >&2
}

function logln() {
   printf "%s\n" "$1" >&2
}

start_bitcoind() {
   logln "Setting up bitcoind..."
   test -f "$BITCOIN_CONF".in || exit_error "No such file or directory: $BITCOIN_CONF"
   mkdir -p "$BITCOIN_DATA_DIR" || exit_error "Failed to create bitcoin data directory $BITCOIN_DATA_DIR"

   log "  Generating bitcoind config file..."
   sed -r \
     -e "s!@@BITCOIN_DATA_DIR@@!$BITCOIN_DATA_DIR!g" \
     "$BITCOIN_CONF".in \
     > "$BITCOIN_CONF"
   logln "ok"
   
   log "Starting bitcoind..."
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
   logln "Setting up bitcoind controller..."
   test -f "$BITCOIN_CONTROLLER_CONF".in || exit_error "No such file or directory: $BITCOIN_CONTROLLER_CONF.in"

   log "  Generating bitcoind controller config file..."
   local NOW="$(date +%s)"
   sed -r \
    -e "s/@@BITCOIN_NEON_CONTROLLER_GENESIS_TIMESTAMP@@/$NOW/g" \
    "$BITCOIN_CONTROLLER_CONF".in \
    > "$BITCOIN_CONTROLLER_CONF"
   logln "ok"

   log "Starting bitcoind controller..."
   bitcoin-neon-controller "$BITCOIN_CONTROLLER_CONF" >"$BITCOIN_NEON_CONTROLLER_LOGFILE" 2>&1 &
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
   logln "Setting up bitcoin faucet..."
   test -f "$BITCOIN_CONTROLLER_CONF" || exit_error "No such file or directory: $BITCOIN_CONTROLLER_CONF"
   test -f "$BITCOIN_CONF" || exit_error "No such file or directory: $BITCOIN_CONF"

   local PRIVKEY="$(cat "$BITCOIN_CONTROLLER_CONF" | grep "# WIF" | cut -d ' ' -f 3)"

   log "  Importing faucet private key..."
   bitcoin-cli -conf="$BITCOIN_CONF" importprivkey "$PRIVKEY" >"$FAUCET_LOGFILE" 2>&1
   local RC=$?
   if [ $RC -ne 0 ]; then
      logln "FAILED!"
      return 1
   fi
   logln "ok"

   local MINER_ADDR="$(cat "$BITCOIN_CONTROLLER_CONF" | grep "miner_address =" | cut -d ' ' -f 3 | sed -r 's/"//g')"

   log "  Importing miner address $MINER_ADDR..."
   
   echo "Try importing miner address $MINER_ADDR" >>"$FAUCET_LOGFILE"
   bitcoin-cli -conf="$BITCOIN_CONF" importaddress "$MINER_ADDR" >>"$FAUCET_LOGFILE" 2>&1
   RC=$?
   if [ $RC -ne 0 ]; then 
      logln "FAILED!"
      return 1
   fi

   logln "ok"

   log "Starting bitcoin faucet..."
   faucet.sh "$FAUCET_PORT" "$BITCOIN_CONF" >"$FAUCET_LOGFILE" 2>&1 &
   local FAUCET_PID=$!
   logln "PID $FAUCET_PID"

   echo "$FAUCET_PID"
   return 0
}

start_stacks_master_node() {
   logln "Setting up Stacks master node..."
   test -f "$STACKS_MASTER_CONF".in || exit_error "No such file or directory: $STACKS_MASTER_CONF.in"

   log "  Generating Stacks master config file..."
   sed -r \
      -e "s!@@STACKS_CHAINSTATE_DIR@@!$STACKS_CHAINSTATE_DIR!g" \
      -e "s!@@STACKS_PUBLIC_IP@@!$STACKS_MASTER_PUBLIC_IP!g" \
      "$STACKS_MASTER_CONF".in \
      > "$STACKS_MASTER_CONF"
   logln "ok"

   log "Starting Stacks master node..."
   BLOCKSTACK_DEBUG=1 RUST_BACKTRACE=full stacks-node start --config="$STACKS_MASTER_CONF" >"$STACKS_MASTER_LOGFILE" 2>&1 &
   local STACKS_PID=$!
   logln "PID $STACKS_PID"

   echo "$STACKS_PID"
   return 0
}

start_stacks_miner_node() {
   logln "Setting up Stacks miner node..."
   test -f "$STACKS_MINER_CONF".in || exit_error "No such file or directory: $STACKS_MINER_CONF.in"

   log "  Generating Stacks miner config file..."
   local STACKS_MASTER_IP="$1"
   local BITCOIN_IP="$2"
   local FAUCET_URL="$3"
   local STACKS_MINER_SEED="$(blockstack-cli generate-sk | jq -r '.secretKey')"

   sed -r \
      -e "s/@@STACKS_MASTER_IP@@/$STACKS_MASTER_IP/g" \
      -e "s/@@BITCOIN_IP@@/$BITCOIN_IP/g" \
      -e "s/@@STACKS_MINER_SEED@@/$STACKS_MINER_SEED/g" \
      -e "s!@@STACKS_CHAINSTATE_DIR@@!$STACKS_CHAINSTATE_DIR!g" \
      "$STACKS_MINER_CONF".in \
      > "$STACKS_MINER_CONF"
   logln "ok"

   local BTCADDR="$(blockstack-cli --testnet addresses "$STACKS_MINER_SEED" | jq -r '.BTC')"
   local TIMEOUT=2
   local TXID=""
   local CONFIRMATIONS=0

   log "  Fetching BTC from the faucet for this miner ($BTCADDR)..."
   for i in $(seq 1 10); do
       TXID="$(curl -sf -X POST -d $BTCADDR$'\n' -H "content-type: text/plain" "$FAUCET_URL"/fund)"
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

   log "  Waiting for BTC to get confirmed..."
   for i in $(seq 1 5); do
       sleep 60
       local CONFIRMATIONS="$(curl -sf "$FAUCET_URL"/confirmations/"$TXID")"
       local RC=$?
       if [ $RC -ne 0 ]; then 
          logln "FAILED!  Try again (attempt $i)..."
          continue
       fi
       if [ $CONFIRMATIONS -gt 0 ]; then 
          break
       fi
   done

   if [ $CONFIRMATIONS -eq 0 ]; then 
      logln "FAILED"
      return 1
   fi
   logln "ok"
   
   log "Starting Stacks miner node..."
   BLOCKSTACK_DEBUG=1 RUST_BACKTRACE=full stacks-node start --config="$STACKS_MINER_CONF" >"$STACKS_MINER_LOGFILE" 2>&1 &
   local STACKS_PID=$!
   logln "PID $STACKS_PID"

   echo "$STACKS_PID"
   return 0
}

start_stacks_follower_node() {
   logln "Setting up Stacks follower node..."
   test -f "$STACKS_FOLLOWER_CONF".in || exit_error "No such file or directory: $STACKS_FOLLOWER_CONF.in"

   log "  Generating Stacks follower config file..."
   local STACKS_MASTER_IP="$1"
   local BITCOIN_IP="$2"
   sed -r \
      -e "s/@@STACKS_MASTER_IP@@/$STACKS_MASTER_IP/g" \
      -e "s/@@BITCOIN_IP@@/$BITCOIN_IP/g" \
      -e "s!@@STACKS_CHAINSTATE_DIR@@!$STACKS_CHAINSTATE_DIR!g" \
      "$STACKS_FOLLOWER_CONF".in \
      > "$STACKS_FOLLOWER_CONF"
   logln "ok"
   
   log "Starting Stacks follower node..."
   BLOCKSTACK_DEBUG=1 RUST_BACKTRACE=full stacks-node start --config="$STACKS_FOLLOWER_CONF" >"$STACKS_FOLLOWER_LOGFILE" 2>&1 &
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
         logln "Send $SIG to PID $PID"
         kill -s "$SIG" "$PID" 2>/dev/null || true
      fi
   fi
}

usage() {
   exit_error "Usage:\n   $0 master\n   $0 miner STACKS_MASTER_IP BITCOIN_IP FAUCET_URL\n   $0 follower STACKS_MASTER_IP BITCOIN_IP\n\n"
}

if [ -z "$MODE" ]; then
   usage
fi

BITCOIN_PID=0
BITCOIN_NEON_CONTROLLER_PID=0
STACKS_NODE_PID=0
FAUCET_PID=0

shutdown() {
   echo "Sending SIGTERM to all processes"
   for PID in $BITCOIN_PID $BITCOIN_NEON_CONTROLLER_PID $STACKS_NODE_PID $FAUCET_PID; do
       kill_if_running SIGTERM $PID
   done

   sleep 5
   echo "Sending SIGKILL to all processes"
   for PID in $BITCOIN_PID $BITCOIN_NEON_CONTROLLER_PID $STACKS_NODE_PID $FAUCET_PID; do
       kill_if_running SIGKILL $PID
   done

   exit 0
}

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
      test -n "$2" || usage
      test -n "$3" || usage
      test -n "$4" || usage
      STACKS_NODE_PID="$(start_stacks_miner_node "$2" "$3" "$4")"
      ;;

   follower)
      test -n "$2" || usage
      test -n "$3" || usage
      STACKS_NODE_PID="$(start_stacks_follower_node "$2" "$3")"
      ;;
   *)
      usage
      ;;
esac

echo "Running!"

# reap children
while true; do
   wait
   sleep 5

   ALL_GOOD=0
   for PID in $BITCOIN_PID $BITCOIN_NEON_CONTROLLER_PID $STACKS_NODE_PID $FAUCET_PID; do
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

echo "Some process exited unexpectedly"
shutdown
