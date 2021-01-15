#!/bin/bash

exit_error() {
   printf "$1" >&2
   exit 1
}

for cmd in sqlite3 curl xxd grep cut jq date; do
   which $cmd >/dev/null 2>&1 || exit_error "Missing command: $cmd"
done

if [ $(echo ${BASH_VERSION} | cut -d '.' -f 1) -lt 4 ]; then
   exit_error "This script requires Bash 4.x or higher"
fi

set -uo pipefail

DEBUG=1

log() {
   printf >&2 "%s\n" "$1"
}

debug() {
   if [ $DEBUG -ne 0 ]; then
      log "$1"
   fi
}

# args:
# $1 mempool path
# $2 minimum accept time
get_mempool_txs() {
   local mempool_path="$1"
   local min_accept_time="$2"

   debug "Get mempool transactions from $mempool_path newer than $min_accept_time"
   sqlite3 "$mempool_path" "SELECT HEX(tx) FROM mempool WHERE accept_time >= $min_accept_time"
}

# args
# $1 target host:port
# $2 tx
post_tx() {
   local target_hostport="$1"
   local tx="$2"

   debug "Send $tx to $target_hostport"
   ( echo "$tx" | xxd -r -p | curl -sf -m 3 -X POST -H 'content-type: application/octet-stream' --data-binary @- "http://$target_hostport/v2/transactions" >/dev/null || log "WARN: failed to propagate to $target_hostport" ) || true
}

# args
# $1 local peer host:port
# prints newline-separated lists of "host:port"
list_outbound_neighbors() {
   local local_hostport="$1"
   
   debug "Get outbound neighbors of $local_hostport"
   ( curl -sf -m 3 "http://$local_hostport/v2/neighbors" | jq -r '.outbound[] | "\(.ip):\(.port)"' ) || true
}

# args
# reads stdin to get the next hostport
to_rpc_host() {
   # /v2/neighbors only reports the p2p port, so deduce the rpc port from it -- if it's 20444, then assume 20443
   local hostport=""
   while read -r hostport; do
      if [ -n "$(echo "$hostport" | grep ":20444")" ]; then
         echo "$hostport" | sed -r 's/:20444$/:20443/g'
      fi
   done
}

# args
# $1 local peer host:port
# $2 local mempool path
# $3 last sent
antientropy_pass() {
   local mempool_path="$1"
   local local_peer="$2"
   local last_sent="$3"

   # do this sequentially so we don't hold open the DB
   get_mempool_txs "$mempool_path" "$last_sent" > "/tmp/last_mempool_scan.txs.$$"
   cat "/tmp/last_mempool_scan.txs.$$" | ( \
      local tx=""
      local host=""
      while read -r tx; do
         list_outbound_neighbors "$local_peer" | to_rpc_host | ( \
            local hostport=""
            while read -r hostport; do
               post_tx "$hostport" "$tx"
            done
         )
      done
   )
}

get_last_scan_time() {
   if [ -f "/tmp/last_mempool_scan.time.$$" ]; then
      cat "/tmp/last_mempool_scan.time.$$"
   else
      date +%s
   fi
}

# args
# $1 last scan time
save_last_scan_time() {
   echo "$1" > "/tmp/last_mempool_scan.time.$$"
}

# args
# $1 mempool DB path
# $2 local peer host:port
main() {
   local mempool_path="$1"
   local local_peer="$2"
   local deadline=0
   local delay_time=0
   local now="$(date +%s)"
   local last_sent="$(get_last_scan_time)"
   while true; do
      local scan_time="$(date +%s)"
      deadline=$((scan_time + 300))
      log "Begin mempool scan at $(date +%s)"

      antientropy_pass "$mempool_path" "$local_peer" "$last_sent"

      now=$scan_time
      delay_time=$((deadline - now))
      save_last_scan_time "$scan_time"

      log "Scan completed at $now"
      if (($delay_time > 0)); then
         log "Rescan at $deadline"
         sleep $delay_time
      fi
   done
}

usage() {
   log "Usage: $0 PATH_TO_MEMPOOL LOCAL_PEER_HOST:PORT"
   exit 1
}

set +u
mempool_path="$1"
local_hostport="$2"
set -u

if [ -z "$mempool_path" ] || [ -z "$local_hostport" ]; then
   usage
fi

if ! [ -f "$mempool_path" ]; then 
   log "No such file or directory: $mempool_path"
   exit 1
fi

main "$mempool_path" "$local_hostport"

# testing
# get_mempool_txs "$1" "$2"
# list_outbound_neighbors "$1" | to_rpc_host
# post_tx "$1" "$2"
# antientropy_pass "$1" "$2" "$3"

