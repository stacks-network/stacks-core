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

# Prints out the list of mempool transactions with acceptance times later than a given time.
# args:
# $1 mempool path
# $2 minimum accept time
get_mempool_txs() {
   local mempool_path="$1"
   local min_accept_time="$2"

   debug "Get mempool transactions from $mempool_path newer than $min_accept_time"
   sqlite3 "$mempool_path" "SELECT HEX(tx) FROM mempool WHERE accept_time >= $min_accept_time"
}

# POSTs a transaction to a given node
# args
# $1 target host:port
# $2 tx
post_tx() {
   local target_hostport="$1"
   local tx="$2"

   debug "Send $tx to $target_hostport"
   ( echo "$tx" | xxd -r -p | curl -sf -m 3 -X POST -H 'content-type: application/octet-stream' --data-binary @- "http://$target_hostport/v2/transactions" >/dev/null || log "WARN: failed to propagate to $target_hostport" ) || true
}

# Prints out a list of a node's neighbors as newline-separated "host:port" strings
# args
# $1 local peer host:port
# prints newline-separated lists of "host:port"
list_outbound_neighbors() {
   local local_hostport="$1"
   
   debug "Get outbound neighbors of $local_hostport"
   ( curl -sf -m 3 "http://$local_hostport/v2/neighbors" | jq -r '.outbound[] | "\(.ip):\(.port)"' ) || true
}

# Deduces the RPC port for a peer.  Meant to be used in a pipeline -- it reads the host:p2p_port from stdin, and writes host:rpc_port to stdout.
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

# Reads a list of transactions to broadcast from a file, and pushes each transaction to the given node's neighbors.
# args
# $1 path to file with transactions
# $2 local peer host:port
antientropy_push() {
   local tx_file="$1"
   local local_peer="$2"

   cat "$tx_file" | ( \
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

# Grabs a list of transactions from the given mempool that arrived later than a given last_sent time, and pushes them all to the node's neighbors.
# args
# $1 local peer host:port
# $2 local mempool path
# $3 last sent
antientropy_pass() {
   local mempool_path="$1"
   local local_peer="$2"
   local last_sent="$3"
   local peer_count=0

   # do this sequentially so we don't hold open the DB
   for peer in ${local_peer//,/ }; do
         if [ $peer_count -eq 0 ]; then
            get_mempool_txs "$mempool_path" "$last_sent" > "/tmp/last_mempool_scan.txs.$$"
         fi
         antientropy_push "/tmp/last_mempool_scan.txs.$$" "$peer"
         let peer_count++
   done
}

# Obtain the last-sent time (stored to disk)
get_last_scan_time() {
   if [ -f "/tmp/last_mempool_scan.time.$$" ]; then
      cat "/tmp/last_mempool_scan.time.$$"
   else
      date +%s
   fi
}

# Save the last-sent time (stored to disk)
# args
# $1 last scan time
save_last_scan_time() {
   echo "$1" > "/tmp/last_mempool_scan.time.$$"
}

# Daemon mode main loop
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
   log "Usage: $0 MODE [ARGS...]"
   log "MODE can be the following:"
   log "      $0 daemon PATH_TO_MEMPOOL LOCAL_PEER_HOST:PORT"
   log "      $0 daemon PATH_TO_MEMPOOL LOCAL_PEER_HOST1:PORT,LOCAL_PEER_HOST2:PORT,..."
   log ""
   log "      $0 push PATH_TO_TX_FILE LOCAL_PEER_HOST:PORT"
   log "      $0 push PATH_TO_TX_FILE LOCAL_PEER_HOST1:PORT,LOCAL_PEER_HOST2:PORT,..."
   log ""
   log "In daemon mode, this program simply loops forever and re-sends transactions from the given"
   log "mempool every 5 minutes to the given node's neighbors."
   log "Example:"
   log "      $ $0 daemon /path/to/mempool.sqlite localhost:20443"
   log ""
   log "In push mode, this program reads a list of hex-encoded newline-separated transactions from"
   log "a file, and pushes them to a given node's neighbors."
   log "Example:"
   log "      $ sqlite3 -noheader /path/to/mempool.sqlite \\"
   log "          'SELECT HEX(tx) FROM mempool ORDER BY accept_time DESC LIMIT 10' \\"
   log "           > /tmp/txs.dat"
   log "      $ $0 push /tmp/txs.dat localhost:20443"
   log ""
   exit 1
}

set +u
mode="$1"
set -u

case "$mode" in
   daemon)
      set +u
      mempool_path="$2"
      local_hostport="$3"
      set -u

      if [ -z "$mempool_path" ] || [ -z "$local_hostport" ]; then
         usage
      fi

      if ! [ -f "$mempool_path" ]; then 
         log "No such file or directory: $mempool_path"
         exit 1
      fi

      main "$mempool_path" "$local_hostport"
      ;;

   push)
      set +u
      tx_path="$2"
      local_hostport="$3"
      set -u

      if [ -z "$tx_path" ] || [ -z "$local_hostport" ]; then
         usage
      fi
      
      if ! [ -f "$tx_path" ]; then 
         log "No such file or directory: $tx_path"
         exit 1
      fi

      antientropy_push "$tx_path" "$local_hostport"
      ;;

   *)
      usage
      ;;
esac

# testing
# get_mempool_txs "$1" "$2"
# list_outbound_neighbors "$1" | to_rpc_host
# post_tx "$1" "$2"
# antientropy_pass "$1" "$2" "$3"

