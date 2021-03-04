#!/bin/bash

exit_error() {
   printf "$1" >&2
   exit 1
}

for cmd in sqlite3 curl xxd jq cut cat sed stat; do
   which $cmd >/dev/null 2>&1 || exit_error "Missing command: $cmd\n"
done

if [ $(echo ${BASH_VERSION} | cut -d '.' -f 1) -lt 4 ]; then
   exit_error "This script requires Bash 4.x or higher\n"
fi

chainstate_dir="$1"
hostport="$2"
first_burn_height="$3"
chain_mode="krypton"                      # change this for mainnet

if [ -z "$first_burn_height" ]; then
   first_burn_height=1902512
fi

if [ -z "$chainstate_dir" ] || [ -z "$hostport" ]; then 
   exit_error "Usage: $0 CHAINSTATE_DIR HOST:PORT [START_BURN_HEIGHT]\n"
fi

blocks_db="$chainstate_dir/$chain_mode/chainstate/vm/index.sqlite"
sortition_db="$chainstate_dir/$chain_mode/burnchain/sortition/marf.sqlite"
blocks_path="$chainstate_dir/$chain_mode/chainstate/blocks"

set -uo pipefail

tip_burn_block="$(curl -sf http://$hostport/v2/info | jq -r '.burn_block_height')"

block_path() {
   local p="$(echo "$1" | sed -r 's/^([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]+)$/\1\/\2\/\1\2\3/g')"
   echo "$blocks_path/$p"
}

main() {
   local burn_block_begin="$1"
   local burn_block_end="$2"
   local row=""
   for row in $(sqlite3 "$blocks_db" "SELECT index_block_hash,block_hash,consensus_hash,burn_header_height FROM block_headers WHERE burn_header_height >= $burn_block_begin AND burn_header_height < $burn_block_end ORDER BY block_height ASC"); do
       local index_block_hash=""
       local block_hash=""
       local consensus_hash=""
       local burn_header_height=""
       local bp=""
       local sz=""
       local rc=""
       local microblock_hash=""
       local microblock_data=""
       local pox_valid=""

       IFS="|" read -r index_block_hash block_hash consensus_hash burn_header_height <<< $(echo "$row")

       pox_valid="$(sqlite3 "$sortition_db" "SELECT pox_valid FROM snapshots WHERE consensus_hash = '$consensus_hash'")"
       if [[ "$pox_valid" != "1" ]]; then
          echo "INFO: skip PoX-invalid block $index_block_hash ($consensus_hash/$block_hash)"
          continue
       fi

       echo "DEBG: Upload $index_block_hash ($consensus_hash/$block_hash)"

       bp="$(block_path $index_block_hash)"
       sz="$(stat -c "%s" "$bp")"
       /bin/cat "$(block_path $index_block_hash)" | \
         curl -sf -X POST -H 'content-type: application/octet-stream' -H "content-length: $sz" --data-binary @- "http://$hostport/v2/blocks/upload/$consensus_hash" && echo ''

       rc=$?
       if [ $rc -ne 0 ]; then
          echo "WARN: failed to upload $index_block_hash (burn height $burn_header_height): curl error $rc"
       fi

       for microblock_hash in $(sqlite3 "$blocks_db" "SELECT microblock_hash FROM staging_microblocks WHERE index_block_hash = '$index_block_hash'"); do
          microblock_data="$(sqlite3 "$blocks_db" "SELECT hex(block_data) FROM staging_microblocks_data WHERE block_hash = '$microblock_hash'")"
          sz=${#microblock_data}
          sz=$((sz / 2))

          echo "$microblock_data" | xxd -r -p | \
            curl -sf -X POST -H 'content-type: application/octet-stream' -H "content-length: $sz" --data-binary @- "http://$hostport/v2/microblocks" && echo ''

          rc=$?
          if [ $rc -ne 0 ]; then
             echo "WARN: failed to upload $index_block_hash $consensus_hash/$block_hash-$microblock_hash (burn height $burn_header_height): curl error $rc"
          fi
       done
   done
}

main $first_burn_height $tip_burn_block
