#!/usr/bin/env bash

# Yup, it's a faucet HTTP server written in bash.  This is what my life has come to.

MAX_BODY_LENGTH=65536
FAUCET_AMOUNT="1.0"

MODE="$1"
BITCOIN_CONF="$2"
STACKS_WORKING_DIR="$3"

REPORT_MODE="http"

# applicable if run with 'serve'
STACKS_WORKING_DIR="$3"
STACKS_BLOCKS_ROOT="$STACKS_WORKING_DIR/chainstate/chain-00000080-testnet/blocks/"
STACKS_STAGING_DB="$STACKS_WORKING_DIR/chainstate/chain-00000080-testnet/vm/index"
STACKS_HEADERS_DB="$STACKS_WORKING_DIR/chainstate/chain-00000080-testnet/vm/index"
STACKS_SORTITION_DB="$STACKS_WORKING_DIR/burnchain/db/bitcoin/regtest/sortition.db/marf"
STACKS_MEMPOOL_DB="$STACKS_WORKING_DIR/chainstate/mempool.db"

exit_error() {
   printf "$1" >&2
   exit 1
}

for cmd in ncat bitcoin-cli egrep grep tr dd sed cut date sqlite3 awk xxd openssl blockstack-cli; do
   which $cmd >/dev/null 2>&1 || exit_error "Missing command: $cmd"
done

if [ $(echo ${BASH_VERSION} | cut -d '.' -f 1) -lt 4 ]; then
   exit_error "This script requires Bash 4.x or higher"
fi

set -uo pipefail

log() {
   printf >&2 "%s\n" "$1"
}

http_200() {
   if [[ "$REPORT_MODE" = "http" ]]; then
       local CONTENT_LENGTH="$1"
       local CONTENT_TYPE="$2"
       printf "HTTP/1.1 200 OK\r\nContent-Length: $CONTENT_LENGTH\r\nContent-Type: $CONTENT_TYPE\r\nConnection: close\r\n\r\n"
   fi
}

http_401() {
   if [[ "$REPORT_MODE" = "http" ]]; then
      printf "HTTP/1.1 401 Unsupported Method\r\nConnection: close\r\n"
   elif [[ "$REPORT_MODE" = "text" ]]; then
      printf "Unsupported method"
   fi
}

http_500() {
   local ERR="$1"
   local ERR_LEN=${#ERR}

   if [[ "$REPORT_MODE" = "http" ]]; then
       log "500 error: ${ERR}"
       printf "HTTP/1.1 500 Internal Server error\r\nContent-Length: $ERR_LEN\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n$ERR"
   elif [[ "$REPORT_MODE" = "text" ]]; then
       printf "Failed to create report: $ERR\n"
   fi
}

http_404() {
   local ERR="$1"
   local ERR_LEN=${#ERR}
   
   if [[ "$REPORT_MODE" = "http" ]]; then
       printf "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: $ERR_LEN\r\nContent-Type: text/plain\r\n\r\n$ERR"
   elif [[ "$REPORT_MODE" = "text" ]]; then
       printf "Not found: $ERR\n"
   fi
}

http_chunk() {
   local CHUNK_DATA="$1"
   local CHUNK_DATA_LEN=${#CHUNK_DATA}

   if [[ "$REPORT_MODE" = "http" ]]; then
       printf "%x\r\n%s\r\n" "$CHUNK_DATA_LEN" "$CHUNK_DATA"
   elif [[ "$REPORT_MODE" = "text" ]]; then
       printf "$CHUNK_DATA\n"
   fi
}

http_stream() {
   local LINE
   while read LINE; do
      http_chunk "$LINE"
   done
}

http_stream_end() {
   http_chunk ""
}

http_200_stream() {
   local CONTENT_TYPE="$1"

   if [[ "$REPORT_MODE" = "http" ]]; then
       printf "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nContent-Type: $CONTENT_TYPE\r\n\r\n"
   fi
}

http_page_begin() {
   http_200_stream "text/html"
   echo "<html><head></head><body>" | http_stream
}

http_page_end() {
   echo "</body><html>" | http_stream
   http_stream_end
}

http_json_begin() {
   http_200_stream "application/json"
}

http_json_end() {
   http_stream_end
}

get_ping() {
   http_200 5 "text/plain"
   printf "alive"
   return 0
}

get_bitcoin_ping() {
   if ! [ -f "$BITCOIN_CONF" ]; then
      http_404 "Bitcoind is not running on this host"
      return 2
   fi
   bitcoin-cli -conf="$BITCOIN_CONF" ping >/dev/null 2>&1
   if [ $? -eq 0 ]; then 
      local MSG="Bitcoind appears to be running"
      http_200 ${#MSG} "text/plain"
      echo "$MSG"
      return 0
   else
      http_500 "Bitcoind appears to be stopped"
      return 1
   fi
}

get_balance() {
   if ! [ -f "$BITCOIN_CONF" ]; then
      http_404 "Bitcoind is not running on this host"
      return 2
   fi
   local BALANCE="$(bitcoin-cli -conf="$BITCOIN_CONF" getbalance 2>&1)"
   if [ $? -eq 0 ]; then
      http_200 "${#BALANCE}" "text/plain"
      echo "$BALANCE"
      return 0
   else
      http_500 "$BALANCE"
      return 1
   fi
}

get_utxos() {
   local ADDR="$1"
   if ! [ -f "$BITCOIN_CONF" ]; then
      http_404 "Bitcoind is not running on this host"
      return 2
   fi
   local UTXOS="$(bitcoin-cli -conf="$BITCOIN_CONF" listunspent 1 1000000 "[\"$ADDR\"]" 2>&1)"
   if [ $? -eq 0 ]; then 
      http_200 ${#UTXOS} "application/json"
      echo "$UTXOS"
      return 0
   else
      http_500 "$UTXOS"
      return 1
   fi
}

get_confirmations() {
   local TXID="$1"
   if ! [ -f "$BITCOIN_CONF" ]; then
      http_404 "Bitcoind is not running on this host"
      return 2
   fi
   local CONFIRMATIONS="$(bitcoin-cli -conf="$BITCOIN_CONF" gettransaction "$TXID" | jq -r '.confirmations')"
   local RC=$?
   if [ $RC -eq 0 ]; then 
      http_200 ${#CONFIRMATIONS} "text/plain"
      echo "$CONFIRMATIONS"
      return 0
   elif [ $RC -eq 1 ]; then 
      http_500 "$CONFIRMATIONS"
      return 1
   else
      http_404
      return 2
   fi
}

rows_to_json() {
   awk -F '|' '{
      print "["
      for (i = 1; i <= NF; i++) {
         columns[i] = $i
      }
      if ((getline nextline) == 0) {
         exit 1
      }
      split(nextline, line, "|")
      while (1) {
         print "{"
         for (i = 1; i < NF; i++) {
            print "\"" columns[i] "\": \"" line[i] "\","
         }
         print "\"" columns[NF] "\": \"" line[NF] "\""

         if ((getline nextline) == 0) {
            print "}"
            break;
         }
         else {
            print "},"
            split(nextline, line, "|")
         }
      }
      print "]"
   }'
}

rows_to_table() {
   awk -F '|' '{
      print "<table style='"'"'font-family:\"Courier New\", Courier, monospace; font-size:80%'"'"'>"
      print "<tr>"
      for (i = 1; i <= NF; i++) {
         columns[i] = $i
         print "<td><b>" columns[i] "</b></td>"
      }
      if ((getline nextline) == 0) {
         exit 1
      }
      split(nextline, line, "|")
      while (1) {
         print "<tr>"
         for (i = 1; i <= NF; i++) {
            print "<td>" line[i] "</td>"
         }
         print "</tr>"

         if ((getline nextline) == 0) {
            break;
         }
         else {
            split(nextline, line, "|")
         }
      }
      print "</table>"
   }'
}

row_transpose() {
   KEY="$1"
   VALUE="$2"
   printf "$KEY|$VALUE\n"
   awk -F '|' '{
      for (i = 1; i <= NF; i++) {
         columns[i] = $i
      }
      num_cols = NF
      if ((getline nextline) == 0 ) {
         exit 1
      }
      split(nextline, line, "|")
      for (i = 1; i <= num_cols; i++) {
         print columns[i] "|" line[i]
      }
   }'
}

make_index_block_hash() {
   local CONSENSUS_HASH="$1"
   local BLOCK_HASH="$2"
   echo "${BLOCK_HASH}${CONSENSUS_HASH}" | xxd -r -p - | openssl dgst -sha512-256 | cut -d ' ' -f 2
}

query_stacks_block_ptrs() {
   local PREDICATE="$1"
   local COLUMNS="height,index_block_hash,consensus_hash,anchored_block_hash,parent_consensus_hash,parent_anchored_block_hash,processed,attachable,orphaned"
   sqlite3 -header "$STACKS_STAGING_DB" "SELECT $COLUMNS FROM staging_blocks $PREDICATE"
}

query_stacks_index_blocks_by_height() {
   local PREDICATE="$1"
   local COLUMNS="height,index_block_hash,processed,orphaned"
   sqlite3 -header "$STACKS_STAGING_DB" "SELECT $COLUMNS FROM staging_blocks $PREDICATE" | ( \
      local HEADERS
      read HEADERS
      printf "height|index_block_hash(processed,orphaned)\n"

      local LAST_HEIGHT=0
      local HEIGHT=0
      local INDEX_BLOCK_HASH=""
      local PROCESSED=0
      local ORPHANED=0
      IFS="|"
      while read HEIGHT INDEX_BLOCK_HASH PROCESSED ORPHANED; do
         if (( $HEIGHT != $LAST_HEIGHT)); then
            if (( $LAST_HEIGHT > 0 )); then
               printf "\n"
            fi
            LAST_HEIGHT="$HEIGHT"
            printf "%s|%s(%s,%s)" "$HEIGHT" "$INDEX_BLOCK_HASH" "$PROCESSED" "$ORPHANED"
         else
            printf ",%s(%s,%s)" "$INDEX_BLOCK_HASH" "$PROCESSED" "$ORPHANED"
         fi
      done
      printf "\n"
   )
}

query_sortitions() {
   local PREDICATE="$1"
   local COLUMNS="block_height,burn_header_hash,consensus_hash,winning_stacks_block_hash"
   sqlite3 -header "$STACKS_SORTITION_DB" "SELECT $COLUMNS FROM snapshots $PREDICATE" | ( \
      local HEADERS
      read HEADERS
      printf "height|burn_header_hash|index_block_hash\n"

      local BLOCK_HEIGHT
      local BURN_HEADER_HASH
      local CONSENSUS_HASH
      local WINNING_STACKS_BLOCK_HASH
      local INDEX_BLOCK_HASH

      IFS="|"
      while read BLOCK_HEIGHT BURN_HEADER_HASH CONSENSUS_HASH WINNING_STACKS_BLOCK_HASH; do
         INDEX_BLOCK_HASH="0000000000000000000000000000000000000000000000000000000000000000"
         if [[ "$WINNING_STACKS_BLOCK_HASH" != "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
            INDEX_BLOCK_HASH="$(make_index_block_hash "$CONSENSUS_HASH" "$WINNING_STACKS_BLOCK_HASH")"
         fi
         printf "%d|%s|%s\n" \
            "$BLOCK_HEIGHT" "$BURN_HEADER_HASH" "$INDEX_BLOCK_HASH"
      done
    )
}

query_stacks_miners() {
   local PREDICATE="$1"
   local COLUMNS="address,block_hash,consensus_hash,parent_block_hash,parent_consensus_hash,coinbase,tx_fees_anchored,tx_fees_streamed,stx_burns,burnchain_commit_burn,burnchain_sortition_burn,stacks_block_height,miner,vtxindex,index_block_hash"
   sqlite3 -header "$STACKS_HEADERS_DB" "SELECT $COLUMNS FROM payments $PREDICATE"
}

query_stacks_block_miners() {
   local PREDICATE="$1"
   local COLUMNS="stacks_block_height as height,address,index_block_hash"
   sqlite3 -header "$STACKS_HEADERS_DB" "SELECT $COLUMNS FROM payments $PREDICATE"
}

query_miner_power() {
   printf "total_blocks|address|total_btc|total_stx\n"
   sqlite3 -noheader "$STACKS_HEADERS_DB" "SELECT DISTINCT address FROM payments" | ( \
      local ADDR=""
      local COLUMNS="COUNT(index_block_hash) AS total_blocks,address,SUM(burnchain_commit_burn) AS total_btc,(SUM(coinbase) + SUM(tx_fees_anchored) + SUM(tx_fees_streamed)) AS total_stx"
      while read ADDR; do 
         sqlite3 -noheader "$STACKS_HEADERS_DB" "SELECT $COLUMNS FROM payments WHERE address = \"$ADDR\" LIMIT 1"
      done
   ) | sort -rh
}

query_stacks_mempool() {
   local PREDICATE="$1"
   local COLUMNS="accept_time AS time,txid,origin_address AS origin,origin_nonce AS nonce,sponsor_address AS sponsor,sponsor_nonce,estimated_fee,tx_fee,length"
   sqlite3 -header "$STACKS_MEMPOOL_DB" "SELECT $COLUMNS from mempool $PREDICATE"
}

query_stacks_mempool_tx() {
   local TXID="$1"
   local COLUMNS="lower(hex(tx))"
   sqlite3 -noheader "$STACKS_MEMPOOL_DB" "SELECT $COLUMNS FROM mempool WHERE txid = \"$TXID\""
}

make_prev_next_buttons() {
   local A_PATH="$1"
   local PAGE="$2"

   printf "<div style='font-family:\"Courier New\", Courier, monospace; font-size:80%%'>"
   if [[ $PAGE =~ ^[0-9]+$ ]]; then
      if (( $PAGE > 0 )); then
         printf "<a href=\"%s/%d\">[prev]</a> " "$A_PATH" "$((PAGE - 1))"
      fi
      printf "<a href=\"%s/%d\">[next]</a>" "$A_PATH" "$((PAGE + 1))"
   fi
   printf "</div><br>\n"
   return 0
}

print_table_of_contents() {
   IFS="|"
   ANCHOR=""
   NAME=""
   
   printf "<table style='font-family:\"Courier New\", Courier, monospace; font-size:80%%'>"
   printf "<tr><td><b>Table of Contents</b></td></tr>"
   while read ANCHOR NAME; do
      printf "<tr><td><a href=\"#$ANCHOR\">$NAME</a></td><tr>"
   done
   printf "</table>\n"
   return 0
}

get_page_list_stacks_blocks() {
   if ! [ -f "$STACKS_STAGING_DB" ]; then
      http_404 "Stacks node not running on this host"
      return 2
   fi

   local FORMAT="$1"
   local LIMIT="$2"
   local PAGE="$3"
   local QUERY="ORDER BY height DESC, processed DESC, orphaned ASC"
   if [[ "$LIMIT" != "all" ]]; then
     local OFFSET=$((PAGE * LIMIT))
     QUERY="$QUERY LIMIT $LIMIT OFFSET $OFFSET"
   fi

   if [[ "$FORMAT" = "html" ]]; then 
      echo "<h3 id=\"stacks_history\"><b>Stacks blockchain history</b></h3>" | http_stream
      make_prev_next_buttons "/stacks/history" "$PAGE" | http_stream
      query_stacks_index_blocks_by_height "$QUERY" | \
         sed -r 's/([0-9a-f]{64})/<a href="\/stacks\/blocks\/\1">\1<\/a>/g' | \
         rows_to_table | \
         http_stream

   elif [[ "$FORMAT" = "json" ]]; then
      query_stacks_block_ptrs "$QUERY" | rows_to_json | http_stream
   fi

   return 0
}

get_page_list_sortitions() {
   if ! [ -f "$STACKS_SORTITION_DB" ]; then
      http_404 "Stacks node not running on this host"
      return 2
   fi

   local FORMAT="$1"
   local LIMIT="$2"
   local PAGE="$3"
   local QUERY="WHERE pox_valid = 1 ORDER BY block_height DESC"
   if [[ "$LIMIT" != "all" ]]; then
     local OFFSET=$((PAGE * LIMIT))
     QUERY="$QUERY LIMIT $LIMIT OFFSET $OFFSET"
   fi
   
   if [[ "$FORMAT" = "html" ]]; then 
      echo "<h3 id=\"stacks_sortitions\"><b>Sortition history</b></h3>" | http_stream
      make_prev_next_buttons "/stacks/sortitions" "$PAGE" | http_stream
      query_sortitions "$QUERY" | \
         sed -r \
            -e 's/0{64}/no winner/g' \
            -e 's/([0-9a-f]{64})$/<a href="\/stacks\/blocks\/\1">\1<\/a>/g' | \
         rows_to_table | \
         http_stream

   elif [[ "$FORMAT" = "json" ]]; then
      query_sortitions "$QUERY" | rows_to_json | http_stream
   fi

   return 0
}

get_page_list_miners() {
   if ! [ -f "$STACKS_HEADERS_DB" ]; then
      http_404 "Stacks node not running on this host"
      return 2
   fi
   
   local FORMAT="$1"
   local LIMIT="$2"
   local PAGE="$3"
   local QUERY="ORDER BY stacks_block_height DESC"
   if [[ "$LIMIT" != "all" ]]; then
     local OFFSET=$((PAGE * LIMIT))
     QUERY="$QUERY LIMIT $LIMIT OFFSET $OFFSET"
   fi
   
   if [[ "$FORMAT" = "html" ]]; then 
      echo "<h3 id=\"stacks_miners\"><b>Stacks Block Miner History</b></h3>" | http_stream
      make_prev_next_buttons "/stacks/miners" "$PAGE" | http_stream
      query_stacks_block_miners "$QUERY" | \
         sed -r \
            -e 's/([0-9a-f]{64})$/<a href="\/stacks\/blocks\/\1">\1<\/a>/g' | \
         rows_to_table | \
         http_stream

   elif [[ "$FORMAT" = "json" ]]; then
      query_stacks_block_miners "$QUERY" | rows_to_json | http_stream
   fi

   return 0
}

get_page_list_mempool() {
   if ! [ -f "$STACKS_MEMPOOL_DB" ]; then
      http_404 "Stacks node not running on this host"
      return 2
   fi

   local FORMAT="html"
   local LIMIT="$2"
   local PAGE="$3"
   local QUERY="ORDER BY time DESC"
   if [[ "$LIMIT" != "all" ]]; then
     local OFFSET=$((PAGE * LIMIT))
     QUERY="$QUERY LIMIT $LIMIT OFFSET $OFFSET"
   fi
   
   if [[ "$FORMAT" = "html" ]]; then 
      echo "<h3 id=\"stacks_mempool\"><b>Node Mempool</b></h3>" | http_stream
      make_prev_next_buttons "/stacks/mempool" "$PAGE" | http_stream
      query_stacks_mempool "$QUERY" | \
         sed -r 's/([0-9a-f]{64})/<a href=\"\/stacks\/mempool_tx\/\1">\1<\/a>/g' | \
         rows_to_table | \
         http_stream

   elif [[ "$FORMAT" = "json" ]]; then 
      query_stacks_mempool "$QUERY" | rows_to_json | http_stream
   fi

   return 0
}

get_page_miner_power() {
   if ! [ -f "$STACKS_HEADERS_DB" ]; then
      http_404 "Stacks node not running on this host"
      return 2
   fi

   local FORMAT="$1"
   
   if [[ "$FORMAT" = "html" ]]; then
      echo "<h3 id=\"miner_power\"><b>Miner Power</b></h3>" | http_stream
      query_miner_power | rows_to_table | http_stream

   elif [[ "$FORMAT" = "json" ]]; then
      query_miner_power | rows_to_json | http_stream
   fi

   return 0
}

get_block_path() {
   local INDEX_BLOCK_HASH="$1"
   local PATH_SUFFIX="$(echo "$INDEX_BLOCK_HASH" | sed -r 's/^([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]+)$/\1\/\2\/\1\2\3/g')"
   echo "$STACKS_BLOCKS_ROOT/$PATH_SUFFIX"
   return 0
}

get_page_stacks_block() {
   if ! [ -f "$STACKS_STAGING_DB" ]; then 
      http_404 "Stacks node not running on ths host"
      return 2
   fi

   local FORMAT="$1"
   local INDEX_BLOCK_HASH="$2"
   local BLOCK_PATH="$(get_block_path "$INDEX_BLOCK_HASH")"
   
   if ! [ -f "$BLOCK_PATH" ]; then 
      http_404 "No such block: $INDEX_BLOCK_HASH"
      return 2
   fi

   if [[ "$(stat -c "%s" "$BLOCK_PATH")" = "0" ]]; then
      http_404 "Invalid block: $INDEX_BLOCK_HASH"
      return 2
   fi

   if [[ "$FORMAT" = "html" ]]; then
      http_page_begin
   elif [[ "$FORMAT" = "json" ]]; then
      http_json_begin
   fi

   local MINER_QUERY="WHERE index_block_hash = '$INDEX_BLOCK_HASH' AND miner = 1 LIMIT 1"
   local PARENT_QUERY="WHERE index_block_hash = '$INDEX_BLOCK_HASH' LIMIT 1"
   local HAS_BLOCK_PROCESSED="$(
      if [[ "$(query_stacks_miners "$MINER_QUERY" | wc -l)" = "0" ]]; then
         echo "0"
      else
         echo "1"
      fi
   )"

   local PARENT_BLOCK_PTR="$(
     query_stacks_block_ptrs "$PARENT_QUERY" | \
        rows_to_json | \
        jq -r '.[].parent_consensus_hash,.[].parent_anchored_block_hash' | ( \
           read PARENT_CONSENSUS_HASH
           read PARENT_BLOCK_HASH
           echo "$PARENT_CONSENSUS_HASH|$PARENT_BLOCK_HASH"
        )
     )"

   local PARENT_CONSENSUS_HASH="$(echo "$PARENT_BLOCK_PTR" | ( IFS="|" read PARENT_CONSENSUS_HASH UNUSED; echo "$PARENT_CONSENSUS_HASH" ))"
   local PARENT_BLOCK_HASH="$(echo "$PARENT_BLOCK_PTR" | ( IFS="|" read UNUSED PARENT_BLOCK_HASH; echo "$PARENT_BLOCK_HASH" ))"

   local PARENT_INDEX_BLOCK_HASH="$(
     echo "$PARENT_BLOCK_PTR" | ( \
        IFS="|" read PARENT_CONSENSUS_HASH PARENT_BLOCK_HASH
        make_index_block_hash "$PARENT_CONSENSUS_HASH" "$PARENT_BLOCK_HASH"
     ))"

   if [[ "$FORMAT" = "html" ]]; then
      query_stacks_miners "$MINER_QUERY" | ( \
            row_transpose "block_id" "$INDEX_BLOCK_HASH"
            echo "parent|<a href=\"/stacks/blocks/$PARENT_INDEX_BLOCK_HASH\">$PARENT_INDEX_BLOCK_HASH</a>"
            if [[ "$HAS_BLOCK_PROCESSED" = "0" ]]; then
                echo "parent_consensus_hash|$PARENT_CONSENSUS_HASH"
                echo "parent_block_hash|$PARENT_BLOCK_HASH"
            fi
         ) | \
         rows_to_table | \
         http_stream

   elif [[ "$FORMAT" = "json" ]]; then
      echo "{\"metadata\": " | http_stream
      query_stacks_miners "$MINER_QUERY" | \
         rows_to_json | \
         http_stream
      echo ", \"parent\": \"$PARENT_INDEX_BLOCK_HASH\", " | http_stream
      
      if [[ "$HAS_BLOCK_PROCESSED" = "0" ]]; then
         echo "\"parent_consensus_hash\": \"$PARENT_CONSENSUS_HASH\"," | http_stream
         echo "\"parent_block_hash\": \"$PARENT_BLOCK_HASH\"," | http_stream
      fi
   fi
   
   local BLOCK_JSON="$(/bin/cat "$BLOCK_PATH" | blockstack-cli decode-block - | jq)"
   local RAW_BLOCK="$(/bin/cat "$BLOCK_PATH" | xxd -ps -c 65536 | tr -d '\n')"
   
   if [[ "$FORMAT" = "html" ]]; then
      echo "<br><div style='font-family:\"Courier New\", Courier, monospace; font-size:80%'><b>Block</b><br><div style=\"white-space: pre-wrap;\">" | http_stream
      http_chunk "$BLOCK_JSON"
      echo "</div><br>" | http_stream
      
      echo "<div style='font-family:\"Courier New\", Courier, monospace; font-size:80%'><b>Raw block</b><br><div style=\"overflow-wrap: break-word;\"><br>" | http_stream
      http_chunk "$RAW_BLOCK"
      echo "</div>" | http_stream
      http_page_end

   elif [[ "$FORMAT" = "json" ]]; then
      echo "\"block\": " | http_stream
      http_chunk "$BLOCK_JSON"
      echo "}" | http_stream
      http_json_end
   fi
   
   return 0
}

get_page_mempool_tx() {
   if ! [ -f "$STACKS_MEMPOOL_DB" ]; then
      http_404 "Stacks node not running on this host"
      return 2
   fi

   local FORMAT="$1"
   local TXID="$2"
   local QUERY="WHERE txid = \"$TXID\" LIMIT 1"

   if [[ "$FORMAT" = "html" ]]; then
      query_stacks_mempool "$QUERY" | \
         row_transpose "txid" "$TXID" | \
         rows_to_table | \
         http_stream

   elif [[ "$FORMAT" = "json" ]]; then
      echo "{\"metadata\": " | http_stream
      query_stacks_mempool_tx "$QUERY" | \
         rows_to_json | \
         http_stream
      echo "," | http_stream
   fi
   
   local TX="$(query_stacks_mempool_tx "$TXID")"
   if [ -z "$TX" ]; then
      http_404 "No such transaction: $TXID"
      return 2
   fi

   local TXJSON="$(blockstack-cli decode-tx "$TX" | jq)"

   if [[ "$FORMAT" = "html" ]]; then
      echo "<br><div style='font-family:\"Courier New\", Courier, monospace; font-size:80%'><b>Transaction</b><br><div style=\"white-space: pre-wrap;\">" | http_stream
      http_chunk "$TXJSON"
      echo "</div><br>" | http_stream
      
      echo "<div style='font-family:\"Courier New\", Courier, monospace; font-size:80%'><b>Raw transaction</b><br><div style=\"overflow-wrap: break-word;\">" | http_stream
      http_chunk "$TX"
      echo "</div>" | http_stream

   elif [[ "$FORMAT" = "json" ]]; then
      echo "\"tx\": " | http_stream
      http_chunk "$TXJSON"
      echo ", \"raw_tx\": " | http_stream
      http_chunk "\"$TX\""
      echo "}" | http_stream
   fi

   return 0
}

post_sendbtc() {
   local ADDR
   if ! [ -f "$BITCOIN_CONF" ]; then
      http_404 "Bitcoind is not running on this host"
      return 2
   fi

   # format: address\n
   read ADDR
   if ! [[ $ADDR =~ ^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{27,35}$ ]]; then 
      http_401
      return 3
   fi

   TXID="$(bitcoin-cli -conf="$BITCOIN_CONF" sendtoaddress "$ADDR" "$FAUCET_AMOUNT" 2>&1)"
   if [ $? -ne 0 ]; then
      http_500 "$TXID"
      return 1
   fi

   ERR="$(bitcoin-cli -conf="$BITCOIN_CONF" importaddress "$ADDR" 2>&1)"
   if [ $? -ne 0 ]; then
      http_500 "$ERR"
      return 1
   fi

   http_200 ${#TXID} "text/plain"
   echo "$TXID"
   return 0
}

parse_request() {
   local REQLINE
   local VERB=""
   local REQPATH=""
   local CONTENT_TYPE=""
   local CONTENT_LENGTH=0

   while read REQLINE; do
      # trim trailing whitespace
      REQLINE="${REQLINE%"${REQLINE##*[![:space:]]}"}"
      if [ -z "$REQLINE" ]; then
         break
      fi

      # log "   reqline = '$REQLINE'"

      TOK="$(echo "$REQLINE" | egrep "GET|POST" | sed -r 's/^(GET|POST)[ ]+([^ ]+)[ ]+HTTP\/1.(0|1)$/\1 \2/g')"
      if [ -n "$TOK" ] && [ -z "$VERB" ] && [ -z "$REQPATH" ]; then 
         set -- $TOK
         VERB="$1"
         REQPATH="$2"
         continue
      fi

      TOK="$(echo "$REQLINE" | grep -i "content-type" | cut -d ' ' -f 2)"
      if [ -n "$TOK" ] && [ -z "$CONTENT_TYPE" ]; then
         CONTENT_TYPE="${TOK,,}"
         continue
      fi

      TOK="$(echo "$REQLINE" | grep -i "content-length" | cut -d ' ' -f 2)"
      if [ -n "$TOK" ] && [ $CONTENT_LENGTH -eq 0 ]; then
         if [[ "$TOK" =~ ^[0-9]+$ ]]; then
            CONTENT_LENGTH="$TOK"
            continue
         fi
      fi
   done

   if [ $CONTENT_LENGTH -gt $MAX_BODY_LENGTH ]; then 
      exit 1
   fi

   if [ -z "$VERB" ] || [ -z "$REQPATH" ]; then
      exit 1
   fi
   
   # log "   verb = '$VERB', reqpath = '$REQPATH', content-type = '$CONTENT_TYPE', content-length = '$CONTENT_LENGTH'"

   printf "$VERB\n$REQPATH\n$CONTENT_TYPE\n$CONTENT_LENGTH\n"
   dd bs=$CONTENT_LENGTH 2>/dev/null
   return 0
}

handle_request() {
   local VERB
   local REQPATH
   local CONTENT_TYPE
   local CONTENT_LENGTH
   local STATUS=200
   local RC=0

   read VERB
   read REQPATH
   read CONTENT_TYPE
   read CONTENT_LENGTH

   case "$VERB" in
      GET)
         case "$REQPATH" in
            /ping)
               get_ping
               if [ $? -ne 0 ]; then
                  STATUS=500
               fi
               ;;

            /bitcoin)
               get_bitcoin_ping
               RC=$?
               ;;

            /bitcoin/balance)
               get_balance
               RC=$?
               ;;

            /bitcoin/confirmations/*)
               local TXID="${REQPATH#/bitcoin/confirmations/}"
               if ! [[ "$TXID" =~ ^[0-9a-f]{64}$ ]]; then
                  http_401
                  STATUS=401
               else
                  get_confirmations "$TXID"
                  RC=$?
               fi
               ;;

            /bitcoin/utxos/*)
               local ADDR="${REQPATH#/bitcoin/utxos/}"
               if ! [[ "$ADDR" =~ ^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{27,35}$ ]]; then 
                  http_401
                  STATUS=401
               else
                  get_utxos "$ADDR"
                  RC=$?
               fi
               ;;

            /stacks/blocks/*)
               local INDEX_BLOCK_HASH="${REQPATH#/stacks/blocks/}"
               if ! [[ "$INDEX_BLOCK_HASH" =~ ^[0-9a-f]{64} ]]; then
                  http_401
                  STATUS=401
               else
                  get_page_stacks_block "html" "$INDEX_BLOCK_HASH"
                  RC=$?
               fi
               ;;

            /stacks/history/*)
               local PAGE="${REQPATH#/stacks/history/}"
               if ! [[ $PAGE =~ ^[0-9]+$ ]]; then
                  http_401
                  STATUS=401
               else
                  http_page_begin
                  get_page_list_stacks_blocks "html" 50 "$PAGE"
                  RC=$?
                  http_page_end
               fi
               ;;

            /stacks/sortitions/*)
               local PAGE="${REQPATH#/stacks/sortitions/}"
               if ! [[ $PAGE =~ ^[0-9]+$ ]]; then
                  http_401
                  STATUS=401
               else
                  http_page_begin
                  get_page_list_sortitions "html" 50 "$PAGE"
                  RC=$?
                  http_page_end
               fi
               ;;
            
            /stacks/miners/*)
               local PAGE="${REQPATH#/stacks/miners/}"
               if ! [[ $PAGE =~ ^[0-9]+$ ]]; then
                  http_401
                  STATUS=401
               else
                  http_page_begin
                  get_page_list_miners "html" 50 "$PAGE"
                  RC=$?
                  http_page_end
               fi
               ;;

            /stacks/mempool/*)
               local PAGE="${REQPATH#/stacks/mempool/}"
               if ! [[ $PAGE =~ ^[0-9]+$ ]]; then
                  http_401
                  STATUS=401
               else
                  http_page_begin
                  get_page_list_mempool "html" 50 "$PAGE"
                  RC=$?
                  http_page_end
               fi
               ;;

            /stacks/mempool_tx/*)
               local TXID="${REQPATH#/stacks/mempool_tx/}"
               if ! [[ $TXID =~ ^[0-9a-f]{64}$ ]]; then
                  http_401
                  STATUS=401
               else
                  http_page_begin
                  get_page_mempool_tx "html" "$TXID"
                  RC=$?
                  http_page_end
               fi
               ;;
            
            /|/index.html)
               http_page_begin
               printf "%s\n%s\n%s\n%s\n%s\n" \
                  "stacks_history|Stacks Blockchain History" \
                  "stacks_sortitions|Sortition History" \
                  "stacks_miners|Stacks Block Miner History" \
                  "miner_power|Stacks Miner Power" \
                  "stacks_mempool|Node Mempool" | \
                  print_table_of_contents | http_stream
               get_page_list_stacks_blocks "html" 50 0
               get_page_list_sortitions "html" 50 0
               get_page_list_miners "html" 50 0
               get_page_miner_power "html"
               get_page_list_mempool "html" 50 0
               http_page_end
               ;;

            /api/blocks/*)
               local INDEX_BLOCK_HASH="${REQPATH#/api/blocks/}"
               if ! [[ "$INDEX_BLOCK_HASH" =~ ^[0-9a-f]{64} ]]; then
                  http_401
                  STATUS=401
               else
                  get_page_stacks_block "json" "$INDEX_BLOCK_HASH"
               fi
               ;;

            /api/history)
               http_json_begin
               get_page_list_stacks_blocks "json" "all" "all"
               RC=$?
               http_json_end
               ;;

            /api/sortitions)
               http_json_begin
               get_page_list_sortitions "json" "all" "all"
               RC=$?
               http_json_end
               ;;
            
            /api/miners)
               http_json_begin
               get_page_list_miners "json" "all" "all"
               RC=$?
               http_json_end
               ;;

            /api/miner_power)
               http_json_begin
               get_page_miner_power "json"
               RC=$?
               http_json_end
               ;;

            /api/mempool)
               http_json_begin
               get_page_list_mempool "json" "all" "all"
               RC=$?
               http_json_end
               ;;

            /api/mempool_tx/*)
               local TXID="${REQPATH#/api/mempool_tx/}"
               if ! [[ $TXID =~ ^[0-9a-f]{64}$ ]]; then
                  http_401
                  STATUS=401
               else
                  http_page_begin
                  get_page_mempool_tx "json" "$TXID"
                  RC=$?
                  http_page_end
               fi
               ;;
            *)
               http_404 "No such page $REQPATH"
               STATUS=404
               ;;
         esac
         ;;
      POST)
         case "$REQPATH" in
            /bitcoin/fund)
               if [ "$CONTENT_TYPE" != "text/plain" ]; then
                  http_401
                  STATUS=401
               else
                  post_sendbtc
                  if [ $? -eq 1 ]; then
                     STATUS=500
                  elif [ $? -eq 2 ]; then
                     STATUS=404
                  elif [ $? -eq 3 ]; then
                     STATUS=401
                  fi
               fi
               ;;
            *)
               http_404 "No such page $REQPATH"
               STATUS=404
               ;;
         esac
         ;;
      *)
         http_401
         STATUS=404
         ;;
   esac

   if [ $STATUS -eq 200 ]; then
      if [ $RC -eq 1 ]; then
         STATUS=500
      elif [ $RC -eq 2 ]; then
         STATUS=404
      fi
   fi

   if [[ "$MODE" = "serve" ]]; then
       log "[$(date +%s)] $VERB $REQPATH ($CONTENT_LENGTH bytes) - $STATUS"
   fi
}

usage() {
   exit_error "Usage:\n   $0 serve </path/to/bitcoin.conf> </path/to/stacks/chainstate>\n   $0 report </path/to/bitcoin.conf> </path/to/stacks/chainstate> <report-name>\n   $0 <port> </path/to/bitcoin.conf> </path/to/stacks/chainstate>\n"
}

if [ -z "$MODE" ] || [ -z "$BITCOIN_CONF" ]; then
   usage
fi

if [ "$MODE" = "serve" ]; then
   parse_request | handle_request
   exit 0
elif [ "$MODE" = "report" ]; then
   REPORT_PATH="$4"
   REPORT_MODE="text"
   printf "GET $REPORT_PATH HTTP/1.0\r\n\r\n" | parse_request | handle_request
   exit 0
elif [ "$MODE" = "parse" ]; then 
   # undocumented test mode
   parse_request
   exit 0
elif [ "$MODE" = "test" ]; then
   # undocumented test mode
   shift 3
   echo "$@"
   eval "$@"
   exit 0
fi

# $MODE will be the port number in this usage path
if ! [[ $MODE =~ ^[0-9]+$ ]]; then
   usage
fi

exec ncat -k -l -p "$MODE" -c "$BASH \"$0\" serve \"$BITCOIN_CONF\" \"$STACKS_WORKING_DIR\""
