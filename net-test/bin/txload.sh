#!/usr/bin/env bash

FEE_RATE=300
MAX_CHAINING=25
CONFIRMATIONS=1

exit_error() {
   printf "$1"
   exit 1
}

for CMD in cut grep egrep sed blockstack-cli curl; do
   which "$CMD" >/dev/null 2>&1 || exit_error "Missing command $CMD"
done

if [ $(echo ${BASH_VERSION} | cut -d '.' -f 1) -lt 4 ]; then
   exit_error "This script requires Bash 4.x or higher"
fi

# grab fd 3 for curl
exec 3>&1

usage() {
   exit_error "$0 <private-key-hex> <stacks-url> <num-txs>\n"
}

MAIN_PRIVATE_KEY="$1"
STACKS_NODE_URL="$2"
NUM_TXS="$3"

if [ -z "$MAIN_PRIVATE_KEY" ] || [ -z "$STACKS_NODE_URL" ] || [ -z "$NUM_TXS" ]; then 
   usage
fi

set -uo pipefail

function log() {
   printf "%s" "$1" >&2
}

function logln() {
   printf "%s\n" "$1" >&2
}

make_token_transfer() {
   local PRIVKEY="$1"
   local NONCE="$2"
   local DEST="$3"
   local AMOUNT="$4"
   local MEMO="load test $NONCE"
   local TX="$(blockstack-cli --testnet token-transfer "$PRIVKEY" "$FEE_RATE" "$NONCE" "$DEST" "$AMOUNT" "$MEMO" 2>&1)"
   local RC=$?
   if [ $RC -ne 0 ]; then 
      logln "Failed to generate tx: blockstack-cli --testnet token-transfer $PRIVKEY $FEE_RATE $NONCE $DEST $AMOUNT \"$MEMO\""
      return 1
   fi

   printf "$TX"
   return 0
}

send_tx() {
   local STACKS_NODE_URL="$1"

   read TX
   TXID="$(printf "$TX" | \
      xxd -r -p | \
      curl -s -X POST --data-binary @- -w "%{http_code}" -o >(cat >&3) -H "content-type: application/octet-stream" "$STACKS_NODE_URL"/v2/transactions 2>&1 | ( \
        read HTTP_CODE
        read BODY
        if [ $HTTP_CODE -ne 200 ]; then 
           logln "Failed to send to node $STACKS_NODE_URL: server replied $HTTP_CODE. Tx was $TX"
           logln "Error text: $BODY"
           return 1
        fi
        echo "$BODY"
   ))"

   local RC=$?
   if [ $RC -ne 0 ]; then 
      return 1
   fi

   echo "$TXID"
   return 0
}

get_chain_tip() {
   local STACKS_NODE_URL="$1"
   local TIP="$(curl -sf "$STACKS_NODE_URL"/v2/info | jq -r '.stacks_tip' 2>&1)"
   local RC=$?

   if [ $RC -ne 0 ]; then 
      logln "Failed to query chain tip on node $STACKS_NODE_URL: curl exited with code $RC"
      return 1
   fi

   echo "$TIP"
   return 0
}

get_account_nonce() {
   local STACKS_NODE_URL="$1"
   local ADDR="$2"
   local NONCE="$(curl -sf "$STACKS_NODE_URL"/v2/accounts/"$ADDR""?proof=0" | jq -r '.nonce')"
   local RC=$?

   if [ $RC -ne 0 ]; then 
      logln "Failed to query account $ADDR on node $STACKS_NODE_URL: curl exited with code $RC"
      return 1
   fi

   echo "$NONCE"
   return 0
}

wait_for_new_stacks_block() {
   local TIP="$1"
   local STACKS_NODE_URL="$2"
   while true; do 
       local CUR_TIP="$(get_chain_tip "$STACKS_NODE_URL")"
       local RC=$?
       if [ $RC -ne 0 ]; then 
          return 1
       fi

       if [[ "$CUR_TIP" != "$TIP" ]]; then
          echo "$CUR_TIP"
          return 0
       fi
       
       sleep 5
    done
}

wait_for_confirmations() {
   local CONFS=$1
   local STACKS_NODE_URL="$2"
   local TIP="$(get_chain_tip "$STACKS_NODE_URL")"

   local CONF=0
   for CONF in $(seq 0 $CONFS); do
      TIP="$(wait_for_new_stacks_block "$TIP" "$STACKS_NODE_URL")"
      RC=$?

      if [ $RC -ne 0 ]; then 
         return 1
      fi
   done

   echo "$TIP"
   return 0
}

fund_keys() {
   local MAIN_PRIVKEY="$1"
   local AMOUNT="$2"
   local STACKS_NODE_URL="$3"

   local MAIN_ADDR="$(blockstack-cli --testnet addresses "$MAIN_PRIVKEY" | jq -r '.STX')"
   local RC=$?
   if [ $RC -ne 0 ]; then 
      logln "Failed to generate address for \"$MAIN_PRIVKEY\""
      return 1
   fi

   local MAIN_NONCE="$(get_account_nonce "$STACKS_NODE_URL" "$MAIN_ADDR")"
   RC=$?
   if [ $RC -ne 0 ]; then 
      return 1
   fi

   local NEXT_PRIVKEY=""
   local CHAIN_TIP="$(get_chain_tip "$STACKS_NODE_URL")"
   local TX_COUNT=0

   while read NEXT_PRIVKEY; do
      local ADDR="$(blockstack-cli --testnet addresses "$NEXT_PRIVKEY" | jq -r '.STX')"
      RC=$?

      if [ $RC -ne 0 ]; then 
         logln "Failed to generate address for \"$NEXT_PRIVKEY\""
         return 1
      fi

      log "Funding $NEXT_PRIVKEY ($ADDR) with $AMOUNT uSTX as tx #$MAIN_NONCE..."
      TXID="$(make_token_transfer "$MAIN_PRIVKEY" "$MAIN_NONCE" "$ADDR" "$AMOUNT" | send_tx "$STACKS_NODE_URL")"
      RC=$?

      if [ $RC -ne 0 ]; then 
         logln "FAILED!"
         logln "Failed to send fund-load token-transfer to $NEXT_PRIVKEY ($ADDR)"
         return 1
      fi
      logln " ok"
      echo "$NEXT_PRIVKEY"

      MAIN_NONCE=$((MAIN_NONCE + 1))
      TX_COUNT=$((TX_COUNT + 1))
      if (( $TX_COUNT >= $MAX_CHAINING )); then 
         while true; do
            log "Wait for at least $CONFIRMATIONS new Stacks blocks after $CHAIN_TIP..."
            CHAIN_TIP="$(wait_for_confirmations $CONFIRMATIONS "$STACKS_NODE_URL")"
            RC=$?

            if [ $RC -ne 0 ]; then 
               logln "FAILED"
               return 1
            fi
            logln "ok"

            TX_COUNT=0

            # wait for blockchain to catch up with us
            local CUR_NONCE="$(get_account_nonce "$STACKS_NODE_URL" "$MAIN_ADDR")"
            if [ $RC -ne 0 ]; then 
               return 1
            fi
            if (( $CUR_NONCE >= $MAIN_NONCE )); then
               MAIN_NONCE=$CUR_NONCE
               break
            else
               logln "Current nonce of fund key is $CUR_NONCE; need to wait until it is $MAIN_NONCE"
            fi
         done
      fi
   done

   return 0
}

get_addrs_and_nonces() {
   local NEXT_PRIVKEY=""
   local STACKS_NODE_URL="$1" 
   while read NEXT_PRIVKEY; do
      local ADDR="$(blockstack-cli --testnet addresses "$NEXT_PRIVKEY" | jq -r '.STX')"
      RC=$?

      if [ $RC -ne 0 ]; then 
         logln "Failed to generate address for \"$NEXT_PRIVKEY\""
         return 1
      fi

      NONCE="$(get_account_nonce "$STACKS_NODE_URL" "$ADDR")"
      if [ $RC -ne 0 ]; then 
         return 1
      fi

      echo "$NEXT_PRIVKEY $ADDR $NONCE"
   done

   return 0
}

tx_load() {
   local DEST="$1"
   local AMOUNT="$2"
   local STACKS_NODE_URL="$3"

   local NEXT_PRIVKEY=""
   local RC=0
   local NONCE=0

   while read NEXT_PRIVKEY_ADDR_NONCE; do
      set -- $NEXT_PRIVKEY_ADDR_NONCE
      NEXT_PRIVKEY="$1"
      ADDR="$2"
      NONCE="$3"

      log "Send $AMOUNT uSTX from $NEXT_PRIVKEY ($ADDR) to $DEST as tx #$NONCE..."
      TXID="$(make_token_transfer "$NEXT_PRIVKEY" "$NONCE" "$DEST" "$AMOUNT" | send_tx "$STACKS_NODE_URL")"
      RC=$?

      if [ $RC -ne 0 ]; then 
         logln "FAILED!"
         logln "Failed to send tx-load token-transfer from $NEXT_PRIVKEY ($ADDR) to $DEST"
         return 1
      fi
      logln " ok"
   done

   return 0
}

generate_keys() {
   local NUM_KEYS="$1"
   local CNT=0
   for CNT in $(seq 1 $NUM_KEYS); do
      local PRIVKEY="$(blockstack-cli --testnet generate-sk | jq -r '.secretKey')"
      RC=$?

      if [ $RC -ne 0 ]; then 
         logln "Failed to generate private key"
         return 1
      fi

      echo "$PRIVKEY"
   done
   return 0
}

DEST_ADDR="$(blockstack-cli --testnet generate-sk | jq -r '.secretKey,.stacksAddress' | ( \
   read DEST_PRIVKEY
   read DEST_ADDR
   logln "Destination private key: $DEST_PRIVKEY ($DEST_ADDR)"
   echo "$DEST_ADDR"
))"

AMOUNT=1

generate_keys "$NUM_TXS" | \
   fund_keys "$MAIN_PRIVATE_KEY" "$((AMOUNT + FEE_RATE))" "$STACKS_NODE_URL" \
   > /tmp/tx-load.keys

logln "Waiting for $CONFIRMATIONS confirmations before beginning"
TIP="$(wait_for_confirmations $CONFIRMATIONS "$STACKS_NODE_URL")"
RC=$?

if [ $RC -ne 0 ]; then 
    logln "FAILED"
    exit 1
fi

cat /tmp/tx-load.keys | \
   get_addrs_and_nonces "$STACKS_NODE_URL" | \
   tx_load "$DEST_ADDR" "$AMOUNT" "$STACKS_NODE_URL"

exit $?
