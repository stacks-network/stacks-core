#!/bin/bash
# source after $__BIN/start.sh

check_chain_quality() {
    local EXPECTED_SORTITION_FRACTION="$1"
    local EXPECTED_FORK_FRACTION="$2"
    local EXPECTED_NUM_BLOCKS="$3"

    local TOTAL_BLOCKS="$(report "/api/miners" | jq -r ".[].height" | wc -l)"
    local CHAIN_HEIGHT="$(report "/api/miners" | jq -r ".[].height" | head -n 1)"

    local TOTAL_SORTITIONS="$(report "/api/sortitions" | jq -r '.[].height' | head -n 1)"
    
    # find first non-empty sortition 
    local LAST_EMPTY_SORTITION="$(report "/api/sortitions" | jq -r '.[] | select(.index_block_hash == "0000000000000000000000000000000000000000000000000000000000000000") | .height' | head -n 1)"
    local FIRST_SORTITION_HEIGHT="$((LAST_EMPTY_SORTITION + 1))"

    # enough burn blocks had a sortition once mining began
    local EMPTY_SORTITIONS="$(
        report "/api/sortitions" | \
        jq -r '.[] | {height: (.height)|tonumber, index_block_hash: (.index_block_hash)} | select(.height >= '$FIRST_SORTITION_HEIGHT') | select(.index_block_hash == "0000000000000000000000000000000000000000000000000000000000000000")' | \
        wc -l
    )"

    local SORTITION_FRACTION=$(( (TOTAL_SORTITIONS - EMPTY_SORTITIONS) * 100 / TOTAL_SORTITIONS ))
    if (( $SORTITION_FRACTION < $EXPECTED_SORTITION_FRACTION )); then
       echo >&2 "Resulting chain has $SORTITION_FRACTION percent sortitions"
       return 1
    fi
    
    # enough blocks were mined
    if (( $TOTAL_BLOCKS < $EXPECTED_NUM_BLOCKS )); then
       echo >&2 "Resulting chain only has $TOTAL_BLOCKS blocks"
       return 1
    fi

    local FORK_FRACTION=$((CHAIN_HEIGHT * 100 / TOTAL_BLOCKS))

    # enough blocks were on the same fork
    if (( $FORK_FRACTION < $EXPECTED_FORK_FRACTION )); then
       echo >&2 "Only $FORK_FRACTION percent of blocks were mined on the same fork"
       return 1
    fi

    return 0
}

# reads tx from stdin
send_tx() {
   local STACKS_NODE_URL="$1"

   exec 3>&1
   
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

get_unconfirmed_chain_tip() {
   local STACKS_NODE_URL="$1"
   local TIP="$(curl -sf "$STACKS_NODE_URL"/v2/info | jq -r '.unanchored_tip' 2>&1)"
   local RC=$?

   if [ $RC -ne 0 ]; then 
      logln "Failed to query unconfirmed chain tip on node $STACKS_NODE_URL: curl exited with code $RC"
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

get_unconfirmed_account_nonce() {
   local STACKS_NODE_URL="$1"
   local ADDR="$2"
   local UNCONFIRMED_TIP="$(get_unconfirmed_chain_tip "$STACKS_NODE_URL")"
   local RC=$?
   if [ $RC -ne 0 ]; then
      logln "Failed to query unconfirmed tip at $STACKS_NODE_URL: curl exited with code $RC"
      return 1
   fi

   local URL="$STACKS_NODE_URL/v2/accounts/$ADDR?proof=0"
   if [[ "$UNCONFIRMED_TIP" != "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
      # have microblocks applied
      URL="$URL&tip=$UNCONFIRMED_TIP"
   fi

   local NONCE="$(curl -sf "$URL" | jq -r '.nonce')"
   RC=$?

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

easy_token_transfer() {
   local STACKS_NODE_URL="$1"
   local PRIVKEY="$2"
   local DEST="$3"
   local AMOUNT="$4"
   shift 4
   local OPTS="$@"
   local FEE_RATE=300

   local ADDR="$(blockstack-cli --testnet addresses "$PRIVKEY" | jq -r '.STX')"
   local NONCE="$(get_unconfirmed_account_nonce "$STACKS_NODE_URL" "$ADDR")"
   local RC=$?
   if [ $RC -ne 0 ] || [ -z "$NONCE" ]; then
      logln "Failed to query unconfirmed account nonce: rc '$RC' nonce '$NONCE'"
      return 1
   fi

   local MEMO="test $NONCE"
   logln "blockstack-cli --testnet token-transfer '$PRIVKEY' '$FEE_RATE' '$NONCE' '$DEST' '$AMOUNT' '$MEMO' '$OPTS'"
   local TX="$(blockstack-cli --testnet token-transfer "$PRIVKEY" "$FEE_RATE" "$NONCE" "$DEST" "$AMOUNT" "$MEMO" "$OPTS" 2>&1)"
   RC=$?
   if [ $RC -ne 0 ]; then 
      logln "Failed to generate tx: blockstack-cli --testnet token-transfer $PRIVKEY $FEE_RATE $NONCE $DEST $AMOUNT \"$MEMO\""
      return 1
   fi

   logln "Generated tx: $TX"
   printf "$TX"
   return 0
}
