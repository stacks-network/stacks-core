#!/usr/bin/env bash

# Yup, it's a faucet HTTP server written in bash.  This is what my life has come to.

MAX_BODY_LENGTH=65536
FAUCET_AMOUNT="1.0"

MODE="$1"
BITCOIN_CONF="$2"

exit_error() {
   printf "$1" >&2
   exit 1
}

for cmd in ncat bitcoin-cli egrep grep tr dd sed cut date; do
   which $cmd >/dev/null 2>&1 || exit_error "Missing command: $cmd"
done

if [ $(echo ${BASH_VERSION} | cut -d '.' -f 1) -lt 4 ]; then
   exit_error "This script requires Bash 4.x or higher"
fi

set -uo pipefail

log() {
   printf >&2 "%s\n" "$1"
}

http_ok() {
   local CONTENT_LENGTH
   local CONTENT_TYPE

   CONTENT_LENGTH=$1
   CONTENT_TYPE=$2
   printf "HTTP/1.0 200 OK\r\nContent-Length: $CONTENT_LENGTH\r\nContent-Type: $CONTENT_TYPE\r\n\r\n"
}

http_401() {
   printf "HTTP/1.0 401 Unsupported Method\r\n\r\n"
}

http_500() {
   local ERR="$1"
   local ERR_LEN=${#ERR}
   log "500 error: ${ERR}"
   printf "HTTP/1.0 500 Internal Server error\r\nContent-Length: $ERR_LEN\r\nContent-Type: text/plain\r\n\r\n$ERR"
}

http_404() {
   printf "HTTP/1.0 404 Not Found\r\n\r\n"
}

get_ping() {
   http_ok 5 "text/plain"
   printf "alive"
   return 0
}

get_bitcoin_ping() {
   bitcoin-cli -conf="$BITCOIN_CONF" ping >/dev/null 2>&1
   if [ $? -eq 0 ]; then 
      local MSG="Bitcoind appears to be running"
      http_ok ${#MSG} "text/plain"
      echo "$MSG"
      return 0
   else
      http_500 "Bitcoind appears to be stopped"
      return 1
   fi
}

get_balance() {
   BALANCE="$(bitcoin-cli -conf="$BITCOIN_CONF" getbalance 2>&1)"
   if [ $? -eq 0 ]; then
      http_ok "${#BALANCE}" "text/plain"
      echo "$BALANCE"
      return 0
   else
      http_500 "$BALANCE"
      return 1
   fi
}

get_utxos() {
   local ADDR="$1"
   UTXOS="$(bitcoin-cli -conf="$BITCOIN_CONF" listunspent 1 1000000 "[\"$ADDR\"]" 2>&1)"
   if [ $? -eq 0 ]; then 
      http_ok ${#UTXOS} "application/json"
      echo "$UTXOS"
      return 0
   else
      http_500 "$UTXOS"
      return 1
   fi
}

get_confirmations() {
   local TXID="$1"
   CONFIRMATIONS="$(bitcoin-cli -conf="$BITCOIN_CONF" gettransaction "$TXID" | jq -r '.confirmations')"
   RC=$?
   if [ $RC -eq 0 ]; then 
      http_ok ${#CONFIRMATIONS} "text/plain"
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

post_sendbtc() {
   local ADDR

   # format: address\n
   read ADDR
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

   http_ok ${#TXID} "text/plain"
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
               if [ $? -ne 0 ]; then
                  STATUS=500
               fi
               ;;

            /balance)
               get_balance
               if [ $? -ne 0 ]; then
                  STATUS=500
               fi
               ;;

            /confirmations/*)
               TXID="${REQPATH#/confirmations/}"
               get_confirmations "$TXID"
               if [ $? -eq 1 ]; then
                  STATUS=500
               elif [ $? -eq 2 ]; then
                  STATUS=404
               fi
               ;;

            /utxos/*)
               ADDR="${REQPATH#/utxos/}"
               get_utxos "$ADDR"
               if [ $? -ne 0 ]; then
                  STATUS=500
               fi
               ;;
            *)
               http_404
               STATUS=404
               ;;
         esac
         ;;
      POST)
         case "$REQPATH" in
            /fund)
               if [ "$CONTENT_TYPE" != "text/plain" ]; then
                  http_401
                  STATUS=401
               else
                  post_sendbtc
                  if [ $? -ne 0 ]; then
                     STATUS=500
                  fi
               fi
               ;;
            *)
               http_404
               STATUS=404
               ;;
         esac
         ;;
      *)
         http_401
         STATUS=404
         ;;
   esac

   log "[$(date +%s)] $VERB $REQPATH ($CONTENT_LENGTH bytes) - $STATUS"
}

usage() {
   exit_error "Usage:\n   $0 serve </path/to/bitcoin.conf>\n   $0 <port> </path/to/bitcoin.conf>\n"
}

if [ -z "$MODE" ] || [ -z "$BITCOIN_CONF" ]; then
   usage
fi

if [ "$MODE" = "serve" ]; then
   parse_request | handle_request
   exit 0
elif [ "$MODE" = "parse" ]; then 
   # undocumented test mode
   parse_request
   exit 0
fi

# $MODE will be the port number in this usage path
if ! [[ $MODE =~ ^[0-9]+$ ]]; then
   usage
fi

exec ncat -k -l -p "$MODE" -c "$BASH \"$0\" serve \"$BITCOIN_CONF\""
