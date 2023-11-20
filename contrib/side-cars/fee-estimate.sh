#!/bin/bash

####################################
# Usage
# 
# $ # one-shot fee-rate calculation
# $ ./fee-estimate.sh
# 161
# 
# $ # Check fees every 5 seconds and update `satoshis_per_byte` in `/path/to/miner.toml`
# $ ./fee-estimate.sh watch /path/to/miner.toml 5
# 
# $ # Run unit tests and report result (0 means success)
# $ ./fee-estimate.sh test; echo $?
# 0
####################################

set -uoe pipefail

function exit_error() {
   echo >&2 "$@"
   exit 1
}

####################################
# Dependencies
####################################
for cmd in curl jq bc sed date grep head tail; do
   command -v "$cmd" >/dev/null 2>&1 || exit_error "Command not found: '$cmd'"
done


####################################
# Functions
####################################

# Convert a fee/kb to fee/vbyte.
# If there's a fractional part of the fee/kb (i.e. if it's not divisible by 1000),
# then round up.
# Arguments:
#   $1 -- the fee per kb
# Stdout: the satoshis per vbyte, as an integer
# Stderr: none
# Return:
#   0 on success
#   nonzero on error
function fee_per_kb_to_fee_per_vbyte() {
   local fee_per_kb="$1"
   local fee_per_vbyte_float=
   local fee_per_vbyte_ipart=
   local fee_per_vbyte_fpart=
   local fee_per_vbyte=

   # must be an integer
   if ! [[ "$fee_per_kb" =~ ^[0-9]+$ ]]; then
      return 1
   fi

   # NOTE: round up -- get the fractional part, and if it's anything other than 000, then add 1
   fee_per_vbyte_float="$(echo "scale=3; $fee_per_kb / 1000" | bc)"
   fee_per_vbyte_ipart="$(echo "$fee_per_vbyte_float" | sed -r 's/^([0-9]*)\..+$/\1/g')"
   fee_per_vbyte_fpart="$(echo "$fee_per_vbyte_float" | sed -r -e 's/.+\.([0-9]+)$/\1/g' -e 's/0//g')"
   fee_per_vbyte="$fee_per_vbyte_ipart"
   if [ -n "$fee_per_vbyte_fpart" ]; then
      fee_per_vbyte="$((fee_per_vbyte + 1))"
   fi

   echo "$fee_per_vbyte"
   return 0
}

# Query the endpoint and log HTTP errors gracefully 
# Arguments:
#   $1 endpoint to query
# Stdout: the HTTP response body
# Stderr: an error message, if we failed to query
# Return:
#   0 on success
#   nonzero on error
function query_fee_endpoint() {
   local fee_endpoint="$1"
   local response=
   local http_status_code=

   response="$(curl -sL -w "\n%{http_code}" "$fee_endpoint" || true)";
   http_status_code="$(echo "$response" | tail -n 1)";
   case $http_status_code in 
      200)
         ;;
      429)
         echo >&2 "WARN[$(date +%s)]: 429 Rate-Limited retreiving ${fee_endpoint}"
         return 1
         ;;
      404)
         echo >&2 "WARN[$(date +%s)]: 404 Not Found retrieving ${fee_endpoint}"
         return 1
         ;;
      **)
         echo >&2 "WARN[$(date +%s)]: ${http_status_code} Error retrieving ${fee_endpoint}"
         return 1
         ;;
   esac
   echo "$response" | head -n -1
   return 0
}

# Determine satoshis per vbyte
# Arguments: none
# Stdout: the satoshis per vbyte, as an integer
# Stderr: none
# Return:
#   0 on success
#   nonzero on error
function get_sats_per_vbyte() {
   local fee_endpoint="https://api.blockcypher.com/v1/btc/main"
   local fee_per_kb=

   fee_per_kb="$(query_fee_endpoint "$fee_endpoint" | jq -r '.high_fee_per_kb')"
   if ! fee_per_kb_to_fee_per_vbyte "$fee_per_kb"; then
      return 1
   fi
   return 0
}

# Update the fee rate in the config file.
# Arguments:
#   $1 -- path to the config file
#   $2 -- new fee to write
# Stdout: (none)
# Stderr: (none)
# Returns:
#   0 on success
#   nonzero on error
function update_fee() {
   local config_path="$1"
   local fee="$2"
   sed -i -r "s/satoshis_per_byte[ \t]+=.*$/satoshis_per_byte = ${fee}/g" "$config_path"
   return 0
}

# Poll fees every so often, and update a config file.
# Runs indefinitely.
# If the fee estimator endpoint cannot be reached, then the file is not modified.
# Arguments:
#   $1 -- path to file to watch
#   $2 -- interval at which to poll, in seconds
# Stdout: (none)
# Stderr: (none)
# Returns: (none)
function watch_fees() {
   local config_path="$1"
   local interval="$2"

   local fee=
   local rc=

   while true; do
      # allow poll command to fail without killing the script
      set +e
      fee="$(get_sats_per_vbyte)"
      rc="$?"
      set -e

      if [ $rc -ne 0 ]; then
         echo >&2 "WARN[$(date +%s)]: failed to poll fees"
      else
         update_fee "$config_path" "$fee"
      fi
      sleep "$interval"
   done
}

# Unit tests
function unit_test() {
   local test_config="/tmp/test-miner-config-$$.toml"
   if [ "$(fee_per_kb_to_fee_per_vbyte 1000)" != "1" ]; then
      exit_error "failed -- 1000 sats/kbyte != 1 sats/vbyte"
   fi

   if [ "$(fee_per_kb_to_fee_per_vbyte 1001)" != "2" ]; then
      exit_error "failed -- 1001 sats/vbyte != 2 sats/vbyte"
   fi

   if [ "$(fee_per_kb_to_fee_per_vbyte 999)" != "1" ]; then 
      exit_error "failed -- 999 sats/vbyte != 1 sats/vbyte"
   fi

   echo "satoshis_per_byte = 123" > "$test_config"
   update_fee "$test_config" "456"
   if ! grep 'satoshis_per_byte = 456' >/dev/null "$test_config"; then
      exit_error "failed -- did not update satoshis_per_byte"
   fi
  
   echo "" > "$test_config"
   update_fee "$test_config" "456"
   if grep "satoshis_per_byte" "$test_config" >/dev/null; then
      exit_error "failed -- updated satoshis_per_byte in a config file without it"
   fi

   rm "$test_config"
   return 0
}

####################################
# Entry point
####################################

# Main body
# Arguments
#   $1: mode of operation.  Can be "test" or empty
# Stdout: the fee rate, in sats/vbte
# Stderr: None
# Return: (no return)
function main() {
   local mode="$1"
   local config_path=
   local interval=

   case "$mode" in
      "test")
         # run unit tests
         echo "Run unit tests"
         unit_test
         exit 0
         ;;
      "watch")
         # watch and update the file
         if (( $# < 3 )); then
            exit_error "Usage: $0 watch /path/to/miner.toml interval_in_seconds"
         fi
         
         config_path="$2"
         interval="$3"

         if ! [ -f "$config_path" ]; then 
            exit_error "No such config file: ${config_path}"
         fi

         watch_fees "$config_path" "$interval"
         ;;

      "")
         # one-shot
         get_sats_per_vbyte
         ;;
   esac
   exit 0
}

if (( $# > 0 )); then
   # got arguments
   main "$@"
else
   # no arguments
   main ""
fi
