#!/bin/bash

###################################################################
# You need to edit the variables below to configure your namespace!
# The price curve here is the one for `.id`.
###################################################################

# Namespace version
# 1 == "burn all BTC for name registrations and renewals"
# 2 == "send BTC for name registrations and renewals to your PAYMENT_KEY for the first year"
# 3 == "name prices are in STACKs, not BTC; burn all name registrations and renewals"
NAMESPACE_VERSION=1

# Name lifetime
# Values here are multiplied by 2 internally.
# e.g. NAMESPACE_LIFETIME=1000 means "names last 2000 blocks before expiring"
# If you want infinite lives, pass -1
NAMESPACE_LIFETIME=52595    # 2 years

#############################################################################################################################################################
# Namespace prices are calculated as a function of the name itself (excluding the namespace identifier) with this formula:
#
#                                                                                               NAMESPACE_BUCKETS[min(name.length, 16) - 1]
#                                                        NAMESPACE_COEFFICIENT * NAMESPACE_BASE
# price(name) = NAME_UNIT_COST * -------------------------------------------------------------------------------------------------------------------------
#                                  10 * max(has_nonalpha(name) ? NAMESPACE_NONALPHA_DISCOUNT : 1, has_no_vowels(name) ? NAMESPACE_NOVOWEL_DISCOUNT : 1)
#
# where NAME_UNIT_COST is 100 satoshis or 1733 microStacks (depending on how names are paid for)
#
# Example:  In .id, we have the following:
#                                 1
#                          250 * 4
# price(judecn) = 100 * --------------- = 10000 satoshis
#                       10 * max(1,1)
#
#                           6
#                    250 * 4
# price(a) = 100 * ------------- = 10240000 satoshis
#                  10 * max(1,1)
#
#                             5
#                      250 * 4
# price(a1) = 100 * -------------- = 640000 satoshis
#                   10 * max(4,1)
#
#
# You can confirm manually with `blockstack-cli price`
#############################################################################################################################################################

# The following price parameters are taken from the .id namespace on mainnet.

# Price multiplicative coefficient.
# between 0 and 255.
NAMESPACE_COEFFICIENT=250

# Price exponential base.
# between 0 and 255.
NAMESPACE_BASE=4

# Price exponent buckets
# 16 values, between 0 and 15
NAMESPACE_BUCKETS="6,5,4,3,2,1,0,0,0,0,0,0,0,0,0,0"

# Discount to be applied to a name's price if it has a non-alpha character.
# The price is *divided* by this value.
# Can be between 1 and 15.
NAMESPACE_NONALPHA_DISCOUNT=4      # names are 1/4th the price if they have numbers or punctuation

# Discount to be applied to a name's price if it does not have a vowel.
# The price is *divided* by this value.
# Can be between 1 and 15.
NAMESPACE_NOVOWEL_DISCOUNT=4       # names are 1/4th the price if they have no vowels

# Regarding discounts, the *maximum of the two* discounts will be taken if both apply.
# Both will not be applied.

# Run on the testnet? 
TESTNET=1

# How long to wait for confirmations?
# -- use 1 for testnet
# -- use 10 for mainnet
CONFIRMATIONS=1

# extra blockstack-cli opts (leave blank unless you know what you're doing)
OPTS=

###################################################################

# set -e

function usage() {
    echo "Usage: $0 NAMESPACE_ID PAYMENT_KEY REVEAL_KEY"
    exit 1
}

function missing() {
   echo "Missing the \"$1\" program.  Please install it before continuing."
   exit 1
}

function wait_confs() {
   TXID="$1"
   REQUIRED_CONFS="$2"
   echo "Waiting ${REQUIRED_CONFS} confirmation(s) for $TXID to confirm..."
   while true; do 
      CONFS="$(blockstack-cli $OPTS get_confirmations "$TXID" | jq '.confirmations')"
      if [ -n "$CONFS" ]; then 
         if [[ "$CONFS" -gt "$REQUIRED_CONFS" ]]; then 
            echo "$TXID has $CONFS confirmations"
            break
         fi
      else
         echo "WARN: got empty response for 'blockstack_cli "$OPTS" get_confirmations $TXID'"
      fi

      sleep 60
   done
}


which blockstack-cli >/dev/null || missing "blockstack-cli"
which jq >/dev/null || missing "jq"

NAMESPACE_ID="$1"
PAYMENT_KEY="$2"
REVEAL_KEY="$3"

if [ -z "$NAMESPACE_ID" ] || [ -z "$PAYMENT_KEY" ] || [ -z "$REVEAL_KEY" ]; then 
   usage
fi

if [[ "$TESTNET" = "1" ]]; then 
   OPTS="$OPTS -t"
fi

REVEAL_ADDR="$(blockstack-cli $OPTS get_address "$REVEAL_KEY")"
PREORDER_TXID="$(blockstack-cli $OPTS namespace_preorder "$NAMESPACE_ID" "$REVEAL_ADDR" "$PAYMENT_KEY")"
RC=$?

if [[ "$RC" != "0" ]]; then 
   echo "Namespace preorder failed"
   echo "$PREORDER_TXID" | jq -S
   exit 1
fi

TMP="$(echo "$PREORDER_TXID" | egrep '^[0-9a-f]+$')"
RC=$?

if [[ "$RC" != "0" ]]; then 
   echo "Did not get a preorder TXID, but got this instead:"
   echo "$PREORDER_TXID"
   exit 1
fi

echo "Namespace preorder txid: $PREORDER_TXID"
echo "Sleeping until it confirms"

wait_confs "$PREORDER_TXID" "$CONFIRMATIONS"

REVEAL_TXID="$(blockstack-cli $OPTS namespace_reveal "$NAMESPACE_ID" "$REVEAL_ADDR" "$NAMESPACE_VERSION" "$NAMESPACE_LIFETIME" "$NAMESPACE_COEFFICIENT" "$NAMESPACE_BASE" "$NAMESPACE_BUCKETS" "$NAMESPACE_NONALPHA_DISCOUNT" "$NAMESPACE_NOVOWEL_DISCOUNT" "$PAYMENT_KEY")"
RC=$?

if [[ "$RC" != "0" ]]; then 
   echo "Namespace reveal failed"
   echo "$REVEAL_TXID" | jq -S
   exit 1
fi

echo "Namespace reveal txid: $REVEAL_TXID"
echo "Sleeping until it confirms"

wait_confs "$REVEAL_TXID" "$CONFIRMATIONS"

echo "Namespace preordered and revealed.  Go ahead and import names."
echo "When you're ready, do the following"
echo "   * Send some BTC to $REVEAL_ADDR to fund the NAMESPACE_READY transaction (below),"
echo "   * run 'blockstack-cli $OPTS namespace_ready $NAMESPACE_ID $REVEAL_KEY'"
exit 0

