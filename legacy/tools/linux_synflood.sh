#!/bin/sh

# This script adds iptables rules that
# limit the number of connections to Blockstack

if [ -z "$1" ]; then 
   echo >&2 "Usage: $0 enable/disable"
   exit 1
fi

RULE_NAME="BLOCKSTACK_SYNFLOOD"

case "$1" in
   "enable")

        PRESENT="$(iptables -L -v | grep "$RULE_NAME")"
        if [ -n "$PRESENT" ]; then 
           echo >&2 "Blockstack SYN flood rules appear to be installed already..."
           exit 0
        fi

        # add the rule for 5/second SYN requests and max burst of 10.  Drop after that
        iptables -N "$RULE_NAME"
        iptables -A "$RULE_NAME" -m limit --limit 5/second --limit-burst 10 -j ACCEPT
        iptables -A "$RULE_NAME" -j DROP
        iptables -A "$RULE_NAME" -p tcp --syn --dport 6264 -j "$RULE_NAME"

        # verify that it was installed 
        PRESENT="$(iptables -L -v | grep "$RULE_NAME")"
        if [ -z "$PRESENT" ]; then 
           echo >&2 "Failed to enable rule $RULE_NAME.  Check iptables."
           exit 1
        fi
        ;;

    "disable")
        
        PRESENT="$(iptables -L -v | grep "$RULE_NAME")"
        if [ -z "$PRESENT" ]; then
           echo >&2 "Blockstack SYN flood rules appear to be disabled already..."
           exit 0
        fi

        # disable rules 
        iptables -D "$RULE_NAME" 1
        iptables -D "$RULE_NAME" 1
        iptables -D "$RULE_NAME" 1
        iptables -X "$RULE_NAME"
        ;;

    *)

       echo >&2 "Usage: $0 enable/disable"
       exit 1
  
esac

exit 0

