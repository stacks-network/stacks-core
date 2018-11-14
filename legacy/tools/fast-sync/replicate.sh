#!/bin/bash

SNAPSHOT_PATH="$1"
if [ -z "$SNAPSHOT_PATH" ]; then 
   echo "Usage: $0 /path/to/snapshot.bsk"
   exit 1
fi

CONF="$HOME/.blockstack-snapshots/replication.script"
if ! [ -f "$CONF" ]; then 
   echo >&2 "You must create a $CONF file first."
   echo >&2 "Each line will be executed from this directory, and passed the snapshot path as its last argument"
   exit 1
fi

cat "$CONF" | \
while IFS= read line; do 
   echo "$line $SNAPSHOT_PATH"
   bash -c "$line $SNAPSHOT_PATH"
   rc=$?
   if [ $rc -ne 0 ]; then 
      echo >&2 "exit $rc: $line $SNAPSHOT_PATH"
   fi
done
