#!/bin/bash

# boot script for blockstack-core within the docker container.
# your container should have a sensible init that will keep the container alive,
# since this script exits once blockstack-core starts.

STATE_DIR="/root/.blockstack-server"

function exit_error() {
   echo "$1" >&2
   exit 1
}

function abort_container() { 
   echo "$1" >&2
   kill -9 1
   exit 1       # for good measure
}

if [ "$BLOCKSTACK_DEPLOYMENT_ASSERT_FAULTY" = "1" ]; then 
   abort_container "Exiting in error due to fault injection"
fi

# sanity check
which blockstack-core >/dev/null || exit_error "blockstack-core not found"

if [ "$BLOCKSTACK_DEPLOYMENT_ASSERT_NO_BINARY" = "1" ]; then 
   # make the container fail by moving blockstack-core out of the path 
   mv "$(which blockstack-core)" /tmp/blockstack-core
fi

if [ -f "$STATE_DIR/blockstack-server.db" ]; then 
   # make sure it matches *this* version
   DB_VERSION="$(blockstack-core db_version)"
   if [ $? -ne 0 ]; then 
      # obsolete
      rm -f "$STATE_DIR"/*.db* "$STATE_DIR"/*.snapshots
   fi
fi

set -e

if ! [ -f "$STATE_DIR/blockstack-server.db" ]; then 
   # no state
   if [ -n "$BLOCKSTACK_DEPLOYMENT_FAST_SYNC_URL" ] && [ -n "$BLOCKSTACK_DEPLOYMENT_FAST_SYNC_PUBLIC_KEY" ]; then 
       blockstack-core --debug fast_sync "$BLOCKSTACK_DEPLOYMENT_FAST_SYNC_URL" "$BLOCKSTACK_DEPLOYMENT_FAST_SYNC_PUBLIC_KEY"
   else
       blockstack-core --debug fast_sync
   fi
   sed -i -e 's/api_host = localhost/api_host = 0.0.0.0/' "$STATE_DIR/blockstack-server.ini"
fi

touch "$STATE_DIR/blockstack-server.log"

# start daemon
if [ -n "$BLOCKSTACK_DEPLOYMENT_GENESIS_BLOCK_URL" ] && [ -n "$BLOCKSTACK_DEPLOYMENT_GENESIS_BLOCK_KEY_ID" ]; then 
   apt-get install -y gnupg2 curl
   gpg2 --recv-keys "$BLOCKSTACK_DEPLOYMENT_GENESIS_BLOCK_KEY_ID"
   curl -sL "$BLOCKSTACK_DEPLOYMENT_GENESIS_BLOCK_URL" > /tmp/genesis_block.py

   blockstack-core --debug start --signing_key "$BLOCKSTACK_DEPLOYMENT_GENESIS_BLOCK_KEY_ID" --genesis_block /tmp/genesis_block.py
else
   blockstack-core --debug start
fi

if [ "$BLOCKSTACK_DEPLOYMENT_ASSERT_FAST_SYNC" = "1" ]; then 
    # wait for the daemon to come up
    sleep 15

    # make sure the daemon is *not* starting from scratch
    API_PORT="$(grep "api_port" "$STATE_DIR/blockstack-server.ini" | sed -r 's/([^=]+)=[ ]*([^ ]+)/\2/g')"
    if [ -z "$API_PORT" ]; then 
       abort_container "Could not determine api_port from config file"
    fi

    BLOCK_HEIGHT="$(curl -sL "http://localhost:$API_PORT/v1/info" | jq '.last_block_processed')"
    if [ $BLOCK_HEIGHT -lt 500000 ]; then 
       abort_container "Node is trying to boot from scratch when we asked it not to"
    fi
fi

# wait forever
tail -f "$STATE_DIR/blockstack-server.log"
