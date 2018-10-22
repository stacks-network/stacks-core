#!/bin/bash

# boot script for blockstack-core within the docker container.
# your container should have a sensible init that will keep the container alive,
# since this script exits once blockstack-core starts.

set -e
STATE_DIR="/root/.blockstack-server"

function exit_error() {
   echo "$1" >&2
   exit 1
}

# santiy check
which blockstack-core >/dev/null || exit_error "blockstack-core not found"

if ! [ -f "$STATE_DIR/blockstack-server.db" ]; then 
   # no state yet
   blockstack-core --debug fast_sync
   sed -i -e 's/api_host = localhost/api_host = 0.0.0.0/' "$STATE_DIR/blockstack-server.ini"
fi

# start daemon and wait forever
touch "$STATE_DIR/blockstack-server.log"
blockstack-core --debug start

tail -f "$STATE_DIR/blockstack-server.log"
