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
   # TODO: remove arguments once in master
   blockstack-core --debug fast_sync http://testnet.blockstack.org/snapshot.bsk 04874e5e95e9da7662de351c967c1edcaccf902536cbb0d4e00e6d22038034628700ae6b360c2cf10c3c834863c9c98f33e9bd07fc0c349e7c14f07f8b0e5a7421
fi

# start daemon and wait forever
touch "$STATE_DIR/blockstack-server.log"
blockstack-core --debug start

tail -f "$STATE_DIR/blockstack-server.log"
