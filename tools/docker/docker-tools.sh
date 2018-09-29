#!/bin/bash

image=quay.io/blockstack/blockstack-core
tag=master

init-core () {
  local coreData=data/core
  echo "Initializing Blockstack Core node. This task runs in the background and may take up to 20 minutes..."
  mkdir -p $(pwd)/$coreData/server/
  cp $(pwd)/blockstack-server.ini $(pwd)/$coreData/server/blockstack-server.ini
  docker run -d --rm \
    -v $(pwd)/$coreData/server/:/root/.blockstack-server/ \
    --name blockstack-core-init \
    $image:$tag \
    blockstack-core --debug fast_sync http://fast-sync.blockstack.org/snapshot.bsk > /dev/null
}

test-core () {
  if [ -z "$1" ]; then
    echo "Need to input host to test against..."
    exit 1
  fi
  if [ -z "$2" ]; then
    echo "Need to input port to test against..."
    exit 1
  else
    local rpccall='<?xml version="1.0"?><methodCall><methodName>getinfo</methodName><params></params></methodCall>'
    curl -L -XPOST -H "Content-Type: application/xml" $1:$2/RPC2 -d "$rpccall"
  fi
}

commands () {
  cat <<-EOF
ops commands:
  init-core               -> Fast sync core node directories to $(pwd)/data/core
  test-core {host} {port} -> Call the getinfo RPC method against node running at {host}:{port}
EOF
}

case $1 in
init-core)
  init-core
  ;;
test-core)
  test-core $2 $3
  ;;
*)
  commands
  ;;
esac
