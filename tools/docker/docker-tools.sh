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
    -v $(pwd)/$coreData/api/:/root/.blockstack \
    --name blockstack-core-init \
    $image:$tag \
    blockstack-core --debug fast_sync http://fast-sync.blockstack.org/snapshot.bsk > /dev/null
}

init-api () {
  local apiData=data/api
  echo "Initializing Blockstack Core API server with dummy wallet..."
  mkdir -p $(pwd)/$apiData
  docker run -it --rm \
    -v $(pwd)/$apiData:/root/.blockstack \
    $image:$tag \
    blockstack setup -y --password dummywalletpassword
  sudo cp client.ini $apiData/client.ini
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

test-api () {
  if [ -z "$1" ]; then
    echo "Need to input host to test against..."
    exit 1
  fi
  if [ -z "$2" ]; then
    echo "Need to input port to test against..."
    exit 1
  else
    curl -L $1:$2/v1/ping
  fi
}

commands () {
  cat <<-EOF
ops commands:
  init-core               -> Fast sync core node directories to $(pwd)/data/core
  init-api                -> Create dummywallet and config for blockstack api in $(pwd)/data/api
  test-core {host} {port} -> Call the getinfo RPC method against node running at {host}:{port}
  test-api  {host} {port} -> Call the /v1/ping route against api running at {host}:{port}
EOF
}

case $1 in
init-core)
  init-core
  ;;
init-api)
  init-api
  ;;
test-core)
  test-core $2 $3
  ;;
test-api)
  test-api $2 $3
  ;;
*)
  commands
  ;;
esac
