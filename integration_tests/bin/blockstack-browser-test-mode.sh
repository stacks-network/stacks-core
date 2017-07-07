#!/bin/bash

# launcher for browser

BROWSER_DIR='/tmp/blockstack-browser'
if ! [ -d "$BROWSER_DIR" ]; then 
   echo ""
   echo "Missing $BROWSER_DIR"
   echo "Please make sure Blockstack Browser is available in that directory"
   echo "(https://github.com/blockstack/blockstack-browser)"
   echo ""
   exit 1
fi

TEST_PID=
DEV_PROXY_PID=

# start environment 
# override RPC port
export BLOCKSTACK_TEST_CLIENT_RPC_PORT=6270

# tell the RPC system to encode all addresses to mainnet, even though we're in testing
export BLOCKSTACK_RPC_MOCK_BLOCKCHAIN_NETWORK="mainnet"

blockstack-test-scenario --interactive-web 3001 blockstack_integration_tests.scenarios.portal_empty_namespace 2>&1 | tee browser_test.log &
TEST_PID=$!

# wait for it to begin serving 
while true; do
   curl http://localhost:3001 >/dev/null 2>/dev/null
   if [ $? -eq 0 ]; then
      break
   else
      sleep 1
   fi
done

pushd "$BROWSER_DIR" >/dev/null

echo ""
echo "Starting Browser CORS proxy"
echo ""
npm run dev-proxy 2>&1 | tee "$BROWSER_DIR/cors-proxy.log" &
DEV_PROXY_PID=$!

sleep 5

echo ""
echo "Starting Blockstack Browser"
echo ""
npm run dev

echo ""
echo "Test framework control panel at http://localhost:3001"
echo "Blockstack Browser at http://localhost:3000"

popd

echo "cleaning up"

if [ -n "$TEST_PID" ]; then
    kill "$TEST_PID"
fi
if [ -n "$DEV_PROXY_PID" ]; then 
    kill "$DEV_PROXY_PID"
fi
