#!/bin/sh

# api_password is $1
if [ -z "$1" ]; then 
   echo "Usage: $0 api_password"
   exit 1
fi

API_PASSWORD="$1"
TEST_OUTPUT=/tmp/blockstack-portal.log

export BLOCKSTACK_CLIENT_CONFIG="/tmp/blockstack-run-scenario.blockstack_integration_tests.scenarios.name_preorder_register_portal/client/client.ini"
if [ -f "$BLOCKSTACK_CLIENT_CONFIG" ]; then 
   rm "$BLOCKSTACK_CLIENT_CONFIG"
fi

# set up a fake .id namespace, with 5-second block times.
# do this in the background
blockstack-test-scenario --interactive 5 blockstack_integration_tests.scenarios.name_preorder_register_portal > "$TEST_OUTPUT" 2>&1 &
TEST_PID="$!"

trap "kill -s 0 $TEST_PID && kill -s 2 $TEST_PID; exit 1" 2

# set up client 
export BLOCKSTACK_TEST=1
export BLOCKSTACK_TESTNET=1
export BLOCKSTACK_TEST_NODEBUG=1

echo -n 'Test is spinning up...'
while true; do
   if [ -f "$BLOCKSTACK_CLIENT_CONFIG" ]; then 
      break
   else
      echo -n "."
      sleep 1
   fi
done
echo ""

# wait for foo.id to appear 
echo -n "Waiting for foo.id to appear..."
while true; do 
    ERR="$(blockstack -y whois foo.id | sed -r '1,2d' | jq '.error' | grep -v 'null')"
    if [ -n "$ERR" ]; then 
        # not there yet
        sleep 1
        echo -n '.'
        continue
    else
        break
    fi
done

echo ''

# activate debugging
export BLOCKSTACK_TEST_NODEBUG=0
export BLOCKSTACK_DEBUG=1

echo "Patching client config..."

# patch client config:
# * set port to 6270
# * set API password
ed "$BLOCKSTACK_CLIENT_CONFIG" <<EOF
1
/api_endpoint_port
s/16268/6270/g
1
/api_password
d
a
api_password = $API_PASSWORD
.
w
EOF

echo "Starting API server..."

# start API server
blockstack -y -p 0123456789abcdef api start-foreground
