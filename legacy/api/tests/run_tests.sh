#!/bin/bash

BLOCKSTACK_CORE_URL="$1"
BLOCKSTACK_CORE_REST_PORT="$2"
BLOCKSTACK_CORE_INDEXER_PORT="$3"

if [ -z "$BLOCKSTACK_CORE_URL" ] || [ -z "$BLOCKSTACK_CORE_REST_PORT" ] || [ -z "$BLOCKSTACK_CORE_INDEXER_PORT" ]; then 
   echo "Usage: $0 BLOCKSTACK_CORE_URL REST_PORT INDEXER_PORT"
   exit 1
fi

# flask server
test -f server.py || (echo "You must run this within the api/ directory" && exit 1)

echo "Starting Flask server; logs to /tmp/flask.log"
DEBUG=True BASE_INDEXER_API_URL="$BLOCKSTACK_CORE_URL:$BLOCKSTACK_CORE_INDEXER_PORT" BASE_API_URL="$BLOCKSTACK_CORE_URL:$BLOCKSTACK_CORE_REST_PORT" FLASK_APP=server.py flask run >/tmp/flask.log 2>&1 &
FLASK_PID="$!"
trap "kill -9 $FLASK_PID" SIGINT SIGQUIT SIGTERM

sleep 5
DEBUG=True BASE_INDEXER_API_URL="$BLOCKSTACK_CORE_URL:$BLOCKSTACK_CORE_INDEXER_PORT" BASE_API_URL="http://localhost:5000" python tests/api_tests.py
RC=$?

kill -9 "$FLASK_PID"
exit "$RC"
