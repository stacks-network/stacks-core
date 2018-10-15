#!/bin/bash

# what's our public hostname?
# XXX If you're running your own testnet, change this to your server's hostname!
export BLOCKSTACK_TESTNET_PUBLIC_HOST="testnet.blockstack.org"


function exit_error() {
    echo $1
    exit 1
}

which blockstack-test-scenario 2>&1 > /dev/null || exit_error 'You must install the integration test suite first'
which blockstack-core 2>&1 > /dev/null || exit_error 'You must install Blockstack Core first'

# take all inbound requests
export BLOCKSTACK_TEST_CLIENT_BIND="0.0.0.0"

# activate public testnet features (i.e. make Atlas run at the normal speed)
export BLOCKSTACK_PUBLIC_TESTNET="1"

# make ourselves look like we're an old Core node, so mainnet nodes don't add us as peers
export BLOCKSTACK_CORE_VERSION="0.0.0.1"

LOGFILE=testnet.log
LOGFILE_BACKUPS=testnet-logs

mkdir -p "$LOGFILE_BACKUPS"

while true; do 
   if [ -f "$LOGFILE" ]; then 
       BACKUP_LOGFILE="$LOGFILE_BACKUPS/testnet.log.$(date +%s)"
       mv "$LOGFILE" "$BACKUP_LOGFILE"
       bzip2 "$BACKUP_LOGFILE" &
   fi

   blockstack-test-scenario blockstack_integration_tests.scenarios.testnet_public > "$LOGFILE" 2>&1 &
   TEST_PID=$!
  
   sleep 60

   # reboot once a day
   for i in $(seq 1 1440); do
       kill -s 0 $TEST_PID
       RC=$?
       if [ $RC -ne 0 ]; then 
          echo "Testnet crashed at $(date)"
          echo "Testnet crashed at $(date)" >> "$LOGFILE"
          break;
       fi
       sleep 60
   done
       
   echo "Rebooting testnet..." >> "$LOGFILE"
   echo "Rebooting testnet..."
   kill "$TEST_PID"
   sleep 10
   echo "Testnet stopped at "$(date)"" >> "$LOGFILE"
   echo "Testnet stopped at "$(date)""
done

