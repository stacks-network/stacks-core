#!/bin/bash

source ./config.sh
set -uo pipefail

SUCCEEDED=0
for TESTNAME in $(ls test_*); do
   ( cd "$__MNT" && ./cleanup.sh )
   echo "Running $TESTNAME"
   "./$TESTNAME"
   RC=$?
   echo "$TESTNAME exit $RC"

   if [ $RC -ne 0 ]; then
      SUCCEEDED=1
   fi
done

exit $SUCCEEDED
