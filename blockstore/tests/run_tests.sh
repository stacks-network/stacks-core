#!/bin/sh

usage() {
   echo "Usage: $0 [path/to/scenarios] [path/to/test/output/dir]"
   exit 1
}

if [ $# -ne 2 ]; then 
   usage $0
fi

SCENARIOS="$1"
OUTPUTS="$2"

test -d "$OUTPUTS" || mkdir -p "$OUTPUTS"

SCENARIOS_PYTHON="$(echo "$SCENARIOS" | sed 's/[\/]+/\./g')"

while IFS= read SCENARIO_FILE; do
   
   if ! [ "$(echo "$SCENARIO_FILE" | egrep '.py$')" ]; then 
      continue 
   fi

   if [ "$SCENARIO_FILE" == "__init__.py" ] || [ "$SCENARIO_FILE" == "testlib.py" ]; then 
      continue
   fi

   SCENARIO_MODULE_BASE="$(echo "$SCENARIO_FILE" | sed 's/\.py//g')"
   SCENARIO_MODULE="$SCENARIOS_PYTHON.$SCENARIO_MODULE_BASE"

   echo -n "$SCENARIO_MODULE ... "

   TESTDIR="/tmp/blockstore-test"

   mkdir -p "$TESTDIR"
   ./run_scenario.py "$SCENARIO_MODULE" "$TESTDIR" > "$OUTPUTS/$SCENARIO_MODULE_BASE.log" 2>&1

   RC=$?

   if [ $RC -eq 0 ]; then 
      echo " SUCCESS"
      rm -rf "$TESTDIR"

   else
      echo " FAILURE"
      mv "$TESTDIR" "$OUTPUTS/$SCENARIO_MODULE_BASE.d"
   fi
done <<EOF
$(ls "$SCENARIOS")
EOF

exit 0
