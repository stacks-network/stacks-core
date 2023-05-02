#!/usr/bin/env bash

if [ $# -eq 0 ]; then
    echo "Usage: "
    echo "keep-fuzzing.sh [test_name_goes_here]"
    echo -en "\tExample:\n\t"
    echo "keep-fuzzing.sh fuzz_admits_type"
    exit 1
fi

while true; do
    cargo fuzz run $1 -- -rss_limit_mb=4096
    FUZZ_STATUS="$?"
    echo "$FUZZ_STATUS"
    if [ $FUZZ_STATUS -eq 0 ]; then
        echo "Exiting keep-fuzzing.sh"
        break
    fi
done
