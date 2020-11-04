#!/bin/bash
# source after $__BIN/start.sh

check_chain_quality() {
    local EXPECTED_SORTITION_FRACTION="$1"
    local EXPECTED_FORK_FRACTION="$2"
    local EXPECTED_NUM_BLOCKS="$3"

    local TOTAL_BLOCKS="$(report "/api/miners" | jq -r ".[].height" | wc -l)"
    local CHAIN_HEIGHT="$(report "/api/miners" | jq -r ".[].height" | head -n 1)"

    local TOTAL_SORTITIONS="$(report "/api/sortitions" | jq -r '.[].height' | head -n 1)"
    
    # find first non-empty sortition 
    local LAST_EMPTY_SORTITION="$(report "/api/sortitions" | jq -r '.[] | select(.index_block_hash == "0000000000000000000000000000000000000000000000000000000000000000") | .height' | head -n 1)"
    local FIRST_SORTITION_HEIGHT="$((LAST_EMPTY_SORTITION + 1))"

    # enough burn blocks had a sortition once mining began
    local EMPTY_SORTITIONS="$(
        report "/api/sortitions" | \
        jq -r '.[] | {height: (.height)|tonumber, index_block_hash: (.index_block_hash)} | select(.height >= '$FIRST_SORTITION_HEIGHT') | select(.index_block_hash == "0000000000000000000000000000000000000000000000000000000000000000")' | \
        wc -l
    )"

    local SORTITION_FRACTION=$(( (TOTAL_SORTITIONS - EMPTY_SORTITIONS) * 100 / TOTAL_SORTITIONS ))
    if (( $SORTITION_FRACTION < $EXPECTED_SORTITION_FRACTION )); then
       echo >&2 "Resulting chain has $SORTITION_FRACTION percent sortitions"
       return 1
    fi
    
    # enough blocks were mined
    if (( $TOTAL_BLOCKS < $EXPECTED_NUM_BLOCKS )); then
       echo >&2 "Resulting chain only has $TOTAL_BLOCKS blocks"
       return 1
    fi

    local FORK_FRACTION=$((CHAIN_HEIGHT * 100 / TOTAL_BLOCKS))

    # enough blocks were on the same fork
    if (( $FORK_FRACTION < $EXPECTED_FORK_FRACTION )); then
       echo >&2 "Only $FORK_FRACTION percent of blocks were mined on the same fork"
       return 1
    fi

    return 0
}

