#!/bin/sh

if [ $# -ne 2 ]; then 
   echo >&2 "Usage: $0 [/path/to/blockstore/config/template/file] [csv of wif:value pairs]"
   exit 1
fi

TEMPLATE_PATH="$1"
INITIAL_UTXOS="$2"

if ! [ -f "$TEMPLATE_PATH" ]; then 
   echo >&2 "$TEMPLATE_PATH: No such file or directory"
   exit 1
fi

cat "$TEMPLATE_PATH" | sed "s~@MOCK_INITIAL_UTXOS@~$INITIAL_UTXOS~g" 
exit 0
