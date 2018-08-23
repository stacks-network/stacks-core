#!/bin/bash

ALT_HOME=
if [ -n "$VIRTUAL_ENV" ]; then 
   ALT_HOME="-H $VIRTUAL_ENV"
fi

if ! [ -d "templates" ]; then
    echo 'Run thi script from the api/ directory (./templates must exist)' 
    exit 1
fi

PUBLIC_NODE=True DEBUG=True BSK_API_TMPLTDIR=$(realpath ./templates/) uwsgi --plugins http,python $ALT_HOME --ini ./deployment/blockstack_api.ini
