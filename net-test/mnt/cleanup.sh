#!/bin/bash

NOW="$(date +%s)"
mkdir -p "archive/$NOW"
ls | while read NAME; do
    if [[ "$NAME" != "cleanup.sh" ]] && [[ "$NAME" != "archive" ]]; then
        echo "mv $NAME archive/$NOW"
        mv "$NAME" "archive/$NOW"
    fi
done

