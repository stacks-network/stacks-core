#!/bin/bash

echo "Building mongodb index at $(date)" >> /tmp/indexer_out
python -m api.search.basic_index --refresh 2>>/tmp/indexer_out
echo "Finished indexing at $(date)" >> /tmp/indexer_out
