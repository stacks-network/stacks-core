#!/bin/bash

echo "Refreshing mongodb index at $(date)" >> /tmp/update_index_out
python -m api.search.basic_index --refresh  >> /tmp/update_index_out
echo "Finished indexing at $(date)" >> /tmp/update_index_out
