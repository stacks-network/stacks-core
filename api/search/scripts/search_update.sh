#!/bin/bash

echo "Starting indexing at $(date)" >> /tmp/update_index_out

python -m api.search.fetch_data --update_profiles 2>&1 | tee /tmp/update_profiles_out >> /tmp/update_index_out
grep -q "Indexed" /tmp/update_profiles_out
UPDATED=$?
grep -q "Indexed 0 profiles" /tmp/update_profiles_out
UPDATED_ZERO=$?
if [ $UPDATED -eq 0 ] && [ $UPDATED_ZERO -ne 0 ]; then
    echo "Refreshing mongodb index at $(date)" >> /tmp/update_index_out
    python -m api.search.basic_index --refresh  >> /tmp/update_index_out
else
    echo "Skipping mongodb index, no new profiles" >> /tmp/update_index_out
fi
echo "Finished indexing at $(date)" >> /tmp/update_index_out
