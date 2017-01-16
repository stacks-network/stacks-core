#!/bin/bash

BRANCH="rc-0.14.0"
if [ $# -ge 2 ]; then 
   BRANCH="$1"
   shift 1
fi

for repo in dns-zone-file-py blockstack-profiles-py virtualchain blockstack-cli blockstack-core blockstack-files blockstack-gpg blockstack-integration-tests; do
   git clone "https://github.com/blockstack/$repo"
   pushd "$repo"
   git checkout "$BRANCH"
   python ./setup.py build && sudo python ./setup.py install

   if [ $? -ne 0 ]; then 
      echo "Failed to install"
      exit 1
   fi

   popd
done

exit 0

