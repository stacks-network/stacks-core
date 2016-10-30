#!/bin/bash

# This script will set you up with all the 
# code you need to run a Blockstack Core node,
# version 0.14.
#
# Please note that this is *experimental software*.
# Use at your own risk.
#
# It's best to run this in a virtualenv.  Otherwise,
# if you have any prior Blockstack packages installed,
# you should remove them.

BRANCH="rc-0.14.0"
if [ $# -ge 2 ]; then 
   BRANCH="$1"
fi

for repo in dns-zone-file-py blockstack-profiles-py virtualchain blockstack-cli blockstack-core; do
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

echo ""
echo "Installation finished"
echo "For best results, start and run with this command:"
echo ""
echo "    $ nohup BLOCKSTACK_DEBUG=1 blockstack-server start --foreground &"
echo ""
echo "To stop it later, use this command:"
echo ""
echo "    $ blockstack-server stop
echo ""
exit 0

