#!/bin/bash
############################################################################
#
# This script will create a folder `blockstack` in your current directory
#   this folder will contain: 
#        a Python virtualenv with Blockstack-Core
#        a git clone of the Blockstack-Portal node app 
#                (with dependencies installed)
#        a `bin` directory with scripts:
#          blockstack_portal_start.sh -> for starting core and portal
#          blockstack_portal_stop.sh  -> for stopping portal
#          blockstack_core_stop.sh    -> for stopping core
#          blockstack_copy_api_pass.sh-> copies the API key to the clipboard
#
# The script will also install system dependencies using `apt`. For this, it
#  will attempt to `sudo` -- if you'd like to run this script without sudo,
#  you can pass the `--no-install` flag, but you will have to have installed
#  these dependencies prior to runnig the script.
#
# Finally, you must pass your desired wallet password to the script as an
#  argument. 
#
############################################################################

set -e

NO_INSTALL=0

if [ "$1" == "--no-install" ]
then
   NO_INSTALL=1
   BITCOIN_WALLET_PASSWORD="$2"
else
   BITCOIN_WALLET_PASSWORD="$1"
   if [ "$2" == "--no-install" ]
   then
       NO_INSTALL=1
   fi
fi

DIR=$PWD/blockstack
CORE_VENV="$DIR/core-venv"

if [ -z "$BITCOIN_WALLET_PASSWORD" ]
then
    echo "You have to pass the desired wallet password to script as an argument."
    exit 1
fi

if [ -e "$DIR" ]
then
    echo "The directory '$DIR' already exists"
    exit 1
fi


############################################################################
# The sudoer section. If all of these are already installed on your system,
#  you can comment this out and run the script without it ever sudoing
############################################################################

if [ "$NO_INSTALL" -eq "0" ]
then
    sudo apt install -y curl xclip
    curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
    sudo apt update 
    sudo apt install -y python-pip python-dev libssl-dev libffi-dev rng-tools curl build-essential git firefox nodejs
    sudo pip install virtualenv
fi

############################################################################

mkdir -p "$DIR"

virtualenv --python=python2.7 "$CORE_VENV"

"$CORE_VENV/bin/python" -m pip install git+https://github.com/blockstack/virtualchain.git@rc-0.14.2
"$CORE_VENV/bin/python" -m pip install git+https://github.com/blockstack/blockstack-core.git@rc-0.14.2

"$CORE_VENV/bin/python" "$CORE_VENV/bin/blockstack" setup -y --password "$BITCOIN_WALLET_PASSWORD"

cd "$DIR"

git clone https://github.com/blockstack/blockstack-portal.git -bv0.9
cd blockstack-portal

npm install node-sass
npm install

echo "Installed Blockstack Core + Portal!"

# make some bin scripts.

mkdir "$DIR/bin"
cd "$DIR/bin"

START_PORTAL_NAME=blockstack_portal_start.sh
STOP_PORTAL_NAME=blockstack_portal_stop.sh
STOP_CORE_NAME=blockstack_core_stop.sh
COPY_API_NAME=blockstack_copy_api_pass.sh

echo "#!/bin/bash" > $START_PORTAL_NAME
echo "cd \"$DIR/blockstack-portal\"" >> $START_PORTAL_NAME
echo "\"$CORE_VENV/bin/python\" \"$CORE_VENV/bin/blockstack\" api status -y | grep 'true' > /dev/null" >> $START_PORTAL_NAME
echo "if [ \$? -ne 0 ]; then" >> $START_PORTAL_NAME
echo "\"$CORE_VENV/bin/python\" \"$CORE_VENV/bin/blockstack\" api start -y" >> $START_PORTAL_NAME
echo "fi" >> $START_PORTAL_NAME
echo "npm run dev-proxy 2>&1 > /tmp/rundev_proxy_out &" >> $START_PORTAL_NAME
echo "echo \"\$!\" > /tmp/devproxy.pid" >> $START_PORTAL_NAME
echo "echo > /tmp/rundev_out" >> $START_PORTAL_NAME
echo "npm run dev 2>&1 >> /tmp/rundev_out &" >> $START_PORTAL_NAME
echo "echo \"\$!\" > /tmp/dev.pid" >> $START_PORTAL_NAME
echo "tail -f /tmp/rundev_out | grep -m 1 \"Finished 'dev'\" > /dev/null" >> $START_PORTAL_NAME
echo "echo 'Running... connect at localhost:3000'" >> $START_PORTAL_NAME


echo "#!/bin/bash" > $STOP_PORTAL_NAME
echo "tokill=\$(cat /tmp/dev.pid)" >> $STOP_PORTAL_NAME
echo "kill -s SIGTERM -\$(ps -o pgid= \$tokill | cut -d\\  -f2)" >> $STOP_PORTAL_NAME
echo "echo 'Killed Blockstack Portal'" >> $STOP_PORTAL_NAME

echo "#!/bin/bash" > $STOP_CORE_NAME
echo "\"$CORE_VENV/bin/python\" \"$CORE_VENV/bin/blockstack\" api stop -y" >> $STOP_CORE_NAME
echo "echo 'Stopped Blockstack Core'" >> $STOP_CORE_NAME

echo "#!/bin/bash" > $COPY_API_NAME
echo "grep api_password ~/.blockstack/client.ini | sed 's/api_password = //g' | xclip -selection clipboard" >> $COPY_API_NAME

chmod +x $START_PORTAL_NAME
chmod +x $STOP_PORTAL_NAME
chmod +x $COPY_API_NAME
chmod +x $STOP_CORE_NAME

echo "Made app scripts!"
echo "You can add bins to your path with \$ export PATH=\$PWD/blockstack/bin:\$PATH"
