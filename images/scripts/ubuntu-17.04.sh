#!/bin/bash
set -e

BITCOIN_WALLET_PASSWORD=$1

if [ -z "$BITCOIN_WALLET_PASSWORD" ]
then
    echo "You have to pass the desired wallet password to script as an argument."
    exit 1
fi

sudo apt install -y curl xclip
curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
sudo apt update 
sudo apt install -y python-pip python-dev libssl-dev libffi-dev rng-tools curl build-essential git firefox nodejs
sudo pip install virtualenv

virtualenv --python=python2.7 ~/.blockstack.venv/

~/.blockstack.venv/bin/pip install git+https://github.com/blockstack/virtualchain.git@rc-0.14.2
~/.blockstack.venv/bin/pip install git+https://github.com/blockstack/blockstack-core.git@rc-0.14.2

~/.blockstack.venv/bin/python ~/.blockstack.venv/bin/blockstack setup -y --password $BITCOIN_WALLET_PASSWORD

mkdir ~/.blockstack.portal
cd ~/.blockstack.portal

git clone https://github.com/blockstack/blockstack-portal.git -bv0.9
cd blockstack-portal

npm install node-sass
npm install

echo "Installed Blockstack Core + Portal!"

mkdir ~/.blockstack.portal/bin
cd ~/.blockstack.portal/bin

echo "#!/bin/bash" > start_portal.sh
echo "cd ~/.blockstack.portal/blockstack-portal" >> start_portal.sh
echo "~/.blockstack.venv/bin/python ~/.blockstack.venv/bin/blockstack api status -y | grep 'true' > /dev/null" >> start_portal.sh
echo "if [ \$? -ne 0 ]; then" >> start_portal.sh
echo "~/.blockstack.venv/bin/python ~/.blockstack.venv/bin/blockstack api start -y" >> start_portal.sh
echo "fi" >> start_portal.sh
echo "npm run dev-proxy 2>&1 > /tmp/rundev_proxy_out &" >> start_portal.sh
echo "echo \"\$!\" > /tmp/devproxy.pid" >> start_portal.sh
echo "echo > /tmp/rundev_out" >> start_portal.sh
echo "npm run dev 2>&1 >> /tmp/rundev_out &" >> start_portal.sh
echo "echo \"\$!\" > /tmp/dev.pid" >> start_portal.sh
echo "tail -f /tmp/rundev_out | grep -m 1 \"Finished 'dev'\" > /dev/null" >> start_portal.sh
echo "echo 'Running... connect at localhost:3000'" >> start_portal.sh


echo "#!/bin/bash" > stop_portal.sh
echo "tokill=\$(cat /tmp/dev.pid)" >> stop_portal.sh
echo "kill -s SIGTERM -\$(ps -o pgid= \$tokill | cut -d\\  -f2)" >> stop_portal.sh
echo "echo 'Killed Blockstack Portal'" >> stop_portal.sh

echo "#!/bin/bash" > copy_api_pass.sh
echo "grep api_password ~/.blockstack/client.ini | sed 's/api_password = //g' | xclip -selection clipboard" >> copy_api_pass.sh

chmod +x start_portal.sh
chmod +x stop_portal.sh
chmod +x copy_api_pass.sh

echo "Made app scripts!"
