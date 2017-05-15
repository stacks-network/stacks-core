#!/bin/bash

BITCOIN_WALLET_PASSWORD=$1

curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
sudo apt update 
sudo apt install -y python-pip python-dev libssl-dev libffi-dev rng-tools curl build-essential git firefox nodejs
sudo pip install virtualenv

virtualenv --python=python2.7 ~/.blockstack.venv/ && source ~/.blockstack.venv/bin/activate

pip install git+https://github.com/blockstack/virtualchain.git@rc-0.14.2
pip install git+https://github.com/blockstack/blockstack-core.git@rc-0.14.2

blockstack setup -y --password $BITCOIN_WALLET_PASSWORD

deactivate

mkdir ~/.blockstack.portal
cd ~/.blockstack.portal

git clone https://github.com/blockstack/blockstack-portal.git -bv0.9
cd blockstack-portal

npm install

mkdir ~/.blockstack.portal/bin
cd ~/.blockstack.portal/bin

echo "#!/bin/bash" > start_portal.sh
echo "cd ~/.blockstack.portal/blockstack-portal" > start_portal.sh
echo "~/.blockstack.venv/bin/python ~/.blockstack.venv/bin/blockstack api start -y" > start_portal.sh
echo "npm run dev-proxy 2>&1 > /tmp/rundev_proxy_out &" > start_portal.sh
echo "echo \"\$\!\" > /tmp/devproxy.pid" > start_portal.sh
echo "npm run dev 2>&1 > /tmp/rundev_out &" > start_portal.sh
echo "echo \"\$\!\" > /tmp/dev.pid" > start_portal.sh

echo "tail -f /tmp/rundev_out | grep 'Finished \'dev\'' | head -n 1"

echo "echo 'Running... connect at localhost:3000'" > start_portal.sh

echo "#!/bin/bash" > stop_portal.sh
echo "kill -9 \$(cat /tmp/dev.pid)" > stop_portal.sh
echo "kill -9 \$(cat /tmp/devproxy.pid)" > stop_portal.sh

chmod +x start_portal.sh
chmod +x stop_portal.sh
