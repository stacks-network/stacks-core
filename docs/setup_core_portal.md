
# Setting up Blockstack Core API Service

Install required binaries in Ubuntu:

`sudo apt update && sudo apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools curl build-essential`


If you'd like to use a virtualenv to install Blockstack, you can do that
`pip install virtualenv`
`virtualenv --python=python2.7 ~/.blockstack.venv/ && source ~/.blockstack.venv/bin/activate`

Let's install virtualchain 0.14.2 and blockstack 0.14.2

`sudo apt install git`
`pip install git+https://github.com/blockstack/virtualchain.git@rc-0.14.2`
`pip install git+https://github.com/blockstack/blockstack-core.git@rc-0.14.2`

Get Blockstack core congifured with default settings and choose your Bitcoin wallet password
`blockstack setup -y --password BITCOIN_WALLET_PASSWORD --debug`

# Setting up Blockstack Portal Node Application

Install NodeJS through NodeSource PPA

`curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -`
`sudo apt install -y nodejs`

Download Blockstack Portal and install its dependencies

`git clone https://github.com/blockstack/blockstack-portal.git -bv0.8`
`cd blockstack-portal && npm install`


# Running Blockstack Portal

First, start the Core API service.

`blockstack api start -y --password BITCOIN_WALLET_PASSWORD --debug`

Start the CORS proxy.

`npm run dev-proxy &` 

Start the Node Application, reading your API password from the Blockstack Core API config file.

`npm run dev`
`grep api_password ~/.blockstack/client.ini | sed 's/api_password = //g' | xclip -selection clipboard`

Open http://localhost:3000/ in your browser (tested on Firefox and Chromium).
