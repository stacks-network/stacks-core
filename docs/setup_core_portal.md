# Install Script

We provide a [script](../images/scripts/ubuntu-17.04.sh) which will
perform all the steps outlined in this doc, creating a virtualenv of
Blockstack Core and installing Portal in a subdirectory. It additionally creates some
scripts for starting Core and Portal together.

However, if you'd like to customize your install, step through it 
yourself, or you are on a different distro, continue on with this doc!

# Setting up Blockstack Core API Service

Install required binaries in Ubuntu:

```
sudo apt update && sudo apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools curl build-essential
```


If you'd like to use a virtualenv to install Blockstack, you can do that

```
pip install virtualenv
virtualenv --python=python2.7 ~/.blockstack.venv/ && source ~/.blockstack.venv/bin/activate
```

Let's install virtualchain 0.14.2 and blockstack 0.14.2

```
sudo apt install git
pip install git+https://github.com/blockstack/virtualchain.git@rc-0.14.2
pip install git+https://github.com/blockstack/blockstack-core.git@rc-0.14.2
```

Get Blockstack core configured with default settings and choose your Bitcoin wallet password
```
blockstack setup -y --password BITCOIN_WALLET_PASSWORD --debug
```

# Setting up Blockstack Portal Node Application

Install NodeJS through NodeSource PPA

```
curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
sudo apt install -y nodejs
```

Download Blockstack Portal and install its dependencies

```
git clone https://github.com/blockstack/blockstack-portal.git -bv0.8
cd blockstack-portal
npm install node-sass
npm install
```

Note that `blockstack-portal` depends on `node-sass` which can sometimes install strangely on Linux, running `npm install node-sass` before trying to install the other dependencies solves that problem.

# Running Blockstack Portal

Now we're ready to run our Core API service and start the Portal node app.

First, start the Core API service.

```
blockstack api start -y --password BITCOIN_WALLET_PASSWORD --debug
```

Start the CORS proxy.

```
npm run dev-proxy &
```

Start the Node Application

```
npm run dev
```

Then you can open `http://localhost:3000/` in your browser to get to the portal.


You can copy your api password to your clipboard with this command:
```
grep api_password ~/.blockstack/client.ini | sed 's/api_password = //g' | xclip -selection clipboard
```

