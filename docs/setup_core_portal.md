# Install Script

We provide a [script](../images/scripts/ubuntu-17.04.sh) which will
perform all the steps outlined in this doc (except for creating a protocol handler -- see the bottom of the doc). The script creates a virtualenv of
Blockstack Core and installs Portal in a subdirectory. It additionally creates some
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

## Setting up a protocol handler

If you'd like your browser to automatically handle links with the `blockstack:` protocol specifier, you will need to register a protocol handler with your desktop environment. In Ubuntu/Gnome, this can be done by creating a file 

`~/.local/share/applications/blockstack.desktop`

With the following contents:

```
[Desktop Entry]
Type=Application
Terminal=false
Exec=bash -c 'xdg-open http://localhost:3000/auth?authRequest=$(echo "%u" | sed s/blockstack://)'
Name=Blockstack-Portal
MimeType=x-scheme-handler/blockstack;
```

Then you need to make this file executable, and register it as a protocol handler.

```
$ chmod +x ~/.local/share/applications/blockstack.desktop
$ xdg-mime default blockstack.desktop x-scheme-handler/blockstack
```

Now, `blockstack:` protocol URLs should get handled by your Blockstack Portal. If you're running Portal in your browser's private mode, you may have to copy and paste the link, as this protocol handler will try to open in a regular browser window.
