# About

This document is for **Linux users who do not want to use Docker** to run the
Blockstack Browser.  Instructions are tailored for Ubuntu, but are similar on other distributions.

# Setting up Blockstack Browser Node Application

Install NodeJS through NodeSource PPA

```
curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
sudo apt install -y nodejs
```

Download Blockstack Browser and install its dependencies

```
git clone https://github.com/blockstack/blockstack-browser.git
cd blockstack-browser
npm install node-sass
npm install
```

Note that `blockstack-browser` depends on `node-sass` which can sometimes install strangely on Linux, running `npm install node-sass` before trying to install the other dependencies solves that problem.

# Running Blockstack Browser

Start the CORS proxy.

```
npm run dev-proxy &
```

Start the Node Application

```
npm run dev
```

Then you can open `http://localhost:3000/` in your browser to get to the Blockstack Browser.


## Setting up a protocol handler

If you'd like your browser to automatically handle links with the `blockstack:` protocol specifier, you will need to register a protocol handler with your desktop environment. In Ubuntu/Gnome, this can be done by creating a file 

`~/.local/share/applications/blockstack.desktop`

With the following contents:

```
[Desktop Entry]
Type=Application
Terminal=false
Exec=bash -c 'xdg-open http://localhost:3000/auth?authRequest=$(echo "%u" | sed s,blockstack:////*,,)'
Name=Blockstack-Browser
MimeType=x-scheme-handler/blockstack;
```

Then you need to make this file executable, and register it as a protocol handler.

```
$ chmod +x ~/.local/share/applications/blockstack.desktop
$ xdg-mime default blockstack.desktop x-scheme-handler/blockstack
```

Now, `blockstack:` protocol URLs should get handled by your Blockstack Browser. If you're running Browser in your browser's private mode, you may have to copy and paste the link, as this protocol handler will try to open in a regular browser window.
