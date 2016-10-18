# Blockstack Command Line Interface

[![PyPI](https://img.shields.io/pypi/v/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![PyPI](https://img.shields.io/pypi/l/blockstack.svg)](https://github.com/blockstack/blockstack-client/blob/master/LICENSE)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

This package contains the CLI (command line interface) and reference client library for
[Blockstack Server](https://github.com/blockstack/blockstack-server). It talks to the
Blockstack server and provides an interface for creating and managing names in decentralized namespaces and database tables on the blockchain.

## Installation

Installing the command line interface and client library:

### Debian + Ubuntu

Via APT:
```
$ curl https://raw.githubusercontent.com/blockstack/packaging/master/repo-key.pub | sudo apt-key add -
$ sudo sh -c "echo \"deb http://packages.blockstack.com/repositories/ubuntu xenial main\" > /etc/apt/sources.list.d/blockstack.list"
$ sudo apt-get update
$ sudo apt-get install blockstack
```

Via pip:
```
$ sudo apt-get update && sudo apt-get install -y python-pip python-dev libssl-dev libffi-dev
$ sudo pip install blockstack --upgrade
```

### OS X

```bash
$ brew install libffi openssl
$ sudo pip install blockstack --upgrade
```

We recommend installing the CLI inside of a [virtual environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/), in which case you can drop the "sudo" at the beginning like so:

```bash
$ pip install blockstack --upgrade
```

If the installation command above fails, see the [troubleshooting section](#troubleshooting-installation).

## Command Line Usage 

### Listing All Commands

```bash
$ blockstack
usage: blockstack [-h]
                  ...

Blockstack cli version 0.0.13.3
positional arguments:
    balance             Get the account balance
    configure           Interactively configure the client
    deposit             Display the address with which to receive bitcoins
    import              Display the address with which to receive names
    info                Get details about pending name commands
    lookup              Get the zone file and profile for a particular name
    migrate             Migrate a profile to the latest profile format
    names               Display the names owned by local addresses
    ping                Check server status and get server details
    price               Get the price of a name
    register            Register a name
    renew               Renew a name
    revoke              Revoke a name
    set_advanced_mode   Enable advanced commands
    transfer            Transfer a name to a new address
    update              Set the zone file for a name
    whois               Look up the blockchain info for a name

optional arguments:
  -h, --help            show this help message and exit
```

### Info (or ping or status)

```bash
$ blockstack info
```

##### Examples

```bash
$ blockstack info
{
    "advanced_mode": false,
    "cli_version": "0.0.13.3",
    "consensus_hash": "106d4648661d49e16d103b071e26617e",
    "last_block_processed": 420518,
    "last_block_seen": 420596,
    "server_alive": true,
    "server_host": "40.76.8.249",
    "server_port": "6264",
    "server_version": "0.0.13.0"
}
```

### Config

```bash
$ blockstack configure
```

##### Examples

```bash
$ blockstack  configure
---------------------------------------------------------
Your client does not have enough information to connect
to a Blockstack server.  Please supply the following
parameters, or press [ENTER] to select the default value.
---------------------------------------------------------
blockchain_headers (default: '/home/jude/.blockstack/blockchain-headers.dat'): 
blockchain_writer (default: 'blockcypher'): 
api_endpoint_port (default: '6270'): 
poll_interval (default: '300'): 
metadata (default: '/home/jude/.blockstack/metadata'): 
server (default: 'node.blockstack.org'): 
advanced_mode (default: 'False'): 
blockchain_reader (default: 'blockcypher'): 
email (default: ''): 
rpc_token (default: '2dbf700c6c0d546be23ad7ae4e5e1bbb6cdaa10a3ae4deca8e598bf9ec58fc6a'): 
storage_drivers_required_write (default: 'disk,blockstack_server'): 
queue_path (default: '/home/jude/.blockstack/queues.db'): 
storage_drivers (default: 'disk,blockstack_resolver,blockstack_server,http,dht'): 
path (default: '/home/jude/.blockstack/client.ini'): 
client_version (default: '0.0.13.4'): 
rpc_detach (default: 'True'): 
port (default: '6264'): 
dir (default: '/home/jude/.blockstack/client.ini'): 
anonymous_statistics (default: 'True'): 
--------------------------------------------------------
Blockstack does not have enough information to connect
to bitcoind.  Please supply the following parameters, or
press [ENTER] to select the default value.
--------------------------------------------------------
mock (default: 'False'): 
passwd (default: 'blockstacksystem'): 
server (default: 'bitcoin.blockstack.com'): 
user (default: 'blockstack'): 
timeout (default: '300.0'): 
port (default: '8332'): 
use_https (default: 'False'): 
-------------------------------
Blockchain reader configuration
----------------------------------------
Please enter your Blockcypher API token.
----------------------------------------
api_token (default: ''): 
-------------------------------
Blockchain writer configuration
----------------------------------------
Please enter your Blockcypher API token.
----------------------------------------
api_token (default: ''): 
Saving configuration to /home/jude/.blockstack/client.ini
{
    "path": "/home/jude/.blockstack/client.ini"
}
```

### Cost

```bash
$ blockstack price <name>
```

##### Examples

```bash
$ blockstack price $(whoami).id
{
    "name_price": 25000,
    "preorder_tx_fee": 13255,
    "register_tx_fee": 12309,
    "total_estimated_cost": 71480,
    "update_tx_fee": 20916
}
```

### Whois

```bash
$ blockstack whois <name>
```

##### Examples

```bash
$ blockstack whois fredwilson.id
{
    "approx_expiration_date": "2016 Sep 11 09:02:31 UTC",
    "block_preordered_at": 374084,
    "block_renewed_at": 374084,
    "expire_block": 426679,
    "has_zonefile": true,
    "last_transaction_id": "2986ec31ec957692d7f5bc58a3b02d2ac2d1a60039e9163365fc954ff51aeb5a",
    "owner_address": "1F2nHEDLRJ39XxAvSxwQhJsaVzvS5RHDRM",
    "owner_script": "76a91499e7f97f5d2c77b4f32b4ed9ae0f0385c45aa5c788ac",
    "zonefile_hash": "1a587366368aaf8477d5ddcea2557dcbcc67073e"
}
```

```bash
$ blockstack whois $(whoami)_$(date +"%m_%d").id
Not found.
```

### Lookup

```bash
$ blockstack lookup <name>
```

##### Examples

```bash
$ blockstack lookup fredwilson.id
{
    "profile": {
        "avatar": {
            "url": "https://s3.amazonaws.com/kd4/fredwilson1"
        },
        "bio": "I am a VC",
   ...
}

```

```bash
$ blockstack lookup $(whoami)_$(date +"%m_%d").id
Not found.
```

### Register

```bash
$ blockstack register <name>
```

##### Example

```bash
$ blockstack register $(whoami)_$(date +"%m_%d").id
Registering muneeb_02_22.id will cost 0.0002225 BTC. Continue? (y/n): y
{
    "message": "Added to registration queue. Takes several hours. You can check status at anytime.",
    "success": true
}
```

```bash
$ blockstack register fredwilson.id
fredwilson.id is already registered.
```

### Update

```bash
$ blockstack update <name> <data>
```

##### Examples

```bash
$ blockstack update muneeb.id '{"$origin": "muneeb.id", "$ttl": "3600", "uri": [{"name": "@", "priority": "10", "weight": "1", "target": "https://muneeb.ali/muneeb.id"}]}'
{
  "message": "Added to update queue. Takes ~1 hour. You can check status at anytime.",
  "success": true
}
```

```bash
$ blockstack update fredwilson.id '{}'
Invalid $origin; must use your name

$ blockstack update fredwilson.id '{"$origin": "fredwilson.id"}'
Missing $ttl; please supply a positive integer

$ blockstack update fredwilson.id '{"$origin": "fredwilson.id", "$ttl": "3600"}'
Zonefile is missing or has invalid URI and/or TXT records

$ blockstack update fredwilson.id '{"$origin": "fredwilson.id", "$ttl": "3600", "uri": [{"name": "@", "priority": "10", "weight": "1", "target": "https://blockstack.s3.amazonaws.com/fredwilson.id"}]}'
fredwilson.id is not in your possession.
```

### Transfer

```bash
$ blockstack transfer <name> <address>
```

##### Examples

```bash
$ blockstack transfer $(whoami)_$(date +"%m_%d").id 1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt
{
  "message": "Added to transfer queue. Takes ~1 hour. You can check status at anytime.",
  "success": true
}
```

```bash
$ blockstack transfer fredwilson.id 1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt
fredwilson.id is not in your possession.
```

### Balance

```bash
$ blockstack balance
```

##### Examples

```bash
$ blockstack balance
{
    "addresses": [
        {
            "address": "16yE3e928JakaXbympwSywyrJPM9cuL4wZ",
            "balance": 840500
        }
    ],
    "total_balance": 840500.0
}
```

### Names

```bash
$ blockstack names
```

##### Examples

```bash
$ blockstack names
{
    "addresses": [
        {
            "address": "16CtpS8LhmW3bGtVC69UGZ3wSwvi95BE8E",
            "names_owned": [
                "testregistration001.id",
                "testregistration002.id"
            ]
        }
    ],
    "names_owned": [
        "testregistration001.id",
        "testregistration002.id"
    ]
}
```

### Deposit

```bash
$ blockstack deposit
```

##### Examples

```bash
$ blockstack deposit
{
    "address": "1EHgqHVpA1tjn6RhaVj8bx6y5NGvBwoMNS",
    "message": "Send bitcoins to the address specified.",
}
```

### Import

```bash
$ blockstack import
```

##### Examples

```bash
$ blockstack import
{
    "address": "1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt"
    "message": "Send the name you want to receive to the address specified.",
}
```

## Troubleshooting Installation

**a) Error installing pycrypto**

If you see the following error, while pycrpyto installs on OS X:

```bash
error: command 'cc' failed with exit status 1
```

Try installing it with the following:

```bash
$ ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future pip install pycrypto
```

**b) Twisted error when running blockstack**

If you see the following error, when you run '$ blockstack':

```bash
ImportError: Twisted requires zope.interface 3.6.0 or later.
```

Try upgrading zope.interface:

```bash
$ pip install zope.interface --upgrade
```

If this doesn't solve the issue and you're trying to install Blockstack inside
a virtual environment, then Twisted is likely already installed outside of the
virtual environment, so exit the virtual environment and uninstall Twisted:

```bash
$ deactivate
$ sudo pip uninstall twisted
```

Now, install blockstack in a new virtual environment.

If the issue you are experiencing is not listed here, please
[report it as a new issue](https://github.com/blockstack/blockstack-client/issues/new).

## Running Your Server

The CLI by default talks to a remote server, but you can easily start your own server.

Open a new terminal window and run the following command:

```bash
$ blockstack-server start --foreground
```

You can now switch the cli to use the local server:

```bash
$ blockstack config --host=localhost
```

[More information on the Blockstack Server(http://github.com/blockstack/blockstack-server)

## Client Library

You can also import the blockstack client and write your own programs.

Here is some example code to get you started:

```python
from blockstack_client import client
from blockstack_client.utils import print_result as pprint

client.session(server_host='127.0.0.1', server_port=6264)
resp = client.ping()
pprint(resp)
```
