# Blockstack Client

[![PyPI](https://img.shields.io/pypi/v/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![PyPI](https://img.shields.io/pypi/dm/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![PyPI](https://img.shields.io/pypi/l/blockstack.svg)](https://github.com/blockstack/blockstack-client/blob/master/LICENSE)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

This package contains the reference client library for
[blockstack-server](https://github.com/blockstack/blockstack-server). It talks to the
server and provides an interface for creating and managing names in decentralized namespaces on the blockchain.

## Installation

Installing the command line interface and the client library:

### Debian + Ubuntu

```
$ sudo apt-get update && sudo apt-get install -y python-pip python-dev libssl-dev
$ sudo pip install blockstack --upgrade
```

### OS X

```
$ sudo pip install blockstack --upgrade
```

If the above install command fails, see the [trouble shooting section](#troubleshooting-installation).

### Development Version

The client is under heavy development and you might want to install the development version.
The development version can have bug fixes for some issues you're experiencing. Anyone
helping with testing and development should also use the development version.

On Debian/Ubuntun first install required packages:
> sudo apt-get update && sudo apt-get install -y python-pip python-dev libssl-dev git

Now, install the development version:
```
$ pip install git+https://github.com/blockstack/blockstack-client.git@develop --upgrade
$ pip install git+https://github.com/blockstack/registrar.git@develop --upgrade

```

If the above install commands fail, see the [trouble shooting section](#troubleshooting-installation).

## Command Line Usage 

### Listing All Commands

```
$ blockstack
usage: blockstack [-h]
                  ...

Blockstack cli version 0.0.12.4

positional arguments:
  balance             display the wallet balance
  config              configure --server=x --port=y --advanced=on/off
  cost                <name> | get the cost of a name
  deposit             display the address with which to receive bitcoins
  import              display the address with which to receive names
  info                check server status and get details about the server
  lookup              <name> | get the data record for a particular name
  names               display the names owned by local addresses
  register            <name> | register a new name
  transfer            <name> <address> | transfer a name you own
  update              <name> <data> | update a name record with new data
  whois               <name> | get the registration record of a name

optional arguments:
  -h, --help            show this help message and exit

```

### Info  (or ping or status)

```
$ blockstack info
```

##### Examples

```
$ blockstack info
{
    "advanced_mode": "off",
    "cli_version": "0.0.12.4",
    "consensus_hash": "4520fbed8459cc9fe6ef1161d683bf0b",
    "last_block_processed": 399610,
    "last_block_seen": 399616,
    "server_alive": true,
    "server_host": "server.blockstack.org",
    "server_port": "6264",
    "server_version": "0.0.10.3"
}
```

### Config

```
$ blockstack config <options>
```

##### Examples

```
$ blockstack config --host=server.blockstack.org --port=6264 --advanced=off
{
  "message": "Updated settings for host port advanced"
}
```

### Cost

```
$ blockstack cost <name>
```

##### Examples

```
$ blockstack cost $(whoami).id
{
    "details": {
        "registration_fee": 0.001,
        "transactions_fee": 0.00016
    },
    "total_cost": 0.00116
}
```

### Whois

```
$ blockstack whois <name>
```

##### Examples

```
$ blockstack whois fredwilson.id
{
    "block_preordered_at": 374084,
    "block_renewed_at": 374084,
    "owner_address": "1F2nHEDLRJ39XxAvSxwQhJsaVzvS5RHDRM",
    "owner_public_key": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090",
    "owner_script": "76a91499e7f97f5d2c77b4f32b4ed9ae0f0385c45aa5c788ac",
    "preorder_transaction_id": "2986ec31ec957692d7f5bc58a3b02d2ac2d1a60039e9163365fc954ff51aeb5a",
    "registered": true
}
```

```
$ blockstack whois $(whoami)_$(date +"%m_%d").id
{
  "registered": false
}
```

### Lookup

```
$ blockstack lookup <name>
```

##### Examples

```
$ blockstack lookup fredwilson.id
{
    "data_record": {
        "avatar": {
            "url": "https://s3.amazonaws.com/kd4/fredwilson1"
        },
        "bio": "I am a VC",
   ...
}

```

```
$ blockstack lookup $(whoami)_$(date +"%m_%d").id
{
    "error": "muneeb_02_22.id is not registered"
}
```

### Register

```
$ blockstack register <name>
```

##### Example

```
$ blockstack register $(whoami)_$(date +"%m_%d").id
Registering muneeb_02_22.id will cost 0.0002225 BTC. Continue? (y/n): y
{
    "message": "Added to registration queue. Takes several hours. You can check status at anytime.",
    "success": true
}
```

```
$ blockstack register fredwilson.id
{
    "error": "fredwilson.id is already registered"
}
```

### Update

```
$ blockstack update <name> <data>
```

##### Examples

```
$ blockstack update $(whoami)_$(date +"%m_%d").id '{"cname": [{ "name": "@", "alias": "https://zk9.s3.amazonaws.com" }]}'
{
  "message": "Added to update queue. Takes ~1 hour. You can check status at anytime.",
  "success": true
}
```

```
$ blockstack update fredwilson.id '{}'
{
    "error": "fredwilson.id not owned by 1UGQbEV6JXEk1onBzDoNGikrCjeXenA75"
}
```

### Transfer

```
$ blockstack transfer <name> <address>
```

##### Examples

```
$ blockstack transfer $(whoami)_$(date +"%m_%d").id 1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt
{
  "message": "Added to transfer queue. Takes ~1 hour. You can check status at anytime.",
  "success": true
}
```

```
$ blockstack transfer fredwilson.id 1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt
{
    "error": "fredwilson.id not owned by 1UGQbEV6JXEk1onBzDoNGikrCjeXenA75"
}
```

### Balance

```
$ blockstack balance
```

##### Examples

```
$ blockstack balance
{
    "addresses": [
        {
            "address": "16yE3e928JakaXbympwSywyrJPM9cuL4wZ",
            "balance": 0.008405000000000001
        }
    ],
    "total_balance": 0.008405000000000001
}
```

### Names

```
$ blockstack names
```

##### Examples

```
$ blockstack names
{
    "names_owned": [],
    "addresses": [
      { "address": "1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt", "names_owned": [] }
    ]
}
```

### Deposit

```
$ blockstack deposit
```

##### Examples

```
$ blockstack deposit
{
    "message": "Send bitcoins to the address specified.",
    "address": "1EHgqHVpA1tjn6RhaVj8bx6y5NGvBwoMNS",
}
```

### Import

```
$ blockstack import
```

##### Examples

```
$ blockstack import
{
    "message": "Send the name you want to receive to the address specified.",
    "address": "1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt"
}
```

## Troubleshooting Installation

**a) Error installing pycrypto**

If you see the following error, while pycrpyto installs on OS X:
> error: command 'cc' failed with exit status 1

Try installing it using:
> $ ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future pip install pycrypto

**b) Twisted error when running blockstack**

If you see the following error, when you run '$ blockstack':
> ImportError: Twisted requires zope.interface 3.6.0 or later.

Then you're trying to install inside of a virtualenvironment and Twisted is
already installed outside. Exit the virtualenvironment and uninstall Twisted:
```
$ deactivate
$ sudo pip uninstall twisted
```
Now, install blockstack in a new virtualenvironment.

If the issue you are experiencing is not listed here, please
[report it as a new issue](https://github.com/blockstack/blockstack-client/issues/new).

## Client Library

You can also import the blockstack client and write your own programs.

Here is some example code to get you started:

```
from blockstack_client import client
from blockstack_client.utils import print_result as pprint

client.session(server_host='127.0.0.1', server_port=6264)
resp = client.ping()
pprint(resp)
```
