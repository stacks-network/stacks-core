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
$ sudo pip install blockstack
```

### OS X

```
$ sudo pip install blockstack --upgrade
```

If the above install command fails, see the [trouble shooting section](#troubleshooting-installation).

### Development Version

The client is under heavy development and you might want to install the development version.
The development version can have bug fixes for some issues you're experiencing. Anyone
helping with testing and development should also use the development version:

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

Blockstack cli version 0.0.12.2

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
    wallet              display wallet information
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
    "alive": true,
    "advanced_mode": false,
    "cli_version": "0.0.12.2",
    "consensus_hash": "ccf9a90ae7a10dc83a9da7e02213eb20",
    "last_block_processed": 398758,
    "last_block_seen": 398765,
    "server": "server.blockstack.org:6264",
    "server_host": "server.blockstack.org",
    "server_port": 6264,
    "server_version": "0.0.10.1"
}
```

### Config

```
$ blockstack config <options>
```

##### Examples

```
$ blockstack config --server=server.blockstack.org --port=6264 --advanced=false
{
  "message": "Configuration settings updated.",
  "error": false
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
    "fee": 0.01624,
    "registration_fee": 0.016,
    "transaction_fee": 0.00024
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
    "owner_public_keys": ["0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090"],
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
  "data": {
    "$origin": "fredwilson.id",
    "$ttl": "3600",
    "cname": [{ "name": "@", "alias": "https://zk9.s3.amazonaws.com" }]
  }
}
```

```
$ blockstack lookup $(whoami)_$(date +"%m_%d").id
{
  "data": null
}
```

### Register

```
$ blockstack register <name>
```

##### Example

```
$ blockstack register $(whoami)_$(date +"%m_%d").id
Registering ryan_02_17.id will cost 0.0003025 BTC. Continue? (y/n): y
{
    "message": "Name queued up for registration. Please expect a few hours for this process to be completed.",
    "error": false
}
```

```
$ blockstack register fredwilson.id
{
  "message": "Name has already been registered.",
  "error": true
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
  "message": "Data record updated.",
  "error": false
}
```

```
$ blockstack update fredwilson.id '{}'
{
  "message": "That name is not in your possession.",
  "error": true
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
  "message": "Name queued up for transfer.",
  "error": false
}
```

```
$ blockstack transfer fredwilson.id 1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt
{
  "message": "That name is not in your possession.",
  "error": true
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
    "balance": 0.05,
    "addresses": [
      { "address": "1EHgqHVpA1tjn6RhaVj8bx6y5NGvBwoMNS", "balance": 0.05 }
    ]
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
      { "address": "1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt", "names": [] }
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

If you see the following error, while pycrpyto installs:
> error: command 'cc' failed with exit status 1

Try installing it using:
> $ ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future pip install pycrypto

**b) Twisted error when running blockstack**

If you see the following error, when you run '$ blockstack':
> ImportError: Twisted requires zope.interface 3.6.0 or later.

Try uninstalling Twisted from outside of virtualenvironment:
> sudo pip uninstall twisted

And installing blockstack in a new virtualenvironment.

If the issue you are experiencing is not listed here, please [report it as a new issue](https://github.com/blockstack/blockstack-client/issues/new).

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
