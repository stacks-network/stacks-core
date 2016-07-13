# Blockstack Command Line Interface

[![PyPI](https://img.shields.io/pypi/v/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![PyPI](https://img.shields.io/pypi/dm/blockstack.svg)](https://pypi.python.org/pypi/blockstack/)
[![PyPI](https://img.shields.io/pypi/l/blockstack.svg)](https://github.com/blockstack/blockstack-client/blob/master/LICENSE)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

This package contains the CLI (command line interface) and reference client library for
[Blockstack Server](https://github.com/blockstack/blockstack-server). It talks to the
Blockstack server and provides an interface for creating and managing names in decentralized namespaces and database tables on the blockchain.

## Installation

Installing the command line interface and client library:

### Debian + Ubuntu

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

Blockstack cli version 0.0.12.4

positional arguments:
    balance             display the wallet balance
    config              configure --server=x --port=y --advanced=on/off
    price               <name> | get the cost of a name
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

### Info (or ping or status)

```bash
$ blockstack info
```

##### Examples

```bash
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

```bash
$ blockstack config <options>
```

##### Examples

```bash
$ blockstack config --host=server.blockstack.org --port=6264 --advanced=off
{
  "message": "Updated settings for host port advanced"
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
    "name_price": 0.001,
    "total_estimated_cost": 0.00116,
    "transaction_fee": 0.00016
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
    "block_preordered_at": 374084,
    "block_renewed_at": 374084,
    "owner_address": "1F2nHEDLRJ39XxAvSxwQhJsaVzvS5RHDRM",
    "owner_public_key": "0411d88aa37a0eea476a5b63ca4b1cd392ded830865824c27dacef6bde9f9bc53fa13a0926533ef4d20397207e212c2086cbe13db5470fd29616abd35326d33090",
    "owner_script": "76a91499e7f97f5d2c77b4f32b4ed9ae0f0385c45aa5c788ac",
    "preorder_transaction_id": "2986ec31ec957692d7f5bc58a3b02d2ac2d1a60039e9163365fc954ff51aeb5a",
    "registered": true
}
```

```bash
$ blockstack whois $(whoami)_$(date +"%m_%d").id
{
  "registered": false
}
```

### Lookup

```bash
$ blockstack lookup <name>
```

##### Examples

```bash
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

```bash
$ blockstack lookup $(whoami)_$(date +"%m_%d").id
{
    "error": "muneeb_02_22.id is not registered"
}
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
{
    "error": "fredwilson.id is already registered"
}
```

### Update

```bash
$ blockstack update <name> <data>
```

##### Examples

```bash
$ blockstack update $(whoami)_$(date +"%m_%d").id '{"cname": [{ "name": "@", "alias": "https://zk9.s3.amazonaws.com" }]}'
{
  "message": "Added to update queue. Takes ~1 hour. You can check status at anytime.",
  "success": true
}
```

```bash
$ blockstack update fredwilson.id '{}'
{
    "error": "fredwilson.id not owned by 1UGQbEV6JXEk1onBzDoNGikrCjeXenA75"
}
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
{
    "error": "fredwilson.id not owned by 1UGQbEV6JXEk1onBzDoNGikrCjeXenA75"
}
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
            "balance": 0.008405000000000001
        }
    ],
    "total_balance": 0.008405000000000001
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
    "names_owned": [],
    "addresses": [
      { "address": "1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt", "names_owned": [] }
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
    "message": "Send bitcoins to the address specified.",
    "address": "1EHgqHVpA1tjn6RhaVj8bx6y5NGvBwoMNS",
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
    "message": "Send the name you want to receive to the address specified.",
    "address": "1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt"
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
