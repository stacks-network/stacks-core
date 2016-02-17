# Blockstack Client

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
$ ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future pip install pycrypto
$ sudo pip install blockstack
```

*Note that the first line is a custom command meant to ensure that pycrypto installs properly.*

### Development Version

The client is under heavy development and you might want to install the latest development version:

```
$ sudo pip install git+https://github.com/blockstack/blockstack-client.git@develop
```

## Usage 

### Getting a List of All Commands

```
$ blockstack
usage: blockstack [-h]
                  {advanced,consensus,cost,lookup,ping,register,server,status,transfer,update,wallet}
                  ...

Blockstack cli version 0.0.12.2

positional arguments:
  {advanced,consensus,cost,lookup,ping,register,server,status,transfer,update,wallet}
    advanced            check advanced mode | turn --mode=off or --mode=on
    consensus           <block number> | get consensus hash at given block
    cost                <name> | get the cost of a name
    lookup              <name> | get data record for a particular name
    ping                check if the blockstack server is up
    register            <name> <data> | register a name
    server              display server:port | change by --server=x --port=y
    status              get basic information from the blockstack server
    transfer            <name> <address> | transfer a name you own
    update              <name> <data> | update a name record
    wallet              display wallet information

optional arguments:
  -h, --help            show this help message and exit
```

## Command Line Interface

### Ping (or Status or Details or Info)

*Note: formerly ping, status, server and consensus*

```
$ blockstack ping/status/details/info
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

*Note: formerly server and advanced*

```
$ blockstack config --server=server.blockstack.org --port=6264 --advanced=false
{
    "success": true
}
```

### Lookup

*Note: formerly lookup and cost*

```
$ blockstack lookup fredwilson.id
{
}
```

### Register

```
$ blockstack register
{
}
```

### Transfer

```
$ blockstack transfer
{
}
```

### Update

```
$ blockstack update
{
}
```

### Wallet

```
$ blockstack wallet
------------------------------------------------------------
Payment address:	1EHgqHVpA1tjn6RhaVj8bx6y5NGvBwoMNS
Owner address:		1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt
------------------------------------------------------------
Balance:
1EHgqHVpA1tjn6RhaVj8bx6y5NGvBwoMNS: 0.05
------------------------------------------------------------
Names Owned:
1Jbcrh9Lkwm73jXyxramFukViEtktwq8gt: []
------------------------------------------------------------
```

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
