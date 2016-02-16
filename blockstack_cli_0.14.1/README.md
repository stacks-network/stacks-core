# Blockstack Client

[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

This package contains the reference client library for
[Blockstore](https://github.com/blockstack/blockstore). It talks to blockstored
and provides an interface for creating and managing decentralized namespaces and
registries on the blockchain.

## Installation

The easiest way to get the stable version of blockstack-client is:

On Debian or Ubuntu:

> sudo apt-get install -y python-pip python-dev libssl-dev
> sudo pip install blockstack

This will give you both the cli and the client library.

#### Latest version

The client is under heavy development and you might want to install the latest version:

> pip install git+https://github.com/blockstack/blockstack-client.git@develop

## Usage 

For the cli, typing: 

> blockstack

will give you a complete list of supported commands along with
usage instructions.
```
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
```

You can try out commands like: 
```
$ blockstack ping
$ blockstack lookup fredwilson.id
$ blockstack consensus
$ blockstack cost newname.id
$ blockstack server --server=server.blockstack.org
$ blockstack advanced --mode=on
$ blockstack wallet
```

# Client Library

You can also import the blockstack client and write your own programs. Here is some example code to get you started:

```
from blockstack_client import client
from blockstack_client.utils import print_result as pprint
SERVER_IP = '127.0.0.1'
SERVER_PORT = 6264

# start session
client.session(server_host=SERVER_IP, server_port=SERVER_PORT)

resp = client.ping()
pprint(resp)
```