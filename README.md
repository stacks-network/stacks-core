# Blockstack Client

[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

This package contains the reference client library for
[Blockstore](https://github.com/blockstack/blockstore). It talks to blockstored
and provides an interface for creating and managing decentralized namespaces and
registries on the blockchain.

## Installation

The easiest way to get the stable version of blockstack-client is:

> pip install blockstack

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
  server              display server:port | change by --server=x --port=y
  advanced            check advanced mode | turn --mode=off or --mode=on
  consensus           <block number> | get consensus hash at given block
  cost                <name> | get the cost of a name
  status              get basic information from the blockstack server
  lookup              <name> | get name record for a particular name
  ping                check if the blockstack server is up
  register            <name> <private_key> <addr> | register/claim a name
  transfer            <name> <address> <private_key> | transfer a name
  update              <name> <data> <private_key> | update a name record
```

You can try out commands like: 
```
$ blockstack ping
$ blockstack lookup fredwilson.id
$ blockstack consensus
$ blockstack cost newname.id
$ blockstack server --server=localhost
$ blockstack advanced --mode=on
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