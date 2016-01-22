# Blockstore Client

[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

This package contains the reference client library for
[Blockstore](https://github.com/blockstack/blockstore). It talks to blockstored
and provides an interface for creating and managing decentralized namespaces and
registries on the blockchain.

## Installation

The easiest way to get the stable version of blockstore-client is:

> pip install blockstore-client

This will give you both the cli and the client library.

#### Latest version

The client is under heavy development and you might want to install the latest version:

> pip install git+https://github.com/blockstack/blockstore-client.git@develop

## Usage 

For the cli, typing: 

> blockstore

will give you a complete list of supported commands along with
usage instructions.
```
  server              display server:port | update using --server --port
  advanced            check advanced mode | turn --mode=off or --mode=on
  consensus           <block height> | get consensus hash at given block
  cost                <name> | get the cost of a name
  getinfo             get basic info from the blockstored server
  lookup              <name> | get name record for a particular name
  ping                check if the blockstored server is up
  preorder            <name> <private_key> | preorder a name
  register            <name> <private_key> <addr> | register/claim a name
  transfer            <name> <address> <private_key> | transfer a name
  update              <name> <data> <private_key> | update a name record
```

You can try out commands like: 
```
$ blockstore ping
$ blockstore lookup fredwilson.id
$ blockstore consensus
$ blockstore cost newname.id
$ blockstore server --server=localhost
$ blockstore advanced --mode=on
```

# Client Library

You can also import the blockstore client and write your own programs. Here is some example code to get you started:

```
from blockstore_client import client
from blockstore_client.utils import print_result as pprint
BLOCKSTORED_SERVER = '127.0.0.1'
BLOCKSTORED_PORT = 6264

# start session
client.session(server_host=BLOCKSTORED_SERVER, server_port=BLOCKSTORED_PORT)

resp = client.ping()
pprint(resp)
```
