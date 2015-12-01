# Blockstore Client

[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

This package contains the reference client library for
[Blockstore](https://github.com/blockstack/blockstore). It talks to blockstored
and provides an interface for creating and managing decentralized namespaces and
registries on the blockchain.

## Installation

The easiest way to get the stable version of blockstore-client is:

> pip install blockstore

Note: This will change to "pip install blockstore-client" once
[#20](https://github.com/blockstack/blockstore-client/issues/20) is resolved.

This will give you both the cli and the client library.

#### Latest version

The client is under heavy development and you might want to install the latest version:

> pip install git+https://github.com/blockstack/blockstore-client.git

## Usage 

For the cli: 

> blockstore-cli 

will give you a complete list of supported commands along with
usage instructions, these include:

* delete_immutable
* delete_mutable
* get_immutable
* get_mutable
* get_name_cost
* get_name_import_cost
* get_namespace_cost
* getindex
* getinfo
* lookup
* name_import
* namespace_begin
* namespace_define
* namespace_preorder
* ping
* preorder
* put_immutable
* put_mutable
* register
* renew
* transfer
* update

For the client library here is some example code to get you started:

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