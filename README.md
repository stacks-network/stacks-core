# Blockstore: Name Registrations on the Bitcoin Blockchain

[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)
[![PyPI](https://img.shields.io/pypi/v/blockstore.svg)](https://pypi.python.org/pypi/blockstore/)
[![PyPI](https://img.shields.io/pypi/dm/blockstore.svg)](https://pypi.python.org/pypi/blockstore/)

Blockstore enables human-readable name registrations on the Bitcoin blockchain, along with the ability to store associated data in external datastores. You can use it to register globally unique names, associate data with those names, and transfer them between Bitcoin addresses. Anyone can perform lookups on those names and securely obtain the data associated with them.

Blockstore uses the Bitcoin blockchain for storing name operations and data hashes, and the Kademlia-based distributed hash table (DHT) and other external datastores for storing the full data files outside of the blockchain.

## Installation

The fastest way to get started with blockstore is to use a docker image:

```
docker run -it --entrypoint=/bin/bash blockstack/blockstored
```

The docker image comes pre-populated with a snapshot that was processed till a recent block and you won't have to process all the blocks yourself (takes time). Alternatively, you can install a version on your machine directly:

```
pip install blockstore
```

## Getting Started

Start blockstored and index the blockchain:

```
$ blockstored start
```

Then, perform name lookups:

```
$ blockstore-cli lookup swiftonsecurity
{
    "data": "{\"name\":{\"formatted\": \"Taylor Swift\"}}"
}
```

Next, learn how to register names of your own, as well as transfer them and associate data with them:

[Full usage docs](../../wiki/Usage)

## Design

[Design decisions](../../wiki/Design-Decisions)

[Protocol details](../../wiki/Protocol-Details)

[Definitions](../../wiki/Definitions)

[FAQ](../../wiki/FAQ)

## Contributions

The best way to contribute is to:

1. decide what changes you'd like to make (you can find inspiration in the tab of issues)
1. fork the repo
1. make your changes
1. submit a pull request

[Code contributors](../../graphs/contributors)

[Full contributor list](../../wiki/Contributors)

## License

GPL v3. See LICENSE.

Copyright: (c) 2015 by Blockstack.org
