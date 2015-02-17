# Blockstore: A Key-Value Store on Bitcoin

Blockstore is a generic key-value store on Bitcoin. You can use it register globally unique names, associate data with those names, and transfer them between Bitcoin addresses.

Then, you or anyone can perform lookups on those names and securely obtain the data associated with them.

Blockstore uses the Bitcoin blockchain for storing name operations and data hashes, and the Kademlia distributed hash table for storing the full data files.

## Installation

```
pip install blockstore
```

## Getting Started

First, start blockstored and index the blockchain:

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

[Full usage docs](/doc/usage.md)

## Design

[Design overview](/doc/design.md)

[Protocol specifications](/doc/protocol.md)

## Contributions

[Full contributor list](/doc/contributors.md)

## License

[Released under the MIT License](/LICENSE)

Copyright 2015, openname.org
