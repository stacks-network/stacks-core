# Blockstore: A Blockchain Key-Value Store

__Table of Contents__

- [Intro](<#intro>)
- [Installation](<#installation>)
- [Getting Started](<#getting-started>)
- [Design](<#design>)
- [Contributions](<#contributions>)
- [License](<#license>)

## Intro

#### What this project is

A key-value store on the Bitcoin Blockchain.

#### What this repo contains

+ code for running a node that participates in the KV store network
    + blockstored
+ code for issuing commands to blockstored like name lookups and name registrations
    + blockstore-cli
    + blockstore python lib

## Installation

> pip install blockstore

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