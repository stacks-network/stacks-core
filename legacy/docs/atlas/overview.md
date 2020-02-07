---
layout: core
permalink: /:collection/:path.html
---
#  Overview of the Atlas network
{:.no_toc}

This document describes the Atlas network, a peer-to-peer content-addressed
storage system whose chunks' hashes are announced on a public blockchain. Atlas
allows users and developers to **permanently store** chunks of data that are
**replicated across every peer.**  As long as at least one Atlas peer is online,
all chunks are available to clients.

This document is aimed at developers and technical users.  The following
concepts are discussed:

* TOC
{:toc}

The reader of this document is expected to be familiar with the [Blockstack Naming Service]({{site.baseurl}}/core/naming/introduction.html)(BNS), as well as Blockstack's
storage system [Gaia](https://github.com/blockstack/gaia).  We advise the reader
to familiarize themselves with both systems before approaching this document.

## Architecture

Atlas is designed to integrate with BNS in order to allow users to
store name state off-chain, encoded as a DNS zone file.
The overwhelmingly-common use-cases in Blockstack are:

* Storing a name's routing information for its owners' [Gaia](https://github.com/blockstack/gaia)
datastores.
* Storing BNS subdomain transactions and associated state.

Atlas is a middleware system in Blockstack.  Most developers do not
interact with it directly.  BNS clients like the
[Blockstack Browser](https://github.com/blockstack/blockstack-browser)
automatically generate zone files for the names they register, and automatically
propagate them to the Atlas network.  BNS API endpoints, including our
[public endpoint](https://core.blockstack.org) and the
[blockstack.js](https://github.com/blockstack/blockstack.js) library,
will automatically fetch zone files from Atlas when they need to look
up data in Gaia (such as profiles and app data).

```
               +--------------+       +---------------+       +----------------+
clients        |  Blockstack  |       | blockstack.js |       | BNS API module |
               |    Browser   |       |               |       |                |
               +--------------+       +---------------+       +----------------+
                 ^          ^           ^           ^           ^            ^
                 |          |           |           |           |            |
                 |          |           |           |           |            |
                 V          |           V           |           V            |
          +----------+      |    +----------+       |    +----------+        |
Gaia      | Gaia hub |      |    | Gaia hub |       |    | Gaia hub |        |
          +----------+      |    +----------+       |    +----------+        |
                            |                       |                        |
                            |                       |                        |
                            V                       V                        V
               +---------------------------------------------------------------+
Atlas          |                      Atlas Peer Network                       |
               +----------+------+----------+-----+----------+------+----------+
BNS            | BNS node |      | BNS node |     | BNS node |      | BNS node |
               +----------+      +----------+     +----------+      +----------+
                    ^                 ^                ^                 ^
                    | (indexing       |                |                 |
                    |  blockchain)    |                |                 |
               +---------------------------------------------------------------+
Blockchain     |                    Blockchain Peer Network                    |
               +---------------------------------------------------------------+


Figure 1:  Location of Atlas in the Blockstack architecture.  Each BNS node
implements an Atlas peer.  An Atlas peer treats a name state value in BNS as
the hash of a DNS zone file.  Atlas peers exchange zone files with one another
until they each have a full replica of all known zone files.  Clients can look
up zone files for names using the name's stat value as a zone file hash.  Clients
can broadcast zone files to the network  if they match a previously-announced
hash.  In practice, zone files store URLs to a name owner's Gaia hubs, thereby
allowing Blockstack apps to read and write data in Gaia.
```

Nevertheless, Atlas is a general-purpose content-addressed storage
system that advanced developers can use to **host data in an immutable
and durable manner.**  Beyond its default use-case in Blockstack,
Atlas is ideal for tasks like:

* Announcing PGP public keys under a human-readable name
* Storing package hashes for a software release
* Securely deploying shell scripts to remote VMs
* Binding human-readable names to Tor .onion addresses
  ([example](https://github.com/blockstack-packages/blockstack-tor))

## Motivation

Atlas was designed to augment BNS.  BNS allows each name to store a small
amount of state---on the order of 20 bytes.  The size is so small because the
state must be recorded to a public blockchain, where the cost per byte is
high and the blockchain protocol limits the size of transactions.

To compensate for this, we developed an off-chain storage system allows BNS
names to bind and store a large amount of state to each name in a way that
*preserves the security properties of having written that state to the
blockchain*.  Instead of storing 20 bytes of data on the blockchain, a BNS name
owner would store the *cryptograhpic hash* of its state, and then store the actual state
Atlas.  This decouples the name's state size from the blockchain.

The reference implementation of Atlas currently allows up to 40kb of state to be
bound to a BNS name, instead of a measly 20 bytes.  The 40kb of data is
replicated to each BNS node, where it is stored forever.

## Feature Comparison

Atlas is not the only peer-to-peer content-addressible chunk store in existance.  The following
feature table describes Atlas in relation to other popular chunk stores.

| **Features**                | Atlas | BitTorrent | [DAT](https://datproject.org/) | [IPFS](https://ipfs.io) | [Swarm](https://github.com/ethersphere/swarm) |
|-----------------------------|-------|------------|--------------------------------|-------------------------|-----------------------------------------------|
| Each peer stores all chunks | X     | X          |        |                         |                                               |
| Replicas are permanent [1]  | X     | X          | X  |    |    |
| Replicas are free           |       | X          | X  | X   |   |
| Sybil-resistant chunk discovery | X | X          |    |    | X |
| Sybil-resistant peer discovery  | X |  |  |  |  |
| Fixed chunk size             | X      |          | X   |  X  |   X  |

[1] Here, "permanent" means that once a peer has data, they will never evict it
as part of the protocol.
