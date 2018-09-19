---
layout: core
permalink: /:collection/:path.html
---
# Understand the Architecture

The BNS node is the heart of the system.  It is responsible for building up
and replicating global name state.

There are three parts to BNS that developers should be aware of.  They are:

* **The BNS indexer**.  This module crawls the blockchain and builds
  up its name database.  BNS indexers do not contain any private or sensitive
state, and can be deployed publicly.  We maintain a fleet of them at
`https://node.blockstack.org:6263` for developers to use to get started.

* **The BNS API**.  This module gives
  developers a *stable RESTful API* for interacting with the BNS network.
We provide one for developers to experiment with at `https://core.blockstack.org`.

* **BNS clients**.  These communicate with the BNS API module in order to
  resolve names.  Internally, they generate and send transactions to register
and modify names.

The BNS indexer and BNS API comprise the **BNS node**.  An architectural schematic appears below.

```
                      +-------------------------------------------------------+
            RESTful   | +----------------+             +--------------------+ |
+--------+   API      | |                | private API |                    | |
| client |<------------>| BNS API module |<----------->| BNS indexer module | |
+--------+            | |                |             |                    | |
    |                 | +----------------+             | +----------------+ | |
    |                 |                                | | name database  | | |
    |                 |                                | +----------------+ | |
    |                 |                                +--------------------+ |
    |                 | BNS node                                 ^            |
    |                 +------------------------------------------|------------+
    |                                                            |
    |                                                            v
    |       blockchain transactions                    +--------------------+
    +------------------------------------------------->|   blockchain peer  |
                                                       +--------------------+

Figure 1: BNS architecture overview.  Clients talk to the BNS API module to
resolve names, and generate and send blockchain transactions to register and
modify names.   The API module talks to the indexer module and gives clients
a stable, Web-accessible interface for resolving names.  The indexer module reads
the blochchain via a blockchain peer, over the blockchain's peer network.

Blockstack Core currently implements the API module and indexer module as separate
daemons (`blockstack api` and `blockstack-core`, respectively).  However, this
is an implementation detail, and may change in the future.
```

The BNS indexer implements the blockchain consensus rules and network protocols.
Its main responsibility is to build up and replicate all of the name state.  It does
not have any public APIs of its own.

The BNS API modules allows users and developers to resolve names via a RESTful
interface.  Resolution can be done with vanilla `curl` or `wget`.
BNS applications should use the BNS API module for name resolution.
They should not attempt to talk to a BNS indexer directly, because its API is not stable and is not meant
for consumption by any other process except for the API module.

Registering and managing names require generating and sending blockchain
transactions, which requires running a BNS client.  We provide two reference
BNS clients:

* The [Blockstack Browser](https://github.com/blockstack/blockstack-browser) gives users
and developers a graphical UI to resolve, register and manage names.  This is the recommended
way to interact with BNS.
* The Blockstack CLI gives developers low-level
control over resolving, registering, and managing names.
A new CLI that uses [blockstack.js](https://github.com/blockstack/blockstack.js)
is under development, and will replace the existing CLI program.

We recommend that new developers use the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser).

Developers who want to make their own client programs that do not use
the reference client library code should read the
[BNS transaction wire format]({{ site.baseurl }}/core/wire-format.html) document for generating and
sending their own transactions.

The examples in this document focus on resolving names using `curl`.  We refer
the reader to client-specific documentation for registering and managing names.
