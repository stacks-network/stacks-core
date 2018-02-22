# Atlas Network

This document describes the Atlas network, a peer-to-peer content-addressed
storage system whose chunks' hashes are announced on a public blockchain.
Atlas allows users and developers to **permanently store** chunks of data that are 
**replicated across every peer.**  As long as at least one Atlas peer is online,
all chunks are available to clients.

This document is aimed at developers and technical users.  The following
concepts are discussed:

* What the Atlas network offers developers
* How to load and store data in the Atlas network
* How the Atlas network works internally
* How the Atlas network compares to related content-addressed storage systems

The reader of this document is expected to be familiar with the [Blockstack
Naming Service](blockstack_naming_service.md) (BNS), as well as Blockstack's
storage system [Gaia](https://github.com/blockstack/gaia).  We advise the reader
to familiarize themselves with both systems before approaching this document.

# Introduction 

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
[public](https://core.blockstack.org) endpoint and the
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

# Motivation

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

# How to Use the Atlas Network

While the Blockstack software stack expects that Atlas-hosted data is made up of
DNS zone files, Atlas itself does not enforce this (nor does it care about the
format of its chunks).  It is designed as a general-purpose chunk store.
Nevertheless, the ubiquitous use of Atlas to store data as DNS zone files has
had an influence on its API design---fields and method names frequently allude
to zone files and zone file hashes.  This is intentional.

The [public BNS API endpoint](https://core.blockstack.org) does not support
resolving Atlas chunks that do not encode Gaia routing information or subdomain
information.  To directly interact with Atlas, developers will need to install
[Blockstack Core](https://github.com/blockstack/blockstack-core) and use its
Python client libraries for these examples.

## Looking up Chunks

All Atlas chunks are addressed by the RIPEMD160 hash of the SHA256 hash of the
chunk data.  A client can query up to 100 chunks in one RPC call.

A client can look up a chunk with the `get_zonefiles()` method.  If successful,
the returned payload will be a `dict` with a `zonefiles` key that maps the chunk
hashes to their respective data.

```python
>>> import blockstack
>>> data = blockstack.lib.client.get_zonefiles('https://node.blockstack.org:6263', ['1b89a685f4c4ea245ce9433d0b29166c22175ab4'])
>>> print data['zonefiles']['1b89a685f4c4ea245ce9433d0b29166c22175ab4']
$ORIGIN duckduckgo_tor.id
$TTL 3600
tor TXT "3g2upl4pq6kufc4m.onion"

>>>
```

(This particular chunk happens to be associated with the BNS name
`duckduckgo_tor.id`).

## Adding a New Chunk

The only way to add a chunk to Atlas is to do so through an on-chain name in
BNS.  Adding a new chunk is a two-step process:

* The name owner announces the chunk hash as a name's state 
via a `NAME_REGISTRATION`, `NAME_UPDATE`, `NAME_RENEWAL`, or `NAME_IMPORT` transaction.
* Once the transaction is confirmed and processed by BNS, the name owner
  broadcasts the matching zone file.

Setting a name's state to be the hash of a chunk is beyond the scope of this
document, since it needs to be done through a BNS client.
See the relevant documentation for
[blockstack.js](https://github.com/blockstack/blockstack.js) and the [Blockstack
Browser](https://github.com/blockstack/blockstack-browser) for doing this.

Once the name operation is confirmed, you can announce the data to the
Atlas network.  You can do so with the Python client as follows:

```python
>>> import blockstack
>>> import base64
>>> data = "..."   # this is the chunk data you will announce
>>> data_b64 = base64.b64encode(data)
>>> result = blockstack.lib.client.put_zonefiles('https://node.blockstack.org:6263', [data_b64])
>>> assert result['saved'][0] == 1
>>>
```

At most five chunks can be announced in one RPC call.
Note that the data must be base64-encoded before it can be announced.

When the `put_zonefiles()` method succeeds, it returns a `dict` with a list
under the `saved` key.  Here, `result['saved'][i]` will be 1 if the `i`th
chunk given to `put_zonefiles()` was saved by the node, and 0 if not.
The node will not save a chunk if it is too big, or if it has not yet processed
the name operation that contained the chunk's hash.

The `put_zonefiles()` method is idempotent.

## Propagating Chunks

Atlas peers will each store a copy of the chunks you announce.  In the
background, they will asynchronously announce to one another which chunks they
have available, and replicate them to one another in a rarest-first order (much
like how BitTorrent works).  Eventually, every Atlas peer will receive the
chunk.

However, developers can accelerate this process by eagerly propagating chunks.
To do so, they can ask an Atlas peer for its immediate neighbors in the Atlas
peer graph, and replicate the chunk to each of them as well.

For example, this code will replicate the chunk to not only
`https://node.blockstack.org:6263`, but also to its immediate neighbors.

```python
>>> import blockstack
>>> import base64
>>> data = "..."   # this is the chunk you will replicate widely
>>> data_b64 = base64.b64encode(data)
>>> 
>>> result = blockstack.lib.client.get_atlas_peers('https://node.blockstack.org:6263')
>>> neighbors = result['peers']
>>> print ", ".join(neighbors)
13.65.207.163:6264, 52.225.128.191:6264, node.blockstack.org:6264, 23.102.162.7:6264, 52.167.230.235:6264, 23.102.162.124:6264, 52.151.59.26:6264, 13.92.134.106:6264
>>> 
>>> for neighbor in neighbors:
...    result = blockstack.lib.client.put_zonefiles(neighbor, [data_b64])
...    assert result['saved'][0] == 1
...
>>>
```

This is not strictly necessary, but it does help accelerate chunk replication
and makes it less likely that a chunk will get lost due to individual node
failures.

# How Atlas Works

Atlas was designed to overcome the structural weaknesses inherent to all
distributed hash tables.  In particular, it uses an unstructured peer network to
maximize resilience against network link failure, and it uses the underlying
blockchain (through BNS) to rate-limit chunk announcements.

## Peer Selection

Atlas peers self-organize into an unstructured peer-to-peer network.
The Atlas peer network is a [random K-regular
graph](https://en.wikipedia.org/wiki/Random_regular_graph).  Each node maintains
*K* neighbors chosen at random from the set of Atlas peers.

Atlas nodes select peers by carrying out an unbiased random walk of the peer
graph.  When "visiting" a node *N*, it will ask for *N*'s neighbors and then
"step" to one of them with a probability dependent on *N*'s out-degree and the
neighbor's in-degree.

The sampling algorithm is based on the Metropolis-Hastings (MH) random graph walk
algorithm, but with a couple key differences.  In particular, the algorithm
attempts to calculate an unbiased peer graph sample that accounts for the fact
that most nodes will be short-lived or unreliable, while a few persistent nodes
will remain online for long periods of time.  The sampling algorithm accounts
for this with the following tweaks:

* If the neighbors of the visited node *N* are all unresponsive, the random
walk resets to a randomly-chosen known neighbor.  There is no back-tracking on
the peer graph in this case.

* The transition probability from *N* to a live neighbor is *NOT* `min(1,
degree(neighbor)/degree(N))` like it is in the vanilla MH algorithm.  Instead,
the transition probability discourages backtracking to the previous neighbor *N_prev*, 
but in a way that still guarantees that the sampling will remain unbiased.

The algorithm was adapted from the work from [Lee, Xu, and
Eun](https://arxiv.org/pdf/1204.4140.pdf) in the proceedings of 
ACM SIGMETRICS 2012.

## Chunk Propagation

Atlas nodes maintain an *inventory* of chunks that are known to exist.  Each
node independently calculates the chunk inventory from its BNS database.
Because the history of name operations in BNS is linearized, each node can
construct a linearized sub-history of name operations that can set chunk
hashes as their name state.  This gives them a linearized sequence of chunks,
and every Atlas peer will independently arrive at the same sequence by reading
the same blockchain.

Atlas peers keep track of which chunks are present and which are absent.  They
each construct an *inventory vector* of chunks *V* such that *V[i]* is set to 1
if the node has the chunk whose hash is in the *i*th position in the chunk
sequence (and set to 0 if it is absent).

Atlas peers exchange their inventory vectors with their neighbors in order to
find out which chunks they each have.  Atlas nodes download chunks from
neighbors in rarest-first order in order to prioritize data replication for the
chunks that are currently most at-risk for disappearing due to node failure.

```
   Name operation   |  chunk hashes  |   chunk data    |  Inventory
      history       |  as name state |                 |   vector

+-------------------+
| NAME_PREORDER     |
+-------------------+----------------+
| NAME_REGISTRATION | chunk hash     |  "0123abcde..."       1
+-------------------+----------------+
| NAME_UPDATE       | chunk hash     |    (null)             0
+-------------------+----------------+
| NAME_TRANSFER     |
+-------------------+
| NAME_PREORDER     |
+-------------------+----------------+
| NAME_IMPORT       | chunk hash     |  "4567fabcd..."       1
+-------------------+----------------+
| NAME_TRANSFER     |
+-------------------|
      .  .  .


Figure 2:  Relationship between Atlas node chunk inventory and BNS name state.
Some name operations announce name state in the blockchain, which Atlas
interprets as a chunk hash.  The Atlas node builds up a vector of which chunks
it has and which ones it does not, and announces it to other Atlas peers so
they can fetch chunks they are missing.  In this example, the node's
inventory vector is [1, 0, 1], since the 0th and 2nd chunks are present
but the 1st chunk is missing.
```

## Querying Chunk Inventories

Developers can query a node's inventory vector as follows:

```python
>>> import blockstack
>>> result = blockstack.lib.client.get_zonefile_inventory("https://node.blockstack.org:6263", 0, 524288)
>>> print len(result['inv'])
11278
>>> 
```

The variable `result['inv']` here is a big-endian bit vector, where the *i*th
bit is set to 1 if the *i*th chunk in the chunk sequence is present.  The bit at
`i=0` (the earliest chunk) refers to the leftmost bit.

A sample program that inspects a set of Atlas nodes' inventory vectors and determines
which ones are missing which chunks can be found
[here](https://github.com/blockstack/atlas/blob/master/atlas/atlas-test).

# Appendix 1: Feature Comparison

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
