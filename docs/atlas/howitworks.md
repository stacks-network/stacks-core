---
layout: core
permalink: /:collection/:path.html
---
# How Atlas Works
{:.no_toc}

Atlas was designed to overcome the structural weaknesses inherent to all
distributed hash tables.  In particular, it uses an unstructured peer network to
maximize resilience against network link failure, and it uses the underlying
blockchain (through BNS) to rate-limit chunk announcements.

This section contains the following sections:

* TOC
{:toc}

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

* A peer does not report its entire neighbor set when queried,
but only reports a random subset of peers that have met a minimium health threshold.

* A new neighbor is only selected if it belongs to the same [BNS
  fork-set]({{site.baseurl}}/core/naming/introduction.html#bns-forks) (i.e. it reports
as having a recent valid consensus hash).

The algorithm was adapted from the work from [Lee, Xu, and
Eun](https://arxiv.org/pdf/1204.4140.pdf) in the proceedings of
ACM SIGMETRICS 2012.

## Comparison to DHTs

The reason Atlas uses an unstructured random peer network
instead of a [distributed hash table](https://en.wikipedia.org/wiki/Distributed_hash_table)
(DHT) is that DHTs are susceptbile to Sybil attacks.  An adaptive adversary can
insert malicious nodes into the DHT in order to stop victims from
resolving chunks or finding honest neighbors.

### Chunk Censorship

In a DHT, an attacker can censor a chunk by inserting nodes into the peers' routing tables
such that the attacker takes control over all of the chunk's hash buckets.
It can do so at any point in time after the chunk was first stored,
because only the peers who maintain the chunk's hash bucket have to store it.
This is a *fundamental* problem with structured overlay networks
that perform request routing based on content hash---they give the attacker
insight as to the path(s) the queries take through the peer graph, and thus
reduce the number of paths the attacker must disrupt in order to censor the
chunk.

Atlas uses an unstructured overlay network combined with a 100% chunk
replication strategy in order to maximize
the amount of work an adversary has to do to censor a chunk.
In Atlas, all peers replicate a chunk, and the paths the chunk take through the
network are *independent* of the content and *randomized* by the software
(so the paths cannot be predicted in advance).   The attacker's only
recourse is to quickly identify the nodes that can serve the chunk and partition them from
the rest of the network in order to carry out a censorship attack.
This requires them to have visibility into the vast majority of network links in
the Atlas network (which is extremely difficult to do, because in practice Atlas
peers maintain knowledge of up to 65536 neighbors and only report 10 random peers
when asked).

### Neighbor Censorship

Another problem with DHTs is that their overlay
network structure is determined by preferential attachment.  Not every peer that
contacts a given DHT node has an equal chance of becoming its neighbor.
The node will instead rank a set of peers as being more or less ideal
for being neighbors.  In DHTs, the degree of preference a node exhibits to
another node is usually a function of the node's self-given node identifier
(e.g. a node might want to select neighbors based on proximity in the key
space).

The preferential attachment property means that an adaptive adversary can game the node's
neighbor selection algorithm by inserting malicious nodes that do not
forward routing or lookup requests.  The attacker does not even have to eclipse
the victim node---the victim node will simply prefer to talk to the attacker's unhelpful nodes
instead of helpful honest nodes.  In doing so, the attacker can prevent honest peers from discovering each
other and each other's chunks.

Atlas's neighbor selection strategy does not exhibit preferential attachment
based on any self-reported node properties.  A
node is selected as a neighbor only if it is reached through an unbiased random graph
walk, and if it responds to queries correctly.
In doing so, an attacker is forced to completely eclipse a set of nodes
in order to cut them off from the rest of the network.

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
