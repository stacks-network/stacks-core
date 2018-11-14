---
layout: core
permalink: /:collection/:path.html
---
# BNS Forks

BNS effectively uses a public blockchain to store a database log.  A BNS peer
bootstraps itself by downloading and replaying the database log from the
blockchain, and in doing so, will calculate the same name database state as
every other (honest) BNS peer that has the same view of the blockchain.

Crucially, BNS is built on top of a public blockchain that is *unaware* of BNS's existence.
This means that the blockchain peers do not validate BNS transactions.  Instead,
the BNS peer needs to do so, and must know how to *reject* both invalid transactions
as well as well-formed transactions from dishonest peers (i.e. peers that do not
follow the same consensus rules).

BNS nodes do not directly communicate with one another---by design, the set of
BNS peers is not enumerable.  The only shared communication medium between BNS
peers is the blockchain.

To identify and reject invalid and malicious transactions without the blockchain's help,
the log of name operations embedded in the blockchain is constructed as a
[fork\*-consistent](http://www.scs.stanford.edu/~jinyuan/bft2f.pdf) database
log.  Fork\*-consistency is a [consistency
model](https://en.wikipedia.org/wiki/Consistency_model) whereby the state
replicas in all of the nodes exhibit the following properties:

* Each correct peer maintains a history of well-formed, valid state operations.  In this
  case, each correct BNS node maintains a copy of the history blockchain transactions
that encoded well-formed, valid name operations.

* Each honest peer's history contains the sequence of all operations that it
  sent.  That is, a user's BNS peer's transaction log will contain the sequence of all valid
transactions that the user's client wrote to the blockchain.

* If two peers accept operations *op* and *op'* from the same correct client,
  then both of their logs will have the both operations in the same order.  If
*op'* was accepted before *op*, then both peers' logs are identical up to *op'*.
In BNS, this means that if two peers both accept a given transaction, then it
means that they have accepted the same sequence of prior transactions.

This means that unlike with blockchains,
there can be *multiple long-lived conflicting forks* of the BNS database log.
However, due to fork\*-consistency, a correct BNS peer will only process *one*
of these forks, and will *ignore* transactions from peers in other forks.  In other words,
fork\*-consistency partitions the set of BNS peers into different **fork-sets**,
where all peers in a fork-set process each other's transactions, but the
completely ignore peers in other fork-sets.

BNS nodes identify which fork set they belong to using a **consensus hash**.  The
consensus hash is a cryptographic digest of a node's operation
history.  Each BNS peer calculates a new consensus hash each time it processes a
new block, and stores the history of consensus hashes for each block it
processed.

Two honest BNS peers can quickly determine if they are in the same fork-set by querying
each other's consensus hashes for a given block.  If they match, then they are
in the same fork-set (assming no hash collisions).

A BNS client executes a name operation on a specific fork-set by including a
recent consensus hash from that fork-set in the blockchain transaction.
At the same time, the BNS consensus rules state that a transaction can only be
accepted if it included a recent valid consensus hash.
This means that all BNS nodes in the client's desired fork-set will accept
the transaction, and all other BNS nodes not in the fork-set will ignore it.
You can see where the consensus hash is included in blockchain transactions by reading
the [transaction wire format]({{ site.baseurl }}/core/wire-format.html) document.

## Fork-set Selection

The blockchain linearizes the history of transactions, which means that
in general, there exists a fork-set for each distinct set of BNS
consensus rules.  For example, the Blockstack Core [2016 hard fork](https://github.com/blockstack/blockstack-core/blob/master/release_notes/changelog-0.14.md)
and [2017 hard fork](https://github.com/blockstack/blockstack-core/blob/master/release_notes/changelog-0.17.md) both introduced new consensus
rules, which means at the time of this writing there are three possible fork-sets:
the pre-2016 fork-set, the 2016-2017 fork-set, and the post-2017 fork-set.
The [public BNS nodes](https://node.blockstack.org:6263) are always running
in the fork-set with the latest consensus rules.

BNS clients are incentivized to communicate with peers in the fork-set that has
the most use, since this fork-set's name database will encode name/state
bindings that are the most widely-accepted and understood by users.
To identify this fork-set, a BNS client needs to learn one of
its recent consensus hashes.  Once it has a recent consensus hash, it can
query an *untrusted* BNS node for a copy of
its name database, and use the consensus hash to verify that the name database
was used to generate it.

How does a BNS node determine whether or not a consensus hash corresponds to the
most widely-used fork-set?  There are two strategies:

* Determine whether or not a *characteristic transaction* was accepted by the
widely-used fork-set.  If a client knows that a specific transaction belongs to
the widely-used fork-set and not others, then they can use the consensus hash to
efficiently determine whether or not a given node belongs to this fork-set.

* Determine how much "economic activity" exists in a fork-set by inspecting
the blockchain for burned cryptocurrency tokens.  Namespace and name
registrations are structured in a way that sends cryptocurrency tokens to either
a well-known burn address, or to an easily-queried pay-to-namespace-creator
address.

Both strategies rely on the fact that the consensus hash is calculated as a
[Merkle skip-list](https://github.com/blockstack/blockstack-core/issues/146)
over the BNS node's accepted transactions.  A client can use a consensus hash to
determine whether or not a transaction *T* was accepted by a node with *O(log
n)* time and space complexity.  We call the protocol for resolving a consensus hash to a specific transaction
**Simplified Name Verification** (SNV).  See our [paper on the subject](https://blockstack.org/virtualchain_dccl16.pdf)
for details of how SNV works under the hood.

If the client has a consensus hash and knows of a characteristic transaction in the widely-used fork-set,
it can use SNV to determine whether or not a node belongs to the fork-set that accepted it.

If the client knows about multiple conflicting consensus hashes,
they can still use SNV to determine which one corresponds
to the most-used fork-set.  To do so, the client would use a
[blockchain explorer](https://explorer.blockstack.org) to find the
list of transactions that burned cryptocurrency tokens.  Each of these
transactions will be treated as potential characteristic transactions:
the client would first select the subset of transactions that are well-formed
BNS transactions, and then use SNV to determine which of them correspond to which
consensus hashes.  The client chooses the consensus hash that corresponds
to the fork-set with the highest cumulative burn.

Work is currently underway to automate this process.
