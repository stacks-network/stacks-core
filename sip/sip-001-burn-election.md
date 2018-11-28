# Abstract

This proposal describes a mechanism for single-leader election using
burn-mining. Leader election is intimately connected to the concept of
chain selection-- as leaders must be able to choose their chain tip, and
that choice is impacted by network participants' rules for chain selection.

# Motivation

Leader election on the Stacks chain enables:

1. Near instantaneous confirmation of Stacks transactions
2. High validation throughput
3. An open leadership set
4. Opportunity to participate without mining hardware
5. Ability to migrate to a separate burn chain in the future

# Election

The basic structure for leader election through burn-mining is that
for some Stacks block _N_, the leader is selected via some function of
that leader's total cryptocurrency burnt in a block _N'_ on the
underlying burn chain. In more detail, we support a window of burns
_W_, where the effective value of burns for a potential leader at
block _N'_ is equal to their total burn over the prior _W_ blocks.

In such a system, if a candidate _Alice_ wishes to be a leader of a
Stacks block, she issues a burn transaction in the underlying burn
chain. The network then uses cryptographic sortition to choose a
leader in a verifiably random process, weighted by burn amounts.
The block in which this burn transaction is broadcasted is known
as the "election block" for Stacks block _N_.

## Committing to a chain tip

Leaders must be able to choose which chain tip they want to build off
of. Otherwise, malicious leaders would be able to force subsequent
leaders to follow their chains, even if they misbehaved by hiding
transactions, broadcasting partial blocks, etc.

However, a healthy blockchain requires that leaders _commit_ to the
chain tip they are working on at the time at which they expend energy,
burn cryptocurrency, etc. This ensures that if a would-be malicious
leader fails to win a block, they have suffered a penalty. For
example, in Bitcoin, miners search for the inverse of a hash that
contains the current chain tip. If they fail to win that block, they
have wasted that energy. As they must attempt deeper and deeper forks
to initiate a double-spend attacks, this becomes an exponential energy
expenditure.

It is important that this same property hold in the Stacks
blockchain. The ability for leaders to engage in double-spend attacks
at will is unacceptable. This property is enforced by making a leader
announce their chain commitment _in the burn transaction_. However,
unlike Bitcoin (and, for example, Bitcoin-NG) --- this commitment is a
"lagging commitment". The chain tip announced in a burn transaction
_cannot_ be the exact preceding chain tip, because a key advantage of
using leader election is that a block may be _streamed_ -- namely, a
leader is continuously confirming new transactions as long as their
tenure lasts. So at a minimum, the commitment will be 1-block old.

This time between block _N'_ on the burn chain and the resulting
leader's tenure results in a trade-off between (1) resilience towards
reorgs in the underlying blockchain and (2) period of time during
which a malicious leader may knowingly engage in successful
double-spend attacks. It is important to note that this trade-off
exists regardless of fork selection algorithm--- any fork selection
strategy will allow for a leader to know _a priori_ whether a
malicious fork is likely to be successful.

# Operation as leader

A single leader is selected for each epoch, allowing the leader
to _stream_ the contents of the Stack block. Because blocks are
streamed, rather than batched, transactions can be immediately
"confirmed" by the leader by reading them out of the mempool and
broadcasting them as part of the current block. To do this, the leader
wraps the transaction in a "microblock" (essentially just a
blockheader) and signs the microblock. The design of microblocks is
motivated by [Bitcoin-NG](https://www.usenix.org/node/194907).

When a leader starts an epoch, the first transaction of the epoch must
be announced on the burn-chain. This first transaction, which we call
the `begin-epoch` transaction is a no op, and merely commits the
leader to a particular chaintip. This prevents a leader from hiding
their chain selection until a later block. A leader's `begin-epoch`
transaction does not need to be included on the burn chain before the
leader's epoch begins, rather the leader is allowed up to _l_ blocks
(we will use 6) for their transaction to be included on the
burn-chain. If the leader's `begin-epoch` transaction is not
included on the burn-chain within that time, the epoch is skipped.

Once the epoch begins, the operation of the leader node is relatively
straight-forward. The leader starts by reading transactions out of the
mempool. Transactions should be selected based on the transaction fee
and expected cost of evaluating that transaction. The leader then
executes the transaction, and broadcasts the transaction in a signed
microblock. The microblock contains the hash of the previous
microblock, the transaction, and a signature from the leader over the
microblock.

The leader is only able to choose and broadcast microblocks for the
block (or epoch) in which it was selected as the leader. The node will
cease to be the leader if the next epoch begins and another leader is
selected.

## Leader chain selection

As mentioned above, when a leader begins an epoch, it can choose the
chain tip from which to begin the new block. This allows leaders to
create forks from older blocks in an attempt to reorganize the Stack
chain. In the normal operation of the blockchain, we expect many
short-lived forks to occur at the transition between epochs. As one
leader begins broadcasting a new epoch, invariably some transactions
from the prior epoch will be orphaned, and need to be
rebroadcasted. We call these _micro-forks_.

To choose between forks, Stack nodes employ a chain selection
algorithm which ignores transactions other than transactions on the
longest chain. That is discussed in more detail in the `Fork
Selection` section of this proposal. However, by requiring that
leaders broadcast at least one microblock (the `begin-epoch`) on the
burn-chain, it guarantees that subsequent leaders are able to include
a portion of the epoch in their chain, even if the leader behaves
maliciously by, for example, hiding some transactions with the
intention of later broadcasting them to invalidate subsequent leaders'
chains.

### Using the latest microblock

In correct operation, selected leaders should append transactions to
the longest chain beginning with the latest microblock seen by the
leader so far. However, this chain selection algorithm will only
encourage a leader to include _a single_ microblock from the
preceding block, and not necessarily the latest. Without proper
incentives, a leader could reap a benefit by forcing a reorganization
of the chain history to the start of the prior block, and then
collecting all of the transaction fees for transactions from the prior
block as well.

This problem is also experienced in the Bitcoin-NG system, and the
remediation technique employed there will work here as well. Namely,
the transaction fee rewards for a particular transaction are split
between the current leader and the previous (in particular, only 40%
of the transaction fees go to the current leader, and 60% of the fees
go to the next leader).

### Preventing forks with poison

In the Stack chain, the selected leader is in a position to quickly
and cheaply generate microblocks. This allows the leader to split the
system by creating different chain histories for different nodes in
the network. These malicious forks are easily differentiated from the
forks regularly generated during transition from one to leader to the
next because the forks occur solely within a single epoch. To
discourage these "microblock forks," we employ _poison
  transactions_. These transactions include a proof of a microblock
fork and must be broadcast in the Stack chain before the associated
leader's reward has matured. If such a poison transaction is valid,
the reward for the poisoned epoch is stripped from the offending
leader. As a reward for discovering the fork, the broadcaster of the
poison transaction is rewarded with 5% of the original
epoch's reward.

## Leader volume limits

A leader can send signed microblocks as fast as it can process
them. This poses a DDoS vulnerability to the network: a high
performance leader may swamp the peer network with so many
transactions that the rest of the nodes cannot keep up. When the next
epoch begins and a new leader is chosen, it would likely orphan many
of the previous leader's transactions simply because its view of the
chain tip is far behind the high-volume leader's view. This hurts the
network, because it increases the confirmation time of transactions
and may invalidate previously-confirmed transactions.

To mitigate this, the Stack chain places a limit on the volume of
data a leader can send during its epoch (this places a de facto limit
on the number of transactions in a Stack block). This cap is enforced
by the consensus rules. When a leader exceeds this cap, the additional
transactions are merely ignored by the network.

# Fork Selection

Fork selection in the Stacks blockchain requires a metric to determine
which chain, between two candidates, is the "heaviest" or "longest"
chain. Use Proof-of-Burn as the security method for the blockchain
implies a direct metric: the total sum of burns in the election blocks
for the candidate chain. Even with this metric, there's a design choice--

**How do we count the total burn for a given Stacks block _N_?**

There are two alternatives:

1. The total amount of burn required for _election_ of block _N_.
2. The total amount of burn which _confirms_ block _N_.

Option 1 would allow the "heaviest chain" to be known at the time that
the block _N_ begins. Option 2, however, is much more resilient to
malicious or greedy leaders--- if their blocks aren't well broadcasted
and announced, they will not be confirmed and therefore won't have
competitive chain weights when comparing them against alternative forks.

## Weighting functions for chain length

The naive chain length metric (i.e., summing over total amount burn)
can be modified with weighting functions to encourage different
difficulties for different kinds of forks. In particular, in order to
discourage _deep_ forks, but still tolerate shallow forks, the chain
length metric can use exponential weighting based on burn-chain depth,
such that the "chain weight" applied to a given burn transaction is
equal to:

```
O(b * 2^d)

b := burn amount
d := depth in the burn chain
```

This would strongly favor deeper confirmations, making it very
difficult (though, in extreme circumstances, possible) to perform deep
reorganizations.

## Burn difficulty windowing

In order to prevent massive swings in the chain weights, we can employ
a technique of difficulty windowing. Namely, the total "heaviness" of
blocks in the Stacks chain is only allowed to increase at a maximum
rate per epoch (e.g., 5%). This prevents large spenders from trivially
creating forks by spending large sums of cryptocurrency
reserves. Similar to exponential weighting of block weights, this
modification increases the difficulty of forking (or, strictly places
a limit on how many _epochs_ a fork of a given depth must build across),
which trades resilience towards bad leaders for chain stability.

# Open Questions

The above discussion outlined a few major open questions:

1. How do we set the _election window?_ This is the time between when
   an election is finalized, and the leader begins broadcasting.

2. How do we account for burns in chain-selection? Does the block
   which the burn _elected_ receive the weight? Or does the block
   which the burn _confirmed_?
   
3. How do we weight burns over time? Does an exponential weighting
   function achieve desired properties (and what is the trade-off we
   are making here?) How should we tune these parameters?

