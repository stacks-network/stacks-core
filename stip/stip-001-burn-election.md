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
underlying burn chain (or over a window of blocks).

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


# Fork Selection

Fork selection in the Stacks blockchain requires a metric to determine
which chain, between two candidates, is the "heaviest" or "longested"
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

