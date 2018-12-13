# Abstract

This proposal describes a mechanism for single-leader election using
_burn-mining_. Leader election is intimately connected to the concept of
chain selection-- as leaders must be able to choose their chain tip, and
that choice is impacted by network participants' rules for chain selection.

# Definitions

**Burn-mining** is the act of destroying cryptocurrency from one blockchain in
order to mine a block on another blockchain.  Destroying the cryptocurrency can
be done by rendering it unspendable.

**Burn chain**: the blockchain whose cryptocurrency is destroyed in burn-mining.

**Burn transaction**: a transaction on the burn chain that a Stacks miner issues
in order to become a candidate for producing a future block.

**Chain tip**: the location in the blockchain where a new block can be appended.
Every block is a valid chain tip, but the chain tips can be assigned a total
ordering that determines the "best" chain tip (i.e. which blockchain transaction
history is the canonical history).

**Cryptographic sortition** is the act of selecting the next leader to
produce a block on a blockchain in an unbiased way using cryptographic
primitives.

**Election block**: the block in the burn chain at which point a leader is
chosen.  Each leader has one election block.

**Epoch**: a discrete configuration of the leader and leader candidate state in
the Stacks blockchain.  A new epoch begins when a leader is chosen, or the
leader's tenure expires (these are often, but not always, the same event).

**Fork**: one of a set of divergent transaction histories, one of which is
considered by the blockchain network to be the canonical history
with the "best" chain tip.

**Fork choice rule**: the programmatic rules for deciding how to rank forks to select
the canonical transaction history.  All correct peers that process the same transactions
with the same fork choice rule will agree on the same fork ranks.

**Leader**: the principal selected to produce the next block in the Stacks
blockchain.  The principal is called the block's leader.

**Reorg** (full: _reorganization_): the act of a blockchain network switching
from one fork to another fork as its collective choice of the canonical
transaction history.  From the perspective of an external observer,
such as a wallet, the blockchain appears to have reorganized its transactions.

# Motivation

Leader election on the Stacks chain enables:

1. Near instantaneous acceptance of Stacks transactions into a block
2. High validation throughput
3. An open leadership set
4. Opportunity to participate without mining hardware
5. Ability to migrate to a separate burn chain in the future

# Assumptions

The design of the Stacks leader election protocol makes the following
assumptions:

* Deep forks in the burn chain are exponentially rarer as a function of their
  length.

* Deep forks occur for reasons unrelated to the Stacks protocol execution.  That
  is, miners do not attempt to manipulate the execution of the Stacks protocol
by reorging the burn chain.

* Burn chain miners do not censor all Stacks transactions (i.e. liveness is
  possible).

* At least 2/3 of the Stacks miners (measured by weight) are correct and honest.

# Blocks

Like existing blockchains, the Stacks blockchain encodes a cryptocurrency and
rules for spending its tokens.  Like existing cryptocurrencies, the Stacks
blockchain introduces new tokens into circulation each time a new block is
produced.  This encourages peers to participate in gathering transactions and
creating new blocks.  Peers that do so so called _leaders_ of the blocks that
they produce (analogous to "miners" in existing cryptocurrencies).

Blocks are made of one or more _transactions_, which encode valid state
transitions in each correct peer.  Users create and broadcast to the peer
network in order to (among other things) spend the tokens they own.

Like existing cryptocurrencies, users compete with one another for _space_ in
the underlying blockchain for storing their transactions.  This competition is
realized through transaction fees -- users include an extra token payment in
their transactions to encourage Stacks leaders to incorporate their transactions
first.  Leaders receive the transaction fees of the transactions they
package into their blocks _in addition_ to the tokens minted by producing them.

Blocks are produced in the Stacks blockchain in cadence with the underlying burn
chain.  Each time the burn chain produces a block, at most one Stacks block
will be produced.  This is due to the way that leaders are selected (see below).
Each block discovery on the burn chain triggers a new _epoch_ in the Stacks
blockchain.

With the exception of a designated _genesis block_, each block in the Stacks
blockchain has exactly one "parent" block.  This parent relationship is a
partial ordering of blocks, where concurrent blocks (and their descendents)
are _forks_.

If the leader produces a block, it must have an already-accepted block as its
parent.  A block is "accepted" if it has been successfully
processed by all correct peers.

## Novel properties of the blockchain

Due to the way blocks are produced, each Stacks block is anchored to the burn chain by
way of a cryptographic hash.  That is, the burn chain's canonical transaction
history contains the hashes of all Stacks blocks ever produced.  This gives the
Stacks blockchain two properties that existing blockchains do not possess:

* **Global knowledge of time** -- Stacks blockchain peers each perceive the passage of time
  consistently by measuring the growth of the underlying burn chain.  In
particular, all correct Stacks peers that have same view of the burn chain can
determine the same total order of Stacks blocks.

* **Global knowledge of blocks** -- Each correct Stacks peer with the same
  view of the burn chain will also have the same view of the set of Stacks
blocks that *exist*.

* **Global knowledge of burns** -- Each correct stacks peer with the same view
  of the burn chain will know how much cumulative cryptocurrency was destroyed
in order to produce the blockchain (as well as when it was destroyed).  This is
analogous to a PoW chain peer knowing exactly how much electricity was spent to
produce a block, even if the block was produced in a distributed fashion by a mining pool.

We leverage these properties in order to give users a way to enhance their
preferred fork's chain quality, and in order to help mitigate block-withholding
attacks like selfish mining.

# Leader Election

The Stacks blockchain makes progress by selecting successive leaders to produce
blocks.  It does so via burn mining, whereby would-be leaders submit their candidacies
to be leaders by burning an existing cryptocurrency.  A leader is selected to produce a
block based on two things:

* the fraction of cryptocurrency the burned relative to the other candidates
* an unbiased source of randomness

A new leader is selected whenever the burn chain produces a new block -- the
arrival of a burn chain block triggers a leader election, and terminates the
current leader's tenure.

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

Anyone can submit their candidacy as a leader by issuing a burn transaction on
the underlying burn chain, and have a non-zero chance of being selected by the
network as the leader of a future block.

## Committing to a chain tip

In this section, we describe how the Stacks blockchain tolerates fail-stop
leaders and incentivizes leaders to append blocks to the "best" fork.

Because anyone can become a leader, this means that even misbehaving leaders can
be selected.  If leaders exhibit fail-stop behavior, or do not follow the
protocol rules when deriving a block, then no block will be appended to the
Stacks blockchain during this leader's tenure.  If a leader is operating off of
stale data, then the leader may produce a block
whose parent is not the latest block on the "best" fork.

The Stacks blockchain tolerates fail-stop misbehavior by considering each
previously-accepted block to be a valid chain tip.  A correct leader may choose any
previously-accepted block as the parent of the block it produces during its
tenure.  In doing so, the chain can recover from fail-stop leaders simply by
building on top of the last block on "best" fork that was replicated to the peer network.
A succession of correct leaders that produce blocks will produce a fork that
overtakes the fork in which the fail-stop leader failed to produce a block.

A consequence of tolerating fail-stop leaders is that the Stacks blockchain 
may have multiple competing forks.  However, a well-designed
blockchain encourages leaders to identify the "best" fork and append blocks to
it by requiring leaders to _irrevocably commit_ to the
chain tip they will work on when their tenures begin.
This commitment must be tied to an expenditure of some
non-free resource, like energy, storage, bandwidth, or (in this blockchain's case) an
existing cryptocurrency.  The intution is that if the leader does _not_ build on
the "best" fork, then they commit to and lose that resource at a loss.

This tactic is used to encourage both safety and liveness in other blockchains
today. For example, in Bitcoin, miners search for the inverse of a hash that
contains the current chain tip. If they fail to win that block, they
have wasted that energy. As they must attempt deeper and deeper forks
to initiate a double-spend attacks, this becomes an exponential energy
expenditure.  The only way for the leader to recoup their losses is for the
fork they work on to be considered by the rest of the network as the "best" fork
(i.e. the one where the tokens they minted are spendable).  While this does
not _guarantee_ liveness or safety, penalizing leaders that do not append blocks to the 
"best" chain while rewarding leaders that do provides a strong economic
incentive for leaders to build and append new blocks to the "best" fork
(liveness) and to _not_ attempt to build an alternative fork that reverts
previously-committed blocks (safety).

It is important that the Stacks blockchain offers the same encouragements.
In particular, the ability for leaders to intentionally orphan blocks in order
to initiate double-spend attacks is an undesirable safety violation,
and leaders that do so should be penalized.  This property is enforced by
making a leader announce  their chain fork commitment _in the
burn transaction_ -- they can only receive Stacks tokens if the block referenced
in their burn transaction is accepted into the "best" fork.

# Operation as a leader

How do leaders commit to chain tips?  There are to approaches under
consideration -- the _streaming model_ and the _batch model_.

In the streaming model, commitment to a chain tip is a trailing commitment -- the
leader will know it has been selected _before_ producing the block is produced.
The leader "streams" a block during its tenure by selecting and
packaging transactions on-the-fly.  In correct operation, the next leader
decides where the current leader's block ends by selecting a "last transaction"
of the previous leader, and building off of that.  The upside to the streaming
model is low latency -- users know very quickly (i.e. before the tenure ends)
whether or not their transaction was accepted by the network.  The downside is
that the trailing commitment makes it possible for a leader adaptively
double-spend:  if the leader is selected twice in a row (generally, N+1 times
in a row for N consecutive elections), then the leader can invalidate its previous
transactions by building off of the same parent block as before -- for a 
potentially limitless upside.

In the batch model, commitment to a chain tip is a leading commitment.  Under
correct operation, each leader first commits to a full block, and later discovers
whether or not its block was selected to be the next block.  The leader does not
replicate the block until it is selected.  The upside of this approach is that
there is no way for a leader to adaptively orphan its blocks, since the leader
has no way of knowing whether a double-spend attempt will succeed.  The downside
of this approach is that it significantly increases the latency for users -- the
user must not only wait for the leader to commit to a block, but also wait for
the block to be selected (at a minimum of two burn chain block times).

We discuss both proposals in detail.  Eventually, this SIP will be updated
to select one commitment strategy for the Stacks blockchain.

## Proposal 1: Streaming model

In the streaming mdoel, a single leader is selected for each epoch, allowing the leader
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
leader to a particular chaintip.  Moreover, the leader can only receive Stacks 
transaction fees if it sends a `begin-epoch` transaction for its tenure.
This prevents a leader from hiding
their chain selection until a later block.

A leader's `begin-epoch` transaction does not need to be included on the burn chain before the
leader's epoch begins, rather the leader is allowed up to _l_ blocks
(we will use 6) for their transaction to be included on the
burn-chain. If the leader's `begin-epoch` transaction is not
included on the burn-chain within that time, the epoch is skipped, and no
transaction fees are distributed to the leader.  Other nodes can examine the set
of `begin-epoch` transactions and identify the order in which the leaders were
elected and made their committments.

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

### Leader chain selection

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
a portion of the epoch in their chain, even if the leader misbehaves
by, for example, omitting transactions (fail-stop) or broadcasting 
invalid transactions.

#### Using the latest microblock

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

#### Preventing microblock stream forks

In the Stacks chain, the selected leader is in a position to quickly
and cheaply generate microblocks. This allows the leader to split the
system by creating different chain histories for different nodes in
the network (equivocation). These malicious forks are easily differentiated from the
forks regularly generated during transition from one to leader to the
next because the forks occur solely within a single epoch.

Correct Stacks nodes identify equivocation from a malicious leader and
reject all microblocks generated on conflicting histories.  The malicious leader
is also stripped of their transaction fees and newly-minted tokens.

To discourage leaders from acting on equivocated state, we employ _poison
  transactions_.  These transactions include a proof of a microblock
fork and must be broadcast in the Stack chain before the associated
leader's reward has matured. If such a poison transaction is valid,
the reward for the poisoned epoch is stripped from the offending
leader -- the leader does not receive the block's newly-minted tokens.
As a reward for discovering the fork, the broadcaster of the
poison transaction is rewarded with 5% of the original
epoch's reward.  If the leader produces an invalid block in this way, but no
poison transaction is submitted, then the block's transactions are still all
rejected but the leader keeps the newly-minted tokens.

Any node can sign and broadcast a poison transaction.  To discourage false
positives, the poison transaction sender will be assessed a transaction fee
like any other transaction.  The transaction fee will be redeemed to the
sender if the poison transaction is valid (along with the 5% reward).

## Proposal 2: Batch model

An alternative leader operation model under consideration is the _batch model_.  Unlike the streaming
model, the leader selects all of the transactions for a block _before_ it knows
whether or not its block will be included on the "best" fork.  The leader
commits to a block, and the election algorithm is run to select which of all
candidate blocks will be processed.

### Leader chain selection

Unlike the streaming model, the batch model uses a _leading committment_.  The
leader commits to a block before it knows whether or not they will be elected.
This model precludes the possibility of a leader adaptively orphaning its blocks
in a bid to double-spend -- if the leader wants to orphan itself N+1 times by being
selected N times, it needs to first commit to N blocks (and burn the requisite
amount of cryptocurrency for them).  This makes this model closer to how
existing blockchains work.

To commit to a chain tip, each correct leader candidate first selects the transactions they will
include in their blocks, and commit to their block's hash and block's parent in their
burn transactions.  Once the transactions are confirmed on the burn chain, the
sortition algorithm will be run to select which of the candidate blocks will be
added to the Stacks blockchain.  The candidate that produced the block was the
leader for that epoch.  The leader then announces their block to the peer
network.

#### Using the latest block data

Like existing blockchains, the leader can commit to any prior parent block.  In
the Stacks blockchain, this allows leaders to tolerate block loss by building
off of the latest-built ancestor block's parent.

To encourage leaders to propagate their blocks if they are selected, a
commitment to a block on the burn chain is only considered valid if the peer
network has data for it.  A leader cannot profit by passively winning elections
-- they eventually must propagate the block (even though this enables selfish
mining; see below).

## Leader volume limits

In both models, a leader can propagate transactions irrespective of the underlying burn chain.
This poses a DDoS vulnerability to the network:  a high-transaction-volume
leader may swamp the peer network with so many
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

## Transaction latency

Both models offer different latency guarantees to users.  In the streaming
model, a user can learn very quickly whether or not their transaction was
incorporated into a block (possibly within a few seconds of sending it).  In the
batch model, however, a user will not learn this until at least two epochs have
passed -- one epoch for a leader to commit to a block containing the
transaction, and one epoch for a block to be selected.

The batching model can overcome this latency via an external service: a leader
can supply an API endpoint in their burn transaction that allows a user to query
whether or not their transaction is included in the burn (i.e. the leader's
service would supply a Merkle path to it).  A user can use a set of leader
services to deduce which block(s) included their transaction, and calculate the
probability that their transaction will be accepted in the next epoch.

# Reward distribution

Stacks tokens come into existence on a fork in every epoch where a leader is
selected, regardless of the chain tip commitment strategy.  However, proof-of-burn
mining is not only concerned with electing leaders, but also concerned with
enhancing chain quality by increasing the quantity of the underlying
cryptocurrency destroyed to produce it.  For this reason, the Stacks chain rewards each leader
_candidate_ who submitted a burn transaction with some of the tokens.

Users who do not intend to be block leaders can receive Stacks tokens by issuing burns.
To facilitate this, the Stacks blockchain pools all tokens created and all transaction fees received and
does not distribute them until a large number of epochs (a _reward window_) has
passed.  The tokens cannot be spent until the window passes, and users and leader
candidates in the window do not know in advance what fraction of the rewards
they will receive (but they can estimate it as the window gets longer).
However, unless the number of distinct burns is *very* large, each burner can
expect to recieve some Stacks tokens.

The reason for rewarding users and leader candidates as well as leaders is to help with
fork selection.  In particular, _users_ of the system who do not intend to
become leaders can participate in enhancing the quality of their preferred fork.
To do so, they can submit a burn transaction that simply points to a preferred
leader's burn.  Stacks peers interpret this as increasing the likelihood that the preferred leader
will be elected.  Users are rewarded for helping participate in this process,
since it helps honest leaders out-pace leaders who for whatever reason do not
work to keep the chain live.

# Recovery from data loss

Stacks block data can get lost after a leader commits to it.  However, the burn
chain will record the block hash, the parent block hash, and the leader's public
key, regardless of the chain tip commitment strategy.  This means that all existing forks will be
known to the Stacks peers that share the same view of the burn chain (including
forks made of invalid blocks, and forks that include blocks whose data was lost
forever).

What this means is that regardless of how the leader operates, its
chain tip commitment strategy needs a way to orphan a fork of any length.  In
correct operation, the network recovers from data loss by building an
alternative fork that will eventually become the "best" fork,
thereby recovering from data loss and ensuring that the system continues
to make progress.  Even in the absence of malice, the need for this family of strategies
follows directly from a single-leader model, where a principal can die before
producing a block or failing to propagate a block during its tenure.

However, there is a downside to this approach: it enables **selfish mining.**  A
minority coalition of leaders can statistically gain more Stacks tokens than they are due from
their burns by attempting to build a hidden fork of blocks, and releasing it
once the honest majority comes within one block height difference of the hidden
fork.  This orphans the majority fork, causing them to lose their Stacks tokens.

## Seflish mining mitigation: intuitions

Fortunately, all peers in the Stacks blockchain have global knowledge of state,
 time, and burns.  Intuitively, this gives us some advantages over existing blockchains
for thwarting selfish leaders:

* Since all nodes know about all blocks that have been committed, a selfish leader coalition
  cannot hide their attack forks. The honest leader coalition see
the attack coming, and evidence of the attack will be preserved in the burn
chain for subsequent analysis.  This property allows honest leaders
to prepare for and mitigate a pending attack by burning more
cryptocurrency, thereby reducing the fraction of burn power the selfish leaders wield.

* Since all nodes have global knowledge of the passage of time, honest leaders
  can agree on a total ordering of all block commits and burns.  In certain kinds of
selfish attacks, this gives honest leaders the ability to reject an attack chain 
with over 50% confidence.  For example, honest leaders would not build on top of
a chain tip whose last _A_ blocks arrived all the time or each arrived late by
more than one epoch, even if that chain tip represents the "best" fork, since
this would be the expected action of a selfish miner.

* Since all nodes know about all burn transactions, the "long tail of small burners"
(users and low-probability leaders) can collectively throw their burns behind
known-honest leaders' burns.  This increases the chance that honest leaders will
be elected, thereby increasing the fraction of honest burn power and making it
harder for a selfish leader to get elected.

* The Stacks chain reward structure spreads out rewards for creating
blocks and mining transactions across a large interval.  This "smooths over"
short-lived selfish mining attacks -- while selfish leaders still receive more
than their fair share of the rewards, the reward window makes this discrepancy
smaller.

None of these points _prevent_ selfish mining, but they give honest users and
honest leaders the tools to make selfish mining difficult to pull off.
Depending on user activity, they also make economically-rational leaders less likely to 
participate in a selfish miner cartel -- doing so always produces evidence,
which honest leaders and users can act on to reduce or eliminate 
their expected rewards.

Nevertheless, these arguments here are only intuitions at this time.  A more
rigorous analysis is needed to see exactly how these points affect the
profitibility of selfish mining.  Because the Stacks blockchain represents a
clean slate blockchain design, we have an opportunity to consider the past
several years of research into attacks and defenses against block-hiding
attacks.  This section will be updated as our understanding evolves.

# Fork Selection

Fork selection in the Stacks blockchain requires a metric to determine which
chain, between two candidates, is the "best" chain.  Using proof-of-burn as the
security method for the blockchain implies a direct metric:  the total sum of
burns in the election blocks for a candidate chain.  In particular, **the Stacks
blockchain measures a fork's quality by the total amount of burns which _confirms_ block _N_** (as
opposed to the amount of burn required for the _election_ of block _N_).

This fork choice rule means that the best fork is the _longest valid_ fork.
This fork has the most blocks available of all forks, and statistically has the
highest expected proof-of-burn (i.e. over many epochs).

This fork choice rule makes it difficult to select alternative deep forks.  In
order to carry out a deep fork, the majority coalition of leaders needs to spend
at least as many epochs working on the new fork as they did on the old fork.
We consider this acceptable because it also has the effect of keeping the chain
history relatively stable, and makes it so every participant can observe (and
prepare for) any upcoming forks that would reorg the chain.

An alternative fork-selection rule was considered whereby the chain with the
most total burns would have been the "best" chain, no matter how long it was.
This idea was ultimately
rejected because it would mean that a single rich leader could invalidate a
large number of blocks with a single massive burn.  This is not only an unacceptable risk
to proof-of-burn blockchains that are just getting off the ground, but also 
does not incentivize the behavior that users desire -- i.e. users want the chain history 
to be relatively stable and to usually make forward progress.

## Burn Window Adjustments 

As stated, leader candidates become leaders by burning a cryptocurrency.  But, what
happens if the rate at which they collectively burn it fluctuates?

* If it increases too fast, then a few rich leaders can quickly dominate the
  sortition process and effectively take over the chain before other
participants have had a chance to react.

* If it decreases too fast, then it makes it easy for opportunistic attackers to
  reorg the chain before honest participants can react.

To prevent increases or decreases from occuring too quickly, the Stacks
blockchain implements a variable-sized burn window that has a "minimum burn"
quota that must be met before a leader can be elected.  At a high level, it
operates as a negative feedback mechanism similar to how TCP manages its
bandwidth:

* As more and more leaders and users burn cryptocurrency, the minimum burn of
  the burn window increases additively.  If adding the next block to the burn
window increases the window's average burn/block ratio, then the mininum burn
quota is incremented (e.g. by 0.001 BTC).  The burns/window-size ratio defines
an upper bound on the size of acceptable burns -- if a burn transaction is
discovered in the next block that is too high, it will be rejected outright.

* As fewer and fewer leaders and users burn cryptocurrency, adding the next
  block to the burn window would decrease its average burn/block ratio.  In this
case, the window "grows" to include the next burn chain block.  No leader will be elected
for this epoch.  Only once the window has met its minimum burn quota over all 
of its blocks will a new leader be selected.  Once this happens, the window
"snaps back" to its original size and the minimum burn quota is decreased
multiplicatively (e.g. by 25%).

This burn window protocol enables a set of un-coordinated leader candidates to
burn cryptocurrency units at a rate that is about the market exchange rate of
the burn tokens to Stacks tokens.  The feedback mechanism in the burn window
allows a steady-state behavior where there is one Stacks block produced per
epoch, while also ensuring that the burn rates cannot increase or decrease too
quickly.
