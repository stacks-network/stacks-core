# SIP 001 Burn Election

## Preamble

Title: Burn Election

Author: Jude Nelson <jude@blockstack.com>, Aaron Blankstein <aaron@blockstack.com>

Status: Draft

Type: Standard

Created: 1/1/2019

License: BSD 2-Clause

## Abstract

This proposal describes a mechanism for single-leader election using
_proof-of-burn_ (PoB).  Proof of burn is a mechanism for bootstrapping a new
blockchain on top of an existing blockchain by rendering the tokens unspendable
(i.e. "burning" them).

Proof of burn is concerned with deciding which Stacks block miner (called _leader_ in this text) is elected for
producing the next block, as well as deciding how to resolve
conflicting transaction histories.  The protocol assigns a score to each leader
based on the fraction of tokens it burned, which is used to
(1) probabilistically select the next leader proportional to its normalized score
and to (2) rank conflicting transaction histories by their total number of epochs
to decide which one is the canonical transaction history.

## Introduction

Blockstack's first-generation blockchain operates in such a way that each transaction is
in 1-to-1 correspondence with a Bitcoin transaction.  The reason for doing this
is to ensure that the difficulty of reorganizing Blockstack's blockchain is just
as hard as reorganizing Bitcoin's blockchain -- a [lesson
learned](https://www.usenix.org/node/196209) from when the system was originally
built on Namecoin.

This SIP describes the proof-of-burn consensus algorithm in
Blockstack's second-generation blockchain (the _Stacks
blockchain_).  The Stacks blockchain makes the following improvements over the
first-generation blockchain:

### 1. High validation throughput

The number of Stacks transactions processed is decoupled from the
transaction processing rate of the underlying _burn chain_ (Bitcoin).  Before, each Stacks
transaction was coupled to a single Bitcoin transaction.  In the Stacks
blockchain, an _entire block_ of Blockstack transactions corresponds to a
Bitcoin transaction.  This significantly improves cost/byte ratio for processing
Blockstack transactions, thereby effectively increasing its throughput.

### 2. Low-latency block inclusion

Users of the first version of the Stacks blockchain encounter high latencies for
on-chain transactions -- in particular, they must wait for an equivalent
transaction on the burn chain to be included in a block.  This can take 
minutes to hours.

The Stacks blockchain adopts a _block streaming_ model whereby each leader can
adaptively select and package transactions into their block as they arrive in the
mempool.  This ensures users learn when a transaction is included in a block
on the order of _seconds_.

### 3. An open leadership set

The Stacks blockchain uses proof of burn to decide who appends the next
block.  The protocol (described in this SIP) ensures that anyone can become
a leader, and no coordination amongst leaders is required to produce a block.
This preserves the open-leadership property from the existing blockchain (where
Blockstack blockchain miners were also Bitcoin miners), but realizes it through
an entirely different mechanism that enables the properties listed here.

### 4. Participation without mining hardware

Producing a block in the Stacks blockchain takes negligeable energy on top of
the burn blockchain.  Would-be miners append blocks by _burning_ an existing cryptocurrency
by rendering it unspendable.  The rate at which the cryptocurrency is destroyed
is what drives block production in the Stacks blockchain.  As such, anyone who
can acquire the burn cryptocurrency (e.g. Bitcoin) can participate in mining,
_even if they can only afford a minimal amount_.

### 5. Fair mining pools

Related to the point above, it is difficult to participate in block mining in
a proof-of-work blockchain.  This is because a would-be miner needs to
lock up a huge initial amount of capital in dedicated mining hardware,
and a miner receives few or no rewards for blocks that are not incorporated
into the main chain.  Joining a mining pool is a risky alternative,
because the pool operator can simply abscond with the block reward or
dole out block rewards in an unfair way.

The Stacks blockchain addresses this problem by providing
a provably-fair way to mine blocks in a pool.  To
implement mining pools, users aggregate their individually-small burns
to produce a large burn, which in turn gives them all a
non-negligeable chance to mine a block.  The leader election protocol
is aware of these burns, and rewards users proportional to their
contributions _without the need for a pool operator_.  This both
lowers the barrier to entry in participating in mining, and removes
the risk of operating in traditional mining pools.

In addition to helping lots of small burners mine blocks, fair mining pools
are also used to give different block leaders a way to hedge their bets on their
chain tips:  they can burn some cryptocurrency to competing chain tips and
receive some of the reward if their preferred chain tip loses.  This is
important because it gives frequent leaders a way to reduce the variance of
their block rewards.

### 6. Ability to migrate to a separate burn chain in the future

A key lesson learned in the design of the first-generation Stacks blockchain is that
the network must be portable, in order to survive systemic failures such as peer
network collapse, 51% attacks, and merge miners dominating the hash power.
The proof of burn mining system will preserve this feature,
so the underlying burn chain can be "swapped out" at a later date if need be and
ultimately be replaced by a dedicated set of Stacks leaders.

### Assumptions

Given the design goals, the Stacks leader election protocol makes the following
assumptions:

* Deep forks in the burn chain are exponentially rarer as a function
  of their length.

* Deep forks in the burn chain occur for reasons unrelated to the
  Stacks protocol execution.  That is, miners do not attempt to
  manipulate the execution of the Stacks protocol by reorganizing the
  burn chain (but to be clear, burn chain miners may participate in the Stacks
chain as well).

* Burn chain miners do not censor all Stacks transactions (i.e. liveness is
  possible), but may censor some of them.  In particular, Stacks transactions
on the burn chain will be mined if they pay a sufficiently high transaction
fee.

* At least 2/3 of the Stacks leader candidates, measured by burn
  weight, are correct and honest.  If there is a _selfish mining_ coalition,
then we assume that 3/4 of the Stacks leader candidates are honest (measured
again by burn weight) and that honestly-produced Stacks blocks propagate to the honest 
coalition at least as quickly as burn blocks (i.e. all honest peers receive the
latest honest Stacks block data within one epoch of it being produced).

## Protocol overview

Like existing blockchains, the Stacks blockchain encodes a cryptocurrency and
rules for spending its tokens.  Like existing cryptocurrencies, the Stacks
blockchain introduces new tokens into circulation each time a new block is
produced (a _block reward_).  This encourages peers to participate in gathering transactions and
creating new blocks.  Peers that do so so called _leaders_ of the blocks that
they produce (analogous to "miners" in existing cryptocurrencies).

Blocks are made of one or more _transactions_, which encode valid state
transitions in each correct peer.  Users create and broadcast transactions to the peer
network in order to (among other things) spend the tokens they own.  The current
leader packages transactions into a single block during its epoch -- in this
way, a block represents all transactions processed during one epoch in the
Stacks chain.

Like existing cryptocurrencies, users compete with one another for _space_ 
in the underlying blockchain's peers for storing their transactions.  This competition is
realized through transaction fees -- users include an extra Stacks token payment in
their transactions to encourage leaders to incorporate their transactions
first.  Leaders receive the transaction fees of the transactions they
package into their blocks _in addition_ to the tokens minted by producing them.

Blocks are produced in the Stacks blockchain in cadence with the underlying burn
chain.  Each time the burn chain network produces a block, at most one Stacks block
will be produced.  In doing so, the burn chain acts as a decentralized
rate-limiter for creating Stacks blocks, thereby preventing DDoS attacks on its
peer network.  Each block discovery on the burn chain triggers a new _epoch_ in the Stacks
blockchain, whereby a new leader is elected to produce the next Stacks block.

With the exception of a designated _genesis block_, each block in the Stacks
blockchain has exactly one "parent" block.  This parent relationship is a
partial ordering of blocks, where concurrent blocks (and their descendents)
are _forks_.

If the leader produces a block, it must have an already-accepted block as its
parent.  A block is "accepted" if it has been successfully
processed by all correct peers and exists in at least one Stacks blockchain fork.
The genesis block is accepted on all forks.

Unlike most existing blockchains, Stacks blocks are not produced atomically.
Instead, when a leader is elected, the leader may dynamically package
transactions into a sequence of _microblocks_ as they are received from users.
Logically speaking, the leader produces one block; it just does not need to
commit to all the data it will broadcast when its tenure begins.  This strategy
was first described in the [Bitcoin-NG](https://www.usenix.org/node/194907) system,
and is used in the Stacks blockchain with some modifications -- in particular, a
leader may commit to _some_ transactions that _must_ be broadcast during its
tenure, and may opportunistically stream additional transactions in microblocks.

### Novel properties enabled by Proof of Burn

Each Stacks block is anchored to the burn chain by
way of a cryptographic hash.  That is, the burn chain's canonical transaction
history contains the hashes of all Stacks blocks ever produced -- even ones that
were not incorporated into any fork of the Stacks blockchain.  Moreover, extra
metadata about the block, such as parent/child linkages, are
are written to the burn chain.  This gives the
Stacks blockchain three properties that existing blockchains do not possess:

* **Global knowledge of time** -- Stacks blockchain peers each perceive the passage of time
  consistently by measuring the growth of the underlying burn chain.  In
particular, all correct Stacks peers that have same view of the burn chain can
determine the same total order of Stacks blocks and leader epochs.  Existing blockchains do not
have this, and their peers do not necessarily agree on the times when blocks were produced.

* **Global knowledge of blocks** -- Each correct Stacks peer with the same
  view of the burn chain will also have the same view of the set of Stacks
blocks that *exist*.  Existing blockchains do not have this, but instead
rely on a well-connected peer network to gossip all blocks.

* **Global knowledge of cumulative work** -- Each correct Stacks peer with the same view
  of the burn chain will know how much cumulative cryptocurrency was destroyed
and how long each competing fork is.  Existing
blockchains do not have this -- a private fork can coexist with all public
forks and be released at its creators' discression (often with harmful effects
on the peer network).

The Stacks blockchain leverages these properties to implement three key features:

* **Mitigate block-withholding attacks**:  Like all single-leader blockchains,
  the Stacks blockchain allows the existence of multiple blockchain forks.
These can arise whenever a leader is selected but does not produce a block, or
produces a block that is concurrent with another block.  The
design of the Stacks blockchain leverages the fact that all _attempts_ to produce
a block are known to all leaders in advance in order to detect and mitigate
block-withholding attacks, including selfish mining.  It does not prevent these
attacks, but it makes them easier to detect and offers peers more tools to deal
with them than are available in existing systems.

* **Ancilliary proofs enhance chain quality**:  In the Stacks blockchain, peers can enhance
  their preferred fork's chain quality by _contributing_ burnt tokens to their
preferred chain tip.  This in turn helps ensure chain liveness -- small-time
participants (e.g. typical users) can help honest leaders that commit to
the "best" chain tip get elected, and punish dishonest
leaders that withhold blocks or build off of other chain tips.
Users leverage this property to construct _fair mining pools_, where users can
collectively generate a proof to select a chain tip to build off of and receive a proportional share of the
block reward without needing to rely on any trusted middlemen to do so.

* **Ancilliary proofs to hedge bets**:  Because anyone can produce a proof of burn
in favor of any chain tip, leaders can hedge their bets on their preferred chain tips by distributing
their proofs across _all_ competing chain tips.  Both fair mining pools and generating
proofs over a distribution of chain tips are possible only because all peers have 
knowledge of all existing chain tips and the proofs behind them.

## Leader Election

The Stacks blockchain makes progress by selecting successive leaders to produce
blocks.  It does so by having would-be leaders submit their candidacies
by burning an existing cryptocurrency.
A leader is selected to produce a block based on two things:

* the amount of cryptocurrency burned and energy expended relative to the other candidates
* an unbiased source of randomness

A new leader is selected whenever the burn chain produces a new block -- the
arrival of a burn chain block triggers a leader election, and terminates the
current leader's tenure.

The basic structure for leader election through proof of burn is that
for some Stacks block _N_, the leader is selected via some function of
that leader's total cryptocurrency burnt in a previous block _N'_ on the
underlying burn chain.  In such a system, if a candidate _Alice_ wishes to be a leader of a
Stacks block, she issues a burn transaction in the underlying burn
chain which both destroys some cryptocurrency.
The network then uses cryptographic sortition to choose a
leader in a verifiably random process, weighted by the sums of the burn amounts.
The block in which this burn transaction is
broadcasted is known as the "election block" for Stacks block _N_.

Anyone can submit their candidacy as a leader by issuing a burn transaction on
the underlying burn chain, and have a non-zero chance of being selected by the
network as the leader of a future block.

### Committing to a chain tip

The existence of multiple chain tips is a direct consequence of the
single-leader design of the Stacks blockchain.
Because anyone can become a leader, this means that even misbehaving
leaders can be selected.  If a leader crashes before it can propagate
its block data, or if it produces an invalid block, then no block will
be appended to the leader's selected chain tip during its epoch.  Also, if a
leader is operating off of stale data, then the leader _may_ produce a
block whose parent is not the latest block on the "best" fork, in which case
the "best" fork does not grow during its epoch. These
kinds of failures must be tolerated by the Stacks blockchain.

A consequence of tolerating these failures is that the Stacks blockchain 
may have multiple competing forks; one of which is considered the canonical fork
with the "best" chain tip.  However, a well-designed
blockchain encourages leaders to identify the "best" fork and append blocks to
it by requiring them to _irrevocably commit_ to the
chain tip they will build on for their epoch.
This commitment must be tied to an expenditure of some
non-free resource, like energy, storage, bandwidth, or (in this blockchain's case) an
existing cryptocurrency.  The intuition is that if the leader does _not_ build on
the "best" fork, then it commits to and loses that resource at a loss.

Committing to a _chain tip_, but not necessarily new data,
is used to encourage both safety and liveness in other blockchains
today. For example, in Bitcoin, miners search for the inverse of a hash that
contains the current chain tip. If they fail to win that block, they
have wasted that energy. As they must attempt deeper and deeper forks
to initiate a double-spend attacks, producing a competing fork becomes an exponentially-increasing energy
expenditure.  The only way for the leader to recoup their losses is for the
fork they work on to be considered by the rest of the network as the "best" fork
(i.e. the one where the tokens they minted are spendable).  While this does
not _guarantee_ liveness or safety, penalizing leaders that do not append blocks to the 
"best" chain tip while rewarding leaders that do so provides a strong economic
incentive for leaders to build and append new blocks to the "best" fork
(liveness) and to _not_ attempt to build an alternative fork that reverts
previously-committed blocks (safety).

It is important that the Stacks blockchain offers the same encouragement.
In particular, the ability for leaders to intentionally orphan blocks in order
to initiate double-spend attacks at a profit is an undesirable safety violation,
and leaders that do so must be penalized.  This property is enforced by
making a leader announce their chain tip commitment _before they know if their
blocks are included_ -- they can only receive Stacks tokens if the block for
which they submitted a proof of burn is accepted into the "best" fork.

### Election Protocol

To encourage safety and liveness when appending to the blockchain, the leader
election protocol requires leaders to burn cryptocurrency and spend energy before they know
whether or not they will be selected.  To achieve this, the protocol for electing a leader
runs in three steps.  Each leader candidate submits two transactions to the burn chain -- one to register
their public key used for the election, and one to commit to their token burn and chain tip.
Once these transactions confirm, a leader is selected and the leader can
append and propagate block data.

Block selection is driven by a _verifiable random function_ (VRF).  Leaders submit transactions to
register their VRF proving keys, and later attempt to append a block by generating a
VRF proof over their preferred chain tip's _seed_ -- an unbiased random string
the leader learns after their tip's proof is committed.  The resulting VRF proof is used to
select the next block through cryptographic sortition, as well as the next seed.

The protocol is designed such that a leader can observe _only_ the burn-chain
data and determine the set of all Stacks blockchain forks that can plausibly
exist.  The on-burn-chain data gives all peers enough data to identify all plausible
chain tips, and to reconstruct the proposed block parent relationships and 
block VRF seeds.  The on-burn-chain data does _not_ indicate whether or not a block or a seed is
valid, however.

#### Step 1: Register key

In the first step of the protocol, each leader candidate registers itself for a
future election by sending a _key transaction_. In this transaction, the leader
commits to the public proving key that will be used by the leader candidate to
generate the next seed for the chain tip they will build off of.

The key transactions must be sufficiently confirmed on the burn chain
before the leader can commit to a chain tip in the next step.  For example, the
leader may need to wait for 10 epochs before it can begin committing to a chain
tip.  The exact number will be protocol-defined.

The key transaction can be used at any time to commit to a chain tip, once
confirmed.  This is because the selection of the next block cannot be determined
in advance.  However, a key can only be used once.

#### Step 2: Burn & Commit

Once a leader's key transaction is confirmed, the leader will be a candidate for election
for a subsequent burn block in which it must send a _commitment transaction_.
This transaction burns the leader's cryptocurrency (proof of burn)
and registers the leader's preferred chain tip and new VRF seed
for selection in the cryptographic sortition.

This transaction commits to the following information:

* the amount of cryptocurrency burned to produce the block
* the chain tip that the block will be appended to
* the proving key that will have been used to generate the block's seed
* the new VRF seed if this leader is chosen
* a digest of all transaction data that the leader _promises_ to include in their block (see
  "Operation as a leader").

The seed value is the cryptographic hash of the chain tip's seed (which is available on the burn chain)
and this block's VRF proof generated with the leader's proving key.  The VRF proof
itself is stored in the Stacks block header off-chain, but its hash -- the seed 
for the next sortition -- is committed to on-chain.

The burn chain block that contains the candidates' commitment transaction
serves as the election block for the leader's block (i.e. _N_), and is used to
determine which block commitment "wins."

#### Step 3: Sortition

In each election block, there is one election across all candidate leaders (across
all chain tips).  The next block is determined with the following algorithm:

```python
# inputs:
#   * BLOCK_HEADER -- the burn chain block header, which contains the PoW nonce
# 
#   * BURNS -- a mapping from public keys to proof of burn scores and block hashes,
#              generated from the valid set of commit & burn transaction pairs.
# 
#   * PROOFS -- a mapping from public keys to their verified VRF proofs from
#               their election transactions.  The domains of BURNS and PROOFS
#               are identical.
#
#   * SEED -- the seed from the previous winning leader
#
# outputs:
#   * PUBKEY -- the winning leader public key
#   * BLOCK_HASH -- the winning block hash 
#   * NEW_SEED -- the new public seed

def make_distribution(BURNS, BLOCK_HEADER):
   DISTRIBUTION = []
   BURN_OFFSET = 0
   BURN_ORDER = dict([(hash(PUBKEY + BLOCK_HEADER.nonce), 
                       (PUBKEY, BURN_AMOUNT, BLOCK_HASH))
                      for (PUBKEY, (BURN_AMOUNT, BLOCK_HASH)) in BURNS.items()])
   for (_, (PUBKEY, BURN_AMOUNT, BLOCK_HASH)) in sorted(BURN_ORDER.items()):
      DISTRIBUTION.append((BURN_OFFSET, PUBKEY, BLOCK_HASH))
      BURN_OFFSET += BURN_AMOUNT
   return DISTRIBUTION

def select_block(SEED, BURNS, PROOFS, BURN_BLOCK_HEADER.nonce):
   if len(BURNS) == 0:
      return (None, None, hash(BURN_BLOCK_HEADER.nonce+ SEED))

   DISTRIBUTION = make_distribution(BURNS)
   TOTAL_BURNS = sum(BURN_AMOUNT for (_, (BURN_AMOUNT, _)) in BURNS)
   SEED_NORM = num(hash(SEED || BURN_BLOCK_HEADER.nonce)) / TOTAL_BURNS
   LAST_BURN_OFFSET = -1
   for (INDEX, (BURN_OFFSET, PUBKEY, BLOCK_HASH)) in enumerate(DISTRIBUTION):
      if LAST_BURN_OFFSET <= SEED_NORM and SEED_NORM < BURN_OFFSET:
         return (PUBKEY, BLOCK_HASH, hash(PROOFS[PUBKEY]))
      LAST_BURN_OFFSET = BURN_OFFSET
   return (DISTRIBUTION[-1].PUBKEY, DISTRIBUTION[-1].BLOCK_HASH, hash(PROOFS[DISTRIBUTION[-1].PUBKEY]))
```

Only one leader will win an election.  It is not guaranteed that the block the
leader produces is valid or builds off of the best Stacks fork.  However,
once a leader is elected, all peers will know enough information about the
leader's decisions that the block data can be submitted and relayed by any other
peer in the network.  Crucially, the winner of the sortition will be apparent to
any peer without each candidate needing to submit their blocks beforehand.

The distribution is sampled using the _previous VRF seed_ and the _current block
PoW solution_.  This ensures that no one -- not even the burn chain miner -- knows
which public key in the proof of burn score distribution will be selected with the PoW seed.

Leaders can make their burn chain transactions and
construct their blocks however they want.  So long as the burn chain transactions
and block are broadcast in the right order, the leader has a chance of winning
the election.  This enables the implementation of many different leaders,
such as high-security leaders where all private keys are kept on air-gapped
computers and signed blocks and transactions are generated offline.

#### On the use of a VRF

When generating the chain tip commitment transaction, a correct leader will need to obtain the
previous election's _seed_ to produce its proof output.  This seed, which is
an unbiased public random value known to all peers (i.e. the hash of the
previous leader's VRF proof), is inputted to each leader candidate's VRF using the private
key it committed to in its registration transaction.  The new seed for the next election is
generated from the winning leader's VRF output when run on the parent block's seed
(which itself is an unbiased random value).  The VRF proof attests that only the
leader's private key could have generated the output value, and that the value
was deterministically generated from the key.

The use of a VRF ensures that leader election happens in an unbiased way.
Since the input seed is an unbiased random value that is not known to
leaders before they commit to their public keys, the leaders cannot bias the outcome of the election 
by adaptively selecting proving keys.
Since the output value of the VRF is determined only from the previous seed and is 
pseudo-random, and since the leader already
committed to the key used to generate it, the leader cannot bias the new
seed value once they learn the current seed.

Because there is one election per burn chain block, there is one valid seed per
epoch (and it may be a seed from a non-canonical fork's chain tip).  However as
long as the winning leader produces a valid block, a new, unbiased seed will be
generated.

In the event that an election does not occur in an epoch, or the leader
does not produce a valid block, the next seed will be
generated from the hash of the current seed and the epoch's burn chain block header
hash.  The reason this is reasonably safe in practice is because the resulting
seed is still unpredictable and impractical (but not infeasible) to bias.  This is because the burn chain miners are
racing each other to find a hash collision using a random nonce, and miners who
want to attempt to bias the seed by continuing to search for nonces that both
bias the seed favorably and solve the burn chain block risk losing the mining race against
miners who do not.  For example, a burn chain miner would need to wait an
expected two epochs to produce two nonces and have a choice between two seeds.
At the same time, it is unlikely that there will be epochs
without a valid block being produced, because (1) attempting to produce a block
is costly and (2) users can easily form burning pools to advance the
state of the Stacks chain even if the "usual" leaders go offline.

As an added security measure, the distribution into which the previous epoch's
VRF seed will index will be randomly structured using the VRF seed and the PoW
nonce.  This dissuades PoW miners from omitting or including burn transactions
in order to influence where the VRF seed will index into the weight
distribution.  Since the PoW miner is not expected to be able
to generate more than one PoW nonce per epoch, the burn chain miners won't know
in advance which leader will be elected.

## Operation as a leader

The Stacks blockchain uses a hybrid approach for generating block data:  it can
"batch" transactions and it can "stream" them.  Batched transactions are
anchored to the commitment transaction, meaning that the leader issues a _leading
commitment_ to these transactions.  The leader can only receive the block reward
if _all_ the transactions committed to in the commitment transaction
are propagated during its tenure.  The
downside of batching transactions, however, is that it significantly increases latency
for the user -- the user will not know that their committed transactions have been
accepted until the _next_ epoch begins.

In addition to sending batched transaction data, a Stacks leader can "stream" a
block over the course of its tenure by selecting transactions from the mempool
as they arrive and packaging them into _microblocks_.  These microblocks
contain small batches of transactions, which are organized into a hash chain to
encode the order in which they were processed.  If a leader produces
microblocks, then the new chain tip the next leader builds off of will be the
_last_ microblock the new leader has seen.

The advantage of the streaming approach is that a leader's transaction can be
included in a block _during_ the current epoch, reducing latency.
However, unlike the batch model, the streaming approach implements a _trailing commitment_ scheme.
When the next leader's tenure begins, it must select either one of the current leader's
microblocks as the chain tip (it can select any of them), or the current
leader's on-chain transaction batch.  In doing so, an epoch change triggers a
"micro-fork" where the last few microblocks of the current leader may be orphaned,
and the transactions they contain remain in the mempool.  The Stacks protocol
incentivizes leaders to build off of the last microblock they have seen (see
below).

The user chooses which commitment scheme a leader should apply for her
transactions.  A transaction can be tagged as "batch only," "stream only," or
"try both."  An informed user selects which scheme based on whether or not they
value low-latency more than the associated risks.

To commit to a chain tip, each correct leader candidate first selects the transactions they will
commit to include their blocks as a batch, constructs a Merkle tree from them, and
then commits the Merkle tree root of the batch
and their preferred chain tip (encoded as the hash of the last leader's
microblock header) within the commitment transaction in the election protocol.
Once the transactions are appended to the burn chain, the leaders execute
the third round of the election protocol, and the
sortition algorithm will be run to select which of the candidate leaders will be
able to append to the Stacks blockchain.  Once selected, the new leader broadcasts their
transaction batch and then proceeds to stream microblocks.

### Building off the latest block

Like existing blockchains, the leader can selet any prior block as its preferred
chain tip.  In the Stacks blockchain, this allows leaders to tolerate block loss by building
off of the latest-built ancestor block's parent.

To encourage leaders to propagate their batched transactions if they are selected, a
commitment to a block on the burn chain is only considered valid if the peer
network has (1) the transaction batch, and (2) the microblocks the leader sent
up to the next leader's chain tip commitment on the same fork.  A leader will not receive any compensation
from their block if any block data is missing -- they eventually must propagate the block data
in order for their rewards to materialize (even though this enables selfish
mining; see below).

The streaming approach requires some additional incentives to
encourage leaders to build off of the latest known chain tip (i.e. the latest
microblock sent by the last leader).  In particular, the streaming model enables
the following two safety risks that are not present in the batching approach:

* A leader who gets elected twice in a row can adaptively orphan its previous
  microblocks by building off of its first tenures' chain tip, thereby
double-spending transactions the user may believe are already included.

* A leader can be bribed during their tenure to omit transactions that are
  candidates for streaming.  The price of this bribe is much smaller than the
cost to bribe a leader to not send a block, since the leader only stands to lose
the transaction fees for the targeted transaction and all subsequently-mined
transactions instead of the entire block reward.  Similarly, a leader can
be bribed to mine off of an earlier microblock chain tip than the last one it has seen
for less than the cost of the block reward.

To help discourage both self-orphaning and "micro-bribes" to double-spend or
omit specific transactions or trigger longer-than-necessary micro-forks, leaders are
rewarded only 40% of their transaction fees in their block reward (including
those that were batched).  They receive
60% of the previous leader's transaction fees.  This result was shown in the
Bitcoin-NG paper to be necessary to ensure that honest behavior is the most
profitable behavior in the streaming model.

The presence of a batching approach is meant to raise the stakes for a briber.
Users who are worried that the next leader could orphan their transactions if
they were in a microblock would instead submit their transactions to be batched.
Then, if a leader selects them into its tenure's batch, the leader would
forfeit the entire block reward if even one of the batched transactions was
missing.  This significantly increases the bribe cost to leaders, at the penalty
of higher latency to users.  However, for users who need to send 
transactions under these circumstances, the wait would be worth it.

Users are encouraged to use the batching model for "high-value" transactions and
use the streaming model for "low-value" transactions.  In both cases, the use
of a high transaction fee makes their transactions more likely to be included in
the next batch or streamed first, which additionally raises the bribe price for
omitting transactions.

### Leader volume limits

A leader propagates blocks irrespective of the underlying burn chain's capacity.
This poses a DDoS vulnerability to the network:  a high-transaction-volume
leader may swamp the peer network with so many
transactions and microblocks that the rest of the nodes cannot keep up.  When the next
epoch begins and a new leader is chosen, it would likely orphan many of the high-volume
leader's microblocks simply because its view of the
chain tip is far behind the high-volume leader's view. This hurts the
network, because it increases the confirmation time of transactions
and may invalidate previously-confirmed transactions.

To mitigate this, the Stack chain places a limit on the volume of
data a leader can send during its epoch (this places a _de facto_ limit
on the number of transactions in a Stack block). This cap is enforced
by the consensus rules.  If a leader exceeds this cap, the block is invalid.

### Batch transaction latency

The fact that leaders execute a leading commmitment to batched transactions means that
it takes at least one epoch for a user to know if their transaction was
incorporated into the Stacks blockchain.  To get around this, leaders are
encouraged to to supply a public API endpoint that allows a user to query
whether or not their transaction is included in the burn (i.e. the leader's
service would supply a Merkle path to it).  A user can use a set of leader
services to deduce which block(s) included their transaction, and calculate the
probability that their transaction will be accepted in the next epoch.
Leaders can announce their API endpoints via the [Blockstack Naming
Service](https://docs.blockstack.org/core/naming/introduction.html).

The specification for this transaction confirmation API service is the subject
of a future SIP.  Users who need low-latency confirmations today and are willing
to risk micro-forks and intentional orphaning can submit their transactions for
streaming.

## Burning pools

Proof-of-burn mining is not only concerned with electing leaders, but also concerned with
enhancing chain quality.  For this reason, the Stacks chain not
only rewards leaders who build on the "best" fork, but also each peer who
supported the "best" fork by burning cryptocurrency in support of the winning leader.
The leader that commits to the winning chain tip and the peers who also burn for
that leader collectively share in the block's reward, proportional to how much
each one burned.

### Encouraging honest leaders

The reason for allowing users to support leader candidates at all is to help
maintain the chain's liveness in the presence of leaders who follow the
protocol correctly, but not honestly.  These include leaders who delay
the propagation of blocks and leaders who refuse to mine certain transactions.
By giving users a very low barrier to entry to becoming a leader, and by giving
other users a way to help a known-good leader candidate get selected, the Stacks blockchain
gives users a first-class stake in deciding which transactions to process
as well as incentivizes them to maintain chain liveness in the face of bad
leaders.  In other words, leaders stand to make more make money with
the consent of the users.

Users support their preferred leader by submitting a burn transaction that contains a 
proof of burn and references its leader candidate's chain tip commitment.  These user-submitted
burns count towards the leader's total score for the election, thereby increasing the chance
that they will be selected (i.e. users submit their transactions alongside the
leader's block commitment).  Users who submit proofs for a leader that wins the election
will receive some Stacks tokens alongside the leader (but users whose leaders
are not elected receive no reward).  Users are rewarded alongside leaders by
granting them a share of the block's coinbase.

Allowing users to vote in support of leaders they prefer gives users and leaders
an incentive to cooperate.  Leaders can woo users to submit proofs for them by committing
to honest behavior, and users can help prevent dishonest (but more profitable)
leaders from getting elected.  Moreover, leaders cannot defraud users who submit
proofs in their support, since users are rewarded by the election protocol itself.

### Fair mining

Because all peers see the same sequence of burns in the Stacks blockchain, users
can easily set up distributed mining pools where each user receives a fair share
of the block rewards for all blocks the pool produces.  The selection of a
leader within the pool is arbitrary -- as long as _some_ user issues a key
transaction and a commitment transaction, the _other_ users in the pool can
throw their proofs of burn behind a chain tip.  Since users who submitted proofs for the winning
block are rewarded by the protocol, there is no need for a pool operator to
distribute rewards.  Since all users have global visibility into all outstanding
proofs, there is no need for a pool operator to direct users to work on a
particular block -- users can see for themselves which block(s) are available by
inspecting the on-chain state.

Users only need to have a way to query what's going into a block when one of the pool
members issues a commitment transaction.  This can be done easily for batched
transactions -- the transaction sender can prove that their transaction is
included by submitting a Merkle path from the root to their transaction.  For
streamed transactions, leaders have a variety of options for promising users
that they will stream a transaction, but these techniques are beyond the scope of this SIP.

### Minimizing reward variance

Leaders compete to elect the next block by burning more cryptocurrency and/or
spending more energy.  However, if they lose the election, they lose the cryptocurrency they burned.
This makes for a "high variance" pay-out proposition that puts leaders in a
position where they need to maintain a comfortable cryptocurrency buffer to
stay solvent.

To reduce the need for such a buffer, making proofs of burn to support competing chain tips
enables leaders to hedge their bets by generating proofs to support _all_ plausible
competing chain tips.  Leaders have the option of submitting proofs in support for a
_distribution_ of competing chain tips at a lower cost than committing to many
different chain tips as leaders.  This gives them the ability to receive some
reward no matter who wins.  This also reduces the barrier to
entry for becoming a leader in the first place.

### Leader support mechanism

There are a couple important considerations for the mechanism by which peers
submit proofs for their preferred chain tips.

* Users and runner-up leaders are rewarded strictly fewer tokens
for committing to a chain tip that does not get selected.  This is
  important because leaders and users are indistinguishable
on-chain.  Leaders should not be able to increase their expected reward by sock-puppeting,
and neither leaders nor users should get an out-sized reward for voting for
invalid blocks or blocks that will never be appended to the canonical fork.

* It must be cheaper for a leader to submit a single expensive commitment than it is
  to submit a cheap commitment and a lot of user-submitted proofs.  This is
important because it should not be possible for a leader to profit more from
adaptively increasing their proof submissions in response to other leaders'.

The first property is enforced by the reward distribution rules (see below),
whereby a proof commitment only receives a reward if its block successfully extended the
"canonical" fork.  The second property is given "for free" because the underlying burn chain
assesses each participant a burn chain transaction fee.  Users and leaders incur an ever-increasing
cost of trying to adaptively out-vote other leaders by submitting more and more
transactions.  Further, peers who want to support a leader candidate must send their burn transactions _in the
same burn chain block_ as the commitment transaction.  This limits the degree to
which peers can adaptively out-bid each other to include their
commitments.

## Reward distribution

New Stacks tokens come into existence on a fork in an epoch where a leader is
selected, and are granted to the leader if the leader produces a valid block.
However, the Stacks blockchain pools all tokens created and all transaction fees received and
does not distribute them until a large number of epochs (a _lockup period_) has
passed.  The tokens cannot be spent until the period passes.

### Sharing the rewards among winners

Block rewards (coinbases and transaction fees) are not granted immediately,
but are delayed for a lock-up period.  Once the lock-up period passes,
the exact reward distribution is as follows:

* Coinbases: The coinbase (newly-minted tokens) for a block is rewarded to the leader who
  mined the block, as well as to all individuals who submitted proofs-of-burn in 
support of it.  Each participant (leaders and supporting users) recieves a
portion of the coinbase proportional to the fraction of total tokens destroyed.

* Batched transactions:  The transaction fees for batched transactions are
  distributed exclusively to the leader who produced the block, provided that
the block has enough transactions. 

   To discourage mining empty blocks, an anchored block must be _F_% "full" for the
   leader to receive its transaction fees.  A block's "fullness" is measured by
   how much transaction-computing capacity the block has consumed (see SIP 006).
   Failure to mine a block that is at least _F_% full will be penalized:
   if the miner does not fill the block to at least _F_% capacitiy, then the
   miner will receive _P * M_ STX instead of the transaction fees, where:

   * _0 < M_ is the minimum allowable transaction fee rate,
   * _0 < P < F_ is the fraction of the block that the miner was able to fill.

   Note that _P * M_ is strictly less than the lowest possible sum of the
   transaction fees of any _F_%-full block.

   This is in the service of implementing the fee auction strategy described in [1]. 
   However, unlike in [1], no transaction fee smoothing will take place -- the
   leader receives all of the anchored block's transaction fees.

* Streamed transactions:  the transaction fees for streamed transactions are
  distributed according to a 60/40 split -- the leader that validated the
transactions is awarded 60% of the transaction fees, and the leader that builds
on top of them is awarded 40%.  This ensures that leaders are rewarded for
processing and validating transactions correctly _while also_ incentivizing the
subsequent leader to include them in their block, instead of orphaning them.

## Recovery from data loss

Stacks block data can get lost after a leader commits to it.  However, the burn
chain will record the chain tip, the batched transactions' hash, and the leader's public
key.  This means that all existing forks will be
known to the Stacks peers that share the same view of the burn chain (including
forks made of invalid blocks, and forks that include blocks whose data was lost
forever).

What this means is that regardless of how the leader operates, its
chain tip commitment strategy needs a way to orphan a fork of any length.  In
correct operation, the network recovers from data loss by building an
alternative fork that will eventually become the "best" fork,
thereby recovering from data loss and ensuring that the system continues
to make progress.  Even in the absence of malice, the need for this family of strategies
follows directly from a single-leader model, where a peer can crash before
producing a block or fail to propagate a block during its tenure.

However, there is a downside to this approach: it enables **selfish mining.**  A
minority coalition of leaders can statistically gain more Stacks tokens than they are due from
their burns by attempting to build a hidden fork of blocks, and releasing it
once the honest majority comes within one block height difference of the hidden
fork.  This orphans the majority fork, causing them to lose their Stacks tokens
and re-build on top of the minority fork.

### Seflish mining mitigation strategies

Fortunately, all peers in the Stacks blockchain have global knowledge of state,
 time, and block-commit transactions.  Intuitively, this gives the Stacks blockchain some novel tools
for dealing with selfish leaders:

* Since all nodes know about all blocks that have been committed, a selfish leader coalition
  cannot hide its attack forks. The honest leader coalition can see
the attack coming, and evidence of the attack will be preserved in the burn
chain for subsequent analysis.  This property allows honest leaders
to prepare for and mitigate a pending attack by burning more
cryptocurrency, thereby reducing the fraction
of votes the selfish leaders wield below the point where selfish mining is profitable (subject to network
conditions).

* Since all nodes have global knowledge of the passage of time, honest leaders
  can agree on a total ordering of all chain tip commits.  In certain kinds of
selfish mining attacks, this gives honest leaders the ability to identify and reject an attack fork 
with over 50% confidence.  In particular, honest leaders who have been online long
enough to measure the expected block propagation time would _not_ build on top of
a chain tip whose last _A > 1_ blocks arrived late, even if that chain tip
represents the "best" fork, since this would be the expected behavior of a selfish miner.

* Since all nodes know about all block commitment transactions, the long tail of small-time participants
(i.e. users who support leaders) can collectively throw their resources behind
known-honest leaders' transactions.  This increases the chance that honest leaders will
be elected, thereby increasing the fraction of honest voting power and making it
harder for a selfish leader to get elected.

* All Stacks nodes relay all blocks that correspond to on-chain commitments,
even if they suspect that they came from the attacker.  If an honest leader finds two chain tips of equal
length, it selects at random which chain tip to build off of.  This ensures that
the fraction of honest voting that builds on top of the attack fork versus the honest fork
is statistically capped at 50% when they are the same length.

None of these points _prevent_ selfish mining, but they give honest users and
honest leaders the tools to make selfish mining more difficult to pull off than in
PoW chains.  Depending on user activity, they also make economically-motivated
leaders less likely to participate in a selfish miner cartel -- doing so always produces evidence,
which honest leaders and users can act on to reduce or eliminate 
their expected rewards.

Nevertheless, these arguments are only intuitions at this time.  A more
rigorous analysis is needed to see exactly how these points affect the
profitibility of selfish mining.  Because the Stacks blockchain represents a
clean slate blockchain design, we have an opportunity to consider the past
several years of research into attacks and defenses against block-hiding
attacks.  This section will be updated as our understanding evolves.

## Fork Selection

Fork selection in the Stacks blockchain requires a metric to determine which
chain, between two candidates, is the "best" chain.  For Stacks, **the fork with
the most blocks is the best fork.**  That is, the Stacks blockchain measures the
quality of block _N_'s fork by the total amount of _blocks_ which _confirm_
block _N_.

Using chain length as the fork choice rule makes it time-consuming for alternative forks to
overtake the "canonical" fork, no matter how many burn tokens the alternative-fork miners have at their disposal.
In order to carry out a deep fork of _K_ blocks, the majority coalition of participants needs to spend
at least _K_ epochs working on the new fork. We consider this acceptable
because it also has the effect of keeping the chain history relatively stable, 
and makes it so every participant can observe (and prepare for) any upcoming
forks that would overtake the canonical history.  However, a minority
coalition of dishonest leaders can create short-lived forks by continuously
building forks (i.e. in order to selfishly mine), driving up the confirmation
time for transactions in the honest fork.

This fork choice rule implies a time-based transaction security measurement.  A
transaction _K_ blocks in the past will take at least _K_ epochs to reverse.
The expected cost of doing so can be calculated given the total amount of burned
tokens put into producing blocks, and the expected fraction of the
totals controlled by the attacker.  Note that the attacker is only guaranteed to
reverse a transaction _K_ blocks back if they consistently control over 50% of the total
amount of tokens burned.

## Implementation

The Stacks blockchain leader election protocol will be written in Rust.

## Bitcoin Wire Formats

The election process described in this SIP will be implemented for the Stacks blockchain
on top of the Bitcoin blockchain. There are three associated operations, with the following
wire formats:

### Leader Block Commit

Leader block commits require at least two Bitcoin outputs. The first output is an `OP_RETURN`
with the following data:

```
            0      2  3            35               67     71     73    77   79     80
            |------|--|-------------|---------------|------|------|-----|-----|-----|
             magic  op   block hash     new seed     parent parent key   key   burn parent
                                                     block  txoff  block txoff   modulus
```

Where `op = [` and:

* `block_hash` is the header block hash of the Stacks anchored block.
* `new_seed` is the next value for the VRF seed
* `parent_block` is the burn block height of this block's parent.
* `parent_txoff` is the vtxindex for this block's parent's block commit.
* `key_block` is the burn block height of the miner's VRF key registration
* `key_txoff` is the vtxindex for this miner's VRF key registration
* `burn_parent_modulus` is the burn block height at which this leader block commit
  was created modulo `BURN_COMMITMENT_WINDOW` (=6). That is, if the block commit is
  included in the intended burn block then this value should be equal to:
  `(commit_burn_height - 1) % 6`. This field is used to link burn commitments from
  the same miner together even if a commitment was included in a late burn block.

The second output is the burn commitment. It must send funds to the canonical burn address.

The first input of this Bitcoin operation must have the same address as the second output
of the VRF key registration.

### Leader VRF Key Registrations

Leader VRF key registrations require at least two Bitcoin outputs. The first output is an `OP_RETURN`
with the following data:

```
        0      2  3              23                       55                          80
        |------|--|---------------|-----------------------|---------------------------|
         magic  op consensus hash    proving public key               memo
```

Where `op = ^` and:

* `consensus_hash` is the current consensus hash for the burnchain state of the Stacks blockchain
* `proving_public_key` is the 32-byte public key used in the miner's VRF proof
* `memo` is a field for including a miner memo

The second output is the address that must be used as an input in any of the miner's block commits.

### User Support Burns

User support burns require at least two Bitcoin outputs. The first output is an `OP_RETURN`
with the following data:

```
            0      2  3              22                       54                 74       78        80
            |------|--|---------------|-----------------------|------------------|--------|---------|
             magic  op consensus hash    proving public key       block hash 160   key blk  key
                       (truncated by 1)                                                     vtxindex
```

Where `op = _` and:

* `consensus_hash` is the current consensus hash for the burnchain state of the Stacks blockchain
* `proving_public_key` is the 32-byte public key used in the miner's VRF proof
* `block_hash_160` is the hash_160 of the Stacks anchored block
* `key_blk` is the burn block height of the VRF key used in the miner's VRF proof
* `key_vtxindex` is the vtxindex of the VRF key used in the miner's VRF proof

The second output is the burn commitment. It must send funds to the canonical burn address.

## References

[1] Basu, Easley, O'Hara, and Sirer. [Towards a Functional Market for Cryptocurrencies.](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3318327)

## Appendix

### Definitions

**Burn chain**: the blockchain whose cryptocurrency is destroyed in burn-mining.

**Burn transaction**: a transaction on the burn chain that a Stacks miner issues
in order to become a candidate for producing a future block.  The transaction
includes the chain tip to append to, and the proof that cryptocurrency was
destroyed.

**Chain tip**: the location in the blockchain where a new block can be appended.
Every valid block is a valid chain tip, but only one chain tip will correspond
to the canonical transaction history in the blockchain.  Miners are encouraged
to append to the canonical transaction history's chain tip when possible.

**Cryptographic sortition** is the act of selecting the next leader to
produce a block on a blockchain in an unbiased way.  The Stacks blockchain uses
a _verifiable random function_ to carry this out.

**Election block**: the block in the burn chain at which point a leader is
chosen.  Each Stacks block corresponds to exactly one election block on the burn
chain.

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
