# Abstract

This proposal describes a mechanism for single-leader election using
_proof-of-burn mining_.  The Stacks blockchain grows in tandem with an
underlying "burn blockchain" whose cryptocurrency tokens are destroyed in order to produce a
Stacks block.  Proof-of-burn mining is concerned with deciding
which Stacks block miner (called _leader_ in this text) is elected for
producing the next block, as well as deciding how to resolve
conflicting transaction histories.

# Introduction

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

## 1. High validation throughput

The number of Stacks transactions processed is decoupled from the
transaction processing rate of the underlying burn chain.  Before, each Stacks
transaction was coupled to a single Bitcoin transaction.  In the Stacks
blockchain, an _entire block_ of Blockstack transactions corresponds to a
Bitcoin transaction.  This significantly improves cost/byte ratio for processing
Blockstack transactions, thereby effectively increasing its throughput.

## 2. An open leadership set

The Stacks blockchain uses proof-of-burn mining to decide who appends the next
block.  The protocol (described in this SIP) ensures that anyone can become
a leader, and no coordination amongst leaders is required to produce a block.
This preserves the open-leadership property from the existing blockchain (where
Blockstack blockchain miners were also Bitcoin miners), but realizes it through
an entirely different mechanism that enables the properties listed here.

## 3. Participation without mining hardware

Producing a block in the Stacks blockchain takes negligeable energy on top of
the burn blockchain.  Instead, would-be miners _burn_ an existing cryptocurrency
by rendering it unspendable.  The rate at which the cryptocurrency is destroyed
is what drives block production in the Stacks blockchain.  As such, anyone who
can aquire the burn cryptocurrency (e.g. Bitcoin) can participate in mining,
_even if they can only afford a minimal amount_.

## 4. Ability to migrate to a separate burn chain in the future

A key lesson learned in the design of the first-generation blockchain is that
the network must be portable, in order to survive systemic failures such as peer
network collapse, 51% attacks, and merge miners dominating the hash power.
The proof-of-burn mining system will preserve this feature,
so the underlying burn chain can be "swapped out" at a later date if need be.

## 5. Ability for users to help select which leaders are elected

The design of proof-of-work (PoW) blockchains is that there is "one CPU, one
vote."  This has not played out in practice, since this is fundamentally
unrealizable in a world where different players have different amounts of
capital and access to cheap electricity.  Users of these systems who do not have
access to one of these must fork the blockchain if they want to undermine 
bad-faith miner decisions.

The Stacks blockchain offers a remediation mechanism whereby users can help
_influence_ which Stacks miner gets to produce the next block.  The system is
structured such that miners cannot efficiently buy users (doing so is more expensive 
than participating in proof-of-burn honestly), but users can increase the chance
that a miner discovers a block.  Users that help a miner discover a block share
in the block reward, effectively making them first-class stakeholders in the
network's evolution.  Importantly, users who participate receive Stacks tokens,
no matter how little they burn.

## Assumptions

Given the design goals, the Stacks leader election protocol makes the following
assumptions:

* Deep forks in the burn chain are exponentially rarer as a function of their
  length.

* Deep forks in the burn chain occur for reasons unrelated to the Stacks protocol execution.  That
  is, miners do not attempt to manipulate the execution of the Stacks protocol
by reorganizing the burn chain.

* Burn chain miners do not censor all Stacks transactions (i.e. liveness is
  possible).

* At least 2/3 of the Stacks leader candidates (measured by burn weight) are correct and honest.

* The majority of users (by burn weight) who help leaders get elected only help
known-honest leaders.

# Protocol overview

Like existing blockchains, the Stacks blockchain encodes a cryptocurrency and
rules for spending its tokens.  Like existing cryptocurrencies, the Stacks
blockchain introduces new tokens into circulation each time a new block is
produced (a _block reward_).  This encourages peers to participate in gathering transactions and
creating new blocks.  Peers that do so so called _leaders_ of the blocks that
they produce (analogous to "miners" in existing cryptocurrencies).

Blocks are made of one or more _transactions_, which encode valid state
transitions in each correct peer.  Users create and broadcast transactions to the peer
network in order to (among other things) spend the tokens they own.

Like existing cryptocurrencies, users compete with one another for _space_ and
_CPU time_ in the underlying blockchain's peers for storing their transactions.  This competition is
realized through transaction fees -- users include an extra token payment in
their transactions to encourage Stacks leaders to incorporate their transactions
first.  Leaders receive the transaction fees of the transactions they
package into their blocks _in addition_ to the tokens minted by producing them.

Blocks are produced in the Stacks blockchain in cadence with the underlying burn
chain.  Each time the burn chain produces a block, at most one Stacks block
will be produced.  In doing so, the burn chain acts as a decentralized
rate-limiter for creating Stacks blocks, thereby preventing DDoS attacks.
Each block discovery on the burn chain triggers a new _epoch_ in the Stacks
blockchain, whereby a new leader is elected.

With the exception of a designated _genesis block_, each block in the Stacks
blockchain has exactly one "parent" block.  This parent relationship is a
partial ordering of blocks, where concurrent blocks (and their descendents)
are _forks_.

If the leader produces a block, it must have an already-accepted block as its
parent.  A block is "accepted" if it has been successfully
processed by all correct peers and exists in at least one blockchain fork.

## Novel properties enabled by proof-of-burn mining

Each Stacks block is anchored to the burn chain by
way of a cryptographic hash.  That is, the burn chain's canonical transaction
history contains the hashes of all Stacks blocks ever produced -- even ones that
were not incorporated into any fork of the Stacks blockchain.  This gives the
Stacks blockchain three properties that existing blockchains do not possess:

* **Global knowledge of time** -- Stacks blockchain peers each perceive the passage of time
  consistently by measuring the growth of the underlying burn chain.  In
particular, all correct Stacks peers that have same view of the burn chain can
determine the same total order of Stacks blocks.  Existing blockchains do not
have this, and cannot reason about arrival times for blocks that are not
yet known to be part of a fork.

* **Global knowledge of blocks** -- Each correct Stacks peer with the same
  view of the burn chain will also have the same view of the set of Stacks
blocks that *exist*.  Existing blockchains do not have this, but instead
rely on a well-connected peer graph to gossip all blocks to all peers.

* **Global knowledge of burns** -- Each correct stacks peer with the same view
  of the burn chain will know how much cumulative cryptocurrency was destroyed
in order to produce the blockchain (as well as when it was destroyed).  Existing
blockchains do not have this -- a private fork can coexist with all public
forks and be released at its creators' discression (often with harmful effects
on the peer network).

The Stacks blockchain leverages these properties to implement two key features:

* **Mitigate block-withholding attacks**:  Like all single-leader blockchains,
  the Stacks blockchain allows the existence of multiple blockchain forks.
These can arise whenever a leader is selected but does not produce a block.  The
design of the Stacks blockchain leverages the fact that all _attempts_ to produce
a block are known to all leaders in advance in order to detect and mitigate
block-withholding attacks.

* **Users enhance chain quality**:  In the Stacks blockchain, users can enhance
  their preferred fork's chain quality by _contributing_ burns to their
preferred leader.  This in turn helps ensure chain liveness -- users can help
honest leaders get elected and punish dishonest leaders that withhold blocks
(and if this were not motivation enough, the Stacks blockchain also offers a financial incentive for
doing so).

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

Because anyone can become a leader, this means that even misbehaving leaders can
be selected.  If a leader crashes before it can propagate their blocks, or if
it produces an invalid block, then no block will be appended to the
leader's chain tip during its epoch.  Also, if a leader is operating off of
stale data, then the leader _may_ produce a block
whose parent is not the latest block on the "best" fork.

A consequence of tolerating these failed leaders is that the Stacks blockchain 
may have multiple competing forks; one of which is considered the canonical fork
with the "best" chain tip.  However, a well-designed
blockchain encourages leaders to identify the "best" fork and append blocks to
it by requiring them to _irrevocably commit_ to the
chain tip they will build on for their epoch.
This commitment must be tied to an expenditure of some
non-free resource, like energy, storage, bandwidth, or (in this blockchain's case) an
existing cryptocurrency.  The intution is that if the leader does _not_ build on
the "best" fork, then they commit to and lose that resource at a loss.

This tactic is used to encourage both safety and liveness in other blockchains
today. For example, in Bitcoin, miners search for the inverse of a hash that
contains the current chain tip. If they fail to win that block, they
have wasted that energy. As they must attempt deeper and deeper forks
to initiate a double-spend attacks, producing a competing fork becomes an exponentially-increasing energy
expenditure.  The only way for the leader to recoup their losses is for the
fork they work on to be considered by the rest of the network as the "best" fork
(i.e. the one where the tokens they minted are spendable).  While this does
not _guarantee_ liveness or safety, penalizing leaders that do not append blocks to the 
"best" chain while rewarding leaders that do provides a strong economic
incentive for leaders to build and append new blocks to the "best" fork
(liveness) and to _not_ attempt to build an alternative fork that reverts
previously-committed blocks (safety).

It is important that the Stacks blockchain offers the same encouragement.
In particular, the ability for leaders to intentionally orphan blocks in order
to initiate double-spend attacks is an undesirable safety violation,
and leaders that do so should be penalized.  This property is enforced by
making a leader announce their chain fork commitment _before they know if their
blocks are included_ -- they can only receive Stacks tokens if the block for
which they burned is accepted into the "best" fork.

## Election Protocol

To encourage safety and liveness when appending to the blockchain, the leader
election protocol requires leaders to burn cryptocurrency before they know
whether or not their block will be accepted, and before they even know what the
chain tip _is_.   To achieve this, the protocol for electing a leader
runs in three steps.  Each leader
candidate submits two transactions to the burn chain -- one to register
their public key used for the election, and one to commit to their burn amount and block.
Once these transactions confirm, a block is selected.

Block selection is driven by a _verifiable random function_ (VRF).  Leaders burn to
register their proving keys, and later attempt to append a block by generating a
VRF proof over their preferred chain tip's _seed_ -- an unbiased random string
the leader learns after their burn is committed.  The resulting proof is used to
select the next block through cryptographic sortition, as well as the next seed.

The protocol is designed such that a leader can observe _only_ the burn-chain
data and determine the set of all Stacks blockchain forks that can plausibly
exist.  The on-chain data gives all peers enough data to identify all plausible
chain tips, and to reconstruct the proposed block parent relationships and 
block VRF seeds.  The on-chain data does _not_ indicate whether or not a block is
invalid, however.

### Step 1: Register key

In the first step of the protocol, each leader candidate registers itself for a
future election by sending a _key transaction_. In this transaction, the leader
commits to the public proving key that will be used by the leader candidate to
generate the next seed for the block they will append.

The key transactions must be sufficiently confirmed on the burn chain
before the leader can commit to a block in the next step.  For example, the
leader may need to wait for 10 epochs before it can begin committing to a block.

The key transaction has a short lifetime in the protocol.  It must be consumed
by a subsequent commitment transaction within a small number of epochs (e.g.
less than 100) before it expires.  Once a key transaction is spent or expires,
the public proving key _cannot be used again_.

### Step 2: Burn & Commit

Once a leader's key transaction is confirmed, the leader will be a candidate for election
for a subsequent burn block in which it must send a _commitment transaction_.
This transaction both burns the leader's cryptocurrency
(proof-of-burn) and registers the leader's block and new VRF seed
for selection in the cryptographic sortition.

This transaction commits to the following information:

* the amount of cryptocurrency destroyed to produce the block
* the block that the leader candidate will append
* the chain tip that the block will be appended to
* the proving key that will have been used to generate the block's seed
* the new VRF seed if this block is chosen

The seed value is the cryptographic hash of the parent block's seed (on the burn chain)
and this block's VRF proof generated with the leader's proving key.  The VRF proof
is stored in the Stacks block header.

The leader has a 1-epoch window of time in which to generate a commitment
transaction that matches its key transaction (i.e. if the key transaction is
included at height _H_, then the commitment must be included at height _H+K_ for
fixed _K_).  This is because leaders cannot be allowed to have a choice as to
which seed they will build off of; otherwise they might be able to influence the
sortition.

The burn chain block that contains the candidates' commitment transaction
serves as the election block for the leader's block (i.e. _N_), and is used to
determine which block commitment "wins."

### Step 3: Sortition

In each election block, there is one election per distinct chain tip committed
to.  The next block for each chain tip is determined with
the following algorithm:

```python
# inputs:
#   * BURNS -- a mapping from public keys to burn amounts and block hashes,
#              generated from the valid set of commit & burn transaction pairs.
# 
#   * PROOFS -- a mapping from public keys to their verified VRF proofs from
#               their election transactions.  The domains of BURNS and PROOFS
#               are identical.
#
#   * SEED -- the seed from the previous chain tip
#
# outputs:
#   * PUBKEY -- the winning leader public key
#   * BLOCK_HASH -- the winning block hash 
#   * NEW_SEED -- the new public seed

def make_distribution(BURNS):
   DISTRIBUTION = []
   BURN_OFFSET = 0
   for (PUBKEY, (BURN_AMOUNT, BLOCK_HASH)) in sorted(BURNS.items()):
      DISTRIBUTION.append((BURN_OFFSET, PUBKEY, BLOCK_HASH))
      BURN_OFFSET += BURN_AMOUNT
   return DISTRIBUTION

def select_block(SEED, BURNS, PROOFS):
   DISTRIBUTION = make_distribution(BURNS)
   TOTAL_BURNS = sum(BURN_AMOUNT for (_, (BURN_AMOUNT, _)) in BURNS)
   SEED_NORM = num(SEED) / TOTAL_BURNS
   LAST_BURN_OFFSET = -1
   for (INDEX, (BURN_OFFSET, PUBKEY, BLOCK_HASH)) in enumerate(DISTRIBUTION):
      if LAST_BURN_OFFSET <= SEED_NORM and SEED_NORM < BURN_OFFSET:
         return (PUBKEY, BLOCK_HASH, hash(PROOFS[PUBKEY]))
      LAST_BURN_OFFSET = BURN_OFFSET
   return (DISTRIBUTION[-1].PUBKEY, DISTRIBUTION[-1].BLOCK_HASH, hash(PROOFS[DISTRIBUTION[-1].PUBKEY]))
```

Only one leader per distinct chain tip will win an election.
Once a leader is elected, all peers will know enough information about the
leader's decisions that the block can be submitted and relayed by any other
peer in the network.  Leaders can make their burn chain transactions and
construct their blocks however they want.  So long as the burn chain transactions
and block are broadcast in the right order, the leader has a chance of winning
the block race.  This enables the implementation of many different leaders,
including high-security leaders where all private keys are kept on air-gapped
computers and signed blocks and transactions are generated offline.

### On the use of a VRF

When generating the second and third transactions, a correct leader will need to obtain the
parent block's _seed_ to produce its proof output.  This seed, which is
an unbiased public random value known to all peers (i.e. the hash of the
previous block's VRF proof), is inputted to each leader candidate's VRF using the private
key it committed to in its burn transaction.  The new seed for the next election is
generated from the winning leader's VRF output when run on the parent block's seed
(which itself is an unbiased random value).  The VRF proof attests that only the
leader's private key could have generated the output value.

The use of a VRF ensures that leader election happens in an unbiased way.
Since the input seed is an unbiased random value that is not known to
leaders before they commit to their public keys, the leaders cannot bias the outcome of the election.
Since the output value of the VRF is determined only from the previous seed and is 
pseudo-random, and since the leader already
committed to the key used to generate it, the leader cannot bias the new
seed value once they learn the current seed.

# Operation as a leader

The Stacks blockchain uses a "batch model" to commit to a chain tip.  Leaders
commit to entire blocks before they know whether or not their block was
selected.  In other words, the election protocol ensures that leaders make
_leading commitments_ to their blocks.

Using a leading commitment scheme is necessary to prevent a leader from adaptively orphaning its blocks
in a bid to double-spend.  If the leader wants to orphan itself N+1 times by being
selected N times, it needs to first commit to N blocks (and burn the requisite
amount of cryptocurrency for them).  This makes this strategy similar to how
existing PoW blockchains work.  An alternative commitment strategy whereby
blocks are adaptively streamed into the peer network is discussed in the
appendix, and was ultimatley rejected because it could not provide this
guarantee.

To commit to a chain tip, each correct leader candidate first selects the transactions they will
include in their blocks, and commit to their block's hash and block's parent in their
burn transactions in the second round of the election protocol.
Once the transactions are confirmed on the burn chain, the leaders execute
the third round of the election protocol, and the
sortition algorithm will be run to select which of the candidate blocks will be
added to the Stacks blockchain.  The candidate that produced the block was the
leader for that epoch.  The leader then announces their block to the peer
network.

## Building off the latest block

Like existing blockchains, the leader can commit to any prior parent block.  In
the Stacks blockchain, this allows leaders to tolerate block loss by building
off of the latest-built ancestor block's parent.

To encourage leaders to propagate their blocks if they are selected, a
commitment to a block on the burn chain is only considered valid if the peer
network has data for it.  A leader will not receive any compensation
by passively winning elections -- they eventually must propagate the block 
in order for their rewards to materialize (even though this enables selfish
mining; see below).

_TODO: do we want to consider a 40%/60% transaction fee split here as well?_

## Leader volume limits

A leader propagates blocks irrespective of the underlying burn chain.
This poses a DDoS vulnerability to the network:  a high-transaction-volume
leader may swamp the peer network with so many
transactions that the rest of the nodes cannot keep up. When the next
epoch begins and a new leader is chosen, it would likely orphan the high-volume
leader's block simply because its view of the
chain tip is far behind the high-volume leader's view. This hurts the
network, because it increases the confirmation time of transactions
and may invalidate previously-confirmed transactions.

To mitigate this, the Stack chain places a limit on the volume of
data a leader can send during its epoch (this places a _de facto_ limit
on the number of transactions in a Stack block). This cap is enforced
by the consensus rules.  If a leader exceeds this cap, the block is invalid.

Because each burn block can have as many blocks announced as there are chain
tips, peers may need to make decisions about which blocks they accept and store.
In particular, a peer should only relay a block that is _not_ on the canonical
chain if the associated burn is insufficiently close (e.g. less than 25%) to
the average burn/block rate on the main chain over the
last _W_ blocks.  This prevents a DDoS attack whereby a leader can cheaply spam
the network by producing a lot of cheap orphan blocks.

## Transaction latency

The fact that leaders execute a leading commmitment to their blocks means that
it takes at least one epoch for a user to know if their transaction was
incorporated into the Stacks blockchain.  To get around this, leaders are
encouraged to to supply a public API endpoint that allows a user to query
whether or not their transaction is included in the burn (i.e. the leader's
service would supply a Merkle path to it).  A user can use a set of leader
services to deduce which block(s) included their transaction, and calculate the
probability that their transaction will be accepted in the next epoch.
Leaders can announce their API endpoints via the Blockstack Naming Service.

The specification for this transaction confirmation API service is the subject
of a future SIP.

## Reward distribution

Stacks tokens come into existence on a fork in every epoch where a leader is
selected, regardless of the chain tip commitment strategy.  To reduce the
variance of leader rewards, the Stacks
blockchain pools all tokens created and all transaction fees received and
does not distribute them until a large number of epochs (a _reward window_) has
passed.  The tokens cannot be spent until the window passes, and leaders
in the window do not know in advance what fraction of the rewards
they will receive (but they can estimate it as the window gets longer).
However, unless the number of distinct burns is *very* large, each 
leader can expect to recieve some Stacks tokens.

# Burning in support of a leader

Proof-of-burn mining is not only concerned with electing leaders, but also concerned with
enhancing chain quality.  For this reason, the Stacks chain not
only rewards leaders who build on the "best" fork, but also each user who
supported the "best" fork by burning cryptocurrency in support of the winning leader.

The reason for allowing users to support leaders at all is to help
maintain the chain's liveness in the presence of leaders who follow the
protocol correctly, but not honestly.  These include leaders who delay
the propagation of blocks and leaders who refuse to mine certain transactions.
By giving users a way to help honest leaders get elected, the Stacks blockchain
gives users a first-class stake in deciding the course of its
evolution and an incentive for them to maintain chain liveness in the face of bad leader
behavior.  In other words, leaders stand to make more make money with the consent of the users.

Users support their preferred leader by submitting a burn transaction that references 
a leader candidate's block commitment.  These user-submitted burns count towards the
leader's total burn weight for the election block, thereby increasing the chance
that they will be selected (i.e. users submit their transactions alongside the
leader's block commitment).  Users who burn for a leader who wins the election
will receive some Stacks tokens alongside the leader (but users whose leaders
are not elected receive no reward).  Users are rewarded the same way as
leaders -- they receive their tokens during the reward window.

Allowing users to burn in support of leaders they prefer gives users and leaders
an incentive to cooperate.  Leaders can woo users to burn for them by committing
to honest behavior, and users can help prevent dishonest (but more profitable)
leaders from getting elected.

In addition, allowing users to burn in support of leaders enables the creation
of fair "burn pools."  Users can pool their burn tokens to produce blocks and be
guaranteed to receive a fair payout, since each burn is recorded on the burn chain.
To enhance the payout, users can
coordinate off-chain to amass their tokens into a single multi-sig transaction
on the burn-chain, and then have their Stacks token rewards sent to another
multi-sig address which can later be used to distribute the rewards.

## Leader support mechanism

There are a couple important considerations for the mechanism by which users
burn for their leaders.

* No one is rewarded for helping leaders that do not get elected.  This is
  important because leaders and users that support them are indistinguishable
on-chain.  Leaders should not be able to receive a reward for sock-puppeting,
and neither leaders nor users should get a reward for doing nothing.

* It must be cheaper for a leader to submit a single expensive block commitment than it is
  to submit a cheap block commitment and a lot of user burns.  This is
important because it should not be possible for a leader to profit from
adaptively increasing their burns in response to other leader's burns.

The first property is enforced by the reward window rules.
The second property is given "for free" because the underlying burn chain
assesses each participant a transaction fee.  Users and leaders incur an ever-increasing
cost of trying to adaptively out-burn other leaders by submitting more and more
transactions.

Users who want to support their leaders must send their burn transactions _in the
same block_ as the leader's commitment transaction.  This limits the degree to
which users and leaders can adaptively out-bid each other to include their
commitments.  In addition, this constraint creates negative feedback loop for supporting
leaders -- if there is _too much_ interest in a leader, then the users may accidentally 
kick their preferred leader's commitment out of the target block (or kick all
leaders' commitments out), wasting everyone's cryptocurrency and dissuading
leaders from supporting the leader again.

# Recovery from data loss

Stacks block data can get lost after a leader commits to it.  However, the burn
chain will record the block hash, the parent block hash, and the leader's public
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
follows directly from a single-leader model, where a principal can crash before
producing a block or fail to propagate a block during its tenure.

However, there is a downside to this approach: it enables **selfish mining.**  A
minority coalition of leaders can statistically gain more Stacks tokens than they are due from
their burns by attempting to build a hidden fork of blocks, and releasing it
once the honest majority comes within one block height difference of the hidden
fork.  This orphans the majority fork, causing them to lose their Stacks tokens.

## Seflish mining mitigation strategies

Fortunately, all peers in the Stacks blockchain have global knowledge of state,
 time, and burns.  Intuitively, this gives the Stacks blockchain some novel tools
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
with over 50% confidence.  For example, honest leaders who have been online long
enough to measure the expected block propagation time would _not_ build on top of
a chain tip whose last _A > 1_ blocks arrived late by
more than one epoch, even if that chain tip represents the "best" fork, since
this would be the expected behavior of a selfish miner.

* Since all nodes know about all burn transactions, the long tail of small burners
(i.e. users who support leaders) can collectively throw their burns behind
known-honest leaders' burns.  This increases the chance that honest leaders will
be elected, thereby increasing the fraction of honest burn power and making it
harder for a selfish leader to get elected.

* The Stacks chain reward structure spreads out rewards for creating
blocks and mining transactions across a large interval.  This "smooths over"
short-lived selfish mining attacks -- while selfish leaders still receive more
than their fair share of the rewards, the low variance imposed by the
reward window makes this discrepancy smaller.

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

# Fork Selection

Fork selection in the Stacks blockchain requires a metric to determine which
chain, between two candidates, is the "best" chain.  Using proof-of-burn as the
security method for the blockchain implies a direct metric:  the total sum of
burns in the election blocks for a candidate chain.  In particular, **the Stacks
blockchain measures a fork's quality by the total amount of burns which _confirms_ block _N_** (as
opposed to the amount of burn required for the _election_ of block _N_).

This fork choice rule means that the best fork is the _longest valid_ fork.
This fork has the most blocks available of all forks, and statistically has the
highest expected proof-of-burn of all forks (i.e. over many epochs).

This fork choice rule makes it difficult to for alternative deep forks to
overtake the "canonical" fork.  In order to carry out a deep fork, the majority coalition of leaders needs to spend
at least as many epochs working on the new fork as they did on the old fork.
We consider this acceptable because it also has the effect of keeping the chain
history relatively stable, and makes it so every participant can observe (and
prepare for) any upcoming forks that would reorg the chain.  However, a minority
dishonest coalition of leaders can cause short-lived reorgs by continuously
building forks (i.e. in order to selfishly mine), driving up the confirmation
time for transactions in the honest fork.

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
  reorg the chain and produce cheap orphan blocks before honest participants can react.

To prevent increases or decreases from occuring too quickly, the Stacks
blockchain implements a variable-sized burn window that has a "minimum burn"
quota that must be met before a leader can be elected.  The minimum burn
is controlled via a negative feedback loop, whereby
the minimum burn is additavely increased in the presence of more burns and
multiplicatively decreased in the absence of burns.  In addition, the Stacks
blockchain tracks an average burns/window value to determine which action to
take on the minimum burn value.

* As more cryptocurrency is burned, the minimum burn of
  the burn window increases additively.  If adding the next block to the burn
window increases the window's average burn/block ratio, then the mininum burn
quota is incremented by a protocol-defined constant. The burns/window-size ratio defines
an upper bound on the size of acceptable burns -- if a burn transaction is
discovered in the next block that is too high (e.g. 125% of the minimum burn),
it will be rejected by the network.

* As less cryptocurrency is burned, adding the next
  block to the burn window would decrease its average burn/block ratio.  If the
average burn/block ratio falls beneath the minimum burn by more than a fixed
fraction (e.g. it falls beneath 75% of the minimum burn), then
the burn window "grows" to include the next burn chain block.  No leader will be elected
for its corresponding epoch.  The window contiunes to grow in this manner, up until the sum of its burns
divided by the non-expanded window size exceeds the minimum burn. 
Once it is met, a new leader will be selected, and the window will "snap
back" to its original size.  The minimum burn will be decreased multiplicatively
once this happens (e.g. reduced by 25%).

This burn window protocol enables a set of leader candidates to
burn cryptocurrency units at a rate that is about the market rate for Stacks
tokens.  The feedback loop that governs the burn window's minimum burn value
creates a steady-state behavior where there is about one Stacks block produced per
epoch (in the absence of competing forks), even in the face of wild adjustments
in the market values of Stacks and the underlying burn cryptocurrency.  In
addition, the minimum burn value is used to set the minimum leader burn for
producing a non-orphan block that other peers will relay.

# Implementation

The Stacks blockchain leader election protocol will be written in Rust.

## Leader election protocol burn-chain wire formats

```
Key transaction wire format
0      2  3              19                       51                          80
|------|--|---------------|-----------------------|---------------------------|
 magic  op consensus hash   proving public key                   memo

Commitment transaction wire format
0      2  3              35                 67     71     73    77   79       80
|------|--|---------------|-----------------|------|------|-----|-----|-------|
 magic  op   block hash       new seed       parent parent key   key    memo
                                             delta  txoff  delta txoff 

User support transaction wire format
0      2  3              19                       51                 75       80
|------|--|---------------|-----------------------|------------------|--------|
 magic  op consensus hash    proving public key       block hash        memo

Field name        |   Field contents
------------------|-------------------------------------------------------------------------------------------
magic             |  network ID (e.g. "id")
op                |  one-byte opcode that identifies the transaction type
proving public key|  EdDSA public key (32 bytes)
block hash        |  SHA256(SHA256(block header))
consensus hash    |  first 16 bytes of RIPEMD160(merkle root of prior consensus hashes)
parent delta      |  number of blocks back from this block in which the parent block header hash can be found
parent txoff      |  offset in the block that contains the parent block header hash
key delta         |  number of blocks back from this block in which the proving public key can be found
key txoff         |  offset in the block that contains the proving public key
new seed          |  SHA256(SHA256(parent seed ++ VRF proof))
memo              |  arbitrary data
```

# Appendix

## Definitions

**Burn-mining** is the act of destroying cryptocurrency from one blockchain in
order to mine a block on another blockchain.  Destroying the cryptocurrency can
be done by rendering it unspendable.

**Burn chain**: the blockchain whose cryptocurrency is destroyed in burn-mining.

**Burn transaction**: a transaction on the burn chain that a Stacks miner issues
in order to become a candidate for producing a future block.

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

## Alternative Chain Commitment Protocol: Streaming

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
potentially limitless upside.  **It is for this reason that the streaming model
is _not_ used in the final design of the Stacks blockchain.**

In the streaming model, a single leader is selected for each epoch, allowing the leader
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
