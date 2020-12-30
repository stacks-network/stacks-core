# SIP-007: Stacking Consensus

# Preamble

Title: Stacking Consensus

Authors:

    Muneeb Ali <muneeb@blockstack.com>,
    Aaron Blankstein <aaron@blockstack.com>,
    Michael J. Freedman <mfreed@cs.princeton.edu>,
    Diwaker Gupta <diwaker@blockstack.com>,
    Jude Nelson <jude@blockstack.com>, 
    Jesse Soslow <jesse@blockstack.com>, 
    Patrick Stanley <patrick@blockstack.com>

Status: Draft

Type: Standard

Created: 01/14/2020

# Abstract

This SIP proposes a new consensus algorithm, called Stacking, that
uses the proof-of-work cryptocurrency of an established blockchain to
secure a new blockchain. An economic benefit of the Stacking consensus
algorithm is that the holders of the new cryptocurrency can earn a
reward in a base cryptocurrency by actively participating in the
consensus algorithm.

This SIP proposes to change the mining mechanism of the Stacks
blockchain. [SIP-001](./sip-001-burn-election.md) introduced
proof-of-burn (PoB) where a base cryptocurrency is destroyed to
participate in mining of a new cryptocurrency. This proposal argues
that a new mining mechanism called proof-of-transfer (PoX) will be an
improvement over proof-of-burn.

With proof-of-transfer, instead of destroying the base cryptocurrency,
miners are required to distribute the base cryptocurrency to existing
holders of the new cryptocurrency who participate in the consensus
algorithm. Therefore, existing holders of the new cryptocurrency have
an economic incentive to participate, do useful work for the network,
and receive rewards.

Proof-of-transfer avoids burning of the base cryptocurrency which
destroys some supply of the base cryptocurrency. Stacking in general
can be viewed as a more "efficient" algorithm where instead of
destroying a valuable resource (like electricity or base
cryptocurrency), the valuable resource is distributed to holders of
the new cryptocurrency.

The SIP describes one potential implementation of the Stacking
consensus algorithm for the Stacks blockchain using Bitcoin as the
base cryptocurrency.

# Introduction

Consensus algorithms for public blockchains require computational or
financial resources to secure the blockchain state. Mining mechanisms
used by these algorithms are broadly divided into proof-of-work (PoW),
in which nodes dedicate computational resources, and proof-of-stake
(PoS), in which nodes dedicate financial resources. The intention
behind both proof-of-work and proof-of-stake is to make it practically
infeasible for any single malicious actor to have enough computational
power or ownership stake to attack the network.

With proof-of-work, a miner does some "work" that consumes electricity
and is rewarded with digital currency. The miner is, theoretically,
converting electricity and computing power into the newly minted
digital currency. Bitcoin is an example of this and is by far the
largest and most secure PoW blockchain.

With proof-of-stake, miners stake their holdings of a new digital
currency to participate in the consensus algorithm and bad behavior
can be penalized by "slashing" the funds of the miner. PoS requires
less energy/electricity to be consumed and can give holders of the new
cryptocurrency who participate in staking a reward on their holdings
in the new cryptocurrency.

In this SIP we introduce a new consensus algorithm called
Stacking. The Stacking consensus algorithm uses a new type of mining
mechanism called *proof-of-transfer* (PoX). With PoX, miners are not
converting electricity and computing power to newly minted tokens, nor
are they staking their cryptocurrency. Rather they use an existing PoW
cryptocurrency to secure a new, separate blockchain.

This SIP is currently a draft and proposes to change the mining
mechanism of the Stacks blockchain from proof-of-burn (SIP-001) to
proof-of-transfer.

The PoX mining mechanism is a modification of proof-of-burn (PoB)
mining (See
the [Blockstack Technical Whitepaper](https://blockstack.org/papers)
and [SIP-001](./sip-001-burn-election.md)). In
proof-of-burn mining, miners burn a base cryptocurrency to participate
in mining — effectively destroying the base cryptocurrency to mint
units of a new cryptocurrency. **In proof-of-transfer, rather than
destroying the base cryptocurrency, miners transfer the base
cryptocurrency as a reward to owners of the new cryptocurrency**. In
the case of the Stacks blockchain, miners would transfer Bitcoin to
owners of Stacks tokens in order for miners to receive newly-minted
Stacks tokens. The security properties of proof-of-transfer are
comparable to proof-of-burn.

# Stacking with Bitcoin

In the Stacking consensus protocol, we require the base cryptocurrency
to be a proof-of-work blockchain. In this proposed implementation of
Stacking we assume that the PoW crypto-currency is Bitcoin, given it
is by far the most secure PoW blockchain. Theoretically, other PoW
blockchains can be used, but the security properties of Bitcoin are
currently superior to other PoW blockchains.

As with PoB, in PoX, the protocol selects the winning miner (*i.e.*,
the leader) of a round using a verifiable random function (VRF). The
leader writes the new block of the Stacks blockchain and mints the
rewards (newly minted Stacks). However, instead of bitcoins being sent
to burn addresses, the bitcoins are sent to a set of specific
addresses corresponding to Stacks (STX) tokens holders that are adding
value to the network. Thus, rather than being destroyed, the bitcoins
consumed in the mining process go to productive Stacks holders as a
reward based on their holdings of Stacks and participation in the
Stacking algorithm.

# Stacking Consensus Algorithm

In addition to the normal tasks of PoB mining
(see [SIP-001](./sip-001-burn-election.md)), the Stacking consensus
algorithm *must* determine the set of addresses that miners may
validly transfer funds to. PoB mining does not need to perform these
steps, because the address is always the same — the burn
address. However, with Stacking, network participants must be able to
validate the addresses that are sent to.

Progression in Stacking consensus happens over *reward cycles*. In
each reward cycle, a set of Bitcoin addresses are iterated over, such
that each Bitcoin address in the set of reward addresses has exactly
one Bitcoin block in which miners will transfer funds to the reward
address.

To qualify for a reward cycle, an STX holder must:


* Control a Stacks wallet with >= 0.02% of the total share of unlocked
  Stacks tokens (currently, there are ~470m unlocked Stacks tokens,
  meaning this would require ~94k Stacks). This threshold level
  adjusts based on the participation levels in the Stacking protocol.
* Broadcast a signed message before the reward cycle begins that:
    * Locks the associated Stacks tokens for a protocol-specified
      lockup period.
    * Specifies a Bitcoin address to receive the funds.
    * Votes on a Stacks chain tip.

Miners participating in the Stacks blockchain compete to lead blocks
by transferring Bitcoin. Leaders for particular Stacks blocks are
chosen by sortition, weighted by the amount of Bitcoin sent (see
SIP-001). Before a reward cycle begins, the Stacks network must reach
consensus on which addresses are valid recipients. Reaching consensus
on this is non-trivial: the Stacks blockchain itself has many
properties independent from the Bitcoin blockchain, and may experience
forks, missing block data, etc., all of which make reaching consensus
difficult. As an extreme example, consider a miner that forks the
Stacks chain with a block that claims to hold a large fraction (e.g.,
100%) of all Stacks holdings, and proceeds to issue block commitments
that pay all of the fees to themselves. How can other nodes on the
network detect that this miner’s commitment transfers are invalid?

The Stacking algorithm addresses this with a two-phase cycle. Before
each reward cycle, Stacks nodes engage in a *prepare* phase, in which
two items are decided:


1. An **anchor block** — the anchor block is a Stacks chain block. For
   the duration of the reward cycle, mining any descendant forks of
   the anchor block requires transferring mining funds to the
   appropriate reward addresses.
2. The **reward set** -- the reward set is the set of Bitcoin
   addresses which will receive funds in the reward cycle. This set is
   determined using Stacks chain state from the anchor block.

During the reward cycle, miners contend with one another to become the
leader of the next Stacks block by broadcasting *block commitments* on
the Bitcoin chain. These block commitments send Bitcoin funds to
either a burn address or a PoX reward address.

Address validity is determined according to two different rules:


1. If a miner is building off of any chain tip *which is not a
   descendant of the anchor block*, all of the miner's commitment
   funds must be burnt.
2. If a miner is building off a descendant of the anchor block, the
   miner must send commitment funds to 2 addresses from the reward
   set, chosen as follows:
    * Use the verifiable random function (also used by sortition) to
      choose 2 addresses from the reward set. These 2 addresses are
      the reward addresses for this block.
    * Once addresses have been chosen for a block, these addresses are
      removed from the reward set, so that future blocks in the reward
      cycle do not repeat the addresses.

Note that the verifiable random function (VRF) used for address
selection ensures that the same addresses are chosen by each miner
selecting reward addresses. If a miner submits a burn commitment which
*does not* send funds to a valid address, those commitments are
ignored by the rest of the network (because other network participants
can deduce that the transfer addresses are invalid).

To reduce the complexity of the consensus algorithm, Stacking reward
cycles are fixed length --- if fewer addresses participate in the
Stacking rewards than there are slots in the cycle, then the remaining
slots are filled with *burn* addresses. Burn addresses are included
in miner commitments at fixed intervals (e.g, if there are 1000 burn
addresses for a reward cycle, then each miner commitment would have
1 burn address as an output).

## Adjusting Reward Threshold Based on Participation

Each reward cycle may transfer miner funds to up to 4000 Bitcoin
addresses (2 addresses in a 2000 burn block cycle). To ensure that
this number of addresses is sufficient to cover the pool of
participants (given 100% participation of liquid STX), the threshold
for participation must be 0.025% (1/4000th) of the liquid supply of
STX. However, if participation is _lower_ than 100%, the reward pool
could admit lower STX holders. The Stacking protocol specifies **2
operating levels**:

* **25%** If fewer than `0.25 * STX_LIQUID_SUPPLY` STX participate in
  a reward cycle, participant wallets controlling `x` STX may include
  `floor(x / (0.0000625*STX_LIQUID_SUPPLY))` addresses in the reward set.
  That is, the minimum participation threshold is 1/16,000th of the liquid
  supply.
* **25%-100%** If between `0.25 * STX_LIQUID_SUPPLY` and `1.0 *
  STX_LIQUID_SUPPLY` STX participate in a reward cycle, the reward
  threshold is optimized in order to maximize the number of slots that
  are filled. That is, the minimum threshold `T` for participation will be
  roughly 1/4,000th of the participating STX (adjusted in increments
  of 10,000 STX). Participant wallets controlling `x` STX may
  include `floor(x / T)` addresses in the
  reward set.

In the event that a Stacker signals and locks up enough STX to submit
multiple reward addresses, but only submits one reward address, that
reward address will be included in the reward set multiple times.

## Submitting Reward Address and Chain Tip Signaling

Stacking participants must broadcast signed messages for three purposes:

1. Indicating to the network how many STX should be locked up, and for
   how many reward cycles.
2. Indicate support for a particular chain tip.
3. Specifying the Bitcoin address for receiving Stacking rewards.

These messages may be broadcast either on the Stacks chain or the
Bitcoin chain. If broadcast on the Stacks chain, these messages must
be confirmed on the Stacks chain _before_ the anchor block for the
reward period. If broadcast on the Bitcoin chain, they may be
broadcast during the prepare phase, but must be included before
the prepare phase finishes.

These signed messages are valid for at most 12 reward cycles (25200 Bitcoin
blocks or ~7 months). If the signed message specifies a lockup period `x` less
than 25200 blocks, then the signed message is only valid for Stacking
participation for `floor(x / 2100)` reward cycles (the minimum participation
length is one cycle: 2100 blocks).


# Anchor Blocks and Reward Consensus

In the **prepare** phase of the Stacking algorithm, miners and network
participants determine the anchor block and the reward set. The
prepare phase is a window `w` of Bitcoin blocks *before* the reward
cycle begins (e.g., the window may be 100 Bitcoin blocks).

At a high-level, nodes determine whether any block was confirmed by
`F*w` blocks during the phase, where `F` is a large fraction (e.g.,
`0.8`). Once the window `w` closes at time `cur`, Stacks nodes find
the potential anchor block as described in the following pseudocode:


```python
def find_anchor_block(cur):
  blocks_worked_on = get_all_stacks_blocks_between(cur - w, cur)

  # get the highest/latest ancestor before the PREPARE phase for each block worked
  # on during the PREPARE phase.

  candidate_anchors = {}
  for block in blocks_worked_on:
    pre_window_ancestor = last_ancestor_of_block_before(block, cur - w)
    if pre_window_ancestor is None:
      continue
    if pre_window_ancestor in candidate_anchors:
      candidate_anchors[pre_window_ancestor] += 1
    else:
      candidate_anchors[pre_window_ancestor] = 1

  # if any block is confirmed by at least F*w, then it is the anchor block.
  for candidate, confirmed_by_count in candidate_anchors.items():
    if confirmed_by_count >= F*w
      return candidate

  return None
```

Note that there can be at most one anchor block (so long as `F >
0.5`), because:

* Each of the `w` blocks in the prepare phase has at most one
  candidate ancestor.
* The total possible number of confirmations for anchor blocks is `w`.
* If any block is confirmed by `>= 0.5*w`, then any other block must
  have been confirmed by `< 0.5*w`.

The prepare phase, and the high threshold for `F`, are necessary to
protect the Stacking consensus protocol from damage due to natural
forks, missing block data, and potentially malicious participants. As
proposed, PoX and the Stacking protocol require that Stacks nodes are
able to use the anchor block to determine the *reward set*. If, by
accident or malice, the data associated with the anchor block is
unavailable to nodes, then the Stacking protocol cannot operate
normally — nodes cannot know whether or not a miner is submitting
valid block commitments. A high threshold for `F` ensures that a large
fraction of the Stacks mining power has confirmed the receipt of the
data associated with the anchor block.

## Recovery from Missing Data

In the extreme event that a malicious miner *is* able to get a hidden
or invalid block accepted as an anchor block, Stacks nodes must be
able to continue operation. To do so, Stacks nodes treat missing
anchor block data as if no anchor block was chosen for the reward
cycle — the only valid election commitments will therefore be *burns*
(this is essentially a fallback to PoB). If anchor block data which
was previously missing is revealed to the Stacks node, it must
reprocess all of the leader elections for that anchor block's
associated reward cycle, because there may now be many commitments
which were previously invalid that are now valid.

Reprocessing leader elections is computationally expensive, and
would likely result in a large reorganization of the Stacks
chain. However, such an election reprocessing may only occur once per
reward window (only one valid anchor block may exist for a reward
cycle, whether it was hidden or not). Crucially, intentionally
performing such an attack would require collusion amongst a large
fraction `F` of the Stacks mining power — because such a hidden block
must have been confirmed by `w*F` subsequent blocks. If collusion
amongst such a large fraction of the Stacks mining power is possible,
we contend that the security of the Stacks chain would be compromised
through other means beyond attacking anchor blocks.

## Anchoring with Stacker Support.

The security of anchor block selection is further increased through
Stacker support transactions. In this protocol, when Stacking
participants broadcast their signed participation messages, they
signal support of anchor blocks. This is specified by the chain tip's
hash, and the support signal is valid as long as the message itself is
valid.

This places an additional requirement on anchor block selection. In
addition to an anchor block needing to reach a certain number of miner
confirmations, it must also pass some threshold `t` of valid Stacker
support message signals. This places an additional burden on an anchor
block attack --- not only must the attacker collude amongst a large
fraction of mining power, but they must also collude amongst a
majority of the Stacking participants in their block.

# Stacker Delegation

The process of delegation allows a Stacks wallet address (the
represented address) to designate another address (the delegate
address) for participating in the Stacking protocol. This delegate
address, for as long as the delegation is valid, is able to sign and
broadcast Stacking messages (i.e., messages which lock up Stacks,
designate the Bitcoin reward address, and signal support for chain
tips) on behalf of the represented address. This allows the owner of
the represented address to contribute to the security of the network
by having the delegate address signal support for chain tips. This
combats potential attacks on the blockchain stability by miners that
may attempt to mine hidden forks, hide eventually invalid forks, and
other forms of miner misbehavior.

Supporting delegation adds two new transaction types to the Stacks
blockchain:

* **Delegate Funds.** This transaction initiates a
  represented-delegate relationship. It carries the following data:
    * Delegate address
    * End Block: the Bitcoin block height at which this relationship
      terminates, unless a subsequent delegate funds transaction updates
      the relationship.
    * Delegated Amount: the total amount of STX from this address
      that the delegate address will be able to issue Stacking messages
      on behalf of.
    * Reward Address (_optional_): a Bitcoin address that must be
      designated as the funds recipient in the delegate’s Stacking
      messages. If unspecified, the delegate can choose the address.
* **Terminate Delegation.** This transaction terminates a
  represented-delegate relationship. It carries the following data:
    * Delegate Address
    
_Note_: There is only ever one active represented-delegate
relationship between a given represented address and delegate address
(i.e., the pair _(represented-address, delegate-address)_ uniquely
identifies a relationship). If a represented-delegate relationship is
still active and the represented address signs and broadcasts a new
"delegate funds" transaction, the information from the new transaction
replaces the prior relationship.

Both types of delegation transactions must be signed by the
represented address. These are transactions on the Stacks blockchain,
and will be implemented via a native smart contract, loaded into the
blockchain during the Stacks 2.0 genesis block. These transactions,
therefore, are `contract-call` invocations. The invoked methods are
guarded by:

```
    (asserts! (is-eq contract-caller tx-sender) (err u0))
```

This insures that the methods can only be invoked by direct
transaction execution.

**Evaluating Stacking messages in the context of delegation.** In
order to determine which addresses’ STX should be locked by a given
Stacking message, the message must include the represented address in
the Stacking message. Therefore, if a single Stacks address is the
delegate for many represented Stacks addresses, the delegate address
must broadcast a Stacking message for each of the represented
addresses.

# Adressing Miner Consolidation in Stacking

PoX when used for Stacking rewards could lead to miner
consolidation. Because miners that _also_ participate as Stackers
could gain an advantage over miners who do not participate as
Stackers, miners would be strongly incentivized to buy Stacks and use
it to crowd out other miners. In the extreme case, this consolidation
could lead to centralization of mining, which would undermine the
decentralization goals of the Stacks blockchain. While we are actively
investigating additional mechanisms to address this potential
consolidation, we propose a time-bounded PoX mechanism and a Stacker-
driven mechanism here.

**Time-Bounded PoX.** Stacking rewards incentivize miner consolidation
if miners obtain _permanent_ advantages for obtaining the new
cryptocurrency. However, by limiting the time period of PoX, this
advantage declines over time. To do this, we define two time periods for Pox:

1. **Initial Phase.** In this phase, Stacking rewards proceed as
   described above -- commitment funds are sent to Stacking rewards
   addresses, except if a miner is not mining a descendant of the
   anchor block, or if the registered reward addresses for a given
   reward cycle have all been exhausted. This phase will last for
   approximately 2 years (100,000 Bitcoin blocks).

2. **Sunset Phase.** After the initial phase, a _sunset_ block is
   determined. This sunset block will be ~8 years (400,000 Bitcoin
   blocks) after the sunset phase begins. After the sunset block,
   _all_ miner commitments must be burned, rather than transfered to
   reward addresses. During the sunset phase, the reward / burn ratio
   linearly decreases by `0.25%` (1/400) on each reward cycle, such
   that in the 200th reward cycle, the ratio of funds that are
   transfered to reward addresses versus burnt must be equal to
   `0.5`. For example, if a miner commits 10 BTC, the miner must send
   5 BTC to reward addresses and 5 BTC to the burn address.

By time-bounding the PoX mechanism, we allow the Stacking protocol to
use PoX to help bootstrap support for the new blockchain, providing
miners and holders with incentives for participating in the network
early on. Then, as natural use cases for the blockchain develop and
gain steam, the PoX system could gradually scale down.

**Stacker-driven PoX.**  To further discourage miners from consolidating,
holders of liquid (i.e. non-Stacked) STX tokens may vote to disable PoX in the next upcoming
reward cycle.  This can be done with any amount of STX, and the act of voting
to disable PoX does not lock the tokens.

This allows a community of vigilent
users guard the chain from bad miner behavior arising from consolidation
on a case-by-case basis.  Specifically, if a fraction _R_ of liquid STX
tokens vote to disable PoX, it is disabled
only for the next reward cycle.  To continuously deactivate PoX, the STX
holders must continuously vote to disable it.

Due to the costs of remaining vigilent, this proposal recomments _R = 0.25_.
At the time of this writing, this is higher than any single STX allocation, but
not so high that large-scale cooperation is needed to stop a mining cartel.

# Bitcoin Wire Formats

Supporting PoX in the Stacks blockchain requires modifications to the
wire format for leader block commitments, and the introduction of new
wire formats for burnchain PoX participation (e.g., performing the STX
lockup on the burnchain).


## Leader Block Commits

For PoX, leader block commitments are similar to PoB block commits: the constraints on the
BTC transaction's inputs are the same, and the `OP_RETURN` output is identical. However,
the _burn output_ is no longer the same. For PoX, the following constraints are applied to
the second through nth outputs:

1. If the block commitment is in a reward cycle, with a chosen anchor block, and this block
   commitment builds off a descendant of the PoX anchor block (or the anchor block itself),
   then the commitment must use the chosen PoX recipients for the current block.
    a. PoX recipients are chosen as described in "Stacking Consensus Algorithm": addresses
       are chosen without replacement, by using the previous burn block's sortition hash,
       mixed with the previous burn block's burn header hash as the seed for the ChaCha12
       pseudorandom function to select M addresses.
    b. The leader block commit transaction must use the selected M addresses as outputs [1, M]
       That is, the second through (M+1)th output correspond to the select PoX addresses.
       The order of these addresses does not matter. Each of these outputs must receive the
       same amount of BTC.
    c. If the number of remaining addresses in the reward set N is less than M, then the leader
       block commit transaction must burn BTC by including (M-N) burn outputs.
2. Otherwise, the second through (M+1)th output must be burn addresses, and the amount burned by
   these outputs will be counted as the amount committed to by the block commit.

In addition, during the sunset phase (i.e., between the 100,000th and 500,000th burn block in the chain),
the miner must include a _sunset burn_ output. This is an M+1 indexed output that includes the burn amount
required to fulfill the sunset burn ratio, and must be sent to the burn address:

```
sunset_burn_amount = (total_block_commit_amount) * (reward_cycle_start_height - 100,000) / (400,000)
```

Where `total_block_commit_amount` is equal to the sum of outputs [1, M+1].

After the sunset phase _ends_ (i.e., blocks >= 500,000th burn block), block commits are _only_ burns, with
a single burn output at index 1.

## STX Operations on Bitcoin

As described above, PoX allows stackers to submit `stack-stx`
operations on Bitcoin as well as on the Stacks blockchain. The Stacks
chain also allows addresses to submit STX transfers on the Bitcoin
chain. Such operations are only evaluated by the miner of an anchor block
elected in the burn block that immediately follows the burn block that included the
operations. For example, if a `TransferStxOp` occurs in burnchain block 100, then the
Stacks block elected by burnchain block 101 will process that transfer.

In order to submit on the Bitcoin chain, stackers must submit two Bitcoin transactions:

* `PreStxOp`: this operation prepares the Stacks blockchain node to validate the subsequent
  `StackStxOp` or `TransferStxOp`.
* `StackStxOp`: this operation executes the `stack-stx` operation.
* `TransferStxOp`: this operation transfers STX from a sender to a recipient

The wire formats for the above operations are as follows:

### PreStxOp

This operation includes an `OP_RETURN` output for the first Bitcoin output that looks as follows:

```
            0      2  3
            |------|--|
             magic  op 
```

Where `op = p` (ascii encoded).

Then, the second Bitcoin output _must_ be Stacker address that will be used in a `StackStxOp`. This
address must be a standard address type parseable by the stacks-blockchain node.

### StackStxOp

The first input to the Bitcoin operation _must_ consume a UTXO that is
the second output of a `PreStxOp`. This validates that the `StackStxOp` was signed
by the appropriate Stacker address.

This operation includes an `OP_RETURN` output for the first Bitcoin output:

```
            0      2  3                             19        20
            |------|--|-----------------------------|---------|
             magic  op         uSTX to lock (u128)     cycles (u8)
```

Where `op = x` (ascii encoded).

Where the unsigned integer is big-endian encoded.

The second Bitcoin output will be used as the reward address for any stacking rewards.

### TransferStxOp

The first input to the Bitcoin operation _must_ consume a UTXO that is
the second output of a `PreStxOp`. This validates that the `TransferStxOp` was signed
by the appropriate STX address.

This operation includes an `OP_RETURN` output for the first Bitcoin output:

```
            0      2  3                             19        80
            |------|--|-----------------------------|---------|
             magic  op     uSTX to transfer (u128)     memo (up to 61 bytes)
```

Where `op = $` (ascii encoded).

Where the unsigned integer is big-endian encoded.

The second Bitcoin output is either a `p2pkh` or `p2sh` output such
that the recipient Stacks address can be derived from the
corresponding 20-byte hash (hash160).
