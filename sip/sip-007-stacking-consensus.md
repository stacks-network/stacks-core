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
  meaning this would require ~94k Stacks).
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
   miner must send commitment funds to 5 addresses from the reward
   set, chosen as follows:
    * Use the verifiable random function (also used by sortition) to
      choose 5 addresses from the reward set. These 5 addresses are
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
Stacking rewards than there are slots in the cycle, then for the
remaining blocks, all miners must send funds to burn addresses.

# Anchor Blocks and Reward Consensus

In the **prepare** phase of the Stacking algorithm, miners and network
participants determine the anchor block and the reward set. The
prepare phase is a window `w` of Bitcoin blocks *before* the reward
cycle begins (e.g., the window may be 240 Bitcoin blocks).

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

**Recovery from Missing Data**. In the extreme event that a malicious
miner *is* able to get a hidden or invalid block accepted as an anchor
block, Stacks nodes must be able to continue operation. To do so,
Stacks nodes treat missing anchor block data as if no anchor block was
chosen for the reward cycle — the only valid election commitments will
therefore be *burns* (this is essentially a fallback to PoB). If
anchor block data which was previously missing is revealed to the
Stacks node, it must reprocess all of the leader elections for that
anchor block's associated reward cycle, because there may now be many
commitments which were previously invalid that are now
valid.

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

**Anchoring with Stacker Support.** The security of anchor block
selection is further increased through Stacker support
transactions. In this protocol, when Stacking participants broadcast
their signed participation messages, they signal support of anchor
blocks.

This places an additional requirement on anchor block selection. In
addition to an anchor block needing to reach a certain number of miner
confirmations, it must also pass some threshold `t` of valid Stacker
support message signals. This places an additional burden on an anchor
block attack --- not only must the attacker collude amongst a large
fraction of mining power, but they must also collude amongst a
majority of the Stacking participants in their block.
