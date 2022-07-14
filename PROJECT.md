# Hyperchains Project

Hiro is proposing and planning to implement an iterative approach to
subnets.

The plan is to begin with a fully-trusted approach, federating miners
using a BFT protocol. This approach will use a Stacks smart contract to
handle deposits and withdrawals, and will require some new P2P messages
for miners to communicate on block construction.

The first iteration on this is to introduce an incentive scheme for
processing user to user asset transfers on the subnet. This scheme would
protect asset transfers between users, but not between smart contracts
and users. Such a scheme can be implemented through a combination of
merkle proofs and miner responsiveness challenges.

Further iterations on this scheme will involve a fair amount of research
and could be categorized as far-future work. The next step after the
first iteration would be to update the incentivization scheme to protect
smart contract to user asset transfers. This requires validation of
*contract execution* and is similar to the solution posed by Arbitrum.
This would likely require new functionality in the Clarity VM. The final
approach would be to develop a full trustless scheme using PCPs as the
theoretical framework for a Stacks smart contract to act as a "verifier"
to a layer 2 "prover". This is similar to the promise of ZK rollups, and
would require similar amount of refinement and research to discover
if the approach was workable.

# Project Components

There are relatively few high-level components required in the initial
subnets implementation. However, much of the implementation work will
be in fitting these components into the larger code structure of the
Stacks node.

## Trusted Sortition

The first step of building the Stacks subnets is to support the
fully-trusted consensus algorithm. This system is responsible for
determining which "blocks" of the subnet chain exist, need to be
downloaded, and processed. This is essentially the same job performed
by the `SortitionDB` struct and `burnchain` modules in
`stacks-blockchain`. The implementation of this is essentially
equivalent to replacing those with a new module that listens for
`stacks-blockchain` events, receiving announced blocks and adds
those blocks to a database of expected blocks.

## Block validation

Block validation in a subnets node is different from validation in a
normal Stacks node: all participants in the BFT protocol must sign the
block, and normal sortition checks must be skipped.

This requires a variation in the block wire format to support
multiple signatures.

## Skeletal subnets contract implementation

Each subnet instantiates with a specific subnet controller contract
on the Stacks chain. The subnets project will supply some skeletal
contracts for instantiating a new subnet, and these contracts will
be used in the subnets prototypes and end-to-end testing.

The initial version of this contract will only be used for publishing
subnet block hashes, but as the prototype evolves, the subnet
contracts will also be used to issue withdrawals and handle deposits.

## Multiparty block proposals

The initial subnets prototype supports mining through a federated
trust system: there are multiple trusted miners, and some coalition of
them must sign each block. Passing block proposals from one miner to
the other requires an extension of the node's P2P protocol.

# Project Milestones

## 0: Single leader replay-validation

Milestone 0 is a minimum end-to-end testable build. This build will
take a Stacks event stream as input, and use it to download subnet blocks
from peers (or validate pushed blocks), and serve responses over the
RPC interface.

Components required for this are:

* https://github.com/hirosystems/stacks-subnets/issues/2
* https://github.com/hirosystems/stacks-subnets/issues/3
* https://github.com/hirosystems/stacks-subnets/issues/4
* https://github.com/hirosystems/stacks-subnets/issues/5
* https://github.com/hirosystems/stacks-subnets/issues/7
* https://github.com/hirosystems/stacks-subnets/issues/8
* https://github.com/hirosystems/stacks-subnets/issues/9

## 1: Active listening and Stacks commitments

Milestone 1 is a build with support for committing subnet blocks
to the Stacks chain, and reading commitments out of the stacks
chain using the actual event listener interface.

* https://github.com/hirosystems/stacks-subnets/issues/1
* https://github.com/hirosystems/stacks-subnets/issues/10

## 2: BFT commitments and Miner P2P protocol

Milestone 2 introduces multi-party trust: miner commitments
must be signed by a coalition of participants. Block assembly
will require passing proposals between participants.

* https://github.com/hirosystems/stacks-subnets/issues/11
* https://github.com/hirosystems/stacks-subnets/issues/12

## 3: Workable end-to-end prototype

Milestone 3 introduces withdrawals, mints, and receives to
the subnets contract. This milestone also includes implementation
of a case study application: a NFT launch and marketplace.

* https://github.com/hirosystems/stacks-subnets/issues/13
* https://github.com/hirosystems/stacks-subnets/issues/14
* https://github.com/hirosystems/stacks-subnets/issues/15
* https://github.com/hirosystems/stacks-subnets/issues/16
* https://github.com/hirosystems/stacks-subnets/issues/17

## Subsequent features

After Milestones 0, 1, 2, and 3 the rest of the initial subnets
implementation can be thought of as simply features or improvements on
the implementation:

### Network stack improvements

Subnets would be a great testing ground for replacing the
existing network stack with something faster, easier
to monitor, and easier to add endpoints for: something along
the lines of replacing the `net::rpc` module with warp.

### Data storage improvements

The MARF backend which will initially be used in the subnets
implementation is not read or write optimized -- rather, it is *fork*
optimized. But subnets do not expect to face malicious forks: the
subnet "miners" are themselves trusted, and malicious Stacks forks
can only create performance-degradation (light DoS) in the subnet,
which would happen in any event during rapid Stacks forks.

So, instead, subnets should be able to use a faster backend that
sacrifices speed in the event of reorgs/forks:

https://github.com/hirosystems/stacks-subnets/issues/6
