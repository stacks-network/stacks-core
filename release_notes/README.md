Release Notes
=============

This directory contains the release notes for each version of Blockstack Core.  In particular, there are two types of changes in each release:

* **Consensus-breaking Releases**:  These are releases of Blockstack Core that change its consensus rules.
Examples include adding new name opcodes, removing old ones, changing the types of transactions that are supported, which blockchain(s) are used, etc.
Each consensus-breaking release is incompatible with all prior releases; old releases will not agree with new releases on the global name set.
For this reason, **it is strongly recommended to run the latest Blockstack Core release.**

* **Non-consenus-breaking Releases**:  These are all other releases.  They include bugfixes, reliability improvements, performance improvements, and so on.

The consensus-breaking releases are:

* [0.17](changelog-0.17.md): hard fork of 2017
* [0.14](changelog-0.14.md): hard fork of 2016
* initial release: hardfork of 2015; migration from Namecoin to Bitcoin

Notes on Consensus
==================

The Blockstack Core developers do their best to avoid consensus-breaking releases whenever possible.
However, certain improvements and bugfixes cannot be done without them.
As such, the project tries to limit consensus-breaking releases to one per year (in Q4), and only with extensive testing.
Consensus-breaking changes are documented in the release notes, and will be publicly documented beforehand whenever possible.

If a critical consensus-breaking bug or security vulnerability is found, a new consensus-breaking release may be made on the spot.
If this happens, it will be documented here and announced publicly on the
[Blockstack Forum](https://forum.blockstack.org) and on [Twitter](https://twitter.com/blockstack).

A yearly consensus-breaking release is required in order to keep name and namespace prices reasonable.
When Blockstack was first deployed, namespace prices were determined on a 1 BTC == $230 USD exchange.
At a minimum, the consensus-breaking release must adjust the BTC prices to ensure that names and namespaces
are neither too cheap (making squatting trivial) nor too expensive (making the system unusable).
