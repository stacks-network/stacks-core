# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.3] - 2021-02-04

### Added

- `stacks-node --mine-at-height` commandline option, which tells the
  `stacks-node` not to mine until it has synchronized to the given
  Stacks block height
- A new RPC endpoint `/v2/blocks/upload/{consensus_hash}` that accepts
  an uploaded a Stacks block for a given sortition

### Changed

- Enabled WAL mode for the chainstate databases. This allows much more
  concurrency in the `stacks-node`, and improves network performance
  across the board. **NOTE:** *This changed the database schema, any
  running node would need to re-initialize their nodes from a new chain
  state when upgrading*.
- The mempool now performs more transfer semantics checks before admitting
  a transaction (e.g., reject if origin = recipient): see issue #2354
- Improved the performance of the code that handles `GetBlocksInv` p2p
  messages by an order of magnitude.
- Improved the performance of the block-downloader's block and
  microblock search code by a factor of 5x.

### Fixed

- Miner mempool querying now works across short-lived forks: see issue #2389
- JSON deserialization for high-depth JSON objects
- Atlas attachment serving: see PR #2390
