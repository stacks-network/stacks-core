# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.6]

### Fixed

- The miner will no longer attempt to mine a new Stacks block if it receives a
  microblock in a discontinuous microblock stream.

## [2.0.5] - 2021-02-12

### Added

- Miner heuristic for handling relatively large or computationally
  expensive transactions: such transactions will be dropped from the
  mempool to prevent miners from re-attempting them once they fail.
  Miners can also now continue processing transactions that are
  behind those transactions in the mempool "queue".

### Fixed

- Miner block assembly now uses the correct block limit available via
  the node config
- `tx_fees_streamed_produced` fees are included in miner coinbase
  events for event observers
- SQLite indexes are now correctly created on database instantion

### Changed

- STX unlock events are now sent over the events endpoint bundled
  into an associated unlock transaction
- Atlas attachments networking endpoints are disabled for this
  release, while networking issues are addressed in the
  implementation

## [2.0.4] - 2021-02-07

### Changed

- Atlas attachments networking endpoints are disabled for this
  release, while networking issues are addressed in the
  implementation.

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
- Default value `wait_time_for_microblocks`: from 60s to 30s
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
- Address issues #2379, #2356, #2347, #2346. The tracking of the
  `LeaderBlockCommit` operations inflight is improved, drastically
  reducing the number of block commit rejections. When
  a`LeaderBlockCommit` is not included in the Bitcoin block it was
  targeting, it is condemned to be rejected, per the Stacks
  consensus. To avoid wasting BTC, the miner now tries to send its
  next `LeaderBlockCommit` operations using the UTXOs of the previous
  transaction with a replacement by fee. The fee increase increments
  can be configured with the setting `rbf_fee_increment`.
