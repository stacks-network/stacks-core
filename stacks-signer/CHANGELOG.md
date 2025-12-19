# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to the versioning scheme outlined in the [README.md](README.md).

## [Unreleased]

### Changed

- Avoid sending duplicate block acceptance messages when additional pre-commits arrive

## [3.3.0.0.2.0]

### Added

- Support read-count tenure extends
  - Added `read_count_idle_timeout_secs` config option to set the amount of seconds of idle time must pass before a read-count tenure extend is allowed (defaults to 20 seconds)
  - Send a read-count tenure extend timestamp in the block responses
  - Approve a block with a read-count tenure extend when the appropriate amount of idle time has passed

## [3.2.0.0.2.0]

### Added

- Added two-phase commit to signer block responses ensuring signers only issue a signature in a BlockResponse when a majority threshold number have pre-committed to sign a proposed Naka block
- When determining a global transaction replay set, the state evaluator now uses a longest-common-prefix algorithm to find a replay set in the case where a single replay set has less than 70% of signer weight.

### Changed

- Database schema updated to version 17

## [3.2.0.0.1.1]

### Added

- Introduced `stackerdb_timeout_secs`: config option to set the maximum time (in seconds) the signer will wait for StackerDB HTTP requests to complete.


## [3.2.0.0.1.0]

### Changed

- Repurposes the `capitulate_miner_view` timeout to prevent needlessly checking for capitulation when blocks are globally accepted (#6307)
- Consider the local state machine update regardless of local vs global paths (#6325)
- Use the local supported version by default if no consensus is found (#6341)

## [3.2.0.0.0.0]

### Added

- Added `info` logs to the signer to provide more visibility into the block approval/rejection status
- Introduced `capitulate_miner_view_timeout_secs`: the duration (in seconds) for the signer to wait between updating the local state machine viewpoint and capitulating to other signers' miner views.
- Added codepath to enable signers to evaluate block proposals and miner activity against global signer state for improved consistency and correctness. Currently feature gated behind the `SUPPORTED_SIGNER_PROTOCOL_VERSION`
- When a transaction replay set has been active for a configurable number of burn blocks (which defaults to `2`), and the replay set still hasn't been cleared, the replay set is automatically cleared. This is provided as a "failsafe" to ensure chain liveness as transaction replay is rolled out.

### Changed

- Do not count both a block acceptance and a block rejection for the same signer/block. Also ignore repeated responses (mainly for logging purposes).
- Database schema updated to version 16

## [3.1.0.0.13.0]

### Changed

- Database schema update (requires stacks-node >= 3.1.0.0.13)


## [3.1.0.0.12.0]

### Changed

- Refactor / cleanup signerDB migrations code
- Signers should not infinitely loop when pushing a block to stacks-node
- Logging improvements and cleanup

### Fixed

- Fix `capitulate_miner_view` so stacks-node won't swap between multiple miners
- Mark current miner as invalid on capitulation
- Fix flaky `miner_recovers_when_broadcast_block_delay_across_tenures_occurs` test

## [3.1.0.0.10.0]

### Added
- Persisted tracking of StackerDB slot versions. This improves signer p2p performance.

## [3.1.0.0.9.0]

### Changed

- Upgraded `SUPPORTED_SIGNER_PROTOCOL_VERSION` to 1

## [3.1.0.0.8.1]

### Added

- The signer will now check if their associated stacks-node has processed the parent block for a block proposal before submitting that block proposal. If it cannot confirm that the parent block has been processed, it waits a default time of 15s before submitting, configurable via `proposal_wait_for_parent_time_secs` in the signer config.toml.


## [3.1.0.0.8.0]

### Changed

- For some rejection reasons, a signer will reconsider a block proposal that it previously rejected ([#5880](https://github.com/stacks-network/stacks-core/pull/5880))

## [3.1.0.0.7.0]

### Changed

- Add new reject codes to the signer response for better visibility into why a block was rejected.
- When allowing a reorg within the `reorg_attempts_activity_timeout_ms`, the signer will now watch the responses from other signers and if >30% of them reject this reorg attempt, then the signer will mark the miner as invalid, reject further attempts to reorg and allow the previous miner to extend their tenure.

### Fixed

- The signer runloop no longer relies on pubkey reports from the SignerDB event system. This previously led to improper proposal rejections via #5858.

## [3.1.0.0.6.0]

### Added

- Introduced the `reorg_attempts_activity_timeout_ms` configuration option for signers which is used to determine the length of time after the last block of a tenure is confirmed that an incoming miner's attempts to reorg it are considered valid miner activity.
- Add signer configuration option `tenure_idle_timeout_buffer_secs` to specify the number of seconds of buffer the signer will add to its tenure extend time that it sends to miners. The idea is to allow for some clock skew between the miner and signers, preventing the case where the miner attempts to tenure extend too early.

### Changed

- Increase default `block_proposal_timeout_ms` from 10 minutes to 4 hours. Until #5729 is implemented, there is no value in rejecting a late block from a miner, since a late block is better than no block at all.
- Signers no longer view any block proposal by a miner in their DB as indicative of valid miner activity.
- Various index improvements to the signer's database to improve performance.

## [3.1.0.0.5.0]

### Added

- Add `dry_run` configuration option to `stacks-signer` config toml. Dry run mode will
  run the signer binary as if it were a registered signer. Instead of broadcasting
  `StackerDB` messages, it logs `INFO` messages. Other interactions with the `stacks-node`
  behave normally (e.g., submitting validation requests, submitting finished blocks). A
  dry run signer will error out if the supplied key is actually a registered signer.
- Reduce default value of `block_proposal_timeout_ms` to 120_000

## [3.1.0.0.4.0]

### Added

- When a new block proposal is received while the signer is waiting for an existing proposal to be validated, the signer will wait until the existing block is done validating before submitting the new one for validating. ([#5453](https://github.com/stacks-network/stacks-core/pull/5453))
- Introduced two new prometheus metrics:
  - `stacks_signer_block_validation_latencies_histogram`: the validation_time_ms reported by the node when validating a block proposal
  - `stacks_signer_block_response_latencies_histogram`: the "end-to-end" time it takes for the signer to issue a block response

### Changed

## [3.1.0.0.3.0]

### Added

- Introduced the `block_proposal_max_age_secs` configuration option for signers, enabling them to automatically ignore block proposals that exceed the specified age in seconds.

### Changed
- Improvements to the stale signer cleanup logic: deletes the prior signer if it has no remaining unprocessed blocks in its database
- Signers now listen to new block events from the stacks node to determine whether a block has been successfully appended to the chain tip

## [3.1.0.0.2.1]

### Added

### Changed

- Prevent old reward cycle signers from processing block validation response messages that do not apply to blocks from their cycle.

## [3.1.0.0.2.1]

### Added

### Changed

- Prevent old reward cycle signers from processing block validation response messages that do not apply to blocks from their cycle.

## [3.1.0.0.2.0]

### Added

- **SIP-029 consensus rules, activating in epoch 3.1 at block 875,000** (see [SIP-029](https://github.com/will-corcoran/sips/blob/feat/sip-029-halving-alignment/sips/sip-029/sip-029-halving-alignment.md) for details)

### Changed

- Added tenure extend timestamp to signer block responses
- Added tenure_idle_timeout_secs configuration option for determining when a time-based tenure extend will be accepted


## [3.1.0.0.0.0]

### Added

- **SIP-029 consensus rules, activating in epoch 3.1 at block 875,000** (see [SIP-029](https://github.com/will-corcoran/sips/blob/feat/sip-029-halving-alignment/sips/sip-029/sip-029-halving-alignment.md) for details)

### Changed

## [3.0.0.0.4.0]

### Added

### Changed

- Use the same burn view loader in both block validation and block processing

## [3.0.0.0.3.0]

### Added

### Changed

- Allow a miner to extend their tenure immediately if the winner of the next tenure has committed to the wrong parent tenure (#5361)

## [3.0.0.0.2.0]

### Added
-  Adds `tenure_last_block_proposal_timeout_secs` option to account for delayed global block acceptance. default to 30s

### Changed

## [3.0.0.0.1.0]

### Added

### Changed

- Change block rejection message to generic block response

## [3.0.0.0.0.1]

### Added

### Changed
- Update block proposal timeout default to 10 minutes (#5391)
- Updated documentation link in output (#5363)

## [3.0.0.0.0.0]

### Added

- Improved StackerDB message structures
- Improved mock signing during epoch 2.5
- Include the `stacks-signer` binary version in startup logging and StackerDB messages
- Added a `monitor-signers` CLI command for better visibility into other signers on the network
- Support custom Chain ID in signer configuration
- Refresh the signer's sortition view when it sees a block proposal for a new tenure
- Fixed a race condition where a signer would try to update before StackerDB configuration was set

### Changed

- Migrate to new Stacks Node RPC endpoint `/v3/tenures/fork_info/:start/:stop`
- Improved chainstate storage for handling of forks and other state
- Updated prometheus metric labels to reduce high cardinality

## [2.5.0.0.5.3]

### Added

### Changed

- Update node endpoints to match stacks-core release 2.5.0.0.7
  - `/v2/block_proposal` -> `/v3/block_proposal`
  - `/v2/stacker_set` -> `/v3/stacker_set`

## [2.5.0.0.5.2]

### Added

### Changed

- Reuse BlockResponse slot for MockSignature message type (#5103)

## [2.5.0.0.5.2-rc1]

### Added

- Signer set handoff integration test (#5037)
- Add mock signing (#5020)
- Add versioning info set at build-time (#5016)

### Changed

- Fix out of sync `RPCPeerInfo` with stacks-node (#5033, #5014, #4999)
- Logging Improvements (#5025)
- Timeout empty sortition (#5003)
- Enum for version specific data (#4981)

## [2.5.0.0.5.1]

### Added

- Adds signerdb schema versioning (#4965)
- Added voting cli commands `generate-vote` and `verify-vote` (#4934)
- Add soritiion tracking cache (#4905)
- Push blocks to signer set and adds `/v3/blocks/upload` (#4902)

### Changed

- Fix an issue of poorly timed tenure and bitcoin blocks (#4956)
- Process pending blocks before ending tenure (#4952)
- Update rusqlite/sqlite versions (#4948)
- return last block sortition in `/v3/sortitions` (#4939)
