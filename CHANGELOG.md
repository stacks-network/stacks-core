# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to the versioning scheme outlined in the [README.md](README.md).

## Upcoming

### Added
- Added prometheus output for "transactions in last block" (#3138).

### Changed
- Updates to the logging of transaction events (#3139).

### Fixed
- Make it so that a new peer private key in the config file will propagate to
  the peer database (#3165).
- Fixed default miner behavior regarding block assembly
  attempts. Previously, the miner would only attempt to assemble a
  larger block after their first attempt (by Bitcoin RBF) if new
  microblock or block data arrived. This changes the miner to always
  attempt a second block assembly (#3184).
- Fixed a bug in the node whereby the node would encounter a deadlock when
  processing attachment requests before the P2P thread had started (#3236).

## [2.05.0.2.1]

### Fixed
- Fixed a security bug in the SPV client whereby the chain work was not being
  considered at all when determining the canonical Bitcoin fork.  The SPV client
  now only accepts a new Bitcoin fork if it has a higher chain work than any other
  previously-seen chain (#3152).

## [2.05.0.2.0]

### IMPORTANT! READ THIS FIRST

Please read the following **WARNINGs** in their entirety before upgrading.

WARNING: Please be aware that using this node on chainstate prior to this release will cause
the node to spend **up to 30 minutes** migrating the data to a new schema.
Depending on the storage medium, this may take even longer.

WARNING: This migration process cannot be interrupted. If it is, the chainstate
will be **irrecovarably corrupted and require a sync from genesis.**

WARNING: You will need **at least 2x the disk space** for the migration to work.
This is because a copy of the chainstate will be made in the same directory in
order to apply the new schema.

It is highly recommended that you **back up your chainstate** before running
this version of the software on it.

### Changed
- The MARF implementation will now defer calculating the root hash of a new trie
  until the moment the trie is committed to disk.  This avoids gratuitous hash
  calculations, and yields a performance improvement of anywhere between 10x and
  200x (#3041).
- The MARF implementation will now store tries to an external file for instances
  where the tries are expected to exceed the SQLite page size (namely, the
  Clarity database). This improves read performance by a factor of 10x to 14x
  (#3059).
- The MARF implementation may now cache trie nodes in RAM if directed to do so
  by an environment variable (#3042).
- Sortition processing performance has been improved by about an order of
  magnitude, by avoiding a slew of expensive database reads (#3045).
- Updated chains coordinator so that before a Stacks block or a burn block is processed, 
  an event is sent through the event dispatcher. This fixes #3015. 
- Expose a node's public key and public key hash160 (i.e. what appears in
  /v2/neighbors) via the /v2/info API endpoint (#3046)
- Reduced the default subsequent block attempt timeout from 180 seconds to 30
  seconds, based on benchmarking the new MARF performance data during a period
  of network congestion (#3098)
- The `blockstack-core` binary has been renamed to `stacks-inspect`.
  This binary provides CLI tools for chain and mempool inspection.

## [2.05.0.1.0]

### Added 
- A new fee estimator intended to produce fewer over-estimates, by having less
  sensitivity to outliers. Its characteristic features are: 1) use a window to
  forget past estimates instead of exponential averaging, 2) use weighted
  percentiles, so that bigger transactions influence the estimates more, 3)
  assess empty space in blocks as having paid the "minimum fee", so that empty
  space is accounted for, 4) use random "fuzz" so that in busy times the fees can
  change dynamically. (#2972)
- Implements anti-entropy protocol for querying transactions from other 
  nodes' mempools. Before, nodes wouldn't sync mempool contents with one another.
  (#2884)
- Structured logging in the mining code paths. This will shine light 
  on what happens to transactions (successfully added, skipped or errored) that the
  miner considers while buildings blocks. (#2975)
- Added the mined microblock event, which includes information on transaction
  events that occurred in the course of mining (will provide insight
  on whether a transaction was successfully added to the block,
  skipped, or had a processing error). (#2975)
- For v2 endpoints, can now specify the `tip` parameter to `latest`. If 
  `tip=latest`, the node will try to run the query off of the latest tip. (#2778)
- Adds the /v2/headers endpoint, which returns a sequence of SIP-003-encoded 
  block headers and consensus hashes (see the ExtendedStacksHeader struct that 
  this PR adds to represent this data). (#2862)
- Adds the /v2/data_var endpoint, which returns a contract's data variable 
  value and a MARF proof of its existence. (#2862)
- Fixed a bug in the unconfirmed state processing logic that could lead to a
  denial of service (node crash) for nodes that mine microblocks (#2970)
- Added prometheus metric that tracks block fullness by logging the percentage of each
  cost dimension that is consumed in a given block (#3025).  
  

### Changed
- Updated the mined block event. It now includes information on transaction 
  events that occurred in the course of mining (will provide insight
  on whether a transaction was successfully added to the block, 
  skipped, or had a processing error). (#2975)
- Updated some of the logic in the block assembly for the miner and the follower
  to consolidate similar logic. Added functions `setup_block` and `finish_block`.
  (#2946)
- Makes the p2p state machine more reactive to newly-arrived 
  `BlocksAvailable` and `MicroblocksAvailable` messages for block and microblock 
  streams that this node does not have. If such messages arrive during an inventory 
  sync, the p2p state machine will immediately transition from the inventory sync 
  work state to the block downloader work state, and immediately proceed to fetch 
  the available block or microblock stream. (#2862)
- Nodes will push recently-obtained blocks and microblock streams to outbound
  neighbors if their cached inventories indicate that they do not yet have them
(#2986).
- Nodes will no longer perform full inventory scans on their peers, except
  during boot-up, in a bid to minimize block-download stalls (#2986).
- Nodes will process sortitions in parallel to downloading the Stacks blocks for
  a reward cycle, instead of doing these tasks sequentially (#2986).
- The node's runloop will coalesce and expire stale requests to mine blocks on
  top of parent blocks that are no longer the chain tip (#2969).
- Several database indexes have been updated to avoid table scans, which
  significantly improves most RPC endpoint speed and cuts node spin-up time in
half (#2989, #3005).
- Fixed a rare denial-of-service bug whereby a node that processes a very deep
  burnchain reorg can get stuck, and be rendered unable to process further
sortitions.  This has never happened in production, but it can be replicated in
tests (#2989).
- Updated what indices are created, and ensures that indices are created even 
  after the database is initialized (#3029).

### Fixed 
- Updates the lookup key for contracts in the pessimistic cost estimator. Before, contracts
  published by different principals with the same name would have had the same 
  key in the cost estimator. (#2984)
- Fixed a few prometheus metrics to be more accurate compared to `/v2` endpoints 
  when polling data (#2987)
- Fixed an error message from the type-checker that shows up when the type of a
  parameter refers to a trait defined in the same contract (#3064).

## [2.05.0.0.0]

This software update is a consensus changing release and the
implementation of the proposed cost changes in SIP-012. This release's
chainstate directory is compatible with chainstate directories from
2.0.11.4.0. However, this release is only compatible with chainstate
directories before the 2.05 consensus changes activate (Bitcoin height
713,000). If you run a 2.00 stacks-node beyond this point, and wish to
run a 2.05 node afterwards, you must start from a new chainstate
directory.

### Added

- At height 713,000 a new `costs-2` contract will be launched by the
  Stacks boot address.

### Changed

- Stacks blocks whose parents are mined >= 713,000 will use default costs
  from the new `costs-2` contract.
- Stacks blocks whose parents are mined >= 713,000 will use the real
  serialized length of Clarity values as the cost inputs to several methods
  that previously used the maximum possible size for the associated types.
- Stacks blocks whose parents are mined >= 713,000 will use the new block
  limit defined in SIP-012.

### Fixed

- Miners are now more aggressive in calculating their block limits
  when confirming microblocks (#2916)

## [2.0.11.4.0]

This software update is a point-release to change the transaction
selection logic in the default miner to prioritize by an estimated fee
rate instead of raw fee. This release's chainstate directory is
compatible with chainstate directories from 2.0.11.3.0.

### Added

- FeeEstimator and CostEstimator interfaces. These can be controlled
  via node configuration options. See the `README.md` for more
  information on the configuration.
- New fee rate estimation endpoint `/v2/fees/transaction` (#2872). See
  `docs/rpc/openapi.yaml` for more information.

### Changed

- Prioritize transaction inclusion in blocks by estimated fee rates (#2859).
- MARF sqlite connections will now use `mmap`'ed connections with up to 256MB
  space (#2869).

## [2.0.11.3.0]

This software update is a point-release to change the transaction selection
logic in the default miner to prioritize by fee instead of nonce sequence.  This
release's chainstate directory is compatible with chainstate directories from
2.0.11.2.0.

## Added

- The node will enforce a soft deadline for mining a block, so that a node
  operator can control how frequently their node attempts to mine a block
regardless of how congested the mempool is.  The timeout parameters are
controlled in the `[miner]` section of the node's config file (#2823).

## Changed

- Prioritize transaction inclusion in the mempool by transaction fee (#2823).

## [2.0.11.2.0]

NOTE: This change resets the `testnet`. Users running a testnet node will need
to reset their chain states.

### Added

- `clarity-cli` will now also print a serialized version of the resulting
  output from `eval` and `execute` commands. This serialization is in
  hexademical string format and supports integration with other tools. (#2684)
- The creation of a Bitcoin wallet with BTC version `> 0.19` is now supported
  on a private testnet. (#2647)
- `lcov`-compatible coverage reporting has been added to `clarity-cli` for
  Clarity contract testing. (#2592)
- The `README.md` file has new documentation about the release process. (#2726)

### Changed

- This change resets the testnet. (#2742)
- Caching has been added to speed up `/v2/info` responses. (#2746)

### Fixed

- PoX syncing will only look back to the reward cycle prior to divergence,
  instead of looking back over all history. This will speed up running a
  follower node. (#2746)
- The UTXO staleness check is re-ordered so that it occurs before the RBF-limit
  check. This way, if stale UTXOs reached the "RBF limit" a miner will recover
  by resetting the UTXO cache. (#2694)
- Microblock events were being sent to the event observer when microblock data
  was received by a peer, but were not emitted if the node mined the
  microblocks itself. This made something like the private-testnet setup
  incapable of emitting microblock events. Microblock events are now sent
  even when self-mined. (#2653)
- A bug is fixed in the mocknet/helium miner that would lead to a panic if a
  burn block occurred without a sortition in it. (#2711)
- Two bugs that caused problems syncing with the bitcoin chain during a
  bitcoin reorg have been fixed (#2771, #2780).
- Documentation is fixed in cases where string and buffer types are allowed
  but not covered in the documentation.  (#2676)

## [2.0.11.1.0]

This software update is our monthly release. It introduces fixes and features for both developers and miners. 
This release's chainstate directory is compatible with chainstate directories from 2.0.11.0.0.

## Added

- `/new_microblock` endpoint to notify event observers when a valid microblock
  has been received (#2571).
- Added new features to `clarity-cli` (#2597)
- Exposing new mining-related metrics in prometheus (#2664)
  - Miner's computed relative miner score as a percentage
  - Miner's computed commitment, the min of their previous commitment and their median commitment
  - Miner's current median commitment
- Add `key-for-seed` command to the `stacks-node` binary - outputs the associated secret key hex string
  and WIF formatted secret key for a given "seed" value (#2658).

## Changed

- Improved mempool walk order (#2514).
- Renamed database `tx_tracking.db` to `tx_tracking.sqlite` (#2666).
  
## Fixed 

- Alter the miner to prioritize spending the most recent UTXO when building a transaction, 
  instead of the largest UTXO. In the event of a tie, it uses the smallest UTXO first (#2661).
- Fix trait rpc lookups for implicitly implemented traits (#2602).
- Fix `v2/pox` endpoint, broken on Mocknet (#2634).
- Align cost limits on mocknet, testnet and mainnet (#2660). 
- Log peer addresses in the HTTP server (#2667)
- Mine microblocks if there are no recent unprocessed Stacks blocks

## [2.0.11.0.0]

The chainstate directory has been restructured in this release. It is not
compatible with prior chainstate directories.

## Added

- `/drop_mempool_tx` endpoint to notify event observers when a mempool
  transaction has been removed the mempool.
- `"reward_slot_holders"` field to the `new_burn_block` event
- CTRL-C handler for safe shutdown of `stacks-node`
- Log transactions in local db table via setting env `STACKS_TRANSACTION_LOG=1`
- New prometheus metrics for mempool transaction processing times and
  outstanding mempool transactions
- New RPC endpoint with path `/v2/traits/contractAddr/contractName/traitContractName
  /traitContractAddr/traitName` to determine whether a given trait is implemented 
  within the specified contract (either explicitly or implicitly).
- Re-activate the Atlas network for propagating and storing transaction
  attachments. This re-enables off-chain BNS name storage.
- Re-activate microblock mining.

## Changed

- Improved chainstate directory layout
- Improved node boot up time
- Better handling of flash blocks
- The `/v2/pox` RPC endpoint was updated to include more useful
  information about the current and next PoX cycles. For details, see
  `docs/rpc-endpoints.md`
  
## Fixed 

- Fixed faulty logic in the mempool that was still treating the transaction fee
  as a fee rate, which prevented replace-by-fee from working as expected.

## [2.0.10.0.1]

This is a low-priority hotfix release to address a bug in the deserialization logic. The
chainstate directory of 2.0.10.0.1 is compatible with 2.0.10. This release also begins the
usage of the versioning scheme outlined in the [README.md](README.md).

## [2.0.10]

This is a low-priority hotfix release to address two bugs in the block downloader. The
chainstate directory of 2.0.10 is compatible with 2.0.9. If booting up a node from genesis, or
an existing node has stalled in downloading blocks, this hotfix is necessary for your
node.

## Fixed

- Bug in microblocks inventory vector calculation that included invalidated microblocks
  as present bit. This bug will impact nodes booting up from genesis, but not affect nodes
  currently running at the chain tip (#2518).
- Bug in microblocks downloader logic that would cause the stacks-node to fail to wake-up
  to process newly arrived microblocks in certain instances (#2491).

## [2.0.9]

This is a hotfix release for improved handling of arriving Stacks blocks through
both the RPC interface and the P2P ineterface.  The chainstate directory of
2.0.9 is compatible with the 2.0.8 chainstate.

## Fixed

- TOCTTOU bug fixed in the chain processing logic that, which now ensures that
  an arriving Stacks block is processed at most once.

## [2.0.8] - 2021-03-02

This is a hotfix release for improved handling of static analysis storage and
improved `at-block` behavior. The chainstate directory of 2.0.8 is compatible with
the 2.0.7 chainstate.

## Fixed

- Improved static analysis storage
- `at-block` behavior in `clarity-cli` and unit tests (no changes in `stacks-node`
  behavior).

## [2.0.7] - 2021-02-26

This is an emergency hotfix that prevents the node from accidentally deleting
valid block data if its descendant microblock stream is invalid for some reason.

## Fixed

- Do not delete a valid parent Stacks block.


## [2.0.6] - 2021-02-15

The database schema has not changed since 2.0.5, so when spinning up a
2.0.6 node from a 2.0.5 chainstate, you do not need to use a fresh
working directory. Earlier versions' chainstate directories are
incompatible, however.

### Fixed

- Miner RBF logic has two "fallback" logic changes. First, if the RBF
  logic has increased fees by more than 50%, do not submit a new
  transaction. Second, fix the "same chainstate hash" fallback check.
- Winning block txid lookups in the SortitionDB have been corrected
  to use the txid during the lookup.
- The miner will no longer attempt to mine a new Stacks block if it receives a
  microblock in a discontinuous microblock stream.

## [2.0.5] - 2021-02-12

The database schema has changed since 2.0.4, so when spinning up a 2.0.5
node from an earlier chainstate, you must use a fresh working directory.

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
