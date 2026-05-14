# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to the versioning scheme outlined in the [README.md](README.md).

## [3.4.0.0.2]

### Added

* Miners now track `failed_txid` from signer block rejections. When a blocking minority (>30%) of signers report the same transaction as failed, the miner excludes it from the next block proposal. A new `ProblematicTransaction` validation reject code distinguishes genuinely broken transactions (permanently blacklisted from the mempool) from context-dependent failures like deadline exceeded (excluded until a successful block only).
* Added some diagnostics data to a miner's block proposal StackerDB message. This data contains nothing confidential, only some information about the miner's view of the world. This may help with investigating issues where a miner keeps submitting blocks that are then rejected by signers.
* Added `error!`-level logging with `UNREACHABLE_ERROR_TRIGGERED` marker and `stacks_unreachable_errors_total` Prometheus counter when unreachable errors are hit during transaction processing ([#7046](https://github.com/stacks-network/stacks-core/pull/7046))
* Add a helper script for creating changelog fragments.
* Add tests for handling of bad block commits (vtxindex=0, wrong parent).

### Changed

* Optimized `SequenceData::retain_values` built-in from O(n²) to O(n)
* Renamed `SequenceData::retain_values` to `SequenceData::try_retain` and changed it to take `self` by value instead of `&mut self`
* **Breaking**: Removed duplicate `value` field from NFT and SmartContract observer event payloads. Use `raw_value` (hex-encoded Clarity value) instead.
* **Breaking**: Removed `result` field from block replay/simulate transaction responses. Use `result_hex` (hex-encoded Clarity value) instead.
* `BlockResponseData` version bumped from 4 to 5 to include the new `failed_txid` field. Older signers that don't send this field are handled gracefully via backwards-compatible deserialization.
* Remove unused `version_string` function (for building binary version) from `clarity` and `clarity-types` crates.
* Improved performance for `fold`, `map`, and `filter` Clarity functions
* Refactor to avoid the risk of panics when creating `ClarityName`s and similar
* Updated deprecated usage of `slog` macros and `GenericArray`
* Updates the PoX constants used in various test scenarios to ensure there are 3 blocks in the prepare phase, which is required for Nakamoto.
* Moved codec types and traits into a new `stacks-codec` crate, extracted from `stacks-common`

### Fixed

* Fix to clear ongoing block commits when a `send_transaction` call fails ([#6976](https://github.com/stacks-network/stacks-core/pull/6976))
* Fixed `clarity-cli` to print errors to stderr and exit gracefully instead of panicking with a backtrace on invalid inputs.
* Fixed flakiness in Bitcoin integration tests.
* Fixed flakiness in `fuzzed_median_fee_rate_estimation_test` tests.
* Fixed flaky `miner_stackerdb_version_rollover` and `multiple_miners_mock_sign_epoch_25` integration tests by increasing polling frequency and extending the timeout in `wait_for_registered` and `wait_for_registered_both_reward_cycles`, and aligning `boot_to_epoch_25_reward_cycle` with `boot_to_epoch_3` (extended timeout plus mine-another-block recovery when the reward set isn't yet available)
* Fixed flakiness in `signer_waits_for_validation_before_signing` by waiting for state machine updates to prevent the signer from rejecting immediately.
* Fixed logical operator in tenure-start block validation to correctly reject blocks where either the coinbase or tenure-change transaction is in the wrong position, not only when both are wrong