# CI Workflow

All releases are built via a Github Actions workflow named [`Release`](../.github/workflows/release.yml), and is responsible for:

- Checking for the absence of release-blocker markers (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
- Executing Epoch tests
- Creating releases
  - Building binary archives and calculating checksums
  - Publishing Docker images

1. Releases are only created when the [Release workflow](../.github/workflows/release.yml) is triggered against a release branch (ex: `release/X.Y.Z`).
   The node and signer share a single version and ship in one combined release, so there is no separate signer release branch.
2. [Caching](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows) is used to speed up testing - a cache is created based on the type of data (i.e. cargo) and the commit sha.
   Tests can be retried quickly since the cache will persist until the cleanup job is run or the cache is evicted.
3. [Nextest](https://nexte.st/) is used to run the tests from a cached build archive file (using commit sha as the cache key).
   - Two [test archives](https://nexte.st/docs/ci-features/archiving/) are created, one for genesis tests and one for non-genesis tests.

## TL;DR

- Pushing a new branch will not trigger a workflow
- A PR that is opened/re-opened/synchronized will produce an amd64 docker image built from source on Debian with glibc with the following tags:
  - `stacks-core:<branch-name>`
  - `stacks-core:<pr-number>`
- An untagged build of any branch will produce a single image built from source on Debian with glibc:
  - `stacks-core:<branch-name>`
- Running the [Release workflow](../.github/workflows/release.yml) on a `release/X.Y.Z` branch will produce:
  - A single Github Release of the branch with:
    - Binary archives for several architectures, each containing both the `stacks-node` and `stacks-signer` binaries
    - Checksum file containing hashes for each archive
  - Git tag of the `release/X.Y.Z` version, in the format of: `X.Y.Z`
  - Docker Debian images for several architectures, for both `stacks-core` and `stacks-signer`, tagged with:
    - `latest` and `latest-debian` (release candidates are not tagged `latest`)
    - `X.Y.Z`
    - `X.Y.Z-debian`
  - Docker Alpine images for several architectures, for both `stacks-core` and `stacks-signer`, tagged with:
    - `latest-alpine` (release candidates are not tagged `latest-alpine`)
    - `X.Y.Z-alpine`

## Release Workflow

The process to build and tag a release is defined [here](./release-process.md)

## Tests

Tests are separated into several different workflows, with the intention that they can be _conditionally_ run depending upon the triggering operation. For example, when a PR is opened we don't want to run some identified "slow" tests, but we do want to run the [Tests: Stacks Core](../.github/workflows/_tests-stacks-core.yml) and [Tests: Bitcoin](../.github/workflows/_tests-bitcoin.yml).

There are also 2 different methods in use with regard to running tests:

1. [Github Actions matrix](https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs)
2. [nextest partitioning](https://nexte.st/book/partitioning.html)

A matrix is used when there are several known tests that need to be run in parallel.
Partitions (shards) are used when there is a large and unknown number of tests to run (ex: `cargo test` to run all tests).

### Cross-version signer tests

[Tests: Cross Version](../.github/workflows/_tests-cross-version.yml) runs nine scenarios in `stacks-node/src/tests/signer/cross_version.rs`, one per job and release baseline. `ci.yml` calls the reusable workflow once; its `cross-version-tests` job runs every scenario against every selected baseline. The [support policy](../.github/cross-version/policy.json) requires the latest stable published release and runs the preceding release as advisory. Drafts, release candidates and releases older than the policy's `min_release` (4.0, the first line that can run the Epoch 4.0 schedule) are excluded. A manual `workflow_dispatch` of `ci.yml` can pin a stable release at or above `min_release` through `baseline-version`; an explicit baseline is required. Changing required version pairs is a maintainer decision made by reviewing this policy file.

The [stacks-baseline action](../.github/actions/stacks-baseline/action.yml) caches the shipped Linux archive by release tag, verifies both cached and freshly downloaded bytes with `gh attestation verify` (pinned to the `_release-build.yml` signer workflow and the `release/<tag>` source branch), exports the shipped signer as `STACKS_SIGNER_BASELINE_BIN`, and outputs the source commit recorded in the verified attestation. The baseline node is not the shipped binary: the embedded test node is always a `testing` build, and `testing` changes consensus-visible constants such as `MINER_REWARD_MATURITY`, so a release-profile node forks from it at the first matured miner reward. A build job therefore compiles `stacks-node` once per baseline per workflow run from the attested commit with `--features testing` and the release's own toolchain. The Rust setup action's cache is enabled. The build job shares its output with scenario jobs through an artifact from the same workflow run, exported as `STACKS_NODE_BASELINE_BIN`. The finished baseline-node binary has no separate cross-run cache: the release attestation authenticates the source commit, not the bytes of a separately cached testing build. Release signers depend on no such constants and remain the shipped bytes. The archive build job also uploads current `testing` binaries and exports them in scenario jobs as `STACKS_NODE_BIN` and `STACKS_SIGNER_BIN`. No old crates are linked into the nextest archive. Releases 4.0.1 and earlier were attested by a differently named workflow (`release-build.yml`), so they fail verification and cannot be used as baselines.

The matrix covers 4 current / 6 baseline signers, 7 current / 3 baseline signers, all-baseline signers with the current miner, rolling signer upgrades, a baseline miner with current signers, a baseline follower between the current miner and current signers, a node upgrade on existing chainstate, and all-baseline / all-current sanity rows. Every observed block requires an acceptance verified against every signer's public key. Protocol agreement is checked from authenticated StackerDB updates, including after each signer swap. The process-miner rows also exercise ordinary and read-count tenure extensions. A minority's absence therefore cannot pass on chain progress alone.

The embedded node boots to Epoch 4.0, the newest epoch activated on mainnet, and every signer stakes in pox-5. Scenarios start only after the chain enters the first reward cycle whose signer set pox-5 computes, so every block they check is signed under a pox-5 reward set. The schedule stops at 4.0 because Epoch 4.1 has no mainnet activation height. Baseline nodes receive the same epoch heights and pox-5 sBTC contract settings, which must match for them to follow the chain. Baseline nodes sync into a fresh directory before mining or serving signers; only a forward upgrade reuses that directory. Signer upgrades reopen the exact same SQLite path with the PR-built binary. The follower scenario moves signer event endpoints as well as RPC hosts so the embedded miner cannot bypass the follower. Child processes are reaped on unwind, and CI uploads their file-backed logs on failure. These tests cover upgrades within a shared epoch, not future epoch activation or a mixed-version hard fork. Release signers have no test fault injection or in-memory `StateInfo`; readiness and participation must be observed externally.

For local execution, set all four binary variables to absolute executable paths and run `BITCOIND_TEST=1 cargo test -p stacks-node node_upgrade_in_place -- --ignored --nocapture --test-threads=1`. Set `STACKS_SIGNER_BIN` even for an all-current subprocess sanity run. Run one scenario at a time because ports are shared. The `ci_skip` tags exclude these tests from the ordinary Bitcoin matrix.

Implementation follows the issue's four phases in one change: release/current artifacts and retirement of pinned crates; process signers and identity-based assertions; process nodes with minimal configuration and RPC waits; then persistent upgrades and an explicit latest/previous support policy. Containers and release-side fault injection remain later work.
