# CI Workflow

All releases are built via a Github Actions workflow named [`Release`](../.github/workflows/release.yml), and is responsible for:

- Checking for the absence of various "DO NOT RELEASE" preconditions
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
