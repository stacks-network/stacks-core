# Releases

All releases are built via a Github Actions workflow named `CI` ([ci.yml](../.github/workflows/ci.yml)), and is responsible for:

- Verifying code is formatted correctly
- Building binary archives and checksums
- Docker images
- Triggering tests conditionally (different tests run for a release vs a PR)

1. Releases are only created if a tag is **manually** provided when the [CI workflow](../.github/workflows/ci.yml) is triggered.
2. [Caching](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows) is used to speed up testing - a cache is created based on the type of data (i.e. cargo) and the commit sha. tests can be retried quickly since the cache will persist until the cleanup job is run.
3. [nextest](https://nexte.st/) is used to run the tests from an archived file that is cached (using commit sha as a key))
   - Two [archives](https://nexte.st/book/reusing-builds.html) are created, one for genesis tests and one for generic tests (it is done this way to reduce the time spent building)
   - Unit-tests are [partitioned](https://nexte.st/book/partitioning.html) and multi-threaded to speed up execution time

## TL;DR

- Pushing a feature branch will not trigger a workflow
- An open/re-opened/synchronized PR will produce a single image built from source on Debian with glibc with 2 tags:
  - `stacks-core:<branch-name>`
  - `stacks-core:<pr-number>`
- A merged PR into `default-branch` from `develop` will produce a single image built from source on Debian with glibc:
  - `stacks-core:<default-branch-name>`
- An untagged build of any branch will produce a single image built from source on Debian with glibc:
  - `stacks-core:<branch-name>`
- A tagged release on a non-default branch will produces:
  - Docker Alpine image for several architectures tagged with:
    - `stacks-core:<x.x.x.x.x>`
  - Docker Debian image for several architectures tagged with:
    - `stacks-core:<x.x.x.x.x-debian>`
- A tagged release on the default branch will produce:
  - Github Release of the specified tag with:
    - Binary archives for several architectures
  - Docker Alpine image for several architectures tagged with:
    - `stacks-core:<x.x.x.x.x>`
    - `stacks-core:<latest>`
  - Docker Debian image for several architectures tagged with:
    - `stacks-core:<x.x.x.x.x-debian>`
    - `stacks-core:<latest-debian>`

## Release workflow

1. Create a feature branch: `feat/fix-something`
2. PR `feat/fix-something` to the `develop` branch where the PR is numbered `112`
   1. Docker image tagged with the **branch name** and **PR number**
   - ex:
     - `stacks-core:feat-fix-something`
     - `stacks-core:pr-112`
   2. CI tests are run
3. PR `develop` to the default branch where the PR is numbered `112`
   1. Docker image tagged with the **branch name** and **PR number**
   - ex:
     - `stacks-core:feat-fix-something`
     - `stacks-core:pr-112`
   2. CI tests are run
4. Merge `develop` branch to the default branch
   1. Docker image is tagged with the **default branch** `master`
   - ex:
     - `stacks-core:master`
   2. CI tests are run
5. CI workflow is manually triggered on **non-default branch** with a version, i.e. `2.1.0.0.0-rc0`
   1. No Docker images/binaries are created
   2. All release tests are run
6. CI workflow is manually triggered on **default branch** with a version, i.e. `2.1.0.0.0`
   1. Github release for the manually input version is created with binaries
   2. All release tests are run
   3. Docker image pushed with tags of the **input version** and **latest**
   - ex:
   - `stacks-core:2.1.0.0.0-debian`
   - `stacks-core:latest-debian`
   - `stacks-core:2.1.0.0.0`
   - `stacks-core:latest`

## Tests

Tests are separated into several different workflows, with the intention that they can be _conditionally_ run depending upon the triggering operation. For example, on a PR synchronize we don't want to run some identified "slow" tests, but we do want to run the [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml) and [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml).

There are also 2 different methods in use with regard to running tests:

1. [Github Actions matrix](https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs)
2. [nextest partitioning](https://nexte.st/book/partitioning.html)

A matrix is used when there are several known tests that need to be run. Partitions (shards) are used when there is a large and unknown number of tests to run (ex: `cargo test` to run all tests).

There is also a workflow designed to run tests that are manually triggered: [Standalone Tests](../.github/workflows/standalone-tests.yml).
This workflow requires you to select which test(s) you want to run, which then triggers a reusbale workflow via conditional. For example, selecting "Epoch Tests" will run the tests defined in [Epoch Tests](../.github/workflows/epoch-tests.yml). Likewise, selecting `Release Tests` will run the same tests as a release workflow.

Files:

- [Standalone Tests](../.github/workflows/standalone-tests.yml)
- [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml)
- [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml)
- [Atlas Tests](../.github/workflows/atlas-tests.yml)
- [Epoch Tests](../.github/workflows/epoch-tests.yml)
- [Slow Tests](../.github/workflows/slow-tests.yml)

### Adding/changing tests

With the exception of `unit-tests` in [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml), adding/removing a test requires a change to the workflow matrix. Example from [Atlas Tests](../.github/workflows/atlas-tests.yml):

```yaml
atlas-tests:
  name: Atlas Test
  runs-on: ubuntu-latest
  strategy:
    ## Continue with the test matrix even if we've had a failure
    fail-fast: false
    ## Run a maximum of 2 concurrent tests from the test matrix
    max-parallel: 2
    matrix:
      test-name:
        - tests::neon_integrations::atlas_integration_test
        - tests::neon_integrations::atlas_stress_integration_test
```

Example of adding a new test `tests::neon_integrations::atlas_new_test`:

```yaml
    ...
    matrix:
      test-name:
        - tests::neon_integrations::atlas_integration_test
        - tests::neon_integrations::atlas_stress_integration_test
        - tests::neon_integrations::atlas_new_test
```

The separation of tests (outside of [Slow Tests](../.github/workflows/slow-tests.yml)) is performed by creating a separate workflow for each _type_ of test that is being run. Using the example above, to add/remove any tests from being run - the `matrix` will need to be adjusted.

ex:

- `Atlas Tests`: Tests related to Atlas
- `Bitcoin Tests`: Tests relating to burnchain operations
- `Epoch Tests`: Tests related to epoch changes
- `Slow Tests`: These tests have been identified as taking longer than others. The threshold used is if a test takes longer than `10 minutes` to complete successfully (or times out semi-regularly), it should be added here.
- `Stacks Blockchain Tests`:
  - `full-genesis`: Tests related to full genesis

## Triggering a workflow

### PR a branch to develop

ex: Branch is named `feat/fix-something` and the PR is numbered `112`

- [Rust format](../.github/workflows/ci.yml)
- [Create Test Cache](../.github/workflows/create-cache.yml)
- [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml)
- [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml)
- [Docker image](../.github/workflows/image-build-source.yml) is built from source on a debian distribution and pushed with the branch name and PR number as tags
- ex:
  - `stacks-core:feat-fix-something`
  - `stacks-core:pr-112`

---

### Merging a branch to develop

Nothing is triggered automatically

---

### PR develop to master branches

ex: Branch is named `develop` and the PR is numbered `113`

- [Rust format](../.github/workflows/ci.yml)
- [Create Test Cache](../.github/workflows/create-cache.yml)
- [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml)
- [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml)
- [Docker image](../.github/workflows/image-build-source.yml) is built from source on a debian distribution and pushed with the branch name and PR number as tags
- ex:
  - `stacks-core:develop`
  - `stacks-core:pr-113`

---

### Merging a PR from develop to master

- [Rust format](../.github/workflows/ci.yml)
- [Create Test Cache](../.github/workflows/create-cache.yml)
- [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml)
- [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml)
- [Docker image](../.github/workflows/image-build-source.yml) is built from source on a debian distribution and pushed with the branch name as a tag
- ex:
  - `stacks-core:master`

---

### Manually triggering workflow without tag (any branch)

- [Rust format](../.github/workflows/ci.yml)
- [Create Test Cache](../.github/workflows/create-cache.yml)
- [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml)
- [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml)
- [Docker image](../.github/workflows/image-build-source.yml) is built from source on a debian distribution and pushed with the branch name as a tag
- ex:
  - `stacks-core:<branch name>`

---

### Manually triggering workflow with tag on a non-default branch (i.e. tag of `2.1.0.0.0-rc0`)

- [Rust format](../.github/workflows/ci.yml)
- [Create Test Cache](../.github/workflows/create-cache.yml)
- [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml)
- [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml)
- [Atlas Tests](../.github/workflows/atlas-tests.yml)
- [Epoch Tests](../.github/workflows/epoch-tests.yml)
- [Slow Tests](../.github/workflows/slow-tests.yml)

---

### Manually triggering workflow with tag on default branch (i.e. tag of `2.1.0.0.0`)

- [Rust format](../.github/workflows/ci.yml)
- [Create Test Cache](../.github/workflows/create-cache.yml)
- [Stacks Blockchain Tests](../.github/workflows/stacks-blockchain-tests.yml)
- [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml)
- [Atlas Tests](../.github/workflows/atlas-tests.yml)
- [Epoch Tests](../.github/workflows/epoch-tests.yml)
- [Slow Tests](../.github/workflows/slow-tests.yml)
- [Binaries built for specified architectures](../.github/workflows/create-source-binary.yml)
  - Archive and checksum files added to github release
- [Github release](../.github/workflows/github-release.yml) (with artifacts/checksum) is created using the manually input tag
- [Docker image](../.github/workflows/image-build-binary.yml) built from binaries on debian/alpine distributions and pushed with the provided input tag and `latest`
- ex:
  - `stacks-core:2.1.0.0.0-debian`
  - `stacks-core:latest-debian`
  - `stacks-core:2.1.0.0.0`
  - `stacks-core:latest`

---
