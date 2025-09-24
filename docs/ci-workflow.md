# CI Workflow

All releases are built via a Github Actions workflow named [`CI`](../.github/workflows/ci.yml), and is responsible for:

- Verifying code is formatted correctly
- Integration tests
- Unit tests
- Creating releases
  - Building binary archives and calculating checksums
  - Publishing Docker images

1. Releases are only created when the [CI workflow](../.github/workflows/ci.yml) is triggered against a release branch (ex: `release/X.Y.Z.A.n`, or `release/signer-X.Y.Z.A.n.x`).
2. [Caching](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows) is used to speed up testing - a cache is created based on the type of data (i.e. cargo) and the commit sha.
   Tests can be retried quickly since the cache will persist until the cleanup job is run or the cache is evicted.
3. [Nextest](https://nexte.st/) is used to run the tests from a cached build archive file (using commit sha as the cache key).
   - Two [test archives](https://nexte.st/docs/ci-features/archiving/) are created, one for genesis tests and one for non-genesis tests.
   - Unit-tests are [partitioned](https://nexte.st/docs/ci-features/partitioning/) and parallelized to speed up execution time.
4. Most workflow steps are called from a separate actions repo <https://github.com/stacks-network/actions> to enforce DRY.

## TL;DR

- Pushing a new branch will not trigger a workflow
- A PR that is opened/re-opened/synchronized will produce an amd64 docker image built from source on Debian with glibc with the following tags:
  - `stacks-core:<branch-name>`
  - `stacks-core:<pr-number>`
- An untagged build of any branch will produce a single image built from source on Debian with glibc:
  - `stacks-core:<branch-name>`
- Running the [CI workflow](../.github/workflows/ci.yml) on a `release/X.Y.Z.A.n` branch will produce:
  - Github Release of the branch with:
    - Binary archives for several architectures
    - Checksum file containing hashes for each archive
  - Git tag of the `release/X.Y.Z.A.n` version, in the format of: `X.Y.Z.A.n`
  - Docker Debian images for several architectures tagged with:
    - `stacks-core:latest`
    - `stacks-core:X.Y.Z.A.n`
    - `stacks-core:X.Y.Z.A.n-debian`
  - Docker Alpine images for several architectures tagged with:
    - `stacks-core:X.Y.Z.A.n-alpine`

## Release workflow

The process to build and tag a release is defined [here](./release-process.md)

## Tests

Tests are separated into several different workflows, with the intention that they can be _conditionally_ run depending upon the triggering operation. For example, when a PR is opened we don't want to run some identified "slow" tests, but we do want to run the [Stacks Core Tests](../.github/workflows/stacks-core-tests.yml) and [Bitcoin Tests](../.github/workflows/bitcoin-tests.yml).

There are also 2 different methods in use with regard to running tests:

1. [Github Actions matrix](https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs)
2. [nextest partitioning](https://nexte.st/book/partitioning.html)

A matrix is used when there are several known tests that need to be run in parallel.
Partitions (shards) are used when there is a large and unknown number of tests to run (ex: `cargo test` to run all tests).

There is also a workflow designed to run tests that is manually triggered: [Standalone Tests](../.github/workflows/standalone-tests.yml).
This workflow requires you to select which test(s) you want to run, which then triggers a reusable workflow via conditional.
For example, selecting `Epoch Tests` will run the tests defined in [Epoch Tests](../.github/workflows/epoch-tests.yml).
Likewise, selecting `Release Tests` will run the same tests as a release workflow.

### Adding/changing tests

With the exception of `unit-tests` in [Stacks Core Tests](../.github/workflows/stacks-core-tests.yml), adding/removing a test requires a change to the workflow matrix. Example from [Atlas Tests](../.github/workflows/atlas-tests.yml):

```yaml
atlas-tests:
  name: Atlas Test
   ...
    matrix:
      test-name:
        - tests::neon_integrations::atlas_integration_test
        - tests::neon_integrations::atlas_stress_integration_test
```

Example of adding a new test `tests::neon_integrations::atlas_new_test`:

```yaml
atlas-tests:
  name: Atlas Test
    ...
    matrix:
      test-name:
        - tests::neon_integrations::atlas_integration_test
        - tests::neon_integrations::atlas_stress_integration_test
        - tests::neon_integrations::atlas_new_test
```

The separation of tests (outside of [Slow Tests](../.github/workflows/slow-tests.yml)) is performed by creating a separate workflow for each _type_ of test that is being run.
Using the example above, to add/remove any tests from being run - the workflow `matrix` will need to be adjusted.

ex:

- `Atlas Tests`: Tests related to Atlas
- `Bitcoin Tests`: Tests relating to burnchain operations
- `Epoch Tests`: Tests related to epoch changes
- `P2P Tests`: Tests P2P operations
- `Slow Tests`: These tests have been identified as taking longer than others. The threshold used is if a test takes longer than `10 minutes` to complete successfully (or even times out intermittently), it should be added here.
- `Stacks Core Tests`:
  - `full-genesis`: Tests related to full genesis
  - `core-contracts`: Tests related to boot contracts

### Checking the result of multiple tests at once

The [check-jobs-status](https://github.com/stacks-network/actions/tree/main/check-jobs-status) composite action may be used in order to check that multiple tests are successful in a workflow job.
If any of the tests given to the action (JSON string of `needs` field) fails, the step that calls the action will also fail.

If you have to mark more than 1 job from the same workflow required in a ruleset, you can use this action in a separate job and only add that job as required.

In the following example, `unit-tests` is a matrix job from [Stacks Core Tests](../.github/workflows/stacks-core-tests.yml) with 8 partitions (i.e. 8 jobs are running), while the others are normal jobs.
If any of the jobs are failing, the `check-tests` job will also fail.

```yaml
check-tests:
  name: Check Tests
  runs-on: ubuntu-latest
  if: always()
  needs:
    - full-genesis
    - unit-tests
    - open-api-validation
    - core-contracts-clarinet-test
  steps:
    - name: Check Tests Status
      id: check_tests_status
      uses: stacks-network/actions/check-jobs-status@main
      with:
        jobs: ${{ toJson(needs) }}
        summary_print: "true"
```
