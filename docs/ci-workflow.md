# CI Workflow

All releases are built via a Github Actions workflow named [`CI`](../.github/workflows/ci.yml), and is responsible for:

- Verifying code is formatted correctly
- Integration tests
- Unit tests
- [Mutation tests](https://en.wikipedia.org/wiki/Mutation_testing)
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

## Mutation Testing

When a new Pull Request (PR) is submitted, this feature evaluates the quality of the tests added or modified in the PR.
It checks the new and altered functions through mutation testing.
Mutation testing involves making small changes (mutations) to the code to check if the tests can detect these changes.

The mutations are run with or without a [Github Actions matrix](https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs).
The matrix is used when there is a large number of mutations to run ([check doc specific cases](https://github.com/stacks-network/actions/blob/main/stacks-core/mutation-testing/check-packages-and-shards/README.md#outputs)).
We utilize a matrix strategy with shards to enable parallel execution in GitHub Actions.
This approach allows for the concurrent execution of multiple jobs across various runners.
The total workload is divided across all shards, effectively reducing the overall duration of a workflow because the time taken is approximately the total time divided by the number of shards (+ initial build & test time).
This is particularly advantageous for large packages that have significant build and test times, as it enhances efficiency and speeds up the process.

Since mutation testing is directly correlated to the written tests, there are slower packages (due to the quantity or time it takes to run the tests) like `stackslib` or `stacks-node`.
These mutations are run separately from the others, with one or more parallel jobs, depending on the amount of mutations found.

Once all the jobs have finished testing mutants, the last job collects all the tested mutations from the previous jobs, combines them and outputs them to the `Summary` section of the workflow, at the bottom of the page.
There, you can find all mutants on categories, with links to the function they tested, and a short description on how to fix the issue.
The PR should only be approved/merged after all the mutants tested are in the `Caught` category.

### Time required to run the workflow based on mutants outcome and packages' size

- Small packages typically completed in under 30 minutes, aided by the use of shards.
- Large packages like stackslib and stacks-node initially required about 20-25 minutes for build and test processes.
  - Each "missed" and "caught" mutant took approximately 15 minutes. Using shards, this meant about 50-55 minutes for processing around 32 mutants (10-16 functions modified). Every additional 8 mutants added another 15 minutes to the runtime.
  - "Unviable" mutants, which are functions lacking a Default implementation for their returned struct type, took less than a minute each.
  - "Timeout" mutants typically required more time. However, these should be marked to be skipped (by adding a skip flag to their header) since they indicate functions unable to proceed in their test workflow with mutated values, as opposed to the original implementations.

File:

- [PR Differences Mutants](../.github/workflows/pr-differences-mutants.yml)

### Mutant Outcomes

- caught — A test failed with this mutant applied.
  This is a good sign about test coverage.

- missed — No test failed with this mutation applied, which seems to indicate a gap in test coverage.
  Or, it may be that the mutant is undistinguishable from the correct code.
  In any case, you may wish to add a better test.

- unviable — The attempted mutation doesn't compile.
  This is inconclusive about test coverage, since the function's return structure may not implement `Default::default()` (one of the mutations applied), hence causing the compile to fail.
  It is recommended to add `Default` implementation for the return structures of these functions, only mark that the function should be skipped as a last resort.

- timeout — The mutation caused the test suite to run for a long time, until it was eventually killed.
  You might want to investigate the cause and only mark the function to be skipped if necessary.

### Skipping Mutations

Some functions may be inherently hard to cover with tests, for example if:

- Generated mutants cause tests to hang.
- You've chosen to test the functionality by human inspection or some higher-level integration tests.
- The function has side effects or performance characteristics that are hard to test.
- You've decided that the function is not important to test.

To mark functions as skipped, so they are not mutated:

- Add a Cargo dependency of the [mutants](https://crates.io/crates/mutants) crate, version `0.0.3` or later (this must be a regular `dependency`, not a `dev-dependency`, because the annotation will be on non-test code) and mark functions with `#[mutants::skip]`, or

- You can avoid adding the dependency by using the slightly longer `#[cfg_attr(test, mutants::skip)]`.

### Example

```rust
use std::time::{Duration, Instant};

/// Returns true if the program should stop
#[cfg_attr(test, mutants::skip)] // Returning false would cause a hang
fn should_stop() -> bool {
    true
}

pub fn controlled_loop() {
    let start = Instant::now();
    for i in 0.. {
        println!("{}", i);
        if should_stop() {
            break;
        }
        if start.elapsed() > Duration::from_secs(60 * 5) {
            panic!("timed out");
        }
    }
}

mod test {
    #[test]
    fn controlled_loop_terminates() {
        super::controlled_loop()
    }
}
```

---
