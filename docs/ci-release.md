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

### Checking the result of multiple tests at once

You can use the [check-jobs-status](https://github.com/stacks-network/actions/tree/main/check-jobs-status) composite action in order to check that multiple tests are successful in 1 job.
If any of the tests given to the action (JSON string of `needs` field) fails, the step that calls the action will also fail.

If you have to mark more than 1 job from the same workflow required in a ruleset, you can use this action in a separate job and only add that job as required.

In the following example, `unit-tests` is a matrix job with 8 partitions (i.e. 8 jobs are running), while the others are normal jobs.
If any of the 11 jobs are failing, the `check-tests` job will also fail.

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
