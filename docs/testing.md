# Testing Tools

This document describes several techniques to test the code, especially before committing or submitting PRs.

## Unit testing

## Integration testing

## Mutation testing

### Overview

Mutation testing is complementary to code coverage.
It evaluates the tests' quality of the functions added or modified in the PR.
Mutation testing involves making small changes (mutations) to the code to check if the tests can detect these changes.
This mutations represent a clone of the original code with one given function having a default value instead of its body.
Then the `cargo build` and `cargo nextest` for the package intended are called. If the mutated code breaks, this means that function is properly tested.

This is useful for any size of changed code, being it one line in one function, or tens and hundreds of functions, but the time required increases directly with the number of mutants.

### Run Mutations Locally

The main goal is to run mutations for the changed functions to check that all mutants are caught.

Check your differences compared to the target-branch you intend to merge to

```shell
git diff $(git merge-base origin/${{ target-branch }} HEAD)..HEAD > git.diff
```

Install nextest

```shell
cargo install nextest
```

Generate mutations from the git.diff file

1. If there are changes in `stackslib` or `stacks-node` there are more arguments required

```shell
BITCOIND_TEST=1 cargo mutants --no-shuffle -vV -F git.diff -E ": replace .{1,2} with .{1,2} in " --output ./ --test-tool=nextest -- --all-targets --test-threads 1
```

2. If the changes are in other folders use

```shell
cargo mutants --no-shuffle -vV -F git.diff -E ": replace .{1,2} with .{1,2} in " --output ./ --test-tool=nextest -- --all-targets
```

Check the mutations outcomes in `mutants.out` folder.

### Mutations Outcomes

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
