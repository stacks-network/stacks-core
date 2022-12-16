# Contributing

## Tests and Coverage

PRs must include test coverage. However, if your PR includes large tests or tests which cannot run in parallel
(which is the default operation of the `cargo test` command), these tests should be decorated with `#[ignore]`.
If you add `#[ignore]` tests, you should add your branch to the filters for the `all_tests` job in our circle.yml
(or if you are working on net code or marf code, your branch should be named such that it matches the existing
filters there).

A test should be marked `#[ignore]` if:

1. It does not _always_ pass `cargo test` in a vanilla environment (i.e., it does not need to run with `--test-threads 1`).
2. Or, it runs for over a minute via a normal `cargo test` execution (the `cargo test` command will warn if this is not the case).

## Formatting

This repository uses the default rustfmt formatting style. PRs will be checked against `rustfmt` and will _fail_ if not
properly formatted.

You can check the formatting locally via:

```bash
cargo fmt --all -- --check
```

You can automatically reformat your commit via:

```bash
cargo fmt --all
```
