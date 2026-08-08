# Clarity conformance vectors

`clarity-conformance` is a test-support crate for exercising any Clarity
engine through `clarity_kernel::engine::Engine`. It contains no interpreter
implementation and does not select an engine.

The versioned JSON format records a sequence of ABI operations and exact
observations: interface fingerprints, diagnostics, rejection classification,
cumulative costs, values, asset maps, events, aborts, and rollback-visible
reads. Call arguments use consensus-serialized hexadecimal, so the format is
lossless across the full Clarity value domain and independent of Rust serde
representations.

An engine crate loads a suite with `parse_suite` and checks itself with
`verify_suite`. `record_suite` is provided for maintainers to record a new
golden file from a trusted engine. Recording and verification are deliberately
separate: a new engine needs only the checked-in JSON, this crate, and the
kernel ABI; it does not link the oracle engine.

The first suite lives at
`clarity-v6/tests/vectors/clarity6-v1.json`. Its ignored recorder test can be
run with:

```sh
CLARITY_V6_UPDATE_VECTORS="$PWD/clarity-v6/tests/vectors/clarity6-v1.json" \
  cargo test -p clarity-v6 print_vectors_recorded_from_the_legacy_oracle -- --ignored
```

Review all golden-file changes as consensus changes. Never refresh a vector
merely to make a failing implementation pass.
