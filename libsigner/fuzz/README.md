# Fuzz Testing

This directory contains fuzz targets for the signer's handling of untrusted
input, using [libfuzzer-sys](https://docs.rs/libfuzzer-sys/).

## Targets

| Target | Input | Checks |
|---|---|---|
| `signer_message` | A StackerDB chunk payload, as any miner or signer can write one | Decoding it as a `SignerMessage` and making the calls a signer makes on the result (hashes, signature checks, logging) doesn't panic; the message re-encodes to bytes that decode to the same message; proposed blocks and state updates survive the serde JSON round trip the signer DB stores them with |
| `signer_event` | An event-observer request body for each path the signer serves | Decoding it the way the event receiver does doesn't panic |
| `global_state` | Arbitrary state machine updates from the peers of a weighted signer set | `GlobalStateEvaluator` doesn't panic, and any protocol version, burn view or global state it reports has threshold weight behind it |

## Requirements

- Rust nightly toolchain, required by `cargo fuzz` for sanitizer
  instrumentation (the default `-s address`). The fuzz targets themselves build
  on stable, so `cargo fuzz run -s none <target_name>` also works on stable.
- `cargo-fuzz` (`cargo install cargo-fuzz`)

## Running Fuzz Tests

List available targets:

```bash
cargo +nightly fuzz list
```

Run a fuzz target with overflow checks, as the signer's test builds have:

```bash
cargo +nightly fuzz run -a <target_name>
```

To keep fuzzing past a known crash, run in fork mode; each crash is saved
under `artifacts/<target_name>/`:

```bash
cargo +nightly fuzz run -a <target_name> -- -fork=4 -ignore_crashes=1
```

Reproduce a crash:

```bash
cargo +nightly fuzz run -a <target_name> artifacts/<target_name>/<crash-file>
```
