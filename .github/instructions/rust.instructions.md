---
applyTo: "**/*.rs"
---

# Rust and core-node review guidance

## Rust correctness

- Flag a newly introduced panic, `unwrap`, or `expect` only when the failure is reachable from runtime, persisted, network, or otherwise untrusted input; do not flag uses protected by a locally established invariant.
- Check integer conversions, narrowing, overflow behavior, and signedness where values affect consensus, heights, balances, lengths, or wire formats.
- For `unsafe` code or FFI changes, verify that the PR establishes the required memory, lifetime, aliasing, and thread-safety invariants.
- Check error conversions when they discard distinctions or context needed for retry, peer handling, RPC behavior, rollback, or operator diagnosis.
- Flag visibility expansion only when it unintentionally exposes an API or permits cross-module use that can violate an invariant.

## Rust license headers

- For every `.rs` file added by the PR, including tests, benches, examples, and generated source, verify it begins with appropriate copyright attribution followed by the complete GPLv3-or-later notice.
- For newly authored Rust source, require this header, replacing `<year>` with the appropriate year:
  ```text
  // Copyright (C) <year> Stacks Open Internet Foundation
  //
  // This program is free software: you can redistribute it and/or modify
  // it under the terms of the GNU General Public License as published by
  // the Free Software Foundation, either version 3 of the License, or
  // (at your option) any later version.
  //
  // This program is distributed in the hope that it will be useful,
  // but WITHOUT ANY WARRANTY; without even the implied warranty of
  // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  // GNU General Public License for more details.
  //
  // You should have received a copy of the GNU General Public License
  // along with this program.  If not, see <http://www.gnu.org/licenses/>.
  ```
- Check copyright holders and years against the source's provenance, not the nearest file alone. Do not copy historical Blockstack attribution onto newly authored source unless that attribution applies.
- For generated source, require the generator or template to emit the header rather than requesting a manual output-only edit.
- If the PR changes an existing Rust file's header, verify the resulting block remains complete and accurate. Otherwise, do not request unrelated year-only updates or retroactive header changes to existing files.

## Consensus and chainstate

- Verify code uses the chainstate or sortition view for the specific Stacks block or burn block being processed, not an unrelated tip view.
- Trace parent block IDs, consensus hashes, sortition IDs, burn heights, tenure IDs, reward cycles, and epoch boundaries through changed state transitions.
- Ensure fork-sensitive cache keys contain enough chain identity to prevent reward sets, PoX data, sortition state, epoch state, or validation results from being reused across forks.
- Check behavior and regression coverage before, at, and after epoch or protocol activation boundaries.
- Verify database transactions, MARF/Clarity state, replay state, and other long-lived state are rolled back or cleaned up on every error path.

## Clarity implementation

- Compare interpreter, Wasm, analysis, database/read, and serialization paths when the PR changes semantics shared by them.
- Check read-only operations, trait dispatch, nested calls, epoch gating, and transaction rollback for parity across affected execution paths.
- Check serialization, deserialization, type limits, malformed input, and compatibility with data produced under older epochs.

## Signer, miner, events, and operations

- Check stale, delayed, duplicated, reordered, or replayed signer, miner, block, tenure, and burn-chain messages.
- Verify signer thresholds, signer-set selection, miner selection, authorization, and validation decisions use the intended reward cycle and chain view.
- Treat changes to event-observer payload shapes, field names, optionality, types, and encodings as compatibility-sensitive for downstream indexers and observers; verify serialization tests and `docs/event-dispatcher.md` remain aligned.
- Check timeout, retry, failover, restart, cleanup, shutdown, backpressure, and bounded resource-use behavior when the PR changes a long-running or external interaction.
- Check configuration and external-service changes, including bitcoind integration, for safe defaults, validation, timeouts, retries, partial responses, and actionable errors.
