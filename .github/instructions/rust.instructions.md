---
applyTo: "**/*.rs,**/Cargo.toml,rust-toolchain.toml"
---

# Rust and core-node review guidance

## Rust correctness

- Flag a newly introduced panic, `unwrap`, or `expect` only when the failure is reachable from runtime, persisted, network, or otherwise untrusted input; do not flag uses protected by a locally established invariant.
- Check integer conversions, narrowing, overflow behavior, and signedness where values affect consensus, heights, balances, lengths, or wire formats.
- For `unsafe` code or FFI changes, verify that the PR establishes the required memory, lifetime, aliasing, and thread-safety invariants.
- Check error conversions when they discard distinctions or context needed for retry, peer handling, RPC behavior, rollback, or operator diagnosis.
- Flag visibility expansion only when it unintentionally exposes an API or permits cross-module use that can violate an invariant.
- For `Cargo.toml` and toolchain changes, check feature unification, default features, target-specific dependencies, minimum supported versions, and consistency with CI and release builds.

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

## Signer, miner, RPC, and operations

- Check stale, delayed, duplicated, reordered, or replayed signer, miner, block, tenure, and burn-chain messages.
- Verify signer thresholds, signer-set selection, miner selection, authorization, and validation decisions use the intended reward cycle and chain view.
- Check timeout, retry, failover, restart, cleanup, shutdown, backpressure, and bounded resource-use behavior when the PR changes a long-running or external interaction.
- Check changed RPC status codes, response bodies, encodings, event payloads, error mapping, and block-specific requests for compatibility and correct chain views.
- Check configuration and external-service changes, including bitcoind integration, for safe defaults, validation, timeouts, retries, partial responses, and actionable errors.

## Example of a high-value comment

If a fork-sensitive reward-set lookup uses `index_handle_at_tip()` while validating a block on a non-tip fork, it can resolve the PoX calculation against the wrong burn view and reuse the wrong reward set. Resolve the sortition handle from the block's parent, or establish why the tip view is guaranteed.
