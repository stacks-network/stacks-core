# marf-bench

`marf-bench` compares MARF benchmark results across revisions using temporary git worktrees.

This document explains the git operations it performs, what they change (or do not change), and how cleanup works.

## Quick start

### `run` (current working tree only)

Run one benchmark target against your current checkout.

```sh
# Run primitive microbenchmarks
cargo marf-bench run primitives

# Run read-path benchmarks
cargo marf-bench run read

# Run write-path benchmarks
cargo marf-bench run write

# Run patch-node compression benchmarks
cargo marf-bench run patch

# Repeat a single-tree patch run and emit repeat statistics
cargo marf-bench run --repeats 5 patch --iters 100000 --rounds 10
```

### `bench` (base/target comparisons)

Compare benchmark output between revisions or snapshots.

Core comparison examples:

```sh
# Compare a known commit to current working tree
cargo marf-bench bench --base c8a06adfc2c9c33ee858766a971eb36845e81499 read

# Compare staged snapshot to current working tree
cargo marf-bench bench --base staged read

# Compare against merge-base with explicit upstream ref
cargo marf-bench bench --base merge-base:upstream/develop read

# Compare two named revisions
cargo marf-bench bench --base master --target v3.0.0.0.0 read

# Primitive benchmark with machine-readable output
cargo marf-bench bench --base staged --output-format tsv primitives

# Patch-node benchmark across revisions
cargo marf-bench bench --base merge-base:upstream/develop patch

# Repeated comparisons with confidence stats
cargo marf-bench bench --base merge-base:upstream/develop --repeats 5 write

# Keep and reuse revision worktrees
cargo marf-bench bench --base merge-base:upstream/develop --keep-worktrees write
```

Advanced comparison examples:

```sh
# Compare proofed reads
cargo marf-bench bench --base staged read --proofs

# A/B WAL checkpoint behavior in write benchmark
cargo marf-bench bench --base merge-base:upstream/develop write --sqlite-wal-autocheckpoint 0

# Explicit checkpoint mode when auto-checkpoint is disabled
cargo marf-bench bench --base merge-base:upstream/develop write --sqlite-wal-autocheckpoint 0 --sqlite-wal-checkpoint-mode FULL

# Read benchmark with matching WAL controls
cargo marf-bench bench --base merge-base:upstream/develop read --sqlite-wal-autocheckpoint 0 --sqlite-wal-checkpoint-mode FULL

# Tune high-jitter threshold in repeat confidence summary
cargo marf-bench bench --base merge-base:upstream/develop --repeats 5 --repeat-jitter-threshold 40 write

# Override loop controls from CLI
cargo marf-bench bench --base staged read --iters 400000 --rounds 4
```

### `clean` (temporary state cleanup)

Remove or preview cleanup of marf-bench temporary resources.

```sh
# Remove marf-bench temporary worktrees and cached temp data
cargo marf-bench clean

# Preview cleanup actions without deleting
cargo marf-bench clean --dry-run
```

## Command shape

- `run`: `cargo marf-bench run [--output-format <summary|raw|tsv>] [--repeats <N>] [--repeat-jitter-threshold <PCT>] <primitives|read|write|patch> [bench-specific options]`
- `bench`: `cargo marf-bench bench [--base <rev|staged|merge-base:<upstream-ref>>] [--target <rev>] [--repeats <N>] [--repeat-jitter-threshold <PCT>] [--keep-worktrees] [--output-format <summary|raw|tsv>] <primitives|read|write|patch> [bench-specific options]`
- `clean`: `cargo marf-bench clean [--dry-run]`

Notes:

- Global `bench` options (`--base`, `--target`, `--output-format`) come before the bench subcommand.
- `--base` also accepts keywords: `staged`, `merge-base:<upstream-ref>`.
- `merge-base` keyword requires an explicit upstream ref suffix (no default remote/ref).
- `--target` requires `--base`.
- For `bench`, `--repeats` requires `--base`; when set, marf-bench runs full base/target comparisons N times and appends repeat statistics.
- `run --repeats` repeats the same current-tree run N times and reports repeat statistics relative to repeat #1.
- `--repeat-jitter-threshold` sets the spread threshold (percentage points) for classifying high-jitter rows in repeat confidence output; default is `30`.
- Repeat confidence classifies a row as high-jitter when total-ms repeat deltas straddle both signs (`min < 0 < max`) and spread exceeds threshold.
- `--keep-worktrees` keeps revision worktrees under the platform temp directory (for example `/tmp/marf-bench-worktrees/...` on Linux) and reuses them across invocations (faster subsequent builds when overlays are unchanged).
- Bench-specific options (`--iters`, `--rounds`, etc.) come after the bench subcommand.

## Benchmark parameter flags

Bench-specific options are accepted on the benchmark target subcommands and are forwarded to benchmark subprocess env vars:

- `--iters <N>` sets `ITERS`
- `--rounds <N>` sets `ROUNDS`
- `--chain-len <N>` sets `CHAIN_LEN`
- `--proofs` sets `READ_PROOFS=1` (uses `MARF::get_with_proof`)
- `--keys-per-block <N>` sets `KEYS_PER_BLOCK` (additional noise/bulk keys per fixture block)
- `--depths <CSV>` sets `DEPTHS`
- `--cache-strategies <CSV>` sets `CACHE_STRATEGIES`
- `--write-depths <CSV>` sets `WRITE_DEPTHS` (write parent-chain depth distribution)
- `--key-updates <N>` sets `KEY_UPDATES` (write update share in percent, `0..=100`)
- `--sqlite-wal-autocheckpoint <N>` sets `SQLITE_WAL_AUTOCHECKPOINT` (read/write benchmarks; page threshold for SQLite WAL auto-checkpoint, `0` disables auto-checkpoint)
- `--sqlite-wal-checkpoint-mode <MODE>` sets `SQLITE_WAL_CHECKPOINT_MODE` (read/write benchmarks; used for explicit post-setup checkpoint only when `SQLITE_WAL_AUTOCHECKPOINT=0`; allowed: `PASSIVE|FULL|RESTART|TRUNCATE`; default mode is `PASSIVE`)
- `--key-search-max-tries <N>` sets `KEY_SEARCH_MAX_TRIES`
- `--patch-diffs <CSV>` sets `PATCH_DIFFS` (patch benchmark diff-count cases, for example `1,4,16,64`)
- `--node-types <CSV>` sets `NODE_TYPES` (patch benchmark node types, for example `node4,node16,node48,node256` or `all`)

Patch benchmark compatibility:

- The patch target requires revisions that define `TrieNodePatch`/`TrieNodeID::Patch`.
- `marf-bench` checks each compared revision via ancestry (`git merge-base --is-ancestor 0317850e7f042de98e7bc6a1f26f6183e7d20f98 HEAD`) and fails fast with a clear error when patch support is absent.

Read fixture semantics:

- Exactly one measured depth key is inserted per block.
- `KEYS_PER_BLOCK` controls additional non-measured noise/bulk keys inserted alongside it.
- Total fixture keys per block = `1 + KEYS_PER_BLOCK`.

These flags are useful for automation since callers can avoid command-specific env var conditionals.

## Raw output notes

When `--output-format raw` (or `OUTPUT_FORMAT=raw`) is used, `read`
bench `result` lines include:

- `variant=get`
- `variant=get-with-proof`

This allows direct side-by-side comparison of plain reads and proofed reads within the same depth/strategy case.

In `raw` mode, read/write `config` lines also include WAL-control fields useful for parsers:

- `sqlite_wal_autocheckpoint`
- `sqlite_wal_checkpoint_mode`
- `sqlite_post_setup_checkpoint_ran`

## High-level lifecycle

For `bench` runs, the runner does the following:

1. Resolve the base/target revisions.
2. Create temporary detached worktree(s) for revision-based runs.
3. Overlay benchmark sources into those worktrees.
4. Build and run benchmarks.
5. Remove temporary worktrees.

If `--target` is omitted, target defaults to the current working tree (no worktree creation needed for target).

## Revision modes

## Regular revision (e.g. `--base <commit|branch|tag>`)

- Validation: `git rev-parse --verify <rev>^{commit}`
- Execution worktree: `git worktree add --detach <tmp-path> <rev>`

`<rev>` may be any git name that resolves to a commit, including:

- commit hash
- local branch name
- remote-tracking branch name (for example `origin/master`)
- tag name

Impact:

- Does not move your current branch or `HEAD`.
- Does not modify your index/staging area.
- Creates a temporary worktree directory plus corresponding metadata in `.git/worktrees/`.

See Quick start for concise command examples.

## Staged snapshot mode (`--base staged`)

`staged` is a special base selector for comparing:

- **base** = current index (staged content)
- **target** = current working tree (unless `--target` is supplied)

Internally it runs:

1. `git write-tree`
   - Creates a tree object from your current index state.
2. `git commit-tree <tree> [-p HEAD] -m "marf-bench staged snapshot"`
   - Creates a commit object pointing to that tree.
   - No branch/tag/ref is updated.
3. `git worktree add --detach <tmp-path> <ephemeral-commit>`
   - Benchmarks run in this detached temporary worktree.

Impact:

- No branch movement.
- No ref updates.
- No staging changes.
- No modifications to your current checkout files.

Notes:

- The commit/tree objects created by `commit-tree`/`write-tree` are typically unreachable (no ref points to them).
- Unreachable objects are cleaned by normal git garbage collection (`git gc`) over time.

See Quick start for concise command examples.

## Overlay behavior

Inside each temporary worktree, the runner copies the benchmark harness files from your current checkout into `stackslib/benches/marf/` before building.

This ensures benchmark source consistency across compared revisions.

Impact:

- Only affects temporary worktree filesystem contents.
- Does not modify files in your active checkout.

## Cleanup behavior

The runner tracks created worktrees and removes them on process teardown:

- `git worktree remove --force <tmp-path>`

This is triggered in `Drop` cleanup for the runner object.

Temporary worktree roots are created with the `tempfile` crate in your platform temp directory
(for example `/tmp` on Linux, `/var/folders/...` on macOS, `%TEMP%` on Windows).

If the process exits normally, these temporary directories are removed by the runner cleanup.
On startup, marf-bench also performs a stale-worktree sweep for prior marf-bench temp worktrees.
On `Ctrl-C` and panic paths, marf-bench proactively runs the same cleanup before exiting.
When `--keep-worktrees` is enabled, cached worktrees are stored under the platform temp directory and intentionally retained for reuse.
If the process is forcibly terminated (`SIGKILL`, power loss), the OS temp area lifecycle usually
cleans up old temp files/directories over time, and you can also remove leftovers manually using
the recovery commands below.

You can also run explicit marf-bench cleanup:

- `cargo marf-bench clean`
  - Removes stale marf-bench git worktrees.
  - Removes this repo's cached keep-worktree root.
  - Removes orphan temp dirs matching marf-bench naming conventions.
- `cargo marf-bench clean --dry-run`
  - Prints the same removal plan without deleting anything.

## Failure/interrupt recovery

If the process is interrupted (panic/kill/crash), temporary state can remain.

Safe cleanup commands:

- Remove stale worktree metadata/dirs:
  - `git worktree prune`
- Inspect worktrees:
  - `git worktree list`
- Optional object cleanup (later, not required immediately):
  - `git gc`

Examples:

- Clean up stale worktree metadata after an interrupted run:
  - `git worktree prune`
- Verify no temporary worktrees remain:
  - `git worktree list`
- Force object cleanup when you want to prune unreachable staged-snapshot objects sooner:
  - `git gc`

## Safety summary

Operations are designed to be non-destructive to your active development state:

- No branch switching in your current checkout.
- No reset/checkout/stash on your working tree.
- No index mutation by the runner.
- Temporary worktree isolation for revision runs.

The only persistent artifacts are normal git objects (including temporary unreachable objects in `staged` mode), which are garbage-collected by git.
