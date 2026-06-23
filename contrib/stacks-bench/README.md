<!-- markdownlint-disable MD060 -->
# `stacks-bench`: Stacks-Core Benchmarking Tool

## Features

| Feature | Description | CLI Command | MCP Tool | MCP Resource |
| ---- | ---- | ---- | ---- | ---- |
| Run benchmark | Replay a block range recording per-block timing, clarity costs, and profiler data | `bench run` | `run_benchmark` | — |
| Calibrate baseline | Measure and save a reusable empty-block overhead baseline | `bench baseline calibrate` | — | — |
| Re-run benchmark | Re-run a previous benchmark using its stored parameters | `bench rerun` | `rerun_benchmark` | — |
| List runs | List benchmark runs with optional filters and sorting | `bench list` | `list_runs` | — |
| Show run details | Display detailed stats and profiler hotspots for a run | `bench show` | `get_run_details` | — |
| Delete runs | Delete benchmark runs and all dependent data | `bench remove` | `delete_run` | — |
| Profiler hotspots | View top-N slowest profiler spans for a run | `bench show --profiler-hot N` | `get_hotspots` | — |
| Per-block stats | Paginated per-block timing breakdown and clarity costs | — | `get_block_stats` | — |
| Per-tx stats | Paginated per-transaction timing and clarity costs | — | `get_tx_stats` | — |
| Compare runs | Diff two runs at summary and per-span level | — | `compare_runs` | — |
| Index chainstate | Index blocks from the node database into the app DB | `chainstate index` | `index_chainstate` | — |
| List chainstates | List indexed chainstates | `chainstate list` | `list_chainstates` | — |
| Chainstate details | View chainstate info including epochs and cost budgets | — | `get_chainstate` | — |
| Delete chainstates | Delete chainstates and all associated data | `chainstate remove` | `delete_chainstate` | — |
| Schema discovery | Expose the database DDL as MCP resources | — | — | `stacks-bench://schema` |

## Running Benchmarks

The primary command is `bench run`, which replays blocks from a Stacks node
data directory and stores per-block, per-transaction, and profiler data in the
`stacks-bench` application database.

```bash
cargo stacks-bench bench run \
  --source /path/to/node-data \
  --network mainnet \
  --start-at 7920000 \
  --count 100 \
  --name my-run
```

### Replay targets and filters

By default, `bench run` replays a block range. A range can be selected with
`--start-at`, `--end-at`, `--count`, and optionally `--tip` to anchor canonical
history resolution to a specific tip.

Targeted modes are also available:

| Option | Meaning |
| ---- | ---- |
| `--txid <TXID>...` | Replay one or more transactions independently from each transaction's parent block. Enables `--repetitions`. |
| `--block <BLOCK>...` | Replay one or more specific blocks independently from each block's parent. Enables `--repetitions`. |
| `--filter contract-call` | In range mode, measure only segments containing contract-call transactions. |
| `--contract <ADDR.CONTRACT[.FUNCTION]>...` | In range mode, measure only segments containing calls to one or more specific contracts or contract functions. Multiple values are OR-combined. |

`--contract` is a stricter form of `--filter contract-call` and is mutually
exclusive with `--filter`, `--txid`, and `--block`. If a contract is supplied
without a function name, all function calls to that contract match.

Example:

```bash
cargo stacks-bench bench run \
  --source /data/chainstates/mainnet \
  --start-at 7920000 \
  --count 10000 \
  --contract SP000000000000000000002Q6VF78.pox-4.stack-stx \
  --contract SP000000000000000000002Q6VF78.pox-4.delegate-stack-stx
```

### Baseline calibration

Before replay, `bench run` normally measures an empty-block overhead baseline
inline. This remains the default behavior and now also saves that measurement
as a reusable baseline calibration.

Dedicated benchmark harnesses can measure the baseline as a separate process:

```bash
cargo stacks-bench bench baseline calibrate \
  --source /data/chainstates/mainnet \
  --network mainnet
```

Then reuse it in any run against the same indexed chainstate and resolved tip:

```bash
cargo stacks-bench bench run \
  --source /data/chainstates/mainnet \
  --network mainnet \
  --start-at 7920000 \
  --end-at 7920100 \
  --baseline-id 12
```

Use `--no-baseline` to skip empty-block baseline measurement and linking
entirely. Reused calibrations must belong to the same indexed chainstate and
anchor block as the run; this keeps the saved per-run baseline row semantically
equivalent to the historical inline baseline. By default, the baseline anchor
is the run's resolved chain tip (or the block supplied with `--tip`), so a
single tip-anchored calibration can be reused across multiple ranges from the
same chainstate snapshot. Use `bench baseline calibrate --at <BLOCK>` only when
you intentionally need a non-tip calibration anchor.

### Profiler persistence controls

Profiler filtering happens when metrics are persisted to the `stacks-bench`
database. The underlying profiler may still collect spans during replay, but
filtered-out spans are omitted from the stored profiler tree. Any kept span
retains its direct ancestry up to the profiler root; structural ancestors are
stored without their own key/value or Clarity-cost rows unless they also match
the filter.

`stacks-bench` generated spans, such as `Segment` and `Transaction`, are always
persisted so the replay scaffold remains visible.

| Option | Meaning |
| ---- | ---- |
| `--bench-spans-only` | Persist only `stacks-bench` generated profiler spans. Node/Clarity spans and their profiler key/value records are omitted. |
| `--no-profiler` | Alias for `--bench-spans-only`, kept for compatibility with the first version of this option. |
| `--no-profiler-kv` | Disable capture and persistence of profiler key/value records generated by `record!` and `counter!` macros. Span timing records are still stored. |
| `--profiler-threshold <METRIC:DURATION>` | Persist non-`stacks-bench` spans only when a timing metric reaches the threshold. May be passed multiple times; thresholds are OR-combined. |
| `--span <GLOB>...` | Persist only non-`stacks-bench` spans matching one or more glob patterns. Mutually exclusive with `--ignore-span`. |
| `--ignore-span <GLOB>...` | Omit non-`stacks-bench` spans matching one or more glob patterns. Mutually exclusive with `--span`. |

`--profiler-threshold` accepts bare durations as shorthand for inclusive wall
time:

```bash
--profiler-threshold 1ms
```

The explicit form is:

```text
<metric>:<duration>
```

Supported metrics:

| Metric | Meaning |
| ---- | ---- |
| `wall` | Inclusive wall-clock time. This is the default for bare durations. |
| `self-wall` | Wall-clock time minus child wall-clock time. |
| `cpu` | Inclusive CPU time. |
| `self-cpu` | CPU time minus child CPU time. |
| `wait` | Wall-clock time minus CPU time. This is most meaningful for single-threaded spans; multi-threaded CPU accounting can reduce or clamp the value. |
| `self-wait` | `self-wall` minus `self-cpu`. |

Supported duration units are `ns`, `us`, `µs`, `μs`, `ms`, and `s`; decimal
values are allowed, e.g. `1.3s`.

Examples:

```bash
# Keep only the benchmark scaffold and block/tx summary stats.
cargo stacks-bench bench run \
  --source /data/chainstates/mainnet \
  --start-at 7920000 \
  --count 1000 \
  --bench-spans-only

# Keep long wall-time spans, plus spans with expensive local CPU work.
cargo stacks-bench bench run \
  --source /data/chainstates/mainnet \
  --start-at 7920000 \
  --count 1000 \
  --profiler-threshold wall:1ms \
  --profiler-threshold self-cpu:500us

# Keep only Clarity database spans, excluding noisy key/value payload rows.
cargo stacks-bench bench run \
  --source /data/chainstates/mainnet \
  --start-at 7920000 \
  --count 1000 \
  --span 'clarity::vm::database::*' \
  --no-profiler-kv
```

### Shadow directory placement

Before replaying, `stacks-bench` creates a shadow copy of the source node data
directory using strict reflinks. By default, the shadow directory is created
under the source directory's parent so it remains on the same filesystem.

Use `--shadow-dir-root <DIR>` when the default parent is not writable, such as
inside a sandbox:

```bash
cargo stacks-bench bench run \
  --source /data/chainstates/mainnet \
  --shadow-dir-root /work/stacks-bench-shadows \
  --start-at 7920000 \
  --count 10
```

The override directory must satisfy two constraints:

- It must be on the same filesystem as `--source`; cross-filesystem reflinks
  are refused.
- It must not resolve inside the source tree; otherwise the shadow copy would
  recursively copy itself.

The generated shadow directory is still auto-named and removed when the run
finishes.

## Structured output

Both `--json` on the CLI and successful MCP tool results wrap their payload in a
single **versioned envelope** (`CommandResult`) with a frozen header
(`schema_version`, `success`, `result_type`, `result_version`, `duration_secs`)
and a version-specific `result` body. A consumer parses the header to learn
status and how to interpret `result`, regardless of which `stacks-bench` build
produced it. (CLI failures are enveloped too, with `success: false`; MCP
failures use the protocol's native error channel rather than an envelope.)

In `--json` mode, stdout is reserved for the final envelope. Long-running CLI
commands may emit versioned progress events as JSONL on stderr.

The machine-readable JSON Schema and the full evolution policy live in
[`schema/`](schema/README.md).

## MCP Server

`stacks-bench` includes an MCP (Model Context Protocol) server for querying
benchmark data and running benchmark operations over stdio. Long-running
operations emit progress notifications.

### Configuration

Configure `stacks-bench` as a `STDIO`-style MCP server. Example:

```json
{
  "mcpServers": {
    "stacks-bench": {
      "command": "cargo",
      "args": [
        "run",
        "-p", "stacks-bench",
        "--release",
        "--",
        "--db", "/path/to/stacks-bench-data",
        "mcp"
      ]
    }
  }
}
```

### Tools

| Tool | Description | Destructive |
| ---- | ---- | ---- |
| `list_runs` | List benchmark runs with optional filters (name, incomplete) | No |
| `get_run_details` | Detailed run info with summary stats and top-N profiler hotspots | No |
| `get_hotspots` | Profiler hotspots sorted by estimated self wall time | No |
| `get_block_stats` | Paginated per-block timing, clarity costs, and storage delta | No |
| `get_tx_stats` | Paginated per-tx timing and clarity costs, filterable by block | No |
| `compare_runs` | Summary-level and per-span diff between two runs | No |
| `list_chainstates` | List indexed chainstates with run counts | No |
| `get_chainstate` | Chainstate detail including epochs and cost budgets | No |
| `run_benchmark` | Run a benchmark (block range or single tx) with progress notifications | Yes |
| `rerun_benchmark` | Re-run a previous benchmark by ID | Yes |
| `index_chainstate` | Index chainstate blocks into the app DB | Yes |
| `delete_run` | Delete a benchmark run and all dependent data | Yes |
| `delete_chainstate` | Delete a chainstate and all associated runs | Yes |

The `run_benchmark` MCP tool mirrors the main `bench run` target/filter and
profiler persistence options. CLI flags map to snake_case JSON fields; for
example, `--shadow-dir-root` becomes `shadow_dir_root`, `--bench-spans-only`
becomes `no_profiler`, and repeated options such as `--contract`, `--span`,
`--ignore-span`, and `--profiler-threshold` are JSON arrays.

Example:

```json
{
  "source_dir": "/data/chainstates/mainnet",
  "start_at": "7920000",
  "count": 1000,
  "filter": "contract-call",
  "profiler_threshold": ["wall:1ms", "self-cpu:500us"],
  "ignore_span": ["clarity::vm::analysis::*"],
  "no_profiler_kv": true,
  "shadow_dir_root": "/work/stacks-bench-shadows",
  "name": "profile-contract-calls"
}
```

### Resources

| URI | Description |
| ---- | ---- |
| `stacks-bench://schema` | SQL DDL for the stacks-bench database (excludes internal/staging tables) |
| `stacks-bench://schema/{table}` | DDL for a single table and its indexes |

## Storage Check

`stacks-bench` is sensitive to disk speed. Slow random reads or writes can make
benchmark results reflect local storage bottlenecks instead of node behavior.

Internal NVMe storage is strongly recommended. High-quality USB4/Thunderbolt NVMe can also pass.

### Run the check

Run this `fio` command in a temporary directory on the target disk:

```text
fio --name=stacks-hw-check \
    --ioengine=psync --direct=1 \
    --rw=randrw --rwmixread=70 \
    --bs=16k \
    --size=8G --numjobs=1 --iodepth=1 \
    --time_based=1 --runtime=30 \
    --refill_buffers=1 --randrepeat=0 \
    --fsync=0
```

This approximates the mixed random I/O pattern of Stacks MARF state and SQLite
commit operations.

### How to interpret results

Focus only on the final **READ**/**WRITE** bandwidth values:

| Metric           | Minimum Recommended | Meaning |
|-----------------|-------------------:|--------|
| **Read BW**     | ≥ **300 MiB/s**     | MARF/state reads are not bottlenecked |
| **Write BW**    | ≥ **120 MiB/s**     | Commit path is not blocked on disk |

_(Thresholds are based on typical NVMe performance in cloud production setups:
AWS `m6i` + `gp3`/`gp4`.)_

Example (PASS):

```text
READ: bw=418MiB/s
WRITE: bw=179MiB/s
```

### PASS / WARNING / FAIL guidance

| Result | Interpretation | Action |
|--------|----------------|--------|
| **PASS** | Meets recommended thresholds | Benchmark results are valid |
| **WARNING** | Slightly below thresholds | Results may under-represent node performance |
| **FAIL** | Well below thresholds | Disk is a bottleneck → upgrade or move benchmark to faster storage |

## Benchmark Data Storage

`stacks-bench` stores its benchmarking data in an SQLite database at `~/.stacks-bench/appdata/stacks-bench.db`.

The data directory can be overridden in three ways (highest priority first):

1. **`--db <path>`** CLI flag
2. **`STACKS_BENCH_DATA_DIR`** environment variable
3. **Default:** `~/.stacks-bench`

Using a fixed home-relative path means benchmark data is shared across worktrees, making cross-branch comparisons straightforward.
