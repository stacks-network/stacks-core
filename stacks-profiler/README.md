# Stacks Profiler

A lightweight, thread-local profiler for Rust that measures **wall time**,
**CPU time**, and **wait time** (wall − CPU) with minimal overhead.

Designed for performance-critical code where understanding the distinction
between "working" (burning CPU) and "waiting" (disk I/O, network, mutex
contention) is vital.

## Features

* **Dual Timing** — captures wall-clock and per-thread CPU time simultaneously.
* **Wait Time** — automatically derives `wait = wall − CPU`.
* **Nested Spans** — supports deep call stacks with hierarchical reporting.
* **Tags** — distinguish spans at the same callsite (e.g., transaction index).
* **Records & Counters** — attach key/value data and additive metrics to spans.
* **Sampling** — `rate: N` skips N−1 out of every N entries at a callsite.
* **Macros** — `#[profile]`, `span!`, `measure!`, `record!`, `counter_add!`.
* **Platform Support**:
  * **macOS** — `clock_gettime_nsec_np` (sub-µs resolution).
  * **Linux** — `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` (sub-µs resolution).
  * **Windows** — `GetThreadTimes` (~15.6 ms resolution; see crate docs).

## API Reference

### Instrumentation Macros

#### `#[profile]` / `#[profile(name = "...", sample_rate = N, unsampled = "...")]`

Attribute macro for profiling an entire function. Use when every call to the
function should be timed. The span name defaults to the function name.

```rust
use stacks_profiler::profile;

#[profile]                          // span name: "setup"
fn setup() { /* ... */ }

#[profile(name = "Teardown Phase")] // span name: "Teardown Phase"
fn teardown() { /* ... */ }
```

Supports sampling via `sample_rate` and control over unsampled calls via
`unsampled` (same semantics as `rate:` / `suppress` / `count_only` on `span!`):

```rust
use stacks_profiler::profile;

// Time ~1% of calls; unsampled calls are no-ops (default):
#[profile(sample_rate = 100)]
fn hot_path() { /* ... */ }

// Unsampled calls suppress nested spans (prevents tree distortion):
#[profile(sample_rate = 100, unsampled = "suppress")]
fn request_handler() { /* ... */ }

// Unsampled calls preserve hierarchy and increment counts without timing:
#[profile(sample_rate = 100, unsampled = "count_only")]
fn execute_tx() { /* ... */ }
```

**Note:** `#[profile]` currently does not support `async fn`.

**Tip:** Power-of-two rates (e.g., 2, 4, 8, 16, 32, 64, 128) use a bitmask
instead of modulo on the hot path (more efficient), so prefer them when the exact ratio doesn't
matter.

#### `span!(name, [tag], [rate: N], [suppress | count_only])`

Creates an RAII guard — the span lives until the guard is dropped. Use when
you need the span to outlive a single block (e.g., wrapping a loop body where
you `break`/`continue`), or when you want to end the span early with
`drop(_guard)`.

```rust
let _guard = stacks_profiler::span!("Outer");

// With a tag to distinguish iterations:
for i in 0..10 {
    let _iter = stacks_profiler::span!("Iteration", i);
}
```

Returns `Option<ProfileGuard>` — `None` when suppressed or unsampled.

#### `measure!(name, [tag], { block })`

Block-scoped span — wraps a block and returns its value. Shorter and harder
to misuse than `span!` when you just want to time a region inline.

```rust
let result = stacks_profiler::measure!("Compute", {
    expensive_work()
});
```

Also supports all `span!` modifiers (`rate:`, `suppress`, `count_only`):

```rust
stacks_profiler::measure!("Hot Path", rate: 100, count_only, {
    // timed ~1/100 calls; all calls counted
});
```

#### `record!(key, value)`

Attaches a key/value pair to the current span. Records are **per-occurrence**
(each call appends a new entry). Use for capturing contextual metadata that
varies per invocation — contract IDs, block heights, error messages, etc.

Values can be `&str`, `String`, `u64`, `i64`, or `&[u8]`.

```rust
stacks_profiler::record!("contract_id", "SP000...pox-4");
stacks_profiler::record!("deploy_height", 100u64);
```

#### `record_if!(predicate, key, value)`

Conditional variant — equivalent to `if pred { record!(...) }`. Use when
recording is gated on a runtime flag (e.g., verbose mode).

```rust
stacks_profiler::record_if!(verbose, "debug_info", "extra detail");
```

#### `counter_add!(key, delta)`

Increments a named counter on the current span. Counters with the same key
are **summed** (saturating). Use for additive metrics that accumulate across
a span — bytes processed, rows scanned, cache hits, etc.

```rust
for chunk in data.chunks(1024) {
    stacks_profiler::counter_add!("bytes_read", chunk.len() as u64);
}
// The span shows a single counter: bytes_read = total
```

#### `counter_add_if!(predicate, key, delta)`

Conditional variant of `counter_add!`.

```rust
stacks_profiler::counter_add_if!(capture, "runtime_cost", 500u64);
```

#### `span_if!(predicate, name, [...])`

Conditional span creation — returns `None` when the predicate is `false`,
otherwise forwards to `span!`. Use when an entire span should be
enabled/disabled at runtime.

```rust
let _detail = stacks_profiler::span_if!(verbose, "Detail", i);
```

### Sampling Modifiers

These modifiers reduce overhead in hot loops by only timing a fraction of
calls at each callsite. They are available on both `span!` and `measure!`.

| Modifier | Unsampled behaviour | Use case |
| --- | --- | --- |
| `rate: N` | Returns `None` (no node created) | Cheapest; fine when you don't need exact counts |
| `rate: N, count_only` | Pushes a lightweight frame, increments count, no timing (records/counters on that unsampled frame are skipped) | Need accurate per-context call counts |
| `rate: N, suppress` | Suppresses all nested spans | Prevent child spans from attaching to wrong parent |

```rust
// Sample ~1 in 100 calls (cheapest fast path):
let _g = stacks_profiler::span!("hot", rate: 100);

// Accurate count, timing only on sampled calls:
let _g = stacks_profiler::span!("hot", rate: 100, count_only);

// Suppress children on unsampled calls:
let _g = stacks_profiler::span!("hot", rate: 100, suppress);
```

### Retrieving Results

#### `Profiler::take_results() -> Vec<ProfileStats>`

Drains the calling thread's profile tree and returns it. Each entry is a
root span. The thread-local state is reset afterward.

```rust
use stacks_profiler::Profiler;

let results = Profiler::take_results();

for root in &results {
    // Pretty-print to stdout (colourised tree with records & counters)
    root.print_tree();

    // Or use a custom TreeFormatter:
    // root.print_with(&MyFormatter);
}
```

#### `ProfileStats` Fields

Each node in the returned tree exposes:

```rust
// ── Identity ──────────────────────────────────
root.id.name       // &str   — span name ("Execute TX")
root.id.context    // Option  — module path, if set
root.id.file       // &str   — source file
root.id.line       // u32    — source line
root.tag()         // Option<&Tag> — tag (u64/i64/usize/str)

// ── Timing ────────────────────────────────────
root.wall_time_ns  // u64    — cumulative wall-clock (ns)
root.cpu_time_ns   // u64    — cumulative CPU time (ns)
root.wait_time_ns()// u64    — wall − CPU (ns)
root.wall_time()   // Duration
root.cpu_time()    // Duration
root.wait_time()   // Duration

// ── Counts ────────────────────────────────────
root.entered_count // usize  — total entries (sampled + count-only)
root.sampled_count // usize  — entries that were fully timed

// ── Metadata ──────────────────────────────────
root.records       // Vec<Record>  — per-occurrence key/value pairs
                   //   .key: &str, .value: RecordValue (u64/i64/str/bytes)
root.counters      // Vec<Counter> — aggregated counters
                   //   .key: &str, .value: u64

// ── Tree ──────────────────────────────────────
root.children      // Vec<ProfileStats> — child spans
```

#### `Profiler::enable_record()` / `Profiler::disable_record()`

Globally enable or disable `record!` and `counter_add!` capture. Useful for
suppressing metadata collection during setup/warmup phases where you don't
need it, or if you're only interested in timings.

```rust
Profiler::disable_record();  // records & counters are no-ops
// ... warmup ...
Profiler::enable_record();   // resume capturing
```

### Output Example

`print_tree` produces a colourised, hierarchical view with records (`⊕`)
and counters (`∑`) shown inline:

```text
Pipeline [total: 192.887ms | busy: 65.103ms | wait: 127.784ms] (x1)
├── ▶ Fetch Data (I/O) [total: 85.042ms | busy: 0.022ms | wait: 85.020ms] (x1)
│   ⊕ endpoint = https://api.example.com/blocks
│   ⊕ timeout_ms = 500
├── ▶ Process Data (CPU) [total: 45.043ms | busy: 45.005ms | wait: 0.037ms] (x1)
│   ⊕ total_bytes = 2944
│   ├── ▶ Item Detail #0 [total: 15.032ms | busy: 14.999ms | wait: 0.033ms] (x1)
│   │   ⊕ last_item = tx-alpha
│   │   ∑ bytes_processed = 1,024
│   ├── ▶ Item Detail #1 [total: 15.002ms | busy: 14.998ms | wait: 0.004ms] (x1)
│   │   ⊕ last_item = tx-beta
│   │   ∑ bytes_processed = 896
│   └── ▶ Item Detail #2 [total: 15.001ms | busy: 15.001ms | wait: 0.000ms] (x1)
│       ⊕ last_item = tx-gamma
│       ∑ bytes_processed = 1,024
└── ▶ Save Results [total: 62.738ms | busy: 20.014ms | wait: 42.724ms] (x1)
    ├── ▶ Serialize (CPU) [total: 20.001ms | busy: 19.998ms | wait: 0.003ms] (x1)
    └── ▶ Disk Write (I/O) [total: 42.731ms | busy: 0.014ms | wait: 42.717ms] (x1)
```

## Examples

Run the included examples:

```sh
# Quick tour of every instrumentation macro
cargo run -p stacks-profiler --example basics

# CPU-time vs wall-time, records, and counters
cargo run -p stacks-profiler --example cpu_vs_wait

# Loop aggregation, call-site identity, and sampling (rate/suppress/count_only)
cargo run -p stacks-profiler --example aggregation
```
