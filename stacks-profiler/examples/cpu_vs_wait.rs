//! CPU work vs idle waiting — demonstrates wall-time / CPU-time distinction,
//! `record!`, `record_if!`, `counter_add!`, and `span_if!`.
//!
//! ```sh
//! cargo run -p stacks-profiler --example cpu_vs_wait
//! ```

use std::thread;
use std::time::{Duration, Instant};

use stacks_profiler::Profiler;

/// Pure CPU load — busy-loops so the CPU-time counter ticks.
fn burn_cpu(ms: u64) {
    let start = Instant::now();
    let target = Duration::from_millis(ms);
    while start.elapsed() < target {
        std::hint::spin_loop();
    }
}

/// Simulated I/O — sleeps so CPU time stays near zero while wall-time increases.
fn simulate_io(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

fn fetch_data() {
    let _guard = stacks_profiler::span!("Fetch Data (I/O)");

    // Attach metadata to the span
    stacks_profiler::record!("endpoint", "https://api.example.com/blocks");
    stacks_profiler::record!("timeout_ms", 500u64);

    simulate_io(80); // network latency
}

fn process_data(items: &[&str], verbose: bool) {
    stacks_profiler::measure!("Process Data (CPU)", {
        let mut total_bytes: u64 = 0;

        for (i, item) in items.iter().enumerate() {
            // Conditional span — only created when `verbose` is true
            let _detail = stacks_profiler::span_if!(verbose, "Item Detail", i);

            burn_cpu(15); // per-item computation

            let item_bytes = item.len() as u64 * 128; // pretend work
            total_bytes += item_bytes;

            // counter_add! aggregates across the loop
            stacks_profiler::counter_add!("bytes_processed", item_bytes);

            // record_if! — attach extra info only in verbose mode
            stacks_profiler::record_if!(verbose, "last_item", *item);
        }

        // Attach the final tally as a record too
        stacks_profiler::record!("total_bytes", total_bytes);
    });
}

fn save_results() {
    let _guard = stacks_profiler::span!("Save Results");

    {
        let _cpu = stacks_profiler::span!("Serialize (CPU)");
        burn_cpu(20);
    }
    {
        let _io = stacks_profiler::span!("Disk Write (I/O)");
        simulate_io(40);
    }
}

fn main() {
    let verbose = true;
    let items = &["tx-alpha", "tx-beta", "tx-gamma"];

    {
        let _guard = stacks_profiler::span!("Pipeline");

        fetch_data();
        process_data(items, verbose);
        save_results();
    }

    let results = Profiler::take_results();

    println!("\n=== cpu_vs_wait ===");
    println!("(Wait-bound spans are highlighted in RED)\n");
    for root in &results {
        root.print_tree();
    }
}
