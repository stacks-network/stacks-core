//! Loop aggregation and sampling (`rate: N`, `count_only`, `suppress`).
//!
//! ```sh
//! cargo run -p stacks-profiler --example aggregation
//! ```

use stacks_profiler::Profiler;

/// A tiny unit of work — called multiple times from the same `span!` callsite.
fn sub_task() {
    let _span = stacks_profiler::span!("Sub Task");
    let mut _x = 0u64;
    for _ in 0..1_000 {
        _x = _x.wrapping_add(1);
    }
}

fn main() {
    // Part 1: Basic loop aggregation
    // "Iteration" is called 100 times at a single call site → 1 node, count=100.
    // "Sub Task" has its span! inside the function body (one callsite), so both
    // the unconditional and conditional calls aggregate into a single node.
    {
        let _root = stacks_profiler::span!("Loop (always recorded)");

        for i in 0..100 {
            let _iter = stacks_profiler::span!("Iteration");

            sub_task(); // same span! callsite → aggregated into one node

            if i % 10 == 0 {
                sub_task(); // same span! callsite → same aggregated node
            }
        }
    }

    // Part 2: rate: N (sampling)
    // Only ~1 in 10 iterations are timed; unsampled → None.
    {
        let _root = stacks_profiler::span!("Loop (rate: 10)");

        for _ in 0..100 {
            let _iter = stacks_profiler::span!("Sampled Iteration", rate: 10);
            std::hint::spin_loop();
        }
    }

    // Part 3: rate + count_only
    // Unsampled iterations still maintain hierarchy and increment count.
    // Result: count=100, timing only from ~10 sampled calls.
    {
        let _root = stacks_profiler::span!("Loop (rate: 10, count_only)");

        for _ in 0..100 {
            let _iter = stacks_profiler::span!("Counted Iteration", rate: 10, count_only);
            std::hint::spin_loop();
        }
    }

    // Part 4: rate + suppress
    // Unsampled iterations suppress all nested spans.
    {
        let _root = stacks_profiler::span!("Loop (rate: 10, suppress)");

        for _ in 0..100 {
            let _iter = stacks_profiler::span!("Suppressed Iteration", rate: 10, suppress);
            // This child only appears when the parent is sampled:
            let _child = stacks_profiler::span!("Nested Work");
            std::hint::spin_loop();
        }
    }

    let results = Profiler::take_results();

    println!("\n=== aggregation ===\n");
    for root in &results {
        root.print_tree();
        println!();
    }
}
