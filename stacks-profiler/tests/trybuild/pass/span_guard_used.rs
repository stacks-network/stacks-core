#![deny(unused_must_use)]

use stacks_profiler::{counter_add, counter_add_if, measure, profile, record, record_if, span, span_if};

#[profile]
fn profiled_function() {}

fn main() {
    let _guard = span!("bound");
    let _sampled = span!("sampled", rate: 10);
    let _suppressed = span!("suppressed", rate: 10, suppress);
    let _count_only = span!("count-only", rate: 10, count_only);
    let _conditional = span_if!(true, "conditional");

    measure!("measured", {
        let _nested = span!("nested");
    });

    measure!("statement-style", {
        record!("key", "value");
        record_if!(true, "conditional_key", 1u64);
        counter_add!("items", 1);
        counter_add_if!(true, "conditional_items", 1);
    });

    let result = measure!("expression-style", { 21 + 21 });
    assert_eq!(result, 42);

    profiled_function();
}
