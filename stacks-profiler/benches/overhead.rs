use std::hint::black_box;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use stacks_profiler::{Profiler, counter_add, measure, record, span};

fn make_unique_tag(i: u64) -> String {
    // Unique each iteration -> always a miss in interner
    format!("contract::call::{}", i)
}

#[inline]
fn clear_every(counter: &mut u64, n: u64) {
    *counter += 1;
    if counter.is_multiple_of(n) {
        Profiler::clear();
    }
}

fn bench_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Profiler Overhead");

    // 1. Baseline: How fast is a raw function call?
    // We need this to subtract from the profiler results to find the pure overhead.
    group.bench_function("baseline_noop", |b| {
        b.iter(|| {
            black_box(());
        });
    });

    // 2. Untagged Span Overhead
    // This measures the cost of:
    // - Thread Local access
    // - Instant::now() x2 (start/end)
    // - CPU timer x2
    // - Stack push/pop
    // - Vector recycling logic
    group.bench_function("span_untagged", |b| {
        // We define the ID outside the loop to simulate the OnceLock behavior
        // of the macros, ensuring we only measure the runtime cost, not initialization.
        let id = Box::leak(Box::new(Profiler::new_span_id("bench")));

        // Warm up OnceLock / TLS by doing one span outside measurement
        {
            let _guard = Profiler::begin_span(id, None);
            black_box(());
        }

        b.iter(|| {
            let _guard = Profiler::begin_span(id, None);
            black_box(());
        });
        Profiler::clear();
    });

    // Tagged Span Overhead
    // Adds the cost of constructing and storing the Tag enum.
    group.bench_function("span_tagged_u64", |b| {
        let id = Box::leak(Box::new(Profiler::new_span_id("bench_tag")));

        // Warm up OnceLock / TLS by doing one span outside measurement
        {
            let _guard = Profiler::begin_span(id, None);
            black_box(());
        }

        b.iter(|| {
            let _guard = Profiler::begin_span(id, Some(12345u64.into()));
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_str_as_tag_baseline", |b| {
        b.iter(|| {
            let _g = span!("record_str_tag_baseline");
            record!("tag", "contract::call::foo");
            black_box(());
        });
        Profiler::clear();
    });

    // Tagged Span Overhead: interned string tag (warm hit)
    group.bench_function("span_tagged_str_interned_hit", |b| {
        let id = Box::leak(Box::new(Profiler::new_span_id("bench_tag_str_hit")));

        // Pre-intern once (warm hit for tag)
        let tag = "contract::call::foo".to_string();
        let _warm = Profiler::begin_span(id, Some(tag.clone().into()));
        drop(_warm);

        b.iter(|| {
            // Same string content each time -> interner hit
            let _guard = Profiler::begin_span(id, Some(tag.clone().into()));
            black_box(());
        });
        Profiler::clear();
    });

    // Tagged Span Overhead: interned string tag (cold miss)
    group.bench_function("span_tagged_str_interned_miss", |b| {
        let id = Box::leak(Box::new(Profiler::new_span_id("bench_tag_str_miss")));

        let mut counter: u64 = 0;
        b.iter(|| {
            counter += 1;
            // Unique content each time -> interner miss
            let tag = make_unique_tag(counter);
            let _guard = Profiler::begin_span(id, Some(tag.into()));
            black_box(());
        });
        Profiler::clear();
    });

    // Macro Overhead
    // Measures the full cost including the OnceLock check inside the macro.
    group.bench_function("macro_span", |b| {
        b.iter(|| {
            let _guard = span!("macro_bench");
            black_box(());
        });
        Profiler::clear();
    });

    // Nested Overhead (Depth 3)
    // This tests pushing to stack, popping, and merging into PARENT (not root).
    group.bench_function("nested_depth_3", |b| {
        b.iter(|| {
            measure!("root", {
                measure!("child", {
                    measure!("grandchild", {
                        black_box(());
                    })
                })
            })
        });
        Profiler::clear();
    });

    // Sibling Merge Overhead
    // This tests the "Hot Loop" scenario where we merge into the same sibling repeatedly.
    // This exercises the `last_child` fast-path in `find_or_create_child`.
    group.bench_function("sibling_merge_loop", |b| {
        b.iter(|| {
            measure!("root", {
                for _ in 0..10 {
                    measure!("child", { black_box(()) });
                }
            })
        });
        Profiler::clear();
    });

    // Sampled Span (10% sampling)
    // Should be significantly faster than untagged
    group.bench_function("span_sampled_10", |b| {
        b.iter(|| {
            let _guard = span!("sampled_10", rate: 10);
            black_box(());
        });
        Profiler::clear();
    });

    // Sampled Span (1% sampling)
    // Should be nearly as fast as baseline
    group.bench_function("span_sampled_100", |b| {
        b.iter(|| {
            let _guard = span!("sampled_100", rate: 100);
            black_box(());
        });
        Profiler::clear();
    });

    // Suppressed unsampled parent:
    // - If not sampled, we enter suppression and *nested spans become no-ops*.
    group.bench_function("span_sampled_100_suppress_parent", |b| {
        b.iter(|| {
            let _guard = span!("sampled_100_suppress_parent", rate: 100, suppress);
            black_box(());
        });
        Profiler::clear();
    });

    // Count-only unsampled parent:
    // - If not sampled, we still push a lightweight frame to preserve hierarchy,
    //   increment per-context count, but do not read clocks.
    group.bench_function("span_sampled_100_count_only_parent", |b| {
        b.iter(|| {
            let _guard = span!("sampled_100_count_only_parent", rate: 100, count_only);
            black_box(());
        });
        Profiler::clear();
    });

    // Demonstrates the hierarchy issue explicitly:
    // Suppression means children don't attach to the wrong parent (they are dropped).
    group.bench_function("nested_parent_unsampled_suppress_children", |b| {
        b.iter(|| {
            measure!("root", {
                let _p = span!("parent", rate: 100, suppress);
                // Child work that would otherwise attach to root if parent is unsampled.
                let _c = span!("child");
                black_box(());
            });
        });
        Profiler::clear();
    });

    // Count-only means children still attach under the parent, preserving tree context.
    group.bench_function("nested_parent_unsampled_count_only_children", |b| {
        b.iter(|| {
            measure!("root", {
                let _p = span!("parent", rate: 100, count_only);
                let _c = span!("child");
                black_box(());
            });
        });
        Profiler::clear();
    });

    // Optional: tagged variants (root fanout is often tag-driven)
    group.bench_function("span_sampled_100_suppress_tagged_u64", |b| {
        b.iter(|| {
            let _guard = span!("sampled_100_suppress_tagged_u64", 12345u64, rate: 100, suppress);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("span_sampled_100_count_only_tagged_u64", |b| {
        b.iter(|| {
            let _guard =
                span!("sampled_100_count_only_tagged_u64", 12345u64, rate: 100, count_only);
            black_box(());
        });
        Profiler::clear();
    });

    group.finish();
}

fn bench_10m_sampled_spans(c: &mut Criterion) {
    let mut group = c.benchmark_group("Profiler 10M sampled spans");

    // Use flat sampling: explicitly tell Criterion to run exactly 10 samples. This overrides the
    // auto-tuning logic that tries to fit 100 samples into a time window. This works well here
    // since we're manually running a large number of iterations internally for each sample.
    group.sample_size(10).sampling_mode(SamplingMode::Flat);

    group.bench_function("10M_calls_sampled_10", |b| {
        b.iter(|| {
            let _outer_guard = span!("outer_loop");
            for _ in 0..10_000_000u32 {
                let _guard = span!("sampled_10", rate: 10);
                black_box(());
            }
            Profiler::clear();
        });
    });

    group.bench_function("10M_calls_sampled_100", |b| {
        b.iter(|| {
            let _outer_guard = span!("outer_loop");
            for _ in 0..10_000_000u32 {
                let _guard = span!("sampled_100", rate: 100);
                black_box(());
            }
            Profiler::clear();
        });
    });

    group.bench_function("10M_calls_sampled_100_suppress_parent", |b| {
        b.iter(|| {
            let _outer_guard = span!("outer_loop");
            for _ in 0..10_000_000u32 {
                let _guard = span!("sampled_100_suppress_parent", rate: 100, suppress);
                black_box(());
            }
            Profiler::clear();
        });
    });

    group.bench_function("10M_calls_sampled_100_count_only_parent", |b| {
        b.iter(|| {
            let _outer_guard = span!("outer_loop");
            for _ in 0..10_000_000u32 {
                let _guard = span!("sampled_100_count_only_parent", rate: 100, count_only);
                black_box(());
            }
            Profiler::clear();
        });
    });

    group.finish();
}

fn bench_record(c: &mut Criterion) {
    let mut group = c.benchmark_group("Profiler Record Overhead");

    // Record overhead: no span (should be near-zero due to early return)
    group.bench_function("record_no_span", |b| {
        b.iter(|| {
            record!("k", 123u64);
            black_box(());
        });
    });

    group.bench_function("record_u64", |b| {
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("record_u64_span");
            record!("k", 123u64);
            clear_every(&mut c, 1_000);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_str", |b| {
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("record_str_span");
            record!("k", "some-key");
            clear_every(&mut c, 1_000);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_bytes", |b| {
        let bytes = [0u8; 32];
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("record_bytes_span");
            record!("k", &bytes[..]);
            clear_every(&mut c, 1_000);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_1k_u64", |b| {
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("record_1k_u64_span");
            for i in 0..1000u64 {
                record!("k", i);
            }
            clear_every(&mut c, 50);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_string", |b| {
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("record_string_span");
            let s = String::from("some-key");
            record!("k", s);
            clear_every(&mut c, 1_000);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_1k_string", |b| {
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("record_1k_string_span");
            for i in 0..1000u64 {
                let s = format!("k{i}");
                record!("k", s);
            }
            clear_every(&mut c, 50);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_string_outer_span", |b| {
        let _g = span!("record_string_outer_span");
        let mut c = 0u64;
        b.iter(|| {
            let s = String::from("some-key");
            record!("k", s);
            clear_every(&mut c, 1_000);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("record_1k_string_outer_span", |b| {
        let _g = span!("record_1k_string_outer_span");
        let mut c = 0u64;
        b.iter(|| {
            for i in 0..1000u64 {
                let s = format!("k{i}");
                record!("k", s);
            }
            clear_every(&mut c, 50);
            black_box(());
        });
        Profiler::clear();
    });

    group.finish();
}

fn bench_counter(c: &mut Criterion) {
    let mut group = c.benchmark_group("Profiler Counter Overhead");

    // Counter overhead: no span (should be near-zero due to early return)
    group.bench_function("counter_no_span", |b| {
        b.iter(|| {
            counter_add!("k", 1u64);
            black_box(());
        });
    });

    group.bench_function("counter_u64", |b| {
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("counter_u64_span");
            counter_add!("k", 1u64);
            clear_every(&mut c, 1_000);
            black_box(());
        });
        Profiler::clear();
    });

    group.bench_function("counter_1k_u64", |b| {
        let mut c = 0u64;
        b.iter(|| {
            let _g = span!("counter_1k_u64_span");
            for _ in 0..1000u64 {
                counter_add!("k", 1u64);
            }
            clear_every(&mut c, 50);
            black_box(());
        });
        Profiler::clear();
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_overhead, bench_10m_sampled_spans, bench_record, bench_counter
}
criterion_main!(benches);
