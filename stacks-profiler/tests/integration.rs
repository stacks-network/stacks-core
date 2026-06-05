use std::hint::black_box;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use std::{panic, thread};

use stacks_profiler::{Profiler, RecordValue, Tag, TakeResultsError, profile, span};

static RECORD_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_record_tests() -> MutexGuard<'static, ()> {
    RECORD_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct RecordEnabledRestore;

impl Drop for RecordEnabledRestore {
    fn drop(&mut self) {
        Profiler::enable_record();
    }
}

struct NoopFormatter;

impl stacks_profiler::print::TreeFormatter for NoopFormatter {
    fn format_node<W: std::fmt::Write>(
        &self,
        _ctx: &stacks_profiler::print::NodeContext,
        _writer: &mut W,
    ) -> std::fmt::Result {
        Ok(())
    }
}

fn find_child<'a>(
    node: &'a stacks_profiler::ProfileStats,
    name: &'static str,
) -> Option<&'a stacks_profiler::ProfileStats> {
    node.children.iter().find(|c| c.name() == name)
}

#[test]
fn test_basic_nesting() {
    Profiler::clear();

    stacks_profiler::measure!("Root", {
        thread::sleep(Duration::from_millis(1));
        stacks_profiler::measure!("Child", {
            thread::sleep(Duration::from_millis(1));
        });
    });

    let results = Profiler::take_results().expect("take profiler results");

    assert_eq!(results.len(), 1, "Should have 1 root");
    let root = &results[0];
    assert_eq!(root.id.name, "Root");

    assert_eq!(root.children.len(), 1, "Root should have 1 child");
    let child = &root.children[0];
    assert_eq!(child.id.name, "Child");
}

#[test]
fn test_records_counters_and_profile_stats_accessors() {
    let _lock = lock_record_tests();
    let _restore = RecordEnabledRestore;

    Profiler::clear();
    Profiler::enable_record();

    // No active span: these should be no-ops.
    Profiler::record("no_span", RecordValue::from(1u64));
    Profiler::counter_add("no_span", 1);

    stacks_profiler::measure!("Accessors", "tag", {
        stacks_profiler::record!("u64", 7u64);
        stacks_profiler::record!("i64", -7i64);
        stacks_profiler::record!("str", "value");
        stacks_profiler::record!("string", String::from("owned"));
        stacks_profiler::record!("bytes", &[0xabu8, 0xcd][..]);
        stacks_profiler::counter_add!("saturating", u64::MAX);
        stacks_profiler::counter_add!("saturating", 1);
    });

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 1);

    let root = &results[0];
    assert_eq!(root.name(), "Accessors");
    assert_eq!(root.context(), Some(module_path!()));
    assert!(root.source_file().ends_with("integration.rs"));
    assert!(root.source_line() > 0);
    assert_eq!(root.tag(), Some(&Tag::Str("tag")));
    assert_eq!(root.count(), 1);
    assert_eq!(root.wall_time().as_nanos(), root.wall_time_ns as u128);
    assert_eq!(root.cpu_time().as_nanos(), root.cpu_time_ns as u128);
    assert_eq!(root.wait_time().as_nanos(), root.wait_time_ns() as u128);
    assert_eq!(root.wall_time_micros(), root.wall_time_ns / 1_000);
    assert_eq!(root.cpu_time_micros(), root.cpu_time_ns / 1_000);
    root.print_with(&NoopFormatter);
    root.print_tree();

    let rendered_records: Vec<_> = root
        .records
        .iter()
        .map(|record| (record.key, record.value.to_string()))
        .collect();
    assert_eq!(
        rendered_records,
        vec![
            ("u64", "7".to_string()),
            ("i64", "-7".to_string()),
            ("str", "value".to_string()),
            ("string", "owned".to_string()),
            ("bytes", "0xabcd".to_string()),
        ]
    );

    assert_eq!(root.counters.len(), 1);
    assert_eq!(root.counters[0].key, "saturating");
    assert_eq!(root.counters[0].value, u64::MAX);
}

#[test]
fn test_records_and_counters_respect_disabled_and_suppressed_states() {
    let _lock = lock_record_tests();
    let _restore = RecordEnabledRestore;

    Profiler::clear();
    Profiler::disable_record();
    assert!(!Profiler::is_record_enabled());

    stacks_profiler::measure!("DisabledRecord", {
        stacks_profiler::record!("disabled_record", 1u64);
        stacks_profiler::counter_add!("disabled_counter", 1);
    });

    Profiler::enable_record();
    assert!(Profiler::is_record_enabled());

    stacks_profiler::measure!("SuppressedRecordRoot", {
        let _suppressed = span!("SuppressedRecordParent", rate: 100, suppress);
        stacks_profiler::record!("suppressed_record", 1u64);
        stacks_profiler::counter_add!("suppressed_counter", 1);
    });

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].name(), "DisabledRecord");
    assert!(results[0].records.is_empty());
    assert!(results[0].counters.is_empty());
    assert_eq!(results[1].name(), "SuppressedRecordRoot");
    assert!(results[1].records.is_empty());
    assert!(results[1].counters.is_empty());
}

#[test]
fn test_non_consecutive_root_and_child_spans_reuse_existing_nodes() {
    Profiler::clear();

    for tag in ["a", "b", "a"] {
        let _root = span!("RootScan", tag);
    }

    stacks_profiler::measure!("RootWithChildren", {
        for tag in ["a", "b", "a"] {
            let _child = span!("ChildScan", tag);
        }
    });

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(
        results
            .iter()
            .filter(|node| node.name() == "RootScan")
            .count(),
        2,
        "different tags should create distinct root nodes"
    );
    let root_a = results
        .iter()
        .find(|node| node.name() == "RootScan" && node.tag() == Some(&Tag::Str("a")))
        .expect("RootScan tag=a should exist");
    assert_eq!(root_a.count(), 2);

    let root_with_children = results
        .iter()
        .find(|node| node.name() == "RootWithChildren")
        .expect("RootWithChildren should exist");
    assert_eq!(
        root_with_children
            .children
            .iter()
            .filter(|node| node.name() == "ChildScan")
            .count(),
        2,
        "different tags should create distinct child nodes"
    );
    let child_a = root_with_children
        .children
        .iter()
        .find(|node| node.name() == "ChildScan" && node.tag() == Some(&Tag::Str("a")))
        .expect("ChildScan tag=a should exist");
    assert_eq!(child_a.count(), 2);
}

#[test]
fn test_count_only_spans_skip_records_and_counters() {
    let _lock = lock_record_tests();
    let _restore = RecordEnabledRestore;

    Profiler::clear();
    Profiler::enable_record();

    for iteration in 0..2 {
        let _guard = span!("CountOnlyRecords", rate: 2, count_only);
        stacks_profiler::record!("iteration", iteration as u64);
        stacks_profiler::counter_add!("iterations", 1);
    }

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 1);

    let root = &results[0];
    assert_eq!(root.name(), "CountOnlyRecords");
    assert_eq!(root.entered_count, 2);
    assert_eq!(root.sampled_count, 1);
    assert_eq!(
        root.records.len(),
        1,
        "record! should be skipped for the count-only entry"
    );
    assert_eq!(root.records[0].value.to_string(), "0");
    assert_eq!(
        root.counters.len(),
        1,
        "counter_add! should be skipped for the count-only entry"
    );
    assert_eq!(root.counters[0].value, 1);
}

#[test]
fn test_take_results_errors_with_active_spans() {
    Profiler::clear();

    let guard = span!("StillActive");
    let err = Profiler::take_results().expect_err("active span should prevent result drain");
    assert_eq!(err, TakeResultsError::ActiveSpans { active: 1 });

    drop(guard);

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name(), "StillActive");
}

#[test]
fn test_macro_variations() {
    Profiler::clear();

    // Statement style (wrapped in block to force drop)
    {
        let _guard = stacks_profiler::span!("Statement");
    }

    // Anonymous/block style
    stacks_profiler::measure!({
        let _x = 1 + 1;
    });

    // Expression style
    let res = stacks_profiler::measure!("Expression", { 5 + 5 });
    assert_eq!(res, 10);

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name(), "Statement");
    assert_eq!(results[1].name(), "scope");
    assert_eq!(results[2].name(), "Expression");
}

#[test]
fn test_multi_threading_isolation() {
    Profiler::clear();

    // Spawn a thread that does profiling
    let t = thread::spawn(|| {
        // Wrap in block so guard drops before take_results
        {
            let _span = stacks_profiler::span!("ThreadWork");
            thread::sleep(Duration::from_millis(10));
        }
        // Return the results to the main thread
        Profiler::take_results().expect("take profiler results")
    });

    // Do work on main thread simultaneously
    {
        let _span = stacks_profiler::span!("MainWork");
        thread::sleep(Duration::from_millis(10));
    } // Guard drops here, finishing the span

    let thread_results = t.join().expect("Thread failed");
    let main_results = Profiler::take_results().expect("take profiler results");

    // Verify thread results
    assert_eq!(thread_results.len(), 1, "Thread should have 1 result");
    assert_eq!(thread_results[0].name(), "ThreadWork");

    // Verify main results
    assert_eq!(main_results.len(), 1, "Main thread should have 1 result");
    assert_eq!(main_results[0].name(), "MainWork");

    // Ensure no cross-contamination
    assert!(!main_results.iter().any(|r| r.name() == "ThreadWork"));
}

#[test]
fn test_panic_safety() {
    Profiler::clear();

    let result = panic::catch_unwind(|| {
        let _span = stacks_profiler::span!("WillPanic");
        panic!("Oops");
    });
    assert!(result.is_err());

    // Run a normal profile to prove the stack recovered
    {
        let _span = stacks_profiler::span!("Recovered");
    } // Guard drops here, finishing the span

    let results = Profiler::take_results().expect("take profiler results");

    // Logic:
    // 1. "WillPanic" started.
    // 2. Panic -> stack unwind -> guard dropped -> "WillPanic" finished & recorded.
    // 3. "Recovered" started -> finished -> recorded.

    assert_eq!(results.len(), 2, "Should have 'WillPanic' and 'Recovered'");
    assert_eq!(results[0].name(), "WillPanic");
    assert_eq!(results[1].name(), "Recovered");
}

#[test]
fn test_recursion() {
    Profiler::clear();

    #[profile(name = "Recursive")]
    fn recursive_func(depth: usize) {
        if depth > 0 {
            recursive_func(depth - 1);
        }
    }

    recursive_func(3);

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 1);

    let mut current = &results[0];
    let mut depth = 0;
    assert_eq!(current.name(), "Recursive");

    while !current.children.is_empty() {
        current = &current.children[0];
        assert_eq!(current.name(), "Recursive");
        depth += 1;
    }

    assert_eq!(depth, 3);
}

#[test]
fn test_zero_time_safety() {
    Profiler::clear();

    // Ensure very fast operations don't cause underflow/crashes
    for _ in 0..1000 {
        let _guard = stacks_profiler::span!("Fast");
    }

    let results = Profiler::take_results().expect("take profiler results");

    // Because all calls happen at the same file/line, they are aggregated.
    assert_eq!(
        results.len(),
        1,
        "Should aggregate 1000 identical calls into 1 entry"
    );
    assert_eq!(
        results[0].entered_count, 1000,
        "Count should reflect the loop iterations"
    );
    assert_eq!(results[0].id.name, "Fast");
}

#[test]
fn test_owned_string_tags_are_interned_once() {
    let a: stacks_profiler::Tag = String::from("same-tag").into();
    let b: stacks_profiler::Tag = String::from("same-tag").into();

    let (stacks_profiler::Tag::Str(a), stacks_profiler::Tag::Str(b)) = (a, b) else {
        panic!("owned string tags should intern as Tag::Str");
    };

    assert!(
        std::ptr::eq(a, b),
        "repeated owned string tags should reuse the same interned string"
    );
}

#[test]
fn test_sampling_rate_accuracy() {
    Profiler::clear();

    let iterations = 100_000;
    let rate = 10;

    // Run loop
    for _ in 0..iterations {
        // This macro expansion site has its own unique static counter
        let _guard = span!("test_sampling", rate: 10);
    }

    // Get stats
    let stats = Profiler::take_results().expect("take profiler results");

    // Find our span
    let root = stats
        .iter()
        .find(|s| s.id.name == "test_sampling")
        .expect("Span not found");

    // We expect exactly iterations / rate because the counter is deterministic
    // and starts at 0 for this specific macro expansion site.
    let expected = iterations / rate;
    let actual = root.entered_count;
    assert_eq!(actual, expected, "Sampling count mismatch");
}

#[test]
fn test_suppression_prevents_wrong_parent_attachment() {
    Profiler::clear();

    // With rate=2, the first callsite execution samples (n=0), the second does not (n=1).
    // In suppress mode, the unsampled parent becomes a suppression guard, and nested spans
    // must become no-ops (so they don't attach to the wrong parent).
    stacks_profiler::measure!("RootSuppress", {
        for _ in 0..2 {
            let _parent = span!("ParentSuppress", rate: 2, suppress);
            let _child = span!("ChildSuppress");
            black_box(());
        }
    });

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 1, "Should have exactly one root");
    let root = &results[0];
    assert_eq!(root.name(), "RootSuppress");

    // Parent span should only be recorded on the sampled iteration (so count == 1).
    let parent =
        find_child(root, "ParentSuppress").expect("Expected ParentSuppress under RootSuppress");
    assert_eq!(
        parent.count(),
        1,
        "Suppress mode should NOT create a parent span entry on unsampled iterations"
    );

    // Child should only exist under the sampled parent (count == 1).
    let child =
        find_child(parent, "ChildSuppress").expect("Expected ChildSuppress under ParentSuppress");
    assert_eq!(
        child.count(),
        1,
        "Child should only be recorded on sampled iterations"
    );

    // Child must NOT attach to root when parent is unsampled.
    assert!(
        find_child(root, "ChildSuppress").is_none(),
        "Child must not attach to Root when Parent is unsampled (suppression should drop it)"
    );
}

#[test]
fn test_count_only_preserves_hierarchy_and_counts() {
    Profiler::clear();

    stacks_profiler::measure!("RootCountOnly", {
        for _ in 0..2 {
            let _parent = span!("ParentCountOnly", rate: 2, count_only);
            let _child = span!("ChildCountOnly");
            black_box(());
        }
    });

    let results = Profiler::take_results().expect("take profiler results");
    assert_eq!(results.len(), 1, "Should have exactly one root");
    let root = &results[0];
    assert_eq!(root.name(), "RootCountOnly");

    let parents: Vec<_> = root
        .children
        .iter()
        .filter(|c| c.name() == "ParentCountOnly")
        .collect();
    assert_eq!(
        parents.len(),
        1,
        "Expected exactly one ParentCountOnly node (duplicate SpanIds indicates macro hoisting bug)"
    );
    let parent = parents[0];

    assert_eq!(
        parent.count(),
        2,
        "Count-only mode should increment count even when not timing"
    );

    let child = find_child(parent, "ChildCountOnly")
        .expect("Expected ChildCountOnly under ParentCountOnly");
    assert_eq!(
        child.count(),
        2,
        "Child should attach under Parent for both iterations"
    );

    assert!(
        find_child(root, "ChildCountOnly").is_none(),
        "Child must not attach to Root when Parent is count-only"
    );
}
