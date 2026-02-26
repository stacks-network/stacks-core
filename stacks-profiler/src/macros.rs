// Copyright (C) 2026 Stacks Open Internet Foundation
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

/// Execute a block inside a profiling span.
///
/// Wraps a block in a [`span!`] guard — the span ends when the block exits (including early
/// returns and panics). Accepts the same modifiers as `span!` (`rate:`, `suppress`, `count_only`,
/// tags). See [`span!`] for full details on sampling and tagging.
///
/// Use `span!` directly if you need the guard to outlive a single block.
///
/// ## Examples
///
/// ```rust
/// use stacks_profiler::measure;
///
/// // Always recorded:
/// measure!("decode_block", { /* ... */ });
///
/// // With a tag:
/// measure!("execute_tx", 42u64, { /* ... */ });
///
/// // Sampled with suppression:
/// measure!("tx", rate: 100, suppress, {
///     measure!("verify", { /* ... */ });
/// });
/// ```
#[macro_export]
macro_rules! measure {
    // Name, Tag, Rate, count_only, Block
    ($name:literal, $tag:expr, rate: $rate:literal, count_only, $block:block) => {{
        let _guard = $crate::span!($name, $tag, rate: $rate, count_only);
        $block
    }};

    // Name, Rate, count_only, Block
    ($name:literal, rate: $rate:literal, count_only, $block:block) => {{
        let _guard = $crate::span!($name, rate: $rate, count_only);
        $block
    }};

    // Name, Tag, Rate, suppress, Block
    ($name:literal, $tag:expr, rate: $rate:literal, suppress, $block:block) => {{
        let _guard = $crate::span!($name, $tag, rate: $rate, suppress);
        $block
    }};

    // Name, Rate, suppress, Block
    ($name:literal, rate: $rate:literal, suppress, $block:block) => {{
        let _guard = $crate::span!($name, rate: $rate, suppress);
        $block
    }};

    // Name, Tag, Rate, Block
    ($name:literal, $tag:expr, rate: $rate:literal, $block:block) => {{
        let _guard = $crate::span!($name, $tag, rate: $rate);
        $block
    }};

    // Name, Rate, Block
    ($name:literal, rate: $rate:literal, $block:block) => {{
        let _guard = $crate::span!($name, rate: $rate);
        $block
    }};

    // Name, Tag, Block
    ($name:literal, $tag:expr, $block:block) => {{
        let _guard = $crate::span!($name, $tag);
        $block
    }};

    // Name, Block
    ($name:literal, $block:block) => {{
        let _guard = $crate::span!($name);
        $block
    }};

    // Trap (Name, Rate)
    ($name:literal, rate: $rate:literal) => {
        let _guard = $crate::span!($name, rate: $rate);
    };

    // Trap (Name)
    ($name:literal) => {
        let _guard = $crate::span!($name);
    };

    // Anonymous Block
    ($($t:tt)*) => {{
        let _guard = $crate::span!("scope");
        $($t)*
    }};
}

/// Create a profiling span guard for the current scope.
///
/// Returns `Option<ProfileGuard>` — `Some` when recorded, `None` when suppressed or unsampled.
/// The span ends when the guard is dropped. Use [`measure!`] instead if you just want to
/// time a block.
///
/// ## Forms
///
/// | Form | Behavior |
/// |------|----------|
/// | `span!("name")` | Always timed |
/// | `span!("name", tag)` | Always timed, with tag |
/// | `span!("name", rate: N)` | Timed 1/N; unsampled → `None` |
/// | `span!("name", rate: N, suppress)` | Timed 1/N; unsampled → suppresses nested spans |
/// | `span!("name", rate: N, count_only)` | Timed 1/N; unsampled → preserves hierarchy, increments count, no clocks (records/counters on that frame are skipped) |
///
/// All forms also accept `(name, tag, rate: N, ...)`.
///
/// ## Sampling modifiers
///
/// - **`suppress`**: unsampled parents suppress all nested `span!`/`measure!` calls (they
///   return `None`), preventing children from attaching to the wrong ancestor.
/// - **`count_only`**: unsampled parents still push a frame to maintain hierarchy and
///   increment `count`, but skip clock reads. Timing fields only reflect sampled calls.
///   `record!`/`counter_add!` on that unsampled frame are no-ops.
///
/// ## Examples
///
/// ```rust
/// use stacks_profiler::{measure, span};
///
/// let guard = span!("outer");
/// drop(guard); // end early
///
/// let _g = span!("hot", rate: 100); // sample 1%
///
/// measure!("root", {
///     let _p = span!("parent", rate: 100, suppress);
///     let _c = span!("child"); // only recorded when parent is sampled
/// });
/// ```
#[macro_export]
macro_rules! span {
    // Internal helpers

    (@get_id $name:literal) => {{
        static __PROFILER_SPAN_ID: std::sync::OnceLock<$crate::SpanId> = std::sync::OnceLock::new();
        __PROFILER_SPAN_ID.get_or_init(|| $crate::Profiler::new_span_id($name).with_context(module_path!()))
    }};

    (@begin $id:expr, $tag_opt:expr) => {{
        Some($crate::Profiler::begin_span($id, $tag_opt))
    }};

    (@should_sample $counter:ident, $rate:literal) => {{
        const __RATE: usize = $rate;
        if __RATE <= 1 {
            true
        } else {
            let __n = $counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            if __RATE.is_power_of_two() {
                (__n & (__RATE - 1)) == 0
            } else {
                (__n % __RATE) == 0
            }
        }
    }};

    // Public forms

    // Name, Tag, Rate, count_only
    ($name:literal, $tag:expr, rate: $rate:literal, count_only) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            static __PROFILER_SAMPLE_COUNTER: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);

            // Hoist id + tag so both branches share the same OnceLock/static.
            let __id = $crate::span!(@get_id $name);
            let __tag: $crate::Tag = ::core::convert::Into::into($tag);

            if $crate::span!(@should_sample __PROFILER_SAMPLE_COUNTER, $rate) {
                $crate::span!(@begin __id, Some(__tag))
            } else {
                Some($crate::Profiler::begin_span_count_only(__id, Some(__tag)))
            }
        }
    }};

    // Name, Rate, count_only
    ($name:literal, rate: $rate:literal, count_only) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            static __PROFILER_SAMPLE_COUNTER: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);

            // Hoist id so both branches share the same OnceLock/static.
            let __id = $crate::span!(@get_id $name);

            if $crate::span!(@should_sample __PROFILER_SAMPLE_COUNTER, $rate) {
                $crate::span!(@begin __id, None)
            } else {
                Some($crate::Profiler::begin_span_count_only(__id, None))
            }
        }
    }};

    // Name, Tag, Rate, suppress
    ($name:literal, $tag:expr, rate: $rate:literal, suppress) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            static __PROFILER_SAMPLE_COUNTER: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);

            if $crate::span!(@should_sample __PROFILER_SAMPLE_COUNTER, $rate) {
                let __id = $crate::span!(@get_id $name);
                let __tag: $crate::Tag = ::core::convert::Into::into($tag);
                $crate::span!(@begin __id, Some(__tag))
            } else {
                Some($crate::Profiler::begin_suppression())
            }
        }
    }};

    // Name, Rate, suppress
    ($name:literal, rate: $rate:literal, suppress) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            static __PROFILER_SAMPLE_COUNTER: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);

            if $crate::span!(@should_sample __PROFILER_SAMPLE_COUNTER, $rate) {
                let __id = $crate::span!(@get_id $name);
                $crate::span!(@begin __id, None)
            } else {
                Some($crate::Profiler::begin_suppression())
            }
        }
    }};

    // Name, Tag, Rate (default: unsampled => None)
    ($name:literal, $tag:expr, rate: $rate:literal) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            static __PROFILER_SAMPLE_COUNTER: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);

            if $crate::span!(@should_sample __PROFILER_SAMPLE_COUNTER, $rate) {
                let __id = $crate::span!(@get_id $name);
                let __tag: $crate::Tag = ::core::convert::Into::into($tag);
                $crate::span!(@begin __id, Some(__tag))
            } else {
                None
            }
        }
    }};

    // Name, Rate (default: unsampled => None)
    ($name:literal, rate: $rate:literal) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            static __PROFILER_SAMPLE_COUNTER: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);

            if $crate::span!(@should_sample __PROFILER_SAMPLE_COUNTER, $rate) {
                let __id = $crate::span!(@get_id $name);
                $crate::span!(@begin __id, None)
            } else {
                None
            }
        }
    }};

    // Name, Tag
    ($name:literal, $tag:expr) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            let __id = $crate::span!(@get_id $name);
            let __tag: $crate::Tag = ::core::convert::Into::into($tag);
            $crate::span!(@begin __id, Some(__tag))
        }
    }};

    // Name
    ($name:literal) => {{
        if $crate::Profiler::is_suppressed() {
            None
        } else {
            let __id = $crate::span!(@get_id $name);
            $crate::span!(@begin __id, None)
        }
    }};
}

/// Conditional [`span!`](crate::span) — returns `None` when the predicate is false, otherwise
/// forwards to `span!`.
#[macro_export]
macro_rules! span_if {
    ($pred:expr, $($rest:tt)+) => {{
        if $pred {
            $crate::span!($($rest)+)
        } else {
            None
        }
    }};
}

/// Attach a key/value record to the current span (if any).
///
/// Records are stored per-occurrence (not aggregated). The value is converted via
/// `Into<RecordValue>`, which accepts `&str`, `String`, `u64`, `i64`, and `&[u8]`.
///
/// ## Examples
///
/// ```rust
/// use stacks_profiler::{measure, record};
///
/// measure!("load_contract", {
///     record!("contract_id", "SP000000000000000000002Q6VF78.pox-4");
///     record!("deploy_height", 100u64);
/// });
/// ```
#[macro_export]
macro_rules! record {
    ($key:literal, $val:expr) => {{
        $crate::Profiler::record($key, ($val).into());
    }};
}

/// Conditional [`record!`](crate::record) — equivalent to `if pred { record!(key, val) }`.
///
/// ```rust
/// # use stacks_profiler::{measure, record_if};
/// let verbose = true;
/// measure!("process", {
///     record_if!(verbose, "debug_info", "extra detail");
/// });
/// ```
#[macro_export]
macro_rules! record_if {
    ($pred:expr, $key:literal, $val:expr) => {{
        if $pred {
            $crate::Profiler::record($key, ($val).into());
        }
    }};
}

/// Increment a named counter on the current span (aggregated by key).
///
/// If a counter with this key already exists on the span, `delta` is added to it (saturating).
/// Otherwise a new counter is created with the given value.
///
/// ## Examples
///
/// ```rust
/// use stacks_profiler::{measure, counter_add};
///
/// measure!("process_block", {
///     for chunk in [1024u64, 2048, 512] {
///         counter_add!("bytes_read", chunk);
///     }
///     // The span will show a single counter: bytes_read = 3584
/// });
/// ```
#[macro_export]
macro_rules! counter_add {
    ($key:literal, $delta:expr) => {{
        $crate::Profiler::counter_add($key, $delta);
    }};
}

/// Conditional [`counter_add!`](crate::counter_add) — equivalent to
/// `if pred { counter_add!(key, delta) }`.
///
/// ```rust
/// # use stacks_profiler::{measure, counter_add_if};
/// let capture = true;
/// measure!("execute", {
///     counter_add_if!(capture, "runtime_cost", 500u64);
/// });
/// ```
#[macro_export]
macro_rules! counter_add_if {
    ($pred:expr, $key:literal, $delta:expr) => {{
        if $pred {
            $crate::Profiler::counter_add($key, $delta);
        }
    }};
}
