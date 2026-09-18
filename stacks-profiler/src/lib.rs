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

//! # Stacks Profiler
//!
//! A lightweight, low-overhead profiler built on thread-local storage.
//!
//! ## Key concepts
//!
//! - **Span** — a named region of execution.  Spans form a tree: each span is either a root or a
//!   child of the span that was active when it was entered.
//! - **[`SpanId`]** — a static, callsite-unique identifier (name + source location).
//! - **[`Tag`]** — an optional value that further distinguishes spans with the same `SpanId` (e.g.,
//!   a transaction index).
//! - **[`ProfileGuard`]** — an RAII guard returned by [`Profiler::begin_timed_span`]. Dropping the
//!   guard ends the span and records elapsed wall and CPU time.
//! - **[`ProfileStats`]** — the collected metrics tree, retrieved via [`Profiler::take_results`].
//!
//! ## Threading model
//!
//! All state is **thread-local** — no cross-thread synchronisation on the hot path.
//! The only process-global state is [`Profiler::enable_record`] / [`Profiler::disable_record`]
//! (an [`AtomicBool`] kill-switch for record/counter attachment).
//!
//! ## Typical usage
//!
//! Most code should instrument using the [`span!`](span), [`measure!`](measure), or
//! [`#[profile]`](profile) macros rather than calling [`Profiler`] methods directly.
//!
//! ```rust
//! use stacks_profiler::{measure, Profiler};
//!
//! measure!("my_work", {
//!     // ... timed ...
//! });
//!
//! let results = Profiler::take_results().expect("take profiler results");
//! for root in &results {
//!     root.print_tree();
//! }
//! ```
//!
//! ```compile_fail
//! use stacks_profiler::profile;
//!
//! #[profile]
//! async fn async_not_supported() {}
//! ```
//!
//! `#[profile]` rejects `async fn` because a function-wide async span would hold the thread-local
//! guard across `.await`. Use [`span!`](span) or [`measure!`](measure) around synchronous regions
//! between await points instead.

use std::cell::{Cell, RefCell};
use std::fmt;
use std::marker::PhantomData;
use std::panic::Location;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// Re-exported procedural macro.
pub use stacks_profiler_macros::profile;

mod macros;
mod platform;
mod state;
mod types;

pub mod print;

use state::*;
pub use types::*;

/// Process-global kill-switch for record/counter attachment. Span timing is unaffected.
static RECORD_ENABLED: AtomicBool = AtomicBool::new(true);

thread_local! {
    /// Per-thread profiler state (arena + stack).
    static STATE: RefCell<ThreadState> = RefCell::new(ThreadState::new());
}

thread_local! {
    /// Suppression nesting depth. Separate from [`STATE`] to avoid borrowing the `RefCell`.
    ///
    /// Invariant: `begin_suppression` always pairs with `end_suppression`; underflow on misuse
    /// saturates at 0 rather than wrapping (which would suppress the thread effectively forever).
    static SUPPRESS_DEPTH: Cell<u32> = const { Cell::new(0) };
}

thread_local! {
    /// Thread-local string interner for [`Tag::Str`] values from owned `String`s.
    /// Strings are leaked once and reused for the thread's lifetime, keeping [`Tag`] `Copy`.
    static TAG_INTERNER: RefCell<rapidhash::RapidHashMap<&'static str, &'static str>> =
        RefCell::new(rapidhash::HashMapExt::with_capacity(64));
}

/// Intern a `String` into a `&'static str` via the thread-local interner.
/// Repeated calls with the same content return the same pointer.
#[inline]
fn intern_tag_str(s: String) -> &'static str {
    TAG_INTERNER.with(|cell| {
        let mut map = cell.borrow_mut();
        if let Some(&interned) = map.get(s.as_str()) {
            return interned;
        }
        let boxed: Box<str> = s.into_boxed_str();
        let leaked: &'static str = Box::leak(boxed);
        map.insert(leaked, leaked);
        leaked
    })
}

/// A static, callsite-unique identifier for a profiling span.
///
/// Created once per callsite (via `OnceLock` inside [`span!`](span) / [`#[profile]`](profile))
/// and reused on every subsequent invocation. Equality checks pointer identity first, then falls
/// back to content comparison.
#[derive(Debug, Copy, Clone, Eq, Hash)]
#[allow(clippy::derived_hash_with_manual_eq)] // Manual PartialEq is semantically equivalent
pub struct SpanId {
    /// Human-readable span name (e.g., `"execute_tx"`).
    pub name: &'static str,
    /// Optional context qualifier, typically the module path.
    pub context: Option<&'static str>,
    /// Source file where the span was defined.
    pub file: &'static str,
    /// Source line where the span was defined.
    pub line: u32,
}

impl PartialEq for SpanId {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        // Optimization: Pointer equality check first.
        if std::ptr::eq(self.name, other.name)
            && std::ptr::eq(self.file, other.file)
            && self.line == other.line
        {
            match (self.context, other.context) {
                (Some(a), Some(b)) => std::ptr::eq(a, b),
                (None, None) => true,
                _ => false,
            }
        } else {
            self.name == other.name
                && self.file == other.file
                && self.line == other.line
                && self.context == other.context
        }
    }
}

impl SpanId {
    /// Create a `SpanId` from static strings and a caller [`Location`].
    #[inline(always)]
    fn new_from_loc(name: &'static str, loc: &'static Location) -> Self {
        Self {
            name,
            context: None,
            file: loc.file(),
            line: loc.line(),
        }
    }

    /// Attach a context qualifier (typically the module path).
    #[inline(always)]
    pub fn with_context(mut self, context: &'static str) -> Self {
        self.context = Some(context);
        self
    }
}

/// Collected metrics for one node in the profiling tree.
///
/// Each node aggregates timing from every sampled entry of the same `(SpanId, Tag)` pair under
/// the same parent. The tree mirrors the dynamic call structure observed at runtime.
#[derive(Debug, Clone)]
pub struct ProfileStats {
    /// The callsite identity.
    pub id: &'static SpanId,
    /// Optional discriminator (see [`Tag`]).
    pub tag: Option<Tag>,
    /// Cumulative wall-clock time (nanoseconds) across all sampled entries.
    pub wall_time_ns: u64,
    /// Cumulative CPU time (nanoseconds) across all sampled entries.
    pub cpu_time_ns: u64,
    /// Child nodes in the call tree.
    pub children: Vec<ProfileStats>,
    /// Total number of times this span was entered (sampled **and** count-only).
    pub entered_count: usize,
    /// Number of entries that were fully timed (a subset of [`Self::entered_count`]).
    pub sampled_count: usize,
    /// Per-occurrence key/value records (see [`record!`](record)).
    pub records: Vec<Record>,
    /// Aggregated counters (see [`counter_add!`](counter_add)).
    pub counters: Vec<Counter>,
}

/// Error returned when profile results cannot be drained into a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakeResultsError {
    /// Results were requested while spans are still active on this thread.
    ActiveSpans { active: usize },
    /// A root or child pointed at a node id outside the arena.
    MissingNode { node_id: u32 },
    /// A node was reachable more than once, which would make materialization ambiguous.
    DuplicateNodeReference { node_id: u32 },
}

impl fmt::Display for TakeResultsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TakeResultsError::ActiveSpans { active } => {
                write!(f, "take_results called with {active} active span(s)")
            }
            TakeResultsError::MissingNode { node_id } => {
                write!(f, "profile tree references missing node {node_id}")
            }
            TakeResultsError::DuplicateNodeReference { node_id } => {
                write!(f, "profile tree references node {node_id} more than once")
            }
        }
    }
}

impl std::error::Error for TakeResultsError {}

impl ProfileStats {
    /// Span name (e.g., `"execute_tx"`).
    pub fn name(&self) -> &'static str {
        self.id.name
    }

    /// Module-path context, if set.
    pub fn context(&self) -> Option<&'static str> {
        self.id.context
    }

    /// Source file where the span was defined.
    pub fn source_file(&self) -> &'static str {
        self.id.file
    }

    /// Source line where the span was defined.
    pub fn source_line(&self) -> u32 {
        self.id.line
    }

    /// The optional [`Tag`] discriminator.
    pub fn tag(&self) -> Option<&Tag> {
        self.tag.as_ref()
    }

    /// Total times this span was entered (sampled + count-only).
    pub fn count(&self) -> usize {
        self.entered_count
    }

    /// Estimated idle time (wall − CPU). See [`platform`] for resolution caveats.
    pub fn wait_time(&self) -> Duration {
        Duration::from_nanos(self.wait_time_ns())
    }

    /// Cumulative wall-clock time as a [`Duration`].
    pub fn wall_time(&self) -> Duration {
        Duration::from_nanos(self.wall_time_ns)
    }

    /// Cumulative CPU time as a [`Duration`].
    pub fn cpu_time(&self) -> Duration {
        Duration::from_nanos(self.cpu_time_ns)
    }

    /// Wait time in nanoseconds (convenience for `wall - cpu`).
    pub fn wait_time_ns(&self) -> u64 {
        self.wall_time_ns.saturating_sub(self.cpu_time_ns)
    }

    /// Wall-clock time truncated to whole microseconds.
    pub fn wall_time_micros(&self) -> u64 {
        self.wall_time_ns / 1_000
    }

    /// CPU time truncated to whole microseconds.
    pub fn cpu_time_micros(&self) -> u64 {
        self.cpu_time_ns / 1_000
    }

    /// Print the tree to stdout using the built-in [`PrettyPrinter`](crate::print::PrettyPrinter).
    pub fn print_tree(&self) {
        crate::print::print_tree(self, &crate::print::PrettyPrinter);
    }

    /// Print the tree to stdout using a custom [`TreeFormatter`](crate::print::TreeFormatter).
    pub fn print_with<F: crate::print::TreeFormatter>(&self, formatter: &F) {
        crate::print::print_tree(self, formatter);
    }
}

/// Static entry-point for all profiler operations.
///
/// Most users should prefer the [`span!`](span), [`measure!`](measure), and [`#[profile]`](profile)
/// macros over calling these methods directly.
///
/// The hidden `begin_*` helpers are stack operations used by the macros. Returned guards must be
/// dropped in strict LIFO order; manual out-of-order drops can corrupt the per-thread active span
/// stack.
pub struct Profiler;

impl Profiler {
    /// Create a new [`SpanId`] anchored at the caller's source location.
    ///
    /// Typically called once per callsite inside a [`OnceLock`](std::sync::OnceLock); the macros
    /// handle this automatically.
    #[doc(hidden)]
    #[inline(always)]
    #[track_caller]
    pub fn new_span_id(name: &'static str) -> SpanId {
        let loc = Location::caller();
        SpanId::new_from_loc(name, loc)
    }

    /// Begin a **timed** span.  Wall and CPU clocks are read on entry; elapsed time is accumulated
    /// when the returned guard is dropped.
    #[doc(hidden)]
    #[must_use = "the returned guard must be kept alive for the span's duration"]
    #[inline]
    pub fn begin_timed_span(id: &'static SpanId, tag: Option<Tag>) -> ProfileGuard {
        let start_wall = Instant::now();
        let start_cpu_ns = crate::platform::thread_cpu_nanos();

        STATE.with(|cell| {
            let mut st = cell.borrow_mut();
            let node = st.resolve_node(id, tag);
            st.stack.push(ActiveFrame {
                node,
                kind: ActiveKind::Timed {
                    start_wall,
                    start_cpu_ns,
                },
            });
        });

        ProfileGuard {
            kind: GuardKind::TimedSpan,
            _not_send: PhantomData,
        }
    }

    /// Begin a **count-only** span — preserves hierarchy and increments [`Node::entered_count`],
    /// but does **not** read clocks.
    #[doc(hidden)]
    #[must_use = "the returned guard must be kept alive for the span's duration"]
    #[inline]
    pub fn begin_count_only_span(id: &'static SpanId, tag: Option<Tag>) -> ProfileGuard {
        STATE.with(|cell| {
            let mut st = cell.borrow_mut();
            let node = st.resolve_node(id, tag);
            st.stack.push(ActiveFrame {
                node,
                kind: ActiveKind::CountOnly,
            });
        });

        ProfileGuard {
            kind: GuardKind::CountOnlySpan,
            _not_send: PhantomData,
        }
    }

    /// Enter a **suppression** region.  While suppressed, nested
    /// [`span!`](span)/[`measure!`](measure) calls return [`None`] (no-op), preventing children
    /// from attaching to the wrong parent.
    #[doc(hidden)]
    #[must_use = "the returned guard must be kept alive for the suppression region's duration"]
    #[inline(always)]
    pub fn begin_suppression() -> ProfileGuard {
        SUPPRESS_DEPTH.with(|d| {
            let depth = d.get();
            debug_assert!(depth < u32::MAX, "begin_suppression overflow");
            d.set(depth.saturating_add(1));
        });

        ProfileGuard {
            kind: GuardKind::Suppression,
            _not_send: PhantomData,
        }
    }

    #[doc(hidden)]
    #[must_use = "span guard is dropped immediately unless bound; assign it to a variable for the span duration"]
    #[inline(always)]
    pub fn must_use_span_guard(guard: Option<ProfileGuard>) -> Option<ProfileGuard> {
        guard
    }

    /// Ends a timed span, updating the node's cumulative wall and CPU time with the elapsed
    /// duration.
    ///
    /// ## Design Notes
    ///
    /// * Clock-probe placement is intentionally asymmetric with `begin_timed_span`: begin reads
    ///   clocks before entering the TLS borrow, while end reads them inside the borrow. This causes
    ///   each child span to absorb more of its own begin/end bookkeeping overhead instead of
    ///   shifting that overhead into the parent's derived self-time, where it would scale with the
    ///   number of child spans.
    /// * Tracking exclusive self-time directly inside the profiler would remove this trade-off, but
    ///   it would require additional clock probes or bookkeeping on every span. This implementation
    ///   keeps the hot path smaller and leaves self-time derivation to downstream tooling.
    /// * Duration arithmetic is done online when the span ends. Because entries for the same
    ///   `(SpanId, Tag)` at the same call-tree path aggregate into one node, storing raw timings
    ///   would require per-sampled-entry storage, making memory usage (and allocator work) scale
    ///   with sampled entries rather than unique profile nodes.
    #[inline]
    #[doc(hidden)]
    pub fn end_timed_span() {
        STATE.with(|cell| {
            let mut st = cell.borrow_mut();
            let Some(frame) = st.stack.pop() else {
                return;
            };

            let ActiveKind::Timed {
                start_wall,
                start_cpu_ns,
            } = frame.kind
            else {
                // Timed frames carry the start clocks needed to finish timing. A mismatch means
                // guards were dropped out of LIFO order or mixed incorrectly.
                //
                // * Debug-only: panic to catch instrumentation bugs early.
                // * Release fallback: do nothing because non-timed frames do not carry the start
                //   clocks needed to record elapsed time.
                debug_assert!(false, "timed guard ended an incompatible span");
                return;
            };

            // Intentionally resolved prior to reading end clocks so that the cost is captured in
            // this span's wall_ns instead of leaking into the parent's derived self-time.
            let node = st.node_mut(frame.node);

            let end_wall = Instant::now();
            let end_cpu_ns = crate::platform::thread_cpu_nanos();

            let wall_ns = end_wall.duration_since(start_wall).as_nanos() as u64;
            let cpu_ns = end_cpu_ns.saturating_sub(start_cpu_ns);

            node.wall_time_ns += wall_ns;
            node.cpu_time_ns += cpu_ns;
            node.entered_count += 1;
            node.sampled_count += 1;
        });
    }

    /// Ends a count-only span, incrementing its entered count without reading clocks.
    #[inline]
    #[doc(hidden)]
    pub fn end_count_only_span() {
        STATE.with(|cell| {
            let mut st = cell.borrow_mut();
            let Some(frame) = st.stack.pop() else {
                return;
            };

            // Count-only frames do not carry clocks, but for symmetry with `end_timed_span` we
            // still require them to be ended by a matching guard. On mismatch, debug builds panic
            // and release builds return without mutating the wrong node.
            let ActiveKind::CountOnly = frame.kind else {
                debug_assert!(false, "count-only guard ended an incompatible span");
                return;
            };

            let node = st.node_mut(frame.node);
            node.entered_count += 1;
        });
    }

    #[doc(hidden)]
    #[inline(always)]
    pub fn is_suppressed() -> bool {
        SUPPRESS_DEPTH.with(|d| d.get() != 0)
    }

    #[inline(always)]
    #[doc(hidden)]
    pub fn end_suppression() {
        SUPPRESS_DEPTH.with(|d| {
            let depth = d.get();
            debug_assert!(depth > 0, "end_suppression underflow: depth already zero");
            d.set(depth.saturating_sub(1));
        });
    }

    /// Enable record/counter attachment (**process-global** default: enabled).
    #[inline(always)]
    pub fn enable_record() {
        RECORD_ENABLED.store(true, Ordering::Relaxed);
    }

    /// Disable record/counter attachment process-wide.  Spans and timing are unaffected — only
    /// [`record!`](record) and [`counter_add!`](counter_add) become no-ops.
    #[inline(always)]
    pub fn disable_record() {
        RECORD_ENABLED.store(false, Ordering::Relaxed);
    }

    /// Returns `true` if record/counter attachment is currently enabled.
    #[inline(always)]
    pub fn is_record_enabled() -> bool {
        RECORD_ENABLED.load(Ordering::Relaxed)
    }

    /// Attach a key/value [`Record`] to the innermost active span on this thread.  No-op if
    /// recording is disabled, suppressed, or no span is active.
    #[inline]
    pub fn record(key: &'static str, value: RecordValue) {
        if !Self::is_record_enabled() || Self::is_suppressed() {
            return;
        }

        STATE.with(|cell| {
            let mut st = cell.borrow_mut();
            let (node_id, is_count_only) = match st.stack.last() {
                Some(frame) => (frame.node, matches!(frame.kind, ActiveKind::CountOnly)),
                None => return,
            };

            // Skip count-only spans (no timing) to avoid noisy data.
            if is_count_only {
                return;
            }

            let node = st.node_mut(node_id);
            node.records.push(Record { key, value });
        });
    }

    /// Add `delta` to the named [`Counter`] on the innermost active span. Counters with the same
    /// key are summed (saturating).
    #[inline]
    pub fn counter_add(key: &'static str, delta: u64) {
        if !Self::is_record_enabled() || Self::is_suppressed() {
            return;
        }

        STATE.with(|cell| {
            let mut st = cell.borrow_mut();
            let (node_id, is_count_only) = match st.stack.last() {
                Some(frame) => (frame.node, matches!(frame.kind, ActiveKind::CountOnly)),
                None => return,
            };

            if is_count_only {
                return;
            }

            let node = st.node_mut(node_id);
            if let Some(counter) = node.counters.iter_mut().find(|c| c.key == key) {
                counter.value = counter.value.saturating_add(delta);
            } else {
                node.counters.push(Counter { key, value: delta });
            }
        });
    }

    /// Drain the calling thread's profile tree (one entry per root span) and reset state.
    ///
    /// Returns an error if spans are still active or the internal arena cannot be materialized
    /// into a tree. Active-span errors leave state intact so callers can drop the guard and retry;
    /// arena materialization errors discard the broken state while returning the error.
    #[inline]
    pub fn take_results() -> Result<Vec<ProfileStats>, TakeResultsError> {
        STATE.with(|cell| cell.borrow_mut().take_results_and_reset())
    }

    /// Discard all accumulated data on the calling thread without returning it.
    #[inline]
    pub fn clear() {
        STATE.with(|cell| cell.borrow_mut().clear())
    }
}

/// Discriminates the RAII guard variants for [`Drop`] dispatch.
enum GuardKind {
    /// Timed span — ends timing and records elapsed wall/CPU time.
    TimedSpan,
    /// Count-only span — updates counts without reading clocks.
    CountOnlySpan,
    /// Suppression region — calls [`Profiler::end_suppression()`] on drop.
    Suppression,
}

/// RAII guard that ends a span (or suppression region) when dropped.
///
/// A guard does not carry a unique token for the frame it created; `Drop` ends the current
/// top-of-stack frame for this thread. The public macros produce strict LIFO drops naturally.
/// Manual use of the hidden `Profiler::begin_*` helpers must preserve that invariant.
///
/// Intentionally `!Send + !Sync` — its `Drop` operates on thread-local state.
///
/// ```compile_fail,E0277
/// fn assert_send<T: Send>() {}
/// assert_send::<stacks_profiler::ProfileGuard>();
/// ```
///
/// ```compile_fail,E0277
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<stacks_profiler::ProfileGuard>();
/// ```
#[must_use = "span ends when this guard is dropped; bind it to keep the span active"]
pub struct ProfileGuard {
    kind: GuardKind,
    _not_send: PhantomData<*const ()>,
}

impl Drop for ProfileGuard {
    #[inline]
    fn drop(&mut self) {
        match self.kind {
            GuardKind::TimedSpan => Profiler::end_timed_span(),
            GuardKind::CountOnlySpan => Profiler::end_count_only_span(),
            GuardKind::Suppression => Profiler::end_suppression(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Profiler, SpanId, TakeResultsError};

    static NAME: &str = "span";
    static OTHER_NAME: &str = "other";
    static FILE: &str = "file.rs";
    static OTHER_FILE: &str = "other.rs";
    static CONTEXT: &str = "context";
    static OTHER_CONTEXT: &str = "other_context";

    fn span_id(
        name: &'static str,
        context: Option<&'static str>,
        file: &'static str,
        line: u32,
    ) -> SpanId {
        SpanId {
            name,
            context,
            file,
            line,
        }
    }

    #[test]
    fn span_id_equality_handles_pointer_fast_path_and_fallback() {
        let fallback_name: &'static str = Box::leak(String::from("span").into_boxed_str());
        let fallback_file: &'static str = Box::leak(String::from("file.rs").into_boxed_str());
        let fallback_context: &'static str = Box::leak(String::from("context").into_boxed_str());

        assert_eq!(
            span_id(NAME, Some(CONTEXT), FILE, 1),
            span_id(NAME, Some(CONTEXT), FILE, 1)
        );
        assert_eq!(span_id(NAME, None, FILE, 1), span_id(NAME, None, FILE, 1));
        assert_ne!(
            span_id(NAME, Some(CONTEXT), FILE, 1),
            span_id(NAME, None, FILE, 1)
        );
        assert_eq!(
            span_id(NAME, Some(CONTEXT), FILE, 1),
            span_id(fallback_name, Some(fallback_context), fallback_file, 1)
        );
        assert_ne!(
            span_id(NAME, Some(CONTEXT), FILE, 1),
            span_id(OTHER_NAME, Some(CONTEXT), FILE, 1)
        );
        assert_ne!(
            span_id(NAME, Some(CONTEXT), FILE, 1),
            span_id(NAME, Some(CONTEXT), OTHER_FILE, 1)
        );
        assert_ne!(
            span_id(NAME, Some(CONTEXT), FILE, 1),
            span_id(NAME, Some(CONTEXT), FILE, 2)
        );
        assert_ne!(
            span_id(NAME, Some(CONTEXT), FILE, 1),
            span_id(NAME, Some(OTHER_CONTEXT), FILE, 1)
        );
    }

    #[test]
    fn take_results_error_display_messages() {
        assert_eq!(
            TakeResultsError::ActiveSpans { active: 2 }.to_string(),
            "take_results called with 2 active span(s)"
        );
        assert_eq!(
            TakeResultsError::MissingNode { node_id: 7 }.to_string(),
            "profile tree references missing node 7"
        );
        assert_eq!(
            TakeResultsError::DuplicateNodeReference { node_id: 7 }.to_string(),
            "profile tree references node 7 more than once"
        );
    }

    #[test]
    fn hidden_end_helpers_tolerate_empty_stacks() {
        Profiler::clear();
        Profiler::end_timed_span();
        Profiler::end_count_only_span();
    }
}
