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

//! Allocation/timing micro-benchmarks for `TrieNodePatch` creation/application/codec paths.
//!
//! This harness focuses on the parts of Patch-node behavior that matter most in a hot MARF:
//! frequent short-diff construction, compact encoding/decoding, and fast application back onto
//! `TrieNode256` state during read/write-heavy flows.
//!
//! What is measured (for each configured diff size):
//! - `patch_from_node256_diff=*`: cost to build a patch from old/new `TrieNode256` snapshots.
//! - `patch_size_diff=*`: size accounting cost used by serialization/allocation planning.
//! - `patch_serialize_diff=*`: consensus-encoding throughput and allocator pressure.
//! - `patch_deserialize_diff=*`: consensus-decoding throughput and allocator pressure.
//! - `patch_apply_node256_diff=*`: cost to materialize updated node state from a patch.
//! - `patch_try_from_patch_diff=*`: incremental patch-from-patch transition cost.
//!
//! Why this maps to production behavior:
//! - Patch nodes are a compression/diff representation, so performance scales primarily with
//!   pointer-diff cardinality (`PATCH_DIFFS`), not full-node width.
//! - Real MARF workloads repeatedly exercise create/encode/decode/apply loops under cache misses,
//!   proof construction, and commit paths; these microbench cases isolate those costs.
//! - Reported allocation counters plus elapsed time make it easier to detect regressions in both
//!   latency and memory churn as Patch-node internals evolve.

use std::hint::black_box;
use std::time::Instant;

use blockstack_lib::chainstate::stacks::index::node::{
    is_backptr, set_backptr, TrieNode256, TrieNodeID, TrieNodePatch, TriePtr,
};
use blockstack_lib::codec::StacksMessageCodec;

#[path = "../marf/allocator.rs"]
mod allocator;

const DEFAULT_ITERS: usize = 40_000;
const DEFAULT_ROUNDS: usize = 1;
const DEFAULT_DIFFS: [usize; 4] = [1, 4, 16, 64];
const PATCH_OLD_PTR: TriePtr = TriePtr {
    id: 0x85,
    chr: 0,
    ptr: 777,
    back_block: 123,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    Summary,
    Raw,
}

impl OutputMode {
    fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }
}

#[derive(Clone, Debug)]
struct SummaryLine {
    pub name: String,
    pub total_ms: f64,
    pub alloc_count: u64,
    pub alloc_bytes: u64,
}

#[derive(Clone, Debug)]
struct Summary {
    pub title: &'static str,
    pub lines: Vec<SummaryLine>,
}

impl Summary {
    fn new(title: &'static str, capacity: usize) -> Self {
        Self {
            title,
            lines: Vec::with_capacity(capacity),
        }
    }

    fn push_line(
        &mut self,
        name: impl Into<String>,
        total_ms: f64,
        alloc_count: u64,
        alloc_bytes: u64,
    ) {
        self.lines.push(SummaryLine {
            name: name.into(),
            total_ms,
            alloc_count,
            alloc_bytes,
        });
    }
}

#[derive(Clone, Copy)]
struct CaseStats {
    alloc_calls: u64,
    alloc_bytes: u64,
    elapsed_ms: f64,
}

fn parse_output_mode() -> OutputMode {
    match std::env::var("OUTPUT_FORMAT").ok().as_deref() {
        Some("raw") => OutputMode::Raw,
        _ => OutputMode::Summary,
    }
}

fn has_help_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "-h" || arg == "--help")
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(default)
}

fn parse_csv_usize_env(name: &str, default: &[usize]) -> Vec<usize> {
    let Some(raw) = std::env::var(name).ok() else {
        return default.to_vec();
    };

    let parsed: Vec<usize> = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid {name} integer entry: '{item}'"))
        })
        .collect();

    assert!(!parsed.is_empty(), "{name} must contain at least one value");
    parsed
}

#[rustfmt::skip]
fn print_usage() {
    println!("marf-patch: TrieNodePatch compression microbench");
    println!();
    println!("Usage:");
    println!("  cargo bench -p stackslib --bench marf-patch -- [--help]");
    println!();
    println!("Environment Variables:");
    println!("  ITERS           Iterations per measured case [default: {DEFAULT_ITERS}]");
    println!("  ROUNDS          Independent repetitions per case [default: {DEFAULT_ROUNDS}]");
    println!("  PATCH_DIFFS     Comma-separated patch diff sizes [default: 1,4,16,64]");
    println!("                  Must be in range 1..=255 and unique");
    println!("  OUTPUT_FORMAT   Output mode [default: summary]");
    println!("                  'summary': unified summary lines only");
    println!("                  'raw': detailed per-case lines + unified summary lines");
    println!();
    println!("Output Lines:");
    println!("  summary         Unified summary lines emitted by marf-patch main");
}

fn run_case<F>(name: &str, mode: OutputMode, mut f: F) -> CaseStats
where
    F: FnMut(),
{
    allocator::reset_stats();
    let start = Instant::now();
    f();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let stats = allocator::snapshot();

    if mode.is_raw() {
        println!(
            "{name}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\telapsed_ms={:.2}",
            stats.alloc_calls,
            stats.alloc_bytes,
            stats.realloc_calls,
            stats.dealloc_calls,
            stats.dealloc_bytes,
            elapsed_ms
        );
    }

    CaseStats {
        alloc_calls: stats.alloc_calls,
        alloc_bytes: stats.alloc_bytes,
        elapsed_ms,
    }
}

fn record_case<F>(summary: &mut Summary, name: &str, mode: OutputMode, rounds: usize, mut f: F)
where
    F: FnMut(),
{
    let mut total_ms = 0.0;
    let mut total_alloc_calls = 0u64;
    let mut total_alloc_bytes = 0u64;

    for round in 0..rounds {
        let raw_name;
        let case_name = if rounds > 1 {
            raw_name = format!("{name}#round={}", round + 1);
            raw_name.as_str()
        } else {
            name
        };

        let stats = run_case(case_name, mode, &mut f);
        total_ms += stats.elapsed_ms;
        total_alloc_calls = total_alloc_calls.saturating_add(stats.alloc_calls);
        total_alloc_bytes = total_alloc_bytes.saturating_add(stats.alloc_bytes);
    }

    summary.push_line(name, total_ms, total_alloc_calls, total_alloc_bytes);
}

fn parse_patch_diffs() -> Vec<usize> {
    let diffs = parse_csv_usize_env("PATCH_DIFFS", &DEFAULT_DIFFS);
    let mut prev = None;
    for value in &diffs {
        assert!(
            *value > 0 && *value <= 255,
            "PATCH_DIFFS entries must be in range 1..=255"
        );
        if let Some(last) = prev {
            assert!(*value != last, "PATCH_DIFFS entries must be unique");
        }
        prev = Some(*value);
    }
    diffs
}

fn make_base_node(path: &[u8], existing_children: usize) -> TrieNode256 {
    assert!(existing_children <= 255);

    let mut node = TrieNode256::new(path);
    for idx in 0..existing_children {
        let chr = idx as u8;
        node.ptrs[idx] = TriePtr::new(TrieNodeID::Leaf as u8, chr, (idx as u32) + 1);
    }
    node
}

fn make_new_node_with_extra_ptrs(
    base: &TrieNode256,
    start_chr: u8,
    count: usize,
    old_back_block: u32,
) -> TrieNode256 {
    let mut node = base.clone();

    for ptr in node.ptrs.iter_mut() {
        if ptr.id() == TrieNodeID::Empty as u8 {
            continue;
        }
        if !is_backptr(ptr.id()) {
            ptr.id = set_backptr(ptr.id());
            ptr.back_block = old_back_block;
        }
    }

    for i in 0..count {
        let chr = start_chr.wrapping_add(i as u8);
        let mut ptr = TriePtr::new(set_backptr(TrieNodeID::Leaf as u8), chr, 10_000 + i as u32);
        ptr.back_block = old_back_block;
        node.ptrs[chr as usize] = ptr;
    }
    node
}

fn make_patch_fixture(diff_count: usize) -> (TrieNode256, TrieNodePatch, Vec<u8>) {
    let path: [u8; 32] = std::array::from_fn(|i| i as u8);
    let base = make_base_node(&path, 64);
    let next = make_new_node_with_extra_ptrs(&base, 128, diff_count, PATCH_OLD_PTR.back_block);

    let patch = TrieNodePatch::from_node256(PATCH_OLD_PTR, &base, &next);
    assert_eq!(patch.ptr_diff.len(), diff_count);
    assert!(is_backptr(patch.ptr.id()));

    let mut encoded = Vec::with_capacity(patch.size());
    patch
        .consensus_serialize(&mut encoded)
        .expect("serialize TrieNodePatch fixture");

    (base, patch, encoded)
}

fn print_summary(summary: &Summary) {
    println!("summary\tbenchmark\tname\ttotal_ms\talloc_count\talloc_bytes");
    for line in &summary.lines {
        println!(
            "summary\t{}\t{}\t{:.3}\t{}\t{}",
            summary.title, line.name, line.total_ms, line.alloc_count, line.alloc_bytes
        );
    }
}

fn main() {
    // SAFETY: This is the first operation in process startup, before threads or FFI that may
    // consult environment variables.
    unsafe {
        std::env::set_var("STACKS_LOG_CRITONLY", "1");
    }

    let args: Vec<String> = std::env::args().collect();
    if has_help_flag(&args[1..]) {
        print_usage();
        return;
    }

    let output_mode = parse_output_mode();
    let iters = parse_usize_env("ITERS", DEFAULT_ITERS);
    let rounds = parse_usize_env("ROUNDS", DEFAULT_ROUNDS);
    assert!(iters > 0, "ITERS must be > 0");
    assert!(rounds > 0, "ROUNDS must be > 0");

    let diff_sizes = parse_patch_diffs();
    if output_mode.is_raw() {
        println!("iters={iters}\trounds={rounds}\tpatch_diffs={diff_sizes:?}");
    }

    let mut summary = Summary::new("patch", diff_sizes.len() * 6);

    for diff_count in diff_sizes {
        let (base, patch, encoded) = make_patch_fixture(diff_count);

        record_case(
            &mut summary,
            &format!("patch_from_node256_diff={diff_count}"),
            output_mode,
            rounds,
            || {
                for _ in 0..iters {
                    let next = make_new_node_with_extra_ptrs(
                        &base,
                        128,
                        diff_count,
                        PATCH_OLD_PTR.back_block,
                    );
                    black_box(TrieNodePatch::from_node256(PATCH_OLD_PTR, &base, &next));
                }
            },
        );

        record_case(
            &mut summary,
            &format!("patch_size_diff={diff_count}"),
            output_mode,
            rounds,
            || {
                for _ in 0..iters {
                    black_box(patch.size());
                }
            },
        );

        record_case(
            &mut summary,
            &format!("patch_serialize_diff={diff_count}"),
            output_mode,
            rounds,
            || {
                for _ in 0..iters {
                    let mut out = Vec::with_capacity(patch.size());
                    patch
                        .consensus_serialize(&mut out)
                        .expect("serialize patch in benchmark");
                    black_box(out.len());
                }
            },
        );

        record_case(
            &mut summary,
            &format!("patch_deserialize_diff={diff_count}"),
            output_mode,
            rounds,
            || {
                for _ in 0..iters {
                    let mut cursor = std::io::Cursor::new(encoded.as_slice());
                    black_box(
                        <TrieNodePatch as StacksMessageCodec>::consensus_deserialize(&mut cursor)
                            .expect("deserialize patch in benchmark"),
                    );
                }
            },
        );

        record_case(
            &mut summary,
            &format!("patch_apply_node256_diff={diff_count}"),
            output_mode,
            rounds,
            || {
                for _ in 0..iters {
                    black_box(
                        patch
                            .apply_node256(base.clone(), 777, 888)
                            .expect("apply patch to node256"),
                    );
                }
            },
        );

        record_case(
            &mut summary,
            &format!("patch_try_from_patch_diff={diff_count}"),
            output_mode,
            rounds,
            || {
                for _ in 0..iters {
                    let mut next =
                        make_new_node_with_extra_ptrs(&base, 128, 0, PATCH_OLD_PTR.back_block);
                    let promote_chr = 220u8;
                    let mut promote_ptr =
                        TriePtr::new(set_backptr(TrieNodeID::Leaf as u8), promote_chr, 90_000);
                    promote_ptr.back_block = PATCH_OLD_PTR.back_block;
                    next.ptrs[promote_chr as usize] = promote_ptr;

                    black_box(
                        TrieNodePatch::try_from_patch(
                            PATCH_OLD_PTR,
                            &patch,
                            &blockstack_lib::chainstate::stacks::index::node::TrieNodeType::Node256(
                                Box::new(next),
                            ),
                        )
                        .expect("try_from_patch should produce non-empty diff"),
                    );
                }
            },
        );
    }

    print_summary(&summary);
}
