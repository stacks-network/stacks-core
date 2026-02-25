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
//! This harness focuses on the parts of Patch-node behavior which have most meaning in hot loops.
//!
//! What is measured (for each configured diff size):
//! - `patch_from_node{4|16|48|256}_diff=*`: cost to build a patch from old/new node snapshots.
//! - `patch_size_diff=*`: size accounting cost used by serialization/allocation planning.
//! - `patch_serialize_diff=*`: consensus-encoding throughput and allocator pressure.
//! - `patch_deserialize_diff=*`: consensus-decoding throughput and allocator pressure.
//! - `patch_apply_node{4|16|48|256}_diff=*`: cost to materialize updated node state from a patch.
//! - `patch_try_from_patch_node{4|16|48|256}_diff=*`: incremental patch-from-patch transition cost.

use std::hint::black_box;
use std::time::Instant;

use blockstack_lib::chainstate::stacks::index::node::{
    is_backptr, set_backptr, TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeID,
    TrieNodePatch, TrieNodeType, TriePtr,
};
use blockstack_lib::codec::StacksMessageCodec;

#[path = "../marf/allocator.rs"]
mod allocator;

/// Default number of loop iterations per benchmark case.
const DEFAULT_ITERS: usize = 40_000;
/// Default number of repeated rounds per benchmark case.
const DEFAULT_ROUNDS: usize = 1;
/// Default patch diff cardinalities to benchmark.
const DEFAULT_DIFFS: [usize; 4] = [1, 4, 16, 64];
/// Default set of trie node fanout variants covered by the harness.
const DEFAULT_NODE_TYPES: [NodeBenchType; 4] = [
    NodeBenchType::Node4,
    NodeBenchType::Node16,
    NodeBenchType::Node48,
    NodeBenchType::Node256,
];
/// Synthetic `chr` used for fixture patch-old pointers.
const PATCH_OLD_PTR_CHR: u8 = 0;
/// Synthetic pointer offset used for fixture patch-old pointers.
const PATCH_OLD_PTR_OFFSET: u32 = 777;
/// Synthetic back-block id used to keep fixture pointers in backptr mode.
const PATCH_OLD_BACK_BLOCK: u32 = 123;

/// Output style emitted by the harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    /// Emit only normalized summary rows.
    Summary,
    /// Emit per-case raw lines in addition to summary rows.
    Raw,
}

impl OutputMode {
    /// Return `true` when verbose/raw case rows should be printed.
    fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }
}

/// Single summary row for a benchmark case.
#[derive(Clone, Debug)]
struct SummaryLine {
    pub name: String,
    pub total_ms: f64,
    pub alloc_count: u64,
    pub alloc_bytes: u64,
}

/// Collection of summary rows for one benchmark family.
#[derive(Clone, Debug)]
struct Summary {
    pub title: &'static str,
    pub lines: Vec<SummaryLine>,
}

impl Summary {
    /// Create a new summary with pre-allocated row capacity.
    fn new(title: &'static str, capacity: usize) -> Self {
        Self {
            title,
            lines: Vec::with_capacity(capacity),
        }
    }

    /// Append one measured case row to the summary.
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

/// Aggregated metrics for a single timed case execution.
#[derive(Clone, Copy)]
struct CaseStats {
    alloc_calls: u64,
    alloc_bytes: u64,
    elapsed_ms: f64,
}

/// Supported trie node variants in patch microbench coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeBenchType {
    Node4,
    Node16,
    Node48,
    Node256,
}

impl NodeBenchType {
    /// Parse one `NODE_TYPES` CSV token into a node variant.
    fn parse_token(token: &str) -> Option<Self> {
        match token {
            "node4" => Some(Self::Node4),
            "node16" => Some(Self::Node16),
            "node48" => Some(Self::Node48),
            "node256" => Some(Self::Node256),
            _ => None,
        }
    }

    /// Return the lowercase label used in output row names.
    fn as_label(self) -> &'static str {
        match self {
            Self::Node4 => "node4",
            Self::Node16 => "node16",
            Self::Node48 => "node48",
            Self::Node256 => "node256",
        }
    }

    /// Return the maximum diff count representable by this node type.
    fn max_diffs(self) -> usize {
        match self {
            Self::Node4 => 4,
            Self::Node16 => 16,
            Self::Node48 => 48,
            Self::Node256 => 255,
        }
    }
}

#[rustfmt::skip]
/// Print CLI/env usage help for the patch harness.
fn print_usage() {
    println!("marf-patch: TrieNodePatch compression microbench");
    println!();
    println!("Usage:");
    println!("  cargo bench -p stackslib --bench marf-patch -- [--help]");
    println!();
    println!("Environment Variables:");
    println!("  ITERS           Iterations per measured case [default: {DEFAULT_ITERS}]");
    println!("  ROUNDS          Independent repetitions per case [default: {DEFAULT_ROUNDS}]");
    println!("  NODE_TYPES      Comma-separated node types [default: all]");
    println!("                  Allowed: all,node4,node16,node48,node256");
    println!("  PATCH_DIFFS     Comma-separated patch diff sizes [default: 1,4,16,64]");
    println!("                  Must be in range 1..=255 and unique");
    println!("  OUTPUT_FORMAT   Output mode [default: summary]");
    println!("                  'summary': unified summary lines only");
    println!("                  'raw': detailed per-case lines + unified summary lines");
    println!();
    println!("Output Lines:");
    println!("  summary         Unified summary lines emitted by marf-patch main");
}

/// Parse `OUTPUT_FORMAT` and choose summary-only vs raw output.
fn parse_output_mode() -> OutputMode {
    match std::env::var("OUTPUT_FORMAT").ok().as_deref() {
        Some("raw") => OutputMode::Raw,
        _ => OutputMode::Summary,
    }
}

/// Return `true` when command-line args request usage output.
fn has_help_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "-h" || arg == "--help")
}

/// Parse a `usize` env var with fallback to the provided default.
fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(default)
}

/// Parse a CSV list of `usize` values from an env var.
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

/// Parse `NODE_TYPES` into deduplicated node variants, defaulting to all.
fn parse_node_types() -> Vec<NodeBenchType> {
    let Some(raw) = std::env::var("NODE_TYPES").ok() else {
        return DEFAULT_NODE_TYPES.to_vec();
    };

    let tokens: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect();

    assert!(
        !tokens.is_empty(),
        "NODE_TYPES must contain at least one value"
    );

    if tokens.iter().any(|token| token == "all") {
        return DEFAULT_NODE_TYPES.to_vec();
    }

    let mut parsed = Vec::new();
    for token in tokens {
        let Some(node_type) = NodeBenchType::parse_token(&token) else {
            panic!(
                "invalid NODE_TYPES entry: '{token}' (expected all,node4,node16,node48,node256)"
            );
        };
        if !parsed.contains(&node_type) {
            parsed.push(node_type);
        }
    }

    assert!(
        !parsed.is_empty(),
        "NODE_TYPES must contain at least one valid node type"
    );
    parsed
}

/// Measure one benchmark case and return allocator/time stats.
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

/// Execute a case for one or more rounds and aggregate into the summary.
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

/// Parse and validate `PATCH_DIFFS` cardinalities.
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

/// Build a leaf pointer fixture in backptr representation.
fn make_backptr_leaf(chr: u8, ptr: u32, old_back_block: u32) -> TriePtr {
    let mut node_ptr = TriePtr::new(set_backptr(TrieNodeID::Leaf as u8), chr, ptr);
    node_ptr.back_block = old_back_block;
    node_ptr
}

/// Build the synthetic old-pointer used as patch origin metadata.
fn patch_old_ptr_for(node_type: NodeBenchType) -> TriePtr {
    let node_id = match node_type {
        NodeBenchType::Node4 => TrieNodeID::Node4 as u8,
        NodeBenchType::Node16 => TrieNodeID::Node16 as u8,
        NodeBenchType::Node48 => TrieNodeID::Node48 as u8,
        NodeBenchType::Node256 => TrieNodeID::Node256 as u8,
    };

    let mut ptr = TriePtr::new(
        set_backptr(node_id),
        PATCH_OLD_PTR_CHR,
        PATCH_OLD_PTR_OFFSET,
    );
    ptr.back_block = PATCH_OLD_BACK_BLOCK;
    ptr
}

/// Normalize non-empty child pointers to backptr mode for fixture compatibility.
fn normalize_node_ptrs_to_backptr(node: &mut TrieNodeType, old_back_block: u32) {
    for ptr in node.ptrs_mut().iter_mut() {
        if ptr.id() == TrieNodeID::Empty as u8 {
            continue;
        }
        if !is_backptr(ptr.id()) {
            ptr.id = set_backptr(ptr.id());
            ptr.back_block = old_back_block;
        }
    }
}

/// Insert a pointer into any supported node variant.
fn insert_ptr(node: &mut TrieNodeType, ptr: TriePtr) {
    assert!(
        node.insert(&ptr),
        "failed to insert ptr into benchmark node"
    );
}

/// Construct an empty base node for the selected node type and path.
fn make_base_node(node_type: NodeBenchType, path: &[u8]) -> TrieNodeType {
    match node_type {
        NodeBenchType::Node4 => TrieNodeType::Node4(TrieNode4::new(path)),
        NodeBenchType::Node16 => TrieNodeType::Node16(TrieNode16::new(path)),
        NodeBenchType::Node48 => TrieNodeType::Node48(Box::new(TrieNode48::new(path))),
        NodeBenchType::Node256 => TrieNodeType::Node256(Box::new(TrieNode256::new(path))),
    }
}

/// Clone a base node and append `count` synthetic pointers for diff generation.
fn make_new_node_with_extra_ptrs(
    base: &TrieNodeType,
    start_chr: u8,
    count: usize,
    old_back_block: u32,
) -> TrieNodeType {
    let mut node = base.clone();
    normalize_node_ptrs_to_backptr(&mut node, old_back_block);

    for i in 0..count {
        let chr = start_chr.wrapping_add(i as u8);
        let ptr = make_backptr_leaf(chr, 10_000 + i as u32, old_back_block);
        insert_ptr(&mut node, ptr);
    }

    node
}

/// Apply a patch to a typed base node and return the resulting typed node.
fn apply_patch_to_base(
    patch: &TrieNodePatch,
    base: &TrieNodeType,
    patch_block_id: u32,
    cur_block_id: u32,
) -> TrieNodeType {
    match base {
        TrieNodeType::Node4(node) => TrieNodeType::Node4(
            patch
                .apply_node4(node.clone(), patch_block_id, cur_block_id)
                .expect("apply patch to node4"),
        ),
        TrieNodeType::Node16(node) => TrieNodeType::Node16(
            patch
                .apply_node16(node.clone(), patch_block_id, cur_block_id)
                .expect("apply patch to node16"),
        ),
        TrieNodeType::Node48(node) => TrieNodeType::Node48(Box::new(
            patch
                .apply_node48((**node).clone(), patch_block_id, cur_block_id)
                .expect("apply patch to node48"),
        )),
        TrieNodeType::Node256(node) => TrieNodeType::Node256(Box::new(
            patch
                .apply_node256((**node).clone(), patch_block_id, cur_block_id)
                .expect("apply patch to node256"),
        )),
        TrieNodeType::Leaf(_) => panic!("NODE_TYPES does not support leaves"),
    }
}

/// Build a reusable `(base, patch, encoded)` fixture for a node type and diff size.
fn make_patch_fixture(
    node_type: NodeBenchType,
    diff_count: usize,
) -> (TrieNodeType, TrieNodePatch, Vec<u8>) {
    let path: [u8; 32] = std::array::from_fn(|i| i as u8);
    let base = make_base_node(node_type, &path);
    let patch_old_ptr = patch_old_ptr_for(node_type);
    let next = make_new_node_with_extra_ptrs(&base, 128, diff_count, patch_old_ptr.back_block);

    let patch = TrieNodePatch::try_from_nodetype(patch_old_ptr, &base, &next)
        .expect("make patch fixture from nodetype");
    assert_eq!(patch.ptr_diff.len(), diff_count);
    assert!(is_backptr(patch.ptr.id()));

    let mut encoded = Vec::with_capacity(patch.size());
    patch
        .consensus_serialize(&mut encoded)
        .expect("serialize TrieNodePatch fixture");

    (base, patch, encoded)
}

/// Print normalized summary rows in a stable tab-separated format.
fn print_summary(summary: &Summary) {
    println!("summary\tbenchmark\tname\ttotal_ms\talloc_count\talloc_bytes");
    for line in &summary.lines {
        println!(
            "summary\t{}\t{}\t{:.3}\t{}\t{}",
            summary.title, line.name, line.total_ms, line.alloc_count, line.alloc_bytes
        );
    }
}

/// Entrypoint for `marf-patch` microbench execution.
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
    let node_types = parse_node_types();
    assert!(iters > 0, "ITERS must be > 0");
    assert!(rounds > 0, "ROUNDS must be > 0");

    let diff_sizes = parse_patch_diffs();
    if output_mode.is_raw() {
        let node_type_labels: Vec<&str> = node_types
            .iter()
            .map(|node_type| node_type.as_label())
            .collect();
        println!(
            "iters={iters}\trounds={rounds}\tnode_types={node_type_labels:?}\tpatch_diffs={diff_sizes:?}"
        );
    }

    let mut summary = Summary::new("patch", diff_sizes.len() * node_types.len() * 6);
    let mut ran_any_case = false;

    for node_type in node_types {
        let node_label = node_type.as_label();
        let eligible_diffs: Vec<usize> = diff_sizes
            .iter()
            .copied()
            .filter(|diff| *diff <= node_type.max_diffs())
            .collect();

        for diff_count in eligible_diffs {
            ran_any_case = true;
            let (base, patch, encoded) = make_patch_fixture(node_type, diff_count);
            let patch_old_ptr = patch_old_ptr_for(node_type);

            record_case(
                &mut summary,
                &format!("patch_from_{node_label}_diff={diff_count}"),
                output_mode,
                rounds,
                || {
                    for _ in 0..iters {
                        let next = make_new_node_with_extra_ptrs(
                            &base,
                            128,
                            diff_count,
                            patch_old_ptr.back_block,
                        );
                        black_box(
                            TrieNodePatch::try_from_nodetype(patch_old_ptr, &base, &next)
                                .expect("patch_from_nodetype benchmark fixture"),
                        );
                    }
                },
            );

            record_case(
                &mut summary,
                &format!("patch_size_{node_label}_diff={diff_count}"),
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
                &format!("patch_serialize_{node_label}_diff={diff_count}"),
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
                &format!("patch_deserialize_{node_label}_diff={diff_count}"),
                output_mode,
                rounds,
                || {
                    for _ in 0..iters {
                        let mut cursor = std::io::Cursor::new(encoded.as_slice());
                        black_box(
                            <TrieNodePatch as StacksMessageCodec>::consensus_deserialize(
                                &mut cursor,
                            )
                            .expect("deserialize patch in benchmark"),
                        );
                    }
                },
            );

            record_case(
                &mut summary,
                &format!("patch_apply_{node_label}_diff={diff_count}"),
                output_mode,
                rounds,
                || {
                    for _ in 0..iters {
                        black_box(apply_patch_to_base(&patch, &base, 777, 888));
                    }
                },
            );

            record_case(
                &mut summary,
                &format!("patch_try_from_patch_{node_label}_diff={diff_count}"),
                output_mode,
                rounds,
                || {
                    for _ in 0..iters {
                        let mut next =
                            make_new_node_with_extra_ptrs(&base, 128, 0, patch_old_ptr.back_block);
                        let promote_chr = 220u8;
                        let promote_ptr =
                            make_backptr_leaf(promote_chr, 90_000, patch_old_ptr.back_block);
                        insert_ptr(&mut next, promote_ptr);

                        black_box(
                            TrieNodePatch::try_from_patch(patch_old_ptr, &patch, &next)
                                .expect("try_from_patch should produce non-empty diff"),
                        );
                    }
                },
            );
        }
    }

    assert!(
        ran_any_case,
        "no benchmark cases were generated; check NODE_TYPES and PATCH_DIFFS compatibility"
    );

    print_summary(&summary);
}
