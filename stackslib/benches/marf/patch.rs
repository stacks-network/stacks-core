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
//! Cases are evaluated across configurable node fanout (`NODE_TYPES`), pointer-state regime
//! (`PTR_STATES` = `backptr|plain`), and diff cardinality (`PATCH_DIFFS`).
//!
//! What is measured (for each configured node type, pointer state, and diff size):
//! - `patch_from_node{4|16|48|256}_{backptr|plain}_diff=*`: patch construction from old/new snapshots.
//! - `patch_size_node*_...`: patch size accounting cost for allocation/serialization planning.
//! - `patch_serialize_node*_...`: consensus-encoding throughput and allocator pressure.
//! - `patch_deserialize_node*_...`: consensus-decoding throughput and allocator pressure.
//! - `patch_apply_node{4|16|48|256}_{backptr|plain}_diff=*`: patch application to typed base nodes.
//! - `patch_try_from_patch_node{4|16|48|256}_{backptr|plain}_diff=*`: incremental patch-from-patch transition cost.

use std::collections::HashSet;
use std::hint::black_box;

use blockstack_lib::chainstate::stacks::index::node::{
    is_backptr, set_backptr, TrieNode16, TrieNode256, TrieNode4, TrieNode48, TrieNodeID,
    TrieNodePatch, TrieNodeType, TriePtr,
};
use blockstack_lib::codec::StacksMessageCodec;

use crate::common::{record_case_with_rounds, OutputMode, Summary};
use crate::utils::{
    has_help_flag, parse_csv_lowercase_tokens_env, parse_csv_usize_env, parse_usize_env,
};

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
/// Default pointer-state variants covered by the harness.
const DEFAULT_PTR_STATES: [PtrState; 2] = [PtrState::Backptr, PtrState::Plain];
/// Synthetic `chr` used for fixture patch-old pointers.
const PATCH_OLD_PTR_CHR: u8 = 0;
/// Synthetic pointer offset used for fixture patch-old pointers.
const PATCH_OLD_PTR_OFFSET: u32 = 777;
/// Synthetic back-block id used to keep fixture pointers in backptr mode.
const PATCH_OLD_BACK_BLOCK: u32 = 123;

/// Supported trie node variants in patch microbench coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeBenchType {
    Node4,
    Node16,
    Node48,
    Node256,
}

/// Pointer state regime used when constructing synthetic node fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PtrState {
    Backptr,
    Plain,
}

impl PtrState {
    /// Parse one `PTR_STATES` CSV token into a pointer-state variant.
    fn parse_token(token: &str) -> Option<Self> {
        match token {
            "backptr" => Some(Self::Backptr),
            "plain" => Some(Self::Plain),
            _ => None,
        }
    }

    /// Return the lowercase label used in output row names.
    fn as_label(self) -> &'static str {
        match self {
            Self::Backptr => "backptr",
            Self::Plain => "plain",
        }
    }
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
            Self::Node256 => 256,
        }
    }
}

#[rustfmt::skip]
/// Print CLI/env usage help for the patch harness.
fn print_usage() {
    println!("marf-patch: TrieNodePatch compression microbench");
    println!();
    println!("Usage:");
    println!("  cargo bench -p stackslib --bench marf -- patch [--help]");
    println!();
    println!("Environment Variables:");
    println!("  ITERS           Iterations per measured case [default: {DEFAULT_ITERS}]");
    println!("  ROUNDS          Independent repetitions per case [default: {DEFAULT_ROUNDS}]");
    println!("  NODE_TYPES      Comma-separated node types [default: all]");
    println!("                  Allowed: all,node4,node16,node48,node256");
    println!("  PTR_STATES      Comma-separated pointer states [default: all]");
    println!("                  Allowed: all,backptr,plain");
    println!("  PATCH_DIFFS     Comma-separated patch diff sizes [default: 1,4,16,64]");
    println!("                  Must be in range 1..=256 and unique");
    println!("  OUTPUT_FORMAT   Output mode [default: summary]");
    println!("                  'summary': unified summary lines only");
    println!("                  'raw': detailed per-case lines + unified summary lines");
    println!();
    println!("Output Lines:");
    println!("  summary         Unified summary lines emitted by marf bench main");
}

/// Parse `NODE_TYPES` into deduplicated node variants, defaulting to all.
fn parse_node_types() -> Vec<NodeBenchType> {
    let Some(tokens) = parse_csv_lowercase_tokens_env("NODE_TYPES") else {
        return DEFAULT_NODE_TYPES.to_vec();
    };

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

/// Parse `PTR_STATES` into deduplicated pointer-state variants, defaulting to all.
fn parse_ptr_states() -> Vec<PtrState> {
    let Some(tokens) = parse_csv_lowercase_tokens_env("PTR_STATES") else {
        return DEFAULT_PTR_STATES.to_vec();
    };

    if tokens.iter().any(|token| token == "all") {
        return DEFAULT_PTR_STATES.to_vec();
    }

    let mut parsed = Vec::new();
    for token in tokens {
        let Some(ptr_state) = PtrState::parse_token(&token) else {
            panic!("invalid PTR_STATES entry: '{token}' (expected all,backptr,plain)");
        };
        if !parsed.contains(&ptr_state) {
            parsed.push(ptr_state);
        }
    }

    assert!(
        !parsed.is_empty(),
        "PTR_STATES must contain at least one valid pointer state"
    );
    parsed
}

/// Parse and validate `PATCH_DIFFS` cardinalities.
fn parse_patch_diffs() -> Vec<usize> {
    let diffs = parse_csv_usize_env("PATCH_DIFFS", &DEFAULT_DIFFS);
    let mut seen = HashSet::with_capacity(diffs.len());
    for value in &diffs {
        assert!(
            *value > 0 && *value <= 256,
            "PATCH_DIFFS entries must be in range 1..=256"
        );
        assert!(seen.insert(*value), "PATCH_DIFFS entries must be unique");
    }
    diffs
}

/// Build a leaf pointer fixture in backptr representation.
fn make_leaf_ptr(chr: u8, ptr: u32, old_back_block: u32, ptr_state: PtrState) -> TriePtr {
    match ptr_state {
        PtrState::Backptr => {
            let mut node_ptr = TriePtr::new(set_backptr(TrieNodeID::Leaf as u8), chr, ptr);
            node_ptr.back_block = old_back_block;
            node_ptr
        }
        PtrState::Plain => TriePtr::new(TrieNodeID::Leaf as u8, chr, ptr),
    }
}

/// Build the synthetic old-pointer used as patch origin metadata.
fn patch_old_ptr_for(node_type: NodeBenchType, ptr_state: PtrState) -> TriePtr {
    let node_id = match node_type {
        NodeBenchType::Node4 => TrieNodeID::Node4 as u8,
        NodeBenchType::Node16 => TrieNodeID::Node16 as u8,
        NodeBenchType::Node48 => TrieNodeID::Node48 as u8,
        NodeBenchType::Node256 => TrieNodeID::Node256 as u8,
    };

    match ptr_state {
        PtrState::Backptr => {
            let mut ptr = TriePtr::new(
                set_backptr(node_id),
                PATCH_OLD_PTR_CHR,
                PATCH_OLD_PTR_OFFSET,
            );
            ptr.back_block = PATCH_OLD_BACK_BLOCK;
            ptr
        }
        PtrState::Plain => TriePtr::new(node_id, PATCH_OLD_PTR_CHR, PATCH_OLD_PTR_OFFSET),
    }
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
    ptr_state: PtrState,
) -> TrieNodeType {
    let mut node = base.clone();
    if ptr_state == PtrState::Backptr {
        normalize_node_ptrs_to_backptr(&mut node, old_back_block);
    }

    for i in 0..count {
        let chr = start_chr.wrapping_add(i as u8);
        let ptr = make_leaf_ptr(chr, 10_000 + i as u32, old_back_block, ptr_state);
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
    ptr_state: PtrState,
) -> (TrieNodeType, TrieNodePatch, Vec<u8>) {
    let path: [u8; 32] = std::array::from_fn(|i| i as u8);
    let base = make_base_node(node_type, &path);
    let patch_old_ptr = patch_old_ptr_for(node_type, ptr_state);
    let next =
        make_new_node_with_extra_ptrs(&base, 128, diff_count, patch_old_ptr.back_block, ptr_state);

    let patch = TrieNodePatch::try_from_nodetype(patch_old_ptr, &base, &next)
        .expect("make patch fixture from nodetype");
    assert_eq!(patch.ptr_diff.len(), diff_count);
    match ptr_state {
        PtrState::Backptr => assert!(is_backptr(patch.ptr.id())),
        PtrState::Plain => assert!(!is_backptr(patch.ptr.id())),
    }

    let mut encoded = Vec::with_capacity(patch.size());
    patch
        .consensus_serialize(&mut encoded)
        .expect("serialize TrieNodePatch fixture");

    (base, patch, encoded)
}

/// Run patch benchmark subcommand and return summary rows.
pub fn run(args: &[String], output_mode: OutputMode) -> Option<Summary> {
    if has_help_flag(args) {
        print_usage();
        return None;
    }

    let iters = parse_usize_env("ITERS", DEFAULT_ITERS);
    let rounds = parse_usize_env("ROUNDS", DEFAULT_ROUNDS);
    let node_types = parse_node_types();
    let ptr_states = parse_ptr_states();
    assert!(iters > 0, "ITERS must be > 0");
    assert!(rounds > 0, "ROUNDS must be > 0");

    let diff_sizes = parse_patch_diffs();
    if output_mode.is_raw() {
        let node_type_labels: Vec<&str> = node_types
            .iter()
            .map(|node_type| node_type.as_label())
            .collect();
        let ptr_state_labels: Vec<&str> = ptr_states
            .iter()
            .map(|ptr_state| ptr_state.as_label())
            .collect();
        println!(
            "iters={iters}\trounds={rounds}\tnode_types={node_type_labels:?}\tptr_states={ptr_state_labels:?}\tpatch_diffs={diff_sizes:?}"
        );
    }

    let mut summary = Summary::new(
        "patch",
        diff_sizes.len() * node_types.len() * ptr_states.len() * 6,
    );
    let mut ran_any_case = false;

    for ptr_state in ptr_states {
        let ptr_state_label = ptr_state.as_label();
        for node_type in node_types.iter().copied() {
            let node_label = node_type.as_label();
            let eligible_diffs: Vec<usize> = diff_sizes
                .iter()
                .copied()
                .filter(|diff| *diff <= node_type.max_diffs())
                .collect();

            for diff_count in eligible_diffs {
                ran_any_case = true;
                let (base, patch, encoded) = make_patch_fixture(node_type, diff_count, ptr_state);
                let patch_old_ptr = patch_old_ptr_for(node_type, ptr_state);

                // Measure patch construction from base/new node snapshots.
                record_case_with_rounds(
                    &mut summary,
                    &format!("patch_from_{node_label}_{ptr_state_label}_diff={diff_count}"),
                    output_mode,
                    rounds,
                    || {
                        for _ in 0..iters {
                            let next = make_new_node_with_extra_ptrs(
                                &base,
                                128,
                                diff_count,
                                patch_old_ptr.back_block,
                                ptr_state,
                            );
                            black_box(
                                TrieNodePatch::try_from_nodetype(patch_old_ptr, &base, &next)
                                    .expect("patch_from_nodetype benchmark fixture"),
                            );
                        }
                    },
                );

                // Measure patch size computation overhead.
                record_case_with_rounds(
                    &mut summary,
                    &format!("patch_size_{node_label}_{ptr_state_label}_diff={diff_count}"),
                    output_mode,
                    rounds,
                    || {
                        for _ in 0..iters {
                            black_box(patch.size());
                        }
                    },
                );

                // Measure consensus serialization throughput/cost.
                let encoded_size = patch.size();
                let mut out = Vec::with_capacity(encoded_size);
                record_case_with_rounds(
                    &mut summary,
                    &format!("patch_serialize_{node_label}_{ptr_state_label}_diff={diff_count}"),
                    output_mode,
                    rounds,
                    || {
                        for _ in 0..iters {
                            out.clear();
                            patch
                                .consensus_serialize(&mut out)
                                .expect("serialize patch in benchmark");
                            black_box(out.len());
                        }
                    },
                );

                // Measure consensus deserialization throughput/cost.
                record_case_with_rounds(
                    &mut summary,
                    &format!("patch_deserialize_{node_label}_{ptr_state_label}_diff={diff_count}"),
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

                // Measure patch application onto the typed base node.
                record_case_with_rounds(
                    &mut summary,
                    &format!("patch_apply_{node_label}_{ptr_state_label}_diff={diff_count}"),
                    output_mode,
                    rounds,
                    || {
                        for _ in 0..iters {
                            black_box(apply_patch_to_base(&patch, &base, 777, 888));
                        }
                    },
                );

                // Measure incremental patch generation from prior patch + updated node.
                record_case_with_rounds(
                    &mut summary,
                    &format!(
                        "patch_try_from_patch_{node_label}_{ptr_state_label}_diff={diff_count}"
                    ),
                    output_mode,
                    rounds,
                    || {
                        for _ in 0..iters {
                            let mut next = make_new_node_with_extra_ptrs(
                                &base,
                                128,
                                0,
                                patch_old_ptr.back_block,
                                ptr_state,
                            );
                            let promote_chr = 220u8;
                            let promote_ptr = make_leaf_ptr(
                                promote_chr,
                                90_000,
                                patch_old_ptr.back_block,
                                ptr_state,
                            );
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
    }

    assert!(
        ran_any_case,
        "no benchmark cases were generated; check NODE_TYPES and PATCH_DIFFS compatibility"
    );

    Some(summary)
}
