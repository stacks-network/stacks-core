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

//! # Merkle CVE-2012-2459 adversarial machine
//!
//! Stateful PBT exhausting the attack surface around tree-shape confusion
//! in `verify_merkle`. Composes random sequences of three commands:
//!
//! 1. **`BuildTree`** — append a random tree to the in-memory pool.
//! 2. **`VerifyHonestProof`** — pick a tree at random, construct a valid
//!    proof of inclusion for one of its leaves, assert `verify_merkle`
//!    returns `true`.
//! 3. **`VerifyForge3`** — construct a fresh 3-leaf tree (the canonical
//!    CVE-2012-2459 padded shape) and the intermediate-as-leaf forgery,
//!    then assert two complementary invariants:
//!    - the forgery is accepted when presented with `tx_count = 2`
//!      (the gap documented in
//!      `verify_merkle`)
//!    - the forgery is rejected when presented with the real `tx_count = 3`
//!      (the depth-check defense works for the truthful caller)
//!
//! There is no external SUT — the SUT is the pure function
//! `verify_merkle` itself. The `State` is the adversary's tree pool. The
//! `Context` is empty (purely for the `TestContext` trait shape).

use std::sync::Arc;

use madhouse::{Command, CommandWrapper, State, TestContext, execute_commands, prop_allof};
use pinny::tag;
use proptest::prelude::*;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;

use super::bitcoin::{VERIFY_MERKLE_PROOF_MAX_DEPTH, canonical_merkle_depth, verify_merkle};

// ---------------------------------------------------------------------------
// Local merkle helpers — we don't reuse the `mod tests` private helpers in
// bitcoin.rs because we live in a different module.
// ---------------------------------------------------------------------------

/// Walk a proof from `leaf` to the root using `siblings`. Used both by
/// honest-proof construction (to compute the canonical root) and by the
/// pinning assertions.
fn compute_root_from_proof(leaf: [u8; 32], tx_index: u128, siblings: &[[u8; 32]]) -> [u8; 32] {
    let mut cur = leaf;
    let mut idx = tx_index;
    let mut buf = [0u8; 64];
    for sibling in siblings {
        if idx & 1 == 1 {
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&cur);
        } else {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(sibling);
        }
        cur = Sha256dHash::from_data(&buf).0;
        idx >>= 1;
    }
    cur
}

/// Hash two 32-byte values with double-SHA-256 in Bitcoin's order.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    Sha256dHash::from_data(&buf).0
}

/// Compute the canonical root of a Bitcoin merkle tree from `leaves`. Pads
/// odd-length rows by duplicating the last node (the source of
/// CVE-2012-2459).
fn canonical_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty(), "leaves must be non-empty");
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut row = leaves.to_vec();
    while row.len() > 1 {
        if row.len() % 2 == 1 {
            let last = row[row.len() - 1];
            row.push(last);
        }
        row = row
            .chunks(2)
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
    }
    row[0]
}

/// Synthesize an honest inclusion proof for `leaf_idx` in `leaves`. Returns
/// `(leaf, root, leaf_idx, tx_count, siblings)` such that
/// `verify_merkle(leaf, root, leaf_idx, tx_count, &siblings)` is true.
fn honest_proof(
    leaves: &[[u8; 32]],
    leaf_idx: usize,
) -> ([u8; 32], [u8; 32], u128, u128, Vec<[u8; 32]>) {
    let tx_count = leaves.len() as u128;
    let leaf = leaves[leaf_idx];
    let mut row = leaves.to_vec();
    let mut siblings = Vec::new();
    let mut idx = leaf_idx;
    while row.len() > 1 {
        if row.len() % 2 == 1 {
            let last = row[row.len() - 1];
            row.push(last);
        }
        let sib_idx = if idx & 1 == 0 { idx + 1 } else { idx - 1 };
        siblings.push(row[sib_idx]);
        row = row
            .chunks(2)
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
        idx >>= 1;
    }
    let root = row[0];
    (leaf, root, leaf_idx as u128, tx_count, siblings)
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// In-memory pool of trees the adversary has built so far. Each tree
/// stores its leaves so `VerifyHonestProof` can build a proof on demand.
#[derive(Debug, Clone)]
struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

#[derive(Debug, Clone, Default)]
struct MerkleAdversaryState {
    trees: Vec<MerkleTree>,
}

impl State for MerkleAdversaryState {}

// ---------------------------------------------------------------------------
// Empty test context — there is no shared SUT to wrap.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct AdversaryContext;

impl TestContext for AdversaryContext {}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Append a tree of `leaves.len()` random leaves to the pool. Honest
/// verification later can target any of them.
struct BuildTree {
    leaves: Vec<[u8; 32]>,
}

impl Command<MerkleAdversaryState, AdversaryContext> for BuildTree {
    fn check(&self, _state: &MerkleAdversaryState) -> bool {
        !self.leaves.is_empty() && self.leaves.len() <= (1 << VERIFY_MERKLE_PROOF_MAX_DEPTH)
    }

    fn apply(&self, state: &mut MerkleAdversaryState) {
        let root = canonical_root(&self.leaves);
        state.trees.push(MerkleTree {
            leaves: self.leaves.clone(),
            root,
        });
    }

    fn label(&self) -> String {
        format!("BUILD_TREE(n={})", self.leaves.len())
    }

    fn build(
        _ctx: Arc<AdversaryContext>,
    ) -> impl Strategy<Value = CommandWrapper<MerkleAdversaryState, AdversaryContext>> {
        // 1..=8 leaves covers the interesting CVE-relevant shapes (odd
        // counts have last-row padding; n=2,4,8 are power-of-two and
        // free of padding).
        prop::collection::vec(any::<[u8; 32]>(), 1usize..=8)
            .prop_map(|leaves| CommandWrapper::new(BuildTree { leaves }))
    }
}

/// Pick an existing tree + leaf at random, synthesize an honest proof,
/// and assert `verify_merkle` returns `true`. The check guarantees the
/// pool is non-empty so `apply` never panics on indexing.
struct VerifyHonestProof {
    tree_seed: usize,
    leaf_seed: usize,
}

impl Command<MerkleAdversaryState, AdversaryContext> for VerifyHonestProof {
    fn check(&self, state: &MerkleAdversaryState) -> bool {
        !state.trees.is_empty()
    }

    fn apply(&self, state: &mut MerkleAdversaryState) {
        let tree_idx = self.tree_seed % state.trees.len();
        let tree = &state.trees[tree_idx];
        let leaf_idx = self.leaf_seed % tree.leaves.len();
        let (leaf, root, tx_index, tx_count, siblings) = honest_proof(&tree.leaves, leaf_idx);
        assert_eq!(
            root, tree.root,
            "honest_proof root mismatches canonical_root for tree_idx={tree_idx} leaf_idx={leaf_idx}"
        );
        assert!(
            verify_merkle(leaf, root, tx_index, tx_count, &siblings),
            "honest proof rejected: tree_idx={tree_idx} leaf_idx={leaf_idx}"
        );
    }

    fn label(&self) -> String {
        format!(
            "VERIFY_HONEST(tree_seed={}, leaf_seed={})",
            self.tree_seed, self.leaf_seed
        )
    }

    fn build(
        _ctx: Arc<AdversaryContext>,
    ) -> impl Strategy<Value = CommandWrapper<MerkleAdversaryState, AdversaryContext>> {
        (any::<usize>(), any::<usize>())
            .prop_map(|(tree_seed, leaf_seed)| {
                CommandWrapper::new(VerifyHonestProof {
                    tree_seed,
                    leaf_seed,
                })
            })
    }
}

/// Construct the canonical CVE-2012-2459 forgery on a fresh 3-leaf tree
/// and assert both sides of the gap:
///   - the forgery IS accepted by `verify_merkle` when the attacker
///     supplies `tx_count = 2` (this is the known buggy behavior, see
///     `prop_merkle_intermediate_as_leaf_forgery_currently_accepted` in
///     `bitcoin.rs`),
///   - the forgery IS rejected by `verify_merkle` when the truthful
///     `tx_count = 3` is supplied (the depth-check defense works for the
///     caller that validates `tx_count`).
///
/// This command does NOT touch the tree pool — each invocation builds a
/// fresh 3-leaf tree from the random `(a, b, c)`.
struct VerifyForge3 {
    a: [u8; 32],
    b: [u8; 32],
    c: [u8; 32],
}

impl Command<MerkleAdversaryState, AdversaryContext> for VerifyForge3 {
    fn check(&self, _state: &MerkleAdversaryState) -> bool {
        true
    }

    fn apply(&self, _state: &mut MerkleAdversaryState) {
        // Canonical 3-leaf padded tree shape: [a, b, c, c]
        // → row 1: [H(a, b), H(c, c)]
        // → row 2: H(H(a, b), H(c, c)) = root
        let h_ab = hash_pair(&self.a, &self.b);
        let h_cc = hash_pair(&self.c, &self.c);
        let root = hash_pair(&h_ab, &h_cc);

        // Forgery: present H(c, c) as a leaf at index 1 of a "2-leaf
        // tree" with sibling H(a, b). The walk reaches the genuine root.
        assert!(
            verify_merkle(h_cc, root, 1, 2, &[h_ab]),
            "CVE forgery should be ACCEPTED with claimed tx_count=2 (gap)"
        );

        // Same forgery presented with the truthful tx_count=3 is rejected
        // because `canonical_depth(3) = 2 != 1 = siblings.len()`.
        assert_eq!(
            canonical_merkle_depth(3),
            2,
            "canonical_depth(3) should be 2"
        );
        assert!(
            !verify_merkle(h_cc, root, 1, 3, &[h_ab]),
            "CVE forgery should be REJECTED with real tx_count=3 (defense)"
        );
    }

    fn label(&self) -> String {
        "VERIFY_FORGE_3".to_string()
    }

    fn build(
        _ctx: Arc<AdversaryContext>,
    ) -> impl Strategy<Value = CommandWrapper<MerkleAdversaryState, AdversaryContext>> {
        (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(a, b, c)| {
            CommandWrapper::new(VerifyForge3 { a, b, c })
        })
    }
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

/// Drive the adversary through random sequences of `BuildTree`,
/// `VerifyHonestProof`, and `VerifyForge3`. Default deterministic order;
/// `MADHOUSE=1` switches to random walks of 1..=16 commands.
#[test]
#[cfg_attr(test, tag(t_prop))]
fn merkle_cve_adversarial_madhouse() {
    let ctx = Arc::new(AdversaryContext);
    let config = proptest::test_runner::Config {
        cases: 1,
        max_shrink_iters: 0,
        ..proptest::test_runner::Config::default()
    };

    let use_madhouse = std::env::var("MADHOUSE") == Ok("1".into());

    if use_madhouse {
        proptest::proptest!(config.clone(), |(commands in proptest::collection::vec(
            proptest::prop_oneof![
                BuildTree::build(ctx.clone()),
                VerifyHonestProof::build(ctx.clone()),
                VerifyForge3::build(ctx.clone()),
            ],
            1..16,
        ))| {
            // No SUT to reset — state is purely the tree pool, which is
            // reset by `Default` here.
            let mut state = MerkleAdversaryState::default();
            execute_commands(&commands, &mut state);
        });
    } else {
        proptest::proptest!(config, |(commands in prop_allof![
            BuildTree::build(ctx.clone()),
            VerifyHonestProof::build(ctx.clone()),
            VerifyForge3::build(ctx.clone()),
        ])| {
            let mut state = MerkleAdversaryState::default();
            execute_commands(&commands, &mut state);
        });
    }
}
