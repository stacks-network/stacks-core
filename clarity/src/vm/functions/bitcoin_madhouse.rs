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

//! Stateful PBT against `verify_merkle`, targeting CVE-2012-2459-style
//! tree-shape confusion. Random sequences mix:
//!
//! - `BuildTree`: append a random tree to the in-memory pool.
//! - `VerifyHonestProof`: build a valid inclusion proof for a pool leaf, assert
//!   `verify_merkle` returns true.
//! - `VerifyForge3`: build a fresh 3-leaf tree (the CVE padded shape) plus the
//!   intermediate-as-leaf forgery, then check both gap directions: accepted at
//!   `tx_count = 2`, rejected at the real `tx_count = 3`.
//! - `VerifyTamperedLeaf` / `VerifyWrongDepth` / `VerifyOutOfRangeIndex`:
//!   honest proof minus one component, must be rejected.
//!
//! No SUT: the SUT is the pure `verify_merkle`. `State` is the tree pool;
//! `Context` is empty (only for the `TestContext` trait shape).

use std::sync::Arc;

use madhouse::{
    Command, CommandWrapper, State, TestContext, execute_commands, prop_allof, scenario,
};
use proptest::prelude::*;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;

use super::bitcoin::{VERIFY_MERKLE_PROOF_MAX_DEPTH, verify_merkle};

/// Independent depth oracle: count halvings to reach 1 (0 for n <= 1).
/// Recomputed here rather than calling production `canonical_merkle_depth`, so
/// the forge-shape assertions that use it don't inherit a depth bug from the
/// code under test.
fn naive_depth(n: u128) -> u32 {
    if n <= 1 {
        return 0;
    }
    let mut depth = 0u32;
    let mut m = n;
    while m > 1 {
        m = m.div_ceil(2);
        depth += 1;
    }
    depth
}

// Local merkle helpers. The `mod tests` helpers in bitcoin.rs are private to
// that module, so reuse is not possible from here.

/// Hash two 32-byte values with double-SHA-256 in Bitcoin's order.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    Sha256dHash::from_data(&buf).0
}

/// Canonical Bitcoin merkle root of `leaves`. Odd rows are padded by
/// duplicating the last node (the CVE-2012-2459 source).
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

/// Honest inclusion proof for `leaf_idx`. Returns `(leaf, root, leaf_idx,
/// tx_count, siblings)` such that
/// `verify_merkle(leaf, root, leaf_idx, tx_count, &siblings)` holds.
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

/// Each tree stores its leaves so `VerifyHonestProof` can build a proof on demand.
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

/// Empty context; the SUT is the pure `verify_merkle` function.
#[derive(Debug, Clone, Default)]
pub struct AdversaryContext;

impl TestContext for AdversaryContext {}

/// Append a tree of `leaves.len()` random leaves to the pool.
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
        // 1..=8 covers CVE-relevant shapes: odd counts trigger last-row
        // padding; n=2,4,8 are power-of-two and unpadded.
        prop::collection::vec(any::<[u8; 32]>(), 1usize..=8)
            .prop_map(|leaves| CommandWrapper::new(BuildTree { leaves }))
    }
}

/// Pick an existing tree + leaf, synthesize an honest proof, assert
/// `verify_merkle` returns true. `check` guards against an empty pool.
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
        (any::<usize>(), any::<usize>()).prop_map(|(tree_seed, leaf_seed)| {
            CommandWrapper::new(VerifyHonestProof {
                tree_seed,
                leaf_seed,
            })
        })
    }
}

/// CVE-2012-2459 collision on a fresh 3-leaf tree, both directions:
/// accepted at the deflated `tx_count = 2` (the intermediate node `H(c, c)`
/// is a valid 2-leaf leaf that collides with the 3-leaf root — accepted by
/// design, see `prop_merkle_deflated_tx_count_collision_accepted` in
/// `bitcoin.rs`), rejected at the real `tx_count = 3` (depth check).
///
/// Does not touch the tree pool: each call builds a fresh tree from `(a, b, c)`.
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
        // 3-leaf padded shape [a, b, c, c]:
        //   row 1: [H(a, b), H(c, c)]
        //   row 2: H(H(a, b), H(c, c)) = root
        let h_ab = hash_pair(&self.a, &self.b);
        let h_cc = hash_pair(&self.c, &self.c);
        let root = hash_pair(&h_ab, &h_cc);

        // H(c, c) is a valid leaf of the 2-leaf tree [_, H(c, c)] with sibling
        // H(a, b); the walk lands on the genuine 3-leaf root. Accepted by design.
        assert!(
            verify_merkle(h_cc, root, 1, 2, &[h_ab]),
            "deflated tx_count=2 collision should be ACCEPTED by design"
        );

        // With truthful tx_count=3 the proof is rejected because
        // naive_depth(3) = 2 != 1 = siblings.len(). Oracle is independent
        // of production `canonical_merkle_depth`.
        assert_eq!(naive_depth(3), 2, "naive_depth(3) should be 2");
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
        (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<[u8; 32]>())
            .prop_map(|(a, b, c)| CommandWrapper::new(VerifyForge3 { a, b, c }))
    }
}

// Negative-path commands. Pick a tree, build the honest proof, sabotage one
// component, assert `verify_merkle` rejects.

/// Flip one bit of the leaf in an honest proof.
struct VerifyTamperedLeaf {
    tree_seed: usize,
    leaf_seed: usize,
    byte_idx: u8,
    bit: u8,
}

impl Command<MerkleAdversaryState, AdversaryContext> for VerifyTamperedLeaf {
    fn check(&self, state: &MerkleAdversaryState) -> bool {
        !state.trees.is_empty()
    }

    fn apply(&self, state: &mut MerkleAdversaryState) {
        let tree_idx = self.tree_seed % state.trees.len();
        let tree = &state.trees[tree_idx];
        let leaf_idx = self.leaf_seed % tree.leaves.len();
        let (leaf, root, tx_index, tx_count, siblings) = honest_proof(&tree.leaves, leaf_idx);
        let byte = (self.byte_idx as usize) % 32;
        let mut tampered = leaf;
        tampered[byte] ^= 1u8 << (self.bit % 8);
        // A bit-flip is by definition a change.
        debug_assert_ne!(tampered, leaf);
        assert!(
            !verify_merkle(tampered, root, tx_index, tx_count, &siblings),
            "tampered leaf accepted: tree_idx={tree_idx} leaf_idx={leaf_idx}"
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_TAMPERED_LEAF({}, {})", self.byte_idx, self.bit)
    }

    fn build(
        _ctx: Arc<AdversaryContext>,
    ) -> impl Strategy<Value = CommandWrapper<MerkleAdversaryState, AdversaryContext>> {
        (any::<usize>(), any::<usize>(), 0u8..32, 0u8..8).prop_map(
            |(tree_seed, leaf_seed, byte_idx, bit)| {
                CommandWrapper::new(VerifyTamperedLeaf {
                    tree_seed,
                    leaf_seed,
                    byte_idx,
                    bit,
                })
            },
        )
    }
}

/// Take an honest proof and truncate or extend its siblings vector so
/// `siblings.len() != canonical_depth(tx_count)`. `verify_merkle`'s
/// path-length check must then reject it.
struct VerifyWrongDepth {
    tree_seed: usize,
    leaf_seed: usize,
    /// `true` = truncate one sibling, `false` = append one extra sibling.
    truncate: bool,
}

impl Command<MerkleAdversaryState, AdversaryContext> for VerifyWrongDepth {
    fn check(&self, state: &MerkleAdversaryState) -> bool {
        if state.trees.is_empty() {
            return false;
        }
        let tree_idx = self.tree_seed % state.trees.len();
        let tree = &state.trees[tree_idx];
        // Truncate needs siblings.len() >= 1 (i.e. tx_count >= 2). Extend is
        // always meaningful.
        !self.truncate || tree.leaves.len() >= 2
    }

    fn apply(&self, state: &mut MerkleAdversaryState) {
        let tree_idx = self.tree_seed % state.trees.len();
        let tree = &state.trees[tree_idx];
        let leaf_idx = self.leaf_seed % tree.leaves.len();
        let (leaf, root, tx_index, tx_count, mut siblings) = honest_proof(&tree.leaves, leaf_idx);
        if self.truncate {
            siblings.pop().expect("guarded by check");
        } else {
            siblings.push([0u8; 32]);
        }
        assert!(
            !verify_merkle(leaf, root, tx_index, tx_count, &siblings),
            "wrong-depth proof accepted: tree_idx={tree_idx} tx_count={tx_count}"
        );
    }

    fn label(&self) -> String {
        if self.truncate {
            "VERIFY_WRONG_DEPTH(truncated)".to_string()
        } else {
            "VERIFY_WRONG_DEPTH(extended)".to_string()
        }
    }

    fn build(
        _ctx: Arc<AdversaryContext>,
    ) -> impl Strategy<Value = CommandWrapper<MerkleAdversaryState, AdversaryContext>> {
        (any::<usize>(), any::<usize>(), any::<bool>()).prop_map(
            |(tree_seed, leaf_seed, truncate)| {
                CommandWrapper::new(VerifyWrongDepth {
                    tree_seed,
                    leaf_seed,
                    truncate,
                })
            },
        )
    }
}

/// Honest proof with `tx_index >= tx_count`; must fail the `tx_index <
/// tx_count` guard in `verify_merkle`.
struct VerifyOutOfRangeIndex {
    tree_seed: usize,
    leaf_seed: usize,
    /// Added to `tx_count` to derive the bad index (so bad_idx > tx_count).
    slop: u32,
}

impl Command<MerkleAdversaryState, AdversaryContext> for VerifyOutOfRangeIndex {
    fn check(&self, state: &MerkleAdversaryState) -> bool {
        !state.trees.is_empty()
    }

    fn apply(&self, state: &mut MerkleAdversaryState) {
        let tree_idx = self.tree_seed % state.trees.len();
        let tree = &state.trees[tree_idx];
        let leaf_idx = self.leaf_seed % tree.leaves.len();
        let (leaf, root, _tx_index, tx_count, siblings) = honest_proof(&tree.leaves, leaf_idx);
        let bad_idx = tx_count.saturating_add(self.slop as u128);
        assert!(
            !verify_merkle(leaf, root, bad_idx, tx_count, &siblings),
            "out-of-range index {bad_idx} accepted with tx_count={tx_count}"
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_OOB_INDEX(slop={})", self.slop)
    }

    fn build(
        _ctx: Arc<AdversaryContext>,
    ) -> impl Strategy<Value = CommandWrapper<MerkleAdversaryState, AdversaryContext>> {
        (any::<usize>(), any::<usize>(), 0u32..=64).prop_map(|(tree_seed, leaf_seed, slop)| {
            CommandWrapper::new(VerifyOutOfRangeIndex {
                tree_seed,
                leaf_seed,
                slop,
            })
        })
    }
}

/// Drive the adversary through random command sequences. Default:
/// deterministic order. `MADHOUSE=1`: random walks of 1..=16 commands.
#[test]
fn madhouse_merkle_cve_adversarial() {
    let ctx = Arc::new(AdversaryContext);
    scenario![
        ctx,
        BuildTree,
        VerifyHonestProof,
        VerifyForge3,
        VerifyTamperedLeaf,
        VerifyWrongDepth,
        VerifyOutOfRangeIndex
    ]
}
