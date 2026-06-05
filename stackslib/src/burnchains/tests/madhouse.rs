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

//! Stateful PBT for `watched_p2wsh_outputs` in the burnchain DB. Random
//! sequences of `StoreBlock` and `PruneAtHeight` run against an in-memory
//! SQLite-backed `BurnchainDB`, with a shadow `BTreeMap` kept aligned. Ordered
//! collections are used throughout so iteration order is reproducible across
//! machines from a saved seed (`HashMap` iteration is per-process seeded and
//! would alter which counter-example shrinking lands on).
//!
//! Invariants checked after every command:
//! 1. DB/shadow consistency: every block_hash in the model has the same outputs
//!    in the DB, and no DB rows exist for block_hashes outside the model.
//! 2. Prune correctness: after `PruneAtHeight(H)`, no entry with
//!    `block_height < H.saturating_sub(3 * RCL / 2)` survives on either side.
//!
//! Both the shadow model and the real SUT live in [`WatchedOutputsState`], which
//! `scenario!` rebuilds fresh per proptest case via `Default` — so MADHOUSE walks
//! stay independent without a manual SUT reset.
//!
//! See [`tests::db`](super::db) for the example-based counterpart.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use madhouse::{
    execute_commands, prop_allof, scenario, Command, CommandWrapper, State, TestContext,
};
use pinny::tag;
use proptest::prelude::*;
use stacks_common::types::chainstate::BurnchainHeaderHash;

use crate::burnchains::bitcoin::{WatchedP2WSHOutput, WitnessScriptHash};
use crate::burnchains::db::BurnchainDB;
use crate::burnchains::{Burnchain, BurnchainBlockHeader, Txid};
use crate::core::BITCOIN_REGTEST_FIRST_BLOCK_HASH;

/// Fixed across the scenario so the prune threshold is reproducible.
const REWARD_CYCLE_LENGTH: u32 = 100;

/// Per-block output cap. Keeps each block small.
const MAX_OUTPUTS_PER_BLOCK: usize = 4;

/// Upper bound on generated block heights.
const MAX_HEIGHT: u64 = 10_000;

/// 32-byte hash derived from `height`. Distinct heights yield distinct hashes,
/// avoiding the PK collision of the example test's `[h as u8; 32]` (wraps at 256).
fn height_hash(height: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&height.to_le_bytes());
    bytes
}

fn header_at_height(height: u64, parent: BurnchainHeaderHash) -> BurnchainBlockHeader {
    BurnchainBlockHeader {
        block_height: height,
        block_hash: BurnchainHeaderHash(height_hash(height)),
        parent_block_hash: parent,
        num_txs: 0,
        timestamp: height,
    }
}

/// Deterministic P2WSH outputs for `(height, num_outputs)`, in `vout` order.
/// Distinct heights produce non-overlapping txids.
fn outputs_for_block(height: u64, num_outputs: usize) -> Vec<WatchedP2WSHOutput> {
    (0..num_outputs as u32)
        .map(|vout| {
            let mut txid_bytes = height_hash(height);
            txid_bytes[31] = vout as u8;
            let mut hash_bytes = height_hash(height);
            hash_bytes[30] = vout as u8;
            WatchedP2WSHOutput {
                txid: Txid(txid_bytes),
                vout,
                witness_script_hash: WitnessScriptHash(hash_bytes),
                amount: 1_000 * (vout as u64 + 1),
            }
        })
        .collect()
}

/// Block height + outputs expected on the DB side.
#[derive(Debug, Clone, PartialEq)]
struct BlockEntry {
    block_height: u64,
    outputs: Vec<WatchedP2WSHOutput>,
}

/// Model + real SUT for the watched-outputs scenario. Created fresh per proptest
/// case via `Default` (so `scenario!`/MADHOUSE walks stay independent without a
/// manual reset). `current_height` is model state (not SUT-driven):
/// `BurnchainDB::prune_watched_outputs` takes the tip as a parameter each call.
#[derive(Debug)]
struct WatchedOutputsState {
    current_height: u64,
    blocks: BTreeMap<BurnchainHeaderHash, BlockEntry>,
    sut: WatchedOutputsSut,
}

impl Default for WatchedOutputsState {
    fn default() -> Self {
        Self {
            current_height: 0,
            blocks: BTreeMap::new(),
            sut: WatchedOutputsSut::fresh(),
        }
    }
}

impl State for WatchedOutputsState {}

struct WatchedOutputsSut {
    db: BurnchainDB,
    /// Last header inserted; subsequent inserts use it as `parent_block_hash`
    /// to satisfy orphan constraints. Initialized to `BITCOIN_REGTEST_FIRST_BLOCK_HASH`.
    last_block_hash: BurnchainHeaderHash,
    /// Heights for which a header has already been recorded.
    seen_heights: BTreeSet<u64>,
}

impl WatchedOutputsSut {
    fn fresh() -> Self {
        let burnchain = Burnchain::regtest(":memory:");
        let db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();
        Self {
            db,
            last_block_hash: BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH)
                .unwrap(),
            seen_heights: BTreeSet::new(),
        }
    }

    fn store_block(&mut self, header: &BurnchainBlockHeader, outputs: &[WatchedP2WSHOutput]) {
        let db_tx = self.db.tx_begin().unwrap();
        db_tx.store_burnchain_db_entry(header).unwrap();
        db_tx.store_watched_outputs(header, outputs).unwrap();
        db_tx.commit().unwrap();
        self.last_block_hash = header.block_hash.clone();
        self.seen_heights.insert(header.block_height);
    }

    fn prune(&mut self, reward_cycle_length: u32, current_block_height: u64) {
        let db_tx = self.db.tx_begin().unwrap();
        db_tx
            .prune_watched_outputs(reward_cycle_length, current_block_height)
            .unwrap();
        db_tx.commit().unwrap();
    }

    fn outputs_at(&self, block_hash: &BurnchainHeaderHash) -> Vec<WatchedP2WSHOutput> {
        BurnchainDB::get_watched_outputs_at_block(self.db.conn(), block_hash).unwrap()
    }
}

impl std::fmt::Debug for WatchedOutputsSut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchedOutputsSut")
            .field("last_block_hash", &self.last_block_hash)
            .field("seen_heights_count", &self.seen_heights.len())
            .finish_non_exhaustive()
    }
}

/// Empty context: all mutable state (shadow model + the real DB) lives in
/// [`WatchedOutputsState`], so `scenario!` rebuilds it fresh per case.
#[derive(Clone, Debug, Default)]
pub struct WatchedOutputsContext;

impl TestContext for WatchedOutputsContext {}

/// Cross-check model against SUT block-by-block. Divergence panics with the
/// offending block hash.
fn check_invariants(state: &WatchedOutputsState) {
    // Direction 1: every block in the model has matching outputs in the DB.
    for (block_hash, entry) in &state.blocks {
        let db_outputs = state.sut.outputs_at(block_hash);
        // DB returns rows ordered by `(txid, vout)`. Shadow entries are
        // inserted in `vout` order with deterministic txids, so they share
        // the canonical ordering after sort.
        let mut expected = entry.outputs.clone();
        expected.sort_by(|a, b| (a.txid.0, a.vout).cmp(&(b.txid.0, b.vout)));
        let mut got = db_outputs.clone();
        got.sort_by(|a, b| (a.txid.0, a.vout).cmp(&(b.txid.0, b.vout)));
        assert_eq!(
            got, expected,
            "DB/shadow mismatch at block_hash={block_hash}: db={got:?}, model={expected:?}"
        );
    }

    // Direction 2: every block_hash the model says is gone has no rows in the
    // DB. Only block_hashes the SUT has seen can be enumerated (model.blocks
    // tracks what's still there; sut.seen_heights tracks what was ever inserted).
    for &height in &state.sut.seen_heights {
        let bh = BurnchainHeaderHash(height_hash(height));
        if !state.blocks.contains_key(&bh) {
            let db_rows = state.sut.outputs_at(&bh);
            assert!(
                db_rows.is_empty(),
                "DB has orphan rows at block_hash={bh} (height={height}), model has none"
            );
        }
    }
}

/// Store a block of P2WSH outputs at `height`. `check` asserts the block_hash
/// is fresh; re-inserts would violate the `burnchain_db_block_headers` PK.
struct StoreBlock {
    height: u64,
    num_outputs: usize,
}

impl Command<WatchedOutputsState, WatchedOutputsContext> for StoreBlock {
    fn check(&self, state: &WatchedOutputsState) -> bool {
        let bh = BurnchainHeaderHash(height_hash(self.height));
        !state.blocks.contains_key(&bh) && self.num_outputs > 0
    }

    fn apply(&self, state: &mut WatchedOutputsState) {
        let bh = BurnchainHeaderHash(height_hash(self.height));
        let outputs = outputs_for_block(self.height, self.num_outputs);
        let parent = state.sut.last_block_hash.clone();
        let header = header_at_height(self.height, parent);
        state.sut.store_block(&header, &outputs);
        state.blocks.insert(
            bh,
            BlockEntry {
                block_height: self.height,
                outputs,
            },
        );
        // Track max height seen on the model.
        if self.height > state.current_height {
            state.current_height = self.height;
        }
        check_invariants(state);
    }

    fn label(&self) -> String {
        format!("STORE_BLOCK(h={}, n={})", self.height, self.num_outputs)
    }

    fn build(
        _ctx: Arc<WatchedOutputsContext>,
    ) -> impl Strategy<Value = CommandWrapper<WatchedOutputsState, WatchedOutputsContext>> {
        (1u64..=MAX_HEIGHT, 1usize..=MAX_OUTPUTS_PER_BLOCK).prop_map(|(height, num_outputs)| {
            CommandWrapper::new(StoreBlock {
                height,
                num_outputs,
            })
        })
    }
}

/// Prune at `current_height`: both sides drop entries with
/// `block_height < current.saturating_sub(3 * RCL / 2)`.
struct PruneAtHeight {
    current_height: u64,
}

impl Command<WatchedOutputsState, WatchedOutputsContext> for PruneAtHeight {
    fn check(&self, _state: &WatchedOutputsState) -> bool {
        true
    }

    fn apply(&self, state: &mut WatchedOutputsState) {
        let rcl = REWARD_CYCLE_LENGTH;
        let window = (3u64 * u64::from(rcl)) / 2;
        let threshold = self.current_height.saturating_sub(window);

        state.sut.prune(rcl, self.current_height);

        // Shadow prune: remove blocks at `block_height < threshold`.
        state
            .blocks
            .retain(|_block_hash, entry| entry.block_height >= threshold);
        state.current_height = state.current_height.max(self.current_height);

        // Independent of the shadow: enumerate every inserted height and assert
        // the SUT has no rows below `threshold`. Catches a correctly-pruning SUT
        // even if the shadow itself has a retention bug.
        for &height in &state.sut.seen_heights {
            if height < threshold {
                let bh = BurnchainHeaderHash(height_hash(height));
                let rows = state.sut.outputs_at(&bh);
                assert!(
                    rows.is_empty(),
                    "post-prune SUT row at height {height} (threshold={threshold}): {rows:?}"
                );
            }
        }

        check_invariants(state);
    }

    fn label(&self) -> String {
        format!("PRUNE_AT(h={})", self.current_height)
    }

    fn build(
        _ctx: Arc<WatchedOutputsContext>,
    ) -> impl Strategy<Value = CommandWrapper<WatchedOutputsState, WatchedOutputsContext>> {
        (0u64..=MAX_HEIGHT)
            .prop_map(|current_height| CommandWrapper::new(PruneAtHeight { current_height }))
    }
}

/// Drive the watched-outputs store through random `StoreBlock`/`PruneAtHeight`
/// sequences. Default: deterministic order. `MADHOUSE=1`: random permutations
/// of 1..16 commands.
#[test]
#[cfg_attr(test, tag(t_prop))]
fn p2wsh_store_lifecycle_madhouse() {
    let ctx = Arc::new(WatchedOutputsContext);
    scenario![ctx, StoreBlock, PruneAtHeight]
}
