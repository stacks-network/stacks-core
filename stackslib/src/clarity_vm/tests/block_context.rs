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

//! Tests for `ClarityDatabase` behavior that depends on a MARF-backed store,
//! where multiple blocks can be committed and the read context can be shifted
//! between them via `set_block_hash`. `MemoryBackingStore` does not support
//! these scenarios (its `set_block_hash` returns an error).

use clarity::vm::test_util::{TEST_BURN_STATE_DB, TEST_HEADER_DB};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::{ClarityMarfStore, ClarityMarfStoreTransaction};
use crate::clarity_vm::database::marf::MarfedKV;

/// Regression test: when `set_block_hash` switches the MARF context to a
/// block that was committed under a different epoch, `get_clarity_epoch_version`
/// must reflect the target block's stored epoch, not the constructor's epoch.
/// Also verifies that restoring the prior block hash with `set_block_hash`
/// correctly returns the cached epoch to the original value.
#[test]
fn epoch_cache_updates_on_set_block_hash() {
    let mut marf_kv = MarfedKV::temporary();
    let block_0 = StacksBlockId([0; 32]);
    let block_1 = StacksBlockId([1; 32]);
    let block_2 = StacksBlockId([2; 32]);

    // Block 0: initialize and set epoch to Epoch21
    {
        let mut store = marf_kv.begin(&StacksBlockId::sentinel(), &block_0);
        let mut db = store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB);
        db.initialize();
        db.begin();
        db.set_clarity_epoch_version(StacksEpochId::Epoch21)
            .unwrap();
        db.commit().unwrap();
        store.test_commit();
    }

    // Block 1: bump epoch to Epoch25
    {
        let mut store = marf_kv.begin(&block_0, &block_1);
        let mut db = store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB);
        db.begin();
        db.set_clarity_epoch_version(StacksEpochId::Epoch25)
            .unwrap();
        db.commit().unwrap();
        store.test_commit();
    }

    // Block 2: start in Epoch25, then set_block_hash back to block_0 (Epoch21)
    {
        let mut store = marf_kv.begin(&block_1, &block_2);
        let mut db = store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB);
        db.begin();
        assert_eq!(
            db.get_clarity_epoch_version().unwrap(),
            StacksEpochId::Epoch25
        );

        // Time-shift to block_0 which has Epoch21 stored.
        let prior_bhh = db.set_block_hash(block_0, false).unwrap();
        assert_eq!(
            db.get_clarity_epoch_version().unwrap(),
            StacksEpochId::Epoch21,
            "epoch should reflect the target block after set_block_hash"
        );

        // Explicitly restore the original block context. This also
        // invalidates the cached epoch so the next read picks up Epoch25.
        db.set_block_hash(prior_bhh, true).unwrap();
        assert_eq!(
            db.get_clarity_epoch_version().unwrap(),
            StacksEpochId::Epoch25,
            "epoch should revert to the original value after restoring the block hash"
        );
    }
}
