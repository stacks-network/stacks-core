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

//! Shared helpers for `clarity_vm` tests.

use clarity::vm::test_util::{generate_test_burn_state_db, TEST_BURN_STATE_DB, TEST_HEADER_DB};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::ClarityInstance;
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};

/// Runs genesis and applies the epoch transitions required to reach
/// `target_epoch`, committing each transition.
///
/// Returns the tip block ID to use as the parent for the next block in the
/// test.
///
/// Only epoch transitions that deploy a boot cost contract are applied,
/// following the mapping defined in
/// [`clarity::vm::costs::LimitedCostTracker::default_cost_contract_for_epoch`].
pub fn apply_transitions_for_epoch(
    clarity_instance: &mut ClarityInstance,
    target_epoch: StacksEpochId,
) -> StacksBlockId {
    let genesis_block =
        StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &genesis_block,
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    let mut tip = genesis_block;

    if target_epoch >= StacksEpochId::Epoch2_05 {
        let burn_db = generate_test_burn_state_db(StacksEpochId::Epoch20);
        let next = StacksBlockId([0xa1; 32]);
        let mut conn = clarity_instance.begin_block(&tip, &next, &TEST_HEADER_DB, &burn_db);
        conn.initialize_epoch_2_05().unwrap();
        conn.commit_block();
        tip = next;
    }
    if target_epoch >= StacksEpochId::Epoch21 {
        let burn_db = generate_test_burn_state_db(StacksEpochId::Epoch2_05);
        let next = StacksBlockId([0xa2; 32]);
        let mut conn = clarity_instance.begin_block(&tip, &next, &TEST_HEADER_DB, &burn_db);
        conn.initialize_epoch_2_1().unwrap();
        conn.commit_block();
        tip = next;
    }
    if target_epoch >= StacksEpochId::Epoch30 {
        let burn_db = generate_test_burn_state_db(StacksEpochId::Epoch21);
        let next = StacksBlockId([0xa3; 32]);
        let mut conn = clarity_instance.begin_block(&tip, &next, &TEST_HEADER_DB, &burn_db);
        conn.initialize_epoch_3_0().unwrap();
        conn.commit_block();
        tip = next;
    }
    if target_epoch >= StacksEpochId::Epoch33 {
        let burn_db = generate_test_burn_state_db(StacksEpochId::Epoch30);
        let next = StacksBlockId([0xa4; 32]);
        let mut conn = clarity_instance.begin_block(&tip, &next, &TEST_HEADER_DB, &burn_db);
        conn.initialize_epoch_3_3().unwrap();
        conn.commit_block();
        tip = next;
    }

    tip
}
