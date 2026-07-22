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
//!
//! These build a fresh [`ClarityInstance`] and walk it through the epoch
//! transitions that deploy the boot cost contracts, so tests run against the
//! `costs-N` contract that actually corresponds to the epoch under test.
//!
//! Supporting a new epoch's cost contract is a matter of appending it to
//! [`TEST_COST_BOOT_EPOCHS`] and adding the matching arm in
//! [`setup_cost_test_epoch`].

use clarity::vm::test_util::{generate_test_burn_state_db, TEST_BURN_STATE_DB, TEST_HEADER_DB};
use clarity::vm::tests::test_only_mainnet_to_chain_id;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::ClarityInstance;
use crate::clarity_vm::database::marf::MarfedKV;
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};

/// Epochs whose transition deploys a new boot cost contract, in order.
///
/// This mirrors the epoch → cost-contract mapping in
/// [`clarity::vm::costs::LimitedCostTracker::default_cost_contract_for_epoch`]:
/// only epochs that introduce a *new* `costs-N` contract are listed (e.g.
/// Epoch 3.0 reuses `costs-3` from Epoch 2.1, so it is intentionally absent).
pub const TEST_TEST_COST_BOOT_EPOCHS: [StacksEpochId; 4] = [
    StacksEpochId::Epoch2_05,
    StacksEpochId::Epoch21,
    StacksEpochId::Epoch33,
    StacksEpochId::Epoch40,
];

/// Produce a fresh, unique [`StacksBlockId`] for the next test block and
/// advance `block_id_byte` in place.
pub fn next_test_block_id(block_id_byte: &mut u8) -> StacksBlockId {
    let block_id = StacksBlockId([*block_id_byte; 32]);
    *block_id_byte += 1;
    block_id
}

/// Create a new [`ClarityInstance`] on a temporary MARF and commit its genesis
/// block.
///
/// Returns the instance, the genesis tip to build the next block on, and the
/// next free block-id byte to hand to [`next_test_block_id`].
pub fn new_cost_test_clarity_instance(use_mainnet: bool) -> (ClarityInstance, StacksBlockId, u8) {
    let marf_kv = MarfedKV::temporary();
    let chain_id = test_only_mainnet_to_chain_id(use_mainnet);
    let mut clarity_instance = ClarityInstance::new(use_mainnet, chain_id, marf_kv);

    let first_block = StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &first_block,
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    (clarity_instance, first_block, 1)
}

/// Apply the single epoch transition that deploys `setup_epoch`'s boot cost
/// contract, committing the block. `tip` and `block_id_byte` are advanced in
/// place.
pub fn setup_cost_test_epoch(
    clarity_instance: &mut ClarityInstance,
    tip: &mut StacksBlockId,
    block_id_byte: &mut u8,
    setup_epoch: StacksEpochId,
) {
    let burn_state_db = generate_test_burn_state_db(setup_epoch);
    let next_block = next_test_block_id(block_id_byte);
    let mut clarity_conn =
        clarity_instance.begin_block(tip, &next_block, &TEST_HEADER_DB, &burn_state_db);

    match setup_epoch {
        StacksEpochId::Epoch2_05 => {
            clarity_conn.initialize_epoch_2_05().unwrap();
        }
        StacksEpochId::Epoch21 => {
            clarity_conn.initialize_epoch_2_1().unwrap();
        }
        StacksEpochId::Epoch33 => {
            clarity_conn.initialize_epoch_3_3().unwrap();
        }
        StacksEpochId::Epoch40 => {
            // Epoch 4.0's `costs-5` is a native (default) cost function, not a
            // deployed Clarity boot contract, so only the epoch needs setting.
            // `initialize_epoch_4_0()` is avoided here because it also deploys
            // PoX-5, which requires the chainstate test harness's sBTC stubs.
            clarity_conn.set_epoch_for_testing(StacksEpochId::Epoch40);
        }
        _ => unreachable!(
            "TEST_COST_BOOT_EPOCHS only contains epochs which instantiate boot contracts needed for costs tests"
        ),
    }

    clarity_conn.commit_block();
    *tip = next_block;
}

/// Apply, in order, every epoch transition in [`TEST_COST_BOOT_EPOCHS`] up to and
/// including `epoch`, so the boot cost contract for `epoch` is available. `tip`
/// and `block_id_byte` are advanced in place.
pub fn setup_cost_test_epochs_through(
    clarity_instance: &mut ClarityInstance,
    tip: &mut StacksBlockId,
    block_id_byte: &mut u8,
    epoch: StacksEpochId,
) {
    for setup_epoch in TEST_TEST_COST_BOOT_EPOCHS {
        if epoch < setup_epoch {
            break;
        }

        setup_cost_test_epoch(clarity_instance, tip, block_id_byte, setup_epoch);
    }
}
