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

//! Tests for the Epoch 4.0 / PoX-5 placement checks in
//! `validate_nakamoto_transition_schedule`. The fixture uses
//! `first_block_height = 100`, `reward_cycle_length = 10`,
//! `prepare_length = 3`. Reward-phase offsets are 1..=7 (mod-0 and
//! mod-8/9 are prepare-phase per `is_in_prepare_phase`. Offset 1
//! is disallowed because of historical ambiguity.

use clarity::vm::costs::ExecutionCost;
use stacks_common::types::chainstate::BurnchainHeaderHash;

use crate::burnchains::{Burnchain, PoxConstants};
use crate::core::{StacksEpoch, StacksEpochExtension, StacksEpochId, STACKS_EPOCH_MAX};

const FIRST_BLOCK_HEIGHT: u64 = 100;
const RC_LEN: u64 = 10;

fn test_burnchain(pox_5_activation: u32) -> Burnchain {
    let mut b = Burnchain::default_unittest(FIRST_BLOCK_HEIGHT, &BurnchainHeaderHash([0; 32]));
    let mut pox = PoxConstants::new(
        RC_LEN as u32,
        3,
        3,
        25,
        5,
        u64::MAX,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    );
    pox.pox_5_activation_height = pox_5_activation;
    b.pox_constants = pox;
    b
}

fn epoch(epoch_id: StacksEpochId, start_height: u64, end_height: u64) -> StacksEpoch {
    StacksEpoch {
        epoch_id,
        start_height,
        end_height,
        block_limit: ExecutionCost::max_value(),
        network_epoch: StacksEpochId::network_epoch(epoch_id),
    }
}

/// Build a minimal epoch list spanning Epoch 1.0 through `last`. Heights
/// for Epoch 2.5, 3.0, 4.0 are tunable; earlier epochs are placed at
/// non-overlapping positions before `epoch_2_5_start` and are not
/// inspected by `validate_nakamoto_transition_schedule`.
fn epoch_list(
    epoch_2_5_start: u64,
    epoch_3_0_start: u64,
    epoch_4_0_start: Option<u64>,
) -> Vec<StacksEpoch> {
    let mut epochs = vec![
        epoch(StacksEpochId::Epoch10, 0, 1),
        epoch(StacksEpochId::Epoch20, 1, 2),
        epoch(StacksEpochId::Epoch2_05, 2, 3),
        epoch(StacksEpochId::Epoch21, 3, 4),
        epoch(StacksEpochId::Epoch22, 4, 5),
        epoch(StacksEpochId::Epoch23, 5, 6),
        epoch(StacksEpochId::Epoch24, 6, epoch_2_5_start),
        epoch(StacksEpochId::Epoch25, epoch_2_5_start, epoch_3_0_start),
    ];
    match epoch_4_0_start {
        Some(e4) => {
            epochs.push(epoch(StacksEpochId::Epoch30, epoch_3_0_start, e4));
            epochs.push(epoch(StacksEpochId::Epoch40, e4, STACKS_EPOCH_MAX));
        }
        None => {
            epochs.push(epoch(
                StacksEpochId::Epoch30,
                epoch_3_0_start,
                STACKS_EPOCH_MAX,
            ));
        }
    }
    epochs
}

// Safe baseline: Epoch 2.5 at cycle 1 mod-0, Epoch 3.0 at cycle 2 mod-5
// (reward phase, offset > 1), Epoch 4.0 at cycle 4 mod-5 (reward phase,
// offset > 1, distinct cycle). pox_5_activation matches Epoch 4.0 start.
fn safe_fixture() -> (Vec<StacksEpoch>, Burnchain) {
    let epoch_4_0_start = FIRST_BLOCK_HEIGHT + 4 * RC_LEN + 5;
    (
        epoch_list(
            FIRST_BLOCK_HEIGHT + RC_LEN,
            FIRST_BLOCK_HEIGHT + 2 * RC_LEN + 5,
            Some(epoch_4_0_start),
        ),
        test_burnchain(epoch_4_0_start as u32),
    )
}

#[test]
fn accepts_safe_placement() {
    let (epochs, b) = safe_fixture();
    StacksEpoch::validate_nakamoto_transition_schedule(&epochs, &b);
}

#[test]
fn accepts_pre_epoch_40_schedule() {
    // No Epoch 4.0 in the list: the Epoch 4.0 branch must be a no-op.
    let epochs = epoch_list(
        FIRST_BLOCK_HEIGHT + RC_LEN,
        FIRST_BLOCK_HEIGHT + 2 * RC_LEN + 5,
        None,
    );
    let b = test_burnchain(u32::MAX);
    StacksEpoch::validate_nakamoto_transition_schedule(&epochs, &b);
}

#[test]
fn skips_epoch_40_checks_when_pox_5_activation_unpinned() {
    // A pox_5_activation_height that doesn't match Epoch 4.0 start is
    // treated as "PoX-5 not yet configured for this fixture" and the
    // checks are skipped -- even if the placement would otherwise be
    // rejected (here: mod-9 of cycle 4, a prepare-phase block).
    let bad_start = FIRST_BLOCK_HEIGHT + 4 * RC_LEN + 9;
    let epochs = epoch_list(
        FIRST_BLOCK_HEIGHT + RC_LEN,
        FIRST_BLOCK_HEIGHT + 2 * RC_LEN + 5,
        Some(FIRST_BLOCK_HEIGHT + 4 * RC_LEN + 5),
    );
    // pox_5_activation points at the bad placement, but Epoch 4.0 start
    // is at the safe placement -- the mismatch causes an early return
    // before any placement check is evaluated.
    let b = test_burnchain(bad_start as u32);
    StacksEpoch::validate_nakamoto_transition_schedule(&epochs, &b);
}

#[test]
#[should_panic(expected = "must fall during a reward phase")]
fn rejects_pox_5_activation_in_prepare_phase() {
    // mod-9 of cycle 4 = a prepare-phase block.
    let bad_start = FIRST_BLOCK_HEIGHT + 4 * RC_LEN + 9;
    let epochs = epoch_list(
        FIRST_BLOCK_HEIGHT + RC_LEN,
        FIRST_BLOCK_HEIGHT + 2 * RC_LEN + 5,
        Some(bad_start),
    );
    let b = test_burnchain(bad_start as u32);
    StacksEpoch::validate_nakamoto_transition_schedule(&epochs, &b);
}

#[test]
#[should_panic(expected = "must not fall on a reward cycle boundary")]
fn rejects_pox_5_activation_at_offset_one() {
    // Offset 1 (mod-1) -- reward phase per is_in_prepare_phase but
    // boundary-ambiguous per the floor-division in waterfall.
    let bad_start = FIRST_BLOCK_HEIGHT + 4 * RC_LEN + 1;
    let epochs = epoch_list(
        FIRST_BLOCK_HEIGHT + RC_LEN,
        FIRST_BLOCK_HEIGHT + 2 * RC_LEN + 5,
        Some(bad_start),
    );
    let b = test_burnchain(bad_start as u32);
    StacksEpoch::validate_nakamoto_transition_schedule(&epochs, &b);
}

#[test]
#[should_panic(expected = "must not be in the same reward cycle")]
fn rejects_epoch_30_and_epoch_40_in_same_cycle() {
    // Both Epoch 3.0 and Epoch 4.0 fall in cycle 2 (offsets 3 and 5).
    let epoch_3_0_start = FIRST_BLOCK_HEIGHT + 2 * RC_LEN + 3;
    let epoch_4_0_start = FIRST_BLOCK_HEIGHT + 2 * RC_LEN + 5;
    let epochs = epoch_list(
        FIRST_BLOCK_HEIGHT + RC_LEN,
        epoch_3_0_start,
        Some(epoch_4_0_start),
    );
    let b = test_burnchain(epoch_4_0_start as u32);
    StacksEpoch::validate_nakamoto_transition_schedule(&epochs, &b);
}
