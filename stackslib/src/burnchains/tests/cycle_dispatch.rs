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

//! Tests for the cycle-keyed PoX-contract dispatch
//! (`PoxConstants::active_pox_contract_for_cycle`) and its agreement with the
//! waterfall boundary (`first_pox_waterfall_block`).

use crate::burnchains::PoxConstants;
use crate::chainstate::stacks::boot::{POX_4_NAME, POX_5_NAME};

// Reward cycle layout used by these tests: first_block_height = 100,
// reward_cycle_length = 10, prepare_length = 3. Each cycle K spans burn
// heights [100 + K*10, 100 + (K+1)*10), where mod-0 (offset 0) and the
// last `prepare_length - 1` offsets (8, 9) are prepare-phase blocks per
// `is_in_prepare_phase`.
fn pox_constants_with_pox_5_at(activation: u32) -> PoxConstants {
    // v1_unlock = v2_unlock = v3_unlock (= pox_4_activation) = pox_3_activation = 0
    // so the pre-PoX-5 fallback returns POX_4_NAME for any cycle whose
    // reward-phase start is > 0.
    let mut c = PoxConstants::new(10, 3, 3, 25, 5, u64::MAX, u64::MAX, 0, 0, 0, 0, u32::MAX);
    c.pox_5_activation_height = activation;
    c
}

#[test]
fn cycle_predicate_agrees_with_waterfall_when_activation_in_reward_phase() {
    // pox_5_activation at offset 5 of cycle 3 (reward phase).
    let first = 100u64;
    let c = pox_constants_with_pox_5_at((first + 3 * 10 + 5) as u32);

    let wf = c.first_pox_waterfall_block(first).expect("waterfall set");
    // Cycle containing activation (cycle 3) is the last classic cycle;
    // cycle 4 onward is PoX-5.
    assert_eq!(wf, first + 4 * 10);
    assert_eq!(c.active_pox_contract_for_cycle(first, 3), POX_4_NAME);
    assert_eq!(c.active_pox_contract_for_cycle(first, 4), POX_5_NAME);
    assert_eq!(c.active_pox_contract_for_cycle(first, 5), POX_5_NAME);
}

#[test]
fn cycle_predicate_is_stable_across_prepare_phase_for_first_pox5_cycle() {
    // Place activation deep inside the prepare phase that sets up the
    // first PoX-5 cycle. Tip-keyed `active_pox_contract` would return
    // POX_4 for some blocks and POX_5 for others; the cycle-keyed
    // predicate must answer consistently for the cycle as a whole.
    let first = 100u64;
    // offset 9 of cycle 3 = a prepare-phase block of cycle 3 (mod-9).
    let activation = first + 3 * 10 + 9;
    let c = pox_constants_with_pox_5_at(activation as u32);

    // Tip-keyed dispatch genuinely disagrees across the prepare phase:
    // mod-8 of cycle 3 returns POX_4 (burn_height < activation), but
    // mod-0 of cycle 4 returns POX_5 (burn_height > activation).
    let prepare_start = first + 3 * 10 + 8;
    let prepare_end = first + 4 * 10; // mod-0 of cycle 4
    assert_eq!(c.active_pox_contract(prepare_start), POX_4_NAME);
    assert_eq!(c.active_pox_contract(prepare_end), POX_5_NAME);

    // The cycle-keyed predicate is the single source of truth.
    // first_pox_waterfall_block puts cycle 3 as the last classic cycle
    // (it contains the activation height), so cycle 4 is first PoX-5.
    assert_eq!(c.active_pox_contract_for_cycle(first, 3), POX_4_NAME);
    assert_eq!(c.active_pox_contract_for_cycle(first, 4), POX_5_NAME);
}

#[test]
fn cycle_predicate_handles_cycle_boundary_activation() {
    // Activation at mod-0 of cycle 3 (a boundary the validation will
    // reject, but the predicate must still answer consistently for
    // any caller that bypasses validation).
    let first = 100u64;
    let activation = first + 3 * 10;
    let c = pox_constants_with_pox_5_at(activation as u32);

    // `block_height_to_reward_cycle` floor-divides activation into
    // cycle 3, so cycle 4 is the first waterfall cycle.
    let wf = c.first_pox_waterfall_block(first).expect("waterfall set");
    assert_eq!(wf, first + 4 * 10);
    assert_eq!(c.active_pox_contract_for_cycle(first, 3), POX_4_NAME);
    assert_eq!(c.active_pox_contract_for_cycle(first, 4), POX_5_NAME);
}

#[test]
fn cycle_predicate_returns_pre_pox5_when_activation_unconfigured() {
    // pox_5_activation_height pushed far past any cycle we'll query =>
    // waterfall is configured but unreachable.
    let first = 100u64;
    let c = pox_constants_with_pox_5_at(u32::MAX);

    // The pre-PoX-5 cascade resolves to POX_4 here (pox_4_activation =
    // 0 in the helper), confirming the fallback path is taken even
    // though `first_pox_waterfall_block` returns a value.
    assert_eq!(c.active_pox_contract_for_cycle(first, 5), POX_4_NAME);
}
