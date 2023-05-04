// Copyright (C) 2023 Stacks Open Internet Foundation
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

use std::env;

/// Verify the (buggy) stacks-increase behavior in PoX-2 does not occurs in PoX-3
// // disable_pox
fn disable_pox() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let reward_cycle_len = 10;
    let prepare_phase_len = 3;
    let epoch_2_05 = 215;
    let epoch_2_1 = 230;
    let v1_unlock_height = 231;
    let epoch_2_2 = 255; // two blocks before next prepare phase.
    let epoch_2_3 = 260;
    // TODO(pavi): verify
    let epoch_2_4 = 268; // two blocks before next prepare phase

    // TODO(pavi): add initial balances


}


/// Verify that PoX-3 stackers only begin receiving rewards at the start of the reward cycle
/// following the one that contains pox 3 activation height.
// // copy fn test_v1_unlock_height_with_current_stackers()

fn test_pox_3_activation_height() {
    let x = 5;
}