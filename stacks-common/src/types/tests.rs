// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::ops::Bound;
use std::str::FromStr;

use super::{
    set_test_coinbase_schedule, CoinbaseInterval, StacksEpochId,
    BITCOIN_MAINNET_GENESIS_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT,
    BITCOIN_TESTNET_GENESIS_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_40_BURN_HEIGHT,
    COINBASE_INTERVALS_MAINNET, COINBASE_INTERVALS_TESTNET,
};
use crate::types::StacksEpochRangeTestExt as _;

#[test]
fn test_epoch_range_ext_iter() {
    // Alias to keep the below cleaner
    fn epoch_index(epoch: StacksEpochId) -> usize {
        StacksEpochId::index_of(epoch)
    }

    // Full range is effectively equivalent to the ALL constant.
    assert_eq!((..).as_slice(), StacksEpochId::ALL);

    // Start = inclusive, end = unbounded
    assert_eq!(
        (StacksEpochId::Epoch32..).as_slice(),
        &StacksEpochId::ALL[epoch_index(StacksEpochId::Epoch32)..]
    );

    // Start = unbounded, end = exclusive
    assert_eq!(
        (..StacksEpochId::Epoch21).as_slice(),
        &[
            StacksEpochId::Epoch10,
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05
        ]
    );

    // Start = unbounded, end = inclusive
    assert_eq!(
        (..=StacksEpochId::Epoch21).as_slice(),
        &[
            StacksEpochId::Epoch10,
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21
        ]
    );

    // Start = inclusive, end = exclusive
    assert_eq!(
        (StacksEpochId::Epoch20..StacksEpochId::Epoch22).as_slice(),
        &[
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21
        ]
    );

    // Start = inclusive, end = inclusive
    assert_eq!(
        (StacksEpochId::Epoch20..=StacksEpochId::Epoch22).as_slice(),
        &[
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21,
            StacksEpochId::Epoch22
        ]
    );

    // Start = exclusive, end = unbounded (a'la `all_after`).
    let expected = &StacksEpochId::ALL[epoch_index(StacksEpochId::Epoch32) + 1..];
    assert_eq!(
        (Bound::Excluded(StacksEpochId::Epoch32), Bound::Unbounded).as_slice(),
        expected
    );
    assert_eq!(StacksEpochId::all_after(StacksEpochId::Epoch32), expected);

    // Single element range with exclusive end bound should yield empty.
    assert_eq!(
        (StacksEpochId::Epoch23..StacksEpochId::Epoch23).as_slice(),
        &[]
    );

    // Single element range with inclusive end bound should yield that item.
    assert_eq!(
        (StacksEpochId::Epoch23..=StacksEpochId::Epoch23).as_slice(),
        &[StacksEpochId::Epoch23]
    );

    // Reversed range should yield empty.
    assert_eq!(
        (StacksEpochId::Epoch22..StacksEpochId::Epoch20).as_slice(),
        &[]
    );
}

#[test]
fn test_stacks_epoch_id_display_fromstr_tryfrom_roundtrip() {
    for epoch in StacksEpochId::ALL {
        let s = epoch.to_string();
        assert_eq!(
            StacksEpochId::from_str(&s),
            Ok(*epoch),
            "Display/FromStr roundtrip failed for {epoch:?} -> {s:?}"
        );
        let u = *epoch as u32;
        assert_eq!(
            StacksEpochId::try_from(u),
            Ok(*epoch),
            "TryFrom<u32> roundtrip failed for {epoch:?} (0x{u:x})"
        );
    }
}

#[test]
fn test_epoch_id_first_last_helpers() {
    assert_eq!(StacksEpochId::first(), StacksEpochId::ALL[0]);
    assert_eq!(
        StacksEpochId::last(),
        StacksEpochId::ALL[StacksEpochId::ALL.len() - 1]
    );
    assert_eq!(StacksEpochId::ALL.first(), Some(&StacksEpochId::first()));
    assert_eq!(StacksEpochId::ALL.last(), Some(&StacksEpochId::last()));
}

#[test]
fn test_mainnet_coinbase_emissions() {
    assert_eq!(COINBASE_INTERVALS_MAINNET.len(), 3);
    assert_eq!(COINBASE_INTERVALS_MAINNET[0].coinbase, 1_000_000_000);
    assert_eq!(COINBASE_INTERVALS_MAINNET[1].coinbase, 500_000_000);
    assert_eq!(COINBASE_INTERVALS_MAINNET[2].coinbase, 1_000_000_000);

    // heights from SIP-029 and SIP-045

    assert_eq!(
        COINBASE_INTERVALS_MAINNET[0].effective_start_height,
        666_050 - 666_050
    );
    assert_eq!(
        COINBASE_INTERVALS_MAINNET[1].effective_start_height,
        945_000 - 666_050
    );
    assert_eq!(
        COINBASE_INTERVALS_MAINNET[2].effective_start_height,
        BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT - BITCOIN_MAINNET_GENESIS_BURN_HEIGHT
    );
}

#[test]
fn test_testnet_coinbase_emissions() {
    assert_eq!(COINBASE_INTERVALS_TESTNET.len(), 6);
    assert_eq!(COINBASE_INTERVALS_TESTNET[0].coinbase, 1_000_000_000);
    assert_eq!(COINBASE_INTERVALS_TESTNET[1].coinbase, 500_000_000);
    assert_eq!(COINBASE_INTERVALS_TESTNET[2].coinbase, 250_000_000);
    assert_eq!(COINBASE_INTERVALS_TESTNET[3].coinbase, 125_000_000);
    assert_eq!(COINBASE_INTERVALS_TESTNET[4].coinbase, 62_500_000);
    assert_eq!(COINBASE_INTERVALS_TESTNET[5].coinbase, 1_000_000_000);

    assert_eq!(COINBASE_INTERVALS_TESTNET[0].effective_start_height, 0);
    assert_eq!(COINBASE_INTERVALS_TESTNET[1].effective_start_height, 77_777);
    assert_eq!(
        COINBASE_INTERVALS_TESTNET[2].effective_start_height,
        77_777 * 7
    );
    assert_eq!(
        COINBASE_INTERVALS_TESTNET[3].effective_start_height,
        77_777 * 14
    );
    assert_eq!(
        COINBASE_INTERVALS_TESTNET[4].effective_start_height,
        77_777 * 21
    );
    assert_eq!(
        COINBASE_INTERVALS_TESTNET[5].effective_start_height,
        BITCOIN_TESTNET_STACKS_40_BURN_HEIGHT - BITCOIN_TESTNET_GENESIS_BURN_HEIGHT
    );
}

#[test]
fn test_get_coinbase_at_effective_height() {
    assert!(CoinbaseInterval::check_order(&*COINBASE_INTERVALS_MAINNET));

    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            666050 - 666050
        ),
        1_000_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            666051 - 666050
        ),
        1_000_000_000
    );

    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            944_999 - 666_050
        ),
        1_000_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            945_000 - 666_050
        ),
        500_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            945_001 - 666_050
        ),
        500_000_000
    );

    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT - BITCOIN_MAINNET_GENESIS_BURN_HEIGHT - 1
        ),
        500_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT - BITCOIN_MAINNET_GENESIS_BURN_HEIGHT
        ),
        1_000_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT - BITCOIN_MAINNET_GENESIS_BURN_HEIGHT + 1
        ),
        1_000_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            2_000_000 - BITCOIN_MAINNET_GENESIS_BURN_HEIGHT
        ),
        1_000_000_000
    );
}

#[test]
fn test_epoch_coinbase_reward() {
    // new coinbase schedule
    for epoch in [StacksEpochId::Epoch31, StacksEpochId::Epoch32].iter() {
        assert_eq!(epoch.coinbase_reward(true, 666050, 666050), 1_000_000_000);
        assert_eq!(epoch.coinbase_reward(true, 666050, 666051), 1_000_000_000);

        assert_eq!(epoch.coinbase_reward(true, 666050, 944_999), 1_000_000_000);
        assert_eq!(epoch.coinbase_reward(true, 666050, 945_000), 500_000_000);
        assert_eq!(epoch.coinbase_reward(true, 666050, 945_001), 500_000_000);

        assert_eq!(
            epoch.coinbase_reward(true, 666050, BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT - 1),
            500_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT),
            1_000_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, BITCOIN_MAINNET_STACKS_40_BURN_HEIGHT + 1),
            1_000_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 2_000_000),
            1_000_000_000
        );
    }

    // old coinbase schedule
    for epoch in [
        StacksEpochId::Epoch20,
        StacksEpochId::Epoch2_05,
        StacksEpochId::Epoch21,
        StacksEpochId::Epoch22,
        StacksEpochId::Epoch23,
        StacksEpochId::Epoch24,
        StacksEpochId::Epoch25,
        StacksEpochId::Epoch30,
    ]
    .iter()
    {
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 4 - 1),
            1_000_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 4),
            500_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 4 + 1),
            500_000_000
        );

        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 8 - 1),
            500_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 8),
            250_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 8 + 1),
            250_000_000
        );

        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 12 - 1),
            250_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 12),
            125_000_000
        );
        assert_eq!(
            epoch.coinbase_reward(true, 666050, 666050 + 52596 * 12 + 1),
            125_000_000
        );
    }
}

/// Verifies that the test facility for setting a coinbase schedule in a unit or integration test
/// actually works.
#[test]
fn test_set_coinbase_intervals() {
    let new_sched = vec![
        CoinbaseInterval {
            coinbase: 1,
            effective_start_height: 0,
        },
        CoinbaseInterval {
            coinbase: 2,
            effective_start_height: 1,
        },
        CoinbaseInterval {
            coinbase: 3,
            effective_start_height: 2,
        },
        CoinbaseInterval {
            coinbase: 4,
            effective_start_height: 3,
        },
        CoinbaseInterval {
            coinbase: 5,
            effective_start_height: 4,
        },
    ];

    assert_eq!(
        StacksEpochId::get_coinbase_intervals(true),
        *COINBASE_INTERVALS_MAINNET
    );
    assert_eq!(
        StacksEpochId::get_coinbase_intervals(false),
        *COINBASE_INTERVALS_TESTNET
    );

    set_test_coinbase_schedule(Some(new_sched.clone()));

    assert_eq!(StacksEpochId::get_coinbase_intervals(true), new_sched);
    assert_eq!(StacksEpochId::get_coinbase_intervals(false), new_sched);

    set_test_coinbase_schedule(None);

    assert_eq!(
        StacksEpochId::get_coinbase_intervals(true),
        *COINBASE_INTERVALS_MAINNET
    );
    assert_eq!(
        StacksEpochId::get_coinbase_intervals(false),
        *COINBASE_INTERVALS_TESTNET
    );
}
