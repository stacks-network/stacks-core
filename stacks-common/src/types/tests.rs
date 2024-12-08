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

use super::{
    set_test_coinbase_schedule, CoinbaseInterval, StacksEpochId, COINBASE_INTERVALS_MAINNET,
    COINBASE_INTERVALS_TESTNET,
};

#[test]
fn test_mainnet_coinbase_emissions() {
    assert_eq!(COINBASE_INTERVALS_MAINNET.len(), 5);
    assert_eq!(COINBASE_INTERVALS_MAINNET[0].coinbase, 1_000_000_000);
    assert_eq!(COINBASE_INTERVALS_MAINNET[1].coinbase, 500_000_000);
    assert_eq!(COINBASE_INTERVALS_MAINNET[2].coinbase, 250_000_000);
    assert_eq!(COINBASE_INTERVALS_MAINNET[3].coinbase, 125_000_000);
    assert_eq!(COINBASE_INTERVALS_MAINNET[4].coinbase, 62_500_000);

    // heights from SIP-029
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
        1_050_000 - 666_050
    );
    assert_eq!(
        COINBASE_INTERVALS_MAINNET[3].effective_start_height,
        1_260_000 - 666_050
    );
    assert_eq!(
        COINBASE_INTERVALS_MAINNET[4].effective_start_height,
        1_470_000 - 666_050
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
            944_999 - 666050
        ),
        1_000_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            945_000 - 666050
        ),
        500_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            945_001 - 666050
        ),
        500_000_000
    );

    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_049_999 - 666050
        ),
        500_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_050_000 - 666050
        ),
        250_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_050_001 - 666050
        ),
        250_000_000
    );

    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_259_999 - 666050
        ),
        250_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_260_000 - 666050
        ),
        125_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_260_001 - 666050
        ),
        125_000_000
    );

    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_469_999 - 666050
        ),
        125_000_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_470_000 - 666050
        ),
        62_500_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            1_470_001 - 666050
        ),
        62_500_000
    );

    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            2_197_559 - 666050
        ),
        62_500_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            2_197_560 - 666050
        ),
        62_500_000
    );
    assert_eq!(
        CoinbaseInterval::get_coinbase_at_effective_height(
            &*COINBASE_INTERVALS_MAINNET,
            2_197_561 - 666050
        ),
        62_500_000
    );
}

#[test]
fn test_epoch_coinbase_reward() {
    // new coinbase schedule
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 666050),
        1_000_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 666051),
        1_000_000_000
    );

    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 944_999),
        1_000_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 945_000),
        500_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 945_001),
        500_000_000
    );

    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_049_999),
        500_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_050_000),
        250_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_050_001),
        250_000_000
    );

    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_259_999),
        250_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_260_000),
        125_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_260_001),
        125_000_000
    );

    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_469_999),
        125_000_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_470_000),
        62_500_000
    );
    assert_eq!(
        StacksEpochId::Epoch31.coinbase_reward(true, 666050, 1_470_001),
        62_500_000
    );

    // old coinbase schedule
    for epoch in [
        StacksEpochId::Epoch20,
        StacksEpochId::Epoch2_05,
        StacksEpochId::Epoch21,
        StacksEpochId::Epoch22,
        StacksEpochId::Epoch23,
        StacksEpochId::Epoch24,
        StacksEpochId::Epoch25,
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
