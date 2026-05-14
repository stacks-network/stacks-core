// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::cmp::Ordering;
use std::fmt;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::str::FromStr;
use std::sync::LazyLock;

#[cfg(feature = "rusqlite")]
pub mod sqlite;

use crate::address::c32::{c32_address, c32_address_decode};
use crate::address::{
    public_keys_to_address_hash, to_bits_p2pkh, AddressHashMode,
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use crate::codec::{read_next, write_next, Error as CodecError, StacksMessageCodec};
use crate::consts::{
    MICROSTACKS_PER_STACKS, PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0,
    PEER_VERSION_EPOCH_2_05, PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2,
    PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4, PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0,
    PEER_VERSION_EPOCH_3_1, PEER_VERSION_EPOCH_3_2, PEER_VERSION_EPOCH_3_3, PEER_VERSION_EPOCH_3_4,
    PEER_VERSION_EPOCH_4_0, STACKS_EPOCH_MAX,
};
use crate::types::chainstate::{StacksAddress, StacksPublicKey};
use crate::util::hash::Hash160;
use crate::util::secp256k1::{MessageSignature, Secp256k1PublicKey};

pub mod chainstate;
pub mod net;

#[cfg(test)]
pub mod tests;

/// A container for public keys (compressed secp256k1 public keys)
pub struct StacksPublicKeyBuffer(pub [u8; 33]);
impl_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_array_hexstring_fmt!(StacksPublicKeyBuffer);
impl_byte_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_byte_array_message_codec!(StacksPublicKeyBuffer, 33);
impl_byte_array_serde!(StacksPublicKeyBuffer);

impl StacksPublicKeyBuffer {
    pub fn from_public_key(pubkey: &Secp256k1PublicKey) -> StacksPublicKeyBuffer {
        let pubkey_bytes_vec = pubkey.to_bytes_compressed();
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&pubkey_bytes_vec[..]);
        StacksPublicKeyBuffer(pubkey_bytes)
    }

    pub fn to_public_key(&self) -> Result<Secp256k1PublicKey, &'static str> {
        Secp256k1PublicKey::from_slice(&self.0)
            .map_err(|_e_str| "Failed to decode Stacks public key")
    }
}

pub trait PublicKey: Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str>;
}

pub trait PrivateKey: Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str>;
    #[cfg(any(test, feature = "testing"))]
    fn sign_with_noncedata(
        &self,
        data_hash: &[u8],
        noncedata: &[u8; 32],
    ) -> Result<MessageSignature, &'static str>;
}

pub trait Address: Clone + fmt::Debug + fmt::Display {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_string(from: &str) -> Option<Self>
    where
        Self: Sized;
    fn is_burn(&self) -> bool;
}

// sliding burnchain window over which a miner's past block-commit payouts will be used to weight
// its current block-commit in a sortition.
// This is the value used in epoch 2.x
pub const MINING_COMMITMENT_WINDOW: u8 = 6;

// how often a miner must commit in its mining commitment window in order to even be considered for
// sortition.
// Only relevant for Nakamoto (epoch 3.x)
pub const MINING_COMMITMENT_FREQUENCY_NAKAMOTO: u8 = 3;

macro_rules! define_stacks_epochs {
    ($($variant:ident = $value:expr => $display:expr),* $(,)?) => {
        #[repr(u32)]
        #[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum StacksEpochId {
            $($variant = $value),*
        }

        impl StacksEpochId {
            pub const ALL: &'static [StacksEpochId] = &[
                $(StacksEpochId::$variant),*
            ];
        }

        impl std::fmt::Display for StacksEpochId {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(StacksEpochId::$variant => f.write_str($display),)*
                }
            }
        }

        impl FromStr for StacksEpochId {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($display => Ok(StacksEpochId::$variant),)*
                    _ => Err("Invalid epoch string"),
                }
            }
        }

        impl TryFrom<u32> for StacksEpochId {
            type Error = &'static str;

            fn try_from(value: u32) -> Result<StacksEpochId, Self::Error> {
                match value {
                    $(x if x == StacksEpochId::$variant as u32 => Ok(StacksEpochId::$variant),)*
                    _ => Err("Invalid epoch"),
                }
            }
        }
    };
}

define_stacks_epochs! {
    Epoch10 = 0x01000 => "1.0",
    Epoch20 = 0x02000 => "2.0",
    Epoch2_05 = 0x02005 => "2.05",
    Epoch21 = 0x0200a => "2.1",
    Epoch22 = 0x0200f => "2.2",
    Epoch23 = 0x02014 => "2.3",
    Epoch24 = 0x02019 => "2.4",
    Epoch25 = 0x0201a => "2.5",
    Epoch30 = 0x03000 => "3.0",
    Epoch31 = 0x03001 => "3.1",
    Epoch32 = 0x03002 => "3.2",
    Epoch33 = 0x03003 => "3.3",
    Epoch34 = 0x03004 => "3.4",
    Epoch40 = 0x04000 => "4.0",
}

#[derive(Debug)]
pub enum MempoolCollectionBehavior {
    ByStacksHeight,
    ByReceiveTime,
}

/// Struct describing an interval of time (measured in burnchain blocks) during which a coinbase is
/// allotted.  Applies to SIP-029 code paths and later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoinbaseInterval {
    /// amount of uSTX to award
    pub coinbase: u128,
    /// height of the chain after Stacks chain genesis at which this coinbase interval starts
    pub effective_start_height: u64,
}

// From SIP-029:
//
// | Coinbase Interval  | Bitcoin Height | Offset Height       | Approx. Supply   | STX Reward | Annual Inflation |
// |--------------------|----------------|---------------------|------------------|------------|------------------|
// | Current            | -              | -                   | 1,552,452,847    | 1000       | -                |
// | 1st                |   945,000      |   278,950           | 1,627,352,847    | 500 (50%)  | 3.23%            |
// | 2nd                | 1,050,000      |   383,950           | 1,679,852,847    | 250 (50%)  | 1.57%            |
// | 3rd                | 1,260,000      |   593,950           | 1,732,352,847    | 125 (50%)  | 0.76%            |
// | 4th                | 1,470,000      |   803,950           | 1,758,602,847    | 62.5 (50%) | 0.37%            |
// | -                  | 2,197,560      | 1,531,510           | 1,804,075,347    | 62.5 (0%)  | 0.18%            |
//
// The above is for mainnet, which has a burnchain year of 52596 blocks and starts at burnchain height 666050.

/// Mainnet coinbase intervals, as of SIP-029
pub static COINBASE_INTERVALS_MAINNET: LazyLock<[CoinbaseInterval; 5]> = LazyLock::new(|| {
    let emissions_schedule = [
        CoinbaseInterval {
            coinbase: 1_000 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 0,
        },
        CoinbaseInterval {
            coinbase: 500 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 278_950,
        },
        CoinbaseInterval {
            coinbase: 250 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 383_950,
        },
        CoinbaseInterval {
            coinbase: 125 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 593_950,
        },
        CoinbaseInterval {
            coinbase: (625 * u128::from(MICROSTACKS_PER_STACKS)) / 10,
            effective_start_height: 803_950,
        },
    ];
    assert!(CoinbaseInterval::check_order(&emissions_schedule));
    emissions_schedule
});

/// Testnet coinbase intervals, as of SIP-029
pub static COINBASE_INTERVALS_TESTNET: LazyLock<[CoinbaseInterval; 5]> = LazyLock::new(|| {
    let emissions_schedule = [
        CoinbaseInterval {
            coinbase: 1_000 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 0,
        },
        CoinbaseInterval {
            coinbase: 500 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777,
        },
        CoinbaseInterval {
            coinbase: 250 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777 * 7,
        },
        CoinbaseInterval {
            coinbase: 125 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777 * 14,
        },
        CoinbaseInterval {
            coinbase: (625 * u128::from(MICROSTACKS_PER_STACKS)) / 10,
            effective_start_height: 77_777 * 21,
        },
    ];
    assert!(CoinbaseInterval::check_order(&emissions_schedule));
    emissions_schedule
});

/// Used for testing to substitute a coinbase schedule
#[cfg(any(test, feature = "testing"))]
pub static COINBASE_INTERVALS_TEST: std::sync::Mutex<Option<Vec<CoinbaseInterval>>> =
    std::sync::Mutex::new(None);

#[cfg(any(test, feature = "testing"))]
pub fn set_test_coinbase_schedule(coinbase_schedule: Option<Vec<CoinbaseInterval>>) {
    match COINBASE_INTERVALS_TEST.lock() {
        Ok(mut schedule_guard) => {
            *schedule_guard = coinbase_schedule;
        }
        Err(_e) => {
            panic!("COINBASE_INTERVALS_TEST mutex poisoned");
        }
    }
}

impl CoinbaseInterval {
    /// Look up the value of a coinbase at an effective height.
    /// Precondition: `intervals` must be sorted in ascending order by `effective_start_height`
    pub fn get_coinbase_at_effective_height(
        intervals: &[CoinbaseInterval],
        effective_height: u64,
    ) -> u128 {
        if intervals.is_empty() {
            return 0;
        }
        if intervals.len() == 1 {
            if intervals[0].effective_start_height <= effective_height {
                return intervals[0].coinbase;
            } else {
                return 0;
            }
        }

        for i in 0..(intervals.len() - 1) {
            if intervals[i].effective_start_height <= effective_height
                && effective_height < intervals[i + 1].effective_start_height
            {
                return intervals[i].coinbase;
            }
        }

        // in last interval, which per the above checks is guaranteed to exist
        intervals.last().unwrap_or_else(|| unreachable!()).coinbase
    }

    /// Verify that a list of intervals is sorted in ascending order by `effective_start_height`
    pub fn check_order(intervals: &[CoinbaseInterval]) -> bool {
        if intervals.len() < 2 {
            return true;
        }

        let mut ht = intervals[0].effective_start_height;
        for interval in intervals.iter().skip(1) {
            if interval.effective_start_height < ht {
                return false;
            }
            ht = interval.effective_start_height;
        }
        true
    }
}

/// Struct describing the intervals in which SIP-031 emission are applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SIP031EmissionInterval {
    /// amount of uSTX to emit
    pub amount: u128,
    /// height of the burn chain in which the interval starts
    pub start_height: u64,
}

// From SIP-031:
//
// | Bitcoin Height | STX Emission |
// |----------------|------------  |
// |   907,740      |     475      |
// |   960,300      |   1,140      |
// | 1,012,860      |   1,705      |
// | 1,065,420      |   1,305      |
// | 1,117,980      |   1,155      |
// | 1,170,540      |       0      |

/// Mainnet sip-031 emission intervals
pub static SIP031_EMISSION_INTERVALS_MAINNET: LazyLock<[SIP031EmissionInterval; 6]> =
    LazyLock::new(|| {
        let emissions_schedule = [
            SIP031EmissionInterval {
                amount: 0,
                start_height: 1_170_540,
            },
            SIP031EmissionInterval {
                amount: 1_155 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 1_117_980,
            },
            SIP031EmissionInterval {
                amount: 1_305 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 1_065_420,
            },
            SIP031EmissionInterval {
                amount: 1_705 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 1_012_860,
            },
            SIP031EmissionInterval {
                amount: 1_140 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 960_300,
            },
            SIP031EmissionInterval {
                amount: 475 * u128::from(MICROSTACKS_PER_STACKS),
                start_height: 907_740,
            },
        ];
        assert!(SIP031EmissionInterval::check_inversed_order(
            &emissions_schedule
        ));
        emissions_schedule
    });

/// Testnet sip-031 emission intervals (starting from 71_525, 1 interval every 360 bitcoin blocks)
pub static SIP031_EMISSION_INTERVALS_TESTNET: LazyLock<[SIP031EmissionInterval; 6]> =
    LazyLock::new(|| {
        let emissions_schedule = [
            SIP031EmissionInterval {
                amount: 0,
                start_height: 71_525 + (360 * 6),
            },
            SIP031EmissionInterval {
                amount: 5_000,
                start_height: 71_525 + (360 * 5),
            },
            SIP031EmissionInterval {
                amount: 4_000,
                start_height: 71_525 + (360 * 4),
            },
            SIP031EmissionInterval {
                amount: 3_000,
                start_height: 71_525 + (360 * 3),
            },
            SIP031EmissionInterval {
                amount: 2_000,
                start_height: 71_525 + (360 * 2),
            },
            SIP031EmissionInterval {
                amount: 1_000,
                start_height: 71_525 + 360,
            },
        ];
        assert!(SIP031EmissionInterval::check_inversed_order(
            &emissions_schedule
        ));
        emissions_schedule
    });

/// Used for testing to substitute a sip-031 emission schedule
#[cfg(any(test, feature = "testing"))]
pub static SIP031_EMISSION_INTERVALS_TEST: std::sync::Mutex<Option<Vec<SIP031EmissionInterval>>> =
    std::sync::Mutex::new(None);

#[cfg(any(test, feature = "testing"))]
pub fn set_test_sip_031_emission_schedule(emission_schedule: Option<Vec<SIP031EmissionInterval>>) {
    if let Some(emission_schedule_vec) = &emission_schedule {
        assert!(SIP031EmissionInterval::check_inversed_order(
            emission_schedule_vec
        ));
    }
    match SIP031_EMISSION_INTERVALS_TEST.lock() {
        Ok(mut schedule_guard) => {
            *schedule_guard = emission_schedule;
        }
        Err(_e) => {
            panic!("SIP031_EMISSION_INTERVALS_TEST mutex poisoned");
        }
    }
}

#[cfg(any(test, feature = "testing"))]
fn get_sip_031_emission_schedule(_mainnet: bool) -> Vec<SIP031EmissionInterval> {
    match SIP031_EMISSION_INTERVALS_TEST.lock() {
        Ok(schedule_opt) => {
            if let Some(schedule) = (*schedule_opt).as_ref() {
                info!("Use overridden SIP-031 emission schedule {:?}", &schedule);
                schedule.clone()
            } else {
                vec![]
            }
        }
        Err(_e) => {
            panic!("COINBASE_INTERVALS_TEST mutex poisoned");
        }
    }
}

#[cfg(not(any(test, feature = "testing")))]
fn get_sip_031_emission_schedule(mainnet: bool) -> Vec<SIP031EmissionInterval> {
    if mainnet {
        SIP031_EMISSION_INTERVALS_MAINNET.to_vec()
    } else {
        SIP031_EMISSION_INTERVALS_TESTNET.to_vec()
    }
}

impl SIP031EmissionInterval {
    /// Look up the amount of STX to emit at the start of the tenure at the specified height.
    /// Precondition: `intervals` must be sorted in descending order by `start_height`
    pub fn get_sip_031_emission_at_height(burn_height: u64, mainnet: bool) -> u128 {
        let intervals = get_sip_031_emission_schedule(mainnet);

        if intervals.is_empty() {
            return 0;
        }

        for interval in intervals {
            if burn_height >= interval.start_height {
                return interval.amount;
            }
        }

        // default emission (out of SIP-031 ranges)
        0
    }

    /// Verify that a list of intervals is sorted in descending order by `start_height`
    pub fn check_inversed_order(intervals: &[SIP031EmissionInterval]) -> bool {
        let Some(mut ht) = intervals.first().map(|x| x.start_height) else {
            // if the interval list is empty, its sorted
            return true;
        };

        for interval in intervals.iter().skip(1) {
            if interval.start_height > ht {
                return false;
            }
            ht = interval.start_height;
        }
        true
    }
}

impl StacksEpochId {
    /// Highest epoch enabled in release builds.
    /// Keep this in sync with `versions.toml` and `PEER_NETWORK_EPOCH`
    /// (validated in tests and `validate_epochs()`)
    pub const RELEASE_LATEST_EPOCH: StacksEpochId = StacksEpochId::Epoch40;

    #[cfg(any(test, feature = "testing"))]
    pub const fn latest() -> StacksEpochId {
        StacksEpochId::Epoch40
    }

    #[cfg(not(any(test, feature = "testing")))]
    pub const fn latest() -> StacksEpochId {
        StacksEpochId::RELEASE_LATEST_EPOCH
    }

    /// In this epoch, how should the mempool perform garbage collection?
    pub fn mempool_garbage_behavior(&self) -> MempoolCollectionBehavior {
        if self < &StacksEpochId::Epoch30 {
            MempoolCollectionBehavior::ByStacksHeight
        } else {
            MempoolCollectionBehavior::ByReceiveTime
        }
    }

    /// Returns whether or not this Epoch should perform
    ///  memory checks during analysis
    pub fn analysis_memory(&self) -> bool {
        self >= &StacksEpochId::Epoch25
    }

    /// Returns whether or not this Epoch should perform
    ///  Clarity value sanitization
    pub fn value_sanitizing(&self) -> bool {
        self >= &StacksEpochId::Epoch24
    }

    pub fn supports_specific_budget_extends(&self) -> bool {
        self >= &StacksEpochId::Epoch33
    }

    /// Whether or not this epoch supports the punishment of PoX reward
    /// recipients using the bitvec scheme
    pub fn allows_pox_punishment(&self) -> bool {
        self >= &StacksEpochId::Epoch30
    }

    /// Whether or not this epoch interprets block commit OPs block hash field
    ///  as a new block hash or the StacksBlockId of a new tenure's parent tenure.
    pub fn block_commits_to_parent(&self) -> bool {
        self >= &StacksEpochId::Epoch30
    }

    /// Whether or not this epoch supports shadow blocks
    pub fn supports_shadow_blocks(&self) -> bool {
        self >= &StacksEpochId::Epoch30
    }

    /// Does this epoch support unlocking PoX contributors that miss a slot?
    ///
    /// Epoch 2.0 - 2.05 didn't support this feature, but they weren't epoch-guarded on it. Instead,
    ///  the behavior never activates in those epochs because the Pox1 contract does not provide
    ///  `contibuted_stackers` information. This check maintains that exact semantics by returning
    ///  true for all epochs before 2.5. For 2.5 and after, this returns false.
    pub fn supports_pox_missed_slot_unlocks(&self) -> bool {
        self < &StacksEpochId::Epoch25
    }

    /// Whether `from-consensus-buff` treats unexpected serialization as `none` or causes
    /// an error that makes the transaction un-includable in a block.
    pub fn treats_unexpected_serialization_as_none(&self) -> bool {
        self >= &StacksEpochId::Epoch34
    }

    /// Whether or not this epoch rejects `SupertypeTooLarge` errors.
    pub fn rejects_supertype_too_large(&self) -> bool {
        self < &StacksEpochId::Epoch34
    }

    /// Whether or not this epoch rejects parse-depth errors.
    pub fn rejects_parse_depth_errors(&self) -> bool {
        self < &StacksEpochId::Epoch34
    }

    /// Whether or not this epoch pre-sanitizes contract variables at deploy
    /// and load time, allowing variable lookups to borrow directly.
    pub fn uses_pre_sanitized_variables(&self) -> bool {
        self >= &StacksEpochId::Epoch34
    }

    /// What is the sortition mining commitment window for this epoch?
    pub fn mining_commitment_window(&self) -> u8 {
        MINING_COMMITMENT_WINDOW
    }

    /// How often must a miner mine in order to be considered for sortition in its commitment
    /// window?
    pub fn mining_commitment_frequency(&self) -> u8 {
        if self >= &StacksEpochId::Epoch30 {
            MINING_COMMITMENT_FREQUENCY_NAKAMOTO
        } else {
            0
        }
    }

    /// Returns true for epochs which use Nakamoto blocks. These blocks use a
    /// different header format than the previous Stacks blocks, which among
    /// other changes includes a Stacks-specific timestamp.
    pub fn uses_nakamoto_blocks(&self) -> bool {
        self >= &StacksEpochId::Epoch30
    }

    /// Returns whether or not this epoch uses the tip for reading burn block
    /// info in Clarity (3.0+ behavior) or should use the parent block's burn
    /// block (behavior before 3.0).
    pub fn clarity_uses_tip_burn_block(&self) -> bool {
        self >= &StacksEpochId::Epoch30
    }

    /// Does this epoch use the nakamoto reward set, or the epoch2 reward set?
    /// We use the epoch2 reward set in all pre-3.0 epochs.
    /// We also use the epoch2 reward set in the first 3.0 reward cycle.
    /// After that, we use the nakamoto reward set.
    pub fn uses_nakamoto_reward_set(
        &self,
        cur_reward_cycle: u64,
        first_epoch30_reward_cycle: u64,
    ) -> bool {
        self >= &StacksEpochId::Epoch30 && cur_reward_cycle > first_epoch30_reward_cycle
    }

    /// Does this epoch support the post-condition enhancements from SIP-040?
    /// This includes support for `Originator` mode and the `MaySend` NFT condition.
    pub fn supports_sip040_post_conditions(&self) -> bool {
        self >= &StacksEpochId::Epoch34
    }

    /// What is the coinbase (in uSTX) to award for the given burnchain height?
    /// Applies prior to SIP-029
    fn coinbase_reward_pre_sip029(
        &self,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128 {
        /*
        From https://forum.stacks.org/t/pox-consensus-and-stx-future-supply

        """

        1000 STX for years 0-4
        500 STX for years 4-8
        250 STX for years 8-12
        125 STX in perpetuity


        From the Token Whitepaper:

        We expect that once native mining goes live, approximately 4383 blocks will be pro-
        cessed per month, or approximately 52,596 blocks will be processed per year.

        """
        */
        // this is saturating subtraction for the initial reward calculation
        //   where we are computing the coinbase reward for blocks that occur *before*
        //   the `first_burn_block_height`
        let effective_ht = current_burnchain_height.saturating_sub(first_burnchain_height);
        let blocks_per_year = 52596;
        let stx_reward = if effective_ht < blocks_per_year * 4 {
            1000
        } else if effective_ht < blocks_per_year * 8 {
            500
        } else if effective_ht < blocks_per_year * 12 {
            250
        } else {
            125
        };

        stx_reward * (u128::from(MICROSTACKS_PER_STACKS))
    }

    /// Get the coinbase intervals to use.
    /// Can be overriden by tests
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn get_coinbase_intervals(mainnet: bool) -> Vec<CoinbaseInterval> {
        match COINBASE_INTERVALS_TEST.lock() {
            Ok(schedule_opt) => {
                if let Some(schedule) = (*schedule_opt).as_ref() {
                    info!("Use overridden coinbase schedule {:?}", &schedule);
                    return schedule.clone();
                }
            }
            Err(_e) => {
                panic!("COINBASE_INTERVALS_TEST mutex poisoned");
            }
        }

        if mainnet {
            COINBASE_INTERVALS_MAINNET.to_vec()
        } else {
            COINBASE_INTERVALS_TESTNET.to_vec()
        }
    }

    #[cfg(not(any(test, feature = "testing")))]
    pub(crate) fn get_coinbase_intervals(mainnet: bool) -> Vec<CoinbaseInterval> {
        if mainnet {
            COINBASE_INTERVALS_MAINNET.to_vec()
        } else {
            COINBASE_INTERVALS_TESTNET.to_vec()
        }
    }

    /// what are the offsets after chain-start when coinbase reductions occur?
    /// Applies at and after SIP-029.
    /// Uses coinbase intervals defined by COINBASE_INTERVALS_MAINNET, unless overridden by a unit
    /// or integration test.
    fn coinbase_reward_sip029(
        &self,
        mainnet: bool,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128 {
        let effective_ht = current_burnchain_height.saturating_sub(first_burnchain_height);
        let coinbase_intervals = Self::get_coinbase_intervals(mainnet);
        CoinbaseInterval::get_coinbase_at_effective_height(&coinbase_intervals, effective_ht)
    }

    /// What is the coinbase to award?
    pub fn coinbase_reward(
        &self,
        mainnet: bool,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128 {
        if self == &StacksEpochId::Epoch10 {
            // Stacks is not active in Epoch 1.0, so no coinbase reward
            0
        } else if self < &StacksEpochId::Epoch31 {
            // For epochs 2.0 - 3.0, use the pre-SIP-029 schedule
            self.coinbase_reward_pre_sip029(first_burnchain_height, current_burnchain_height)
        } else {
            // For epoch 3.1 and later, use the SIP-029 schedule
            self.coinbase_reward_sip029(mainnet, first_burnchain_height, current_burnchain_height)
        }
    }

    /// Whether or not this epoch is part of the SIP-031 schedule
    pub fn includes_sip_031(&self) -> bool {
        self >= &StacksEpochId::Epoch32
    }

    pub fn uses_marfed_block_time(&self) -> bool {
        self >= &StacksEpochId::Epoch33
    }

    /// Before Epoch 3.3, the cost for arguments to functions was based on the
    /// parameter type, not the actual size of the argument passed in. This
    /// resulted in over-charging for arguments smaller than the maximum size
    /// permitted for the parameter.
    pub fn uses_arg_size_for_cost(&self) -> bool {
        self >= &StacksEpochId::Epoch33
    }

    /// In Epoch 3.3, limits are introduced on the number of parameters
    /// in function definitions and the number of methods in trait definitions.
    pub fn limits_parameter_and_method_count(&self) -> bool {
        self >= &StacksEpochId::Epoch33
    }

    pub fn handles_with_stx_combined_check(&self) -> bool {
        self >= &StacksEpochId::Epoch34
    }

    pub fn supports_call_with_constant(&self) -> bool {
        self >= &StacksEpochId::Epoch34
    }

    /// Whether `at-block` is available in this epoch.
    pub fn supports_at_block(&self) -> bool {
        self < &StacksEpochId::Epoch34
    }

    /// Return the network epoch associated with the StacksEpochId
    pub fn network_epoch(epoch: StacksEpochId) -> u8 {
        match epoch {
            StacksEpochId::Epoch10 => PEER_VERSION_EPOCH_1_0,
            StacksEpochId::Epoch20 => PEER_VERSION_EPOCH_2_0,
            StacksEpochId::Epoch2_05 => PEER_VERSION_EPOCH_2_05,
            StacksEpochId::Epoch21 => PEER_VERSION_EPOCH_2_1,
            StacksEpochId::Epoch22 => PEER_VERSION_EPOCH_2_2,
            StacksEpochId::Epoch23 => PEER_VERSION_EPOCH_2_3,
            StacksEpochId::Epoch24 => PEER_VERSION_EPOCH_2_4,
            StacksEpochId::Epoch25 => PEER_VERSION_EPOCH_2_5,
            StacksEpochId::Epoch30 => PEER_VERSION_EPOCH_3_0,
            StacksEpochId::Epoch31 => PEER_VERSION_EPOCH_3_1,
            StacksEpochId::Epoch32 => PEER_VERSION_EPOCH_3_2,
            StacksEpochId::Epoch33 => PEER_VERSION_EPOCH_3_3,
            StacksEpochId::Epoch34 => PEER_VERSION_EPOCH_3_4,
            StacksEpochId::Epoch40 => PEER_VERSION_EPOCH_4_0,
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn since(epoch: StacksEpochId) -> &'static [StacksEpochId] {
        let idx = Self::ALL
            .iter()
            .position(|&e| e == epoch)
            .expect("epoch not found in ALL");

        &Self::ALL[idx..]
    }
}

impl PartialOrd for StacksAddress {
    fn partial_cmp(&self, other: &StacksAddress) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StacksAddress {
    fn cmp(&self, other: &StacksAddress) -> Ordering {
        match self.version().cmp(&other.version()) {
            Ordering::Equal => self.bytes().cmp(other.bytes()),
            inequality => inequality,
        }
    }
}

impl StacksAddress {
    pub fn is_mainnet(&self) -> bool {
        match self.version() {
            C32_ADDRESS_VERSION_MAINNET_MULTISIG | C32_ADDRESS_VERSION_MAINNET_SINGLESIG => true,
            C32_ADDRESS_VERSION_TESTNET_MULTISIG | C32_ADDRESS_VERSION_TESTNET_SINGLESIG => false,
            _ => false,
        }
    }

    pub fn burn_address(mainnet: bool) -> StacksAddress {
        Self::new(
            if mainnet {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG
            } else {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG
            },
            Hash160([0u8; 20]),
        )
        .unwrap_or_else(|_| panic!("FATAL: constant address versions are invalid"))
        // infallible
    }

    /// Generate an address from a given address hash mode, signature threshold, and list of public
    /// keys.  Only return an address if the combination given is supported.
    /// The version is may be arbitrary.
    pub fn from_public_keys(
        version: u8,
        hash_mode: &AddressHashMode,
        num_sigs: usize,
        pubkeys: &Vec<StacksPublicKey>,
    ) -> Option<StacksAddress> {
        // must be sufficient public keys
        if pubkeys.len() < num_sigs {
            return None;
        }

        // address hash mode must be consistent with the number of keys
        match *hash_mode {
            AddressHashMode::SerializeP2PKH | AddressHashMode::SerializeP2WPKH => {
                // must be a single public key, and must require one signature
                if num_sigs != 1 || pubkeys.len() != 1 {
                    return None;
                }
            }
            _ => {}
        }

        // if segwit, then keys must all be compressed
        match *hash_mode {
            AddressHashMode::SerializeP2WPKH | AddressHashMode::SerializeP2WSH => {
                for pubkey in pubkeys {
                    if !pubkey.compressed() {
                        return None;
                    }
                }
            }
            _ => {}
        }

        let hash_bits = public_keys_to_address_hash(hash_mode, num_sigs, pubkeys);
        StacksAddress::new(version, hash_bits).ok()
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh(mainnet: bool, pubkey: &StacksPublicKey) -> StacksAddress {
        let bytes = to_bits_p2pkh(pubkey);
        Self::p2pkh_from_hash(mainnet, bytes)
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh_from_hash(mainnet: bool, hash: Hash160) -> StacksAddress {
        let version = if mainnet {
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG
        } else {
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG
        };
        Self::new(version, hash)
            .unwrap_or_else(|_| panic!("FATAL: constant address versions are invalid"))
        // infallible
    }
}

impl std::fmt::Display for StacksAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the .unwrap_or_else() should be unreachable since StacksAddress is constructed to only
        // accept a 5-bit value for its version
        c32_address(self.version(), self.bytes().as_bytes())
            .expect("Stacks version is not C32-encodable")
            .fmt(f)
    }
}

impl Address for StacksAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes().as_bytes().to_vec()
    }

    fn from_string(s: &str) -> Option<StacksAddress> {
        let (version, bytes) = c32_address_decode(s).ok()?;

        if bytes.len() != 20 {
            return None;
        }

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&bytes[..]);
        StacksAddress::new(version, Hash160(hash_bytes)).ok()
    }

    fn is_burn(&self) -> bool {
        self.bytes() == &Hash160([0u8; 20])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct StacksEpoch<L> {
    pub epoch_id: StacksEpochId,
    pub start_height: u64,
    pub end_height: u64,
    pub block_limit: L,
    pub network_epoch: u8,
}

impl<L> StacksEpoch<L> {
    /// Determine which epoch, if any, in a list of epochs, a given burnchain height falls into.
    /// Returns Some(index) if there is such an epoch in the list.
    /// Returns None if not.
    pub fn find_epoch(epochs: &[StacksEpoch<L>], height: u64) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.start_height <= height && height < epoch.end_height {
                return Some(i);
            }
        }
        None
    }

    /// Find an epoch by its ID
    /// Returns Some(index) if the epoch is in the list
    /// Returns None if not
    pub fn find_epoch_by_id(epochs: &[StacksEpoch<L>], epoch_id: StacksEpochId) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.epoch_id == epoch_id {
                return Some(i);
            }
        }
        None
    }
}

// StacksEpochs are ordered by start block height
impl<L: PartialEq> PartialOrd for StacksEpoch<L> {
    fn partial_cmp(&self, other: &StacksEpoch<L>) -> Option<Ordering> {
        self.epoch_id.partial_cmp(&other.epoch_id)
    }
}

impl<L: PartialEq + Eq> Ord for StacksEpoch<L> {
    fn cmp(&self, other: &StacksEpoch<L>) -> Ordering {
        self.epoch_id.cmp(&other.epoch_id)
    }
}

/// A wrapper for holding a list of Epochs, indexable by StacksEpochId
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct EpochList<L: Clone>(Vec<StacksEpoch<L>>);

impl<L: Clone> From<Vec<StacksEpoch<L>>> for EpochList<L> {
    fn from(value: Vec<StacksEpoch<L>>) -> Self {
        Self(value)
    }
}

impl<L: Clone> EpochList<L> {
    pub fn new(epochs: &[StacksEpoch<L>]) -> EpochList<L> {
        EpochList(epochs.to_vec())
    }

    pub fn get(&self, index: StacksEpochId) -> Option<&StacksEpoch<L>> {
        self.0.get(StacksEpoch::find_epoch_by_id(&self.0, index)?)
    }

    pub fn get_mut(&mut self, index: StacksEpochId) -> Option<&mut StacksEpoch<L>> {
        let index = StacksEpoch::find_epoch_by_id(&self.0, index)?;
        self.0.get_mut(index)
    }

    /// Truncates the list after the given epoch id
    pub fn truncate_after(&mut self, epoch_id: StacksEpochId) {
        if let Some(index) = StacksEpoch::find_epoch_by_id(&self.0, epoch_id) {
            self.0.truncate(index + 1);
        }
        if let Some(epoch) = self.0.last_mut() {
            epoch.end_height = STACKS_EPOCH_MAX;
        }
    }

    /// Determine which epoch, if any, a given burnchain height falls into.
    pub fn epoch_id_at_height(&self, height: u64) -> Option<StacksEpochId> {
        StacksEpoch::find_epoch(self, height).map(|idx| self.0[idx].epoch_id)
    }

    /// Determine which epoch, if any, a given burnchain height falls into.
    pub fn epoch_at_height(&self, height: u64) -> Option<StacksEpoch<L>> {
        StacksEpoch::find_epoch(self, height).map(|idx| self.0[idx].clone())
    }

    /// Pushes a new `StacksEpoch` to the end of the list
    pub fn push(&mut self, epoch: StacksEpoch<L>) {
        if let Some(last) = self.0.last() {
            assert!(
                epoch.start_height == last.end_height && epoch.epoch_id > last.epoch_id,
                "Epochs must be pushed in order"
            );
        }
        self.0.push(epoch);
    }

    pub fn to_vec(self) -> Vec<StacksEpoch<L>> {
        self.0
    }
}

impl<L: Clone> Index<StacksEpochId> for EpochList<L> {
    type Output = StacksEpoch<L>;
    fn index(&self, index: StacksEpochId) -> &StacksEpoch<L> {
        self.get(index)
            .expect("Invalid StacksEpochId: could not find corresponding epoch")
    }
}

impl<L: Clone> IndexMut<StacksEpochId> for EpochList<L> {
    fn index_mut(&mut self, index: StacksEpochId) -> &mut StacksEpoch<L> {
        self.get_mut(index)
            .expect("Invalid StacksEpochId: could not find corresponding epoch")
    }
}

impl<L: Clone> Deref for EpochList<L> {
    type Target = [StacksEpoch<L>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<L: Clone> DerefMut for EpochList<L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Copy)]
pub enum MiningReason {
    BlockFound = 0,
    Extended = 1,
    ReadCountExtend = 2,
}

impl TryFrom<u8> for MiningReason {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, CodecError> {
        match value {
            x if x == MiningReason::BlockFound as u8 => Ok(MiningReason::BlockFound),
            x if x == MiningReason::Extended as u8 => Ok(MiningReason::Extended),
            x if x == MiningReason::ReadCountExtend as u8 => Ok(MiningReason::ReadCountExtend),
            _ => Err(CodecError::DeserializeError(format!(
                "unknown mining reason {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinerDiagnosticData {
    pub burnchain_tip_height: u64,
    pub burnchain_tip_consensus_hash: chainstate::ConsensusHash,
    pub burnchain_tip_header_hash: chainstate::BurnchainHeaderHash,
    pub tenure_extend_time_stamp: u64,
    pub read_count_extend_timestamp: u64,
    pub mining_reason: MiningReason,
}

impl StacksMessageCodec for MinerDiagnosticData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.burnchain_tip_height)?;
        write_next(fd, &self.burnchain_tip_consensus_hash)?;
        write_next(fd, &self.burnchain_tip_header_hash)?;
        write_next(fd, &self.tenure_extend_time_stamp)?;
        write_next(fd, &self.read_count_extend_timestamp)?;
        write_next(fd, &(self.mining_reason as u8))?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let burnchain_tip_height = read_next(fd)?;
        let burnchain_tip_consensus_hash = read_next(fd)?;
        let burnchain_tip_header_hash = read_next(fd)?;
        let tenure_extend_time_stamp = read_next(fd)?;
        let read_count_extend_timestamp = read_next(fd)?;
        let mining_reason = read_next::<u8, _>(fd)?.try_into()?;

        Ok(MinerDiagnosticData {
            burnchain_tip_height,
            burnchain_tip_consensus_hash,
            burnchain_tip_header_hash,
            tenure_extend_time_stamp,
            read_count_extend_timestamp,
            mining_reason,
        })
    }
}
