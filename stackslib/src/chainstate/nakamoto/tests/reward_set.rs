// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use std::collections::HashMap;

use clarity::util::uint::{Uint256, Uint512};
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use pinny::tag;
use proptest::array::uniform20;
use proptest::prelude::{any, prop, proptest, Strategy, TestCaseError};
use proptest::{prop_assert, prop_assert_eq, prop_assume};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::Hash160;

use crate::burnchains::bitcoin::{WatchedP2WSHOutput, WitnessScriptHash};
use crate::burnchains::{PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::WatchedP2WSHOutputMetadata;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::nakamoto::signer_set::{
    NakamotoSigners, Pox5PoolInfoProvider, PoxEntryParsingError, RawPox5Entry, RawPox5EntryInfo,
};
use crate::chainstate::stacks::address::PoxAddress;
use crate::proptest_utils::pox_address_strategy;

// ---------------------------------------------------------------------------
// Mock provider (same as in signer_set::tests, but accessible here)
// ---------------------------------------------------------------------------

struct MockPox5PoolInfoProvider {
    pools: HashMap<PrincipalData, ([u8; 33], PoxAddress)>,
}

impl MockPox5PoolInfoProvider {
    fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    fn add_pool(&mut self, principal: PrincipalData, key: [u8; 33], addr: PoxAddress) {
        self.pools.insert(principal, (key, addr));
    }
}

impl Pox5PoolInfoProvider for MockPox5PoolInfoProvider {
    fn get_pool_info(
        &mut self,
        pool_principal: &PrincipalData,
    ) -> Result<Option<([u8; 33], PoxAddress)>, PoxEntryParsingError> {
        Ok(self.pools.get(pool_principal).cloned())
    }
}

// ---------------------------------------------------------------------------
// Proptest strategies
// ---------------------------------------------------------------------------

/// Generate a StandardPrincipalData from random bytes.
fn standard_principal_strategy() -> impl Strategy<Value = StandardPrincipalData> {
    (
        prop::sample::select(&[0x16u8, 0x1a]),
        uniform20(any::<u8>()),
    )
        .prop_map(|(version, hash)| StandardPrincipalData::new(version, hash).unwrap())
}

/// Generate a signer key (33 bytes).
fn signer_key_strategy() -> impl Strategy<Value = [u8; 33]> {
    prop::collection::vec(any::<u8>(), 33).prop_map(|v| {
        let mut arr = [0u8; 33];
        arr.copy_from_slice(&v);
        arr
    })
}

/// Generate a solo RawPox5Entry with configurable STX amount and num_cycles.
fn solo_entry_strategy(
    amount_ustx: impl Strategy<Value = u128>,
    num_cycles: impl Strategy<Value = u128>,
) -> impl Strategy<Value = (RawPox5Entry, [u8; 33])> {
    (
        standard_principal_strategy(),
        pox_address_strategy(),
        signer_key_strategy(),
        amount_ustx,
        num_cycles,
        1u32..10_000u32,
    )
        .prop_map(
            |(user, pox_addr, signer_key, amount_ustx, num_cycles, unlock_height)| {
                let entry = RawPox5Entry {
                    user,
                    num_cycles,
                    unlock_bytes: vec![],
                    amount_ustx,
                    first_reward_cycle: 0,
                    unlock_height,
                    pox_info: RawPox5EntryInfo::Solo {
                        pox_addr,
                        signer_key,
                    },
                };
                (entry, signer_key)
            },
        )
}

/// Generate a WatchedP2WSHOutputMetadata with a given satoshi amount.
fn watched_output(sats: u64) -> WatchedP2WSHOutputMetadata {
    WatchedP2WSHOutputMetadata {
        output: WatchedP2WSHOutput {
            witness_script_hash: WitnessScriptHash([0u8; 32]),
            amount: sats,
            txid: Txid([0u8; 32]),
            vout: 0,
        },
        at_block_ch: ConsensusHash([0u8; 20]),
        at_block_ht: 100,
    }
}

fn make_test_pox_constants() -> PoxConstants {
    PoxConstants::new(
        5,    // reward_cycle_length
        3,    // prepare_length
        3,    // anchor_threshold
        10,   // pox_rejection_fraction
        10,   // pox_participation_threshold_pct
        5000, // sunset_start
        5100, // sunset_end
        1000, // v1_unlock_height
        2000, // v2_unlock_height
        3000, // v3_unlock_height
        2000, // pox_3_activation_height
        4000, // v4_unlock_height
    )
}

// ---------------------------------------------------------------------------
// Property test helpers
// ---------------------------------------------------------------------------

/// Run pox_5_make_reward_set and check basic invariants that should hold
/// for any valid solo-only input set.
fn check_solo_reward_set_invariants(
    entries: Vec<(RawPox5Entry, Vec<WatchedP2WSHOutputMetadata>)>,
    pox_constants: &PoxConstants,
    prior_ratios: Vec<Uint512>,
) -> Result<(), TestCaseError> {
    let mut provider = MockPox5PoolInfoProvider::new();

    // Count entries that have non-zero sats (these are the ones that can pass d_min)
    let entries_with_btc: Vec<_> = entries
        .iter()
        .filter(|(_, outputs)| {
            outputs
                .iter()
                .fold(0u64, |acc, o| o.output.amount.saturating_add(acc))
                > 0
        })
        .collect();

    let total_ustx: u128 = entries.iter().map(|(e, _)| e.amount_ustx).sum();

    let result =
        NakamotoSigners::pox_5_make_reward_set(entries, pox_constants, &mut provider, prior_ratios);
    info!("Result: {result:?}");

    // The function should not error for valid solo entries
    prop_assert!(
        result.is_ok(),
        "pox_5_make_reward_set returned error: {:?}",
        result.err()
    );

    let (reward_set, ratios_to_store) = result.unwrap();

    // Invariant 1: signers field is always Some
    prop_assert!(
        reward_set.signers.is_some(),
        "signers should always be Some"
    );
    let signers = reward_set.signers.as_ref().unwrap();

    // Invariant 2: ratios_to_store length is between 1 and 4
    prop_assert!(
        !ratios_to_store.is_empty() && ratios_to_store.len() <= 4,
        "ratios_to_store length should be 1..=4, got {}",
        ratios_to_store.len()
    );

    // Invariant 3: no signer has zero stacked_amt
    for signer in signers.iter() {
        prop_assert!(
            signer.stacked_amt > 0,
            "signer should not have zero stacked_amt"
        );
    }

    // Invariant 4: total signer stacked_amt <= total input ustx
    let total_signer_ustx: u128 = signers.iter().map(|s| s.stacked_amt).sum();
    prop_assert!(
        total_signer_ustx <= total_ustx,
        "signer stacked_amt sum ({}) exceeds input total ({})",
        total_signer_ustx,
        total_ustx
    );

    // Invariant 5: signer weights sum correctly (if any signers)
    //
    // Each signer's weight = floor(amount_ustx * reward_slots / total_ustx_locked).
    // Signers below signer_threshold_ustx are dropped, so surviving weights
    // sum to approximately total_signer_ustx * reward_slots / total_ustx_locked.
    // We recover total_ustx_locked from the output: threshold * reward_slots, applying
    //  some tolerance for the precision loss in division by reward_slots.
    if !signers.is_empty() {
        let reward_slots = pox_constants.reward_slots() as u128;
        let threshold = reward_set
            .pox_ustx_threshold
            .expect("pox_ustx_threshold should be Some");
        let total_ustx_locked = threshold * reward_slots;
        let tolerance = reward_slots;
        prop_assert!(total_ustx_locked > 0, "total_ustx_locked should be > 0");
        prop_assert!(total_ustx_locked + tolerance >= total_signer_ustx, "total_ustx_locked ({total_ustx_locked}) should be > total_signer_ustx ({total_signer_ustx})");

        let total_weight: u64 = signers.iter().map(|s| s.weight as u64).sum();
        let scaling = Uint256::from_u64(reward_slots as u64);

        let expected_weight_high = Uint256::from_u128(total_signer_ustx)
            * Uint256::from_u64(reward_slots as u64)
            / Uint256::from_u128(total_ustx_locked);
        let expected_weight_low = Uint256::from_u128(total_signer_ustx)
            * Uint256::from_u64(reward_slots as u64)
            / Uint256::from_u128(total_ustx_locked + tolerance);

        let expected_weight_low = expected_weight_low.low_u32() as u64;
        let expected_weight_high = if expected_weight_high > scaling {
            reward_slots as u64
        } else {
            expected_weight_high.low_u32() as u64
        };
        // Each signer can lose up to 1 from integer truncation
        let tolerance = signers.len() as u64;
        prop_assert!(
            total_weight <= expected_weight_high,
            "total weight ({}) exceeds expected ({})",
            total_weight,
            expected_weight_high
        );
        prop_assert!(
            total_weight >= expected_weight_low.saturating_sub(tolerance),
            "total weight ({}) too far below expected ({}, tolerance {})",
            total_weight,
            expected_weight_low,
            tolerance
        );
    }

    // Invariant 6: reward slot count does not exceed the configured reward_slots
    let reward_slots = pox_constants.reward_slots() as usize;
    prop_assert!(
        reward_set.rewarded_addresses.len() <= reward_slots,
        "rewarded_addresses ({}) exceeds reward_slots ({})",
        reward_set.rewarded_addresses.len(),
        reward_slots
    );

    Ok(())
}

/// Run pox_5_make_reward_set with pool entries and check pool aggregation invariants.
fn check_pool_aggregation_invariants(
    solo_entries: Vec<(RawPox5Entry, Vec<WatchedP2WSHOutputMetadata>)>,
    pool_entries: Vec<(RawPox5Entry, Vec<WatchedP2WSHOutputMetadata>)>,
    provider: &mut MockPox5PoolInfoProvider,
    pox_constants: &PoxConstants,
) -> Result<(), TestCaseError> {
    // Track expected aggregations: pool_principal -> total ustx
    let mut expected_pool_ustx: HashMap<PrincipalData, u128> = HashMap::new();
    for (entry, _) in pool_entries.iter() {
        if let RawPox5EntryInfo::Pool(ref principal) = entry.pox_info {
            *expected_pool_ustx.entry(principal.clone()).or_default() += entry.amount_ustx;
        }
    }

    let all_entries: Vec<_> = solo_entries
        .into_iter()
        .chain(pool_entries.into_iter())
        .collect();

    let result =
        NakamotoSigners::pox_5_make_reward_set(all_entries, pox_constants, provider, vec![]);

    prop_assert!(
        result.is_ok(),
        "pox_5_make_reward_set returned error: {:?}",
        result.err()
    );
    let (reward_set, _) = result.unwrap();
    let signers = reward_set.signers.as_ref().unwrap();

    // Invariant: each pool principal that exists in the provider should produce
    // at most one signer entry (aggregated). Check that no signer_key appears
    // more than once.
    let mut seen_keys: HashMap<[u8; 33], u128> = HashMap::new();
    for signer in signers.iter() {
        let prev = seen_keys.insert(signer.signing_key, signer.stacked_amt);
        prop_assert!(
            prev.is_none(),
            "duplicate signer key found — pool aggregation failed"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Solo entries with valid STX/BTC ratios should never cause panics and
    /// should satisfy basic reward set invariants (signer weights, slot counts).
    #[tag(t_prop)]
    #[test]
    fn pox5_solo_entries_invariants(
        num_entries in 1usize..50,
        amounts_ustx in prop::collection::vec(100_000u128..10_000_000u128, 1..50),
        sats_amounts in prop::collection::vec(1_000u64..1_000_000u64, 1..50),
        num_cycles_vec in prop::collection::vec(1u128..12u128, 1..50),
    ) {
        let pox_constants = make_test_pox_constants();
        let num_entries = num_entries.min(amounts_ustx.len()).min(sats_amounts.len()).min(num_cycles_vec.len());
        prop_assume!(num_entries > 0);

        let mut entries = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            let hash_bytes = {
                let mut h = [0u8; 20];
                h[..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            };
            let user = StandardPrincipalData::new(0x16, hash_bytes).unwrap();
            let pox_addr = PoxAddress::Standard(
                StacksAddress::new(0x16, Hash160(hash_bytes)).unwrap(),
                None,
            );
            let signer_key = {
                let mut k = [0u8; 33];
                k[..8].copy_from_slice(&(i as u64).to_le_bytes());
                k
            };
            let entry = RawPox5Entry {
                user,
                num_cycles: num_cycles_vec[i],
                unlock_bytes: vec![],
                amount_ustx: amounts_ustx[i],
                first_reward_cycle: 0,
                unlock_height: 1000,
                pox_info: RawPox5EntryInfo::Solo { pox_addr, signer_key },
            };
            entries.push((entry, vec![watched_output(sats_amounts[i])]));
        }

        check_solo_reward_set_invariants(entries, &pox_constants, vec![])?;
    }

    /// Entries with zero BTC should be silently excluded (no panic).
    #[tag(t_prop)]
    #[test]
    fn pox5_zero_btc_entries_excluded(
        good_amount_ustx in 100_000u128..10_000_000u128,
        good_sats in 1_000u64..1_000_000u64,
        zero_btc_amount_ustx in 100_000u128..10_000_000u128,
    ) {
        let pox_constants = make_test_pox_constants();
        let mut provider = MockPox5PoolInfoProvider::new();

        let good_entry = RawPox5Entry {
            user: StandardPrincipalData::new(0x16, [1u8; 20]).unwrap(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: good_amount_ustx,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: PoxAddress::Standard(
                    StacksAddress::new(0x16, Hash160([1u8; 20])).unwrap(), None),
                signer_key: [1u8; 33],
            },
        };
        let zero_btc_entry = RawPox5Entry {
            user: StandardPrincipalData::new(0x16, [2u8; 20]).unwrap(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: zero_btc_amount_ustx,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: PoxAddress::Standard(
                    StacksAddress::new(0x16, Hash160([2u8; 20])).unwrap(), None),
                signer_key: [2u8; 33],
            },
        };

        let entries = vec![
            (good_entry, vec![watched_output(good_sats)]),
            (zero_btc_entry, vec![watched_output(0)]),
        ];

        let result = NakamotoSigners::pox_5_make_reward_set(
            entries, &pox_constants, &mut provider, vec![],
        );
        prop_assert!(result.is_ok());
        let (reward_set, _) = result.unwrap();
        let signers = reward_set.signers.unwrap();

        // The zero-BTC entry should be excluded; at most 1 signer
        prop_assert!(signers.len() <= 1, "zero-BTC entry should be excluded");
    }

    /// Pool entries for the same principal should be aggregated into a single
    /// signer with summed stacked amounts.
    #[tag(t_prop)]
    #[test]
    fn pox5_pool_aggregation(
        num_pool_entries in 2usize..20,
        amounts_ustx in prop::collection::vec(100_000u128..5_000_000u128, 2..20),
        sats_amounts in prop::collection::vec(1_000u64..500_000u64, 2..20),
    ) {
        let pox_constants = make_test_pox_constants();
        let num_pool_entries = num_pool_entries.min(amounts_ustx.len()).min(sats_amounts.len());
        prop_assume!(num_pool_entries >= 2);

        let pool_principal = PrincipalData::from(
            StandardPrincipalData::new(0x16, [99u8; 20]).unwrap()
        );
        let pool_signer_key = [42u8; 33];
        let pool_pox_addr = PoxAddress::Standard(
            StacksAddress::new(0x16, Hash160([99u8; 20])).unwrap(),
            None,
        );

        let mut provider = MockPox5PoolInfoProvider::new();
        provider.add_pool(pool_principal.clone(), pool_signer_key, pool_pox_addr);

        let mut entries = Vec::new();
        let mut expected_total_ustx = 0u128;
        for i in 0..num_pool_entries {
            let hash_bytes = {
                let mut h = [0u8; 20];
                h[..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            };
            let entry = RawPox5Entry {
                user: StandardPrincipalData::new(0x16, hash_bytes).unwrap(),
                num_cycles: 1,
                unlock_bytes: vec![],
                amount_ustx: amounts_ustx[i],
                first_reward_cycle: 0,
                unlock_height: 1000,
                pox_info: RawPox5EntryInfo::Pool(pool_principal.clone()),
            };
            expected_total_ustx += amounts_ustx[i];
            entries.push((entry, vec![watched_output(sats_amounts[i])]));
        }

        let result = NakamotoSigners::pox_5_make_reward_set(
            entries, &pox_constants, &mut provider, vec![],
        );
        prop_assert!(result.is_ok());
        let (reward_set, _) = result.unwrap();
        let signers = reward_set.signers.unwrap();

        // All pool entries should aggregate into exactly one signer
        let pool_signers: Vec<_> = signers
            .iter()
            .filter(|s| s.signing_key == pool_signer_key)
            .collect();
        prop_assert_eq!(
            pool_signers.len(), 1,
            "pool entries should aggregate into exactly one signer"
        );
        prop_assert_eq!(
            pool_signers[0].stacked_amt, expected_total_ustx,
            "aggregated stacked_amt should equal sum of pool entry amounts"
        );
    }

    /// Prior ratio percentiles should be carried forward correctly:
    /// the returned ratios should contain D_t as the first element
    /// followed by up to 3 of the provided priors.
    #[tag(t_prop)]
    #[test]
    fn pox5_ratios_stored_correctly(
        num_priors in 0usize..4,
        amount_ustx in 1_000_000u128..10_000_000u128,
        sats in 10_000u64..1_000_000u64,
    ) {
        let pox_constants = make_test_pox_constants();
        let mut provider = MockPox5PoolInfoProvider::new();

        let entry = RawPox5Entry {
            user: StandardPrincipalData::new(0x16, [1u8; 20]).unwrap(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: PoxAddress::Standard(
                    StacksAddress::new(0x16, Hash160([1u8; 20])).unwrap(), None),
                signer_key: [1u8; 33],
            },
        };

        // Create prior ratios as small Uint512 values (valid ratio range)
        let prior_ratios: Vec<Uint512> = (0..num_priors)
            .map(|i| Uint512::from_u64((i as u64 + 1) * 1000))
            .collect();

        let entries = vec![(entry, vec![watched_output(sats)])];
        let result = NakamotoSigners::pox_5_make_reward_set(
            entries, &pox_constants, &mut provider, prior_ratios.clone(),
        );
        prop_assert!(result.is_ok());
        let (_, ratios_to_store) = result.unwrap();

        // First element is D_t (newly computed), rest are prior ratios (up to 3)
        let expected_len = 1 + num_priors.min(3);
        prop_assert_eq!(
            ratios_to_store.len(), expected_len,
            "ratios_to_store should have length 1 + min(num_priors, 3)"
        );

        // The trailing elements should match the provided priors (truncated to 3)
        for (i, prior) in prior_ratios.iter().take(3).enumerate() {
            prop_assert_eq!(
                &ratios_to_store[i + 1], prior,
                "stored prior ratio at index {} should match input",
                i
            );
        }
    }

    /// Entries below the d_min_t threshold (very high STX relative to BTC)
    /// should be excluded. d_min_t = SCALING_FACTOR / 100, meaning the
    /// stx/btc ratio must be >= 1/100. An entry with 1 ustx and 100+ sats
    /// will be below the minimum.
    #[tag(t_prop)]
    #[test]
    fn pox5_below_dmin_excluded(
        good_ustx in 1_000_000u128..10_000_000u128,
        good_sats in 1_000u64..100_000u64,
        bad_ustx in 1u128..50u128,
        bad_sats in 100_000u64..1_000_000u64,
    ) {
        let pox_constants = make_test_pox_constants();
        let mut provider = MockPox5PoolInfoProvider::new();

        // Good entry: high STX, low BTC → high d_i
        let good_entry = RawPox5Entry {
            user: StandardPrincipalData::new(0x16, [1u8; 20]).unwrap(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: good_ustx,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: PoxAddress::Standard(
                    StacksAddress::new(0x16, Hash160([1u8; 20])).unwrap(), None),
                signer_key: [1u8; 33],
            },
        };

        // Bad entry: very low STX, high BTC → low d_i (below d_min)
        let bad_entry = RawPox5Entry {
            user: StandardPrincipalData::new(0x16, [2u8; 20]).unwrap(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: bad_ustx,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: PoxAddress::Standard(
                    StacksAddress::new(0x16, Hash160([2u8; 20])).unwrap(), None),
                signer_key: [2u8; 33],
            },
        };

        let entries = vec![
            (good_entry, vec![watched_output(good_sats)]),
            (bad_entry, vec![watched_output(bad_sats)]),
        ];

        let result = NakamotoSigners::pox_5_make_reward_set(
            entries, &pox_constants, &mut provider, vec![],
        );
        prop_assert!(result.is_ok());
        let (reward_set, _) = result.unwrap();
        let signers = reward_set.signers.unwrap();

        // The bad entry should have been excluded
        let bad_signer = signers.iter().find(|s| s.signing_key == [2u8; 33]);
        prop_assert!(bad_signer.is_none(), "entry below d_min should be excluded from signers");
    }

    /// The time multiplier should scale with num_cycles. An entry with
    /// max cycles should receive a higher weighted stake than the same entry
    /// with 1 cycle (all else being equal).
    #[tag(t_prop)]
    #[test]
    fn pox5_time_multiplier_monotonic(
        amount_ustx in 1_000_000u128..10_000_000u128,
        sats in 10_000u64..100_000u64,
    ) {
        let pox_constants = make_test_pox_constants();

        // Run with num_cycles=1 and num_cycles=12, compare reward slots
        let make_entry = |num_cycles: u128, id: u8| -> Vec<(RawPox5Entry, Vec<WatchedP2WSHOutputMetadata>)> {
            let entry = RawPox5Entry {
                user: StandardPrincipalData::new(0x16, [id; 20]).unwrap(),
                num_cycles,
                unlock_bytes: vec![],
                amount_ustx,
                first_reward_cycle: 0,
                unlock_height: 1000,
                pox_info: RawPox5EntryInfo::Solo {
                    pox_addr: PoxAddress::Standard(
                        StacksAddress::new(0x16, Hash160([id; 20])).unwrap(), None),
                    signer_key: [id; 33],
                },
            };
            vec![(entry, vec![watched_output(sats)])]
        };

        let mut provider = MockPox5PoolInfoProvider::new();

        // Two entries: one with 1 cycle, one with 12 cycles
        let mut entries = make_entry(1, 1);
        entries.extend(make_entry(12, 2));

        let result = NakamotoSigners::pox_5_make_reward_set(
            entries, &pox_constants, &mut provider, vec![],
        );
        prop_assert!(result.is_ok(), "Expected okay result: {result:?}");
        let (reward_set, _) = result.unwrap();

        // The entry with more cycles should get >= reward slots than the one with fewer
        let short_slots = reward_set.rewarded_addresses.iter()
            .filter(|a| {
                matches!(a, PoxAddress::Standard(addr, _) if *addr.bytes() == Hash160([1u8; 20]))
            })
            .count();
        let long_slots = reward_set.rewarded_addresses.iter()
            .filter(|a| {
                matches!(a, PoxAddress::Standard(addr, _) if *addr.bytes() == Hash160([2u8; 20]))
            })
            .count();

        prop_assert!(
            long_slots >= short_slots,
            "entry with more lock cycles ({} slots) should get >= slots than shorter ({} slots)",
            long_slots,
            short_slots
        );
    }
}
