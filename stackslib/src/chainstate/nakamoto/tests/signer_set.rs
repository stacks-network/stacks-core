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
use std::ops::Range;

use pinny::tag;
use proptest::array::uniform32;
use proptest::prelude::{any, prop, proptest, Strategy, TestCaseError};
use proptest::{prop_assert, prop_assert_eq, prop_assume};

use crate::burnchains::PoxConstants;
use crate::chainstate::nakamoto::signer_set::{
    NakamotoSigners, Pox5SignerSetOutput, PoxEntryParsingError, RawPox5Entry,
};
use crate::chainstate::stacks::boot::SIGNERS_PK_LEN;
use crate::chainstate::stacks::Error as ChainstateError;

/// Generate a `RawPox5Entry` with a uniformly random 33-byte signer key
/// and an `amount_ustx` drawn from `amount_range`.
fn raw_pox5_entry_strategy(amount_range: Range<u128>) -> impl Strategy<Value = RawPox5Entry> {
    (uniform32(any::<u8>()), any::<u8>(), amount_range).prop_map(|(first_32, last, amount_ustx)| {
        let mut signer_key = [0u8; SIGNERS_PK_LEN];
        signer_key[..32].copy_from_slice(&first_32);
        signer_key[32] = last;
        RawPox5Entry {
            amount_ustx,
            signer_key,
        }
    })
}

/// Build a `PoxConstants` whose `reward_slots()` returns `pox_slots * 4`
/// (matching the shape used by the reward-set proptest).
fn test_pox_constants(pox_slots: u32) -> PoxConstants {
    let prepare_length = 10;
    let reward_length = pox_slots * 2;
    let cycle_length = reward_length + prepare_length;
    PoxConstants::new(
        cycle_length,
        prepare_length,
        prepare_length / 2 + 1,
        10,
        10,
        u64::MAX,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    )
}

/// Aggregate the input entries the same way `pox_5_make_signer_set` does
/// (summing `amount_ustx` per `signer_key`) and return both the aggregated
/// map and the running total.
fn aggregate(entries: &[RawPox5Entry]) -> (HashMap<[u8; SIGNERS_PK_LEN], u128>, u128) {
    let mut by_signer: HashMap<[u8; SIGNERS_PK_LEN], u128> = HashMap::new();
    let mut total: u128 = 0;
    for entry in entries {
        total = total
            .checked_add(entry.amount_ustx)
            .expect("test inputs overflow u128");
        *by_signer.entry(entry.signer_key).or_default() += entry.amount_ustx;
    }
    (by_signer, total)
}

/// Run all of the property assertions for one set of inputs.
fn check_make_signer_set(
    pox_constants: PoxConstants,
    entries: Vec<RawPox5Entry>,
) -> Result<(), TestCaseError> {
    let (aggregated, total_ustx) = aggregate(&entries);
    let reward_slots = u128::from(pox_constants.reward_slots());
    prop_assume!(reward_slots > 0);
    let threshold = std::cmp::max(1, total_ustx.div_ceil(reward_slots));

    let mut iter = entries.into_iter().map(Ok);
    let Pox5SignerSetOutput {
        signer_set,
        pox_ustx_threshold,
    } = NakamotoSigners::pox_5_make_signer_set(&mut iter, &pox_constants)
        .map_err(|e| TestCaseError::fail(format!("pox_5_make_signer_set returned error: {e:?}")))?;

    // The returned threshold must match the closed form used above.
    prop_assert_eq!(pox_ustx_threshold, threshold);

    // (a) Output is sorted strictly ascending by signing_key
    //     (strict `<` also rules out duplicates).
    for window in signer_set.windows(2) {
        prop_assert!(
            window[0].signing_key < window[1].signing_key,
            "signer set is not strictly sorted by signing_key"
        );
    }

    // (b) Total weight is bounded above by reward_slots.
    let total_weight: u128 = signer_set.iter().map(|e| u128::from(e.weight)).sum();
    prop_assert!(
        total_weight <= reward_slots,
        "total weight {total_weight} exceeds reward_slots {reward_slots}"
    );

    // (c) For each output entry: stacked_amt matches the aggregated input,
    //     weight matches stacked_amt / threshold, and weight >= 1.
    let mut seen: HashMap<[u8; SIGNERS_PK_LEN], ()> = HashMap::new();
    for entry in &signer_set {
        seen.insert(entry.signing_key, ());
        let aggregated_amt = *aggregated.get(&entry.signing_key).ok_or_else(|| {
            TestCaseError::fail("output entry signing_key not present in input aggregation")
        })?;
        prop_assert_eq!(entry.stacked_amt, aggregated_amt);
        prop_assert_eq!(u128::from(entry.weight), aggregated_amt / threshold);
        prop_assert!(entry.weight >= 1, "filtered weight==0 entry leaked through");

        // The user-intuition bound, stated without intermediate rounding:
        //   weight <= reward_slots * stacked_amt / total_ustx
        // is equivalent to:
        //   weight * total_ustx <= stacked_amt * reward_slots
        // (when total_ustx > 0).
        if total_ustx > 0 {
            let lhs = u128::from(entry.weight)
                .checked_mul(total_ustx)
                .expect("weight * total overflow");
            let rhs = aggregated_amt
                .checked_mul(reward_slots)
                .expect("stacked * slots overflow");
            prop_assert!(
                lhs <= rhs,
                "weight {} violates slots*stacked/total bound (lhs={lhs}, rhs={rhs})",
                entry.weight
            );
        }
    }

    // (d) Filtering: every aggregated key with amount >= threshold is in the
    //     output; every key with amount < threshold is absent.
    for (key, amount) in &aggregated {
        if *amount >= threshold {
            prop_assert!(
                seen.contains_key(key),
                "input key with amount >= threshold missing from output"
            );
        } else {
            prop_assert!(
                !seen.contains_key(key),
                "input key with amount < threshold leaked into output"
            );
        }
    }

    Ok(())
}

proptest! {
    #[tag(t_prop)]
    /// Property tests for `pox_5_make_signer_set`:
    ///
    /// * Output is strictly sorted by signing_key (so: sorted + unique).
    /// * Total weight is bounded above by `pox_constants.reward_slots()`.
    /// * Per-entry `weight == aggregated_stacked / threshold` and `weight >= 1`,
    ///   where `threshold = max(1, total.div_ceil(reward_slots))`.
    /// * The filtering rule (`weight == 0` entries dropped) is correct in both
    ///   directions.
    ///
    /// `to_duplicate` forces the per-signer aggregation path by re-using
    /// existing `signer_key`s with new amounts.
    #[test]
    fn pox_5_make_signer_set_props(
        pox_slots in 1..4_000u32,
        mut entries in prop::collection::vec(raw_pox5_entry_strategy(1..100_000_000u128), 1..25_000),
        to_duplicate in prop::collection::vec((0..25_000usize, 1..100_000_000u128), 0..25_000),
    ) {
        let pox_constants = test_pox_constants(pox_slots);

        let _ = entries.try_reserve(to_duplicate.len());
        for (idx, amount_ustx) in to_duplicate.into_iter() {
            let signer_key = entries[idx % entries.len()].signer_key;
            entries.push(RawPox5Entry { amount_ustx, signer_key });
        }

        check_make_signer_set(pox_constants, entries)?;
    }
}

/// Build a 33-byte signer key by repeating a single byte. Convenient for
/// constructing readable unit-test inputs.
fn signer_key(byte: u8) -> [u8; SIGNERS_PK_LEN] {
    [byte; SIGNERS_PK_LEN]
}

#[test]
fn single_entry() {
    let pox_constants = test_pox_constants(1_000);
    let entries = vec![RawPox5Entry {
        signer_key: signer_key(0x01),
        amount_ustx: 1_000_000,
    }];
    let mut iter = entries.into_iter().map(Ok);
    let Pox5SignerSetOutput {
        signer_set,
        pox_ustx_threshold,
    } = NakamotoSigners::pox_5_make_signer_set(&mut iter, &pox_constants).expect("ok");
    assert_eq!(signer_set.len(), 1);
    assert_eq!(signer_set[0].signing_key, signer_key(0x01));
    assert_eq!(signer_set[0].stacked_amt, 1_000_000);
    // total == stacked, so threshold == ceil(total/slots) and weight == total / threshold.
    let total: u128 = 1_000_000;
    let expected_threshold =
        std::cmp::max(1, total.div_ceil(u128::from(pox_constants.reward_slots())));
    assert_eq!(pox_ustx_threshold, expected_threshold);
    assert_eq!(u128::from(signer_set[0].weight), total / expected_threshold);
}

#[test]
fn duplicate_signer_keys_are_aggregated() {
    let pox_constants = test_pox_constants(1_000);
    let key = signer_key(0xAA);
    let entries = vec![
        RawPox5Entry {
            signer_key: key,
            amount_ustx: 600_000,
        },
        RawPox5Entry {
            signer_key: key,
            amount_ustx: 400_000,
        },
    ];
    let mut iter = entries.into_iter().map(Ok);
    let Pox5SignerSetOutput { signer_set, .. } =
        NakamotoSigners::pox_5_make_signer_set(&mut iter, &pox_constants).expect("ok");
    assert_eq!(signer_set.len(), 1);
    assert_eq!(signer_set[0].signing_key, key);
    assert_eq!(signer_set[0].stacked_amt, 1_000_000);
}

#[test]
fn weight_zero_entries_are_filtered() {
    // Two signers: one with the bulk of the stake, one with a dust amount
    // that rounds down to weight zero. The dust signer must not appear.
    let pox_constants = test_pox_constants(1_000);
    let big = signer_key(0x01);
    let dust = signer_key(0x02);
    let entries = vec![
        RawPox5Entry {
            signer_key: big,
            amount_ustx: 10_000_000,
        },
        RawPox5Entry {
            signer_key: dust,
            amount_ustx: 1,
        },
    ];
    let mut iter = entries.into_iter().map(Ok);
    let Pox5SignerSetOutput { signer_set, .. } =
        NakamotoSigners::pox_5_make_signer_set(&mut iter, &pox_constants).expect("ok");
    assert_eq!(signer_set.len(), 1);
    assert_eq!(signer_set[0].signing_key, big);
}

#[test]
fn skip_errors_drop_entry_but_continue() {
    let pox_constants = test_pox_constants(1_000);
    let key_a = signer_key(0x01);
    let key_b = signer_key(0x02);
    let entries: Vec<Result<RawPox5Entry, PoxEntryParsingError>> = vec![
        Ok(RawPox5Entry {
            signer_key: key_a,
            amount_ustx: 1_000_000,
        }),
        Err(PoxEntryParsingError::Skip("synthetic skip".into())),
        Ok(RawPox5Entry {
            signer_key: key_b,
            amount_ustx: 1_000_000,
        }),
    ];
    let mut iter = entries.into_iter();
    let Pox5SignerSetOutput { signer_set, .. } =
        NakamotoSigners::pox_5_make_signer_set(&mut iter, &pox_constants).expect("ok");
    let keys: Vec<_> = signer_set.iter().map(|e| e.signing_key).collect();
    assert_eq!(keys, vec![key_a, key_b]);
}

#[test]
fn abort_error_propagates() {
    let pox_constants = test_pox_constants(1_000);
    let entries: Vec<Result<RawPox5Entry, PoxEntryParsingError>> = vec![
        Ok(RawPox5Entry {
            signer_key: signer_key(0x01),
            amount_ustx: 1_000_000,
        }),
        Err(PoxEntryParsingError::Abort("synthetic abort".into())),
    ];
    let mut iter = entries.into_iter();
    let err = NakamotoSigners::pox_5_make_signer_set(&mut iter, &pox_constants)
        .expect_err("expected abort to surface as Err");
    assert!(matches!(err, ChainstateError::PoxNoRewardCycle));
}
