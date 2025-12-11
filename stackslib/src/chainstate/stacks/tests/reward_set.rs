use std::collections::HashMap;

use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::StacksEpochId;
use proptest::prelude::{prop, proptest, TestCaseError};
use proptest::{prop_assert_eq, prop_assume};
use stacks_common::util::hash::Hash160;

use crate::burnchains::PoxConstants;
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::RawRewardSetEntry;
use crate::chainstate::stacks::db::StacksChainState;
use crate::proptest_utils::reward_set_entry_strategy;

pub fn check_make_reward_set(
    pox_settings: PoxConstants,
    addresses: &[RawRewardSetEntry],
    unstacked_ustx: u128,
) -> Result<(), TestCaseError> {
    let total_stacked = addresses.iter().try_fold(0_u128, |total, entry| {
        total
            .checked_add(entry.amount_stacked)
            .ok_or_else(|| TestCaseError::Reject("Reward set entries must be summable".into()))
    })?;

    let liquid_ustx = total_stacked
        .checked_add(unstacked_ustx)
        .ok_or_else(|| TestCaseError::Reject("Total ustx must be summable".into()))?;

    prop_assume!(total_stacked <= liquid_ustx);

    let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
        &pox_settings,
        addresses,
        liquid_ustx,
    );

    prop_assume!(threshold > 0);

    let reward_set =
        StacksChainState::make_reward_set(threshold, addresses.to_vec(), StacksEpochId::Epoch33);

    prop_assert_eq!(Some(threshold), reward_set.pox_ustx_threshold);

    let mut sum_by_addresses: HashMap<PoxAddress, u128> = HashMap::new();
    for addr in addresses.iter() {
        let entry = sum_by_addresses
            .entry(addr.reward_address.clone())
            .or_default();
        *entry += addr.amount_stacked;
    }

    for (addr, stacked_amount) in sum_by_addresses.iter() {
        let slot_count: u128 = reward_set
            .rewarded_addresses
            .iter()
            .filter(|x| *x == addr)
            .count()
            .try_into()
            .unwrap();

        prop_assert_eq!(slot_count, stacked_amount / threshold);
    }

    Ok(())
}

#[test]
/// Invoke the reward set property test with some known corner cases
fn units_make_reward_set() {
    struct TestVector {
        entries: Vec<RawRewardSetEntry>,
        unstacked_amount: u128,
    }

    let prepare_length = 10;
    let reward_length = 2_000 * 2;
    let cycle_length = reward_length + prepare_length;
    let pox_settings = PoxConstants::new(
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
    );

    let addrs: Vec<_> = (0..10u64).map(|x| PoxAddress::Standard(
        StacksAddress::new(20, Hash160::from_data(&x.to_be_bytes())).unwrap(),
        None)
    ).collect();

    let test_vectors = [
        // Test a reward set where two participants don't stack enough to get slots
        TestVector {
            entries: vec![
                RawRewardSetEntry {
                    reward_address: addrs[0].clone(),
                    amount_stacked: 1_000_000,
                    stacker: None,
                    signer: None,
                },
                RawRewardSetEntry {
                    reward_address: addrs[1].clone(),
                    amount_stacked: 500_000,
                    stacker: None,
                    signer: None,
                },
                RawRewardSetEntry {
                    reward_address: addrs[3].clone(),
                    amount_stacked: 0,
                    stacker: None,
                    signer: None,
                },
                RawRewardSetEntry {
                    reward_address: addrs[4].clone(),
                    amount_stacked: 10,
                    stacker: None,
                    signer: None,
                },
            ],
            unstacked_amount: 4000,
        },
        // Test a reward set with not enough participation for any
        // slots to be claimed
        TestVector {
            entries: vec![
                RawRewardSetEntry {
                    reward_address: addrs[0].clone(),
                    amount_stacked: 100_000,
                    stacker: None,
                    signer: None,
                },
                RawRewardSetEntry {
                    reward_address: addrs[1].clone(),
                    amount_stacked: 50_000,
                    stacker: None,
                    signer: None,
                },
                RawRewardSetEntry {
                    reward_address: addrs[0].clone(),
                    amount_stacked: 20_000,
                    stacker: None,
                    signer: None,
                },
            ],
            unstacked_amount: 40_000_000_000_000,
        },
        // Test a reward set with repeated entries for the same
        // address
        TestVector {
            entries: vec![
                RawRewardSetEntry {
                    reward_address: addrs[0].clone(),
                    amount_stacked: 100_000,
                    stacker: None,
                    signer: None,
                },
                RawRewardSetEntry {
                    reward_address: addrs[1].clone(),
                    amount_stacked: 50_000,
                    stacker: None,
                    signer: None,
                },
                RawRewardSetEntry {
                    reward_address: addrs[0].clone(),
                    amount_stacked: 20_000,
                    stacker: None,
                    signer: None,
                },
            ],
            unstacked_amount: 0,
        },
    ];

    for TestVector { ref entries, unstacked_amount } in test_vectors.iter() {
        check_make_reward_set(pox_settings.clone(), entries.as_slice(), *unstacked_amount).unwrap();
    }
}

proptest! {
    /// Property testing for the make_reward_set:
    ///
    /// * Each reward set participants' allotted slots should equal
    /// the integer division of their total amount stacked across all
    /// entries, divided by the threshold number.
    /// 
    /// This test forces a number of the addresses to have multiple
    /// entries (generated by the `to_duplicate` argument in the
    /// proptest)
    #[test]
    fn make_reward_set(
        pox_slots in 1..4_000u32,
        unstacked_ustx in 0..1_000_000_000u128,
        mut addrs in prop::collection::vec(reward_set_entry_strategy(1..100_000_000u128), 1..25_000),
        to_duplicate in prop::collection::vec((0..25_000usize, 0..100_000_000u128), 0..25_000)
    ) {
        let prepare_length = 10;
        let reward_length = pox_slots * 2;
        let cycle_length = reward_length + prepare_length;
        let pox_settings = PoxConstants::new(
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
        );

        let _ = addrs.try_reserve(to_duplicate.len());
        for (to_dup_ix, duplicated_amount) in to_duplicate.into_iter() {
            let mut new_entry = addrs[to_dup_ix % addrs.len()].clone();
            new_entry.amount_stacked = duplicated_amount;
            addrs.push(new_entry);
        }

        check_make_reward_set(pox_settings, addrs.as_slice(), unstacked_ustx)?;
    }
}
