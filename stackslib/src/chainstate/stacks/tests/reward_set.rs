use std::collections::HashMap;

use clarity::types::chainstate::StacksAddress;
use clarity::types::StacksEpochId;
use clarity::util::hash::Hash160;
use proptest::array::{uniform20, uniform32};
use proptest::prelude::{any, prop, proptest, Strategy, TestCaseError};
use proptest::{prop_assert_eq, prop_assume, prop_oneof};

use crate::burnchains::PoxConstants;
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType20, PoxAddressType32};
use crate::chainstate::stacks::boot::RawRewardSetEntry;
use crate::chainstate::stacks::db::StacksChainState;

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

proptest! {
    #[test]
    fn make_reward_set(
        pox_slots in 1..4_000u32,
        unstacked_ustx in 0..1_000_000_000u128,
        mut addrs in prop::collection::vec(reward_set_entry_strategy(), 1..25_000),
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

pub fn pox_address_standard() -> impl Strategy<Value = PoxAddress> {
    (
        prop::sample::select(&[20u8, 21, 22, 26]),
        uniform20(any::<u8>()),
    )
        .prop_map(|(version, bytes)| {
            PoxAddress::Standard(StacksAddress::new(version, Hash160(bytes)).unwrap(), None)
        })
}

pub fn pox_address_addr20() -> impl Strategy<Value = PoxAddress> {
    (
        any::<bool>(),
        prop::sample::select(&[PoxAddressType20::P2WPKH]),
        uniform20(any::<u8>()),
    )
        .prop_map(|(mainnet, addr_ty, bytes)| PoxAddress::Addr20(mainnet, addr_ty, bytes))
}

pub fn pox_address_addr32() -> impl Strategy<Value = PoxAddress> {
    (
        any::<bool>(),
        prop::sample::select(&[PoxAddressType32::P2TR, PoxAddressType32::P2WSH]),
        uniform32(any::<u8>()),
    )
        .prop_map(|(mainnet, addr_ty, bytes)| PoxAddress::Addr32(mainnet, addr_ty, bytes))
}

pub fn pox_address_strategy() -> impl Strategy<Value = PoxAddress> {
    prop_oneof![
        pox_address_standard(),
        pox_address_addr32(),
        pox_address_addr20()
    ]
}

pub fn reward_set_entry_strategy() -> impl Strategy<Value = RawRewardSetEntry> {
    (pox_address_strategy(), 1..100_000_000u128).prop_map(|(reward_address, amount_stacked)| {
        RawRewardSetEntry {
            reward_address,
            amount_stacked,
            stacker: None,
            signer: None,
        }
    })
}
