use std::ops::Range;

use proptest::array::{uniform20, uniform32};
use proptest::prelude::{any, prop, Strategy};
use proptest::prop_oneof;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::Hash160;

use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType20, PoxAddressType32};
use crate::chainstate::stacks::boot::RawRewardSetEntry;

/// Generate a PoxAddress::Standard with uniform sampling over the 4
/// standard network versions and the 20-byte Hash160.
pub fn pox_address_standard() -> impl Strategy<Value = PoxAddress> {
    (
        prop::sample::select(&[20u8, 21, 22, 26]),
        uniform20(any::<u8>()),
    )
        .prop_map(|(version, bytes)| -> PoxAddress {
            PoxAddress::Standard(StacksAddress::new(version, Hash160(bytes)).unwrap(), None)
        })
}

/// Generate a PoxAddress::Addr20 with uniform sampling over
/// mainnet/testnet and 20 bytes
pub fn pox_address_addr20() -> impl Strategy<Value = PoxAddress> {
    (
        any::<bool>(),
        prop::sample::select(&[PoxAddressType20::P2WPKH]),
        uniform20(any::<u8>()),
    )
        .prop_map(|(mainnet, addr_ty, bytes)| PoxAddress::Addr20(mainnet, addr_ty, bytes))
}

/// Generate a PoxAddress::Addr32 with uniform sampling over
/// mainnet/testnet, P2TR/P2WSH and 32 bytes
pub fn pox_address_addr32() -> impl Strategy<Value = PoxAddress> {
    (
        any::<bool>(),
        prop::sample::select(&[PoxAddressType32::P2TR, PoxAddressType32::P2WSH]),
        uniform32(any::<u8>()),
    )
        .prop_map(|(mainnet, addr_ty, bytes)| PoxAddress::Addr32(mainnet, addr_ty, bytes))
}

/// Generate a PoxAddress with uniform sampling over Addr20, Addr32,
/// and Standard PoxAddresses, using `pox_address_standard`,
/// `pox_address_addr32` and `pox_address_addr20` to generate.
pub fn pox_address_strategy() -> impl Strategy<Value = PoxAddress> {
    prop_oneof![
        pox_address_standard(),
        pox_address_addr32(),
        pox_address_addr20()
    ]
}

/// Generate `RawRewardSetEntry`s, using the `pox_address_strategy` and the supplied range of u128s for generating
///  the total amount stacked.
pub fn reward_set_entry_strategy(
    amount_stacked: Range<u128>,
) -> impl Strategy<Value = RawRewardSetEntry> {
    (pox_address_strategy(), amount_stacked).prop_map(|(reward_address, amount_stacked)| {
        RawRewardSetEntry {
            reward_address,
            amount_stacked,
            stacker: None,
            signer: None,
        }
    })
}
