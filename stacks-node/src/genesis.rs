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

//! Genesis data for booting a node: the initial account balances, lockups and BNS
//! namespaces and names that the neon and nakamoto run loops load into chainstate.

use std::env;

use stacks::chainstate::stacks::db::{
    ChainstateAccountBalance, ChainstateAccountLockup, ChainstateBNSName, ChainstateBNSNamespace,
};

use crate::Config;

/// Builds use the full production `chainstate.txt` (e.g. `cargo build`); tests use a small test
/// file (e.g. `cargo test`) unless the `prod-genesis-chainstate` feature is enabled.
#[cfg(any(not(test), feature = "prod-genesis-chainstate"))]
const USE_TEST_GENESIS_CHAINSTATE: bool = false;

#[cfg(all(test, not(feature = "prod-genesis-chainstate")))]
const USE_TEST_GENESIS_CHAINSTATE: bool = true;

pub fn get_account_lockups(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountLockup>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_lockups()
            .map(|item| ChainstateAccountLockup {
                address: item.address,
                amount: item.amount,
                block_height: item.block_height,
            }),
    )
}

pub fn get_account_balances(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountBalance>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_balances()
            .map(|item| ChainstateAccountBalance {
                address: item.address,
                amount: item.amount,
            }),
    )
}

pub fn get_namespaces(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateBNSNamespace>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_namespaces()
            .map(|item| ChainstateBNSNamespace {
                namespace_id: item.namespace_id,
                importer: item.importer,
                buckets: item.buckets,
                base: item.base as u64,
                coeff: item.coeff as u64,
                nonalpha_discount: item.nonalpha_discount as u64,
                no_vowel_discount: item.no_vowel_discount as u64,
                lifetime: item.lifetime as u64,
            }),
    )
}

pub fn get_names(use_test_chainstate_data: bool) -> Box<dyn Iterator<Item = ChainstateBNSName>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_names()
            .map(|item| ChainstateBNSName {
                fully_qualified_name: item.fully_qualified_name,
                owner: item.owner,
                zonefile_hash: item.zonefile_hash,
            }),
    )
}

/// Check if the small test genesis chainstate data should be used.
/// First check env var, then config file, then use default.
pub fn use_test_genesis_chainstate(config: &Config) -> bool {
    if env::var("BLOCKSTACK_USE_TEST_GENESIS_CHAINSTATE") == Ok("1".to_string()) {
        true
    } else if let Some(use_test_genesis_chainstate) = config.node.use_test_genesis_chainstate {
        use_test_genesis_chainstate
    } else {
        USE_TEST_GENESIS_CHAINSTATE
    }
}
