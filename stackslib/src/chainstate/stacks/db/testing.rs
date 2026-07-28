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

//! Test-support helpers for building a [`StacksChainState`] in tests.

use std::fs;

use super::*;

/// Builder for a fresh test [`StacksChainState`] created under `test_name`,
/// wiping any existing state at that path.
///
/// Required (via [`new_mainnet`](Self::new_mainnet) / [`new_testnet`](Self::new_testnet)):
/// the network and `test_name`.
/// Optional knobs:
/// - [`with_chain_id`](Self::with_chain_id),
/// - [`with_balances`](Self::with_balances).
pub struct TestChainstateBuilder {
    mainnet: bool,
    chain_id: u32,
    test_name: String,
    balances: Vec<(StacksAddress, u64)>,
}

impl TestChainstateBuilder {
    /// Start a builder for a **mainnet** test chainstate named `test_name`.
    /// `chain_id` defaults to [`CHAIN_ID_MAINNET`]; override it with
    /// [`with_chain_id`](Self::with_chain_id) for the rare test that needs a
    /// non-standard value.
    pub fn new_mainnet(test_name: &str) -> Self {
        Self::new(true, test_name)
    }

    /// Start a builder for a **testnet** test chainstate named `test_name`.
    /// `chain_id` defaults to [`CHAIN_ID_TESTNET`]; override it with
    /// [`with_chain_id`](Self::with_chain_id) for the rare test that needs a
    /// non-standard value.
    pub fn new_testnet(test_name: &str) -> Self {
        Self::new(false, test_name)
    }

    /// Start a builder for `test_name` on the given network. Prefer the
    /// [`new_mainnet`](Self::new_mainnet) / [`new_testnet`](Self::new_testnet)
    /// named constructors at call sites; this shared form exists for callers
    /// that only have the network as a runtime `bool`.
    fn new(mainnet: bool, test_name: &str) -> Self {
        let chain_id = if mainnet {
            CHAIN_ID_MAINNET
        } else {
            CHAIN_ID_TESTNET
        };
        Self {
            mainnet,
            chain_id,
            test_name: test_name.to_string(),
            balances: vec![],
        }
    }

    /// Override the chain id (defaults to the network's standard constant).
    pub fn with_chain_id(mut self, chain_id: u32) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Seed the given accounts with initial STX balances at genesis.
    pub fn with_balances(mut self, balances: Vec<(StacksAddress, u64)>) -> Self {
        self.balances = balances;
        self
    }

    pub fn build(self) -> StacksChainState<DiskChainStateBackend> {
        let path = chainstate_path(&self.test_name);
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let initial_balances = self
            .balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let pox_constants = if self.mainnet {
            PoxConstants::mainnet_default()
        } else {
            PoxConstants::testnet_default()
        };

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash: BurnchainHeaderHash::zero(),
            first_burnchain_block_height: 0,
            first_burnchain_block_timestamp: 0,
            pox_constants,
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_names: None,
            get_bulk_initial_namespaces: None,
        };

        StacksChainState::open_and_exec(
            self.mainnet,
            self.chain_id,
            &path,
            Some(&mut boot_data),
            None,
        )
        .unwrap()
        .0
    }
}

pub fn open_chainstate(
    mainnet: bool,
    chain_id: u32,
    test_name: &str,
) -> StacksChainState<DiskChainStateBackend> {
    let path = chainstate_path(test_name);
    StacksChainState::open(mainnet, chain_id, &path, None)
        .unwrap()
        .0
}

pub fn chainstate_path(test_name: &str) -> String {
    let test_name = test_name.replace("::", "-");
    format!("/tmp/stacks-node-tests/cs-{test_name}")
}
