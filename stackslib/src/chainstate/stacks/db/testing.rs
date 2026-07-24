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

use clarity::vm::ClarityVersion;

use super::*;
use crate::chainstate::stacks::boot::{
    BOOT_CODE_COSTS_2, BOOT_CODE_COSTS_2_TESTNET, BOOT_CODE_COSTS_3, BOOT_CODE_COSTS_4,
};
use crate::util_lib::boot::boot_code_id;

/// Builder for a fresh test [`StacksChainState`] created under `test_name`,
/// wiping any existing state at that path. Genesis deploys the standard boot
/// contracts (e.g. `pox`, `costs`, ...); of the cost
/// contracts, only `costs` (v1) is present by default. The later boot cost
/// contracts (`costs-2`, `costs-3`, `costs-4`) are normally installed by the
/// real epoch transitions as the chain advances; use
/// [`with_all_boot_costs`](Self::with_all_boot_costs) to deploy them at
/// genesis instead. (`costs-5` and later are native Rust cost functions, not
/// deployed contracts, so they are never installed this way.)
///
/// Required (via [`new_mainnet`](Self::new_mainnet) / [`new_testnet`](Self::new_testnet)):
/// the network and `test_name`.
/// Optional knobs:
/// - [`with_chain_id`](Self::with_chain_id),
/// - [`with_balances`](Self::with_balances),
/// - [`with_all_boot_costs`](Self::with_all_boot_costs).
pub struct TestChainstateBuilder {
    mainnet: bool,
    chain_id: u32,
    test_name: String,
    balances: Vec<(StacksAddress, u64)>,
    all_boot_costs: bool,
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
            all_boot_costs: false,
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

    /// Deploy the later boot cost contracts (`costs-2`, `costs-3`, `costs-4`)
    /// during genesis so that [`LimitedCostTracker`] can load the deployed
    /// cost contract for any epoch up to `costs-4`. (`costs-5` and later are
    /// native Rust cost functions, resolved by epoch without deployment.)
    pub fn with_all_boot_costs(mut self) -> Self {
        self.all_boot_costs = true;
        self
    }

    pub fn build(self) -> StacksChainState {
        let path = chainstate_path(&self.test_name);
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        };

        let initial_balances = self
            .balances
            .into_iter()
            .map(|(addr, balance)| (PrincipalData::from(addr), balance))
            .collect();

        let mainnet = self.mainnet;
        let post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx)>> =
            self.all_boot_costs.then(|| {
                Box::new(move |clarity_tx: &mut ClarityTx| {
                    deploy_all_boot_costs(clarity_tx, mainnet)
                }) as Box<dyn FnOnce(&mut ClarityTx)>
            });

        let pox_constants = if self.mainnet {
            PoxConstants::mainnet_default()
        } else {
            PoxConstants::testnet_default()
        };

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback,
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

/// Deploy the later boot cost contracts (`costs-2`, `costs-3`, `costs-4`) at
/// genesis (used by [`TestChainstateBuilder::with_all_boot_costs`]).
///
/// Each contract is deployed under the epoch that introduces it, using that
/// epoch's default Clarity version (via [`ClarityVersion::default_for_epoch`]),
/// so that contracts can be properly analyzed and deployed.
fn deploy_all_boot_costs(clarity_tx: &mut ClarityTx, mainnet: bool) {
    // Match `initialize_epoch_2_05`: on testnet, load the testnet
    // variant of `costs-2`. Only `costs-2` has a testnet variant.
    let costs_2_code = if mainnet {
        BOOT_CODE_COSTS_2
    } else {
        BOOT_CODE_COSTS_2_TESTNET
    };

    // This is the complete, closed set of deployable `costs-N` boot
    // contracts. `costs-5` (Epoch 4.0) and every later cost function are
    // native (Rust) — resolved by epoch and never deployed — so there is
    // no further contract to add here.
    let contracts: &[(&str, &str, StacksEpochId)] = &[
        (COSTS_2_NAME, costs_2_code, StacksEpochId::Epoch2_05),
        (COSTS_3_NAME, BOOT_CODE_COSTS_3, StacksEpochId::Epoch21),
        (COSTS_4_NAME, BOOT_CODE_COSTS_4, StacksEpochId::Epoch33),
    ];

    let conn = clarity_tx.connection();

    for (name, code, epoch) in contracts {
        let version = ClarityVersion::default_for_epoch(*epoch);
        conn.set_epoch(*epoch);
        conn.as_transaction(|clarity_db| {
            let (ast, _) = clarity_db
                .analyze_smart_contract(&boot_code_id(name, mainnet), version, code, None)
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &boot_code_id(name, mainnet),
                    version,
                    &ast,
                    code,
                    None,
                    |_, _| None,
                    None,
                )
                .unwrap();
        });
    }

    // restore genesis epoch
    conn.set_epoch(GENESIS_EPOCH);
}

pub fn open_chainstate(mainnet: bool, chain_id: u32, test_name: &str) -> StacksChainState {
    let path = chainstate_path(test_name);
    StacksChainState::open(mainnet, chain_id, &path, None)
        .unwrap()
        .0
}

pub fn chainstate_path(test_name: &str) -> String {
    let test_name = test_name.replace("::", "-");
    format!("/tmp/stacks-node-tests/cs-{test_name}")
}
