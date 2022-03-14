// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use burnchains::stacks::AppChainConfig;
use burnchains::Burnchain;

use core::MINING_COMMITMENT_WINDOW;
use core::NETWORK_ID_MAINNET;
use core::NETWORK_ID_TESTNET;
use core::PEER_VERSION_MAINNET;
use core::PEER_VERSION_TESTNET;

use util_lib::db::Error as db_error;

/// appchain-specific implementations for burnchain
impl Burnchain {
    pub fn new_appchain(
        appchain_config: &AppChainConfig,
        working_dir: &str,
    ) -> Result<Burnchain, db_error> {
        Ok(Burnchain {
            peer_version: if appchain_config.mainnet() {
                PEER_VERSION_MAINNET
            } else {
                PEER_VERSION_TESTNET
            },
            network_id: appchain_config.parent_chain_id(),
            chain_name: format!("{}", &appchain_config.mining_contract_id()),
            network_name: if appchain_config.mainnet() {
                "mainnet".to_string()
            } else {
                "testnet".to_string()
            },
            working_dir: working_dir.to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: appchain_config.start_block(),
            first_block_hash: appchain_config.start_block_hash(),
            first_block_timestamp: 0,
            initial_reward_start_block: appchain_config.start_block(),
            pox_constants: appchain_config.pox_constants(),
        })
    }
}
