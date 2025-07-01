// Copyright (C) 2025 Stacks Open Internet Foundation
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

use blockstack_lib::chainstate::stacks::StacksTransaction;
use clarity::types::chainstate::StacksAddress;
use serde::{Deserialize, Serialize};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::util::hash::Hash160;

use crate::v0::messages::{
    StateMachineUpdate, StateMachineUpdateContent, StateMachineUpdateMinerState,
};

/// A struct used to determine the current global state
#[derive(Debug)]
pub struct GlobalStateEvaluator {
    /// A mapping of signer addresses to their corresponding vote weight
    pub address_weights: HashMap<StacksAddress, u32>,
    /// A mapping of signer addresses to their corresponding updates
    pub address_updates: HashMap<StacksAddress, StateMachineUpdate>,
    /// The total weight of all signers
    pub total_weight: u32,
}

impl GlobalStateEvaluator {
    /// Create a new state evaluator
    pub fn new(
        address_updates: HashMap<StacksAddress, StateMachineUpdate>,
        address_weights: HashMap<StacksAddress, u32>,
    ) -> Self {
        let total_weight = address_weights
            .values()
            .fold(0u32, |acc, val| acc.saturating_add(*val));
        Self {
            address_weights,
            address_updates,
            total_weight,
        }
    }

    /// Determine what the maximum signer protocol version that a majority of signers can support
    pub fn determine_latest_supported_signer_protocol_version(&mut self) -> Option<u64> {
        let mut protocol_versions = HashMap::new();
        for (address, update) in &self.address_updates {
            let Some(weight) = self.address_weights.get(address) else {
                continue;
            };
            let entry = protocol_versions
                .entry(update.local_supported_signer_protocol_version)
                .or_insert_with(|| 0);
            *entry += weight;
        }
        // find the highest version number supported by a threshold number of signers
        let mut protocol_versions: Vec<_> = protocol_versions.into_iter().collect();
        protocol_versions.sort_by_key(|(version, _)| *version);
        let mut total_weight_support = 0;
        for (version, weight_support) in protocol_versions.into_iter().rev() {
            total_weight_support += weight_support;
            if total_weight_support >= self.total_weight * 7 / 10 {
                return Some(version);
            }
        }
        None
    }

    /// Determine what the global burn view is if there is one
    pub fn determine_global_burn_view(&mut self) -> Option<(ConsensusHash, u64)> {
        let mut burn_blocks = HashMap::new();
        for (address, update) in &self.address_updates {
            let Some(weight) = self.address_weights.get(address) else {
                continue;
            };
            let (burn_block, burn_block_height) = match update.content {
                StateMachineUpdateContent::V0 {
                    burn_block,
                    burn_block_height,
                    ..
                }
                | StateMachineUpdateContent::V1 {
                    burn_block,
                    burn_block_height,
                    ..
                } => (burn_block, burn_block_height),
            };

            let entry = burn_blocks
                .entry((burn_block, burn_block_height))
                .or_insert_with(|| 0);
            *entry += weight;
            if self.reached_agreement(*entry) {
                return Some((burn_block, burn_block_height));
            }
        }
        None
    }

    /// Check if there is an agreed upon global state
    pub fn determine_global_state(&mut self) -> Option<SignerStateMachine> {
        let active_signer_protocol_version =
            self.determine_latest_supported_signer_protocol_version()?;
        let mut state_views = HashMap::new();
        for (address, update) in &self.address_updates {
            let Some(weight) = self.address_weights.get(address) else {
                continue;
            };
            let (burn_block, burn_block_height, current_miner, tx_replay_set) =
                match &update.content {
                    StateMachineUpdateContent::V0 {
                        burn_block,
                        burn_block_height,
                        current_miner,
                        ..
                    } => (
                        burn_block,
                        burn_block_height,
                        current_miner,
                        ReplayTransactionSet::none(),
                    ),
                    StateMachineUpdateContent::V1 {
                        burn_block,
                        burn_block_height,
                        current_miner,
                        replay_transactions,
                    } => (
                        burn_block,
                        burn_block_height,
                        current_miner,
                        ReplayTransactionSet::new(replay_transactions.clone()),
                    ),
                };
            let state_machine = SignerStateMachine {
                burn_block: *burn_block,
                burn_block_height: *burn_block_height,
                current_miner: current_miner.into(),
                active_signer_protocol_version,
                tx_replay_set,
            };
            let entry = state_views
                .entry(state_machine.clone())
                .or_insert_with(|| 0);
            *entry += weight;
            if self.reached_agreement(*entry) {
                return Some(state_machine);
            }
        }
        None
    }

    /// Will insert the update for the given address and weight only if the GlobalStateMachineEvaluator already is aware of this address
    pub fn insert_update(&mut self, address: StacksAddress, update: StateMachineUpdate) -> bool {
        if !self.address_weights.contains_key(&address) {
            return false;
        }
        self.address_updates.insert(address, update);
        true
    }

    /// Check if the supplied vote weight crosses the global agreement threshold.
    /// Returns true if it has, false otherwise.
    pub fn reached_agreement(&self, vote_weight: u32) -> bool {
        vote_weight >= self.total_weight * 7 / 10
    }

    /// Get the global transaction replay set. Returns `None` if there
    /// is no global state.
    pub fn get_global_tx_replay_set(&mut self) -> Option<ReplayTransactionSet> {
        let global_state = self.determine_global_state()?;
        Some(global_state.tx_replay_set)
    }
}

/// A "wrapper" struct around Vec<StacksTransaction> that behaves like
/// `None` when the vector is empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct ReplayTransactionSet(Vec<StacksTransaction>);

impl ReplayTransactionSet {
    /// Create a new `ReplayTransactionSet`
    pub fn new(tx_replay_set: Vec<StacksTransaction>) -> Self {
        Self(tx_replay_set)
    }

    /// Check if the `ReplayTransactionSet` is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Map into an optional, returning `None` if the set is empty
    pub fn clone_as_optional(&self) -> Option<Vec<StacksTransaction>> {
        if self.is_empty() {
            None
        } else {
            Some(self.0.clone())
        }
    }

    /// Unwrap the `ReplayTransactionSet` or return a default vector if it is empty
    pub fn unwrap_or_default(self) -> Vec<StacksTransaction> {
        if self.is_empty() {
            vec![]
        } else {
            self.0
        }
    }

    /// Map the transactions in the set to a new type, only
    /// if the set is not empty
    pub fn map<U, F>(self, f: F) -> Option<U>
    where
        F: Fn(Vec<StacksTransaction>) -> U,
    {
        if self.is_empty() {
            None
        } else {
            Some(f(self.0))
        }
    }

    /// Create a new `ReplayTransactionSet` with no transactions
    pub fn none() -> Self {
        Self(vec![])
    }

    /// Check if the `ReplayTransactionSet` isn't empty
    pub fn is_some(&self) -> bool {
        !self.is_empty()
    }
}

impl Default for ReplayTransactionSet {
    fn default() -> Self {
        Self::none()
    }
}

/// A signer state machine view. This struct can
///  be used to encode the local signer's view or
///  the global view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
pub struct SignerStateMachine {
    /// The tip burn block (i.e., the latest bitcoin block) seen by this signer
    pub burn_block: ConsensusHash,
    /// The tip burn block height (i.e., the latest bitcoin block) seen by this signer
    pub burn_block_height: u64,
    /// The signer's view of who the current miner should be (and their tenure building info)
    pub current_miner: MinerState,
    /// The active signing protocol version
    pub active_signer_protocol_version: u64,
    /// Transaction replay set
    pub tx_replay_set: ReplayTransactionSet,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
/// Enum for capturing the signer state machine's view of who
///  should be the active miner and what their tenure should be
///  built on top of.
pub enum MinerState {
    /// The information for the current active miner
    ActiveMiner {
        /// The pubkeyhash of the current miner's signing key
        current_miner_pkh: Hash160,
        /// The tenure ID of the current miner's active tenure
        tenure_id: ConsensusHash,
        /// The tenure that the current miner is building on top of
        parent_tenure_id: ConsensusHash,
        /// The last block of the parent tenure (which should be
        ///  the block that the next tenure starts from)
        parent_tenure_last_block: StacksBlockId,
        /// The height of the last block of the parent tenure (which should be
        ///  the block that the next tenure starts from)
        parent_tenure_last_block_height: u64,
    },
    /// This signer doesn't believe there's any valid miner
    NoValidMiner,
}

impl From<&StateMachineUpdateMinerState> for MinerState {
    fn from(val: &StateMachineUpdateMinerState) -> Self {
        match *val {
            StateMachineUpdateMinerState::NoValidMiner => MinerState::NoValidMiner,
            StateMachineUpdateMinerState::ActiveMiner {
                current_miner_pkh,
                tenure_id,
                parent_tenure_id,
                parent_tenure_last_block,
                parent_tenure_last_block_height,
            } => MinerState::ActiveMiner {
                current_miner_pkh,
                tenure_id,
                parent_tenure_id,
                parent_tenure_last_block,
                parent_tenure_last_block_height,
            },
        }
    }
}
