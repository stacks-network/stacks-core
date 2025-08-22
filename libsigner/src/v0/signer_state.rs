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

use std::cmp::Ordering;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use blockstack_lib::chainstate::stacks::StacksTransaction;
use clarity::types::chainstate::StacksAddress;
use serde::{Deserialize, Serialize};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::util::hash::Hash160;

use crate::v0::messages::{StateMachineUpdate, StateMachineUpdateMinerState};

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
            let (burn_block, burn_block_height) = update.content.burn_block_view();

            let entry = burn_blocks
                .entry((burn_block, burn_block_height))
                .or_insert_with(|| 0);
            *entry += weight;
            if self.reached_agreement(*entry) {
                return Some((*burn_block, burn_block_height));
            }
        }
        None
    }

    /// Check if there is an agreed upon global state
    pub fn determine_global_state(&mut self) -> Option<SignerStateMachine> {
        let active_signer_protocol_version =
            self.determine_latest_supported_signer_protocol_version()?;
        let mut state_views = HashMap::new();
        let mut tx_replay_sets = HashMap::new();
        let mut found_state_view = None;
        let mut found_replay_set = None;
        for (address, update) in &self.address_updates {
            let Some(weight) = self.address_weights.get(address) else {
                continue;
            };
            let (burn_block, burn_block_height) = update.content.burn_block_view();
            let current_miner = update.content.current_miner();
            let tx_replay_set = update.content.tx_replay_set();

            let state_machine = SignerStateMachine {
                burn_block: *burn_block,
                burn_block_height,
                current_miner: current_miner.into(),
                active_signer_protocol_version,
                // We need to calculate the threshold for the tx_replay_set separately
                tx_replay_set: ReplayTransactionSet::none(),
            };
            let key = SignerStateMachineKey(state_machine.clone());
            let entry = state_views.entry(key).or_insert_with(|| 0);
            *entry += weight;

            if self.reached_agreement(*entry) {
                found_state_view = Some(state_machine);
            }

            let replay_entry = tx_replay_sets
                .entry(tx_replay_set.clone())
                .or_insert_with(|| 0);
            *replay_entry += weight;

            if self.reached_agreement(*replay_entry) {
                found_replay_set = Some(tx_replay_set);
            }
            if found_replay_set.is_some() && found_state_view.is_some() {
                break;
            }
        }
        // Try to find agreed replay set, or find longest common prefix if no exact agreement
        let final_replay_set = if let Some(tx_replay_set) = found_replay_set {
            tx_replay_set
        } else {
            // No exact agreement found, try finding longest common prefix with majority support
            self.find_majority_prefix_replay_set(&tx_replay_sets)
                .unwrap_or_else(ReplayTransactionSet::none)
        };

        if let Some(state_view) = found_state_view.as_mut() {
            state_view.tx_replay_set = final_replay_set;
        }
        found_state_view
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

    /// Find the longest common prefix of replay sets that has majority support.
    /// This implements the longest common prefix (LCP) strategy where if one signer's replay set
    /// is [A,B,C] and another is [A,B], we should use [A,B] as the replay set.
    /// Order matters for transaction replay - [A,B] and [B,A] have no common prefix.
    fn find_majority_prefix_replay_set(
        &self,
        tx_replay_sets: &HashMap<ReplayTransactionSet, u32>,
    ) -> Option<ReplayTransactionSet> {
        if tx_replay_sets.is_empty() {
            return None;
        }

        // First, try to find an exact match that reaches agreement
        for (replay_set, weight) in tx_replay_sets {
            if self.reached_agreement(*weight) {
                return Some(replay_set.clone());
            }
        }

        // No exact agreement found, find longest common prefix with majority support

        // Sort replay sets by weight (descending), then deterministically by length and content
        let mut sorted_sets: Vec<_> = tx_replay_sets.iter().collect();
        sorted_sets.sort_by(|(set_a, weight_a), (set_b, weight_b)| {
            // Primary: weight descending
            let weight_cmp = weight_b.cmp(weight_a);
            if weight_cmp != Ordering::Equal {
                return weight_cmp;
            }
            // Secondary: length descending (longer sequences first)
            let len_cmp = set_b.0.len().cmp(&set_a.0.len());
            if len_cmp != Ordering::Equal {
                return len_cmp;
            }
            // Tertiary: compare transaction IDs for determinism
            for (lhs, rhs) in set_a.0.iter().zip(&set_b.0) {
                let ord = lhs.txid().cmp(&rhs.txid());
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            Ordering::Equal
        });

        // Start with the most supported replay set as initial candidate
        if let Some((initial_set, _)) = sorted_sets.first() {
            let mut candidate_prefix = initial_set.0.clone();
            let mut total_supporting_weight = 0u32;

            // Find all sets that support the current candidate prefix
            for (replay_set, weight) in tx_replay_sets {
                if replay_set.0.starts_with(&candidate_prefix) {
                    total_supporting_weight = total_supporting_weight.saturating_add(*weight);
                }
            }

            // If the initial candidate already has majority support, return it
            if self.reached_agreement(total_supporting_weight) {
                return Some(ReplayTransactionSet::new(candidate_prefix));
            }

            // Otherwise, iteratively truncate the prefix until we find majority support
            while !candidate_prefix.is_empty() {
                // Remove the last transaction from the prefix
                candidate_prefix.pop();

                // Recalculate supporting weight for the shorter prefix
                total_supporting_weight = 0u32;
                for (replay_set, weight) in tx_replay_sets {
                    if replay_set.0.starts_with(&candidate_prefix) {
                        total_supporting_weight = total_supporting_weight.saturating_add(*weight);
                    }
                }

                // If this prefix has majority support, return it
                if self.reached_agreement(total_supporting_weight) {
                    return Some(ReplayTransactionSet::new(candidate_prefix));
                }
            }
        }

        // If no common prefix with majority support is found, return None
        None
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug)]
/// A wrapped SignerStateMachine that implements a very specific hash that enables properly ignoring the
/// tx_replay_set when evaluating the global signer state machine
pub struct SignerStateMachineKey(SignerStateMachine);

impl PartialEq for SignerStateMachineKey {
    fn eq(&self, other: &Self) -> bool {
        // NOTE: tx_replay_set is intentionally ignored
        self.0.burn_block == other.0.burn_block
            && self.0.burn_block_height == other.0.burn_block_height
            && self.0.current_miner == other.0.current_miner
            && self.0.active_signer_protocol_version == other.0.active_signer_protocol_version
    }
}

impl Eq for SignerStateMachineKey {}

impl Hash for SignerStateMachineKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // tx_replay_set is intentionally ignored
        self.0.burn_block.hash(state);
        self.0.burn_block_height.hash(state);
        self.0.current_miner.hash(state);
        self.0.active_signer_protocol_version.hash(state);
    }
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
