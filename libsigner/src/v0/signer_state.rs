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
use std::time::{Duration, UNIX_EPOCH};

use blockstack_lib::chainstate::burn::ConsensusHashExtensions;
use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::StacksTransaction;
use clarity::types::chainstate::StacksAddress;
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;
use stacks_common::codec::Error as CodecError;
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, info, warn};

use crate::v0::messages::{
    MessageSlotID, SignerMessage, StateMachineUpdate, StateMachineUpdateContent,
    StateMachineUpdateMinerState,
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
                    } => (burn_block, burn_block_height, current_miner, None),
                    StateMachineUpdateContent::V1 {
                        burn_block,
                        burn_block_height,
                        current_miner,
                        replay_transactions,
                    } => (
                        burn_block,
                        burn_block_height,
                        current_miner,
                        Some(replay_transactions.clone()),
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
    pub tx_replay_set: Option<Vec<StacksTransaction>>,
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
