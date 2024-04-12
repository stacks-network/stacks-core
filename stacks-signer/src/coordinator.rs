// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::time::Instant;

use blockstack_lib::chainstate::burn::ConsensusHashExtensions;
use slog::slog_debug;
use stacks_common::debug;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::util::hash::Sha256Sum;
use wsts::curve::ecdsa;
use wsts::state_machine::PublicKeys;

/// TODO: test this value and adjust as necessary. Maybe make configurable?
pub const COORDINATOR_OPERATION_TIMEOUT_SECS: u64 = 300;

/// TODO: test this value and adjust as necessary. Maybe make configurable?
pub const COORDINATOR_TENURE_TIMEOUT_SECS: u64 = 600;

/// The coordinator selector
#[derive(Clone, Debug)]
pub struct CoordinatorSelector {
    /// The ordered list of potential coordinators for a specific consensus hash
    coordinator_ids: Vec<u32>,
    /// The current coordinator id
    coordinator_id: u32,
    /// The current coordinator index into the coordinator ids list
    coordinator_index: usize,
    /// The last message received time for the current coordinator
    pub last_message_time: Option<Instant>,
    /// The time the coordinator started its tenure
    tenure_start: Instant,
    /// The public keys of the coordinators
    public_keys: PublicKeys,
}

impl From<PublicKeys> for CoordinatorSelector {
    /// Create a new Coordinator selector from the given list of public keys
    fn from(public_keys: PublicKeys) -> Self {
        let coordinator_ids =
            Self::calculate_coordinator_ids(&public_keys, &ConsensusHash::empty());
        let coordinator_id = *coordinator_ids
            .first()
            .expect("FATAL: No registered signers");
        let coordinator_index = 0;
        let last_message_time = None;
        let tenure_start = Instant::now();
        Self {
            coordinator_ids,
            coordinator_id,
            coordinator_index,
            last_message_time,
            tenure_start,
            public_keys,
        }
    }
}

/// Whether or not to rotate to new coordinators in `update_coordinator`
const ROTATE_COORDINATORS: bool = false;

impl CoordinatorSelector {
    /// Update the coordinator id
    fn update_coordinator(&mut self, new_coordinator_ids: Vec<u32>) {
        self.last_message_time = None;
        self.coordinator_index = if new_coordinator_ids != self.coordinator_ids {
            // We have advanced our block height and should select from the new list
            let mut new_index: usize = 0;
            self.coordinator_ids = new_coordinator_ids;
            let new_coordinator_id = *self
                .coordinator_ids
                .first()
                .expect("FATAL: No registered signers");
            if ROTATE_COORDINATORS && new_coordinator_id == self.coordinator_id {
                // If the newly selected coordinator is the same as the current and we have more than one available, advance immediately to the next
                if self.coordinator_ids.len() > 1 {
                    new_index = new_index.saturating_add(1);
                }
            }
            new_index
        } else if ROTATE_COORDINATORS {
            self.coordinator_index.saturating_add(1) % self.coordinator_ids.len()
        } else {
            self.coordinator_index
        };
        self.coordinator_id = *self
            .coordinator_ids
            .get(self.coordinator_index)
            .expect("FATAL: Invalid number of registered signers");
        self.tenure_start = Instant::now();
        self.last_message_time = None;
    }

    /// Check the coordinator timeouts and update the selected coordinator accordingly
    /// Returns the resulting coordinator ID. (Note: it may be unchanged)
    pub fn refresh_coordinator(&mut self, pox_consensus_hash: &ConsensusHash) -> u32 {
        let new_coordinator_ids =
            Self::calculate_coordinator_ids(&self.public_keys, pox_consensus_hash);
        if let Some(time) = self.last_message_time {
            if time.elapsed().as_secs() > COORDINATOR_OPERATION_TIMEOUT_SECS {
                // We have not received a message in a while from this coordinator.
                // We should consider the operation finished and use a new coordinator id.
                self.update_coordinator(new_coordinator_ids);
            }
        } else if self.tenure_start.elapsed().as_secs() > COORDINATOR_TENURE_TIMEOUT_SECS
            || new_coordinator_ids != self.coordinator_ids
        {
            // Our tenure has been exceeded or we have advanced our block height and should select from the new list
            self.update_coordinator(new_coordinator_ids);
        }
        self.coordinator_id
    }

    /// Get the current coordinator id and public key
    pub fn get_coordinator(&self) -> (u32, ecdsa::PublicKey) {
        (
            self.coordinator_id,
            *self
                .public_keys
                .signers
                .get(&self.coordinator_id)
                .expect("FATAL: missing public key for selected coordinator id"),
        )
    }

    /// Calculate the ordered list of coordinator ids by comparing the provided public keys
    pub fn calculate_coordinator_ids(
        public_keys: &PublicKeys,
        pox_consensus_hash: &ConsensusHash,
    ) -> Vec<u32> {
        debug!("Using pox_consensus_hash {pox_consensus_hash:?} for selecting coordinator");
        // Create combined hash of each signer's public key with pox_consensus_hash
        let mut selection_ids = public_keys
            .signers
            .iter()
            .map(|(&id, pk)| {
                let pk_bytes = pk.to_bytes();
                let mut buffer =
                    Vec::with_capacity(pk_bytes.len() + pox_consensus_hash.as_bytes().len());
                buffer.extend_from_slice(&pk_bytes[..]);
                buffer.extend_from_slice(pox_consensus_hash.as_bytes());
                let digest = Sha256Sum::from_data(&buffer).as_bytes().to_vec();
                (id, digest)
            })
            .collect::<Vec<_>>();

        // Sort the selection IDs based on the hash
        selection_ids.sort_by_key(|(_, hash)| hash.clone());
        // Return only the ids
        selection_ids.iter().map(|(id, _)| *id).collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::tests::{generate_random_consensus_hash, generate_signer_config};
    use crate::config::GlobalConfig;

    #[test]
    fn calculate_coordinator_different_consensus_hashes_produces_unique_results() {
        let number_of_tests = 5;
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let public_keys = generate_signer_config(&config, 10, 4000)
            .signer_entries
            .public_keys;
        let mut results = Vec::new();

        for _ in 0..number_of_tests {
            let result = CoordinatorSelector::calculate_coordinator_ids(
                &public_keys,
                &generate_random_consensus_hash(),
            );
            results.push(result);
        }

        // Check that not all coordinator IDs are the same
        let all_ids_same = results.iter().all(|ids| ids == &results[0]);
        assert!(!all_ids_same, "Not all coordinator IDs should be the same");
    }

    fn generate_calculate_coordinator_test_results(
        random_consensus: bool,
        count: usize,
    ) -> Vec<Vec<u32>> {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let public_keys = generate_signer_config(&config, 10, 4000)
            .signer_entries
            .public_keys;
        let mut results = Vec::new();
        let same_hash = generate_random_consensus_hash();
        for _ in 0..count {
            let hash = if random_consensus {
                generate_random_consensus_hash()
            } else {
                same_hash
            };
            let result = CoordinatorSelector::calculate_coordinator_ids(&public_keys, &hash);
            results.push(result);
        }
        results
    }

    #[test]
    fn calculate_coordinator_results_should_vary_or_match_based_on_hash() {
        let results_with_random_hash = generate_calculate_coordinator_test_results(true, 5);
        let all_ids_same = results_with_random_hash
            .iter()
            .all(|ids| ids == &results_with_random_hash[0]);
        assert!(!all_ids_same, "Not all coordinator IDs should be the same");

        let results_with_static_hash = generate_calculate_coordinator_test_results(false, 5);
        let all_ids_same = results_with_static_hash
            .iter()
            .all(|ids| ids == &results_with_static_hash[0]);
        assert!(all_ids_same, "All coordinator IDs should be the same");
    }
}
