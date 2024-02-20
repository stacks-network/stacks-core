// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use libsigner::CoordinatorMetadata;
use wsts::curve::ecdsa;
use wsts::state_machine::PublicKeys;

use crate::client::StacksClient;

/// TODO: test this value and adjust as necessary. Maybe make configurable?
pub const COORDINATOR_OPERATION_TIMEOUT_SECS: u64 = 300;

/// TODO: test this value and adjust as necessary. Maybe make configurable?
pub const COORDINATOR_TENURE_TIMEOUT_SECS: u64 = 600;

/// The coordinator selector
#[derive(Clone, Debug)]
pub struct Selector {
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
    /// The signer's view of coordinator metadata including PoX consensus hash and block height
    pub coordinator_metadata: CoordinatorMetadata,
}

impl Selector {
    /// Create a new Coordinator selector from the given list of public keys and initial coordinator ids
    pub fn new(coordinator_ids: Vec<u32>, public_keys: PublicKeys) -> Self {
        let coordinator_id = *coordinator_ids
            .first()
            .expect("FATAL: No registered signers");
        let coordinator_index = 0;
        let last_message_time = None;
        let tenure_start = Instant::now();
        let coordinator_metadata = CoordinatorMetadata::default();
        Self {
            coordinator_ids,
            coordinator_id,
            coordinator_index,
            last_message_time,
            tenure_start,
            public_keys,
            coordinator_metadata,
        }
    }

    /// Update the coordinator id
    fn update_coordinator(
        &mut self,
        new_coordinator_ids: Vec<u32>,
        new_coordinator_metadata: CoordinatorMetadata,
    ) {
        self.last_message_time = None;
        self.coordinator_index = if new_coordinator_ids != self.coordinator_ids {
            // We have advanced our block height and should select from the new list
            let mut new_index: usize = 0;
            self.coordinator_ids = new_coordinator_ids;
            let new_coordinator_id = *self
                .coordinator_ids
                .first()
                .expect("FATAL: No registered signers");
            if new_coordinator_id == self.coordinator_id {
                // If the newly selected coordinator is the same as the current and we have more than one available, advance immediately to the next
                if self.coordinator_ids.len() > 1 {
                    new_index = new_index.saturating_add(1);
                }
            }
            new_index
        } else {
            let mut new_index = self.coordinator_index.saturating_add(1);
            if new_index == self.coordinator_ids.len() {
                // We have exhausted all potential coordinators. Go back to the start
                new_index = 0;
            }
            new_index
        };
        self.coordinator_id = *self
            .coordinator_ids
            .get(self.coordinator_index)
            .expect("FATAL: Invalid number of registered signers");
        self.tenure_start = Instant::now();
        self.last_message_time = None;
        self.coordinator_metadata = new_coordinator_metadata;
    }

    /// Check the coordinator timeouts and update the selected coordinator accordingly
    /// Returns true if the coordinator was updated, else false
    pub fn refresh_coordinator(&mut self, stacks_client: &StacksClient) -> bool {
        let old_coordinator_id = self.coordinator_id;
        let (new_coordinator_ids, new_coordinator_metadata) =
            stacks_client.calculate_coordinator_ids(&self.public_keys);
        if let Some(time) = self.last_message_time {
            if time.elapsed().as_secs() > COORDINATOR_OPERATION_TIMEOUT_SECS {
                // We have not received a message in a while from this coordinator.
                // We should consider the operation finished and use a new coordinator id.
                self.update_coordinator(new_coordinator_ids, new_coordinator_metadata);
            }
        } else if self.tenure_start.elapsed().as_secs() > COORDINATOR_TENURE_TIMEOUT_SECS
            || new_coordinator_ids != self.coordinator_ids
        {
            // Our tenure has been exceeded or we have advanced our block height and should select from the new list
            self.update_coordinator(new_coordinator_ids, new_coordinator_metadata);
        }
        old_coordinator_id != self.coordinator_id
    }

    /// Get the current coordinator id and public key
    pub fn get_coordinator(&self) -> (u32, ecdsa::PublicKey) {
        (
            self.coordinator_id,
            self.public_keys
                .signers
                .get(&self.coordinator_id)
                .expect("FATAL: missing public key for selected coordinator id")
                .clone(),
        )
    }
}
