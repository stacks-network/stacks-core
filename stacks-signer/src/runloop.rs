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
use std::sync::mpsc::Sender;
use std::time::Duration;

use blockstack_lib::chainstate::stacks::boot::SIGNERS_NAME;
use blockstack_lib::util_lib::boot::boot_code_id;
use hashbrown::{HashMap, HashSet};
use libsigner::{SignerEvent, SignerRunLoop};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks_common::{debug, error, info, warn};
use wsts::curve::ecdsa;
use wsts::curve::point::{Compressed, Point};
use wsts::state_machine::{OperationResult, PublicKeys};

use crate::client::{retry_with_exponential_backoff, ClientError, StacksClient};
use crate::config::{GlobalConfig, RewardCycleConfig};
use crate::signer::{Command as SignerCommand, Signer, State as SignerState};

/// Which operation to perform
#[derive(PartialEq, Clone, Debug)]
pub struct RunLoopCommand {
    /// Which signer operation to perform
    pub command: SignerCommand,
    /// The reward cycle we are performing the operation for
    pub reward_cycle: u64,
}

/// The runloop state
#[derive(PartialEq, Debug)]
pub enum State {
    /// The runloop is uninitialized
    Uninitialized,
    /// The runloop is initialized
    Initialized,
}

/// The runloop for the stacks signer
pub struct RunLoop {
    /// Configuration info
    pub config: GlobalConfig,
    /// The stacks node client
    pub stacks_client: StacksClient,
    /// The internal signer for an odd or even reward cycle
    /// Keyed by reward cycle % 2
    pub stacks_signers: HashMap<u64, Signer>,
    /// The state of the runloop
    pub state: State,
}

impl From<GlobalConfig> for RunLoop {
    /// Creates new runloop from a config
    fn from(config: GlobalConfig) -> Self {
        let stacks_client = StacksClient::from(&config);
        RunLoop {
            config,
            stacks_client,
            stacks_signers: HashMap::with_capacity(2),
            state: State::Uninitialized,
        }
    }
}

impl RunLoop {
    /// Get a signer configruation for a specific reward cycle from the stacks node
    fn get_reward_cycle_config(
        &mut self,
        reward_cycle: u64,
    ) -> Result<Option<RewardCycleConfig>, ClientError> {
        let reward_set_calculated = self.stacks_client.reward_set_calculated(reward_cycle)?;
        if !reward_set_calculated {
            // Must weight for the reward set calculation to complete
            // Accounts for Pre nakamoto by simply using the second block of a prepare phase as the criteria
            return Err(ClientError::RewardSetNotYetCalculated(reward_cycle));
        }
        let current_addr = self.stacks_client.get_signer_address();

        let signer_set =
            u32::try_from(reward_cycle % 2).expect("FATAL: reward_cycle % 2 exceeds u32::MAX");
        let signer_stackerdb_contract_id =
            boot_code_id(SIGNERS_NAME, self.config.network.is_mainnet());
        // Get the signer writers from the stacker-db to find the signer slot id
        let Some(signer_slot_id) = self
            .stacks_client
            .get_stackerdb_signer_slots(&signer_stackerdb_contract_id, signer_set)?
            .iter()
            .position(|(address, _)| address == current_addr)
            .map(|pos| u32::try_from(pos).expect("FATAL: number of signers exceeds u32::MAX"))
        else {
            warn!(
                "Signer {current_addr} was not found in stacker db. Must not be registered for this reward cycle {reward_cycle}."
            );
            return Ok(None);
        };

        // We can only register for a reward cycle if a reward set exists. We know that it should exist due to our earlier check for reward_set_calculated
        let Some(reward_set_signers) = self.stacks_client.get_reward_set(reward_cycle)?.signers
        else {
            warn!(
                "No reward set found for reward cycle {reward_cycle}. Must not be a valid Nakamoto reward cycle."
            );
            return Ok(None);
        };

        let mut weight_end = 1;
        // signer uses a Vec<u32> for its key_ids, but coordinator uses a HashSet for each signer since it needs to do lots of lookups
        let mut coordinator_key_ids = HashMap::with_capacity(4000);
        let mut signer_key_ids = HashMap::with_capacity(reward_set_signers.len());
        let mut signer_address_ids = HashMap::with_capacity(reward_set_signers.len());
        let mut public_keys = PublicKeys {
            signers: HashMap::with_capacity(reward_set_signers.len()),
            key_ids: HashMap::with_capacity(4000),
        };
        let mut signer_public_keys = HashMap::with_capacity(reward_set_signers.len());
        for (i, entry) in reward_set_signers.iter().enumerate() {
            let signer_id = u32::try_from(i).expect("FATAL: number of signers exceeds u32::MAX");
            let ecdsa_public_key = ecdsa::PublicKey::try_from(entry.signing_key.as_slice()).map_err(|e| {
                ClientError::CorruptedRewardSet(format!(
                        "Reward cycle {reward_cycle} failed to convert signing key to ecdsa::PublicKey: {e}"
                    ))
                })?;
            let signer_public_key = Point::try_from(&Compressed::from(ecdsa_public_key.to_bytes()))
                .map_err(|e| {
                    ClientError::CorruptedRewardSet(format!(
                        "Reward cycle {reward_cycle} failed to convert signing key to Point: {e}"
                    ))
                })?;
            let stacks_public_key = StacksPublicKey::from_slice(entry.signing_key.as_slice()).map_err(|e| {
                    ClientError::CorruptedRewardSet(format!(
                        "Reward cycle {reward_cycle} failed to convert signing key to StacksPublicKey: {e}"
                    ))
                })?;

            let stacks_address =
                StacksAddress::p2pkh(self.config.network.is_mainnet(), &stacks_public_key);

            signer_address_ids.insert(stacks_address, signer_id);
            signer_public_keys.insert(signer_id, signer_public_key);
            let weight_start = weight_end;
            weight_end = weight_start + entry.slots;
            for key_id in weight_start..weight_end {
                public_keys.key_ids.insert(key_id, ecdsa_public_key);
                public_keys.signers.insert(signer_id, ecdsa_public_key);
                coordinator_key_ids
                    .entry(signer_id)
                    .or_insert(HashSet::with_capacity(entry.slots as usize))
                    .insert(key_id);
                signer_key_ids
                    .entry(signer_id)
                    .or_insert(Vec::with_capacity(entry.slots as usize))
                    .push(key_id);
            }
        }
        let Some(signer_id) = signer_address_ids.get(current_addr) else {
            warn!("Signer {current_addr} was found in stacker db but not the reward set for reward cycle {reward_cycle}.");
            return Ok(None);
        };
        debug!(
            "Signer #{signer_id} ({current_addr}) is registered for reward cycle {reward_cycle}."
        );
        let key_ids = signer_key_ids.get(signer_id).cloned().unwrap_or_default();
        Ok(Some(RewardCycleConfig {
            reward_cycle,
            signer_id: *signer_id,
            signer_slot_id,
            signer_address_ids,
            key_ids,
            coordinator_key_ids,
            signer_key_ids,
            public_keys,
            signer_public_keys,
        }))
    }

    /// Refresh signer configuration for a specific reward cycle
    fn refresh_signer_config(&mut self, reward_cycle: u64) -> Result<(), ClientError> {
        let reward_index = reward_cycle % 2;
        let mut needs_refresh = false;
        if let Some(stacks_signer) = self.stacks_signers.get_mut(&reward_index) {
            let old_reward_cycle = stacks_signer.reward_cycle;
            if old_reward_cycle == reward_cycle {
                //If the signer is already registered for the reward cycle, we don't need to do anything further here
                debug!("Signer is already configured for reward cycle {reward_cycle}. No need to update it's state machines.")
            } else {
                needs_refresh = true;
            }
        } else {
            needs_refresh = true;
        };
        if needs_refresh {
            let new_reward_cycle_config = self.get_reward_cycle_config(reward_cycle)?;
            if let Some(new_reward_cycle_config) = new_reward_cycle_config {
                let signer_id = new_reward_cycle_config.signer_id;
                debug!("Signer is registered for reward cycle {reward_cycle} as signer #{signer_id}. Initializing signer state.");
                self.stacks_signers.insert(
                    reward_index,
                    Signer::from_configs(&self.config, new_reward_cycle_config),
                );
                debug!("Signer #{signer_id} for reward cycle {reward_cycle} initialized. Initialized {} signers", self.stacks_signers.len());
            } else {
                // Nothing to initialize. Signer is not registered for this reward cycle
                debug!("Signer is not registered for reward cycle {reward_cycle}. Nothing to initialize.");
            }
        }
        Ok(())
    }

    /// Refresh the signer configuration by retrieving the necessary information from the stacks node
    /// Note: this will trigger DKG if required
    fn refresh_signers_with_retry(&mut self) -> Result<(), ClientError> {
        retry_with_exponential_backoff(|| {
            let current_reward_cycle = self
                .stacks_client
                .get_current_reward_cycle()
                .map_err(backoff::Error::transient)?;
            let next_reward_cycle = current_reward_cycle.saturating_add(1);
            if let Err(e) = self.refresh_signer_config(current_reward_cycle) {
                match e {
                    ClientError::NotRegistered => {
                        debug!("Signer is NOT registered for the current reward cycle {current_reward_cycle}.");
                    }
                    ClientError::RewardSetNotYetCalculated(_) => {
                        debug!("Current reward cycle {current_reward_cycle} reward set is not yet calculated. Let's retry...");
                        return Err(backoff::Error::transient(e));
                    }
                    _ => return Err(backoff::Error::transient(e)),
                }
            }
            if let Err(e) = self.refresh_signer_config(next_reward_cycle) {
                match e {
                    ClientError::NotRegistered => {
                        debug!("Signer is NOT registered for the next reward cycle {next_reward_cycle}.");
                    }
                    ClientError::RewardSetNotYetCalculated(_) => {
                        debug!("Next reward cycle {next_reward_cycle} reward set is not yet calculated.");
                    }
                    _ => return Err(backoff::Error::transient(e)),
                }
            }
            for stacks_signer in self.stacks_signers.values_mut() {
                stacks_signer
                    .update_dkg(&self.stacks_client)
                    .map_err(backoff::Error::transient)?;
            }
            if self.stacks_signers.is_empty() {
                info!("Signer is not registered for the current {current_reward_cycle} or next {next_reward_cycle} reward cycles. Waiting for confirmed registration...");
                return Err(backoff::Error::transient(ClientError::NotRegistered));
            } else {
                info!("Runloop successfully initialized!");
            }
            self.state = State::Initialized;
            Ok(())
        })
    }

    /// Cleanup stale signers that have exceeded their tenure
    fn cleanup_stale_signers(&mut self) {
        let mut to_delete = Vec::with_capacity(self.stacks_signers.len());
        for (index, stacks_signer) in self.stacks_signers.iter() {
            if stacks_signer.state == SignerState::TenureExceeded {
                debug!(
                    "Deleting signer for stale reward cycle: {}.",
                    stacks_signer.reward_cycle
                );
                to_delete.push(*index);
            }
        }
        for index in to_delete {
            self.stacks_signers.remove(&index);
        }
    }
}

impl SignerRunLoop<Vec<OperationResult>, RunLoopCommand> for RunLoop {
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.config.event_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.config.event_timeout
    }

    fn run_one_pass(
        &mut self,
        event: Option<SignerEvent>,
        cmd: Option<RunLoopCommand>,
        res: Sender<Vec<OperationResult>>,
    ) -> Option<Vec<OperationResult>> {
        info!(
            "Running one pass for the signer. Current state: {:?}",
            self.state
        );
        if let Err(e) = self.refresh_signers_with_retry() {
            if self.state == State::Uninitialized {
                // If we were never actually initialized, we cannot process anything. Just return.
                error!("Failed to initialize signers. Are you sure this signer is correctly registered for the current or next reward cycle?");
                warn!("Ignoring event: {event:?}");
                return None;
            } else {
                error!("Failed to refresh signers: {e}. Signer may have an outdated view of the network. Attempting to process event anyway.");
            }
        }
        if let Some(command) = cmd {
            let reward_cycle = command.reward_cycle;
            if let Some(stacks_signer) = self.stacks_signers.get_mut(&(reward_cycle % 2)) {
                if stacks_signer.reward_cycle != reward_cycle {
                    warn!(
                        "Signer is not registered for reward cycle {reward_cycle}. Ignoring command: {command:?}"
                    );
                } else {
                    stacks_signer.commands.push_back(command.command);
                }
            } else {
                warn!(
                    "Signer is not registered for reward cycle {reward_cycle}. Ignoring command: {command:?}"
                );
            }
        }
        for stacks_signer in self.stacks_signers.values_mut() {
            if let Err(e) =
                stacks_signer.process_event(&self.stacks_client, event.as_ref(), res.clone())
            {
                error!(
                    "Signer #{} for reward cycle {} errored processing event: {e}",
                    stacks_signer.signer_id, stacks_signer.reward_cycle
                );
            }
            // After processing event, run the next command for each signer
            stacks_signer.process_next_command(&self.stacks_client);
        }
        // Cleanup any stale signers
        self.cleanup_stale_signers();
        None
    }
}
