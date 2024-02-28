use std::collections::VecDeque;
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

use blockstack_lib::chainstate::burn::ConsensusHashExtensions;
use hashbrown::HashMap;
use libsigner::{SignerEvent, SignerRunLoop};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::{debug, error, info, warn};
use wsts::state_machine::coordinator::State as CoordinatorState;
use wsts::state_machine::OperationResult;

use crate::client::{retry_with_exponential_backoff, ClientError, StacksClient};
use crate::config::{GlobalConfig, SignerConfig};
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
    /// The commands received thus far
    pub commands: VecDeque<RunLoopCommand>,
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
            commands: VecDeque::new(),
        }
    }
}

impl RunLoop {
    /// Get a signer configuration for a specific reward cycle from the stacks node
    fn get_signer_config(&mut self, reward_cycle: u64) -> Option<SignerConfig> {
        // We can only register for a reward cycle if a reward set exists.
        let registered_signers = self
            .stacks_client
            .get_registered_signers_info(reward_cycle).map_err(|e| {
                error!(
                    "Failed to retrieve registered signers info for reward cycle {reward_cycle}: {e}"
                );
                e
            }).ok()??;

        let current_addr = self.stacks_client.get_signer_address();

        let Some(signer_slot_id) = registered_signers.signer_slot_ids.get(current_addr) else {
            warn!(
                    "Signer {current_addr} was not found in stacker db. Must not be registered for this reward cycle {reward_cycle}."
                );
            return None;
        };
        let Some(signer_id) = registered_signers.signer_ids.get(current_addr) else {
            warn!(
                "Signer {current_addr} was found in stacker db but not the reward set for reward cycle {reward_cycle}."
            );
            return None;
        };
        info!(
            "Signer #{signer_id} ({current_addr}) is registered for reward cycle {reward_cycle}."
        );
        let key_ids = registered_signers
            .signer_key_ids
            .get(signer_id)
            .cloned()
            .unwrap_or_default();
        Some(SignerConfig {
            reward_cycle,
            signer_id: *signer_id,
            signer_slot_id: *signer_slot_id,
            key_ids,
            registered_signers,
            ecdsa_private_key: self.config.ecdsa_private_key,
            stacks_private_key: self.config.stacks_private_key,
            node_host: self.config.node_host,
            mainnet: self.config.network.is_mainnet(),
            dkg_end_timeout: self.config.dkg_end_timeout,
            dkg_private_timeout: self.config.dkg_private_timeout,
            dkg_public_timeout: self.config.dkg_public_timeout,
            nonce_timeout: self.config.nonce_timeout,
            sign_timeout: self.config.sign_timeout,
            tx_fee_ustx: self.config.tx_fee_ustx,
        })
    }

    /// Refresh signer configuration for a specific reward cycle
    fn refresh_signer_config(&mut self, reward_cycle: u64) {
        let reward_index = reward_cycle % 2;
        let mut needs_refresh = false;
        if let Some(signer) = self.stacks_signers.get_mut(&reward_index) {
            let old_reward_cycle = signer.reward_cycle;
            if old_reward_cycle == reward_cycle {
                //If the signer is already registered for the reward cycle, we don't need to do anything further here
                debug!("Signer is configured for reward cycle {reward_cycle}.")
            } else {
                needs_refresh = true;
            }
        } else {
            needs_refresh = true;
        };
        if needs_refresh {
            if let Some(new_signer_config) = self.get_signer_config(reward_cycle) {
                let signer_id = new_signer_config.signer_id;
                debug!("Signer is registered for reward cycle {reward_cycle} as signer #{signer_id}. Initializing signer state.");
                let prior_reward_cycle = reward_cycle.saturating_sub(1);
                let prior_reward_set = prior_reward_cycle % 2;
                if let Some(signer) = self.stacks_signers.get_mut(&prior_reward_set) {
                    if signer.reward_cycle == prior_reward_cycle {
                        // The signers have been calculated for the next reward cycle. Update the current one
                        debug!("Signer #{}: Next reward cycle ({reward_cycle}) signer set calculated. Updating current reward cycle ({prior_reward_cycle}) signer.", signer.signer_id);
                        signer.next_signer_ids = new_signer_config
                            .registered_signers
                            .signer_ids
                            .values()
                            .copied()
                            .collect();
                        signer.next_signer_slot_ids =
                            new_signer_config.registered_signers.signer_slot_ids.clone();
                    }
                }
                self.stacks_signers
                    .insert(reward_index, Signer::from(new_signer_config));
                debug!("Signer #{signer_id} for reward cycle {reward_cycle} initialized. Initialized {} signers", self.stacks_signers.len());
            } else {
                warn!("Signer is not registered for reward cycle {reward_cycle}. Waiting for confirmed registration...");
            }
        }
    }

    /// Refresh the signer configuration by retrieving the necessary information from the stacks node
    /// Note: this will trigger DKG if required
    fn refresh_signers(&mut self, current_reward_cycle: u64) -> Result<(), ClientError> {
        let next_reward_cycle = current_reward_cycle.saturating_add(1);
        self.refresh_signer_config(current_reward_cycle);
        self.refresh_signer_config(next_reward_cycle);
        // TODO: do not use an empty consensus hash
        let pox_consensus_hash = ConsensusHash::empty();
        for signer in self.stacks_signers.values_mut() {
            let old_coordinator_id = signer.coordinator_selector.get_coordinator().0;
            let updated_coordinator_id = signer
                .coordinator_selector
                .refresh_coordinator(&pox_consensus_hash);
            if old_coordinator_id != updated_coordinator_id {
                debug!(
                    "Signer #{}: Coordinator updated. Resetting state to Idle.", signer.signer_id;
                    "old_coordinator_id" => {old_coordinator_id},
                    "updated_coordinator_id" => {updated_coordinator_id},
                    "pox_consensus_hash" => %pox_consensus_hash
                );
                signer.coordinator.state = CoordinatorState::Idle;
                signer.state = SignerState::Idle;
            }
            if signer.approved_aggregate_public_key.is_none() {
                retry_with_exponential_backoff(|| {
                    signer
                        .update_dkg(&self.stacks_client, current_reward_cycle)
                        .map_err(backoff::Error::transient)
                })?;
            }
        }
        if self.stacks_signers.is_empty() {
            info!("Signer is not registered for the current {current_reward_cycle} or next {next_reward_cycle} reward cycles. Waiting for confirmed registration...");
            self.state = State::Uninitialized;
            return Err(ClientError::NotRegistered);
        }
        self.state = State::Initialized;
        info!("Runloop successfully initialized!");
        Ok(())
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
        debug!(
            "Running one pass for the signer. state={:?}, cmd={cmd:?}, event={event:?}",
            self.state
        );
        if let Some(cmd) = cmd {
            self.commands.push_back(cmd);
        }
        // TODO: queue events and process them potentially after initialization success (similar to commands)?
        let Ok(current_reward_cycle) = retry_with_exponential_backoff(|| {
            self.stacks_client
                .get_current_reward_cycle()
                .map_err(backoff::Error::transient)
        }) else {
            error!("Failed to retrieve current reward cycle");
            warn!("Ignoring event: {event:?}");
            return None;
        };
        if let Err(e) = self.refresh_signers(current_reward_cycle) {
            if self.state == State::Uninitialized {
                // If we were never actually initialized, we cannot process anything. Just return.
                warn!("Failed to initialize signers. Are you sure this signer is correctly registered for the current or next reward cycle?");
                warn!("Ignoring event: {event:?}");
                return None;
            }
            error!("Failed to refresh signers: {e}. Signer may have an outdated view of the network. Attempting to process event anyway.");
        }
        for signer in self.stacks_signers.values_mut() {
            if let Err(e) = signer.process_event(
                &self.stacks_client,
                event.as_ref(),
                res.clone(),
                current_reward_cycle,
            ) {
                error!(
                    "Signer #{} for reward cycle {} errored processing event: {e}",
                    signer.signer_id, signer.reward_cycle
                );
            }
            if let Some(command) = self.commands.pop_front() {
                let reward_cycle = command.reward_cycle;
                if signer.reward_cycle != reward_cycle {
                    warn!(
                        "Signer #{}: not registered for reward cycle {reward_cycle}. Ignoring command: {command:?}", signer.signer_id
                    );
                } else {
                    info!(
                        "Signer #{}: Queuing an external runloop command ({:?}): {command:?}",
                        signer.signer_id,
                        signer
                            .signing_round
                            .public_keys
                            .signers
                            .get(&signer.signer_id)
                    );
                    signer.commands.push_back(command.command);
                }
            }
            // After processing event, run the next command for each signer
            signer.process_next_command(&self.stacks_client);
        }
        None
    }
}
