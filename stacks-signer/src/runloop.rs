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
use blockstack_lib::chainstate::stacks::boot::{NakamotoSignerEntry, SIGNERS_NAME};
use blockstack_lib::util_lib::boot::boot_code_id;
use libsigner::{SignerEvent, SignerRunLoop};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::types::chainstate::{ConsensusHash, StacksAddress, StacksPublicKey};
use stacks_common::types::{StacksHashMap as HashMap, StacksHashSet as HashSet};
use stacks_common::{debug, error, info, warn};
use wsts::curve::ecdsa;
use wsts::curve::point::{Compressed, Point};
use wsts::state_machine::coordinator::State as CoordinatorState;
use wsts::state_machine::{OperationResult, PublicKeys};

use crate::client::{retry_with_exponential_backoff, ClientError, StacksClient};
use crate::config::{GlobalConfig, ParsedSignerEntries, SignerConfig};
use crate::signer::{Command as SignerCommand, Signer, SignerSlotID, State as SignerState};

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
    /// Parse Nakamoto signer entries into relevant signer information
    pub fn parse_nakamoto_signer_entries(
        signers: &[NakamotoSignerEntry],
        is_mainnet: bool,
    ) -> ParsedSignerEntries {
        let mut weight_end = 1;
        let mut coordinator_key_ids = HashMap::with_capacity(4000);
        let mut signer_key_ids = HashMap::with_capacity(signers.len());
        let mut signer_ids = HashMap::with_capacity(signers.len());
        let mut public_keys = PublicKeys {
            signers: hashbrown::HashMap::with_capacity(signers.len()),
            key_ids: hashbrown::HashMap::with_capacity(4000),
        };
        let mut signer_public_keys = HashMap::with_capacity(signers.len());
        for (i, entry) in signers.iter().enumerate() {
            // TODO: track these signer ids as non participating if any of the conversions fail
            let signer_id = u32::try_from(i).expect("FATAL: number of signers exceeds u32::MAX");
            let ecdsa_public_key = ecdsa::PublicKey::try_from(entry.signing_key.as_slice())
                .expect("FATAL: corrupted signing key");
            let signer_public_key = Point::try_from(&Compressed::from(ecdsa_public_key.to_bytes()))
                .expect("FATAL: corrupted signing key");
            let stacks_public_key = StacksPublicKey::from_slice(entry.signing_key.as_slice())
                .expect("FATAL: Corrupted signing key");

            let stacks_address = StacksAddress::p2pkh(is_mainnet, &stacks_public_key);
            signer_ids.insert(stacks_address, signer_id);
            signer_public_keys.insert(signer_id, signer_public_key);
            let weight_start = weight_end;
            weight_end = weight_start + entry.weight;
            for key_id in weight_start..weight_end {
                public_keys.key_ids.insert(key_id, ecdsa_public_key);
                public_keys.signers.insert(signer_id, ecdsa_public_key);
                coordinator_key_ids
                    .entry(signer_id)
                    .or_insert(HashSet::with_capacity(entry.weight as usize))
                    .insert(key_id);
                signer_key_ids
                    .entry(signer_id)
                    .or_insert(Vec::with_capacity(entry.weight as usize))
                    .push(key_id);
            }
        }
        ParsedSignerEntries {
            signer_ids,
            public_keys,
            signer_key_ids,
            signer_public_keys,
            coordinator_key_ids,
        }
    }

    /// Get the registered signers for a specific reward cycle
    /// Returns None if no signers are registered or its not Nakamoto cycle
    pub fn get_parsed_reward_set(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<ParsedSignerEntries>, ClientError> {
        debug!("Getting registered signers for reward cycle {reward_cycle}...");
        let Some(signers) = self.stacks_client.get_reward_set_signers(reward_cycle)? else {
            warn!("No reward set signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        };
        if signers.is_empty() {
            warn!("No registered signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        }
        Ok(Some(Self::parse_nakamoto_signer_entries(
            &signers,
            self.config.network.is_mainnet(),
        )))
    }

    /// Get the stackerdb signer slots for a specific reward cycle
    pub fn get_parsed_signer_slots(
        &self,
        stacks_client: &StacksClient,
        reward_cycle: u64,
    ) -> Result<HashMap<StacksAddress, SignerSlotID>, ClientError> {
        let signer_set =
            u32::try_from(reward_cycle % 2).expect("FATAL: reward_cycle % 2 exceeds u32::MAX");
        let signer_stackerdb_contract_id =
            boot_code_id(SIGNERS_NAME, self.config.network.is_mainnet());
        // Get the signer writers from the stacker-db to find the signer slot id
        let stackerdb_signer_slots =
            stacks_client.get_stackerdb_signer_slots(&signer_stackerdb_contract_id, signer_set)?;
        let mut signer_slot_ids = HashMap::with_capacity(stackerdb_signer_slots.len());
        for (index, (address, _)) in stackerdb_signer_slots.into_iter().enumerate() {
            signer_slot_ids.insert(
                address,
                SignerSlotID(
                    u32::try_from(index).expect("FATAL: number of signers exceeds u32::MAX"),
                ),
            );
        }
        Ok(signer_slot_ids)
    }
    /// Get a signer configuration for a specific reward cycle from the stacks node
    fn get_signer_config(&mut self, reward_cycle: u64) -> Option<SignerConfig> {
        // We can only register for a reward cycle if a reward set exists.
        let signer_entries = self.get_parsed_reward_set(reward_cycle).ok()??;
        let signer_slot_ids = self
            .get_parsed_signer_slots(&self.stacks_client, reward_cycle)
            .ok()?;
        let current_addr = self.stacks_client.get_signer_address();

        let Some(signer_slot_id) = signer_slot_ids.get(current_addr) else {
            warn!(
                    "Signer {current_addr} was not found in stacker db. Must not be registered for this reward cycle {reward_cycle}."
                );
            return None;
        };
        let Some(signer_id) = signer_entries.signer_ids.get(current_addr) else {
            warn!(
                "Signer {current_addr} was found in stacker db but not the reward set for reward cycle {reward_cycle}."
            );
            return None;
        };
        info!(
            "Signer #{signer_id} ({current_addr}) is registered for reward cycle {reward_cycle}."
        );
        let key_ids = signer_entries
            .signer_key_ids
            .get(signer_id)
            .cloned()
            .unwrap_or_default();
        Some(SignerConfig {
            reward_cycle,
            signer_id: *signer_id,
            signer_slot_id: *signer_slot_id,
            key_ids,
            signer_entries,
            signer_slot_ids: signer_slot_ids.into_values().collect(),
            ecdsa_private_key: self.config.ecdsa_private_key,
            stacks_private_key: self.config.stacks_private_key,
            node_host: self.config.node_host.to_string(),
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
                        signer.next_signer_addresses = new_signer_config
                            .signer_entries
                            .signer_ids
                            .keys()
                            .copied()
                            .collect();
                        signer.next_signer_slot_ids = new_signer_config.signer_slot_ids.clone();
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
                        .update_dkg(&self.stacks_client)
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
#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};

    use super::RunLoop;

    #[test]
    fn parse_nakamoto_signer_entries_test() {
        let nmb_signers = 10;
        let weight = 10;
        let mut signer_entries = Vec::with_capacity(nmb_signers);
        for _ in 0..nmb_signers {
            let key = StacksPublicKey::from_private(&StacksPrivateKey::new()).to_bytes_compressed();
            let mut signing_key = [0u8; 33];
            signing_key.copy_from_slice(&key);
            signer_entries.push(NakamotoSignerEntry {
                signing_key,
                stacked_amt: 0,
                weight,
            });
        }

        let parsed_entries = RunLoop::parse_nakamoto_signer_entries(&signer_entries, false);
        assert_eq!(parsed_entries.signer_ids.len(), nmb_signers);
        let mut signer_ids = parsed_entries.signer_ids.into_values().collect::<Vec<_>>();
        signer_ids.sort();
        assert_eq!(
            signer_ids,
            (0..nmb_signers).map(|id| id as u32).collect::<Vec<_>>()
        );
    }
}
