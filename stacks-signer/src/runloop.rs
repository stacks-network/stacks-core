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

use blockstack_lib::burnchains::PoxConstants;
use blockstack_lib::chainstate::stacks::boot::SIGNERS_NAME;
use blockstack_lib::util_lib::boot::boot_code_id;
use hashbrown::HashMap;
use libsigner::{SignerEntries, SignerEvent, SignerRunLoop};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::{debug, error, info, warn};
use wsts::state_machine::OperationResult;

use crate::client::{retry_with_exponential_backoff, ClientError, StacksClient};
use crate::config::{GlobalConfig, SignerConfig};
use crate::signer::{Command as SignerCommand, Signer, SignerSlotID};

/// Which operation to perform
#[derive(PartialEq, Clone, Debug)]
pub struct RunLoopCommand {
    /// Which signer operation to perform
    pub command: SignerCommand,
    /// The reward cycle we are performing the operation for
    pub reward_cycle: u64,
}

/// The runloop state
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum State {
    /// The runloop is uninitialized
    Uninitialized,
    /// The runloop has no registered signers
    NoRegisteredSigners,
    /// The runloop has registered signers
    RegisteredSigners,
}

/// The current reward cycle info
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct RewardCycleInfo {
    /// The current reward cycle
    pub reward_cycle: u64,
    /// The reward phase cycle length
    pub reward_phase_block_length: u64,
    /// The prepare phase length
    pub prepare_phase_block_length: u64,
    /// The first burn block height
    pub first_burnchain_block_height: u64,
    /// The burnchain block height of the last query
    pub last_burnchain_block_height: u64,
}

impl RewardCycleInfo {
    /// Check if the provided burnchain block height is part of the reward cycle
    pub const fn is_in_reward_cycle(&self, burnchain_block_height: u64) -> bool {
        let blocks_mined = burnchain_block_height.saturating_sub(self.first_burnchain_block_height);
        let reward_cycle_length = self
            .reward_phase_block_length
            .saturating_add(self.prepare_phase_block_length);
        let reward_cycle = blocks_mined / reward_cycle_length;
        self.reward_cycle == reward_cycle
    }

    /// Check if the provided burnchain block height is in the prepare phase
    pub fn is_in_prepare_phase(&self, burnchain_block_height: u64) -> bool {
        PoxConstants::static_is_in_prepare_phase(
            self.first_burnchain_block_height,
            self.reward_phase_block_length,
            self.prepare_phase_block_length,
            burnchain_block_height,
        )
    }
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
    /// The current reward cycle info. Only None if the runloop is uninitialized
    pub current_reward_cycle_info: Option<RewardCycleInfo>,
}

impl From<GlobalConfig> for RunLoop {
    /// Creates new runloop from a config
    fn from(config: GlobalConfig) -> Self {
        let stacks_client = StacksClient::from(&config);
        Self {
            config,
            stacks_client,
            stacks_signers: HashMap::with_capacity(2),
            state: State::Uninitialized,
            commands: VecDeque::new(),
            current_reward_cycle_info: None,
        }
    }
}

impl RunLoop {
    /// Get the registered signers for a specific reward cycle
    /// Returns None if no signers are registered or its not Nakamoto cycle
    pub fn get_parsed_reward_set(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<SignerEntries>, ClientError> {
        debug!("Getting registered signers for reward cycle {reward_cycle}...");
        let Some(signers) = self
            .stacks_client
            .get_reward_set_signers_with_retry(reward_cycle)?
        else {
            warn!("No reward set signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        };
        if signers.is_empty() {
            warn!("No registered signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        }
        let entries = SignerEntries::parse(self.config.network.is_mainnet(), &signers).unwrap();
        Ok(Some(entries))
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
            db_path: self.config.db_path.clone(),
        })
    }

    /// Refresh signer configuration for a specific reward cycle
    fn refresh_signer_config(&mut self, reward_cycle: u64) {
        let reward_index = reward_cycle % 2;
        if let Some(new_signer_config) = self.get_signer_config(reward_cycle) {
            let signer_id = new_signer_config.signer_id;
            debug!("Signer is registered for reward cycle {reward_cycle} as signer #{signer_id}. Initializing signer state.");
            if reward_cycle != 0 {
                let prior_reward_cycle = reward_cycle.saturating_sub(1);
                let prior_reward_set = prior_reward_cycle % 2;
                if let Some(signer) = self.stacks_signers.get_mut(&prior_reward_set) {
                    if signer.reward_cycle == prior_reward_cycle {
                        // The signers have been calculated for the next reward cycle. Update the current one
                        debug!("{signer}: Next reward cycle ({reward_cycle}) signer set calculated. Reconfiguring current reward cycle signer.");
                        signer.next_signer_addresses = new_signer_config
                            .signer_entries
                            .signer_ids
                            .keys()
                            .copied()
                            .collect();
                        signer.next_signer_slot_ids = new_signer_config.signer_slot_ids.clone();
                    }
                }
            }
            let new_signer = Signer::from(new_signer_config);
            info!("{new_signer} initialized.");
            self.stacks_signers.insert(reward_index, new_signer);
        } else {
            warn!("Signer is not registered for reward cycle {reward_cycle}. Waiting for confirmed registration...");
        }
    }

    fn initialize_runloop(&mut self) -> Result<(), ClientError> {
        debug!("Initializing signer runloop...");
        let reward_cycle_info = retry_with_exponential_backoff(|| {
            self.stacks_client
                .get_current_reward_cycle_info()
                .map_err(backoff::Error::transient)
        })?;
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        self.refresh_signer_config(current_reward_cycle);
        // We should only attempt to initialize the next reward cycle signer if we are in the prepare phase of the next reward cycle
        if reward_cycle_info.is_in_prepare_phase(reward_cycle_info.last_burnchain_block_height) {
            self.refresh_signer_config(current_reward_cycle.saturating_add(1));
        }
        self.current_reward_cycle_info = Some(reward_cycle_info);
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    fn refresh_runloop(&mut self, current_burn_block_height: u64) -> Result<(), ClientError> {
        let reward_cycle_info = self
            .current_reward_cycle_info
            .as_mut()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.");
        // First ensure we refresh our view of the current reward cycle information
        if !reward_cycle_info.is_in_reward_cycle(current_burn_block_height) {
            let new_reward_cycle_info = retry_with_exponential_backoff(|| {
                self.stacks_client
                    .get_current_reward_cycle_info()
                    .map_err(backoff::Error::transient)
            })?;
            *reward_cycle_info = new_reward_cycle_info;
        }
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        // We should only attempt to refresh the signer if we are not configured for the next reward cycle yet and we received a new burn block for its prepare phase
        if reward_cycle_info.is_in_prepare_phase(current_burn_block_height) {
            let next_reward_cycle = current_reward_cycle.saturating_add(1);
            if self
                .stacks_signers
                .get(&(next_reward_cycle % 2))
                .map(|signer| signer.reward_cycle != next_reward_cycle)
                .unwrap_or(true)
            {
                info!("Received a new burnchain block height ({current_burn_block_height}) in the prepare phase of the next reward cycle ({next_reward_cycle}). Checking for signer registration...");
                self.refresh_signer_config(next_reward_cycle);
            }
        }
        self.cleanup_stale_signers(current_reward_cycle);
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    fn cleanup_stale_signers(&mut self, current_reward_cycle: u64) {
        let mut to_delete = Vec::new();
        for (idx, signer) in &mut self.stacks_signers {
            if signer.reward_cycle < current_reward_cycle {
                debug!("{signer}: Signer's tenure has completed.");
                to_delete.push(*idx);
                continue;
            }
        }
        for idx in to_delete {
            self.stacks_signers.remove(&idx);
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
        debug!(
            "Running one pass for the signer. state={:?}, cmd={cmd:?}, event={event:?}",
            self.state
        );
        if let Some(cmd) = cmd {
            self.commands.push_back(cmd);
        }
        if self.state == State::Uninitialized {
            if let Err(e) = self.initialize_runloop() {
                error!("Failed to initialize signer runloop: {e}.");
                if let Some(event) = event {
                    warn!("Ignoring event: {event:?}");
                }
                return None;
            }
        } else if let Some(SignerEvent::NewBurnBlock(current_burn_block_height)) = event {
            if let Err(e) = self.refresh_runloop(current_burn_block_height) {
                error!("Failed to refresh signer runloop: {e}.");
                warn!("Signer may have an outdated view of the network.");
            }
        }
        let current_reward_cycle = self
            .current_reward_cycle_info
            .as_ref()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.")
            .reward_cycle;
        if self.state == State::NoRegisteredSigners {
            let next_reward_cycle = current_reward_cycle.saturating_add(1);
            if let Some(event) = event {
                info!("Signer is not registered for the current reward cycle ({current_reward_cycle}) or next reward cycle ({next_reward_cycle}). Waiting for confirmed registration...");
                warn!("Ignoring event: {event:?}");
            }
            return None;
        }
        for signer in self.stacks_signers.values_mut() {
            let event_parity = match event {
                Some(SignerEvent::BlockValidationResponse(_)) => Some(current_reward_cycle % 2),
                // Block proposal events do have reward cycles, but each proposal has its own cycle,
                //  and the vec could be heterogenous, so, don't differentiate.
                Some(SignerEvent::MinerMessages(..))
                | Some(SignerEvent::NewBurnBlock(_))
                | Some(SignerEvent::StatusCheck)
                | None => None,
                Some(SignerEvent::SignerMessages(msg_parity, ..)) => {
                    Some(u64::from(msg_parity) % 2)
                }
            };
            let other_signer_parity = (signer.reward_cycle + 1) % 2;
            if event_parity == Some(other_signer_parity) {
                continue;
            }

            if signer.approved_aggregate_public_key.is_none() {
                if let Err(e) = retry_with_exponential_backoff(|| {
                    signer
                        .update_dkg(&self.stacks_client, current_reward_cycle)
                        .map_err(backoff::Error::transient)
                }) {
                    error!("{signer}: failed to update DKG: {e}");
                }
            }
            signer.refresh_coordinator();
            if let Err(e) = signer.process_event(
                &self.stacks_client,
                event.as_ref(),
                res.clone(),
                current_reward_cycle,
            ) {
                error!("{signer}: errored processing event: {e}");
            }
            if let Some(command) = self.commands.pop_front() {
                let reward_cycle = command.reward_cycle;
                if signer.reward_cycle != reward_cycle {
                    warn!(
                        "{signer}: not registered for reward cycle {reward_cycle}. Ignoring command: {command:?}"
                    );
                } else {
                    info!(
                        "{signer}: Queuing an external runloop command ({:?}): {command:?}",
                        signer
                            .state_machine
                            .public_keys
                            .signers
                            .get(&signer.signer_id)
                    );
                    signer.commands.push_back(command.command);
                }
            }
            // After processing event, run the next command for each signer
            signer.process_next_command(&self.stacks_client, current_reward_cycle);
        }
        None
    }
}
#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;
    use libsigner::SignerEntries;
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};

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

        let parsed_entries = SignerEntries::parse(false, &signer_entries).unwrap();
        assert_eq!(parsed_entries.signer_ids.len(), nmb_signers);
        let mut signer_ids = parsed_entries.signer_ids.into_values().collect::<Vec<_>>();
        signer_ids.sort();
        assert_eq!(
            signer_ids,
            (0..nmb_signers).map(|id| id as u32).collect::<Vec<_>>()
        );
    }
}
