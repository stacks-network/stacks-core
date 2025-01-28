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

use std::collections::HashMap;

use clarity::codec::read_next;
use clarity::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use clarity::types::StacksEpochId;
use clarity::util::sleep_ms;
use libsigner::v0::messages::{MessageSlotID, SignerMessage};
use libsigner::SignerSession;
use slog::{slog_info, slog_warn};
use stacks_common::{info, warn};

use crate::cli::MonitorSignersArgs;
use crate::client::{ClientError, SignerSlotID, StacksClient};
use crate::utils::stackerdb_session;

/// The `SignerMonitor` struct is used to monitor the signers stackerdb slots for expected new messages
pub struct SignerMonitor {
    /// The client being used to monitor stackerdb messages
    stacks_client: StacksClient,
    /// The current view of the reward cycle
    cycle_state: RewardCycleState,
    /// The arguments used to configure the monitor
    args: MonitorSignersArgs,
}

#[derive(Debug, Default, Clone)]
/// The `RewardCycleState` struct is used to store the current reward cycle view
pub struct RewardCycleState {
    signers_slots: HashMap<StacksAddress, SignerSlotID>,
    signers_keys: HashMap<StacksAddress, StacksPublicKey>,
    signers_addresses: HashMap<SignerSlotID, StacksAddress>,
    signers_weights: HashMap<StacksAddress, u32>,
    slot_ids: Vec<u32>,
    /// Reward cycle is not known until the first successful call to the node
    reward_cycle: Option<u64>,
}

impl SignerMonitor {
    /// Create a new `SignerMonitor` instance
    pub fn new(args: MonitorSignersArgs) -> Self {
        url::Url::parse(&format!("http://{}", args.host)).expect("Failed to parse node host");
        let stacks_client = StacksClient::try_from_host(
            StacksPrivateKey::random(), // We don't need a private key to read
            args.host.clone(),
            "FOO".to_string(), // We don't care about authorized paths. Just accessing public info
        )
        .expect("Failed to connect to provided host.");
        Self {
            stacks_client,
            cycle_state: RewardCycleState::default(),
            args,
        }
    }

    fn refresh_state(&mut self) -> Result<bool, ClientError> {
        let reward_cycle = self
            .stacks_client
            .get_current_reward_cycle_info()?
            .reward_cycle;
        if Some(reward_cycle) == self.cycle_state.reward_cycle {
            // The reward cycle has not changed. Nothing to refresh.
            return Ok(false);
        }
        self.cycle_state.reward_cycle = Some(reward_cycle);

        self.cycle_state.signers_keys.clear();
        self.cycle_state.signers_addresses.clear();

        self.cycle_state.signers_slots =
            self.stacks_client.get_parsed_signer_slots(reward_cycle)?;

        let entries = self
            .stacks_client
            .get_reward_set_signers(reward_cycle)?
            .unwrap_or_else(|| {
                panic!("No signers found for the current reward cycle {reward_cycle}")
            });
        for entry in entries {
            let public_key = StacksPublicKey::from_slice(entry.signing_key.as_slice())
                .expect("Failed to convert signing key to StacksPublicKey");
            let stacks_address = StacksAddress::p2pkh(self.stacks_client.mainnet, &public_key);
            self.cycle_state
                .signers_keys
                .insert(stacks_address, public_key);
            self.cycle_state
                .signers_weights
                .insert(stacks_address, entry.weight);
        }
        for (signer_address, slot_id) in self.cycle_state.signers_slots.iter() {
            self.cycle_state
                .signers_addresses
                .insert(*slot_id, *signer_address);
        }

        for (signer_address, slot_id) in self.cycle_state.signers_slots.iter() {
            self.cycle_state
                .signers_addresses
                .insert(*slot_id, *signer_address);
            self.cycle_state.slot_ids.push(slot_id.0);
        }
        Ok(true)
    }

    fn print_missing_signers(&self, missing_signers: &[StacksAddress]) {
        if missing_signers.is_empty() {
            return;
        }
        let formatted_signers = missing_signers
            .iter()
            .map(|addr| format!("{addr}"))
            .collect::<Vec<_>>()
            .join(", ");
        let formatted_keys = self
            .cycle_state
            .signers_keys
            .iter()
            .filter_map(|(addr, key)| {
                if missing_signers.contains(addr) {
                    Some(format!("0x{}", key.to_hex()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let missing_weight = missing_signers
            .iter()
            .map(|addr| self.cycle_state.signers_weights.get(addr).unwrap())
            .sum::<u32>();
        let total_weight = self.cycle_state.signers_weights.values().sum::<u32>();
        let percentage_missing = missing_weight as f64 / total_weight as f64 * 100.00;
        warn!(
            "Missing messages for {} of {} signer(s). Missing {percentage_missing:.2}% of signing weight  ({missing_weight}/{total_weight})", missing_signers.len(), self.cycle_state.signers_addresses.len();
            "signer_addresses" => formatted_signers,
            "signer_keys" => formatted_keys
        );
    }

    fn print_stale_signers(&self, stale_signers: &[StacksAddress]) {
        if stale_signers.is_empty() {
            return;
        }
        let formatted_signers = stale_signers
            .iter()
            .map(|addr| format!("{addr}"))
            .collect::<Vec<_>>()
            .join(", ");
        let formatted_keys = self
            .cycle_state
            .signers_keys
            .iter()
            .filter_map(|(addr, key)| {
                if stale_signers.contains(addr) {
                    Some(format!("0x{}", key.to_hex()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            "No new updates from {} of {} signer(s) in over {} seconds",
            stale_signers.len(),
            self.cycle_state.signers_addresses.len(),
            self.args.max_age;
            "signer_addresses" => formatted_signers,
            "signer_keys" => formatted_keys
        );
    }

    fn print_unexpected_messages(
        &self,
        unexpected_messages: &HashMap<StacksAddress, (SignerMessage, SignerSlotID)>,
    ) {
        if unexpected_messages.is_empty() {
            return;
        }
        let formatted_signers = unexpected_messages
            .iter()
            .map(|(addr, (msg, slot))| {
                format!("(address: {addr}, slot_id: {slot}, message: {msg:?})")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let formatted_keys = self
            .cycle_state
            .signers_keys
            .iter()
            .filter_map(|(addr, key)| {
                if unexpected_messages.contains_key(addr) {
                    Some(format!("0x{}", key.to_hex()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            "Unexpected messages from {} of {} signer(s).",
            unexpected_messages.len(),
            self.cycle_state.signers_addresses.len();
            "signer_addresses" => formatted_signers,
            "signer_keys" => formatted_keys
        );
    }

    /// Start monitoring the signers stackerdb slots for expected new messages
    pub fn start(&mut self) -> Result<(), ClientError> {
        self.refresh_state()?;
        let nmb_signers = self.cycle_state.signers_keys.len();
        let interval_ms = self.args.interval * 1000;
        let reward_cycle = self
            .cycle_state
            .reward_cycle
            .expect("BUG: reward cycle not set");
        let contract = MessageSlotID::BlockResponse
            .stacker_db_contract(self.stacks_client.mainnet, reward_cycle);
        info!(
            "Monitoring signers stackerdb. Polling interval: {} secs, Max message age: {} secs, Reward cycle: {reward_cycle}, StackerDB contract: {contract}",
            self.args.interval, self.args.max_age
        );
        let mut session = stackerdb_session(&self.args.host, contract);
        info!("Confirming messages for {nmb_signers} registered signers";
            "signer_addresses" => self.cycle_state.signers_addresses.values().map(|addr| format!("{addr}")).collect::<Vec<_>>().join(", ")
        );
        let mut last_messages = HashMap::with_capacity(nmb_signers);
        let mut last_updates = HashMap::with_capacity(nmb_signers);
        loop {
            info!("Polling signers stackerdb for new messages...");
            let mut missing_signers = Vec::with_capacity(nmb_signers);
            let mut stale_signers = Vec::with_capacity(nmb_signers);
            let mut unexpected_messages = HashMap::new();

            if self.refresh_state()? {
                let reward_cycle = self
                    .cycle_state
                    .reward_cycle
                    .expect("BUG: reward cycle not set");
                let contract = MessageSlotID::BlockResponse
                    .stacker_db_contract(self.stacks_client.mainnet, reward_cycle);
                info!(
                    "Reward cycle has changed to {reward_cycle}. Updating stacker db session to StackerDB contract {contract}.",
                );
                session = stackerdb_session(&self.args.host, contract);
                // Clear the last messages and signer last update times.
                last_messages.clear();
                last_updates.clear();
            }
            let new_messages: Vec<_> = session
                .get_latest_chunks(&self.cycle_state.slot_ids)?
                .into_iter()
                .map(|chunk_opt| {
                    chunk_opt.and_then(|data| read_next::<SignerMessage, _>(&mut &data[..]).ok())
                })
                .collect();

            for (signer_message_opt, slot_id) in
                new_messages.into_iter().zip(&self.cycle_state.slot_ids)
            {
                let signer_slot_id = SignerSlotID(*slot_id);
                let signer_address = *self
                    .cycle_state
                    .signers_addresses
                    .get(&signer_slot_id)
                    .expect("BUG: missing signer address for given slot id");
                let Some(signer_message) = signer_message_opt else {
                    missing_signers.push(signer_address);
                    continue;
                };
                if let Some(last_message) = last_messages.get(&signer_slot_id) {
                    if last_message == &signer_message {
                        continue;
                    }
                }
                let epoch = self.stacks_client.get_node_epoch()?;
                if epoch < StacksEpochId::Epoch25 {
                    return Err(ClientError::UnsupportedStacksFeature(format!("Monitoring signers is only supported for Epoch 2.5 and later. Current epoch: {epoch:?}")));
                }
                if (epoch == StacksEpochId::Epoch25
                    && !matches!(signer_message, SignerMessage::MockSignature(_)))
                    || (epoch > StacksEpochId::Epoch25
                        && !matches!(signer_message, SignerMessage::BlockResponse(_)))
                {
                    unexpected_messages.insert(signer_address, (signer_message, signer_slot_id));
                    continue;
                }
                last_messages.insert(signer_slot_id, signer_message);
                last_updates.insert(signer_slot_id, std::time::Instant::now());
            }
            for (slot_id, last_update_time) in last_updates.iter() {
                if last_update_time.elapsed().as_secs() > self.args.max_age {
                    let address = self
                        .cycle_state
                        .signers_addresses
                        .get(slot_id)
                        .expect("BUG: missing signer address for given slot id");
                    stale_signers.push(*address);
                }
            }
            if missing_signers.is_empty()
                && stale_signers.is_empty()
                && unexpected_messages.is_empty()
            {
                info!(
                    "All {} signers are sending messages as expected.",
                    nmb_signers
                );
            } else {
                self.print_missing_signers(&missing_signers);
                self.print_stale_signers(&stale_signers);
                self.print_unexpected_messages(&unexpected_messages);
            }
            sleep_ms(interval_ms);
        }
    }
}
