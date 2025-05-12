// Copyright (C) 2024 Stacks Open Internet Foundation
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
#[cfg(test)]
use std::sync::LazyLock;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use libsigner::v0::messages::{
    BlockAccepted, BlockResponse, MessageSlotID, SignerMessage as SignerMessageV0,
    StateMachineUpdate,
};
use libsigner::v0::signer_state::{GlobalStateEvaluator, SignerStateMachine};
use libsigner::{SignerEntries, SignerEvent, SignerSession, StackerDBSession};
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::nakamoto::NakamotoBlockHeader;
use stacks::chainstate::stacks::boot::{NakamotoSignerEntry, RewardSet, SIGNERS_NAME};
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::codec::StacksMessageCodec;
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::types::PublicKey;
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::{MerkleHashFunc, Sha512Trunc256Sum};
use stacks::util::secp256k1::MessageSignature;
#[cfg(test)]
use stacks_common::util::tests::TestFlag;

use super::Error as NakamotoNodeError;
use crate::event_dispatcher::StackerDBChannel;
use crate::Config;

#[cfg(test)]
/// Fault injection flag to prevent the miner from seeing enough signer signatures.
/// Used to test that the signers will broadcast a block if it gets enough signatures
pub static TEST_IGNORE_SIGNERS: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

/// How long should the coordinator poll on the event receiver before
/// waking up to check timeouts?
pub static EVENT_RECEIVER_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct BlockStatus {
    /// Set of the slot ids of signers who have responded
    pub responded_signers: HashSet<u32>,
    /// Map of the slot id of signers who have signed the block and their signature
    pub gathered_signatures: BTreeMap<u32, MessageSignature>,
    /// Total weight of signers who have signed the block
    pub total_weight_approved: u32,
    /// Total weight of signers who have rejected the block
    pub total_weight_rejected: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct TimestampInfo {
    pub timestamp: u64,
    pub weight: u32,
}

/// The listener for the StackerDB, which listens for messages from the
/// signers and tracks the state of block signatures and idle timestamps.
pub struct StackerDBListener {
    /// Channel to communicate with StackerDB
    stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
    /// Receiver end of the StackerDB events channel
    receiver: Option<Receiver<StackerDBChunksEvent>>,
    /// Flag to shut the node down
    node_keep_running: Arc<AtomicBool>,
    /// Flag to shut the listener down
    keep_running: Arc<AtomicBool>,
    /// The signer set for this tenure (0 or 1)
    signer_set: u32,
    /// The total weight of all signers
    pub(crate) total_weight: u32,
    /// The weight threshold for block approval
    pub(crate) weight_threshold: u32,
    /// The signer entries for this tenure (keyed by slot_id)
    signer_entries: HashMap<u32, NakamotoSignerEntry>,
    /// Tracks signatures for blocks
    ///   - key: Sha512Trunc256Sum (signer signature hash)
    ///   - value: BlockStatus
    pub(crate) blocks: Arc<(Mutex<HashMap<Sha512Trunc256Sum, BlockStatus>>, Condvar)>,
    /// Tracks the timestamps from signers to decide when they should be
    /// willing to accept time-based tenure extensions
    ///  - key: StacksPublicKey
    ///  - value: TimestampInfo
    pub(crate) signer_idle_timestamps: Arc<Mutex<HashMap<StacksPublicKey, TimestampInfo>>>,
    /// Tracks the signer's global state machine through signer state machine update messages
    pub(crate) global_state_evaluator: Arc<Mutex<GlobalStateEvaluator>>,
    /// Wehther we are operating on mainnet
    is_mainnet: bool,
}

/// Interface for other threads to retrieve info from the StackerDBListener
pub struct StackerDBListenerComms {
    /// Tracks signatures for blocks
    ///   - key: Sha512Trunc256Sum (signer signature hash)
    ///   - value: BlockStatus
    blocks: Arc<(Mutex<HashMap<Sha512Trunc256Sum, BlockStatus>>, Condvar)>,
    /// Tracks the timestamps from signers to decide when they should be
    /// willing to accept time-based tenure extensions
    ///  - key: StacksPublicKey
    ///  - value: TimestampInfo
    signer_idle_timestamps: Arc<Mutex<HashMap<StacksPublicKey, TimestampInfo>>>,
    /// Tracks the signer's global state machine through signer state machine update messages
    global_state_evaluator: Arc<Mutex<GlobalStateEvaluator>>,
}

impl StackerDBListener {
    pub fn new(
        stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
        node_keep_running: Arc<AtomicBool>,
        keep_running: Arc<AtomicBool>,
        reward_set: &RewardSet,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
        config: &Config,
    ) -> Result<Self, ChainstateError> {
        let (receiver, replaced_other) = stackerdb_channel
            .lock()
            .expect("FATAL: failed to lock StackerDB channel")
            .register_miner_coordinator();
        if replaced_other {
            warn!("Replaced the miner/coordinator receiver of a prior thread. Prior thread may have crashed.");
        }

        let total_weight = reward_set.total_signing_weight().map_err(|e| {
            warn!("Failed to calculate total weight for the reward set: {e:?}");
            ChainstateError::NoRegisteredSigners(0)
        })?;

        let weight_threshold = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)?;

        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burn_tip.block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");
        let signer_set =
            u32::try_from(reward_cycle_id % 2).expect("FATAL: reward cycle id % 2 exceeds u32");

        let Some(ref reward_set_signers) = reward_set.signers else {
            error!("Could not initialize signing coordinator for reward set without signer");
            debug!("reward set: {reward_set:?}");
            return Err(ChainstateError::NoRegisteredSigners(0));
        };

        let signer_entries = reward_set_signers
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, signer)| {
                let Ok(slot_id) = u32::try_from(idx) else {
                    return Err(ChainstateError::InvalidStacksBlock(
                        "Signer index exceeds u32".into(),
                    ));
                };
                Ok((slot_id, signer))
            })
            .collect::<Result<HashMap<_, _>, ChainstateError>>()?;

        let signers_contract_id = MessageSlotID::StateMachineUpdate
            .stacker_db_contract(config.is_mainnet(), reward_cycle_id);
        let rpc_socket = config
            .node
            .get_rpc_loopback()
            .ok_or_else(|| ChainstateError::MinerAborted)?;
        let mut signers_session =
            StackerDBSession::new(&rpc_socket.to_string(), signers_contract_id.clone());
        let entries: Vec<_> = signer_entries.values().cloned().collect();
        let parsed_entries = SignerEntries::parse(config.is_mainnet(), &entries)
            .expect("FATAL: could not parse retrieved signer entries");
        let address_weights = parsed_entries.signer_addr_to_weight;
        let slot_ids: Vec<_> = parsed_entries.signer_id_to_addr.keys().cloned().collect();

        let chunks = signers_session
            .get_latest_chunks(&slot_ids)
            .inspect_err(|e| warn!("Unable to read the latest signer state from signer db: {e}."))
            .unwrap_or_default();
        let mut global_state_evaluator = GlobalStateEvaluator::new(HashMap::new(), address_weights);
        for (chunk, slot_id) in chunks.into_iter().zip(slot_ids) {
            let Some(chunk) = chunk else {
                continue;
            };
            let Some(signer_entry) = &signer_entries.get(&slot_id) else {
                continue;
            };
            let Ok(signer_pubkey) = StacksPublicKey::from_slice(&signer_entry.signing_key) else {
                continue;
            };
            let address = StacksAddress::p2pkh(config.is_mainnet(), &signer_pubkey);
            if let Ok(SignerMessageV0::StateMachineUpdate(update)) =
                SignerMessageV0::consensus_deserialize(&mut chunk.as_slice())
            {
                global_state_evaluator.insert_update(address, update);
            }
        }

        Ok(Self {
            stackerdb_channel,
            receiver: Some(receiver),
            node_keep_running,
            keep_running,
            signer_set,
            total_weight,
            weight_threshold,
            signer_entries,
            blocks: Arc::new((Mutex::new(HashMap::new()), Condvar::new())),
            signer_idle_timestamps: Arc::new(Mutex::new(HashMap::new())),
            global_state_evaluator: Arc::new(Mutex::new(global_state_evaluator)),
            is_mainnet: config.is_mainnet(),
        })
    }

    pub fn get_comms(&self) -> StackerDBListenerComms {
        StackerDBListenerComms {
            blocks: self.blocks.clone(),
            signer_idle_timestamps: self.signer_idle_timestamps.clone(),
            global_state_evaluator: self.global_state_evaluator.clone(),
        }
    }

    /// Run the StackerDB listener.
    pub fn run(&mut self) -> Result<(), NakamotoNodeError> {
        info!("StackerDBListener: Starting up");

        let Some(receiver) = &self.receiver else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "StackerDBListener: Failed to obtain the StackerDB event receiver".into(),
            ));
        };

        loop {
            // was the node asked to stop?
            if !self.node_keep_running.load(Ordering::SeqCst) {
                info!("StackerDBListener: received node exit request. Aborting");
                return Ok(());
            }

            // was the listener asked to stop?
            if !self.keep_running.load(Ordering::SeqCst) {
                info!("StackerDBListener: received listener exit request. Aborting");
                return Ok(());
            }

            let event = match receiver.recv_timeout(EVENT_RECEIVER_POLL) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    debug!("StackerDBListener: No StackerDB event received. Checking flags and polling again.");
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    warn!("StackerDBListener: StackerDB event receiver disconnected");
                    return Err(NakamotoNodeError::SigningCoordinatorFailure(
                        "StackerDB event receiver disconnected".into(),
                    ));
                }
            };

            // check to see if this event we got is a signer event
            let is_signer_event =
                event.contract_id.name.starts_with(SIGNERS_NAME) && event.contract_id.is_boot();

            if !is_signer_event {
                debug!("StackerDBListener: Ignoring StackerDB event for non-signer contract"; "contract" => %event.contract_id);
                continue;
            }

            let modified_slots = &event.modified_slots.clone();

            let Ok(signer_event) = SignerEvent::<SignerMessageV0>::try_from(event).map_err(|e| {
                warn!("StackerDBListener: Failure parsing StackerDB event into signer event. Ignoring message."; "err" => ?e);
            }) else {
                continue;
            };
            let SignerEvent::SignerMessages {
                signer_set,
                messages,
                ..
            } = signer_event
            else {
                debug!("StackerDBListener: Received signer event other than a signer message. Ignoring.");
                continue;
            };
            if signer_set != self.signer_set {
                debug!(
                    "StackerDBListener: Received signer event for other reward cycle. Ignoring."
                );
                continue;
            };
            let slot_ids = modified_slots
                .into_iter()
                .map(|chunk| chunk.slot_id)
                .collect::<Vec<_>>();

            debug!("StackerDBListener: Received messages from signers";
                "count" => messages.len(),
                "slot_ids" => ?slot_ids,
            );

            for ((_, message), slot_id) in messages.into_iter().zip(slot_ids) {
                let Some(signer_entry) = &self.signer_entries.get(&slot_id) else {
                    return Err(NakamotoNodeError::SignerSignatureError(
                        "Signer entry not found".into(),
                    ));
                };
                let Ok(signer_pubkey) = StacksPublicKey::from_slice(&signer_entry.signing_key)
                else {
                    return Err(NakamotoNodeError::SignerSignatureError(
                        "Failed to parse signer public key".into(),
                    ));
                };

                match message {
                    SignerMessageV0::BlockResponse(BlockResponse::Accepted(accepted)) => {
                        let BlockAccepted {
                            signer_signature_hash: block_sighash,
                            signature,
                            metadata,
                            response_data,
                        } = accepted;
                        let tenure_extend_timestamp = response_data.tenure_extend_timestamp;

                        let (lock, cvar) = &*self.blocks;
                        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");

                        let Some(block) = blocks.get_mut(&block_sighash) else {
                            info!(
                                "StackerDBListener: Received signature for block that we did not request. Ignoring.";
                                "signature" => %signature,
                                "signer_signature_hash" => %block_sighash,
                                "slot_id" => slot_id,
                                "signer_set" => self.signer_set,
                            );
                            continue;
                        };

                        let Ok(valid_sig) = signer_pubkey.verify(block_sighash.bits(), &signature)
                        else {
                            warn!(
                                "StackerDBListener: Got invalid signature from a signer. Ignoring."
                            );
                            continue;
                        };
                        if !valid_sig {
                            warn!(
                                "StackerDBListener: Processed signature but didn't validate over the expected block. Ignoring";
                                "signature" => %signature,
                                "signer_signature_hash" => %block_sighash,
                                "slot_id" => slot_id,
                            );
                            continue;
                        }

                        if Self::fault_injection_ignore_signatures() {
                            warn!("StackerDBListener: fault injection: ignoring well-formed signature for block";
                                "signer_signature_hash" => %block_sighash,
                                "signer_pubkey" => signer_pubkey.to_hex(),
                                "signer_slot_id" => slot_id,
                                "signature" => %signature,
                                "signer_weight" => signer_entry.weight,
                                "total_weight_approved" => block.total_weight_approved,
                                "percent_approved" => block.total_weight_approved as f64 / self.total_weight as f64 * 100.0,
                                "total_weight_rejected" => block.total_weight_rejected,
                                "percent_rejected" => block.total_weight_rejected as f64 / self.total_weight as f64 * 100.0,
                            );
                            continue;
                        }

                        if !block.gathered_signatures.contains_key(&slot_id) {
                            block.total_weight_approved = block
                                .total_weight_approved
                                .checked_add(signer_entry.weight)
                                .expect("FATAL: total weight signed exceeds u32::MAX");
                        }

                        info!("StackerDBListener: Signature Added to block";
                            "signer_signature_hash" => %block_sighash,
                            "signer_pubkey" => signer_pubkey.to_hex(),
                            "signer_slot_id" => slot_id,
                            "signature" => %signature,
                            "signer_weight" => signer_entry.weight,
                            "total_weight_approved" => block.total_weight_approved,
                            "percent_approved" => block.total_weight_approved as f64 / self.total_weight as f64 * 100.0,
                            "total_weight_rejected" => block.total_weight_rejected,
                            "percent_rejected" => block.total_weight_rejected as f64 / self.total_weight as f64 * 100.0,
                            "weight_threshold" => self.weight_threshold,
                            "tenure_extend_timestamp" => tenure_extend_timestamp,
                            "server_version" => metadata.server_version,
                        );
                        block.gathered_signatures.insert(slot_id, signature);
                        block.responded_signers.insert(slot_id);

                        if block.total_weight_approved >= self.weight_threshold {
                            // Signal to anyone waiting on this block that we have enough signatures
                            cvar.notify_all();
                        }

                        // Update the idle timestamp for this signer
                        self.update_idle_timestamp(
                            signer_pubkey,
                            tenure_extend_timestamp,
                            signer_entry.weight,
                        );
                    }
                    SignerMessageV0::BlockResponse(BlockResponse::Rejected(rejected_data)) => {
                        let (lock, cvar) = &*self.blocks;
                        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");

                        let Some(block) = blocks.get_mut(&rejected_data.signer_signature_hash)
                        else {
                            info!(
                                "StackerDBListener: Received rejection for block that we did not request. Ignoring.";
                                "signer_signature_hash" => %rejected_data.signer_signature_hash,
                                "slot_id" => slot_id,
                                "signer_set" => self.signer_set,
                            );
                            continue;
                        };

                        let rejected_pubkey = match rejected_data.recover_public_key() {
                            Ok(rejected_pubkey) => {
                                if rejected_pubkey != signer_pubkey {
                                    warn!("StackerDBListener: Recovered public key from rejected data does not match signer's public key. Ignoring.");
                                    continue;
                                }
                                rejected_pubkey
                            }
                            Err(e) => {
                                warn!("StackerDBListener: Failed to recover public key from rejected data: {e:?}. Ignoring.");
                                continue;
                            }
                        };

                        if block.responded_signers.insert(slot_id) {
                            block.total_weight_rejected = block
                                .total_weight_rejected
                                .checked_add(signer_entry.weight)
                                .expect("FATAL: total weight rejected exceeds u32::MAX");
                        }

                        info!("StackerDBListener: Signer rejected block";
                            "signer_signature_hash" => %rejected_data.signer_signature_hash,
                            "signer_pubkey" => rejected_pubkey.to_hex(),
                            "signer_slot_id" => slot_id,
                            "signature" => %rejected_data.signature,
                            "signer_weight" => signer_entry.weight,
                            "total_weight_approved" => block.total_weight_approved,
                            "percent_approved" => block.total_weight_approved as f64 / self.total_weight as f64 * 100.0,
                            "total_weight_rejected" => block.total_weight_rejected,
                            "percent_rejected" => block.total_weight_rejected as f64 / self.total_weight as f64 * 100.0,
                            "weight_threshold" => self.weight_threshold,
                            "reason" => rejected_data.reason,
                            "reason_code" => ?rejected_data.reason_code,
                            "tenure_extend_timestamp" => rejected_data.response_data.tenure_extend_timestamp,
                            "server_version" => rejected_data.metadata.server_version,
                        );

                        if block
                            .total_weight_rejected
                            .saturating_add(self.weight_threshold)
                            > self.total_weight
                        {
                            // Signal to anyone waiting on this block that we have enough rejections
                            cvar.notify_all();
                        }

                        // Update the idle timestamp for this signer
                        self.update_idle_timestamp(
                            signer_pubkey,
                            rejected_data.response_data.tenure_extend_timestamp,
                            signer_entry.weight,
                        );
                    }
                    SignerMessageV0::BlockProposal(_) => {
                        debug!("Received block proposal message. Ignoring.");
                    }
                    SignerMessageV0::BlockPushed(_) => {
                        debug!("Received block pushed message. Ignoring.");
                    }
                    SignerMessageV0::MockSignature(_)
                    | SignerMessageV0::MockProposal(_)
                    | SignerMessageV0::MockBlock(_) => {
                        debug!("Received mock message. Ignoring.");
                    }
                    SignerMessageV0::StateMachineUpdate(update) => {
                        self.update_global_state_evaluator(&signer_pubkey, update);
                    }
                };
            }
        }
    }

    fn update_idle_timestamp(&self, signer_pubkey: StacksPublicKey, timestamp: u64, weight: u32) {
        let mut idle_timestamps = self
            .signer_idle_timestamps
            .lock()
            .expect("FATAL: failed to lock idle timestamps");

        // Check the current timestamp for the given signer_pubkey
        if let Some(existing_info) = idle_timestamps.get(&signer_pubkey) {
            // Only update if the new timestamp is greater
            if timestamp <= existing_info.timestamp {
                return; // Exit early if the new timestamp is not greater
            }
        }

        // Update the map with the new timestamp and weight
        let timestamp_info = TimestampInfo { timestamp, weight };
        idle_timestamps.insert(signer_pubkey, timestamp_info);
    }

    fn update_global_state_evaluator(&self, pubkey: &StacksPublicKey, update: StateMachineUpdate) {
        let mut eval = self
            .global_state_evaluator
            .lock()
            .expect("FATAL: failed to lock global state evaluator");

        let address = StacksAddress::p2pkh(self.is_mainnet, pubkey);
        eval.insert_update(address, update);
    }

    /// Do we ignore signer signatures?
    #[cfg(test)]
    fn fault_injection_ignore_signatures() -> bool {
        TEST_IGNORE_SIGNERS.get()
    }

    #[cfg(not(test))]
    fn fault_injection_ignore_signatures() -> bool {
        false
    }
}

impl Drop for StackerDBListener {
    fn drop(&mut self) {
        let stackerdb_channel = self
            .stackerdb_channel
            .lock()
            .expect("FATAL: failed to lock stackerdb channel");
        stackerdb_channel.replace_receiver(self.receiver.take().expect(
            "FATAL: lost possession of the StackerDB channel before dropping SignCoordinator",
        ));
    }
}

impl StackerDBListenerComms {
    /// Insert a block into the block status map with initial values.
    pub fn insert_block(&self, block: &NakamotoBlockHeader) {
        let (lock, _cvar) = &*self.blocks;
        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");
        let block_status = BlockStatus {
            responded_signers: HashSet::new(),
            gathered_signatures: BTreeMap::new(),
            total_weight_approved: 0,
            total_weight_rejected: 0,
        };
        blocks.insert(block.signer_signature_hash(), block_status);
    }

    /// Reset rejections for a block proposal.
    /// This is used when a block proposal times out and we need to retry it by
    /// clearing the block's rejections. Block approvals cannot be cleared
    /// because an old approval could always be used to make a block reach
    /// the approval threshold.
    pub fn reset_rejections(&self, signer_sighash: &Sha512Trunc256Sum) {
        let (lock, _cvar) = &*self.blocks;
        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");
        if let Some(block) = blocks.get_mut(signer_sighash) {
            block.responded_signers.clear();
            block.total_weight_rejected = 0;

            // Add approving signers back to the responded signers set
            for (slot_id, _) in block.gathered_signatures.iter() {
                block.responded_signers.insert(*slot_id);
            }
        }
    }

    /// Get the status for `block` from the Stacker DB listener.
    /// If the block is not found in the map, return an error.
    /// If the block is found, call `condition` to check if the block status
    /// satisfies the condition.
    /// If the condition is satisfied, return the block status as
    ///   `Ok(Some(status))`.
    /// If the condition is not satisfied, wait for it to be satisfied.
    /// If the timeout is reached, return `Ok(None)`.
    pub fn wait_for_block_status<F>(
        &self,
        block_signer_sighash: &Sha512Trunc256Sum,
        timeout: Duration,
        condition: F,
    ) -> Result<Option<BlockStatus>, NakamotoNodeError>
    where
        F: Fn(&BlockStatus) -> bool,
    {
        let (lock, cvar) = &*self.blocks;
        let blocks = lock.lock().expect("FATAL: failed to lock block status");

        let (guard, timeout_result) = cvar
            .wait_timeout_while(blocks, timeout, |map| {
                let Some(status) = map.get(block_signer_sighash) else {
                    return true;
                };
                condition(status)
            })
            .expect("FATAL: failed to wait on block status cond var");

        // If we timed out, return None
        if timeout_result.timed_out() {
            return Ok(None);
        }
        match guard.get(block_signer_sighash) {
            Some(status) => Ok(Some(status.clone())),
            None => Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Block not found in status map".into(),
            )),
        }
    }

    /// Get the timestamp at which at least 70% of the signing power should be
    /// willing to accept a time-based tenure extension.
    pub fn get_tenure_extend_timestamp(&self, weight_threshold: u32) -> u64 {
        let signer_idle_timestamps = self
            .signer_idle_timestamps
            .lock()
            .expect("FATAL: failed to lock signer idle timestamps");
        debug!("SignerCoordinator: signer_idle_timestamps: {signer_idle_timestamps:?}");
        let mut idle_timestamps = signer_idle_timestamps.values().collect::<Vec<_>>();
        idle_timestamps.sort_by_key(|info| info.timestamp);
        let mut weight_sum = 0;
        for info in idle_timestamps {
            weight_sum += info.weight;
            if weight_sum >= weight_threshold {
                debug!("SignerCoordinator: 70% threshold reached for tenure extension timestamp";
                    "tenure_extend_timestamp" => info.timestamp,
                    "tenure_extend_in" => (info.timestamp as i64 - get_epoch_time_secs() as i64)
                );
                return info.timestamp;
            }
        }

        // We don't have enough information to reach a 70% threshold at any
        // time, so return u64::MAX to indicate that we should not extend the
        // tenure.
        u64::MAX
    }

    /// Get the global state if there is one
    pub fn get_signer_global_state(&self) -> Option<SignerStateMachine> {
        let mut eval = self
            .global_state_evaluator
            .lock()
            .expect("FATAL: failed to lock global state evaluator");
        eval.determine_global_state()
    }
}
