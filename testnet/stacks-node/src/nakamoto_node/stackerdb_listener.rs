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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use hashbrown::{HashMap, HashSet};
use libsigner::v0::messages::{BlockAccepted, BlockResponse, SignerMessage as SignerMessageV0};
use libsigner::SignerEvent;
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::nakamoto::NakamotoBlockHeader;
use stacks::chainstate::stacks::boot::{NakamotoSignerEntry, RewardSet, SIGNERS_NAME};
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::types::chainstate::StacksPublicKey;
use stacks::types::PublicKey;
use stacks::util::hash::{MerkleHashFunc, Sha512Trunc256Sum};
use stacks::util::secp256k1::MessageSignature;

use super::Error as NakamotoNodeError;
use crate::event_dispatcher::StackerDBChannel;

/// Fault injection flag to prevent the miner from seeing enough signer signatures.
/// Used to test that the signers will broadcast a block if it gets enough signatures
#[cfg(test)]
pub static TEST_IGNORE_SIGNERS: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

/// How long should the coordinator poll on the event receiver before
/// waking up to check timeouts?
pub static EVENT_RECEIVER_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub(crate) struct BlockStatus {
    pub responded_signers: HashSet<StacksPublicKey>,
    pub gathered_signatures: BTreeMap<u32, MessageSignature>,
    pub total_weight_signed: u32,
    pub total_reject_weight: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct TimestampInfo {
    pub timestamp: u64,
    pub weight: u32,
}

/// The listener for the StackerDB, which listens for messages from the
/// signers and tracks the state of block signatures and idle timestamps.
#[derive(Debug)]
pub struct StackerDBListener {
    /// Channel to receive StackerDB events
    receiver: Receiver<StackerDBChunksEvent>,
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
}

impl StackerDBListener {
    pub fn new(
        stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
        keep_running: Arc<AtomicBool>,
        reward_set: &RewardSet,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
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

        Ok(Self {
            receiver,
            keep_running,
            signer_set,
            total_weight,
            weight_threshold,
            signer_entries,
            blocks: Arc::new((Mutex::new(HashMap::new()), Condvar::new())),
            signer_idle_timestamps: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Run the StackerDB listener.
    pub fn run(&mut self) -> Result<(), NakamotoNodeError> {
        info!("StackerDBListener: Starting up");
        loop {
            let event = match self.receiver.recv_timeout(EVENT_RECEIVER_POLL) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    warn!("StackerDBListener: StackerDB event receiver disconnected");
                    return Err(NakamotoNodeError::SigningCoordinatorFailure(
                        "StackerDB event receiver disconnected".into(),
                    ));
                }
            };

            // was the miner asked to stop?
            if !self.keep_running.load(Ordering::SeqCst) {
                info!("StackerDBListener: received miner exit request. Aborting");
                return Err(NakamotoNodeError::ChannelClosed);
            }

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
            let SignerEvent::SignerMessages(signer_set, messages) = signer_event else {
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
                .iter()
                .map(|chunk| chunk.slot_id)
                .collect::<Vec<_>>();

            debug!("StackerDBListener: Received messages from signers";
                "count" => messages.len(),
                "slot_ids" => ?slot_ids,
            );

            for (message, slot_id) in messages.into_iter().zip(slot_ids) {
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

                        let block = match blocks.get_mut(&block_sighash) {
                            Some(block) => block,
                            None => {
                                info!(
                                    "StackerDBListener: Received signature for block that we did not request. Ignoring.";
                                    "signature" => %signature,
                                    "block_signer_sighash" => %block_sighash,
                                    "slot_id" => slot_id,
                                    "signer_set" => self.signer_set,
                                );
                                continue;
                            }
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
                                "block_signer_signature_hash" => %block_sighash,
                                "slot_id" => slot_id,
                            );
                            continue;
                        }

                        if Self::fault_injection_ignore_signatures() {
                            warn!("StackerDBListener: fault injection: ignoring well-formed signature for block";
                                "block_signer_sighash" => %block_sighash,
                                "signer_pubkey" => signer_pubkey.to_hex(),
                                "signer_slot_id" => slot_id,
                                "signature" => %signature,
                                "signer_weight" => signer_entry.weight,
                                "total_weight_signed" => block.total_weight_signed,
                            );
                            continue;
                        }

                        if !block.gathered_signatures.contains_key(&slot_id) {
                            block.total_weight_signed = block
                                .total_weight_signed
                                .checked_add(signer_entry.weight)
                                .expect("FATAL: total weight signed exceeds u32::MAX");
                        }

                        info!("StackerDBListener: Signature Added to block";
                            "block_signer_sighash" => %block_sighash,
                            "signer_pubkey" => signer_pubkey.to_hex(),
                            "signer_slot_id" => slot_id,
                            "signature" => %signature,
                            "signer_weight" => signer_entry.weight,
                            "total_weight_signed" => block.total_weight_signed,
                            "tenure_extend_timestamp" => tenure_extend_timestamp,
                            "server_version" => metadata.server_version,
                        );
                        block.gathered_signatures.insert(slot_id, signature);
                        block.responded_signers.insert(signer_pubkey);

                        if block.total_weight_signed >= self.weight_threshold {
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

                        let block = match blocks.get_mut(&rejected_data.signer_signature_hash) {
                            Some(block) => block,
                            None => {
                                info!(
                                    "StackerDBListener: Received rejection for block that we did not request. Ignoring.";
                                    "block_signer_sighash" => %rejected_data.signer_signature_hash,
                                    "slot_id" => slot_id,
                                    "signer_set" => self.signer_set,
                                );
                                continue;
                            }
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
                        block.responded_signers.insert(rejected_pubkey);
                        block.total_reject_weight = block
                            .total_reject_weight
                            .checked_add(signer_entry.weight)
                            .expect("FATAL: total weight rejected exceeds u32::MAX");

                        info!("StackerDBListener: Signer rejected block";
                            "block_signer_sighash" => %rejected_data.signer_signature_hash,
                            "signer_pubkey" => rejected_pubkey.to_hex(),
                            "signer_slot_id" => slot_id,
                            "signature" => %rejected_data.signature,
                            "signer_weight" => signer_entry.weight,
                            "total_weight_signed" => block.total_weight_signed,
                            "reason" => rejected_data.reason,
                            "reason_code" => %rejected_data.reason_code,
                            "tenure_extend_timestamp" => rejected_data.response_data.tenure_extend_timestamp,
                            "server_version" => rejected_data.metadata.server_version,
                        );

                        if block
                            .total_reject_weight
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
                };
            }
        }
    }

    fn update_idle_timestamp(&self, signer_pubkey: StacksPublicKey, timestamp: u64, weight: u32) {
        let mut idle_timestamps = self
            .signer_idle_timestamps
            .lock()
            .expect("FATAL: failed to lock idle timestamps");
        let timestamp_info = TimestampInfo { timestamp, weight };
        idle_timestamps.insert(signer_pubkey, timestamp_info);
    }

    /// Do we ignore signer signatures?
    #[cfg(test)]
    fn fault_injection_ignore_signatures() -> bool {
        if *TEST_IGNORE_SIGNERS.lock().unwrap() == Some(true) {
            return true;
        }
        false
    }

    #[cfg(not(test))]
    fn fault_injection_ignore_signatures() -> bool {
        false
    }
}
