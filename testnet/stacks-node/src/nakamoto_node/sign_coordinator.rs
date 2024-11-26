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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hashbrown::{HashMap, HashSet};
use libsigner::v0::messages::{
    BlockAccepted, BlockResponse, MinerSlotID, SignerMessage as SignerMessageV0,
};
use libsigner::{BlockProposal, SignerEntries, SignerEvent, SignerSession, StackerDBSession};
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use stacks::chainstate::stacks::boot::{NakamotoSignerEntry, RewardSet, MINERS_NAME, SIGNERS_NAME};
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::stackerdb::StackerDBs;
use stacks::types::PublicKey;
use stacks::util::hash::MerkleHashFunc;
use stacks::util::secp256k1::MessageSignature;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};

use super::Error as NakamotoNodeError;
use crate::event_dispatcher::StackerDBChannel;
use crate::neon::Counters;
use crate::Config;

/// Fault injection flag to prevent the miner from seeing enough signer signatures.
/// Used to test that the signers will broadcast a block if it gets enough signatures
#[cfg(test)]
pub static TEST_IGNORE_SIGNERS: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

/// How long should the coordinator poll on the event receiver before
/// waking up to check timeouts?
static EVENT_RECEIVER_POLL: Duration = Duration::from_millis(500);

/// The `SignCoordinator` struct sole function is to serve as the coordinator for Nakamoto block signing.
/// This struct is used by Nakamoto miners to act as the coordinator for the blocks they produce.
pub struct SignCoordinator {
    receiver: Option<Receiver<StackerDBChunksEvent>>,
    message_key: StacksPrivateKey,
    is_mainnet: bool,
    miners_session: StackerDBSession,
    signer_entries: HashMap<u32, NakamotoSignerEntry>,
    weight_threshold: u32,
    total_weight: u32,
    keep_running: Arc<AtomicBool>,
    pub next_signer_bitvec: BitVec<4000>,
    stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
}

impl Drop for SignCoordinator {
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

impl SignCoordinator {
    /// * `reward_set` - the active reward set data, used to construct the signer
    ///    set parameters.
    /// * `aggregate_public_key` - the active aggregate key for this cycle
    pub fn new(
        reward_set: &RewardSet,
        message_key: StacksPrivateKey,
        config: &Config,
        keep_running: Arc<AtomicBool>,
        stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
    ) -> Result<Self, ChainstateError> {
        let is_mainnet = config.is_mainnet();
        let Some(ref reward_set_signers) = reward_set.signers else {
            error!("Could not initialize signing coordinator for reward set without signer");
            debug!("reward set: {reward_set:?}");
            return Err(ChainstateError::NoRegisteredSigners(0));
        };

        let signer_entries = SignerEntries::parse(is_mainnet, reward_set_signers).map_err(|e| {
            ChainstateError::InvalidStacksBlock(format!(
                "Failed to parse NakamotoSignerEntries: {e:?}"
            ))
        })?;
        let rpc_socket = config
            .node
            .get_rpc_loopback()
            .ok_or_else(|| ChainstateError::MinerAborted)?;
        let miners_contract_id = boot_code_id(MINERS_NAME, is_mainnet);
        let miners_session = StackerDBSession::new(&rpc_socket.to_string(), miners_contract_id);

        let next_signer_bitvec: BitVec<4000> = BitVec::zeros(
            reward_set_signers
                .clone()
                .len()
                .try_into()
                .expect("FATAL: signer set length greater than u16"),
        )
        .expect("FATAL: unable to construct initial bitvec for signer set");

        debug!(
            "Initializing miner/coordinator";
            "num_signers" => signer_entries.signer_pks.len(),
            "signer_public_keys" => ?signer_entries.signer_pks,
        );

        let total_weight = reward_set.total_signing_weight().map_err(|e| {
            warn!("Failed to calculate total weight for the reward set: {e:?}");
            ChainstateError::NoRegisteredSigners(0)
        })?;

        let threshold = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)?;

        let signer_public_keys = reward_set_signers
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
        #[cfg(test)]
        {
            // In test mode, short-circuit spinning up the SignCoordinator if the TEST_SIGNING
            //  channel has been created. This allows integration tests for the stacks-node
            //  independent of the stacks-signer.
            use crate::tests::nakamoto_integrations::TEST_SIGNING;
            if TEST_SIGNING.lock().unwrap().is_some() {
                debug!("Short-circuiting spinning up coordinator from signer commitments. Using test signers channel.");
                let (receiver, replaced_other) = stackerdb_channel
                    .lock()
                    .expect("FATAL: failed to lock StackerDB channel")
                    .register_miner_coordinator();
                if replaced_other {
                    warn!("Replaced the miner/coordinator receiver of a prior thread. Prior thread may have crashed.");
                }
                let sign_coordinator = Self {
                    message_key,
                    receiver: Some(receiver),
                    is_mainnet,
                    miners_session,
                    next_signer_bitvec,
                    signer_entries: signer_public_keys,
                    weight_threshold: threshold,
                    total_weight,
                    keep_running,
                    stackerdb_channel,
                };
                return Ok(sign_coordinator);
            }
        }

        let (receiver, replaced_other) = stackerdb_channel
            .lock()
            .expect("FATAL: failed to lock StackerDB channel")
            .register_miner_coordinator();
        if replaced_other {
            warn!("Replaced the miner/coordinator receiver of a prior thread. Prior thread may have crashed.");
        }

        Ok(Self {
            receiver: Some(receiver),
            message_key,
            is_mainnet,
            miners_session,
            next_signer_bitvec,
            signer_entries: signer_public_keys,
            weight_threshold: threshold,
            total_weight,
            keep_running,
            stackerdb_channel,
        })
    }

    /// Send a message over the miners contract using a `StacksPrivateKey`
    #[allow(clippy::too_many_arguments)]
    pub fn send_miners_message<M: StacksMessageCodec>(
        miner_sk: &StacksPrivateKey,
        sortdb: &SortitionDB,
        tip: &BlockSnapshot,
        stackerdbs: &StackerDBs,
        message: M,
        miner_slot_id: MinerSlotID,
        is_mainnet: bool,
        miners_session: &mut StackerDBSession,
        election_sortition: &ConsensusHash,
    ) -> Result<(), String> {
        let Some(slot_range) = NakamotoChainState::get_miner_slot(sortdb, tip, election_sortition)
            .map_err(|e| format!("Failed to read miner slot information: {e:?}"))?
        else {
            return Err("No slot for miner".into());
        };

        let slot_id = slot_range
            .start
            .saturating_add(miner_slot_id.to_u8().into());
        if !slot_range.contains(&slot_id) {
            return Err("Not enough slots for miner messages".into());
        }
        // Get the LAST slot version number written to the DB. If not found, use 0.
        // Add 1 to get the NEXT version number
        // Note: we already check above for the slot's existence
        let miners_contract_id = boot_code_id(MINERS_NAME, is_mainnet);
        let slot_version = stackerdbs
            .get_slot_version(&miners_contract_id, slot_id)
            .map_err(|e| format!("Failed to read slot version: {e:?}"))?
            .unwrap_or(0)
            .saturating_add(1);
        let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message.serialize_to_vec());
        chunk
            .sign(miner_sk)
            .map_err(|_| "Failed to sign StackerDB chunk")?;

        match miners_session.put_chunk(&chunk) {
            Ok(ack) => {
                if ack.accepted {
                    debug!("Wrote message to stackerdb: {ack:?}");
                    Ok(())
                } else {
                    Err(format!("{ack:?}"))
                }
            }
            Err(e) => Err(format!("{e:?}")),
        }
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

    /// Check if the tenure needs to change
    fn check_burn_tip_changed(sortdb: &SortitionDB, burn_block: &BlockSnapshot) -> bool {
        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if cur_burn_chain_tip.consensus_hash != burn_block.consensus_hash {
            info!("SignCoordinator: Cancel signature aggregation; burnchain tip has changed");
            true
        } else {
            false
        }
    }

    /// Start gathering signatures for a Nakamoto block.
    /// This function begins by sending a `BlockProposal` message
    /// to the signers, and then waits for the signers to respond
    /// with their signatures.  It does so in two ways, concurrently:
    /// * It waits for signer StackerDB messages with signatures. If enough signatures can be
    ///   found, then the block can be broadcast.
    /// * It waits for the chainstate to contain the relayed block. If so, then its signatures are
    ///   loaded and returned. This can happen if the node receives the block via a signer who
    ///   fetched all signatures and assembled the signature vector, all before we could.
    // Mutants skip here: this function is covered via integration tests,
    //  which the mutation testing does not see.
    #[cfg_attr(test, mutants::skip)]
    #[allow(clippy::too_many_arguments)]
    pub fn run_sign_v0(
        &mut self,
        block: &NakamotoBlock,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chain_state: &mut StacksChainState,
        stackerdbs: &StackerDBs,
        counters: &Counters,
        election_sortition: &ConsensusHash,
    ) -> Result<Vec<MessageSignature>, NakamotoNodeError> {
        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burn_tip.block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");

        let block_proposal = BlockProposal {
            block: block.clone(),
            burn_height: burn_tip.block_height,
            reward_cycle: reward_cycle_id,
        };

        let block_proposal_message = SignerMessageV0::BlockProposal(block_proposal);
        debug!("Sending block proposal message to signers";
            "signer_signature_hash" => %block.header.signer_signature_hash(),
        );
        Self::send_miners_message::<SignerMessageV0>(
            &self.message_key,
            sortdb,
            burn_tip,
            stackerdbs,
            block_proposal_message,
            MinerSlotID::BlockProposal,
            self.is_mainnet,
            &mut self.miners_session,
            election_sortition,
        )
        .map_err(NakamotoNodeError::SigningCoordinatorFailure)?;
        counters.bump_naka_proposed_blocks();

        #[cfg(test)]
        {
            info!(
                "SignCoordinator: sent block proposal to .miners, waiting for test signing channel"
            );
            // In test mode, short-circuit waiting for the signers if the TEST_SIGNING
            //  channel has been created. This allows integration tests for the stacks-node
            //  independent of the stacks-signer.
            if let Some(signatures) =
                crate::tests::nakamoto_integrations::TestSigningChannel::get_signature()
            {
                debug!("Short-circuiting waiting for signers, using test signature");
                return Ok(signatures);
            }
        }

        let Some(ref mut receiver) = self.receiver else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Failed to obtain the StackerDB event receiver".into(),
            ));
        };

        let mut total_weight_signed: u32 = 0;
        let mut total_reject_weight: u32 = 0;
        let mut responded_signers = HashSet::new();
        let mut gathered_signatures = BTreeMap::new();

        info!("SignCoordinator: beginning to watch for block signatures OR posted blocks.";
            "threshold" => self.weight_threshold,
        );

        loop {
            // look in the nakamoto staging db -- a block can only get stored there if it has
            // enough signing weight to clear the threshold
            if let Ok(Some((stored_block, _sz))) = chain_state
                .nakamoto_blocks_db()
                .get_nakamoto_block(&block.block_id())
                .map_err(|e| {
                    warn!(
                        "Failed to query chainstate for block {}: {e:?}",
                        &block.block_id()
                    );
                    e
                })
            {
                debug!("SignCoordinator: Found signatures in relayed block");
                counters.bump_naka_signer_pushed_blocks();
                return Ok(stored_block.header.signer_signature);
            }

            if Self::check_burn_tip_changed(sortdb, burn_tip) {
                debug!("SignCoordinator: Exiting due to new burnchain tip");
                return Err(NakamotoNodeError::BurnchainTipChanged);
            }

            // one of two things can happen:
            // * we get enough signatures from stackerdb from the signers, OR
            // * we see our block get processed in our chainstate (meaning, the signers broadcasted
            // the block and our node got it and processed it)
            let event = match receiver.recv_timeout(EVENT_RECEIVER_POLL) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(NakamotoNodeError::SigningCoordinatorFailure(
                        "StackerDB event receiver disconnected".into(),
                    ))
                }
            };

            // was the node asked to stop?
            if !self.keep_running.load(Ordering::SeqCst) {
                info!("SignerCoordinator: received node exit request. Aborting");
                return Err(NakamotoNodeError::ChannelClosed);
            }

            // check to see if this event we got is a signer event
            let is_signer_event =
                event.contract_id.name.starts_with(SIGNERS_NAME) && event.contract_id.is_boot();

            if !is_signer_event {
                debug!("Ignoring StackerDB event for non-signer contract"; "contract" => %event.contract_id);
                continue;
            }

            let modified_slots = &event.modified_slots.clone();

            let Ok(signer_event) = SignerEvent::<SignerMessageV0>::try_from(event).map_err(|e| {
                warn!("Failure parsing StackerDB event into signer event. Ignoring message."; "err" => ?e);
            }) else {
                continue;
            };
            let SignerEvent::SignerMessages(signer_set, messages) = signer_event else {
                debug!("Received signer event other than a signer message. Ignoring.");
                continue;
            };
            if signer_set != u32::try_from(reward_cycle_id % 2).unwrap() {
                debug!("Received signer event for other reward cycle. Ignoring.");
                continue;
            };
            let slot_ids = modified_slots
                .iter()
                .map(|chunk| chunk.slot_id)
                .collect::<Vec<_>>();

            debug!("SignCoordinator: Received messages from signers";
                "count" => messages.len(),
                "slot_ids" => ?slot_ids,
                "threshold" => self.weight_threshold
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

                if responded_signers.contains(&signer_pubkey) {
                    debug!(
                        "Signer {slot_id} already responded for block {}. Ignoring {message:?}.", block.header.signer_signature_hash();
                        "stacks_block_hash" => %block.header.block_hash(),
                        "stacks_block_id" => %block.header.block_id()
                    );
                    continue;
                }

                match message {
                    SignerMessageV0::BlockResponse(BlockResponse::Accepted(accepted)) => {
                        let BlockAccepted {
                            signer_signature_hash: response_hash,
                            signature,
                            metadata,
                            response_data: _, // TOOD: utilize this info
                        } = accepted;
                        let block_sighash = block.header.signer_signature_hash();
                        if block_sighash != response_hash {
                            warn!(
                                "Processed signature for a different block. Will try to continue.";
                                "signature" => %signature,
                                "block_signer_signature_hash" => %block_sighash,
                                "response_hash" => %response_hash,
                                "slot_id" => slot_id,
                                "reward_cycle_id" => reward_cycle_id,
                                "response_hash" => %response_hash,
                                "server_version" => %metadata.server_version
                            );
                            continue;
                        }
                        debug!("SignCoordinator: Received valid signature from signer"; "slot_id" => slot_id, "signature" => %signature);
                        let Ok(valid_sig) = signer_pubkey.verify(block_sighash.bits(), &signature)
                        else {
                            warn!("Got invalid signature from a signer. Ignoring.");
                            continue;
                        };
                        if !valid_sig {
                            warn!(
                                "Processed signature but didn't validate over the expected block. Ignoring";
                                "signature" => %signature,
                                "block_signer_signature_hash" => %block_sighash,
                                "slot_id" => slot_id,
                            );
                            continue;
                        }

                        if Self::fault_injection_ignore_signatures() {
                            warn!("SignCoordinator: fault injection: ignoring well-formed signature for block";
                                "block_signer_sighash" => %block_sighash,
                                "signer_pubkey" => signer_pubkey.to_hex(),
                                "signer_slot_id" => slot_id,
                                "signature" => %signature,
                                "signer_weight" => signer_entry.weight,
                                "total_weight_signed" => total_weight_signed,
                                "stacks_block_hash" => %block.header.block_hash(),
                                "stacks_block_id" => %block.header.block_id()
                            );
                            continue;
                        }

                        if !gathered_signatures.contains_key(&slot_id) {
                            total_weight_signed = total_weight_signed
                                .checked_add(signer_entry.weight)
                                .expect("FATAL: total weight signed exceeds u32::MAX");
                        }

                        info!("SignCoordinator: Signature Added to block";
                            "block_signer_sighash" => %block_sighash,
                            "signer_pubkey" => signer_pubkey.to_hex(),
                            "signer_slot_id" => slot_id,
                            "signature" => %signature,
                            "signer_weight" => signer_entry.weight,
                            "total_weight_signed" => total_weight_signed,
                            "stacks_block_hash" => %block.header.block_hash(),
                            "stacks_block_id" => %block.header.block_id(),
                            "server_version" => metadata.server_version,
                        );
                        gathered_signatures.insert(slot_id, signature);
                        responded_signers.insert(signer_pubkey);
                    }
                    SignerMessageV0::BlockResponse(BlockResponse::Rejected(rejected_data)) => {
                        let block_sighash = block.header.signer_signature_hash();
                        if block_sighash != rejected_data.signer_signature_hash {
                            warn!(
                                "Processed rejection for a different block. Will try to continue.";
                                "block_signer_signature_hash" => %block_sighash,
                                "rejected_data.signer_signature_hash" => %rejected_data.signer_signature_hash,
                                "slot_id" => slot_id,
                                "reward_cycle_id" => reward_cycle_id,
                            );
                            continue;
                        }
                        let rejected_pubkey = match rejected_data.recover_public_key() {
                            Ok(rejected_pubkey) => {
                                if rejected_pubkey != signer_pubkey {
                                    warn!("Recovered public key from rejected data does not match signer's public key. Ignoring.");
                                    continue;
                                }
                                rejected_pubkey
                            }
                            Err(e) => {
                                warn!("Failed to recover public key from rejected data: {e:?}. Ignoring.");
                                continue;
                            }
                        };
                        responded_signers.insert(rejected_pubkey);
                        debug!(
                            "Signer {slot_id} rejected our block {}/{}",
                            &block.header.consensus_hash,
                            &block.header.block_hash()
                        );
                        total_reject_weight = total_reject_weight
                            .checked_add(signer_entry.weight)
                            .expect("FATAL: total weight rejected exceeds u32::MAX");

                        if total_reject_weight.saturating_add(self.weight_threshold)
                            > self.total_weight
                        {
                            debug!(
                                "{total_reject_weight}/{} signers vote to reject our block {}/{}",
                                self.total_weight,
                                &block.header.consensus_hash,
                                &block.header.block_hash()
                            );
                            counters.bump_naka_rejected_blocks();
                            return Err(NakamotoNodeError::SignersRejected);
                        }
                        continue;
                    }
                    SignerMessageV0::BlockProposal(_) => {
                        debug!("Received block proposal message. Ignoring.");
                        continue;
                    }
                    SignerMessageV0::BlockPushed(_) => {
                        debug!("Received block pushed message. Ignoring.");
                        continue;
                    }
                    SignerMessageV0::MockSignature(_)
                    | SignerMessageV0::MockProposal(_)
                    | SignerMessageV0::MockBlock(_) => {
                        debug!("Received mock message. Ignoring.");
                        continue;
                    }
                };
            }
            // After gathering all signatures, return them if we've hit the threshold
            if total_weight_signed >= self.weight_threshold {
                info!("SignCoordinator: Received enough signatures. Continuing.";
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id()
                );
                return Ok(gathered_signatures.values().cloned().collect());
            }
        }
    }
}
