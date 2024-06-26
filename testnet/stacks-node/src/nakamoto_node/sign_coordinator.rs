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

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use hashbrown::{HashMap, HashSet};
use libsigner::v1::messages::{MessageSlotID, SignerMessage};
use libsigner::{BlockProposal, SignerEntries, SignerEvent, SignerSession, StackerDBSession};
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stacks::chainstate::stacks::boot::{NakamotoSignerEntry, RewardSet, MINERS_NAME, SIGNERS_NAME};
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::{Error as ChainstateError, ThresholdSignature};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::stackerdb::StackerDBs;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use wsts::common::PolyCommitment;
use wsts::curve::ecdsa;
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{Config as CoordinatorConfig, Coordinator};
use wsts::state_machine::PublicKeys;
use wsts::v2::Aggregator;

use super::Error as NakamotoNodeError;
use crate::event_dispatcher::STACKER_DB_CHANNEL;
use crate::neon::Counters;
use crate::Config;

/// How long should the coordinator poll on the event receiver before
/// waking up to check timeouts?
static EVENT_RECEIVER_POLL: Duration = Duration::from_millis(50);

/// The `SignCoordinator` struct represents a WSTS FIRE coordinator whose
///  sole function is to serve as the coordinator for Nakamoto block signing.
///  This coordinator does not operate as a DKG coordinator. Rather, this struct
///  is used by Nakamoto miners to act as the coordinator for the blocks they
///  produce.
pub struct SignCoordinator {
    coordinator: FireCoordinator<Aggregator>,
    receiver: Option<Receiver<StackerDBChunksEvent>>,
    message_key: Scalar,
    wsts_public_keys: PublicKeys,
    is_mainnet: bool,
    miners_session: StackerDBSession,
    signing_round_timeout: Duration,
    pub next_signer_bitvec: BitVec<4000>,
}

pub struct NakamotoSigningParams {
    /// total number of signers
    pub num_signers: u32,
    /// total number of keys
    pub num_keys: u32,
    /// threshold of keys needed to form a valid signature
    pub threshold: u32,
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
    /// ECDSA public keys as Point objects indexed by signer_id
    pub signer_public_keys: HashMap<u32, Point>,
    pub wsts_public_keys: PublicKeys,
}

impl Drop for SignCoordinator {
    fn drop(&mut self) {
        STACKER_DB_CHANNEL.replace_receiver(self.receiver.take().expect(
            "FATAL: lost possession of the StackerDB channel before dropping SignCoordinator",
        ));
    }
}

impl NakamotoSigningParams {
    pub fn parse(
        is_mainnet: bool,
        reward_set: &[NakamotoSignerEntry],
    ) -> Result<Self, ChainstateError> {
        let parsed = SignerEntries::parse(is_mainnet, reward_set).map_err(|e| {
            ChainstateError::InvalidStacksBlock(format!(
                "Invalid Reward Set: Could not parse into WSTS structs: {e:?}"
            ))
        })?;

        let num_keys = parsed
            .count_keys()
            .expect("FATAL: more than u32::max() signers in the reward set");
        let num_signers = parsed
            .count_signers()
            .expect("FATAL: more than u32::max() signers in the reward set");
        let threshold = parsed
            .get_signing_threshold()
            .expect("FATAL: more than u32::max() signers in the reward set");

        Ok(NakamotoSigningParams {
            num_signers,
            threshold,
            num_keys,
            signer_key_ids: parsed.coordinator_key_ids,
            signer_public_keys: parsed.signer_public_keys,
            wsts_public_keys: parsed.public_keys,
        })
    }
}

fn get_signer_commitments(
    is_mainnet: bool,
    reward_set: &[NakamotoSignerEntry],
    stackerdbs: &StackerDBs,
    reward_cycle: u64,
    expected_aggregate_key: &Point,
) -> Result<Vec<(u32, PolyCommitment)>, ChainstateError> {
    let commitment_contract =
        MessageSlotID::DkgResults.stacker_db_contract(is_mainnet, reward_cycle);
    let signer_set_len = u32::try_from(reward_set.len())
        .map_err(|_| ChainstateError::InvalidStacksBlock("Reward set length exceeds u32".into()))?;
    for signer_id in 0..signer_set_len {
        let Some(signer_data) = stackerdbs.get_latest_chunk(&commitment_contract, signer_id)?
        else {
            warn!(
                "Failed to fetch DKG result, will look for results from other signers.";
                "signer_id" => signer_id
            );
            continue;
        };
        let Ok(SignerMessage::DkgResults {
            aggregate_key,
            party_polynomials,
        }) = SignerMessage::consensus_deserialize(&mut signer_data.as_slice())
        else {
            warn!(
                "Failed to parse DKG result, will look for results from other signers.";
                "signer_id" => signer_id,
            );
            continue;
        };

        if &aggregate_key != expected_aggregate_key {
            warn!(
                "Aggregate key in DKG results does not match expected, will look for results from other signers.";
                "expected" => %expected_aggregate_key,
                "reported" => %aggregate_key,
            );
            continue;
        }
        let computed_key = party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        if expected_aggregate_key != &computed_key {
            warn!(
                "Aggregate key computed from DKG results does not match expected, will look for results from other signers.";
                "expected" => %expected_aggregate_key,
                "computed" => %computed_key,
            );
            continue;
        }

        return Ok(party_polynomials);
    }
    error!(
        "No valid DKG results found for the active signing set, cannot coordinate a group signature";
        "reward_cycle" => reward_cycle,
    );
    Err(ChainstateError::InvalidStacksBlock(
        "Failed to fetch DKG results for the active signer set".into(),
    ))
}

impl SignCoordinator {
    /// * `reward_set` - the active reward set data, used to construct the signer
    ///    set parameters.
    /// * `message_key` - the signing key that the coordinator will use to sign messages
    ///    broadcasted to the signer set. this should be the miner's registered key.
    /// * `aggregate_public_key` - the active aggregate key for this cycle
    pub fn new(
        reward_set: &RewardSet,
        reward_cycle: u64,
        message_key: Scalar,
        aggregate_public_key: Point,
        stackerdb_conn: &StackerDBs,
        config: &Config,
    ) -> Result<Self, ChainstateError> {
        let is_mainnet = config.is_mainnet();
        let Some(ref reward_set_signers) = reward_set.signers else {
            error!("Could not initialize WSTS coordinator for reward set without signer");
            return Err(ChainstateError::NoRegisteredSigners(0));
        };

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

        let NakamotoSigningParams {
            num_signers,
            num_keys,
            threshold,
            signer_key_ids,
            signer_public_keys,
            wsts_public_keys,
        } = NakamotoSigningParams::parse(is_mainnet, reward_set_signers.as_slice())?;
        debug!(
            "Initializing miner/coordinator";
            "num_signers" => num_signers,
            "num_keys" => num_keys,
            "threshold" => threshold,
            "signer_key_ids" => ?signer_key_ids,
            "signer_public_keys" => ?signer_public_keys,
            "wsts_public_keys" => ?wsts_public_keys,
        );
        let coord_config = CoordinatorConfig {
            num_signers,
            num_keys,
            threshold,
            signer_key_ids,
            signer_public_keys,
            dkg_threshold: threshold,
            message_private_key: message_key.clone(),
            ..Default::default()
        };

        let mut coordinator: FireCoordinator<Aggregator> = FireCoordinator::new(coord_config);
        #[cfg(test)]
        {
            // In test mode, short-circuit spinning up the SignCoordinator if the TEST_SIGNING
            //  channel has been created. This allows integration tests for the stacks-node
            //  independent of the stacks-signer.
            use crate::tests::nakamoto_integrations::TEST_SIGNING;
            if TEST_SIGNING.lock().unwrap().is_some() {
                debug!("Short-circuiting spinning up coordinator from signer commitments. Using test signers channel.");
                let (receiver, replaced_other) = STACKER_DB_CHANNEL.register_miner_coordinator();
                if replaced_other {
                    warn!("Replaced the miner/coordinator receiver of a prior thread. Prior thread may have crashed.");
                }
                let mut sign_coordinator = Self {
                    coordinator,
                    message_key,
                    receiver: Some(receiver),
                    wsts_public_keys,
                    is_mainnet,
                    miners_session,
                    signing_round_timeout: config.miner.wait_on_signers.clone(),
                    next_signer_bitvec,
                };
                sign_coordinator
                    .coordinator
                    .set_aggregate_public_key(Some(aggregate_public_key));
                return Ok(sign_coordinator);
            }
        }
        let party_polynomials = get_signer_commitments(
            is_mainnet,
            reward_set_signers.as_slice(),
            stackerdb_conn,
            reward_cycle,
            &aggregate_public_key,
        )?;
        if let Err(e) = coordinator
            .set_key_and_party_polynomials(aggregate_public_key.clone(), party_polynomials)
        {
            warn!("Failed to set a valid set of party polynomials"; "error" => %e);
        };

        let (receiver, replaced_other) = STACKER_DB_CHANNEL.register_miner_coordinator();
        if replaced_other {
            warn!("Replaced the miner/coordinator receiver of a prior thread. Prior thread may have crashed.");
        }

        Ok(Self {
            coordinator,
            message_key,
            receiver: Some(receiver),
            wsts_public_keys,
            is_mainnet,
            miners_session,
            signing_round_timeout: config.miner.wait_on_signers.clone(),
            next_signer_bitvec,
        })
    }

    fn get_sign_id(burn_block_height: u64, burnchain: &Burnchain) -> u64 {
        burnchain
            .pox_constants
            .reward_cycle_index(burnchain.first_block_height, burn_block_height)
            .expect("FATAL: tried to initialize WSTS coordinator before first burn block height")
    }

    fn send_signers_message(
        message_key: &Scalar,
        sortdb: &SortitionDB,
        tip: &BlockSnapshot,
        stackerdbs: &StackerDBs,
        message: SignerMessage,
        is_mainnet: bool,
        miners_session: &mut StackerDBSession,
    ) -> Result<(), String> {
        let mut miner_sk = StacksPrivateKey::from_slice(&message_key.to_bytes()).unwrap();
        miner_sk.set_compress_public(true);
        let miner_pubkey = StacksPublicKey::from_private(&miner_sk);
        let Some(slot_range) = NakamotoChainState::get_miner_slot(sortdb, tip, &miner_pubkey)
            .map_err(|e| format!("Failed to read miner slot information: {e:?}"))?
        else {
            return Err("No slot for miner".into());
        };
        // We only have one slot per miner
        let slot_id = slot_range.start;
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
            .sign(&miner_sk)
            .map_err(|_| "Failed to sign StackerDB chunk")?;

        match miners_session.put_chunk(&chunk) {
            Ok(ack) => {
                debug!("Wrote message to stackerdb: {ack:?}");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to write message to stackerdb {e:?}");
                Err("Failed to write message to stackerdb".into())
            }
        }
    }

    #[cfg_attr(test, mutants::skip)]
    pub fn begin_sign(
        &mut self,
        block: &NakamotoBlock,
        burn_block_height: u64,
        block_attempt: u64,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        stackerdbs: &StackerDBs,
        counters: &Counters,
    ) -> Result<ThresholdSignature, NakamotoNodeError> {
        let sign_id = Self::get_sign_id(burn_tip.block_height, burnchain);
        let sign_iter_id = block_attempt;
        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burn_tip.block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");
        self.coordinator.current_sign_id = sign_id;
        self.coordinator.current_sign_iter_id = sign_iter_id;

        let proposal_msg = BlockProposal {
            block: block.clone(),
            burn_height: burn_block_height,
            reward_cycle: reward_cycle_id,
        };

        let block_bytes = proposal_msg.serialize_to_vec();
        let nonce_req_msg = self
            .coordinator
            .start_signing_round(&block_bytes, false, None)
            .map_err(|e| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "Failed to start signing round in FIRE coordinator: {e:?}"
                ))
            })?;
        Self::send_signers_message(
            &self.message_key,
            sortdb,
            burn_tip,
            &stackerdbs,
            nonce_req_msg.into(),
            self.is_mainnet,
            &mut self.miners_session,
        )
        .map_err(NakamotoNodeError::SigningCoordinatorFailure)?;
        counters.bump_naka_proposed_blocks();
        #[cfg(test)]
        {
            // In test mode, short-circuit waiting for the signers if the TEST_SIGNING
            //  channel has been created. This allows integration tests for the stacks-node
            //  independent of the stacks-signer.
            if let Some(signature) =
                crate::tests::nakamoto_integrations::TestSigningChannel::get_signature()
            {
                debug!("Short-circuiting waiting for signers, using test signature");
                return Ok(signature);
            }
        }

        let Some(ref mut receiver) = self.receiver else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Failed to obtain the StackerDB event receiver".into(),
            ));
        };

        let start_ts = Instant::now();
        while start_ts.elapsed() <= self.signing_round_timeout {
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

            let is_signer_event =
                event.contract_id.name.starts_with(SIGNERS_NAME) && event.contract_id.is_boot();
            if !is_signer_event {
                debug!("Ignoring StackerDB event for non-signer contract"; "contract" => %event.contract_id);
                continue;
            }
            let modified_slots = &event.modified_slots;

            // Update `next_signers_bitvec` with the slots that were modified in the event
            modified_slots.iter().for_each(|chunk| {
                if let Ok(slot_id) = chunk.slot_id.try_into() {
                    match &self.next_signer_bitvec.set(slot_id, true) {
                        Err(e) => {
                            warn!("Failed to set bitvec for next signer: {e:?}");
                        }
                        _ => (),
                    };
                } else {
                    error!("FATAL: slot_id greater than u16, which should never happen.");
                }
            });

            let Ok(signer_event) = SignerEvent::try_from(event).map_err(|e| {
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
            debug!("Miner/Coordinator: Received messages from signers"; "count" => messages.len());
            let coordinator_pk = ecdsa::PublicKey::new(&self.message_key).map_err(|_e| {
                NakamotoNodeError::MinerSignatureError("Bad signing key for the FIRE coordinator")
            })?;
            let packets: Vec<_> = messages
                .into_iter()
                .filter_map(|msg| match msg {
                    SignerMessage::DkgResults { .. }
                    | SignerMessage::BlockResponse(_)
                    | SignerMessage::EncryptedSignerState(_)
                    | SignerMessage::Transactions(_) => None,
                    SignerMessage::Packet(packet) => {
                        debug!("Received signers packet: {packet:?}");
                        if !packet.verify(&self.wsts_public_keys, &coordinator_pk) {
                            warn!("Failed to verify StackerDB packet: {packet:?}");
                            None
                        } else {
                            Some(packet)
                        }
                    }
                })
                .collect();
            let (outbound_msgs, op_results) = self
                .coordinator
                .process_inbound_messages(&packets)
                .unwrap_or_else(|e| {
                    error!(
                        "Miner/Coordinator: Failed to process inbound message packets";
                        "err" => ?e
                    );
                    (vec![], vec![])
                });
            for operation_result in op_results.into_iter() {
                match operation_result {
                    wsts::state_machine::OperationResult::Dkg { .. }
                    | wsts::state_machine::OperationResult::SignTaproot(_)
                    | wsts::state_machine::OperationResult::DkgError(_) => {
                        debug!("Ignoring unrelated operation result");
                    }
                    wsts::state_machine::OperationResult::Sign(signature) => {
                        // check if the signature actually corresponds to our block?
                        let block_sighash = block.header.signer_signature_hash();
                        let verified = signature.verify(
                            self.coordinator.aggregate_public_key.as_ref().unwrap(),
                            &block_sighash.0,
                        );
                        let signature = ThresholdSignature(signature);
                        if !verified {
                            warn!(
                                "Processed signature but didn't validate over the expected block. Returning error.";
                                "signature" => %signature,
                                "block_signer_signature_hash" => %block_sighash
                            );
                            return Err(NakamotoNodeError::SignerSignatureError(
                                "Signature failed to validate over the expected block".into(),
                            ));
                        } else {
                            info!(
                                "SignCoordinator: Generated a valid signature for the block";
                                "next_signer_bitvec" => self.next_signer_bitvec.binary_str(),
                            );
                            return Ok(signature);
                        }
                    }
                    wsts::state_machine::OperationResult::SignError(e) => {
                        return Err(NakamotoNodeError::SignerSignatureError(format!(
                            "Signing failed: {e:?}"
                        )))
                    }
                }
            }
            for msg in outbound_msgs {
                match Self::send_signers_message(
                    &self.message_key,
                    sortdb,
                    burn_tip,
                    stackerdbs,
                    msg.into(),
                    self.is_mainnet,
                    &mut self.miners_session,
                ) {
                    Ok(()) => {
                        debug!("Miner/Coordinator: sent outbound message.");
                    }
                    Err(e) => {
                        warn!(
                            "Miner/Coordinator: Failed to send message to StackerDB instance: {e:?}."
                        );
                    }
                };
            }
        }

        Err(NakamotoNodeError::SignerSignatureError(
            "Timed out waiting for group signature".into(),
        ))
    }
}
