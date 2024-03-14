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
use libsigner::{MessageSlotID, SignerEvent, SignerMessage};
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stacks::chainstate::stacks::boot::{NakamotoSignerEntry, RewardSet, MINERS_NAME, SIGNERS_NAME};
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::{Error as ChainstateError, ThresholdSignature};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::stackerdb::{StackerDBConfig, StackerDBs};
use stacks::util_lib::boot::boot_code_id;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use wsts::common::PolyCommitment;
use wsts::curve::ecdsa;
use wsts::curve::point::{Compressed, Point};
use wsts::curve::scalar::Scalar;
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{Config as CoordinatorConfig, Coordinator};
use wsts::state_machine::PublicKeys;
use wsts::v2::Aggregator;

use super::Error as NakamotoNodeError;
use crate::event_dispatcher::STACKER_DB_CHANNEL;
use crate::{Config, EventDispatcher};

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
    miners_db_config: StackerDBConfig,
    signing_round_timeout: Duration,
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

impl From<&[NakamotoSignerEntry]> for NakamotoSigningParams {
    fn from(reward_set: &[NakamotoSignerEntry]) -> Self {
        let mut weight_end = 1;
        let mut signer_key_ids = HashMap::with_capacity(reward_set.len());
        let mut signer_public_keys = HashMap::with_capacity(reward_set.len());
        let mut wsts_signers = HashMap::new();
        let mut wsts_key_ids = HashMap::new();
        for (i, entry) in reward_set.iter().enumerate() {
            let signer_id = u32::try_from(i).expect("FATAL: number of signers exceeds u32::MAX");
            let ecdsa_pk = ecdsa::PublicKey::try_from(entry.signing_key.as_slice())
                .map_err(|e| format!("Failed to convert signing key to ecdsa::PublicKey: {e}"))
                .unwrap_or_else(|err| {
                    panic!("FATAL: failed to convert signing key to Point: {err}")
                });
            let signer_public_key = Point::try_from(&Compressed::from(ecdsa_pk.to_bytes()))
                .map_err(|e| format!("Failed to convert signing key to wsts::Point: {e}"))
                .unwrap_or_else(|err| {
                    panic!("FATAL: failed to convert signing key to Point: {err}")
                });

            signer_public_keys.insert(signer_id, signer_public_key);
            let weight_start = weight_end;
            weight_end = weight_start + entry.weight;
            let key_ids: HashSet<u32> = (weight_start..weight_end).collect();
            for key_id in key_ids.iter() {
                wsts_key_ids.insert(*key_id, ecdsa_pk.clone());
            }
            signer_key_ids.insert(signer_id, key_ids);
            wsts_signers.insert(signer_id, ecdsa_pk);
        }

        let num_keys = weight_end - 1;
        let threshold = (num_keys * 70) / 100;
        let num_signers = reward_set
            .len()
            .try_into()
            .expect("FATAL: more than u32::max() signers in the reward set");

        NakamotoSigningParams {
            num_signers,
            threshold,
            num_keys,
            signer_key_ids,
            signer_public_keys,
            wsts_public_keys: PublicKeys {
                signers: wsts_signers,
                key_ids: wsts_key_ids,
            },
        }
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
        is_mainnet: bool,
        stackerdb_conn: &StackerDBs,
        miners_db_config: StackerDBConfig,
        config: &Config,
    ) -> Result<Self, ChainstateError> {
        let Some(ref reward_set_signers) = reward_set.signers else {
            error!("Could not initialize WSTS coordinator for reward set without signer");
            return Err(ChainstateError::NoRegisteredSigners(0));
        };

        let Some(receiver) = STACKER_DB_CHANNEL
            .receiver
            .lock()
            .expect("FATAL: StackerDBChannel lock is poisoned")
            .take()
        else {
            error!("Could not obtain handle for the StackerDBChannel");
            return Err(ChainstateError::ChannelClosed(
                "WSTS coordinator requires a handle to the StackerDBChannel".into(),
            ));
        };

        let NakamotoSigningParams {
            num_signers,
            num_keys,
            threshold,
            signer_key_ids,
            signer_public_keys,
            wsts_public_keys,
        } = NakamotoSigningParams::from(reward_set_signers.as_slice());
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

        Ok(Self {
            coordinator,
            message_key,
            receiver: Some(receiver),
            wsts_public_keys,
            is_mainnet,
            miners_db_config,
            signing_round_timeout: config.miner.wait_on_signers.clone(),
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
        stackerdbs: &mut StackerDBs,
        message: SignerMessage,
        is_mainnet: bool,
        miners_db_config: &StackerDBConfig,
        event_dispatcher: &EventDispatcher,
    ) -> Result<(), String> {
        let mut miner_sk = StacksPrivateKey::from_slice(&message_key.to_bytes()).unwrap();
        miner_sk.set_compress_public(true);
        let miner_pubkey = StacksPublicKey::from_private(&miner_sk);
        let Some(slot_range) = NakamotoChainState::get_miner_slot(sortdb, tip, &miner_pubkey)
            .map_err(|e| format!("Failed to read miner slot information: {e:?}"))?
        else {
            return Err("No slot for miner".into());
        };
        let target_slot = 1;
        let slot_id = slot_range.start + target_slot;
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

        let stackerdb_tx = stackerdbs.tx_begin(miners_db_config.clone()).map_err(|e| {
            warn!("Failed to begin stackerdbs transaction to write .miners message"; "err" => ?e);
            "Failed to begin StackerDBs transaction"
        })?;

        match stackerdb_tx.put_chunk(&miners_contract_id, chunk, event_dispatcher) {
            Ok(()) => {
                debug!("Wrote message to stackerdb: {message:?}");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to write message to stackerdb {e:?}");
                Err("Failed to write message to stackerdb".into())
            }
        }
    }

    pub fn begin_sign(
        &mut self,
        block: &NakamotoBlock,
        block_attempt: u64,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        stackerdbs: &mut StackerDBs,
        event_dispatcher: &EventDispatcher,
    ) -> Result<ThresholdSignature, NakamotoNodeError> {
        let sign_id = Self::get_sign_id(burn_tip.block_height, burnchain);
        let sign_iter_id = block_attempt;
        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burn_tip.block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");
        self.coordinator.current_sign_id = sign_id;
        self.coordinator.current_sign_iter_id = sign_iter_id;

        let block_bytes = block.serialize_to_vec();
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
            stackerdbs,
            nonce_req_msg.into(),
            self.is_mainnet,
            &self.miners_db_config,
            event_dispatcher,
        )
        .map_err(NakamotoNodeError::SigningCoordinatorFailure)?;

        let Some(ref mut receiver) = self.receiver else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Failed to obtain the StackerDB event receiver".into(),
            ));
        };

        let start_ts = Instant::now();
        while start_ts.elapsed() <= self.signing_round_timeout {
            let event = match receiver.recv_timeout(Duration::from_millis(50)) {
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

            let is_signer_event = event.contract_id.name.starts_with(SIGNERS_NAME)
                && event.contract_id.issuer.1 == [0; 20];
            if !is_signer_event {
                debug!("Ignoring StackerDB event for non-signer contract"; "contract" => %event.contract_id);
                continue;
            }
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
                    &self.miners_db_config,
                    event_dispatcher,
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
