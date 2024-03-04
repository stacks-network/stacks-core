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
use std::time::Duration;

use hashbrown::{HashMap, HashSet};
use libsigner::{SignerEvent, SignerMessage, SignerSession, StackerDBSession};
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
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use wsts::common::{PublicNonce, Signature, SignatureShare};
use wsts::curve::ecdsa;
use wsts::curve::point::{Compressed, Point};
use wsts::curve::scalar::Scalar;
use wsts::errors::AggregatorError;
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{Config as CoordinatorConfig, Coordinator};
use wsts::state_machine::PublicKeys;

use crate::event_dispatcher::STACKER_DB_CHANNEL;

#[derive(Clone)]
pub struct MyAggregator {
    aggregate_public_key: Point,
}

impl MyAggregator {
    pub fn sign_with_tweak(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        _key_ids: &[u32],
        tweak: &Scalar,
    ) -> Result<(Point, Signature), AggregatorError> {
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (_intermediate_rs, intermediate_r) =
            wsts::compute::intermediate(msg, &party_ids, nonces);
        let mut z = Scalar::from(0);
        let aggregate_public_key = self.aggregate_public_key;
        let tweaked_public_key = aggregate_public_key + tweak * wsts::curve::point::G;
        let c = wsts::compute::challenge(&tweaked_public_key, &intermediate_r, msg);
        let mut cx_sign = Scalar::from(1);
        if tweak != &Scalar::from(0) && !tweaked_public_key.has_even_y() {
            cx_sign = -Scalar::from(1);
        }

        // optimistically try to create the aggregate signature without checking for bad keys or sig shares
        for i in 0..sig_shares.len() {
            z += sig_shares[i].z_i;
        }

        z += cx_sign * c * tweak;

        let sig = Signature {
            R: intermediate_r,
            z,
        };

        Ok((tweaked_public_key, sig))
    }
}

impl wsts::traits::Aggregator for MyAggregator {
    fn new(_num_keys: u32, _threshold: u32) -> Self {
        Self {
            aggregate_public_key: Point::default(),
        }
    }

    fn init(
        &mut self,
        _poly_comms: &HashMap<u32, wsts::common::PolyCommitment>,
    ) -> Result<(), wsts::errors::AggregatorError> {
        // pass
        Ok(())
    }

    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[wsts::common::PublicNonce],
        sig_shares: &[wsts::common::SignatureShare],
        key_ids: &[u32],
    ) -> Result<wsts::common::Signature, wsts::errors::AggregatorError> {
        let (key, sig) =
            self.sign_with_tweak(msg, nonces, sig_shares, key_ids, &Scalar::from(0))?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(AggregatorError::BadGroupSig)
        }
    }

    fn sign_taproot(
        &mut self,
        _msg: &[u8],
        _nonces: &[wsts::common::PublicNonce],
        _sig_shares: &[wsts::common::SignatureShare],
        _key_ids: &[u32],
        _merkle_root: Option<wsts::common::MerkleRoot>,
    ) -> Result<wsts::taproot::SchnorrProof, wsts::errors::AggregatorError> {
        Err(wsts::errors::AggregatorError::BadGroupSig)
    }
}

/// The `SignCoordinator` struct represents a WSTS FIRE coordinator whose
///  sole function is to serve as the coordinator for Nakamoto block signing.
///  This coordinator does not operate as a DKG coordinator. Rather, this struct
///  is used by Nakamoto miners to act as the coordinator for the blocks they
///  produce.
pub struct SignCoordinator {
    coordinator: FireCoordinator<MyAggregator>,
    receiver: Option<Receiver<StackerDBChunksEvent>>,
    message_key: Scalar,
    wsts_public_keys: PublicKeys,
    is_mainnet: bool,
    rpc_sock: String,
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
                    // TODO: This behavior **must** be corrected.
                    //  `signer_public_keys` should be a `Map<u32, Option<Point>>`
                    //  DKG needs to handle this case, treating `None` options as keys that never participate
                    panic!("FATAL: failed to convert signing key to Point: {err}")
                });
            let signer_public_key = Point::try_from(&Compressed::from(ecdsa_pk.to_bytes()))
                .map_err(|e| format!("Failed to convert signing key to wsts::Point: {e}"))
                .unwrap_or_else(|err| {
                    // TODO: This behavior **must** be corrected.
                    //  `signer_public_keys` should be a `Map<u32, Option<Point>>`
                    //  DKG needs to handle this case, treating `None` options as keys that never participate
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

impl SignCoordinator {
    /// * `reward_set` - the active reward set data, used to construct the signer
    ///    set parameters.
    /// * `message_key` - the signing key that the coordinator will use to sign messages
    ///    broadcasted to the signer set. this should be the miner's registered key.
    /// * `aggregate_public_key` - the active aggregate key for this cycle
    pub fn new(
        reward_set: &RewardSet,
        message_key: Scalar,
        aggregate_public_key: Point,
        is_mainnet: bool,
        rpc_sock: String,
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
        info!(
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

        let mut coordinator: FireCoordinator<MyAggregator> = FireCoordinator::new(coord_config);
        coordinator.set_aggregate_public_key(Some(aggregate_public_key.clone()));
        coordinator.aggregator.aggregate_public_key = aggregate_public_key;
        // this has to match the signer sets in order for the
        //  individual signer's local coordinator instance to accept
        //  the SigShareRequest. This *isn't* necessary to to validate
        //  the actual SigShareRequest and produce SigShareResponses,
        //  but it *is* necessary for the signers to produce the
        //  `BlockResponse` messages. Those aren't read by the miner
        //  anymore because its acting as the coordinator, which means
        //  that it just validates the sigshares itself. However, at a minimum,
        //  those are consumed by the signer integration tests... so, this is an attempt
        //  to get *those* to pass. I'm not sure if the system would actually work without
        //  the signers individually sending all the messages to their local coordinator
        //  instances.
        // coordinator.current_dkg_id = 1;
        Ok(Self {
            coordinator,
            message_key,
            receiver: Some(receiver),
            wsts_public_keys,
            is_mainnet,
            rpc_sock,
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
        rpc_sock: &str,
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
        if slot_range.1 - slot_range.0 <= target_slot {
            return Err("Not enough slots for miner messages".into());
        }
        let slot_id = slot_range.0 + target_slot;
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

        let mut stackerdb_session = StackerDBSession::new(rpc_sock.clone(), miners_contract_id);
        match stackerdb_session.put_chunk(&chunk) {
            Ok(ack) => {
                info!("Wrote message to stackerdb: {ack:?}");
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
        burn_block_height: u64,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        stackerdbs: &StackerDBs,
    ) -> Result<ThresholdSignature, String> {
        let sign_id = Self::get_sign_id(burn_block_height, burnchain);
        let sign_iter_id = block_attempt;
        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burn_block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");
        self.coordinator.current_sign_id = sign_id;
        self.coordinator.current_sign_iter_id = sign_iter_id;

        let block_bytes = block.serialize_to_vec();
        let nonce_req_msg = self
            .coordinator
            .start_signing_round(&block_bytes, false, None)
            .map_err(|e| format!("Failed to start signing round in FIRE coordinator: {e:?}"))?;
        Self::send_signers_message(
            &self.message_key,
            sortdb,
            burn_tip,
            stackerdbs,
            nonce_req_msg.into(),
            self.is_mainnet,
            &self.rpc_sock,
        )?;

        let Some(ref mut receiver) = self.receiver else {
            return Err("Failed to obtain the StackerDB event receiver".into());
        };

        // TODO: we need to add an abort signal to this loop function
        loop {
            let event = match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("StackerDB event receiver disconnected".into())
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
            let coordinator_pk = ecdsa::PublicKey::new(&self.message_key)
                .map_err(|_e| "Bad signing key for the FIRE coordinator")?;
            let packets: Vec<_> = messages
                .into_iter()
                .filter_map(|msg| match msg {
                    SignerMessage::BlockResponse(_) | SignerMessage::Transactions(_) => None,
                    SignerMessage::Packet(packet) => {
                        info!("Packet: {packet:?}");
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
                    wsts::state_machine::OperationResult::Dkg(_)
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
                            info!(
                                "Processed signature but didn't validate over the expected block. Returning error.";
                                "signature" => %signature,
                                "block_signer_signature_hash" => %block_sighash
                            );
                            return Err(
                                "Signature failed to validate over the expected block".into()
                            );
                        } else {
                            return Ok(signature);
                        }
                    }
                    wsts::state_machine::OperationResult::SignError(e) => {
                        return Err(format!("Signing failed: {e:?}"))
                    }
                }
            }
            for msg in outbound_msgs {
                let ack = Self::send_signers_message(
                    &self.message_key,
                    sortdb,
                    burn_tip,
                    stackerdbs,
                    msg.into(),
                    self.is_mainnet,
                    &self.rpc_sock,
                );
                if let Ok(ack) = ack {
                    debug!("Miner/Coordinator: send outbound ACK: {ack:?}");
                } else {
                    warn!(
                        "Miner/Coordinator: Failed to send message to StackerDB instance: {ack:?}"
                    );
                };
            }
        }
    }
}
