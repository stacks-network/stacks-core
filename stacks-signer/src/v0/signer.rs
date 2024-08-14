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
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::mpsc::Sender;

use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::postblock_proposal::BlockValidateResponse;
use clarity::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use clarity::types::chainstate::StacksPrivateKey;
use clarity::types::{PrivateKey, StacksEpochId};
use clarity::util::hash::MerkleHashFunc;
use clarity::util::secp256k1::Secp256k1PublicKey;
use libsigner::v0::messages::{
    BlockResponse, MessageSlotID, MockSignature, RejectCode, SignerMessage,
};
use libsigner::{BlockProposal, SignerEvent};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, error, info, warn};

use crate::chainstate::{ProposalEvalConfig, SortitionsView};
use crate::client::{SignerSlotID, StackerDB, StacksClient};
use crate::config::SignerConfig;
use crate::runloop::{RunLoopCommand, SignerResult};
use crate::signerdb::{BlockInfo, SignerDb};
use crate::Signer as SignerTrait;

/// The stacks signer registered for the reward cycle
#[derive(Debug)]
pub struct Signer {
    /// The private key of the signer
    private_key: StacksPrivateKey,
    /// The stackerdb client
    pub stackerdb: StackerDB<MessageSlotID>,
    /// Whether the signer is a mainnet signer or not
    pub mainnet: bool,
    /// The signer id
    pub signer_id: u32,
    /// The signer slot ids for the signers in the reward cycle
    pub signer_slot_ids: Vec<SignerSlotID>,
    /// The addresses of other signers
    pub signer_addresses: Vec<StacksAddress>,
    /// The reward cycle this signer belongs to
    pub reward_cycle: u64,
    /// Reward set signer addresses and their weights
    pub signer_weights: HashMap<StacksAddress, usize>,
    /// SignerDB for state management
    pub signer_db: SignerDb,
    /// Configuration for proposal evaluation
    pub proposal_config: ProposalEvalConfig,
    /// Whether or not to broadcast signed blocks if we gather all signatures
    pub broadcast_signed_blocks: bool,
}

impl std::fmt::Display for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cycle #{} Signer #{}", self.reward_cycle, self.signer_id,)
    }
}

impl SignerTrait<SignerMessage> for Signer {
    /// Create a new signer from the given configuration
    fn new(config: SignerConfig) -> Self {
        Self::from(config)
    }

    /// Return the reward cycle of the signer
    fn reward_cycle(&self) -> u64 {
        self.reward_cycle
    }

    /// Process the event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        event: Option<&SignerEvent<SignerMessage>>,
        _res: &Sender<Vec<SignerResult>>,
        current_reward_cycle: u64,
    ) {
        let event_parity = match event {
            // Block proposal events do have reward cycles, but each proposal has its own cycle,
            //  and the vec could be heterogeneous, so, don't differentiate.
            Some(SignerEvent::BlockValidationResponse(_))
            | Some(SignerEvent::MinerMessages(..))
            | Some(SignerEvent::NewBurnBlock { .. })
            | Some(SignerEvent::StatusCheck)
            | None => None,
            Some(SignerEvent::SignerMessages(msg_parity, ..)) => Some(u64::from(*msg_parity) % 2),
        };
        let other_signer_parity = (self.reward_cycle + 1) % 2;
        if event_parity == Some(other_signer_parity) {
            return;
        }
        debug!("{self}: Processing event: {event:?}");
        let Some(event) = event else {
            // No event. Do nothing.
            debug!("{self}: No event received");
            return;
        };
        match event {
            SignerEvent::BlockValidationResponse(block_validate_response) => {
                debug!("{self}: Received a block proposal result from the stacks node...");
                self.handle_block_validate_response(stacks_client, block_validate_response)
            }
            SignerEvent::SignerMessages(_signer_set, messages) => {
                debug!(
                    "{self}: Received {} messages from the other signers",
                    messages.len()
                );
                // try and gather signatures
                for message in messages {
                    let SignerMessage::BlockResponse(block_response) = message else {
                        continue;
                    };
                    let BlockResponse::Accepted((block_hash, signature)) = block_response else {
                        continue;
                    };
                    self.handle_block_signature(stacks_client, block_hash, signature);
                }
            }
            SignerEvent::MinerMessages(messages, miner_pubkey) => {
                debug!(
                    "{self}: Received {} messages from the miner",
                    messages.len();
                );
                for message in messages {
                    match message {
                        SignerMessage::BlockProposal(block_proposal) => {
                            self.handle_block_proposal(
                                stacks_client,
                                sortition_state,
                                block_proposal,
                                miner_pubkey,
                            );
                        }
                        SignerMessage::BlockPushed(b) => {
                            let block_push_result = stacks_client.post_block(b);
                            info!(
                                "{self}: Got block pushed message";
                                "block_id" => %b.block_id(),
                                "signer_sighash" => %b.header.signer_signature_hash(),
                                "push_result" => ?block_push_result,
                            );
                        }
                        _ => {}
                    }
                }
            }
            SignerEvent::StatusCheck => {
                debug!("{self}: Received a status check event.");
            }
            SignerEvent::NewBurnBlock {
                burn_height,
                burn_header_hash,
                received_time,
            } => {
                info!("{self}: Received a new burn block event for block height {burn_height}");
                if let Err(e) =
                    self.signer_db
                        .insert_burn_block(burn_header_hash, *burn_height, received_time)
                {
                    warn!(
                        "Failed to write burn block event to signerdb";
                        "err" => ?e,
                        "burn_header_hash" => %burn_header_hash,
                        "burn_height" => burn_height
                    );
                }
                *sortition_state = None;
                let epoch = match stacks_client.get_node_epoch() {
                    Ok(epoch) => epoch,
                    Err(e) => {
                        warn!("{self}: Failed to determine node epoch. Cannot mock sign: {e}");
                        return;
                    }
                };
                debug!("{self}: Epoch 2.5 signer received a new burn block event.";
                    "burn_height" => burn_height,
                    "current_reward_cycle" => current_reward_cycle,
                    "epoch" => ?epoch
                );
                if epoch == StacksEpochId::Epoch25 && self.reward_cycle == current_reward_cycle {
                    // We are in epoch 2.5, so we should mock mine to prove we are still alive.
                    self.mock_sign(*burn_height, stacks_client);
                }
            }
        }
    }

    fn process_command(
        &mut self,
        _stacks_client: &StacksClient,
        _current_reward_cycle: u64,
        command: Option<RunLoopCommand>,
    ) {
        if let Some(command) = command {
            warn!("{self}: Received a command: {command:?}. V0 Signers do not support commands. Ignoring...")
        }
    }

    fn has_pending_blocks(&self) -> bool {
        self.signer_db
            .has_pending_blocks(self.reward_cycle)
            .unwrap_or_else(|e| {
                error!("{self}: Failed to check for pending blocks: {e:?}",);
                // Assume we have pending blocks to prevent premature cleanup
                true
            })
    }
}

impl From<SignerConfig> for Signer {
    fn from(signer_config: SignerConfig) -> Self {
        let stackerdb = StackerDB::from(&signer_config);
        debug!(
            "Reward cycle #{} Signer #{}",
            signer_config.reward_cycle, signer_config.signer_id,
        );
        let signer_db =
            SignerDb::new(&signer_config.db_path).expect("Failed to connect to signer Db");
        let proposal_config = ProposalEvalConfig::from(&signer_config);

        // compute signer addresses *in reward cycle order*
        let signer_ids_and_addrs: BTreeMap<_, _> = signer_config
            .signer_entries
            .signer_ids
            .iter()
            .map(|(addr, id)| (*id, addr.clone()))
            .collect();

        let signer_addresses: Vec<_> = signer_ids_and_addrs.into_values().collect();

        let signer_weights = signer_addresses
            .iter()
            .map(|addr| {
                let Some(signer_id) = signer_config.signer_entries.signer_ids.get(addr) else {
                    panic!("Malformed config: no signer ID for {}", addr);
                };
                let Some(key_ids) = signer_config.signer_entries.signer_key_ids.get(signer_id)
                else {
                    panic!(
                        "Malformed config: no key IDs for signer ID {} ({})",
                        signer_id, addr
                    );
                };
                (addr.clone(), key_ids.len())
            })
            .collect();

        Self {
            private_key: signer_config.stacks_private_key,
            stackerdb,
            mainnet: signer_config.mainnet,
            signer_id: signer_config.signer_id,
            signer_addresses,
            signer_weights,
            signer_slot_ids: signer_config.signer_slot_ids.clone(),
            reward_cycle: signer_config.reward_cycle,
            signer_db,
            proposal_config,
            broadcast_signed_blocks: signer_config.broadcast_signed_blocks,
        }
    }
}

impl Signer {
    /// Determine this signers response to a proposed block
    /// Returns a BlockResponse if we have already validated the block
    /// Returns None otherwise
    fn determine_response(&self, block_info: &BlockInfo) -> Option<BlockResponse> {
        let valid = block_info.valid?;
        let response = if valid {
            debug!("{self}: Accepting block {}", block_info.block.block_id());
            let signature = self
                .private_key
                .sign(block_info.signer_signature_hash().bits())
                .expect("Failed to sign block");
            BlockResponse::accepted(block_info.signer_signature_hash(), signature)
        } else {
            debug!("{self}: Rejecting block {}", block_info.block.block_id());
            BlockResponse::rejected(
                block_info.signer_signature_hash(),
                RejectCode::RejectedInPriorRound,
            )
        };
        Some(response)
    }

    /// Handle block proposal messages submitted to signers stackerdb
    fn handle_block_proposal(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_proposal: &BlockProposal,
        miner_pubkey: &Secp256k1PublicKey,
    ) {
        debug!("{self}: Received a block proposal: {block_proposal:?}");
        if block_proposal.reward_cycle != self.reward_cycle {
            // We are not signing for this reward cycle. Ignore the block.
            debug!(
                "{self}: Received a block proposal for a different reward cycle. Ignore it.";
                "requested_reward_cycle" => block_proposal.reward_cycle
            );
            return;
        }
        // TODO: should add a check to ignore an old burn block height if we know its outdated. Would require us to store the burn block height we last saw on the side.
        //  the signer needs to be able to determine whether or not the block they're about to sign would conflict with an already-signed Stacks block
        let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
        if let Some(block_info) = self
            .signer_db
            .block_lookup(self.reward_cycle, &signer_signature_hash)
            .expect("Failed to connect to signer DB")
        {
            let Some(block_response) = self.determine_response(&block_info) else {
                // We are still waiting for a response for this block. Do nothing.
                debug!("{self}: Received a block proposal for a block we are already validating.";
                    "signer_sighash" => %signer_signature_hash,
                    "block_id" => %block_proposal.block.block_id()
                );
                return;
            };
            // Submit a proposal response to the .signers contract for miners
            debug!("{self}: Broadcasting a block response to stacks node: {block_response:?}");
            if let Err(e) = self
                .stackerdb
                .send_message_with_retry::<SignerMessage>(block_response.into())
            {
                warn!("{self}: Failed to send block rejection to stacker-db: {e:?}",);
            }
            return;
        }

        info!(
            "{self}: received a block proposal for a new block. Submit block for validation. ";
            "signer_sighash" => %signer_signature_hash,
            "block_id" => %block_proposal.block.block_id(),
        );
        crate::monitoring::increment_block_proposals_received();
        let mut block_info = BlockInfo::from(block_proposal.clone());

        // Get sortition view if we don't have it
        if sortition_state.is_none() {
            *sortition_state =
                SortitionsView::fetch_view(self.proposal_config.clone(), stacks_client)
                    .inspect_err(|e| {
                        warn!(
                            "{self}: Failed to update sortition view: {e:?}";
                            "signer_sighash" => %signer_signature_hash,
                            "block_id" => %block_proposal.block.block_id(),
                        )
                    })
                    .ok();
        }

        // Check if proposal can be rejected now if not valid against sortition view
        let block_response = if let Some(sortition_state) = sortition_state {
            match sortition_state.check_proposal(
                stacks_client,
                &self.signer_db,
                &block_proposal.block,
                miner_pubkey,
            ) {
                // Error validating block
                Err(e) => {
                    warn!(
                        "{self}: Error checking block proposal: {e:?}";
                        "signer_sighash" => %signer_signature_hash,
                        "block_id" => %block_proposal.block.block_id(),
                    );
                    Some(BlockResponse::rejected(
                        block_proposal.block.header.signer_signature_hash(),
                        RejectCode::ConnectivityIssues,
                    ))
                }
                // Block proposal is bad
                Ok(false) => {
                    warn!(
                        "{self}: Block proposal invalid";
                        "signer_sighash" => %signer_signature_hash,
                        "block_id" => %block_proposal.block.block_id(),
                    );
                    Some(BlockResponse::rejected(
                        block_proposal.block.header.signer_signature_hash(),
                        RejectCode::SortitionViewMismatch,
                    ))
                }
                // Block proposal passed check, still don't know if valid
                Ok(true) => None,
            }
        } else {
            warn!(
                "{self}: Cannot validate block, no sortition view";
                "signer_sighash" => %signer_signature_hash,
                "block_id" => %block_proposal.block.block_id(),
            );
            Some(BlockResponse::rejected(
                block_proposal.block.header.signer_signature_hash(),
                RejectCode::NoSortitionView,
            ))
        };

        if let Some(block_response) = block_response {
            // We know proposal is invalid. Send rejection message, do not do further validation
            block_info.valid = Some(false);
            debug!("{self}: Broadcasting a block response to stacks node: {block_response:?}");
            let res = self
                .stackerdb
                .send_message_with_retry::<SignerMessage>(block_response.into());

            match res {
                Err(e) => warn!("{self}: Failed to send block rejection to stacker-db: {e:?}"),
                Ok(ack) if !ack.accepted => warn!(
                    "{self}: Block rejection not accepted by stacker-db: {:?}",
                    ack.reason
                ),
                Ok(_) => debug!("{self}: Block rejection accepted by stacker-db"),
            }
        } else {
            // We don't know if proposal is valid, submit to stacks-node for further checks
            stacks_client
                .submit_block_for_validation(block_info.block.clone())
                .unwrap_or_else(|e| {
                    warn!("{self}: Failed to submit block for validation: {e:?}");
                });
        }

        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|_| panic!("{self}: Failed to insert block in DB"));
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(
        &mut self,
        stacks_client: &StacksClient,
        block_validate_response: &BlockValidateResponse,
    ) {
        info!("{self}: Received a block validate response: {block_validate_response:?}");
        let (response, block_info, signature_opt) = match block_validate_response {
            BlockValidateResponse::Ok(block_validate_ok) => {
                crate::monitoring::increment_block_validation_responses(true);
                let signer_signature_hash = block_validate_ok.signer_signature_hash;
                // For mutability reasons, we need to take the block_info out of the map and add it back after processing
                let mut block_info = match self
                    .signer_db
                    .block_lookup(self.reward_cycle, &signer_signature_hash)
                {
                    Ok(Some(block_info)) => block_info,
                    Ok(None) => {
                        // We have not seen this block before. Why are we getting a response for it?
                        debug!("{self}: Received a block validate response for a block we have not seen before. Ignoring...");
                        return;
                    }
                    Err(e) => {
                        error!("{self}: Failed to lookup block in signer db: {e:?}",);
                        return;
                    }
                };
                block_info.mark_signed_and_valid();
                let signature = self
                    .private_key
                    .sign(&signer_signature_hash.0)
                    .expect("Failed to sign block");

                (
                    BlockResponse::accepted(signer_signature_hash, signature),
                    block_info,
                    Some(signature.clone()),
                )
            }
            BlockValidateResponse::Reject(block_validate_reject) => {
                crate::monitoring::increment_block_validation_responses(false);
                let signer_signature_hash = block_validate_reject.signer_signature_hash;
                let mut block_info = match self
                    .signer_db
                    .block_lookup(self.reward_cycle, &signer_signature_hash)
                {
                    Ok(Some(block_info)) => block_info,
                    Ok(None) => {
                        // We have not seen this block before. Why are we getting a response for it?
                        debug!("{self}: Received a block validate response for a block we have not seen before. Ignoring...");
                        return;
                    }
                    Err(e) => {
                        error!("{self}: Failed to lookup block in signer db: {e:?}");
                        return;
                    }
                };
                block_info.valid = Some(false);
                (
                    BlockResponse::from(block_validate_reject.clone()),
                    block_info,
                    None,
                )
            }
        };
        // Submit a proposal response to the .signers contract for miners
        info!(
            "{self}: Broadcasting a block response to stacks node: {response:?}";
            "signer_sighash" => %block_info.signer_signature_hash(),
        );
        match self
            .stackerdb
            .send_message_with_retry::<SignerMessage>(response.clone().into())
        {
            Ok(_) => {
                let accepted = matches!(response, BlockResponse::Accepted(..));
                crate::monitoring::increment_block_responses_sent(accepted);
            }
            Err(e) => {
                warn!("{self}: Failed to send block rejection to stacker-db: {e:?}",);
            }
        }
        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|_| panic!("{self}: Failed to insert block in DB"));

        if let Some(signature) = signature_opt {
            // have to save the signature _after_ the block info
            self.handle_block_signature(
                stacks_client,
                &block_info.signer_signature_hash(),
                &signature,
            );
        }
    }

    /// Compute the signing weight, given a list of signatures
    fn compute_signature_signing_weight<'a>(
        &self,
        addrs: impl Iterator<Item = &'a StacksAddress>,
    ) -> u32 {
        let signing_weight = addrs.fold(0usize, |signing_weight, stacker_address| {
            let stacker_weight = self.signer_weights.get(&stacker_address).unwrap_or(&0);
            signing_weight.saturating_add(*stacker_weight)
        });
        u32::try_from(signing_weight)
            .unwrap_or_else(|_| panic!("FATAL: signing weight exceeds u32::MAX"))
    }

    /// Compute the total signing weight
    fn compute_signature_total_weight(&self) -> u32 {
        let total_weight = self
            .signer_weights
            .values()
            .fold(0usize, |acc, val| acc.saturating_add(*val));
        u32::try_from(total_weight)
            .unwrap_or_else(|_| panic!("FATAL: total weight exceeds u32::MAX"))
    }

    /// Handle an observed signature from another signer
    fn handle_block_signature(
        &mut self,
        stacks_client: &StacksClient,
        block_hash: &Sha512Trunc256Sum,
        signature: &MessageSignature,
    ) {
        if !self.broadcast_signed_blocks {
            debug!("{self}: Will ignore block-accept signature, since configured not to broadcast signed blocks");
            return;
        }

        debug!("{self}: Received a block-accept signature: ({block_hash}, {signature})");

        // have we broadcasted before?
        if let Some(ts) = self
            .signer_db
            .get_block_broadcasted(self.reward_cycle, block_hash)
            .unwrap_or_else(|_| {
                panic!("{self}: failed to determine if block {block_hash} was broadcasted")
            })
        {
            debug!(
                "{self}: have already broadcasted block {} at {}, so will not re-attempt",
                block_hash, ts
            );
            return;
        }

        // recover public key
        let Ok(public_key) = Secp256k1PublicKey::recover_to_pubkey(block_hash.bits(), signature)
        else {
            debug!("{self}: Received unrecovarable signature. Will not store.";
                   "signature" => %signature,
                   "block_hash" => %block_hash);

            return;
        };

        // authenticate the signature -- it must be signed by one of the stacking set
        let is_valid_sig = self
            .signer_addresses
            .iter()
            .find(|addr| {
                let stacker_address = StacksAddress::p2pkh(true, &public_key);

                // it only matters that the address hash bytes match
                stacker_address.bytes == addr.bytes
            })
            .is_some();

        if !is_valid_sig {
            debug!("{self}: Receive invalid signature {signature}. Will not store.");
            return;
        }

        // signature is valid! store it
        self.signer_db
            .add_block_signature(block_hash, signature)
            .unwrap_or_else(|_| panic!("{self}: Failed to save block signature"));

        // do we have enough signatures to broadcast?
        // i.e. is the threshold reached?
        let signatures = self
            .signer_db
            .get_block_signatures(block_hash)
            .unwrap_or_else(|_| panic!("{self}: Failed to load block signatures"));

        // put signatures in order by signer address (i.e. reward cycle order)
        let addrs_to_sigs: HashMap<_, _> = signatures
            .into_iter()
            .filter_map(|sig| {
                let Ok(public_key) = Secp256k1PublicKey::recover_to_pubkey(block_hash.bits(), &sig)
                else {
                    return None;
                };
                let addr = StacksAddress::p2pkh(self.mainnet, &public_key);
                Some((addr, sig))
            })
            .collect();

        let signature_weight = self.compute_signature_signing_weight(addrs_to_sigs.keys());
        let total_weight = self.compute_signature_total_weight();

        let min_weight = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
            .unwrap_or_else(|_| {
                panic!("{self}: Failed to compute threshold weight for {total_weight}")
            });

        if min_weight > signature_weight {
            debug!(
                "{self}: Not enough signatures on block {} (have {}, need at least {}/{})",
                block_hash, signature_weight, min_weight, total_weight
            );
            return;
        }

        // have enough signatures to broadcast!
        let Ok(Some(mut block_info)) = self
            .signer_db
            .block_lookup(self.reward_cycle, block_hash)
            .map_err(|e| {
                warn!("{self}: Failed to load block {block_hash}: {e:?})");
                e
            })
        else {
            warn!("{self}: No such block {block_hash}");
            return;
        };

        // record time at which we reached the threshold
        block_info.signed_group = Some(get_epoch_time_secs());
        let _ = self.signer_db.insert_block(&block_info).map_err(|e| {
            warn!(
                "Failed to set group threshold signature timestamp for {}: {:?}",
                block_hash, &e
            );
            e
        });

        // collect signatures for the block
        let signatures: Vec<_> = self
            .signer_addresses
            .iter()
            .filter_map(|addr| addrs_to_sigs.get(addr).cloned())
            .collect();

        let mut block = block_info.block;
        block.header.signer_signature = signatures;

        debug!(
            "{self}: Broadcasting Stacks block {} to node",
            &block.block_id()
        );
        let broadcasted = stacks_client
            .post_block(&block)
            .map_err(|e| {
                warn!(
                    "{self}: Failed to post block {block_hash} (id {}): {e:?}",
                    &block.block_id()
                );
                e
            })
            .is_ok();

        if broadcasted {
            self.signer_db
                .set_block_broadcasted(self.reward_cycle, block_hash, get_epoch_time_secs())
                .unwrap_or_else(|_| {
                    panic!("{self}: failed to determine if block {block_hash} was broadcasted")
                });
        }
    }

    /// Send a mock signature to stackerdb to prove we are still alive
    fn mock_sign(&mut self, burn_block_height: u64, stacks_client: &StacksClient) {
        let Ok(peer_info) = stacks_client.get_peer_info() else {
            warn!("{self}: Failed to get peer info. Cannot mock sign.");
            return;
        };
        let chain_id = if self.mainnet {
            CHAIN_ID_MAINNET
        } else {
            CHAIN_ID_TESTNET
        };
        info!("Mock signing for burn block {burn_block_height:?}";
            "stacks_tip_consensus_hash" => ?peer_info.stacks_tip_consensus_hash.clone(),
            "stacks_tip" => ?peer_info.stacks_tip.clone(),
            "peer_burn_block_height" => peer_info.burn_block_height,
            "pox_consensus" => ?peer_info.pox_consensus.clone(),
            "server_version" => peer_info.server_version.clone(),
            "chain_id" => chain_id
        );
        let mock_signature =
            MockSignature::new(burn_block_height, peer_info, chain_id, &self.private_key);
        let message = SignerMessage::MockSignature(mock_signature);
        if let Err(e) = self
            .stackerdb
            .send_message_with_retry::<SignerMessage>(message)
        {
            warn!("{self}: Failed to send mock signature to stacker-db: {e:?}",);
        }
    }
}
