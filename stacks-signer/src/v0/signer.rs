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
use std::fmt::Debug;
use std::sync::mpsc::Sender;

use blockstack_lib::net::api::postblock_proposal::BlockValidateResponse;
use clarity::types::chainstate::StacksPrivateKey;
use clarity::types::PrivateKey;
use clarity::util::hash::MerkleHashFunc;
use clarity::util::secp256k1::Secp256k1PublicKey;
use libsigner::v0::messages::{BlockResponse, MessageSlotID, RejectCode, SignerMessage};
use libsigner::{BlockProposal, SignerEvent};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::types::chainstate::StacksAddress;
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
    /// SignerDB for state management
    pub signer_db: SignerDb,
    /// Configuration for proposal evaluation
    pub proposal_config: ProposalEvalConfig,
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

    /// Refresh the next signer data from the given configuration data
    fn update_signer(&mut self, _new_signer_config: &SignerConfig) {
        // do nothing
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
        _res: Sender<Vec<SignerResult>>,
        _current_reward_cycle: u64,
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
                self.handle_block_validate_response(block_validate_response)
            }
            SignerEvent::SignerMessages(_signer_set, messages) => {
                debug!(
                    "{self}: Received {} messages from the other signers. Ignoring...",
                    messages.len()
                );
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
                debug!("{self}: Receved a new burn block event for block height {burn_height}");
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
        Self {
            private_key: signer_config.stacks_private_key,
            stackerdb,
            mainnet: signer_config.mainnet,
            signer_id: signer_config.signer_id,
            signer_addresses: signer_config
                .signer_entries
                .signer_ids
                .into_keys()
                .collect(),
            signer_slot_ids: signer_config.signer_slot_ids.clone(),
            reward_cycle: signer_config.reward_cycle,
            signer_db,
            proposal_config,
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
        // TODO: should add a check to ignore an old burn block height if we know its oudated. Would require us to store the burn block height we last saw on the side.
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

        debug!(
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
    fn handle_block_validate_response(&mut self, block_validate_response: &BlockValidateResponse) {
        debug!("{self}: Received a block validate response: {block_validate_response:?}");
        let (response, block_info) = match block_validate_response {
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
                )
            }
        };
        // Submit a proposal response to the .signers contract for miners
        debug!("{self}: Broadcasting a block response to stacks node: {response:?}");
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
    }
}
