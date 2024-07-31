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
use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::time::Instant;

use blockstack_lib::chainstate::nakamoto::signer_set::NakamotoSigners;
use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockVote};
use blockstack_lib::chainstate::stacks::boot::SIGNERS_VOTING_FUNCTION_NAME;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::net::api::postblock_proposal::BlockValidateResponse;
use libsigner::{BlockRejection, BlockResponse, RejectCode, SignerEvent, SignerMessage};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::{StacksEpochId, StacksHashMap as HashMap, StacksHashSet as HashSet};
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::{debug, error, info, warn};
use wsts::common::{MerkleRoot, Signature};
use wsts::curve::keys::PublicKey;
use wsts::curve::point::Point;
use wsts::net::{Message, NonceRequest, Packet, SignatureShareRequest};
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{
    Config as CoordinatorConfig, Coordinator, State as CoordinatorState,
};
use wsts::state_machine::signer::Signer as WSTSSigner;
use wsts::state_machine::{OperationResult, SignError};
use wsts::v2;

use crate::client::{retry_with_exponential_backoff, ClientError, StackerDB, StacksClient};
use crate::config::SignerConfig;
use crate::coordinator::CoordinatorSelector;

/// The signer StackerDB slot ID, purposefully wrapped to prevent conflation with SignerID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, PartialOrd, Ord)]
pub struct SignerSlotID(pub u32);

impl std::fmt::Display for SignerSlotID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Additional Info about a proposed block
pub struct BlockInfo {
    /// The block we are considering
    block: NakamotoBlock,
    /// Our vote on the block if we have one yet
    vote: Option<NakamotoBlockVote>,
    /// Whether the block contents are valid
    valid: Option<bool>,
    /// The associated packet nonce request if we have one
    nonce_request: Option<NonceRequest>,
    /// Whether this block is already being signed over
    signed_over: bool,
}

impl BlockInfo {
    /// Create a new BlockInfo
    pub fn new(block: NakamotoBlock) -> Self {
        Self {
            block,
            vote: None,
            valid: None,
            nonce_request: None,
            signed_over: false,
        }
    }

    /// Create a new BlockInfo with an associated nonce request packet
    pub fn new_with_request(block: NakamotoBlock, nonce_request: NonceRequest) -> Self {
        Self {
            block,
            vote: None,
            valid: None,
            nonce_request: Some(nonce_request),
            signed_over: true,
        }
    }
}

/// Which signer operation to perform
#[derive(PartialEq, Clone, Debug)]
pub enum Command {
    /// Generate a DKG aggregate public key
    Dkg,
    /// Sign a message
    Sign {
        /// The block to sign over
        block: NakamotoBlock,
        /// Whether to make a taproot signature
        is_taproot: bool,
        /// Taproot merkle root
        merkle_root: Option<MerkleRoot>,
    },
}

/// The Signer state
#[derive(PartialEq, Debug, Clone)]
pub enum State {
    /// The signer is idle, waiting for messages and commands
    Idle,
    /// The signer is executing a DKG or Sign round
    OperationInProgress,
}

/// The stacks signer registered for the reward cycle
pub struct Signer {
    /// The coordinator for inbound messages for a specific reward cycle
    pub coordinator: FireCoordinator<v2::Aggregator>,
    /// The signing round used to sign messages for a specific reward cycle
    pub signing_round: WSTSSigner<v2::Signer>,
    /// the state of the signer
    pub state: State,
    /// Observed blocks that we have seen so far
    // TODO: cleanup storage and garbage collect this stuff
    pub blocks: HashMap<Sha512Trunc256Sum, BlockInfo>,
    /// Received Commands that need to be processed
    pub commands: VecDeque<Command>,
    /// The stackerdb client
    pub stackerdb: StackerDB,
    /// Whether the signer is a mainnet signer or not
    pub mainnet: bool,
    /// The signer id
    pub signer_id: u32,
    /// The signer slot ids for the signers in the reward cycle
    pub signer_slot_ids: Vec<SignerSlotID>,
    /// The addresses of other signers
    pub signer_addresses: Vec<StacksAddress>,
    /// The signer slot ids for the signers in the NEXT reward cycle
    pub next_signer_slot_ids: Vec<SignerSlotID>,
    /// The addresses of the signers for the NEXT reward cycle
    pub next_signer_addresses: Vec<StacksAddress>,
    /// The reward cycle this signer belongs to
    pub reward_cycle: u64,
    /// The tx fee in uSTX to use if the epoch is pre Nakamoto (Epoch 3.0)
    pub tx_fee_ustx: u64,
    /// The coordinator info for the signer
    pub coordinator_selector: CoordinatorSelector,
    /// The approved key registered to the contract
    pub approved_aggregate_public_key: Option<Point>,
}

impl From<SignerConfig> for Signer {
    fn from(signer_config: SignerConfig) -> Self {
        let stackerdb = StackerDB::from(&signer_config);

        let num_signers = u32::try_from(signer_config.signer_entries.public_keys.signers.len())
            .expect("FATAL: Too many registered signers to fit in a u32");
        let num_keys = u32::try_from(signer_config.signer_entries.public_keys.key_ids.len())
            .expect("FATAL: Too many key ids to fit in a u32");
        let threshold = (num_keys as f64 * 7_f64 / 10_f64).ceil() as u32;
        let dkg_threshold = (num_keys as f64 * 9_f64 / 10_f64).ceil() as u32;

        let coordinator_config = CoordinatorConfig {
            threshold,
            dkg_threshold,
            num_signers,
            num_keys,
            message_private_key: signer_config.ecdsa_private_key,
            dkg_public_timeout: signer_config.dkg_public_timeout,
            dkg_private_timeout: signer_config.dkg_private_timeout,
            dkg_end_timeout: signer_config.dkg_end_timeout,
            nonce_timeout: signer_config.nonce_timeout,
            sign_timeout: signer_config.sign_timeout,
            signer_key_ids: signer_config.signer_entries.coordinator_key_ids.into(),
            signer_public_keys: signer_config.signer_entries.signer_public_keys.into(),
        };

        let coordinator = FireCoordinator::new(coordinator_config);
        let signing_round = WSTSSigner::new(
            threshold,
            num_signers,
            num_keys,
            signer_config.signer_id,
            signer_config.key_ids,
            signer_config.ecdsa_private_key,
            signer_config.signer_entries.public_keys.clone(),
        );
        let coordinator_selector =
            CoordinatorSelector::from(signer_config.signer_entries.public_keys);

        debug!(
            "Signer #{}: initial coordinator is signer {}",
            signer_config.signer_id,
            coordinator_selector.get_coordinator().0
        );

        Self {
            coordinator,
            signing_round,
            state: State::Idle,
            blocks: HashMap::new(),
            commands: VecDeque::new(),
            stackerdb,
            mainnet: signer_config.mainnet,
            signer_id: signer_config.signer_id,
            signer_addresses: signer_config
                .signer_entries
                .signer_ids
                .into_keys()
                .collect(),
            signer_slot_ids: signer_config.signer_slot_ids.clone(),
            next_signer_slot_ids: vec![],
            next_signer_addresses: vec![],
            reward_cycle: signer_config.reward_cycle,
            tx_fee_ustx: signer_config.tx_fee_ustx,
            coordinator_selector,
            approved_aggregate_public_key: None,
        }
    }
}

impl Signer {
    /// Finish an operation and update the coordinator selector accordingly
    fn finish_operation(&mut self) {
        self.state = State::Idle;
        self.coordinator_selector.last_message_time = None;
    }

    /// Update operation
    fn update_operation(&mut self) {
        self.state = State::OperationInProgress;
        self.coordinator_selector.last_message_time = Some(Instant::now());
    }

    /// Execute the given command and update state accordingly
    fn execute_command(&mut self, stacks_client: &StacksClient, command: &Command) {
        match command {
            Command::Dkg => {
                if self.approved_aggregate_public_key.is_some() {
                    debug!("Signer #{}: Already have an aggregate key for reward cycle {}. Ignoring DKG command.", self.signer_id, self.reward_cycle);
                    return;
                }
                let vote_round = match retry_with_exponential_backoff(|| {
                    stacks_client
                        .get_last_round(self.reward_cycle)
                        .map_err(backoff::Error::transient)
                }) {
                    Ok(last_round) => last_round,
                    Err(e) => {
                        error!("Signer #{}: Unable to perform DKG. Failed to get last round from stacks node: {e:?}", self.signer_id);
                        return;
                    }
                };
                // The dkg id will increment internally following "start_dkg_round" so do not increment it here
                self.coordinator.current_dkg_id = vote_round.unwrap_or(0);
                info!(
                    "Signer #{}: Starting DKG vote",
                    self.signer_id;
                    "round" => self.coordinator.current_dkg_id.wrapping_add(1),
                    "cycle" => self.reward_cycle,
                );
                match self.coordinator.start_dkg_round() {
                    Ok(msg) => {
                        let ack = self.stackerdb.send_message_with_retry(msg.into());
                        debug!("Signer #{}: ACK: {ack:?}", self.signer_id);
                    }
                    Err(e) => {
                        error!("Signer #{}: Failed to start DKG: {e:?}", self.signer_id);
                        return;
                    }
                }
            }
            Command::Sign {
                block,
                is_taproot,
                merkle_root,
            } => {
                if self.approved_aggregate_public_key.is_none() {
                    debug!("Signer #{}: Cannot sign a block without an approved aggregate public key. Ignore it.", self.signer_id);
                    return;
                }
                let signer_signature_hash = block.header.signer_signature_hash();
                let block_info = self
                    .blocks
                    .entry(signer_signature_hash)
                    .or_insert_with(|| BlockInfo::new(block.clone()));
                if block_info.signed_over {
                    debug!("Signer #{}: Received a sign command for a block we are already signing over. Ignore it.", self.signer_id);
                    return;
                }
                info!("Signer #{}: Signing block", self.signer_id;
                         "block_consensus_hash" => %block.header.consensus_hash,
                         "block_height" => block.header.chain_length,
                         "pre_sign_block_id" => %block.block_id(),
                );
                match self.coordinator.start_signing_round(
                    &block.serialize_to_vec(),
                    *is_taproot,
                    *merkle_root,
                ) {
                    Ok(msg) => {
                        let ack = self.stackerdb.send_message_with_retry(msg.into());
                        debug!("Signer #{}: ACK: {ack:?}", self.signer_id);
                        block_info.signed_over = true;
                    }
                    Err(e) => {
                        error!(
                            "Signer #{}: Failed to start signing block: {e:?}",
                            self.signer_id
                        );
                        return;
                    }
                }
            }
        }
        self.update_operation();
    }

    /// Attempt to process the next command in the queue, and update state accordingly
    pub fn process_next_command(&mut self, stacks_client: &StacksClient) {
        let coordinator_id = self.coordinator_selector.get_coordinator().0;
        match &self.state {
            State::Idle => {
                if coordinator_id != self.signer_id {
                    debug!(
                        "Signer #{}: Coordinator is {coordinator_id:?}. Will not process any commands...",
                        self.signer_id
                    );
                    return;
                }
                if let Some(command) = self.commands.pop_front() {
                    self.execute_command(stacks_client, &command);
                } else {
                    debug!(
                        "Signer #{}: Nothing to process. Waiting for command...",
                        self.signer_id
                    );
                }
            }
            State::OperationInProgress => {
                // We cannot execute the next command until the current one is finished...
                debug!(
                    "Signer #{}: Waiting for coordinator {coordinator_id:?} operation to finish...",
                    self.signer_id,
                );
            }
        }
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(
        &mut self,
        stacks_client: &StacksClient,
        block_validate_response: &BlockValidateResponse,
        res: Sender<Vec<OperationResult>>,
    ) {
        let block_info = match block_validate_response {
            BlockValidateResponse::Ok(block_validate_ok) => {
                let signer_signature_hash = block_validate_ok.signer_signature_hash;
                // For mutability reasons, we need to take the block_info out of the map and add it back after processing
                let Some(mut block_info) = self.blocks.remove(&signer_signature_hash) else {
                    // We have not seen this block before. Why are we getting a response for it?
                    debug!("Signer #{}: Received a block validate response for a block we have not seen before. Ignoring...", self.signer_id);
                    return;
                };
                let is_valid = self.verify_block_transactions(stacks_client, &block_info.block);
                block_info.valid = Some(is_valid);
                info!(
                    "Signer #{}: Treating block validation for block {} as valid: {:?}",
                    self.signer_id,
                    &block_info.block.block_id(),
                    block_info.valid
                );
                // Add the block info back to the map
                self.blocks
                    .entry(signer_signature_hash)
                    .or_insert(block_info)
            }
            BlockValidateResponse::Reject(block_validate_reject) => {
                let signer_signature_hash = block_validate_reject.signer_signature_hash;
                let Some(block_info) = self.blocks.get_mut(&signer_signature_hash) else {
                    // We have not seen this block before. Why are we getting a response for it?
                    debug!("Signer #{}: Received a block validate response for a block we have not seen before. Ignoring...", self.signer_id);
                    return;
                };
                block_info.valid = Some(false);
                // Submit a rejection response to the .signers contract for miners
                // to observe so they know to send another block and to prove signers are doing work);
                warn!("Signer #{}: Broadcasting a block rejection due to stacks node validation failure...", self.signer_id);
                if let Err(e) = self
                    .stackerdb
                    .send_message_with_retry(block_validate_reject.clone().into())
                {
                    warn!(
                        "Signer #{}: Failed to send block rejection to stacker-db: {e:?}",
                        self.signer_id
                    );
                }
                block_info
            }
        };
        if let Some(mut nonce_request) = block_info.nonce_request.take() {
            debug!("Signer #{}: Received a block validate response from the stacks node for a block we already received a nonce request for. Responding to the nonce request...", self.signer_id);
            // We have received validation from the stacks node. Determine our vote and update the request message
            Self::determine_vote(self.signer_id, block_info, &mut nonce_request);
            // Send the nonce request through with our vote
            let packet = Packet {
                msg: Message::NonceRequest(nonce_request),
                sig: vec![],
            };
            self.handle_packets(stacks_client, res, &[packet]);
        } else {
            let coordinator_id = self.coordinator_selector.get_coordinator().0;
            if block_info.valid.unwrap_or(false)
                && !block_info.signed_over
                && coordinator_id == self.signer_id
            {
                // We are the coordinator. Trigger a signing round for this block
                debug!(
                    "Signer #{}: triggering a signing round over the block {}",
                    self.signer_id,
                    block_info.block.header.block_hash()
                );
                self.commands.push_back(Command::Sign {
                    block: block_info.block.clone(),
                    is_taproot: false,
                    merkle_root: None,
                });
            } else {
                debug!(
                    "Signer #{} ignoring block.", self.signer_id;
                    "block_hash" => block_info.block.header.block_hash(),
                    "valid" => block_info.valid,
                    "signed_over" => block_info.signed_over,
                    "coordinator_id" => coordinator_id,
                );
            }
        }
    }

    /// Handle signer messages submitted to signers stackerdb
    fn handle_signer_messages(
        &mut self,
        stacks_client: &StacksClient,
        res: Sender<Vec<OperationResult>>,
        messages: &[SignerMessage],
    ) {
        let coordinator_pubkey = self.coordinator_selector.get_coordinator().1;
        let packets: Vec<Packet> = messages
            .iter()
            .filter_map(|msg| match msg {
                SignerMessage::BlockResponse(_) | SignerMessage::Transactions(_) => None,
                // TODO: if a signer tries to trigger DKG and we already have one set in the contract, ignore the request.
                SignerMessage::Packet(packet) => {
                    self.verify_packet(stacks_client, packet.clone(), &coordinator_pubkey)
                }
            })
            .collect();
        self.handle_packets(stacks_client, res, &packets);
    }

    /// Handle proposed blocks submitted by the miners to stackerdb
    fn handle_proposed_blocks(&mut self, stacks_client: &StacksClient, blocks: &[NakamotoBlock]) {
        for block in blocks {
            // Store the block in our cache
            self.blocks.insert(
                block.header.signer_signature_hash(),
                BlockInfo::new(block.clone()),
            );
            // Submit the block for validation
            stacks_client
                .submit_block_for_validation(block.clone())
                .unwrap_or_else(|e| {
                    warn!(
                        "Signer #{}: Failed to submit block for validation: {e:?}",
                        self.signer_id
                    );
                });
        }
    }

    /// Process inbound packets as both a signer and a coordinator
    /// Will send outbound packets and operation results as appropriate
    fn handle_packets(
        &mut self,
        stacks_client: &StacksClient,
        res: Sender<Vec<OperationResult>>,
        packets: &[Packet],
    ) {
        let signer_outbound_messages = self
            .signing_round
            .process_inbound_messages(packets)
            .unwrap_or_else(|e| {
                error!(
                    "Signer #{}: Failed to process inbound messages as a signer: {e:?}",
                    self.signer_id
                );
                vec![]
            });

        // Next process the message as the coordinator
        let (coordinator_outbound_messages, operation_results) = self
            .coordinator
            .process_inbound_messages(packets)
            .unwrap_or_else(|e| {
                error!(
                    "Signer #{}: Failed to process inbound messages as a coordinator: {e:?}",
                    self.signer_id
                );
                (vec![], vec![])
            });

        if !operation_results.is_empty() {
            // We have finished a signing or DKG round, either successfully or due to error.
            // Regardless of the why, update our state to Idle as we should not expect the operation to continue.
            self.process_operation_results(stacks_client, &operation_results);
            self.send_operation_results(res, operation_results);
            self.finish_operation();
        } else if !packets.is_empty() && self.coordinator.state != CoordinatorState::Idle {
            // We have received a message and are in the middle of an operation. Update our state accordingly
            self.update_operation();
        }
        self.send_outbound_messages(signer_outbound_messages);
        self.send_outbound_messages(coordinator_outbound_messages);
    }

    /// Validate a signature share request, updating its message where appropriate.
    /// If the request is for a block it has already agreed to sign, it will overwrite the message with the agreed upon value
    /// Returns whether the request is valid or not.
    fn validate_signature_share_request(&self, request: &mut SignatureShareRequest) -> bool {
        let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &request.message[..]).ok()
        else {
            // We currently reject anything that is not a block vote
            debug!(
                "Signer #{}: Received a signature share request for an unknown message stream. Reject it.",
                self.signer_id
            );
            return false;
        };
        match self
            .blocks
            .get(&block_vote.signer_signature_hash)
            .map(|block_info| &block_info.vote)
        {
            Some(Some(vote)) => {
                // Overwrite with our agreed upon value in case another message won majority or the coordinator is trying to cheat...
                debug!(
                    "Signer #{}: set vote for {} to {vote:?}",
                    self.signer_id, block_vote.rejected
                );
                request.message = vote.serialize_to_vec();
                true
            }
            Some(None) => {
                // We never agreed to sign this block. Reject it.
                // This can happen if the coordinator received enough votes to sign yes
                // or no on a block before we received validation from the stacks node.
                debug!("Signer #{}: Received a signature share request for a block we never agreed to sign. Ignore it.", self.signer_id);
                false
            }
            None => {
                // We will only sign across block hashes or block hashes + b'n' byte for
                // blocks we have seen a Nonce Request for (and subsequent validation)
                // We are missing the context here necessary to make a decision. Reject the block
                debug!("Signer #{}: Received a signature share request from an unknown block. Reject it.", self.signer_id);
                false
            }
        }
    }

    /// Validate a nonce request, updating its message appropriately.
    /// If the request is for a block, we will update the request message
    /// as either a hash indicating a vote no or the signature hash indicating a vote yes
    /// Returns whether the request is valid or not
    fn validate_nonce_request(
        &mut self,
        stacks_client: &StacksClient,
        nonce_request: &mut NonceRequest,
    ) -> bool {
        let Some(block): Option<NakamotoBlock> = read_next(&mut &nonce_request.message[..]).ok()
        else {
            // We currently reject anything that is not a block
            debug!(
                "Signer #{}: Received a nonce request for an unknown message stream. Reject it.",
                self.signer_id
            );
            return false;
        };
        let signer_signature_hash = block.header.signer_signature_hash();
        let Some(block_info) = self.blocks.get_mut(&signer_signature_hash) else {
            // We have not seen this block before. Cache it. Send a RPC to the stacks node to validate it.
            debug!("Signer #{}: We have received a block sign request for a block we have not seen before. Cache the nonce request and submit the block for validation...", self.signer_id);
            // We need to update our state to OperationInProgress so we can respond to the nonce request from this signer once we get our validation back
            self.update_operation();
            // Store the block in our cache
            self.blocks.insert(
                signer_signature_hash,
                BlockInfo::new_with_request(block.clone(), nonce_request.clone()),
            );
            stacks_client
                .submit_block_for_validation(block)
                .unwrap_or_else(|e| {
                    warn!(
                        "Signer #{}: Failed to submit block for validation: {e:?}",
                        self.signer_id
                    );
                });
            return false;
        };

        if block_info.valid.is_none() {
            // We have not yet received validation from the stacks node. Cache the request and wait for validation
            debug!("Signer #{}: We have yet to receive validation from the stacks node for a nonce request. Cache the nonce request and wait for block validation...", self.signer_id);
            block_info.nonce_request = Some(nonce_request.clone());
            return false;
        }

        Self::determine_vote(self.signer_id, block_info, nonce_request);
        true
    }

    /// Verify the transactions in a block are as expected
    fn verify_block_transactions(
        &mut self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
    ) -> bool {
        if self.approved_aggregate_public_key.is_some() {
            // We do not enforce a block contain any transactions except the aggregate votes when it is NOT already set
            // TODO: should be only allow special cased transactions during prepare phase before a key is set?
            debug!("Signer #{}: Already have an aggregate key for reward cycle {}. Skipping transaction verification...", self.signer_id, self.reward_cycle);
            return true;
        }
        if let Ok(expected_transactions) = self.get_expected_transactions(stacks_client) {
            //It might be worth building a hashset of the blocks' txids and checking that against the expected transaction's txid.
            let block_tx_hashset = block.txs.iter().map(|tx| tx.txid()).collect::<HashSet<_>>();
            // Ensure the block contains the transactions we expect
            let missing_transactions = expected_transactions
                .into_iter()
                .filter_map(|tx| {
                    if !block_tx_hashset.contains(&tx.txid()) {
                        debug!(
                            "Signer #{}: expected txid {} is in the block",
                            self.signer_id,
                            &tx.txid()
                        );
                        Some(tx)
                    } else {
                        debug!(
                            "Signer #{}: missing expected txid {}",
                            self.signer_id,
                            &tx.txid()
                        );
                        None
                    }
                })
                .collect::<Vec<_>>();
            let is_valid = missing_transactions.is_empty();
            if !is_valid {
                debug!("Signer #{}: Broadcasting a block rejection due to missing expected transactions...", self.signer_id);
                let block_rejection = BlockRejection::new(
                    block.header.signer_signature_hash(),
                    RejectCode::MissingTransactions(missing_transactions),
                );
                // Submit signature result to miners to observe
                if let Err(e) = self
                    .stackerdb
                    .send_message_with_retry(block_rejection.into())
                {
                    warn!(
                        "Signer #{}: Failed to send block rejection to stacker-db: {e:?}",
                        self.signer_id
                    );
                }
            }
            is_valid
        } else {
            // Failed to connect to the stacks node to get transactions. Cannot validate the block. Reject it.
            debug!(
                "Signer #{}: Broadcasting a block rejection due to signer connectivity issues...",
                self.signer_id
            );
            let block_rejection = BlockRejection::new(
                block.header.signer_signature_hash(),
                RejectCode::ConnectivityIssues,
            );
            // Submit signature result to miners to observe
            if let Err(e) = self
                .stackerdb
                .send_message_with_retry(block_rejection.into())
            {
                warn!(
                    "Signer #{}: Failed to send block submission to stacker-db: {e:?}",
                    self.signer_id
                );
            }
            false
        }
    }

    /// Get transactions from stackerdb for the given addresses and account nonces, filtering out any malformed transactions
    fn get_signer_transactions(
        &mut self,
        nonces: &HashMap<StacksAddress, u64>,
    ) -> Result<Vec<StacksTransaction>, ClientError> {
        let transactions: Vec<_> = self
            .stackerdb
            .get_current_transactions_with_retry()?
            .into_iter()
            .filter_map(|tx| {
                if !NakamotoSigners::valid_vote_transaction(nonces, &tx, self.mainnet) {
                    return None;
                }
                Some(tx)
            })
            .collect();
        Ok(transactions)
    }

    /// Get the transactions that should be included in the block, filtering out any invalid transactions
    fn get_expected_transactions(
        &mut self,
        stacks_client: &StacksClient,
    ) -> Result<Vec<StacksTransaction>, ClientError> {
        if self.next_signer_slot_ids.is_empty() {
            debug!(
                "Signer #{}: No next signers. Skipping transaction retrieval.",
                self.signer_id
            );
            return Ok(vec![]);
        }
        // Get all the account nonces for the next signers
        let account_nonces = self.get_account_nonces(stacks_client, &self.next_signer_addresses);
        let transactions: Vec<_> = self
            .stackerdb
            .get_next_transactions_with_retry(&self.next_signer_slot_ids)?;
        let mut filtered_transactions = HashMap::new();
        NakamotoSigners::update_filtered_transactions(
            &mut filtered_transactions,
            &account_nonces,
            self.mainnet,
            transactions,
        );
        // We only allow enforcement of one special cased transaction per signer address per block
        Ok(filtered_transactions.into_values().collect())
    }

    /// Determine the vote for a block and update the block info and nonce request accordingly
    fn determine_vote(
        signer_id: u32,
        block_info: &mut BlockInfo,
        nonce_request: &mut NonceRequest,
    ) {
        let rejected = !block_info.valid.unwrap_or(false);
        if rejected {
            debug!(
                "Signer #{}: Rejecting block {}",
                signer_id,
                block_info.block.block_id()
            );
        } else {
            debug!(
                "Signer #{}: Accepting block {}",
                signer_id,
                block_info.block.block_id()
            );
        }
        let block_vote = NakamotoBlockVote {
            signer_signature_hash: block_info.block.header.signer_signature_hash(),
            rejected: !block_info.valid.unwrap_or(false),
        };
        let block_vote_bytes = block_vote.serialize_to_vec();
        // Cache our vote
        block_info.vote = Some(block_vote);
        nonce_request.message = block_vote_bytes;
    }

    /// Verify a chunk is a valid wsts packet. Returns the packet if it is valid, else None.
    /// NOTE: The packet will be updated if the signer wishes to respond to NonceRequest
    /// and SignatureShareRequests with a different message than what the coordinator originally sent.
    /// This is done to prevent a malicious coordinator from sending a different message than what was
    /// agreed upon and to support the case where the signer wishes to reject a block by voting no
    fn verify_packet(
        &mut self,
        stacks_client: &StacksClient,
        mut packet: Packet,
        coordinator_public_key: &PublicKey,
    ) -> Option<Packet> {
        // We only care about verified wsts packets. Ignore anything else.
        if packet.verify(&self.signing_round.public_keys, coordinator_public_key) {
            match &mut packet.msg {
                Message::SignatureShareRequest(request) => {
                    if !self.validate_signature_share_request(request) {
                        return None;
                    }
                }
                Message::NonceRequest(request) => {
                    if !self.validate_nonce_request(stacks_client, request) {
                        return None;
                    }
                }
                _ => {
                    // Nothing to do for other message types
                }
            }
            Some(packet)
        } else {
            debug!(
                "Signer #{}: Failed to verify wsts packet with {}: {packet:?}",
                self.signer_id, coordinator_public_key
            );
            None
        }
    }

    /// Processes the operation results, broadcasting block acceptance or rejection messages
    /// and DKG vote results accordingly
    fn process_operation_results(
        &mut self,
        stacks_client: &StacksClient,
        operation_results: &[OperationResult],
    ) {
        for operation_result in operation_results {
            // Signers only every trigger non-taproot signing rounds over blocks. Ignore SignTaproot results
            match operation_result {
                OperationResult::Sign(signature) => {
                    debug!("Signer #{}: Received signature result", self.signer_id);
                    self.process_signature(signature);
                }
                OperationResult::SignTaproot(_) => {
                    debug!("Signer #{}: Received a signature result for a taproot signature. Nothing to broadcast as we currently sign blocks with a FROST signature.", self.signer_id);
                }
                OperationResult::Dkg(dkg_public_key) => {
                    self.process_dkg(stacks_client, dkg_public_key);
                }
                OperationResult::SignError(e) => {
                    warn!("Signer #{}: Received a Sign error: {e:?}", self.signer_id);
                    self.process_sign_error(e);
                }
                OperationResult::DkgError(e) => {
                    warn!("Signer #{}: Received a DKG error: {e:?}", self.signer_id);
                    // TODO: process these errors and track malicious signers to report
                }
            }
        }
    }

    /// Process a dkg result by broadcasting a vote to the stacks node
    fn process_dkg(&mut self, stacks_client: &StacksClient, dkg_public_key: &Point) {
        let epoch = retry_with_exponential_backoff(|| {
            stacks_client
                .get_node_epoch()
                .map_err(backoff::Error::transient)
        })
        .unwrap_or(StacksEpochId::Epoch24);
        let tx_fee = if epoch < StacksEpochId::Epoch30 {
            debug!(
                "Signer #{}: in pre Epoch 3.0 cycles, must set a transaction fee for the DKG vote.",
                self.signer_id
            );
            Some(self.tx_fee_ustx)
        } else {
            None
        };
        // Get our current nonce from the stacks node and compare it against what we have sitting in the stackerdb instance
        let signer_address = stacks_client.get_signer_address();
        // Retreieve ALL account nonces as we may have transactions from other signers in our stackerdb slot that we care about
        let account_nonces = self.get_account_nonces(stacks_client, &self.signer_addresses);
        let account_nonce = account_nonces.get(signer_address).unwrap_or(&0);
        let signer_transactions = retry_with_exponential_backoff(|| {
            self.get_signer_transactions(&account_nonces)
                .map_err(backoff::Error::transient)
        })
        .map_err(|e| {
            warn!(
                "Signer #{}: Unable to get signer transactions: {e:?}",
                self.signer_id
            );
        })
        .unwrap_or_default();
        // If we have a transaction in the stackerdb slot, we need to increment the nonce hence the +1, else should use the account nonce
        let next_nonce = signer_transactions
            .first()
            .map(|tx| tx.get_origin_nonce().wrapping_add(1))
            .unwrap_or(*account_nonce);
        match stacks_client.build_vote_for_aggregate_public_key(
            self.stackerdb.get_signer_slot_id().0,
            self.coordinator.current_dkg_id,
            *dkg_public_key,
            self.reward_cycle,
            tx_fee,
            next_nonce,
        ) {
            Ok(new_transaction) => {
                if let Err(e) = self.broadcast_dkg_vote(
                    stacks_client,
                    epoch,
                    signer_transactions,
                    new_transaction,
                ) {
                    warn!(
                        "Signer #{}: Failed to broadcast DKG public key vote ({dkg_public_key:?}): {e:?}",
                        self.signer_id
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Signer #{}: Failed to build DKG public key vote ({dkg_public_key:?}) transaction: {e:?}.",
                    self.signer_id
                );
            }
        }
    }

    // Get the account nonces for the provided list of signer addresses
    fn get_account_nonces(
        &self,
        stacks_client: &StacksClient,
        signer_addresses: &[StacksAddress],
    ) -> HashMap<StacksAddress, u64> {
        let mut account_nonces = HashMap::with_capacity(signer_addresses.len());
        for address in signer_addresses {
            let Ok(account_nonce) = retry_with_exponential_backoff(|| {
                stacks_client
                    .get_account_nonce(address)
                    .map_err(backoff::Error::transient)
            }) else {
                warn!(
                    "Signer #{}: Unable to get account nonce for address: {address}.",
                    self.signer_id
                );
                continue;
            };
            account_nonces.insert(*address, account_nonce);
        }
        account_nonces
    }

    /// broadcast the dkg vote transaction according to the current epoch
    fn broadcast_dkg_vote(
        &mut self,
        stacks_client: &StacksClient,
        epoch: StacksEpochId,
        mut signer_transactions: Vec<StacksTransaction>,
        new_transaction: StacksTransaction,
    ) -> Result<(), ClientError> {
        let txid = new_transaction.txid();
        if self.approved_aggregate_public_key.is_some() {
            // We do not enforce a block contain any transactions except the aggregate votes when it is NOT already set
            info!(
                "Signer #{}: Already has an aggregate key for reward cycle {}. Do not broadcast the transaction ({txid:?}).",
                self.signer_id, self.reward_cycle
            );
            return Ok(());
        }
        if epoch >= StacksEpochId::Epoch30 {
            debug!("Signer #{}: Received a DKG result while in epoch 3.0. Broadcast the transaction only to stackerDB.", self.signer_id);
        } else if epoch == StacksEpochId::Epoch25 {
            debug!("Signer #{}: Received a DKG result while in epoch 2.5. Broadcast the transaction to the mempool.", self.signer_id);
            stacks_client.submit_transaction(&new_transaction)?;
            info!(
                "Signer #{}: Submitted DKG vote transaction ({txid:?}) to the mempool",
                self.signer_id
            );
        } else {
            debug!("Signer #{}: Received a DKG result, but are in an unsupported epoch. Do not broadcast the transaction ({}).", self.signer_id, new_transaction.txid());
            return Ok(());
        }
        // For all Pox-4 epochs onwards, broadcast the results also to stackerDB for other signers/miners to observe
        signer_transactions.push(new_transaction);
        let signer_message = SignerMessage::Transactions(signer_transactions);
        self.stackerdb.send_message_with_retry(signer_message)?;
        info!(
            "Signer #{}: Broadcasted DKG vote transaction ({txid}) to stacker DB",
            self.signer_id,
        );
        Ok(())
    }

    /// Process a signature from a signing round by deserializing the signature and
    /// broadcasting an appropriate Reject or Approval message to stackerdb
    fn process_signature(&mut self, signature: &Signature) {
        // Deserialize the signature result and broadcast an appropriate Reject or Approval message to stackerdb
        let message = self.coordinator.get_message();
        let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &message[..]).ok() else {
            debug!(
                "Signer #{}: Received a signature result for a non-block. Nothing to broadcast.",
                self.signer_id
            );
            return;
        };

        // TODO: proper garbage collection...This is currently our only cleanup of blocks
        self.blocks.remove(&block_vote.signer_signature_hash);

        let block_submission = if block_vote.rejected {
            // We signed a rejection message. Return a rejection message
            BlockResponse::rejected(block_vote.signer_signature_hash, signature.clone()).into()
        } else {
            // we agreed to sign the block hash. Return an approval message
            BlockResponse::accepted(block_vote.signer_signature_hash, signature.clone()).into()
        };

        // Submit signature result to miners to observe
        debug!(
            "Signer #{}: submit block response {block_submission:?}",
            self.signer_id
        );
        if let Err(e) = self.stackerdb.send_message_with_retry(block_submission) {
            warn!(
                "Signer #{}: Failed to send block submission to stacker-db: {e:?}",
                self.signer_id
            );
        }
    }

    /// Process a sign error from a signing round, broadcasting a rejection message to stackerdb accordingly
    fn process_sign_error(&mut self, e: &SignError) {
        let message = self.coordinator.get_message();
        // We do not sign across blocks, but across their hashes. however, the first sign request is always across the block
        // so we must handle this case first

        let block: NakamotoBlock = read_next(&mut &message[..]).ok().unwrap_or({
            // This is not a block so maybe its across its hash
            let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &message[..]).ok() else {
                // This is not a block vote either. We cannot process this error
                debug!("Signer #{}: Received a signature error for a non-block. Nothing to broadcast.", self.signer_id);
                return;
            };
            let Some(block_info) = self.blocks.remove(&block_vote.signer_signature_hash) else {
                debug!("Signer #{}: Received a signature result for a block we have not seen before. Ignoring...", self.signer_id);
                return;
            };
            block_info.block
        });
        let block_rejection =
            BlockRejection::new(block.header.signer_signature_hash(), RejectCode::from(e));
        debug!(
            "Signer #{}: Broadcasting block rejection: {block_rejection:?}",
            self.signer_id
        );
        // Submit signature result to miners to observe
        if let Err(e) = self
            .stackerdb
            .send_message_with_retry(block_rejection.into())
        {
            warn!(
                "Signer #{}: Failed to send block rejection submission to stacker-db: {e:?}",
                self.signer_id
            );
        }
    }

    /// Send any operation results across the provided channel
    fn send_operation_results(
        &mut self,
        res: Sender<Vec<OperationResult>>,
        operation_results: Vec<OperationResult>,
    ) {
        let nmb_results = operation_results.len();
        match res.send(operation_results) {
            Ok(_) => {
                debug!(
                    "Signer #{}: Successfully sent {} operation result(s)",
                    self.signer_id, nmb_results
                )
            }
            Err(e) => {
                warn!(
                    "Signer #{}: Failed to send {nmb_results} operation results: {e:?}",
                    self.signer_id
                );
            }
        }
    }

    /// Sending all provided packets through stackerdb with a retry
    fn send_outbound_messages(&mut self, outbound_messages: Vec<Packet>) {
        debug!(
            "Signer #{}: Sending {} messages to other stacker-db instances.",
            self.signer_id,
            outbound_messages.len()
        );
        for msg in outbound_messages {
            let ack = self.stackerdb.send_message_with_retry(msg.into());
            if let Ok(ack) = ack {
                debug!("Signer #{}: send outbound ACK: {ack:?}", self.signer_id);
            } else {
                warn!(
                    "Signer #{}: Failed to send message to stacker-db instance: {ack:?}",
                    self.signer_id
                );
            }
        }
    }

    /// Update the DKG for the provided signer info, triggering it if required
    pub fn update_dkg(&mut self, stacks_client: &StacksClient) -> Result<(), ClientError> {
        let reward_cycle = self.reward_cycle;
        self.approved_aggregate_public_key =
            stacks_client.get_approved_aggregate_key(reward_cycle)?;
        if self.approved_aggregate_public_key.is_some() {
            // TODO: this will never work as is. We need to have stored our party shares on the side etc for this particular aggregate key.
            // Need to update state to store the necessary info, check against it to see if we have participated in the winning round and
            // then overwrite our value accordingly. Otherwise, we will be locked out of the round and should not participate.
            self.coordinator
                .set_aggregate_public_key(self.approved_aggregate_public_key);
            // We have an approved aggregate public key. Do nothing further
            debug!(
                "Signer #{}: Have updated DKG value to {:?}.",
                self.signer_id, self.approved_aggregate_public_key
            );
            return Ok(());
        };
        let coordinator_id = self.coordinator_selector.get_coordinator().0;
        if self.signer_id == coordinator_id && self.state == State::Idle {
            debug!(
                "Signer #{}: Checking if old vote transaction exists in StackerDB...",
                self.signer_id
            );
            // Have I already voted and have a pending transaction? Check stackerdb for the same round number and reward cycle vote transaction
            // Only get the account nonce of THIS signer as we only care about our own votes, not other signer votes
            let signer_address = stacks_client.get_signer_address();
            let account_nonces = self.get_account_nonces(stacks_client, &[*signer_address]);
            let old_transactions = self.get_signer_transactions(&account_nonces).map_err(|e| {
                warn!("Signer #{}: Failed to get old signer transactions: {e:?}. May trigger DKG unnecessarily", self.signer_id);
            }).unwrap_or_default();
            // Check if we have an existing vote transaction for the same round and reward cycle
            for transaction in old_transactions.iter() {
                let params =
                    NakamotoSigners::parse_vote_for_aggregate_public_key(transaction).unwrap_or_else(|| panic!("BUG: Signer #{}: Received an invalid {SIGNERS_VOTING_FUNCTION_NAME} transaction in an already filtered list: {transaction:?}", self.signer_id));
                if Some(params.aggregate_key) == self.coordinator.aggregate_public_key
                    && params.voting_round == self.coordinator.current_dkg_id
                    && reward_cycle == self.reward_cycle
                {
                    debug!("Signer #{}: Not triggering a DKG round. Already have a pending vote transaction.", self.signer_id;
                        "txid" => %transaction.txid(),
                        "aggregate_key" => %params.aggregate_key,
                        "voting_round" => params.voting_round
                    );
                    return Ok(());
                }
            }
            if stacks_client
                .get_vote_for_aggregate_public_key(
                    self.coordinator.current_dkg_id,
                    self.reward_cycle,
                    *stacks_client.get_signer_address(),
                )?
                .is_some()
            {
                // TODO Check if the vote failed and we need to retrigger the DKG round not just if we have already voted...
                // TODO need logic to trigger another DKG round if a certain amount of time passes and we still have no confirmed DKG vote
                debug!("Signer #{}: Not triggering a DKG round. Already voted and we may need to wait for more votes to arrive.", self.signer_id);
                return Ok(());
            }
            if self.commands.front() != Some(&Command::Dkg) {
                info!("Signer #{} is the current coordinator for {reward_cycle} and must trigger DKG. Queuing DKG command...", self.signer_id);
                self.commands.push_front(Command::Dkg);
            }
        }
        Ok(())
    }

    /// Process the event
    pub fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        event: Option<&SignerEvent>,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    ) -> Result<(), ClientError> {
        debug!("Signer #{}: Processing event: {event:?}", self.signer_id);
        match event {
            Some(SignerEvent::BlockValidationResponse(block_validate_response)) => {
                debug!(
                    "Signer #{}: Received a block proposal result from the stacks node...",
                    self.signer_id
                );
                self.handle_block_validate_response(stacks_client, block_validate_response, res)
            }
            Some(SignerEvent::SignerMessages(signer_set, messages)) => {
                if *signer_set != self.stackerdb.get_signer_set() {
                    debug!("Signer #{}: Received a signer message for a reward cycle that does not belong to this signer. Ignoring...", self.signer_id);
                    return Ok(());
                }
                debug!(
                    "Signer #{}: Received {} messages from the other signers...",
                    self.signer_id,
                    messages.len()
                );
                self.handle_signer_messages(stacks_client, res, messages);
            }
            Some(SignerEvent::ProposedBlocks(blocks)) => {
                if current_reward_cycle != self.reward_cycle {
                    // There is not point in processing blocks if we are not the current reward cycle (we can never actually contribute to signing these blocks)
                    debug!("Signer #{}: Received a proposed block, but this signer's reward cycle ({}) is not the current one ({}). Ignoring...", self.signer_id, self.reward_cycle, current_reward_cycle);
                    return Ok(());
                }
                debug!(
                    "Signer #{}: Received {} block proposals from the miners...",
                    self.signer_id,
                    blocks.len()
                );
                self.handle_proposed_blocks(stacks_client, blocks);
            }
            Some(SignerEvent::StatusCheck) => {
                debug!("Signer #{}: Received a status check event.", self.signer_id)
            }
            None => {
                // No event. Do nothing.
                debug!("Signer #{}: No event received", self.signer_id)
            }
        }
        Ok(())
    }
}
