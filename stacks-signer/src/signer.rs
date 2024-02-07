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

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::boot::SIGNERS_VOTING_NAME;
use blockstack_lib::chainstate::stacks::{StacksTransaction, TransactionPayload};
use blockstack_lib::net::api::postblock_proposal::BlockValidateResponse;
use blockstack_lib::util_lib::boot::boot_code_id;
use hashbrown::{HashMap, HashSet};
use libsigner::{BlockRejection, BlockResponse, RejectCode, SignerEvent, SignerMessage};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::StacksAddress;
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
use wsts::state_machine::{OperationResult, PublicKeys, SignError};
use wsts::v2;

use crate::client::{
    retry_with_exponential_backoff, ClientError, EpochId, StackerDB, StacksClient,
    VOTE_FUNCTION_NAME,
};
use crate::config::Config;

/// The info needed from the stacks node to configure a signer
#[derive(Debug, Clone)]
pub struct StacksNodeInfo {
    /// The signer set for this runloop
    pub signer_set: u32,
    /// The index into the signers list of this signer's key (may be different from signer_id)
    pub signer_slot_id: u32,
    /// The signer ID assigned to this signer
    pub signer_id: u32,
    /// The reward cycle of the configuration
    pub reward_cycle: u64,
    /// The signer ids to wsts pubilc keys mapping
    pub signer_public_keys: HashMap<u32, Point>,
    /// The signer to key ids mapping
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
    /// The signer addresses
    pub signer_addresses: HashSet<StacksAddress>,
    /// The public keys for the reward cycle
    pub public_keys: PublicKeys,
}

/// Additional Info about a proposed block
pub struct BlockInfo {
    /// The block we are considering
    block: NakamotoBlock,
    /// Our vote on the block if we have one yet
    vote: Option<Vec<u8>>,
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
    /// The signer is executing a DKG round
    Dkg,
    /// The signer is executing a signing round
    Sign,
    /// The Signer has exceeded its tenure
    TenureExceeded,
}

/// The stacks signer for the rewrad cycle
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
    /// The stacks client
    pub stacks_client: StacksClient,
    /// Whether the signer is a mainnet signer or not
    pub is_mainnet: bool,
    /// The signer id
    pub signer_id: u32,
    /// The addresses of other signers to compare our transactions against
    pub signer_addresses: HashSet<StacksAddress>,
    /// The reward cycle this signer belongs to
    pub reward_cycle: u64,
}

impl Signer {
    /// Create a new stacks signer
    pub fn new(config: &Config, stacks_node_info: StacksNodeInfo) -> Self {
        let stackerdb = StackerDB::new_with_config(config, &stacks_node_info);
        let stacks_client = StacksClient::from(config);

        let num_signers = u32::try_from(stacks_node_info.public_keys.signers.len())
            .expect("FATAL: Too many registered signers to fit in a u32");
        let num_keys = u32::try_from(stacks_node_info.public_keys.key_ids.len())
            .expect("FATAL: Too many key ids to fit in a u32");
        let threshold = num_keys * 7 / 10;
        let dkg_threshold = num_keys * 9 / 10;
        // signer uses a Vec<u32> for its key_ids, but coordinator uses a HashSet for each signer since it needs to do lots of lookups
        let signer_key_ids: Vec<u32> = stacks_node_info
            .public_keys
            .key_ids
            .keys()
            .cloned()
            .collect();

        let coordinator_config = CoordinatorConfig {
            threshold,
            dkg_threshold,
            num_signers,
            num_keys,
            message_private_key: config.ecdsa_private_key,
            dkg_public_timeout: config.dkg_public_timeout,
            dkg_private_timeout: config.dkg_private_timeout,
            dkg_end_timeout: config.dkg_end_timeout,
            nonce_timeout: config.nonce_timeout,
            sign_timeout: config.sign_timeout,
            signer_key_ids: stacks_node_info.signer_key_ids.clone(),
            signer_public_keys: stacks_node_info.signer_public_keys.clone(),
        };

        let coordinator = FireCoordinator::new(coordinator_config);
        let signing_round = WSTSSigner::new(
            threshold,
            num_signers,
            num_keys,
            stacks_node_info.signer_id,
            signer_key_ids,
            config.ecdsa_private_key,
            stacks_node_info.public_keys,
        );
        Self {
            coordinator,
            signing_round,
            state: State::Idle,
            blocks: HashMap::new(),
            commands: VecDeque::new(),
            stackerdb,
            stacks_client,
            is_mainnet: config.network.is_mainnet(), // will be updated on .initialize()
            signer_id: stacks_node_info.signer_id,
            signer_addresses: stacks_node_info.signer_addresses,
            reward_cycle: stacks_node_info.reward_cycle,
        }
    }

    /// Execute the given command and update state accordingly
    /// Returns true when it is successfully executed, else false
    fn execute_command(&mut self, command: &Command) -> bool {
        let (coordinator_id, _) = self
            .stacks_client
            .calculate_coordinator(&self.signing_round.public_keys);
        if coordinator_id != self.signer_id {
            warn!(
                "Signer #{}: Not the coordinator. Ignoring command {:?}.",
                self.signer_id, command,
            );
            return false;
        }
        match command {
            Command::Dkg => {
                info!("Signer #{}: Starting DKG", self.signer_id);
                match self.coordinator.start_dkg_round() {
                    Ok(msg) => {
                        let ack = self.stackerdb.send_message_with_retry(msg.into());
                        debug!("Signer #{}: ACK: {:?}", self.signer_id, ack);
                        self.state = State::Dkg;
                        true
                    }
                    Err(e) => {
                        error!("Failed to start DKG: {:?}", e);
                        warn!("Resetting coordinator's internal state.");
                        self.coordinator.reset();
                        false
                    }
                }
            }
            Command::Sign {
                block,
                is_taproot,
                merkle_root,
            } => {
                let signer_signature_hash = block.header.signer_signature_hash();
                let block_info = self
                    .blocks
                    .entry(signer_signature_hash)
                    .or_insert_with(|| BlockInfo::new(block.clone()));
                if block_info.signed_over {
                    debug!("Signer #{}: Received a sign command for a block we are already signing over. Ignore it.", self.signer_id);
                    return false;
                }
                info!("Signer #{}: Signing block: {:?}", self.signer_id, block);
                match self.coordinator.start_signing_round(
                    &block.serialize_to_vec(),
                    *is_taproot,
                    *merkle_root,
                ) {
                    Ok(msg) => {
                        let ack = self.stackerdb.send_message_with_retry(msg.into());
                        debug!("Signer #{}: ACK: {:?}", self.signer_id, ack);
                        self.state = State::Sign;
                        block_info.signed_over = true;
                        true
                    }
                    Err(e) => {
                        error!(
                            "Signer #{}: Failed to start signing message: {:?}",
                            self.signer_id, e
                        );
                        warn!(
                            "Signer #{}: Resetting coordinator's internal state.",
                            self.signer_id
                        );
                        self.coordinator.reset();
                        false
                    }
                }
            }
        }
    }

    /// Attempt to process the next command in the queue, and update state accordingly
    pub fn process_next_command(&mut self) {
        match self.state {
            State::Idle => {
                if let Some(command) = self.commands.pop_front() {
                    while !self.execute_command(&command) {
                        warn!(
                            "Signer #{}: Failed to execute command. Retrying...",
                            self.signer_id
                        );
                    }
                } else {
                    debug!(
                        "Signer #{}: Nothing to process. Waiting for command...",
                        self.signer_id
                    );
                }
            }
            State::Dkg | State::Sign => {
                // We cannot execute the next command until the current one is finished...
                // Do nothing...
                debug!(
                    "Signer #{}: Waiting for {:?} operation to finish",
                    self.signer_id, self.state
                );
            }
            State::TenureExceeded => {
                // We have exceeded our tenure. Do nothing...
                debug!(
                    "Signer #{}: Waiting to clean up signer for reward cycle {}",
                    self.signer_id, self.reward_cycle
                );
            }
        }
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(
        &mut self,
        block_validate_response: &BlockValidateResponse,
        res: Sender<Vec<OperationResult>>,
    ) {
        let block_info = match block_validate_response {
            BlockValidateResponse::Ok(block_validate_ok) => {
                let signer_signature_hash = block_validate_ok.signer_signature_hash;
                // For mutability reasons, we need to take the block_info out of the map and add it back after processing
                let Some(mut block_info) = self.blocks.remove(&signer_signature_hash) else {
                    // We have not seen this block before. Why are we getting a response for it?
                    debug!("Received a block validate response for a block we have not seen before. Ignoring...");
                    return;
                };
                let is_valid = self.verify_transactions(&block_info.block);
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
                        "Signer #{}: Failed to send block rejection to stacker-db: {:?}",
                        self.signer_id, e
                    );
                }
                block_info
            }
        };

        if let Some(mut nonce_request) = block_info.nonce_request.take() {
            debug!("Received a block validate response from the stacks node for a block we already received a nonce request for. Responding to the nonce request...");
            // We have received validation from the stacks node. Determine our vote and update the request message
            Self::determine_vote(self.signer_id, block_info, &mut nonce_request);
            // Send the nonce request through with our vote
            let packet = Packet {
                msg: Message::NonceRequest(nonce_request),
                sig: vec![],
            };
            self.handle_packets(res, &[packet]);
        } else {
            let (coordinator_id, _) = self
                .stacks_client
                .calculate_coordinator(&self.signing_round.public_keys);
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
        res: Sender<Vec<OperationResult>>,
        messages: &[SignerMessage],
    ) {
        let (coordinator_id, coordinator_public_key) = self
            .stacks_client
            .calculate_coordinator(&self.signing_round.public_keys);
        debug!(
            "Signer #{}: coordinator is signer #{} public key {}",
            self.signer_id, coordinator_id, &coordinator_public_key
        );
        let packets: Vec<Packet> = messages
            .iter()
            .filter_map(|msg| match msg {
                SignerMessage::BlockResponse(_) | SignerMessage::Transactions(_) => None,
                SignerMessage::Packet(packet) => {
                    self.verify_packet(packet.clone(), &coordinator_public_key)
                }
            })
            .collect();
        self.handle_packets(res, &packets);
    }

    /// Handle proposed blocks submitted by the miners to stackerdb
    fn handle_proposed_blocks(&mut self, blocks: &[NakamotoBlock]) {
        for block in blocks {
            // Store the block in our cache
            self.blocks.insert(
                block.header.signer_signature_hash(),
                BlockInfo::new(block.clone()),
            );
            // Submit the block for validation
            self.stacks_client
                .submit_block_for_validation(block.clone())
                .unwrap_or_else(|e| {
                    warn!("Failed to submit block for validation: {:?}", e);
                });
        }
    }

    /// Process inbound packets as both a signer and a coordinator
    /// Will send outbound packets and operation results as appropriate
    fn handle_packets(&mut self, res: Sender<Vec<OperationResult>>, packets: &[Packet]) {
        let signer_outbound_messages = self
            .signing_round
            .process_inbound_messages(packets)
            .unwrap_or_else(|e| {
                error!("Failed to process inbound messages as a signer: {e}");
                vec![]
            });

        // Next process the message as the coordinator
        let (coordinator_outbound_messages, operation_results) = self
            .coordinator
            .process_inbound_messages(packets)
            .unwrap_or_else(|e| {
                error!("Failed to process inbound messages as a coordinator: {e}");
                (vec![], vec![])
            });

        if !operation_results.is_empty() {
            // We have finished a signing or DKG round, either successfully or due to error.
            // Regardless of the why, update our state to Idle as we should not expect the operation to continue.
            self.state = State::Idle;
            self.process_operation_results(&operation_results);
            self.send_operation_results(res, operation_results);
        }
        self.send_outbound_messages(signer_outbound_messages);
        self.send_outbound_messages(coordinator_outbound_messages);
    }

    /// Validate a signature share request, updating its message where appropriate.
    /// If the request is for a block it has already agreed to sign, it will overwrite the message with the agreed upon value
    /// Returns whether the request is valid or not.
    fn validate_signature_share_request(&self, request: &mut SignatureShareRequest) -> bool {
        let message_len = request.message.len();
        // Note that the message must always be either 32 bytes (the block hash) or 33 bytes (block hash + b'n')
        let hash_bytes = if message_len == 33 && request.message[32] == b'n' {
            // Pop off the 'n' byte from the block hash
            &request.message[..32]
        } else if message_len == 32 {
            // This is the block hash
            &request.message
        } else {
            // We will only sign across block hashes or block hashes + b'n' byte
            debug!("Signer #{}: Received a signature share request for an unknown message stream. Reject it.", self.signer_id);
            return false;
        };

        let Some(hash) = Sha512Trunc256Sum::from_bytes(hash_bytes) else {
            // We will only sign across valid block hashes
            debug!("Signer #{}: Received a signature share request for an invalid block hash. Reject it.", self.signer_id);
            return false;
        };
        match self.blocks.get(&hash).map(|block_info| &block_info.vote) {
            Some(Some(vote)) => {
                // Overwrite with our agreed upon value in case another message won majority or the coordinator is trying to cheat...
                debug!(
                    "Signer #{}: set vote for {} to {:?}",
                    self.signer_id, &hash, &vote
                );
                request.message = vote.clone();
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
    fn validate_nonce_request(&mut self, nonce_request: &mut NonceRequest) -> bool {
        let Some(block) = read_next::<NakamotoBlock, _>(&mut &nonce_request.message[..]).ok()
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
            // Store the block in our cache
            self.blocks.insert(
                signer_signature_hash,
                BlockInfo::new_with_request(block.clone(), nonce_request.clone()),
            );
            self.stacks_client
                .submit_block_for_validation(block)
                .unwrap_or_else(|e| {
                    warn!(
                        "Signer #{}: Failed to submit block for validation: {:?}",
                        self.signer_id, e
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
    fn verify_transactions(&mut self, block: &NakamotoBlock) -> bool {
        if let Ok(expected_transactions) = self.get_expected_transactions() {
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
                        "Signer #{}: Failed to send block rejection to stacker-db: {:?}",
                        self.signer_id, e
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
                    "Signer #{}: Failed to send block submission to stacker-db: {:?}",
                    self.signer_id, e
                );
            }
            false
        }
    }

    /// Get the transactions we expect to see in the next block
    fn get_expected_transactions(&mut self) -> Result<Vec<StacksTransaction>, ClientError> {
        let signer_ids = self
            .signing_round
            .public_keys
            .signers
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let transactions = self
                .stackerdb
                .get_signer_transactions_with_retry(&signer_ids)?.into_iter().filter_map(|transaction| {
                    // Filter out transactions that have already been confirmed (can happen if a signer did not update stacker db since the last block was processed)
                    let origin_address = transaction.origin_address();
                    let origin_nonce = transaction.get_origin_nonce();
                    let Ok(account_nonce) = self.stacks_client.get_account_nonce(&origin_address) else {
                        warn!("Signer #{}: Unable to get account for address: {origin_address}. Ignoring it for this block...", self.signer_id);
                        return None;
                    };
                    let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, self.is_mainnet);
                    match &transaction.payload {
                        TransactionPayload::ContractCall(payload) => {
                            if payload.contract_identifier() != vote_contract_id || payload.function_name != VOTE_FUNCTION_NAME.into() {
                                // This is not a special cased transaction. We don't care if its in the next block
                                debug!("Signer #{}: Received an unrecognized transaction. Ignoring it.", self.signer_id;
                                    "origin_address" => origin_address.to_string(),
                                    "orign_nonce" => origin_nonce,
                                    "txid" => transaction.txid().to_string(),
                                    "contract_id" => payload.contract_identifier().to_string(),
                                    "function_name" => payload.function_name.to_string(),
                                );
                                return None;
                            }
                        }
                        _ => {
                            // This is not a special cased transaction.
                            debug!("Signer #{}: Received an unrecognized transaction. Ignoring it.", self.signer_id;
                            "origin_address" => origin_address.to_string(),
                            "orign_nonce" => origin_nonce,
                            "txid" => transaction.txid().to_string(),
                            "payload" => format!("{:?}", transaction.payload),
                        );
                            return None;
                        }
                    }
                    if !self.signer_addresses.contains(&origin_address) || origin_nonce < account_nonce {
                        debug!("Signer #{}: Received a transaction from either an unrecognized address or with an invalid nonce. Ignoring it.", self.signer_id;
                            "txid" => transaction.txid().to_string(),
                            "origin_address" => origin_address.to_string(),
                            "origin_nonce" => origin_nonce,
                            "account_nonce" => account_nonce,
                        );
                        return None;
                    }
                    debug!("Signer #{}: Expect transaction {} ({:?})", self.signer_id, transaction.txid(), &transaction);
                    Some(transaction)
                }).collect();
        Ok(transactions)
    }

    /// Determine the vote for a block and update the block info and nonce request accordingly
    fn determine_vote(
        signer_id: u32,
        block_info: &mut BlockInfo,
        nonce_request: &mut NonceRequest,
    ) {
        let mut vote_bytes = block_info.block.header.signer_signature_hash().0.to_vec();
        // Validate the block contents
        if !block_info.valid.unwrap_or(false) {
            // We don't like this block. Update the request to be across its hash with a byte indicating a vote no.
            debug!(
                "Signer #{}: Updating the request with a block hash with a vote no.",
                signer_id
            );
            vote_bytes.push(b'n');
        } else {
            debug!("Signer #{}: The block passed validation. Update the request with the signature hash.", signer_id);
        }

        // Cache our vote
        block_info.vote = Some(vote_bytes.clone());
        nonce_request.message = vote_bytes;
    }

    /// Verify a chunk is a valid wsts packet. Returns the packet if it is valid, else None.
    /// NOTE: The packet will be updated if the signer wishes to respond to NonceRequest
    /// and SignatureShareRequests with a different message than what the coordinator originally sent.
    /// This is done to prevent a malicious coordinator from sending a different message than what was
    /// agreed upon and to support the case where the signer wishes to reject a block by voting no
    fn verify_packet(
        &mut self,
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
                    if !self.validate_nonce_request(request) {
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
                "Signer #{}: Failed to verify wsts packet with {}: {:?}",
                self.signer_id, coordinator_public_key, &packet
            );
            None
        }
    }

    /// Processes the operation results, broadcasting block acceptance or rejection messages
    /// and DKG vote results accordingly
    fn process_operation_results(&mut self, operation_results: &[OperationResult]) {
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
                OperationResult::Dkg(point) => {
                    // Broadcast via traditional methods to the stacks node if we are pre nakamoto or we cannot determine our Epoch
                    let epoch = self
                        .stacks_client
                        .get_node_epoch()
                        .unwrap_or(EpochId::UnsupportedEpoch);
                    let new_transaction = match epoch {
                        EpochId::UnsupportedEpoch => {
                            debug!("Signer #{}: Received a DKG result, but are in an unsupported epoch. Do not broadcast the result.", self.signer_id);
                            continue;
                        }
                        EpochId::Epoch25 => {
                            debug!("Signer #{}: Received a DKG result, but are in epoch 2.5. Broadcast the transaction to the mempool.", self.signer_id);
                            match retry_with_exponential_backoff(|| {
                                self.stacks_client
                                    .cast_vote_for_aggregate_public_key(
                                        self.reward_cycle,
                                        self.stackerdb.get_signer_slot_id(),
                                        *point,
                                    )
                                    .map_err(backoff::Error::transient)
                            }) {
                                Ok(transaction) => {
                                    debug!("Signer #{}: Successfully cast aggregate public key vote: {:?}",
                                    self.signer_id,
                                        transaction.txid()
                                    );
                                    transaction
                                }
                                Err(e) => {
                                    warn!("Signer #{}: Failed to cast aggregate public key vote: {:?}", self.signer_id, e);
                                    continue;
                                }
                            }
                        }
                        EpochId::Epoch30 => {
                            debug!("Signer #{}: Received a DKG result, but are in epoch 3. Broadcast the transaction to stackerDB.", self.signer_id);
                            match retry_with_exponential_backoff(|| {
                                self.stacks_client
                                    .build_vote_for_aggregate_public_key(
                                        self.reward_cycle,
                                        self.stackerdb.get_signer_slot_id(),
                                        *point,
                                    )
                                    .map_err(backoff::Error::transient)
                            }) {
                                Ok(transaction) => transaction,
                                Err(e) => {
                                    warn!("Signer #{}: Failed to build a cast aggregate public key vote transaction: {:?}", self.signer_id, e);
                                    continue;
                                }
                            }
                        }
                    };
                    let old_transactions = self
                        .stackerdb
                        .get_signer_transactions_with_retry(&[self.signer_id])
                        .map_err(|e| {
                            error!("Failed to get old transactions from stackerdb: {:?}", e);
                        })
                        .unwrap_or_default();
                    // Filter out our old transactions that are no longer valid
                    let mut new_transactions: Vec<_> = old_transactions.into_iter().filter_map(|transaction|  {
                        let origin_address = transaction.origin_address();
                        let origin_nonce = transaction.get_origin_nonce();
                        let Ok(account_nonce) = retry_with_exponential_backoff(|| self.stacks_client.get_account_nonce(&origin_address).map_err(backoff::Error::transient)) else {
                            warn!("Signer #{}: Unable to get account for address: {origin_address}. Removing {} from our stored transactions.", self.signer_id, transaction.txid());
                            return None;
                        };
                        if origin_nonce < account_nonce {
                            debug!("Signer #{}: Transaction {} has an outdated nonce. Removing it from our stored transactions.", self.signer_id, transaction.txid());
                            return None;
                        }
                        Some(transaction)
                    }).collect();
                    info!("Signer #{}: Writing DKG vote transaction {} to stackerdb for other signers and the miner to observe.", new_transaction.txid(), self.signer_id);
                    new_transactions.push(new_transaction);
                    let signer_message = SignerMessage::Transactions(new_transactions);
                    if let Err(e) = self.stackerdb.send_message_with_retry(signer_message) {
                        warn!(
                            "Signer #{}: Failed to update transactions in stacker-db: {:?}",
                            self.signer_id, e
                        );
                    }
                }
                OperationResult::SignError(e) => {
                    self.process_sign_error(e);
                }
                OperationResult::DkgError(e) => {
                    warn!("Signer #{}: Received a DKG error: {:?}", self.signer_id, e);
                }
            }
        }
    }

    /// Process a signature from a signing round by deserializing the signature and
    /// broadcasting an appropriate Reject or Approval message to stackerdb
    fn process_signature(&mut self, signature: &Signature) {
        // Deserialize the signature result and broadcast an appropriate Reject or Approval message to stackerdb
        let Some(aggregate_public_key) = &self.coordinator.get_aggregate_public_key() else {
            debug!(
                "Signer #{}: No aggregate public key set. Cannot validate signature...",
                self.signer_id
            );
            return;
        };
        let message = self.coordinator.get_message();
        // This jankiness is because a coordinator could have signed a rejection we need to find the underlying block hash
        let signer_signature_hash_bytes = if message.len() > 32 {
            &message[..32]
        } else {
            &message
        };
        let Some(signer_signature_hash) =
            Sha512Trunc256Sum::from_bytes(signer_signature_hash_bytes)
        else {
            debug!("Signer #{}: Received a signature result for a signature over a non-block. Nothing to broadcast.", self.signer_id);
            return;
        };

        // TODO: proper garbage collection...This is currently our only cleanup of blocks
        self.blocks.remove(&signer_signature_hash);

        // This signature is no longer valid. Do not broadcast it.
        if !signature.verify(aggregate_public_key, &message) {
            warn!("Signer #{}: Received an invalid signature result across the block. Do not broadcast it.", self.signer_id);
            // TODO: should we reinsert it and trigger a sign round across the block again?
            return;
        }

        let block_submission = if message == signer_signature_hash.0.to_vec() {
            // we agreed to sign the block hash. Return an approval message
            BlockResponse::accepted(signer_signature_hash, signature.clone()).into()
        } else {
            // We signed a rejection message. Return a rejection message
            BlockResponse::rejected(signer_signature_hash, signature.clone()).into()
        };

        // Submit signature result to miners to observe
        debug!(
            "Signer #{}: submit block response {:?}",
            self.signer_id, &block_submission
        );
        if let Err(e) = self.stackerdb.send_message_with_retry(block_submission) {
            warn!(
                "Signer #{}: Failed to send block submission to stacker-db: {:?}",
                self.signer_id, e
            );
        }
    }

    /// Process a sign error from a signing round, broadcasting a rejection message to stackerdb accordingly
    fn process_sign_error(&mut self, e: &SignError) {
        warn!(
            "Signer #{}: Received a signature error: {:?}",
            self.signer_id, e
        );
        match e {
            SignError::NonceTimeout(_valid_signers, _malicious_signers) => {
                //TODO: report these malicious signers
                debug!(
                    "Signer #{}: Received a nonce timeout error.",
                    self.signer_id
                );
            }
            SignError::InsufficientSigners(malicious_signers) => {
                debug!(
                    "Signer #{}: Received a insufficient signers error.",
                    self.signer_id
                );
                let message = self.coordinator.get_message();
                let block = read_next::<NakamotoBlock, _>(&mut &message[..]).ok().unwrap_or({
                        // This is not a block so maybe its across its hash
                        // This jankiness is because a coordinator could have signed a rejection we need to find the underlying block hash
                        let signer_signature_hash_bytes = if message.len() > 32 {
                            &message[..32]
                        } else {
                            &message
                        };
                        let Some(signer_signature_hash) = Sha512Trunc256Sum::from_bytes(signer_signature_hash_bytes) else {
                            debug!("Signer #{}: Received a signature result for a signature over a non-block. Nothing to broadcast.", self.signer_id);
                            return;
                        };
                        let Some(block_info) = self.blocks.remove(&signer_signature_hash) else {
                            debug!("Signer #{}: Received a signature result for a block we have not seen before. Ignoring...", self.signer_id);
                            return;
                        };
                        block_info.block
                    });
                // We don't have enough signers to sign the block. Broadcast a rejection
                let block_rejection = BlockRejection::new(
                    block.header.signer_signature_hash(),
                    RejectCode::InsufficientSigners(malicious_signers.clone()),
                );
                debug!(
                    "Signer #{}: Insufficient signers for block; send rejection {:?}",
                    self.signer_id, &block_rejection
                );
                // Submit signature result to miners to observe
                if let Err(e) = self
                    .stackerdb
                    .send_message_with_retry(block_rejection.into())
                {
                    warn!(
                        "Signer #{}: Failed to send block submission to stacker-db: {:?}",
                        self.signer_id, e
                    );
                }
            }
            SignError::Aggregator(e) => {
                warn!(
                    "Signer #{}: Received an aggregator error: {:?}",
                    self.signer_id, e
                );
            }
        }
        // TODO: should reattempt to sign the block here or should we just broadcast a rejection or do nothing and wait for the signers to propose a new block?
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
                    "Signer #{}: Failed to send {} operation results: {:?}",
                    self.signer_id, nmb_results, e
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
                debug!("Signer #{}: send outbound ACK: {:?}", self.signer_id, ack);
            } else {
                warn!(
                    "Signer #{}: Failed to send message to stacker-db instance: {:?}",
                    self.signer_id, ack
                );
            }
        }
    }

    /// Update the DKG for the provided signer info, triggering it if required
    pub fn update_dkg(&mut self) -> Result<(), ClientError> {
        let reward_cycle = self.reward_cycle;
        let aggregate_public_key = self.stacks_client.get_aggregate_public_key(reward_cycle)?;
        let in_vote_window = self
            .stacks_client
            .reward_cycle_in_vote_window(reward_cycle)?;
        self.coordinator
            .set_aggregate_public_key(aggregate_public_key);
        let coordinator_id = self
            .stacks_client
            .calculate_coordinator(&self.signing_round.public_keys)
            .0;
        // TODO: should we attempt to vote anyway if out of window? what if we didn't successfully run DKG in prepare phase?
        if in_vote_window
            && aggregate_public_key.is_none()
            && self.signer_id == coordinator_id
            && self.coordinator.state == CoordinatorState::Idle
        {
            info!("Signer is the coordinator and is in the prepare phase for reward cycle {reward_cycle}. Triggering a DKG round...");
            self.commands.push_back(Command::Dkg);
        } else {
            debug!("Not updating dkg";
                "in_vote_window" => in_vote_window,
                "aggregate_public_key" => aggregate_public_key.is_some(),
                "signer_id" => self.signer_id,
                "coordinator_id" => coordinator_id,
            );
        }
        Ok(())
    }

    /// Process the event
    pub fn process_event(
        &mut self,
        event: Option<&SignerEvent>,
        res: Sender<Vec<OperationResult>>,
    ) -> Result<(), ClientError> {
        let current_reward_cycle = retry_with_exponential_backoff(|| {
            self.stacks_client
                .get_current_reward_cycle()
                .map_err(backoff::Error::transient)
        })?;
        if current_reward_cycle > self.reward_cycle {
            // We have advanced past our tenure as a signer. Nothing to do.
            info!(
                "Signer #{}: Signer has passed its tenure. Ignoring event...",
                self.signer_id
            );
            self.state = State::TenureExceeded;
            return Ok(());
        }
        debug!("Signer #{}: Processing event: {:?}", self.signer_id, event);
        match event {
            Some(SignerEvent::BlockValidationResponse(block_validate_response)) => {
                debug!(
                    "Signer #{}: Received a block proposal result from the stacks node...",
                    self.signer_id
                );
                self.handle_block_validate_response(block_validate_response, res)
            }
            Some(SignerEvent::SignerMessages(reward_index, messages)) => {
                if *reward_index != self.stackerdb.get_signer_set() {
                    debug!("Signer #{}: Received a signer message for a reward cycle that do not belong to this signer. Ignoring...", self.signer_id);
                    return Ok(());
                }
                debug!(
                    "Signer #{}: Received {} messages from the other signers...",
                    self.signer_id,
                    messages.len()
                );
                self.handle_signer_messages(res, messages);
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
                self.handle_proposed_blocks(blocks);
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

#[cfg(test)]
mod tests {
    use std::thread::spawn;

    use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use blockstack_lib::chainstate::stacks::boot::SIGNERS_VOTING_NAME;
    use blockstack_lib::chainstate::stacks::{ThresholdSignature, TransactionVersion};
    use blockstack_lib::util_lib::boot::{boot_code_addr, boot_code_id};
    use libsigner::SignerMessage;
    use serial_test::serial;
    use stacks_common::bitvec::BitVec;
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::types::chainstate::{
        ConsensusHash, StacksBlockId, StacksPrivateKey, TrieHash,
    };
    use stacks_common::util::hash::{MerkleTree, Sha512Trunc256Sum};
    use stacks_common::util::secp256k1::MessageSignature;
    use wsts::curve::ecdsa;

    use crate::client::tests::{
        generate_stacks_node_info, mock_server_from_config, write_response,
    };
    use crate::client::{StacksClient, VOTE_FUNCTION_NAME};
    use crate::config::Config;
    use crate::signer::{BlockInfo, Signer};

    #[test]
    #[serial]
    fn get_expected_transactions_should_filter_invalid_transactions() {
        // Create a runloop of a valid signer
        let config = Config::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let (stacks_node_info, _ordered_addresses) = generate_stacks_node_info(
            5,
            20,
            Some(
                ecdsa::PublicKey::new(&config.ecdsa_private_key)
                    .expect("Failed to create public key."),
            ),
        );
        let mut signer = Signer::new(&config, stacks_node_info);

        let signer_private_key = config.stacks_private_key;
        let non_signer_private_key = StacksPrivateKey::new();

        let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, signer.is_mainnet);
        let contract_addr = vote_contract_id.issuer.into();
        let contract_name = vote_contract_id.name.clone();
        // Create a valid transaction signed by the signer private key coresponding to the slot into which it is being inserted (signer id 0)
        let valid_tx = StacksClient::build_signed_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            VOTE_FUNCTION_NAME.into(),
            &[],
            &signer_private_key,
            TransactionVersion::Testnet,
            config.network.to_chain_id(),
            1,
            10,
        )
        .unwrap();
        let invalid_tx_bad_signer = StacksClient::build_signed_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            VOTE_FUNCTION_NAME.into(),
            &[],
            &non_signer_private_key,
            TransactionVersion::Testnet,
            config.network.to_chain_id(),
            0,
            10,
        )
        .unwrap();
        let invalid_tx_outdated_nonce = StacksClient::build_signed_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            VOTE_FUNCTION_NAME.into(),
            &[],
            &signer_private_key,
            TransactionVersion::Testnet,
            config.network.to_chain_id(),
            0,
            5,
        )
        .unwrap();
        let bad_contract_addr = boot_code_addr(true);
        let invalid_tx_bad_contract_addr = StacksClient::build_signed_contract_call_transaction(
            &bad_contract_addr,
            contract_name.clone(),
            VOTE_FUNCTION_NAME.into(),
            &[],
            &signer_private_key,
            TransactionVersion::Testnet,
            config.network.to_chain_id(),
            1,
            5,
        )
        .unwrap();

        let invalid_tx_bad_contract_name = StacksClient::build_signed_contract_call_transaction(
            &contract_addr,
            "wrong".into(),
            VOTE_FUNCTION_NAME.into(),
            &[],
            &signer_private_key,
            TransactionVersion::Testnet,
            config.network.to_chain_id(),
            1,
            5,
        )
        .unwrap();

        let invalid_tx_bad_function = StacksClient::build_signed_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            "fake-function".into(),
            &[],
            &signer_private_key,
            TransactionVersion::Testnet,
            config.network.to_chain_id(),
            1,
            5,
        )
        .unwrap();

        let transactions = vec![
            valid_tx.clone(),
            invalid_tx_outdated_nonce,
            invalid_tx_bad_signer,
            invalid_tx_bad_contract_addr,
            invalid_tx_bad_contract_name,
            invalid_tx_bad_function,
        ];
        let num_transactions = transactions.len();

        let h = spawn(move || signer.get_expected_transactions().unwrap());

        // Simulate the response to the request for transactions
        let signer_message = SignerMessage::Transactions(transactions);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        for _ in 0..num_transactions {
            let nonce_response = b"HTTP/1.1 200 OK\n\n{\"nonce\":1,\"balance\":\"0x00000000000000000000000000000000\",\"locked\":\"0x00000000000000000000000000000000\",\"unlock_height\":0}";
            let mock_server = mock_server_from_config(&config);
            write_response(mock_server, nonce_response);
        }

        let filtered_txs = h.join().unwrap();
        assert_eq!(filtered_txs, vec![valid_tx]);
    }

    #[test]
    #[serial]
    fn verify_transactions_valid() {
        let config = Config::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let (stacks_node_info, _ordered_addresses) = generate_stacks_node_info(
            5,
            20,
            Some(
                ecdsa::PublicKey::new(&config.ecdsa_private_key)
                    .expect("Failed to create public key."),
            ),
        );
        let mut signer = Signer::new(&config, stacks_node_info);

        let signer_private_key = config.stacks_private_key;
        let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, signer.is_mainnet);
        let contract_addr = vote_contract_id.issuer.into();
        let contract_name = vote_contract_id.name.clone();
        // Create a valid transaction signed by the signer private key coresponding to the slot into which it is being inserted (signer id 0)
        let valid_tx = StacksClient::build_signed_contract_call_transaction(
            &contract_addr,
            contract_name.clone(),
            VOTE_FUNCTION_NAME.into(),
            &[],
            &signer_private_key,
            TransactionVersion::Testnet,
            config.network.to_chain_id(),
            1,
            10,
        )
        .unwrap();

        // Create a block
        let header = NakamotoBlockHeader {
            version: 1,
            chain_length: 2,
            burn_spent: 3,
            consensus_hash: ConsensusHash([0x04; 20]),
            parent_block_id: StacksBlockId([0x05; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
            state_index_root: TrieHash([0x07; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: ThresholdSignature::empty(),
            signer_bitvec: BitVec::zeros(1).unwrap(),
        };
        let mut block = NakamotoBlock {
            header,
            txs: vec![valid_tx.clone()],
        };
        let tx_merkle_root = {
            let txid_vecs = block
                .txs
                .iter()
                .map(|tx| tx.txid().as_bytes().to_vec())
                .collect();

            MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
        };
        block.header.tx_merkle_root = tx_merkle_root;

        // Ensure this is a block the signer has seen already
        signer.blocks.insert(
            block.header.signer_signature_hash(),
            BlockInfo::new(block.clone()),
        );

        let h = spawn(move || signer.verify_transactions(&block));

        // Simulate the response to the request for transactions with the expected transaction
        let signer_message = SignerMessage::Transactions(vec![valid_tx]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let nonce_response = b"HTTP/1.1 200 OK\n\n{\"nonce\":1,\"balance\":\"0x00000000000000000000000000000000\",\"locked\":\"0x00000000000000000000000000000000\",\"unlock_height\":0}";
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, nonce_response);

        let valid = h.join().unwrap();
        assert!(valid);
    }
}
