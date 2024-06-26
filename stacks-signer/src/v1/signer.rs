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
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Instant;

use blockstack_lib::chainstate::burn::ConsensusHashExtensions;
use blockstack_lib::chainstate::nakamoto::signer_set::NakamotoSigners;
use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockVote};
use blockstack_lib::chainstate::stacks::boot::SIGNERS_VOTING_FUNCTION_NAME;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::net::api::postblock_proposal::BlockValidateResponse;
use blockstack_lib::util_lib::db::Error as DBError;
use hashbrown::HashSet;
use libsigner::v1::messages::{
    BlockRejection, BlockResponse, MessageSlotID, RejectCode, SignerMessage,
};
use libsigner::{BlockProposal, SignerEvent};
use rand_core::OsRng;
use serde_derive::{Deserialize, Serialize};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::{ConsensusHash, StacksAddress};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::{debug, error, info, warn};
use wsts::common::Signature;
use wsts::curve::keys::PublicKey;
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;
use wsts::net::{Message, NonceRequest, Packet, SignatureShareRequest};
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{
    Config as CoordinatorConfig, Coordinator, State as CoordinatorState,
};
use wsts::state_machine::signer::Signer as SignerStateMachine;
use wsts::state_machine::{OperationResult, SignError};
use wsts::traits::Signer as _;
use wsts::v2;

use crate::client::{ClientError, SignerSlotID, StackerDB, StacksClient};
use crate::config::SignerConfig;
use crate::runloop::{RunLoopCommand, SignerCommand};
use crate::v1::coordinator::CoordinatorSelector;
use crate::v1::signerdb::SignerDb;
use crate::Signer as SignerTrait;

/// Additional Info about a proposed block
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BlockInfo {
    /// The block we are considering
    pub block: NakamotoBlock,
    /// The burn block height at which the block was proposed
    pub burn_block_height: u64,
    /// The reward cycle the block belongs to
    pub reward_cycle: u64,
    /// Our vote on the block if we have one yet
    pub vote: Option<NakamotoBlockVote>,
    /// Whether the block contents are valid
    valid: Option<bool>,
    /// The associated packet nonce request if we have one
    nonce_request: Option<NonceRequest>,
    /// Whether this block is already being signed over
    pub signed_over: bool,
}

impl From<BlockProposal> for BlockInfo {
    fn from(value: BlockProposal) -> Self {
        Self {
            block: value.block,
            burn_block_height: value.burn_height,
            reward_cycle: value.reward_cycle,
            vote: None,
            valid: None,
            nonce_request: None,
            signed_over: false,
        }
    }
}
impl BlockInfo {
    /// Create a new BlockInfo with an associated nonce request packet
    pub fn new_with_request(block_proposal: BlockProposal, nonce_request: NonceRequest) -> Self {
        let mut block_info = BlockInfo::from(block_proposal);
        block_info.nonce_request = Some(nonce_request);
        block_info.signed_over = true;
        block_info
    }

    /// Return the block's signer signature hash
    pub fn signer_signature_hash(&self) -> Sha512Trunc256Sum {
        self.block.header.signer_signature_hash()
    }
}

/// The specific operations that a signer can perform
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Operation {
    /// A DKG operation
    Dkg,
    /// A Sign operation
    Sign,
}

/// The Signer state
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum State {
    /// The signer is uninitialized and should read stackerdb to restore state
    Uninitialized,
    /// The signer is idle, waiting for messages and commands
    Idle,
    /// The signer is executing a DKG or Sign round
    OperationInProgress(Operation),
}

/// The stacks signer registered for the reward cycle
#[derive(Debug)]
pub struct Signer {
    /// The coordinator for inbound messages for a specific reward cycle
    pub coordinator: FireCoordinator<v2::Aggregator>,
    /// The signing round used to sign messages for a specific reward cycle
    pub state_machine: SignerStateMachine<v2::Signer>,
    /// the state of the signer
    pub state: State,
    /// Received Commands that need to be processed
    pub commands: VecDeque<SignerCommand>,
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
    /// The default tx fee in uSTX to use when the epoch is pre Nakamoto (Epoch 3.0).
    pub tx_fee_ustx: u64,
    /// If estimating the tx fee, the max tx fee in uSTX to use when the epoch is pre Nakamoto (Epoch 3.0)
    /// If None, will not cap the fee.
    pub max_tx_fee_ustx: Option<u64>,
    /// The coordinator info for the signer
    pub coordinator_selector: CoordinatorSelector,
    /// The approved key registered to the contract
    pub approved_aggregate_public_key: Option<Point>,
    /// The current active miner's key (if we know it!)
    pub miner_key: Option<PublicKey>,
    /// Signer DB path
    pub db_path: PathBuf,
    /// SignerDB for state management
    pub signer_db: SignerDb,
}

impl std::fmt::Display for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cycle #{} Signer #{}(C:{})",
            self.reward_cycle,
            self.signer_id,
            self.coordinator_selector.get_coordinator().0,
        )
    }
}

impl SignerTrait<SignerMessage> for Signer {
    /// Create a new signer from the given configuration
    fn new(config: SignerConfig) -> Self {
        Self::from(config)
    }
    /// Refresh the next signer data from the given configuration data
    fn update_next_signer_data(&mut self, new_signer_config: &SignerConfig) {
        self.next_signer_addresses = new_signer_config
            .signer_entries
            .signer_ids
            .keys()
            .copied()
            .collect();
        self.next_signer_slot_ids = new_signer_config.signer_slot_ids.clone();
    }
    /// Return the reward cycle of the signer
    fn reward_cycle(&self) -> u64 {
        self.reward_cycle
    }

    /// Process the event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        event: Option<&SignerEvent<SignerMessage>>,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    ) {
        let event_parity = match event {
            Some(SignerEvent::BlockValidationResponse(_)) => Some(current_reward_cycle % 2),
            // Block proposal events do have reward cycles, but each proposal has its own cycle,
            //  and the vec could be heterogenous, so, don't differentiate.
            Some(SignerEvent::MinerMessages(..))
            | Some(SignerEvent::NewBurnBlock(_))
            | Some(SignerEvent::StatusCheck)
            | None => None,
            Some(SignerEvent::SignerMessages(msg_parity, ..)) => Some(u64::from(*msg_parity) % 2),
        };
        let other_signer_parity = (self.reward_cycle + 1) % 2;
        if event_parity == Some(other_signer_parity) {
            return;
        }
        if self.approved_aggregate_public_key.is_none() {
            if let Err(e) = self.refresh_dkg(stacks_client, res.clone(), current_reward_cycle) {
                error!("{self}: failed to refresh DKG: {e}");
            }
        }
        self.refresh_coordinator();
        if self.approved_aggregate_public_key.is_none() {
            if let Err(e) = self.refresh_dkg(stacks_client, res.clone(), current_reward_cycle) {
                error!("{self}: failed to refresh DKG: {e}");
            }
        }
        self.refresh_coordinator();
        debug!("{self}: Processing event: {event:?}");
        match event {
            Some(SignerEvent::BlockValidationResponse(block_validate_response)) => {
                debug!("{self}: Received a block proposal result from the stacks node...");
                self.handle_block_validate_response(
                    stacks_client,
                    block_validate_response,
                    res,
                    current_reward_cycle,
                )
            }
            Some(SignerEvent::SignerMessages(signer_set, messages)) => {
                if *signer_set != self.stackerdb.get_signer_set() {
                    debug!("{self}: Received a signer message for a reward cycle that does not belong to this signer. Ignoring...");
                    return;
                }
                debug!(
                    "{self}: Received {} messages from the other signers...",
                    messages.len()
                );
                self.handle_signer_messages(stacks_client, res, messages, current_reward_cycle);
            }
            Some(SignerEvent::MinerMessages(messages, miner_key)) => {
                let miner_key = PublicKey::try_from(miner_key.to_bytes_compressed().as_slice())
                    .expect("FATAL: could not convert from StacksPublicKey to PublicKey");
                self.miner_key = Some(miner_key);
                if current_reward_cycle != self.reward_cycle {
                    // There is not point in processing blocks if we are not the current reward cycle (we can never actually contribute to signing these blocks)
                    debug!("{self}: Received a proposed block, but this signer's reward cycle is not the current one ({current_reward_cycle}). Ignoring...");
                    return;
                }
                debug!(
                    "{self}: Received {} messages from the miner",
                    messages.len();
                    "miner_key" => ?miner_key,
                );
                self.handle_signer_messages(stacks_client, res, messages, current_reward_cycle);
            }
            Some(SignerEvent::StatusCheck) => {
                debug!("{self}: Received a status check event.")
            }
            Some(SignerEvent::NewBurnBlock(height)) => {
                debug!("{self}: Receved a new burn block event for block height {height}")
            }
            None => {
                // No event. Do nothing.
                debug!("{self}: No event received")
            }
        }
    }

    fn process_command(
        &mut self,
        stacks_client: &StacksClient,
        current_reward_cycle: u64,
        command: Option<RunLoopCommand>,
    ) {
        if let Some(command) = command {
            let reward_cycle = command.reward_cycle;
            if self.reward_cycle != reward_cycle {
                warn!(
                    "{self}: not registered for reward cycle {reward_cycle}. Ignoring command: {command:?}"
                );
            } else {
                info!(
                    "{self}: Queuing an external runloop command ({:?}): {command:?}",
                    self.state_machine.public_keys.signers.get(&self.signer_id)
                );
                self.commands.push_back(command.command);
            }
        }
        self.process_next_command(stacks_client, current_reward_cycle);
    }
}

impl Signer {
    /// Attempt to process the next command in the queue, and update state accordingly
    fn process_next_command(&mut self, stacks_client: &StacksClient, current_reward_cycle: u64) {
        match &self.state {
            State::Uninitialized => {
                // We cannot process any commands until we have restored our state
                warn!("{self}: Cannot process commands until state is restored. Waiting...");
            }
            State::Idle => {
                let Some(command) = self.commands.front() else {
                    debug!("{self}: Nothing to process. Waiting for command...");
                    return;
                };
                let coordinator_id = if matches!(command, SignerCommand::Dkg) {
                    // We cannot execute a DKG command if we are not the coordinator
                    Some(self.get_coordinator_dkg().0)
                } else {
                    self.get_coordinator_sign(current_reward_cycle).0
                };
                if coordinator_id != Some(self.signer_id) {
                    debug!(
                                "{self}: Coordinator is {coordinator_id:?}. Will not process any commands...",
                            );
                    return;
                }
                let command = self
                    .commands
                    .pop_front()
                    .expect("BUG: Already asserted that the command queue was not empty");
                self.execute_command(stacks_client, &command);
            }
            State::OperationInProgress(op) => {
                // We cannot execute the next command until the current one is finished...
                debug!(
                    "{self}: Waiting for {op:?} operation to finish. Coordinator state = {:?}",
                    self.coordinator.state
                );
            }
        }
    }
    /// Return the current coordinator.
    /// If the current reward cycle is the active reward cycle, this is the miner,
    /// so the first element of the tuple will be None (because the miner does not have a signer index).
    /// Otherwise, the coordinator is the signer with the index returned by the coordinator selector.
    fn get_coordinator_sign(&self, current_reward_cycle: u64) -> (Option<u32>, PublicKey) {
        if self.reward_cycle == current_reward_cycle {
            let Some(ref cur_miner) = self.miner_key else {
                error!(
                    "Signer #{}: Could not lookup current miner while in active reward cycle",
                    self.signer_id
                );
                let selected = self.coordinator_selector.get_coordinator();
                return (Some(selected.0), selected.1);
            };
            // coordinator is the current miner.
            (None, *cur_miner)
        } else {
            let selected = self.coordinator_selector.get_coordinator();
            (Some(selected.0), selected.1)
        }
    }

    /// Get the current coordinator for executing DKG
    /// This will always use the coordinator selector to determine the coordinator
    fn get_coordinator_dkg(&self) -> (u32, PublicKey) {
        self.coordinator_selector.get_coordinator()
    }

    /// Read stackerdb messages in case the signer was started late or restarted and missed incoming DKG messages
    pub fn read_dkg_stackerdb_messages(
        &mut self,
        stacks_client: &StacksClient,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    ) -> Result<(), ClientError> {
        if self.state != State::Uninitialized {
            // We should only read stackerdb if we are uninitialized
            return Ok(());
        }
        let ordered_packets = self
            .stackerdb
            .get_dkg_packets(&self.signer_slot_ids)?
            .iter()
            .filter_map(|packet| {
                let coordinator_pubkey = if Self::is_dkg_message(&packet.msg) {
                    self.get_coordinator_dkg().1
                } else {
                    debug!(
                        "{self}: Received a non-DKG message in the DKG message queue. Ignoring it."
                    );
                    return None;
                };
                self.verify_packet(stacks_client, packet.clone(), &coordinator_pubkey)
            })
            .collect::<Vec<_>>();
        // We successfully read stackerdb so we are no longer uninitialized
        self.state = State::Idle;
        debug!(
            "{self}: Processing {} DKG messages from stackerdb: {ordered_packets:?}",
            ordered_packets.len()
        );
        self.handle_packets(stacks_client, res, &ordered_packets, current_reward_cycle);
        Ok(())
    }
}

impl From<SignerConfig> for Signer {
    fn from(signer_config: SignerConfig) -> Self {
        let mut stackerdb = StackerDB::from(&signer_config);

        let num_signers = signer_config
            .signer_entries
            .count_signers()
            .expect("FATAL: Too many registered signers to fit in a u32");
        let num_keys = signer_config
            .signer_entries
            .count_keys()
            .expect("FATAL: Too many key ids to fit in a u32");
        let threshold = signer_config
            .signer_entries
            .get_signing_threshold()
            .expect("FATAL: Too many key ids to fit in a u32");
        let dkg_threshold = signer_config
            .signer_entries
            .get_dkg_threshold()
            .expect("FATAL: Too many key ids to fit in a u32");

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
            signer_key_ids: signer_config.signer_entries.coordinator_key_ids,
            signer_public_keys: signer_config.signer_entries.signer_public_keys,
        };

        let coordinator = FireCoordinator::new(coordinator_config);
        let coordinator_selector =
            CoordinatorSelector::from(signer_config.signer_entries.public_keys.clone());

        debug!(
            "Reward cycle #{} Signer #{}: initial coordinator is signer {}",
            signer_config.reward_cycle,
            signer_config.signer_id,
            coordinator_selector.get_coordinator().0
        );
        let signer_db =
            SignerDb::new(&signer_config.db_path).expect("Failed to connect to signer Db");

        let mut state_machine = SignerStateMachine::new(
            threshold,
            num_signers,
            num_keys,
            signer_config.signer_id,
            signer_config.key_ids,
            signer_config.ecdsa_private_key,
            signer_config.signer_entries.public_keys,
        );

        if let Some(state) = load_encrypted_signer_state(
            &mut stackerdb,
            signer_config.signer_slot_id,
            &state_machine.network_private_key,
        ).or_else(|err| {
                warn!("Failed to load encrypted signer state from StackerDB, falling back to SignerDB: {err}");
                load_encrypted_signer_state(
                    &signer_db,
                    signer_config.reward_cycle,
                    &state_machine.network_private_key)
            }).expect("Failed to load encrypted signer state from both StackerDB and SignerDB") {
            state_machine.signer = state;
        };

        Self {
            coordinator,
            state_machine,
            state: State::Uninitialized,
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
            max_tx_fee_ustx: signer_config.max_tx_fee_ustx,
            coordinator_selector,
            approved_aggregate_public_key: None,
            miner_key: None,
            db_path: signer_config.db_path,
            signer_db,
        }
    }
}

impl Signer {
    /// Refresh the coordinator selector
    pub fn refresh_coordinator(&mut self) {
        // TODO: do not use an empty consensus hash
        let pox_consensus_hash = ConsensusHash::empty();
        let old_coordinator_id = self.coordinator_selector.get_coordinator().0;
        let updated_coordinator_id = self
            .coordinator_selector
            .refresh_coordinator(&pox_consensus_hash);
        if old_coordinator_id != updated_coordinator_id {
            debug!(
                "{self}: Coordinator updated. Resetting state to Idle.";
                "old_coordinator_id" => {old_coordinator_id},
                "updated_coordinator_id" => {updated_coordinator_id},
                "pox_consensus_hash" => %pox_consensus_hash
            );
            self.coordinator.state = CoordinatorState::Idle;
            self.state = State::Idle;
        }
    }

    /// Finish an operation and update the coordinator selector accordingly
    fn finish_operation(&mut self) {
        self.state = State::Idle;
        self.coordinator_selector.last_message_time = None;
    }

    /// Update operation
    fn update_operation(&mut self, operation: Operation) {
        self.state = State::OperationInProgress(operation);
        self.coordinator_selector.last_message_time = Some(Instant::now());
    }

    /// Execute the given command and update state accordingly
    fn execute_command(&mut self, stacks_client: &StacksClient, command: &SignerCommand) {
        match command {
            SignerCommand::Dkg => {
                crate::monitoring::increment_commands_processed("dkg");
                if self.approved_aggregate_public_key.is_some() {
                    debug!("Reward cycle #{} Signer #{}: Already have an aggregate key. Ignoring DKG command.", self.reward_cycle, self.signer_id);
                    return;
                }
                let vote_round = match stacks_client.get_last_round(self.reward_cycle) {
                    Ok(last_round) => last_round,
                    Err(e) => {
                        error!("{self}: Unable to perform DKG. Failed to get last round from stacks node: {e:?}");
                        return;
                    }
                };
                // The dkg id will increment internally following "start_dkg_round" so do not increment it here
                self.coordinator.current_dkg_id = vote_round.unwrap_or(0);
                info!(
                    "{self}: Starting DKG vote";
                    "round" => self.coordinator.current_dkg_id.wrapping_add(1),
                    "cycle" => self.reward_cycle,
                );
                match self.coordinator.start_dkg_round() {
                    Ok(msg) => {
                        let ack = self.stackerdb.send_message_with_retry(msg.into());
                        debug!("{self}: ACK: {ack:?}",);
                        self.update_operation(Operation::Dkg);
                    }
                    Err(e) => {
                        error!("{self}: Failed to start DKG: {e:?}",);
                        return;
                    }
                }
                self.update_operation(Operation::Dkg);
            }
            SignerCommand::Sign {
                block_proposal,
                is_taproot,
                merkle_root,
            } => {
                crate::monitoring::increment_commands_processed("sign");
                if self.approved_aggregate_public_key.is_none() {
                    debug!("{self}: Cannot sign a block without an approved aggregate public key. Ignore it.");
                    return;
                }
                let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
                let mut block_info = self
                    .signer_db
                    .block_lookup(self.reward_cycle, &signer_signature_hash)
                    .unwrap_or_else(|_| Some(BlockInfo::from(block_proposal.clone())))
                    .unwrap_or_else(|| BlockInfo::from(block_proposal.clone()));
                if block_info.signed_over {
                    debug!("{self}: Received a sign command for a block we are already signing over. Ignore it.");
                    return;
                }
                info!("{self}: Signing block";
                         "block_consensus_hash" => %block_proposal.block.header.consensus_hash,
                         "block_height" => block_proposal.block.header.chain_length,
                         "pre_sign_block_id" => %block_proposal.block.block_id(),
                );
                match self.coordinator.start_signing_round(
                    &block_proposal.serialize_to_vec(),
                    *is_taproot,
                    *merkle_root,
                ) {
                    Ok(msg) => {
                        let ack = self.stackerdb.send_message_with_retry(msg.into());
                        debug!("{self}: ACK: {ack:?}",);
                        block_info.signed_over = true;
                        self.signer_db
                            .insert_block(&block_info)
                            .unwrap_or_else(|e| {
                                error!("{self}: Failed to insert block in DB: {e:?}");
                            });
                        self.update_operation(Operation::Sign);
                    }
                    Err(e) => {
                        error!("{self}: Failed to start signing block: {e:?}",);
                        return;
                    }
                }
                self.update_operation(Operation::Sign);
            }
        }
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(
        &mut self,
        stacks_client: &StacksClient,
        block_validate_response: &BlockValidateResponse,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    ) {
        let mut block_info = match block_validate_response {
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
                let is_valid = self.verify_block_transactions(stacks_client, &block_info.block);
                block_info.valid = Some(is_valid);
                self.signer_db
                    .insert_block(&block_info)
                    .unwrap_or_else(|_| panic!("{self}: Failed to insert block in DB"));
                info!(
                    "{self}: Treating block validation for block {} as valid: {:?}",
                    &block_info.block.block_id(),
                    block_info.valid
                );
                block_info
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
                // Submit a rejection response to the .signers contract for miners
                // to observe so they know to send another block and to prove signers are doing work);
                warn!("{self}: Broadcasting a block rejection due to stacks node validation failure...");
                if let Err(e) = self
                    .stackerdb
                    .send_message_with_retry(block_validate_reject.clone().into())
                {
                    warn!("{self}: Failed to send block rejection to stacker-db: {e:?}",);
                }
                block_info
            }
        };
        if let Some(mut nonce_request) = block_info.nonce_request.take() {
            debug!("{self}: Received a block validate response from the stacks node for a block we already received a nonce request for. Responding to the nonce request...");
            // We have received validation from the stacks node. Determine our vote and update the request message
            self.determine_vote(&mut block_info, &mut nonce_request);
            // Send the nonce request through with our vote
            let packet = Packet {
                msg: Message::NonceRequest(nonce_request),
                sig: vec![],
            };
            self.handle_packets(stacks_client, res, &[packet], current_reward_cycle);
        }
        debug!(
            "{self}: Received a block validate response";
            "block_hash" => block_info.block.header.block_hash(),
            "valid" => block_info.valid,
            "signed_over" => block_info.signed_over,
        );
        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|_| panic!("{self}: Failed to insert block in DB"));
    }

    /// Handle signer messages submitted to signers stackerdb
    fn handle_signer_messages(
        &mut self,
        stacks_client: &StacksClient,
        res: Sender<Vec<OperationResult>>,
        messages: &[SignerMessage],
        current_reward_cycle: u64,
    ) {
        let packets: Vec<Packet> = messages
            .iter()
            .filter_map(|msg| match msg {
                SignerMessage::DkgResults { .. }
                | SignerMessage::BlockResponse(_)
                | SignerMessage::EncryptedSignerState(_)
                | SignerMessage::Transactions(_) => None,
                // TODO: if a signer tries to trigger DKG and we already have one set in the contract, ignore the request.
                SignerMessage::Packet(packet) => {
                    let coordinator_pubkey = if Self::is_dkg_message(&packet.msg) {
                        self.get_coordinator_dkg().1
                    } else {
                        self.get_coordinator_sign(current_reward_cycle).1
                    };
                    self.verify_packet(stacks_client, packet.clone(), &coordinator_pubkey)
                }
            })
            .collect();
        self.handle_packets(stacks_client, res, &packets, current_reward_cycle);
    }

    /// Helper function for determining if the provided message is a DKG specific message
    fn is_dkg_message(msg: &Message) -> bool {
        matches!(
            msg,
            Message::DkgBegin(_)
                | Message::DkgEnd(_)
                | Message::DkgEndBegin(_)
                | Message::DkgPrivateBegin(_)
                | Message::DkgPrivateShares(_)
                | Message::DkgPublicShares(_)
        )
    }

    /// Process inbound packets as both a signer and a coordinator
    /// Will send outbound packets and operation results as appropriate
    fn handle_packets(
        &mut self,
        stacks_client: &StacksClient,
        res: Sender<Vec<OperationResult>>,
        packets: &[Packet],
        current_reward_cycle: u64,
    ) {
        if let Ok(packets_len) = packets.len().try_into() {
            crate::monitoring::increment_inbound_packets(packets_len);
        }
        let signer_outbound_messages = self
            .state_machine
            .process_inbound_messages(packets)
            .unwrap_or_else(|e| {
                error!("{self}: Failed to process inbound messages as a signer: {e:?}",);
                vec![]
            });

        // Next process the message as the coordinator
        let (coordinator_outbound_messages, operation_results) = if self.reward_cycle
            != current_reward_cycle
        {
            self.coordinator
                .process_inbound_messages(packets)
                .unwrap_or_else(|e| {
                    error!("{self}: Failed to process inbound messages as a coordinator: {e:?}");
                    (vec![], vec![])
                })
        } else {
            (vec![], vec![])
        };

        if !operation_results.is_empty() {
            // We have finished a signing or DKG round, either successfully or due to error.
            // Regardless of the why, update our state to Idle as we should not expect the operation to continue.
            self.process_operation_results(stacks_client, &operation_results);
            self.send_operation_results(res, operation_results);
            self.finish_operation();
        } else if !packets.is_empty() {
            // We have received a message. Update our state accordingly
            // Let us be extra explicit in case a new state type gets added to wsts' state machine
            match &self.coordinator.state {
                CoordinatorState::Idle => {}
                CoordinatorState::DkgPublicDistribute
                | CoordinatorState::DkgPublicGather
                | CoordinatorState::DkgPrivateDistribute
                | CoordinatorState::DkgPrivateGather
                | CoordinatorState::DkgEndDistribute
                | CoordinatorState::DkgEndGather => {
                    self.update_operation(Operation::Dkg);
                }
                CoordinatorState::NonceRequest(_, _)
                | CoordinatorState::NonceGather(_, _)
                | CoordinatorState::SigShareRequest(_, _)
                | CoordinatorState::SigShareGather(_, _) => {
                    self.update_operation(Operation::Sign);
                }
            }
        }

        if packets
            .iter()
            .any(|packet| matches!(packet.msg, Message::DkgEnd(_)))
        {
            debug!("{self}: Saving signer state");
            self.save_signer_state()
                .unwrap_or_else(|_| panic!("{self}: Failed to save signer state"));
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
                "{self}: Received a signature share request for an unknown message stream. Reject it.",
            );
            return false;
        };

        match self
            .signer_db
            .block_lookup(self.reward_cycle, &block_vote.signer_signature_hash)
            .unwrap_or_else(|_| panic!("{self}: Failed to connect to DB"))
            .map(|b| b.vote)
        {
            Some(Some(vote)) => {
                // Overwrite with our agreed upon value in case another message won majority or the coordinator is trying to cheat...
                debug!(
                    "{self}: Set vote (rejected = {}) to {vote:?}", block_vote.rejected;
                    "requested_sighash" => %block_vote.signer_signature_hash,
                );
                request.message = vote.serialize_to_vec();
                true
            }
            Some(None) => {
                // We never agreed to sign this block. Reject it.
                // This can happen if the coordinator received enough votes to sign yes
                // or no on a block before we received validation from the stacks node.
                debug!(
                    "{self}: Received a signature share request for a block we never agreed to sign. Ignore it.";
                    "requested_sighash" => %block_vote.signer_signature_hash,
                );
                false
            }
            None => {
                // We will only sign across block hashes or block hashes + b'n' byte for
                // blocks we have seen a Nonce Request for (and subsequent validation)
                // We are missing the context here necessary to make a decision. Reject the block
                debug!(
                    "{self}: Received a signature share request from an unknown block. Reject it.";
                    "requested_sighash" => %block_vote.signer_signature_hash,
                );
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
    ) -> Option<BlockInfo> {
        let Some(block_proposal) =
            BlockProposal::consensus_deserialize(&mut nonce_request.message.as_slice()).ok()
        else {
            // We currently reject anything that is not a valid block proposal
            warn!("{self}: Received a nonce request for an unknown message stream. Reject it.",);
            return None;
        };
        if block_proposal.reward_cycle != self.reward_cycle {
            // We are not signing for this reward cycle. Reject the block
            warn!(
                "{self}: Received a nonce request for a different reward cycle. Reject it.";
                "requested_reward_cycle" => block_proposal.reward_cycle,
            );
            return None;
        }
        // TODO: could add a check to ignore an old burn block height if we know its oudated. Would require us to store the burn block height we last saw on the side.
        let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
        let Some(mut block_info) = self
            .signer_db
            .block_lookup(self.reward_cycle, &signer_signature_hash)
            .expect("Failed to connect to signer DB")
        else {
            debug!(
                "{self}: received a nonce request for a new block. Submit block for validation. ";
                "signer_sighash" => %signer_signature_hash,
            );
            let block_info = BlockInfo::new_with_request(block_proposal, nonce_request.clone());
            stacks_client
                .submit_block_for_validation(block_info.block.clone())
                .unwrap_or_else(|e| {
                    warn!("{self}: Failed to submit block for validation: {e:?}",);
                });
            return Some(block_info);
        };

        if block_info.valid.is_none() {
            // We have not yet received validation from the stacks node. Cache the request and wait for validation
            debug!("{self}: We have yet to receive validation from the stacks node for a nonce request. Cache the nonce request and wait for block validation...");
            block_info.nonce_request = Some(nonce_request.clone());
            return Some(block_info);
        }

        self.determine_vote(&mut block_info, nonce_request);
        Some(block_info)
    }

    /// Verify the transactions in a block are as expected
    fn verify_block_transactions(
        &mut self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
    ) -> bool {
        let next_reward_cycle = self.reward_cycle.wrapping_add(1);
        let approved_aggregate_public_key = stacks_client
            .get_approved_aggregate_key(next_reward_cycle)
            .unwrap_or(None);
        if approved_aggregate_public_key.is_some() {
            // We do not enforce a block contain any transactions except the aggregate votes when it is NOT already set for the upcoming signers' reward cycle
            // Otherwise it is a waste of block space and time to enforce as the desired outcome has been reached.
            debug!("{self}: Already have an aggregate key for the next signer set's reward cycle ({}). Skipping transaction verification...", next_reward_cycle);
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
                        debug!("{self}: expected txid {} is in the block", &tx.txid());
                        Some(tx)
                    } else {
                        debug!("{self}: missing expected txid {}", &tx.txid());
                        None
                    }
                })
                .collect::<Vec<_>>();
            let is_valid = missing_transactions.is_empty();
            if !is_valid {
                debug!("{self}: Broadcasting a block rejection due to missing expected transactions...");
                let block_rejection = BlockRejection::new(
                    block.header.signer_signature_hash(),
                    RejectCode::MissingTransactions(missing_transactions),
                );
                // Submit signature result to miners to observe
                if let Err(e) = self
                    .stackerdb
                    .send_message_with_retry(block_rejection.into())
                {
                    warn!("{self}: Failed to send block rejection to stacker-db: {e:?}",);
                }
            }
            is_valid
        } else {
            // Failed to connect to the stacks node to get transactions. Cannot validate the block. Reject it.
            debug!("{self}: Broadcasting a block rejection due to signer connectivity issues...",);
            let block_rejection = BlockRejection::new(
                block.header.signer_signature_hash(),
                RejectCode::ConnectivityIssues,
            );
            // Submit signature result to miners to observe
            if let Err(e) = self
                .stackerdb
                .send_message_with_retry(block_rejection.into())
            {
                warn!("{self}: Failed to send block submission to stacker-db: {e:?}",);
            }
            false
        }
    }

    /// Get transactions from stackerdb for the given addresses and account nonces, filtering out any malformed transactions
    fn get_signer_transactions(
        &mut self,
        nonces: &std::collections::HashMap<StacksAddress, u64>,
    ) -> Result<Vec<StacksTransaction>, ClientError> {
        let transactions: Vec<_> = self
            .stackerdb
            .get_current_transactions()?
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
            debug!("{self}: No next signers. Skipping transaction retrieval.",);
            return Ok(vec![]);
        }
        // Get all the account nonces for the next signers
        let account_nonces = self.get_account_nonces(stacks_client, &self.next_signer_addresses);
        let transactions: Vec<_> = self
            .stackerdb
            .get_next_transactions(&self.next_signer_slot_ids)?;
        let mut filtered_transactions = std::collections::HashMap::new();
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
    fn determine_vote(&self, block_info: &mut BlockInfo, nonce_request: &mut NonceRequest) {
        let rejected = !block_info.valid.unwrap_or(false);
        if rejected {
            debug!("{self}: Rejecting block {}", block_info.block.block_id());
        } else {
            debug!("{self}: Accepting block {}", block_info.block.block_id());
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
        if packet.verify(&self.state_machine.public_keys, coordinator_public_key) {
            match &mut packet.msg {
                Message::SignatureShareRequest(request) => {
                    if !self.validate_signature_share_request(request) {
                        return None;
                    }
                }
                Message::NonceRequest(request) => {
                    let Some(updated_block_info) =
                        self.validate_nonce_request(stacks_client, request)
                    else {
                        warn!("Failed to validate and parse nonce request");
                        return None;
                    };
                    self.signer_db
                        .insert_block(&updated_block_info)
                        .unwrap_or_else(|_| panic!("{self}: Failed to insert block in DB"));
                    let process_request = updated_block_info.vote.is_some();
                    if !process_request {
                        debug!("Failed to validate nonce request");
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
                "{self}: Failed to verify wsts packet with {}: {packet:?}",
                coordinator_public_key
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
                    crate::monitoring::increment_operation_results("sign");
                    debug!("{self}: Received signature result");
                    self.process_signature(signature);
                }
                OperationResult::SignTaproot(_) => {
                    crate::monitoring::increment_operation_results("sign_taproot");
                    debug!("{self}: Received a signature result for a taproot signature. Nothing to broadcast as we currently sign blocks with a FROST signature.");
                }
                OperationResult::Dkg(aggregate_key) => {
                    crate::monitoring::increment_operation_results("dkg");
                    self.process_dkg(stacks_client, aggregate_key);
                }
                OperationResult::SignError(e) => {
                    crate::monitoring::increment_operation_results("sign_error");
                    warn!("{self}: Received a Sign error: {e:?}");
                    self.process_sign_error(e);
                }
                OperationResult::DkgError(e) => {
                    crate::monitoring::increment_operation_results("dkg_error");
                    warn!("{self}: Received a DKG error: {e:?}");
                    // TODO: process these errors and track malicious signers to report
                }
            }
        }
    }

    /// Process a dkg result by broadcasting a vote to the stacks node
    fn process_dkg(&mut self, stacks_client: &StacksClient, dkg_public_key: &Point) {
        let mut dkg_results_bytes = vec![];
        debug!(
            "{self}: Received DKG result. Broadcasting vote to the stacks node...";
            "dkg_public_key" => %dkg_public_key
        );
        if let Err(e) = SignerMessage::serialize_dkg_result(
            &mut dkg_results_bytes,
            dkg_public_key,
            self.coordinator.party_polynomials.iter(),
        ) {
            error!("{}: Failed to serialize DKGResults message for StackerDB, will continue operating.", self.signer_id;
                   "error" => %e);
        } else if let Err(e) = self
            .stackerdb
            .send_message_bytes_with_retry(&MessageSlotID::DkgResults, dkg_results_bytes)
        {
            error!("{}: Failed to send DKGResults message to StackerDB, will continue operating.", self.signer_id;
                       "error" => %e);
        }

        // Get our current nonce from the stacks node and compare it against what we have sitting in the stackerdb instance
        let signer_address = stacks_client.get_signer_address();
        // Retreieve ALL account nonces as we may have transactions from other signers in our stackerdb slot that we care about
        let account_nonces = self.get_account_nonces(stacks_client, &self.signer_addresses);
        let account_nonce = account_nonces.get(signer_address).unwrap_or(&0);
        let signer_transactions = self
            .get_signer_transactions(&account_nonces)
            .map_err(|e| {
                error!("{self}: Unable to get signer transactions: {e:?}.");
            })
            .unwrap_or_default();
        // If we have a transaction in the stackerdb slot, we need to increment the nonce hence the +1, else should use the account nonce
        let next_nonce = signer_transactions
            .first()
            .map(|tx| tx.get_origin_nonce().wrapping_add(1))
            .unwrap_or(*account_nonce);
        let epoch = stacks_client
            .get_node_epoch()
            .unwrap_or(StacksEpochId::Epoch24);
        match self.build_dkg_vote(stacks_client, &epoch, next_nonce, *dkg_public_key) {
            Ok(new_transaction) => {
                if let Err(e) = self.broadcast_dkg_vote(
                    stacks_client,
                    epoch,
                    signer_transactions,
                    new_transaction,
                ) {
                    warn!(
                        "{self}: Failed to broadcast DKG public key vote ({dkg_public_key:?}): {e:?}"
                    );
                }
            }
            Err(e) => {
                warn!(
                    "{self}: Failed to build DKG public key vote ({dkg_public_key:?}) transaction: {e:?}."
                );
            }
        }
    }

    /// Build a signed DKG vote transaction
    fn build_dkg_vote(
        &mut self,
        stacks_client: &StacksClient,
        epoch: &StacksEpochId,
        nonce: u64,
        dkg_public_key: Point,
    ) -> Result<StacksTransaction, ClientError> {
        let mut unsigned_tx = stacks_client.build_unsigned_vote_for_aggregate_public_key(
            self.stackerdb.get_signer_slot_id().0,
            self.coordinator.current_dkg_id,
            dkg_public_key,
            self.reward_cycle,
            nonce,
        )?;
        let tx_fee = if epoch < &StacksEpochId::Epoch30 {
            info!("{self}: in pre Epoch 3.0 cycles, must set a transaction fee for the DKG vote.");
            let fee = if let Some(max_fee) = self.max_tx_fee_ustx {
                let estimated_fee = stacks_client
                    .get_medium_estimated_fee_ustx(&unsigned_tx)
                    .map_err(|e| {
                        warn!("{self}: unable to estimate fee for DKG vote transaction: {e:?}.");
                        e
                    })
                    .unwrap_or(self.tx_fee_ustx);
                std::cmp::min(estimated_fee, max_fee)
            } else {
                self.tx_fee_ustx
            };
            debug!("{self}: Using a fee of {fee} uSTX for DKG vote transaction.");
            fee
        } else {
            0
        };
        unsigned_tx.set_tx_fee(tx_fee);
        stacks_client.sign_transaction(unsigned_tx)
    }

    // Get the account nonces for the provided list of signer addresses
    fn get_account_nonces(
        &self,
        stacks_client: &StacksClient,
        signer_addresses: &[StacksAddress],
    ) -> std::collections::HashMap<StacksAddress, u64> {
        let mut account_nonces = std::collections::HashMap::with_capacity(signer_addresses.len());
        for address in signer_addresses {
            let Ok(account_nonce) = stacks_client.get_account_nonce(address) else {
                warn!("{self}: Unable to get account nonce for address: {address}.");
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
                "{self}: Already has an approved aggregate key. Do not broadcast the transaction ({txid:?})."
            );
            return Ok(());
        }
        if epoch >= StacksEpochId::Epoch30 {
            debug!("{self}: Received a DKG result while in epoch 3.0. Broadcast the transaction only to stackerDB.");
        } else if epoch == StacksEpochId::Epoch25 {
            debug!("{self}: Received a DKG result while in epoch 2.5. Broadcast the transaction to the mempool.");
            stacks_client.submit_transaction(&new_transaction)?;
            info!("{self}: Submitted DKG vote transaction ({txid:?}) to the mempool");
        } else {
            debug!("{self}: Received a DKG result, but are in an unsupported epoch. Do not broadcast the transaction ({}).", new_transaction.txid());
            return Ok(());
        }
        // For all Pox-4 epochs onwards, broadcast the results also to stackerDB for other signers/miners to observe
        signer_transactions.push(new_transaction);
        let signer_message = SignerMessage::Transactions(signer_transactions);
        self.stackerdb.send_message_with_retry(signer_message)?;
        crate::monitoring::increment_dkg_votes_submitted();
        info!("{self}: Broadcasted DKG vote transaction ({txid}) to stacker DB");
        Ok(())
    }

    /// Process a signature from a signing round by deserializing the signature and
    /// broadcasting an appropriate Reject or Approval message to stackerdb
    fn process_signature(&mut self, signature: &Signature) {
        // Deserialize the signature result and broadcast an appropriate Reject or Approval message to stackerdb
        let message = self.coordinator.get_message();
        let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &message[..]).ok() else {
            debug!("{self}: Received a signature result for a non-block. Nothing to broadcast.");
            return;
        };

        let block_submission = if block_vote.rejected {
            crate::monitoring::increment_block_responses_sent(false);
            // We signed a rejection message. Return a rejection message
            BlockResponse::rejected(block_vote.signer_signature_hash, signature.clone())
        } else {
            crate::monitoring::increment_block_responses_sent(true);
            // we agreed to sign the block hash. Return an approval message
            BlockResponse::accepted(block_vote.signer_signature_hash, signature.clone())
        };

        // Submit signature result to miners to observe
        info!("{self}: Submit block response: {block_submission}");
        if let Err(e) = self
            .stackerdb
            .send_message_with_retry(block_submission.into())
        {
            warn!("{self}: Failed to send block submission to stacker-db: {e:?}");
        }
    }

    /// Process a sign error from a signing round, broadcasting a rejection message to stackerdb accordingly
    fn process_sign_error(&mut self, e: &SignError) {
        let message = self.coordinator.get_message();
        // We do not sign across blocks, but across their hashes. however, the first sign request is always across the block
        // so we must handle this case first

        let block: NakamotoBlock = read_next(&mut &message[..]).ok().unwrap_or({
            // This is not a block so maybe its across its hash
            let Some(block_vote): Option<NakamotoBlockVote> = read_next(&mut &message[..]).ok()
            else {
                // This is not a block vote either. We cannot process this error
                debug!(
                    "{self}: Received a signature error for a non-block. Nothing to broadcast."
                );
                return;
            };
            let Some(block_info) = self
                .signer_db
                .block_lookup(self.reward_cycle, &block_vote.signer_signature_hash)
                .unwrap_or_else(|_| panic!("{self}: Failed to connect to signer DB"))
            else {
                debug!(
                    "{self}: Received a signature result for a block we have not seen before. Ignoring..."
                );
                return;
            };
            block_info.block
        });
        let block_rejection =
            BlockRejection::new(block.header.signer_signature_hash(), RejectCode::from(e));
        debug!("{self}: Broadcasting block rejection: {block_rejection:?}");
        // Submit signature result to miners to observe
        if let Err(e) = self
            .stackerdb
            .send_message_with_retry(block_rejection.into())
        {
            warn!("{self}: Failed to send block rejection submission to stacker-db: {e:?}");
        }
    }

    /// Persist signer state in both SignerDB and StackerDB
    fn save_signer_state(&mut self) -> Result<(), PersistenceError> {
        let rng = &mut OsRng;

        let state = self.state_machine.signer.save();
        let serialized_state = serde_json::to_vec(&state)?;

        let encrypted_state = encrypt(
            &self.state_machine.network_private_key,
            &serialized_state,
            rng,
        )?;

        let signerdb_result = self.save_signer_state_in_signerdb(&encrypted_state);
        let stackerdb_result = self.save_signer_state_in_stackerdb(encrypted_state);

        if let Err(err) = &signerdb_result {
            warn!("{self}: Failed to persist state in SignerDB: {err}");
        }

        if let Err(err) = &stackerdb_result {
            warn!("{self}: Failed to persist state in StackerDB: {err}");

            stackerdb_result
        } else {
            signerdb_result
        }
    }

    /// Persist signer state in SignerDB
    fn save_signer_state_in_signerdb(
        &self,
        encrypted_state: &[u8],
    ) -> Result<(), PersistenceError> {
        self.signer_db
            .insert_encrypted_signer_state(self.reward_cycle, encrypted_state)?;
        Ok(())
    }

    /// Persist signer state in StackerDB
    /// TODO: this is a no-op until the number of signer slots can be expanded
    fn save_signer_state_in_stackerdb(
        &mut self,
        _encrypted_state: Vec<u8>,
    ) -> Result<(), PersistenceError> {
        /*
         * This is a no-op until the number of signer slots can be expanded to 14
         *
        let message = SignerMessage::EncryptedSignerState(encrypted_state);
        self.stackerdb.send_message_with_retry(message)?;
        */
        Ok(())
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
                debug!("{self}: Successfully sent {nmb_results} operation result(s)")
            }
            Err(e) => {
                warn!("{self}: Failed to send {nmb_results} operation results: {e:?}");
            }
        }
    }

    /// Sending all provided packets through stackerdb with a retry
    fn send_outbound_messages(&mut self, outbound_messages: Vec<Packet>) {
        debug!(
            "{self}: Sending {} messages to other stacker-db instances.",
            outbound_messages.len()
        );
        for msg in outbound_messages {
            let ack = self.stackerdb.send_message_with_retry(msg.into());
            if let Ok(ack) = ack {
                debug!("{self}: send outbound ACK: {ack:?}");
            } else {
                warn!("{self}: Failed to send message to stacker-db instance: {ack:?}");
            }
        }
    }

    /// Refresh DKG and queue it if required
    pub fn refresh_dkg(
        &mut self,
        stacks_client: &StacksClient,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    ) -> Result<(), ClientError> {
        // First attempt to retrieve the aggregate key from the contract.
        self.update_approved_aggregate_key(stacks_client)?;
        if self.approved_aggregate_public_key.is_some() {
            return Ok(());
        }
        // Check stackerdb for any missed DKG messages to catch up our state.
        self.read_dkg_stackerdb_messages(stacks_client, res, current_reward_cycle)?;
        // Check if we should still queue DKG
        if !self.should_queue_dkg(stacks_client)? {
            return Ok(());
        }
        // Because there could be a slight delay in reading pending transactions and a key being approved by the contract,
        // check one last time if the approved key was set since we finished the should queue dkg call
        self.update_approved_aggregate_key(stacks_client)?;
        if self.approved_aggregate_public_key.is_some() {
            return Ok(());
        }
        if self.commands.front() != Some(&SignerCommand::Dkg) {
            info!("{self} is the current coordinator and must trigger DKG. Queuing DKG command...");
            self.commands.push_front(SignerCommand::Dkg);
        } else {
            debug!("{self}: DKG command already queued...");
        }
        Ok(())
    }

    /// Overwrites the approved aggregate key to the value in the contract, updating state accordingly
    pub fn update_approved_aggregate_key(
        &mut self,
        stacks_client: &StacksClient,
    ) -> Result<(), ClientError> {
        let old_dkg = self.approved_aggregate_public_key;
        self.approved_aggregate_public_key =
            stacks_client.get_approved_aggregate_key(self.reward_cycle)?;
        if self.approved_aggregate_public_key.is_some() {
            // TODO: this will never work as is. We need to have stored our party shares on the side etc for this particular aggregate key.
            // Need to update state to store the necessary info, check against it to see if we have participated in the winning round and
            // then overwrite our value accordingly. Otherwise, we will be locked out of the round and should not participate.
            let internal_dkg = self.coordinator.aggregate_public_key;
            if internal_dkg != self.approved_aggregate_public_key {
                warn!("{self}: we do not support changing the internal DKG key yet. Expected {internal_dkg:?} got {:?}", self.approved_aggregate_public_key);
            }
            self.coordinator
                .set_aggregate_public_key(self.approved_aggregate_public_key);
            if old_dkg != self.approved_aggregate_public_key {
                warn!(
                    "{self}: updated DKG value from {old_dkg:?} to {:?}.",
                    self.approved_aggregate_public_key
                );
            }
            match self.state {
                State::OperationInProgress(Operation::Dkg) => {
                    debug!(
                        "{self}: DKG has already been set. Aborting DKG operation {}.",
                        self.coordinator.current_dkg_id
                    );
                    self.finish_operation();
                }
                State::Uninitialized => {
                    // If we successfully load the DKG value, we are fully initialized
                    self.state = State::Idle;
                }
                _ => {
                    // do nothing
                }
            }
        }
        Ok(())
    }

    /// Should DKG be queued to the current signer's command queue
    /// This assumes that no key has been approved by the contract yet
    pub fn should_queue_dkg(&mut self, stacks_client: &StacksClient) -> Result<bool, ClientError> {
        if self.state != State::Idle
            || self.signer_id != self.get_coordinator_dkg().0
            || self.commands.front() == Some(&SignerCommand::Dkg)
        {
            // We are not the coordinator, we are in the middle of an operation, or we have already queued DKG. Do not attempt to queue DKG
            return Ok(false);
        }
        let signer_address = stacks_client.get_signer_address();
        let account_nonces = self.get_account_nonces(stacks_client, &[*signer_address]);
        let old_transactions = self.get_signer_transactions(&account_nonces).map_err(|e| {
                warn!("{self}: Failed to get old signer transactions: {e:?}. May trigger DKG unnecessarily");
            }).unwrap_or_default();
        // Check if we have an existing vote transaction for the same round and reward cycle
        for transaction in old_transactions.iter() {
            let params =
                    NakamotoSigners::parse_vote_for_aggregate_public_key(transaction).unwrap_or_else(|| panic!("BUG: {self}: Received an invalid {SIGNERS_VOTING_FUNCTION_NAME} transaction in an already filtered list: {transaction:?}"));
            if Some(params.aggregate_key) == self.coordinator.aggregate_public_key
                && params.voting_round == self.coordinator.current_dkg_id
            {
                debug!("{self}: Not triggering a DKG round. Already have a pending vote transaction.";
                    "txid" => %transaction.txid(),
                    "aggregate_key" => %params.aggregate_key,
                    "voting_round" => params.voting_round
                );
                return Ok(false);
            }
        }
        if let Some(aggregate_key) = stacks_client.get_vote_for_aggregate_public_key(
            self.coordinator.current_dkg_id,
            self.reward_cycle,
            *signer_address,
        )? {
            let Some(round_weight) = stacks_client
                .get_round_vote_weight(self.reward_cycle, self.coordinator.current_dkg_id)?
            else {
                // This only will happen if somehow we registered as a signer and were granted no weight which should not really ever happen.
                error!("{self}: already voted for DKG, but no round vote weight found. We either have no voting power or the contract is corrupted.";
                    "voting_round" => self.coordinator.current_dkg_id,
                    "aggregate_key" => %aggregate_key
                );
                return Ok(false);
            };
            let threshold_weight = stacks_client.get_vote_threshold_weight(self.reward_cycle)?;
            if round_weight < threshold_weight {
                // The threshold weight has not been met yet. We should wait for more votes to arrive.
                // TODO: this should be on a timeout of some kind. We should not wait forever for the threshold to be met.
                // See https://github.com/stacks-network/stacks-core/issues/4568
                debug!("{self}: Not triggering a DKG round. Weight threshold has not been met yet. Waiting for more votes to arrive.";
                    "voting_round" => self.coordinator.current_dkg_id,
                    "aggregate_key" => %aggregate_key,
                    "round_weight" => round_weight,
                    "threshold_weight" => threshold_weight
                );
                return Ok(false);
            }
        } else {
            // Have I already voted, but the vote is still pending in StackerDB? Check stackerdb for the same round number and reward cycle vote transaction
            // Only get the account nonce of THIS signer as we only care about our own votes, not other signer votes
            let account_nonce = stacks_client.get_account_nonce(signer_address).unwrap_or(0);
            let old_transactions = self.stackerdb.get_current_transactions()?;
            // Check if we have an existing vote transaction for the same round and reward cycle
            for transaction in old_transactions.iter() {
                // We should not consider other signer transactions and should ignore invalid transaction versions
                if transaction.origin_address() != *signer_address
                    || transaction.is_mainnet() != self.mainnet
                {
                    continue;
                }
                let Some(params) =
                    NakamotoSigners::parse_vote_for_aggregate_public_key(transaction)
                else {
                    continue;
                };
                let Some(dkg_public_key) = self.coordinator.aggregate_public_key else {
                    break;
                };
                if params.aggregate_key == dkg_public_key
                    && params.voting_round == self.coordinator.current_dkg_id
                    && params.reward_cycle == self.reward_cycle
                {
                    let origin_nonce = transaction.get_origin_nonce();
                    if origin_nonce < account_nonce {
                        // We have already voted, but our vote nonce is outdated. Resubmit vote with updated transaction
                        warn!("{self}: DKG vote submitted with invalid nonce ({origin_nonce} < {account_nonce}). Resubmitting vote.");
                        self.process_dkg(stacks_client, &dkg_public_key);
                    } else {
                        debug!("{self}: Already have a pending DKG vote in StackerDB. Waiting for it to be confirmed.";
                            "txid" => %transaction.txid(),
                            "aggregate_key" => %params.aggregate_key,
                            "voting_round" => params.voting_round,
                            "reward_cycle" => params.reward_cycle,
                            "nonce" => origin_nonce
                        );
                    }
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

fn load_encrypted_signer_state<S: SignerStateStorage>(
    storage: S,
    id: S::IdType,
    private_key: &Scalar,
) -> Result<Option<v2::Signer>, PersistenceError> {
    if let Some(encrypted_state) = storage.get_encrypted_signer_state(id)? {
        let serialized_state = decrypt(private_key, &encrypted_state)?;
        let state = serde_json::from_slice(&serialized_state)
            .expect("Failed to deserialize decryoted state");
        Ok(Some(v2::Signer::load(&state)))
    } else {
        Ok(None)
    }
}

trait SignerStateStorage {
    type IdType;

    fn get_encrypted_signer_state(
        self,
        signer_config: Self::IdType,
    ) -> Result<Option<Vec<u8>>, PersistenceError>;
}

impl SignerStateStorage for &mut StackerDB {
    type IdType = SignerSlotID;

    fn get_encrypted_signer_state(
        self,
        id: Self::IdType,
    ) -> Result<Option<Vec<u8>>, PersistenceError> {
        Ok(self.get_encrypted_signer_state(id)?)
    }
}

impl SignerStateStorage for &SignerDb {
    type IdType = u64;
    fn get_encrypted_signer_state(
        self,
        id: Self::IdType,
    ) -> Result<Option<Vec<u8>>, PersistenceError> {
        Ok(self.get_encrypted_signer_state(id)?)
    }
}

fn encrypt(
    private_key: &Scalar,
    msg: &[u8],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<u8>, EncryptionError> {
    wsts::util::encrypt(derive_encryption_key(private_key).as_bytes(), msg, rng)
        .map_err(|_| EncryptionError::Encrypt)
}

fn decrypt(private_key: &Scalar, encrypted_msg: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    wsts::util::decrypt(derive_encryption_key(private_key).as_bytes(), encrypted_msg)
        .map_err(|_| EncryptionError::Decrypt)
}

fn derive_encryption_key(private_key: &Scalar) -> Sha512Trunc256Sum {
    let mut prefixed_key = "SIGNER_STATE_ENCRYPTION_KEY/".as_bytes().to_vec();
    prefixed_key.extend_from_slice(&private_key.to_bytes());

    Sha512Trunc256Sum::from_data(&prefixed_key)
}

/// Error stemming from a persistence operation
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    /// Encryption error
    #[error("{0}")]
    Encryption(#[from] EncryptionError),
    /// Database error
    #[error("Database operation failed: {0}")]
    DBError(#[from] DBError),
    /// Serialization error
    #[error("JSON serialization failed: {0}")]
    JsonSerializationError(#[from] serde_json::Error),
    /// StackerDB client error
    #[error("StackerDB client error: {0}")]
    StackerDBClientError(#[from] ClientError),
}

/// Error stemming from a persistence operation
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    /// Encryption failed
    #[error("Encryption operation failed")]
    Encrypt,
    /// Decryption failed
    #[error("Encryption operation failed")]
    Decrypt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_messages_should_be_possible_to_decrypt() {
        let msg = "Nobody's gonna know".as_bytes();
        let key = Scalar::random(&mut OsRng);

        let encrypted = encrypt(&key, msg, &mut OsRng).unwrap();

        assert_ne!(encrypted, msg);

        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, msg);
    }
}
