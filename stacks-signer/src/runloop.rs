use std::collections::VecDeque;
use std::sync::mpsc::Sender;
use std::time::Duration;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::boot::MINERS_NAME;
use blockstack_lib::net::api::postblock_proposal::BlockValidateResponse;
use blockstack_lib::net::api::poststackerdbchunk::StackerDBChunksEvent;
use blockstack_lib::util_lib::boot::boot_code_id;
use hashbrown::{HashMap, HashSet};
use libsigner::{SignerEvent, SignerRunLoop};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::{debug, error, info, warn};
use wsts::common::MerkleRoot;
use wsts::curve::ecdsa;
use wsts::net::Packet;
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::coordinator::{Config as CoordinatorConfig, Coordinator};
use wsts::state_machine::signer::Signer;
use wsts::state_machine::{OperationResult, PublicKeys};
use wsts::v2;

use crate::client::{
    retry_with_exponential_backoff, BlockRejection, BlockResponse, ClientError, RejectCode,
    SignerMessage, StackerDB, StacksClient,
};
use crate::config::{Config, Network};

/// Which operation to perform
#[derive(PartialEq, Clone)]
pub enum RunLoopCommand {
    /// Generate a DKG aggregate public key
    Dkg,
    /// Sign a message
    Sign {
        /// The bytes to sign
        message: Vec<u8>,
        /// Whether to make a taproot signature
        is_taproot: bool,
        /// Taproot merkle root
        merkle_root: Option<MerkleRoot>,
    },
}

/// The RunLoop state
#[derive(PartialEq, Debug)]
pub enum State {
    // TODO: Uninitialized should indicate we need to replay events/configure the signer
    /// The runloop signer is uninitialized
    Uninitialized,
    /// The runloop is idle
    Idle,
    /// The runloop is executing a DKG round
    Dkg,
    /// The runloop is executing a signing round
    Sign,
}

/// The runloop for the stacks signer
pub struct RunLoop<C> {
    /// The timeout for events
    pub event_timeout: Duration,
    /// The coordinator for inbound messages
    pub coordinator: C,
    /// The signing round used to sign messages
    // TODO: update this to use frost_signer directly instead of the frost signing round
    // See: https://github.com/stacks-network/stacks-blockchain/issues/3913
    pub signing_round: Signer<v2::Signer>,
    /// The stacks node client
    pub stacks_client: StacksClient,
    /// The stacker db client
    pub stackerdb: StackerDB,
    /// Received Commands that need to be processed
    pub commands: VecDeque<RunLoopCommand>,
    /// The current state
    pub state: State,
    /// Wether mainnet or not
    pub mainnet: bool,
}

impl<C: Coordinator> RunLoop<C> {
    /// Initialize the signer, reading the stacker-db state and setting the aggregate public key
    fn initialize(&mut self) -> Result<(), ClientError> {
        // TODO: update to read stacker db to get state.
        // Check if the aggregate key is set in the pox contract
        if let Some(key) = self.stacks_client.get_aggregate_public_key()? {
            debug!("Aggregate public key is set: {:?}", key);
            self.coordinator.set_aggregate_public_key(Some(key));
        } else {
            debug!("Aggregate public key is not set. Coordinator must trigger DKG...");
            // Update the state to IDLE so we don't needlessy requeue the DKG command.
            let (coordinator_id, _) = calculate_coordinator(&self.signing_round.public_keys);
            if coordinator_id == self.signing_round.signer_id
                && self.commands.front() != Some(&RunLoopCommand::Dkg)
            {
                self.commands.push_front(RunLoopCommand::Dkg);
            }
        }
        self.state = State::Idle;
        Ok(())
    }

    /// Execute the given command and update state accordingly
    /// Returns true when it is successfully executed, else false
    fn execute_command(&mut self, command: &RunLoopCommand) -> bool {
        match command {
            RunLoopCommand::Dkg => {
                info!("Starting DKG");
                match self.coordinator.start_dkg_round() {
                    Ok(msg) => {
                        let ack = self
                            .stackerdb
                            .send_message_with_retry(self.signing_round.signer_id, msg.into());
                        debug!("ACK: {:?}", ack);
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
            RunLoopCommand::Sign {
                message,
                is_taproot,
                merkle_root,
            } => {
                info!("Signing message: {:?}", message);
                match self
                    .coordinator
                    .start_signing_round(message, *is_taproot, *merkle_root)
                {
                    Ok(msg) => {
                        let ack = self
                            .stackerdb
                            .send_message_with_retry(self.signing_round.signer_id, msg.into());
                        debug!("ACK: {:?}", ack);
                        self.state = State::Sign;
                        true
                    }
                    Err(e) => {
                        error!("Failed to start signing message: {:?}", e);
                        warn!("Resetting coordinator's internal state.");
                        self.coordinator.reset();
                        false
                    }
                }
            }
        }
    }

    /// Attempt to process the next command in the queue, and update state accordingly
    fn process_next_command(&mut self) {
        match self.state {
            State::Uninitialized => {
                debug!(
                    "Signer is uninitialized. Waiting for aggregate public key from stacks node..."
                );
            }
            State::Idle => {
                if let Some(command) = self.commands.pop_front() {
                    while !self.execute_command(&command) {
                        warn!("Failed to execute command. Retrying...");
                    }
                } else {
                    debug!("Nothing to process. Waiting for command...");
                }
            }
            State::Dkg | State::Sign => {
                // We cannot execute the next command until the current one is finished...
                // Do nothing...
                debug!("Waiting for operation to finish");
            }
        }
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(&mut self, block_validate_response: BlockValidateResponse) {
        match block_validate_response {
            BlockValidateResponse::Ok(block_validate_ok) => {
                // This is a valid block proposal from the miner. Trigger a signing round for it.
                let (coordinator_id, _) = calculate_coordinator(&self.signing_round.public_keys);
                if coordinator_id == self.signing_round.signer_id {
                    // We are the coordinator. Trigger a signing round for this block
                    self.commands.push_back(RunLoopCommand::Sign {
                        message: block_validate_ok.block.serialize_to_vec(),
                        is_taproot: false,
                        merkle_root: None,
                    });
                }
            }
            BlockValidateResponse::Reject(block_validate_reject) => {
                warn!(
                    "Received a block proposal that was rejected by the stacks node: {:?}",
                    block_validate_reject
                );
                // TODO: submit a rejection response to the .signers contract for miners
                // to observe so they know to ignore it and to prove signers are doing work
                let block_rejection = BlockRejection {
                    block: block_validate_reject.block,
                    reason: block_validate_reject.reason,
                    reason_code: RejectCode::ValidationFailed(block_validate_reject.reason_code),
                };
                let message =
                    SignerMessage::BlockResponse(BlockResponse::Rejected(block_rejection));
                if let Err(e) = self
                    .stackerdb
                    .send_message_with_retry(self.signing_round.signer_id, message)
                {
                    warn!(
                        "Failed to send block rejection response to stacker-db: {:?}",
                        e
                    );
                }
            }
        }
    }

    // Handle the stackerdb chunk event as a signer message
    fn handle_stackerdb_chunk_event_signers(
        &mut self,
        stackerdb_chunk_event: StackerDBChunksEvent,
        res: Sender<Vec<OperationResult>>,
    ) {
        let (_coordinator_id, coordinator_public_key) =
            calculate_coordinator(&self.signing_round.public_keys);

        let inbound_messages: Vec<Packet> = stackerdb_chunk_event
            .modified_slots
            .iter()
            .filter_map(|chunk| {
                // We only care about verified wsts packets. Ignore anything else
                let signer_message = bincode::deserialize::<SignerMessage>(&chunk.data).ok()?;
                let packet = match signer_message {
                    SignerMessage::Packet(packet) => packet,
                    _ => return None, // This is a message for miners to observe. Ignore it.
                };
                if packet.verify(&self.signing_round.public_keys, &coordinator_public_key) {
                    debug!("Verified wsts packet: {:?}", &packet);
                    Some(packet)
                } else {
                    None
                }
            })
            .collect();

        // First process all messages as a signer
        // TODO: deserialize the packet into a block and verify its contents
        // TODO: we need to be able to sign yes or no on a block...this needs to propogate
        // to the singning round/coordinator that we are signing yes or no on a block
        // self.verify_block_transactions(&block);
        let signer_outbound_messages = self
            .signing_round
            .process_inbound_messages(&inbound_messages)
            .unwrap_or_else(|e| {
                error!("Failed to process inbound messages as a signer: {e}");
                vec![]
            });

        // Next process the message as the coordinator
        let (coordinator_outbound_messages, operation_results) = self
            .coordinator
            .process_inbound_messages(&inbound_messages)
            .unwrap_or_else(|e| {
                error!("Failed to process inbound messages as a coordinator: {e}");
                (vec![], vec![])
            });

        self.send_outbound_messages(signer_outbound_messages);
        self.send_outbound_messages(coordinator_outbound_messages);
        self.send_operation_results(res, operation_results);
    }

    // Handle the stackerdb chunk event as a miner message
    fn handle_stackerdb_chunk_event_miners(&mut self, stackerdb_chunk_event: StackerDBChunksEvent) {
        for chunk in &stackerdb_chunk_event.modified_slots {
            let mut ptr = &chunk.data[..];
            let Some(block) = read_next::<NakamotoBlock, _>(&mut ptr).ok() else {
                warn!("Received an unrecognized message type from .miners stacker-db slot id {}: {:?}", chunk.slot_id, ptr);
                continue;
            };

            // Received a block proposal from the miner. Submit it for verification.
            self.stacks_client
                .submit_block_for_validation(block)
                .unwrap_or_else(|e| {
                    warn!("Failed to submit block for validation: {:?}", e);
                });
        }
    }

    /// Helper function to send operation results across the provided channel
    fn send_operation_results(
        &mut self,
        res: Sender<Vec<OperationResult>>,
        operation_results: Vec<OperationResult>,
    ) {
        let nmb_results = operation_results.len();
        if nmb_results > 0 {
            // We finished our command. Update the state
            self.state = State::Idle;
            match res.send(operation_results) {
                Ok(_) => {
                    debug!("Successfully sent {} operation result(s)", nmb_results)
                }
                Err(e) => {
                    warn!("Failed to send operation results: {:?}", e);
                }
            }
        }
    }

    // Helper function for sending packets through stackerdb
    fn send_outbound_messages(&mut self, outbound_messages: Vec<Packet>) {
        debug!(
            "Sending {} messages to other stacker-db instances.",
            outbound_messages.len()
        );
        for msg in outbound_messages {
            let ack = self
                .stackerdb
                .send_message_with_retry(self.signing_round.signer_id, msg.into());
            if let Ok(ack) = ack {
                debug!("ACK: {:?}", ack);
            } else {
                warn!("Failed to send message to stacker-db instance: {:?}", ack);
            }
        }
    }
}

impl From<&Config> for RunLoop<FireCoordinator<v2::Aggregator>> {
    /// Creates new runloop from a config
    fn from(config: &Config) -> Self {
        // TODO: this should be a config option
        // See: https://github.com/stacks-network/stacks-blockchain/issues/3914
        let threshold = ((config.signer_ids_public_keys.key_ids.len() * 7) / 10)
            .try_into()
            .unwrap();
        let dkg_threshold = ((config.signer_ids_public_keys.key_ids.len() * 9) / 10)
            .try_into()
            .unwrap();
        let total_signers = config
            .signer_ids_public_keys
            .signers
            .len()
            .try_into()
            .unwrap();
        let total_keys = config
            .signer_ids_public_keys
            .key_ids
            .len()
            .try_into()
            .unwrap();
        let key_ids = config
            .signer_key_ids
            .get(&config.signer_id)
            .unwrap()
            .iter()
            .map(|i| i - 1) // Signer::new (unlike Signer::from) doesn't do this
            .collect::<Vec<u32>>();
        // signer uses a Vec<u32> for its key_ids, but coordinator uses a HashSet for each signer since it needs to do lots of lookups
        let signer_key_ids = config
            .signer_key_ids
            .iter()
            .map(|(i, ids)| (*i, ids.iter().map(|id| id - 1).collect::<HashSet<u32>>()))
            .collect::<HashMap<u32, HashSet<u32>>>();

        let coordinator_config = CoordinatorConfig {
            threshold,
            dkg_threshold,
            num_signers: total_signers,
            num_keys: total_keys,
            message_private_key: config.message_private_key,
            dkg_public_timeout: config.dkg_public_timeout,
            dkg_end_timeout: config.dkg_end_timeout,
            nonce_timeout: config.nonce_timeout,
            sign_timeout: config.sign_timeout,
            signer_key_ids,
        };
        let coordinator = FireCoordinator::new(coordinator_config);
        let signing_round = Signer::new(
            threshold,
            total_signers,
            total_keys,
            config.signer_id,
            key_ids,
            config.message_private_key,
            config.signer_ids_public_keys.clone(),
        );
        let stacks_client = StacksClient::from(config);
        let stackerdb = StackerDB::from(config);
        RunLoop {
            event_timeout: config.event_timeout,
            coordinator,
            signing_round,
            stacks_client,
            stackerdb,
            commands: VecDeque::new(),
            state: State::Uninitialized,
            mainnet: config.network == Network::Mainnet,
        }
    }
}

impl<C: Coordinator> SignerRunLoop<Vec<OperationResult>, RunLoopCommand> for RunLoop<C> {
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.event_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.event_timeout
    }

    fn run_one_pass(
        &mut self,
        event: Option<SignerEvent>,
        cmd: Option<RunLoopCommand>,
        res: Sender<Vec<OperationResult>>,
    ) -> Option<Vec<OperationResult>> {
        info!(
            "Running one pass for signer ID# {}. Current state: {:?}",
            self.signing_round.signer_id, self.state
        );
        if let Some(command) = cmd {
            self.commands.push_back(command);
        }
        // TODO: This should be called every time as DKG can change at any time...but until we have the node
        // set up to receive cast votes...just do on initialization.
        if self.state == State::Uninitialized {
            let request_fn = || self.initialize().map_err(backoff::Error::transient);
            retry_with_exponential_backoff(request_fn)
                .expect("Failed to connect to initialize due to timeout. Stacks node may be down.");
        }
        // Process any arrived events
        debug!("Processing event: {:?}", event);
        match event {
            Some(SignerEvent::BlockProposal(block_validate_response)) => {
                debug!("Received a block proposal result from the stacks node...");
                self.handle_block_validate_response(block_validate_response)
            }
            Some(SignerEvent::StackerDB(stackerdb_chunk_event)) => {
                if stackerdb_chunk_event.contract_id == *self.stackerdb.signers_contract_id() {
                    debug!("Received a StackerDB event for the .signers contract...");
                    self.handle_stackerdb_chunk_event_signers(stackerdb_chunk_event, res);
                } else if stackerdb_chunk_event.contract_id
                    == boot_code_id(MINERS_NAME, self.mainnet)
                {
                    debug!("Received a StackerDB event for the .miners contract...");
                    self.handle_stackerdb_chunk_event_miners(stackerdb_chunk_event);
                } else {
                    // Ignore non miner or signer messages
                    debug!(
                        "Received a StackerDB event for an unrecognized contract id: {:?}. Ignoring...",
                        stackerdb_chunk_event.contract_id
                    );
                }
            }
            None => {
                // No event. Do nothing.
                debug!("No event received")
            }
        }

        // The process the next command
        // Must be called AFTER processing the event as the state may update to IDLE due to said event.
        self.process_next_command();
        None
    }
}

/// Helper function for determining the coordinator public key given the the public keys
fn calculate_coordinator(public_keys: &PublicKeys) -> (u32, ecdsa::PublicKey) {
    // TODO: do some sort of VRF here to calculate the public key
    // See: https://github.com/stacks-network/stacks-blockchain/issues/3915
    // Mockamato just uses the first signer_id as the coordinator for now
    (0, public_keys.signers.get(&0).cloned().unwrap())
}
