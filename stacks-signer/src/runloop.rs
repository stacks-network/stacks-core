use frost_signer::{
    config::PublicKeys,
    net::Message,
    signing_round::{MessageTypes, Signable, SigningRound},
};
use libsigner::{SignerRunLoop, StackerDBChunksEvent};
use p256k1::ecdsa;
use slog::{slog_info, slog_warn};
use stacks_common::{info, warn};
use std::time::Duration;
use wsts::Point;

use crate::{
    config::Config,
    crypto::{frost::Coordinator as FrostCoordinator, Coordinatable, OperationResult},
    stacks_client::StacksClient,
};

/// Which operation to perform
#[derive(PartialEq)]
pub enum RunLoopCommand {
    /// Continaully poll for commands to execute
    Run,
    /// Generate a DKG aggregate public key
    Dkg,
    /// Generate a DKG aggregate public key and then sign the message
    DkgSign {
        /// The bytes to sign
        message: Vec<u8>,
    },
    /// Sign a message
    Sign {
        /// The bytes to sign
        message: Vec<u8>,
    },
}

/// The RunLoop state
#[derive(PartialEq, Debug)]
pub enum State {
    /// The runloop is idle
    Idle,
    /// The runloop is executing a DKG round
    Dkg,
    /// The runloop has finished a DKG round
    DkgDone,
    /// The runloop is executing a signing round
    Sign,
    /// The runloop has finished a signing round
    SignDone,
    /// The runloop is exiting
    Exit,
    /// The runloop is waiting for messages
    Run,
}

/// The runloop for the stacks signer
pub struct RunLoop<C> {
    /// The timeout for events
    pub event_timeout: Duration,
    /// the coordinator for inbound messages
    pub coordinator: C,
    /// TODO: update this to use frost_signer directly instead of the frost signing round
    pub signing_round: SigningRound,
    /// The stacks client
    pub stacks_client: StacksClient,
    /// The DKG Command to perform
    pub command: RunLoopCommand,
    /// The current state
    pub state: State,
}

impl<C: Coordinatable> RunLoop<C> {
    /// Helper function to check the current state and execute commands accordingly
    fn execute_dkg_sign(&mut self) {
        match (&self.command, &self.state) {
            (RunLoopCommand::Run, State::Idle) => {
                info!("Starting runloop");
                self.state = State::Run;
            }
            (RunLoopCommand::Dkg, State::Idle) => {
                info!("Starting DKG");
                if let Ok(msg) = self.coordinator.start_distributed_key_generation() {
                    let ack = self
                        .stacks_client
                        .send_message(self.signing_round.signer.signer_id, msg);
                    info!("ACK: {:?}", ack);
                }
                self.state = State::Dkg;
            }
            (RunLoopCommand::Dkg, State::DkgDone) => {
                info!("Done DKG");
                self.state = State::Exit;
            }
            (RunLoopCommand::DkgSign { message }, State::Idle) => {
                info!("Starting DKG");
                info!("DKG Required for Message: {:?}", message);
                if let Ok(msg) = self.coordinator.start_distributed_key_generation() {
                    let _ = self
                        .stacks_client
                        .send_message(self.signing_round.signer.signer_id, msg);
                }
                self.state = State::Dkg;
            }
            (RunLoopCommand::DkgSign { message }, State::DkgDone)
            | (RunLoopCommand::Sign { message }, State::Idle) => {
                info!("Signing message");
                if let Ok(msg) = self.coordinator.start_signing_message(message) {
                    let _ = self
                        .stacks_client
                        .send_message(self.signing_round.signer.signer_id, msg);
                }
                self.state = State::Sign
            }
            (RunLoopCommand::DkgSign { message }, State::SignDone)
            | (RunLoopCommand::Sign { message }, State::SignDone) => {
                info!("Done Signing Message: {:?}", message);
                self.state = State::Exit;
            }
            _ => {}
        }
    }

    /// Process the event as both a signer and a coordinator
    fn process_event(
        &mut self,
        event: &StackerDBChunksEvent,
    ) -> (Vec<Message>, Vec<OperationResult>) {
        info!("Processing event: {:?}", event);
        // Determine the current coordinator id and public key for verification
        let (coordinator_id, coordinator_public_key) =
            calculate_coordinator(&self.signing_round.public_keys);
        // Filter out invalid messages
        let inbound_messages: Vec<Message> = event
            .modified_slots
            .iter()
            .filter_map(|chunk| {
                let message = bincode::deserialize::<Message>(&chunk.data).ok()?;
                if verify_msg(
                    &message,
                    &self.signing_round.public_keys,
                    coordinator_public_key,
                ) {
                    Some(message)
                } else {
                    None
                }
            })
            .collect();
        // First process all messages as a signer
        let mut outbound_messages =
            process_inbound_messages(&mut self.signing_round, inbound_messages.clone())
                .unwrap_or_default();
        // If the signer is the coordinator, then next process the message as the coordinator
        let (messages, results) = if self.signing_round.signer.signer_id == coordinator_id {
            self.coordinator
                .process_inbound_messages(inbound_messages)
                .unwrap_or_default()
        } else {
            (vec![], vec![])
        };
        outbound_messages.extend(messages);
        (outbound_messages, results)
    }
}

impl RunLoop<FrostCoordinator> {
    /// Creates new runloop from a config and command
    pub fn new(config: &Config, command: RunLoopCommand) -> Self {
        // TODO: should this be a config option?
        // The threshold is 70% of the shares
        let threshold = (config.signer_ids_public_keys.key_ids.len() / 10 * 7)
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
            .clone();
        RunLoop {
            event_timeout: config.event_timeout,
            coordinator: FrostCoordinator::new(total_signers, config.message_private_key),
            signing_round: SigningRound::new(
                threshold,
                total_signers,
                total_keys,
                config.signer_id,
                key_ids,
                config.message_private_key,
                config.signer_ids_public_keys.clone(),
            ),
            stacks_client: StacksClient::from(config),
            command,
            state: State::Idle,
        }
    }
}

/// Process inbound messages using the frost_signer signing round mechanism
pub fn process_inbound_messages(
    signing_round: &mut SigningRound,
    messages: Vec<Message>,
) -> Result<Vec<Message>, frost_signer::signing_round::Error> {
    let mut responses = vec![];
    for message in messages {
        // TODO: this code was swiped from frost-signer. Expose it there so we don't have duplicate code
        let outbounds = signing_round.process(message.msg)?;
        for out in outbounds {
            let msg = Message {
                msg: out.clone(),
                sig: match out {
                    MessageTypes::DkgBegin(msg) | MessageTypes::DkgPrivateBegin(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign DkgBegin")
                        .to_vec(),
                    MessageTypes::DkgEnd(msg) | MessageTypes::DkgPublicEnd(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign DkgEnd")
                        .to_vec(),
                    MessageTypes::DkgPublicShare(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign DkgPublicShare")
                        .to_vec(),
                    MessageTypes::DkgPrivateShares(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign DkgPrivateShare")
                        .to_vec(),
                    MessageTypes::NonceRequest(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign NonceRequest")
                        .to_vec(),
                    MessageTypes::NonceResponse(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign NonceResponse")
                        .to_vec(),
                    MessageTypes::SignShareRequest(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign SignShareRequest")
                        .to_vec(),
                    MessageTypes::SignShareResponse(msg) => msg
                        .sign(&signing_round.network_private_key)
                        .expect("failed to sign SignShareResponse")
                        .to_vec(),
                },
            };
            responses.push(msg);
        }
    }
    Ok(responses)
}

impl<C: Coordinatable> SignerRunLoop<Vec<Point>> for RunLoop<C> {
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.event_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.event_timeout
    }

    // TODO: update the return type to return any OperationResult
    fn run_one_pass(&mut self, event: Option<StackerDBChunksEvent>) -> Option<Vec<Point>> {
        // TODO: we should potentially trigger shares outside of the runloop. This may be temporary?
        self.execute_dkg_sign();
        if let Some(event) = event {
            let (outbound_messages, operation_results) = self.process_event(&event);
            info!(
                "Sending {} messages to other stacker-db instances.",
                outbound_messages.len()
            );
            for msg in outbound_messages {
                let ack = self
                    .stacks_client
                    .send_message(self.signing_round.signer.signer_id, msg);
                if let Ok(ack) = ack {
                    info!("ACK: {:?}", ack);
                } else {
                    warn!("Failed to send message to stacker-db instance: {:?}", ack);
                }
            }
            let mut results = vec![];
            // TODO: cleanup this logic.
            for operation_result in operation_results {
                match operation_result {
                    OperationResult::Dkg(public_key) => {
                        self.state = State::DkgDone;
                        results.push(public_key);
                    }
                    OperationResult::Sign(_signature, _proof) => {
                        self.state = State::SignDone;
                    }
                }
            }
            // Determine if we need to trigger Sign or Exit.
            self.execute_dkg_sign();
            if self.state == State::Exit {
                return Some(results);
            }
        }
        None
    }
}

/// Helper function for determining the coordinator public key given the the public keys
fn calculate_coordinator(public_keys: &PublicKeys) -> (u32, &ecdsa::PublicKey) {
    // TODO do some sort of VRF here to calculate the public key
    // Mockamato just uses the first signer_id as the coordinator for now
    (0, public_keys.signers.get(&0).unwrap())
}

/// TODO: this should not be here.
/// Temporary copy paste from frost-signer
fn verify_msg(
    m: &Message,
    public_keys: &PublicKeys,
    coordinator_public_key: &ecdsa::PublicKey,
) -> bool {
    match &m.msg {
        MessageTypes::DkgBegin(msg) | MessageTypes::DkgPrivateBegin(msg) => {
            if !msg.verify(&m.sig, coordinator_public_key) {
                warn!("Received a DkgPrivateBegin message with an invalid signature.");
                return false;
            }
        }
        MessageTypes::DkgEnd(msg) | MessageTypes::DkgPublicEnd(msg) => {
            if let Some(public_key) = public_keys.signers.get(&msg.signer_id) {
                info!("{:?}", public_key.to_bytes());

                if !msg.verify(&m.sig, public_key) {
                    warn!("Received a DkgPublicEnd message with an invalid signature.");
                    return false;
                }
            } else {
                warn!(
                    "Received a DkgPublicEnd message with an unknown id: {}",
                    msg.signer_id
                );
                return false;
            }
        }
        MessageTypes::DkgPublicShare(msg) => {
            if let Some(public_key) = public_keys.key_ids.get(&msg.party_id) {
                if !msg.verify(&m.sig, public_key) {
                    warn!("Received a DkgPublicShare message with an invalid signature.");
                    return false;
                }
            } else {
                warn!(
                    "Received a DkgPublicShare message with an unknown id: {}",
                    msg.party_id
                );
                return false;
            }
        }
        MessageTypes::DkgPrivateShares(msg) => {
            // Private shares have key IDs from [0, N) to reference IDs from [1, N]
            // in Frost V4 to enable easy indexing hence ID + 1
            // TODO: Once Frost V5 is released, this off by one adjustment will no longer be required
            let key_id = msg.key_id + 1;
            if let Some(public_key) = public_keys.key_ids.get(&key_id) {
                if !msg.verify(&m.sig, public_key) {
                    warn!("Received a DkgPrivateShares message with an invalid signature from key_id {} key {}", msg.key_id, &public_key);
                    return false;
                }
            } else {
                warn!(
                    "Received a DkgPrivateShares message with an unknown id: {}",
                    key_id
                );
                return false;
            }
        }
        MessageTypes::NonceRequest(msg) => {
            if !msg.verify(&m.sig, coordinator_public_key) {
                warn!("Received a NonceRequest message with an invalid signature.");
                return false;
            }
        }
        MessageTypes::NonceResponse(msg) => {
            if let Some(public_key) = public_keys.signers.get(&msg.signer_id) {
                if !msg.verify(&m.sig, public_key) {
                    warn!("Received a NonceResponse message with an invalid signature.");
                    return false;
                }
            } else {
                warn!(
                    "Received a NonceResponse message with an unknown id: {}",
                    msg.signer_id
                );
                return false;
            }
        }
        MessageTypes::SignShareRequest(msg) => {
            if !msg.verify(&m.sig, coordinator_public_key) {
                warn!("Received a SignShareRequest message with an invalid signature.");
                return false;
            }
        }
        MessageTypes::SignShareResponse(msg) => {
            if let Some(public_key) = public_keys.signers.get(&msg.signer_id) {
                if !msg.verify(&m.sig, public_key) {
                    warn!("Received a SignShareResponse message with an invalid signature.");
                    return false;
                }
            } else {
                warn!(
                    "Received a SignShareResponse message with an unknown id: {}",
                    msg.signer_id
                );
                return false;
            }
        }
    }
    true
}
