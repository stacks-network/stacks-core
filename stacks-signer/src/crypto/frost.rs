use std::collections::BTreeMap;

use crate::crypto::{Coordinatable, Error as CryptoError, OperationResult};
use frost_signer::{
    net::Message,
    signing_round::{DkgBegin, DkgPublicShare, MessageTypes, Signable},
};
use hashbrown::HashSet;
use slog::{slog_debug, slog_info, slog_warn};
use stacks_common::{debug, error, info, warn};
use wsts::{Point, Scalar};

#[derive(thiserror::Error, Debug)]
/// The error type for the coordinator
pub enum Error {
    /// A bad state change was made
    #[error("Bad State Change: {0}")]
    BadStateChange(String),
}

/// The coordinator for the FROST algorithm
pub struct Coordinator {
    current_dkg_id: u64,
    current_dkg_public_id: u64,
    total_signers: u32, // Assuming the signers cover all id:s in {1, 2, ..., total_signers}
    dkg_public_shares: BTreeMap<u32, DkgPublicShare>,
    aggregate_public_key: Point,
    message_private_key: Scalar,
    ids_to_await: HashSet<u32>,
    state: State,
}

impl Coordinator {
    /// Create a new coordinator
    pub fn new(total_signers: u32, message_private_key: Scalar) -> Self {
        Self {
            current_dkg_id: 0,
            current_dkg_public_id: 0,
            total_signers,
            dkg_public_shares: Default::default(),
            aggregate_public_key: Point::default(),
            message_private_key,
            ids_to_await: (1..=total_signers).collect(),
            state: State::Idle,
        }
    }
}

impl Coordinator {
    /// Handle a message from the stacker-db instance
    pub fn process_message(
        &mut self,
        message: &Message,
    ) -> Result<(Option<Message>, Option<OperationResult>), Error> {
        loop {
            match self.state {
                State::Idle => {
                    // do nothing
                    // We are the coordinator and should be the only thing triggering messages right now
                    return Ok((None, None));
                }
                State::DkgPublicDistribute => {
                    let message = self.start_public_shares()?;
                    return Ok((Some(message), None));
                }
                State::DkgPublicGather => {
                    self.gather_public_shares(message)?;
                    if self.state == State::DkgPublicGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgPrivateDistribute => {
                    let message = self.start_private_shares()?;
                    return Ok((Some(message), None));
                }
                State::DkgEndGather => {
                    self.gather_dkg_end(message)?;
                    if self.state == State::DkgEndGather {
                        // We need more data
                        return Ok((None, None));
                    } else if self.state == State::Idle {
                        // We are done with the DKG round! Return the operation result
                        return Ok((None, Some(OperationResult::Dkg(self.aggregate_public_key))));
                    }
                }
            }
        }
    }

    /// Start a DKG round
    pub fn start_dkg_round(&mut self) -> Result<Message, Error> {
        self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        info!("Starting DKG round #{}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
    }

    fn start_public_shares(&mut self) -> Result<Message, Error> {
        self.dkg_public_shares.clear();
        info!(
            "DKG Round #{}: Starting Public Share Distribution Round #{}",
            self.current_dkg_id, self.current_dkg_public_id
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };

        let dkg_begin_message = Message {
            sig: dkg_begin.sign(&self.message_private_key).expect(""),
            msg: MessageTypes::DkgBegin(dkg_begin),
        };
        self.move_to(State::DkgPublicGather)?;
        Ok(dkg_begin_message)
    }

    fn start_private_shares(&mut self) -> Result<Message, Error> {
        info!(
            "DKG Round #{}: Starting Private Share Distribution",
            self.current_dkg_id
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };
        let dkg_private_begin_msg = Message {
            sig: dkg_begin.sign(&self.message_private_key).expect(""),
            msg: MessageTypes::DkgPrivateBegin(dkg_begin),
        };
        self.move_to(State::DkgEndGather)?;
        Ok(dkg_private_begin_msg)
    }

    fn gather_public_shares(&mut self, message: &Message) -> Result<(), Error> {
        match &message.msg {
            MessageTypes::DkgPublicEnd(dkg_end_msg) => {
                self.ids_to_await.remove(&dkg_end_msg.signer_id);
                debug!(
                    "DKG_Public_End round #{} from signer #{}. Waiting on {:?}",
                    dkg_end_msg.dkg_id, dkg_end_msg.signer_id, self.ids_to_await
                );
            }
            MessageTypes::DkgPublicShare(dkg_public_share) => {
                self.dkg_public_shares
                    .insert(dkg_public_share.party_id, dkg_public_share.clone());

                debug!(
                    "DKG round #{} DkgPublicShare from party #{}",
                    dkg_public_share.dkg_id, dkg_public_share.party_id
                );
            }
            _ => {}
        }
        if self.ids_to_await.is_empty() {
            // Calculate the aggregate public key
            let key = self
                .dkg_public_shares
                .iter()
                .fold(Point::default(), |s, (_, dps)| s + dps.public_share.A[0]);
            // check to see if aggregate public key has even y
            if key.has_even_y() {
                debug!("Aggregate public key has even y coord!");
                info!("Aggregate public key: {}", key);
                self.aggregate_public_key = key;
                self.move_to(State::DkgPrivateDistribute)?;
            } else {
                warn!("DKG Round #{} Failed: Aggregate public key does not have even y coord, re-running dkg.", self.current_dkg_id);
                self.move_to(State::DkgPublicDistribute)?;
            }
            self.ids_to_await = (1..=self.total_signers).collect();
        }
        Ok(())
    }

    fn gather_dkg_end(&mut self, message: &Message) -> Result<(), Error> {
        info!(
            "DKG Round #{}: waiting for Dkg End from signers {:?}",
            self.current_dkg_id, self.ids_to_await
        );
        if let MessageTypes::DkgEnd(dkg_end_msg) = &message.msg {
            self.ids_to_await.remove(&dkg_end_msg.signer_id);
            debug!(
                "DKG_End round #{} from signer #{}. Waiting on {:?}",
                dkg_end_msg.dkg_id, dkg_end_msg.signer_id, self.ids_to_await
            );
        }

        if self.ids_to_await.is_empty() {
            self.ids_to_await = (1..=self.total_signers).collect();
            self.move_to(State::Idle)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
/// Coordinator states
pub enum State {
    /// The coordinator is idle
    Idle,
    /// The coordinator is distributing public shares
    DkgPublicDistribute,
    /// The coordinator is gathering public shares
    DkgPublicGather,
    /// The coordinator is distributing private shares
    DkgPrivateDistribute,
    /// The coordinator is gathering DKG End messages
    DkgEndGather,
}

/// The state machine trait for the frost coordinator
pub trait StateMachine {
    /// Attempt to move the state machine to a new state
    fn move_to(&mut self, state: State) -> Result<(), Error>;
    /// Check if the state machine can move to a new state
    fn can_move_to(&self, state: &State) -> Result<(), Error>;
}

impl StateMachine for Coordinator {
    fn move_to(&mut self, state: State) -> Result<(), Error> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgPublicGather
                    || prev_state == &State::DkgEndGather
            }
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgEndGather => prev_state == &State::DkgPrivateDistribute,
        };
        if accepted {
            info!("state change from {:?} to {:?}", prev_state, state);
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{:?} to {:?}",
                prev_state, state
            )))
        }
    }
}

impl Coordinatable for Coordinator {
    /// Process inbound messages
    fn process_inbound_messages(
        &mut self,
        messages: Vec<Message>,
    ) -> Result<(Vec<Message>, Vec<OperationResult>), crate::crypto::Error> {
        let mut outbound_messages = vec![];
        let mut operation_results = vec![];
        for message in &messages {
            let (outbound_message, operation_result) = self.process_message(message)?;
            if let Some(outbound_message) = outbound_message {
                outbound_messages.push(outbound_message);
            }
            if let Some(operation_result) = operation_result {
                operation_results.push(operation_result);
            }
        }
        Ok((outbound_messages, operation_results))
    }

    /// Retrieve the aggregate public key
    fn get_aggregate_public_key(&self) -> Point {
        self.aggregate_public_key
    }

    /// Trigger a DKG round
    fn start_distributed_key_generation(&mut self) -> Result<Message, CryptoError> {
        let message = self.start_dkg_round()?;
        Ok(message)
    }

    // Trigger a signing round
    fn start_signing_message(&mut self, _message: &[u8]) -> Result<Message, CryptoError> {
        todo!()
    }
}

#[cfg(test)]
mod test {

    use crate::runloop::process_inbound_messages;

    use super::*;
    use frost_signer::{config::PublicKeys, signing_round::SigningRound};
    use hashbrown::HashMap;
    use p256k1::ecdsa;
    use rand_core::OsRng;

    #[test]
    fn test_state_machine() {
        let mut rng = OsRng::default();
        let message_private_key = Scalar::random(&mut rng);

        let mut coordinator = Coordinator::new(3, message_private_key);
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPublicGather).unwrap();
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_ok());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_ok());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_err());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgPrivateDistribute).unwrap();
        assert!(coordinator
            .can_move_to(&State::DkgPublicDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgPublicGather).is_err());
        assert!(coordinator
            .can_move_to(&State::DkgPrivateDistribute)
            .is_err());
        assert!(coordinator.can_move_to(&State::DkgEndGather).is_ok());
        assert!(coordinator.can_move_to(&State::Idle).is_ok());

        coordinator.move_to(State::DkgEndGather).unwrap();
        assert!(coordinator.can_move_to(&State::DkgPublicDistribute).is_ok());
    }

    #[test]
    fn test_new_coordinator() {
        let total_signers = 10;
        let mut rng = OsRng::default();
        let message_private_key = Scalar::random(&mut rng);

        let coordinator = Coordinator::new(total_signers, message_private_key);

        assert_eq!(coordinator.total_signers, total_signers);
        assert_eq!(coordinator.message_private_key, message_private_key);
        assert_eq!(coordinator.ids_to_await.len(), total_signers as usize);
        assert_eq!(coordinator.state, State::Idle);
    }

    #[test]
    fn test_start_dkg_round() {
        let total_signers = 10;
        let mut rng = OsRng::default();
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator = Coordinator::new(total_signers, message_private_key);

        let result = coordinator.start_dkg_round();

        assert!(result.is_ok());
        assert!(match result.unwrap().msg {
            MessageTypes::DkgBegin(_) => true,
            _ => false,
        });
        assert_eq!(coordinator.state, State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 1);
    }

    #[test]
    fn test_start_public_shares() {
        let total_signers = 10;
        let mut rng = OsRng::default();
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator = Coordinator::new(total_signers, message_private_key);
        coordinator.state = State::DkgPublicDistribute; // Must be in this state before calling start public shares

        let result = coordinator.start_public_shares().unwrap();

        assert!(match result.msg {
            MessageTypes::DkgBegin(_) => true,
            _ => false,
        });
        assert_eq!(coordinator.state, State::DkgPublicGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    #[test]
    fn test_start_private_shares() {
        let total_signers = 10;
        let mut rng = OsRng::default();
        let message_private_key = Scalar::random(&mut rng);
        let mut coordinator = Coordinator::new(total_signers, message_private_key);
        coordinator.state = State::DkgPrivateDistribute; // Must be in this state before calling start private shares

        let message = coordinator.start_private_shares().unwrap();
        assert!(match message.msg {
            MessageTypes::DkgPrivateBegin(_) => true,
            _ => false,
        });
        assert_eq!(coordinator.state, State::DkgEndGather);
        assert_eq!(coordinator.current_dkg_id, 0);
    }

    fn setup() -> (Coordinator, Vec<SigningRound>) {
        let mut rng = OsRng::default();
        let total_signers = 5;
        let threshold = total_signers / 10 + 7;
        let keys_per_signer = 3;
        let total_keys = total_signers * keys_per_signer;
        let key_pairs = (0..total_signers)
            .map(|_| {
                let private_key = Scalar::random(&mut rng);
                let public_key = ecdsa::PublicKey::new(&private_key).unwrap();
                (private_key, public_key)
            })
            .collect::<Vec<(Scalar, ecdsa::PublicKey)>>();
        let mut key_id: u32 = 0;
        let mut signer_ids_map = HashMap::new();
        let mut key_ids_map = HashMap::new();
        let mut key_ids = Vec::new();
        for (i, (_private_key, public_key)) in key_pairs.iter().enumerate() {
            for _ in 0..keys_per_signer {
                key_ids_map.insert((key_id + 1) as u32, public_key.clone());
                key_ids.push(key_id);
                key_id += 1;
            }
            signer_ids_map.insert((i + 1) as u32, public_key.clone());
        }
        let public_keys = PublicKeys {
            signers: signer_ids_map,
            key_ids: key_ids_map,
        };

        let signing_rounds = key_pairs
            .iter()
            .enumerate()
            .map(|(signer_id, (private_key, _public_key))| {
                SigningRound::new(
                    threshold,
                    total_signers,
                    total_keys,
                    (signer_id + 1) as u32,
                    key_ids.clone(),
                    *private_key,
                    public_keys.clone(),
                )
            })
            .collect::<Vec<SigningRound>>();

        let coordinator = Coordinator::new(total_signers, key_pairs[0].0);
        (coordinator, signing_rounds)
    }

    /// Helper function for feeding messages back from the processor into the signing rounds and coordinator
    fn feedback_messages(
        coordinator: &mut Coordinator,
        signing_rounds: &mut Vec<SigningRound>,
        messages: Vec<Message>,
    ) -> (Vec<Message>, Vec<OperationResult>) {
        let mut inbound_messages = vec![];
        let mut feedback_messages = vec![];
        for signing_round in signing_rounds.as_mut_slice() {
            let outbound_messages =
                process_inbound_messages(signing_round, messages.clone()).unwrap();
            feedback_messages.extend_from_slice(outbound_messages.as_slice());
            inbound_messages.extend(outbound_messages);
        }
        for signing_round in signing_rounds.as_mut_slice() {
            let outbound_messages =
                process_inbound_messages(signing_round, feedback_messages.clone()).unwrap();
            inbound_messages.extend(outbound_messages);
        }
        let outbound_messages = coordinator
            .process_inbound_messages(inbound_messages)
            .unwrap();
        outbound_messages
    }

    #[test]
    fn test_process_inbound_messages_dkg() {
        let (mut coordinator, mut signing_rounds) = setup();
        // We have started a dkg round
        let message = coordinator.start_dkg_round().unwrap();
        assert_eq!(coordinator.aggregate_public_key, Point::default());
        assert_eq!(coordinator.state, State::DkgPublicGather);
        // we have to loop in case we get an invalid y coord...
        loop {
            // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
            let (outbound_messages, operation_results) =
                feedback_messages(&mut coordinator, &mut signing_rounds, vec![message.clone()]);
            assert!(operation_results.is_empty());
            if coordinator.state == State::DkgEndGather {
                // Successfully got an Aggregate Public Key...
                assert_eq!(outbound_messages.len(), 1);
                match &outbound_messages[0].msg {
                    MessageTypes::DkgPrivateBegin(_) => {}
                    _ => {
                        panic!("Expected DkgPrivateBegin message");
                    }
                }
                // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
                let (outbound_messages, operation_results) =
                    feedback_messages(&mut coordinator, &mut signing_rounds, outbound_messages);
                assert!(outbound_messages.is_empty());
                assert_eq!(operation_results.len(), 1);
                match operation_results[0] {
                    OperationResult::Dkg(point) => {
                        assert_ne!(point, Point::default());
                        assert_eq!(coordinator.aggregate_public_key, point);
                        assert_eq!(coordinator.state, State::Idle);
                        break;
                    }
                    _ => panic!("Expected Dkg Operation result"),
                }
            }
        }
        assert_ne!(coordinator.aggregate_public_key, Point::default());
    }
}
