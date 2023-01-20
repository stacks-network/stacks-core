pub use frost;
use frost::common::PolyCommitment;
use frost::v1::{Party, Signer};
use hashbrown::HashMap;
use rand_core::OsRng;
use secp256k1_math::scalar::Scalar;
use serde::{Deserialize, Serialize};
use crate::state_machine::{StateMachine, States};

type KeyShare = HashMap<usize, Scalar>;

pub struct SigningRound {
    pub id: usize,
    pub threshold: usize,
    pub total: usize,
    pub signer: Signer,
    pub state: States,
    pub commitments: Vec<PolyCommitment>,
}

impl StateMachine for SigningRound {
    fn move_to(&self, state: States) -> Result<(), String> {
        let accepted = match state {
            States::Init => false,
            States::DkgDistribute => self.state == States::Init,
            States::DkgGather => self.state == States::DkgDistribute,
            States::SignGather => self.state == States::DkgGather,
            States::Signed => self.state == States::SignGather,
        };
        if accepted {
            Ok(())
        } else {
            Err(format!("bad state change: {:?} to {:?}", self.state, state))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShare {
    pub signature_shares: Vec<Scalar>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageTypes {
    DkgBegin,
    DkgEnd,
    SignatureShare(SignatureShare),
}

impl SigningRound {
    pub fn new(id: usize, threshold: usize, total: usize) -> SigningRound {
        assert!(threshold <= total);
        assert!(id <= total);
        SigningRound {
            id: id,
            threshold: threshold,
            total: total,
            signer: Signer {
                n: id,
                group_key: Default::default(),
                parties: vec![],
            },
            state: States::Init,
            commitments: vec![],
        }
    }

    pub fn reset(&mut self) {
        let mut rng = OsRng::default();

        self.signer.parties = (0..self.total)
            .map(|i| Party::new(i, self.total, self.threshold, &mut rng))
            .collect();
    }

    pub fn process(&mut self, message: MessageTypes) -> Result<Vec<MessageTypes>, String> {
        match message {
            MessageTypes::DkgBegin => self.dkg_begin(),
            MessageTypes::SignatureShare(_share) => Ok(vec![]),
            MessageTypes::DkgEnd => Ok(vec![]),
        }
    }

    pub fn key_share(&self, party_id: usize) -> KeyShare {
        self.signer.parties[party_id].get_shares()
    }

    pub fn dkg_begin(&mut self)  -> Result<Vec<MessageTypes>, String> {
        self.move_to(States::DkgDistribute).unwrap();

        self.reset();
        let _party_state = self.signer.parties[self.id].save();
        let mut rng = OsRng::default();
        self.commitments = self
            .signer
            .parties
            .iter()
            .map(|p| p.get_poly_commitment(&mut rng))
            .collect();

        let mut msgs = vec![];
        for party in &self.signer.parties {
            let msg_share = MessageTypes::SignatureShare(SignatureShare {
                signature_shares: party.get_shares().into_values().collect(),
            });
            msgs.push(msg_share);
        }
        Ok(msgs)
    }
}
