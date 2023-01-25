pub use frost;
use frost::common::{PolyCommitment, PublicNonce};
use frost::v1::{Party, Signer};
use hashbrown::HashMap;
use p256k1::scalar::Scalar;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use slog::slog_info;

use stacks_common::info;

use crate::state_machine::{StateMachine, States};

type KeyShares = HashMap<usize, Scalar>;

pub struct SigningRound {
    pub id: usize,
    pub threshold: usize,
    pub total: usize,
    pub signer: Signer,
    pub state: States,
    pub commitments: Vec<PolyCommitment>,
}

impl StateMachine for SigningRound {
    fn move_to(&mut self, state: States) -> Result<(), String> {
        self.can_move_to(&state)?;
        self.state = state;
        Ok(())
    }

    fn can_move_to(&self, state: &States) -> Result<(), String> {
        let accepted = match state {
            States::Init => false,
            States::DkgDistribute => self.state == States::Init,
            States::DkgGather => self.state == States::DkgDistribute,
            States::SignGather => self.state == States::DkgGather,
            States::Signed => self.state == States::SignGather,
        };
        if accepted {
            info!("");
            Ok(())
        } else {
            Err(format!("bad state change: {:?} to {:?}", self.state, state))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageTypes {
    DkgBegin(DkgBegin),
    DkgEnd(DkgEnd),
    DkgQuery,
    DkgQueryResponse(DkgQueryResponse),
    DkgPublicShares(DkgPublicShare),
    DkgPrivateShares(DkgPrivateShares),
    NonceRequest(NonceRequest),
    NonceResponse(NonceResponse),
    SignShareRequest(SignatureShareRequest),
    SignShareResponse(SignatureShareResponse),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DkgPublicShare {
    pub public_share: PolyCommitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DkgPrivateShares {
    pub private_shares: KeyShares,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DkgBegin {
    pub dkg_id: u64, //TODO: Strong typing for this, alternatively introduce a type alias
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DkgEnd {
    pub dkg_id: u64,
    pub signer_id: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DkgQueryResponse {
    pub dkg_id: u64,
    pub public_share: PolyCommitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonceRequest {
    pub dkg_id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonceResponse {
    pub dkg_id: u64,
    pub signer_id: usize,
    pub nonce: PublicNonce,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShareRequest {
    pub dkg_id: u64,
    pub correlation_id: u64,
    pub signer_id: usize,
    pub nonce: PublicNonce,
    pub message: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShareResponse {
    pub dkg_id: u64,
    pub correlation_id: u64,
    pub signer_id: usize,
    pub signature_share: frost::v1::SignatureShare,
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
            MessageTypes::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin),
            _ => Ok(vec![]), // TODO
        }
    }

    pub fn key_share(&self, party_id: usize) -> KeyShares {
        self.signer.parties[party_id].get_shares()
    }

    pub fn dkg_begin(&mut self, dkg_begin: DkgBegin) -> Result<Vec<MessageTypes>, String> {
        self.move_to(States::DkgDistribute).unwrap();

        self.reset();
        let _party_state = self.signer.parties[self.id].save();
        let mut rng = OsRng::default();
        let mut msgs = vec![];
        for (idx, party) in self.signer.parties.iter().enumerate() {
            info!("creating dkg private share for party #{}", idx);
            let private_shares = MessageTypes::DkgPrivateShares(DkgPrivateShares {
                private_shares: party.get_shares(),
            });
            msgs.push(private_shares);
            let public_share = MessageTypes::DkgPublicShares(DkgPublicShare {
                public_share: party.get_poly_commitment(&mut rng),
            });
            msgs.push(public_share);
        }
        let dkg_end = MessageTypes::DkgEnd(DkgEnd{ dkg_id: dkg_begin.dkg_id, signer_id: self.id });
        msgs.push(dkg_end);
        Ok(msgs)
    }
}
