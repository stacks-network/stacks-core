pub use frost;
use frost::common::PolyCommitment;
use frost::v1::Party;
use hashbrown::HashMap;
use rand_core::OsRng;
use secp256k1_math::scalar::Scalar;
use serde::{Deserialize, Serialize};

type KeyShare = HashMap<usize, Scalar>;

pub struct Signer {
    pub id: usize,
    pub threshold: usize,
    pub total: usize,
    pub parties: Vec<Party>,
    pub commitments: Vec<PolyCommitment>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShare {
    pub signature_share: frost::common::SignatureShare,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MessageTypes {
    DkgBegin,
    DkgEnd,
    SignatureShare(SignatureShare),
}

impl Signer {
    pub fn new(id: usize, threshold: usize, total: usize) -> Signer {
        assert!(threshold <= total);
        assert!(id <= total);
        Signer {
            id: id,
            threshold: threshold,
            total: total,
            parties: vec![],
            commitments: vec![]
        }
    }

    pub fn reset(&mut self) {
        let mut rng = OsRng::default();

        let parties = (0..self.total)
            .map(|i| Party::new(i, self.total, self.threshold, &mut rng))
            .collect();
        self.parties = parties;
    }

    pub fn process(&mut self, message: MessageTypes) -> bool {
        match message {
            MessageTypes::DkgBegin => self.dkg_begin(),
            MessageTypes::SignatureShare(_share) => {}
            MessageTypes::DkgEnd => {}
        };
        true
    }

    pub fn key_share(&self, party_id: usize) -> KeyShare {
        self.parties[party_id].get_shares()
    }

    pub fn dkg_begin(&mut self) {
        // T and N from dkg_begin msg?
        self.reset();
        let _party_state = self.parties[self.id].save();
        let mut rng = OsRng::default();
        self.commitments = self.parties
            .iter()
            .map(|p| p.get_poly_commitment(&mut rng))
            .collect();
    }
}
