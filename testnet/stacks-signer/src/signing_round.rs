pub use frost;
use frost::common::{PolyCommitment, PublicNonce};
use hashbrown::HashMap;
use p256k1::scalar::Scalar;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_info};

use stacks_common::{debug, info};

use crate::state_machine::{StateMachine, States};

type KeyShares = HashMap<usize, Scalar>;

pub struct SigningRound {
    pub dkg_id: Option<usize>,
    pub threshold: usize,
    pub total: usize,
    pub signer: Signer,
    pub state: States,
    pub commitments: HashMap<u32, PolyCommitment>,
    pub shares: HashMap<u32, HashMap<usize, Scalar>>,
}

pub struct Signer {
    pub frost_signer: frost::v1::Signer,
    pub signer_id: u64,
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
            States::DkgDistribute => {
                self.state == States::Init || self.state == States::DkgDistribute
            }
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
    DkgPublicShare(DkgPublicShare),
    DkgPrivateShares(DkgPrivateShares),
    NonceRequest(NonceRequest),
    NonceResponse(NonceResponse),
    SignShareRequest(SignatureShareRequest),
    SignShareResponse(SignatureShareResponse),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DkgPublicShare {
    pub dkg_id: u64,
    pub party_id: u32,
    pub public_share: PolyCommitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DkgPrivateShares {
    pub dkg_id: u64,
    pub party_id: u32,
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
    pub fn new(
        threshold: usize,
        total: usize,
        signer_id: u64,
        party_ids: Vec<usize>,
    ) -> SigningRound {
        assert!(threshold <= total);
        let mut rng = OsRng::default();
        let frost_signer = frost::v1::Signer::new(&party_ids, total, threshold, &mut rng);
        let signer = Signer {
            frost_signer,
            signer_id: signer_id,
        };

        SigningRound {
            dkg_id: None,
            threshold: threshold,
            total: total,
            signer: signer,
            state: States::Init,
            commitments: HashMap::new(),
            shares: HashMap::new(),
        }
    }

    pub fn process(&mut self, message: MessageTypes) -> Result<Vec<MessageTypes>, String> {
        let out_msgs = match message {
            MessageTypes::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin),
            MessageTypes::DkgPublicShare(dkg_public_shares) => {
                self.dkg_public_share(dkg_public_shares)
            }
            MessageTypes::DkgPrivateShares(dkg_private_shares) => {
                self.dkg_private_shares(dkg_private_shares)
            }
            _ => Ok(vec![]), // TODO
        };

        match out_msgs {
            Ok(mut out) => {
                if self.can_dkg_end() {
                    let dkg_end = MessageTypes::DkgEnd(DkgEnd {
                        dkg_id: self.dkg_id.unwrap() as u64,
                        signer_id: self.signer.signer_id as usize,
                    });
                    out.push(dkg_end);
                    self.move_to(States::SignGather).unwrap();
                }
                Ok(out)
            }
            Err(e) => Err(e),
        }
    }

    pub fn can_dkg_end(&self) -> bool {
        debug!(
            "can_dkg_end state {:?} commitments {} shares {}",
            self.state,
            self.commitments.len(),
            self.shares.len()
        );
        self.state == States::DkgGather
            && self.commitments.len() == self.total
            && self.shares.len() == self.total
    }

    pub fn key_share_for_party(&self, party_id: usize) -> KeyShares {
        self.signer.frost_signer.parties[party_id].get_shares()
    }

    pub fn dkg_begin(&mut self, dkg_begin: DkgBegin) -> Result<Vec<MessageTypes>, String> {
        self.dkg_id = Some(dkg_begin.dkg_id as usize);
        self.move_to(States::DkgDistribute).unwrap();
        let _party_state = self.signer.frost_signer.save();
        let mut rng = OsRng::default();
        let mut msgs = vec![];
        for (_idx, party) in self.signer.frost_signer.parties.iter().enumerate() {
            info!("creating dkg private share for party #{}", party.id);
            let private_shares = MessageTypes::DkgPrivateShares(DkgPrivateShares {
                dkg_id: self.dkg_id.unwrap() as u64,
                party_id: party.id as u32,
                private_shares: party.get_shares(),
            });
            msgs.push(private_shares);
            let public_share = MessageTypes::DkgPublicShare(DkgPublicShare {
                dkg_id: self.dkg_id.unwrap() as u64,
                party_id: party.id as u32,
                public_share: party.get_poly_commitment(&mut rng),
            });
            msgs.push(public_share);
        }
        self.move_to(States::DkgGather).unwrap();
        Ok(msgs)
    }

    pub fn dkg_public_share(
        &mut self,
        dkg_public_share: DkgPublicShare,
    ) -> Result<Vec<MessageTypes>, String> {
        self.commitments
            .insert(dkg_public_share.party_id, dkg_public_share.public_share);
        info!(
            "public share received for party #{}. commitments {}/{}",
            dkg_public_share.party_id,
            self.commitments.len(),
            self.total
        );
        Ok(vec![])
    }

    pub fn dkg_private_shares(
        &mut self,
        dkg_private_shares: DkgPrivateShares,
    ) -> Result<Vec<MessageTypes>, String> {
        info!(
                "{} private shares received for party #{}. shares {}/{}",
                dkg_private_shares.private_shares.len(),
                dkg_private_shares.party_id,
                self.shares.len(),
                self.total
            );
        self.shares.insert(dkg_private_shares.party_id, dkg_private_shares.private_shares);
        Ok(vec![])
    }
}
