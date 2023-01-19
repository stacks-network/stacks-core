use secp256k1_math::scalar::Scalar;
use stacks_signer::signing_round::{MessageTypes, SignatureShare, SigningRound};

fn setup_signer(total: usize, threshold: usize) -> SigningRound {
    let my_id = 1;
    let mut signer = SigningRound::new(my_id, threshold, total);
    signer.reset();
    signer
}

#[test]
fn dkg_begin() {
    let mut signer = setup_signer(2, 1);
    assert_eq!(signer.commitments.len(), 0);

    let dkg_begin_msg = MessageTypes::DkgBegin;
    assert!(signer.process(dkg_begin_msg));

    // part of the DKG_BEGIN process is to fill the commitments array
    assert_eq!(signer.commitments.len(), signer.total);
}

#[test]
fn signature_share() {
    let share = frost::common::SignatureShare {
        id: 0,
        z_i: Scalar::new(),
        public_key: Default::default(),
    };

    let msg_share = MessageTypes::SignatureShare(SignatureShare {
        signature_share: share,
    });

    let mut signer = setup_signer(2, 1);
    signer.process(msg_share);
}
