use secp256k1_math::scalar::Scalar;
use stacks_signer::signer::{MessageTypes, SignatureShare, Signer};

fn setup_signer() -> Signer {
    let my_id = 1;
    let mut signer = Signer::new(my_id);
    signer.reset(1, 2);
    signer
}

#[test]
fn dkg_begin() {
    let mut signer = setup_signer();

    let dkg_begin_msg = MessageTypes::DkgBegin;
    assert!(signer.process(dkg_begin_msg));
}

#[test]
fn receive_share() {
    let share = frost::common::SignatureShare {
        id: 0,
        z_i: Scalar::new(),
        public_key: Default::default(),
    };

    let msg_share = MessageTypes::SignatureShare(SignatureShare {
            signature_share: share,
        });

    let mut signer = setup_signer();
    signer.process(msg_share);
}
