use stacks_signer::{net, signer};
use stacks_signer::net::Net;
use stacks_signer::signer::{MessageTypes, Signer};
use secp256k1_math::scalar::Scalar;

fn setup() -> (Signer, Net) {
    let mut signer = Signer::new();
    signer.reset(1, 2);
    (signer, Net::new())
}

#[test]
fn receive_message() {
    let (signer, net) = setup();

    let join = MessageTypes::Join;
    assert!(signer.process(join));
}

#[test]
fn broadcast_share() {
    let (mut signer, net) = setup();

    let share = signer::frost::SignatureShare{
        id: 0,
        z_i: Scalar::new(),
        public_key: Default::default()
    };

    net.send_message(share);
}
