use secp256k1_math::scalar::Scalar;
use stacks_signer::net::Net;
use stacks_signer::signer::{MessageTypes, Signer};
use frost::common::SignatureShare;
use stacks_signer::config::Config;

fn setup() -> (Signer, Net) {
    let mut signer = Signer::new();
    signer.reset(1, 2);
    let config = Config::default();
    (signer, Net::new(&config))
}

#[test]
fn receive_message() {
    let (mut signer, _net) = setup();

    let join = MessageTypes::Join;
    assert!(signer.process(join));
}

#[test]
fn broadcast_share() {
    let (_signer, net) = setup();

    let share = SignatureShare {
        id: 0,
        z_i: Scalar::new(),
        public_key: Default::default(),
    };

    net.send_message(share);
}
