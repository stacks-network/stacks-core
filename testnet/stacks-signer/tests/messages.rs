use secp256k1_math::scalar::Scalar;
use stacks_signer::net::Net;
use stacks_signer::signer;
use stacks_signer::signer::{MessageTypes, Signer};

async fn setup() -> (Signer, Net) {
    let mut signer = Signer::new();
    signer.reset(1, 2);
    (signer, Net::new().await.unwrap())
}

fn receive_message() {
    let (mut signer, _net) = setup();

    let join = MessageTypes::Join;
    assert!(signer.process(join));
}

fn broadcast_share() {
    let (_signer, net) = setup();

    let share = signer::frost::SignatureShare {
        id: 0,
        z_i: Scalar::new(),
        public_key: Default::default(),
    };

    net.send_message(share);
}
