use secp256k1_math::scalar::Scalar;
use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::{MessageTypes, SignatureShare, Signer};

fn setup() -> (Signer, Box<dyn Net>) {
    let mut signer = Signer::new();
    signer.reset(1, 2);
    let config = Config::default();
    (signer, Box::new(HttpNet::new(&config)))
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

    let share = frost::common::SignatureShare {
        id: 0,
        z_i: Scalar::new(),
        public_key: Default::default(),
    };

    net.send_message(Message {
        r#type: MessageTypes::SignatureShare(SignatureShare {
            signature_share: share,
        }),
    });

    let next = net.next_message();
    match next.r#type {
        MessageTypes::SignatureShare(share) => {
            assert_eq!(share.signature_share.id, 0)
        }
        _ => {}
    }
}
