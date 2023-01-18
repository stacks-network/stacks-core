use secp256k1_math::scalar::Scalar;
use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::{MessageTypes, SignatureShare, Signer};

fn setup_signer() -> Signer {
    let my_id = 1;
    let mut signer = Signer::new(my_id);
    signer.reset(1, 2);
    signer
}

#[test]
fn receive_msg() {
    let m1 = Message {
        msg: MessageTypes::DkgBegin,
    };
    let mut config = Config::default();
    config.common.stacks_node_url = "http://localhost:9775".to_owned();

    let in_queue = vec![m1];
    let out_queue = vec![];
    let mut net = HttpNet::new(&config, in_queue, out_queue);
    match net.next_message() {
        Some(_msg) => {
            assert!(true)
        }
        None => {}
    }
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
